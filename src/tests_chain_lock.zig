//! Cross-thread reproducers for the clearbit chain-lock audit
//! (receipts/arch-concurrency-liveness-audit-2026-10-07.md, CB-1/3/4/5/6/8).
//!
//! clearbit runs the P2P loop and the RPC server on two OS threads.  Each test
//! here freezes ONE thread at an exact instruction boundary with a test-only
//! park hook (src/test_hooks.zig, compiled out of non-test builds) and drives
//! the OTHER thread through the code that races it, through the same entry
//! points the live node uses: `RpcServer.dispatch` for the RPC thread and the
//! `.headers`/`.block` handlers, drain, ATMP and `processAllMessages` for the
//! P2P thread.
//!
//! Each test records whether the second thread was able to FINISH while the
//! first was frozen mid-operation (= no mutual exclusion), then checks the
//! consequence the audit predicts: a spent coin resurrected in the cache and a
//! double spend accepted (CB-1), two conflicting transactions in the mempool
//! (CB-3), an RPC reading a destroyed peer (CB-4), a double free on
//! disconnectnode (CB-5), the node aborting on a block the RPC connected
//! first (CB-6), and one trickling inbound connection freezing the P2P thread
//! (CB-8).
//!
//! Run: `zig build test-chain-lock [-Dchain-lock-filter=<substr>]`.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const peer_mod = @import("peer.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const p2p = @import("p2p.zig");
const mempool_mod = @import("mempool.zig");
const rpc = @import("rpc.zig");
const fatal = @import("fatal.zig");
const hooks = @import("test_hooks.zig");

/// How long the racing thread is given to finish while the first thread is
/// parked.  Without a lock it needs milliseconds; with one it can never finish
/// inside the window.  Generous so a loaded box cannot produce a false PASS.
const RACE_WINDOW_MS: u64 = 1500;

/// The lock-held instrument (chain_lock.zig) exists only on builds that have
/// the chain lock; on the deployed build these are no-ops.
const has_lock_instrument = @hasDecl(storage, "chain_lock");

fn instrumentOn() u64 {
    if (comptime has_lock_instrument) {
        storage.chain_lock.debug_checks.store(true, .seq_cst);
        return storage.chain_lock.violations.load(.seq_cst);
    }
    return 0;
}

fn instrumentForceOff() void {
    if (comptime has_lock_instrument) storage.chain_lock.debug_checks.store(false, .seq_cst);
}

/// Turn the instrument off and return the violations seen since `v0`.
fn instrumentOff(v0: u64) u64 {
    if (comptime has_lock_instrument) {
        storage.chain_lock.debug_checks.store(false, .seq_cst);
        return storage.chain_lock.violations.load(.seq_cst) - v0;
    }
    return 0;
}

// ====================================================================
// Fixture
// ====================================================================

const IbBlock = struct { block: types.Block, hash: types.Hash256 };

const Fixture = struct {
    allocator: std.mem.Allocator,
    params: consensus.NetworkParams,
    tmp_dir: testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: peer_mod.PeerManager,
    mp: mempool_mod.Mempool,
    server: rpc.RpcServer,
    src_peer: *peer_mod.Peer,

    fn init(self: *Fixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.params = consensus.REGTEST;
        self.tmp_dir = testing.tmpDir(.{});
        self.path = try self.tmp_dir.dir.realpathAlloc(allocator, ".");
        self.db = try storage.Database.open(self.path, 64, allocator);
        self.cs = storage.ChainState.init(&self.db, 64, allocator);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(&self.params);
        self.cs.best_hash = self.params.genesis_hash;
        self.cs.initGenesisTimestamp(self.params.genesis_header.timestamp);
        self.pm = peer_mod.PeerManager.init(allocator, &self.params);
        self.pm.anchors_path = "/dev/null";
        self.pm.chain_state = &self.cs;
        self.mp = mempool_mod.Mempool.init(&self.cs, &self.params, allocator);
        self.pm.mempool = &self.mp;
        self.server = rpc.RpcServer.init(allocator, &self.cs, &self.mp, &self.pm, &self.params, .{});
        self.src_peer = try stubPeer(&self.params, allocator, 3, -1);
        try self.pm.peers.append(self.src_peer);
    }

    fn deinit(self: *Fixture) void {
        hooks.reset();
        self.server.deinit();
        // The stub source peer has no socket; never let deinit close fd -1.
        for (self.pm.peers.items, 0..) |p, i| {
            if (p == self.src_peer) {
                _ = self.pm.peers.swapRemove(i);
                break;
            }
        }
        self.src_peer.recv_buffer.deinit();
        self.allocator.destroy(self.src_peer);
        self.pm.deinit();
        // Mempool.deinit frees entries, not the transactions they hold.
        var it = self.mp.entries.valueIterator();
        while (it.next()) |e| serialize.freeTransaction(self.allocator, &e.*.tx);
        self.mp.deinit();
        self.cs.deinit();
        self.db.close();
        self.allocator.free(self.path);
        self.tmp_dir.cleanup();
    }

    /// Feed a block through the REAL P2P `.headers` + `.block` handlers
    /// (which buffer it and run the drain: validate + connect).
    fn p2pDeliver(self: *Fixture, b: *const IbBlock) !void {
        const hs = try self.allocator.alloc(types.BlockHeader, 1);
        hs[0] = b.block.header;
        try self.pm.ingestHeadersMessage(self.src_peer, hs);
        try self.pm.ingestBlockMessage(self.src_peer, try cloneBlock(self.allocator, &b.block));
    }

    fn rpcCall(self: *Fixture, body: []const u8) ![]const u8 {
        return self.server.dispatch(body);
    }
};

fn stubPeer(params: *const consensus.NetworkParams, allocator: std.mem.Allocator, ip_last: u8, fd: std.posix.fd_t) !*peer_mod.Peer {
    const p = try allocator.create(peer_mod.Peer);
    p.* = .{
        .stream = .{ .handle = fd },
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, ip_last }, 18444),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 100,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .is_witness_capable = true,
        .is_headers_first = true,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = false,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
        .time_offset = 0,
        .advertise_node_bloom = false,
        .transport_version = .v1,
        .v2_cipher = null,
        .v2_transport = null,
    };
    return p;
}

fn cloneBlock(allocator: std.mem.Allocator, b: *const types.Block) !types.Block {
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readBlock(&r, allocator);
}

fn blockHex(allocator: std.mem.Allocator, b: *const types.Block) ![]u8 {
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    return std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
}

fn txHex(allocator: std.mem.Allocator, tx: *const types.Transaction) ![]u8 {
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try serialize.writeTransaction(&w, tx);
    return std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
}

fn cloneTx(allocator: std.mem.Allocator, tx: *const types.Transaction) !types.Transaction {
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try serialize.writeTransaction(&w, tx);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readTransaction(&r, allocator);
}

/// Display (RPC) hex of a txid.
fn hashHexDisplay(h: types.Hash256) [64]u8 {
    var out: [64]u8 = undefined;
    const digits = "0123456789abcdef";
    for (0..32) |i| {
        const byte = h[31 - i];
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0xf];
    }
    return out;
}

/// Regtest block at `height` (<= 16) on `prev`: valid coinbase, plus one tx
/// spending `spend` (scriptSig OP_1) when given.
fn mineBlock(
    allocator: std.mem.Allocator,
    params: *const consensus.NetworkParams,
    prev: types.Hash256,
    height: u32,
    tag: u8,
    spend: ?types.OutPoint,
) !IbBlock {
    std.debug.assert(height >= 1 and height <= 16);
    const ntx: usize = if (spend != null) 2 else 1;
    const txs = try allocator.alloc(types.Transaction, ntx);
    {
        const inputs = try allocator.alloc(types.TxIn, 1);
        inputs[0] = .{
            .previous_output = types.OutPoint.COINBASE,
            .script_sig = try allocator.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag }),
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };
        const outputs = try allocator.alloc(types.TxOut, 1);
        outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = try allocator.dupe(u8, &[_]u8{0x51}) };
        txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    }
    if (spend) |op| {
        const inputs = try allocator.alloc(types.TxIn, 1);
        inputs[0] = .{
            .previous_output = op,
            .script_sig = try allocator.dupe(u8, &[_]u8{0x51}),
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };
        const outputs = try allocator.alloc(types.TxOut, 1);
        outputs[0] = .{ .value = 1000 + @as(i64, tag), .script_pubkey = try allocator.dupe(u8, &[_]u8{0x51}) };
        txs[1] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    }
    var ids: [2]types.Hash256 = undefined;
    for (txs, 0..) |*t, i| ids[i] = try crypto.computeTxid(t, allocator);
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeMerkleRoot(ids[0..ntx], allocator),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

/// Persist a confirmed (height 1, non-coinbase) coin directly in the coin DB
/// and drop it from the cache, so the next read is a cold DB read-through.
fn plantColdCoin(cs: *storage.ChainState, op: types.OutPoint, value: i64, spk: []const u8) !void {
    try cs.utxo_set.add(&op, &types.TxOut{ .value = value, .script_pubkey = spk }, 1, false);
    try cs.flush();
    var it = cs.utxo_set.cache.iterator();
    while (it.next()) |e| {
        var ce = e.value_ptr.*;
        ce.utxo.deinit(cs.allocator);
    }
    cs.utxo_set.cache.clearRetainingCapacity();
}

fn outpoint(tag: u8) types.OutPoint {
    var h = [_]u8{0} ** 32;
    h[0] = 0xC1;
    h[1] = tag;
    return .{ .hash = h, .index = 0 };
}

/// Run `f(ctx)` on a thread; `done` flips when it returns.
fn Racer(comptime Ctx: type, comptime f: fn (*Ctx) void) type {
    return struct {
        ctx: *Ctx,
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: ?std.Thread = null,

        fn body(self: *@This()) void {
            f(self.ctx);
            self.done.store(true, .seq_cst);
        }
        fn start(self: *@This()) !void {
            self.thread = try std.Thread.spawn(.{}, body, .{self});
        }
        /// True iff it finished within `ms`.
        fn finishesWithin(self: *@This(), ms: u64) bool {
            var waited: u64 = 0;
            while (!self.done.load(.seq_cst)) {
                if (waited >= ms) return false;
                std.time.sleep(std.time.ns_per_ms);
                waited += 1;
            }
            return true;
        }
        fn join(self: *@This()) void {
            if (self.thread) |t| t.join();
            self.thread = null;
        }
    };
}

// ====================================================================
// CB-1: gettxout (RPC thread) caches a coin the P2P thread just spent
// ====================================================================

const GetTxOutCtx = struct {
    fx: *Fixture,
    body: []const u8,
    response: ?[]const u8 = null,
    fn run(self: *GetTxOutCtx) void {
        self.response = self.fx.rpcCall(self.body) catch null;
    }
};

const DeliverCtx = struct {
    fx: *Fixture,
    blk: *const IbBlock,
    fn run(self: *DeliverCtx) void {
        self.fx.p2pDeliver(self.blk) catch {};
    }
};

test "tests_chain_lock CB-1: gettxout racing a P2P block connect must not resurrect the spent coin" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();

    var a1 = try mineBlock(allocator, &fx.params, fx.params.genesis_hash, 1, 0xA1, null);
    defer serialize.freeBlock(allocator, &a1.block);
    try fx.p2pDeliver(&a1);
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);

    const g = outpoint(0x01);
    try plantColdCoin(&fx.cs, g, 100_000, &[_]u8{0x51});

    var b2 = try mineBlock(allocator, &fx.params, a1.hash, 2, 0xB2, g);
    defer serialize.freeBlock(allocator, &b2.block);

    const g_hex = hashHexDisplay(g.hash);
    const body = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"gettxout\",\"params\":[\"{s}\",0]}}", .{g_hex});
    defer allocator.free(body);

    // RPC thread: gettxout reads the coin from the DB and freezes before
    // caching it.
    const lock_v0 = instrumentOn();
    defer instrumentForceOff();
    const key = storage.makeUtxoKey(&g);
    hooks.arm(.utxo_get_after_db_read, &key);
    var rctx = GetTxOutCtx{ .fx = &fx, .body = body };
    var r = Racer(GetTxOutCtx, GetTxOutCtx.run){ .ctx = &rctx };
    try r.start();
    try testing.expect(hooks.waitParked(.utxo_get_after_db_read, 5000));

    // P2P thread: block 2 spending the coin arrives and is connected.
    var pctx = DeliverCtx{ .fx = &fx, .blk = &b2 };
    var p = Racer(DeliverCtx, DeliverCtx.run){ .ctx = &pctx };
    try p.start();
    const p2p_finished_during_rpc = p.finishesWithin(RACE_WINDOW_MS);
    hooks.release(.utxo_get_after_db_read);
    r.join();
    p.join();
    if (rctx.response) |resp| allocator.free(resp);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);

    // After block 2 the coin is spent.  Ask again.
    const after = try fx.rpcCall(body);
    defer allocator.free(after);
    const resurrected = std.mem.indexOf(u8, after, "\"result\":null") == null;

    // Consequence: a block double-spending the coin.
    var b3 = try mineBlock(allocator, &fx.params, b2.hash, 3, 0xB3, g);
    defer serialize.freeBlock(allocator, &b3.block);
    try fx.p2pDeliver(&b3);
    const double_spend_connected = fx.cs.best_height == 3;

    std.debug.print(
        "\n[CB-1] p2p_connect_finished_while_gettxout_parked={} gettxout_after_spend_returns_coin={} double_spend_block_connected={}\n",
        .{ p2p_finished_during_rpc, resurrected, double_spend_connected },
    );
    try testing.expect(!p2p_finished_during_rpc);
    try testing.expect(!resurrected);
    try testing.expect(!double_spend_connected);
    const lock_violations = instrumentOff(lock_v0);
    if (lock_violations != 0) std.debug.print("[CB-1] lock-held instrument: {d} violation(s)\n", .{lock_violations});
    try testing.expectEqual(@as(u64, 0), lock_violations);
}

// ====================================================================
// CB-3: two conflicting transactions admitted at once (RPC + P2P)
// ====================================================================

fn p2wshOpTrue() [34]u8 {
    var spk: [34]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x20;
    std.crypto.hash.sha2.Sha256.hash(&[_]u8{0x51}, spk[2..34], .{});
    return spk;
}

fn spendP2wsh(allocator: std.mem.Allocator, op: types.OutPoint, out_value: i64) !types.Transaction {
    const spk = p2wshOpTrue();
    const inputs = try allocator.alloc(types.TxIn, 1);
    const wit = try allocator.alloc([]const u8, 1);
    wit[0] = try allocator.dupe(u8, &[_]u8{0x51});
    inputs[0] = .{
        .previous_output = op,
        .script_sig = try allocator.dupe(u8, &[_]u8{}),
        .sequence = 0xFFFFFFFF,
        .witness = wit,
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = out_value, .script_pubkey = try allocator.dupe(u8, &spk) };
    return .{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
}

const SendRawCtx = struct {
    fx: *Fixture,
    body: []const u8,
    response: ?[]const u8 = null,
    fn run(self: *SendRawCtx) void {
        self.response = self.fx.rpcCall(self.body) catch null;
    }
};

const AtmpCtx = struct {
    fx: *Fixture,
    tx: types.Transaction,
    accepted: bool = false,
    fn run(self: *AtmpCtx) void {
        // The call the P2P `tx` handler makes (peer.zig handleMessage .tx).
        const res = self.fx.mp.acceptToMemoryPool(self.tx, false);
        self.accepted = res.accepted;
    }
};

test "tests_chain_lock CB-3: sendrawtransaction racing P2P ATMP must not admit two conflicting spends" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();

    var a1 = try mineBlock(allocator, &fx.params, fx.params.genesis_hash, 1, 0xA1, null);
    defer serialize.freeBlock(allocator, &a1.block);
    try fx.p2pDeliver(&a1);

    const g = outpoint(0x03);
    const spk = p2wshOpTrue();
    try plantColdCoin(&fx.cs, g, 100_000, &spk);

    var tx1 = try spendP2wsh(allocator, g, 99_000);
    defer serialize.freeTransaction(allocator, &tx1);
    var tx2 = try spendP2wsh(allocator, g, 98_000);
    defer serialize.freeTransaction(allocator, &tx2);
    const id1 = try crypto.computeTxid(&tx1, allocator);
    const id2 = try crypto.computeTxid(&tx2, allocator);

    // Instrument check: each tx alone is admissible (else the race below
    // proves nothing).
    {
        var probe_tx = try cloneTx(allocator, &tx1);
        defer serialize.freeTransaction(allocator, &probe_tx);
        const probe = fx.mp.acceptToMemoryPool(probe_tx, true);
        if (!probe.accepted) std.debug.print("\n[CB-3] instrument: tx1 rejected alone: {s}\n", .{probe.reject_reason orelse "?"});
        try testing.expect(probe.accepted);
    }

    const hex1 = try txHex(allocator, &tx1);
    defer allocator.free(hex1);
    const body = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"{s}\"]}}", .{hex1});
    defer allocator.free(body);

    const lock_v0 = instrumentOn();
    defer instrumentForceOff();
    hooks.arm(.mempool_pre_insert, null);
    var rctx = SendRawCtx{ .fx = &fx, .body = body };
    var r = Racer(SendRawCtx, SendRawCtx.run){ .ctx = &rctx };
    try r.start();
    try testing.expect(hooks.waitParked(.mempool_pre_insert, 5000));

    var pctx = AtmpCtx{ .fx = &fx, .tx = try cloneTx(allocator, &tx2) };
    var p = Racer(AtmpCtx, AtmpCtx.run){ .ctx = &pctx };
    try p.start();
    const p2p_finished_during_rpc = p.finishesWithin(RACE_WINDOW_MS);
    hooks.release(.mempool_pre_insert);
    r.join();
    p.join();
    if (rctx.response) |resp| allocator.free(resp);
    if (!pctx.accepted) serialize.freeTransaction(allocator, &pctx.tx);

    const has1 = fx.mp.contains(id1);
    const has2 = fx.mp.contains(id2);
    std.debug.print(
        "\n[CB-3] p2p_atmp_finished_while_sendraw_parked={} tx1_in_pool={} tx2_in_pool={} pool_size={d}\n",
        .{ p2p_finished_during_rpc, has1, has2, fx.mp.entries.count() },
    );
    try testing.expect(!p2p_finished_during_rpc);
    // Exactly one spend of the coin may be in the pool.
    try testing.expect(has1 != has2);
    const lock_violations = instrumentOff(lock_v0);
    if (lock_violations != 0) std.debug.print("[CB-3] lock-held instrument: {d} violation(s)\n", .{lock_violations});
    try testing.expectEqual(@as(u64, 0), lock_violations);
}

// ====================================================================
// CB-4: getpeerinfo walking the peer list while the P2P thread frees a peer
// ====================================================================

const PeerInfoCtx = struct {
    fx: *Fixture,
    response: ?[]const u8 = null,
    fn run(self: *PeerInfoCtx) void {
        self.response = self.fx.rpcCall("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getpeerinfo\",\"params\":[]}") catch null;
    }
};

const PamCtx = struct {
    fx: *Fixture,
    fn run(self: *PamCtx) void {
        self.fx.pm.processAllMessages() catch {};
    }
};

test "tests_chain_lock CB-4: getpeerinfo racing a P2P disconnect must not read a freed peer" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();

    // Peer A (index 0) with a real socket; the stub source peer moves aside.
    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
    const a = try stubPeer(&fx.params, allocator, 77, fds[0]);
    _ = fx.pm.peers.swapRemove(0);
    try fx.pm.peers.append(a);

    const lock_v0 = instrumentOn();
    defer instrumentForceOff();
    hooks.arm(.getpeerinfo_peer, null);
    var rctx = PeerInfoCtx{ .fx = &fx };
    var r = Racer(PeerInfoCtx, PeerInfoCtx.run){ .ctx = &rctx };
    try r.start();
    try testing.expect(hooks.waitParked(.getpeerinfo_peer, 5000));

    // The remote end hangs up: the P2P loop sees EOF and removes + frees A.
    std.posix.close(fds[1]);
    var pctx = PamCtx{ .fx = &fx };
    var p = Racer(PamCtx, PamCtx.run){ .ctx = &pctx };
    try p.start();
    const p2p_finished_during_rpc = p.finishesWithin(RACE_WINDOW_MS);
    const removed_during_walk = fx.pm.peers.items.len == 0;
    hooks.release(.getpeerinfo_peer);
    r.join();
    p.join();
    try fx.pm.peers.append(fx.src_peer);

    const resp = rctx.response orelse "";
    defer if (rctx.response) |x| allocator.free(x);
    const listed_a = std.mem.indexOf(u8, resp, "127.0.0.77") != null;
    std.debug.print(
        "\n[CB-4] p2p_removed_peer_while_getpeerinfo_holds_it={} getpeerinfo_reported_peer_A_intact={}\n",
        .{ p2p_finished_during_rpc and removed_during_walk, listed_a },
    );
    try testing.expect(!p2p_finished_during_rpc);
    try testing.expect(listed_a);
    try testing.expectEqual(@as(usize, 1), fx.pm.peers.items.len); // only the stub
    const lock_violations = instrumentOff(lock_v0);
    if (lock_violations != 0) std.debug.print("[CB-4] lock-held instrument: {d} violation(s)\n", .{lock_violations});
    try testing.expectEqual(@as(u64, 0), lock_violations);
}

// ====================================================================
// CB-5: disconnectnode tears the peer down on the RPC thread; the P2P loop
// then tears it down again (double close + double free).
// ====================================================================

test "tests_chain_lock CB-5: disconnectnode then a P2P pass must free the peer exactly once" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();

    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
    defer std.posix.close(fds[1]);
    const a = try stubPeer(&fx.params, allocator, 78, fds[0]);
    try fx.pm.peers.append(a);

    const lock_v0 = instrumentOn();
    defer instrumentForceOff();
    const resp = try fx.rpcCall("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"disconnectnode\",\"params\":[\"127.0.0.78:18444\"]}");
    defer allocator.free(resp);
    try testing.expect(std.mem.indexOf(u8, resp, "\"error\":null") != null or std.mem.indexOf(u8, resp, "\"result\":null") != null);

    // Next P2P loop pass.  On the deployed code this is where the second
    // disconnect() runs: close() of an fd number the RPC already closed, and
    // a second free of the receive buffer.
    std.debug.print("\n[CB-5] running the P2P pass after disconnectnode (a double free aborts here)\n", .{});
    try fx.pm.processAllMessages();
    try testing.expectEqual(@as(usize, 1), fx.pm.peers.items.len); // A reaped, stub left
    // The remote side saw the connection close.
    var buf: [8]u8 = undefined;
    const n = try std.posix.read(fds[1], &buf);
    try testing.expectEqual(@as(usize, 0), n);
    const lock_violations = instrumentOff(lock_v0);
    if (lock_violations != 0) std.debug.print("[CB-5] lock-held instrument: {d} violation(s)\n", .{lock_violations});
    try testing.expectEqual(@as(u64, 0), lock_violations);
}

// ====================================================================
// CB-6: RPC submitblock connects the block the P2P drain already checked;
// the drain's connect then fails and the node aborts.
// ====================================================================

const SubmitCtx = struct {
    fx: *Fixture,
    body: []const u8,
    response: ?[]const u8 = null,
    fn run(self: *SubmitCtx) void {
        self.response = self.fx.rpcCall(self.body) catch null;
    }
};

test "tests_chain_lock CB-6: submitblock racing the P2P drain must not abort the node" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();
    defer fatal.resetForTest();

    var a1 = try mineBlock(allocator, &fx.params, fx.params.genesis_hash, 1, 0xA1, null);
    defer serialize.freeBlock(allocator, &a1.block);
    try fx.p2pDeliver(&a1);
    var b2 = try mineBlock(allocator, &fx.params, a1.hash, 2, 0xB2, null);
    defer serialize.freeBlock(allocator, &b2.block);

    const lock_v0 = instrumentOn();
    defer instrumentForceOff();
    hooks.arm(.drain_after_parent_check, &b2.hash);
    var pctx = DeliverCtx{ .fx = &fx, .blk = &b2 };
    var p = Racer(DeliverCtx, DeliverCtx.run){ .ctx = &pctx };
    try p.start();
    try testing.expect(hooks.waitParked(.drain_after_parent_check, 5000));

    const hex = try blockHex(allocator, &b2.block);
    defer allocator.free(hex);
    const body = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"submitblock\",\"params\":[\"{s}\"]}}", .{hex});
    defer allocator.free(body);
    var rctx = SubmitCtx{ .fx = &fx, .body = body };
    var r = Racer(SubmitCtx, SubmitCtx.run){ .ctx = &rctx };
    try r.start();
    const rpc_finished_during_drain = r.finishesWithin(RACE_WINDOW_MS);
    hooks.release(.drain_after_parent_check);
    p.join();
    r.join();
    if (rctx.response) |x| allocator.free(x);

    const aborted = fatal.isLatched();
    std.debug.print(
        "\n[CB-6] submitblock_finished_while_drain_parked={} node_aborted={} tip={d}\n",
        .{ rpc_finished_during_drain, aborted, fx.cs.best_height },
    );
    try testing.expect(!rpc_finished_during_drain);
    try testing.expect(!aborted);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);
    const lock_violations = instrumentOff(lock_v0);
    if (lock_violations != 0) std.debug.print("[CB-6] lock-held instrument: {d} violation(s)\n", .{lock_violations});
    try testing.expectEqual(@as(u64, 0), lock_violations);
}

// ====================================================================
// CB-8: one trickling inbound connection freezes the P2P thread
// ====================================================================

const TrickleCtx = struct {
    port: u16,
    magic: u32,
    bytes: usize,
    gap_ms: u64,
    fn run(self: *TrickleCtx) void {
        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, self.port);
        const s = std.net.tcpConnectToAddress(addr) catch return;
        defer s.close();
        var hdr: [24]u8 = [_]u8{0} ** 24;
        std.mem.writeInt(u32, hdr[0..4], self.magic, .little);
        @memcpy(hdr[4..11], "version");
        std.mem.writeInt(u32, hdr[16..20], 100, .little);
        var i: usize = 0;
        while (i < self.bytes) : (i += 1) {
            _ = s.write(hdr[i % 24 .. i % 24 + 1]) catch return;
            std.time.sleep(self.gap_ms * std.time.ns_per_ms);
        }
    }
};

test "tests_chain_lock CB-8: a trickling inbound peer must not hold the P2P thread" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();

    // Ephemeral listener.
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    fx.pm.listener = try addr.listen(.{ .reuse_address = true });
    const port = fx.pm.listener.?.listen_address.getPort();

    // 20 bytes, one every 400 ms: an 8 s trickle that never finishes a header.
    var tctx = TrickleCtx{ .port = port, .magic = fx.params.magic, .bytes = 20, .gap_ms = 400 };
    const t = try std.Thread.spawn(.{}, TrickleCtx.run, .{&tctx});
    defer t.join();
    std.time.sleep(100 * std.time.ns_per_ms); // let it connect

    const t0 = std.time.milliTimestamp();
    try fx.pm.acceptInbound();
    const held_ms = std.time.milliTimestamp() - t0;
    std.debug.print("\n[CB-8] acceptInbound held the P2P thread for {d} ms\n", .{held_ms});
    try testing.expect(held_ms < 1000);
}
