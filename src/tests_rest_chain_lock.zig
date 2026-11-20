//! REST handlers must run under the chain lock (cs_main), like every JSON-RPC
//! handler does (`handleSingleRequest`).
//!
//! clearbit answers `GET /rest/...` on the RPC server's connection threads,
//! unauthenticated.  Before this fix the REST branch of `handleConnection`
//! took only `serve_mutex` (which orders RPC requests among themselves, not
//! against the P2P thread), so `/rest/getutxos` called `UtxoSet.get` — whose
//! cold-read path inserts into the coin cache and may evict — while the P2P
//! thread connected blocks.  That is the CB-1 race (tests_chain_lock.zig)
//! reached through the REST door: the REST read caches a coin the P2P thread
//! has just spent, and the next block double-spending it connects.  Every
//! other REST endpoint likewise read the tip, block index and mempool without
//! the lock.
//!
//! Core: rest.cpp takes `LOCK(cs_main)` (and `LOCK2(cs_main, mempool.cs)` in
//! rest_getutxos / rest_tx / rest_mempool) for every chain or mempool read.
//!
//! The tests drive the REAL HTTP path: an `RpcServer` listening on an
//! ephemeral loopback port, its accept loop on a thread, and plain HTTP GETs.
//!
//! Run: `zig build test-rest-chain-lock` (also folded into `zig build test`).

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
const hooks = @import("test_hooks.zig");

/// How long the racing thread is given to finish while the other side holds
/// (or should hold) the chain lock.  Without the lock it needs milliseconds.
const RACE_WINDOW_MS: u64 = 1500;

fn instrumentOn() u64 {
    storage.chain_lock.debug_checks.store(true, .seq_cst);
    return storage.chain_lock.violations.load(.seq_cst);
}

fn instrumentForceOff() void {
    storage.chain_lock.debug_checks.store(false, .seq_cst);
}

fn instrumentOff(v0: u64) u64 {
    storage.chain_lock.debug_checks.store(false, .seq_cst);
    return storage.chain_lock.violations.load(.seq_cst) - v0;
}

// ====================================================================
// Fixture (same shape as tests_chain_lock.zig, plus a listening server)
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
    server_thread: ?std.Thread = null,
    port: u16 = 0,

    fn init(self: *Fixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.server_thread = null;
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
        self.server = rpc.RpcServer.init(allocator, &self.cs, &self.mp, &self.pm, &self.params, .{ .port = 0 });
        self.src_peer = try stubPeer(&self.params, allocator, 3, -1);
        try self.pm.peers.append(self.src_peer);

        // Listen on an ephemeral port; record it so stop() can wake accept().
        try self.server.start();
        self.port = self.server.listener.?.listen_address.getPort();
        self.server.config.port = self.port;
        self.server_thread = try std.Thread.spawn(.{}, serverRun, .{&self.server});
    }

    fn serverRun(s: *rpc.RpcServer) void {
        s.run() catch {};
    }

    fn deinit(self: *Fixture) void {
        hooks.reset();
        self.server.stop();
        if (self.server_thread) |t| t.join();
        self.server.deinit();
        for (self.pm.peers.items, 0..) |p, i| {
            if (p == self.src_peer) {
                _ = self.pm.peers.swapRemove(i);
                break;
            }
        }
        self.src_peer.recv_buffer.deinit();
        self.allocator.destroy(self.src_peer);
        self.pm.deinit();
        var it = self.mp.entries.valueIterator();
        while (it.next()) |e| serialize.freeTransaction(self.allocator, &e.*.tx);
        self.mp.deinit();
        self.cs.deinit();
        self.db.close();
        self.allocator.free(self.path);
        self.tmp_dir.cleanup();
    }

    fn p2pDeliver(self: *Fixture, b: *const IbBlock) !void {
        const hs = try self.allocator.alloc(types.BlockHeader, 1);
        hs[0] = b.block.header;
        try self.pm.ingestHeadersMessage(self.src_peer, hs);
        try self.pm.ingestBlockMessage(self.src_peer, try cloneBlock(self.allocator, &b.block));
    }

    /// Plain HTTP GET against the fixture's server; returns the whole reply
    /// (status line, headers and body).  Caller frees.
    fn httpGet(self: *Fixture, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, self.port);
        const conn = try std.net.tcpConnectToAddress(addr);
        defer conn.close();
        const req = try std.fmt.allocPrint(allocator, "GET {s} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", .{path});
        defer allocator.free(req);
        try conn.writeAll(req);
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = try conn.read(&buf);
            if (n == 0) break;
            try out.appendSlice(buf[0..n]);
        }
        return out.toOwnedSlice();
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

/// Display (RPC) hex of a hash.
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

/// Persist a confirmed coin in the coin DB and drop the cache, so the next
/// read is a cold DB read-through (the path that inserts into the cache).
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

const GetCtx = struct {
    fx: *Fixture,
    path: []const u8,
    response: ?[]u8 = null,
    fn run(self: *GetCtx) void {
        // page_allocator: the reply is freed by the test thread.
        self.response = self.fx.httpGet(std.heap.page_allocator, self.path) catch null;
    }
};

const DeliverCtx = struct {
    fx: *Fixture,
    blk: *const IbBlock,
    fn run(self: *DeliverCtx) void {
        self.fx.p2pDeliver(self.blk) catch {};
    }
};

// ====================================================================
// 1. /rest/getutxos racing a P2P block connect (CB-1 through REST)
// ====================================================================

test "tests_rest_chain_lock: REST getutxos racing a P2P block connect must not resurrect the spent coin" {
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
    const path = try std.fmt.allocPrint(allocator, "/rest/getutxos/{s}-0.json", .{g_hex});
    defer allocator.free(path);

    // REST thread: getutxos reads the coin from the DB and freezes before
    // caching it.
    const lock_v0 = instrumentOn();
    defer instrumentForceOff();
    const key = storage.makeUtxoKey(&g);
    hooks.arm(.utxo_get_after_db_read, &key);
    var rctx = GetCtx{ .fx = &fx, .path = path };
    var r = Racer(GetCtx, GetCtx.run){ .ctx = &rctx };
    try r.start();
    try testing.expect(hooks.waitParked(.utxo_get_after_db_read, 5000));

    // P2P thread: block 2 spending the coin arrives and is connected.
    var pctx = DeliverCtx{ .fx = &fx, .blk = &b2 };
    var p = Racer(DeliverCtx, DeliverCtx.run){ .ctx = &pctx };
    try p.start();
    const p2p_finished_during_rest = p.finishesWithin(RACE_WINDOW_MS);
    hooks.release(.utxo_get_after_db_read);
    r.join();
    p.join();
    const first = rctx.response orelse return error.NoRestReply;
    defer std.heap.page_allocator.free(first);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 200"));
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);

    // After block 2 the coin is spent.  Ask again (Core: bitmap "0").
    const after = try fx.httpGet(allocator, path);
    defer allocator.free(after);
    const resurrected = std.mem.indexOf(u8, after, "\"bitmap\":\"1\"") != null;

    // Consequence: a block double-spending the coin.
    var b3 = try mineBlock(allocator, &fx.params, b2.hash, 3, 0xB3, g);
    defer serialize.freeBlock(allocator, &b3.block);
    try fx.p2pDeliver(&b3);
    const double_spend_connected = fx.cs.best_height == 3;

    const lock_violations = instrumentOff(lock_v0);
    std.debug.print(
        "\n[REST-getutxos] p2p_connect_finished_while_rest_parked={} rest_after_spend_returns_coin={} double_spend_block_connected={} lock_violations={d}\n",
        .{ p2p_finished_during_rest, resurrected, double_spend_connected, lock_violations },
    );
    try testing.expect(!p2p_finished_during_rest);
    try testing.expect(!resurrected);
    try testing.expect(!double_spend_connected);
    try testing.expectEqual(@as(u64, 0), lock_violations);
}

// ====================================================================
// 2. Every REST endpoint waits for cs_main
// ====================================================================

test "tests_rest_chain_lock: every REST endpoint waits for the chain lock" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();

    var a1 = try mineBlock(allocator, &fx.params, fx.params.genesis_hash, 1, 0xA1, null);
    defer serialize.freeBlock(allocator, &a1.block);
    try fx.p2pDeliver(&a1);
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);

    const bh = hashHexDisplay(a1.hash);
    const cb_txid = hashHexDisplay(try crypto.computeTxid(&a1.block.transactions[0], allocator));

    const paths = [_][]const u8{
        try std.fmt.allocPrint(allocator, "/rest/block/{s}.json", .{bh}),
        try std.fmt.allocPrint(allocator, "/rest/block/notxdetails/{s}.json", .{bh}),
        try std.fmt.allocPrint(allocator, "/rest/blockfilter/basic/{s}.json", .{bh}),
        try std.fmt.allocPrint(allocator, "/rest/blockfilterheaders/basic/1/{s}.json", .{bh}),
        try allocator.dupe(u8, "/rest/blockhashbyheight/1.json"),
        try allocator.dupe(u8, "/rest/chaininfo.json"),
        try std.fmt.allocPrint(allocator, "/rest/getutxos/checkmempool/{s}-0.json", .{cb_txid}),
        try allocator.dupe(u8, "/rest/mempool/info.json"),
        try allocator.dupe(u8, "/rest/mempool/contents.json"),
        try std.fmt.allocPrint(allocator, "/rest/tx/{s}.json", .{cb_txid}),
        try std.fmt.allocPrint(allocator, "/rest/headers/1/{s}.json", .{bh}),
    };
    defer for (paths) |pth| allocator.free(pth);

    var unlocked = std.ArrayList([]const u8).init(allocator);
    defer unlocked.deinit();

    for (paths) |pth| {
        // Stand in for the P2P thread mid-connect: hold cs_main.
        fx.cs.connect_mutex.lock();
        var ctx = GetCtx{ .fx = &fx, .path = pth };
        var r = Racer(GetCtx, GetCtx.run){ .ctx = &ctx };
        r.start() catch |e| {
            fx.cs.connect_mutex.unlock();
            return e;
        };
        const answered_without_lock = r.finishesWithin(RACE_WINDOW_MS);
        fx.cs.connect_mutex.unlock();
        const answered_after = r.finishesWithin(10_000);
        r.join();
        const resp = ctx.response;
        defer if (resp) |x| std.heap.page_allocator.free(x);
        std.debug.print("[REST-lock] {s}: answered_while_cs_main_held={} answered_after_release={} status={s}\n", .{
            pth,
            answered_without_lock,
            answered_after,
            if (resp) |x| x[0..@min(x.len, 12)] else "none",
        });
        try testing.expect(answered_after);
        try testing.expect(resp != null);
        if (answered_without_lock) try unlocked.append(pth);
    }
    if (unlocked.items.len != 0) {
        std.debug.print("[REST-lock] {d} of {d} endpoints answered while cs_main was held\n", .{ unlocked.items.len, paths.len });
    }
    try testing.expectEqual(@as(usize, 0), unlocked.items.len);
}

// ====================================================================
// 3. /rest/blockfilterheaders must NOT hold cs_main for its filter walk
// ====================================================================
//
// The handler recomputes every filter from genesis to the requested block.
// Run under cs_main, one unauthenticated GET at mainnet height would stall
// block connection for the whole walk.  It must collect the hashes it needs
// under the lock and release it for the filter work: a P2P block connect
// must complete while the REST request is parked inside the walk.

test "tests_rest_chain_lock: REST blockfilterheaders releases the chain lock for its filter walk" {
    // The park point exists only once the walk runs in a lock-free window.
    if (comptime !@hasField(hooks.Point, "rest_filter_walk")) return error.SkipZigTest;
    const validation = @import("validation.zig");
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator);
    defer fx.deinit();

    var a1 = try mineBlock(allocator, &fx.params, fx.params.genesis_hash, 1, 0xA1, null);
    defer serialize.freeBlock(allocator, &a1.block);
    try fx.p2pDeliver(&a1);
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);

    // Block index for the REST handler: genesis <- a1.
    var cm = validation.ChainManager.init(&fx.cs, &fx.mp, allocator);
    defer cm.deinit();
    try cm.loadGenesis(&fx.params);
    const g_entry = cm.getBlock(&fx.params.genesis_hash).?;
    const a1_entry = try allocator.create(validation.BlockIndexEntry);
    a1_entry.* = .{
        .hash = a1.hash,
        .header = a1.block.header,
        .height = 1,
        .status = .{ .has_data = true },
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = g_entry,
        .file_number = 0,
        .file_offset = 0,
    };
    try cm.addBlock(a1_entry);
    cm.active_tip = a1_entry;
    fx.server.setChainManager(&cm);

    const bh = hashHexDisplay(a1.hash);
    const path = try std.fmt.allocPrint(allocator, "/rest/blockfilterheaders/basic/1/{s}.json", .{bh});
    defer allocator.free(path);

    hooks.arm(.rest_filter_walk, null);
    var rctx = GetCtx{ .fx = &fx, .path = path };
    var r = Racer(GetCtx, GetCtx.run){ .ctx = &rctx };
    try r.start();
    try testing.expect(hooks.waitParked(.rest_filter_walk, 5000));

    // P2P thread: block 2 arrives and is connected while REST is mid-walk.
    var b2 = try mineBlock(allocator, &fx.params, a1.hash, 2, 0xB2, null);
    defer serialize.freeBlock(allocator, &b2.block);
    var pctx = DeliverCtx{ .fx = &fx, .blk = &b2 };
    var p = Racer(DeliverCtx, DeliverCtx.run){ .ctx = &pctx };
    try p.start();
    const p2p_finished_during_walk = p.finishesWithin(RACE_WINDOW_MS);
    hooks.release(.rest_filter_walk);
    r.join();
    p.join();
    const resp = rctx.response orelse return error.NoRestReply;
    defer std.heap.page_allocator.free(resp);
    std.debug.print("\n[REST-filterheaders] p2p_connect_finished_during_walk={} status={s}\n", .{
        p2p_finished_during_walk,
        resp[0..@min(resp.len, 12)],
    });
    try testing.expect(p2p_finished_during_walk);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200"));

    // The reply is still right: the one header (block a1) equals the
    // `header` that JSON-RPC getblockfilter computes for a1 by its own,
    // unchanged walk.
    const body_at = (std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return error.NoBody) + 4;
    const rest_body = resp[body_at..];
    const rpc_req = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockfilter\",\"params\":[\"{s}\"]}}", .{bh});
    defer allocator.free(rpc_req);
    // getblockfilter refuses without the index flag; no filter is persisted,
    // so it still computes every filter on demand, as the REST call did.
    fx.cs.blockfilterindex_enabled = true;
    const rpc_resp = try fx.server.dispatch(rpc_req);
    fx.cs.blockfilterindex_enabled = false;
    defer allocator.free(rpc_resp);
    const hk = "\"header\":\"";
    const hi = (std.mem.indexOf(u8, rpc_resp, hk) orelse return error.NoHeaderField) + hk.len;
    const want_header = rpc_resp[hi .. hi + 64];
    const want_body = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{want_header});
    defer allocator.free(want_body);
    std.debug.print("[REST-filterheaders] rest={s} getblockfilter.header={s}\n", .{ rest_body, want_header });
    try testing.expectEqualStrings(want_body, rest_body);
}
