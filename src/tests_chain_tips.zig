//! getchaintips after failed reorgs, invalidateblock / reconsiderblock round
//! trips and restarts.
//!
//! Same block shapes as the core-regtest `failed_reorg` group, on real regtest
//! blocks driven through the live submitblock path and the call sequence the
//! invalidateblock / reconsiderblock RPC handlers run, read back through the
//! getchaintips RPC handler.  Expected values are Core v31.1's (the
//! core-regtest rows named in each test).
//!
//! Core reference: rpc/blockchain.cpp getchaintips (every block off the active
//! chain that no other such block builds on, plus the active tip; status
//! active / invalid / headers-only / valid-fork / valid-headers), and
//! validation.cpp: BLOCK_VALID_SCRIPTS stays set when DisconnectTip takes a
//! block off the active chain, and BLOCK_FAILED_VALID from InvalidBlockFound
//! is written to the block index, so both survive a restart.
//!
//! A "restart" reopens the ChainState on the same database and builds a fresh
//! ChainManager holding only genesis, as main.zig does at boot.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const validation = @import("validation.zig");
const block_template = @import("block_template.zig");
const rpc = @import("rpc.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");

const params = &consensus.REGTEST;

const Blk = struct { block: types.Block, hash: types.Hash256 };

/// Coinbase-only regtest block at `height` (<= 16) on `prev`, paying the
/// subsidy plus `overpay` sat.  `tag` makes same-height siblings distinct.
fn mine(allocator: std.mem.Allocator, prev: types.Hash256, height: u32, overpay: i64, tag: u8) !Blk {
    std.debug.assert(height >= 1 and height <= 16);
    const script_sig = try allocator.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag });
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const spk = try allocator.dupe(u8, &[_]u8{0x51});
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000 + overpay, .script_pubkey = spk };
    const txs = try allocator.alloc(types.Transaction, 1);
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeTxid(&txs[0], allocator),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

/// A regtest node: database, chain state and chain manager.  `restart`
/// drops the chain state and the in-memory block index and reloads both
/// from the database.
const Node = struct {
    allocator: std.mem.Allocator,
    db: *storage.Database,
    cs: *storage.ChainState,
    cm: *validation.ChainManager,

    fn boot(allocator: std.mem.Allocator, db: *storage.Database) !Node {
        const cs = try allocator.create(storage.ChainState);
        cs.* = storage.ChainState.init(db, 64, allocator);
        cs.wireUtxoParent();
        cs.setNetworkParams(params);
        cs.best_hash = params.genesis_hash;
        cs.initGenesisTimestamp(params.genesis_header.timestamp);
        cs.initGenesisRetarget(params.genesis_header.timestamp, params.genesis_header.bits);
        // main.zig: nChainWork(genesis) = GetBlockProof(genesis), so the
        // persisted per-height work is genesis-scale (Core's).
        cs.seedGenesisTotalWork(params.genesis_header.bits);
        // main.zig: load the persisted tip.
        if (try db.get(storage.CF_DEFAULT, "chain_tip")) |data| {
            defer allocator.free(data);
            if (data.len == 36) {
                @memcpy(&cs.best_hash, data[0..32]);
                cs.best_height = std.mem.readInt(u32, data[32..36], .little);
                cs.restoreTotalWork(params);
            }
        }
        const cm = try allocator.create(validation.ChainManager);
        cm.* = validation.ChainManager.init(cs, null, allocator);
        try cm.loadGenesis(params);
        return .{ .allocator = allocator, .db = db, .cs = cs, .cm = cm };
    }

    fn shutdown(self: *Node) void {
        self.cs.flush() catch {};
        self.cm.deinit();
        self.allocator.destroy(self.cm);
        self.cs.deinit();
        self.allocator.destroy(self.cs);
    }

    fn restart(self: *Node) !void {
        self.shutdown();
        self.* = try Node.boot(self.allocator, self.db);
    }

    fn submit(self: *Node, b: *const Blk) !block_template.SubmitResult {
        return block_template.submitBlockWithIndex(&b.block, self.cs, params, self.cm, self.allocator);
    }

    /// handleInvalidateBlock's call sequence.
    fn invalidate(self: *Node, hash: types.Hash256) !void {
        block_template.syncChainManagerFromDisk(self.cm, self.cs, self.allocator);
        _ = block_template.ensureIndexed(self.cm, self.cs, &hash, self.allocator);
        try self.cm.invalidateBlock(&hash);
    }

    /// handleReconsiderBlock's call sequence.
    fn reconsider(self: *Node, hash: types.Hash256) !void {
        block_template.syncChainManagerFromDisk(self.cm, self.cs, self.allocator);
        _ = block_template.ensureIndexed(self.cm, self.cs, &hash, self.allocator);
        try self.cm.reconsiderBlock(&hash);
    }

    fn expectTip(self: *Node, want: *const Blk, height: u32) !void {
        try testing.expectEqual(height, self.cs.best_height);
        try testing.expectEqualSlices(u8, &want.hash, &self.cs.best_hash);
    }
};

const Fixture = struct {
    tmp: testing.TmpDir,
    path: []u8,
    db: *storage.Database,
    arena: std.heap.ArenaAllocator,

    fn init() !Fixture {
        const allocator = testing.allocator;
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const path = try tmp.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(path);
        const db = try allocator.create(storage.Database);
        db.* = try storage.Database.open(path, 64, allocator);
        return .{ .tmp = tmp, .path = path, .db = db, .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    fn deinit(self: *Fixture) void {
        const allocator = testing.allocator;
        self.arena.deinit();
        self.db.close();
        allocator.destroy(self.db);
        allocator.free(self.path);
        self.tmp.cleanup();
    }
};

fn expectAccepted(r: block_template.SubmitResult) !void {
    if (!r.accepted) {
        std.debug.print("submitblock rejected: {?s}\n", .{r.reject_reason});
        return error.TestUnexpectedReject;
    }
}

const Tip = struct { height: i64, branchlen: i64, status: []const u8 };

/// getchaintips through the RPC handler, on the node's current chain state and
/// chain manager.  Returns the response text (caller frees).
fn chainTipsJson(node: *Node) ![]const u8 {
    const allocator = testing.allocator;
    var mp = mempool_mod.Mempool.init(null, null, allocator);
    defer mp.deinit();
    var pm = peer_mod.PeerManager.init(allocator, params);
    defer pm.deinit();
    var srv = rpc.RpcServer.init(allocator, node.cs, &mp, &pm, params, .{});
    defer srv.deinit();
    srv.setChainManager(node.cm);
    return srv.dispatch("{\"id\":1,\"method\":\"getchaintips\",\"params\":[]}");
}

fn hashHex(hash: types.Hash256) [64]u8 {
    var hex: [64]u8 = undefined;
    for (0..32) |i| _ = std.fmt.bufPrint(hex[i * 2 ..][0..2], "{x:0>2}", .{hash[31 - i]}) catch unreachable;
    return hex;
}

/// The getchaintips entry for `hash`, or null when the node does not list it.
fn findTip(node: *Node, hash: types.Hash256, out_status: []u8) !?Tip {
    const allocator = testing.allocator;
    const resp = try chainTipsJson(node);
    defer allocator.free(resp);
    var p = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer p.deinit();
    const result = p.value.object.get("result") orelse return error.NoResult;
    const want = hashHex(hash);
    for (result.array.items) |t| {
        if (!std.mem.eql(u8, t.object.get("hash").?.string, &want)) continue;
        const st = t.object.get("status").?.string;
        @memcpy(out_status[0..st.len], st);
        return .{
            .height = t.object.get("height").?.integer,
            .branchlen = t.object.get("branchlen").?.integer,
            .status = out_status[0..st.len],
        };
    }
    return null;
}

fn tipCount(node: *Node) !usize {
    const allocator = testing.allocator;
    const resp = try chainTipsJson(node);
    defer allocator.free(resp);
    var p = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer p.deinit();
    return p.value.object.get("result").?.array.items.len;
}

fn expectTipRow(node: *Node, hash: types.Hash256, height: i64, branchlen: i64, status: []const u8) !void {
    var sbuf: [32]u8 = undefined;
    const t = (try findTip(node, hash, &sbuf)) orelse {
        const resp = try chainTipsJson(node);
        defer testing.allocator.free(resp);
        std.debug.print("tip {s} missing from getchaintips: {s}\n", .{ &hashHex(hash), resp });
        return error.TipMissing;
    };
    if (t.height != height or t.branchlen != branchlen or !std.mem.eql(u8, t.status, status)) {
        std.debug.print("tip {s}: got height {d} branchlen {d} status {s}, want {d} {d} {s}\n", .{ &hashHex(hash), t.height, t.branchlen, t.status, height, branchlen, status });
        return error.TipMismatch;
    }
}

const RoundTrip = struct { r2: Blk, x3: Blk, x4: Blk, y3: Blk, y4: Blk };

/// Scenario C / E shape: r1-r2-x3-x4 active, y3-y4 an equal-work side branch
/// submitted afterwards.
fn roundTripChain(node: *Node, a: std.mem.Allocator, tag: u8) !RoundTrip {
    const r1 = try mine(a, params.genesis_hash, 1, 0, tag);
    const r2 = try mine(a, r1.hash, 2, 0, tag + 1);
    const x3 = try mine(a, r2.hash, 3, 0, tag + 2);
    const x4 = try mine(a, x3.hash, 4, 0, tag + 3);
    const y3 = try mine(a, r2.hash, 3, 0, tag + 4);
    const y4 = try mine(a, y3.hash, 4, 0, tag + 5);
    for ([_]*const Blk{ &r1, &r2, &x3, &x4 }) |b| try expectAccepted(try node.submit(b));
    for ([_]*const Blk{ &y3, &y4 }) |b| _ = try node.submit(b);
    try node.expectTip(&x4, 4);
    return .{ .r2 = r2, .x3 = x3, .x4 = x4, .y3 = y3, .y4 = y4 };
}

// core-regtest failed_reorg/c-before and c-reconsider/tips:795f067e (c4s):
// Core height 13, branchlen 2, valid-headers before the round trip (never
// connected), valid-fork after reconsiderblock displaced it (connected while
// c4a was invalidated).  clearbit listed only the active tip.
test "chain_tips: c-reconsider lists the block reconsiderblock displaced as a valid-fork tip" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();
    const rt = try roundTripChain(&node, a, 0x10);

    // c-before: the side tip was never connected.
    try expectTipRow(&node, rt.y4.hash, 4, 2, "valid-headers");
    try expectTipRow(&node, rt.x4.hash, 4, 0, "active");

    // c-invalidate: x4 is an invalid tip, y4 active.
    try node.invalidate(rt.x4.hash);
    try node.expectTip(&rt.y4, 4);
    try expectTipRow(&node, rt.x4.hash, 4, 2, "invalid");
    try expectTipRow(&node, rt.y4.hash, 4, 0, "active");

    // c-reconsider: x4 wins the tie, y4 is displaced.
    try node.reconsider(rt.x4.hash);
    try node.expectTip(&rt.x4, 4);
    try expectTipRow(&node, rt.y4.hash, 4, 2, "valid-fork");
    try expectTipRow(&node, rt.x4.hash, 4, 0, "active");
    try testing.expectEqual(@as(usize, 2), try tipCount(&node));
}

// core-regtest failed_reorg/e-reconsider/tips:640d52da (e4a): invalidateblock,
// restart, reconsiderblock.  The tip loaded from disk wins the tie, so e4a
// stays off the active chain; Core reports it valid-fork, branchlen 2.
test "chain_tips: e-reconsider lists the reconsidered block that lost the tie after a restart as a valid-fork tip" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();
    const rt = try roundTripChain(&node, a, 0x30);

    try node.invalidate(rt.x4.hash);
    try node.expectTip(&rt.y4, 4);
    try node.restart();
    // e-restart-invalidated: still an invalid tip after the restart.
    try expectTipRow(&node, rt.x4.hash, 4, 2, "invalid");

    try node.reconsider(rt.x4.hash);
    try node.expectTip(&rt.y4, 4);
    try expectTipRow(&node, rt.x4.hash, 4, 2, "valid-fork");
    try expectTipRow(&node, rt.y4.hash, 4, 0, "active");
    try testing.expectEqual(@as(usize, 2), try tipCount(&node));
}

// core-regtest failed_reorg/e-restart/tips:640d52da: the same block after a
// second restart.  Only durable state is left; Core still reports valid-fork.
test "chain_tips: e-restart keeps the displaced block as a valid-fork tip across a restart" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();
    const rt = try roundTripChain(&node, a, 0x50);

    try node.invalidate(rt.x4.hash);
    try node.restart();
    try node.reconsider(rt.x4.hash);
    try node.restart();
    try node.expectTip(&rt.y4, 4);
    try expectTipRow(&node, rt.x4.hash, 4, 2, "valid-fork");
    try expectTipRow(&node, rt.y4.hash, 4, 0, "active");
    try testing.expectEqual(@as(usize, 2), try tipCount(&node));
}

// Scenario A (core-regtest failed_reorg/a-*): a heavier side branch whose last
// block is invalid.  Core connects 3', fails 4' (bad-cb-amount), marks it
// BLOCK_FAILED_VALID and returns to 3; 4' is an invalid tip, branchlen 2, and
// stays invalid after a restart.  The guard half: the valid block under it
// (3') is NOT marked, so a valid child of 3' still connects and wins.
test "chain_tips: a block that fails the reorg connect is an invalid tip, durably, and its valid parent is not marked" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const a1 = try mine(a, params.genesis_hash, 1, 0, 0x71);
    const a2 = try mine(a, a1.hash, 2, 0, 0x72);
    const a3 = try mine(a, a2.hash, 3, 0, 0x73);
    const a3s = try mine(a, a2.hash, 3, 0, 0x83);
    const a4s_bad = try mine(a, a3s.hash, 4, 1, 0x84);
    for ([_]*const Blk{ &a1, &a2, &a3 }) |b| try expectAccepted(try node.submit(b));
    _ = try node.submit(&a3s);
    const r = try node.submit(&a4s_bad);
    try testing.expect(!r.accepted);
    try node.expectTip(&a3, 3);
    try expectTipRow(&node, a4s_bad.hash, 4, 2, "invalid");

    try node.restart();
    try node.expectTip(&a3, 3);
    try expectTipRow(&node, a4s_bad.hash, 4, 2, "invalid");

    // A valid block on 3' is more work than 3: it connects, so 3' was not
    // failed along with 4'.
    const a4s_good = try mine(a, a3s.hash, 4, 0, 0x94);
    try expectAccepted(try node.submit(&a4s_good));
    try node.expectTip(&a4s_good, 4);
    try expectTipRow(&node, a4s_bad.hash, 4, 1, "invalid");
    // a3 was connected and is now displaced.
    try expectTipRow(&node, a3.hash, 3, 1, "valid-fork");
}

// Scenario B (core-regtest failed_reorg/b-invalidate and b-restart): the bad
// tip of the side branch that invalidateblock reorged onto is an invalid tip
// (branchlen 1 off 4'), and the invalidated 4a's child 5a is invalid too
// (branchlen 3), before and after a restart.
test "chain_tips: invalidateblock onto a side branch with a bad tip lists both invalid tips across a restart" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const b1 = try mine(a, params.genesis_hash, 1, 0, 0xA1);
    const b2 = try mine(a, b1.hash, 2, 0, 0xA2);
    const b3a = try mine(a, b2.hash, 3, 0, 0xA3);
    const b4a = try mine(a, b3a.hash, 4, 0, 0xA4);
    const b5a = try mine(a, b4a.hash, 5, 0, 0xA5);
    const b3s = try mine(a, b2.hash, 3, 0, 0xB3);
    const b4s = try mine(a, b3s.hash, 4, 0, 0xB4);
    const b5s_bad = try mine(a, b4s.hash, 5, 1, 0xB5);
    for ([_]*const Blk{ &b1, &b2, &b3a, &b4a, &b5a }) |b| try expectAccepted(try node.submit(b));
    for ([_]*const Blk{ &b3s, &b4s, &b5s_bad }) |b| _ = try node.submit(b);

    // b-before: the unvalidated side tip.
    try expectTipRow(&node, b5s_bad.hash, 5, 3, "valid-headers");

    try node.invalidate(b4a.hash);
    try node.expectTip(&b4s, 4);
    try expectTipRow(&node, b5s_bad.hash, 5, 1, "invalid");
    try expectTipRow(&node, b5a.hash, 5, 3, "invalid");
    try expectTipRow(&node, b4s.hash, 4, 0, "active");
    try testing.expectEqual(@as(usize, 3), try tipCount(&node));

    try node.restart();
    try node.expectTip(&b4s, 4);
    try expectTipRow(&node, b5s_bad.hash, 5, 1, "invalid");
    try expectTipRow(&node, b5a.hash, 5, 3, "invalid");
    try testing.expectEqual(@as(usize, 3), try tipCount(&node));
}
