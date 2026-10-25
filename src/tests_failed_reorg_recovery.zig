//! Failed-reorg recovery through invalidateblock / reconsiderblock.
//!
//! Same block shapes as the core-regtest `failed_reorg` group (scenarios B,
//! C and E), on real regtest blocks driven through the live submitblock path
//! (block_template.submitBlockWithIndex) and the exact call sequence the
//! invalidateblock / reconsiderblock RPC handlers run (syncChainManagerFromDisk
//! + ensureIndexed + ChainManager).  A bad block's coinbase pays one satoshi
//! over the subsidy, so the reorg connect fails it bad-cb-amount.
//!
//! Core reference (validation.cpp):
//!   * ActivateBestChain loops: when ConnectTip fails a block of the
//!     most-work candidate, InvalidBlockFound marks it and the next
//!     most-work chain is tried, usually the valid prefix of that branch.
//!     invalidateblock then answers null.
//!   * CBlockIndexWorkComparator: most work, then lowest nSequenceId (the
//!     block received first), so a reconsidered block that was received
//!     first wins an equal-work tie.
//!   * LoadChainTip: after a restart the active chain gets nSequenceId 0 and
//!     every other block 1, so the pre-restart tip wins the tie.
//!
//! A "restart" here reopens the ChainState on the same database and builds a
//! fresh ChainManager holding only genesis, as main.zig does at boot.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const validation = @import("validation.zig");
const block_template = @import("block_template.zig");

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

// Scenario B (KB-176):
//
//     G-1-2-3a-4a-5a
//          \-3'-4'-5''      (5'' pays one satoshi too much)
//
// The side blocks arrive while 5a is the tip.  invalidateblock 4a leaves 5''
// as the most-work candidate: Core connects 3' and 4', fails 5'', and stays
// on 4' because that valid prefix has more work than 3a.
test "failed_reorg_recovery: invalidateblock connects the valid prefix of a side branch whose tip is invalid, and it survives a restart" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const b1 = try mine(a, params.genesis_hash, 1, 0, 0x31);
    const b2 = try mine(a, b1.hash, 2, 0, 0x32);
    const b3a = try mine(a, b2.hash, 3, 0, 0x33);
    const b4a = try mine(a, b3a.hash, 4, 0, 0x34);
    const b5a = try mine(a, b4a.hash, 5, 0, 0x35);
    const b3s = try mine(a, b2.hash, 3, 0, 0x43);
    const b4s = try mine(a, b3s.hash, 4, 0, 0x44);
    const b5s_bad = try mine(a, b4s.hash, 5, 1, 0x45);

    for ([_]*const Blk{ &b1, &b2, &b3a, &b4a, &b5a }) |b| try expectAccepted(try node.submit(b));
    for ([_]*const Blk{ &b3s, &b4s, &b5s_bad }) |b| _ = try node.submit(b);
    try node.expectTip(&b5a, 5);

    // Core: null.  Pre-fix: DisconnectFailed ("Failed to disconnect block")
    // with the tip left on 3a.
    try node.invalidate(b4a.hash);
    try node.expectTip(&b4s, 4);
    try testing.expect(!node.cs.flush_error);
    const e5 = node.cm.getBlock(&b5s_bad.hash).?;
    try testing.expect(e5.status.failed_valid);
    const e4s = node.cm.getBlock(&b4s.hash).?;
    try testing.expect(!e4s.status.isInvalid());
    try testing.expectEqual(e4s, node.cm.active_tip.?);

    try node.restart();
    try node.expectTip(&b4s, 4);
    // The active chain still extends after the restart.
    const b5s = try mine(a, b4s.hash, 5, 0, 0x55);
    try expectAccepted(try node.submit(&b5s));
    try node.expectTip(&b5s, 5);
}

// An invalid block in the MIDDLE of a heavier side branch: Core connects the
// valid blocks below it, fails it, and then compares what is left.  Here the
// valid prefix (3') has less work than the tip that invalidateblock left
// (3a after invalidating 4a), so the node returns to 3a.
test "failed_reorg_recovery: an invalid block mid-branch stops that branch; the more-work valid chain is kept" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const c1 = try mine(a, params.genesis_hash, 1, 0, 0x61);
    const c2 = try mine(a, c1.hash, 2, 0, 0x62);
    const c3a = try mine(a, c2.hash, 3, 0, 0x63);
    const c4a = try mine(a, c3a.hash, 4, 0, 0x64);
    const c5a = try mine(a, c4a.hash, 5, 0, 0x65);
    const c3s = try mine(a, c2.hash, 3, 0, 0x73);
    const c4s_bad = try mine(a, c3s.hash, 4, 1, 0x74);
    const c5s = try mine(a, c4s_bad.hash, 5, 0, 0x75);

    for ([_]*const Blk{ &c1, &c2, &c3a, &c4a, &c5a }) |b| try expectAccepted(try node.submit(b));
    for ([_]*const Blk{ &c3s, &c4s_bad, &c5s }) |b| _ = try node.submit(b);
    try node.expectTip(&c5a, 5);

    try node.invalidate(c4a.hash);
    try node.expectTip(&c3a, 3);
    try testing.expect(node.cm.getBlock(&c4s_bad.hash).?.status.isInvalid());
    try testing.expect(node.cm.getBlock(&c5s.hash).?.status.isInvalid());
    // The valid block below the bad one is not marked.
    try testing.expect(!node.cm.getBlock(&c3s.hash).?.status.isInvalid());
    try testing.expect(!node.cs.flush_error);
}

/// Round trip with an equal-work side branch.  `first_tag` / `second_tag`
/// pick the two branches' blocks; the branch submitted first is the active
/// one.  Returns whether 4 of the first branch sorts below 4 of the second
/// by hash, so a caller can prove both hash orders were covered (a hash
/// tie-break passes exactly one of them).
fn equalWorkRoundTrip(first_tag: u8, second_tag: u8, restart_between: bool) !bool {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const r1 = try mine(a, params.genesis_hash, 1, 0, 0x01);
    const r2 = try mine(a, r1.hash, 2, 0, 0x02);
    const x3 = try mine(a, r2.hash, 3, 0, first_tag);
    const x4 = try mine(a, x3.hash, 4, 0, first_tag +% 1);
    const y3 = try mine(a, r2.hash, 3, 0, second_tag);
    const y4 = try mine(a, y3.hash, 4, 0, second_tag +% 1);

    for ([_]*const Blk{ &r1, &r2, &x3, &x4 }) |b| try expectAccepted(try node.submit(b));
    for ([_]*const Blk{ &y3, &y4 }) |b| _ = try node.submit(b);
    try node.expectTip(&x4, 4);

    try node.invalidate(x4.hash);
    try node.expectTip(&y4, 4);

    if (restart_between) {
        // Scenario E: the restart resets the sequence ids; the tip loaded
        // from disk (y4) now wins the tie, so reconsiderblock keeps it.
        try node.restart();
        try node.expectTip(&y4, 4);
        try node.reconsider(x4.hash);
        try node.expectTip(&y4, 4);
        try testing.expect(!node.cm.getBlock(&x4.hash).?.status.isInvalid());
        try node.restart();
        try node.expectTip(&y4, 4);
    } else {
        // Scenario C: x4 was received first, so it wins the tie.
        try node.reconsider(x4.hash);
        try node.expectTip(&x4, 4);
    }
    return std.mem.lessThan(u8, &x4.hash, &y4.hash);
}

test "failed_reorg_recovery: reconsiderblock returns to the first-received block on an equal-work tie" {
    var saw_lower = false;
    var saw_higher = false;
    var i: u8 = 0;
    while (i < 8 and !(saw_lower and saw_higher)) : (i += 1) {
        const lower = try equalWorkRoundTrip(0x10 + 4 * i, 0x90 + 4 * i, false);
        if (lower) saw_lower = true else saw_higher = true;
    }
    // Instrument check: both hash orders were exercised.
    try testing.expect(saw_lower and saw_higher);
}

test "failed_reorg_recovery: after a restart the loaded tip wins the tie and reconsiderblock keeps it" {
    var saw_lower = false;
    var saw_higher = false;
    var i: u8 = 0;
    while (i < 8 and !(saw_lower and saw_higher)) : (i += 1) {
        const lower = try equalWorkRoundTrip(0x10 + 4 * i, 0x90 + 4 * i, true);
        if (lower) saw_lower = true else saw_higher = true;
    }
    try testing.expect(saw_lower and saw_higher);
}

// Guard: a heavier side branch submitted after invalidateblock stays the tip
// when the invalidated block is reconsidered (scenario D).
test "failed_reorg_recovery: reconsiderblock keeps a heavier side branch" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const d1 = try mine(a, params.genesis_hash, 1, 0, 0x81);
    const d2 = try mine(a, d1.hash, 2, 0, 0x82);
    const d3a = try mine(a, d2.hash, 3, 0, 0x83);
    const d4a = try mine(a, d3a.hash, 4, 0, 0x84);
    for ([_]*const Blk{ &d1, &d2, &d3a, &d4a }) |b| try expectAccepted(try node.submit(b));

    try node.invalidate(d4a.hash);
    try node.expectTip(&d3a, 3);
    const d3s = try mine(a, d2.hash, 3, 0, 0xA3);
    const d4s = try mine(a, d3s.hash, 4, 0, 0xA4);
    const d5s = try mine(a, d4s.hash, 5, 0, 0xA5);
    _ = try node.submit(&d3s);
    try expectAccepted(try node.submit(&d4s));
    try expectAccepted(try node.submit(&d5s));
    try node.expectTip(&d5s, 5);

    try node.reconsider(d4a.hash);
    try node.expectTip(&d5s, 5);
}
