//! At-tip DRAIN-BREAK-WEDGE lag (QUEUES clearbit 2026-09-30).
//!
//! Live shape: 3-5 blocks behind Core with RPC fine, restart.log repeating
//!   DRAIN-BREAK-WEDGE connect_cursor=1821 download_cursor=1823 buffer=1
//!     sampled_ahead_min=1 sampled_ahead_max=1
//!   drain-wedge recovery: cancelled stuck front block ... (stalled 13s)
//!   drain-wedge recovery: cancelled stuck front block ... (stalled 50s)
//! and up to 12 cancels of ONE front block. The next block was requested
//! from whichever peer the rotation offered, announced or not. A peer that
//! has not seen the block ignores the getdata (Core sends no notfound for a
//! block), so each request is a 2s→64s stall, and the re-request after a
//! cancel again went to any peer except the last staller.
//!
//! Core asks a peer for a block only below its pindexBestKnownBlock
//! (FindNextBlocksToDownload). These tests drive the REAL PeerManager
//! (`.headers` / `.block` handlers, pipelineBlockRequests, drainBlockBuffer)
//! over unix socketpairs, on real regtest blocks, and use only APIs that
//! exist on the pre-fix tree so the same file gives the fail-before run.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const storage = @import("storage.zig");
const peer_mod = @import("peer.zig");
const tl = @import("tests_tip_liveness.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

const params = &consensus.REGTEST;

const Mined = struct { block: types.Block, hash: types.Hash256 };

/// Coinbase-only regtest block at `height` (<= 16) on `prev`, paying the
/// subsidy + `overpay` sat (overpay > 0 is bad-cb-amount). `tag` makes
/// same-height siblings distinct.
fn mine(a: std.mem.Allocator, prev: types.Hash256, height: u32, overpay: i64, tag: u8) !Mined {
    std.debug.assert(height >= 1 and height <= 16);
    const script_sig = try a.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag });
    const inputs = try a.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const spk = try a.dupe(u8, &[_]u8{0x51});
    const outputs = try a.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000 + overpay, .script_pubkey = spk };
    const txs = try a.alloc(types.Transaction, 1);
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeTxid(&txs[0], a),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

fn clone(a: std.mem.Allocator, b: *const types.Block) !types.Block {
    var w = serialize.Writer.init(a);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readBlock(&r, a);
}

fn sendHeaders(pm: *PeerManager, a: std.mem.Allocator, from: *Peer, blocks: []const *const Mined) !void {
    const hs = try a.alloc(types.BlockHeader, blocks.len);
    for (blocks, 0..) |b, i| hs[i] = b.block.header;
    try pm.ingestHeadersMessage(from, hs);
}

fn sendBlock(pm: *PeerManager, a: std.mem.Allocator, from: *Peer, b: *const Mined) !void {
    try pm.ingestBlockMessage(from, try clone(a, &b.block));
}

/// Drop `hash`'s in-flight record (what the drain-wedge recovery does).
fn cancelInFlight(pm: *PeerManager, hash: types.Hash256) void {
    if (pm.inflight_block_peer.fetchRemove(hash)) |kv| {
        if (pm.blocks_in_flight > 0) pm.blocks_in_flight -= 1;
        for (pm.peers.items) |p| {
            if (@intFromPtr(p) == kv.value) p.recordBlockReceived();
        }
    }
}

/// A regtest chainstate on a temp DB, at genesis, plus three socketpair
/// peers A, B, C (all NODE_WITNESS, handshake complete).
const Fx = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: PeerManager,
    pa: tl.Pair,
    pb: tl.Pair,
    pc: tl.Pair,
    chain: [5]Mined, // chain[h] at height h (chain[0] unused)

    fn init(self: *Fx, a: std.mem.Allocator) !void {
        self.a = a;
        self.tmp = testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(a, ".");
        self.db = try storage.Database.open(self.path, 64, a);
        self.cs = storage.ChainState.init(&self.db, 64, a);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(params);
        self.cs.best_hash = params.genesis_hash;
        self.cs.initGenesisTimestamp(params.genesis_header.timestamp);
        self.pm = tl.initPm(a);
        self.pm.chain_state = &self.cs;
        self.pa = try tl.addPeer(&self.pm, a, .{ 10, 0, 0, 1 }, false);
        self.pb = try tl.addPeer(&self.pm, a, .{ 10, 0, 0, 2 }, false);
        self.pc = try tl.addPeer(&self.pm, a, .{ 10, 0, 0, 3 }, false);
        var prev = params.genesis_hash;
        var h: u32 = 1;
        while (h <= 4) : (h += 1) {
            self.chain[h] = try mine(a, prev, h, 0, @intCast(h));
            prev = self.chain[h].hash;
        }
    }

    fn deinit(self: *Fx) void {
        var h: usize = 1;
        while (h <= 4) : (h += 1) serialize.freeBlock(self.a, &self.chain[h].block);
        std.posix.close(self.pa.remote);
        std.posix.close(self.pb.remote);
        std.posix.close(self.pc.remote);
        self.pm.chain_state = null;
        self.pm.deinit();
        self.cs.deinit();
        self.db.close();
        self.a.free(self.path);
        self.tmp.cleanup();
    }

    /// Connect height 1 from A, then stand at tip 1 with every peer having
    /// connected while the tip was 1 (version start_height = 1).
    fn atTipOne(self: *Fx) !void {
        try sendHeaders(&self.pm, self.a, self.pa.peer, &.{&self.chain[1]});
        try sendBlock(&self.pm, self.a, self.pa.peer, &self.chain[1]);
        try testing.expectEqual(@as(u32, 1), self.cs.best_height);
        self.pa.peer.start_height = 1;
        self.pb.peer.start_height = 1;
        self.pc.peer.start_height = 1;
    }

    fn holder(self: *Fx, hash: types.Hash256) ?*Peer {
        const v = self.pm.inflight_block_peer.get(hash) orelse return null;
        for (self.pm.peers.items) |p| if (@intFromPtr(p) == v) return p;
        return null;
    }
};

test "tip_lag: the next block is requested only from the peer that announced it, whatever the rotation" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.atTipOne();

    // A announces height 2. B and C are still at 1 and never saw it.
    // Rotation 0 offers peers[(0+1)%3] = B first: pre-fix B got the getdata.
    fx.pm.block_request_rotation = 0;
    try sendHeaders(&fx.pm, fx.a, fx.pa.peer, &.{&fx.chain[2]});
    const h2 = fx.chain[2].hash;
    try testing.expect(fx.holder(h2) == fx.pa.peer);

    // Every rotation start: still A, never a peer that has not seen it.
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        cancelInFlight(&fx.pm, h2);
        fx.pm.download_cursor = fx.pm.connect_cursor;
        fx.pm.block_request_rotation = r;
        try fx.pm.pipelineBlockRequests();
        try testing.expect(fx.holder(h2) == fx.pa.peer);
    }

    // Delivered by A: connects.
    try sendBlock(&fx.pm, fx.a, fx.pa.peer, &fx.chain[2]);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &h2, &fx.cs.best_hash);
}

test "tip_lag: a cancelled stuck front block goes to another peer that announced it, not one still behind" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.atTipOne();

    // A announces height 2 and takes the getdata; C re-announces it (an
    // already-queued header); B never does.
    fx.pm.block_request_rotation = 2; // first offer (2+1)%3 = A
    try sendHeaders(&fx.pm, fx.a, fx.pa.peer, &.{&fx.chain[2]});
    const h2 = fx.chain[2].hash;
    try testing.expect(fx.holder(h2) == fx.pa.peer);
    try sendHeaders(&fx.pm, fx.a, fx.pc.peer, &.{&fx.chain[2]});

    // A stalls past the drain-wedge timeout: the recovery cancels it.
    fx.pm.wedge_since = std.time.timestamp() - peer_mod.DRAIN_WEDGE_STALL_TIMEOUT - 1;
    fx.pm.wedge_timeout = peer_mod.DRAIN_WEDGE_STALL_TIMEOUT;
    fx.pm.drainBlockBuffer();
    try testing.expect(fx.holder(h2) == null);

    // Rotation 0 offers B first. Pre-fix B (any peer but the staller) got
    // it and the front block stalled again; it must go to C.
    fx.pm.block_request_rotation = 0;
    try fx.pm.pipelineBlockRequests();
    try testing.expect(fx.holder(h2) == fx.pc.peer);

    try sendBlock(&fx.pm, fx.a, fx.pc.peer, &fx.chain[2]);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);
}

test "tip_lag: a block no peer has announced is still requested from some peer" {
    // Control for the fallback: the availability filter never leaves a
    // block unrequested that the old pipeline would have requested.
    var fx: Fx = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.atTipOne();

    const h2 = fx.chain[2].hash;
    try fx.pm.expected_blocks.append(h2); // queued, announced by nobody
    fx.pm.block_request_rotation = 0;
    try fx.pm.pipelineBlockRequests();
    try testing.expect(fx.holder(h2) != null);
}

test "tip_lag: out-of-order delivery connects only in chain order" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.atTipOne();

    try sendHeaders(&fx.pm, fx.a, fx.pa.peer, &.{ &fx.chain[2], &fx.chain[3], &fx.chain[4] });

    // 4 then 3 arrive first: buffered, nothing connects past the gap.
    try sendBlock(&fx.pm, fx.a, fx.pa.peer, &fx.chain[4]);
    try sendBlock(&fx.pm, fx.a, fx.pa.peer, &fx.chain[3]);
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &fx.chain[1].hash, &fx.cs.best_hash);
    try testing.expectEqual(@as(u32, 2), fx.pm.block_buffer.count());

    // 2 arrives: 2, 3, 4 connect in order.
    try sendBlock(&fx.pm, fx.a, fx.pa.peer, &fx.chain[2]);
    try testing.expectEqual(@as(u32, 4), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &fx.chain[4].hash, &fx.cs.best_hash);
    var h: u32 = 1;
    while (h <= 4) : (h += 1) {
        const at = fx.cs.getBlockHashByHeight(h) orelse return error.MissingHeight;
        try testing.expectEqualSlices(u8, &fx.chain[h].hash, &at);
    }
    try testing.expectEqual(@as(u32, 0), fx.pm.block_buffer.count());
}

test "tip_lag: an invalid block at the front is rejected even when its child arrived first" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.atTipOne();

    // B announces a height-2 block paying subsidy + 1 sat (bad-cb-amount)
    // and a valid-looking child, delivered child first.
    var bad2 = try mine(fx.a, fx.chain[1].hash, 2, 1, 0xB2);
    defer serialize.freeBlock(fx.a, &bad2.block);
    var bad3 = try mine(fx.a, bad2.hash, 3, 0, 0xB3);
    defer serialize.freeBlock(fx.a, &bad3.block);
    try sendHeaders(&fx.pm, fx.a, fx.pb.peer, &.{ &bad2, &bad3 });
    try sendBlock(&fx.pm, fx.a, fx.pb.peer, &bad3);
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);
    try sendBlock(&fx.pm, fx.a, fx.pb.peer, &bad2);

    // Rejected: tip unchanged, marked failed, child never connected,
    // deliverer punished.
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &fx.chain[1].hash, &fx.cs.best_hash);
    try testing.expect(fx.pm.isBlockFailed(&bad2.hash));
    try testing.expect(fx.pb.peer.should_ban);
    try testing.expect(!fx.pa.peer.should_ban);

    // The valid height 2..3 from A, also out of order, then connect.
    try sendHeaders(&fx.pm, fx.a, fx.pa.peer, &.{ &fx.chain[2], &fx.chain[3] });
    try sendBlock(&fx.pm, fx.a, fx.pa.peer, &fx.chain[3]);
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);
    try sendBlock(&fx.pm, fx.a, fx.pa.peer, &fx.chain[2]);
    try testing.expectEqual(@as(u32, 3), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &fx.chain[3].hash, &fx.cs.best_hash);
}
