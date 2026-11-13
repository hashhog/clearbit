//! Security audit 2026-10-29, finding C2, the part left after the
//! proof-of-work gate (clearbit#39): a peer could still
//!   (a) arm `pending_reorg` with a higher-work fork and never send the
//!       bodies. Nothing ever cleared it, so every later honest fork was
//!       refused as `already_pending`.
//!   (b) grow `expected_blocks` and the persisted header DB without bound by
//!       sending unsolicited batches of headers that carry real but cheap
//!       work. HEADER_PREFETCH_CAP only stopped us from ASKING for more.
//! Core has no indefinite pending reorg (a block that is not delivered is
//! re-requested after the block-download timeout, net_processing.cpp
//! BLOCK_DOWNLOAD_TIMEOUT_BASE) and does not hold an unbounded queue of
//! headers it cannot download.
//!
//! Every test drives the real `.headers` / `.block` handlers through
//! `ingestHeadersMessage` / `ingestBlockMessage`. Fields the fix adds
//! (`PendingReorg.armed_at`, `.last_progress_at`,
//! `PeerManager.max_unconnected_headers`) are only touched behind `@hasField`,
//! so this file compiles on the pre-fix tree and the fail-before tests fail
//! there on their assertions. Backdating `armed_at` / `last_progress_at` is
//! the mock clock: it is the same as the wall clock moving past the timeout.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const storage = @import("storage.zig");
const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;
const PendingReorg = peer_mod.PendingReorg;

const REGTEST_BITS: u32 = 0x207fffff;

/// A header on `prev` whose proof of work passes (`want_valid`) or fails.
fn grind(params: *const consensus.NetworkParams, prev: types.Hash256, bits: u32, timestamp: u32, tag: u8, want_valid: bool) types.BlockHeader {
    var h = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = [_]u8{tag} ** 32,
        .timestamp = timestamp,
        .bits = bits,
        .nonce = 0,
    };
    while (consensus.validateProofOfWork(&h, params) != want_valid) h.nonce +%= 1;
    return h;
}

/// Coinbase-only regtest block at `height` (<= 16) on `prev`, with real PoW.
fn mineBlock(a: std.mem.Allocator, prev: types.Hash256, height: u32, tag: u8) !types.Block {
    const params = &consensus.REGTEST;
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
    outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = spk };
    const txs = try a.alloc(types.Transaction, 1);
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeTxid(&txs[0], a),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = REGTEST_BITS,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    return .{ .header = header, .transactions = txs };
}

fn cloneBlock(a: std.mem.Allocator, b: *const types.Block) !types.Block {
    var w = serialize.Writer.init(a);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readBlock(&r, a);
}

/// A chainstate at genesis on a temp DB, a PeerManager on `params` and one
/// handshake-complete socketpair peer.
const Fx = struct {
    a: std.mem.Allocator,
    params: *const consensus.NetworkParams,
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: PeerManager,
    peer: *Peer,
    remote: std.posix.fd_t,

    fn init(self: *Fx, a: std.mem.Allocator, params: *const consensus.NetworkParams) !void {
        self.a = a;
        self.params = params;
        self.tmp = testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(a, ".");
        self.db = try storage.Database.open(self.path, 64, a);
        self.cs = storage.ChainState.init(&self.db, 64, a);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(params);
        self.cs.best_hash = params.genesis_hash;
        self.cs.initGenesisTimestamp(params.genesis_header.timestamp);
        self.pm = PeerManager.init(a, params);
        self.pm.anchors_path = "/dev/null";
        self.pm.ban_list.file_path = null; // never write banlist.json from a test
        self.pm.chain_state = &self.cs;

        var fds: [2]i32 = undefined;
        try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
        const p = try a.create(Peer);
        p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8333), params, a);
        p.state = .handshake_complete;
        p.services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
        try self.pm.peers.append(p);
        self.peer = p;
        self.remote = fds[1];
    }

    fn deinit(self: *Fx) void {
        std.posix.close(self.remote);
        self.pm.chain_state = null;
        self.pm.deinit();
        self.cs.deinit();
        self.db.close();
        self.a.free(self.path);
        self.tmp.cleanup();
    }

    fn send(self: *Fx, hdrs: []const types.BlockHeader) !void {
        const owned = try self.a.dupe(types.BlockHeader, hdrs);
        try self.pm.ingestHeadersMessage(self.peer, owned);
    }

    fn queued(self: *Fx, hash: types.Hash256) bool {
        for (self.pm.expected_blocks.items) |e| {
            if (std.mem.eql(u8, &e, &hash)) return true;
        }
        return false;
    }
};

/// Move the pending reorg's clocks `arm_age` / `progress_age` seconds into
/// the past. A no-op on the pre-fix tree, which has no clocks.
fn age(pm: *PeerManager, arm_age: i64, progress_age: i64) void {
    const pr = if (pm.pending_reorg) |*p| p else return;
    if (@hasField(PendingReorg, "armed_at")) pr.armed_at = std.time.timestamp() - arm_age;
    if (@hasField(PendingReorg, "last_progress_at")) pr.last_progress_at = std.time.timestamp() - progress_age;
}

fn pendingIs(pm: *PeerManager, hashes: []const types.Hash256) bool {
    const pr = pm.pending_reorg orelse return false;
    if (pr.fork_hashes.items.len != hashes.len) return false;
    for (pr.fork_hashes.items, hashes) |a, b| {
        if (!std.mem.eql(u8, &a, &b)) return false;
    }
    return true;
}

/// Active chain genesis <- b1 (connected), then a 2-header fork off genesis
/// with valid proof of work whose bodies are never sent: pending_reorg armed.
fn armWithheldFork(fx: *Fx) !struct { b1: types.Block, f: [2]types.Hash256, hdrs: [2]types.BlockHeader } {
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;
    const b1 = try mineBlock(fx.a, p.genesis_hash, 1, 1);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);

    const f1 = grind(p, p.genesis_hash, REGTEST_BITS, t0 + 650, 0x71, true);
    const f2 = grind(p, crypto.computeBlockHash(&f1), REGTEST_BITS, t0 + 1250, 0x72, true);
    try fx.send(&.{ f1, f2 });
    const f = [2]types.Hash256{ crypto.computeBlockHash(&f1), crypto.computeBlockHash(&f2) };
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &f));
    return .{ .b1 = b1, .f = f, .hdrs = .{ f1, f2 } };
}

/// Honest 3-block fork off genesis (more work than the withheld 2-block fork).
fn mineHonestFork(fx: *Fx) ![3]types.Block {
    const p = fx.params;
    var g: [3]types.Block = undefined;
    g[0] = try mineBlock(fx.a, p.genesis_hash, 1, 0x21);
    g[1] = try mineBlock(fx.a, crypto.computeBlockHash(&g[0].header), 2, 0x22);
    g[2] = try mineBlock(fx.a, crypto.computeBlockHash(&g[1].header), 3, 0x23);
    return g;
}

fn gHashes(g: *const [3]types.Block) [3]types.Hash256 {
    return .{
        crypto.computeBlockHash(&g[0].header),
        crypto.computeBlockHash(&g[1].header),
        crypto.computeBlockHash(&g[2].header),
    };
}

/// Honest 2-block fork off genesis with the SAME work as the withheld fork:
/// it cannot displace the withheld reorg on work, so it arms only once that
/// reorg is given up. Tests of the timeout itself use this fork, because a
/// heavier fork displaces a pending reorg without any timeout.
fn mineEqualFork(fx: *Fx) ![2]types.Block {
    const p = fx.params;
    var e: [2]types.Block = undefined;
    e[0] = try mineBlock(fx.a, p.genesis_hash, 1, 0x61);
    e[1] = try mineBlock(fx.a, crypto.computeBlockHash(&e[0].header), 2, 0x62);
    return e;
}

fn eHashes(e: *const [2]types.Block) [2]types.Hash256 {
    return .{ crypto.computeBlockHash(&e[0].header), crypto.computeBlockHash(&e[1].header) };
}

test "sec_p2p_headers_queue: a pending reorg whose bodies never arrive is given up after the timeout and a later honest reorg is accepted" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();

    var w = try armWithheldFork(&fx);
    defer serialize.freeBlock(fx.a, &w.b1);
    var e = try mineEqualFork(&fx);
    defer for (&e) |*b| serialize.freeBlock(fx.a, b);
    const eh = eHashes(&e);

    // The withholding peer never delivers. Move past the stall timeout.
    age(&fx.pm, 601, 601);

    try fx.send(&.{ e[0].header, e[1].header });
    // Pre-fix: .already_pending, forever.
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &eh));

    for (&e) |*b| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, b));
    try testing.expect(fx.pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &eh[1], &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
}

test "sec_p2p_headers_queue: a pending reorg that keeps receiving bodies is still given up at its lifetime ceiling" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();

    var w = try armWithheldFork(&fx);
    defer serialize.freeBlock(fx.a, &w.b1);
    var e = try mineEqualFork(&fx);
    defer for (&e) |*b| serialize.freeBlock(fx.a, b);

    // Progress is fresh (a body arrived just now) but the 2-block fork has
    // been armed for longer than 600 s + 2 * 60 s: a peer dribbling bodies
    // cannot hold the slot forever.
    age(&fx.pm, 721, 0);

    try fx.send(&.{ e[0].header, e[1].header });
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &eHashes(&e)));
}

test "sec_p2p_headers_queue: control, before the timeout a second fork is still deferred" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();

    var w = try armWithheldFork(&fx);
    defer serialize.freeBlock(fx.a, &w.b1);
    var e = try mineEqualFork(&fx);
    defer for (&e) |*b| serialize.freeBlock(fx.a, b);

    // Same work as the pending fork, so only the timeout could free the slot.
    age(&fx.pm, 599, 599);
    try fx.send(&.{ e[0].header, e[1].header });
    try testing.expectEqual(peer_mod.ReorgArmResult.already_pending, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &w.f));
}

test "sec_p2p_headers_queue: control, a reorg whose bodies are arriving is not dropped by the stall timer and completes" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;

    var b1 = try mineBlock(fx.a, p.genesis_hash, 1, 1);
    defer serialize.freeBlock(fx.a, &b1);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));

    var g = try mineHonestFork(&fx);
    defer for (&g) |*b| serialize.freeBlock(fx.a, b);
    const gh = gHashes(&g);
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expect(pendingIs(&fx.pm, &gh));

    // Armed 700 s ago (under the 600 + 3*60 s ceiling), quiet for 700 s;
    // then a new body arrives, which is progress.
    age(&fx.pm, 700, 700);
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &g[0]));
    try testing.expect(pendingIs(&fx.pm, &gh));

    // Another fork announcement with the same work does not displace it.
    const x1 = grind(p, p.genesis_hash, REGTEST_BITS, t0 + 700, 0x31, true);
    const x2 = grind(p, crypto.computeBlockHash(&x1), REGTEST_BITS, t0 + 1300, 0x32, true);
    const x3 = grind(p, crypto.computeBlockHash(&x2), REGTEST_BITS, t0 + 1900, 0x33, true);
    try fx.send(&.{ x1, x2, x3 });
    try testing.expectEqual(peer_mod.ReorgArmResult.already_pending, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &gh));

    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &g[1]));
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &g[2]));
    try testing.expectEqual(@as(u32, 3), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &gh[2], &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
}

test "sec_p2p_headers_queue: unsolicited 2000-header batches with valid proof of work do not grow expected_blocks or the header DB without bound" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;

    // Nobody asked this peer for headers. 8 x 2000 = 16000 headers, each
    // meeting its regtest target, each extending the last.
    const batches = 8;
    const batch = try fx.a.alloc(types.BlockHeader, peer_mod.MAX_HEADERS_RESULTS);
    defer fx.a.free(batch);
    var prev = p.genesis_hash;
    var n: u32 = 0;
    var last_hash = prev;
    var first_hash: ?types.Hash256 = null;
    for (0..batches) |_| {
        for (batch) |*h| {
            n += 1;
            h.* = grind(p, prev, REGTEST_BITS, t0 + 600 * n, @truncate(n), true);
            prev = crypto.computeBlockHash(h);
            if (first_hash == null) first_hash = prev;
        }
        last_hash = prev;
        try fx.send(batch);
        try testing.expect(!fx.peer.should_ban);
    }

    // The honest prefix was taken...
    try testing.expect(fx.pm.expected_blocks.items.len >= peer_mod.MAX_HEADERS_RESULTS);
    try testing.expect(fx.cs.getPersistedHeader(&first_hash.?) != null);
    // ...but the queue stays under the cap (pre-fix: 16000, growing linearly
    // with every batch) and the tail never reached the header DB.
    const queued = fx.pm.expected_blocks.items.len - fx.pm.connect_cursor;
    try testing.expect(queued <= peer_mod.MAX_HEADER_INDEX);
    try testing.expect(fx.pm.expected_blocks.items.len <= peer_mod.MAX_HEADER_INDEX);
    try testing.expect(fx.cs.getPersistedHeader(&last_hash) == null);
    try testing.expect(!fx.pm.header_index.contains(last_hash));
}

test "sec_p2p_headers_queue: control, honest header sync continues past the queue cap once blocks connect" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;
    if (@hasField(PeerManager, "max_unconnected_headers")) fx.pm.max_unconnected_headers = 3;

    var b: [5]types.Block = undefined;
    var prev = p.genesis_hash;
    for (&b, 0..) |*blk, i| {
        blk.* = try mineBlock(fx.a, prev, @intCast(i + 1), @intCast(0x41 + i));
        prev = crypto.computeBlockHash(&blk.header);
    }
    defer for (&b) |*blk| serialize.freeBlock(fx.a, blk);

    try fx.send(&.{ b[0].header, b[1].header, b[2].header, b[3].header, b[4].header });
    if (@hasField(PeerManager, "max_unconnected_headers")) {
        try testing.expectEqual(@as(usize, 3), fx.pm.expected_blocks.items.len);
        try testing.expect(fx.cs.getPersistedHeader(&crypto.computeBlockHash(&b[3].header)) == null);
    }
    try testing.expect(!fx.peer.should_ban);
    for (b[0..3]) |*blk| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, blk));
    try testing.expectEqual(@as(u32, 3), fx.cs.best_height);

    // The queue drained; the next headers reply (to the drain's getheaders)
    // is taken and the chain completes.
    try fx.send(&.{ b[3].header, b[4].header });
    for (b[3..5]) |*blk| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, blk));
    try testing.expectEqual(@as(u32, 5), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &crypto.computeBlockHash(&b[4].header), &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
}

test "sec_p2p_headers_queue: a heavier fork whose pending reorg expired is armed again when the same headers are re-sent" {
    // Warden on clearbit#71: the competing-fork path returns before
    // maybeArmReorg when `seen_fork_batches` already holds the batch key, and
    // the key was recorded on the first (arming) announcement. Once that
    // reorg is given up, a peer re-sending the identical headers (the usual
    // retry) must be judged on its work again, not ignored as a duplicate.
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;

    // Active chain genesis <- b1.
    var b1 = try mineBlock(fx.a, p.genesis_hash, 1, 1);
    defer serialize.freeBlock(fx.a, &b1);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);

    // Heavier 3-block fork announced; its bodies are not sent (yet).
    var g = try mineHonestFork(&fx);
    defer for (&g) |*b| serialize.freeBlock(fx.a, b);
    const gh = gHashes(&g);
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &gh));

    // Past the stall timeout. A different fork with equal work (one header
    // off genesis, same as b1) clears the stale slot but does not arm.
    age(&fx.pm, 601, 601);
    const x1 = grind(p, p.genesis_hash, REGTEST_BITS, t0 + 640, 0x5a, true);
    try fx.send(&.{x1});
    try testing.expect(fx.pm.last_arm_result != .armed);
    try testing.expect(fx.pm.pending_reorg == null);

    // The original headers, re-sent unchanged. Pre-fix: dropped as a seen
    // batch, pending_reorg stays empty and no getdata goes out.
    fx.pm.last_arm_result = .skipped;
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &gh));

    for (&g) |*b| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, b));
    try testing.expect(fx.pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 3), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &gh[2], &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
    for (gh) |h| try testing.expect(!fx.pm.failed_blocks.contains(h));
}

test "sec_p2p_headers_queue: an expired pending reorg re-armed by its own re-sent headers before any other fork arrives" {
    // Same retry, but with no other fork in between: the stale slot must
    // be cleared by the re-announcement itself.
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;

    var b1 = try mineBlock(fx.a, p.genesis_hash, 1, 1);
    defer serialize.freeBlock(fx.a, &b1);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));

    var g = try mineHonestFork(&fx);
    defer for (&g) |*b| serialize.freeBlock(fx.a, b);
    const gh = gHashes(&g);
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expect(pendingIs(&fx.pm, &gh));

    age(&fx.pm, 601, 601);
    fx.pm.last_arm_result = .skipped;
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &gh));
    if (@hasField(PendingReorg, "armed_at")) {
        try testing.expect(std.time.timestamp() - fx.pm.pending_reorg.?.armed_at < 600);
    }

    for (&g) |*b| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, b));
    try testing.expectEqual(@as(u32, 3), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &gh[2], &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
    for (gh) |h| try testing.expect(!fx.pm.failed_blocks.contains(h));
}

test "sec_p2p_headers_queue: control, re-sending the headers of a reorg that is still pending does not re-arm or duplicate it" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;

    var b1 = try mineBlock(fx.a, p.genesis_hash, 1, 1);
    defer serialize.freeBlock(fx.a, &b1);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));

    var g = try mineHonestFork(&fx);
    defer for (&g) |*b| serialize.freeBlock(fx.a, b);
    const gh = gHashes(&g);
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expect(pendingIs(&fx.pm, &gh));
    const armed_at_before: i64 = if (@hasField(PendingReorg, "armed_at")) fx.pm.pending_reorg.?.armed_at else 0;

    age(&fx.pm, 100, 100);
    fx.pm.last_arm_result = .skipped;
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    // Still the same pending reorg; the duplicate batch was a no-op.
    try testing.expectEqual(peer_mod.ReorgArmResult.skipped, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &gh));
    if (@hasField(PendingReorg, "armed_at")) {
        try testing.expect(fx.pm.pending_reorg.?.armed_at <= armed_at_before - 100 + 1);
    }
    try testing.expect(!fx.peer.should_ban);
}

test "sec_p2p_headers_queue: a fork deferred as already_pending is armed when its headers are re-sent after the pending reorg expires" {
    // Pre-review of the clearbit#71 rework: a fork turned away as
    // already_pending had its batch key recorded too, and only the ARMING
    // batch's key is dropped on expiry. So the honest fork that arrived while
    // a withholder held the slot stayed a "seen" batch and its retry was
    // ignored after the slot expired.
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();

    var w = try armWithheldFork(&fx);
    defer serialize.freeBlock(fx.a, &w.b1);
    var e = try mineEqualFork(&fx);
    defer for (&e) |*b| serialize.freeBlock(fx.a, b);
    const eh = eHashes(&e);

    // An honest fork with the same work arrives while the withheld one is
    // pending: deferred.
    try fx.send(&.{ e[0].header, e[1].header });
    try testing.expectEqual(peer_mod.ReorgArmResult.already_pending, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &w.f));

    // The withheld fork times out; the honest fork's headers are re-sent.
    age(&fx.pm, 601, 601);
    fx.pm.last_arm_result = .skipped;
    try fx.send(&.{ e[0].header, e[1].header });
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &eh));

    for (&e) |*b| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, b));
    try testing.expect(fx.pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &eh[1], &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
    for (eh) |h| try testing.expect(!fx.pm.failed_blocks.contains(h));
}

test "sec_p2p_headers_queue: a withholder re-sending its own expired fork cannot keep a heavier fork from arming" {
    // Second pre-review of the clearbit#71 rework: once expiry forgot the
    // arming batch, the withholder could re-send its own headers right
    // after each expiry and re-take the slot in the same message, and the
    // heavier honest fork kept getting already_pending. A fork with more
    // work than the pending one now takes the slot, so holding it costs the
    // withholder real work.
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();

    var w = try armWithheldFork(&fx);
    defer serialize.freeBlock(fx.a, &w.b1);
    var g = try mineHonestFork(&fx);
    defer for (&g) |*b| serialize.freeBlock(fx.a, b);
    const gh = gHashes(&g);

    // The heavier honest fork arrives while the withheld one is pending.
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    // Whatever holds the slot ages out; the withholder re-sends its own
    // headers FIRST, then the honest fork is re-sent.
    age(&fx.pm, 601, 601);
    try fx.send(&w.hdrs);
    fx.pm.last_arm_result = .skipped;
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expect(pendingIs(&fx.pm, &gh));

    for (&g) |*b| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, b));
    try testing.expect(fx.pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 3), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &gh[2], &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
    for (gh) |h| try testing.expect(!fx.pm.failed_blocks.contains(h));
}

test "sec_p2p_headers_queue: a heavier extension displaces a pending reorg before the timeout and keeps the body already received" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();

    var b1 = try mineBlock(fx.a, fx.params.genesis_hash, 1, 1);
    defer serialize.freeBlock(fx.a, &b1);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));

    var g = try mineHonestFork(&fx);
    defer for (&g) |*b| serialize.freeBlock(fx.a, b);
    const gh = gHashes(&g);
    var g4 = try mineBlock(fx.a, gh[2], 4, 0x24);
    defer serialize.freeBlock(fx.a, &g4);
    const g4h = crypto.computeBlockHash(&g4.header);

    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    try testing.expect(pendingIs(&fx.pm, &gh));
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &g[0]));
    try testing.expect(fx.pm.block_buffer.contains(gh[0]));

    // One more block on the same fork, well before any timeout.
    try fx.send(&.{ g[0].header, g[1].header, g[2].header, g4.header });
    try testing.expectEqual(peer_mod.ReorgArmResult.armed, fx.pm.last_arm_result);
    try testing.expect(pendingIs(&fx.pm, &.{ gh[0], gh[1], gh[2], g4h }));
    // The body the displaced reorg already had is not thrown away.
    try testing.expect(fx.pm.block_buffer.contains(gh[0]));

    for (g[1..]) |*b| try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, b));
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &g4));
    try testing.expect(fx.pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 4), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &g4h, &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
}

test "sec_p2p_headers_queue: control, a heavier fork that is then refused leaves the pending reorg and its bodies alone" {
    // A heavier fork now gets past the already_pending gate, so the swap
    // must wait until it passes every arm check. Here it fails the last one
    // (the announcer cannot serve witnesses): the pending reorg must keep
    // its slot and the body it already has, and still complete.
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();

    var b1 = try mineBlock(fx.a, fx.params.genesis_hash, 1, 1);
    defer serialize.freeBlock(fx.a, &b1);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));

    var e = try mineEqualFork(&fx);
    defer for (&e) |*b| serialize.freeBlock(fx.a, b);
    const eh = eHashes(&e);
    try fx.send(&.{ e[0].header, e[1].header });
    try testing.expect(pendingIs(&fx.pm, &eh));
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &e[0]));
    try testing.expect(fx.pm.block_buffer.contains(eh[0]));

    var g = try mineHonestFork(&fx);
    defer for (&g) |*b| serialize.freeBlock(fx.a, b);
    const services = fx.peer.services;
    fx.peer.services = p2p.NODE_NETWORK; // no NODE_WITNESS
    try fx.send(&.{ g[0].header, g[1].header, g[2].header });
    fx.peer.services = services;
    try testing.expect(fx.pm.last_arm_result != .armed);
    try testing.expect(pendingIs(&fx.pm, &eh));
    try testing.expect(fx.pm.block_buffer.contains(eh[0]));
    if (@hasField(PeerManager, "pending_reorgs_displaced")) {
        try testing.expectEqual(@as(u64, 0), fx.pm.pending_reorgs_displaced);
    }

    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &e[1]));
    try testing.expect(fx.pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 2), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &eh[1], &fx.cs.best_hash);
    try testing.expect(!fx.peer.should_ban);
}
