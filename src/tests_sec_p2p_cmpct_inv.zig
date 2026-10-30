//! Security audit 2026-10-29, findings H1 and H2 (P2P work far cheaper to
//! request than to serve).
//!
//! H1: a `cmpctblock` carrying ANY header (unknown parent, no proof of work)
//! made the node SipHash its whole mempool and then send a getdata /
//! getblocktxn for the block. Core first requires a known parent, enough
//! work, and a header that passes ProcessNewBlockHeaders
//! (net_processing.cpp:4475-4508), and reconstructs only blocks close to the
//! tip. The reconstruction itself is not observable from the socket, but its
//! last step always is: every path through it ends in a getdata
//! (MSG_WITNESS_BLOCK) or getblocktxn to the sender. These tests count those.
//!
//! H2: `inv` had no throttles. Every block inv sent a getheaders (Core:
//! only for unknown blocks, at most one per HEADERS_RESPONSE_TIME = 2 min,
//! net_processing.cpp:2823-2831); every block-inv item cost a linear scan
//! of the header download queue; every unknown tx was requested with no
//! per-peer limit, during IBD, and from block-relay-only peers (Core:
//! RejectIncomingTxs disconnects, IsInitialBlockDownload skips, and
//! txdownloadman caps MAX_PEER_TX_ANNOUNCEMENTS = 5000).
//!
//! Every test here uses only API that exists on the base commit, so the
//! fix-before / pass-after comparison runs the same file on both.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const h = @import("tests_tip_liveness.zig");
const params = h.params;
const addPeer = h.addPeer;

const Fixture = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: peer_mod.PeerManager,

    fn init(self: *Fixture, a: std.mem.Allocator) !void {
        self.a = a;
        self.tmp = testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(a, ".");
        self.db = try storage.Database.open(self.path, 64, a);
        self.cs = storage.ChainState.init(&self.db, 64, a);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(params);
        self.cs.best_hash = params.genesis_hash;
        self.cs.best_height = 0;
        self.pm = h.initPm(a);
        self.pm.chain_state = &self.cs;
    }

    fn deinit(self: *Fixture) void {
        self.pm.deinit();
        self.cs.deinit();
        self.db.close();
        self.a.free(self.path);
        self.tmp.cleanup();
    }
};

// ---------------------------------------------------------------------------
// Frame reading
// ---------------------------------------------------------------------------

/// Everything the node has written to `fd` so far, appended to `buf`.
fn slurp(fd: std.posix.fd_t, buf: *std.ArrayList(u8)) !void {
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = std.posix.recv(fd, &tmp, std.posix.MSG.DONTWAIT) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;
        try buf.appendSlice(tmp[0..n]);
    }
}

const Seen = struct {
    getdata_msgs: usize = 0,
    /// Inventory items across all getdata frames.
    getdata_items: usize = 0,
    /// getdata items asking for a block (MSG_BLOCK / MSG_WITNESS_BLOCK).
    getdata_block_items: usize = 0,
    getblocktxn: usize = 0,
    getheaders: usize = 0,
};

fn readCompactSize(b: []const u8, n: *u64) usize {
    if (b[0] < 0xfd) {
        n.* = b[0];
        return 1;
    }
    if (b[0] == 0xfd) {
        n.* = std.mem.readInt(u16, b[1..3], .little);
        return 3;
    }
    n.* = std.mem.readInt(u32, b[1..5], .little);
    return 5;
}

/// Tally the complete frames in `buf`.
fn tally(buf: []const u8) Seen {
    var s = Seen{};
    var pos: usize = 0;
    while (buf.len - pos >= 24) {
        const hdr = buf[pos .. pos + 24];
        const len = std.mem.readInt(u32, hdr[16..20], .little);
        if (buf.len - pos < 24 + len) break;
        const name_end = std.mem.indexOfScalar(u8, hdr[4..16], 0) orelse 12;
        const cmd = hdr[4 .. 4 + name_end];
        const payload = buf[pos + 24 .. pos + 24 + len];
        if (std.mem.eql(u8, cmd, "getdata")) {
            s.getdata_msgs += 1;
            var count: u64 = 0;
            var off = readCompactSize(payload, &count);
            s.getdata_items += @intCast(count);
            var i: u64 = 0;
            while (i < count) : (i += 1) {
                const t = std.mem.readInt(u32, payload[off..][0..4], .little) & ~@as(u32, 0x40000000);
                if (t == @intFromEnum(p2p.InvType.msg_block)) s.getdata_block_items += 1;
                off += 36;
            }
        } else if (std.mem.eql(u8, cmd, "getblocktxn")) {
            s.getblocktxn += 1;
        } else if (std.mem.eql(u8, cmd, "getheaders")) {
            s.getheaders += 1;
        }
        pos += 24 + len;
    }
    return s;
}

const Writer = struct {
    fd: std.posix.fd_t,
    bytes: []const u8,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *Writer) void {
        h.writeAllFd(self.fd, self.bytes) catch {};
        self.done.store(true, .release);
    }
};

/// After a handler punishes or drops a peer, the next pass frees it, so the
/// tests read the outcome from the peer list and the ban list instead.
fn stillConnected(fx: *Fixture) bool {
    return fx.pm.peers.items.len == 1;
}

fn banned(fx: *Fixture, ip: [4]u8) bool {
    return fx.pm.ban_list.isBanned(ip);
}

/// Send `msg`, let the node process it, and return what it has sent so far
/// (cumulative over `buf`). The frame is written from a helper thread while
/// the node reads, so a message larger than the socketpair buffer cannot
/// deadlock the test against itself.
fn roundTrip(fx: *Fixture, remote: std.posix.fd_t, msg: p2p.Message, buf: *std.ArrayList(u8)) !Seen {
    const bytes = try p2p.encodeMessage(&msg, params.magic, testing.allocator);
    defer testing.allocator.free(bytes);
    var w = Writer{ .fd = remote, .bytes = bytes };
    const t = try std.Thread.spawn(.{}, Writer.run, .{&w});
    while (!w.done.load(.acquire)) {
        try fx.pm.processAllMessages();
        try slurp(remote, buf);
    }
    t.join();
    try fx.pm.processAllMessages();
    try slurp(remote, buf);
    return tally(buf.items);
}

// ---------------------------------------------------------------------------
// Compact blocks
// ---------------------------------------------------------------------------

const PowWant = enum { pass, fail };

/// A header on `prev` with `bits`, nonce ground until proof of work passes
/// (or, for `.fail`, fails) against `bits`.
fn grindHeader(prev: types.Hash256, bits: u32, ts: u32, want: PowWant, salt: u8) types.BlockHeader {
    var hdr = types.BlockHeader{
        .version = 0x20000000,
        .prev_block = prev,
        .merkle_root = [_]u8{salt} ** 32,
        .timestamp = ts,
        .bits = bits,
        .nonce = 0,
    };
    const target = consensus.bitsToTarget(bits);
    while (true) : (hdr.nonce += 1) {
        const hash = crypto.computeBlockHash(&hdr);
        const ok = consensus.hashMeetsTarget(&hash, &target);
        if (ok == (want == .pass)) return hdr;
    }
}

/// A header extending the regtest genesis tip that passes every header check.
fn validTipHeader(salt: u8) types.BlockHeader {
    return grindHeader(params.genesis_hash, params.genesis_header.bits, params.genesis_header.timestamp + 600, .pass, salt);
}

/// Coinbase prefilled + two short ids: with an empty / absent mempool two of
/// three slots are missing (> 50 %), so a reconstruction ends in a getdata
/// for the full block.
const CmpctParts = struct {
    ins: [1]types.TxIn,
    outs: [1]types.TxOut,
    prefilled: [1]p2p.PrefilledTransaction,
    sids: [2][6]u8,

    fn msg(self: *CmpctParts, hdr: types.BlockHeader) p2p.Message {
        const spk = [_]u8{0x51};
        self.ins[0] = .{
            .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xffffffff },
            .script_sig = &[_]u8{ 0x01, 0x01 },
            .sequence = 0xffffffff,
            .witness = &[_][]const u8{},
        };
        self.outs[0] = .{ .value = 50 * 100_000_000, .script_pubkey = &spk };
        self.prefilled[0] = .{
            .index = 0,
            .tx = .{ .version = 2, .inputs = &self.ins, .outputs = &self.outs, .lock_time = 0 },
        };
        self.sids = .{ .{ 1, 2, 3, 4, 5, 6 }, .{ 7, 8, 9, 10, 11, 12 } };
        return .{ .cmpctblock = .{
            .header = hdr,
            .nonce = 42,
            .short_ids = &self.sids,
            .prefilled_txs = &self.prefilled,
        } };
    }
};

test "sec_p2p_cmpct_inv H1 control: a valid cmpctblock extending the tip is still reconstructed" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 1 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    var parts: CmpctParts = undefined;
    const s = try roundTrip(&fx, p.remote, parts.msg(validTipHeader(0x11)), &buf);
    try testing.expectEqual(@as(usize, 1), s.getdata_block_items + s.getblocktxn);
    try testing.expect(stillConnected(&fx));
}

test "sec_p2p_cmpct_inv H1 a cmpctblock whose header fails proof of work is not reconstructed and is punished" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 2 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    const bad = grindHeader(params.genesis_hash, params.genesis_header.bits, params.genesis_header.timestamp + 600, .fail, 0x12);
    var parts: CmpctParts = undefined;
    const s = try roundTrip(&fx, p.remote, parts.msg(bad), &buf);
    if (s.getdata_block_items + s.getblocktxn != 0) {
        std.debug.print("high-hash cmpctblock was reconstructed: getdata block items={d} getblocktxn={d}\n", .{ s.getdata_block_items, s.getblocktxn });
        return error.ReconstructedHighHash;
    }
    // Core: ProcessNewBlockHeaders -> BLOCK_INVALID_HEADER (high-hash) ->
    // MaybePunishNodeForBlock punishes even via a compact block.
    try testing.expect(!stillConnected(&fx));
    try testing.expect(banned(&fx, .{ 8, 8, 8, 2 }));
}

test "sec_p2p_cmpct_inv H1 a cmpctblock on the tip with the wrong nBits is not reconstructed and is punished" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 3 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    // A harder-than-required target: real PoW for its own nBits, but
    // regtest requires the pow-limit bits (bad-diffbits).
    const wrong_bits: u32 = 0x2000ffff;
    try testing.expect(wrong_bits != params.genesis_header.bits);
    const hdr = grindHeader(params.genesis_hash, wrong_bits, params.genesis_header.timestamp + 600, .pass, 0x13);
    var parts: CmpctParts = undefined;
    const s = try roundTrip(&fx, p.remote, parts.msg(hdr), &buf);
    if (s.getdata_block_items + s.getblocktxn != 0) {
        std.debug.print("bad-diffbits cmpctblock was reconstructed: getdata block items={d} getblocktxn={d}\n", .{ s.getdata_block_items, s.getblocktxn });
        return error.ReconstructedBadDiffbits;
    }
    try testing.expect(!stillConnected(&fx));
    try testing.expect(banned(&fx, .{ 8, 8, 8, 3 }));
}

test "sec_p2p_cmpct_inv H1 a cmpctblock with an unknown parent is not reconstructed; one getheaders instead" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 4 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    // Three different headers on parents we have never seen, each with
    // valid regtest PoW so only the parent check can stop them.
    var s: Seen = .{};
    for (0..3) |i| {
        const hdr = grindHeader([_]u8{@intCast(0xA0 + i)} ** 32, params.genesis_header.bits, params.genesis_header.timestamp + 600, .pass, 0x14);
        var parts: CmpctParts = undefined;
        s = try roundTrip(&fx, p.remote, parts.msg(hdr), &buf);
    }
    if (s.getdata_block_items + s.getblocktxn != 0) {
        std.debug.print("unknown-parent cmpctblocks were reconstructed: getdata block items={d} getblocktxn={d}\n", .{ s.getdata_block_items, s.getblocktxn });
        return error.ReconstructedUnknownParent;
    }
    // Core: "Doesn't connect ... request deeper headers" via
    // MaybeSendGetHeaders, which allows one per HEADERS_RESPONSE_TIME.
    try testing.expectEqual(@as(usize, 1), s.getheaders);
    try testing.expect(stillConnected(&fx));
}

test "sec_p2p_cmpct_inv H1 the same cmpctblock repeated by one peer is reconstructed once" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 5 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    const hdr = validTipHeader(0x15);
    var s: Seen = .{};
    for (0..4) |_| {
        var parts: CmpctParts = undefined;
        s = try roundTrip(&fx, p.remote, parts.msg(hdr), &buf);
    }
    // Core: a block already in flight from this peer as a compact block ->
    // "Peer sent us compact block we were already syncing!", return.
    if (s.getdata_block_items + s.getblocktxn != 1) {
        std.debug.print("4 copies of one cmpctblock -> {d} block requests\n", .{s.getdata_block_items + s.getblocktxn});
        return error.RepeatedReconstruction;
    }
}

// ---------------------------------------------------------------------------
// inv: blocks
// ---------------------------------------------------------------------------

test "sec_p2p_cmpct_inv H2 block invs for unknown blocks send one getheaders per response window" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 9, 1 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    var s: Seen = .{};
    for (0..5) |i| {
        var inv = [_]p2p.InvVector{.{ .inv_type = .msg_block, .hash = [_]u8{@intCast(0xB0 + i)} ** 32 }};
        s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = &inv } }, &buf);
    }
    if (s.getheaders != 1) {
        std.debug.print("5 block invs, no headers reply -> {d} getheaders\n", .{s.getheaders});
        return error.UnthrottledGetheaders;
    }
}

test "sec_p2p_cmpct_inv H2 a getheaders answered by headers re-opens the window" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 9, 2 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    var inv1 = [_]p2p.InvVector{.{ .inv_type = .msg_block, .hash = [_]u8{0xC1} ** 32 }};
    var s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = &inv1 } }, &buf);
    try testing.expectEqual(@as(usize, 1), s.getheaders);
    // The peer answers (empty headers: "nothing new") -> Core clears
    // m_last_getheaders_timestamp, so the next announcement may ask again.
    _ = try roundTrip(&fx, p.remote, .{ .headers = .{ .headers = &[_]types.BlockHeader{} } }, &buf);
    var inv2 = [_]p2p.InvVector{.{ .inv_type = .msg_block, .hash = [_]u8{0xC2} ** 32 }};
    s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = &inv2 } }, &buf);
    try testing.expectEqual(@as(usize, 2), s.getheaders);
}

test "sec_p2p_cmpct_inv H2 a block inv for a block we already have sends no getheaders" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 9, 3 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    // Our tip (genesis), announced back at us.
    var inv = [_]p2p.InvVector{.{ .inv_type = .msg_block, .hash = params.genesis_hash }};
    const s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = &inv } }, &buf);
    if (s.getheaders != 0) {
        std.debug.print("inv of our own tip -> {d} getheaders\n", .{s.getheaders});
        return error.GetheadersForKnownBlock;
    }
}

test "sec_p2p_cmpct_inv H2 control: a block inv for a queued header still records the peer's availability" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 9, 4 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    // Heights 1..300 queued for download (tip = genesis, cursor at 0).
    for (0..300) |i| {
        var hh = [_]u8{0} ** 32;
        std.mem.writeInt(u64, hh[0..8], 0x5100_0000 + i, .little);
        try fx.pm.expected_blocks.append(hh);
    }
    var target = [_]u8{0} ** 32;
    std.mem.writeInt(u64, target[0..8], 0x5100_0000 + 199, .little);
    var inv = [_]p2p.InvVector{.{ .inv_type = .msg_block, .hash = target }};
    _ = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = &inv } }, &buf);
    try testing.expectEqual(@as(u32, 200), p.peer.blocks_available_height);

    // The queue is compacted/rewritten (the connect path shifts it to the
    // front after a large connect run) and re-extended: lookups must follow.
    fx.pm.expected_blocks.shrinkRetainingCapacity(100);
    for (100..250) |i| {
        var hh = [_]u8{0} ** 32;
        std.mem.writeInt(u64, hh[0..8], 0x5200_0000 + i, .little);
        try fx.pm.expected_blocks.append(hh);
    }
    // The old height-199 hash is gone from the queue: no availability.
    p.peer.blocks_available_height = 0;
    _ = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = &inv } }, &buf);
    try testing.expectEqual(@as(u32, 0), p.peer.blocks_available_height);
    var moved = [_]u8{0} ** 32;
    std.mem.writeInt(u64, moved[0..8], 0x5200_0000 + 240, .little);
    var inv2 = [_]p2p.InvVector{.{ .inv_type = .msg_block, .hash = moved }};
    _ = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = &inv2 } }, &buf);
    try testing.expectEqual(@as(u32, 241), p.peer.blocks_available_height);
}

test "sec_p2p_cmpct_inv H2 a full block inv against a long header queue is not a linear scan per item" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 9, 5 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    // A header-sync queue of 20,000 (mainnet IBD holds ~900,000).
    try fx.pm.expected_blocks.ensureTotalCapacity(20_000);
    for (0..20_000) |i| {
        var hh = [_]u8{0} ** 32;
        std.mem.writeInt(u64, hh[0..8], 0x6100_0000 + i, .little);
        fx.pm.expected_blocks.appendAssumeCapacity(hh);
    }
    // One block inv of 50,000 unknown hashes (MAX_INV_SZ).
    const items = try a.alloc(p2p.InvVector, p2p.MAX_INV_SIZE);
    defer a.free(items);
    for (items, 0..) |*it, i| {
        it.inv_type = .msg_block;
        it.hash = [_]u8{0xEE} ** 32;
        std.mem.writeInt(u64, it.hash[0..8], i, .little);
    }
    var timer = try std.time.Timer.start();
    _ = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = items } }, &buf);
    const ms = timer.read() / std.time.ns_per_ms;
    std.debug.print("50,000-item block inv against a 20,000-header queue: {d} ms\n", .{ms});
    // Linear: 5*10^4 items x 2*10^4 compares = 10^9. Hash lookup: 5*10^4 probes.
    if (ms > 2_000) return error.InvLinearScan;
}

// ---------------------------------------------------------------------------
// inv: transactions
// ---------------------------------------------------------------------------

fn txInv(a: std.mem.Allocator, n: usize, tag: u32, kind: p2p.InvType) ![]p2p.InvVector {
    const items = try a.alloc(p2p.InvVector, n);
    for (items, 0..) |*it, i| {
        it.inv_type = kind;
        it.hash = [_]u8{0x77} ** 32;
        std.mem.writeInt(u32, it.hash[0..4], tag, .little);
        std.mem.writeInt(u32, it.hash[4..8], @intCast(i), .little);
    }
    return items;
}

test "sec_p2p_cmpct_inv H2 control: an honest tx inv is requested" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var pool = mempool_mod.Mempool.init(null, null, a);
    defer pool.deinit();
    fx.pm.mempool = &pool;
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 10, 1 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    const items = try txInv(a, 10, 1, .msg_wtx);
    defer a.free(items);
    const s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = items } }, &buf);
    try testing.expectEqual(@as(usize, 10), s.getdata_items);
}

test "sec_p2p_cmpct_inv H2 tx invs are capped at MAX_PEER_TX_ANNOUNCEMENTS outstanding per peer" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var pool = mempool_mod.Mempool.init(null, null, a);
    defer pool.deinit();
    fx.pm.mempool = &pool;
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 10, 2 }, false);
    defer std.posix.close(p.remote);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    const first = try txInv(a, 6000, 2, .msg_wtx);
    defer a.free(first);
    var s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = first } }, &buf);
    if (s.getdata_items != 5000) {
        std.debug.print("6,000 unknown wtxids announced -> {d} requested (Core caps 5,000)\n", .{s.getdata_items});
        return error.TxRequestsUncapped;
    }
    // The same announcements again: all already requested from this peer.
    s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = first } }, &buf);
    if (s.getdata_items != 5000) {
        std.debug.print("re-announcement -> {d} total requested (want 5000)\n", .{s.getdata_items});
        return error.TxReRequested;
    }
    // notfound for 1,000 of them frees 1,000 slots for fresh announcements.
    _ = try roundTrip(&fx, p.remote, .{ .notfound = .{ .inventory = first[0..1000] } }, &buf);
    const fresh = try txInv(a, 1500, 3, .msg_wtx);
    defer a.free(fresh);
    s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = fresh } }, &buf);
    try testing.expectEqual(@as(usize, 6000), s.getdata_items);
}

test "sec_p2p_cmpct_inv H2 tx invs are not requested during initial block download" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var pool = mempool_mod.Mempool.init(null, null, a);
    defer pool.deinit();
    fx.pm.mempool = &pool;
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 10, 3 }, false);
    defer std.posix.close(p.remote);
    // The peer is far ahead of our tip: we are in IBD.
    p.peer.start_height = 1000;
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    const items = try txInv(a, 50, 4, .msg_wtx);
    defer a.free(items);
    const s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = items } }, &buf);
    if (s.getdata_items != 0) {
        std.debug.print("tx inv during IBD -> {d} requested\n", .{s.getdata_items});
        return error.TxRequestedDuringIbd;
    }
}

test "sec_p2p_cmpct_inv H2 a tx inv from a block-relay-only peer disconnects it and requests nothing" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var pool = mempool_mod.Mempool.init(null, null, a);
    defer pool.deinit();
    fx.pm.mempool = &pool;
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 10, 4 }, false);
    defer std.posix.close(p.remote);
    p.peer.conn_type = .block_relay;
    p.peer.relay_self = false;
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    const items = try txInv(a, 5, 5, .msg_wtx);
    defer a.free(items);
    const s = try roundTrip(&fx, p.remote, .{ .inv = .{ .inventory = items } }, &buf);
    if (s.getdata_items != 0) {
        std.debug.print("tx inv on a block-relay-only link -> {d} requested\n", .{s.getdata_items});
        return error.TxRequestedFromBlockRelayOnly;
    }
    // Core RejectIncomingTxs: "inv sent in violation of protocol" ->
    // fDisconnect, no discouragement.
    try testing.expect(!stillConnected(&fx));
    try testing.expect(!banned(&fx, .{ 8, 8, 10, 4 }));
}
