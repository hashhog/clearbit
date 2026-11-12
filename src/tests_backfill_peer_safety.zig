//! Historical-body backfill peer safety (fix-clearbit-backfill-peer-safety).
//!
//! 11-11 mainnet: after every restart the assumeutxo-hole backfill
//!   (a) asked NODE_NETWORK_LIMITED (pruned) peers for 2012-era bodies, which
//!       Core answers by disconnecting (net_processing.cpp:2384-2390);
//!   (b) re-armed on every delivered body, sending up to 16 NEW getdata per
//!       body with no per-peer cap (Core MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16);
//!   (c) never released a departed peer's in-flight hashes, so the body cursor
//!       stuck at the first lost hash for the rest of the run;
//!   (d) walked cumulative tx counts from height 1 on every body (~179k
//!       RocksDB reads per body under cs_main on the P2P thread).
//!
//! These tests drive the real PeerManager paths (driveHistoricalBackfill, the
//! `.block` handler via ingestBlockMessage, removePeer) and read what each
//! peer is actually sent off the far end of a socketpair.

const std = @import("std");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const p2p = @import("p2p.zig");
const storage = @import("storage.zig");
const hb = @import("historical_backfill.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

const params = &consensus.REGTEST;

const FULL: u64 = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
const LIMITED: u64 = p2p.NODE_NETWORK_LIMITED | p2p.NODE_WITNESS;

/// One peer wired to a socketpair; `far` is what the remote would read.
const Wire = struct {
    peer: *Peer,
    far: std.posix.fd_t,
    /// Bytes read off `far` but not yet a whole frame.
    pending: std.ArrayListUnmanaged(u8) = .{},
};

const Rig = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: PeerManager,
    blocks: []types.Block,
    floor: u32,
    wires: std.ArrayListUnmanaged(Wire) = .{},

    /// Regtest chain 0..tip with an assumeutxo hole 1..floor-1. All hole
    /// headers are stored (so the drive only asks for bodies).
    fn init(self: *Rig, allocator: std.mem.Allocator, floor: u32, tip: u32) !void {
        self.allocator = allocator;
        self.floor = floor;
        self.wires = .{};
        self.tmp = std.testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(allocator, ".");
        self.db = try storage.Database.open(self.path, 64, allocator);
        self.cs = storage.ChainState.init(&self.db, 64, allocator);
        self.blocks = try hb.buildRegtestChain(allocator, params, tip);
        hb.seedSnapshotHole(&self.cs, self.blocks, floor, tip);
        self.pm = PeerManager.init(allocator, params);
        self.pm.anchors_path = "/dev/null";
        self.pm.chain_state = &self.cs;
        self.pm.armHistoricalBackfill();
        const bf = &(self.pm.historical_backfill orelse return error.BackfillNotArmed);
        const hdrs = try allocator.alloc(types.BlockHeader, floor - 1);
        defer allocator.free(hdrs);
        for (hdrs, 0..) |*h, i| h.* = self.blocks[i + 1].header;
        _ = try bf.acceptHeaders(hdrs, &self.cs, params);
        try std.testing.expect(bf.headersComplete());
    }

    fn deinit(self: *Rig) void {
        for (self.wires.items) |*w| {
            w.pending.deinit(self.allocator);
            std.posix.close(w.far);
        }
        self.wires.deinit(self.allocator);
        // pm.deinit disconnects + destroys every peer still in pm.peers.
        self.pm.chain_state = null;
        self.pm.deinit();
        hb.freeRegtestChain(self.allocator, self.blocks);
        self.cs.deinit();
        self.db.close();
        self.allocator.free(self.path);
        self.tmp.cleanup();
    }

    /// A handshake-complete outbound peer with `services`, registered in
    /// pm.peers. Returns its wire index.
    fn addPeer(self: *Rig, services: u64, last_octet: u8) !usize {
        var fds: [2]i32 = undefined;
        try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
        const p = try self.allocator.create(Peer);
        p.* = stubPeer(self.allocator, services, last_octet);
        p.stream = .{ .handle = fds[0] };
        try self.pm.peers.append(p);
        try self.wires.append(self.allocator, .{ .peer = p, .far = fds[1] });
        return self.wires.items.len - 1;
    }

    fn removePeer(self: *Rig, wire: usize) void {
        self.pm.removePeer(self.wires.items[wire].peer);
    }

    /// Block hashes in every getdata the peer on `wire` has been sent since
    /// the last call, appended to `out`.
    fn drainGetdata(self: *Rig, wire: usize, out: *std.ArrayList(types.Hash256)) !void {
        const w = &self.wires.items[wire];
        var buf: [65536]u8 = undefined;
        while (true) {
            const n = std.posix.recv(w.far, &buf, std.posix.MSG.DONTWAIT) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (n == 0) break;
            try w.pending.appendSlice(self.allocator, buf[0..n]);
        }
        var off: usize = 0;
        while (w.pending.items.len - off >= 24) {
            const hdr = p2p.MessageHeader.decode(w.pending.items[off..][0..24]);
            const frame_len = 24 + @as(usize, hdr.length);
            if (w.pending.items.len - off < frame_len) break;
            const payload = w.pending.items[off + 24 .. off + frame_len];
            if (std.mem.eql(u8, hdr.commandName(), "getdata")) {
                const msg = try p2p.decodePayload("getdata", payload, self.allocator);
                defer p2p.freeDecodedMessage(self.allocator, msg);
                for (msg.getdata.inventory) |inv| try out.append(inv.hash);
            }
            off += frame_len;
        }
        const rest = w.pending.items.len - off;
        std.mem.copyForwards(u8, w.pending.items[0..rest], w.pending.items[off..]);
        w.pending.shrinkRetainingCapacity(rest);
    }

    /// Height of a hole hash.
    fn heightOf(self: *Rig, hash: *const types.Hash256) u32 {
        return self.cs.getBlockHeightByHash(hash).?;
    }

    /// A fresh owned copy of hole block `h` (the `.block` handler frees it).
    fn ownedBlock(self: *Rig, h: u32) !types.Block {
        const prev = crypto.computeBlockHash(&self.blocks[h - 1].header);
        const b = try hb.mineCoinbaseBlock(
            self.allocator,
            prev,
            h,
            self.blocks[h].header.timestamp,
            self.blocks[h].header.bits,
            params,
        );
        try std.testing.expectEqualSlices(u8, &crypto.computeBlockHash(&self.blocks[h].header), &crypto.computeBlockHash(&b.header));
        return b;
    }

    fn deliver(self: *Rig, wire: usize, h: u32) !void {
        try self.pm.ingestBlockMessage(self.wires.items[wire].peer, try self.ownedBlock(h));
    }
};

fn stubPeer(allocator: std.mem.Allocator, services: u64, last_octet: u8) Peer {
    return .{
        .stream = .{ .handle = -1 },
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, last_octet }, 0),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = services,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        // Not ahead of our tip: the drive yields to forward sync otherwise.
        .start_height = 0,
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
        .connect_time = 0,
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
    };
}

fn containsHash(list: []const types.Hash256, h: *const types.Hash256) bool {
    for (list) |x| if (std.mem.eql(u8, &x, h)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// (a) NODE_NETWORK gate
// ---------------------------------------------------------------------------

test "limited peer gets no historical getdata" {
    var r: Rig = undefined;
    try r.init(std.testing.allocator, 40, 50);
    defer r.deinit();
    const w = try r.addPeer(LIMITED, 2);

    r.pm.driveHistoricalBackfill(r.wires.items[w].peer);

    var got = std.ArrayList(types.Hash256).init(std.testing.allocator);
    defer got.deinit();
    try r.drainGetdata(w, &got);
    try std.testing.expectEqual(@as(usize, 0), got.items.len);
}

test "full-archive peer gets historical getdata (control for the limited-peer test)" {
    var r: Rig = undefined;
    try r.init(std.testing.allocator, 40, 50);
    defer r.deinit();
    const w = try r.addPeer(FULL, 2);

    r.pm.driveHistoricalBackfill(r.wires.items[w].peer);

    var got = std.ArrayList(types.Hash256).init(std.testing.allocator);
    defer got.deinit();
    try r.drainGetdata(w, &got);
    try std.testing.expectEqual(@as(usize, 16), got.items.len);
    try std.testing.expectEqual(@as(u32, 1), r.heightOf(&got.items[0]));
}

// ---------------------------------------------------------------------------
// (b) per-peer cap, including the `.block` re-drive
// ---------------------------------------------------------------------------

test "historical requests per peer never exceed 16 after 64 bodies delivered" {
    const allocator = std.testing.allocator;
    var r: Rig = undefined;
    try r.init(allocator, 200, 210);
    defer r.deinit();
    const w = try r.addPeer(FULL, 2);

    var asked = std.ArrayList(types.Hash256).init(allocator);
    defer asked.deinit();
    var delivered: usize = 0;
    var max_outstanding: usize = 0;

    r.pm.driveHistoricalBackfill(r.wires.items[w].peer);
    try r.drainGetdata(w, &asked);

    while (delivered < 64) {
        const outstanding = asked.items.len - delivered;
        max_outstanding = @max(max_outstanding, outstanding);
        if (outstanding == 0) return error.PeerStarved;
        // Deliver the oldest outstanding request, in order.
        const h = r.heightOf(&asked.items[delivered]);
        try r.deliver(w, h);
        delivered += 1;
        try r.drainGetdata(w, &asked);
    }
    max_outstanding = @max(max_outstanding, asked.items.len - delivered);

    try std.testing.expect(max_outstanding <= 16);
    // The cap tops the peer up rather than starving it: still 16 owed.
    try std.testing.expectEqual(@as(usize, 16), asked.items.len - delivered);
}

// ---------------------------------------------------------------------------
// (c) release on disconnect / timeout
// ---------------------------------------------------------------------------

test "in-flight hash of a removed peer is re-requested from another peer" {
    const allocator = std.testing.allocator;
    var r: Rig = undefined;
    try r.init(allocator, 10, 20); // hole 1..9: fits in one peer's 16
    defer r.deinit();
    const a = try r.addPeer(FULL, 2);
    const b = try r.addPeer(FULL, 3);

    r.pm.driveHistoricalBackfill(r.wires.items[a].peer);
    var to_a = std.ArrayList(types.Hash256).init(allocator);
    defer to_a.deinit();
    try r.drainGetdata(a, &to_a);
    try std.testing.expectEqual(@as(usize, 9), to_a.items.len);

    // B is not asked for what A owes.
    r.pm.driveHistoricalBackfill(r.wires.items[b].peer);
    var to_b = std.ArrayList(types.Hash256).init(allocator);
    defer to_b.deinit();
    try r.drainGetdata(b, &to_b);
    try std.testing.expectEqual(@as(usize, 0), to_b.items.len);

    // A disconnects without delivering anything.
    r.removePeer(a);

    r.pm.driveHistoricalBackfill(r.wires.items[b].peer);
    try r.drainGetdata(b, &to_b);
    try std.testing.expectEqual(@as(usize, 9), to_b.items.len);
    for (to_a.items) |h| try std.testing.expect(containsHash(to_b.items, &h));
}

test "historical body not delivered in time is re-requested from another peer" {
    // Head-only API (requested_at); guarded so the file compiles on master.
    if (comptime !@hasDecl(hb, "HISTORICAL_BODY_TIMEOUT_S")) return error.NoHistoricalTimeout else try timeoutReRequest();
}

fn timeoutReRequest() !void {
    const allocator = std.testing.allocator;
    var r: Rig = undefined;
    try r.init(allocator, 10, 20);
    defer r.deinit();
    const a = try r.addPeer(FULL, 2);
    const b = try r.addPeer(FULL, 3);

    r.pm.driveHistoricalBackfill(r.wires.items[a].peer);
    var to_a = std.ArrayList(types.Hash256).init(allocator);
    defer to_a.deinit();
    try r.drainGetdata(a, &to_a);
    try std.testing.expectEqual(@as(usize, 9), to_a.items.len);

    // A stays connected but its requests age past the timeout.
    const bf = &r.pm.historical_backfill.?;
    var it = bf.in_flight.valueIterator();
    while (it.next()) |v| v.requested_at -= hb.HISTORICAL_BODY_TIMEOUT_S + 1;

    r.pm.driveHistoricalBackfill(r.wires.items[b].peer);
    var to_b = std.ArrayList(types.Hash256).init(allocator);
    defer to_b.deinit();
    try r.drainGetdata(b, &to_b);
    try std.testing.expectEqual(@as(usize, 9), to_b.items.len);
    try std.testing.expectEqual(@as(usize, 0), bf.inFlightFor(@intFromPtr(r.wires.items[a].peer)));
}

// ---------------------------------------------------------------------------
// (d) incremental tx counts
// ---------------------------------------------------------------------------

test "accepting one body above a stuck cursor reads O(1) tx counts" {
    const allocator = std.testing.allocator;
    var r: Rig = undefined;
    try r.init(allocator, 300, 310);
    defer r.deinit();
    const bf = &r.pm.historical_backfill.?;

    // Bodies 1..99 and 101..150: the cursor sticks at the hole at 100.
    var h: u32 = 1;
    while (h <= 150) : (h += 1) {
        if (h == 100) continue;
        try std.testing.expect(try bf.acceptBlock(&r.blocks[h], &r.cs));
    }
    try std.testing.expectEqual(@as(u32, 100), bf.next_body_height);

    // The read counter is a test hook the fix adds; master has none and
    // walks heights 1..cursor-1 on every body.
    if (comptime !@hasDecl(hb, "tx_count_reads")) {
        return error.NoTxCountReadHook;
    } else {
        @field(hb, "tx_count_reads") = 0;
        try std.testing.expect(try bf.acceptBlock(&r.blocks[200], &r.cs));
        try std.testing.expect(@field(hb, "tx_count_reads") <= 2);
    }
}

test "cumulative tx counts are still exact after the hole closes" {
    const allocator = std.testing.allocator;
    var r: Rig = undefined;
    try r.init(allocator, 40, 50);
    defer r.deinit();
    const bf = &r.pm.historical_backfill.?;

    // Out of order with a late hole: 1..19, 21..39, then 20.
    var h: u32 = 1;
    while (h < 40) : (h += 1) {
        if (h == 20) continue;
        _ = try bf.acceptBlock(&r.blocks[h], &r.cs);
    }
    try std.testing.expect(r.cs.getCumulativeTxCount(20) == null);
    _ = try bf.acceptBlock(&r.blocks[20], &r.cs);
    try std.testing.expect(bf.bodiesComplete());
    // One coinbase per block, genesis counts 1: height n has n+1 txs.
    h = 1;
    while (h < 40) : (h += 1) {
        try std.testing.expectEqual(@as(?u64, h + 1), r.cs.getCumulativeTxCount(h));
    }
}

// ---------------------------------------------------------------------------
// Consensus-adjacent: a body is only ever stored under its own hole header.
// ---------------------------------------------------------------------------

test "historical body that matches no hole header is rejected and not stored" {
    const allocator = std.testing.allocator;
    var r: Rig = undefined;
    try r.init(allocator, 10, 20);
    defer r.deinit();
    const bf = &r.pm.historical_backfill.?;

    // A block with a valid PoW header that is not in the hole (different
    // timestamp, so a different hash) must not be stored at any height.
    var stray = try hb.mineCoinbaseBlock(
        allocator,
        crypto.computeBlockHash(&r.blocks[4].header),
        5,
        r.blocks[5].header.timestamp + 1,
        r.blocks[5].header.bits,
        params,
    );
    defer @import("serialize.zig").freeBlock(allocator, &stray);
    const stray_hash = crypto.computeBlockHash(&stray.header);
    try std.testing.expectError(hb.BackfillError.UnexpectedBlock, bf.acceptBlock(&stray, &r.cs));
    try std.testing.expect(!r.cs.hasBlock(&stray_hash));
    const h5 = crypto.computeBlockHash(&r.blocks[5].header);
    try std.testing.expect(!r.cs.hasBlock(&h5));

    // A snapshot-tail body (height >= floor) is not the backfill's to write.
    try std.testing.expectError(hb.BackfillError.UnexpectedBlock, bf.acceptBlock(&r.blocks[12], &r.cs));
    const h12 = crypto.computeBlockHash(&r.blocks[12].header);
    try std.testing.expect(!r.cs.hasBlock(&h12));

    // The real body lands under its own hash, at its own height, and the tip
    // does not move.
    const tip_hash = r.cs.best_hash;
    try std.testing.expect(try bf.acceptBlock(&r.blocks[5], &r.cs));
    try std.testing.expect(r.cs.hasBlock(&h5));
    try std.testing.expectEqualSlices(u8, &h5, &r.cs.getBlockHashByHeight(5).?);
    try std.testing.expectEqual(@as(u32, 20), r.cs.best_height);
    try std.testing.expectEqualSlices(u8, &tip_hash, &r.cs.best_hash);
}
