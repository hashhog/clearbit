//! At-tip liveness + send-stall wedge: tests that need the NEW API (send
//! queue, stale-tip extra outbound, quiet-headers ask). The base-comparable
//! tests (which also run against 51b9917 to show fail-before) live in
//! tests_tip_liveness.zig, whose helpers this file reuses.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;
const h = @import("tests_tip_liveness.zig");
const params = h.params;
const initPm = h.initPm;
const addPeer = h.addPeer;
const sendFrom = h.sendFrom;
const countFrames = h.countFrames;
const BigBlock = h.BigBlock;

test "tip_liveness: getdata past the send-pause limit is deferred and resumed once the peer reads (Core fPauseSend)" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const slow = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, false);
    defer std.posix.close(slow.remote);

    var bb: BigBlock = undefined;
    const blk = try bb.init(a, 300_000);
    defer bb.deinit(a);
    const bh = crypto.computeBlockHash(&blk.header);
    try pm.block_buffer.put(bh, blk);
    defer _ = pm.block_buffer.remove(bh);

    const n_req: usize = 16;
    var inv: [n_req]p2p.InvVector = undefined;
    for (&inv) |*it| it.* = .{ .inv_type = .msg_witness_block, .hash = bh };
    try sendFrom(slow.remote, .{ .getdata = .{ .inventory = &inv } });
    try pm.processAllMessages();

    // Paused after ~1 MB queued; the rest is waiting, not queued.
    try testing.expect(slow.peer.sendPaused());
    try testing.expect(slow.peer.deferred_getdata.items.len > 0);
    try testing.expect(slow.peer.pendingSendBytes() < peer_mod.SEND_BUFFER_PAUSE_BYTES + 400_000);

    // Now the peer reads: every requested block arrives, in full.
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();
    var got: usize = 0;
    var spins: usize = 0;
    while (spins < 2_000 and got < n_req) : (spins += 1) {
        got = try countFrames(slow.remote, &buf, "block", null);
        try pm.processAllMessages(); // sweep: flush + resume deferred getdata
    }
    got = try countFrames(slow.remote, &buf, "block", null);
    try testing.expectEqual(n_req, got);
    try testing.expectEqual(@as(usize, 0), slow.peer.deferred_getdata.items.len);
    try testing.expectEqual(@as(usize, 1), pm.peers.items.len); // still connected
}

// ---------------------------------------------------------------------------
// 3. stalled sender → disconnect, no ban; draining sender kept
// ---------------------------------------------------------------------------

test "tip_liveness: a peer whose send queue makes no progress is disconnected (no ban); a draining one is kept" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const stuck = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, true);
    defer std.posix.close(stuck.remote);
    const slow = try addPeer(&pm, a, .{ 9, 9, 9, 9 }, true);
    defer std.posix.close(slow.remote);

    const hdr = params.genesis_header;
    var hash: types.Hash256 = [_]u8{1} ** 32;
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        hash[0] = @truncate(i);
        pm.announceBlock(&hdr, &hash);
    }
    try testing.expect(stuck.peer.pendingSendBytes() > 0);
    try testing.expect(slow.peer.pendingSendBytes() > 0);

    const now = std.time.timestamp();
    // Both have been "stuck" longer than the limit by the clock...
    stuck.peer.send_progress_ts = now - peer_mod.SEND_STALL_TIMEOUT_SECS - 5;
    slow.peer.send_progress_ts = now - peer_mod.SEND_STALL_TIMEOUT_SECS - 5;
    // ...but the slow peer reads some bytes now, so the flush makes progress.
    var sink = std.ArrayList(u8).init(a);
    defer sink.deinit();
    _ = try countFrames(slow.remote, &sink, "inv", null);

    const stuck_addr = stuck.peer.address;
    const slow_ptr = slow.peer;
    pm.sweepSendQueues();

    try testing.expectEqual(@as(usize, 1), pm.peers.items.len);
    try testing.expect(pm.peers.items[0] == slow_ptr);
    try testing.expect(!pm.ban_list.isAddressBanned(stuck_addr));
    try testing.expectEqual(@as(u64, 1), pm.send_stall_disconnects);
}

test "tip_liveness: a hard send error marks the peer failed and it is disconnected without a ban" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();
    const dead = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, false);
    const addr = dead.peer.address;
    std.posix.close(dead.remote); // peer gone: next send gets EPIPE
    const ping = p2p.Message{ .ping = .{ .nonce = 7 } };
    try testing.expectError(peer_mod.PeerError.ConnectionClosed, dead.peer.sendMessage(&ping));
    try testing.expect(dead.peer.send_failed);
    pm.sweepSendQueues();
    try testing.expectEqual(@as(usize, 0), pm.peers.items.len);
    try testing.expect(!pm.ban_list.isAddressBanned(addr));
}


// ---------------------------------------------------------------------------
// 7. stale tip → extra outbound; extra outbound eviction
// ---------------------------------------------------------------------------

test "tip_liveness: stale tip allows one extra outbound; the extra with the oldest announcement is evicted" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const now = std.time.timestamp();
    var remotes: [9]std.posix.fd_t = undefined;
    var victim: *Peer = undefined;
    for (0..9) |k| {
        const pr = try addPeer(&pm, a, .{ 10, 0, 0, @intCast(k + 1) }, false);
        remotes[k] = pr.remote;
        pr.peer.direction = .outbound;
        pr.peer.conn_type = .outbound_full_relay;
        pr.peer.connect_time = now - 600;
        pr.peer.last_block_announcement = now - 100 + @as(i64, @intCast(k));
        if (k == 0) victim = pr.peer; // oldest announcement
    }
    defer for (remotes) |r| std.posix.close(r);

    // Tip not updated for > 30 min, nothing in flight → stale.
    pm.last_tip_update_time = now - peer_mod.STALE_TIP_THRESHOLD - 1;
    try testing.expect(pm.tipMayBeStale());
    pm.last_stale_check_time = 0;
    pm.checkForStaleTipAndEvictPeers();
    // 9 > 8 full-relay outbound: the oldest announcer is trimmed, and the
    // extra-peer attempt ends with it (Core SetTryNewOutboundPeer(false)).
    try testing.expectEqual(@as(usize, 8), pm.peers.items.len);
    for (pm.peers.items) |p| try testing.expect(p != victim);
    try testing.expect(pm.try_new_outbound); // still stale → may try again

    // Fresh tip → no extra peer.
    pm.last_tip_update_time = now;
    pm.last_stale_check_time = 0;
    pm.checkForStaleTipAndEvictPeers();
    try testing.expect(!pm.try_new_outbound);
}

// ---------------------------------------------------------------------------
// 8. quiet headers → ask up to 3 outbound peers
// ---------------------------------------------------------------------------

test "tip_liveness: no header progress for HEADERS_QUIET_ASK_SECS sends getheaders to up to 3 outbound peers" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();
    var remotes: [5]std.posix.fd_t = undefined;
    for (0..5) |k| {
        const pr = try addPeer(&pm, a, .{ 10, 0, 1, @intCast(k + 1) }, false);
        remotes[k] = pr.remote;
        pr.peer.direction = if (k == 4) .inbound else .outbound;
    }
    defer for (remotes) |r| std.posix.close(r);

    const now = std.time.timestamp();
    // Negative control: recent progress → nobody asked.
    pm.last_header_progress_time = now - 10;
    pm.last_tip_update_time = now - 10;
    pm.askHeadersIfQuiet(now);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();
    var asked: usize = 0;
    for (remotes) |r| {
        buf.clearRetainingCapacity();
        asked += try countFrames(r, &buf, "getheaders", null);
    }
    try testing.expectEqual(@as(usize, 0), asked);

    pm.last_header_progress_time = now - peer_mod.HEADERS_QUIET_ASK_SECS - 1;
    pm.last_tip_update_time = now - peer_mod.HEADERS_QUIET_ASK_SECS - 1;
    pm.askHeadersIfQuiet(now);
    asked = 0;
    for (remotes, 0..) |r, k| {
        buf.clearRetainingCapacity();
        const c = try countFrames(r, &buf, "getheaders", null);
        if (k == 4) try testing.expectEqual(@as(usize, 0), c); // inbound never asked
        asked += c;
    }
    try testing.expectEqual(@as(usize, peer_mod.HEADERS_QUIET_ASK_PEERS), asked);
}
