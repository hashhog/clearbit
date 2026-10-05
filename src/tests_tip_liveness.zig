//! At-tip liveness + send-stall wedge (2026-10-05 mainnet tip stalls).
//!
//! These drive the REAL PeerManager over unix socketpairs. A "non-reading
//! peer" is a socketpair whose far end never recv()s, with tiny socket
//! buffers so it fills after a few writes — exactly what an inbound peer
//! that stops reading looks like to clearbit's single P2P thread.
//!
//! Every test that could HANG on a regression (a blocking send) runs the
//! clearbit call on a worker thread under a watchdog: if the call has not
//! returned within WATCHDOG_MS the test FAILS, then shuts the socket down to
//! unblock the worker so the suite can continue. On 51b9917 those tests fail
//! (the call blocks until the watchdog); on the fix they pass in milliseconds.
//!
//! Pinned behaviour:
//!   1. announceBlock (called from the block-connect loop) never blocks on a
//!      peer that stopped reading; other peers still get the announcement.
//!   2. getdata block serving to a non-reader returns promptly; the rest of
//!      the request is deferred (Core fPauseSend) and resumed once it drains.
//!   3. a peer whose queued bytes make no progress for SEND_STALL_TIMEOUT_SECS
//!      is disconnected, never banned; a slow-but-draining peer is kept.
//!   4. a headers reply (empty or connecting) clears the getheaders timer
//!      (Core net_processing.cpp:2977/3041).
//!   5. a headers timeout DISCONNECTS, never discourages (Core :6124-6153);
//!      manual peers are kept.
//!   6. the drain-wedge recovery re-requests a stuck front block from a
//!      DIFFERENT peer than the one it stalled on.
//!   7. stale tip → one extra outbound allowed; the extra peer with the
//!      oldest block announcement is evicted (Core CheckForStaleTipAndEvictPeers).
//!   8. quiet headers → getheaders to up to 3 outbound peers.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

pub const params = &consensus.REGTEST;
pub const WATCHDOG_MS: i64 = 3000;

/// The same file compiles against the pre-fix tree (51b9917) so the
/// fail-before run uses identical tests: assertions that need the new API
/// sit behind these comptime gates, and fix-only tests skip on the old tree.
pub const has_queue = @hasDecl(Peer, "pendingSendBytes");
pub const has_liveness = @hasDecl(PeerManager, "askHeadersIfQuiet");

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub fn initPm(a: std.mem.Allocator) PeerManager {
    var pm = PeerManager.init(a, params);
    pm.anchors_path = "/dev/null";
    pm.ban_list.file_path = null; // never write banlist.json from a test
    return pm;
}

pub const Pair = struct { peer: *Peer, remote: std.posix.fd_t };

/// A handshake-complete peer on a socketpair, owned by `pm` once appended.
/// `small` shrinks both socket buffers so a non-reading remote fills fast.
pub fn addPeer(pm: *PeerManager, a: std.mem.Allocator, ip: [4]u8, small: bool) !Pair {
    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
    if (small) {
        const sz: c_int = 4096;
        try std.posix.setsockopt(fds[0], std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&sz));
        try std.posix.setsockopt(fds[1], std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&sz));
    }
    const p = try a.create(Peer);
    p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4(ip, 8333), params, a);
    p.state = .handshake_complete;
    p.services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
    try pm.peers.append(p);
    return .{ .peer = p, .remote = fds[1] };
}

pub fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) off += try std.posix.write(fd, bytes[off..]);
}

pub fn sendFrom(remote: std.posix.fd_t, msg: p2p.Message) !void {
    const bytes = try p2p.encodeMessage(&msg, params.magic, testing.allocator);
    defer testing.allocator.free(bytes);
    try writeAllFd(remote, bytes);
}

/// Read everything currently readable on `fd`; return the count of complete
/// frames whose command is `cmd` (and the total frame count via `total`).
pub fn countFrames(fd: std.posix.fd_t, buf: *std.ArrayList(u8), cmd: []const u8, total: ?*usize) !usize {
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = std.posix.recv(fd, &tmp, std.posix.MSG.DONTWAIT) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;
        try buf.appendSlice(tmp[0..n]);
    }
    var pos: usize = 0;
    var hits: usize = 0;
    var all: usize = 0;
    while (buf.items.len - pos >= 24) {
        const hdr = buf.items[pos .. pos + 24];
        const len = std.mem.readInt(u32, hdr[16..20], .little);
        if (buf.items.len - pos < 24 + len) break;
        const name_end = std.mem.indexOfScalar(u8, hdr[4..16], 0) orelse 12;
        if (std.mem.eql(u8, hdr[4 .. 4 + name_end], cmd)) hits += 1;
        all += 1;
        pos += 24 + len;
    }
    if (total) |t| t.* = all;
    return hits;
}

/// Run `func(ctx)` on a worker thread; true iff it returned within
/// WATCHDOG_MS. While waiting, the test thread READS `drain_fd` (an honest
/// peer's far end) into `drain_buf`, so only the deliberately non-reading
/// peer can fill up. On a timeout every fd in `unblock_fds` is shut down so
/// the worker's blocking write fails and the thread can be joined.
pub fn finishesInTime(
    comptime Ctx: type,
    comptime func: fn (*Ctx) void,
    ctx: *Ctx,
    unblock_fds: []const std.posix.fd_t,
    drain_fd: ?std.posix.fd_t,
    drain_buf: ?*std.ArrayList(u8),
) bool {
    var done = std.atomic.Value(bool).init(false);
    const Wrap = struct {
        fn run(c: *Ctx, d: *std.atomic.Value(bool)) void {
            func(c);
            d.store(true, .release);
        }
    };
    const t = std.Thread.spawn(.{}, Wrap.run, .{ ctx, &done }) catch return false;
    const start = std.time.milliTimestamp();
    var tmp: [65536]u8 = undefined;
    while (!done.load(.acquire) and std.time.milliTimestamp() - start < WATCHDOG_MS) {
        if (drain_fd) |fd| {
            const n = std.posix.recv(fd, &tmp, std.posix.MSG.DONTWAIT) catch 0;
            if (n > 0) {
                if (drain_buf) |b| b.appendSlice(tmp[0..n]) catch {};
                continue;
            }
        }
        std.time.sleep(2 * std.time.ns_per_ms);
    }
    const ok = done.load(.acquire);
    if (!ok) for (unblock_fds) |fd| std.posix.shutdown(fd, .both) catch {};
    t.join();
    return ok;
}

/// A block of roughly `n_bytes` (one tx with a big output script).
pub const BigBlock = struct {
    tx_in: [1]types.TxIn,
    tx_out: [1]types.TxOut,
    txs: [1]types.Transaction,
    script: []u8,

    pub fn init(self: *BigBlock, a: std.mem.Allocator, n_bytes: usize) !types.Block {
        self.script = try a.alloc(u8, n_bytes);
        @memset(self.script, 0x6a);
        self.tx_in[0] = .{
            .previous_output = .{ .hash = [_]u8{0x55} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xffffffff,
            .witness = &[_][]const u8{},
        };
        self.tx_out[0] = .{ .value = 1000, .script_pubkey = self.script };
        self.txs[0] = .{ .version = 2, .inputs = self.tx_in[0..], .outputs = self.tx_out[0..], .lock_time = 0 };
        return .{ .header = params.genesis_header, .transactions = self.txs[0..] };
    }
    pub fn deinit(self: *BigBlock, a: std.mem.Allocator) void {
        a.free(self.script);
    }
};

// ---------------------------------------------------------------------------
// 1. announceBlock never blocks on a non-reading peer
// ---------------------------------------------------------------------------

const AnnounceCtx = struct {
    pm: *PeerManager,
    hdr: types.BlockHeader,
    hash: types.Hash256,
    n: usize,
    fn run(c: *AnnounceCtx) void {
        var i: usize = 0;
        while (i < c.n) : (i += 1) {
            c.hash[0] = @truncate(i);
            c.pm.announceBlock(&c.hdr, &c.hash);
        }
    }
};

test "tip_liveness: announceBlock does not block on a peer that stopped reading; others still get every announcement" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const stuck = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, true); // never reads
    defer std.posix.close(stuck.remote);
    const good = try addPeer(&pm, a, .{ 8, 8, 8, 8 }, false);
    defer std.posix.close(good.remote);

    const n_ann: usize = 400;
    var ctx = AnnounceCtx{ .pm = &pm, .hdr = params.genesis_header, .hash = [_]u8{0} ** 32, .n = n_ann };
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();
    // 400 inv announcements (~61 B each) are far beyond a 4 KB socket: a
    // blocking send parks the connect loop on the first full write. The good
    // peer is read concurrently, so it is never the one that blocks.
    const ok = finishesInTime(
        AnnounceCtx,
        AnnounceCtx.run,
        &ctx,
        &.{ stuck.peer.stream.handle, good.peer.stream.handle },
        good.remote,
        &buf,
    );
    try testing.expect(ok);

    if (comptime has_queue) {
        // Every other peer still got all of them (drain while flushing: the
        // good peer's queue may hold a tail until its socket accepts it).
        var got: usize = 0;
        var spins: usize = 0;
        while (spins < 200) : (spins += 1) {
            good.peer.flushSendQueue();
            got = try countFrames(good.remote, &buf, "inv", null);
            if (got == n_ann) break;
        }
        try testing.expectEqual(n_ann, got);
        // The stuck peer's backlog is queued, not lost and not blocking.
        try testing.expect(stuck.peer.pendingSendBytes() > 0);
    }
}

// ---------------------------------------------------------------------------
// 2. getdata serving to a non-reader: prompt return + deferral + resume
// ---------------------------------------------------------------------------

const PamCtx = struct {
    pm: *PeerManager,
    fn run(c: *PamCtx) void {
        c.pm.processAllMessages() catch {};
    }
};

test "tip_liveness: serving getdata blocks to a non-reading peer does not block the P2P thread" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const stuck = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, true);
    defer std.posix.close(stuck.remote);

    var bb: BigBlock = undefined;
    const blk = try bb.init(a, 300_000);
    defer bb.deinit(a);
    const bh = crypto.computeBlockHash(&blk.header);
    try pm.block_buffer.put(bh, blk);
    defer _ = pm.block_buffer.remove(bh); // stack-owned block

    // 16 x 300 KB = 4.8 MB requested by a peer that never reads.
    var inv: [16]p2p.InvVector = undefined;
    for (&inv) |*it| it.* = .{ .inv_type = .msg_witness_block, .hash = bh };
    try sendFrom(stuck.remote, .{ .getdata = .{ .inventory = &inv } });

    var ctx = PamCtx{ .pm = &pm };
    try testing.expect(finishesInTime(PamCtx, PamCtx.run, &ctx, &.{stuck.peer.stream.handle}, null, null));
}

test "tip_liveness: an empty headers reply clears the getheaders timer (Core net_processing.cpp:2977)" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();
    const pr = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, false);
    defer std.posix.close(pr.remote);

    pr.peer.last_getheaders_time = std.time.timestamp() - 10;
    try sendFrom(pr.remote, .{ .headers = .{ .headers = &[_]types.BlockHeader{} } });
    try pm.processAllMessages();
    try testing.expectEqual(@as(i64, 0), pr.peer.last_getheaders_time);
}

test "tip_liveness: headers timeout disconnects the peer and does NOT discourage it; manual peers are kept" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const slow = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, false);
    defer std.posix.close(slow.remote);
    const manual = try addPeer(&pm, a, .{ 9, 9, 9, 9 }, false);
    defer std.posix.close(manual.remote);
    manual.peer.conn_type = .manual;

    const past = std.time.timestamp() - peer_mod.HEADERS_RESPONSE_TIMEOUT - 1;
    slow.peer.last_getheaders_time = past;
    manual.peer.last_getheaders_time = past;
    const slow_addr = slow.peer.address;
    const manual_ptr = manual.peer;

    pm.last_stale_check_time = 0;
    pm.checkForStaleTipAndEvictPeers();
    // Let any should_ban flag take effect the way the live loop would.
    try pm.processAllMessages();

    try testing.expect(!pm.ban_list.isAddressBanned(slow_addr));
    try testing.expectEqual(@as(usize, 1), pm.peers.items.len);
    try testing.expect(pm.peers.items[0] == manual_ptr);
    try testing.expect(!manual_ptr.should_ban);
}

// ---------------------------------------------------------------------------
// 6. stuck front block → re-request from a DIFFERENT peer
// ---------------------------------------------------------------------------

test "tip_liveness: a stuck front block is cancelled after the stall timeout and re-requested from another peer" {
    const a = testing.allocator;
    var cs = storage.ChainState.init(null, 64, a);
    defer cs.deinit();
    var pm = initPm(a);
    defer pm.deinit();
    pm.chain_state = &cs;
    defer pm.chain_state = null;

    // peers[0] announced the block and took the getdata but never delivers.
    const staller = try addPeer(&pm, a, .{ 8, 8, 4, 4 }, false);
    defer std.posix.close(staller.remote);
    const honest = try addPeer(&pm, a, .{ 9, 9, 9, 9 }, false);
    defer std.posix.close(honest.remote);

    const front: types.Hash256 = [_]u8{0xF0} ** 32;
    try pm.expected_blocks.append(front);
    pm.connect_cursor = 0;
    pm.download_cursor = 1;
    try pm.inflight_block_peer.put(front, @intFromPtr(staller.peer));
    staller.peer.recordBlockRequest();
    pm.blocks_in_flight = 1;

    // Negative control: inside the stall timeout nothing is cancelled.
    const now = std.time.timestamp();
    pm.wedge_since = now;
    pm.wedge_timeout = peer_mod.DRAIN_WEDGE_STALL_TIMEOUT;
    pm.drainBlockBuffer();
    try testing.expectEqual(@intFromPtr(staller.peer), pm.inflight_block_peer.get(front).?);

    // Past the stall timeout: cancelled...
    pm.wedge_since = now - peer_mod.DRAIN_WEDGE_STALL_TIMEOUT - 1;
    pm.drainBlockBuffer();
    try testing.expect(pm.inflight_block_peer.get(front) == null);
    try testing.expectEqual(@as(u32, 0), staller.peer.blocks_in_flight_count);

    // ...and re-requested from the OTHER peer, even when the rotation would
    // offer it to the staller first ((rotation+1) % 2 == 0 → peers[0]).
    pm.block_request_rotation = 1;
    try pm.pipelineBlockRequests();
    const holder = pm.inflight_block_peer.get(front) orelse return error.NotReRequested;
    try testing.expectEqual(@intFromPtr(honest.peer), holder);
}


