//! P2P loop fairness: one busy peer must not hold up accept and dial adoption.
//!
//! clearbit ran inbound accept, inbound/outbound adoption and message
//! processing once per run() pass, and processAllMessages drained up to 256
//! messages from each peer before moving on. After a mainnet restart on
//! 2026-11-11 one slow pass left a finished outbound handshake un-adopted
//! for more than 5 minutes and inbound connections in the kernel backlog. Core's shape: ThreadMessageHandler handles one message
//! per peer per round (fMoreWork, net.cpp ThreadMessageHandler) and
//! AcceptConnection runs on every socket wake-up (net.cpp SocketHandler →
//! SocketHandlerListening), independent of message processing.
//!
//! Every test here uses only API that exists on the base commit, so the same
//! file runs on the base (fail by name) and on the fix (pass).

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

const params = &consensus.MAINNET;

/// Messages queued from the busy peer.
const BACKLOG: usize = 256;
/// The most one pass may take from a single peer for these tests to call it
/// "bounded" (the fix uses 16 messages or a 50 ms slice, whichever is first).
const PASS_BOUND: usize = 32;

fn initPm(a: std.mem.Allocator) PeerManager {
    var pm = PeerManager.init(a, params);
    pm.anchors_path = "/dev/null";
    pm.ban_list.file_path = null; // never write banlist.json from a test
    return pm;
}

const Pair = struct { peer: *Peer, remote: std.posix.fd_t };

fn socketPair() ![2]std.posix.fd_t {
    var fds: [2]i32 = undefined;
    if (std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0, &fds) != 0)
        return error.SocketPair;
    return fds;
}

/// A handshake-complete inbound peer on a socketpair, appended to `pm`.
fn addInboundPeer(pm: *PeerManager, a: std.mem.Allocator, ip: [4]u8) !Pair {
    const fds = try socketPair();
    const p = try a.create(Peer);
    p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4(ip, 8333), params, a);
    p.state = .handshake_complete;
    p.services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
    // A negotiated version above BIP-31, so every ping is answered by a pong.
    p.version_info = p2p.VersionMessage{
        .version = p2p.PROTOCOL_VERSION,
        .services = p.services,
        .timestamp = 0,
        .addr_recv = .{ .services = 0, .ip = [_]u8{0} ** 16, .port = 0 },
        .addr_from = .{ .services = 0, .ip = [_]u8{0} ** 16, .port = 0 },
        .nonce = 1,
        .user_agent = "",
        .start_height = 0,
        .relay = true,
    };
    try pm.peers.append(p);
    return .{ .peer = p, .remote = fds[1] };
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) off += try std.posix.write(fd, bytes[off..]);
}

/// Queue `n` pings from the remote end; each one the node handles answers a pong.
fn queuePings(remote: std.posix.fd_t, n: usize) !void {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const msg = p2p.Message{ .ping = .{ .nonce = 0x1000 + i } };
        const bytes = try p2p.encodeMessage(&msg, params.magic, testing.allocator);
        defer testing.allocator.free(bytes);
        try writeAllFd(remote, bytes);
    }
}

/// Read what the node has written so far; return the number of complete pong frames.
fn countPongs(fd: std.posix.fd_t, buf: *std.ArrayList(u8)) !usize {
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
    while (buf.items.len - pos >= 24) {
        const hdr = buf.items[pos .. pos + 24];
        const len = std.mem.readInt(u32, hdr[16..20], .little);
        if (buf.items.len - pos < 24 + len) break;
        const name_end = std.mem.indexOfScalar(u8, hdr[4..16], 0) orelse 12;
        if (std.mem.eql(u8, hdr[4 .. 4 + name_end], "pong")) hits += 1;
        pos += 24 + len;
    }
    return hits;
}

fn listenerHasPending(pm: *PeerManager) bool {
    var pfd = [_]std.posix.pollfd{.{ .fd = pm.listener.?.stream.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&pfd, 0) catch return false;
    return n > 0 and (pfd[0].revents & std.posix.POLL.IN) != 0;
}

fn addKnown(pm: *PeerManager, addr: std.net.Address) !void {
    try pm.known_addresses.put(PeerManager.addressKey(addr), .{
        .address = addr,
        .services = 1,
        .last_seen = std.time.timestamp(),
        .last_tried = 0,
        .attempts = 0,
        .success = false,
        .source = .peer_addr,
    });
}

test "processAllMessages returns after a bounded slice when one peer has 256 queued messages" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const busy = try addInboundPeer(&pm, a, .{ 10, 1, 1, 1 });
    defer std.posix.close(busy.remote);
    try queuePings(busy.remote, BACKLOG);

    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();

    try pm.processAllMessages();
    const after_one = try countPongs(busy.remote, &buf);
    // Instrument: the pass did read from the peer at all.
    try testing.expect(after_one >= 1);
    // The bound: one pass does not drain the whole backlog.
    try testing.expect(after_one <= PASS_BOUND);

    // Control: nothing is lost. Further passes finish the backlog, including
    // after the kernel buffer has been read dry by earlier passes.
    var passes: usize = 1;
    var got = after_one;
    while (got < BACKLOG and passes < 4 * BACKLOG) : (passes += 1) {
        try pm.processAllMessages();
        got = try countPongs(busy.remote, &buf);
    }
    try testing.expectEqual(BACKLOG, got);
    try testing.expectEqual(@as(usize, 1), pm.peers.items.len);
}

test "a pending inbound connection is accepted while another peer has a long message backlog" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    const laddr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    pm.listener = try laddr.listen(.{ .reuse_address = true, .force_nonblocking = true });

    const busy = try addInboundPeer(&pm, a, .{ 10, 1, 1, 1 });
    defer std.posix.close(busy.remote);
    try queuePings(busy.remote, BACKLOG);

    // A new inbound connection waiting in the listen backlog.
    const client = try std.net.tcpConnectToAddress(pm.listener.?.listen_address);
    defer client.close();
    try testing.expect(listenerHasPending(&pm)); // instrument: it is pending

    try pm.processAllMessages();

    // Accepted inside the message pass (on the poll wake-up, before the busy
    // peer's slice), not left for the next run() pass.
    try testing.expect(!listenerHasPending(&pm));
    pm.stop(); // ends the inbound handshake worker before deinit
}

test "a completed dial is adopted and the next one spawned without waiting a full loop pass" {
    const a = testing.allocator;
    var pm = initPm(a);
    defer pm.deinit();

    var far_ends = std.ArrayList(std.posix.fd_t).init(a);
    defer {
        for (far_ends.items) |fd| std.posix.close(fd);
        far_ends.deinit();
    }

    // The next address to dial: a loopback listener that never answers.
    const taddr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var tarpit = try taddr.listen(.{ .reuse_address = true, .force_nonblocking = true });
    defer tarpit.deinit();
    try addKnown(&pm, tarpit.listen_address);

    const busy = try addInboundPeer(&pm, a, .{ 10, 1, 1, 1 });
    defer std.posix.close(busy.remote);
    try queuePings(busy.remote, BACKLOG);

    // An outbound dial that finished its handshake while the loop was busy.
    const done_addr = std.net.Address.initIp4(.{ 10, 200, 0, 1 }, 8333);
    const fds = try socketPair();
    try far_ends.append(fds[1]);
    const dp = try a.create(Peer);
    dp.* = Peer.fromOutboundStream(.{ .handle = fds[0] }, done_addr, params, a);
    dp.state = .handshake_complete;
    dp.services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
    const R = std.meta.Elem(@TypeOf(pm.dial_done.items));
    try pm.dial_done.append(a, R{ .addr = done_addr, .peer = dp, .v1_fallback = false });
    pm.next_outbound_dial_ms = 0;

    try pm.processAllMessages();

    // Adopted during the pass.
    try testing.expectEqual(@as(usize, 0), pm.dial_done.items.len);
    var adopted = false;
    for (pm.peers.items) |p| {
        if (p == dp) adopted = true;
    }
    try testing.expect(adopted);

    // ...and the next dial started in the same pass: it reaches the tarpit.
    var dialled = false;
    var spins: usize = 0;
    while (!dialled and spins < 100) : (spins += 1) {
        if (tarpit.accept()) |c| {
            c.stream.close();
            dialled = true;
        } else |_| std.time.sleep(10 * std.time.ns_per_ms);
    }
    pm.stop();
    try testing.expect(dialled);
}
