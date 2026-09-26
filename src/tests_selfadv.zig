//! Self-address advertisement tests (Core MaybeSendAddr / GetLocalAddrForPeer
//! / -externalip / -discover parity).
//!
//! Run via `zig build test-selfadv` (also folded into `zig build test`).
//! The build step filters on "tests_selfadv" so peer.zig's own (drifted)
//! inline tests are not pulled in; localaddr.zig's pure-table tests are
//! re-exported under this file's name by the wrapper test at the bottom.
//!
//! These EXECUTE the real PeerManager hooks. The send tests give the Peer a
//! pipe as its stream, so `maybeSendLocalAddr` goes through the real
//! `Peer.sendMessage` -> `p2p.encodeMessage` path, and the bytes are read
//! back and decoded with `p2p.decodePayload`.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const localaddr = @import("localaddr.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

fn v4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    var out = [_]u8{0} ** 16;
    out[10] = 0xff;
    out[11] = 0xff;
    out[12] = a;
    out[13] = b;
    out[14] = c;
    out[15] = d;
    return out;
}

fn makePeer(
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    address: std.net.Address,
    direction: peer_mod.PeerDirection,
    conn_type: peer_mod.ConnectionType,
) Peer {
    return Peer{
        .stream = .{ .handle = fd },
        .address = address,
        .state = .handshake_complete,
        .direction = direction,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.REGTEST,
        .allocator = allocator,
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = conn_type,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };
}

/// Give the peer a VERSION whose addr_recv (the peer's view of us) is `recv`.
fn setAddrRecv(p: *Peer, recv: [16]u8, port: u16) void {
    p.version_info = p2p.VersionMessage{
        .version = p2p.PROTOCOL_VERSION,
        .services = p2p.NODE_NETWORK,
        .timestamp = 0,
        .addr_recv = .{ .services = 0, .ip = recv, .port = port },
        .addr_from = .{ .services = 0, .ip = [_]u8{0} ** 16, .port = 0 },
        .nonce = 1,
        .user_agent = "",
        .start_height = 0,
        .relay = true,
    };
}

fn newManager(allocator: std.mem.Allocator) PeerManager {
    var m = PeerManager.init(allocator, &consensus.REGTEST);
    m.anchors_path = "/dev/null"; // deinit() saves anchors; write nowhere
    return m;
}

var stub_ibd: bool = false;
fn stubIbd(_: *anyopaque) bool {
    return stub_ibd;
}

/// Read one v1-framed message from `fd` (non-blocking: null if the pipe is
/// empty) and decode it. decodePayload is ZERO-COPY for some fields (addrv2
/// addr_bytes point into the payload), so the payload is returned too and the
/// caller frees it (and the decoded slices) only after its checks.
const Read = struct { msg: p2p.Message, payload: []u8 };
fn readOneMessage(allocator: std.mem.Allocator, fd: std.posix.fd_t) !?Read {
    var hdr: [24]u8 = undefined;
    const n = std.posix.read(fd, &hdr) catch |err| switch (err) {
        error.WouldBlock => return null,
        else => return err,
    };
    if (n == 0) return null;
    try testing.expectEqual(@as(usize, 24), n);
    const cmd_end = std.mem.indexOfScalar(u8, hdr[4..16], 0) orelse 12;
    const command = hdr[4 .. 4 + cmd_end];
    const len = std.mem.readInt(u32, hdr[16..20], .little);
    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    try testing.expectEqual(@as(usize, len), try std.posix.read(fd, payload));
    return .{ .msg = try p2p.decodePayload(command, payload, allocator), .payload = payload };
}

/// Free a Read: the decoded top-level slice, then the payload.
fn freeRead(allocator: std.mem.Allocator, r: Read) void {
    switch (r.msg) {
        .addr => |a| allocator.free(a.addrs),
        .addrv2 => |a2| allocator.free(a2.entries),
        else => {},
    }
    allocator.free(r.payload);
}

fn makePipe() ![2]std.posix.fd_t {
    return std.posix.pipe2(.{ .NONBLOCK = true });
}

// ----------------------------------------------------------------------------
// Routable filter + discovery from addr_recv
// ----------------------------------------------------------------------------

test "tests_selfadv: discovery records an outbound peer's addr_recv with OUR listen port" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 8456;
    m.discover = true;

    var p = makePeer(allocator, -1, std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer p.recv_buffer.deinit();
    setAddrRecv(&p, v4(1, 2, 3, 4), 51234); // ephemeral port as the peer saw it
    m.noteVersionAddrRecv(&p, 1000);

    var out: [localaddr.LocalAddrTable.MAX_LIST]localaddr.LocalAddress = undefined;
    const n = m.local_addrs.list(&out, 1000);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualSlices(u8, &v4(1, 2, 3, 4), &out[0].ip);
    try testing.expectEqual(@as(u16, 8456), out[0].port); // listen port, not 51234
    try testing.expectEqual(@as(u32, 1), out[0].score);
    // One netgroup is not enough to advertise it to others.
    try testing.expect(m.local_addrs.best(null, 1000) == null);

    // A second outbound peer in a DIFFERENT /16 makes it usable.
    var p2 = makePeer(allocator, -1, std.net.Address.initIp4(.{ 9, 9, 9, 9 }, 8333), .outbound, .outbound_full_relay);
    defer p2.recv_buffer.deinit();
    setAddrRecv(&p2, v4(1, 2, 3, 4), 40000);
    m.noteVersionAddrRecv(&p2, 1001);
    const b = m.local_addrs.best(null, 1001).?;
    try testing.expectEqual(@as(u32, 2), b.score);
    try testing.expectEqual(@as(u16, 8456), b.port);
}

test "tests_selfadv: routable filter rejects private addr_recv, private peer, discover off, inbound-create" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 8456;
    m.discover = true;
    var out: [localaddr.LocalAddrTable.MAX_LIST]localaddr.LocalAddress = undefined;

    // addr_recv is RFC1918 -> ignored.
    var a = makePeer(allocator, -1, std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer a.recv_buffer.deinit();
    setAddrRecv(&a, v4(192, 168, 1, 128), 8456);
    m.noteVersionAddrRecv(&a, 1);
    try testing.expectEqual(@as(usize, 0), m.local_addrs.list(&out, 1));

    // addr_recv is loopback -> ignored.
    setAddrRecv(&a, v4(127, 0, 0, 1), 8456);
    m.noteVersionAddrRecv(&a, 1);
    try testing.expectEqual(@as(usize, 0), m.local_addrs.list(&out, 1));

    // Peer itself is private (10/8) -> ignored even with a public addr_recv.
    var b = makePeer(allocator, -1, std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8333), .outbound, .outbound_full_relay);
    defer b.recv_buffer.deinit();
    setAddrRecv(&b, v4(1, 2, 3, 4), 8456);
    m.noteVersionAddrRecv(&b, 1);
    try testing.expectEqual(@as(usize, 0), m.local_addrs.list(&out, 1));

    // Inbound peer never CREATES an entry (Core SeenLocal).
    var c = makePeer(allocator, -1, std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 50000), .inbound, .inbound);
    defer c.recv_buffer.deinit();
    setAddrRecv(&c, v4(1, 2, 3, 4), 8456);
    m.noteVersionAddrRecv(&c, 1);
    try testing.expectEqual(@as(usize, 0), m.local_addrs.list(&out, 1));

    // discover off -> an otherwise-good outbound report is ignored.
    m.discover = false;
    var d = makePeer(allocator, -1, std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer d.recv_buffer.deinit();
    setAddrRecv(&d, v4(1, 2, 3, 4), 8456);
    m.noteVersionAddrRecv(&d, 1);
    try testing.expectEqual(@as(usize, 0), m.local_addrs.list(&out, 1));

    // Control: discover on + both routable -> recorded (the filter is not
    // simply rejecting everything).
    m.discover = true;
    m.noteVersionAddrRecv(&d, 1);
    try testing.expectEqual(@as(usize, 1), m.local_addrs.list(&out, 1));
}

test "tests_selfadv: addExternalIp refuses non-routable, bare IP takes the listen port" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 18444;
    try testing.expect(!m.addExternalIp(v4(192, 168, 0, 1), 0));
    try testing.expect(!m.addExternalIp(v4(127, 0, 0, 1), 0));
    try testing.expect(m.addExternalIp(v4(1, 2, 3, 4), 0));
    try testing.expect(m.addExternalIp(v4(5, 6, 7, 8), 9999));
    var out: [localaddr.LocalAddrTable.MAX_LIST]localaddr.LocalAddress = undefined;
    const n = m.local_addrs.list(&out, 0);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |e| {
        try testing.expectEqual(localaddr.LOCAL_MANUAL, e.score);
        if (e.ip[12] == 1) try testing.expectEqual(@as(u16, 18444), e.port);
        if (e.ip[12] == 5) try testing.expectEqual(@as(u16, 9999), e.port);
    }
}

// ----------------------------------------------------------------------------
// addr / addrv2 message contents
// ----------------------------------------------------------------------------

test "tests_selfadv: self-announcement addr carries our address, services, now, LISTEN port" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 18444;
    m.discover = false;
    stub_ibd = false;
    m.setIbdSource(@ptrCast(&m), stubIbd);
    try testing.expect(m.addExternalIp(v4(1, 2, 3, 4), 0));

    const fds = try makePipe();
    defer std.posix.close(fds[0]);
    defer std.posix.close(fds[1]);
    var p = makePeer(allocator, fds[1], std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 39601), .outbound, .manual);
    defer p.recv_buffer.deinit();

    const now: i64 = 1_700_000_000;
    try testing.expect(m.maybeSendLocalAddr(&p, now));
    try testing.expect(p.next_local_addr_send > now);

    const r = (try readOneMessage(allocator, fds[0])).?;
    defer freeRead(allocator, r);
    switch (r.msg) {
        .addr => |a| {
            try testing.expectEqual(@as(usize, 1), a.addrs.len);
            try testing.expectEqualSlices(u8, &v4(1, 2, 3, 4), &a.addrs[0].addr.ip);
            try testing.expectEqual(@as(u16, 18444), a.addrs[0].addr.port);
            try testing.expectEqual(p.localServices(), a.addrs[0].addr.services);
            try testing.expectEqual(@as(u32, @intCast(now)), a.addrs[0].timestamp);
        },
        else => return error.WrongMessage,
    }
    // Exactly one message.
    try testing.expect((try readOneMessage(allocator, fds[0])) == null);

    // Not due again right away (Poisson timer armed).
    try testing.expect(!m.maybeSendLocalAddr(&p, now + 1));
    try testing.expect((try readOneMessage(allocator, fds[0])) == null);
    // Due once the timer has passed.
    try testing.expect(m.maybeSendLocalAddr(&p, p.next_local_addr_send + 1));
    const again = (try readOneMessage(allocator, fds[0])).?;
    defer freeRead(allocator, again);
    if (again.msg != .addr) return error.WrongMessage;
}

test "tests_selfadv: addrv2 when the peer sent sendaddrv2" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 8456;
    m.discover = false;
    stub_ibd = false;
    m.setIbdSource(@ptrCast(&m), stubIbd);
    try testing.expect(m.addExternalIp(v4(1, 2, 3, 4), 0));

    const fds = try makePipe();
    defer std.posix.close(fds[0]);
    defer std.posix.close(fds[1]);
    var p = makePeer(allocator, fds[1], std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer p.recv_buffer.deinit();
    p.wants_addrv2 = true;

    try testing.expect(m.maybeSendLocalAddr(&p, 1_700_000_000));
    const r = (try readOneMessage(allocator, fds[0])).?;
    defer freeRead(allocator, r);
    switch (r.msg) {
        .addrv2 => |a2| {
            try testing.expectEqual(@as(usize, 1), a2.entries.len);
            try testing.expectEqual(@as(u8, 1), a2.entries[0].network_id); // IPv4
            try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, a2.entries[0].addr_bytes);
            try testing.expectEqual(@as(u16, 8456), a2.entries[0].port);
            try testing.expectEqual(p.localServices(), a2.entries[0].services);
            try testing.expectEqual(@as(u32, 1_700_000_000), a2.entries[0].timestamp);
        },
        else => return error.WrongMessage,
    }
}

// ----------------------------------------------------------------------------
// Gates: IBD, connection type, listening, no usable address
// ----------------------------------------------------------------------------

test "tests_selfadv: IBD suppresses the send and leaves the first-send slot untouched" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 8456;
    m.discover = false;
    m.setIbdSource(@ptrCast(&m), stubIbd);
    try testing.expect(m.addExternalIp(v4(1, 2, 3, 4), 0));

    const fds = try makePipe();
    defer std.posix.close(fds[0]);
    defer std.posix.close(fds[1]);
    var p = makePeer(allocator, fds[1], std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer p.recv_buffer.deinit();

    stub_ibd = true;
    try testing.expect(!m.maybeSendLocalAddr(&p, 100));
    try testing.expectEqual(@as(i64, 0), p.next_local_addr_send);
    try testing.expect((try readOneMessage(allocator, fds[0])) == null);

    // IBD over: the very next tick sends.
    stub_ibd = false;
    try testing.expect(m.maybeSendLocalAddr(&p, 101));
    const r = (try readOneMessage(allocator, fds[0])).?;
    defer freeRead(allocator, r);
    if (r.msg != .addr) return error.WrongMessage;
}

test "tests_selfadv: never to block-relay-only or feeler; not when not listening; not without a usable address" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 8456;
    m.discover = false;
    stub_ibd = false;
    m.setIbdSource(@ptrCast(&m), stubIbd);

    const fds = try makePipe();
    defer std.posix.close(fds[0]);
    defer std.posix.close(fds[1]);

    // No local address known yet -> nothing (but the timer still advances,
    // like Core, which re-arms m_next_local_addr_send regardless).
    var full = makePeer(allocator, fds[1], std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer full.recv_buffer.deinit();
    try testing.expect(!m.maybeSendLocalAddr(&full, 10));
    try testing.expect((try readOneMessage(allocator, fds[0])) == null);

    try testing.expect(m.addExternalIp(v4(1, 2, 3, 4), 0));

    var br = makePeer(allocator, fds[1], std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .block_relay);
    defer br.recv_buffer.deinit();
    try testing.expect(!m.maybeSendLocalAddr(&br, 10));
    var fe = makePeer(allocator, fds[1], std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .feeler);
    defer fe.recv_buffer.deinit();
    try testing.expect(!m.maybeSendLocalAddr(&fe, 10));
    try testing.expect((try readOneMessage(allocator, fds[0])) == null);

    // Not listening -> nothing.
    m.listen_port = 0;
    var full2 = makePeer(allocator, fds[1], std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer full2.recv_buffer.deinit();
    try testing.expect(!m.maybeSendLocalAddr(&full2, 10));
    try testing.expect((try readOneMessage(allocator, fds[0])) == null);

    // Control: listening again -> the same peer gets it.
    m.listen_port = 8456;
    try testing.expect(m.maybeSendLocalAddr(&full2, 10));
    const r = (try readOneMessage(allocator, fds[0])).?;
    defer freeRead(allocator, r);
    if (r.msg != .addr) return error.WrongMessage;
}

test "tests_selfadv: inbound peer's view is used with ITS port when nothing routable is known" {
    const allocator = testing.allocator;
    var m = newManager(allocator);
    defer m.deinit();
    m.listen_port = 8456;
    m.discover = true;
    stub_ibd = false;
    m.setIbdSource(@ptrCast(&m), stubIbd);

    var in_peer = makePeer(allocator, -1, std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 50000), .inbound, .inbound);
    defer in_peer.recv_buffer.deinit();
    setAddrRecv(&in_peer, v4(1, 2, 3, 4), 8456);
    const got = m.localAddrForPeer(&in_peer, 0).?;
    try testing.expectEqualSlices(u8, &v4(1, 2, 3, 4), &got.ip);
    try testing.expectEqual(@as(u16, 8456), got.port);

    // Outbound: IP from the peer, port stays our listen port.
    var out_peer = makePeer(allocator, -1, std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 8333), .outbound, .outbound_full_relay);
    defer out_peer.recv_buffer.deinit();
    setAddrRecv(&out_peer, v4(1, 2, 3, 4), 51234);
    const got2 = m.localAddrForPeer(&out_peer, 0).?;
    try testing.expectEqual(@as(u16, 8456), got2.port);
}

// localaddr.zig's own pure-table tests are named "tests_selfadv localaddr: ..."
// so the step filter keeps them; they are discovered because this file
// imports localaddr.zig.
