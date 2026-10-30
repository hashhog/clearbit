//! Security audit 2026-10-29 (audits/security/clearbit-2026-10-29.md in the
//! meta-repo), findings C3 and H3.
//!
//! C3: a v1 peer that trickles a message (one byte at a time, each just
//! inside the receive timeout) held the single P2P thread inside
//! `receiveMessage` until the message completed, because every byte of
//! progress reset the partial-read deadline. Core keeps per-peer receive
//! state (net.cpp ReceiveMsgBytes / V1Transport) so a slow peer costs only
//! its own buffer.
//!
//! H3: the 60 s version-handshake deadline was checked only between
//! messages, so the same trickle held one of the 8 inbound handshake slots
//! for as long as the peer liked. Core's -peertimeout is absolute
//! (net.cpp InactivityCheck / ShouldRunInactivityChecks).
//!
//! These run the real `Peer.receiveMessage` / `Peer.performHandshake` over a
//! unix socketpair; a thread on the far end plays the attacker. Every test
//! compiles against the pre-fix tree, so on it they fail by name.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const crypto = @import("crypto.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerError = peer_mod.PeerError;

const params = &consensus.REGTEST;

fn socketPair() ![2]i32 {
    var fds: [2]i32 = undefined;
    if (std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0)
        return error.SkipZigTest;
    return fds;
}

fn makePeer(fd: i32, direction: peer_mod.PeerDirection) Peer {
    var p = Peer.accept(
        .{ .handle = fd },
        std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 18444),
        params,
        testing.allocator,
    );
    p.direction = direction;
    return p;
}

fn frame(allocator: std.mem.Allocator, command: []const u8, payload: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, 24 + payload.len);
    @memset(out[0..24], 0);
    std.mem.writeInt(u32, out[0..4], params.magic, .little);
    @memcpy(out[4 .. 4 + command.len], command);
    std.mem.writeInt(u32, out[16..20], @intCast(payload.len), .little);
    const h = crypto.hash256(payload);
    @memcpy(out[20..24], h[0..4]);
    @memcpy(out[24..], payload);
    return out;
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) off += try std.posix.write(fd, bytes[off..]);
}

/// Attacker: writes `bytes` `chunk` bytes at a time, sleeping `gap_ms`
/// between chunks, until done or `stop_after_ms` has passed; then closes
/// its end when `close_at_end` (the far end sees EOF).
const Trickler = struct {
    fd: std.posix.fd_t,
    bytes: []const u8,
    chunk: usize,
    gap_ms: u64,
    stop_after_ms: i64,
    close_at_end: bool,
    /// Bytes actually written, and whether the peer closed on us first.
    sent: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    peer_closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *Trickler) void {
        const start = std.time.milliTimestamp();
        var off: usize = 0;
        while (off < self.bytes.len) {
            if (std.time.milliTimestamp() - start >= self.stop_after_ms) break;
            const end = @min(self.bytes.len, off + self.chunk);
            const n = std.posix.write(self.fd, self.bytes[off..end]) catch {
                self.peer_closed.store(true, .release);
                break;
            };
            off += n;
            self.sent.store(off, .release);
            std.time.sleep(self.gap_ms * std.time.ns_per_ms);
        }
        if (self.close_at_end) std.posix.close(self.fd);
    }
};

fn versionFrame(allocator: std.mem.Allocator) ![]const u8 {
    const msg = p2p.Message{ .version = .{
        .version = p2p.PROTOCOL_VERSION,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .timestamp = std.time.timestamp(),
        .addr_recv = .{ .services = 0, .ip = [_]u8{0} ** 16, .port = 0 },
        .addr_from = .{ .services = 0, .ip = [_]u8{0} ** 16, .port = 0 },
        .nonce = 0x5eca_0d17_c3c3_4a4a,
        .user_agent = "/trickle-test/",
        .start_height = 0,
        .relay = true,
    } };
    return p2p.encodeMessage(&msg, params.magic, allocator);
}

// ---------------------------------------------------------------------------
// C3: a trickled message must not hold the receive (the single P2P thread)
// ---------------------------------------------------------------------------

test "sec_p2p_trickle: C3 a v1 message trickled a byte at a time does not hold receiveMessage" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    // The drain loop's own SO_RCVTIMEO (processAllMessages).
    p.setRecvTimeout(0, 1_000);

    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, 0xC3C3_0000_1111_2222, .little);
    const bytes = try frame(a, "ping", &nonce);
    defer a.free(bytes);

    // 32 bytes, one every 60 ms: ~1.9 s for the whole ping, each byte well
    // inside the old 30 s partial-read deadline, which it reset.
    var t = Trickler{ .fd = fds[1], .bytes = bytes, .chunk = 1, .gap_ms = 60, .stop_after_ms = 10_000, .close_at_end = true };
    const th = try std.Thread.spawn(.{}, Trickler.run, .{&t});
    defer th.join();
    while (t.sent.load(.acquire) == 0) std.time.sleep(std.time.ns_per_ms);

    // One drain-loop visit: must give the thread back at once, with the
    // byte(s) kept.
    const t0 = std.time.milliTimestamp();
    const first = p.receiveMessage();
    const held_ms = std.time.milliTimestamp() - t0;
    std.debug.print("C3 header trickle: first receiveMessage returned after {d} ms ({any})\n", .{ held_ms, first });
    if (first) |msg| {
        p2p.freeDecodedMessage(a, msg);
        return error.TrickleHeldReceive;
    } else |err| {
        try testing.expectEqual(PeerError.Timeout, err);
    }
    try testing.expect(held_ms < 500);

    // Later visits (as the drain loop's poll wakes) reassemble the message.
    const deadline = std.time.milliTimestamp() + 8_000;
    while (std.time.milliTimestamp() < deadline) {
        const r = p.receiveMessage();
        if (r) |msg| {
            switch (msg) {
                .ping => |pg| try testing.expectEqual(@as(u64, 0xC3C3_0000_1111_2222), pg.nonce),
                else => return error.WrongMessage,
            }
            return;
        } else |err| {
            try testing.expectEqual(PeerError.Timeout, err);
            std.time.sleep(5 * std.time.ns_per_ms);
        }
    }
    return error.NeverReassembled;
}

test "sec_p2p_trickle: C3 a payload trickled past its header does not hold receiveMessage" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    p.setRecvTimeout(0, 1_000);

    // Header and first payload byte at once, then the rest of a 4,000-byte
    // payload a byte every 50 ms (a 4 MB claim works the same, for years).
    const payload = try a.alloc(u8, 4000);
    defer a.free(payload);
    @memset(payload, 0x42);
    const bytes = try frame(a, "zzunknown", payload);
    defer a.free(bytes);
    try writeAllFd(fds[1], bytes[0..25]);
    var t = Trickler{ .fd = fds[1], .bytes = bytes[25..], .chunk = 1, .gap_ms = 50, .stop_after_ms = 3_000, .close_at_end = true };
    const th = try std.Thread.spawn(.{}, Trickler.run, .{&t});
    defer th.join();

    const t0 = std.time.milliTimestamp();
    const r = p.receiveMessage();
    const held_ms = std.time.milliTimestamp() - t0;
    if (r) |msg| p2p.freeDecodedMessage(a, msg) else |_| {}
    std.debug.print("C3 payload trickle: receiveMessage returned after {d} ms\n", .{held_ms});
    try testing.expectError(PeerError.Timeout, r);
    try testing.expect(held_ms < 500);
}

test "sec_p2p_trickle: C3 control: a large message arriving in bursts across many receive calls is reassembled byte-exact" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    p.setRecvTimeout(0, 1_000);

    // inv with 20,000 entries = 720,003 bytes: spans several 256 KiB
    // buffer-growth steps and many partial receives.
    const count: usize = 20_000;
    var payload = try a.alloc(u8, 3 + count * 36);
    defer a.free(payload);
    payload[0] = 0xfd;
    std.mem.writeInt(u16, payload[1..3], @intCast(count), .little);
    for (0..count) |i| {
        const e = payload[3 + i * 36 ..][0..36];
        std.mem.writeInt(u32, e[0..4], 1, .little); // MSG_TX
        @memset(e[4..36], 0);
        std.mem.writeInt(u32, e[4..8], @intCast(i), .little);
    }
    const bytes = try frame(a, "inv", payload);
    defer a.free(bytes);

    var t = Trickler{ .fd = fds[1], .bytes = bytes, .chunk = 50_000, .gap_ms = 20, .stop_after_ms = 30_000, .close_at_end = false };
    const th = try std.Thread.spawn(.{}, Trickler.run, .{&t});
    defer {
        th.join();
        std.posix.close(fds[1]);
    }

    var timeouts: usize = 0;
    const deadline = std.time.milliTimestamp() + 20_000;
    while (std.time.milliTimestamp() < deadline) {
        const r = p.receiveMessage();
        if (r) |msg| {
            defer p2p.freeDecodedMessage(a, msg);
            switch (msg) {
                .inv => |iv| {
                    try testing.expectEqual(count, iv.inventory.len);
                    for (iv.inventory, 0..) |item, i| {
                        try testing.expectEqual(@as(u32, @intCast(i)), std.mem.readInt(u32, item.hash[0..4], .little));
                    }
                },
                else => return error.WrongMessage,
            }
            std.debug.print("C3 control: 720,027-byte inv reassembled after {d} Timeout returns\n", .{timeouts});
            return;
        } else |err| {
            try testing.expectEqual(PeerError.Timeout, err);
            timeouts += 1;
            std.time.sleep(2 * std.time.ns_per_ms);
        }
    }
    return error.NeverReassembled;
}

test "sec_p2p_trickle: C3 control: two whole messages already buffered are returned in order by consecutive calls" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    defer std.posix.close(fds[1]);
    p.setRecvTimeout(0, 1_000);

    var n1: [8]u8 = undefined;
    var n2: [8]u8 = undefined;
    std.mem.writeInt(u64, &n1, 1, .little);
    std.mem.writeInt(u64, &n2, 2, .little);
    const f1 = try frame(a, "ping", &n1);
    defer a.free(f1);
    const f2 = try frame(a, "pong", &n2);
    defer a.free(f2);
    const empty = try frame(a, "verack", &[_]u8{});
    defer a.free(empty);
    try writeAllFd(fds[1], f1);
    try writeAllFd(fds[1], empty);
    try writeAllFd(fds[1], f2);

    const m1 = try p.receiveMessage();
    try testing.expectEqual(@as(u64, 1), m1.ping.nonce);
    const m0 = try p.receiveMessage();
    try testing.expect(m0 == .verack);
    const m2 = try p.receiveMessage();
    try testing.expectEqual(@as(u64, 2), m2.pong.nonce);
    try testing.expectError(PeerError.Timeout, p.receiveMessage());
}

test "sec_p2p_trickle: C3 control: a bad checksum still consumes exactly one frame" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    defer std.posix.close(fds[1]);
    p.setRecvTimeout(0, 1_000);

    var n1: [8]u8 = undefined;
    std.mem.writeInt(u64, &n1, 7, .little);
    const bad = try frame(a, "ping", &n1);
    defer a.free(bad);
    bad[20] ^= 0xff;
    var n2: [8]u8 = undefined;
    std.mem.writeInt(u64, &n2, 8, .little);
    const good = try frame(a, "ping", &n2);
    defer a.free(good);
    try writeAllFd(fds[1], bad);
    try writeAllFd(fds[1], good);

    try testing.expectError(PeerError.BadChecksum, p.receiveMessage());
    const m = try p.receiveMessage();
    try testing.expectEqual(@as(u64, 8), m.ping.nonce);
}

// ---------------------------------------------------------------------------
// H3: the handshake deadline must bound reads inside a message
// ---------------------------------------------------------------------------

test "sec_p2p_trickle: H3 an inbound peer trickling its VERSION is dropped at the 60 s handshake deadline" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    // acceptInbound's SO_RCVTIMEO.
    p.setRecvTimeout(10, 0);

    const bytes = try versionFrame(a);
    defer a.free(bytes);
    // The first 16 bytes at once (the v1/v2 classifier peeks them), then a
    // byte every 2 s: inside both the 10 s receive timeout and the old 30 s
    // partial-read deadline. The attacker gives up after deadline + 15 s.
    try writeAllFd(fds[1], bytes[0..16]);
    const limit_ms: i64 = Peer.HANDSHAKE_TIMEOUT_SECS * 1000;
    var t = Trickler{ .fd = fds[1], .bytes = bytes[16..], .chunk = 1, .gap_ms = 2_000, .stop_after_ms = limit_ms + 15_000, .close_at_end = true };
    const th = try std.Thread.spawn(.{}, Trickler.run, .{&t});
    defer th.join();

    const t0 = std.time.milliTimestamp();
    const r = p.performHandshake(0);
    const held_ms = std.time.milliTimestamp() - t0;
    // Close our end now so the attacker's next write fails and it exits.
    p.disconnect();
    std.debug.print("H3: trickled handshake ended after {d} ms ({any})\n", .{ held_ms, r });
    if (r) |_| return error.HandshakeCompleted else |err| {
        // ConnectionClosed would mean we only stopped because the attacker
        // did.
        try testing.expect(err != PeerError.ConnectionClosed);
    }
    try testing.expect(held_ms <= limit_ms + 2_000);
}

test "sec_p2p_trickle: H3 an inbound peer that stalls mid-VERSION is dropped after one receive timeout" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    defer std.posix.close(fds[1]);
    p.setRecvTimeout(2, 0);

    const bytes = try versionFrame(a);
    defer a.free(bytes);
    // Full header and part of the payload, then nothing: the old partial
    // path waited the 2 s receive timeout and then 30 s more.
    try writeAllFd(fds[1], bytes[0..40]);

    const t0 = std.time.milliTimestamp();
    const r = p.performHandshake(0);
    const held_ms = std.time.milliTimestamp() - t0;
    std.debug.print("H3 stall: handshake ended after {d} ms ({any})\n", .{ held_ms, r });
    try testing.expect(std.meta.isError(r));
    try testing.expect(held_ms < 6_000);
}

test "sec_p2p_trickle: H3 control: a VERSION arriving slowly within the deadline still completes the handshake" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = makePeer(fds[0], .inbound);
    defer p.disconnect();
    p.setRecvTimeout(10, 0);

    const ver = try versionFrame(a);
    defer a.free(ver);
    const verack = try frame(a, "verack", &[_]u8{});
    defer a.free(verack);
    var all = try a.alloc(u8, ver.len + verack.len);
    defer a.free(all);
    @memcpy(all[0..ver.len], ver);
    @memcpy(all[ver.len..], verack);
    // 16 bytes at once, then 10-byte chunks every 150 ms (~2 s in all).
    try writeAllFd(fds[1], all[0..16]);
    var t = Trickler{ .fd = fds[1], .bytes = all[16..], .chunk = 10, .gap_ms = 150, .stop_after_ms = 30_000, .close_at_end = false };
    const th = try std.Thread.spawn(.{}, Trickler.run, .{&t});
    defer {
        th.join();
        std.posix.close(fds[1]);
    }

    try p.performHandshake(0);
    try testing.expect(p.state == .handshake_complete);
    try testing.expectEqual(@as(i32, p2p.PROTOCOL_VERSION), p.peerVersion());
}
