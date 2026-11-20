//! BIP-324 unknown short IDs must not recurse (skill record
//! `clearbit:v2-unknown-shortid-unbounded-recursion`).
//!
//! `Peer.receiveMessageV2` used to discard a packet whose short ID is
//! unknown (29..255) with `return self.receiveMessageV2();`. Each frame holds
//! a 16 KiB read buffer and nothing bounds the depth, so an unauthenticated
//! peer could overflow the stack of the inbound handshake worker before
//! VERSION with a stream of 21-byte packets. Core drops such a message and
//! moves on (net.cpp V2Transport::GetReceivedMessage / GetMessageType), with
//! no recursion and no score.
//!
//! These run the real `Peer.receiveMessage` over a unix socketpair with a
//! V2Transport pair already past the cipher handshake. The flood test runs
//! the receiver on a thread with a 1 MiB stack: the old recursion needs
//! ~160 MB for 10,000 packets and overflows it. Every test compiles against
//! the pre-fix tree (`NoMessage` is matched by name).

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const v2 = @import("v2_transport.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerError = peer_mod.PeerError;

const params = &consensus.REGTEST;
const MAGIC: u32 = 0xDAB5BFFA;
const SECRET = [_]u8{0x5A} ** 32;

fn socketPair() ![2]i32 {
    var fds: [2]i32 = undefined;
    if (std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0)
        return error.SkipZigTest;
    return fds;
}

/// A transport already in the application phase, keyed from SECRET.
fn appTransport(allocator: std.mem.Allocator, initiating: bool) v2.V2Transport {
    var magic_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &magic_bytes, MAGIC, .little);
    var t: v2.V2Transport = .{
        .cipher = v2.BIP324Cipher{},
        .initiating = initiating,
        .recv_state = .app,
        .send_state = .ready,
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .send_buffer = std.ArrayList(u8).init(allocator),
        .send_garbage = &[_]u8{},
        .network_magic = magic_bytes,
        .allocator = allocator,
        .recv_decode_buffer = std.ArrayList(u8).init(allocator),
        .recv_len = null,
        .recv_aad = &[_]u8{},
        .version_packet_sent = true,
    };
    t.cipher.initializeWithSharedSecret(&SECRET, initiating, magic_bytes);
    return t;
}

/// Inbound peer on `fd` whose v2 transport is the responder half.
fn v2Peer(allocator: std.mem.Allocator, fd: i32) !Peer {
    var p = Peer.accept(
        .{ .handle = fd },
        std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 18444),
        params,
        allocator,
    );
    p.direction = .inbound;
    const t = try allocator.create(v2.V2Transport);
    t.* = appTransport(allocator, false);
    p.v2_transport = t;
    p.transport_version = .v2;
    p.setRecvTimeout(2, 0);
    return p;
}

/// Append one raw packet with the given decrypted contents.
fn appendPacket(out: *std.ArrayList(u8), sender: *v2.V2Transport, contents: []const u8, ignore: bool) !void {
    const start = out.items.len;
    try out.resize(start + contents.len + v2.EXPANSION);
    sender.cipher.encrypt(contents, &[_]u8{}, ignore, out.items[start..]);
}

fn appendPing(out: *std.ArrayList(u8), sender: *v2.V2Transport, nonce: u64) !void {
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u64, &payload, nonce, .little);
    try sender.sendMessage("ping", &payload, false);
    try out.appendSlice(sender.getSendData());
    sender.markBytesSent(sender.getSendData().len);
}

const Writer = struct {
    fd: std.posix.fd_t,
    bytes: []const u8,
    failed: bool = false,
    fn run(self: *Writer) void {
        var off: usize = 0;
        while (off < self.bytes.len) {
            off += std.posix.write(self.fd, self.bytes[off..]) catch {
                self.failed = true;
                return;
            };
        }
    }
};

const Outcome = struct {
    ping_nonce: ?u64 = null,
    no_message: u32 = 0,
    calls: u32 = 0,
    other_err: ?anyerror = null,
};

/// Call receiveMessage until a ping arrives or a real error. "No message"
/// (the per-call discard cap) and Timeout (the writer is still writing)
/// mean call again.
fn receiveUntilPing(p: *Peer, out: *Outcome) void {
    while (out.calls < 100_000) {
        out.calls += 1;
        const msg = p.receiveMessage() catch |err| {
            if (std.mem.eql(u8, @errorName(err), "NoMessage")) {
                out.no_message += 1;
                continue;
            }
            if (err == PeerError.Timeout) continue;
            out.other_err = err;
            return;
        };
        switch (msg) {
            .ping => |pg| {
                out.ping_nonce = pg.nonce;
                return;
            },
            else => p2p.freeDecodedMessage(p.allocator, msg),
        }
    }
}

test "v2 unknown short id: 10,000 unknown-ID packets then a ping, on a 1 MiB stack, returns the ping" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = try v2Peer(a, fds[0]);
    defer p.disconnect();

    var sender = appTransport(a, true);
    defer sender.deinit();

    const N: usize = 10_000;
    var bytes = std.ArrayList(u8).init(a);
    defer bytes.deinit();
    for (0..N) |_| try appendPacket(&bytes, &sender, &[_]u8{0xFF}, false);
    const nonce: u64 = 0x5107_1D00_0000_FFFF;
    try appendPing(&bytes, &sender, nonce);

    var w = Writer{ .fd = fds[1], .bytes = bytes.items };
    const wt = try std.Thread.spawn(.{}, Writer.run, .{&w});

    var out = Outcome{};
    // Small stack: the recursion (>=16 KiB per packet) cannot fit; a loop does.
    const rt = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, receiveUntilPing, .{ &p, &out });
    rt.join();
    wt.join();
    std.posix.close(fds[1]);

    try testing.expect(!w.failed);
    try testing.expectEqual(@as(?anyerror, null), out.other_err);
    try testing.expectEqual(@as(?u64, nonce), out.ping_nonce);
    // The discard is bounded per call: the flood came back as "no message"
    // several times instead of being drained in one call.
    try testing.expect(out.no_message >= 1);
    try testing.expect(out.no_message <= N);
}

test "v2 unknown short id: a buffered flood returns NoMessage, not Timeout, and keeps the stream in sync" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = try v2Peer(a, fds[0]);
    defer p.disconnect();

    var sender = appTransport(a, true);
    defer sender.deinit();

    // Every unknown ID (29..255) several times, all written before the
    // first read so the whole flood is already buffered.
    var bytes = std.ArrayList(u8).init(a);
    defer bytes.deinit();
    var count: usize = 0;
    for (0..2) |_| {
        var id: u16 = 29;
        while (id <= 255) : (id += 1) {
            try appendPacket(&bytes, &sender, &[_]u8{@intCast(id)}, false);
            count += 1;
        }
    }
    const nonce: u64 = 0xA11_0F_1D5;
    try appendPing(&bytes, &sender, nonce);

    var w = Writer{ .fd = fds[1], .bytes = bytes.items };
    const wt = try std.Thread.spawn(.{}, Writer.run, .{&w});
    wt.join();
    defer std.posix.close(fds[1]);
    try testing.expect(!w.failed);

    // First call: the cap is hit with packets still buffered.
    const first = p.receiveMessage();
    try testing.expect(if (first) |_| false else |err| std.mem.eql(u8, @errorName(err), "NoMessage"));

    var out = Outcome{};
    receiveUntilPing(&p, &out);
    try testing.expectEqual(@as(?anyerror, null), out.other_err);
    try testing.expectEqual(@as(?u64, nonce), out.ping_nonce);
    try testing.expect(out.calls <= count);
}

test "v2 unknown short id control: decoys and a few unknown IDs before a ping still yield the ping in one call" {
    const a = testing.allocator;
    const fds = try socketPair();
    var p = try v2Peer(a, fds[0]);
    defer p.disconnect();

    var sender = appTransport(a, true);
    defer sender.deinit();

    var bytes = std.ArrayList(u8).init(a);
    defer bytes.deinit();
    // Decoys (ignore bit) carry arbitrary contents, including a known
    // short ID: they must be skipped, never delivered.
    try appendPacket(&bytes, &sender, &[_]u8{18}, true); // 18 = "ping" short ID
    try appendPacket(&bytes, &sender, "decoy contents", true);
    try appendPacket(&bytes, &sender, &[_]u8{0xFF}, false);
    try appendPacket(&bytes, &sender, &[_]u8{}, true);
    try appendPacket(&bytes, &sender, &[_]u8{29}, false);
    try appendPacket(&bytes, &sender, &[_]u8{0xFF}, true);
    const nonce: u64 = 0xDEC0_7000_0000_0001;
    try appendPing(&bytes, &sender, nonce);

    var w = Writer{ .fd = fds[1], .bytes = bytes.items };
    const wt = try std.Thread.spawn(.{}, Writer.run, .{&w});
    wt.join();
    defer std.posix.close(fds[1]);
    try testing.expect(!w.failed);

    const msg = try p.receiveMessage();
    switch (msg) {
        .ping => |pg| try testing.expectEqual(nonce, pg.nonce),
        else => {
            p2p.freeDecodedMessage(a, msg);
            return error.TestUnexpectedResult;
        },
    }
}
