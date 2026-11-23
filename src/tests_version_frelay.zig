//! fRelay (BIP-37 version field) and block-relay-only links gate tx relay.
//!
//! Core net_processing.cpp, VERSION handler: tx relay is set up only when the
//! link is not block-relay-only, and then `tx_relay->m_relay_txs = fRelay`.
//! RelayTransaction announces only to peers with tx relay set. A peer that
//! receives a tx inv on a block-relay-only link disconnects the sender.
//!
//! clearbit decoded fRelay but never stored it (`relay_txs` stayed `true`), and
//! `PeerManager.broadcast` sent tx invs to every handshake-complete peer.
//!
//! These run the real `Peer.performHandshake` over a socketpair, put the peers
//! in a real `PeerManager`, call `broadcast` with the same tx inv that
//! `RpcServer.broadcastTxInv` (sendrawtransaction) builds, and read back what
//! each peer was sent.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

const params = &consensus.REGTEST;

fn versionMsg(relay: bool) p2p.Message {
    const services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
    return .{ .version = .{
        .version = p2p.PROTOCOL_VERSION,
        .services = services,
        .timestamp = std.time.timestamp(),
        .addr_recv = .{ .services = 0, .ip = [_]u8{0} ** 16, .port = 0 },
        .addr_from = .{ .services = services, .ip = [_]u8{0} ** 16, .port = 0 },
        .nonce = 0x0bad_cafe_0000_0001,
        .user_agent = "/frelay-test/",
        .start_height = 0,
        .relay = relay,
    } };
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) off += try std.posix.write(fd, bytes[off..]);
}

fn sendFromRemote(remote: std.posix.fd_t, msg: p2p.Message) !void {
    const bytes = try p2p.encodeMessage(&msg, params.magic, testing.allocator);
    defer testing.allocator.free(bytes);
    try writeAllFd(remote, bytes);
}

/// A handshaked heap Peer (owned by `pm` once appended) + the far end.
const Link = struct {
    peer: *Peer,
    remote: std.posix.fd_t,
};

/// Handshake a peer that announces `relay` in its version. `relay_self` is our
/// own advertised fRelay (false on block-relay-only / feeler dials).
fn handshake(
    pm: *PeerManager,
    direction: peer_mod.PeerDirection,
    relay: bool,
    relay_self: bool,
) !Link {
    const a = testing.allocator;
    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
    const p = try a.create(Peer);
    p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 18444), params, a);
    p.direction = direction;
    p.relay_self = relay_self;
    p.setRecvTimeout(2, 0);
    try pm.peers.append(p); // pm.deinit owns p and fds[0]

    try sendFromRemote(fds[1], versionMsg(relay));
    try sendFromRemote(fds[1], .{ .verack = {} });
    try p.performHandshake(0);
    try testing.expectEqual(peer_mod.PeerState.handshake_complete, p.state);
    return .{ .peer = p, .remote = fds[1] };
}

const Seen = struct {
    tx_inv: bool = false,
    block_inv: bool = false,
    feefilter: bool = false,
};

/// Drain everything clearbit has written to `remote` and classify it.
fn drain(remote: std.posix.fd_t) !Seen {
    const a = testing.allocator;
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();
    var tmp: [65536]u8 = undefined;
    while (true) {
        const n = std.posix.recv(remote, &tmp, std.posix.MSG.DONTWAIT) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;
        try buf.appendSlice(tmp[0..n]);
    }
    var seen = Seen{};
    var pos: usize = 0;
    while (buf.items.len - pos >= 24) {
        const hdr = buf.items[pos .. pos + 24];
        const len = std.mem.readInt(u32, hdr[16..20], .little);
        if (buf.items.len - pos < 24 + len) break;
        const cmd_raw = hdr[4..16];
        const cmd = cmd_raw[0 .. std.mem.indexOfScalar(u8, cmd_raw, 0) orelse 12];
        const payload = buf.items[pos + 24 .. pos + 24 + len];
        if (std.mem.eql(u8, cmd, "feefilter")) seen.feefilter = true;
        if (std.mem.eql(u8, cmd, "inv") and payload.len >= 1) {
            // One-byte CompactSize count is enough for these single-item invs.
            const count = payload[0];
            var i: usize = 0;
            while (i < count and 1 + i * 36 + 36 <= payload.len) : (i += 1) {
                const t = std.mem.readInt(u32, payload[1 + i * 36 ..][0..4], .little) & ~@as(u32, 0x40000000);
                if (t == 1 or t == 5) seen.tx_inv = true;
                if (t == 2) seen.block_inv = true;
            }
        }
        pos += 24 + len;
    }
    return seen;
}

/// Exactly the message RpcServer.broadcastTxInv (rpc.zig) hands to broadcast.
fn txInv() p2p.Message {
    const S = struct {
        var items = [_]p2p.InvVector{.{ .inv_type = .msg_witness_tx, .hash = [_]u8{0x42} ** 32 }};
    };
    return .{ .inv = .{ .inventory = &S.items } };
}

fn blockInv() p2p.Message {
    const S = struct {
        var items = [_]p2p.InvVector{.{ .inv_type = .msg_block, .hash = [_]u8{0x24} ** 32 }};
    };
    return .{ .inv = .{ .inventory = &S.items } };
}

fn newPm() PeerManager {
    var pm = PeerManager.init(testing.allocator, params);
    pm.anchors_path = "/dev/null";
    return pm;
}

test "tests_version_frelay: version fRelay=false is stored as relay_txs=false (fRelay=true as true)" {
    var pm = newPm();
    defer pm.deinit();
    const off = try handshake(&pm, .inbound, false, true);
    defer std.posix.close(off.remote);
    const on = try handshake(&pm, .inbound, true, true);
    defer std.posix.close(on.remote);
    try testing.expect(!off.peer.relay_txs);
    try testing.expect(on.peer.relay_txs);
}

test "tests_version_frelay: broadcast of a tx inv skips a fRelay=false peer; block inv still reaches it" {
    var pm = newPm();
    defer pm.deinit();
    const off = try handshake(&pm, .inbound, false, true);
    defer std.posix.close(off.remote);
    const on = try handshake(&pm, .inbound, true, true);
    defer std.posix.close(on.remote);
    _ = try drain(off.remote);
    _ = try drain(on.remote);

    const tx = txInv();
    pm.broadcast(&tx);
    const s_off = try drain(off.remote);
    const s_on = try drain(on.remote);
    // The fix: no tx inv to the peer that asked for none.
    try testing.expect(!s_off.tx_inv);
    // Positive control: a tx-relaying peer still gets it.
    try testing.expect(s_on.tx_inv);

    // Non-tx broadcasts are unaffected.
    const blk = blockInv();
    pm.broadcast(&blk);
    try testing.expect((try drain(off.remote)).block_inv);
    try testing.expect((try drain(on.remote)).block_inv);
}

test "tests_version_frelay: block-relay-only outbound link gets no tx inv even if the peer said fRelay=true" {
    var pm = newPm();
    defer pm.deinit();
    // Dialed as block-relay-only: we advertise fRelay=false (relay_self=false)
    // and the dial worker marks the connection type after the handshake.
    const br = try handshake(&pm, .outbound, true, false);
    defer std.posix.close(br.remote);
    br.peer.conn_type = .block_relay;
    _ = try drain(br.remote);

    try testing.expect(!br.peer.relay_txs);
    const tx = txInv();
    pm.broadcast(&tx);
    try testing.expect(!(try drain(br.remote)).tx_inv);
}

test "tests_version_frelay: conn_type block_relay alone suppresses tx inv" {
    var pm = newPm();
    defer pm.deinit();
    const br = try handshake(&pm, .outbound, true, true);
    defer std.posix.close(br.remote);
    br.peer.conn_type = .block_relay;
    _ = try drain(br.remote);
    const tx = txInv();
    pm.broadcast(&tx);
    try testing.expect(!(try drain(br.remote)).tx_inv);
}

test "tests_version_frelay: fRelay=false inbound peer still gets our feefilter (Core gates on IsBlockOnlyConn only)" {
    var pm = newPm();
    defer pm.deinit();
    // Handshake output is what we inspect here, so do not pre-drain.
    const off = try handshake(&pm, .inbound, false, true);
    defer std.posix.close(off.remote);
    try testing.expect((try drain(off.remote)).feefilter);
}

test "tests_version_frelay: our block-relay-only dial sends no feefilter" {
    var pm = newPm();
    defer pm.deinit();
    const br = try handshake(&pm, .outbound, true, false);
    defer std.posix.close(br.remote);
    try testing.expect(!(try drain(br.remote)).feefilter);
}
