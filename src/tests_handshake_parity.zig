//! Version-handshake Core parity (net_processing.cpp VERSION / pre-verack
//! handling) + witness-aware block download / getdata serving.
//!
//! Run via `zig build test-handshake` (also folded into `zig build test`).
//! The build step filters on "tests_handshake_parity" so peer.zig's own
//! (drifted) inline tests are not pulled in.
//!
//! These EXECUTE the real `Peer.performHandshake` over a socketpair: the far
//! end plays the remote node, pre-loading its side of the conversation, and
//! afterwards everything clearbit wrote is read back and decoded.
//!
//! Core behaviour pinned here:
//!   - the ONLY version floor is MIN_PEER_PROTO_VERSION = 31800, for inbound
//!     and outbound alike (was 70001 in clearbit);
//!   - feature messages are gated on the common version: wtxidrelay/sendaddrv2
//!     >= 70016, sendheaders >= 70012, feefilter >= 70013, sendcmpct >= 70014;
//!   - between VERSION and VERACK, sendheaders/sendcmpct/wtxidrelay/sendaddrv2
//!     are RECORDED; everything else (ping, inv, feefilter, unknown commands)
//!     is ignored — no pong, no disconnect;
//!   - blocks are requested only from NODE_WITNESS peers (CanServeWitnesses);
//!   - getdata MSG_BLOCK is answered WITHOUT witness data.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

const params = &consensus.REGTEST;

/// One side of a unix socketpair wired to a real `Peer`; `remote` is the
/// far end the test drives.
const Harness = struct {
    peer: Peer,
    remote: std.posix.fd_t,

    fn init(allocator: std.mem.Allocator, direction: peer_mod.PeerDirection) !Harness {
        var fds: [2]i32 = undefined;
        try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
        var p = Peer.accept(
            .{ .handle = fds[0] },
            std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 18444),
            params,
            allocator,
        );
        p.direction = direction;
        // Bound every read so a regression fails the test instead of hanging.
        p.setRecvTimeout(2, 0);
        return .{ .peer = p, .remote = fds[1] };
    }

    fn deinit(self: *Harness) void {
        self.peer.disconnect(); // closes fds[0], frees recv_buffer/subver
        std.posix.close(self.remote);
    }

    /// Write one v1-framed message to clearbit from the remote side.
    fn send(self: *Harness, msg: p2p.Message) !void {
        const bytes = try p2p.encodeMessage(&msg, params.magic, testing.allocator);
        defer testing.allocator.free(bytes);
        try writeAllFd(self.remote, bytes);
    }

    /// Write a raw frame with an arbitrary command (e.g. one clearbit does
    /// not know) and payload.
    fn sendRaw(self: *Harness, command: []const u8, payload: []const u8) !void {
        var hdr: [24]u8 = [_]u8{0} ** 24;
        std.mem.writeInt(u32, hdr[0..4], params.magic, .little);
        @memcpy(hdr[4 .. 4 + command.len], command);
        std.mem.writeInt(u32, hdr[16..20], @intCast(payload.len), .little);
        const h = crypto.hash256(payload);
        @memcpy(hdr[20..24], h[0..4]);
        try writeAllFd(self.remote, &hdr);
        if (payload.len > 0) try writeAllFd(self.remote, payload);
    }

    /// Drain everything clearbit has written so far; returns the command
    /// names in order (payloads kept in `raw` for byte-level checks).
    fn drain(self: *Harness, allocator: std.mem.Allocator, out: *std.ArrayList(Frame)) !void {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        var tmp: [65536]u8 = undefined;
        while (true) {
            const n = std.posix.recv(self.remote, &tmp, std.posix.MSG.DONTWAIT) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (n == 0) break;
            try buf.appendSlice(tmp[0..n]);
        }
        var pos: usize = 0;
        while (buf.items.len - pos >= 24) {
            const hdr = buf.items[pos .. pos + 24];
            const len = std.mem.readInt(u32, hdr[16..20], .little);
            if (buf.items.len - pos < 24 + len) break;
            var f: Frame = .{ .cmd = [_]u8{0} ** 12, .cmd_len = 0, .payload = undefined };
            @memcpy(&f.cmd, hdr[4..16]);
            f.cmd_len = std.mem.indexOfScalar(u8, &f.cmd, 0) orelse 12;
            f.payload = try allocator.dupe(u8, buf.items[pos + 24 .. pos + 24 + len]);
            try out.append(f);
            pos += 24 + len;
        }
    }
};

const Frame = struct {
    cmd: [12]u8,
    cmd_len: usize,
    payload: []u8,
    fn name(self: *const Frame) []const u8 {
        return self.cmd[0..self.cmd_len];
    }
};

fn freeFrames(allocator: std.mem.Allocator, frames: *std.ArrayList(Frame)) void {
    for (frames.items) |f| allocator.free(f.payload);
    frames.deinit();
}

fn hasCmd(frames: []const Frame, cmd: []const u8) bool {
    for (frames) |*f| if (std.mem.eql(u8, f.name(), cmd)) return true;
    return false;
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) off += try std.posix.write(fd, bytes[off..]);
}

fn versionMsg(version: i32, services: u64) p2p.Message {
    return .{ .version = .{
        .version = version,
        .services = services,
        .timestamp = std.time.timestamp(),
        .addr_recv = .{ .services = 0, .ip = [_]u8{0} ** 16, .port = 0 },
        .addr_from = .{ .services = services, .ip = [_]u8{0} ** 16, .port = 0 },
        .nonce = 0x1234_5678_9abc_def0,
        .user_agent = "/hs-parity-test/",
        .start_height = 0,
        .relay = true,
    } };
}

/// Feature messages a peer below 70016 (or below the per-message version)
/// cannot parse; none may reach a 70002 peer.
const FEATURE_CMDS = [_][]const u8{ "wtxidrelay", "sendaddrv2", "sendheaders", "sendcmpct", "feefilter" };

// ---------------------------------------------------------------------------
// Point 1: version floor + version-gated feature messages
// ---------------------------------------------------------------------------

test "tests_handshake_parity: inbound VERSION(70002) completes and is sent no unparseable feature message" {
    const a = testing.allocator;
    var h = try Harness.init(a, .inbound);
    defer h.deinit();
    try h.send(versionMsg(70002, p2p.NODE_NETWORK));
    try h.send(.{ .verack = {} });

    try h.peer.performHandshake(0);
    try testing.expectEqual(peer_mod.PeerState.handshake_complete, h.peer.state);
    try testing.expectEqual(@as(i32, 70002), h.peer.commonVersion());

    var frames = std.ArrayList(Frame).init(a);
    defer freeFrames(a, &frames);
    try h.drain(a, &frames);
    try testing.expect(hasCmd(frames.items, "version"));
    try testing.expect(hasCmd(frames.items, "verack"));
    for (FEATURE_CMDS) |c| {
        if (hasCmd(frames.items, c)) {
            std.debug.print("70002 peer was sent '{s}'\n", .{c});
            return error.TestUnexpectedResult;
        }
    }
}

test "tests_handshake_parity: outbound VERSION(70002) completes and is sent no unparseable feature message" {
    const a = testing.allocator;
    var h = try Harness.init(a, .outbound);
    defer h.deinit();
    try h.send(versionMsg(70002, p2p.NODE_NETWORK));
    try h.send(.{ .verack = {} });

    try h.peer.performHandshake(0);
    try testing.expectEqual(peer_mod.PeerState.handshake_complete, h.peer.state);

    var frames = std.ArrayList(Frame).init(a);
    defer freeFrames(a, &frames);
    try h.drain(a, &frames);
    for (FEATURE_CMDS) |c| try testing.expect(!hasCmd(frames.items, c));
}

test "tests_handshake_parity: version 40000 (in [31800, 70001)) is accepted, 31799 is rejected" {
    const a = testing.allocator;
    {
        var h = try Harness.init(a, .inbound);
        defer h.deinit();
        try h.send(versionMsg(40000, p2p.NODE_NETWORK));
        try h.send(.{ .verack = {} });
        try h.peer.performHandshake(0);
        try testing.expectEqual(peer_mod.PeerState.handshake_complete, h.peer.state);
    }
    // Negative control: the floor still exists, at Core's value.
    {
        var h = try Harness.init(a, .inbound);
        defer h.deinit();
        try h.send(versionMsg(p2p.MIN_PEER_PROTO_VERSION - 1, p2p.NODE_NETWORK));
        try h.send(.{ .verack = {} });
        try testing.expectError(peer_mod.PeerError.HandshakeFailed, h.peer.performHandshake(0));
    }
    // Same floor for outbound.
    {
        var h = try Harness.init(a, .outbound);
        defer h.deinit();
        try h.send(versionMsg(p2p.MIN_PEER_PROTO_VERSION - 1, p2p.NODE_NETWORK | p2p.NODE_WITNESS));
        try testing.expectError(peer_mod.PeerError.HandshakeFailed, h.peer.performHandshake(0));
    }
}

test "tests_handshake_parity: 70016 peer gets the full feature set; per-message version thresholds" {
    const a = testing.allocator;
    const Case = struct { v: i32, expect: [5]bool };
    // order: wtxidrelay, sendaddrv2, sendheaders, sendcmpct, feefilter
    const cases = [_]Case{
        .{ .v = 70016, .expect = .{ true, true, true, true, true } },
        .{ .v = 70015, .expect = .{ false, false, true, true, true } },
        .{ .v = 70014, .expect = .{ false, false, true, true, true } },
        .{ .v = 70013, .expect = .{ false, false, true, false, true } },
        .{ .v = 70012, .expect = .{ false, false, true, false, false } },
        .{ .v = 70011, .expect = .{ false, false, false, false, false } },
    };
    for (cases) |c| {
        var h = try Harness.init(a, .inbound);
        defer h.deinit();
        try h.send(versionMsg(c.v, p2p.NODE_NETWORK | p2p.NODE_WITNESS));
        try h.send(.{ .verack = {} });
        try h.peer.performHandshake(0);
        var frames = std.ArrayList(Frame).init(a);
        defer freeFrames(a, &frames);
        try h.drain(a, &frames);
        for (FEATURE_CMDS, 0..) |cmd, i| {
            if (hasCmd(frames.items, cmd) != c.expect[i]) {
                std.debug.print("version {d}: '{s}' sent={} want={}\n", .{ c.v, cmd, hasCmd(frames.items, cmd), c.expect[i] });
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "tests_handshake_parity: wtxidrelay from a pre-70016 peer is ignored (common-version gate)" {
    const a = testing.allocator;
    var h = try Harness.init(a, .inbound);
    defer h.deinit();
    try h.send(versionMsg(70015, p2p.NODE_NETWORK | p2p.NODE_WITNESS));
    try h.send(.{ .wtxidrelay = {} });
    try h.send(.{ .verack = {} });
    try h.peer.performHandshake(0);
    try testing.expect(!h.peer.wtxid_relay_negotiated);
}

// ---------------------------------------------------------------------------
// Point 2: messages between VERSION and VERACK
// ---------------------------------------------------------------------------

test "tests_handshake_parity: pre-verack sendheaders + sendcmpct are RECORDED (inbound and outbound)" {
    const a = testing.allocator;
    for ([_]peer_mod.PeerDirection{ .inbound, .outbound }) |dir| {
        var h = try Harness.init(a, dir);
        defer h.deinit();
        try h.send(versionMsg(70016, p2p.NODE_NETWORK | p2p.NODE_WITNESS));
        try h.send(.{ .wtxidrelay = {} });
        try h.send(.{ .sendaddrv2 = {} });
        try h.send(.{ .sendheaders = {} });
        try h.send(.{ .sendcmpct = .{ .announce = true, .version = 2 } });
        try h.send(.{ .verack = {} });

        try h.peer.performHandshake(0);
        try testing.expectEqual(peer_mod.PeerState.handshake_complete, h.peer.state);
        try testing.expect(h.peer.send_headers);
        try testing.expect(h.peer.bip152_provides_cmpctblocks);
        try testing.expect(h.peer.bip152_highbandwidth_from);
        try testing.expect(h.peer.wtxid_relay_negotiated);
        try testing.expect(h.peer.wants_addrv2);
    }
}

test "tests_handshake_parity: pre-verack sendcmpct version 1 is not recorded" {
    const a = testing.allocator;
    var h = try Harness.init(a, .inbound);
    defer h.deinit();
    try h.send(versionMsg(70016, p2p.NODE_NETWORK | p2p.NODE_WITNESS));
    try h.send(.{ .sendcmpct = .{ .announce = true, .version = 1 } });
    try h.send(.{ .verack = {} });
    try h.peer.performHandshake(0);
    try testing.expect(!h.peer.bip152_provides_cmpctblocks);
}

test "tests_handshake_parity: pre-verack ping/inv/feefilter/unknown are ignored — no pong, no disconnect (both directions)" {
    const a = testing.allocator;
    for ([_]peer_mod.PeerDirection{ .inbound, .outbound }) |dir| {
        var h = try Harness.init(a, dir);
        defer h.deinit();
        try h.send(versionMsg(70016, p2p.NODE_NETWORK | p2p.NODE_WITNESS));
        try h.send(.{ .ping = .{ .nonce = 7 } });
        var inv_items = [_]p2p.InvVector{.{ .inv_type = .msg_tx, .hash = [_]u8{0xAB} ** 32 }};
        try h.send(.{ .inv = .{ .inventory = &inv_items } });
        try h.send(.{ .feefilter = .{ .feerate = 12345 } });
        try h.sendRaw("notacommand", "xyz");
        try h.send(.{ .ping = .{ .nonce = 8 } });
        try h.send(.{ .verack = {} });

        try h.peer.performHandshake(0);
        try testing.expectEqual(peer_mod.PeerState.handshake_complete, h.peer.state);
        // Core ignores a pre-verack feefilter.
        try testing.expectEqual(@as(u64, 0), h.peer.fee_filter_received);

        var frames = std.ArrayList(Frame).init(a);
        defer freeFrames(a, &frames);
        try h.drain(a, &frames);
        if (hasCmd(frames.items, "pong")) {
            std.debug.print("direction {s}: pre-verack ping was ponged\n", .{@tagName(dir)});
            return error.TestUnexpectedResult;
        }
    }
}

test "tests_handshake_parity: messages before VERSION are ignored, not fatal" {
    const a = testing.allocator;
    var h = try Harness.init(a, .outbound);
    defer h.deinit();
    try h.send(.{ .ping = .{ .nonce = 1 } });
    try h.send(.{ .sendheaders = {} });
    try h.send(versionMsg(70016, p2p.NODE_NETWORK | p2p.NODE_WITNESS));
    try h.send(.{ .verack = {} });
    try h.peer.performHandshake(0);
    try testing.expectEqual(peer_mod.PeerState.handshake_complete, h.peer.state);
    // A sendheaders BEFORE version is ignored by Core (no version yet).
    try testing.expect(!h.peer.send_headers);
}

// ---------------------------------------------------------------------------
// BIP-31 ping for pre-60001 peers
// ---------------------------------------------------------------------------

test "tests_handshake_parity: pre-BIP31 peer gets a nonce-less ping and no ping timeout" {
    const a = testing.allocator;
    var h = try Harness.init(a, .inbound);
    defer h.deinit();
    try h.send(versionMsg(40000, p2p.NODE_NETWORK));
    try h.send(.{ .verack = {} });
    try h.peer.performHandshake(0);
    var discard = std.ArrayList(Frame).init(a);
    try h.drain(a, &discard);
    freeFrames(a, &discard);

    try h.peer.sendPing();
    var frames = std.ArrayList(Frame).init(a);
    defer freeFrames(a, &frames);
    try h.drain(a, &frames);
    try testing.expectEqual(@as(usize, 1), frames.items.len);
    try testing.expectEqualStrings("ping", frames.items[0].name());
    try testing.expectEqual(@as(usize, 0), frames.items[0].payload.len);
    try testing.expect(!h.peer.hasPingTimeout());
    try testing.expect(!h.peer.isTimedOut());

    // An empty-payload ping decodes (was a ProtocolViolation).
    const m = try p2p.decodePayload("ping", &[_]u8{}, a);
    try testing.expect(m == .ping);
}

// ---------------------------------------------------------------------------
// Witness-aware block download and getdata serving
// ---------------------------------------------------------------------------

fn witnessBlock(tx_in: *[1]types.TxIn, tx_out: *[1]types.TxOut, wit: *[1][]const u8, txs: *[1]types.Transaction) types.Block {
    wit[0] = "WITNESS-ITEM";
    tx_in[0] = .{
        .previous_output = .{ .hash = [_]u8{0x55} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xffffffff,
        .witness = wit[0..],
    };
    tx_out[0] = .{ .value = 1000, .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0x11} ** 20 };
    txs[0] = .{ .version = 2, .inputs = tx_in[0..], .outputs = tx_out[0..], .lock_time = 0 };
    return .{ .header = params.genesis_header, .transactions = txs[0..] };
}

test "tests_handshake_parity: getdata MSG_BLOCK is answered without witness, MSG_WITNESS_BLOCK with" {
    const a = testing.allocator;
    var pm = PeerManager.init(a, params);
    pm.anchors_path = "/dev/null";
    defer pm.deinit();

    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
    defer std.posix.close(fds[1]);
    const p = try a.create(Peer);
    p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 18444), params, a);
    p.state = .handshake_complete;
    p.services = p2p.NODE_NETWORK; // a non-witness peer
    try pm.peers.append(p); // pm.deinit owns p and fds[0]

    var tx_in: [1]types.TxIn = undefined;
    var tx_out: [1]types.TxOut = undefined;
    var wit: [1][]const u8 = undefined;
    var txs: [1]types.Transaction = undefined;
    const blk = witnessBlock(&tx_in, &tx_out, &wit, &txs);
    const bh = crypto.computeBlockHash(&blk.header);
    try pm.block_buffer.put(bh, blk);
    // Stack-owned block: take it back out before pm.deinit frees buffer values.
    defer _ = pm.block_buffer.remove(bh);

    var w_nowit = serialize.Writer.init(a);
    defer w_nowit.deinit();
    try serialize.writeBlockNoWitness(&w_nowit, &blk);
    var w_wit = serialize.Writer.init(a);
    defer w_wit.deinit();
    try serialize.writeBlock(&w_wit, &blk);
    try testing.expect(!std.mem.eql(u8, w_nowit.getWritten(), w_wit.getWritten()));

    const H = Harness{ .peer = undefined, .remote = fds[1] };
    for ([_]p2p.InvType{ .msg_block, .msg_witness_block }) |t| {
        var inv_items = [_]p2p.InvVector{.{ .inv_type = t, .hash = bh }};
        const gd = try p2p.encodeMessage(&p2p.Message{ .getdata = .{ .inventory = &inv_items } }, params.magic, a);
        defer a.free(gd);
        try writeAllFd(fds[1], gd);
        try pm.processAllMessages();

        var frames = std.ArrayList(Frame).init(a);
        defer freeFrames(a, &frames);
        var hh = H;
        try hh.drain(a, &frames);
        try testing.expectEqual(@as(usize, 1), frames.items.len);
        try testing.expectEqualStrings("block", frames.items[0].name());
        const want = if (t == .msg_block) w_nowit.getWritten() else w_wit.getWritten();
        try testing.expectEqualSlices(u8, want, frames.items[0].payload);
    }
}

test "tests_handshake_parity: tx_no_witness encodes the stripped serialization" {
    const a = testing.allocator;
    var tx_in: [1]types.TxIn = undefined;
    var tx_out: [1]types.TxOut = undefined;
    var wit: [1][]const u8 = undefined;
    var txs: [1]types.Transaction = undefined;
    _ = witnessBlock(&tx_in, &tx_out, &wit, &txs);
    const enc = try p2p.encodeMessage(&p2p.Message{ .tx_no_witness = txs[0] }, params.magic, a);
    defer a.free(enc);
    var w = serialize.Writer.init(a);
    defer w.deinit();
    try serialize.writeTransactionNoWitness(&w, &txs[0]);
    try testing.expectEqualStrings("tx", enc[4..6]);
    try testing.expectEqualSlices(u8, w.getWritten(), enc[24..]);
    // and it really dropped the witness (marker/flag absent)
    var w2 = serialize.Writer.init(a);
    defer w2.deinit();
    try serialize.writeTransaction(&w2, &txs[0]);
    try testing.expect(w2.getWritten().len > w.getWritten().len);
}

test "tests_handshake_parity: pipelineBlockRequests never asks a non-witness peer for blocks" {
    const a = testing.allocator;
    var cs = @import("storage.zig").ChainState.init(null, 64, a);
    defer cs.deinit();

    for ([_]u64{ p2p.NODE_NETWORK, p2p.NODE_NETWORK | p2p.NODE_WITNESS }) |svc| {
        var pm = PeerManager.init(a, params);
        pm.anchors_path = "/dev/null";
        defer pm.deinit();
        pm.chain_state = &cs;

        var fds: [2]i32 = undefined;
        try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
        defer std.posix.close(fds[1]);
        const p = try a.create(Peer);
        p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 18444), params, a);
        p.state = .handshake_complete;
        p.services = svc;
        try pm.peers.append(p);

        var i: u8 = 0;
        while (i < 4) : (i += 1) {
            var hsh: types.Hash256 = [_]u8{0} ** 32;
            hsh[0] = i + 1;
            try pm.expected_blocks.append(hsh);
        }
        try pm.pipelineBlockRequests();

        const witness = (svc & p2p.NODE_WITNESS) != 0;
        if (witness) {
            // Control: the same setup with NODE_WITNESS does request.
            try testing.expectEqual(@as(u32, 4), p.blocks_in_flight_count);
        } else {
            try testing.expectEqual(@as(u32, 0), p.blocks_in_flight_count);
            try testing.expectEqual(@as(u32, 0), pm.inflight_block_peer.count());
        }
        pm.chain_state = null;
    }
}
