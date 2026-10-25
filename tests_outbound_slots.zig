//! Outbound slot accounting: 8 full-relay + 2 block-relay-only, separate pools.
//!
//! Core net.cpp keeps MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8 and
//! MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2 as independent budgets.  clearbit's
//! dial target counted every outbound peer, so the 2 anchor (block-relay-only)
//! peers and any addnode peer ate full-relay slots and the node sat at 6-7
//! full-relay outbound.
//!
//! CONTROL: `zig build test-outbound-slots --summary new`

const std = @import("std");
const testing = std.testing;
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");

const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

fn outboundPeer(allocator: std.mem.Allocator, n: u8, kind: peer_mod.ConnectionType) !*Peer {
    const p = try allocator.create(Peer);
    p.* = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 10, 0, 0, n }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.MAINNET,
        .allocator = allocator,
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .is_witness_capable = true,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = kind,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };
    return p;
}

test "outbound_slots: anchors and manual peers do not use the 8 full-relay slots" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();
    defer {
        for (manager.peers.items) |p| {
            p.recv_buffer.deinit();
            allocator.destroy(p);
        }
        manager.peers.clearRetainingCapacity();
    }

    // 2 anchors (block-relay-only) + 1 addnode peer + 6 full-relay.
    const kinds = [_]peer_mod.ConnectionType{
        .block_relay,         .block_relay,         .manual,
        .outbound_full_relay, .outbound_full_relay, .outbound_full_relay,
        .outbound_full_relay, .outbound_full_relay, .outbound_full_relay,
    };
    for (kinds, 0..) |k, i| {
        try manager.peers.append(try outboundPeer(allocator, @intCast(i + 1), k));
    }
    try testing.expectEqual(@as(usize, 9), manager.outboundCount());
    try testing.expectEqual(@as(usize, 6), manager.countFullRelayOutbound());
    try testing.expectEqual(@as(usize, 8), manager.fullRelayOutboundTarget());
    try testing.expectEqual(@as(usize, 2), peer_mod.MAX_BLOCK_RELAY_ONLY_CONNECTIONS);
    // Two more full-relay dials wanted (old accounting: 9 >= 8 -> none).
    try testing.expectEqual(@as(usize, 2), manager.outboundDialHeadroom());
    // Both block-relay-only slots are held by the anchors: no further dial.
    try testing.expectEqual(@as(usize, 2), manager.countBlockRelayOutbound());
    try testing.expectEqual(@as(usize, 0), manager.blockRelayDialHeadroom());

    // Fill the 8 full-relay slots: headroom closes, extra stale-tip peer opens one.
    try manager.peers.append(try outboundPeer(allocator, 10, .outbound_full_relay));
    try manager.peers.append(try outboundPeer(allocator, 11, .outbound_full_relay));
    try testing.expectEqual(@as(usize, 0), manager.outboundDialHeadroom());
    manager.try_new_outbound = true;
    try testing.expectEqual(@as(usize, 1), manager.outboundDialHeadroom());
}

test "outbound_slots: rotation never opens a hole in the 8 full-relay slots" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();
    defer {
        for (manager.peers.items) |p| {
            p.recv_buffer.deinit();
            allocator.destroy(p);
        }
        manager.peers.clearRetainingCapacity();
    }
    const now = std.time.timestamp();

    // 8 full-relay + 2 anchors, anchors the oldest.
    var i: u8 = 0;
    while (i < 10) : (i += 1) {
        const kind: peer_mod.ConnectionType = if (i < 2) .block_relay else .outbound_full_relay;
        const p = try outboundPeer(allocator, i + 1, kind);
        p.last_message_time = now - 1000 + @as(i64, i);
        try manager.peers.append(p);
    }
    // Exactly 8 full-relay: rotation must not drop one (old code dropped the
    // oldest outbound, taking the node to 7 every 30 min).
    try testing.expectEqual(@as(?usize, null), manager.rotationVictimIndex(now));

    // A 9th full-relay peer (stale-tip extra): trim the oldest FULL-RELAY
    // one, never an anchor.
    const extra = try outboundPeer(allocator, 20, .outbound_full_relay);
    extra.last_message_time = now;
    try manager.peers.append(extra);
    const victim = manager.rotationVictimIndex(now).?;
    try testing.expectEqual(peer_mod.ConnectionType.outbound_full_relay, manager.peers.items[victim].conn_type);
    try testing.expectEqual(@as(usize, 2), victim);
}

test "outbound_slots: 8 full-relay + 2 block-relay-only are both wanted from an empty node" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();
    try testing.expectEqual(@as(usize, 8), manager.outboundDialHeadroom());
    try testing.expectEqual(@as(usize, 2), manager.blockRelayDialHeadroom());
}
