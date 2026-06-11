//! Advertised P2P service-flag tests for `Peer.localServices()`.
//!
//! Run via `zig build test-service-flags` (also folded into `zig build test`).
//!
//! These EXECUTE the real `Peer.localServices()` (not a re-implemented
//! mirror of it) and assert that a default full node advertises the
//! honest, correct bitmap:
//!
//!   * NODE_NETWORK (0x1) and NODE_WITNESS (0x8): always set.
//!   * NODE_NETWORK_LIMITED (0x400): set UNCONDITIONALLY for a full node,
//!     even with prune mode OFF — matching Bitcoin Core init.cpp:863,
//!     which seeds `g_local_services` with `NODE_NETWORK_LIMITED |
//!     NODE_WITNESS`.  (Regression guard: clearbit previously gated this
//!     bit on prune mode, so a normal run advertised 0x9 / 0x809 instead
//!     of the correct 0xC09.)
//!   * NODE_P2P_V2 (0x800): honest — advertised iff `bip324V2Enabled()`
//!     (default on; BIP-324 v2 transport is genuinely implemented in
//!     v2_transport.zig and wired into live peers).
//!   * NODE_BLOOM / NODE_COMPACT_FILTERS: config-gated off by default.
//!
//! A real socket is not needed: `localServices()` reads only struct fields
//! and the env-gated `bip324V2Enabled()`, so we construct a Peer with a
//! no-op stream (handle = -1) and never send/receive bytes.  This test root
//! imports peer.zig directly; the build step filters to "tests_service_flags"
//! so the pre-existing (drifted) peer.zig inline tests are not pulled in,
//! mirroring the tests_reorg_p2p / tests_bip35 isolation pattern.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");
const Peer = peer_mod.Peer;

/// Build a Peer with a no-op stream and the given service-config flags.
/// Only the fields `localServices()` reads (advertise_node_bloom,
/// advertise_compact_filters, advertise_node_network_limited) are
/// meaningful; the rest are inert defaults.  Caller must `recv_buffer.deinit()`.
fn makeServicePeer(
    allocator: std.mem.Allocator,
    recv_buffer: std.ArrayList(u8),
    advertise_bloom: bool,
    advertise_compact_filters: bool,
    prune: bool,
) Peer {
    return Peer{
        .stream = .{ .handle = -1 },
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8333),
        .state = .connecting,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.MAINNET,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
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
        .advertise_node_bloom = advertise_bloom,
        .advertise_compact_filters = advertise_compact_filters,
        .advertise_node_network_limited = prune,
    };
}

test "tests_service_flags: NODE_P2P_V2 constant equals 0x800 (1 << 11) per BIP-324" {
    try testing.expectEqual(@as(u64, 0x800), p2p.NODE_P2P_V2);
    try testing.expectEqual(@as(u64, 1 << 11), p2p.NODE_P2P_V2);
}

test "tests_service_flags: localServices() advertises NETWORK_LIMITED unconditionally for a full node" {
    const allocator = testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    // Default full node: prune OFF, bloom OFF, compact-filters OFF.
    var peer = makeServicePeer(allocator, recv_buffer, false, false, false);

    const s = peer.localServices();

    // Always-on full-node bits.
    try testing.expect((s & p2p.NODE_NETWORK) != 0);
    try testing.expect((s & p2p.NODE_WITNESS) != 0);
    // The fix: NODE_NETWORK_LIMITED is set even though prune mode is OFF.
    // (Old behaviour wrongly omitted it → 0x9 / 0x809.)
    try testing.expect((s & p2p.NODE_NETWORK_LIMITED) != 0);

    // Off-by-default config bits absent.
    try testing.expect((s & p2p.NODE_BLOOM) == 0);
    try testing.expect((s & p2p.NODE_COMPACT_FILTERS) == 0);

    // NODE_P2P_V2 is honest: present iff v2 transport enabled (default on).
    const expect_v2 = Peer.bip324V2Enabled();
    try testing.expectEqual(expect_v2, (s & p2p.NODE_P2P_V2) != 0);

    // Exact honest bitmap for the default full node.
    if (expect_v2) {
        // 0xC09 = NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2.
        try testing.expectEqual(@as(u64, 0xC09), s);
    } else {
        // v2 disabled via CLEARBIT_BIP324_V2=0 → honest set is 0x409.
        try testing.expectEqual(@as(u64, 0x409), s);
    }
}

test "tests_service_flags: prune mode does not change NETWORK_LIMITED advertisement" {
    const allocator = testing.allocator;
    var rb_full = std.ArrayList(u8).init(allocator);
    defer rb_full.deinit();
    var rb_prune = std.ArrayList(u8).init(allocator);
    defer rb_prune.deinit();

    var full = makeServicePeer(allocator, rb_full, false, false, false);
    var pruned = makeServicePeer(allocator, rb_prune, false, false, true);

    // NODE_NETWORK_LIMITED is unconditional (Core init.cpp:863), so a
    // pruned node and a non-pruned node advertise the SAME flags.
    try testing.expectEqual(full.localServices(), pruned.localServices());
    try testing.expect((pruned.localServices() & p2p.NODE_NETWORK_LIMITED) != 0);
}

test "tests_service_flags: optional bits OR in additively without dropping the full-node base" {
    const allocator = testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    // Operator opts into bloom + compact filters.
    var peer = makeServicePeer(allocator, recv_buffer, true, true, false);
    const s = peer.localServices();

    try testing.expect((s & p2p.NODE_BLOOM) != 0);
    try testing.expect((s & p2p.NODE_COMPACT_FILTERS) != 0);
    // The full-node base bits are still present.
    try testing.expect((s & p2p.NODE_NETWORK) != 0);
    try testing.expect((s & p2p.NODE_WITNESS) != 0);
    try testing.expect((s & p2p.NODE_NETWORK_LIMITED) != 0);
}
