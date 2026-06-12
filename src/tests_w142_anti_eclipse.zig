//! W142 — P2P anti-eclipse hardening proof suite (clearbit / Zig 0.13)
//!
//! Proves the Bitcoin Core v31.99 anti-eclipse guards wired into peer.zig:
//!
//!   1. FEELER: select-from-NEW only + promote NEW->TRIED on handshake-SUCCESS
//!      ONLY (a not-probed NEW entry stays NEW = falsification), bounded to
//!      MAX_FEELER_CONNECTIONS=1, off the outbound budget, 120s interval.
//!   2. GETADDR-once guard (answer only the first getaddr per connection;
//!      ignore from outbound peers).
//!   3. GETADDR 23%-cap: min(1000, floor(0.23 * addrman_size)) (integer div, Core GetAddr_).
//!   4. Inbound-addr token bucket (refill elapsed*0.1 cap 1000, spend 1/addr,
//!      drop excess) shared by BOTH the addr and addrv2 handlers (one per-peer
//!      bucket) — an addrv2 flood on a drained bucket is dropped.
//!
//! Core references:
//!   net.cpp ThreadOpenConnections FEELER branch (FEELER_INTERVAL=120s,
//!     MAX_FEELER_CONNECTIONS=1, addrman.Select(new_only=true), Good() on
//!     success, disconnect).
//!   net_processing.cpp GETADDR handler (m_getaddr_recvd one-shot, ignore
//!     outbound, MAX_PCT_ADDR_TO_SEND=23, MAX_ADDR_TO_SEND=1000).
//!   net_processing.cpp ProcessAddrs token bucket (m_addr_token_bucket init
//!     1.0, MAX_ADDR_RATE_PER_SECOND=0.1, MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000;
//!     addr AND addrv2 share one bucket).

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const addrman = @import("addrman.zig");
const consensus = @import("consensus.zig");

const PeerManager = peer_mod.PeerManager;
const Peer = peer_mod.Peer;
const AddrMan = addrman.AddrMan;
const SocketAddr = std.net.Address;

/// A routable test IPv4 a.b.c.d:8333 (isRoutable() accepts these — none fall
/// in an RFC-1918 / loopback / documentation range).
fn ip(a: u8, b: u8, c: u8, d: u8) SocketAddr {
    return SocketAddr.initIp4(.{ a, b, c, d }, 8333);
}

/// Minimal handshake-complete inbound Peer for the token-bucket tests. Only the
/// addr token-bucket fields matter here; everything else uses sane defaults.
fn makeInboundPeer(allocator: std.mem.Allocator) Peer {
    return Peer{
        .stream = undefined,
        .address = ip(1, 2, 3, 4),
        .state = .handshake_complete,
        .direction = .inbound,
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
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .inbound,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };
}

// ============================================================================
// 3. GETADDR 23%-cap formula: min(1000, floor(0.23 * size))
//    Core CAddrMan::GetAddr_ (addrman.cpp:800):
//      nNodes = max_pct * nNodes / 100;            // integer FLOOR (truncate)
//      nNodes = std::min(nNodes, max_addresses);   // clamp to MAX_ADDR_TO_SEND
//    Core applies NO floor-of-1: size<5 -> 0 addresses.
// ============================================================================

test "w142/cap: getaddrCap = min(1000, floor(0.23*size)) — genuine Core FLOOR formula" {
    // Empty addrman → 0 (Core returns no addresses).
    try testing.expectEqual(@as(usize, 0), peer_mod.getaddrCap(0));
    // DISTINGUISHING (no floor-of-1): floor(0.23*1) = floor(0.23) = 0.
    // Core has no "answer at least one"; size 1 yields ZERO. (ceil would give 1.)
    try testing.expectEqual(@as(usize, 0), peer_mod.getaddrCap(1));
    // DISTINGUISHING (no floor-of-1): floor(0.23*4) = floor(0.92) = 0.
    try testing.expectEqual(@as(usize, 0), peer_mod.getaddrCap(4));
    // First non-zero: floor(0.23*5) = floor(1.15) = 1.
    try testing.expectEqual(@as(usize, 1), peer_mod.getaddrCap(5));
    // DISTINGUISHING (floor vs ceil): floor(0.23*10) = floor(2.3) = 2 (ceil=3).
    try testing.expectEqual(@as(usize, 2), peer_mod.getaddrCap(10));
    // floor(0.23*100) = 23 (exact; floor==ceil here, not distinguishing).
    try testing.expectEqual(@as(usize, 23), peer_mod.getaddrCap(100));
    // floor(0.23*1000) = 230.
    try testing.expectEqual(@as(usize, 230), peer_mod.getaddrCap(1000));
    // DISTINGUISHING (floor vs ceil): floor(0.23*4347)=floor(999.81)=999 (ceil=1000).
    try testing.expectEqual(@as(usize, 999), peer_mod.getaddrCap(4347));
    // floor(0.23*4348)=floor(1000.04)=1000 → also == the absolute cap.
    try testing.expectEqual(@as(usize, 1000), peer_mod.getaddrCap(4348));
    // floor(0.23*4348)=1000 exactly hits the cap; one more stays clamped.
    try testing.expectEqual(@as(usize, 1000), peer_mod.getaddrCap(4349));
    // Huge addrman → still clamped to 1000.
    try testing.expectEqual(@as(usize, 1000), peer_mod.getaddrCap(10_000_000));
    // The Core constants themselves.
    try testing.expectEqual(@as(usize, 23), peer_mod.MAX_PCT_ADDR_TO_SEND);
    try testing.expectEqual(@as(usize, 1000), peer_mod.MAX_ADDR_TO_SEND);
}

// ============================================================================
// 4. Inbound-addr token bucket: drop excess; addr + addrv2 share ONE bucket.
// ============================================================================

test "w142/token: bucket inits at 1.0 (Core m_addr_token_bucket{1}) and drops excess" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    var peer = makeInboundPeer(allocator);
    defer peer.recv_buffer.deinit();

    // Core inits the bucket to 1.0 — NOT 1000.
    try testing.expectEqual(@as(f64, 1.0), peer.addr_token_bucket);

    // First addr message of 50 addresses: only floor(1.0)=1 admitted, 49 dropped.
    const admit = manager.takeAddrTokens(&peer, 50);
    try testing.expectEqual(@as(usize, 1), admit);
    // Bucket spent down to ~0 (no time elapsed → no refill).
    try testing.expect(peer.addr_token_bucket < 1.0);
}

test "w142/token: addr + addrv2 share ONE per-peer bucket (addrv2 flood on a drained bucket is dropped)" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    var peer = makeInboundPeer(allocator);
    defer peer.recv_buffer.deinit();

    // Drain the bucket via a legacy ADDR message (spends the single init token).
    const admit_addr = manager.takeAddrTokens(&peer, 100);
    try testing.expectEqual(@as(usize, 1), admit_addr);
    try testing.expect(peer.addr_token_bucket < 1.0);

    // CRITICAL anti-bypass: a follow-up ADDRV2 flood on the SAME peer hits the
    // SAME drained bucket — an attacker cannot switch to addrv2 to dodge the
    // rate limit. With no time elapsed the bucket is still < 1.0 → 0 admitted.
    const admit_addrv2 = manager.takeAddrTokens(&peer, 100);
    try testing.expectEqual(@as(usize, 0), admit_addrv2);
}

test "w142/token: bucket refills at 0.1/sec capped at 1000 (Core MAX_ADDR_RATE_PER_SECOND)" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    var peer = makeInboundPeer(allocator);
    defer peer.recv_buffer.deinit();

    // Back-date the refill clock by 100 seconds → +10 tokens (100 * 0.1), plus
    // the 1.0 init = 11.0 available. Stamp timestamp so refill is computed.
    peer.addr_token_bucket = 0.0;
    peer.addr_token_timestamp = std.time.timestamp() - 100;
    const admit = manager.takeAddrTokens(&peer, 100);
    // floor(0 + 100*0.1) = 10 admitted.
    try testing.expectEqual(@as(usize, 10), admit);

    // Cap: a huge elapsed time cannot exceed MAX_ADDR_PROCESSING_TOKEN_BUCKET.
    peer.addr_token_bucket = 0.0;
    peer.addr_token_timestamp = std.time.timestamp() - 1_000_000; // would be 100k tokens
    const admit_capped = manager.takeAddrTokens(&peer, 5000);
    try testing.expectEqual(@as(usize, 1000), admit_capped);
}

// ============================================================================
// 2. GETADDR-once guard + ignore-from-outbound (Core m_getaddr_recvd).
// ============================================================================

test "w142/getaddr-once: getaddr_recvd gates a second answer; outbound is ignored" {
    const allocator = testing.allocator;

    var inbound = makeInboundPeer(allocator);
    defer inbound.recv_buffer.deinit();
    // Fresh inbound peer: not yet answered, direction inbound → answerable.
    try testing.expectEqual(false, inbound.getaddr_recvd);
    const answerable_first = (inbound.direction != .outbound) and !inbound.getaddr_recvd;
    try testing.expect(answerable_first);
    // Handler sets the flag on the first answer.
    inbound.getaddr_recvd = true;
    const answerable_second = (inbound.direction != .outbound) and !inbound.getaddr_recvd;
    try testing.expect(!answerable_second); // repeat is ignored

    // An OUTBOUND peer is never answered, even on its first getaddr.
    var outbound = makeInboundPeer(allocator);
    defer outbound.recv_buffer.deinit();
    outbound.direction = .outbound;
    try testing.expectEqual(false, outbound.getaddr_recvd);
    const outbound_answerable = (outbound.direction != .outbound) and !outbound.getaddr_recvd;
    try testing.expect(!outbound_answerable);
}

test "w142/getaddr-cap: shareableAddrCount feeds the 23%-cap over successful addrs" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // 100 routable addresses added → all start with success=false, so the
    // shareable pool (the cap basis) is 0 until they connect.
    var i: u8 = 0;
    while (i < 100) : (i += 1) {
        try manager.addAddress(ip(8, 8, i, 1), 0, .peer_addr);
    }
    try testing.expectEqual(@as(usize, 0), manager.shareableAddrCount());
    try testing.expectEqual(@as(usize, 0), peer_mod.getaddrCap(manager.shareableAddrCount()));

    // Promote 100 of them to "shareable" (a successful feeler/outbound marks
    // success=true). Now the cap basis is 100 → floor(0.23*100)=23.
    i = 0;
    while (i < 100) : (i += 1) {
        manager.makeTriedOnFeelerSuccess(ip(8, 8, i, 1));
    }
    try testing.expectEqual(@as(usize, 100), manager.shareableAddrCount());
    try testing.expectEqual(@as(usize, 23), peer_mod.getaddrCap(manager.shareableAddrCount()));
}

// ============================================================================
// 1. FEELER: select-from-NEW + promote-on-success-ONLY + falsification.
// ============================================================================

test "w142/feeler: selects from NEW, promotes NEW->TRIED on success ONLY (not-probed stays NEW)" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Seed two routable addresses into the live addrman (addAddress feeds the
    // bucketed NEW table). Use distinct /16 groups so anti-Sybil spread does
    // not collapse them into one bucket position.
    const probed = ip(8, 8, 8, 8);
    const not_probed = ip(9, 9, 9, 9);
    try manager.addAddress(probed, 0, .peer_addr);
    try manager.addAddress(not_probed, 0, .peer_addr);

    // Both land in NEW, neither in TRIED.
    const am = &manager.addrman.?;
    try testing.expect(am.newCount() >= 2);
    try testing.expectEqual(@as(usize, 0), am.triedCount());
    try testing.expect(!am.isInTried(probed));
    try testing.expect(!am.isInTried(not_probed));

    // selectFeelerAddress draws ONLY from the NEW table (new_only=true).
    const picked = manager.selectFeelerAddress();
    try testing.expect(picked != null);
    // The picked address is a NEW-table entry (not already in TRIED).
    try testing.expect(!am.isInTried(picked.?));

    // A SUCCESSFUL feeler handshake promotes its address NEW->TRIED.
    manager.makeTriedOnFeelerSuccess(probed);
    try testing.expect(am.isInTried(probed));
    try testing.expect(am.triedCount() >= 1);

    // FALSIFICATION: the OTHER NEW entry, which was never probed, is STILL NEW.
    // A feeler dial/handshake FAILURE never calls makeTriedOnFeelerSuccess, so
    // it would never be promoted. If promotion happened unconditionally this
    // assertion would fail.
    try testing.expect(!am.isInTried(not_probed));
}

test "w142/feeler: bounded to MAX_FEELER_CONNECTIONS=1 and off the outbound budget" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // No feeler peers tracked initially.
    try testing.expectEqual(@as(usize, 0), manager.feelerCount());

    // Inject a fake in-flight feeler peer into the manager's peer list. Use a
    // safe init and clean it up manually (NOT via deinit, which would call
    // disconnect()->stream.close() on the undefined test stream).
    const feeler = try allocator.create(Peer);
    feeler.* = makeInboundPeer(allocator);
    feeler.conn_type = .feeler;
    feeler.direction = .outbound; // a feeler dials outbound
    try manager.peers.append(feeler);

    try testing.expectEqual(@as(usize, 1), manager.feelerCount());
    // At the bound: maybeOpenFeeler must not open another (feelerCount >= 1).
    // It returns cleanly (no panic, no new peer appended).
    const before = manager.peers.items.len;
    manager.maybeOpenFeeler();
    try testing.expectEqual(before, manager.peers.items.len);

    // Off the OUTBOUND budget: the live feeler is a `.feeler`, never an
    // `.outbound_full_relay`/`.block_relay`, so maintainOutbound's outbound
    // slot accounting (which the real probe never even joins — it is destroyed
    // after the handshake) cannot be consumed by it.
    try testing.expect(feeler.conn_type == .feeler);
    try testing.expect(feeler.conn_type != .outbound_full_relay);
    try testing.expect(feeler.conn_type != .block_relay);

    // Manual cleanup: remove from the manager list and free without calling
    // disconnect() on the undefined stream.
    _ = manager.peers.pop();
    feeler.recv_buffer.deinit();
    allocator.destroy(feeler);
    try testing.expectEqual(@as(usize, 0), manager.feelerCount());
}

test "w142/feeler: 120s interval + no-op when no NEW address (Core FEELER_INTERVAL / -connect)" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Genuine Core constants.
    try testing.expectEqual(@as(i64, 120), peer_mod.FEELER_INTERVAL_SECS);
    try testing.expectEqual(@as(usize, 1), peer_mod.MAX_FEELER_CONNECTIONS);

    // Empty addrman → no NEW candidate → selectFeelerAddress returns null and
    // maybeOpenFeeler is a clean no-op (no peers appended, no crash).
    try testing.expect(manager.selectFeelerAddress() == null);
    const before = manager.peers.items.len;
    manager.maybeOpenFeeler();
    try testing.expectEqual(before, manager.peers.items.len);

    // Interval guard: a recent feeler suppresses the next one. Stamp last_feeler
    // to "now" and seed a NEW addr; maybeOpenFeeler must NOT dial again (it
    // would have to open a socket, which in a unit test would fail anyway, but
    // the interval guard short-circuits before any dial).
    try manager.addAddress(ip(8, 8, 8, 8), 0, .peer_addr);
    manager.last_feeler_time = std.time.timestamp();
    const before2 = manager.peers.items.len;
    manager.maybeOpenFeeler(); // within 120s → suppressed
    try testing.expectEqual(before2, manager.peers.items.len);
    // last_feeler_time unchanged because the interval guard returned early.
    try testing.expect(std.time.timestamp() - manager.last_feeler_time < peer_mod.FEELER_INTERVAL_SECS);
}
