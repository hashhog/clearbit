//! FIX-3G — ADDR/ADDRV2 peer-timestamp clamp (3G policy, fleet-wide)
//!
//! Reference: bitcoin-core/src/net_processing.cpp:5678-5679
//!   if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_time + 10min)
//!       addr.nTime = std::chrono::time_point_cast<std::chrono::seconds>(current_time - 5*24h);
//!
//! Before this fix, clearbit's addr and addrv2 handlers ignored entry.timestamp
//! entirely; addAddress always stored std.time.timestamp() as last_seen regardless
//! of what the remote peer advertised.  A peer could therefore flood us with
//! future-dated addresses (nTime = now + 1 year) and those would survive into
//! addrman / known_addresses with last_seen = now, indistinguishable from a
//! freshly-seen live peer — the same staleness-inflation DoS Core plugged.
//!
//! This fix adds `clampAddrTimestamp(peer_time: u32, now: i64) u64` and threads
//! the clamped value through `addAddressWithTime` so addrman and known_addresses
//! record the peer-reported freshness (clamped, not now) for gossip entries.
//!
//! Test strategy (non-vacuous — FAILS without the fix):
//!   T1: unit-test clampAddrTimestamp against the three Core cases:
//!         pre-2001 (≤ 100_000_000) → now − 5*24h
//!         far-future (> now + 10 min) → now − 5*24h
//!         valid window → unchanged
//!   T2: verify addAddressWithTime is exported (FAILS pre-fix: symbol absent)
//!   T3: addAddressWithTime with a fresh valid timestamp stores that timestamp
//!       as last_seen (NOT the current wall clock), proving the gossip path uses
//!       the clamped peer time.
//!   T4: addAddressWithTime with a pre-2001 timestamp stores now − 5*24h (clamped).
//!   T5: legacy addAddress (null peer_time) still stores a now-like value
//!       (no regression for dns_seed / fixed_seed / manual callers).

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");

const PeerManager = peer_mod.PeerManager;
const AddressSource = peer_mod.AddressSource;

// ============================================================================
// T1 — clampAddrTimestamp unit tests
// ============================================================================

test "fix3g/T1a: pre-2001 timestamp clamped to now minus 5 days" {
    // peer_time = 1 (epoch + 1s) is pre-2001 (≤ 100_000_000)
    // Core: addr.nTime = current_time - 5*24h
    const now: i64 = 1_750_000_000; // 2025-era reference
    const five_days: i64 = 5 * 24 * 60 * 60;
    const result = peer_mod.clampAddrTimestamp(1, now);
    try testing.expectEqual(@as(u64, @intCast(now - five_days)), result);
}

test "fix3g/T1b: zero timestamp clamped to now minus 5 days" {
    const now: i64 = 1_750_000_000;
    const five_days: i64 = 5 * 24 * 60 * 60;
    const result = peer_mod.clampAddrTimestamp(0, now);
    try testing.expectEqual(@as(u64, @intCast(now - five_days)), result);
}

test "fix3g/T1c: exact pre-2001 boundary (100_000_000) clamped" {
    // Core condition is `<= 100_000_000`, so the boundary value is clamped.
    const now: i64 = 1_750_000_000;
    const five_days: i64 = 5 * 24 * 60 * 60;
    const result = peer_mod.clampAddrTimestamp(100_000_000, now);
    try testing.expectEqual(@as(u64, @intCast(now - five_days)), result);
}

test "fix3g/T1d: one second past pre-2001 boundary passes through unclamped" {
    // 100_000_001 > 100_000_000, and if ≤ now + 10min it is a valid timestamp.
    const now: i64 = 1_750_000_000;
    const result = peer_mod.clampAddrTimestamp(100_000_001, now);
    try testing.expectEqual(@as(u64, 100_000_001), result);
}

test "fix3g/T1e: far-future timestamp clamped to now minus 5 days" {
    // peer_time = now + 11 minutes is > now + 10 minutes → clamp
    const now: i64 = 1_750_000_000;
    const eleven_min: u32 = 11 * 60;
    const peer_time: u32 = @intCast(now + @as(i64, eleven_min));
    const five_days: i64 = 5 * 24 * 60 * 60;
    const result = peer_mod.clampAddrTimestamp(peer_time, now);
    try testing.expectEqual(@as(u64, @intCast(now - five_days)), result);
}

test "fix3g/T1f: exactly 10 minutes in the future passes through unclamped" {
    // Core: > now + 10min is clamped; exactly now + 10min is NOT clamped.
    const now: i64 = 1_750_000_000;
    const peer_time: u32 = @intCast(now + 10 * 60);
    const result = peer_mod.clampAddrTimestamp(peer_time, now);
    try testing.expectEqual(@as(u64, @intCast(now + 10 * 60)), result);
}

test "fix3g/T1g: valid recent timestamp passes through unchanged" {
    // A timestamp 1 hour in the past — completely normal gossip.
    const now: i64 = 1_750_000_000;
    const peer_time: u32 = @intCast(now - 3600);
    const result = peer_mod.clampAddrTimestamp(peer_time, now);
    try testing.expectEqual(@as(u64, @intCast(now - 3600)), result);
}

// ============================================================================
// T2 — addAddressWithTime is exported (FAILS pre-fix: symbol absent)
// ============================================================================

test "fix3g/T2: addAddressWithTime is a public method of PeerManager" {
    // This test FAILS to compile without the fix because addAddressWithTime
    // did not exist before — proving the test is non-vacuous.
    try testing.expect(@hasDecl(PeerManager, "addAddressWithTime"));
}

// ============================================================================
// T3 — gossip path stores clamped peer timestamp, not now
// ============================================================================

test "fix3g/T3: addAddressWithTime stores clamped peer timestamp as last_seen" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Use a routable public address.
    const addr = std.net.Address.initIp4([4]u8{ 8, 8, 8, 8 }, 8333);
    // Supply a valid peer timestamp from 1 hour ago.
    const now_i = std.time.timestamp();
    const peer_ts: u64 = if (now_i > 3600) @intCast(now_i - 3600) else 0;

    try manager.addAddressWithTime(addr, p2p.NODE_NETWORK, .peer_addr, peer_ts);

    const key = PeerManager.addressKey(addr);
    const info = manager.known_addresses.get(key).?;

    // last_seen must equal peer_ts (≈ now - 3600), NOT now.
    // Without the fix, last_seen would be set to now (within a few seconds of
    // the current wall clock), which is ~3600 seconds MORE than peer_ts.
    // Tolerance of 5s around peer_ts to absorb any clock drift in the test.
    const diff: i64 = info.last_seen - @as(i64, @intCast(peer_ts));
    try testing.expect(diff >= 0 and diff <= 5);
    // Confirm it is NOT approximately now (which would be ~3600s larger).
    try testing.expect(info.last_seen < now_i - 3000);
}

// ============================================================================
// T4 — pre-2001 timestamp stored as now − 5*24h (clamped via addAddressWithTime)
// ============================================================================

test "fix3g/T4: pre-2001 peer timestamp stored as now minus 5 days" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    const addr = std.net.Address.initIp4([4]u8{ 1, 1, 1, 1 }, 8333);
    const now_i = std.time.timestamp();
    // Clamp a pre-2001 timestamp before calling addAddressWithTime (as the
    // addr handler does).
    const clamped = peer_mod.clampAddrTimestamp(42, now_i);
    try manager.addAddressWithTime(addr, p2p.NODE_NETWORK, .peer_addr, clamped);

    const key = PeerManager.addressKey(addr);
    const info = manager.known_addresses.get(key).?;

    // Expected: now − 5*24h  (± 5s tolerance for test execution time)
    const five_days: i64 = 5 * 24 * 60 * 60;
    const expected: i64 = now_i - five_days;
    const diff = info.last_seen - expected;
    try testing.expect(diff >= -5 and diff <= 5);
}

// ============================================================================
// T5 — legacy addAddress (null peer_time) still uses now (no regression)
// ============================================================================

test "fix3g/T5: addAddress (no peer_time) stores current wall clock as last_seen" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    const addr = std.net.Address.initIp4([4]u8{ 9, 9, 9, 9 }, 8333);
    const before = std.time.timestamp();
    try manager.addAddress(addr, p2p.NODE_NETWORK, .dns_seed);
    const after = std.time.timestamp();

    const key = PeerManager.addressKey(addr);
    const info = manager.known_addresses.get(key).?;

    // last_seen should be within [before, after+1] — the wall clock at call time.
    try testing.expect(info.last_seen >= before);
    try testing.expect(info.last_seen <= after + 1);
}
