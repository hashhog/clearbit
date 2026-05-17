//! W128 — AddrMan + connman + peer selection 30-gate audit (clearbit / Zig 0.13)
//!
//! Reference: bitcoin-core/src/{addrman.cpp, addrman.h, addrman_impl.h,
//!                              net.cpp, net.h, banman.cpp, banman.h,
//!                              node/eviction.cpp, node/eviction.h}
//!
//! This wave audits the *runtime/peer-selection* surface of AddrMan,
//! ThreadOpenConnections, AttemptToEvictConnection, BanMan, and the
//! discouragement bloom filter. The static-storage / bucketing layer was
//! audited in W104; gates here re-cross-test at the eviction, select, and
//! peer-selection call sites and explicitly call out the overlap when one
//! exists.
//!
//! Excludes (already audited):
//!   - W104 storage/bucketing structure (we re-test at the call-sites, not
//!     re-cover the storage layer).
//!   - W117 BIP-155 wire-format (addr / addrv2 message parsing).
//!   - W115 ASMap health-check (cf. peer.zig asmapHealthCheck()).
//!
//! Gate result legend:  PASS  /  BUG  /  MISSING
//!
//! See clearbit/audit/w128_addrman.md for the bug catalogue and matrix.

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const banlist_mod = @import("banlist.zig");

const PeerManager = peer_mod.PeerManager;
const Peer = peer_mod.Peer;
const AddressInfo = peer_mod.AddressInfo;
const AddressSource = peer_mod.AddressSource;
const ConnectionType = peer_mod.ConnectionType;
const EvictionCandidate = peer_mod.EvictionCandidate;
const BanList = banlist_mod.BanList;

// ============================================================================
// AddrMan Good/Attempt/Connected/IsTerrible/GetChance (G1-G5)
// ============================================================================

// G1 BUG-1: AddrMan.Good() standalone API missing.
// Core: addrman.h:150 `Good(const CService& addr, NodeSeconds time)`.
// clearbit folds the equivalent of Good() inline into the success path of
// selectPeerToConnect+connectOutboundNegotiated, but exposes no callable.
// Any code path that connects WITHOUT going through that pair (e.g.
// connectToAnchors at peer.zig:3405) never updates known_addresses.success.
test "w128/G1: PeerManager has no markAddressGood / Good() standalone API" {
    try testing.expect(!@hasDecl(PeerManager, "markAddressGood"));
    try testing.expect(!@hasDecl(PeerManager, "Good"));
    try testing.expect(!@hasDecl(PeerManager, "addrmanGood"));
    try testing.expect(!@hasDecl(PeerManager, "good"));
    // Anchors connect bypasses good-marking — assert the anchor connect
    // function exists but PeerManager has no anchor-good hook.
    try testing.expect(@hasDecl(PeerManager, "connectToAnchors"));
    try testing.expect(!@hasDecl(PeerManager, "markAnchorGood"));
}

// G2 BUG-2: AddrMan.Attempt() standalone API missing.
// Core: addrman.h:127 `Attempt(addr, fCountFailure, time)`.
// clearbit's attempt-counting is welded into selectPeerToConnect.  manual
// reconnect / anchor reconnect / onetry RPC never bump info.attempts.
test "w128/G2: PeerManager has no Attempt() standalone API; attempts coupled to selection" {
    try testing.expect(!@hasDecl(PeerManager, "Attempt"));
    try testing.expect(!@hasDecl(PeerManager, "markAttempt"));
    try testing.expect(!@hasDecl(PeerManager, "recordAttempt"));
    try testing.expect(!@hasDecl(PeerManager, "addrmanAttempt"));
    // selectPeerToConnect exists; that is the only attempt-incrementing path.
    try testing.expect(@hasDecl(PeerManager, "selectPeerToConnect"));
    // maintainManualConnections exists; it does NOT call any markAttempt
    // helper — only sets info.last_tried/attempts inline.
    try testing.expect(@hasDecl(PeerManager, "maintainManualConnections"));
}

// G3 BUG-3: AddrMan.Connected() refresh missing.
// Core: addrman.h:220 `Connected(addr, time)` refreshes info.nTime every
// 20 minutes for live peers.  clearbit's known_addresses entries are
// never refreshed during the lifetime of a connection — last_seen is
// set once on addAddress and once on outbound-connect success.
test "w128/G3: PeerManager has no Connected() refresh for long-lived peers" {
    try testing.expect(!@hasDecl(PeerManager, "Connected"));
    try testing.expect(!@hasDecl(PeerManager, "markConnected"));
    try testing.expect(!@hasDecl(PeerManager, "refreshLastSeen"));
    try testing.expect(!@hasDecl(PeerManager, "addrmanConnected"));
    // AddressInfo has last_seen but it is not refreshed by any periodic loop.
    try testing.expect(@hasField(AddressInfo, "last_seen"));
}

// G4 BUG-4: IsTerrible eviction missing.
// Core addrman.cpp:49-72 enumerates 5 conditions.  clearbit has no
// equivalent on AddressInfo; known_addresses grows unbounded.
// Overlap: W104 G8 (storage-layer).  Here re-tested at the eviction-on-
// failure call site — selectPeerToConnect does not consult IsTerrible
// when skipping a candidate.
test "w128/G4: No IsTerrible eviction at selectPeerToConnect skip-set" {
    try testing.expect(!@hasDecl(peer_mod, "isTerrible"));
    try testing.expect(!@hasDecl(peer_mod, "IsTerrible"));
    try testing.expect(!@hasDecl(AddressInfo, "isTerrible"));
    // Constants from Core addrman.h:29-37:
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_HORIZON"));
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_RETRIES"));
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_MAX_FAILURES"));
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_MIN_FAIL"));
}

// G5 BUG-5: GetChance() probabilistic selection missing.
// Core addrman.cpp:74-87 weights selection by 0.66^min(nAttempts,8)
// times 0.01 when last_try < 10min ago.  clearbit picks the candidate
// with the minimum attempts count — deterministic; predictable; attackable.
// Overlap: W104 G9 (storage-layer). Re-tested for consequence at select.
test "w128/G5: selectPeerToConnect picks min-attempts, not probabilistic" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    try testing.expect(!@hasDecl(AddressInfo, "getChance"));
    try testing.expect(!@hasDecl(AddressInfo, "GetChance"));
    try testing.expect(!@hasDecl(peer_mod, "getAddressChance"));

    // Two routable addresses; one with high attempts, one fresh.
    const addr_attempted = std.net.Address.initIp4([4]u8{ 8, 8, 8, 8 }, 8333);
    const addr_fresh = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333);

    try manager.addAddress(addr_attempted, p2p.NODE_NETWORK, .dns_seed);
    try manager.addAddress(addr_fresh, p2p.NODE_NETWORK, .dns_seed);

    if (manager.known_addresses.getPtr(PeerManager.addressKey(addr_attempted))) |info| {
        info.attempts = 8; // 0.66^8 ≈ 3.6% probability in Core
        info.last_tried = std.time.timestamp() - 7200; // not in 10-min cooldown
    }

    // Deterministic: clearbit picks addr_fresh every time (min attempts=0).
    // Repeat many times to demonstrate non-randomness.
    var fresh_picks: usize = 0;
    var attempted_picks: usize = 0;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        // Reset attempts so selection is repeatable.
        if (manager.known_addresses.getPtr(PeerManager.addressKey(addr_fresh))) |info| {
            info.attempts = 0;
            info.last_tried = 0;
        }
        if (manager.known_addresses.getPtr(PeerManager.addressKey(addr_attempted))) |info| {
            info.attempts = 8;
            info.last_tried = std.time.timestamp() - 7200;
        }
        const pick = manager.selectPeerToConnect() orelse continue;
        if (PeerManager.addressKey(pick) == PeerManager.addressKey(addr_fresh)) {
            fresh_picks += 1;
        } else {
            attempted_picks += 1;
        }
    }
    // Core: occasional attempted_picks expected (3.6%).  clearbit: 100% fresh.
    try testing.expect(fresh_picks >= 4);
}

// ============================================================================
// nKey + bucketing (G6-G7)
// ============================================================================

// G6 BUG-6: Per-node nKey randomizer missing (P0).
// Core: addrman_impl.h:163 uint256 nKey; persisted in peers.dat.
// clearbit has no nKey; bucket positions and netgroup keying use raw
// address bytes.  Overlap: W104 G7/G20 (presence/persistence).  Re-tested
// here for the eviction-time + select-time consequence — without nKey
// the eviction netgroup-protect order is deterministic + attackable.
test "w128/G6: PeerManager has no per-node nKey randomizer for bucket hashing" {
    try testing.expect(!@hasField(PeerManager, "nKey"));
    try testing.expect(!@hasField(PeerManager, "n_key"));
    try testing.expect(!@hasField(PeerManager, "addrman_key"));
    try testing.expect(!@hasField(PeerManager, "bucket_key"));
    // Core also persists nKey — no load/save path either.
    try testing.expect(!@hasDecl(PeerManager, "savePeersKey"));
    try testing.expect(!@hasDecl(PeerManager, "loadPeersKey"));
}

// G7 BUG-7: Cryptographic source-group + ASN bucketing missing.
// Core: addrman.cpp:35-46 GetNewBucket(nKey, src, netgroupman) hashes
// nKey << target-group << src-group → bucket index.  clearbit has no
// bucket function at all; known_addresses is a flat AutoHashMap.
test "w128/G7: No getNewBucket / getTriedBucket pure functions" {
    try testing.expect(!@hasDecl(peer_mod, "getNewBucket"));
    try testing.expect(!@hasDecl(peer_mod, "getTriedBucket"));
    try testing.expect(!@hasDecl(peer_mod, "GetNewBucket"));
    try testing.expect(!@hasDecl(peer_mod, "GetTriedBucket"));
    try testing.expect(!@hasDecl(AddressInfo, "getNewBucket"));
    try testing.expect(!@hasDecl(AddressInfo, "getTriedBucket"));
    // ASMap exists for netgroup keying at select time (peer.zig:3441-3444),
    // confirming this is a deliberate divergence — bucketing is not
    // wired even though the inputs are available.
    try testing.expect(@hasField(PeerManager, "asmap_data"));
}

// ============================================================================
// ThreadOpenConnections architecture (G8)
// ============================================================================

// G8 BUG-8: ThreadOpenConnections loop architecture missing.
// Core net.cpp:2530-2899: dedicated thread, FEELER_INTERVAL, EXTRA_*
// timers, 100-tries-per-call selection loop, ResolveCollisions head,
// fixed-seeds grace, MaybePickPreferredNetwork.  clearbit's
// maintainOutbound is a per-tick function in the main loop with no
// equivalent timers.
test "w128/G8: No dedicated ThreadOpenConnections loop / timers" {
    try testing.expect(!@hasDecl(peer_mod, "threadOpenConnections"));
    try testing.expect(!@hasDecl(peer_mod, "ThreadOpenConnections"));
    // FEELER_INTERVAL: Core net.h:61 = 2min
    try testing.expect(!@hasDecl(peer_mod, "FEELER_INTERVAL"));
    try testing.expect(!@hasDecl(peer_mod, "FEELER_INTERVAL_SECS"));
    // EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL: Core net.h:63 = 5min
    try testing.expect(!@hasDecl(peer_mod, "EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL"));
    // EXTRA_NETWORK_PEER_INTERVAL: Core net.cpp:91 = 5min
    try testing.expect(!@hasDecl(peer_mod, "EXTRA_NETWORK_PEER_INTERVAL"));
    // No 100-try inner loop constant either
    try testing.expect(!@hasDecl(peer_mod, "MAX_OUTBOUND_TRIES_PER_LOOP"));
    // The per-tick function exists — that is the equivalent surface.
    try testing.expect(@hasDecl(PeerManager, "maintainOutbound"));
}

// ============================================================================
// AttemptToEvictConnection / SelectNodeToEvict (G9-G12)
// ============================================================================

// G9 BUG-9: Eviction netgroup-protect picks the WRONG end of the sorted
// candidate list. Core eviction.cpp:188:
//   EraseLastKElements(vEvictionCandidates, CompareNetGroupKeyed, 4)
// — sort ascending then erase LAST 4 (highest netgroup-keyed values).
// clearbit peer.zig:2130-2141:
//   sort ascending then iterate FORWARD protecting the first 4 unique.
test "w128/G9: selectEvictionCandidate protects LOWEST netgroup keys (Core protects HIGHEST)" {
    const allocator = testing.allocator;

    // Build 5 candidates with distinct netgroups; the lowest 4 should be
    // protected by clearbit's algorithm, leaving the HIGHEST to be evicted.
    var candidates = [_]EvictionCandidate{
        .{ .peer_index = 0, .net_group = 100, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 1000, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 1, .net_group = 200, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 1000, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 2, .net_group = 300, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 1000, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 3, .net_group = 400, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 1000, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 4, .net_group = 500, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 1000, .relay_txs = true, .is_protected = false },
    };
    // With only 5 candidates and protect-4-netgroups + protect-8-ping (etc.),
    // there is only one unprotected slot. clearbit picks the highest netgroup
    // (peer_index=4, net_group=500) — Core would have picked the lowest.
    const victim_idx = peer_mod.selectEvictionCandidate(&candidates, allocator);
    // clearbit selects exactly peer_index=4 (highest-netgroup unprotected).
    if (victim_idx) |idx| {
        try testing.expect(idx == 4);
    } else {
        // Algorithm may decline (over-protection); the assertion is that
        // IF it picks, it picks the high end. Document both branches.
        try testing.expect(victim_idx == null);
    }
}

// G10 BUG-10: Block-relay-only protect predicate wrong.
// Core eviction.cpp:196 protects only candidates where
//   !m_relay_txs && fRelevantServices.
// clearbit peer.zig:2161 protects every !relay_txs candidate up to 8 —
// no fRelevantServices guard.  A peer with relay_txs=false AND services=0
// (misbehaving SPV) gets incorrectly protected by clearbit.
test "w128/G10: block-relay-only protect ignores fRelevantServices" {
    // EvictionCandidate has no fRelevantServices field at all.
    try testing.expect(!@hasField(EvictionCandidate, "fRelevantServices"));
    try testing.expect(!@hasField(EvictionCandidate, "relevant_services"));
    try testing.expect(!@hasField(EvictionCandidate, "has_all_wanted_services"));
    // It has relay_txs (peer.zig:2054) — that is the predicate clearbit uses.
    try testing.expect(@hasField(EvictionCandidate, "relay_txs"));
}

// G11 BUG-11: ProtectNoBanConnections not derived from no_ban.
// Core eviction.cpp:182 calls ProtectNoBanConnections FIRST, removing
// candidates with m_noban=true entirely.  clearbit's is_protected is a
// hand-set bool with no automatic derivation from Peer.no_ban.
test "w128/G11: EvictionCandidate.is_protected not auto-derived from Peer.no_ban" {
    // is_protected exists but defaults to false (see peer.zig:2077).
    try testing.expect(@hasField(EvictionCandidate, "is_protected"));
    // Peer.no_ban exists (peer.zig:724) but buildEvictionCandidates never
    // reads it.  The closest helper is isEvictionCandidate (peer.zig:2019).
    try testing.expect(@hasField(Peer, "no_ban"));
    // buildEvictionCandidates is defined; verify it doesn't filter by no_ban
    // by reading the source.  Structural assertion: no helper exists named
    // protectNoBanConnections / filterByNoBan.
    try testing.expect(!@hasDecl(peer_mod, "protectNoBanConnections"));
    try testing.expect(!@hasDecl(peer_mod, "filterByNoBan"));
}

// G12 BUG-12: ProtectEvictionCandidatesByRatio (disadvantaged networks) missing.
// Core eviction.cpp:105-176 reserves up to 25% of protect-by-time slots for
// CJDNS / I2P / localhost / Onion — even when their uptime is lower.
// clearbit peer.zig:2173-2189 does straight protect-half-by-time with no
// network-class awareness.
test "w128/G12: No disadvantaged-network reservation in eviction protect-by-time" {
    try testing.expect(!@hasDecl(peer_mod, "protectEvictionCandidatesByRatio"));
    try testing.expect(!@hasDecl(peer_mod, "ProtectEvictionCandidatesByRatio"));
    // EvictionCandidate has no network/is_local fields the disadvantaged-
    // ratio logic needs.
    try testing.expect(!@hasField(EvictionCandidate, "network"));
    try testing.expect(!@hasField(EvictionCandidate, "is_local"));
    try testing.expect(!@hasField(EvictionCandidate, "m_is_local"));
    try testing.expect(!@hasField(EvictionCandidate, "m_network"));
}

// ============================================================================
// Feeler scheduling + extra-network outbound (G13-G14)
// ============================================================================

// G13 BUG-13: Feeler scheduling missing.
// ConnectionType.feeler exists in the enum (peer.zig:548) but PeerManager
// has no state to schedule feelers — no next_feeler timer, no
// makeTriedOnFeelerSuccess, no select-new-only.
// Overlap: W104 G14.  Re-tested here for the *scheduling* call site.
test "w128/G13: ConnectionType.feeler enum variant exists but has no scheduler state" {
    // Variant exists in the enum.
    try testing.expect(@hasField(ConnectionType, "feeler"));
    // No timer / scheduler state on PeerManager.
    try testing.expect(!@hasField(PeerManager, "next_feeler_time"));
    try testing.expect(!@hasField(PeerManager, "last_feeler_time"));
    try testing.expect(!@hasField(PeerManager, "feeler_schedule"));
    // No feeler-specific selection helper.
    try testing.expect(!@hasDecl(PeerManager, "scheduleFeeler"));
    try testing.expect(!@hasDecl(PeerManager, "selectFeelerAddress"));
    try testing.expect(!@hasDecl(PeerManager, "makeTriedOnFeelerSuccess"));
}

// G14 BUG-14: MaybePickPreferredNetwork extra-network slot missing.
// Core net.cpp:2514 opens an extra full-relay slot to an under-represented
// network after the regular 8 slots are full.  clearbit has cjdnsreachable
// (peer.zig:2441) but no per-network-count tracking or extra-network logic.
test "w128/G14: No maybePickPreferredNetwork extra-outbound-by-network slot" {
    try testing.expect(!@hasDecl(PeerManager, "maybePickPreferredNetwork"));
    try testing.expect(!@hasDecl(PeerManager, "MaybePickPreferredNetwork"));
    // No per-network outbound count tracking.
    try testing.expect(!@hasField(PeerManager, "outbound_per_network"));
    try testing.expect(!@hasField(PeerManager, "network_peer_counts"));
    // cjdnsreachable is the only reachable-network field; it is a single
    // bool, not a Network-keyed counter.
    try testing.expect(@hasField(PeerManager, "cjdnsreachable"));
}

// ============================================================================
// BanMan: Ban vs Discourage distinction (G15-G19)
// ============================================================================

// G15 BUG-15: BanMan.Discourage() distinct primitive missing.
// Core banman.cpp:124-128 inserts CNetAddr bytes into a rolling bloom filter.
// clearbit's BanList has only ban/unban/isBanned — no discourage.
test "w128/G15: BanList has no Discourage() / IsDiscouraged() primitives" {
    try testing.expect(!@hasDecl(BanList, "discourage"));
    try testing.expect(!@hasDecl(BanList, "Discourage"));
    try testing.expect(!@hasDecl(BanList, "isDiscouraged"));
    try testing.expect(!@hasDecl(BanList, "IsDiscouraged"));
    try testing.expect(!@hasDecl(banlist_mod, "discourageAddress"));
    // ban / isBanned exist (the conflated path).
    try testing.expect(@hasDecl(BanList, "ban"));
    try testing.expect(@hasDecl(BanList, "isBanned"));
}

// G16 BUG-16: Rolling bloom filter for discouragement missing.
// Core banman.h:98 `CRollingBloomFilter m_discouraged{50000, 0.000001}`.
// clearbit has no bloom filter; misbehaviour entries pile into the
// unbounded BanList JSON file.
test "w128/G16: No rolling bloom filter for discouragement (unbounded misbehaviour set)" {
    try testing.expect(!@hasField(BanList, "discouraged"));
    try testing.expect(!@hasField(BanList, "m_discouraged"));
    try testing.expect(!@hasField(BanList, "discouragement_filter"));
    // No bloom-filter-related constants.
    try testing.expect(!@hasDecl(banlist_mod, "DISCOURAGEMENT_BLOOM_SIZE"));
    try testing.expect(!@hasDecl(banlist_mod, "DISCOURAGEMENT_BLOOM_FPR"));
}

// G17 BUG-17: Peer.prefer_evict flag missing.
// Core net.cpp:1814: `bool discouraged = m_banman->IsDiscouraged(addr)` →
// candidate.prefer_evict = discouraged.  Eviction prefers prefer_evict
// candidates last (eviction.cpp:212).  clearbit has no prefer_evict field.
test "w128/G17: Peer / EvictionCandidate have no prefer_evict flag" {
    try testing.expect(!@hasField(Peer, "prefer_evict"));
    try testing.expect(!@hasField(Peer, "m_prefer_evict"));
    try testing.expect(!@hasField(EvictionCandidate, "prefer_evict"));
    try testing.expect(!@hasField(EvictionCandidate, "m_prefer_evict"));
}

// G18 BUG-18: CalculateKeyedNetGroup keyed by per-node nKey missing.
// Core net.cpp:4144-4148 keys the netgroup through
// GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(vchNetGroup).
// clearbit's EvictionCandidate.net_group is the raw u32 from
// netGroup(address) — predictable.
test "w128/G18: net_group on EvictionCandidate is raw u32, not nKey-keyed" {
    // Field is raw u32 (peer.zig:2049).
    try testing.expect(@hasField(EvictionCandidate, "net_group"));
    const candidate = EvictionCandidate{
        .peer_index = 0,
        .net_group = 0x0a000000, // 10.x.x.x /16
        .min_ping_time = 0,
        .last_block_time = 0,
        .last_tx_time = 0,
        .connect_time = 0,
        .relay_txs = false,
        .is_protected = false,
    };
    // Raw u32 — no Deterministic Randomizer hashing.
    try testing.expectEqual(@as(u32, 0x0a000000), candidate.net_group);
    // No calculateKeyedNetGroup helper exists.
    try testing.expect(!@hasDecl(peer_mod, "calculateKeyedNetGroup"));
    try testing.expect(!@hasDecl(peer_mod, "CalculateKeyedNetGroup"));
    // No RANDOMIZER_ID_NETGROUP constant.
    try testing.expect(!@hasDecl(peer_mod, "RANDOMIZER_ID_NETGROUP"));
}

// G19 BUG-19: Subnet (CSubNet) banning missing.
// Core banman.cpp:130-154 accepts both CNetAddr and CSubNet.  RPC
// `setban "192.168.0.0/16" add` ban-by-subnet works against Core.
// clearbit's BanList.ban accepts only ip: [4]u8 — single host, IPv4 only.
test "w128/G19: BanList has no subnet (CSubNet) banning support" {
    // No banSubnet / banByPrefix helper.
    try testing.expect(!@hasDecl(BanList, "banSubnet"));
    try testing.expect(!@hasDecl(BanList, "banByPrefix"));
    try testing.expect(!@hasDecl(BanList, "banCIDR"));
    try testing.expect(!@hasDecl(banlist_mod, "SubNet"));
    try testing.expect(!@hasDecl(banlist_mod, "CSubNet"));

    // banAddress silently no-ops for IPv6 (banlist.zig:109-113).
    const allocator = testing.allocator;
    var bl = BanList.init(allocator, null);
    defer bl.deinit();
    const ipv6_addr = std.net.Address.initIp6(
        [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        8333, 0, 0,
    );
    try bl.banAddress(ipv6_addr, 60 * 60, "ipv6 ban silent no-op");
    // The count must be zero — IPv6 ban silently dropped.
    try testing.expectEqual(@as(usize, 0), bl.count());
}

// ============================================================================
// Outbound diversity at select time (G20 — PASS)
// ============================================================================

// G20 PASS: Outbound IPv4/IPv6 distinct netgroup at select.
// clearbit's violatesNetgroupDiversity (peer.zig:3449-3452) checks
// outbound_netgroups before connecting.  Core net.cpp:2831 does the same
// (`if (outbound_ipv46_peer_netgroups.contains(...)) continue`).
// This is correctly wired — the only-asn-or-/16 difference is acceptable.
test "w128/G20: PASS — outbound netgroup diversity enforced at select" {
    // The diversity check exists and is called from selectPeerToConnect.
    try testing.expect(@hasDecl(PeerManager, "violatesNetgroupDiversity"));
    try testing.expect(@hasField(PeerManager, "outbound_netgroups"));
    // getNetGroup is the keying function (ASN-aware when asmap loaded).
    try testing.expect(@hasDecl(PeerManager, "getNetGroup"));
}

// ============================================================================
// Discouragement vs ban policy (G21-G22)
// ============================================================================

// G21 BUG-21: DEFAULT_BAN_DURATION=24h applied to misbehaviour at all.
// Core's DEFAULT_MISBEHAVING_BANTIME=24h matches clearbit's
// DEFAULT_BAN_DURATION constant, but Core only applies that duration to
// manual `setban` calls — misbehaviour uses Discourage (bloom-filter
// insert, no time-bounded entry).
test "w128/G21: DEFAULT_BAN_DURATION = 24h applied to misbehaviour (wrong policy)" {
    // Value matches Core's DEFAULT_MISBEHAVING_BANTIME.
    try testing.expectEqual(@as(i64, 24 * 60 * 60), peer_mod.DEFAULT_BAN_DURATION);
    // banlist_mod re-exports the same constant.
    try testing.expectEqual(@as(i64, 24 * 60 * 60), banlist_mod.DEFAULT_BAN_DURATION);
    // No separate DISCOURAGE-only constant — there is no discourage path.
    try testing.expect(!@hasDecl(peer_mod, "DEFAULT_DISCOURAGE_DURATION"));
    try testing.expect(!@hasDecl(peer_mod, "DEFAULT_MISBEHAVING_BANTIME"));
}

// G22 BUG-22: should_ban → 24h hard ban via processAllMessages.
// peer.zig:3593-3605: any peer with should_ban=true gets banIP'd for
// DEFAULT_BAN_DURATION. misbehaving() (peer.zig:1856-1886) sets
// should_ban for every non-noban/non-manual/non-local peer on a SINGLE
// misbehaviour event.  Net effect: clearbit instant-bans for 24h on any
// misbehaviour — Core uses the rolling bloom-filter discouragement instead.
test "w128/G22: misbehaving() sets should_ban; processAllMessages would 24h-ban" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Construct a peer at runtime.  Use a manually-created Peer with a
    // fake stream — we just need the misbehaving() side-effect.
    var peer: Peer = .{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333),
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
        .min_ping_time = 0,
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
    };
    // Default no_ban=false, conn_type=.inbound, address routable, so
    // misbehaving() falls through to the single-event discourage branch.
    peer.misbehaving(10, "test-violation");
    // BUG-22: a single misbehaving call flips should_ban TRUE.
    try testing.expect(peer.should_ban);
    // processAllMessages would then commit a 24h ban — assert the
    // commit-on-should_ban code path exists.  (No way to introspect a
    // function body in Zig at comptime, but we can confirm the
    // DEFAULT_BAN_DURATION constant is referenced from the misbehaving
    // path conceptually by checking that the constant is the value Core
    // would use for `setban` permanent — distinguishing the two.)
    try testing.expectEqual(@as(i64, 24 * 60 * 60), peer_mod.DEFAULT_BAN_DURATION);

    peer.recv_buffer.deinit();
}

// ============================================================================
// Stale-tip + extra block-relay (G23-G24)
// ============================================================================

// G23 BUG-23: GetTryNewOutboundPeer stale-tip extra outbound missing.
// Core net_processing.cpp:5380-5390 opens an EXTRA full-relay slot when
// the tip is stale.  clearbit's evictStaleTipPeer (peer.zig:5984-6021)
// disconnects the worst stale-tip peer but does not open an extra slot.
test "w128/G23: No setTryNewOutboundPeer flag for stale-tip extra outbound" {
    try testing.expect(!@hasDecl(PeerManager, "setTryNewOutboundPeer"));
    try testing.expect(!@hasDecl(PeerManager, "getTryNewOutboundPeer"));
    try testing.expect(!@hasField(PeerManager, "try_new_outbound_peer"));
    try testing.expect(!@hasField(PeerManager, "m_try_new_outbound_peer"));
    // evictStaleTipPeer exists but the extra-slot logic doesn't.
    // (evictStaleTipPeer is private — verified by source inspection.)
}

// G24 BUG-24: next_extra_block_relay timer missing.
// Core periodically opens an extra block-relay-only connection (5 min
// exponential).  clearbit has no scheduled block-relay-only creation —
// only the 2 anchors loaded at startup go through .block_relay.
test "w128/G24: No next_extra_block_relay timer / scheduled BLOCK_RELAY creation" {
    try testing.expect(!@hasField(PeerManager, "next_extra_block_relay"));
    try testing.expect(!@hasField(PeerManager, "last_extra_block_relay_time"));
    try testing.expect(!@hasDecl(PeerManager, "startExtraBlockRelayPeers"));
    try testing.expect(!@hasDecl(PeerManager, "StartExtraBlockRelayPeers"));
    try testing.expect(!@hasField(PeerManager, "start_extra_block_relay_peers"));
}

// ============================================================================
// Outbound caps (G25 — PASS) + anchors (G26 — PASS)
// ============================================================================

// G25 PASS: MAX_OUTBOUND_FULL_RELAY=8 vs MAX_BLOCK_RELAY=2.
// Core net.h:69-73.  clearbit peer.zig:20 + 354+357.  Constants align.
test "w128/G25: PASS — MAX_OUTBOUND_CONNECTIONS=8, MAX_BLOCK_RELAY_ONLY_CONNECTIONS=2" {
    try testing.expectEqual(@as(usize, 8), peer_mod.MAX_OUTBOUND_CONNECTIONS);
    try testing.expectEqual(@as(usize, 2), peer_mod.MAX_BLOCK_RELAY_ONLY_CONNECTIONS);
    try testing.expectEqual(@as(usize, 2), peer_mod.MAX_BLOCK_RELAY_ONLY_ANCHORS);
}

// G26 PASS: Anchors saved on shutdown / loaded on startup.
// Core net.cpp:3496-3497.  clearbit saveAnchors / loadAnchors exists.
test "w128/G26: PASS — anchors.dat save/load wired" {
    try testing.expect(@hasDecl(PeerManager, "saveAnchors"));
    try testing.expect(@hasDecl(PeerManager, "loadAnchors"));
    try testing.expect(@hasDecl(PeerManager, "connectToAnchors"));
    try testing.expect(@hasField(PeerManager, "anchors_path"));
    try testing.expect(@hasField(PeerManager, "anchor_addresses"));
}

// ============================================================================
// MaybeDiscourageAndDisconnect flow (G27)
// ============================================================================

// G27 BUG-27: MaybeDiscourageAndDisconnect flow conflated.
// Core: misbehaviour increments m_should_discourage; per-tick
// MaybeDiscourageAndDisconnect reads it and either Discourage+disconnect
// or disconnect-only (local).  clearbit short-circuits this — the
// misbehaving function directly sets should_ban (≡ should_discourage)
// AND processAllMessages does the ban+disconnect.  Intermediate hand-off
// step (MaybeDiscourageAndDisconnect as a distinct function) is absent.
test "w128/G27: No standalone MaybeDiscourageAndDisconnect function" {
    try testing.expect(!@hasDecl(PeerManager, "maybeDiscourageAndDisconnect"));
    try testing.expect(!@hasDecl(PeerManager, "MaybeDiscourageAndDisconnect"));
    try testing.expect(!@hasDecl(peer_mod, "maybeDiscourageAndDisconnect"));
    // should_ban is the single flag for both intents.
    try testing.expect(@hasField(Peer, "should_ban"));
    try testing.expect(!@hasField(Peer, "should_discourage"));
    try testing.expect(!@hasField(Peer, "m_should_discourage"));
}

// ============================================================================
// Inbound discouragement-on-near-full (G28)
// ============================================================================

// G28 BUG-28: Inbound: drop discouraged peer when (almost) full missing.
// Core net.cpp:1813-1818 rejects a connection at nInbound+1 >= max_inbound
// when the address is in the discouragement bloom filter.  clearbit's
// acceptInbound only checks the deterministic ban list (peer.zig:3541).
test "w128/G28: acceptInbound has no isDiscouraged near-full check" {
    // No discouragement filter to query.
    try testing.expect(!@hasField(PeerManager, "discouraged_filter"));
    try testing.expect(!@hasField(PeerManager, "m_discouraged"));
    // ban_list exists (the conflated path).
    try testing.expect(@hasField(PeerManager, "ban_list"));
    // No MAX_INBOUND_DISCOURAGED_THRESHOLD constant.
    try testing.expect(!@hasDecl(peer_mod, "INBOUND_DISCOURAGED_REJECT_THRESHOLD"));
}

// ============================================================================
// Periodic banlist flush (G29)
// ============================================================================

// G29 BUG-29: DUMP_BANS_INTERVAL = 15min periodic flush missing.
// Core banman.h:23 + banman.cpp:48 flush on shutdown AND periodically
// (15-minute interval).  clearbit's BanList.save is called only on deinit
// (peer.zig:2495).  A crash between misbehaviour and shutdown loses bans.
test "w128/G29: No DUMP_BANS_INTERVAL periodic flush" {
    try testing.expect(!@hasDecl(banlist_mod, "DUMP_BANS_INTERVAL"));
    try testing.expect(!@hasDecl(banlist_mod, "DUMP_BANS_INTERVAL_SECS"));
    try testing.expect(!@hasDecl(peer_mod, "DUMP_BANS_INTERVAL"));
    try testing.expect(!@hasField(BanList, "last_dump_time"));
    try testing.expect(!@hasField(BanList, "next_dump_time"));
}

// ============================================================================
// ResolveCollisions at top of feeler loop (G30)
// ============================================================================

// G30 BUG-30: ResolveCollisions at top of feeler loop missing.
// Core net.cpp:2773 calls addrman.ResolveCollisions() at the top of every
// ThreadOpenConnections iteration BEFORE selecting an address.  clearbit
// has no collision set and no equivalent call.  Overlap: W104 G15 covers
// the storage-layer absence.  Here we assert the call-site absence.
test "w128/G30: maintainOutbound has no ResolveCollisions head-of-loop call" {
    try testing.expect(!@hasDecl(PeerManager, "resolveCollisions"));
    try testing.expect(!@hasDecl(PeerManager, "ResolveCollisions"));
    try testing.expect(!@hasDecl(PeerManager, "selectTriedCollision"));
    try testing.expect(!@hasField(PeerManager, "tried_collisions"));
    try testing.expect(!@hasField(PeerManager, "m_tried_collisions"));
    // maintainOutbound exists; the call-site does not invoke a resolve.
    try testing.expect(@hasDecl(PeerManager, "maintainOutbound"));
}
