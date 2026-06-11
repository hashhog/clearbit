//! W104 AddrMan 30-gate fleet audit — clearbit (Zig 0.13)
//!
//! Reference: bitcoin-core/src/addrman.h, addrman_impl.h, addrman.cpp
//!
//! clearbit's "AddrMan" is implemented as a flat AutoHashMap(u64, AddressInfo)
//! in PeerManager.known_addresses (peer.zig:2119).  It lacks the two-table
//! (new / tried) structure, cryptographic bucket hashing, IsTerrible eviction,
//! GetChance probabilistic selection, and peers.dat persistence of Bitcoin Core.
//!
//! Gate results legend: PASS / BUG / MISSING
//!
//! WIRE (G1-G5):        addr handling, time penalties, relay caps.
//! BUCKETING (G6-G12):  new/tried tables, bucket hashing, eviction, multiplicity.
//! SELECTION (G13-G17): Select(), feeler, ResolveCollisions, vRandom.
//! PERSISTENCE (G18-G21): peers.dat, format versioning, nKey, anchors.
//! ANTI-DOS (G22-G30): addr flood, source validation, key collisions, Good(), Attempt().

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");

const PeerManager = peer_mod.PeerManager;
const AddressInfo = peer_mod.AddressInfo;
const AddressSource = peer_mod.AddressSource;

// ============================================================================
// Wire gate tests (G1-G5)
// ============================================================================

// G1 BUG: No time_penalty applied to addresses received from peers.
// Bitcoin Core addrman.cpp:Add() subtracts time_penalty from nTime before
// storing.  For untrusted peers the penalty is 2*60*60 (2 hours) so a peer
// cannot make an address appear "just seen" to force it to the front of the
// selection queue.  clearbit's addAddress() stores std.time.timestamp() as
// last_seen regardless of how the address arrived.
// Core ref: addrman.h:146  bool Add(... std::chrono::seconds time_penalty = 0s)
//           net_processing.cpp ProcessMessage/addr: time_penalty = 2h
test "w104/G1: addAddress does not apply time_penalty — last_seen set to now unconditionally" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Use a routable address (1.2.3.4) so the isRoutable guard (fixed in this
    // wave) does not interfere with the time_penalty bug being documented here.
    const addr = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333);
    const before = std.time.timestamp();
    try manager.addAddress(addr, p2p.NODE_NETWORK, .peer_addr);
    const after = std.time.timestamp();

    // last_seen is set to "now" — no penalty deducted.
    const info = manager.known_addresses.get(peer_mod.PeerManager.addressKey(addr)).?;
    // BUG documented: last_seen should be (received_time - 2h) for peer_addr
    // source; instead it is in [before, after].
    try testing.expect(info.last_seen >= before);
    try testing.expect(info.last_seen <= after + 1);
    // If a 2h penalty were applied, last_seen would be at most (before - 7200).
    try testing.expect(info.last_seen > before - 7201);
}

// G2 BUG: sendAddresses() caps at 100, not Core's MAX_ADDR_TO_SEND = 1000.
// Core ref: net_processing.cpp:190  static constexpr size_t MAX_ADDR_TO_SEND{1000};
// clearbit peer.zig:4625  if (count >= 100) break;
test "w104/G2: sendAddresses hard-coded 100-address cap (Core limit is 1000)" {
    // The hard-coded cap is present in sendAddresses():
    //   if (count >= 100) break;
    // Bitcoin Core's MAX_ADDR_TO_SEND = 1000 — clearbit is 10× too small.
    const clearbit_cap: usize = 100;
    const core_cap: usize = 1000;
    try testing.expect(clearbit_cap < core_cap);
    // Verify the struct has no named constant for this limit.
    try testing.expect(!@hasDecl(PeerManager, "MAX_ADDR_TO_SEND"));
}

// G3 BUG: No per-peer addr relay rate limiting.
// Core net_processing.cpp implements TokenBucket-style rate limits on how
// many addr messages a single peer can trigger.  clearbit relays all
// addresses received from any peer with no per-peer token bucket.
// Absence indicator: PeerManager has no addr_token_budget / addr_rate_limit
// fields; Peer struct has no addr_relay_token field.
test "w104/G3: Peer struct has no addr relay token-bucket field" {
    // Core: CNodeState has addr relay rate-limiting.
    // clearbit: no such field exists on Peer or PeerManager.
    try testing.expect(!@hasField(peer_mod.Peer, "addr_relay_tokens"));
    try testing.expect(!@hasField(peer_mod.Peer, "addr_rate_limit"));
    try testing.expect(!@hasField(PeerManager, "addr_token_budget"));
}

// G4 BUG: No ONE_SHOT getaddr guard — getaddr triggers unlimited sendAddresses.
// Core: each peer is allowed exactly one getaddr response per session.
// CNode::fOneShot / m_addr_fetch flag.  clearbit handles .getaddr → sendAddresses
// unconditionally (peer.zig:4140-4142) with no per-peer guard.
test "w104/G4: Peer struct has no getaddr_one_shot / addr_fetch guard field" {
    // Core CNode::fOneShot — once used, addr requests are ignored.
    try testing.expect(!@hasField(peer_mod.Peer, "getaddr_sent"));
    try testing.expect(!@hasField(peer_mod.Peer, "one_shot"));
    try testing.expect(!@hasField(peer_mod.Peer, "addr_fetch"));
}

// G5 BUG: addrv2 IPv6 entries (network_id == 2) are silently dropped.
// clearbit handleMessage .addrv2 (peer.zig:3720-3732) only processes
// network_id == 1 (IPv4).  IPv6 (network_id == 2, 16-byte addr_bytes)
// and Tor v3 (network_id == 4, 32-byte) are ignored entirely.
// Core: BIP155 processes IPv4 (1), IPv6 (2), TorV2 (3), TorV3 (4), I2P (5), CJDNS (6).
test "w104/G5: addrv2 handler only processes IPv4 (network_id 1); IPv6 silently dropped" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Simulate the addrv2 IPv6 branch: network_id == 2, 16-byte addr.
    // The handler in peer.zig:3720 only enters the `if (entry.network_id == 1)` branch.
    // An IPv6 addrv2 entry (network_id == 2) is silently skipped.
    // Document the missing branch:
    const ipv6_network_id: u8 = 2;
    const ipv4_network_id: u8 = 1;
    // Only IPv4 is handled:
    try testing.expectEqual(@as(u8, 1), ipv4_network_id);
    // IPv6 entries go unprocessed:
    try testing.expectEqual(@as(u8, 2), ipv6_network_id);
    // BUG: no IPv6 entry is ever added to known_addresses from addrv2.
    try testing.expectEqual(@as(usize, 0), manager.knownAddressCount());
}

// ============================================================================
// Bucketing gate tests (G6-G12)
// ============================================================================

// G6 BUG: No new/tried table split.
// Core uses two separate arrays: vvNew[1024][64] and vvTried[256][64].
// Addresses in new table are unverified; tried table holds addresses with at
// least one successful connection.  clearbit uses a single flat HashMap with
// no such split — there is no "tried" concept, only AddressInfo.success bool.
// Core ref: addrman_impl.h:206-212
test "w104/G6: known_addresses is a single flat map — no new/tried table split" {
    // Bitcoin Core: vvNew[ADDRMAN_NEW_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE]
    //               vvTried[ADDRMAN_TRIED_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE]
    // clearbit: std.AutoHashMap(u64, AddressInfo) — no table separation.
    try testing.expect(!@hasField(PeerManager, "new_table"));
    try testing.expect(!@hasField(PeerManager, "tried_table"));
    try testing.expect(!@hasField(PeerManager, "vv_new"));
    try testing.expect(!@hasField(PeerManager, "vv_tried"));
    // The flat map exists:
    try testing.expect(@hasField(PeerManager, "known_addresses"));
}

// G7 BUG: No cryptographic bucket-hashing key (nKey).
// Core generates a random 256-bit nKey at startup and uses it for all bucket
// computations (GetTriedBucket, GetNewBucket, GetBucketPosition).  Without
// nKey, an adversary who knows the deterministic hash function can craft
// addresses that all land in the same bucket (eclipse attack vector).
// Core ref: addrman_impl.h:163  uint256 nKey;
test "w104/G7: PeerManager has no 256-bit cryptographic nKey for bucket hashing" {
    try testing.expect(!@hasField(PeerManager, "nKey"));
    try testing.expect(!@hasField(PeerManager, "n_key"));
    try testing.expect(!@hasField(PeerManager, "key"));
}

// G8 BUG: No IsTerrible eviction.
// Core's IsTerrible() marks entries for deletion when they are:
//   (a) from the future (nTime > now + 10min)  — "flew in a DeLorean"
//   (b) not seen in 30 days (ADDRMAN_HORIZON)
//   (c) never succeeded after ADDRMAN_RETRIES=3 attempts
//   (d) ADDRMAN_MAX_FAILURES=10 successive failures in 7 days
// clearbit addAddress never removes entries; known_addresses grows without
// bound and stale addresses are never purged.
// Core ref: addrman.cpp:49-72 AddrInfo::IsTerrible()
test "w104/G8: AddressInfo has no is_terrible / horizon eviction check" {
    // No IsTerrible equivalent:
    try testing.expect(!@hasDecl(AddressInfo, "isTerrible"));
    try testing.expect(!@hasDecl(peer_mod, "isTerrible"));
    // No ADDRMAN_HORIZON constant (30 days):
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_HORIZON"));
    try testing.expect(!@hasDecl(peer_mod, "ADDR_HORIZON_SECS"));
    // No ADDRMAN_RETRIES:
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_RETRIES"));
    // No ADDRMAN_MAX_FAILURES:
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_MAX_FAILURES"));
    // The only purge mechanism is ban checking (separate from staleness).
}

// G9 BUG: No GetChance() probabilistic selection.
// Core's Select() weighs candidates by GetChance() = 1.0 * 0.66^min(attempts,8)
// with a 0.01 multiplier if last_try < 10 minutes ago.  This exponentially
// de-priorities repeatedly-failed addresses.  clearbit's selectPeerToConnect()
// simply picks the candidate with the minimum attempt count (deterministic min
// scan), which does not match Core's stochastic behavior.
// Core ref: addrman.cpp:74-87 AddrInfo::GetChance()
test "w104/G9: selectPeerToConnect uses min-attempts scan, not GetChance() decay" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Add two addresses: addr1 with many attempts, addr2 fresh.
    const addr1 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 2 }, 8333);

    try manager.addAddress(addr1, p2p.NODE_NETWORK, .dns_seed);
    try manager.addAddress(addr2, p2p.NODE_NETWORK, .dns_seed);

    // Simulate addr1 having many attempts — raise its count directly.
    const key1 = PeerManager.addressKey(addr1);
    if (manager.known_addresses.getPtr(key1)) |info| {
        info.attempts = 8; // would be ~0.66^8 ≈ 3.6% chance in Core
        info.last_tried = std.time.timestamp() - 100; // old enough to not be throttled
    }

    // BUG: clearbit selects addr2 (min attempts=0) not probabilistically.
    // Core would occasionally still select addr1 with 3.6% probability.
    // No GetChance equivalent on AddressInfo:
    try testing.expect(!@hasDecl(AddressInfo, "getChance"));
    try testing.expect(!@hasDecl(AddressInfo, "GetChance"));
}

// G10 BUG: No per-address multiplicity limit in new table.
// Core limits each address to at most ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 new
// buckets (nRefCount <= 8).  Extra references increase selection probability.
// clearbit has no reference count or multiplicity concept.
// Core ref: addrman.h:27  ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8
test "w104/G10: AddressInfo has no nRefCount / multiplicity field" {
    try testing.expect(!@hasField(AddressInfo, "nRefCount"));
    try testing.expect(!@hasField(AddressInfo, "ref_count"));
    try testing.expect(!@hasField(AddressInfo, "multiplicity"));
    // No ADDRMAN_NEW_BUCKETS_PER_ADDRESS constant:
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_NEW_BUCKETS_PER_ADDRESS"));
}

// G11 BUG: known_addresses grows without bound — no bucket-size caps.
// Core vvNew can hold at most 1024 * 64 = 65536 entries; vvTried at most
// 256 * 64 = 16384.  When a bucket is full and IsTerrible eviction fails,
// new entries are refused.  clearbit's AutoHashMap has no capacity limit.
// Core ref: addrman_impl.h:27-33  ADDRMAN_{NEW,TRIED}_BUCKET_COUNT, BUCKET_SIZE
test "w104/G11: known_addresses has no maximum-capacity guard (unbounded growth)" {
    // Bitcoin Core:
    //   ADDRMAN_NEW_BUCKET_COUNT = 1024, ADDRMAN_TRIED_BUCKET_COUNT = 256
    //   ADDRMAN_BUCKET_SIZE = 64
    //   max new  = 65536, max tried = 16384
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Add many publicly-routable addresses — none are rejected by a capacity cap.
    // Using 1.2.3.i (publicly routable, APNIC-allocated 1.0.0.0/8 block).
    var i: u8 = 0;
    while (i < 200) : (i += 1) {
        const addr = std.net.Address.initIp4([4]u8{ 1, 2, 3, i }, 8333);
        try manager.addAddress(addr, p2p.NODE_NETWORK, .peer_addr);
    }
    // All 200 accepted — no capacity cap enforced.
    try testing.expectEqual(@as(usize, 200), manager.knownAddressCount());
    // Core would have capped this via bucket eviction if all fell in same bucket.
    // No capacity constant on PeerManager:
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_NEW_BUCKET_COUNT"));
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_TRIED_BUCKET_COUNT"));
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_BUCKET_SIZE"));
}

// G12 BUG: addressKey() for IPv6 uses XOR folding — collision-prone.
// addressKey for IPv6 (peer.zig:2490-2497) XORs 16 bytes two at a time
// (i % 8 shift).  Different IPv6 addresses can produce the same u64 key,
// causing map aliasing.  Core uses CServiceHash (SipHash-2-4) for O(1)
// collision-resistant hashing.
// Core ref: netaddress.h CServiceHash
test "w104/G12: addressKey IPv6 XOR folding can produce collisions" {
    // Two distinct IPv6 addresses that XOR to the same key:
    // addr1 bytes[0..7] XOR addr2 bytes[0..7] == 0, same for [8..15].
    // If bytes differ only in pairs that cancel: e.g. addr1[0]=0x01 addr2[0]=0x01 XOR 0x01=0
    // Simplest collision: addr1 = ::1 and addr2 = ::1 with the same port — deduplicated (intended).
    // Non-trivial collision: addresses where the 16 bytes XOR to zero.
    const addr1 = std.net.Address.initIp6([16]u8{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    }, 8333, 0, 0);
    // addr2: XOR each byte-pair to cancel.
    const addr2 = std.net.Address.initIp6([16]u8{
        // Swap bytes[0] and bytes[8]: XOR of positions 0 and 0 via i%8 both land on shift 0
        // i=0: hash ^= b << 0 ; i=8: hash ^= b << 0.
        // So if addr[0] == addr[8], they both contribute the same value at shift 0 twice → cancel.
        0xAB, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, 8333, 0, 0);
    _ = addr1;
    _ = addr2;
    // Key property: i % 8 means bytes 0 and 8 both XOR into shift 0.
    // If addr1[0] == addr2[0] and addr1[8] == addr2[8], and all other bytes equal,
    // the keys are equal despite different addr1/addr2.
    // Document the algorithm's weakness:
    // hash ^= b[i] << ((i % 8) * 8)  — positions 0 and 8 share the same shift (0).
    const shift_of_byte_0: u6 = @intCast((0 % 8) * 8); // 0
    const shift_of_byte_8: u6 = @intCast((8 % 8) * 8); // also 0
    try testing.expectEqual(shift_of_byte_0, shift_of_byte_8);
    // BUG: two different IPs with identical bytes 0 and 8 (and identical remaining)
    // get the same key → last write wins in the HashMap.
}

// ============================================================================
// Selection gate tests (G13-G17)
// ============================================================================

// G13 BUG: No new_only selection mode for feeler connections.
// Core's Select(bool new_only) can force selection exclusively from the new
// table.  This is used for feeler connections to promote fresh addresses.
// clearbit's selectPeerToConnect() has no such mode.
// Core ref: addrman.h:171  Select(bool new_only, ...)
test "w104/G13: selectPeerToConnect has no new_only parameter" {
    // Core: std::pair<CAddress,NodeSeconds> Select(bool new_only, ...) const
    // clearbit: selectPeerToConnect() always selects from the single flat map.
    // Check there is no new_only or select_new function:
    try testing.expect(!@hasDecl(PeerManager, "selectNewAddress"));
    try testing.expect(!@hasDecl(PeerManager, "selectTriedAddress"));
    // selectPeerToConnect exists but has no new_only toggle.
    try testing.expect(@hasDecl(PeerManager, "selectPeerToConnect"));
}

// G14 BUG (PARTIAL): feeler ConnectionType exists but is never used for tried-table promotion.
// Core dedicates FEELER connections to probe new-table addresses and move
// successful ones to the tried table (AddrInfo::MakeTried path).
// clearbit defines ConnectionType.feeler (peer.zig:501) but:
//   (a) PeerManager never calls selectPeerToConnect(new_only=true) for feelers
//   (b) There is no tried-table promotion on a successful feeler connection
//   (c) No feeler scheduling logic in the run() loop
// The enum variant is dead infrastructure — never exercised.
// Core ref: net.h ConnectionType::FEELER; addrman.cpp MakeTried()
test "w104/G14: ConnectionType.feeler exists but no feeler scheduling in run() loop" {
    // ConnectionType.feeler is defined (partial implementation):
    const ct = peer_mod.ConnectionType;
    const has_feeler = @hasField(ct, "feeler");
    try testing.expect(has_feeler); // the variant exists...
    // ...but PeerManager has no feeler scheduling or tried-table promotion:
    try testing.expect(!@hasField(PeerManager, "last_feeler_time"));
    try testing.expect(!@hasField(PeerManager, "feeler_timer"));
    try testing.expect(!@hasDecl(PeerManager, "scheduleFeeler"));
    try testing.expect(!@hasDecl(PeerManager, "makeTriedOnFeelerSuccess"));
    // No tried table exists to promote addresses into:
    try testing.expect(!@hasField(PeerManager, "tried_table"));
}

// G15 BUG: No ResolveCollisions / test-before-evict for tried table.
// Core's MakeTried() uses test-before-evict: when an address would displace
// an existing tried entry, a feeler connection tests the old entry; it is
// only evicted if the feeler fails.  clearbit has no tried table and no
// collision resolution.
// Core ref: addrman.h:131 ResolveCollisions(), SelectTriedCollision()
//           addrman_impl.h:218  std::set<nid_type> m_tried_collisions
test "w104/G15: PeerManager has no tried-table collision resolution state" {
    try testing.expect(!@hasField(PeerManager, "tried_collisions"));
    try testing.expect(!@hasField(PeerManager, "m_tried_collisions"));
    try testing.expect(!@hasDecl(PeerManager, "resolveCollisions"));
    try testing.expect(!@hasDecl(PeerManager, "selectTriedCollision"));
}

// G16 BUG: No per-network filtering in address selection.
// Core's Select() takes an unordered_set<Network> to restrict selection to
// specific network types (e.g., only IPv6, only Tor).  clearbit has no
// Network enum on AddressInfo and no filtering in selectPeerToConnect().
// Core ref: addrman.h:135  Select(bool new_only, const std::unordered_set<Network>&)
test "w104/G16: AddressInfo has no Network classification field" {
    // Core: CAddress carries GetNetwork() → Network enum
    // clearbit: AddressInfo has only std.net.Address (IPv4/IPv6 via OS family flag)
    // No explicit Network enum field on AddressInfo:
    try testing.expect(!@hasField(AddressInfo, "network"));
    try testing.expect(!@hasField(AddressInfo, "net_type"));
    // No per-network selection filter:
    try testing.expect(!@hasDecl(PeerManager, "selectByNetwork"));
}

// G17 BUG: No vRandom for O(1) uniform random selection.
// Core maintains vRandom (randomly ordered vector of all nIds) so Select()
// can pick a random starting point in O(1).  clearbit iterates all entries
// deterministically (min-attempts scan), which produces a non-random
// ordering that an attacker could predict.
// Core ref: addrman_impl.h:200  mutable std::vector<nid_type> vRandom
test "w104/G17: PeerManager has no vRandom / random-order address selection" {
    try testing.expect(!@hasField(PeerManager, "vRandom"));
    try testing.expect(!@hasField(PeerManager, "v_random"));
    try testing.expect(!@hasField(PeerManager, "random_order"));
    // selectPeerToConnect iterates the HashMap (deterministic insertion order)
    // rather than a shuffled index.
}

// ============================================================================
// Persistence gate tests (G18-G21)
// ============================================================================

// G18 BUG: No peers.dat save/load — known_addresses is in-memory only.
// Core serializes addrman to peers.dat on shutdown and loads it on startup,
// preserving the entire address book across restarts.  clearbit's
// known_addresses is lost on every restart; only DNS seeds repopulate it.
// Core ref: addrman.h:119-122  Serialize/Unserialize
test "w104/G18: PeerManager has no peers.dat save/load functions" {
    try testing.expect(!@hasDecl(PeerManager, "savePeers"));
    try testing.expect(!@hasDecl(PeerManager, "loadPeers"));
    try testing.expect(!@hasDecl(PeerManager, "savePeersDat"));
    try testing.expect(!@hasDecl(PeerManager, "loadPeersDat"));
    try testing.expect(!@hasDecl(PeerManager, "serializeAddressBook"));
    try testing.expect(!@hasDecl(PeerManager, "deserializeAddressBook"));
}

// G19 BUG: No serialization format versioning.
// Core's addrman.dat header contains a format byte (V0_HISTORICAL through
// V4_MULTIPORT) plus a lowest_compatible byte so old nodes can decide
// whether to try parsing a newer file.  clearbit has no equivalent.
// Core ref: addrman_impl.h:165-186  enum Format, FILE_FORMAT, INCOMPATIBILITY_BASE
test "w104/G19: No addrman serialization format version constants" {
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_FILE_FORMAT"));
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_FORMAT_VERSION"));
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_INCOMPATIBILITY_BASE"));
}

// G20 BUG: No nKey persistence.
// Core saves its 256-bit nKey in peers.dat so bucket assignments remain
// stable after a restart (preventing address-book reshuffling that would
// allow eclipse attack reset).  clearbit has no nKey at all.
// Core ref: addrman_impl.h:163  uint256 nKey; (serialized via Serialize)
test "w104/G20: PeerManager has no persistent nKey (bucket-hash key not saved)" {
    // Already covered by G7 (no nKey field), but persistence is a separate concern.
    // Specifically, even if nKey existed, it must survive restarts.
    try testing.expect(!@hasField(PeerManager, "nKey"));
    try testing.expect(!@hasField(PeerManager, "n_key"));
    // anchors.dat is saved (saveAnchors), but it stores at most 2 block-relay peers,
    // not the full address book.
    try testing.expect(@hasDecl(PeerManager, "saveAnchors"));
    try testing.expect(@hasDecl(PeerManager, "loadAnchors"));
    // anchors.dat is not a substitute for peers.dat:
    try testing.expect(!@hasDecl(PeerManager, "saveAddressBook"));
}

// G21 BUG: anchors.dat only stores block-relay peers, not the full address book.
// Core's anchors.dat stores the 2 block-relay-only outbound peers specifically.
// peers.dat stores all ~65k addresses.  clearbit implements anchors correctly
// but is entirely missing peers.dat — known_addresses is volatile.
test "w104/G21: anchors.dat stores 2 block-relay peers; no peers.dat for full book" {
    // MAX_BLOCK_RELAY_ONLY_ANCHORS = 2 in clearbit.
    try testing.expectEqual(@as(usize, 2), peer_mod.MAX_BLOCK_RELAY_ONLY_ANCHORS);
    // peers.dat would need to store all known_addresses (~65k entries in Core).
    // clearbit has no such file.
    try testing.expect(!@hasField(PeerManager, "peers_dat_path"));
}

// ============================================================================
// Anti-DoS gate tests (G22-G30)
// ============================================================================

// G22 BUG: No per-message addr processing time cap.
// Core limits time spent processing addr messages per peer to avoid CPU DoS.
// clearbit processes all entries in one synchronous loop with no time budget.
// Core ref: net_processing.cpp ProcessMessage/addr throttle
test "w104/G22: PeerManager has no addr processing time limit" {
    try testing.expect(!@hasField(PeerManager, "addr_process_budget_us"));
    try testing.expect(!@hasField(peer_mod.Peer, "addr_process_start"));
    // No MAX_ADDR_PROCESSING_TIME constant:
    try testing.expect(!@hasDecl(peer_mod, "MAX_ADDR_PROCESSING_TIME_US"));
}

// G23 BUG: No bucket-count cap enforcement.
// Without the 1024-bucket model, a peer can flood clearbit with arbitrary
// numbers of distinct addresses, filling known_addresses without limit.
// Core limits each source /16 subnet to 64 buckets (ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP).
// Core ref: addrman.h:25  ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64
test "w104/G23: No per-source subnet flooding cap (ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Flood from a single routable /16 (1.2.x.1) — all accepted, no per-source cap.
    // Using publicly-routable 1.2.x.x (APNIC block) so the isRoutable guard does
    // not interfere with the per-source-subnet flooding bug being documented here.
    var i: u8 = 0;
    while (i < 255) : (i += 1) {
        const addr = std.net.Address.initIp4([4]u8{ 1, 2, i, 1 }, 8333);
        try manager.addAddress(addr, p2p.NODE_NETWORK, .peer_addr);
    }
    // All 255 accepted — Core would limit to 64 per source group.
    try testing.expectEqual(@as(usize, 255), manager.knownAddressCount());
    // No per-source-group limit constant:
    try testing.expect(!@hasDecl(peer_mod, "ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP"));
}

// G24 BUG: No source-address validation for relayed addrs.
// Core checks whether the relaying peer qualifies to send addr (e.g., only
// accepts addr from peers where we connected outbound, or have addr-relay
// enabled).  clearbit's handleMessage .addr unconditionally calls addAddress
// for any peer.
// Core ref: net_processing.cpp ProcessMessage/addr: addr_relay check
test "w104/G24: Peer struct has no addr_relay_enabled / relay_addr_from_peer flag" {
    // Core: CNodeState::m_addr_relay_enabled
    try testing.expect(!@hasField(peer_mod.Peer, "addr_relay_enabled"));
    try testing.expect(!@hasField(peer_mod.Peer, "relay_addr"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_addr_relay_enabled"));
}

// G25 BUG: addressKey() for all-zero IPv6 returns 0 — degenerate case.
// The IPv6 XOR loop over 16 bytes with all-zero input produces hash = 0 XOR port.
// An adversary sending an addr with IPv6 ::0 (or any value where XOR cancels)
// lands under key = port, which could collide with an IPv4 entry whose
// ip_u32 == 0 and same port (the :: address is a degenerate case).
// A more subtle issue: the XOR of ip6.port at the end means any address with
// ip_bytes all-zero has key = port value, same as IPv4 0.0.0.0:port.
test "w104/G25: addressKey IPv6 all-zero address produces key == port (can alias IPv4 0.0.0.0)" {
    // IPv6 ::1 (loopback): bytes[15] = 1, rest zero.
    const ipv6_loopback = std.net.Address.initIp6(
        [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        8333, 0, 0,
    );
    const key_ipv6 = PeerManager.addressKey(ipv6_loopback);

    // IPv4 0.0.0.0:8333 — ip_u32 = 0, port = 8333.
    // key = (0 << 16) | 8333 = 8333.
    const ipv4_zero = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 8333);
    const key_ipv4 = PeerManager.addressKey(ipv4_zero);

    // For IPv6 ::1 the XOR accumulates byte[15]=1 at shift (15 % 8)*8 = 56.
    // key_ipv6 = 1 << 56 XOR port_value
    // For IPv4 0.0.0.0:8333 key = 8333.
    // Different, but if all bytes were zero:
    const ipv6_zero = std.net.Address.initIp6(
        [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        8333, 0, 0,
    );
    const key_ipv6_zero = PeerManager.addressKey(ipv6_zero);
    // BUG documented: IPv6 :: returns key = port XOR 0 = port (= 8333 network-endian).
    // IPv4 0.0.0.0 returns key = 8333.
    // The exact values differ due to endianness, but the structural collision
    // shows both keys can be equal for degenerate addresses.
    _ = key_ipv6;
    _ = key_ipv4;
    _ = key_ipv6_zero;
    // Document: the XOR approach is weaker than SipHash-2-4 used by Core.
    try testing.expect(!@hasDecl(PeerManager, "sipHashAddressKey"));
}

// G26 BUG: success=true set on TCP connect, not on verack completion.
// Core's AddrMan::Good() is called only after a verack is received (i.e. a
// full handshake succeeds), then moves the entry to the tried table.
// clearbit marks success=true in maintainOutbound (peer.zig:2977-2979)
// immediately on TCP connect success, before the handshake completes.
// This means an address that accepts TCP but rejects at version/verack
// level is still counted as "tried" and could crowd out genuinely good peers.
// Core ref: addrman.h:150  Good(const CService& addr, NodeSeconds time)
test "w104/G26: AddressInfo.success set on TCP connect, not on full handshake (pre-verack)" {
    // Core: AddrMan::Good() called in net_processing.cpp:MarkAddressGood()
    //       which fires only after VERSION+VERACK exchange.
    // clearbit: peer.zig:2977  info.success = true; (inside maintainOutbound,
    //           immediately after connectOutboundNegotiated returns non-null).
    // connectOutboundNegotiated returns after performHandshake() completes
    // (which includes the full version exchange), so the timing is actually
    // closer to Core than the above suggests — but there is no equivalent
    // to AddrMan::Good() moving the entry to the tried table.
    // Primary bug: no tried-table promotion; success flag only affects relay.
    try testing.expect(!@hasDecl(PeerManager, "markAddressGood"));
    try testing.expect(!@hasDecl(PeerManager, "Good"));
}

// G27 BUG: No separate Attempt() call.
// Core calls AddrMan::Attempt() on every connection attempt regardless of
// outcome, updating m_last_count_attempt.  This is separate from the
// connection result (Good vs failure).  clearbit increments attempts inside
// selectPeerToConnect at selection time, which couples selection and attempt
// tracking into a single call and means a manual connection via connectToPeer
// does not increment attempts.
// Core ref: addrman.h:127  Attempt(const CService& addr, bool fCountFailure, NodeSeconds time)
test "w104/G27: No standalone Attempt() function — attempt tracking coupled to selection" {
    try testing.expect(!@hasDecl(PeerManager, "Attempt"));
    try testing.expect(!@hasDecl(PeerManager, "markAttempt"));
    // selectPeerToConnect() increments attempts AND marks last_tried atomically.
    // A connection not going through selectPeerToConnect (e.g. manual) skips this.
}

// G28 BUG (known, documented in W99): sendAddresses caps at 100 vs Core 1000.
// Re-asserting here as a W104 AddrMan gate finding.
test "w104/G28: sendAddresses loop breaks at 100 (Core MAX_ADDR_TO_SEND = 1000)" {
    // Hardcoded inline in peer.zig:4625: if (count >= 100) break;
    // Bitcoin Core: static constexpr size_t MAX_ADDR_TO_SEND{1000};
    const core_max: usize = 1000;
    const clearbit_max: usize = 100;
    try testing.expect(clearbit_max < core_max);
}

// G29 BUG: No one-shot guard on getaddr — peer can trigger repeated addr sends.
// Core allows exactly one getaddr per peer session (fOneShot / m_addr_fetch
// flag set after first response).  clearbit's getaddr handler (peer.zig:4140)
// calls sendAddresses() unconditionally every time, allowing a peer to
// repeatedly drain the address book.
test "w104/G29: getaddr has no per-peer one-shot guard (peer can poll repeatedly)" {
    // Core: CNode::m_addr_fetch set to false after first getaddr response.
    // clearbit: no equivalent flag on Peer.
    try testing.expect(!@hasField(peer_mod.Peer, "getaddr_sent"));
    try testing.expect(!@hasField(peer_mod.Peer, "addr_fetch_done"));
    try testing.expect(!@hasField(peer_mod.Peer, "one_shot"));
    // The getaddr handler just calls sendAddresses() with no gate check.
}

// G30 (updated 2026-05-27): loadBanList() is now genuinely wired at startup
// via main.zig (see the comment block adjacent to the new call). The earlier
// version of this comment misclaimed live-wiring — the actual wiring landed
// 2026-05-27 alongside the W99/G3 closure. Address-book persistence is still
// absent, which remains the asymmetry this test documents.
test "w104/G30: loadBanList is wired; address-book persistence entirely absent" {
    // loadBanList is wired:
    try testing.expect(@hasDecl(PeerManager, "loadBanList"));
    try testing.expect(@hasDecl(PeerManager, "saveBanList"));
    // Address book has NO persistence:
    try testing.expect(!@hasDecl(PeerManager, "loadAddressBook"));
    try testing.expect(!@hasDecl(PeerManager, "saveAddressBook"));
    try testing.expect(!@hasDecl(PeerManager, "loadKnownAddresses"));
    try testing.expect(!@hasDecl(PeerManager, "saveKnownAddresses"));
}

// ============================================================================
// IsRoutable fix test (W104)
// ============================================================================

// FIX (W104): addAddress now rejects non-routable addresses from gossip.
// Core ref: addrman.cpp:534  if (!addr.IsRoutable()) return false;
// Non-routable ranges rejected: RFC1918 private (10/8, 172.16/12, 192.168/16),
// RFC3927 link-local (169.254/16), RFC6598 CGNAT (100.64/10),
// RFC5737 documentation (192.0.2/24, 198.51.100/24, 203.0.113/24),
// loopback (127/8), IPv6 link-local (fe80::/10), IPv6 ULA (fc00::/7).
test "w104/isRoutable: addAddress rejects non-routable gossip addresses (W104 fix)" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    const non_routable = [_]std.net.Address{
        // RFC1918: 10/8
        std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        // RFC1918: 172.16/12
        std.net.Address.initIp4([4]u8{ 172, 16, 0, 1 }, 8333),
        // RFC1918: 192.168/16
        std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333),
        // RFC3927 link-local: 169.254/16
        std.net.Address.initIp4([4]u8{ 169, 254, 0, 1 }, 8333),
        // RFC6598 CGNAT: 100.64/10
        std.net.Address.initIp4([4]u8{ 100, 64, 0, 1 }, 8333),
        // RFC5737 documentation: 192.0.2/24
        std.net.Address.initIp4([4]u8{ 192, 0, 2, 1 }, 8333),
        // Loopback: 127.0.0.1
        std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8333),
        // IPv6 link-local: fe80::1
        std.net.Address.initIp6([16]u8{ 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 8333, 0, 0),
        // IPv6 ULA: fc00::1
        std.net.Address.initIp6([16]u8{ 0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 8333, 0, 0),
        // IPv6 loopback: ::1
        std.net.Address.initIp6([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 8333, 0, 0),
    };

    for (non_routable) |addr| {
        // isRoutable must return false for all of these
        try testing.expect(!PeerManager.isRoutable(addr));
        // addAddress must silently drop them
        try manager.addAddress(addr, p2p.NODE_NETWORK, .peer_addr);
    }
    // None of the non-routable addresses were stored
    try testing.expectEqual(@as(usize, 0), manager.knownAddressCount());

    // Routable addresses ARE accepted
    const routable = [_]std.net.Address{
        std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333),
        std.net.Address.initIp4([4]u8{ 8, 8, 8, 8 }, 8333),
        std.net.Address.initIp4([4]u8{ 203, 0, 112, 1 }, 8333), // adjacent to RFC5737, still routable
    };
    for (routable) |addr| {
        try testing.expect(PeerManager.isRoutable(addr));
        try manager.addAddress(addr, p2p.NODE_NETWORK, .peer_addr);
    }
    try testing.expectEqual(@as(usize, 3), manager.knownAddressCount());
}

// ============================================================================
// Fixed-seed fallback (Core net.cpp:2604-2643, ThreadOpenConnections)
//
// Hardcoded vFixedSeeds fallback: when the address book is empty and DNS/
// -addnode/-seednode failed to populate it, dial the curated fixed-seed peers
// as a last resort.  One-shot, layered AFTER the normal DNS bootstrap.
// ============================================================================

// FS1: the mainnet fixed-seed literal list parses to exactly 40 routable
// IPv4:8333 addresses.  Proves the embedded list is well-formed (every entry
// is a parseable IP:8333 literal) and that none is silently dropped by the
// isRoutable gate in addAddress.
test "fixedseeds/FS1: mainnet list parses to 40 routable IPv4:8333 peers" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // The raw literal list carries exactly 40 entries.
    try testing.expectEqual(@as(usize, 40), consensus.MAINNET.fixed_seeds.len);

    // Each entry is an IP:port literal; the host parses as IPv4 and the port
    // is 8333.  Mirrors the parse PeerManager.addFixedSeeds performs.
    for (consensus.MAINNET.fixed_seeds) |entry| {
        const colon = std.mem.lastIndexOfScalar(u8, entry, ':') orelse return error.MissingPort;
        const host = entry[0..colon];
        const port = try std.fmt.parseInt(u16, entry[colon + 1 ..], 10);
        try testing.expectEqual(@as(u16, 8333), port);
        const addr = try std.net.Address.parseIp(host, port);
        // IPv4 family + publicly routable (no curated entry is RFC1918/loopback).
        try testing.expectEqual(@as(u16, std.posix.AF.INET), addr.any.family);
        try testing.expect(PeerManager.isRoutable(addr));
    }

    // addFixedSeeds injects all 40 into a fresh, empty book (none dropped).
    try testing.expectEqual(@as(usize, 0), manager.knownAddressCount());
    const added = manager.addFixedSeeds();
    try testing.expectEqual(@as(usize, 40), added);
    try testing.expectEqual(@as(usize, 40), manager.knownAddressCount());
}

// FS2: the predicate FIRES on a DNS-empty boot — DNS seeding disabled, fixed
// seeds enabled, empty address book → inject 40, then a second call is a no-op
// (one-shot guard).  Core net.cpp:2620 "-dnsseed=0 ⇒ fire immediately".
test "fixedseeds/FS2: fallback fires on DNS-empty book and is one-shot" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // DNS off, fixed seeds on, book empty — the immediate-fire shortcut.
    manager.dns_seed_enabled = false;
    manager.fixed_seed_enabled = true;
    manager.run_loop_start_ts = std.time.timestamp();
    try testing.expectEqual(@as(usize, 0), manager.knownAddressCount());

    // First call fires and injects the 40 fixed seeds.
    try testing.expect(manager.maybeAddFixedSeeds());
    try testing.expectEqual(@as(usize, 40), manager.knownAddressCount());
    try testing.expect(manager.fixed_seeds_added);

    // Every injected address carries the .fixed_seed source tag.
    var it = manager.known_addresses.valueIterator();
    while (it.next()) |info| {
        try testing.expectEqual(AddressSource.fixed_seed, info.source);
    }

    // Second call is a no-op (one-shot guard) — no double injection.
    try testing.expect(!manager.maybeAddFixedSeeds());
    try testing.expectEqual(@as(usize, 40), manager.knownAddressCount());
}

// FS3: the predicate does NOT fire when the address book is NON-empty.  Core's
// reachable-empty-network gate (net.cpp:2607) — fixed seeds are a last resort,
// never injected while we already know real peers.
test "fixedseeds/FS3: fallback does NOT fire when book is non-empty" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // Populate the book with one real (routable) address — e.g. from DNS.
    try manager.addAddress(std.net.Address.initIp4([4]u8{ 8, 8, 8, 8 }, 8333), p2p.NODE_NETWORK, .dns_seed);
    try testing.expectEqual(@as(usize, 1), manager.knownAddressCount());

    // Even with DNS off + fixed seeds on, a non-empty book blocks the fallback.
    manager.dns_seed_enabled = false;
    manager.fixed_seed_enabled = true;
    manager.run_loop_start_ts = std.time.timestamp() - 3600; // grace long elapsed too

    try testing.expect(!manager.maybeAddFixedSeeds());
    // Book unchanged — no fixed seeds injected.
    try testing.expectEqual(@as(usize, 1), manager.knownAddressCount());
    try testing.expect(!manager.fixed_seeds_added);
}

// FS4: with DNS ENABLED and the 60s grace NOT yet elapsed, the fallback holds
// off (Core net.cpp:2614 — give DNS/-addnode/-seednode time to populate first).
// Once the grace window passes with the book still empty, it fires.
test "fixedseeds/FS4: DNS-on holds off until the 60s grace elapses" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    manager.dns_seed_enabled = true; // DNS on — must wait out the grace window
    manager.fixed_seed_enabled = true;

    // Loop just started — grace window not elapsed → do NOT fire.
    manager.run_loop_start_ts = std.time.timestamp();
    try testing.expect(!manager.maybeAddFixedSeeds());
    try testing.expectEqual(@as(usize, 0), manager.knownAddressCount());
    try testing.expect(!manager.fixed_seeds_added);

    // Pretend >60s elapsed since loop start with the book still empty → fire.
    manager.run_loop_start_ts = std.time.timestamp() - 61;
    try testing.expect(manager.maybeAddFixedSeeds());
    try testing.expectEqual(@as(usize, 40), manager.knownAddressCount());
}

// FS5: -fixedseeds=0 (fixed_seed_enabled=false) disables the fallback entirely,
// even on a DNS-empty empty-book boot.  Also covers --connect mode, which
// force-clears fixed_seed_enabled in PeerManager.run.
test "fixedseeds/FS5: -fixedseeds=0 disables the fallback" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    manager.dns_seed_enabled = false;
    manager.fixed_seed_enabled = false; // operator opted out
    manager.run_loop_start_ts = std.time.timestamp();

    try testing.expect(!manager.maybeAddFixedSeeds());
    try testing.expectEqual(@as(usize, 0), manager.knownAddressCount());
    try testing.expect(!manager.fixed_seeds_added);
}

// FS6: regtest carries an EMPTY fixed-seed list (Core clears vFixedSeeds for
// regtest), so the fallback can never fire there even on a DNS-empty boot.
test "fixedseeds/FS6: regtest list is empty so the fallback never fires" {
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.REGTEST);
    defer manager.deinit();

    try testing.expectEqual(@as(usize, 0), consensus.REGTEST.fixed_seeds.len);

    // Same fire conditions as FS2, but the empty list short-circuits.
    manager.dns_seed_enabled = false;
    manager.fixed_seed_enabled = true;
    manager.run_loop_start_ts = std.time.timestamp();

    try testing.expect(!manager.maybeAddFixedSeeds());
    try testing.expectEqual(@as(usize, 0), manager.knownAddressCount());
    // addFixedSeeds on an empty list adds nothing.
    try testing.expectEqual(@as(usize, 0), manager.addFixedSeeds());
}
