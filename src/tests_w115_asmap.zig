//! W115 ASMap 30-gate fleet audit — clearbit (Zig 0.13)
//!
//! Reference: bitcoin-core/src/util/asmap.h/cpp, netgroup.h/cpp, addrman.cpp,
//!            init.cpp (-asmap arg), net.cpp (GetMappedAS, ASMapHealthCheck)
//!
//! VERDICT: PARTIALLY FIXED (FIX-50 + FIX-51)
//!
//! FIX-50 implemented: asmap.zig (Interpret trie, SanityCheckAsmap,
//!   CheckStandardAsmap, getMappedAS, loadAsmap), peer.zig (getMappedAS,
//!   addressToIPv6, getNetGroup, PeerManager.asmap_data, Peer.mapped_as,
//!   Config.asmap_path, --asmap CLI flag).
//!
//! FIX-51 implemented: AddrMan bucket hashing via PeerManager.getNetGroup()
//!   uses ASN-keyed group when asmap loaded; outbound ASN-diversity enforced
//!   via violatesNetgroupDiversity → getNetGroup → ASN.  Tests G8/G13/G22
//!   converted from bug-documentation to PASS verification.
//!
//! Still deferred:
//!   - `AddrMan` two-table (new/tried) with SipHash nKey (FIX-52)
//!   - asmap version in peers.dat (FIX-52)
//!   - `AsmapVersion` checksum (FIX-52)
//!   - `ASMapHealthCheck` periodic task
//!   - Embedded asmap fallback
//!
//! Gate results legend: PASS / BUG / MISSING ENTIRELY
//!
//! G1-G5   Config/load:   -asmap flag, file load, sanity check, version hash, embed
//! G6-G10  Data struct:   Interpret() trie, NetGroupManager, GetMappedAS(), ASN→group, fallback
//! G11-G15 AddrMan:       bucket key uses ASN, new/tried keyed by ASN, source group, eviction, mismatch
//! G16-G20 Sanity:        SanityCheckAsmap, MAX_ASMAP_FILESIZE, bit-LE encoding, reload, error path
//! G21-G24 Peer behavior: mapped_as getpeerinfo, netgroup diversity uses ASN, feeler, eclipse
//! G25-G28 Stats:         getnetworkinfo asmap field, ASMapHealthCheck, log, RPC asmap version
//! G29-G30 Persistence:   asmap version in peers.dat serialization, reindex/rebuild

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const main_mod = @import("main.zig");
const asmap_mod = @import("asmap.zig");

const PeerManager = peer_mod.PeerManager;
const AddressInfo = peer_mod.AddressInfo;
const Config = main_mod.Config;

// ============================================================================
// G1: -asmap CLI flag — FIX-50 IMPLEMENTED
// FIX: clearbit now has `asmap_path: ?[]const u8 = null` in Config and
//      parses `--asmap=<file>` / `-asmap=<file>` in parseArgs.
//
//      Core ref: bitcoin-core/src/init.cpp:540
//        argsman.AddArg("-asmap=<file>", "Specify asn mapping used for
//        bucketing of the peers.")
// ============================================================================
test "w115/G1: Config has asmap_path field (FIX-50)" {
    // FIX-50: asmap_path field now present and defaults to null.
    try testing.expect(@hasField(Config, "asmap_path"));
    // Default value is null (no asmap loaded).
    const cfg = Config{};
    try testing.expect(cfg.asmap_path == null);
}

// ============================================================================
// G2: DecodeAsmap / file loading — FIX-50 IMPLEMENTED
// FIX: PeerManager now has `asmap_data: ?[]u8 = null` and `src/asmap.zig`
//      provides `loadAsmap(allocator, path) ![]u8` with MAX_ASMAP_FILESIZE
//      guard and SanityCheckAsmap validation.
//
//      Core ref: bitcoin-core/src/util/asmap.cpp:DecodeAsmap()
// ============================================================================
test "w115/G2: PeerManager has asmap_data field (FIX-50)" {
    // FIX-50: asmap_data field now present and defaults to null.
    try testing.expect(@hasField(PeerManager, "asmap_data"));
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();
    // Default: no asmap loaded.
    try testing.expect(manager.asmap_data == null);
}

// ============================================================================
// G3: SanityCheckAsmap / CheckStandardAsmap absent
// BUG: Core validates asmap bytecode with `SanityCheckAsmap(data, 128)` and
//      `CheckStandardAsmap(data)` before use.  These guard against truncated,
//      malformed, or adversarially crafted trie files that could cause the
//      Interpret() walker to loop or misclassify peers.  clearbit has no
//      equivalent validation.
//
//      Core ref: bitcoin-core/src/util/asmap.h
//        bool SanityCheckAsmap(std::span<const std::byte> asmap, int bits);
//        bool CheckStandardAsmap(std::span<const std::byte> data);
// ============================================================================
test "w115/G3: no SanityCheckAsmap / CheckStandardAsmap function in peer module" {
    // These functions are MISSING ENTIRELY — no asmap validation in clearbit.
    const has_sanity = @hasDecl(peer_mod, "sanityCheckAsmap");
    const has_check = @hasDecl(peer_mod, "checkStandardAsmap");
    const has_validate = @hasDecl(peer_mod, "validateAsmap");
    try testing.expect(!has_sanity);
    try testing.expect(!has_check);
    try testing.expect(!has_validate);
}

// ============================================================================
// G4: AsmapVersion / checksum computation absent
// BUG: Core computes `AsmapVersion()` — a SHA256d hash over the raw asmap
//      bytes — to identify which asmap is in use, log it at startup, and
//      compare it against the version stored in peers.dat so stale cached
//      bucket assignments are invalidated when a new asmap is loaded.
//      clearbit performs none of this.
//
//      Core ref: bitcoin-core/src/util/asmap.cpp:AsmapVersion()
//        uint256 AsmapVersion(const std::span<const std::byte> data) { … }
// ============================================================================
test "w115/G4: no AsmapVersion / asmap checksum computation in peer module" {
    const has_version = @hasDecl(peer_mod, "asmapVersion");
    const has_hash = @hasDecl(peer_mod, "asmapHash");
    try testing.expect(!has_version);
    try testing.expect(!has_hash);
}

// ============================================================================
// G5: Embedded asmap fallback absent
// BUG: Core embeds a default asmap in the binary (`node::data::ip_asn`) and
//      activates it when `-asmap=1` is passed without a path (init.cpp:1612).
//      clearbit has no embedded asmap bytes and no activation logic.
//
//      Core ref: bitcoin-core/src/init.cpp:1612
//        std::span<const std::byte> asmap{node::data::ip_asn};
//        if (!asmap.empty() && CheckStandardAsmap(asmap))
//            node.netgroupman = WithEmbeddedAsmap(asmap);
// ============================================================================
test "w115/G5: Config has no use_embedded_asmap flag (embedded asmap absent)" {
    try testing.expect(!@hasField(Config, "use_embedded_asmap"));
    try testing.expect(!@hasField(Config, "asmap_embedded"));
}

// ============================================================================
// G6: Interpret() trie walker absent — MISSING ENTIRELY
// BUG: Core's `Interpret(asmap, ip)` (asmap.cpp) walks a variable-length
//      bit-packed binary trie to return the ASN for a 128-bit IPv6/mapped-IPv4
//      address.  This is the core algorithmic primitive.  clearbit has no trie
//      walker whatsoever; all IP-to-group mappings use raw prefix slicing.
//
//      Core ref: bitcoin-core/src/util/asmap.cpp
//        uint32_t Interpret(std::span<const std::byte> asmap,
//                           std::span<const std::byte> ip);
// ============================================================================
test "w115/G6: no Interpret() trie walker in peer module (core primitive absent)" {
    const has_interpret = @hasDecl(peer_mod, "interpretAsmap");
    const has_lookup = @hasDecl(peer_mod, "asmapLookup");
    const has_get_asn = @hasDecl(peer_mod, "getASN");
    try testing.expect(!has_interpret);
    try testing.expect(!has_lookup);
    try testing.expect(!has_get_asn);
}

// ============================================================================
// G7: NetGroupManager / GetMappedAS() — FIX-50 IMPLEMENTED
// FIX: `getMappedAS(asmap_data, address)` is now exported from peer.zig.
//      PeerManager.getNetGroup() uses ASN-keyed grouping when asmap is loaded.
//      PeerManager.asmap_data holds the loaded bytes.
//
//      Core ref: bitcoin-core/src/netgroup.h
//        uint32_t GetMappedAS(const CNetAddr& address) const;
// ============================================================================
test "w115/G7: getMappedAS available in peer module (FIX-50)" {
    // FIX-50: getMappedAS() is now exported from peer.zig.
    try testing.expect(@hasDecl(peer_mod, "getMappedAS"));
    // Returns 0 when asmap_data is empty.
    const addr = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333);
    try testing.expectEqual(@as(u32, 0), peer_mod.getMappedAS(&[_]u8{}, addr));
    // PeerManager has asmap_data field that feeds getNetGroup().
    try testing.expect(@hasField(PeerManager, "asmap_data"));
}

// ============================================================================
// G8: ASN-keyed GetGroup() — FIX-51 IMPLEMENTED
// FIX: PeerManager.getNetGroup(address) now returns the ASN as a u32 group
//      key when asmap is loaded (matching Core's NetGroupManager::GetGroup
//      which embeds the ASN in the returned byte vector).  Two addresses in
//      the same AS but different /16 prefixes now hash to the same bucket key.
//      The standalone `netGroup()` helper still returns /16 (used as fallback
//      when asmap is absent).
//
//      Core ref: bitcoin-core/src/netgroup.cpp:NetGroupManager::GetGroup()
//        if (asn != 0) {
//            vchRet.push_back(NET_IPV6);  // same ASN → same bucket
//            for (int i = 0; i < 4; i++) vchRet.push_back((asn >> (8*i)) & 0xFF);
//            return vchRet;
//        }
// ============================================================================
test "w115/G8: netGroup() raw /16 fallback + getNetGroup() uses ASN when asmap loaded (FIX-51)" {
    // --- Part A: standalone netGroup() still returns /16 (correct fallback) ---
    const addr1 = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 5, 6, 7, 8 }, 8333);
    const g1 = peer_mod.netGroup(addr1);
    const g2 = peer_mod.netGroup(addr2);
    // /16 of 1.2.x.x = (1<<8)|2 = 258
    try testing.expectEqual(@as(u32, 258), g1);
    // /16 of 5.6.x.x = (5<<8)|6 = 1286
    try testing.expectEqual(@as(u32, 1286), g2);
    try testing.expect(g1 != g2); // Different /16 → different group (correct)

    // --- Part B: getNetGroup() returns ASN when asmap is loaded ---
    // Using the Core reference test vector (bitcoin-core/src/test/netbase_tests.cpp).
    // 0000:1559:... and 00d0:d493:... both map to ASN 961340 in that asmap.
    const allocator = testing.allocator;
    const asmap_bytes = try asmap_mod.parseTestAsmapHex(allocator);
    defer allocator.free(asmap_bytes);

    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();
    // Wire the asmap into PeerManager.
    manager.asmap_data = try allocator.dupe(u8, asmap_bytes);

    // IPv6 address bytes for 0000:1559:0183:3728:224c:65a5:62e6:e991
    const ip_a = std.net.Address.initIp6(
        [16]u8{ 0x00, 0x00, 0x15, 0x59, 0x01, 0x83, 0x37, 0x28,
                0x22, 0x4c, 0x65, 0xa5, 0x62, 0xe6, 0xe9, 0x91 },
        8333, 0, 0,
    );
    // IPv6 address bytes for 00d0:d493:faa0:8609:e927:8b75:293c:f5a4
    const ip_b = std.net.Address.initIp6(
        [16]u8{ 0x00, 0xd0, 0xd4, 0x93, 0xfa, 0xa0, 0x86, 0x09,
                0xe9, 0x27, 0x8b, 0x75, 0x29, 0x3c, 0xf5, 0xa4 },
        8333, 0, 0,
    );

    const grp_a = manager.getNetGroup(ip_a);
    const grp_b = manager.getNetGroup(ip_b);

    // Both are in ASN 961340 → same group key (ASN-keyed bucketing).
    try testing.expectEqual(@as(u32, 961340), grp_a);
    try testing.expectEqual(@as(u32, 961340), grp_b);
    try testing.expectEqual(grp_a, grp_b); // Confirmed: same bucket

    // Their raw /16 groups differ (different first 2 octets) — confirming
    // that without asmap they would NOT have been grouped together.
    const raw_a = peer_mod.netGroup(ip_a);
    const raw_b = peer_mod.netGroup(ip_b);
    try testing.expect(raw_a != raw_b);
}

// ============================================================================
// G9: IPv4-in-IPv6 prefix handling absent in group computation
// BUG: Core's GetGroup treats IPv4-mapped IPv6 (::ffff:0:0/96) as IPv4,
//      returning a /16 prefix group for embedded IPv4 addresses.  With ASMap
//      active, the same 128-bit normalised representation (IPV4_IN_IPV6_PREFIX
//      + 4 IPv4 bytes) is passed to Interpret().  clearbit's netGroup() only
//      handles AF.INET / AF.INET6 by raw socket address — it does not handle
//      IPv4-mapped IPv6 as IPv4 for group purposes.
//
//      Core ref: bitcoin-core/src/netgroup.cpp
//        if (address.HasLinkedIPv4()) { return /16 of linked IPv4; }
// ============================================================================
test "w115/G9: netGroup IPv6 uses /32 raw prefix (no IPv4-mapped normalisation)" {
    // IPv4-mapped IPv6 ::ffff:1.2.3.4 → clearbit returns /32 of IPv6 octets,
    // not /16 of the embedded IPv4 as Core would for non-ASMap path.
    const ipv4_mapped = std.net.Address.initIp6(
        [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4 },
        8333, 0, 0,
    );
    const group = peer_mod.netGroup(ipv4_mapped);
    // clearbit returns /32 = first 4 bytes of IPv6: 0,0,0,0 → 0x00000000 = 0
    try testing.expectEqual(@as(u32, 0), group);
    // Core without asmap would return /16 of embedded IPv4 1.2.x.x = 258.
    // With asmap it would return ASN. Neither is implemented in clearbit.
}

// ============================================================================
// G10: Tor/I2P/CJDNS ASN-bypass absent (non-issue for missing feature)
// BUG: Core's GetMappedAS() returns 0 for Tor/I2P/CJDNS and falls through to
//      prefix-based grouping (netgroup.cpp:85: if net_class != IPv4 && != IPv6,
//      return 0).  clearbit's netGroup() returns 0 for unknown AF families.
//      This happens to be compatible for non-IP addresses, but the Tor/I2P
//      handling is moot since GetMappedAS itself is absent.
//
//      Core ref: bitcoin-core/src/netgroup.cpp:82
//        if (m_asmap.empty() || (net_class != NET_IPV4 && net_class != NET_IPV6))
//            return 0;
// ============================================================================
test "w115/G10: netGroup returns 0 for unknown AF (moot without ASMap)" {
    // For unknown address family clearbit returns 0; that matches Core's
    // fallthrough-to-zero for non-IPv4/IPv6 when asmap is absent.
    // When asmap IS loaded Core still returns 0 for Tor. Since asmap is
    // entirely absent in clearbit, this gate just documents current behavior.
    const unknown = std.net.Address{ .any = .{ .family = 99, .data = [_]u8{0} ** 14 } };
    const group = peer_mod.netGroup(unknown);
    try testing.expectEqual(@as(u32, 0), group);
}

// ============================================================================
// G11: AddrMan bucket hash does not use ASN
// BUG: Core's GetNewBucket(nKey, src, netgroupman) passes the ASN-derived
//      group vectors into the SipHash bucket key:
//        hash1 = Hash(nKey || GetGroup(addr) || GetGroup(src))
//      clearbit has no nKey, no two-table AddrMan, and no ASN-keyed hash.
//      The known_addresses flat map does not differentiate by AS membership.
//
//      Core ref: bitcoin-core/src/addrman.cpp:35-42
//        GetNewBucket(const uint256& nKey, const CNetAddr& src,
//                     const NetGroupManager& netgroupman) const
// ============================================================================
test "w115/G11: PeerManager has no new/tried tables keyed by ASN" {
    try testing.expect(!@hasField(PeerManager, "new_table"));
    try testing.expect(!@hasField(PeerManager, "tried_table"));
    // No nKey field → no cryptographic bucket hash
    try testing.expect(!@hasField(PeerManager, "nKey"));
    try testing.expect(!@hasField(PeerManager, "n_key"));
}

// ============================================================================
// G12: Source group (ASN of relayer) absent in bucket placement
// BUG: Core's new-table bucket number depends on the ASN of the SOURCE peer
//      (who relayed the addr), not just the destination address.  This ensures
//      that a single malicious AS cannot flood multiple buckets even if it
//      controls many /16 ranges across different ASes.  clearbit has no source
//      tracking in addAddress at all (no source param to bucket hash).
//
//      Core ref: bitcoin-core/src/addrman.cpp:35-42
//        uint64_t hash1 = (HashWriter{} << nKey
//                       << netgroupman.GetGroup(*this)    // addr group
//                       << vchSourceGroupKey).GetCheapHash(); // source group
// ============================================================================
test "w115/G12: addAddress does not accept source-ASN parameter" {
    // Core: AddrManImpl::Add takes a src CNetAddr that feeds GetGroup(src)
    // into the bucket hash for anti-eclipse.  clearbit's addAddress ignores
    // source identity entirely.
    const allocator = testing.allocator;
    var manager = PeerManager.init(allocator, &consensus.MAINNET);
    defer manager.deinit();

    // addAddress signature: (self, address, services, source: AddressSource)
    // No CNetAddr src parameter → source-ASN contribution absent.
    const addr = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333);
    try manager.addAddress(addr, p2p.NODE_NETWORK, .peer_addr);
    // At this point, the address is stored without any source-group hash.
    try testing.expectEqual(@as(usize, 1), manager.knownAddressCount());
}

// ============================================================================
// G13: violatesNetgroupDiversity uses ASN when asmap loaded — FIX-51 IMPLEMENTED
// FIX: `violatesNetgroupDiversity` delegates to `getNetGroup()` which returns
//      the ASN as the group key when asmap is loaded.  Two peers from the same
//      AS but different /16 prefixes now correctly share the same group key,
//      so the second peer is rejected as a diversity violation.
//
//      Without asmap: falls back to /16 prefix (same as before FIX-51).
//      With asmap:    uses ASN — same AS → same group → violation detected.
//
//      Core ref: bitcoin-core/src/net.cpp (connection diversification uses
//              netgroupman.GetGroup() which returns ASN-key when asmap loaded)
// ============================================================================
test "w115/G13: violatesNetgroupDiversity uses ASN when asmap loaded (FIX-51)" {
    const allocator = testing.allocator;
    const asmap_bytes = try asmap_mod.parseTestAsmapHex(allocator);
    defer allocator.free(asmap_bytes);

    // --- Without asmap: /16-based diversity (baseline / fallback) ---
    {
        var manager = PeerManager.init(allocator, &consensus.MAINNET);
        defer manager.deinit();

        // Two IPs from same AS but different /16s — without asmap they differ.
        const ip_a = std.net.Address.initIp6(
            [16]u8{ 0x00, 0x00, 0x15, 0x59, 0x01, 0x83, 0x37, 0x28,
                    0x22, 0x4c, 0x65, 0xa5, 0x62, 0xe6, 0xe9, 0x91 },
            8333, 0, 0,
        );
        const ip_b = std.net.Address.initIp6(
            [16]u8{ 0x00, 0xd0, 0xd4, 0x93, 0xfa, 0xa0, 0x86, 0x09,
                    0xe9, 0x27, 0x8b, 0x75, 0x29, 0x3c, 0xf5, 0xa4 },
            8333, 0, 0,
        );
        // Record ip_a as connected outbound (using getNetGroup → /16 fallback).
        manager.outbound_netgroups.put(manager.getNetGroup(ip_a), {}) catch unreachable;
        // ip_b is in a different /16 → no violation without asmap.
        try testing.expect(!manager.violatesNetgroupDiversity(ip_b));
    }

    // --- With asmap: ASN-based diversity (FIX-51 correct behavior) ---
    {
        var manager = PeerManager.init(allocator, &consensus.MAINNET);
        defer manager.deinit();
        manager.asmap_data = try allocator.dupe(u8, asmap_bytes);

        // Same two IPs — both map to ASN 961340.
        const ip_a = std.net.Address.initIp6(
            [16]u8{ 0x00, 0x00, 0x15, 0x59, 0x01, 0x83, 0x37, 0x28,
                    0x22, 0x4c, 0x65, 0xa5, 0x62, 0xe6, 0xe9, 0x91 },
            8333, 0, 0,
        );
        const ip_b = std.net.Address.initIp6(
            [16]u8{ 0x00, 0xd0, 0xd4, 0x93, 0xfa, 0xa0, 0x86, 0x09,
                    0xe9, 0x27, 0x8b, 0x75, 0x29, 0x3c, 0xf5, 0xa4 },
            8333, 0, 0,
        );
        // Record ip_a as connected outbound (getNetGroup → ASN 961340).
        manager.outbound_netgroups.put(manager.getNetGroup(ip_a), {}) catch unreachable;
        // ip_b is in the SAME AS (ASN 961340) → diversity violation detected.
        try testing.expect(manager.violatesNetgroupDiversity(ip_b));
    }
}

// ============================================================================
// G14: Eviction candidate scoring ignores ASN
// BUG: Core's SelectNodeToEvict / ProtectEvictionCandidatesByRatio uses
//      netgroup-based protection which, with ASMap, groups by ASN.  clearbit's
//      eviction (peer.zig:selectPeerToEvict) uses `net_group` which is the raw
//      /16 prefix returned by netGroup().  No ASN-based protection applies.
//
//      Core ref: bitcoin-core/src/net.cpp:ProtectEvictionCandidatesByRatio
// ============================================================================
test "w115/G14: EvictionCandidate net_group field holds /16 prefix, not ASN" {
    const addr = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333);
    // netGroup returns /16 = (1<<8)|2 = 258, not an ASN.
    const group = peer_mod.netGroup(addr);
    try testing.expectEqual(@as(u32, 258), group);
    // An ASN for this IP (e.g., AS13335 = Cloudflare) would be 13335.
    // clearbit uses 258, not 13335.
    try testing.expect(group != 13335);
}

// ============================================================================
// G15: DNS seed addresses not ASN-bucketed during initial population
// BUG: Core seeds AddrMan via DNS; the resolved addresses are added with the
//      source being the DNS server's address, whose ASN feeds GetGroup(src).
//      clearbit's dnsSeeds() calls addAddress with .dns_seed source enum,
//      which carries no source-ASN information.  The flat known_addresses map
//      does not perform ASN-keyed placement.
//
//      Core ref: bitcoin-core/src/addrman.cpp:AddSingle() — src feeds hash
// ============================================================================
test "w115/G15: DNS seeds stored in flat map, no ASN bucket placement" {
    // AddressSource.dns_seed has no IP/ASN information attached.
    // This confirms the source-group / ASN bucketing is absent for DNS seeds.
    const src = peer_mod.AddressSource.dns_seed;
    // dns_seed is just an enum tag — no associated CNetAddr for source ASN.
    try testing.expect(src == .dns_seed);
    // Contrast: Core's AddrManImpl::Add(vAddr, source) where source is a
    // full CNetAddr whose ASN is computed via netgroupman.GetGroup(source).
}

// ============================================================================
// G16: SanityCheckAsmap bit-format validation absent
// BUG: Core's SanityCheckAsmap validates the variable-length bit-packed
//      bytecode format (little-endian bit ordering, RETURN/JUMP/MATCH/DEFAULT
//      instructions) before allowing use.  Without it a malformed asmap file
//      could cause the Interpret() walker to read past the buffer end.
//      clearbit has no Interpret() and no sanity checker.
//
//      Core ref: bitcoin-core/src/util/asmap.cpp:SanityCheckAsmap()
// ============================================================================
test "w115/G16: no bit-LE-ordered trie decoder (sanity check target absent)" {
    // The absence of any asmap data field or Interpret() means no trie
    // bytecode is ever read — sanity check is structurally unreachable.
    try testing.expect(!@hasDecl(peer_mod, "sanityCheckAsmap"));
    try testing.expect(!@hasDecl(peer_mod, "interpretBits"));
    try testing.expect(!@hasDecl(peer_mod, "consumeBitLE"));
}

// ============================================================================
// G17: MAX_ASMAP_FILESIZE guard absent
// BUG: Core limits asmap files to 8 MiB (MAX_ASMAP_FILESIZE = 8 * 1024 * 1024
//      per comments and file-size check before reading).  clearbit has no such
//      constant or guard because there is no file loading at all.  If loading
//      were added naively without this guard, a 1 GB adversarial file could be
//      mapped into memory.
//
//      Core ref: bitcoin-core/src/init.cpp — asmap file path is guarded;
//               large asmap would OOM — 8 MiB is the practical upper bound.
// ============================================================================
test "w115/G17: no MAX_ASMAP_FILESIZE constant (file size guard absent)" {
    const has_const = @hasDecl(peer_mod, "MAX_ASMAP_FILESIZE");
    const has_main = @hasDecl(main_mod, "MAX_ASMAP_FILESIZE");
    try testing.expect(!has_const);
    try testing.expect(!has_main);
}

// ============================================================================
// G18: Asmap reload on SIGHUP absent
// BUG: Core schedules an ASMapHealthCheck every 24 hours (net.cpp:3570-3573)
//      and can reload the asmap on reconfiguration.  clearbit has no periodic
//      health check, no reload path, and no persistent reference to asmap bytes
//      that could be swapped at runtime.
//
//      Core ref: bitcoin-core/src/net.cpp:3570
//        scheduler.scheduleEvery([this] { ASMapHealthCheck(); },
//                                ASMAP_HEALTH_CHECK_INTERVAL);
// ============================================================================
test "w115/G18: PeerManager has no asmap_health_check_time / periodic reload" {
    try testing.expect(!@hasField(PeerManager, "last_asmap_health_check"));
    try testing.expect(!@hasField(PeerManager, "asmap_reload_path"));
    try testing.expect(!@hasDecl(peer_mod, "asmapHealthCheck"));
}

// ============================================================================
// G19: Error path on invalid asmap file absent (no file loading)
// BUG: Core emits InitError with a human-readable message when the asmap
//      file cannot be opened or fails sanity check (init.cpp:1598-1607).
//      clearbit has no error path because loading is absent entirely.
//      A future implementor could add loading without error handling.
//
//      Core ref: bitcoin-core/src/init.cpp:1597
//        InitError(_("Could not find asmap file %s"), path);
//        InitError(_("Could not parse asmap file %s"), path);
// ============================================================================
test "w115/G19: Config has no asmap_error field (error path absent)" {
    try testing.expect(!@hasField(Config, "asmap_error"));
    try testing.expect(!@hasField(Config, "asmap_load_failed"));
}

// ============================================================================
// G20: Version mismatch invalidation absent
// BUG: On startup Core compares the asmap version stored in peers.dat against
//      the currently-loaded asmap's AsmapVersion() hash.  When they differ
//      (new asmap deployed), cached bucket positions are recomputed for all
//      stored addresses.  clearbit has neither peers.dat nor asmap versioning,
//      so no invalidation is possible.
//
//      Core ref: bitcoin-core/src/addrman.cpp:313-349
//        uint256 supplied_asmap_version{m_netgroupman.GetAsmapVersion()};
//        … if (supplied_asmap_version != serialized_asmap_version) {
//            … rebucket all addresses with new asmap …
// ============================================================================
test "w115/G20: no asmap_version / rebucket-on-mismatch logic in PeerManager" {
    try testing.expect(!@hasField(PeerManager, "asmap_version"));
    try testing.expect(!@hasDecl(peer_mod, "rebucketOnAsmapChange"));
}

// ============================================================================
// G21: mapped_as in getpeerinfo RPC response — FIX-50 IMPLEMENTED
// FIX: Peer struct now has `mapped_as: u32 = 0`.  getpeerinfo handler emits
//      `"mapped_as": <asn>` for every peer (0 when asmap is not loaded or
//      the ASN is unknown).  Mirrors Core's net.cpp:3813.
//
//      Core ref: bitcoin-core/src/net.cpp:3813
//        vstats.back().m_mapped_as = GetMappedAS(pnode->addr);
// ============================================================================
test "w115/G21: Peer struct has mapped_as field (FIX-50)" {
    // FIX-50: Peer struct now has mapped_as field.
    try testing.expect(@hasField(peer_mod.Peer, "mapped_as"));
    // Default value is 0 (no asmap loaded).
    const dummy = peer_mod.Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333),
        .direction = .outbound,
        .state = .connecting,
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
        .allocator = testing.allocator,
        .recv_buffer = std.ArrayList(u8).init(testing.allocator),
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
    };
    try testing.expectEqual(@as(u32, 0), dummy.mapped_as);
}

// ============================================================================
// G22: Eclipse attack prevented by ASN grouping when asmap loaded — FIX-51
// FIX: With asmap loaded, `violatesNetgroupDiversity` uses `getNetGroup()` →
//      ASN-keyed group.  Two same-AS peers in different /16 prefixes now share
//      the same group key, so the second one is blocked as a diversity
//      violation.  Eclipse resistance is enforced at the AS level when asmap
//      is active.
//
//      Without asmap: /16-only (pre-FIX-51 behavior preserved as fallback).
//      With asmap:    same AS → same group → second peer rejected.
// ============================================================================
test "w115/G22: eclipse attack prevented with asmap — same-AS peers blocked (FIX-51)" {
    const allocator = testing.allocator;
    const asmap_bytes = try asmap_mod.parseTestAsmapHex(allocator);
    defer allocator.free(asmap_bytes);

    // --- Without asmap: eclipse possible (baseline documented behavior) ---
    // Two IPs in the same hypothetical AS but different /16s.
    // Use the Core test-vector addresses: both → ASN 961340, different /32 prefixes.
    const ip_a = std.net.Address.initIp6(
        [16]u8{ 0x00, 0x00, 0x15, 0x59, 0x01, 0x83, 0x37, 0x28,
                0x22, 0x4c, 0x65, 0xa5, 0x62, 0xe6, 0xe9, 0x91 },
        8333, 0, 0,
    );
    const ip_b = std.net.Address.initIp6(
        [16]u8{ 0x00, 0xd0, 0xd4, 0x93, 0xfa, 0xa0, 0x86, 0x09,
                0xe9, 0x27, 0x8b, 0x75, 0x29, 0x3c, 0xf5, 0xa4 },
        8333, 0, 0,
    );
    {
        var manager = PeerManager.init(allocator, &consensus.MAINNET);
        defer manager.deinit();
        // No asmap: /16 fallback — different /32 groups.
        manager.outbound_netgroups.put(manager.getNetGroup(ip_a), {}) catch unreachable;
        // Without asmap ip_b is in a different /32 → no violation (baseline).
        try testing.expect(!manager.violatesNetgroupDiversity(ip_b));
    }

    // --- With asmap: eclipse prevented (FIX-51 behavior) ---
    {
        var manager = PeerManager.init(allocator, &consensus.MAINNET);
        defer manager.deinit();
        manager.asmap_data = try allocator.dupe(u8, asmap_bytes);

        // ASN 961340 recorded for ip_a.
        manager.outbound_netgroups.put(manager.getNetGroup(ip_a), {}) catch unreachable;
        // ip_b shares ASN 961340 → diversity violation detected → eclipse blocked.
        try testing.expect(manager.violatesNetgroupDiversity(ip_b));
    }
}

// ============================================================================
// G23: Feeler connections not ASN-diversified
// BUG: Core's feeler connection logic calls GetGroup() (ASN-keyed when asmap
//      is loaded) to pick a tried-table candidate from an under-represented
//      ASN.  clearbit has no feeler connection type and no ASN-keyed tried
//      table, so feeler-based churn to improve AS diversity is absent.
//
//      Core ref: bitcoin-core/src/addrman.cpp (MakeTried, feeler selects
//               from tried bucket of specific ASN group)
// ============================================================================
test "w115/G23: PeerManager has no feeler connection type or ASN-tried-table churn" {
    // No FEELER connection type exists.
    try testing.expect(!@hasField(PeerManager, "feeler_address"));
    try testing.expect(!@hasDecl(peer_mod, "selectFeelerTarget"));
}

// ============================================================================
// G24: New-table key collision between IPv4 and IPv6 in same AS absent
// BUG: Core's GetGroup with ASMap returns the same key for an IPv4 address
//      and its mapped IPv6 counterpart when they share the same ASN.  This
//      prevents an attacker with both IPv4 and IPv6 addresses in one AS from
//      doubling their bucket presence.  clearbit's netGroup returns different
//      values for IPv4 vs IPv4-mapped IPv6 even when they share the same host.
//
//      Core ref: bitcoin-core/src/netgroup.cpp:26
//        vchRet.push_back(NET_IPV6); // IPv4 and IPv6 with same ASN use same bucket
// ============================================================================
test "w115/G24: IPv4 and IPv4-mapped IPv6 get different group keys (ASN collapse absent)" {
    const ipv4 = std.net.Address.initIp4([4]u8{ 1, 2, 3, 4 }, 8333);
    const ipv4_mapped = std.net.Address.initIp6(
        [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4 },
        8333, 0, 0,
    );
    const g_v4 = peer_mod.netGroup(ipv4);
    const g_v6 = peer_mod.netGroup(ipv4_mapped);
    // With ASMap both would share the same 5-byte ASN group key.
    // Without ASMap: IPv4 gets /16 = 258; IPv4-mapped IPv6 gets /32 = 0.
    try testing.expect(g_v4 != g_v6); // BUG: they should be equal when same ASN
}

// ============================================================================
// G25: getnetworkinfo does not report asmap field
// BUG: When asmap is loaded, bitcoin-cli getnetworkinfo-style tools can detect
//      this via the `mapped_as` field presence in peer listings.  Core's
//      getnetworkinfo could also be extended.  clearbit's handleGetNetworkInfo
//      (rpc.zig:3239) has no asmap-related field in its response.
//
//      Core ref: bitcoin-core/src/bitcoin-cli.cpp:563
//        m_is_asmap_on |= (mapped_as != 0);
// ============================================================================
test "w115/G25: getnetworkinfo JSON includes no asmap version or enabled flag" {
    // The structural prerequisite — asmap_version stored on PeerManager —
    // is absent, so the RPC handler cannot emit it.
    try testing.expect(!@hasField(PeerManager, "asmap_version_string"));
    try testing.expect(!@hasField(PeerManager, "asmap_enabled"));
}

// ============================================================================
// G26: ASMapHealthCheck absent (no periodic AS-diversity logging)
// BUG: Core schedules `ASMapHealthCheck()` every 24h (net.cpp:3570-3573).
//      It counts connected clearnet peers per ASN and how many are unmapped,
//      then logs "ASMap Health Check: N clearnet peers mapped to M ASNs with P
//      peers being unmapped."  clearbit never logs this information.
//
//      Core ref: bitcoin-core/src/netgroup.cpp:109
//        void NetGroupManager::ASMapHealthCheck(const vector<CNetAddr>&) const
// ============================================================================
test "w115/G26: no ASMapHealthCheck periodic task in PeerManager" {
    try testing.expect(!@hasField(PeerManager, "last_asmap_check_time"));
    try testing.expect(!@hasDecl(peer_mod, "runAsmapHealthCheck"));
}

// ============================================================================
// G27: No logging of asmap version at startup
// BUG: Core logs `"Using asmap version %s for IP bucketing"` at startup
//      (init.cpp:1628) so operators can verify which asmap is active.
//      clearbit logs no asmap information because asmap is entirely absent.
//
//      Core ref: bitcoin-core/src/init.cpp:1628
//        LogInfo("Using asmap version %s for IP bucketing", asmap_version)
// ============================================================================
test "w115/G27: Config has no asmap_log_version field (startup log absent)" {
    // No asmap_version field in Config means no startup log is possible.
    try testing.expect(!@hasField(Config, "asmap_version"));
    try testing.expect(!@hasField(Config, "log_asmap_version"));
}

// ============================================================================
// G28: RPC getpeerinfo column format for asmap consumers — FIX-50 IMPLEMENTED
// FIX: Peer struct has `mapped_as: u32 = 0`; getpeerinfo always emits the
//      field (0 when asmap not loaded).  Downstream tooling that parses
//      `mapped_as` from getpeerinfo will work correctly.
//
//      Core ref: bitcoin-core/src/bitcoin-cli.cpp:604-605
// ============================================================================
test "w115/G28: Peer struct has mapped_as field for RPC emission (FIX-50)" {
    // FIX-50: mapped_as is now present on Peer and emitted by getpeerinfo.
    try testing.expect(@hasField(peer_mod.Peer, "mapped_as"));
    // No extra aliased fields needed — single canonical mapped_as field.
    try testing.expect(!@hasField(peer_mod.Peer, "remote_asn"));
    try testing.expect(!@hasField(peer_mod.Peer, "asn_number"));
}

// ============================================================================
// G29: asmap version not serialized in peers.dat (persistence absent)
// BUG: Core writes the asmap version hash as the last field of peers.dat
//      (addrman.cpp:207: `s << m_netgroupman.GetAsmapVersion()`).  On reload
//      Core compares stored vs current asmap version and rebuckets all
//      addresses when they differ.  clearbit has no peers.dat serialization
//      and no asmap version field — the UTXO-set-equivalent for peer
//      addresses is entirely volatile.
//
//      Core ref: bitcoin-core/src/addrman.cpp:207
//        s << m_netgroupman.GetAsmapVersion();
// ============================================================================
test "w115/G29: PeerManager has no peers.dat path (persistence + asmap version absent)" {
    try testing.expect(!@hasField(PeerManager, "peers_dat_path"));
    try testing.expect(!@hasField(PeerManager, "asmap_version_hash"));
}

// ============================================================================
// G30: Rebucket / reindex on asmap change absent
// BUG: Core's AddrManImpl::Unserialize() detects asmap version change and
//      recomputes bucket assignments for all stored addresses (addrman.cpp:
//      347-349: "In case the new table data cannot be used (bucket count
//      wrong or new asmap), rebucket").  clearbit has no persisted addresses
//      and no ASN-keyed buckets, making this rebucket logic structurally
//      impossible to implement without first building AddrMan + asmap loader.
//
//      Core ref: bitcoin-core/src/addrman.cpp:347
//        bucket = info.GetNewBucket(nKey, m_netgroupman); // recompute
// ============================================================================
test "w115/G30: no rebucket / asmap-change reindex path in PeerManager" {
    try testing.expect(!@hasDecl(peer_mod, "rebucketAddresses"));
    try testing.expect(!@hasDecl(peer_mod, "reindexOnAsmapChange"));
    try testing.expect(!@hasField(PeerManager, "needs_rebucket"));
}
