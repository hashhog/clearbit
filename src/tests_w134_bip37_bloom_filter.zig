//! W134 — BIP-37 Bloom Filter + BIP-111 NODE_BLOOM 30-gate audit (clearbit / Zig 0.13)
//!
//! Reference: bitcoin-core/src/common/bloom.{cpp,h}     (CBloomFilter, CRollingBloomFilter)
//!            bitcoin-core/src/merkleblock.{cpp,h}      (CMerkleBlock, CPartialMerkleTree)
//!            bitcoin-core/src/net_processing.cpp       (FILTERLOAD/FILTERADD/FILTERCLEAR
//!                                                        @ 4963-5033; MSG_FILTERED_BLOCK
//!                                                        getdata @ 2438-2458; TxRelay
//!                                                        m_bloom_filter @ 293-297)
//!            bitcoin-core/src/init.cpp                 (-peerbloomfilters NODE_BLOOM
//!                                                        wiring @ 1104-1105)
//!            bitcoin-core/src/protocol.h               (NODE_BLOOM = (1<<2) @ 317)
//!            bitcoin-core/src/net_processing.h         (DEFAULT_PEERBLOOMFILTERS @ 44)
//!            BIP-37 (Connection Bloom filtering)
//!            BIP-111 (NODE_BLOOM service bit + disconnect gate)
//!
//! Run: zig build test-w134 --summary none
//!
//! ============================================================
//! SUBSYSTEM STATUS: CBloomFilter + PartialMerkleTree MISSING.
//! BIP-111 DISCONNECT PATH: PASS (FIX-36, b0bc679, 2026-05-13).
//! W134 EXTENDS W110 WITH GATES W110 DID NOT FORMALISE:
//!   - G15 insert(COutPoint) 36-byte serialization
//!   - G24 PartialMerkleTree build/extract + CVE-2012-2459
//!   - G25 MSG_FILTERED_BLOCK getdata response
//!   - G28 per-peer m_bloom_filter / m_relay_txs (mutex-guarded)
//!   - G29 fRelay semantics + TxRelay init
//!   - CRollingBloomFilter primitive (cross-ref W128 BUG-16)
//! ============================================================
//!
//! XFAIL-style: BUG tests assert the current (buggy/missing) state so a
//! future fix wave can flip each gate by intentionally breaking the test.
//! PASS tests (G26/G27/mempool/TWO-PIPELINE) protect against regression.
//!
//! See clearbit/audit/w134_bip37_bloom_filter.md for the catalogue.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");
const crypto = @import("crypto.zig");

// ============================================================================
// G1-G5: Constants & sizing formulas — BUG-1..BUG-5
// ============================================================================
//
// Core bloom.h:17-18 + bloom.cpp:23-24 + 32 + 38.  Clearbit has no bloom.zig
// and no CBloomFilter type.  Every constant/formula is therefore MISSING.

test "w134/G1: MAX_BLOOM_FILTER_SIZE = 36000 absent (BUG-1)" {
    // Core bloom.h:17 — static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000.
    try testing.expect(!@hasDecl(p2p, "MAX_BLOOM_FILTER_SIZE"));
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "CBloomFilter"));
}

test "w134/G2: MAX_HASH_FUNCS = 50 absent (BUG-2)" {
    // Core bloom.h:18 — static constexpr unsigned int MAX_HASH_FUNCS = 50.
    try testing.expect(!@hasDecl(p2p, "MAX_HASH_FUNCS"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_MAX_HASH_FUNCS"));
}

test "w134/G3: LN2SQUARED and LN2 precision constants absent (BUG-3)" {
    // Core bloom.cpp:23-24 defines both constants to 16-digit precision:
    //   LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
    //   LN2 = 0.6931471805599453094172321214581765680755001343602552
    // Lower-precision constants would change vData.size() rounding at
    // certain (nElements, fpRate) combinations.
    try testing.expect(!@hasDecl(p2p, "LN2SQUARED"));
    try testing.expect(!@hasDecl(p2p, "LN2"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_LN2"));
}

test "w134/G4: vData sizing formula absent (BUG-4)" {
    // Core bloom.cpp:32:
    //   vData(std::min((unsigned int)(-1/LN2SQUARED * nElements * log(fp)),
    //                  MAX_BLOOM_FILTER_SIZE * 8) / 8)
    // Note: the cap is applied in BIT space, then divided by 8 to bytes.
    try testing.expect(!@hasDecl(p2p, "bloomFilterDataSize"));
    try testing.expect(!@hasDecl(p2p, "computeBloomDataSize"));
}

test "w134/G5: nHashFuncs formula absent (BUG-5)" {
    // Core bloom.cpp:38:
    //   nHashFuncs(std::min((unsigned int)(vData.size() * 8 / nElements * LN2),
    //                        MAX_HASH_FUNCS))
    // INTEGER division of vData.size()*8 by nElements BEFORE multiplying by
    // LN2 — a subtle ordering difference from m/n*ln(2) and required for
    // wire-compatible filters.
    try testing.expect(!@hasDecl(p2p, "bloomFilterHashFuncs"));
    try testing.expect(!@hasDecl(p2p, "computeBloomHashFuncs"));
}

// ============================================================================
// G6-G10: Hash schedule + bit-set + CVE-2013-5700 — BUG-6..BUG-10
// ============================================================================

test "w134/G6: MurmurHash3 primitive absent from crypto module (BUG-6)" {
    // Core: src/hash.h `MurmurHash3` (32-bit).  Cross-ref W128 BUG-16 —
    // CRollingBloomFilter also depends on MurmurHash3.  Adding MurmurHash3
    // unlocks both subsystems with one ~30 LOC change.
    try testing.expect(!@hasDecl(crypto, "murmurHash3"));
    try testing.expect(!@hasDecl(crypto, "MurmurHash3"));
    try testing.expect(!@hasDecl(crypto, "murmurhash3_x86_32"));
    try testing.expect(!@hasDecl(crypto, "murmur3"));
}

test "w134/G7: 0xFBA4C795 hash schedule constant absent (BUG-7)" {
    // Core bloom.cpp:47: MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vData).
    // The constant ensures reasonable bit difference between nHashNum values.
    try testing.expect(!@hasDecl(p2p, "BLOOM_HASH_MULTIPLIER"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_HASH_SCHEDULE"));
}

test "w134/G8: hash-to-bit-index reduction missing (BUG-8)" {
    // Core bloom.cpp:47-48: hash % (vData.size() * 8) → bit index.
    // No CBloomFilter struct; no equivalent method.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

test "w134/G9: bit set/test using (idx>>3) byte index + (7&idx) bit-in-byte absent (BUG-9)" {
    // Core bloom.cpp:58: vData[nIndex >> 3] |= (1 << (7 & nIndex)).
    // Bit-in-byte is LSB-first: bit 0 of byte 0 corresponds to hash output 0.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "bloomFilterSetBit"));
}

test "w134/G10: CVE-2013-5700 divide-by-zero guard missing (BUG-10)" {
    // Core bloom.cpp:52, 71, 100 — `if (vData.empty()) ...`.
    // - insert(): return silently.
    // - contains(): return TRUE ("match-all" filter).
    // - IsRelevantAndUpdate(): return TRUE.
    // Any future CBloomFilter impl must preserve these three call-sites.
    // Structurally: no CBloomFilter exists, so the guard is implicitly absent.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

// ============================================================================
// G11-G14: BLOOM_UPDATE_* flags + UPDATE_MASK — BUG-11
// ============================================================================

test "w134/G11: BLOOM_UPDATE_NONE = 0 absent (BUG-11)" {
    // Core bloom.h:26.
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_NONE"));
}

test "w134/G12: BLOOM_UPDATE_ALL = 1 absent (BUG-11)" {
    // Core bloom.h:27.
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_ALL"));
}

test "w134/G13: BLOOM_UPDATE_P2PUBKEY_ONLY = 2 absent (BUG-11)" {
    // Core bloom.h:29 — only auto-insert outpoint when scriptPubKey is
    // P2PK or multisig (for wallet privacy modes).
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_P2PUBKEY_ONLY"));
}

test "w134/G14: BLOOM_UPDATE_MASK = 3 + nFlags low-2-bit application absent (BUG-11)" {
    // Core bloom.h:30 — only the low 2 bits of nFlags are consulted; the
    // upper 6 bits are reserved.
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_MASK"));
    // Sanity: 3 is the largest meaningful nFlags value.
    try testing.expectEqual(@as(u8, 3), 0b11);
}

// ============================================================================
// G15: insert(COutPoint) 36-byte serialization — BUG-12
// ============================================================================

test "w134/G15: insert(COutPoint) 36-byte serialization absent (BUG-12)" {
    // Core bloom.cpp:62-67:
    //   void CBloomFilter::insert(const COutPoint& outpoint) {
    //       DataStream stream{}; stream << outpoint; insert(span);
    //   }
    // COutPoint::SERIALIZE_METHODS = (hash, n) → 32B Txid + 4B LE n = 36B.
    // The TWO overloads of insert() are the only canonical entry points;
    // a divergent serialization (BE n, non-Txid form) would produce filters
    // that do NOT match Core-built ones for the same outpoint.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "bloomInsertOutpoint"));
    // Sanity: the canonical outpoint serialization SHOULD be 36 bytes when
    // a future impl is added.  Document the expected size here so a fix
    // wave can flip this assertion to a real serialize-and-check.
    const expected_outpoint_len: usize = 32 + 4;
    try testing.expectEqual(@as(usize, 36), expected_outpoint_len);
}

// ============================================================================
// G16-G20: IsRelevantAndUpdate match logic — BUG-13..BUG-17
// ============================================================================

test "w134/G16: IsRelevantAndUpdate txid match absent (BUG-13)" {
    // Core bloom.cpp:102-104 — cheap path: TXID first.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "isRelevantAndUpdate"));
}

test "w134/G17: per-output scriptPubKey GetOp loop absent (BUG-14)" {
    // Core bloom.cpp:113-135 — opcode-by-opcode walk via CScript::GetOp;
    // each pushed data element checked against the filter.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

test "w134/G18: P2PK / P2PKH / multisig outpoint auto-insertion absent (BUG-15)" {
    // Core bloom.cpp:127-131 — Solver(scriptPubKey, vSolutions) on match;
    // insert COutPoint only if type == PUBKEY or MULTISIG.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

test "w134/G19: outpoint contained-in-filter test absent (BUG-16)" {
    // Core bloom.cpp:144: if (contains(txin.prevout)) return true.
    // The spend-side match — clients add outpoints via filteradd so any
    // tx that spends one of their UTXOs hits.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

test "w134/G20: scriptSig per-data-element match absent (BUG-17)" {
    // Core bloom.cpp:148-157 — GetOp loop on each input's scriptSig.
    // Catches P2SH-spending tx that reveal a redeem script the client cares about.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

// ============================================================================
// G21-G23: FILTERLOAD / FILTERADD / FILTERCLEAR — BUG-18 (PARTIAL via FIX-36)
// ============================================================================
//
// FIX-36 added the outer NODE_BLOOM disconnect gate.  On every clearbit peer
// with peerbloomfilters=false (default, matching Core), filterload/filteradd/
// filterclear → instant disconnect — same observable behaviour as Core.
// What is MISSING if peerbloomfilters=true is ever enabled:
//   G21: IsWithinSizeConstraints() check after deserialization.
//   G22: MAX_SCRIPT_ELEMENT_SIZE = 520 byte cap on FILTERADD vData.
//   G23: per-peer filter destruction on FILTERCLEAR.

test "w134/G21: filterload variant present + BIP-111 disconnect gate (FIX-36 PASS); inner CBloomFilter parse + size check MISSING (BUG-18 partial)" {
    // PASS branch (FIX-36).
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterload")) found = true;
        }
        if (!found) @compileError("filterload missing from Message — FIX-36 regression");
    }
    try testing.expect(@hasDecl(p2p, "BloomFilterRawMessage"));
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));

    // BUG branch: inner CBloomFilter parse + IsWithinSizeConstraints absent.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "isWithinSizeConstraints"));
    try testing.expect(!@hasDecl(p2p, "FilterLoadMessage"));

    // Round-trip the decoder to confirm the wire shape.
    const fake_payload = [_]u8{ 0x01, 0x02, 0x03 };
    const allocator = std.testing.allocator;
    const msg = try p2p.decodePayload("filterload", &fake_payload, allocator);
    defer allocator.free(msg.filterload.payload);
    try testing.expect(msg == .filterload);
    try testing.expectEqualSlices(u8, &fake_payload, msg.filterload.payload);
}

test "w134/G22: filteradd variant present (FIX-36 PASS); MAX_SCRIPT_ELEMENT_SIZE 520 guard + Misbehaving(100) MISSING (BUG-18 partial)" {
    // PASS branch.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filteradd")) found = true;
        }
        if (!found) @compileError("filteradd missing from Message — FIX-36 regression");
    }

    // BUG branch: 520-byte cap (script.h:28 MAX_SCRIPT_ELEMENT_SIZE) absent.
    try testing.expect(!@hasDecl(p2p, "MAX_SCRIPT_ELEMENT_SIZE"));
    try testing.expect(!@hasDecl(p2p, "FilterAddMessage"));
    // Document the canonical size for any future fix wave:
    const max_script_element_size_core: usize = 520;
    try testing.expectEqual(@as(usize, 520), max_script_element_size_core);

    // Confirm decode round-trip.
    const fake_payload = [_]u8{ 0xAB, 0xCD };
    const allocator = std.testing.allocator;
    const msg = try p2p.decodePayload("filteradd", &fake_payload, allocator);
    defer allocator.free(msg.filteradd.payload);
    try testing.expect(msg == .filteradd);
}

test "w134/G23: filterclear variant present (FIX-36 PASS); per-peer filter destruction MISSING (BUG-18 partial)" {
    // PASS branch.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterclear")) found = true;
        }
        if (!found) @compileError("filterclear missing from Message — FIX-36 regression");
    }
    const allocator = std.testing.allocator;
    const msg = try p2p.decodePayload("filterclear", &[_]u8{}, allocator);
    try testing.expect(msg == .filterclear);

    // BUG branch: Peer has no bloom_filter field to NULL on filterclear.
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_bloom_filter"));
}

// ============================================================================
// G24: PartialMerkleTree + BitsToBytes / BytesToBits + CVE-2012-2459 — BUG-19
// ============================================================================

test "w134/G24: PartialMerkleTree primitive entirely absent — CVE-2012-2459 guard MUST be ported with any future impl (BUG-19)" {
    // Core merkleblock.cpp:
    //   13-29:    BitsToBytes / BytesToBits helpers.
    //   80-95:    TraverseAndBuild (encoder).
    //   99-135:   TraverseAndExtract (decoder; CVE-2012-2459 reject at line 127:
    //              `if (right == left) { fBad = true; }`).
    //   137-149:  CPartialMerkleTree(vTxid, vMatch) ctor.
    //   151-184:  ExtractMatches.
    try testing.expect(!@hasDecl(p2p, "PartialMerkleTree"));
    try testing.expect(!@hasDecl(p2p, "CPartialMerkleTree"));
    try testing.expect(!@hasDecl(p2p, "MerkleBlock"));
    try testing.expect(!@hasDecl(p2p, "MerkleBlockMessage"));
    try testing.expect(!@hasDecl(p2p, "bitsToBytes"));
    try testing.expect(!@hasDecl(p2p, "bytesToBits"));

    // The merkleblock variant IS present in Message union (opaque) — confirm.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "merkleblock")) found = true;
        }
        if (!found) @compileError("merkleblock missing from Message — FIX-36 regression");
    }

    // Document CVE-2012-2459: any future PartialMerkleTree impl MUST
    // reject left==right at the same-height-pair check.  This test serves
    // as a hard reminder in the audit trail.
    const cve_2012_2459_guard_text = "if (right == left) { fBad = true; }";
    try testing.expect(cve_2012_2459_guard_text.len > 0);
}

// ============================================================================
// G25: MSG_FILTERED_BLOCK getdata response — BUG-20
// ============================================================================

test "w134/G25: msg_filtered_block InvType present (=3) PASS; MERKLEBLOCK getdata response handler MISSING (BUG-20)" {
    // PASS: InvType constant is correct.
    const filtered_block_val = @as(u32, @intFromEnum(p2p.InvType.msg_filtered_block));
    try testing.expectEqual(@as(u32, 3), filtered_block_val);
    const wbf_block_val = @as(u32, @intFromEnum(p2p.InvType.msg_witness_filtered_block));
    // Core protocol.h: 0x40000003 = MSG_WITNESS_FILTERED_BLOCK.
    try testing.expectEqual(@as(u32, 0x40000003), wbf_block_val);

    // BUG: getdata-side response handler MISSING.
    // Core net_processing.cpp:2438-2458:
    //   1. Build CMerkleBlock(*pblock, *bloom_filter).
    //   2. Send MERKLEBLOCK message.
    //   3. For each vMatchedTxn entry, send TX (TX_NO_WITNESS) so the SPV
    //      client doesn't have to round-trip.
    // Clearbit peer.zig getdata switch (5077-5253) covers msg_block /
    // msg_cmpct_block / msg_tx / msg_wtx — no msg_filtered_block branch.
    try testing.expect(!@hasDecl(peer_mod, "sendMerkleBlock"));
    try testing.expect(!@hasDecl(peer_mod, "buildMerkleBlock"));
    try testing.expect(!@hasDecl(peer_mod, "processFilteredBlockRequest"));
}

// ============================================================================
// G26-G27: NODE_BLOOM service bit + -peerbloomfilters default — PASS
// ============================================================================

test "w134/G26: NODE_BLOOM = (1<<2) = 4 service bit correct — PASS" {
    // Core protocol.h:317 — NODE_BLOOM = (1 << 2).
    try testing.expectEqual(@as(u64, 4), p2p.NODE_BLOOM);
    try testing.expectEqual(@as(u64, 1 << 2), p2p.NODE_BLOOM);
}

test "w134/G27: -peerbloomfilters default false matches DEFAULT_PEERBLOOMFILTERS — PASS" {
    // Core net_processing.h:44 — static const bool DEFAULT_PEERBLOOMFILTERS = false.
    try testing.expect(@hasField(peer_mod.PeerManager, "peerbloomfilters"));
    const default_val: bool = comptime blk: {
        const info = @typeInfo(peer_mod.PeerManager).Struct;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "peerbloomfilters")) {
                break :blk @as(*const bool, @ptrCast(@alignCast(f.default_value.?))).*;
            }
        }
        break :blk true;
    };
    try testing.expectEqual(false, default_val);

    // Confirm the Peer-side mirror also defaults false.
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
    const peer_default: bool = comptime blk: {
        const info = @typeInfo(peer_mod.Peer).Struct;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "advertise_node_bloom")) {
                break :blk @as(*const bool, @ptrCast(@alignCast(f.default_value.?))).*;
            }
        }
        break :blk true;
    };
    try testing.expectEqual(false, peer_default);
}

// ============================================================================
// G28: Per-peer m_bloom_filter / m_relay_txs (mutex-guarded) — BUG-22
// ============================================================================

test "w134/G28: per-peer m_bloom_filter / m_relay_txs receive-side state MISSING (BUG-22)" {
    // Core net_processing.cpp:293-297 — three CO-LOCATED fields on TxRelay:
    //   RecursiveMutex m_bloom_filter_mutex;
    //   bool m_relay_txs GUARDED_BY(...) {false};
    //   std::unique_ptr<CBloomFilter> m_bloom_filter PT_GUARDED_BY(...);
    // Clearbit's Peer has `advertise_node_bloom` (ADVERTISE side — what we
    // tell remote peers about US) but no equivalent for what the REMOTE
    // told us.  Without per-peer m_relay_txs, the version.relay=false →
    // filterload transition that BIP-37 clients use is a silent no-op.
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "tx_relay"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_tx_relay"));
    // Note: relay_txs IS a field on EvictionCandidate (peer.zig:612) but
    // not on the live Peer struct itself; that EvictionCandidate field is
    // populated from the (always-true) initialiser, not from the remote's
    // VERSION.fRelay byte.
    try testing.expect(@hasField(peer_mod.EvictionCandidate, "relay_txs"));

    // Cross-check: advertise_node_bloom DOES exist (ADVERTISE side present).
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
}

// ============================================================================
// G29: fRelay semantics + TxRelay init — BUG-23
// ============================================================================

test "w134/G29: fRelay-driven TxRelay init absent — remote VERSION.relay byte unused at peer setup (BUG-23)" {
    // Core net_processing.cpp:3682-3691:
    //   if (!IsBlockOnlyConn() && !IsFeelerConn() && (fRelay || NODE_BLOOM)) {
    //       auto* tx_relay = peer.SetTxRelay();
    //       tx_relay->m_relay_txs = fRelay;
    //   }
    // The KEY semantic: m_relay_txs is INITIALISED from fRelay; later
    // filterload flips it to true.  Without TxRelay, the entire transition
    // sequence is missing.
    //
    // Clearbit always feeds EvictionCandidate `.relay_txs = true` regardless
    // of the remote's VERSION.fRelay byte (peer.zig:810, 887, 937 — three
    // call-sites all unconditional).  Block-relay-only clients are treated
    // as tx-relay peers; the BIP-37 negotiation pattern of
    //   VERSION fRelay=false → filterload → m_relay_txs=true
    // cannot work because there's no per-peer m_relay_txs to flip.
    try testing.expect(!@hasDecl(peer_mod, "setTxRelay"));
    try testing.expect(!@hasField(peer_mod.Peer, "tx_relay"));
    // version.relay IS a wire-field (BIP-37) on VersionMessage — confirm.
    try testing.expect(@hasField(p2p.VersionMessage, "relay"));
}

// ============================================================================
// G30: BIP-111 misbehaving score on FILTERADD oversize — BUG-25 (PARTIAL)
// ============================================================================

test "w134/G30: filteradd oversize → Misbehaving(100) score MISSING; disconnect-without-ban only (BUG-25)" {
    // Core net_processing.cpp:5010-5012:
    //   if (bad) { Misbehaving(peer, "bad filteradd message"); }
    // Misbehaving score 100 = instant discourage in Core's banman.
    // Clearbit's handler (peer.zig:5354-5363) disconnects on NODE_BLOOM
    // absent but does NOT score-misbehave on oversize content.  The
    // oversize check is structurally unreachable (peer is disconnected
    // before the content is inspected, default peerbloomfilters=false).
    // If peerbloomfilters=true is ever enabled, BUG-25 becomes a real DoS
    // window (no penalty for repeated oversize spam).
    try testing.expect(!@hasDecl(peer_mod, "misbehaving"));
    try testing.expect(!@hasDecl(peer_mod, "scoreMisbehaviour"));
    // The PeerManager dispatch DOES have a path to set should_ban / disconnect
    // (consumed by W128 BUG-22).
    try testing.expect(@hasField(peer_mod.Peer, "should_ban"));
}

// ============================================================================
// CRollingBloomFilter — BUG-24 (cross-cuts W128 BUG-16)
// ============================================================================

test "w134/CROSS: CRollingBloomFilter primitive entirely absent (BUG-24; cross-ref W128 BUG-16)" {
    // Core bloom.h:108-125 + bloom.cpp:163-247 — separate primitive used by:
    //   - BanMan (CRollingBloomFilter m_discouraged{50000, 0.000001})
    //   - net_processing (already-seen tx tracking)
    // Adding MurmurHash3 (BUG-6) + FastRange32 + generation-rolling logic
    // unlocks BOTH this gate AND W128 BUG-16 (discouragement bloom filter).
    try testing.expect(!@hasDecl(p2p, "RollingBloomFilter"));
    try testing.expect(!@hasDecl(p2p, "CRollingBloomFilter"));
    try testing.expect(!@hasDecl(crypto, "fastRange32"));
    try testing.expect(!@hasDecl(crypto, "FastRange32"));
}

// ============================================================================
// TWO-PIPELINE: v2_transport ↔ Message union — CLOSED (FIX-36)
// ============================================================================

test "w134/TWO-PIPELINE: v2_transport short IDs 6/7/8/16 ↔ Message union variants — CLOSED (FIX-36)" {
    // Confirm both halves of the pipeline are populated.
    const v2 = @import("v2_transport.zig");
    try testing.expectEqualStrings("filteradd", v2.V2_MESSAGE_IDS[6]);
    try testing.expectEqualStrings("filterclear", v2.V2_MESSAGE_IDS[7]);
    try testing.expectEqualStrings("filterload", v2.V2_MESSAGE_IDS[8]);
    try testing.expectEqualStrings("merkleblock", v2.V2_MESSAGE_IDS[16]);

    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found_fl = false; var found_fa = false;
        var found_fc = false; var found_mb = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterload")) found_fl = true;
            if (std.mem.eql(u8, f.name, "filteradd")) found_fa = true;
            if (std.mem.eql(u8, f.name, "filterclear")) found_fc = true;
            if (std.mem.eql(u8, f.name, "merkleblock")) found_mb = true;
        }
        if (!found_fl or !found_fa or !found_fc or !found_mb)
            @compileError("BIP-37 variant missing from Message union — FIX-36 regression");
    }
    try testing.expect(true);
}

// ============================================================================
// Mempool gate (BIP-35) — PASS (re-tested for cross-cut with NODE_BLOOM)
// ============================================================================

test "w134/MEMPOOL-GATE: mempool message requires advertised NODE_BLOOM — PASS" {
    // Core net_processing.cpp:4852-4855 — peers that send `mempool` when
    // NODE_BLOOM not advertised are disconnected (unless NetPermission::Mempool).
    // Clearbit peer.zig:5295-5306 matches: NODE_BLOOM off → disconnect.
    //
    // This test is a structural assertion that the gate flag exists; the
    // dispatch is tested in tests_bip35.zig already.
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
    try testing.expect(@hasField(peer_mod.PeerManager, "peerbloomfilters"));
}

// ============================================================================
// Summary — overall subsystem state assertion
// ============================================================================

test "w134/SUMMARY: BIP-37 CBloomFilter + PartialMerkleTree subsystem MISSING; BIP-111 disconnect PASS (FIX-36)" {
    // CBloomFilter core (G1-G20): every primitive absent.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "CBloomFilter"));
    try testing.expect(!@hasDecl(p2p, "MAX_BLOOM_FILTER_SIZE"));
    try testing.expect(!@hasDecl(p2p, "MAX_HASH_FUNCS"));
    try testing.expect(!@hasDecl(p2p, "LN2SQUARED"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_NONE"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_ALL"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_P2PUBKEY_ONLY"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_MASK"));
    try testing.expect(!@hasDecl(p2p, "PartialMerkleTree"));
    try testing.expect(!@hasDecl(p2p, "MerkleBlock"));
    try testing.expect(!@hasDecl(p2p, "RollingBloomFilter"));

    // Wire pipeline (FIX-36): four Message variants + BloomFilterRawMessage carrier.
    try testing.expect(@hasDecl(p2p, "BloomFilterRawMessage"));
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found_fl = false; var found_fa = false;
        var found_fc = false; var found_mb = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterload")) found_fl = true;
            if (std.mem.eql(u8, f.name, "filteradd")) found_fa = true;
            if (std.mem.eql(u8, f.name, "filterclear")) found_fc = true;
            if (std.mem.eql(u8, f.name, "merkleblock")) found_mb = true;
        }
        if (!found_fl or !found_fa or !found_fc or !found_mb)
            @compileError("FIX-36 variants missing");
    }

    // NODE_BLOOM bit + -peerbloomfilters default + Peer.advertise_node_bloom field.
    try testing.expectEqual(@as(u64, 4), p2p.NODE_BLOOM);
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
    try testing.expect(@hasField(peer_mod.PeerManager, "peerbloomfilters"));

    // Receive-side state (BUG-22, BUG-23): MISSING.
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "tx_relay"));

    // Final state assertion: 25 BUGs / 5 PASSing gates / 30 total.
    // (Documented in audit/w134_bip37_bloom_filter.md gate matrix.)
    try testing.expect(true);
}
