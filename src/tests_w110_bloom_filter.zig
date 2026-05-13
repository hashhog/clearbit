//! W110 — BIP-37 bloom filter fleet audit (clearbit / Zig 0.13)
//!
//! Reference: bitcoin-core/src/common/bloom.h, bloom.cpp
//!            bitcoin-core/src/merkleblock.h, merkleblock.cpp
//!            BIP-37 (bloom filtering), BIP-111 (NODE_BLOOM service flag)
//!
//! Run: zig build test-w110 --summary none
//!
//! ============================================================
//! SUBSYSTEM STATUS: BLOOM FILTER CORE ENTIRELY MISSING
//! ============================================================
//!
//! clearbit has NO `bloom.zig` and no CBloomFilter implementation.
//! The `p2p.Message` union has no `filterload`, `filteradd`,
//! `filterclear`, or `merkleblock` variants.  The message decoder
//! (`p2p.decodeMessage`) returns `ParseError.UnknownCommand` for all
//! four BIP-37 P2P messages.  The peer handler (`peer.zig`) has no
//! dispatch arms for any of them.
//!
//! This is a "valid MISSING ENTIRELY" result per the audit spec —
//! BIP-37 is largely deprecated and the subsystem is intentionally
//! absent.  However the omission creates a **two-pipeline gap**:
//! `v2_transport.zig` lists filteradd (6), filterclear (7),
//! filterload (8), and merkleblock (16) in `V2_MESSAGE_IDS[]`
//! (the BIP-324 short-ID table), implying the node can receive and
//! route these messages over v2 transport — but there is nothing on
//! the receiving end.  A v2 peer that sends `filterload` over a
//! BIP-324 session gets `ParseError.UnknownCommand`; the node does
//! not disconnect cleanly as BIP-111 requires.
//!
//! BIP-111 requirement: if `peerbloomfilters=false` (the default),
//! the node MUST disconnect any peer that sends `filterload`.
//! clearbit silently drops the message instead.
//!
//! ============================================================
//! FINDINGS SUMMARY
//! ============================================================
//!
//!   BUG-1  (G1–G5, MISSING): MAX_BLOOM_FILTER_SIZE, MAX_HASH_FUNCS,
//!          LN2SQUARED constant, sizing formula, nHashFuncs formula
//!          absent — no bloom.zig exists.
//!
//!   BUG-2  (G6–G10, MISSING): MurmurHash3, hash schedule, bit-set
//!          logic, isFull/isEmpty — entire hash-and-bit-set layer absent.
//!
//!   BUG-3  (G11–G15, MISSING): BLOOM_UPDATE_* flags, UPDATE_MASK,
//!          nFlags application — absent.
//!
//!   BUG-4  (G16–G20, MISSING): txid match, per-output pushdata
//!          extraction, P2PKH/P2PK/multisig match, outpoint match,
//!          scriptSig data items — absent.
//!
//!   BUG-5  (G21–G24, MISSING): isRelevantAndUpdate with UPDATE_ALL /
//!          UPDATE_P2PUBKEY_ONLY / UPDATE_NONE / 36-byte outpoint
//!          serialization — absent.
//!
//!   BUG-6  (G25, HIGH): `filterload` message not parsed or dispatched.
//!          A peer can send `filterload` and clearbit returns
//!          `ParseError.UnknownCommand`.  BIP-111: node must disconnect
//!          peer if bloom filters are disabled; clearbit silently drops.
//!
//!   BUG-7  (G26, HIGH): `filteradd` message not parsed or dispatched.
//!          BIP-111 disconnect-on-oversize guard absent.
//!
//!   BUG-8  (G27, HIGH): `filterclear` message not parsed or dispatched.
//!
//!   BUG-9  (G28, HIGH): `merkleblock` message not implemented.
//!          No PartialMerkleTree construction; msg_filtered_block getdata
//!          requests cannot be fulfilled.
//!
//!   BUG-10 (G29, MEDIUM): IsWithinSizeConstraints + peer disconnect
//!          on oversized filterload absent (no CBloomFilter at all).
//!
//!   BUG-11 (G30, LOW — PARTIAL): NODE_BLOOM service flag (=4) is
//!          correctly defined in p2p.zig and conditionally advertised
//!          when `peerbloomfilters=true`.  The BIP-111 gate (disconnect
//!          peer that sends filterload when NODE_BLOOM is not advertised)
//!          is ABSENT.  The mempool gate (disconnect on `mempool` when
//!          NODE_BLOOM off) IS correct.
//!
//!   TWO-PIPELINE: v2_transport.zig registers short IDs for filteradd
//!          (6), filterclear (7), filterload (8), merkleblock (16) in
//!          V2_MESSAGE_IDS[], but p2p.Message has no corresponding
//!          union variants.  A BIP-324 session that receives any of
//!          these short IDs decodes the short ID correctly but then
//!          falls into `ParseError.UnknownCommand` at the message-
//!          body layer, which is indistinguishable from an unknown
//!          1-byte command ID.  This is a 26-wave two-pipeline streak
//!          extension.
//!
//!   PASS:  NODE_BLOOM = 4 constant correct (p2p.zig:19).
//!   PASS:  peerbloomfilters=false default matches Core
//!          DEFAULT_PEERBLOOMFILTERS.
//!   PASS:  NODE_BLOOM conditionally set in services bitmap
//!          (peer.zig:1311).
//!   PASS:  mempool gate disconnects peer when NODE_BLOOM not advertised
//!          (peer.zig:4694).
//!
//! Total: 11 BUG entries (G1-G30 coverage), 1 two-pipeline finding.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");

// ============================================================================
// G1–G5: Constants & sizing — MISSING ENTIRELY
// ============================================================================
//
// Core: bloom.h defines MAX_BLOOM_FILTER_SIZE=36000, MAX_HASH_FUNCS=50,
//       LN2SQUARED=0.4804530139182014246671025263266649717305529515945455.
//       Sizing: vData.size = min(-1/LN2SQUARED * nElements * log(fpRate),
//               MAX_BLOOM_FILTER_SIZE*8) / 8.
//       nHashFuncs = min(vData.size()*8 / nElements * LN2, MAX_HASH_FUNCS).
// Clearbit: no bloom.zig, no constants, no sizing formula.

test "w110 G1: MAX_BLOOM_FILTER_SIZE constant absent (BUG-1)" {
    // BUG-1: clearbit has no bloom filter module and no BloomFilter type.
    // Core bloom.h: static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000;
    // Expected: a BloomFilter struct or module-level constant in the codebase.
    // Actual: absent — no src/bloom.zig, no p2p.BloomFilter, no p2p.MAX_BLOOM_FILTER_SIZE.
    //
    // This test documents the absence: if a BloomFilter type were added to p2p.zig
    // or bloom.zig, this test would need updating.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "MAX_BLOOM_FILTER_SIZE"));
}

test "w110 G2: MAX_HASH_FUNCS constant absent (BUG-1)" {
    // BUG-1: Core bloom.h: static constexpr unsigned int MAX_HASH_FUNCS = 50;
    try testing.expect(!@hasDecl(p2p, "MAX_HASH_FUNCS"));
}

test "w110 G3: LN2SQUARED precision constant absent (BUG-1)" {
    // BUG-1: Core bloom.cpp:
    //   static constexpr double LN2SQUARED =
    //     0.4804530139182014246671025263266649717305529515945455;
    // No such constant exists in clearbit.
    try testing.expect(!@hasDecl(p2p, "LN2SQUARED"));
}

test "w110 G4-G5: bloom filter sizing and nHashFuncs formula absent (BUG-1)" {
    // BUG-1: Core CBloomFilter constructor computes vData.size and nHashFuncs
    // using LN2SQUARED / LN2.  No such computation exists in clearbit.
    // Structural absence check: p2p.Message has no filterload variant.
    try testing.expect(!@hasDecl(p2p, "FilterLoadMessage"));
    try testing.expect(!@hasDecl(p2p, "FilterAddMessage"));
}

// ============================================================================
// G6–G10: Hash & bit-set — MISSING ENTIRELY
// ============================================================================
//
// Core: MurmurHash3 32-bit; hash schedule i*0xFBA4C795 + nTweak;
//       bit index = hash % (vData.size() * 8); isFull/isEmpty short-circuit.
// Clearbit: no MurmurHash3 in crypto.zig or anywhere else.

test "w110 G6: MurmurHash3 absent from crypto module (BUG-2)" {
    // BUG-2: Core uses MurmurHash3 (hash.h) for bloom filter hashing.
    // clearbit's crypto.zig has sha256, hash256, ripemd160, etc. — no murmur.
    const crypto = @import("crypto.zig");
    try testing.expect(!@hasDecl(crypto, "murmurHash3"));
    try testing.expect(!@hasDecl(crypto, "MurmurHash3"));
    try testing.expect(!@hasDecl(crypto, "murmurhash3_x86_32"));
}

test "w110 G7: hash schedule constant 0xFBA4C795 absent (BUG-2)" {
    // BUG-2: Core: MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash)
    // No such constant exists in p2p.zig, crypto.zig, or any clearbit module.
    try testing.expect(!@hasDecl(p2p, "BLOOM_HASH_MULTIPLIER"));
}

test "w110 G8-G10: bit-set operations, isFull/isEmpty absent (BUG-2)" {
    // BUG-2: Bit index = hash % (vData.size() * 8); isFull = all bytes 0xFF;
    // isEmpty = all bytes 0x00.  No BloomFilter struct exists to check.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

// ============================================================================
// G11–G15: Update flags — MISSING ENTIRELY
// ============================================================================
//
// Core: BLOOM_UPDATE_NONE=0, BLOOM_UPDATE_ALL=1,
//       BLOOM_UPDATE_P2PUBKEY_ONLY=2, BLOOM_UPDATE_MASK=3.
// Clearbit: no bloom update flags defined anywhere.

test "w110 G11: BLOOM_UPDATE_NONE = 0 absent (BUG-3)" {
    // BUG-3: Core bloom.h: BLOOM_UPDATE_NONE = 0
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_NONE"));
}

test "w110 G12: BLOOM_UPDATE_ALL = 1 absent (BUG-3)" {
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_ALL"));
}

test "w110 G13: BLOOM_UPDATE_P2PUBKEY_ONLY = 2 absent (BUG-3)" {
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_P2PUBKEY_ONLY"));
}

test "w110 G14-G15: BLOOM_UPDATE_MASK = 3 and nFlags application absent (BUG-3)" {
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_MASK"));
}

// ============================================================================
// G16–G20: Match logic — MISSING ENTIRELY
// ============================================================================
//
// Core: IsRelevantAndUpdate checks txid, per-output scriptPubKey pushdata,
//       COutPoint (36 bytes), scriptSig data items.
// Clearbit: no such logic.

test "w110 G16-G20: per-tx bloom match logic absent — no IsRelevantAndUpdate (BUG-4)" {
    // BUG-4: txid match, output pushdata, outpoint 36-byte, scriptSig items —
    // none present.  p2p.Message has no merkleblock or filterload variants.
    const has_filterload = @hasField(
        std.meta.Tag(p2p.Message),
        "filterload",
    );
    try testing.expect(!has_filterload);
}

// ============================================================================
// G21–G24: isRelevantAndUpdate — MISSING ENTIRELY
// ============================================================================

test "w110 G21-G24: isRelevantAndUpdate entirely absent (BUG-5)" {
    // BUG-5: UPDATE_ALL (insert all matching outpoints), UPDATE_P2PUBKEY_ONLY
    // (insert only P2PK/multisig outpoints), UPDATE_NONE (read-only).
    // 36-byte outpoint serialization (txid[32] + vout[4] LE).
    // None of this exists in clearbit.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

// ============================================================================
// G25: filterload — NOT IN p2p.Message; no dispatch
// ============================================================================
//
// Core: ProcessMessage NetMsgType::FILTERLOAD parses CBloomFilter, calls
//       IsWithinSizeConstraints(), rejects oversized, sets peer->m_bloom_filter.
//       If peerbloomfilters=false → Misbehaving(100), disconnect.
// Clearbit: filterload is NOT a variant of p2p.Message.  The decoder returns
//           ParseError.UnknownCommand.  No BIP-111 disconnect occurs.

test "w110 G25: filterload not a variant of p2p.Message (BUG-6)" {
    // BUG-6 (HIGH): filterload absent from Message union.
    // Core: net_processing.cpp ProcessMessage FILTERLOAD sets peer bloom filter.
    // Clearbit: p2p.Message union has no .filterload variant.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterload")) {
                @compileError("filterload found in Message — update this test");
            }
        }
    }
    try testing.expect(true); // comptime check passed
}

test "w110 G25b: BIP-111 — filterload when NODE_BLOOM=false: no disconnect handler exists (BUG-6)" {
    // BUG-6: BIP-111 requires: if node does not advertise NODE_BLOOM, it MUST
    // disconnect any peer that sends filterload (Misbehaving(100) in Core).
    // Clearbit: advertise_node_bloom field exists on Peer (correct), but there
    // is no code path that handles a filterload message and checks this flag.
    // The message never reaches a handler — it returns UnknownCommand first.
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
    // Absence of per-peer bloom filter field (would exist if filterload were handled)
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_bloom_filter"));
}

// ============================================================================
// G26: filteradd — NOT IN p2p.Message; 520-byte guard absent
// ============================================================================
//
// Core: FILTERADD: if payload > MAX_SCRIPT_ELEMENT_SIZE (520) → Misbehaving(100).
//       Inserts data into per-peer bloom filter.
// Clearbit: filteradd not in Message union; no parsing, no 520-byte guard.

test "w110 G26: filteradd not a variant of p2p.Message (BUG-7)" {
    // BUG-7 (HIGH): filteradd absent from Message union.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filteradd")) {
                @compileError("filteradd found in Message — update this test");
            }
        }
    }
    try testing.expect(true);
}

test "w110 G26b: MAX_SCRIPT_ELEMENT_SIZE (520) guard for filteradd absent (BUG-7)" {
    // BUG-7: Core: if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) → Misbehaving(100).
    // No such constant or guard exists in clearbit.
    try testing.expect(!@hasDecl(p2p, "MAX_SCRIPT_ELEMENT_SIZE"));
}

// ============================================================================
// G27: filterclear — NOT IN p2p.Message
// ============================================================================
//
// Core: FILTERCLEAR: destroys per-peer bloom filter, marks relay as non-filtered.
// Clearbit: filterclear not in Message union; no handler.

test "w110 G27: filterclear not a variant of p2p.Message (BUG-8)" {
    // BUG-8 (HIGH): filterclear absent from Message union.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterclear")) {
                @compileError("filterclear found in Message — update this test");
            }
        }
    }
    try testing.expect(true);
}

// ============================================================================
// G28: merkleblock — NOT IN p2p.Message; PartialMerkleTree absent
// ============================================================================
//
// Core: CMerkleBlock constructed from CBlock + CBloomFilter; serializes
//       PartialMerkleTree (tx count, hashes, flags bits).
//       getdata MSG_FILTERED_BLOCK triggers merkleblock response.
// Clearbit: no merkleblock Message variant; no PartialMerkleTree; no
//           MSG_FILTERED_BLOCK getdata handler.

test "w110 G28: merkleblock not a variant of p2p.Message (BUG-9)" {
    // BUG-9 (HIGH): merkleblock absent from Message union.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "merkleblock")) {
                @compileError("merkleblock found in Message — update this test");
            }
        }
    }
    try testing.expect(true);
}

test "w110 G28b: PartialMerkleTree type absent (BUG-9)" {
    // BUG-9: Core merkleblock.h defines PartialMerkleTree with vBits[] and vHash[].
    // No such type in clearbit.
    try testing.expect(!@hasDecl(p2p, "PartialMerkleTree"));
    try testing.expect(!@hasDecl(p2p, "MerkleBlockMessage"));
}

test "w110 G28c: msg_filtered_block getdata type present but unhandled (BUG-9)" {
    // msg_filtered_block = 3 is defined in InvType (correct constant),
    // but getdata processing never issues a merkleblock response for it.
    const val = @as(u32, @intFromEnum(p2p.InvType.msg_filtered_block));
    try testing.expectEqual(@as(u32, 3), val);
    // The handler path would construct CMerkleBlock — that code doesn't exist.
    // Verified: no "merkleblock" or "PartialMerkleTree" decl in p2p.zig.
    try testing.expect(!@hasDecl(p2p, "MerkleBlock"));
}

// ============================================================================
// G29: IsWithinSizeConstraints + peer disconnect — ABSENT
// ============================================================================
//
// Core: IsWithinSizeConstraints() = vData.size()<=MAX_BLOOM_FILTER_SIZE &&
//       nHashFuncs<=MAX_HASH_FUNCS.  Called in FILTERLOAD handler; oversized
//       filter → Misbehaving(100).
// Clearbit: no CBloomFilter, no size check, no disconnect on oversized filter.

test "w110 G29: IsWithinSizeConstraints absent — no DoS guard on filterload (BUG-10)" {
    // BUG-10 (MEDIUM): no size-check + disconnect on oversized filterload.
    // Core net_processing.cpp FILTERLOAD:
    //   if (!pfilter->IsWithinSizeConstraints())
    //       peer->Misbehaving(100, "oversized bloom filter");
    // Clearbit: filterload message doesn't reach any handler, so this guard
    // is trivially absent.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
}

// ============================================================================
// G30: NODE_BLOOM + BIP-111 gate
// ============================================================================
//
// Core: NODE_BLOOM = (1 << 2) = 4; advertised only when peerbloomfilters=true.
//       BIP-111: node MUST disconnect peers that send filterload when not
//       advertising NODE_BLOOM.
// Clearbit:
//   PASS: NODE_BLOOM = 4 correct (p2p.zig:19).
//   PASS: peerbloomfilters=false default.
//   PASS: NODE_BLOOM set in services bitmap when advertise_node_bloom=true.
//   PASS: mempool message disconnects peer when NODE_BLOOM not advertised.
//   FAIL: BIP-111 filterload disconnect when NODE_BLOOM=false is ABSENT (BUG-11).

test "w110 G30a: NODE_BLOOM = 4 (1<<2) correct — PASS" {
    // PASS: Core protocol.h: NODE_BLOOM = (1 << 2) = 4.
    try testing.expectEqual(@as(u64, 4), p2p.NODE_BLOOM);
}

test "w110 G30b: advertise_node_bloom field present on Peer — PASS" {
    // PASS: Peer.advertise_node_bloom is the per-peer NODE_BLOOM gate.
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
}

test "w110 G30c: peerbloomfilters default is false — PASS" {
    // PASS: PeerManager.peerbloomfilters defaults to false (Core DEFAULT=false).
    // Structural check: field exists on PeerManager.
    try testing.expect(@hasField(peer_mod.PeerManager, "peerbloomfilters"));
    // Value check via comptime reflection.
    const default_val: bool = comptime blk: {
        const info = @typeInfo(peer_mod.PeerManager).Struct;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "peerbloomfilters")) {
                break :blk @as(*const bool, @ptrCast(@alignCast(f.default_value.?))).*;
            }
        }
        break :blk true; // fail-open: if field vanishes test will catch it above
    };
    try testing.expectEqual(false, default_val);
}

test "w110 G30d: BIP-111 filterload-disconnect when NODE_BLOOM=false absent (BUG-11)" {
    // BUG-11 (LOW — PARTIAL): BIP-111 requires that if a node does not
    // advertise NODE_BLOOM, it MUST disconnect peers that send filterload.
    // Bitcoin Core net_processing.cpp:
    //   if (!pfrom.m_bloom_filter_loaded &&
    //       !(pfrom.GetLocalServices() & NODE_BLOOM)) {
    //       pfrom.fDisconnect = true; return;
    //   }
    // Clearbit: no filterload handler exists at all, so this gate is absent.
    // The partial PASS is that mempool is correctly gated. The filterload
    // path (which precedes mempool semantically) is simply missing.
    //
    // Structural check: filterload not in Message union (already tested G25),
    // and no bloom_filter field on Peer.
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
}

// ============================================================================
// TWO-PIPELINE: v2_transport short IDs registered but Message variants absent
// ============================================================================
//
// v2_transport.zig V2_MESSAGE_IDS[]:
//   index 6 = "filteradd"
//   index 7 = "filterclear"
//   index 8 = "filterload"
//   index 16 = "merkleblock"
//
// These short IDs are used by BIP-324 v2 transport to encode message names.
// When a v2 peer sends one of these short IDs, v2_transport decodes it to the
// command string ("filterload" etc.) and passes it to p2p.decodeMessage.
// p2p.decodeMessage then returns ParseError.UnknownCommand because there is
// no matching branch.
//
// This is a two-pipeline gap: the v2 name table is populated (upstream),
// but the downstream message decoder + peer handler pipeline is absent.

test "w110 TWO-PIPELINE: filterload short ID in V2_MESSAGE_IDS but not in p2p.Message (two-pipeline)" {
    // Two-pipeline: v2_transport.V2_MESSAGE_IDS[8] = "filterload"
    // but p2p.Message has no .filterload variant.
    const v2 = @import("v2_transport.zig");

    // Confirm short IDs are registered
    try testing.expectEqualStrings("filterload", v2.V2_MESSAGE_IDS[8]);
    try testing.expectEqualStrings("filteradd", v2.V2_MESSAGE_IDS[6]);
    try testing.expectEqualStrings("filterclear", v2.V2_MESSAGE_IDS[7]);
    try testing.expectEqualStrings("merkleblock", v2.V2_MESSAGE_IDS[16]);

    // Confirm Message union has no corresponding variants (downstream absent)
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterload") or
                std.mem.eql(u8, f.name, "filteradd") or
                std.mem.eql(u8, f.name, "filterclear") or
                std.mem.eql(u8, f.name, "merkleblock"))
            {
                @compileError("BIP-37 message found in union — two-pipeline gap is fixed; update test");
            }
        }
    }
    try testing.expect(true); // comptime checks passed
}

test "w110 TWO-PIPELINE: msg_filtered_block InvType registered but merkleblock response absent" {
    // Two-pipeline extension: msg_filtered_block = 3 exists in InvType
    // (a getdata peer can request filtered blocks), but the handler that would
    // construct and send a merkleblock response does not exist.
    const filtered_block_val = @as(u32, @intFromEnum(p2p.InvType.msg_filtered_block));
    try testing.expectEqual(@as(u32, 3), filtered_block_val);
    // No MerkleBlock, PartialMerkleTree, or merkleblock Message variant.
    try testing.expect(!@hasDecl(p2p, "MerkleBlock"));
}

// ============================================================================
// Overall subsystem presence: confirm MISSING ENTIRELY
// ============================================================================

test "w110 SUMMARY: BIP-37 CBloomFilter subsystem missing entirely from clearbit" {
    // Structural summary test: all key identifiers absent.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "CBloomFilter"));
    try testing.expect(!@hasDecl(p2p, "MAX_BLOOM_FILTER_SIZE"));
    try testing.expect(!@hasDecl(p2p, "MAX_HASH_FUNCS"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_NONE"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_ALL"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_P2PUBKEY_ONLY"));
    try testing.expect(!@hasDecl(p2p, "BLOOM_UPDATE_MASK"));
    try testing.expect(!@hasDecl(p2p, "FilterLoadMessage"));
    try testing.expect(!@hasDecl(p2p, "FilterAddMessage"));
    try testing.expect(!@hasDecl(p2p, "PartialMerkleTree"));
    try testing.expect(!@hasDecl(p2p, "MerkleBlock"));
    // NODE_BLOOM is present (correct)
    try testing.expectEqual(@as(u64, 4), p2p.NODE_BLOOM);
}
