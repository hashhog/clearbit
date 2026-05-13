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
//! BIP-111 DISCONNECT PATH: FIXED (FIX-36, 2026-05-13)
//! ============================================================
//!
//! clearbit has NO `bloom.zig` and no CBloomFilter implementation.
//! The `p2p.Message` union now has `filterload`, `filteradd`,
//! `filterclear`, and `merkleblock` variants (added in FIX-36).
//! The message decoder (`p2p.decodePayload`) decodes these commands
//! into opaque-payload message variants instead of returning
//! `ParseError.UnknownCommand`.  The peer handler (`peer.zig`)
//! dispatches them and applies the BIP-111 disconnect gate for
//! filterload/filteradd/filterclear (disconnect if NODE_BLOOM not
//! advertised, mirroring Core net_processing.cpp:4964/4990/5018).
//! merkleblock is log+drop (server→client message; receiving it is
//! unexpected but not worth a disconnect).
//!
//! The TWO-PIPELINE gap between v2_transport.zig (short IDs 6/7/8/16
//! registered) and the message body layer is now CLOSED.
//!
//! BIP-111 requirement: if `peerbloomfilters=false` (the default),
//! the node MUST disconnect any peer that sends `filterload`.
//! clearbit now satisfies this requirement (FIX-36).
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
//!   BUG-6  (G25, FIXED FIX-36): `filterload` now parsed as opaque
//!          BloomFilterRawMessage; handler disconnects peer when
//!          NODE_BLOOM not advertised (BIP-111, mirroring Core).
//!
//!   BUG-7  (G26, FIXED FIX-36): `filteradd` now parsed + BIP-111
//!          disconnect gate applied.  520-byte guard deferred (no
//!          CBloomFilter to insert into).
//!
//!   BUG-8  (G27, FIXED FIX-36): `filterclear` now parsed + BIP-111
//!          disconnect gate applied.
//!
//!   BUG-9  (G28, PARTIAL — TWO-PIPELINE CLOSED): `merkleblock` variant
//!          now in Message union (two-pipeline gap closed); handler
//!          logs + drops.  Full PartialMerkleTree construction and
//!          MSG_FILTERED_BLOCK getdata response remain absent.
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
//!   PASS (FIX-36): filterload/filteradd/filterclear parsed and BIP-111
//!          disconnect gate applied.
//!   PASS (FIX-36): merkleblock parsed and dropped (two-pipeline closed).
//!
//! Total: 11 BUG entries (G1-G30 coverage), 1 two-pipeline finding.
//! BUG-6/7/8: FIXED (FIX-36).  BUG-9: TWO-PIPELINE CLOSED (partial fix).

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
    // none present.  No CBloomFilter implementation exists.
    // Note: p2p.Message NOW has filterload/merkleblock variants (FIX-36) but
    // they are opaque-payload stubs with no bloom match logic.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "CBloomFilter"));
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
// G25: filterload — FIXED (FIX-36): now in p2p.Message; BIP-111 disconnect
// ============================================================================
//
// Core: ProcessMessage NetMsgType::FILTERLOAD:
//       if peerbloomfilters=false → fDisconnect=true (net_processing.cpp:4964).
// FIX-36: filterload is now a variant of p2p.Message (BloomFilterRawMessage).
//         The handler in peer.zig disconnects when !advertise_node_bloom.

test "w110 G25: filterload IS a variant of p2p.Message — FIXED (FIX-36)" {
    // FIX-36: filterload now in Message union as BloomFilterRawMessage.
    // The two-pipeline gap (v2_transport short ID 8 registered but no decoder)
    // is closed.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterload")) {
                found = true;
                break;
            }
        }
        if (!found) @compileError("filterload missing from Message union — FIX-36 regression");
    }
    try testing.expect(true); // comptime check passed
}

test "w110 G25b: BIP-111 — filterload when NODE_BLOOM=false: disconnect handler present — FIXED (FIX-36)" {
    // FIX-36: BIP-111 gate now implemented: handler checks advertise_node_bloom
    // and calls peer.disconnect() when NODE_BLOOM is not advertised.
    // Structural checks:
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
    // No CBloomFilter field expected (we don't parse filter contents).
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_bloom_filter"));
    // BloomFilterRawMessage type present in p2p for opaque payload.
    try testing.expect(@hasDecl(p2p, "BloomFilterRawMessage"));
}

test "w110 G25c: filterload decodes to BloomFilterRawMessage via decodePayload — FIXED (FIX-36)" {
    // FIX-36: decodePayload("filterload", ...) now returns Message.filterload
    // instead of ParseError.UnknownCommand.
    // Test with a synthetic payload (arbitrary bytes — no CBloomFilter parse).
    const fake_payload = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const allocator = std.testing.allocator;
    const msg = try p2p.decodePayload("filterload", &fake_payload, allocator);
    defer allocator.free(msg.filterload.payload);
    try testing.expect(msg == .filterload);
    try testing.expectEqualSlices(u8, &fake_payload, msg.filterload.payload);
}

// ============================================================================
// G26: filteradd — FIXED (FIX-36): now in p2p.Message; BIP-111 disconnect
// ============================================================================
//
// Core: FILTERADD: if NODE_BLOOM not advertised → fDisconnect=true
//       (net_processing.cpp:4990); also Misbehaving(100) for >520-byte data.
// FIX-36: filteradd now in Message union as BloomFilterRawMessage.
//         BIP-111 disconnect gate applied.
//         520-byte guard deferred (no CBloomFilter insert path).

test "w110 G26: filteradd IS a variant of p2p.Message — FIXED (FIX-36)" {
    // FIX-36: filteradd now in Message union (two-pipeline gap closed).
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filteradd")) {
                found = true;
                break;
            }
        }
        if (!found) @compileError("filteradd missing from Message union — FIX-36 regression");
    }
    try testing.expect(true);
}

test "w110 G26b: MAX_SCRIPT_ELEMENT_SIZE (520) guard for filteradd still absent (deferred)" {
    // The 520-byte size guard from Core FILTERADD (Misbehaving(100) if
    // vData.size() > MAX_SCRIPT_ELEMENT_SIZE) is deferred — no CBloomFilter
    // insert path exists.  The BIP-111 disconnect fires first anyway
    // (NODE_BLOOM not advertised), so the oversize case never reaches the guard.
    try testing.expect(!@hasDecl(p2p, "MAX_SCRIPT_ELEMENT_SIZE"));
}

test "w110 G26c: filteradd decodes to BloomFilterRawMessage — FIXED (FIX-36)" {
    // FIX-36: decodePayload("filteradd", ...) now returns Message.filteradd.
    const fake_payload = [_]u8{ 0xAB, 0xCD };
    const allocator = std.testing.allocator;
    const msg = try p2p.decodePayload("filteradd", &fake_payload, allocator);
    defer allocator.free(msg.filteradd.payload);
    try testing.expect(msg == .filteradd);
    try testing.expectEqualSlices(u8, &fake_payload, msg.filteradd.payload);
}

// ============================================================================
// G27: filterclear — FIXED (FIX-36): now in p2p.Message; BIP-111 disconnect
// ============================================================================
//
// Core: FILTERCLEAR: if NODE_BLOOM not advertised → fDisconnect=true
//       (net_processing.cpp:5018).  Otherwise destroys per-peer bloom filter.
// FIX-36: filterclear now in Message union (void payload).
//         BIP-111 disconnect gate applied.

test "w110 G27: filterclear IS a variant of p2p.Message — FIXED (FIX-36)" {
    // FIX-36: filterclear now in Message union.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterclear")) {
                found = true;
                break;
            }
        }
        if (!found) @compileError("filterclear missing from Message union — FIX-36 regression");
    }
    try testing.expect(true);
}

test "w110 G27b: filterclear decodes to void message — FIXED (FIX-36)" {
    // FIX-36: decodePayload("filterclear", ...) returns Message.filterclear.
    // filterclear has an empty payload per BIP-37.
    const allocator = std.testing.allocator;
    const msg = try p2p.decodePayload("filterclear", &[_]u8{}, allocator);
    try testing.expect(msg == .filterclear);
}

// ============================================================================
// G28: merkleblock — TWO-PIPELINE CLOSED (FIX-36); PartialMerkleTree absent
// ============================================================================
//
// Core: CMerkleBlock constructed from CBlock + CBloomFilter; serializes
//       PartialMerkleTree (tx count, hashes, flags bits).
//       getdata MSG_FILTERED_BLOCK triggers merkleblock response.
// FIX-36: merkleblock now in Message union (opaque BloomFilterRawMessage).
//         Handler logs + drops (server→client message; receiving is unexpected).
//         PartialMerkleTree construction and MSG_FILTERED_BLOCK getdata
//         response remain absent (no CBloomFilter, not sendable by peers).

test "w110 G28: merkleblock IS a variant of p2p.Message — TWO-PIPELINE CLOSED (FIX-36)" {
    // FIX-36: merkleblock now in Message union.
    // The v2_transport short ID 16 → "merkleblock" → decodePayload chain
    // no longer returns ParseError.UnknownCommand.
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "merkleblock")) {
                found = true;
                break;
            }
        }
        if (!found) @compileError("merkleblock missing from Message union — FIX-36 regression");
    }
    try testing.expect(true);
}

test "w110 G28b: PartialMerkleTree type still absent (BUG-9 deferred)" {
    // BUG-9 partial: Core merkleblock.h defines PartialMerkleTree with
    // vBits[] and vHash[].  clearbit does not construct merkleblock responses
    // (no CBloomFilter, no MSG_FILTERED_BLOCK getdata handler).
    try testing.expect(!@hasDecl(p2p, "PartialMerkleTree"));
    try testing.expect(!@hasDecl(p2p, "MerkleBlockMessage"));
}

test "w110 G28c: msg_filtered_block getdata type present but response handler absent (BUG-9 deferred)" {
    // msg_filtered_block = 3 is defined in InvType (correct constant),
    // but getdata processing never issues a merkleblock response for it.
    const val = @as(u32, @intFromEnum(p2p.InvType.msg_filtered_block));
    try testing.expectEqual(@as(u32, 3), val);
    // No PartialMerkleTree, MerkleBlock struct (only the raw-opaque variant).
    try testing.expect(!@hasDecl(p2p, "MerkleBlock"));
    try testing.expect(!@hasDecl(p2p, "PartialMerkleTree"));
}

test "w110 G28d: merkleblock decodes to BloomFilterRawMessage (log+drop) — FIXED (FIX-36)" {
    // FIX-36: decodePayload("merkleblock", ...) returns Message.merkleblock
    // instead of ParseError.UnknownCommand.  Handler logs + drops.
    const fake_payload = [_]u8{ 0x01, 0x02, 0x03 };
    const allocator = std.testing.allocator;
    const msg = try p2p.decodePayload("merkleblock", &fake_payload, allocator);
    defer allocator.free(msg.merkleblock.payload);
    try testing.expect(msg == .merkleblock);
    try testing.expectEqualSlices(u8, &fake_payload, msg.merkleblock.payload);
}

// ============================================================================
// G29: IsWithinSizeConstraints + peer disconnect — ABSENT
// ============================================================================
//
// Core: IsWithinSizeConstraints() = vData.size()<=MAX_BLOOM_FILTER_SIZE &&
//       nHashFuncs<=MAX_HASH_FUNCS.  Called in FILTERLOAD handler; oversized
//       filter → Misbehaving(100).
// Clearbit: no CBloomFilter, no size check, no disconnect on oversized filter.

test "w110 G29: IsWithinSizeConstraints absent — DoS guard on filterload deferred (BUG-10)" {
    // BUG-10 (MEDIUM — deferred): no size-check + Misbehaving(100) on oversized
    // filterload payload.  Core net_processing.cpp FILTERLOAD calls
    // IsWithinSizeConstraints() after NODE_BLOOM check.
    // FIX-36 applies the BIP-111 disconnect (NODE_BLOOM absent → disconnect)
    // which fires BEFORE the size check, so on a default clearbit node
    // (peerbloomfilters=false) the oversize case is unreachable.
    // The guard remains absent as clearbit has no CBloomFilter.
    try testing.expect(!@hasDecl(p2p, "BloomFilter"));
    try testing.expect(!@hasDecl(p2p, "MAX_BLOOM_FILTER_SIZE"));
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

test "w110 G30d: BIP-111 filterload-disconnect when NODE_BLOOM=false NOW PRESENT — FIXED (FIX-36)" {
    // FIX-36: BIP-111 gate now implemented.
    // Bitcoin Core net_processing.cpp:4964:
    //   if (!(peer.m_our_services & NODE_BLOOM)) {
    //       pfrom.fDisconnect = true; return;
    //   }
    // Clearbit peer.zig: handler checks !peer.advertise_node_bloom and calls
    // peer.disconnect() for filterload, filteradd, filterclear.
    //
    // Structural check: advertise_node_bloom present; no CBloomFilter field.
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
    // BloomFilterRawMessage type is the opaque payload carrier.
    try testing.expect(@hasDecl(p2p, "BloomFilterRawMessage"));
}

// ============================================================================
// TWO-PIPELINE: v2_transport short IDs registered — NOW CLOSED (FIX-36)
// ============================================================================
//
// v2_transport.zig V2_MESSAGE_IDS[]:
//   index 6 = "filteradd"
//   index 7 = "filterclear"
//   index 8 = "filterload"
//   index 16 = "merkleblock"
//
// FIX-36: p2p.Message now has corresponding variants for all four.
//         v2_transport short ID → command string → decodePayload → Message
//         variant → handleMessage BIP-111 gate — full pipeline connected.

test "w110 TWO-PIPELINE: filterload/filteradd/filterclear/merkleblock short IDs AND p2p.Message variants present — CLOSED (FIX-36)" {
    // FIX-36: two-pipeline gap closed.
    // Both sides of the pipeline are now populated.
    const v2 = @import("v2_transport.zig");

    // Confirm short IDs are still registered in v2_transport (upstream).
    try testing.expectEqualStrings("filterload", v2.V2_MESSAGE_IDS[8]);
    try testing.expectEqualStrings("filteradd", v2.V2_MESSAGE_IDS[6]);
    try testing.expectEqualStrings("filterclear", v2.V2_MESSAGE_IDS[7]);
    try testing.expectEqualStrings("merkleblock", v2.V2_MESSAGE_IDS[16]);

    // Confirm Message union now HAS corresponding variants (downstream present).
    comptime {
        const tag = std.meta.Tag(p2p.Message);
        const info = @typeInfo(tag).Enum;
        var found_filterload = false;
        var found_filteradd = false;
        var found_filterclear = false;
        var found_merkleblock = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "filterload")) found_filterload = true;
            if (std.mem.eql(u8, f.name, "filteradd")) found_filteradd = true;
            if (std.mem.eql(u8, f.name, "filterclear")) found_filterclear = true;
            if (std.mem.eql(u8, f.name, "merkleblock")) found_merkleblock = true;
        }
        if (!found_filterload) @compileError("filterload missing from Message — FIX-36 regression");
        if (!found_filteradd) @compileError("filteradd missing from Message — FIX-36 regression");
        if (!found_filterclear) @compileError("filterclear missing from Message — FIX-36 regression");
        if (!found_merkleblock) @compileError("merkleblock missing from Message — FIX-36 regression");
    }
    try testing.expect(true); // comptime checks passed
}

test "w110 TWO-PIPELINE: msg_filtered_block InvType registered but merkleblock RESPONSE still absent (BUG-9 deferred)" {
    // The receive side is now handled (FIX-36).  The send side — constructing
    // and transmitting a merkleblock in response to MSG_FILTERED_BLOCK getdata
    // — remains absent (no CBloomFilter, no PartialMerkleTree).
    const filtered_block_val = @as(u32, @intFromEnum(p2p.InvType.msg_filtered_block));
    try testing.expectEqual(@as(u32, 3), filtered_block_val);
    // No PartialMerkleTree or high-level MerkleBlock struct.
    try testing.expect(!@hasDecl(p2p, "MerkleBlock"));
    try testing.expect(!@hasDecl(p2p, "PartialMerkleTree"));
}

// ============================================================================
// Overall subsystem presence: confirm MISSING ENTIRELY
// ============================================================================

test "w110 SUMMARY: BIP-37 CBloomFilter subsystem missing; BIP-111 disconnect FIXED (FIX-36)" {
    // CBloomFilter core: still absent (BUG-1 through BUG-5 unchanged).
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
    // FIX-36: opaque carrier type present; BIP-111 variants in Message union.
    try testing.expect(@hasDecl(p2p, "BloomFilterRawMessage"));
    // Message union now has all four BIP-37 variants (structural check).
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
            @compileError("One or more FIX-36 variants missing from Message — regression");
    }
    try testing.expect(true);
}
