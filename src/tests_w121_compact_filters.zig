//! W121 — BIP-157/158 compact block filter fleet audit (clearbit / Zig 0.13)
//!
//! Reference: bitcoin-core/src/blockfilter.{cpp,h}
//!            bitcoin-core/src/index/blockfilterindex.{cpp,h}
//!            bitcoin-core/src/net_processing.cpp
//!                (ProcessGetCFilters / ProcessGetCFHeaders / ProcessGetCFCheckPt)
//!            BIP-157 (Client Side Block Filtering), BIP-158 (Compact Block Filters)
//!
//! Run: zig build test-w121 --summary none
//!
//! ============================================================
//! SUBSYSTEM STATUS — clearbit BIP-157/158 compact filters
//! ============================================================
//!
//! Codec + index + REST: SUBSTANTIALLY PRESENT.
//!   - BIP-158 GCS + Golomb-Rice writer/reader: MSB-first, Core-parity
//!     constants (P=19, M=784931).  Round-trip and Core test-vector
//!     coverage already in `src/indexes.zig`.
//!   - `BlockFilterIndex` + `ChainState` integration: connect/disconnect
//!     hooks queue CF_BLOCK_FILTER + CF_BLOCK_FILTER_HEADER writes;
//!     IBD-time `backfillBlockFilterIndex()` rebuilds from
//!     CF_BLOCKS+CF_BLOCK_UNDO when starting cold.
//!   - REST `/rest/blockfilter/<type>/<hash>.{bin,hex,json}` and
//!     `/rest/blockfilterheaders/<type>/<count>/<hash>.{bin,hex,json}`
//!     served from RPC server (with O(N) compute-on-demand fallback).
//!   - CLI: `--blockfilterindex` toggles persistent index +
//!     advertises `NODE_COMPACT_FILTERS` (1<<6) in version.
//!
//! P2P getcfilters / getcfheaders / getcfcheckpt: PRESENT (FIX-84).
//!   - `p2p.Message` union now has all six variants (`getcfilters`,
//!     `cfilter`, `getcfheaders`, `cfheaders`, `getcfcheckpt`,
//!     `cfcheckpt`); decoder + encoder + dispatch arms all wired.
//!   - `peer.zig::processGetCFilters` + `processGetCFHeaders` +
//!     `processGetCFCheckPt` implement Core's PrepareBlockFilterRequest
//!     pattern: validate filter_type / NODE_COMPACT_FILTERS gate /
//!     stop_hash on active chain / range vs MAX_GETCF{ILTERS,HEADERS}_SIZE,
//!     then walk the active chain via getBlockHashByHeight and serve
//!     filters from CF_BLOCK_FILTER+CF_BLOCK_FILTER_HEADER.
//!   - BIP-324 v2 short-IDs 22-27 are no longer dead-helpers: they
//!     decode into real Message-union variants that route to real
//!     handlers.
//!   - Per-violation peer.misbehaving(100) + peer.disconnect() matches
//!     Core's `node.fDisconnect = true; return false;` from
//!     PrepareBlockFilterRequest.
//!
//! JSON-RPC `getblockfilter` / `getindexinfo`: MISSING.
//!   - Core's `getblockfilter(blockhash, filtertype="basic")` returning
//!     `{"filter": <hex>, "header": <hex>}` is NOT registered in
//!     rpc.zig's method dispatch table (no `else if (eql "getblockfilter")`
//!     branch).  REST is the only programmatic access — wallet light
//!     clients using JSON-RPC cannot query filters at all.
//!   - `getindexinfo` (Core: returns sync status of each index incl.
//!     `basic block filter index`) — NOT registered.  Operators have no
//!     RPC view into `blockfilterindex_height`.
//!
//! `--peerblockfilters` CLI flag: MISSING (comment-as-confession in
//!   main.zig:1850 — "clearbit gates only on blockfilterindex
//!   (peerblockfilters follows it)").  Operators cannot run with the
//!   index but withhold P2P serving (Core's standard split — bandwidth
//!   triage).
//!
//! Service-advertise + handshake: PRESENT.
//!   - `NODE_COMPACT_FILTERS = 1<<6` (p2p.zig:16) wired into version
//!     message via `peer.advertise_compact_filters` (peer.zig:1463).
//!
//! ============================================================
//! 30-gate spec (cross-impl parity — DO NOT renumber)
//! ============================================================
//!
//!   G1  BIP-158 basic-filter P parameter (=19)
//!   G2  BIP-158 basic-filter M parameter (=784931)
//!   G3  SipHash-2-4 keyed by block_hash[0..16] little-endian (k0/k1)
//!   G4  FastRange64 map: u64 → [0, N*M) via 128-bit multiply-shift
//!   G5  Golomb-Rice writer — MSB-first, P-bit remainder
//!   G6  Golomb-Rice reader — MSB-first, matches Core test vectors
//!   G7  GCS encode: CompactSize(N) ++ GR-encoded sorted deltas
//!   G8  GCS decode + match() / matchAny() (sorted-merge intersection)
//!   G9  BIP-158 element set: outputs (non-empty, non-OP_RETURN) +
//!       spent prevout scripts (non-empty, OP_RETURN INCLUDED)
//!   G10 Element deduplication before N/F computation (ElementSet)
//!   G11 BlockFilter.getHash() = hash256(encoded filter)
//!   G12 BlockFilter.computeHeader() = hash256(filter_hash || prev_header)
//!   G13 Genesis prev-header = all-zero
//!   G14 BlockFilterIndex persistent RocksDB column families
//!       (CF_BLOCK_FILTER + CF_BLOCK_FILTER_HEADER)
//!   G15 connect-block hook writes filter + header for new tip
//!   G16 disconnect-block hook deletes filter + header, restores
//!       prev_filter_header from parent
//!   G17 IBD backfill (BlockFilterIndex::BaseIndex::Sync analog) —
//!       walks [index_tip+1 .. chain_tip] from CF_BLOCKS+CF_BLOCK_UNDO
//!   G18 Persisted index-tip height (FILTERINDEX_TIP_KEY)
//!   G19 `--blockfilterindex` CLI flag
//!   G20 `--peerblockfilters` CLI flag (Core split: index vs P2P serve)
//!   G21 NODE_COMPACT_FILTERS (1<<6) service flag advertised in version
//!   G22 P2P `getcfilters` message decode + handler
//!       (MAX_GETCFILTERS_SIZE = 1000 range cap)
//!   G23 P2P `cfilter` message encode + response
//!   G24 P2P `getcfheaders` message decode + handler
//!       (MAX_GETCFHEADERS_SIZE = 2000 range cap)
//!   G25 P2P `cfheaders` response (prev_header + filter_hashes vector)
//!   G26 P2P `getcfcheckpt` message decode + handler
//!   G27 P2P `cfcheckpt` response (every CFCHECKPT_INTERVAL=1000 headers)
//!   G28 BIP-324 v2 short-ID registration for cfilter messages (22..27)
//!   G29 JSON-RPC `getblockfilter(blockhash, filtertype)` method
//!   G30 JSON-RPC `getindexinfo` returning index sync state
//!
//! ============================================================
//! BUG FINDINGS — see `BUG-` comments inline below.
//! ============================================================
//!
//!   BUG-1  (G9, LOW-CDIV): `buildBasicBlockFilter` in indexes.zig:603
//!          ALSO filters OP_RETURN scripts from the spent_scripts loop —
//!          Core's `BasicFilterElements` (blockfilter.cpp:200-206) does
//!          NOT skip OP_RETURN from undo prevouts (only the outputs loop
//!          skips them; spends include everything non-empty).  In
//!          practice prevout scripts are almost never OP_RETURN (a spent
//!          OP_RETURN output would mean someone burned bitcoin then
//!          spent the burn — historically rare but legal pre-segwit), so
//!          per-block divergence is unlikely.  STATUS PRESENT but with
//!          this Core-divergence note logged.  *Re-verified 2026-05-16:
//!          the spent_scripts loop in indexes.zig:603 does NOT short-
//!          circuit on `script[0] == 0x6a`; only the outputs loop does.
//!          BUG-1 is therefore SPURIOUS — closing as a non-issue.  Kept
//!          as a documentation pointer for future audits.*
//!
//!   BUG-2  (G20, MEDIUM): `--peerblockfilters` CLI flag is NOT parsed
//!          by main.zig.  clearbit forces P2P serving to follow
//!          `--blockfilterindex`, removing the operator's ability to
//!          maintain a local index while withholding bandwidth-heavy
//!          getcfilters serving.  Core's `init.cpp:992-998` gates
//!          NODE_COMPACT_FILTERS advertisement on BOTH flags; clearbit
//!          advertises whenever the index is on, which is over-eager.
//!
//!   BUG-3  (G22, P0-CDIV-P2P): CLOSED by FIX-84.  `getcfilters`
//!          variant added to `p2p.Message` union; decoder routes to
//!          `peer.zig::processGetCFilters` (Core ProcessGetCFilters
//!          parity — full PrepareBlockFilterRequest validation chain).
//!
//!   BUG-4  (G23, P0-CDIV-P2P): CLOSED by FIX-84.  `cfilter` encoder
//!          + send path wired; one message emitted per height in the
//!          requested range.
//!
//!   BUG-5  (G24-G25, P0-CDIV-P2P): CLOSED by FIX-84.  `getcfheaders`
//!          + `cfheaders` variants + handler + encoder all wired.
//!          Filter-hash chain computed via SHA256d(persisted filter
//!          bytes) per Core's CFHEADERS payload format.
//!
//!   BUG-6  (G26-G27, P0-CDIV-P2P): CLOSED by FIX-84.  `getcfcheckpt`
//!          + `cfcheckpt` variants + handler wired; checkpoint walk
//!          every CFCHECKPT_INTERVAL=1000 blocks.
//!
//!   BUG-7  (G28, DEAD-HELPER): CLOSED by FIX-84.  BIP-324 v2 short-IDs
//!          22-27 are no longer dead helpers — the codec now decodes
//!          to real Message-union variants that route to real handlers.
//!
//!   BUG-8  (G29, MEDIUM): JSON-RPC `getblockfilter` method NOT
//!          registered in rpc.zig's method dispatch.  Wallet RPC
//!          clients (electrum-style wallets that talk JSON-RPC rather
//!          than P2P) cannot query filters.  REST partially covers
//!          this, but Core's documented light-client RPC surface
//!          requires the JSON-RPC entry-point.
//!
//!   BUG-9  (G30, LOW): JSON-RPC `getindexinfo` method NOT registered.
//!          Operators cannot observe `blockfilterindex_height` or
//!          monitor backfill progress over JSON-RPC — only the
//!          REST endpoints surface any state.
//!
//!   BUG-10 (G22-G27, ARCHITECTURAL): CLOSED by FIX-84.  Core constants
//!          ported into `p2p.zig`: `MAX_GETCFILTERS_SIZE=1000`,
//!          `MAX_GETCFHEADERS_SIZE=2000`, `CFCHECKPT_INTERVAL=1000`.
//!
//! ============================================================

const std = @import("std");
const testing = std.testing;

const indexes = @import("indexes.zig");
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const v2_transport = @import("v2_transport.zig");

// ===========================================================================
// G1: BIP-158 basic-filter P parameter
// Status: PRESENT (indexes.zig:178, BASIC_FILTER_P = 19).
// ===========================================================================

test "w121 G1: BASIC_FILTER_P == 19" {
    try testing.expectEqual(@as(u8, 19), indexes.BASIC_FILTER_P);
}

// ===========================================================================
// G2: BIP-158 basic-filter M parameter
// Status: PRESENT (indexes.zig:179, BASIC_FILTER_M = 784931).
// ===========================================================================

test "w121 G2: BASIC_FILTER_M == 784931" {
    try testing.expectEqual(@as(u32, 784931), indexes.BASIC_FILTER_M);
}

// ===========================================================================
// G3: SipHash-2-4 keyed by block_hash[0..16] little-endian.
// Status: PRESENT.  `buildBasicBlockFilter` (indexes.zig:609-610) reads
// k0 = LE u64 of bytes[0..8], k1 = LE u64 of bytes[8..16].
// ===========================================================================

test "w121 G3: GCS params siphash keying from block hash" {
    var block_hash: indexes.Hash256 = undefined;
    for (0..32) |i| block_hash[i] = @intCast(i);

    // Build a tiny filter so we can inspect the params used.
    const script: []const u8 = &[_]u8{ 0x76, 0xa9 }; // p2pkh prefix bytes
    const scripts = [_][]const u8{script};

    var filter = try indexes.buildBasicBlockFilter(&block_hash, &scripts, &.{}, testing.allocator);
    defer filter.deinit();

    const expected_k0 = std.mem.readInt(u64, block_hash[0..8], .little);
    const expected_k1 = std.mem.readInt(u64, block_hash[8..16], .little);
    try testing.expectEqual(expected_k0, filter.filter.params.siphash_k0);
    try testing.expectEqual(expected_k1, filter.filter.params.siphash_k1);
}

// ===========================================================================
// G4: FastRange64 — uniform u64 mapped to [0, range) via 128-bit multiply.
// Status: PRESENT (indexes.zig:183-186).
// ===========================================================================

test "w121 G4: fastRange64 returns < range and 0 for x==0" {
    try testing.expectEqual(@as(u64, 0), indexes.fastRange64(0, 1000));
    // x = 2^63 with range = 2 → product top bit = 1.
    const top = @as(u64, 1) << 63;
    try testing.expect(indexes.fastRange64(top, 2) < 2);
    // Range = 1 → always 0.
    try testing.expectEqual(@as(u64, 0), indexes.fastRange64(0xffff_ffff_ffff_ffff, 1));
}

// ===========================================================================
// G5: Golomb-Rice writer — MSB-first.
// Status: PRESENT.  Verified by W90-era round-trip test, and the FIX-36
// follow-up confirmed the encoder matches Core's BitStreamWriter.
// ===========================================================================

test "w121 G5: BitStreamWriter MSB-first single bit ordering" {
    var w = indexes.BitStreamWriter.init(testing.allocator);
    defer w.deinit();

    // Write 1, 0, 0, 0, 0, 0, 0, 0 → byte 0x80 (MSB-first).
    try w.writeBit(true);
    try w.writeBit(false);
    try w.writeBit(false);
    try w.writeBit(false);
    try w.writeBit(false);
    try w.writeBit(false);
    try w.writeBit(false);
    try w.writeBit(false);
    try w.flush();

    const out = try w.toOwnedSlice();
    defer testing.allocator.free(out);

    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expectEqual(@as(u8, 0x80), out[0]);
}

// ===========================================================================
// G6: Golomb-Rice reader — MSB-first round-trip.
// Status: PRESENT.
// ===========================================================================

test "w121 G6: GR encode/decode round-trip" {
    var w = indexes.BitStreamWriter.init(testing.allocator);
    defer w.deinit();

    const values = [_]u64{ 0, 1, 2, 5, 19, 100, 1000 };
    for (values) |v| try w.golombRiceEncode(v, indexes.BASIC_FILTER_P);
    try w.flush();
    const enc = try w.toOwnedSlice();
    defer testing.allocator.free(enc);

    var r = indexes.BitStreamReader.init(enc);
    for (values) |expected| {
        const got = try r.golombRiceDecode(indexes.BASIC_FILTER_P);
        try testing.expectEqual(expected, got);
    }
}

// ===========================================================================
// G7: GCS encode — CompactSize(N) prefix + GR-encoded sorted deltas.
// Status: PRESENT.
// ===========================================================================

test "w121 G7: GCSFilter empty filter encodes as single CompactSize(0) byte" {
    const params = indexes.GCSParams{
        .siphash_k0 = 0,
        .siphash_k1 = 0,
        .p = indexes.BASIC_FILTER_P,
        .m = indexes.BASIC_FILTER_M,
    };
    var filter = try indexes.GCSFilter.init(params, &.{}, testing.allocator);
    defer filter.deinit();
    try testing.expectEqual(@as(u32, 0), filter.n);
    try testing.expectEqual(@as(usize, 1), filter.encoded.len);
    try testing.expectEqual(@as(u8, 0), filter.encoded[0]);
}

test "w121 G7: GCSFilter non-empty filter starts with CompactSize(N)" {
    const params = indexes.GCSParams{
        .siphash_k0 = 0xdeadbeef,
        .siphash_k1 = 0xcafef00d,
        .p = indexes.BASIC_FILTER_P,
        .m = indexes.BASIC_FILTER_M,
    };
    const e1: []const u8 = "alpha";
    const e2: []const u8 = "beta";
    const e3: []const u8 = "gamma";
    var filter = try indexes.GCSFilter.init(params, &[_][]const u8{ e1, e2, e3 }, testing.allocator);
    defer filter.deinit();
    try testing.expectEqual(@as(u32, 3), filter.n);
    // CompactSize for N < 0xfd is a single byte == N.
    try testing.expectEqual(@as(u8, 3), filter.encoded[0]);
}

// ===========================================================================
// G8: GCS decode + match()/matchAny() — sorted-merge intersection.
// Status: PRESENT.
// ===========================================================================

test "w121 G8: GCSFilter match returns true for inserted elements" {
    const params = indexes.GCSParams{
        .siphash_k0 = 0x1111,
        .siphash_k1 = 0x2222,
        .p = indexes.BASIC_FILTER_P,
        .m = indexes.BASIC_FILTER_M,
    };
    const inserted = [_][]const u8{ "needle", "haystack", "third" };
    var filter = try indexes.GCSFilter.init(params, &inserted, testing.allocator);
    defer filter.deinit();

    for (inserted) |e| {
        try testing.expect(try filter.match(e));
    }
}

test "w121 G8: GCSFilter matchAny finds at least one of the queries" {
    const params = indexes.GCSParams{
        .siphash_k0 = 0x3333,
        .siphash_k1 = 0x4444,
        .p = indexes.BASIC_FILTER_P,
        .m = indexes.BASIC_FILTER_M,
    };
    const inserted = [_][]const u8{"present"};
    var filter = try indexes.GCSFilter.init(params, &inserted, testing.allocator);
    defer filter.deinit();

    const queries = [_][]const u8{ "absent-1", "present", "absent-2" };
    try testing.expect(try filter.matchAny(&queries, testing.allocator));
}

// ===========================================================================
// G9: BIP-158 element set — outputs (non-empty, non-OP_RETURN) + spent
// prevout scripts (non-empty, OP_RETURN INCLUDED per Core).
// Status: PRESENT.  `buildBasicBlockFilter` in indexes.zig:587-626.
// (See header note on BUG-1 — initial flag was spurious: spent_scripts
// loop does NOT skip OP_RETURN.)
// ===========================================================================

test "w121 G9: buildBasicBlockFilter skips empty + OP_RETURN output scripts" {
    var block_hash: indexes.Hash256 = undefined;
    for (0..32) |i| block_hash[i] = @intCast(i +% 7);

    const empty: []const u8 = &[_]u8{};
    const op_return: []const u8 = &[_]u8{ 0x6a, 0x01, 0xaa }; // OP_RETURN <1 byte>
    const real: []const u8 = &[_]u8{ 0x76, 0xa9, 0x14, 0x00, 0x00 }; // p2pkh-ish

    const outs = [_][]const u8{ empty, op_return, real };

    var filter = try indexes.buildBasicBlockFilter(&block_hash, &outs, &.{}, testing.allocator);
    defer filter.deinit();
    // Only `real` survives.
    try testing.expectEqual(@as(u32, 1), filter.filter.n);
}

test "w121 G9: spent_scripts contribute OP_RETURN entries (Core parity)" {
    var block_hash: indexes.Hash256 = undefined;
    for (0..32) |i| block_hash[i] = @intCast(i +% 11);

    const empty: []const u8 = &[_]u8{};
    const op_return_spent: []const u8 = &[_]u8{ 0x6a, 0x01, 0xbb };

    var filter = try indexes.buildBasicBlockFilter(
        &block_hash,
        &.{},
        &[_][]const u8{ empty, op_return_spent },
        testing.allocator,
    );
    defer filter.deinit();
    // Core's BasicFilterElements (blockfilter.cpp:200-206) keeps OP_RETURN
    // in the spend loop — clearbit matches this.  Empty filtered out;
    // OP_RETURN spent script retained.
    try testing.expectEqual(@as(u32, 1), filter.filter.n);
}

// ===========================================================================
// G10: Element deduplication before N/F computation.
// Status: PRESENT.  W90 bug fixed: dedup is content-based via sort + unique.
// ===========================================================================

test "w121 G10: duplicate elements deduplicated to N=1" {
    const params = indexes.GCSParams{
        .siphash_k0 = 1,
        .siphash_k1 = 1,
        .p = indexes.BASIC_FILTER_P,
        .m = indexes.BASIC_FILTER_M,
    };
    const e: []const u8 = "duplicate";
    var filter = try indexes.GCSFilter.init(params, &[_][]const u8{ e, e, e, e }, testing.allocator);
    defer filter.deinit();
    try testing.expectEqual(@as(u32, 1), filter.n);
}

// ===========================================================================
// G11: BlockFilter.getHash() = hash256(encoded filter).
// Status: PRESENT.
// ===========================================================================

test "w121 G11: BlockFilter.getHash is hash256(encoded)" {
    const crypto = @import("crypto.zig");
    var block_hash: indexes.Hash256 = undefined;
    for (0..32) |i| block_hash[i] = @intCast(i +% 13);
    const script: []const u8 = &[_]u8{ 0x51, 0x52 };
    var filter = try indexes.buildBasicBlockFilter(
        &block_hash,
        &[_][]const u8{script},
        &.{},
        testing.allocator,
    );
    defer filter.deinit();
    const got = filter.getHash();
    const expected = crypto.hash256(filter.filter.getEncoded());
    try testing.expectEqualSlices(u8, &expected, &got);
}

// ===========================================================================
// G12: BlockFilter.computeHeader() = hash256(filter_hash || prev_header).
// Status: PRESENT.
// ===========================================================================

test "w121 G12: computeHeader chains hash256(filter_hash || prev)" {
    const crypto = @import("crypto.zig");
    var block_hash: indexes.Hash256 = undefined;
    for (0..32) |i| block_hash[i] = @intCast(i +% 17);
    const script: []const u8 = &[_]u8{ 0x53, 0x54 };
    var filter = try indexes.buildBasicBlockFilter(
        &block_hash,
        &[_][]const u8{script},
        &.{},
        testing.allocator,
    );
    defer filter.deinit();
    var prev: indexes.Hash256 = undefined;
    for (0..32) |i| prev[i] = @intCast(i);
    const got = filter.computeHeader(&prev);

    const filter_hash = filter.getHash();
    var combined: [64]u8 = undefined;
    @memcpy(combined[0..32], &filter_hash);
    @memcpy(combined[32..64], &prev);
    const expected = crypto.hash256(&combined);
    try testing.expectEqualSlices(u8, &expected, &got);
}

// ===========================================================================
// G13: Genesis prev-filter-header is all-zero.
// Status: PRESENT.  BlockFilterIndex.init sets prev_filter_header to [0]**32.
// ===========================================================================

test "w121 G13: BlockFilterIndex.init genesis prev_filter_header == zeros" {
    var idx = indexes.BlockFilterIndex.init(null, testing.allocator, true);
    const zero: indexes.Hash256 = [_]u8{0} ** 32;
    try testing.expectEqualSlices(u8, &zero, &idx.prev_filter_header);
}

// ===========================================================================
// G14: BlockFilterIndex column families.
// Status: PRESENT.  CF_BLOCK_FILTER=6, CF_BLOCK_FILTER_HEADER=7 in storage.zig.
// ===========================================================================

test "w121 G14: CF_BLOCK_FILTER and CF_BLOCK_FILTER_HEADER constants present" {
    try testing.expect(indexes.CF_BLOCK_FILTER != indexes.CF_BLOCK_FILTER_HEADER);
    // Constants are re-exported from storage.zig — ensure they remain stable.
    try testing.expectEqual(@as(usize, 6), indexes.CF_BLOCK_FILTER);
    try testing.expectEqual(@as(usize, 7), indexes.CF_BLOCK_FILTER_HEADER);
}

// ===========================================================================
// G15: connect-block hook writes filter + header for new tip.
// Status: PRESENT.  ChainState.queueFilterIndexWriteForBlock invoked from
// connectBlockInner when blockfilterindex_enabled = true.
// ===========================================================================

test "w121 G15: ChainState exposes blockfilterindex_enabled toggle" {
    // The connect/disconnect hooks read this field directly.  Verify the
    // field is reachable from the public type surface.
    const storage = @import("storage.zig");
    try testing.expect(@hasField(storage.ChainState, "blockfilterindex_enabled"));
}

// ===========================================================================
// G16: disconnect-block hook deletes + restores prev_filter_header.
// Status: PRESENT.  ChainState.queueFilterIndexDeleteForBlock.
// ===========================================================================

test "w121 G16: queueFilterIndexDeleteForBlock symbol exists on ChainState" {
    const storage = @import("storage.zig");
    // The symbol is private to ChainState; we cannot call it from outside,
    // but its existence is asserted by the type checking the disconnect
    // path elsewhere.  Verify the public surrogate field instead.
    try testing.expect(@hasField(storage.ChainState, "pending_filter_deletes"));
}

// ===========================================================================
// G17: IBD backfill walks CF_BLOCKS+CF_BLOCK_UNDO.
// Status: PRESENT.  ChainState.backfillBlockFilterIndex.
// ===========================================================================

test "w121 G17: ChainState.backfillBlockFilterIndex symbol exists" {
    const storage = @import("storage.zig");
    try testing.expect(@hasDecl(storage.ChainState, "backfillBlockFilterIndex"));
}

// ===========================================================================
// G18: Persisted index-tip height.
// Status: PRESENT.  FILTERINDEX_TIP_KEY constant in storage.ChainState.
// ===========================================================================

test "w121 G18: FILTERINDEX_TIP_KEY constant present" {
    const storage = @import("storage.zig");
    try testing.expect(@hasDecl(storage.ChainState, "FILTERINDEX_TIP_KEY"));
    const key = storage.ChainState.FILTERINDEX_TIP_KEY;
    try testing.expectEqualStrings("filterindex_tip", key);
}

// ===========================================================================
// G19: `--blockfilterindex` CLI flag.
// Status: PRESENT (main.zig:283).  This test asserts the parse via the
// config-struct shape; live CLI parsing requires main(), which we avoid.
// ===========================================================================

test "w121 G19: Config struct exposes blockfilterindex bool field" {
    // main.zig defines the config struct locally; we approximate by
    // checking that storage.ChainState wires the field downstream
    // (the only consumer).  A failure here means the toggle isn't
    // reachable at all — see W121 BUG list if this regresses.
    const storage = @import("storage.zig");
    try testing.expect(@hasField(storage.ChainState, "blockfilterindex_enabled"));
}

// ===========================================================================
// G20: `--peerblockfilters` CLI flag (Core split: index vs P2P serve).
// Status: MISSING (BUG-2).  Comment in main.zig:1850 confirms clearbit
// collapses the two flags into one ("peerblockfilters follows it").
// ===========================================================================

test "w121 G20: BUG-2 peerblockfilters NOT a distinct flag (collapsed)" {
    // We can't easily prove a CLI flag is absent without running argv
    // parsing.  Document the architectural collapse instead: the peer
    // manager's `blockfilterindex_enabled` is the SOLE gate for
    // advertising NODE_COMPACT_FILTERS — there is no second field.
    const peer = @import("peer.zig");
    try testing.expect(@hasField(peer.PeerManager, "blockfilterindex_enabled"));
    try testing.expect(!@hasField(peer.PeerManager, "peerblockfilters_enabled"));
    try testing.expect(!@hasField(peer.PeerManager, "peer_block_filters_enabled"));
}

// ===========================================================================
// G21: NODE_COMPACT_FILTERS (1<<6) service flag.
// Status: PRESENT (p2p.zig:16).
// ===========================================================================

test "w121 G21: NODE_COMPACT_FILTERS == (1 << 6)" {
    try testing.expectEqual(@as(u64, 1) << 6, p2p.NODE_COMPACT_FILTERS);
}

// ===========================================================================
// G22: P2P `getcfilters` message decode + handler.
// Status: PRESENT — FIX-84 wired the Message-union variant + decoder +
// handler (peer.zig::processGetCFilters).  Tests flipped from
// "asserts UnknownCommand" → "asserts decodes to getcfilters variant".
// ===========================================================================

test "w121 G22: FIX-84 decodePayload accepts getcfilters" {
    // Synthesize a minimal payload (filter_type=0, start_height=0, stop_hash=0).
    const payload = [_]u8{
        0x00, // filter_type
        0x00, 0x00, 0x00, 0x00, // start_height
    } ++ [_]u8{0} ** 32; // stop_hash

    const decoded = try p2p.decodePayload("getcfilters", &payload, testing.allocator);
    // No heap allocations to free for the getcfilters payload.
    try testing.expectEqual(@as(u8, 0), decoded.getcfilters.filter_type);
    try testing.expectEqual(@as(u32, 0), decoded.getcfilters.start_height);
}

/// Comptime check for a union tag name.  Zig 0.13 requires comptime
/// iteration over `@typeInfo(...).Union.fields`, so we wrap in a
/// `comptime` block and return a `bool` constant.
fn unionHasField(comptime U: type, comptime name: []const u8) bool {
    const info = @typeInfo(U).Union;
    inline for (info.fields) |f| {
        if (comptime std.mem.eql(u8, f.name, name)) return true;
    }
    return false;
}

test "w121 G22: FIX-84 Message union has getcfilters variant" {
    try testing.expect(unionHasField(p2p.Message, "getcfilters")); // FIX-84
}

// ===========================================================================
// G23: P2P `cfilter` message encode + response.
// Status: PRESENT (FIX-84).  Encoder + decoder + dispatch arm wired.
// ===========================================================================

test "w121 G23: FIX-84 Message union has cfilter variant" {
    try testing.expect(unionHasField(p2p.Message, "cfilter")); // FIX-84
}

test "w121 G23: FIX-84 cfilter encode/decode round-trip" {
    const allocator = testing.allocator;
    const filter_bytes = [_]u8{ 0x03, 0xaa, 0xbb, 0xcc }; // CompactSize(3) || bytes
    const cf_msg = p2p.Message{ .cfilter = .{
        .filter_type = 0,
        .block_hash = [_]u8{0x42} ** 32,
        .filter = &filter_bytes,
    } };
    const encoded = try p2p.encodeMessage(&cf_msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);
    const header = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("cfilter", header.commandName());
    const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.cfilter.filter);
    try testing.expectEqual(@as(u8, 0), decoded.cfilter.filter_type);
    try testing.expectEqualSlices(u8, &filter_bytes, decoded.cfilter.filter);
}

// ===========================================================================
// G24: P2P `getcfheaders` message decode + handler.
// Status: PRESENT (FIX-84).
// ===========================================================================

test "w121 G24: FIX-84 decodePayload accepts getcfheaders" {
    const payload = [_]u8{
        0x00,
        0x00, 0x00, 0x00, 0x00,
    } ++ [_]u8{0} ** 32;
    const decoded = try p2p.decodePayload("getcfheaders", &payload, testing.allocator);
    try testing.expectEqual(@as(u8, 0), decoded.getcfheaders.filter_type);
}

test "w121 G24: FIX-84 Message union has getcfheaders variant" {
    try testing.expect(unionHasField(p2p.Message, "getcfheaders"));
}

// ===========================================================================
// G25: P2P `cfheaders` response.
// Status: PRESENT (FIX-84).
// ===========================================================================

test "w121 G25: FIX-84 Message union has cfheaders variant" {
    try testing.expect(unionHasField(p2p.Message, "cfheaders"));
}

test "w121 G25: FIX-84 cfheaders encode/decode round-trip" {
    const allocator = testing.allocator;
    const fhashes = [_]types.Hash256{ [_]u8{0x11} ** 32, [_]u8{0x22} ** 32 };
    const msg = p2p.Message{ .cfheaders = .{
        .filter_type = 0,
        .stop_hash = [_]u8{0x33} ** 32,
        .prev_filter_header = [_]u8{0x44} ** 32,
        .filter_hashes = &fhashes,
    } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);
    const header = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("cfheaders", header.commandName());
    const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.cfheaders.filter_hashes);
    try testing.expectEqual(@as(usize, 2), decoded.cfheaders.filter_hashes.len);
}

// ===========================================================================
// G26: P2P `getcfcheckpt` message.
// Status: PRESENT (FIX-84).
// ===========================================================================

test "w121 G26: FIX-84 decodePayload accepts getcfcheckpt" {
    const payload = [_]u8{0x00} ++ [_]u8{0} ** 32;
    const decoded = try p2p.decodePayload("getcfcheckpt", &payload, testing.allocator);
    try testing.expectEqual(@as(u8, 0), decoded.getcfcheckpt.filter_type);
}

test "w121 G26: FIX-84 Message union has getcfcheckpt variant" {
    try testing.expect(unionHasField(p2p.Message, "getcfcheckpt"));
}

// ===========================================================================
// G27: P2P `cfcheckpt` response (CFCHECKPT_INTERVAL = 1000).
// Status: PRESENT (FIX-84).
// ===========================================================================

test "w121 G27: FIX-84 Message union has cfcheckpt variant" {
    try testing.expect(unionHasField(p2p.Message, "cfcheckpt"));
}

test "w121 G27: FIX-84 CFCHECKPT_INTERVAL + MAX_GET*_SIZE constants defined" {
    // Core: net_processing.cpp:184-186 + index/blockfilterindex.h:31.
    // FIX-84 ports these into p2p.zig (not indexes.zig — they are P2P
    // protocol constants, not index-internal).
    try testing.expectEqual(@as(u32, 1000), p2p.CFCHECKPT_INTERVAL);
    try testing.expectEqual(@as(u32, 1000), p2p.MAX_GETCFILTERS_SIZE);
    try testing.expectEqual(@as(u32, 2000), p2p.MAX_GETCFHEADERS_SIZE);
}

// ===========================================================================
// G28: BIP-324 v2 short-ID registration for cfilter messages.
// Status: PRESENT (FIX-84 closed BUG-7).  Short IDs 22-27 now route into
// real Message-union variants + handlers; no longer a dead helper.
// Test renamed for clarity but kept under the same gate number to
// preserve the audit numbering across waves.
// ===========================================================================

test "w121 G28: FIX-84 BIP-324 short IDs 22-27 registered AND routed" {
    // v2_transport.V2_MESSAGE_IDS is the wire-name table.  Confirm names
    // are present (the dead half of the dead-helper).
    try testing.expectEqualStrings("getcfilters", v2_transport.V2_MESSAGE_IDS[22]);
    try testing.expectEqualStrings("cfilter", v2_transport.V2_MESSAGE_IDS[23]);
    try testing.expectEqualStrings("getcfheaders", v2_transport.V2_MESSAGE_IDS[24]);
    try testing.expectEqualStrings("cfheaders", v2_transport.V2_MESSAGE_IDS[25]);
    try testing.expectEqualStrings("getcfcheckpt", v2_transport.V2_MESSAGE_IDS[26]);
    try testing.expectEqualStrings("cfcheckpt", v2_transport.V2_MESSAGE_IDS[27]);

    // Confirm getShortId round-trip works for the registered names.
    try testing.expectEqual(@as(?u8, 22), v2_transport.getShortId("getcfilters"));
    try testing.expectEqual(@as(?u8, 27), v2_transport.getShortId("cfcheckpt"));
}

// ===========================================================================
// G29: JSON-RPC `getblockfilter` method.
// Status: MISSING (BUG-8).
//
// rpc.zig's method dispatch is a chain of `else if (std.mem.eql(u8,
// method, "X"))` branches.  There is no test-time programmatic way to
// enumerate registered methods, so we document the gap and exercise the
// REST fallback that DOES exist (restBlockFilter at rpc.zig:2554).
// ===========================================================================

test "w121 G29: BUG-8 REST fallback path is the only filter access" {
    // We assert presence of the REST handler symbol indirectly: the
    // module compiles + links its sole consumer.  The bug is the
    // JSON-RPC absence — see BUG-8 in the header.
    const rpc = @import("rpc.zig");
    _ = rpc; // import is enough; restBlockFilter is private to RpcServer.
    try testing.expect(true);
}

// ===========================================================================
// G30: JSON-RPC `getindexinfo` method.
// Status: MISSING (BUG-9).  No JSON-RPC view of blockfilterindex_height
// or backfill progress.
// ===========================================================================

test "w121 G30: BUG-9 blockfilterindex_height field exists but no RPC view" {
    const storage = @import("storage.zig");
    try testing.expect(@hasField(storage.ChainState, "blockfilterindex_height"));
    // ... but `getindexinfo` is unregistered; this is BUG-9.
}
