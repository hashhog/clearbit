//! W150 — bad-diffbits at header admission: EVERY header in a batch.
//!
//! Bitcoin Core reference:
//!   validation.cpp:4083-4088  ContextualCheckBlockHeader
//!                             `assert(pindexPrev != nullptr);`
//!                             `const int nHeight = pindexPrev->nHeight + 1;`
//!                             `if (block.nBits != GetNextWorkRequired(...))
//!                                  -> "bad-diffbits"`   <- FIRST contextual gate
//!   validation.cpp:4215-4217  "prev-blk-not-found", BEFORE the gates run
//!   validation.cpp:4247-4252  ProcessNewBlockHeaders: AcceptBlockHeader per
//!                             header, so header[i] is in the index before
//!                             header[i+1] is validated
//!   pow.cpp:14/44/45          GetNextWorkRequired; GetAncestor + `assert`
//!   pow.cpp:72                BIP-94 base target = FIRST block of the period
//!
//! WHAT WAS BROKEN (W144 left this open):
//!   The `.headers` handler validated the whole batch in one loop and inserted
//!   into `header_index` in a LATER loop.  `validateHeaderContextual` skipped
//!   bad-diffbits whenever the parent was unresolvable, so only headers[0] of
//!   each 2000-header message was difficulty-checked.  headers[1..1999] — whose
//!   parents are in the SAME batch — were admitted with ARBITRARY nBits.
//!   clearbit also performs no proof-of-work check at header-receipt time, so
//!   those headers cost the attacker nothing.
//!   clearbit's own W144 test file documented the hole
//!   (tests_w144_bad_diffbits.zig:19-20) and its Test 5 asserted the fail-open.
//!
//!   Second defect: when the retarget window could not be resolved,
//!   consensus.zig fabricated a plausible-but-wrong expectation
//!   (`orelse return prev_entry.bits`).  A wrong expectation INVERTS the gate:
//!   the honest header carrying the correctly retargeted nBits is rejected as
//!   bad-diffbits (peer discouraged), while an attacker who keeps nBits
//!   constant across the boundary matches our fabricated answer and is
//!   ADMITTED.
//!
//! WHAT THIS SUITE PROVES:
//!   1. Every header in a batch is gated, at the right height, on MAINNET.
//!   2. A mid-batch difficulty-1 header is rejected (the actual attack).
//!   3. A real 2016-block retarget boundary is evaluated correctly, and the
//!      pre-retarget bits are rejected there.
//!   4. An unresolvable retarget window yields "we cannot evaluate" — the
//!      honest header is NOT rejected and the peer is NOT punished.
//!   5. TESTNET4 min-difficulty exception + BIP-94 base-target selection.
//!   6. The batch path never consults a height->hash index.
//!
//! REGTEST IS DELIBERATELY NOT USED: consensus.zig sets REGTEST
//! `.pow_no_retarget = true` and `.pow_allow_min_difficulty_blocks = true`, so
//! the expected value short-circuits and a regtest test proves nothing.
//!
//! Run with: `zig build test-w150`

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

const PeerManager = peer_mod.PeerManager;
const HeaderBatchOverlay = peer_mod.HeaderBatchOverlay;
const BlockHeaderEntry = peer_mod.BlockHeaderEntry;
const HeaderTimeReject = PeerManager.HeaderTimeReject;

// ============================================================================
// Helpers
// ============================================================================

/// Deterministic synthetic block hash for a seeded chain position.
fn synthHash(tag: u8, h: u32) types.Hash256 {
    var out: types.Hash256 = [_]u8{0} ** 32;
    out[0] = tag;
    out[1] = @truncate(h);
    out[2] = @truncate(h >> 8);
    out[3] = @truncate(h >> 16);
    out[4] = @truncate(h >> 24);
    // Keep it clearly distinct from any real hash.
    out[31] = 0xA5;
    return out;
}

fn makeEntry(
    hash: types.Hash256,
    prev: types.Hash256,
    h: u32,
    bits: u32,
    ts: u32,
) BlockHeaderEntry {
    return BlockHeaderEntry{
        .hash = hash,
        .prev_hash = prev,
        .height = h,
        .chain_work = [_]u8{0} ** 32,
        .timestamp = ts,
        .header = types.BlockHeader{
            .version = 4,
            .prev_block = prev,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = ts,
            .bits = bits,
            .nonce = 0,
        },
        .last_seen = 0,
    };
}

fn header(prev: types.Hash256, ts: u32, bits: u32) types.BlockHeader {
    return types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = ts,
        .bits = bits,
        .nonce = 0,
    };
}

/// Seed `count` header_index entries at heights 0..count-1 with a per-height
/// (bits, timestamp) supplied by the caller.  Returns the tip hash.
const SeedVal = struct { bits: u32, ts: u32 };
const SeedFn = *const fn (h: u32) SeedVal;

fn seedChain(pm: *PeerManager, tag: u8, count: u32, f: SeedFn) !types.Hash256 {
    var prev: types.Hash256 = [_]u8{0} ** 32;
    var h: u32 = 0;
    while (h < count) : (h += 1) {
        const v = f(h);
        const hash = synthHash(tag, h);
        try pm.header_index.put(hash, makeEntry(hash, prev, h, v.bits, v.ts));
        prev = hash;
    }
    return prev;
}

const MAINNET_BITS: u32 = 0x1d00ffff; // mainnet pow limit / genesis bits
const HARD_BITS: u32 = 0x1c00ffff; // 256x harder than MAINNET_BITS
const NOW: i64 = 2_000_000_000;

// ============================================================================
// 1 — THE HOLE: a mid-batch header with arbitrary nBits must be rejected
// ============================================================================

test "W150: mid-batch difficulty-1 header is rejected (MAINNET)" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // Active chain: heights 0..4, all at HARD_BITS, 600s apart.
    const S = struct {
        fn f(h: u32) SeedVal {
            return .{ .bits = HARD_BITS, .ts = 1_500_000_000 + h * 600 };
        }
    };
    const tip = try seedChain(&pm, 0x11, 5, S.f);

    // Batch of 4 headers extending the tip (heights 5..8).  Non-retarget
    // heights on mainnet -> required nBits == prev.bits == HARD_BITS.
    // header[2] cheats: difficulty-1.  Before this fix that header's parent
    // was in the SAME batch, so bad-diffbits was skipped and it was admitted.
    var hdrs: [4]types.BlockHeader = undefined;
    var prev = tip;
    var ts: u32 = 1_500_000_000 + 5 * 600;
    for (&hdrs, 0..) |*hp, i| {
        const bits: u32 = if (i == 2) MAINNET_BITS else HARD_BITS;
        hp.* = header(prev, ts, bits);
        prev = crypto.computeBlockHash(hp);
        ts += 600;
    }

    var overlay = HeaderBatchOverlay.init(allocator);
    defer overlay.deinit();

    const before_checks = pm.header_diffbits_checks;
    const outcome = pm.validateHeaderBatch(&hdrs, NOW, &overlay);

    try testing.expectEqual(@as(usize, 2), outcome.accepted);
    try testing.expect(outcome.reject != null);
    try testing.expectEqual(HeaderTimeReject.bad_diffbits, outcome.reject.?);
    try testing.expect(!outcome.undecidable);
    // The gate RAN for headers 0, 1 and 2 — not just for header 0.
    try testing.expectEqual(@as(u64, 3), pm.header_diffbits_checks - before_checks);
    // No height->hash index was consulted anywhere on this path.
    try testing.expectEqual(@as(u64, 0), pm.height_index_fallbacks);
}

// ============================================================================
// 2 — Every header in a good batch is gated (not just the first)
// ============================================================================

test "W150: whole honest batch accepted and every header gated (MAINNET)" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const S = struct {
        fn f(h: u32) SeedVal {
            return .{ .bits = HARD_BITS, .ts = 1_500_000_000 + h * 600 };
        }
    };
    const tip = try seedChain(&pm, 0x12, 5, S.f);

    var hdrs: [6]types.BlockHeader = undefined;
    var prev = tip;
    var ts: u32 = 1_500_000_000 + 5 * 600;
    for (&hdrs) |*hp| {
        hp.* = header(prev, ts, HARD_BITS);
        prev = crypto.computeBlockHash(hp);
        ts += 600;
    }

    var overlay = HeaderBatchOverlay.init(allocator);
    defer overlay.deinit();

    const before_checks = pm.header_diffbits_checks;
    const outcome = pm.validateHeaderBatch(&hdrs, NOW, &overlay);

    try testing.expectEqual(@as(usize, 6), outcome.accepted);
    try testing.expectEqual(@as(?HeaderTimeReject, null), outcome.reject);
    try testing.expect(!outcome.undecidable);
    try testing.expectEqual(@as(u64, 6), pm.header_diffbits_checks - before_checks);
    try testing.expectEqual(@as(u64, 0), pm.header_undecidable_count);
    try testing.expectEqual(@as(u64, 0), pm.height_index_fallbacks);

    // Heights came from the parent (parent.height + 1), not from a counter:
    // the overlay's last entry must be at height 4 + 6 = 10.
    const last_hash = crypto.computeBlockHash(&hdrs[5]);
    const last = overlay.get(&last_hash).?;
    try testing.expectEqual(@as(u32, 10), last.height);
}

// ============================================================================
// 3 — A header re-sent inside the same batch must not shift heights
//     (wave-1 lesson 3: never derive height from a counter / queue length)
// ============================================================================

test "W150: duplicate header inside a batch does not shift heights (MAINNET)" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const S = struct {
        fn f(h: u32) SeedVal {
            return .{ .bits = HARD_BITS, .ts = 1_500_000_000 + h * 600 };
        }
    };
    const tip = try seedChain(&pm, 0x13, 5, S.f);

    const h5 = header(tip, 1_500_000_000 + 5 * 600, HARD_BITS);
    const h5_hash = crypto.computeBlockHash(&h5);
    const h6 = header(h5_hash, 1_500_000_000 + 6 * 600, HARD_BITS);

    // Peer re-sends h5 before h6 (Core tolerates duplicates; a
    // counter/queue-length height derivation would overshoot).
    const hdrs = [_]types.BlockHeader{ h5, h5, h6 };

    var overlay = HeaderBatchOverlay.init(allocator);
    defer overlay.deinit();
    const outcome = pm.validateHeaderBatch(&hdrs, NOW, &overlay);

    try testing.expectEqual(@as(usize, 3), outcome.accepted);
    try testing.expectEqual(@as(?HeaderTimeReject, null), outcome.reject);
    const e6 = overlay.get(&crypto.computeBlockHash(&h6)).?;
    try testing.expectEqual(@as(u32, 6), e6.height);
}

// ============================================================================
// 4 — Real 2016-block retarget boundary, MAINNET
//     Window timespan == 4 * target (clamped max) -> target *= 4.
// ============================================================================

test "W150: MAINNET retarget boundary — correct nBits accepted, prev bits rejected" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const interval = consensus.difficultyAdjustmentInterval(&consensus.MAINNET);
    try testing.expectEqual(@as(u32, 2016), interval);

    // Heights 0..2015, all HARD_BITS.  first.ts = T; last.ts = T + 4*timespan
    // so actual_timespan clamps to the 4x maximum and the new target is
    // old_target * 4  ->  0x1c00ffff * 4 == 0x1c03fffc (below the pow limit,
    // so no clamping).  This expectation is derived from the rule, not from
    // clearbit's own retarget code.
    const T: u32 = 1_500_000_000;
    const S = struct {
        fn f(h: u32) SeedVal {
            const base: u32 = 1_500_000_000;
            if (h == 2015) return .{ .bits = HARD_BITS, .ts = base + 4 * 1_209_600 };
            return .{ .bits = HARD_BITS, .ts = base + h * 2_400 };
        }
    };
    const tip = try seedChain(&pm, 0x14, 2016, S.f);

    const expected_retarget: u32 = 0x1c03fffc;
    const new_ts: u32 = T + 4 * 1_209_600 + 600;

    // (a) The correctly retargeted header is accepted.
    {
        const good = header(tip, new_ts, expected_retarget);
        try testing.expectEqual(
            HeaderTimeReject.ok,
            pm.validateHeaderContextualStrict(&good, NOW, null),
        );
    }

    // (b) Carrying the PRE-retarget bits across the boundary is rejected.
    //     This is precisely what an attacker does when our window is
    //     unresolvable and we fabricate `prev.bits` as the expectation.
    {
        const stale = header(tip, new_ts, HARD_BITS);
        try testing.expectEqual(
            HeaderTimeReject.bad_diffbits,
            pm.validateHeaderContextualStrict(&stale, NOW, null),
        );
    }

    // (c) Difficulty-1 across the boundary is rejected.
    {
        const easy = header(tip, new_ts, MAINNET_BITS);
        try testing.expectEqual(
            HeaderTimeReject.bad_diffbits,
            pm.validateHeaderContextualStrict(&easy, NOW, null),
        );
    }

    // Resolution was a pure prev-pointer walk: 2015 steps back to height 0.
    try testing.expectEqual(@as(u64, 0), pm.height_index_fallbacks);
}

// ============================================================================
// 5 — Unresolvable retarget window: "we cannot evaluate", NOT "invalid"
//     (wave-1 lesson 2 — never punish a peer for our own gap)
// ============================================================================

test "W150: truncated retarget window is undecidable, not bad-diffbits" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // Same chain as test 4 but with the period's FIRST block (height 0)
    // missing — the state a snapshot boot or an evicted index leaves behind.
    var prev: types.Hash256 = synthHash(0x15, 0); // height 0 deliberately absent
    var h: u32 = 1;
    while (h < 2016) : (h += 1) {
        const ts: u32 = if (h == 2015)
            1_500_000_000 + 4 * 1_209_600
        else
            1_500_000_000 + h * 2_400;
        const hash = synthHash(0x15, h);
        try pm.header_index.put(hash, makeEntry(hash, prev, h, HARD_BITS, ts));
        prev = hash;
    }
    const tip = prev;
    const new_ts: u32 = 1_500_000_000 + 4 * 1_209_600 + 600;

    // The HONEST header (correct retarget) must NOT be rejected.
    const good = header(tip, new_ts, 0x1c03fffc);
    try testing.expectEqual(
        HeaderTimeReject.undecidable,
        pm.validateHeaderContextualStrict(&good, NOW, null),
    );

    // And an attacker holding nBits constant across the boundary — the one
    // that MATCHES the old fabricated `prev.bits` answer — is not admitted as
    // `.ok` either; it is equally undecidable, so nothing is silently blessed.
    const attacker = header(tip, new_ts, HARD_BITS);
    try testing.expectEqual(
        HeaderTimeReject.undecidable,
        pm.validateHeaderContextualStrict(&attacker, NOW, null),
    );

    // Batch-level: nothing accepted, NOBODY at fault.
    var overlay = HeaderBatchOverlay.init(allocator);
    defer overlay.deinit();
    const hdrs = [_]types.BlockHeader{good};
    const outcome = pm.validateHeaderBatch(&hdrs, NOW, &overlay);
    try testing.expectEqual(@as(usize, 0), outcome.accepted);
    try testing.expectEqual(@as(?HeaderTimeReject, null), outcome.reject); // no peer penalty
    try testing.expect(outcome.undecidable);

    // The legacy 0-sentinel wrapper reports "not available" rather than the
    // old fabricated prev.bits.
    try testing.expectEqual(@as(u32, 0), pm.computeExpectedBits(tip, 2016, new_ts));
}

// ============================================================================
// 6 — Unknown parent is undecidable (Core: "prev-blk-not-found", no penalty)
// ============================================================================

test "W150: unknown parent -> undecidable, never a peer penalty" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const orphan = header([_]u8{0xDD} ** 32, 1_600_000_000, 0x1c0fafaf);
    try testing.expectEqual(
        HeaderTimeReject.undecidable,
        pm.validateHeaderContextualStrict(&orphan, NOW, null),
    );

    var overlay = HeaderBatchOverlay.init(allocator);
    defer overlay.deinit();
    const hdrs = [_]types.BlockHeader{orphan};
    const outcome = pm.validateHeaderBatch(&hdrs, NOW, &overlay);
    try testing.expectEqual(@as(usize, 0), outcome.accepted);
    try testing.expectEqual(@as(?HeaderTimeReject, null), outcome.reject);
    try testing.expect(outcome.undecidable);
}

// ============================================================================
// 7 — TESTNET4: min-difficulty exception (fPowAllowMinDifficultyBlocks)
// ============================================================================

test "W150: TESTNET4 min-difficulty exception enforced both ways" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.TESTNET4);
    defer pm.deinit();

    try testing.expect(consensus.TESTNET4.pow_allow_min_difficulty_blocks);
    try testing.expect(!consensus.TESTNET4.pow_no_retarget);
    const pow_limit_bits = consensus.getPowLimitBits(&consensus.TESTNET4);

    // Heights 0..20, all at HARD_BITS (a real, non-min difficulty), 600s apart.
    const S = struct {
        fn f(h: u32) SeedVal {
            return .{ .bits = HARD_BITS, .ts = 1_700_000_000 + h * 600 };
        }
    };
    const tip = try seedChain(&pm, 0x16, 21, S.f);
    const tip_ts: u32 = 1_700_000_000 + 20 * 600;

    // (a) > 2 * pow_target_spacing after the parent -> min difficulty is REQUIRED.
    {
        const gap_ts: u32 = tip_ts + 2 * consensus.TESTNET4.pow_target_spacing + 1;
        const ok_hdr = header(tip, gap_ts, pow_limit_bits);
        try testing.expectEqual(
            HeaderTimeReject.ok,
            pm.validateHeaderContextualStrict(&ok_hdr, NOW, null),
        );
        // Claiming the normal difficulty in the min-difficulty window is wrong.
        const wrong = header(tip, gap_ts, HARD_BITS);
        try testing.expectEqual(
            HeaderTimeReject.bad_diffbits,
            pm.validateHeaderContextualStrict(&wrong, NOW, null),
        );
    }

    // (b) Inside the normal spacing -> min difficulty is NOT allowed; the
    //     required value is the last non-min-difficulty block's bits.
    {
        const near_ts: u32 = tip_ts + 600;
        const ok_hdr = header(tip, near_ts, HARD_BITS);
        try testing.expectEqual(
            HeaderTimeReject.ok,
            pm.validateHeaderContextualStrict(&ok_hdr, NOW, null),
        );
        const cheat = header(tip, near_ts, pow_limit_bits);
        try testing.expectEqual(
            HeaderTimeReject.bad_diffbits,
            pm.validateHeaderContextualStrict(&cheat, NOW, null),
        );
    }

    try testing.expectEqual(@as(u64, 0), pm.height_index_fallbacks);
}

// ============================================================================
// 8 — TESTNET4: BIP-94 uses the FIRST block of the period as the base target
// ============================================================================

test "W150: TESTNET4 BIP-94 retarget uses first-block target, not last" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.TESTNET4);
    defer pm.deinit();

    try testing.expect(consensus.TESTNET4.enforce_bip94);

    // Height 0 (period start) carries the REAL difficulty (HARD_BITS);
    // heights 1..2015 are min-difficulty blocks (the timewarp setup BIP-94
    // defends against).  Timespan is exactly the target, so the ratio is 1:
    //   BIP-94    -> base = first.bits = HARD_BITS   (0x1c00ffff)
    //   pre-BIP94 -> base = last.bits  = pow limit   (0x1d00ffff)
    // The two answers differ, so this pins the base-target selection.
    const pow_limit_bits = consensus.getPowLimitBits(&consensus.TESTNET4);
    try testing.expect(pow_limit_bits != HARD_BITS);

    const S = struct {
        fn f(h: u32) SeedVal {
            const base: u32 = 1_700_000_000;
            const limit = consensus.getPowLimitBits(&consensus.TESTNET4);
            if (h == 0) return .{ .bits = HARD_BITS, .ts = base };
            if (h == 2015) return .{ .bits = limit, .ts = base + 1_209_600 };
            return .{ .bits = limit, .ts = base + h * 600 };
        }
    };
    const tip = try seedChain(&pm, 0x17, 2016, S.f);
    const new_ts: u32 = 1_700_000_000 + 1_209_600 + 600;

    const good = header(tip, new_ts, HARD_BITS); // BIP-94 answer
    try testing.expectEqual(
        HeaderTimeReject.ok,
        pm.validateHeaderContextualStrict(&good, NOW, null),
    );

    const pre_bip94 = header(tip, new_ts, pow_limit_bits); // legacy answer
    try testing.expectEqual(
        HeaderTimeReject.bad_diffbits,
        pm.validateHeaderContextualStrict(&pre_bip94, NOW, null),
    );

    try testing.expectEqual(@as(u64, 0), pm.height_index_fallbacks);
}

// ============================================================================
// 9 — NEGATIVE: the height->hash index must never answer for a batch header
// ============================================================================

test "W150: height fast path is structurally forbidden under a batch overlay" {
    // The predicate is the guard itself (PeerManager.heightFastPathAllowed).
    // A height->hash index describes OUR active chain; a header whose parent
    // is another header from the same message is by definition not an
    // extension of our tip, so answering it by height hands back an unrelated
    // block — the inversion that rejects the honest header and admits the
    // attacker who matched the poisoned answer.
    try testing.expectEqual(false, PeerManager.heightFastPathAllowed(true, true));
    try testing.expectEqual(false, PeerManager.heightFastPathAllowed(true, false));
    try testing.expectEqual(false, PeerManager.heightFastPathAllowed(false, false));
    // Only permitted when there is no overlay AND the candidate's parent IS
    // the active tip — and even then it is a fallback, tried only after the
    // prev-pointer walk fails.
    try testing.expectEqual(true, PeerManager.heightFastPathAllowed(false, true));
}

test "W150: batch validation performs zero height-index lookups" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const S = struct {
        fn f(h: u32) SeedVal {
            return .{ .bits = HARD_BITS, .ts = 1_500_000_000 + h * 600 };
        }
    };
    const tip = try seedChain(&pm, 0x18, 2016, S.f);

    var hdrs: [8]types.BlockHeader = undefined;
    var prev = tip;
    var ts: u32 = 1_500_000_000 + 2016 * 600;
    for (&hdrs, 0..) |*hp, i| {
        // Height 2016 is the retarget boundary -> the deepest ancestor walk in
        // the batch (2015 pointer steps).  Window timespan = 2015*600 =
        // 1_209_000 s, above target/4, below target*4, so the new target is
        // old * 1_209_000 / 1_209_600.
        _ = i;
        hp.* = header(prev, ts, HARD_BITS);
        prev = crypto.computeBlockHash(hp);
        ts += 600;
    }

    var overlay = HeaderBatchOverlay.init(allocator);
    defer overlay.deinit();
    _ = pm.validateHeaderBatch(&hdrs, NOW, &overlay);

    // Whatever the verdict, no height->hash structure was consulted.
    try testing.expectEqual(@as(u64, 0), pm.height_index_fallbacks);
}

// ============================================================================
// 10 — consensus.getNextWorkRequiredChecked signals, never guesses
// ============================================================================

test "W150: getNextWorkRequiredChecked returns null instead of fabricating" {
    // A view that resolves everything EXCEPT the retarget period's first block
    // — the state consensus.zig used to paper over with `prev_entry.bits`.
    const Ctx = struct {
        fn getAt(_: *anyopaque, h: u32) ?consensus.BlockIndexEntry {
            if (h == 0) return null; // period start unreachable
            if (h > 2015) return null;
            return consensus.BlockIndexEntry{
                .height = h,
                .timestamp = 1_500_000_000 + h * 600,
                .bits = HARD_BITS,
            };
        }
    };
    var dummy: u8 = 0;
    const view = consensus.BlockIndexView{
        .context = @ptrCast(&dummy),
        .getAtHeightFn = Ctx.getAt,
        .pow_limit_bits = consensus.getPowLimitBits(&consensus.MAINNET),
    };

    // Strict: cannot evaluate.
    try testing.expectEqual(
        @as(?u32, null),
        consensus.getNextWorkRequiredChecked(2016, 1_501_209_600, &view, &consensus.MAINNET),
    );
    // Lenient (legacy, still used by the non-peer-facing shim callers)
    // fabricates prev.bits — documenting exactly what the strict variant fixes.
    try testing.expectEqual(
        HARD_BITS,
        consensus.getNextWorkRequired(2016, 1_501_209_600, &view, &consensus.MAINNET),
    );
}