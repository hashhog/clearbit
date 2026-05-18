//! W139 — Fee estimation engine (CBlockPolicyEstimator) audit (clearbit / Zig 0.13)
//!
//! Discovery-only audit of clearbit's fee-estimation surface vs Bitcoin Core
//! (`bitcoin-core/src/policy/fees/block_policy_estimator.{cpp,h}`,
//!  `bitcoin-core/src/policy/feerate.{cpp,h}`,
//!  `bitcoin-core/src/rpc/fees.cpp`).
//!
//! This is a SECOND pass on the fee subsystem.  W114 closed
//! BUG-1/2/3/7/8/9/10 (FIX-47 / FIX-48 — `trackTransaction` /
//! `confirmTransaction` / `processBlock` wired up + three-horizon
//! architecture).  W139 deliberately targets the Core-specific semantics
//! W114 missed: `CFeeRate`, `FeeFilterRounder`, `validForFeeEstimation`,
//! reorg / side-chain guards, `MaxUsableEstimate` clamping,
//! `estimateCombinedFee` + `estimateConservativeFee`, `FlushUnconfirmed`,
//! file-age / flush-interval, RPC schema parity.
//!
//! Test shape: each gate asserts the CURRENT (buggy) clearbit behavior so a
//! future fix wave flips the assertion when the gap closes.  MISSING bugs
//! are typically asserted via source-grep guards over `mempool.zig` and
//! `rpc.zig`; DIVERGE bugs are asserted with twin checks pinning both
//! "what clearbit does" and "what Core does".
//!
//! Run: `zig build test-w139 --summary all`.
//!
//! See `audit/w139_fee_estimation.md` for the full 30-gate matrix and prose.

const std = @import("std");
const testing = std.testing;

const mempool_mod = @import("mempool.zig");
const types = @import("types.zig");

const FeeEstimator = mempool_mod.FeeEstimator;
const Mempool = mempool_mod.Mempool;

// ===========================================================================
// Helpers
// ===========================================================================

/// Open `src/<basename>.zig` and return the full contents (caller frees).
/// Mirrors the pattern used by `tests_w137_psbt.zig` / `tests_w136_relay_flags.zig`.
fn loadSrc(allocator: std.mem.Allocator, basename: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "src/{s}.zig", .{basename});
    defer allocator.free(path);
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 32 * 1024 * 1024);
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

// ===========================================================================
// G1 — BUG-1: No CFeeRate-equivalent type wrapping fee + size
// ===========================================================================
test "w139 G1: BUG-1 no CFeeRate type wrapping (fee, size) pair" {
    // Core: `class CFeeRate { FeePerVSize m_feerate; ... }` in
    // policy/feerate.h is the canonical wrapper.  clearbit passes raw f64
    // sat/vB anywhere a feerate flows.
    //
    // Source-grep guard: no `CFeeRate` or `FeeRate` struct declaration in
    // mempool.zig / rpc.zig.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    const rpc_src = try loadSrc(a, "rpc");
    defer a.free(rpc_src);
    // CFeeRate is never declared as a struct (only mentioned in comments).
    try testing.expect(!contains(mp_src, "const CFeeRate = struct"));
    try testing.expect(!contains(mp_src, "pub const CFeeRate = struct"));
    try testing.expect(!contains(mp_src, "pub const FeeRate = struct"));
    try testing.expect(!contains(rpc_src, "const CFeeRate = struct"));
}

// ===========================================================================
// G2 — BUG-2: No GetFee(virtual_bytes) ceiling-rounding API
// ===========================================================================
test "w139 G2: BUG-2 no CFeeRate.GetFee ceiling-rounding helper" {
    // Core feerate.cpp:20-27 `GetFee` rounds via `EvaluateFeeUp` (CeilDiv).
    // clearbit divides `fee / vsize` directly with implicit truncation toward
    // zero, surfaced by tests_w130_bip125_feebumper_rule3.zig G2 already.
    //
    // Source-grep guard: no public `getFee` method on the estimator and no
    // CeilDiv-style helper that takes a vsize argument and returns a fee.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "pub fn getFee("));
    try testing.expect(!contains(mp_src, "EvaluateFeeUp"));
    try testing.expect(!contains(mp_src, "CeilDiv"));
}

// ===========================================================================
// G3 — BUG-3: Internal feerate unit mismatch (sat/vB vs Core sat/kvB)
// ===========================================================================
test "w139 G3: BUG-3 estimator stores rate as sat/vB; Core stores sat/kvB" {
    // Core CFeeRate is internally sat/kvB (GetFeePerK).  clearbit's
    // FeeEstimator stores f64 sat/vB and the RPC converts at the boundary:
    //   const btc_per_kvb = rate * 1000.0 / 100_000_000.0;
    // rpc.zig:11156 — multiplied by 1000 to go from sat/vB to sat/kvB,
    // then by 1e-8 to BTC.  This is correct AT THE BOUNDARY but invites
    // unit-mixing bugs internally because other constants (MIN_RELAY_FEE,
    // INCREMENTAL_RELAY_FEE) are sat/kvB (mempool.zig:49,54).
    //
    // Pin both the bucket-bound unit (sat/vB) and the boundary constant
    // (sat/kvB) so a future unit unification flips this gate.
    try testing.expectEqual(@as(f64, 1.0), FeeEstimator.MIN_BUCKET_FEE);
    // mempool.MIN_RELAY_FEE is sat/kvB == 100.
    try testing.expectEqual(@as(i64, 100), mempool_mod.MIN_RELAY_FEE);
    // 1.0 (sat/vB) × 1000 == 1000, which is 10× MIN_RELAY_FEE (100 sat/kvB).
    // Documents the unit mismatch directly.
    try testing.expect(FeeEstimator.MIN_BUCKET_FEE * 1000.0 != @as(f64, @floatFromInt(mempool_mod.MIN_RELAY_FEE)));
}

// ===========================================================================
// G4 — BUG-4: No FeeRateFormat::SAT_VB vs BTC_KVB formatter switch
// ===========================================================================
test "w139 G4: BUG-4 no FeeRateFormat enum / sat/vB RPC formatter mode" {
    // Core feerate.h:22-25 declares `enum class FeeRateFormat { BTC_KVB, SAT_VB }`.
    // clearbit unconditionally emits BTC/kvB; no `sat/vB` formatter mode.
    const a = testing.allocator;
    const rpc_src = try loadSrc(a, "rpc");
    defer a.free(rpc_src);
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(rpc_src, "FeeRateFormat"));
    try testing.expect(!contains(mp_src, "FeeRateFormat"));
    try testing.expect(!contains(rpc_src, "SAT_VB"));
    try testing.expect(!contains(rpc_src, "BTC_KVB"));
}

// ===========================================================================
// G5 — BUG-5: No int32 vsize overflow guard
// ===========================================================================
test "w139 G5: BUG-5 feeToBucket accepts any f64; no virtual_bytes>0 guard" {
    // Core CFeeRate(CAmount, int32_t virtual_bytes) explicitly checks
    // `if (virtual_bytes > 0)` (feerate.cpp:13).  clearbit's feeToBucket
    // takes f64 directly with no size argument, so the caller is responsible
    // for size validation.  Document: passing a negative or NaN rate is
    // accepted silently.
    const a = testing.allocator;
    var est = FeeEstimator.init(a);
    defer est.deinit();
    // Negative rate maps to bucket 0 (since `< bucket_bounds[1]` is true for any negative).
    try testing.expectEqual(@as(usize, 0), est.feeToBucket(-1.0));
    // NaN comparison is always false, so the loop falls through to
    // NUM_BUCKETS-1.  Pin the behavior so a future bounds-check flips this.
    try testing.expectEqual(@as(usize, FeeEstimator.NUM_BUCKETS - 1), est.feeToBucket(std.math.nan(f64)));
}

// ===========================================================================
// G6 — BUG-6: No FeeFilterRounder (BIP-133 quantization helper)
// ===========================================================================
test "w139 G6: BUG-6 no FeeFilterRounder helper / MakeFeeSet" {
    // Core block_policy_estimator.{h:323-344, cpp:1085-1118} declares
    // `class FeeFilterRounder` + `MakeFeeSet` namespace helper.  clearbit
    // has neither.  Cross-validated by W136 G8 (`tests_w136_relay_flags.zig:218`);
    // W139 reasserts from the fee-engine side.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    const p2p_src = loadSrc(a, "p2p") catch null;
    defer if (p2p_src) |s| a.free(s);
    const peer_src = loadSrc(a, "peer") catch null;
    defer if (peer_src) |s| a.free(s);

    try testing.expect(!contains(mp_src, "FeeFilterRounder"));
    try testing.expect(!contains(mp_src, "MakeFeeSet"));
    if (p2p_src) |s| try testing.expect(!contains(s, "FeeFilterRounder"));
    if (peer_src) |s| try testing.expect(!contains(s, "FeeFilterRounder"));
}

// ===========================================================================
// G7 — BUG-7: No FEE_FILTER_SPACING = 1.1 constant
// ===========================================================================
test "w139 G7: BUG-7 no FEE_FILTER_SPACING = 1.1 constant" {
    // Core block_policy_estimator.h:331 declares
    // `static constexpr double FEE_FILTER_SPACING = 1.1;`
    // distinct from `FEE_SPACING = 1.05` (bucket spacing).  clearbit has
    // BUCKET_SPACING = 1.1 (Zig estimator bucket — DIFFERENT meaning), but
    // no FEE_FILTER_SPACING for the BIP-133 rounder.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "FEE_FILTER_SPACING"));
}

// ===========================================================================
// G8 — BUG-8: No MAX_FILTER_FEERATE = 1e7 constant
// ===========================================================================
test "w139 G8: BUG-8 no MAX_FILTER_FEERATE = 1e7 constant" {
    // Core block_policy_estimator.h:326 declares
    // `static constexpr double MAX_FILTER_FEERATE = 1e7;`
    // (caps the FeeFilterRounder range).  clearbit has neither.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "MAX_FILTER_FEERATE"));
}

// ===========================================================================
// G9 — BUG-9: No validForFeeEstimation four-gate skip
// ===========================================================================
test "w139 G9: BUG-9 no validForFeeEstimation gate before trackTransaction" {
    // Core block_policy_estimator.cpp:619 computes
    //   const bool validForFeeEstimation =
    //     !tx.m_mempool_limit_bypassed &&
    //     !tx.m_submitted_in_package &&
    //     tx.m_chainstate_is_current &&
    //     tx.m_has_no_mempool_parents;
    // and bumps untrackedTxs without feeding the estimator when false.
    //
    // clearbit's addTransaction at mempool.zig:1429-1433 calls
    // trackTransaction unconditionally on every successful add.  Confirmed
    // by source-grep + behavioral test below.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "validForFeeEstimation"));
    try testing.expect(!contains(mp_src, "m_mempool_limit_bypassed"));
    try testing.expect(!contains(mp_src, "m_submitted_in_package"));
    try testing.expect(!contains(mp_src, "m_chainstate_is_current"));
    try testing.expect(!contains(mp_src, "m_has_no_mempool_parents"));
}

// ===========================================================================
// G10 — BUG-10: No txHeight != nBestSeenHeight skip in processTransaction
// ===========================================================================
test "w139 G10: BUG-10 no nBestSeenHeight tracking + height-mismatch reorg skip" {
    // Core block_policy_estimator.cpp:607-613 skips processTransaction when
    // tx.info.txHeight != nBestSeenHeight (re-org / side-chain protection).
    //
    // clearbit's FeeEstimator only has `current_height` (updated in
    // processBlock), no `nBestSeenHeight`, and trackTransaction does not
    // compare the incoming `height` against it.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "nBestSeenHeight"));
    // trackTransaction signature has no skip-logic — verify behaviorally.
    var est = FeeEstimator.init(a);
    defer est.deinit();
    est.current_height = 100;
    const txid = [_]u8{0xA1} ** 32;
    // Track with a height 50 BELOW current_height (would-be reorg) — Core
    // would skip; clearbit accepts.
    try est.trackTransaction(txid, 5.0, 50);
    try testing.expectEqual(@as(usize, 1), est.trackedCount());
}

// ===========================================================================
// G11 — BUG-11: No nBlockHeight <= nBestSeenHeight skip in processBlock
// ===========================================================================
test "w139 G11: BUG-11 processBlock has no side-chain / reorg height guard" {
    // Core block_policy_estimator.cpp:673-680 short-circuits when
    // nBlockHeight <= nBestSeenHeight (Core says: assuming attacker can
    // reorg at will, you have bigger problems than fee estimates).
    //
    // clearbit's processBlock unconditionally applies decay + advances
    // current_height to whatever was passed.  A reorg that calls
    // processBlock(N) twice for the same height N applies decay twice
    // (double-discounting historical data) and replays confirmations.
    const a = testing.allocator;
    var est = FeeEstimator.init(a);
    defer est.deinit();
    // Seed total_counts so decay is observable.
    for (0..50) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xB2;
        try est.trackTransaction(txid, 5.0, 100);
    }
    const bucket = est.feeToBucket(5.0);
    const t0 = est.total_counts[bucket];
    // Process block 200 — first time, advances height to 200.
    est.processBlock(200);
    const t1 = est.total_counts[bucket];
    // Decayed → strictly less than t0.
    try testing.expect(t1 < t0);
    // Process block 200 AGAIN — Core would skip; clearbit decays again.
    est.processBlock(200);
    const t2 = est.total_counts[bucket];
    // Double-decay observable: t2 < t1.  (Pinning current behavior.)
    try testing.expect(t2 < t1);
    // And current_height is still 200 (assignment, not guard).
    try testing.expectEqual(@as(u32, 200), est.current_height);
}

// ===========================================================================
// G12 — BUG-12: Duplicate trackTransaction silently overwrites bucket index
// ===========================================================================
test "w139 G12: BUG-12 duplicate trackTransaction overwrites bucket; Core logs+returns" {
    // Core block_policy_estimator.cpp:601-605:
    //   if (mapMemPoolTxs.contains(hash)) {
    //       LogDebug(...,"Blockpolicy error mempool tx %s already being tracked");
    //       return;
    //   }
    // clearbit's trackTransaction uses `put` which overwrites silently AND
    // increments total_counts AGAIN (double-counting the bucket).
    const a = testing.allocator;
    var est = FeeEstimator.init(a);
    defer est.deinit();
    const txid = [_]u8{0xC3} ** 32;
    try est.trackTransaction(txid, 5.0, 100);
    const bucket = est.feeToBucket(5.0);
    try testing.expectEqual(@as(u32, 1), est.total_counts[bucket]);
    // Re-track with a different fee rate (different bucket) — bug: both
    // counters increment but only the LATEST bucket is remembered for
    // confirmation.
    try est.trackTransaction(txid, 50.0, 100);
    const second_bucket = est.feeToBucket(50.0);
    try testing.expect(bucket != second_bucket);
    // Original bucket still counts the duplicate (never decremented).
    try testing.expectEqual(@as(u32, 1), est.total_counts[bucket]);
    // New bucket also counts it.
    try testing.expectEqual(@as(u32, 1), est.total_counts[second_bucket]);
    // trackedCount() still reports 1 (HashMap put overwrote the entry).
    try testing.expectEqual(@as(usize, 1), est.trackedCount());
}

// ===========================================================================
// G13 — BUG-13: No firstRecordedHeight field
// ===========================================================================
test "w139 G13: BUG-13 no firstRecordedHeight field on estimator" {
    // Core block_policy_estimator.h:279 declares
    // `unsigned int firstRecordedHeight GUARDED_BY(...) {0};`
    // set in processBlock on the first block that yields a counted tx
    // (cpp:704-707).  Required for BlockSpan().  clearbit has no such field.
    try testing.expect(!@hasField(FeeEstimator, "firstRecordedHeight"));
    try testing.expect(!@hasField(FeeEstimator, "first_recorded_height"));
}

// ===========================================================================
// G14 — BUG-14: No BlockSpan() getter
// ===========================================================================
test "w139 G14: BUG-14 no BlockSpan / blockSpan getter" {
    // Core block_policy_estimator.cpp:780-786.  Returns
    // `nBestSeenHeight - firstRecordedHeight` (or 0 if not yet recorded).
    try testing.expect(!@hasDecl(FeeEstimator, "blockSpan"));
    try testing.expect(!@hasDecl(FeeEstimator, "BlockSpan"));
    try testing.expect(!@hasDecl(FeeEstimator, "block_span"));
}

// ===========================================================================
// G15 — BUG-15: No historicalFirst / historicalBest fields
// ===========================================================================
test "w139 G15: BUG-15 no historicalFirst / historicalBest fields" {
    // Core block_policy_estimator.h:280-281.  Set from fee_estimates.dat
    // load and used by HistoricalBlockSpan().  clearbit's loadFromFile only
    // restores current_height, not historical span.
    try testing.expect(!@hasField(FeeEstimator, "historicalFirst"));
    try testing.expect(!@hasField(FeeEstimator, "historicalBest"));
    try testing.expect(!@hasField(FeeEstimator, "historical_first"));
    try testing.expect(!@hasField(FeeEstimator, "historical_best"));
}

// ===========================================================================
// G16 — BUG-16: No OLDEST_ESTIMATE_HISTORY constant
// ===========================================================================
test "w139 G16: BUG-16 no OLDEST_ESTIMATE_HISTORY = 6*1008 constant" {
    // Core block_policy_estimator.h:160:
    //   static const unsigned int OLDEST_ESTIMATE_HISTORY = 6 * 1008;
    // (≈ 6 weeks).  Used by HistoricalBlockSpan to invalidate too-old
    // historical data.  clearbit has neither the constant nor the check.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "OLDEST_ESTIMATE_HISTORY"));
    try testing.expect(!contains(mp_src, "oldest_estimate_history"));
}

// ===========================================================================
// G17 — BUG-17: No MaxUsableEstimate clamping
// ===========================================================================
test "w139 G17: BUG-17 estimateFee does not clamp to MaxUsableEstimate" {
    // Core block_policy_estimator.cpp:798-802:
    //   return std::min(longStats->GetMaxConfirms(),
    //                   std::max(BlockSpan(), HistoricalBlockSpan()) / 2);
    // estimateSmartFee at cpp:892-894 clamps confTarget to this.
    //
    // Behavioral consequence in clearbit: a fresh node (BlockSpan=0,
    // HistoricalBlockSpan=0) should clamp every conf_target to 0 (no
    // estimate); instead clearbit's estimateFee happily walks all 1008
    // periods and returns a bucket whenever the success-rate gate
    // happens to be met by injected data.
    const a = testing.allocator;
    var est = FeeEstimator.init(a);
    defer est.deinit();
    // Inject data straight into bucket without any block processing →
    // BlockSpan would be 0 in Core.
    for (0..15) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xD4;
        try est.trackTransaction(txid, 10.0, 100);
        est.confirmTransaction(txid, 101);
    }
    // Core would refuse this estimate (max usable = 0).  clearbit returns one.
    const e = est.estimateFee(1000);
    try testing.expect(e != null);
    // Also: no maxUsableEstimate / max_usable_estimate function exists.
    try testing.expect(!@hasDecl(FeeEstimator, "maxUsableEstimate"));
    try testing.expect(!@hasDecl(FeeEstimator, "max_usable_estimate"));
}

// ===========================================================================
// G18 — BUG-18: No estimateCombinedFee shortest-horizon dispatch helper
// ===========================================================================
test "w139 G18: BUG-18 no estimateCombinedFee helper / checkShorterHorizon" {
    // Core block_policy_estimator.cpp:804-842.  `selectHorizon` exists in
    // clearbit (mempool.zig:7010) but it's only a switch, not the full
    // Core helper that ALSO checks shorter horizons at their max-target.
    try testing.expect(!@hasDecl(FeeEstimator, "estimateCombinedFee"));
    try testing.expect(!@hasDecl(FeeEstimator, "estimate_combined_fee"));
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "checkShorterHorizon"));
    try testing.expect(!contains(mp_src, "check_shorter_horizon"));
}

// ===========================================================================
// G19 — BUG-19: No checkShorterHorizon cross-horizon lookback semantic
// ===========================================================================
test "w139 G19: BUG-19 cross-horizon lookback for monotonic estimates absent" {
    // Core block_policy_estimator.cpp:822-839: if a longer-horizon estimate
    // is HIGHER than the shorter one, take the shorter for monotonicity.
    // clearbit's selectHorizon dispatches once and uses only that horizon's
    // answer.
    //
    // Test: with data only in the SHORT horizon's periods, query target=24
    // (MED horizon).  Core would lookback into SHORT-at-max and might
    // return a lower estimate; clearbit returns whatever MED says alone.
    const a = testing.allocator;
    var est = FeeEstimator.init(a);
    defer est.deinit();
    // Inject data at SHORT-horizon periods only.  blocks_to_confirm=2 fills
    // SHORT slots [2..12); MED slot 1 is also filled (period=ceil(2/2)=1).
    // We query target=3 (SHORT, p_idx=2 — filled) and target=4 (SHORT,
    // p_idx=3 — also filled).  Both should be hits.
    for (0..15) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xE5;
        try est.trackTransaction(txid, 20.0, 100);
        est.confirmTransaction(txid, 102); // blocks_to_confirm=2 → SHORT period 2.
    }
    const e_short = est.estimateFee(3); // SHORT p_idx=2 — should find data.
    // Core's checkShorterHorizon would also consult MED at its max-target
    // (48) and take the lower of the two for monotonicity.  clearbit's
    // selectHorizon picks one horizon and uses only that.  Pin the
    // single-horizon return:
    try testing.expect(e_short != null);
    // A target requiring MED (target=24 → MED p_idx=11; data exists since
    // 1..24 all got +1) also returns; clearbit returns SOMETHING for each
    // target independently with no cross-horizon comparison.
    const e_med = est.estimateFee(24);
    try testing.expect(e_med != null);
    // Core's checkShorterHorizon would compare e_short vs e_med; clearbit
    // does not.  Documented.
}

// ===========================================================================
// G20 — BUG-20: No estimateConservativeFee max(feeStats, longStats) helper
// ===========================================================================
test "w139 G20: BUG-20 no estimateConservativeFee helper / 2*target longStats max" {
    // Core block_policy_estimator.cpp:847-862:
    //   if (doubleTarget <= shortStats->GetMaxConfirms())
    //     estimate = feeStats->EstimateMedianVal(doubleTarget, ...)
    //   if (doubleTarget <= feeStats->GetMaxConfirms())
    //     longEstimate = longStats->EstimateMedianVal(doubleTarget, ...);
    //     if (longEstimate > estimate) estimate = longEstimate;
    try testing.expect(!@hasDecl(FeeEstimator, "estimateConservativeFee"));
    try testing.expect(!@hasDecl(FeeEstimator, "estimate_conservative_fee"));
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    // The helper itself is absent (unrelated comments may use the word
    // "conservative" — narrow to estimator-specific identifiers).
    try testing.expect(!contains(mp_src, "estimateConservativeFee"));
    try testing.expect(!contains(mp_src, "estimate_conservative_fee"));
    try testing.expect(!contains(mp_src, "estimateConservative"));
    try testing.expect(!contains(mp_src, "doubleTarget"));
    try testing.expect(!contains(mp_src, "DOUBLE_SUCCESS_PCT"));
    try testing.expect(!contains(mp_src, "HALF_SUCCESS_PCT"));
}

// ===========================================================================
// G21 — BUG-21: No FlushUnconfirmed shutdown sweep
// ===========================================================================
test "w139 G21: BUG-21 no FlushUnconfirmed shutdown sweep recording failures" {
    // Core block_policy_estimator.cpp:1064-1076: at shutdown (via Flush())
    // every still-tracked tx is removed via _removeTx(hash, /*inBlock=*/false),
    // which records it as a failure (failAvg).  clearbit has no analog —
    // tracked txs on shutdown just disappear from the HashMap when the
    // estimator is deinit'd, and never reach failAvg (which doesn't exist).
    try testing.expect(!@hasDecl(FeeEstimator, "flushUnconfirmed"));
    try testing.expect(!@hasDecl(FeeEstimator, "flush_unconfirmed"));
    try testing.expect(!@hasDecl(FeeEstimator, "FlushUnconfirmed"));
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "FlushUnconfirmed"));
    try testing.expect(!contains(mp_src, "flushUnconfirmed"));
}

// ===========================================================================
// G22 — BUG-22: No MAX_FILE_AGE = 60h rejection in loadFromFile
// ===========================================================================
test "w139 G22: BUG-22 loadFromFile has no MAX_FILE_AGE = 60h staleness check" {
    // Core block_policy_estimator.h:32:
    //   static constexpr std::chrono::hours MAX_FILE_AGE{60};
    // Default DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false (h:35).
    // Constructor cpp:568-572: if file_age > MAX_FILE_AGE && !accept_stale → skip.
    //
    // clearbit's loadFromFile (mempool.zig:7125) only checks magic + version;
    // any-age file is loaded.  (W114 G24 saw this from a behavioral angle;
    // W139 confirms the named constant absence.)
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "MAX_FILE_AGE"));
    try testing.expect(!contains(mp_src, "max_file_age"));
    try testing.expect(!contains(mp_src, "DEFAULT_ACCEPT_STALE_FEE_ESTIMATES"));
    try testing.expect(!contains(mp_src, "read_stale_estimates"));
}

// ===========================================================================
// G23 — BUG-23: No FEE_FLUSH_INTERVAL = 1h periodic save
// ===========================================================================
test "w139 G23: BUG-23 no FEE_FLUSH_INTERVAL periodic save scheduler" {
    // Core block_policy_estimator.h:26: FEE_FLUSH_INTERVAL = 1h.  Core
    // calls FlushFeeEstimates() on an hourly timer in init.cpp.
    //
    // clearbit's main.zig saves only at shutdown (line 2284-2286); no
    // periodic scheduler.  Unclean shutdown loses up to entire session.
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    const main_src = try loadSrc(a, "main");
    defer a.free(main_src);
    try testing.expect(!contains(mp_src, "FEE_FLUSH_INTERVAL"));
    try testing.expect(!contains(mp_src, "fee_flush_interval"));
    try testing.expect(!contains(main_src, "FEE_FLUSH_INTERVAL"));
    // No FlushFeeEstimates method either.
    try testing.expect(!@hasDecl(FeeEstimator, "flushFeeEstimates"));
    try testing.expect(!@hasDecl(FeeEstimator, "flush_fee_estimates"));
}

// ===========================================================================
// G24 — BUG-24: No GetFeeEstimatorFileAge() helper
// ===========================================================================
test "w139 G24: BUG-24 no GetFeeEstimatorFileAge / file mtime helper" {
    // Core block_policy_estimator.cpp:1078-1083 + h:264 declares the helper.
    // Required to implement BUG-22 + sanity at startup.
    try testing.expect(!@hasDecl(FeeEstimator, "getFeeEstimatorFileAge"));
    try testing.expect(!@hasDecl(FeeEstimator, "get_fee_estimator_file_age"));
    try testing.expect(!@hasDecl(FeeEstimator, "fileAge"));
    const a = testing.allocator;
    const mp_src = try loadSrc(a, "mempool");
    defer a.free(mp_src);
    try testing.expect(!contains(mp_src, "GetFeeEstimatorFileAge"));
}

// ===========================================================================
// G25 — BUG-25: No ParseConfirmTarget helper
// ===========================================================================
test "w139 G25: BUG-25 no central ParseConfirmTarget helper; each RPC clamps differently" {
    // Core common/messages.h declares ParseConfirmTarget; used by both
    // estimatesmartfee (rpc/fees.cpp:71) and estimaterawfee (cpp:159).
    //
    // clearbit's handleEstimateSmartFee (rpc.zig:11142) uses
    //   const conf_target: u32 = @intCast(@max(1, @min(1008, target_param.integer)));
    // — clamps silently (returns target=1008 for any over-large input).
    //
    // clearbit's handleEstimateRawFee (rpc.zig:11187) uses
    //   if (conf_target_i < 1 or conf_target_i > 1008) return InvalidParameter;
    // — REJECTS out-of-range input.
    //
    // Different RPCs, different validation strategies — both wrong vs Core
    // which uses the same helper for consistency.
    const a = testing.allocator;
    const rpc_src = try loadSrc(a, "rpc");
    defer a.free(rpc_src);
    try testing.expect(!contains(rpc_src, "ParseConfirmTarget"));
    try testing.expect(!contains(rpc_src, "parseConfirmTarget"));
    try testing.expect(!contains(rpc_src, "parse_confirm_target"));
    // Confirm divergent inline clamp/reject style by verifying both literal patterns.
    try testing.expect(contains(rpc_src, "@max(1, @min(1008,"));
    try testing.expect(contains(rpc_src, "< 1 or conf_target_i > 1008"));
}

// ===========================================================================
// G26 — BUG-26: estimaterawfee emits degenerate pass.startrange/endrange
// ===========================================================================
test "w139 G26: BUG-26 estimaterawfee pass.startrange/endrange both = rate; bucket bounds absent" {
    // Core rpc/fees.cpp:181-194 emits real bucket bounds + the moving-
    // average counts (withintarget / totalconfirmed / inmempool / leftmempool).
    //
    // clearbit's handleEstimateRawFee (rpc.zig:11237-11239):
    //   try w.print("\"startrange\":{d:.0},\"endrange\":{d:.0}", .{ rate, rate });
    //   try w.writeAll(",\"withintarget\":0,\"totalconfirmed\":0,\"inmempool\":0,\"leftmempool\":0}");
    // Both ranges = `rate` (a single number, not a bucket span); counts
    // hardcoded to 0.  Confirms by grep.
    const a = testing.allocator;
    const rpc_src = try loadSrc(a, "rpc");
    defer a.free(rpc_src);
    // Look for the two telltale fragments separately (avoids brittle full-
    // line matches across Zig string escapes).
    try testing.expect(contains(rpc_src, "startrange"));
    try testing.expect(contains(rpc_src, "endrange"));
    try testing.expect(contains(rpc_src, ".{ rate, rate }"));
    // The source-bytes have backslash-escaped quotes (Zig source literal).
    // Use the literal byte sequence directly.
    try testing.expect(contains(rpc_src, "\\\"withintarget\\\":0,\\\"totalconfirmed\\\":0,\\\"inmempool\\\":0,\\\"leftmempool\\\":0"));
}

// ===========================================================================
// G27 — BUG-27: Locking surface (mempool.mutex broad vs Core m_cs_fee_estimator)
// ===========================================================================
test "w139 G27: BUG-27 fee_estimator has no dedicated mutex; uses mempool.mutex" {
    // Core block_policy_estimator.h:276:
    //   mutable Mutex m_cs_fee_estimator;
    // Scoped to the estimator alone.
    //
    // clearbit's handleEstimateSmartFee (rpc.zig:11145-11146):
    //   self.mempool.mutex.lock();
    //   defer self.mempool.mutex.unlock();
    // locks the WHOLE mempool around the read, which serializes against
    // every mempool admission / eviction.  Higher contention surface.
    try testing.expect(!@hasField(FeeEstimator, "mutex"));
    try testing.expect(!@hasField(FeeEstimator, "cs"));
    try testing.expect(!@hasField(FeeEstimator, "m_cs_fee_estimator"));
    const a = testing.allocator;
    const rpc_src = try loadSrc(a, "rpc");
    defer a.free(rpc_src);
    // Both RPC handlers lock mempool.mutex (not a separate estimator mutex).
    try testing.expect(contains(rpc_src, "self.mempool.mutex.lock();"));
}

// ===========================================================================
// G28 — partial / no-bug: FeeestPath canonical filename
// ===========================================================================
test "w139 G28: PARTIAL fee_estimates.dat canonical filename wired in main.zig" {
    // Core block_policy_estimator_args.cpp:10: FEE_ESTIMATES_FILENAME = "fee_estimates.dat".
    // clearbit's main.zig:1807-1810 already uses "{s}/fee_estimates.dat".
    // PARTIAL: filename correct, but the args.h-style helper (FeeestPath)
    // doesn't exist as a separate module — it's inline in main.zig.
    const a = testing.allocator;
    const main_src = try loadSrc(a, "main");
    defer a.free(main_src);
    try testing.expect(contains(main_src, "fee_estimates.dat"));
    // No FeeestPath / feeestPath helper module — path constructed inline
    // (PARTIAL: filename correct, helper absence is a minor style gap, not
    // a behavioral bug).  Note: `fee_est_path` is the var name in main.zig
    // line 1807 — that's the inline construction site, not the helper.
    try testing.expect(!contains(main_src, "FeeestPath"));
    try testing.expect(!contains(main_src, "feeestPath"));
    // The path is constructed inline (PARTIAL — no helper module).
}

// ===========================================================================
// G29 — BUG-28: handleEstimateSmartFee missing min_mempool_feerate floor
// ===========================================================================
test "w139 G29: BUG-28 handleEstimateSmartFee returns rate without min_mempool_feerate / min_relay_feerate floor" {
    // Core rpc/fees.cpp:83-85:
    //   CFeeRate min_mempool_feerate{mempool.GetMinFee()};
    //   CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
    //   feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
    //
    // clearbit's handleEstimateSmartFee (rpc.zig:11148-11157) returns the
    // estimator's raw output without floor.  W114 G20 saw this from the
    // estimator side — W139 G29 confirms at the RPC boundary by grepping
    // the handler for either `getMinFee` or `min_relay_fee` usage adjacent
    // to the smartfee response.
    const a = testing.allocator;
    const rpc_src = try loadSrc(a, "rpc");
    defer a.free(rpc_src);
    // The smartfee handler is between line 11132-11164.  Extract and inspect.
    const start = std.mem.indexOf(u8, rpc_src, "fn handleEstimateSmartFee") orelse return error.HandlerMissing;
    const end_idx = std.mem.indexOfPos(u8, rpc_src, start, "\n    fn ") orelse rpc_src.len;
    const handler = rpc_src[start..end_idx];
    // No floor application in the handler body.
    try testing.expect(!contains(handler, "getMinFee"));
    try testing.expect(!contains(handler, "MIN_RELAY_FEE"));
    try testing.expect(!contains(handler, "min_mempool_feerate"));
    try testing.expect(!contains(handler, "min_relay_feerate"));
}

// ===========================================================================
// G30 — BUG-29: estimatesmartfee max_target hard-coded 1008 (not dynamic)
// ===========================================================================
test "w139 G30: BUG-29 max_target hard-coded 1008; not HighestTargetTracked(LONG)" {
    // Core rpc/fees.cpp:70:
    //   unsigned int max_target = fee_estimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    // Dynamically read from the live estimator.  clearbit clamps to a
    // hard-coded literal `1008` (rpc.zig:11142 + 11187), so any future
    // change to LONG_BLOCK_PERIODS * LONG_SCALE silently desyncs the RPC
    // clamp from the estimator's actual bound.
    const a = testing.allocator;
    const rpc_src = try loadSrc(a, "rpc");
    defer a.free(rpc_src);
    // Hard-coded literal present in BOTH smartfee + rawfee handlers.
    try testing.expect(contains(rpc_src, "@min(1008, target_param.integer))"));
    try testing.expect(contains(rpc_src, "conf_target_i > 1008"));
    // And no use of MAX_CONFIRMATION_TARGET via the constant (which IS
    // what HighestTargetTracked would resolve to in clearbit).
    const start = std.mem.indexOf(u8, rpc_src, "fn handleEstimateSmartFee") orelse return error.HandlerMissing;
    const end_idx = std.mem.indexOfPos(u8, rpc_src, start, "\n    fn ") orelse rpc_src.len;
    const handler = rpc_src[start..end_idx];
    try testing.expect(!contains(handler, "MAX_CONFIRMATION_TARGET"));
    try testing.expect(!contains(handler, "HighestTargetTracked"));
    try testing.expect(!contains(handler, "highestTargetTracked"));
}
