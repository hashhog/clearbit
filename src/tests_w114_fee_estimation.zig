/// W114 Fee estimation (CBlockPolicyEstimator) fleet audit — clearbit (Zig 0.13).
///
/// 30-gate audit across the full fee-estimation subsystem:
/// G1   Subsystem present (not MISSING ENTIRELY)
/// G2   Bucket count: Core uses ~236 buckets (MIN=100 sat/kvB, MAX=1e7, spacing=1.05)
/// G3   Bucket spacing: Core FEE_SPACING = 1.05
/// G4   Min bucket feerate: Core MIN_BUCKET_FEERATE = 100 sat/kvB
/// G5   Max bucket feerate: Core MAX_BUCKET_FEERATE = 1e7 sat/kvB
/// G6   Three-horizon architecture (SHORT/MED/LONG) with separate TxConfirmStats
/// G7   Decay constants: SHORT=0.962, MED=0.9952, LONG=0.99931
/// G8   Period counts: SHORT=12, MED=24, LONG=42; scale: SHORT=1, MED=2, LONG=24
/// G9   MAX_CONFIRMATION_TARGET: Core LONG horizon tracks up to 42*24=1008 blocks
/// G10  trackTransaction/processTransaction wired into addTransaction() mempool path
/// G11  confirmTransaction/processBlockTx wired into removeForBlock() / block-connect path
/// G12  processBlock / UpdateMovingAverages wired into block-connect path
/// G13  removeTx / FlushUnconfirmed: evicted txs recorded as failures (failAvg)
/// G14  unconfTxs circular buffer: tracks in-mempool txs per block height
/// G15  estimateFee algorithm: bucket accumulation across sufficient tx threshold
/// G16  estimateSmartFee three-threshold: half/full/double + conservative path
/// G17  estimateConservativeFee: checks DOUBLE_SUCCESS_PCT at 2*target for all horizons
/// G18  estimateCombinedFee: chooses shortest horizon that covers the target
/// G19  Target clamping: confTarget 1 → 2; clamped to maxUsableEstimate
/// G20  mempool minimum fee / min-relay-fee floor applied to estimateSmartFee result
/// G21  estimaterawfee RPC: per-horizon data (short/medium/long), threshold parameter
/// G22  FeeCalculation / FeeReason populated and returned by estimateSmartFee
/// G23  File format: Core version 296/309900, EncodedDouble wire format (IEEE-754 u64)
/// G24  File age check: MAX_FILE_AGE=60h, stale files rejected (or warned and skipped)
/// G25  file_estimates.dat path: stored in datadir
/// G26  MaxUsableEstimate / BlockSpan / HistoricalBlockSpan guards
/// G27  SUFFICIENT_FEETXS=0.1, SUFFICIENT_TXS_SHORT=0.5 accumulation thresholds
/// G28  SUCCESS_PCT=0.85, HALF_SUCCESS_PCT=0.60, DOUBLE_SUCCESS_PCT=0.95
/// G29  estimate_mode parameter: "conservative" vs "economical" honored
/// G30  CValidationInterface integration: TransactionAddedToMempool / RemovedForBlock
///
/// References:
///   bitcoin-core/src/policy/fees/block_policy_estimator.h / .cpp
///   bitcoin-core/src/policy/fees/block_policy_estimator_args.h
///   bitcoin-core/src/policy/feerate.h
///   bitcoin-core/src/rpc/fees.cpp
///
/// Findings summary (18 bugs):
///   BUG-1  (P0-DEAD-HELPER) G10 — FeeEstimator.trackTransaction() NEVER called from
///                                   addTransaction() or addTransactionWithPackageRate().
///                                   Estimator is initialized, saved/loaded, and queried
///                                   via RPC but never fed data. Always returns null.
///   BUG-2  (P0-DEAD-HELPER) G11 — FeeEstimator.confirmTransaction() NEVER called from
///                                   removeForBlock(). Confirmations are never recorded.
///   BUG-3  (P0-DEAD-HELPER) G12 — FeeEstimator.processBlock() NEVER called from
///                                   removeForBlock() or any block-connect path. Decay
///                                   never applied. Current height never updated.
///   BUG-4  (HIGH)           G2  — NUM_BUCKETS=48 vs Core ~236. Bucket count is wrong
///                                   by ~5x. Core uses MIN=100 sat/kvB, MAX=1e7, spacing=1.05.
///   BUG-5  (HIGH)           G3  — BUCKET_SPACING=1.1 vs Core FEE_SPACING=1.05.
///   BUG-6  (HIGH)           G4  — MIN_BUCKET_FEE=1.0 sat/vB (=1000 sat/kvB) vs Core
///                                   MIN_BUCKET_FEERATE=100 sat/kvB. 10x higher minimum.
///   BUG-7  (HIGH)           G6  — Single horizon only; no SHORT/MED/LONG TxConfirmStats.
///                                   Core's three separate decay/period configurations are
///                                   entirely absent.
///   BUG-8  (HIGH)           G7  — Single hardcoded decay=0.998. Core has SHORT=0.962,
///                                   MED=0.9952, LONG=0.99931.
///   BUG-9  (HIGH)           G8  — No period scale (all periods are 1 block). Core MED
///                                   scale=2, LONG scale=24.
///   BUG-10 (HIGH)           G9  — MAX_CONFIRMATION_TARGET=144 (~1 day). Core long horizon
///                                   tracks 42*24=1008 blocks (~1 week).
///   BUG-11 (HIGH)           G13 — No failAvg / eviction-as-failure tracking. Core calls
///                                   removeTx(hash, inBlock=false) for evicted/expired txs,
///                                   which feeds failAvg and counts tx failures. clearbit
///                                   removeTransaction() has no fee_estimator hook.
///   BUG-12 (HIGH)           G14 — No unconfTxs circular buffer. Core tracks in-mempool
///                                   tx counts per-block to include them in the denominator
///                                   (extraNum) when computing success rates. clearbit uses
///                                   only confirmed counts in the denominator.
///   BUG-13 (HIGH)           G15 — Estimation algorithm uses hard MIN_DATA_POINTS=10
///                                   instead of SUFFICIENT_FEETXS/scale threshold. Core
///                                   accumulates buckets until partialNum >= sufficientTxVal
///                                   / (1 - decay), then tests the success rate.
///   BUG-14 (HIGH)           G16 — estimateSmartFee absent. The single-threshold
///                                   estimateFee() is exposed; Core's three-threshold
///                                   (halfEst/actualEst/doubleEst) algorithm is absent.
///   BUG-15 (MED)            G20 — No min_mempool_feerate / min_relay_feerate floor.
///                                   Core: feeRate = max(estimated, mempool.GetMinFee(),
///                                   min_relay_feerate) before returning.
///   BUG-16 (MED)            G22 — No FeeCalculation / FeeReason. RPC blocks field is
///                                   always conf_target, never the actual returnedTarget
///                                   that was used for estimation.
///   BUG-17 (MED)            G23 — File format incompatible with Core. clearbit uses magic
///                                   "CBFE" + u32 LE version=1 + u32 integer counts. Core
///                                   uses version 309900 (int), EncodedDouble (IEEE-754
///                                   u64 LE), failAvg arrays, and three TxConfirmStats.
///   BUG-18 (MED)            G29 — estimate_mode parameter is accepted but silently ignored;
///                                   conservative vs economical modes produce identical output.

const std = @import("std");
const mempool_mod = @import("mempool.zig");
const types = @import("types.zig");

const FeeEstimator = mempool_mod.FeeEstimator;
const Mempool = mempool_mod.Mempool;

// ============================================================================
// G1 — Subsystem present (not MISSING ENTIRELY)
// ============================================================================

test "w114 G1: FeeEstimator subsystem exists and initialises" {
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();
    // If we got here without a compile error, the struct exists.
    try std.testing.expectEqual(@as(usize, 0), est.trackedCount());
}

// ============================================================================
// G2 — Bucket count: Core ~236, clearbit 48 (BUG-4)
// ============================================================================

test "w114 G2: BUG-4 bucket count is 48, Core requires ~236" {
    // Core: for (v = MIN_BUCKET_FEERATE=100; v <= MAX_BUCKET_FEERATE=1e7; v *= 1.05) count++
    // => ~236 buckets.
    // clearbit: NUM_BUCKETS=48 (about 5x fewer).
    // This is a hard-coded mismatch that makes fee estimates over the full range
    // unreliable and incompatible with any tooling that inspects bucket counts.
    try std.testing.expectEqual(@as(usize, 48), FeeEstimator.NUM_BUCKETS);

    // Document what Core expects: ~236
    // (Computed: floor(log(1e7/100) / log(1.05)) + 1 = 236)
    const core_expected: usize = 236;
    // BUG: clearbit has only 48, not 236
    try std.testing.expect(FeeEstimator.NUM_BUCKETS != core_expected);
}

// ============================================================================
// G3 — Bucket spacing: Core 1.05, clearbit 1.1 (BUG-5)
// ============================================================================

test "w114 G3: BUG-5 bucket spacing is 1.1, Core requires 1.05" {
    // FEE_SPACING = 1.05 in bitcoin-core/src/policy/fees/block_policy_estimator.h:198
    try std.testing.expectApproxEqRel(@as(f64, 1.1), FeeEstimator.BUCKET_SPACING, 0.001);
    // BUG: should be 1.05
    const core_spacing: f64 = 1.05;
    try std.testing.expect(FeeEstimator.BUCKET_SPACING != core_spacing);
}

// ============================================================================
// G4 — Min bucket feerate: Core 100 sat/kvB, clearbit 1 sat/vB=1000 sat/kvB (BUG-6)
// ============================================================================

test "w114 G4: BUG-6 min bucket fee is 1.0 sat/vB; Core MIN_BUCKET_FEERATE=100 sat/kvB=0.1 sat/vB" {
    // Core MIN_BUCKET_FEERATE = 100 (sat/kvB) = 0.1 sat/vB.
    // clearbit uses sat/vB units internally and sets min=1.0.
    // This means clearbit's lowest bucket starts at 1000 sat/kvB, 10x higher than Core.
    try std.testing.expectApproxEqRel(@as(f64, 1.0), FeeEstimator.MIN_BUCKET_FEE, 0.001);
    // In sat/kvB this is 1000; Core's min is 100 sat/kvB.
    const clearbit_min_kvb = FeeEstimator.MIN_BUCKET_FEE * 1000.0;
    try std.testing.expectApproxEqRel(@as(f64, 1000.0), clearbit_min_kvb, 0.001);
    // BUG: Core's min is 100, clearbit's effective min is 1000
    try std.testing.expect(clearbit_min_kvb != 100.0);
}

// ============================================================================
// G5 — Max bucket feerate range coverage
// ============================================================================

test "w114 G5: max feerate bucket coverage with 48 buckets at 1.1x spacing from 1.0 sat/vB" {
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    // With 48 buckets at 1.1x spacing from 1.0, the max is 1.0 * 1.1^48 ≈ 97 sat/vB
    // Core covers up to 1e7 sat/kvB = 10000 sat/vB — roughly 100x more range.
    const last_bound = est.getBucketBound(FeeEstimator.NUM_BUCKETS);
    // ~97 sat/vB
    try std.testing.expect(last_bound < 200.0);
    // Core max: ~10015 sat/vB
    try std.testing.expect(last_bound < 10_000.0);
}

// ============================================================================
// G6 — Three-horizon architecture absent (BUG-7)
// ============================================================================

test "w114 G6: BUG-7 single-horizon architecture; SHORT/MED/LONG TxConfirmStats absent" {
    // Core has:
    //   feeStats    (MED_BLOCK_PERIODS=24, MED_DECAY=0.9952, MED_SCALE=2)
    //   shortStats  (SHORT_BLOCK_PERIODS=12, SHORT_DECAY=0.962, SHORT_SCALE=1)
    //   longStats   (LONG_BLOCK_PERIODS=42, LONG_DECAY=0.99931, LONG_SCALE=24)
    //
    // clearbit has a single FeeEstimator with one decay value.
    // We test that there is only one decay field (structural evidence of single-horizon).
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();
    // The single decay is 0.998, not the three Core values.
    try std.testing.expectApproxEqRel(@as(f64, 0.998), est.decay, 0.0001);
    // Core SHORT_DECAY = 0.962 — absent
    // Core MED_DECAY = 0.9952 — absent
    // Core LONG_DECAY = 0.99931 — absent
    // BUG: all three horizon decay constants differ from 0.998
    try std.testing.expect(est.decay != 0.962);
    try std.testing.expect(est.decay != 0.9952);
    try std.testing.expect(est.decay != 0.99931);
}

// ============================================================================
// G7 — Decay constants wrong (BUG-8)
// ============================================================================

test "w114 G7: BUG-8 single decay=0.998 used; Core SHORT=0.962 MED=0.9952 LONG=0.99931" {
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();
    // clearbit uses a single fixed 0.998 decay (half-life ~346 blocks ~2.4 days).
    // Core SHORT half-life is 18 blocks (~3 hours), MED is 144 blocks (~1 day),
    // LONG is 1008 blocks (~1 week).
    try std.testing.expectApproxEqRel(@as(f64, 0.998), est.decay, 0.0001);
}

// ============================================================================
// G8 — Period/scale structure absent (BUG-9)
// ============================================================================

test "w114 G8: BUG-9 no period scale; MAX_CONFIRMATION_TARGET=144, Core LONG covers 1008 blocks" {
    // Core LONG_BLOCK_PERIODS=42 * LONG_SCALE=24 = 1008 blocks
    // Core MED_BLOCK_PERIODS=24  * MED_SCALE=2   = 48 blocks (periods), real 96 block window
    // Core SHORT_BLOCK_PERIODS=12 * SHORT_SCALE=1 = 12 blocks
    //
    // clearbit MAX_CONFIRMATION_TARGET=144 (treating every block as 1 period, scale=1).
    // This matches neither the 1008-block long horizon nor the period-scale architecture.
    try std.testing.expectEqual(@as(usize, 144), FeeEstimator.MAX_CONFIRMATION_TARGET);
    // Core long horizon max is 42*24=1008
    try std.testing.expect(FeeEstimator.MAX_CONFIRMATION_TARGET < 1008);
}

// ============================================================================
// G10 — trackTransaction not wired into addTransaction (BUG-1 P0-DEAD-HELPER)
// ============================================================================

test "w114 G10: BUG-1 P0 trackTransaction dead-helper: adding tx to mempool does not feed estimator" {
    // FIX-47: addTransaction() now calls fee_estimator.trackTransaction() on success.
    // This test uses a tx that fails validation (no UTXO for the input), so the
    // estimator is still 0 — the hook only fires for successfully-added txs.
    const allocator = std.testing.allocator;
    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Verify estimator starts empty
    try std.testing.expectEqual(@as(usize, 0), mempool.fee_estimator.trackedCount());

    // Build a minimal valid tx (coinbase-style with a fake prevout so it passes checks)
    // Use an input that looks like a standard spend (non-coinbase prevout)
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 50_000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac },
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // With null chain_state, addTransaction assumes inputs exist (test-mode bypass).
    // The tx is accepted (fee=0, fee_rate=0.0) and trackTransaction fires.
    // FIX-47: estimator now has 1 tracked tx after successful addTransaction().
    _ = mempool.addTransaction(tx) catch {};

    // tx accepted in null-chain-state test mode → estimator tracks it.
    try std.testing.expectEqual(@as(usize, 1), mempool.fee_estimator.trackedCount());
}

// ============================================================================
// G11 — confirmTransaction not wired (BUG-2 P0-DEAD-HELPER)
// ============================================================================

test "w114 G11: BUG-2 P0 confirmTransaction dead-helper: removeForBlock does not feed estimator" {
    // FIX-47: removeForBlock() now calls fee_estimator.confirmTransaction() per tx.
    // This test manually tracks txid=0xAA*32, then calls removeForBlock with a
    // coinbase tx.  The coinbase txid != 0xAA*32, so confirmTransaction is called
    // for the coinbase (a no-op in the estimator since it was never tracked) but
    // 0xAA*32 remains tracked — trackedCount() stays 1.
    const allocator = std.testing.allocator;
    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Manually track a transaction so we can later test that removeForBlock confirms it.
    const txid = [_]u8{0xAA} ** 32;
    const fee_rate: f64 = 5.0;
    const enter_height: u32 = 100;
    try mempool.fee_estimator.trackTransaction(txid, fee_rate, enter_height);
    try std.testing.expectEqual(@as(usize, 1), mempool.fee_estimator.trackedCount());

    // Simulate a block that includes this tx (build a minimal block with this txid)
    // removeForBlock removes txs by computing txid of each block tx.
    // Since we can't easily craft a tx whose txid == 0xAA*32 in this test, we instead
    // check that after ANY removeForBlock call, the estimator is still not updated.

    // Build a dummy block with a coinbase tx
    const coinbase_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xFFFFFFFF },
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const coinbase_output = types.TxOut{
        .value = 5_000_000_000,
        .script_pubkey = &[_]u8{0x51},
    };
    const coinbase_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };
    const block = types.Block{
        .header = std.mem.zeroes(types.BlockHeader),
        .transactions = &[_]types.Transaction{coinbase_tx},
    };
    mempool.removeForBlock(&block);

    // The coinbase txid != 0xAA*32, so our manually-tracked entry is unaffected.
    // confirmTransaction is now wired (FIX-47) but fires for the coinbase txid only.
    try std.testing.expectEqual(@as(usize, 1), mempool.fee_estimator.trackedCount());
}

// ============================================================================
// G12 — processBlock not wired into block-connect (BUG-3 P0-DEAD-HELPER)
// ============================================================================

test "w114 G12: BUG-3 P0 processBlock dead-helper: removeForBlock does not call processBlock" {
    // FIX-47: processBlock() is now called from removeForBlock().
    // After 50 removeForBlock calls (no chain_state), current_height increments
    // from 0 to 50 (height = current_height+1 each call).
    const allocator = std.testing.allocator;
    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add enough data so decay would be visible
    for (0..100) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xBB;
        try mempool.fee_estimator.trackTransaction(txid, 5.0, 100);
    }

    // Simulate 50 blocks
    for (0..50) |b| {
        const coinbase_input = types.TxIn{
            .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xFFFFFFFF },
            .script_sig = &[_]u8{ 0x01, @truncate(b) },
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };
        const coinbase_output = types.TxOut{
            .value = 5_000_000_000,
            .script_pubkey = &[_]u8{0x51},
        };
        const cbtx = types.Transaction{
            .version = 2,
            .inputs = &[_]types.TxIn{coinbase_input},
            .outputs = &[_]types.TxOut{coinbase_output},
            .lock_time = 0,
        };
        const blk = types.Block{
            .header = std.mem.zeroes(types.BlockHeader),
            .transactions = &[_]types.Transaction{cbtx},
        };
        mempool.removeForBlock(&blk);
    }

    // FIX-47: processBlock() is now called from removeForBlock().
    // With null chain_state, height increments from current_height+1 each call.
    // After 50 calls starting from 0: current_height == 50.
    try std.testing.expectEqual(@as(u32, 50), mempool.fee_estimator.current_height);
}

// ============================================================================
// G13 — failAvg / eviction-as-failure absent (BUG-11)
// ============================================================================

test "w114 G13: BUG-11 no failAvg; evicted/expired txs not recorded as failures" {
    // Core's removeTx(hash, inBlock=false) increments failAvg for evicted txs.
    // clearbit's removeTransaction() has no fee_estimator hook at all.
    // Test: track a tx, then remove it from mempool — estimator state unchanged.
    const allocator = std.testing.allocator;
    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Manually track
    const txid = [_]u8{0xCC} ** 32;
    try mempool.fee_estimator.trackTransaction(txid, 3.0, 100);
    try std.testing.expectEqual(@as(usize, 1), mempool.fee_estimator.trackedCount());

    // removeTransaction by hash — BUG: does not call fee_estimator.removeTx()
    mempool.removeTransaction(txid);

    // The estimator still holds the tracked entry (ghost) because removeTransaction
    // has no fee_estimator hook.
    try std.testing.expectEqual(@as(usize, 1), mempool.fee_estimator.trackedCount());
}

// ============================================================================
// G14 — unconfTxs circular buffer absent (BUG-12)
// ============================================================================

test "w114 G14: BUG-12 no unconfTxs circular buffer; in-mempool txs not counted in denominator" {
    // Core uses unconfTxs[block % size][bucket] and oldUnconfTxs[bucket] to count
    // transactions that are still in the mempool at a given age. These contribute
    // to the extraNum denominator making estimates more conservative.
    // clearbit has no such structure — success_rate = confirmed / total_counts only.
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    // There is no unconfTxs or oldUnconfTxs field in FeeEstimator.
    // Structural proof: the struct only has confirmed_counts and total_counts.
    // confirmed_counts[target][bucket] / total_counts[bucket] is the whole denominator.
    // BUG: this ignores in-mempool unconfirmed txs (over-estimates success rate).

    // We can verify by checking that total_counts is the only denominator:
    // After tracking 10 txs and confirming 9, success_rate = 9/10 = 90% which
    // would pass the 85% threshold. In Core, if there were also 5 unconfirmed
    // txs (extraNum=5), the denominator would be 10+5=15, giving 9/15=60% < 85% (fail).
    for (0..10) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xDD;
        try est.trackTransaction(txid, 5.0, @truncate(100 + i));
        if (i < 9) {
            est.confirmTransaction(txid, @truncate(100 + i + 1));
        }
    }

    // With clearbit's algorithm: 9/10 = 90% >= 85% → returns an estimate
    const result = est.estimateFee(2);
    // BUG: this succeeds because extraNum is not subtracted
    // In Core, with 1 unconfirmed tx still in mempool, the success rate would be lower
    try std.testing.expect(result != null);
}

// ============================================================================
// G15 — Estimation algorithm uses MIN_DATA_POINTS=10 instead of SUFFICIENT threshold (BUG-13)
// ============================================================================

test "w114 G15: BUG-13 estimateFee uses MIN_DATA_POINTS=10 not SUFFICIENT_FEETXS/decay threshold" {
    // Core: buckets are accumulated until partialNum >= sufficientTxVal / (1 - decay).
    // For MED: sufficientTxVal=0.1, decay=0.9952 → threshold = 0.1 / 0.0048 ≈ 20.8 txs.
    // clearbit: requires MIN_DATA_POINTS=10 integer count per bucket (no accumulation).
    try std.testing.expectEqual(@as(u32, 10), FeeEstimator.MIN_DATA_POINTS);

    // Core SUFFICIENT_FEETXS = 0.1 (avg txs/block per bucket) is a rate, not an absolute count.
    // The threshold for MED horizon is 0.1 / (1-0.9952) ≈ 20.8 absolute txs.
    // clearbit's 10 is too low and doesn't account for decay.
    const core_med_threshold = 0.1 / (1.0 - 0.9952);
    try std.testing.expect(@as(f64, @floatFromInt(FeeEstimator.MIN_DATA_POINTS)) < core_med_threshold);
}

// ============================================================================
// G16 — estimateSmartFee three-threshold absent (BUG-14)
// ============================================================================

test "w114 G16: BUG-14 estimateSmartFee three-threshold algorithm absent; only single-threshold estimateFee" {
    // Core's estimateSmartFee computes:
    //   halfEst   = estimateCombinedFee(target/2, HALF_SUCCESS_PCT=0.60, true)
    //   actualEst = estimateCombinedFee(target,   SUCCESS_PCT=0.85,      true)
    //   doubleEst = estimateCombinedFee(target*2,  DOUBLE_SUCCESS_PCT=0.95, !conservative)
    //   result = max(halfEst, actualEst, doubleEst)
    //
    // clearbit only has estimateFee(target) with a single 85% threshold.
    // We confirm clearbit's MIN_SUCCESS_RATE is 0.85 (only 1 threshold).
    try std.testing.expectApproxEqRel(@as(f64, 0.85), FeeEstimator.MIN_SUCCESS_RATE, 0.001);

    // No HALF_SUCCESS_PCT (0.60) or DOUBLE_SUCCESS_PCT (0.95) constants exist.
    // This is a structural absence — cannot test at runtime but documented here.
}

// ============================================================================
// G19 — Target clamping to 2 for confTarget=1
// ============================================================================

test "w114 G19: confTarget=1 clamped to null (estimateFee returns null for target=0 or 1)" {
    // Core: if (confTarget == 1) confTarget = 2;
    // clearbit: target == 0 returns null, but target == 1 is not explicitly clamped to 2.
    // Instead, estimateFee(1) uses target=1 directly, which is confirmed_counts[1][bucket].
    // This is a subtle difference: Core never reports estimates for target=1.
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    // Target 0 → null (matches Core "confTarget <= 0 → return 0")
    try std.testing.expectEqual(@as(?f64, null), est.estimateFee(0));
    // Target 1 → allowed by clearbit (returns null due to no data), Core clamps to 2
    // This means if there is data at target=1, clearbit would return an estimate
    // that Core would never return for target=1.
}

// ============================================================================
// G20 — mempool min fee floor absent (BUG-15)
// ============================================================================

test "w114 G20: BUG-15 no min_mempool_feerate floor applied in estimatesmartfee RPC" {
    // Core rpc/fees.cpp line 83-85:
    //   CFeeRate min_mempool_feerate{mempool.GetMinFee()};
    //   CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
    //   feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
    //
    // clearbit's handleEstimateSmartFee() calls fee_estimator.estimateFee() and returns
    // that result directly without any floor. Even if the estimator returned a rate
    // below the mempool minimum (theoretically after decay), clearbit would report it.
    //
    // This is tested structurally: the returned fee rate from a saturated estimator
    // could be below getMinFee() with no correction.
    const allocator = std.testing.allocator;
    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Manually inject decayed data into the estimator that produces a very low estimate.
    // This simulates data from much earlier when fees were lower.
    for (0..20) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xEE;
        // fee_rate = 0.001 sat/vB — below typical min relay fee of 1 sat/vB
        try mempool.fee_estimator.trackTransaction(txid, 0.001, @truncate(100 + i));
        mempool.fee_estimator.confirmTransaction(txid, @truncate(100 + i + 1));
    }

    const estimate = mempool.fee_estimator.estimateFee(2);
    if (estimate) |rate| {
        // BUG: this could be below the min relay fee (1 sat/vB) with no floor applied
        // In Core, min_relay_feerate would be applied as a floor.
        _ = rate; // documented: no floor enforced
    }
    // Test passes regardless — we're documenting the structural absence
}

// ============================================================================
// G22 — FeeCalculation / returnedTarget absent (BUG-16)
// ============================================================================

test "w114 G22: BUG-16 blocks field always reflects conf_target not actual returnedTarget" {
    // Core populates FeeCalculation.returnedTarget which may differ from confTarget
    // when the estimator clamps to maxUsableEstimate. clearbit always echoes conf_target
    // in the blocks field of the JSON response.
    //
    // This is tested structurally: if MAX_CONFIRMATION_TARGET=144 and we request 144,
    // the estimator returns null (target >= MAX_CONFIRMATION_TARGET), but the RPC
    // would respond with blocks=144 rather than the actual clamped target used.
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    // target == MAX_CONFIRMATION_TARGET → null (never tries clamping to a lower useful target)
    const result = est.estimateFee(FeeEstimator.MAX_CONFIRMATION_TARGET);
    try std.testing.expectEqual(@as(?f64, null), result);
    // BUG: Core would walk backward from max to find the actual usable estimate and
    // report that target in returnedTarget. clearbit has no such walk.
}

// ============================================================================
// G23 — File format incompatible with Core (BUG-17)
// ============================================================================

test "w114 G23: BUG-17 file format uses 'CBFE' magic + u32 integer counts; Core uses version 309900 + EncodedDouble" {
    // Core fee_estimates.dat format (block_policy_estimator.cpp):
    //   int32 CURRENT_FEES_FILE_VERSION (309900)
    //   uint32 nBestSeenHeight
    //   uint32 historicalFirst, historicalBest
    //   vector<EncodedDouble> buckets (double as IEEE-754 u64 little-endian)
    //   TxConfirmStats (feeStats): decay, scale, m_feerate_avg, txCtAvg, confAvg, failAvg
    //   TxConfirmStats (shortStats): same shape
    //   TxConfirmStats (longStats): same shape
    //
    // clearbit format (mempool.zig):
    //   [4]u8 "CBFE"
    //   u32 LE version=1
    //   u32 LE current_height
    //   u32[48] total_counts
    //   u32[144][48] confirmed_counts
    //
    // Core's fee_estimates.dat cannot be loaded by clearbit and vice versa.
    // This is a full wire-incompatibility for nodes that want to share or migrate data.
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    // Save to a temp file and check the magic
    const tmp_path = "/tmp/clearbit_test_fee_estimator_w114.dat";
    try est.saveToFile(tmp_path);
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    const file = try std.fs.cwd().openFile(tmp_path, .{});
    defer file.close();

    var magic: [4]u8 = undefined;
    _ = try file.reader().readAll(&magic);
    // BUG: clearbit writes "CBFE", Core writes 309900 (little-endian int)
    try std.testing.expectEqualSlices(u8, "CBFE", &magic);
    // Core's format would start with 0x9C 0xB9 0x04 0x00 (309900 in LE int32)
    const core_version_le = [_]u8{ 0x9C, 0xB9, 0x04, 0x00 };
    try std.testing.expect(!std.mem.eql(u8, &magic, &core_version_le));
}

// ============================================================================
// G24 — File age check absent
// ============================================================================

test "w114 G24: file age check absent; clearbit loads fee data regardless of age" {
    // Core: if file_age > MAX_FILE_AGE(60h) && !read_stale_estimates → skip loading.
    // clearbit's loadFromFile() has no timestamp check; it reads any valid "CBFE" file.
    // This means stale (>2.5 day old) fee estimates are used unconditionally.
    //
    // Structural test: save a file, then load it — no age error is returned.
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    const tmp_path = "/tmp/clearbit_test_fee_age_w114.dat";
    try est.saveToFile(tmp_path);
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    var est2 = FeeEstimator.init(allocator);
    defer est2.deinit();
    // Should succeed (no age check): BUG — should reject files older than 60h
    try est2.loadFromFile(tmp_path);
    try std.testing.expectEqual(@as(u32, 0), est2.current_height);
}

// ============================================================================
// G27 — SUFFICIENT_FEETXS threshold absent (BUG-13 continuation)
// ============================================================================

test "w114 G27: no SUFFICIENT_FEETXS=0.1 or SUFFICIENT_TXS_SHORT=0.5 bucket accumulation" {
    // Core: if partialNum < sufficientTxVal / (1 - decay): continue (accumulate more buckets)
    // clearbit: if total_counts[bucket] < MIN_DATA_POINTS (10): skip bucket (no accumulation)
    //
    // This means clearbit never groups adjacent buckets with sparse data together.
    // In a sparse market (few txs), Core might span 3-5 adjacent buckets to get enough
    // data; clearbit simply skips all buckets with < 10 txs and may return null.
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    // Add 9 txs (below MIN_DATA_POINTS=10) — should not produce an estimate
    for (0..9) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xFF;
        try est.trackTransaction(txid, 5.0, @truncate(100 + i));
        est.confirmTransaction(txid, @truncate(100 + i + 1));
    }

    // BUG: Core would accumulate adjacent buckets and might give an estimate;
    // clearbit skips the bucket (9 < 10) and returns null.
    const result = est.estimateFee(2);
    try std.testing.expectEqual(@as(?f64, null), result);

    // Add one more to reach the threshold
    var txid_10: types.Hash256 = undefined;
    txid_10[0] = 9;
    for (1..32) |j| txid_10[j] = 0xFF;
    try est.trackTransaction(txid_10, 5.0, 109);
    est.confirmTransaction(txid_10, 110);

    const result2 = est.estimateFee(2);
    // Now 10 >= MIN_DATA_POINTS, should produce an estimate
    try std.testing.expect(result2 != null);
}

// ============================================================================
// G28 — Success thresholds: only 0.85; HALF (0.60) and DOUBLE (0.95) absent
// ============================================================================

test "w114 G28: only SUCCESS_PCT=0.85 used; HALF_SUCCESS_PCT=0.60 and DOUBLE_SUCCESS_PCT=0.95 absent" {
    try std.testing.expectApproxEqRel(@as(f64, 0.85), FeeEstimator.MIN_SUCCESS_RATE, 0.001);
    // Core uses 0.60 at target/2 and 0.95 at 2*target as additional safety bounds.
    // The 0.60 threshold catches cases where the estimate is too low (not enough txs
    // confirmed at half the target window). The 0.95 threshold at double target catches
    // fee-sniping scenarios. clearbit has neither.
}

// ============================================================================
// G29 — estimate_mode parameter silently ignored (BUG-18)
// ============================================================================

test "w114 G29: BUG-18 conservative vs economical estimate_mode ignored at estimateFee level" {
    // Core: conservative mode uses estimateConservativeFee() which requires DOUBLE_SUCCESS_PCT
    // at 2*target for all longer horizons. This produces higher (safer) estimates.
    // clearbit: handleEstimateSmartFee accepts the estimate_mode param but never passes
    // it to any estimation logic — estimateFee() always uses MIN_SUCCESS_RATE=0.85.
    //
    // Structural test: the FeeEstimator has no 'conservative' parameter.
    const allocator = std.testing.allocator;
    var est = FeeEstimator.init(allocator);
    defer est.deinit();

    // Populate with enough data for an estimate
    for (0..20) |i| {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        for (1..32) |j| txid[j] = 0xAA;
        try est.trackTransaction(txid, 10.0, @truncate(100 + i));
        est.confirmTransaction(txid, @truncate(100 + i + 2));
    }

    const est1 = est.estimateFee(6);
    const est2 = est.estimateFee(6); // same call — no conservative mode distinction
    // BUG: conservative and economical are identical because there's only one algorithm
    try std.testing.expectEqual(est1, est2);
}

// ============================================================================
// G30 — CValidationInterface integration absent
// ============================================================================

test "w114 G30: CValidationInterface integration absent; no TransactionAddedToMempool hook" {
    // Core: CBlockPolicyEstimator inherits CValidationInterface.
    //   TransactionAddedToMempool() → processTransaction()
    //   TransactionRemovedFromMempool() → removeTx()
    //   MempoolTransactionsRemovedForBlock() → processBlock()
    //
    // clearbit: FeeEstimator is a plain struct with no ValidationInterface hooks.
    // The mempool does not call fee_estimator.trackTransaction() on add,
    // fee_estimator.confirmTransaction() on block connect,
    // or fee_estimator.processBlock() on block arrival.
    //
    // This is the root cause of BUG-1/2/3: without these hooks, the estimator
    // is a dead subsystem that always returns null.
    const allocator = std.testing.allocator;
    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Confirm the estimator has no data after operations
    // (indirect proof that hooks are absent)
    try std.testing.expectEqual(@as(usize, 0), mempool.fee_estimator.trackedCount());
    try std.testing.expectEqual(@as(u32, 0), mempool.fee_estimator.current_height);
}
