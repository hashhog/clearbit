# W139 — Fee estimation engine (CBlockPolicyEstimator) — clearbit (Zig 0.13)

Discovery-only audit of clearbit's fee-estimation surface vs. Bitcoin Core's
`CBlockPolicyEstimator` and surrounding helpers (`CFeeRate`, `FeeFilterRounder`,
`estimatesmartfee` / `estimaterawfee` RPC, fee_estimates.dat persistence).

**This is a second pass on the fee subsystem.** W114 (FIX-47 / FIX-48 closed
many of its findings) already covered the broad anatomy (bucket count, decay
constants, three-horizon architecture, `trackTransaction` / `confirmTransaction`
/ `processBlock` wire-up, file format magic, success-rate thresholds). W139
deliberately steers AWAY from gates W114 already owns and toward Core-specific
semantics that W114 missed:

- `CFeeRate` arithmetic + rounding semantics (`GetFee` ceil-up, `GetFeePerK`).
- `FeeFilterRounder` (BIP-133 quantization helper).
- `validForFeeEstimation` gate
  (`m_mempool_limit_bypassed` / `m_submitted_in_package` /
  `m_chainstate_is_current` / `m_has_no_mempool_parents`).
- `processBlock` reorg / side-chain guard (`nBlockHeight <= nBestSeenHeight`).
- `processTransaction` height guard (`txHeight != nBestSeenHeight`).
- `MaxUsableEstimate` / `BlockSpan` / `HistoricalBlockSpan` clamping.
- `estimateCombinedFee` shortest-horizon dispatch + `checkShorterHorizon`.
- `estimateConservativeFee` `max(feeStats, longStats)` at `2*target`.
- `FlushUnconfirmed` end-of-shutdown failure recording.
- `MAX_FILE_AGE=60h` / `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES=false` /
  `FEE_FLUSH_INTERVAL=1h`.
- `OLDEST_ESTIMATE_HISTORY=6*1008` historical-data invalidation.
- `ParseConfirmTarget`.
- `estimaterawfee` per-horizon schema (`startrange`/`endrange`/
  `withintarget`/`totalconfirmed`/`inmempool`/`leftmempool`/`errors`).
- `CValidationInterface` async vs synchronous decoupling.
- `m_cs_fee_estimator` mutex serialization of all operations.
- File path conventions (`FeeestPath` → `<datadir>/fee_estimates.dat`).

## References
- `bitcoin-core/src/policy/fees/block_policy_estimator.cpp` (1119 lines —
  primary).
- `bitcoin-core/src/policy/fees/block_policy_estimator.h` (346 lines).
- `bitcoin-core/src/policy/fees/block_policy_estimator_args.{cpp,h}` —
  `FeeestPath`.
- `bitcoin-core/src/policy/feerate.cpp` + `feerate.h` — `CFeeRate`.
- `bitcoin-core/src/rpc/fees.cpp` — `estimatesmartfee` / `estimaterawfee`.

## clearbit refs

- `src/mempool.zig` lines 6800-7148 — `FeeEstimator` struct.
- `src/mempool.zig` lines 1429-1434 (`trackTransaction` call site in
  `addTransaction`) + 1731-1748 (`confirmTransaction` + `processBlock`
  in `removeForBlock`) + 3995-3996 (package-rate track site).
- `src/rpc.zig` lines 11126-11250 — `handleEstimateSmartFee` + `handleEstimateRawFee`.
- `src/main.zig` lines 1807-1810 (`loadFromFile`) + 2284-2286 (`saveToFile`).

## 30-gate matrix

| G  | Subject                                                              | Status     | BUG |
|----|----------------------------------------------------------------------|------------|-----|
| 1  | `CFeeRate` type (or equivalent) wrapping fee + size                  | MISSING    | 1   |
| 2  | `GetFee(virtual_bytes)` rounds UP (ceil)                             | MISSING    | 2   |
| 3  | `GetFeePerK()` returns sat/kvB (Core internal unit)                  | DIVERGE    | 3   |
| 4  | `FeeRateFormat::SAT_VB` vs `BTC_KVB` formatter                       | MISSING    | 4   |
| 5  | `FeePerVSize` overflow guard at int32 size limit                     | MISSING    | 5   |
| 6  | `FeeFilterRounder` helper (BIP-133 fee filter quantization)          | MISSING    | 6   |
| 7  | `FEE_FILTER_SPACING = 1.1` constant                                  | MISSING    | 7   |
| 8  | `MAX_FILTER_FEERATE = 1e7` constant                                  | MISSING    | 8   |
| 9  | `validForFeeEstimation` four-gate skip                               | MISSING    | 9   |
| 10 | `txHeight != nBestSeenHeight` skip in `processTransaction`           | MISSING    | 10  |
| 11 | `nBlockHeight <= nBestSeenHeight` skip in `processBlock` (reorg)     | MISSING    | 11  |
| 12 | `mapMemPoolTxs.contains(hash)` duplicate-track guard                 | DIVERGE    | 12  |
| 13 | `firstRecordedHeight` set on first counted-tx block                  | MISSING    | 13  |
| 14 | `BlockSpan()` = `nBestSeenHeight - firstRecordedHeight`              | MISSING    | 14  |
| 15 | `HistoricalBlockSpan()` (oldest valid historical data tracker)       | MISSING    | 15  |
| 16 | `OLDEST_ESTIMATE_HISTORY = 6 * 1008` invalidation                    | MISSING    | 16  |
| 17 | `MaxUsableEstimate()` clamp to `max(BlockSpan, HistoricalBlockSpan)/2` | MISSING  | 17  |
| 18 | `estimateCombinedFee` shortest-horizon dispatch                      | MISSING    | 18  |
| 19 | `estimateCombinedFee` `checkShorterHorizon` cross-horizon lookback   | MISSING    | 19  |
| 20 | `estimateConservativeFee` `max(feeStats, longStats)` at `2*target`   | MISSING    | 20  |
| 21 | `FlushUnconfirmed` end-of-shutdown failure recording                 | MISSING    | 21  |
| 22 | `MAX_FILE_AGE = 60h` rejection in `loadFromFile`                     | MISSING    | 22  |
| 23 | `FEE_FLUSH_INTERVAL = 1h` periodic save                              | MISSING    | 23  |
| 24 | `GetFeeEstimatorFileAge()` helper                                    | MISSING    | 24  |
| 25 | `ParseConfirmTarget` helper (RPC parameter validation)               | MISSING    | 25  |
| 26 | `estimaterawfee` per-horizon `pass`/`fail` bucket schema             | DIVERGE    | 26  |
| 27 | `m_cs_fee_estimator` mutex (serialize all ops)                       | DIVERGE    | 27  |
| 28 | `FeeestPath` arg helper / `fee_estimates.dat` canonical filename     | PARTIAL    | -   |
| 29 | `estimatesmartfee` `min_mempool_feerate` floor in RPC                | MISSING    | 28  |
| 30 | `estimatesmartfee` `max_target = HighestTargetTracked(LONG)` clamp   | DIVERGE    | 29  |

(G28 is PARTIAL/no-bug: `main.zig` already wires
`<datadir>/fee_estimates.dat` correctly.)

## Findings (29 BUGs)

### P0 — none (all P0-DEAD-HELPER closed by FIX-47/FIX-48; W139 found no new P0s)

### HIGH (10)

- **BUG-1 — G1** No `CFeeRate`-equivalent type. clearbit passes feerate as a
  bare `f64` (sat/vB) wherever Core uses `CFeeRate`. Loses Core's int32
  ceiling-rounding semantics and BTC/kvB ↔ sat/vB conversion guarantees.
- **BUG-2 — G2** No `GetFee(virtual_bytes)` rounding API. `addTransaction`
  computes `fee / vsize` directly (`mempool.zig:1219`-style float division)
  — no ceiling-up semantics. Affects every fee-floor comparison.
- **BUG-6 — G6** No `FeeFilterRounder`. BIP-133 fee-filter quantization is
  missing; cross-validated by `tests_w136_relay_flags.zig:218` (W136 G8 bug
  already documents the absence — W139 G6 confirms same root cause from the
  fee-engine side, with extra angle on `MakeFeeSet`).
- **BUG-9 — G9** No `validForFeeEstimation` four-gate skip in
  `addTransaction` before `trackTransaction`. clearbit feeds the estimator
  every successful add regardless of whether the chain is current, whether
  the tx is part of a package, whether it has mempool parents, or whether
  the mempool-limit was bypassed. Core skips these via `untrackedTxs++` to
  avoid biasing the estimate.
- **BUG-10 — G10** No `txHeight != nBestSeenHeight` skip. Even if the
  fee-estimator had a separate `nBestSeenHeight` (it doesn't — clearbit
  uses `current_height` only), the height-mismatch reorg skip in Core's
  `processTransaction` is absent.
- **BUG-11 — G11** No `nBlockHeight <= nBestSeenHeight` skip in
  `processBlock`. clearbit's `removeForBlock` unconditionally calls
  `confirmTransaction` + `processBlock` even during a reorg, when the
  same height (or a lower one) is re-processed. Core silently ignores
  side-chain / reorg blocks at this point.
- **BUG-13 — G13** No `firstRecordedHeight` field. Required to compute
  `BlockSpan()` and to clamp the max-usable confirmation target.
- **BUG-14 — G14** No `BlockSpan()` getter. Direct consequence of BUG-13.
- **BUG-17 — G17** No `MaxUsableEstimate()` clamp. `estimateFee` does not
  cap the confirmation target against historical block-span; queries for
  conf_target=1008 will return arbitrary buckets even on a node with only
  10 blocks observed.
- **BUG-18 — G18** `selectHorizon` picks the shortest horizon by max-target
  but does not consult `checkShorterHorizon` — Core's `estimateCombinedFee`
  may re-check a SHORTER horizon at its own max-target if that gives a
  lower estimate, to keep estimates monotonic across targets. clearbit
  cannot return a lower-than-target estimate from a shorter horizon.

### MEDIUM (10)

- **BUG-3 — G3** Unit mismatch: clearbit stores feerate in **sat/vB**; Core
  internally uses **sat/kvB** (1000× larger numbers). Float-rounding error
  surface differs. No correctness bug at the boundary (RPC converts), but
  internal comparisons against `MIN_RELAY_FEE` (already sat/kvB elsewhere)
  must coerce — invitation for unit-mixing bugs (see e.g. W86 / FIX-47
  history).
- **BUG-4 — G4** No `SAT_VB` vs `BTC_KVB` formatter switch. RPC always
  emits BTC/kvB; sat/vB output (Core's newer help text) absent.
- **BUG-5 — G5** No int32 vsize-overflow guard. `feeToBucket(rate)` accepts
  any `f64`; if a caller passes `(fee*1000.0) / size` and `size` overflows
  i32 (Core guards via `virtual_bytes > 0`), behavior is undefined.
- **BUG-7 — G7** `FEE_FILTER_SPACING = 1.1` constant absent. Core
  separated this from `FEE_SPACING` (1.05 — bucket spacing) to allow
  independent evolution; clearbit has neither rounder nor either constant.
- **BUG-8 — G8** `MAX_FILTER_FEERATE = 1e7` constant absent. Used by
  `FeeFilterRounder::round` to cap the filter range.
- **BUG-12 — G12** `mapMemPoolTxs.contains(hash)` duplicate-track guard
  exists (in spirit) — `trackTransaction` overwrites via `put(...)` — but
  Core's behavior is to LogDebug-and-return on duplicate. clearbit silently
  overwrites the bucket index; on a re-orged re-add, this clobbers the
  original bucket index for the in-flight estimate denominator.
- **BUG-15 — G15** No `historicalFirst` / `historicalBest` (loaded from
  saved file). Direct consequence: historical span cannot inform
  MaxUsableEstimate after a restart with stale-but-not-too-old data.
- **BUG-16 — G16** `OLDEST_ESTIMATE_HISTORY = 6 * 1008` invalidation
  threshold absent (no field, no constant). Core invalidates historical
  span if `nBestSeenHeight - historicalBest > OLDEST_ESTIMATE_HISTORY`.
- **BUG-19 — G19** `checkShorterHorizon` cross-horizon lookback absent
  (same root cause as BUG-18 but distinct semantic).
- **BUG-20 — G20** No `estimateConservativeFee` taking `max(feeStats,
  longStats)` at `2*target`. clearbit's `estimateFee` is single-horizon
  per target, never compares with the long horizon at `2*target`.

### LOW (9)

- **BUG-21 — G21** No `FlushUnconfirmed` on shutdown. `mempool.deinit()`
  (or any shutdown path) does not record still-tracked txs as failures
  before saving. Restart-after-stale-mempool will skew estimates because
  the failure side of the moving averages is never decremented.
- **BUG-22 — G22** No `MAX_FILE_AGE = 60h` rejection. `loadFromFile`
  reads the file regardless of file timestamp. Stale (>2.5d) fee data
  gets used unconditionally. (W114 G24 covers this from the structural
  side — W139 G22 confirms still open with explicit `MAX_FILE_AGE` const
  absence.)
- **BUG-23 — G23** No `FEE_FLUSH_INTERVAL = 1h` periodic save. The fee
  estimator only persists at shutdown; an unclean shutdown loses up to
  the entire lifetime of accumulated estimates.
- **BUG-24 — G24** No `GetFeeEstimatorFileAge()` helper. Required to
  implement BUG-22 + sanity checks at startup.
- **BUG-25 — G25** No `ParseConfirmTarget` helper. Each RPC inline-clamps
  conf_target with `@min(1008, ...)` rather than reusing a centralised
  helper. Result: different RPCs round / clamp differently (estimatesmartfee
  uses `@max(1, @min(1008, ...))`; estimaterawfee uses `< 1 or > 1008`
  reject).
- **BUG-26 — G26** `handleEstimateRawFee` emits a degenerate
  `pass.startrange/endrange` (both equal to `rate`) and zeros for
  `withintarget`/`totalconfirmed`/`inmempool`/`leftmempool`. Core emits
  the real bucket range bounds + the moving-average counts.
- **BUG-27 — G27** Locking strategy: clearbit uses `mempool.mutex`
  externally (RPC handlers lock the whole mempool around the read);
  Core has a separate `m_cs_fee_estimator` mutex scoped to the
  estimator. clearbit's broader lock surface increases contention.
- **BUG-28 — G29** `handleEstimateSmartFee` does not apply
  `min_mempool_feerate` floor in the RPC layer (W114 BUG-15 still open).
  W139 re-asserts via fresh test angle (post-RPC floor, not the
  estimator's raw output).
- **BUG-29 — G30** `handleEstimateSmartFee` clamps `conf_target` to a
  hard-coded `1008` rather than calling `HighestTargetTracked(LONG_HALFLIFE)`
  dynamically. Affects any future change to the long-horizon period
  count (would silently desync).

## Tests

`src/tests_w139_fee_estimation.zig` — 30 gates, each with one `test`
block. Build step: `zig build test-w139`.

The shape is BUG-attesting (assert current/wrong behavior so a future
fix-wave flips the assertion). For DIVERGE bugs, two parallel assertions
pin both "what clearbit does" (current) and "what Core does" (target).
For MISSING bugs, source-grep guards over `mempool.zig` and `rpc.zig`
assert the Core-named identifier is absent.

## Out-of-scope

- Multi-impl comparison (this is clearbit-only).
- Performance / RSS measurement.
- Actual RPC integration tests (would need a live node; the test root
  exercises `FeeEstimator` directly + grep-guards over the RPC handler).
- `FeeFilterRounder` is covered briefly here (G6/G7/G8) but already lives
  in W136 G8 — W139 surfaces it from the fee-engine side for completeness.
- Mainnet replay / consensus-diff (no consensus impact — fee estimation
  is purely policy + RPC).

## Cross-wave parallel-agent coordination note

W139 lands alongside three other parallel discovery audits (waves
unknown — likely W138 / W140 / W141). All four agents touch
`build.zig`. This wave appends its test step to the bottom of the
`b.step("test-w139", ...)` block AFTER the existing `test-w137` /
`test-w136` blocks. Conflict resolution: hand-edit on rebase.
