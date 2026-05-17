# W129 — Coin selection deep audit (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's coin-selection subsystem vs Bitcoin Core
(`bitcoin-core/src/wallet/coinselection.{h,cpp}`,
`bitcoin-core/src/wallet/spend.cpp`,
`bitcoin-core/src/wallet/feebumper.cpp`).
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w129` (folded into `zig build test`).
**Related prior wave:** W113 (`tests_w113_coin_selection.zig`) audited algorithm
*presence* and surface-level mechanics; W129 audits *algorithmic depth* — the
formulas, tiebreaks, integration with `spend.cpp`, change-target generation,
SFFO interaction, and dust-threshold semantics.

## Summary

Where W113 catalogued the "what's missing entirely" view (SRD, CoinGrinder,
OutputGroup, SelectionAlgorithm enum, change-position randomisation, etc.),
W129 zooms in on the algorithms clearbit *does* implement (BnB + Knapsack +
shared driver) and on `createTransaction`'s integration with selection. The
algorithm bodies in `src/wallet.zig:1300-1679` are recognisable Core ports
but diverge from Core in numerically observable ways:

- **Effective value is per-coin but cost_of_change is a constant default**:
  `CoinSelectOptions.cost_of_change = 34 * 10` (line 1288) is the
  product `change_output_size * fee_rate=10`. Core computes
  `m_cost_of_change = m_discard_feerate.GetFee(change_spend_size) + m_change_fee`
  i.e. `(discard_fee × spend_size) + (effective_fee × output_size)`. clearbit
  uses neither feerate; the constant is wrong at every non-default feerate.
- **long_term_fee_rate default = 10 sat/vB** (line 1287). Core defaults to
  10 000 sat/kvB = 10 sat/vB *only* for the `-fallbackfee` knob; the
  long-term feerate estimate is normally derived from the fee estimator, not a
  hard-coded constant. The default biases waste calculation everywhere.
- **min_change default = 546** (line 1289) hard-codes the P2PKH dust constant
  regardless of the change output type. Core computes
  `min_viable_change = max(change_spend_fee + 1, dust)` where `dust =
  GetDustThreshold(change_prototype_txout, discard_feerate)` (spend.cpp:1182-1184).
- **GenerateChangeTarget is absent**. Every clearbit selection uses
  `min_change = 546` as its change target floor; Core randomises change between
  `CHANGE_LOWER = 50_000` and `min(2 × payment, CHANGE_UPPER = 1_000_000)` to
  fight the "unnecessary input" heuristic (coinselection.cpp:809-818).
- **CHANGE_LOWER / CHANGE_UPPER constants are entirely absent** — the
  privacy-motivated bounds are not defined and not used anywhere in the
  source tree.
- **SFFO (subtract-fee-from-outputs) plumbing is absent**. There is no
  `CreateTxOptions.subtract_fee_outputs` flag and no `m_subtract_fee_outputs`
  field in selection options; the BnB-skip-on-SFFO branch
  (`spend.cpp:751`) has no analog.
- **SelectCoinsBnB excess-as-waste sign is wrong on the "is_feerate_high
  backtrack" path**: clearbit backtracks when `curr_waste > best_waste and
  is_feerate_high` (line 1458), but `is_feerate_high` is the *global*
  comparator `options.fee_rate > options.long_term_fee_rate`, not Core's
  per-coin `pool[0].fee > pool[0].long_term_fee` (coinselection.cpp:120).
  Documented in W113 BUG-7; W129 re-asserts via algorithm-output observation.
- **Knapsack `lowest_larger` tiebreak picks first-seen-smaller**
  (line 1567): `eff_value < effective_values[lowest_larger.?]`. Core's
  comparison uses `GetSelectionAmount()` and is order-stable through the
  shuffle; clearbit lacks the pre-loop shuffle so the order is whatever
  the descending sort left, which makes the pick *deterministic for a given
  UTXO set* but *order-dependent on insertion*.
- **Knapsack RNG is `std.crypto.random.boolean()`** (line 1618). This is
  cryptographically secure but **unseeded across calls** — it returns
  different values each run with no way for the caller to reproduce a
  selection. Core uses `FastRandomContext& rng_fast` threaded through
  `CoinSelectionParams`, which the wallet can seed deterministically for
  tests. clearbit cannot make selection deterministic without monkey-patching
  the std lib.
- **Knapsack second ApproximateBestSubset pass on `+change_target` is
  absent**. Core's KnapsackSolver runs ApproximateBestSubset twice — once
  for `nTargetValue` and once for `nTargetValue + change_target` — when the
  first run fails to hit the exact target (coinselection.cpp:708-711).
  clearbit only runs the single pass.
- **CoinGrinder `min_tail_weight` lookahead absent.** Even if CoinGrinder
  were ported, the weight-based pruning that makes CG faster than BnB at
  high feerates depends on the per-index `min_tail_weight` array
  (coinselection.cpp:339-343). No `min_tail_weight` exists.
- **SRD `CHANGE_LOWER` bump absent.** Core SRD adds `CHANGE_LOWER +
  change_fee` to the target before running the random draw
  (coinselection.cpp:546). No analog.
- **`AttemptSelection` waste-comparison is absent**. Core runs BnB then
  Knapsack then CoinGrinder (when feerate > 3× long-term) then SRD and
  picks the result with the lowest waste metric (spend.cpp:752-786).
  clearbit runs BnB, falls back to Knapsack only on `null`, and stops —
  no waste comparison, no per-output-type loop, no all-types fallback,
  no `min_element` over multiple results.

| Verdict | Gates | Notes |
|---|---|---|
| PRESENT | 4 | Core-equal: BnB iteration cap, BnB sort direction, Knapsack exact-match, BnB pool dedup of negative-EV |
| PARTIAL | 7 | Implemented but with a numeric / formula / ordering divergence |
| MISSING | 19 | No analog in clearbit (algorithm, struct, constant, plumbing) |

**Bug count: 22** (P0=0 / HIGH=8 / MED=10 / LOW=2 / COSMETIC=2).
No consensus-divergent bugs — coin selection is local-policy. Impacts: privacy
(no change-position randomisation, no CHANGE_LOWER/UPPER), fee efficiency (wrong
cost_of_change formula, no SRD/CG), reproducibility (no seeded RNG), wallet
compatibility (no SFFO, no min_viable_change, no multi-algo waste comparison).

## Methodology

1. Read `coinselection.{h,cpp}`, `spend.cpp` (selection-related portions), and
   `policy/policy.cpp` `GetDustThreshold`.
2. Synthesise 30 gates targeting algorithmic depth (not just presence —
   W113 already covered that surface).
3. Map each gate to clearbit's `wallet.zig` selection / change / dust code.
4. Catalogue numerical or algorithmic divergences as BUGs.
5. Write `src/tests_w129_coin_selection.zig` with one test per gate.
   Tests are XFAIL-style: BUG gates assert clearbit's current (buggy) state
   so a future fix wave can flip each gate by intentionally breaking the test.

## Gates

### Effective value & UTXO pool preparation (G1-G5)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G1 | effective_value = txout.value − fee (coinselection.h:88) | wallet.zig:1357 `effective_values[i] = utxo.output.value - input_fee` | PRESENT |
| G2 | `is_feerate_high = pool[0].fee > pool[0].long_term_fee` (coinselection.cpp:120) | wallet.zig:1434 `options.fee_rate > options.long_term_fee_rate` (global, not per-coin) | **PARTIAL — BUG-1 HIGH** (also W113 BUG-7) |
| G3 | Sort descending by effective value, **lower weight tiebreaker** (`descending_effval_weight`, coinselection.cpp:41-50) | wallet.zig:1376-1380 sorts descending by eff value but lacks any tiebreaker | **PARTIAL — BUG-2 MED** |
| G4 | OutputGroup grouping → `m_subtract_fee_outputs` toggles `GetSelectionAmount` between effective_value and raw value (coinselection.cpp:789-792) | absent — clearbit has no SFFO plumbing | **MISSING — BUG-3 MED** |
| G5 | Negative effective-value UTXOs filtered from BnB pool (coinselection.cpp:106 assert) | wallet.zig:1410-1418 — counts positive-only, skips ≤0 in the BnB inner loop | PRESENT |

### Branch and Bound depth (G6-G10)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G6 | TOTAL_TRIES = 100 000 (coinselection.cpp:91) | wallet.zig:1402 `max_iterations: usize = 100_000` | PRESENT |
| G7 | Lookahead pre-computed by summing all positive UTXOs (coinselection.cpp:103-108) | wallet.zig:1413-1418 same shape | PRESENT |
| G8 | Backtrack restores `curr_available_value` over all skipped (omitted) UTXOs since the last selected (coinselection.cpp:154-156) | wallet.zig:1477-1485 — counts down from `utxo_pool_index` toward `last_selected`. **The slice `restore_idx == last_selected → break` excludes the last_selected itself** which matches Core; but clearbit's loop variable `restore_idx` walks indices not positions in `sorted_indices` — same shape. | PRESENT |
| G9 | Duplicate-omission shortcut: skip inclusion branch if `pool[i].fee == pool[i-1].fee && pool[i].value == pool[i-1].value && i-1 not in curr_selection` (coinselection.cpp:171-178) | absent — wallet.zig:1497-1503 always pushes inclusion | **MISSING — BUG-4 MED** (W113 BUG-8) |
| G10 | `RecalculateWaste` after BnB success uses `cost_of_change` (coinselection.cpp:197) | wallet.zig:1463 `selection_waste = curr_waste + (curr_value - target_value)` — does not include `cost_of_change` because the changeless BnB result has no change output; matches Core's `else` branch in `RecalculateWaste` (excess-as-waste). However clearbit never recomputes after the loop and never adjusts for `bump_fee_group_discount`. | **PARTIAL — BUG-5 LOW** (bump-fee discount absent) |

### Knapsack depth (G11-G15)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G11 | `std::shuffle(groups, rng)` before the main loop (coinselection.cpp:665) | absent — wallet.zig:1535-1572 iterates `sorted_indices` in descending sort order; W113 BUG-10 | **MISSING — BUG-6 HIGH** (W113 BUG-10) |
| G12 | Exact-match short-circuit returns the single UTXO immediately (coinselection.cpp:672-674) | wallet.zig:1556-1560 returns single-UTXO match | PRESENT |
| G13 | `applicable_groups` = those with `GetSelectionAmount() < nTargetValue + change_target` (coinselection.cpp:675-677) | wallet.zig:1561-1564 uses `eff_value < target_value + change_cost` — bound matches | PRESENT |
| G14 | `lowest_larger` is overwrite-on-smaller (coinselection.cpp:678) | wallet.zig:1567-1568 — same logic | PRESENT |
| G15 | If `nTotalLower < target` and `lowest_larger` exists → return `lowest_larger` (coinselection.cpp:694-700) | wallet.zig:1584-1593 same shape | PRESENT |
| G15b | **ApproximateBestSubset runs TWICE** when the first run misses: once at `nTargetValue`, once at `nTargetValue + change_target` (coinselection.cpp:708-711) | wallet.zig:1602 single pass of 1000 iterations | **MISSING — BUG-7 MED** |
| G15c | `lowest_larger` is preferred over the subset-sum approximation when `lowest_larger.value <= nBest` (coinselection.cpp:715-716) | wallet.zig:1648-1654 — same idea but compares against `best_value` which is the *minimum overshoot above target*, not the absolute selection sum; ordering of comparison differs | **PARTIAL — BUG-8 LOW** |
| G15d | RNG threaded as `FastRandomContext& rng_fast` so callers can seed deterministically (coinselection.cpp:602) | wallet.zig:1618 calls `std.crypto.random.boolean()` directly — no seed plumbing | **MISSING — BUG-9 HIGH** (no deterministic test mode) |

### SRD (G16-G19)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G16 | `SelectCoinsSRD` function exists (coinselection.cpp:536) | absent | **MISSING — BUG-10 HIGH** (W113 BUG-1) |
| G17 | Target bumped by `CHANGE_LOWER + change_fee` before draw (coinselection.cpp:546) | absent | **MISSING — BUG-11 HIGH** |
| G18 | Priority-queue eviction of lowest-EV when weight exceeded (coinselection.cpp:567-575) | absent | **MISSING — BUG-12 MED** |
| G19 | Uses `MinOutputGroupComparator` (lowest first) for eviction (coinselection.cpp:527-534) | absent | **MISSING — BUG-13 LOW** |

### CoinGrinder (G20-G23)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G20 | `CoinGrinder` function exists (coinselection.cpp:325) | absent | **MISSING — BUG-14 HIGH** (W113 BUG-2) |
| G21 | `min_tail_weight[]` per-index lookahead for weight pruning (coinselection.cpp:331, 339-343) | absent | **MISSING — BUG-15 MED** |
| G22 | Clone-skipping after SHIFT to omission branch (coinselection.cpp:502-510) | absent | **MISSING — BUG-16 MED** |
| G23 | Sort by `descending_effval_weight` (coinselection.cpp:42-50) — distinct from BnB's `descending` (waste tiebreak) (coinselection.cpp:30-38) | absent | **MISSING — BUG-17 MED** |

### Change construction (G24-G26)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G24 | `m_cost_of_change = m_discard_feerate.GetFee(change_spend_size) + m_change_fee` (spend.cpp:1175) | wallet.zig:1288 — constant `34 * 10` (one feerate × one size, no discard); does not depend on output type, feerate, or discard feerate | **PARTIAL — BUG-18 HIGH** |
| G25 | `min_viable_change = max(change_spend_fee + 1, dust)` where dust is `GetDustThreshold(change_prototype_txout, discard_feerate)` (spend.cpp:1182-1184) | wallet.zig:1289 — `min_change = 546` constant (P2PKH dust, no per-type lookup, no discard feerate) | **PARTIAL — BUG-19 HIGH** |
| G26 | Change output inserted at `rng.randrange(vout.size() + 1)` position (privacy) | wallet.zig:2613-2618 — change always appended last (fixed position) | **MISSING — BUG-20 MED** (W113 BUG-11) |

### SFFO + change avoidance (G27-G28)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G27 | `m_subtract_fee_outputs` flag toggles BnB skip + `GetSelectionAmount` between value/effective_value (spend.cpp:751, coinselection.cpp:789-792) | absent — `CreateTxOptions` has no SFFO flag; `CoinSelectOptions` has no `m_subtract_fee_outputs`; `createTransaction` cannot reduce outputs to cover fee | **MISSING — BUG-21 HIGH** |
| G28 | Change-avoidance: if BnB finds a changeless solution within `cost_of_change`, use it; otherwise CG/Knapsack/SRD produce change-bearing solutions. Pick the lowest-waste result across all algos (spend.cpp:716, 811). | clearbit returns BnB if non-null, else Knapsack. No cross-algorithm waste comparison. | **PARTIAL — BUG-22 MED** |

### Constants & dust (G29-G30)

| Gate | Reference | clearbit | Status |
|---|---|---|---|
| G29 | `CHANGE_LOWER = 50000` and `CHANGE_UPPER = 1000000` defined and used in `GenerateChangeTarget` (coinselection.h:23-25, coinselection.cpp:809) | absent — no constants and no `GenerateChangeTarget` | **MISSING — BUG-23 COSMETIC** |
| G30 | `GetDustThreshold(txout, dustRelayFee)` is per-scriptPubKey (P2WPKH = 294, P2PKH = 546, P2WSH/P2TR ≈ 330, P2SH = 540), computed as `dustRelayFee × (output_size + spending_input_size)` (policy.cpp:27-64). clearbit has `dustThresholdFor` (wallet.zig:2689-2703) that returns the right per-spk *numbers* but only for the bumpfee path; the *selection* path uses the flat 546 from `CoinSelectOptions.min_change`. | **PARTIAL — BUG-24 COSMETIC** |

## Bugs

### High severity (algorithmic / wallet-compatibility)

- **BUG-1** (G2) — BnB `is_feerate_high` uses global feerate comparator
  instead of per-coin `pool[0].fee > pool[0].long_term_fee`. Re-affirms
  W113 BUG-7.
- **BUG-6** (G11) — Knapsack lacks pre-loop shuffle; selection becomes
  deterministic w.r.t. UTXO insertion order rather than randomised. W113 BUG-10.
- **BUG-9** (G15d) — RNG cannot be seeded deterministically because the
  algorithm calls `std.crypto.random.boolean()` directly; no `FastRandomContext`
  analog plumbed through `CoinSelectOptions`. Blocks deterministic regression
  tests of the Knapsack stochastic path.
- **BUG-10** (G16) — SRD (Single Random Draw) algorithm entirely absent.
  W113 BUG-1.
- **BUG-11** (G17) — Even if SRD were added, the `CHANGE_LOWER + change_fee`
  target bump is also absent.
- **BUG-14** (G20) — CoinGrinder algorithm entirely absent. At feerates ≥
  3 × long_term_feerate (Core: ≥ 30 sat/vB), CG produces lower-weight
  change-bearing selections than Knapsack/SRD. W113 BUG-2.
- **BUG-18** (G24) — `cost_of_change` is a constant `34 * 10` regardless of
  effective feerate, discard feerate, or output type. At any non-default
  feerate the value diverges from Core's `m_discard_feerate.GetFee(spend_size)
  + m_change_fee`. Concretely: at 5 sat/vB effective feerate + 3 sat/vB
  discard feerate + P2WPKH change (31 bytes out / 68 vbytes in), Core's
  `cost_of_change ≈ 3*68 + 5*31 = 359`. clearbit's constant is 340. At
  30 sat/vB Core ≈ `3*68 + 30*31 = 1134`; clearbit still 340.
- **BUG-19** (G25) — `min_viable_change = 546` constant regardless of change
  output type or discard feerate. Core dust for P2WPKH is 294, P2TR ≈ 330,
  P2WSH ≈ 330, P2SH ≈ 540, P2PKH = 546. Wallets producing P2WPKH change will
  unnecessarily forgo change between 295 and 546 sat (dropping it to fees).
- **BUG-21** (G27) — SFFO (subtract-fee-from-outputs) entirely absent. The
  `CWallet::CreateTransactionInternal` SFFO path lets users send a "round
  number" with the fee subtracted from the recipient output(s); clearbit
  cannot do this. RPC-level: `sendmany`, `sendtoaddress`, `walletcreatefundedpsbt`
  all expose `subtract_fee_from_outputs`. Mainnet ouroboros + nimrod ship this;
  clearbit is the outlier.

### Medium severity (selection quality / privacy)

- **BUG-2** (G3) — Sort tiebreaker absent. Core's BnB sort tiebreaks on
  `fee - long_term_fee` (waste), CG tiebreaks on `m_weight`. Ties are rare
  but produce non-determinism in clearbit's sort because `std.sort.pdq` is
  not stable.
- **BUG-3** (G4) — `GetSelectionAmount` semantics absent. Without
  `m_subtract_fee_outputs`, clearbit always uses `effective_value` for
  selection arithmetic, which is correct *only* when SFFO is off.
- **BUG-4** (G9) — BnB duplicate-omission shortcut absent. W113 BUG-8.
- **BUG-7** (G15b) — Knapsack runs ApproximateBestSubset only once; Core
  runs it twice (target, then target+change_target) which improves the
  hit rate when the exact-target draw misses.
- **BUG-12** (G18) — SRD's heap-based weight-exceeded eviction absent
  (downstream of BUG-10).
- **BUG-15** (G21) — CG's `min_tail_weight` pruning array absent
  (downstream of BUG-14).
- **BUG-16** (G22) — CG's clone-skipping logic absent (downstream of BUG-14).
- **BUG-17** (G23) — CG's distinct `descending_effval_weight` sort comparator
  absent (downstream of BUG-14).
- **BUG-20** (G26) — Change-output position is always last. Trivial
  privacy heuristic (change is usually the larger or smaller-than-payment
  output at index 1) is enabled. W113 BUG-11.
- **BUG-22** (G28) — No cross-algorithm waste-metric comparison; clearbit
  picks BnB-or-Knapsack rather than `min_element(BnB, Knapsack, SRD, CG)`.

### Low / cosmetic

- **BUG-5** (G10) — `bump_fee_group_discount` (shared-ancestor bump-fee
  overestimate refund) absent from waste calculation. Only matters for
  unconfirmed-parent selections that share ancestors.
- **BUG-8** (G15c) — Knapsack `lowest_larger`-vs-subset comparison
  threshold uses different value semantics than Core; rare edge case.
- **BUG-13** (G19) — `MinOutputGroupComparator` heap comparator absent
  (downstream of BUG-10).
- **BUG-23** (G29) — `CHANGE_LOWER = 50_000` and `CHANGE_UPPER = 1_000_000`
  not defined as constants; `GenerateChangeTarget` not implemented.
- **BUG-24** (G30) — Selection-path dust uses flat 546; the per-spk
  `dustThresholdFor` exists for the bumpfee path but is not consulted
  during selection.

## Universal patterns observed

- **"Constant-where-Core-uses-a-formula"** (BUG-18 + BUG-19 + BUG-24) — the
  three numeric defaults in `CoinSelectOptions` (`cost_of_change = 340`,
  `min_change = 546`, `long_term_fee_rate = 10`) all hard-code a value where
  Core derives one from feerate × size. Same shape as a recurring
  cross-impl pattern: defaults that are correct *only* at the default
  feerate.
- **"Single-algorithm pipeline where Core runs N and picks min-waste"**
  (BUG-22) — clearbit's `selectCoinsWithOptions` is BnB-then-Knapsack with
  no cross-comparison; the waste-metric framing has no analog. Fleet-wide
  this would land as a multi-impl wave if other impls share the shape.
- **"Direct-std-RNG-where-Core-threads-a-context"** (BUG-9) — calling
  `std.crypto.random.boolean()` deep inside an algorithm blocks
  deterministic regression tests. Test isolation requires either explicit
  RNG threading (Core: `FastRandomContext&`) or a wallet-level seed.
- **"SFFO plumbing absence cascades through CreateTransaction"** (BUG-21)
  — without an SFFO flag on selection options, downstream RPC methods
  (`sendmany`, `sendtoaddress`, `walletcreatefundedpsbt`) cannot offer the
  `subtract_fee_from_outputs` parameter without rewriting the selection
  pipeline. Single missing bool field, large downstream surface area.
- **"Change-position privacy is a binary"** (BUG-20) — either you append
  change last (any fingerprinter recognises) or you `randrange` the position.
  No middle ground.

## Out of scope (intentional)

- All W113 gates that are still asserted in `tests_w113_coin_selection.zig`.
  W129 cross-references W113 BUGs (1, 2, 7, 8, 10, 11) where the same finding
  recurs at deeper level but does not re-execute the W113 tests.
- Coin-control selection (manual UTXO inclusion via `CCoinControl::Select`
  / `m_allow_other_inputs`) — W113 G29 covered the presence of forced-inclusion.
- Anti-fee-sniping locktime (W113 G25-G28) — orthogonal to selection.
- Mempool-cluster eligibility (W120/W121 territory).
- BIP-174 PSBT funding-via-`walletcreatefundedpsbt` — separate wave
  (`tests_psbt_w47.zig`).
