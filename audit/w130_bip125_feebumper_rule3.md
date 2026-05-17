# W130 — BIP-125 RBF feebumper Rule 3 audit (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's wallet `bumpFee` / `psbtBumpFee` / RPC `bumpfee` /
`psbtbumpfee` paths and the matching mempool RBF rules (esp. Rule 3 /
Rule 4 absolute fee + bandwidth checks), vs Bitcoin Core's
`wallet/feebumper.{h,cpp}`, `policy/rbf.{h,cpp}`, `policy/feerate.{h,cpp}`,
and `validation.cpp` ATMP RBF path.
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w130` (folded into `zig build test`).
**Related prior wave:** W120 (`tests_w120_mempool_rbf.zig`) audits Rule 1-5
*mempool* enforcement; W118 (`tests_w118_wallet.zig`) audits wallet
foundations; W129 audits coin selection. W130 zooms on the *feebumper*
client of those rules — how clearbit constructs replacement transactions
and which Rule 3 invariants are observable on the wallet side, with
particular attention to the `incrementalRelayFee.GetFee(maxTxSize)`
arithmetic Core uses as the canonical Rule 3 floor.

## Summary

clearbit ships a minimal but functional `bumpFee` / `psbtBumpFee` in
`src/wallet.zig:2823-3051` plus a `bumpfee` / `psbtbumpfee` RPC at
`src/rpc.zig:10832-11098`, and the mempool-side RBF enforcement in
`src/mempool.zig::checkRBFRules` (W120-audited, 6/8 gates PRESENT).
The two halves DO NOT share constants, units, or rounding direction:

- **`wallet.INCREMENTAL_FEE_RATE = 1` sat/vB** (`wallet.zig:2684`) vs
  **`mempool.INCREMENTAL_RELAY_FEE = 100` sat/kvB** (`mempool.zig:55`).
  Numerically `1 sat/vB = 1000 sat/kvB`, so the wallet's incremental
  bump is **10× higher** than the mempool's incremental-relay floor.
  That direction is safe (wallet over-pays), but the two constants are
  out of sync and the comment block at `wallet.zig:2680-2683` claims
  Core's `DEFAULT_INCREMENTAL_RELAY_FEE` is `1` — Core's
  `DEFAULT_INCREMENTAL_RELAY_FEE` is **1000 sat/kvB = 1 sat/vB**, which
  is consistent in *sat/vB*, so the wallet matches Core's network
  incremental floor while the mempool is 10× UNDER it. See W120 BUG-1
  cross-reference and BUG-1 below.
- **Core's wallet uses `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB =
  5 sat/vB`** as a *wallet-private* floor (`wallet.h:124`) — five times
  larger than the network incremental fee. clearbit's wallet has no
  analog, so bumps at the BIP-125 absolute floor will fail mempool
  re-admission whenever a node has `-incrementalrelayfee` set higher
  than `1 sat/vB`.
- **Core's precise Rule 3 invariant is**
  `new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)`
  (feebumper.cpp:93) where `GetFee` **rounds UP** via
  `FeeFrac::EvaluateFeeUp` (`feefrac.h:212` — `CeilDiv`). clearbit's
  wallet computes `orig_fee + 1 * orig_vsize` (integer multiplication,
  no rounding ambiguity since the rate is exactly per-vbyte), but the
  size used is **`orig_vsize`**, not Core's `maxTxSize` (the
  maximum-signed *new* vsize). The replacement is typically slightly
  larger than the original (signature-size variance, change reductions,
  signaling-sequence changes), so clearbit's wallet under-shoots Core's
  floor on every bump.
- **The mempool side rounds DOWN**: `mempool.zig:3061`
  `@divTrunc(new_vsize * INCREMENTAL_RELAY_FEE, 1000)` truncates toward
  zero, but Core's `CFeeRate::GetFee` uses `EvaluateFeeUp` (`CeilDiv`)
  for the Rule 4 floor. The difference is at most `INCREMENTAL_RELAY_FEE
  / 1000 = 0.1` sat per vbyte under-counted, but the strict `<`
  comparison means a replacement paying *exactly* the ceiling is
  **rejected** by Core and **accepted** by clearbit when
  `new_vsize % 1000 != 0`. Documented in BUG-7 below.
- **`computeBumpFee` user-fee-rate path**
  (`wallet.zig:2801-2804`): `new_fee = fr * orig_vsize` uses **integer
  multiplication, no rounding**, and again uses `orig_vsize`, not the
  *new* vsize. Core multiplies the user-supplied `CFeeRate` against
  `maxTxSize` (the new-tx maximum-signed vsize) and reports an
  insufficient-total-fee error before constructing the replacement.
- **No `mempoolMinFee` / `requiredFee` / `m_default_max_tx_fee`
  precondition checks**: Core's `CheckFeeRate`
  (feebumper.cpp:60-117) gates on three additional thresholds beyond the
  Rule 3 floor — clearbit checks none of them, so a bumpfee call can
  emit a tx that the mempool will then reject for unrelated reasons
  with no error mapping back to the operator.
- **No `PreconditionChecks`**: Core's `PreconditionChecks`
  (feebumper.cpp:23-57) rejects bumps when (a) the wallet/mempool has
  any descendant of the bumped tx, (b) the tx has been mined, (c) the
  tx was already bumped (`mapValue["replaced_by_txid"]` is set), or
  (d) the tx has external inputs the wallet can't reason about
  (`AllInputsMine`). clearbit performs *none* of these checks on the
  wallet side; the RPC layer does a minimal "is it in the mempool?"
  lookup at `rpc.zig:10936`, which substitutes only for (b).

The Core feebumper API surface clearbit is missing:

| Core feature | clearbit status |
|---|---|
| `outputs` (replace original outputs) | absent |
| `original_change_index` | absent |
| `m_min_depth = 1` (no new unconfirmed inputs — BIP-125 Rule 2) | absent |
| `combined_bump_fee` (ancestor cluster) | absent |
| `mempoolMinFee` precondition | absent |
| `requiredFee` precondition | absent |
| `m_default_max_tx_fee` ceiling | absent |
| `HasWalletSpend` precondition | absent |
| `hasDescendantsInMempool` precondition | absent |
| `GetTxDepthInMainChain != 0` precondition | absent |
| `AllInputsMine` (require_mine) precondition | absent |
| `replaced_by_txid` / `replaces_txid` markers | absent |
| `TransactionCanBeBumped` standalone predicate | absent |
| `WALLET_INCREMENTAL_RELAY_FEE = 5000` | absent |
| `wallet.MarkReplaced` (commit-side bookkeeping) | absent |

Rule 4 bandwidth precision is the most-load-bearing finding:
**clearbit's mempool admits replacements that pay 0.000001-0.99 sat
LESS than Core's Rule 4 threshold whenever
`replacement_vsize % 1000 != 0` and the `additional_fee` equals the
floor-of-the-true-ceiling.** Operator-level effect is small, but the
divergence is observable by replaying a Core-rejected RBF onto clearbit
and watching it accept.

## 30-gate matrix

Each gate documents a Core invariant or surface, classifies clearbit's
current state, and points at the exact source location.

### Wallet-side (feebumper.cpp parity)

- **G1 — Rule 3 absolute-fee comparator: `new_total_fee >= old_fee +
  incrementalRelayFee.GetFee(maxTxSize)`** [PARTIAL]
  - `wallet.zig:2796-2809` (`computeBumpFee`) computes `orig_fee +
    INCREMENTAL_FEE_RATE * orig_vsize`. Comparator is implicit (the new
    fee is *constructed* to satisfy the floor; there is no explicit
    `if (new_total_fee < minTotalFee) return INVALID_PARAMETER` gate).
  - BUG-2 (uses `orig_vsize`, not `maxTxSize` of *new* tx).

- **G2 — `incrementalRelayFee.GetFee(maxTxSize)` rounds UP via
  `CFeeRate::GetFee` → `EvaluateFeeUp` → `CeilDiv`** [PARTIAL]
  - `wallet.zig:2806` uses integer multiplication
    `INCREMENTAL_FEE_RATE * orig_vsize`. Because the rate is `1 sat/vB`,
    the product is already integer — no rounding direction visible.
    If anyone changes `INCREMENTAL_FEE_RATE` to a fractional rate the
    rounding direction will silently flip. BUG-3.

- **G3 — `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB` private floor**
  [MISSING]
  - Core's `EstimateFeeRate` (feebumper.cpp:135-137) takes
    `max(node_incremental_relay_fee, WALLET_INCREMENTAL_RELAY_FEE)`.
    clearbit has no `WALLET_INCREMENTAL_RELAY_FEE` constant. BUG-4.

- **G4 — `mempoolMinFee` precondition (newFeerate.GetFeePerK() <
  minMempoolFeeRate.GetFeePerK())** [MISSING]
  - Core: feebumper.cpp:67-75. clearbit's mempool has `getMinFee()`
    (`mempool.zig:3655`+) but `wallet.bumpFee` / RPC `bumpfee` never
    consult it. BUG-5.

- **G5 — `requiredFee = GetRequiredFee(wallet, maxTxSize)`
  precondition** [MISSING]
  - Core: feebumper.cpp:101-106. clearbit has no `GetRequiredFee`
    analog and no precondition that compares the new total fee to
    `MIN_RELAY_FEE * maxTxSize / 1000`. BUG-6.

- **G6 — `m_default_max_tx_fee` ceiling** [MISSING]
  - Core: feebumper.cpp:109-114; default `COIN/10 = 0.1 BTC`.
    clearbit has no `max_tx_fee` constant or precondition. BUG-7.

- **G7 — `PreconditionChecks` panel (HasWalletSpend, hasDescendantsInMempool,
  GetTxDepthInMainChain, replaced_by_txid, AllInputsMine)** [MISSING]
  - Core: feebumper.cpp:23-57. clearbit's RPC does a single mempool
    lookup (`rpc.zig:10936`) that covers only "already confirmed". The
    other four checks are missing. BUG-8.

- **G8 — `outputs` parameter (replace original outputs)** [MISSING]
  - Core: feebumper.h:57 + feebumper.cpp:249-263. clearbit's
    `BumpFeeOptions` (`wallet.zig:2737-2746`) has no `outputs` field;
    the bump always preserves original outputs. BUG-9.

- **G9 — `original_change_index` parameter** [MISSING]
  - Core: feebumper.h:58 + feebumper.cpp:181-184. clearbit auto-finds
    a wallet-owned change output via `findChangeOutput`
    (`wallet.zig:2768-2792`); no caller override. BUG-10.

- **G10 — `m_min_depth = 1` (BIP-125 Rule 2: no new unconfirmed inputs)**
  [MISSING]
  - Core: feebumper.cpp:312. The replacement transaction is built via
    `createTransaction` which has no `min_depth=1` filter — coin
    selection happily uses zero-conf change. BUG-11.

- **G11 — `calculateCombinedBumpFee` (ancestor cluster)** [MISSING]
  - Core: feebumper.cpp:83-87. clearbit has no ancestor-cluster
    bump-fee accounting; reused inputs that have unconfirmed parents
    will silently under-pay for the cluster. BUG-12.

- **G12 — `replaces_txid` mapValue on new tx + `replaced_by_txid`
  mapValue on old tx (wallet bookkeeping)** [MISSING]
  - Core: feebumper.cpp:371-372 + feebumper.cpp:42-45. clearbit's
    wallet has no per-tx `mapValue` and never writes either marker; a
    second `bumpfee` call on the same txid will succeed silently. BUG-13.

- **G13 — `TransactionCanBeBumped` standalone predicate** [MISSING]
  - Core: feebumper.h:34 + feebumper.cpp:148-157. clearbit has no
    standalone predicate; callers must invoke `bumpFee` and catch
    errors. BUG-14.

- **G14 — `wallet.MarkReplaced` (commit-side bookkeeping)** [MISSING]
  - Core: feebumper.cpp:378-380. clearbit doesn't mark the original
    tx as replaced; a re-broadcast of the original would not be
    deduped. BUG-15.

- **G15 — `BumpFeeOptions.outputs / original_change_index /
  replaceable` (RPC-level options)** [MISSING]
  - Core wallet `bumpfee` RPC accepts `replaceable`, `outputs`,
    `original_change_index`, `conf_target`, `fee_rate`, `estimate_mode`,
    `signer` (Core 26+). clearbit's `parseBumpFeeArgs`
    (`rpc.zig:10866-10919`) accepts only `fee_rate` + `force`. BUG-16.

### Mempool-side (rbf.cpp parity, audited against W120)

- **G16 — Mempool Rule 3 absolute-fee comparator (`new_modified_fee <
  total_evicted_fee`)** [PRESENT]
  - `mempool.zig:3053`. FIX-72 closed the modified-fee accumulation
    bug. Strict `<` matches Core.

- **G17 — Mempool Rule 4 bandwidth: `additional_fee >=
  relay_fee.GetFee(replacement_vsize)`** [PARTIAL]
  - `mempool.zig:3061` uses `@divTrunc(new_vsize *
    INCREMENTAL_RELAY_FEE, 1000)` — **rounds DOWN**, Core rounds UP via
    `CFeeRate::GetFee` / `FeeFrac::EvaluateFeeUp` (`feefrac.h:212`).
    For `new_vsize % 1000 != 0`, clearbit's floor is up to `(1000 -
    new_vsize % 1000) * INCREMENTAL_RELAY_FEE / 1000` sat LOWER than
    Core's. Strict `<` comparison then admits replacements Core would
    reject. BUG-17 (CDIV — consensus-policy divergence).

- **G18 — `INCREMENTAL_RELAY_FEE` magnitude parity with
  Core's `DEFAULT_INCREMENTAL_RELAY_FEE = 1000 sat/kvB`** [PRESENT]
  - `mempool.zig:55` declares `INCREMENTAL_RELAY_FEE: i64 = 100` and
    the comment claims parity with Core's `DEFAULT_INCREMENTAL_RELAY_FEE
    = 100`. Core's actual default is `DEFAULT_INCREMENTAL_RELAY_FEE =
    1000` sat/kvB (`policy/policy.h`). The clearbit constant is **10×
    too low** — but every place clearbit consumes it
    (`mempool.zig:3061`, `mempool.zig:3183`) treats the unit as
    sat/kvB and divides by 1000, so the *effective* incremental rate
    in clearbit's mempool is `100/1000 = 0.1 sat/vB`, i.e. one-tenth
    of Core's. BUG-1 (CDIV — every RBF rule 4 admits 10× cheaper
    bumps than Core). This bug was flagged in the pre-FIX-72 comment
    at `mempool.zig:48-54` as a *historical* misvalue but the same
    pattern recurs for `INCREMENTAL_RELAY_FEE` itself — the comment
    block says "10× too high, RBF rule 4 broken" yet the value `100`
    is identical to the value the comment is warning about. PARENT
    of BUG-17. Cross-impl-cmp candidate against rustoshi /
    blockbrew / ouroboros which use sat/vB units directly.

- **G19 — Mempool Rule 5 max evictions = 100** [PRESENT]
  - `mempool.zig:66` `MAX_REPLACEMENT_EVICTIONS = 100`. Matches Core.

- **G20 — Mempool Rule 2 (BIP-125 spends-conflicting check)** [PRESENT]
  - `mempool.zig:3027-3031`. Matches Core's `EntriesAndTxidsDisjoint`.

- **G21 — Mempool Rule 1 (opt-in signaling or full-RBF)** [PRESENT]
  - `mempool.zig:2973-2981`. Matches Core.

- **G22 — `ImprovesFeerateDiagram` (Core 28+ refinement)** [PARTIAL]
  - `mempool.zig:3066-3109` implements a single-chunk diagram
    approximation. W120 already classified this as PARTIAL.

### Cross-cutting

- **G23 — Wallet bumpFee + mempool checkRBFRules share constants /
  units** [MISSING]
  - `wallet.INCREMENTAL_FEE_RATE = 1` (sat/vB) and
    `mempool.INCREMENTAL_RELAY_FEE = 100` (claimed sat/kvB) are
    DIFFERENT constants. A future fix wave must consolidate. BUG-18.

- **G24 — `bumpfee` RPC error mapping covers all Core
  Result::* variants** [PARTIAL]
  - `rpc.zig:10981-10992`: maps 7 wallet errors but uses
    `RPC_VERIFY_REJECTED` for `NotBIP125Replaceable` /
    `NoChangeOutput` / `DustAfterReduce`. Core wallet uses
    `RPC_INVALID_PARAMETER` for these. BUG-19.

- **G25 — `bumpfee` RPC returns `errors: []` even on success** [PARTIAL]
  - `rpc.zig:11047`. Matches Core's shape (always-present `errors`
    array). PRESENT in shape; PARTIAL because Core also returns
    `psbt` when the wallet is watch-only and `replaceable: true` by
    default.

- **G26 — `prioritisetransaction` modifies bump-fee accounting** [PARTIAL]
  - `mempool.zig:3001` applies delta on conflict side and
    `mempool.zig:3044` on new-tx side (FIX-72). Wallet bumpFee
    however does NOT query the delta — the wallet computes a bump
    relative to *old_fee* (= `Σ in − Σ out`), not modified_fee. If
    the operator prioritised the original tx by `+k` sat, the wallet
    bump will under-shoot Core's Rule 3 floor by `k` sat. BUG-20.

- **G27 — `psbtbumpfee` emits `replaces_txid` field in PSBT global
  map** [MISSING]
  - clearbit's `psbtBumpFee` does not attach the original txid to
    the new PSBT. Caller can't tell which tx it replaces. BUG-21.

- **G28 — `bumpfee` RPC accepts `conf_target` / `estimate_mode`**
  [MISSING]
  - `rpc.zig:10891-10915` only parses `fee_rate` and `force`. Core
    accepts target-block and mode-string for fee estimation. BUG-22.

- **G29 — `walletrbf` / `-walletrbf` default-on toggle** [MISSING]
  - Core `DEFAULT_WALLET_RBF = true` (`wallet.h:132`). clearbit's
    `CreateTxOptions.replaceable` defaults to `false` (which Core
    overrides to `true` for wallet-created txs). BUG-23.

- **G30 — Forward-regression guard against unit drift** [MISSING]
  - No source-grep test asserts that
    `mempool.INCREMENTAL_RELAY_FEE` and
    `wallet.INCREMENTAL_FEE_RATE` are consistent in their effective
    sat/vB rate. A future drive-by change to one constant will
    silently de-sync the two halves. BUG-24.

## Bugs

1. **BUG-1 (CDIV, MED) — `mempool.INCREMENTAL_RELAY_FEE = 100` is 10×
   too low.** Core's `DEFAULT_INCREMENTAL_RELAY_FEE = 1000 sat/kvB`
   (`policy/policy.h:48`). The comment at `mempool.zig:48-54`
   contradicts itself (claims the historical `1000` was 10× too high,
   then sets the value to `100` which is 10× too low). Every Rule 4
   floor admits 10× cheaper bumps than Core. Cross-impl-cmp candidate
   vs rustoshi (sat/vB units directly) / blockbrew (Core-aligned
   constants).

2. **BUG-2 (MED) — `computeBumpFee` uses `orig_vsize`, not new-tx
   `maxTxSize`.** Core's `CheckFeeRate` (feebumper.cpp:88-99) uses
   `newFeerate.GetFee(maxTxSize)` where `maxTxSize` is the *new* tx's
   maximum-signed vsize. clearbit's `wallet.zig:2806-2808` uses
   `orig_vsize` returned by `estimateTxVsize(orig_prevouts,
   orig_tx.outputs.len)`. Replacement is typically 2-5 vbytes larger
   due to signaling-sequence changes + change reductions; clearbit's
   bump under-shoots Core's floor by that delta × incremental_rate.

3. **BUG-3 (LOW) — `computeBumpFee` lacks `CFeeRate::GetFee` round-up
   semantics.** Core's `CFeeRate::GetFee` rounds via `CeilDiv`
   (`feefrac.h:212`). clearbit's integer multiplication at
   `wallet.zig:2806` happens to round correctly only because
   `INCREMENTAL_FEE_RATE = 1` (whole sat/vB). Any future change to
   fractional rate (e.g., `1.5 sat/vB`) will silently truncate.

4. **BUG-4 (MED) — `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB`
   private floor absent.** Core's `EstimateFeeRate`
   (feebumper.cpp:135-137) takes `max(node_incremental, WALLET_INC)`,
   defending against operator-lowered `-incrementalrelayfee`.
   clearbit has no such floor; a node with `-incrementalrelayfee=0`
   would emit bumps that Core mempool peers reject.

5. **BUG-5 (MED) — `mempoolMinFee` precondition missing in
   `bumpFee`.** Core feebumper.cpp:67-75 rejects with
   `RPC_WALLET_ERROR` before constructing the replacement. clearbit
   constructs + signs the replacement and only finds out at
   `sendrawtransaction` (which has no error-mapping back to the
   `bumpfee` caller).

6. **BUG-6 (LOW) — `requiredFee = GetRequiredFee(wallet, maxTxSize)`
   precondition missing.** Symptoms: same as BUG-5 — caller sees a
   signed replacement that the mempool then rejects.

7. **BUG-7 (CDIV, HIGH) — Mempool Rule 4 rounds DOWN.**
   `mempool.zig:3061`: `@divTrunc(new_vsize * INCREMENTAL_RELAY_FEE,
   1000)`. Core's `relay_fee.GetFee(replacement_vsize)` rounds UP
   (`FeeFrac::EvaluateFeeUp` → `CeilDiv`). For `new_vsize % 1000 !=
   0`, clearbit's floor is up to 99 sat × `INCREMENTAL_RELAY_FEE /
   1000` lower than Core's. With BUG-1 compounding, the discrepancy
   is ~1 sat per replacement at typical vsizes. Cross-impl-cmp
   candidate.

8. **BUG-8 (MED) — `PreconditionChecks` panel missing.**
   Specifically:
   (a) `HasWalletSpend` — bumping a tx with a wallet descendant is
       silently allowed (the descendant will be invalidated on
       broadcast; caller has no warning).
   (b) `hasDescendantsInMempool` — same as (a) but for mempool
       descendants from any wallet.
   (c) `GetTxDepthInMainChain != 0` — already covered partially by
       "not in mempool" rejection but doesn't distinguish
       *conflicted-with-mined* vs *mined-itself*.
   (d) `replaced_by_txid` — clearbit has no per-tx mapValue, so a
       second `bumpfee` on the same txid runs the full pipeline
       again.
   (e) `AllInputsMine` (require_mine) — clearbit does require this
       (`rpc.zig:10956-10976`) at the RPC layer but the wallet API
       allows callers to pass external prevouts.

9. **BUG-9 (LOW) — `outputs` parameter (replace originals) absent.**

10. **BUG-10 (LOW) — `original_change_index` parameter absent.**

11. **BUG-11 (MED) — BIP-125 Rule 2 not enforced wallet-side.** The
    replacement tx may include new unconfirmed inputs via coin
    selection in `createTransaction`. Core forces `m_min_depth = 1`
    (feebumper.cpp:312) precisely to prevent this. Replacements with
    new unconfirmed inputs are *valid* per BIP-125 §3 Rule 2 (it
    only forbids *the replacement* spending NEW unconfirmed inputs)
    but they enlarge the conflict graph and may fail Rule 5 later.

12. **BUG-12 (LOW) — `calculateCombinedBumpFee` (ancestor cluster
    bump fee) absent.** When the reused inputs depend on an enormous
    unconfirmed cluster, Core early-rejects; clearbit silently
    under-pays for the cluster.

13. **BUG-13 (MED) — No `replaces_txid` / `replaced_by_txid`
    bookkeeping.** Caller can replay `bumpfee` on the same txid
    indefinitely. Core's `mapValue["replaced_by_txid"]` rejects
    re-bumps in `PreconditionChecks` (feebumper.cpp:42-45).

14. **BUG-14 (LOW) — `TransactionCanBeBumped` standalone predicate
    absent.** RPC clients have to call `bumpfee` (which signs +
    sends) just to find out if a tx is bumpable.

15. **BUG-15 (LOW) — `wallet.MarkReplaced` commit-side bookkeeping
    absent.** Original tx is not flagged as replaced; subsequent
    `getbalance` / `listtransactions` views won't show the
    replacement linkage.

16. **BUG-16 (LOW) — RPC `bumpfee` options surface is minimal.**
    Missing: `replaceable`, `outputs`, `original_change_index`,
    `conf_target`, `estimate_mode`, `signer` (Core 26+).

17. **BUG-17 (CDIV, HIGH) — Mempool Rule 4 strict-`<` + round-down
    floor admits Core-rejected bumps.** Concrete repro:
    `replacement_vsize = 1500`, `INCREMENTAL_RELAY_FEE = 100`,
    Core floor = `ceil(1500 × 100 / 1000) = 150` sat (CeilDiv
    when divisible: same). For `replacement_vsize = 1501`:
    clearbit floor = `floor(1501 × 100 / 1000) = 150`, Core floor =
    `ceil(150100 / 1000) = 151`. Bumps paying exactly 150 sat extra:
    Core REJECT, clearbit ACCEPT.

18. **BUG-18 (LOW) — Wallet `INCREMENTAL_FEE_RATE` and mempool
    `INCREMENTAL_RELAY_FEE` constants are different.**
    `wallet.INCREMENTAL_FEE_RATE = 1` sat/vB.
    `mempool.INCREMENTAL_RELAY_FEE = 100` sat/kvB = 0.1 sat/vB.
    The two halves of clearbit's RBF code use **different effective
    rates** — wallet bumps at 1 sat/vB, mempool admits at 0.1
    sat/vB. Direction is safe (wallet over-pays) but the
    inconsistency is a foot-gun.

19. **BUG-19 (LOW) — `bumpFeeErrorToRpc` uses
    `RPC_VERIFY_REJECTED` for `NotBIP125Replaceable` /
    `NoChangeOutput` / `DustAfterReduce`.** Core uses
    `RPC_INVALID_PARAMETER` for these (see Core
    `wallet/rpc/spend.cpp::bumpfee` `Result::INVALID_PARAMETER`
    branches).

20. **BUG-20 (MED) — Wallet `bumpFee` ignores `prioritisetransaction`
    delta on the bumped tx.** `mempool.entries.get(txid)` →
    `getModifiedFee(entry)` gives the priority-adjusted fee; the
    wallet computes the bump relative to raw `Σ in − Σ out` only.
    If operator prioritised the original tx by `+k` sat, the bump
    pays `k` sat less than Core's `replacement_fees < original_fees`
    threshold (mempool then rejects with `ReplacementFeeTooLow`,
    `bumpfee` returns a confusing "succeeded but mempool says no"
    state).

21. **BUG-21 (LOW) — `psbtBumpFee` emits no `replaces_txid` field
    in PSBT global map.**

22. **BUG-22 (LOW) — `bumpfee` RPC doesn't accept `conf_target` /
    `estimate_mode`.**

23. **BUG-23 (MED) — `CreateTxOptions.replaceable` defaults to
    `false`; Core's `DEFAULT_WALLET_RBF = true`.** Every clearbit
    wallet-created tx emits non-replaceable inputs by default; the
    user must opt-in to RBF. Core's default is opt-out.

24. **BUG-24 (LOW) — No forward-regression guard for the two
    incremental-fee constants.** A drive-by `INCREMENTAL_RELAY_FEE =
    1000` "fix" would silently restore the historical 10×-too-high
    floor without a CI failure (W120 G3 only verifies the constant
    is present, not its magnitude).

## Top findings (5)

1. **BUG-1 / BUG-17 / BUG-7 compound: clearbit's mempool admits
   Rule 4 violations Core rejects.** Effective incremental relay
   floor is `0.1 sat/vB` (Core: `1 sat/vB`) AND the floor itself
   rounds DOWN (Core rounds UP). A bump paying exactly the
   floor-of-Core's-true-ceiling is accepted by clearbit, rejected
   by Core. Two CDIV bugs, single chain of fixes. **Highest-
   priority morning candidate.**

2. **BUG-2: `computeBumpFee` uses original tx's vsize, not the
   new tx's maximum-signed vsize.** Replacement is typically
   slightly larger (changed sequences, reduced change, added
   signaling). Core multiplies the incremental floor against the
   *new* `maxTxSize`. clearbit under-shoots Core's threshold by
   delta × incremental_rate on every bump.

3. **BUG-18: Two different incremental-fee constants in same
   codebase.** `wallet.INCREMENTAL_FEE_RATE = 1 sat/vB`,
   `mempool.INCREMENTAL_RELAY_FEE = 100 sat/kvB = 0.1 sat/vB`. The
   wallet over-bumps relative to its own mempool by 10×. Direction
   is safe but the inconsistency is fragile. Should consolidate to
   one source.

4. **BUG-8: Five-precondition panel missing on wallet side.**
   `HasWalletSpend` / `hasDescendantsInMempool` / `GetTxDepthInMainChain`
   / `replaced_by_txid` / `AllInputsMine`. Core gates these before
   any tx is signed. clearbit signs first, fails at mempool
   submission (or worse, broadcasts and invalidates a wallet
   descendant silently).

5. **BUG-23: Wallet-emitted txs are non-replaceable by default.**
   Core's `DEFAULT_WALLET_RBF = true`. Every clearbit-created tx
   has sequence `0xFFFFFFFE` (locktime-only) unless the caller
   explicitly passes `replaceable: true`. This means the *vast
   majority* of clearbit-emitted txs cannot be bumped at all —
   `bumpFee` will return `NotBIP125Replaceable` for them. This is
   a UX cliff, not a consensus break, but it makes the entire
   BIP-125 wallet path unreachable for default-options callers.

## Out of scope

- Active code changes — this is a discovery audit. BUG-1 / BUG-17 /
  BUG-7 are CDIV-grade and warrant a FIX-90 wave (or similar) but
  no production code is touched here.
- `submitpackage` RBF (BIP-431 TRUC v3 always-replaceable) — covered
  by W120 G21.
- Cluster-mempool reformulation (Core master) — feebumper Rule 3 is
  a stable invariant; cluster mempool only changes the diagram-check
  side (W120 G22).
- `-incrementalrelayfee` CLI plumbing — operator-experience surface,
  covered by W124.
- Fee estimator's `processBlock` reaction to RBF replacements —
  fee-estimator audit was W114.

## References

- `bitcoin-core/src/wallet/feebumper.cpp`
- `bitcoin-core/src/wallet/feebumper.h`
- `bitcoin-core/src/policy/rbf.cpp`
- `bitcoin-core/src/policy/rbf.h`
- `bitcoin-core/src/policy/feerate.cpp`
- `bitcoin-core/src/policy/feerate.h`
- `bitcoin-core/src/util/feefrac.h`
- `bitcoin-core/src/wallet/wallet.h` (`WALLET_INCREMENTAL_RELAY_FEE`)
- BIP-125 §3 (Opt-in Full Replace-by-Fee Signaling)
- clearbit `src/wallet.zig:2648-3051` (bumpFee / psbtBumpFee)
- clearbit `src/rpc.zig:10832-11098` (bumpfee / psbtbumpfee RPC)
- clearbit `src/mempool.zig:2925-3110` (checkRBFRules) — W120 audited
