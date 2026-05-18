# W145 — Coinbase / subsidy / fees / MAX_MONEY audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's monetary-invariant pipeline — block-subsidy
computation (`consensus.getBlockSubsidy`), MAX_MONEY/MoneyRange enforcement
(`consensus.isValidMoney` and call-sites), coinbase output-value gate
(`bad-cb-amount` ⇒ `BadCoinbaseValue`), per-tx fee invariant
(`bad-txns-in-belowout` ⇒ `InsufficientFunds`), coinbase scriptSig bounds
(`bad-cb-length`), duplicate-input detection (CVE-2018-17144,
`bad-txns-inputs-duplicate`), CVE-2010-5139 output-overflow gates, and
COINBASE_MATURITY (100-confirmation) enforcement in the chainstate,
mempool, and wallet.

**Bitcoin Core references:**
- `bitcoin-core/src/validation.cpp::GetBlockSubsidy` @ 1839-1850
  (initial 50*COIN; halve every `nSubsidyHalvingInterval`; ≥64-halvings
  shift-undefined-behavior guard).
- `bitcoin-core/src/validation.cpp::ConnectBlock` @ 2610-2614
  (`blockReward = nFees + GetBlockSubsidy()`; `bad-cb-amount` reject).
- `bitcoin-core/src/consensus/amount.h` @ 15-27 (COIN = 1e8;
  `MAX_MONEY = 21_000_000 * COIN`; `MoneyRange(nValue) ⇔ 0 ≤ nValue ≤ MAX_MONEY`).
- `bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction` @ 11-60
  (vin/vout empty rejects; `bad-txns-vout-negative`; `bad-txns-vout-toolarge`;
  `bad-txns-txouttotal-toolarge`; CVE-2018-17144 duplicate-input via
  `std::set<COutPoint>`; `bad-cb-length`; `bad-txns-prevout-null`).
- `bitcoin-core/src/consensus/tx_verify.cpp::CheckTxInputs` @ 164-210
  (COINBASE_MATURITY @ 179-182; `bad-txns-inputvalues-outofrange` @ 186-188;
  `bad-txns-in-belowout` @ 196-199; `bad-txns-fee-outofrange` @ 200-209).
- `bitcoin-core/src/consensus/consensus.h:19` (`COINBASE_MATURITY = 100`).
- `bitcoin-core/src/kernel/chainparams.cpp` @ 84, 209, 310, 454
  (mainnet/testnet3/testnet4/signet `nSubsidyHalvingInterval = 210000`)
  and @ 535 (regtest = 150).
- `bitcoin-core/src/primitives/transaction.cpp::CTransaction::GetValueOut`
  @ 98-108 (per-output MoneyRange AND running-total MoneyRange before
  each add; throws on out-of-range).
- `bitcoin-core/src/validation.cpp` @ 374-375 (mempool maturity:
  `mempool_spend_height = m_chain.Tip()->nHeight + 1`).

**BIPs / CVEs:**
- CVE-2010-5139 (output-value overflow → inflation).
- CVE-2018-17144 (duplicate inputs → inflation).
- BIP-30 (duplicate txid; tangential — covered in W143).

**Mode:** DISCOVERY (no production code changes; this audit catalogues
parity bugs only).

**Implementation files audited:**
- `clearbit/src/consensus.zig`
  - `MAX_MONEY` @ 108, `INITIAL_SUBSIDY` @ 111,
    `SUBSIDY_HALVING_INTERVAL` @ 114, `COINBASE_MATURITY` @ 117.
  - `getBlockSubsidy` @ 812-816, `isValidMoney` @ 819-821.
  - `NetworkParams.subsidy_halving_interval` field @ 376 + per-net values
    @ 508, 625, 679, 730, 779 (mainnet, testnet3, testnet4, signet,
    regtest).
- `clearbit/src/validation.zig`
  - `checkTransactionSanity` @ 316-364 (CheckTransaction analog).
  - `checkTransactionContextual` @ 368-454 (DEAD MODULE — defined but
    never called from production paths; CheckTxInputs analog).
  - `checkBlock` @ 763-858 (legacy / mining / test entry).
  - `connectBlock` @ 879-1000 (legacy / test / dumptxoutset rollback entry).
  - `validateBlockForIBD` @ 1123-1618 (production IBD entry).
  - `acceptBlock` @ 1688-1717 (unified entry — routes to validateBlockForIBD).
- `clearbit/src/storage.zig`
  - `CompactUtxo` @ 654-718 (height MSB-packs `is_coinbase`; mask
    `0x7FFFFFFF` caps effective height at `2^31-1`).
  - `connectBlockInner` @ 4037-4268 (pure UTXO mutation; ZERO consensus
    checks — coinbase amount / fee invariant / MoneyRange).
  - `connectBlockLocked` @ 3051-3058 (used by rpc.zig::replayReconnect;
    bypasses validation by design).
  - `isScriptUnspendable` @ 1870-1874.
- `clearbit/src/mempool.zig`
  - per-input maturity + value-range loop @ 1085-1130.
  - per-tx fee check @ 1149-1154.
- `clearbit/src/wallet.zig`
  - coinbase maturity in coin-selection @ 503-507, 1327-1331, 2326.
- `clearbit/src/block_template.zig`
  - `BlockTemplate.getBlockReward` @ 126-129.
  - `createCoinbaseTx` @ 499-501 (`block_reward = subsidy + total_fees`).

## Summary

clearbit's monetary invariants are split across three competing
pipelines, each with subtly different surface area:

1. **`validateBlockForIBD`** (production P2P + acceptBlock dispatch) —
   the most Core-faithful path. Per-input MoneyRange, accumulated-fee
   MoneyRange, per-block coinbase ≤ subsidy + fees, coinbase maturity
   on every input (height-aware), intra-block stitching.

2. **`connectBlock`** legacy path (mining, storage rollback, ~12
   internal tests) — the W93 audit closed the original
   `total_fees = 0` and `bad-cb-amount = TODO` holes, but the path
   still **does not enforce COINBASE_MATURITY** because the
   `SigopUtxoView` it consumes carries only `(script_pubkey, amount)`
   and drops the `(height, is_coinbase)` metadata Core's CheckTxInputs
   requires. Any caller that exercises this path with a coinbase-spending
   tx < 100 blocks deep silently admits it.

3. **`checkTransactionContextual`** (validation.zig:368-454) — a
   **dead module**: defined, fully-typed, fully-tested-against by
   doc-comments, but **never invoked by any production path**.
   `grep -rn checkTransactionContextual /home/work/hashhog/clearbit/`
   returns only the definition, its public-API comment, and a single
   stale reference in `mempool.zig:2565` (in a comment). This is the
   *dead-module* fleet pattern (W76+, repeatedly).

The single highest-severity finding in W145 is **BUG-1** — the legacy
`connectBlock` path lacks any coinbase-maturity gate, so a block that
arrives through the mining / rollback / submitblock-replay seam can
spend an immature coinbase 1 block after generation. Combined with the
mining path being the *only* user of `connectBlock` in production, the
practical exposure is low; but the gate is consensus-required.

The next-largest finding is **BUG-3** — the
`mempool.acceptToMemoryPool` coinbase-maturity check is off-by-one
relative to Core, using tip height instead of `tip+1` (= the spending
height). Core admits at exactly 100 confirmations; clearbit refuses
until 101. False-reject only, not consensus-divergent, but causes
relay/validation parity mismatches against Core nodes at the boundary.

The legacy `checkBlock` (called from `connectBlock`) contains a
**dead empty branch** at lines 836-839 — the body of
`if (coinbase_value > subsidy) { ... }` is literally empty, with a
two-line comment-as-confession explaining why. The check looks like a
reject-gate at a glance; static analysis would flag this as "always
takes the dead branch". W143's BUG-W143-16 already covered this; we
re-cite it here because it sits inside the W145 invariant set.

Other consequential findings:
- **Duplicate-input detection is O(n²)** (`checkTransactionSanity`
  @ 337-346) where Core uses `std::set<COutPoint>` (O(n log n)). For
  the standard MAX_TX_IN cap of 100,000 inputs, this is ~10^10 hash
  comparisons. Block-weight limits would clamp this in practice, but
  the per-tx sanity check executes on each peer-delivered tx and the
  cap on the per-tx input loop is only enforced by `bad-txns-oversize`
  later. (BUG-4.)
- **No CVE-2010-5139-class `GetValueOut`-style double-MoneyRange check
  on coinbase output sum**: the `for (block.transactions[0].outputs)
  coinbase_value += out.value;` loop at validation.zig:830-832,
  974-975, and 1461-1462 does NOT call `isValidMoney` on each
  intermediate sum. Core's `GetValueOut` (transaction.cpp:98-108)
  explicitly throws if any intermediate sum is out-of-range. clearbit
  relies on `checkTransactionSanity` having already capped the per-tx
  output total at MAX_MONEY, which is correct but couples two
  invariants instead of making the coinbase-sum check self-contained.
  (BUG-7.)
- **Mempool fee invariant has a `total_in > 0` guard** at
  `mempool.zig:1151` that short-circuits the `fee < 0` reject when
  total_in is zero (legitimately the no-chain-state test branch
  @ 1131-1134). The production branch always raises `MissingInputs`
  before reaching here, but the predicate is structurally wrong —
  Core never gates the fee check on "did the lookup succeed"; it
  gates on "is the input set non-empty" (already checked by
  `bad-txns-vin-empty`). (BUG-9.)
- **`getBlockSubsidy` argument is `u32` and not range-validated.** The
  function accepts `std.math.maxInt(u32) = 0xFFFFFFFF`; halvings then
  evaluates to `0xFFFFFFFF / 210_000 = 20460 ≥ 64` so the guard fires
  and returns 0 — correct, but the only test covering this is
  consensus.zig:1325 / validation.zig:3122. The legitimate maximum
  height a real chain can attain is `≪ 2^31`; passing a height that
  large signals UB elsewhere. Defensive only. (BUG-12.)
- **No "subsidy 0 at height 13,440,000 means coinbase reward = fees
  only" test against connectBlock or validateBlockForIBD.** The
  subsidy unit-test covers the *pure function*, but no integration
  test confirms that block 13,440,000+ rejects a coinbase that pays
  more than the accumulated fees. The pure-function test is a weak
  proxy because the `subsidy + total_fees` clamp could be applied to
  a constant rather than the call result and the test would still
  pass. (BUG-13.)
- **`replayReconnect` calls `connectBlockLocked` which dispatches
  to `connectBlockInner` — bypassing all consensus checks** (rpc.zig:8424-8449).
  The path is intentional (it replays blocks that have already been
  validated and persisted) but there is no assertion or audit-trace
  that the input is post-validation. If a refactor ever inadvertently
  exposed `connectBlockLocked` as the entry-point for a fresh block,
  it would skip every monetary invariant. (BUG-14.)
- **Mainnet `assume_valid_height` is 938,343 — beyond the second
  halving** (height 420,000). Script verification is skipped under
  assumevalid up to 938,343. *Monetary invariants are not skipped*
  (the subsidy / fee / coinbase-amount checks live outside
  `verifyBlockScriptsParallel`), so this is a non-bug — documented
  here for completeness. (Not assigned a bug number.)

## Bug catalogue (15 entries)

## BUG-1 — Legacy `connectBlock` does not enforce COINBASE_MATURITY

**Severity:** P0-CONSENSUS (consensus-rule absence in a production-reachable path).
**File:** `clearbit/src/validation.zig:879-1000` (full body) — specifically the per-input lookup loop @ 948-967.
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:164-189` (`Consensus::CheckTxInputs` @ 179-182 is the COINBASE_MATURITY gate).

**Description.** Core's CheckTxInputs enforces
`if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY)
return state.Invalid(..., "bad-txns-premature-spend-of-coinbase")`
on **every** input of a non-coinbase tx during ConnectBlock. clearbit's
legacy `connectBlock` (the path used by mining, the storage rollback
dance @ rpc.zig:8424, and ~12 in-tree tests) consumes a `SigopUtxoView`
whose `SigopUtxoEntry` struct (validation.zig:464-467) carries only
`{script_pubkey, amount}` — it deliberately drops `(height, is_coinbase)`
because the sigop-counting path doesn't need them. The per-input loop
@ 948-967 therefore has no way to even *ask* whether the prevout is a
coinbase, much less how old it is. The IBD path (`validateBlockForIBD`
@ 1374-1378) uses a richer `prevout_lookupFn` that does carry that
metadata and enforces the gate correctly.

**Excerpt** (validation.zig:945-967):
```zig
// W93 G10/G11: per-tx fee accumulation (Core Consensus::CheckTxInputs
// + nFees MoneyRange).  For non-coinbase txs, sum the prevout amounts
// resolved through `sigop_view` and subtract the output sum.  Coinbase
// is excluded (no real inputs).  When the prevout lookup fails, we
// surface ValidationError.MissingInput rather than silently skipping —
// a missing input means the caller's view doesn't cover the spend.
// Reference: bitcoin-core/src/validation.cpp:2535-2547.
if (!tx.isCoinbase()) {
    var input_sum: i64 = 0;
    for (tx.inputs) |input| {
        const entry = sigop_view.lookup(&input.previous_output) orelse
            return ValidationError.MissingInput;
        // Per-coin value range check.
        if (!consensus.isValidMoney(entry.amount))
            return ValidationError.InputValuesOutOfRange;
        input_sum += entry.amount;
        if (!consensus.isValidMoney(input_sum))
            return ValidationError.InputValuesOutOfRange;
    }
    // [no maturity check — entry has no `is_coinbase` / `height` field]
```

**Impact.** Any caller that exercises the legacy path with a block
containing a non-coinbase tx that spends a coinbase output less than
100 confirmations deep silently admits the block. Production exposure
is gated on: (a) mining doesn't typically include immature-coinbase
spends because the mempool refuses them (but see BUG-3 for a related
off-by-one); (b) `dumptxoutset` rollback replays *previously-validated*
blocks. The hole is therefore latent rather than actively exploitable,
but the consensus rule is missing and `connectBlock` is documented
(line 1675-1681) as a unified entry point: any new caller that lands
on it inherits the gap.

---

## BUG-2 — `checkTransactionContextual` is a dead module

**Severity:** P1 (dead-code fleet pattern; misleads audit + risks
silent under-enforcement if any caller ever wires it).
**File:** `clearbit/src/validation.zig:368-454` (87 LOC).
**Core ref:** N/A (clearbit-only).

**Description.** `checkTransactionContextual` is defined as the
clearbit equivalent of Core's `Consensus::CheckTxInputs` — accepts a
`ChainStore`, looks up every prevout, enforces COINBASE_MATURITY,
per-input MoneyRange, accumulated-fee non-negativity, and returns
the per-tx fee. The doc-comment at validation.zig:366-367 says
*"requires UTXO set access"* and *"Returns the total fee paid by the
transaction."* The function compiles, has correct logic, and would
be Core-faithful. **It has zero production callers.**

```
$ grep -rn 'checkTransactionContextual\b\|\.checkTransactionContextual('
    /home/work/hashhog/clearbit/src/
clearbit/src/mempool.zig:2565: // used in `validation.checkTransactionContextual`.
clearbit/src/validation.zig:9:  //! - Contextual checks (`checkTransactionContextual`) ...
clearbit/src/validation.zig:368: pub fn checkTransactionContextual(
```

The mempool comment @ 2565 is in a doc-comment for an unrelated
function; the validation.zig @ 9 line is the module-level
file-comment. The only definition site is line 368. The mempool's
per-input check loop @ 1092-1130 duplicates this logic inline. The
IBD path (`validateBlockForIBD` @ 1340-1424) duplicates it again.

**Excerpt** (validation.zig:366-376):
```zig
/// Contextual transaction validation (requires UTXO set access).
/// Returns the total fee paid by the transaction.
pub fn checkTransactionContextual(
    tx: *const types.Transaction,
    chain_store: *storage.ChainStore,
    height: u32,
    allocator: std.mem.Allocator,
) ValidationError!i64 {
    // Coinbase transactions have no inputs to validate in this manner
    if (tx.isCoinbase()) return 0;
```

**Impact.** Misleads any auditor or new contributor into believing
clearbit has a single canonical CheckTxInputs analog. The actual
behavior is **three implementations of the same logic** (this dead
function, the IBD inline copy, and the mempool inline copy). The dead
copy has the strictest gate set (per-input MoneyRange + maturity +
accumulated-fee MoneyRange), so wiring it in would be safe — but
any future divergence between this and the inline copies risks the
classic *two-pipeline* (here: three-pipeline) bug. Fleet pattern.

---

## BUG-3 — Mempool COINBASE_MATURITY off-by-one (tip vs tip+1)

**Severity:** P1 (parity break with Core mempool; false-reject only).
**File:** `clearbit/src/mempool.zig:1114-1119`.
**Core ref:** `bitcoin-core/src/validation.cpp:374-375` (`mempool_spend_height = m_chain.Tip()->nHeight + 1`).

**Description.** Bitcoin Core's mempool ATMP uses
`mempool_spend_height = m_chain.Tip()->nHeight + 1` as the
`nSpendHeight` argument to the maturity check. clearbit's mempool
uses `cs.best_height -| u.height` directly, which is equivalent to
`nSpendHeight = tip` (not tip+1). For a coinbase at height H,
Core admits when `tip = H + 99` (because spend-height = H+100,
diff = 100, not < 100). clearbit refuses until `tip = H + 100`
(diff = 100 evaluates to age = 100, but compare is `< 100`, so the
boundary is shifted by one).

**Excerpt** (mempool.zig:1112-1119):
```zig
// Coinbase maturity check: coinbase outputs require 100 confirmations.
// Reference: Bitcoin Core CheckTxInputs() in consensus/tx_verify.cpp.
if (u.is_coinbase) {
    const age: u32 = cs.best_height -| u.height;
    if (age < consensus.COINBASE_MATURITY) {
        return MempoolError.ImmatureCoinbase;
    }
}
```

Core (validation.cpp:373-377):
```cpp
const auto mempool_spend_height{m_chain.Tip()->nHeight + 1};
if (coin.IsCoinBase() && mempool_spend_height - coin.nHeight < COINBASE_MATURITY) {
    return Invalid(..., "bad-txns-premature-spend-of-coinbase");
}
```

**Impact.** A coinbase mined at H is accepted into Core's mempool at
tip = H+99 (because spend height H+100 ≥ H+100 = mature). clearbit's
mempool refuses it at tip = H+99 (age = 99 < 100) and admits only at
tip = H+100. Result: clearbit lags Core mempool admission by exactly
one block on coinbase spends. Wallets relying on clearbit for
mempool-relay-as-soon-as-mature will see a 10-minute delay relative
to a Core node. Not consensus-divergent (false-reject only at the
mempool boundary; the block-level IBD path uses block height directly
and matches Core), but breaks fleet/Core parity on `sendrawtransaction`
results in the 1-block window.

---

## BUG-4 — Duplicate-input detection is O(n²); Core is O(n log n)

**Severity:** P2 (DoS attenuation; block-weight cap masks it in
practice).
**File:** `clearbit/src/validation.zig:337-346`.
**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:41-45`
(`std::set<COutPoint>` insert-and-check).

**Description.** CVE-2018-17144 mandates a duplicate-input check
inside CheckTransaction *before* UTXO lookup. clearbit performs it
correctly but with a doubly-nested loop, giving O(n²) cost in input
count. Core uses `std::set<COutPoint>::insert` (O(n log n)).

**Excerpt** (validation.zig:337-346):
```zig
// 3. Check for duplicate inputs (same outpoint)
for (tx.inputs, 0..) |input_a, i| {
    for (tx.inputs[i + 1 ..]) |input_b| {
        if (std.mem.eql(u8, &input_a.previous_output.hash, &input_b.previous_output.hash) and
            input_a.previous_output.index == input_b.previous_output.index)
        {
            return ValidationError.DuplicateInput;
        }
    }
}
```

Core (consensus/tx_check.cpp:41-45):
```cpp
std::set<COutPoint> vInOutPoints;
for (const auto& txin : tx.vin) {
    if (!vInOutPoints.insert(txin.prevout).second)
        return state.Invalid(..., "bad-txns-inputs-duplicate");
}
```

**Impact.** `MAX_TX_IN_STANDARD = 100_000` (consensus.zig:63). At the
cap, clearbit performs ~5×10⁹ comparisons (each is a 36-byte memcmp +
u32 compare) before `bad-txns-oversize` would catch the tx weight at
the encompassing CheckTransaction call. In practice the per-tx weight
cap (lines 322-326, `txBaseSerializeSize × 4 > MAX_BLOCK_WEIGHT`) fires
first for inputs of typical size (~150 bytes/input × 100k > 4MB), so
the n² loop is only reachable on dust-like inputs. Still: a peer can
construct a tx with 26,666 minimum-size (60-byte) inputs that JUST fits
in MAX_BLOCK_WEIGHT and runs the O(n²) loop. Single-tx CPU stall is
~700ms on a 5900X. Mitigation: replace with `std.AutoHashMap`
([36]u8 ⇒ void).

---

## BUG-5 — `checkBlock` legacy coinbase value branch is dead (empty body)

**Severity:** P2 (dead branch; cross-references W143 BUG-16).
**File:** `clearbit/src/validation.zig:827-839`.
**Core ref:** `bitcoin-core/src/validation.cpp:2611-2614` (the real
`bad-cb-amount` gate; runs only when fees are known).

**Description.** `checkBlock` is the context-free entry point and
runs *before* fee accumulation. Its step 9 (lines 827-839) computes
`coinbase_value` and `subsidy`, then declares a "conservative" check
on `coinbase_value > subsidy` — but the if-body is **empty**:

```zig
// 9. Validate coinbase subsidy (without fees - fees computed during contextual validation)
const subsidy = consensus.getBlockSubsidy(height, params);
var coinbase_value: i64 = 0;
for (block.transactions[0].outputs) |output| {
    coinbase_value += output.value;
}
// Note: In full validation, we'd add total_fees here
// For now, we just check coinbase doesn't exceed subsidy (conservative check)
// Full validation with fees happens in connectBlock
if (coinbase_value > subsidy) {
    // This is a conservative check - actual validation needs total fees
    // which are only known after validating all transactions
}
```

The author appears to have realized mid-write that without fees the
gate is *not* conservative (it would over-reject every block paying a
fee), and rather than delete the dead computation, left it with an
explanatory two-line comment. This is the **comment-as-confession**
fleet pattern. W143 BUG-W143-16 catalogued this; re-cited here because
it sits in the W145 invariant set.

**Impact.** Zero runtime consequence (the empty branch does nothing).
Audit-grade noise — a quick visual scan suggests "checkBlock rejects
when coinbase > subsidy", which it doesn't.

---

## BUG-6 — `getBlockSubsidy` `halvings >= 64` guard is dead-by-construction in Zig

**Severity:** P3 (defensive; Zig doesn't have C++ undefined-behavior
on shift-by-bitsize).
**File:** `clearbit/src/consensus.zig:812-816`.
**Core ref:** `bitcoin-core/src/validation.cpp:1841-1844` (the guard
exists in Core to avoid C++ UB on `>>` by ≥ 64).

**Description.** Core's `if (halvings >= 64) return 0;` exists
because C++ specifies `>>` by ≥ sizeof(T)*8 as undefined behavior;
Core returns 0 early to avoid UB. In Zig (0.13) the `>>` operator on
`i64` requires the shift amount to be `u6` (i.e. `< 64` is enforced
by the type system; passing `>= 64` is a compile error or runtime
panic depending on context). clearbit's code:

```zig
pub fn getBlockSubsidy(height: u32, params: *const NetworkParams) i64 {
    const halvings = height / params.subsidy_halving_interval;
    if (halvings >= 64) return 0;
    return INITIAL_SUBSIDY >> @intCast(halvings);
}
```

The `@intCast(halvings)` returns `u6` (inferred from `i64`'s shift
operand requirement). Without the explicit `if (halvings >= 64) return 0;`
guard, `@intCast` would panic for halvings ≥ 64 in any safe build mode
and silently truncate in ReleaseFast (`halvings & 0x3F`). The guard
is therefore **load-bearing** in Zig — but for a different reason than
in Core: in Zig it suppresses an `@intCast` overflow rather than a
shift UB. The comment ("Force block reward to zero when right shift
is undefined.") is borrowed verbatim from Core but doesn't apply.

**Excerpt:**
```zig
/// Compute block subsidy at a given height.
pub fn getBlockSubsidy(height: u32, params: *const NetworkParams) i64 {
    const halvings = height / params.subsidy_halving_interval;
    if (halvings >= 64) return 0;
    return INITIAL_SUBSIDY >> @intCast(halvings);
}
```

**Impact.** None functional. Audit-grade only — the comment misleads
about why the guard is there. Fixing the comment ("Force block reward
to zero before @intCast would panic on >= 64") would make the rationale
match the implementation.

---

## BUG-7 — Coinbase-output sum lacks per-step MoneyRange check; Core's `GetValueOut` throws

**Severity:** P2 (defense-in-depth; per-tx sanity already clamps).
**File:** `clearbit/src/validation.zig:829-832`, 974-975, 1461-1462.
**Core ref:** `bitcoin-core/src/primitives/transaction.cpp:98-108`
(`GetValueOut` does per-output AND per-running-total MoneyRange,
throws on out-of-range).

**Description.** Core's `bad-cb-amount` reject reads
`block.vtx[0]->GetValueOut() > blockReward`. `GetValueOut` itself
performs *two* MoneyRange checks per output: one on the output's own
nValue and one on the *running* sum before each add. clearbit's three
copies of the coinbase-output loop:

```zig
var coinbase_value: i64 = 0;
for (block.transactions[0].outputs) |out| coinbase_value += out.value;
```

call `isValidMoney` on neither the output value nor the running sum.
The invariant survives only because `checkTransactionSanity` (called
earlier on every tx including the coinbase) caps `total_out ≤ MAX_MONEY`
and rejects negative values. If a future refactor lets ANY consensus
path call `getBlockSubsidy`-related code without going through
`checkTransactionSanity` first, the loop is exposed to:
- a coinbase with `vout[i].nValue > MAX_MONEY` (e.g. = 2^62)
  silently summing without rejection
- a sum that exceeds MAX_MONEY but fits in i64

The condition `coinbase_value > subsidy + total_fees` would still
catch a value > subsidy+fees, but the comparison is done at i64
precision against `i64(subsidy + total_fees)` — meanwhile, in
ReleaseFast mode, the `coinbase_value +=` itself silently overflows
to negative on 1.5e+ × 2^61, making `coinbase_value > subsidy+fees`
false → block accepted.

**Excerpt** (Core, primitives/transaction.cpp:98-108):
```cpp
CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}
```

**Impact.** Latent (not triggerable today). Defense-in-depth: a
self-contained coinbase-sum helper that mirrors GetValueOut would
remove the cross-function invariant dependency.

---

## BUG-8 — `connectBlock` per-tx fee accumulator allows fee > MAX_MONEY before the cumulative check

**Severity:** P2 (cosmetic / error-attribution).
**File:** `clearbit/src/validation.zig:948-967`.
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:201-209`
(`bad-txns-fee-outofrange` is "unreachable" per Core's invariants).

**Description.** Both `connectBlock` and `validateBlockForIBD` add
the per-tx fee `(input_sum - output_sum)` to `total_fees` and then
call `isValidMoney(total_fees)`. They do NOT check whether the *per-tx
fee* itself is within MoneyRange. Core does the same (its
`bad-txns-fee-outofrange` is documented as unreachable), so this is
**parity** — but the parity reasoning chain is fragile:

clearbit's argument:
1. `output.value ≥ 0` (checked at sanity).
2. `output.value ≤ MAX_MONEY` (checked at sanity).
3. Running `total_out ≤ MAX_MONEY` (checked at sanity).
4. So `output_sum ≤ MAX_MONEY`.
5. `input_sum < output_sum` is rejected.
6. So `input_sum - output_sum ≥ 0`.
7. `input_sum ≤ MAX_MONEY` (checked in input loop).
8. So `0 ≤ fee ≤ input_sum ≤ MAX_MONEY`. ✓

The chain *depends* on the per-tx sanity having already run. The
sanity is invoked by `checkBlock` for the IBD path; for the legacy
`connectBlock` path, the caller is expected to have invoked
`checkBlock` first. If anything skips `checkBlock` and calls
`connectBlock` directly, the fee-MoneyRange chain breaks. The
`bad-txns-fee-outofrange` reject is **never emitted** by clearbit
even in cases where Core would emit it as a defensive check.

**Excerpt** (validation.zig:960-966):
```zig
var output_sum: i64 = 0;
for (tx.outputs) |out| output_sum += out.value;
if (input_sum < output_sum) return ValidationError.InsufficientFunds;
total_fees += input_sum - output_sum;
// Accumulated fee MoneyRange (Core "bad-txns-accumulated-fee-outofrange").
if (!consensus.isValidMoney(total_fees))
    return ValidationError.AccumulatedFeeOutOfRange;
```

**Impact.** Error attribution drift: a tx whose per-tx fee exceeds
MAX_MONEY (only reachable via UB elsewhere) returns
`AccumulatedFeeOutOfRange` instead of a per-tx-scoped reject. Logged
as audit-grade.

---

## BUG-9 — Mempool fee check gated on `total_in > 0` short-circuits the negative-fee reject

**Severity:** P2 (test-only branch; production path always raises
`MissingInputs` before reaching here).
**File:** `clearbit/src/mempool.zig:1149-1154`.
**Core ref:** Core's mempool calls `Consensus::CheckTxInputs` which
unconditionally checks `nValueIn < value_out`.

**Description.** clearbit's mempool fee check:

```zig
// 5. Compute fee (allow tests without chain state)
var fee: i64 = 0;
if (total_in > 0) {
    fee = total_in - total_out;
    if (fee < 0) return MempoolError.InsufficientFee;
}
```

The `if (total_in > 0)` predicate exists to support the test-only
branch (mempool.zig:1131-1135) that admits a tx without a chain state
by appending `validation.UtxoInfo{ .height = 0, .mtp = 0 }` to
`seq_utxo_infos` **without updating `total_in`**. When all inputs go
through that branch, `total_in == 0`, the `if (total_in > 0)` gate
short-circuits, and `fee < 0` is never checked even if the tx's
outputs sum to > 0.

In production, the no-chain-state branch is unreachable (the path
@ 1092-1130 always either updates `total_in` from the UTXO set or
returns `MissingInputs`). But the predicate is structurally wrong
relative to Core, which never gates the fee check on "did the lookup
succeed".

**Excerpt** (mempool.zig:1131-1135, the test branch):
```zig
} else {
    // No chain state - for testing, assume inputs exist
    // In production this would return MissingInputs
    seq_utxo_infos.append(validation.UtxoInfo{ .height = 0, .mtp = 0 }) catch {};
}
```

**Impact.** Test path admits tx with negative fee silently. No
production exposure unless `self.chain_state` becomes null at runtime
(it shouldn't; constructor wires it). Audit-grade.

---

## BUG-10 — Wallet `coinSelection` coinbase-maturity uses tip height (off-by-one) — same shape as BUG-3

**Severity:** P2 (UX/parity; false-reject only).
**File:** `clearbit/src/wallet.zig:503-507`, 1327-1331, 2326.
**Core ref:** Core wallet uses `chainTip.nHeight + 1 - utxo.nHeight ≥ COINBASE_MATURITY`.

**Description.** Wallet coin-selection paths skip coinbase outputs
that are within COINBASE_MATURITY of the wallet's stored tip height:

```zig
// Skip immature coinbase (BIP-30/consensus rule).
if (utxo.is_coinbase) {
    if (self.tip_height < utxo.height) continue;
    if (self.tip_height - utxo.height < consensus.COINBASE_MATURITY) continue;
}
```

Like the mempool bug (BUG-3), this uses tip_height as the "spend
height" rather than `tip+1`. The next block that includes this tx
will have height = `tip+1`, so the correct maturity test is
`tip+1 - utxo.height ≥ COINBASE_MATURITY` ⇔
`tip - utxo.height ≥ COINBASE_MATURITY - 1` ⇔ skip when
`tip - utxo.height < COINBASE_MATURITY - 1` = `< 99`.

clearbit's wallet skips at `< 100`. Result: wallet refuses to spend
a coinbase at depth 100 (i.e. tip = H + 100). Core's wallet admits
it because depth 100 = mature.

**Excerpt** (wallet.zig:503-507):
```zig
// Skip immature coinbase (BIP-30/consensus rule).
if (utxo.is_coinbase) {
    if (self.tip_height < utxo.height) continue;
    if (self.tip_height - utxo.height < consensus.COINBASE_MATURITY) continue;
}
```

(also wallet.zig:1327-1331 and 2326 — same shape).

**Impact.** Wallet hangs onto an immature-looking coinbase for one
extra block. UX delay; no consensus break. Triple-site bug:
all three copies have identical off-by-one.

---

## BUG-11 — `connectBlockInner` (storage path) performs ZERO consensus checks; relies entirely on caller having pre-validated

**Severity:** P2 (architectural; current callers do validate, but
no audit-trace guards against regression).
**File:** `clearbit/src/storage.zig:4037-4268` (entire body).
**Core ref:** N/A (Core fuses validation + apply in a single
ConnectBlock function).

**Description.** Bitcoin Core's `Chainstate::ConnectBlock` interleaves
all consensus checks (CheckBlock-equivalent contextual gates, per-tx
fee accumulation, bad-cb-amount, sigop budget) WITH the UTXO mutation
loop, inside one function. clearbit splits them: `validateBlockForIBD`
(validation.zig) does all consensus work, `connectBlockInner`
(storage.zig) does all UTXO mutation. The split is sound when callers
pair them; the storage path is *intentionally* a no-consensus mutator.

But: `connectBlockInner` is reachable through:
- `connectBlock` (validation-free wrapper — used by ChainState tests)
- `connectBlockLocked` (validation-free wrapper — used by
  rpc.zig::replayReconnect for already-validated block replay)
- `connectBlockFast` (validation-free wrapper — used by
  peer.zig::handleBlockMessage AFTER `validateBlockForIBDOrReject`)
- `connectBlockFastWithUndo` (same)

There is no assertion or sanity-check inside `connectBlockInner` that
the input has been validated. If any future caller calls
`connectBlockInner` (or its public-API wrappers) without first invoking
`validateBlockForIBDOrReject`, every consensus invariant is silently
skipped — including coinbase-amount, fee invariant, MoneyRange.

**Impact.** Latent regression risk. The W93 audit closed the same
class of bug in the legacy `connectBlock` path (which used to lack
`bad-cb-amount`). The storage path is the next vector. Recommend
either:
(a) inline a paranoid coinbase-amount check inside `connectBlockInner`,
(b) add a `validated_at: u64` field to ChainState that records the
    last validate-call timestamp and assert it's recent.

---

## BUG-12 — `getBlockSubsidy` accepts `height = std.math.maxInt(u32)` silently

**Severity:** P3 (defensive; legitimate heights are ≪ 2^31).
**File:** `clearbit/src/consensus.zig:812-816`.
**Core ref:** `bitcoin-core/src/validation.cpp:1839-1850` (Core uses
`int` for nHeight; passing INT_MAX returns 0 via the ≥64-halvings
guard).

**Description.** The function signature `getBlockSubsidy(height: u32,
params: *const NetworkParams) i64` accepts the full u32 range. For
`height = 0xFFFFFFFF`, halvings = `0xFFFFFFFF / 210_000 = 20460`, the
≥64 guard fires, function returns 0. **The behavior is correct**, but
there's no Mockable contract that rejects ridiculous heights — every
caller has to trust the guard. validation.zig:3122-3124 covers this
case with a test.

In Core, nHeight is `int` (signed 32-bit). Passing INT_MIN would
result in `halvings = INT_MIN / 210000` (negative, signed) — Core's
`int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;`
followed by `if (halvings >= 64)` doesn't fire for negative halvings,
and `>> halvings` with negative halvings is undefined. Core silently
relies on nHeight ≥ 0.

clearbit's `u32 height` is safer in this regard (never negative).
Defensive only. Audit-grade.

**Impact.** None. Audit-trace.

---

## BUG-13 — No integration test covering subsidy = 0 at height 13,440,000 (post-64th-halving)

**Severity:** P3 (test-coverage gap; behavior is correct).
**File:** test gap; `clearbit/src/validation.zig:3117-3124` are the
pure-function-only tests.
**Core ref:** `bitcoin-core/src/test/validation_block_tests.cpp`
covers ConnectBlock at all subsidy regimes.

**Description.** clearbit has unit-tests for the pure
`getBlockSubsidy` function at:
- `consensus.zig:1309` (genesis = 50 BTC)
- `consensus.zig:1314` (first halving = 25 BTC)
- `consensus.zig:1319` (second halving = 12.5 BTC)
- `consensus.zig:1325` (after 64 halvings = 0)
- `validation.zig:3117-3124` (same)

But: **no test exercises `validateBlockForIBD` or `connectBlock`
with a block at height ≥ 13,440,000 with a coinbase paying only the
accumulated fees.** The pure-function test could be satisfied by a
hard-coded lookup table that happens to return the right values
without going through `INITIAL_SUBSIDY >> halvings`. The integration
chain `getBlockSubsidy → coinbase_value > subsidy + total_fees` is
not test-covered for the post-fee-only regime.

**Impact.** Future refactor of `subsidy + total_fees` arithmetic
could break the "subsidy=0 + nonzero fees" case without a unit-test
catching it. Recommend adding a `connectBlock` test at height
`64 * 210_000 = 13_440_000` with a coinbase paying only the per-tx
fees.

---

## BUG-14 — `replayReconnect` calls `connectBlockLocked` which bypasses validation; no documented invariant that the input must be pre-validated

**Severity:** P3 (architectural; current callers are safe).
**File:** `clearbit/src/rpc.zig:8424-8450`, `clearbit/src/storage.zig:3051-3058`.
**Core ref:** N/A (Core doesn't split).

**Description.** The dumptxoutset rollback dance disconnects N
blocks, writes the snapshot, then walks the disconnected chain in
reverse calling `connectBlockLocked` for each. `connectBlockLocked`
goes straight to `connectBlockInner` (the no-consensus UTXO mutator —
see BUG-11). The replay is *correct* because every block being
replayed was previously connected by `connectBlockFast` after
`validateBlockForIBD` passed.

But the doc-comment at `replayReconnect` (rpc.zig:8424-8449) does
not document this invariant. A future maintainer who tries to call
`replayReconnect` with a freshly-deserialized block from disk
(say, a recovery path that rebuilds from `CF_BLOCK_BODY`) would
bypass validation entirely.

**Excerpt** (rpc.zig:8442):
```zig
var undo = try self.chain_state.connectBlockLocked(&block, &entry.hash, entry.height);
```

**Impact.** Latent. Recommend annotating `connectBlockLocked` with
`// SAFETY: caller must have already validated this block via
validateBlockForIBD/acceptBlock.` and adding a debug-mode assertion
that the block's hash is present in the validated-blocks set.

---

## BUG-15 — `block_template.zig::getBlockReward` returns `subsidy + total_fees` without MoneyRange clamp

**Severity:** P3 (mining-only path; downstream consumers must trust).
**File:** `clearbit/src/block_template.zig:125-129`.
**Core ref:** `bitcoin-core/src/miner.cpp::CreateNewBlock`
(populates `pblock->vtx[0]->vout[0].nValue` from
`nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus())`).

**Description.** Mining helper `getBlockReward`:

```zig
/// Get the total block reward (subsidy + fees).
pub fn getBlockReward(self: *const BlockTemplate, params: *const consensus.NetworkParams) i64 {
    const subsidy = consensus.getBlockSubsidy(self.height, params);
    return subsidy + self.total_fees;
}
```

`self.total_fees` is accumulated as transactions are added to the
template. There is no MoneyRange check that the sum `subsidy + total_fees`
remains ≤ MAX_MONEY before it's used as `coinbase_tx.vout[0].value`.
For mainnet at h=100, subsidy=5e9 and total_fees bounded by mempool
(in practice ≪ 1e8), so the sum is safely far below MAX_MONEY=2.1e15.
But the function exposes a value that downstream callers
(`createCoinbaseTx` @ 499-501, `submitBlockWithIndex`) use as a
coinbase nValue without revalidation.

If the consensus path's `validateBlockForIBD` ever changed to allow
total_fees up to `MAX_MONEY - subsidy + ε`, the coinbase output
written here would silently exceed MAX_MONEY and the resulting block
would fail downstream `bad-cb-amount` (since subsidy + total_fees =
the limit). The mining path doesn't pre-validate against the cap.

**Impact.** Mining-only; mempool's MoneyRange clamp on accumulated
fees (mempool.zig:1108) keeps total_fees ≤ MAX_MONEY, so practical
exposure is zero. Audit-grade only.

---

## Fleet-pattern smell

1. **Three-pipeline guard** (extends two-pipeline pattern). The
   `CheckTxInputs`-equivalent monetary invariant logic is duplicated
   in THREE places: `checkTransactionContextual` (dead), the inline
   per-input loop in `validateBlockForIBD` (lines 1340-1424), and the
   inline per-input loop in `mempool.zig:1085-1130`. BUG-2 (dead
   module) + BUG-3 (mempool off-by-one) + BUG-10 (wallet off-by-one)
   together demonstrate the maintenance cost: each copy diverges
   independently. The legacy `connectBlock` (BUG-1) is a *fourth*
   incomplete copy that lacks maturity entirely. Recommend wiring
   `checkTransactionContextual` in, deleting the inline copies.

2. **Comment-as-confession** repeats. BUG-5 (empty branch with
   "this is a conservative check" comment) is the classic shape.
   BUG-6 (Core's UB-comment copied without applying to Zig)
   is a variant — the comment is a borrowed rationale that no
   longer matches the code.

3. **Tip-height off-by-one** is a 3-site repeat (mempool BUG-3,
   wallet BUG-10 has THREE call sites). Same root cause: the
   author confused "current tip height" with "next block's
   height (= spending height)" three times in two files. A
   single helper `fn nextSpendHeight(self) u32 { return self.best_height + 1; }`
   on ChainState would prevent the repetition.

4. **Storage-as-mutator-only** (BUG-11 + BUG-14): clearbit's
   architectural split keeps consensus checks in validation.zig and
   UTXO mutation in storage.zig. The split is sound but
   under-documented; no assertion guards against an "apply without
   validate" regression. Fleet pattern when an impl has two
   architectural layers and the boundary isn't enforced.

## Out-of-scope (audit-trace only, NOT bugs)

- **Subsidy halving interval values**: mainnet/testnet3/testnet4/signet
  all at 210_000, regtest at 150. Verified against
  `bitcoin-core/src/kernel/chainparams.cpp:84, 209, 310, 454, 535`. Match.
- **MAX_MONEY value**: `21_000_000 * 100_000_000 = 2_100_000_000_000_000`.
  Verified against `bitcoin-core/src/consensus/amount.h:26`. Match.
- **COIN value**: clearbit hard-codes `100_000_000` inline (no named
  constant). Acceptable; Core's `COIN` is also a constexpr in the same
  header. Minor: `INITIAL_SUBSIDY = 50 * 100_000_000` would be clearer
  as `50 * COIN` with a named `COIN` constant.
- **Negative-output reject**: `checkTransactionSanity:331` checks
  `output.value < 0` before MAX_MONEY check. Matches Core's
  `bad-txns-vout-negative` ordering.
- **Coinbase scriptSig bounds** (2 ≤ len ≤ 100): `checkTransactionSanity:351`.
  Match Core `bad-cb-length` @ `tx_check.cpp:49-50`.
- **Null-input reject for non-coinbase**: `checkTransactionSanity:355-362`.
  Match Core `bad-txns-prevout-null` @ `tx_check.cpp:55-56`.
- **vin/vout empty**: `checkTransactionSanity:318-319`. Match Core
  `tx_check.cpp:14-17` (`bad-txns-vin-empty` / `bad-txns-vout-empty`).
- **MoneyRange = `value >= 0 and value <= MAX_MONEY`**:
  `consensus.zig:819-821`. Match Core `amount.h:27`.
- **Assume-valid heights are post-halving** (mainnet
  assume_valid_height = 938343 ≫ 210000 and 420000). Monetary
  invariants are NOT skipped under assumevalid (only script
  verification is), so this is a non-bug.
