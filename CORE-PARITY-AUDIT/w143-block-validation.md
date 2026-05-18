# W143 — Block-level validation audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's block-level validation pipeline (`checkBlock`,
`checkBlockHeader`, `connectBlock`, `validateBlockForIBD`, and the merkle-root
helper in `crypto.zig::computeMerkleRoot`) vs Bitcoin Core's
`CheckBlock` + `ContextualCheckBlock` + `ContextualCheckBlockHeader` +
`CheckMerkleRoot` + `CheckWitnessMalleation` + `CheckProofOfWorkImpl` +
`ConnectBlock`.
**Bitcoin Core references:**
- `bitcoin-core/src/validation.cpp::CheckBlockHeader` @ 3828-3835
- `bitcoin-core/src/validation.cpp::CheckMerkleRoot` @ 3837-3862
- `bitcoin-core/src/validation.cpp::CheckWitnessMalleation` @ 3864-3916
- `bitcoin-core/src/validation.cpp::CheckBlock` @ 3918-3983
- `bitcoin-core/src/validation.cpp::ContextualCheckBlockHeader` @ 4080-4121
- `bitcoin-core/src/validation.cpp::ContextualCheckBlock` @ 4129-4184
- `bitcoin-core/src/validation.cpp::ConnectBlock` @ 2400-2700 (BIP-30, sigop
  budget, fee accumulation, bad-cb-amount, IsFinalTx)
- `bitcoin-core/src/consensus/merkle.cpp::ComputeMerkleRoot` @ 46-63
  (CVE-2012-2459 mutation flag), `BlockMerkleRoot` @ 66-74
- `bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction` @ 11-60
  (CVE-2010-5139 overflow, CVE-2018-17144 duplicate inputs, bad-cb-length)
- `bitcoin-core/src/pow.cpp::CheckProofOfWorkImpl` @ 140-160 and
  `DeriveTarget` @ 146-159 (`fNegative || bnTarget == 0 || fOverflow ||
  bnTarget > pow_limit` rejection)

**BIPs:** BIP-34 (height-in-coinbase), BIP-30 (duplicate-txid), BIP-141
(witness commitment, weight), CVE-2012-2459 (merkle mutation),
CVE-2018-17144 (duplicate inputs), CVE-2010-5139 (output overflow).

**Mode:** DISCOVERY (no production code changes; this audit catalogues
bugs only).

**Implementation files audited:**
- `clearbit/src/validation.zig`
  - `checkBlockHeader` @ 576-596 (44 LOC)
  - `checkTransactionSanity` @ 316-364 (Core `CheckTransaction` analog)
  - `checkBlock` @ 763-858 (96 LOC, context-free)
  - `connectBlock` @ 879-1000 (122 LOC, legacy path)
  - `validateBlockForIBD` @ 1123-1618 (496 LOC, "real" IBD path)
  - `acceptBlock` + `AcceptBlockOptions` @ 1655-1717 (unified entry)
  - `validateCoinbaseHeight` / `encodeBip34Height` @ 1801-1844 (BIP-34)
  - `checkWitnessMalleation` @ 1888-1942 (BIP-141)
  - `getLegacySigOpCount` / `getP2SHSigOpCount` /
    `getTransactionSigOpCost` @ 480-569
- `clearbit/src/crypto.zig::computeMerkleRoot` @ 621-655
- `clearbit/src/consensus.zig::bitsToTarget` @ 832-869 (PoW range gates)
- `clearbit/src/storage.zig::connectBlockFast` @ 3061-3220 +
  `connectBlockInner` @ 4037-4195 (mutation-only fast path)
- `clearbit/src/types.zig::Transaction.isCoinbase` @ 43-47

## Summary

clearbit's block-validation pipeline is bifurcated: the **legacy**
`checkBlock` + `connectBlock` pair (still exercised by the mining path,
the storage rollback dance, and ~30 in-tree tests) is materially weaker
than the **IBD-fast-path** `validateBlockForIBD` (which is the
production path peer.zig drives). Every check enumerated in the wave
brief exists somewhere in the codebase, but the *legacy* path is
missing BIP-30, BIP-113 MTP, BIP-94 timewarp, BIP-141
witness-commitment-then-weight ordering, future-time, bad-version, and
fee-balance — leaving consensus rules entirely dependent on which entry
point the caller picked. The largest single P0-CDIV is
**CVE-2012-2459 is not detected anywhere** —
`crypto.zig::computeMerkleRoot` has no `mutated` flag at all, so a
duplicate-pair internal node never triggers the
`bad-txns-duplicate` reject. Combined with `connectBlock`'s lack of
BIP-30 enforcement, the legacy code path admits both classic Bitcoin
attack-vectors that consensus is supposed to close.

Other consequential findings:
- `bitsToTarget` returns the all-zero target for negative-flagged,
  mantissa-zero, or overflowed `nBits` rather than Core's
  `bad-diffbits` reject; downstream this manifests as `BadProofOfWork`
  (`high-hash`) — a different reject reason than Core would emit on the
  wire (audit-grade error-attribution drift).
- `checkBlockHeader` does not enforce the
  `MAX_FUTURE_BLOCK_TIME` gate; only `validateBlockForIBD` does, gated
  on `ctx.current_time != 0`. Any caller that does not set
  `current_time` (mining, RPC `submitblock`, regtest, legacy tests)
  accepts blocks with arbitrary future timestamps as far as the legacy
  pipeline is concerned. This is the **comment-as-confession** pattern
  (`validation.zig:594-595`).
- `checkBlock` orders the witness-commitment check BEFORE the weight
  check; Core deliberately orders weight AFTER witness commitment to
  prevent a malleable witness (which doesn't change the block hash)
  from masking a real over-weight block. clearbit's
  `validateBlockForIBD` inherits the same ordering by calling
  `checkBlock`. (Pattern: ordering-vs-Core divergence.)
- `getP2SHSigOpCount` and the witness-sigop loop silently `continue`
  on a UTXO miss; Core asserts the coin is present (a missing prevout
  is an upstream invariant violation). Defensive — but it means a
  malformed block with missing-prevout P2SH inputs would underestimate
  the sigop budget by `getTransactionSigOpCost`'s standards if any
  upstream gate were ever bypassed.
- The legacy `connectBlock` path (still alive at line 879) duplicates
  ~50% of the consensus surface that `validateBlockForIBD` covers, but
  with neither BIP-30, BIP-141 witness commitment, BIP-113 MTP, BIP-94
  timewarp, nor future-time / bad-version gates — exactly the
  *two-pipeline guard* fleet pattern (W76 etc.) plus the
  *one-path-misses-N-checks* dead-helper pattern.

This wave catalogues 22 BUGs across the eight wave-brief behaviors.
None are fixed; the goal here is parity-bug discovery for the campaign
tally.

---

## BUG-W143-1 — CVE-2012-2459 mutated-merkle detection is entirely missing

**Severity:** P0-CDIV

**File:** `clearbit/src/crypto.zig:621-655`
**Core ref:** `bitcoin-core/src/consensus/merkle.cpp:46-63`,
`bitcoin-core/src/validation.cpp:3853-3858`

**Description.** Core's `ComputeMerkleRoot` exposes a `bool* mutated`
out-parameter and scans every internal-node pair for `hashes[pos] ==
hashes[pos+1]`, setting `mutation = true` if any duplicate-pair would
otherwise be silently merged. `CheckMerkleRoot` then rejects with
`bad-txns-duplicate` (`BLOCK_MUTATED`). clearbit's `computeMerkleRoot`
has neither the parameter nor the comparison; it duplicates the last
element when the level is odd (`right_idx = if (left_idx + 1 < len)
left_idx + 1 else left_idx`) and proceeds without any audit of the
pair-equality case. The grep `mutated` / `bMutated` / `fMutated` in
`crypto.zig` and `validation.zig` returns ZERO consensus-path hits.

**Excerpt** (`crypto.zig:621-655`):
```zig
pub fn computeMerkleRoot(hashes: []const Hash256, allocator: std.mem.Allocator) !Hash256 {
    if (hashes.len == 0) return [_]u8{0} ** 32;
    if (hashes.len == 1) return hashes[0];
    var current = try allocator.alloc(Hash256, hashes.len);
    defer allocator.free(current);
    @memcpy(current, hashes);
    var len = hashes.len;
    while (len > 1) {
        const pair_count = (len + 1) / 2;
        for (0..pair_count) |i| {
            const left_idx = i * 2;
            const right_idx = if (left_idx + 1 < len) left_idx + 1 else left_idx;
            // No equality check on (current[left_idx], current[right_idx]) ↑
            var concat: [64]u8 = undefined;
            @memcpy(concat[0..32], &current[left_idx]);
            @memcpy(concat[32..64], &current[right_idx]);
            sha256d64(&current[i], &concat);
        }
        len = pair_count;
    }
    return current[0];
}
```

**Impact.** Two transaction lists `[T1, T2, T3, T4, T5, T6]` and
`[T1, T2, T3, T4, T5, T6, T5, T6]` produce the same merkle root and the
same block hash (the CVE-2012-2459 attack pattern documented in Core's
`merkle.cpp:9-43` ASCII tree). A malicious peer can craft and submit
the duplicated form alongside a valid block; both yield identical
`block_hash` but the duplicated form spends/creates phantom inputs and
outputs. Core marks the block PERMANENTLY invalid via
`BLOCK_MUTATED`; clearbit accepts whichever form arrives first and
later attempts to mark the canonical form invalid because it now
"already exists" in the block index — exactly the failure mode the CVE
fix prevents.

---

## BUG-W143-2 — `checkBlock` does not consume the mutation flag

**Severity:** P0-CDIV
**File:** `clearbit/src/validation.zig:789-805`
**Core ref:** `bitcoin-core/src/validation.cpp:3837-3862`,
`bitcoin-core/src/validation.cpp:3936-3938`

**Description.** Even if `computeMerkleRoot` were patched to expose a
`mutated` flag, `checkBlock` never asks for it. The current code
compares only `computed_root` against `block.header.merkle_root` and
returns `BadMerkleRoot` on mismatch; the `bad-txns-duplicate` reject
reason that Core emits for CVE-2012-2459 cases has no path in clearbit.

**Excerpt** (`validation.zig:789-805`):
```zig
var tx_hashes = allocator.alloc(types.Hash256, block.transactions.len) catch {
    return ValidationError.OutOfMemory;
};
defer allocator.free(tx_hashes);
for (block.transactions, 0..) |*tx, i| {
    tx_hashes[i] = crypto.computeTxid(tx, allocator) catch { ... };
}
const computed_root = crypto.computeMerkleRoot(tx_hashes, allocator) catch { ... };
if (!std.mem.eql(u8, &computed_root, &block.header.merkle_root)) {
    return ValidationError.BadMerkleRoot;
}
// ← Core would call BlockMerkleRoot(&mutated) here and then
//   if (mutated) return state.Invalid(..., "bad-txns-duplicate"); ←  MISSING
```

**Impact.** Two-fold blocker: even after BUG-W143-1, this site needs a
companion patch. Without the consumption, BUG-W143-1's fix is dead
code.

---

## BUG-W143-3 — Legacy `connectBlock` skips BIP-30 entirely

**Severity:** P0-CDIV
**File:** `clearbit/src/validation.zig:879-1000`
**Core ref:** `bitcoin-core/src/validation.cpp:2402-2476` (ConnectBlock
BIP-30 enforcement block)

**Description.** `validateBlockForIBD` (line 1230-1304) correctly
enforces BIP-30 with the BIP-34-implies-BIP-30 bypass, the
`bip30_exempt` height/hash tuple list, and the
`BIP34_IMPLIES_BIP30_LIMIT = 1_983_702` re-enablement ceiling.
**`connectBlock` (the legacy / mining / test path) does none of this.**
Grep confirms: `bip30` / `BIP30` / `Bip30` references in
`validation.zig:8XX-10XX` only appear in the new IBD path (1230-1304)
and in tests (8870+). The function body for `connectBlock` itself
contains zero references.

**Excerpt** (`validation.zig:879-1000`, abbreviated):
```zig
pub fn connectBlock(
    block: *const types.Block,
    height: u32,
    params: *const consensus.NetworkParams,
    sigop_view: *const SigopUtxoView,
    sequence_view: ?*const UtxoView,
    tip: ?*const BlockIndex,
    allocator: std.mem.Allocator,
) ValidationError!i64 {
    const flags = getBlockScriptFlags(height, params);
    // ContextualCheckBlock: enforce IsFinalTx for every transaction
    const csv_active = height >= params.csv_height;
    const lock_time_cutoff: u32 = ...;
    for (block.transactions) |*tx| { if (!isFinalTx(...)) return ...; }
    // Track total sigop cost and fees.
    var total_sigops_cost: u64 = 0;
    var total_fees: i64 = 0;
    for (block.transactions) |*tx| { ... } // no BIP-30 anywhere
    // … coinbase value, parallel script verification …
    return total_fees;
}
```

**Impact.** Any block submitted via the mining path (RPC
`submitblock`) or routed through `connectBlock` in tests bypasses BIP-30.
On mainnet this is currently masked by the BIP-34-implies-BIP-30 bypass
(blocks ≥ 227,931 are exempt by design until `BIP34_IMPLIES_BIP30_LIMIT
= 1_983_702`), but: (a) clearbit will need BIP-30 again at h ≥ 1,983,702
and (b) the legacy path is also exercised on testnet3 / regtest where
BIP-30 enforcement matters. Fleet-pattern: two-pipeline guard.

---

## BUG-W143-4 — Legacy `connectBlock` skips BIP-113 MTP, BIP-94 timewarp, future-time, bad-version

**Severity:** P0-CDIV
**File:** `clearbit/src/validation.zig:879-1000`
**Core ref:** `bitcoin-core/src/validation.cpp:4080-4121`
(`ContextualCheckBlockHeader`)

**Description.** `validateBlockForIBD` enforces BIP-113 MTP
(`prev_mtp` gate), BIP-94 timewarp, future-time
(`MAX_FUTURE_BLOCK_TIME`), and the bad-version 2/3/4 ladder
(`bip34_height`/`bip66_height`/`bip65_height`) at steps 1a-1d
(lines 1153-1224). `connectBlock` enforces NONE of these — it goes
straight from header PoW (via `checkBlock` → `checkBlockHeader`) to
`IsFinalTx`. A legacy-path caller can mine and submit a block with
nVersion=1 long after BIP-34 activation, a timestamp 24 hours in the
future, or a difficulty-adjustment boundary that violates MAX_TIMEWARP,
and `connectBlock` will admit it.

**Excerpt** (`validation.zig:879-905`):
```zig
pub fn connectBlock(...) ValidationError!i64 {
    const flags = getBlockScriptFlags(height, params);
    // ContextualCheckBlock: enforce IsFinalTx for every transaction
    const csv_active = height >= params.csv_height;
    const lock_time_cutoff: u32 = ...;
    for (block.transactions) |*tx| {
        if (!isFinalTx(tx, height, lock_time_cutoff)) return ValidationError.NonFinalTx;
    }
    // ← MISSING: MTP gate, timewarp gate, future-time, bad-version
```

**Impact.** All four consensus gates skipped on the legacy path.
Fleet-pattern: two-pipeline guard (the IBD pipeline carries N more
checks than the legacy pipeline). Same shape as the W76+ guards
audited fleet-wide.

---

## BUG-W143-5 — `checkBlockHeader` lacks the future-time gate; comment-as-confession

**Severity:** P1
**File:** `clearbit/src/validation.zig:576-596`
**Core ref:** `bitcoin-core/src/validation.cpp:4108-4110`

**Description.** Core's future-time gate is in
`ContextualCheckBlockHeader` (which `AcceptBlockHeader` always invokes).
clearbit's `checkBlockHeader` only does PoW; the
`MAX_FUTURE_BLOCK_TIME` gate is moved into `validateBlockForIBD` step
1c and runs only when `ctx.current_time != 0`. Crucially, the source
contains an explicit comment-as-confession:

**Excerpt** (`validation.zig:594-595`):
```zig
// Note: Timestamp validation (not too far in the future) requires current time
// which should be passed as a parameter in production use.
```

**Impact.** Production-grade pattern: the *fixed* version of the
function exists elsewhere, but the historical signature persists. Any
caller of `checkBlockHeader` (RPC `getblockheader`, header pre-validation
in P2P fast paths, the mining template path) is missing the future-time
gate. Comment-as-confession (5th instance fleet-wide).

---

## BUG-W143-6 — `bitsToTarget` does not reject negative / zero / overflow targets the way Core does

**Severity:** P1
**File:** `clearbit/src/consensus.zig:832-869`
**Core ref:** `bitcoin-core/src/pow.cpp:146-159` (`DeriveTarget`),
`bitcoin-core/src/pow.cpp:155` reject path

**Description.** Core's `DeriveTarget` explicitly rejects
`fNegative || bnTarget == 0 || fOverflow || bnTarget > pow_limit` and
the caller maps that to `bad-diffbits`. clearbit's `bitsToTarget`
returns the all-zero `[32]u8` in three pathological cases — negative
flag set with non-zero mantissa, exponent==0, and exponent>34 (silent
truncation because writes are bounded by `offset+2 < 32`). The
all-zero target then "passes" the `target <= pow_limit` test because
`0 <= pow_limit`, and the block is rejected one step later as
`BadProofOfWork` (`high-hash`) only because no real block hash is ≤
zero. **Functional outcome is reject either way**, but the rejection
reason differs (Core emits `bad-diffbits`; clearbit emits `high-hash`).

**Excerpt** (`consensus.zig:832-868`):
```zig
pub fn bitsToTarget(bits: u32) [32]u8 {
    var target: [32]u8 = [_]u8{0} ** 32;
    const exponent: u8 = @intCast((bits >> 24) & 0xFF);
    const mantissa: u32 = bits & 0x007FFFFF;
    // Negative flag check (Bitcoin specific)
    if (mantissa != 0 and (bits & 0x00800000) != 0) {
        // Negative targets are invalid, return zero
        return target;            // ← Core rejects with "bad-diffbits"; we silently zero
    }
    if (exponent == 0) {
        return target;            // ← Core rejects; we zero
    } ...
    // For exponent > 34 (offset >= 32), all writes are guarded by
    // `offset+2 < 32` → silently no-op → all-zero target → also
    // a "Core would have rejected" case.
}
```

**Impact.** Error-attribution divergence: peers expect a particular
reject reason and may misbehavior-score differently. Not a
consensus-divergence in admit/reject outcomes, but the wire-level
status messages and the BIP-152 / compact-block error path will not
match Core. Pairs with W125 (RPC error parity).

---

## BUG-W143-7 — `checkBlock` lacks the `vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` early DoS gate

**Severity:** P2
**File:** `clearbit/src/validation.zig:763-817`
**Core ref:** `bitcoin-core/src/validation.cpp:3947`

**Description.** Core's first size check is
`block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR >
MAX_BLOCK_WEIGHT || ::GetSerializeSize(TX_NO_WITNESS(block)) *
WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`. The middle prong is a cheap
short-circuit: any block claiming > 1,000,000 transactions is rejected
without iterating. clearbit's `checkBlock` skips this prong — it goes
directly to per-tx `checkTransactionSanity`, then computes the full
weight via `calculateBlockWeight` which allocates a serialize writer
PER TRANSACTION (`serializeTransactionSize`).

**Excerpt** (`validation.zig:763-817`):
```zig
pub fn checkBlock(...) ValidationError!void {
    try checkBlockHeader(&block.header, params);                      // 1
    if (block.transactions.len == 0) return ValidationError.FirstTxNotCoinbase; // 2
    if (!block.transactions[0].isCoinbase()) return ...;
    for (block.transactions[1..]) |*tx| if (tx.isCoinbase()) return ...;
    for (block.transactions) |*tx| try checkTransactionSanity(tx);    // ← already iterates
    // ...
    const weight = calculateBlockWeight(block, allocator) catch { ... };
    if (weight > consensus.MAX_BLOCK_WEIGHT) return ValidationError.BadBlockWeight;
}
```

**Impact.** DoS vector. An attacker can submit a header claiming N tx
where the serialized block is enormous; clearbit allocates and
serializes every transaction before rejecting. Core rejects in one
multiplication. Not consensus, but operational.

---

## BUG-W143-8 — `checkBlock` checks witness commitment BEFORE weight; Core orders weight LAST for a specific reason

**Severity:** P2
**File:** `clearbit/src/validation.zig:807-858`
**Core ref:** `bitcoin-core/src/validation.cpp:4173-4181`,
`bitcoin-core/src/validation.cpp:4179`

**Description.** Core has a deliberate comment explaining the ordering:
"After the coinbase witness reserved value and commitment are verified,
we can check if the block weight passes (before we've checked the
coinbase witness, it would be possible for the weight to be too large
by filling up the coinbase witness, which doesn't change the block
hash, so we couldn't mark the block as permanently failed)." clearbit
`checkBlock` does weight FIRST (line 812-817) and witness commitment
LAST (line 857). An attacker can therefore craft a block with a bloated
coinbase witness; clearbit rejects on weight but marks it
*permanently invalid* — Core would not mark such a block permanently
invalid because the witness can be fixed without changing the block
hash.

**Excerpt** (`validation.zig:807-858`):
```zig
// 7. Check block weight                                ← FIRST in clearbit
const weight = calculateBlockWeight(block, allocator) catch { ... };
if (weight > consensus.MAX_BLOCK_WEIGHT) return ValidationError.BadBlockWeight;

// 8. BIP-34 ...
// 9. Coinbase subsidy ...
// 10. Legacy sigop check ...
// 11. BIP-141 witness commitment + unexpected-witness check.  ← LAST
try checkWitnessMalleation(...);
```

**Impact.** Reject-permanence divergence. If a block's coinbase witness
is malleated to bloat weight, clearbit's BLOCK_FAILED_VALID mark
persists across reorgs/restarts; the same block with a fixed witness
is then rejected as "duplicate-invalid". Core handles this correctly.
Tied to the BLOCK_MUTATED result-attribution path.

---

## BUG-W143-9 — Witness commitment check is in `checkBlock` not `ContextualCheckBlock`

**Severity:** P2
**File:** `clearbit/src/validation.zig:854-857`
**Core ref:** `bitcoin-core/src/validation.cpp:4169`,
`bitcoin-core/src/validation.cpp:3943` (comment: "witness malleability
is checked in ContextualCheckBlock")

**Description.** Core deliberately moves witness malleation to
`ContextualCheckBlock` because (a) it depends on segwit activation
(per-prev-block-context) and (b) other context-free checks must
complete first so the block can be marked invalid by hash. clearbit
runs it in `checkBlock` and gates segwit activation by raw height
(`height >= params.segwit_height`). This is the same outcome on
mainnet (segwit is buried activation) but on regtest where segwit
activation is via versionbits, clearbit's height-gated check fires
before activation is contextually decided.

**Excerpt** (`validation.zig:854-857`):
```zig
// 11. BIP-141 witness commitment + unexpected-witness check.
// Mirrors Bitcoin Core's CheckWitnessMalleation called from
// ContextualCheckBlock (validation.cpp:4169).
// `expect_witness_commitment` is true when SegWit is active.
try checkWitnessMalleation(block, height >= params.segwit_height, allocator);
```

**Impact.** Regtest activation-height misalignment. Tests that exercise
segwit-activation logic (e.g. BIP-9 versionbits walk-back) may see
divergent reject reasons. No mainnet impact (buried).

---

## BUG-W143-10 — `getP2SHSigOpCount` silently skips on UTXO miss; Core asserts

**Severity:** P2
**File:** `clearbit/src/validation.zig:506-527`
**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp::GetTransactionSigOpCost`

**Description.** Core's `GetTransactionSigOpCost` does
`const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout); assert(!coin.IsSpent());`
— a missing prevout is an upstream invariant violation and the program
aborts. clearbit's equivalent does `orelse continue;`, silently
returning the sigop count of a tx whose inputs are partially absent.
Same `orelse continue` pattern at line 557-558 for the witness-sigop
loop.

**Excerpt** (`validation.zig:516-525`):
```zig
for (tx.inputs) |input| {
    // Look up the previous output
    const entry = utxo_view.lookup(&input.previous_output) orelse continue;  // ← silent skip
    const prev_script_pubkey = entry.script_pubkey;
    if (script.isPayToScriptHash(prev_script_pubkey)) {
        n += script.getP2SHSigOpCount(prev_script_pubkey, input.script_sig);
    }
}
```

**Impact.** Defensive but loses the invariant. If any upstream caller
ever invokes `getTransactionSigOpCost` on a tx whose `sigop_view` is
incomplete (e.g. a buggy mempool path), the sigop budget is silently
underestimated and the
`total_sigops_cost > MAX_BLOCK_SIGOPS_COST` check at line 921 in
`connectBlock` and line 1493 in `validateBlockForIBD` would pass when
it should fail. Defense-in-depth gap.

---

## BUG-W143-11 — `connectBlock` does not enforce the witness-commitment gate

**Severity:** P0-CDIV
**File:** `clearbit/src/validation.zig:879-1000`
**Core ref:** `bitcoin-core/src/validation.cpp:4169-4171`

**Description.** `validateBlockForIBD` chains through `checkBlock`
(line 1228) which DOES include `checkWitnessMalleation`. But the
legacy `connectBlock` (line 879) is called WITHOUT a preceding
`checkBlock`/`validateBlockForIBD` in several test paths and in the
mining-path rollback code. It does NOT re-run witness-commitment.
Mining-path produced blocks that omit the witness-commitment output
post-segwit would be admitted by `connectBlock`.

**Excerpt** (`validation.zig:879-1000`) — entire function body has no
reference to `checkWitnessMalleation` or BIP-141 commitment. Grep
verifies: `checkWitnessMalleation` is called from line 857 only.

**Impact.** Legacy/mining path can produce or accept blocks lacking a
witness commitment after segwit activation. On mainnet this is gated by
checkBlock-being-called-first (sync.zig + peer.zig) but the mining
template path constructs the commitment via `GenerateCoinbaseCommitment`
elsewhere and the consensus side never re-verifies. Defense-in-depth gap
plus two-pipeline drift.

---

## BUG-W143-12 — `checkBlock` calls `checkTransactionSanity` per-tx but Core also requires `CheckTransaction` to fire from per-tx mempool path

**Severity:** P3
**File:** `clearbit/src/mempool.zig:1003` (grep hit), `clearbit/src/validation.zig:316`
**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction`

**Description.** Verified by grep that clearbit DOES call
`checkTransactionSanity` from both `checkBlock` (line 785) and
`Mempool.acceptToMemoryPool` (mempool.zig:1003). However, the per-tx
`tx_too_large` check (Core: `GetSerializeSize(TX_NO_WITNESS(tx)) *
WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`) is implemented via
`txBaseSerializeSize(tx) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`
which uses a hand-rolled byte counter (`txBaseSerializeSize`,
validation.zig:1755-1777). The counter assumes `inp.script_sig.len`
and `out.script_pubkey.len` fit in a `compactSizeLen` produces 1/3/5/9
bytes. Core uses `::GetSerializeSize` which traverses the actual
serializer. For exotic edge cases (e.g. an attacker-crafted tx with a
`compactSizeLen` field claiming a different length than the actual
script length), the two could disagree. Unlikely to matter for
consensus but is a discrepancy.

**Excerpt** (`validation.zig:1755-1777`):
```zig
fn txBaseSerializeSize(tx: *const types.Transaction) u64 {
    var sz: u64 = 4;                              // version
    sz += compactSizeLen(tx.inputs.len);
    for (tx.inputs) |inp| {
        sz += 32 + 4;                              // outpoint
        sz += compactSizeLen(inp.script_sig.len);
        sz += inp.script_sig.len;
        sz += 4;                                   // sequence
    }
    sz += compactSizeLen(tx.outputs.len);
    for (tx.outputs) |out| {
        sz += 8;                                   // value
        sz += compactSizeLen(out.script_pubkey.len);
        sz += out.script_pubkey.len;
    }
    sz += 4;                                       // locktime
    return sz;
}
```

**Impact.** Low. The hand-rolled counter is correct for well-formed
in-memory `Transaction` values (which is all clearbit ever holds). But
this is the kind of code that drifts if the serializer is later
extended (e.g. taproot annex, future witness versions in non-witness
position). Reuse the serializer instead. Pattern: hand-rolled-vs-
serializer drift risk.

---

## BUG-W143-13 — `checkBlock` lacks vin/vout-non-empty per-tx gate (only checks coinbase position)

**Severity:** P3
**File:** `clearbit/src/validation.zig:773-786`
**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:14-17`
(`bad-txns-vin-empty`, `bad-txns-vout-empty`)

**Description.** Verified that `checkTransactionSanity` (line 318-319)
DOES enforce `vin.len == 0 || vout.len == 0` per-tx. But `checkBlock`
calls `checkTransactionSanity` in step 5 (line 784-786), AFTER step 3
(coinbase position check at line 776) which assumes
`block.transactions[0].inputs[0]` is dereferenceable via `isCoinbase`.
`isCoinbase` (types.zig:43-47) is short-circuit safe: `inputs.len == 1
and std.mem.eql(...)`. If `inputs.len == 0`, `isCoinbase` returns
`false`, so `checkBlock` returns `FirstTxNotCoinbase`. OK at this site
but the *ordering invariant* is fragile.

**Excerpt** (`validation.zig:773-786`):
```zig
if (block.transactions.len == 0) return ValidationError.FirstTxNotCoinbase;
if (!block.transactions[0].isCoinbase()) return ValidationError.FirstTxNotCoinbase;
for (block.transactions[1..]) |*tx| {
    if (tx.isCoinbase()) return ValidationError.MultipleCoinbase;
}
for (block.transactions) |*tx| {
    try checkTransactionSanity(tx);                  // ← only here is vin/vout checked
}
```

**Impact.** Latent reorder hazard: if a future refactor moves the
coinbase-position check ahead of the loop in a way that dereferences
`block.transactions[0].outputs[0]`, an empty-vout block crashes
clearbit before the consensus reject fires. Low severity (no current
trigger), but the *invariant ordering* (sanity-then-position) is what
Core encodes by ordering CheckTransaction BEFORE the coinbase-multiple
loop.

---

## BUG-W143-14 — `connectBlock` no `bad-blk-length` re-check; relies on `checkBlock` having run

**Severity:** P2
**File:** `clearbit/src/validation.zig:879-1000`
**Core ref:** `bitcoin-core/src/validation.cpp:3947` (CheckBlock)

**Description.** `connectBlock` assumes `checkBlock` already ran (so
size limits are vetted). Callers of `connectBlock` that do not invoke
`checkBlock` first will skip ALL size checks. The
`validateBlockForIBD` path (peer.zig live IBD) does call
`checkBlock` first, but rollback paths (storage.zig undo dance) and
some mining-path tests invoke `connectBlock` directly. Defense-in-depth
gap.

**Impact.** Same shape as BUG-W143-3 and BUG-W143-4 — the legacy path
omits gates that the IBD path enforces.

---

## BUG-W143-15 — `validateBlockForIBD` step 6 re-checks sigop budget but uses different flags than `connectBlock`

**Severity:** P3
**File:** `clearbit/src/validation.zig:1486-1496` vs. 888-924
**Core ref:** `bitcoin-core/src/validation.cpp::ConnectBlock` sigop block

**Description.** `validateBlockForIBD` calls
`getBlockScriptFlagsForHash(height, params, &ctx.block_hash)` (line
1489) — passing the block hash so the BIP-16/Taproot exception list is
applied. `connectBlock` (line 889) calls
`getBlockScriptFlags(height, params)` — the variant that hardcodes
`block_hash = null`, so the exception list is NOT applied. This means
on the two specific exception blocks
(`00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22` and
`0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`),
the legacy `connectBlock` path uses `verify_p2sh=true` and computes
P2SH sigops; `validateBlockForIBD` uses `verify_p2sh=false` and skips
them. **Sigop counts diverge between the two paths for these two
blocks.**

**Excerpt** (`validation.zig:889`):
```zig
// Get script verification flags for this block height
const flags = getBlockScriptFlags(height, params);  // ← null block_hash; exception list not applied
```

vs. `validation.zig:1489`:
```zig
const flags = getBlockScriptFlagsForHash(height, params, &ctx.block_hash);
// ← exception list applied
```

**Impact.** Subtle two-path drift. For 99.9999% of blocks the two
flag sets produce identical sigop counts; for the two exception blocks
they differ. The BIP-16 exception block at h=174,724 was a
non-standard P2SH-violator from 2012; computing its P2SH sigops vs not
shouldn't change the block's sigop cost meaningfully in practice. But
this is exactly the kind of two-path divergence that historically
caused chain splits (e.g. Bitcoin Core's own LevelDB-vs-BDB split in
2013).

---

## BUG-W143-16 — Coinbase value check in `checkBlock` does nothing (dead branch)

**Severity:** P2 (dead-code-in-consensus-path)
**File:** `clearbit/src/validation.zig:827-839`
**Core ref:** `bitcoin-core/src/validation.cpp::ConnectBlock` bad-cb-amount

**Description.** `checkBlock` computes `coinbase_value` and compares it
to `subsidy` (without fees), then has a comment "This is a conservative
check - actual validation needs total fees which are only known after
validating all transactions" — and **the conditional body is empty.**

**Excerpt** (`validation.zig:827-839`):
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
}                                                       // ← empty body!
```

The `if` body has zero statements; the `coinbase_value > subsidy`
condition is evaluated and then discarded. This is the
**comment-as-confession** pattern (6th instance fleet-wide) and
**dead-branch-in-consensus** pattern.

**Impact.** Subsidy-only conservative check is silently a no-op.
`validateBlockForIBD` step 4 (line 1460-1465) does the real check
with `subsidy + total_fees`; `connectBlock` does the same at line
976. So the legacy paths are OK, but `checkBlock` is misleading —
the code looks like it's enforcing something but isn't.

---

## BUG-W143-17 — `checkBlock` legacy sigop check ignores BIP-141 witness sigops; comment explicitly notes it

**Severity:** P3 (by design, but error-attribution drift)
**File:** `clearbit/src/validation.zig:841-851`
**Core ref:** `bitcoin-core/src/validation.cpp:3970-3977`

**Description.** Core's `CheckBlock` (line 3970) has the same
*context-free* sigop check (legacy only) and an explicit comment "This
underestimates the number of sigops, because unlike ConnectBlock it
does not count witness and p2sh sigops." clearbit copies the comment
verbatim. The downstream `connectBlock` and `validateBlockForIBD` runs
the full count. **Match.** Documented for completeness.

**Impact.** None — matches Core. Listed for audit-coverage.

---

## BUG-W143-18 — `validateBlockForIBD` sigop budget can be exceeded by intra-block exception override; tracked in TODO

**Severity:** P2
**File:** `clearbit/src/validation.zig:1487-1495`
**Core ref:** `bitcoin-core/src/validation.cpp::ConnectBlock`

**Description.** Sigop budget is re-counted in `validateBlockForIBD`
step 6 (line 1486-1496) — but the budget compares against
`MAX_BLOCK_SIGOPS_COST` AFTER each tx. Core does the same. However,
clearbit's iteration short-circuits with `return TooManySigops` mid-tx
which is technically correct: an over-budget cumulative count cannot
recover. But Core does the cumulative check BEFORE adding each tx's
sigops; clearbit adds first then checks. Functionally equivalent
because the addition cannot underflow, but for an attacker-crafted
tx with `getTransactionSigOpCost` returning a value > 80,000 in a
single tx, clearbit's `total_sigops_cost += getTransactionSigOpCost(...)`
COULD overflow `u64` if the per-tx count is fabricated >= 2^63 (it
isn't — it's bounded by tx-weight / 4 — but the *ordering* invariant
is fragile).

**Excerpt** (`validation.zig:1490-1496`):
```zig
var total_sigops_cost: u64 = 0;
for (block.transactions) |*tx| {
    total_sigops_cost += getTransactionSigOpCost(tx, &sigop_view, flags);   // ← add first
    if (total_sigops_cost > consensus.MAX_BLOCK_SIGOPS_COST) {              // ← check after
        return ValidationError.TooManySigops;
    }
}
```

**Impact.** Latent overflow risk if per-tx sigops are ever fabricated >
2^63. In practice not exploitable but the ordering is non-Core.

---

## BUG-W143-19 — `BadCoinbaseValue` returned from `connectBlock` without explicit fee MoneyRange ceiling on subsidy

**Severity:** P3
**File:** `clearbit/src/validation.zig:973-978`
**Core ref:** `bitcoin-core/src/validation.cpp:2611-2614` (bad-cb-amount)

**Description.** `connectBlock` computes `coinbase_value > subsidy +
total_fees` (line 976) but `subsidy + total_fees` is an `i64`
addition. If `total_fees` is at the upper edge of MoneyRange
(2.1e15) and subsidy is at the early-chain limit (5e9), the sum is far
from `INT64_MAX`. But the check does not enforce `MoneyRange(subsidy +
total_fees)` before the comparison — Core does (`bad-blk-amount`).

**Excerpt** (`validation.zig:970-978`):
```zig
// W93 G16: coinbase value ≤ subsidy + total_fees (Core "bad-cb-amount",
// validation.cpp:2611-2614).  Previously a TODO; now the legacy path
// matches `validateBlockForIBD`'s gate exactly.
const subsidy = consensus.getBlockSubsidy(height, params);
var coinbase_value: i64 = 0;
for (block.transactions[0].outputs) |out| coinbase_value += out.value;
if (coinbase_value > subsidy + total_fees) {
    return ValidationError.BadCoinbaseValue;
}
```

**Impact.** Currently safe because every `total_fees` accumulator is
bounded by `isValidMoney` (line 965 inside the same function), but the
ceiling on the sum is implicit. Core makes this explicit. Low priority.

---

## BUG-W143-20 — `validateBlockForIBD` BIP-30 enforcement falls through to "enforce always" when `active_chain` is null but BIP-34 height is below caller-provided height

**Severity:** P1
**File:** `clearbit/src/validation.zig:1275-1288`
**Core ref:** `bitcoin-core/src/validation.cpp:2460-2462`

**Description.** Core's bypass: `fEnforceBIP30 &&= !(pindexBIP34height
&& pindexBIP34height->GetBlockHash() == params.BIP34Hash);`. clearbit
mirrors with `bip34_truly_active` (line 1275-1281). When
`ctx.active_chain` is `null` (caller has no chain snapshot), clearbit
sets `bip34_truly_active = false` and **always enforces BIP-30** —
even at heights well above the bypass window. Mining path /
`submitblock` RPC pass `active_chain = null` (see acceptBlock
defaults at line 1701-1704). This is **safer than Core** in the
direction of "false reject" rather than "false accept", but it
means a `submitblock` RPC of a height-2,000,000 block with no
duplicate-txid will still be subjected to a UTXO-lookup loop for every
output (line 1290-1303), which costs O(outputs) RocksDB lookups per
submitblock call. Performance / DoS concern.

**Excerpt** (`validation.zig:1275-1288`):
```zig
const bip34_truly_active: bool = blk: {
    const bip34_h = params.bip34_height;
    const bip34_hash = params.bip34_hash orelse break :blk false;
    const chain = ctx.active_chain orelse break :blk false;    // ← null → false
    if (bip34_h >= chain.len) break :blk false;
    break :blk std.mem.eql(u8, &chain[bip34_h], &bip34_hash);
};

const enforce_bip30 = if (bip30_exempt) false
    else if (bip34_truly_active and height >= params.bip34_height and height < BIP34_IMPLIES_BIP30_LIMIT) false
    else true;                                                   // ← falls through to "enforce" when null
```

**Impact.** Mining path / submitblock RPC pays O(outputs) BIP-30
lookup overhead per block regardless of height. Not consensus-breaking
but operationally costly at large heights.

---

## BUG-W143-21 — `connectBlock` two-path-sigops divergence on `getP2SHSigOpCount` missing-utxo behavior (couples with BUG-W143-10)

**Severity:** P3
**File:** `clearbit/src/validation.zig:919-923`
**Core ref:** `bitcoin-core/src/validation.cpp::ConnectBlock`

**Description.** Same pattern as BUG-W143-10 but specific to
`connectBlock`: when `sigop_view.lookup` misses, the sigop count for
that input is zero. `connectBlock` continues iterating without
flagging the missing input. The `total_sigops_cost > MAX_BLOCK_SIGOPS_COST`
check then passes when it should have aborted on missing-prevout
earlier. The subsequent fee-balance loop (line 948-967) DOES catch the
missing input via `MissingInput`, so the practical outcome is reject —
but for an attacker-crafted block where every input is missing AND no
fees are computed (e.g. an all-coinbase block which clearbit already
rejects as MultipleCoinbase), the sigop check is silently bypassed.

**Excerpt** (`validation.zig:917-923`):
```zig
for (block.transactions) |*tx| {
    total_sigops_cost += getTransactionSigOpCost(tx, sigop_view, flags);
    if (total_sigops_cost > consensus.MAX_BLOCK_SIGOPS_COST) {
        return ValidationError.TooManySigops;
    }
    // ...
}
```

**Impact.** Defense-in-depth gap. Already mostly mitigated by other
gates but the *path through `connectBlock`* loses one layer of
protection.

---

## BUG-W143-22 — `checkBlock` does not enforce `block.vtx[0].outputs.len > 0` for SegWit witness-commitment path

**Severity:** P2
**File:** `clearbit/src/validation.zig:1898-1899`,
`clearbit/src/validation.zig:1927`
**Core ref:** `bitcoin-core/src/validation.cpp::CheckWitnessMalleation`
@ 3877 (`assert(!block.vtx.empty() && !block.vtx[0]->vin.empty());`)

**Description.** `checkWitnessMalleation` indexes
`coinbase.outputs[commitpos.?]` (line 1927). If
`getWitnessCommitmentIndex` finds a commit at `commitpos`, this is
safe. But it ALSO indexes `coinbase.inputs[0].witness` at line 1899
BEFORE checking `coinbase.inputs.len > 0`. clearbit relies on
`isCoinbase()` having been verified upstream, which guarantees
`inputs.len == 1`. But a malformed block where `checkBlock` was
NOT run first (e.g. a buggy caller that invokes `connectBlock`
directly without `checkBlock`) crashes on `inputs[0]` if `inputs.len ==
0`. This is the same invariant-ordering hazard as BUG-W143-13 but
specifically for the witness commitment path.

**Excerpt** (`validation.zig:1896-1903`):
```zig
const commitpos = getWitnessCommitmentIndex(block);
if (commitpos != null) {
    // Gate 1: coinbase witness stack must have exactly 1 element.
    const coinbase = &block.transactions[0];
    const witness_stack = coinbase.inputs[0].witness;        // ← crash if inputs.len == 0
    if (witness_stack.len != 1 or witness_stack[0].len != 32) {
        return ValidationError.BadWitnessCommitment;
    }
```

**Impact.** Crash hazard on malformed input. Core uses an `assert`
(debug build crashes, release builds undefined behavior). clearbit's
implicit invariant is identical but unverified. Latent.

---

## Fleet-pattern observations

1. **Two-pipeline guard (legacy `connectBlock` + new `validateBlockForIBD`).**
   This is the 7+ instance fleet pattern across `clearbit`. Six of the
   audit's BUGs (3, 4, 11, 14, 15, 21) trace to the legacy
   `connectBlock` path being missing checks that the new path
   enforces. The fix is either to delete `connectBlock` (it's exercised
   only by tests + the rollback dance) or to have it delegate to
   `validateBlockForIBD` with `current_time=0`, `prev_mtp=tip.mtp`,
   etc.

2. **Comment-as-confession (5th + 6th fleet instance).** BUG-W143-5
   (`checkBlockHeader` future-time TODO comment) and BUG-W143-16
   (`checkBlock` subsidy check with empty `if` body) are the kind of
   pattern that turns up consistently in fleet audits — the developer
   knew the gate was missing, left a comment, and never removed the
   skeleton. Matches the W141 BUG-13 / W138 BUG-3 pattern (Haskoin /
   rustoshi instances).

3. **`mutated` flag absence (P0-CDIV).** clearbit is far from alone
   here in the fleet; W76/W93/W101 P0 sweeps have not historically
   touched merkle-root mutation detection. Worth a fleet-wide sweep:
   `grep -rn "fMutated\|bMutated\|mutated" {impl}/src` and verify the
   merkle-root helper sets a flag that `CheckBlock` consumes.

4. **Dead-branch-in-consensus** (BUG-W143-16) — empty `if` body in the
   subsidy check is a new instance of the
   "scaffolding-present-no-callers" pattern (W138 cluster — though here
   it's "branch-present-no-body"). Catalogued for the campaign tally.

5. **Hand-rolled-counter-vs-serializer drift** (BUG-W143-12) — new
   instance class. The hand-rolled `txBaseSerializeSize` will be
   correct only as long as the serializer is not extended.

## Test coverage observations

The `validateCoinbaseHeight` byte-prefix tests (line 3167-3201) are
GOOD — they exercise the canonical BIP-34 encoding ladder including
the sign-pad byte and the
"reject non-canonical 1-byte-push for height ≤ 16" cases. The merkle
root tests (line 1892-1940) only test happy paths; **there is no
test exercising the duplicate-pair mutation case** (BUG-W143-1 /
BUG-W143-2). Adding such a test would catch the CVE-2012-2459 gap.

## Recommendations (DISCOVERY mode — not applied here)

Priority order for follow-up fix waves:
1. BUG-W143-1 + BUG-W143-2 — single architectural patch: thread a
   `mutated_out` parameter through `computeMerkleRoot` and consume it
   in `checkBlock`. Both fixes land together. P0-CDIV closure.
2. BUG-W143-3 + BUG-W143-4 + BUG-W143-11 — make `connectBlock` a thin
   wrapper around `validateBlockForIBD`. Closes the two-pipeline guard
   in one move. P0-CDIV closure (legacy path).
3. BUG-W143-5 — move the future-time check into `checkBlockHeader`
   itself with a `current_time: ?i64` optional parameter that defaults
   to `std.time.timestamp()`. Drop the
   "should be passed as a parameter in production use" comment.
4. BUG-W143-16 — delete the dead `if` body or wire it through with
   `total_fees` (then it duplicates the work `connectBlock` does, so
   probably just delete the entire block).
5. BUG-W143-6 — emit `BadDifficulty` (`bad-diffbits`) for negative /
   zero / overflowed `nBits` to match Core's reject reason.
6. BUG-W143-7 — add the `block.transactions.len * WITNESS_SCALE_FACTOR
   > MAX_BLOCK_WEIGHT` early gate to `checkBlock`.
7. BUG-W143-8 / BUG-W143-9 — reorder weight check after witness
   commitment in `checkBlock`; move witness commitment to a
   `contextualCheckBlock` analog.

Bugs 10, 12, 13, 17–22 are defense-in-depth / hardening / cleanup;
none are urgent.

## End of W143
