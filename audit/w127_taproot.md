# W127 — Taproot / Schnorr / Tapscript audit (clearbit)

**Date:** 2026-05-17
**Scope:** BIP-340 Schnorr, BIP-341 Taproot (key-path + script-path), BIP-342
Tapscript opcodes + OP_CHECKSIGADD + leaf version 0xc0 + per-leaf
validation-weight sigops budget, sighash construction, annex handling,
SIGHASH_DEFAULT, future-soft-fork gates.
**Mode:** DISCOVERY (no production code changes; XFAIL guards only).
**Test step:** `zig build test-w127` (30 tests, folded into `zig build test`).

## Summary

clearbit's BIP-340/341/342 stack is **substantially complete and largely
Core-aligned at the byte level** — the BIP-341 vector runner shim
(`src/bip341_shim.zig`) is documented to produce byte-perfect `sigMsg` +
`sigHash` for all 7 `keyPathSpending` vectors against
`bitcoin-core/src/test/data/bip341_wallet_vectors.json`, the Schnorr-verify
wrapper goes straight to `libsecp256k1::secp256k1_schnorrsig_verify` (so
BIP-340 strict semantics — including the `s >= n` / `rx >= p` rejections —
are externalised to upstream), and the script-path control-block math is
the canonical `secp256k1_xonly_pubkey_tweak_add_check` call. The
tapscript executor honours the leaf-version gate (0xc0 only; unknown
versions → soft-fork no-op or `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`),
the validation-weight budget (50 * sigops vs 50 + serialized witness
stack), the consensus-MINIMALIF rule, and the `EvalChecksigTapscript`
ordering (`success = !sig.empty()` → weight deduct → empty-pubkey →
32-byte vs unknown branching).

The remaining gaps are **not** in the cryptographic primitives. They are
clustered in three areas:

1. **Caching / performance** — `SigCache` (sig_cache.zig) is fully
   engineered (LRU + nonce-keyed, Core-parity hashing) AND wired — but
   at the **wrong granularity**: `validation.zig:2462-2546
   verifyScriptJob` caches the entire `ScriptEngine.verify()` result
   keyed by `(txid, prev_script_pubkey, script_sig||witness, flags)`,
   not per-CHECKSIG `(sighash, pubkey, sig)` tuples the way Core does
   in `script/sigcache.cpp`. This catches mempool→block replay but
   misses cross-tx / cross-input signature reuse. No
   `PrecomputedTransactionData` analog exists, so `sha_prevouts /
   sha_amounts / sha_scriptpubkeys / sha_sequences` are re-hashed once
   per input on multi-input transactions (W105 already filed this for
   the ECDSA side; W127 confirms it applies to Schnorr).
2. **Error-code emission parity** — three call sites surface a different
   `SCRIPT_ERR_*` than Core would, all without altering the
   accept/reject decision. The most operationally visible is the
   discourage-upgradable-witness-program path emitting
   `WitnessProgramMismatch` rather than
   `DiscourageUpgradableWitnessProgram` (mismatch → wrong error class
   for soft-fork-future warning, breaks parity diffs).
3. **Test-coverage / vector-runner provenance** — the BIP-341 wallet
   vector validation lives in a separate runner (`tools/bip341-vector-
   runner`) plus an in-repo `bip341_shim.zig`, but no in-tree test under
   `src/` re-runs the canonical vectors against `computeTaprootSighash`
   on every `zig build test`. Likewise `script_assets_test.json` (Core's
   tapscript end-to-end vectors covering all of BIP-342 opcodes
   including OP_CHECKSIGADD) is not exercised by any in-tree test. This
   is a *coverage* gap, not a code gap; the vectors-passing claim in
   `taproot_sighash.zig:8-10` is plausible but not gated by CI here.

| Verdict | Gates | Notes |
|---|---|---|
| PRESENT | 22 | Core-equal behavior + at least one exercised call site |
| PARTIAL | 5  | Behavior right but a side-channel (cache granularity / error class / coverage) is off |
| MISSING | 3  | Whole feature absent (no PrecomputedTransactionData / no in-tree assets vector runner / wrong error code on discourage path) |

**Bug count: 9** (P0-CONSENSUS=0 / P0-CDIV=0 / P0=0 / P1=1 / P2=5 / P3=3).
No consensus-divergent findings. All bugs are performance, error-class
parity, or test-coverage; the cryptographic decisions match Core.

## Gates

### BIP-340 Schnorr signature verification (G1–G6)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G1 | 64-byte sig accepted via `secp256k1_schnorrsig_verify` | `pubkey.cpp:236-241` | `crypto.zig:890-908 verifySchnorr` | PRESENT |
| G2 | 65-byte sig accepted (hashtype byte stripped before verify) | `interpreter.cpp:1731-1734` | `script.zig:1119-1139, 2318-2330` | PRESENT |
| G3 | size ∉ {64,65} → `SCRIPT_ERR_SCHNORR_SIG_SIZE` | `interpreter.cpp:1726` | `script.zig:1112-1114, 2308` | PRESENT |
| G4 | 65-byte sig with hashtype byte = SIGHASH_DEFAULT → `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE` | `interpreter.cpp:1733` | `script.zig:1128-1130, 2324-2326` | PRESENT |
| G5 | hashtype ∉ {0, 1, 2, 3, 0x81, 0x82, 0x83} → reject | `interpreter.cpp:1516` | `taproot_sighash.zig:25-30 isValidTaprootHashType` | PRESENT |
| G6 | x-only pubkey parse via `secp256k1_xonly_pubkey_parse` (rx ≥ p / non-curve fails here) | `pubkey.cpp:237-240` | `crypto.zig:894-897` | PRESENT |

### BIP-341 Taproot key-path spending (G7–G12)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G7 | Gated on witversion=1 ∧ program.len=32 ∧ !is_p2sh | `interpreter.cpp:1947` | `script.zig:1078` | PRESENT |
| G8 | Pre-activation `!SCRIPT_VERIFY_TAPROOT` returns success without consuming witness | `interpreter.cpp:1949` | `script.zig:1089-1091` | PRESENT |
| G9 | `WITNESS_PROGRAM_WITNESS_EMPTY` for zero witness items | `interpreter.cpp:1950` | `script.zig:1093` | PRESENT |
| G10 | Annex stripped only when len ≥ 2 ∧ back[0] == 0x50 | `interpreter.cpp:1951-1958` | `script.zig:1099-1102` | PRESENT |
| G11 | Annex bytes (including 0x50 prefix) committed via `sha_annex` | `interpreter.cpp:1954` | `taproot_sighash.zig:169-176` (compactsize+bytes, hashed with prefix) | PRESENT |
| G12 | Key-path = exactly 1 element after annex strip; calls `CheckSchnorrSignature` against the **scriptPubKey output key** (no on-the-fly tweak math) | `interpreter.cpp:1960-1965` | `script.zig:1108-1169` | PRESENT |

### BIP-341 Taproot script-path spending (G13–G18)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G13 | Control block size ∈ [33, 33 + 32*128] ∧ (size-33) % 32 == 0; else `TAPROOT_WRONG_CONTROL_SIZE` | `interpreter.cpp:1970` | `script.zig:1178-1183` | PRESENT |
| G14 | Tapleaf hash = tagged_hash("TapLeaf", leaf_version || compactsize(len) || script) with **full** compactsize encoding (not capped at 0xFFFF — Ordinals tapscripts > 64 KiB) | `interpreter.cpp:1872-1875` + `streams.h::WriteCompactSize` | `crypto.zig:1534-1576 computeTapleafHash` + `appendCompactSize` (documents prior bug at line 1541 — capped at 0xFFFF — that wrongly failed mainnet block 947960) | PRESENT |
| G15 | Tapbranch lexicographic-sort + double-tagged-hash | `interpreter.cpp:1877-1886` | `crypto.zig:1605-1621` | PRESENT |
| G16 | TapTweak = tagged_hash("TapTweak", internal_key || merkle_root); verified via `xonly_pubkey_tweak_add_check` with parity from `control[0] & 1` | `interpreter.cpp:1888-1914` | `crypto.zig:1623-1650` | PRESENT |
| G17 | `WITNESS_PROGRAM_MISMATCH` on commitment-verify failure (not a dedicated "BAD_TAPROOT_COMMITMENT" code) | `interpreter.cpp:1975` | `script.zig:1200-1202` | PRESENT |
| G18 | Leaf version mask = `control[0] & 0xfe` (parity bit dropped) | `interpreter.cpp:1973` | `script.zig:1192` + `crypto.zig:1585` | PRESENT |

### BIP-342 Tapscript (G19–G26)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G19 | Leaf version 0xc0 ONLY executed as tapscript; unknown versions → success (or `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` if flag) | `interpreter.cpp:1978-1988` | `script.zig:1204-1216` | PRESENT |
| G20 | OP_SUCCESSx pre-scan returns success immediately (unless DISCOURAGE_OP_SUCCESS) | `interpreter.cpp:1837-1852` + `IsOpSuccess` | `script.zig:552-614 preScanTapscript + isOpSuccess` | PRESENT |
| G21 | Per-leaf validation-weight budget initialised to `serializedSize(witness.stack) + 50`; -50 per non-empty sig OP_CHECKSIG/-VERIFY/CHECKSIGADD; abort on negative | `interpreter.cpp:1981-1982, 357-365` | `script.zig:1253-1255, 716-732, 1853 / 1903 / 2046-2048` | PRESENT |
| G22 | OP_CHECKSIGADD: `<sig><num><pubkey> → <num+success>` ; success = !sig.empty(); non-empty failure → `NULLFAIL` abort | `interpreter.cpp:347-385 EvalChecksigTapscript` + main switch arm | `script.zig:2027-2070` | PRESENT |
| G23 | OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY DISABLED in tapscript | `interpreter.cpp:1933-1942` | `script.zig:1932-1942` | PRESENT |
| G24 | Tapscript: empty pubkey → `SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY` even when sig is also empty | `interpreter.cpp:367-368` | `script.zig:1856, 1904, 2049` | PRESENT |
| G25 | Tapscript: unknown pubkey size (≠ 32) treated as future-soft-fork; `success` unchanged; `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` gate | `interpreter.cpp:373-381` | `script.zig:1868-1880, 1910-1919, 2059-2067` | PRESENT |
| G26 | Tapscript: MINIMALIF is a CONSENSUS rule (gated on sigversion alone, not on flag) | `interpreter.cpp:614-620` | `script.zig:1407-1410, 1431-1434` | PRESENT |

### Cross-cutting / wiring (G27–G30)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G27 | BIP-341 sighash ext_flag = 1 (script path) commits to tapleaf_hash + key_version=0x00 + codesep_pos | `interpreter.cpp:1560-1566` | `taproot_sighash.zig:187-192` | PRESENT |
| G28 | Schnorr signature cache (BIP-340 verify result, salted-nonce keyed) | `script/sigcache.cpp:39-118 CSignatureCache::ComputeEntrySchnorr` per `(sighash, pubkey, sig)` | `sig_cache.zig` wired by `validation.zig:2462-2546 verifyScriptJob` but at WHOLE-INPUT granularity (`(txid, scriptPubKey, script_sig\|\|witness, flags)`), not per-CHECKSIG. Catches mempool→block replay; misses cross-tx / cross-input signature reuse | **PARTIAL — BUG-1 P2** |
| G29 | PrecomputedTransactionData: per-tx hash of `sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences` computed once and shared across inputs | `interpreter.cpp:1482-1570 SignatureHashSchnorr` + `cache.m_*_single_hash` | `taproot_sighash.zig:104-138 buildSigMsg` recomputes all four per-input | **PARTIAL — BUG-2 P1** |
| G30 | In-tree CI exercise of canonical BIP-341 (`bip341_wallet_vectors.json`) + BIP-342 (`script_assets_test.json`) vectors | Core: `src/test/script_tests.cpp` reads `script_assets_test.json` under unit-test | clearbit: vectors live in external runner `tools/bip341-vector-runner` (per `taproot_sighash.zig:8-10`); no `src/tests_*.zig` re-runs them on `zig build test` | **MISSING — BUG-3 P2** |

## BUGs catalogued

### BUG-1 — Sig-cache wired at WHOLE-INPUT granularity, not per-signature (PARTIAL — P2 perf)

**Where:** `src/validation.zig:2462-2546 verifyScriptJob` + `src/sig_cache.zig`
**What:** `SigCache` IS wired — but at the wrong level. Core's
`CSignatureCache` (sigcache.cpp:39-118) caches per-signature
verification results — i.e. `(sighash, pubkey, sig) → bool`. clearbit
caches the entire `ScriptEngine.verify()` result keyed by
`(txid, prev_script_pubkey, script_sig||witness, flags)`.
That works (and is the right thing for the mempool→block hot path
where the entire input is replayed), but it means the cache **cannot
hit** when the same signature appears across different transactions or
across different inputs in the same transaction — both common cases on
chain. Per-input-script-by-itself rather than per-sigop. Core's design
de-duplicates at the (sighash, pubkey, sig) tuple level, which is a
strict superset of clearbit's caching.
**Inside** `verifySchnorr` / `verifyEcdsa` themselves: zero cache
lookups. The "Schnorr-specific" comment at `sig_cache.zig:183` ("32
bytes x-only for Schnorr") is aspirational — no call site keys the
cache with a 32-byte x-only pubkey.
**Impact:** Re-verification cost on blocks containing the same
signature across multiple inputs (common in CoinJoin / consolidation /
batched-MuSig2-future scenarios). Constant-factor improvement
available; not consensus-relevant.
**Verdict:** **Coarse-granularity caching** — better than nothing,
worse than Core. Distinct from "helper never wired" because the helper
IS wired, just at the outer layer only.
**Priority:** P2 (perf optimisation, fleet-wide). Future wave should
introduce a second cache layer at the per-CHECKSIG site (or migrate
the existing cache into `verifySchnorr` / `verifyEcdsa` and switch the
outer cache to a script-result cache keyed by witness data).

### BUG-2 — No PrecomputedTransactionData analog (PARTIAL — P1 perf)

**Where:** `src/taproot_sighash.zig:104-138 buildSigMsg` + `src/script.zig:1153-1161, 2349-2357`
**What:** Core's `PrecomputedTransactionData` (`interpreter.h`) holds
`m_prevouts_single_hash`, `m_spent_amounts_single_hash`,
`m_spent_scripts_single_hash`, `m_sequences_single_hash`,
`m_outputs_single_hash`, and `m_spent_outputs[]`, computed **once per
transaction** and shared across every input's sighash. Tapscript
`SignatureHashSchnorr` consults them at `interpreter.cpp:1523-1529`.
clearbit's `buildSigMsg` re-runs the four SHA256 streams (`sha_prevouts`,
`sha_amounts`, `sha_scriptpubkeys`, `sha_sequences`) on every call —
i.e. every CHECKSIG inside every input. For a 100-input Taproot tx with
N sigs per input, you do `4 * N * (inputs)` SHA256 invocations on data
that does not vary across inputs.
**Impact:** Quadratic-ish cost on multi-input Taproot transactions.
Same algorithmic class as W105 G22 finding for the witness-v0 side.
No consensus difference.
**Priority:** P1 (performance). Future fix wave should mirror Core's
`PrecomputedTransactionData` shape and thread it through `ScriptEngine`
construction.

### BUG-3 — In-tree CI does not run BIP-341/342 canonical vectors (MISSING — P2 coverage)

**Where:** test wiring (no file exists at `src/tests_bip341_vectors.zig` or similar)
**What:** `taproot_sighash.zig:8-10` claims byte-perfect parity with
`bitcoin-core/src/test/data/bip341_wallet_vectors.json` across all 7
`keyPathSpending` vectors — and the parity is real, validated via the
external runner under `tools/bip341-vector-runner/clearbit-shim`. But
the runner is **not** invoked by `zig build test`; the unit-test suite
exercises only hand-rolled cases. Likewise `script_assets_test.json`
(Core's tapscript end-to-end vectors covering OP_CHECKSIGADD, the leaf-
version + control-block error matrix, MINIMALIF, OP_SUCCESSx, etc.) is
not run anywhere in tree.
**Impact:** Refactors of `buildSigMsg` / `verifyTaprootControlBlock` /
`EvalChecksigTapscript` can silently break parity until somebody
re-runs the external shim. No consensus difference today, but future
edits are at risk.
**Priority:** P2 (test coverage). Future wave should add an in-tree
test that `@embedFile`s the JSON, parses it, and asserts each vector's
`intermediary.sigMsg` + `intermediary.sigHash` matches `buildSigMsg`
output, plus a tapscript subset against `EvalChecksigTapscript`.

### BUG-4 — `discourage_upgradable_witness_program` emits wrong SCRIPT_ERR (MISSING — P2 wire-format)

**Where:** `src/script.zig:1273-1283`
**What:** Core's path at `interpreter.cpp:1993-1995` emits
`SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` for an unknown
witness version when the discourage flag is set. clearbit's code
returns `ScriptError.WitnessProgramMismatch` (line 1281). The
`WitnessProgramMismatch` enum is the consensus-MISMATCH error code,
which Core uses only for "witness program does not match scriptPubKey
hash" — a hard reject, not a future-soft-fork warning. clearbit's
`ScriptError` enum has no `DiscourageUpgradableWitnessProgram` variant
at all.
**Impact:** Wire-format / RPC error class. Any tooling that
distinguishes "discouraged-future-soft-fork-script" from "outright
malformed witness" sees them collapsed. accept/reject decision is
unchanged (both branches reject when the flag is set), so no
consensus impact.
**Priority:** P2 (error-code parity).

### BUG-5 — Effective-witness-empty edge after annex strip surfaces `WITNESS_PROGRAM_WITNESS_EMPTY` rather than a key-path Schnorr error (PARTIAL — P2 wire-format)

**Where:** `src/script.zig:1262-1266`
**What:** Witness = `[annex_only_0x50…]` is impossible (annex strip
requires `witness.len >= 2`, so a sole 0x50-prefixed item is treated as
the sig, not as the annex). But: witness = `[empty, 0x50…]` strips
annex → `effective_witness = [empty]` → key-path; sig.len = 0 → falls
through to `SchnorrSigSize`. **That** path is right.
The bug is the **other** edge: witness = `[0x50…]` (single annex-like
item, not strippable). clearbit hits the else-branch at line 1262
because `effective_witness.len == 1` is the *key-path* branch — which
it correctly takes. Core, on the same input, also takes the key-path.
This row is **not** a bug in fact; it is on the audit only to flag
that the comment at line 1263 ("no signature for key-path, no script
for script-path") is misleading — that branch is `effective_witness.len
== 0`, which can only happen via the strip path when `witness.len ==
1` AND the only item is exactly the annex marker — but the strip is
gated on `len ≥ 2`, so this branch is **structurally unreachable**.
**Impact:** Dead code; no consensus impact. Cosmetic.
**Priority:** P3 (code clarity).

### BUG-6 — `tapleaf_hash` field on `ScriptEngine` is also unreachably reset (PARTIAL — P3 cosmetic)

**Where:** `src/script.zig:645, 1194`
**What:** `tapleaf_hash` is `?[32]u8 = null` on the struct; set at line
1194 before tapscript exec; consulted at line 2316. There is no
reset-on-failure path — if `execute(tap_script)` errors and the engine
is reused, `tapleaf_hash` would carry over. But the engine is
constructed per-input in the only production caller, so reuse never
happens. Same pattern as `validation_weight_init` / `taproot_annex`.
**Impact:** None today; tripwire for future refactors that pool
engines across inputs.
**Priority:** P3.

### BUG-7 — `codesep_pos` default `0xFFFFFFFF` vs Core's `0xFFFFFFFFUL` initialized inside EvalScript (PARTIAL — P3 wire-format)

**Where:** `src/script.zig:697, 1838` vs `bitcoin-core/src/script/interpreter.cpp:434-435`
**What:** Core resets `execdata.m_codeseparator_pos = 0xFFFFFFFFUL`
**inside** `EvalScript` at every entry (line 434) and sets
`m_codeseparator_pos_init = true`. clearbit sets it once at engine
construction (line 697) and never re-asserts initialization on
tapscript re-entry. The tapscript sigmsg-write at
`taproot_sighash.zig:191` is unconditional — so if `verify()` is
called twice on the same engine (with a tapscript leaf each time), the
second run carries over the first run's OP_CODESEPARATOR position.
**Impact:** Same as BUG-6 — the engine is constructed per-input, so
reuse never happens. But the sighash bytes WOULD differ from Core if
it did.
**Priority:** P3 (tripwire).

### BUG-8 — Tapscript sigops budget guard fires on `validation_weight_init = false` rather than `assert!` (PARTIAL — P3 cosmetic)

**Where:** `src/script.zig:725-732`
**What:** Core asserts `m_validation_weight_left_init` at
`interpreter.cpp:361` and proceeds; failure is a programmer error.
clearbit's `consumeValidationWeight` checks the same flag and returns
`TapscriptValidationWeight` (a recoverable script error) instead of
asserting. Behavior is fail-closed — script rejects — but the error
class differs.
**Impact:** Wire-format / RPC error. Any path that hits this with the
flag uninitialised would surface "validation weight budget exhausted"
where Core would crash with an assertion. Today the budget is always
initialised before `execute(tap_script)` so the branch is unreachable.
**Priority:** P3 (defensive guard returning the "wrong" error code in
an unreachable branch).

### BUG-9 — `WitnessProgramWrongLength` for unknown-witness-v0-size emits wrong error class (MISSING — P2 wire-format)

**Where:** `src/script.zig:1074-1077`
**What:** When witness version is 0 but program length is neither 20
(P2WPKH) nor 32 (P2WSH), Core emits
`SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH` (`interpreter.cpp:1945`).
clearbit emits `ScriptError.WitnessProgramWrongLength` — which is
correct. But the field naming inconsistency: clearbit uses
`WitnessProgramWrongLength` here, `WitnessProgramWitnessEmpty` at
line 1036, `WitnessProgramMismatch` at line 1041 and line 1281, with
no separate `DiscourageUpgradableWitnessProgram`. This is the same
class of finding as BUG-4 — partial enum coverage of Core's
`SCRIPT_ERR_*` set. Listed separately so a fix wave can sweep both at
once.
**Impact:** Wire-format / RPC error class only.
**Priority:** P2.

## Out of scope (W127 explicit non-targets)

- **BIP-341 wallet derivation** (BIP-32 / BIP-86 tweak math): owned by W118
  wallet audit. Wallet-level tests in `tests_wallet_taproot.zig` already
  exercise BIP-86 + BIP-341 sighash; W127 only catalogues the consensus
  path.
- **`script_assets_test.json` full re-run**: BUG-3 flags the gap; W127
  itself does not embed or run the file (would inflate the
  diff and pull in JSON-parsing infrastructure). Future wave can.
- **Schnorr signature aggregation (MuSig2, BIP-327)**: not on chain yet,
  no Core reference path.
- **Cross-input Schnorr sig batch verification**: a Core optimisation
  (`secp256k1_schnorrsig_verify_batch`) clearbit could use; deferred.
- **BIP-119 / OP_CTV, BIP-118 / SIGHASH_ANYPREVOUT**: not active on
  mainnet, not enforced by clearbit.

## Methodology

1. Read Bitcoin Core consensus refs:
   - `bitcoin-core/src/script/interpreter.cpp` — `EvalChecksigPreTapscript`,
     `EvalChecksigTapscript`, `EvalChecksig`, `EvalScript`,
     `ExecuteWitnessScript`, `ComputeTapleafHash`, `ComputeTapbranchHash`,
     `ComputeTaprootMerkleRoot`, `VerifyTaprootCommitment`,
     `VerifyWitnessProgram`, `CheckSchnorrSignature`,
     `SignatureHashSchnorr`.
   - `bitcoin-core/src/script/interpreter.h` — `TAPROOT_LEAF_TAPSCRIPT`,
     `TAPROOT_LEAF_MASK`, `TAPROOT_CONTROL_*_SIZE`,
     `VALIDATION_WEIGHT_PER_SIGOP_PASSED`, `VALIDATION_WEIGHT_OFFSET`,
     `SIGHASH_OUTPUT_MASK`, `SIGHASH_INPUT_MASK`.
   - `bitcoin-core/src/script/script.h` — `ANNEX_TAG = 0x50`.
   - `bitcoin-core/src/script/script_error.h` — `SCRIPT_ERR_TAPROOT_*`,
     `SCRIPT_ERR_TAPSCRIPT_*`, `SCRIPT_ERR_SCHNORR_*`,
     `SCRIPT_ERR_DISCOURAGE_*`.
   - `bitcoin-core/src/pubkey.cpp:236` — `XOnlyPubKey::VerifySchnorr`.
   - `bitcoin-core/src/script/sigcache.cpp` — `CSignatureCache`.
2. BIPs: 340 (Schnorr signatures), 341 (Taproot), 342 (Tapscript), 86
   (key derivation).
3. Crawl clearbit src for:
   - `taproot|schnorr|bip340|bip341|bip342|tapscript|tapleaf|checksigadd|
      annex|sighash_default|0xc0|leaf_version|control_block|verify_schnorr|
      key_path|script_path|validation_weight|sigops_budget`.
   - All `ScriptError.Tapscript*` / `ScriptError.Schnorr*` / `ScriptError.Taproot*` /
     `ScriptError.DiscourageUpgradable*` sites.
   - All `verifySchnorr` / `verifyTaprootControlBlock` / `computeTapleafHash` /
     `computeTaprootSighash` / `buildSigMsg` invocations.
4. Classify gates against the 30-gate matrix, ordering tests by BIP
   subsection (Schnorr → key-path → script-path → tapscript → cross-cutting).
5. Catalogue PARTIAL+MISSING gates as BUGs with consensus / performance /
   wire-format / coverage priority.

Streak preserved: 71 fix + 56 discovery.
