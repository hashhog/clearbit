# W135 — Standardness rules (IsStandardTx) audit (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's mempool standardness gate vs Bitcoin Core
(`bitcoin-core/src/policy/policy.{h,cpp}` — `IsStandardTx`, `IsStandard`,
`ValidateInputsStandardness`, `IsWitnessStandard`, `GetDust`,
`GetDustThreshold`, dust-output cap, datacarrier, bare-multisig,
scriptSig push-only / size, version range, MAX_STANDARD_TX_WEIGHT,
MIN_STANDARD_TX_NONWITNESS_SIZE, MAX_TX_LEGACY_SIGOPS),
`bitcoin-core/src/script/solver.{h,cpp}` (`Solver` /
`MatchPayToPubkey` / `MatchPayToPubkeyHash` / `MatchMultisig` /
`MatchMultiA` / `TxoutType` enum incl. `WITNESS_UNKNOWN`),
`bitcoin-core/src/policy/truc_policy.{h,cpp}` (TRUC `TX_MAX_STANDARD_VERSION=3`),
`bitcoin-core/src/consensus/tx_check.cpp` (consensus pre-checks).
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w135` (folded into `zig build test`).
**Related prior waves:** W70e (initial IsStandardTx scaffold),
W71 (`MIN_STANDARD_TX_NONWITNESS_SIZE` / scriptSig limits / datacarrier
cumulative / bare-multisig n≤3), W96 (`MAX_STANDARD_TX_SIGOPS_COST`
relay gate + `IsWitnessStandard` + `ValidateInputsStandardness` in
the script-verify path), W56 (truncated-OP_RETURN classified as
NONSTANDARD, not NULL_DATA), W129 (dust threshold per scriptPubKey).

## Summary

clearbit ships a working `checkStandard` in `src/mempool.zig:2774`
called from the mempool admission path
(`addTransactionInternal`/`acceptTransactionWithMessage`/
`acceptTransaction`).  The gate is **substantially complete and
mostly Core-aligned**: tx-version range, tx-weight ceiling,
non-witness-min-size, per-input scriptSig size and push-only,
per-input legacy-sigops and a conservative P2SH redeem-script
sigop pre-filter, per-output classifier with bare-multisig n-of-3
check, and per-output P2A zero-value enforcement all fire in the
right order.  Witness-standardness lives in
`src/mempool.zig:2383 checkWitnessStandard` (called from
`verifyInputScripts` rather than `checkStandard`, matching Core's
sequencing of `IsWitnessStandard` after prevouts are loaded).
`ValidateInputsStandardness` is implemented at
`src/mempool.zig:2516`.

The gaps are clustered in three areas:

1. **No GetDust / MAX_DUST_OUTPUTS_PER_TX gate at all.**
   Core's `IsStandardTx` calls `GetDust(tx, dust_relay_fee).size() >
   MAX_DUST_OUTPUTS_PER_TX` (policy/policy.cpp:159) which rejects
   any tx with more than 1 dust output (the lone-survivor is
   intended for ephemeral-anchor / TRUC use).  clearbit has
   `Mempool.isDust` (mempool.zig:3113) and calls it during the
   wallet-side TRUC sibling-eviction path (line 1324, 3899), but
   the `checkStandard` admission gate **never calls `isDust` and
   never enforces the per-tx dust cap**.  A standard 1.0-block
   broadcasting a tx with 1000 dust P2WPKH outputs would today be
   accepted into clearbit's mempool and relayed onward.  See
   BUG-1 + BUG-2.
2. **No `permit_bare_multisig` / `max_datacarrier_bytes` / `dust_relay_feerate`
   plumbing.**  Core's `IsStandardTx` is parameterised on three
   knobs: `max_datacarrier_bytes` (`-datacarriersize`),
   `permit_bare_multisig` (`-permitbaremultisig`),
   `dust_relay_fee` (`-dustrelayfee`).  Each maps to a CLI flag and
   ultimately to `CTxMemPool::Options`.  clearbit has none of
   these — the bare-multisig branch in `checkStandard` reads no
   config and is unconditionally accepted when `1 ≤ m ≤ n ≤ 3`;
   the datacarrier branch hard-codes `MAX_OP_RETURN_RELAY = 100000`;
   the dust threshold hard-codes `3 *(spend_size + output_size)`
   matching `DUST_RELAY_TX_FEE = 3000`.  This is fine on mainnet
   defaults but means operators cannot disable bare-multisig
   (which Knots node operators frequently do) or raise/lower
   `-datacarriersize` or `-dustrelayfee` from the CLI — and the
   eventual fix in (1) will inherit a hard-coded threshold.
   See BUG-3 + BUG-4 + BUG-5 + BUG-6.
3. **Solver/classifier shape diverges from Core's `Solver`.**
   clearbit's `classifyScript` (`src/script.zig:2393`) is a
   shape-matcher that does NOT call `MatchPayToPubkey` /
   `MatchPayToPubkeyHash` / `MatchMultisig` and does NOT have a
   `WITNESS_UNKNOWN` variant.  Consequences:
   - MULTISIG classification only checks the first byte and the
     two trailing bytes (`OP_m … OP_n OP_CHECKMULTISIG`) — it
     does NOT walk the pubkey list and verify `pubkeys.size() ==
     n` the way `MatchMultisig` does.  A malformed script like
     `OP_3 <key1> OP_3 OP_CHECKMULTISIG` (claims 3-of-3 but
     only has one key) is mis-classified as MULTISIG and reaches
     the `m ≤ n ≤ 3` bare-multisig branch where it passes.
     Bare-multisig with mismatched-pubkey-count would then be
     relayed.  See BUG-7.
   - `WITNESS_UNKNOWN` is folded into NONSTANDARD by
     `classifyScript`, which is correct for the policy decision
     (both reject) but breaks `ValidateInputsStandardness`'s
     ability to emit Core's distinct error string
     `"input %u witness program is undefined"`
     (policy/policy.cpp:239).  Cross-impl diff reporting will
     blur these two cases.  See BUG-8.
   - P2PK is classified via byte-pattern rather than
     `CPubKey::ValidSize` + `MatchPayToPubkey` — a 33-byte push
     starting with 0x00 or 0x05 (not 0x02/0x03/0x04/0x06/0x07)
     would today be accepted by clearbit as a standard P2PK
     output even though `CPubKey::ValidSize` would reject the
     uncompressed prefix and Core's classifier-side `MatchPayToPubkey`
     would also reject it.  See BUG-9.
4. **`checkStandard` does not invoke `isWitnessStandard`.** Core's
   `MemPoolAccept::PreChecks` calls `IsStandardTx` first then
   `IsWitnessStandard` separately (validation.cpp:808 + later);
   clearbit's `checkStandard` is only called from the admission
   path (mempool.zig:1042), but `checkWitnessStandard` is called
   from `verifyInputScripts` (mempool.zig:2611) which is *only*
   invoked when `self.chain_state` is set.  The single-tx
   unit-test path (chain_state=null) **skips witness-standardness
   entirely**.  In a CI run this manifests as: tests like
   `mempool.acceptTx(tx_with_oversized_p2wsh_witness_script)`
   that mock out chain state will silently accept non-standard
   txes that production would reject.  This is a TESTING /
   coverage gap, not a production miss.  See BUG-10.

The remaining BUGs are smaller (cosmetic error-code parity, missing
RBF interaction with bare-multisig, `IsStandard` parametric
multisig cap, MULTI_A gate absence).

| Verdict | Gates | Notes |
|---|---|---|
| PRESENT | 17 | Core-equal behavior + exercised call site (W70e/W71/W96 prior closures hold) |
| PARTIAL | 8 | Logic right but a side-channel (no CLI plumbing / no WITNESS_UNKNOWN variant / no MULTISIG keys-walk) is off |
| MISSING | 5 | Whole rule absent (no GetDust cap / no MULTI_A / no IsStandard params / no Solver-shape Solver / no permit_bare_multisig) |

**Bug count: 17** (P0-CONSENSUS=0 / P0-CDIV=0 / P0=2 / P1=4 / P2=8 /
P3=3).  No consensus-divergent findings: every bug is a relay-policy
divergence with no impact on the consensus rules a block would have
to follow.

The two P0s are:

- **P0/BUG-1**: no `GetDust` per-tx cap.  A relay node that does
  not enforce `MAX_DUST_OUTPUTS_PER_TX` propagates dust-flood
  packets out to peers, contradicting the protective intent of the
  policy and breaking parity with the rest of the fleet.  The
  underlying `isDust` helper exists, so the fix is small (one
  loop in `checkStandard`), but the gate is fully missing today.
- **P0/BUG-7**: `classifyScript` mis-classifies a malformed
  multisig as standard.  An attacker can broadcast
  `OP_3 <33-byte key> OP_3 OP_CHECKMULTISIG` (1 key, claims 3-of-3)
  and clearbit will treat it as a standard bare-multisig output;
  Core's `Solver` walks the pubkey list and rejects.  Outbound
  relay of unminable garbage scripts is the harm.

## Gates

### A. Version + size + weight (G1–G5)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G1 | `tx.version < TX_MIN_STANDARD_VERSION=1` → reject "version" | `policy/policy.cpp:102` | `mempool.zig:2776` (`tx.version < 1`) | PRESENT |
| G2 | `tx.version > TX_MAX_STANDARD_VERSION=3` → reject "version" | `policy/policy.cpp:102` + `truc_policy.h:20` | `mempool.zig:2776` (`tx.version > TRUC_VERSION`) | PRESENT |
| G3 | `GetTransactionWeight(tx) > MAX_STANDARD_TX_WEIGHT=400000` → reject "tx-size" | `policy/policy.cpp:111-115` | `mempool.zig:2796-2799` | PRESENT |
| G4 | Non-witness serialized size < `MIN_STANDARD_TX_NONWITNESS_SIZE=65` → reject "tx-size-small" (CVE-2017-12842) | `policy/policy.h:40` + `validation.cpp` | `mempool.zig:2807-2809` | PRESENT |
| G5 | CheckTransaction pre-gate runs before standardness (vin/vout non-empty, value range, dup inputs, coinbase length) | `consensus/tx_check.cpp:11-59` called via `validation.cpp` PreChecks | `validation.zig` `checkTransaction` called from `addTransactionInternal` via `acceptTransaction` (mempool.zig:1018-1040) | PRESENT |

### B. Per-input checks (G6–G10)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G6 | `scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE=1650` → reject "scriptsig-size" | `policy/policy.cpp:127-130` | `mempool.zig:2815-2817` | PRESENT |
| G7 | `!scriptSig.IsPushOnly()` → reject "scriptsig-not-pushonly" | `policy/policy.cpp:131-134` | `mempool.zig:2819-2821` | PRESENT |
| G8 | Per-input `subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS=15` → reject "p2sh redeemscript sigops exceed limit" | `policy/policy.cpp:254-258 ValidateInputsStandardness` | `mempool.zig:2530-2543 validateInputsStandardness` (correct, P2SH-only) + `mempool.zig:2864-2878 checkStandard` (conservative, P2SH-or-not) | PARTIAL — BUG-11 (duplicate gates, conservative one fires for non-P2SH inputs too) |
| G9 | Per-tx legacy sigops `> MAX_TX_LEGACY_SIGOPS=2500` → reject "non-witness sigops exceed bip54 limit" | `policy/policy.cpp:171-194 CheckSigopsBIP54` | `mempool.zig:2841-2844` (uses `getLegacySigOpCount` from validation.zig) | PARTIAL — BUG-12 (does not access prevout scriptPubKey sigops; Core's BIP-54 includes spent-output sigops) |
| G10 | Input scriptPubKey type after `Solver`: NONSTANDARD/WITNESS_UNKNOWN → reject "bad-txns-nonstandard-inputs" | `policy/policy.cpp:226-240 ValidateInputsStandardness` | `mempool.zig:2516-2545` (no WITNESS_UNKNOWN distinction) | PARTIAL — BUG-8 |

### C. Per-output checks (G11–G16)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G11 | `Solver(scriptPubKey) == NONSTANDARD` → reject "scriptpubkey" | `policy/policy.cpp:139-143` | `mempool.zig:2886` (uses `classifyScript`) | PARTIAL — BUG-7 (multisig misclassification) + BUG-9 (P2PK pubkey-shape unchecked) |
| G12 | `whichType == NULL_DATA` and `size > datacarrier_bytes_left` → reject "datacarrier" | `policy/policy.cpp:145-151` | `mempool.zig:2901-2906` (hard-coded MAX_OP_RETURN_RELAY=100000) | PARTIAL — BUG-4 (no `-datacarriersize` plumbing) |
| G13 | `whichType == MULTISIG && !permit_bare_multisig` → reject "bare-multisig" | `policy/policy.cpp:152-155` | `mempool.zig:2913-2921` (always permitted; n≤3 check only) | PARTIAL — BUG-3 (no `-permitbaremultisig` plumbing) |
| G14 | `IsStandard` MULTISIG branch: `1 ≤ m ≤ n ≤ 3` → standard | `policy/policy.cpp:80-95` | `mempool.zig:2913-2921` | PRESENT |
| G15 | `whichType == ANCHOR && txout.nValue != 0` → reject (anchor must be 0-value) | (Core treats anchor as standard regardless; clearbit added a stricter rule) | `mempool.zig:2891-2893 (AnchorNonZeroValue)` | PRESENT (stricter than Core; flagged BUG-13) |
| G16 | `GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX=1` → reject "dust" | `policy/policy.cpp:159-162` + `policy.cpp:71-78 GetDust` + `policy/policy.h:95` | NOT IMPLEMENTED — `checkStandard` never calls `isDust` | MISSING — BUG-1 + BUG-2 |

### D. Witness-standardness (G17–G22)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G17 | `IsWitnessStandard` runs after prevouts loaded; coinbase exempt | `policy/policy.cpp:265-352` | `mempool.zig:2383-2497 checkWitnessStandard` called from `verifyInputScripts` (2611) | PRESENT (but PARTIAL via BUG-10 — only runs when `chain_state != null`) |
| G18 | P2A prevout + any witness → reject (anti-stuffing) | `policy/policy.cpp:283-285` | `mempool.zig:2394-2397` | PRESENT |
| G19 | P2SH wrapper: extract redeemScript via EvalScript stack-top; empty stack → reject | `policy/policy.cpp:287-299` | `mempool.zig:2406-2418 + scriptSigTopPush` (mempool.zig:2300+) | PRESENT |
| G20 | P2WSH v0 32-byte: witnessScript ≤ 3600B; stack items (excl script) ≤ 100; each item ≤ 80B | `policy/policy.cpp:308-318` | `mempool.zig:2428-2449` | PRESENT |
| G21 | P2TR v1 32B (non-P2SH): annex tag 0x50 reject; tapscript leaf 0xc0 → items ≤ 80B; empty stack reject | `policy/policy.cpp:321-348` | `mempool.zig:2453-2490` | PRESENT |
| G22 | Non-witness-program prevout + non-empty witness → reject | `policy/policy.cpp:304-306` | `mempool.zig:2420-2424` | PRESENT |

### E. Solver / classifier shape (G23–G27)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G23 | `Solver` walks `MatchMultisig` and verifies `pubkeys.size() == n` and `req_sigs ≤ n` | `script/solver.cpp:85-105 MatchMultisig` | `script.zig:2496-2503 classifyScript` (only checks first + last-2 bytes) | PARTIAL — BUG-7 (mis-classifies malformed multisig) |
| G24 | `Solver` returns `WITNESS_UNKNOWN` for valid-shape witness programs of unknown version (2-16) | `script/solver.cpp:172-176` | `script.zig:2509-2533 isWitnessProgram` returns the program but `classifyScript` returns `nonstandard` for any non-{0,1} version | PARTIAL — BUG-8 (collapses WITNESS_UNKNOWN into NONSTANDARD) |
| G25 | `Solver` calls `MatchPayToPubkey` which checks `CPubKey::ValidSize` (size 33 OR 65) AND first byte ∈ {0x02,0x03} (compressed) or {0x04,0x06,0x07} (uncompressed) | `script/solver.cpp:36-47 MatchPayToPubkey` + `pubkey.h ValidSize`/`ValidPrefix` | `script.zig:2433-2438` — only checks length + last-byte-OP_CHECKSIG + push-prefix; does NOT call any pubkey-prefix validator | MISSING — BUG-9 |
| G26 | `Solver` recognises `MULTI_A` (Tapscript-style aggregated multisig: `<key> CHECKSIG (<key> CHECKSIGADD)* <k> NUMEQUAL`) and returns it as a valid scriptPubKey type for output classification (`MatchMultiA`) | `script/solver.cpp:107-139 MatchMultiA` + `solver.h MAX_PUBKEYS_PER_MULTI_A` | NOT IMPLEMENTED — `classifyScript` has no MULTI_A branch | MISSING — BUG-14 |
| G27 | `Solver` returns one of `{NONSTANDARD, ANCHOR, PUBKEY, PUBKEYHASH, SCRIPTHASH, MULTISIG, NULL_DATA, WITNESS_V0_SCRIPTHASH, WITNESS_V0_KEYHASH, WITNESS_V1_TAPROOT, WITNESS_UNKNOWN}` — 11 TxoutTypes total | `script/solver.h:22-35 TxoutType` | `script.zig:2370-2381 ScriptType` — 10 variants, missing `WITNESS_UNKNOWN` (folds into `nonstandard`); also no MULTI_A awareness | MISSING — BUG-8 + BUG-14 (variant set under-populated) |

### F. CLI plumbing / config / RBF interaction (G28–G30)

| Gate | Topic | Core ref | clearbit ref | Status |
|---|---|---|---|---|
| G28 | `-permitbaremultisig` plumbed into `CTxMemPool::Options.permit_bare_multisig`, default true | `policy/policy.h:52 DEFAULT_PERMIT_BAREMULTISIG` + `kernel/mempool_options.h:54` + `init.cpp` arg-parser | NOT IMPLEMENTED — no `config.permitbaremultisig`; `mempool.zig:2913-2921` does not consult any flag | MISSING — BUG-3 |
| G29 | `-datacarriersize=N` raises/lowers `max_datacarrier_bytes`; `-datacarrier=0` disables datacarrier entirely | `policy/policy.h:80 DEFAULT_ACCEPT_DATACARRIER` + `kernel/mempool_options.h:53` + `init.cpp` arg-parser | NOT IMPLEMENTED — hard-coded `MAX_OP_RETURN_RELAY` constant | MISSING — BUG-4 |
| G30 | `-dustrelayfee=N` plumbed into `dust_relay_fee` and feeds `GetDustThreshold`; default 3000 sat/kvB | `policy/policy.h:68 DUST_RELAY_TX_FEE` + `kernel/mempool_options.h dust_relay_feerate` + `init.cpp` arg-parser | NOT IMPLEMENTED — hard-coded multiplier `3 *(spend_size + output_size)` matches the default | MISSING — BUG-5 (BUG-6 covers wallet-side `discardrelayfee` parallel) |

## Bugs

### P0 — material relay-policy divergence

#### BUG-1 (P0): no `MAX_DUST_OUTPUTS_PER_TX` gate; relays dust-floods

clearbit's `Mempool.checkStandard` (mempool.zig:2774) implements all
the per-input and per-output checks Core does, except the one that
caps the number of dust outputs per transaction.  Core's
`IsStandardTx` (policy/policy.cpp:159):

```cpp
// Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
    reason = "dust";
    return false;
}
```

with `MAX_DUST_OUTPUTS_PER_TX = 1` (policy/policy.h:95).  This is
the lone-survivor anchor-pattern: at most ONE dust output is
allowed per tx, and only when it's an ephemeral-anchor-style
output that will be spent immediately.

clearbit has the lower-level primitive `Mempool.isDust`
(mempool.zig:3113) and uses it during RBF / TRUC sibling-eviction
calculations (mempool.zig:1324, 3899), but `checkStandard` never
calls it and the per-tx cap is never enforced.  Concrete attack
shape: a malicious peer broadcasts a 100-output P2WPKH tx where
every output is below `dust_threshold` ≈ 294 sat (default rate).
Core nodes reject this with "dust"; clearbit nodes accept and
relay it onward.

**Fix sketch (out of scope for W135):** after the per-output loop in
`checkStandard`, iterate outputs again and count dust outputs (use
the existing `isDust`); reject if `count > MAX_DUST_OUTPUTS_PER_TX`.

#### BUG-2 (P0): `MAX_DUST_OUTPUTS_PER_TX` constant absent from `mempool.zig`

Companion to BUG-1: the constant itself is missing, so even if a
caller wanted to query the gate (e.g. for an RPC like `testmempoolaccept`)
it cannot.  `policy/policy.h:95` defines
`MAX_DUST_OUTPUTS_PER_TX = 1`.  clearbit has no analog.

#### BUG-7 (P0): `classifyScript` mis-classifies malformed MULTISIG

`classifyScript` (`src/script.zig:2496-2502`) only checks
`script[0] ∈ [OP_1, OP_16]` and `script[len-2] ∈ [OP_1, OP_16]` and
`script[len-1] == OP_CHECKMULTISIG`.  It does NOT walk the
intermediate bytes to verify they are valid pubkey pushes nor that
the count of pubkeys equals `n`.  Core's `MatchMultisig`
(script/solver.cpp:85-105) walks the script with `GetOp` and
explicitly checks `pubkeys.size() == *num_keys`.

Concrete vector: `script = [0x53, 0x21, <33-byte key>, 0x53, 0xae]`
(`OP_3 <key1> OP_3 OP_CHECKMULTISIG`) has 1 pubkey but claims
3-of-3.  Core's `Solver` returns `NONSTANDARD`; clearbit's
`classifyScript` returns `MULTISIG` and the bare-multisig branch
in `checkStandard` accepts it because `m=3, n=3, 1≤m≤n≤3`.  Output
is relayed but unminable.

### P1 — single-feature parity gaps

#### BUG-3 (P1): no `-permitbaremultisig` flag plumbing

Core's `IsStandardTx` takes `permit_bare_multisig` as a parameter,
sourced from `CTxMemPool::Options::permit_bare_multisig` populated
from `gArgs.GetBoolArg("-permitbaremultisig", ...)` at startup
(init.cpp).  clearbit unconditionally permits bare-multisig: there
is no `config.permitbaremultisig`, no CLI flag in `main.zig`, no
mempool option, and `checkStandard` does not consult any boolean
before the bare-multisig n≤3 branch.

Operators (notably Bitcoin Knots users) commonly run with
`-permitbaremultisig=0` to discourage bare-multisig as inscription
vector.  clearbit cannot run that configuration.

#### BUG-4 (P1): no `-datacarriersize` flag plumbing

Core's `max_datacarrier_bytes` (an `std::optional<unsigned>`) is
sourced from `-datacarrier` (default true) + `-datacarriersize`
(default MAX_OP_RETURN_RELAY=100000).  When `-datacarrier=0` the
optional is `nullopt` and OP_RETURN outputs are NONSTANDARD.

clearbit hard-codes `MAX_OP_RETURN_RELAY` at
`consensus.MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR` and has
no way to disable datacarrier entirely.  No `config.datacarrier`,
no `config.datacarriersize`, no `mempool_options.max_datacarrier_bytes`.

#### BUG-5 (P1): no `-dustrelayfee` flag plumbing

`Mempool.isDust` (mempool.zig:3113) uses a hard-coded
`3 * (spend_size + output_size)` which matches Core's
`DUST_RELAY_TX_FEE = 3000 sat/kvB` × `nSize / 1000`.  But Core
takes `dust_relay_fee` as a parameter (`CFeeRate`) and uses
`dustRelayFeeIn.GetFee(nSize)` so operators can raise/lower the
threshold via `-dustrelayfee=N`.  clearbit's threshold is frozen.
Downstream once BUG-1 is fixed, the cap will also be frozen at
the default 294 sat / 546 sat thresholds.

#### BUG-6 (P1): `Mempool.isDust` per-script-type spend_size table is approximate

The table at mempool.zig:3128-3136 uses fixed integer constants
(148/91/68/108/58/114) instead of computing `GetSerializeSize(txout) +
(prevout-input-size with witness discount applied)` the way Core
does in `GetDustThreshold` (policy/policy.cpp:46-61).  In
particular:

- Core treats every witness program (`IsWitnessProgram`) with the
  same `(32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4) = 67.75`
  formula — clearbit hard-codes 68 (P2WPKH) and 108 (P2WSH) and 58
  (P2TR), which is 3 different numbers where Core has one.
- The Core 107-byte witness item is fixed (it's the budget for the
  largest segwit-v0 minimum-spending input "33-byte pubkey + ECDSA
  signature"); using different per-output-type constants is an
  approximation that diverges for unusual witness programs.

This is fine for the common case but diverges from Core's algebraic
threshold by 10-50 sat per output at the default rate.

### P2 — observable but smaller

#### BUG-8 (P2): no `WITNESS_UNKNOWN` TxoutType variant

`ScriptType` (script.zig:2370-2381) has 10 variants; Core's
`TxoutType` has 11.  Witness programs with versions 2-16 fold into
`nonstandard` in clearbit, whereas Core distinguishes
`WITNESS_UNKNOWN` for them.  Consequences:

- `ValidateInputsStandardness` in clearbit cannot emit the
  Core-equivalent "input %u witness program is undefined" error
  string (policy/policy.cpp:239) — it emits the generic
  "input %u script unknown" path.  Cross-impl error-code parity
  (W125) regresses one line.
- A future "discourage upgradable witness program" P2P/RPC layer
  cannot distinguish "unknown future witness version" from "garbage
  scriptPubKey".

#### BUG-9 (P2): P2PK classifier accepts invalid pubkey prefixes

`classifyScript` for P2PK (script.zig:2433-2438) accepts any
33-byte push followed by `OP_CHECKSIG` (`script[0] == 0x21`) and
any 65-byte push followed by `OP_CHECKSIG` (`script[0] == 0x41`).
Core's `MatchPayToPubkey` additionally calls `CPubKey::ValidSize`
which routes to `CPubKey::ValidLength(GetLen(prefix))` that returns
0 for prefixes outside {0x02, 0x03, 0x04, 0x06, 0x07}.  A 33-byte
push with prefix 0x00 followed by OP_CHECKSIG would be standard in
clearbit but NONSTANDARD in Core.

#### BUG-10 (P2): `checkWitnessStandard` skipped when `chain_state == null`

`Mempool.verifyInputScripts` (mempool.zig:2547-2741) starts with:

```zig
const cs = self.chain_state orelse return;
```

so when chain_state is unset (unit-test path with mocked mempool)
the entire script-verification block — including
`checkWitnessStandard` and `validateInputsStandardness` — is
skipped.  Production has `chain_state` set so this is a
TESTING-MODE-ONLY gap; production parity is intact.

#### BUG-11 (P2): per-input P2SH sigops check fires for non-P2SH inputs

`checkStandard` (mempool.zig:2864-2878) runs the P2SH redeemScript
sigop check on EVERY input (regardless of whether the prevout is
actually P2SH), using a `dummy_p2sh` scriptPubKey to force the
P2SH branch in `getP2SHSigOpCount`.  The comment acknowledges this
is "conservative" — the actual P2SH-only enforcement runs in
`validateInputsStandardness` (mempool.zig:2530-2543).  In practice
the conservative check is harmless (legitimate non-P2SH inputs
have 0 sigops in the last push), but it diverges from Core which
only runs the check when `Solver(prevout) == SCRIPTHASH`
(policy/policy.cpp:241).

#### BUG-12 (P2): BIP-54 sigops accounting omits spent scriptPubKey sigops

Core's `CheckSigopsBIP54` (policy/policy.cpp:170-194) sums
`scriptSig.GetSigOpCount(true) + prev_txo.scriptPubKey.GetSigOpCount(scriptSig)`
per input.  The second term — sigops in the SPENT scriptPubKey —
is what makes BIP-54 a "where they execute" rather than "where they
sit" accounting.

clearbit (mempool.zig:2841-2844) uses
`validation.getLegacySigOpCount(tx)` which sums sigops in tx's own
scriptSigs and scriptPubKeys but NOT in the spent scriptPubKey
(no UTXO access available in `checkStandard`).  Net effect: a tx
that spends a P2PKH prevout (1 sigop in the spent scriptPubKey)
+ has 2499 sigops in its own scriptSig will pass clearbit's gate
at 2499 but Core's gate at 2499+1=2500 (still within the limit) —
inverse direction would fail in Core but pass in clearbit at
2500-N inputs of 2500-N sigops.  Small divergence at the boundary.

#### BUG-13 (P2): anchor-with-nonzero-value is stricter than Core

`checkStandard` (mempool.zig:2891-2893) rejects any output where
`stype == .anchor and value != 0` with `AnchorNonZeroValue`.  Core
treats ANCHOR (P2A) as a standard scriptPubKey type and does NOT
enforce a zero-value constraint at `IsStandardTx` time —
ephemeral-policy handles the cap differently.  This is a stricter-
than-Core relay decision: clearbit will refuse to relay
`OP_1 0x4e73` outputs with non-zero value that Core would relay.
Minor in practice (P2A outputs are conventionally zero-value), but
it's an over-rejection.

#### BUG-14 (P2): no `MULTI_A` (tapscript multisig) classifier

`classifyScript` has no MULTI_A branch.  Core's `MatchMultiA`
(script/solver.cpp:107-139) recognises the tapscript multisig
pattern `<key> CHECKSIG (<key> CHECKSIGADD)*N <k> NUMEQUAL` which
becomes the standard MULTISIG-equivalent for tapscript spending
paths.  Affects RPC `decodescript` / `getrawtransaction` output
shape rather than `IsStandardTx` decisions per se (MULTI_A is a
tapscript-internal classification, not an output-script classifier
result), but the scaffold is missing.

#### BUG-15 (P2): no MAX_PUBKEYS_PER_MULTI_A constant

`script.zig` defines `MAX_PUBKEYS_PER_MULTISIG = 20` but no analog
for MULTI_A (`MAX_PUBKEYS_PER_MULTI_A = 999` in
script/solver.h).  Companion to BUG-14.

#### BUG-16 (P2): `IsStandard` MULTISIG cap parameterised by Core (`< 1 || > 3`) but `m == 0` only catches in `m > n`

`classifyScript` returns `multisig` when `script[0] >= 0x51`
(i.e. m ≥ 1) so the `m == 0` case (which would be `OP_0 …` →
`script[0] == 0x00`) is already filtered out before
`checkStandard` looks at m/n.  Net: `m < 1` cannot fire in
clearbit because the classifier already rejected it.  Core's
explicit `m < 1` check (policy/policy.cpp:93) is defence-in-depth;
clearbit relies on the classifier to filter.  No bug, but the
defence-in-depth posture is weaker.  Logged as a P2 because
re-classifying via a future `Solver` rewrite could regress.

### P3 — cosmetic / parity-only

#### BUG-17 (P3): reject reason strings diverge from Core's

clearbit's `checkStandard` returns `MempoolError.*` enum variants;
RPC layer (mempool.zig:1505-1520, 1554-1570) translates a few of
them ("datacarrier", "bare-multisig", "tx-size", etc.) but not all
of Core's `IsStandardTx` reasons: "version", "scriptpubkey",
"scriptsig-size", "scriptsig-not-pushonly", "dust" are all bundled
into the catch-all `NonStandard`/`TxValidationFailed` reason
strings.  Cross-impl `testmempoolaccept` diffs (W125 scope) will
show these as divergences.

## Forward path

For W135-related fix waves the priority is:

1. **FIX-P0/dust-cap (BUG-1, BUG-2):** add `MAX_DUST_OUTPUTS_PER_TX`
   constant + per-tx dust-count gate in `checkStandard` after the
   per-output loop.  Use existing `isDust` helper; about 8 lines
   of code.  Test against Core's `feature_dust.py` vector.
2. **FIX-P0/multisig-classify (BUG-7):** add `MatchMultisig`-style
   walk to `classifyScript` (or split into a real `Solver`
   function) so malformed bare-multisig scripts are rejected.
3. **FIX-P1/CLI-plumbing (BUG-3, BUG-4, BUG-5):** add three CLI
   flags + three mempool options + thread them through
   `checkStandard` and `isDust`.  Lockstep with parity-table item
   in `consensus-monitor.sh` if other impls' defaults differ.
4. Remaining P2s are coverage / parity work for cross-impl diff
   (W125) — schedule per-quarter.

No FIX wave dispatched yet; W135 is discovery-only.
