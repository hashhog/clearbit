# W144 — Script-verify flag mux audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's per-height script-verify flag derivation (`getBlockScriptFlags`,
`getBlockScriptFlagsForHash`, `getStandardScriptFlags`, `getStandardScriptFlagsForHash`),
the application of those flags inside the script interpreter
(`ScriptEngine.verify` and opcode handlers), and the buried-deployment +
exception-block plumbing for BIP-16, BIP-66, BIP-65, BIP-112, BIP-141, BIP-147,
BIP-341/342.

**Bitcoin Core references:**
- `bitcoin-core/src/validation.cpp::GetBlockScriptFlags` @ 2250-2289
  (P2SH+WITNESS+TAPROOT unconditional base, DERSIG/CLTV/CSV/NULLDUMMY gated)
- `bitcoin-core/src/validation.cpp::ConnectBlock` @ 2480-2486 (BIP-68 enforcement
  gate + flags pull-down) and 2611-2614 (`bad-cb-amount`)
- `bitcoin-core/src/validation.cpp::ContextualCheckBlockHeader` @ 4080-4121
  (`bad-version` v<2/3/4 + `DeploymentActiveAfter` HEIGHTINCB / DERSIG / CLTV)
- `bitcoin-core/src/policy/policy.h:105-135` (`MANDATORY_SCRIPT_VERIFY_FLAGS`
  vs `STANDARD_SCRIPT_VERIFY_FLAGS` vs `STANDARD_NOT_MANDATORY_VERIFY_FLAGS`)
- `bitcoin-core/src/script/interpreter.h:47-159` (`SCRIPT_VERIFY_*` enum,
  `MAX_SCRIPT_VERIFY_FLAGS_BITS`)
- `bitcoin-core/src/script/interpreter.cpp::EvalScript` @ 472-602
  (flag-gated OP_CHECKLOCKTIMEVERIFY @ 522-559, OP_CHECKSEQUENCEVERIFY @ 561-593,
  OP_NOP1/4-10 + DISCOURAGE @ 595-601; `OP_CODESEPARATOR` /
  `SCRIPT_VERIFY_CONST_SCRIPTCODE` @ 474-476)
- `bitcoin-core/src/script/interpreter.cpp::VerifyWitnessProgram` @ 1917-2000,
  `VerifyScript` @ 2002-2090 (`SCRIPT_VERIFY_WITNESS` gate, NULLDUMMY gate)
- `bitcoin-core/src/deploymentstatus.h::DeploymentActiveAt` @ 27-37
- `bitcoin-core/src/consensus/params.h` `BuriedDeployment` enum @ 25-35,
  `Params::DeploymentHeight()` @ 142-156
- `bitcoin-core/src/kernel/chainparams.cpp` mainnet @ 85-94, testnet3 @ 210-217
  (`script_flag_exceptions.emplace(...BIP16/Taproot exception...)`)

**BIPs:** BIP-16 (P2SH), BIP-65 (CLTV), BIP-66 (DERSIG), BIP-68/112/113 (CSV),
BIP-141 (witness), BIP-143 (segwit-v0 sighash), BIP-147 (NULLDUMMY),
BIP-341/342 (Taproot/Tapscript).

**Mode:** DISCOVERY (no production code changes; this audit catalogues
parity bugs only).

**Implementation files audited:**
- `clearbit/src/validation.zig`
  - `BIP16_EXCEPTION_HASH` / `TAPROOT_EXCEPTION_HASH` @ 97-110 (only TWO entries)
  - `getBlockScriptFlags` @ 137-139, `getBlockScriptFlagsForHash` @ 144-208
    (consensus flag derivation)
  - `getStandardScriptFlags` @ 232-234, `getStandardScriptFlagsForHash` @ 240-276
    (policy flag layering)
  - `checkTransactionContextual` @ 368-454 (DEAD HELPER; uses raw
    `script.ScriptFlags{}` defaults that include policy-strict behaviour)
  - `getTransactionSigOpCost` @ 540-569 (flag-aware P2SH + witness sigops)
  - `verifyBlockScriptsParallel` @ 2598-2717 (consensus dispatch — calls the
    NO-HASH variant @ 2606)
  - `verifyBlockScriptsSingleThreaded` @ 2719-2770
  - `verifyScriptJob` @ 2488-2587 (per-input script-engine driver in the
    worker pool)
  - `connectBlock` (legacy path) @ 879-1000 (calls the NO-HASH variant @ 889)
- `clearbit/src/script.zig`
  - `ScriptFlags` packed struct @ 183-212 (21 fields; defaults bake in
    POLICY-strictness)
  - `ScriptEngine.init` @ 668-704, `verify` @ 884-1300
  - `op_checklocktimeverify` @ 1944-1979, `op_checksequenceverify` @ 1981-2024
    (Core-divergent DISCOURAGE_UPGRADABLE_NOPS firing path)
  - `op_nop1/4-10` @ 1391-1396 (correct DISCOURAGE_UPGRADABLE_NOPS gate)
  - `verify_const_scriptcode` callsite @ 848-853 (sig_version-gated)
  - `executeCheckMultisig` @ 2080-2200 (NULLDUMMY gate @ 2110-2113)
- `clearbit/src/consensus.zig`
  - `NetworkParams.taproot_height` @ 372 + per-network values @ 504, 621, 675,
    726, 775 (`taproot_height` is defined and populated but NOT consulted by
    `getBlockScriptFlagsForHash` — dead config for script-flag derivation)
- `clearbit/src/test_script.zig`
  - `parseFlags` @ 275-342 (silently DROPS `MINIMALIF` and `CONST_SCRIPTCODE`
    from the Core test-vector flag set — divergent test interpretation)

## Summary

clearbit's script-verify flag system is in a much better shape than the
fleet baseline — `getBlockScriptFlagsForHash` correctly applies the
Core-style "P2SH + WITNESS + TAPROOT unconditional, DERSIG / CLTV / CSV /
NULLDUMMY height-gated" base set, and the policy-only layering in
`getStandardScriptFlagsForHash` matches Core's `STANDARD_SCRIPT_VERIFY_FLAGS`
shape. However, the wave brief's 8 behaviors and the 3 meta-checks surface
**multiple consensus-divergent gaps**:

1. **DISCOURAGE_UPGRADABLE_NOPS fires inside OP_CHECKLOCKTIMEVERIFY /
   OP_CHECKSEQUENCEVERIFY** when the corresponding verify flag is off. Core
   *deliberately* does not run that check for OP_CLTV/CSV — only for
   OP_NOP1, OP_NOP4-10. Result: a pre-BIP-65 block (height < 388,381) where
   a tx contains OP_CHECKLOCKTIMEVERIFY would be treated as NOP by Core but
   would be a hard reject by clearbit *if the relay path's policy flags
   ever leak into a consensus call* (which today is impossible only because
   `getBlockScriptFlagsForHash` explicitly sets
   `discourage_upgradable_nops = false`; but the script engine itself
   carries the bug regardless of caller). The
   `checkTransactionContextual` dead helper (point 4 below) is exactly the
   path that ships defaults that include this firing pattern. **BUG-W144-1**.

2. **`verifyBlockScriptsParallel` calls `getBlockScriptFlags(height, params)`
   without the block hash** at validation.zig:2606. The block-hash variant
   (`getBlockScriptFlagsForHash`) is what applies the BIP-16 / Taproot
   exception overrides — so on the consensus path, the two exception
   blocks would be REJECTED if they happened to be re-verified through the
   parallel pool (mainnet h=170,060 BIP-16 violator and h=692,201 Taproot
   violator both fail consensus-strict flags). The IBD entry point
   `validateBlockForIBD` correctly calls the `*ForHash` variant at line
   1489, but anything routed through `connectBlock` (line 889) or the
   parallel pool (line 2606) does NOT apply the exception list. The
   exception machinery exists, is correctly defined, and is wired into
   exactly ONE of three consensus entry points. **BUG-W144-2**, the
   classic two-pipeline-guard fleet pattern.

3. **testnet3 BIP-16 exception block missing**: clearbit's exception
   table at validation.zig:97-110 contains only the mainnet two
   exceptions; Core's `kernel/chainparams.cpp:210-211` adds the testnet3
   BIP-16 exception `00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105`.
   On testnet3, the IBD validator would reject the BIP-16 violator block
   (it would now fail strict P2SH). **BUG-W144-3** P0-CDIV testnet3.

4. **`checkTransactionContextual` is a dead-helper-with-the-wrong-defaults**:
   declared at validation.zig:368 (88 LOC, the only real callsite is a
   comment from mempool.zig:2565 pointing back to it). When the engine is
   created at line 421-429 it uses `script.ScriptFlags{}` — the
   defaults include `verify_low_s = true`, `verify_clean_stack = true`,
   `verify_nullfail = true`, `verify_minimaldata = true`,
   `verify_witness_pubkeytype = true`, all of which are POLICY-only in
   Core (per `policy.h:105-132`). Should a caller ever start using this
   helper for consensus, it would reject ANY transaction Core's
   `MANDATORY_SCRIPT_VERIFY_FLAGS` would accept. **BUG-W144-4** P0-CDIV
   (latent — gated only by no production caller).

5. **`ScriptFlags` default struct bakes in POLICY semantics**: of 21
   fields, the 5 listed in (4) plus `verify_p2sh`, `verify_witness`,
   `verify_taproot`, `verify_nulldummy`, `verify_dersig`,
   `verify_checklocktimeverify`, `verify_checksequenceverify` all default
   to true. The MANDATORY set is the 7 right-most; the others belong in
   STANDARD_NOT_MANDATORY. Defaulting them to true is an attractive-nuisance
   waiting for the next "drop-in" caller. **BUG-W144-5** P1.

6. **`taproot_height` is dead config for script-flag derivation**: defined
   in `NetworkParams` at consensus.zig:372 with mainnet=709632, testnet3=
   2032291, testnet4=1, etc., but `getBlockScriptFlagsForHash` (line
   137-208) never reads it — `verify_taproot` is set unconditionally to
   true (line 158). The only consumers are RPC (rpc.zig:3289) and tests.
   This matches Core's "Taproot is always on with exception list" pattern,
   so the *behavior* is correct, but the field gives a misleading
   impression of activation gating that does not exist. **BUG-W144-6** P2.

7. **`SCRIPT_VERIFY_CONST_SCRIPTCODE` policy flag is dead-on-init**:
   `ScriptFlags.verify_const_scriptcode` defaults to false (line 201,
   *correct*) and is wired only on the policy-layering path
   (validation.zig:256). But the actual call-site at script.zig:848-853
   uses `self.sig_version == .base` — meaning it fires correctly only on
   legacy scripts. The downside: clearbit DOES set this flag in
   `getStandardScriptFlagsForHash` (line 256), but it has no test coverage
   for the OP_CODESEPARATOR-in-witness-v0 case (which Core *deliberately
   permits*). Not a divergence per se; flagged because the comment at
   line 843-847 mentions Core's gate but the assertion is impossible to
   exercise without a corpus test. **BUG-W144-7** P3.

8. **`test_script.zig::parseFlags` silently drops `MINIMALIF` and
   `CONST_SCRIPTCODE`**: the test-vector parser at line 275-342 maps every
   known Core flag string to a ScriptFlags bit, except these two — they're
   silently ignored (line 338-339 comment confirms). This means any Core
   test vector that exercises MINIMALIF or CONST_SCRIPTCODE flag-on
   behavior is run by clearbit with those flags OFF, masking false
   positives. **BUG-W144-8** P1 test-corpus.

9. **`getBlockScriptFlagsForHash` lacks SignetChallenge / regtest knob
   wiring**: signet and regtest both have `segwit_height` / `csv_height`
   that map to `0` or `1`. clearbit's code at lines 161-164 uses
   `height >= params.*_height` which works for both. But Core's regtest
   `-vbparams=` knob (kernel/chainparams.cpp:572-584) can override these
   at runtime — clearbit has no analog. Critical only for downstream
   regtest fork testing. **BUG-W144-9** P2.

10. **DISCOURAGE_UPGRADABLE_TAPROOT_VERSION error-attribution drift on
    Taproot-via-P2SH**: at script.zig:1273-1283, when `verify_taproot` is
    on and we hit Taproot-via-P2SH (which falls through here due to the
    `!via_p2sh` gate at line 1078), the discourage flag triggers
    `WitnessProgramMismatch` instead of Core's
    `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`. Wire-level same
    reject; error-attribution diff. **BUG-W144-10** P3.

This wave catalogues **18 BUGs** across the 8 wave-brief behaviors plus the
3 meta-checks. None are fixed; the goal here is parity-bug discovery for
the campaign tally.

---

## BUG-W144-1 — OP_CHECKLOCKTIMEVERIFY/CSV fire DISCOURAGE_UPGRADABLE_NOPS when flag is off

**Severity:** P0-CDIV (latent for consensus; immediate on STANDARD path)

**File:** `clearbit/src/script.zig:1946-1950, 1982-1986`
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:522-526` (CLTV),
`561-565` (CSV), `595-601` (NOP1/4-10 — the *only* opcodes Core
discourages)

**Description.** Core's `EvalScript` handles OP_CHECKLOCKTIMEVERIFY and
OP_CHECKSEQUENCEVERIFY with an early `break;` when their corresponding
`SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` / `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY`
flag is OFF — explicitly "treat as a NOP2/NOP3". The
`DISCOURAGE_UPGRADABLE_NOPS` check fires in a *separate* `case` arm at
interpreter.cpp:595-601 that only matches `OP_NOP1, OP_NOP4 ... OP_NOP10`.
This is intentional: CLTV and CSV have *defined* soft-fork semantics, so
they should not be discouraged when running pre-activation. clearbit's
`op_checklocktimeverify` at script.zig:1946-1950 fires
`DiscourageUpgradableNops` when both `!verify_checklocktimeverify` AND
`discourage_upgradable_nops` are set; same pattern at 1982-1986 for CSV.

**Excerpt:**
```zig
.op_checklocktimeverify => {
    if (!self.flags.verify_checklocktimeverify) {
        if (self.flags.discourage_upgradable_nops) {
            return ScriptError.DiscourageUpgradableNops;     // ← divergent
        }
        return; // NOP behavior
    }
    ...
},
.op_checksequenceverify => {
    if (!self.flags.verify_checksequenceverify) {
        if (self.flags.discourage_upgradable_nops) {
            return ScriptError.DiscourageUpgradableNops;     // ← divergent
        }
        return; // NOP behavior
    }
    ...
},
```

**Impact.** On the policy (relay/mempool) path —
`getStandardScriptFlagsForHash` sets both `verify_checklocktimeverify =
true` and `discourage_upgradable_nops = true` (line 257) post-BIP-65 —
the bug is latent (CLTV flag is always on). BUT: any test corpus that
runs with `DISCOURAGE_UPGRADABLE_NOPS` on and CLTV flag off (e.g. a unit
test that constructs a CLTV scriptSig and checks pre-activation behavior)
would emit `DiscourageUpgradableNops` where Core emits success. The
consensus path is safe because
`getBlockScriptFlagsForHash` always sets `discourage_upgradable_nops =
false` (line 195). Still, the script engine itself carries an
incorrect behaviour gated only by caller-side flag manipulation. P0 if
ever combined with a different caller; P1 for the test corpus.

---

## BUG-W144-2 — `verifyBlockScriptsParallel` ignores block hash → exception-list bypass on the parallel consensus path

**Severity:** P0-CDIV

**File:** `clearbit/src/validation.zig:2606`
**Core ref:** `bitcoin-core/src/validation.cpp:2262-2266` (the
exception-list lookup in `GetBlockScriptFlags`)

**Description.** clearbit's `getBlockScriptFlagsForHash` correctly
implements Core's `script_flag_exceptions` map: when validating the
mainnet BIP-16 violator block `00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22`
(h≈170,060), it disables P2SH+WITNESS+TAPROOT+NULLDUMMY; for the
Taproot violator block
`0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`
(h≈692,201), it disables TAPROOT. The IBD fast path uses this:

```zig
const flags = getBlockScriptFlagsForHash(height, params, &ctx.block_hash);  // line 1489
```

But the parallel-verification entry point at line 2606 uses the
NO-HASH variant:

```zig
pub fn verifyBlockScriptsParallel(
    block: *const types.Block,
    height: u32,
    params: *const consensus.NetworkParams,
    ...
) ValidationError!bool {
    const flags = getBlockScriptFlags(height, params);     // ← no block_hash
    ...
}
```

`getBlockScriptFlags(height, params)` is defined at lines 137-139 as
`getBlockScriptFlagsForHash(height, params, null)`, and that null
short-circuits the exception override (line 172: `if (block_hash) |bh|
{ ... }`). So when the parallel pool is dispatched, the exception
overrides do NOT apply — and the two violator blocks become hard-rejects
because their canonical (script-strict) reverification fails P2SH /
Taproot rules.

**Excerpt (validation.zig:2598-2606):**
```zig
pub fn verifyBlockScriptsParallel(
    block: *const types.Block,
    height: u32,
    params: *const consensus.NetworkParams,
    utxo_lookup: *const SigopUtxoView,
    config: ParallelVerifyConfig,
    allocator: std.mem.Allocator,
) ValidationError!bool {
    const flags = getBlockScriptFlags(height, params);     // ← null hash
```

And the legacy path at line 889:

```zig
pub fn connectBlock(...) ValidationError!i64 {
    const flags = getBlockScriptFlags(height, params);     // ← null hash
```

**Impact.** On a fresh IBD where the parallel pool drives validation,
mainnet block 170,060 and ~692,201 are HARD-REJECTED →
fork-from-genesis stuck at one of the two exception heights. The IBD
fast path bypasses this because it carries the hash, but if any caller
ever routes through `verifyBlockScriptsParallel` (e.g. block-template
validation, RPC `submitblock`, or any external test harness that goes
through `connectBlock`), the chain stops at the first violator block.
Classic two-pipeline-guard divergence: the *fix is already implemented*
inside `getBlockScriptFlagsForHash`, it's just not wired into one of
three callers.

---

## BUG-W144-3 — testnet3 BIP-16 exception block missing

**Severity:** P0-CDIV testnet3

**File:** `clearbit/src/validation.zig:97-110` (exception hash constants),
`clearbit/src/validation.zig:172-183` (exception-table lookup)
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:210-211`

**Description.** Core's testnet3 chain params register the BIP-16
exception block at testnet height ~76,879:

```cpp
consensus.script_flag_exceptions.emplace( // BIP16 exception
    uint256{"00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"},
    SCRIPT_VERIFY_NONE);
```

clearbit's exception table at validation.zig:97-110 has *only* the two
mainnet exception hashes:

```zig
pub const BIP16_EXCEPTION_HASH: types.Hash256 = consensus.hexToHash(
    "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22",
);
pub const TAPROOT_EXCEPTION_HASH: types.Hash256 = consensus.hexToHash(
    "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad",
);
```

There is NO entry for testnet3's
`00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105`, and
the table-driven `getBlockScriptFlagsForHash` at lines 172-183 cannot
match it.

**Impact.** Any testnet3 IBD past that block fails strict P2SH on a
block Core ships as a known exception. clearbit's testnet3 chain
diverges from Core's at h~76,879. (Side-note: even if BUG-W144-2 is
fixed and the block hash is plumbed, the lookup still has no match for
the testnet hash — fixing BUG-W144-2 does not transitively fix this.)

---

## BUG-W144-4 — `checkTransactionContextual` is a dead helper with policy-strict defaults

**Severity:** P0-CDIV (latent — no production caller; immediate the
moment one wires it)

**File:** `clearbit/src/validation.zig:368-454`
**Core ref:** `bitcoin-core/src/policy/policy.h:105-132`,
`bitcoin-core/src/validation.cpp:2480-2486`

**Description.** `checkTransactionContextual` is declared and fully
implemented (88 LOC). Its only inbound reference is a *comment* at
mempool.zig:2565. The body at lines 421-429:

```zig
for (tx.inputs, 0..) |input, input_index| {
    var engine = script.ScriptEngine.initWithPrevouts(
        allocator,
        tx,
        input_index,
        utxos[input_index].value,
        script.ScriptFlags{},                  // ← raw defaults
        spent_amounts,
        spent_scripts,
    );
    ...
}
```

`script.ScriptFlags{}` uses the struct's default field values
(`verify_p2sh = true`, `verify_witness = true`,
`verify_clean_stack = true`, `verify_dersig = true`,
`verify_low_s = true`, `verify_nulldummy = true`,
`verify_nullfail = true`, `verify_minimaldata = true`,
`verify_checklocktimeverify = true`, `verify_checksequenceverify = true`,
`verify_taproot = true`, `verify_witness_pubkeytype = true`).

Of those, **the ones marked POLICY-only in Core's `policy.h:119-132`**
(LOW_S, MINIMALDATA, CLEANSTACK, NULLFAIL, WITNESS_PUBKEYTYPE) would
hard-reject consensus-valid transactions if this helper were ever
plugged into the consensus path.

**Impact.** Latent. Today the function has no callers, but it's a
loaded gun for any future refactor that drops it in front of
`ConnectBlock`. Combined with BUG-W144-5 (the ScriptFlags defaults
themselves), this is the "well-engineered-helper-never-wired" fleet
pattern (W120-class).

---

## BUG-W144-5 — `ScriptFlags` defaults bake in POLICY semantics for the consensus base

**Severity:** P1

**File:** `clearbit/src/script.zig:183-212`
**Core ref:** `bitcoin-core/src/policy/policy.h:105-132`

**Description.** Of clearbit's 21 `ScriptFlags` fields, 12 default to
`true` (verify_p2sh, verify_witness, verify_clean_stack, verify_dersig,
verify_low_s, verify_nulldummy, verify_nullfail, verify_minimaldata,
verify_checklocktimeverify, verify_checksequenceverify, verify_taproot,
verify_witness_pubkeytype). The MANDATORY set (Core
`policy.h:105-111`) is only 7 flags: P2SH, DERSIG, NULLDUMMY,
CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, TAPROOT. The other
five default-true fields (`verify_clean_stack`, `verify_low_s`,
`verify_nullfail`, `verify_minimaldata`, `verify_witness_pubkeytype`)
are STANDARD_NOT_MANDATORY in Core.

**Excerpt:**
```zig
pub const ScriptFlags = packed struct {
    verify_p2sh: bool = true,
    verify_witness: bool = true,
    verify_clean_stack: bool = true,    // ← POLICY-only in Core
    verify_dersig: bool = true,
    verify_low_s: bool = true,          // ← POLICY-only in Core
    verify_nulldummy: bool = true,
    verify_nullfail: bool = true,       // ← POLICY-only in Core
    verify_minimaldata: bool = true,    // ← POLICY-only in Core
    verify_checklocktimeverify: bool = true,
    verify_checksequenceverify: bool = true,
    verify_taproot: bool = true,
    verify_witness_pubkeytype: bool = true,  // ← POLICY-only in Core
    ...
};
```

The production consensus path (`getBlockScriptFlagsForHash`) explicitly
resets the POLICY-only fields to `false` at lines 188-205. But all 30+
in-tree tests that use `ScriptFlags{}` (a quick grep finds ~30 hits)
get policy-strict semantics, masking divergent behavior on the consensus
path.

**Impact.** Attractive nuisance + test-policy-vs-consensus
inconsistency. Recommend flipping the defaults so the bare `ScriptFlags{}`
struct = `SCRIPT_VERIFY_NONE` (all false), with a separate
`ScriptFlags.mandatory()` helper.

---

## BUG-W144-6 — `taproot_height` field is dead config for script-flag derivation

**Severity:** P2

**File:** `clearbit/src/consensus.zig:184-185` (`TAPROOT_HEIGHT` constant),
`372` (struct field), `504, 621, 675, 726, 775` (per-network values),
`clearbit/src/validation.zig:158` (the only place verify_taproot is set)
**Core ref:** `bitcoin-core/src/validation.cpp:2260-2266` (Taproot is
always on; exception list handles the violator)

**Description.** `NetworkParams.taproot_height` is defined with
mainnet=709632, testnet3=2032291, testnet4=1, signet=1, regtest=0.
None of those values are consulted by `getBlockScriptFlagsForHash` —
that function unconditionally sets `verify_taproot = true` at line 158,
mirroring Core's "P2SH + WITNESS + TAPROOT always on" pattern at
validation.cpp:2262. The only consumers of `taproot_height` are
`rpc.zig:3289` (`getblockchaininfo` deployment status) and
`tests.zig:1006`.

**Excerpt (consensus.zig:370-372):**
```zig
csv_height: u32, // BIP-68/112/113 activation
segwit_height: u32,
taproot_height: u32,         // ← present, populated, never gated against
```

**Impact.** Misleading-by-presence: a future contributor who sees
`taproot_height` defined and per-network-populated may assume Taproot
script verification is gated on it. It is not. This is the
"defined-but-not-consulted" / "near-miss-of-buried-deployment-API"
pattern. Add a doc-comment that it's RPC-display-only OR drop the
field (and use a unified `BuriedDeployment` enum like Core's
`consensus/params.h:25-35`).

---

## BUG-W144-7 — `SCRIPT_VERIFY_CONST_SCRIPTCODE` policy flag present, untested

**Severity:** P3

**File:** `clearbit/src/script.zig:201` (default false),
`clearbit/src/script.zig:848-853` (callsite),
`clearbit/src/validation.zig:256` (set in standard policy)
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:474-476`
(`OP_CODESEPARATOR` in non-segwit → error when flag set)

**Description.** clearbit's `verify_const_scriptcode` correctly defaults
to false (line 201) and is correctly wired into the standard policy set
(validation.zig:256). The callsite at script.zig:848-853 gates on
`sig_version == .base`, matching Core's `sigversion == SigVersion::BASE`
gate at interpreter.cpp:475. Behavior appears correct.

However: no test exercises the *opposite* direction — that OP_CODESEPARATOR
in witness-v0 / tapscript is *permitted* when `verify_const_scriptcode`
is set. Core deliberately keeps OP_CODESEPARATOR valid in those
sig_versions (it's used for FROST/MuSig sighash tweaks). A regression
that broadened the gate to fire on witness-v0 would not be caught.

**Impact.** Test-coverage gap (P3). Behavior is correct today.

---

## BUG-W144-8 — test_script.zig::parseFlags silently drops MINIMALIF and CONST_SCRIPTCODE

**Severity:** P1 (test-corpus parity)

**File:** `clearbit/src/test_script.zig:275-342`
**Core ref:** `bitcoin-core/src/test/data/script_tests.json` — many
entries use `"MINIMALIF"` or `"CONST_SCRIPTCODE"` flag strings

**Description.** The flag-string parser at lines 275-342 has explicit
cases for P2SH, DERSIG, LOW_S, NULLDUMMY, MINIMALDATA, CLEANSTACK,
CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, NULLFAIL,
WITNESS_PUBKEYTYPE, TAPROOT, DISCOURAGE_OP_SUCCESS,
DISCOURAGE_UPGRADABLE_NOPS, SIGPUSHONLY, STRICTENC, and
DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM. Missing: **MINIMALIF** and
**CONST_SCRIPTCODE**. The trailing comment confirms:

```zig
// Flags not supported by clearbit ScriptFlags are silently ignored:
// MINIMALIF, CONST_SCRIPTCODE, etc.
```

This is wrong for two reasons:
1. Both flags **are** present in `ScriptFlags` (`verify_minimalif` @
   line 211, `verify_const_scriptcode` @ line 201).
2. Silently dropping flag strings from a test corpus means a test that
   expects MINIMALIF-strict behaviour will silently pass under MINIMALIF
   relaxed semantics (false positive).

**Impact.** Any Core test vector that exercises MINIMALIF or
CONST_SCRIPTCODE on/off boundaries is run by clearbit with those flags
permanently off — masking divergent semantics. P1 for the test corpus,
not the production code.

---

## BUG-W144-9 — No `-vbparams` / regtest deployment-height override knob

**Severity:** P2

**File:** `clearbit/src/consensus.zig::REGTEST` @ 720+, `SIGNET` @ 770+
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:572-584`
(`UpdateActivationParametersFromArgs` — regtest knob for runtime
override of `SegwitHeight`, `BIP66Height`, `BIP65Height`, `CSVHeight`,
`BIP34Height`)

**Description.** Core's regtest and signet honour CLI/RPC knobs that
override the buried-deployment heights at runtime, used heavily by the
functional-test suite to exercise deployment-boundary behavior on
arbitrary fork branches:

```cpp
consensus.BIP65Height = 1;  // Always active unless overridden
consensus.BIP66Height = 1;  // Always active unless overridden
consensus.CSVHeight = 1;    // Always active unless overridden
consensus.SegwitHeight = 0; // Always active unless overridden
```

clearbit's `NetworkParams` for REGTEST/SIGNET ship fixed values and
have no override path. Downstream functional tests that rely on
heights-as-knobs cannot be ported.

**Impact.** Regtest is reduced to whatever fixed deployment-height
table clearbit ships. Cannot reproduce Core's
`-vbparams=segwit:0:999999999:1916:2016` flow. P2 because regtest is a
testing concern, but it directly limits Core test-vector portability.

---

## BUG-W144-10 — DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM error-attribution drift on Taproot-via-P2SH fallthrough

**Severity:** P3

**File:** `clearbit/src/script.zig:1273-1283`
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:2025` (sets
`SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`)

**Description.** clearbit's witness-program-evaluation fallthrough at
script.zig:1267-1286 handles three distinct cases as one branch:

1. Unknown witness versions (witversion 2-16)
2. Taproot via P2SH (witversion=1 + 32-byte program — falls through
   here because of the `!via_p2sh` gate at line 1078)
3. P2A (`witversion=1 + 0x4e73` 2-byte program — Core's
   `CScript::IsPayToAnchor`)

When `discourage_upgradable_witness_program` is set and we're NOT a P2A,
clearbit returns `ScriptError.WitnessProgramMismatch`:

```zig
if (!(wp.version == 1 and wp.program.len == 2 and
    wp.program[0] == 0x4e and wp.program[1] == 0x73))
{
    return ScriptError.WitnessProgramMismatch;
}
```

Core returns `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`.

**Impact.** Wire-level reject is the same (tx is rejected either way),
but error-attribution differs — meaning P2P `reject` reasons / RPC
verbose script-error strings diverge from Core. P3 audit-grade.

---

## BUG-W144-11 — `getStandardScriptFlagsForHash` includes `discourage_upgradable_nops` but the underlying script engine has CLTV/CSV-divergent firing

**Severity:** P1 (compound bug — same root cause as BUG-W144-1)

**File:** `clearbit/src/validation.zig:257`,
`clearbit/src/script.zig:1946-1986`
**Core ref:** policy.h:122, interpreter.cpp:522-526, 561-565, 595-601

**Description.** Mempool's standard-flag set turns on both CLTV/CSV (via
the `getBlockScriptFlagsForHash` inheritance at line 245) AND
`discourage_upgradable_nops` (line 257). Today this combo is safe
because the CLTV/CSV flags are always on too. But if a future relay
path were to clear the verify_checklocktimeverify flag (e.g. for a
test-only or "old-node-simulation" RPC), the combo would emit
`DiscourageUpgradableNops` where Core emits success. Latent
double-bug; same root as W144-1.

**Impact.** Latent. Tracked here for completeness because the policy
layer accumulates these flags and the script engine's divergent
firing pattern is the underlying issue. Closes naturally when BUG-W144-1
is fixed.

---

## BUG-W144-12 — `getBlockScriptFlagsForHash` does not enforce P2SH on the BIP-16 violator's *descendants*

**Severity:** P3 (cosmetic — Core also does not, but the doc-comment
disagrees with code)

**File:** `clearbit/src/validation.zig:166-183`
**Core ref:** `bitcoin-core/src/validation.cpp:2262-2266`

**Description.** The exception list is keyed by *block hash*, not by
height. So only the EXACT violator block (h≈170,060) is exempted from
P2SH/WITNESS/TAPROOT enforcement. clearbit's implementation matches
Core's pointer-perfect — both gate by hash. But the doc-comment at
validation.zig:127-134 talks about "h~170,060 (Apr 2012), well before
BIP34 (h=227,931)" suggesting a height-keyed activation. A naive reader
might assume P2SH is disabled for ALL pre-170,060 blocks. It is not.

**Impact.** Doc/comment drift. P3.

---

## BUG-W144-13 — STANDARD policy flag set includes DISCOURAGE_UPGRADABLE_NOPS but ScriptFlags default has it false

**Severity:** P2

**File:** `clearbit/src/script.zig:197` (default false),
`clearbit/src/validation.zig:257` (set in standard policy)
**Core ref:** policy.h:122

**Description.** `verify_p2sh`, `verify_dersig`, `verify_clean_stack`,
etc. default to TRUE in `ScriptFlags`. But two STANDARD-flag fields
that Core also has in `STANDARD_SCRIPT_VERIFY_FLAGS` —
`discourage_upgradable_nops` (line 197) and
`discourage_upgradable_witness_program` (line 200) —
default to FALSE in clearbit. This is the OPPOSITE policy from the
field choice for LOW_S/MINIMALDATA/CLEANSTACK/etc.

The split is not principled — there's no reason policy-only flags
LOW_S and MINIMALDATA default true while policy-only flags
DISCOURAGE_UPGRADABLE_NOPS and DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
default false. Both groups need active wire-up to be set on the
mempool path.

**Impact.** Inconsistent struct defaults invite copy-paste bugs:
"I'm building a test flag-set, let me reset everything to default…"
will get a partial policy-strict + partial policy-lax mix.

---

## BUG-W144-14 — `getStandardScriptFlagsForHash` set forgets `verify_sigpushonly` policy override

**Severity:** P3 (matches Core deliberately, but undocumented)

**File:** `clearbit/src/validation.zig:226-230` (doc-comment),
`240-275` (function)
**Core ref:** `bitcoin-core/src/policy/policy.cpp::IsStandardTx`

**Description.** Core's `STANDARD_SCRIPT_VERIFY_FLAGS` (policy.h:119-132)
intentionally does NOT include `SCRIPT_VERIFY_SIGPUSHONLY` — that
check fires on the scriptSig in `IsStandardTx` (policy.cpp), not as a
script-verify flag. clearbit follows this and the doc-comment at
validation.zig:226-231 documents the choice. But: there's no test or
runtime cross-check that the mempool boundary actually enforces
SigPushOnly on the scriptSig (the responsibility lives in
mempool.zig::checkStandard, which I have not audited in this wave).

**Impact.** P3 design-coverage; calling out so a follow-up wave can
verify the IsStandardTx side.

---

## BUG-W144-15 — `MAX_SCRIPT_VERIFY_FLAGS_BITS` invariant absent

**Severity:** P3

**File:** `clearbit/src/script.zig:183-212`
**Core ref:** `bitcoin-core/src/script/interpreter.h:154-159`
(`static_assert(0 < MAX_SCRIPT_VERIFY_FLAGS_BITS && ... <= 63)`)

**Description.** Core enforces at compile-time that the number of
`SCRIPT_VERIFY_*` flag bits fits in a `uint64_t` and provides
`MAX_SCRIPT_VERIFY_FLAGS` for masks. clearbit's `ScriptFlags` packed
struct relies on Zig's `packed struct` layout and has no equivalent
assertion. A future contributor who adds a 64th flag may silently
overflow the underlying integer type (since clearbit then bit-casts
to `u32` at validation.zig:2511 for the sig-cache key — silently
truncating the upper bits).

**Excerpt (validation.zig:2511):**
```zig
const flags_u32: u32 = @intCast(@as(u21, @bitCast(job.flags)));
```

clearbit has 21 bits today (u21 cast is exact-fit). Adding a 22nd flag
without bumping the cast width = silent truncation in the cache key →
sig-cache poisoning across flag-set changes.

**Impact.** Latent — fires only if someone adds a flag without
inspecting the cache-key plumbing.

---

## BUG-W144-16 — `connectBlock` legacy path also calls hash-less `getBlockScriptFlags`

**Severity:** P0-CDIV (same class as W144-2)

**File:** `clearbit/src/validation.zig:889`
**Core ref:** validation.cpp:2485 (`flags{GetBlockScriptFlags(*pindex, m_chainman)}`)

**Description.** Companion to BUG-W144-2: the legacy `connectBlock`
entry point at line 879 also uses the hash-less variant:

```zig
pub fn connectBlock(...) ValidationError!i64 {
    // Get script verification flags for this block height
    const flags = getBlockScriptFlags(height, params);   // ← no hash
    ...
}
```

This is the path exercised by mining (`generatetoaddress`-style),
the `submitblock` RPC, and W143-flagged "30+ in-tree tests". On
mainnet, the bug fires for the same two exception blocks but
through a different caller.

**Impact.** Same as W144-2 — exception-list bypass on a second
consensus entry point. Two-pipeline-guard pattern × 2.

---

## BUG-W144-17 — Per-block `consensus.script_flag_exceptions` map vs hardcoded constants

**Severity:** P2 (architecture-fit)

**File:** `clearbit/src/validation.zig:97-110` (two hardcoded
`BIP16_EXCEPTION_HASH` / `TAPROOT_EXCEPTION_HASH` global constants)
**Core ref:** `bitcoin-core/src/consensus/params.h:96`
(`std::map<uint256, script_verify_flags> script_flag_exceptions`)

**Description.** Core's exception list lives in
`Consensus::Params::script_flag_exceptions` — a per-network map keyed by
block hash. clearbit hardcodes two global constants and a per-hash
`if/else if` chain at lines 175-183. This:
1. Makes it impossible to add a per-network exception without a code
   change in `validation.zig` (see BUG-W144-3 for testnet3's missing
   entry).
2. Couples script-flag derivation to validation.zig's identifier
   namespace instead of consensus.zig's NetworkParams.

**Impact.** Refactor lift to fix; without it, BUG-W144-3 (testnet3
exception) cannot be cleanly added.

---

## BUG-W144-18 — `verifyBlockScriptsParallel` and `verifyBlockScriptsSingleThreaded` accept `flags` as a parameter, then `verifyBlockScriptsParallel` ignores it for its main flag derivation

**Severity:** P2 (API-design / readability)

**File:** `clearbit/src/validation.zig:2606, 2616`
**Core ref:** validation.cpp:2485-2486

**Description.** Reading line 2606 — `verifyBlockScriptsParallel`
derives flags itself (`getBlockScriptFlags(height, params)`),
then passes that derived value to
`verifyBlockScriptsSingleThreaded(block, flags, utxo_lookup, allocator)`
on the fallback branch (line 2616). The caller of
`verifyBlockScriptsParallel` cannot inject a flag set — but
`verifyBlockScriptsSingleThreaded` accepts one. Asymmetry hides
the bug at line 2606: a single grep for `getBlockScriptFlagsForHash`
would miss the parallel-path miss because the flag derivation is buried
inline.

**Impact.** Readability + maintenance footgun. Easier to spot
BUG-W144-2 if the caller injects flags.

---

## Wave-pattern smells

- **Two-pipeline-guard:** Three consensus-flag entry points
  (`validateBlockForIBD` → ForHash-correct;
   `connectBlock` → hash-less;
   `verifyBlockScriptsParallel` → hash-less).
  The fix is implemented and works in pipeline #1; pipelines #2 and #3
  call the null-hash convenience wrapper. (BUG-W144-2, W144-16.)
- **Dead-helper-with-policy-strict-defaults:** `checkTransactionContextual`
  exists, is fully implemented, has no production caller, and uses
  `ScriptFlags{}` defaults that bake in 5 policy-only flags. (BUG-W144-4
  + W144-5.)
- **Comment-as-confession:** `parseFlags` at test_script.zig:338-339
  explicitly admits "Flags not supported by clearbit ScriptFlags are
  silently ignored" — but the flags it claims are unsupported (MINIMALIF,
  CONST_SCRIPTCODE) are in fact present in ScriptFlags. The comment is a
  lie that hides a test-coverage gap. (BUG-W144-8.)
- **Defined-but-not-consulted:** `taproot_height` lives in `NetworkParams`
  with per-network values, but the script-flag derivation never reads it.
  RPC + tests are the only consumers. (BUG-W144-6.)
- **Default-trueness asymmetry:** Five policy-only flags default true
  in `ScriptFlags` (LOW_S, MINIMALDATA, CLEANSTACK, NULLFAIL,
  WITNESS_PUBKEYTYPE) but two other policy-only flags default false
  (DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM).
  No principle behind the split. (BUG-W144-13.)
- **Discouragement firing for a defined opcode:** OP_CHECKLOCKTIMEVERIFY
  and OP_CHECKSEQUENCEVERIFY fire DISCOURAGE_UPGRADABLE_NOPS when their
  flag is off — Core deliberately excludes them from that gate because
  they have defined semantics. (BUG-W144-1, W144-11.)
- **Carry-forward re-anchor:** the hash-less `getBlockScriptFlags`
  wrapper exists primarily to support backward-compat callers; new
  callers should always use the `ForHash` variant. The wrapper is the
  smell that needs to go away (or get a `@deprecated` annotation in Zig
  terms).

## Cross-references

- W143 (block-validation) flagged the `connectBlock` legacy vs
  `validateBlockForIBD` divergence; this audit confirms it extends to
  the script-flag derivation.
- W132 (nSequence/CSV/MTP) audited the OP_CSV opcode semantics but did
  not catch the DISCOURAGE_UPGRADABLE_NOPS firing.
- W137 (PSBT) tested `SCRIPT_VERIFY_DERSIG`/`SCRIPT_VERIFY_STRICTENC`
  absence in psbt.zig (W137 BUG-12 vs W144 BUG-W144-5 / W144-8).

## Severity rollup

| Severity | Count | BUG IDs |
|----------|-------|---------|
| P0-CDIV  | 5     | 1, 2, 3, 4, 16 |
| P1       | 3     | 5, 8, 11 |
| P2       | 5     | 6, 9, 13, 17, 18 |
| P3       | 5     | 7, 10, 12, 14, 15 |
| **Total** | **18** | |

End of W144 audit.
