# W142 — BIP-141/143 SegWit witness validation audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's witness-related consensus & cryptographic surface:
coinbase witness commitment, witness Merkle root, BIP-143 segwit v0
sighash (P2WPKH / P2WSH), witness program parsing, weight / vsize
computation, MAX_BLOCK_WEIGHT enforcement, CheckWitnessMalleation, and
mempool/relay weight gates.
**Bitcoin Core references:**
- `bitcoin-core/src/validation.cpp:3864-3916`
  (`CheckWitnessMalleation` — `bad-witness-nonce-size`,
  `bad-witness-merkle-match`, `unexpected-witness`)
- `bitcoin-core/src/validation.cpp:3985-4019`
  (`UpdateUncommittedBlockStructures`, `GenerateCoinbaseCommitment`)
- `bitcoin-core/src/validation.cpp:3947`
  (`bad-blk-length` triple-condition gate including
  `block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` and
  `GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`)
- `bitcoin-core/src/consensus/validation.h:18-19,147-165`
  (`MINIMUM_WITNESS_COMMITMENT = 38`, `NO_WITNESS_COMMITMENT = -1`,
  `GetWitnessCommitmentIndex`)
- `bitcoin-core/src/consensus/consensus.h:13-24`
  (`MAX_BLOCK_WEIGHT = 4_000_000`, `WITNESS_SCALE_FACTOR = 4`,
  `MIN_TRANSACTION_WEIGHT`, `MIN_SERIALIZABLE_TRANSACTION_WEIGHT`)
- `bitcoin-core/src/consensus/merkle.cpp:76-85` (`BlockWitnessMerkleRoot`)
- `bitcoin-core/src/script/interpreter.cpp:320-339` (`EvalChecksigPreTapscript`
  — "Subset of script starting at the most recent codeseparator" for BOTH
  `SigVersion::BASE` and `SigVersion::WITNESS_V0`)
- `bitcoin-core/src/script/interpreter.cpp:1600-1677` (`SignatureHash` — BIP-143
  v0 layout: `hashPrevouts`, `hashSequence`, `hashOutputs`, scriptCode rules,
  SIGHASH_SINGLE / SIGHASH_NONE / ANYONECANPAY masking)
- `bitcoin-core/src/script/interpreter.cpp:1917-2000` (`VerifyWitnessProgram`)
- `bitcoin-core/src/script/interpreter.cpp:2002-2090` (`VerifyScript` —
  `SCRIPT_ERR_WITNESS_MALLEATED` when scriptSig non-empty on a native witness
  program at line 2040)
- `bitcoin-core/src/script/interpreter.h:237-238`
  (`WITNESS_V0_SCRIPTHASH_SIZE = 32`, `WITNESS_V0_KEYHASH_SIZE = 20`)
- `bitcoin-core/src/primitives/transaction.h:392-400` (`HasWitness`)
- `bitcoin-core/src/policy/policy.h:38,54-56` (`MAX_STANDARD_TX_WEIGHT = 400000`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS = 100`, `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80`)
- `bitcoin-core/src/kernel/chainparams.cpp:94,217,316,460,541`
  (`SegwitHeight` per network — mainnet 481824, testnet3 834624, testnet4 1,
  signet 1, regtest 0)

**BIPs:** BIP-141 (segwit consensus), BIP-143 (segwit-v0 sighash),
BIP-144 (segwit P2P serialization), BIP-145 (compactblock segwit).
**Mode:** DISCOVERY (no production code changes).
**Implementation files audited:**
- `clearbit/src/validation.zig`
  (`checkWitnessMalleation` @ 1888, `getWitnessCommitmentIndex` @ 1860,
   `checkBlock` weight gate @ 807-817, coinbase amount soft-check @ 836-839,
   `calculateBlockWeight` @ 1723, `getBlockScriptFlags` @ 137,
   `WITNESS_COMMITMENT_MAGIC` @ 1849, `MINIMUM_WITNESS_COMMITMENT` @ 1853)
- `clearbit/src/crypto.zig`
  (`writeTransactionToHasher` @ 1144, `computeWtxid` @ 1201,
   `legacySighash` @ 1234, `segwitSighash` @ 1382,
   `SegwitSighashCache` @ 1329)
- `clearbit/src/script.zig`
  (`isWitnessProgram` @ 2509, `verify` witness branch @ 952-1293,
   `verifySignature` @ 2203, `countWitnessSigOps` @ 2724, `witnessSigOps` @ 2702,
   `OP_CODESEPARATOR` handling @ 1830-1839)
- `clearbit/src/serialize.zig`
  (`readTransaction` @ 191, `writeTransaction` @ 331, `writeTransactionNoWitness` @ 373)
- `clearbit/src/block_template.zig`
  (`computeWitnessCommitment` @ 701, `constructCoinbaseWithCommitment` @ 468,
   `addTransactionsToBlock` second-path commitment @ 1804-1818,
   `estimateTxWeight` @ 1872)
- `clearbit/src/consensus.zig`
  (`MAX_BLOCK_WEIGHT` @ 11, `WITNESS_SCALE_FACTOR` @ 38,
   `MAX_STANDARD_TX_WEIGHT` @ 42, `segwit_height` per-network @ 503/620/674/725/774)
- `clearbit/src/mempool.zig`
  (`MAX_STANDARD_P2WSH_STACK_ITEMS` @ 98, weight gate @ 2796-2799)

## Summary

clearbit's BIP-141 / BIP-143 surface is **mostly wired but has multiple
sighash-divergence and dead-code-confession defects**. The
`CheckWitnessMalleation` analogue is correctly implemented at
`validation.zig:1888-1942` (gates 1-3 mirror Core
`validation.cpp:3864-3916`), the witness Merkle root uses the canonical
all-zeros coinbase wtxid (`validation.zig:1911`), and the per-network
`segwit_height` constants match Bitcoin Core exactly (mainnet 481824,
testnet3 834624, testnet4 1, signet 1, regtest 0).

However, **two consensus-divergent BIP-143 sighash bugs** sit in
`crypto.zig`:

1. `segwitSighash` (`crypto.zig:1382-1500`) re-implements CompactSize
   encoding for output `script_pubkey.len` inline at lines 1456-1463
   and 1476-1483 and only handles the `< 0xFD` and `0xFD` (u16)
   branches. Output scripts of length 65,536-4,294,967,295 panic via
   `@intCast(u16, len)` (Zig RuntimeSafety crash); the `> 0xFFFFFFFF`
   branch is structurally unreachable but the principle is wrong.
   The `Writer.writeCompactSize` helper at `serialize.zig:141-154`
   handles all four ranges correctly — `segwitSighash` could simply use
   it instead. This is divergent from Core's `WriteCompactSize` for
   any conceivable >64 KB scriptPubKey.

2. `SegwitSighashCache.init` (`crypto.zig:1329-1377`) is **dead code
   with a triple-SHA256 bug**. The struct is `pub` but has zero call
   sites in production. If a future caller wires it up the output-hash
   field would be SHA256(SHA256(SHA256(serialized_outputs))) instead
   of Core's `SHA256d(serialized_outputs)` = SHA256(SHA256(x)) — a
   guaranteed `mandatory-script-verify-flag-failed` for every P2WPKH
   / P2WSH spend on first use. The struct also stack-allocates
   `[36 * 256]u8` and `[4 * 256]u8` buffers and silently overflows on
   txs with >256 inputs.

**Critical OP_CODESEPARATOR divergence**: Core's BIP-143 scriptCode is
"Subset of script starting at the most recent codeseparator" for BOTH
`SigVersion::BASE` and `SigVersion::WITNESS_V0`
(`bitcoin-core/src/script/interpreter.cpp:325-326`). clearbit tracks
`codesep_pos` in `script.zig:1838` but **never slices
`script_pubkey_for_sighash` for `SigVersion::WITNESS_V0`** at line 1061
or anywhere else. A P2WSH script containing OP_CODESEPARATOR followed
by OP_CHECKSIG produces a sighash that diverges from Core — clearbit
will reject every valid signature crafted against the post-codeseparator
prefix. Bare P2WPKH (no OP_CODESEPARATOR by construction) is unaffected.

**Mining-side commitment drop**: `block_template.zig:1805-1818` computes
the witness commitment in the secondary `addTransactionsToBlock` path
and immediately discards it (`_ = witness_commitment;`) with a
**comment-as-confession** that reads *"Simplified: in full
implementation would reconstruct coinbase"*. Any block assembled via
this path will have a coinbase commitment that doesn't match its
transactions → `bad-witness-merkle-match` rejection at consensus.

**Coinbase amount soft-check dead branch**: `checkBlock` step 9 at
`validation.zig:836-839` evaluates `if (coinbase_value > subsidy)` and
the body is empty (no return, no error). The full subsidy + fees check
is correctly enforced later in `connectBlock` (line 976), but the
empty-body fall-through is a comment-as-confession smell ("conservative
check ... actual validation needs total fees") and would be removed in
a strict diff with Core.

**Witness-error code semantic divergence**: clearbit returns
`WitnessUnexpected` (BIP-141 reject reason) when a native witness
program has a non-empty scriptSig (`script.zig:968-970`); Core returns
`SCRIPT_ERR_WITNESS_MALLEATED` (`interpreter.cpp:2040`). Likewise
clearbit returns `WitnessProgramMismatch` for the
`SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` path
(`script.zig:1281`) where Core returns
`SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`. Distinguishable to
mempool peers via reject-code scoring.

**Operator-facing weight estimate**: `block_template.zig::estimateTxWeight`
(`block_template.zig:1872-1918`) uses single-byte CompactSize prefixes
for input count, scriptSig length, output count, scriptPubKey length,
witness stack count, and witness item length — with an in-file
acknowledgement *"simplified; accurate for <= 252 inputs"* at line 1875.
A tx with ≥253 inputs underestimates weight by 2 bytes per varint × 5
varint sites. The function also contains an always-false `else if
(has_witness or blk: { break :blk false; })` branch
(`block_template.zig:1899-1906`) — when the FIRST input has no witness
and a LATER input does, the empty witness-stack count byte for the
first input is not added.

Key findings ranked by severity:

- **P0-CDIV (consensus-divergent on the script-eval hot path):
  BIP-143 sighash drops OP_CODESEPARATOR slicing for WITNESS_V0.**
  Core's BIP-143 `scriptCode` is the witness-script subset starting at
  the most recent OP_CODESEPARATOR. clearbit records `codesep_pos` but
  never slices `script_pubkey_for_sighash` for v0 spends. Every P2WSH
  with `... OP_CODESEPARATOR OP_CHECKSIG` produces a wrong sighash;
  Core-signed sigs are rejected and clearbit-signed sigs are rejected
  by Core. See BUG-1.
- **P0-CDIV (sighash crash + silent truncation on outputs ≥ 65 KB):
  segwitSighash CompactSize encoding only handles 1-byte and 3-byte
  prefixes.** The `0xFE` (u32) and `0xFF` (u64) prefixes are missing,
  and `@intCast(u16, len)` panics at runtime on overflow. Realistic
  scripts under MAX_SCRIPT_SIZE = 10 000 bytes are safe; any synthetic
  >64 KB output script (legal under BIP-141 weight budget) crashes the
  signer/validator process. See BUG-2.
- **P0-CDIV (block-template path produces unconfirmable blocks):
  addTransactionsToBlock computes the witness commitment then
  discards it with a comment-as-confession.** Any block assembled via
  this path is structurally invalid (commitment ≠ actual wtxid merkle).
  See BUG-3.
- **P0-DEAD-LATENT (triple-SHA256 + stack-buffer-overflow in unused
  cache module): SegwitSighashCache.init.** Public struct with zero
  call sites; would compute SHA256³(outputs) instead of SHA256²(outputs)
  if wired up. Stack buffers sized to 256 inputs silently overflow on
  larger txs. See BUG-4.
- **P1 (error-code semantic divergence on witness-malleated input):**
  WitnessUnexpected vs SCRIPT_ERR_WITNESS_MALLEATED. See BUG-5.
- **P1 (error-code semantic divergence on discourage-upgradable v2+):**
  WitnessProgramMismatch vs SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.
  See BUG-6.
- **P2 (dead-branch in checkBlock — coinbase value soft check has empty
  body):** if (coinbase_value > subsidy) { /* empty */ }. See BUG-7.
- **P2 (block-weight check missing two of Core's three bad-blk-length
  conditions):** `vtx.size() × WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`
  and `GetSerializeSize(TX_NO_WITNESS(block)) × WITNESS_SCALE_FACTOR >
  MAX_BLOCK_WEIGHT` (Core validation.cpp:3947). See BUG-8.
- **P2 (weight-estimator simplified varint encoding):**
  estimateTxWeight assumes ≤252 items at five distinct sites. See BUG-9.
- **P2 (weight-estimator empty-witness-stack-count for prefix non-witness
  inputs):** always-false `or` arm produces 0 bytes for first
  non-witness input when later input has witness. See BUG-10.
- **P3 (defensive — coinbase witness-stack indexed without input
  presence guard):** assumes `coinbase.inputs.len > 0` — Core asserts
  identically. See BUG-11.

---

## BUG-1 — BIP-143 sighash ignores OP_CODESEPARATOR slicing for WITNESS_V0
- **Severity:** P0-CDIV
- **File:** `clearbit/src/script.zig:2258-2272` (caller),
  `clearbit/src/script.zig:1061` (where `script_pubkey_for_sighash` is set
  for P2WSH), `clearbit/src/script.zig:1830-1839` (where `codesep_pos` is
  updated but `script_pubkey_for_sighash` is not)
- **Core ref:** `bitcoin-core/src/script/interpreter.cpp:320-339`
  (`EvalChecksigPreTapscript`)

### Description
Core's BIP-143 specification: *"Subset of script starting at the most
recent codeseparator"*. This applies to BOTH `SigVersion::BASE` and
`SigVersion::WITNESS_V0` per `EvalChecksigPreTapscript`'s assertion at
line 323. The variable `pbegincodehash` advances every time
`OP_CODESEPARATOR` executes (`interpreter.cpp:1048-1055`), and the
scriptCode passed to `CheckECDSASignature` is `(pbegincodehash, pend)`
— the suffix from the last OP_CODESEPARATOR.

clearbit sets `script_pubkey_for_sighash = witness_script` once on
P2WSH entry (`script.zig:1061`) and never re-slices it after
`OP_CODESEPARATOR`. The `codesep_pos` field is incremented at line 1838
but is used **only** by the tapscript ext_flag=1 sigmsg path
(`script.zig:2346`), not by BIP-143 sighash.

### Excerpt — clearbit OP_CODESEPARATOR handler (no V0 scriptCode update)
```zig
.op_codeseparator => {
    // BIP-341: record the OPCODE INDEX, not the byte position.
    // Core stores `opcode_pos` (interpreter.cpp:1055), the 0-based
    // counter of opcodes seen so far, committed to the tapscript
    // sigmsg at interpreter.cpp:1565.
    // CONST_SCRIPTCODE: Core rejects OP_CODESEPARATOR in legacy
    // (BASE) scripts when this flag is set — checked ABOVE the
    // fExec gate in the main execute() loop, not here.
    self.codesep_pos = opcode_pos;
},
```

### Excerpt — Core's EvalChecksigPreTapscript (handles BOTH BASE and WITNESS_V0)
```cpp
static bool EvalChecksigPreTapscript(... CScript::const_iterator pbegincodehash,
                                      CScript::const_iterator pend, ...)
{
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0);
    // Subset of script starting at the most recent codeseparator
    CScript scriptCode(pbegincodehash, pend);
```

### Impact
A P2WSH spending a witness script containing `OP_CODESEPARATOR
OP_CHECKSIG` (or `OP_CODESEPARATOR ... OP_CHECKSIGVERIFY` /
`OP_CHECKMULTISIG`) computes a different sighash in clearbit vs Core.
Every signature crafted against Core's "post-codeseparator subset" is
rejected by clearbit (the script aborts with a verification failure),
and every signature crafted against clearbit's "full script" is rejected
by Core. P2WPKH is unaffected (its implicit script is
`OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG` — no
OP_CODESEPARATOR). Practical impact is small (OP_CODESEPARATOR is
extremely rare in real P2WSH scripts), but it is a strict-mode
consensus split.

---

## BUG-2 — segwitSighash CompactSize encoding crashes / truncates on output scripts ≥ 64 KB
- **Severity:** P0-CDIV
- **File:** `clearbit/src/crypto.zig:1455-1463` (SIGHASH_ALL output loop),
  `clearbit/src/crypto.zig:1476-1483` (SIGHASH_SINGLE single output)
- **Core ref:** `bitcoin-core/src/serialize.h::WriteCompactSize`
  (full four-tier encoding: u8, 0xFD+u16, 0xFE+u32, 0xFF+u64)

### Description
`segwitSighash` ad-hoc-encodes CompactSize for each output's
`script_pubkey.len` inline. The implementation only handles two of the
four CompactSize tiers — `< 0xFD` and `0xFD` + u16. For
`script_pubkey.len ∈ [0x10000, 0xFFFFFFFF]` the `@intCast(u16, len)`
operation panics at runtime under Zig's RuntimeSafety (the default for
ReleaseFast). For `script_pubkey.len > 0xFFFFFFFF` the code is
structurally unreachable but the encoding would still be wrong.

The contrast is stark because the working helper
`Writer.writeCompactSize` at `serialize.zig:141-154` correctly handles
all four ranges in 13 lines. The legacy-sighash path at
`crypto.zig:1234-1326` uses `writer.writeCompactSize` correctly. The
segwit path re-implements the encoding inline and gets it wrong.

### Excerpt — clearbit segwit SIGHASH_ALL output serialization (two-tier only)
```zig
for (tx.outputs) |output| {
    var val_buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &val_buf, output.value, .little);
    try outputs_data.appendSlice(&val_buf);

    // CompactSize
    if (output.script_pubkey.len < 0xFD) {
        try outputs_data.append(@intCast(output.script_pubkey.len));
    } else {
        try outputs_data.append(0xFD);
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(output.script_pubkey.len), .little);
        try outputs_data.appendSlice(&len_buf);
    }
    try outputs_data.appendSlice(output.script_pubkey);
}
```

### Impact
Bitcoin Core's `MAX_SCRIPT_SIZE = 10_000` bytes is enforced for legacy
scripts but does not apply to witness scriptPubKey output scripts (an
output script can be any size up to the tx weight budget). A
synthetic >64 KB output script (e.g. a TRUC anchor with embedded data,
or a future soft-fork output type) crashes clearbit's signer when
computing the sighash. Even if no real >64 KB output exists today,
the encoding is divergent from Core's `WriteCompactSize` per BIP-143
spec wording "txout serialization including the value and scriptPubKey".

---

## BUG-3 — Block-template re-commitment computation discards result (comment-as-confession)
- **Severity:** P0-CDIV
- **File:** `clearbit/src/block_template.zig:1804-1818`
- **Core ref:** `bitcoin-core/src/validation.cpp:3985-4019`
  (`UpdateUncommittedBlockStructures`, `GenerateCoinbaseCommitment`)

### Description
After the primary `createBlockTemplate` path adds the coinbase
commitment correctly, the secondary `addTransactionsToBlock` path
re-computes the witness commitment after appending more transactions
— but immediately throws it away with `_ = witness_commitment;`. The
in-file comment is the textbook **comment-as-confession** pattern:
*"Simplified: in full implementation would reconstruct coinbase"*.

### Excerpt — clearbit's dead-output commitment computation
```zig
// Recompute witness commitment with new transactions
if (transactions.len > 0) {
    var txs_for_witness = try allocator.alloc(types.Transaction, transactions.len);
    defer allocator.free(txs_for_witness);
    for (transactions, 0..) |tx, i| {
        txs_for_witness[i] = tx;
    }

    const witness_nonce: [32]u8 = [_]u8{0} ** 32;
    const witness_commitment = try computeWitnessCommitment(txs_for_witness, witness_nonce, allocator);

    // Update coinbase witness commitment output
    // (Simplified: in full implementation would reconstruct coinbase)
    _ = witness_commitment;
}
```

### Impact
Any block produced by the `addTransactionsToBlock` path with segwit
active will have a coinbase commitment that no longer matches the
block's wtxid Merkle root → `bad-witness-merkle-match` reject at every
peer. This breaks any RPC / test path that adds transactions to an
existing template (e.g. `prioritisetransaction` followed by GBT, or
incremental block assembly). The primary `createBlockTemplate` path
is correct; only the secondary update path is broken.

---

## BUG-4 — SegwitSighashCache: dead module with triple-SHA256 bug + 256-input buffer overflow
- **Severity:** P0-LATENT (dead-code; would be P0-CDIV if wired up)
- **File:** `clearbit/src/crypto.zig:1329-1377`
- **Core ref:** `bitcoin-core/src/script/interpreter.cpp:1442-1444,1627-1638`
  (`PrecomputedTransactionData` caches single-SHA256 of each
  preimage; the final sighash applies a single SHA256 on top, totalling
  SHA256d, NOT triple SHA256)

### Description
`SegwitSighashCache` is a `pub` struct with `init(tx, allocator)`. Zero
call sites in production (`grep -rn SegwitSighashCache src/` outside
the definition file returns no production callers). If a future caller
wires it up:

1. `hash_outputs` is computed as `hash256(&first_hash)` at line 1375,
   where `first_hash` is **already** a SHA256 of the serialized
   outputs (`outputs_hasher.final(&first_hash)` at line 1370).
   `hash256` = SHA256d = SHA256(SHA256(x)). So `hash_outputs =
   SHA256(SHA256(SHA256(serialized_outputs)))` — **triple SHA256**.
   Core's `hashOutputs = SHA256d(serialized_outputs)` — double SHA256.

2. Stack buffers `[36 * 256]u8` and `[4 * 256]u8` silently overflow on
   any tx with >256 inputs. The MAX_STANDARD_TX_WEIGHT = 400 000 limit
   does not bound input count; a 250-input tx is well under weight, but
   a 257-input mempool tx (or any consensus-valid block-tier tx)
   writes past the buffer.

3. Output CompactSize encoding has the same two-tier-only bug as
   BUG-2 (lines 1361-1366).

### Excerpt — triple-SHA256 finalisation
```zig
var outputs_hasher = std.crypto.hash.sha2.Sha256.init(.{});
for (tx.outputs) |output| {
    // ...accumulate output value + script...
    outputs_hasher.update(output.script_pubkey);
}
var first_hash: Hash256 = undefined;
outputs_hasher.final(&first_hash);

return .{
    .hash_prevouts = hash256(prevouts_data[0..prevouts_len]),
    .hash_sequence = hash256(sequence_data[0..sequence_len]),
    .hash_outputs = hash256(&first_hash),   // ← triple SHA256 !
};
```

### Impact
**Latent** today (zero callers). The danger is a future PR wiring the
cache into `segwitSighash` for performance — every P2WPKH / P2WSH
SIGHASH_ALL sighash would diverge from Core, breaking signature
verification across the entire mempool. Should be deleted (preferred)
or rewritten before any wire-up. Fits the **fleet-wide
"declared-but-never-used helper hides a wrong implementation"**
pattern.

---

## BUG-5 — Native witness program with non-empty scriptSig returns wrong error code
- **Severity:** P1
- **File:** `clearbit/src/script.zig:964-970`
- **Core ref:** `bitcoin-core/src/script/interpreter.cpp:2038-2040`
  (`SCRIPT_ERR_WITNESS_MALLEATED`)

### Description
When a tx spends a native witness program (e.g. P2WPKH output)
with a non-empty scriptSig, Core sets `SCRIPT_ERR_WITNESS_MALLEATED`
(line 2040). clearbit returns `ScriptError.WitnessUnexpected` (line 969)
— the BIP-141 reject reason for "block contains witness data without a
commitment", which is a different error class. Mempool peers that
score by reject-reason will record clearbit's rejection under the wrong
category, and tests asserting on the specific Core error code will fail.

### Excerpt
```zig
if (isWitnessProgram(script_pubkey)) |_| {
    // Native witness program (scriptPubKey is the witness program directly)
    wit_program_script = script_pubkey;
    // BIP-141: scriptSig must be empty for native witness programs
    if (script_sig.len != 0) {
        return ScriptError.WitnessUnexpected;
    }
}
```

### Impact
Cosmetic at the consensus level (both errors → invalid tx), but
behaviourally distinguishable on the wire (different reject reason
returned in `inv reject` / `notfound`).

---

## BUG-6 — Discouraged-upgradable witness program returns WitnessProgramMismatch
- **Severity:** P1
- **File:** `clearbit/src/script.zig:1273-1283`
- **Core ref:** `bitcoin-core/src/script/interpreter.cpp:1993-1994`
  (`SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`)

### Description
When `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` is set and a
witness program is v2..v16 (and not P2A), Core sets a dedicated
`SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`. clearbit returns
`ScriptError.WitnessProgramMismatch`, conflating "wrong program length"
with "future witness version".

### Excerpt
```zig
} else {
    // Unknown witness version, OR Taproot via P2SH (which
    // falls through to here because of the !via_p2sh gate
    // on the v1-32B branch above), OR P2A (anyone-can-spend
    // anchor — Core's CScript::IsPayToAnchor returns true
    // for this exact shape: witversion=1, prog={0x4e,0x73}).
    if (self.flags.discourage_upgradable_witness_program) {
        if (!(wp.version == 1 and wp.program.len == 2 and
            wp.program[0] == 0x4e and wp.program[1] == 0x73))
        {
            return ScriptError.WitnessProgramMismatch;
        }
    }
```

### Impact
Same as BUG-5: cosmetic at the consensus level but distinguishable on
the wire / in mempool-rejection metrics.

---

## BUG-7 — checkBlock coinbase soft-check has empty if-body (dead comment-as-confession)
- **Severity:** P2 (cosmetic: real check is enforced in connectBlock)
- **File:** `clearbit/src/validation.zig:828-839`
- **Core ref:** `bitcoin-core/src/validation.cpp:5089-5096`
  (`ConnectBlock` `bad-cb-amount`)

### Description
`checkBlock` step 9 evaluates `coinbase_value > subsidy` then enters
an empty if-body. The full check (`coinbase_value > subsidy + total_fees`)
is correctly enforced in `connectBlock` at line 976. The redundant
empty-body check is a leftover from an earlier "TODO: needs total fees"
refactor (referenced at line 873).

### Excerpt
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

### Impact
Zero consensus impact — the real gate runs in `connectBlock`. But the
empty if-body is dead code that misleads readers into believing a
soft-rejection occurs at the checkBlock layer. Should be deleted.
Counts as a **comment-as-confession** pattern (the code openly admits
it does nothing).

---

## BUG-8 — checkBlock missing two of Core's three bad-blk-length conditions
- **Severity:** P2 (redundant with the weight gate, but the structure
  diverges from Core)
- **File:** `clearbit/src/validation.zig:807-817`
- **Core ref:** `bitcoin-core/src/validation.cpp:3947`

### Description
Core's `CheckBlock` size-limits gate is three conditions chained with
`||`:
```cpp
if (block.vtx.empty()
    || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

clearbit checks only the third (the actual weight) via
`calculateBlockWeight`. The transaction-count cap
(`vtx.size() × 4 > MAX_BLOCK_WEIGHT` ⇒ vtx.size > 1 000 000) is implied
by the weight gate (each tx is at least MIN_TRANSACTION_WEIGHT = 240 WU),
but Core's explicit guard exits faster on the pathological case before
attempting per-tx serialization.

### Excerpt — clearbit (single condition only)
```zig
// 7. Check block weight
const weight = calculateBlockWeight(block, allocator) catch {
    return ValidationError.OutOfMemory;
};
if (weight > consensus.MAX_BLOCK_WEIGHT) {
    return ValidationError.BadBlockWeight;
}
```

### Impact
None on legitimate blocks. A DoS-shaped block with 1 000 001+ trivial
transactions still gets rejected — just after a full serialization
pass rather than a constant-time cap check. Structural divergence from
Core, not a consensus split.

---

## BUG-9 — block_template estimateTxWeight uses single-byte CompactSize at five sites (≤252 inputs only)
- **Severity:** P2 (mining/template only — does not affect consensus,
  but feeds GBT weight reporting)
- **File:** `clearbit/src/block_template.zig:1872-1918`
- **Core ref:** `bitcoin-core/src/policy/policy.h::GetTransactionWeight`
  via `bitcoin-core/src/consensus/validation.h:130-145`

### Description
`estimateTxWeight` assumes a 1-byte varint for input count, scriptSig
length, output count, scriptPubKey length, witness item count, and
witness item length. The in-file comment at line 1875 admits the
limitation: *"input count varint (simplified; accurate for <= 252
inputs)"*. The same shortcut at four more sites silently undercounts
weight by 2 bytes per varint per crossing-of-252 boundary.

### Excerpt
```zig
fn estimateTxWeight(tx: *const types.Transaction) usize {
    var base_size: usize = 4; // version
    base_size += 1; // input count varint (simplified; accurate for <= 252 inputs)
    for (tx.inputs) |input| {
        // ...
        base_size += 1 + input.script_sig.len; // scriptSig length + data
    }
    base_size += 1; // output count varint (simplified)
    for (tx.outputs) |output| {
        // ...
        base_size += 1 + output.script_pubkey.len; // scriptPubKey length + data
    }
    // ...
    witness_size += 1; // stack item count varint for this input
    for (input.witness) |item| {
        witness_size += 1 + item.len; // item length + data
    }
```

### Impact
GBT `weight` field for any tx with ≥253 inputs/outputs underestimates
by 6 WU per crossing (3 bytes × WITNESS_SCALE_FACTOR=3 added vs 1×3).
Affects miner reward maximisation and operator-facing weight reporting.
No consensus impact (consensus uses the canonical serializer via
`calculateBlockWeight` / `Writer.writeCompactSize`).

---

## BUG-10 — estimateTxWeight skips empty witness-stack byte for non-witness inputs preceding witness inputs
- **Severity:** P2 (mining/template only)
- **File:** `clearbit/src/block_template.zig:1899-1906`
- **Core ref:** `bitcoin-core/src/primitives/transaction.h::UnserializeTransaction`
  (segwit serialization writes a stack-count varint for **every** input
  when flag=1, including 0x00 for inputs with no witness)

### Description
For a mixed-input tx (e.g. input[0] is P2PKH non-witness, input[1] is
P2WPKH), Core's segwit serialization writes a 0x00 stack-count byte
for input[0] AND the proper stack for input[1]. clearbit's
`estimateTxWeight` adds the 0x00 byte for non-witness inputs only
**after** seeing a witness input — the always-false `or` arm gates
the increment.

### Excerpt
```zig
var has_witness = false;
var witness_size: usize = 0;
for (tx.inputs) |input| {
    if (input.witness.len > 0) {
        has_witness = true;
        witness_size += 1; // stack item count varint for this input
        for (input.witness) |item| {
            witness_size += 1 + item.len;
        }
    } else if (has_witness or blk: {
        // If a later input has witness we still need a 0x00 stack-count byte
        // for this input.  Check conservatively: any input with witness
        // triggers the segwit serialization for ALL inputs.
        break :blk false;
    }) {
        witness_size += 1; // empty witness stack (0x00) for non-witness inputs
    }
}
```

The comment hints at the bug (*"If a later input has witness we still
need a 0x00 stack-count byte for this input. Check conservatively"*),
but the `blk` arm hard-codes `false`. A forward-iterating loop sees
`has_witness == false` when processing input[0], so the empty-stack
byte is never added even though it WILL be serialised.

### Impact
Same as BUG-9: GBT weight underestimate by 1 byte × number of
non-witness inputs preceding any witness input. Operator-facing only.

---

## BUG-11 — checkWitnessMalleation accesses coinbase.inputs[0] without bounds guard
- **Severity:** P3 (defensive — upstream `checkTransactionSanity`
  already rejects empty-inputs, and Core itself asserts identically)
- **File:** `clearbit/src/validation.zig:1898-1900`
- **Core ref:** `bitcoin-core/src/validation.cpp:3877`
  (`assert(!block.vtx.empty() && !block.vtx[0]->vin.empty());`)

### Description
`checkWitnessMalleation` enters the commitpos-present branch and
dereferences `coinbase.inputs[0]` without verifying `inputs.len > 0`.
Core asserts the same condition (line 3877) — both implementations
rely on upstream sanity checks. Zig's RuntimeSafety mode produces a
clear panic on out-of-bounds; ReleaseFast omits the bounds check and
produces undefined behaviour.

### Excerpt
```zig
if (commitpos != null) {
    // Gate 1: coinbase witness stack must have exactly 1 element.
    // Reference: validation.cpp:3880
    const coinbase = &block.transactions[0];
    const witness_stack = coinbase.inputs[0].witness;  // ← unguarded
    if (witness_stack.len != 1 or witness_stack[0].len != 32) {
        return ValidationError.BadWitnessCommitment;
    }
```

### Impact
On real chains the path is never hit (coinbase has exactly one input
by checkTransactionSanity). On a fuzz harness building synthetic
blocks bypassing checkTransactionSanity, ReleaseFast clearbit triggers
UB.

---

## BUG-12 — getWitnessCommitmentIndex prefix-match silently truncates on short coinbase outputs (defensive, not a bug per se)
- **Severity:** P3 (defensive nit; documents Core parity)
- **File:** `clearbit/src/validation.zig:1860-1873`
- **Core ref:** `bitcoin-core/src/consensus/validation.h:147-165`

### Description
clearbit's `getWitnessCommitmentIndex` correctly mirrors Core: requires
`spk.len >= MINIMUM_WITNESS_COMMITMENT (38)` AND `spk[0..6] == magic
{0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed}`. **No bug**, but a note: the
"last match wins" comment is correct (Core line 161 `commitpos = o;`
keeps updating).

The audit hint asked for grep on `commitpos = o;` — verified parity.

### Impact
None — flagged here to confirm parity rather than divergence.

---

## BUG-13 — Coinbase wtxid hardcoded to all-zeros without consistency check
- **Severity:** P3 (matches Core spec; flagged for completeness)
- **File:** `clearbit/src/validation.zig:1911`,
  `clearbit/src/block_template.zig:710-711`
- **Core ref:** `bitcoin-core/src/consensus/merkle.cpp:80-83`

### Description
Both clearbit and Core fix the coinbase wtxid at all-zeros for the
witness Merkle root computation. clearbit at validation.zig:1911:
`wtxids[0] = [_]u8{0} ** 32; // coinbase wtxid is all zeros`. This is
correct per BIP-141 (the *real* coinbase wtxid is non-zero because
coinbase carries the 32-byte witness nonce, but the spec requires the
all-zeros sentinel for the merkle).

A consistency check (assert `coinbase.computeWtxid()` ≠ all-zeros in
debug builds) would catch a future bug where someone changes the
hashing primitive — but is not required for consensus. Flagged for
completeness.

### Impact
None — flagged here to confirm parity.

---

## BUG-14 — `flags.verify_witness` set unconditionally for ALL block heights (matches Core; flagged for review)
- **Severity:** P3 (parity-with-Core)
- **File:** `clearbit/src/validation.zig:157`
- **Core ref:** `bitcoin-core/src/validation.cpp:2262`

### Description
clearbit sets `flags.verify_witness = true` unconditionally in
`getBlockScriptFlags` regardless of `height >= segwit_height`. This
matches Core's behaviour at validation.cpp:2262
(`flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT}`,
unconditional). Core comments at 2256-2261 explain: *"For simplicity,
always leave P2SH+WITNESS+TAPROOT on except for the two violating
blocks"*. clearbit handles the BIP-16/Taproot exception blocks too
(lines 172-183).

### Impact
None — flagged here to confirm parity (a future audit might flag this
without context as a divergence).

---

## BUG-15 — UpdateUncommittedBlockStructures (dummy-nonce backfill) absent
- **Severity:** P2 (mining-only)
- **File:** clearbit has no analogue;
  `clearbit/src/block_template.zig::constructCoinbaseWithCommitment`
  always builds the witness stack from scratch (line 547-553)
- **Core ref:** `bitcoin-core/src/validation.cpp:3985-3995`
  (`UpdateUncommittedBlockStructures`)

### Description
Core's `UpdateUncommittedBlockStructures` runs in `submitblock` /
`generateBlock` paths: if the block has a commitment output but
the coinbase witness is empty (because the submitter forgot to add it),
Core silently backfills a 32-byte zero witness nonce. clearbit's
template builder constructs the witness from scratch; an external
submitter passing a commitment-bearing block with an empty coinbase
witness gets rejected at CheckWitnessMalleation gate 1
(`bad-witness-nonce-size`).

### Excerpt — Core's backfill
```cpp
void ChainstateManager::UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev) const
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT
        && DeploymentActiveAfter(pindexPrev, *this, Consensus::DEPLOYMENT_SEGWIT)
        && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}
```

### Impact
Operator-facing: a `submitblock` RPC sent by a non-clearbit miner
(e.g. external pool software) that has a witness commitment but no
coinbase witness nonce will be rejected by clearbit when Core would
accept (and silently backfill). Cross-stack miner compatibility hazard.

---

## BUG-16 — SegwitSighashCache.init has CompactSize two-tier bug too (same as BUG-2)
- **Severity:** P0-LATENT (dead-code; folded into BUG-4)
- **File:** `clearbit/src/crypto.zig:1359-1366`
- **Core ref:** see BUG-2

### Description
The output CompactSize encoding inside `SegwitSighashCache.init` has
the same bug as `segwitSighash` (BUG-2). For output scripts ≥ 64 KB,
the encoding silently falls through both if-branches and the
script_pubkey is hashed WITHOUT a length prefix — strictly different
from Core's preimage.

### Excerpt
```zig
// CompactSize for script length
if (output.script_pubkey.len < 0xFD) {
    outputs_hasher.update(&[_]u8{@intCast(output.script_pubkey.len)});
} else if (output.script_pubkey.len <= 0xFFFF) {
    var size_buf: [3]u8 = undefined;
    size_buf[0] = 0xFD;
    std.mem.writeInt(u16, size_buf[1..3], @intCast(output.script_pubkey.len), .little);
    outputs_hasher.update(&size_buf);
}
// ← no else branch: output script ≥ 64 KB has zero CompactSize prefix written
outputs_hasher.update(output.script_pubkey);
```

Worse than BUG-2: the missing `else` branch silently omits the
CompactSize prefix entirely (instead of crashing). Latent because the
cache has no callers.

### Impact
Folded under BUG-4 (dead module). Reiterated here for completeness.

---

## BUG-17 — Two-pipeline guard absent on BIP-143 sighash divergence
- **Severity:** P3 (architectural smell)
- **File:** `clearbit/src/crypto.zig:1382` (production segwitSighash) +
  `clearbit/src/crypto.zig:1329` (dead SegwitSighashCache);
  clearbit has no test that compares the two paths' output on identical
  inputs.
- **Core ref:** Core ships a single sighash codepath (template-specialised);
  no two-pipeline hazard exists.

### Description
clearbit ships a working `segwitSighash` AND a dead
`SegwitSighashCache` that uses different output-hashing semantics
(triple-SHA256 vs the production double-SHA256). A regression test
that fuzzes both implementations against identical txs would have
caught BUG-4 on first run. No such guard exists.

This is the **two-pipeline guard absence** fleet pattern: when a
codebase ships both a "fast cached" and a "slow recomputed" version of
the same logic, a parity assertion between them is mandatory or one
will silently drift.

### Impact
Architectural: future PRs wiring up the cache risk a silent consensus
split. Recommend either deleting `SegwitSighashCache` or adding a
parity-vs-`segwitSighash` golden-vector test.

---

## BUG-18 — segwitSighash hash_type written as u32 instead of int32 (cosmetic per BIP-143)
- **Severity:** P3 (cosmetic; bit-identical encoding)
- **File:** `clearbit/src/crypto.zig:1495`
- **Core ref:** `bitcoin-core/src/script/interpreter.cpp:1675`

### Description
clearbit writes `try writer.writeInt(u32, hash_type);`. Core writes
`ss << nHashType;` where `nHashType` is `int32_t`. The little-endian
byte encoding is identical for all in-range hash types (1, 2, 3, 0x81,
0x82, 0x83) so this is purely cosmetic. Flagged for future audits to
avoid spurious re-discovery.

### Impact
None.

---

## Cross-cuts / fleet-pattern smells

- **comment-as-confession (5+ instances in this audit):**
  - `block_template.zig:1816` *"Simplified: in full implementation would
    reconstruct coinbase"* (BUG-3)
  - `block_template.zig:1875` *"simplified; accurate for <= 252 inputs"*
    (BUG-9)
  - `block_template.zig:1882` *"simplified"* (BUG-9 cross-cite)
  - `validation.zig:836-839` empty-body `if (coinbase_value > subsidy)`
    with `// Note: In full validation, we'd add total_fees here` (BUG-7)
  - `block_template.zig:1899-1906` always-false `or blk: { break :blk false; }`
    with comment hinting at the intended logic (BUG-10)

- **dead-module-with-latent-bug**: `SegwitSighashCache` (BUG-4 + BUG-16)
  is the canonical example. Public struct, zero callers, both a
  hashing-semantic bug (triple-SHA256) and a buffer-overflow trap.
  Matches the fleet-wide pattern catalogued in
  `MEMORY.md` ("declare-init-deinit-but-never-populate").

- **two-pipeline guard absent**: BUG-17. Production `segwitSighash`
  and dead `SegwitSighashCache` use different output-hashing semantics
  with no parity assertion.

- **error-code semantic drift**: BUG-5 + BUG-6. clearbit returns
  one of its general `WitnessUnexpected` /
  `WitnessProgramMismatch` errors where Core returns a dedicated
  enum value (`SCRIPT_ERR_WITNESS_MALLEATED`,
  `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`). Mempool
  reject-reason scoring diverges.

- **operator-knob simplification**: BUG-9 + BUG-10 + BUG-15. Mining/
  template path uses approximations or omits Core's
  `UpdateUncommittedBlockStructures` backfill. Cross-stack miner
  compatibility hazard.

- **fleet pattern (BIP-143 W142): inline CompactSize re-encoding in
  crypto modules instead of using the canonical serializer.** Both
  clearbit hot-path bugs (BUG-2, BUG-16) come from re-implementing
  CompactSize inline when `serialize.Writer.writeCompactSize` is right
  there. Recommend a project-wide grep audit for *every* inline
  CompactSize encoding outside `serialize.zig`.
