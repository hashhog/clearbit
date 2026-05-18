# W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's PSBT (Partially Signed Bitcoin Transaction) implementation
vs Bitcoin Core
(`bitcoin-core/src/psbt.h`,
 `bitcoin-core/src/psbt.cpp`,
 `bitcoin-core/src/wallet/rpc/spend.cpp`,
 `bitcoin-core/src/rpc/rawtransaction.cpp` PSBT entrypoints).
**BIPs:** 174 (PSBT v0), 370 (PSBT v2), 371 (Taproot fields), 373 (MuSig2 fields).
**Files in scope:** `src/psbt.zig` (2654 LOC), `src/wallet.zig` (PSBT fill / sign /
psbtBumpFee), `src/rpc.zig` (createpsbt / decodepsbt / combinepsbt / finalizepsbt
/ analyzepsbt / converttopsbt / walletcreatefundedpsbt / psbtbumpfee).
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w137` (folded into `zig build test`).
**Related prior waves:** W31 / W38 / W47 (P2SH/P2WSH commitments + finalizer
multisig); W53 (decodepsbt UniValue format); W118 (psbtBumpFee). This wave
audits the BIP-174 / BIP-370 / BIP-371 wire format & semantic invariants
that those waves did NOT close — primarily duplicate-key detection, BIP-174
deserialize-time invariants, BIP-370 (PSBT v2) entire wire format, BIP-371
output mappings on serialization, and the assorted RPCs that don't exist
yet (joinpsbts, utxoupdatepsbt, walletprocesspsbt, descriptorprocesspsbt).

## Summary

clearbit ships a partial **PSBT v0 (BIP-174)** implementation that round-trips
the common happy path (unsigned tx + witness UTXO + partial sigs +
finalize-then-extract for P2PKH / P2WPKH / P2SH-P2WPKH / P2SH-multisig /
P2WSH-multisig / P2SH-P2WSH-multisig) but **diverges substantially** from
Core's deserialize-time invariants and is **entirely missing BIP-370 (PSBT
v2)** and several BIP-371 output-side mappings. The module docstring
claims "BIP174/370" support but BIP-370 has zero wire types, zero RPCs,
zero tests — `PSBT_HIGHEST_VERSION` is 0 (matching Core's intentional
non-support) so the user-visible surface is the same, but the docstring
is **wrong** (BUG-1).

Key findings ranked by severity:

- **HIGH-CDIV: No duplicate-key detection on deserialize.** Core
  `psbt.h:480` allocates a per-map `std::set<std::vector<unsigned char>>
  key_lookup` and on every key entry checks `!key_lookup.emplace(key).second`
  and throws "Duplicate Key, ... already provided". clearbit's
  `parseInputMap` / `parseOutputMap` / global-map reader just calls
  `input.partial_sigs.put(...)` (which **silently overwrites**) and for
  scalar fields (`witness_utxo`, `redeem_script`, etc.) blindly overwrites
  the optional field. An attacker can ship a PSBT with two `witness_utxo`
  entries carrying different amounts; clearbit happily keeps the last one
  → signer signs the wrong amount, fee accounting is silently wrong.
  See BUG-3 (the universal bug — 12 fields, one map). (G2.)

- **HIGH-CDIV: No non-witness UTXO ↔ outpoint hash validation on
  deserialize.** Core `psbt.h:1371-1378` checks `input.non_witness_utxo->
  GetHash() != tx->vin[i].prevout.hash` and throws "Non-witness UTXO does
  not match outpoint hash"; clearbit's deserialize just sets
  `input.non_witness_utxo = readTransaction(...)` with no check
  (`psbt.zig:1597`). `addInputNonWitnessUtxo` (Updater path) DOES check
  the txid (`psbt.zig:660-674`), but the deserialize path is the
  attacker-controlled entry point. See BUG-4. (G3.)

- **HIGH-CDIV: No `key.size() == 1` length check on scalar key types.**
  Core consistently checks `key.size() != 1` on every singleton key type
  (`witness_utxo`, `sighash`, `redeem_script`, `witness_script`,
  `final_scriptSig`, `final_scriptWitness`, `tap_internal_key`,
  `tap_merkle_root`, `tap_key_sig`, …) and throws "X key is more than
  one byte type" if extra bytes follow the type byte. clearbit drops the
  trailing `key_data` silently on every scalar-keyed type. See BUG-5. (G4.)

- **HIGH-CDIV: No `partial_sigs` pubkey validity check.** Core
  `psbt.h:531-535` constructs a `CPubKey` from the key bytes and rejects
  with "Invalid pubkey" if `IsFullyValid()` is false; further checks
  `partial_sigs.contains(pubkey.GetID())` to detect duplicate-keyed-by-
  CKeyID (i.e. both compressed and uncompressed forms of the same key).
  clearbit accepts any 33-byte or 65-byte payload, stores it as `[33]u8`
  (silently truncating 65-byte uncompressed pubkeys to the first 33
  bytes — losing the y-coordinate parity AND any uniqueness vs. the
  compressed form). See BUG-6. (G5.)

- **HIGH-CDIV: No DER-signature validity check on `PSBT_IN_PARTIAL_SIG`
  value.** Core `psbt.h:544` calls `CheckSignatureEncoding(sig,
  SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)` and rejects
  on invalid encoding; clearbit takes any byte string verbatim. See
  BUG-7. (G6.)

- **HIGH-MISSING: `PSBT_GLOBAL_XPUB` (BIP-174 0x01) is parsed-but-dropped
  on deserialize, and never serialized.** The `xpubs` HashMap exists on
  `Psbt` (`psbt.zig:558`) but the global-map reader has no case for
  `PSBT_GLOBAL_XPUB` (`psbt.zig:1418-1437`) so it lands in the `unknown`
  bucket (and the explicit `TODO: Serialize xpubs` comment at
  `psbt.zig:1231` is honoured by emitting nothing on the wire). Round-
  tripping a PSBT with a global xpub via clearbit silently drops it.
  Affects hardware-wallet "show me where this key originates" UX and
  multisig coordinator workflows. See BUG-8. (G7.)

- **HIGH-MISSING: No `PSBT_IN_/OUT_PROPRIETARY` (0xFC) parser at all.**
  Core has a per-key proprietary type that downstream wallets use for
  vendor-specific extensions (e.g. Coldcard pre-flighted spending
  conditions). clearbit drops them into the `unknown` bucket and uses
  Wyhash on the key — collision-resistant but **not** sorted on serialize,
  so a round-trip mutates the byte order. See BUG-9. (G8.)

- **HIGH-MISSING: Input-side MuSig2 fields (BIP-373 0x1a/0x1b/0x1c) not
  parsed.** Core `psbt.h:56-58` defines `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS`
  (0x1a), `PSBT_IN_MUSIG2_PUB_NONCE` (0x1b), `PSBT_IN_MUSIG2_PARTIAL_SIG`
  (0x1c). clearbit defines none of them. The `PsbtInput` struct has no
  MuSig2 fields. The output-side participant pubkeys (0x08) IS supported,
  asymmetrically, which is even more confusing because output-side alone
  is useless without the input-side flow. See BUG-10. (G9.)

- **HIGH-MISSING: `PSBT_OUT_TAP_TREE` (BIP-371 0x06) parses but does NOT
  validate.** Core `psbt.h:1042-1064` parses the value as a vector of
  `(depth, leaf_ver, script)` triples, asserts `depth <=
  TAPROOT_CONTROL_MAX_NODE_COUNT (128)` and `(leaf_ver & ~TAPROOT_LEAF_MASK) ==
  0` per leaf, AND calls `TaprootBuilder::Add()` plus `builder.IsComplete()`
  to verify the tree is structurally valid; clearbit stores the raw bytes
  as `output.tap_tree = ?[]const u8` (`psbt.zig:1793`) with NO depth check,
  NO leaf-version check, and NO structural-validity check. An attacker
  can ship a `tap_tree` with depth=255 and `leaf_ver=0xff` and clearbit
  will accept it; round-trip preserves the garbage; downstream consumers
  trusting the field will misbehave. See BUG-11. (G10.)

- **HIGH-MISSING: BIP-371 output-side fields (`PSBT_OUT_TAP_BIP32_DERIVATION`
  + `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS`) parsed but NOT serialized.**
  `parseOutputMap` (`psbt.zig:1795-1843`) handles types 0x07 and 0x08,
  but `serializeOutputMap` (`psbt.zig:1326-1354`) only emits redeem_script,
  witness_script, BIP32. The fields are clone-preserved but go out as
  empty on the wire. Round-trip is lossy: deserialize → serialize drops
  the data. See BUG-12. (G11.)

- **HIGH-MISSING: BIP-371 input-side taproot fields NOT serialized.**
  Same shape: `parseInputMap` handles types 0x13/0x14/0x15/0x16/0x17/0x18,
  but `serializeInputMap` (`psbt.zig:1237-1324`) only emits 0x00-0x08
  (and skips 0x09/0x0a/0x0b/0x0c/0x0d preimages — which IS the bug below).
  See BUG-13. (G12.)

- **HIGH-MISSING: hash preimage maps (`ripemd160_preimages`,
  `sha256_preimages`, `hash160_preimages`, `hash256_preimages`) NOT
  serialized.** The fields are parsed (or rather, would be — see BUG-14)
  but never emitted. `serializeInputMap` has zero references to any of
  the four preimage maps. Even more confusingly, parseInputMap has zero
  case arms for `PSBT_IN_RIPEMD160 = 0x0A`, `PSBT_IN_SHA256 = 0x0B`,
  `PSBT_IN_HASH160 = 0x0C`, `PSBT_IN_HASH256 = 0x0D` — the constants
  exist (`psbt.zig:57-60`) but no parser uses them. The `PsbtInput`
  struct has the four maps (`psbt.zig:273-276`) and they get initialized
  + deinit'd, but they are populated by no code path and emitted by no
  code path. Pure dead-storage. See BUG-14. (G13.)

- **HIGH-MISSING: `PSBT_GLOBAL_PROPRIETARY` (0xFC) NOT parsed.** Same
  shape as BUG-9 but at the global-map level. Falls into `unknown` and
  loses the proprietary subtype/identifier structure. See BUG-15. (G14.)

- **MED-CDIV: `PSBT_IN_BIP32_DERIVATION` accepts only 33-byte (compressed)
  keys, drops uncompressed.** Core `psbt.h:153` accepts both `CPubKey::SIZE`
  (65) and `CPubKey::COMPRESSED_SIZE` (33) for the key length. clearbit
  has `if (key_data.len != 33) return InvalidKeyLength` (`psbt.zig:1628`),
  rejecting 65-byte (uncompressed) pubkeys outright. Same applies to
  `PSBT_OUT_BIP32_DERIVATION` (`psbt.zig:1766`). See BUG-16. (G15.)

- **MED-CDIV: No fingerprint+path size sanity check.** Core
  `psbt.h:127-129` rejects HD key paths where `length % 4 || length == 0`
  with "Invalid length for HD key path". clearbit checks `value.len < 4 or
  (value.len - 4) % 4 != 0` (`psbt.zig:1629`) — close but not equivalent:
  Core's `length` is the post-compact-size byte count of the keyorigin,
  clearbit's `value.len` is the total value bytes (includes the
  fingerprint). Net effect: identical bounds in the BIP32 case, but the
  cross-impl semantic differs (Core throws on `length == 0`; clearbit
  succeeds on `value.len == 4` which is fingerprint-only no-path, which
  Core actually accepts as an empty path). See BUG-17 for the inverse:
  clearbit rejects empty-path with `value.len < 4`, but Core accepts
  fingerprint-only as a valid 0-depth derivation. (G16.)

- **MED-MISSING: No `MAX_FILE_SIZE_PSBT` check on input.** Core defines
  `MAX_FILE_SIZE_PSBT = 100_000_000` (100 MB) and the `streamsize` enforces
  it at deserialize. clearbit has `MAX_PSBT_SIZE = 100_000_000` as a
  constant but never references it anywhere — no length check on input
  to `Psbt.deserialize` or `Psbt.fromBase64`. A 4 GiB PSBT base64 string
  will be allocated whole in `Psbt.fromBase64` before deserialization
  fails. DOS amplifier. See BUG-18. (G17.)

- **MED-CDIV: Separator-not-found is silently accepted.** Core
  `psbt.h:865-867` / `:1126-1128` / `:1354-1356` throws "Separator is
  missing at the end of a [...] map" if the input stream ends without
  the explicit `0x00` separator (i.e. truncated PSBT). clearbit's
  `parseInputMap` / `parseOutputMap` / global reader loop is:

  ```zig
  while (true) {
      const key_len = try reader.readCompactSize();  // may throw EndOfStream
      if (key_len == 0) break; // separator
      ...
  }
  ```

  If the stream ends mid-value but key_len was already read, the
  subsequent reads throw EndOfStream (good); but if the stream ends
  cleanly after the last KV without the 0x00 separator, `readCompactSize`
  throws EndOfStream which is mapped to a generic `EndOfStream` error,
  NOT a domain-specific "MissingSeparator" — even though the error
  variant exists in `PsbtError`. The downstream RPC handler then reports
  a generic decode error instead of the Core-specific message. Cross-impl
  fuzz suites that match on error strings will diverge. See BUG-19. (G18.)

- **MED-MISSING: No `PSBT_IN_SIGHASH` value range check.** Core `psbt.h:559`
  reads the sighash as a signed `int` via `UnserializeFromVector(s,
  sighash)`. Most consumers later validate it's one of {1,2,3,0x81,0x82,
  0x83} or SIGHASH_DEFAULT (0). clearbit accepts any u32 (including
  0xDEADBEEF) and stores it (`psbt.zig:1619`). Downstream finalizer
  doesn't validate either. Cross-impl PSBT consumers will receive a
  malformed PSBT validated by clearbit. See BUG-20. (G19.)

- **MED-MISSING: `RemoveUnnecessaryTransactions` (Core `psbt.cpp:514`)
  not implemented.** Core's helper drops `non_witness_utxo` when all
  inputs are segwit-v1 (taproot) with non-ANYONECANPAY sighash, since
  taproot signs the amount directly. clearbit never drops them, so
  taproot-only PSBTs are 32× larger than necessary on the wire. Not a
  consensus bug but a size-bloat. See BUG-21. (G20.)

- **MED-MISSING: `PSBTInputSigned` / `PSBTInputSignedAndVerified` not
  exposed.** Core has both as free functions; clearbit has only the
  `PsbtInput.isFinalized` method, which is the same as
  `PSBTInputSigned` but the `…AndVerified` variant (which actually runs
  the script interpreter against the final scriptSig + witness) does
  not exist. Means `extract()` on a PSBT with a malformed
  `final_script_witness` would emit a tx that any later script-verifier
  rejects. Latent bug; would matter on hostile-input fuzz. See BUG-22. (G21.)

- **MED-CDIV: `analyzepsbt` doesn't compute `next_role` correctly for
  the SIGNER role.** Core's `AnalyzePSBT` (`node/psbt.cpp`) determines
  the next role per-input (UPDATER if missing UTXO, SIGNER if missing
  signature for a known pubkey, FINALIZER if signature complete, etc.).
  clearbit's `analyze` (`psbt.zig:1520-1575`) computes one global
  next_role based on aggregate state (signed/finalized counts). The
  Core JSON shape includes a per-input `next` field; clearbit's
  `handleAnalyzePsbt` (`rpc.zig:8003-8059`) doesn't emit it. JSON-RPC
  consumers comparing to Core will see structural differences. See BUG-23. (G22.)

- **MED-MISSING: `joinpsbts` RPC missing.** Core's `joinpsbts`
  (`rpc/rawtransaction.cpp:1778`) joins multiple distinct-transaction
  PSBTs into one, summing inputs + outputs. clearbit's dispatch table
  (`rpc.zig:3061-3071`) has no `joinpsbts` arm. See BUG-24. (G23.)

- **MED-MISSING: `utxoupdatepsbt` RPC missing.** Core's `utxoupdatepsbt`
  (`rpc/rawtransaction.cpp:1731`) updates a PSBT with UTXO data from
  the active chain + optional descriptors. clearbit's dispatch table
  has no arm. See BUG-25. (G24.)

- **MED-MISSING: `walletprocesspsbt` RPC missing.** Core's
  `walletprocesspsbt` (`wallet/rpc/spend.cpp:1569`) signs / updates /
  finalizes a PSBT using wallet keys. clearbit has `walletcreatefundedpsbt`
  + `psbtbumpfee` (both wallet-coupled) but no `walletprocesspsbt`. See
  BUG-26. (G25.)

- **MED-MISSING: `descriptorprocesspsbt` RPC missing.** Core's
  `descriptorprocesspsbt` (`wallet/rpc/spend.cpp` and standalone)
  processes a PSBT given a descriptor without needing a wallet.
  clearbit has descriptor support (W131) but no PSBT bridge. See BUG-27. (G26.)

- **LOW-MISSING: `extract()` does not validate the produced tx.** Core's
  `FinalizeAndExtractPSBT` (`psbt.cpp:567`) calls `FinalizePSBT` first
  (which runs the signature check); clearbit's `extract()` only checks
  `isComplete()` (final_script_sig OR final_script_witness present) and
  emits the tx — no script verification. Hostile PSBT with valid-shape
  but invalid-signature finalization extracts to a broadcast-time-failing
  tx. See BUG-28. (G27.)

- **LOW-DIVERGE: `combine()` accepts PSBTs with structurally-different
  underlying transactions.** Core's `Merge` (`psbt.cpp:30`) checks
  `tx->GetHash() != psbt.tx->GetHash()` and refuses; clearbit's
  `mergeFrom` only checks `inputs.len != other.inputs.len` (`psbt.zig:754`).
  Two PSBTs with the same input count but different prevouts will combine
  silently, producing a PSBT whose partial sigs no longer correspond to
  the new outpoints. See BUG-29. (G28.)

- **LOW-MISSING: `Psbt.IsNull()` semantic predicate not implemented.**
  Core's `PartiallySignedTransaction::IsNull()` returns true if the PSBT
  is empty/uninitialized; clearbit has no analog. Used by Core for cheap
  "did we get a real PSBT?" checks. See BUG-30. (G29.)

- **LOW-CDIV: Module docstring lies about BIP-370 support.** Line 1 of
  `psbt.zig`: `//! PSBT (Partially Signed Bitcoin Transaction) - BIP174/370`.
  BIP-370 (PSBT v2) wire format requires `PSBT_GLOBAL_TX_VERSION` (0x02),
  `PSBT_GLOBAL_FALLBACK_LOCKTIME` (0x03), `PSBT_GLOBAL_INPUT_COUNT` (0x04),
  `PSBT_GLOBAL_OUTPUT_COUNT` (0x05), `PSBT_GLOBAL_TX_MODIFIABLE` (0x06),
  plus per-input/output `PSBT_IN_PREVIOUS_TXID` (0x0E), `PSBT_IN_OUTPUT_INDEX`
  (0x0F), `PSBT_IN_SEQUENCE` (0x10), `PSBT_IN_REQUIRED_TIME_LOCKTIME` (0x11),
  `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME` (0x12), `PSBT_OUT_AMOUNT` (0x03),
  `PSBT_OUT_SCRIPT` (0x04). NONE are defined or handled. The constant
  `PSBT_HIGHEST_VERSION = 0` rejects any v2 PSBT (matching Core behaviour),
  but the docstring is misleading — Core also rejects v2 PSBTs, but
  Core's docstring is honest about it. See BUG-1. (G30.)

## 30-gate audit matrix

| # | Gate | Subject | Status | Bug |
|---|------|---------|--------|-----|
| G1 | Module docstring accurately describes supported BIPs | Docs | DIVERGE | BUG-1 |
| G2 | `key_lookup` set on deserialize prevents duplicate keys | Wire format | MISSING | BUG-3 |
| G3 | `non_witness_utxo` hash matches `tx.vin[i].prevout.hash` on deserialize | Wire format | MISSING | BUG-4 |
| G4 | Singleton key types reject `key.size() != 1` | Wire format | MISSING | BUG-5 |
| G5 | `PSBT_IN_PARTIAL_SIG` pubkey-in-key is `IsFullyValid` | Wire format | MISSING | BUG-6 |
| G6 | `PSBT_IN_PARTIAL_SIG` value passes `CheckSignatureEncoding(DERSIG|STRICTENC)` | Wire format | MISSING | BUG-7 |
| G7 | `PSBT_GLOBAL_XPUB` (0x01) parsed AND serialized | BIP-174 | MISSING | BUG-8 |
| G8 | `PSBT_{IN,OUT}_PROPRIETARY` (0xFC) parsed AND serialized | BIP-174 | MISSING | BUG-9 |
| G9 | Input-side MuSig2 fields (0x1a/0x1b/0x1c) parsed AND serialized | BIP-373 | MISSING | BUG-10 |
| G10 | `PSBT_OUT_TAP_TREE` depth ≤ 128, leaf_ver masked, builder.IsComplete | BIP-371 | MISSING | BUG-11 |
| G11 | BIP-371 output fields (TAP_BIP32, MUSIG2) serialized on wire | BIP-371 | MISSING | BUG-12 |
| G12 | BIP-371 input fields (TAP_KEY_SIG..TAP_MERKLE_ROOT) serialized on wire | BIP-371 | MISSING | BUG-13 |
| G13 | Hash preimage maps (RIPEMD160/SHA256/HASH160/HASH256) parsed AND serialized | BIP-174 | MISSING | BUG-14 |
| G14 | `PSBT_GLOBAL_PROPRIETARY` (0xFC) parsed AND serialized | BIP-174 | MISSING | BUG-15 |
| G15 | BIP32 derivation accepts both 33-byte and 65-byte pubkeys | Wire format | DIVERGE | BUG-16 |
| G16 | HD key path length is multiple of 4 AND nonzero | Wire format | DIVERGE | BUG-17 |
| G17 | `MAX_FILE_SIZE_PSBT` (100 MB) enforced on `deserialize` input | DOS | MISSING | BUG-18 |
| G18 | Missing separator at EOF maps to `PsbtError.MissingSeparator` not generic `EndOfStream` | Error parity | DIVERGE | BUG-19 |
| G19 | `PSBT_IN_SIGHASH` value range-checked | Wire format | MISSING | BUG-20 |
| G20 | `RemoveUnnecessaryTransactions` drops non-witness UTXO on segwit-v1 | Size | MISSING | BUG-21 |
| G21 | `PSBTInputSignedAndVerified` runs the script interpreter | Correctness | MISSING | BUG-22 |
| G22 | `analyzepsbt` emits per-input `next` role | RPC parity | DIVERGE | BUG-23 |
| G23 | `joinpsbts` RPC | RPC parity | MISSING | BUG-24 |
| G24 | `utxoupdatepsbt` RPC | RPC parity | MISSING | BUG-25 |
| G25 | `walletprocesspsbt` RPC | RPC parity | MISSING | BUG-26 |
| G26 | `descriptorprocesspsbt` RPC | RPC parity | MISSING | BUG-27 |
| G27 | `extract()` validates signed-and-verified state | Correctness | MISSING | BUG-28 |
| G28 | `Merge` refuses PSBTs with different `tx.GetHash()` | Correctness | DIVERGE | BUG-29 |
| G29 | `Psbt.IsNull()` predicate | API | MISSING | BUG-30 |
| G30 | Any BIP-370 (PSBT v2) wire types defined | BIP-370 | MISSING | BUG-2 |

## Bug catalogue (28 BUGs total — 23 MISSING + 5 DIVERGE)

### BUG-1 (G1, LOW-CDIV): Module docstring claims BIP-174/370 support but BIP-370 is absent
**Severity:** LOW (documentation drift). The `psbt.zig` module header
says `BIP174/370` but PSBT v2 (BIP-370) defines 12 new wire types
(`PSBT_GLOBAL_TX_VERSION`, `PSBT_GLOBAL_FALLBACK_LOCKTIME`,
`PSBT_GLOBAL_INPUT_COUNT`, `PSBT_GLOBAL_OUTPUT_COUNT`,
`PSBT_GLOBAL_TX_MODIFIABLE`, `PSBT_IN_PREVIOUS_TXID`,
`PSBT_IN_OUTPUT_INDEX`, `PSBT_IN_SEQUENCE`,
`PSBT_IN_REQUIRED_TIME_LOCKTIME`, `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME`,
`PSBT_OUT_AMOUNT`, `PSBT_OUT_SCRIPT`); none are defined or handled.
`PSBT_HIGHEST_VERSION = 0` (matching Core) means any v2 PSBT is
rejected with `UnsupportedVersion`, which is the **correct** behaviour
— but advertising support is wrong.
**Fix:** change docstring to `BIP-174 PSBT v0 (+ BIP-371 partial /
BIP-373 partial)`.

### BUG-2 (G30, INFO): No BIP-370 (PSBT v2) wire types defined
**Severity:** INFO (Core also rejects v2; consistent behaviour). Listed
here as a discovery-only gate because the docstring claims support.
Status: clearbit is Core-parity (both reject v2) which is correct.
**Fix:** none required for parity; close BUG-1 to align docs.

### BUG-3 (G2, HIGH-CDIV): No duplicate-key detection on deserialize
**Severity:** HIGH-CDIV. Core `psbt.h:480` allocates a per-map
`std::set<std::vector<unsigned char>> key_lookup` and on every key
entry checks `!key_lookup.emplace(key).second` to detect duplicates,
throwing "Duplicate Key, ... already provided". clearbit's
`parseInputMap` / `parseOutputMap` / global reader has no such map. The
result is that for scalar fields stored in `?T` options
(`witness_utxo`, `redeem_script`, `witness_script`, `final_script_sig`,
`final_script_witness`, `tap_internal_key`, `tap_merkle_root`,
`tap_key_sig`, `sighash_type`, `non_witness_utxo`), the second
occurrence silently overwrites the first. For HashMap-keyed fields
(`partial_sigs`, `bip32_derivation`, `tap_bip32_derivation`,
`tap_script_sigs` (an ArrayList so APPENDS — also wrong),
`tap_leaf_scripts` (ditto)), behaviour depends on container: HashMap
silently overwrites, ArrayList silently appends two copies. Attack
vectors:
1. Send a PSBT with two `witness_utxo` entries carrying different
   amounts. Clearbit signs the one it keeps; if it's the smaller
   amount, the signature commits to the wrong amount.
2. Send a PSBT with two `redeem_script` entries; finalizer commits to
   whichever survived — silent change.
3. Send a PSBT with two `tap_leaf_scripts` entries with the same
   control block but different scripts; ArrayList stores both and
   the round-trip duplicates the wire data.
**Fix:** allocate a `std.AutoHashMap([]const u8, void) key_lookup` per
map, check `!key_lookup.put(key, {}).found_existing` before processing
each entry, raise `PsbtError.DuplicateKey`. The error variant already
exists (`psbt.zig:88`).

### BUG-4 (G3, HIGH-CDIV): No non-witness UTXO ↔ outpoint hash validation on deserialize
**Severity:** HIGH-CDIV. Core `psbt.h:1371-1378`:
```cpp
if (input.non_witness_utxo) {
    if (input.non_witness_utxo->GetHash() != tx->vin[i].prevout.hash) {
        throw std::ios_base::failure("Non-witness UTXO does not match outpoint hash");
    }
    if (tx->vin[i].prevout.n >= input.non_witness_utxo->vout.size()) {
        throw std::ios_base::failure("Input specifies output index that does not exist");
    }
}
```
clearbit's deserialize path (`psbt.zig:1595`) just sets
`input.non_witness_utxo = try readTransaction(...)` without ANY check.
`addInputNonWitnessUtxo` (the Updater API at `psbt.zig:656-676`) does
verify the hash + emits the byte-reversal correctly, but that's the
in-process happy path; the attacker-facing deserialize is wide open.
Consequence: a PSBT carrying a `non_witness_utxo` whose txid does NOT
match the input's prevout.hash is happily accepted; the Signer will
read the wrong scriptPubKey + amount and produce a signature that no
verifier accepts. From the user's perspective, the PSBT looks
"funded" but the broadcast tx fails. Worse, if the user trusts the
non-witness UTXO for fee accounting (`analyze`), the displayed fee
will be wrong by an attacker-controlled amount.
**Fix:** in `parseInputMap`'s `PSBT_IN_NON_WITNESS_UTXO` arm, hash the
parsed tx (with witness — Core uses the raw txid) and compare against
the corresponding `unsigned_tx.inputs[i].previous_output.hash`. Throw
`PsbtError.NonWitnessUtxoMismatch` (already defined at `psbt.zig:97`)
on mismatch. Note: `parseInputMap` doesn't currently have access to
the unsigned-tx index `i`; need to thread it through.

### BUG-5 (G4, HIGH-CDIV): No `key.size() == 1` length check on singleton key types
**Severity:** HIGH-CDIV. Core consistently checks `key.size() != 1` on
every singleton key type (`psbt.h:509`, `:519`, `:555`, `:566`, `:576`,
`:591`, `:600`, …). clearbit doesn't. The bug shape: read keys like
`<0x01><extra bytes>` where the type is `PSBT_IN_WITNESS_UTXO` (0x01)
and trailing `key_data` carries unrecognized bytes — clearbit ignores
the trailing bytes silently and processes the value as if the key were
just `0x01`. Cross-impl fuzzers will diverge: Core throws "Witness utxo
key is more than one byte type", clearbit silently accepts.
**Fix:** add `if (key_data.len != 0) return PsbtError.InvalidKeyLength`
to every singleton-keyed switch arm.

### BUG-6 (G5, HIGH-CDIV): `PSBT_IN_PARTIAL_SIG` pubkey not validated as `IsFullyValid`
**Severity:** HIGH-CDIV. Core `psbt.h:531-535`:
```cpp
CPubKey pubkey(key.begin() + 1, key.end());
if (!pubkey.IsFullyValid()) {
   throw std::ios_base::failure("Invalid pubkey");
}
if (partial_sigs.contains(pubkey.GetID())) {
    throw std::ios_base::failure("Duplicate Key, input partial signature for pubkey already provided");
}
```
clearbit's `parseInputMap` `PSBT_IN_PARTIAL_SIG` arm at
`psbt.zig:1609-1616`:
```zig
if (key_data.len != 33 and key_data.len != 65) {
    return PsbtError.InvalidKeyLength;
}
var pubkey: [33]u8 = undefined;
@memcpy(&pubkey, key_data[0..33]);  // SILENTLY TRUNCATES 65-byte uncompressed
try input.partial_sigs.put(pubkey, try allocator.dupe(u8, value));
```
Three bugs in one:
1. No `IsFullyValid` check on the public key.
2. 65-byte uncompressed keys are silently truncated to 33 bytes,
   losing the y-coordinate sign byte AND any uniqueness with the
   compressed form. Two distinct legitimate uncompressed pubkeys
   with the same x-coordinate collide in storage.
3. No duplicate-key check (`partial_sigs.put` silently overwrites the
   sig if the same pubkey appears twice).
**Fix:** call `crypto.parseAndValidatePubKey` (or similar helper) on
the 33-byte raw bytes; for 65-byte payloads, validate as
SEC1-uncompressed and store either as a tagged union or normalize to
the compressed form using libsecp256k1; check `partial_sigs.contains`
before insert.

### BUG-7 (G6, HIGH-CDIV): No DER-signature encoding check on `PSBT_IN_PARTIAL_SIG` value
**Severity:** HIGH-CDIV. Core `psbt.h:543-546`:
```cpp
if (sig.empty() || !CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)) {
    throw std::ios_base::failure("Signature is not a valid encoding");
}
```
clearbit accepts any byte string as the signature value. The
`script.zig` interpreter has `checkSignatureEncoding` (used during
script verification), but the PSBT deserialize path doesn't call it.
Means an attacker can sneak a non-DER signature into the PSBT and
clearbit will pass it through; a downstream Core signer/finalizer
will reject the PSBT entirely. Cross-impl interop break.
**Fix:** import `script_mod.checkSignatureEncoding`, call it on the
sig with `SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC` (or
clearbit's equivalent flag constants); raise on failure.

### BUG-8 (G7, HIGH-MISSING): `PSBT_GLOBAL_XPUB` parsed-as-unknown, never serialized
**Severity:** HIGH-MISSING. The `Psbt.xpubs` HashMap exists
(`psbt.zig:558`) and is initialized in `create`, `clone`, `deserialize`
— but the deserialize global-map switch (`psbt.zig:1418-1437`) has no
case for `PSBT_GLOBAL_XPUB` (0x01) so xpub entries fall into the
generic `unknown` bucket. Serialization (`psbt.zig:1231`) has the
explicit TODO comment `// TODO: Serialize xpubs` and emits nothing.
Round-tripping a PSBT with an xpub through clearbit drops the xpub.
Hardware wallets (Coldcard, Ledger, Trezor) rely on global xpubs to
let the signer show which subaccount a key derivation belongs to;
multisig coordinators rely on them to verify quorum membership. Both
break silently.
**Fix:** add `PSBT_GLOBAL_XPUB` case to global parse + emit; reuse
the BIP32 (`fingerprint || path`) parser for the value (the key is
the 78-byte serialized ExtPubKey). Note: Core stores the map *swapped*
(`std::map<KeyOriginInfo, std::set<CExtPubKey>>`) for fast lookup by
keypath; clearbit's `xpubs` field stores it the wire way
(`HashMap([78]u8 ExtPubKey → KeyOriginInfo`)) — that's fine since
clearbit doesn't expose the by-keypath lookup, but emit-ordering must
be deterministic on serialize.

### BUG-9 (G8, HIGH-MISSING): `PSBT_{IN,OUT}_PROPRIETARY` (0xFC) not parsed
**Severity:** HIGH-MISSING. Core defines `PSBTProprietary` as a
structured field with `(subtype: uint64, identifier: vec<u8>, key:
vec<u8>, value: vec<u8>)` (`psbt.h:84-96`) and parses it explicitly
into `m_proprietary` on every map. clearbit has no `m_proprietary`
field on `Psbt`, `PsbtInput`, or `PsbtOutput` — proprietary keys land
in the generic `unknown` HashMap keyed by Wyhash of the raw key bytes,
which (a) doesn't preserve the structured subtype/identifier split
and (b) isn't sorted on serialize (HashMap iteration order is
non-deterministic), so round-trip output is non-deterministic.
**Fix:** define `PsbtProprietary` struct mirroring Core; parse the key
as `<0xFC><compact_size n_id><identifier_n><compact_size subtype>` and
sort-on-emit.

### BUG-10 (G9, HIGH-MISSING): Input-side MuSig2 fields (BIP-373) not parsed
**Severity:** HIGH-MISSING. Core defines three input-side MuSig2 wire
types:
- `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` (0x1a, `psbt.h:56`)
- `PSBT_IN_MUSIG2_PUB_NONCE` (0x1b, `psbt.h:57`)
- `PSBT_IN_MUSIG2_PARTIAL_SIG` (0x1c, `psbt.h:58`)

clearbit defines NONE of them. The `PsbtInput` struct has no MuSig2
fields. Output-side `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` (0x08) IS
implemented (`psbt.zig:1827`), which is asymmetric and broken-by-
design: a PSBT that names output-side participants but has no input-
side path is useless. A signer that supports MuSig2 will round-trip
PSBT through clearbit and lose all input-side MuSig2 data silently.
**Fix:** define `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a`,
`PSBT_IN_MUSIG2_PUB_NONCE = 0x1b`, `PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c`.
Add `m_musig2_participants`, `m_musig2_pubnonces`,
`m_musig2_partial_sigs` to `PsbtInput`. Parse + serialize + merge.

### BUG-11 (G10, HIGH-MISSING): `PSBT_OUT_TAP_TREE` no depth / leaf-ver / structural validation
**Severity:** HIGH-MISSING. Core `psbt.h:1042-1064` runs the full
TaprootBuilder + `IsComplete()` check; clearbit stores the raw bytes
as `tap_tree: ?[]const u8` (`psbt.zig:1793`) with NO validation. An
attacker shipping `tap_tree = <single byte 0xFF>` lands a 1-byte
"tree" with depth=0xFF in clearbit's storage; round-trip preserves it;
downstream consumers (a future tap-script finalizer) trusting the
field will crash or commit to garbage.
**Fix:** parse the value into a vector of `(depth: u8, leaf_ver: u8,
script: vec<u8>)`; reject `depth > 128` (TAPROOT_CONTROL_MAX_NODE_COUNT)
and `(leaf_ver & ~0xFE) != 0`; build a TaprootBuilder and assert
`builder.IsComplete()`; store the parsed vector (not the raw bytes).

### BUG-12 (G11, HIGH-MISSING): BIP-371 output-side fields parsed but NOT serialized
**Severity:** HIGH-MISSING. `parseOutputMap` (`psbt.zig:1746-1855`)
handles types `PSBT_OUT_TAP_INTERNAL_KEY` (0x05),
`PSBT_OUT_TAP_TREE` (0x06), `PSBT_OUT_TAP_BIP32_DERIVATION` (0x07),
and `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` (0x08). But
`serializeOutputMap` (`psbt.zig:1326-1354`) only emits redeem_script,
witness_script, and BIP32. Deserialize → serialize is lossy: tap
internal key, tap tree, tap bip32 paths, and output MuSig2 participants
all disappear.
**Fix:** add the missing emit branches in `serializeOutputMap`,
mirroring `parseOutputMap`'s shape exactly.

### BUG-13 (G12, HIGH-MISSING): BIP-371 input-side taproot fields NOT serialized
**Severity:** HIGH-MISSING. Same shape as BUG-12 but input-side.
`parseInputMap` (`psbt.zig:1582-1744`) handles `PSBT_IN_TAP_KEY_SIG`
(0x13), `PSBT_IN_TAP_SCRIPT_SIG` (0x14), `PSBT_IN_TAP_LEAF_SCRIPT`
(0x15), `PSBT_IN_TAP_BIP32_DERIVATION` (0x16),
`PSBT_IN_TAP_INTERNAL_KEY` (0x17), `PSBT_IN_TAP_MERKLE_ROOT` (0x18).
But `serializeInputMap` (`psbt.zig:1237-1324`) only emits 0x00–0x08.
The taproot key sig, script sigs, leaf scripts, tap BIP32 paths,
internal key, and merkle root are all dropped on serialize.
**Fix:** add the missing emit branches in `serializeInputMap`. Be
careful with leaf-script ordering (Core uses
`ShortestVectorFirstComparator` for control blocks).

### BUG-14 (G13, HIGH-MISSING): Hash preimage maps NOT parsed AND NOT serialized
**Severity:** HIGH-MISSING. `PsbtInput` declares four preimage maps
(`psbt.zig:273-276`); they get `init`'d and `deinit`'d
(`psbt.zig:296-299`, `:325-347`) but they are populated by NO code
path and serialized by NO code path. The four constants
`PSBT_IN_RIPEMD160 = 0x0A`, `PSBT_IN_SHA256 = 0x0B`,
`PSBT_IN_HASH160 = 0x0C`, `PSBT_IN_HASH256 = 0x0D` are declared
(`psbt.zig:57-60`) and used by NOTHING. Pure dead storage on the heap.
A PSBT containing a hash160 preimage (used in HTLC scripts) will
silently drop it. Lightning-style hash-locked scripts cannot be
finalized through clearbit.
**Fix:** add `PSBT_IN_RIPEMD160` / `…SHA256` / `…HASH160` / `…HASH256`
arms to `parseInputMap`. Validate `hash160(value) == key[1..21]` for
hash160/ripemd160 entries (Core does this implicitly via the type-
size check on the key, but the cross-check is a defense-in-depth gate).
Add the four emit branches to `serializeInputMap`.

### BUG-15 (G14, HIGH-MISSING): `PSBT_GLOBAL_PROPRIETARY` not parsed
**Severity:** HIGH-MISSING. Same shape as BUG-9 but at the global-map
level. Affects any wallet/coordinator that uses global proprietary
keys (e.g. version-pinning, multisig-quorum metadata).
**Fix:** mirror BUG-9 fix at the global level.

### BUG-16 (G15, MED-CDIV): BIP32 derivation rejects 65-byte (uncompressed) pubkeys
**Severity:** MED-CDIV. Core `psbt.h:153`:
```cpp
if (key.size() != CPubKey::SIZE + 1 && key.size() != CPubKey::COMPRESSED_SIZE + 1) {
    throw std::ios_base::failure("Size of key was not the expected size for the type BIP32 keypath");
}
```
i.e. accepts both `33+1=34` (compressed) AND `65+1=66` (uncompressed).
clearbit's `parseInputMap PSBT_IN_BIP32_DERIVATION` arm at
`psbt.zig:1628`:
```zig
if (key_data.len != 33) return PsbtError.InvalidKeyLength;
```
Rejects uncompressed pubkeys outright. Same applies to
`PSBT_OUT_BIP32_DERIVATION` (`psbt.zig:1766`). Old wallets / legacy
hardware tokens still using uncompressed keys cannot round-trip a
PSBT through clearbit.
**Fix:** accept both 33 and 65; the storage type `[33]u8` is wrong for
uncompressed pubkeys and would need to become a tagged union or
variable-length slice.

### BUG-17 (G16, MED-CDIV): HD key path empty-path semantics differ
**Severity:** MED-CDIV. Core `psbt.h:127-129`:
```cpp
if (length % 4 || length == 0) {
    throw std::ios_base::failure("Invalid length for HD key path");
}
```
Where `length` is the BYTE COUNT of the (fingerprint + path) blob —
so `length == 0` means no fingerprint at all (rejected), and
`length == 4` means fingerprint-only with empty path (ACCEPTED, since
4 % 4 == 0 and length != 0).

clearbit:
```zig
if (value.len < 4 or (value.len - 4) % 4 != 0) return PsbtError.InvalidValueLength;
```
`value.len < 4` rejects fingerprint-shorter-than-4-bytes (good but
already implicit in the `(value.len - 4) % 4 != 0` arithmetic). What's
WRONG: this also rejects `value.len == 0` with the same error code,
not Core's specific "Invalid length for HD key path" string. The
inverse direction: Core requires `length != 0` so a path of just the
fingerprint (`length == 4`) is accepted; clearbit's check
`value.len < 4` is `4 < 4 = false`, so 4 is accepted (good); but
`value.len == 0` returns `InvalidValueLength` (whereas Core would
report "Invalid length for HD key path"). Net result: clearbit
accepts the same valid cases as Core but reports different errors on
the malformed cases, breaking cross-impl error-string-matching fuzz.
**Fix:** match Core's exact bound — `if (value.len % 4 != 0 or
value.len == 0) return PsbtError.InvalidValueLength;`.

### BUG-18 (G17, MED-MISSING): `MAX_FILE_SIZE_PSBT` not enforced
**Severity:** MED-MISSING. Constant declared (`psbt.zig:30`,
`MAX_PSBT_SIZE = 100_000_000`) but never referenced. `Psbt.deserialize`
(`psbt.zig:1383`) just sets `reader.data = data` with no length check;
`Psbt.fromBase64` calls `decoder.Decoder.decode` which allocates an
arbitrary-size buffer. A 4 GiB base64 string allocates 3 GiB of
decoded data before any PSBT logic kicks in. DOS amplifier for any
RPC endpoint that accepts PSBT input.
**Fix:** in `deserialize`, reject `data.len > MAX_PSBT_SIZE` up front.
In `fromBase64`, reject `base64_str.len > MAX_PSBT_SIZE * 4 / 3 + N`
before decoding.

### BUG-19 (G18, MED-DIVERGE): Missing separator at EOF maps to generic EndOfStream
**Severity:** MED-DIVERGE. Core throws a domain-specific "Separator is
missing at the end of [the global/input/output] map" string; clearbit
re-raises whatever Reader.readCompactSize threw (typically
`EndOfStream`). The error variant `PsbtError.MissingSeparator`
(`psbt.zig:89`) is declared but never used (dead enum variant).
**Fix:** wrap the `while (true) { const key_len = try
reader.readCompactSize(); ... }` loop with a guard: catch
`EndOfStream` from the *initial* `readCompactSize` and rewrite to
`MissingSeparator`; let mid-value EndOfStream pass through as-is.

### BUG-20 (G19, MED-MISSING): `PSBT_IN_SIGHASH` value range not checked
**Severity:** MED-MISSING. Core stores the sighash as a signed `int`
without explicit range-check, but most consumers later validate it's
one of the known sighash flag combos. clearbit reads u32 verbatim
(`psbt.zig:1619`). A PSBT with `sighash_type = 0xDEADBEEF` is happily
stored, round-trips, and is fed to the finalizer/signer downstream.
**Fix:** validate `sighash_type` is one of {0, 1, 2, 3, 0x81, 0x82,
0x83} (DEFAULT, ALL, NONE, SINGLE, ALL|ANYONECANPAY, NONE|ANYONECANPAY,
SINGLE|ANYONECANPAY); reject otherwise.

### BUG-21 (G20, MED-MISSING): `RemoveUnnecessaryTransactions` not implemented
**Severity:** MED-MISSING. Core's helper (`psbt.cpp:514-549`) drops
`non_witness_utxo` when all inputs are segwit-v1 with non-ANYONECANPAY
sighash (since taproot signs the amount directly via the BIP341
sighash). clearbit never drops them, so taproot-only PSBTs are
~30-100× larger than necessary. Not a correctness bug, but inflates
wire size and worst-case allocator pressure.
**Fix:** port Core's helper; call it before each `serialize()` (or
expose as standalone `Psbt.removeUnnecessaryTransactions`).

### BUG-22 (G21, MED-MISSING): `PSBTInputSignedAndVerified` not implemented
**Severity:** MED-MISSING. Core's `PSBTInputSignedAndVerified`
(`psbt.cpp:325`) calls `VerifyScript` against `final_script_sig` +
`final_script_witness` to actually check the signatures verify;
clearbit has only `isFinalized()` which is structural (any non-null
final field).
**Fix:** add `Psbt.isInputSignedAndVerified(input_index: usize) bool`
that runs the script interpreter (clearbit has `script.zig`).

### BUG-23 (G22, MED-DIVERGE): `analyzepsbt` doesn't emit per-input `next` role
**Severity:** MED-DIVERGE. Core's `AnalyzePSBT` returns a per-input
`{has_utxo, is_final, next}` triple plus a top-level `next` and
`estimated_vsize`; clearbit's `handleAnalyzePsbt` (`rpc.zig:8003-8059`)
emits a per-input `has_utxo` + `is_final` + a top-level `next`, missing
the per-input `next`. Also missing `estimated_vsize` (Core estimates it
based on script size + worst-case sig size).
**Fix:** extend `Psbt.analyze` to return per-input next role; update
`handleAnalyzePsbt` to emit it; compute `estimated_vsize`.

### BUG-24 (G23, MED-MISSING): `joinpsbts` RPC missing
**Severity:** MED-MISSING. Core's `joinpsbts`
(`rpc/rawtransaction.cpp:1778`) joins multiple PSBTs over DIFFERENT
underlying transactions into one PSBT whose tx has the union of
inputs and outputs. Used by coinjoin coordinators. clearbit's dispatch
table at `rpc.zig:3061-3071` has no `joinpsbts` arm.
**Fix:** add `Psbt.join(psbts: []const *Psbt)` helper +
`handleJoinPsbts` RPC.

### BUG-25 (G24, MED-MISSING): `utxoupdatepsbt` RPC missing
**Severity:** MED-MISSING. Core's `utxoupdatepsbt`
(`rpc/rawtransaction.cpp:1731`) takes a PSBT + optional descriptors,
looks up the prevouts in the active chain's UTXO set, and fills in
`witness_utxo` / `non_witness_utxo`. clearbit has `addInputUtxo` /
`addInputNonWitnessUtxo` on the Psbt struct, but no RPC.
**Fix:** add a new dispatch arm; UTXO lookup via
`chain_state.utxo_set.get(outpoint)`.

### BUG-26 (G25, MED-MISSING): `walletprocesspsbt` RPC missing
**Severity:** MED-MISSING. Core's `walletprocesspsbt`
(`wallet/rpc/spend.cpp:1569`) signs + updates + (optionally) finalizes
a PSBT using wallet keys; clearbit has `walletcreatefundedpsbt` for
the creation flow, and `psbtbumpfee` for fee-bump, but NO general
"hand wallet a PSBT, get back a more-signed PSBT" entry point.
**Fix:** new RPC. Wallet-side `FillPSBT` analog already exists in
`wallet.zig` (it's called from `walletcreatefundedpsbt`); extract +
expose.

### BUG-27 (G26, MED-MISSING): `descriptorprocesspsbt` RPC missing
**Severity:** MED-MISSING. Core's `descriptorprocesspsbt` (standalone
RPC in wallet/rpc/spend.cpp) signs a PSBT given a descriptor — used
for "wallet-less" hardware signers. clearbit has descriptors (W131
audited 28 BUGs) but no PSBT bridge.
**Fix:** new RPC, key derivation via `descriptor.zig`.

### BUG-28 (G27, LOW-MISSING): `extract()` doesn't validate signatures
**Severity:** LOW-MISSING. Core's `FinalizeAndExtractPSBT`
(`psbt.cpp:567-581`) calls `FinalizePSBT` first, which internally runs
`SignPSBTInput(DUMMY_SIGNING_PROVIDER)` against each input — this
re-runs the script interpreter for each input as a side-effect.
clearbit's `extract()` only structurally checks `isComplete()`. A
hostile PSBT with cryptographically-invalid signatures but
structurally-valid `final_script_witness` extracts to a tx that
broadcast-fails.
**Fix:** call `isInputSignedAndVerified(i)` (BUG-22) for each input
inside `extract`; raise if any fails.

### BUG-29 (G28, LOW-DIVERGE): `combine()` doesn't verify same-underlying-tx
**Severity:** LOW-DIVERGE. Core's `Merge` (`psbt.cpp:30-32`):
```cpp
if (tx->GetHash() != psbt.tx->GetHash()) {
    return false;
}
```
clearbit's `mergeFrom` (`psbt.zig:752-769`) only checks
`inputs.len != other.inputs.len`. Two PSBTs with the same input count
but different prevouts will combine silently. The resulting PSBT's
partial sigs no longer correspond to the new outpoints; signers
trying to add a missing sig will hit a "no UTXO for outpoint" error.
**Fix:** hash both `psbt.tx` blobs (with `writeTransactionNoWitness`)
and compare; raise if different.

### BUG-30 (G29, LOW-MISSING): `Psbt.IsNull()` predicate not implemented
**Severity:** LOW-MISSING. Core's `PartiallySignedTransaction::IsNull()`
returns true if the PSBT is empty/uninitialized; clearbit has no
analog. Affects no current code path but a future API addition (e.g. a
deserialize-or-default helper) would silently treat zero-input PSBTs
as valid.
**Fix:** add `pub fn isNull(self: *const Psbt) bool` returning
`self.tx.inputs.len == 0 and self.tx.outputs.len == 0 and
self.unknown.count() == 0 and self.xpubs.count() == 0`.

## Universal patterns

W137 surfaces three universal patterns relevant fleet-wide:

1. **"declare-init-deinit-but-never-populate" dead storage.** `PsbtInput`
   declares four hash-preimage maps that are init'd and deinit'd but never
   filled by any code path and never emitted by any serializer.
   Same pattern fired in earlier waves: nimrod cfBlocks (W57), camlcoin
   getblockheader (FIX-80). The wave-level test here grep-asserts that
   every PSBT field declared in `PsbtInput` is referenced by both
   `parseInputMap` and `serializeInputMap`; flips will land when the
   fields wire up.

2. **"parse-but-no-emit asymmetry" lossy round-trip.** BIP-371 output-
   side fields are parsed in `parseOutputMap` but the corresponding emit
   branches in `serializeOutputMap` are absent — exactly the same bug-
   shape as W121/W122 BUG-3 in lunarblock/blockbrew/nimrod (BIP-158
   filter encoder asymmetry) and the W125 RPC error-parity audit pattern.
   The cross-impl pattern: when a wave plumbs PARSE without EMIT,
   round-trip is silently lossy and only surfaces on Core-comparison
   diff tests. Audit framework lesson: every PARSE arm needs a matched
   EMIT arm test.

3. **"docstring-as-aspiration" — module advertises future support.**
   `psbt.zig:1` says `BIP174/370` but BIP-370 is zero LOC. Similar to
   blockbrew W122 BUG-1 "test-comment-as-confession" — the documentation
   surface is the most-trusted user-visible interface and silent drift
   here is more harmful than missing functionality. Tests here grep-
   assert `"BIP174/370"` does NOT appear, which flips when either (a)
   BIP-370 is implemented or (b) the docstring is corrected to
   `BIP-174`.

## Out of scope

- BIP-370 (PSBT v2) full wire format — `PSBT_HIGHEST_VERSION = 0`
  parity with Core means clearbit correctly rejects v2 PSBTs; only the
  docstring needs alignment (BUG-1). Future wave could implement v2
  if/when BIPs make it mandatory.
- W31 / W38 / W47 finalizer multisig work — already audited and fixed.
- W53 decodepsbt UniValue formatting — already audited.
- W118 / FIX-61 `psbtbumpfee` — already audited.
- W131 descriptors integration — `descriptorprocesspsbt` listed here as
  RPC parity gap, but the underlying descriptor parse path is W131's
  scope.
- Network-side PSBT exchange (BIP-78 payjoin) — W119 / FIX-65 / FIX-66
  / FIX-67 cover the receive/send flow; that wave audited the PSBT
  validation gates specific to payjoin (G10-G15 in FIX-67), not the
  general BIP-174 deserialize-time invariants audited here.
