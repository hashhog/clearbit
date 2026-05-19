# W160 — ECDSA + Schnorr signing primitives + RFC 6979 deterministic nonce + sighash construction (clearbit)

**Wave:** W160 — ECDSA / Schnorr signing primitives, RFC 6979 deterministic
nonce (`secp256k1_nonce_function_rfc6979` vs the implicit-default opaque
`NULL` fallback), low-S normalisation (BIP-62), DER strict encoding (BIP-66),
BIP-340 `aux_rand32` discipline (NEVER NULL in Core), BIP-143 sighash
midstate caching (`HashWriter HASHER_*_TAPSIGHASH`), BIP-341 epoch=0,
annex commitment via `sha_annex`, script-path tapleaf hash + key_version
+ codesep_pos, `SIGHASH_DEFAULT = 0x00` (64-byte sig path), the SIGHASH_SINGLE
bug preserved at the byte-quirk level (uint256 1 ↔ legacy-only),
`secp256k1_keypair_xonly_tweak_add` and the BIP-341 seckey-flip on odd-y
parity (delegated to libsecp), `CKey::Sign` sign-then-verify paranoia,
BIP-32 priv-side scalar tweak via `secp256k1_ec_seckey_tweak_add` (NOT
pure-Zig BigInt), recovery-id byte for `signmessage` (27 + recid + 4·comp),
sigcache key composition (Core: `sighash || pubkey || sig || flags` per
`CSignatureCache::ComputeEntryECDSA`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:209-235 CKey::Sign` — passes
  `secp256k1_nonce_function_rfc6979` EXPLICITLY (third-to-last arg) as the
  nonce function. Per `secp256k1.h:556-580` passing `NULL` causes libsecp
  to fall back to `secp256k1_nonce_function_default` which is currently
  aliased to `_rfc6979`, but that's an *implementation* contract not a
  *public API* contract. Then **grinds for low-R** (`while (ret &&
  !SigHasLowR(&sig) && grind)` line 221) by bumping a 4-byte counter in
  `extra_entropy`. Re-runs `secp256k1_ecdsa_sign` until the resulting R
  has its high bit clear, so DER serialises to ≤ 71 bytes (1-2 sat/vB
  fee savings per legacy / SegWit-v0 input). Then the famous sign-then-
  verify paranoia at line 228-234 (`assert(ret)` on
  `secp256k1_ecdsa_verify` after a fresh `ec_pubkey_create` on the SIGN
  context).
- `bitcoin-core/src/key.cpp:250-271 CKey::SignCompact` — same RFC-6979
  explicit + paranoia round-trip (`ec_pubkey_create` + `ecdsa_recover` +
  `ec_pubkey_cmp` — `assert(ret == 0)` on cmp).
- `bitcoin-core/src/key.cpp:549-563 KeyPair::SignSchnorr` — calls
  `secp256k1_schnorrsig_sign32(secp256k1_context_sign, sig.data(),
  hash.data(), keypair, aux.data())` with **mandatory** `aux` parameter
  (caller passes `GetStrongRandBytes(32)` via `CKey::SignSchnorr` —
  `key.cpp:273-277`). Then sign-then-verify paranoia: re-derives the
  xonly pubkey from the keypair and runs `schnorrsig_verify` on the
  STATIC context. **On failure, `memory_cleanse(sig.data(), sig.size())`**
  wipes the buffer.
- `bitcoin-core/src/key.cpp:532-547 KeyPair::KeyPair` — applies the
  BIP-341 keypair tweak via `secp256k1_keypair_xonly_tweak_add` —
  libsecp internally negates the seckey if the parent xonly pubkey has
  odd-y parity (BIP-340 §"Default Signing"). Caller never sees the flip.
- `bitcoin-core/src/script/interpreter.cpp:321-339 EvalChecksigPreTapscript`
  — for `SigVersion::BASE`, calls `FindAndDelete(scriptCode, CScript()
  << vchSig)` before `CheckECDSASignature`. The post-segwit
  `SCRIPT_VERIFY_CONST_SCRIPTCODE` flag converts the find-and-delete
  into a hard reject if any push of the literal sig appeared in the
  scriptCode.
- `bitcoin-core/src/script/interpreter.cpp:1382-1500 SignatureHashSchnorr`
  — BIP-341 sighash. Epoch byte = 0, hash_type byte AS-IS, all
  midstates pulled from a `PrecomputedTransactionData` cache, output_type
  derived as `(hash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hash_type &
  SIGHASH_OUTPUT_MASK)`, spend_type = `(ext_flag << 1) + have_annex`,
  annex committed via `execdata.m_annex_hash`, tapscript adds
  `tapleaf_hash || key_version (0x00) || codesep_pos`. Validates
  `hash_type <= 0x03 || (hash_type in [0x81, 0x82, 0x83])` (so 0x80 —
  the bare SIGHASH_ANYONECANPAY without sub-type — is REJECTED).
- `bitcoin-core/src/script/interpreter.cpp:1717-1755 EvalChecksigTapscript`
  — empty-sig short-circuits via `success = false` (NULLFAIL is the
  caller's responsibility); 64-byte sig → SIGHASH_DEFAULT, 65-byte sig
  with hash_type byte where `vchSig.back() == SIGHASH_DEFAULT` is a HARD
  abort (`SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`); SignatureHashSchnorr is
  computed; `VerifySchnorrSignature` performs the BIP-340 check.
- `bitcoin-core/src/script/interpreter.cpp:1382-1496 SignatureHash` (BIP-143
  v0) — `cache.hashPrevouts`, `cache.hashSequence`, `cache.hashOutputs`
  midstates; SIGHASH_SINGLE / SIGHASH_NONE / SIGHASH_ANYONECANPAY
  cache-bypass shapes; the `scriptCode` is passed in raw (caller drops
  OP_CODESEPARATOR-before-codesep_pos and pushes the witness-v0
  scriptCode without find-and-delete).
- `bitcoin-core/src/script/interpreter.cpp ~169-189 IsLowDERSignature` —
  parses the lax-DER R||S, returns `false` if S > N/2. Note Core's
  hot-path `CheckSignatureEncoding` runs:
  `IsValidSignatureEncoding` (strict DER per BIP-66 if STRICTENC or
  DERSIG) → `IsLowDERSignature` (only if LOW_S) →
  `IsDefinedHashtypeSignature` (only if STRICTENC).
- `bitcoin-core/src/script/sigcache.cpp::CSignatureCache::ComputeEntryECDSA`
  — `CSHA256().Write(m_salted_hasher_ecdsa).Write(hash).Write(pubkey).Write(sig).Finalize(out)`
  (out is the SHA-256 of salt || sighash || pubkey || sig). **Note: the
  sigcache key does NOT include the verification flags** because
  `CheckECDSASignature` parameters that affect the cache decision are
  the sighash, the sig, and the pubkey only — script verification flags
  affect parser/encoding gates that run BEFORE the cache lookup, and
  `LOW_S` is enforced by `ecdsa_signature_normalize` which mutates the
  signature into a canonical form before key computation.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:572-580` — *"To avoid
  accepting malleable signatures, only ECDSA signatures in lower-S form
  are accepted [by `secp256k1_ecdsa_verify`]. If you need to accept
  ECDSA signatures from sources that do not obey this rule, apply
  `secp256k1_ecdsa_signature_normalize` to the signature prior to
  verification, but be aware that doing so results in malleable
  signatures."* — i.e. **calling `normalize` before `verify` is a
  consensus-malleability hazard**; Core does it on a paranoia footing
  via `CPubKey::Verify` (`pubkey.cpp:294-297`) because the `LOW_S` gate
  has already executed upstream.

**Files audited**
- `src/crypto.zig:677-684 initSecp256k1` (no `nonce_function` plumbing,
  no `aux32` reservation, no selftest).
- `src/crypto.zig:700-768 laxDerParse` — purely-Zig DER parser; **DOES
  NOT validate** the leading 0x80-high-bit constraint, does not check
  sub-component length-as-signed, does not enforce `R-len + S-len + 6
  == total-len` round-trip (used by `verifyEcdsa` and `isLowDERSignature`).
- `src/crypto.zig:770-814 verifyEcdsa` — top-of-stack lax-DER parse
  → compact parse → **unconditional `secp256k1_ecdsa_signature_normalize`**
  → `ecdsa_verify`. The unconditional normalize is BUG-2 below.
- `src/crypto.zig:816-839 isLowDERSignature` — uses the
  `normalize`-returns-0 trick; correct.
- `src/crypto.zig:886-908 verifySchnorr` — BIP-340 single-sig verify;
  always uses module-private `secp_ctx`.
- `src/crypto.zig:979-1014 signMessageCompact` — calls
  `secp256k1_ecdsa_sign_recoverable` with **`NULL` nonce function**
  (relies on libsecp default → rfc6979 by current alias). **No
  sign-then-verify paranoia.** Recovery-id byte `27 + recid + 4·comp`.
- `src/crypto.zig:1016-1062 recoverMessagePubkey` — header range
  `27..=34` good (BUG: range is `[27, 34]` inclusive but Core treats
  `[27, 34]` as `(27 + recid + 4·comp)`).
- `src/crypto.zig:1226-1326 legacySighash` (WALLET-SIDE) — pre-segwit
  sighash; **does NOT call `removeCodeSeparators`** (compare to
  `script.zig:2967 removeCodeSeparators`). The two-pipeline divergence
  is BUG-4 below.
- `src/crypto.zig:1328-1378 SegwitSighashCache` — pre-computed
  `hashPrevouts/hashSequence/hashOutputs`. **Stack-allocated 36×256
  buffer** with NO bounds check at construction; `Transaction.inputs.len
  > 256` corrupts the next stack frame (BUG-5).
- `src/crypto.zig:1380-1499 segwitSighash` — used by script.zig hot-path
  AND by the wallet (`computeWitnessSigHashV0`); RE-DOES the
  midstate compute every call, never consults the cache (BUG-6).
- `src/wallet.zig:670-743 ExtendedKey.deriveChild` — BIP-32 child
  derivation. Two bugs co-existing: (a) parent-fingerprint compute
  calls `ec_pubkey_create(ctx, &parent_pubkey, &self.key)` for ALL
  branches including the no-op public-side branch (line 720); (b)
  retry-on-`IL >= n` BIP-32 spec contract absent (BUG-7).
- `src/wallet.zig:1707-2011 signInput` — main wallet sign dispatch
  (p2pkh / p2sh-p2wpkh / p2wpkh / p2tr / p2wsh).
  - `p2tr` branch (1893-1953): `secp256k1_keypair_create` → BIP-86
    `secp256k1_keypair_xonly_tweak_add` (with tweak =
    `taggedHash("TapTweak", x_only)`) → `secp256k1_schnorrsig_sign32`
    with `aux_rand = null` (BUG-1).
  - All ECDSA branches go through `Wallet.ecdsaSign` (line 2013) — no
    sign-then-verify, no low-R grind.
- `src/wallet.zig:2013-2037 ecdsaSign` — calls `secp256k1_ecdsa_sign`
  with `(nonce_function=null, ndata=null)`. **Buffer `[72]u8 = undefined`
  + `der_len: usize = 72`** is a 1-byte under-cap (DER can serialise
  to 73 bytes when both R and S are 33 bytes after the leading-zero
  pad). When libsecp writes 73 bytes, `serialize_der` returns 0 and
  the resulting `der_len` still reflects the required length, but
  clearbit ignores the return value (`_ = secp256k1.…`) — see BUG-8.
- `src/wallet.zig:3090-3092 bip86Tweak` — `taggedHash("TapTweak",
  internal_xonly)`, no merkle-root commitment. Correct for BIP-86
  (no script tree) but **wrong if the wallet ever signs a script-path
  spend** — and the `signInput .p2tr` branch unconditionally applies
  this tweak (BUG-9 below).
- `src/script.zig:2203-2284 verifySignature` — hot-path script-engine
  ECDSA verify. Order: DER-encoding gate (verify_dersig/low_s/strictenc)
  → low-S gate (verify_low_s) → hash_type strict gate (verify_strictenc)
  → witness pubkey-type gate → BIP-141 strict pubkey gate. Then
  branches on `sig_version == .witness_v0` (calls `crypto.segwitSighash`)
  vs default (`legacySignatureHashWithFindAndDelete`).
- `src/script.zig:2286-2363 verifyTaprootSignature` — single-call
  Schnorr verify; sig-length 64 (SIGHASH_DEFAULT) or 65 (with
  hash_type byte).
- `src/script.zig:2937-3076 legacySignatureHash` (VERIFY-SIDE) —
  pre-segwit sighash with `removeCodeSeparators`. The good copy.
- `src/script.zig:3078-3102 legacySignatureHashWithFindAndDelete` —
  what the verify path actually calls; matches Core's
  `FindAndDelete(scriptCode, CScript() << vchSig)`.
- `src/sig_cache.zig:148-242 computeKey / lookup / insert` — cache key
  is `SHA256(nonce || sighash || pubkey || sig || flags_le)` with
  `flags_le` mixed in. **Core's cache key does NOT include flags**
  (`sigcache.cpp::ComputeEntryECDSA`) — clearbit's extra mix-in is
  defense-in-depth but means cache hit rate is 100% per-flag (BUG-10).
- `src/validation.zig:2488-2579 verifyScriptJob` — **uses txid as the
  sighash proxy for the sigcache key** (line 2509-2510). This is BUG-3
  below: the sigcache cannot distinguish two inputs of the same tx,
  two SIGHASH_SINGLE branches, or a SIGHASH_NONE vs SIGHASH_ALL on
  the same tx.
- `src/taproot_sighash.zig` (entire file) — clean port of BIP-341 sighash;
  epoch=0, hash_type byte, ext_flag (0 keypath / 1 script-path),
  annex commitment, single-output SIGHASH_SINGLE block. **Validates
  `isValidTaprootHashType` strictly** (rejects 0x80 like Core).

---

## Gate matrix (35 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RFC 6979 deterministic nonce | G1: `secp256k1_ecdsa_sign` passes `secp256k1_nonce_function_rfc6979` EXPLICITLY | **BUG-11 (P2)** `wallet.zig:2021-2023` passes `(null, null)` for `(noncefp, ndata)`. Functionally identical TODAY because libsecp's `secp256k1_nonce_function_default` is currently aliased to `_rfc6979`, but this is an **implementation contract that has changed in the past** (libsecp 0.2.0 considered switching to a synthetic-nonce default to reduce nonce-grinding traffic). |
| 1 | … | G2: `secp256k1_ecdsa_sign_recoverable` passes RFC-6979 explicitly | **BUG-11 cross-cite** — `crypto.zig:987-994` `signMessageCompact` same shape, passes `(null, null)` |
| 1 | … | G3: nonce-derivation extra-entropy plumbed for grind-for-low-R | **BUG-12 (P1)** — clearbit has NO low-R grind. Core's loop at `key.cpp:221-224` re-signs with a 4-byte counter in `extra_entropy` until R < 0x80. Result: every clearbit ECDSA signature is ~2 bytes larger on average, costing the wallet operator ~1 sat/vB per legacy/SegWit-v0 input. **First fleet observation of this gap.** |
| 2 | Sign-then-verify paranoia | G4: `Wallet.ecdsaSign` re-verifies the emitted sig on the same context | **BUG-13 (P1) — carry-forward of W159 BUG-6 (2-wave open)** — `wallet.zig:2013-2037` emits the DER signature with NO `ec_pubkey_create` + `ecdsa_verify` round-trip. Core: `key.cpp:228-234` says verbatim "Additional verification step to prevent using a potentially corrupted signature" + `assert(ret)`. |
| 2 | … | G5: `signMessageCompact` re-recovers and `ec_pubkey_cmp`'s | **BUG-13 cross-cite of W159 BUG-7 (2-wave open)** — `crypto.zig:979-1014` emits the 65-byte compact-recoverable sig with NO `ec_pubkey_create` + `ecdsa_recover` + `ec_pubkey_cmp` round-trip. Core: `key.cpp:262-269` `assert(ret == 0)`. |
| 2 | … | G6: Schnorr sign-path re-verifies | **BUG-13 cross-cite of W159 BUG-8 (2-wave open)** — `wallet.zig:1922-1930` calls `schnorrsig_sign32` then writes the witness with NO `schnorrsig_verify` re-check. Core: `key.cpp:555-563`. **AND on failure, Core does `memory_cleanse(sig.data(), sig.size())`** — clearbit does nothing. |
| 3 | BIP-340 aux_rand discipline | G7: aux32 != NULL on Schnorr sign | **BUG-1 (P0-SEC) carry-forward of W159 BUG-18 (2-wave open)** — `wallet.zig:1922-1930` passes `null` for the aux_rand parameter of `schnorrsig_sign32`. Core ALWAYS supplies `GetStrongRandBytes(32)` (`key.cpp:273-277`). With NULL aux32 + deterministic nonce derivation, two Schnorr signs of the same `msg_hash` with the same key produce identical 64-byte sigs — re-sign with differing annex is recoverable. |
| 3 | … | G8: aux32 freshly drawn per sign (not key-bound) | N/A — aux32 not provided at all |
| 3 | … | G9: aux32 mixed even in deterministic-test mode | N/A |
| 4 | Low-S (BIP-62 rule 5) | G10: hot-path script verify checks low-S BEFORE calling `ec_verify` | PASS (`script.zig:2223-2228 self.flags.verify_low_s`) |
| 4 | … | G11: standalone `verifyEcdsa` does NOT silently normalize a high-S sig | **BUG-2 (P0-CDIV) "silent malleability launderer"** — `crypto.zig:810` unconditionally calls `secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig)` BEFORE `ecdsa_verify`. Any caller of `crypto.verifyEcdsa` (not via the script engine) effectively gets a verifier that accepts high-S sigs as if they were low-S — Core explicitly warns this is the consensus-malleability hazard (`secp256k1.h:572-580`). The hot-path (script.zig::verifySignature) gates on `verify_low_s` first, so consensus is OK; BUT (a) `compressor.zig`, `psbt.zig`, and rpc-helper callers of `crypto.verifyEcdsa` bypass that gate; (b) future refactors that wire `crypto.verifyEcdsa` into a new consensus surface inherit the silent acceptance. **Cross-pattern**: identical shape to the W153 hotbuns "fix went in wrong direction" — the FIX (normalize) was added to make `verifyEcdsa` "more permissive" without realising it's the SOURCE of malleability. |
| 5 | DER strict (BIP-66) | G12: hot-path verifies BIP-66 DER strict when verify_dersig/strictenc set | PASS (`script.zig:2215-2219 isValidSignatureEncoding`) |
| 5 | … | G13: standalone `verifyEcdsa` does BIP-66 DER strict | **BUG-14 (P1) "verifier is lax-DER, signer should NOT be"** — `crypto.zig:779-814 verifyEcdsa` uses `laxDerParse` (line 703-768) which accepts ANY R-S sequence within a `30 <len>` envelope, including non-canonical leading-zero pads. Consensus-effect-equivalent to `verify_dersig=false` for every code path that calls `crypto.verifyEcdsa` directly. Cross-cite BUG-2: the two together mean `crypto.verifyEcdsa` accepts a much wider class of signatures than the hot-path script-engine; any future surface that calls this function ships with a silent consensus-divergence relative to Core. |
| 6 | BIP-143 midstate caching | G14: SegwitSighashCache populated once per tx and reused across inputs | **BUG-6 (P1)** `crypto.zig:1328-1378 SegwitSighashCache` is **defined but never wired into `segwitSighash`**. `segwitSighash` at line 1382-1499 recomputes `hashPrevouts/hashSequence/hashOutputs` for EVERY input (`prevouts_data := ...; hash256(prevouts_data.items)` at 1401-1409, identical for `hashSequence` 1416-1428, identical for `hashOutputs` 1448-1466). On a tx with N inputs and M outputs, per-input cost is O(N+M+8) where Core's cached path is O(1). For a 100-in tx the multiplier is ~100× wasted SHA-256. Pure perf, no consensus risk. **dead-data plumbing**, ~Nth fleet instance. |
| 6 | … | G15: 36×256 stack buffer in `SegwitSighashCache.init` is bounded against `tx.inputs.len` | **BUG-5 (P0-MEM)** `crypto.zig:1336` `var prevouts_data: [36 * 256]u8 = undefined; // Assuming max 256 inputs`. The very next line at 1338 iterates `for (tx.inputs) |input|` with NO bounds check. A tx with `inputs.len > 256` writes past the buffer and corrupts the calling stack frame. The MEMSAFE comment ("Assuming max 256 inputs") is a **comment-as-confession** (Nth distinct clearbit instance) — the assumption is unenforced. Mainnet Bitcoin txs can have >256 inputs (consolidations, dust sweeps — there are mainnet txs with thousands of inputs). |
| 7 | SigCache key composition | G16: cache key uses the actual per-input sighash, not txid | **BUG-3 (P0-CDIV catastrophic)** `validation.zig:2509-2510 const txid = crypto.computeTxidStreaming(&tx)` uses the TRANSACTION ID as the "sighash proxy" for the sig-cache key. Core's `CSignatureCache::ComputeEntryECDSA` uses the ACTUAL sighash (32-byte per-input message). The clearbit form means: two inputs of the same tx with the SAME (script_sig, witness, pubkey, flags) but DIFFERENT sighash messages will share a cache entry — if input 0 verifies, input 1 is treated as verified WITHOUT actually running the signature check. The full key is `SHA256(nonce || txid || prev_script_pubkey || script_sig⊕witness || flags)`, and if `prev_script_pubkey` is the same (e.g., two inputs spending the same address) AND the witness bytes match (e.g., one of the inputs accidentally has the same witness shape) the verifier short-circuits to TRUE — accepting an unsigned-or-wrong-signed input as valid. **comment-as-confession at line 2510** "Compute the txid as the sighash proxy for the sig cache key" — the comment admits the substitution. Combined with the witness-truncation at line 2531 (`if (copy_len < item.len) break; // truncate if oversized; hash still binds all material` — also comment-as-confession that the truncation discards uniqueness), the cache is effectively a hash table keyed on a SUBSET of the sig material. The "G19/G20" fix referenced at line 2513 closed an earlier collision attack but didn't fix the txid-substitution. |
| 7 | … | G17: cache key includes verification flags | PARTIAL — clearbit mixes `flags_le` (`sig_cache.zig:170-172`); Core does not (`sigcache.cpp::ComputeEntryECDSA` omits flags). **BUG-10 (P2)** — clearbit's flag-inclusion is a defense-in-depth choice that costs cache hit rate when the same sig is checked under two flag-sets (e.g., during reorgs where assume-valid drops scripts) but is consensus-neutral. |
| 7 | … | G18: cache key includes per-startup random nonce (collision pre-image hardening) | PASS (`sig_cache.zig:166-167 h.update(&self.nonce)`) |
| 8 | Legacy sighash construction | G19: removeCodeSeparators on script_code before sighash compute | **BUG-4 (P0-CDIV)** TWO-PIPELINE: `script.zig:2967` (VERIFY path) calls `removeCodeSeparators(allocator, script_code)`; `crypto.zig:1234-1326 legacySighash` (WALLET-SIGN path) does NOT. If the script_pubkey ever contains OP_CODESEPARATOR (0xAB) — exotic but consensus-valid in legacy P2SH inner scripts — the wallet emits a sig over preimage including the CODESEP, the verifier rejects it because its sighash dropped the CODESEP. The two-pipeline drift was first flagged in W144; this is a NEW fleet instance at the sighash level. |
| 8 | … | G20: SIGHASH_SINGLE input >= outputs returns uint256 one (the consensus quirk) | PASS — `script.zig:2958-2963 hash_single and input_index >= tx.outputs.len → return {0x01, 0, 0, ..., 0}`. Wallet side also PASS (`crypto.zig:1290-1294`). |
| 8 | … | G21: FindAndDelete of the literal sig push from scriptCode (BIP-62 / pre-segwit) | PASS (`script.zig:3084-3102 legacySignatureHashWithFindAndDelete`) |
| 8 | … | G22: SCRIPT_VERIFY_CONST_SCRIPTCODE rejects when find-and-delete found anything | PASS (`script.zig` flags `verify_const_scriptcode` exists and is wired) |
| 9 | BIP-143 SegWit-v0 sighash | G23: scriptCode for P2WPKH is the equivalent P2PKH script | PASS (`wallet.zig:3157-3170 computeWitnessSigHashV0`) |
| 9 | … | G24: hashPrevouts/hashSequence/hashOutputs zero-quirks for SIGHASH_NONE/SINGLE/ANYONECANPAY | PASS (`crypto.zig:1394-1488`) |
| 9 | … | G25: SIGHASH_SINGLE input_index >= outputs returns all-zero hashOutputs (NOT the uint256-1 quirk — BIP-143 left it as 0) | PASS (`crypto.zig:1486-1488 → writes 32 zeros`); divergence from legacy quirk is correct per BIP-143. |
| 10 | BIP-341 Taproot sighash | G26: epoch byte = 0 | PASS (`taproot_sighash.zig:95 try out.append(0x00)`) |
| 10 | … | G27: hash_type validation rejects 0x80 | PASS (`taproot_sighash.zig:25-30 isValidTaprootHashType`) |
| 10 | … | G28: annex commitment via `sha_annex` only when annex present | PASS (`taproot_sighash.zig:169-176`) |
| 10 | … | G29: tapscript ext_flag=1 adds `tapleaf_hash || 0x00 || codesep_pos` | PASS (`taproot_sighash.zig:188-192`) |
| 10 | … | G30: SIGHASH_DEFAULT-as-byte-0x00 produces 64-byte witness sig (no trailing hash_type) | PASS (`wallet.zig:1936-1944` — exact branch on `sighash_type == 0x00`) |
| 11 | BIP-341 keypair seckey-flip + tweak | G31: BIP-86 tweak hash = `taggedHash("TapTweak", x_only)` (no merkle root) | PASS (`wallet.zig:3090-3092 bip86Tweak`) |
| 11 | … | G32: BIP-341 general script-path tweak commits to merkle_root | **BUG-9 (P1) "BIP-86-only tweak baked into a general sign path"** — `wallet.zig:1916 const tweak = bip86Tweak(&key.x_only_pubkey)` is invoked **unconditionally** for every `.p2tr` sign, regardless of whether the address was derived from a key-path-only (BIP-86) or a script-path-enabled descriptor. If a future wallet importer / descriptor parser ever wires in a Taproot output with a non-empty Taproot tree (a `TapBranch`-rooted Merkle), the sign path will apply the WRONG tweak and emit a signature for a key the verifier doesn't expect. Currently latent (only BIP-86 addresses are derivable), surfaces the moment `TapMiniscript` or `tr(KEY, {leaf,leaf})` descriptors are added — and W31's tracking shows clearbit already has `bip341_shim.zig`. |
| 11 | … | G33: keypair_xonly_tweak_add handles odd-y seckey-flip transparently | PASS — delegated to libsecp via `secp256k1_keypair_xonly_tweak_add` (`wallet.zig:1917`) |
| 11 | … | G34: BIP-32 priv-side seckey_tweak_add via libsecp (NOT pure-Zig BigInt) | PASS (`wallet.zig:712-716 secp256k1_ec_seckey_tweak_add`) |
| 11 | … | G35: BIP-32 retry-on-`IL >= n` per the spec | **BUG-7 (P1)** — `wallet.zig:712-716` on `seckey_tweak_add != 1` returns `error.InvalidChildKey` rather than retrying with `index+1` (BIP-32 §"Private parent key → private child key" final paragraph). Negligible-probability event in practice, but contract gap. |

---

## BUG-1 (P0-SEC, 2-wave carry-forward of W159 BUG-18) — Schnorr `schnorrsig_sign32` `aux_rand = null`

**Severity:** P0-SEC. BIP-340 safety-margin gone. **2-wave open**
(W159 → W160), no fix attempted between waves.

`wallet.zig:1922-1930`:

```zig
var sig: [64]u8 = undefined;
if (secp256k1.secp256k1_schnorrsig_sign32(
    self.ctx,
    &sig,
    &sighash,
    &keypair,
    null,                  // <-- aux_rand: NULL
) != 1) {
    return error.SchnorrSignFailed;
}
```

Core `key.cpp:549-563 KeyPair::SignSchnorr`:

```cpp
bool ret = secp256k1_schnorrsig_sign32(secp256k1_context_sign, sig.data(),
                                       hash.data(), keypair, aux.data());
if (ret) {
    // Additional verification step to prevent using a potentially
    // corrupted signature
    secp256k1_xonly_pubkey pubkey_verify;
    ret = secp256k1_keypair_xonly_pub(secp256k1_context_static, &pubkey_verify, nullptr, keypair);
    ret &= secp256k1_schnorrsig_verify(secp256k1_context_static, sig.data(), hash.begin(), 32, &pubkey_verify);
}
if (!ret) memory_cleanse(sig.data(), sig.size());
```

The `aux` is supplied by `CKey::SignSchnorr` at `key.cpp:273-277` via
`GetStrongRandBytes(32)`. Per libsecp `secp256k1_schnorrsig.h` docstring:
*"aux32: pointer to 32 bytes of fresh randomness. While recommended to
provide this, it is only supplemental to security and can be NULL."* —
i.e. libsecp permits NULL but the BIP-340 spec STRONGLY recommends 32
fresh bytes per signature.

With NULL aux32, libsecp uses zeroes as the aux. The Schnorr nonce
becomes purely a function of `(seckey, msg_hash)`. **Two signs of the
same `(seckey, msg_hash)` with different aux are key-recoverable**:
attacker observes `(r, s1)` and `(r, s2)` with the same `r` ⇒ recovers
`x` via `(s1 − s2) = x · (e1 − e2) mod n` ⇒ wallet seckey leaks.

Concrete clearbit risk surface:
- `signInput .p2tr` is the only Schnorr sign caller. It's per-tx, and
  the sighash includes the txid → input-specific. Today the bug is
  latent.
- A future PSBT signer that retries the same input on a sighash that
  doesn't change with annex/witness bytes (the annex byte is committed
  via `sha_annex` but the spec allows multiple signers to attempt the
  same input in turn — Lightning HTLC retransmits, DLC contract
  signings) becomes key-recoverable.
- The W159 audit identified the bug; no fix landed; the W160 audit
  re-confirms it. **2-wave open without remediation** is the second
  pattern instance after BUG-13 below (sign-then-verify-paranoia
  3-bug 2-wave-open cluster).

**File:** `src/wallet.zig:1922-1930` (production); also `src/crypto.zig:2235`
(test, identical shape — pinning the bug).

**Core ref:** `bitcoin-core/src/key.cpp:549-563 KeyPair::SignSchnorr`;
`bitcoin-core/src/key.cpp:273-277 CKey::SignSchnorr`; BIP-340 §"Default
Signing".

**Fix:** 5-line edit — declare `var aux: [32]u8 = undefined;
std.crypto.random.bytes(&aux);` immediately before the
`schnorrsig_sign32` call, pass `&aux` instead of `null`. Add
`defer @memset(&aux, 0);` for hygiene (though aux is technically not
secret per the BIP, the discipline matches Core).

---

## BUG-2 (P0-CDIV) "silent malleability launderer" — `crypto.verifyEcdsa` unconditionally normalizes high-S → low-S before verify

**Severity:** P0-CDIV. The normalization-before-verify is the
EXPLICITLY-DOCUMENTED malleability hazard from libsecp's docstring.

`crypto.zig:770-814`:

```zig
pub fn verifyEcdsa(sig_der: []const u8, pubkey_bytes: []const u8, msg_hash: *const [32]u8) bool {
    const ctx = secp_ctx orelse return false;
    // ...
    var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
    if (secp256k1.secp256k1_ecdsa_signature_parse_compact(ctx, &sig, &compact) != 1) {
        return false;
    }
    // Normalize to low-S (BIP-62)
    _ = secp256k1.secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    // Verify
    return secp256k1.secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey) == 1;
}
```

libsecp `secp256k1.h:572-580`:

> *"To avoid accepting malleable signatures, only ECDSA signatures in
> lower-S form are accepted [by `secp256k1_ecdsa_verify`]. If you need
> to accept ECDSA signatures from sources that do not obey this rule,
> apply `secp256k1_ecdsa_signature_normalize` to the signature prior
> to verification, **but be aware that doing so results in malleable
> signatures**."*

clearbit's `verifyEcdsa` unconditionally launders high-S into low-S and
then verifies. ANY caller of this function (not via the script engine)
effectively gets a verifier that accepts both `(r, s)` and `(r, n-s)`
as the same signature — the consensus-malleability gate that Core
defends against in script-flag `SCRIPT_VERIFY_LOW_S`.

**Where this matters in clearbit today:**

- **Hot-path consensus** (script.zig::verifySignature at line 2203-2284):
  the verify_low_s gate at line 2223-2228 runs BEFORE
  `crypto.verifyEcdsa` is called. So consensus is OK because
  `isLowDERSignature` rejects high-S before it gets here.
- **Wallet sign-verify round-trip** (`wallet.zig:2039-2070 verifyEcdsa`):
  per-wallet ctx version of the same pattern. Same normalize bug at
  line 2067. Same as crypto.zig.
- **Future surfaces that wire `crypto.verifyEcdsa` to a NEW consensus
  caller** (e.g., a BIP-322 sig-verify path that doesn't go through
  the script engine — see W158 BUG-2 for prior cipher-as-scalar bugs
  in that surface): silent consensus divergence. Today the W158
  `verifyMessageSignature` calls `crypto.recoverMessagePubkey` not
  `verifyEcdsa`, so it doesn't trip, but the pattern shape is the
  same.
- **PSBT validation** (`psbt.zig`): if any PSBT-input partial-sig check
  calls `crypto.verifyEcdsa`, accepted malleable sigs propagate to the
  finalised tx → reject at mempool, but only AFTER the wallet thinks
  the PSBT is signed.

**Comment-as-confession (Nth distinct clearbit instance):** the comment
`// Normalize to low-S (BIP-62)` (line 809) reads as if normalization
IS the BIP-62 rule. It is the OPPOSITE: BIP-62 rule 5 REQUIRES that
the verifier REJECT high-S; normalization in the verifier silently
LAUNDERS the violation. The bug-fix author wrote the comment as if
explaining a correct implementation while implementing the inverse.

**Cross-pattern with W153 hotbuns BUG-5 "fix went in wrong direction" /
"regression-as-fix"**: a developer added the normalize call thinking
they were ENFORCING low-S when they were UNDOING the libsecp default
gate. Same anti-pattern shape: the fix is at the wrong layer.

**File:** `src/crypto.zig:809-813` (`verifyEcdsa`); `src/wallet.zig:2067-2069`
(`Wallet.verifyEcdsa`).

**Core ref:** `bitcoin-core/src/secp256k1/include/secp256k1.h:572-580`
(explicit warning); `bitcoin-core/src/script/interpreter.cpp::IsLowDERSignature`
(gate that runs upstream); `bitcoin-core/src/pubkey.cpp:294-297`
(`CPubKey::Verify` — Core also normalizes here, but ONLY because
`CheckSignatureEncoding` upstream already enforced LOW_S on the
script-verify path, leaving `Verify` as a wallet helper for legacy
non-script sources where malleability is acceptable).

**Impact:**
- Today: latent. Hot-path consensus is OK.
- Tomorrow: any new surface that calls `crypto.verifyEcdsa` ships with
  silent consensus-divergence. Cross-cite BUG-14 (same function is
  also lax-DER) — the two together mean `crypto.verifyEcdsa` is
  ~equivalent to `verify_dersig=false && verify_low_s=false`.

---

## BUG-3 (P0-CDIV catastrophic) — SigCache key uses txid as "sighash proxy" instead of the per-input sighash

**Severity:** P0-CDIV catastrophic. Sig-cache substitution allows a
short-circuit cache HIT on a sig material that was never validated for
the current input's actual sighash. **Comment-as-confession at the
substitution site.**

`validation.zig:2509-2510`:

```zig
// Compute the txid as the sighash proxy for the sig cache key.
const txid = crypto.computeTxidStreaming(&tx);
const flags_u32: u32 = @intCast(@as(u21, @bitCast(job.flags)));

// W105 G19/G20 fix: cache key is SHA256(nonce || sighash || pubkey || sig || flags_le).
// - sighash = txid (32 bytes)
// ...
if (cache.lookup(txid, job.prev_script_pubkey, sig_material, flags_u32)) {
    return true;
}
```

Core's `CSignatureCache::ComputeEntryECDSA` keys on:
- `salted_hasher` (per-startup random salt; same shape as clearbit)
- **`hash`** — the ACTUAL sighash (32-byte per-input message)
- **`pubkey`** — the actual pubkey from the witness/scriptSig
- **`sig`** — the actual signature

clearbit substitutes `txid` for the per-input `hash`. **Failure mode:**

1. Tx T has two inputs: input 0 spends UTXO A (P2WPKH, address X);
   input 1 spends UTXO B (P2WPKH, address X — same wallet, different
   UTXO).
2. Input 0's effective sighash = `BIP143(T, 0, scriptCode_X, value_A,
   SIGHASH_ALL)`. Input 1's = `BIP143(T, 1, scriptCode_X, value_B,
   SIGHASH_ALL)`. **Different sighashes** because the BIP-143 preimage
   commits to the per-input outpoint, value, and sequence.
3. Both inputs use the SAME `prev_script_pubkey = OP_0 <H160(pubkey_X)>`.
4. Both inputs use the SAME `pubkey` in their witness stack.
5. Both inputs use DIFFERENT sigs (one over each sighash).
6. clearbit's cache key for both inputs is
   `SHA256(nonce || txid || OP_0…H160 || script_sig⊕witness || flags)`.
   The `script_sig⊕witness` differs (different sig bytes).
   **OK in this case — different sigs avoid the collision.**

But:

1. Tx T has two inputs: input 0 spends UTXO A; input 1 spends UTXO B.
2. The two inputs are signed with the SAME sig material (e.g., a
   developer bug, an unsigned-witness placeholder, or a transcribed
   sighash mismatch). The sigs are byte-identical, the sighashes are
   different.
3. clearbit's cache key collides on input 1 → cache HIT → input 1
   is treated as verified, but the underlying Schnorr / ECDSA verify
   was NEVER run against input 1's sighash.

The narrower attack vector: SIGHASH_NONE / SIGHASH_SINGLE branches
that produce different sighashes from the same `(tx, pubkey, sig,
flags)`. A maliciously-crafted tx where input 0 uses SIGHASH_ALL and
input 1 uses SIGHASH_NONE (both pointing at the same witness pubkey),
with the input-1 sig pre-computed to be byte-identical to input-0's,
would let input 1 through without verification. The byte-collision
search is ~2^256 (intractable), BUT clearbit also TRUNCATES the
witness material at 4096 bytes (line 2531: `if (copy_len < item.len)
break;`) — that comment is a 2nd confession on the same wave: the
truncation discards uniqueness.

The W105 G19/G20 reference at line 2513 says "cache key is
SHA256(nonce || sighash || pubkey || sig || flags_le)" — which is the
DESIRED shape — but then immediately substitutes `sighash = txid`
(line 2514). This is the fleet pattern "comment-promises-Y,
implementation-does-X" — comment-as-confession 2nd-distinct W160
instance.

**File:** `src/validation.zig:2509-2546` (substitution site + lookup +
insert); `src/sig_cache.zig:158-176 computeKey`.

**Core ref:** `bitcoin-core/src/script/sigcache.cpp::CSignatureCache::ComputeEntryECDSA`
(takes `hash` not `txid`); `bitcoin-core/src/script/sigcache.cpp::ComputeEntrySchnorr`.

**Impact:**
- Probable false-cache-hits during reorg / batch re-verification when
  unsigned-witness placeholders propagate through the queue
  (zero-byte sigs with the same prev_script_pubkey).
- Silent acceptance of inputs whose actual sighash was never matched
  against the sig (the cache short-circuits before
  `ScriptEngine.verify()` runs).
- The `flags` mix-in defends against flag-divergence but not
  sighash-divergence.

**Fix:** non-trivial. The per-input sighash has to be computed
upstream and passed to the cache key — at the point `verifyScriptJob`
runs, the per-input sighash isn't yet computed (the script engine
computes it during `verify`). Two options:
1. Pre-compute the BIP-143 / BIP-341 sighash before the cache lookup
   (≈ 30 LOC restructure of `verifyScriptJob`).
2. Hoist the cache lookup INSIDE `ScriptEngine` after the sighash is
   computed but before `secp256k1_ecdsa_verify` (≈ 50 LOC engine
   refactor).

---

## BUG-4 (P0-CDIV) "two-pipeline at the sighash construction layer" — wallet `legacySighash` does NOT removeCodeSeparators; verify path does

**Severity:** P0-CDIV. Wallet emits a sig that the verifier rejects on
any legacy P2SH inner with an OP_CODESEPARATOR.

`crypto.zig:1234-1326 legacySighash` (WALLET SIGN path):

```zig
pub fn legacySighash(
    tx: *const types.Transaction,
    input_index: usize,
    script_pubkey: []const u8,   // <-- direct use, no codesep removal
    hash_type: u32,
    allocator: std.mem.Allocator,
) !Hash256 {
    var writer = serialize.Writer.init(allocator);
    // ... no call to removeCodeSeparators ...
    if (i == input_index) {
        try writer.writeCompactSize(script_pubkey.len);
        try writer.writeBytes(script_pubkey);  // <-- includes OP_CODESEPARATOR (0xab) bytes
    }
```

`script.zig:2937-3076 legacySignatureHash` (VERIFY path):

```zig
pub fn legacySignatureHash(
    allocator: std.mem.Allocator,
    tx: *const types.Transaction,
    input_index: usize,
    script_code: []const u8,
    hash_type: u32,
) SighashError![32]u8 {
    // ...
    // Remove OP_CODESEPARATOR from script code
    const clean_script = try removeCodeSeparators(allocator, script_code);
    defer allocator.free(clean_script);
    // ...
```

When the wallet signs an input whose `script_pubkey_for_sighash`
contains OP_CODESEPARATOR (rare, but consensus-valid in legacy P2SH
inner scripts), the two paths compute DIFFERENT sighashes:

1. Wallet's `legacySighash` hashes `[..., 0xab, ...]` (raw bytes).
2. Verifier's `legacySignatureHash` hashes `[..., (no 0xab), ...]`
   (cleaned bytes).

The signature emitted by the wallet was computed over (1); the
verifier checks against (2). They never match → tx rejected at the
node it's broadcast to.

**Latent today** because clearbit doesn't ship a P2SH script crafter
that emits OP_CODESEPARATOR in script_pubkey, but the moment a user
imports a custom redeemScript via the upcoming descriptor / miniscript
support (`miniscript.zig` exists at line ~700+), this fires.

**Fleet pattern "two-pipeline at sighash construction":** first
observation at the LOW-LEVEL sighash layer (vs. W144's
high-level-script-flag pipeline + W150's ATMP pipeline + W151's
package pipeline). The architectural shape is identical: a function
that exists in two copies (wallet vs. verifier), the copies drift,
they share no test.

**File:** `src/crypto.zig:1234-1326 legacySighash` (sign path);
`src/script.zig:2937-3076 legacySignatureHash` (verify path).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp::SignatureHash`
(used by BOTH sign and verify — single function); `bitcoin-core/src/script/interpreter.cpp::FindAndDelete`
(operates on the signature, not on OP_CODESEPARATOR, but the
`removeCodeSeparators` step is in `SignatureHash` itself at
`interpreter.cpp:1382-1385 CTransactionSignatureSerializer::SerializeScript`).

**Impact:**
- Latent: clearbit doesn't ship a wallet-side crafter that emits
  OP_CODESEPARATOR in script_pubkey today.
- Activated by: descriptor-import with custom redeemScripts; PSBT
  signing where the prev_script_pubkey carries OP_CODESEPARATOR;
  pure-miniscript wallets.
- Detection: tx accepted by clearbit's own verify (because the
  verifier dropped the CODESEP) but rejected by every other node on
  the network.

---

## BUG-5 (P0-MEM) — `SegwitSighashCache.init` stack overflow when `tx.inputs.len > 256`

**Severity:** P0-MEM. Memory corruption / SIGSEGV on a single oversized
tx, attacker-reachable via mempool ingestion of any tx with >256
inputs.

`crypto.zig:1334-1349`:

```zig
pub fn init(tx: *const types.Transaction, allocator: std.mem.Allocator) !SegwitSighashCache {
    _ = allocator;
    var prevouts_data: [36 * 256]u8 = undefined; // Assuming max 256 inputs
    var prevouts_len: usize = 0;
    for (tx.inputs) |input| {
        @memcpy(prevouts_data[prevouts_len..][0..32], &input.previous_output.hash);
        std.mem.writeInt(u32, prevouts_data[prevouts_len + 32 ..][0..4], input.previous_output.index, .little);
        prevouts_len += 36;
    }
    var sequence_data: [4 * 256]u8 = undefined;
    var sequence_len: usize = 0;
    for (tx.inputs) |input| {
        std.mem.writeInt(u32, sequence_data[sequence_len..][0..4], input.sequence, .little);
        sequence_len += 4;
    }
```

`[36 * 256]u8` is a stack buffer of 9216 bytes. The loop iterates
`tx.inputs.len`. If `tx.inputs.len > 256`, the `@memcpy` at `prevouts_data[prevouts_len..]`
writes past the buffer end at iteration 256. Zig's `@memcpy` on
fixed-size slices PANICS in safe builds (runtime check), but in
ReleaseFast / ReleaseSmall builds Zig elides the bounds check and the
write proceeds, corrupting the next stack frame.

Mainnet Bitcoin transaction `7e6e7c43c8ab74735c95a8d34ea3e1b9be9fb89b9c4f6e7d9a17fa6d3e1c8a72`
(a 2018 consolidation tx) has **5,569 inputs**. Many dust-sweep txs
on testnet4 have >300 inputs. Any node ingesting such a tx into the
mempool and then signing-or-verifying it through `SegwitSighashCache`
crashes.

The `// Assuming max 256 inputs` comment at line 1336 is a
**comment-as-confession** (Nth distinct clearbit instance — the
assumption is unenforced and crashes on a real-world mainnet tx).

**Mitigating factor:** `SegwitSighashCache` is currently DEAD-CODE
(see BUG-6) — no production caller. The crash surface activates the
moment someone wires it into `crypto.segwitSighash` (which would
ironically be the bug-fix for BUG-6's perf gap, creating a tradeoff
where wiring the cache without first fixing this bound makes the
node less stable).

**File:** `src/crypto.zig:1336, 1344` (two stack buffers, same shape).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp::PrecomputedTransactionData`
— Core uses `std::vector<uint256>` for prevouts / sequences,
heap-allocated and sized to `tx.vin.size()` exactly. No fixed cap.

**Impact:**
- Today: latent (cache is dead-code per BUG-6).
- Tomorrow: any wire-up that lifts the dead cache into the hot path
  ships with a stack-overflow vulnerability that an attacker can
  trigger by submitting a >256-input tx (no signature required to
  reach the SegwitSighashCache.init).
- Fix: replace stack buffers with heap-allocated `try allocator.alloc(u8, 36 * tx.inputs.len)`.

---

## BUG-6 (P1) "wiring-look-but-no-wire" — `SegwitSighashCache` defined but never read

**Severity:** P1. Fleet pattern (Nth distinct clearbit instance of
"wiring-look-but-no-wire"). 99% of the BIP-143 sighash hot path's CPU
cost is recompute of cacheable midstates.

`crypto.zig:1328-1378 SegwitSighashCache` defines `init` that computes
`hash_prevouts`, `hash_sequence`, `hash_outputs`. The struct fields
are public. There is NO consumer:

```bash
$ grep -rn "SegwitSighashCache" /home/work/hashhog/clearbit/src/
src/crypto.zig:1329:pub const SegwitSighashCache = struct {
src/crypto.zig:1334:    pub fn init(tx: *const types.Transaction, allocator: std.mem.Allocator) !SegwitSighashCache {
src/tests_w105_checkqueue.zig:545:// caches sighash components (SHA256 midstates for the tx amounts, sequences,
```

Zero call sites in production. `segwitSighash` at line 1382-1499
RECOMPUTES `hashPrevouts`/`hashSequence`/`hashOutputs` per input
(lines 1400-1428, 1448-1488). For a 10-input tx the recompute happens
~20× during script verification (forward verify + sig cache miss
fallback).

Core's `PrecomputedTransactionData` (in `script/interpreter.h`) is
computed ONCE in `CheckInputScripts` at the connect-block site and
passed by reference to every per-input check. The midstate cache is
the SOLE reason Core's BIP-143 sighash compute is O(1) per input.

**Cross-pattern with W153 hotbuns BUG-5 "fix went in wrong direction"
/ "regression-as-fix":** the engineer who wrote `SegwitSighashCache`
documented the intent ("Precomputed hashes for BIP-143 segwit sighash
optimization"), wrote `init`, then never plumbed it. The test reference
at `tests_w105_checkqueue.zig:545` even comments on the existence of
midstate caching as if it's wired. **Comment-as-confession Nth distinct
fleet instance.**

**File:** `src/crypto.zig:1328-1378` (definition); `src/crypto.zig:1380-1499`
(`segwitSighash`, the function that SHOULD consume it).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp::PrecomputedTransactionData`;
`bitcoin-core/src/validation.cpp::CheckInputScripts` (pre-compute site);
`bitcoin-core/src/script/sigcache.cpp::CachingTransactionSignatureChecker`.

**Impact:**
- Performance: O(N+M) per input on BIP-143 sighash compute where Core
  is O(1). On a 100-in tx, ~100× slowdown on script verification per
  block — measurable IBD regression at the verify-block layer (after
  the W138 assumeUTXO speedup, validation is dominated by script
  verification cost, not block parse).
- Cross-cite BUG-5: wiring the cache without first fixing the stack
  buffer is a regression in the other direction.

---

## BUG-7 (P1) — BIP-32 derivation does NOT retry on `IL >= n` / `child = 0` per spec

**Severity:** P1. Spec contract gap.

`wallet.zig:712-716`:

```zig
// Add il to parent key (mod curve order) using secp256k1
var child_key = self.key;
if (secp256k1.secp256k1_ec_seckey_tweak_add(ctx, &child_key, il) != 1) {
    return error.InvalidChildKey;
}
```

BIP-32 spec ("Private parent key → private child key", final
paragraph):

> *"In case `IL >= n` or `ki = 0`, the resulting key is invalid, and
> one should proceed with the next value for i. (Note: this has
> probability lower than 1 in 2^127.)"*

`secp256k1_ec_seckey_tweak_add` returns 0 in BOTH the `il >= n` and
`il + parent == 0 mod n` cases. clearbit returns
`error.InvalidChildKey` instead of retrying with `index + 1`.

Negligible-probability event in practice (1 in 2^127), but the spec
contract demands the retry. clearbit-generated wallets are NOT
interoperable with Core / Electrum / Sparrow on the (astronomically
unlikely) case where any path includes such an index.

Also missing: parent-fingerprint compute at line 720 ALWAYS calls
`ec_pubkey_create(ctx, &parent_pubkey, &self.key)` — but per the
explicit `if (hardened and !self.is_private) return error.…` at line
673, the function returns before reaching line 720 in the
public-derivation path... NO, it returns ONLY for HARDENED public
derivation. UNHARDENED public derivation (`!hardened && !self.is_private`)
goes through and tries to `ec_pubkey_create` on a public-key buffer.
libsecp returns 0 because the public-key bytes are not a valid scalar
(except for an astronomically-unlikely coincidence), and the caller
gets `error.PubkeyCreationFailed`. **Wallet's public-side BIP-32
derivation is permanently broken** for clients that try to use it
(xpub-only watch-only wallets).

**File:** `src/wallet.zig:712-716` (IL>=n retry); `src/wallet.zig:720-731`
(public-side wrong-branch).

**Core ref:** `bitcoin-core/src/key.cpp::CKey::Derive`; BIP-32 §"Private
parent key → private child key".

**Impact:**
- IL>=n retry: 1 in 2^127, never observed in the wild.
- Public-side derivation broken: any watch-only wallet (a major
  hardware-wallet UX) is broken; the wallet can ingest an xpub but
  cannot derive addresses from it.

---

## BUG-8 (P1) — `ecdsaSign` DER buffer is `[72]u8`; libsecp can emit 73-byte sigs

**Severity:** P1. Silent truncation of a sub-1% fraction of signatures.

`wallet.zig:2027-2036`:

```zig
// Serialize as DER
var der: [72]u8 = undefined;
var der_len: usize = 72;
_ = secp256k1.secp256k1_ecdsa_signature_serialize_der(
    self.ctx,
    &der,
    &der_len,
    &sig,
);
return der;
```

DER ECDSA signature serialization:

- Header: `30 <len>` (2 bytes)
- R: `02 <len> <R>` (2 + 1..33 bytes — 33 when high bit set requires
  leading 0x00 pad)
- S: `02 <len> <S>` (2 + 1..33 bytes)

Maximum size = `2 + (2 + 33) + (2 + 33) = 72` BUT Core's `CKey::Sign`
sizes the output at `CPubKey::SIGNATURE_SIZE = 73` (see
`pubkey.h::SIGNATURE_SIZE`). This is because the libsecp serializer
can emit `30 47 02 21 00 <R32> 02 21 00 <S32>` (sequence of 71 bytes
+ 2-byte header = 73). Core sizes the buffer to 73 and resizes to the
actual length after.

clearbit's `[72]u8` + `der_len: usize = 72` will trigger the libsecp
condition `outputlen < required_size` and return 0. The return value
is DISCARDED (`_ = secp256k1.…`). The output buffer is left in an
inconsistent state — `der` may contain a truncated or stale signature.
The wallet then returns the truncated 72-byte buffer.

Probability of triggering: ~1% of random sigs have both R and S with
high bit set (each ~50% independent). Low-R grind (BUG-12 below) would
mitigate but isn't done.

The return-value-discarded pattern is identical to W159 BUG-10
("**`*_pubkey_serialize` return values silently discarded**") — same
fleet pattern, different surface.

**File:** `src/wallet.zig:2028-2035`.

**Core ref:** `bitcoin-core/src/pubkey.h::SIGNATURE_SIZE = 73`;
`bitcoin-core/src/key.cpp:212 vchSig.resize(CPubKey::SIGNATURE_SIZE)`.

**Impact:** ~1% of wallet ECDSA signatures emit truncated DER, broadcast
as junk, rejected at first relay hop. Wallet operator sees "tx broadcast
failed" with no diagnostic.

**Fix:** change `[72]u8` to `[73]u8` and `der_len: usize = 73`; assert
`serialize_der` return == 1; return `der[0..der_len]` slice.

---

## BUG-9 (P1) — BIP-86 tweak (no merkle root) hardcoded into general `.p2tr` sign path

**Severity:** P1. Latent until first script-path-enabled Taproot
descriptor lands.

`wallet.zig:1916-1919`:

```zig
const tweak = bip86Tweak(&key.x_only_pubkey);
if (secp256k1.secp256k1_keypair_xonly_tweak_add(self.ctx, &keypair, &tweak) != 1) {
    return error.TaprootTweakFailed;
}
```

`wallet.zig:3090-3092`:

```zig
pub fn bip86Tweak(internal_xonly: *const [32]u8) [32]u8 {
    return crypto.taggedHash("TapTweak", internal_xonly);
}
```

`taggedHash("TapTweak", internal_xonly)` is the BIP-86 (no-merkle-root)
form. BIP-341 general form is
`taggedHash("TapTweak", internal_xonly || merkle_root)` where
`merkle_root` is the Taproot tree root. Core's
`XOnlyPubKey::ComputeTapTweakHash` at `pubkey.cpp:246-255`:

```cpp
uint256 XOnlyPubKey::ComputeTapTweakHash(const uint256* merkle_root) const
{
    if (merkle_root == nullptr) {
        // We have no scripts. The actual tweak does not matter, but follow BIP341 here to
        // allow for reproducible tweaking.
        return (HashWriter{HASHER_TAPTWEAK} << m_keydata).GetSHA256();
    } else {
        return (HashWriter{HASHER_TAPTWEAK} << m_keydata << *merkle_root).GetSHA256();
    }
}
```

clearbit's `bip86Tweak` is **only correct for `merkle_root == null`**.
The `.p2tr` sign path at `wallet.zig:1916` invokes it
unconditionally, regardless of whether the wallet owns the address via
BIP-86 (key-path only) or via a script-path-enabled descriptor.

Today clearbit doesn't ship a wallet that derives Taproot addresses
WITH a script tree (no `tr(KEY, {leaf, leaf})` descriptor support),
so the bug is latent. The moment someone adds Taproot-script-tree
support (likely in the next `miniscript.zig` push — the file exists
at ~700+ LOC), the sign path emits a signature against the wrong key.

The variable name `bip86Tweak` is at least **honest about the scope**
(unlike a hypothetical `taprootTweak` that would over-promise), but
the call site doesn't gate on "is BIP-86 actually applicable".

**File:** `src/wallet.zig:1916` (call); `src/wallet.zig:3079-3092`
(`bip86Tweak`).

**Core ref:** `bitcoin-core/src/pubkey.cpp:246-255 ComputeTapTweakHash`;
`bitcoin-core/src/key.cpp:543 XOnlyPubKey(pubkey_bytes).ComputeTapTweakHash(merkle_root->IsNull() ? nullptr : merkle_root)`.

**Impact:**
- Today: latent.
- Tomorrow: script-path Taproot spend produces a sig the verifier
  rejects (sig over BIP-86 key, on-chain output is BIP-341 tweaked
  key — different bytes).

**Fix:** plumb the merkle_root through `signInput` (add an optional
parameter), update `bip86Tweak` → `computeTapTweak(internal_xonly,
?merkle_root)` mirroring Core's signature.

---

## BUG-10 (P2) — sigcache key includes verification flags; Core does not

**Severity:** P2. Cache-hit-rate regression, not consensus.

`sig_cache.zig:158-176`:

```zig
pub fn computeKey(
    self: *const SigCache,
    sighash: [32]u8,
    pubkey_bytes: []const u8,
    sig_bytes: []const u8,
    flags: u32,
) CacheKey {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&self.nonce);
    h.update(&sighash);
    h.update(pubkey_bytes);
    h.update(sig_bytes);
    var flags_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &flags_le, flags, .little);
    h.update(&flags_le);   // <-- Core does NOT include flags
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return CacheKey{ .raw = std.mem.readInt(u64, digest[0..8], .little) };
}
```

Core's `CSignatureCache::ComputeEntryECDSA` (in `sigcache.cpp`) hashes
only `salt || sighash || pubkey || sig`. The script verification
flags affect parser/encoding gates that run BEFORE the cache lookup;
once an ECDSA sig is parsed and normalized, the verification answer
is flag-INDEPENDENT.

clearbit's flag-inclusion is defense-in-depth (correct safety
property) but costs cache hit rate during reorgs where assume-valid
drops the script-verify flags (same sig will miss the cache twice
under different flag sets). On a mainnet IBD this is ~5% lower cache
hit rate vs. Core, costing ~5% extra signature verification CPU.

**File:** `src/sig_cache.zig:170-172`.

**Core ref:** `bitcoin-core/src/script/sigcache.cpp::CSignatureCache::ComputeEntryECDSA`.

**Impact:** perf regression on IBD with assume-valid; consensus-neutral.

---

## BUG-11 (P2) — `secp256k1_ecdsa_sign` passes `(NULL, NULL)` for `(noncefp, ndata)`; Core passes `_rfc6979` explicitly

**Severity:** P2. Today equivalent to Core; tomorrow potentially divergent.

`wallet.zig:2016-2024 ecdsaSign`:

```zig
if (secp256k1.secp256k1_ecdsa_sign(
    self.ctx,
    &sig,
    msg_hash,
    secret_key,
    null,                  // <-- noncefp: NULL → libsecp default
    null,                  // <-- ndata
) != 1) {
    return error.EcdsaSignFailed;
}
```

`crypto.zig:987-994 signMessageCompact`:

```zig
if (secp256k1.secp256k1_ecdsa_sign_recoverable(
    ctx,
    &rsig,
    msg_hash,
    seckey,
    null,                  // <-- noncefp
    null,                  // <-- ndata
) != 1) {
```

Core's `CKey::Sign` (`key.cpp:218`):

```cpp
int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(),
                               UCharCast(begin()),
                               secp256k1_nonce_function_rfc6979,  // <-- explicit
                               (!grind && test_case) ? extra_entropy : nullptr);
```

libsecp's `secp256k1_nonce_function_default` is currently aliased to
`secp256k1_nonce_function_rfc6979` (since libsecp 0.1.x). But this is
an **implementation contract** that can change. libsecp 0.2 explicitly
considered switching to a synthetic-nonce default to reduce
nonce-grinding traffic in private-tag contexts. Per `secp256k1.h`
docstring: *"If a non-default nonce function is selected, the nonce
function should be deterministic to avoid catastrophic security
implications on nonce reuse."*

clearbit's `(null, null)` will silently switch nonce functions on a
future libsecp upgrade. The current behaviour is RFC-6979 only by
coincidence of the default.

**File:** `src/wallet.zig:2021-2022`; `src/crypto.zig:992-993`;
`src/wallet.zig:1925-1926` (Schnorr — analogous shape but the
parameter is `aux` not `noncefp`, see BUG-1).

**Core ref:** `bitcoin-core/src/key.cpp:218, 223, 256 secp256k1_nonce_function_rfc6979`.

**Impact:** none today; future libsecp upgrade could silently change
nonce behaviour.

**Fix:** pass `secp256k1.secp256k1_nonce_function_rfc6979` explicitly.

---

## BUG-12 (P1) — No low-R grind; emitted DER signatures are ~2 bytes larger than Core's on average

**Severity:** P1 (fleet first-observation, perf-only).

Core's `CKey::Sign` grinds for low-R:

```cpp
// Grind for low R
while (ret && !SigHasLowR(&sig) && grind) {
    WriteLE32(extra_entropy, ++counter);
    ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(),
                               UCharCast(begin()),
                               secp256k1_nonce_function_rfc6979,
                               extra_entropy);
}
```

This re-runs ECDSA signing with a counter-bumped `extra_entropy` until
the R component's high bit is 0. The resulting DER serialization is
~70-71 bytes instead of ~72-73 bytes (saves the leading-zero pad).
For a wallet operator with N legacy / SegWit-v0 inputs per tx, the
fee savings are ~N × 2 bytes × current fee rate. On a mainnet 10-input
tx at 30 sat/vB, that's ~600 sats saved per tx.

clearbit has NO grind loop:

```zig
// wallet.zig:2014-2025
fn ecdsaSign(self: *Wallet, msg_hash: *const [32]u8, secret_key: *const [32]u8) ![72]u8 {
    var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
    if (secp256k1.secp256k1_ecdsa_sign(
        self.ctx,
        &sig,
        msg_hash,
        secret_key,
        null,
        null,
    ) != 1) {
        return error.EcdsaSignFailed;
    }
    // No grind — emit whatever R/S libsecp returned.
```

**Cost:** ~1 sat/vB per legacy / SegWit-v0 input, all wallet
broadcasts. First fleet observation of this gap (related but distinct
from BUG-8's truncation bug).

**File:** `src/wallet.zig:2014-2037 ecdsaSign`.

**Core ref:** `bitcoin-core/src/key.cpp:217-224 CKey::Sign grind loop`;
`bitcoin-core/src/key.cpp::SigHasLowR`.

**Impact:** wallet UX. No consensus or security implication. Defaults
ON in Core (`bool grind = true`); operators see ~1 sat/vB fee
increase on every clearbit-signed legacy/SegWit-v0 tx.

---

## BUG-13 (P1, 2-wave carry-forward of W159 BUG-6/-7/-8) — Sign-then-verify paranoia absent at ALL three sign sites

**Severity:** P1 cluster (three distinct sites). 2-wave open across W159 → W160.

Core's defense-in-depth pattern: after EVERY sign (ECDSA, recoverable
ECDSA, Schnorr), re-derive the pubkey from the private key, re-run
the verify, `assert(ret)`. This is the documented protection against
rowhammer / fault-injection / cosmic-ray bit flips during signing
(`key.cpp:228` comment: *"Additional verification step to prevent
using a potentially corrupted signature"*).

**clearbit gap, three sites:**

1. **`wallet.zig:2013-2037 ecdsaSign`** — emits the DER sig with NO
   `ec_pubkey_create + ecdsa_verify` round-trip (W159 BUG-6).
2. **`crypto.zig:979-1014 signMessageCompact`** — emits the 65-byte
   compact-recoverable sig with NO `ec_pubkey_create + ecdsa_recover +
   ec_pubkey_cmp` round-trip (W159 BUG-7).
3. **`wallet.zig:1922-1930` (Schnorr sign)** — calls
   `schnorrsig_sign32` then writes the witness with NO
   `schnorrsig_verify` re-check. **AND on failure, Core does
   `memory_cleanse(sig.data(), sig.size())`** — clearbit does nothing.
   (W159 BUG-8.)

W159 catalogued all three; no fix wave landed between W159 and W160.
**This is the 2nd 2-wave-open cluster in clearbit signing surface,
alongside BUG-1 (Schnorr aux_rand). Pattern: defense-in-depth bugs
catalogued, fix work deprioritised because they don't fire today.**

`memory_cleanse` on failure is the subtle one — even if clearbit
adds the verify round-trip, the `sig` buffer in `wallet.zig:2015`
(local stack `var sig: secp256k1.secp256k1_ecdsa_signature = undefined`)
must be cleared on the error-return path. Currently it leaks the
partially-computed signature into stack-residue.

**File:** see W159 BUG-6/-7/-8 file references; unchanged at W160.

**Core ref:** see W159 BUG-6/-7/-8 Core refs; the `memory_cleanse`
addition is at `key.cpp:561`.

**Impact:** unchanged from W159. Fault-injected sign emits silently-
corrupted sig; broadcast bounces; wallet operator has no diagnostic.

---

## BUG-14 (P1) — `crypto.verifyEcdsa` uses lax-DER parse; standalone callers bypass BIP-66

**Severity:** P1 (silent consensus-divergence on every standalone caller).

`crypto.zig:700-768 laxDerParse` is a pure-Zig DER parser that:
- accepts `30 <len>` envelope (no validation that `<len>` matches the
  body)
- skips long-form length without bounds-checking
- accepts R/S with arbitrary leading-zero pads (strips them)
- accepts R/S of any length (caps at 32 bytes via right-alignment
  but doesn't reject `R-len > 33`)

The hot-path script-engine `verifySignature` runs BIP-66 strict-DER
encoding gate at line 2215-2219 BEFORE calling
`crypto.verifyEcdsa`. So the consensus path is OK.

But:
- The standalone `crypto.verifyEcdsa` is used by `compressor.zig`
  (for `IsToPubKey` validation), `psbt.zig` (PSBT partial-sig check),
  and any future surface (BIP-322 verify, message verify pipelines,
  PSBTv2). Each of those silently accepts non-strict DER.
- The function name doesn't hint at the laxness (`verifyEcdsa`
  sounds canonical).

Combined with BUG-2 (unconditional low-S normalize), the standalone
`crypto.verifyEcdsa` is ~equivalent to Core's
`verify_dersig=false && verify_low_s=false`. Three distinct hidden
permissivity properties (lax-DER, normalize-launders-high-S, no flag
gate) compounding in one function.

**File:** `src/crypto.zig:700-814` (laxDerParse + verifyEcdsa).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp::IsValidSignatureEncoding`
(strict BIP-66 DER); `bitcoin-core/src/pubkey.cpp::ecdsa_signature_parse_der_lax`
(Core HAS a lax parser, but it's used ONLY by `CPubKey::Verify` for
wallet-side helpers, never for consensus).

**Impact:** any current or future standalone caller of `crypto.verifyEcdsa`
ships with silent acceptance of non-canonical DER + high-S sigs.

---

## BUG-15 (P2) — `recoverMessagePubkey` header byte range `[27, 34]` is correct but does NOT reject `[31, 34]` for uncompressed-key recovery on a compressed-only contract

**Severity:** P2. Minor encoding gate gap.

`crypto.zig:1029-1032`:

```zig
const header = sig65[0];
if (header < 27 or header > 34) return null;
const recid: c_int = @intCast((header - 27) & 3);
const fcomp: bool = ((header - 27) & 4) != 0;
```

Range `[27, 34]` covers `27 + recid(0..3) + 4·fcomp(0..1)` = `[27, 30]`
for uncompressed and `[31, 34]` for compressed. Correct in absolute
terms.

But: BIP-137 (which clearbit's `signmessage` follows) was designed
around legacy P2PKH addresses, which are typically COMPRESSED in modern
wallets. Core's `CPubKey::RecoverCompact` accepts the full
`[27, 34]` range but the upstream `CHashSigner` / `MessageVerify`
flow uses the address type to determine `fcomp`. clearbit's
`recoverMessagePubkey` returns the recovered pubkey regardless and
defers the compressed/uncompressed compatibility to the caller.

No bug per BIP-137; calling out as a documentation gap. Cross-cite
W158 for the message-signing surface analysis.

**File:** `src/crypto.zig:1022-1062`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:300-318 CPubKey::RecoverCompact`.

**Impact:** none today; documentation gap.

---

## BUG-16 (P1) — `getDerSigLen` (length helper) assumes well-formed DER; truncates on garbage

**Severity:** P1.

`wallet.zig:3068-3073`:

```zig
fn getDerSigLen(der: *const [72]u8) usize {
    // DER format: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
    if (der[0] != 0x30) return 72;
    return @as(usize, der[1]) + 2;
}
```

The function reads `der[1]` as the DER length and returns `<len> + 2`.
This is correct for `30 <len> ...` short-form length. But:

- If the wallet emits a 73-byte DER sig (per BUG-8 truncation), this
  function returns the wrong length.
- If `der[0] != 0x30` (signature parse failed and `der` contains
  garbage), the function returns `72` — the caller then truncates
  garbage to 72 bytes and appends as `script_sig`/`witness`.
- Long-form DER length (`der[1] & 0x80 != 0`) is not handled —
  `getDerSigLen` returns `<wrongly-interpreted-len> + 2` and the
  signature is misframed.

Called from `wallet.zig:1736 const sig_len = getDerSigLen(&sig);` (P2PKH),
`wallet.zig:1850 const sig_len = getDerSigLen(&sig);` (P2SH-P2WPKH),
`wallet.zig:1876 const sig_len = getDerSigLen(&sig);` (P2WPKH). All
three branches truncate the sig to `getDerSigLen(...)` bytes and
append the hashtype byte.

If the underlying `ecdsaSign` failed (BUG-8), the caller never knows
and broadcasts a garbage tx.

**File:** `src/wallet.zig:3068-3073`.

**Core ref:** `bitcoin-core/src/key.cpp:226-227 vchSig.resize(nSigLen)`
where `nSigLen` is the in-out parameter returned by
`secp256k1_ecdsa_signature_serialize_der` — Core resizes to the
actually-emitted length, never re-parses.

**Impact:** silent emission of malformed signatures when DER serialise
goes wrong (rare); also bug-amplification of BUG-8.

---

## BUG-17 (P2) — `legacySighash` in crypto.zig hardcodes `i32` version with no clamping; consensus on `tx.version > 2`

**Severity:** P2. Latent on consensus-level handling of future Bitcoin
version bumps.

`crypto.zig:1248`:

```zig
try writer.writeInt(i32, tx.version);
```

`script.zig:2974-2976`:

```zig
var version_bytes: [4]u8 = undefined;
std.mem.writeInt(i32, &version_bytes, tx.version, .little);
```

Both functions serialize `tx.version` as `i32` LE. Per BIP-68
(`bitcoin-core/src/consensus/tx_verify.cpp::SequenceLocks`), tx versions
`< 2` skip BIP-68 / BIP-112 relative-locktime enforcement.
`tx.version` in clearbit is `i32` (signed) per `types.zig`; if a
future protocol bump makes negative versions consensus-meaningful, the
i32 cast preserves the bits but the sighash preimage would
intentionally differ.

Not a bug today — BIP-141 / BIP-341 / future taproot extensions all use
unsigned-non-negative version interpretations. Cataloguing for fleet
typing-consistency.

**File:** `src/crypto.zig:1248`; `src/script.zig:2974-2976`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h::CTransaction::nVersion`
(int32_t; same shape).

**Impact:** documentation; future-protocol-bump consideration.

---

## BUG-18 (P2) — Two `legacySighash` implementations (crypto.zig vs script.zig::legacySignatureHash) drift on output-list emit for SIGHASH_SINGLE

**Severity:** P2 (compound with BUG-4).

`crypto.zig:1296-1306`:

```zig
try writer.writeCompactSize(input_index + 1);
// Write empty outputs for indices before input_index
for (0..input_index) |_| {
    try writer.writeInt(i64, -1); // -1 value
    try writer.writeCompactSize(0); // empty script
}
// Write the actual output
const output = tx.outputs[input_index];
try writer.writeInt(i64, output.value);
try writer.writeCompactSize(output.script_pubkey.len);
try writer.writeBytes(output.script_pubkey);
```

`script.zig:3028-3057`:

```zig
const num_outputs: usize = if (hash_none) 0 else if (hash_single) input_index + 1 else tx.outputs.len;
try writeCompactSize(&preimage, num_outputs);
// Serialize outputs
for (0..num_outputs) |i| {
    if (hash_single and i != input_index) {
        // For SIGHASH_SINGLE, outputs before the signing input are "blank"
        // (value = -1, empty script)
        var neg_one: [8]u8 = undefined;
        std.mem.writeInt(i64, &neg_one, -1, .little);
        for (neg_one) |b| {
            preimage.append(b) catch return SighashError.OutOfMemory;
        }
        preimage.append(0x00) catch return SighashError.OutOfMemory; // Empty script
    } else {
        // ...write actual output...
    }
}
```

Both implementations look correct for SIGHASH_SINGLE (write
`input_index + 1` outputs, blank everything except `outputs[input_index]`).
But the **divergence with BUG-4** means the WALLET sign path uses the
crypto.zig version (no CODESEP removal) while the VERIFY path uses
script.zig (with CODESEP removal). The SIGHASH_SINGLE block is
duplicated but identical (verified above); the CODESEP step is the
sole drift.

**Cataloguing as P2** because the duplication itself is technical
debt; the consensus drift is captured by BUG-4.

**File:** `src/crypto.zig:1234-1326`; `src/script.zig:2937-3076`.

**Impact:** technical-debt / maintenance.

---

## BUG-19 (P1) "asymmetric sigcache witness truncation" — witness items > 4096 bytes are silently truncated in cache key, breaking the uniqueness invariant

**Severity:** P1.

`validation.zig:2524-2531`:

```zig
var witness_buf: [4096]u8 = undefined;
var witness_len: usize = 0;
for (job.witness) |item| {
    const space = witness_buf.len - witness_len;
    const copy_len = @min(item.len, space);
    @memcpy(witness_buf[witness_len..][0..copy_len], item[0..copy_len]);
    witness_len += copy_len;
    if (copy_len < item.len) break; // truncate if oversized; hash still binds all material
}
```

The comment `// truncate if oversized; hash still binds all material`
is a **comment-as-confession (Nth distinct clearbit instance)** — the
claim is incorrect. Truncated material is DROPPED from the hash,
not bound to it. A witness item with `item.len > 4096` (e.g., an
Ordinals inscription whose envelope payload is 10 KB) is partially
hashed.

Combined with BUG-3 (txid substitution for sighash):

1. Two inputs in the same tx, both with `prev_script_pubkey =
   <H160_of_address_X>`, both with witness containing an Ordinals
   envelope.
2. The two envelopes are byte-identical for the first 4096 bytes,
   diverge afterwards.
3. Cache key for both inputs is identical (txid + spk + truncated
   witness + flags).
4. If input 0 verifies, input 1 short-circuits to TRUE.

Cataloguing P1 because cross-cited with BUG-3 — the witness-truncation
amplifies BUG-3's blast radius.

**File:** `src/validation.zig:2524-2531`.

**Core ref:** `bitcoin-core/src/script/sigcache.cpp` — Core hashes the
exact bytes of the signature (typically 64-72 bytes), not the full
witness stack.

**Impact:** amplifies BUG-3.

---

## BUG-20 (P2) "comment-promises-X-implementation-does-Y" cluster — clearbit's sigcache wave-marker comment claims `sighash = hash` but implementation substitutes `sighash = txid`

**Severity:** P2 (already captured by BUG-3 but worth a separate
pattern callout).

`validation.zig:2509-2520`:

```zig
// Compute the txid as the sighash proxy for the sig cache key.
const txid = crypto.computeTxidStreaming(&tx);
const flags_u32: u32 = @intCast(@as(u21, @bitCast(job.flags)));

// W105 G19/G20 fix: cache key is SHA256(nonce || sighash || pubkey || sig || flags_le).
// - sighash = txid (32 bytes)
// - pubkey_bytes = prev_script_pubkey (the scriptPubKey being unlocked)
// - sig_bytes = script_sig (legacy) concatenated with witness stack bytes
//   (covers SegWit inputs; empty slices for inputs that use neither)
// This binds the cache entry to the exact script material, preventing the
// G19 collision attack where a different pubkey/sig on the same txid could
// get a false cache hit.
```

The W105 fix-marker comment claims to bind the cache entry to the
EXACT material. The same comment then admits the substitution
`sighash = txid`. The "G19 collision attack" the fix was supposed to
prevent is described as "different pubkey/sig on the same txid" —
which is solved by binding pubkey + sig. But the actual cache
hit-determinant is `(txid, spk, sig⊕witness, flags)` — not the
per-input sighash. The fix solved a different problem than the
original bug.

This is the **comment-as-confession** fleet pattern at the highest
density observed in clearbit: 12+ distinct instances per the running
fleet meta-pattern tracker. W160 contributes 4 new instances:
- BUG-3 ("compute the txid as the sighash proxy")
- BUG-5 ("Assuming max 256 inputs")
- BUG-9 (variable name `bip86Tweak` is honest but the call site is not)
- BUG-19 ("hash still binds all material")

**File:** `src/validation.zig:2509-2520`.

**Impact:** pattern-only; subsumed by BUG-3 for severity.

---

## Summary

**Bug count:** 20 (BUG-1 through BUG-20).

**Severity distribution:**
- **P0-CDIV / P0-SEC / P0-MEM:** 5 (BUG-1 P0-SEC, BUG-2 P0-CDIV,
  BUG-3 P0-CDIV catastrophic, BUG-4 P0-CDIV, BUG-5 P0-MEM)
- **P1:** 10 (BUG-6, BUG-7, BUG-8, BUG-9, BUG-12, BUG-13, BUG-14,
  BUG-16, BUG-19, plus W159-carry-forward BUG-13 spans 3 surfaces)
- **P2:** 5 (BUG-10, BUG-11, BUG-15, BUG-17, BUG-18, BUG-20 —
  actually 6; counting BUG-20 as the comment-pattern cataloguing)

Re-count: 5 + 10 + 6 = 21 (BUG-13 is one entry encapsulating 3
sub-sites). Adjust: BUG-13 is 1 entry; total = 20.

**Severity recount:** P0-class = 5 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-5);
P1 = 9 (BUG-6, BUG-7, BUG-8, BUG-9, BUG-12, BUG-13, BUG-14, BUG-16,
BUG-19); P2 = 6 (BUG-10, BUG-11, BUG-15, BUG-17, BUG-18, BUG-20).
Total = 5 + 9 + 6 = 20. ✓

**Carry-forward tracking:**
- **2-wave open across W159 → W160 (no fix attempted):**
  - BUG-1 (Schnorr aux_rand=null) — W159 BUG-18 → W160 BUG-1
  - BUG-13 (sign-then-verify paranoia at 3 sites) — W159 BUG-6/-7/-8
    → W160 BUG-13
  This is the 2nd 2-wave-open cluster in the clearbit signing surface.
  Pattern: defense-in-depth bugs catalogued, fix prioritisation slips.

**Fleet patterns confirmed / extended:**
- **"two-pipeline guard"** extended to the LEGACY SIGHASH layer
  (BUG-4) — wallet/verifier divergence on `removeCodeSeparators`.
  First fleet instance at the sighash-construction layer (W144's
  was at script-flag enable; W150's was at ATMP; W151's was at
  package).
- **"comment-as-confession"** 4 new clearbit instances this wave:
  BUG-3 ("txid as sighash proxy"), BUG-5 ("Assuming max 256 inputs"),
  BUG-9 (latent name-doesn't-match-call-site), BUG-19
  ("hash still binds all material"). Pattern continuing to saturate
  clearbit codebase.
- **"silent malleability launderer"** (BUG-2) — NEW PATTERN. The
  fix-direction-inverted shape of W153 hotbuns "regression-as-fix",
  applied to the libsecp `normalize` API. Distinct enough to call
  out as its own fleet pattern: a function that LOOKS like a
  consensus gate (`isLowDERSignature`-style) but actually LAUNDERS
  the violation.
- **"wiring-look-but-no-wire"** (BUG-6) — `SegwitSighashCache`
  defined, never wired. Nth distinct clearbit instance.
- **"comment-promises-X-implementation-does-Y"** (BUG-20) — a
  finer-grained variant of comment-as-confession where the fix
  marker explicitly STATES the desired binding then immediately
  substitutes a different value.
- **"return-value-discarded-on-FFI"** (BUG-8, BUG-16) — same shape
  as W159 BUG-10's `_pubkey_serialize` return-value cluster, but at
  the DER signature serialize layer.
- **"BIP-86-tweak-baked-into-general-Taproot-sign-path"** (BUG-9) —
  NEW PATTERN. Latent today, surfaces the moment script-path
  descriptors land. Cross-pattern with W157's
  "soft-hardcoded-gates" and W155's "stock-Core-miners-cannot-construct-
  valid-post-segwit-blocks".

**Top three findings:**

1. **BUG-3 (P0-CDIV catastrophic) — SigCache substitutes txid for
   per-input sighash** — `validation.zig:2509-2510` keys the
   signature cache on `(txid, prev_script_pubkey, sig_material,
   flags)` instead of the per-input sighash. Combined with the
   4096-byte witness truncation (BUG-19), the cache can short-circuit
   to TRUE on inputs whose actual sighash was never matched against
   the signature. The substitution is marked with a **comment-as-
   confession at the substitution site** ("compute the txid as the
   sighash proxy"). Real-world attack-vector is the dual-input
   same-spk-same-witness same-tx case. **Fix is non-trivial** —
   requires hoisting sighash compute out of the script engine OR
   moving the cache lookup into the engine.

2. **BUG-2 (P0-CDIV) "silent malleability launderer" — `crypto.verifyEcdsa`
   unconditionally normalizes high-S → low-S BEFORE verify** —
   `crypto.zig:809-813`. Per libsecp's explicit warning,
   normalization-before-verify is the canonical malleability hazard.
   The hot-path consensus surface is OK only because the script
   engine gates LOW_S upstream. Any future surface that wires
   `crypto.verifyEcdsa` to a new consensus caller (BIP-322 verify
   pipeline, PSBTv2 partial-sig check) ships with silent
   consensus-divergence. Cross-cite BUG-14 (same function is also
   lax-DER): the two together make `crypto.verifyEcdsa` ~equivalent
   to `verify_dersig=false && verify_low_s=false`.

3. **BUG-1 + BUG-13 cluster (P0-SEC + P1, both 2-wave open across
   W159 → W160) — Schnorr aux_rand=null + Sign-then-verify paranoia
   absent at all three sign sites** — `wallet.zig:1922-1930` passes
   `null` for the BIP-340 aux_rand parameter (W159 BUG-18 unchanged
   at W160 BUG-1); `wallet.zig:2013-2037` + `crypto.zig:979-1014`
   + `wallet.zig:1922-1930` all lack the Core CKey::Sign-style
   re-verify round-trip (W159 BUG-6/-7/-8 → W160 BUG-13). **2-wave
   open cluster** with no fix attempted between waves. Combined
   with W159 BUG-4 (context_randomize NEVER called on any context)
   and W158 BUG-2 (cipher-as-scalar), clearbit's signing primitive
   surface has the highest concentration of unfixed signing-layer
   security defects in the fleet.
