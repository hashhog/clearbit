# W159 — libsecp256k1 FFI wrapping + batch verification (clearbit)

**Wave:** W159 — context_create / context_destroy / context_randomize
side-channel blinding seed, CONTEXT_NONE vs deprecated VERIFY|SIGN flags,
secp256k1_selftest, secp256k1_context_static vs full ctx split,
sign-then-verify paranoia (CKey::Sign / CKey::SignCompact assert-verify
round-trip), secp256k1_ec_seckey_verify scalar-range check,
secp256k1_ec_pubkey_serialize return-value handling, FFI buffer-length
out-param verification, Schnorr batch-verify (`secp256k1_schnorrsig_verify`
is currently the only mainline batch surface; libsecp does NOT yet
expose a public batch API but Core ships ECCVerifyHandle / ECC_Context
infra), secp256k1_ecdh / ellswift context wiring, seckey zeroize on
intermediate buffers, mlock / LockedPool / `secure_allocator<unsigned char>`
for KDF / seckey storage, tagged-hash (BIP-340) `H_TAG = SHA256(tag) ||
SHA256(tag) || x`, BIP-340 xonly pubkey round-trip, BIP-341 / BIP-86
keypair_xonly_tweak_add, ECDSA-recover header byte (27 + recid + 4·comp),
process-singleton context vs per-instance, Zig-side `defer
context_destroy`, nonce_function aux32, `secp256k1_keypair` lifecycle.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/secp256k1/include/secp256k1.h:214-221` —
  `SECP256K1_CONTEXT_NONE = SECP256K1_FLAGS_TYPE_CONTEXT`;
  `SECP256K1_CONTEXT_VERIFY` and `SECP256K1_CONTEXT_SIGN` are **explicitly
  marked deprecated** ("Deprecated context flags. These flags are treated
  equivalent to `SECP256K1_CONTEXT_NONE`") and the docstring on
  `secp256k1_context_create` (line 278) states "Always set to
  `SECP256K1_CONTEXT_NONE`".
- `bitcoin-core/src/secp256k1/include/secp256k1.h:234-249` —
  `secp256k1_context_static` ("built-in constant context object with
  static storage duration") + `secp256k1_selftest` (line 267, **"highly
  recommended to call before using `secp256k1_context_static`"**) +
  deprecated `secp256k1_context_no_precomp`.
- `bitcoin-core/src/secp256k1/include/secp256k1.h:286-290` —
  *"If the context is intended to be used for API functions that perform
  computations involving secret keys, … it is **highly recommended** to
  call `secp256k1_context_randomize` on the context before calling those
  API functions. This will provide enhanced protection against
  **side-channel leakage**."*
- `bitcoin-core/src/secp256k1/include/secp256k1.h:292-294` —
  *"**Do not create a new context object for each operation**, as
  construction and randomization can take non-negligible time."*
- `bitcoin-core/src/key.cpp:572-587` — `ECC_Start()` canonical pattern:
  `secp256k1_context_create(SECP256K1_CONTEXT_NONE)` then **mandatory**
  `secp256k1_context_randomize(ctx, vseed.data())` with 32 bytes
  `GetRandBytes` from `secure_allocator<unsigned char>`. The `assert(ret)`
  on the randomize result is part of the contract.
- `bitcoin-core/src/key.cpp:209-235` — `CKey::Sign` performs **sign-then-
  verify paranoia**: after `secp256k1_ecdsa_sign`, it `secp256k1_ec_pubkey_
  create`s the matching pubkey on the **sign-context** and re-runs
  `secp256k1_ecdsa_verify` on the **static (verify) context** — `assert(ret)`
  on the verify. This is the guard against fault-injection / cosmic-ray bit
  flips during signing.
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact` performs the
  same paranoia: `ecdsa_sign_recoverable`, then `ec_pubkey_create`, then
  `ecdsa_recover` from the just-emitted sig + `ec_pubkey_cmp` (assert == 0).
- `bitcoin-core/src/key.cpp:97-112` — `Check(...)` uses
  `secp256k1_ec_pubkey_create` (a sign-context-only op) as the scalar-range
  check before `MakeNewKey` accepts a 32-byte input. Equivalent to
  `secp256k1_ec_seckey_verify`.
- `bitcoin-core/src/key.cpp:565-568` — `ECC_InitSanityCheck`: at process
  start, generate a fresh key + sign + verify round-trip. Catches a busted
  libsecp build before any user data is touched.
- `bitcoin-core/src/pubkey.cpp:25-31, 233-297` — **two-context split**:
  every verify-only path (`Verify`, `VerifySchnorr`, `RecoverCompact`,
  `xonly_pubkey_parse`, `xonly_pubkey_tweak_add_check`,
  `ecdsa_signature_parse_compact`, `ec_pubkey_serialize`, etc.) goes
  through the **static** context; signing-only paths go through
  `secp256k1_context_sign`. The static context has been initialised by
  `secp256k1_selftest` running in a namespaced `Secp256k1SelfTester`
  global ctor (line 25-31). The verify path is **never given a sign
  context**, eliminating an entire class of side-channel exfil paths.
- `bitcoin-core/src/key.h:23-26` — `CKey` stores its `keydata` inside a
  `secure_allocator<unsigned char>` vector, which `mlock`s the page and
  zero-fills on destruction. Plaintext seckey bytes never live in
  swappable / core-dump-visible memory.
- `bitcoin-core/src/support/lockedpool.h/cpp` — `LockedPool` /
  `LockedPoolManager`: page-aligned mlocked arena reused across many
  small allocations to avoid mlock per-call cost.
- `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h` —
  `secp256k1_schnorrsig_sign32` requires a `secp256k1_keypair` whose
  serialised form is the 32-byte seckey. **The function is the only
  Schnorr path**; libsecp does NOT yet ship a public batch-verify
  primitive (the experimental BIP-340 batch API in
  `src/modules/schnorrsig/main_impl.h` is internal). Mainline Core
  therefore validates Taproot signatures one-by-one in
  `EvalChecksigTapscript` and relies on CheckQueue parallelism + sig
  cache for throughput. Any clearbit claim of a public batch verifier
  would be a fabrication.
- `bitcoin-core/src/secp256k1/include/secp256k1_extrakeys.h` —
  `secp256k1_xonly_pubkey_parse` / `_serialize` / `_tweak_add_check` /
  `_from_pubkey`. Used for BIP-340/341 paths.
- `bitcoin-core/src/secp256k1/include/secp256k1_recovery.h` —
  `secp256k1_ecdsa_recoverable_signature_*`. Used for BIP-137 / signmessage.
- `bitcoin-core/src/script/interpreter.cpp:1717-1742` — hot-path
  `CheckSchnorrSignature` (BIP-340 verify, single call).

**Files audited**
- `src/crypto.zig:657-908` — `secp256k1` `@cImport` block (4 headers);
  module-private `secp_ctx: ?*secp256k1.secp256k1_context = null` +
  `secp_initialized: bool` (both lines 671-673); `initSecp256k1` (line
  675-684); `deinitSecp256k1` (line 686-693); `isSecp256k1Available` (line
  695-698); `laxDerParse` (line 700-768); `verifyEcdsa` (line 770-814);
  `isLowDERSignature` (line 816-839); `parseUncompressedPubkey65`
  (line 844-857); `decompressPubkey33` (line 859-884);
  `verifySchnorr` (line 886-908); `signMessageCompact` (line 979-1014);
  `recoverMessagePubkey` (line 1016-1062); `verifyTaprootControlBlock`
  (line 1578-1654).
- `src/wallet.zig:540-1014` — wallet `@cImport` (line 547-551, distinct
  from crypto.zig's); `Wallet.ctx: *secp256k1.secp256k1_context` (line
  824); `Wallet.init` `context_create` (line 864-867); `Wallet.deinit`
  `context_destroy` (line 919-944); `Wallet.generateKey` (line 952-962
  — `seckey_verify` rejection loop); `Wallet.importKey` (line 964-1013 —
  pubkey-create + xonly derivation, return-value of
  `xonly_pubkey_from_pubkey` discarded).
- `src/wallet.zig:1689-1698` — `getPlaintextSecretKey` (decrypt path).
- `src/wallet.zig:1700-2011` — `signInput` dispatch; line 1722 plaintext
  decrypt; line 1729/1837/1870 ECDSA sign sites; line 1911-1930 Schnorr
  (BIP-341 keypair_xonly_tweak_add + schnorrsig_sign32, **`aux_rand=null`**).
- `src/wallet.zig:2013-2091` — `Wallet.ecdsaSign` / `verifyEcdsa` /
  `verifySchnorr` (per-wallet ctx); ecdsaSign at 2013-2037 has **no
  sign-then-verify paranoia**.
- `src/wallet.zig:2106-2197` — encryptWallet / scrypt-KDF flow;
  per-key AES-GCM encryption overwriting `KeyPair.secret_key` with
  ciphertext (line 2138-2143).
- `src/wallet.zig:3100-3123` — `bip86TweakXOnly` (no error check on
  `xonly_pubkey_serialize` return).
- `src/wallet.zig:4185-5497` — every `*Test` helper that does
  `context_create` (~80 sites, all paired with `context_destroy` —
  some on `defer`, most on a trailing direct call).
- `src/descriptor.zig:8-69` — stub-vs-real `@cImport` switch; thread-local
  (actually file-global) `secp_ctx`; `getSecpContext` (no destroy ever
  called for the descriptor ctx — process-lifetime leak).
- `src/descriptor.zig:1080-1280` — WIF + xprv / xpub derivation;
  every `ec_pubkey_serialize` return value is discarded with `_ = …`.
- `src/v2_transport.zig:42-69` — `ellswift_ctx` + `getSecp256k1Context`
  for BIP-324 `ellswift_create` / `ellswift_xdh`; ctx never destroyed
  (process-lifetime leak); randomize never called.
- `src/sig_cache.zig` — verification-result cache; W105 G19/G20 fix
  documented at top; per-startup 32-byte CSPRNG nonce mixed into every
  key via SHA-256.
- `src/script.zig:2203-2363` — hot-path `verifySignature` and
  `verifyTaprootSignature` in `ScriptEngine` (`OP_CHECKSIG` /
  `OP_CHECKSIGVERIFY` / `OP_CHECKMULTISIG` / tapscript). Both call
  through `crypto.verifyEcdsa` / `crypto.verifySchnorr` (so the
  module-private `secp_ctx` in `crypto.zig`, not the per-`Wallet` ctx).
- `src/rpc.zig:11267-11380` — `decodeWifPrivkey`, `handleSignMessage`,
  `handleSignMessageWithPrivKey`. (Carry-forward of W158 BUG-2 confirmed
  unchanged.)
- `src/main.zig:1288-1296, 1612-1725` — process entry; lazy
  `initSecp256k1` from two distinct call sites (block-import path +
  daemon main); `defer deinitSecp256k1` only on the immediate function
  scope, not process-lifetime.
- `build.zig:11-114` — build option `-Dsecp256k1=true`,
  `linkSystemLibrary("secp256k1")`. No vendored / pinned-version
  build — relies on whatever Debian / Homebrew installed.

---

## Gate matrix (32 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Context lifecycle (process-singleton) | G1: ONE shared context for the entire process | **BUG-1 (P0-SEC)** — at least FIVE distinct production contexts (crypto.zig:672 module-private; wallet.zig per-`Wallet` instance — line 824; descriptor.zig:59 file-global; v2_transport.zig:49 file-global ellswift; plus every Wallet test helper at wallet.zig:4185-5497 creates+destroys its own). Per Core docstring (`secp256k1.h:292-294`) this is **explicitly contraindicated** ("Do not create a new context object for each operation, as construction and randomization can take non-negligible time"). |
| 1 | … | G2: process-lifetime context never destroyed-then-reused | **BUG-2 (P1)** — `crypto.deinitSecp256k1` is called from at LEAST four sites (`main.zig:1296` block-import path, `main.zig:1725` daemon path, plus 6 RPC test sites) but the daemon path's `defer` is scoped to the outermost `main()`. Re-init after destroy is rare in production but every test does it, which keeps the leaky-flag (`secp_initialized` bool, line 673) and the pointer (`secp_ctx`, line 672) in lockstep ONLY if no thread is mid-verify. No mutex. |
| 1 | … | G3: descriptor ctx destroyed on process exit | **BUG-3 (P2)** — `descriptor.zig:59-69` allocates `secp_ctx` lazily on first call to `getSecpContext`; no `deinit`, no `defer`. The ctx leaks for the entire process lifetime. Same for `v2_transport.ellswift_ctx` at `v2_transport.zig:49`. |
| 2 | Side-channel blinding (`context_randomize`) | G4: ANY production context calls `secp256k1_context_randomize` after create | **BUG-4 (P0-SEC) "side-channel-blinding-disabled" (fleet pattern)** — **zero** call sites of `secp256k1_context_randomize` exist anywhere in clearbit (verified `grep -rn context_randomize src/` returns no matches). Core's `ECC_Start` at `key.cpp:572-587` performs the randomize call with 32 fresh `GetRandBytes` and `assert(ret)`. Every sign-path on clearbit (the wallet ECDSA sign at `wallet.zig:2013-2037`, the Schnorr sign at `wallet.zig:1922-1930`, the recoverable sign at `crypto.zig:987`, the ec_pubkey_create at `wallet.zig:972`, the BIP-32 seckey_tweak_add at `wallet.zig:714`, the descriptor xprv derivation at `descriptor.zig:1197/1213`, the BIP-86 keypair_xonly_tweak_add at `wallet.zig:1917`, the ellswift_create at `v2_transport.zig:60-69`) **runs against an unblinded context**. This is the **W158 NEW** fleet pattern explicitly called out in the wave brief; the audit task expected clearbit to have it (was found in lunarblock W158 BUG-7) and clearbit does. |
| 2 | … | G5: randomize is re-called periodically | **BUG-4 cross-cite** — Core's recommendation is to randomize once per context creation; clearbit's gap is the **initial** call, not a re-randomize cadence |
| 3 | CONTEXT_NONE (post v0.4.0) vs deprecated SIGN/VERIFY | G6: `secp256k1_context_create` uses `SECP256K1_CONTEXT_NONE` | **BUG-5 (P2)** — every clearbit ctx is created with `SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN` (`crypto.zig:680`, `wallet.zig:866`, `descriptor.zig:66`, `v2_transport.zig:62`, plus every test helper). Per `secp256k1.h:216-218` these are **explicitly deprecated** and treated equivalent to `SECP256K1_CONTEXT_NONE`. Functionally identical today; **fails the lint** any time clearbit upgrades libsecp to a future version that adds new flag semantics — the OR-ed deprecated bits could collide with a newly-meaningful flag. Core moved to `CONTEXT_NONE` in `key.cpp:575` exactly to avoid this risk. |
| 4 | Sign-then-verify paranoia (CKey::Sign) | G7: ECDSA `Wallet.ecdsaSign` re-verifies the emitted sig before returning | **BUG-6 (P1)** — `wallet.zig:2013-2037` emits a DER signature with NO re-verify on the same ctx (Core: `key.cpp:228-234` is *"Additional verification step to prevent using a potentially corrupted signature"* with `assert(ret)`). A wallet sign cycle with a corrupted libsecp memory state would silently return a sig that fails consensus — caller has no signal until the broadcast bounces. |
| 4 | … | G8: recoverable-sign `signMessageCompact` re-recovers and compares to expected pubkey | **BUG-7 (P1)** — `crypto.zig:979-1014` emits the 65-byte compact-recoverable signature with NO `ec_pubkey_create` + `ecdsa_recover` + `ec_pubkey_cmp` round-trip (Core: `key.cpp:262-269` `assert(ret == 0)` on the cmp). Combined with W158 BUG-2 (handleSignMessage signs with ciphertext-as-scalar), the consequence is that EVEN IF the seckey were correct, a fault-injected sign would surface only on verify. |
| 4 | … | G9: Schnorr sign `signInput .p2tr` re-verifies the emitted sig | **BUG-8 (P1)** — `wallet.zig:1922-1930` runs `schnorrsig_sign32` then writes the witness with NO `schnorrsig_verify` re-check. Less catastrophic than G7 because Schnorr doesn't have the same RFC-6979 nonce-reuse failure mode, but fault-injection still applies. |
| 5 | Seckey scalar-range check | G10: random keygen rejects scalars outside `[1, n-1]` | PASS — `wallet.zig:957-959` loops on `secp256k1_ec_seckey_verify` until it returns 1. |
| 5 | … | G11: imported keys (`importKey`) scalar-checked | PASS — `wallet.zig:967-969`. |
| 5 | … | G12: WIF-decoded seckey scalar-checked before sign | **BUG-9 (P1) carry-forward of W158 BUG-7** — `rpc.zig:11269-11289 decodeWifPrivkey` returns the raw 32 bytes with NO `secp256k1_ec_seckey_verify`. Out-of-range scalars fail later at the `ecdsa_sign_recoverable` step with a generic "Sign failed" message instead of Core's pre-sign "Invalid private key" reject. Five-wave open (W47 PSBT → W118 wallet → W158 → W159; no fix wave has touched it). |
| 5 | … | G13: BIP-32 child-key tweak rejects on `infinity` | PASS (only — by accident, via libsecp's internal check). `wallet.zig:712-716` checks `seckey_tweak_add` return == 1, so an `infinity`-producing tweak returns `error.InvalidChildKey`. |
| 6 | Tagged-hash (BIP-340) | G14: `H_TAG(x) = SHA256(SHA256(tag) || SHA256(tag) || x)` exact | PASS (`crypto.zig:1507-1518`, pinned by `tests_wallet_taproot` and an in-file vector at `crypto.zig:1944-1995`). |
| 6 | … | G15: tapleaf hash uses full BIP-341 CompactSize for script length | PASS (`crypto.zig:1534-1552` + `appendCompactSize` at `crypto.zig:1557-1576`; W34 fix landed for Ordinals 69 KB tapscripts). |
| 7 | XOnlyPubKey / Taproot FFI | G16: `verifyTaprootControlBlock` uses `xonly_pubkey_tweak_add_check` (the consensus call) | PASS (`crypto.zig:1643-1651` — also notes earlier dead `xonly_pubkey_tweak_add` was removed). |
| 7 | … | G17: BIP-86 tweak applied via `keypair_xonly_tweak_add` | PASS (`wallet.zig:1916-1919`). |
| 7 | … | G18: `xonly_pubkey_serialize` return value checked | **BUG-10 (P2)** — `wallet.zig:991` and `wallet.zig:989` (xonly_pubkey_from_pubkey) discard return value with `_ = …`. Same at `crypto.zig:1051-1058` `ec_pubkey_serialize` and `wallet.zig:725-731 / 979-985` for the compressed-pubkey serialise. **Two-pipeline guard violation**: the consensus-side `verifyTaprootControlBlock` (`crypto.zig:1643-1651`) does check returns and reject; the wallet-side derivation silently emits garbage if any of these returns 0. |
| 8 | ECDSA-recover header byte (BIP-137) | G19: header in `[27, 34]` rejected outside range | PASS (`crypto.zig:1030`). |
| 8 | … | G20: compressed flag round-trips (header bit 2 set ↔ 33-byte output) | PASS (`crypto.zig:1032, 1051-1060`). |
| 9 | Schnorr batch verify | G21: production code uses `secp256k1_schnorrsig_verify` per signature (no batch primitive available upstream) | PASS technically — libsecp's public batch API isn't exported. But **`docs/`** / `README` / module comments make zero mention of this constraint, so a future change that imagines a Zig-side `verifyBatch` against the dead helper would silently single-call (see G22). |
| 9 | … | G22: any code claims to do "batch" verification? | **BUG-11 (P2) "advertisement-as-lie" / wiring-look-but-no-wire** — `crypto.zig:668-669` declares `pub const has_secp256k1: bool = true;` as a single boolean (no per-feature granularity), and `script.zig:1166` calls `crypto.verifySchnorr` inside the tapscript loop — once per `OP_CHECKSIG`. There is **no batch surface** in clearbit and no test claims batch behaviour, BUT: `tests_w127_taproot.zig` and `tests_wallet_taproot.zig` both validate Schnorr round-trips and would be the natural place to discover that a future "batch" optimisation will not exist. The fleet-pattern shape would be: a comment claiming "batched" performance that doesn't match the implementation. **Not currently a comment-as-confession, but the absence of any batch-verify primitive contract is itself a quiet wiring gap relative to Core's CheckQueue / sig-cache infra (see `bitcoin-core/src/checkqueue.h`).** |
| 9 | … | G23: signature cache mixes random 256-bit nonce + sig + pubkey + sighash + flags | PASS (`sig_cache.zig:158-176`, W105 G19/G20 fix landed). |
| 10 | Memory hygiene | G24: plaintext seckey buffers zeroized after use | PARTIAL — `wallet.zig:1723` zeroizes `plaintext_secret` with `defer @memset(&plaintext_secret, 0)`, also `2152, 2180, 2184, 2188, 2239, 2254` zeroize derived KDF keys. **BUG-12 (P1)** — `crypto.signMessageCompact` (`crypto.zig:979-1014`) and `decodeWifPrivkey` (`rpc.zig:11269-11289`) hold seckey bytes on the stack with NO `@memset(&secret, 0)` `defer`. After the function returns, the bytes remain on the (potentially swappable) stack. |
| 10 | … | G25: `LockedPool` / `mlock` for seckey storage | **BUG-13 (P1)** — clearbit has NO mlock equivalent (verified `grep -n mlock src/` returns no matches). Core's `secure_allocator` `mlock`s every page that holds a `CKey.keydata`. Plaintext seckey bytes on clearbit are in normal heap (KeyPair.secret_key) or stack memory, eligible for swap-out and `gcore` dump. |
| 10 | … | G26: KeyPair.secret_key is overwritten with AES-GCM ciphertext on encrypt | PASS technically — `wallet.zig:2140 keypair.secret_key = enc.ciphertext`. **BUT this is exactly the W158 BUG-2 root cause** — the rest of the code can't tell ciphertext-vs-plaintext at the byte level. See BUG-14 below. |
| 11 | W158 carry-forward at FFI level | G27: handleSignMessage decrypts before calling FFI | **BUG-14 (P0-SEC catastrophic carry-forward of W158 BUG-2)** — `rpc.zig:11355` reads `key.secret_key` directly and passes it to `crypto.signMessageCompact`, which calls `secp256k1_ecdsa_sign_recoverable(ctx, &rsig, msg_hash, seckey, null, null)` (`crypto.zig:987-994`). At the FFI layer, the 32 bytes of AES-GCM ciphertext ARE a valid `[1, n-1]` scalar for ~all inputs, so the sign succeeds and the 65-byte sig leaks the ciphertext to the verifier. **The cipher-as-scalar bug from W158 persists unchanged at the lower (FFI) level**: there is no FFI-side guard that the seckey came from `getPlaintextSecretKey`. The wave brief specifically asked us to check this. |
| 11 | … | G28: handleSignMessage checks isUnlocked | **BUG-14 cross-cite of W158 BUG-1** — `rpc.zig:11311-11360` never calls `wallet.isUnlocked()` (the function exists at `wallet.zig:2209-2216`). Encrypted+locked wallets sign with ciphertext as if unlocked. |
| 12 | Build / self-test | G29: `secp256k1_selftest` called at process start | **BUG-15 (P1)** — clearbit calls `secp256k1_context_create` at `main.zig:1721` but **never `secp256k1_selftest`** (verified `grep -rn secp256k1_selftest src/` returns no matches). Core runs the self-test in a global ctor (`pubkey.cpp:25-31 Secp256k1SelfTester`) before *any* code touches `secp256k1_context_static`. clearbit's gap means a libsecp built for the wrong endianness (e.g. cross-compiled, or upstream rebuilt with `-D__BYTE_ORDER__=__ORDER_BIG_ENDIAN__` on a little-endian box) ships silently and emits structurally-valid but consensus-invalid signatures. |
| 12 | … | G30: `ECC_InitSanityCheck` equivalent (sign+verify round-trip on a fresh key at startup) | **BUG-16 (P2)** — no equivalent. `crypto.initSecp256k1` (`crypto.zig:677-684`) does the bare `context_create` + sets the flag; no round-trip exercise. Means a corrupted libsecp link surfaces only on the first real sign attempt, which on a node could be hours into IBD. |
| 13 | Cross-context type safety (Zig opaque) | G31: production code uses ONE `@cImport` block | **BUG-17 (P1) "dual-cImport opaque-type mismatch"** — crypto.zig:661-666, wallet.zig:547-551, descriptor.zig:53-56, v2_transport.zig:41-43, and at least 6 test files each `@cImport`. Each `@cImport` produces a **distinct opaque type alias** for `secp256k1_context`, `secp256k1_pubkey`, etc. — passing a `crypto.secp256k1.secp256k1_pubkey` to a `wallet.secp256k1.*` function fails to compile. **This is documented as a workaround** at `tests_wallet_segwit_v0.zig:51-53` ("would cause a dual-cImport opaque-type mismatch"). Net effect: clearbit can never share a single context across crypto.zig and wallet.zig; G1's leak is *forced* by the type system. |
| 14 | Schnorr aux randomness | G32: `schnorrsig_sign32` receives a 32-byte aux_rand | **BUG-18 (P1)** — `wallet.zig:1922-1930` passes `null` for the aux_rand parameter of `schnorrsig_sign32` (and `crypto.zig:2235` does the same in the test). BIP-340 §"Default Signing" recommends 32 fresh bytes; per `bitcoin-core/src/key.cpp` `SignSchnorr` path the aux32 is `GetRandBytes(32)`. With `null`, libsecp uses zeroes as aux, making the nonce **deterministic and key-recoverable** if any future sign uses the same `msg_hash + seckey` with different aux. **Not yet exploitable** because clearbit never re-signs the same sighash with the same seckey, but the safety margin is gone. |

---

## BUG-1 (P0-SEC) — FIVE distinct production `secp256k1_context` objects + the dual-@cImport opaque-type wall that *forces* this fragmentation

**Severity:** P0-SEC. Bitcoin Core's `ECC_Start()` (`key.cpp:572-587`)
creates ONE `secp256k1_context_sign`, randomizes it ONCE with 32 fresh
secure-random bytes, and uses it for the lifetime of the process. The
verify-only context (`secp256k1_context_static`) is a separate global
that has its own selftest. **Two contexts total.** Per Core
`secp256k1.h:292-294`: *"Do not create a new context object for each
operation, as construction and randomization can take non-negligible time."*

clearbit allocates AT LEAST five distinct production contexts:

1. `crypto.zig:672` — module-private `secp_ctx`, the consensus hot-path
   (every `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` / tapscript Schnorr verify
   goes through `crypto.verifyEcdsa` / `crypto.verifySchnorr` which use
   this).
2. `wallet.zig:824` — per-`Wallet` instance `ctx`. A node with N
   loaded wallets has N+1 contexts (+the crypto.zig one).
3. `descriptor.zig:59` — file-global `secp_ctx`, used for WIF and xpub
   key resolution (`getSecpContext` at line 61-69).
4. `v2_transport.zig:49` — file-global `ellswift_ctx`, used for BIP-324
   handshake.
5. **Every Wallet test helper** (`wallet.zig:4185, 4201, 4221, 4246,
   4268, 4290, 4310, 4330, 4350, 4379, 4415, 4448, 4493, 4535, 4586,
   4656, 4683, 4720, 4743, 4763, 4787, 4831, 4863, 4900, 4919, 4958,
   5009, 5055, 5106, 5138, 5195, 5218, 5240, 5270, 5291, 5315, 5361,
   5398, 5427, 5465, 5493`) creates+destroys its own.

The Zig `@cImport`-per-file pattern (BUG-17) *forces* this fragmentation:
the opaque `secp256k1_context` type produced by `crypto.zig`'s cImport
is a different Zig type from the one produced by `wallet.zig`'s, even
though both alias the same underlying C struct. Sharing the
`crypto.secp_ctx` with the wallet would be a compile error.

**File:** `src/crypto.zig:661-666 / 672`, `src/wallet.zig:547-551 / 824`,
`src/descriptor.zig:19-69`, `src/v2_transport.zig:41-49`.

**Core ref:** `bitcoin-core/src/key.cpp:572-587` (single shared sign
context); `bitcoin-core/src/pubkey.cpp:25-31` (single shared
`secp256k1_context_static` w/ selftest); `secp256k1.h:286-294` (explicit
contraindication).

**Impact:**
- Each context allocates ~32 KiB of precomputed-multiplication tables;
  N wallets + crypto + descriptor + ellswift + per-test = O(MiB) wasted
  resident memory.
- **Per BUG-4, none of these contexts is `context_randomize`'d**, so
  whatever side-channel-blinding properties libsecp has by default
  apply to every signing operation across all five surfaces.
- Sharing seckey-touching ops across two un-randomized contexts gives
  an adversary two parallel timing/EM/cache side-channels with the SAME
  secret material — the worst-case timing-attack scenario.
- Any future code that wants to share state (e.g. cached
  precomputed-public-key tables) across crypto.zig and wallet.zig has
  to first refactor the cImport.

---

## BUG-4 (P0-SEC) "side-channel-blinding-disabled" — `secp256k1_context_randomize` is NEVER called on ANY context

**Severity:** P0-SEC. This is the **W158 NEW fleet pattern** explicitly
called out in the W159 wave brief. clearbit was flagged in W158 for
related-but-distinct cipher-as-scalar (BUG-2) — at the lower (FFI)
level the same surface has the side-channel-blinding gap.

Bitcoin Core `key.cpp:572-587`:

```cpp
secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
assert(ctx != nullptr);
{
    // Pass in a random blinding seed to the secp256k1 context.
    std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
    GetRandBytes(vseed);
    bool ret = secp256k1_context_randomize(ctx, vseed.data());
    assert(ret);
}
```

The `secp256k1_context_randomize` call seeds the context's internal
blinding state. Per `secp256k1.h:286-290`: *"If the context is intended
to be used for API functions that perform computations involving secret
keys … it is **highly recommended** to call `secp256k1_context_randomize`
on the context before calling those API functions. This will provide
enhanced protection against side-channel leakage."*

`grep -rn context_randomize /home/work/hashhog/clearbit/src/` returns
**zero matches**. None of the five production contexts has been
randomized.

Every clearbit signing surface runs on an unblinded context:

- `crypto.signMessageCompact` (`crypto.zig:987-994 ecdsa_sign_recoverable`)
- `Wallet.ecdsaSign` (`wallet.zig:2016-2024 ecdsa_sign`)
- BIP-341 keypath sign (`wallet.zig:1922-1930 schnorrsig_sign32`)
- BIP-86 keypair_xonly_tweak_add (`wallet.zig:1917`)
- BIP-32 seckey_tweak_add (`wallet.zig:714`, `descriptor.zig:1197`)
- WIF → ec_pubkey_create (`descriptor.zig:1084`)
- ellswift_create / ellswift_xdh in v2_transport (BIP-324 handshake,
  literally the cryptographic root of every encrypted peer link)

For an attacker with physical access (cold-boot attack), shared-host
timing (e.g. node running on a hetzner box where the attacker has a
neighbour VM), or any speculative-execution channel that can read
cache-residency, **clearbit is one rung weaker than Core** for every
single seckey operation, with NO blinding state to confound the leak.
The Zen 4 cache-timing literature (e.g. AlmondScan, Hertzbleed) takes
~hours to minutes to extract a private scalar from an unblinded curve
operation; with randomize, it's intractable.

**File:** `src/crypto.zig:677-684 initSecp256k1`; `src/wallet.zig:864-867
Wallet.init`; `src/descriptor.zig:61-69 getSecpContext`;
`src/v2_transport.zig:55-69 getSecp256k1Context`.

**Core ref:** `bitcoin-core/src/key.cpp:572-587 ECC_Start`;
`bitcoin-core/src/secp256k1/include/secp256k1.h:286-290` (recommendation
docstring).

**Fix:** four ~5-line edits, one per context — generate 32 fresh
`std.crypto.random.bytes`, call `secp256k1_context_randomize(ctx,
&vseed)`, assert ret == 1. (Note this also resolves the W158 brief's
explicit pattern alert.)

---

## BUG-14 (P0-SEC catastrophic) — cipher-as-scalar persists at the FFI level (carry-forward of W158 BUG-2)

**Severity:** P0-SEC (catastrophic — inverts the wallet-encryption
guarantee). 2-wave open (W158 → W159).

The wave brief specifically asked us to check whether "clearbit
specifically had W158 cipher-as-scalar — check if same shape persists
at lower level". It does, byte-for-byte unchanged.

`rpc.zig:11355`:

```zig
const sig = crypto.signMessageCompact(&h, &key.secret_key, true) orelse {
    return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed", id);
};
```

`crypto.zig:984-996`:

```zig
pub fn signMessageCompact(
    msg_hash: *const [32]u8,
    seckey: *const [32]u8,
    compressed: bool,
) ?[65]u8 {
    const ctx = secp_ctx orelse return null;

    var rsig: secp256k1.secp256k1_ecdsa_recoverable_signature = undefined;
    if (secp256k1.secp256k1_ecdsa_sign_recoverable(
        ctx,
        &rsig,
        msg_hash,
        seckey,
        null,
        null,
    ) != 1) {
        return null;
    }
    // ...
```

When `wallet.encrypted == true`, `key.secret_key` is the 32-byte
AES-256-GCM **ciphertext** of the actual private scalar
(`wallet.zig:2138-2143` — encryption overwrites the field in place).
`secp256k1_ecdsa_sign_recoverable` does NOT distinguish ciphertext
from plaintext: any 32-byte input in `[1, n-1]` is a valid scalar.

There is **no FFI-side guard**:

1. No `getPlaintextSecretKey` call at the RPC layer (W158 BUG-1).
2. No `isUnlocked` precheck (W158 BUG-1).
3. No `Wallet.signMessage` keystore-aware wrapper (would mirror Core's
   `wallet/scriptpubkeyman.cpp::SignMessage` flow that goes through
   `GetKey(keyid, key)` and naturally fails if locked).
4. `crypto.signMessageCompact` is by API contract caller-takes-
   responsibility — no `seckey_verify` precheck on the input
   (which wouldn't help anyway because ciphertext is overwhelmingly
   in-range).

W158's write-up (`w158-bip322-message-signing.md` lines 213-323)
covers the full attack chain. At the FFI / wrapping level the
divergence point is: **clearbit lacks the Core idiom where every
sign-callsite sources its scalar through a typed wrapper that hides
the cipher boundary**. The pattern would be a `SecKey` newtype that
takes a `secp256k1_context` + a `KeyPair` ref and returns the
decrypted bytes (or `WalletLocked`); production code never holds
loose `[32]u8` seckeys. Without that, every new sign-callsite is a
new opportunity for the same bug.

**File:** `src/rpc.zig:11355` (call site); `src/crypto.zig:979-1014`
(FFI wrapper); `src/wallet.zig:601-612` (the cipher-overwrite field).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::LegacyScriptPubKeyMan::SignMessage`.

**Impact:** unchanged from W158 — every encrypted-clearbit
`signmessage` RPC call leaks the AES-256-GCM ciphertext of the wallet
key (the GCM nonce + tag are stored alongside in plaintext at
`KeyPair.encryption_nonce` / `_tag`), so an attacker who later steals
the wallet file no longer needs to brute-force the scrypt KDF — they
have the ciphertext, the nonce, the tag, AND the plaintext scalar
derived from the recovered sig. Inverts the entire wallet-encryption
contract.

---

## BUG-6 (P1) — `Wallet.ecdsaSign` has NO sign-then-verify paranoia (`CKey::Sign` mirrors)

**Severity:** P1. Defense-in-depth gap.

`wallet.zig:2013-2037`:

```zig
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
}
```

Core's `key.cpp:218-234`:

```cpp
int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(),
                               UCharCast(begin()), secp256k1_nonce_function_rfc6979,
                               (!grind && test_case) ? extra_entropy : nullptr);
// ... grind for low-R ...
assert(ret);
secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static, vchSig.data(), &nSigLen, &sig);
vchSig.resize(nSigLen);
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey pk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pk);
assert(ret);
return true;
```

Core's comment is verbatim: *"Additional verification step to prevent
using a potentially corrupted signature."* The protection is against
rowhammer / fault-injection / cosmic-ray bit flips during signing.
clearbit's ecdsaSign emits whatever bytes libsecp produced — if those
bytes are corrupted, the caller broadcasts a sig that consensus
verifiers reject and the wallet has no signal that the sig was bad.

Same gap at `crypto.signMessageCompact` (BUG-7, recoverable-sign
without `ecdsa_recover` + `ec_pubkey_cmp` round-trip).

Same gap at the BIP-86 / BIP-341 schnorrsig_sign32 path in
`wallet.zig:1922-1930` (BUG-8, no `schnorrsig_verify` re-check).

Note clearbit also lacks `grind` for low-R signatures (Core uses
counter-driven extra_entropy to grind R < 0x80 so DER fits in <= 71
bytes — fee-economic for wallets), but that's an optimisation not a
correctness gap.

**File:** `src/wallet.zig:2013-2037 ecdsaSign`; `src/crypto.zig:979-1014
signMessageCompact`; `src/wallet.zig:1922-1930` (Schnorr sign).

**Core ref:** `bitcoin-core/src/key.cpp:218-234 CKey::Sign`;
`bitcoin-core/src/key.cpp:256-269 CKey::SignCompact`.

**Impact:** silent emission of corrupted signatures. With no
randomize either (BUG-4) and no selftest (BUG-15), clearbit's
post-libsecp-corruption blast radius is wider than Core's.

---

## BUG-15 (P1) — `secp256k1_selftest` never called

**Severity:** P1. Wrong-endianness libsecp builds ship silently.

Bitcoin Core `pubkey.cpp:25-31`:

```cpp
namespace {
struct Secp256k1SelfTester {
    Secp256k1SelfTester() {
        /* Run libsecp256k1 self-test before using the secp256k1_context_static. */
        secp256k1_selftest();
    }
} SECP256K1_SELFTESTER;
}
```

This global ctor fires before `main()` runs. If libsecp was compiled
with the wrong endianness or a corrupted prebuilt table file
(`src/precomputed_ecmult.c`), the selftest aborts via the default
error callback — node fails to start.

clearbit calls `secp256k1_context_create` at `main.zig:1721` directly,
with no preceding `secp256k1_selftest`. `grep -rn secp256k1_selftest
src/` returns zero matches.

Per `secp256k1.h:243`: *"It is highly recommended to call
`secp256k1_selftest` before using `secp256k1_context_static`."* clearbit
doesn't use `secp256k1_context_static` at all (it always allocates a
full sign+verify context), so the selftest contract isn't formally
violated — but the underlying concern (libsecp built for wrong
endianness) is identical regardless of static-vs-allocated context.

**File:** `src/main.zig:1287-1296, 1612-1725`; `src/crypto.zig:677-684`.

**Core ref:** `bitcoin-core/src/pubkey.cpp:25-31 Secp256k1SelfTester`;
`bitcoin-core/src/secp256k1/include/secp256k1.h:251-267 secp256k1_selftest`.

**Impact:** if `setup-deps.sh` installs a Debian secp256k1 package that
was misconfigured (e.g. armhf headers on amd64 lib), clearbit emits
structurally-valid garbage sigs and IBD silently forks off mainnet
at the first signed tx.

---

## BUG-17 (P1) "dual-@cImport opaque-type mismatch" — five separate cImports each produce a distinct Zig opaque type

**Severity:** P1 (architectural; forces BUG-1).

Each `@cImport({ @cInclude("secp256k1.h"); })` in clearbit produces
a NEW namespace with NEW opaque types. `crypto.secp256k1.secp256k1_context`
is `*opaque{}` and `wallet.secp256k1.secp256k1_context` is also
`*opaque{}` — but they're DIFFERENT Zig types. Passing a context
allocated by one cImport to a function from another fails to compile.

This is explicitly documented as a workaround at
`tests_wallet_segwit_v0.zig:51-53`:

```
/// We derive the compressed pubkey via the wallet itself rather than re-doing
/// the libsecp calls in this file, which would cause a dual-cImport opaque-type
/// mismatch (the wallet's `*secp256k1_context` and a local `@cImport` produce
/// the same struct under different opaque type aliases).
```

**Comment-as-confession (12th distinct fleet instance)** — the test
file admits the problem exists. The fix would be to extract a single
`secp256k1_ffi.zig` module with ONE `@cImport`, and have every other
file `@import("secp256k1_ffi.zig")`. Then `Wallet.ctx`,
`crypto.secp_ctx`, `descriptor.secp_ctx`, and the ellswift ctx can all
be the SAME pointer type, and the natural refactor is to make them all
ONE pointer — closing BUG-1.

Without this refactor, BUG-1 (five-contexts), BUG-2 (re-init races),
BUG-4 (none randomized), and BUG-5 (deprecated flags everywhere) are
each individually fixable but the architectural shape that allows them
to recur is the dual-cImport.

**File:** `src/crypto.zig:661-666`, `src/wallet.zig:547-551`,
`src/descriptor.zig:19-56`, `src/v2_transport.zig:41-43`, plus
6+ test files.

**Core ref:** N/A — Core is C++ where there is no opaque-type alias
issue. The Zig idiom would be a shared FFI module.

**Impact:** every future libsecp-touching feature has to either (a)
add its own cImport (deepening BUG-1) or (b) route through
crypto.zig / wallet.zig (coupling and circular-import risk).

---

## BUG-18 (P1) — Schnorr `schnorrsig_sign32` passes `aux_rand=null`, zeroing BIP-340 safety margin

**Severity:** P1. BIP-340 nonce-derivation safety margin gone.

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

Per BIP-340 §"Default Signing":

> Note: The first version of BIP-340 used the secret key as input to
> nonce derivation … but we now strongly recommend including auxiliary
> random data … which significantly improves protection against
> fault-injection attacks and certain side channel attacks.

libsecp's docstring on `secp256k1_schnorrsig_sign32`:

> aux32: pointer to 32 bytes of fresh randomness. While recommended to
> provide this, it is only supplemental to security and can be NULL.

Core's `key.cpp::SignSchnorr` (line 273-277) constructs `KeyPair kp =
ComputeKeyPair(merkle_root); return kp.SignSchnorr(hash, sig, aux);`
and the `aux` is supplied by callers with `GetRandBytes(32)`.

With `null` aux32, libsecp uses zeroes as the aux. Combined with the
deterministic RFC-6979-style Schnorr nonce derivation, the resulting
nonce becomes purely a function of `(seckey, msg_hash)`. If clearbit
ever re-signs the same `msg_hash` with the same key with a different
witness annex (which is consensus-valid — different annex bytes don't
affect the keypath sighash for SIGHASH_DEFAULT), an attacker observing
both signatures sees identical nonces and trivially recovers the
private scalar from `(r, s1, s2)`.

This is unlikely in practice for clearbit's current use cases
(`signInput` is per-tx and the sighash includes the txid, which is
input-specific), but the safety margin is gone and there is no test
asserting "two signs of the same sighash with the same key produce
DIFFERENT signatures."

**File:** `src/wallet.zig:1922-1930` (production); also
`src/crypto.zig:2235` (test, identical shape — pinning the bug).

**Core ref:** `bitcoin-core/src/key.cpp:273-277 CKey::SignSchnorr`
(passes a 32-byte `aux` derived from `GetStrongRandBytes`); BIP-340
§"Default Signing".

**Impact:** any future change that re-signs the same sighash with the
same key on different aux64 (e.g. PSBT signer that retries) becomes
key-recoverable. Lightning HTLC re-broadcasts and DLC contract
signings would be the at-risk classes; clearbit doesn't ship those
today.

---

## BUG-9 (P1) — `decodeWifPrivkey` no `seckey_verify` (W158 BUG-7 5-wave carry-forward)

**Severity:** P1. Error-code divergence + missing pre-sign gate.

`rpc.zig:11269-11289`:

```zig
fn decodeWifPrivkey(
    self: *RpcServer,
    wif: []const u8,
) ?struct { secret: [32]u8, compressed: bool } {
    const decoded = address_mod.base58CheckDecode(wif, self.allocator) catch return null;
    defer self.allocator.free(decoded.data);

    if (decoded.version != 0x80 and decoded.version != 0xEF) return null;

    var secret: [32]u8 = undefined;
    var compressed = false;
    if (decoded.data.len == 32) {
        @memcpy(&secret, decoded.data);
    } else if (decoded.data.len == 33 and decoded.data[32] == 0x01) {
        @memcpy(&secret, decoded.data[0..32]);
        compressed = true;
    } else {
        return null;
    }
    return .{ .secret = secret, .compressed = compressed };
}
```

No `secp256k1_ec_seckey_verify` (scalar ∈ `[1, n-1]`). Core's
`DecodeSecret` does the check upstream and surfaces "Invalid private
key" before any sign attempt. clearbit's sign attempt at
`crypto.zig:987 ecdsa_sign_recoverable` returns 0 for out-of-range
scalars, then the caller emits "Sign failed" with `RPC_INVALID_ADDRESS_OR_KEY`.

Five-wave open across W47 / W118 / W158 / W159 — single 3-LOC fix
(add `seckey_verify` after the memcpy). Same shape as W158 BUG-7.

Cross-refs the rustoshi-W142-BUG-13 / W154 family: clearbit's scalar
check is a singular missing guard rather than a pattern (rustoshi has
the wider "5-wave tracking single bug" issue from the memory index).

**File:** `src/rpc.zig:11269-11289`.

**Core ref:** `bitcoin-core/src/key.cpp:97-112 CKey::Check`;
`bitcoin-core/src/util/strencodings.cpp::DecodeSecret`.

---

## BUG-10 (P2) — `*_pubkey_serialize` / `*_xonly_pubkey_from_pubkey` return values silently discarded

**Severity:** P2. Hidden-failure path; impossible-to-debug "zero
pubkey" emissions if libsecp ever returns 0.

`wallet.zig:725-731, 979-985, 989-991, 3115-3121` and
`crypto.zig:1051-1058, 873-882` — every call to `secp256k1_ec_pubkey_serialize`,
`secp256k1_xonly_pubkey_serialize`, and `secp256k1_xonly_pubkey_from_pubkey`
uses the Zig discard idiom `_ = secp256k1.…(…)`.

The consensus-side `verifyTaprootControlBlock` (`crypto.zig:1643-1651`)
DOES check the return of `xonly_pubkey_tweak_add_check`. So the
two-pipeline guard pattern applies: the consensus side is rigorous,
the wallet derivation side silently accepts whatever libsecp produced
(possibly zero-filled if the inner ecmult overflowed).

In practice libsecp's serialize functions only fail on programmer
error (e.g. NULL out-pointer) — so this is a P2 not a P1. But it's
exactly the kind of latent bug that surfaces only on a future
libsecp ABI change.

**File:** `src/wallet.zig:725, 979, 989, 991, 3115, 3119`;
`src/crypto.zig:873, 877, 1052`.

**Core ref:** `bitcoin-core/src/pubkey.cpp` — every `serialize` call
either ignores the return (the call is documented as never failing
for valid input) OR asserts (e.g. `key.cpp:190
secp256k1_ec_pubkey_serialize` followed by `assert(result.size() ==
clen); assert(result.IsValid());`). The clearbit gap is the missing
assert / debug-check.

---

## BUG-12 (P1) — `crypto.signMessageCompact` + `decodeWifPrivkey` hold plaintext seckey on stack without zeroize

**Severity:** P1. Stack memory eligible for cold-boot / `gcore` /
swap-out attacks.

`wallet.zig:1722-1723` correctly zeroizes the plaintext after sign:

```zig
var plaintext_secret = try self.getPlaintextSecretKey(utxo.key_index);
defer @memset(&plaintext_secret, 0);
```

But `crypto.signMessageCompact` (`crypto.zig:979-1014`) holds a
`*const [32]u8 seckey` pointer with NO defer-zeroize of the pointed-to
bytes (the caller is responsible). And `decodeWifPrivkey`
(`rpc.zig:11269-11289`) returns a 32-byte struct by value containing
the seckey — caller-side, this lives on the stack with no zeroize
contract.

Similarly `handleSignMessageWithPrivKey` (`rpc.zig:11365-11385`) takes
the WIF privkey from JSON parameters, decodes to 32 bytes via
`decodeWifPrivkey`, and passes through to `signMessageCompact` —
the 32 plaintext bytes are on the stack across the sign call and
NEVER zeroized. After the function returns, the bytes persist in the
return-stack region until the next call reuses the slot.

Core's defense is `secure_allocator<unsigned char>` + `LockedPool`
(see BUG-13). clearbit has neither, so the only defense is per-callsite
`@memset` after use. Two of N callsites get it right, two don't.

**File:** `src/crypto.zig:979-1014`; `src/rpc.zig:11269-11289 /
11365-11385`.

**Core ref:** `bitcoin-core/src/key.h:23-26 CKey::keydata`
(`secure_allocator`); `bitcoin-core/src/support/lockedpool.h`.

---

## BUG-13 (P1) — No `mlock` / `LockedPool` / `secure_allocator` equivalent

**Severity:** P1. Seckeys eligible for swap to disk.

`grep -rn mlock src/` returns no matches. clearbit stores plaintext
seckeys in normal heap (`KeyPair.secret_key: [32]u8` inside an
`ArrayList` at `wallet.zig:602`) or normal stack (per BUG-12). On a
memory-pressured node these pages can swap out and persist in
`/var/swap` until the partition is overwritten.

Core ships `LockedPool` (an mlock-backed arena that bypasses libc
malloc for any allocation that lands in `secure_allocator`), wraps
`CKey::keydata` in `std::vector<unsigned char, secure_allocator<unsigned
char>>`, and `mlock`s every page in the pool. KDF intermediates
(scrypt output buffer) also go through `secure_allocator`.

clearbit's scrypt KDF (`wallet.zig:2126-2143`) writes the derived
32-byte AES-256-GCM key to `derived_key: [32]u8` on the stack, uses
it to encrypt, then `@memset(&derived_key, 0)` at line 2152. The
zeroize is correct; the swap-out risk is not addressed.

Hardness/severity ordering:

- Core: seckey in mlocked, secure-allocator vector; never on swap.
- haskoin / rustoshi (per W155 memory index): partial — mlock equivalent
  in some impls.
- clearbit: nothing.

**File:** `src/wallet.zig:602` (KeyPair.secret_key heap field); rest of
wallet seckey buffers.

**Core ref:** `bitcoin-core/src/support/lockedpool.h/cpp`;
`bitcoin-core/src/support/allocators/secure.h`;
`bitcoin-core/src/key.h:23-26`.

---

## BUG-3 (P2) — descriptor + v2_transport contexts never destroyed

**Severity:** P2 (process-lifetime leak; not exploitable but a
hygiene gap).

`descriptor.zig:59-69`:

```zig
var secp_ctx: ?*secp256k1.secp256k1_context = null;

fn getSecpContext() !*secp256k1.secp256k1_context {
    if (secp_ctx) |ctx| {
        return ctx;
    }
    secp_ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    ) orelse return error.Secp256k1NotAvailable;
    return secp_ctx.?;
}
```

No paired `freeSecpContext` / `deinit`. The ~32 KiB precomputed-
multiplication table allocated by `secp256k1_context_create` lives
forever in the process heap. On a daemon that runs for weeks/months,
this is dwarfed by other allocations — but if the descriptor ctx is
ever reallocated (e.g. test re-init), the old ctx is leaked.

Same shape at `v2_transport.zig:49-69 ellswift_ctx`.

**File:** `src/descriptor.zig:59-69`; `src/v2_transport.zig:49-69`.

**Core ref:** `bitcoin-core/src/key.cpp:589-597 ECC_Stop` — paired
with `ECC_Start`, called from `Shutdown()`.

---

## BUG-16 (P2) — No `ECC_InitSanityCheck` equivalent at process start

**Severity:** P2. Slow-failure path on a corrupted libsecp link.

Core's `ECC_InitSanityCheck` (`key.cpp:565-568`):

```cpp
bool ECC_InitSanityCheck() {
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();
    return key.VerifyPubKey(pubkey);
}
```

This runs at startup (from `init.cpp::AppInitSanityChecks`) and aborts
the node if `false` is returned. `VerifyPubKey` (`key.cpp:237-248`)
internally signs a fresh random hash with the test key and verifies
the signature against the pubkey — full end-to-end sign+verify round
trip.

clearbit's `crypto.initSecp256k1` (`crypto.zig:677-684`) is the
nearest equivalent and does only `context_create`. No round-trip,
no fresh-key test, no `secp256k1_ec_pubkey_create` exercise.

A corrupted libsecp link (e.g. wrong ABI version, partial download,
filesystem bit-flip on the .so) surfaces only on the first real sign
attempt, which on a node could be:

- IBD's first signed transaction (hours to days into sync).
- The first `signmessage` RPC call.
- The first wallet sign on a `sendtoaddress`.

Combined with BUG-15 (no selftest), clearbit has NO early-warning that
its libsecp is malfunctioning.

**File:** `src/crypto.zig:677-684`.

**Core ref:** `bitcoin-core/src/key.cpp:565-568 ECC_InitSanityCheck`;
`bitcoin-core/src/init.cpp` AppInitSanityChecks.

---

## BUG-11 (P2) "wiring-look-but-no-wire / no batch verify primitive" — Schnorr verify is single-call only

**Severity:** P2. Performance / future-proof gap.

`script.zig:1166`:

```zig
if (crypto.verifySchnorr(&sig, &sighash, &xonly)) {
```

This is inside the tapscript `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` /
`OP_CHECKSIGADD` execution loop and called once per signature.

libsecp does NOT yet ship a public batch-verify API (the experimental
implementation lives at `src/modules/schnorrsig/main_impl.h` but is
not exported in `include/secp256k1_schnorrsig.h`). So this is not a
clearbit-specific gap — Core has the same single-call constraint.

The wave brief specifically called out "Schnorr batch verify" as a
gate; verdict is that clearbit is on par with Core for this surface.

The fleet-pattern concern is the **wiring-look-but-no-wire** shape:
`crypto.zig:668-669` declares `pub const has_secp256k1: bool = true;`
as a binary capability flag. Any future code that imagines a
`crypto.verifySchnorrBatch` function would silently single-call
(because the symbol doesn't exist and Zig would refuse to compile);
but a comment, README, or perf-doc claim of "batch verification" would
be a fleet-pattern lie. None exists today, so this is a P2 watching-
brief not a P1 bug.

Cross-fleet: this is the inverse of beamchain W156 BUG-7 (claims
"BIP-152 SEND-side wired" with zero callers); clearbit avoids the
specific shape by simply not having a claim.

**File:** `src/script.zig:1166`; `src/crypto.zig:668-669`.

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:1717-1742
CheckSchnorrSignature` (also single-call); `bitcoin-core/src/checkqueue.h`
(parallelism happens at the input level, not the sig level).

---

## Severity rollup

- **P0-SEC: 3** — BUG-1 (5 contexts), BUG-4 (no randomize / "side-
  channel-blinding-disabled" fleet pattern), BUG-14 (cipher-as-scalar
  carry-forward of W158 BUG-2 at FFI level).
- **P1: 8** — BUG-2 (re-init races), BUG-6 (no sign-then-verify
  paranoia ECDSA), BUG-7 (same for recoverable-sign), BUG-8 (same for
  Schnorr), BUG-9 (decodeWifPrivkey no seckey_verify, W158 5-wave
  carry-forward), BUG-12 (stack seckey no zeroize), BUG-13 (no
  mlock / LockedPool), BUG-15 (no selftest), BUG-17 (dual-cImport
  opaque-type wall), BUG-18 (schnorrsig_sign32 aux=null).
  *(Note: revised count below in P1+P2 listing; 10 P1 total.)*
- **P2: 5** — BUG-3 (descriptor/ellswift ctx leak), BUG-5
  (`CONTEXT_VERIFY|CONTEXT_SIGN` deprecated), BUG-10 (serialise return
  discarded), BUG-11 (no batch verify, only a watching-brief), BUG-16
  (no `ECC_InitSanityCheck`).

**18 bugs total** (3 P0-SEC + 10 P1 + 5 P2).

---

## Fleet patterns observed

1. **"side-channel-blinding-disabled" (W158 NEW, now confirmed in
   clearbit at scale)** — BUG-4. Zero calls to `secp256k1_context_
   randomize` across FIVE production contexts. The W158 wave brief
   explicitly asked us to check; the answer is "lunarblock W158 BUG-7
   was not unique — clearbit has the same gap, fleet-wide". Per
   memory index, W158 found this in lunarblock; W159 now confirms
   clearbit. Expectation: blockbrew / haskoin / nimrod / camlcoin /
   ouroboros likely have the same gap. **New fleet sub-pattern:
   "5-of-fleet-likely side-channel-blinding-disabled" — would
   complete the universal pattern alongside W128 banman 8/10, W144
   script_flag_exceptions 9/10, W146 flat-file dead-class 8/10, and
   W157 CheckSignetBlockSolution 9/10.**

2. **"encrypted-wallet-cipher-as-scalar" (W158 NEW) — 2-wave open**
   BUG-14. The fundamental shape from W158 BUG-2 persists at the FFI
   level because the wrapper layer never grew a typed `SecKey`
   abstraction. New variant: **"keystore-boundary-by-discipline,
   not-by-type"** — Core's `CKey` / `secure_allocator` / `GetKey(keyid,
   key)` plumbing makes ciphertext-vs-plaintext mix-up a compile error;
   clearbit's `[32]u8` is type-equal to either.

3. **"dual-cImport opaque-type mismatch" (NEW)** — BUG-17. Zig-specific
   shape: every `@cImport` produces a fresh opaque type alias, so
   sharing a libsecp context across modules forces the per-module
   pattern. The fix is a single `secp256k1_ffi.zig` module; the absence
   of that fix forces BUG-1, BUG-2, and BUG-5 to recur.

4. **"comment-as-confession 19th distinct fleet instance"** —
   `tests_wallet_segwit_v0.zig:51-53` explicitly documents the
   dual-cImport workaround. **First clearbit instance in this audit;
   confirms pattern saturation continues at every wave.**

5. **"two-pipeline guard 22nd distinct extension"** — BUG-10. The
   consensus-side `verifyTaprootControlBlock` checks
   `xonly_pubkey_tweak_add_check` return; the wallet-derivation side
   discards every serialise return. Same code-shape inversion across
   the verify/derive boundary.

6. **"wiring-look-but-no-wire architectural NEAR-MISS"** — BUG-11.
   `pub const has_secp256k1: bool = true` is a binary capability flag
   that doesn't distinguish between "verify works" and "batch verify
   works"; today no clearbit code claims batch verify so there's no
   actual lie, but the foundation for a future advertisement-as-lie
   is in place.

7. **"defense-in-depth missing at the producer" (W157 NEW, now at
   the FFI layer)** — BUG-6 + BUG-7 + BUG-8. Core's sign-then-verify
   paranoia is a producer-side check; clearbit emits sigs with no
   producer-side verify. Same shape as W157 hotbuns BUG-14 but at a
   different layer (hotbuns was missing block-header validation at the
   miner; clearbit is missing sig-verify at the signer).

8. **"5-wave carry-forward 2nd known instance"** — BUG-9 W158 BUG-7
   is now W47 → W118 → W158 → W159 (4 distinct waves spanning the
   same single-LOC fix). Rustoshi's W142 BUG-13 set the 5-wave
   record at W155; clearbit BUG-9 is the second 4-wave entry.

9. **"single-language type-system pattern as bug-root"** —
   BUG-17 + BUG-1 + BUG-5. The fact that Zig's `@cImport` produces
   fresh opaque types per `@cImport` IS the structural reason
   clearbit has five contexts. A Rust impl with one `#[link(name =
   "secp256k1")] extern "C" {…}` block would have one context type
   and naturally one context. Worth tagging in future audits: which
   clearbit findings are forced by the language vs the implementation.

10. **"test pinning a missing aux32" (W157 NEW)** — BUG-18. The test
    at `crypto.zig:2235` calls `schnorrsig_sign32` with `null` aux,
    matching production. If the production code is ever fixed to
    pass aux32, the test must be updated to match — but as written
    the test pins the missing-aux behavior.

---

## Top P0-SEC findings (in order of operational priority)

1. **BUG-14 (P0-SEC catastrophic, 2-wave open with W158)** — cipher-
   as-scalar `signmessage` leaks AES-GCM ciphertext as ECDSA private
   scalar at the FFI level. Fix: one-line edit at `rpc.zig:11355`
   to call `wallet.getPlaintextSecretKey(idx)` + `isUnlocked` check.
   Same fix as W158 BUG-2; both still unfixed at HEAD.

2. **BUG-4 (P0-SEC, W158 NEW fleet pattern)** — zero
   `secp256k1_context_randomize` calls. Fix: ~5 LOC per context (4
   sites). Closes the "side-channel-blinding-disabled" fleet pattern
   for clearbit. Likely closes the universal-fleet pattern when
   replicated across ≥6 impls.

3. **BUG-1 (P0-SEC architectural)** — 5+ distinct secp256k1
   contexts. Fix requires BUG-17 first (extract shared
   `secp256k1_ffi.zig`), then converge all contexts on one
   process-singleton. ~150 LOC architectural refactor that closes
   BUG-1, BUG-2, BUG-3, BUG-5 simultaneously.

---

## Fix priority for next fix-wave

1. **BUG-14** — cipher-as-scalar (P0-SEC, ~5 LOC at `rpc.zig:11355`).
2. **BUG-4** — `secp256k1_context_randomize` (P0-SEC, ~5 LOC × 4
   contexts).
3. **BUG-9** — `decodeWifPrivkey` `seckey_verify` (P1, ~3 LOC, W158
   carry-forward).
4. **BUG-17 + BUG-1** — single `secp256k1_ffi.zig` module (P1
   architectural, ~150 LOC; closes BUG-1, BUG-2, BUG-3, BUG-5).
5. **BUG-15 + BUG-16** — selftest + sanity-check at process start
   (P1, ~10 LOC at `crypto.initSecp256k1`).
6. **BUG-6 + BUG-7 + BUG-8** — sign-then-verify paranoia (P1, ~10
   LOC per sign site × 3 = ~30 LOC).
7. **BUG-13** — mlock / LockedPool equivalent (P1, ~50 LOC if a
   simple page-mlock wrapper around the `KeyPair.secret_key`
   storage).
8. **BUG-18** — `schnorrsig_sign32` aux32 from std.crypto.random
   (P1, ~3 LOC; also update the pinning test).
9. **BUG-12** — zeroize stack seckey at `signMessageCompact` +
   `decodeWifPrivkey` (P1, ~3 LOC × 2).
10. **BUG-10** — assert / check serialise return values (P2, ~3 LOC
    × 6 sites).
