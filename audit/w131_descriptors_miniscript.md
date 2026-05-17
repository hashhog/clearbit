W131 — Descriptors + Miniscript audit (clearbit / Zig 0.13)
============================================================

Wave: W131
Subsystem: BIP-380/385 Descriptors (descriptor language, key expressions,
           tr() tree, multisig, derivation paths, multipath, checksum) +
           Miniscript (BIP-380's miniscript dialect — type system,
           non-malleability, sat/dsat analysis, ms parser, script lowering).
Excludes: secp256k1 / BIP-32 derivation correctness (W118 covers wallet
          derivation); BIP-340/341/342 Schnorr/Taproot consensus (W127);
          taproot leaf-hash + control-block formatting beyond the descriptor
          language proper.

References (Bitcoin Core):
- bitcoin-core/src/script/descriptor.cpp + descriptor.h
- bitcoin-core/src/script/miniscript.cpp + miniscript.h
- bitcoin-core/src/test/descriptor_tests.cpp
- bitcoin-core/src/test/miniscript_tests.cpp
- bitcoin-core/src/test/data/descriptor_tests_external.json
- bitcoin-core/src/script/script.h
  (MAX_PUBKEYS_PER_MULTISIG = 20, MAX_PUBKEYS_PER_MULTI_A = 999)

BIPs:
- BIP-380 (Output Script Descriptors, general operation)
- BIP-381 (pk / pkh / sh / wpkh / wsh / multi / sortedmulti / addr / raw / combo)
- BIP-382 (Taproot output descriptors — tr())
- BIP-385 (Raw segwit-key descriptors — rawtr())
- BIP-386 (Taproot descriptors — tr() with miniscript tapleaves)
- ms (informal): https://bitcoin.sipa.be/miniscript/

Likely clearbit paths:
- src/descriptor.zig — checksum (polymod, INPUT_CHARSET, CHECKSUM_CHARSET);
  KeyOrigin / KeyExpression / Key / Descriptor union;
  Parser (parseDescriptor / parseKey / parseExtendedKey / parseTapTree /
  parseMulti / parseOrigin / parsePathComponent); deriveScript;
  parseDescriptor (top-level entry); toString / toStringWithChecksum;
  getDescriptorInfo; hasPrivateKeys; isSolvable; deriveAddresses;
  decodeAddressToScript / scriptToAddress.
- src/miniscript.zig — ScriptContext (p2wsh / tapscript); NodeType (B/V/K/W);
  TypeProperties (only z o n d e f s m u x; missing g/h/i/j/k);
  Key (pubkey | descriptor_key); MiniNode + Fragment enum;
  computeType / computeMaxWitnessSize / computeScriptSize;
  toScript / toScriptInner; satisfy / satisfyInner; SatisfactionProvider /
  Witness; Parser (parseExpr / parseKey / parseHash{20,32}); getFragment.
- src/script.zig — opcode constants used by miniscript-emitted bytecode
  (referenced only for opcode parity checks at the lowering layer).

-------------------------------------------------------------------------------
Summary
-------------------------------------------------------------------------------

**28 BUGS across 30 gates.** Two gates (G1 polymod constants, G2
checksum charset) PASS — clearbit's BCH-32 checksum implementation is a
byte-faithful port of Core's DescriptorChecksum. Every other layer of the
descriptor + miniscript stack diverges from Core in ways that range from
"silently accepts garbage" to "produces a wrong scriptPubKey" to "claims a
non-malleable script is non-malleable when it actually is malleable". The
chief categories are:

1. **Descriptor language coverage gaps — BIP-380/381 surface holes**
   (BUG-1, BUG-3, BUG-4, BUG-7, BUG-9, BUG-10, BUG-13, BUG-22).
   `Func("multi_a")` / `Func("sortedmulti_a")` / `Func("musig")` /
   `Func("rawtr")` (the BIP-386 raw-taproot variant) parsing is partial or
   missing. clearbit's `parseDescriptor` has NO arm for `multi_a` or
   `sortedmulti_a`, even though `miniscript.zig` has the `multi_a` fragment.
   `combo()` is parsed but `deriveScript` only emits the P2PKH script
   (Core emits 4 scripts: P2PK, P2PKH, P2WPKH, P2SH-P2WPKH; line in
   `deriveScript`: "combo() returns multiple scripts - for now just return
   P2PKH"). `addr()` is parsed at any depth; Core restricts it to TOP.
   `raw()` likewise. `pkh()` is allowed inside `tr()` via the lazy generic
   parser dispatch even though Core forbids `pkh` outside of TOP/P2SH/P2WSH.
   The "n" key-path multipath specifier `<0;1>` (BIP-389) is entirely
   absent from `parsePathComponent` / `parseExtendedKey`.

2. **Checksum + canonicalization correctness** (BUG-2, BUG-5, BUG-6, BUG-23).
   The polymod / charset / 8-symbol shift loop ARE correct (G1, G2 PASS).
   But the integration is loose: `parseDescriptor` accepts a descriptor
   with NO checksum without complaint (Core fails fast unless the caller
   explicitly opts into "no checksum"). `verifyChecksum` mandates the
   exact `desc#8chars` shape but does not reject the empty-checksum case
   `desc#` (8 chars after `#` are required, but trailing whitespace or a
   shorter tag is silently rejected without a recoverable error message).
   `toString` for `wsh(miniscript)` prints literally `"wsh(...)"` —
   round-tripping a miniscript descriptor is broken: parse(toString(x))
   does not equal x. `addChecksum` does not validate that the input has
   no embedded `#` (Core's `AddChecksum` is a thin wrapper but the
   call site `GetDescriptorChecksum` strips before re-adding).

3. **Key expression / origin parsing — BIP-380 §"Key Origin Identification"**
   (BUG-8, BUG-11, BUG-12, BUG-14, BUG-15, BUG-25).
   `parseOrigin` requires the fingerprint be exactly 4 bytes / 8 hex chars
   but does not check that the 8 chars are hex BEFORE attempting to read
   them (Core: `if (slash_split[0].size() != 8) error; if (!IsHex(fpr))
   error`). Hardened markers: clearbit accepts BOTH `'` and `h` per
   `parsePathComponent`, but the `KeyOrigin.format` always rewrites with
   `'`, breaking the round-trip when a user supplied `h` (Core preserves
   the apostrophe-vs-h distinction via `m_apostrophe` and `StringType::
   NORMALIZED`). `parseKeyExpression` distinguishes xpub/xprv/tpub/tprv
   prefixes but NOT `xpub`-then-anything-that-base58-decodes-to-a-78-byte-
   ext-key: it accepts a *prefix match* without actually decoding base58
   first, so `tpubgarbage/0/*` proceeds to `parseExtendedKey` which only
   detects errors at derive time. `parsePathComponent` accepts unbounded
   numeric values up to `u32` max, then `or`s `0x80000000` for hardened —
   Core enforces `*p > 0x7FFFFFFFUL` rejection (any value ≥ 2³¹ is invalid
   BEFORE the hardened bit is applied; clearbit lets `4294967295h` pass
   silently, which silently means index 2³¹-1 hardened ∨ undefined).
   Path component parsing also does not check for empty `//` segments;
   Core's `Split(span, '/')` allows empty spans only at boundaries.

4. **Miniscript type system — missing properties + wrong propagation**
   (BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-24).
   clearbit's `TypeProperties` is missing **g, h, i, j, k** entirely.
   Without `g`/`h`/`i`/`j`, the timelock-mixing predicate (Core's `<<k_mst`)
   cannot be computed; `checkTimeLocksMix` returns the wrong boolean
   (`return !(self.typ.has_time_lock and self.typ.has_height_lock)`,
   where the two booleans are themselves never set in `computeType`).
   The K-type sanity check `K implies u and s` is encoded but Core also
   requires `K implies s` AND `e implies d` AND `e conflicts with f` AND
   `d conflicts with f` AND `V implies f` AND `z implies m` — clearbit's
   `isValid` misses 6 of the 12 sanity-checks `SanitizeType` enforces.
   `WRAP_D` does not encode the BIP-related Tapscript subtlety: Core sets
   `u` only when `IsTapscript(ms_ctx)` (P2WSH MINIMALIF is a policy rule,
   not consensus, so `u` does NOT hold under P2WSH). clearbit's
   `wrap_d` returns `.u = true` unconditionally — this propagates
   wrong-non-malleable claims up the tree under P2WSH context.
   `or_b` requires `x:Bd y:Wd`; clearbit checks `x.d and y.d` but not
   `x.base_type == .B and y.base_type == .W`. `and_b` requires
   `x:B y:W`; clearbit does check both but writes `e = x.e and y.e and
   (x.s or y.s)` where Core has `e=e_x*e_y*s_x*s_y` (BOTH must be safe,
   not either) — this is a TYPE-ERROR that allows malleable
   dissatisfactions to be claimed non-malleable.

5. **Miniscript parser — wrappers, comma-separated chained wrappers,
   `0`/`1` literals, lifetime issues** (BUG-21, BUG-26, BUG-27, BUG-28).
   The wrapper parser at `parseExpr` checks `self.input[self.pos + 1] ==
   ':'`, which means it ONLY accepts SINGLE-LETTER wrappers. Core
   accepts CHAINS of wrappers (e.g. `dv:older(144)`, `tlc:pk_k(...)`).
   `t:` / `l:` / `u:` are special-cased as desugaring but `a:` / `s:` /
   `c:` / `d:` / `v:` / `j:` / `n:` are folded one-at-a-time, so
   `dvc:pk_k(x)` parses as `d:(vc:pk_k(x))` — clearbit can never
   accept it. The `pk` / `pkh` aliases in `getFragment` clash with the
   descriptor-level `pk()` / `pkh()` (which take a *Key*, not a key-or-
   pubkey-hash); since the same identifier flows through both layers a
   miniscript fragment named `pk(...)` is dispatched the same as a
   descriptor `pk(...)`, and the parser shape disambiguates by which
   parser is on the call stack — fragile and not how Core does it
   (Core's `pk` is a wrapper macro that becomes `c:pk_k(KEY)`).
   `parseKey` in miniscript falls back to `descriptor_key: 0` for every
   non-hex string, never using the actual key index — every descriptor
   key reference inside a miniscript expression collides at index 0.

Severity legend: **P0-CDIV** = consensus-divergent emit-side bug;
**P0** = wrong-script for declared semantics; **P1** = wrong
type/property leading to wrong sat/dsat or non-malleability claim;
**P2** = parser accept/reject mismatch with Core; **P3** = cosmetic /
RPC output / round-trip.

-------------------------------------------------------------------------------
30-gate audit matrix
-------------------------------------------------------------------------------

### Group A — Checksum (BIP-380 §"Checksum")

**G1 PASS:** Polymod generator constants
(0xf5dee51989 / 0xa9fdca3312 / 0x1bab10e32d / 0x3706b1677a / 0x644d626ffd)
are byte-for-byte from Core descriptor.cpp:98-102.

**G2 PASS:** INPUT_CHARSET + CHECKSUM_CHARSET match Core
descriptor.cpp:121-127. `polyMod` masks `c & 0x7ffffffff` and shifts left
by 5 identically. The 8-symbol output loop and final `c ^= 1` match.

**G3 BUG-1 (P2) — `parseDescriptor` does not require a checksum.**
Top-level `parseDescriptor(allocator, input)` returns success on a
descriptor without `#` separator. Core's `Parse()` accepts a `require_
checksum` bool: when true, missing checksum fails with "Missing checksum";
when false, the function still verifies if a `#` is present. clearbit has
NEITHER the gate NOR a "missing checksum" failure mode.

**G4 BUG-2 (P3) — `verifyChecksum` accepts only fixed-length tails.**
The implementation enforces `hash_pos + 9 != desc_with_checksum.len`,
which means a 9-character tail starting with `#` is required. Core also
fails on length mismatch but produces specific error
"Expected 8 character checksum, not 7 characters" (descriptor.cpp:2853).
clearbit returns a bare `false` without an error string — RPC
`getdescriptorinfo` and `deriveaddresses` errors collapse to
`InvalidDescriptorCharacter`.

### Group B — Descriptor language coverage (BIP-380/381/382/386)

**G5 BUG-3 (P0) — `multi_a` / `sortedmulti_a` are NOT parsed.**
`parseDescriptor` has 12 if-arms for function names: pk, pkh, wpkh, sh,
wsh, tr, multi, sortedmulti, addr, raw, rawtr, combo. There is no arm
for `multi_a` or `sortedmulti_a` (BIP-381 / BIP-342 tapscript). The
*miniscript* layer has `multi_a` as a Fragment, but the *descriptor*
layer cannot reach it: `tr(KEY, multi_a(2, a, b, c))` is rejected with
`InvalidFunctionName` at the tap-tree parse step because `parseTapTree`
recurses through `parseDescriptor`, not `miniscript.parse`.

**G6 BUG-4 (P0) — `combo()` emits only the P2PKH script.**
`deriveScript` for `.combo` produces the P2PKH 25-byte sequence and
nothing else. Core's `ComboDescriptor::MakeScripts` returns up to 4
scripts: P2PK, P2PKH, then if the key is compressed P2WPKH and
P2SH-P2WPKH (descriptor.cpp:1140-1170). The `deriveAddresses` RPC
output is therefore missing 1-3 addresses per combo() index per call.
A wallet importing `combo(0279…)#cks` will only watch P2PKH, missing
deposits to P2WPKH (the default for modern wallets).

**G7 BUG-5 (P3) — `wsh(miniscript)` toString prints literal `"wsh(...)"`.**
`writeDescriptor` for `.wsh_miniscript` writes the placeholder string
`"wsh(...)"`. Round-trip via `toStringWithChecksum` then re-`parseDescriptor`
is broken. Core's `WSHDescriptor::ToStringHelper` walks the inner
miniscript via the keyparser's `ToString` callback (descriptor.cpp:1300-).
clearbit cannot reconstruct a miniscript descriptor from `toString` output.

**G8 BUG-6 (P3) — `addChecksum` is not idempotent.**
`addChecksum(allocator, "raw(00)")` returns `"raw(00)#<chksum>"`. A
second call on that result would attempt to compute a checksum over the
already-checksummed string, returning a non-recoverable string. Core's
`AddChecksum` is documented as taking a no-checksum input; `GetDescriptorChecksum`
strips before re-adding. clearbit has no guard / no companion strip
helper, so naive callers can produce double-checksummed descriptors.

**G9 BUG-7 (P0) — `addr()` accepted at any depth.**
`parseDescriptor(ctx)` for `addr` does not check `ctx == .top`. Core
descriptor.cpp:2447 explicitly: `if (ctx == ParseScriptContext::TOP &&
Func("addr", expr))`. clearbit allows `sh(addr(...))` and
`wsh(addr(...))` and even `tr(KEY, addr(...))` as a tap-leaf, all of
which are spec violations.

**G10 BUG-8 (P0) — `raw()` accepted at any depth.**
Same shape as G9: Core restricts `raw()` to TOP only; clearbit allows
nesting. `sh(raw(0014deadbeef…))` parses successfully; Core would
emit "Can only have raw() at top level".

**G11 BUG-9 (P0) — `rawtr()` accepts only the bare `xonly_hex` form.**
The clearbit `rawtr` arm only handles a 64-char hex literal. Core's
rawtr supports any pubkey provider (origin info, xpub/path/wildcard),
so `rawtr([fingerprint/86h/0h/0h/0]xpub.../0/*)` is a legal BIP-386
descriptor — clearbit returns `InvalidKeyExpression` because the lower
parser path is not used.

**G12 BUG-10 (P0) — `pkh()` allowed inside any context including `tr()`.**
Core descriptor.cpp:2290 gates `pkh` on TOP || P2SH || P2WSH. clearbit's
`parseDescriptor` for `pkh` has no `ctx` guard; it will parse and emit a
P2PKH script for a tapleaf, which is not a valid tapleaf script (the
output script has OP_DUP/OP_HASH160/.../OP_CHECKSIG, but a tapleaf
expects miniscript or rawtr-style key-only).

**G13 BUG-11 (P2) — `multi()` allowed inside `tr()`.**
Core requires `multi` only in TOP/P2SH/P2WSH and `multi_a` inside `tr()`.
clearbit's `parseMulti(false)` is dispatched the same way regardless
of `ctx`, so `tr(KEY, multi(2, a, b))` parses — Core would emit "Can
only have multi/sortedmulti at top level, in sh(), or in wsh()".

**G14 BUG-12 (P0-CDIV) — `multi()` does not enforce MAX_PUBKEYS_PER_MULTISIG=20.**
`parseMulti` collects keys into a list with no upper bound. Core caps
at `MAX_PUBKEYS_PER_MULTISIG = 20` (script.h:34) and `multi_a` at 999
(script.h:37). A `multi(2, key1, …, key25)` descriptor will be accepted
and `deriveScript` will produce `<2> <key1> ... <key25> <0x69> OP_CHECKMULTISIG`
— that `0x50+25 = 0x69` is NOT a valid OP_N (0x69 is OP_VERIFY). The
script is invalid AND consensus-invalid for any n>16.

**G15 BUG-13 (P1) — `multi()` does not enforce `1 <= k <= n`.**
`threshold` is parsed as `u32` without bounds. `multi(0, key)`,
`multi(5, key1, key2)`, `multi(2, )` are all accepted; Core rejects
threshold < 1 or threshold > n with explicit error messages
(descriptor.cpp:2353-2358). The emitted script encodes `0x50 + 0 = 0x50
= OP_0` for `multi(0,...)`, producing a non-malleable but useless script.

**G16 BUG-14 (P0-CDIV) — `parseMulti` resolves keys with parseKey(.top), not the actual context.**
Even though `parseMulti` is called from a context like `sh()` or `wsh()`,
it parses keys with `parseKey(.top)`. Core threads the parse context
through to `ParsePubkey` so e.g. inside `wsh()` an uncompressed pubkey
is rejected (`permit_uncompressed = ctx == ParseScriptContext::TOP ||
ctx == ParseScriptContext::P2SH`, descriptor.cpp:1879). clearbit does
not perform this check at all (no `permit_uncompressed`/`is_compressed`
guard), so `wsh(multi(2, <uncompressed-key>, …))` would build a
nonstandard P2WSH script.

**G17 BUG-15 (P2) — `parseOrigin` does not hex-validate fingerprint before reading.**
The 8-character read loop calls `hexDigit(c) orelse return error.Invalid
Fingerprint`, which means invalid chars are caught — but only after
advancing the parser. A 7-character fingerprint plus a `/` is detected
only at the `expect('/')` step (since the 8th char read happens to be
`/`, which `hexDigit` rejects). Error reporting therefore confuses
"7-char fingerprint" with "invalid hex in fingerprint". Core has
explicit `if (slash_split[0].size() != 8)` check upfront
(descriptor.cpp:2119) producing a distinct error.

**G18 BUG-16 (P0) — `parsePathComponent` does not reject path values ≥ 2³¹.**
Core: ParseKeyPathNum (descriptor.cpp:1769) `if (*p > 0x7FFFFFFFUL)
{ error = "Key path value %u is out of range"; return nullopt; }`.
clearbit accepts any `u32`; the hardened-bit OR collides with high
values: a literal `4294967295h` would produce `0xFFFFFFFF | 0x80000000
= 0xFFFFFFFF` which is consensus-impossible for BIP-32 (hardened indices
top out at `2³¹ - 1`, then the hardened bit is set internally).

**G19 BUG-17 (P2) — multipath specifier `<n;m;…>` not supported.**
BIP-389 introduces `<0;1>` in derivation paths so a single descriptor
expands to two scripts. clearbit's `parsePathComponent` only knows
numeric paths plus hardened markers; `parseExtendedKey` only knows `*`
and `*'`/`*h`. There is no logic for `<…;…>`. Core ParseKeyPath:1789
handles this and produces multiple `KeyPath`s.

**G20 BUG-18 (P2) — `musig()` key aggregation not supported.**
Recent Core (descriptor.cpp:1751 ParseScriptContext::MUSIG and
:1964 `Func("musig", …)`) supports `musig(KEY1, KEY2, ...)` as a tap
internal-key composite. clearbit has no `musig` arm anywhere.

### Group C — Miniscript type system

**G21 BUG-19 (P1) — `TypeProperties` missing `g/h/i/j/k` (timelock + duplicate-key tracking).**
Core's Type carries 19 bits (B/V/K/W + zonddefmsx + ghijk). clearbit
keeps `has_time_lock` / `has_height_lock` as `bool`s on the type
record but never sets them — `computeTypeForFragment` for OLDER and
AFTER returns `.{ .base_type = .B, .z = true, .f = true, .m = true }`
without `has_time_lock = true`. The `checkTimeLocksMix` helper then
always returns `true` (because both booleans stay `false`).

**G22 BUG-20 (P1) — `isValid` misses 6 of Core's 12 SanitizeType assertions.**
Specifically `e implies d`, `e conflicts with f`, `V implies f`,
`d conflicts with f`, `z implies m`, and the single-base-type
uniqueness (B+V+K+W must be exactly one). clearbit only checks
`z ∧ (o ∨ n) → invalid`, `n ∧ W → invalid`, `V ∧ (d ∨ e ∨ u) →
invalid`, and `K → (u ∧ s)`. Missing checks allow a fragment to
claim mutually-incompatible properties.

**G23 BUG-21 (P1-CDIV) — `wrap_d` propagates `u = true` unconditionally.**
Core descriptor: in P2WSH, `WRAP_D` does NOT set `u` (MINIMALIF is a
policy rule, not consensus) — `u` is set ONLY in Tapscript context
(miniscript.cpp:126). clearbit unconditionally sets `.u = true` for
`wrap_d`. A P2WSH miniscript with `d:` will be claimed to satisfy
the `u` property (push exactly 1) when in fact it may push any
non-zero value, which makes downstream type composition wrong.

**G24 BUG-22 (P1) — `or_b` does not require `x:B y:W`.**
clearbit's `or_b` arm: `if (x.base_type == .B and y.base_type == .W
and x.d and y.d)`. So this one's actually checked. **WAIT — recheck:**
At line 1382 it does: `if (x.base_type == .B and y.base_type == .W
and x.d and y.d)` — OK G24 is partially correct. BUT
**`and_b` correctness for `e`**: line 1367 has
`.e = x.e and y.e and (x.s or y.s)` where Core: `(x & y & "e"_mst).If((x & y) << "s"_mst)`
= `x.e AND y.e AND x.s AND y.s` (both safe). clearbit's `or` should
be `and`. Result: an and_b where one subexp is `s` but the other is
not is claimed non-malleable-dissatisfiable when in fact it is malleable.

**G25 BUG-23 (P1) — `or_b` non-malleability missed.**
Same shape: Core `m=m_x*m_y*e_x*e_y*(s_x+s_y)`. clearbit:
`.m = x.m and y.m and x.e and y.e and (x.s or y.s)` (line 1390) —
actually MATCHES Core. So G25 partial PASS. **But `or_d`**: Core
`m=m_x*m_y*e_x*(s_x+s_y)` (only x.e, not y.e); clearbit
(line 1431) `.m = x.m and y.m and x.e and (x.s or y.s)` — **MATCHES**.
**Or_c**: Core `m=m_x*m_y*e_x*(s_x+s_y)`. clearbit line 1409
`.m = x.m and y.m and x.e and (x.s or y.s)`. **MATCHES**.
BUT `or_i`: Core `m=m_x*m_y*(s_x+s_y)`. clearbit line 1452
`.m = x.m and y.m and (x.s or y.s)`. **MATCHES**.
BUT `and_v` non-malleability: Core `m=m_x*m_y*z_x*z_y` — NO. Core
is `(x & y & "mz"_mst)` so it propagates m AND z, but the actual `m`
clause is `(x & y & "mz"_mst)` meaning the result m=x.m∧y.m AND
result z=x.z∧y.z (it's a 2-bit field merge, not a relation between
m and z). clearbit line 1346: `.m = x.m and y.m and (x.s or !y.f)`.
**Core does NOT have this `(x.s or !y.f)` clause for `m` in AND_V**.
This is a synthetic/wrong propagation. The Core form for AND_V `m`
is just `m_x and m_y`. clearbit's extra `(x.s or !y.f)` term will
*reject* some non-malleable scripts as malleable (over-conservative
in a CONSENSUS-IRRELEVANT way, but still wrong).

**G26 BUG-24 (P1) — Threshold type computation oversimplified.**
clearbit's `thresh` arm aggregates only z/m/s/d as plain AND/OR
loops. Core's THRESH (miniscript.cpp:229-258) maintains `args`,
`num_s`, `acc_tl`, and `all_e`/`all_m`. The output is
`Bdu | z.If(args==0) | o.If(args==1) | e.If(all_e ∧ num_s==n_subs) |
m.If(all_e ∧ all_m ∧ num_s ≥ n_subs-k) | s.If(num_s ≥ n_subs-k+1) |
acc_tl`. clearbit misses `u`/`e`/`acc_tl`/`o`/`Bdu` entirely. Two
practical consequences: (a) `thresh(2, pk_k(a), pk_k(b), pk_k(c))` is
claimed `o = false` always, when Core sets `o = true` when only one
sub is non-z (correct for one-arg input). (b) `e` is never set so
`d:thresh(…)` mis-types; (c) timelock-mix info is lost across the
threshold boundary.

**G27 BUG-25 (P1) — `WRAP_C` does not require `K` subtype.**
clearbit's `wrap_c` (line 1239) DOES require `x.base_type == .K` —
this one PASSES. **But `WRAP_J`** (line 1296): Core requires
`x:Bn`. clearbit requires `x.base_type == .B and x.n` — MATCH. PASS.
**But `WRAP_V`**: Core requires `x:B`. clearbit (line 1277) requires
`x.base_type == .B`. PASS. **But `AND_V`**: Core requires `x:V`.
clearbit (line 1338) requires `x.base_type == .V`. PASS. **But
`OR_C`**: Core requires `x:Bdu y:V`. clearbit (line 1403): `x.base_type
== .B and y.base_type == .V and x.d`. **Missing `x.u`**. So `or_c(B-not-u, V)` will be claimed valid in clearbit — wrong type, allows
underlying script to push a non-1 value where Core would reject the
program from forming. (Re-numbering: this is the actual G27 BUG-25.)

### Group D — Miniscript parser / script lowering

**G28 BUG-26 (P2) — Wrapper parser accepts only single-letter chains.**
`parseExpr` at miniscript.zig:1818 checks ONE character followed by a
colon. So `dv:older(144)` is parsed as `d:` then `v:older(144)`,
which in turn fails because `v:older(144)` is a `V`-type wrap and
the outer `d:` requires `x:V z:` (Core OK with this). But `tlc:pk_k(KEY)`
should parse as wrapper-chain `t`, `l`, `c` applied to `pk_k`. clearbit
only sees `t:`, recurses, sees `lc:`, then `l:c:`, then fails because
`c:` recurses into `parseExpr` and tries to read `pk_k(...)` as a
wrapper before falling through to fragment parsing. The chain-of-
wrappers convention from miniscript.sipa.be is broken — clearbit
accepts SOME chains by accident (because the single-letter check
recurses) but fails any chain that puts wrappers requiring different
input types in non-greedy order.

**G29 BUG-27 (P0) — `wrap_v` script-lowering does not switch to VERIFY for or_b/or_d/wrap_c.**
clearbit's `wrap_v` lowering (line 393-409) lists `wrap_c, and_b, or_b,
thresh` as the fragments whose final opcode can be merged with a
following VERIFY. Core's optimization additionally handles `WRAP_C`
inside other wrappers, `OLDER`/`AFTER` (the final OP_CSV/OP_CLTV
are themselves verify-style), `SHA256`/`HASH160`/etc (final OP_EQUAL
becomes OP_EQUALVERIFY), `or_d` (final OP_BOOLOR). clearbit's list
is shorter, so `v:sha256(h)` emits the unmerged form
(OP_EQUAL OP_VERIFY = 2 bytes) instead of OP_EQUALVERIFY (1 byte),
making the script ~1 byte larger per occurrence. Not consensus-
divergent, but a fingerprintable lowering difference.

**G30 BUG-28 (P0-CDIV) — `multi` script-lowering emits raw `0x50+threshold`/`0x50+n` without OP_1..OP_16 guard.**
`deriveScript` for `.multi`/`.sorted_multi` (descriptor.zig:970/997):
`try script.append(@intCast(0x50 + m.threshold))` and similarly for
`m.keys.len`. For threshold = 17..20 this emits 0x61..0x64 which are
OP_NOP / OP_VER / OP_IF / OP_NOTIF — completely wrong instructions.
Threshold must be encoded with a minimal push for values > 16
(`<0x01 17>` = OP_PUSHBYTES_1 0x11). Same bug applies to keys.len:
`multi(2, key1, …, key17)` will emit a script whose "n" position
contains OP_NOP, which silently passes interpreter validation but
the OP_CHECKMULTISIG that follows then takes a wildly wrong number
of keys off the stack. **P0-CDIV**: this is a CONSENSUS-DIVERGENT
emit-side bug that can disagree with Core on any 17-of-20 multisig.

-------------------------------------------------------------------------------
Cross-reference of clearbit source-line citations
-------------------------------------------------------------------------------

descriptor.zig:
- 98-104, 107-116 — INPUT_CHARSET, polyMod
- 127-158, 161-181 — computeChecksum, verifyChecksum, addChecksum
- 188-225, 235-278 — KeyOrigin, KeyExpression
- 554-661 — parseDescriptor switch
- 663-700 — parseMulti
- 702-718 — parseTapTree
- 741-769 — parseOrigin
- 772-792 — parsePathComponent
- 794-863 — parseKeyExpression / parseExtendedKey
- 898-1036 — deriveScript switch
- 1351-1422 — writeDescriptor (toString)
- 1518-1530 — parseDescriptor (top-level)

miniscript.zig:
- 35-40, 43-98 — NodeType, TypeProperties, isValid (sanity checks)
- 144-183 — Fragment enum (no multi_a → 27 fragments, Core has 27 plus 4 desugarings)
- 186-241 — MiniNode + deinit
- 248-258 — computeType / toScript
- 265-551 — toScriptInner (script lowering)
- 580-615 — isValid, isValidTopLevel, isNonMalleable, needsSignature, checkTimeLocksMix
- 712-1073 — satisfyInner
- 1138-1517 — computeTypeForFragment
- 1520-1593 — computeWitnessSizeForFragment
- 1597-1729 — computeScriptSizeForFragment
- 1763-2005 — parser (parseExpr, wrappers, fragments)
- 2087-2110 — getFragment (note: `pk`/`pkh` aliases; clash with descriptor names)
- 2113-2136 — isHex, decodeHex, hexDigit
