# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (clearbit)

**Wave:** W161 — `ExtendedKey.fromSeed` (BIP-32 master key generation,
HMAC-SHA512(key="Bitcoin seed", msg=seed), IL/IR split, IL==0 / IL≥n
master-key reject), `ExtendedKey.deriveChild` (CKDpriv via
`secp256k1_ec_seckey_tweak_add`; CKDpub via `secp256k1_ec_pubkey_tweak_add`;
hardened format `0x00 || k || ser32(i)`; normal format
`serP(K) || ser32(i)`; parent-fingerprint = HASH160(parent_pubkey)[0:4];
chain_code = IR; BIP-32 mandated retry on IL≥n or k_i==0; nDepth ≤ 255
overflow guard; xprv/xpub 78-byte base58check encoding with version
prefix per network), `bip39.entropyToMnemonic` /
`bip39.mnemonicToEntropy` / `bip39.mnemonicToSeed` (PBKDF2-HMAC-SHA512
iter=2048, salt="mnemonic"||NFKD(passphrase), 12/15/18/21/24-word
mnemonics, ENT/32 checksum), `bip39.parseMnemonicString` and the
non-ASCII passphrase NFKD policy, `Wallet.initFromMnemonic` /
`Wallet.initFromSeed`, `WalletManager.createWallet` (the
`std.crypto.random.bytes(&seed)` path that BYPASSES the BIP-39 mnemonic
generation entirely), `Wallet.getnewaddress` HD-path selection
(`BIP-44 m/44'/coin'/0'/change/index` for P2PKH, `BIP-49 m/49'`,
`BIP-84 m/84'`, `BIP-86 m/86'`; BIP-43 `purpose'` hardened enforcement),
`getStandardPath` formatter, `derivePath` parser (`m/.../i'` and
`m/.../ih` syntax; index-range/overflow validation), version-byte
discipline (mainnet `0x0488B21E xpub` / `0x0488ADE4 xprv` /
testnet `0x043587CF tpub` / `0x04358394 tprv`; SLIP-132 `ypub/zpub/Ypub/Zpub`
for BIP-49/84 entirely absent), `descriptor.decodeExtendedKeyToPubkey`
(parses xpub/xprv/tpub/tprv but discards version byte and never
validates against active network), `WalletManager.serializeWallet` /
`deserializeWallet` (the on-disk JSON contract that ships the master
private key in PLAINTEXT regardless of `encrypted=true`), the absent
`importmnemonic` / `sethdseed` / `gethdkeys` / `listdescriptors` /
`importdescriptors` (refused) / `importprivkey` / `importaddress` /
`importpubkey` / `dumpwallet` / `importwallet` / `backupwallet` /
`restorewallet` / `rescanblockchain` / `getrawchangeaddress` RPC
surfaces; `getaddressinfo` / `getwalletinfo` absent
`hdseedid` / `hdmasterfingerprint` / `hdkeypath` fields; the
keypool / gap-limit total absence (W111 BUG-5 carry-forward); memory
hygiene for `master_key.key` / `chain_code` / `seed[64]` / HMAC
output buffers.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**

- `bitcoin-core/src/key.cpp:293-310 CKey::Derive` — CKDpriv. For
  hardened (`nChild >> 31`), `BIP32Hash(cc, nChild, 0, k, vout)` (prefix
  byte `0x00`). For normal, `BIP32Hash(cc, nChild, *pubkey.begin(),
  pubkey.begin()+1, vout)` (serP(K) prefix). Sets `keyChild = Add(IL)`;
  on `secp256k1_ec_seckey_tweak_add != 1` (the IL≥n OR k_i==0 path)
  returns `false` AND calls `keyChild.ClearKeyData()`. The
  `[[nodiscard]]` attribute (`key.h:177`) forces every caller to handle
  the retry. Callers in `descriptor.cpp::BIP32PubkeyProvider` retry
  with `++_nChild` per BIP-32 §"Private parent key → private child key"
  final paragraph.
- `bitcoin-core/src/key.cpp:482-489 CExtKey::Derive` — wraps `CKey::Derive`;
  also `if (nDepth == std::numeric_limits<unsigned char>::max()) return
  false;` (the BIP-32 §"Specification: Wallet structure" mandated
  depth-255 overflow guard at line 483).
- `bitcoin-core/src/key.cpp:491-501 CExtKey::SetSeed` —
  `HMAC-SHA512(key="Bitcoin seed", msg=seed)` master generation,
  `key.Set(vout.data(), vout.data()+32, true)` (32-byte private key,
  compressed flag), `chaincode = vout[32:64]`, `nDepth=0`, `nChild=0`,
  `vchFingerprint=0`. Note: `key.Set` internally calls
  `secp256k1_ec_seckey_verify` (key.cpp:154-164) which DOES check
  IL == 0 AND IL ≥ n; the `keydata` allocator is only populated on
  success. Master-from-seed silently produces an INVALID `CExtKey`
  whose `IsValid() == false` rather than retrying with the next seed
  — but this is acceptable per BIP-32 because the probability is
  cryptographically negligible.
- `bitcoin-core/src/key.cpp:513-521 CExtKey::Encode` — 78-byte payload:
  `nDepth(1) || vchFingerprint(4) || nChild_BE(4) || chaincode(32) ||
  0x00 || key(32)`. Then `EncodeBase58Check(version(4) || payload(74))`.
- `bitcoin-core/src/pubkey.cpp:341-363 CPubKey::Derive` — CKDpub via
  `secp256k1_ec_pubkey_parse` + `secp256k1_ec_pubkey_tweak_add`. Returns
  false on tweak failure (the IL≥n / pubkey-at-infinity path).
- `bitcoin-core/src/pubkey.cpp:415-421 CExtPubKey::Derive` — depth-255
  overflow guard mirrored.
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp` — `LegacyDataSPKM` /
  `DescriptorScriptPubKeyMan`; `TopUpChain` / `TopUp` (KEYPOOL_SIZE
  default 1000; `keypoolrefill` RPC; gap-limit enforcement at
  `DescriptorScriptPubKeyMan::TopUp` checks
  `range_end - max(m_max_cached_index + 1, m_keypool_size)`).
  `GetActiveScriptPubKeyMans()` per output type. `SetHDSeed` /
  `GenerateNewSeed` (BIP-32 master key persistence with AES-256-CBC
  encryption when wallet is locked; see `WalletDescriptor::ToString`
  for xprv→xpub neutering on serialisation).
- `bitcoin-core/src/script/descriptor.cpp` — descriptor key origin
  `[fingerprint/path]xpub/xprv` parsing; version-byte → network map at
  `Base58Prefix(CChainParams::EXT_PUBLIC_KEY)`; SLIP-132 `ypub`/`zpub`/
  `Ypub`/`Zpub`/`upub`/`vpub` are NOT supported by Core (descriptors
  use `wpkh(xpub)` / `wsh(xpub)` / `sh(wpkh(xpub))` / `tr(xpub)` to
  express the same semantics); the version byte is parsed AND
  validated against `Params().Base58Prefix(EXT_PUBLIC_KEY|EXT_SECRET_KEY)`
  in `ParseExtKey` (descriptor.cpp ~1820).
- `bitcoin-core/src/script/descriptor.cpp:380-410 BIP32PubkeyProvider::GetDerivation`
  — the canonical `pubkey.Derive` retry loop. **Throws
  `KeyTypeError("hardened from xpub")`** on hardened-from-pubkey ask;
  for the non-hardened path retries `++_nChild` if Derive returns
  false; bounded by `MAX_HARDENED_DERIVATION_RETRIES` (effectively
  unbounded because the probability of failure per index is 2^-128).
- `bitcoin-core/src/key.cpp:154-164 CKey::Set` — `secp256k1_ec_seckey_verify`
  is THE place IL≥n and IL==0 are enforced (returns false → `keydata`
  is never populated → `IsValid()=false`).
- `bitcoin-core/src/chainparams.cpp::CMainParams ctor` — sets
  `base58Prefixes[EXT_PUBLIC_KEY]={0x04, 0x88, 0xB2, 0x1E}` (xpub),
  `[EXT_SECRET_KEY]={0x04, 0x88, 0xAD, 0xE4}` (xprv). Testnet:
  `{0x04, 0x35, 0x87, 0xCF}` (tpub), `{0x04, 0x35, 0x83, 0x94}` (tprv).
  Signet uses testnet prefixes. Regtest uses testnet prefixes.
- `bitcoin-core/src/wallet/wallet.cpp::CWallet::EncryptWallet` — encrypts
  ALL `CKey` and `CExtKey` material via `EncryptSecret`; the master
  HD seed (CExtKey) is wrapped EXACTLY like a normal CKey. The
  on-disk wallet.dat NEVER contains plaintext key bytes after
  `encryptwallet` succeeds. AES-256-CBC with per-key IV; master key
  derivation via `BytesToKeySHA512AES`.
- `bitcoin-core/src/wallet/rpc/wallet.cpp::getwalletinfo` — emits
  `hdseedid` (BIP-32 master fingerprint, 4 bytes hex). For descriptor
  wallets, `gethdkeys` lists per-descriptor xpubs.
- `bitcoin-core/src/wallet/rpc/addresses.cpp::getaddressinfo` — emits
  `hdkeypath` (e.g. `m/84h/0h/0h/0/0`), `hdseedid`,
  `hdmasterfingerprint` (4 bytes hex of the master xpub's hash160).
- BIP-32 (`https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki`):
  - §"Master key generation": "In case IL is 0 or ≥n, the master key is
    invalid."
  - §"Private parent key → private child key": "In case parse256(IL) ≥ n
    or k_i = 0, the resulting key is invalid, and one should proceed
    with the next value for i."
  - §"Public parent key → public child key": "In case parse256(IL) ≥ n
    or K_i is the point at infinity, the resulting key is invalid, and
    one should proceed with the next value for i."
  - §"Specification: Wallet structure": "depth ... maximum 255".
  - §"Serialization format": 78 bytes — 4 version + 1 depth + 4
    fingerprint + 4 child + 32 chaincode + 33 keydata.
- BIP-39 (`https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki`):
  - "ENT must be a multiple of 32 and within the range 128-256" — i.e.
    {128, 160, 192, 224, 256} bits.
  - Salt: `"mnemonic" || NFKD(passphrase)`.
  - PBKDF2-HMAC-SHA512, iter=2048, dkLen=64.
  - NFKD normalisation MANDATED for both mnemonic and passphrase.
- BIP-43 (`https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki`):
  "`purpose'` MUST be hardened".
- BIP-44 / BIP-49 / BIP-84 / BIP-86: `m/purpose'/coin_type'/account'/change/address_index`,
  with `purpose ∈ {44, 49, 84, 86}` and `coin_type` from SLIP-44
  (mainnet=0, testnet/signet/regtest=1).
- BIP-86: TapTweak commits to **empty** merkle root —
  `tagged_hash("TapTweak", internal_xonly)` (no second argument).

**Files audited**

- `src/bip39.zig:34 BIP39_WORDLIST_BLOB` (`@embedFile("../resources/bip39-english.txt")`),
  `parseWordlist` (comptime parse, 50k branch quota).
- `src/bip39.zig:142-184 entropyToMnemonic` — ENT/32 checksum, MSB-first
  bit-packing into 11-bit chunks.
- `src/bip39.zig:195-238 mnemonicToEntropy` — inverse + checksum
  validation; the linear-scan `wordIndex` at line 117-124 (O(2048)
  per word, O(N·2048) per mnemonic).
- `src/bip39.zig:242-248 validateMnemonic` — wraps
  `mnemonicToEntropy` and frees the buffer.
- `src/bip39.zig:265-306 mnemonicToSeed` — joins on `' '`, salt
  `"mnemonic"||passphrase`, `std.crypto.pwhash.pbkdf2(..., 2048, HmacSha512)`,
  rejects non-ASCII passphrase with
  `error.NonAsciiPassphraseRequiresNfkd`.
- `src/bip39.zig:336-345 parseMnemonic` (re-exported as
  `parseMnemonicString`) — tokenises on `' '`, validates each word
  exists in the wordlist.
- `src/wallet.zig:619-624 DerivationPurpose` enum (bip44=44, bip49=49,
  bip84=84, bip86=86).
- `src/wallet.zig:627-789 ExtendedKey` struct + methods:
  - `:644-666 fromSeed` (HMAC, IL==0 check ONLY, IL≥n check ABSENT;
    seed.len range [16,64]).
  - `:670-743 deriveChild` (CKDpriv via `secp256k1_ec_seckey_tweak_add`;
    public-side branch at :701 returns `error.NotImplemented`; depth+1
    at :738 with no overflow guard; parent-fingerprint compute at
    :718-733).
  - `:746-770 derivePath` (lowercase `h` ONLY, no `H`; `parseInt(u32, ...)`
    accepts `2147483648` which silently collides with the hardened
    counterpart of index 0).
  - `:773-788 getStandardPath` (`"m/{d}'/{d}'/{d}'/{d}/{d}"`).
- `src/wallet.zig:823-944 Wallet` struct, `init`, `initFromSeed` (:889),
  `initFromMnemonic` (:904); deinit zeroizes `encryption_key` but NOT
  `master_key.key` / `chain_code`.
- `src/wallet.zig:1015-1072 getnewaddress` — purpose-from-address-type
  map (p2wsh maps to BIP-84 — questionable), account hardcoded to 0,
  `derivePath` once per call (no keypool, no cached derivations).
- `src/wallet.zig:2106-2153 encryptWallet` — encrypts `keys.items[*].secret_key`
  ONLY, NEVER touches `master_key.key` or `master_key.chain_code`.
- `src/wallet.zig:3080-3092 bip86Tweak` (already W160 BUG-9 — cross-cite).
- `src/wallet.zig:3612-3621 WalletManager.createWallet` — DIRECT RNG seed
  generation, BYPASSES the BIP-39 mnemonic flow entirely (no mnemonic
  is ever shown to the user, no mnemonic is persisted to disk).
- `src/wallet.zig:3823-3858 saveWalletInternal` — JSON wallet.dat
  write; atomic temp+rename.
- `src/wallet.zig:3890-4023 serializeWallet` — emits `master_key`
  (32-byte private key) AND `chain_code` (32 bytes) in PLAINTEXT HEX,
  UNCONDITIONALLY (comment claims gated on `encrypted=false` but code
  is not — BUG-5).
- `src/wallet.zig:4025-4126 deserializeWallet` — reads plaintext master
  key and chain code back into memory; on-disk shape symmetric with
  `serializeWallet`.
- `src/descriptor.zig:243-273 KeyExpression` variants (`xpub`,
  `xprv`); `:824-863 parseExtendedKey` (accepts ONLY `xpub|xprv|tpub|tprv`
  4-byte prefix; no `ypub|zpub|Ypub|Zpub|upub|vpub` SLIP-132); `:1116-1272
  decodeExtendedKeyToPubkey` (decodes base58check, **discards version
  byte**, walks path and the wildcard index).
- `src/rpc.zig:5397-5429 handleGetAddressInfo` — emits `address` and
  optional `label`; **NO** `hdkeypath`, `hdseedid`, `hdmasterfingerprint`,
  `scriptPubKey`, `solvable`, `iswatchonly`, etc.
- `src/rpc.zig:5431-5474 handleGetWalletInfo` — emits `balance`,
  `unconfirmed_balance`, `immature_balance`, `txcount`,
  `keypoolsize`, `unlocked_until`; **NO** `hdseedid`,
  `hdmasterkeyid`, `walletversion`, `format`, `descriptors`,
  `private_keys_enabled`. **`txcount` is `wallet.keys.items.len`**
  (NOT transaction count), **`keypoolsize` is `wallet.keys.items.len`**
  (NOT keypool, because there is no keypool).
- `src/rpc.zig:10622-10661 handleGetNewAddress` — accepts param[1]
  (address type), IGNORES param[0] (label). Default `.p2wpkh`.
- `src/rpc.zig:12389-12409 handleImportDescriptors` — refused with
  `RPC_WALLET_ERROR -4`. The fix was deliberate "honest gate" per
  the comment block — but operator has NO way to import an external
  descriptor.
- `src/rpc.zig` RPC dispatch (`:2949-3145+`) — `importprivkey`,
  `importpubkey`, `importaddress`, `importmulti`, `listdescriptors`,
  `gethdkeys`, `sethdseed`, `dumpwallet`, `importwallet`, `backupwallet`,
  `restorewallet`, `rescanblockchain`, `getrawchangeaddress`,
  `keypoolrefill` — ALL absent from the dispatch table.

---

## Gate matrix (30 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | BIP-39 mnemonic round-trip | G1: TREZOR vector 1 (all-zero entropy, 12 words) | PASS (`bip39.zig:376-408`) |
| 1 | … | G2: TREZOR vector 2 (0x7f entropy, 12 words) | PASS (`bip39.zig:410-438`) |
| 1 | … | G3: TREZOR vector 3 (0x80 entropy, 24 words) | PASS (`bip39.zig:440-472`) |
| 1 | … | G4: Invalid-checksum reject | PASS (`bip39.zig:474-491`) |
| 1 | … | G5: Unknown-word reject | PASS (`bip39.zig:493-507`) |
| 1 | … | G6: Non-ASCII passphrase reject (no NFKD) | PASS-by-policy (`bip39.zig:271, 522-534`) — **fail-closed; BIP-39 spec requires NFKD** |
| 2 | BIP-32 master key generation | G7: HMAC-SHA512(key="Bitcoin seed", msg=seed) | PASS (`wallet.zig:649`) |
| 2 | … | G8: IL == 0 reject | PASS (`wallet.zig:654-656`) |
| 2 | … | G9: IL ≥ n reject (BIP-32 §"Master key generation") | **BUG-1 (P1)** — `wallet.zig:654` checks `private_key == 0` ONLY. The `secp256k1_ec_seckey_verify(ctx, &private_key)` call that Core's `CKey::Set` makes (key.cpp:154-164) is NOT done. Probability is 2^-128 per seed, but spec compliance gap and the comment at :653 **lies about what's checked** ("non-zero AND less than curve order") |
| 2 | … | G10: Seed length validation | PARTIAL (`wallet.zig:645-647` accepts `[16, 64]`); spec accepts any in that range, but does not match the canonical {16, 32, 64} BIP-39 outputs and accepts `17, 23, ...` |
| 3 | BIP-32 CKDpriv | G11: hardened format `0x00 || k || ser32(i)` BE | PASS (`wallet.zig:679-682, 706`) |
| 3 | … | G12: normal format `serP(K) || ser32(i)` BE | PASS (`wallet.zig:685-700, 706`) |
| 3 | … | G13: retry on IL≥n / k_i==0 per BIP-32 §"Private parent key → private child key" | **BUG-2 (P1, 2-wave open: W160 BUG-7 → W161 BUG-2)** — `wallet.zig:712-716` returns `error.InvalidChildKey`; caller in `derivePath` propagates → user-facing error; no `++index` retry. The W160 audit catalogued this; W161 confirms still present |
| 3 | … | G14: depth ≤ 255 overflow guard | **BUG-3 (P0-CDIV)** — `wallet.zig:738 self.depth + 1` with `depth: u8` overflows at d=256. In Release modes Zig wraps to 0; in Debug/Safe modes panics. Core: `CExtKey::Derive` line 483 explicit guard. clearbit has NO guard — a deep crafted PSBT-import path (or recursive `derivePath`) at depth 256 crashes the node OR (worse) wraps depth=0 and re-derives the master key's children with a corrupted fingerprint chain |
| 4 | BIP-32 CKDpub (public-side derivation) | G15: x-only / compressed pubkey input | **BUG-4 (P0-CDIV)** — `ExtendedKey.key: [32]u8` (`wallet.zig:628`) CANNOT hold a 33-byte compressed pubkey. The public-side branch at :701 returns `error.NotImplemented`. The `is_private: bool` flag exists but is structurally meaningless — the struct can only represent PRIVATE keys. xpub-only wallets (watch-only) are unrepresentable. Descriptor `xpub` parsing (`descriptor.zig:1116-1272`) uses a separate, parallel BIP-32 implementation — two-pipeline at the BIP-32 layer |
| 5 | BIP-32 parent fingerprint | G16: HASH160(parent_compressed_pubkey)[0:4] | PASS-for-priv (`wallet.zig:718-733`) |
| 5 | … | G17: fingerprint compute survives encrypted master key | **BUG-5 cross-cite** — works because master key is plaintext on disk |
| 6 | xprv/xpub 78-byte base58check encode | G18: encode round-trips Core's `xprv9s21ZrQH143K...` form | **BUG-6 (P0-CDIV)** — clearbit has NO `ExtendedKey.encode` / `serialize` function at all. The `master_key` is serialised to wallet.dat as **raw 32-byte hex + 32-byte chain-code hex** with no version-byte / no depth / no fingerprint / no child-index / no base58check. **xpub/xprv export is structurally impossible** — there is no `dumpwallet`, no `gethdkeys`, no `listdescriptors`. Users cannot back up their wallet to a Coldcard / Sparrow / Bitcoin Core / Electrum import path |
| 6 | … | G19: version byte per network (xpub/xprv mainnet, tpub/tprv testnet) | **BUG-7 (P0-CDIV)** — `descriptor.zig:1116-1272 decodeExtendedKeyToPubkey` discards the version byte (only checks payload length == 77 at :1125). A `tpub...` from testnet feeds the SAME derivation path as an `xpub...` from mainnet; the network-mismatch is silently accepted. Cross-network key reuse via descriptor import is undetected — operator can import a mainnet xpub into a regtest wallet and the wallet emits valid-looking addresses |
| 7 | BIP-39 seed → BIP-32 master (the full mnemonic-import flow) | G20: `initFromMnemonic` calls `validateMnemonic` then `mnemonicToSeed` then `initFromSeed` | PASS (`wallet.zig:904-917`) |
| 7 | … | G21: createwallet UI surfaces the mnemonic to the operator | **BUG-8 (P0-CDIV catastrophic UX)** — `WalletManager.createWallet` (`wallet.zig:3612-3621`) generates the BIP-32 seed via `std.crypto.random.bytes(&seed)` **DIRECTLY** — bypasses the BIP-39 mnemonic flow entirely. No mnemonic is ever produced, displayed, or persisted. Wallet recovery without the wallet.dat file is **IMPOSSIBLE**. The only recovery surface is the encrypted wallet.dat itself — same security model as Bitcoin Core pre-HD (Berkeley DB wallet.dat), worse than Bitcoin Core ≥0.13 (which surfaces 24-word seed via dumpwallet). Compare to lunarblock W155 funds-burn pattern in severity: this isn't funds-burn but funds are unrecoverable if the AES-256-GCM wallet.dat is lost |
| 8 | BIP-44/49/84/86 paths | G22: BIP-44 P2PKH path `m/44'/coin'/0'/change/index` | PASS (`wallet.zig:1031-1053`) |
| 8 | … | G23: BIP-49 P2SH-P2WPKH path | PASS (`wallet.zig:1033, 1053`) |
| 8 | … | G24: BIP-84 P2WPKH path | PASS (`wallet.zig:1034, 1053`) |
| 8 | … | G25: BIP-86 P2TR path | PASS (`wallet.zig:1035, 1053`) |
| 8 | … | G26: P2WSH purpose mapping | **BUG-9 (P1)** — `wallet.zig:1036` maps `.p2wsh => .bip84`. P2WSH has NO canonical BIP-43 purpose; the wallet derives a single-key, then unconditionally hashes that to scriptPubKey — but P2WSH is a script (e.g. multisig), the derived key isn't the witness program. Cross-cite: `wallet.zig:1199-1201 getAddress(.p2wsh)` returns `error.NotImplemented`. So the `.p2wsh` purpose mapping path is dead code that allocates a key, fails on address, leaks the key |
| 9 | derivePath parser | G27: `m/44'/0'/0'/0/0` accepted; lowercase `'` hardened | PASS (`wallet.zig:760`) |
| 9 | … | G28: `H` uppercase hardened marker accepted | **BUG-10 (P1)** — `wallet.zig:760` checks `endsWith(..., "'")` OR `endsWith(..., "h")` (lowercase ONLY). BIP-32 spec accepts both `h` and `H`; Core's `descriptor.cpp::ParseKeyPath` accepts `'`, `h`, AND `H`. clearbit silently rejects user-pasted `m/84H/0H/0H/0/0` paths with `error.InvalidDerivationPath` |
| 9 | … | G29: index range `[0, 2^31)` for non-hardened components | **BUG-11 (P0-CDIV)** — `wallet.zig:763 parseInt(u32, num_str, 10)` accepts `2147483648` (= `0x80000000`). On the un-hardened branch (no trailing `'`/`h`), `full_index = 0x80000000` which **silently has the hardened bit set**. So `m/2147483648` and `m/0'` and `m/0h` all derive the SAME key. Worse, an attacker-crafted descriptor `tr(xpub.../0'/2147483648/0)` slices a hardened child off an xpub (which should fail outright because hardened-from-pubkey is impossible) without raising the canonical `CannotDeriveHardenedFromPublic` error. Cross-cite W148 fleet pattern "silent index normalisation" |
| 9 | … | G30: empty path component skipped | PASS-by-accident (`wallet.zig:758`) |
| 10 | Wallet persistence | G31: master_key encrypted at rest when wallet is encrypted | **BUG-5 (P0-SEC catastrophic)** — `serializeWallet` (`wallet.zig:3919-3930`) writes `master_key.key` (32-byte private key) and `master_key.chain_code` (32 bytes) in PLAINTEXT HEX in wallet.dat REGARDLESS of `wallet.encrypted`. `encryptWallet` (`wallet.zig:2106-2153`) iterates `self.keys.items[*].secret_key` ONLY — `master_key` is never touched. The wallet.dat for an encrypted wallet contains: encrypted child keys (AES-256-GCM with random nonce + scrypt-derived key) AND **plaintext master key** that derives ALL child keys including the encrypted ones. Filesystem-level attacker (chrooted backup, accidental rsync, leaked Docker volume, SD card sale) recovers ALL funds without breaking the AES. The comment at :3918 LIES: "if present and wallet is not encrypted, or encrypted master key" — code is unconditional. **comment-as-confession 14th distinct clearbit instance** |
| 11 | RPC surface — HD-discovery / recovery | G32: `getwalletinfo.hdseedid` / `hdmasterkeyid` | **BUG-12 (P1)** — `rpc.zig:5446-5466` emits no HD field at all. `keypoolsize` is reported as `wallet.keys.items.len` (which is NOT the keypool — there is no keypool). `txcount` is also `wallet.keys.items.len`. Two distinct `getwalletinfo` fields that mean entirely different things in Core both report the same wallet-internal counter. **Pattern: advertisement-as-lie (5th distinct clearbit instance after hotbuns W155, W156)** |
| 11 | … | G33: `getaddressinfo.hdkeypath` / `hdseedid` / `hdmasterfingerprint` | **BUG-13 (P1)** — `rpc.zig:5397-5429` emits ONLY `address` and `label`. A Sparrow/Electrum user importing an HD wallet from clearbit cannot reconstruct the derivation path for any address |
| 11 | … | G34: `importmnemonic` / `sethdseed` / `gethdkeys` / `listdescriptors` / `importdescriptors` (active) / `importprivkey` / `importpubkey` / `importaddress` / `importmulti` / `dumpwallet` / `importwallet` / `backupwallet` / `restorewallet` / `rescanblockchain` / `getrawchangeaddress` / `keypoolrefill` | **BUG-14 (P0-CDIV)** — 16 RPC methods entirely absent from the dispatch table (`rpc.zig:2949-3145+`). `importdescriptors` is present but refuses with `RPC_WALLET_ERROR`. The wallet is effectively a **read-only-once** surface — operator can `createwallet` and `getnewaddress` and `sendtoaddress`, but cannot back up to a mnemonic, import a key from cold storage, restore from another wallet, or rescan after import. Cross-cite **5-CONSECUTIVE-QUAD "wiring-look-but-no-wire" fleet pattern** |
| 12 | Keypool / gap-limit | G35: KEYPOOL_SIZE=1000 pre-generation | **BUG-15 (P1, W111 BUG-5 carry-forward, 50+ days open)** — `wallet.zig` has no `keypool`/`gap_limit` concept at all. The wallet increments `next_external_index`/`next_change_index` on demand. A wallet restored from mnemonic (which is also impossible per BUG-8) would start at index 0 and miss all in-use addresses |

---

## BUG-1 (P1) — Master-key IL≥n check absent; comment lies

**Severity:** P1. BIP-32 §"Master key generation" mandates two
rejection cases: IL == 0 OR IL ≥ n (the secp256k1 curve order). clearbit
checks ONLY the IL == 0 case:

```zig
// Verify the key is valid (non-zero and less than curve order)
if (std.mem.eql(u8, &private_key, &[_]u8{0} ** 32)) {
    return error.InvalidMasterKey;
}
```

The comment claims the check covers both — it does not. The IL ≥ n
case is not enforceable from raw bytes (you'd need to compare against
the curve order `n` constant), but `secp256k1_ec_seckey_verify` does
exactly this and is the canonical Core idiom (`bitcoin-core/src/key.cpp:154-164
CKey::Set` calls it). Probability of a 256-bit HMAC output exceeding
`n` is `(2^256 - n) / 2^256 ≈ 2^-128` — cryptographically negligible —
but the spec-compliance gap is real and the comment is misleading.

**File:** `src/wallet.zig:644-666 ExtendedKey.fromSeed`.

**Core ref:** `bitcoin-core/src/key.cpp:154-164 CKey::Set` →
`secp256k1_ec_seckey_verify`.

**Impact:** spec-conformance gap; comment-as-confession (15th distinct
clearbit instance — see BUG-5 for 14th).

---

## BUG-2 (P1, 2-wave open) — BIP-32 derivation does NOT retry on `IL ≥ n` / `child = 0`

**Severity:** P1. **Carry-forward from W160 BUG-7 (catalogued
2026-05-18, no fix attempted)**. BIP-32 §"Private parent key →
private child key" final paragraph: "In case parse256(IL) ≥ n or k_i
= 0, the resulting key is invalid, and one should proceed with the
next value for i."

clearbit's `deriveChild` returns `error.InvalidChildKey` instead of
retrying with `index + 1`:

```zig
if (secp256k1.secp256k1_ec_seckey_tweak_add(ctx, &child_key, il) != 1) {
    return error.InvalidChildKey;
}
```

Core's `CKey::Derive` returns `false` (not an error) and Core's
descriptor / wallet callers (`descriptor.cpp::BIP32PubkeyProvider::GetDerivation`)
retry the call with `++_nChild`. clearbit's `derivePath` (line 766) has no
retry — it propagates the error.

**File:** `src/wallet.zig:712-716`.

**Core ref:** BIP-32 §"Private parent key → private child key";
`bitcoin-core/src/script/descriptor.cpp::BIP32PubkeyProvider::GetDerivation`.

**Impact:** spec-conformance gap; probability ~2^-128 per call so
negligible in practice. **2-wave-open carry-forward — third 2-wave
open BIP-32 / signing gap (BUG-1 Schnorr aux_rand, BUG-13 sign-then-
verify paranoia, this BIP-32 retry).**

---

## BUG-3 (P0-CDIV) — Depth-255 overflow guard absent

**Severity:** P0-CDIV. BIP-32 §"Specification: Wallet structure"
constrains depth to `[0, 255]` (one unsigned byte). Core enforces
this at `bitcoin-core/src/key.cpp:483`:

```cpp
bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
    // ...
}
```

clearbit has NO depth guard at all:

```zig
return ExtendedKey{
    .key = child_key,
    .chain_code = ir,
    .depth = self.depth + 1, // ← wraps on overflow
    // ...
};
```

`self.depth + 1` where `depth: u8` and `self.depth == 255`:
- Zig Release mode: wraps to 0 (silent corruption).
- Zig Debug/Safe mode: integer-overflow panic → process crash.

Attack surface: an attacker-crafted descriptor like
`tr(xpub.../0/0/0/.../0)` with 256+ path components, fed to
`descriptor.zig:1116-1272 decodeExtendedKeyToPubkey`, exercises this
path. Today this path is bounded by the descriptor parser's
`std.ArrayList(u32)` capacity (essentially unbounded), so a 300-byte
descriptor literal can crash the daemon. In Release mode, the result
is worse: depth wraps to 0 and the fingerprint chain becomes corrupted
without any error signal — a watch-only descriptor import silently
binds to a different key than the user expected.

**File:** `src/wallet.zig:738 self.depth + 1`; symmetric gap in
`descriptor.zig:1116-1272` (no depth tracking AT ALL — the descriptor
path walker doesn't propagate a depth counter, so the guard couldn't
fire even if it existed).

**Core ref:** `bitcoin-core/src/key.cpp:483, src/pubkey.cpp:417`.

**Impact:**
- Debug/Safe: remote DoS via descriptor import / PSBT BIP32_DERIVATION
  with a 256-deep path.
- Release: silent fingerprint-chain corruption on deep paths;
  watch-only descriptors bind to wrong keys.
- New fleet pattern instance: **"missing-overflow-guard at a
  spec-mandated boundary"** — first BIP-32 instance.

---

## BUG-4 (P0-CDIV) — Public-key (xpub) derivation is architecturally impossible

**Severity:** P0-CDIV. `ExtendedKey.key` is `[32]u8` (`wallet.zig:628`).
A BIP-32 extended PUBLIC key holds a 33-byte compressed pubkey in
this slot per the spec. clearbit's struct **cannot store one**. The
runtime check at `wallet.zig:701`:

```zig
if (self.is_private) {
    // Get public key from private
    // ...
} else {
    return error.NotImplemented; // Public key derivation
}
```

means every public-side `deriveChild` call errors out at construction.
Combined with BUG-6 (no xpub serialisation), watch-only HD wallets are
**structurally unrepresentable** in clearbit's primary HD code path.

Worse, this forced a **second, parallel BIP-32 implementation** in
`descriptor.zig:1116-1272 decodeExtendedKeyToPubkey`, which is a
complete reimplementation of CKDpriv AND CKDpub (the descriptor path
uses 33-byte pubkey storage via raw `[33]u8 current_pubkey` locals).
**Two-pipeline at the BIP-32 derivation layer** — they will drift,
and they already do (see BUG-7: descriptor.zig discards the version
byte; wallet.zig has no encode at all).

**File:** `src/wallet.zig:627-633 ExtendedKey struct definition`
(the field width is the architectural root cause).

**Core ref:** `bitcoin-core/src/pubkey.h:294-374 CExtPubKey` (the
dedicated "extended public key" type with its own 33-byte pubkey
slot).

**Impact:**
- Watch-only HD wallets impossible from the wallet-side path.
- Cosigner workflows (BIP-174 PSBT with `bip32_derivation` against an
  xpub) impossible from the wallet-side path.
- Two-pipeline maintenance burden at the BIP-32 layer.
- **NEW PATTERN: "type-width-too-narrow-for-spec"** — first fleet
  instance. The struct field width itself rules out a spec-required
  representation.

---

## BUG-5 (P0-SEC catastrophic) — Master private key serialised to wallet.dat in PLAINTEXT regardless of `encrypted=true`

**Severity:** P0-SEC. The most-severe finding this wave. clearbit's
`saveWalletInternal` serialises `wallet.master_key.key` (the 32-byte
BIP-32 master private key) and `wallet.master_key.chain_code` (32 bytes,
also a secret per BIP-32 §"Public derivation") to disk as **plaintext
hex** in the wallet.dat JSON. The block is gated on
`if (wallet.master_key) |master_key|` — the `wallet.encrypted` flag is
NOT consulted:

```zig
// Master key (if present and wallet is not encrypted, or encrypted master key)
if (wallet.master_key) |master_key| {
    try json.appendSlice("\"master_key\":\"");
    var hex_buf: [128]u8 = undefined;
    const key_hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&master_key.key)}) catch return error.SerializationFailed;
    try json.appendSlice(key_hex);
    try json.appendSlice("\",");

    try json.appendSlice("\"chain_code\":\"");
    const cc_hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&master_key.chain_code)}) catch return error.SerializationFailed;
    try json.appendSlice(cc_hex);
    try json.appendSlice("\",");
}
```

The comment **lies** about what the code does — it claims "if present
and wallet is not encrypted, or encrypted master key" but the
implementation is unconditional. **comment-as-confession 14th distinct
clearbit instance** (after W160 BUG-3/5/9/19; W155; W152; W150).

`encryptWallet` (`wallet.zig:2106-2153`) iterates `keys.items[*].secret_key`
ONLY:

```zig
// Encrypt all private keys in place using AES-256-GCM.
// Each key gets a unique random nonce; the auth tag is stored alongside.
for (self.keys.items) |*keypair| {
    const enc = encryptPrivateKey(&derived_key, &keypair.secret_key);
    // ...
}
```

The `master_key` field is NEVER touched.

Concrete attack:
1. Operator creates a wallet, sets a passphrase via `encryptwallet`.
2. Filesystem-level attacker (chrooted backup tool, accidental
   `rsync -a wallet_dir/`, leaked Docker volume, sold SSD/SD-card,
   leaked cloud-snapshot) reads `wallet.dat`.
3. JSON parse → `master_key` field → hex-decode → 32-byte master priv
   key in attacker's hands.
4. From master priv + chain_code, attacker derives ALL child keys at
   ALL BIP-44/49/84/86 paths and steals ALL funds.

The AES-256-GCM child-key encryption is **purely cosmetic** — the
master key is the seed of EVERY child key, so plaintext master
trivially derives every plaintext child.

**File:**
- `src/wallet.zig:3918-3930 serializeWallet` (the leak).
- `src/wallet.zig:2106-2153 encryptWallet` (the missing branch).
- `src/wallet.zig:4062-4081 deserializeWallet` (symmetric read).

**Core ref:** `bitcoin-core/src/wallet/wallet.cpp::CWallet::EncryptWallet`
— ALL key material (including HD master `CExtKey`) is encrypted via
`EncryptSecret` BEFORE wallet.dat write. Plaintext is unreachable
on disk.

**Impact:**
- **Filesystem-level wallet.dat compromise = total funds loss for ALL
  derived addresses**, even with `encryptwallet` set.
- Operator UX promise of "my wallet is encrypted, the passphrase is
  what protects me" is FALSE.
- **comment-as-confession 14th distinct clearbit instance**.
- **NEW PATTERN: "encrypt-the-children-not-the-parent"** —
  defense-in-depth applied to LEAVES but not to the ROOT of the key
  tree. The fix is single-digit-LOC (wire master_key.key /
  chain_code through `encryptPrivateKey` in `encryptWallet`, store
  ciphertext+nonce+tag in the JSON) but the architectural omission is
  structural — the JSON shape doesn't have a slot for the master
  ciphertext / nonce / tag.

---

## BUG-6 (P0-CDIV) — xpub/xprv 78-byte base58check encoding entirely absent

**Severity:** P0-CDIV. The BIP-32 §"Serialization format" specifies a
78-byte payload (4 version || 1 depth || 4 fingerprint || 4 child ||
32 chaincode || 33 keydata) base58check-encoded. This is THE canonical
interoperability format for extended keys — every wallet (Bitcoin
Core, Sparrow, Electrum, Coldcard, BlueWallet, etc.) imports and
exports xpub / xprv / tpub / tprv strings.

clearbit has NO encoder. `ExtendedKey` has no `encode`, `serialize`,
`toXprv`, `toXpub`, `toBase58` method. The struct is stored to
wallet.dat as raw `master_key` (32-byte hex) + `chain_code` (32-byte
hex). No version byte → no network distinction. No depth → no fingerprint
chain. No child index → no derivation context.

Concrete consequences:
- **Backup to Sparrow / Electrum / Coldcard impossible** — those tools
  import via xpub / xprv string.
- **Cosigner setup impossible** — multisig descriptors take xpubs.
- **HWW (hardware wallet) integration impossible** — HWWs expect to be
  given a derivation prefix and an xpub for the watching wallet.
- **`dumpwallet` impossible** — Core's `dumpwallet` emits descriptor
  expressions like `wpkh([fp/84h/0h/0h]xprv...)#...checksum`. clearbit
  has no way to construct that string.

This is the **structural reason** that BUG-14 (16 missing RPC
methods) exists — without xprv/xpub encoding, none of the
export/import RPCs can be implemented even in principle.

**File:** `src/wallet.zig:627-789 ExtendedKey` (no encode method);
absent infrastructure throughout `src/rpc.zig`.

**Core ref:** `bitcoin-core/src/key.cpp:513-521 CExtKey::Encode`,
`bitcoin-core/src/base58.cpp::EncodeBase58Check`,
`bitcoin-core/src/chainparams.cpp` Base58Prefix tables.

**Impact:**
- Operator cannot migrate a wallet off clearbit.
- Operator cannot create a watch-only multisig.
- Operator cannot integrate with hardware wallets.
- Cross-impl divergence — every other fleet impl with HD support has
  xpub export (ouroboros via `python-bip32`, rustoshi via `bdk`,
  blockbrew via `btcsuite/btcutil/hdkeychain`, haskoin via
  `haskoin-core`, etc.).

---

## BUG-7 (P0-CDIV) — `decodeExtendedKeyToPubkey` discards version byte; no network gate

**Severity:** P0-CDIV. `descriptor.zig:1116-1272 decodeExtendedKeyToPubkey`
calls `address.base58CheckDecode(key_str, allocator)` which returns
`{ version: u8, data: []const u8 }`. clearbit reads ONLY `decoded.data`
and ignores `decoded.version`:

```zig
const decoded = address.base58CheckDecode(key_str, allocator) catch return error.InvalidKeyExpression;
defer allocator.free(decoded.data);
// `decoded.version` is never inspected.

// Extended key format: 4 bytes version + 1 byte depth + ...
// Total: 78 bytes payload (version already stripped by base58CheckDecode)
if (decoded.data.len != 77) {
    return error.InvalidKeyExpression;
}
```

Worse, `base58CheckDecode` only returns the **first byte** of the
version (it's typed as `u8`):

```zig
const version = payload[0];
const data = try allocator.dupe(u8, payload[1..]);
return .{ .version = version, .data = data };
```

A BIP-32 extended key has a **4-byte** version prefix
(`0x04 0x88 0xB2 0x1E` for xpub mainnet). `base58CheckDecode` strips
1 byte as the version; the remaining 3 version bytes leak into
`decoded.data`. So `data.len = 77 = 3 version + 1 depth + 4 fp + 4
child + 32 chaincode + 33 keydata`. The CKDpriv parse at
`descriptor.zig:1135-1138` reads `depth = decoded.data[0]` (but
that's actually `version[1]` = `0x88`) and `chain_code = data[9..41]`
(actually offset by 3 — `version[3] || depth || fp[0..2]` overlap).

**Two compounding bugs:**
1. The `base58CheckDecode` is structurally wrong for extended keys
   (expects 1-byte version, BIP-32 has 4-byte).
2. Even if (1) were fixed, the version byte is never compared against
   the active network's expected prefix. xpub-on-regtest, tpub-on-mainnet,
   are accepted silently.

This means `decodeExtendedKeyToPubkey` **derives wrong keys** from
any real-world xpub / xprv string. Tests presumably only exercise
synthetic strings constructed by clearbit's own (absent) encoder, so
they don't catch the misalignment.

**File:**
- `src/descriptor.zig:1119-1138 decodeExtendedKeyToPubkey` (misaligned
  parse).
- `src/address.zig:181-206 base58CheckDecode` (assumes 1-byte version;
  no support for multi-byte versions).

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeExtKey` /
`DecodeExtPubKey` — explicit 4-byte version byte parse + comparison
against `Params().Base58Prefix(EXT_SECRET_KEY)` /
`EXT_PUBLIC_KEY`.

**Impact:**
- Every real-world xpub/xprv/tpub/tprv import via `decodeExtendedKeyToPubkey`
  derives the wrong child key (misaligned chain_code / keydata fields).
- Network mismatch (mainnet xpub on regtest) silently accepted.
- Descriptor `wpkh(xpub.../0/*)` ranged-derivation produces addresses
  that don't match what any other Bitcoin tool would derive for the
  same xpub.
- **NEW PATTERN: "parser-misaligned-by-truncated-version-byte"** —
  combining a generic base58check decoder with a multi-byte-versioned
  format.

---

## BUG-8 (P0-CDIV catastrophic UX) — `createwallet` bypasses BIP-39 mnemonic entirely; no recovery path without wallet.dat

**Severity:** P0-CDIV. `WalletManager.createWallet` (`wallet.zig:3612-3621`)
generates the BIP-32 seed via `std.crypto.random.bytes(&seed)` DIRECTLY:

```zig
if (options.blank) {
    wallet.* = try Wallet.init(self.allocator, self.network);
} else {
    // Generate BIP32 seed
    var seed: [64]u8 = undefined;
    std.crypto.random.bytes(&seed);
    wallet.* = try Wallet.initFromSeed(self.allocator, self.network, &seed);
    @memset(&seed, 0); // Clear seed from memory
}
```

The BIP-39 module (`src/bip39.zig`) is wired and complete — it has
`entropyToMnemonic`, `mnemonicToEntropy`, `mnemonicToSeed`, and the
canonical TREZOR test vectors all pass. `Wallet.initFromMnemonic`
(`wallet.zig:904-917`) is also wired. But the **RPC path** for creating
a wallet never goes through either:

1. `createwallet` RPC → `handleCreateWallet` → `WalletManager.createWallet`.
2. `createWallet` calls `std.crypto.random.bytes(&seed)` for the seed.
3. **No mnemonic is generated, displayed, returned, or persisted.**
4. **Wallet recovery without the wallet.dat file is IMPOSSIBLE.**

The only recovery surface is the AES-256-GCM-encrypted wallet.dat
itself (and per BUG-5, even that protection is broken because the
master key is plaintext anyway). There is no:
- `importmnemonic` RPC (the inverse — load a wallet from a backed-up
  mnemonic).
- `dumpwallet` RPC (export the mnemonic / xprv).
- CLI flag like `--mnemonic="word word word ..."` for `createwallet`.
- Even a debug-log print of the generated mnemonic.

Compare to lunarblock W155 BUG-8 / W154 BUG-22 funds-burn pattern in
severity: this isn't funds-burn but the funds are **structurally
unrecoverable** if the wallet.dat is destroyed (hardware failure,
filesystem corruption, lost device). Every Bitcoin wallet built since
2013 supports BIP-39 recovery as the canonical loss-of-device path.
clearbit does not.

**File:** `src/wallet.zig:3612-3621 WalletManager.createWallet`.

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::DescriptorScriptPubKeyMan::SetupDescriptorGeneration`
(Core descriptor wallets use the BIP-32 seed AND surface
`getwalletinfo.hdseedid` so the operator can match against a backed-up
extended key); `bitcoin-core/src/wallet/rpc/wallet.cpp::dumpwallet`
emits descriptor records that include the BIP-32 origin info.

(N.B. Core doesn't directly support BIP-39 mnemonics — Core uses raw
BIP-32 seeds — but Core DOES support `dumpwallet`/`importwallet` and
the descriptor-with-xprv export format, so a Core wallet can be
backed up. clearbit cannot.)

**Impact:**
- Total loss of funds on hardware failure / lost device / corrupt
  wallet.dat.
- Worst BIP-39 / BIP-32 backup story in the fleet.
- **NEW PATTERN: "BIP-39 module wired but never on the createwallet
  path"** — sister pattern of "wiring-look-but-no-wire" applied to a
  WALLET MODULE, not an RPC handler.

---

## BUG-9 (P1) — P2WSH purpose mapping is meaningless dead code

**Severity:** P1. `wallet.zig:1036` maps `.p2wsh => .bip84`. P2WSH
has no canonical BIP-43 purpose — Core uses descriptor expressions
`wsh(multi(M, k1, k2, ...))` or similar; the witness program is
`sha256(witness_script)`, not a single derived pubkey.

The derived key from the BIP-84 path is unrelated to the actual
P2WSH scriptPubKey, so the wallet allocates a key, then fails at
`getAddress(.p2wsh)`:

```zig
.p2wsh => {
    // Needs witness script as parameter in real impl
    return error.NotImplemented;
},
```

The `getnewaddress` flow with `addr_type=.p2wsh` therefore:
1. Derives a key at `m/84'/coin'/0'/change/index` (correct path
   format).
2. Imports the key into the wallet.
3. Tries to compute the address — returns `error.NotImplemented`.
4. The increment of `next_external_index` happens AT THE END of the
   function — does this run on the error path? Let me check:
   `wallet.zig:1062-1069` shows the increment is AFTER `getAddress`.
   So the error path leaks the key without incrementing — partial
   side effect. The leaked key sits in `wallet.keys.items` with no
   address to associate it to.

**File:** `src/wallet.zig:1036, 1199-1201 getAddress(.p2wsh)`.

**Core ref:** N/A — Core's P2WSH support is entirely via
descriptor wallets (`wsh(...)`), there is no "BIP-84 P2WSH" concept.

**Impact:**
- Leaks a derived key on every `getnewaddress p2wsh` call.
- Reaches an `error.NotImplemented` rather than refusing at the gate.
- Pollutes the keys list with addresses-less entries.
- **NEW PATTERN: "purpose-enum-overloaded-with-impossible-mapping"**.

---

## BUG-10 (P1) — derivePath only accepts lowercase `h`; uppercase `H` rejected

**Severity:** P1. BIP-32 §"Specification: Wallet structure" example
notation uses `H` AND `h` AND `'` interchangeably for hardened
derivation. Core's `descriptor.cpp::ParseKeyPath` accepts all three.

clearbit's `derivePath` (`wallet.zig:760`) only accepts `'` or
lowercase `h`:

```zig
const hardened = std.mem.endsWith(u8, component, "'") or
    std.mem.endsWith(u8, component, "h");
```

So a path like `m/84H/0H/0H/0/0` (commonly emitted by Coldcard and
Specter) raises `error.InvalidDerivationPath` at line 763 (`parseInt`
fails on `84H`).

**File:** `src/wallet.zig:760`.

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParseKeyPath`
(accepts `'`, `h`, `H`).

**Impact:** UX gap — paths copy-pasted from common HWW tooling
silently rejected; user sees `error.InvalidDerivationPath` with no
hint that case sensitivity is the issue.

---

## BUG-11 (P0-CDIV) — Index out-of-range silently mapped to hardened counterpart

**Severity:** P0-CDIV. `wallet.zig:763`:

```zig
const index = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidDerivationPath;
const full_index = if (hardened) index | 0x80000000 else index;
```

`parseInt(u32, num_str, 10)` accepts the full `u32` range
`[0, 2^32 - 1]`. BIP-32 restricts the un-hardened component to
`[0, 2^31 - 1]`; values `≥ 2^31` are hardened and conventionally
written with a trailing `'` / `h` / `H` marker.

clearbit:
- `m/2147483648` (un-hardened path, value 2^31) → `full_index = 2147483648 = 0x80000000` → silently HARDENED, equals `m/0'`.
- `m/2147483649` → `full_index = 0x80000001 = m/1'`.
- ...
- `m/4294967295` → `full_index = 0xFFFFFFFF = m/2147483647'`.

So **every un-hardened path with index ≥ 2^31 silently collides with
a hardened path**. Worse, on the descriptor.zig CKDpub path (which
DOES support xpub-only derivation), this means a path like
`wpkh(xpub.../0/2147483648/0)` succeeds via the xpub at the
`2147483648` step (because hardened-from-pubkey check at
`descriptor.zig:1172` reads `if (hardened and !is_xprv) return ...`
and the `hardened` flag is FALSE — the caller passed a u32 in the
non-hardened branch).

But the resulting HMAC input prefix is `serP(K)` (not `0x00 || k`),
yet the index byte `0x80000000` LOOKS hardened to any verifier. The
key derived doesn't match what Core would derive for the same descriptor
(Core rejects un-hardened indices ≥ 2^31 at parse time).

Cross-cite W148 fleet pattern "silent index normalisation".

**File:** `src/wallet.zig:763-764`; symmetric in `src/descriptor.zig:849-850`.

**Core ref:** `bitcoin-core/src/script/descriptor.cpp::ParseKeyPath`
explicitly rejects path components `>= 0x80000000` on the non-hardened
branch.

**Impact:**
- `m/2147483648` and `m/0'` derive the same key (silent collision).
- Descriptor `wpkh(xpub.../2147483648/0)` derives a key that no other
  Bitcoin tool produces.
- Cross-impl divergence on the same descriptor string.

---

## BUG-12 (P1) — `getwalletinfo` emits no HD info; advertisement-as-lie for `keypoolsize` and `txcount`

**Severity:** P1. `rpc.zig:5446-5466`:

```zig
try writer.print(",\"txcount\":{d}", .{wallet.keys.items.len});
try writer.print(",\"keypoolsize\":{d}", .{wallet.keys.items.len});
```

Two distinct Bitcoin Core fields meaning two distinct things are both
populated with the SAME wallet-internal counter (`keys.items.len`).
Per Core:
- `txcount`: number of transactions in the wallet's transaction
  history.
- `keypoolsize`: number of pre-generated keys in the keypool (default
  1000).

clearbit:
- `txcount`: number of imported / derived keys.
- `keypoolsize`: number of imported / derived keys.

A monitoring dashboard pulling `keypoolsize` to alert on
"keypool exhaustion" gets the WRONG metric. A monitoring dashboard
pulling `txcount` to alert on "transaction throughput" gets the WRONG
metric.

Additionally absent fields (all required by Core's wallet-info contract):
- `hdseedid` (4-byte hex master fingerprint).
- `hdmasterkeyid` (legacy).
- `walletversion`, `format`, `descriptors`, `private_keys_enabled`.
- `paytxfee`, `avoid_reuse`, `scanning`, `last_processed_block`.

**File:** `src/rpc.zig:5431-5474 handleGetWalletInfo`.

**Core ref:** `bitcoin-core/src/wallet/rpc/wallet.cpp::getwalletinfo`.

**Impact:**
- Operator monitoring on keypool / txcount sees lies.
- HD discovery from another tool (Sparrow's "import from clearbit
  node") impossible because hdseedid is missing.
- **advertisement-as-lie 5th distinct clearbit instance** (after hotbuns
  patterns at W155, W156; cross-fleet).

---

## BUG-13 (P1) — `getaddressinfo` emits no HD info

**Severity:** P1. `rpc.zig:5397-5429 handleGetAddressInfo` emits ONLY
`address` and optional `label`. Per Core, the contract is:

```json
{
  "address": "bc1q...",
  "scriptPubKey": "0014...",
  "ismine": true,
  "iswatchonly": false,
  "solvable": true,
  "desc": "wpkh([fp/84h/0h/0h/0/0]02xxx...)#abcd",
  "isscript": false,
  "ischange": false,
  "iswitness": true,
  "witness_version": 0,
  "witness_program": "...",
  "hdkeypath": "m/84h/0h/0h/0/0",
  "hdseedid": "0123...",
  "hdmasterfingerprint": "deadbeef",
  ...
}
```

clearbit emits two fields out of 15+. Cross-tool import (Sparrow,
Electrum) cannot identify which derivation path a clearbit-generated
address corresponds to.

**File:** `src/rpc.zig:5397-5429`.

**Core ref:** `bitcoin-core/src/wallet/rpc/addresses.cpp::getaddressinfo`.

**Impact:** wallet-discovery / wallet-migration friction.

---

## BUG-14 (P0-CDIV) — 16 wallet RPC methods entirely absent from dispatch

**Severity:** P0-CDIV. Grep over `rpc.zig:2949-3145+` finds NONE of:

| RPC | Purpose | Status |
|-----|---------|--------|
| `importprivkey` | Import a WIF-encoded private key | ABSENT |
| `importpubkey` | Import a watch-only pubkey | ABSENT |
| `importaddress` | Import a watch-only address | ABSENT |
| `importmulti` | Bulk-import keys/addresses | ABSENT |
| `importdescriptors` | Import descriptor wallets | REFUSED `RPC_WALLET_ERROR` (handler returns gate-error) |
| `listdescriptors` | Enumerate descriptors | ABSENT |
| `gethdkeys` | List HD master keys | ABSENT |
| `sethdseed` | Set/replace the HD seed | ABSENT |
| `dumpwallet` | Export wallet to file | ABSENT |
| `importwallet` | Import wallet from file | ABSENT |
| `backupwallet` | Backup wallet.dat | ABSENT |
| `restorewallet` | Restore from backup | ABSENT |
| `rescanblockchain` | Rescan after import | ABSENT |
| `getrawchangeaddress` | Get a fresh change address | ABSENT |
| `keypoolrefill` | Refill keypool | ABSENT |
| `signmessageWithKeypair` | (Core has `signmessage` only) | N/A |

The `importdescriptors` handler is the only one that exists, and it
**refuses with `RPC_WALLET_ERROR -4`** per the deliberate "honest gate"
fix block at `rpc.zig:12356-12409`. So in effect there is NO key
import path at all.

The wallet is effectively **read-only-once**: operator can `createwallet`
+ `getnewaddress` + `sendtoaddress`, but cannot:
- Back up to a different format.
- Import a key from cold storage.
- Restore from another wallet.
- Rescan the chain after an import.
- Generate a fresh change address explicitly.

Cross-cite the **5-CONSECUTIVE-QUAD fleet pattern "wiring-look-but-no-wire"**
— infrastructure exists at the lib layer (Wallet has `importKey`,
ExtendedKey can derive) but no RPC plumbing exposes it.

**File:** `src/rpc.zig:2949-3145+ RPC dispatch table`.

**Core ref:** `bitcoin-core/src/wallet/rpc/*.cpp`.

**Impact:**
- No cold-storage import workflow.
- No backup-and-restore workflow.
- No descriptor wallet import.
- **PRIMARY DRIVER of "clearbit 30-of-30-gates-buggy" pattern** —
  wallet RPC surface is the most uniformly broken subsystem.

---

## BUG-15 (P1, W111 BUG-5 carry-forward 50+ days open) — No keypool / no gap-limit

**Severity:** P1. `tests_w111_wallet.zig:702-707` documents BUG-5:
"No KeyPool or gap-limit enforcement". The wallet only increments a
counter when `getnewaddress` is called; there is no pre-generation,
no `keypoolrefill`, no `keypoolsize`.

Carry-forward status:
- W111 (~2026-04-01 wave) catalogued the bug.
- W118 (~2026-04-12) confirmed still present.
- W155 (~2026-05-18) ouroboros's hdkeypath-equivalent absent.
- W161: still present.

That's 50+ days. **Single architectural gap** (the `Wallet.keypool`
field doesn't exist) blocks both backup-recovery (BUG-8) and watch-only
import (BUG-4, BUG-14).

**File:** `src/wallet.zig:823-944 Wallet struct` (no keypool field).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::LegacyDataSPKM::TopUp`,
`DescriptorScriptPubKeyMan::TopUp`,
`bitcoin-core/src/wallet/wallet.cpp::CWallet::GetKeypoolSize`.

**Impact:**
- Wallet restored from a (non-existent) mnemonic backup can't discover
  any in-use addresses because the keypool isn't pre-generated.
- Address reuse risk because there's no "gap" buffer.
- Mnemonic-recovery completely broken (combined with BUG-8).

---

## BUG-16 (P1) — `master_key.key` / `chain_code` never zeroized

**Severity:** P1. Two distinct hygiene gaps:

1. **`fromSeed`** (`wallet.zig:644-666`) computes `hmac_result` =
   HMAC-SHA512(seed). The buffer holds `private_key || chain_code`
   = 64 bytes of secrets. The function never zeroizes
   `hmac_result` after copying to the returned struct. The 64-byte
   buffer persists on the stack until the next stack frame overwrites
   it; standard library code paths may copy it elsewhere via inline
   move semantics.
2. **`deriveChild`** (`wallet.zig:670-743`) computes another
   `hmac_result` = HMAC-SHA512(chain_code, data). Same buffer-lifetime
   issue.
3. **`Wallet.deinit`** (`wallet.zig:919-944`) zeroizes
   `encryption_key` but NOT `master_key.key` or `master_key.chain_code`.
   When a wallet is unloaded, the master private key and chain code
   stay in heap memory until the allocator reuses the region.

Compare to clearbit's own discipline at `wallet.zig:1723 defer
@memset(&plaintext_secret, 0)` (the unlock path correctly clears the
decrypted child key) — the master-key path is inconsistent.

**File:**
- `src/wallet.zig:644-666 fromSeed` (no zeroize of `hmac_result`).
- `src/wallet.zig:670-743 deriveChild` (no zeroize of `hmac_result`).
- `src/wallet.zig:919-944 Wallet.deinit` (no zeroize of `master_key`).
- `src/bip39.zig:265-306 mnemonicToSeed` (no zeroize of `password`
  / `salt` after pbkdf2; `defer allocator.free` does NOT clear).

**Core ref:** `bitcoin-core/src/key.cpp` `CKey` uses
`secure_allocator<unsigned char>` for `keydata` so the destructor
auto-zeroizes. `CExtKey` holds a `CKey` which inherits this.
`CHMAC_SHA512::Finalize` calls `memory_cleanse(buf, 128)` on the
internal HMAC state.

**Impact:**
- Coredumps / debug-builds leak master key bytes.
- Heap-dump attacks (gdb attach, /proc/PID/mem) recover plaintext.
- Same hygiene class as W160 BUG-1 (Schnorr aux_rand) and W159 BUG-4
  (context_randomize absent).

---

## BUG-17 (P1) — `BIP39Error.OutOfMemory` declared but `mnemonicToSeed` cannot return it

**Severity:** P1 (paper-cut). `bip39.zig:81` declares
`OutOfMemory` in the error set, then `mnemonicToSeed` allocates
`password` and `salt` via `allocator.alloc` (`bip39.zig:284, 300`)
which CAN fail with `error.OutOfMemory`. The error set covers this.
But `validateMnemonic` (`bip39.zig:242-248`) only catches the BIP-39
errors AND `error.OutOfMemory` — fine.

However: the broader issue is `entropyToMnemonic` calls
`allocator.alloc([]const u8, word_count)` (`bip39.zig:166`). If this
fails with OOM, the `errdefer allocator.free(out)` runs — but `out`
was never assigned. Actually it IS assigned at that point (the `try`
returns the value if it succeeds). So errdefer catches the post-success
path. But the actual issue is: on OOM at `allocator.alloc`, the function
returns `error.OutOfMemory` and the `errdefer` doesn't run because `out`
wasn't initialised. OK, that's correct Zig semantics.

(This is a paper-cut — no functional impact, just confirms careful
review of every allocator-fallible site.)

**File:** `src/bip39.zig:81, 165-184`.

**Impact:** none in practice; documentation gap.

---

## BUG-18 (P1) — `wordIndex` linear scan, O(N·2048) per mnemonic

**Severity:** P1 (perf). `bip39.zig:117-124 wordIndex` is a linear
scan over 2048 words for each of the N mnemonic words. For the
canonical 12-word and 24-word mnemonics this is `12*2048` and
`24*2048` comparisons. Not a hot path — mnemonics are parsed once
at wallet creation — but on RPC entry points that accept user
mnemonics (none exist in clearbit yet, but if `importmnemonic` is
ever wired) this is trivially DoSable.

The wordlist IS sorted (the BIP-39 English wordlist is alphabetic
by spec); a binary search would be O(N·log2(2048)) = O(N·11). A
sorted-array binary search or a compile-time hash table is a 5-LOC
optimisation.

**File:** `src/bip39.zig:117-124`.

**Impact:** perf paper-cut; potential DoS surface if `importmnemonic`
is wired without rate-limiting.

---

## BUG-19 (P1) — Non-ASCII passphrase fail-closed is correct policy but silently divergent from BIP-39 spec

**Severity:** P1 (policy gap, intentional). `bip39.zig:271`:

```zig
if (!isAscii(passphrase)) return error.NonAsciiPassphraseRequiresNfkd;
```

The module docstring (`bip39.zig:15-20`) explains the rationale:
Zig's std library does not ship Unicode normalisation. Rather than
silently produce wrong seeds (the "haskoin iteration-collapse trap"
mentioned in the comment), clearbit refuses non-ASCII passphrases.

This is a defensible policy — better fail-closed than silently
diverge — but it IS a spec divergence. BIP-39 mandates NFKD
normalisation; a user with a non-ASCII passphrase from another wallet
(BlueWallet, Trezor Suite, Sparrow) cannot recover their wallet on
clearbit. Importing a Trezor-generated seed where the passphrase
contains `é` or `中` is rejected with
`error.NonAsciiPassphraseRequiresNfkd`.

The fix is non-trivial (vendor a NFKD table or call into ICU) so
the policy is defensible. But it should be DOCUMENTED in operator
docs, not buried in an internal module comment.

**File:** `src/bip39.zig:271`.

**Core ref:** BIP-39 §"Wordlist": "the passphrase must be normalised
using NFKD".

**Impact:** spec divergence + interop gap with non-ASCII-passphrase
wallets.

---

## BUG-20 (P2) — `derivePath` accepts empty path components silently

**Severity:** P2. `wallet.zig:758`:

```zig
if (component.len == 0) continue;
```

So `m/44'//0'/0/0` (note the double slash) silently skips the empty
component and derives the same key as `m/44'/0'/0/0`. Core's
`descriptor.cpp::ParseKeyPath` rejects empty components with a parse
error.

**File:** `src/wallet.zig:758`.

**Impact:** spec divergence; user pasting a malformed path gets a
silently-different key from what they intended.

---

## Cross-cite tracking (fleet patterns)

**Same-shape patterns confirmed extended this wave:**

- **"wiring-look-but-no-wire"** — BUG-8 (BIP-39 module wired but the
  createwallet RPC never uses it); BUG-14 (16 RPC methods missing
  from dispatch). 5-CONSECUTIVE-QUAD fleet pattern; clearbit instance
  count now ≥ 6.
- **"comment-as-confession"** — BUG-1 (master IL≥n claim vs check),
  BUG-5 (master-key encrypted-on-disk claim vs implementation). 14th
  + 15th distinct clearbit instances. Pattern fully saturating.
- **"advertisement-as-lie"** — BUG-12 (`keypoolsize` reports
  `keys.len`; `txcount` reports `keys.len`). 5th distinct clearbit
  instance.
- **"two-pipeline guard"** — BUG-4 + BUG-7: BIP-32 derivation has two
  parallel implementations (`wallet.zig` priv-only + `descriptor.zig`
  priv+pub). They have already diverged: descriptor.zig has version-byte
  parse-misalignment (BUG-7); wallet.zig has no encode at all (BUG-6).
  First fleet instance of two-pipeline at the **BIP-32 derivation**
  layer. 22nd distinct fleet extension.
- **"silent index normalisation"** — BUG-11. Cross-cite W148.
- **"hash / byte-order wire mismatch"** — BUG-7 (4-byte version vs
  1-byte base58check). Cross-cite W151 hotbuns BUG-3.
- **"BIP-32 priv-side via libsecp (NOT pure-Zig BigInt)"** — VERIFIED
  PASS this wave. (`wallet.zig:714 secp256k1_ec_seckey_tweak_add`.)
  Cross-cite W160 G34 PASS; cross-cite haskoin / blockbrew names.
- **"context_randomize UNIVERSAL"** — confirmed still absent at the
  HD layer. The single shared `secp256k1_context` plumbed through
  `Wallet.ctx` (`wallet.zig:864-867`) and into `deriveChild` is the
  same context audited at W159 BUG-4. Not re-litigated here.
- **"sigcache-omits-sighash UNIVERSAL 10/10"** — out of scope for
  W161. Cross-cite W160 BUG-3.
- **"BIP-86 baked into general Taproot sign-path"** — cross-cite W160
  BUG-9; the W161 wallet HD-derivation layer does NOT make this worse,
  but the BIP-86 tweak is applied at `signInput` not at `getnewaddress`,
  so any future fix that adds non-key-path Taproot descriptors (`tr(KEY,
  {leaf})`) must coordinate across BOTH layers.

**New patterns introduced this wave:**

- **"type-width-too-narrow-for-spec"** (BUG-4) — `ExtendedKey.key:
  [32]u8` cannot hold a 33-byte compressed pubkey, so xpub
  representation is structurally impossible.
- **"encrypt-the-children-not-the-parent"** (BUG-5) — defense-in-depth
  applied to LEAVES (child keys) but not to the ROOT (master key).
  Plaintext-on-disk hierarchical key compromise.
- **"BIP-39 module wired but never on the createwallet path"** (BUG-8)
  — sister of "wiring-look-but-no-wire" applied to a wallet MODULE.
- **"parser-misaligned-by-truncated-version-byte"** (BUG-7) — generic
  base58check decoder reads 1-byte version; BIP-32 has 4-byte version;
  payload offsets shift.
- **"purpose-enum-overloaded-with-impossible-mapping"** (BUG-9) —
  `.p2wsh => .bip84` derives a key but address compute fails.
- **"missing-overflow-guard at a spec-mandated boundary"** (BUG-3) —
  BIP-32 depth=255 overflow guard absent.

**Carry-forward this wave:**

- **W160 BUG-7 → W161 BUG-2** (BIP-32 retry-on-IL≥n): 2-wave open,
  no fix attempted. Sister of W159→W160 cluster (Schnorr aux_rand,
  sign-then-verify paranoia).
- **W111 BUG-5 → W161 BUG-15** (no keypool / no gap-limit): 50+
  days open across 5+ audits.

---

## Summary

**Bug count:** 20 (BUG-1 through BUG-20).

**Severity distribution:**
- **P0-CDIV catastrophic:** 1 (BUG-5 — plaintext master key)
- **P0-CDIV:** 7 (BUG-3, BUG-4, BUG-6, BUG-7, BUG-8, BUG-11, BUG-14)
- **P1:** 11 (BUG-1, BUG-2, BUG-9, BUG-10, BUG-12, BUG-13, BUG-15,
  BUG-16, BUG-17, BUG-18, BUG-19)
- **P2:** 1 (BUG-20)

Total: 1 + 7 + 11 + 1 = 20. ✓

**P0-class total (P0-CDIV + P0-CDIV catastrophic):** 8.

**Top three findings:**

1. **BUG-5 (P0-SEC catastrophic) — Master private key serialised in
   PLAINTEXT to wallet.dat regardless of `encryptwallet`.** The
   `encryptWallet` routine iterates only `keys.items[*].secret_key`
   and never touches `wallet.master_key.key` / `chain_code`. The
   on-disk JSON contains the 32-byte master private key in plaintext
   hex even for encrypted wallets, and the comment at the
   serialisation site **lies** about the gate. A filesystem-level
   attacker (chrooted backup, accidental rsync, leaked Docker volume,
   sold SSD) recovers ALL funds across ALL derivations without
   touching the AES-256-GCM envelope. The child-key encryption is
   purely cosmetic because the master is the root of every child.
   Comment-as-confession 14th distinct clearbit instance.

2. **BUG-8 (P0-CDIV catastrophic UX) — `createwallet` bypasses BIP-39
   entirely; no mnemonic recovery path exists.** The BIP-39 module is
   fully implemented (canonical TREZOR vectors pass), but the RPC
   `createwallet` path calls `std.crypto.random.bytes(&seed)` directly
   and never surfaces a mnemonic. Combined with BUG-14 (no `dumpwallet`,
   no `importmnemonic`, no `backupwallet`, no `rescanblockchain`),
   wallet recovery without the wallet.dat file is **structurally
   impossible**. New fleet pattern "BIP-39 module wired but never on
   the createwallet path" — sister of wiring-look-but-no-wire applied
   to a wallet MODULE.

3. **BUG-6 + BUG-7 cluster — xpub/xprv encode entirely absent + decode
   misaligned by base58check truncated version byte.** clearbit has
   no `ExtendedKey.encode` function and stores `master_key.key` /
   `chain_code` as raw hex in wallet.dat. The descriptor-side parallel
   BIP-32 implementation reads xpub strings via a generic
   `base58CheckDecode` that strips ONE version byte (BIP-32 has FOUR),
   so payload offsets shift by 3 bytes and every imported xpub
   produces the WRONG child keys (chain_code and keydata are
   misaligned). Combined with BUG-4 (struct cannot hold a 33-byte
   pubkey at all), watch-only HD wallets are structurally
   unrepresentable AND every imported xpub silently derives wrong
   addresses. New fleet pattern "parser-misaligned-by-truncated-
   version-byte"; first fleet instance of "two-pipeline at the BIP-32
   layer" with measurable divergence.

**Operational observations:**

- **clearbit 30-of-30-gates-buggy continues at W161** — W138 assumeUTXO
  through W160 ECDSA/Schnorr all flagged subsystem-rewrite-candidate;
  W161 adds HD wallet derivation to that pile. **Single most-broken
  subsystem in clearbit is the wallet layer**, with 20 bugs from this
  wave alone (8 P0-class) plus BUG-15 (W111 carry-forward, 50+ days
  open) plus the W160 sign-side stack.
- **clearbit signing + HD-derivation surface combined** (W158 BIP-322
  + W159 libsecp + W160 ECDSA/Schnorr + W161 HD): cipher-as-scalar
  (W158, 2-wave open), context_randomize UNIVERSAL (W159 BUG-4,
  2-wave open), sigcache-omits-sighash (W160 BUG-3), Schnorr
  aux_rand=null (W159 BUG-18 → W160 BUG-1, 2-wave open),
  sign-then-verify paranoia absent (W159 BUG-6/-7/-8 → W160 BUG-13,
  2-wave open), BIP-32 IL≥n retry (W160 BUG-7 → W161 BUG-2, 2-wave
  open), plaintext master key on disk (W161 BUG-5, NEW catastrophic),
  no BIP-39 recovery (W161 BUG-8, NEW catastrophic). **Cumulative
  signing+HD bug count: ~80 across W158-W161.**
- The W161 BUG-5 (plaintext master) is **higher-severity than the
  W160 BUG-3 (sigcache substitution)** because the attack surface is
  much wider — anyone with read access to wallet.dat is an attacker,
  not just an on-chain adversary crafting carefully-timed
  transactions.

**Fix priority order:**

1. **BUG-5 (P0-SEC catastrophic)** — wire `master_key.key` /
   `master_key.chain_code` through `encryptPrivateKey` /
   `decryptPrivateKey`, extend the JSON shape with `master_nonce` /
   `master_tag` fields. ~50 LOC.
2. **BUG-8 (P0-CDIV catastrophic UX)** — refactor
   `WalletManager.createWallet` to generate 256-bit entropy →
   `bip39.entropyToMnemonic` → `bip39.mnemonicToSeed` →
   `Wallet.initFromSeed`. Return the mnemonic in the
   `createwallet` RPC response. ~30 LOC + RPC shape change.
3. **BUG-6 (P0-CDIV)** — add `ExtendedKey.encode(version_bytes:
   [4]u8) [78]u8` and `ExtendedKey.toBase58Check(version_bytes)
   ![]u8`. Wire via new `dumpwallet` / `gethdkeys` /
   `listdescriptors` RPCs. ~100 LOC.
4. **BUG-7 (P0-CDIV)** — fix `base58CheckDecode` to accept multi-byte
   version prefixes (or add a separate `base58CheckDecodeExt` that
   returns the full version slice). Validate version byte against
   `Params().Base58Prefix(EXT_PUBLIC_KEY|EXT_SECRET_KEY)`. ~30 LOC.
5. **BUG-4 (P0-CDIV)** — widen `ExtendedKey.key: [32]u8` to a tagged
   union `Key = enum { private: [32]u8, public: [33]u8 }`. Restructure
   `deriveChild` accordingly. ~80 LOC + breaking change to
   `ExtendedKey` consumers.
6. **BUG-3 (P0-CDIV)** — add `if (self.depth == 255) return
   error.MaxDepthExceeded;` at `wallet.zig:738`. ~3 LOC.
7. **BUG-11 (P0-CDIV)** — clamp `parseInt(u32, ...)` result to
   `[0, 2^31)` on the un-hardened branch; reject otherwise. ~3 LOC
   in `wallet.zig` + 3 in `descriptor.zig`.
8. **BUG-14 (P0-CDIV)** — implement at least `importprivkey` (most
   urgent for cold-storage import) and `rescanblockchain`. ~200 LOC.
9. **BUG-2 (P1, 2-wave open)** — retry-on-IL≥n in `derivePath`. ~10 LOC.
10. **BUG-12 (P1)** — add `hdseedid` to `getwalletinfo`; correctly
    populate `keypoolsize` / `txcount` from separate counters. ~20
    LOC.
11. Remaining P1/P2 bugs are paper-cuts; bundle into a wallet-cleanup
    PR.

**Verification harness needed:**
- Canonical BIP-32 test vectors (chain m, m/0'/1, m/0'/1/2', ...) →
  match `xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi`
  byte-by-byte. CURRENTLY ABSENT — only the depth=0 / depth=1 /
  path-format-string round-trips are tested. Without canonical
  vectors, there is no proof that clearbit's BIP-32 matches the spec
  at all.
- SLIP-132 ypub/Ypub/zpub/Zpub round-trip refusal (Core doesn't
  support these; clearbit should explicitly reject if a user pastes
  one).
- Cross-impl identity vectors: same mnemonic → same xpub on clearbit
  vs Bitcoin Core, ouroboros, rustoshi, etc.
