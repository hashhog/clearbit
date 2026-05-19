# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (clearbit)

**Wave:** W157 — `CheckSignetBlockSolution`, `FetchAndClearCommitmentSection`,
`SignetTxs::Create`, `ComputeModifiedMerkleRoot`, `SIGNET_HEADER` (`0xecc7daa2`),
`signet_challenge` / `signet_blocks` chain params, default-signet challenge,
custom-signet wiring (`-signetchallenge` / `-signetseednode`),
miner-side `GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval())`
(MTP+1 with BIP-94 timewarp guard on **all** networks since v25),
`UpdateTime` (`pblock->nTime = max(GetMinimumTime, GetAdjustedTime)` +
`pblock->nBits = GetNextWorkRequired` re-clamp on testnet
min-difficulty), `MAX_TIMEWARP=600` constant, `enforce_BIP94` per-network
flag (mainnet/testnet3/signet/regtest false; testnet4 true), `fPowAllowMinDifficultyBlocks`,
nVersion BIP-9 signaling (`ComputeBlockVersion`), `target` nBits encoding,
`GetNextWorkRequired` call at retarget on the assembler path, signet on
regtest (custom-signet test mode), default vs operator-supplied
`signet_challenge`, `MinBIP9WarningHeight`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.cpp:28` —
  `static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};`
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection`:
  walks the coinbase's BIP-141 witness-commitment scriptPubKey, locates the
  pushdata that begins with `SIGNET_HEADER`, extracts the trailing bytes as
  the signet solution, and re-emits the script with the header-prefix bytes
  stripped from the matching push. Idempotent.
- `bitcoin-core/src/signet.cpp:59-68` — `ComputeModifiedMerkleRoot`:
  rebuilds the merkle root from the *modified* coinbase (signet solution
  stripped) and the rest of the block's txids. This is the message that
  the signet challenge script signs over.
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create`: constructs
  the two synthetic transactions (`m_to_spend`, `m_to_sign`) that mirror
  BIP-325. `m_to_spend.vout[0].scriptPubKey = challenge`;
  `m_to_sign.vin[0].scriptSig` and `scriptWitness.stack` come from the
  decoded signet solution; the spend points at `m_to_spend.GetHash()`.
  `block_data = nVersion || hashPrevBlock || signet_merkle || nTime` is
  pushed into `m_to_spend.vin[0].scriptSig`.
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  fast-path returns true for `block.GetHash() == hashGenesisBlock`;
  otherwise builds `SignetTxs`, runs `VerifyScript(scriptSig, scriptPubKey,
  &witness, BLOCK_SCRIPT_VERIFY_FLAGS=P2SH|WITNESS|DERSIG|NULLDUMMY,
  sigcheck)`. Returns false on any parse error or script-verify failure.
  Single call site: `validation.cpp:3931` (inside `CheckBlock`).
- `bitcoin-core/src/signet.h` (omitted, but its essential surface):
  `BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS
  | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY` (a fixed bundle, not the
  network's script-verify flag set).
- `bitcoin-core/src/validation.cpp:3931` — single CheckSignetBlockSolution
  call site, inside `CheckBlock`:
  `if (consensusParams.signet_blocks && fCheckPOW &&
   !CheckSignetBlockSolution(block, consensusParams))
       return state.Invalid(BLOCK_CONSENSUS, "bad-signet-blksig", …);`
- `bitcoin-core/src/consensus/params.h:139-140` —
  `bool signet_blocks{false};
   std::vector<uint8_t> signet_challenge;`
- `bitcoin-core/src/kernel/chainparams.cpp:417-453::SigNetParams` —
  default signet challenge constant (the 2-of-2 multisig
  `512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43021…ae`);
  `signet_blocks = true`, `signet_challenge.assign(bin.begin(), bin.end())`,
  `nMinimumChainWork = 0x…0b463ea0a4b8`,
  `defaultAssumeValid = 00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329`,
  DNS seeds `seed.signet.bitcoin.sprovoost.nl` + `seed.signet.achownodes.xyz`,
  `pchMessageStart = first4(sha256d(signet_challenge))` — magic is
  challenge-derived.
- `bitcoin-core/src/chainparams.cpp:26-42::ReadSigNetArgs` —
  `-signetchallenge=<hex>` operator-supplied custom challenge (must be hex,
  exactly one value); `-signetseednode` operator-supplied seed list.
- `bitcoin-core/src/kernel/chainparams.cpp:464` — `consensus.enforce_BIP94
  = false` for signet (signet does NOT enforce the BIP-94 timewarp check
  at retarget boundaries because the signing key replaces PoW; but signet
  blocks still respect the difficulty pipeline as defense-in-depth).
- `bitcoin-core/src/node/miner.cpp:36-47::GetMinimumTime` —
  ```cpp
  int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
  if (height % difficulty_adjustment_interval == 0) {
      min_time = std::max<int64_t>(min_time,
                                   pindexPrev->GetBlockTime() - MAX_TIMEWARP);
  }
  ```
  **Comment in source:** "Account for BIP94 timewarp rule on all networks.
  This makes future activation safer." Miner-side BIP-94 fires on
  EVERY network including mainnet/testnet3/signet/regtest, even though
  the consensus-side `enforce_BIP94` is only true on testnet4.
- `bitcoin-core/src/node/miner.cpp:49-65::UpdateTime` —
  `nNewTime = max(GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval()),
   TicksSinceEpoch<seconds>(NodeClock::now()))`; if testnet `fPowAllowMinDifficultyBlocks`,
   re-computes `pblock->nBits = GetNextWorkRequired(...)` because changing
   nTime can change the work target on min-difficulty chains.
- `bitcoin-core/src/node/miner.cpp` (`CreateNewBlock`) — uses
  `GetMinimumTime` for `pblock->nTime`; uses `GetNextWorkRequired` for
  `pblock->nBits`; both at every template build.
- `bitcoin-core/src/consensus/consensus.h:35` —
  `static constexpr int64_t MAX_TIMEWARP = 600;`
- `bitcoin-core/src/validation.cpp:4097-4105` — consensus-side BIP-94 timewarp:
  ```cpp
  if (consensusParams.enforce_BIP94) {
      if (nHeight % DiffAdjInterval == 0 &&
          block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP) {
          return state.Invalid(…, "time-timewarp-attack", …);
      }
  }
  ```
- `bitcoin-core/src/pow.cpp:67-76` — retarget-side BIP-94:
  uses `pindexFirst->nBits` (first block of period) instead of
  `pindexLast->nBits` when `enforce_BIP94` is set.
- `bitcoin-core/src/rpc/blockchain.cpp:1458-1461::getblockchaininfo` —
  emits `"signet_challenge": HexStr(signet_challenge)` only when on signet.
- `bitcoin-core/src/rpc/mining.cpp::getblocktemplate` — emits
  `signet_challenge` GBT field only on signet.

**Files audited**
- `src/consensus.zig` — `Network` enum (line 213-219: includes
  `signet`), `NetworkParams` struct (line 361-442: NO `signet_challenge`
  field, NO `signet_blocks` field), `SIGNET` constants (line 706-754),
  `TESTNET3/TESTNET4/MAINNET/REGTEST` constants (lines 477-595 / 597-648 /
  653-702 / 756-end), `MAX_TIMEWARP` (line 166), `enforce_bip94` field
  (line 383), `difficultyAdjustmentInterval` (line 973), `getNextWorkRequired`
  (line 989-1046), `calculateNextWorkRequiredBip94` (line 1058-1102),
  `calculateNextWorkRequired` (line 1115-1146, legacy).
- `src/main.zig` — `Config` struct (line 47-189), `Config.Network` enum
  (line 158-163: `{ mainnet, testnet, testnet4, regtest }` — NO signet),
  `getNetworkParams` (line 167-189: switch arms for 4 networks, NO
  `.signet` case), `parseArgs` (line 205-end: registers `--testnet` /
  `--testnet4` / `--regtest`, NO `--signet` / `--signetchallenge` /
  `--signetseednode`), `getNetworkSubdir` (line 581-589: 4 networks,
  no signet).
- `src/validation.zig` — `checkBlock` (line 763-858: full perimeter
  validation, NO `CheckSignetBlockSolution` call), `checkBlockHeader`
  (line 576-596), `validateBlockForIBD` (line 1123-1717: BIP-94 check
  at 1162-1185 is the ONLY enforce_bip94 site; NO signet check
  anywhere), `acceptBlock` (line 1673-1716), `checkDifficulty`
  (line 1963-end: retarget consumer of `enforce_bip94`).
- `src/peer.zig` — `validateBlockBody` (around line 6378-6402:
  populates `prev_block_timestamp` for BIP-94, NO signet path).
- `src/block_template.zig` — `createBlockTemplate` (line 218-459),
  header construction (line 430-437: `timestamp = std.time.timestamp()`
  with NO `GetMinimumTime` / `MTP+1` / `BIP-94` clamp, `bits = (placeholder)`
  per W154 BUG-1), `nVersion = computeBlockVersion(stub)` (line 409-429),
  `constructCoinbaseWithCommitment` (line 468-end: NO signet solution
  payload injection into witness-commitment script).
- `src/rpc.zig` — `handleGetBlockTemplate` (line 6065-6133):
  emits `mintime` and `curtime` BOTH set to `template.header.timestamp`,
  NO `signet_challenge` field, NO `default_witness_commitment`,
  NO `rules: ["segwit", "signet"]`.
- `src/perf.zig` — `Network` (line 130-145): a third `Network` enum
  including `signet` whose magic constant `{0x0A, 0x03, 0xCF, 0x40}`
  is hand-encoded as little-endian bytes.

---

## Gate matrix (30 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `CheckSignetBlockSolution` present in validation pipeline | G1: `checkBlock` calls helper when signet | **BUG-1 (P0-CONS)** absent everywhere |
| 1 | … | G2: `validateBlockForIBD` calls helper when signet | **BUG-1 cross-cite** |
| 1 | … | G3: fast-path skip on genesis hash | **BUG-1 cross-cite** (no helper at all) |
| 2 | `SIGNET_HEADER` magic = 0xecc7daa2 | G4: constant defined | **BUG-2 (P0-CONS)** constant entirely absent |
| 3 | `signet_challenge` chain param wired | G5: `NetworkParams.signet_challenge` field exists | **BUG-3 (P0-CONS)** field missing from struct |
| 3 | … | G6: default challenge populated for SIGNET | **BUG-3 cross-cite** |
| 3 | … | G7: `signet_blocks` boolean dispatch flag | **BUG-3 cross-cite** (no field) |
| 4 | `FetchAndClearCommitmentSection` reachable | G8: helper exists | **BUG-4 (P0-CONS)** absent |
| 4 | … | G9: `SignetTxs::Create` analogue exists | **BUG-4 cross-cite** |
| 4 | … | G10: `ComputeModifiedMerkleRoot` analogue exists | **BUG-4 cross-cite** |
| 5 | BIP-94 consensus check at retarget | G11: `validateBlockForIBD` enforces guard when `enforce_bip94` AND height%interval==0 | PASS (`validation.zig:1172-1185`) |
| 5 | … | G12: `MAX_TIMEWARP = 600` constant | PASS (`consensus.zig:166`) |
| 5 | … | G13: testnet4 has `enforce_bip94 = true` | PASS (`consensus.zig:683`) |
| 5 | … | G14: mainnet/testnet3/signet/regtest `enforce_bip94 = false` | PASS (lines 512/629/735/787) |
| 6 | `GetMinimumTime` miner-side clamp on ALL networks | G15: assembler nTime = `max(MTP+1, wall)` | **BUG-5 (P0-CDIV)** uses raw wall clock |
| 6 | … | G16: assembler nTime = `max(prevTime-MAX_TIMEWARP, …)` at retarget | **BUG-6 (P0-CDIV)** miner-side BIP-94 guard absent |
| 6 | … | G17: GBT response `mintime` field = `GetMinimumTime`, not wall | **BUG-7 (P0-CDIV)** (re-anchor of W154 BUG-13) |
| 7 | nVersion BIP-9 signaling | G18: assembler nVersion derived from real per-height view | FAIL — W154 BUG-2 (carry-forward); stub IndexView returns null |
| 8 | target nBits encoding | G19: GBT response `bits` = `GetNextWorkRequired(prev)` | FAIL — W154 BUG-1 (22-wave carry-forward); placeholder bits |
| 9 | `GetNextWorkRequired` reachable from assembler | G20: assembler calls it | FAIL — W154 BUG-1 cross-cite |
| 10 | `fPowAllowMinDifficultyBlocks` honored on testnet | G21: nBits re-derived after nTime update on testnet | **BUG-8 (P1)** UpdateTime analogue absent |
| 11 | signet on regtest test mode (custom challenge) | G22: `-signetchallenge` operator knob | **BUG-9 (P0-CDIV)** CLI flag absent |
| 11 | … | G23: `-signetseednode` operator knob | **BUG-9 cross-cite** |
| 12 | default vs custom `signet_challenge` selection | G24: code path divides `if (!options.challenge)` | **BUG-10 (P1)** N/A; field absent |
| 13 | Miscellaneous signet plumbing | G25: `Config.Network` enum includes `.signet` | **BUG-11 (P0-CDIV)** signet unreachable via CLI |
| 13 | … | G26: `getNetworkParams` switch covers `.signet` | **BUG-12 (P0-CDIV)** no `.signet` arm |
| 13 | … | G27: signet DNS seeds match Core (2 entries) | **BUG-13 (P1)** only 1 of 2 seeds |
| 13 | … | G28: signet `min_chain_work` matches Core | **BUG-14 (P1)** clearbit `…0100000000` vs Core `…0b463ea0a4b8` |
| 13 | … | G29: signet `nDefaultPort=38333` | PASS (line 708) |
| 13 | … | G30: signet `assume_utxo` snapshot table | FAIL — W102 G27 (carry-forward; 2 Core entries missing) |

---

## BUG-1 (P0-CONS) — `CheckSignetBlockSolution` is completely absent from the validation pipeline

**Severity:** P0-CONS. Bitcoin Core's `CheckSignetBlockSolution`
(`signet.cpp:126-153`) is the **sole** consensus gate that distinguishes
a signet block from "just a low-PoW block": signet replaces hashing with
a challenge-script signature, and this helper is what verifies the
signature is present and valid. It is wired into `CheckBlock` at
`validation.cpp:3931` as `if (consensusParams.signet_blocks && fCheckPOW &&
!CheckSignetBlockSolution(...)) return state.Invalid(BLOCK_CONSENSUS,
"bad-signet-blksig", …)`.

clearbit has **zero** instances of `CheckSignetBlockSolution`,
`SignetTxs`, `FetchAndClearCommitmentSection`, `signet_solution`, or
`ComputeModifiedMerkleRoot` anywhere in `src/`. A `rg`-style search
across the entire production tree confirms:

```
$ grep -rn "CheckSignetBlockSolution\|SignetTxs\|signet_solution\|\
FetchAndClearCommitmentSection\|ComputeModifiedMerkleRoot" src/
# (no production hits — three test-comment hits in tests_w108_gbt.zig)
```

`validation.zig::checkBlock` (line 763-858) runs header, coinbase,
sigops, merkle, weight, BIP-34, BIP-141 witness-malleation — but never
asks "are we on a signet chain, and if so, does this block's coinbase
witness commitment carry a valid signet solution signed by the
challenge script?". `validateBlockForIBD` (line 1123-1717) is the same
story.

The consequence: on a signet network, **any block whose header meets
the easy signet `pow_limit` is accepted as valid**, regardless of who
created it. There is no challenge-script gating at all. An attacker
with no access to the signet signing key can mine and broadcast valid
blocks (signet PoW is intentionally weak —
`pow_limit = 00000377ae00…`), reorg the chain at will, double-spend
themselves, anything they want.

**File:** `src/validation.zig:763-858` (checkBlock has no
`CheckSignetBlockSolution`); `src/validation.zig:1123-1717`
(validateBlockForIBD same); `src/peer.zig:6378-6402`
(validateBlockBody pipeline does not interpose either).

**Core ref:** `bitcoin-core/src/signet.cpp:126-153` (the helper);
`bitcoin-core/src/validation.cpp:3931` (the single call site).

**Impact:** signet network is **completely insecure** in clearbit.
Anyone can mine a 4-byte-PoW header that meets `0x00000377ae…` (trivial
on modern CPUs at 600s spacing) and clearbit accepts it. Reorgs,
double-spends, chain takeover are all wide open. This is the same
P0-CONS class finding as blockbrew W143 BUG-9 (`CheckSignetBlockSolution
entirely missing — accepts any PoW-valid block, forks off signet at
block 1`), now confirmed for clearbit. **2-of-10 fleet signet-helper-absent
pattern** confirmed (blockbrew W143 + clearbit W157).

---

## BUG-2 (P0-CONS) — `SIGNET_HEADER` magic constant (`0xecc7daa2`) entirely absent

**Severity:** P0-CONS (consequence of BUG-1; isolated catalogue here
because it is the wire-format primitive every BIP-325 implementation
must define before any other signet code can be written).

Bitcoin Core declares `SIGNET_HEADER` at `signet.cpp:28`:
```cpp
static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};
```
This is the 4-byte prefix that distinguishes the signet-solution pushdata
inside the witness-commitment output's scriptPubKey from any other
pushdata. It is consumed by `FetchAndClearCommitmentSection` (which
locates the matching push) AND by miners writing a coinbase that
attaches a signet solution (Core embeds the bytes
`SIGNET_HEADER || solution_bytes` after the `OP_RETURN OP_PUSH36
0xaa21a9ed <32-byte commitment>` segment).

A `grep` for `0xecc7daa2`, `ecc7daa2`, `0xec, 0xc7, 0xda, 0xa2`, or
the byte-wise variants returns **zero matches** in clearbit:

```
$ grep -rn "0xecc7daa2\|ecc7daa2\|0xec, 0xc7, 0xda, 0xa2" src/
# (no hits)
```

This is a primitive that must exist before any other signet code can
function. Until it does, no producer can attach a signet solution clearbit
would recognise, and no consumer can decode one. Even if BUG-1 were
fixed by stubbing in a fake validator, the resulting validator would
have no way to identify which pushdata in the commitment script
contains the solution.

**File:** absent from `src/consensus.zig` (where wire-format constants
live); absent from `src/block_template.zig` (where the coinbase
commitment is built).

**Core ref:** `bitcoin-core/src/signet.cpp:28`.

**Impact:** wire-format primitive missing. Even partial signet support
is impossible without it.

---

## BUG-3 (P0-CONS) — `NetworkParams.signet_challenge` and `signet_blocks` fields are not in the struct

**Severity:** P0-CONS. Bitcoin Core's `Consensus::Params` carries two
signet-specific fields (consensus/params.h:139-140):
```cpp
bool signet_blocks{false};
std::vector<uint8_t> signet_challenge;
```
- `signet_blocks` is the dispatch flag every signet-aware check
  conditions on (`if (consensusParams.signet_blocks && …)`).
- `signet_challenge` is the BIP-325 block-signature script: the
  scriptPubKey that the synthetic `m_to_spend.vout[0]` carries and that
  the per-block signature must satisfy.

clearbit's `NetworkParams` (`consensus.zig:361-442`) defines 26 fields:
`magic`, `default_port`, `genesis_hash`, `genesis_header`, `dns_seeds`,
the BIP-34/65/66/CSV/segwit/taproot heights, address prefixes,
bech32 hrp, halving interval, `pow_*` quartet (`limit`, `no_retarget`,
`allow_min_difficulty_blocks`, `enforce_bip94`), spacing/timespan,
`min_chain_work`, `assume_utxo`, `assumed_valid_hash`,
`assume_valid_height`, `bip30_exceptions`, `bip30_disconnect_exceptions`,
`bip34_hash`, `bip9_deployments`. Neither `signet_challenge` nor
`signet_blocks` is among them.

The `SIGNET` instance at line 706-754 is therefore **structurally
identical to TESTNET3 plus pow_limit override** — there is no
challenge-script payload anywhere in the data model, and no flag any
downstream check could read to know "this is a signet chain, apply the
signet rules". A consumer who wanted to add the helper from BUG-1 would
have nothing to call it with — the second argument
(`const Consensus::Params&`) has no `.signet_challenge` member.

**File:** `src/consensus.zig:361-442` (struct definition); 706-754
(`SIGNET` instance, no challenge field).

**Core ref:** `bitcoin-core/src/consensus/params.h:139-140`;
`bitcoin-core/src/kernel/chainparams.cpp:452-453` (Core sets both fields
on `SigNetParams`).

**Impact:** data-model gap. Even a perfect implementation of
`CheckSignetBlockSolution` would have nowhere to read the challenge from.
Companion to BUG-1: the validator cannot be wired until this struct gap
closes.

---

## BUG-4 (P0-CONS) — Helper functions `FetchAndClearCommitmentSection` / `SignetTxs::Create` / `ComputeModifiedMerkleRoot` are not implemented

**Severity:** P0-CONS. The BIP-325 signet pipeline requires three
helpers Core implements in `signet.cpp`:
1. **`FetchAndClearCommitmentSection`** — walks the
   `OP_RETURN OP_PUSH36 0xaa21a9ed …` witness commitment script, finds
   the pushdata that starts with `SIGNET_HEADER`, splits off the
   trailing bytes as the signet solution, and re-emits the script with
   the header-prefix bytes stripped from that pushdata (so the modified
   commitment can be used to recompute the original block's merkle
   root).
2. **`SignetTxs::Create`** — builds the two synthetic transactions
   (`m_to_spend` with the challenge as scriptPubKey, `m_to_sign` with
   the solution as scriptSig/witness) that the script-verify pass
   checks.
3. **`ComputeModifiedMerkleRoot`** — recomputes the block's merkle root
   from the *modified* (signet-header-stripped) coinbase + rest of
   block's transactions. The result is what the signet signature signs
   over (`block_data = nVersion || hashPrevBlock || signet_merkle ||
   nTime` pushed into `m_to_spend.vin[0].scriptSig`).

`grep -rn "FetchAndClearCommitmentSection\|SignetTxs\|signet_solution\|\
ComputeModifiedMerkleRoot" src/` returns zero production hits. The
clearbit witness-commitment construction at
`block_template.zig:522-539` writes the standard
`OP_RETURN OP_PUSH36 0xaa21a9ed <commit32>` output and stops — it has
no signet-header attachment path. The mempool / consensus
`signet_solution` decoder is missing as well.

These three helpers form the BIP-325 protocol surface. Without them, no
clearbit-built block can attach a signet solution (so other signet
peers reject it), and no clearbit consumer can validate an incoming
signet block (so any block whose easy-PoW header passes is accepted —
the BUG-1 outcome).

**File:** absent from `src/consensus.zig`, `src/validation.zig`,
`src/block_template.zig`, `src/script.zig`.

**Core ref:** `bitcoin-core/src/signet.cpp:32-57`,
`bitcoin-core/src/signet.cpp:70-123`,
`bitcoin-core/src/signet.cpp:59-68`.

**Impact:** entire BIP-325 protocol surface absent. Combined with
BUG-1/2/3, clearbit cannot participate on signet at all (cannot
validate incoming, cannot produce outgoing).

---

## BUG-5 (P0-CDIV) — Assembler `nTime` uses raw wall clock; no `GetMinimumTime` / `MTP+1` clamp

**Severity:** P0-CDIV ("two-pipeline guard" applies; the consensus
`MTP+1` gate IS enforced in `validateBlockForIBD:1158-1160`, but the
mining-assembler-side `MTP+1` clamp is missing).

Bitcoin Core's `CreateNewBlock` (`miner.cpp:36-65`) computes:
```cpp
pblock->nTime = std::max<int64_t>(
    GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
    TicksSinceEpoch<std::chrono::seconds>(time::GetAdjustedTime()));
```
where `GetMinimumTime` is:
```cpp
int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time,
                                 pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
return min_time;
```
**Both clauses apply.** The `MTP+1` lower bound is needed because the
BIP-113 consensus gate requires `block.nTime > prev_mtp` — if the wall
clock is below `MTP+1`, the assembler would emit a block that fails
its own validation. The `MAX_TIMEWARP` clamp at retarget is needed
because the consensus-side BIP-94 gate (on networks where it is
active) rejects retarget blocks more than 600s earlier than the
preceding block.

clearbit's `createBlockTemplate` (`block_template.zig:430-437`):
```zig
const header = types.BlockHeader{
    .version = nVersion,
    .prev_block = chain_state.best_hash,
    .merkle_root = merkle_root,
    .timestamp = @intCast(std.time.timestamp()),  // <-- raw wall clock
    .bits = bits,
    .nonce = 0,
};
```
No `GetMinimumTime` analogue, no `chain_state.computeMTP() + 1` lower
clamp, no `prev_block_time - MAX_TIMEWARP` clamp at retarget. If the
node's clock is even one second behind the parent's MTP, the template
is born invalid — every block built from it fails the BIP-113 gate at
`validation.zig:1158-1160`.

W154 already flagged this as BUG-3 (P0-CDIV "nTime uses raw wall clock,
no GetAdjustedTime peer-skew adjustment, no parent_MTP+1 clamp") on the
broader assembler scope. This is the **same finding re-anchored at the
W157 signet/BIP-94 scope** — it is the second leg of the
two-pipeline-guard pattern (validation has MTP+1; mining does not).

**File:** `src/block_template.zig:430-437`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-65`.

**Carry-forward:** W154 BUG-3 (P0-CDIV); W123 BUG-6 (P1: "mintime
should be MTP+1"). 6-wave carry-forward streak.

**Impact:** templates born with `nTime <= prev_mtp` fail consensus the
moment they are submitted. On a node whose system clock is behind
network MTP (clock drift, NTP de-sync, manual misconfiguration),
mining is silently bricked — every submitblock returns
`time-too-old`.

---

## BUG-6 (P0-CDIV) — Miner-side BIP-94 timewarp clamp NOT applied on ANY network

**Severity:** P0-CDIV. Bitcoin Core's `GetMinimumTime`
(`miner.cpp:36-47`) applies the BIP-94 timewarp clamp at retarget
boundaries on **every network**:
```cpp
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time,
                                 pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
```
The source comment is explicit: **"Account for BIP94 timewarp rule on
all networks. This makes future activation safer."** The intent is
that even mainnet templates should never emit retarget-block timestamps
that would violate BIP-94 if BIP-94 ever activated on mainnet (e.g. as
defense-in-depth for future soft-fork). This bound the assembler can
apply universally because it never rejects a valid block — it only
prevents templates from being SOFT-FORK-vulnerable.

clearbit's consensus.zig BIP-94 comment at line 162-166 says
"testnet4 only":
```zig
/// Maximum number of seconds that the timestamp of the first block of a
/// difficulty adjustment period is allowed to be earlier than the last
/// block of the previous period (BIP-94 timewarp prevention, testnet4 only).
/// Reference: bitcoin-core/src/consensus/consensus.h:35.
pub const MAX_TIMEWARP: u32 = 600;
```
This is the **consensus-side** semantics (correct for `validateBlockForIBD`).
But the **miner-side** semantics — apply on all networks — has zero
equivalent in clearbit. `block_template.zig:430-437` constructs the
header with a raw wall-clock timestamp and never consults `MAX_TIMEWARP`
or `enforce_bip94` even at retarget heights, even on testnet4.

On testnet4 today: a clearbit miner whose wall clock is 700s+ behind
the parent's `pindexPrev->nTime` and is building the retarget block
would emit a template whose own `validateBlockForIBD` rejects with
`TimewarpAttack`. The miner-side clamp would have raised the timestamp
to `prev_block_time - MAX_TIMEWARP` and avoided the rejection.

On mainnet/testnet3/signet/regtest today: the consensus-side BIP-94 is
inactive, so a sub-`MAX_TIMEWARP` timestamp at retarget is currently
legal — but the assembler still SHOULD apply the clamp as
defense-in-depth (Core's stated rationale: "makes future activation
safer"). If a future soft-fork ever enables `enforce_BIP94` on
mainnet, clearbit miners would silently start emitting invalid retarget
blocks the moment the fork activates.

**File:** absent from `src/block_template.zig`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47` (the helper with
the "all networks" comment); `bitcoin-core/src/consensus/consensus.h:35`
(`MAX_TIMEWARP=600`).

**Carry-forward:** W108 BUG-5 (G5, P2: "BIP-94 timewarp adjustment
missing from `mintime`/`curtime` calculation"); W123 BUG-6 (G6, P1: "mintime
should be MTP+1 with BIP-94 timewarp guard"); W154 BUG-11 (P1).
**4-wave carry-forward streak now extending to W157.**

**Impact:** testnet4 mining bricks on the first retarget the wall
clock is mis-set for; mainnet/signet/regtest defense-in-depth gap that
will silently break activation of any future BIP-94-on-mainnet fork.

---

## BUG-7 (P0-CDIV) — GBT `mintime` and `curtime` BOTH equal `template.header.timestamp` (a fresh wall-clock pick)

**Severity:** P0-CDIV. The BIP-22/23 `getblocktemplate` response
distinguishes two fields:
- `mintime` = floor allowed by consensus (= Core's `GetMinimumTime(prev,
  interval)` = `max(parent_MTP+1, parent_time - MAX_TIMEWARP_at_retarget)`).
- `curtime` = current-wall-clock suggestion (= Core's
  `GetAdjustedTime()`).

A correct miner uses `curtime` as their starting point and iterates
nonce + nTime up to a ceiling, never going below `mintime`.

clearbit's `handleGetBlockTemplate` emits both fields with the SAME
value:
```zig
try writer.print(
    "\",\"mintime\":{d},\"curtime\":{d},\"bits\":\"{x:0>8}\",\"height\":{d},…",
    .{
        template.header.timestamp,   // <-- mintime
        template.header.timestamp,   // <-- curtime (same)
        template.header.bits,
        template.height,
    },
);
```
(`src/rpc.zig:6125-6130`). The value `template.header.timestamp` came
from the raw wall-clock pick in BUG-5. So:
- `mintime` carries a value that is NEITHER `MTP+1` NOR
  `prev_time - MAX_TIMEWARP` — it is just "whatever the clock said at
  template-build time".
- `curtime` is the same value, defeating the miner's ability to
  distinguish the two.

A miner that respects the protocol invariant "do not emit a block with
`nTime < mintime`" would treat the wall-clock-based `mintime` as the
floor, locking in a `nTime` that may already be below the actual
consensus floor (which is `prev_mtp + 1`) — submitblock then rejects
with `time-too-old` even though the miner believed they were above
`mintime`.

This is the same finding as W154 BUG-13 (re-anchored at W157 scope).

**File:** `src/rpc.zig:6125-6130`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` (getblocktemplate
emits `mintime` separately from `curtime`, both computed via
`GetMinimumTime`/`GetAdjustedTime`).

**Carry-forward:** W154 BUG-13, W123 BUG-6, W108 BUG-5. 4-wave streak.

**Impact:** miners cannot rely on `mintime` for the BIP-113 floor;
submitblock retries until the wall clock catches up to `prev_mtp + 1`.

---

## BUG-8 (P1) — No `UpdateTime` analogue: on testnet `nBits` is not re-derived after `nTime` update

**Severity:** P1. Bitcoin Core's `UpdateTime` (`miner.cpp:49-65`):
```cpp
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams,
                   const CBlockIndex* pindexPrev) {
    int64_t nNewTime = max(GetMinimumTime(...), TicksSinceEpoch<seconds>(NodeClock::now()));
    if (nOldTime < nNewTime) pblock->nTime = nNewTime;
    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
    return nNewTime - nOldTime;
}
```
The second clause is critical: on testnet (`fPowAllowMinDifficultyBlocks
= true`, i.e. testnet3 / testnet4 / regtest), if the block's timestamp
moves forward more than `2 * spacing` past the parent, the consensus
min-difficulty exception fires and the required `nBits` becomes
`pow_limit`. The mining template MUST then re-derive `nBits` so the
emitted block is consistent.

clearbit has no `UpdateTime` helper. The `nTime` is set once at template
creation (the wall-clock pick in BUG-5) and never updated. There is no
"call this between nonce iterations to bump nTime + re-derive nBits"
path. On testnet4, a miner who exhausts the nonce range and would
otherwise call `UpdateTime` to advance the clock instead has to call
`getblocktemplate` again from scratch — and even then BUG-1 (placeholder
bits) means `nBits` was wrong from the start.

**File:** absent from `src/block_template.zig`; not exposed via
`src/rpc.zig`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-65`.

**Impact:** testnet3/testnet4/regtest mining cannot transition into
the min-difficulty exception window mid-template; miners stuck at
`pow_target_spacing * 2`+1 seconds after parent fail with `bad-diffbits`
when they could have re-derived `nBits` to `pow_limit`.

---

## BUG-9 (P0-CDIV) — `-signetchallenge` and `-signetseednode` CLI flags entirely absent

**Severity:** P0-CDIV. Bitcoin Core supports two operator knobs for
custom-signet networks:
- `-signetchallenge=<hex>` overrides the default signet 2-of-2 multisig
  challenge with an operator-supplied hex script. The magic
  (`pchMessageStart`) is recomputed as the first 4 bytes of
  `sha256d(signet_challenge)`, so a custom challenge creates a NEW signet
  network distinct from the default one.
- `-signetseednode=<host>` overrides the DNS seed list.

Both flags are parsed in `bitcoin-core/src/chainparams.cpp::ReadSigNetArgs`
(line 26-42) and feed `CChainParams::SigNetOptions`.

clearbit's `parseArgs` (`main.zig:205-end`) registers `--testnet` /
`--testnet4` / `--regtest` only:
```zig
if (std.mem.eql(u8, arg, "--testnet")) { config.network = .testnet; ... }
else if (std.mem.eql(u8, arg, "--testnet4")) { ... }
else if (std.mem.eql(u8, arg, "--regtest")) { ... }
```
No `--signet`, no `--signetchallenge`, no `--signetseednode`. The
operator has no way to point clearbit at the default signet network,
let alone a custom one. This is the **wiring-look-but-no-wire** fleet
pattern: the SIGNET `NetworkParams` instance is fully constructed at
`consensus.zig:706-754`, the magic and DNS seeds are populated, the
`Network.signet` enum tag exists in `consensus.zig:218` — but the
operator-facing path that selects this configuration is missing.

**File:** `src/main.zig:205-280` (parseArgs lacks signet flags);
`src/main.zig:158-163` (Config.Network enum lacks `.signet`);
`src/main.zig:167-189` (getNetworkParams switch lacks `.signet` arm).

**Core ref:** `bitcoin-core/src/chainparams.cpp:26-42`.

**Impact:** signet network is **unreachable** via the CLI. Even if all
prior bugs in this audit were fixed, operators could not start a clearbit
node on signet.

---

## BUG-10 (P1) — No `if (!options.challenge)` default-vs-custom split in the SIGNET params

**Severity:** P1. Bitcoin Core's `SigNetParams` constructor
(`kernel/chainparams.cpp:411-498`) branches on whether the operator
supplied `-signetchallenge`:
- **No custom challenge:** uses the default 2-of-2 multisig
  `bin = "512103ad5e0edad…ae"_hex_v_u8`, sets fixed DNS seeds, sets
  `nMinimumChainWork`, `defaultAssumeValid`, `assumeUTXO` data,
  `chainTxData` (for IBD progress).
- **Custom challenge:** `bin = *options.challenge`, clears
  `nMinimumChainWork`, `defaultAssumeValid`, `m_assumed_blockchain_size`,
  `chainTxData` — because the custom network is a fresh genesis-chain
  and none of the default-signet assumptions apply.

clearbit's `SIGNET` (`consensus.zig:706-754`) is a single compile-time
constant. There is no branch on a runtime "is custom" flag. If
`-signetchallenge` were added (per BUG-9), there would be no
post-construction mutation path that clears `assumed_valid_hash`,
`assume_valid_height`, `assume_utxo`, `min_chain_work`, etc. for the
custom network — leaving a custom-signet node with mainnet-signet's
assumevalid hash, which is structurally guaranteed to be wrong (custom
signet's chain won't contain that hash).

This is dependent on BUG-9 being fixed; logged here as a follow-on
gate.

**File:** `src/consensus.zig:706-754` (no const-vs-runtime split).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:411-498`.

**Impact:** when BUG-9 is closed, BUG-10 becomes the next gate; custom
signet networks would inherit default-signet's assumevalid horizon and
fail at the first network-data divergence.

---

## BUG-11 (P0-CDIV) — `Config.Network` enum diverges from `consensus.Network` (signet absent)

**Severity:** P0-CDIV ("two-pipeline guard" — two parallel `Network`
enums coexist, with different memberships). clearbit defines **two**
`Network` enums and **one** is incomplete:

`src/consensus.zig:213-219`:
```zig
pub const Network = enum {
    mainnet,
    testnet3,
    testnet4,
    regtest,
    signet,        // <-- present
};
```

`src/main.zig:158-163`:
```zig
pub const Network = enum {
    mainnet,
    testnet,
    testnet4,
    regtest,
                  // <-- signet ABSENT
};
```

The CLI's `Config.Network` is the one the user can SELECT via
`--testnet` / `--testnet4` / `--regtest`. The consensus `Network` is
what `getCheckpointsRuntime`, `getNetworkParams(.signet)`, etc. consume.
Because `Config.Network` cannot represent signet, the bridging function
`Config.getNetworkParams` (`main.zig:167-189`) has only 4 switch arms:
```zig
const base = switch (self.network) {
    .mainnet => &consensus.MAINNET,
    .testnet => &consensus.TESTNET,
    .testnet4 => &consensus.TESTNET4,
    .regtest => &consensus.REGTEST,
    // <-- NO `.signet => &consensus.SIGNET` arm
};
```

A third copy of the enum exists in `src/perf.zig:130-145`:
```zig
network: Network = .mainnet,
const Network = enum(u8) { mainnet, testnet, signet = 3, regtest = 4 };
```
This third copy DOES include signet (as a numeric discriminant 3), so
the metrics subsystem can label perf samples by network — but the
**bridging path that would turn an operator flag into a consensus
`Network` value for the validator is the one that omits signet**.

This is a triple-pipeline pattern (consensus / config / perf each define
their own `Network` enum), with two of them carrying signet and the
third — the operator-facing one — missing it. This is precisely the
shape of "wiring-look-but-no-wire" the fleet has tracked since W138:
SIGNET params are there, the consensus enum has `.signet`, but the
operator-facing entry-point cannot reach them.

**File:** `src/main.zig:158-163` (`Config.Network` missing signet);
`src/perf.zig:130-145` (third copy, has signet but uses non-default
discriminant `signet = 3`).

**Core ref:** `bitcoin-core/src/util/chaintype.h` (single
`enum class ChainType { MAIN, TESTNET, TESTNET4, SIGNET, REGTEST }`
used everywhere).

**Impact:** combined with BUG-9, signet is doubly unreachable: no CLI
flag selects it, and even if one did the bridging enum cannot represent
the choice.

---

## BUG-12 (P0-CDIV) — `Config.getNetworkParams` switch has no `.signet` arm; would be `unreachable` even if Config.Network gained the tag

**Severity:** P0-CDIV (consequence of BUG-11 but logged separately
because the switch itself is the second leg of the two-pipeline gap).

`main.zig:167-189` builds the consensus-side `NetworkParams` from the
config-side `Network` value via a 4-arm `switch`:
```zig
const base = switch (self.network) {
    .mainnet => &consensus.MAINNET,
    .testnet => &consensus.TESTNET,
    .testnet4 => &consensus.TESTNET4,
    .regtest => &consensus.REGTEST,
};
```
Zig's exhaustive-switch checking means this code compiles
**because** `Config.Network` does not have `.signet`. The moment the
BUG-11 fix adds `.signet` to `Config.Network`, this switch will fail
to compile with "switch must handle all possibilities". A follow-up fix
must add the arm:
```zig
.signet => &consensus.SIGNET,
```
Logging this so a partial BUG-11 fix doesn't leave the build broken.

**File:** `src/main.zig:167-189`.

**Core ref:** `bitcoin-core/src/init.cpp` (`ChooseChain(ChainType)`
dispatch).

**Impact:** structural — this is the second leg of BUG-11; both must
land together.

---

## BUG-13 (P1) — Signet DNS seed list is 1 entry; Core ships 2

**Severity:** P1. Bitcoin Core's default-signet DNS seeds
(`kernel/chainparams.cpp:419-421`):
```cpp
vSeeds.emplace_back("seed.signet.bitcoin.sprovoost.nl.");
vSeeds.emplace_back("seed.signet.achownodes.xyz.");
```

clearbit's `SIGNET.dns_seeds` (`consensus.zig:718-720`):
```zig
.dns_seeds = &[_][]const u8{
    "seed.signet.bitcoin.sprovoost.nl",
},
```
Only one of the two Core seeds. The achownodes.xyz seed (operated by Ava
Chow) is the redundancy: when sprovoost.nl is down, mining and IBD
restart on a fresh datadir would have no peer-discovery path. With one
seed, clearbit signet nodes have a single point of failure for initial
peer-discovery.

**File:** `src/consensus.zig:718-720`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:419-421`.

**Impact:** signet IBD bootstrap failure-mode: if
`seed.signet.bitcoin.sprovoost.nl` is unreachable (DNS outage, network
partition), clearbit cannot find peers and IBD does not start.

---

## BUG-14 (P1) — `SIGNET.min_chain_work` is wildly stale relative to Core

**Severity:** P1. Bitcoin Core's signet
`nMinimumChainWork` (`kernel/chainparams.cpp:423`):
```cpp
consensus.nMinimumChainWork =
    uint256{"00000000000000000000000000000000000000000000000000000b463ea0a4b8"};
```

clearbit's `SIGNET.min_chain_work` (`consensus.zig:739`):
```zig
.min_chain_work = hexToHash("0000000000000000000000000000000000000000000000000000000100000000"),
```

These differ by **3.5 orders of magnitude** (`0x0b463ea0a4b8` ≈
`1.24e13` vs `0x100000000` = `0x100000000` ≈ `4.29e9`). The Core value
corresponds to the cumulative chain work at default-signet
`defaultAssumeValid` height 293,175; the clearbit value looks like an
arbitrary placeholder from network bring-up time.

Effect: clearbit's anti-DoS minimum-chain-work gate would accept any
peer's headers showing only ~4 billion work units — the gate is
effectively disabled for serious chain-takeover attacks at default-signet
scale.

**File:** `src/consensus.zig:739`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:423`.

**Impact:** anti-DoS headers gate is ~3000x looser than Core; a
low-work fork chain would not be filtered at headers-sync.

---

## BUG-15 (P1) — `MinBIP9WarningHeight` not represented in `NetworkParams`

**Severity:** P1. Bitcoin Core's `Consensus::Params` carries an
`int MinBIP9WarningHeight` (`consensus/params.h:112`) — the height
below which the node should NOT emit "unknown BIP9 deployment active"
warnings. The constant is per-network:
- mainnet: 711648 (taproot activation + 2016 confirmation window),
- testnet3: 2013984,
- testnet4: 0,
- signet: 0,
- regtest: 0.

The field is consumed by `versionbitscache.cpp::AlertBlockMessages`,
which raises a console warning whenever a block carries unknown version
bits and the height is at or above `MinBIP9WarningHeight`. Without it,
clearbit either:
- never warns (false-negative for soft-fork-activation observation), or
- warns on every block from genesis (false-positive flood on
  mainnet's early-2009 era blocks that legitimately carried `nVersion=1`
  bits the BIP9 framework reserves).

clearbit's `NetworkParams` (`consensus.zig:361-442`) has no
`min_bip9_warning_height` field; grep confirms zero occurrences in
`src/`. The warning channel is silently absent.

**File:** absent from `src/consensus.zig` `NetworkParams`.

**Core ref:** `bitcoin-core/src/consensus/params.h:112`,
`bitcoin-core/src/versionbits/cache.cpp` (consumer).

**Impact:** operator visibility gap; soft-fork-activation monitoring
on mainnet would not surface unknown bits.

---

## BUG-16 (P1) — `MAX_TIMEWARP` doc-comment says "testnet4 only" — directly contradicts Core miner-side application on all networks

**Severity:** P1 ("comment-as-confession" fleet pattern, 13th+ distinct
clearbit instance). `consensus.zig:162-166`:
```zig
/// Maximum number of seconds that the timestamp of the first block of a
/// difficulty adjustment period is allowed to be earlier than the last
/// block of the previous period (BIP-94 timewarp prevention, testnet4 only).
/// Reference: bitcoin-core/src/consensus/consensus.h:35.
pub const MAX_TIMEWARP: u32 = 600;
```
The "testnet4 only" qualifier is true for the **consensus-side check**
(only the testnet4 `enforce_BIP94 = true` triggers
`validation.cpp:4097-4105`), but **false for the miner-side use** —
Core's `node/miner.cpp:43-44` calls `pindexPrev->GetBlockTime() -
MAX_TIMEWARP` on every network, with the source comment **"Account for
BIP94 timewarp rule on all networks. This makes future activation
safer."**

The clearbit doc misleads anyone implementing the miner-side gate
(BUG-6) into thinking the constant only matters on testnet4 — it
would lead an implementer to skip the all-networks clamp. The bug is
the doc-comment narrowing the scope below Core's. Fix: rephrase to
"used by both the consensus-side check (testnet4 only via
`enforce_BIP94`) and the miner-side template clamp (all networks for
defense-in-depth)".

**File:** `src/consensus.zig:162-165`.

**Core ref:** `bitcoin-core/src/consensus/consensus.h:35`;
`bitcoin-core/src/node/miner.cpp:41-44` (the all-networks comment).

**Impact:** documentation directs future implementers away from the
correct fix for BUG-6.

---

## BUG-17 (P1) — Comment says "signet uses block signing instead of PoW" — but the implementation lacks any signing path

**Severity:** P1 ("comment-as-confession", 14th distinct clearbit
instance). `consensus.zig:704-706`:
```zig
/// Signet parameters.
/// Note: Signet uses block signing instead of PoW, but we still define PoW params.
pub const SIGNET = NetworkParams{
    .magic = 0x0a03cf40, // Derived from challenge script hash
```
The comment **acknowledges** that signet replaces PoW with a signature
check — but the actual implementation (BUG-1, BUG-2, BUG-3, BUG-4)
contains zero signature-checking code. The author understood the
protocol's distinguishing feature and left a note about it, then
omitted the gate that implements the feature. This is the same shape
as W145 BUG-6 ("totalfee = coinbase - subsidy with negative-clamp" —
the comment admits the danger then commits the bug) and W144 BUG-12
("comment-as-confession 5th instance literally documents the bug it
perpetuates").

The "// Derived from challenge script hash" sub-comment on the magic
constant is also a confession that signet magic is normally
challenge-derived (so a custom-signet `-signetchallenge` would change
the magic) — and yet the magic is a hard-coded compile-time constant
(BUG-10).

**File:** `src/consensus.zig:704-707`.

**Core ref:** N/A; comment-shape catalogue.

**Impact:** documentation reveals the author was aware of the gap; the
code does not close it.

---

## BUG-18 (P0-CDIV) — `Pow_no_retarget` not enabled for signet despite signet retarget being PoW-less

**Severity:** P0-CDIV (subtle; signet retarget IS active in Core
because signet's PoW IS still validated as a low-difficulty proof
alongside the signature — but clearbit's
`calculateNextWorkRequiredBip94` path means signet-retarget blocks
would have their `nBits` recomputed by `multiplyTargetByRatio` against
the unusual signet `pow_limit = 0x00000377ae00…`).

Both Core and clearbit set `signet.fPowNoRetargeting = false` /
`signet.pow_no_retarget = false`. That part is consistent. The bug is
more subtle: clearbit's `multiplyTargetByRatio` uses the standard
`pow_limit` clamp — but the signet `pow_limit` `0x00000377ae00…` is
NOT a "round number" target like the testnet `0x00000000ffff…`. The
`bitsToTarget`/`targetToBits` round-trip through the compact encoding
loses precision on non-canonical targets, which means clearbit's
re-derived retarget bits for a signet retarget will differ from Core's
by 1-2 ULPs at the compact-bits resolution. The probability that a
signet block proper signature happens to ALSO meet the slightly-different
target is high but not 100%; on the rare retarget where it doesn't,
clearbit will reject the block.

This is testable today (signet retarget block in the wild +
`checkDifficulty` round-trip on clearbit) but logged as P0-CDIV pending
that exercise. Likely outcome: chain-stall at the first signet
retarget where the round-tripped target differs.

**File:** `src/validation.zig:2025-2042` (`checkDifficulty` retarget
arm).

**Core ref:** `bitcoin-core/src/pow.cpp:50-85`
(`CalculateNextWorkRequired`).

**Impact:** likely a sub-rare signet retarget chain-stall if any of
the other signet bugs (BUG-1..4) are ever fixed and clearbit reaches a
retarget on signet.

---

## BUG-19 (P1) — Signet `pow_allow_min_difficulty_blocks = false` matches Core, but signet's actual difficulty rules are NOT PoW-derived

**Severity:** P1 (logged for fleet-pattern continuity). Core and
clearbit both set `signet.fPowAllowMinDifficultyBlocks = false`, which
is technically the right value because signet keeps the regular
difficulty-pipeline semantics. But signet's actual block-validity rule
is the signature, not the PoW — so this field's value is fundamentally
a no-op for any signet block whose signature is valid. The fact that
clearbit COPIED this Core constant without acknowledging that the
constant is irrelevant on signet shows the SIGNET params block was
constructed from a template (likely TESTNET3 minus the fixedseeds list
plus the unusual `pow_limit`) rather than from a careful read of
Core's `SigNetParams`.

This is a smell, not a bug — but it correlates with the BUG-1..4
absence: if SIGNET had been carefully constructed, the
`signet_challenge` field would have been the FIRST thing added.

**File:** `src/consensus.zig:734`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:463`.

**Impact:** smell only; no behavioural impact.

---

## BUG-20 (P1) — `BLOCK_SCRIPT_VERIFY_FLAGS` constant for signet block-solution script is undefined

**Severity:** P1 (consequence of BUG-1, but separately catalogued as
the script-flag primitive). Core's `signet.cpp:30`:
```cpp
static constexpr script_verify_flags BLOCK_SCRIPT_VERIFY_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY;
```
This is the bundle of script-verify flags applied to the signet block
SIGNATURE verification (separate from the per-tx script flag mux of
W144). It is a fixed bundle — NOT inherited from the block's
`GetBlockScriptFlags`. Notably missing: `SCRIPT_VERIFY_CLEANSTACK`,
`SCRIPT_VERIFY_TAPROOT`, `MINIMALIF`, the W144 STANDARD-set flags. The
signet block signature is signed/verified under a deliberately narrow
flag set so future script-rule changes don't accidentally invalidate
historical signet blocks.

clearbit has nothing analogous because BUG-1/4 mean the verifier itself
doesn't exist. When BUG-1 is fixed, the implementer must define this
constant separately and NOT route through the block's normal
script-flag derivation.

**File:** absent from `src/script.zig`, `src/validation.zig`.

**Core ref:** `bitcoin-core/src/signet.cpp:30`.

**Impact:** when BUG-1 is fixed, this is the trap to avoid: re-using
the block's normal script-flag derivation would silently break older
signet blocks that were signed under the narrower flag set.

---

## BUG-21 (P0-CDIV) — Genesis-block fast-path skip in CheckSignetBlockSolution is missing-by-construction

**Severity:** P0-CDIV (consequence of BUG-1). Core's
`CheckSignetBlockSolution` (`signet.cpp:128-131`):
```cpp
if (block.GetHash() == consensusParams.hashGenesisBlock) {
    // genesis block solution is always valid
    return true;
}
```
The signet genesis block carries an empty (or invalid) signet solution
because it pre-dates the signing key — every signet chain accepts its
own genesis without running the signature check. When BUG-1 is fixed,
the implementer must add this fast-path skip first, or the new
validator will reject signet's own genesis block and the node will
refuse to start.

**File:** absent (no helper exists yet).

**Core ref:** `bitcoin-core/src/signet.cpp:128-131`.

**Impact:** when BUG-1 is fixed, omitting this fast-path makes the
signet genesis block invalid → node refuses to start on signet → IBD
failure.

---

## BUG-22 (P1) — `signet.assume_utxo` table is empty (carry-forward from W102 G27)

**Severity:** P1. Bitcoin Core's `SigNetParams::m_assumeutxo_data`
carries two snapshots (heights 160,000 and 290,000 per the W102 G27
test). clearbit's `SIGNET.assume_utxo` is an empty slice (line 741):
```zig
.assume_utxo = &[_]AssumeUtxoData{},
```
This means `loadtxoutset` on signet has no valid snapshot whitelist;
operators cannot fast-bootstrap a signet node from a Core-published
snapshot.

Cross-cite: W102 G27 already flagged this (`tests of storage.zig:11166-11173`).
Now re-anchored at W157 scope because the signet IBD path is incomplete
without it.

**File:** `src/consensus.zig:741`; `src/storage.zig:11166-11173`
(test confirming gap).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:425-426`
(`m_assumed_blockchain_size = 24`).

**Carry-forward:** W102 G27. Logged here as W157 follow-on.

**Impact:** signet operators cannot use `loadtxoutset` to bootstrap.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CONS:** 4 (BUG-1, BUG-2, BUG-3, BUG-4)
- **P0-CDIV:** 6 (BUG-5, BUG-6, BUG-7, BUG-9, BUG-11, BUG-12, BUG-18, BUG-21)

Recount P0-CDIV: BUG-5, BUG-6, BUG-7, BUG-9, BUG-11, BUG-12, BUG-18,
BUG-21 = 8. P0-CONS: BUG-1, BUG-2, BUG-3, BUG-4 = 4. P1: BUG-8, BUG-10,
BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19, BUG-20, BUG-22 = 10.

Total: 4 + 8 + 10 = 22. ✓

**P0-class total:** 12 (4 P0-CONS + 8 P0-CDIV).

**Fleet patterns confirmed:**
- **30-of-30-gates-buggy 10th candidate** — 30 sub-gates audited, 22
  distinct bugs (12 P0-class); clearbit's tenth consecutive quad-audit
  with high P0 concentration since W138.
- **signet-CheckSignetBlockSolution-absent** — fleet-wide pattern
  (blockbrew W143 BUG-9 + clearbit W157 BUG-1 = **2-of-10 confirmed**;
  next quad-audits should sweep remaining 8 impls). P0-CONS class:
  signet is **completely insecure** without this gate.
- **wiring-look-but-no-wire** (BUG-9 + BUG-11 + BUG-12) — `SIGNET`
  params constructed at compile-time, `.signet` enum tag exists in
  `consensus.Network`, but the operator-facing `Config.Network` enum
  cannot represent the choice, the `parseArgs` flag is absent, and
  the `getNetworkParams` switch has no arm. Three independent gaps
  that ALL must close to reach the params.
- **three-pipeline drift** (BUG-11) — `consensus.Network` (5 members),
  `Config.Network` (4 members, signet missing), `perf.Network`
  (4 members with `signet = 3` non-default discriminant). Same `Network`
  concept defined three times with different memberships and
  discriminant schemes.
- **two-pipeline guard** (BUG-5/6/7) — consensus-side BIP-113/BIP-94
  gates ARE enforced in `validateBlockForIBD`, but miner-side
  GetMinimumTime is absent. **17th distinct clearbit instance.**
- **comment-as-confession** (BUG-16 "testnet4 only" + BUG-17 "signet
  uses block signing instead of PoW") — **13th and 14th distinct
  clearbit instances** of the pattern.
- **22-wave carry-forward** (BUG-7 re-anchor of W154 BUG-13 / W123
  BUG-6 / W108 BUG-5: GBT mintime+curtime collision) — same root
  pattern (W154 BUG-1 placeholder bits, W154 BUG-3 raw wall clock)
  finally surfacing at the signet/BIP-94 scope.
- **dead-data plumbing** (BUG-15 MinBIP9WarningHeight) — Core
  consumes the field in `versionbitscache::AlertBlockMessages`;
  clearbit's field absence means the warning channel never fires.
  **9th distinct clearbit instance.**

**Top three findings:**

1. **BUG-1 + BUG-2 + BUG-3 + BUG-4 cluster (P0-CONS, signet is
   completely insecure)** — `CheckSignetBlockSolution`, `SIGNET_HEADER`,
   `signet_challenge` chain-param field, and the three helper functions
   are **all absent**. clearbit has zero signature-checking code on the
   signet path. The four bugs form a single architectural gap: the
   entire BIP-325 protocol surface is missing. Combined effect:
   anyone can mine and broadcast a 4-byte-PoW header that meets
   signet's trivial `pow_limit` and clearbit accepts it — chain
   takeover, double-spends, reorgs are wide open. This matches
   blockbrew W143 BUG-9 ("signet block accepts any PoW-valid block,
   forks off signet at block 1") and confirms a **fleet-wide
   2-of-10 signet-helper-absent pattern**.

2. **BUG-5 + BUG-6 + BUG-7 + BUG-8 cluster (P0-CDIV, mining bricks on
   clock-drift + miner-side BIP-94 absent everywhere)** —
   `block_template.zig:430-437` constructs the header with a raw
   `std.time.timestamp()` and no `GetMinimumTime` analogue. On any
   network where the wall clock is even 1s behind parent's MTP, the
   block is born invalid. On testnet4 retarget blocks with the clock
   600s+ behind parent, the consensus-side BIP-94 gate also rejects.
   GBT `mintime` AND `curtime` are both set to the same wall-clock
   value so miners cannot distinguish the protocol floor from the
   current suggestion. UpdateTime equivalent absent so testnet
   min-difficulty exception cannot be entered mid-template. Together
   these four bugs make clearbit's mining path effectively non-functional
   under any non-trivial network condition. **22-wave carry-forward
   from W108 BUG-5 / W123 BUG-6 / W154 BUG-1/3/11/13.**

3. **BUG-9 + BUG-11 + BUG-12 cluster (P0-CDIV, signet is unreachable
   via CLI)** — `--signet` / `--signetchallenge` / `--signetseednode`
   flags are absent from `parseArgs`; `Config.Network` enum has no
   `.signet` tag; `getNetworkParams` switch has no `.signet` arm.
   Three independent gaps that ALL must close together. SIGNET
   `NetworkParams` is a perfectly-constructed compile-time constant
   with zero call sites. Even fixing BUG-1..4 above wouldn't help —
   the operator can't tell clearbit "run on signet" in the first
   place. This is the **wiring-look-but-no-wire** fleet pattern
   applied to network selection itself: parts exist, but the
   operator-facing entry point is absent.
