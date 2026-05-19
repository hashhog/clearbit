# W154 — CreateNewBlock + BlockAssembler + block template construction (clearbit)

**Wave:** W154 — `BlockAssembler::CreateNewBlock` / `resetBlock` /
`addPackageTxs` / `AddToBlock` / `TestPackage` / `TestPackageTransactions`
/ `IncrementExtraNonce` / `RegenerateCommitments` /
`GenerateCoinbaseCommitment` / `BlockMerkleRoot` / `BlockWitnessMerkleRoot`
/ `pblocktemplate->vTxFees / vTxSigOpsCost` / `nBlockMaxWeight`
(`DEFAULT_BLOCK_MAX_WEIGHT`) / `nBlockSigOpsCost` / `lastFewTxs` /
`MAX_BLOCK_WEIGHT=4000000` / `WITNESS_SCALE_FACTOR=4` /
`DEFAULT_BLOCK_RESERVED_WEIGHT=8000` /
`MINIMUM_BLOCK_RESERVED_WEIGHT=2000` / `MAX_CONSECUTIVE_FAILURES=1000` /
`BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000` / `m_lock_time_cutoff` (parent
MTP) / `GetAdjustedTime` (nTime) / `GetNextWorkRequired` (nBits) /
`ComputeBlockVersion` (BIP-9 versionbits) / `GetMinimumTime` (mintime
GBT field) / `GBT.default_witness_commitment` / `GBT.coinbasetxn` /
`GBT.coinbaseaux` / `GBT.longpollid` / `GBT.vbavailable` / `GBT.vbrequired`
/ `GBT.rules` / `GBT.sigoplimit` / `GBT.sizelimit` / `GBT.weightlimit` /
`GBT.transactions[].depends / .sigops / .hash` / signet
`signet_solution_payload` / `generatetoaddress` / `generatetodescriptor`
/ `generateblock` / `submitblock` / `prioritisetransaction` mining-side
effect / `TestBlockValidity` post-build / `pblock->nTime` clamp at
`pblockindex->GetMedianTimePast()`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.cpp:79-88::ClampOptions` —
  `block_reserved_weight = clamp(opts.block_reserved_weight,
  MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT)`;
  `nBlockMaxWeight = clamp(opts.nBlockMaxWeight, block_reserved_weight,
  MAX_BLOCK_WEIGHT)`.
- `bitcoin-core/src/node/miner.cpp:96-127::resetBlock` — seeds
  `nBlockWeight = *Assert(m_options.block_reserved_weight)` and
  `nBlockSigOpsCost = 0`; clears `pblocktemplate->vTxFees / vTxSigOpsCost`.
- `bitcoin-core/src/node/miner.cpp:134-204::CreateNewBlock` —
  full assembler pipeline:
  - `pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus())`
    via BIP-9 versionbits state machine,
  - `pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1,
    TicksSinceEpoch<std::chrono::seconds>(time::GetAdjustedTime()))`,
  - `pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus())`,
  - `m_lock_time_cutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS &
    LOCKTIME_MEDIAN_TIME_PAST) ? pindexPrev->GetMedianTimePast() :
    pblock->GetBlockTime()`,
  - `addPackageTxs(*pblock, *m_mempool, m_lock_time_cutoff,
    nPackagesSelected, nDescendantsUpdated)` (package-feerate selection),
  - `coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0` (BIP-34),
  - `coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight,
    consensusParams)`,
  - `coinbaseTx.nLockTime = (uint32_t)nHeight - 1` (anti-fee-sniping),
  - `coinbaseTx.vin[0].nSequence = MAX_SEQUENCE_NONFINAL`,
  - `pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx))`,
  - `pblock->hashMerkleRoot = BlockMerkleRoot(*pblock)` (final),
  - `m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev)`,
  - `TestBlockValidity(state, chainparams, *m_chainstate, *pblock,
    pindexPrev, GetAdjustedTime, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)`
    (post-build dry-run against ConnectBlock).
- `bitcoin-core/src/node/miner.cpp:241-283::TestChunkBlockLimits` —
  weight: `if (nBlockWeight + chunk.size >= m_options.nBlockMaxWeight)
  return false`; sigops: `if (nBlockSigOpsCost + chunk.sigops >=
  MAX_BLOCK_SIGOPS_COST) return false`. **`>=` not `>`.**
- `bitcoin-core/src/node/miner.cpp:284-333::addChunks` (formerly
  addPackageTxs in cluster mempool) — early-exit on
  `chunk_feerate < blockMinFeeRate` (m_options.blockMinFeeRate);
  `MAX_CONSECUTIVE_FAILURES + BLOCK_FULL_ENOUGH_WEIGHT_DELTA` give-up.
- `bitcoin-core/src/node/miner.h:32-37` —
  `DEFAULT_BLOCK_MAX_WEIGHT = MAX_BLOCK_WEIGHT - 4_000`;
  `DEFAULT_BLOCK_RESERVED_WEIGHT = 8_000`;
  `MINIMUM_BLOCK_RESERVED_WEIGHT = 2_000`.
- `bitcoin-core/src/consensus/consensus.h:13,15,17,21` —
  `MAX_BLOCK_SERIALIZED_SIZE=4000000`, `MAX_BLOCK_WEIGHT=4000000`,
  `MAX_BLOCK_SIGOPS_COST=80000`, `WITNESS_SCALE_FACTOR=4`.
- `bitcoin-core/src/validation.cpp::GenerateCoinbaseCommitment` —
  if there are any witness-bearing txs, appends an
  `OP_RETURN OP_PUSH36 0xaa21a9ed <commit32>` output to the coinbase
  and sets `coinbaseTx.vin[0].scriptWitness.stack[0]` to a 32-byte
  zero nonce (BIP-141 witness reserved value).
- `bitcoin-core/src/consensus/merkle.cpp::BlockMerkleRoot` /
  `BlockWitnessMerkleRoot` — coinbase's wtxid is hard-coded to zero32
  in the witness merkle.
- `bitcoin-core/src/rpc/mining.cpp::getblocktemplate` (lines ~600-1030) —
  emits `capabilities`, `version`, `rules`, `vbavailable`, `vbrequired`,
  `previousblockhash`, `transactions[].data/txid/hash/depends/fee/sigops/weight`,
  `coinbaseaux`, `coinbasevalue`, `coinbasetxn` (when proposal
  capability negotiated), `longpollid`, `target`, `mintime`, `mutable`
  (`["time","transactions","prevblock","coinbase/append",
  "version/force","submit/coinbase"]`), `noncerange`, `sigoplimit`,
  `sizelimit`, `weightlimit`, `curtime`, `bits`, `height`,
  `default_witness_commitment`, `signet_challenge` (signet only).
- `bitcoin-core/src/rpc/mining.cpp:849-856::getblocktemplate` —
  refuses GBT call without `rules: ["segwit"]` (or
  `["segwit","signet"]` on signet chain).
- `bitcoin-core/src/rpc/mining.cpp:264-302::generatetoaddress` —
  NOT restricted to regtest in Core; available on any chain
  (hidden / advanced operator use).
- `bitcoin-core/src/rpc/mining.cpp:1024-1030` — emits
  `default_witness_commitment` for miners to drop into their
  hand-rolled coinbase when assembling outside getblocktemplate.
- `bitcoin-core/src/node/miner.cpp:185-194` — coinbase scriptSig
  is BIP-34 height push + dummy extranonce; the 2-byte minimum
  (`bad-cb-length` rule) is enforced by tx_check.cpp:49 at
  `2 <= scriptSig.size() <= 100`.

**Files audited**
- `src/block_template.zig` (3,011 lines) — `BlockTemplate`,
  `clampOptions` (line 191), `createBlockTemplate` (line 217),
  `constructCoinbaseWithCommitment` (line 468),
  `constructCoinbase` (line 590 — legacy/test-only),
  `buildCoinbaseScriptSig` (line 620), `encodeHeightPush` (line 639),
  `estimateSigops` (line 683), `computeWitnessCommitment` (line 701),
  `createWitnessCommitmentScript` (line 731),
  `isFinalTx` (line 762), `deriveSubmitHeight` (line 816),
  `submitBlockWithIndex` (line 861),
  `submitBlockWithIndexAndMempool` (line 885),
  `processSideBranchSubmission` (line 1191),
  `fireReorgFromSideBranch` (line 1361), `mineBlock` (line 1587),
  `mineBlockWithIndex` (line 1599), `assembleBlock` (line 1653),
  `generateBlocks` (line 1677),
  `generateBlockWithTxs` (line 1759), `estimateTxWeight` (line 1872).
- `src/consensus.zig` (3,451 lines) — `MAX_BLOCK_WEIGHT=4_000_000`
  (line 11), `MAX_BLOCK_SERIALIZED_SIZE=4_000_000` (line 15),
  `MAX_BLOCK_SIGOPS_COST=80_000` (line 19),
  `WITNESS_SCALE_FACTOR=4` (line 38), `INITIAL_SUBSIDY` /
  `SUBSIDY_HALVING_INTERVAL=210_000` (line 114),
  `subsidy_halving_interval` per-network (line 376, 508, 625, 679,
  730, 779), `getBlockSubsidy` (line 812), `bitsToTarget` (line 832),
  `getNextWorkRequired` (line 989), `computeBlockVersion` (line 2485).
- `src/validation.zig` (11,470 lines) — `checkBlock` (line 763),
  `acceptBlock` (line 1688), `validateCoinbaseHeight` (line 1842),
  `coinbase_value > subsidy` empty-body guard (line 836-839),
  `checkBlockHeader` (line 576), `getLegacySigOpCount`.
- `src/rpc.zig` (18,809 lines) — `handleGetBlockTemplate` (line 6065),
  `handleSubmitBlock` (line 6135), `handleGenerateToAddress` (line 6552),
  `handleGenerateToDescriptor` (line 6653), `handleGenerateBlock`
  (line 6752), `validateSubmitBlockOrReject` (line 6340).
- `src/mempool.zig:715-718,3597-3612,4429-4449` —
  `MempoolEntry.ancestorFeeRate()` (f64 `ancestor_fees / ancestor_size`),
  `getBlockCandidates` (sorts on raw ancestorFeeRate),
  `getBlockCandidatesByMiningScore` (cluster-aware, mining_score sort,
  **never called from production**).
- `src/main.zig` — no `-blockmaxweight` / `-blockreservedweight` /
  `-blockmintxfee` CLI flags.
- `src/tests_w123_mining_gbt.zig` — prior W123 audit (29 bugs across
  30 gates); used to verify carry-forward bugs and re-anchor severity.
- `src/tests_w108_gbt.zig` — earlier W108 audit; carry-forward source.

---

## Gate matrix (30 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR constants | G1: MAX_BLOCK_WEIGHT == 4_000_000 | PASS (`consensus.zig:11`) |
| 1 | … | G2: WITNESS_SCALE_FACTOR == 4 | PASS (`consensus.zig:38`) |
| 1 | … | G3: MAX_BLOCK_SIGOPS_COST == 80_000 | PASS (`consensus.zig:19`) |
| 2 | DEFAULT_BLOCK_RESERVED_WEIGHT / ClampOptions | G4: DEFAULT_BLOCK_RESERVED_WEIGHT == 8_000 | PASS (`block_template.zig:143`) |
| 2 | … | G5: MINIMUM_BLOCK_RESERVED_WEIGHT == 2_000 | PASS (`block_template.zig:147`) |
| 2 | … | G6: clamp(block_reserved_weight, MIN, MAX_BLOCK_WEIGHT); clamp(max_weight, block_reserved_weight, MAX_BLOCK_WEIGHT) | PASS (`block_template.zig:191-203`) |
| 3 | nBits derivation | G7: `pblock->nBits = GetNextWorkRequired(prev)` | **BUG-1 (P0-CDIV)** — `bits = params.genesis_header.bits` placeholder (`block_template.zig:233`); inline comment "Use genesis bits as placeholder" admits the bug. `getNextWorkRequired` EXISTS in consensus.zig but is NEVER called from createBlockTemplate. Carry-forward from W108 + W123 BUG-2. |
| 4 | nVersion derivation | G8: ComputeBlockVersion via BIP-9 versionbits state machine | **BUG-2 (P1)** — stub IndexView returns `null` for ALL heights (`block_template.zig:413-422`); the BIP-9 state machine has no historical block-version data and STARTED-state deployments cannot signal accurately. Comment confesses "clearbit's ChainState currently does not maintain a height-keyed version index ... the fast IBD path bypasses CF_BLOCK_INDEX". |
| 5 | nTime / GetAdjustedTime | G9: `pblock->nTime = max(parent_MTP+1, GetAdjustedTime())` | **BUG-3 (P0-CDIV)** — `block_template.zig:434` uses raw `std.time.timestamp()` (wall clock) and never takes `max(parent_MTP+1, now)`. No `GetAdjustedTime` peer-time-skew adjustment exists anywhere in src/. If wall-clock < parent_MTP+1, the constructed template's `nTime` violates BIP-113 (`time-too-old`) and the block is rejected at acceptBlock. |
| 6 | addPackageTxs / package-feerate selection | G10: ancestor-package selection (pick packages, not individual txs) | **BUG-4 (P0-CDIV)** — `block_template.zig:279-355` iterates `candidates` ONE TX AT A TIME by ancestor fee rate; no `addPackageTxs` / `AddToBlock` package walker exists. A child whose parent is in the mempool but NOT YET in the template gets added without its parent → block fails ConnectBlock with `bad-txns-inputs-missingorspent`. |
| 6 | … | G11: cluster mining_score primary sort | **BUG-5 (P0-CDIV)** — `block_template.zig:252` calls `mempool.getBlockCandidates` (raw ancestor fee rate, f64); the cluster-aware `getBlockCandidatesByMiningScore` exists at `mempool.zig:4431` but is NEVER called from the production mining path (well-engineered dead helper). Carry-forward from W123 BUG-1 + BUG-29. |
| 6 | … | G12: weight gate uses `>=` not `>` | PASS (`block_template.zig:316`, prior W123 PASS) |
| 6 | … | G13: sigops gate uses `>=` not `>` | PASS (`block_template.zig:330`, prior W123 PASS) |
| 6 | … | G14: MAX_CONSECUTIVE_FAILURES + BLOCK_FULL_ENOUGH_WEIGHT_DELTA early-exit | PASS (`block_template.zig:303-307, 318-321, 331-335`) |
| 7 | m_lock_time_cutoff (parent MTP for IsFinalTx) | G15: lock_time_cutoff = parent MTP, not wall clock | PASS (`block_template.zig:267-271`) |
| 7 | … | G16: topological / dependency ordering enforced | **BUG-6 (P0-CDIV)** — `block_template.zig:279-355` has no "parent-already-in-block?" check. The mempool's ancestor-fee-rate sort puts CHILDREN before PARENTS if a child's ancestor_fees / ancestor_size yields a higher rate than the parent alone. Block then fails ConnectBlock. |
| 8 | Coinbase scriptSig (BIP-34, 2..100 bytes) | G17: BIP-34 height push minimal | PASS (`block_template.zig:639-670`, plus W123 PASS pin) |
| 8 | … | G18: scriptSig 2..100 byte cap | PARTIAL — `constructCoinbaseWithCommitment` (`block_template.zig:495`) caps extra at `96 - script_sig.items.len`; Core's limit is 100 (BUG-7 below cosmetic, also: if `script_sig.items.len > 96` would underflow). |
| 8 | … | G19: coinbase nSequence == MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) | PASS (`block_template.zig:562`, plus W123 PASS pin) |
| 8 | … | G20: coinbase nLockTime == height-1 anti-fee-sniping | PASS (`block_template.zig:572`, plus W123 PASS pin) |
| 9 | GenerateCoinbaseCommitment (BIP-141 0xaa21a9ed) | G21: SHA256d(witness_merkle_root || nonce) → 38-byte OP_RETURN with 0xaa21a9ed magic | PASS for createBlockTemplate happy path (`block_template.zig:701-727`); but see BUG-8 for generateBlock break. |
| 9 | … | G22: coinbase witness has exactly one 32-byte zero nonce | PASS (`block_template.zig:546-553`, plus W123 PASS pin) |
| 9 | … | G23: generateblock RECOMPUTES witness commitment after tx swap | **BUG-8 (P0-CONS)** — `generateBlockWithTxs` (`block_template.zig:1804-1818`) literally writes `_ = witness_commitment;` after recomputing it; the original coinbase (built by createBlockTemplate for the EMPTY tx set) carries a stale all-tx-empty commitment. Block fails `bad-witness-merkle-match` at acceptBlock. Inline comment "Simplified: in full implementation would reconstruct coinbase" is comment-as-confession. **Identical to W142 BUG-3.** |
| 9 | … | G24: generateblock total_fees recomputed from supplied txs | **BUG-9 (P1)** — `block_template.zig:1797` writes `fee = 0` for every user-supplied tx; `total_fees` stays at the createBlockTemplate-time value (0 from empty mempool). The coinbase output value was fixed at `subsidy + 0` BEFORE the tx swap, so even if BUG-8 were fixed, miners forfeit all fees. (Note: Core's generateblock docs say "Transaction fees are not collected in the block reward", so this matches Core's documented behaviour for the RPC; cosmetic.) |
| 10 | GBT response shape (BIP-22/23) | G25: emits `rules`, `vbavailable`, `vbrequired`, `coinbaseaux`, `longpollid`, `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`, `default_witness_commitment` | **BUG-10 (P0-CDIV)** — `rpc.zig:6089-6130` emits ONLY `capabilities`, `version`, `previousblockhash`, `transactions[].data/txid/fee/weight`, `coinbasevalue`, `target`, `mintime`, `curtime`, `bits`, `height`, `mutable`. ALL ten of the above fields are absent. Per-tx `depends` and `sigops` are also missing. Carry-forward from W108 + W123 BUG-3. |
| 10 | … | G26: GBT refuses when `rules` lacks "segwit" / "signet" | **BUG-11 (P0-CDIV)** — `rpc.zig:6066` discards params entirely (`_ = params; // Template request params (capabilities, rules) - not fully implemented`). No rules validation. Core REJECTS the call without `["segwit"]` (since 2017). Carry-forward W123 BUG-4. |
| 10 | … | G27: GBT `payout_script` derived from request (not hardcoded) | **BUG-12 (P0-CONS funds-burn)** — `rpc.zig:6069` hardcodes `const payout_script = [_]u8{0x6a}; // OP_RETURN (placeholder)`. A miner that constructs+submits the returned template pays the full subsidy + fees to OP_RETURN → **all block reward burned**. Core takes payout from request `template_request.coinbase_value`; clearbit has no such plumbing. |
| 10 | … | G28: GBT `mintime` = parent MTP + 1 | **BUG-13 (P1)** — `rpc.zig:6125` emits `mintime = template.header.timestamp` (the assembler's wall-clock pick from BUG-3), not `parent_MTP + 1`. Carry-forward W108 + W123 BUG-6. |
| 11 | TestBlockValidity post-build | G29: post-build dry-run via `validation.acceptBlock` against current chainstate | **BUG-14 (P0-CDIV)** — there is no `TestBlockValidity` analog. `createBlockTemplate` returns the assembler's output un-validated; the caller (or operator) discovers consensus invalidity only on submit. |
| 12 | generatetoaddress / submit path | G30: `generateBlocks → mineBlockWithIndex → submitBlockWithIndex` routes through full `validation.acceptBlock` (Core ProcessNewBlock) | **BUG-15 (P0-CDIV)** — `block_template.zig:933` calls only `validation.checkBlock` (the CheckBlock half); the ContextualCheckBlock + ConnectBlock-equivalent half (`validation.acceptBlock`) is BYPASSED on the generatetoaddress / generateblock paths. Only the explicit `submitblock` RPC routes through `validateSubmitBlockOrReject → validation.acceptBlock` (`rpc.zig:6382`). Mining-rpc-bypasses-acceptBlock is companion to W148 carry-forward. |

Additional findings discovered outside the 30-gate matrix below
(BUG-16..BUG-22).

---

## BUG-1 (P0-CDIV) — Template `bits` is genesis_header.bits placeholder, not GetNextWorkRequired(prev)

**Severity:** P0-CDIV. Bitcoin Core sets
`pblock->nBits = GetNextWorkRequired(pindexPrev, pblock,
chainparams.GetConsensus())` (miner.cpp inside `CreateNewBlock`),
which runs the difficulty-adjustment algorithm and yields the
target the next block MUST meet.

clearbit's `createBlockTemplate` (`block_template.zig:230-234`)
literally does:

```zig
// 1. Compute difficulty target
// In production, this would use the full difficulty adjustment algorithm.
// For now, use a placeholder or the previous block's bits.
const bits: u32 = params.genesis_header.bits; // Use genesis bits as placeholder
```

The mining target for EVERY template is genesis difficulty. Effects:

- **Mainnet impact:** a real miner using GBT receives a target so easy
  it would always hash-meet on the first nonce, but the constructed
  block fails `validation.checkBlockHeader → calcNextWorkRequired
  mismatch` at submit time. Mining RPC is broken end-to-end.
- **Testnet4 impact:** same — first retarget at height 2016 onwards
  has a real bits value; clearbit's templates carry genesis bits
  forever. All templates rejected.
- **Regtest impact:** accidentally works because regtest's
  `genesis_header.bits = MAX_TARGET` is also the difficulty Core uses
  for every regtest block (no retarget). This is why W123 / generation
  tests pass.
- **`getNextWorkRequired`** is fully implemented at
  `consensus.zig:989-1056` — the helper EXISTS but the assembler does
  not call it.

**File:** `src/block_template.zig:230-234` (comment-as-confession +
no call site); `src/consensus.zig:989-1056` (helper exists,
unwired).

**Core ref:** `bitcoin-core/src/node/miner.cpp::CreateNewBlock` —
`pblock->nBits = GetNextWorkRequired(pindexPrev, pblock,
chainparams.GetConsensus())`.

**Carry-forward:** W108 BUG-3 + W123 BUG-2; still unfixed in W154
(now W154's 3rd anchor — **22-wave carry-forward streak**).

**Impact:** mining RPCs functionally dead on mainnet / testnet4 /
signet — every block submitted will be rejected with `bad-diffbits`
once past the first retarget.

---

## BUG-2 (P1) — `nVersion` derived from stub IndexView that returns null for ALL heights

**Severity:** P1. `block_template.zig:409-429` derives
`nVersion = computeBlockVersion(params.bip9_deployments, height,
&stub_view, null)` where `stub_view` is a closure that returns null
for every height lookup. The inline comment confesses:

```zig
// Limitation: accurate signaling requires per-height block version data for
// counting signals during STARTED periods. clearbit's ChainState currently
// does not maintain a height-keyed version index (the fast IBD path bypasses
// CF_BLOCK_INDEX). Until that index is wired, the state machine evaluates
// without historical signal data (all blocks appear as non-signaling in the
// backward walk).
```

Consequences:
- For a deployment in STARTED state, the backward walk that counts
  signaling blocks (Core's `Threshold + Period`) always finds 0 signals.
  The state machine never transitions STARTED → LOCKED_IN regardless
  of real miner support.
- For a deployment in LOCKED_IN state, the bit is correctly set
  (the state machine doesn't need historical data once locked in)
  — but the LOCKED_IN transition is unreachable from STARTED.
- ALWAYS_ACTIVE / NEVER_ACTIVE work fine (no counting needed).

**File:** `src/block_template.zig:409-429` (`StubCtx` returns null).

**Core ref:** `bitcoin-core/src/node/miner.cpp::CreateNewBlock` —
`pblock->nVersion = ComputeBlockVersion(pindexPrev,
chainparams.GetConsensus())` (real IndexView walks the block index).

**Carry-forward:** W123 BUG-27.

**Impact:** any future soft-fork deployment via BIP-9 versionbits
that clearbit miners need to signal for is silently inert. Cannot
participate in activation.

---

## BUG-3 (P0-CDIV) — `nTime` uses raw wall clock, no `GetAdjustedTime()` peer-skew adjustment, no `parent_MTP+1` clamp

**Severity:** P0-CDIV. Core's `CreateNewBlock` does:

```cpp
pblock->nTime = std::max(pindexPrev->GetMedianTimePast() + 1,
                         TicksSinceEpoch<seconds>(time::GetAdjustedTime()));
```

This guarantees:
- BIP-113: `nTime > parent_MTP` (consensus rule). Without the
  `max(..., parent_MTP+1)` clamp, a clock-behind node would emit a
  template that violates BIP-113 on first submit.
- Peer-time-skew tolerance: `GetAdjustedTime()` returns local time
  adjusted by the median peer time offset, capped by
  `MAX_TIMEDATA_SAMPLES` peers, so a single misconfigured local
  clock doesn't ship invalid templates.

clearbit's `block_template.zig:434` does:

```zig
.timestamp = @intCast(std.time.timestamp()),
```

— raw wall clock. No `getAdjustedTime` exists anywhere in src/. No
`max(parent_MTP+1, ...)` clamp. The assembler also computed
`mtp = chain_state.computeMTP()` 167 lines earlier for the
locktime-cutoff (`block_template.zig:267`) but doesn't reuse it
here.

**File:** `src/block_template.zig:434` (raw timestamp), 267 (MTP
already in hand, ignored for header.timestamp).

**Core ref:** `bitcoin-core/src/node/miner.cpp:170-173`
(`std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime())`);
`bitcoin-core/src/timedata.cpp::GetAdjustedTime`.

**Impact:**
- A clock-behind node ships templates that fail
  `time-too-old` at submit (`validation.zig::checkBlockHeader`
  BIP-113 check). Miner spins on rejection until clock catches up
  to MTP.
- A clock-ahead node (no peer-time tempering) can ship
  templates `> max_block_time_into_future` (Core's
  `MAX_FUTURE_BLOCK_TIME=2h`) and fail at peer-acceptance time
  on the receive side.
- Fleet-pattern: same shape as raw-clock-without-adjustment finding
  for nimrod W143 / haskoin W148 (operator-time-skew defense gap).

---

## BUG-4 (P0-CDIV) — No `addPackageTxs` / package-feerate selection; child-before-parent admission breaks ConnectBlock

**Severity:** P0-CDIV. Core's `addPackageTxs` (now `addChunks` post
cluster-mempool) selects mempool transactions in **package** units —
the ancestor closure of each candidate, sorted by package fee rate.
Each package is added as an atomic unit: if any tx in the package
fails the per-chunk gates (weight / sigops / lock_time), the whole
package is skipped. This guarantees:

1. Topological ordering: every tx's ancestors are already in the
   block when the tx is added.
2. Package-fee-rate optimality: the assembler always picks the
   highest-rate complete package, never a high-fee child whose
   parent is excluded.

clearbit's `block_template.zig:279-355` walks `candidates` one tx
at a time, sorted by raw `entry.ancestorFeeRate()`. The walk:
- adds individual tx if it fits;
- does NOT add the tx's ancestors first;
- does NOT verify the tx's parent is already in `selected`;
- does NOT skip the tx if its parent was excluded.

Failure modes:
- **Child-before-parent:** a child whose `ancestor_fees /
  ancestor_size` happens to rate higher than the parent alone gets
  added first. Block fails `validation.acceptBlock` with
  `bad-txns-inputs-missingorspent` (parent prevout not in UTXO set
  yet, since it's a mempool ancestor not a chain ancestor).
- **Skipped-parent cascade:** a parent that fails the weight gate
  later in the walk leaves the child orphaned. Block fails
  ConnectBlock for the same reason.
- **Package-fee-rate misorder:** a 100-sat parent + 1000-sat child
  (combined rate = ~550 sat/vB) ranks below a standalone
  600-sat tx, even though the parent+child package would be more
  profitable. Miners forfeit revenue.

**File:** `src/block_template.zig:217-355` (createBlockTemplate
single-tx walk).

**Core ref:** `bitcoin-core/src/node/miner.cpp:284-333::addChunks`
(cluster-mempool package-feerate selection); pre-cluster-mempool
`addPackageTxs` (same shape).

**Impact:**
- Mining RPC ships invalid templates whenever the mempool contains
  ancestor chains. Common case on mainnet (CPFP, BIP-125 RBF
  packages, walletbroadcast clusters).
- Fee revenue is suboptimal: ancestor-feerate ordering
  systematically undervalues parent+child packages.

---

## BUG-5 (P0-CDIV) — Primary candidate sort key is raw ancestor fee rate, not cluster mining_score; modified-fee (prioritisetransaction) not honoured

**Severity:** P0-CDIV. clearbit's mempool exposes two candidate
sources:

- `Mempool.getBlockCandidates(allocator)` at `mempool.zig:3597-3612`
  — sorts on `ancestorFeeRate() = f64(ancestor_fees) / f64(ancestor_size)`.
  `ancestor_fees` is the **stored** field from admission;
  prioritisetransaction map_deltas are NOT applied here.
- `Mempool.getBlockCandidatesByMiningScore(allocator)` at
  `mempool.zig:4431-4449` — cluster-aware, sorts on `mining_score`
  which DOES include the prioritise delta (FIX-72 wired
  getModifiedFee into the linearisation pass).

`block_template.createBlockTemplate` (`block_template.zig:252`)
calls **the raw-ancestor-fee variant**. The cluster-aware variant
is a 30-line "well-engineered dead helper" — exists, tests pass,
production never invokes it. This is the canonical
**"dead-helper-at-call-site"** fleet pattern (the 7th distinct
clearbit instance per the brief's tally, extending W117 + W118 +
W121 + W138 + W141 + W150 / W151 / W152 / W153 streak).

Operator-visible symptoms:
- `prioritisetransaction txid 0 +N_sat` is accepted, stored in
  `map_deltas`, and visible in `getprioritisedtransactions`. But
  the template walker never sees the delta — the prioritised tx
  ranks where its raw ancestor-feerate places it.
- The W123 BUG-1 + BUG-28 + BUG-29 triangle observation: FIX-72
  wired modified-fee into BOTH the cluster linearisation AND the
  block_min_fee_rate gate — but NOT into the primary sort. Net
  effect: prioritisation moves a tx INSIDE its cluster but does
  not move the cluster relative to other clusters.

**File:** `src/block_template.zig:252` (raw-ancestor call site);
`src/mempool.zig:4431-4449` (dead cluster helper).

**Core ref:** `bitcoin-core/src/node/miner.cpp:266-283` (cluster
mempool's `addChunks` consults the cluster chunk linearisation
which Core builds with prioritise-aware fee rate).

**Carry-forward:** W123 BUG-1 + BUG-29.

**Impact:**
- Prioritisation broken across cluster boundaries: an operator
  who prioritises a single tx in a low-rate cluster sees no
  template-level effect.
- Cross-impl divergence: a Core node receiving the same prioritise
  call would shift the template; clearbit doesn't.

---

## BUG-6 (P0-CDIV) — No topological / dependency ordering enforcement during selection

**Severity:** P0-CDIV (cross-cite BUG-4). Independent of BUG-4's
package-selection gap, the per-tx walker does not check whether
each candidate's mempool parents are already in `selected`.

```zig
for (candidates) |entry| {
    // ... fee gate, weight gate, sigops gate ...
    try selected.append(.{ .tx = entry.tx, ... });
}
```

No `parent_already_in_block(entry, selected)` predicate exists.
The walker can land children before parents whenever the
ancestor-feerate sort happens to interleave them. Core's analogous
code path (`addChunks`) is package-atomic — each chunk's
transactions are added in topological order by construction.

**File:** `src/block_template.zig:279-355`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:266-283::addChunks` —
chunks are added in topological order (chunk = ancestor closure of
one candidate).

**Impact:** cross-cite BUG-4. Independent finding because BUG-4 is
"no package selection at all" and BUG-6 is "even without packages,
no topological guard". Together they form one architectural gap.

---

## BUG-7 (P1) — Coinbase scriptSig extra-data cap is 96 (Core's is 100)

**Severity:** P1 (cosmetic / range-tightness). Core enforces
`scriptSig.size() <= 100` (consensus rule `bad-cb-length`,
tx_check.cpp:49). clearbit's `constructCoinbaseWithCommitment`
(`block_template.zig:495`) and `buildCoinbaseScriptSig`
(`block_template.zig:628`) cap extra data at:

```zig
const max_extra = @min(extra_data.len, 96 - script_sig.items.len);
```

Two issues:
- The cap is 96, not 100 — operators lose 4 bytes of legitimate
  coinbase metadata (pool name, ExtraNonce, etc.).
- The cap is `96 - script_sig.items.len`, which **underflows** to a
  near-`usize.max` value when `script_sig.items.len > 96`. Won't
  happen in practice (BIP-34 height push max 5 bytes + 1 OP_0 = 6
  bytes) but the math is wrong.

**File:** `src/block_template.zig:495, 628`.

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:49`
(`scriptSig.size() <= 100`).

**Impact:** cosmetic ergonomics; mining pools that brand
coinbase scriptSig with a 10..15-byte name + 8-byte extranonce +
counter clip into the 96-byte cap one byte earlier than Core.

---

## BUG-8 (P0-CONS) — `generateBlockWithTxs` recomputes witness commitment then DISCARDS it; coinbase carries stale empty-tx-set commitment

**Severity:** P0-CONS. `block_template.zig:1804-1818` in
`generateBlockWithTxs`:

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

The commitment is computed and immediately discarded (`_ =
witness_commitment;`). Inline comment is the literal confession.

Backstory:
1. `generateBlockWithTxs` calls `createBlockTemplate` first
   (`block_template.zig:1771`), which built the coinbase with
   `witness_commitment = computeWitnessCommitment(EMPTY_MEMPOOL,
   nonce, allocator)` — committing to the empty wtxid set.
2. `template.transactions.clearRetainingCapacity()` clears any
   selected txs (`block_template.zig:1784`).
3. User txs appended via `template.transactions.append` — but the
   coinbase OUTPUT (containing the witness commitment) was already
   built and is not rebuilt.
4. `mineBlockWithIndex → submitBlockWithIndex → validation.checkBlock`
   recomputes the witness commitment from the actual block tx set,
   compares to the coinbase OP_RETURN, and rejects with
   `bad-witness-merkle-match` (validation.zig:1893).

**File:** `src/block_template.zig:1804-1818`.

**Core ref:** `bitcoin-core/src/validation.cpp::GenerateCoinbaseCommitment`
+ `bitcoin-core/src/rpc/mining.cpp::generateblock` (rebuilds coinbase
after user txs are appended).

**Cross-cite:** W142 BUG-3 already flagged this exact symbol in the
W142 brief.

**Impact:**
- `generateblock` RPC is functionally dead when user supplies any
  non-empty `transactions` array. Every call returns
  `bad-witness-merkle-match` at submit.
- Operators / CI suites that use `generateblock` for reorg /
  precise-block tests cannot drive clearbit at all.

---

## BUG-9 (P1) — `generateBlockWithTxs` discards per-tx fees; total_fees stays at createBlockTemplate-time value

**Severity:** P1 (matches Core's documented `generateblock`
behaviour but is internally inconsistent). `block_template.zig:1797`
writes `fee = 0` for every user-supplied tx. The coinbase output
was constructed by `createBlockTemplate` at line 1771 with
`subsidy + total_fees(=0)` — so even after txs are appended, the
coinbase reward stays at pure subsidy regardless of user-supplied
tx fees.

Core's `generateblock` documentation explicitly states "Transaction
fees are not collected in the block reward", so the BEHAVIOUR is
intentional — but clearbit's IMPLEMENTATION reaches it through
"fee = 0 hack" rather than "Core deliberately ignores fees
post-construction".

**File:** `src/block_template.zig:1797`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:319` — generateblock
RPC docstring "Transaction fees are not collected in the block reward".

**Impact:** behaviour matches Core, but the internal contract
(fee accumulator should sum actual fees) is broken — any future
change to capture fees would need to fix both the accumulator AND
the coinbase reconstruction.

---

## BUG-10 (P0-CDIV) — GBT response missing 10+ BIP-22/23 fields (default_witness_commitment, longpollid, vbavailable, vbrequired, rules, coinbaseaux, noncerange, sigoplimit, sizelimit, weightlimit) + per-tx `depends`/`sigops`

**Severity:** P0-CDIV. `rpc.zig::handleGetBlockTemplate`
(`rpc.zig:6065-6132`) emits only 11 fields:

```json
{
  "capabilities": ["proposal"],
  "version": <i32>,
  "previousblockhash": "<hex>",
  "transactions": [{"data":"<hex>","txid":"<hex>","fee":<n>,"weight":<n>}, ...],
  "coinbasevalue": <n>,
  "target": "<hex>",
  "mintime": <n>,
  "curtime": <n>,
  "bits": "<hex>",
  "height": <n>,
  "mutable": ["time","transactions","prevblock"]
}
```

Bitcoin Core emits 22+ fields. **Missing**:

| Field | Core ref | Miner impact |
|-------|----------|--------------|
| `rules` | mining.cpp:994 | Miner can't tell which softforks are active |
| `vbavailable` | mining.cpp:978 | Miner can't enumerate signaling bits |
| `vbrequired` | mining.cpp:984 | Miner doesn't know which bits MUST be set |
| `coinbaseaux` | mining.cpp:1008 | No way to inject CSV / per-pool tags |
| `longpollid` | mining.cpp:990 | No long-poll → polling at fixed cadence |
| `noncerange` | mining.cpp:1015 | Miner can't tell which nonces are valid |
| `sigoplimit` | mining.cpp:1016 | Miner can't pre-check sigops budget |
| `sizelimit` | mining.cpp:1017 | Miner can't pre-check serialization size |
| `weightlimit` | mining.cpp:1018 | Miner can't pre-check weight budget |
| `default_witness_commitment` | mining.cpp:1030 | Miner has no segwit commit scriptPubKey — **cannot build valid post-segwit block** |
| per-tx `depends` | BIP-22 §8 | Miner can't reorder safely |
| per-tx `sigops` | BIP-22 §8 | Miner can't sigop-budget |
| per-tx `hash` (wtxid) | BIP-141 | Miner can't compute witness merkle |

The `default_witness_commitment` absence is the most consequential:
a stock-Core miner using clearbit's GBT cannot construct a valid
block because there is no way to know what the witness commitment
output's scriptPubKey should look like for the unmodified tx set.

**File:** `src/rpc.zig:6088-6131` (handleGetBlockTemplate body).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:600-1030`
(getblocktemplate response building).

**Carry-forward:** W108 BUG-1, W123 BUG-3.

**Impact:** stock Core miners cannot use clearbit's GBT at all.
Custom GBT-aware miners (cgminer/bfgminer/luxor) work only because
they're tolerant of missing optional fields — but lose long-poll,
prioritisation, and witness-commit semantics.

---

## BUG-11 (P0-CDIV) — `handleGetBlockTemplate` discards `params`; no `rules: ["segwit"]` validation

**Severity:** P0-CDIV. `rpc.zig:6066`:

```zig
_ = params; // Template request params (capabilities, rules) - not fully implemented
```

Core (since 2017, post-BIP-141 deployment) REQUIRES the GBT
request to include `rules: ["segwit"]` (or `["segwit", "signet"]`
on signet chain). Without it, Core returns:

```
getblocktemplate must be called with the segwit rule set
(call with {"rules": ["segwit"]})
```

clearbit accepts ANY (or no) `rules` value silently and emits a
template anyway. Two effects:

1. Stock miners (cgminer/bfgminer) refuse to use the template
   because the GBT version they speak (post-2017) expects the
   "rules" round-trip negotiation.
2. Signet-aware miners that pass `["segwit","signet"]` expecting
   a signet-shaped response (with `signet_challenge` field) get
   the same shape regardless.

**File:** `src/rpc.zig:6065-6066`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:849-856`.

**Carry-forward:** W123 BUG-4.

**Impact:** cross-cite BUG-10. Operator cannot upgrade from a
Core-compatible miner stack without source-patching clearbit's
GBT handler.

---

## BUG-12 (P0-CONS funds-burn) — GBT `payout_script` hardcoded to OP_RETURN; miner using template burns block reward

**Severity:** P0-CONS funds-burn. `rpc.zig:6069`:

```zig
// Create block template
const payout_script = [_]u8{ 0x6a }; // OP_RETURN (placeholder)
var template = block_template.createBlockTemplate(
    self.chain_state,
    self.mempool,
    self.network_params,
    .{
        .payout_script = &payout_script,
        .include_witness_commitment = true,
    },
    self.allocator,
) catch { ... };
```

The coinbase payout script is hardcoded to a single-byte
`OP_RETURN` (`0x6a`). The full block reward (`subsidy +
total_fees`) goes to this output. `OP_RETURN` outputs are
unspendable — **every satoshi mined this way is permanently
burned**.

A miner that:
1. Calls `getblocktemplate`,
2. Receives the OP_RETURN-paying template,
3. Mines a valid nonce,
4. Calls `submitblock`,

is destroying their full block reward (currently ~3.125 BTC
subsidy + fees). On mainnet at $80k/BTC, this is a ~$250k loss per
block.

Core's GBT response includes `coinbasevalue` only; the miner is
responsible for constructing the coinbase output independently
(based on their address / descriptor). clearbit's GBT
returns a template with the coinbase already constructed +
pointing at OP_RETURN — actively misleading.

**File:** `src/rpc.zig:6069`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` — Core's GBT
returns `coinbasetxn` (when proposal capability negotiated) with
the miner's address-derived scriptPubKey, OR emits only
`coinbasevalue` for the miner to construct the coinbase.

**Impact:** catastrophic for any operator that wires a real miner
to clearbit's getblocktemplate. The OP_RETURN burn is silent —
the block accepts, peers relay, the chain extends, and the miner
discovers the loss only by checking their wallet.

---

## BUG-13 (P1) — GBT `mintime` = `template.header.timestamp` (the wall-clock-pick from BUG-3), not `parent_MTP + 1`

**Severity:** P1. `rpc.zig:6125-6130` emits:

```zig
try writer.print("\",\"mintime\":{d},\"curtime\":{d},\"bits\":\"{x:0>8}\",\"height\":{d},...", .{
    template.header.timestamp,
    template.header.timestamp,
    ...
});
```

Both `mintime` and `curtime` are the same value — the assembler's
wall-clock pick (which has BUG-3 issues of its own). Core's GBT
emits:

- `mintime` = `pindexPrev->GetMedianTimePast() + 1` (the BIP-113
  floor; the earliest timestamp the miner is allowed to set);
- `curtime` = `GetAdjustedTime()` (the current peer-adjusted time;
  the recommended default).

Miners use `mintime` to safely roll the timestamp during nonce
exhaustion (Core's `UpdateTime` rewinds to `mintime` if local
clock drifts).

**File:** `src/rpc.zig:6125-6130`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1020-1022`.

**Carry-forward:** W108 BUG-4 + BUG-5; W123 BUG-6.

**Impact:** miner that rolls timestamp can underflow `parent_MTP`
and submit blocks rejected with `time-too-old`. Production miners
work around with `max(mintime, currentTime - 5min)` heuristics,
but those are non-portable.

---

## BUG-14 (P0-CDIV) — No `TestBlockValidity` post-build dry-run; assembler emits un-validated templates

**Severity:** P0-CDIV. Core's `CreateNewBlock` ends with:

```cpp
BlockValidationState state;
if (m_options.test_block_validity &&
    !TestBlockValidity(state, chainparams, *m_chainstate, *pblock,
                       pindexPrev, GetAdjustedTime,
                       /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
    throw std::runtime_error(...);
}
```

This runs the full ConnectBlock-equivalent (without PoW / merkle
check) against the current chainstate to catch:
- subtle sigops miscounts,
- a tx that was admitted to mempool but is no longer valid against
  the current UTXO,
- BIP-94 timewarp violations the assembler didn't catch,
- witness program validity edge cases.

clearbit's `createBlockTemplate` returns the assembled
`BlockTemplate` with no post-build validation. The first signal
that the template is consensus-invalid arrives at submit time,
which is too late on mining hardware that has spent kilowatts on a
nonce search.

**File:** `src/block_template.zig:447-458` (createBlockTemplate
return, no validity dry-run before).

**Core ref:** `bitcoin-core/src/node/miner.cpp:209-220`.

**Impact:**
- Miner wastes hash work on templates that fail consensus.
- The class of bugs that `TestBlockValidity` catches is exactly
  the class that `getblocktemplate` should never expose — e.g.
  BUG-1 (wrong bits) would have been caught immediately by the
  test pass.

---

## BUG-15 (P0-CDIV) — `generatetoaddress` / `generateblock` mining paths bypass `validation.acceptBlock`; only `submitblock` routes through the unified entry

**Severity:** P0-CDIV. clearbit has a unified block-acceptance
entry point at `validation.zig:1688::acceptBlock` (the "Core
ProcessNewBlock parity" shim documented in waves 3, 7, 8, 11, 15,
22, 23). The `submitblock` RPC routes through it via
`rpc.zig:6340::validateSubmitBlockOrReject → validation.acceptBlock`.

But the mining RPCs (`generatetoaddress`,
`generatetodescriptor`, `generateblock`) route through:

```
handleGenerateToAddress
  → block_template.generateBlocks
  → block_template.mineBlockWithIndex
  → block_template.submitBlockWithIndex
  → validation.checkBlock     ← ONLY THIS
  → chain_state.connectBlockFast / connectBlockFastWithUndo
```

`validation.checkBlock` is only the **CheckBlock** half of
`ProcessNewBlock`. The **ContextualCheckBlock** half (BIP-34 in
context, BIP-94 timewarp guard, prev_block_timestamp check,
fTooFarAhead height ceiling, signet challenge solution check)
and the **ConnectBlock** half (per-input UTXO availability, sigops
under MAX_BLOCK_SIGOPS_COST per-output, fee invariants,
script verification) are NOT run.

Cross-cite W148 (carry-forward note in the brief that
`activateBestChain` may be a TODO stub — IT IS implemented at
`validation.zig:6254` but the mining path doesn't reach it). The
operational impact is: a mined block that has, e.g., an invalid
script that would fail script verification is silently accepted by
the mining path, because `validation.checkBlock` doesn't run script
checks. Effectively, mining-by-RPC bypasses consensus.

**File:** `src/block_template.zig:933` (only `validation.checkBlock`
call), 1062-1093 (connectBlockFast directly); vs
`src/rpc.zig:6382` (submitblock routes through `validation.acceptBlock`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateBlocks`
(uses `Mining::processNewBlock` which IS the unified entry,
ProcessNewBlock).

**Impact:**
- Operators running `generatetoaddress` on testnet/regtest can
  produce blocks that would NEVER be accepted by a Core node.
  Tests that rely on clearbit's mined blocks passing through
  consensus then test divergent semantics.
- `submitblock` is the safe path; `generatetoaddress` /
  `generateblock` / `generatetodescriptor` are not.

---

## BUG-16 (P0) — `validation.checkBlock` coinbase-value > subsidy guard is dead-branch in consensus (empty body)

**Severity:** P0. `validation.zig:836-839`:

```zig
if (coinbase_value > subsidy) {
    // This is a conservative check - actual validation needs total fees
    // which are only known after validating all transactions
}
```

The `if` body is empty — no `return ValidationError.BadCoinbaseAmount`
emitted. Comment justifies the omission by noting that "actual
validation needs total fees" — but that's exactly what
`ConnectBlock`'s `nFees` check does for the real validation.
**`checkBlock` should not have the dead `if` at all** — either
remove it, or emit a conservative-upper-bound reject (since
`coinbase_value > subsidy + MAX_REASONABLE_FEES` is always
invalid). The current shape **misleads readers** into thinking
there's a coinbase-value check when there is none.

**File:** `src/validation.zig:836-839`.

**Core ref:** `bitcoin-core/src/validation.cpp::ConnectBlock`
(coinbase-value check happens at `nFees + subsidy >= blockReward`
post-input-validation).

**Cross-cite:** W143 BUG-16 (already flagged in the brief);
re-anchored here for the mining path.

**Pattern:** "dead-branch-in-consensus" — `if (condition) { /* empty */ }`
gives the reader the false impression of a guard. Fleet pattern
companion to "comment-as-confession" (this is the closer cousin
where the dead branch carries a comment that admits its
emptiness).

---

## BUG-17 (P1) — `mineBlockWithIndex` returns `null` on submit-failure but caller treats it as "exhausted tries"; `result.reject_reason` is dropped

**Severity:** P1. `block_template.zig:1635-1638`:

```zig
const result = try submitBlockWithIndex(&block, chain_state, params, chain_manager, allocator);
if (!result.accepted) {
    return null;
}
```

Then `generateBlocks` (`block_template.zig:1746-1748`):

```zig
} else {
    // Failed to mine block (exhausted tries)
    break;
}
```

The else branch is reached for two completely different reasons:
1. `mineBlockWithIndex` truly exhausted nonces (PoW failure).
2. `mineBlockWithIndex` found a valid nonce, submitBlock failed
   consensus, returned null.

In case 2, the caller's log message ("Failed to mine block —
exhausted tries") is misleading. The `result.reject_reason` is
discarded — operators have no way to diagnose WHY a regtest mine
failed. (Regtest difficulty is so low that case 1 is essentially
never the real cause; almost all failures are case 2, which the
log message hides.)

**File:** `src/block_template.zig:1635-1638, 1746-1748`.

**Impact:** debug ergonomics. Combined with BUG-15 (mining path
bypasses acceptBlock for most checks), the failures that DO surface
arrive via `validation.checkBlock`'s narrow reject set
(`bad-cb-length`, `bad-witness-merkle-match`, `bad-txnmrklroot`,
`bad-cb-height`, `bad-blk-sigops`, `bad-blk-weight`, `bad-blk-length`,
`high-hash`, `rejected`) — none of which the operator ever sees.

---

## BUG-18 (P1) — `generatetoaddress` / `generatetodescriptor` / `generateblock` reject non-regtest networks; Core does NOT restrict

**Severity:** P1 (parity gap). `rpc.zig:6555, 6655, 6754`:

```zig
if (self.network_params.magic != consensus.REGTEST.magic) {
    return self.jsonRpcError(RPC_MISC_ERROR,
        "generatetoaddress is only available in regtest mode", id);
}
```

Bitcoin Core does NOT restrict these RPCs to regtest. They're
marked as "hidden" RPCs (advanced operator use) but available on
any chain. Use cases:
- Signet maintainer mining (signet block solutions require an
  operator-held private key; generateblock against signet with
  pre-signed signet_solution_payload is the canonical workflow).
- testnet4 difficulty resets where a dev resets local difficulty
  and mines a few blocks via generateblock to flush stuck mempool
  for QA.
- Operator-driven test fixtures on testnet (e.g. RBF or CSV state
  machines that need explicit blocks at specific heights).

clearbit hard-blocks all three RPCs unless `regtest.magic` matches
exactly. Cross-impl divergence with Core.

**File:** `src/rpc.zig:6555, 6655, 6754`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:264-302::generatetoaddress`
+ `:305-380::generateblock` (no network restriction; only "hidden"
visibility).

**Impact:** signet operators cannot run signet block production
via clearbit; testnet4 QA workflows broken.

---

## BUG-19 (P1) — No signet support in mining path; no `signet_solution_payload` injection

**Severity:** P1. Signet block production requires the coinbase to
include a `signet_solution_payload` field (BIP-325) — a
signature from the signet operator's private key over the block's
modified Merkle root. clearbit's mining path has zero awareness of
signet:

- `createBlockTemplate` never injects a signet solution payload.
- `validation.checkBlock` doesn't enforce signet solution
  presence (and shouldn't on non-signet, but for signet it must).
- No `signet_challenge` field in GBT response.
- No `signet_solution_payload` parsing in `submitblock`.

Cross-cite W143 BUG-9 (signet block solution missing from
validation) — at the validation layer there's already a known gap;
this audit notes the same gap on the construction layer.

**File:** `src/block_template.zig` (entire file) — no `signet`
mention; `src/rpc.zig:6065-6132` (GBT) — no `signet_challenge`.

**Core ref:** `bitcoin-core/src/node/miner.cpp` —
`Mining::createNewBlock(... signet_solution_payload)` plumbing;
`bitcoin-core/src/validation.cpp::CheckSignetBlockSolution`.

**Impact:** clearbit cannot produce signet blocks, full stop.
Cross-cite BUG-18 (signet operator wanted to use generateblock
but it's regtest-only).

---

## BUG-20 (P1) — No `IncrementExtraNonce` helper; nonce-space exhaustion at u32::MAX has no extra-nonce continuation

**Severity:** P1. Core's `IncrementExtraNonce` (miner.cpp) is the
canonical helper for advancing the coinbase scriptSig extra-nonce
when the 32-bit nonce field is exhausted. Hardware miners iterate:

1. nonce 0..u32::MAX → if no solve, …
2. extra_nonce += 1, rebuild coinbase scriptSig, recompute coinbase
   txid, recompute merkle root, …
3. nonce 0..u32::MAX again → …

clearbit's `mineBlock` (`block_template.zig:1615-1647`) iterates
nonces u64 0..max_tries. When `tries > 0xFFFFFFFF`, the loop
**bumps `template.header.timestamp` by 1** (line 1644-1646)
instead of bumping the coinbase extra-nonce. Timestamp-bumping
is forbidden by BIP-113 to roll backwards (and capped by
`MAX_FUTURE_BLOCK_TIME=2h` on the high end), so this strategy
diverges from Core's behavior and cannot scale beyond a small
timestamp window.

**File:** `src/block_template.zig:1615-1647`.

**Core ref:** `bitcoin-core/src/node/miner.cpp::IncrementExtraNonce`.

**Impact:** regtest fine (always solves on first nonce). Real
mainnet/testnet mining via the assembler is impossible — the
nonce space exhausts in < 1 second on modern ASICs and clearbit
has no extra-nonce continuation.

---

## BUG-21 (P1) — Per-tx `weight` in GBT response uses cached mempool `entry.weight` not freshly recomputed `GetTransactionWeight(tx)`

**Severity:** P1. `rpc.zig:6110-6113`:

```zig
try writer.print("\",\"fee\":{d},\"weight\":{d}}}", .{
    tx.fee,
    tx.weight,
});
```

`tx.weight` is the cached `SelectedTx.weight` field, which is
copied from `MempoolEntry.weight` at admission time
(`block_template.zig:347`). For mempool entries, this is
accurate. For `generateblock`-supplied user txs that didn't go
through admission, `estimateTxWeight` (`block_template.zig:1872-1918`)
provides a reasonable estimate but isn't guaranteed equal to
`GetTransactionWeight(tx)` (Core uses
`(GetTotalSize - GetStrippedSize) * (WITNESS_SCALE_FACTOR - 1) +
GetTotalSize`).

**File:** `src/rpc.zig:6110-6113`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`
emits `weight` from `GetTransactionWeight(*tx)` recomputed at
emit time.

**Carry-forward:** W123 BUG-15.

**Impact:** cosmetic for the mempool case; potentially divergent
for the generateblock case. Miner that trusts the weight value
may overflow weight gates after rolling tx changes.

---

## BUG-22 (P1) — No template caching; every getblocktemplate call rebuilds from scratch (O(mempool_size))

**Severity:** P1. Core caches the last template and invalidates on
`OnBlockConnected` or mempool changes that affect block ordering.
clearbit's `handleGetBlockTemplate` (`rpc.zig:6065`) calls
`block_template.createBlockTemplate` unconditionally — full
mempool walk, full sort, full coinbase reconstruction, every call.

On a busy mainnet mempool (~100k entries), this is multi-second
CPU. Miners that long-poll at 5-second cadence hammer the node;
no template-validity-window optimisation.

**File:** `src/rpc.zig:6065-6132`.

**Core ref:** `bitcoin-core/src/node/miner.cpp` — `BlockAssembler`
keeps `m_options` per-call, but Core's GBT layer
(`rpc/mining.cpp:962`) keeps `cache::CBlockIndex* pindexPrevNew`
+ `cache::CBlockTemplate* pblocktemplate` and short-circuits
when state hasn't moved.

**Carry-forward:** W108 BUG-27, W123 BUG-11.

**Impact:** mining-stack latency. Per-block-extension overhead is
N × O(mempool_size) where N = miner-pool count × poll-rate.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CONS:** 2 (BUG-8 generateblock witness commitment discarded;
  BUG-12 GBT funds-burn via OP_RETURN coinbase)
- **P0-CDIV:** 9 (BUG-1 bits placeholder; BUG-3 wall-clock nTime
  no MTP/GetAdjustedTime; BUG-4 no addPackageTxs; BUG-5 raw ancestor
  sort + dead cluster helper; BUG-6 no topological guard; BUG-10
  GBT shape divergence; BUG-11 rules ignored; BUG-14 no
  TestBlockValidity; BUG-15 mining bypasses acceptBlock)
- **P0:** 1 (BUG-16 dead-branch coinbase-value > subsidy)
- **P1:** 10 (BUG-2 stub BIP-9 versionbits; BUG-7 96-vs-100 cap;
  BUG-9 generateblock fee=0 internal-contract break; BUG-13 mintime
  wall-clock; BUG-17 submit-failure-vs-tries conflation; BUG-18
  regtest-only restriction; BUG-19 no signet; BUG-20 no
  IncrementExtraNonce; BUG-21 stale tx weight; BUG-22 no template
  cache)

Total: 2 + 9 + 1 + 10 = 22. ✓

**P0-class count:** 12 (2 P0-CONS + 9 P0-CDIV + 1 P0).

**Fleet patterns confirmed (W154 contributes):**

- **30-of-30-gates-buggy 7th candidate** — W154 catalogues 22
  divergences across 30 sub-gates spanning the entire block-assembly
  + GBT + submit pipeline. The brief flagged clearbit as the
  6-of-6 leader (W138 + W141 + W150 + W151 + W152 + W153);
  **W154 is the 7th confirmation**. The mining subsystem joins
  assumeUTXO, ZMQ/REST/notify, ATMP-prechecks, package-relay-RBF,
  tx-relay-inv-orphan, and mempool-eviction-minrelay as
  "subsystem rewrite candidates".
- **Dead-helper-at-call-site (7th clearbit instance)** — BUG-5
  `getBlockCandidatesByMiningScore` exists at mempool.zig:4431,
  cluster-aware + prioritise-aware, but production calls the raw
  `getBlockCandidates` (block_template.zig:252). Companion to
  W117 + W118 + W121 + W138 + W141 + W150 / W151 / W152 / W153.
- **Comment-as-confession (14th+ clearbit instance)** — BUG-1
  comment "Use genesis bits as placeholder", BUG-2 comment
  "Limitation: accurate signaling requires per-height block version
  data", BUG-8 comment "Simplified: in full implementation would
  reconstruct coinbase", BUG-9 comment "Fee not tracked for
  generateblock", BUG-11 comment "Template request params ... not
  fully implemented", BUG-12 comment "OP_RETURN (placeholder)",
  BUG-16 comment "This is a conservative check - actual validation
  needs total fees". **7 distinct confessions in this single audit.**
- **Wiring-look-but-no-wire applied to mining (BUG-1 + BUG-5)** —
  `getNextWorkRequired` exists in consensus.zig:989 but is not
  wired into createBlockTemplate; `getBlockCandidatesByMiningScore`
  exists in mempool.zig:4431 but is not wired into the assembler.
  Same shape as fleet's W138 ChainstateManager + W141
  zmq_publisher patterns.
- **Two-pipeline guard (15th+ distinct extension)** — BUG-15
  `submitblock` routes through full `validation.acceptBlock`
  while `generatetoaddress` / `generateblock` route through only
  `validation.checkBlock`. Two block-acceptance pipelines coexist
  within one impl, with divergent consensus depth. Companion to
  W143 5-pipeline-bypass; this is a 2-pipeline split specifically
  for the mining → connect axis.
- **Assume-valid scope creep is NOT present here** — BUG-15 is
  a different shape (pipeline omission, not assume-valid-flag
  semantic creep). Worth noting since hotbuns W145 surfaced the
  scope-creep pattern strongly; clearbit's mining bypass is its
  own architectural gap.
- **Dead-branch-in-consensus (BUG-16)** — first explicit clearbit
  instance of `if (cond) { /* empty */ }` shape with body comment.
  Companion to W143 BUG-16 (which surfaced the same pattern from
  the validation perspective; this audit re-anchors it from the
  mining perspective).
- **No-operator-knob-exists (BUG-22 + BUG-18 + BUG-19 cluster)** —
  no `-blockmaxweight`, no `-blockreservedweight`, no
  `-blockmintxfee` CLI flags (W123 BUG-22 + BUG-23 carry-forward);
  no signet support; no mainnet-mining permission. Same shape as
  W148 BUG-6 (no `-reindex`), W149 BUG-5 (no `-assumevalid`).

**Top three findings:**

1. **BUG-12 (P0-CONS funds-burn)** — `handleGetBlockTemplate`
   hardcodes the coinbase payout script to `OP_RETURN` (`0x6a`).
   A miner that wires a real ASIC pool to clearbit's GBT and
   mines + submits a block burns the full subsidy + fees
   (~$250k at current mainnet prices, per block). Catastrophic
   if exercised at all; the silent OP_RETURN make-it-fail-safe
   is invisible to operators.

2. **BUG-1 (P0-CDIV)** + cluster with **BUG-8 (P0-CONS)** + **BUG-14
   (P0-CDIV)** + **BUG-15 (P0-CDIV)** — the mining path's
   "broken six ways" cluster:
   - bits = genesis placeholder (BUG-1) → templates fail PoW gate
     on mainnet/testnet4;
   - generateblock witness commitment discarded (BUG-8) → user-tx
     blocks fail bad-witness-merkle-match;
   - no TestBlockValidity (BUG-14) → invalid templates ship without
     warning;
   - mining bypasses acceptBlock (BUG-15) → invalid mined blocks
     accept silently into clearbit's chainstate but would be rejected
     by Core peers.

   Carry-forward chain spans W108 → W123 → W154 (~22 waves).
   `getNextWorkRequired` exists since W56-ish; never wired.

3. **BUG-10 (P0-CDIV) + BUG-11 (P0-CDIV)** — GBT response missing
   `default_witness_commitment`, `longpollid`, `vbavailable`,
   `vbrequired`, `rules`, `coinbaseaux`, `noncerange`, `sigoplimit`,
   `sizelimit`, `weightlimit`, per-tx `depends` and `sigops`; and
   `handleGetBlockTemplate` discards the request `params` entirely.
   Stock-Core miners cannot use clearbit's GBT. The
   `default_witness_commitment` absence specifically means there
   is no way for a miner to construct a valid post-segwit block
   from clearbit's GBT — the miner has no commitment scriptPubKey
   to drop into their hand-rolled coinbase. Carry-forward W108 +
   W123 BUG-3 + BUG-4.
