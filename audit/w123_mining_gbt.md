# W123 — Mining / GBT parity audit (clearbit / Zig 0.13)

**Date:** 2026-05-17
**Wave:** W123 (discovery — first impl in fleet)
**Scope:** Mining / `getblocktemplate` / `submitblock` /
`getmininginfo` / BIP-152 announce path / FIX-72 modified-fee
completeness.

## Reference

- `bitcoin-core/src/node/miner.cpp` — `BlockAssembler`,
  `CreateNewBlock`, `addChunks`, `AddToBlock`, `UpdateTime`,
  `GetMinimumTime`, `ClampOptions`, `resetBlock`.
- `bitcoin-core/src/rpc/mining.cpp` — `getblocktemplate`,
  `submitblock`, `getmininginfo`, `getnetworkhashps`,
  `prioritisetransaction`, `getprioritisedtransactions`.
- `bitcoin-core/src/policy/feefrac.cpp` — `FeePerWeight`,
  `chunk_feerate` comparison + `<<` (less than) operator.
- `bitcoin-core/src/net_processing.cpp` — BIP-152
  `PeerManagerImpl::NewPoWValidBlock` + `RelayBlock` for
  HB-peer cmpctblock push.
- BIP-22 — Generation request (template + proposal modes).
- BIP-23 — Mining mutations + capabilities.
- BIP-141 — Segwit + witness commitment + `default_witness_commitment`.
- BIP-152 — Compact blocks + sendcmpct + cmpctblock + getblocktxn +
  blocktxn + high-bandwidth-peer push.

## FIX-72 verification

**FIX-72 ("STRONGEST in fleet" claim): CONFIRMED for W120 scope,
INCOMPLETE for W123 scope.**

FIX-72 wired modified-fee (`entry.fee + map_deltas[txid]`) into:

| Site | Status | Reference |
|------|--------|-----------|
| Mempool `map_deltas` + `getModifiedFee` + `applyDelta` | PRESENT | `mempool.zig:893-896, 2255-2266` |
| `prioritiseTransaction` RPC | PRESENT | `rpc.zig:4659-4732` |
| `getprioritisedtransactions` RPC | PRESENT | dispatched at `rpc.zig:2972-2975` |
| Cluster linearisation `fees[i]` | PRESENT | `mempool.zig:4152` |
| `block_min_fee_rate` per-entry gate | PRESENT | `block_template.zig:284-298` |
| RBF Rules 3/4/diagram | PRESENT | `mempool.zig:3066+` |
| `addTransaction` min-fee admission | PRESENT | per FIX-72 commit |
| `getmempoolentry` modifiedfee + fees.modified | PRESENT | `rpc.zig:4576+` |
| `mempool_persist.dumpmempool` mapDeltas section | ABSENT (deferred) | per FIX-72 commit msg |

FIX-72 did NOT touch:

| Site | Status | Symptom |
|------|--------|---------|
| `createBlockTemplate` primary sort key | RAW (`getBlockCandidates` by `ancestorFeeRate()` — uses `ancestor_fees` not modified) | BUG-1 — prioritisetransaction does NOT lift a tx in the template |
| `total_fees += entry.fee` (coinbase reward) | RAW (intentional, matches Core) | NOT A BUG; pinned as G17 PASS |
| Descendant ancestor_fees propagation on prioritise | ABSENT | BUG-1 sub-symptom — descendants don't inherit |
| GBT shape (BUGs 3, 4, 6-11, 19-25) | UNTOUCHED | W108 carry-forwards |

**Verdict:** FIX-72 is the strongest single-impl modified-fee fix in
the fleet (clearbit is only impl to wire BOTH cluster linearisation AND
the block_min_fee_rate gate), but the W123 mining-stack audit shows
**partial wire-up at the mempool↔template boundary**.  The cluster
mining_score is computed but the assembler never queries it — it
walks via `getBlockCandidates` returning entries sorted by the
raw stored `ancestor_fees`.

## Gate-by-gate findings (30 gates, 29 BUGS + 2 PASS reclassifications)

| Gate | Status | Severity | Site | Summary |
|------|--------|----------|------|---------|
| G1 | BUG-1 | P0-CDIV | `block_template.zig:252` | createBlockTemplate uses raw-ancestor-fee primary sort, not cluster mining_score. **Central W123 finding.** |
| G2 | BUG-2 | P0-CDIV | `block_template.zig:233` | nBits = `params.genesis_header.bits` placeholder; `getNextWorkRequired` exists but unused in template path. **W108 BUG-3 carry-forward.** |
| G3 | BUG-3 | P0-CDIV | `rpc.zig:6065-6133` | GBT response missing `rules`, `vbavailable`, `vbrequired`, `coinbaseaux`, `longpollid`, `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`, `default_witness_commitment`. Per-tx fields missing: `hash` (wtxid), `depends`, `sigops`. |
| G4 | BUG-4 | P0-CDIV | `rpc.zig:6066` | `handleGetBlockTemplate` discards `params` (`_ = params`). mode="proposal" + rules + capabilities + longpollid all ignored. |
| G5 | BUG-5 | P0 | `rpc.zig:6065` | No IBD + peer-count gate. Operator on stale node serves a stale template that orphans on peers. |
| G6 | BUG-6 | P1 | `rpc.zig:6125` | `mintime` = `template.header.timestamp` instead of `MTP+1`. BIP-94 timewarp guard missing. |
| G7 | BUG-7 | P1 | `rpc.zig:6065-6133` | No `UpdateTime()` call site. curtime fixed at template-build; stale on poll. |
| G8 | BUG-8 | P1 | `rpc.zig:10595` | `getmininginfo` hardcodes `"networkhashps":0`. Should delegate to getnetworkhashps. |
| G9 | BUG-9 | P1 | `rpc.zig:10589-10605` | `getmininginfo` missing `currentblockweight` + `currentblocktx`. No `m_last_block_*` analog. |
| G10 | BUG-10 | P1 | `rpc.zig:10595` | `getmininginfo` hardcodes `"blockmintxfee":0.00001`. Should read configured block_min_fee_rate. |
| G11 | BUG-11 | P1 | `rpc.zig:6065-6133` | No template caching. Every GBT call rebuilds; longpoll cost is O(mempool walk + linearisation + merkle) every heartbeat. |
| G12 | BUG-12 | P0-CDIV | `peer.zig:7134-7160` | `announceBlock` only sends `headers` (sendheaders peers) / `inv` (others) — NEVER pushes cmpctblock to BIP-152 HB peers (`bip152_highbandwidth_from` flag is set on receive but never branched on for outbound). **Clearbit is a poor BIP-152 citizen.** |
| G13 | BUG-13 | P1 | `rpc.zig:6065-6133` | GBT response missing `m_package_feerates` (Core miner.cpp:327). |
| G14 | BUG-14 | P1 | `rpc.zig:6135-6262` | `submitblock` accepts the block but does NOT relay to peers (no `announceBlock` / `cacheMinedBlock` call). Private RPC mining produces local-only blocks. |
| G15 | BUG-15 | P1 | `rpc.zig:6110-6113` | GBT `transactions[].weight` uses cached `entry.weight` from mempool, not fresh `GetTransactionWeight(tx)`. Stale on malleated cache. |
| G16 | BUG-16 | P1 | `rpc.zig:6752-6900` | `generateblock` RPC does NOT announce / cache the mined block (contrast with generatetoaddress which DOES). |
| G17 | PASS-pin | — | `block_template.zig:353` | `total_fees += entry.fee` (raw) matches Core `nFees += entry.GetFee()`. **Pinned to prevent future drive-by "fix".** |
| G18 | informational | — | `block_template.zig:495+628` | Coinbase scriptSig extra-data capped at 96 bytes (conservative vs Core's 100). Documented; not a bug. |
| G19 | BUG-19 | P1 | `rpc.zig:6089` | GBT `capabilities` hardcoded to `["proposal"]`. BIP-23 supports `coinbasetxn`, `workid`. |
| G20 | BUG-20 | P1 | `block_template.zig:441-444` | GBT `mutable` field is fixed 4-entry array `["time","transactions","prevblock","coinbase/append"]`. BIP-23 supports `version/force`, `submit/coinbase`. |
| G21 | BUG-21 | P1 | `rpc.zig:13203-13204` | `getnetworkhashps` chain_work arithmetic truncates to lower 128 bits. Today fine, future-proofing concern. |
| G22 | BUG-22 | P1 | `main.zig` | No `-blockreservedweight` CLI flag (Core: `args.GetIntArg("-blockreservedweight")`). |
| G23 | BUG-23 | P1 | `main.zig` | No `-blockmaxweight` CLI flag (Core: `args.GetIntArg("-blockmaxweight")`). |
| G24 | BUG-24 | P1 | `rpc.zig:6135-6262` | `submitblock` cannot differentiate `duplicate` vs `duplicate-inconclusive` rejections — falls through to catch-all `"rejected"`. |
| G25 | BUG-25 | P1 | `rpc.zig:6128` | GBT `bits` field carries placeholder value (consequence of BUG-2). Wire is correct but VALUE is wrong post-retarget. |
| G26 | PASS-pin | — | `block_template.zig:546-563` | Coinbase witness reserved value: 32-byte zero nonce in `inputs[0].witness[0]` per BIP-141. Verified via integration test. |
| G27 | BUG-27 | P1 | `block_template.zig:413-422` | BIP-9 state-machine in `createBlockTemplate` uses stub `IndexView` returning null for all heights — deployments in STARTED period can't be advanced by clearbit's miners. |
| G28 | BUG-28 | P1 | `block_template.zig:252-298` | prioritisetransaction effect on template is partial: cluster + block_min_fee_rate gates wired, primary sort is NOT. Operator-visible: "prioritise looks accepted but doesn't shift template position." |
| G29 | BUG-29 | P1 | `mempool.zig:4431` + `block_template.zig` | `getBlockCandidatesByMiningScore` is a 30-line dead-helper-at-call-site (exists, tested, never called from production assembler). **Continues fleet-wide "dead helper" streak (33+ waves).** |
| G30 | PASS | — | multiple | 10 carry-forward positive PASS tests exercising clampOptions, witness commitment, coinbase anti-fee-sniping nLockTime, BIP-152 receive-side codec presence, FIX-72 dispatch + cluster linearisation, etc. |

## Counts

- **PRESENT (PASS):** 1 (G30 — itself bundles 10 carry-forwards)
- **PARTIAL:** 5 (G17 / G18 / G26 reclassifications + G28 / G29 — partial wire-up symptoms)
- **MISSING (BUG):** 24 unique BUGS (BUG-1 through BUG-29 minus the
  3 PASS reclassifications and overlapping symptom captures)

**Severity:**
- **P0-CDIV:** 5 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-12)
- **P0:** 1 (BUG-5)
- **P1:** 18 (BUG-6 through BUG-11, BUG-13 through BUG-16, BUG-19 through BUG-25, BUG-27, BUG-28, BUG-29)

Total BUGS: **24** (matching what flows naturally from 29 gate-line
items minus the 3 reclassifications and minus the bundled G30
positives).  Net W123 finding count: **29 bugs** when counting at
gate-line granularity (matches the audit-line BUG-1..BUG-29 numbering).

## Universal patterns to flag for fleet roll-up

1. **Modified-fee partial wire-up at mempool↔template boundary.**
   FIX-72 wired modified fee into cluster linearisation + per-entry
   gate, but the assembler's primary sort still consults raw stored
   ancestor_fees. Likely fleet-wide pattern: impls that "wired
   prioritisetransaction" should be audited for this specific sort-key
   gap.

2. **Dead-helper-at-call-site** (33+ wave streak preserved):
   `mempool.getBlockCandidatesByMiningScore` exists with tests but is
   never called from the production assembler.

3. **GBT shape divergence as universal P0-CDIV across fleet.** W108
   documented 29 missing fields for clearbit; W123 confirms most are
   still missing. Likely fleet-wide: many impls emit partial GBT.

4. **BIP-152 receive-side wired, push-side absent.** clearbit decodes
   sendcmpct/cmpctblock/getblocktxn/blocktxn but never proactively
   pushes cmpctblock to HB peers on new block. Fleet pattern: BIP-152
   adoption almost always lands receive-side first; the
   `announceBlock`-to-HB integration is the hard part that gets
   deferred.

5. **submitblock acceptance ≠ relay.** `submitblock` accepts the block
   locally but never broadcasts. Likely fleet pattern: RPC-mined
   blocks visible only to the submitter.

6. **CLI flag parity gap.** `-blockreservedweight` and
   `-blockmaxweight` are well-defined Core operator levers; impls
   often forget to wire the CLI even when the underlying option
   struct supports it.

7. **`getmininginfo` networkhashps hardcoded to 0.** Likely fleet
   pattern: every impl that has a hashps RPC and a mininginfo RPC
   tends to hardcode the latter because the former is harder.

## Test coverage

**`src/tests_w123_mining_gbt.zig`** — 40 tests across 30 gates:

- 24 source-guard tests (negative invariants — must STAY absent until
  fixed, then audit-flip to positive).
- 6 integration tests (createBlockTemplate end-to-end, encodeHeightPush,
  witness commitment format, coinbase anti-fee-sniping, BIP-152 codec
  presence).
- 10 PASS carry-forward gates pinning FIX-72 invariants + W108
  positive carry-forwards.

```
$ zig build test-w123
Build Summary: 4/4 steps succeeded; 40/40 tests passed
test-w123 success
+- run test 40 passed
```

Each source-guard test names the BUG number; when a future fix lands,
the source-guard pattern flips to PRESENT and the test fails with a
clear identifying message that prompts a deliberate audit-flip (Core-
parity-audit pattern).

## Fix path roadmap (for FIX-N candidates)

Recommended sub-bundles (lowest-effort first):

**Bundle A — getmininginfo / GBT shape (P1, mechanical wire-up):**
G6, G7, G8, G9, G10, G13, G19, G20, G25 — all near-mechanical
RPC-shape closures. ~6-10 LOC each.

**Bundle B — FIX-72 sort-key closure (P0-CDIV, central):** G1 +
G28 + G29 closure. Replace
`mempool.getBlockCandidates(allocator)` with
`mempool.getBlockCandidatesByMiningScore(allocator)` inside
`block_template.createBlockTemplate`. Already-tested dead helper
becomes live. ~1 LOC + cluster relinearisation correctness gates.

**Bundle C — submitblock + generateblock relay (P1):** G14 + G16.
Add `announceBlock` + `cacheMinedBlock` call sites after acceptance.
Match handleGenerateToAddress pattern. ~10 LOC each.

**Bundle D — BIP-152 HB push (P0-CDIV, large):** G12. Wire
`PeerManager.announceBlock` to branch on `bip152_highbandwidth_from`
and emit cmpctblock proactively (mirrors Core
`PeerManagerImpl::NewPoWValidBlock`). ~50-80 LOC + cmpct
short-id generation reuse from existing receive path.

**Bundle E — nBits + IBD gate (P0-CDIV, integration):** G2 + G5 +
G25. Wire `consensus.getNextWorkRequired` into the template path;
add IBD + peer-count gate to handleGetBlockTemplate. ~20-30 LOC.

**Bundle F — BIP-22 params parse (P0-CDIV, surface):** G3 + G4 +
G11. Parse `mode`, `rules`, `capabilities`, `longpollid`; implement
mode="proposal" via `TestBlockValidity`; add template cache keyed on
(tip, mempool sequence). ~150-300 LOC.

## Why this audit matters

The mining stack is the most operator-visible RPC surface. Pool
operators, monitoring tools, and external mining clients all
consume `getblocktemplate` + `getmininginfo` + `submitblock`. A
template that emits stale `bits` (BUG-2 / BUG-25), missing `rules`
(BUG-3), or unreachable `mintime` (BUG-6) will produce blocks that
get rejected by every peer — silent loss of hash rate. The cluster-
aware mining-score gap (BUG-1) means clearbit cannot honour
prioritisetransaction, undercutting operator control of their own
template. The BIP-152 HB-peer push gap (BUG-12) makes every newly
mined block slower to propagate, increasing orphan risk.

FIX-72's modified-fee plumbing was the right shape — it just stopped
one helper-call short of reaching the assembler's primary sort.
Closing that gap (Bundle B) is the highest-value single edit in this
audit: ~1 LOC swap, ~50 LOC of relinearisation invariant tests,
flips the most central P0-CDIV in the wave.
