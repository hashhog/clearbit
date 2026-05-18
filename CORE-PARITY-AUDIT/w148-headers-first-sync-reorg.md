# W148 — Headers-first sync + chain selection + reorg (clearbit)

**Wave:** W148 — `ProcessNewBlockHeaders`, `AcceptBlockHeader`,
`ActivateBestChain`, `ActivateBestChainStep`, `ConnectTip`, `DisconnectTip`,
`FindMostWorkChain`, `MAX_REORG_DEPTH`/`MIN_BLOCKS_TO_KEEP`, `CBlockIndex`
validity bitfield (`BLOCK_VALID_TREE`/`TRANSACTIONS`/`CHAIN`/`SCRIPTS`),
`m_chain_tx_count`, `m_best_header`, `InvalidChainFound`,
`ResetBlockFailureFlags`, `IsInitialBlockDownload`/`UpdateIBDStatus`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:4183-4239` — `AcceptBlockHeader`
  (PoW + ContextualCheckBlockHeader + bad-prevblk + `min_pow_checked` gate
  + AddToBlockIndex + `m_best_header` update).
- `bitcoin-core/src/validation.cpp:4242-4270` — `ProcessNewBlockHeaders`
  (loop, batch under `cs_main`, `CheckBlockIndex` after each header,
  `NotifyHeaderTip` outside lock).
- `bitcoin-core/src/validation.cpp:3114-3171` — `FindMostWorkChain`
  (reverse iter over `setBlockIndexCandidates`, ancestor
  `BLOCK_FAILED_VALID` + `BLOCK_HAVE_DATA` filter, candidate erase on
  failure).
- `bitcoin-core/src/validation.cpp:3191-3280` — `ActivateBestChainStep`
  (DisconnectTip loop to fork, vpindexToConnect descending walk in chunks
  of 32, ConnectTip loop, `MaybeUpdateMempoolForReorg`).
- `bitcoin-core/src/validation.cpp:3323-3450` — `ActivateBestChain`
  (do-while loop, releases `cs_main` between iterations, breaks when
  `pindexMostWork == m_chain.Tip()`, ReachedTarget exit).
- `bitcoin-core/src/validation.cpp:2900-3000` — `ConnectTip`
  (block read, ConnectBlock + chainstate write + UpdateTip).
- `bitcoin-core/src/validation.cpp:3055-3107` — `DisconnectTip`
  (CBlockUndo from rev*.dat, DisconnectBlock, mempool refill).
- `bitcoin-core/src/validation.cpp:3711-3730` — `ResetBlockFailureFlags`
  (filter `block_index.GetAncestor(nHeight) == pindex || pindex->GetAncestor(block_index.nHeight) == &block_index`
  AND `BLOCK_FAILED_VALID` — does NOT touch non-failed ancestors).
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus` (`m_cached_is_ibd` latched
  to false when `IsTipRecent(MinimumChainWork(), max_tip_age)`).
- `bitcoin-core/src/validation.cpp:1964-1984` — `InvalidChainFound`
  (sets `m_best_invalid` if new chain has more work than current best
  invalid; `RecalculateBestHeader` if current `m_best_header` descends
  from invalid pindex).
- `bitcoin-core/src/validation.cpp:3765-3815` — `ReceivedBlockTransactions`
  (`nTx = block.vtx.size()`, `m_chain_tx_count = nTx + pprev->m_chain_tx_count`,
  walks descendants to propagate counts).
- `bitcoin-core/src/node/blockstorage.cpp:247` — genesis chainwork
  (`pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);`).
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum (5-level ordered
  validity ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS plus
  HAVE_DATA / HAVE_UNDO / FAILED_VALID / FAILED_CHILD / OPT_WITNESS bits
  and `BLOCK_VALID_MASK = 7`).
- `bitcoin-core/src/chain.h:120-129` — `CBlockIndex::nTx`,
  `m_chain_tx_count` fields.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`.

**Files audited**
- `src/validation.zig` — `ChainManager`, `BlockIndexEntry`, `BlockStatus`,
  `activateBestChain`, `invalidateBlock`, `reconsiderBlock`,
  `preciousBlock`, `clearDescendantFailure`, `markDescendantsInvalid`,
  `disconnectToBlock`, `loadGenesis`, `compareCandidates`,
  `compareChainWork`, `IBDValidationContext`, `validateBlockForIBD`,
  `acceptBlock`.
- `src/peer.zig` — `PeerManager.header_index`, `MAX_REORG_DEPTH`,
  `MAX_HEADER_INDEX`, `BlockHeaderEntry`, `PendingReorg`,
  `classifyHeaderBatch`, `insertHeader`, `validateHeaderContextual`,
  `lookupParentChainWork`, `chainWorkFromHeight`, `maybeArmReorg`,
  `tryFireReorg`, `validateBlockForIBDOrReject`, `drainBlockBuffer`,
  `isIBD`, `.headers` handler (~4399-4574), `.block` handler.
- `src/sync.zig` — `HeaderSyncManager` (PRESYNC), `SyncManager` (DEAD),
  `BlockIndex`, `processHeader`, `processPresyncHeaders`, `handleHeaders`.
- `src/storage.zig` — `ChainState`, `MIN_BLOCKS_TO_KEEP = 288`,
  `MAX_REORG_DEPTH = 100`, `reorgToChain`, `disconnectBlockByHashCF*`,
  `connectBlockFast*`, `flush` (CF_BLOCK_INDEX section ~4498-4595),
  `ChainStore.putBlockIndex` (84 bytes), `ChainStore.putBlockIndexFull`
  (140 bytes), `BlockIndexRecord`.
- `src/main.zig:1896-1925` — `ChainManager` instantiation and wiring.

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | AcceptBlockHeader contract | G1: PoW validated at header acceptance | PASS (`peer.zig:4505-4517` validateHeaderContextual + insertHeader implicit PoW via permittedDifficultyTransition in PRESYNC) |
| 1 | … | G2: ContextualCheckBlockHeader MTP-11 + future-time | PARTIAL — live `.headers` handler runs both (peer.zig:4504-4517); SyncManager `processHeader` runs ONLY PoW (sync.zig:1050) but SyncManager is dead |
| 1 | … | G3: header rejected if `pprev->nStatus & BLOCK_FAILED_VALID` ("bad-prevblk") | **BUG-1 (P0-CDIV)** `insertHeader` never checks parent invalid; `validateHeaderContextual` likewise |
| 1 | … | G4: `min_pow_checked` boolean threaded to header acceptance | PASS at live path (`peer.zig:4519-4551`); PARTIAL at PRESYNC (sync.zig:429) |
| 1 | … | G5: empty headers message is no-op (no Misbehaving) | PASS (sync.zig:335) |
| 1 | … | G6: `m_best_header` advanced independently of full validation | **BUG-2 (P1)** No `m_best_header` analog anywhere — `ChainState.best_hash` is the active-chain tip; PeerManager's "tip" is `cs.best_height`; `header_index` has no "best" pointer (W97 G9, W97 G15 confessions; carry-forward) |
| 2 | CChain m_chain tip pointer | G7: random-access `m_chain[height]` | **BUG-3 (P1)** Three parallel "block index" data structures (validation.ChainManager.block_index, peer.PeerManager.header_index, sync.SyncManager.block_index) — only the last has an active_chain ArrayList; the live path lacks any. `BlockIndexEntry` has no Skip pointer → `getAncestor` walks Parent in O(h). Three-pipeline drift |
| 2 | … | G8: `m_chain.Genesis()` / `Tip()` accessors | PARTIAL — `cs.best_hash` / `cs.best_height` exist; `chain_manager.active_tip` exists but is not the live tip |
| 2 | … | G9: `m_chain.FindFork(other_chain)` | **BUG-4 (P1)** `maybeArmReorg` walks parent pointers via `header_index.get(cursor).prev_hash` (peer.zig:4005-4030), O(depth); no skip-list. ChainManager has no FindFork at all |
| 3 | ActivateBestChain loop | G10: do-while loop iterates until `pindexMostWork == Tip()` | **BUG-5 (P0)** `ChainManager.activateBestChain` is a stub: it scans `block_index`, picks the best candidate, and **just swaps `active_tip` pointer with a `// TODO: Full reorg implementation` comment** (validation.zig:6325-6338). No disconnect/connect — UTXO is NOT updated. Carry-forward from W101 BUG-1 (confession-as-comment) — STILL open after multiple waves |
| 3 | … | G11: releases lock between iterations for responsiveness | **BUG-6 (P1)** ChainManager has no `chainstate_mutex` field (W101 G5 still open). `tryFireReorg`/`reorgToChain` hold no mutex either; relies on single-threaded peer manager loop. Concurrent `submitblock` RPC + IBD drain can race |
| 3 | … | G12: `MaybeUpdateMempoolForReorg` after each ConnectTip | **BUG-7 (P1)** `mempool.RemoveForReorg`-equivalent absent. `evictConflictingTransactions` is a `_ = self; _ = pool; _ = block;` TODO stub (validation.zig:6384-6391). Post-reorg mempool re-validation never fires |
| 3 | … | G13: vpindexToConnect chunked by 32 to bound stack frame | **BUG-8 (P2)** `reorgToChain` builds full disconnect+connect lists in one shot (storage.zig:3892-3962); no chunking. Bounded by MAX_REORG_DEPTH=100 but still under one undivided WriteBatch |
| 4 | MAX_REORG_DEPTH guard | G14: refuse `disconnect+connect > N` | **BUG-9 (P0-CDIV)** Two-pipeline divergence: `peer.zig:45` declares `MAX_REORG_DEPTH = 288` claiming it "mirrors storage.zig"; `storage.zig:3818` actually has `MAX_REORG_DEPTH = 100`. The peer-side arming accepts forks the storage-side will refuse. Core has NO max-reorg-depth — only `MIN_BLOCKS_TO_KEEP=288` |
| 4 | … | G15: error message identifies the limit | PASS (`storage.zig:3884`, `peer.zig:4034`) |
| 4 | … | G16: operator-knob override (`-maxreorgdepth`) | **BUG-10 (P1)** No operator knob; both constants are compile-time. Recovery from a > 100-block reorg needs hot-patch or full re-sync |
| 5 | ConnectTip semantics | G17: ConnectBlock + chainstate write + UpdateTip atomic | PASS (`storage.zig:reorgToChain` uses single shared WriteBatch — Pattern D, atomic flush) |
| 5 | … | G18: on failure, block marked `BLOCK_FAILED_VALID` | **BUG-11 (P0-CDIV)** `validateBlockForIBDOrReject` failure (peer.zig:6584-6604) penalises the supplying peer +100 and rewinds `download_cursor` — but **never marks `node.Status.failed_valid` on the rejected block in either `header_index` OR `chain_manager.block_index`**. The same block can be re-served by another peer and re-validated indefinitely. Cross-cite W101 BUG-4 (still open) |
| 5 | … | G19: assume_valid skip respects ancestor proof | PARTIAL — `validateBlockForIBDOrReject` (peer.zig:6378-6382) computes `skip_via_height = (height <= av_height) and (av_height != 0) and (assumed_valid_hash != null)`. The actual ancestor-of-assumed-valid check (Core's "block must be ancestor of assumedValid") is delegated to chain linearity from the active tip; on a side branch the gate over-permits |
| 6 | DisconnectTip semantics | G20: rev*.dat undo applied in reverse | PASS (`storage.zig:disconnectBlockByHashCF`) |
| 6 | … | G21: DISCONNECT_UNCLEAN logged but not fatal | PARTIAL — `disconnectToBlock` (validation.zig:6086-6089) treats both `DisconnectFailed` and `DisconnectUnclean` as fatal; comment claims this mirrors Core's `!= DISCONNECT_OK`, but Core's VerifyDB caller tolerates UNCLEAN (see comment at line 6075) |
| 6 | … | G22: failure halts (Core `FatalError`) | **BUG-12 (P2)** Both `reorgToChain` failure and `disconnectToBlock` failure return errors that propagate to caller; the caller logs and continues. No `FatalError` halt. A corrupted rev*.dat mid-reorg leaves chainstate in inconsistent state but the process keeps running |
| 7 | CBlockIndex validity bitfield | G23: 5-level ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS | **BUG-13 (P1)** `BlockStatus` is a packed bool bitfield (valid_header, has_data, has_undo, failed_valid, failed_child). The 5-level ORDERED ladder collapses; `BLOCK_VALID_TRANSACTIONS` (have body, no chain-validity yet) vs `BLOCK_VALID_CHAIN` (chain-valid, no scripts) inexpressible. `assumeUTXO` snapshot machinery + script-skip can't distinguish "tree-only" vs "scripts-checked" |
| 7 | … | G24: `BLOCK_HAVE_DATA` set after block body lands | PARTIAL — `storage.zig:4541-4542` sets `has_data` bit (bit 1) in the IBD flush; **but never sets `valid_header` (bit 0)** — so `isValidCandidate()` (validation.zig:5788, requires `has_data` only) accidentally works, but the bit naming is broken |
| 7 | … | G25: `BLOCK_HAVE_UNDO` set after rev*.dat write | PASS in the reorg-enabled path (`storage.zig:4541-4542`); always-off in non-reorg IBD |
| 7 | … | G26: `BLOCK_FAILED_CHILD` propagated to descendants on InvalidateBlock | PASS (`markDescendantsInvalid` BFS at validation.zig:6012-6044) |
| 7 | … | G27: persisted bits survive restart | **BUG-14 (P0-CDIV)** **Two-pipeline guard at CF_BLOCK_INDEX**: `ChainStore.putBlockIndex` (storage.zig:293, 84 bytes — height + header only) used by dead `SyncManager`, vs `ChainStore.putBlockIndexFull` (storage.zig:338, 140 bytes — adds status/chain_work/sequence_id) used only by `ChainManager.persistBlockStatus` (RPC paths). The IBD flush path at storage.zig:4548-4594 **stamps chain_work = [_]u8{0} ** 32** for new IBD blocks (only preserves chain_work if it was *already* in CF_BLOCK_INDEX). Every IBD-connected block gets persisted chain_work = 0; only RPC-touched blocks get the real value |
| 8 | m_chain_tx_count + m_chain_work | G28: per-block cumulative tx counter | **BUG-15 (P1)** `BlockIndexEntry` has **no `nTx` field, no `chain_tx_count` field, no `m_chain_tx_count` analog**. `BlockIndexRecord` (the persisted form) also has no `nTx`. `getblockchaininfo`'s `nchaintx` cannot be returned correctly; `verificationprogress` falls back to height-based linear interpolation (Core uses tx-density via `m_chain_tx_count`); assumeUTXO snapshot validation can't stamp `m_chain_tx_count` on snapshot base |
| 8 | … | G29: cumulative `nChainWork` correctly maintained | **BUG-16 (P0-CDIV)** `loadGenesis` (validation.zig:6358-6359) sets `chain_work = [_]u8{0} ** 32` — but Core (`node/blockstorage.cpp:247`) sets genesis `nChainWork = GetBlockProof(genesis)`. For mainnet that's ~2^32; for regtest/signet it differs. Cumulative `chain_work` for every descendant is therefore short by genesis's GetBlockProof. Any comparison against `min_chain_work` that depends on the absolute value is off-by-genesis-work. Also: `chainWorkFromHeight(height)` (peer.zig:266-281) — used in `maybeArmReorg` (peer.zig:4049) — is a "height encoded in the trailing 5 bytes" PLACEHOLDER that ignores difficulty entirely. Two reorgs at the same height with different cumulative work compare equal |
| 8 | … | G30: `ResetBlockFailureFlags` filter `BLOCK_FAILED_VALID` only | **BUG-17 (P0-CDIV)** `reconsiderBlock` (validation.zig:6105-6144) clears `failed_valid` ONLY on the target itself (line 6109) — not on any ancestor matching Core's `GetAncestor(nHeight) == pindex` filter. `clearDescendantFailure` (validation.zig:6147-6178) clears `failed_child` UNCONDITIONALLY on EVERY descendant via BFS — without the `BLOCK_FAILED_VALID` filter Core uses. If a descendant has its own independently-set `failed_valid` (separate invalidateblock RPC), clearbit resurrects its descendants via failed_child clear without re-validation |

---

## BUG-1 (P0-CDIV) — `insertHeader` never checks parent invalid status

**Severity:** P0-CDIV. Bitcoin Core's `AcceptBlockHeader`
(validation.cpp:4220-4223) rejects with `"bad-prevblk"` /
`BLOCK_INVALID_PREV` when `pindexPrev->nStatus & BLOCK_FAILED_VALID`.
clearbit's `insertHeader` (peer.zig:3820-3869) looks up parent
chainwork via `lookupParentChainWork`, accepts whatever parent is
present, and adds the new entry. `validateHeaderContextual` (peer.zig:6294-6312)
likewise checks only future-time + MTP, never parent invalidity.

**File:** `src/peer.zig:3820-3869` (`insertHeader`), `src/peer.zig:6294-6312`
(`validateHeaderContextual`)

**Core ref:** `bitcoin-core/src/validation.cpp:4220-4223`

**Why this matters:**
- A peer can extend a chain rooted at an explicitly-invalidated block
  (via `invalidateblock` RPC) and every successor header is silently
  grafted into `header_index`. Since clearbit has TWO disjoint block
  indices (`header_index` in peer.zig, `block_index` in
  `chain_manager`) and the invalidate-block RPC writes only to the
  latter, the live header path doesn't even know to look. The
  invalidated chain pollutes `header_index` until eviction; meanwhile
  `maybeArmReorg` can see it as a competing fork and arm a reorg.
- Symmetric to BUG-11 (failed block validation doesn't set
  `failed_valid` on header layer).

---

## BUG-2 (P1) — `m_best_header` analog absent

**Severity:** P1. Bitcoin Core maintains `m_best_header` — the
highest-chainwork header ever seen, advanced independently of full block
validation. Used for `getbestblockhash` header-mode, `NotifyHeaderTip`
ZMQ topic, sync-progress, and to determine when header-sync is "caught
up" (gating sendcmpct activation, fee-filter ramp, addr-relay rate).

clearbit has no `m_best_header`. `header_index` is a flat map with no
"best" pointer; `chain_manager.active_tip` is the active-block tip (not
the best header); `ChainState.best_hash` is the active-block tip. The
W97 G15 / G9 audits explicitly document this absence (validation.zig:10215,
10248); no fix landed across W98-W147.

**File:** `src/peer.zig:2393` (header_index has no best pointer),
`src/validation.zig:10215` (W97 G15 confession)

**Core ref:** `bitcoin-core/src/validation.h` (`ChainstateManager::m_best_header`),
`bitcoin-core/src/validation.cpp:4233-4237`

**Why this matters:**
- `getbestblockhash` always returns the active-block tip, never the
  best-header tip; during IBD when headers are ~900k ahead of blocks,
  external monitors querying `getbestblockhash` see the IBD-block tip
  not the actual chain-best-header tip.
- No `NotifyHeaderTip` ZMQ analog (W97 G15 confession) — Electrum
  servers and explorer indexers can't subscribe to header advances.

---

## BUG-3 (P1) — Three parallel "block index" data structures

**Severity:** P1 (three-pipeline drift, NEW universal pattern this
quad). clearbit holds THREE disjoint in-memory maps that each model
"the set of known blocks":

1. `validation.ChainManager.block_index: AutoHashMap(Hash, *BlockIndexEntry)`
   (validation.zig:5820) — written by `addBlock`/`loadGenesis`/`loadBlockFromStore`;
   consumed ONLY by the four RPC handlers (invalidate/reconsider/precious
   + `getBlock`) and by `block_template.zig` (submitblock). The live IBD
   path never writes here.
2. `peer.PeerManager.header_index: AutoHashMap(Hash, BlockHeaderEntry)`
   (peer.zig:2393) — written by the live `.headers` handler when
   `CLEARBIT_REORG=1` (peer.zig:4561) and by competing-fork ingestion
   (peer.zig:4474). Bounded by MAX_HEADER_INDEX=10000 with LRU eviction.
   The ONLY index the reorg path consults.
3. `sync.SyncManager.block_index: AutoHashMap(Hash, *BlockIndex)`
   (sync.zig:899) — DEAD CODE. `SyncManager` is never instantiated
   outside its own unit tests (grep confirms no production callers in
   main.zig / peer.zig).

The active-chain "tip" lives in a fourth place: `ChainState.best_hash` /
`ChainState.best_height` (storage.zig). None of the three "block index"
maps is the source of truth for the active chain.

**File:** `src/validation.zig:5820`, `src/peer.zig:2393`,
`src/sync.zig:899`, `src/main.zig:1896-1925`

**Why this matters:**
- An `invalidateblock` RPC writes `failed_valid` to ChainManager's
  block_index ONLY. The live `.headers` handler queries
  `peer.header_index`, sees no flag, and continues to accept
  header-extensions of the invalidated chain (cross-cite BUG-1).
- The dead `SyncManager.block_index` carries an `active_chain:
  ArrayList(Hash256)` (sync.zig:905) — the only data structure shaped
  like Core's `CChain m_chain` — but it's a 0-LOC code path. Three
  pipelines, none of them shaped like Core.
- Three-pipeline drift is the W143/W145 universal pattern (rustoshi
  3-merkle, camlcoin 5-pipeline, ouroboros 3-consensus); clearbit
  exhibits the same shape at the block-index layer.

---

## BUG-4 (P1) — `FindFork` analog walks `prev_hash` pointers in O(depth)

**Severity:** P1 (performance, not correctness). Core's
`CChain::FindFork` uses the `m_chain` vector for O(1) "is this hash on
the active chain at height h" lookups. clearbit's `maybeArmReorg`
(peer.zig:3986-4030) walks `header_index.get(cursor).prev_hash` one
pointer at a time, capped at `MAX_REORG_DEPTH = 288` iterations
per call. There is no skip-list — `BlockIndexEntry` in
validation.zig has no Skip pointer either.

For each step the walk does a HashMap lookup followed by a `cs.hasBlock`
RocksDB hit (peer.zig:4000), so a deep fork can do hundreds of disk
reads under no lock guard. Worse, the walk's termination depends on
`cs.best_hash == cursor` (line 3996) — a single equality, not "any
ancestor on the active chain". If the fork point is genesis but
`best_height > 0`, the loop walks ALL the way back to the all-zero
genesis sentinel (lines 4014-4029) before terminating.

**File:** `src/peer.zig:3986-4030`

**Core ref:** `bitcoin-core/src/chain.cpp` (`CChain::FindFork`)

**Why this matters:** A peer offering a 287-deep fork (just under
MAX_REORG_DEPTH) burns 287 HashMap+RocksDB lookups per peer per fork
announcement, no lock release. With 100 peers each spamming forks the
manager loop stalls.

---

## BUG-5 (P0) — `activateBestChain` is a TODO stub; no UTXO disconnect/connect

**Severity:** P0 (semantic gap, **carry-forward W101 BUG-1 — open
across W101..W147 = 46+ waves**). `ChainManager.activateBestChain`
(validation.zig:6254-6339) walks `block_index`, picks the best
candidate via `compareCandidates`, then:

```zig
// If best is different from active_tip, we need to reorganize.
// Full reorg (disconnect + connect) is a separate TODO; here we
// update the pointer after the ancestor-walk guard has ensured the
// chain is valid.
if (best) |b| {
    if (self.active_tip) |tip| {
        if (!std.mem.eql(u8, &b.hash, &tip.hash)) {
            // TODO: Full reorg implementation (disconnect old, connect new).
            self.active_tip = b;
        }
    } else {
        self.active_tip = b;
    }
}
```

The `active_tip` pointer is swapped — but no `disconnectBlock`, no
`connectBlock`, no UTXO mutation, no mempool reorg. The downstream
chain state (`ChainState.best_hash`, `utxo_set`) is **not touched**.

The function is called from:
- `invalidateBlock` (validation.zig:6003) — RPC `invalidateblock`
- `reconsiderBlock` (validation.zig:6143) — RPC `reconsiderblock`
- `preciousBlock` (validation.zig:6218) — RPC `preciousblock`

All three RPCs effectively become "swap a pointer; UTXO and active
chain stay where they were". The bug is documented in
validation.zig:10848-10851 (W101 BUG-1) and again at line 10957 (W101
G1 confirmed test) with `TODO: Full reorg implementation` comment.
Comment-as-confession: 6th instance tracked.

**File:** `src/validation.zig:6325-6338`

**Core ref:** `bitcoin-core/src/validation.cpp:3323-3450`
(`ActivateBestChain`)

**Why this matters:**
- `invalidateblock` RPC succeeds, returns success to the operator, but
  the UTXO set is not rolled back. Subsequent `getbestblockhash`
  returns the original tip (from `chain_state.best_hash`), not the new
  `chain_manager.active_tip`. The two diverge silently. RPC clients
  thinking they invalidated a block continue to see the old tip in
  block-acceptance RPCs.
- This is BUG-class P0 with a 46-wave carry-forward — every quad-audit
  re-anchors it. Same pattern as W123→W145 BUG-1 nSubsidyHalvingInterval.

---

## BUG-6 (P1) — `ChainManager` has no chainstate mutex

**Severity:** P1 (W101 G5 still open). Core's `ActivateBestChain`
holds `cs_main` for its full duration; the chainstate mutex prevents
concurrent reorgs. clearbit's `ChainManager` struct (validation.zig:5818-5839)
has no `mutex`, `chainstate_mutex`, or `rwlock` field. A concurrent
`submitblock` RPC and IBD drain (both eventually touching
`chain_state` + `chain_manager`) can interleave. Today the manager
loop is single-threaded so the race is latent, but the wiring at
main.zig:1896 hands the same `&chain_state` and `&mempool_instance`
to both the `ChainManager` and the `RpcServer` — a future RPC
multithreading change would expose it immediately.

**File:** `src/validation.zig:5818-5839`

**Core ref:** `bitcoin-core/src/validation.cpp:3325` (LOCK cs_main)

---

## BUG-7 (P1) — `evictConflictingTransactions` is a TODO stub

**Severity:** P1 (dead-helper-at-call-site, W101 BUG-6 cross-cite).
`invalidateBlock` calls `evictConflictingTransactions(pool, target)`
at validation.zig:6007 — but the body (validation.zig:6384-6391) is:

```zig
fn evictConflictingTransactions(self: *ChainManager, pool: *@import("mempool.zig").Mempool, block: *BlockIndexEntry) void {
    _ = self;
    _ = pool;
    _ = block;
    // TODO: When we have full block data, evict transactions that:
    // 1. Spend UTXOs created by transactions in the invalidated block
    // 2. Were confirmed in the invalidated block but now need to go back to mempool
}
```

A no-op with three explicit discards and a TODO. Core's
`MaybeUpdateMempoolForReorg` runs after every `ActivateBestChainStep`
and is the primary mechanism for refilling the mempool with
transactions disconnected from the old chain (and evicting newly-stale
spends from the new chain). The dead helper is the disconnect-side
analog of W101 BUG-17; clearbit also lacks the connect-side post-reorg
mempool refill (no `mempool.RemoveForReorg` analog called from
`reorgToChain` either).

**File:** `src/validation.zig:6384-6391`

**Core ref:** `bitcoin-core/src/validation.cpp:3206`
(`MaybeUpdateMempoolForReorg`)

---

## BUG-8 (P2) — `reorgToChain` builds full disconnect+connect lists; no 32-step chunking

**Severity:** P2. Core's `ActivateBestChainStep` builds
`vpindexToConnect` with `nTargetHeight = std::min(nHeight + 32,
pindexMostWork->nHeight)` and re-enters the inner loop for the next
chunk, releasing `cs_main` between chunks. clearbit's `reorgToChain`
(storage.zig:3892-3962) walks the full disconnect path then the full
connect path inside ONE WriteBatch with no release point.

For a MAX_REORG_DEPTH=100 reorg, the function holds the manager loop
single-threadedly for 100 disconnect + 100 connect operations without
processing any P2P messages or RPC calls. The atomicity is the Pattern
D design (single shared WriteBatch); the responsiveness cost is
unmitigated.

**File:** `src/storage.zig:3892-3962`

**Core ref:** `bitcoin-core/src/validation.cpp:3217-3260`

---

## BUG-9 (P0-CDIV) — Two-pipeline `MAX_REORG_DEPTH` divergence: 288 vs 100

**Severity:** P0-CDIV (two-pipeline guard, **new fleet pattern
this quad**). Two distinct `MAX_REORG_DEPTH` constants:

1. `src/peer.zig:45`:
   ```zig
   /// Mirror of storage.MAX_REORG_DEPTH (= MIN_BLOCKS_TO_KEEP, 288).  Headers
   /// for a competing fork whose split-point is more than this many blocks
   /// behind the active tip are refused: we cannot disconnect that far without
   /// risking running out of undo data.  Per BIP-37 / Core's MIN_BLOCKS_TO_KEEP.
   pub const MAX_REORG_DEPTH: u32 = 288;
   ```

2. `src/storage.zig:3818`:
   ```zig
   pub const MAX_REORG_DEPTH: u32 = 100;
   ```

The peer-side `maybeArmReorg` (peer.zig:3992) arms a fork up to
288-deep; the storage-side `reorgToChain` (storage.zig:3882, 3903)
returns `error.ReorgTooDeep` for any fork > 100. A fork of depth 150
is **armed** by the peer (`pending_reorg` set, getdata sent to source
peer, bodies buffered) and then **refused** at the storage layer
after all bodies arrive — wasted bandwidth, wasted manager-loop time.

The peer.zig comment "Mirror of storage.MAX_REORG_DEPTH (= 288)" is
factually wrong on both halves — storage.zig says 100, not 288, and
288 is `MIN_BLOCKS_TO_KEEP` not `MAX_REORG_DEPTH`. **Comment-as-confession
7th tracked instance**.

Core has NO `MAX_REORG_DEPTH` constant — the only governing constant is
`MIN_BLOCKS_TO_KEEP = 288` (validation.h:75). On a > 100-block reorg
clearbit goes off-consensus relative to Core by *staying* on the
losing chain.

**File:** `src/peer.zig:41-45`, `src/storage.zig:3810-3818`

**Core ref:** `bitcoin-core/src/validation.h:75-76` (`MIN_BLOCKS_TO_KEEP`)

**Why this matters:**
- Cross-impl divergence at the reorg boundary: clearbit refuses a
  150-block reorg Core would happily apply. Two clearbit nodes at this
  depth will partition.
- Within a single clearbit node, the two-pipeline split wastes the
  manager loop on doomed reorg arms (288 — 100 = 188 buffered fork
  bodies that will never be connected).
- W123 P0-CDIV pattern at the `MAX_REORG_DEPTH` level — confidently
  asserted Core behavior that doesn't exist (echoes blockbrew W148
  BUG-5 in the cross-impl audit).

---

## BUG-10 (P1) — No operator knob for `MAX_REORG_DEPTH`

**Severity:** P1. Even granting BUG-9's atomicity / undo-availability
rationale, Core permits an operator to force deeper reorgs by setting
`-assumevalid=0` and restarting (effectively re-validates the entire
chain). clearbit offers no such knob — both
`peer.MAX_REORG_DEPTH = 288` and `storage.MAX_REORG_DEPTH = 100` are
compile-time constants. Recovery from a genuine 150-block reorg needs
a binary patch or full re-sync from genesis.

**File:** `src/peer.zig:45`, `src/storage.zig:3818`

---

## BUG-11 (P0-CDIV) — Failed block validation never marks `failed_valid`

**Severity:** P0-CDIV (carry-forward W101 BUG-4 — open across multiple
waves). `validateBlockForIBDOrReject` (peer.zig:6584-6604) on
failure:
1. Penalises the supplying peer +100 (immediate ban).
2. Removes the source-peer tracking entry.
3. Rewinds `download_cursor` so the slot is re-fetched.
4. `break;` out of the drain loop.

The failed block is **never marked invalid in either index**:
- `peer.header_index` entry stays as-is (no failed flag on
  BlockHeaderEntry — the struct has none at peer.zig:58-75).
- `chain_manager.block_index` doesn't even know about this block
  (live IBD path never writes here).

So the same hash can be re-served by a different peer; `insertHeader`
hits the "already present, refresh last_seen" path (peer.zig:3826-3832),
and `validateBlockForIBDOrReject` runs again — same failure, same +100
ban, same `break`. With many peers all serving the same bad chunk an
attacker burns through the peer list while the manager loop loops on
the same drain attempt.

**File:** `src/peer.zig:6584-6604`, `src/peer.zig:58-75` (BlockHeaderEntry has no failed flag)

**Core ref:** `bitcoin-core/src/validation.cpp:1988-1994`
(`InvalidBlockFound`)

**Why this matters:**
- Symmetric to BUG-1 — header layer and block layer both leak invalid
  state. Combined with the dead `chain_manager` pipeline (BUG-5), the
  entire failed-block accounting machinery is missing.

---

## BUG-12 (P2) — Reorg failure does NOT halt the node

**Severity:** P2. Core's `ActivateBestChainStep` treats DisconnectTip
failure as fatal (`FatalError`, return false). clearbit's
`reorgToChain` errdefer chain calls `abortReorgInProgress` (sets
`flush_error` sticky), then returns the error. The caller
(`tryFireReorg` at peer.zig:4191-4196) logs a warning, bans the
source peer, clears `pending_reorg`, and continues. No FatalError,
no shutdown.

`disconnectToBlock` (validation.zig:6086-6089) returns
`ChainError.DisconnectFailed` and the caller propagates. The
`flush_error` sticky bit blocks all further mutation but the read
path is unaffected — the node serves stale RPC responses until
restart.

**File:** `src/storage.zig:reorgToChain` (~3870-3987), `src/peer.zig:4191-4196`,
`src/validation.zig:6086-6089`

**Core ref:** `bitcoin-core/src/validation.cpp:3208-3214` (FatalError)

---

## BUG-13 (P1) — `BlockStatus` is a flag bitfield, not Core's 5-level ordered ladder

**Severity:** P1 (semantic mismatch). Core's `BlockStatus` encodes a
5-level **ordered** validity ladder in the low 3 bits (UNKNOWN=0,
RESERVED=1, TREE=2, TRANSACTIONS=3, CHAIN=4, SCRIPTS=5,
`BLOCK_VALID_MASK=7`), enabling `pindex->IsValid(BLOCK_VALID_TRANSACTIONS)`
("level ≥ 3"). High bits encode independent flags (HAVE_DATA=8,
HAVE_UNDO=16, FAILED_VALID=32, FAILED_CHILD=64, OPT_WITNESS=128).

clearbit's `BlockStatus` (validation.zig:5730-5760) is a packed
struct with bool flags:
```zig
valid_header: bool = false,  // bit 0
has_data: bool = false,      // bit 1
has_undo: bool = false,      // bit 2
failed_valid: bool = false,  // bit 3
failed_child: bool = false,  // bit 4
_padding: u27 = 0,
```

The ordered ladder collapses to a single `valid_header` boolean.
Intermediate states like `BLOCK_VALID_TRANSACTIONS` (body landed, no
chain-validity yet) vs `BLOCK_VALID_CHAIN` (chain-valid, scripts not
yet checked — relevant for assume-valid IBD) are inexpressible.
`FindMostWorkChain`-equivalent can't filter on "level ≥
BLOCK_VALID_CHAIN".

**File:** `src/validation.zig:5730-5760`

**Core ref:** `bitcoin-core/src/chain.h:42-86`

**Why this matters:**
- W138 assumeUTXO snapshot machinery needs to distinguish "header-only
  pindex" from "body-present pindex" from "chain-validated pindex" —
  with bool flags there's no clean way.
- `script_skip` decision (assume-valid path) wants to express "we've
  done CheckBlock but not ConnectBlock" — Core uses
  `BLOCK_VALID_TRANSACTIONS` for exactly this; clearbit has no analog.

---

## BUG-14 (P0-CDIV) — IBD-path persisted chain_work is ZERO; two-pipeline `putBlockIndex`

**Severity:** P0-CDIV (two-pipeline guard at the storage layer).
`ChainStore` exposes two writers to CF_BLOCK_INDEX:

1. `putBlockIndex` (storage.zig:293-306, 84-byte payload) — height (4) +
   header (80). Called by `SyncManager` (DEAD) at sync.zig:1085.
2. `putBlockIndexFull` (storage.zig:338-355, 140-byte payload) —
   height + header + status + chain_work + sequence_id + file_number +
   file_offset. Called by `ChainManager.persistBlockStatus`
   (validation.zig:5907-5921) — RPC paths only.

The live IBD path uses neither directly. Instead, the IBD flush
(storage.zig:4498-4595) constructs a `BlockIndexRecord` per block and
puts it into CF_BLOCK_INDEX. The relevant excerpt:

```zig
var rec = ChainStore.BlockIndexRecord{
    .height = bw.height,
    .header = blk_header,
    .status = new_status_bits,
    .chain_work = [_]u8{0} ** 32,   // ← zero!
    .sequence_id = 0,
    .file_number = 0,
    .file_offset = 0,
};
if (db.get(CF_BLOCK_INDEX, &bw.hash) catch null) |existing| {
    // ... overlay chain_work from existing entry IF PRESENT
}
```

For a fresh IBD block, no prior CF_BLOCK_INDEX entry exists, so
`chain_work = 0` is committed to disk. The only blocks that ever get
the real `chain_work` written are those touched by
`ChainManager.persistBlockStatus` — which is ONLY called by RPC
`invalidate`/`reconsider`/`precious`.

**File:** `src/storage.zig:293-306`, `src/storage.zig:338-355`,
`src/storage.zig:4548-4571`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp` (CBlockTreeDB
WriteBatchSync persists CDiskBlockIndex with full nChainWork).

**Why this matters:**
- After restart, `chain_manager.loadBlockFromStore` reads
  `chain_work = 0` for every non-RPC-touched block. `compareCandidates`
  (validation.zig:6239-6251) compares chain_work first — every block
  ties on chain_work=0 and falls through to sequence_id (also 0) then
  to hash-lessThan. Chain selection becomes lexicographically-smallest-
  hash chosen, NOT highest-work.
- Cross-impl divergence: a restart-replay of the same chain may pick a
  different "best candidate" than the live node ever did, because the
  persisted ordering is broken.
- This is the same shape as the rustoshi W142 "decoder accepts
  superset-of-encoder" — two write paths produce records that the
  read path can't reconcile.

---

## BUG-15 (P1) — `BlockIndexEntry` has no `nTx` / `chain_tx_count` field

**Severity:** P1 (cross-cite W138 BUG-18). Core's `CBlockIndex` carries
`nTx` (per-block tx count, set by `ReceivedBlockTransactions`) and
`m_chain_tx_count` (cumulative tx count from genesis or assumeutxo base,
set when both pprev and self are `BLOCK_VALID_TRANSACTIONS`). Used by
`getblockchaininfo` (returns `nchaintx`), `EstimateBlockTime`,
sync-progress, and verificationprogress.

clearbit's `BlockIndexEntry` (validation.zig:5765-5814) has fields:
`hash, header, height, status, chain_work, sequence_id, parent,
file_number, file_offset`. **No `tx_count`, no `chain_tx_count`, no
`nTx`.** The persisted `BlockIndexRecord` (storage.zig:326-334)
likewise has no tx count fields.

**File:** `src/validation.zig:5765-5814`, `src/storage.zig:326-334`

**Core ref:** `bitcoin-core/src/chain.h:120-129`

**Why this matters:**
- `getblockchaininfo`'s `nchaintx` must be fabricated, returned as
  zero, or computed by walking all stored block bodies (expensive).
- `verificationprogress` can't consult per-block tx density; falls back
  to height-based linear interpolation. Mainnet's tx density varies
  ~100× across history, so the progress bar is significantly inaccurate
  during IBD.
- assumeUTXO snapshot validation (W138) can't stamp `m_chain_tx_count`
  on the snapshot base — silent W138 dependency.

---

## BUG-16 (P0-CDIV) — Genesis `chain_work = 0`; `chainWorkFromHeight` placeholder ignores difficulty

**Severity:** P0-CDIV (two-pipeline + dead-data). Two distinct
chain-work computation bugs in the same wave:

### 16a. `loadGenesis` stamps zero chain_work
`ChainManager.loadGenesis` (validation.zig:6349-6369):
```zig
genesis.* = BlockIndexEntry{
    ...
    .chain_work = [_]u8{0} ** 32,
    ...
};
```

Bitcoin Core (`bitcoin-core/src/node/blockstorage.cpp:247`) sets:
```cpp
pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
```

For genesis (`pprev == nullptr`), this is `0 + GetBlockProof(genesis)`
— for mainnet `nBits = 0x1d00ffff`, that's `~2^32`. Every clearbit
descendant block's chain_work is therefore short by genesis's
GetBlockProof. `min_chain_work` gates that depend on the absolute
chain_work value (peer.zig:4519-4551) are off by the genesis-work
amount.

### 16b. `chainWorkFromHeight` is a placeholder with no difficulty
`chainWorkFromHeight` (peer.zig:266-281) encodes `(height + 1)` into
the trailing 5 bytes of a 32-byte big-endian buffer — purely linear
in height, ignoring `nBits` entirely. Used by:
- `lookupParentChainWork` fallback at peer.zig:3800 (when ChainState
  best_hash is the parent — common case)
- `maybeArmReorg` to compute `active_work` at peer.zig:4049

The function's own docstring confesses: "intentionally cheap — the
only invariant the consumer cares about is that two heights H1 < H2
produce work-values W1 < W2". **But the consumer at peer.zig:4050 IS
comparing it against fork chain_work computed from real difficulty**
via `workFromBits` — apples vs oranges.

A consequence: a fork of equal height that has actually retargeted to
higher difficulty (heavy chain) will compare ≤ the active tip's
`chainWorkFromHeight(best_height)` (light placeholder) — clearbit will
refuse to reorg to a chain Core would happily accept.

**File:** `src/validation.zig:6349-6369` (16a), `src/peer.zig:266-281`
(16b), `src/peer.zig:4049` (16b consumer)

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:247`

**Why this matters:**
- 16a: persisted chain_work is short by genesis work for every block;
  any future cross-impl chain_work comparison (e.g. assumeUTXO snapshot
  bind check) will fail. Core's snapshots are stamped with absolute
  nChainWork.
- 16b: heavy forks at the same height as the active tip are silently
  refused. This is the **placeholder-as-production** anti-pattern;
  similar shape to ouroboros's BIP9 "TAPROOT NEVER SET" P0-CONS in W144
  (data structure exists, value derivation is fake).

---

## BUG-17 (P0-CDIV) — `reconsiderBlock` clears `failed_child` unconditionally on all descendants

**Severity:** P0-CDIV (W101 BUG-7 carry-forward; cross-cite blockbrew
W148 BUG-12). Core's `ResetBlockFailureFlags` (validation.cpp:3711-3730)
walks `m_block_index` and clears `BLOCK_FAILED_VALID` ONLY from blocks
that match BOTH:
1. `(block_index.GetAncestor(nHeight) == pindex || pindex->GetAncestor(block_index.nHeight) == &block_index)` — block is in pindex's ancestor chain OR a descendant of pindex
2. `(block_index.nStatus & BLOCK_FAILED_VALID)` — already failed

clearbit's `reconsiderBlock` (validation.zig:6105-6144) +
`clearDescendantFailure` (validation.zig:6147-6178):
- Clears `failed_valid` ONLY on the exact target (line 6109), not on
  any ancestor matching the height filter.
- Clears `failed_child` UNCONDITIONALLY on every descendant via BFS,
  with no `BLOCK_FAILED_VALID` filter:

```zig
const block = queue.items[i];
block.status.failed_child = false;
try self.persistBlockStatus(block);
```

If a descendant of the reconsidered block has its own
independently-set `failed_valid` (e.g. a separate `invalidateblock`
RPC was fired on that descendant), `clearDescendantFailure`
**doesn't touch failed_valid** but DOES strip `failed_child` —
opening the door for that descendant's children to be re-evaluated
without re-validation. The operator's deliberate two-block
invalidation is partially undone.

**File:** `src/validation.zig:6105-6178`

**Core ref:** `bitcoin-core/src/validation.cpp:3711-3730`

**Why this matters:**
- An operator who invalidates block b1 and then later invalidates b2
  (descendant of b1, for an independent reason) and then reconsiders
  b1 will see b2 stay `failed_valid` (correct) but b2's children lose
  `failed_child` (wrong) — they become re-eligible. Same shape as
  blockbrew W148 BUG-12 ("clears all ancestors") but at the descendant
  side.
- Already documented at validation.zig:10876 (W101 BUG-7) and
  validation.zig:11192 (W101 G8 BUG-CONFIRMED test) — no fix lands
  across W101..W147.

---

## BUG-18 (P1) — `chain_tips` ArrayList is dead in production; only written by RPC

**Severity:** P1 (dead-data plumbing). `ChainManager.chain_tips:
ArrayList(*BlockIndexEntry)` (validation.zig:5822) is declared as
"Blocks eligible for being the chain tip (valid candidates)". In
production code:

- WRITES: only `reconsiderBlock` (validation.zig:6138) appends.
  `loadGenesis` does NOT add genesis. The live IBD path does NOT add
  newly-extended tips. Test code adds entries (lines 6802, 6803, 6887,
  6888, 6958, 6959 in test-only paths).
- READS: only `removeFromChainTips` (validation.zig:6372-6381) — which
  is itself only called from `invalidateBlock` (validation.zig:5991).
- `activateBestChain` (validation.zig:6254-6339) **does not read
  chain_tips** — it scans ALL of `block_index` instead.

The field exists, is declared, is initialised, has dedicated
maintenance methods (`removeFromChainTips`) — and contributes nothing
to chain selection. Dead-data pattern: field defined-and-consulted-
in-tests-but-never-emitted-in-production. Compare with W141 ouroboros
"BIP9 DEFINED forever" and W138 ChainstateManager wiring patterns.

**File:** `src/validation.zig:5822, 5848-5849, 6138, 6372-6381`

**Core ref:** `bitcoin-core/src/validation.cpp:3110-3171`
(`setBlockIndexCandidates`)

**Why this matters:**
- Future readers may believe `chain_tips` is a maintained set; they
  may add code that depends on it (e.g. for a `gettipinfos`-equivalent
  RPC) and silently get partial data. The dead-data shape is exactly
  the W138 fleet-wide pattern.
- `activateBestChain`'s O(N) scan over `block_index` (validation.zig:
  6262-6263) is the consequence — Core's `FindMostWorkChain` uses the
  sorted candidate set for O(log N) top-of-set; clearbit re-scans 900k
  entries on every invalidate/reconsider RPC.

---

## BUG-19 (P1) — IBD exit / `IsInitialBlockDownload` uses queue-length heuristic, not chainwork+tip-recent

**Severity:** P1 (cross-cite blockbrew W148 BUG-13). Bitcoin Core's
`UpdateIBDStatus` (validation.cpp:3283-3291) exits IBD when the active
chain tip is "recent" (within `max_tip_age = 24h`) AND has chainwork ≥
`MinimumChainWork`. The state is a one-way latch
(`m_cached_is_ibd.store(false)`).

clearbit's `PeerManager.isIBD` (peer.zig:6899-6912):
```zig
fn isIBD(self: *const PeerManager) bool {
    if (self.chain_state) |cs| {
        if (self.expected_blocks.items.len > 0) return true;
        if (self.block_buffer.count() > 0) return true;
        for (self.peers.items) |p| {
            if (p.start_height > 0 and cs.best_height + 10 < @as(u32, @intCast(p.start_height))) {
                return true;
            }
        }
    }
    return false;
}
```

Issues:
- Not latched — every call re-evaluates against live peer state. A
  peer reconnecting with `start_height` 11 ahead of our tip flips us
  BACK to IBD even at steady state.
- Doesn't consult `MinimumChainWork` at all — a chain on testnet that
  reorgs back below `min_chain_work` doesn't trigger IBD-resume.
- Doesn't consult wall-clock — `max_tip_age` (24h in Core) is the
  primary signal that "we're no longer in IBD" even when no peers are
  ahead. clearbit has no tip-freshness gate.
- The `+ 10` literal is a magic number with no Core analog. Core's
  comparison is `pindex->GetBlockTime() > GetAdjustedTime() - max_tip_age`.

**File:** `src/peer.zig:6899-6912`

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291`

**Why this matters:**
- On regtest: with no peers, `isIBD()` returns false — but cs.best_height
  may be 0 (genesis-only). Operator workflows expecting "stay in IBD
  until I mine N blocks" silently exit IBD.
- Wall-clock-irrelevance breaks mempool-acceptance ramp-up: Core uses
  `IsInitialBlockDownload` to gate fee filter publication, addr relay
  rate, sendcmpct activation. clearbit gates differently (or not at
  all) for each subsystem.

---

## BUG-20 (P1) — `is_requested = true` hardcoded; `fTooFarAhead` gate never fires for unsolicited blocks

**Severity:** P1. `validateBlockForIBDOrReject` (peer.zig:6396-6424)
unconditionally passes `is_requested = true` to `acceptBlock`:

```zig
.active_tip_height = cs.best_height,
.is_requested = true,
```

The plumbing is there (`IBDValidationContext.is_requested: bool =
false` default at validation.zig:1103; the fTooFarAhead gate at
validation.zig:1133-1148 only fires when `is_requested == false`). The
comment at peer.zig:6418-6421 explicitly anticipates this:
> "active_tip_height is still wired so future callers that pass
> is_requested=false (e.g. unsolicited block handlers) get the check
> for free."

But there is no unsolicited-block handler — the `.block` handler at
peer.zig:4575+ has no `fRequested` classification. Every block goes
through `validateBlockForIBDOrReject` with `is_requested = true`. The
gate exists, the plumbing exists, but no production caller exercises
the `is_requested = false` path. **Plumbed-but-never-flipped pattern**
(W141 nimrod precedent).

**File:** `src/peer.zig:6422-6423`, `src/validation.zig:1103, 1133-1148`

**Core ref:** `bitcoin-core/src/validation.cpp:4325-4339`

**Why this matters:**
- A peer can announce an unsolicited block at h = tip + 1000000 and
  clearbit will run the full validation pipeline (PoW, MTP, BIP-30
  context lookups, etc.) before failing — Core would short-circuit at
  the fTooFarAhead gate before any work. DoS amplification.

---

## BUG-21 (P1) — Header-time MTP check skipped when fewer than 1 ancestor in `header_index`

**Severity:** P1. `validateHeaderContextual` (peer.zig:6294-6312)
delegates MTP to `computePrevMtp`:
```zig
const prev_mtp = self.computePrevMtp(&header.prev_block);
if (prev_mtp != 0 and header.timestamp <= prev_mtp) {
    return .mtp_violation;
}
```

`computePrevMtp` returns 0 when fewer than 1 ancestor is in
`header_index`. The comment at peer.zig:6288-6290 says "skipped when
fewer than 1 ancestor is in `header_index` (e.g. headers received
before any prior batch landed in the index)". This is the early-IBD
window where the index is being populated.

Issue: a peer that delivers a single header out-of-band (e.g. via the
unsolicited-block path, or a competing-fork batch where the parent
hash is in `chain_state` but no recent ancestors are in
`header_index`) bypasses MTP entirely. The body-validation pipeline
re-checks MTP via `validateBlockForIBD`'s `ctx.prev_mtp` — but only
if the body arrives. A header-only flood can fill `header_index` with
MTP-violating headers that compete for tip selection.

**File:** `src/peer.zig:6288-6312`

**Core ref:** `bitcoin-core/src/validation.cpp:4092-4093` (CContextualCheckBlockHeader unconditional MTP)

---

## BUG-22 (P2) — No `NotifyHeaderTip` analog / no header-tip change notification

**Severity:** P2 (operability, W97 G15 carry-forward). Core's
`ProcessNewBlockHeaders` (validation.cpp:4263) emits `NotifyHeaderTip`
after each accepted header batch (outside `cs_main`). Subscribers:
ZMQ `hashheader`/`headerhwm`, RPC `waitfornewblock` (header-mode),
GUI block-count, headerssync.cpp progress.

clearbit has no equivalent. W97 G15 test (validation.zig:10248) is a
documentation-only assertion ("module compiles without the symbol").
No ZMQ topic; no callback hook. Operators bringing up a new node have
no way to subscribe to header-arrival events; explorers depending on
header-tip advances must poll `getbestblockhash`.

**File:** `src/peer.zig:.headers handler (~4399-4574)`, `src/validation.zig:10248`

**Core ref:** `bitcoin-core/src/validation.cpp:4263`

---

## BUG-23 (P2) — `evictHeaderIndex` LRU sweep can drop active-chain ancestors

**Severity:** P2. `evictHeaderIndex` (peer.zig:3875-3907) drops the
oldest 10% of `header_index` entries by `last_seen` whenever the index
exceeds MAX_HEADER_INDEX (10000). The comment at peer.zig:3859-3864
claims "Active-chain ancestors should rarely be touched in practice
(they arrive once during IBD then never again), so this happens to
bias eviction toward stale fork branches".

This is the **opposite of correct**: active-chain ancestors that
arrived during IBD have the OLDEST `last_seen` timestamps (no
re-touch). A 287-deep fork announcement at peer.zig:4005-4030 walks
`header_index.get(cursor).prev_hash` — if those active-chain
ancestors have been evicted, the walk falls off the index (line 4007:
"walk fell off header_index") and the reorg arming **aborts**.

So the eviction policy systematically drops the exact ancestors the
reorg path needs to walk. The comment's confident assertion is the
inverse of the bug it documents — **comment-as-confession 8th
tracked instance**.

**File:** `src/peer.zig:3859-3907`

**Why this matters:** On a long-running clearbit node with steady-state
header churn (rare fork announcements over hundreds of hours), the
header_index gradually loses its IBD-vintage ancestors. A genuine
network-level reorg attempt then aborts at the FindFork analog because
the common ancestor is no longer in memory. The reorg is silently
refused; the operator sees no log entry beyond a warning.

---

## BUG-24 (P2) — `disconnectToBlock` treats `DisconnectUnclean` as fatal

**Severity:** P2 (over-rejection vs Core). `disconnectToBlock`
(validation.zig:6056-6094) at line 6086-6089:

```zig
chain_state.disconnectBlockByHash(
    &tip.hash, ...
) catch |err| {
    std.debug.print("disconnectToBlock: disconnect of {x} failed with {}\n", ...);
    return ChainError.DisconnectFailed;
};
```

The W92 comment at lines 6071-6079 says this mirrors Core's
`DisconnectTip` which "checks `!= DISCONNECT_OK`". But the same
comment notes Core's VerifyDB caller (`RollbackBlock` at
validation.cpp:4824) "may tolerate UNCLEAN". clearbit collapses both
DISCONNECT_FAILED and DISCONNECT_UNCLEAN into one `DisconnectFailed`
return, with no UNCLEAN distinction. So:
- A reorg-side disconnect that is UNCLEAN aborts the reorg (fine —
  matches Core's reorg-side).
- A future VerifyDB / `checkblock` RPC path that wants to tolerate
  UNCLEAN can't — there's no second error variant.

**File:** `src/validation.zig:6056-6094`

**Core ref:** `bitcoin-core/src/validation.cpp:2949-2956` (DisconnectTip checks),
`bitcoin-core/src/validation.cpp:4824` (VerifyDB tolerates UNCLEAN)

---

## Fleet-pattern smells

- **Two-pipeline guard** (3×):
  - `MAX_REORG_DEPTH = 288` (peer.zig:45) vs `MAX_REORG_DEPTH = 100`
    (storage.zig:3818) (BUG-9; 16th fleet-tracked distinct instance,
    new shape: "two consts with a mirror-comment that lies about the
    value")
  - `ChainStore.putBlockIndex` (84-byte) vs `putBlockIndexFull`
    (140-byte) (BUG-14; both write to CF_BLOCK_INDEX)
  - `validateHeaderContextual` vs `validation.acceptBlock` MTP path
    (BUG-21; header layer optional, body layer mandatory)
- **Three-pipeline drift** (1×): `validation.ChainManager.block_index`
  + `peer.PeerManager.header_index` + `sync.SyncManager.block_index`
  + `ChainState.best_hash` (BUG-3; 4-way drift, exceeds W143/W145
  three-pipeline pattern by one tier)
- **Comment-as-confession** (8th–10th tracked instances):
  - BUG-9 "Mirror of storage.MAX_REORG_DEPTH (= MIN_BLOCKS_TO_KEEP,
    288)" — neither half is correct (storage has 100, MIN_BLOCKS_TO_KEEP
    isn't MAX_REORG_DEPTH)
  - BUG-5 `// TODO: Full reorg implementation (disconnect old, connect
    new)` — documented hole, never closed
  - BUG-23 "Active-chain ancestors should rarely be touched in
    practice, so this happens to bias eviction toward stale fork
    branches" — exactly the opposite of what happens
- **Dead-data plumbing** (3×):
  - `chain_tips: ArrayList` (BUG-18; defined, init'd, mutated by tests,
    never read by production chain selection)
  - `BlockHeaderEntry.last_seen` LRU sentinel (BUG-23; consumed by an
    eviction policy that drops the records the reorg path needs)
  - `IBDValidationContext.is_requested = false` path (BUG-20; default
    exists, gate exists, no production caller flips it)
- **Plumb-gate-then-flip absent** (1×): `fTooFarAhead` (BUG-20;
  W141 nimrod parallel — `is_requested` always hardcoded true)
- **TODO-stub-in-RPC-handler** (2×):
  - `activateBestChain` (BUG-5; pointer swap, no UTXO mutation)
  - `evictConflictingTransactions` (BUG-7; `_ = self; _ = pool; _ =
    block;` no-op)
- **Carry-forward re-anchor** (5×): W101 BUG-1 (activateBestChain
  stub, BUG-5 here), W101 BUG-4 (failed_valid never set, BUG-11 here),
  W101 BUG-5 (no chainstate_mutex, BUG-6 here), W101 BUG-6
  (evictConflictingTransactions stub, BUG-7 here), W101 BUG-7
  (clearDescendantFailure unconditional, BUG-17 here) — five W101 bugs
  still open ~47 waves later, all documented with TODOs.
- **Placeholder-in-production** (1×): `chainWorkFromHeight` returns a
  height-encoded value not actual GetBlockProof; consumed by
  reorg arming comparison (BUG-16b). Same shape as ouroboros W144
  TAPROOT BIP9 dead-data.
- **30-of-30 GATES** — not fired (this audit has 24 BUGs spread
  across 8 behaviours; clusters around chain-manager being a
  pointer-only stub, two-pipeline writes to the persisted index, and
  the absence of an `m_best_header`/`setBlockIndexCandidates`
  equivalent).

---

## Summary

24 BUGs across 8 behaviours. Severity totals:

- **P0-CDIV** (consensus-divergent): 7 — BUG-1, BUG-9, BUG-11, BUG-14,
  BUG-16, BUG-17, BUG-3 *(P1 listed but borderline)*
- **P0** (semantic gap): 1 — BUG-5 (activateBestChain stub; 47-wave
  carry-forward)
- **P1** (correctness / performance / observability): 12 — BUG-2,
  BUG-3, BUG-4, BUG-6, BUG-7, BUG-10, BUG-13, BUG-15, BUG-18, BUG-19,
  BUG-20, BUG-21
- **P2**: 4 — BUG-8, BUG-12, BUG-22, BUG-23, BUG-24

Highest-leverage fixes:
1. **BUG-9** (~3 lines: reconcile `MAX_REORG_DEPTH` constants and
   update the lying comment) — also closes the wasted-bandwidth path
   between arming and refusing.
2. **BUG-5** (architectural — implement disconnect/connect in
   `activateBestChain` or remove the stub and route invalidate/
   reconsider/precious through `storage.reorgToChain`) — closes the
   long-standing chain_state / chain_manager state divergence.
3. **BUG-14** (~5 lines: in the IBD flush path, derive chain_work from
   the header's parent rather than stamping zero — uses
   `chain_manager.getBlock(prev) -> chain_work + workFromBits(bits)`).
4. **BUG-16a** (1 line: `loadGenesis` stamps `chain_work =
   getBlockProof(genesis_header.bits)`).
5. **BUG-1** (~5 lines: `insertHeader` consults
   `chain_manager.getBlock(prev).status.isInvalid()` and rejects with
   peer-misbehavior on parent-invalid).
6. **BUG-11** (~10 lines: on `validateBlockForIBDOrReject` failure,
   mark the failing block's `chain_manager` entry as `failed_valid`
   before banning the supplying peer).
7. **BUG-17** (~5 lines: add `if (block.status.failed_valid) continue;`
   inside `clearDescendantFailure`'s BFS body).
8. **BUG-3** (architectural — collapse the three pipelines to one;
   delete the dead `SyncManager` and route header arrival through
   `chain_manager.block_index`).
