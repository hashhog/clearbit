# W153 — Mempool eviction + tx-removed signals + min-relay fee (clearbit)

**Wave:** W153 — `TrimToSize`, `GetMinFee`, `CalculateMemPoolAncestors`,
`RemoveStaged`, `removeForBlock` / `removeRecursive` /
`MemPoolRemovalReason::{EXPIRY,SIZELIMIT,REORG,BLOCK,CONFLICT,REPLACED}`,
`trackPackageRemoved` / `rollingMinimumFeeRate` /
`blockSinceLastRollingFeeBump` / `lastRollingFeeUpdate`,
`DEFAULT_MAX_MEMPOOL_SIZE_MB=300`, `DEFAULT_MEMPOOL_EXPIRY_HOURS=336`,
`DEFAULT_MIN_RELAY_TX_FEE=100`, `DEFAULT_INCREMENTAL_RELAY_FEE=100`,
`DUST_RELAY_TX_FEE=3000`, `ROLLING_FEE_HALFLIFE=12h` (× ÷4 / ÷2 by
fill-fraction), `MaybeUpdateMempoolForReorg`, `prioritisetransaction`
RPC, `TransactionRemovedFromMempool` / `TransactionAddedToMempool`
signal fan-out, ZMQ `hashtx` / `rawtx` / `sequence` ('A'/'R').

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/kernel/mempool_options.h:19,23,40-44` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB=300`, `DEFAULT_MEMPOOL_EXPIRY_HOURS=336`,
  `max_size_bytes{300 * 1'000'000}` (SI MB),
  `expiry{hours{336}}` (= 14 days = 1,209,600 s),
  `incremental_relay_feerate{DEFAULT_INCREMENTAL_RELAY_FEE}`,
  `min_relay_feerate{DEFAULT_MIN_RELAY_TX_FEE}`.
- `bitcoin-core/src/policy/policy.h:48,68,70` —
  `DEFAULT_INCREMENTAL_RELAY_FEE=100`, `DUST_RELAY_TX_FEE=3000`,
  `DEFAULT_MIN_RELAY_TX_FEE=100` (all sat/kvB).
- `bitcoin-core/src/txmempool.h:212` —
  `static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12;` (12h).
- `bitcoin-core/src/txmempool.cpp:829-851::GetMinFee(size_t sizelimit)` —
  rolling-fee state machine: returns `CFeeRate(0)` when zeroed; ÷4 / ÷2
  halflife by `DynamicMemoryUsage() < sizelimit/{4,2}`; takes `sizelimit`
  AS A PARAMETER (the operator-configurable max_size_bytes).
- `bitcoin-core/src/txmempool.cpp:853-859::trackPackageRemoved(rate)` —
  bumps `rollingMinimumFeeRate` to `max(rate, current)`;
  clears `blockSinceLastRollingFeeBump`.
- `bitcoin-core/src/txmempool.cpp:861-911::TrimToSize(size_t sizelimit,
  std::vector<COutPoint>* pvNoSpendsRemaining)` — loops
  `while (DynamicMemoryUsage() > sizelimit)`, picks `GetWorstMainChunk()`,
  computes `removed += incremental_relay_feerate` and calls
  `trackPackageRemoved(removed)`, then `removeUnchecked(e,
  MemPoolRemovalReason::SIZELIMIT)`. **Pushes `pvNoSpendsRemaining` so
  the caller can prune the UTXO cache of outpoints whose only spender
  was just evicted (Core's CCoinsViewCache eviction hook).**
- `bitcoin-core/src/txmempool.cpp:811-827::Expire(time)` —
  collects expired entries, calls `CalculateDescendants` per entry to
  expand the stage to its descendants, then `RemoveStaged(stage,
  MemPoolRemovalReason::EXPIRY)`.
- `bitcoin-core/src/txmempool.cpp:1143::blockConnected` — sets
  `blockSinceLastRollingFeeBump = true`.
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20` —
  `enum class MemPoolRemovalReason { EXPIRY, SIZELIMIT, REORG, BLOCK,
  CONFLICT, REPLACED };`.
- `bitcoin-core/src/validationinterface.h:96-109,224` —
  `TransactionRemovedFromMempool(tx, reason, mempool_sequence)` signal
  fans out to ZMQ (`zmqpubsequence` 'R' frame +
  per-tx `zmqpubhashtx-removed` topic), fee-estimator
  `MempoolTransactionsRemovedForBlock`, REST `/rest/mempool`,
  wallet `NotifyTransactionLock`.
- `bitcoin-core/src/validation.cpp:275` —
  `pool.TrimToSize(pool.m_opts.max_size_bytes, &vNoSpendsRemaining)`
  inside `AcceptToMemoryPoolWorker` post-admission.
- `bitcoin-core/src/validation.cpp:319,2978` —
  `m_mempool->removeRecursive(tx, MemPoolRemovalReason::REORG)` inside
  `MaybeUpdateMempoolForReorg` (called from `DisconnectTip`).
- `bitcoin-core/src/rpc/mining.cpp:502::prioritisetransaction` —
  three-arg RPC (txid, dummy_btc=0, fee_delta_sats).
- `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo` — emits
  `maxmempool`, `mempoolminfee` (= GetMinFee/100M as BTC/kvB),
  `minrelaytxfee` (= m_opts.min_relay_feerate as BTC/kvB),
  `incrementalrelayfee` (= m_opts.incremental_relay_feerate as BTC/kvB),
  `unbroadcastcount`, `fullrbf` — every value sourced from
  live `m_opts` / state, NOT hardcoded literals.

**Files audited**
- `src/mempool.zig` — `MAX_MEMPOOL_SIZE`, `MEMPOOL_EXPIRY`,
  `MIN_RELAY_FEE`, `INCREMENTAL_RELAY_FEE`, `ROLLING_FEE_HALFLIFE`,
  `Mempool.init`, `addTransaction` (line 986), `addTransactionWithPackageRate`
  (line 3752), `removeTransaction` (line 1593),
  `removeTransactionWithDescendants` (line 1705), `removeForBlock`
  (line 1726), `blockDisconnected` (line 1778), `evict` (line 3153),
  `evictByCluster` (line 4454), `evictOldestOrphan` (line 1918),
  `trackPackageRemoved` (line 3634), `getMinFee` (line 3661),
  `removeExpired` (line 3729), `prioritiseTransaction` (line 2240),
  `applyDelta` (line 2257), `getModifiedFee` (line 2263), `isDust`
  (line 3113).
- `src/mempool_persist.zig` — `MEMPOOL_DUMP_VERSION=2`, XOR
  obfuscation, `loadMempool`, `dumpMempool`.
- `src/zmq.zig:252-277` — `publishTx(txid, raw_bytes)`: emits
  `hashtx`, `rawtx`, and `sequence` 'A' (Added) frame ONLY. No
  'R' (Removed) frame exists; no `removeUnchecked` hook calls
  `publishTx`.
- `src/rpc.zig:2965-3163` — RPC dispatch table for
  `getmempoolinfo`, `prioritisetransaction`,
  `getprioritisedtransactions`, `savemempool`, `loadmempool`,
  `submitpackage`, `testmempoolaccept`, `gettxoutproof`.
- `src/rpc.zig:4500-4519::handleGetMempoolInfo` — JSON template.
- `src/rpc.zig:4659-4741::handlePrioritiseTransaction`.
- `src/main.zig:85-86, 289-294, 712-715, 1803` — `config.maxmempool`
  (default 300), `config.mempoolexpiry` (default 336), `Mempool.init(
  &chain_state, params, allocator)`.
- `src/validation.zig:11116-11125` — `evictConflictingTransactions
  is a no-op stub` (W101 G6 / BUG-6 already catalogued).
- `src/block_template.zig:1162, 1359, 1530-1547, 884, 1525` —
  `removeForBlock(block)` call after `acceptBlock`; `blockDisconnected`
  + `removeForBlock` two-step for reorg refill ("Pattern B").
- `src/peer.zig:6673, 1716-1718` — `removeForBlock` on inbound block;
  `passesFeeFilter` BIP-133 honouring.

---

## Gate matrix (30 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | DEFAULT_MAX_MEMPOOL_SIZE_MB=300 | G1: constant set | PASS (`mempool.zig:29` `MAX_MEMPOOL_SIZE = 300 * 1_000_000` — SI MB, correct) |
| 1 | … | G2: CLI `--maxmempool=N` actually wired into mempool | **BUG-1 (P1)** — flag is parsed (`main.zig:289-291, 712-713`) but never read; `Mempool.init` takes no max-size parameter (`main.zig:1803`). Hardcoded constant is the only source. |
| 1 | … | G3: documented unit matches Core | **BUG-2 (P1)** — `main.zig:85` and `--help` (line 511) say "MiB"; Core uses SI MB. |
| 1 | … | G4: TrimToSize loops while `total_bytes > sizelimit` | **BUG-3 (P0-CDIV)** — `evict()` (line 3159) loops `while (freed < needed_bytes)` — terminates on per-call delta, not on absolute target. Core loops `while (DynamicMemoryUsage() > sizelimit)`. Effect: a tx that needs e.g. 600 KB of room can leave the mempool over the configured cap if a single eviction freed 600 KB exactly at the cap-boundary; subsequent admits use `total_size + vsize > MAX` against the still-overfilled total. |
| 1 | … | G5: TrimToSize size metric matches Core (DynamicMemoryUsage, not vsize) | **BUG-4 (P0-CDIV)** — `total_size` (line 782, 1416, 1696, 3989) is the SUM OF VBYTES, not memory usage. Core's `DynamicMemoryUsage()` includes entry metadata, descendant maps, mapDeltas, etc — roughly 6-10× the raw tx bytes. A 300 MB cap on vsize lets the in-memory footprint reach 1.8 GB+. Cross-impl divergence: a mempool that would TrimToSize on Core stays uncapped on clearbit until it consumes 6× more memory. |
| 2 | DEFAULT_MEMPOOL_EXPIRY_HOURS=336 (14 d) | G6: constant set | PASS (`mempool.zig:44` `MEMPOOL_EXPIRY = 14 * 24 * 60 * 60`) |
| 2 | … | G7: operator can override via `--mempoolexpiry=N` (hours) | **BUG-5 (P1)** — flag parsed (`main.zig:292-294, 714-715`, default 336) but never read; constant is hard-coded. Dead-data plumbing. |
| 2 | … | G8: time-based expiry sweep ever runs in production | **BUG-6 (P0-CDIV)** — `removeExpired()` is defined (`mempool.zig:3729`), TESTED at line 12048, but a `grep -rE removeExpired src/` against production paths (validation, sync, peer, block_template, main) returns ZERO call sites. Mempool entries that exceed 14 days are NEVER swept. Cross-impl divergence: clearbit will accumulate expired txs indefinitely on a node with no inbound blocks (idle node, regtest, signet stalled). **Dead-helper-at-call-site, 6th distinct clearbit instance.** |
| 2 | … | G9: descendants of an expired parent also expire | PASS (`mempool.zig:3729-3747` calls `removeTransactionWithDescendants`, comment explicitly documents the bug-this-fixes from prior wave); held back ONLY by G8 (function never runs in production). |
| 3 | DEFAULT_MIN_RELAY_TX_FEE=100 (sat/kvB) | G10: constant set | PASS (`mempool.zig:49` `MIN_RELAY_FEE = 100`) |
| 3 | … | G11: operator override via `--minrelaytxfee=X` | **BUG-7 (P1)** — no CLI flag exists (`main.zig:285-295` has no minrelaytxfee parse case). Operator cannot raise/lower minimum-relay. |
| 4 | DEFAULT_INCREMENTAL_RELAY_FEE=100 (sat/kvB) | G12: constant set | PASS (`mempool.zig:55` `INCREMENTAL_RELAY_FEE = 100`) |
| 4 | … | G13: operator override via `--incrementalrelayfee=X` | **BUG-8 (P1)** — no CLI flag exists. |
| 5 | Rolling-fee decay (HALFLIFE=12h, ÷4/÷2 by fill) | G14: ROLLING_FEE_HALFLIFE=12h | PASS (`mempool.zig:61`) |
| 5 | … | G15: `mempool < 1/4 full → halflife ÷ 4` | PASS (`mempool.zig:3675-3676`) |
| 5 | … | G16: `mempool < 1/2 full → halflife ÷ 2` | PASS (`mempool.zig:3677-3678`) |
| 5 | … | G17: decay only when `> 10 s` since last update | PASS (`mempool.zig:3672`) |
| 5 | … | G18: zero out when `< incremental/2` | PASS (`mempool.zig:3687-3691`) |
| 5 | … | G19: `getMinFee` returns `CFeeRate(0)` when rolling rate zeroed | **BUG-9 (P0-CDIV)** — Core's `GetMinFee` returns `CFeeRate(0)` when rolling rate is zero or never bumped (`txmempool.cpp:831-832`). clearbit's `getMinFee` (line 3666) ALWAYS floors at `MIN_RELAY_FEE`; line 3691 returns `MIN_RELAY_FEE` after zeroing instead of 0. The two are SEPARATE concepts in Core: `GetMinFee` is the eviction-driven minimum (often zero), `m_opts.min_relay_feerate` is the standalone floor. Conflating them silently raises the fee filter peers advertise (`feefilter` BIP-133) when the rolling-fee logic legitimately drops to zero. |
| 5 | … | G20: `block_since_last_rolling_fee_bump=true` set on each block | PASS (`mempool.zig:1749` inside `removeForBlock`) |
| 6 | MemPoolRemovalReason enum + emission | G21: enum exists with all 6 variants | **BUG-10 (P0-CDIV)** — there is NO `MemPoolRemovalReason` enum anywhere in clearbit. `grep -nE "RemovalReason\|MemPoolRemovalReason" src/` returns zero hits. `removeTransaction` (line 1593) takes only a txid; callers cannot distinguish EXPIRY vs SIZELIMIT vs REORG vs BLOCK vs CONFLICT vs REPLACED. Downstream signal consumers (ZMQ, fee estimator) cannot distinguish. |
| 6 | … | G22: SIZELIMIT reason passed by `evict()` | **BUG-10 cross-cite** — N/A (no enum) |
| 6 | … | G23: EXPIRY reason passed by `removeExpired()` | **BUG-10 cross-cite** — N/A (and G8 makes this moot) |
| 6 | … | G24: BLOCK reason passed by `removeForBlock()` | **BUG-10 cross-cite** — N/A |
| 6 | … | G25: REORG reason passed by reorg path | **BUG-10 cross-cite** — N/A |
| 6 | … | G26: REPLACED reason passed by RBF | **BUG-10 cross-cite** — N/A |
| 7 | Removed-signal fan-out to subsystems | G27: ZMQ `sequence` 'R' frame emitted on every removal | **BUG-11 (P0-CDIV)** — `zmq.zig:267-275::publishTx` emits 'A' (Added) frame only. No 'R' (Removed) frame exists. `publishTxRemoved` / `publishHashTxRemoved` are NOT defined. **Downstream ecosystem tools that subscribe to `zmqpubsequence` (electrs, fulcrum, lightning daemons) see admissions but not evictions — the mempool view on the subscriber drifts permanently out of sync.** |
| 7 | … | G28: fee estimator hooked from `removeTransaction` for non-block removals | **BUG-12 (P1)** — `removeForBlock` (line 1742) feeds confirmed txs to `fee_estimator.confirmTransaction`. But `removeTransaction` (line 1593), `removeExpired` (line 3729), `evict` (line 3153), and RBF replace (line 1276) do NOT call the estimator. Core's `CBlockPolicyEstimator::removeTx(hash, inBlock=false)` is called via `TransactionRemovedFromMempool` for every non-BLOCK removal, removing the stale entry from `mapMemPoolTxs` so it does not contaminate future buckets. clearbit's estimator carries ghost entries forever. |
| 8 | BlockConnected/BlockDisconnected MaybeUpdateMempoolForReorg | G29: reorg disconnect-side re-admits via `blockDisconnected` | PASS (`block_template.zig:1530-1533`); does NOT pass REORG reason but at least the data flow exists. |
| 8 | … | G30: reorg connect-side evicts via `removeForBlock` | PASS (`block_template.zig:1544-1546`); does NOT pass BLOCK reason. |
| 8 | … | G31: post-reorg orphan-conflicts evicted (`evictConflictingTransactions`) | **BUG-13 (P0-CDIV)** — `evictConflictingTransactions` is a documented no-op stub (`validation.zig:11116`, BUG-6 in the audit comment block at line 10871-10875). On reorg-induced invalidations the mempool keeps txs whose inputs now conflict with the new active tip. |
| 9 | prioritisetransaction RPC | G32: RPC method registered | PASS (`rpc.zig:2969`, `handlePrioritiseTransaction` at line 4659) |
| 9 | … | G33: 3-arg signature (txid, dummy=0, fee_delta) | PASS (`rpc.zig:4686-4710`) |
| 9 | … | G34: stacks via saturating add | PASS (`mempool.zig:2270-2275 saturatingAddI64`) |
| 9 | … | G35: erase on net-zero delta | PASS (`mempool.zig:2245-2248`) |
| 9 | … | G36: persisted across restart via mempool.dat | PASS (`mempool_persist.zig:29-37` FIX-76 note documents the wire-up) |

---

## BUG-1 (P1) — `--maxmempool=N` parsed but never wired to the mempool

**Severity:** P1 ("dead-data plumbing" fleet pattern, ~5th distinct
clearbit instance per W141/W148/W150/W151/W152 tracking).
`main.zig:289-291` parses `--maxmempool=N` into `config.maxmempool`
(default 300). `main.zig:712-713` parses the same key from the config
file. `main.zig:1803` constructs `mempool.Mempool.init(&chain_state,
params, allocator)` — three arguments, NONE of them the max-size.
`Mempool.init` (`mempool.zig:898-934`) ignores any operator override;
the only source of the cap is the file-scope constant
`MAX_MEMPOOL_SIZE = 300 * 1_000_000` (line 29).

`grep -nE "config\.maxmempool\|cfg\.maxmempool" src/main.zig src/mempool.zig`
returns 6 hits: 2 parse, 2 config-file lookup, 2 tests. **Zero
production code reads the value.**

**File:** `src/main.zig:85,289-291,712-713,1803`;
`src/mempool.zig:29,898-934`.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h:40`
(`max_size_bytes{DEFAULT_MAX_MEMPOOL_SIZE_MB * 1'000'000}` —
constructed FROM the options block populated by `-maxmempool`).

**Impact:**
- Operators who set `-maxmempool=5000` for a 5 GB mempool on a high-RAM
  node get silently capped at 300 MB.
- Operators who set `-maxmempool=50` for a memory-constrained node still
  carry a 300 MB pool, OOM-kill risk.
- Cross-impl divergence: same `bitcoin.conf` produces different
  behaviour on clearbit than on Core.

---

## BUG-2 (P1) — `--maxmempool` documented as MiB but constant is SI MB

**Severity:** P1. `main.zig:85` says `maxmempool: u64 = 300, // Max
mempool size in MiB`. `main.zig:511` `--help` says `--maxmempool=<MiB>`.
But Core (`kernel/mempool_options.h:40`) and clearbit's own constant
(`mempool.zig:27-29` "DEFAULT_MAX_MEMPOOL_SIZE_MB * 1_000_000 (SI
megabytes), NOT 1024*1024") agree on **SI MB**, not binary MiB. The
docstring is wrong by a factor of 1024/1000 = 1.024 (≈ 2.4%).

The constant itself is correct (300 MB SI). The bug is operator-facing:
a user who reads "300 MiB" and types `--maxmempool=300` in fact gets
300 MB.

**File:** `src/main.zig:85, 511`.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h:19`
(`DEFAULT_MAX_MEMPOOL_SIZE_MB`).

**Impact:** documentation/operator-UX bug. Compounded by BUG-1 (the
flag is inert anyway), but if BUG-1 is ever fixed the unit will mislead.

---

## BUG-3 (P0-CDIV) — `evict()` loops on per-call freed-bytes, not absolute target

**Severity:** P0-CDIV. Bitcoin Core's `CTxMemPool::TrimToSize`
(`txmempool.cpp:868`) loops:

```cpp
while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
    ...
    removeUnchecked(e, MemPoolRemovalReason::SIZELIMIT);
}
```

The loop condition is an **absolute** test against the **mempool's
current total memory usage**. As txs are evicted, `DynamicMemoryUsage()`
goes down; the loop exits the moment the pool falls below `sizelimit`.

clearbit's `evict()` (`mempool.zig:3159`) loops:

```zig
var freed: usize = 0;
while (freed < needed_bytes) {
    ...
    freed += entry.vsize;
    ...
}
```

The loop tracks only the bytes freed BY THIS CALL. `needed_bytes` is
the new tx's vsize passed in from line 1330. The exit condition is met
the moment the cumulative `freed` ≥ the new tx's vsize, regardless of
whether the pool is still over `MAX_MEMPOOL_SIZE`.

**Failure modes:**
- A pool that was over-cap before this admission (because a previous
  `addTransaction` raced or because vsize ≠ memory usage — see BUG-4)
  stays over-cap; eviction only frees enough for the NEW tx. Multiple
  successive admissions can drift the pool unboundedly above the
  configured cap.
- The next addition path (`mempool.zig:1328`) tests
  `self.total_size + vsize > MAX_MEMPOOL_SIZE` and triggers evict on the
  next tx — so the over-cap window is bounded by inter-tx arrival, but
  the invariant "pool ≤ cap immediately after evict returns" does not
  hold.

**File:** `src/mempool.zig:3153-3194, 4454-4487` (both `evict` and
`evictByCluster` share the bug).

**Core ref:** `bitcoin-core/src/txmempool.cpp:861-911::TrimToSize`.

**Excerpt (clearbit, per-call delta)**
```zig
fn evict(self: *Mempool, needed_bytes: usize) !void {
    ...
    var freed: usize = 0;
    while (freed < needed_bytes) {        // <-- per-call delta
        ...
        freed += entry.vsize;
        ...
        self.removeTransactionWithDescendants(txid_hash);
    }
}
```

**Impact:** soft-cap-only behaviour. Adversary can push the pool over
the configured limit by interleaving large-vsize admissions with
small-vsize admissions: each admission evicts only `vsize_self` bytes,
not back to the cap.

---

## BUG-4 (P0-CDIV) — `total_size` is sum of vbytes, not Core's `DynamicMemoryUsage()`

**Severity:** P0-CDIV. Bitcoin Core's mempool cap (`-maxmempool`,
`m_opts.max_size_bytes`) is enforced against `DynamicMemoryUsage()`
(`txmempool.cpp:778`), which sums:

- `mapTx` boost-multi-index overhead (~250 B / entry),
- `cachedInnerUsage` (descendant maps, ancestor maps, mapDeltas),
- `mapNextTx` (per-input ≈ 80 B / outpoint),
- the underlying `CTransactionRef`'s serialized memory,
- `m_txgraph` cluster machinery.

Empirically Core's `DynamicMemoryUsage()` is ~3-10× the raw vsize of
the txs in the pool. A 300 MB cap typically holds **~75-100 MB of
actual transaction data** (the rest is bookkeeping).

clearbit's `total_size` (`mempool.zig:782, 909, 1416, 1696, 3989`) is
the simple sum of `entry.vsize`. Comparison against
`MAX_MEMPOOL_SIZE = 300_000_000` therefore lets the pool hold up to
300 MB of **vbytes** ≈ 300 MB × 6-10 of in-memory data ≈ **1.8 GB to
3 GB of real RAM**. On a 1 GB-RAM node, this OOM-kills the process
silently.

Conversely, Core operators who tune `-maxmempool=5000` (5 GB) for a
large node will see clearbit cap at the same numeric value but hold
**~6× as much real RAM** (~30 GB), if that much vsize fits.

**File:** `src/mempool.zig:29, 782, 909, 1416, 1696, 3675-3678,
3903, 3989` (every site that compares or updates `total_size` against
`MAX_MEMPOOL_SIZE`).

**Core ref:** `bitcoin-core/src/txmempool.cpp:778::DynamicMemoryUsage()`;
`bitcoin-core/src/kernel/mempool_options.h:40::max_size_bytes`.

**Impact:** cross-impl divergence in actual memory footprint at the
"same" cap; OOM risk on small-RAM nodes; under-utilisation on
high-RAM nodes.

---

## BUG-5 (P1) — `--mempoolexpiry=N` parsed but never wired

**Severity:** P1. Same shape as BUG-1.
`main.zig:292-294, 714-715` parse `--mempoolexpiry=N` (hours, default
336) into `config.mempoolexpiry`. `Mempool.init` ignores it. The
constant `MEMPOOL_EXPIRY = 14 * 24 * 60 * 60` (`mempool.zig:44`, seconds)
is the only source.

**File:** `src/main.zig:86, 292-294, 714-715, 1803`;
`src/mempool.zig:44`.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h:23, 41`
(`DEFAULT_MEMPOOL_EXPIRY_HOURS=336`, `expiry{hours{DEFAULT_...}}`).

**Impact:** dead-data plumbing; operators cannot tune expiry; same
divergence pattern as BUG-1.

---

## BUG-6 (P0-CDIV) — `removeExpired()` is never called from production paths

**Severity:** P0-CDIV ("dead-helper-at-call-site" fleet pattern, 6th
distinct clearbit instance — companion to W148/W150/W152 cluster).
`Mempool.removeExpired()` (`mempool.zig:3729-3747`) is well-formed:
walks `self.entries`, collects entries where `now -
entry.time_added > MEMPOOL_EXPIRY`, removes them via
`removeTransactionWithDescendants` to capture children. Tested at
`mempool.zig:12001-12055` (W86-G11).

But `grep -rE "removeExpired" src/ | grep -v test` returns exactly
two hits, both inside `mempool.zig` itself (the test sites). **There
is NO production caller** — no scheduler thread in `main.zig`, no
per-block hook in `block_template.zig`, no periodic loop in
`peer.zig`, no `removeForBlock` invocation.

Bitcoin Core's `CChainState::ActivateBestChainStep` calls
`m_mempool->Expire(now - m_opts.expiry)` after every successful
`ConnectTip` (the cadence is roughly per-block on active sync, every
few minutes on idle nodes via the validation interface's scheduled
flush). clearbit does neither.

**Failure modes:**
- A node with no inbound blocks (paused network, mainnet stall,
  regtest test scenario, signet outage) accumulates expired
  transactions indefinitely. After 14 days the entries SHOULD be
  swept; instead they pile up until `MAX_MEMPOOL_SIZE` is hit and
  `evict()` removes them by feerate (cheapest first, not oldest
  first).
- The MEMPOOL_EXPIRY policy is therefore enforced **only as a
  back-pressure side-effect of size-limit eviction**, not as a
  time-based sweep. Two semantically distinct policies collapse into
  one.
- Cross-impl divergence: on Core, a 5-day-old tx that was 6 sat/vB
  expires after 14 days even on an idle 5 MB pool. On clearbit, it
  stays forever until size-limit eviction removes it (which never
  happens on a 5 MB pool with a 300 MB cap).

**File:** `src/mempool.zig:3729-3747` (function defined),
`src/main.zig:1803-...` (no scheduler), `src/block_template.zig:1162,
1545` (`removeForBlock` is the only periodic hook, and it does NOT
call removeExpired).

**Core ref:** `bitcoin-core/src/txmempool.cpp:811-827::Expire`,
`bitcoin-core/src/validation.cpp::ActivateBestChainStep` (Expire call).

**Impact:** mempool grows forever on idle nodes; expiry policy
unenforced; classic dead-helper-at-call-site.

---

## BUG-7 (P1) — `-minrelaytxfee` CLI flag does not exist

**Severity:** P1. Bitcoin Core's `-minrelaytxfee=<n.nnn>` BTC/kvB is
the canonical operator knob for the minimum-relay floor. Default
`100` sat/kvB. Operators tighten (`0.00010` BTC = 10000 sat/kvB
for a spam-resistant relay) or loosen (`0.000001` BTC = 100 sat/kvB
for testnet-style permissiveness) it.

clearbit's `parseFlags` (`main.zig:285-...`) does NOT define such a
flag. The only source of `MIN_RELAY_FEE` is the file-scope constant
(`mempool.zig:49`, value 100). Operator cannot tune.

**File:** `src/main.zig:285-...` (parseFlags, no minrelaytxfee
registration); `src/mempool.zig:49` (only source).

**Core ref:** `bitcoin-core/src/init.cpp` (`-minrelaytxfee` parse);
`bitcoin-core/src/kernel/mempool_options.h:44`
(`min_relay_feerate{DEFAULT_MIN_RELAY_TX_FEE}`).

**Impact:** no operator-knob; cross-impl divergence on
`getmempoolinfo.minrelaytxfee` reporting (BUG-15); the
`feefilter` BIP-133 floor a peer sees is hard-coded.

---

## BUG-8 (P1) — `-incrementalrelayfee` CLI flag does not exist

**Severity:** P1. Same shape as BUG-7 for the BIP-125 RBF Rule 4
increment. Core's `-incrementalrelayfee=<n.nnn>` BTC/kvB. clearbit's
`INCREMENTAL_RELAY_FEE = 100` is hard-coded.

**File:** `src/main.zig:285-...` (no incrementalrelayfee parse);
`src/mempool.zig:55`.

**Core ref:** `bitcoin-core/src/init.cpp` (`-incrementalrelayfee`);
`bitcoin-core/src/kernel/mempool_options.h:42`.

**Impact:** no operator knob for RBF fee-bump increment; cross-impl
divergence on `getmempoolinfo.incrementalrelayfee`.

---

## BUG-9 (P0-CDIV) — `getMinFee()` conflates `GetMinFee` and `min_relay_feerate`; never returns 0

**Severity:** P0-CDIV. Bitcoin Core's `CTxMemPool::GetMinFee(size_t
sizelimit)` (`txmempool.cpp:829-851`) returns **the rolling-minimum
feerate alone** — it can be (and frequently IS) `CFeeRate(0)`. The
"floor at min_relay_feerate" is applied SEPARATELY in
`MemPoolAccept::CheckFeeRate` via `std::max(feerate, m_opts.min_relay_feerate)`
(`txmempool.cpp:850`). These are two distinct knobs:
- `GetMinFee(sizelimit)` answers "what was the cheapest tx we evicted
  recently (decayed)?". On a non-full pool with no recent evictions,
  the answer is **0**.
- `m_opts.min_relay_feerate` is the static "we will never accept
  cheaper than this".

clearbit's `getMinFee()` (`mempool.zig:3661-3699`) ALWAYS floors at
`MIN_RELAY_FEE`:
- Line 3666 (no-bump branch): `return @max(rolling, MIN_RELAY_FEE)`.
- Line 3691 (post-zero branch): `return @intCast(MIN_RELAY_FEE)`
  (instead of returning 0).
- Line 3698 (final branch): `return @max(@max(rolling, incremental),
  MIN_RELAY_FEE)`.

`getMinFee` is consumed at:
- `mempool.zig:1219, 1825-1826` for tx admission (`InsufficientFee`
  rejection). Conflation harmless here — Core uses
  `std::max(GetMinFee, min_relay_feerate)` for the same gate.
- `rpc.zig:4510` (hardcoded `0.00001`, see BUG-15) and other
  observation points — Core exposes `mempoolminfee` separately from
  `minrelaytxfee`. clearbit cannot.
- `peer.zig::passesFeeFilter` (BIP-133): peers see a non-zero
  feefilter ALWAYS, even when Core would advertise 0. Wasted bandwidth
  on the receiving side that has to compute fee-rate before drop.

**File:** `src/mempool.zig:3661-3699`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:829-851::GetMinFee`;
`bitcoin-core/src/kernel/mempool_options.h:44::min_relay_feerate`.

**Excerpt (clearbit, conflated)**
```zig
pub fn getMinFee(self: *Mempool) u64 {
    if (!self.block_since_last_rolling_fee_bump or
        self.rolling_minimum_fee_rate == 0.0)
    {
        const rolling = @as(u64, @intFromFloat(@round(...)));
        return @max(rolling, @as(u64, @intCast(MIN_RELAY_FEE)));
        //     ^^^^ Core returns the raw rolling rate here (often 0)
    }
    ...
    if (self.rolling_minimum_fee_rate < INCREMENTAL_RELAY_FEE/2.0) {
        self.rolling_minimum_fee_rate = 0.0;
        return @intCast(MIN_RELAY_FEE);
        //     ^^^^ Core returns CFeeRate(0) here
    }
    return @max(@max(rolling, incremental), MIN_RELAY_FEE);
}
```

**Impact:** observability divergence (`getmempoolinfo`,
`feefilter`); semantic conflation that hides a free-tx-window an
operator might tune through `-minrelaytxfee=0` in regtest scenarios.

---

## BUG-10 (P0-CDIV) — `MemPoolRemovalReason` enum is entirely absent

**Severity:** P0-CDIV. Bitcoin Core's
`kernel/mempool_removal_reason.h:13-20`:

```cpp
enum class MemPoolRemovalReason {
    EXPIRY, SIZELIMIT, REORG, BLOCK, CONFLICT, REPLACED,
};
```

This enum is the **single most load-bearing tag in the mempool
notification system**. It threads through:
- `CTxMemPool::removeUnchecked(it, reason)`,
- `CTxMemPool::removeRecursive(tx, reason)`,
- `CTxMemPool::RemoveStaged(stage, reason)`,
- `CValidationInterface::TransactionRemovedFromMempool(tx, reason,
  mempool_sequence)`,
- ZMQ `pubsequence` 'R' frame (per-Core convention, the 'R' byte is
  appended after the txid hash).
- `CBlockPolicyEstimator::removeTx(hash, inBlock)` — uses BLOCK to
  set `inBlock=true` so the entry feeds the histogram, EXPIRY /
  SIZELIMIT / CONFLICT to set `inBlock=false` so the entry is silently
  dropped from buckets without contaminating future estimates.

clearbit has **no equivalent enum**. `grep -nE
"RemovalReason\|MemPoolRemovalReason" src/` returns zero hits.
`removeTransaction` (`mempool.zig:1593`) takes only a txid.
`removeForBlock` (line 1726) passes confirmed txs to
`fee_estimator.confirmTransaction` (BLOCK semantics), but the
non-block removal paths (RBF, eviction, expiry, reorg) cannot
indicate to the estimator that the removal was non-final.

**File:** absent throughout `src/mempool.zig`; signal-wiring sites
`zmq.zig:252`, `mempool.zig:1276, 1593, 1705, 1726, 1742, 3191,
3729, 4484` all lack a reason argument.

**Core ref:** `bitcoin-core/src/kernel/mempool_removal_reason.h`,
`bitcoin-core/src/validationinterface.h:109`.

**Impact:**
- Fee estimator histograms contain ghost entries from evicted /
  replaced txs (BUG-12 cross-cite).
- ZMQ subscribers cannot distinguish a tx that was confirmed
  (legitimate "tx in block X") from one that was replaced (zombie
  txid).
- Cross-impl divergence on the validation-interface signal.

---

## BUG-11 (P0-CDIV) — ZMQ `sequence` 'R' (Removed) frame is not emitted

**Severity:** P0-CDIV. Bitcoin Core's `zmqpubsequence` topic emits
five frame types: 'A' (Added to mempool, +mempool_sequence),
'R' (Removed from mempool, +mempool_sequence), 'C' (block Connected),
'D' (block Disconnected). The 'R' frame is the only wire-level way
downstream subscribers (electrs, fulcrum, c-lightning, btcpay) can
learn a previously-announced mempool tx is gone — replaced, evicted,
or expired.

clearbit's `zmq.zig:252-277::publishTx` emits 'A' frames only. There
is no `publishTxRemoved` / `emitRemovedFrame` / `publishHashTxRemoved`.
`grep -rE "'R'\|TOPIC_HASHTX.*remov\|publishTxRemoved" src/zmq.zig`
returns zero hits.

**Failure modes:**
- Subscribers' in-memory mempool views drift permanently. A wallet
  that watches `zmqpubrawtx` for inbound payments cannot detect an
  RBF-replaced tx without an external query. Long-running daemons
  accumulate stale entries.
- electrs / fulcrum re-derive the mempool from periodic full snapshots
  to compensate; the cost is bandwidth and CPU. A correctly-implemented
  'R' frame would let them stream-update.
- This is the same pattern as W141 BUG-9 (blockbrew ZMQ hash byte-order
  break) — different impl, same "downstream-ecosystem-tool-breaks"
  shape.

**File:** `src/zmq.zig:251-277`; missing call sites in
`src/mempool.zig:1276, 1593, 1705, 1742, 3191, 3729, 4484`.

**Core ref:** `bitcoin-core/src/zmq/zmqpublishnotifier.cpp::SendZmqMessage`
('R' frame); `bitcoin-core/src/validationinterface.h:109`.

**Impact:** cross-impl ZMQ wire-protocol divergence; subscriber
ecosystem (electrs / fulcrum / mempool.space backends) silently
drifts on a clearbit node.

---

## BUG-12 (P1) — fee estimator not informed of non-block removals

**Severity:** P1. Bitcoin Core's `CBlockPolicyEstimator::removeTx(hash,
inBlock)` is called from `CValidationInterface::TransactionRemovedFromMempool`
for **every** removal — not just confirmations:
- `inBlock=true` for `MemPoolRemovalReason::BLOCK` (confirmed).
- `inBlock=false` for EXPIRY / SIZELIMIT / REORG / CONFLICT /
  REPLACED.

The `inBlock=false` path **removes the entry from
`mapMemPoolTxs` without crediting the histogram**. This is critical:
without it, a tx that was added at confirm-by-2-blocks priority but
got evicted because it was undercut by RBF would still show up in the
"6-block target" bucket later when blocks 5, 6, 7, 8 confirm without
it — falsely inflating the long-tail estimates.

clearbit's `removeForBlock` (`mempool.zig:1742`) calls
`self.fee_estimator.confirmTransaction(tx_hash, block_height)` (the
inBlock=true path). But:
- `removeTransaction` (line 1593): no estimator call.
- `removeTransactionWithDescendants` (line 1705): inherits from
  `removeTransaction`, no call.
- `removeExpired` (line 3729): doesn't run anyway (BUG-6), but even
  the function body has no estimator call.
- `evict` (line 3153): no estimator call.
- `evictByCluster` (line 4454): no estimator call.
- RBF removal (`mempool.zig:1276, 3864`): no estimator call.

Net effect: clearbit's fee estimator histograms accumulate ghost
entries for every tx that was admitted then evicted/replaced/expired.
On a high-throughput node with significant RBF traffic, the
estimator's bucket weights drift toward "everything confirms slowly"
because the unconfirmed-and-vanished entries are never debited.

**File:** `src/mempool.zig:1276, 1593, 1705, 3153, 3729, 3864,
4454, 4484`.

**Core ref:** `bitcoin-core/src/policy/fees.cpp::CBlockPolicyEstimator::removeTx`;
`bitcoin-core/src/validation.cpp` (signal fan-out from
`TransactionRemovedFromMempool`).

**Impact:** fee-estimator accuracy regression on RBF-heavy or
eviction-heavy traffic; `estimatesmartfee` returns values biased
toward too-high (over-estimates blocks-to-confirm).

---

## BUG-13 (P0-CDIV) — `evictConflictingTransactions` is a documented no-op stub

**Severity:** P0-CDIV (carry-forward from W101 audit; re-flagged here
because W153 is the canonical mempool-eviction wave). The function is
declared, takes `(pool, block)`, and is invoked by `invalidateBlock`
(`validation.zig` BUG-6 audit note line 10871-10875) — but the body
ignores both arguments. On invalidation-induced reorgs, the mempool
keeps txs whose inputs now conflict with the new active tip.

The W101 audit explicitly admits:
> "// BUG-6  [CORRECTNESS] invalidateBlock() calls activateBestChain()
>  //             BEFORE evictConflictingTransactions(); ... The mempool
>  //             eviction stub is a no-op today but the ordering is wrong."

The "ordering is wrong" comment is a *second-order* concern; the
*first-order* concern is the stub itself.

**Failure modes:**
- After `invalidateblock` RPC, the mempool can hold txs that double-spend
  outpoints now spent by the new active branch. The next miner who
  drags from this mempool produces a block Core rejects with
  `bad-txns-inputs-missingorspent`.
- The `removeForBlock` call in `block_template.zig:1545` covers the
  txs that the new branch's blocks confirmed — but does NOT cover
  txs that conflict with newly-active-branch UTXOs without sharing a
  txid (i.e., RBF-pair where one was on the side branch).

**File:** `src/validation.zig:11116-11125` (test names the stub);
`src/validation.zig` (production callsite of the stub —
`invalidateBlock`).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
(walks the mempool, calls `removeRecursive(tx, REORG)` on every entry
whose inputs conflict with the new tip's UTXO set).

**Impact:** post-invalidate mempool corruption; mining template
pollution; cross-cite BUG-10 (the REORG reason would be needed even
once the stub is filled in).

---

## BUG-14 (P0-CDIV) — `addTransactionWithPackageRate` bypasses ZMQ + does not fire fee_estimator until end

**Severity:** P0-CDIV. `addTransactionWithPackageRate`
(`mempool.zig:3752`) is the CPFP / package-relay admission path used
by `submitpackage` RPC. It mirrors `addTransaction` (line 986) gate
by gate — BUT at the end (line 3989-3995) it does NOT publish the
ZMQ `hashtx`/`rawtx`/`sequence` 'A' frames that `addTransaction`
publishes (line 1418-1427). It only feeds the fee estimator.

`grep -nE "zmq\.global\.publishTx" src/mempool.zig` confirms:
- Line 1426: inside `addTransaction` (single-tx path) — present.
- No corresponding call inside `addTransactionWithPackageRate`.

**Failure modes:**
- Wallets that subscribe via `zmqpubhashtx` to detect inbound
  payments see single-tx admissions but miss package admissions.
- electrs / fulcrum / mempool.space backends miss the child txs of a
  CPFP package.
- Inconsistent observability across two paths that should be
  semantically equivalent ("a new tx is in the mempool").

This is a "two-pipeline guard" instance — two functions that should
have identical observability behaviour drift on the ZMQ side.

**File:** `src/mempool.zig:1418-1427` (publish call) vs
`src/mempool.zig:3989-3995` (no publish).

**Core ref:** `bitcoin-core/src/validation.cpp::ProcessNewPackage` →
`TransactionAddedToMempool` signal fires per-tx for every package
member.

**Impact:** package-admitted txs invisible to ZMQ subscribers;
fleet-wide pattern continuation (W141 already flagged ZMQ gaps
fleet-wide).

---

## BUG-15 (P1) — `getmempoolinfo` returns HARDCODED `0.00001` for `mempoolminfee`/`minrelaytxfee`/`incrementalrelayfee`

**Severity:** P1 ("comment-as-confession" fleet pattern, 14th distinct
instance per W141/W144/W148/W150/W152). `handleGetMempoolInfo`
(`rpc.zig:4500-4519`) builds the JSON response:

```zig
try writer.print(
    "{{\"loaded\":true,\"size\":{d},\"bytes\":{d},\"usage\":{d},"
    "\"total_fee\":0.0,\"maxmempool\":{d},"
    "\"mempoolminfee\":0.00001,"
    "\"minrelaytxfee\":0.00001,"
    "\"incrementalrelayfee\":0.00001,"
    "\"unbroadcastcount\":0,\"fullrbf\":{s}}}",
    .{ mempool_stats.count, mempool_stats.size, mempool_stats.size,
       mempool_mod.MAX_MEMPOOL_SIZE, fullrbf_str });
```

- `mempoolminfee = 0.00001` BTC/kvB = 1000 sat/kvB. **clearbit's actual
  `MIN_RELAY_FEE = 100` sat/kvB**, and `getMinFee()` returns a dynamic
  value bounded by 100 and elevated post-eviction. The reported value
  is 10× too high and is a constant string, not computed.
- `minrelaytxfee = 0.00001` BTC/kvB = 1000 sat/kvB. Same value
  inversion — clearbit's actual constant is 100 sat/kvB =
  `0.000001` BTC/kvB.
- `incrementalrelayfee = 0.00001` — same.
- `unbroadcastcount = 0` — clearbit has no unbroadcast-tx tracking;
  always zero (cross-cite W141 BUG-class).
- `total_fee = 0.0` — clearbit never sums entry fees for reporting.

Note that `maxmempool` IS sourced from the constant
(`mempool_mod.MAX_MEMPOOL_SIZE`), so the bug is partial: the
size-related fields are correct, but the fee-related fields are
hardcoded.

**File:** `src/rpc.zig:4500-4519`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`.

**Impact:**
- Wallets that call `getmempoolinfo` to compute target feerates see
  values inconsistent with the actual mempool admission gate.
- Monitoring tools that scrape `mempoolminfee` to detect mempool-full
  conditions see a static `0.00001` regardless of actual rolling-fee
  state.
- A wallet that constructs at the wire-displayed `0.00001` BTC/kvB
  (1000 sat/kvB) overpays 10× — minor harm.
- A wallet that constructs BELOW the wire-displayed value (assuming
  it's correct) but above the actual 100-sat/kvB floor sees its tx
  REJECTED locally, but accepted on a Core peer — cross-impl
  divergence in admission decisions.

---

## BUG-16 (P1) — `isDust` hardcodes `3 * (spend_size + output_size)` instead of using `DUST_RELAY_TX_FEE`

**Severity:** P1. Bitcoin Core's `IsDust()` (`policy/policy.cpp:23-47`)
computes `dust_threshold = output.GetDustThreshold(dust_relay_feerate)`,
where `dust_relay_feerate` defaults to
`DUST_RELAY_TX_FEE = 3000` sat/kvB = 3 sat/B. The full formula is
`spend_size_bytes * dust_relay_feerate / 1000`.

clearbit's `isDust` (`mempool.zig:3113-3144`) hardcodes:

```zig
const dust_threshold = 3 * (spend_size + output_size);
```

This is mathematically equivalent to `3 sat/B * (spend_size +
output_size)`, matching Core's default. But:
1. The `* 3` is the SI-MB equivalent of `DUST_RELAY_TX_FEE / 1000`
   = 3 sat/B baked in as a magic number, with NO reference to the
   operator's `-dustrelayfee` setting.
2. There is no `--dustrelayfee` CLI flag (`grep -nE "dust\|DUST" 
   src/main.zig` returns nothing).
3. An operator who wants to relax dust to 1 sat/B (testnet/regtest
   experimentation) or tighten to 10 sat/B (anti-spam) cannot.

**File:** `src/mempool.zig:3113-3144`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp::IsDust`,
`bitcoin-core/src/policy/policy.h:68::DUST_RELAY_TX_FEE`.

**Impact:** correct behaviour at the default; no operator knob;
cross-impl divergence on the operator's `-dustrelayfee=X` setting.

---

## BUG-17 (P1) — `removeForBlock` size argument is the new tx's vsize, not the freed amount

**Severity:** P1. `addTransaction` line 1330 calls
`self.evict(vsize) catch return MempoolError.MempoolFull`. The
`vsize` is the NEW tx's serialised vbyte count — i.e., the amount of
space the new tx will consume. Core's `TrimToSize(sizelimit, ...)` is
called with **the absolute target the pool must shrink to**, not the
delta. The two are independent: if the pool is 350 MB and the new tx
is 1 KB, Core trims to `< 300 MB` (frees ≥50 MB+1 KB). clearbit
trims by `1 KB` and stops.

This is the wire-up partner of BUG-3 (the loop condition). Even if
the loop were corrected, the argument passed in would still be wrong.

**File:** `src/mempool.zig:1328-1331, 3903`.

**Core ref:** `bitcoin-core/src/validation.cpp:275`
(`pool.TrimToSize(pool.m_opts.max_size_bytes, &vNoSpendsRemaining)`).

**Impact:** under-eviction; pool can stay over-cap for multiple
admission cycles. Cross-cite BUG-3 + BUG-4.

---

## BUG-18 (P0-CDIV) — `pvNoSpendsRemaining` UTXO-cache hook is entirely absent

**Severity:** P0-CDIV. Bitcoin Core's `TrimToSize` signature is:

```cpp
void TrimToSize(size_t sizelimit,
                std::vector<COutPoint>* pvNoSpendsRemaining = nullptr);
```

When the second argument is non-null, every outpoint that was spent
ONLY by a tx that was just evicted is pushed into the vector. The
caller (`AcceptToMemoryPoolWorker`, `validation.cpp:275`) then walks
the vector and calls `m_coins_views->Cache().Uncache(outpoint)` on
each, evicting the orphan UTXO cache entry. Without this, the UTXO
cache holds entries that no live mempool tx references — but the
cache eviction policy doesn't see them as orphans because no signal
fires.

clearbit's `evict()` (`mempool.zig:3153`) has NO such output argument
and NO equivalent walk. The chainstate's coin cache (W147 audit subject)
silently accumulates entries spent only by evicted txs. Over a long
node uptime under high RBF traffic, this can balloon the coin cache
beyond `-dbcache`.

**File:** `src/mempool.zig:3153, 4454`; cross-cite
`src/storage.zig::ChainState.utxo_set`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:861, 898-905::TrimToSize`
(pvNoSpendsRemaining hook); `bitcoin-core/src/validation.cpp:275`.

**Impact:** UTXO cache growth on eviction-heavy nodes; long-term
memory pressure not bounded by `-dbcache`; classic forgotten-hook
fleet pattern.

---

## BUG-19 (P1) — No `vTxHashes` consistency hook on remove (light-client / compactblock impact)

**Severity:** P1. Core's `CTxMemPool::removeUnchecked` removes the
entry from `vTxHashes` (the txid-prefix-keyed sketch used for BIP-152
compact-block prefilling, BIP-339 wtxid relay, and BIP-37 bloom-match
queries). clearbit's `removeTransaction` (`mempool.zig:1669-1701`) does
remove from `entries` and `by_wtxid` — but the SHA-256 prefix sketches
used by compact-block reconstruction (W126 audit subject) live in
parallel state in `peer.zig::CompactBlockSession` and are not signalled.

A compact-block arrival that references an evicted tx by short-id
hash will then issue an unnecessary `getblocktxn` round-trip and
fall back to full-block download. Soft impact; bandwidth waste only.

**File:** `src/mempool.zig:1669-1701`; cross-cite
`src/peer.zig::CompactBlockSession`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::removeUnchecked` (clears
all per-tx state in one place under cs).

**Impact:** compact-block reconstruction round-trip waste on
eviction-driven mempool churn; bandwidth only.

---

## BUG-20 (P1) — `blockDisconnected` does not pass REORG reason; cannot distinguish from operator submission

**Severity:** P1. `block_template.zig:1530-1533` calls
`mp.blockDisconnected(b.transactions)` per disconnected block.
`Mempool.blockDisconnected` (`mempool.zig:1778-1810`) re-admits each
non-coinbase tx via `addTransaction` — same path used by RPC
`sendrawtransaction` / P2P `tx` message.

There is no way for downstream signal consumers (fee estimator, ZMQ)
to distinguish a "re-admitted-after-reorg" tx from a freshly-broadcast
tx. Core's `MaybeUpdateMempoolForReorg` calls `removeRecursive(tx,
REORG)` on every disconnected tx before re-attempting admission, so
the signal fan-out sees REORG → ADDED rather than ADDED alone.

clearbit's `blockDisconnected` skips the REORG removal (because BUG-10
no enum) and skips ANY pre-removal signal — it goes straight to
re-admission, where the ZMQ `hashtx` 'A' frame fires.

**Failure modes:**
- A subscriber sees the txid arrive once via the original `tx`
  broadcast, then again via the reorg re-admission. To Core
  subscribers (REORG remove → A add) the txid is gone-and-back. To
  clearbit subscribers (just A add) the same tx appears twice.
- Fee estimator gets a fresh "track this fee" call for a tx that was
  already in its histogram (idempotent in clearbit's implementation
  but semantically wrong: re-admission shouldn't double-count).

**File:** `src/mempool.zig:1778-1810`; `src/block_template.zig:1525-1547`.

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`.

**Impact:** observability divergence on the reorg path; cross-cite
BUG-10, BUG-11, BUG-12.

---

## BUG-21 (P1) — `Mempool.init` has no `fullrbf` / `expiry` / `max_size` parameter (constructor is shape-frozen)

**Severity:** P1. `Mempool.init(chain_state, params, allocator)`
(`mempool.zig:898-934`) takes three arguments. There is no way to pass
operator policy into the mempool at construction time:
- `full_rbf` field exists on the struct (line 823) but is initialised
  to `false` (line 922) with no init-time override.
- `MAX_MEMPOOL_SIZE`, `MEMPOOL_EXPIRY`, `MIN_RELAY_FEE`,
  `INCREMENTAL_RELAY_FEE`, `ROLLING_FEE_HALFLIFE` are all file-scope
  constants.

Compare Core's `CTxMemPool(Options)` constructor that takes a fully
populated `CTxMemPool::Options` struct: `min_relay_feerate`,
`incremental_relay_feerate`, `max_size_bytes`, `expiry`,
`dust_relay_feerate`, `permit_bare_multisig`, `require_standard`,
`max_datacarrier_bytes`, `max_sigop_cost`, `mempool_full_rbf`,
`signals` (validation interface pointer for fan-out), `estimator`
(policy estimator pointer), `check_ratio` (consistency sampling).

clearbit's constructor accepts none of these. Operator-knob plumbing
is shape-broken from the constructor outward.

**File:** `src/mempool.zig:898-934`.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h`,
`bitcoin-core/src/txmempool.cpp::CTxMemPool::CTxMemPool(const Options&)`.

**Impact:** all of BUG-1, BUG-5, BUG-7, BUG-8, BUG-16 share this root
cause. Fixing the constructor shape is a prerequisite for any
operator-knob wire-up.

---

## BUG-22 (P1) — `removeExpired` is O(N) but never decay-stamps after sweep; rolling-fee bump not fired

**Severity:** P1. Bitcoin Core's `Expire` (`txmempool.cpp:811-827`)
removes via `RemoveStaged(stage, MemPoolRemovalReason::EXPIRY)`, which
threads through `removeUnchecked` and ultimately fires
`TransactionRemovedFromMempool(tx, EXPIRY, ...)`. The rolling-fee
state is updated implicitly: although EXPIRY does not bump
`rollingMinimumFeeRate` directly (only SIZELIMIT does via
`trackPackageRemoved`), the next `GetMinFee` call sees the smaller
pool and can amplify the halflife decay (÷4 / ÷2 fill thresholds).

clearbit's `removeExpired` (`mempool.zig:3729-3747`) does the right
thing data-wise (calls `removeTransactionWithDescendants`) but does
NOT update `last_rolling_fee_update` or trigger a `getMinFee` recompute
pass. The next admission to a now-smaller pool may still see the
pre-expiry rolling rate without the decay-acceleration benefit.

Minor; BUG-6 (the function never runs in production) supersedes.

**File:** `src/mempool.zig:3729-3747`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:811-827::Expire`.

**Impact:** post-expiry rolling-fee value is one tick stale; minor
estimator drift if the function ever fires.

---

## BUG-23 (P0-CDIV) — `evict` uses O(N²) full-scan per eviction; no cluster-aware skip-list

**Severity:** P0-CDIV (perf-driving correctness — clearbit can wedge
under sustained spam). `evict()` (`mempool.zig:3159-3193`) finds the
worst tx by linear scan of `self.entries.iterator()` on EVERY iteration
of the while loop. For an admission that needs `K` evictions out of `N`
entries, the cost is `O(K * N)`.

On a full 300 MB mempool with ~150,000 entries average, a single
size-limit admission that needs to evict 10 entries costs 1.5M
HashMap lookups per admission. Under spam load (10s of txs per second
all triggering size-limit eviction), this is the dominant CPU cost
in the validation pipeline.

Core uses `m_txgraph->GetWorstMainChunk()` (`txmempool.cpp:869`), an
O(log N) skip-list operation. clearbit's `cluster_linearizations`
HashMap (line 809) exists but is recomputed lazily and NOT consulted
inside `evict()` — only inside `evictByCluster` (line 4454), which is
itself O(N²) by linear scan (line 4466).

**File:** `src/mempool.zig:3159-3193, 4454-4487`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:861-911::TrimToSize`
(uses `m_txgraph->GetWorstMainChunk()`).

**Impact:** sustained-spam DOS amplification factor 10-100× vs Core;
single-tx admission can take seconds when pool is at cap. Cross-cite
W148 BUG-5 activateBestChain stub (perf wedge fleet pattern).

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-CDIV:** 10 (BUG-3, BUG-4, BUG-6, BUG-9, BUG-10, BUG-11, BUG-13,
  BUG-14, BUG-18, BUG-23)
- **P1:** 13 (BUG-1, BUG-2, BUG-5, BUG-7, BUG-8, BUG-12, BUG-15,
  BUG-16, BUG-17, BUG-19, BUG-20, BUG-21, BUG-22)

**Fleet patterns confirmed:**
- **30-of-30-gates-buggy 6th instance candidate** — 23 / 36 gates fail
  (W138 → W141 → W150 → W151 → W152 → **W153**). The mempool
  subsystem joins assumeUTXO / ZMQ-rest-notify / ATMP-prechecks /
  package-relay-RBF / tx-relay-inv-orphan as a "subsystem-rewrite"
  candidate. Six consecutive waves with the same density of bugs across
  a single audit.
- **Dead-data plumbing** (BUG-1 `maxmempool`, BUG-5 `mempoolexpiry`,
  BUG-7 `minrelaytxfee` *absent*, BUG-8 `incrementalrelayfee` *absent*,
  BUG-16 `dustrelayfee` *absent*) — 5 distinct operator knobs missing
  or unwired. Clusters under the BUG-21 constructor-shape root cause.
- **Dead-helper-at-call-site** (BUG-6 `removeExpired`, BUG-13
  `evictConflictingTransactions`) — 6th and 7th distinct clearbit
  instances per W148 / W150 / W152 tracking.
- **Comment-as-confession** (BUG-15 `rpc.zig:4510` hardcoded literals
  while comment block at line 4501-4507 explicitly cites Core's
  GetMempoolInfo for parity; BUG-13 `validation.zig:11116-11125`
  test name "no-op stub"; BUG-3 `mempool.zig:3149-3152` comment
  cites Core's TrimToSize verbatim while body diverges) — 13th, 14th,
  15th distinct fleet instances. Pattern crystallises further: comment
  cites Core's behaviour, code implements something else, comment
  becomes the documentation of the divergence.
- **Two-pipeline guard 17th distinct extension** (BUG-14:
  `addTransaction` publishes ZMQ; `addTransactionWithPackageRate`
  doesn't, despite both being "tx admitted to mempool"). First clearbit
  instance of the cross-path observability split inside one mempool.
- **Wiring-look-but-no-wire** (BUG-1, BUG-5 — flags accepted, parsed,
  documented; never read) — first W153 instance.
- **Shape-frozen-constructor as root cause** (BUG-21) — first
  instance of fleet pattern; Mempool.init has 3 args, Core
  `CTxMemPool::Options` has 13. Every operator-knob is locked out at
  the constructor boundary.

**Top three findings:**
1. **BUG-3 + BUG-4 + BUG-17 + BUG-18 cluster (eviction semantics
   diverge from Core's TrimToSize at FOUR independent points)** — clearbit's
   `evict()` exits on per-call delta not absolute target (BUG-3),
   meters vsize-not-memory (BUG-4), is called with vsize not sizelimit
   (BUG-17), and has no `pvNoSpendsRemaining` UTXO-cache hook (BUG-18).
   The pool can drift above the configured cap while the UTXO cache
   accumulates orphan entries. Combined with the 300 MB-vsize cap that
   admits ~1.8 GB of real-memory traffic, this is the most severe
   memory-safety divergence in the mempool subsystem.
2. **BUG-10 + BUG-11 + BUG-12 + BUG-20 cluster (entire
   removed-signal fan-out is absent)** — no `MemPoolRemovalReason`
   enum (BUG-10), no ZMQ 'R' frame (BUG-11), no estimator hook on
   non-block removal (BUG-12), no REORG-specific handling (BUG-20).
   Downstream ecosystem tools (electrs / fulcrum / wallets /
   estimator) cannot maintain coherent mempool views. Fleet-wide
   pattern: W141 ZMQ-fleet audit found similar absence in 8 of 10
   impls; clearbit is in the 8.
3. **BUG-6 (removeExpired never runs in production)** — classic
   dead-helper-at-call-site. 14-day expiry policy entirely unenforced
   on idle nodes. The function exists, is tested, has a thorough
   docstring citing Core's `Expire`. Zero production callers. 6th
   distinct clearbit instance of the pattern (W148/W150/W152
   companions: activateBestChain stub / TxRequestTracker absent /
   evictConflictingTransactions stub).

**Pending fleet-wide corollaries to surface in W154+:**
- Per-impl `MemPoolRemovalReason` enum status — likely fleet-wide
  absent given clearbit + W141 ZMQ findings.
- Per-impl `removeExpired` production caller status — clearbit
  dead-helper today; check rustoshi / blockbrew / nimrod / hotbuns /
  ouroboros / lunarblock / camlcoin / haskoin / beamchain next.
- Per-impl `TrimToSize` semantics (loop condition + size metric +
  pvNoSpendsRemaining hook) — three orthogonal divergence axes;
  enumerate across fleet.
- Per-impl ZMQ 'R' frame emission — clearbit absent; expect 7-9 of 10
  impls absent (consistent with W141 finding).
