# W149 — Pruning + assumevalid + minimumchainwork (clearbit)

**Wave:** W149 — `-prune` CLI + `pruneToTarget` (`FindFilesToPrune` /
`FindFilesToPruneManual` / `UnlinkPrunedFiles` analogs), `pruneblockchain`
RPC, `BLOCK_HAVE_DATA` bit semantics, `MIN_BLOCKS_TO_KEEP` (288),
`MIN_DISK_SPACE_FOR_BLOCK_FILES` (550 MiB), `PRUNE_TARGET_MANUAL` sentinel,
`m_have_pruned`, `BLOCK_ASSUMED_VALID` propagation, `fScriptChecks` skip
gate in `ConnectBlock`, `-assumevalid=<hex>` arg, `-minimumchainwork=<hex>`
arg, `defaultAssumeValid` per network, `nMinimumChainWork` per network,
`MinimumConnectedChainWork` peer-acceptance, `UpdateIBDStatus` IBD-exit
latch.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.cpp:248-300` — `FindFilesToPrune`,
  `FindFilesToPruneManual`, `UnlinkPrunedFiles`, `FlushBlockFile`,
  `PruneOneBlockFile`, `PruneAndFlush`. Deletes BOTH `blk*.dat` AND
  `rev*.dat` for every pruned file.
- `bitcoin-core/src/node/blockstorage.h:408` —
  `PRUNE_TARGET_MANUAL{std::numeric_limits<uint64_t>::max()}`.
- `bitcoin-core/src/validation.h:75-76, 87` — `MIN_BLOCKS_TO_KEEP = 288`,
  `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024`.
- `bitcoin-core/src/init.cpp:487, 512` — `-assumevalid=<hex>` and
  `-minimumchainwork=<hex>` operator-override args (both accept `0` to
  disable).
- `bitcoin-core/src/rpc/blockchain.cpp:908-965` — `pruneblockchain` RPC.
  Dual-mode: height < 1e9 → height; height ≥ 1e9 → epoch timestamp,
  resolved via `active_chain.FindEarliestAtLeast(heightParam -
  TIMESTAMP_WINDOW, 0)`.  Returns the last pruned height. Refuses when
  `chainHeight < params.PruneAfterHeight()` or when not in prune mode.
- `bitcoin-core/src/validation.cpp:2345-2383` — `fScriptChecks` skip gate
  in `ConnectBlock`. Six-condition ancestor check:
  (1) `m_chainman.AssumedValidBlock()` is set,
  (2) `m_blockman.LookupBlockIndex(...)` returns it,
  (3) it has at least `params.nMinimumChainWork` chainwork,
  (4) `pindex` is an ancestor of the assumed-valid block,
  (5) the assumed-valid block is an ancestor of `m_chain.Tip()`,
  (6) the assumed-valid block is at least `MIN_BLOCKS_TO_KEEP` (288)
  blocks past `pindex`. (Note: Core has tightened to a single
  ancestor-table lookup `it != m_assumed_valid_blocks.end()` in the
  current tree, but the semantics are equivalent.)
- `bitcoin-core/src/validation.cpp:2347` — `script_check_reason =
  "assumevalid=0 (always verify)"` for `-assumevalid=0`.
- `bitcoin-core/src/kernel/chainparams.cpp` — per-network
  `defaultAssumeValid` and `nMinimumChainWork`:
  - mainnet:   AV `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac` h=938343, MCW `0000000000000000000000000000000000000001128750f82f4c366153a3a030`
  - testnet3:  AV `000000000000000465b1a66c9f386308e8c75acef9e3ed3a9f59c534fc91d2af` (varies), MCW `0000000000000000000000000000000000000000000017dde1c649f3708d14b6`
  - testnet4:  AV `000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4` h=4842348, MCW `0000000000000000000000000000000000000000000009a0fe15d0177d086304`
  - signet:    AV `00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329` h=293175, MCW `00000000000000000000000000000000000000000000000000000b463ea0a4b8`
  - regtest:   AV `{}` (none), MCW `{}` (none).
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus` (`m_cached_is_ibd` latched
  false when tip is within `max_tip_age` (24h) AND chainwork ≥
  `MinimumChainWork`).
- `bitcoin-core/src/net_processing.cpp` — `MinimumConnectedChainWork`
  peer-acceptance gate; peer is disconnected if its best-known chain has
  less work than `m_chainman.MinimumChainWork()`.
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum.
  `BLOCK_HAVE_DATA = 8`, `BLOCK_HAVE_UNDO = 16`, `BLOCK_ASSUMED_VALID =
  256`.  Assumed-valid bit is propagated to all descendants of an
  assumed-valid block via `ConditionallyAddToBlockIndex`.

**Files audited**
- `src/main.zig:75, 127-128, 165-189, 278-290, 391-394, 437-499, 543,
  696-705, 1280-1421, 1638-1845, 2199-2225, 2453-2625` — `Config.prune`,
  `Config.noassumevalid`, `getNetworkParams`, `validatePruneTarget`,
  `parseArgs`, `importBlocks` (assumevalid simulation), pruner tick loop,
  CLI tests.
- `src/storage.zig:1665-1830` — `UndoFileManager` (rev*.dat read/write
  surface).
- `src/storage.zig:1914-3023` — `ChainState.MIN_BLOCKS_TO_KEEP`,
  `MIN_PRUNE_TARGET_MIB`, `prune_target_mib`, `prune_height`,
  `pruneToTarget`, `isHeightPruned`, `estimateBlockCfBytes`,
  `pending_block_writes` / `pending_undo_writes`.
- `src/consensus.zig:380-442, 475-802` — `NetworkParams.min_chain_work`,
  `assumed_valid_hash`, `assume_valid_height`; MAINNET, TESTNET3,
  TESTNET4, SIGNET, REGTEST blocks; `hexToHash` comptime helper.
- `src/validation.zig:670-756, 879-998, 1030-1104, 1118-1618,
  1620-1720` — `shouldSkipScripts` six-condition gate, legacy
  `connectBlock` (no assume-valid), `IBDValidationContext`,
  `validateBlockForIBD` (force_skip_scripts wiring), `acceptBlock` unified
  entry point.
- `src/peer.zig:122-255, 4519-4549, 6374-6440` — `addChainWorkBE`,
  `workFromBits`, `cmpChainWorkBE`, IBD assumevalid wiring,
  `min_pow_checked` gate in headers handler.
- `src/sync.zig:170-790, 1340-1355, 1730-1810` —
  `HeaderSyncState.min_chain_work`, PRESYNC/REDOWNLOAD anti-DoS,
  `compareWork` (little-endian!), `validateAndConnectBlock` assumevalid
  wiring (legacy BlockDownloader).
- `src/rpc.zig:1858, 2949-3370, 3530-3700, 6373-6400,
  13654-13740` — `handleGetBlockchainInfo` (hardcoded
  `pruned:false`, `size_on_disk:0`, `verificationprogress:1.0`),
  `handleGetBlock` (no `isHeightPruned` consult),
  `validateSubmitBlockOrReject` (RPC assumevalid wiring),
  `isInitialBlockDownload` latch, `compareChainWork` (big-endian).

---

## Gate matrix (32 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `-prune=N` CLI parse | G1: `prune=0` → off | PASS (`main.zig:75, 454`) |
| 1 | … | G2: `prune=1` → manual sentinel (Core: `uint64::MAX`) | **BUG-1 (P0-CDIV)** sentinel encoding diverges from Core's `PRUNE_TARGET_MANUAL` |
| 1 | … | G3: `2 ≤ prune < 550` → reject | PASS (`main.zig:456-461`) |
| 1 | … | G4: `prune ≥ 550` → target MiB | PASS (`main.zig:462`) |
| 2 | `pruneToTarget` mechanics | G5: only deletes when `best_height > MIN_BLOCKS_TO_KEEP` | PASS (`storage.zig:2969`) |
| 2 | … | G6: `prune_height ≤ best_height - 288` watermark | PASS (`storage.zig:2971`) |
| 2 | … | G7: deletes CF_BLOCKS (blk*.dat analog) | PARTIAL (no-op in production — see BUG-3) |
| 2 | … | G8: deletes CF_BLOCK_UNDO (rev*.dat analog) | **BUG-2 (P0)** `pruneToTarget` NEVER deletes CF_BLOCK_UNDO; Core's `UnlinkPrunedFiles` deletes both |
| 2 | … | G9: deletes `UndoFileManager` rev*.dat files on disk | **BUG-2 cross-cite** UndoFileManager writes rev*.dat (`storage.zig:1699-1758`) but pruner never unlinks them |
| 2 | … | G10: `m_have_pruned` analog set on first delete | **BUG-9 (P1)** no `m_have_pruned` field — restart cannot distinguish "never pruned" from "pruned but reindex needed" |
| 3 | `pruneblockchain` RPC | G11: handler exists | **BUG-3 (P0)** handler ENTIRELY ABSENT — `grep pruneblockchain src/rpc.zig` returns zero matches; only the comment at `storage.zig:2963` mentions it |
| 3 | … | G12: dual-mode height < 1e9 vs timestamp ≥ 1e9 | **BUG-3 cross-cite** dual-mode unimplementable without handler |
| 3 | … | G13: refuses when not in prune mode (Core JSON-RPC -1) | **BUG-3 cross-cite** |
| 3 | … | G14: clamps `height` to `chainHeight - MIN_BLOCKS_TO_KEEP` | **BUG-3 cross-cite** |
| 4 | `getblockchaininfo` prune fields | G15: emits `"pruned":true` when `prune_target_mib > 0` | **BUG-4 (P0-CDIV)** hardcoded `"pruned":false` regardless of `chain_state.prune_target_mib` (`rpc.zig:3363`) |
| 4 | … | G16: emits `"pruneheight"` when pruned | **BUG-4 cross-cite** never emitted |
| 4 | … | G17: emits `"automatic_pruning"`, `"prune_target_size"` | **BUG-4 cross-cite** never emitted |
| 4 | … | G18: emits real `"size_on_disk"` | **BUG-4 cross-cite** hardcoded `0` |
| 4 | … | G19: emits real `"verificationprogress"` | **BUG-10 (P1)** hardcoded `1.0` |
| 5 | `getblock` honors prune watermark | G20: returns "block not available (pruned data)" for `height ≤ prune_height` | **BUG-5 (P0)** `handleGetBlock` (`rpc.zig:3530-3618`) never consults `isHeightPruned`; "missing" pruned bytes return "Block not found" or silently proxy to Core |
| 6 | `-assumevalid=<hex>` CLI | G21: accepts hash arg to override default | **BUG-6 (P0-CDIV)** only `--noassumevalid` boolean exists (`main.zig:391-394`); Core accepts `-assumevalid=<hex>` for custom hashes and `-assumevalid=0` to disable |
| 6 | … | G22: per-network defaults from chainparams | PASS (mainnet h=938343 / testnet4 h=4842348 / signet h=293175) |
| 6 | … | G23: `getNetworkParams` returns stable pointer to params | **BUG-7 (P1)** `getNetworkParams` returns pointer to a static struct mutated on every call when `--noassumevalid` is set (`main.zig:175-188`) — comment claims "callers must not store the pointer beyond the current call frame" but PeerManager / RpcServer / SyncManager all store `*const NetworkParams` long-lived |
| 7 | `shouldSkipScripts` ancestor check | G24: skip only when block is ancestor of `assumed_valid_hash` on active chain | **BUG-8 (P0-CONS)** the THREE production callers (peer.zig:6379, sync.zig:1741, rpc.zig:6375) compute `skip_via_height = (height <= av_height)` and pass `force_skip_scripts=true` UNCONDITIONALLY — bypassing the six-condition gate (cross-cite "three-pipeline drift" pattern) |
| 7 | … | G25: skip requires chainwork ≥ `min_chain_work` (Core cond 5) | **BUG-8 cross-cite** force_skip path skips this gate entirely |
| 7 | … | G26: skip requires 2-week timestamp gap (Core cond 6) | **BUG-8 cross-cite** force_skip path skips this gate entirely |
| 7 | … | G27: skip requires `assumed_valid_hash` to be in block index | **BUG-8 cross-cite** force_skip path skips this gate entirely |
| 7 | … | G28: legacy `connectBlock` (mining + dumptxoutset rollback) consults assumevalid | **BUG-11 (P1)** `connectBlock()` (`validation.zig:879-998`) has NO `skip_scripts` parameter — always runs every script (carry-forward: comment at line 893 says "assumevalid only skips script verification" but the function never even checks) |
| 8 | `min_chain_work` / `nMinimumChainWork` | G29: per-network value matches Core | **BUG-12 (P0-CDIV)** testnet4=`0x0...0100000000` vs Core `0x0...09a0fe15d0177d086304` (~9 orders of magnitude lower); signet=`0x0...0100000000` vs Core `0x0...0b463ea0a4b8`; testnet3=`0x0...0100000000` vs Core `0x0...17dde1c649f3708d14b6`; mainnet stamped Oct 2024 (carry-forward W141 P-class) |
| 8 | … | G30: endianness consistency between `hexToHash`-derived `min_chain_work` and runtime `chain_work` | **BUG-13 (P0-CDIV)** `hexToHash` stores hashes little-endian (LSB at index 0); `workFromBits` produces big-endian chain_work (MSB at index 0); `cmpChainWorkBE` / `compareChainWork` / `shouldSkipScripts` walk index 0 upward as MSB — comparing runtime `chain_work` against `min_chain_work` is endianness-flipped |
| 8 | … | G31: `-minimumchainwork=<hex>` CLI override | **BUG-14 (P1)** no operator knob — Core supports `-minimumchainwork=<hex>` (init.cpp:512); clearbit has no analog |
| 8 | … | G32: `MinimumConnectedChainWork` per-peer disconnect gate | **BUG-15 (P1)** clearbit's `MinimumChainWork` is consulted only in PRESYNC/REDOWNLOAD anti-DoS and in IBD-exit; Core also rejects peer connections whose chain advertises < `MinimumConnectedChainWork` — clearbit has no per-peer disconnect on this criterion |

---

## BUG-1 (P0-CDIV) — `-prune=1` manual sentinel encoded as `1` literal, not Core's `PRUNE_TARGET_MANUAL = uint64::MAX`

**Severity:** P0-CDIV (semantic divergence + tooling interop).
Bitcoin Core distinguishes "auto-prune to N MiB" from "manual-prune
only" via an internal sentinel: `PRUNE_TARGET_MANUAL =
std::numeric_limits<uint64_t>::max()` (`bitcoin-core/src/node/blockstorage.h:408`).
The user-facing `-prune=1` CLI flag is translated to this sentinel
inside `AppInitParameterInteraction` (init.cpp:524).  Downstream code
checks `m_prune_target == PRUNE_TARGET_MANUAL`.

clearbit stores the literal value `1` (in MiB) as the sentinel
(`main.zig:455, 696-705`) and `pruneToTarget` checks `if
(self.prune_target_mib == 1) return 0` (`storage.zig:2967`).  The
mainnet/testnet4 datadir size on disk is several MiB even before pruning
begins — the sentinel was chosen for tests, not for byte-accurate
"manual mode" semantics.

**File:** `src/main.zig:455`, `src/storage.zig:2967`.

**Core ref:** `bitcoin-core/src/init.cpp:524`,
`bitcoin-core/src/node/blockstorage.h:408`.

**Excerpt (clearbit, sentinel = literal 1)**
```zig
if (prune_mib == 1) return 1; // manual-mode sentinel (Core init.cpp:524)
```

```zig
// In ChainState.pruneToTarget:
if (self.prune_target_mib == 1) return 0;
```

**Impact:**
- Cosmetic for the auto-prune trigger (the check fires correctly).
- BREAKS Core-compatible config-file round-tripping: an operator who
  exports clearbit's effective prune target reads `prune_target_mib=1`
  and would round-trip it to a Bitcoin Core node as a 1-MiB target
  (rejected by Core's `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB` guard).
- Inverse: importing a Core `getblockchaininfo` output where
  `prune_target_size` reports `1099511627776` (effectively MAX) would
  not map to clearbit's "manual" intent.

---

## BUG-2 (P0) — `pruneToTarget` never deletes `CF_BLOCK_UNDO` (Core deletes both blk*.dat AND rev*.dat)

**Severity:** P0. Bitcoin Core's `UnlinkPrunedFiles` (blockstorage.cpp)
unlinks BOTH the `blk*.dat` block file AND its matching `rev*.dat` undo
file for every pruned file number. Pruning only blocks leaves the undo
data on disk forever — `~120 GiB` of `rev*.dat` accumulates and the
operator's `-prune=550` target is meaningless.

clearbit's `pruneToTarget` (`storage.zig:2958-3013`) walks heights and
issues `db.delete(CF_BLOCKS, &hash)` for each. It NEVER touches
`CF_BLOCK_UNDO` (column family `5`, defined at `storage.zig:36`) or the
`UndoFileManager`'s rev*.dat files (`storage.zig:1699-1758`).

**File:** `src/storage.zig:2958-3013` (`pruneToTarget`), `2997`
(only delete site).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:248-300`
(`UnlinkPrunedFiles`, `PruneOneBlockFile`).

**Excerpt (clearbit, only deletes CF_BLOCKS)**
```zig
const hash = self.getBlockHashByHeight(h) orelse {
    self.prune_height = h;
    continue;
};
db.delete(CF_BLOCKS, &hash) catch {};   // ← undo never touched
self.prune_height = h;
```

**Impact:**
- Disk usage continues to grow despite pruning being "enabled"; the
  operator's `-prune=550 MiB` target is effectively ignored for the
  undo half of the pair (Core's blk*.dat ↔ rev*.dat are roughly
  similar in size: undo is ~half of blocks for typical mainnet
  blocks → 50% of the savings lost).
- `estimateBlockCfBytes()` (called at the size-driven stop in
  pruneToTarget line 3008) only measures CF_BLOCKS, so the size-stop
  loop terminates "early" thinking the target is reached — but the
  rev*.dat half is still bloating disk.
- Cross-cite BUG-11 (legacy `connectBlock` doesn't consult assumevalid):
  the surface area for "blocks-on-disk vs undo-on-disk asymmetry" is
  large.

---

## BUG-3 (P0) — `pruneblockchain` RPC ENTIRELY ABSENT (no handler in `rpc.zig`)

**Severity:** P0 (operator UX gap; manual-prune mode unusable).
Bitcoin Core's `pruneblockchain <height>` RPC is the ONLY way to
trigger a prune sweep when `-prune=1` (manual mode) is configured
(`bitcoin-core/src/rpc/blockchain.cpp:908-965`). It also accepts a
Unix timestamp ≥ 1e9 and resolves it to a height via
`FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0)`.

A grep of `src/rpc.zig` for `pruneblockchain` returns ZERO matches.
The only references to the symbol are in the comments at
`storage.zig:2963` ("Only the pruneblockchain RPC (not yet shipped
here) may delete data") and `main.zig:441` ("only the pruneblockchain
RPC (when shipped) triggers a sweep") — both explicitly call out that
the handler is missing.

**File:** `src/rpc.zig` (no handler), `src/storage.zig:2963`
(comment-as-confession).

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:908-965`,
`bitcoin-core/src/rpc/blockchain.cpp:3539`
(`{"blockchain", &pruneblockchain}` dispatch table entry).

**Impact:**
- In `-prune=1` manual mode, the operator literally cannot prune
  anything. `pruneToTarget` short-circuits at `prune_target_mib == 1`
  (BUG-1 sentinel); there is no other entry point.
- Existing operator tooling (`bitcoin-cli pruneblockchain`,
  electrs-prune-scripts, monitoring dashboards) all fail with
  "method not found".
- Cross-impl divergence: 5+ fleet impls already ship some form of
  `pruneblockchain` (see fleet pattern tracking); clearbit + likely 2-3
  others remain GAPS.

---

## BUG-4 (P0-CDIV) — `getblockchaininfo` hardcodes `"pruned":false` and `"size_on_disk":0`

**Severity:** P0-CDIV (RPC wire-format break + monitoring black-out).
Bitcoin Core's `getblockchaininfo` populates `"pruned"`,
`"pruneheight"`, `"automatic_pruning"`, `"prune_target_size"`, and
`"size_on_disk"` from `BlockManager::IsPruneMode()`,
`GetPruneHeight(m_blockman, m_chain)`, `m_prune_target`,
`!m_prune_target_manual`, and `CalculateCurrentUsage()` respectively.

clearbit's `handleGetBlockchainInfo` emits the literal string
`"size_on_disk":0,"pruned":false` regardless of
`chain_state.prune_target_mib`, `chain_state.prune_height`, or the
actual on-disk footprint:

```zig
try writer.writeAll("\",\"size_on_disk\":0,\"pruned\":false,\"softforks\":{");
```

**File:** `src/rpc.zig:3363`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp` —
`getblockchaininfo` populates the pruned object via
`obj.pushKV("pruned", chainman.m_blockman.IsPruneMode())` plus the
sub-fields.

**Impact:**
- Monitoring tools (mempool.space, fulcrum, electrs, custom
  Prometheus exporters) detect prune state ONLY via this field — they
  will report clearbit nodes as "not pruned" even when fully pruned.
- The `"size_on_disk":0` lie means disk-usage alerts will never fire
  on clearbit nodes.
- An operator running `bitcoin-cli getblockchaininfo` cannot verify
  whether their `-prune=N` flag took effect.
- Cross-cite BUG-3: combined with the missing pruneblockchain handler,
  there is no way for an operator to know *or* trigger prune state.

---

## BUG-5 (P0) — `getblock` RPC never consults `isHeightPruned`; returns "Block not found" for pruned bytes

**Severity:** P0 (operator UX + tooling parity gap). Bitcoin Core's
`getblock` returns RPC error code `-1` with message `"Block not
available (pruned data)"` when the block exists in the header index
but has been pruned. Wallet software, indexers, and explorers
distinguish "this block never existed" from "we used to have it but
pruned" via this error.

clearbit's `handleGetBlock` (`rpc.zig:3530-3700`) has the standard
path: try CF_BLOCKS, fall back to chain_manager.getBlock(header), then
proxy to Core. It NEVER consults `chain_state.isHeightPruned()` (which
is correctly implemented at `storage.zig:3020`). The pruned-block
branch falls through to "Block not found" or silently proxies to Core
(BUG-19 below).

**File:** `src/rpc.zig:3530-3700` (no `isHeightPruned` call); the
helper exists at `src/storage.zig:3015-3023`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp` `getblock`
pruned-block branch:
```cpp
if (pblockindex->nStatus & BLOCK_HAVE_DATA) { ... }
else if (chainman.m_blockman.IsPruneMode()) {
    throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");
}
```

**Impact:**
- Operators get misleading errors that don't distinguish
  config/network problems from intentional pruning.
- `isHeightPruned` is implemented and unit-tested but never wired —
  classic "dead-helper-at-call-site" pattern (cross-cite W141 +
  W128 fleet pattern).
- The proxy-to-Core path (Path A fallback) silently masks the issue
  ONLY for operators who run a sidecar Core node; standalone clearbit
  deployments get a hard "not found" with no remediation hint.

---

## BUG-6 (P0-CDIV) — No `-assumevalid=<hex>` CLI; only boolean `--noassumevalid`

**Severity:** P0-CDIV (operator-control gap; Core wire-format parity).
Bitcoin Core ships three behaviors via the `-assumevalid` arg
(`bitcoin-core/src/init.cpp:487`):
1. `-assumevalid` unset → use chainparams default (mainnet h=938343, etc).
2. `-assumevalid=0` → disable script-skip; verify every script.
3. `-assumevalid=<hex>` → use the supplied block hash as the
   assume-valid anchor instead of the chainparams default. This is
   how a release-engineer ships an updated default and how an
   operator pins a specific recent block.

clearbit only ships option 2 (renamed `--noassumevalid` —
`main.zig:391-394`). Option 3 has no CLI surface; the operator must
recompile to change the assume-valid anchor.

**File:** `src/main.zig:127-128, 391-394`, `src/main.zig:543`.

**Core ref:** `bitcoin-core/src/init.cpp:487`.

**Excerpt (clearbit, boolean-only)**
```zig
// Assumevalid control
noassumevalid: bool = false, // if true, set assumed_valid_hash = null (always verify scripts)
```

**Impact:**
- Cannot ship a hotfix updated assume-valid hash to operators without
  a binary release.
- Cannot pin a recent verified-good block during contentious
  fork-recovery events (Core operators routinely use this).
- Wire-format divergence: monitoring tools that parse
  `--assumevalid=<hex>` config files reject clearbit's boolean variant.

---

## BUG-7 (P1) — `getNetworkParams` returns stale pointer to thread-local-mutated static struct

**Severity:** P1 (latent data race; correctness under concurrent
network switch). `getNetworkParams` (`main.zig:165-189`) returns
`*const NetworkParams`. When `--noassumevalid` is set, the function
deep-copies the base params into a Zig `comptime struct { var
patched: NetworkParams; }`, writes to the static field, and returns
its address:

```zig
const S = struct { var patched: consensus.NetworkParams = undefined; };
S.patched = p;
return &S.patched;
```

The comment immediately above the function says "Callers must not
store the pointer beyond the current call frame — all callers use it
immediately for SyncManager / block_template construction." But the
ACTUAL callers (`PeerManager`, `RpcServer`, `SyncManager`,
`ChainManager`, `block_template`) all store this pointer as
`network_params: *const NetworkParams` for the entire process
lifetime.

If two callers ever invoke `getNetworkParams` concurrently — or if the
function is ever extended to swap params on a network change — the
`S.patched` static is overwritten while live callers hold pointers
into it. Even single-threaded today, the static buffer is fragile:
any second call (e.g. RPC re-init, test setup) clobbers the live
PeerManager's params silently.

**File:** `src/main.zig:165-189`.

**Impact:**
- Latent — single boot path today only calls `getNetworkParams` once
  per network. But the code shape invites future regressions.
- Tests that exercise multiple networks in one process can corrupt
  each other's params.
- Comment-as-confession (4th instance in clearbit this audit period):
  the comment documents the contract that the live callers violate.

---

## BUG-8 (P0-CONS) — Three production paths set `force_skip_scripts` from `height ≤ av_height` alone, bypassing Core's six-condition gate

**Severity:** P0-CONS (consensus-divergent — accepts blocks that Core
rejects). This is the most significant finding in the wave.

Bitcoin Core's `fScriptChecks` gate in `ConnectBlock`
(validation.cpp:2345-2383) requires SIX conditions to skip scripts:
1. `m_chainman.AssumedValidBlock()` (== `params.defaultAssumeValid`) is
   set;
2. the assumed-valid block is in `m_blockman.m_block_index`;
3. the assumed-valid block's chainwork ≥ `nMinimumChainWork`;
4. `pindex` (block being connected) is an ancestor of the
   assumed-valid block (via `pindex->GetAncestor(av_height) ==
   av_block`);
5. the assumed-valid block is an ancestor of `m_chain.Tip()`;
6. the assumed-valid block is at least 288 blocks past `pindex`
   (`av_block->nHeight - pindex->nHeight >= MIN_BLOCKS_TO_KEEP`).

clearbit's `shouldSkipScripts` (`validation.zig:706-756`) implements
ALL SIX conditions correctly. But the THREE production callers ALL
compute `skip_via_height` from condition (4) alone — and pass it as
`force_skip_scripts = true` to bypass the six-condition gate:

- **peer.zig:6379-6381** (IBD/P2P drain path — live IBD on mainnet):
```zig
const av_height = self.network_params.assume_valid_height;
const skip_via_height = (height <= av_height) and (av_height != 0) and
    (self.network_params.assumed_valid_hash != null);
// ...
.force_skip_scripts = skip_via_height,
```

- **sync.zig:1741-1743** (legacy BlockDownloader IBD path): byte-identical
  pattern.
- **rpc.zig:6375-6377** (submitblock RPC): byte-identical pattern.

And in `validateBlockForIBD`:
```zig
const skip_scripts = blk: {
    if (ctx.force_skip_scripts) break :blk true;  // ← bypasses shouldSkipScripts entirely
    if (ctx.active_chain) |chain| break :blk shouldSkipScripts(...);
    break :blk false;
};
```

So if a peer feeds clearbit a block whose height is ≤ 938343 (mainnet
assume-valid height) on a fork off the active chain, clearbit:
- skips script verification because `height <= av_height` is true;
- but the block is NOT actually an ancestor of `assumed_valid_hash` —
  conditions 4 and 5 of Core's gate are violated;
- the block silently passes script validation that Core would have
  caught.

Conditions 5 (chainwork) and 6 (2-week timestamp gap) are also
unenforced on this path.

**File:** `src/peer.zig:6374-6408`, `src/sync.zig:1740-1797`,
`src/rpc.zig:6373-6390`, `src/validation.zig:1589-1604`.

**Core ref:** `bitcoin-core/src/validation.cpp:2345-2383`.

**Excerpt (Core's gate; conditions 4 + 5 omitted in clearbit's
force-skip path)**
```cpp
auto it = m_assumed_valid_blocks.find(pindex->GetBlockHash());
if (it == m_assumed_valid_blocks.end()) {
    script_check_reason = "assumevalid hash not in headers";
} else if (pindex->nHeight > it->second.nHeight) {
    script_check_reason = "block height above assumevalid height";
} else if (...) {
    // ancestor checks, chainwork, 288-block gap
}
```

**Impact:**
- **Chain-split candidate on mainnet during a fork at h ≤ 938343** —
  a peer that submits a competing chain whose tip is below the
  assume-valid height will have its scripts skipped on clearbit but
  verified on Core. If the peer's block has an invalid script, Core
  rejects it; clearbit accepts.
- This is a "three-pipeline drift" pattern (cross-cite W143
  ouroboros): IBD, legacy sync, AND submitblock RPC all duplicate
  the buggy short-circuit logic. Same shape across three files
  guarantees the bug survives any single-file fix.
- Risk profile: in steady-state IBD where every block is genuinely an
  ancestor of the assume-valid hash on the active chain, this is
  benign. The exposure is during reorgs that cross the av_height
  boundary or peer-driven side-branch ingest.

---

## BUG-9 (P1) — No `m_have_pruned` analog; reindex-after-prune cannot detect missing files

**Severity:** P1. Bitcoin Core's `BlockManager::m_have_pruned` is set
on the first successful prune and persisted to disk via
`block_index.dat`. On boot, Core consults this flag to decide whether
to:
- error out on `-reindex` if pruned data is missing (rev*.dat / blk*.dat
  unrecoverable);
- skip the "verify-all-blocks" startup check that would otherwise fail
  on holes;
- advertise NODE_NETWORK_LIMITED + NODE_BLOOM correctly.

clearbit has no such field. The `prune_height` watermark IS persisted
(via the standard ChainState serialization), but a fresh boot cannot
distinguish "this node has never run prune" from "this node has run
prune and is missing files below `prune_height`". A user who flips
`--prune=550` on, runs for a week, then turns it off and restarts has
no signal that their datadir is now permanently pruned.

**File:** `src/storage.zig:1914-2050` (no `m_have_pruned` analog).

**Core ref:** `bitcoin-core/src/node/blockstorage.h`,
`bitcoin-core/src/node/blockstorage.cpp::BlockManager::LoadBlockIndexDB`.

**Impact:**
- `-reindex` after pruning silently fails halfway through with
  "block not found" errors instead of a clear "this datadir is pruned,
  reindex requires un-pruned files".
- NODE_BLOOM advertisement is correctly suppressed today via
  `advertise_node_network_limited = chain_state.prune_target_mib > 0`
  (`main.zig:1846`) — but flipping the flag mid-life without setting
  prune_target_mib=0 in the same boot leaves the advertisement stale.

---

## BUG-10 (P1) — `getblockchaininfo` hardcodes `"verificationprogress":1.0`

**Severity:** P1 (operator UX + assumevalid-aware-progress gap).
Bitcoin Core's `verificationprogress` is computed from
`m_chain_tx_count` against the chainparams `m_assumed_chain_state_size`
estimate plus a tx-density extrapolation. It's the canonical sync
progress indicator. clearbit hardcodes `1.0`:

```zig
try writer.print("\",\"difficulty\":{d},\"time\":{d},\"mediantime\":{d},\"verificationprogress\":1.0,\"initialblockdownload\":{},\"chainwork\":\"", .{...});
```

**File:** `src/rpc.zig:3354`.

**Impact:**
- Every monitoring dashboard / launcher script that polls
  `verificationprogress` for "node is ready" gets a false-positive
  on day-1 IBD.
- IBD-state divergence: `initialblockdownload:true` AND
  `verificationprogress:1.0` simultaneously is internally
  inconsistent — Core only emits 1.0 once IBD has been false for ≥1
  full block.

---

## BUG-11 (P1) — Legacy `connectBlock()` ignores assumevalid; always runs scripts

**Severity:** P1 (semantic divergence on mining / dumptxoutset
rollback path; carry-forward from W93). `validation.zig:879-998`
defines the legacy `connectBlock()` that is called by mining
(`block_template`), the `dumptxoutset` rollback path, and ChainState
test harnesses. Its inline comment at line 893 explicitly mentions
assumevalid:

```zig
// ContextualCheckBlock: enforce IsFinalTx for every transaction
// (Bitcoin Core validation.cpp:4146). Consensus rule that runs even
// under assumevalid — assumevalid only skips script verification.
```

But the function has NO `skip_scripts` parameter and unconditionally
calls `verifyBlockScriptsParallel` at line 987. The IBD path
(`validateBlockForIBD`) and the unified `acceptBlock` entry point DO
plumb assumevalid; the legacy path does not.

**File:** `src/validation.zig:879-998`.

**Core ref:** `bitcoin-core/src/validation.cpp:2345-2383` (single
`fScriptChecks` is computed once at the top of `ConnectBlock` and
applies to ALL paths).

**Impact:**
- Mining path (`block_template`) re-verifies every script on every
  template — performance regression during mining, but
  consensus-safe.
- `dumptxoutset` rollback dance is the more interesting
  consequence: the rollback walks blocks via `connectBlockLocked` →
  `connectBlockInner` — but the actual script eval happens in
  whichever path called connectBlock. Combined with BUG-8's
  over-skip, the asymmetry is: IBD over-skips, mining under-skips.

---

## BUG-12 (P0-CDIV) — Per-network `min_chain_work` constants severely diverge from Core

**Severity:** P0-CDIV (anti-DoS gate effectively disabled on
testnet4/testnet3/signet). clearbit ships placeholder values for
non-mainnet networks:

| Network | clearbit `min_chain_work` | Core `nMinimumChainWork` | Magnitude gap |
|---------|---------------------------|--------------------------|---------------|
| mainnet | `00000000000000000000000000000000000000009c68c8e19c0c2e0b00000000` (~Oct 2024) | `0000000000000000000000000000000000000001128750f82f4c366153a3a030` | Core ~2× larger; clearbit value 7+ months stale |
| testnet3 | `0000000000000000000000000000000000000000000000000000000100000000` | `0000000000000000000000000000000000000000000017dde1c649f3708d14b6` | Core ~10^13× larger |
| testnet4 | `0000000000000000000000000000000000000000000000000000000100000000` | `0000000000000000000000000000000000000000000009a0fe15d0177d086304` | Core ~10^11× larger |
| signet | `0000000000000000000000000000000000000000000000000000000100000000` | `00000000000000000000000000000000000000000000000000000b463ea0a4b8` | Core ~10^7× larger |
| regtest | `0000...0000` (zeros) | `{}` (empty) | PASS (both effectively 0) |

The `0x0...0100000000` placeholder accepts essentially any chain with
even one valid header — defeating the anti-DoS purpose of the
constant on testnet4 (the live test network that gets the most
exposure).

**File:** `src/consensus.zig:518, 633, 687, 739, 791`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:109, 232, 332,
423, 557`.

**Impact:**
- On testnet4: an attacker advertising a low-work fake chain passes
  PRESYNC/REDOWNLOAD anti-DoS (sync.zig:429, 519) and the headers
  handler's `min_pow_checked` gate (peer.zig:4532-4546).
- On testnet4, IBD-exit (rpc.zig:13698) latches `m_cached_is_ibd =
  false` immediately on any first synced block — clearbit reports
  "not in IBD" on testnet4 with zero chainwork.
- Mainnet value is from clearbit's W141-era stamp (Bitcoin Core v28.0,
  Oct 2024); Core has bumped twice since.

---

## BUG-13 (P0-CDIV) — Endianness mismatch: `min_chain_work` stored little-endian by `hexToHash`, compared as big-endian by `cmpChainWorkBE` / `compareChainWork` / `shouldSkipScripts`

**Severity:** P0-CDIV (chain-work compares against `min_chain_work`
are silently wrong). `hexToHash` (`consensus.zig:1282-1291`) takes a
display-hex string (big-endian) and reverses bytes — storing the result
"with display-MSB at index 31, display-LSB at index 0". This is the
standard Bitcoin internal little-endian layout for hashes.

But the runtime cumulative `chain_work` produced by `workFromBits`
(`peer.zig:146-243`) is BIG-ENDIAN (MSB at index 0); see the comment
at peer.zig:114-116: "Stored big-endian to keep byte-comparison
semantics".

The chain-work comparators (`cmpChainWorkBE` peer.zig:248,
`compareChainWork` rpc.zig:13731, the inline loop in
`shouldSkipScripts` validation.zig:739-744) all walk `i=0..31`
treating index 0 as MSB.

Concretely, mainnet `min_chain_work` after `hexToHash` reversal:
- index 0: `0x00` (display-byte 31, LSB of the number)
- index 11: `0x9c` (display-byte 20)
- index 31: `0x00` (display-byte 0, MSB)

Runtime chain_work for a near-tip mainnet block:
- index 0: high-order bytes (MSB), several non-zero bytes here
- index 31: low-order bytes, typically 0x00

Comparing index 0 of runtime (high non-zero) vs index 0 of
`min_chain_work` (0x00) → runtime > min always passes early. Not
catastrophically wrong on mainnet because runtime chain_work happens
to have huge MSB, but the gate is comparing wrong byte-order and on
testnet4/testnet3 the comparison can flip the wrong way.

**File:** `src/consensus.zig:1282` (hexToHash storage layout),
`src/peer.zig:114-115, 146-243, 248-255` (workFromBits + cmp),
`src/rpc.zig:13731-13739` (compareChainWork), `src/validation.zig:
739-744` (shouldSkipScripts internal compare).

**Compare with**: `src/sync.zig:1346-1355` (`compareWork`) walks
`i=32..0` (high-index downward) — i.e. assumes the OPPOSITE byte
order. So clearbit has TWO competing chain-work comparators using
opposite byte-order conventions:
- `sync.zig::compareWork` — walks high index first (little-endian
  storage)
- `peer.zig::cmpChainWorkBE`, `rpc.zig::compareChainWork`,
  `validation.zig::shouldSkipScripts` — walk index 0 first (big-endian
  storage)

The `min_chain_work` constant is stored in the layout `compareWork`
expects (little-endian) but every consumer except sync.zig uses the
big-endian comparator.

**Impact:**
- PRESYNC / REDOWNLOAD anti-DoS (sync.zig:429, 519) uses `compareWork`
  → works with min_chain_work's storage layout.
- Headers-handler `min_pow_checked` gate (peer.zig:4544) uses
  `cmpChainWorkBE` against `min_chain_work` → comparing wrong byte
  order. Anti-DoS effectively disabled on this path.
- `shouldSkipScripts` condition 5 (`best_tip_chain_work ≥
  min_chain_work`) → comparing wrong byte order. Condition 5 may
  silently pass or fail by accident.
- `isInitialBlockDownload` (rpc.zig:13698) uses `compareChainWork`
  against `min_chain_work` → wrong byte order. IBD-exit latch can
  trigger before chainwork is actually high enough (or never trigger).

This is the same pattern as W128 banman fleet-wide CVE: two pipelines
diverging on byte-order convention, both shipping in production.

---

## BUG-14 (P1) — No `-minimumchainwork=<hex>` CLI override

**Severity:** P1 (operator-control gap). Bitcoin Core ships
`-minimumchainwork=<hex>` (`init.cpp:512`, gated `DEBUG_ONLY`) so
operators can override the chainparams default — used during regtest
testing, custom networks, or to bypass anti-DoS for forensics.

clearbit has no analog. The only knob is `--noassumevalid` (boolean,
BUG-6).

**File:** `src/main.zig:204-435` (no `-minimumchainwork` arg parsing).

**Impact:**
- Cannot replay testnet4 IBD against clearbit with a custom
  min-chain-work for performance benchmarking.
- Cannot bypass the (already-broken) min_chain_work gate when
  triaging a peer-acceptance issue.

---

## BUG-15 (P1) — No `MinimumConnectedChainWork` per-peer disconnect gate

**Severity:** P1 (DoS surface). Bitcoin Core's
`net_processing.cpp` checks each peer's advertised best-known chain
against `m_chainman.MinimumChainWork()` and disconnects peers whose
chain has less work than the minimum.

clearbit's `min_chain_work` is consulted only:
1. PRESYNC / REDOWNLOAD anti-DoS (sync.zig:429, 519) — header sync
   anti-DoS during the initial sync;
2. IBD-exit latch (rpc.zig:13698) — own chainwork vs minimum;
3. `shouldSkipScripts` condition 5 (validation.zig:738) —
   assume-valid gate (also broken per BUG-13).

There is NO per-peer disconnect gate. A peer advertising a 1-header
testnet4 stub chain on mainnet would not be disconnected on chainwork
grounds (other gates may still catch them).

**File:** `src/peer.zig` (no analog), `src/p2p.zig` (no analog).

**Impact:**
- Low-work fork peers stay connected and consume slots — DoS surface
  bound by the addrman + ban gates, not chainwork.

---

## BUG-16 (P2) — Pruner runs every 60 s with no chain-extension trigger

**Severity:** P2 (latency / bursty disk). Bitcoin Core's
`FindFilesToPrune` is called from `FlushStateToDisk` which fires on
chain extension events (each block connect, plus periodic flushes).
Pruning latency is proportional to chain growth.

clearbit's pruner (`main.zig:2199-2225`) runs unconditionally every
60 seconds in the main loop, regardless of chain activity:
```zig
const PRUNE_TICK_MS: u64 = 60 * 1000; // every 60 s
```

For a node that's at-tip and idle, the pruner is a no-op (good).
For a node that's mid-IBD and adding 100+ blocks per minute,
the pruner can lag by a full minute behind the connect loop and
trigger a large delete batch (MAX_PRUNE_BATCH=4096) all at once — a
disk-I/O burst that competes with the connect loop's flush.

**File:** `src/main.zig:2200-2225`.

**Impact:**
- IBD throughput dip every 60s when prune is enabled.
- Tail latency on `connectBlockFast`'s flush goes up during prune
  bursts.

---

## BUG-17 (P2) — `pruneToTarget` `MAX_PRUNE_BATCH = 4096` is unconditional; no progressive widening

**Severity:** P2. Core's `FindFilesToPrune` walks until either the
target is met OR the keep-horizon is hit — no fixed batch cap. The
4096 cap means that pruning a freshly-flipped `--prune=550` config on
a fully-synced mainnet node (best_height=890,000, prune_height=0)
requires `890000 / 4096 ≈ 218` separate ticks @ 60s each = 3.6 hours
just to walk the height range, regardless of how big the actual
deletion is.

**File:** `src/storage.zig:2980`.

**Impact:**
- Operator who flips `--prune=550` on a full node waits hours before
  the watermark catches up; during that time CF_BLOCKS is unbounded.
- No mechanism to "catch up" the watermark in a single pass after a
  reconfig.

---

## BUG-18 (P2) — `pruneToTarget` ignores `flush_error` sticky flag

**Severity:** P2. The connect path consults `chain_state.flush_error`
on entry to `connectBlockFast` and refuses to advance the tip if a
prior flush failed (storage.zig:3075-3078). The pruner has no such
check — it will happily delete CF_BLOCKS entries even when the chain
is in a broken-flush state, potentially deleting blocks that the
recovery dance would need to re-flush.

**File:** `src/storage.zig:2958-3013` (no `flush_error` check).

**Impact:** Low — `pruneToTarget` deletes blocks at heights ≤
best_height − 288, which by definition are not the ones the
broken-flush recovery would re-write. But the safety check is missing.

---

## BUG-19 (P2) — `getblock` falls through to Core proxy when CF_BLOCKS misses, masking pruned state

**Severity:** P2 (operator-confusion + degraded standalone mode).
When clearbit's `handleGetBlock` (rpc.zig:3593-3618) finds no
CF_BLOCKS entry, it calls `proxyGetBlock0FromCore` or
`proxyGetBlock2FromCore`. For operators running a Core sidecar this
silently masks the pruned state (BUG-5 fallback). For standalone
operators the proxy returns "node not configured" or hangs.

**File:** `src/rpc.zig:3614-3618, 3700-3707`.

**Impact:**
- Operator sees inconsistent behavior depending on whether they
  configured the Core proxy URL.
- Pruned-block detection silently degrades the user-facing error
  message.

---

## BUG-20 (P2) — `assumeUTXO` snapshot has no `m_chain_tx_count` bridge into pruning

**Severity:** P2. Core's `assumeUTXO` workflow sets
`m_chain_tx_count` on the snapshot base block from
`AssumeutxoData.m_chain_tx_count`. Combined with pruning, this lets
the snapshot-loaded chainstate prune everything below the snapshot
height even though no blocks have been physically applied below it.

clearbit's `AssumeUtxoData` struct DOES carry `chain_tx_count`
(consensus.zig:467-473), but it's only used to populate block-index
counts after snapshot load — `pruneToTarget` doesn't consult snapshot
base at all (it walks from `prune_height + 1` to `best_height -
288`). A snapshot at h=840,000 wouldn't allow pruning of heights
1..839,711 without first synthetic-writing those CF_BLOCKS entries.

**File:** `src/storage.zig:2982-3012`,
`src/consensus.zig:459-473`.

**Impact:** Low — `assumeUTXO` is not heavily exercised on clearbit
today. The snapshot-prune interaction will surface when both features
are enabled at the same time.

---

## BUG-21 (P2) — `shouldSkipScripts` condition 5 uses `>=` semantics but comments document equal-also-sufficient ambiguously

**Severity:** P2 (defensive — small consensus difference).
Core's six-condition gate at validation.cpp:2358 uses
`pindex->nChainWork >= nMinimumChainWork`. clearbit's `shouldSkipScripts`
inline compare returns `true` on equality:

```zig
for (0..32) |i| {
    if (best_tip_chain_work[i] > min_work[i]) break :blk true;
    if (best_tip_chain_work[i] < min_work[i]) break :blk false;
}
break :blk true; // Equal: also sufficient
```

The `// Equal: also sufficient` comment is correct per Core, but the
byte-order issue (BUG-13) makes the whole loop comparing wrong bytes,
so the equality case never triggers in practice.

**File:** `src/validation.zig:739-744`.

**Impact:** Negligible standalone; compounds BUG-13.

---

## BUG-22 (P3) — `validatePruneTarget` test uses obsolete constant name in error message

**Severity:** P3 (cosmetic). The error path at main.zig:457-461 prints
`MIN_PRUNE_TARGET_MIB` but with no contextual hint that Core uses the
same constant (550 MiB).

```zig
std.debug.print(
    "Error: Prune target must be 0 (off), 1 (manual mode), or at least {d} MiB (got {d} MiB).\n",
    .{ storage.ChainState.MIN_PRUNE_TARGET_MIB, prune_mib },
);
```

Core emits a similar message; cosmetic only.

**File:** `src/main.zig:457-461`.

**Impact:** None functional.

---

## Fleet-pattern smells

- **Three-pipeline drift** (1×, P0-CONS): BUG-8 — peer.zig, sync.zig,
  AND rpc.zig all duplicate the `skip_via_height = (height <=
  av_height)` short-circuit. Same shape across THREE production
  entry points. Single architectural fix (route everything through
  `shouldSkipScripts` and remove `force_skip_scripts` from the
  `AcceptBlockOptions` struct) closes all three.  Cross-cite W143
  ouroboros 3-pipeline.
- **Dead-helper-at-call-site** (3×): (a) `isHeightPruned`
  implemented at storage.zig:3020 but never called from rpc.zig
  (BUG-5); (b) `pruneblockchain` RPC handler ENTIRELY absent (BUG-3);
  (c) legacy `connectBlock` has no assumevalid plumbing despite
  comment claiming it (BUG-11). Same family as W141's "exports the
  primitive, just not called".
- **Two-pipeline guard** (BUG-13): TWO competing chain-work
  comparators in production:
  - `sync.zig::compareWork` (little-endian byte walk)
  - `peer.zig::cmpChainWorkBE` / `rpc.zig::compareChainWork` /
    `validation.zig::shouldSkipScripts` (big-endian byte walk).
  Same data (`min_chain_work` from hexToHash), opposite conventions.
  17th distinct instance fleet-wide.
- **Comment-as-confession** (3×):
  - `main.zig:441` "only the pruneblockchain RPC (when shipped)" —
    documents BUG-3.
  - `main.zig:175-177` "Callers must not store the pointer beyond the
    current call frame" — every actual caller violates this (BUG-7).
  - `validation.zig:893` "assumevalid only skips script verification"
    inside `connectBlock` which doesn't even check assumevalid
    (BUG-11).
- **Dead-data plumbing**: `pending_undo_writes` and
  `pending_undo_deletes` are populated by the connect path but
  `pruneToTarget` never schedules undo deletes (BUG-2).
- **Hardcoded constants that should be params-aware**:
  - testnet4/testnet3/signet `min_chain_work` placeholders (BUG-12)
  - mainnet `min_chain_work` snapshot stamp from Oct 2024 (BUG-12
    carry-forward)
- **Carry-forward re-anchor**: BUG-11 (legacy connectBlock no
  assumevalid) is a W93 carry-forward — the inline comment was
  updated to reflect the IBD path's fix, but the function itself was
  never modified. Same pattern as W123 → W145 BUG-1.
- **30-of-30-gates-buggy**: NOT fired this audit (22 bugs across 32
  gates; about half buggy). clearbit's pruning + assumevalid
  subsystem is *partially* present: the storage primitives (prune
  watermark, undo files, CF_BLOCKS / CF_BLOCK_UNDO column families,
  isHeightPruned helper, shouldSkipScripts six-condition gate) ARE
  implemented; the RPC surface (`pruneblockchain`,
  `getblockchaininfo` prune fields, `getblock` pruned errors) and the
  consensus-gate WIRING into the three production paths are the major
  gaps.

---

## Summary

22 bugs catalogued — 7 P0-class, 8 P1-class, 6 P2-class, 1 P3-class.

Severity-totals:
- **P0-CONS** (consensus-divergent on script execution): 1 — BUG-8
  (three-pipeline assumevalid over-skip).
- **P0-CDIV** (consensus-divergent semantics / wire-format
  divergent): 4 — BUG-1 (sentinel encoding), BUG-4
  (`getblockchaininfo` lies about prune state), BUG-6
  (`-assumevalid=<hex>` absent), BUG-12 (testnet4/3/signet
  `min_chain_work` placeholders), BUG-13 (endianness mismatch).
- **P0** (semantic gap / functional missing): 3 — BUG-2 (no
  CF_BLOCK_UNDO pruning), BUG-3 (no `pruneblockchain` RPC), BUG-5
  (`getblock` ignores pruned watermark).
- **P1** (correctness / persistence): 7 — BUG-7 (static-buffer
  pointer footgun), BUG-9 (no `m_have_pruned`), BUG-10
  (`verificationprogress` hardcoded 1.0), BUG-11 (legacy connectBlock
  no assumevalid), BUG-14 (no `-minimumchainwork`), BUG-15 (no per-peer
  disconnect), BUG-20 (assumeUTXO + prune interplay).
- **P2**: 6 — BUG-16, BUG-17, BUG-18, BUG-19, BUG-21.
- **P3**: 1 — BUG-22.

Highest-leverage fixes:

1. **BUG-13** (endianness): single architectural fix; pick ONE byte
   convention (Core uses little-endian internal storage, big-endian
   compare via arith_uint256). Either change `hexToHash` to NOT
   reverse, OR change every consumer to walk index 31 downward. Closes
   the silent-pass on min_chain_work + assume-valid condition 5.
   ~5 LOC.

2. **BUG-8** (three-pipeline force-skip): delete the
   `force_skip_scripts` field from `AcceptBlockOptions`; have all
   three callers pass through `shouldSkipScripts` proper. Closes the
   P0-CONS chain-split window. ~15 LOC across 3 files.

3. **BUG-2** (CF_BLOCK_UNDO pruning): add a parallel
   `db.delete(CF_BLOCK_UNDO, &hash)` next to the existing CF_BLOCKS
   delete in `pruneToTarget`. Optionally also walk `UndoFileManager`
   rev*.dat unlinks. ~5 LOC.

4. **BUG-4** (getblockchaininfo prune fields): emit `"pruned":
   prune_target_mib > 0`, `"pruneheight": prune_height`,
   `"automatic_pruning": prune_target_mib > 1`, `"prune_target_size":
   prune_target_mib * 1024 * 1024`, and a real `size_on_disk` via the
   existing `estimateBlockCfBytes` helper. ~10 LOC.

5. **BUG-3** (pruneblockchain RPC): implement the handler — refuse
   when not in prune mode, parse height/timestamp dual-mode, clamp
   to `chainHeight - MIN_BLOCKS_TO_KEEP`, advance `prune_height` to
   the requested boundary, optionally walk a single-pass delete loop
   bigger than MAX_PRUNE_BATCH. ~80 LOC. Closes the manual-mode
   tooling gap.

6. **BUG-12** (testnet4/3/signet min_chain_work): copy values from
   Core's chainparams.cpp verbatim. ~4 LOC. Refresh mainnet value
   alongside.

7. **BUG-11** (legacy connectBlock assumevalid): add
   `skip_scripts: bool = false` parameter; gate the
   `verifyBlockScriptsParallel` call on `!skip_scripts`. Wire callers
   to use the same `shouldSkipScripts` path as the IBD path. ~10 LOC.
