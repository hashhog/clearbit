# W138 — assumeUTXO snapshots audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's assumeUTXO snapshot subsystem vs Bitcoin Core
(`bitcoin-core/src/node/utxo_snapshot.{h,cpp}`,
 `bitcoin-core/src/validation.cpp` `ActivateSnapshot` / `PopulateAndValidateSnapshot` /
   `MaybeValidateSnapshot` / `InvalidateCoinsDBOnDisk` / `MaybeRebalanceCaches` /
   `LoadBlockIndexDB(snapshot_blockhash)`,
 `bitcoin-core/src/rpc/blockchain.cpp` `dumptxoutset` / `loadtxoutset` /
   `getchainstates` / `PrepareUTXOSnapshot` / `WriteUTXOSnapshot`).
**BIPs:** none (assumeUTXO is a Bitcoin Core implementation feature, not a BIP).
**Files in scope:** `src/storage.zig` (`SnapshotMetadata`, `SnapshotCoin`,
`ChainstateRole`, `ChainStateManager`, `dumpTxOutSet`,
`dumpTxOutSetWithResult`, `loadTxOutSet`, `validateAndLoadSnapshot`,
`findAssumeUtxoEntry`, `findAssumeUtxoEntryByHeight`,
`findLatestAssumeUtxoEntryAtOrBelow`, `computeHashSerializedTxOutSet`,
`computeMuHashTxOutSet`, `computeUtxoSetHash`, `SnapshotError`,
`SnapshotLoadResult`, `SnapshotDumpResult`, `writeSnapshotCoinPayload`,
`readSnapshotCoinPayload`), `src/consensus.zig` (`AssumeUtxoData`,
`MAINNET.assume_utxo`, `TESTNET3/4.assume_utxo`, `SIGNET.assume_utxo`,
`REGTEST.assume_utxo`), `src/main.zig` (`--load-snapshot=<path>` CLI
mode + `loadSnapshotFromFile` streaming RocksDB import), `src/rpc.zig`
(`handleLoadTxOutSet` gate, `handleDumpTxOutSet` rollback dance,
`replayReconnect`). Tangential but not in scope: `src/muhash.zig`
(MuHash3072 primitive used only by `gettxoutsetinfo hash_type=muhash`).
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards +
source greps only).
**Test step:** `zig build test-w138` (folded into `zig build test`).
**Related prior work:** "W102 AssumeUTXO snapshot loading gate audit"
(`src/storage.zig:10915+`) — closed G1/B2/B3/B4/B7/B11 + documented
G3/G15 (legacy hash) / G26/G27 (testnet3/4/signet empty whitelists) /
G7/G9 (MoneyRange in CLI but not storage). FIX-EXISTING handles W102 gaps
2026-04-29ish.  W57 height-index gap referenced in `handleDumpTxOutSet`
rollback. `_snapshot-cli-rpc-parity-audit-2026-05-05.md` documents the
RPC-vs-CLI fork. This wave audits the **end-to-end** assumeUTXO
lifecycle: dump → wire-format → load → activate → background-validate →
snapshot completion → persistence across restarts.

## Summary

clearbit ships a **partial assumeUTXO implementation**: the wire format
(`SnapshotMetadata`, coin grouping, ScriptCompression+VARINT coin
encoding) is **byte-correct** vs Core for both directions, the
strict-content-hash gate (`hash_serialized` SHA256d via HashWriter) is
**Core-strict** on the in-memory `validateAndLoadSnapshot` path, and the
`dumptxoutset` RPC (both `latest` and `rollback` shapes) **works
end-to-end** including a temp-file + fsync + atomic rename protocol that
mirrors Core. However, the **activation half** of assumeUTXO is largely
non-functional: the only operational load path is the CLI flag
(`--load-snapshot=<path>`), which seeds RocksDB before any P2P stack
exists; the **RPC `loadtxoutset` is fully gated** with an
`RPC_INTERNAL_ERROR` refuse-at-the-door (`handleLoadTxOutSet` /
`rpc.zig:8332-8352`). Once loaded by either path, there is **no
background chainstate, no two-chainstate split, no validation merge, no
snapshot-blockhash persistence file, no `_snapshot` chainstate dir, no
`getchainstates` RPC, and no `InvalidateCoinsDBOnDisk` cleanup** —
clearbit's `ChainStateManager` defines the *structure* for dual
chainstates but it is **wired to nothing**: no caller activates it from
either the CLI path (which just writes to the single live chainstate)
or the gated RPC path (which refuses before any wiring).

Key findings ranked by severity:

- **HIGH-DIVERGE: CLI `--load-snapshot` skips the strict
  `hash_serialized` content-hash gate.** `loadSnapshotFromFile`
  (`main.zig:1025-1277`) validates magic / version / network / per-coin
  MoneyRange / coin-height-vs-snapshot-height, but **never computes
  `hash_serialized` over the loaded UTXOs and compares against
  `assume_entry.hash_serialized`**. The in-memory
  `validateAndLoadSnapshot` (used by tests + the gated RPC) DOES enforce
  this gate (`storage.zig:6002-6011`), but the CLI — the **only** path
  actually loadable today — silently accepts any coin set as long as
  per-coin invariants pass. An attacker who can write to the operator's
  disk can substitute a snapshot file with the correct
  `base_blockhash` (which is whitelisted) and arbitrary UTXO
  contents; clearbit will populate RocksDB with the attacker's UTXO set,
  pin the chain tip to that height, and start serving wrong UTXO answers
  via `gettxout` / `scantxoutset` / mining templates. This is the
  inverse of W102 G4 — the audit there pinned the strict gate on the
  *RPC* path while leaving the CLI path open. See BUG-1. (G1.)

- **HIGH-MISSING: No two-chainstate / background chainstate / snapshot
  validation lifecycle.** Core's assumeUTXO design requires running
  *two* chainstates simultaneously: the snapshot chainstate (fast-forwarded
  to the snapshot tip, used for tip-following) and the background
  chainstate (validating from genesis up to the snapshot height, after
  which `MaybeValidateSnapshot` compares `hash_serialized` against
  `m_assumeutxo_data`). clearbit's `ChainStateManager` defines
  `active_chainstate`, `background_chainstate`,
  `snapshot_base_blockhash`, `ChainstateRole`, `activateSnapshot`,
  `startBackgroundValidation`, `completeValidation`,
  `isBackgroundValidationComplete`, **but no production code path
  constructs a `ChainStateManager`, calls `activateSnapshot`, or starts
  the background thread.** The only `ChainStateManager` instances are
  in unit tests. Once a snapshot is CLI-loaded, the node runs a
  single-chainstate model with no background re-validation of historical
  state — meaning even a fully-correct snapshot is never verified
  against historical block data. See BUG-2. (G2.)

- **HIGH-MISSING: No `getchainstates` RPC.** Core's `getchainstates`
  (`rpc/blockchain.cpp:3462`) lists every active chainstate (validated
  + snapshot, ordered by work) with per-chainstate `blocks`,
  `bestblockhash`, `bits`, `target`, `difficulty`,
  `verificationprogress`, `snapshot_blockhash` (when snapshot-based),
  `coins_db_cache_bytes`, `coins_tip_cache_bytes`, and `validated`
  (true if the chainstate is fully validated; false if snapshot is not
  yet validated). clearbit's RPC dispatch (`rpc.zig:3074-3079`) has
  arms for `loadtxoutset` and `dumptxoutset` but **zero references to
  `getchainstates`** (verified by grep). Operators monitoring snapshot
  validation progress have no Core-equivalent API. Cross-impl test
  suites that probe `getchainstates` will see a `Method not found`
  response. See BUG-3. (G3.)

- **HIGH-MISSING: No `base_blockhash` persistence file (Core's
  `SNAPSHOT_BLOCKHASH_FILENAME`).** Core writes the snapshot base
  blockhash to a file named `base_blockhash` inside the snapshot
  chainstate directory (`node/utxo_snapshot.cpp:22-46`,
  `WriteSnapshotBaseBlockhash`) and reads it back on subsequent
  initializations (`ReadSnapshotBaseBlockhash`,
  `validation.cpp:4905` `LoadBlockIndexDB(snapshot_blockhash)`) to
  reconstruct the snapshot-based chainstate. clearbit has zero callers
  of `WriteSnapshotBaseBlockhash` / `ReadSnapshotBaseBlockhash` /
  `FindAssumeutxoChainstateDir` — those functions don't even exist in
  the Zig codebase. After a `--load-snapshot=<path>` CLI run, clearbit
  writes a `chain_tip` key + `utxo_count` key + a placeholder
  `block_index` entry, but on the next start there is no machinery to
  recognize this datadir as "snapshot-based, height N, not-yet-validated"
  — it just looks like a regular short chain. See BUG-4. (G4.)

- **HIGH-MISSING: No `_snapshot` chainstate-dir suffix / dual on-disk
  chainstates.** Core's `SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"`
  (`node/utxo_snapshot.h:128`) appends to the chainstate dir name so a
  snapshot-based chainstate lives in `<datadir>/chainstate_snapshot/`
  while the validated chainstate lives in `<datadir>/chainstate/`. This
  is what allows the two-chainstate design to share a datadir. clearbit
  has **zero references** to `_snapshot` as a path suffix (verified by
  grep); the CLI path writes to `<datadir>/chainstate/` directly, the
  same dir a non-snapshot start would use. An operator who runs
  `--load-snapshot` then realizes it was the wrong snapshot has no way
  to roll back without nuking the entire datadir. See BUG-5. (G5.)

- **HIGH-DIVERGE: No `InvalidateCoinsDBOnDisk` / rename-on-failure
  cleanup path.** Core's `MaybeValidateSnapshot` calls
  `InvalidateCoinsDBOnDisk` (`validation.cpp:6001`) when the
  background chainstate's `hash_serialized` doesn't match
  `m_assumeutxo_data`. This renames `chainstate_snapshot/` to
  `chainstate_snapshot_INVALIDATED/` so the next restart doesn't try to
  re-use the bad snapshot. clearbit has nothing equivalent — the
  `SnapshotError.BackgroundValidationFailed` path
  (`storage.zig:5348`) returns an error to the caller (which nobody
  catches in production) and *leaves the bad UTXO set on disk*. Next
  restart loads from the same RocksDB and the node operates on
  corrupted state until manual cleanup. See BUG-6. (G6.)

- **HIGH-DIVERGE: `loadtxoutset` RPC is fully gated; CLI is the only
  production loader.** `handleLoadTxOutSet` (`rpc.zig:8332-8352`)
  returns `RPC_INTERNAL_ERROR` *before any file I/O* with the message
  "loadtxoutset RPC is disabled in this build". Core uses
  `RPC_INTERNAL_ERROR` only when `ActivateSnapshot` returns a fatal
  error; the **method-disabled gate is non-Core**. Cross-impl test
  suites comparing JSON-RPC error codes will see a different shape than
  Core (Core would respond with the actual reason from
  `ActivateSnapshot`). The intent is documented in the RPC handler
  doc-comment, but it diverges from how Bitcoin Core handles a
  not-yet-wired path. See BUG-7. (G7.)

- **HIGH-MISSING: Per-coin height-vs-base-height guard absent in
  `storage.loadTxOutSet`.** Core's `PopulateAndValidateSnapshot` checks
  `coin.nHeight > base_height` and rejects with "Bad snapshot data
  after deserializing %d coins" (`validation.cpp:5811-5816`).
  `main.zig:1157-1160` (CLI streaming path) DOES this check, but
  `storage.zig:5780+` (`loadTxOutSet` in-memory path used by
  `validateAndLoadSnapshot` and the gated RPC) does **NOT**. A
  fuzzed-but-otherwise-valid snapshot with a per-coin `nHeight` above
  the snapshot tip would slip through `validateAndLoadSnapshot`'s
  whitelist + content-hash gate iff the attacker tuned the entire UTXO
  set to hash-match (cryptographically infeasible for mainnet 840k,
  but the missing check is a hardening gap regardless). See BUG-8. (G8.)

- **HIGH-MISSING: Per-coin `outpoint.n >= u32::max` guard absent.** Core
  rejects outpoints with `n >= std::numeric_limits<decltype(n)>::max()`
  to avoid integer wraparound in `coinstats.cpp:ApplyHash`
  (`validation.cpp:5812-5816`). `main.zig:1145` checks `vout_u64 >=
  std::math.maxInt(u32)` (correct), but the storage-level
  `readSnapshotCoinPayload` (`storage.zig:5184`) and `loadTxOutSet`
  do the same check via `readSnapshotCoinPayload`. **However** the
  in-memory `loadTxOutSet` never enforces the `< u32::max` upper bound
  (it uses `@intCast` which would trap), so the guard is by accident,
  not by design. The behaviour-vs-Core diverges in the failure mode
  (Core throws ios_base::failure; clearbit traps in
  `@intCast` and panics). See BUG-9. (G9.)

- **HIGH-MISSING: No `ResizeCoinsCaches` / `IBD_CACHE_PERC=0.01` /
  `SNAPSHOT_CACHE_PERC=0.99` cache-bias on activation.** Core
  `ActivateSnapshot` (`validation.cpp:5638-5677`) reallocates the
  coins-tip + coins-db caches to give 99% to the snapshot chainstate
  during bulk load, then `MaybeRebalanceCaches` rebalances after.
  clearbit has zero references to `ResizeCoinsCaches`,
  `MaybeRebalanceCaches`, `IBD_CACHE_PERC`, `SNAPSHOT_CACHE_PERC` — its
  `UtxoSet` has a single `max_cache_mb` configured at `init` and no
  resize API. On a 16 GB cache target, clearbit's CLI snapshot import
  is bottlenecked by the default cache size (no bulk-load boost). See
  BUG-10. (G10.)

- **HIGH-MISSING: No `CoinsCacheSizeState::CRITICAL` mid-load flush.**
  Core's `PopulateAndValidateSnapshot` checks every 120k coins whether
  `GetCoinsCacheSizeState() >= CRITICAL` and calls `FlushSnapshotToDisk`
  if so (`validation.cpp:5844-5856`). clearbit's
  `loadSnapshotFromFile` (`main.zig:1219-1228`) does a fixed
  `BATCH_SIZE=100_000` flush regardless of cache state. The Core design
  optimizes for memory pressure (flush when near limit) rather than a
  fixed count; clearbit's fixed-count design wastes I/O on small
  snapshots and risks OOM on large ones with low per-coin allocator
  overhead. See BUG-11. (G11.)

- **HIGH-MISSING: No `interrupt` / `StopHashingException` /
  `SnapshotUTXOHashBreakpoint` hook in coin-load loop.** Core's loop
  every 120k coins calls `m_interrupt` to allow user-triggered abort
  (`validation.cpp:5841`). clearbit's CLI loop has no interrupt check;
  the loop runs to completion or `std.process.exit(1)` on read error.
  An operator running `--load-snapshot=10gb-file.dat` who hits SIGINT
  partway through has no clean abort path; the process either
  hard-kills (leaves RocksDB in an undefined state) or runs to
  completion. See BUG-12. (G12.)

- **HIGH-MISSING: `LoadBlockIndexDB(snapshot_blockhash)` analog
  missing.** Core's `LoadBlockIndexDB(snapshot_blockhash)`
  (`validation.cpp:4905`) takes the snapshot base blockhash on startup
  and reconstructs the dual-chainstate state from disk. clearbit has no
  such function — there's no plumbing on startup to detect "this
  datadir was loaded from a snapshot" because BUG-4 means the
  `base_blockhash` file doesn't exist. See BUG-13. (G13.)

- **MED-DIVERGE: `dumpTxOutSet` `coins_count` reflects in-memory cache
  size, NOT the persisted total.** Pinned by W102 G3
  (`storage.zig:10923`); the test documents the bug rather than fixes
  it. Core's `WriteUTXOSnapshot` writes
  `maybe_stats->coins_count` (the result of `GetUTXOStats` which walks
  the **disk** UTXO set) into the metadata header. clearbit's
  `dumpTxOutSet` writes `chainstate.utxo_set.cache.count()` (the
  in-memory HashMap size). For a node with a RocksDB backend where the
  cache holds only the recent-modify set, the dumped header lies about
  the coin count. The actual coin loop below reads from `cache.iterator()`
  so the *body* of the dump matches the header (under-count), but it's
  not a real snapshot of the chain state. See BUG-14. (G14.)

- **MED-DIVERGE: `completeValidation` uses the legacy
  `computeUtxoSetHash` (VARINT/compressed encoding), NOT the Core-strict
  `computeHashSerializedTxOutSet`.** Pinned by W102 G15
  (`storage.zig:11031`). The two functions hash *different layouts* of
  the same UTXO set; if the snapshot and the background chainstate
  produce different bit-level Coin representations
  (e.g. one stores raw scripts, the other compressed),
  `completeValidation` could pass on identical-but-differently-encoded
  state. More importantly, the function doesn't compare against
  `assume_entry.hash_serialized` at all — it only compares the active
  vs background chainstate to each other. A corrupt-but-self-consistent
  pair would pass. See BUG-15. (G15.)

- **MED-DIVERGE: `completeValidation` never compares against
  `assume_entry.hash_serialized` from chainparams.** Pinned by W102
  G15 (`storage.zig:11074`). Core's `MaybeValidateSnapshot` compares
  `validated_cs_stats->hashSerialized` against
  `au_data.hash_serialized` (`validation.cpp:5994-5999`). clearbit's
  `completeValidation` only checks that active and background
  chainstates *agree with each other*. Two corrupt-identical
  chainstates pass; the **chainparams-pinned value is never
  consulted**. See BUG-16. (G16.)

- **MED-MISSING: testnet3 / testnet4 / signet `assume_utxo` tables are
  empty.** Pinned by W102 G26/G27. Bitcoin Core ships:
    - testnet3: 2 entries (h=2_500_000 + h=4_840_000)
    - testnet4: 2 entries (h=90_000 + h=120_000)
    - signet: 2 entries (h=160_000 + h=290_000)
  clearbit's `TESTNET3.assume_utxo` / `TESTNET4.assume_utxo` /
  `SIGNET.assume_utxo` are all `&[_]AssumeUtxoData{}` (empty slices).
  Snapshot loads for these networks always fail with `UnknownSnapshot`.
  See BUG-17. (G17.)

- **MED-MISSING: `BLOCK_OPT_WITNESS` flag-set during snapshot
  population is absent.** Core's `PopulateAndValidateSnapshot` walks
  `AFTER_GENESIS_START..snapshot_chain.Height()` and sets
  `BLOCK_OPT_WITNESS` on each block-index entry where SegWit is active
  (`validation.cpp:5928-5934`) so `Chainstate::NeedsRedownload()`
  doesn't ask for `-reindex` on next start. clearbit's CLI snapshot
  import (`main.zig:1259+`) writes a single block-index entry for the
  snapshot tip with `block_index_buf = [_]u8{0} ** 84` (zero status
  bits, including no `BLOCK_OPT_WITNESS`). On next start, validation
  may flag the block as needing redownload. See BUG-18. (G18.)

- **MED-DIVERGE: Block-index header bytes are not populated during CLI
  snapshot import (placeholder zeros only).** `main.zig:1262-1266`
  writes `block_index_buf = [_]u8{0} ** 84` with only the height bytes
  set; bytes 4..84 (header + status + chain_work + sequence_id +
  file_number + file_offset) are all zero. This means the block-index
  record at the snapshot tip has *no header data*, so RPC
  `getblockheader` against the snapshot block returns garbage until
  headers are fetched from peers. Comment at `main.zig:1259` says
  "Header bytes are not in the snapshot (Core reconstructs them from
  the sibling block index); we write a placeholder that will be
  overwritten once headers are fetched" — but the *block index* should
  exist *before* the snapshot is loaded (Core requires it; otherwise
  `ActivateSnapshot` rejects with "The base block header must appear in
  the headers chain"). The CLI ordering is inverted vs Core. See BUG-19.
  (G19.)

- **MED-MISSING: No `m_best_header` ancestor check during snapshot
  activation.** Core's `ActivateSnapshot` checks
  `m_best_header->GetAncestor(snapshot_start_block->nHeight) ==
  snapshot_start_block` (`validation.cpp:5622-5624`) to ensure the
  snapshot block is on the best-headers chain. clearbit's
  `ChainStateManager.activateSnapshot` only checks `active_role ==
  .snapshot` (the double-activation guard). It does **not** verify
  that the snapshot's base hash is in the best-headers chain, an
  invariant Core relies on to prevent activating a snapshot that forks
  from a less-work header chain. See BUG-20. (G20.)

- **MED-MISSING: No "snapshot work > active tip work" final check.**
  Core's `ActivateSnapshot` does a final
  `CBlockIndexWorkComparator()(ActiveTip(),
  snapshot_chainstate->m_chain.Tip())` (`validation.cpp:5706-5708`)
  to refuse a snapshot loaded later in IBD whose tip has less work
  than the live chain. clearbit's `ChainStateManager.activateSnapshot`
  takes any snapshot regardless of relative work. See BUG-21. (G21.)

- **MED-DIVERGE: Mempool-empty precondition not enforced on snapshot
  activation.** Core's `ActivateSnapshot` checks `mempool &&
  mempool->size() > 0` and refuses with "Can't activate a snapshot when
  mempool not empty" (`validation.cpp:5626-5628`). clearbit's
  `activateSnapshot` doesn't reference the mempool at all. If a future
  caller wires `loadtxoutset` to `activateSnapshot`, an operator with
  pending transactions would silently lose them on snapshot activation.
  See BUG-22. (G22.)

- **MED-MISSING: No `RemoveLocalServices(NODE_NETWORK)` /
  `AddLocalServices(NODE_NETWORK_LIMITED)` after snapshot load.** Core's
  `loadtxoutset` RPC handler (`rpc/blockchain.cpp:3434-3437`) updates
  local-services flags so peers know the node can only serve recent
  blocks (since historical blocks are unavailable on a snapshot-based
  chainstate). clearbit's `--load-snapshot` CLI path never touches
  `local_services`; the node advertises full `NODE_NETWORK` even
  though it can't serve blocks below the snapshot tip. See BUG-23. (G23.)

- **MED-DIVERGE: `SnapshotMetadata.network_magic` serializes as
  little-endian u32; Core serializes as 4-byte `MessageStartChars`
  array.** `storage.zig:5084`:
  ```zig
  writer.writeInt(u32, self.network_magic) catch ...
  ```
  Core writes the magic via `MessageStartChars` which is a 4-byte
  array (`f9 be b4 d9` for mainnet, in the order
  `pchMessageStart[0..4]`). Zig's `writeInt(u32, ..., .little)` would
  write `f9 be b4 d9` for `0xD9B4BEF9` which **happens to match** —
  because the magic numbers are stored as little-endian u32 such that
  the byte sequence comes out the same. This works for mainnet, testnet,
  signet, and regtest, but it's coincidence, not parity: a future
  network that didn't have its `pchMessageStart` chosen with
  little-endian u32 in mind would break. See BUG-24. (G24.)

- **LOW-DIVERGE: `dumptxoutset` rollback aborts iff CF_BLOCKS body is
  missing for any block on the disconnect path.** `rpc.zig:8712-8721`
  bails with "rollback aborted: CF_BLOCKS missing body" if any block on
  the [target+1 .. tip] interval lacks its body. Core's `dumptxoutset
  rollback` uses `TemporaryRollback` which invokes `InvalidateBlock`
  + `ReconsiderBlock` (no body-reload requirement). clearbit's design
  is *safer* but diverges in error shape and what's possible. On a
  pruned datadir this is the only acceptable behaviour; clearbit notes
  it doesn't implement pruning today (Cat C audit). On a fresh-IBD
  datadir where bodies were stored from the network, this gate fires
  unexpectedly. See BUG-25. (G25.)

- **LOW-DIVERGE: `dumptxoutset rollback` rejects if the IBD fast-path
  was used.** `rpc.zig:8722-8738` bails if `undo_manager.readUndoData`
  fails or returns null. The IBD fast-path skips `connectBlockWithUndo`,
  so undo files are not produced. After IBD completes, the operator
  cannot dump a rollback snapshot until a few non-IBD blocks have been
  connected with undo data. Core does not have this restriction (it
  loads bodies, computes undo on the fly). See BUG-26. (G26.)

- **LOW-MISSING: `dumptxoutset rollback` does not suspend P2P /
  `NetworkDisable`.** Core's `dumptxoutset rollback` invokes
  `NetworkDisable` (`rpc/blockchain.cpp:3187-3193`) to prevent peer-
  delivered blocks from racing the rollback. clearbit takes a different
  approach — it holds `chain_state.connect_mutex` for the duration of
  the dance (`rpc.zig:8746-8747`) — which is *equivalent in safety*
  (peer.zig's drainBlockBuffer also goes through this mutex) but
  diverges from Core's design choice. Documented in the RPC doc-comment
  but listed here for completeness. See BUG-27. (G27.)

- **LOW-DIVERGE: `SnapshotError.AlreadyActivated` is thread-safe but
  not fatal-mode-safe.** `ChainStateManager.activateSnapshot` returns
  a recoverable error; Core terminates the node with a fatal error if
  a second activation is attempted on a misbehaving caller path. Less
  critical because the activation path is gated, but the design choice
  diverges. See BUG-28. (G28.)

- **LOW-MISSING: `chainstate.m_target_blockhash` /
  `chainstate.m_target_utxohash` / `ReachedTarget()` not modeled.** Core's
  `Chainstate` has `m_target_blockhash` (set during snapshot load) and
  `m_target_utxohash` (set after validation), plus a `ReachedTarget()`
  predicate driving `MaybeValidateSnapshot`. clearbit's `ChainState`
  has no equivalent fields. Without `m_target_blockhash`, the
  background chainstate has no signal for when to stop and validate.
  This is upstream of BUG-2 (no background thread is wired) but is a
  distinct missing data model. See BUG-29. (G29.)

- **LOW-DIVERGE: `dumpTxOutSet` flushes via `file.sync()` then `rename`;
  Core uses `fclose` then `fs::rename`.** clearbit's `dumpTxOutSet` is
  more durable than Core (an explicit `fsync` before rename). Doc-
  comment notes this as a "durability barrier". Listed under DIVERGE
  for completeness; this is a *stricter* implementation than Core's. See
  BUG-30. (G30.)

## 30-gate audit matrix

| # | Gate | Subject | Status | Bug |
|---|------|---------|--------|-----|
| G1 | CLI `--load-snapshot` enforces `hash_serialized` content-hash gate | Validation | MISSING | BUG-1 |
| G2 | Production code constructs a `ChainStateManager` + calls `activateSnapshot` | Lifecycle | MISSING | BUG-2 |
| G3 | `getchainstates` RPC implemented | RPC parity | MISSING | BUG-3 |
| G4 | `base_blockhash` persistence file (Core's `SNAPSHOT_BLOCKHASH_FILENAME`) | Persistence | MISSING | BUG-4 |
| G5 | `_snapshot` chainstate-dir suffix / dual on-disk chainstates | Persistence | MISSING | BUG-5 |
| G6 | `InvalidateCoinsDBOnDisk` rename-on-failure cleanup path | Recovery | MISSING | BUG-6 |
| G7 | `loadtxoutset` RPC reaches Core's `ActivateSnapshot` (or returns equivalent) | RPC parity | DIVERGE | BUG-7 |
| G8 | `storage.loadTxOutSet` checks `coin.nHeight > base_height` | Validation | MISSING | BUG-8 |
| G9 | Per-coin `outpoint.n >= u32::max` returns clean error, not `@intCast` panic | Validation | DIVERGE | BUG-9 |
| G10 | `ResizeCoinsCaches` / `IBD_CACHE_PERC=0.01` / `SNAPSHOT_CACHE_PERC=0.99` on activation | Performance | MISSING | BUG-10 |
| G11 | `CoinsCacheSizeState::CRITICAL` mid-load flush | Performance | MISSING | BUG-11 |
| G12 | `m_interrupt` / SIGINT-safe abort in coin-load loop | Operator | MISSING | BUG-12 |
| G13 | `LoadBlockIndexDB(snapshot_blockhash)` analog on startup | Persistence | MISSING | BUG-13 |
| G14 | `dumpTxOutSet` `coins_count` reflects persisted total, not cache size | Wire format | DIVERGE | BUG-14 |
| G15 | `completeValidation` uses `computeHashSerializedTxOutSet`, not legacy hash | Validation | DIVERGE | BUG-15 |
| G16 | `completeValidation` compares against `assume_entry.hash_serialized` | Validation | DIVERGE | BUG-16 |
| G17 | testnet3 / testnet4 / signet `assume_utxo` tables populated | Chainparams | MISSING | BUG-17 |
| G18 | `BLOCK_OPT_WITNESS` set on snapshot block during population | Block index | MISSING | BUG-18 |
| G19 | Block-index header bytes are populated during CLI snapshot import | Block index | DIVERGE | BUG-19 |
| G20 | `activateSnapshot` checks `m_best_header->GetAncestor(...) == snapshot_start_block` | Validation | MISSING | BUG-20 |
| G21 | `activateSnapshot` does final `work_active < work_snapshot` check | Validation | MISSING | BUG-21 |
| G22 | `activateSnapshot` refuses if mempool not empty | Lifecycle | MISSING | BUG-22 |
| G23 | After snapshot load, `RemoveLocalServices(NODE_NETWORK)` / `AddLocalServices(NODE_NETWORK_LIMITED)` | P2P | MISSING | BUG-23 |
| G24 | `SnapshotMetadata.network_magic` serialized as `MessageStartChars` byte array (not LE u32) | Wire format | DIVERGE | BUG-24 |
| G25 | `dumptxoutset rollback` succeeds on pruned datadir | Pruning | DIVERGE | BUG-25 |
| G26 | `dumptxoutset rollback` succeeds after IBD fast-path (no rev*.dat) | Rollback | DIVERGE | BUG-26 |
| G27 | `dumptxoutset rollback` uses `NetworkDisable` (or equivalent that doesn't gate other RPCs) | Concurrency | DIVERGE | BUG-27 |
| G28 | `ChainStateManager.activateSnapshot` is fatal-mode-safe (or doc-comment matches Core) | Lifecycle | DIVERGE | BUG-28 |
| G29 | `ChainState` has `m_target_blockhash` / `m_target_utxohash` / `ReachedTarget` | Data model | MISSING | BUG-29 |
| G30 | `dumpTxOutSet` writes via `tmp + sync + rename` atomic protocol | Wire format | DIVERGE | BUG-30 |

## Bug catalogue (30 BUGs total — 19 MISSING + 11 DIVERGE)

### BUG-1 (G1, HIGH-DIVERGE): CLI `--load-snapshot` skips the `hash_serialized` content-hash gate
**Severity:** HIGH-DIVERGE. `loadSnapshotFromFile`
(`main.zig:1025-1277`) is the **only operational** snapshot loader
today (RPC `loadtxoutset` is gated; `validateAndLoadSnapshot` is only
used by unit tests). The CLI path validates:
1. Magic bytes match `SNAPSHOT_MAGIC_BYTES`.
2. Version == 2.
3. Network magic matches `network_params.magic`.
4. `base_blockhash` is whitelisted by `findAssumeUtxoEntry`.
5. Per-coin `nHeight > block_height` rejected.
6. Per-coin `isValidMoney(amount)` enforced.

It does **NOT** compute the `hash_serialized` (SHA256d via HashWriter)
of the loaded UTXOs and compare against `assume_entry.hash_serialized`.
The in-memory `validateAndLoadSnapshot` does
(`storage.zig:6002-6011`) — but it's not the CLI's caller.

Impact: a file with a valid header (correct magic + version + network +
whitelisted base_blockhash) but garbage coin contents is silently
accepted. An attacker who can write the snapshot file to disk can
construct one with the canonical 840k mainnet `base_blockhash` and an
arbitrary UTXO set; clearbit will populate RocksDB with the attacker's
coins, pin the tip to height 840000, and start serving wrong UTXO
answers. Bitcoin Core's "AssumeUTXO is trust-on-first-use" claim relies
on the `hash_serialized` gate to make the trust automatic; without it,
clearbit's `--load-snapshot` is trust-the-filesystem.

**Fix:** in `loadSnapshotFromFile`, after the final batch flush,
compute `hash_serialized` over the freshly-imported coins (walk RocksDB
CF_UTXO in canonical key order via `computeHashSerializedTxOutSet`-
equivalent) and compare against `assume_entry.hash_serialized`. Reject
with a `FATAL: Snapshot content hash mismatch: expected X, got Y` and
delete the chainstate dir if mismatch. The W102 G4 test exists for the
RPC path; this wave should extend it to the CLI path.

### BUG-2 (G2, HIGH-MISSING): No two-chainstate / background chainstate / snapshot validation lifecycle
**Severity:** HIGH-MISSING. `ChainStateManager` (`storage.zig:5207-5383`)
defines:
- `active_chainstate`, `background_chainstate`
- `active_role` (`.normal | .snapshot | .background`)
- `snapshot_base_blockhash`
- `network_params`, `allocator`
- `background_thread`, `stop_background`, `mutex`
- methods: `init`, `deinit`, `activateSnapshot`,
  `startBackgroundValidation`, `stopBackgroundValidation`,
  `isBackgroundValidationComplete`, `completeValidation`,
  `activeChainstate`, `isAssumeUtxoMode`,
  `backgroundValidationThread`

But:
- `ChainStateManager.init` is never called in production code; only in
  unit tests (`storage.zig:10415, 10433, 10900, 10973, 11051,
  11096`).
- `main.zig` runs the daemon (`runDaemon`) with a single
  `ChainState`; no `ChainStateManager` is constructed.
- `loadSnapshotFromFile` writes the snapshot into the single
  chainstate's RocksDB directly; no second chainstate is created for
  background validation.

Impact: clearbit can load a snapshot but can never *validate* it.
The whole assumeUTXO trust model is "we trust the chainparams-pinned
hash now, and re-validate in the background"; clearbit performs the
first step (whitelist + hash check on the in-memory path) but not the
second.

**Fix:** wire `ChainStateManager` into `runDaemon`. When
`--load-snapshot` is used, also construct a background chainstate
in `<datadir>/chainstate/` (the snapshot goes to
`<datadir>/chainstate_snapshot/` per BUG-5), start the background sync
thread, and on background-tip-reaches-snapshot-base run
`completeValidation` (after BUG-15/BUG-16 are fixed).

### BUG-3 (G3, HIGH-MISSING): No `getchainstates` RPC
**Severity:** HIGH-MISSING. Core's `getchainstates`
(`rpc/blockchain.cpp:3462-3503`) returns:
```json
{
  "headers": <int>,
  "chainstates": [
    {"blocks": ..., "bestblockhash": ..., "bits": ..., "target": ...,
     "difficulty": ..., "verificationprogress": ...,
     "snapshot_blockhash": "<hash if snapshot-based>",
     "coins_db_cache_bytes": ..., "coins_tip_cache_bytes": ...,
     "validated": <bool>},
    ...
  ]
}
```

clearbit's RPC dispatch (`rpc.zig:3074-3079`) only has arms for
`loadtxoutset` and `dumptxoutset`. Grep confirms **zero** references
to `getchainstates` anywhere. Any cross-impl test suite probing
`getchainstates` will get a `Method not found` (-32601) response.

**Fix:** add a `handleGetChainStates` arm to the dispatch; the
response can be a single-element `chainstates` array (clearbit has no
background chainstate yet — BUG-2) with `validated: true` always
(unless BUG-2 lands).

### BUG-4 (G4, HIGH-MISSING): No `base_blockhash` persistence file
**Severity:** HIGH-MISSING. Core writes
`SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"`
(`node/utxo_snapshot.h:113`) inside the snapshot chainstate directory
after activation:
```cpp
afile << *snapshot_chainstate.m_from_snapshot_blockhash;
```
and reads it back on startup via `ReadSnapshotBaseBlockhash`
(`utxo_snapshot.cpp:48-81`). This is what allows the snapshot-based
chainstate to be reconstructed across restarts.

clearbit has **zero** references to `WriteSnapshotBaseBlockhash`,
`ReadSnapshotBaseBlockhash`, or `SNAPSHOT_BLOCKHASH_FILENAME`. The CLI
import (`main.zig:1244-1257`) writes:
- `chain_tip` key (32-byte hash + 4-byte height) into CF_DEFAULT
- `utxo_count` key into CF_DEFAULT
- a placeholder `block_index` entry

None of these mark the chainstate as snapshot-based or store the
`base_blockhash` of the snapshot. On the next start, there is no signal
to clearbit that it's running on a snapshot-based chainstate; it just
sees a chain that started at the snapshot height.

**Fix:** define `SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"` (string
const), write `base_blockhash` to `<datadir>/chainstate_snapshot/base_blockhash`
after CLI import / RPC activation, read it back on `loadDataDir`.

### BUG-5 (G5, HIGH-MISSING): No `_snapshot` chainstate-dir suffix
**Severity:** HIGH-MISSING. Core's `SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"`
(`node/utxo_snapshot.h:128`) makes the snapshot chainstate dir
`<datadir>/chainstate_snapshot/` while the validated chainstate dir is
`<datadir>/chainstate/`. clearbit has no equivalent — the CLI path
writes the snapshot into `<datadir>/chainstate/` directly. This means:
1. You cannot have a snapshot and a background chainstate coexisting
   on disk (no dual datadir support).
2. There's no way to "unload" a snapshot — once you've imported into
   `chainstate/`, the only rollback is `rm -rf datadir`.
3. The `--load-snapshot` operation is destructive; if the snapshot is
   wrong, you've corrupted your only chainstate.

**Fix:** make the CLI path open
`<datadir>/<network>/chainstate_snapshot/` (creating it if missing),
write the snapshot there. On startup, prefer
`chainstate_snapshot/` over `chainstate/` for active operations
(equivalent to Core's `FindAssumeutxoChainstateDir`).

### BUG-6 (G6, HIGH-DIVERGE): No `InvalidateCoinsDBOnDisk` rename-on-failure cleanup
**Severity:** HIGH-DIVERGE. Core's `MaybeValidateSnapshot` calls
`InvalidateCoinsDBOnDisk` (`validation.cpp:6001`) which:
1. Sets `unvalidated_cs.m_assumeutxo = Assumeutxo::INVALID`
2. Renames `<datadir>/chainstate_snapshot/` to
   `<datadir>/chainstate_snapshot_INVALIDATED_<timestamp>/`
3. Triggers a fatal error to shut down the node

clearbit's `completeValidation` returns
`SnapshotError.BackgroundValidationFailed`
(`storage.zig:5348`) which propagates back to whoever calls
`completeValidation`. Since BUG-2 means `completeValidation` is never
called in production, the cleanup path is dead code. But even if BUG-2
were fixed, the error path doesn't rename or cleanup — it just
returns. Next restart would re-load the same bad UTXO set and the same
validation failure would occur in a loop.

**Fix:** add an `invalidateCoinsDBOnDisk` method that renames the
snapshot chainstate dir and triggers a fatal-exit signal. Call it from
the `BackgroundValidationFailed` path in `completeValidation`.

### BUG-7 (G7, HIGH-DIVERGE): `loadtxoutset` RPC is fully gated
**Severity:** HIGH-DIVERGE. `handleLoadTxOutSet` (`rpc.zig:8332-8352`)
returns `RPC_INTERNAL_ERROR` with the message
"loadtxoutset RPC is disabled in this build because the live daemon
cannot atomically activate a UTXO snapshot once the header-sync and
block-download components have started. Use the CLI flag
--load-snapshot=<path> at startup instead". Core's
`loadtxoutset` handler does the actual snapshot activation
(`rpc/blockchain.cpp:3404-3445`). The gate is **non-Core** behaviour.

Note: this is intentional in clearbit (per the rustoshi 1d0a325 /
hotbuns e355cd7 pattern from 2026-05-05) because the live-daemon
swap is invasive, but it diverges from Core's behaviour shape. Cross-
impl test suites comparing JSON-RPC error codes will see a different
shape than Core.

**Fix:** either wire `ChainStateManager.activateSnapshot` to do the
actual swap (resolves BUG-2 + BUG-3 + BUG-4 + BUG-5 in one) or update
the error message + error code (`RPC_METHOD_NOT_FOUND` is closer to the
"not supported" semantic than `RPC_INTERNAL_ERROR`).

### BUG-8 (G8, HIGH-MISSING): Per-coin `nHeight > base_height` check absent in `storage.loadTxOutSet`
**Severity:** HIGH-MISSING. Core's `PopulateAndValidateSnapshot`
(`validation.cpp:5811-5816`) rejects:
```cpp
if (coin.nHeight > base_height || outpoint.n >= ...) {
    return util::Error{...};
}
```
`main.zig:1157-1160` (CLI streaming path) does:
```zig
if (utxo_height > block_height) {
    std.debug.print("\nFATAL: Coin height {d} > snapshot height {d}", ...);
    std.process.exit(1);
}
```
`storage.zig:5780-5790` (`loadTxOutSet` in-memory) does:
```zig
if (!consensus.isValidMoney(coin.value)) return StorageError.CorruptData;
// ... but no nHeight check
```
The two loaders disagree. A snapshot that the CLI rejects, the in-memory
loader would accept. Since the in-memory loader is what `validateAndLoadSnapshot`
uses (and `validateAndLoadSnapshot` is what the test suite + the
gated RPC stub call), the test suite has weaker coverage than the CLI.

**Fix:** add `if (coin.height > base_height) return StorageError.CorruptData`
to `loadTxOutSet` after `readSnapshotCoinPayload`. The check needs
`base_height`, which requires looking up `findAssumeUtxoEntry` *before*
the coin loop (currently done after).

### BUG-9 (G9, HIGH-DIVERGE): `vout` overflow handling diverges from Core (panic vs error)
**Severity:** HIGH-DIVERGE. Core's `PopulateAndValidateSnapshot` rejects
with `ios_base::failure` if `outpoint.n >= u32::max`
(`validation.cpp:5814`). clearbit's `readSnapshotCoinPayload`
(`storage.zig:5183-5185`):
```zig
const vout_u64 = try reader.readCompactSize();
if (vout_u64 >= std.math.maxInt(u32)) return StorageError.CorruptData;
const vout: u32 = @intCast(vout_u64);
```
This is correct *in `storage.zig`*. But the CLI path (`main.zig:1145`)
does:
```zig
if (vout_u64 >= std.math.maxInt(u32)) {
    std.debug.print("\nFATAL: vout overflow at coin {d}\n", ...);
    std.process.exit(1);
}
```
which is `>=` not `>`, leaving `vout == max-1` as the highest accepted
value. Core uses `>= max` too — they agree on the boundary — but the
panic-vs-error divergence is still a behavioural fork. Worse, neither
path uses Core's exact diagnostic ("Bad snapshot data after deserializing
%d coins"), so cross-impl error-string matchers diverge.

**Fix:** unify the failure mode between CLI and storage: return
`StorageError.CorruptData` with the Core-equivalent diagnostic.

### BUG-10 (G10, HIGH-MISSING): No cache-resize bias on snapshot activation
**Severity:** HIGH-MISSING. Core
(`validation.cpp:5638-5677`):
```cpp
static constexpr double IBD_CACHE_PERC = 0.01;
static constexpr double SNAPSHOT_CACHE_PERC = 0.99;
this->ActiveChainstate().ResizeCoinsCaches(
    static_cast<size_t>(current_coinstip_cache_size * IBD_CACHE_PERC),
    static_cast<size_t>(current_coinsdb_cache_size * IBD_CACHE_PERC));
snapshot_chainstate->InitCoinsDB(
    static_cast<size_t>(current_coinsdb_cache_size * SNAPSHOT_CACHE_PERC),
    in_memory, /*should_wipe=*/false);
```
clearbit has zero references to `IBD_CACHE_PERC`, `SNAPSHOT_CACHE_PERC`,
or `ResizeCoinsCaches`. The `UtxoSet.init` (`storage.zig:1915ish`)
takes `max_cache_mb` once at construction. No resize API exists.

Impact: on a 16 GB dbcache, Core gives ~15 GB to the snapshot chainstate
during bulk load (much higher write throughput); clearbit's import
runs against the configured cache size (which may be much less),
hitting frequent flushes during the multi-billion-coin mainnet import.

**Fix:** add `UtxoSet.resizeCache(new_max_mb)` method and call it
before / after the CLI snapshot import. (Or document that the CLI mode
ignores `--dbcache` and always uses a large cache.)

### BUG-11 (G11, HIGH-MISSING): No `CRITICAL` mid-load flush check
**Severity:** HIGH-MISSING. Core
(`validation.cpp:5847-5856`):
```cpp
if (coins_processed % 120000 == 0) {
    if (m_interrupt) { return util::Error{...}; }
    const auto snapshot_cache_state = ...
        snapshot_chainstate.GetCoinsCacheSizeState();
    if (snapshot_cache_state >= CoinsCacheSizeState::CRITICAL) {
        coins_cache.SetBestBlock(GetRandHash());
        FlushSnapshotToDisk(coins_cache, /*snapshot_loaded=*/false);
    }
}
```
clearbit (`main.zig:1219-1228`):
```zig
if (imported % BATCH_SIZE == 0 or coins_left == 0) {
    db.writeBatch(batch_ops.items) catch ...
}
```
Fixed `BATCH_SIZE = 100_000` regardless of cache pressure. Wastes I/O on
small datadirs (flushes every 100k even with plenty of cache); risks
OOM if per-coin allocator overhead is high (e.g. uncompressible
scripts).

**Fix:** add `UtxoSet.getCacheSizeState() -> .ok | .large | .critical`
method (or equivalent), check it at batch boundaries, and flush only
when `>= .critical`.

### BUG-12 (G12, HIGH-MISSING): No SIGINT-safe abort in coin-load loop
**Severity:** HIGH-MISSING. Core checks `m_interrupt`
(`validation.cpp:5841`) and returns a clean error. clearbit's CLI loop
(`main.zig:1125-1240`) has no interrupt check; the loop either runs to
completion or exits via `std.process.exit(1)` on a read/write error.
An operator running `--load-snapshot=10gb-file.dat` who hits SIGINT
partway through (an operator-error reaction, or an OOM-killer signal)
has no clean abort path:
- If the signal is SIGINT (default handler): immediate termination,
  leaves RocksDB in undefined state.
- If the signal is SIGTERM: same as SIGINT.
- If the process is wrapped by a supervisor that traps signals: still
  no inner-loop abort, the loop runs to completion or panics.

**Fix:** install a SIGINT/SIGTERM handler in `main.zig` that sets an
`std.atomic.Value(bool)` "interrupted" flag; check it at every
`BATCH_SIZE` boundary; on detection, flush what's been imported, mark
the chainstate as "partial" (BUG-5 dir suffix would help), and exit
cleanly.

### BUG-13 (G13, HIGH-MISSING): No `LoadBlockIndexDB(snapshot_blockhash)` analog
**Severity:** HIGH-MISSING. Core's `LoadBlockIndexDB(snapshot_blockhash)`
(`validation.cpp:4905`) takes the snapshot base blockhash on startup
and reconstructs the dual-chainstate state from disk:
1. Reads `base_blockhash` file (BUG-4) for the snapshot chainstate.
2. Reconstructs `m_from_snapshot_blockhash` on the chainstate.
3. Restores `m_assumeutxo = Assumeutxo::UNVALIDATED` on the snapshot
   chainstate.
4. Reconstructs the background chainstate (if `base_blockhash` exists
   but background hasn't reached the snapshot tip yet).

clearbit has nothing equivalent. After a `--load-snapshot` import,
the next `runDaemon` invocation just opens `<datadir>/chainstate/`
as a regular chainstate; there's no "this is snapshot-based" flag and
no background chainstate state to restore.

**Fix:** on `runDaemon` start, check for `<datadir>/chainstate_snapshot/base_blockhash`
(BUG-4 + BUG-5); if present, set the chainstate's `from_snapshot_blockhash`
field (which needs to be added to `ChainState` per BUG-29).

### BUG-14 (G14, MED-DIVERGE): `dumpTxOutSet.coins_count` is cache size, not persisted total
**Severity:** MED-DIVERGE (pinned by W102 G3, `storage.zig:10923`).
Already documented; listed here for completeness in the lifecycle audit.

**Fix:** call `chainstate.utxo_set.getTotalCount()` (which walks RocksDB)
instead of `chainstate.utxo_set.cache.count()`.

### BUG-15 (G15, MED-DIVERGE): `completeValidation` uses legacy hash function
**Severity:** MED-DIVERGE (pinned by W102 G15, `storage.zig:11031`).
Already documented.

**Fix:** swap `computeUtxoSetHash` for `computeHashSerializedTxOutSet`
in `completeValidation` (`storage.zig:5338-5339`).

### BUG-16 (G16, MED-DIVERGE): `completeValidation` doesn't compare against chainparams `hash_serialized`
**Severity:** MED-DIVERGE (pinned by W102 G15, `storage.zig:11074`).
Already documented.

**Fix:** in `completeValidation`, after computing the active /
background hashes, look up `findAssumeUtxoEntry(network_params,
snapshot_base_blockhash)` and compare the computed `hash_serialized`
against `assume_entry.hash_serialized` (not just active-vs-background).

### BUG-17 (G17, MED-MISSING): testnet3 / testnet4 / signet `assume_utxo` empty
**Severity:** MED-MISSING (pinned by W102 G26/G27,
`storage.zig:11156, 11168, 11177`). Bitcoin Core ships:
- testnet3: `(h=2_500_000, blockhash=0000000000000093bcb68c03..., hash_serialized=f841584909f68e47...)` + `(h=4_840_000, blockhash=00000000000000f4971a7fb3..., hash_serialized=ce6bb677bb2ee978...)`
- testnet4: `(h=90_000, blockhash=0000000002ebe8bcda020e0d..., hash_serialized=784fb5e98241de66...)` + `(h=120_000, blockhash=000000000bd2317e51b3c579..., hash_serialized=10b05d05ad468d09...)`
- signet: `(h=160_000, blockhash=0000003ca3c99aff040f2563..., hash_serialized=fe0a44309b74d6b5...)` + `(h=290_000, hash_serialized=97267e000b4b8768..., ...)`

clearbit's `TESTNET3.assume_utxo` / `TESTNET4.assume_utxo` /
`SIGNET.assume_utxo` are all empty (`consensus.zig:635, 689, 740`).

**Fix:** copy the entries verbatim from
`bitcoin-core/src/kernel/chainparams.cpp:271-284` (testnet3),
`:376-389` (testnet4), `:489-502` (signet).

### BUG-18 (G18, MED-MISSING): No `BLOCK_OPT_WITNESS` flag set during snapshot population
**Severity:** MED-MISSING. Core
(`validation.cpp:5928-5934`):
```cpp
for (int i = AFTER_GENESIS_START; i <= snapshot_chainstate.m_chain.Height(); ++i) {
    index = snapshot_chainstate.m_chain[i];
    if (DeploymentActiveAt(*index, *this, Consensus::DEPLOYMENT_SEGWIT)) {
        index->nStatus |= BLOCK_OPT_WITNESS;
    }
    m_blockman.m_dirty_blockindex.insert(index);
}
```
This walks every block from height 1 to snapshot height and sets
`BLOCK_OPT_WITNESS` on every block-index entry past the SegWit
activation height, so `Chainstate::NeedsRedownload()` doesn't ask for
`-reindex` on next start.

clearbit's CLI snapshot import (`main.zig:1259-1266`) writes a single
block-index entry for *only* the snapshot tip with all-zero status
bits — no per-block walk, no `BLOCK_OPT_WITNESS` flag, no
`m_dirty_blockindex` equivalent. On next start, if validation looks at
the snapshot block's status to decide whether SegWit applies, it sees
`status = 0` and may flag the block as needing redownload.

**Fix:** after CLI snapshot import, when the headers chain is
synced up to the snapshot block, walk back and set `BLOCK_OPT_WITNESS`
on every block past `network_params.segwit_height`.

### BUG-19 (G19, MED-DIVERGE): Block-index header bytes are placeholder zeros after CLI import
**Severity:** MED-DIVERGE. `main.zig:1262-1266`:
```zig
var block_index_buf: [84]u8 = [_]u8{0} ** 84;
std.mem.writeInt(u32, block_index_buf[0..4], block_height, .little);
db.put(storage.CF_BLOCK_INDEX, &metadata.base_blockhash, &block_index_buf) catch ...
```
Bytes 0..4 = height; bytes 4..84 = all zero. clearbit's block-index
record layout (per `storage.zig:300+`) is height(4) + header(80) +
status(4) + chain_work(32) + sequence_id(8) + file_number(4) +
file_offset(8). The CLI writes height + 80 zero bytes for the header
+ 0 for everything else.

Downstream:
- `getblockheader <snapshot_block_hash>` returns the zero-byte header
  (version=0, prev=zero, merkle=zero, timestamp=0, bits=0, nonce=0)
  until P2P headers-sync overwrites it.
- `chain_work` is zero, so `getblockchaininfo.chainwork` is wrong.
- `status & BLOCK_OPT_WITNESS == 0`, so BUG-18 compounds.

Core's design avoids this by requiring the **block header** to be in
the block index *before* `loadtxoutset` runs. clearbit's CLI flips the
ordering: snapshot first, headers later. The comment at `main.zig:1259`
acknowledges this — "a placeholder that will be overwritten once
headers are fetched" — but in the window between snapshot load and
headers sync, the node has corrupt block-index state.

**Fix:** either (a) require headers to be synced *before*
`--load-snapshot` can be used (matching Core's
`ActivateSnapshot:5611-5614` check that `LookupBlockIndex(base_blockhash)`
returns non-null), or (b) document the placeholder state and refuse
RPCs that depend on the header until headers arrive.

### BUG-20 (G20, MED-MISSING): No `m_best_header->GetAncestor` check on activation
**Severity:** MED-MISSING. Core's `ActivateSnapshot`
(`validation.cpp:5622-5624`):
```cpp
if (!m_best_header ||
    m_best_header->GetAncestor(snapshot_start_block->nHeight) != snapshot_start_block) {
    return util::Error{Untranslated("A forked headers-chain with more work than the chain with the snapshot base block header exists.")};
}
```
This ensures the snapshot block is on the current best-headers chain
(not a stale fork). clearbit's `ChainStateManager.activateSnapshot`
(`storage.zig:5263-5281`) only checks `active_role == .snapshot` (the
double-activation guard). Without the ancestor check, an operator
running `--load-snapshot` *after* a deep reorg could activate a
snapshot that no longer represents the canonical chain.

**Fix:** add a `best_header` field to `ChainStateManager` (or pass it
in to `activateSnapshot`), walk back from `best_header` to the
snapshot height, assert the hash matches.

### BUG-21 (G21, MED-MISSING): No "snapshot work > active tip work" final check
**Severity:** MED-MISSING. Core's `ActivateSnapshot`
(`validation.cpp:5706-5708`):
```cpp
if (!CBlockIndexWorkComparator()(ActiveTip(), snapshot_chainstate->m_chain.Tip())) {
    return cleanup_bad_snapshot(Untranslated("work does not exceed active chainstate"));
}
```
This refuses a snapshot loaded later in IBD whose tip has less work
than the live chain (it would be a step backwards). clearbit's
`ChainStateManager.activateSnapshot` takes any snapshot regardless of
relative work.

**Fix:** in `activateSnapshot`, after the double-activation guard,
compare the snapshot's chain work (which needs to be computed from
the snapshot's tip height via `chain_work_from_height`) against
the current `active_chainstate.chain_work`. Refuse if the snapshot has
less work.

### BUG-22 (G22, MED-DIVERGE): Mempool-empty precondition not enforced
**Severity:** MED-DIVERGE. Core's `ActivateSnapshot`
(`validation.cpp:5626-5628`):
```cpp
auto mempool{CurrentChainstate().GetMempool()};
if (mempool && mempool->size() > 0) {
    return util::Error{Untranslated("Can't activate a snapshot when mempool not empty")};
}
```
clearbit's `activateSnapshot` has zero references to the mempool. If
BUG-2 / BUG-7 are fixed and `loadtxoutset` becomes wired, an operator
with pending transactions would silently lose them on activation.

**Fix:** add a `mempool: ?*Mempool` field to `ChainStateManager`, check
`mempool.size() == 0` before activation.

### BUG-23 (G23, MED-MISSING): No `NODE_NETWORK_LIMITED` advertisement after snapshot
**Severity:** MED-MISSING. Core's `loadtxoutset` RPC handler
(`rpc/blockchain.cpp:3434-3437`):
```cpp
node.connman->RemoveLocalServices(NODE_NETWORK);
node.connman->AddLocalServices(NODE_NETWORK_LIMITED);
```
After snapshot load, the node can't serve historical blocks below the
snapshot tip, so it advertises `NODE_NETWORK_LIMITED` (last 288 blocks
only). clearbit's `--load-snapshot` CLI path never touches local
services; the node advertises full `NODE_NETWORK` even though it can't
serve blocks below the snapshot tip. Peers requesting old blocks will
disconnect after the timeout.

**Fix:** in `loadSnapshotFromFile`, after the import completes, also
write a "snapshot_loaded" flag that the P2P layer reads to set local
services. Or, simpler: have `--load-snapshot` always emit
`NODE_NETWORK_LIMITED` for the duration of the daemon's lifetime
(BUG-13 / BUG-4 needed for cross-restart).

### BUG-24 (G24, MED-DIVERGE): `network_magic` serialized as LE u32, Core uses `MessageStartChars` array
**Severity:** MED-DIVERGE. `storage.zig:5084`:
```zig
writer.writeInt(u32, self.network_magic) catch ...
```
Core writes it as `MessageStartChars` (an `std::array<uint8_t, 4>`):
```cpp
s << m_network_magic;
```
For little-endian platforms, `writeInt(u32, ..., .little)` produces the
same byte sequence as the array. clearbit's bytes happen to be correct
*because all current Bitcoin networks have their `pchMessageStart`
chosen such that the byte sequence is the LE-encoding of a u32*. A
hypothetical future network with a magic like `[0xFF, 0x00, 0x00, 0x00]`
would deserialize via Core as `magic == {0xFF, 0x00, 0x00, 0x00}` but
via clearbit as `magic = 0x000000FF` (LE u32) which, when re-serialized
with `writeInt(u32, ..., .little)`, comes back as the same bytes. So
it's accidental parity, not designed parity.

The bigger concern: future maintainers reading `network_magic: u32`
in `SnapshotMetadata` will think it's a numeric value, but on disk it's
4 raw bytes whose interpretation is "these specific bytes for this
specific network".

**Fix:** rename `network_magic: u32` to `network_magic: [4]u8`,
write/read as 4 raw bytes (which is what `MessageStartChars` is).

### BUG-25 (G25, LOW-DIVERGE): `dumptxoutset rollback` aborts on missing CF_BLOCKS body
**Severity:** LOW-DIVERGE. `rpc.zig:8711-8721` walks the disconnect
path and bails if any block lacks its body. Core uses
`TemporaryRollback` which doesn't have this constraint. clearbit's
design is safer on a pruned datadir (clearbit notes it doesn't
implement pruning today) but diverges in error shape on a fresh-IBD
datadir.

**Fix:** acceptable as-is, but the error message should reference
"--load-snapshot" or "wait until pruning is implemented" — currently
it just says "CF_BLOCKS missing body". Cross-impl test suites that
match on Core's error string will see a different message.

### BUG-26 (G26, LOW-DIVERGE): `dumptxoutset rollback` rejects on IBD-fast-path datadirs
**Severity:** LOW-DIVERGE. The IBD fast path (`peer.zig drainBlockBuffer`
→ `connectBlockFast` with `skip_undo=true`) doesn't write undo files.
After IBD completes, the operator cannot dump a rollback snapshot
until a few non-IBD blocks have been connected with undo data. Core
doesn't have this restriction.

**Fix:** make `connectBlockFast` optionally write undo data even
during IBD, or document the requirement in the RPC error.

### BUG-27 (G27, LOW-DIVERGE): `dumptxoutset rollback` uses `connect_mutex`, not `NetworkDisable`
**Severity:** LOW-DIVERGE. Documented in `handleDumpTxOutSet` doc-
comment as a design choice ("Equivalent to Core's NetworkDisable
guard but cheaper (no socket churn)"). The behaviour is functionally
equivalent but diverges from Core's approach.

**Fix:** no fix needed; document the design choice in the cross-impl
audit deck.

### BUG-28 (G28, LOW-DIVERGE): `AlreadyActivated` is recoverable, not fatal
**Severity:** LOW-DIVERGE. clearbit's `activateSnapshot` returns
`SnapshotError.AlreadyActivated` for the second activation
(`storage.zig:5272-5274`), per the W102 B2 FIX. Core treats a
double-activation as a fatal error (the comment at
`validation.cpp:5601` says "Can't activate a snapshot-based
chainstate more than once" but Core's actual behaviour is to surface
the error to the RPC caller, not fatal-error the node).

Actually re-reading Core: it's also recoverable (returns
`util::Error{...}` not `FatalError`). So clearbit is Core-parity.

**Fix:** no fix needed; recategorize as INFO if W102 didn't already.

### BUG-29 (G29, LOW-MISSING): No `m_target_blockhash` / `m_target_utxohash` / `ReachedTarget` on `ChainState`
**Severity:** LOW-MISSING. Core's `Chainstate` has:
- `m_from_snapshot_blockhash: std::optional<uint256>` — set when this
  chainstate was created from a snapshot
- `m_target_blockhash: std::optional<uint256>` — set on the background
  chainstate to the snapshot block hash; when the background reaches
  this, validation runs
- `m_target_utxohash: AssumeutxoHash` — set on the background after
  validation succeeds; signals "validated, can decommission"
- `ReachedTarget()` predicate

clearbit's `ChainState` (`storage.zig:1915+`) has no equivalent fields.
This is upstream of BUG-2 — there's no point in adding the fields
until the dual-chainstate is wired — but it's a distinct missing data
model and easy to add.

**Fix:** add `from_snapshot_blockhash: ?types.Hash256`,
`target_blockhash: ?types.Hash256`, `target_utxohash: ?types.Hash256`,
and a `reachedTarget()` method on `ChainState`.

### BUG-30 (G30, LOW-DIVERGE): `dumpTxOutSet` is more durable than Core (`fsync` before rename)
**Severity:** LOW-DIVERGE. clearbit's `dumpTxOutSet`
(`storage.zig:5704-5722`) does explicit `file.sync()` before rename.
Core does `fclose` (which may or may not sync depending on platform)
then `fs::rename`. clearbit's behaviour is **stricter** than Core's,
so this is not a bug per se but a divergence to flag.

**Fix:** no fix needed; document as INFO.

## Coverage / out-of-scope

- **In scope (audited):** the full assumeUTXO lifecycle from CLI/RPC
  entry through chain-state population, validation gating, and
  cross-restart persistence. The W102-pinned bugs are re-confirmed at
  the lifecycle level (BUG-14/15/16/17).
- **Out of scope (separate waves):** `gettxoutsetinfo`, `scantxoutset`,
  `verifychain` (audited in W133); MuHash3072 primitive correctness
  (covered by `tests` in `muhash.zig`); P2P-level handling of
  snapshot-based nodes (`NODE_NETWORK_LIMITED` advertisement is in
  scope as BUG-23, but the actual `version` message changes are out
  of scope); the `chainstate_blocks/` directory structure for
  block-files vs snapshot interaction.
- **Universal patterns observed:**
  - "Data model defined in source but never instantiated in
    production code" (`ChainStateManager`) — same shape as W120
    BUG-7 (validateRbfDiagram dead helper closed by FIX-79, and
    multiple other cross-impl audits).
  - "CLI path enforces invariant X but RPC/test path doesn't, or
    vice-versa" — BUG-1 / BUG-8 / BUG-9 are all variants. Same shape
    as W137 BUG-4 (Updater vs deserialize divergence on
    `non_witness_utxo` hash check).
  - "Chainparams whitelist arrays partially populated" — BUG-17 is
    the third occurrence (after W102 G26/G27 and W134's BIP-37 default
    set).
- **Test methodology:** Source-level greps for absence of Core-named
  symbols (`getchainstates`, `SNAPSHOT_BLOCKHASH_FILENAME`,
  `SNAPSHOT_CHAINSTATE_SUFFIX`, `ResizeCoinsCaches`,
  `MaybeRebalanceCaches`, `IBD_CACHE_PERC`, `NODE_NETWORK_LIMITED`
  in snapshot context, `InvalidateCoinsDBOnDisk`, `LoadBlockIndexDB`
  + snapshot, `BLOCK_OPT_WITNESS` in snapshot context,
  `m_target_blockhash`, `m_target_utxohash`, `ReachedTarget`,
  `m_best_header.GetAncestor`, `IBD_CACHE_PERC`, `SNAPSHOT_CACHE_PERC`,
  `CoinsCacheSizeState`, `m_interrupt`). Behavioral tests on the
  `dumpTxOutSet` / `loadTxOutSet` round-trip already exist in
  W102 (`storage.zig:10617+`) so this audit doesn't duplicate them.
  Each gate's BUG test asserts the **current (buggy) state** so a
  future fix wave flips the assertion by closing the gate.
