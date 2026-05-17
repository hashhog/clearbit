# W133 — Index databases (txindex + coinstatsindex) audit (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's optional-index subsystem vs Bitcoin Core
(`bitcoin-core/src/index/base.{h,cpp}`,
`bitcoin-core/src/index/txindex.{h,cpp}`,
`bitcoin-core/src/index/coinstatsindex.{h,cpp}`,
`bitcoin-core/src/index/disktxpos.h`,
`bitcoin-core/src/index/db_key.h`).
**Exclusion:** BIP-157/158 blockfilterindex is owned by W121 + W122; this
wave does NOT re-audit `BlockFilterIndex` in `src/indexes.zig:870` or
`prev_filter_header` / `CF_BLOCK_FILTER` wiring in `src/storage.zig`.
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w133` (folded into `zig build test`).
**Related prior waves:** the existing `Pattern C0` txindex work
(commits around 2026-05-05) plumbed `--txindex` from the CLI into
`ChainState.txindex_enabled` and got `connectBlockInner` to queue
`CF_TX_INDEX` writes. W133 audits the same code paths for **Core
semantic parity**, with particular attention to the wire format of the
indexed value (`CDiskTxPos` vs clearbit's 40-byte block-hash blob), the
`BaseIndex::Init` / `BlockLocator` semantics that govern restart
recovery, and the **entirely-unimplemented** `coinstatsindex` (CLI flag
parsed, struct exists in `src/indexes.zig`, but nothing in `storage.zig`
ever calls `CoinStatsIndex.connectBlock` and the column family is
literally out of range).

## Summary

clearbit ships a partial `txindex` and a non-wired `coinstatsindex`.
The txindex is functional for the happy-path
`getrawtransaction(<confirmed-txid>)` query when launched with
`--txindex`, but it diverges from Core in **wire-format**, **restart
semantics**, **disconnect ordering**, **prune-mode safety**,
**reindex-chainstate** support, and **`getindexinfo` RPC**. The
coinstatsindex is plumbed only in the CLI parser:

- **`CF_COINSTATS = storage.CF_COUNT = 8`** (`indexes.zig:41`).
  `CF_COUNT` is the count, not a valid CF index — any actual write
  through this constant would index past the end of the
  `cf_handles[CF_COUNT]` array in `storage_rocksdb.zig:41`. Today the
  array is never indexed because nothing calls `CoinStatsIndex.put`,
  but the moment a wire-up patch lands without bumping `CF_COUNT` it
  will UB-read past `cf_handles`. See BUG-7.
- **`config.coinstatsindex` is parsed but never read.** `main.zig:286`
  toggles `config.coinstatsindex = true` for `--coinstatsindex`, and
  `main.zig:709` for the conf-file knob, but no call site of
  `config.coinstatsindex` exists anywhere in the source tree
  (`grep -rn "config\.coinstatsindex"` returns 4 hits, all assignments
  or test asserts). The flag is a no-op, mirroring the pre-Pattern-C0
  state of `--txindex`. See BUG-8.
- **No MuHash, no per-block stats record, no `RevertBlock`.**
  `indexes.zig:770` has an in-memory `CoinStatsIndex` struct with
  `connectBlock` that updates `utxo_count`/`total_amount`/`bogo_size`,
  but it is never instantiated outside the unit tests in the same
  file. Core's `kernel::ApplyCoinHash` (MuHash3072 accumulator) is
  entirely absent from any coinstats wiring — clearbit *does* have a
  working `MuHash3072` (`muhash.zig`) used by
  `gettxoutsetinfo hash_type=muhash`, but it is recomputed from
  scratch per RPC call rather than maintained incrementally per block
  the way Core's `CoinStatsIndex` does. See BUG-9 + BUG-12 + BUG-13.
- **`CoinStatsIndex.connectBlock` bogo_size formula has the wrong
  outpoint width.** Core's `GetBogoSize` (`kernel/coinstats.cpp`)
  returns `32 + 4 + 1 + 8 + 2 + scriptPubKey.size()`
  (`bitcoin-core/src/kernel/coinstats.cpp` `GetBogoSize` for
  txid=32, vout=4, height/coinbase=1, value=8, scriptlen=2,
  scriptpubkey=N). clearbit's `getBogoSize` (`indexes.zig:796`)
  returns `32 + 4 + 8 + N` — missing the 1-byte coinbase/height tag
  AND the 2-byte script-length prefix. The constant difference of 3
  bytes per UTXO means `bogosize` reported via any future
  `getindexinfo` would be ~10 GiB low at mainnet tip
  (~80M UTXOs × 3 bytes ÷ 1024³). See BUG-11.
- **`CoinStatsIndex.connectBlock` ignores unspendables.** Core
  separates `total_unspendables_genesis_block`,
  `total_unspendables_bip30`, `total_unspendables_scripts`, and
  `total_unspendables_unclaimed_rewards` — these all roll into the
  invariant
  `total_amount + total_unspendables == total_subsidy + total_prevout_spent_amount - total_coinbase_amount - total_new_outputs_ex_coinbase_amount`.
  clearbit tracks neither field. The `total_subsidy` running sum is
  fine, but without unspendables tracking the consistency check in
  Core's `CustomAppend:182-188` (the "unclaimed rewards"
  arithmetic) cannot be performed. See BUG-10 + BUG-14 + BUG-15.
- **No reorg revert path.** `CoinStatsIndex` has no analog of Core's
  `RevertBlock` (`coinstatsindex.cpp:326`). A future wire-up would
  need to read the previous block's `DBVal`, undo the MuHash and
  rollback the running totals; clearbit's `disconnectBlockByHashCF`
  in `storage.zig` would have nothing to call. See BUG-16.

The txindex has different, narrower problems:

- **Wire format diverges from `CDiskTxPos`.** Core stores
  `(file_number, file_offset, tx_offset_in_block)` per txid
  (`disktxpos.h:11`, 16-bit varint values). clearbit stores
  `(block_hash, block_height, tx_index_in_block)` —
  `storage.zig:2207` `TXINDEX_VAL_LEN = 40`, fields are
  `[32-byte hash][LE u32 height][LE u32 tx-position]`. The clearbit
  layout is more expensive (32-byte block hash per tx instead of
  Core's 8-byte file-pos blob) and the position field is
  **transaction index within block** instead of **byte offset after
  the block header** — meaning clearbit must re-deserialise the
  whole block from `CF_BLOCKS` to answer a `FindTx` query, while
  Core can `lseek` straight to the tx. See BUG-1 + BUG-2.
- **`BaseIndex::Init` block-locator semantics absent.** Core's
  `BaseIndex::DB::ReadBestBlock` stores a `CBlockLocator` (32 hashes
  walking back from tip) so the index can recover from a partial
  reorg even if the index DB advanced ahead of the chainstate (the
  index reads the locator on startup, walks back to the fork point,
  and resumes). clearbit has no locator — the index trusts
  `chain_state.best_hash` / `chain_state.best_height` blindly.
  On an unclean shutdown mid-flush where the CF batch landed but the
  in-memory `best_hash` did not, the next start would re-index from
  the wrong height. See BUG-3 + BUG-4.
- **No `getindexinfo` RPC.** Core exposes `getindexinfo` which
  returns `{name, synced, best_block_height, best_block_hash}` per
  index (`rpc/blockchain.cpp` GetIndexInfo). clearbit has no analog;
  operators cannot query whether `--txindex` is synced. See BUG-19.
- **Sync is synchronous on the connect path, no background thread.**
  Core runs `BaseIndex::Sync` in `m_thread_sync` so the chain tip can
  advance independently of indexing. clearbit's `queueTxIndexWrites`
  is called inline inside `connectBlockInner` — fine for IBD
  throughput, but blocks the connect path when index DB writes are
  slow. Bigger issue: there is **no resume mechanism** if the index
  is enabled after a partial sync (`backfillBlockFilterIndex` is
  W121 / blockfilterindex-only; no `backfillTxIndex` equivalent
  exists). See BUG-5 + BUG-6.
- **`AllowPrune() = false` invariant not enforced.** Core's
  `TxIndex::AllowPrune()` returns `false`, which means
  `BaseIndex::SetBestBlockIndex` will assert if the chainstate is in
  prune mode and the index is txindex — Core explicitly rejects
  `-txindex` with `-prune` (`init.cpp` startup check). clearbit
  silently allows both flags together; `--txindex --prune=N` will
  IBD with the txindex going stale as `CF_BLOCKS` is pruned out from
  under it (`getrawtransaction` for the pruned-out blocks will fail
  with "Block decode failed" even though the txindex still has the
  txid entry). See BUG-17 + BUG-18.
- **Disconnect ordering races the active-chain index.** clearbit's
  `disconnectBlockByHashCF` queues `pending_tx_index_deletes`
  BEFORE the tip rewind in the same flush batch (good), but if a
  reorg disconnects N blocks then re-connects N' blocks at the same
  txid in the same batch, the new-chain put lands after the old-chain
  delete (correct, since the batch is array-ordered)
  EXCEPT when the txid appears in both blocks at *different*
  positions — both writes go through but the height/position blob
  differs. RocksDB resolves the put as last-write-wins, so this is
  actually correct, but the **`getrawtransaction` confirmations
  computation** in `rpc.zig:5891-5898` is decoupled: it walks the
  active height→hash index, which may not have been advanced yet if
  the rpc client hits the server mid-reorg. See BUG-20 + BUG-21.
- **No "old datadir" mitigation.** Core's `CoinStatsIndex`
  constructor (`coinstatsindex.cpp:96-101`) warns about
  `indexes/coinstats` from older versions; clearbit has no
  comparable migration logic for a future format change. Pre-emptive
  bug; matters if W133 leads to a v2 wire format. See BUG-22.

## 30-gate audit matrix

| # | Gate | Subject | Status | Bug |
|---|------|---------|--------|-----|
| G1 | TxIndex DB key prefix matches Core `DB_TXINDEX = 't'` | Wire format | DIVERGE | BUG-1 |
| G2 | TxIndex DB value is `CDiskTxPos` (file_num + nPos + nTxOffset) | Wire format | DIVERGE | BUG-2 |
| G3 | `BaseIndex::DB::ReadBestBlock` returns a `CBlockLocator` | Restart | MISSING | BUG-3 |
| G4 | `BaseIndex::Init` rewinds to fork point on locator mismatch | Restart | MISSING | BUG-4 |
| G5 | `BaseIndex::Sync` runs in a background thread | Threading | DIVERGE | BUG-5 |
| G6 | `BaseIndex::BlockUntilSyncedToCurrentChain` exists | Public API | MISSING | BUG-6 |
| G7 | `CF_COINSTATS` is a valid CF in the array | Storage | DIVERGE | BUG-7 |
| G8 | `--coinstatsindex` enables coin-stats wiring | CLI plumbing | MISSING | BUG-8 |
| G9 | `CoinStatsIndex` maintains a `MuHash3072` accumulator | Semantic | MISSING | BUG-9 |
| G10 | `CoinStatsIndex` tracks unspendables genesis / BIP30 / script / unclaimed | Semantic | MISSING | BUG-10 |
| G11 | `getBogoSize` formula matches Core | Wire | DIVERGE | BUG-11 |
| G12 | `CoinStatsIndex` writes per-block (height→DBVal) records | Storage | MISSING | BUG-12 |
| G13 | `CoinStatsIndex::LookUpStats` is exposed via `gettxoutsetinfo`/`gettxoutsetinfo` | RPC | MISSING | BUG-13 |
| G14 | `connect_undo_data` propagates spent-prevout amounts | Plumbing | MISSING | BUG-14 |
| G15 | `total_subsidy` / `total_coinbase_amount` / `total_new_outputs_ex_coinbase_amount` rollups | Semantic | MISSING | BUG-15 |
| G16 | `CoinStatsIndex::CustomRemove` reverts a block on reorg | Reorg | MISSING | BUG-16 |
| G17 | `-txindex` + `-prune` is rejected at startup | Operator safety | MISSING | BUG-17 |
| G18 | `AllowPrune() = false` invariant prevents tip > prune_height | Operator safety | MISSING | BUG-18 |
| G19 | `getindexinfo` RPC reports per-index sync status | RPC parity | MISSING | BUG-19 |
| G20 | `getrawtransaction` confirmations reflect reorg in-flight | Disconnect race | DIVERGE | BUG-20 |
| G21 | Reorg-loop putwins handles position-shifted txids | Reorg | DIVERGE | BUG-21 |
| G22 | Legacy `indexes/coinstats` datadir migration warning | Operator | MISSING | BUG-22 |
| G23 | TxIndex `FindTx` verifies `tx->GetHash() == tx_hash` | Integrity | DIVERGE | BUG-23 |
| G24 | TxIndex `FindTx` deserialises witness-included tx | Wire | PRESENT | — |
| G25 | TxIndex prefix `'t' + uint256` keys are big-endian for ordered scans | Storage | DIVERGE | BUG-25 |
| G26 | TxIndex genesis-skip (Core `block.height == 0` short-circuit) | Edge case | PRESENT | — |
| G27 | TxIndex disconnect deletes BEFORE writes in flush batch | Reorg | PRESENT | — |
| G28 | TxIndex flush is atomic with tip update | Storage | PRESENT | — |
| G29 | TxIndex `BLOCK_HAVE_UNDO` status bit OR'd into block index | Storage | PRESENT | — |
| G30 | `getindexinfo`-style summary on logging at startup | Operator | DIVERGE | BUG-30 |

## Bug catalogue (30 BUGs total — 22 MISSING + 8 DIVERGE)

### BUG-1 (G1, LOW-CDIV): TxIndex CF prefix not byte-equal to Core
**Severity:** LOW (clearbit uses dedicated `CF_TX_INDEX` column family,
so RocksDB key prefix byte is irrelevant). However the docstrings claim
Core parity. Core's key is `(0x74, uint256)` (`DB_TXINDEX = 't' = 0x74`,
`txindex.cpp:31`). clearbit's key is the raw `uint256` written to a
dedicated CF (`storage.zig:480`). If a future migration tries to merge
column families this drift would cause silent key collisions.
**Fix:** documentation; OR prepend `0x74` to the CF key.

### BUG-2 (G2, HIGH-CDIV): TxIndex value blob is 40 bytes of block-hash
instead of Core's `CDiskTxPos`
**Severity:** HIGH-CDIV (cross-impl drift). Core stores
`(file_num: VARINT, file_offset: VARINT, tx_offset_in_block: VARINT)`
— typically 4-6 bytes per entry depending on block file. clearbit stores
`[32-byte block hash][LE u32 height][LE u32 tx-position]` — 40 bytes,
fixed. Operational consequence:
1. clearbit's txindex DB is ~6.5× larger than Core's at mainnet tip
   (~900M txs × 40 bytes = 36 GiB vs Core's ~5.6 GiB);
2. `FindTx` must do a `CF_BLOCKS` lookup (block-hash → raw bytes) then
   `serialize.readBlock` then `block_data.transactions[entry.tx_index_in_block]`
   (`rpc.zig:5882`) — O(block_size) deserialisation per query. Core's
   `FindTx` does an `lseek` straight to `nTxOffset` (`txindex.cpp:108`).
**Fix:** define a `DiskTxPos` matching Core layout, populate
`pending_block_writes`-level `(file_number, file_offset)` and the
per-tx offset, switch `FindTx` to seek-and-deserialise-one-tx.

### BUG-3 (G3, MED): No block locator written to index DB
**Severity:** MED (correctness on unclean shutdown). Core writes a
`CBlockLocator` (32 ancestor hashes) at every index flush; clearbit
writes nothing. On a crash where the index batch landed but the tip
batch did not, restart logic in `main.zig` will trust the in-memory
`chain_state.best_hash` (loaded from `CF_DEFAULT` chain_tip), which may
predate the durable index state — meaning the next IBD round-trip will
re-write txids that are already in `CF_TX_INDEX`, harmless except for
wasted I/O and the inability to detect index-vs-chainstate
divergence at startup.
**Fix:** write a `(DB_BEST_BLOCK, locator)` entry alongside every
flush; read it on startup.

### BUG-4 (G4, MED): No fork-point rewind on index-vs-chainstate divergence
**Severity:** MED. Core's `BaseIndex::Init` (`base.cpp:124-133`) looks
up the locator's top block; if it's not on the best chain it rewinds
forward from the fork point. clearbit has nothing — if the chainstate
reorganises while the index DB is in any unsynchronised state
(e.g. the operator deleted the chainstate but kept the indexes dir),
no rewind happens and stale txindex entries silently persist.
**Fix:** on startup, walk the locator back until a hash matches the
current active chain; rewind from that point.

### BUG-5 (G5, LOW): No background sync thread
**Severity:** LOW (perf-only). Core runs `BaseIndex::Sync` in a
dedicated `m_thread_sync` so block connections aren't blocked on
LevelDB writes. clearbit does everything inline inside
`connectBlockInner`'s call to `queueTxIndexWritesForBlock`
(`storage.zig:4210`). The `BackgroundIndexer` struct exists at
`indexes.zig:958` but its `runIndexer` is a stub
(`indexes.zig:1011-1022` — comment "For now, just sleep").
**Fix:** wire `BackgroundIndexer.runIndexer` to drain a queue of
connected blocks against `TxIndex.indexBlock`; today the indexer
thread is started for no reason.

### BUG-6 (G6, MED): No `BlockUntilSyncedToCurrentChain` API
**Severity:** MED (RPC correctness). Core's
`getrawtransaction`/`scantxoutset`/`gettxoutsetinfo` callers call
`BaseIndex::BlockUntilSyncedToCurrentChain` to drain the
ValidationInterface queue before answering. clearbit has no such
sync point — an RPC client that just submitted a block and then asks
`getrawtransaction(<txid-in-block>)` can race the index write.
**Fix:** add a `chain_state.blockUntilTxIndexSynced()` that no-ops
when synchronous; meaningful only after BUG-5 is closed.

### BUG-7 (G7, HIGH): `CF_COINSTATS = storage.CF_COUNT` = out-of-range CF index
**Severity:** HIGH (latent UB). `indexes.zig:41` sets
`CF_COINSTATS: usize = storage.CF_COUNT` which equals 8. `CF_COUNT` is
the count of valid CFs (0..7), so 8 indexes past the end of
`storage_rocksdb.zig:41`'s `cf_handles: [CF_COUNT]?*…` array. Today
no code path actually calls `db.put(CF_COINSTATS, …)` (the
`CoinStatsIndex.connectBlock` body at `indexes.zig:846` is a unit-test
only since `CoinStatsIndex` is never instantiated against a real DB);
the moment a wire-up patch lands without bumping `CF_COUNT` to 9 it
will index past the array and trigger either an out-of-bounds panic
(debug) or read-past-end UB (ReleaseFast).
**Fix:** bump `CF_COUNT = 9`, add `CF_COINSTATS = 8` to
`storage.zig`, add it to `cf_names` in `storage_rocksdb.zig`.

### BUG-8 (G8, LOW): `--coinstatsindex` flag is parsed but never read
**Severity:** LOW (operator-confusion). `main.zig:286` parses the
flag into `config.coinstatsindex`. No code reads it. Mirrors the
pre-Pattern-C0 state of `--txindex`.
**Fix:** plumb `config.coinstatsindex` into a new
`chain_state.coinstatsindex_enabled` and wire the connect/disconnect
path; or emit a startup warning that the flag is a no-op.

### BUG-9 (G9, HIGH-CDIV): No MuHash3072 accumulator in `CoinStatsIndex`
**Severity:** HIGH-CDIV. Core's `CoinStatsIndex` maintains
`MuHash3072 m_muhash` (`coinstatsindex.h:36`) and calls
`kernel::ApplyCoinHash(m_muhash, outpoint, coin)` per
created-utxo and `kernel::RemoveCoinHash(...)` per spent-utxo
(`coinstatsindex.cpp:145, 166`). The result is exposed as
`hashSerialized` via `LookUpStats`, allowing clients to ask
"what is the UTXO-set MuHash at block <hash>?" without scanning the
whole set. clearbit's `gettxoutsetinfo hash_type=muhash`
(`rpc.zig:13123`) recomputes the MuHash from scratch on every call by
iterating `utxo_set.cache` — O(N) and only for the current tip.
**Fix:** maintain a `MuHash3072` field in `CoinStatsIndex`,
incremental-update per block.

### BUG-10 (G10, HIGH-CDIV): No unspendables tracking
**Severity:** HIGH-CDIV. Core tracks four unspendables sub-totals
(`coinstatsindex.h:43-46`):
1. `total_unspendables_genesis_block` — the satoshis in the genesis
   coinbase that are unspendable because of the bug in Bitcoin v0.1;
2. `total_unspendables_bip30` — duplicate-coinbase txns (BIP30
   pre-activation in blocks 91722, 91812, etc.);
3. `total_unspendables_scripts` — outputs whose `scriptPubKey` is
   `IsUnspendable` (OP_RETURN, or scripts starting with `OP_RETURN`);
4. `total_unspendables_unclaimed_rewards` — miners who did not claim
   the full block subsidy (regtest miner has been doing this
   forever; mainnet miners rarely).
clearbit tracks none of these.
**Fix:** add four `i64` fields to `CoinStatsIndex`, classify each
output's `scriptPubKey` on connect (`script.IsUnspendable`); compute
unclaimed rewards via the
`(prevout_spent + subsidy) - (new_outputs + coinbase + unspendables)`
invariant.

### BUG-11 (G11, LOW-CDIV): `getBogoSize` formula is short by 3 bytes
**Severity:** LOW-CDIV. Core's `GetBogoSize`
(`kernel/coinstats.cpp`) returns
`32 /* txid */ + 4 /* vout */ + 4 /* height + coinbase */ + 8 /* value */ + 2 /* CompactSize(script_len) */ + scriptPubKey.size()`.
clearbit (`indexes.zig:796-799`) returns
`32 + 4 + 8 + script_len` — missing the 4-byte height/coinbase
combo (Core packs them as a single u32) and the 2-byte
`CompactSize` overhead.
Wait — Core actually uses
`32 + 4 + 1 + 8 + scriptPubKey.size()` per the original
`coinstats.cpp` formulation (1 byte for the height-and-coinbase
packed tag). clearbit's `32 + 4 + 8` makes the
coinbase/height tag a 4-byte (`u32`) instead of 1-byte field.
Either way the constant is wrong, and the `bogosize` reported by
any future `gettxoutsetinfo` consumer will drift from Core's by
~3 bytes per UTXO.
**Fix:** mirror Core's formula exactly.

### BUG-12 (G12, HIGH-CDIV): No per-block height→DBVal records written
**Severity:** HIGH-CDIV. Core writes a height-indexed record per
block (`DB_BLOCK_HEIGHT`-prefixed key, see `db_key.h:30`) containing
the full `DBVal` (12 sub-totals + muhash). clearbit's
`CoinStatsIndex.connectBlock` writes a single 56-byte
`CoinStats.toBytes` blob (block_hash + height + utxo_count +
total_amount + total_subsidy + bogo_size) keyed by height
(`indexes.zig:843-846`). Half the Core fields are missing
(prevout_spent, new_outputs_ex_coinbase, coinbase_amount, four
unspendables, muhash).
**Fix:** mirror Core's `DBVal` struct; emit on every connect.

### BUG-13 (G13, MED): `LookUpStats` not exposed via RPC
**Severity:** MED. Core surfaces `CoinStatsIndex::LookUpStats` via
`gettxoutsetinfo(hash_type, hash_or_height)` — the second arg
queries an arbitrary historical block, not just the current tip.
clearbit's `handleGetTxOutSetInfo` (`rpc.zig:13064`) ignores any
second arg and only reports the current tip's UTXO set
(`rpc.zig:13094-13146`).
**Fix:** parse the optional second arg, look up the indexed entry
when `coinstatsindex_enabled`, return historical stats.

### BUG-14 (G14, HIGH-CDIV): No `connect_undo_data` propagation hook
**Severity:** HIGH-CDIV. Core's `CoinStatsIndex::CustomOptions` sets
`connect_undo_data = true` (`coinstatsindex.cpp:319`) and
`disconnect_data = true` / `disconnect_undo_data = true`, which
tells `BaseIndex::ProcessBlock` to call `ReadBlockUndo` and pass it
to `CustomAppend`. clearbit's `ChainState` already has
`pending_undo_writes` populated by `connectBlockFastWithUndo`, but
nothing propagates the undo data into a coinstatsindex hook.
**Fix:** add a `connect_undo_data`-style option enum that
`connectBlockInner` consults before reading undo from RocksDB; or
just always pass the undo data when coinstatsindex_enabled.

### BUG-15 (G15, HIGH-CDIV): No `total_subsidy` / `total_coinbase_amount` / `total_prevout_spent_amount` rollups
**Severity:** HIGH-CDIV. Same root cause as BUG-12. clearbit's
`CoinStatsIndex` has a single `total_subsidy` field
(`indexes.zig:778`) but no `total_coinbase_amount`,
`total_new_outputs_ex_coinbase_amount`, or
`total_prevout_spent_amount`. Core uses all of these to verify the
invariant that `m_total_unspendables_unclaimed_rewards` is non-
negative (`coinstatsindex.cpp:185-188`); without them clearbit
cannot reproduce the unclaimed-rewards arithmetic.
**Fix:** add the three running sums to `CoinStatsIndex`; update on
every connect/disconnect.

### BUG-16 (G16, HIGH-CDIV): No `CustomRemove` reorg path
**Severity:** HIGH-CDIV. Core's
`CoinStatsIndex::CustomRemove`/`RevertBlock`
(`coinstatsindex.cpp:216,326`) reads back the previous block's
`DBVal`, undoes the MuHash, and restores all 12 running sums.
clearbit has nothing — a reorg with `--coinstatsindex` enabled
(once it is wired) would leave the running totals permanently out
of sync.
**Fix:** add a `disconnectBlock`-time hook that reads the
height-1 record from disk and restores in-memory state.

### BUG-17 (G17, MED): `-txindex` + `-prune` not rejected at startup
**Severity:** MED (operator safety). Core's `init.cpp`
explicitly errors when both are set:
`"Prune mode is incompatible with -txindex."`. clearbit silently
accepts the combination — `main.zig:1770-1773` enables txindex,
`main.zig:1795-1801` enables pruning, no cross-flag validation.
The data path is silently broken: pruned blocks have their bodies
deleted from `CF_BLOCKS`, but the `CF_TX_INDEX` entries for txids
in those pruned blocks remain. `getrawtransaction(<pruned-txid>)`
will then succeed at the `getTxIndexEntry` step but fail at the
`db.get(CF_BLOCKS, &entry.block_hash)` step (`rpc.zig:5870`),
emitting `RPC_INTERNAL_ERROR "Block decode failed"` instead of
the expected `RPC_INVALID_ADDRESS_OR_KEY "No such mempool or
blockchain transaction"`.
**Fix:** add a startup assertion `if (config.txindex and
config.prune > 0) return error.IncompatibleFlags`; OR teach
`getrawtransaction` to fall back gracefully.

### BUG-18 (G18, LOW): `AllowPrune()` semantic absent
**Severity:** LOW. Core's `BaseIndex::SetBestBlockIndex`
(`base.cpp:487`) asserts `!IsPruneMode() || AllowPrune()`. The
prune-lock mechanism (`PruneLockInfo`) prevents the chainstate's
pruner from deleting blocks that the index hasn't caught up to yet.
clearbit has neither the `AllowPrune` flag nor a prune-lock; the
pruner (`storage.zig`) and the txindex run independently.
**Fix:** add a `txindex_min_height` field, refuse to prune below it.

### BUG-19 (G19, MED): No `getindexinfo` RPC
**Severity:** MED. Core's `getindexinfo` RPC reports
`{ <index_name>: { synced, best_block_height, best_block_hash } }`
for every enabled index. clearbit has no analog —
`rpc.zig:12997` lists `getrawtransaction` and a long table of RPCs
but `getindexinfo` is absent (`grep -n "getindexinfo" rpc.zig`
returns 0 hits).
**Fix:** add `handleGetIndexInfo` that reports
`txindex_enabled`/`coinstatsindex_enabled`/`blockfilterindex_enabled`
plus sync status (currently `synced == best_height == chain_tip`
because the index is inline).

### BUG-20 (G20, LOW-CDIV): `getrawtransaction` confirmations race a reorg
**Severity:** LOW-CDIV. `rpc.zig:5891-5898` computes confirmations
from `chain_state.getBlockHashByHeight(entry.block_height)`. If
the RPC server is mid-reorg (after the `pending_tx_index_deletes`
were appended but before the flush completes), the canonical hash
may still match the soon-to-be-orphaned entry. Core mitigates this
by holding `cs_main` for the lookup; clearbit does not lock
`chain_state` against the flush.
**Fix:** acquire `chain_state.connect_mutex` for the duration of
the `getTxIndexEntry` → `getBlockHashByHeight` → confirmation
computation.

### BUG-21 (G21, LOW): Reorg position-shifted txid in same flush
**Severity:** LOW. If a reorg disconnects N blocks then connects N'
blocks at the same txid (same txid, different position in the
block), both writes go through the array-ordered flush correctly
(delete-then-put = put wins). However, the `tx_index_in_block`
field will be the new position, which is correct. Listed as a
DIVERGE only because the **flush ordering** is implicit (relies on
RocksDB array order in WriteBatch); Core uses a leveldb WriteBatch
with identical semantics, so this matches Core, but the assumption
is undocumented in `storage.zig`.
**Fix:** documentation; OR explicit comment.

### BUG-22 (G22, LOW): No legacy datadir migration
**Severity:** LOW (pre-emptive). Core's `CoinStatsIndex`
constructor (`coinstatsindex.cpp:96-101`) warns about
`indexes/coinstats` (old) vs `indexes/coinstatsindex` (new).
clearbit has no naming convention yet; this only matters if W133
leads to a v2 wire format.
**Fix:** define `indexes/txindex/` and `indexes/coinstatsindex/`
subdirs; warn on `indexes/coinstats`.

### BUG-23 (G23, MED-CDIV): No `tx->GetHash() == tx_hash` integrity check in FindTx
**Severity:** MED-CDIV. Core's `FindTx` re-hashes the deserialised
transaction and compares to the queried txid as a corruption check
(`txindex.cpp:114-117`): if they differ it returns false (the index
DB is corrupt). clearbit's `getrawtransaction` handler
(`rpc.zig:5867-5938`) trusts `entry.tx_index_in_block` blindly and
deserialises `block_data.transactions[entry.tx_index_in_block]`
without re-hashing. A corrupted CF_TX_INDEX entry (or a stale
entry pointing to a now-reused block hash at a different tx
position) returns the wrong transaction.
**Fix:** re-hash `tx` after deserialisation; verify it equals the
queried txid; return `RPC_INTERNAL_ERROR "txid mismatch"` if not.

### BUG-25 (G25, LOW-CDIV): Key is the raw txid, not `(prefix, txid)` BE
**Severity:** LOW-CDIV. Core stores keys as
`(uint8_t prefix, uint256 txid)` (i.e. one prefix byte then 32
bytes of txid little-endian), with the prefix making
`DB_TXINDEX = 't'`-prefixed entries sort together. clearbit's CF
isolates the prefix into the column family, so the prefix byte is
not needed for sort-order; the 32-byte txid is stored as-is in
little-endian (matching the in-memory `Hash256` layout). This is
correct in clearbit's CF model but diverges from Core's single-CF
LevelDB layout.
**Fix:** documentation; no code change unless CFs are merged.

### BUG-30 (G30, LOW): Startup log says "Transaction index enabled" but no height
**Severity:** LOW. `main.zig:1772` prints `"Transaction index
enabled (--txindex)"` but does not report the current best
indexed height or whether the index needs to backfill. Core's
log message is `"%s is enabled at height %d"`
(`base.cpp:264`).
**Fix:** read `chain_state.best_height` after the chain tip is
loaded, log `"Transaction index enabled (--txindex), synced at
height %d"`.

## Patterns observed

- **"Parsed-but-dead CLI flag"** continues to be the dominant
  shape. `--coinstatsindex` is *exactly* the state `--txindex` was
  in pre-Pattern-C0 (commit history around 2026-05-05): parser
  populates `config.coinstatsindex`, no downstream consumer reads
  it. The Pattern-C0 fix (4 commits across `main.zig` → `storage.zig`
  → `connectBlockInner` → `disconnectBlockByHashCF` → tests) is
  the template for closing G7+G8+G12+G14+G15+G16.
- **"CF index = CF count"** UB ambush (BUG-7) is a new pattern: a
  module declares a placeholder CF id `usize = CF_COUNT` "until it
  is wired" but the array bounds-check is silent at runtime under
  ReleaseFast. Pattern-fix is to either reserve the slot
  (`CF_COUNT = 9; CF_COINSTATS = 8`) OR use an `?usize` Option type
  for placeholder CF ids.
- **"In-memory recompute vs incremental index"** (BUG-9, BUG-13):
  `gettxoutsetinfo hash_type=muhash` exists and works, but it
  recomputes from scratch on every RPC call by iterating the
  UTXO cache. The incremental-index pattern (Core's
  `CoinStatsIndex`) is absent. Same shape as `getrawtransaction`
  pre-Pattern-C0 (relied on mempool lookup before falling back to
  Core proxy).
- **"Wire format divergence with operational consequence"**
  (BUG-2): clearbit's 40-byte block-hash value is correct
  semantically but ~7× larger than Core's `CDiskTxPos` and
  requires an O(block_size) re-deserialise on every query. This is
  a "ports-from-scratch" decision that was correct given clearbit
  has no flat block files, but it inherits all the cost.
- **Forward-regression source guards** are still the right XFAIL
  shape for closing this audit. Each gate's test asserts the
  current (buggy) state by source-grep or by checking
  `config.coinstatsindex` reaches a specific call site; a future
  fix wave flips the assertion.

## Out of scope

- BIP-157/158 `BlockFilterIndex` (W121 + W122 own it).
- `assumeutxo` snapshot loading (separate subsystem).
- `txospenderindex` (Core's experimental third index — clearbit
  has no analog and this wave does not introduce one).
- `coinstats` migration plumbing (BUG-22 is forward-looking only).

## Verdict

clearbit has the **skeleton** of the index subsystem (CLI flags
parsed, struct definitions in `indexes.zig`, txindex CF wired to
connect/disconnect) but the implementation is **shallow** vs Core.
The txindex works for happy-path lookups; it does not survive a
reorg-during-prune or RPC-during-reorg; it has no
`getindexinfo` / `BlockUntilSyncedToCurrentChain` API; and the
on-disk wire format is incompatible with Core. The coinstatsindex
is **not wired at all** — the CLI flag is a no-op, the CF index is
out of range, and the struct in `indexes.zig` has no real call
site outside its own unit tests.

22 BUGs MISSING + 8 BUGs DIVERGE = **30 BUGs** across 30 gates.
Top fix-wave candidates ordered by closure ROI:

1. **FIX-X: coinstatsindex wire-up** — closes BUG-7..16 in one
   wave (CLI plumbing + CF slot + connect/disconnect hooks +
   MuHash + DBVal + unspendables). Largest single-impl closure
   yield. Mirrors the Pattern-C0 wave-shape for `--txindex`.
2. **FIX-Y: -txindex + -prune cross-flag check** — closes BUG-17
   and BUG-18 in a one-liner.
3. **FIX-Z: getindexinfo RPC + BlockUntilSyncedToCurrentChain** —
   closes BUG-19 + BUG-6.
4. **FIX-W: FindTx integrity hash check** — closes BUG-23 in
   ~20 lines.
