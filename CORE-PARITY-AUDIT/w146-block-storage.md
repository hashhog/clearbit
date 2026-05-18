# W146 — Block storage layer audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's on-disk block storage and block-index layer —
`blkXXXXX.dat` flat-file emission, `revXXXXX.dat` undo-file emission,
block-index leveldb (clearbit substitutes RocksDB column families
CF_BLOCKS / CF_BLOCK_INDEX / CF_BLOCK_UNDO), file-rotation rules,
fsync discipline, key-prefix layout, and reindex/recovery paths.

**Bitcoin Core references:**
- `bitcoin-core/src/node/blockstorage.cpp::BlockManager::WriteBlock` @ 1134-1165
  (FlatFilePos → blk*.dat append; MessageStart + size header; AutoFile fclose).
- `bitcoin-core/src/node/blockstorage.cpp::BlockManager::WriteBlockUndo` @ 967-1034
  (rev*.dat append; size header + serialized CBlockUndo + HashWriter checksum;
  UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES + 32-byte checksum).
- `bitcoin-core/src/node/blockstorage.cpp::BlockManager::FindNextBlockPos` @ 833-921
  (rotation at MAX_BLOCKFILE_SIZE; FlushBlockFile on rotation; FlatFileSeq::Allocate
  in BLOCKFILE_CHUNK_SIZE increments via fallocate; cursor split by BlockfileType
  NORMAL / ASSUMED).
- `bitcoin-core/src/node/blockstorage.cpp::BlockManager::FindUndoPos` @ 945-965
  (rev*.dat allocation; UNDOFILE_CHUNK_SIZE increments; FlushUndoFile on
  finalize).
- `bitcoin-core/src/node/blockstorage.cpp::BlockManager::FlushBlockFile` @ 742-769
  + `FlushUndoFile` @ 732-740 (FlatFileSeq::Flush → FileCommit → fdatasync
  for durability before considering write durable).
- `bitcoin-core/src/node/blockstorage.h` @ 119-129
  (`BLOCKFILE_CHUNK_SIZE = 0x1000000` 16 MiB; `UNDOFILE_CHUNK_SIZE = 0x100000`
  1 MiB; `MAX_BLOCKFILE_SIZE = 0x8000000` 128 MiB; `STORAGE_HEADER_BYTES = 8`;
  `UNDO_DATA_DISK_OVERHEAD = 8 + 32 = 40`).
- `bitcoin-core/src/node/blockstorage.h` @ 55-95 (CBlockFileInfo —
  nBlocks/nSize/**nUndoSize**/nHeightFirst/nHeightLast/nTimeFirst/nTimeLast,
  serialized with VARINT).
- `bitcoin-core/src/node/blockstorage.cpp` @ 58-65 (BlockTreeDB key prefixes:
  `DB_BLOCK_FILES = 'f'`, `DB_BLOCK_INDEX = 'b'`, `DB_FLAG = 'F'`,
  `DB_REINDEX_FLAG = 'R'`, `DB_LAST_BLOCK = 'l'`, txindex `'t'`/`'T'`).
- `bitcoin-core/src/txdb.cpp` @ 24 (`DB_BEST_BLOCK = 'B'` in CoinsDB).
- `bitcoin-core/src/chain.h` @ 75-82 (`BLOCK_HAVE_DATA = 8`,
  `BLOCK_HAVE_UNDO = 16`, `BLOCK_HAVE_MASK = 24`, `BLOCK_OPT_WITNESS = 128`).
- `bitcoin-core/src/chain.h` @ 109-115 (CBlockIndex stores nFile, nDataPos,
  nUndoPos).
- `bitcoin-core/src/util/fs_helpers.cpp::FileCommit` @ 102-130 (durability —
  `FlushFileBuffers` on Win32, `F_FULLFSYNC` on macOS, `fdatasync` on Linux).
- `bitcoin-core/src/kernel/messagestartchars.h` (mainnet 0xF9BEB4D9 LE;
  testnet3 0x0B110907; **testnet4 0x1C163F28**; signet 0x0A03CF40;
  regtest 0xFABFB5DA).

**Mode:** DISCOVERY (no production changes; this audit catalogues parity
bugs and code-shape gaps).

**Implementation files audited:**
- `clearbit/src/storage.zig`
  - `FlatFileBlockStore` @ 8557-8896 (dead module — blk*.dat writer used
    only by `tests` inside the same file; confessional comment at L2010
    explicitly tags it dead).
  - `UndoFileManager` @ 1665-1829 (rev*.dat writer; hard-coded mainnet
    magic; never rotates; the production reorg path consumes it).
  - `BlockFileInfo` @ 8497-8552 (clearbit's CBlockFileInfo analog).
  - Constants @ 8472-8479
    (`MAX_BLOCKFILE_SIZE`, `BLOCKFILE_CHUNK_SIZE`, `STORAGE_HEADER_BYTES`;
    no `UNDOFILE_CHUNK_SIZE` defined).
  - `ChainState.queueBlockWrite` @ 2441-2469 + `flush` @ 4340-…
    (production CF_BLOCKS / CF_BLOCK_UNDO put pipeline).
  - `ChainStore.putBlockIndexFull` @ 338-355 (32-byte block-hash-keyed
    record; no `'b'` / `'f'` / `'l'` / `'F'` / `'R'` prefix bytes).
  - `connectBlockWithUndo` @ 4836-4858 + `disconnectBlockFromFile` @
    4912-5044 (file-based undo entry; production reorg path).
- `clearbit/src/storage_rocksdb.zig`
  - `openDatabase` @ 48-278 (RocksDB open; `write_options =
    rocksdb_writeoptions_create()` @ 268 — **never** calls
    `rocksdb_writeoptions_set_sync(state.write_options, 1)`).
  - `dbWriteBatch` @ 453-486 (passes `state.write_options` straight into
    `rocksdb_write` — sync=false default).
- `clearbit/src/validation.zig`
  - `BlockIndexEntry` @ 5765-5814 (struct holds `file_number: u32`,
    `file_offset: u64`).
  - `BlockStatus` @ 5730-5760 (packed `struct(u32)` — bit positions
    diverge from Core's BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO).
  - ChainManager paths @ 6362-6737 — **every** site that constructs
    a `BlockIndexEntry` hard-codes `.file_number = 0, .file_offset = 0`.
- `clearbit/src/main.zig`
  - `--reindex` handler @ 1982-2003 — accepts flag, logs warning,
    no-op (does not wipe chainstate or replay CF_BLOCKS).
- `clearbit/src/rpc.zig`
  - replayReconnect helper @ 17683-17719 — production-adjacent fallback
    path that calls `connectBlockWithUndo(.., .., .., 0)` (always
    `file_number = 0`).

## Summary

clearbit's block-storage layer is structured as **three independent, partially
overlapping pipelines**, two of which are dead and one of which is the live
production path. None of the three matches Bitcoin Core's blk*.dat / rev*.dat
flat-file layout with sufficient fidelity to be cross-readable, and the
production path itself has several durability and correctness gaps.

**Pipeline A — `FlatFileBlockStore`** (`storage.zig:8557-8896`):
A nominally-complete blk*.dat writer with magic/size header, rotation at
`MAX_BLOCKFILE_SIZE`, BLOCKFILE_CHUNK_SIZE pre-allocation, and a `'b'+hash`
→ FlatFilePos index. **Dead module** — search across the impl shows zero
callers outside tests in `storage.zig` itself (lines 8975, 8996, 9026, …).
The confessional comment in the pruner block at `storage.zig:2010` explicitly
flags it: *"rather than unlinking blk*.dat flat files, which clearbit does
not write — FlatFileBlockStore is dead code."*

**Pipeline B — `UndoFileManager`** (`storage.zig:1665-1829`):
A rev*.dat writer with hard-coded mainnet magic, **no rotation logic**,
and a custom format that differs from Core's wire layout (extra 32-byte
prev_block_hash field inserted between size and undo data; checksum
hashed over `prev_block_hash || serialized` rather than Core's
`prev_block_hash || blockundo`). Production code does call it
(`disconnectBlockByHash` from validation.zig's reorg path), but **every
caller passes `file_number = 0`**, so all undo records are appended to a
single growing `rev00000.dat`.

**Pipeline C — RocksDB column families** (`CF_BLOCKS = 1`, `CF_BLOCK_UNDO = 5`,
`CF_BLOCK_INDEX = 2`):
The production path. `queueBlockWrite` + `queueUndoWrite` accumulate per-block
entries; `flush()` commits them with the UTXO mutations and the tip update
in a single `db.writeBatch`. **No `rocksdb_writeoptions_set_sync(1)` call**
anywhere in the openDatabase setup, so the WAL is buffered to OS pagecache
only — a kernel-level power loss between writeBatch returning and the OS
flushing can lose blocks the caller considers committed.

The RocksDB write_options miss the only line that turns RocksDB's write path
into a durable one. `storage_rocksdb.zig:268` allocates the options but
never sets `set_sync` or even tags it as `disableWAL=false` explicitly.
This is the single biggest IBD-durability gap in the impl.

Beyond pipeline shape, the on-disk block-index layout is also non-interop
with Core:
- clearbit's block-index keys are **raw 32-byte hashes** in CF_BLOCK_INDEX
  with no `'b'`-prefix byte. Core writes `('b', uint256)` and reserves the
  one-byte prefix space for `'f'` (file info), `'l'` (last file), `'F'`
  (flag), `'R'` (reindex), `'t'` (txindex). A Core node cannot read
  clearbit's block-index without a translation shim, and the inverse is
  also true.
- `BlockFileInfo` is a fixed 32-byte record (`storage.zig:8512-8522`) with
  fields written via `writeInt` — Core uses VARINT for every field
  (`blockstorage.h:67-76`). **`nUndoSize` is missing entirely**, and
  `time_last` is silently truncated to 32 bits (`@truncate(self.time_last)`
  at line 8520) — overflow at year-2106.
- `BlockStatus` packed struct is `valid_header=bit0, has_data=bit1,
  has_undo=bit2, failed_valid=bit3, failed_child=bit4` (validation.zig:5730).
  Core's chain.h values are BLOCK_HAVE_DATA=**8** (bit 3),
  BLOCK_HAVE_UNDO=**16** (bit 4), BLOCK_FAILED_VALID=**32** (bit 5),
  BLOCK_OPT_WITNESS=**128** (bit 7). The integer values don't line up,
  and BLOCK_OPT_WITNESS isn't represented at all. So `record.status`
  serialized to disk via `putBlockIndexFull` is a clearbit-private encoding.

**Fleet-pattern smells found:**
1. **Dead module — full surface, zero callers** — `FlatFileBlockStore`
   (Bug-1) and `UndoFileManager` partial-dead (file_number always 0).
2. **Three-pipeline guard** — three distinct block-storage implementations
   coexist (FlatFileBlockStore / UndoFileManager / CF_BLOCKS-CF_BLOCK_UNDO),
   each in a slightly different state of completeness.
3. **Comment-as-confession** — `storage.zig:2010` ("FlatFileBlockStore
   is dead code"), `main.zig:1986-1998` ("`--reindex` requested:
   clearbit's CF_BLOCKS-based reindex is partial"), `validation.zig:10591`
   ("Reindex is unsupported"). Four explicit acknowledgements within
   the storage layer.
4. **Wrong constants** — `UndoFileManager.MAGIC` hard-coded mainnet
   regardless of `--testnet4` / `--signet` / `--regtest`.
5. **Carry-forward re-anchor** — `BlockStatus` bit assignments first wrong
   in `validation.zig:5730` and propagated unchanged through `flush()` @
   4541-4542 (`new_status_bits = 1<<1 | 1<<2`), `persistBlockStatus`,
   and `BlockIndexRecord.fromBytes`.

---

## Bugs catalogued

### BUG-1 (P0 — DEAD MODULE) — `FlatFileBlockStore` is 340 LOC of unused blk*.dat writer

**File:** `clearbit/src/storage.zig:8557-8896`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1134-1165`

**Description:** `FlatFileBlockStore` is a complete blk*.dat writer (rotation,
chunk pre-allocation, magic+size header, `'b'`-prefixed block-index entries,
file_info tracking, getNumFiles, flush). It is referenced from **zero**
production code paths — only its own `test "..."` blocks reference it.
The pruner code in the same file explicitly tags it dead at
`storage.zig:2010`.

**Excerpt** (storage.zig:8557-8565, 9134):
```zig
/// Flat file block storage manager.
/// Stores blocks in blk{nnnnn}.dat files with a maximum size per file.
pub const FlatFileBlockStore = struct {
    data_dir: []const u8,
    network_magic: u32,
    file_info: std.ArrayList(BlockFileInfo),
    current_file: u32,
    current_pos: u64,
    ...
};
// All non-test references live in lines 9134, 9142, 8978, 8996, …
// — every one inside a `test "..."` block.
```

**Impact:** 340 LOC of carrying cost; future readers will assume the module
is the canonical block storage path and chase a non-existent integration.
Companion to the well-engineered-helper-never-wired fleet pattern noted in
W126 / W136. Either wire it into `peer.zig::drainBlockBuffer` (so clearbit
emits real blk*.dat files like Core), or delete the module and the
confessional comment together.

---

### BUG-2 (P0-CDIV) — `UndoFileManager.MAGIC` hard-coded mainnet, ignores network params

**File:** `clearbit/src/storage.zig:1670, 1741, 1792`
**Core ref:** `bitcoin-core/src/kernel/messagestartchars.h`

**Description:** `UndoFileManager` is a struct field on `ChainState`
(`storage.zig:1932, 2340`) initialized regardless of `--testnet4` /
`--signet` / `--regtest`. The 4-byte magic prefix written into rev*.dat
is the compile-time constant `0xf9beb4d9` (mainnet), so testnet4 / signet /
regtest nodes write mainnet magic into their rev files. On a reorg-and-restart
cycle, `readUndoData` then either rejects valid rev files when run on a
non-mainnet network (if the constant ever gets fixed) or, today, masks
network mis-mounts entirely.

**Excerpt** (storage.zig:1669-1671):
```zig
    /// Network magic bytes for file header (mainnet default).
    const MAGIC: [4]u8 = .{ 0xf9, 0xbe, 0xb4, 0xd9 };
```

**Impact:** P0-CDIV on testnet4 / signet / regtest disconnect-via-rev paths
(reorg + cross-network mount confusion). Companion to FlatFileBlockStore
which DOES parameterize on `network_magic: u32` — proves the bug is just
an oversight, not a design choice.

---

### BUG-3 (P0-CDIV) — `BlockStatus` bit positions diverge from Core's BLOCK_HAVE_DATA/BLOCK_HAVE_UNDO

**File:** `clearbit/src/validation.zig:5730-5760`, `clearbit/src/storage.zig:4541-4542`
**Core ref:** `bitcoin-core/src/chain.h:75-82`

**Description:** clearbit packs `valid_header=bit0, has_data=bit1,
has_undo=bit2, failed_valid=bit3, failed_child=bit4`. Core uses
`BLOCK_VALID_MASK = 7` (bits 0-2), `BLOCK_HAVE_DATA = 8` (bit 3),
`BLOCK_HAVE_UNDO = 16` (bit 4), `BLOCK_FAILED_VALID = 32` (bit 5),
`BLOCK_FAILED_CHILD = 64`, `BLOCK_OPT_WITNESS = 128`. The integer-value
encodings of "has data" / "has undo" / "failed valid" thus diverge —
clearbit's `flush()` at `storage.zig:4541-4542` writes `(1<<1)|(1<<2) = 6`
where a Core reader would read `4|8 = 12`. `BLOCK_OPT_WITNESS` is not
represented at all (no field for it in the packed struct).

**Excerpt** (storage.zig:4540-4542, validation.zig:5730-5736):
```zig
// Bit 1 = has_data, bit 2 = has_undo (clearbit packed layout).
const new_status_bits: u32 = @as(u32, 1 << 1) |
    (if (has_undo_this_block) @as(u32, 1 << 2) else @as(u32, 0));
```
```zig
pub const BlockStatus = packed struct(u32) {
    valid_header: bool = false,  // bit 0
    has_data: bool = false,      // bit 1   (Core: bit 3)
    has_undo: bool = false,      // bit 2   (Core: bit 4)
    failed_valid: bool = false,  // bit 3   (Core: bit 5)
    failed_child: bool = false,  // bit 4   (Core: bit 6)
    _padding: u27 = 0,
    ...
};
```

**Impact:** Block-index records written by clearbit cannot be read by a
Core node and vice-versa. Any future BIP-30 / assumeUTXO / pruning logic
that reads `status & BLOCK_HAVE_DATA` with the Core constant will read
the wrong bit and silently treat all blocks as "no data." Carry-forward
re-anchor pattern — three sites consume the same wrong bit definition.

---

### BUG-4 (P0-CDIV) — `BlockFileInfo.toBytes` omits `nUndoSize`; truncates `nTimeLast` to 32 bits

**File:** `clearbit/src/storage.zig:8497-8534`
**Core ref:** `bitcoin-core/src/node/blockstorage.h:55-95`

**Description:** Core's `CBlockFileInfo` carries 7 fields, every one
VARINT-encoded: nBlocks / nSize / **nUndoSize** / nHeightFirst /
nHeightLast / nTimeFirst / nTimeLast. clearbit's clone omits `nUndoSize`
entirely and packs the remaining 6 fields into a fixed 32-byte buffer.
Worse, the 64-bit `time_last` field is silently truncated to 32 bits
on write (line 8520) — overflow at the year 2106.

**Excerpt** (storage.zig:8512-8521):
```zig
pub fn toBytes(self: *const BlockFileInfo) [32]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], self.num_blocks, .little);
    std.mem.writeInt(u64, buf[4..12], self.size, .little);
    std.mem.writeInt(u32, buf[12..16], self.height_first, .little);
    std.mem.writeInt(u32, buf[16..20], self.height_last, .little);
    std.mem.writeInt(u64, buf[20..28], self.time_first, .little);
    // Only 4 bytes left for time_last; store low 32 bits
    std.mem.writeInt(u32, buf[28..32], @truncate(self.time_last), .little);
    return buf;
}
```

**Impact:** P0-CDIV vs Core for any future blk*.dat / rev*.dat readers
(pruning, NODE_NETWORK_LIMITED service flag, assumeutxo). Time_last
truncation: silent y2106 footgun. The "Only 4 bytes left" comment is a
self-confession that the buffer was sized first and the fields fit
in second — the standard data-loss antipattern.

---

### BUG-5 (P0-SEC / IBD-DURABILITY) — `rocksdb_writeoptions_set_sync(1)` is NEVER called; WAL is buffered to OS pagecache only

**File:** `clearbit/src/storage_rocksdb.zig:265-272, 453-486`
**Core ref:** `bitcoin-core/src/util/fs_helpers.cpp:FileCommit @ 102-130`
(invoked by `FlatFileSeq::Flush` → `BlockManager::FlushBlockFile`).

**Description:** `openDatabase` allocates `state.write_options =
c.rocksdb_writeoptions_create()` and never calls
`c.rocksdb_writeoptions_set_sync(state.write_options, 1)`. RocksDB's default
sync setting is `false`, meaning every `writeBatch` returns successfully
once the bytes are in the OS pagecache (not fsync'd to the underlying
disk). A kernel-level power loss between `db.writeBatch` returning and the
periodic kernel flush can lose every CF_BLOCKS / CF_BLOCK_UNDO / UTXO /
tip update that has not yet been flushed by the kernel — potentially
**hundreds of blocks** of advance on a busy SSD.

**Excerpt** (storage_rocksdb.zig:265-272):
```zig
const state = allocator.create(DbState) catch return storage.StorageError.OutOfMemory;
state.* = .{
    .db = if (db != null) db else return storage.StorageError.OpenFailed,
    .write_options = c.rocksdb_writeoptions_create(),  // <-- defaults: sync=false
    .read_options = c.rocksdb_readoptions_create(),
    ...
};
// nowhere does the code call rocksdb_writeoptions_set_sync(...)
```

**Impact:** Bitcoin Core invokes `FileCommit(file)` (Linux: `fdatasync`,
macOS: `F_FULLFSYNC`, Win: `FlushFileBuffers`) after every blk*.dat write
inside `FlushBlockFile`, AND uses leveldb in sync-on-commit mode for the
chainstate writes. clearbit does neither — every block "committed" via
`flush()` is durable only to the OS pagecache. A power loss can roll the
on-disk tip back by however many writes the kernel has buffered. The
optimistic `flush_error = false` after writeBatch returning gives the rest
of the impl false confidence in the durability.

---

### BUG-6 (P0) — `--reindex` flag is a no-op; CF_BLOCKS-based reindex unimplemented

**File:** `clearbit/src/main.zig:1982-2003`
**Core ref:** `bitcoin-core/src/init.cpp` + `validation.cpp::LoadExternalBlockFile`

**Description:** `--reindex` is accepted on the CLI and parsed into
`config.reindex`. The handler logs a warning and continues. It does not:
(a) wipe `<datadir>/chainstate`, (b) clear `CF_BLOCK_INDEX` / `CF_UTXO`,
(c) write the `'R'`/REINDEX flag to disk, (d) iterate CF_BLOCKS in height
order, or (e) replay `connectBlockFast` over each. The block-index
DB_REINDEX_FLAG persistence (Core's `BlockTreeDB::WriteReindexing`) is
completely absent. An operator who passes `--reindex` for a corruption
recovery gets the same chainstate they started with.

**Excerpt** (main.zig:1993-2003):
```zig
if (config.reindex) {
    std.debug.print(
        "--reindex requested: clearbit's CF_BLOCKS-based reindex is partial.\n" ++
        "  For a full rebuild, stop the node, delete <datadir>/<network>/chainstate,\n" ++
        "  and restart. CF_BLOCKS bodies are preserved; UTXO + headers will\n" ++
        "  rebuild from peers (or from blockstorage when --import-blocks= is set).\n",
        .{},
    );
    // Mark in debug log so the [REINDEX] category is visible if enabled.
    _ = debug_log.parseAndApply("reindex");
}
```

**Impact:** Operators relying on `--reindex` for crash recovery silently
do not get a reindex. Combined with BUG-5 (no fsync), a power loss
recovery story degrades to "delete chainstate manually then resync from
peers" — i.e., a full IBD on every flush_error event.

---

### BUG-7 (P0-CDIV) — Block-index DB keys lack Core's `'b'` / `'f'` / `'l'` / `'F'` / `'R'` prefix bytes

**File:** `clearbit/src/storage.zig:293-355` (ChainStore.putBlockIndex /
putBlockIndexFull), `clearbit/src/storage_rocksdb.zig:21-34` (cf_names)
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:58-62`,
`bitcoin-core/src/txdb.cpp:24`

**Description:** Core stores everything in one leveldb (`blocks/index/`)
keyed by a 1-byte prefix:
- `'b' + uint256` → CDiskBlockIndex
- `'f' + int32` → CBlockFileInfo
- `'l'` → last block file number (int32)
- `'F' + name` → flag (1-byte '0'/'1')
- `'R'` → reindexing flag (1-byte '1' when set)
- `'B'` → best block hash (in the chainstate DB)

clearbit instead uses 7 column families (`default / blocks / block_index /
utxo / tx_index / block_undo / block_filter / block_filter_header`) and
keys each by the raw 32-byte hash (or 6-byte `"H:" ++ u32_LE(height)` for
the height→hash index). Zero of the Core prefix bytes appear in the
production write path. The dead `FlatFileBlockStore.putBlockIndex` at
storage.zig:8824-8836 DOES write a `'b'` prefix — but only on disk in a
column family that's never read in production.

**Excerpt** (storage_rocksdb.zig:21-34):
```zig
const cf_names = [_][*:0]const u8{
    "default",
    "blocks",
    "block_index",
    "utxo",
    "tx_index",
    "block_undo",
    "block_filter",
    "block_filter_header",
};
```

**Impact:** Not a consensus bug per se, but a fundamental interop break.
Operators cannot point a Core binary at a clearbit datadir for emergency
recovery, and analytics tooling that reads Core's leveldb format directly
(e.g. `bitcoin-iterate`, `blocknotify` scrapers) silently produces empty
output. Companion to BUG-3 (BlockStatus bit reassignment).

---

### BUG-8 (P0-CDIV) — `UndoFileManager.writeUndoData` does NOT rotate at MAX_BLOCKFILE_SIZE; single rev00000.dat grows unbounded

**File:** `clearbit/src/storage.zig:1699-1758`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::FindUndoPos` @ 945-965 +
`FindNextBlockPos` @ 833-921

**Description:** Core caps `rev*.dat` at the same `MAX_BLOCKFILE_SIZE`
(128 MiB) as `blk*.dat` and rotates via `FindUndoPos`. clearbit's
`writeUndoData` takes a `file_number: u32` parameter — but never inspects
file size, never calls `FindUndoPos`-equivalent, and every production
caller hard-codes `file_number = 0` (see BlockIndexEntry sites in
validation.zig:6362, 6486, 6511, 6526, …). The result is a single
`rev00000.dat` that grows unbounded across the entire chain history.

**Excerpt** (validation.zig:6486-6487):
```zig
        .file_number = 0,
        .file_offset = 0,
```
(repeated ~25× across validation.zig:6362-6737, every BlockIndexEntry constructor)

**Impact:** On a chain of 500K+ blocks, the lone rev00000.dat ends up
multiple-GB in size — pruning cannot delete intermediate slices because
the prune unit is "the rev*.dat file." Any cross-Core analysis tool that
expects rev*.dat ≤ 128 MiB will buffer-overflow or refuse to mmap. Also:
`writeUndoData` opens the file with `seekFromEnd(0)` and writes — but
`UndoFileManager` is **not** synchronized with `connectBlockWithUndo`'s
caller across threads, so two concurrent connect-with-undo flows would
race on the file pointer. The reorg path acquires `connect_mutex` and
serializes that today, but the contract is not documented at the
UndoFileManager boundary.

---

### BUG-9 (P0-SEC) — `connectBlockWithUndo` writes rev*.dat OUTSIDE the writeBatch; crash-recovery atomicity broken

**File:** `clearbit/src/storage.zig:4836-4858`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::WriteBlockUndo @ 967-1034`
(writes rev file first; then `m_dirty_blockindex.insert(&block)` queues the
block-index update for the next leveldb commit).

**Description:** `connectBlockWithUndo` calls `manager.writeUndoData(...)`
**after** `self.connectBlock(...)` already mutated the UTXO set. The rev*.dat
write is a plain file append — no fsync, no writeBatch participation. The
caller is then supposed to call `flush()` separately. If the rev file write
succeeds but flush() crashes before committing the UTXO mutations and the
tip update, the rev file has a record for a block that was never connected;
on restart, `disconnectBlockByHash` tries to apply that undo against a UTXO
set that doesn't know about the spends → BIP-30-style overwrite or
"output claimed by block but missing from UTXO set" warning.

**Excerpt** (storage.zig:4836-4858):
```zig
pub fn connectBlockWithUndo(
    self: *ChainState,
    block: *const types.Block,
    hash: *const types.Hash256,
    height: u32,
    file_number: u32,
) !BlockUndo {
    // First, connect the block normally
    var undo = try self.connectBlock(block, hash, height);
    errdefer undo.deinit(self.allocator);

    // If we have an undo manager, persist the undo data
    if (self.undo_manager) |manager| {
        var undo_data = try undo.toBlockUndoData(block, self.allocator);
        defer undo_data.deinit(self.allocator);

        // Write to file — no fsync, not in the writeBatch
        try manager.writeUndoData(file_number, &block.header.prev_block, &undo_data);
    }

    return undo;
}
```

**Impact:** Reorg path crash window: rev file advances (durable to pagecache)
without UTXO advance → false disconnect drift. Core sidesteps this by
writing `nStatus |= BLOCK_HAVE_UNDO` to the block index inside the SAME
batch as the rev file's flush call, and by serializing block-index commits
with the chainstate commits via `FlushStateToDisk`.

---

### BUG-10 (P0) — `readBlockFromDisk` hard-caps block size at 4 MiB (Core limit is 4M weight units ≈ 4MB serialized but post-segwit witness data could exceed bare 4 MB)

**File:** `clearbit/src/storage.zig:8754-8808`
**Core ref:** `bitcoin-core/src/consensus/consensus.h::MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`

**Description:** `FlatFileBlockStore.readBlockFromDisk` sanity-checks
deserialized block size as `if (block_size > 4 * 1024 * 1024)` — i.e.,
4_194_304 bytes. Core's `MAX_BLOCK_SERIALIZED_SIZE` is 4_000_000 bytes
(decimal MB, not MiB). The constant doesn't match Core's, AND the impl
uses `4 * 1024 * 1024` for the threshold which over-shoots by 194_304 bytes.
A malicious actor planting a corrupt blk file with size = 4_100_000
bypasses the rejection.

**Excerpt** (storage.zig:8793-8796):
```zig
        // Sanity check: block size shouldn't be too large
        if (block_size > 4 * 1024 * 1024) { // 4 MB max
            return error.CorruptData;
        }
```

**Impact:** Read-side bypass against a corrupt-disk scenario; dead module
today (BUG-1), but if `FlatFileBlockStore` is ever wired in, this is the
P0 ratchet. Also: the comment says "4 MB" but the constant is 4 MiB — the
classic MB/MiB confusion that surfaces in operator-facing tools.

---

### BUG-11 (P1) — `FlatFileBlockStore.preAllocate` ignores file rename errors and uses `setEndPos` without fallocate semantics

**File:** `clearbit/src/storage.zig:8645-8654`
**Core ref:** `bitcoin-core/src/util/fs_helpers.cpp::AllocateFileRange @
112-150` (uses fallocate / posix_fallocate / F_PREALLOCATE / zero-write
fallback to actually RESERVE disk space).

**Description:** `preAllocate` calls `file.setEndPos(new_size)` which is
just `ftruncate` on POSIX — it extends the file logical size but does NOT
reserve disk blocks. On a near-full disk, a later write inside the
"pre-allocated" region can still ENOSPC mid-block. The block-storage
contract Core provides (`FlatFileSeq::Allocate` uses fallocate with
FALLOC_FL_ZERO_RANGE-equivalent on Linux) is to reserve disk blocks so a
mid-write ENOSPC never leaves a torn block.

**Excerpt** (storage.zig:8644-8654):
```zig
fn preAllocate(self: *Self, file: std.fs.File, target_size: u64) !void {
    _ = self;
    const stat = file.stat() catch return;
    if (target_size > stat.size) {
        // Allocate in BLOCKFILE_CHUNK_SIZE increments
        const chunks_needed = (target_size + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        const new_size = chunks_needed * BLOCKFILE_CHUNK_SIZE;
        file.setEndPos(new_size) catch {};  // <-- swallows error
    }
}
```

**Impact:** P1 vs Core's ENOSPC-safe model. The `catch {}` swallows the
error silently — so the caller never knows the preallocation failed. Also
dead-code today (FlatFileBlockStore is unwired), but ratchets P1 if wired.

---

### BUG-12 (P0-CDIV) — `UndoFileManager` undo-record format diverges from Core's CBlockUndo serialization

**File:** `clearbit/src/storage.zig:1692-1758`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::WriteBlockUndo @ 989-1000`

**Description:** Core's rev*.dat record layout is:
```
[message magic 4 bytes] [size 4 bytes LE] [serialized CBlockUndo] [SHA256d(prev_block_hash || CBlockUndo) 32 bytes]
```
clearbit's `writeUndoData` writes:
```
[mainnet magic 4 bytes] [undo_size 4 bytes LE] [prev_block_hash 32 bytes] [serialized BlockUndoData] [SHA256d(prev_block_hash || BlockUndoData) 32 bytes]
```
The extra `prev_block_hash` inserted between size and the undo payload, AND
the checksum is over the same bytes as Core (good), but the prefix shape
differs. A Core rev file is unreadable to clearbit and vice-versa.

**Excerpt** (storage.zig:1693-1698, 1741-1754):
```zig
/// Write undo data for a block to disk.
/// File format:
/// - magic (4 bytes)
/// - undo_size (4 bytes LE)
/// - prev_block_hash (32 bytes) — for integrity check        <-- NOT in Core
/// - serialized BlockUndoData
/// - checksum: double-SHA256(prev_block_hash || BlockUndoData)
```

**Impact:** Cross-impl rev*.dat reuse impossible; pruning-and-restore
across implementations (a stated meta-repo goal of multi-impl parity)
silently fails on the undo side. The "32 bytes — for integrity check"
comment proves the divergence is documented but the implications
weren't pursued.

---

### BUG-13 (P1) — `FlatFileBlockStore.flush` calls `file.sync()` on a freshly-opened second file handle, not the buffered writer used for writes

**File:** `clearbit/src/storage.zig:8870-8878`
**Core ref:** `bitcoin-core/src/util/fs_helpers.cpp::FileCommit`

**Description:** `flush()` reopens the current block file by calling
`self.openBlockFile(self.current_file, false)` and immediately calls
`file.sync()` on the new handle. Two issues:
1. The original file handle used by `writeBlock` was closed already
   (`defer file.close()` at line 8713). Reopening for sync is correct,
   but…
2. `file.sync()` on a freshly opened handle whose buffered writer's
   contents were already flushed inside `writeBlock` (line 8739) is
   sync'ing a file that has no further-pending OS-level dirty pages
   from this code's perspective. On POSIX `fsync` operates per-inode
   so this works — but the cumulative semantics (sync N blocks at
   once vs. per-block) is wrong: Core sync's the whole file at
   FlushBlockFile time, not every write.

**Excerpt** (storage.zig:8870-8878):
```zig
pub fn flush(self: *Self) !void {
    // Sync the current file if we have written to it
    if (self.current_pos > 0) {
        var file = self.openBlockFile(self.current_file, false) catch return;
        defer file.close();
        file.sync() catch {};   // <-- swallows error
    }
}
```

**Impact:** P1 — dead today (FlatFileBlockStore unwired). When wired,
the `catch {}` swallowing means a disk-full sync error never propagates,
and the operator never learns the sync didn't happen.

---

### BUG-14 (P1) — `BlockIndexRecord` serialized layout is non-VARINT fixed; Core uses VARINT for every field

**File:** `clearbit/src/storage.zig:324-355`
**Core ref:** `bitcoin-core/src/chain.h::CDiskBlockIndex SERIALIZE_METHODS @ 343-365`

**Description:** Core's CDiskBlockIndex serialization uses
`READWRITE(VARINT_MODE(...))` for `nVersion`, `nStatus`, `nTx`, `nFile`,
`nDataPos`, `nUndoPos`. clearbit uses fixed-width writeInt for all fields
of `BlockIndexRecord` (140 bytes total). Disk-space wise this is harmless
on long chains, but it's another cross-Core-interop break and adds 100+
bytes per block-index record across 500K+ blocks (≈50 MiB of extra disk).

**Excerpt** (storage.zig:338-355):
```zig
pub fn putBlockIndexFull(...) StorageError!void {
    var writer = serialize.Writer.init(self.allocator);
    defer writer.deinit();

    writer.writeInt(u32, record.height) catch ...;
    serialize.writeBlockHeader(&writer, &record.header) catch ...;
    writer.writeInt(u32, record.status) catch ...;
    writer.writeBytes(&record.chain_work) catch ...;
    writer.writeInt(i64, record.sequence_id) catch ...;
    writer.writeInt(u32, record.file_number) catch ...;
    writer.writeInt(u64, record.file_offset) catch ...;
    ...
```

**Impact:** Interop loss + ~50 MiB disk-space inflation on a mature
chain. Carry-forward dependency for any future Core-format read tools.

---

### BUG-15 (P0) — `BlockfileType { NORMAL, ASSUMED }` cursor split absent; clearbit cannot segment blockfiles by chainstate type

**File:** `clearbit/src/storage.zig` (no BlockfileType enum)
**Core ref:** `bitcoin-core/src/node/blockstorage.h::BlockfileType @ 151-156`,
`blockstorage.cpp::FindNextBlockPos @ 833-846` (assumeUTXO cursor)

**Description:** Core's `BlockManager::m_blockfile_cursors` is an
`std::array<std::optional<BlockfileCursor>, BlockfileType::NUM_TYPES>` —
two cursors, one for the NORMAL (background-validation) chain and one for
the ASSUMED (assumeUTXO snapshot) chain. clearbit has neither the enum
nor any cursor concept; `FlatFileBlockStore.current_file` is a single u32.
Combined with W138's findings (ChainstateManager dead-class fleet pattern),
clearbit cannot run a dual-chainstate IBD: incoming blocks on the assumed
chain would intermingle with normal-chain blocks in the same blk file,
breaking the pruning-via-file-deletion invariant.

**Excerpt** (storage.zig:8557-8568):
```zig
pub const FlatFileBlockStore = struct {
    data_dir: []const u8,
    network_magic: u32,
    file_info: std.ArrayList(BlockFileInfo),
    current_file: u32,        // <-- single cursor, no NORMAL/ASSUMED split
    current_pos: u64,
    allocator: std.mem.Allocator,
    db: ?*Database,
    ...
};
```

**Impact:** P0 vs Core for assumeUTXO. Confirms W138's dead-module finding
extends into the storage layer.

---

### BUG-16 (P0) — DB_REINDEX_FLAG `'R'` never written; mid-reindex crash leaves no on-disk indicator

**File:** `clearbit/src/main.zig:1993-2003`, `clearbit/src/storage.zig` (no equivalent)
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::BlockTreeDB::WriteReindexing @ 73-79`

**Description:** Core writes the byte `('R', '1')` to the block-index DB
when reindexing starts and erases it when reindexing completes.
A mid-reindex crash leaves the flag on disk → next startup detects
"reindex in progress" and resumes from the beginning rather than from
a half-resynced chainstate. clearbit's reindex path (which is a no-op
anyway per BUG-6) never writes such a flag.

**Excerpt** (nothing — there is no clearbit equivalent. main.zig's `--reindex`
handler at 1993-2003 just logs and continues.)

**Impact:** Even if BUG-6 is fixed and a real reindex is wired in, the
"reindex restart on crash" semantics cannot work without a persistent
flag. P0 for crash-resilience of any future reindex implementation.

---

### BUG-17 (P1) — No `m_dirty_blockindex` / `m_dirty_fileinfo` deferred-write tracking; every block-index write hits disk immediately

**File:** `clearbit/src/storage.zig:4498-4596`
**Core ref:** `bitcoin-core/src/node/blockstorage.h:307-313` (m_dirty_blockindex,
m_dirty_fileinfo) + `blockstorage.cpp::WriteBlockIndexDB @ 247-282`

**Description:** Core defers block-index writes via two sets:
`m_dirty_blockindex` (block-index entries that need writing) and
`m_dirty_fileinfo` (CBlockFileInfo entries that need writing). The
flush hits leveldb once with everything that accumulated. clearbit's
`flush()` reads back every `pending_block_write`'s existing CF_BLOCK_INDEX
entry via `db.get(CF_BLOCK_INDEX, &bw.hash)` (storage.zig:4557), then
re-serializes — every block-connect pays a read-modify-write round trip
to the SST level.

**Excerpt** (storage.zig:4544-4571):
```zig
// Read back the existing CF_BLOCK_INDEX entry so we can
// preserve chain_work, sequence_id, file_number, file_offset
// fields that may have been set by ChainManager.persistBlockStatus.
// If no entry exists (normal IBD fast path), start from zeros.
var rec = ChainStore.BlockIndexRecord{ ... };
if (db.get(CF_BLOCK_INDEX, &bw.hash) catch null) |existing| {
    defer self.allocator.free(existing);
    var er = serialize.Reader{ .data = existing };
    _ = er.readInt(u32) catch {}; // skip stored height
    _ = serialize.readBlockHeader(&er) catch {};
    const existing_status = er.readInt(u32) catch 0;
    // OR in the new bits, preserve any existing bits.
    rec.status = existing_status | new_status_bits;
    ...
}
```

**Impact:** Per-block read amplification ≈ 140 bytes + bloom-filter lookup
per connect, multiplied by IBD's ~840K blocks = significant slowdown vs
Core's "queue, flush in bulk" model. Not a correctness bug; performance
gap on IBD.

---

### BUG-18 (P1) — `getNumFiles` returns `@intCast(self.file_info.items.len)`; doesn't account for pruned-removed entries

**File:** `clearbit/src/storage.zig:8865-8867`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::PruneOneBlockFile`
(sets nBlocks/nSize to 0 in the existing entry rather than removing)

**Description:** Core never removes CBlockFileInfo entries from
`m_blockfile_info` even after pruning — it zeroes the relevant fields,
preserving the array index. clearbit's getNumFiles returns the array length
directly, which is fine in isolation, but `FlatFileBlockStore` has no
pruning hook that mirrors Core's PruneOneBlockFile, so the field-zeroing
contract is undefined.

**Excerpt** (storage.zig:8865-8867):
```zig
/// Get the total number of block files.
pub fn getNumFiles(self: *const Self) u32 {
    return @intCast(self.file_info.items.len);
}
```

**Impact:** P1 (dead-code today). When wired, this needs a PruneOneBlockFile
analog or the prune walker will skip "files" whose entries were
silently removed from the array.

---

### BUG-19 (P0) — `connectBlockWithUndo` always called with `file_number = 0` from production reorg path

**File:** `clearbit/src/validation.zig:5916-5917, 5940-5941, 6362-6363, 6486, 6511, …`
+ `clearbit/src/rpc.zig:17717`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::WriteBlock @ 1137`
(uses `FindNextBlockPos` to determine the actual file number, which rotates
at MAX_BLOCKFILE_SIZE)

**Description:** Every `BlockIndexEntry` constructor across validation.zig
(roughly 25 sites at lines 6362-6737) sets `.file_number = 0,
.file_offset = 0`. The replay helper in rpc.zig:17717 also passes `0`
explicitly. So `disconnectBlockByHash(.., 0, entry.file_offset, ..)`
always reads from `rev00000.dat`. This is consistent with BUG-8
(no rotation in writeUndoData) but compounds the same flaw — there is
no place in the impl that ever advances file_number past 0, so all undo
records over the whole chain live in one file, with file_offsets that
grow linearly with chain height.

**Excerpt** (validation.zig:6362-6363):
```zig
        .file_number = 0,
        .file_offset = 0,
```
(repeats at: 6486, 6511, 6526, 6554, 6568, 6582, 6596, 6629, 6643, 6657,
6691, 6737, …)

**Impact:** Effectively: no rotation across the whole undo storage layer.
Combined with BUG-8, the entire chain's undo history lives in one ever-growing
rev00000.dat. P0 vs Core's chunked rev*.dat scheme; couples directly into
the no-pruning-of-undo BUG-18 fleet-pattern smell.

---

### BUG-20 (P2) — No `m_have_pruned` boolean; pruning state not persistent across restarts

**File:** `clearbit/src/storage.zig:2042-2047`
**Core ref:** `bitcoin-core/src/node/blockstorage.h::m_have_pruned @ 450`
("True if any block files have ever been pruned")

**Description:** Core persists a one-bit flag (via the `'F'+name` flag DB
key, name = "prunedblockfiles") so that on restart, the node knows that
"this datadir has been pruned" and refuses to serve blocks <
`prune_height`. clearbit tracks `prune_height` as a runtime u32 only,
seeded fresh on each start by reading the chainstate metadata — there is
no "have ever pruned" persistent flag. If `prune_height` is somehow reset
to 0 (cosmic ray, partial DB rebuild, manual edit), the node silently
forgets it ever pruned, may try to serve blocks it doesn't have, and
peers ban it for missing-data lies.

**Impact:** P2 vs Core's pruning model. Operationally: edge-case-only
unless an admin manually fiddles with the DB.

---

### BUG-21 (P1) — `BlockFileInfo.toBytes` lossy: `time_last @truncate` silently drops top 32 bits

**File:** `clearbit/src/storage.zig:8519-8521`
**Core ref:** `bitcoin-core/src/node/blockstorage.h:65` (`uint64_t nTimeLast`)

**Description:** As noted in BUG-4, line 8520 uses `@truncate(self.time_last)`
to fit a 64-bit value into 32 bits. Bitcoin timestamps are seconds since
epoch, so this overflows in the year 2106 (2^32 seconds past 1970).
Once it overflows, two distinct block timestamps can be mapped to the
same on-disk u32 → fileinfo's time_last becomes ambiguous, and Core-style
prune heuristics that compare time_last across files break.

**Excerpt** (storage.zig:8519-8521):
```zig
// Only 4 bytes left for time_last; store low 32 bits
std.mem.writeInt(u32, buf[28..32], @truncate(self.time_last), .little);
```

**Impact:** P1 — silent data corruption ~80 years out. Carry-forward
re-anchor onto BUG-4's structural issue with the fixed 32-byte buffer.

---

### BUG-22 (P0-CDIV) — `BlockFileInfo.addBlock` initializes height_first/time_first lazily but doesn't symmetrically reset on file rotation

**File:** `clearbit/src/storage.zig:8537-8551`, `8666-8678`
**Core ref:** `bitcoin-core/src/node/blockstorage.h::AddBlock @ 83-94`
(uses `nBlocks == 0` as the "first block" sentinel)

**Description:** `addBlock` uses `if (self.num_blocks == 0) { init to first }`
which is correct. However, the rotation logic in `findNextBlockPos` at
8666-8678 appends a new zeroed BlockFileInfo, so the sentinel works for
new files. The problem: on RESTART, when `file_info` is re-loaded from
RocksDB (it's never persisted! see BUG-23), the sentinel logic kicks in
because `num_blocks == 0` for what was previously a populated file, and
the first block written after restart sets height_first/time_first to its
own values — losing whatever the lower bound was before the restart.

**Excerpt** (storage.zig:8497-8552, 8666-8678):
Both the addBlock helper AND the rotation block both use `num_blocks == 0`
to detect "this file is fresh" — but the helper assumes that's only true
for the initial entry. There's no `loadBlockIndexFromDisk` for FlatFileBlockStore.

**Impact:** P0-CDIV vs Core, IF FlatFileBlockStore is wired. The on-disk
file actually contains blocks at heights H_first..H_last, but the in-memory
BlockFileInfo reports it as starting from "first block since restart" — a
silent metadata drift that pruning would key off.

---

### BUG-23 (P1) — `FlatFileBlockStore.file_info` is in-memory only; never persisted to CF_BLOCK_INDEX or any other CF

**File:** `clearbit/src/storage.zig:8557-8896`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::WriteBatchSync @ 91-103`
(writes std::make_pair(DB_BLOCK_FILES, file) → CBlockFileInfo for every
m_dirty_fileinfo entry)

**Description:** `FlatFileBlockStore` keeps `file_info: std.ArrayList(BlockFileInfo)`
as a live in-memory list. There is no `persistFileInfo()` method, no
write-into-CF_BLOCK_INDEX for the 'f'+file_num key (which clearbit's
encoding doesn't have anyway per BUG-7), and `init` always starts with a
single zero entry. After restart, the file_info is reconstructed entirely
from "current_file = 0, file_info = [one zero entry]" → loses every
preceding rotation.

**Impact:** P1 vs Core, dead today (BUG-1). When wired, restart-amnesia.

---

### BUG-24 (P2) — `flush_error` sticky flag set after `writeBatch` failure but on-disk state already partial

**File:** `clearbit/src/storage.zig:4718-4748`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::FlushBlockFile @ 742-769`
(`FatalError` on flush failure)

**Description:** When `db.writeBatch(batch.items)` fails, clearbit sets
`self.flush_error = true` and refuses further mutation — but the comment
at storage.zig:4724-4727 explicitly says *"if any later flush succeeds,
the on-disk tip jumps over un-persisted intermediate UTXOs"*. That race
window is only closed by the flush_error being sticky in-process; if the
process restarts (operator-induced or crash), the sticky flag is gone
and the next IBD pass starts from whatever the half-flushed tip says.
This is acknowledged in code (Option A, wave2-2026-04-14) but never
resolved.

**Excerpt** (storage.zig:4720-4728):
```zig
db.writeBatch(batch.items) catch |err| {
    std.debug.print("ChainState flush: writeBatch failed with {}, {d} entries NOT persisted — setting flush_error\n", .{ err, batch.items.len });
    // Sticky flush_error so connectBlockFast / submitBlock refuse
    // to advance the in-memory tip past the last good on-disk tip.
    // Without this, the next per-block flush retries the same
    // writeBatch but the tip in that batch reflects the NEW height
    // — if any later flush succeeds, the on-disk tip jumps over
    // un-persisted intermediate UTXOs (Option A, wave2-2026-04-14).
    self.flush_error = true;
    ...
```

**Impact:** P2 — already mitigated by Option A. The note remains valuable
because the mitigation is process-lifetime-only.

---

## Fleet-pattern summary

| Pattern | Bugs |
|---|---|
| Dead module (defined, fully tested, zero production callers) | BUG-1, partial BUG-8 |
| Three-pipeline guard (3 coexisting block-store impls) | structural; not a single bug |
| Comment-as-confession (TODO/FIXME/HACK acknowledging gap) | BUG-1 (L2010), BUG-6 (L1986-1998), L10591 |
| Wrong constants / units | BUG-2 (mainnet magic hard-coded), BUG-10 (4 MiB vs 4 MB), BUG-21 (32-bit time truncation) |
| Carry-forward re-anchor (single bad assumption replicated) | BUG-3 (BlockStatus bits in 3 sites), BUG-19 (file_number=0 in ~25 sites) |
| Interop break (cross-Core readability) | BUG-3, BUG-4, BUG-7, BUG-12, BUG-14 |
| Crash-recovery gap | BUG-5 (no fsync), BUG-9 (rev outside batch), BUG-16 (no R flag), BUG-22, BUG-23 (file_info volatile) |

**Total bugs: 24** (3 × P0-CDIV related to magic/format/cursor segregation,
2 × P0-SEC related to durability, 7 × P0, 8 × P1, 4 × P2/other).

The most concerning finding: **BUG-5 (RocksDB sync=false default)** combined
with **BUG-9 (rev*.dat write outside writeBatch)** and **BUG-6 (--reindex
no-op)** means a power loss during IBD can roll the on-disk tip backwards
by hundreds of blocks, and the operator has no built-in recovery path.

The most cosmetic-but-systemic finding: clearbit and Core cannot share a
datadir because of BUG-3 (BlockStatus bit layout), BUG-4 (CBlockFileInfo
field omission + truncation), BUG-7 (no Core key prefixes), and BUG-12
(rev format divergence). This is a structural decision rather than a bug
per se — but the impl carries the cost of three half-implementations
(`FlatFileBlockStore`, `UndoFileManager`, CF_BLOCKS) instead of either
fully matching Core or fully owning a custom format.
