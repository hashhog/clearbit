# W147 — UTXO database / chainstate audit (clearbit, Zig 0.13)

**Date:** 2026-05-18
**Scope:** clearbit's `CCoinsView` / `CCoinsViewCache` / `CCoinsViewDB`
analogues — production UTXO write/read path (`ChainStore`, `UtxoSet`,
`CompactUtxo`), nominal Core-shaped `CoinsViewCache` / `CoinsViewDB`
module, on-disk Coin encoding, RocksDB key layout, FRESH/DIRTY flag
semantics, BatchWrite atomicity with the chain tip, FlushStateToDisk
trigger surface, and obfuscation-key protocol.

**Mode:** DISCOVERY (no production code changes; this audit catalogues
parity bugs only).

**Bitcoin Core references:**
- `bitcoin-core/src/coins.h` @ 89-167 (`CCoinsCacheEntry` + DIRTY/FRESH
  flag definitions; AddCoin / SpendCoin / FetchCoin semantics).
- `bitcoin-core/src/coins.cpp` @ 17-32 (`CCoinsView` interface
  contract: GetCoin, PeekCoin, HaveCoin, GetBestBlock, GetHeadBlocks,
  BatchWrite, Cursor).
- `bitcoin-core/src/coins.cpp` @ 44-50 (`PeekCoin` — cache-checking
  variant that does NOT populate cache).
- `bitcoin-core/src/coins.cpp` @ 68-87 (`FetchCoin` — cache→base
  fallback with cache population).
- `bitcoin-core/src/coins.cpp` @ 89-130 (`AddCoin` — IsUnspendable
  short-circuit, FRESH derivation, possible_overwrite contract).
- `bitcoin-core/src/coins.cpp` @ 153-175 (`SpendCoin` — FRESH=erase,
  non-FRESH=mark dirty + Clear).
- `bitcoin-core/src/coins.cpp` @ 179-186 (`AccessCoin` returning
  `coinEmpty` on miss).
- `bitcoin-core/src/txdb.cpp` @ 23-30, 41-49 (key encoding: `DB_COIN
  = 'C'`, `DB_BEST_BLOCK = 'B'`, `DB_HEAD_BLOCKS = 'H'`,
  `CoinEntry::SERIALIZE_METHODS` uses `key, hash, VARINT(n)`).
- `bitcoin-core/src/txdb.cpp` @ 72-90 (`GetCoin`, `HaveCoin`,
  `GetBestBlock`, `GetHeadBlocks`).
- `bitcoin-core/src/txdb.cpp` @ 100-164 (`BatchWrite` — atomic
  HEAD_BLOCKS handoff protocol, `simulate_crash_ratio`, partial-batch
  flush, `Erase(DB_BEST_BLOCK)` then `Write(DB_HEAD_BLOCKS)` then per-
  coin batch then `Erase(DB_HEAD_BLOCKS)` + `Write(DB_BEST_BLOCK)`).
- `bitcoin-core/src/dbwrapper.h` @ 188-192, `dbwrapper.cpp` @ 253-261
  (`OBFUSCATION_KEY` = `"\0obfuscate_key"` (14-byte key stored at
  null-prefixed key in DB; XOR'd onto all values on read/write).
- `bitcoin-core/src/util/obfuscation.h` (8-byte rotating obfuscation
  key XOR'd against all chainstate values).
- `bitcoin-core/src/compressor.cpp` @ 55-93 (`CompressScript` —
  P2PKH/P2SH/compressed-P2PK/uncompressed-P2PK to 1-byte tag + 20 or
  32 bytes; otherwise VARINT(size + 6) + raw).
- `bitcoin-core/src/compressor.cpp` @ 149-200 (`CompressAmount` —
  mantissa+exponent encoding; `DecompressAmount` inverse).
- `bitcoin-core/src/coins.h::Coin` (serialization: `VARINT(code) ||
  VARINT(CompressAmount(value)) || ScriptCompression(scriptPubKey)`
  where `code = (height << 1) | coinbase`).
- `bitcoin-core/src/validation.cpp::FlushStateToDisk` — gating modes
  NONE / IF_NEEDED / PERIODIC / ALWAYS; nMinDiskSpace abort guard;
  GetMainSignals().ChainStateFlushed callback; dbcache pressure
  thresholds.
- `bitcoin-core/src/util/hasher.cpp` @ 25-37 (`SaltedOutpointHasher`
  with `m_k0`, `m_k1` randomly seeded per-process via
  `FastRandomContext` for HashDoS protection).

**Implementation files audited:**
- `clearbit/src/storage.zig` (565 KB — the canonical storage layer).
  - `UtxoEntry` (lines 70-114) — production-A serialization shape.
  - `makeUtxoKey` (line 117) — production-A key (36 bytes, no
    prefix, raw LE u32 vout).
  - `ChainStore` (line 253), `putUtxo` @ 405-425, `applyUtxoBatch` @
    501-560, `applyBlockAtomic` @ 565-660 (production UTXO writers).
  - `CompactUtxo` (line 654) + `encode` @ 670-690 — production-B
    on-disk Coin encoding (4-byte LE packed_height + raw i64 value +
    1-byte script_type + hash/script payload).
  - `UtxoSet` (line 870), `flush` @ 1353-1430, `flushPendingDeletes`
    @ 1430-1469 (cache-tier; non-atomic with tip on the no-parent
    fallback path).
  - `isScriptUnspendable` @ 1870-1874 (correct two-prong check used
    by the production paths).
  - `ChainState.flush` @ 4340 (production atomic tip+UTXO batch
    using `CompactUtxo.encode`).
  - `Coin` (line 9175) + `toBytes` @ 9203-9219 + `fromBytes` @ 9222-
    9246 — third Coin shape (used only by the dead `CoinsViewDB`
    module).
  - `CoinEntry` (line 9260) — DIRTY/FRESH cache-flag struct
    (Core-shaped, dead module).
  - `OutPointContext` (line 9307) — unsalted hash for the dead
    `CoinsViewCache` HashMap.
  - `makeCoinsDbKey` (line 9325) — fourth UTXO key shape (37 bytes,
    `'C'` prefix, raw LE u32 vout — almost but not quite Core).
  - `CoinsViewDB` (line 9335) — dead-module DB wrapper.
  - `CoinsViewCache` (line 9440) — dead-module cache wrapper with
    Core-shaped FRESH/DIRTY semantics.
- `clearbit/src/compressor.zig` (507 LOC) — fully Core-faithful port
  of `CompressAmount` / `CompressScript` / `writeCoin` / `readCoin`,
  with golden round-trip tests against Core's `compress_tests.cpp`
  vectors. **Used only on the assumeUTXO `dumptxoutset` / `load-
  txoutset` snapshot path** (`storage.zig:5172`, 5186, 5564). Never
  invoked from the production UTXO write path.
- `clearbit/src/storage_rocksdb.zig` (709 LOC) — RocksDB binding;
  no obfuscation, no XOR layer.
- `clearbit/src/sync.zig` @ 1846-1858 — the live block-connect
  caller that drives the production `applyBlockAtomic` write.

**Prior audits to cross-cite:**
- W100 — `CCoinsViewCache + FlushStateToDisk` (already catalogued
  BUG-5 inline `count*500` memory estimate, BUG-6 no FlushStateMode
  dispatch, BUG-7 no nMinDiskSpace abort, BUG-8 no MainSignals hook,
  BUG-9 flush evicts ALL entries vs Core's dirty-only sweep). The
  bugs below carry these forward where they intersect; new W147 bugs
  start at BUG-1.
- W107 — CompactSize vs VARINT divergence (BUG-3: `storage.Coin.to-
  Bytes` uses `writeCompactSize` for the coin code where Core uses
  VARINT). W107 also closed BUG-4 in `BlockUndoData.toBytes` (now
  uses `writeVarInt`); but the `storage.Coin.toBytes` BUG-3 remains
  open in production, and broadens further (see BUG-1 below).
- W138 — assumeUTXO snapshots (already covered the `dumptxoutset`
  consumer of `compressor.writeCoin`; the parallel-write-path
  question between snapshot-format and live-storage-format is part
  of W147 BUG-7).

## Summary

clearbit's UTXO chainstate is split across **three concurrent
encodings and four cache layers**, none of which talk Core's
chainstate wire format. The same on-disk database is written by
**two different production paths** that use **two different on-disk
Coin serializations** — `UtxoEntry.toBytes` (CompactSize + raw i64 +
raw script bytes, via `ChainStore.applyBlockAtomic`) and
`CompactUtxo.encode` (4-byte packed-height + raw i64 + 1-byte
script_type + hash, via `ChainState.flush`). A *third* shape
(`Coin.toBytes`) exists in a dead `CoinsViewCache`/`CoinsViewDB`
module that no production code calls, and a *fourth* fully Core-
faithful encoding (`compressor.writeCoin`, mantissa/exponent
compression + Core VARINT) is used only for `dumptxoutset` snapshot
emission. The four-pipeline divergence is fleet-pattern-canonical
("two-pipeline guard", but with two production writers and two test
writers).

Within those layers, the per-Core-behavior parity gaps are:

1. **CCoinsView interface contract** — clearbit has no central
   interface. `UtxoSet`, `CoinsViewCache`, `ChainStore`, and `CoinsViewDB`
   each define ad-hoc GetCoin/HaveCoin variants with conflicting
   signatures (some return `?Coin`, others return `?UtxoEntry`, some
   take `*const`, some take `*`). No `PeekCoin` (Core's non-cache-
   populating variant; coin.cpp:44-50). No `GetHeadBlocks` (the
   crash-recovery handoff key Core ships in BatchWrite). No `Cursor`
   on the production UtxoSet (only `applyBlockAtomic` and `flush`).

2. **CCoinsViewCache** — the Core-shaped FRESH/DIRTY layer is
   defined (`CoinEntry` at storage.zig:9260) but ZERO callers reach
   it from production: `grep -rn 'CoinsViewCache\|CoinsViewDB'` outside
   `storage.zig` and the test files returns nothing. The production
   path uses a different cache (`UtxoSet.cache` of `CacheEntry`), which
   also tracks dirty/fresh, but with subtly different invariants
   (see BUG-2, BUG-5).

3. **CCoinsViewDB leveldb backend** — clearbit uses RocksDB. The
   production CF_UTXO key shape is **36 bytes raw** (32-byte txid + 4-
   byte LE u32 vout, NO prefix byte; `makeUtxoKey` at line 117). The
   dead `CoinsViewDB` module uses a **37-byte 'C'-prefixed** key
   (line 9325). Core uses **'C' + 32-byte hash + VARINT(n)** which is
   a **variable** 34-37 byte key. Neither clearbit shape can read a
   Core chainstate; the two clearbit shapes cannot read each other.

4. **Coin compression** — `CompressAmount`/`CompressScript` is fully
   implemented (compressor.zig) but UNCALLED from the production
   write path. `UtxoEntry.toBytes` stores raw `i64` value and raw
   script. `CompactUtxo.encode` stores raw `i64` value plus 1-byte
   `script_type` (which is NOT Core's 6 special tags). On-disk size
   is ~2x Core's.

5. **obfuscate_key** — entirely absent. clearbit's CF_UTXO is
   plaintext on disk. Antivirus false-positive risk Core hedges
   against is unmitigated; this is also a P3-class privacy/forensic
   weakness for any operator who runs malware-scan against a snapshot.

6. **FlushStateToDisk triggers** — single `evictCache` / `flush`
   path, no IF_NEEDED/PERIODIC/ALWAYS/NONE dispatch (W100 BUG-6),
   no nMinDiskSpace abort (W100 BUG-7), no MainSignals callback
   (W100 BUG-8). Re-cited.

7. **Coin height+is_coinbase encoding** — three divergent shapes:
   `UtxoEntry` stores `code = height*2 + coinbase` as a CompactSize
   varint; `CompactUtxo` stores `is_coinbase` in MSB of a raw u32
   `packed_height` (effectively masking height to 2^31-1); the dead
   `Coin.toBytes` uses CompactSize on `height*2 + coinbase`.
   None match Core's VARINT-on-`(height << 1) | coinbase`.

8. **AccessCoin / SpendCoin flag plumbing** — production `UtxoSet`
   tracks `dirty: bool`/`fresh: bool` per entry and treats spent
   coins via `pending_deletes` (a separate side-list) rather than
   Core's "spent coin remains in cache as a null/cleared entry with
   dirty=true" approach. The two pieces are wired correctly through
   the connect/disconnect path but their semantics diverge from Core
   in observable ways (see BUG-9).

The single highest-severity finding is **BUG-1** — the production
`ChainStore.applyBlockAtomic` writes UTXO values with a Coin encoding
(`UtxoEntry.toBytes`) that is **bytewise incompatible with Bitcoin
Core's `coins.h::Coin::Serialize`** at every gate: it uses
`writeCompactSize` (Bitcoin network-protocol prefix encoding) where
Core uses VARINT (custom variable-length); it stores raw `i64` value
where Core stores `CompressAmount(value)`; it stores the raw script
bytes where Core stores `CompressScript(scriptPubKey)`. The
chainstate on disk cannot be loaded by Bitcoin Core; cannot
participate in Core's `assumeutxo` snapshot interchange; cannot be
inspected with Core tooling (the assumeUTXO snapshot path that DOES
use the correct format lives in `compressor.zig` but is wired only
to `dumptxoutset` / `loadtxoutset`).

The next-largest finding is **BUG-2** — `ChainState.flush` (the
production atomic writer) uses **yet another** Coin encoding
(`CompactUtxo.encode`), distinct from both `UtxoEntry.toBytes` AND
from Core. The production database is therefore written by two
parallel paths with two different on-disk Coin formats, sharing a
single `CF_UTXO` column family. Whichever path is invoked last for
a given outpoint determines the on-disk bytes; subsequent reads via
`getUtxo` (`UtxoEntry.fromBytes`) will misinterpret entries written
by `flush` (`CompactUtxo.encode`), and vice versa. The codebase
does not have an integration test that exercises both write paths
against a single CF_UTXO.

Below: 22 bugs catalogued. P0-CDIV / P0-SEC / P0 / P1 / P2 / P3.

## Bug catalogue (22 entries)

## BUG-1 — Production `UtxoEntry.toBytes` Coin encoding is byte-incompatible with Core at every gate (P0-CDIV)

**Severity:** P0-CDIV

**File:** `clearbit/src/storage.zig:77-88` (definition);
`clearbit/src/storage.zig:421` (`ChainStore.putUtxo` writer);
`clearbit/src/storage.zig:527, 592` (`applyUtxoBatch`, `apply-
BlockAtomic` writers).

**Core ref:** `bitcoin-core/src/coins.h::Coin::Serialize` (via
`compressor.{h,cpp}`):
`VARINT(code) || VARINT(CompressAmount(value)) || ScriptCompression(
scriptPubKey)` where `code = (height << 1) | coinbase`.

**Description:** Every gate of the production UTXO write path
diverges from Core's wire format. Field-by-field:

| Gate | clearbit `UtxoEntry.toBytes` | Bitcoin Core |
|------|------------------------------|--------------|
| `code` / `(height, is_coinbase)` | `value: i64 (8 LE)` written first; height written separately as raw `u32 LE`; coinbase as raw `u8` byte | single `VARINT((height << 1) \| coinbase)` |
| value (amount) | raw `i64 LE` (8 bytes) | `VARINT(CompressAmount(value))` (1-9 bytes, typically 2-3 for satoshi-quantized outputs) |
| script length | `writeCompactSize(len)` | implicit via `CompressScript` (1-byte tag + 20/32 bytes for P2PKH/P2SH/P2WPKH/P2WSH/P2PK), or `VARINT(len + 6)` for raw |
| script body | raw bytes | special-form 20/32-byte payload OR raw bytes |
| field order | value, height, coinbase, len(script), script | code, value, script |

For a typical P2PKH 5_000_000_000-sat coinbase output at height
800_000, this means clearbit writes `(8 + 4 + 1 + 1 + 25) = 39
bytes` where Core writes ~`(2 + 3 + 1 + 20) = 26 bytes`. Beyond the
~50% on-disk inflation, the formats are **mutually unreadable**.

**Excerpt:**
```zig
// storage.zig:77-88 — production UtxoEntry serialization
pub fn toBytes(self: *const UtxoEntry, allocator: std.mem.Allocator) StorageError![]const u8 {
    var writer = serialize.Writer.init(allocator);
    errdefer writer.deinit();

    writer.writeInt(i64, self.value)            catch return StorageError.SerializationFailed;
    writer.writeInt(u32, self.height)           catch return StorageError.SerializationFailed;
    writer.writeInt(u8, if (self.is_coinbase) 1 else 0) catch return StorageError.SerializationFailed;
    writer.writeCompactSize(self.script_pubkey.len)     catch return StorageError.SerializationFailed;
    writer.writeBytes(self.script_pubkey)               catch return StorageError.SerializationFailed;

    return writer.toOwnedSlice() catch return StorageError.OutOfMemory;
}
```
Compare to `compressor.zig:312-326` which DOES implement the Core
shape correctly — but is invoked only from the assumeUTXO snapshot
path (`storage.zig:5172`, 5186, 5564). The W107 BUG-3 closure landed
in `BlockUndoData.toBytes` but never propagated to `UtxoEntry`.

**Impact:** clearbit's on-disk chainstate cannot be read by Bitcoin
Core; cannot be exchanged with any peer-impl that targets Core wire
format; cannot be inspected with Core's `dumptxoutset` tooling. This
also strands clearbit from the `assumeutxo` interchange ecosystem —
even though `compressor.zig` does encode snapshots correctly, the
live chainstate it writes can't be loaded back as a snapshot
without a round-trip through `compressor.writeCoin`. This is the
clearest cross-impl chainstate-portability blocker, and combined
with BUG-2 it means clearbit's own two production paths can't read
each other's writes either.

## BUG-2 — `ChainState.flush` uses a third, different Coin encoding (`CompactUtxo.encode`), divergent from both `UtxoEntry.toBytes` AND Core (P0-CDIV)

**Severity:** P0-CDIV

**File:** `clearbit/src/storage.zig:670-690` (definition);
`clearbit/src/storage.zig:1371, 4400` (writers in production flush
paths).

**Core ref:** Same as BUG-1.

**Description:** clearbit has TWO production paths that both write
to `CF_UTXO` but use DIFFERENT Coin encodings. The first
(`ChainStore.applyBlockAtomic`, via `UtxoEntry.toBytes`) is described
in BUG-1. The second (`ChainState.flush` and `UtxoSet.flush`, via
`CompactUtxo.encode`) uses a completely different shape:

```zig
// storage.zig:669-690 — CompactUtxo.encode (the OTHER production path)
pub fn encode(self: *const CompactUtxo, allocator: std.mem.Allocator) ![]const u8 {
    var writer = serialize.Writer.init(allocator);
    errdefer writer.deinit();

    // Pack coinbase flag into MSB of height
    const packed_height: u32 = self.height | (if (self.is_coinbase) @as(u32, 1) << 31 else 0);
    try writer.writeInt(u32, packed_height);
    try writer.writeInt(i64, self.value);
    try writer.writeBytes(&[_]u8{self.script_type});

    if (self.script_type <= 4) {
        // Known script types: just store the hash
        try writer.writeBytes(self.hash_or_script);
    } else {
        // Other: store length-prefixed script
        try writer.writeCompactSize(self.hash_or_script.len);
        try writer.writeBytes(self.hash_or_script);
    }

    return writer.toOwnedSlice();
}
```

`script_type` is 0..=5 (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OTHER) —
not Core's 6 compressor special tags (which are 0..=5 mapping to
P2PKH, P2SH, compressed-P2PK x2, uncompressed-P2PK x2). The
`OTHER` branch length-prefixes with CompactSize; Core uses VARINT.

**Impact:** Two production write paths each leave on-disk bytes
that the OTHER path's reader will mis-parse. `UtxoEntry.fromBytes`
called on bytes written by `CompactUtxo.encode` will:
1. Read 8 bytes (first 4 = `packed_height` masquerading as low 32
   bits of `value`, next 4 = beginning of raw i64 value) as the
   value field;
2. Read 4 more bytes as height — actually the high 32 bits of value
   plus 0 padding for value MSB;
3. Read 1 byte as `is_coinbase` — actually the `script_type` tag;
4. Misread the script length and payload.

This is silent corruption — no checksum, no magic, no version byte.
The only thing that prevents in-flight breakage is that any single
outpoint is written by ONE path. The current code happens to route
all live-IBD writes through `applyBlockAtomic` and all dbcache-
eviction-driven writes through `ChainState.flush`. There is no
runtime gate that enforces the partition, and no test that exercises
both writers against a single `CF_UTXO` row. **A reorg that
disconnects a block originally written by `ChainState.flush` and
reconnects via `applyBlockAtomic` will produce two on-disk shapes
for the same outpoint over the reorg window**, with the latter
overwriting the former — but if the reorg is interrupted mid-way
and the database is reopened, the surviving entries will be in
mixed format.

## BUG-3 — `Coin.toBytes` (dead `CoinsViewDB` path) uses a *fourth* divergent encoding (P1 — dead-module carry-forward of W107 BUG-3)

**Severity:** P1 (dead module — no production caller, but the bug
class is still present in shipped source).

**File:** `clearbit/src/storage.zig:9203-9219` (encoder),
`clearbit/src/storage.zig:9222-9246` (decoder).

**Core ref:** Same as BUG-1.

**Description:** Carry-forward of **W107 BUG-3** (`tests_w107_-
compactsize.zig:401-432`). `Coin.toBytes` uses `writeCompactSize`
for the coin-code where Core uses VARINT; uses raw `i64` for value
where Core uses VARINT(CompressAmount); uses CompactSize-length-
prefixed raw script bytes where Core uses CompressScript.

```zig
// storage.zig:9203-9219 (dead-path encoding)
pub fn toBytes(self: *const Coin, allocator: std.mem.Allocator) ![]const u8 {
    var writer = serialize.Writer.init(allocator);
    errdefer writer.deinit();
    // Pack height and coinbase flag: height * 2 + coinbase
    const code: u64 = @as(u64, self.height) * 2 + @intFromBool(self.is_coinbase);
    try writer.writeCompactSize(code);      // <-- BUG: Core uses VARINT
    try writer.writeInt(i64, self.tx_out.value);                   // <-- BUG: Core uses VARINT(CompressAmount(value))
    try writer.writeCompactSize(self.tx_out.script_pubkey.len);    // <-- BUG: Core uses ScriptCompression
    try writer.writeBytes(self.tx_out.script_pubkey);
    return writer.toOwnedSlice();
}
```

W107's audit asserted the bug and added a regression test; the
`BlockUndoData` instance was fixed (now uses `writeVarInt`) but the
`Coin.toBytes` instance was never patched. As of 2026-05-18 the
breakage remains exactly as W107 documented — and the carry-forward
is a "re-anchor" pattern (now ~6+ weeks open).

**Impact:** None directly in production (dead module). However,
shippable dead code primes the gun: any future audit that adds a
caller of `CoinsViewCache`/`CoinsViewDB` (e.g. swapping the cache
layer) would silently route writes through this incorrect encoder.
The `compressor.writeCoin` correct-shape encoder is RIGHT THERE,
called by no one in this module. The cleanup is one-line: replace
`writeCompactSize` with `writeVarInt`, route through `compressor.-
writeCoin`. Until then, the W107 BUG-3 carry-forward is now the
**4th-instance "carry-forward re-anchor"** pattern this audit cycle.

## BUG-4 — `CoinsViewDB` / `CoinsViewCache` are entirely dead modules; no production caller (P1 — dead-module fleet pattern)

**Severity:** P1

**File:** `clearbit/src/storage.zig:9333-9826` (~500 LOC of
defined, public, type-complete code).

**Core ref:** `bitcoin-core/src/coins.h::CCoinsViewCache`,
`bitcoin-core/src/txdb.h::CCoinsViewDB`.

**Description:** `CoinsViewDB`, `CoinsViewCache`, `CoinEntry`, and
`OutPointContext` are all defined, exported (`pub const`), have
init/deinit, getCoin/haveCoin/addCoin/spendCoin/flush, a parent-
cache initWithParent constructor, and full doc-comments. They are
referenced ONLY from internal test code (`storage.zig:9970-13352`
test cases) and from `tests_w107_compactsize.zig`. The production
write path uses `UtxoSet` + `ChainStore`. The production read path
uses `UtxoSet.haveCoin` / `chain_store.getUtxo` (returning
`UtxoEntry`, NOT `Coin`).

```
$ grep -rn 'CoinsViewCache\|CoinsViewDB' /home/work/hashhog/clearbit/src/ \
    | grep -v '/storage.zig:' \
    | grep -v '^.*/tests_'
(empty)
```

**Excerpt:** The module defines and tests `flush`, `haveCoin`,
`getCoin`, `spendCoin`, `addCoin`, FRESH/DIRTY semantics — all
correctly named per Core — but the call sites in `sync.zig`,
`validation.zig`, `rpc.zig`, `mempool.zig`, `block_template.zig`,
`main.zig` are all on `UtxoSet` / `ChainStore`. The total dead-code
volume is ~500 LOC of plausibly-Core-shaped logic that no
production block-connect or reorg path will ever exercise.

**Impact:** Architectural confusion plus the W138 / W141 fleet
pattern of "dead-class with full method surface, no production
callers". A future contributor reading `storage.zig` would
plausibly mistake `CoinsViewCache` for the canonical cache layer,
since it has the most Core-faithful naming. Combined with BUG-1 +
BUG-2, the codebase now has four UTXO cache/storage layers (the
two dead `CoinsViewCache`/`CoinsViewDB` + `UtxoSet` + `ChainStore`)
each with its own DIRTY/FRESH tracker, its own encoding, and its
own atomic-flush semantics. Fleet pattern. The mitigation is to
delete the dead module (or wire it in as the canonical cache); the
audit recommendation is to wire it in, deleting `UtxoSet` and
`CompactUtxo` instead — Core-shape compatibility is the goal.

## BUG-5 — `CoinsViewCache.addCoin` only checks OP_RETURN prong of `IsUnspendable`; misses `MAX_SCRIPT_SIZE` (W92 was already-fixed in the live path) (P1 — dead-module)

**Severity:** P1

**File:** `clearbit/src/storage.zig:9596-9599`.

**Core ref:** `bitcoin-core/src/coins.cpp:91` (calls
`IsUnspendable()` which checks `OP_RETURN` first byte OR
`size() > MAX_SCRIPT_SIZE`). `bitcoin-core/src/script/script.h:563`.

**Description:** The dead-module `CoinsViewCache.addCoin` checks
ONLY the OP_RETURN prong, despite W92 having fixed the same bug
in the live `connectBlockInner` path:

```zig
// storage.zig:9596-9599 (CoinsViewCache.addCoin — dead module)
// Check for OP_RETURN (unspendable)
if (coin.tx_out.script_pubkey.len > 0 and coin.tx_out.script_pubkey[0] == 0x6a) {
    return;
}
```

The live production path (storage.zig:4181) DOES call
`isScriptUnspendable` which is the correct two-prong check
(`storage.zig:1870-1874`). The cleanup is one-line: replace the
inline OP_RETURN check with `isScriptUnspendable`.

**Impact:** Two-pipeline guard divergence: the dead `CoinsViewCache`
will admit oversized (>10_000 byte) scripts to the cache where the
live path would reject them. If the dead module is ever wired into
production, this becomes a real bug class. As-is it's a latent
inconsistency that signals copy-paste-without-thinking.

## BUG-6 — RocksDB key prefix mismatch between `makeUtxoKey` (production, 36 bytes no prefix) and `makeCoinsDbKey` (dead module, 37 bytes 'C' prefix); neither matches Core's variable-length `'C' + hash + VARINT(n)` (P0-CDIV)

**Severity:** P0-CDIV

**File:** `clearbit/src/storage.zig:117-123` (production `makeUtxoKey`);
`clearbit/src/storage.zig:9325-9331` (dead `makeCoinsDbKey`).

**Core ref:** `bitcoin-core/src/txdb.cpp:23-48` — `DB_COIN='C'`,
`CoinEntry::SERIALIZE_METHODS(obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }`.

**Description:** clearbit's production CF_UTXO key shape is:

```zig
// storage.zig:117-123 — PRODUCTION
pub fn makeUtxoKey(outpoint: *const types.OutPoint) [36]u8 {
    @setRuntimeSafety(true);
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);  // raw LE u32
    return key;
}
```

NO prefix byte (Core uses `'C'`). Raw `u32` LE (Core uses VARINT,
which for typical small vout indices is 1 byte vs 4 bytes here).

The dead module uses a different shape:

```zig
// storage.zig:9325-9331 — DEAD MODULE
fn makeCoinsDbKey(outpoint: *const types.OutPoint) [37]u8 {
    var key: [37]u8 = undefined;
    key[0] = UTXO_KEY_PREFIX;  // 'C'
    @memcpy(key[1..33], &outpoint.hash);
    std.mem.writeInt(u32, key[33..37], outpoint.index, .little);  // raw LE u32
    return key;
}
```

`'C'` prefix matches Core; but still raw LE u32 vout (vs Core
VARINT). Both clearbit shapes are FIXED-LENGTH; Core's is variable
(34-37 bytes). For a coinbase vout (n=0), Core would write `'C' +
hash + 0x00` = 34 bytes; clearbit-prod writes 36 bytes; clearbit-
dead writes 37 bytes. Three incompatible key shapes.

**Impact:** clearbit's chainstate CF_UTXO is keyed differently from
Core. Cross-impl `dumptxoutset` interop is impossible. Cross-impl
re-IBD-from-existing-chainstate (a maintenance pattern Core users
rely on) is impossible. Single-impl backward compatibility is also
fragile: if `makeUtxoKey` is ever swapped to match Core, every
existing on-disk row becomes unreachable without a migration sweep.

## BUG-7 — `ChainState.flush` and `UtxoSet.flush` and `applyBlockAtomic` use NO obfuscation; Core XORs every value with an 8-byte per-DB obfuscation key (P3)

**Severity:** P3 (cosmetic for clearbit's standalone deployment;
real for any cross-impl portability story)

**File:** `clearbit/src/storage.zig` (entire CF_UTXO write path);
`clearbit/src/storage_rocksdb.zig` (RocksDB binding has no XOR
layer).

**Core ref:** `bitcoin-core/src/dbwrapper.cpp:253-261` + `bitcoin-
core/src/util/obfuscation.h` (8-byte rotating-XOR obfuscation key
stored under leading-`\0` key `"\0obfuscate_key"` (14 bytes) and
XORed against every value on read and write to avoid antivirus
false-positives on scriptPubKey bytes).

**Description:** clearbit does not implement obfuscation. CF_UTXO
values are plaintext on disk. The obfuscation key is also not
generated, written, or read. Any antivirus that pattern-matches on
known-malicious scriptPubKey shapes will see them in plaintext on
a clearbit-mined node's NVMe.

**Excerpt:** Searches turn up nothing:
```
$ grep -n 'obfuscat\|OBFUSCATION\|xor_key' \
    /home/work/hashhog/clearbit/src/storage.zig \
    /home/work/hashhog/clearbit/src/storage_rocksdb.zig
(empty)
```

**Impact:** P3 in isolation (no functional consequence on
consensus). Compounds BUG-1 / BUG-6 / BUG-7 for cross-impl
chainstate portability — even if the key shape and value encoding
matched Core, the XOR layer would still need to be reversed before
read.

## BUG-8 — `BatchWrite` lacks Core's HEAD_BLOCKS atomic-recovery handoff protocol; crash mid-flush leaves DB in undetectable inconsistent state (P0-CDIV)

**Severity:** P0-CDIV

**File:** `clearbit/src/storage.zig:565-660` (`applyBlockAtomic`),
`clearbit/src/storage.zig:4340-4475` (`ChainState.flush`).

**Core ref:** `bitcoin-core/src/txdb.cpp:100-164` (`BatchWrite`):
```cpp
// In the first batch, mark the database as being in the middle of a
// transition from old_tip to hashBlock.
batch.Erase(DB_BEST_BLOCK);
batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));
...
// In the last batch, mark the database as consistent with hashBlock again.
batch.Erase(DB_HEAD_BLOCKS);
batch.Write(DB_BEST_BLOCK, hashBlock);
```
The chainstate writer brackets the per-coin batches with
HEAD_BLOCKS-write-first and HEAD_BLOCKS-erase-last so that a
crash mid-write leaves a detectable "stuck mid-transition" marker
that triggers `-reindex-chainstate`-only recovery (see Core
`CCoinsViewDB::BatchWrite` lines 109-118: detects `old_heads.size()
== 2` and demands recovery).

**Description:** clearbit does not write a HEAD_BLOCKS-equivalent
key. Its `applyBlockAtomic` and `ChainState.flush` build a single
WriteBatch with UTXO ops AND the new tip; the RocksDB writeBatch
is atomic, so partial writes are NOT possible at the database
layer. BUT if the batch is split across multiple writeBatches (Core
splits on `batch.ApproximateSize() > m_options.batch_write_bytes`,
see txdb.cpp:142), the partial-flush window is unprotected.
clearbit does not split — it issues a single writeBatch per flush
— so the practical consequence is currently mitigated by RocksDB
atomicity. However:

1. There is no detection layer if the OS or hardware reorders fsyncs
   across the writeBatch and the WAL files (a real risk on consumer
   NVMe with delayed-allocation file systems).
2. RocksDB itself can defer the actual SST write to later background
   compaction; only the WAL guarantees durability. If the writeBatch
   commits to WAL but the WAL is corrupted by a power event before
   compaction, the recovery story is silent.
3. The single-writeBatch path forces every flush to be all-or-
   nothing memory-wise; for a 4 GiB UTXO cache, this allocates one
   4-GiB batch and burns it once. Core's batch-write_bytes split
   would chunk into ~16-MiB pieces and recover gracefully on any of
   them failing.

**Impact:** Lower-severity than BUG-1/BUG-2 but documented as a
divergence from Core's belt-and-braces approach. A future
opt-in flag to enable batch splitting would expose the missing
HEAD_BLOCKS protocol.

## BUG-9 — `UtxoSet.flush` (the no-parent fallback path) writes UTXOs without updating the chain tip in the same batch (P0)

**Severity:** P0

**File:** `clearbit/src/storage.zig:1353-1430`.

**Core ref:** `bitcoin-core/src/txdb.cpp:100-164` — every
`BatchWrite` takes a `hashBlock` argument and writes it as
`DB_BEST_BLOCK` in the same atomic batch. The tip update is the
LAST batch operation, after all coin writes.

**Description:** `UtxoSet.flush` (line 1353) builds a writeBatch
containing the dirty UTXO puts but does NOT include the chain
tip. The doc-comment on lines 1224-1236 acknowledges that the
TIP-included flush is `ChainState.flush` (line 4340) and that
`UtxoSet.flush` is used when `parent` is null:

```zig
// storage.zig:1224-1236
if (self.parent) |cs| {
    cs.flush() catch |err| {
        std.debug.print("UTXO evictCache: atomic flush failed with {}, skipping eviction\n", .{err});
        return;
    };
} else {
    self.flush() catch |err| {
        std.debug.print("UTXO evictCache: flush failed with {}, skipping eviction to prevent data loss\n", .{err});
        return;
    };
}
```

When `parent == null` (test paths, mining bench fixtures, and
some assumeUTXO bootstrap paths), `UtxoSet.flush` runs. After
that flush returns, the DB has new UTXO bytes but the same old
chain tip recorded under `"chain_tip"`. On crash recovery, the
chainstate is inconsistent: UTXOs reflect height N+1 but the
recorded tip is at height N.

**Impact:** On its own, this is a P1. The reason it's bumped to
P0 is that the `parent: ?*ChainState = null` default is the
constructor default (storage.zig:891) — anyone who creates a
UtxoSet without explicitly wiring the parent reference (or who
forgets to set `parent` after constructing a ChainState that owns
the UtxoSet) silently gets the non-atomic flush path. The wiring is
in `ChainState.init` (around storage.zig:2316/2335) but is an opt-in
side-effect, not a constructor invariant.

## BUG-10 — `OutPointContext.hash` is unsalted; Core's `SaltedOutpointHasher` uses 128-bit per-process random salt (P0-SEC for HashDoS)

**Severity:** P0-SEC

**File:** `clearbit/src/storage.zig:9307-9319`.

**Core ref:** `bitcoin-core/src/util/hasher.cpp:25-37`
(`SaltedOutpointHasher`: `m_k0{FastRandomContext().rand64()},
m_k1{FastRandomContext().rand64()}`, SipHash with random k0/k1).

**Description:** clearbit's HashMap for the (dead) `CoinsViewCache`
uses a fixed multiplier with no salt:

```zig
// storage.zig:9307-9314
pub const OutPointContext = struct {
    pub fn hash(_: OutPointContext, key: types.OutPoint) u64 {
        // Use the first 8 bytes of txid + index for hashing
        var h: u64 = 0;
        h = std.mem.readInt(u64, key.hash[0..8], .little);
        h ^= @as(u64, key.index) *% 0x9e3779b97f4a7c15;
        return h;
    }
    ...
};
```

This is dead code (BUG-4) so production has no current exposure.
HOWEVER, the production-path `UtxoSet.cache` uses `UtxoKeyContext`
(elsewhere in the file) which also has a fixed hash function with
no random salt. An attacker who can predict which OutPoints land in
the same hash bucket can grind the cache HashMap to O(n) lookups,
slowing IBD or live block validation. The cost is low — read Core's
`SaltedOutpointHasher` and copy the SipHash + random-init pattern.

**Excerpt:** Live cache (production, `UtxoKeyContext`) at
`storage.zig` (also fixed multiplier, no per-process salt):
```
$ grep -n 'UtxoKeyContext' /home/work/hashhog/clearbit/src/storage.zig
(definition; uses same fixed-pattern hash)
```

**Impact:** HashDoS. Core ships SipHash with per-process random
k0/k1 specifically to thwart this; clearbit copies the name
("Salted") in the dead module but does NOT salt. Attacker
preparation cost is moderate (compute a few thousand colliding
outpoints offline once, replay them as a flood of tx invs); attack
effect is to slow the victim's IBD or live mempool to a crawl.

## BUG-11 — `CoinsViewCache.flush` writes UTXOs to backing DB but does NOT thread `hashBlock` (P1 — dead-module mirror of BUG-9)

**Severity:** P1

**File:** `clearbit/src/storage.zig:9735-9789`.

**Core ref:** `bitcoin-core/src/coins.cpp:279-299` (CCoinsViewCache::Flush
calls base->BatchWrite(cursor, hashBlock)).

**Description:** The dead-module `flush` calls `db.batchWrite(puts.items,
deletes.items)` — no `hashBlock`. Even if this module were wired up,
it could not produce a Core-shaped chainstate (which always brackets
the per-coin batch with `DB_BEST_BLOCK` and `DB_HEAD_BLOCKS` writes).
This is the dead-module mirror of BUG-9 — they share the same
omission across both clearbit cache layers.

**Excerpt:**
```zig
// storage.zig:9775-9778
} else if (self.base) |db| {
    // Flush to database
    try db.batchWrite(puts.items, deletes.items);   // no hashBlock argument
}
```

The companion `CoinsViewDB.batchWrite` (storage.zig:9387-9432) does
not accept a `hashBlock` parameter at all.

**Impact:** As BUG-4, no current production impact. But the dead
module's interface itself is incompatible with Core's `CCoinsView::
BatchWrite(cursor, hashBlock)` — any future wire-up would have to
extend the signature.

## BUG-12 — No `Cursor()` API on the production UtxoSet/ChainStore; impossible to iterate the UTXO set without holding the entire RocksDB in memory (P1)

**Severity:** P1

**File:** Absent across `storage.zig`. The dead `CoinsViewDB`
defines no cursor either.

**Core ref:** `bitcoin-core/src/txdb.cpp:194-200` — `CCoinsViewDB::
Cursor()` returns a `CCoinsViewDBCursor` that wraps a leveldb
iterator and walks the `'C'`-prefixed range; used by `dumptxoutset`,
`gettxoutsetinfo`, MuHash3072 accumulator, and the snapshot stats
RPC.

**Description:** clearbit can iterate the cache (`UtxoSet.cache.
iterator()` at storage.zig:937 etc.) but cannot iterate the on-
disk CF_UTXO range without an ad-hoc rocksdb_iterator call. There
is no public `iterUtxos` on `ChainStore`. The assumeUTXO dumptxoutset
implementation iterates the in-memory cache only (storage.zig:5419
`utxo_set.cache.iterator()`), which means: if eviction has
already moved live UTXOs to disk, `dumptxoutset` produces an
incomplete snapshot.

**Excerpt:**
```
$ grep -n 'fn cursor\|fn Cursor' /home/work/hashhog/clearbit/src/storage.zig
(empty)
```

**Impact:** `gettxoutsetinfo` and `dumptxoutset` cannot be a
faithful snapshot of the chainstate without a full pre-flush. The
existing pre-flush is unconditional (storage.zig around the
assumeUTXO snapshot path) but the bug is structural — the chain-
state cannot be observed except through the cache layer, which is
not Core's contract.

## BUG-13 — `CompactUtxo.script_type=4` (P2TR) collides with `CompactUtxo.script_type=4` Core compressor tag (uncompressed-P2PK with Y_lsb=0); same byte means different things (P0-CDIV — silent script reconstruction mis-classification)

**Severity:** P0-CDIV

**File:** `clearbit/src/storage.zig:666-687`.

**Core ref:** `bitcoin-core/src/compressor.cpp:33-92` —
`CompressScript` returns tag 4 for `(0x04 | 0)` uncompressed P2PK
with Y_lsb=0; tag 5 for Y_lsb=1.

**Description:** clearbit's `CompactUtxo` uses script_type tags
0..=5 mapped to {P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OTHER}. Core's
`CompressScript` uses tags 0..=5 mapped to {P2PKH, P2SH,
compressed-P2PK-prefix-2, compressed-P2PK-prefix-3, uncompressed-
P2PK-Y_even, uncompressed-P2PK-Y_odd}. The numeric values overlap
but the semantics diverge entirely:

| Tag | clearbit `CompactUtxo` | Core `CompressScript` |
|-----|-------------------------|------------------------|
| 0   | P2PKH                   | P2PKH                  |
| 1   | P2SH                    | P2SH                   |
| 2   | P2WPKH                  | compressed P2PK 0x02   |
| 3   | P2WSH                   | compressed P2PK 0x03   |
| 4   | **P2TR**                | **uncompressed P2PK Y=0** |
| 5   | OTHER                   | uncompressed P2PK Y=1  |

Tags 0/1 are accidentally compatible (P2PKH and P2SH semantics
match). Tags 2..=5 are wholly different.

**Impact:** If a clearbit chainstate is loaded by a Core-shape
decoder (or vice-versa), tag 4 will be reconstructed as a 67-byte
uncompressed-P2PK script (`<65>` push of a 65-byte pubkey + OP_-
CHECKSIG) when it should be a 34-byte P2TR (`OP_1 <32>` v1 SegWit
program), or vice versa. The reconstruction would not throw — it
would silently emit a wrong scriptPubKey, which would then fail
script verification on every spend.

In clearbit's own world this is not a bug (the encoder and decoder
agree). It IS a bug for any future cross-impl chainstate
interchange story, and the tag-number choice is gratuitously
incompatible with Core when an alternative shape would be free
(use tags 6..=10 for P2WPKH/P2WSH/P2TR/OTHER and stay below Core's
N_SPECIAL_SCRIPTS=6 reserved range).

## BUG-14 — `CompactUtxo.script_type=4` (P2TR) stores 32-byte payload as bare hash; Core's compressor does not compress P2TR at all (P1 — encoding-on-the-floor)

**Severity:** P1

**File:** `clearbit/src/storage.zig:680-687`, `703`, `735-770`
(reconstructScript).

**Core ref:** `bitcoin-core/src/compressor.cpp` (`CompressScript`
returns false for P2TR / P2WPKH / P2WSH / any witness program; only
P2PKH/P2SH/P2PK are compressible).

**Description:** clearbit's `CompactUtxo` does compress P2TR /
P2WPKH / P2WSH outputs (script_types 2/3/4). On the wire this
saves 2-3 bytes per output (it elides the `OP_n <push_len>` prefix
bytes). Core does not — Core writes those outputs as raw bytes via
the VARINT(size + 6) escape. The compression scheme is benign and
in-impl consistent, but it's a deliberate deviation from Core's
on-disk shape that compounds BUG-13's incompatibility.

**Impact:** Lower bound: ~3 bytes per P2WPKH/P2WSH/P2TR output of
on-disk space saved (good!). Upper bound: any reader that doesn't
know about clearbit's extension will misread these outputs as
either Core's tag-4/5 (uncompressed P2PK, see BUG-13) or as
unparseable. Cross-impl chainstate interchange is foreclosed by
this independent of BUG-13.

## BUG-15 — `CompactUtxo.height` is silently masked to 31 bits; coinbase flag steals the MSB; coinbase blocks at height ≥ 2^31 (~40,800 years away at current cadence) corrupted on read (P3)

**Severity:** P3

**File:** `clearbit/src/storage.zig:654-718`.

**Core ref:** Core uses `VARINT((height << 1) | coinbase)` which
supports the full 64-bit range; with `height` typed as `int32_t`
in the CTxOut data path, the actual max is `2^31 - 1` blocks (same
bit-budget as clearbit), but Core's encoding doesn't hardcode the
choice into a binary mask.

**Description:** `CompactUtxo.encode` packs `is_coinbase` into the
MSB of `packed_height: u32`:

```zig
// storage.zig:675
const packed_height: u32 = self.height | (if (self.is_coinbase) @as(u32, 1) << 31 else 0);
```

`CompactUtxo.decode` masks:
```zig
// storage.zig:711
.height = packed_height & 0x7FFFFFFF,
.is_coinbase = (packed_height & (1 << 31)) != 0,
```

If `self.height` ever has its bit 31 set (height ≥ `2^31` ≈
2.1 × 10^9, ~40_800 years away at 10-minute blocks), that bit is
overwritten by the coinbase flag and the height is mis-decoded.

**Impact:** P3 (no practical exposure). Noted to document the
implicit invariant for future Y2.1e9 maintainers.

## BUG-16 — `Coin.isSpent` is `value == 0 AND script_pubkey.len == 0`; Core uses `value == -1`-cleared sentinel; produces ambiguity with legitimate zero-value, zero-script outputs (P1 — Core ambiguity-free; clearbit ambiguous)

**Severity:** P1

**File:** `clearbit/src/storage.zig:9183-9186`.

**Core ref:** `bitcoin-core/src/coins.h::Coin::Clear` sets
`nValue = -1` and `nHeight = 0`; `IsSpent` returns `nValue == -1`
which is unambiguous (legitimate UTXOs have `nValue >= 0`).

**Description:** clearbit's `Coin.isSpent`:
```zig
// storage.zig:9183-9186
pub fn isSpent(self: *const Coin) bool {
    return self.tx_out.value == 0 and self.tx_out.script_pubkey.len == 0;
}
```

A legitimate-but-trivial output (`value = 0`, `script_pubkey = []`)
is indistinguishable from a cleared sentinel. Such outputs do not
occur on mainnet (zero-value outputs are non-standard and zero-
length scriptPubKeys are non-relayable), but they CAN occur on
regtest or in unit tests that exercise edge cases. The dead-module
`Coin.clear` (storage.zig:9189-9194) zeroes value and empties
script, which means a deliberately-constructed empty Coin behaves
identically to a cleared Coin.

**Impact:** Dead-module-only as of this audit; if the module is
ever wired up, the ambiguity becomes a real bug class.

## BUG-17 — `CoinsViewCache.addCoin` unconditionally marks new entries as `fresh = true` without checking parent presence; UTXO resurrection risk if `possible_overwrite=false` is paired with an already-flushed parent entry (P1 — dead-module)

**Severity:** P1

**File:** `clearbit/src/storage.zig:9639-9657`.

**Core ref:** `bitcoin-core/src/coins.cpp:89-130` — Core marks
`fresh = !it->second.IsDirty()` ONLY in the existing-cache-entry
branch, and even then only if `!possible_overwrite`. New entries
(not in the cache) get `fresh = !possible_overwrite` derivable from
the assertion that `!coin.IsSpent()` was checked before entry.

**Description:** clearbit's `addCoin` for the new-entry path:
```zig
// storage.zig:9639-9651
} else {
    // New entry - mark as FRESH (doesn't exist in parent)
    const entry = CoinEntry{
        .coin = Coin{ ... },
        .dirty = true,
        .fresh = true,        // <-- unconditionally true
    };
    self.cache.put(outpoint.*, entry) catch return error.OutOfMemory;
    ...
}
```

The comment is wrong: a cache MISS does not imply the parent does
not have the entry — the parent is only consulted via the lazy-
fetch in `getCoin`, not in `addCoin`. A caller that does
`cache.addCoin(outpoint, coin, possible_overwrite=true)` for an
outpoint that exists in the parent DB will now have a `fresh=true`
entry in the cache; if it is subsequently spent before flush, the
FRESH optimization (storage.zig:9682) drops the entry without
issuing the parent-DB delete — so the parent retains the (now-
spent) coin. This is the **UTXO resurrection** bug class.

**Impact:** Dead-module-only as of this audit. If wired up, this
is one of the canonical CCoinsViewCache bug classes Core has
carefully prevented (coins.cpp:107-114 documents the exact
scenario). The fix is one line: derive `fresh = !possible_overwrite`
in the new-entry branch, mirroring Core.

## BUG-18 — `CoinsViewCache.flush` wipes the entire cache after writing dirty entries; Core's `Flush` keeps non-DIRTY entries and only erases the ones it wrote (P2 — performance / cache-warmup loss)

**Severity:** P2

**File:** `clearbit/src/storage.zig:9780-9789`.

**Core ref:** `bitcoin-core/src/coins.cpp` `CCoinsViewCache::Flush`
calls `Sync()` which only erases entries with DIRTY or FRESH;
non-dirty cached entries (clean reads from the parent) survive
across the flush.

**Description:** After writing puts/deletes to the parent or DB,
clearbit's flush:
```zig
// storage.zig:9780-9788
// Clear the cache
var clear_iter = self.cache.iterator();
while (clear_iter.next()) |entry| {
    var e = entry.value_ptr.*;
    e.deinit(self.allocator);
}
self.cache.clearRetainingCapacity();
self.cached_coins_usage = 0;
self.dirty_count = 0;
```

This wipes ALL entries, including clean reads cached from a previous
parent lookup. Subsequent UTXO accesses will re-hit the parent /
DB for every clean entry the cache previously absorbed. Core
preserves clean entries to avoid this re-warm-up cost.

W100 BUG-9 already catalogued this. Carry-forward; cited here for
the dead-module record.

**Impact:** Dead-module. P2 on the live `UtxoSet` analog (the
live cache also wipes-all on `evictCache`/`flush`; the actual
fix would be on both cache layers).

## BUG-19 — Production `UtxoSet` uses `pending_deletes` side-list rather than Core's "dirty + spent + null-coin" cache-entry convention (P1 — semantic divergence)

**Severity:** P1

**File:** `clearbit/src/storage.zig:884` (`pending_deletes`),
`storage.zig:1430-1469` (`flushPendingDeletes`), various
spendUtxo callers.

**Core ref:** `bitcoin-core/src/coins.cpp:153-175` (`SpendCoin`):
on non-FRESH spend, the entry is kept in the cache with
`coin.Clear()` (nValue=-1) and DIRTY set. The deletion to the
parent fires from `BatchWrite` walking dirty + IsSpent entries.

**Description:** clearbit's `UtxoSet` does NOT keep spent-but-
not-flushed entries in the cache. Instead it pushes a copy of
the key onto a `pending_deletes: std.ArrayList([36]u8)` side
list, and `haveCoin` (storage.zig:959) does a LINEAR SCAN of
`pending_deletes` on every DB-fallback lookup:

```zig
// storage.zig:967-972
// First check pending_deletes — if queued for delete, treat
// as spent.  pending_deletes is small (per-block), linear
// scan is fine for the disconnect path.
for (self.pending_deletes.items) |pkey| {
    if (std.mem.eql(u8, &pkey, &key)) return false;
}
```

The comment claims "small (per-block)" — true on a single block
connect, but across a deep reorg `pending_deletes` accumulates
proportional to total spends across all reverted/re-applied
blocks. Each `haveCoin` call is now O(pending_deletes), and
`haveCoin` is called per-input on every transaction validated.

**Impact:** O(n × m) on deep reorgs where n = txin count and
m = pending-deletes queue size. The cleanup is to either:
1. Replace the linear scan with a `HashSet([36]u8)` (one-line);
2. Adopt Core's spent-coin-stays-in-cache convention.

The current implementation is correct, just non-Core and
quadratic in a worst-case.

## BUG-20 — No `PeekCoin` API; every cache lookup populates the cache, including read-only consultations (P2 — cache-pollution / memory-pressure)

**Severity:** P2

**File:** Absent across the production code; `UtxoSet.haveCoin`
(storage.zig:959) does fetch-without-populate IF the DB lookup
succeeds, but `getCoin` always populates.

**Core ref:** `bitcoin-core/src/coins.cpp:44-50` (`PeekCoin`)
returns the cache entry if present but DOES NOT consult or
populate the cache from the base. Used by the mempool to check
input existence without dragging the entire spend-set into the
chainstate cache.

**Description:** clearbit has no read-only inspection API on the
cache. Every `getCoin` populates. The mempool uses
`UtxoSet.haveCoin` (which has a partial peek semantic — it
short-circuits on cache hit) for relay-side input-exists checks,
but any future code path that wants to actually retrieve the Coin
without cache pollution must go straight to `ChainStore.getUtxo`
(which is correct but bypasses the cache and any future
optimisation).

**Impact:** P2 — performance. Core's PeekCoin is specifically
there to keep mempool RBF / package-relay / preimage-replay logic
from polluting the chainstate cache with one-off lookups.

## BUG-21 — `applyBlockAtomic` does not call `isScriptUnspendable`; OP_RETURN and oversized scripts are added to CF_UTXO and then never spent (P0 — UTXO bloat at consensus-correct level, but Core never writes them)

**Severity:** P0

**File:** `clearbit/src/storage.zig:583-601` (`applyBlockAtomic`
UTXO-create loop).

**Core ref:** `bitcoin-core/src/coins.cpp:91` (`AddCoin`
short-circuits on `IsUnspendable()`); also `AddCoins` at line 142
which is the canonical txn→cache wrapper.

**Description:** `applyBlockAtomic` creates a UTXO entry for every
output of every block transaction with no `isScriptUnspendable`
gate:

```zig
// storage.zig:583-600
for (creates) |create| {
    const entry = UtxoEntry{
        .value = create.txout.value,
        .script_pubkey = create.txout.script_pubkey,
        .height = create.height,
        .is_coinbase = create.is_coinbase,
    };
    const data = try entry.toBytes(self.allocator);
    const key = makeUtxoKey(&create.outpoint);
    // ... append to batch ...
}
```

The caller in `sync.zig:1846-1858` is responsible for filtering
unspendable outputs before they reach `pending_creates`. The
filtering is done at `storage.zig:3595` and `4169` and `4962`
(three independent call sites of `isScriptUnspendable`), but
`applyBlockAtomic` itself does not enforce it. A future caller
that forgets the filter would write OP_RETURN and >10_000-byte
scripts to CF_UTXO, bloating the DB indefinitely.

**Impact:** P0 (UTXO bloat) — IF the caller forgets the
pre-filter. Currently mitigated by the three caller-side filters.
The recommendation is to add a defence-in-depth check inside
`applyBlockAtomic` (one line per create), mirroring
Core's `AddCoin` invariant.

## BUG-22 — Three different `flush` paths (`UtxoSet.flush`, `ChainState.flush`, `CoinsViewCache.flush`) each emit a single writeBatch with no size-cap; Core splits on `batch.ApproximateSize() > m_options.batch_write_bytes` (P2)

**Severity:** P2

**File:** `clearbit/src/storage.zig:1353` (UtxoSet.flush),
`storage.zig:4340` (ChainState.flush), `storage.zig:9735`
(CoinsViewCache.flush).

**Core ref:** `bitcoin-core/src/txdb.cpp:142-153` — partial-batch
flush triggered when `batch.ApproximateSize() > m_options.batch_-
write_bytes` (default 16 MiB); critically, it interleaves
`simulate_crash_ratio` check between partial batches for the
`-stopatheight` / fuzz-crash testing matrix.

**Description:** clearbit's three flush paths each build one
arbitrarily-large WriteBatch and issue one `writeBatch` call. On a
fresh-IBD-eviction flush of a full 4 GiB dbcache, this allocates a
~4 GiB batch and burns it in one shot. On any allocator failure
or partial commit, the entire flush rolls back. Core's chunked
flush would absorb the same eviction in ~250 batches of ~16 MiB
each.

**Impact:** Memory-pressure spike during large flushes; on a node
with `dbcache=4096` and a freshly-filled cache, the flush burst
can push RSS to 2x dbcache for the duration. Core's chunking caps
this at ~2 * batch_write_bytes (~32 MiB).

## Fleet-pattern smell

This audit surfaces FIVE distinct fleet patterns clearbit exhibits
in W147:

1. **Dead-module fleet pattern** (W138/W141 canonical) — `CoinsView-
   Cache` + `CoinsViewDB` + their support types `CoinEntry` /
   `OutPointContext` / `makeCoinsDbKey` form a complete ~500 LOC
   parallel cache stack that no production path invokes. The
   dead module exposes the Core-shape DIRTY/FRESH flag semantics
   that the production `UtxoSet` does NOT mirror exactly (BUG-5,
   BUG-11, BUG-17, BUG-18). Identical to the W138 (Chain-
   StateManager dead) / W141 (zmq.rs dead) / W139 (publisher
   dead) shape this campaign has now catalogued in 9+ impls.

2. **Two-pipeline guard fleet pattern (now FOUR pipelines in
   W147)** — production `applyBlockAtomic` + production
   `ChainState.flush` + dead `CoinsViewCache.flush` + dead
   `Coin.toBytes` each emit a DIFFERENT on-disk Coin shape. The
   live production paths (BUG-1, BUG-2) cannot read each other's
   writes; the dead paths (BUG-3) cannot read either; and a fifth
   correct path (`compressor.writeCoin` in `compressor.zig`)
   exists but is wired only to the assumeUTXO snapshot stream
   (`storage.zig:5172`, 5186, 5564). This is the "two-pipeline
   guard" extension to FOUR + ONE = five distinct pipelines.

3. **Carry-forward re-anchor fleet pattern (4th instance)** —
   W107 BUG-3 (CompactSize vs VARINT for the Coin code byte) was
   asserted ~6 weeks ago in `tests_w107_compactsize.zig`; the
   `BlockUndoData` instance was patched; the `Coin.toBytes`
   instance was left open. W147 BUG-3 documents the same defect
   still in tree, the fix still one-line.

4. **Comment-as-confession (1st instance in W147)** — the dead
   `CoinsViewCache.addCoin` (storage.zig:9596) checks ONLY the
   OP_RETURN prong of unspendability with the comment "// Check
   for OP_RETURN (unspendable)" — exactly the pre-W92 bug class
   the documented `isScriptUnspendable` (storage.zig:1862-1870)
   was created to close. The comment confesses the partial fix
   without acknowledging the dead-module duplicate.

5. **Bucket-grid shape mismatch (W139 cross-cite)** — `CompactUtxo`
   tags 4 and 5 collide with Core's compressor tags 4 and 5 with
   ENTIRELY DIFFERENT semantics (BUG-13). Same shape (single byte,
   range 0..=5), wholly different mapping. Identical to W139's
   bucket-grid SHAPE MISMATCH where hotbuns used ~41 buckets vs
   Core's ~235.

The recommendation is to converge on `compressor.writeCoin` as the
single canonical Coin encoding (BUG-1, BUG-2, BUG-3 close at the
same time), wire `CoinsViewCache` + `CoinsViewDB` into production
(BUG-4, BUG-5, BUG-11, BUG-17 close), delete `UtxoSet` /
`CompactUtxo` (BUG-6, BUG-13, BUG-14, BUG-15, BUG-19 close), and
add an obfuscation-key layer (BUG-7). The single-PR cleanup is
large but the underlying primitives are already in tree.

## Out-of-scope (audit-trace only, NOT bugs)

- The `compressor.zig` module is fully Core-faithful (golden round-
  trip tests against Core's `compress_tests.cpp` vectors at lines
  357-378). It is the recommended canonical Coin encoder; W147 only
  flags that it is not wired into the production write path.
- `assumeUTXO` dumptxoutset / loadtxoutset wire-format compatibility
  was audited in W138 separately; W147 does not re-litigate it.
- The W100 audit findings (BUG-5 through BUG-9) on the dead-module
  flush path are carry-forward-cited but not re-numbered here.
- `flushPendingDeletes` (storage.zig:1430) is also non-atomic with
  the tip — but it is called from inside `UtxoSet.flush` (BUG-9)
  which is the same path, so it folds into BUG-9.
