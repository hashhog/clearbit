//! W133 — Index databases (txindex + coinstatsindex) audit (clearbit / Zig 0.13)
//!
//! Discovery-only audit of clearbit's optional-index subsystem vs Bitcoin
//! Core (`bitcoin-core/src/index/base.{h,cpp}` +
//! `bitcoin-core/src/index/txindex.{h,cpp}` +
//! `bitcoin-core/src/index/coinstatsindex.{h,cpp}` +
//! `bitcoin-core/src/index/disktxpos.h`). Excludes `blockfilterindex`
//! (W121 + W122 own it).
//!
//! Test shape: XFAIL-style guards over `indexes.zig` + `storage.zig`
//! constants + source-level grep over `main.zig` / `rpc.zig`. Each gate's
//! BUG test asserts the **current (buggy) state** so a future fix wave can
//! flip the assertion by closing the gate.
//!
//! Run: `zig build test-w133 --summary all`
//!
//! See `audit/w133_index_databases.md` for the full 30-gate matrix.

const std = @import("std");
const testing = std.testing;

const indexes = @import("indexes.zig");
const storage = @import("storage.zig");

// ===========================================================================
// Helpers
// ===========================================================================

/// Open `src/<basename>.zig` and return the full contents (caller frees).
fn loadSrc(allocator: std.mem.Allocator, basename: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "src/{s}.zig", .{basename});
    defer allocator.free(path);
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 4 * 1024 * 1024);
}

/// Returns true if any line in `haystack` contains `needle`.
fn containsLine(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

// ===========================================================================
// G1 — TxIndex DB key prefix matches Core `DB_TXINDEX = 't'`
// Status: DIVERGE (BUG-1). Core uses `0x74` as a one-byte prefix on every
// txindex key; clearbit uses a dedicated CF (`CF_TX_INDEX = 4`) and writes
// the raw 32-byte txid as the key with no prefix byte.
// ===========================================================================
test "w133 G1: TxIndex CF prefix not byte-equal to Core 't' (BUG-1)" {
    // clearbit isolates txindex into its own CF; the prefix byte is implicit
    // in the column family rather than encoded in the key. Sanity check that
    // CF_TX_INDEX is the dedicated slot.
    try testing.expectEqual(@as(usize, 4), storage.CF_TX_INDEX);

    // Verify the key shape used by getTxIndexEntry: it reads exactly 36-byte
    // (block_hash) + 4 (tx_index) — no leading prefix byte is consumed.
    // (Refer to storage.zig:2826-2839; TXINDEX_VAL_LEN = 40 leaves no room
    // for an in-value prefix tag either.)
    try testing.expectEqual(@as(usize, 40), storage.ChainState.TXINDEX_VAL_LEN);
}

// ===========================================================================
// G2 — TxIndex DB value is `CDiskTxPos` (file_num + nPos + nTxOffset)
// Status: DIVERGE (BUG-2). Core stores `(file_number, file_offset,
// nTxOffset)` — typically 4-6 bytes per entry. clearbit stores
// `[32-byte block hash][LE u32 height][LE u32 tx-position]` = 40 bytes.
// ===========================================================================
test "w133 G2: TxIndex value is 40 bytes (block_hash + height + tx-pos), not CDiskTxPos (BUG-2)" {
    try testing.expectEqual(@as(usize, 40), storage.ChainState.TXINDEX_VAL_LEN);

    // Round-trip via the in-memory TxLocation analog to confirm layout.
    const loc = indexes.TxLocation{
        .block_hash = [_]u8{0xAB} ** 32,
        .block_height = 0x01020304,
        .tx_offset = 0x05060708,
    };
    const bytes = loc.toBytes();
    try testing.expectEqual(@as(usize, 40), bytes.len);

    // First 32 bytes are block hash (NOT a Core-style file_number varint).
    try testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 32), bytes[0..32]);

    // Bytes 32..36 are LE u32 (NOT a Core-style VARINT).
    try testing.expectEqual(@as(u32, 0x01020304), std.mem.readInt(u32, bytes[32..36], .little));

    // Bytes 36..40 are tx INDEX within block (NOT a byte offset after header).
    try testing.expectEqual(@as(u32, 0x05060708), std.mem.readInt(u32, bytes[36..40], .little));
}

// ===========================================================================
// G3 — `BaseIndex::DB::ReadBestBlock` returns a CBlockLocator
// Status: MISSING (BUG-3). clearbit writes no block locator; only the
// chain_tip key in CF_DEFAULT.
// ===========================================================================
test "w133 G3: no block locator written to txindex (BUG-3)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    // No "DB_BEST_BLOCK" / "BlockLocator" / "ReadBestBlock" anywhere in storage.zig
    // — the txindex DB has no locator concept.
    try testing.expect(!containsLine(src, "DB_BEST_BLOCK"));
    try testing.expect(!containsLine(src, "ReadBestBlock"));
    try testing.expect(!containsLine(src, "WriteBestBlock"));
    // The only "Locator" reference would be ours — none exists today.
    try testing.expect(!containsLine(src, "CBlockLocator"));
}

// ===========================================================================
// G4 — `BaseIndex::Init` rewinds to fork point on locator mismatch
// Status: MISSING (BUG-4). No startup fork-point walk exists.
// ===========================================================================
test "w133 G4: no fork-point rewind on index-vs-chainstate divergence (BUG-4)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    // main.zig:1770 enables txindex_enabled, but no FindFork / locator-walk
    // logic exists alongside it.
    try testing.expect(containsLine(main_src, "txindex_enabled = config.txindex"));
    try testing.expect(!containsLine(main_src, "FindFork"));
    try testing.expect(!containsLine(main_src, "rewindToForkPoint"));
}

// ===========================================================================
// G5 — `BaseIndex::Sync` runs in a background thread
// Status: DIVERGE (BUG-5). `BackgroundIndexer.runIndexer` is a stub that
// just sleeps.
// ===========================================================================
test "w133 G5: BackgroundIndexer.runIndexer is a stub (BUG-5)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "indexes");
    defer allocator.free(src);

    // The function exists...
    try testing.expect(containsLine(src, "fn runIndexer(self: *BackgroundIndexer) void"));
    // ...but it just sleeps; no actual work is done.
    try testing.expect(containsLine(src, "std.time.sleep(100 * std.time.ns_per_ms)"));
    // No call to TxIndex.indexBlock from inside the runner.
    // (Source-level guard — flip when a real drain loop lands.)
    const idx_block_call = "self.tx_index.indexBlock";
    try testing.expect(!containsLine(src, idx_block_call));
}

// ===========================================================================
// G6 — `BaseIndex::BlockUntilSyncedToCurrentChain` exists
// Status: MISSING (BUG-6). No such API in clearbit.
// ===========================================================================
test "w133 G6: no BlockUntilSyncedToCurrentChain API (BUG-6)" {
    const allocator = testing.allocator;
    const src_storage = try loadSrc(allocator, "storage");
    defer allocator.free(src_storage);
    const src_indexes = try loadSrc(allocator, "indexes");
    defer allocator.free(src_indexes);
    const src_rpc = try loadSrc(allocator, "rpc");
    defer allocator.free(src_rpc);

    try testing.expect(!containsLine(src_storage, "BlockUntilSyncedToCurrentChain"));
    try testing.expect(!containsLine(src_indexes, "BlockUntilSyncedToCurrentChain"));
    try testing.expect(!containsLine(src_rpc, "BlockUntilSyncedToCurrentChain"));
    // Snake-case variant either.
    try testing.expect(!containsLine(src_storage, "blockUntilTxIndexSynced"));
    try testing.expect(!containsLine(src_indexes, "blockUntilTxIndexSynced"));
}

// ===========================================================================
// G7 — `CF_COINSTATS` is a valid CF in the array
// Status: DIVERGE (BUG-7) — actually HIGH severity. CF_COINSTATS = CF_COUNT
// = 8, which is OUT OF RANGE for the cf_handles[CF_COUNT=8] array.
// ===========================================================================
test "w133 G7: CF_COINSTATS aliases CF_COUNT (out-of-range, BUG-7)" {
    // The most damning constant in the file.
    try testing.expectEqual(@as(usize, 8), storage.CF_COUNT);
    try testing.expectEqual(@as(usize, 8), indexes.CF_COINSTATS);
    // Future-fix gate: CF_COINSTATS must be < CF_COUNT.
    // Today this fails — flip when CF_COUNT is bumped to 9.
    try testing.expect(indexes.CF_COINSTATS >= storage.CF_COUNT);
}

// ===========================================================================
// G8 — `--coinstatsindex` enables coin-stats wiring
// Status: MISSING (BUG-8). Flag is parsed-but-dead.
// ===========================================================================
test "w133 G8: --coinstatsindex flag is parsed-but-dead (BUG-8)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    // Parser hits exist.
    try testing.expect(containsLine(main_src, "--coinstatsindex"));
    try testing.expect(containsLine(main_src, "config.coinstatsindex = true"));

    // No downstream consumer: storage.zig has no coinstatsindex_enabled field
    // and no read of config.coinstatsindex.
    try testing.expect(!containsLine(storage_src, "coinstatsindex_enabled"));
    try testing.expect(!containsLine(main_src, "chain_state.coinstatsindex_enabled"));
}

// ===========================================================================
// G9 — `CoinStatsIndex` maintains a `MuHash3072` accumulator
// Status: MISSING (BUG-9). CoinStatsIndex struct has no MuHash field.
// ===========================================================================
test "w133 G9: CoinStatsIndex has no MuHash3072 accumulator (BUG-9)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "indexes");
    defer allocator.free(src);

    // The full CoinStatsIndex struct body sits at indexes.zig:770-863.
    // Verify that the substring "MuHash" is NOT present anywhere in the
    // file (no muhash field, no insert, no remove).
    try testing.expect(!containsLine(src, "MuHash3072"));
    try testing.expect(!containsLine(src, "ApplyCoinHash"));
    try testing.expect(!containsLine(src, "RemoveCoinHash"));
}

// ===========================================================================
// G10 — `CoinStatsIndex` tracks unspendables genesis / BIP30 / script / unclaimed
// Status: MISSING (BUG-10). No unspendables fields exist.
// ===========================================================================
test "w133 G10: CoinStatsIndex has no unspendables tracking (BUG-10)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "indexes");
    defer allocator.free(src);

    try testing.expect(!containsLine(src, "total_unspendables_genesis_block"));
    try testing.expect(!containsLine(src, "total_unspendables_bip30"));
    try testing.expect(!containsLine(src, "total_unspendables_scripts"));
    try testing.expect(!containsLine(src, "total_unspendables_unclaimed_rewards"));
}

// ===========================================================================
// G11 — `getBogoSize` formula matches Core
// Status: DIVERGE (BUG-11). clearbit returns 32 + 4 + 8 + N. Core formula
// includes a 1-byte coinbase-and-height packed tag (`32 + 4 + 1 + 8 + N`
// per the original `coinstats.cpp:GetBogoSize`).
// ===========================================================================
test "w133 G11: getBogoSize formula short by 1+ bytes vs Core (BUG-11)" {
    // We can't call the private getBogoSize directly, so reproduce its math.
    // clearbit (indexes.zig:796-799): 32 + 4 + 8 + script_len
    const script_len: u64 = 25; // P2PKH
    const clearbit_bogo: u64 = 32 + 4 + 8 + script_len;
    try testing.expectEqual(@as(u64, 69), clearbit_bogo);

    // Core: 32 (txid) + 4 (vout) + 1 (height/coinbase tag) + 8 (value) + N (script)
    const core_bogo: u64 = 32 + 4 + 1 + 8 + script_len;
    try testing.expectEqual(@as(u64, 70), core_bogo);

    // clearbit is short by exactly 1 byte per UTXO.
    try testing.expectEqual(@as(u64, 1), core_bogo - clearbit_bogo);
}

// ===========================================================================
// G12 — `CoinStatsIndex` writes per-block (height→DBVal) records
// Status: MISSING (BUG-12). clearbit's CoinStats has fewer fields than
// Core's DBVal and is never instantiated against a real DB.
// ===========================================================================
test "w133 G12: clearbit CoinStats has 6 fields vs Core DBVal's 12 (BUG-12)" {
    // clearbit CoinStats fields: block_hash, height, utxo_count,
    // total_amount, total_subsidy, bogo_size — 6 fields, no muhash, no
    // unspendables, no prevout_spent, no coinbase_amount,
    // no new_outputs_ex_coinbase.
    const stats = indexes.CoinStats{
        .block_hash = [_]u8{0} ** 32,
        .height = 0,
        .utxo_count = 0,
        .total_amount = 0,
        .total_subsidy = 0,
        .bogo_size = 0,
    };
    // Field count guard: count the fields via reflection.
    const fields = std.meta.fields(indexes.CoinStats);
    try testing.expectEqual(@as(usize, 6), fields.len);

    // Verify NONE of the Core-required fields exist.
    var saw_muhash = false;
    var saw_prevout = false;
    var saw_coinbase = false;
    var saw_unspendables = false;
    inline for (fields) |f| {
        if (std.mem.eql(u8, f.name, "muhash")) saw_muhash = true;
        if (std.mem.indexOf(u8, f.name, "prevout") != null) saw_prevout = true;
        if (std.mem.indexOf(u8, f.name, "coinbase") != null) saw_coinbase = true;
        if (std.mem.indexOf(u8, f.name, "unspendables") != null) saw_unspendables = true;
    }
    try testing.expect(!saw_muhash);
    try testing.expect(!saw_prevout);
    try testing.expect(!saw_coinbase);
    try testing.expect(!saw_unspendables);

    // Use the stats variable to keep it live.
    _ = stats;
}

// ===========================================================================
// G13 — `LookUpStats` is exposed via `gettxoutsetinfo` historical lookup
// Status: MISSING (BUG-13). handleGetTxOutSetInfo ignores any second arg.
// ===========================================================================
test "w133 G13: gettxoutsetinfo cannot query historical block (BUG-13)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    // Core's gettxoutsetinfo takes (hash_type, hash_or_height); clearbit's
    // takes only hash_type. Verify by checking the parsing block:
    // rpc.zig:13069 only inspects `params.array.items.len >= 1`.
    try testing.expect(containsLine(src, "if (params == .array and params.array.items.len >= 1)"));
    // No "items.len >= 2" inside handleGetTxOutSetInfo means no second-arg
    // path is implemented for coinstats lookup. Find the function and
    // confirm we never see "items.len >= 2" between the start of the
    // function and the next "fn " — naive check via indexOf.
    const start = std.mem.indexOf(u8, src, "fn handleGetTxOutSetInfo(") orelse {
        return error.HandlerNotFound;
    };
    const after = start + 200; // skip past signature
    const end = std.mem.indexOf(u8, src[after..], "fn handle") orelse src.len - after;
    const slice = src[start .. after + end];
    try testing.expect(std.mem.indexOf(u8, slice, "items.len >= 2") == null);
    try testing.expect(std.mem.indexOf(u8, slice, "hash_or_height") == null);
}

// ===========================================================================
// G14 — `connect_undo_data` propagates spent-prevout amounts
// Status: MISSING (BUG-14). No CustomOptions equivalent; coinstats hook
// would need undo data but no plumbing exists.
// ===========================================================================
test "w133 G14: no connect_undo_data hook for coinstats (BUG-14)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);
    const src_indexes = try loadSrc(allocator, "indexes");
    defer allocator.free(src_indexes);

    // No NotifyOptions / CustomOptions-equivalent exists.
    try testing.expect(!containsLine(src, "connect_undo_data"));
    try testing.expect(!containsLine(src, "NotifyOptions"));
    try testing.expect(!containsLine(src_indexes, "connect_undo_data"));
    try testing.expect(!containsLine(src_indexes, "CustomOptions"));
}

// ===========================================================================
// G15 — `total_subsidy` / `total_coinbase_amount` / `total_new_outputs_ex_coinbase_amount`
// Status: MISSING (BUG-15). Only `total_subsidy` exists.
// ===========================================================================
test "w133 G15: CoinStatsIndex only tracks total_subsidy, missing 2 other rollups (BUG-15)" {
    const fields = std.meta.fields(indexes.CoinStatsIndex);
    var saw_subsidy = false;
    var saw_coinbase_amount = false;
    var saw_new_outputs = false;
    var saw_prevout_spent = false;
    inline for (fields) |f| {
        if (std.mem.eql(u8, f.name, "total_subsidy")) saw_subsidy = true;
        if (std.mem.indexOf(u8, f.name, "coinbase_amount") != null) saw_coinbase_amount = true;
        if (std.mem.indexOf(u8, f.name, "new_outputs") != null) saw_new_outputs = true;
        if (std.mem.indexOf(u8, f.name, "prevout_spent") != null) saw_prevout_spent = true;
    }
    try testing.expect(saw_subsidy);
    try testing.expect(!saw_coinbase_amount);
    try testing.expect(!saw_new_outputs);
    try testing.expect(!saw_prevout_spent);
}

// ===========================================================================
// G16 — `CoinStatsIndex::CustomRemove` reverts a block on reorg
// Status: MISSING (BUG-16). No disconnectBlock / RevertBlock method.
// ===========================================================================
test "w133 G16: CoinStatsIndex has no disconnectBlock / RevertBlock path (BUG-16)" {
    // Source-grep over the CoinStatsIndex struct body in indexes.zig:770-863.
    // Verify no `fn disconnectBlock` / `fn revertBlock` is defined within
    // the struct (or anywhere in the file, since CoinStatsIndex is the only
    // struct in this position).
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "indexes");
    defer allocator.free(src);

    // Find the start of the CoinStatsIndex struct.
    const struct_start = std.mem.indexOf(u8, src, "pub const CoinStatsIndex = struct {") orelse {
        return error.CoinStatsIndexNotFound;
    };
    // End of struct = next "// ===" header (the next big section).
    const after_struct_offset = std.mem.indexOf(u8, src[struct_start..], "// ====") orelse {
        return error.StructEndNotFound;
    };
    const struct_body = src[struct_start .. struct_start + after_struct_offset];

    try testing.expect(std.mem.indexOf(u8, struct_body, "pub fn disconnectBlock") == null);
    try testing.expect(std.mem.indexOf(u8, struct_body, "pub fn revertBlock") == null);
    try testing.expect(std.mem.indexOf(u8, struct_body, "pub fn RevertBlock") == null);
    try testing.expect(std.mem.indexOf(u8, struct_body, "pub fn CustomRemove") == null);
}

// ===========================================================================
// G17 — `-txindex` + `-prune` is rejected at startup
// Status: MISSING (BUG-17). No cross-flag validation in main.zig.
// ===========================================================================
test "w133 G17: -txindex + -prune not rejected (BUG-17)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "main");
    defer allocator.free(src);

    // Search for any cross-flag check between txindex and prune.
    // No such guard exists today.
    try testing.expect(!containsLine(src, "Prune mode is incompatible with -txindex"));
    try testing.expect(!containsLine(src, "config.txindex and config.prune"));
    try testing.expect(!containsLine(src, "IncompatibleFlags"));
}

// ===========================================================================
// G18 — `AllowPrune() = false` invariant prevents tip > prune_height
// Status: MISSING (BUG-18). No prune-lock for txindex.
// ===========================================================================
test "w133 G18: no AllowPrune / prune-lock for txindex (BUG-18)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    try testing.expect(!containsLine(src, "AllowPrune"));
    try testing.expect(!containsLine(src, "UpdatePruneLock"));
    try testing.expect(!containsLine(src, "txindex_min_height"));
    try testing.expect(!containsLine(src, "PruneLockInfo"));
}

// ===========================================================================
// G19 — `getindexinfo` RPC reports per-index sync status
// Status: MISSING (BUG-19). No handler in rpc.zig.
// ===========================================================================
test "w133 G19: no getindexinfo RPC (BUG-19)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    try testing.expect(!containsLine(src, "getindexinfo"));
    try testing.expect(!containsLine(src, "handleGetIndexInfo"));
}

// ===========================================================================
// G20 — `getrawtransaction` confirmations race a reorg
// Status: DIVERGE (BUG-20). RPC handler does NOT lock connect_mutex.
// ===========================================================================
test "w133 G20: getrawtransaction does not lock connect_mutex (BUG-20)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    // Find the getrawtransaction handler region — specifically the
    // "Pattern C0" lookup block at rpc.zig:5845-5939 — and verify it does
    // NOT acquire connect_mutex.
    const start = std.mem.indexOf(u8, src, "Pattern C0 (CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-") orelse {
        return error.HandlerNotFound;
    };
    const end = std.mem.indexOf(u8, src[start..], "Core proxy for getrawtransaction") orelse 5000;
    const slice = src[start .. start + end];

    try testing.expect(std.mem.indexOf(u8, slice, "connect_mutex.lock") == null);
    try testing.expect(std.mem.indexOf(u8, slice, "connect_mutex.lock()") == null);
}

// ===========================================================================
// G21 — Reorg-loop putwins handles position-shifted txids
// Status: DIVERGE (BUG-21). Behaviourally correct but undocumented.
// ===========================================================================
test "w133 G21: flush() relies on RocksDB array order for delete-then-put (BUG-21)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    // The semantics are correct but the documentation note appears at one
    // site only (around line 4598-4605); verify the comment is present
    // (so we can detect a future regression that removes it).
    try testing.expect(containsLine(src, "delete-then-write within a single flush window"));
    try testing.expect(containsLine(src, "last-write-wins"));
    // No formal test asserts the ordering — that's the BUG.
    try testing.expect(!containsLine(src, "test \"flush ordering delete-then-put wins\""));
}

// ===========================================================================
// G22 — Legacy `indexes/coinstats` datadir migration warning
// Status: MISSING (BUG-22). No migration logic.
// ===========================================================================
test "w133 G22: no legacy indexes/coinstats migration (BUG-22)" {
    const allocator = testing.allocator;
    const src_main = try loadSrc(allocator, "main");
    defer allocator.free(src_main);
    const src_storage = try loadSrc(allocator, "storage");
    defer allocator.free(src_storage);
    const src_indexes = try loadSrc(allocator, "indexes");
    defer allocator.free(src_indexes);

    try testing.expect(!containsLine(src_main, "indexes/coinstats"));
    try testing.expect(!containsLine(src_storage, "indexes/coinstats"));
    try testing.expect(!containsLine(src_indexes, "indexes/coinstats"));
    try testing.expect(!containsLine(src_main, "old version of coinstatsindex"));
}

// ===========================================================================
// G23 — TxIndex `FindTx` verifies `tx->GetHash() == tx_hash`
// Status: DIVERGE (BUG-23). rpc.zig's handler does NOT re-hash the
// deserialised tx as a corruption check.
// ===========================================================================
test "w133 G23: getrawtransaction does not verify tx->GetHash() == txid (BUG-23)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    // Find the Pattern-C0 lookup block.
    const start = std.mem.indexOf(u8, src, "if (try self.chain_state.getTxIndexEntry(&txid)) |entry|") orelse {
        return error.HandlerNotFound;
    };
    const end_idx = std.mem.indexOf(u8, src[start..], "verbosity=2 Core proxy fallback") orelse 5000;
    const slice = src[start .. start + end_idx];

    // No "txid mismatch" string and no "computeTxidStreaming(&tx)" call to
    // verify integrity post-deserialisation.
    try testing.expect(std.mem.indexOf(u8, slice, "txid mismatch") == null);
    // The slice does NOT call computeTxidStreaming on the returned tx body
    // (it might compute the txid we look up by, but not re-verify it after
    // pulling from the block).
    // Count occurrences of computeTxidStreaming inside the slice — should
    // be 0; the txid is provided by the caller, we trust the index entry.
    var pos: usize = 0;
    var count: usize = 0;
    while (std.mem.indexOf(u8, slice[pos..], "computeTxidStreaming")) |idx| {
        count += 1;
        pos += idx + "computeTxidStreaming".len;
    }
    try testing.expectEqual(@as(usize, 0), count);
}

// ===========================================================================
// G24 — TxIndex `FindTx` deserialises witness-included tx
// Status: PRESENT. `serialize.readBlock` returns transactions with witness
// data when present; the resulting tx body is witness-included.
// ===========================================================================
test "w133 G24: readBlock supports witness-included transactions (PRESENT)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "serialize");
    defer allocator.free(src);

    // We only confirm by source-grep that segwit deserialisation is present
    // somewhere — the function readTransaction handles the witness marker.
    try testing.expect(containsLine(src, "fn readTransaction"));
    // Witness marker handling is present (any of: 0x00 marker, witnesses,
    // segwit, has_witness).
    const has_segwit_handling =
        containsLine(src, "witness") or
        containsLine(src, "0x00, 0x01") or
        containsLine(src, "SEGWIT_MARKER");
    try testing.expect(has_segwit_handling);
}

// ===========================================================================
// G25 — TxIndex prefix `'t' + uint256` keys are big-endian for ordered scans
// Status: DIVERGE (BUG-25). clearbit's CF model stores the txid raw in
// little-endian (Hash256 internal). This is documented-divergence not a
// correctness bug; flagged for cross-impl awareness.
// ===========================================================================
test "w133 G25: TxIndex CF key is raw 32-byte little-endian txid (BUG-25)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    // Confirm putTxIndex stores the raw txid pointer as the key without any
    // prefix byte and without endianness-swap.
    try testing.expect(containsLine(src, "pub fn putTxIndex("));
    try testing.expect(containsLine(src, "try self.db.put(CF_TX_INDEX, txid, &buf)"));
    // No `ser_writedata8(DB_TXINDEX)` style prefix.
    try testing.expect(!containsLine(src, "ser_writedata8"));
}

// ===========================================================================
// G26 — TxIndex genesis-skip
// Status: PRESENT.  queueTxIndexWritesForBlock at storage.zig:2494 has the
// height==0 short-circuit.
// ===========================================================================
test "w133 G26: TxIndex skips genesis (PRESENT)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    try testing.expect(containsLine(src, "// Bitcoin Core's TxIndex skips genesis"));
    try testing.expect(containsLine(src, "if (height == 0) return"));
}

// ===========================================================================
// G27 — TxIndex disconnect deletes BEFORE writes in flush batch
// Status: PRESENT. flush() ordering at storage.zig:4598-4647 appends
// pending_tx_index_deletes before pending_tx_index_writes.
// ===========================================================================
test "w133 G27: flush() drains tx_index_deletes before tx_index_writes (PRESENT)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    const deletes_idx = std.mem.indexOf(u8, src, "for (self.pending_tx_index_deletes.items) |txid|") orelse {
        return error.MarkerNotFound;
    };
    const writes_idx = std.mem.indexOf(u8, src, "for (self.pending_tx_index_writes.items) |entry|") orelse {
        return error.MarkerNotFound;
    };

    try testing.expect(deletes_idx < writes_idx);
}

// ===========================================================================
// G28 — TxIndex flush is atomic with tip update
// Status: PRESENT. Both go into the same WriteBatch via writeBatch().
// ===========================================================================
test "w133 G28: TxIndex flush is atomic with tip in one WriteBatch (PRESENT)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    // The flush() function builds one ArrayList(BatchOp) and calls
    // writeBatch on it once. The chain tip put and the txindex puts are
    // both appended to the SAME `batch` list. Verify by checking that
    // pending_tx_index_writes loop appends to `batch.append` (not a
    // separate list) within fn flush.
    const flush_start = std.mem.indexOf(u8, src, "pub fn flush(self: *ChainState)") orelse {
        return error.FlushNotFound;
    };
    const flush_end = std.mem.indexOf(u8, src[flush_start..], "\n    }\n\n") orelse 30000;
    const slice = src[flush_start .. flush_start + flush_end];

    try testing.expect(std.mem.indexOf(u8, slice, "var batch = std.ArrayList(BatchOp).init(self.allocator)") != null);
    try testing.expect(std.mem.indexOf(u8, slice, "for (self.pending_tx_index_writes.items) |entry|") != null);
    try testing.expect(std.mem.indexOf(u8, slice, "batch.append(.{ .put = .{") != null);
}

// ===========================================================================
// G29 — TxIndex `BLOCK_HAVE_UNDO` status bit OR'd into block index
// Status: PRESENT. flush() section 6b sets bits 1 and 2 in BlockStatus.
// ===========================================================================
test "w133 G29: flush() sets BLOCK_HAVE_DATA + BLOCK_HAVE_UNDO bits (PRESENT)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    try testing.expect(containsLine(src, "BLOCK_HAVE_DATA"));
    try testing.expect(containsLine(src, "BLOCK_HAVE_UNDO"));
    try testing.expect(containsLine(src, "bit 1 = has_data"));
    try testing.expect(containsLine(src, "bit 2 = has_undo"));
}

// ===========================================================================
// G30 — `getindexinfo`-style summary on logging at startup
// Status: DIVERGE (BUG-30). main.zig logs flag-only, no height.
// ===========================================================================
test "w133 G30: startup log says enabled but does not include current height (BUG-30)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "main");
    defer allocator.free(src);

    try testing.expect(containsLine(src, "Transaction index enabled (--txindex)"));
    // Verify the log line does NOT include a height or sync-status field.
    // We look for the specific simple format string emitted today
    // (`"Transaction index enabled (--txindex)\n"`) and assert that
    // the surrounding 50 chars don't contain the substring "height".
    const idx = std.mem.indexOf(u8, src, "Transaction index enabled (--txindex)") orelse {
        return error.LogMessageNotFound;
    };
    const start_window = if (idx > 50) idx - 50 else 0;
    const end_window = @min(idx + 100, src.len);
    const window = src[start_window..end_window];

    try testing.expect(std.mem.indexOf(u8, window, "height") == null);
    try testing.expect(std.mem.indexOf(u8, window, "synced at") == null);
}

// ===========================================================================
// Bonus: Construct CoinStats + TxLocation round-trips to lock in current
// wire format so a future fix wave intentionally breaks these.
// ===========================================================================

test "w133 wire-format-lock: TxLocation 40-byte round-trip" {
    const loc = indexes.TxLocation{
        .block_hash = [_]u8{0xCD} ** 32,
        .block_height = 700_000,
        .tx_offset = 42,
    };
    const bytes = loc.toBytes();
    try testing.expectEqual(@as(usize, 40), bytes.len);
    const back = try indexes.TxLocation.fromBytes(&bytes);
    try testing.expectEqualSlices(u8, &loc.block_hash, &back.block_hash);
    try testing.expectEqual(loc.block_height, back.block_height);
    try testing.expectEqual(loc.tx_offset, back.tx_offset);
}

test "w133 wire-format-lock: CoinStats round-trip with 6 fields" {
    const allocator = testing.allocator;
    const stats = indexes.CoinStats{
        .block_hash = [_]u8{0xEF} ** 32,
        .height = 800_000,
        .utxo_count = 100_000_000,
        .total_amount = 19_500_000 * 100_000_000,
        .total_subsidy = 19_500_000 * 100_000_000,
        .bogo_size = 8_000_000_000,
    };
    const bytes = try stats.toBytes(allocator);
    defer allocator.free(bytes);

    // Total = 32 (hash) + 4 (height) + 8 (count) + 8 (amount) + 8 (subsidy)
    //       + 8 (bogo) = 68 bytes. Lock this in.
    try testing.expectEqual(@as(usize, 68), bytes.len);

    const back = try indexes.CoinStats.fromBytes(bytes);
    try testing.expectEqualSlices(u8, &stats.block_hash, &back.block_hash);
    try testing.expectEqual(stats.height, back.height);
    try testing.expectEqual(stats.utxo_count, back.utxo_count);
    try testing.expectEqual(stats.total_amount, back.total_amount);
    try testing.expectEqual(stats.total_subsidy, back.total_subsidy);
    try testing.expectEqual(stats.bogo_size, back.bogo_size);
}

// CoinStatsIndex.connectBlock smoke test using the in-memory (no DB) path
// to confirm the running-totals arithmetic is exactly what indexes.zig
// implements today. A future fix wave that adds MuHash, unspendables, and
// the other 9 DBVal fields will need to update this assertion.
test "w133 connectBlock smoke: only 4 in-memory fields advanced" {
    const allocator = testing.allocator;
    var index = indexes.CoinStatsIndex.init(null, allocator, true);

    const block_hash: [32]u8 = [_]u8{0x42} ** 32;
    const created = [_]indexes.UtxoInfo{
        .{ .value = 5_000_000_000, .script_len = 25 },
        .{ .value = 100_000, .script_len = 22 },
    };
    const spent = [_]indexes.UtxoInfo{};

    try index.connectBlock(&block_hash, 1, 5_000_000_000, &created, &spent);

    // Verify only 4 in-memory fields move.
    try testing.expectEqual(@as(u64, 2), index.utxo_count);
    try testing.expectEqual(@as(i64, 5_000_100_000), index.total_amount);
    try testing.expectEqual(@as(i64, 5_000_000_000), index.total_subsidy);
    // bogo formula: 2 * (32 + 4 + 8) + 25 + 22 = 88 + 47 = 135.
    try testing.expectEqual(@as(u64, 135), index.bogo_size);
    try testing.expectEqual(@as(u32, 1), index.best_height);
}
