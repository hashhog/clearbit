//! W138 — assumeUTXO snapshots audit (clearbit / Zig 0.13)
//!
//! Discovery-only audit of clearbit's assumeUTXO snapshot subsystem vs
//! Bitcoin Core:
//!   bitcoin-core/src/node/utxo_snapshot.{h,cpp}
//!   bitcoin-core/src/validation.cpp (ActivateSnapshot,
//!     PopulateAndValidateSnapshot, MaybeValidateSnapshot,
//!     InvalidateCoinsDBOnDisk, MaybeRebalanceCaches,
//!     LoadBlockIndexDB)
//!   bitcoin-core/src/rpc/blockchain.cpp (dumptxoutset, loadtxoutset,
//!     getchainstates, PrepareUTXOSnapshot, WriteUTXOSnapshot)
//!
//! BIPs: none (assumeUTXO is a Bitcoin Core implementation feature).
//!
//! Test shape: a mixture of source-level grep guards over `storage.zig`
//! + `main.zig` + `rpc.zig` + `consensus.zig` (asserts a Core-named
//! string is absent / present per the current buggy state — flip when
//! wired) AND a few behavioural assertions on `dumpTxOutSet` +
//! `loadTxOutSet` + `validateAndLoadSnapshot` to pin the cross-path
//! divergences (BUG-1 / BUG-8). Each gate's BUG test asserts the
//! **current (buggy) state** so a future fix wave flips the assertion
//! by closing the gate.
//!
//! Run: `zig build test-w138 --summary all`
//!
//! See `audit/w138_assumeutxo.md` for the full 30-gate matrix and prose.

const std = @import("std");
const testing = std.testing;

const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");

// ===========================================================================
// Helpers
// ===========================================================================

/// Open `src/<basename>.zig` and return the full contents (caller frees).
fn loadSrc(allocator: std.mem.Allocator, basename: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "src/{s}.zig", .{basename});
    defer allocator.free(path);
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 32 * 1024 * 1024);
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var idx: usize = 0;
    while (idx + needle.len <= haystack.len) {
        if (std.mem.eql(u8, haystack[idx .. idx + needle.len], needle)) {
            count += 1;
            idx += needle.len;
        } else {
            idx += 1;
        }
    }
    return count;
}

/// Build a P2PKH script template (25 bytes).
fn p2pkh() [25]u8 {
    var spk: [25]u8 = undefined;
    spk[0] = 0x76;
    spk[1] = 0xa9;
    spk[2] = 20;
    @memset(spk[3..23], 0xCC);
    spk[23] = 0x88;
    spk[24] = 0xac;
    return spk;
}

// ===========================================================================
// G1 — CLI --load-snapshot enforces hash_serialized content-hash gate
// Status: MISSING (BUG-1). Only RPC/in-memory path enforces it.
// ===========================================================================
test "w138 G1: CLI --load-snapshot path lacks hash_serialized content-hash gate (BUG-1)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "main");
    defer allocator.free(src);

    // The CLI loader is `loadSnapshotFromFile`.
    try testing.expect(contains(src, "fn loadSnapshotFromFile"));

    // It validates magic / version / network / per-coin MoneyRange /
    // height — confirmed by these greps:
    try testing.expect(contains(src, "SnapshotMetadata.fromBytes"));
    try testing.expect(contains(src, "findAssumeUtxoEntry"));
    try testing.expect(contains(src, "isValidMoney(amount)"));
    try testing.expect(contains(src, "utxo_height > block_height"));

    // BUT: it does NOT call `computeHashSerializedTxOutSet` over the
    // imported coins. That function exists in storage.zig but is not
    // referenced from main.zig at all.
    try testing.expect(!contains(src, "computeHashSerializedTxOutSet"));
    // And it doesn't compare against `assume_entry.hash_serialized`
    // anywhere in the body.
    try testing.expect(!contains(src, "assume_entry.?.hash_serialized"));
    try testing.expect(!contains(src, "expected_entry.hash_serialized"));
    // The in-memory path (storage.zig) DOES have it — sanity check.
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    try testing.expect(contains(storage_src, "assume_entry.hash_serialized"));
}

// ===========================================================================
// G1 behavioral — validateAndLoadSnapshot rejects garbage UTXOs; CLI would not
// We can't easily exercise the CLI path in a unit test (it calls
// std.process.exit on error), but we can pin the asymmetry: the RPC/in-memory
// path detects the mismatch, so a future fix wave wiring the same check
// into main.zig will close BUG-1.
// ===========================================================================
test "w138 G1b: validateAndLoadSnapshot rejects mismatched content (BUG-1 inverse)" {
    const allocator = testing.allocator;

    // Use the well-known 840k whitelist entry; build a snapshot whose
    // base_blockhash matches but whose UTXOs are garbage.
    const entry840k = consensus.MAINNET.assume_utxo[0];

    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    cs.best_hash = entry840k.block_hash;
    cs.best_height = entry840k.height;

    const spk = p2pkh();
    const op = types.OutPoint{ .hash = [_]u8{0x99} ** 32, .index = 0 };
    try cs.utxo_set.add(&op, &types.TxOut{ .value = 1_234, .script_pubkey = &spk }, 100, false);

    const tmp = "/tmp/clearbit-w138-g1b-garbage.dat";
    defer std.fs.cwd().deleteFile(tmp) catch {};
    try storage.dumpTxOutSet(&cs, consensus.MAINNET.magic, tmp, allocator);

    var actual: types.Hash256 = undefined;
    var expected: types.Hash256 = undefined;
    const result = storage.validateAndLoadSnapshot(
        tmp,
        &consensus.MAINNET,
        allocator,
        null,
        null,
        &actual,
        &expected,
    );
    // RPC/in-memory path correctly rejects with HashMismatch.
    try testing.expectError(storage.SnapshotError.HashMismatch, result);
    try testing.expectEqualSlices(u8, &entry840k.hash_serialized, &expected);
    // The CLI path (`loadSnapshotFromFile`) lacks this gate — see G1
    // (the source-grep test) for the asymmetry pinning.
}

// ===========================================================================
// G2 — Production code constructs a ChainStateManager + calls activateSnapshot
// Status: MISSING (BUG-2). ChainStateManager is dead code.
// ===========================================================================
test "w138 G2: ChainStateManager is unused in production code (BUG-2)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    // Type and methods exist.
    try testing.expect(contains(storage_src, "pub const ChainStateManager = struct"));
    try testing.expect(contains(storage_src, "pub fn activateSnapshot"));
    try testing.expect(contains(storage_src, "pub fn startBackgroundValidation"));
    try testing.expect(contains(storage_src, "pub fn completeValidation"));

    // But: ChainStateManager.init is never called from main.zig or
    // rpc.zig (production callers). Only storage.zig's own tests construct
    // them.
    try testing.expect(!contains(main_src, "ChainStateManager.init"));
    try testing.expect(!contains(rpc_src, "ChainStateManager.init"));
    try testing.expect(!contains(main_src, "activateSnapshot"));
    // Note: rpc.zig mentions `ChainStateManager.activateSnapshot()` in
    // the handleLoadTxOutSet doc-comment (explaining why the RPC is
    // gated and what wiring it would require). It is NOT actually
    // called in code. Confirm by checking the doc-comment mention is
    // the only one (a single `///` line):
    try testing.expectEqual(
        @as(usize, 1),
        countOccurrences(rpc_src, "ChainStateManager.activateSnapshot()"),
    );
    // No code calls of the form `mgr.activateSnapshot(...)` or
    // `manager.activateSnapshot(...)` in production code.
    try testing.expect(!contains(rpc_src, "mgr.activateSnapshot"));
    try testing.expect(!contains(rpc_src, "manager.activateSnapshot"));
    try testing.expect(!contains(main_src, ".activateSnapshot("));
}

// ===========================================================================
// G3 — getchainstates RPC implemented
// Status: MISSING (BUG-3). No arm in dispatch table.
// ===========================================================================
test "w138 G3: getchainstates RPC is not implemented (BUG-3)" {
    const allocator = testing.allocator;
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    // No dispatch arm for "getchainstates".
    try testing.expect(!contains(rpc_src, "\"getchainstates\""));
    try testing.expect(!contains(rpc_src, "handleGetChainStates"));
    // Sister methods ARE dispatched (sanity check the dispatch table works).
    try testing.expect(contains(rpc_src, "\"loadtxoutset\""));
    try testing.expect(contains(rpc_src, "\"dumptxoutset\""));
    try testing.expect(contains(rpc_src, "\"gettxoutsetinfo\""));
}

// ===========================================================================
// G4 — base_blockhash persistence file (SNAPSHOT_BLOCKHASH_FILENAME)
// Status: MISSING (BUG-4). No code references the filename constant.
// ===========================================================================
test "w138 G4: SNAPSHOT_BLOCKHASH_FILENAME / WriteSnapshotBaseBlockhash absent (BUG-4)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    // No constant for the filename anywhere.
    try testing.expect(!contains(storage_src, "SNAPSHOT_BLOCKHASH_FILENAME"));
    try testing.expect(!contains(main_src, "SNAPSHOT_BLOCKHASH_FILENAME"));
    try testing.expect(!contains(storage_src, "\"base_blockhash\""));
    // No function for write/read of the file (function-definition shapes
    // `fn writeSnapshotBaseBlockhash` and `fn readSnapshotBaseBlockhash`
    // are not defined; note a comment may mention Core's
    // `WriteSnapshotBaseBlockhash` in passing — count it).
    try testing.expect(!contains(storage_src, "fn writeSnapshotBaseBlockhash"));
    try testing.expect(!contains(storage_src, "fn readSnapshotBaseBlockhash"));
    try testing.expect(!contains(storage_src, "pub fn WriteSnapshotBaseBlockhash"));
    try testing.expect(!contains(storage_src, "pub fn ReadSnapshotBaseBlockhash"));
    // Pin: at most a single doc-comment reference to Core's function
    // exists in storage.zig (the W102 G3 reference). Tighten when wired.
    const wsbb_count = countOccurrences(storage_src, "WriteSnapshotBaseBlockhash");
    try testing.expect(wsbb_count <= 1);
}

// ===========================================================================
// G5 — _snapshot chainstate-dir suffix (dual on-disk chainstates)
// Status: MISSING (BUG-5). CLI writes directly into chainstate/.
// ===========================================================================
test "w138 G5: SNAPSHOT_CHAINSTATE_SUFFIX (_snapshot) absent (BUG-5)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    // No `_snapshot` suffix anywhere — neither constant nor used path.
    try testing.expect(!contains(storage_src, "SNAPSHOT_CHAINSTATE_SUFFIX"));
    try testing.expect(!contains(storage_src, "\"_snapshot\""));
    try testing.expect(!contains(main_src, "chainstate_snapshot"));
    // CLI uses `chainstate` dir directly.
    try testing.expect(contains(main_src, "/chainstate"));
    // No FindAssumeutxoChainstateDir analog.
    try testing.expect(!contains(storage_src, "FindAssumeutxoChainstateDir"));
    try testing.expect(!contains(main_src, "findAssumeutxoChainstateDir"));
}

// ===========================================================================
// G6 — InvalidateCoinsDBOnDisk rename-on-failure cleanup path
// Status: MISSING (BUG-6). No analog.
// ===========================================================================
test "w138 G6: InvalidateCoinsDBOnDisk / rename-on-failure cleanup absent (BUG-6)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    try testing.expect(!contains(storage_src, "InvalidateCoinsDBOnDisk"));
    try testing.expect(!contains(storage_src, "invalidateCoinsDBOnDisk"));
    try testing.expect(!contains(storage_src, "_INVALIDATED"));
    // BackgroundValidationFailed is the error variant, but the cleanup
    // path after it is just a `return` — no rename, no fatal-error.
    try testing.expect(contains(storage_src, "BackgroundValidationFailed"));
    // The completeValidation arm just returns the error — no rename
    // sibling.
    const cv_start = std.mem.indexOf(u8, storage_src, "fn completeValidation").?;
    const cv_end = std.mem.indexOfPos(u8, storage_src, cv_start, "pub fn activeChainstate") orelse storage_src.len;
    const cv_body = storage_src[cv_start..cv_end];
    try testing.expect(!contains(cv_body, "rename"));
    try testing.expect(!contains(cv_body, "deleteTree"));
    try testing.expect(!contains(cv_body, "fatalError"));
}

// ===========================================================================
// G7 — loadtxoutset RPC reaches Core's ActivateSnapshot equivalent
// Status: DIVERGE (BUG-7). RPC is fully gated with RPC_INTERNAL_ERROR.
// ===========================================================================
test "w138 G7: loadtxoutset RPC returns RPC_INTERNAL_ERROR (BUG-7)" {
    const allocator = testing.allocator;
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    // The handler exists.
    try testing.expect(contains(rpc_src, "fn handleLoadTxOutSet"));
    // Returns RPC_INTERNAL_ERROR (the gate).
    try testing.expect(contains(rpc_src, "loadtxoutset RPC is disabled in this build"));
    try testing.expect(contains(rpc_src, "RPC_INTERNAL_ERROR"));
    // Does NOT call validateAndLoadSnapshot (the gate fires first).
    const handler_start = std.mem.indexOf(u8, rpc_src, "fn handleLoadTxOutSet").?;
    const handler_end = std.mem.indexOfPos(u8, rpc_src, handler_start, "fn handleDumpTxOutSet") orelse rpc_src.len;
    const handler_body = rpc_src[handler_start..handler_end];
    try testing.expect(!contains(handler_body, "validateAndLoadSnapshot("));
    try testing.expect(!contains(handler_body, "activateSnapshot("));
}

// ===========================================================================
// G8 — storage.loadTxOutSet checks coin.nHeight > base_height
// Status: MISSING (BUG-8). CLI path checks; storage path does not.
// ===========================================================================
test "w138 G8: storage.loadTxOutSet missing per-coin nHeight check (BUG-8)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    // CLI path has the check.
    try testing.expect(contains(main_src, "utxo_height > block_height"));

    // Storage path (loadTxOutSet) does NOT. Find the function and
    // assert no `coin.height > ` check within its body.
    const ltx_start = std.mem.indexOf(u8, storage_src, "pub fn loadTxOutSet").?;
    const ltx_end = std.mem.indexOfPos(u8, storage_src, ltx_start, "pub fn findAssumeUtxoEntry") orelse storage_src.len;
    const ltx_body = storage_src[ltx_start..ltx_end];
    // The body checks isValidMoney but NOT coin.height vs base_height.
    try testing.expect(contains(ltx_body, "isValidMoney(coin.value)"));
    try testing.expect(!contains(ltx_body, "coin.height >"));
    try testing.expect(!contains(ltx_body, "height > base_height"));
    try testing.expect(!contains(ltx_body, "coin.height > base_height"));
}

// ===========================================================================
// G9 — vout overflow handling: CLI exits(1), storage returns error
// Status: DIVERGE (BUG-9). Failure mode differs.
// ===========================================================================
test "w138 G9: vout overflow handling diverges between CLI panic and storage error (BUG-9)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    // CLI path: panics via std.process.exit(1).
    try testing.expect(contains(main_src, "FATAL: vout overflow"));
    // Storage path: returns StorageError.CorruptData.
    const rscp_start = std.mem.indexOf(u8, storage_src, "pub fn readSnapshotCoinPayload").?;
    const rscp_end = std.mem.indexOfPos(u8, storage_src, rscp_start, "pub const ChainstateRole") orelse storage_src.len;
    const rscp_body = storage_src[rscp_start..rscp_end];
    try testing.expect(contains(rscp_body, "return StorageError.CorruptData"));
    try testing.expect(!contains(rscp_body, "std.process.exit"));
}

// ===========================================================================
// G10 — ResizeCoinsCaches / IBD_CACHE_PERC / SNAPSHOT_CACHE_PERC absent
// Status: MISSING (BUG-10). No cache bias on activation.
// ===========================================================================
test "w138 G10: ResizeCoinsCaches / IBD_CACHE_PERC / SNAPSHOT_CACHE_PERC absent (BUG-10)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    try testing.expect(!contains(storage_src, "ResizeCoinsCaches"));
    try testing.expect(!contains(storage_src, "resizeCoinsCaches"));
    try testing.expect(!contains(storage_src, "IBD_CACHE_PERC"));
    try testing.expect(!contains(storage_src, "SNAPSHOT_CACHE_PERC"));
    try testing.expect(!contains(main_src, "IBD_CACHE_PERC"));
    try testing.expect(!contains(main_src, "SNAPSHOT_CACHE_PERC"));
    // MaybeRebalanceCaches also missing.
    try testing.expect(!contains(storage_src, "MaybeRebalanceCaches"));
    try testing.expect(!contains(storage_src, "maybeRebalanceCaches"));
}

// ===========================================================================
// G11 — CoinsCacheSizeState::CRITICAL mid-load flush
// Status: MISSING (BUG-11). Fixed-batch-size flush, no critical check.
// ===========================================================================
test "w138 G11: CoinsCacheSizeState / mid-load critical flush absent (BUG-11)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    try testing.expect(!contains(storage_src, "CoinsCacheSizeState"));
    try testing.expect(!contains(storage_src, "GetCoinsCacheSizeState"));
    try testing.expect(!contains(main_src, "CoinsCacheSizeState"));
    // The CLI path uses fixed BATCH_SIZE = 100_000.
    try testing.expect(contains(main_src, "BATCH_SIZE: u64 = 100_000"));
    // No "every 120000 coins" check either (Core's check interval).
    try testing.expect(!contains(main_src, "120000"));
    try testing.expect(!contains(main_src, "120_000"));
}

// ===========================================================================
// G12 — m_interrupt / SIGINT-safe abort in coin-load loop
// Status: MISSING (BUG-12). No interrupt handler.
// ===========================================================================
test "w138 G12: SIGINT-safe abort hook absent in coin-load loop (BUG-12)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    // No interrupt-flag check in the load loop.
    // loadSnapshotFromFile body must not reference an atomic interrupt flag.
    const lsf_start = std.mem.indexOf(u8, main_src, "fn loadSnapshotFromFile").?;
    const lsf_end = std.mem.indexOfPos(u8, main_src, lsf_start, "// ====") orelse main_src.len;
    const lsf_body = main_src[lsf_start..lsf_end];
    try testing.expect(!contains(lsf_body, "interrupt"));
    try testing.expect(!contains(lsf_body, "Interrupt"));
    try testing.expect(!contains(lsf_body, "SIGINT"));
    try testing.expect(!contains(lsf_body, "SIGTERM"));
    try testing.expect(!contains(lsf_body, "shutdown_requested"));
    try testing.expect(!contains(lsf_body, "stop_requested"));
}

// ===========================================================================
// G13 — LoadBlockIndexDB(snapshot_blockhash) analog on startup
// Status: MISSING (BUG-13). No reconstruction-from-disk plumbing.
// ===========================================================================
test "w138 G13: LoadBlockIndexDB(snapshot_blockhash) analog absent (BUG-13)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    // No code that reads a base_blockhash file on startup.
    try testing.expect(!contains(main_src, "ReadSnapshotBaseBlockhash"));
    try testing.expect(!contains(main_src, "readSnapshotBaseBlockhash"));
    try testing.expect(!contains(main_src, "from_snapshot_blockhash"));
    // No `m_from_snapshot_blockhash` field on ChainState.
    try testing.expect(!contains(storage_src, "from_snapshot_blockhash"));
    try testing.expect(!contains(storage_src, "m_from_snapshot_blockhash"));
}

// ===========================================================================
// G14 — dumpTxOutSet.coins_count reflects persisted total
// Status: DIVERGE (BUG-14). Uses cache.count(). Pinned by W102 G3.
// ===========================================================================
test "w138 G14: dumpTxOutSet coins_count uses cache size, not persisted total (BUG-14)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    // dumpTxOutSet body samples chainstate.utxo_set.cache.count()
    // (not total_utxos).
    const dts_start = std.mem.indexOf(u8, storage_src, "pub fn dumpTxOutSet").?;
    const dts_end = std.mem.indexOfPos(u8, storage_src, dts_start, "pub fn loadTxOutSet") orelse storage_src.len;
    const dts_body = storage_src[dts_start..dts_end];

    try testing.expect(contains(dts_body, "chainstate.utxo_set.cache.count()"));
    // No reference to total_utxos in the dumpTxOutSet body.
    try testing.expect(!contains(dts_body, "total_utxos"));
}

// ===========================================================================
// G15 — completeValidation uses computeHashSerializedTxOutSet
// Status: DIVERGE (BUG-15). Uses legacy computeUtxoSetHash. Pinned by W102 G15.
// ===========================================================================
test "w138 G15: completeValidation uses legacy computeUtxoSetHash, not strict hash (BUG-15)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    const cv_start = std.mem.indexOf(u8, storage_src, "pub fn completeValidation").?;
    const cv_end = std.mem.indexOfPos(u8, storage_src, cv_start, "pub fn activeChainstate") orelse storage_src.len;
    const cv_body = storage_src[cv_start..cv_end];

    // Uses legacy.
    try testing.expect(contains(cv_body, "computeUtxoSetHash("));
    // Does NOT use strict.
    try testing.expect(!contains(cv_body, "computeHashSerializedTxOutSet"));
}

// ===========================================================================
// G16 — completeValidation compares against assume_entry.hash_serialized
// Status: DIVERGE (BUG-16). Only compares active vs background.
// ===========================================================================
test "w138 G16: completeValidation never consults chainparams hash_serialized (BUG-16)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    const cv_start = std.mem.indexOf(u8, storage_src, "pub fn completeValidation").?;
    const cv_end = std.mem.indexOfPos(u8, storage_src, cv_start, "pub fn activeChainstate") orelse storage_src.len;
    const cv_body = storage_src[cv_start..cv_end];

    // Does not look up findAssumeUtxoEntry.
    try testing.expect(!contains(cv_body, "findAssumeUtxoEntry"));
    try testing.expect(!contains(cv_body, "assume_entry"));
    try testing.expect(!contains(cv_body, "hash_serialized"));
}

// ===========================================================================
// G17 — testnet3 / testnet4 / signet assume_utxo populated
// Status: MISSING (BUG-17). All three are empty slices. Pinned by W102 G26/G27.
// ===========================================================================
test "w138 G17: testnet3/testnet4/signet assume_utxo tables are empty (BUG-17)" {
    try testing.expectEqual(@as(usize, 0), consensus.TESTNET3.assume_utxo.len);
    try testing.expectEqual(@as(usize, 0), consensus.TESTNET4.assume_utxo.len);
    try testing.expectEqual(@as(usize, 0), consensus.SIGNET.assume_utxo.len);
    // Mainnet has 4 entries (Core v28).
    try testing.expectEqual(@as(usize, 4), consensus.MAINNET.assume_utxo.len);
}

// ===========================================================================
// G18 — BLOCK_OPT_WITNESS flag set during snapshot population
// Status: MISSING (BUG-18). CLI writes zero status bits for snapshot tip.
// ===========================================================================
test "w138 G18: BLOCK_OPT_WITNESS not set during CLI snapshot import (BUG-18)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    const lsf_start = std.mem.indexOf(u8, main_src, "fn loadSnapshotFromFile").?;
    const lsf_end = std.mem.indexOfPos(u8, main_src, lsf_start, "// ====") orelse main_src.len;
    const lsf_body = main_src[lsf_start..lsf_end];

    // Writes a zero-byte status placeholder.
    try testing.expect(contains(lsf_body, "block_index_buf: [84]u8 = [_]u8{0} ** 84"));
    // Does not reference BLOCK_OPT_WITNESS.
    try testing.expect(!contains(lsf_body, "BLOCK_OPT_WITNESS"));
    try testing.expect(!contains(lsf_body, "block_opt_witness"));
    // No per-block walk past segwit_height.
    try testing.expect(!contains(lsf_body, "segwit_height"));
    try testing.expect(!contains(lsf_body, "DeploymentActiveAt"));
}

// ===========================================================================
// G19 — Block-index header bytes populated during CLI snapshot import
// Status: DIVERGE (BUG-19). Bytes 4..84 are zero placeholder.
// ===========================================================================
test "w138 G19: CLI snapshot import writes placeholder zero header bytes (BUG-19)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    const lsf_start = std.mem.indexOf(u8, main_src, "fn loadSnapshotFromFile").?;
    const lsf_end = std.mem.indexOfPos(u8, main_src, lsf_start, "// ====") orelse main_src.len;
    const lsf_body = main_src[lsf_start..lsf_end];

    // The placeholder zero-buffer is explicit (no header bytes written).
    try testing.expect(contains(lsf_body, "block_index_buf: [84]u8 = [_]u8{0} ** 84"));
    // The body never invokes serialize.writeBlockHeader / parseBlockHeader.
    try testing.expect(!contains(lsf_body, "writeBlockHeader"));
    try testing.expect(!contains(lsf_body, "parseBlockHeader"));
    // No header field populated either (no version/timestamp/bits/nonce
    // assignments).
    try testing.expect(!contains(lsf_body, "header.version"));
    try testing.expect(!contains(lsf_body, "header.timestamp"));
}

// ===========================================================================
// G20 — activateSnapshot checks m_best_header->GetAncestor matches
// Status: MISSING (BUG-20). Only the double-activation guard.
// ===========================================================================
test "w138 G20: activateSnapshot lacks m_best_header ancestor check (BUG-20)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    const as_start = std.mem.indexOf(u8, storage_src, "pub fn activateSnapshot").?;
    const as_end = std.mem.indexOfPos(u8, storage_src, as_start, "pub fn startBackgroundValidation") orelse storage_src.len;
    const as_body = storage_src[as_start..as_end];

    // Has the double-activation guard.
    try testing.expect(contains(as_body, "AlreadyActivated"));
    // Lacks any best_header / GetAncestor check.
    try testing.expect(!contains(as_body, "best_header"));
    try testing.expect(!contains(as_body, "m_best_header"));
    try testing.expect(!contains(as_body, "GetAncestor"));
    try testing.expect(!contains(as_body, "getAncestor"));
}

// ===========================================================================
// G21 — activateSnapshot final work-comparison
// Status: MISSING (BUG-21). No work-comparator check.
// ===========================================================================
test "w138 G21: activateSnapshot lacks final work-comparison check (BUG-21)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    const as_start = std.mem.indexOf(u8, storage_src, "pub fn activateSnapshot").?;
    const as_end = std.mem.indexOfPos(u8, storage_src, as_start, "pub fn startBackgroundValidation") orelse storage_src.len;
    const as_body = storage_src[as_start..as_end];

    try testing.expect(!contains(as_body, "CBlockIndexWorkComparator"));
    try testing.expect(!contains(as_body, "chain_work"));
    try testing.expect(!contains(as_body, "work does not exceed"));
}

// ===========================================================================
// G22 — activateSnapshot refuses if mempool not empty
// Status: MISSING (BUG-22). No mempool reference.
// ===========================================================================
test "w138 G22: activateSnapshot lacks mempool-empty precondition (BUG-22)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    const as_start = std.mem.indexOf(u8, storage_src, "pub fn activateSnapshot").?;
    const as_end = std.mem.indexOfPos(u8, storage_src, as_start, "pub fn startBackgroundValidation") orelse storage_src.len;
    const as_body = storage_src[as_start..as_end];

    try testing.expect(!contains(as_body, "mempool"));
    try testing.expect(!contains(as_body, "Mempool"));
}

// ===========================================================================
// G23 — RemoveLocalServices(NODE_NETWORK) after snapshot load
// Status: MISSING (BUG-23). No services downgrade.
// ===========================================================================
test "w138 G23: NODE_NETWORK_LIMITED advertisement on snapshot load absent (BUG-23)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);

    const lsf_start = std.mem.indexOf(u8, main_src, "fn loadSnapshotFromFile").?;
    const lsf_end = std.mem.indexOfPos(u8, main_src, lsf_start, "// ====") orelse main_src.len;
    const lsf_body = main_src[lsf_start..lsf_end];

    // The CLI snapshot import doesn't reference NODE_NETWORK_LIMITED.
    try testing.expect(!contains(lsf_body, "NODE_NETWORK_LIMITED"));
    try testing.expect(!contains(lsf_body, "RemoveLocalServices"));
    try testing.expect(!contains(lsf_body, "removeLocalServices"));
    // Conversely, NODE_NETWORK_LIMITED IS defined in p2p.zig — sanity.
    const p2p_src = try loadSrc(allocator, "p2p");
    defer allocator.free(p2p_src);
    try testing.expect(contains(p2p_src, "NODE_NETWORK_LIMITED"));
}

// ===========================================================================
// G24 — SnapshotMetadata.network_magic serialized as [4]u8 (MessageStartChars)
// Status: DIVERGE (BUG-24). Stored as u32; serialization happens to match LE.
// ===========================================================================
test "w138 G24: SnapshotMetadata.network_magic is u32, not [4]u8 (BUG-24)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    // The struct field type is u32, not [4]u8.
    try testing.expect(contains(storage_src, "network_magic: u32"));
    try testing.expect(!contains(storage_src, "network_magic: [4]u8"));
    // Serializer writes it as a u32 little-endian.
    try testing.expect(contains(storage_src, "writer.writeInt(u32, self.network_magic)"));

    // Behavioral confirmation: mainnet magic round-trips byte-exact
    // (parity with Core's `MessageStartChars` for mainnet).
    const metadata = storage.SnapshotMetadata{
        .network_magic = 0xD9B4BEF9,
        .base_blockhash = [_]u8{0} ** 32,
        .coins_count = 0,
    };
    const serialized = try metadata.toBytes(allocator);
    defer allocator.free(serialized);
    // Bytes 7..11 hold the magic; for mainnet it's f9 be b4 d9 (LE of
    // 0xD9B4BEF9), which also matches Core's mainnet pchMessageStart.
    try testing.expectEqual(@as(u8, 0xf9), serialized[7]);
    try testing.expectEqual(@as(u8, 0xbe), serialized[8]);
    try testing.expectEqual(@as(u8, 0xb4), serialized[9]);
    try testing.expectEqual(@as(u8, 0xd9), serialized[10]);
}

// ===========================================================================
// G25 — dumptxoutset rollback succeeds on pruned datadir
// Status: DIVERGE (BUG-25). Aborts if CF_BLOCKS body is missing.
// ===========================================================================
test "w138 G25: dumptxoutset rollback aborts on missing CF_BLOCKS body (BUG-25)" {
    const allocator = testing.allocator;
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    // The error string exists.
    try testing.expect(contains(rpc_src, "rollback aborted: CF_BLOCKS missing body"));
    // The guard explicitly references CF_BLOCKS.
    try testing.expect(contains(rpc_src, "getBlockBytes(&entry.hash)"));
}

// ===========================================================================
// G26 — dumptxoutset rollback succeeds after IBD fast-path
// Status: DIVERGE (BUG-26). Rejects if undo data missing.
// ===========================================================================
test "w138 G26: dumptxoutset rollback aborts on missing undo data (BUG-26)" {
    const allocator = testing.allocator;
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    try testing.expect(contains(rpc_src, "rollback aborted: undo data unreadable"));
    try testing.expect(contains(rpc_src, "rollback aborted: undo data missing"));
    try testing.expect(contains(rpc_src, "IBD fast-path"));
}

// ===========================================================================
// G27 — dumptxoutset uses connect_mutex, not NetworkDisable
// Status: DIVERGE (BUG-27). Different mechanism, equivalent safety.
// ===========================================================================
test "w138 G27: dumptxoutset rollback uses connect_mutex, not NetworkDisable (BUG-27)" {
    const allocator = testing.allocator;
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    // Uses connect_mutex.
    try testing.expect(contains(rpc_src, "chain_state.connect_mutex.lock()"));
    try testing.expect(contains(rpc_src, "chain_state.connect_mutex.unlock()"));
    // rpc.zig DOES reference NetworkDisable — but only in doc-comments
    // explaining why clearbit chose connect_mutex instead. Confirm
    // they're all comment lines (each starts with `///` or `//`).
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, rpc_src, idx, "NetworkDisable")) |found_at| {
        // Walk backward to the start of the line, check the first two
        // non-whitespace chars look like a comment marker.
        var line_start = found_at;
        while (line_start > 0 and rpc_src[line_start - 1] != '\n') line_start -= 1;
        var p = line_start;
        while (p < found_at and (rpc_src[p] == ' ' or rpc_src[p] == '\t')) p += 1;
        // Must be a comment line (`//`).
        const is_comment = p + 1 < found_at and rpc_src[p] == '/' and rpc_src[p + 1] == '/';
        try testing.expect(is_comment);
        idx = found_at + "NetworkDisable".len;
    }
    // No function-call form of NetworkDisable.
    try testing.expect(!contains(rpc_src, "NetworkDisable("));
    try testing.expect(!contains(rpc_src, "networkDisable("));
    try testing.expect(!contains(rpc_src, "SetNetworkActive(false)"));
}

// ===========================================================================
// G28 — AlreadyActivated is recoverable (not fatal)
// Status: DIVERGE (BUG-28). Core also recoverable — actually parity.
// Listed for completeness; this test confirms parity with Core's recoverable
// behaviour and documents that BUG-28 should be downgraded to INFO.
// ===========================================================================
test "w138 G28: AlreadyActivated is recoverable (BUG-28 — actually parity)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    const as_start = std.mem.indexOf(u8, storage_src, "pub fn activateSnapshot").?;
    const as_end = std.mem.indexOfPos(u8, storage_src, as_start, "pub fn startBackgroundValidation") orelse storage_src.len;
    const as_body = storage_src[as_start..as_end];

    // Returns a recoverable error variant.
    try testing.expect(contains(as_body, "return SnapshotError.AlreadyActivated"));
    // Does not call fatalError / @panic.
    try testing.expect(!contains(as_body, "@panic"));
    try testing.expect(!contains(as_body, "fatalError"));

    // Behavioural: a second activateSnapshot call returns the error
    // without crashing (parity with Core's `util::Error{...}`).
    var cs1 = storage.ChainState.init(null, 64, allocator);
    defer cs1.deinit();
    var cs2 = storage.ChainState.init(null, 64, allocator);
    defer cs2.deinit();
    var cs3 = storage.ChainState.init(null, 64, allocator);
    defer cs3.deinit();

    var mgr = storage.ChainStateManager.init(&cs1, &consensus.MAINNET, allocator);
    defer mgr.deinit();

    try mgr.activateSnapshot(&cs2, [_]u8{0x01} ** 32);
    try testing.expectError(
        storage.SnapshotError.AlreadyActivated,
        mgr.activateSnapshot(&cs3, [_]u8{0x02} ** 32),
    );
}

// ===========================================================================
// G29 — ChainState has m_target_blockhash / m_target_utxohash / ReachedTarget
// Status: MISSING (BUG-29). Data model fields absent.
// ===========================================================================
test "w138 G29: ChainState lacks m_target_blockhash / ReachedTarget fields (BUG-29)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    // Find ChainState struct body — span from "pub const ChainState = struct"
    // to the next top-level "pub const" or "pub fn".
    const cs_start = std.mem.indexOf(u8, storage_src, "pub const ChainState = struct").?;
    // Look for the end of the struct (very rough: "};" near "pub const" or
    // "pub fn dumpTxOutSet").
    const cs_end = std.mem.indexOfPos(u8, storage_src, cs_start, "pub fn dumpTxOutSet") orelse storage_src.len;
    const cs_body = storage_src[cs_start..cs_end];

    // No target_blockhash / target_utxohash field on ChainState.
    try testing.expect(!contains(cs_body, "target_blockhash:"));
    try testing.expect(!contains(cs_body, "target_utxohash:"));
    try testing.expect(!contains(cs_body, "m_target_blockhash"));
    try testing.expect(!contains(cs_body, "m_target_utxohash"));
    // No reachedTarget method.
    try testing.expect(!contains(cs_body, "fn reachedTarget"));
    try testing.expect(!contains(cs_body, "fn ReachedTarget"));
}

// ===========================================================================
// G30 — dumpTxOutSet writes via tmp + sync + rename atomic protocol
// Status: DIVERGE (BUG-30). clearbit's atomic write is stricter than Core's.
// Listed for completeness; this is a stricter (good) divergence.
// ===========================================================================
test "w138 G30: dumpTxOutSet uses .incomplete tmp + fsync + rename protocol (BUG-30, stricter than Core)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    const dts_start = std.mem.indexOf(u8, storage_src, "pub fn dumpTxOutSet").?;
    const dts_end = std.mem.indexOfPos(u8, storage_src, dts_start, "pub fn loadTxOutSet") orelse storage_src.len;
    const dts_body = storage_src[dts_start..dts_end];

    // .incomplete temp path.
    try testing.expect(contains(dts_body, ".incomplete"));
    // fsync barrier.
    try testing.expect(contains(dts_body, "file.sync()"));
    // Atomic rename.
    try testing.expect(contains(dts_body, "std.fs.cwd().rename(tmp_path, path)"));

    // Behavioural: confirm the dump produces a real file (sanity check
    // the atomic protocol doesn't leave .incomplete behind on success).
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 0;
    const spk = p2pkh();
    const op = types.OutPoint{ .hash = [_]u8{0x33} ** 32, .index = 0 };
    try cs.utxo_set.add(&op, &types.TxOut{ .value = 1_000, .script_pubkey = &spk }, 0, false);

    const tmp = "/tmp/clearbit-w138-g30-atomic.dat";
    defer std.fs.cwd().deleteFile(tmp) catch {};
    defer std.fs.cwd().deleteFile(tmp ++ ".incomplete") catch {};
    try storage.dumpTxOutSet(&cs, consensus.MAINNET.magic, tmp, allocator);

    // Final file exists.
    const stat = try std.fs.cwd().statFile(tmp);
    try testing.expect(stat.size > 0);
    // .incomplete is gone (rename succeeded).
    const probe = std.fs.cwd().statFile(tmp ++ ".incomplete");
    try testing.expectError(error.FileNotFound, probe);
}

// ===========================================================================
// Universal: snapshot magic byte sequence
// (sanity guard, cheap)
// ===========================================================================
test "w138 sanity: SNAPSHOT_MAGIC_BYTES matches Core's {'u','t','x','o',0xff}" {
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 'u', 't', 'x', 'o', 0xff },
        &storage.SNAPSHOT_MAGIC_BYTES,
    );
}

// ===========================================================================
// Universal: snapshot version pinned to 2 (Core's current)
// ===========================================================================
test "w138 sanity: SNAPSHOT_VERSION pinned to 2 (Core v28 current)" {
    try testing.expectEqual(@as(u16, 2), storage.SNAPSHOT_VERSION);
}

// ===========================================================================
// Universal: header size pinned at 51 bytes (magic[5] + version[2] +
// magic[4] + hash[32] + count[8])
// ===========================================================================
test "w138 sanity: SnapshotMetadata.HEADER_SIZE pinned at 51 bytes" {
    try testing.expectEqual(@as(usize, 51), storage.SnapshotMetadata.HEADER_SIZE);
}
