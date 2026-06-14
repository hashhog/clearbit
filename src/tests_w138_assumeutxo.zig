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
// G2 — REAL background-validation second chainstate is wired into production
// Status: CLOSED (was BUG-2: ChainStateManager dead code). The from-scratch
// background chainstate (au_bg_chainstate.zig) is now constructed + run by the
// live loadtxoutset RPC (storage.runInProcessBackgroundValidation), which seeds
// an EMPTY separate store and re-derives genesis→base.
// ===========================================================================
test "w138 G2: REAL background-validation second chainstate wired into loadtxoutset (BUG-2 CLOSED)" {
    const allocator = testing.allocator;
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);
    const au_src = try loadSrc(allocator, "au_bg_chainstate");
    defer allocator.free(au_src);

    // The from-scratch background chainstate exists with the genuine pieces:
    // a separate store, an aliasing guard, a real genesis→base connect, a
    // HASH_SERIALIZED recompute, and a validate-against-au_data decision.
    try testing.expect(contains(au_src, "pub const BgChainState = struct"));
    try testing.expect(contains(au_src, "pub fn assertNotAliased"));
    try testing.expect(contains(au_src, "pub fn connectBlock"));
    try testing.expect(contains(au_src, "pub fn computeHashSerialized"));
    try testing.expect(contains(au_src, "pub fn validateAgainst"));
    try testing.expect(contains(au_src, "pub fn runBackgroundValidation"));

    // It is WIRED into production: storage exposes the in-process driver and
    // the loadtxoutset RPC calls it (no longer the disabled stub).
    try testing.expect(contains(storage_src, "pub fn runInProcessBackgroundValidation"));
    try testing.expect(contains(rpc_src, "runInProcessBackgroundValidation"));
    // And the legacy ChainStateManager doc-comment stub is gone from the RPC.
    try testing.expect(!contains(rpc_src, "ChainStateManager.activateSnapshot()"));
}

// ===========================================================================
// G3 — getchainstates RPC implemented + reports validated/snapshot_blockhash
//       from the ACTUAL AssumeUTXO activation state.
// Status: CLOSED (was BUG-3). Dispatch arm + handler present; the handler
// reads chain_state.from_snapshot_blockhash / .snapshot_validated.
// ===========================================================================
test "w138 G3: getchainstates RPC implemented, reports real validation state (BUG-3 CLOSED)" {
    const allocator = testing.allocator;
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    // Dispatch arm + handler present.
    try testing.expect(contains(rpc_src, "\"getchainstates\""));
    try testing.expect(contains(rpc_src, "handleGetChainStates"));
    // The handler emits snapshot_blockhash + validated FROM THE ACTUAL STATE
    // (not a hard-coded `true`).
    try testing.expect(contains(rpc_src, "self.chain_state.from_snapshot_blockhash"));
    try testing.expect(contains(rpc_src, "self.chain_state.snapshot_validated"));
    try testing.expect(contains(rpc_src, "\"snapshot_blockhash\""));
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
// G7 — loadtxoutset RPC performs Core's two-stage AssumeUTXO activation.
// Status: CLOSED (was BUG-7: RPC fully gated with RPC_INTERNAL_ERROR). The
// handler now (1) authenticates the file via validateAndLoadSnapshot (load-time
// hash gate) then (2) runs the REAL background genesis→base re-derivation.
// ===========================================================================
test "w138 G7: loadtxoutset RPC performs two-stage activation (BUG-7 CLOSED)" {
    const allocator = testing.allocator;
    const rpc_src = try loadSrc(allocator, "rpc");
    defer allocator.free(rpc_src);

    // The handler exists.
    try testing.expect(contains(rpc_src, "fn handleLoadTxOutSet"));
    // The disabled stub string is gone.
    try testing.expect(!contains(rpc_src, "loadtxoutset RPC is disabled in this build"));

    const handler_start = std.mem.indexOf(u8, rpc_src, "fn handleLoadTxOutSet").?;
    const handler_end = std.mem.indexOfPos(u8, rpc_src, handler_start, "fn handleDumpTxOutSet") orelse rpc_src.len;
    const handler_body = rpc_src[handler_start..handler_end];
    // STAGE 1: load-time hash gate authenticates the file.
    try testing.expect(contains(handler_body, "validateAndLoadSnapshot("));
    // STAGE 2: real background genesis→base re-derivation.
    try testing.expect(contains(handler_body, "runInProcessBackgroundValidation("));
    // The invalid path NEVER silently accepts — it refuses with a hash-mismatch
    // error and leaves the active chainstate untouched.
    try testing.expect(contains(handler_body, "Background validation FAILED"));
    // The validated path marks the real snapshot state for getchainstates.
    try testing.expect(contains(handler_body, "from_snapshot_blockhash ="));
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
// G13 — Chainstate AssumeUTXO data-model field (Core m_from_snapshot_blockhash).
// Status: PARTIALLY CLOSED. The data-model field now exists on ChainState and
// is set by the in-process activation; getchainstates reads it for the live
// `snapshot_blockhash` / `validated` report.
// STILL DEFERRED (honest): cross-restart persistence of the field to a
// base_blockhash file + a LoadBlockIndexDB-style reader that re-attaches the
// background chainstate after a daemon restart. In-process activation is fully
// real; cross-restart resumption of background validation is not yet plumbed.
// ===========================================================================
test "w138 G13: Chainstate carries m_from_snapshot_blockhash data-model field (BUG-13 partial)" {
    const allocator = testing.allocator;
    const main_src = try loadSrc(allocator, "main");
    defer allocator.free(main_src);
    const storage_src = try loadSrc(allocator, "storage");
    defer allocator.free(storage_src);

    // The data-model field now exists on ChainState (Core m_from_snapshot_blockhash).
    try testing.expect(contains(storage_src, "from_snapshot_blockhash: ?types.Hash256"));
    try testing.expect(contains(storage_src, "snapshot_validated: bool"));

    // STILL DEFERRED: the on-startup base_blockhash file reader is not wired
    // (cross-restart resumption of background validation is future work).
    try testing.expect(!contains(main_src, "ReadSnapshotBaseBlockhash"));
    try testing.expect(!contains(main_src, "readSnapshotBaseBlockhash"));
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
    // Mainnet has 4 entries (Core v28). The hashhog-only h=944_183 bootstrap
    // snapshot lives in MAINNET.snapshot_bootstrap, NOT assume_utxo, so the
    // canonical table stays byte-for-byte Core's m_assumeutxo_data.
    try testing.expectEqual(@as(usize, 4), consensus.MAINNET.assume_utxo.len);
    // The hashhog-only bootstrap allowlist carries exactly the 944183 entry.
    try testing.expectEqual(@as(usize, 1), consensus.MAINNET.snapshot_bootstrap.len);
    try testing.expectEqual(@as(u32, 944_183), consensus.MAINNET.snapshot_bootstrap[0].height);
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

// ===========================================================================
// AssumeUTXO REAL background-validation second chainstate (au_bg_chainstate.zig)
//
// These tests exercise the GENUINE genesis→base re-derivation in a SEPARATE
// store (NOT the active coins, NOT a counter), per Core's
// MaybeValidateSnapshot. They are built around an in-memory block chain so they
// need no on-disk DB; the same `au.runBackgroundValidation` driver the live
// loadtxoutset RPC uses is exercised here via the generic BlockProvider.
// ===========================================================================

const au = @import("au_bg_chainstate.zig");
const crypto = @import("crypto.zig");

/// A simple in-memory block chain + a BlockProvider over it.  Each block has a
/// single coinbase tx whose txid is unique per height; block `spend_in` (if
/// set) additionally spends a prior coinbase output to a P2PKH output.
const TestChain = struct {
    allocator: std.mem.Allocator,
    blocks: []types.Block,

    fn getBlockImpl(ctx: *anyopaque, height: u32, out: *types.Block) anyerror!void {
        const self: *TestChain = @ptrCast(@alignCast(ctx));
        if (height >= self.blocks.len) return error.BlockNotFound;
        out.* = self.blocks[height];
    }

    fn provider(self: *TestChain) au.BlockProvider {
        return .{ .ctx = self, .getBlockFn = getBlockImpl };
    }
};

/// Build a coinbase tx that pays `value` to the given scriptPubKey, with a
/// height-tagged scriptSig so the txid is unique per height.
fn buildCoinbase(allocator: std.mem.Allocator, height: u32, value: i64, spk: []const u8) !types.Transaction {
    const ss = try allocator.alloc(u8, 4);
    std.mem.writeInt(u32, ss[0..4], height, .little);
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = ss,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outs = try allocator.alloc(types.TxOut, 1);
    outs[0] = .{ .value = value, .script_pubkey = try allocator.dupe(u8, spk) };
    return .{ .version = 1, .inputs = inputs, .outputs = outs, .lock_time = 0 };
}

/// Build a spend tx: spends (prev_txid, prev_vout) to a single P2PKH output.
fn buildSpend(
    allocator: std.mem.Allocator,
    prev_txid: types.Hash256,
    prev_vout: u32,
    value: i64,
    spk: []const u8,
) !types.Transaction {
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = .{ .hash = prev_txid, .index = prev_vout },
        .script_sig = try allocator.dupe(u8, &[_]u8{ 0x51 }), // OP_1 (dummy)
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outs = try allocator.alloc(types.TxOut, 1);
    outs[0] = .{ .value = value, .script_pubkey = try allocator.dupe(u8, spk) };
    return .{ .version = 1, .inputs = inputs, .outputs = outs, .lock_time = 0 };
}

fn freeTx(allocator: std.mem.Allocator, tx: *const types.Transaction) void {
    for (tx.inputs) |in| if (in.script_sig.len > 0) allocator.free(in.script_sig);
    allocator.free(tx.inputs);
    for (tx.outputs) |o| if (o.script_pubkey.len > 0) allocator.free(o.script_pubkey);
    allocator.free(tx.outputs);
}

/// Build a fixed test chain of `n` blocks (heights 0..n-1).  Block 0 is genesis
/// (coinbase output unspendable). Blocks 1..n-1 each mine a coinbase to a
/// distinct P2PKH; block 2 spends block-1's coinbase output to a new P2PKH.
/// Returns owned blocks (free with freeTestChain).
fn buildTestChain(allocator: std.mem.Allocator, n: u32) ![]types.Block {
    std.debug.assert(n >= 3);
    var blocks = try allocator.alloc(types.Block, n);

    const genesis_spk = p2pkh(); // value irrelevant, genesis coinbase unspendable
    const block1_spk = blk: {
        var s = p2pkh();
        s[3] = 0x01; // make it distinct
        break :blk s;
    };

    // height 0: genesis (coinbase unspendable)
    {
        const txs = try allocator.alloc(types.Transaction, 1);
        txs[0] = try buildCoinbase(allocator, 0, 50 * 100_000_000, &genesis_spk);
        blocks[0] = .{ .header = stdHeader(), .transactions = txs };
    }

    // height 1: coinbase to block1_spk
    var b1_cb_txid: types.Hash256 = undefined;
    {
        const txs = try allocator.alloc(types.Transaction, 1);
        txs[0] = try buildCoinbase(allocator, 1, 50 * 100_000_000, &block1_spk);
        b1_cb_txid = try crypto.computeTxid(&txs[0], allocator);
        blocks[1] = .{ .header = stdHeader(), .transactions = txs };
    }

    // height 2: coinbase + a spend of block 1's coinbase output (vout 0)
    {
        const txs = try allocator.alloc(types.Transaction, 2);
        var cb_spk = p2pkh();
        cb_spk[3] = 0x02;
        txs[0] = try buildCoinbase(allocator, 2, 50 * 100_000_000, &cb_spk);
        var spend_spk = p2pkh();
        spend_spk[3] = 0x22;
        txs[1] = try buildSpend(allocator, b1_cb_txid, 0, 49 * 100_000_000, &spend_spk);
        blocks[2] = .{ .header = stdHeader(), .transactions = txs };
    }

    // heights 3..n-1: plain coinbase blocks (distinct spk per height)
    var h: u32 = 3;
    while (h < n) : (h += 1) {
        const txs = try allocator.alloc(types.Transaction, 1);
        var spk = p2pkh();
        spk[3] = @intCast(0x30 + (h & 0x0f));
        txs[0] = try buildCoinbase(allocator, h, 50 * 100_000_000, &spk);
        blocks[h] = .{ .header = stdHeader(), .transactions = txs };
    }

    return blocks;
}

fn stdHeader() types.BlockHeader {
    return .{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_700_000_000,
        .bits = 0x207fffff,
        .nonce = 0,
    };
}

fn freeTestChain(allocator: std.mem.Allocator, blocks: []types.Block) void {
    for (blocks) |*b| {
        for (b.transactions) |*tx| freeTx(allocator, tx);
        allocator.free(@constCast(b.transactions));
    }
    allocator.free(blocks);
}

// ---------------------------------------------------------------------------
// AU-1: aliasing guard — a bg store bound to an active UtxoSet refuses to
// operate when its backing map IS the active coins cache (hash-of-self guard).
// ---------------------------------------------------------------------------
test "w138 AU-1: aliasing guard rejects a bg store that aliases active coins" {
    const allocator = testing.allocator;

    var active = storage.UtxoSet.init(null, 8, allocator);
    defer active.deinit();

    // A genuinely-separate bg store passes the guard.
    var bg = au.BgChainState.init(allocator, &active);
    defer bg.deinit();
    try bg.assertNotAliased();

    // Forge the alias: point active_cache_addr at the bg store's own coins map.
    bg.active_cache_addr = @intFromPtr(&bg.coins);
    try testing.expectError(au.BgError.AliasesActiveChainstate, bg.assertNotAliased());
}

// ---------------------------------------------------------------------------
// AU-2: the bg store is genuinely SEPARATE from the active coins — connecting
// blocks to the bg store does NOT mutate the active UtxoSet, and the bg store
// is empty until the replay runs.
// ---------------------------------------------------------------------------
test "w138 AU-2: bg store is a separate object, seeded empty, not the active coins" {
    const allocator = testing.allocator;

    var active = storage.UtxoSet.init(null, 8, allocator);
    defer active.deinit();
    // Put one coin in the active set.
    const spk = p2pkh();
    const op = types.OutPoint{ .hash = [_]u8{0xAB} ** 32, .index = 0 };
    try active.add(&op, &types.TxOut{ .value = 1, .script_pubkey = &spk }, 1, false);
    try testing.expectEqual(@as(usize, 1), active.cache.count());

    var bg = au.BgChainState.init(allocator, &active);
    defer bg.deinit();
    // Background store seeded empty (NOT copied from the active set).
    try testing.expectEqual(@as(usize, 0), bg.coinCount());

    // Connect a 3-block chain to the bg store.
    const blocks = try buildTestChain(allocator, 3);
    defer freeTestChain(allocator, blocks);
    var height: u32 = 0;
    while (height < blocks.len) : (height += 1) try bg.connectBlock(&blocks[height], height);

    // Active set is untouched (still exactly its one coin).
    try testing.expectEqual(@as(usize, 1), active.cache.count());
    // Background set has coins from the replay (genesis coinbase excluded).
    try testing.expect(bg.coinCount() > 0);
}

// ---------------------------------------------------------------------------
// AU-3 (CORRECT SNAPSHOT): a snapshot whose committed hash_serialized equals
// the GENUINE genesis→base re-derivation hash → VALIDATED.
// ---------------------------------------------------------------------------
test "w138 AU-3: correct snapshot — genesis→base re-derivation MATCHES → validated" {
    const allocator = testing.allocator;

    const n: u32 = 5;
    const blocks = try buildTestChain(allocator, n);
    defer freeTestChain(allocator, blocks);
    const base_height: u32 = n - 1;

    // Derive the GENUINE hash by an independent replay (this is what an honest
    // snapshot creator commits to). Use a throwaway bg store.
    const genuine_hash = blk: {
        var g = au.BgChainState.init(allocator, null);
        defer g.deinit();
        var h: u32 = 0;
        while (h <= base_height) : (h += 1) try g.connectBlock(&blocks[h], h);
        break :blk try g.computeHashSerialized();
    };

    const au_data = consensus.AssumeUtxoData{
        .height = base_height,
        .block_hash = [_]u8{0x11} ** 32,
        .hash_serialized = genuine_hash, // honest: committed to the genuine set
        .chain_tx_count = 0,
    };

    var chain = TestChain{ .allocator = allocator, .blocks = blocks };
    const prov = chain.provider();

    const activation = try au.runBackgroundValidation(
        allocator,
        &prov,
        &au_data,
        base_height,
        true, // stage-1 load gate "passed"
        null,
    );
    try testing.expectEqual(au.ValidationResult.validated, activation.result);
    try testing.expectEqualSlices(u8, &genuine_hash, &activation.actual_hash);
}

// ---------------------------------------------------------------------------
// AU-4 (THE NON-CIRCULAR REJECT FALSIFICATION):
//
//   Build a TAMPERED UTXO set = the genuine set PLUS a phantom coin the replay
//   never creates. Commit the snapshot to its OWN tampered hash (hash-of-self).
//   That self-committed hash PASSES the load-time gate (stage 1 hashes the
//   file's own coins). BUT the background genesis→base re-derivation re-derives
//   the GENUINE set, whose hash DIFFERS → INVALID. And the phantom coin is
//   ABSENT from the bg store — proving an independent re-derivation, not a
//   hash-of-self.
// ---------------------------------------------------------------------------
test "w138 AU-4: reject falsification — phantom-coin snapshot passes load gate, fails real re-derivation" {
    const allocator = testing.allocator;

    const n: u32 = 5;
    const blocks = try buildTestChain(allocator, n);
    defer freeTestChain(allocator, blocks);
    const base_height: u32 = n - 1;

    // The phantom coin the genuine replay NEVER creates.
    const phantom_txid: types.Hash256 = [_]u8{0xDE} ** 32;
    const phantom_vout: u32 = 7;
    const phantom_spk = p2pkh();

    // ── Build the TAMPERED hash = HASH_SERIALIZED over (genuine set + phantom).
    // We replay the genuine set into a bg store, then insert the phantom coin
    // directly into that store's map and hash it. This is the "hash-of-self"
    // value a tampered snapshot would commit to.
    const tampered_hash = blk: {
        var t = au.BgChainState.init(allocator, null);
        defer t.deinit();
        var h: u32 = 0;
        while (h <= base_height) : (h += 1) try t.connectBlock(&blocks[h], h);
        // Inject the phantom coin directly into the store (bypassing replay):
        try insertPhantom(&t, allocator, phantom_txid, phantom_vout, 1_000, &phantom_spk);
        break :blk try t.computeHashSerialized();
    };

    // Sanity: the tampered hash MUST differ from the genuine hash (otherwise the
    // test would be vacuous — the phantom must actually change the set hash).
    const genuine_hash = blk: {
        var g = au.BgChainState.init(allocator, null);
        defer g.deinit();
        var h: u32 = 0;
        while (h <= base_height) : (h += 1) try g.connectBlock(&blocks[h], h);
        break :blk try g.computeHashSerialized();
    };
    try testing.expect(!std.mem.eql(u8, &tampered_hash, &genuine_hash));

    // The snapshot commits to its OWN tampered hash (hash-of-self).
    const au_data = consensus.AssumeUtxoData{
        .height = base_height,
        .block_hash = [_]u8{0x11} ** 32,
        .hash_serialized = tampered_hash,
        .chain_tx_count = 0,
    };

    // STAGE 1 (conceptual): the load-time gate hashes the tampered FILE's own
    // coins → tampered_hash == au_data.hash_serialized → PASSES. (We pass
    // load_gate_passed=true to mirror that.)
    //
    // STAGE 2: the REAL background genesis→base re-derivation re-derives the
    // GENUINE set (no phantom), whose hash != tampered_hash → INVALID.
    var chain = TestChain{ .allocator = allocator, .blocks = blocks };
    const prov = chain.provider();

    const activation = try au.runBackgroundValidation(
        allocator,
        &prov,
        &au_data,
        base_height,
        true,
        null,
    );
    try testing.expectEqual(au.ValidationResult.invalid, activation.result);
    // The re-derived hash is the GENUINE hash (not the tampered self-hash).
    try testing.expectEqualSlices(u8, &genuine_hash, &activation.actual_hash);
    try testing.expect(!std.mem.eql(u8, &activation.actual_hash, &au_data.hash_serialized));

    // ── PROVE the phantom is ABSENT from a genuine bg re-derivation. ──────────
    var bg = au.BgChainState.init(allocator, null);
    defer bg.deinit();
    var h: u32 = 0;
    while (h <= base_height) : (h += 1) try bg.connectBlock(&blocks[h], h);
    try testing.expect(!bg.hasCoin(&phantom_txid, phantom_vout));
}

/// Inject a phantom coin directly into a bg store (test-only — simulates a
/// snapshot file containing a coin the genesis→base replay never creates).
fn insertPhantom(
    bg: *au.BgChainState,
    allocator: std.mem.Allocator,
    txid: types.Hash256,
    vout: u32,
    value: i64,
    spk: []const u8,
) !void {
    _ = allocator;
    try bg.addPhantomCoin(txid, vout, value, spk);
}

// ---------------------------------------------------------------------------
// AU-5: validateAgainst refuses to validate before the base height is reached
// (Core only validates once the background chainstate ReachedTarget()).
// ---------------------------------------------------------------------------
test "w138 AU-5: validateAgainst errors if base height not yet reached" {
    const allocator = testing.allocator;
    const blocks = try buildTestChain(allocator, 4);
    defer freeTestChain(allocator, blocks);

    var bg = au.BgChainState.init(allocator, null);
    defer bg.deinit();
    // Connect only up to height 1 (base is 3).
    try bg.connectBlock(&blocks[0], 0);
    try bg.connectBlock(&blocks[1], 1);

    const au_data = consensus.AssumeUtxoData{
        .height = 3,
        .block_hash = [_]u8{0x11} ** 32,
        .hash_serialized = [_]u8{0} ** 32,
        .chain_tx_count = 0,
    };
    try testing.expectError(au.BgError.BaseNotReached, bg.validateAgainst(&au_data, 3, null));
}

// ---------------------------------------------------------------------------
// AU-6: runtime-registerable regtest whitelist — register, find, clear.
// mainnet/testnet4 m_assumeutxo_data UNTOUCHED (separate comptime table).
// ---------------------------------------------------------------------------
test "w138 AU-6: runtime regtest AssumeUTXO whitelist register/find/clear" {
    const allocator = testing.allocator;
    au.clearRegtestWhitelist(allocator);
    defer au.clearRegtestWhitelist(allocator);

    const base_hash: types.Hash256 = [_]u8{0x5A} ** 32;
    const hs: types.Hash256 = [_]u8{0x99} ** 32;

    // Not present before registration.
    try testing.expect(au.findRegtestSnapshot(&base_hash) == null);

    try au.registerRegtestSnapshot(allocator, .{
        .height = 100,
        .block_hash = base_hash,
        .hash_serialized = hs,
        .chain_tx_count = 0,
    });
    const found = au.findRegtestSnapshot(&base_hash) orelse return error.NotFound;
    try testing.expectEqual(@as(u32, 100), found.height);
    try testing.expectEqualSlices(u8, &hs, &found.hash_serialized);

    // The canonical comptime tables are untouched (still Core-exact).
    try testing.expectEqual(@as(usize, 4), consensus.MAINNET.assume_utxo.len);
    try testing.expectEqual(@as(usize, 0), consensus.TESTNET4.assume_utxo.len);
}
