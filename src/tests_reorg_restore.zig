//! Reorg disconnect → spent-coin RESTORE persistence tests.
//!
//! Reproduces the live clearbit un-pin blocker: after a reorg disconnects a
//! block, the coins that block SPENT must be restored into the *durable* UTXO
//! set (CF_UTXO on disk), matching Bitcoin Core's DisconnectBlock ->
//! ApplyTxInUndo (validation.cpp:2149/2179).  A block on the new chain (or any
//! later forward block) that legitimately spends a pre-fork coin must then find
//! it — otherwise the node false-rejects with MissingInput and the UTXO set is
//! permanently corrupted.
//!
//! The assertions read the coin back straight from RocksDB (db.get(CF_UTXO,...))
//! — the same durable set a post-restart / post-eviction forward-connect reads —
//! so a restore that only touched the in-memory cache does NOT satisfy them.

const std = @import("std");
const storage = @import("storage.zig");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");

const ChainState = storage.ChainState;
const Database = storage.Database;
const CF_UTXO = storage.CF_UTXO;

fn coinbaseOnlyBlock(prev_hash: [32]u8, comptime cb_script_byte: u8) types.Block {
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const cb_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{cb_script_byte} ** 20);
    const coinbase_output = types.TxOut{
        .value = 5_000_000_000,
        .script_pubkey = cb_script,
    };
    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };
    return types.Block{
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = prev_hash,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = 0,
            .bits = 0,
            .nonce = 0,
        },
        .transactions = &[_]types.Transaction{coinbase_tx},
    };
}

fn queueAndConnect(cs: *ChainState, block: *const types.Block, hash: *const [32]u8, height: u32) !void {
    const allocator = cs.allocator;
    var w = serialize.Writer.init(allocator);
    try serialize.writeBlock(&w, block);
    const owned_const = try w.toOwnedSlice();
    const owned: []u8 = @constCast(owned_const);
    try cs.queueBlockWrite(hash, owned, height);
    try cs.connectBlockFastWithUndo(block, hash, height);
}

// Core scenario: a pre-fork coin X is spent by chain A, the competing chain B
// does NOT spend X.  The reorg must RESTORE X into the on-disk UTXO set.
test "tests_reorg_restore: reorg restores pre-fork coin spent by disconnected chain to durable UTXO set" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    // --- Pre-fork coin X (a normal, spendable, non-coinbase output). ---
    const x_outpoint = types.OutPoint{ .hash = [_]u8{0xFE} ** 32, .index = 0 };
    const x_script = [_]u8{ 0x76, 0xA9, 0x14 } ++ [_]u8{0xCC} ** 20 ++ [_]u8{ 0x88, 0xAC };
    const x_output = types.TxOut{ .value = 100_000_000, .script_pubkey = &x_script };
    try cs.utxo_set.add(&x_outpoint, &x_output, 1, false);

    const x_key = storage.makeUtxoKey(&x_outpoint);

    // Fork-point block h1 (coinbase only). Connecting flushes X to CF_UTXO too.
    const h1 = coinbaseOnlyBlock([_]u8{0} ** 32, 0xF1);
    const H1 = [_]u8{0x11} ** 32;
    try queueAndConnect(&cs, &h1, &H1, 1);
    try std.testing.expectEqual(@as(u32, 1), cs.best_height);

    // X is now durable on disk.
    {
        const on_disk = try db.get(CF_UTXO, &x_key);
        defer if (on_disk) |b| allocator.free(b);
        try std.testing.expect(on_disk != null);
    }

    // --- Chain A: h2_A spends X (coinbase + spend-tx). ---
    const cbA_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x02, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const cbA_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0x2A} ** 20);
    const cbA_out = types.TxOut{ .value = 5_000_000_000, .script_pubkey = cbA_script };
    const cbA = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{cbA_input},
        .outputs = &[_]types.TxOut{cbA_out},
        .lock_time = 0,
    };
    const spendX_input = types.TxIn{
        .previous_output = x_outpoint,
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const yA_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0xAF} ** 20);
    const yA_out = types.TxOut{ .value = 90_000_000, .script_pubkey = yA_script };
    const spendX = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{spendX_input},
        .outputs = &[_]types.TxOut{yA_out},
        .lock_time = 0,
    };
    const h2_A = types.Block{
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = H1,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = 0,
            .bits = 0,
            .nonce = 0,
        },
        .transactions = &[_]types.Transaction{ cbA, spendX },
    };
    const H2A = [_]u8{0x2A} ** 32;
    try queueAndConnect(&cs, &h2_A, &H2A, 2);
    try std.testing.expectEqual(@as(u32, 2), cs.best_height);

    // X consumed: gone from the durable set.
    {
        const on_disk = try db.get(CF_UTXO, &x_key);
        defer if (on_disk) |b| allocator.free(b);
        try std.testing.expect(on_disk == null);
    }

    // --- Reorg to chain B (h2_B, coinbase only, does NOT spend X). ---
    const h2_B = coinbaseOnlyBlock(H1, 0x2B);
    const H2B = [_]u8{0x2B} ** 32;
    var new_chain = [_]ChainState.ReorgBlock{
        .{ .hash = H2B, .block = h2_B, .height = 2 },
    };
    const connected = try cs.reorgToChain(&H1, &new_chain);
    try std.testing.expectEqual(@as(u32, 1), connected);
    try std.testing.expectEqual(@as(u32, 2), cs.best_height);
    try std.testing.expectEqualSlices(u8, &H2B, &cs.best_hash);

    // *** THE EFFECTIVE ASSERTION ***
    // The disconnect of h2_A must have restored X to the DURABLE UTXO set.
    // Pre-fix (restore lost): db.get returns null -> FAILS.
    // Post-fix: X is present on disk -> PASSES.
    {
        const on_disk = try db.get(CF_UTXO, &x_key);
        defer if (on_disk) |b| allocator.free(b);
        if (on_disk == null) {
            std.debug.print(
                "REGRESSION: pre-fork coin X was NOT restored to the durable UTXO set after reorg disconnect\n",
                .{},
            );
        }
        try std.testing.expect(on_disk != null);
    }

    // And it must round-trip with the correct value/metadata via the cache view.
    var x_after = (try cs.utxo_set.get(&x_outpoint)) orelse {
        std.debug.print("REGRESSION: X missing from UTXO set view after reorg\n", .{});
        return error.CoinNotRestored;
    };
    defer x_after.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 100_000_000), x_after.value);
    try std.testing.expectEqual(false, x_after.is_coinbase);

    // --- Strongest check: a later forward block on chain B spends X. ---
    // This is the exact live failure: block 955887 spends a coin restored by
    // the reorg.  It must connect cleanly (pre-fix: MissingInput).
    const cbC_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x03, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const cbC_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0x3B} ** 20);
    const cbC_out = types.TxOut{ .value = 5_000_000_000, .script_pubkey = cbC_script };
    const cbC = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{cbC_input},
        .outputs = &[_]types.TxOut{cbC_out},
        .lock_time = 0,
    };
    const spendX2_input = types.TxIn{
        .previous_output = x_outpoint,
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const yC_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0xCF} ** 20);
    const yC_out = types.TxOut{ .value = 80_000_000, .script_pubkey = yC_script };
    const spendX2 = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{spendX2_input},
        .outputs = &[_]types.TxOut{yC_out},
        .lock_time = 0,
    };
    const h3_B = types.Block{
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = H2B,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = 0,
            .bits = 0,
            .nonce = 0,
        },
        .transactions = &[_]types.Transaction{ cbC, spendX2 },
    };
    const H3B = [_]u8{0x3B} ** 32;
    queueAndConnect(&cs, &h3_B, &H3B, 3) catch |err| {
        std.debug.print(
            "REGRESSION: forward block spending restored coin X failed to connect: {}\n",
            .{err},
        );
        return err;
    };
    try std.testing.expectEqual(@as(u32, 3), cs.best_height);
}

// Reorg-back un-pin blocker: a reorg that ABORTS after the disconnect walk
// began (here: an unreachable fork_point, so the walk tears down the whole
// active chain and hits the genesis guard -> error.ForkPointNotOnChain) must
// NOT leave the in-memory tip collapsed to genesis.  This is the exact live
// symptom: reorg A->B succeeds, then reorg-back B->A' fails with
//   "reorgToChain: walked back to genesis without finding fork point"
// and best_hash/best_height corrupt to genesis (h0) while disk keeps the
// pre-reorg tip.  Bitcoin Core's ActivateBestChainStep leaves m_chain.Tip()
// unchanged when a DisconnectTip/ConnectTip step fails.
//
// Pre-fix: abortReorgInProgress deliberately did NOT restore best_hash/
// best_height, so the disconnect walk's in-memory rewind to genesis stuck ->
// best_height == 0, best_hash == all-zeros (FAILS the assertions below).
// Post-fix: the pre-reorg snapshot is restored on abort -> best_height == 3,
// best_hash == the durable tip (PASSES), matching what is still on disk.
test "tests_reorg_restore: aborted reorg (unreachable fork point) preserves the in-memory tip (no genesis collapse)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    // Build a 3-block active chain (heights 1..3), distinct coinbase txids.
    // Unrolled because coinbaseOnlyBlock's script marker is a comptime param.
    var hashes: [3][32]u8 = undefined;
    inline for (.{ 0xC1, 0xC2, 0xC3 }, 1..) |marker, height| {
        const prev: [32]u8 = if (height == 1) [_]u8{0} ** 32 else hashes[height - 2];
        const block = coinbaseOnlyBlock(prev, marker);
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(height);
        bh[1] = 0xC0;
        hashes[height - 1] = bh;
        try queueAndConnect(&cs, &block, &bh, @intCast(height));
    }
    try std.testing.expectEqual(@as(u32, 3), cs.best_height);
    try std.testing.expectEqualSlices(u8, &hashes[2], &cs.best_hash);

    // The height-3 coinbase output is durable on disk — we re-check it AFTER
    // the aborted reorg to prove the on-disk tip is untouched.
    const cb3 = coinbaseOnlyBlock(hashes[1], 0xC3);
    const cb3_txid = crypto.computeTxidStreaming(&cb3.transactions[0]);
    const cb3_outpoint = types.OutPoint{ .hash = cb3_txid, .index = 0 };
    const cb3_key = storage.makeUtxoKey(&cb3_outpoint);
    {
        const on_disk = try db.get(CF_UTXO, &cb3_key);
        defer if (on_disk) |b| allocator.free(b);
        try std.testing.expect(on_disk != null);
    }

    // Attempt a reorg whose fork_point is NOT on the active chain (and is not
    // genesis).  The disconnect walk rewinds h3->h2->h1->genesis in memory,
    // never matches the fork_point, and trips the genesis guard.
    const bogus_fork_point: types.Hash256 = [_]u8{0xAB} ** 32;
    const dummy = coinbaseOnlyBlock(bogus_fork_point, 0xDD);
    var new_chain = [_]ChainState.ReorgBlock{
        .{ .hash = [_]u8{0xDD} ** 32, .block = dummy, .height = 1 },
    };
    const res = cs.reorgToChain(&bogus_fork_point, &new_chain);
    try std.testing.expectError(error.ForkPointNotOnChain, res);

    // *** THE EFFECTIVE ASSERTIONS ***
    // In-memory tip must be RESTORED to the pre-reorg tip, not collapsed to
    // genesis.  Pre-fix: best_height == 0, best_hash == all-zeros.
    if (cs.best_height != 3 or !std.mem.eql(u8, &cs.best_hash, &hashes[2])) {
        std.debug.print(
            "REGRESSION: aborted reorg collapsed the in-memory tip — best_height={d} best_hash[0]={x} (expected height=3)\n",
            .{ cs.best_height, cs.best_hash[0] },
        );
    }
    try std.testing.expectEqual(@as(u32, 3), cs.best_height);
    try std.testing.expectEqualSlices(u8, &hashes[2], &cs.best_hash);

    // And the durable on-disk tip is unchanged: h3's coinbase still present.
    {
        const on_disk = try db.get(CF_UTXO, &cb3_key);
        defer if (on_disk) |b| allocator.free(b);
        try std.testing.expect(on_disk != null);
    }
}

// Deep-reorg atomicity: a reorg whose connect phase crosses a cache-eviction
// boundary must STILL commit in exactly ONE RocksDB WriteBatch (Pattern D).
//
// The live incident was a ~276-block reorg under memory pressure.  Before the
// fix, connectBlockInner's tail-eviction fired flush() mid-reorg (at every
// height % 10 == 0 that was over the cache budget), splitting the reorg across
// multiple WriteBatches and committing a PARTIAL reorg to disk — so a crash or
// a later mid-reorg abort could leave the durable chainstate at an
// inconsistent intermediate tip whose UTXO set false-rejects the next forward
// block with MissingInput.
//
// This test drives the cache budget to zero so the connect of block height 10
// crosses the eviction boundary, and asserts the whole reorg is a single
// WriteBatch.  Pre-fix: >1 WriteBatch (FAILS).  Post-fix: exactly 1 (PASSES).
test "tests_reorg_restore: deep reorg under cache pressure commits in a single WriteBatch (Pattern D)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    // --- Chain A: 10 coinbase-only blocks (heights 1..10). ---
    var prev_a: [32]u8 = [_]u8{0} ** 32;
    var ha: u32 = 1;
    while (ha <= 10) : (ha += 1) {
        const block = coinbaseOnlyBlock(prev_a, 0xA0);
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(ha);
        bh[1] = 0xA0;
        try queueAndConnect(&cs, &block, &bh, ha);
        prev_a = bh;
    }
    try std.testing.expectEqual(@as(u32, 10), cs.best_height);

    // Force the eviction threshold to zero so the reorg's connect phase will
    // cross the "cache over budget" boundary at height 10 (height % 10 == 0).
    cs.utxo_set.max_cache_size = 0;

    // --- Chain B: 11 coinbase-only blocks (heights 1..11), forking at genesis. ---
    var blocks_b: [11]types.Block = undefined;
    var hashes_b: [11][32]u8 = undefined;
    var prev_b: [32]u8 = [_]u8{0} ** 32;
    var i: u32 = 0;
    while (i < 11) : (i += 1) {
        blocks_b[i] = coinbaseOnlyBlock(prev_b, 0xB0);
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(i + 1);
        bh[1] = 0xB0;
        hashes_b[i] = bh;
        prev_b = bh;
    }
    var new_chain: [11]ChainState.ReorgBlock = undefined;
    i = 0;
    while (i < 11) : (i += 1) {
        new_chain[i] = .{ .hash = hashes_b[i], .block = blocks_b[i], .height = i + 1 };
    }

    const fork_point: types.Hash256 = [_]u8{0} ** 32;
    const writes_before = db.write_batch_calls;
    const connected = try cs.reorgToChain(&fork_point, &new_chain);
    const reorg_writes = db.write_batch_calls - writes_before;

    try std.testing.expectEqual(@as(u32, 11), connected);
    try std.testing.expectEqual(@as(u32, 11), cs.best_height);

    if (reorg_writes != 1) {
        std.debug.print(
            "REGRESSION: reorg under cache pressure issued {d} WriteBatch calls (expected 1) — " ++
                "mid-reorg eviction split the Pattern-D batch and committed a partial reorg\n",
            .{reorg_writes},
        );
    }
    try std.testing.expectEqual(@as(u64, 1), reorg_writes);
}

// ---------------------------------------------------------------------------
// REORG-DISCRIMINATING regression for 968b2c4 (the sole live un-pin blocker).
//
// WHY THE EXISTING TESTS ABOVE DO NOT COVER THIS
// ----------------------------------------------
// The "Pattern D" test above drives coinbase-only blocks through the
// network_params==null reorg path, so reorgToChain's connect side goes
// STRAIGHT to connectBlockInner, which sets suppress_eviction=true before any
// prevout read.  It exercises the connectBlockInner *tail*-eviction (already
// fixed by 1590efa) and passes on BOTH HEAD and 968b2c4's parent 1ae8c61 —
// i.e. it does NOT discriminate the 968b2c4 fix.
//
// The live 956162->955886 boot-wedge came from a DIFFERENT eviction site:
// the read-through eviction check in UtxoSet.get() (storage.zig ~1065).  During
// a deep reorg that window is only reachable via the connect-side script-
// validation Adapter (storage.zig ~5429, guarded by `self.network_params`),
// which runs the prevout `get()` lookups AFTER the last disconnect's `defer`
// reset suppress_eviction=false but BEFORE connectBlockInner re-sets it.  With
// >=1000 accumulated restore-adds (a 276-deep disconnect) + a cold-coin prevout
// (cache miss -> DB read-through) + cache over budget, get() fired evictCache()
// while in_no_flush_batch=true.  Pre-fix evictCache() did a FULL ChainState
// flush() MID-REORG, splitting the single Pattern-D WriteBatch and durably
// committing a PARTIAL reorg (fork-point tip + deleted old-branch undo + stale
// H: index); a crash then boot-wedged with UndoDataNotFound FATAL.
//
// Faithfully driving that end-to-end needs network_params set, which forces
// real PoW + full script/merkle/BIP34/witness validation over a 276-block,
// 1000-coin synthetic fixture — the uncommitted crash-injection harness the
// 968b2c4 footer referenced.  The two tests below instead drive the REAL
// buggy code paths (UtxoSet.get() read-through -> evictCache routing, and the
// ChainState.flush() chokepoint) in the EXACT flag-state reorgToChain
// establishes at the vulnerable window (in_no_flush_batch=true,
// suppress_eviction=false, adds_since_eviction_check>=1000, cache over budget).
// They discriminate cleanly:
//   * post-fix (968b2c4): no mid-batch WriteBatch (single atomic reorg commit);
//   * pre-fix  (1ae8c61): a mid-batch flush() fires -> the split that wedges.

// (1) get() read-through eviction inside the no-flush reorg batch must route to
//     the clean-only drop, NOT a full flush that splits the WriteBatch.
test "tests_reorg_restore: read-through eviction inside the reorg no-flush batch does not split the WriteBatch (968b2c4)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    // --- Cold coin C: a spendable non-coinbase prevout that lives ON DISK ONLY.
    // This is the "cold-coin prevout" the connect-side Adapter get()s during the
    // reorg; the cache miss forces the read-through path that carries the
    // eviction check.  Written straight to RocksDB (never added to the cache) so
    // the later get() is guaranteed to take the DB read-through branch.
    const c_outpoint = types.OutPoint{ .hash = [_]u8{0xC0} ** 32, .index = 0 };
    const c_hash: [20]u8 = [_]u8{0xCD} ** 20; // P2WPKH witness-program hash
    const c_compact = storage.CompactUtxo{
        .height = 5,
        .is_coinbase = false,
        .value = 42_000_000,
        .script_type = storage.CompactUtxo.SCRIPT_P2WPKH,
        .hash_or_script = &c_hash,
    };
    const c_key = storage.makeUtxoKey(&c_outpoint);
    {
        const encoded = try c_compact.encode(allocator);
        defer allocator.free(@constCast(encoded));
        try db.put(CF_UTXO, &c_key, encoded);
    }
    // Sanity: C is durable on disk and NOT in the cache.
    {
        const on_disk = try db.get(CF_UTXO, &c_key);
        defer if (on_disk) |b| allocator.free(b);
        try std.testing.expect(on_disk != null);
        try std.testing.expect(cs.utxo_set.cache.get(c_key) == null);
    }

    // --- Dirty coin D: stands in for the accumulated in-flight reorg mutations
    // (disconnect restores + earlier connect adds) that are dirty-in-cache and
    // NOT yet persisted.  A mid-batch flush would durably commit D as part of a
    // PARTIAL reorg — exactly the split we must prevent.  Left dirty (unflushed).
    const d_outpoint = types.OutPoint{ .hash = [_]u8{0xD0} ** 32, .index = 0 };
    const d_script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xDE} ** 20; // P2WPKH
    const d_out = types.TxOut{ .value = 7_000_000, .script_pubkey = &d_script };
    try cs.utxo_set.add(&d_outpoint, &d_out, 6, false);
    const d_key = storage.makeUtxoKey(&d_outpoint);
    try std.testing.expect(cs.utxo_set.cache.get(d_key) != null);

    // --- Reproduce reorgToChain's vulnerable window state exactly:
    //   * in_no_flush_batch=true  (reorgToChain accumulating its one WriteBatch)
    //   * suppress_eviction=false  (last disconnect's `defer` reset it; the
    //                               first connect block's Adapter runs here)
    //   * adds_since_eviction_check at 999 (a 276-deep disconnect left it >=1000;
    //                               the next read-through add tips the check)
    //   * cache over budget (max_cache_size=0 -> any resident entry is "large")
    cs.utxo_set.max_cache_size = 0;
    cs.utxo_set.suppress_eviction = false;
    cs.utxo_set.adds_since_eviction_check = 999;
    cs.in_no_flush_batch = true;

    const writes_before = db.write_batch_calls;

    // The connect-side Adapter prevout lookup: cache miss -> DB read-through ->
    // adds_since_eviction_check hits 1000 -> cache over budget -> evictCache().
    var c_got = (try cs.utxo_set.get(&c_outpoint)) orelse {
        cs.in_no_flush_batch = false;
        return error.ColdCoinMissing;
    };
    defer c_got.deinit(allocator);

    const reorg_writes = db.write_batch_calls - writes_before;

    // *** THE EFFECTIVE ASSERTIONS ***
    // Post-fix (968b2c4): evictCache saw in_no_flush_batch -> evictCleanOnly ->
    // ZERO WriteBatch calls; the reorg batch stays whole.
    // Pre-fix (1ae8c61): evictCache did a full ChainState.flush() MID-REORG ->
    // >=1 WriteBatch -> the split that durably committed a partial reorg and
    // boot-wedged (UndoDataNotFound) on the live node.
    if (reorg_writes != 0) {
        std.debug.print(
            "REGRESSION (968b2c4): read-through eviction inside the reorg no-flush batch " ++
                "issued {d} WriteBatch call(s) — a mid-reorg flush SPLIT the Pattern-D batch " ++
                "(the 956162->955886 boot-wedge shape)\n",
            .{reorg_writes},
        );
    }
    try std.testing.expectEqual(@as(u64, 0), reorg_writes);

    // The dirty in-flight coin D must NOT have been flushed+wiped: a clean-only
    // drop keeps it resident (dirty), whereas the pre-fix full flush persisted
    // it and cleared the cache.
    const d_after = cs.utxo_set.cache.get(d_key);
    if (d_after == null) {
        std.debug.print(
            "REGRESSION (968b2c4): dirty in-flight reorg coin D was flushed+evicted mid-batch " ++
                "(full-flush split), not preserved by the clean-only drop\n",
            .{},
        );
    }
    try std.testing.expect(d_after != null);
    try std.testing.expect(d_after.?.dirty);

    // The cold coin still reads back correctly through the read-through.
    try std.testing.expectEqual(@as(i64, 42_000_000), c_got.value);
    try std.testing.expectEqual(false, c_got.is_coinbase);

    // Restore the flag before teardown so deinit's paths are unaffected.
    cs.in_no_flush_batch = false;
}

// (2) The flush() chokepoint must REFUSE any flush while the reorg batch is
//     accumulating (covers evictCache AND a flushchainstate RPC racing the
//     reorg between two per-block connect_mutex holds).
test "tests_reorg_restore: flush() refuses a mid-reorg-batch commit (Pattern-D chokepoint, 968b2c4)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    // A dirty coin so a flush would have real work to commit (a non-empty
    // WriteBatch) — otherwise "no write" could be a false negative.
    const e_outpoint = types.OutPoint{ .hash = [_]u8{0xEE} ** 32, .index = 0 };
    const e_script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xEF} ** 20;
    const e_out = types.TxOut{ .value = 3_000_000, .script_pubkey = &e_script };
    try cs.utxo_set.add(&e_outpoint, &e_out, 7, false);

    cs.in_no_flush_batch = true;
    const writes_before = db.write_batch_calls;

    // Post-fix (968b2c4): flush() hits the chokepoint guard and returns
    // error.ReorgBatchInProgress WITHOUT issuing a WriteBatch.
    // Pre-fix (1ae8c61): no guard -> flush() commits -> returns void and bumps
    // write_batch_calls, so expectError FAILS (the discriminator).
    const res = cs.flush();
    cs.in_no_flush_batch = false;

    try std.testing.expectError(error.ReorgBatchInProgress, res);
    try std.testing.expectEqual(writes_before, db.write_batch_calls);
}
