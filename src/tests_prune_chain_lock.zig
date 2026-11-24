//! investigate-clearbit-prune-race: the auto-pruner must run under cs_main.
//!
//! main.zig drives `ChainState.pruneToTarget` from the MAIN thread every 60 s,
//! while the P2P thread connects/disconnects blocks and the RPC thread runs
//! `invalidateblock` / `pruneblockchain` — all of those under `connect_mutex`
//! (cs_main).  Before this fix the pruner took no lock: it read `best_height`
//! once, computed `max_prunable = best_height - MIN_BLOCKS_TO_KEEP` from that
//! snapshot, and deleted bodies up to it while another thread was moving the
//! tip.  An `invalidateblock` walk that lowers the tip mid-prune leaves the
//! pruner deleting blocks that are now within 288 of the tip — the blocks a
//! <=288-deep reorg disconnects (BlockBodyNotFound) and that NODE_NETWORK_LIMITED
//! promises to serve.
//!
//! Bitcoin Core: FlushStateToDisk takes LOCK(cs_main) (validation.cpp) around
//! FindFilesToPrune + UnlinkPrunedFiles, and UnlinkPrunedFiles removes each
//! blk file's rev (undo) file with it (node/blockstorage.cpp).  clearbit never
//! deleted CF_BLOCK_UNDO on prune, so undo grew without bound under --prune.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const storage = @import("storage.zig");

const ChainState = storage.ChainState;
const Database = storage.Database;

/// How long the pruner thread is given to finish while the test thread holds
/// cs_main.  Without the lock it needs a few ms; with it it can never finish
/// inside the window.  Generous so a loaded box cannot produce a false PASS.
const RACE_WINDOW_MS: u64 = 1500;

fn hashFor(h: u32) types.Hash256 {
    var hash: types.Hash256 = undefined;
    @memset(&hash, 0x5c);
    std.mem.writeInt(u32, hash[0..4], h, .little);
    return hash;
}

/// Plant heights 1..total: H:{h}->hash, a CF_BLOCKS body and a CF_BLOCK_UNDO
/// record for each (what the connect path writes for an active-chain block).
fn plantChain(db: *Database, total: u32) !void {
    var h: u32 = 1;
    while (h <= total) : (h += 1) {
        const hash = hashFor(h);
        const key = storage.ChainStore.buildHeightHashKey(h);
        try db.put(storage.CF_DEFAULT, &key, &hash);
        const body = [_]u8{0xAB} ** 16;
        try db.put(storage.CF_BLOCKS, &hash, &body);
        const undo = [_]u8{0xCD} ** 8;
        try db.put(storage.CF_BLOCK_UNDO, &hash, &undo);
    }
}

fn present(db: *Database, cf: usize, h: u32) !bool {
    const hash = hashFor(h);
    const got = try db.get(cf, &hash);
    if (got) |b| {
        db.allocator.free(b);
        return true;
    }
    return false;
}

const PrunerCtx = struct {
    cs: *ChainState,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    pruned: u32 = 0,

    fn run(self: *PrunerCtx) void {
        self.pruned = self.cs.pruneToTarget();
        self.done.store(true, .release);
    }
};

fn openTmpDb(tmp: *std.testing.TmpDir, name: []const u8, allocator: std.mem.Allocator) !struct { db: Database, path: []u8 } {
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const p = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ base, name });
    errdefer allocator.free(p);
    return .{ .db = try Database.open(p, 64, allocator), .path = p };
}

test "tests_prune_chain_lock: auto-prune waits for cs_main and prunes against the tip it finds" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const opened = try openTmpDb(&tmp, "prune_race_db", allocator);
    defer allocator.free(opened.path);
    var db = opened.db;
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const TOTAL: u32 = 1000;
    try plantChain(&db, TOTAL);
    cs.best_height = TOTAL;
    cs.prune_target_mib = ChainState.MIN_PRUNE_TARGET_MIB;

    // Another thread (RPC invalidateblock / P2P reorg) holds cs_main and is
    // walking the tip down.  The main-thread pruner fires now.
    cs.connect_mutex.lock();
    var locked = true;
    defer if (locked) cs.connect_mutex.unlock();

    var ctx = PrunerCtx{ .cs = &cs };
    const th = try std.Thread.spawn(.{}, PrunerCtx.run, .{&ctx});

    var waited: u64 = 0;
    while (waited < RACE_WINDOW_MS and !ctx.done.load(.acquire)) : (waited += 10) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }
    const finished_while_held = ctx.done.load(.acquire);

    // The walk under cs_main lowers the tip to 500 (blocks 501..1000
    // disconnected; their bodies stay for reconsiderblock).  The keep window
    // is now heights 213..500.
    const NEW_TIP: u32 = 500;
    cs.best_height = NEW_TIP;
    cs.connect_mutex.unlock();
    locked = false;
    th.join();

    // Height 250 is 250 below the new tip — inside the keep window.  A pruner
    // working from the stale tip (1000 -> max 712) deletes it.
    try testing.expect(try present(&db, storage.CF_BLOCKS, 250));
    try testing.expect(try present(&db, storage.CF_BLOCKS, NEW_TIP - ChainState.MIN_BLOCKS_TO_KEEP + 1));
    // Once it gets the lock it must use the tip it finds then: nothing within
    // MIN_BLOCKS_TO_KEEP of NEW_TIP may be gone.
    try testing.expect(cs.prune_height <= NEW_TIP - ChainState.MIN_BLOCKS_TO_KEEP);
    // And it must not have run at all while cs_main was held elsewhere.
    try testing.expect(!finished_while_held);
}

test "tests_prune_chain_lock: auto-prune deletes the undo record with the block body" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const opened = try openTmpDb(&tmp, "prune_undo_db", allocator);
    defer allocator.free(opened.path);
    var db = opened.db;
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const TOTAL: u32 = 1000;
    try plantChain(&db, TOTAL);
    cs.best_height = TOTAL;
    cs.prune_target_mib = ChainState.MIN_PRUNE_TARGET_MIB;

    const pruned = cs.pruneToTarget();
    try testing.expect(pruned > 0);
    try testing.expect(cs.prune_height >= 1);

    // Every pruned height lost its body AND its undo (Core UnlinkPrunedFiles
    // removes blk + rev together).
    var h: u32 = 1;
    while (h <= cs.prune_height) : (h += 1) {
        try testing.expect(!try present(&db, storage.CF_BLOCKS, h));
        try testing.expect(!try present(&db, storage.CF_BLOCK_UNDO, h));
    }
    // Above the watermark, and inside the keep window, both survive.
    try testing.expect(try present(&db, storage.CF_BLOCKS, cs.prune_height + 1));
    try testing.expect(try present(&db, storage.CF_BLOCK_UNDO, cs.prune_height + 1));
    try testing.expect(try present(&db, storage.CF_BLOCKS, TOTAL));
    try testing.expect(try present(&db, storage.CF_BLOCK_UNDO, TOTAL));
}

test "tests_prune_chain_lock: pruneblockchain path deletes the undo record with the block body" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const opened = try openTmpDb(&tmp, "prune_manual_undo_db", allocator);
    defer allocator.free(opened.path);
    var db = opened.db;
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const TOTAL: u32 = 1000;
    try plantChain(&db, TOTAL);
    cs.best_height = TOTAL;
    cs.prune_target_mib = ChainState.MIN_PRUNE_TARGET_MIB;

    const pruned = cs.pruneToHeight(300);
    try testing.expectEqual(@as(u32, 300), pruned);
    try testing.expectEqual(@as(u32, 300), cs.prune_height);
    try testing.expect(!try present(&db, storage.CF_BLOCKS, 300));
    try testing.expect(!try present(&db, storage.CF_BLOCK_UNDO, 300));
    try testing.expect(!try present(&db, storage.CF_BLOCK_UNDO, 1));
    try testing.expect(try present(&db, storage.CF_BLOCKS, 301));
    try testing.expect(try present(&db, storage.CF_BLOCK_UNDO, 301));
}

/// Live SST bytes of one CF (excludes obsolete files awaiting deletion).
fn liveSst(db: *Database, cf: usize) u64 {
    return db.getCfPropertyInt(cf, "rocksdb.live-sst-files-size") orelse 0;
}

/// Write `n` incompressible values into `cf` (keys tagged by `cf`).
fn fillCf(db: *Database, cf: usize, n: u32, prng: *std.Random.DefaultPrng) !void {
    var buf: [16 * 1024]u8 = undefined;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        var key = hashFor(i);
        key[31] = @intCast(cf);
        prng.random().bytes(&buf);
        try db.put(cf, &key, &buf);
    }
}

fn deleteCf(db: *Database, cf: usize, n: u32) !void {
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        var key = hashFor(i);
        key[31] = @intCast(cf);
        try db.delete(cf, &key);
    }
}

test "tests_prune_chain_lock: a prune burst of deletes gives the block and undo space back" {
    // A delete is a tombstone; the bytes return only when compaction carries
    // it down to the value.  Close + reopen replays the WAL into an L0 SST per
    // CF (RocksDB recovery flush), so: values -> L0, tombstones -> L0.  Two L0
    // files are below the level-0 trigger (4), so without a deletion-driven
    // trigger nothing compacts and the deleted bytes stay on disk.  CF_TX_INDEX
    // gets the same treatment as the CONTROL: it must keep its bytes, which
    // shows the drop comes from the prune CFs' options and not from something
    // every CF does on open.
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fmt.allocPrint(allocator, "{s}/prune_compact_db", .{base});
    defer allocator.free(path);

    const N: u32 = 400; // 400 x 16 KiB = 6.25 MiB per CF
    const cfs = [_]usize{ storage.CF_BLOCKS, storage.CF_BLOCK_UNDO, storage.CF_TX_INDEX };
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);

    {
        var db = try Database.open(path, 8, allocator);
        defer db.close();
        for (cfs) |cf| try fillCf(&db, cf, N, &prng);
    }
    var before: [cfs.len]u64 = undefined;
    {
        var db = try Database.open(path, 8, allocator);
        defer db.close();
        for (cfs, 0..) |cf, i| {
            before[i] = liveSst(&db, cf);
            // The values reached an SST (else the test measures nothing).
            try testing.expect(before[i] >= 4 * 1024 * 1024);
        }
        for (cfs) |cf| try deleteCf(&db, cf, N);
    }

    var db = try Database.open(path, 8, allocator);
    defer db.close();
    // Background compaction: give it up to 20 s.
    var waited_ms: u32 = 0;
    while (waited_ms < 20_000) : (waited_ms += 50) {
        if (liveSst(&db, storage.CF_BLOCKS) < before[0] / 4 and
            liveSst(&db, storage.CF_BLOCK_UNDO) < before[1] / 4) break;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    std.time.sleep(500 * std.time.ns_per_ms);
    try testing.expect(liveSst(&db, storage.CF_BLOCKS) < before[0] / 4);
    try testing.expect(liveSst(&db, storage.CF_BLOCK_UNDO) < before[1] / 4);
    // CONTROL: the same burst in a CF without the trigger keeps its bytes.
    try testing.expect(liveSst(&db, storage.CF_TX_INDEX) >= before[2] / 2);
}
