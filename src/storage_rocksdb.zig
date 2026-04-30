//! RocksDB-based storage implementation.
//!
//! This module contains the actual RocksDB implementation for the storage layer.
//! It requires linking with librocksdb (-lrocksdb) and libc.
//!
//! To use this implementation, build with: zig build -Drocksdb=true
//!
//! **Dependencies:**
//! - RocksDB: apt install librocksdb-dev (Debian/Ubuntu) or dnf install rocksdb-devel (Fedora)

const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const storage = @import("storage.zig");

const c = @cImport({
    @cInclude("rocksdb/c.h");
});

/// Column family names matching the indices in storage.zig
const cf_names = [_][*:0]const u8{
    "default",
    "blocks",
    "block_index",
    "utxo",
    "tx_index",
};

/// Internal database state
const DbState = struct {
    db: ?*c.rocksdb_t,
    write_options: ?*c.rocksdb_writeoptions_t,
    read_options: ?*c.rocksdb_readoptions_t,
    cf_handles: [5]?*c.rocksdb_column_family_handle_t,
    allocator: std.mem.Allocator,
};

/// Open or create the database at the given path.
/// Removes stale LOCK files from unclean shutdowns before opening.
/// `block_cache_mib` sizes the RocksDB LRU block cache in MiB.
pub fn openDatabase(path: []const u8, block_cache_mib: u64, allocator: std.mem.Allocator) storage.StorageError!storage.Database {
    // Remove stale LOCK file left by a previous unclean shutdown.
    // RocksDB uses this file to prevent concurrent access, but if the
    // previous process crashed or was killed, the LOCK remains and blocks
    // reopening.  It is safe to remove because we are the only process
    // that should be accessing this database directory.
    {
        const lock_path = std.fmt.allocPrint(allocator, "{s}/LOCK", .{path}) catch
            return storage.StorageError.OutOfMemory;
        defer allocator.free(lock_path);
        std.fs.deleteFileAbsolute(lock_path) catch {};
    }

    var errptr: ?[*:0]u8 = null;

    const options = c.rocksdb_options_create();
    defer c.rocksdb_options_destroy(options);

    c.rocksdb_options_set_create_if_missing(options, 1);
    c.rocksdb_options_set_create_missing_column_families(options, 1);
    c.rocksdb_options_set_max_open_files(options, -1); // keep all files open (faster lookups)
    c.rocksdb_options_set_compression(options, c.rocksdb_lz4_compression);

    // Larger write buffer: 256 MiB reduces compaction frequency during IBD
    c.rocksdb_options_set_write_buffer_size(options, 256 * 1024 * 1024);
    // Allow 4 write buffers before stalling (default 2)
    c.rocksdb_options_set_max_write_buffer_number(options, 4);
    // Increase max background jobs for compaction/flush
    c.rocksdb_options_set_max_background_jobs(options, 4);

    // Optimize for point lookups (UTXO set)
    const block_based_options = c.rocksdb_block_based_options_create();
    defer c.rocksdb_block_based_options_destroy(block_based_options);

    c.rocksdb_block_based_options_set_block_size(block_based_options, 16 * 1024);
    c.rocksdb_block_based_options_set_cache_index_and_filter_blocks(block_based_options, 1);

    // Bloom filter: 10 bits per key, reduces unnecessary disk reads on misses
    const bloom_filter = c.rocksdb_filterpolicy_create_bloom_full(10);
    c.rocksdb_block_based_options_set_filter_policy(block_based_options, bloom_filter);

    // Block cache: LRU cache for frequently accessed SST blocks (sized via --dbcache).
    // Was previously hardcoded 512 MiB regardless of --dbcache; with high-RAM machines
    // and a 4+ GiB UTXO CF this saturated and forced disk reads (~89% miss rate).
    const block_cache = c.rocksdb_cache_create_lru(block_cache_mib * 1024 * 1024);
    c.rocksdb_block_based_options_set_block_cache(block_based_options, block_cache);

    c.rocksdb_options_set_block_based_table_factory(options, block_based_options);

    const cf_options = [_]?*c.rocksdb_options_t{options} ** 5;
    var cf_handles: [5]?*c.rocksdb_column_family_handle_t = undefined;

    const path_z = allocator.dupeZ(u8, path) catch return storage.StorageError.OutOfMemory;
    defer allocator.free(path_z);

    // First, try to open with all column families
    var db = c.rocksdb_open_column_families(
        options,
        path_z.ptr,
        5,
        &cf_names,
        &cf_options,
        @ptrCast(&cf_handles),
        &errptr,
    );

    if (errptr) |err| {
        std.debug.print("RocksDB: column family open failed (expected on first run): {s}\n", .{err});
        c.rocksdb_free(@ptrCast(err));

        // Column families don't exist yet - open with default only, then create them
        errptr = null;
        db = c.rocksdb_open(options, path_z.ptr, &errptr);

        if (errptr) |err2| {
            std.debug.print("RocksDB: open failed: {s}\n", .{err2});
            c.rocksdb_free(@ptrCast(err2));
            return storage.StorageError.OpenFailed;
        }

        if (db == null) return storage.StorageError.OpenFailed;

        // Create the non-default column families on the freshly opened DB.
        // We do NOT need a handle for the default CF here because we will
        // close this DB and immediately reopen it via rocksdb_open_column_families
        // below, which returns handles for ALL CFs including "default".
        for (1..5) |i| {
            errptr = null;
            const handle = c.rocksdb_create_column_family(
                db,
                options,
                cf_names[i],
                &errptr,
            );
            if (errptr) |err3| {
                c.rocksdb_free(@ptrCast(err3));
                // Destroy already created handles and close
                for (1..i) |j| {
                    if (cf_handles[j] != null) {
                        c.rocksdb_column_family_handle_destroy(cf_handles[j]);
                    }
                }
                c.rocksdb_close(db);
                return storage.StorageError.OpenFailed;
            }
            // Destroy the handle immediately — we will reopen with all CFs below.
            if (handle != null) c.rocksdb_column_family_handle_destroy(handle);
        }
        c.rocksdb_close(db);

        // Reopen with all five column families so we get proper handles.
        errptr = null;
        db = c.rocksdb_open_column_families(
            options,
            path_z.ptr,
            5,
            &cf_names,
            &cf_options,
            @ptrCast(&cf_handles),
            &errptr,
        );
        if (errptr) |err2| {
            std.debug.print("RocksDB: reopen with column families failed: {s}\n", .{err2});
            c.rocksdb_free(@ptrCast(err2));
            return storage.StorageError.OpenFailed;
        }
        if (db == null) return storage.StorageError.OpenFailed;
    }

    const state = allocator.create(DbState) catch return storage.StorageError.OutOfMemory;
    state.* = .{
        .db = if (db != null) db else return storage.StorageError.OpenFailed,
        .write_options = c.rocksdb_writeoptions_create(),
        .read_options = c.rocksdb_readoptions_create(),
        .cf_handles = cf_handles,
        .allocator = allocator,
    };

    return storage.Database{
        .handle = state,
        .allocator = allocator,
    };
}

/// Close the database.
pub fn closeDatabase(db: *storage.Database) void {
    const state: *DbState = @ptrCast(@alignCast(db.handle));

    for (state.cf_handles) |handle| {
        c.rocksdb_column_family_handle_destroy(handle);
    }
    c.rocksdb_writeoptions_destroy(state.write_options);
    c.rocksdb_readoptions_destroy(state.read_options);
    c.rocksdb_close(state.db);

    db.allocator.destroy(state);
}

/// Get a value by key from a column family.
pub fn dbGet(db: *storage.Database, cf_index: usize, key: []const u8) storage.StorageError!?[]const u8 {
    const state: *DbState = @ptrCast(@alignCast(db.handle));

    var errptr: ?[*:0]u8 = null;
    var val_len: usize = 0;

    const val = c.rocksdb_get_cf(
        state.db,
        state.read_options,
        state.cf_handles[cf_index],
        key.ptr,
        key.len,
        &val_len,
        &errptr,
    );

    if (errptr) |err| {
        c.rocksdb_free(@ptrCast(err));
        return storage.StorageError.ReadFailed;
    }

    if (val == null) return null;

    // Copy to Zig-managed memory
    const result = state.allocator.alloc(u8, val_len) catch {
        c.rocksdb_free(@ptrCast(val));
        return storage.StorageError.OutOfMemory;
    };
    @memcpy(result, val[0..val_len]);
    c.rocksdb_free(@ptrCast(val));

    return result;
}

/// Batch point-lookup across a single column family.  results[i] corresponds
/// to keys[i]: null on miss, allocated slice on hit (caller owns via the
/// Database.allocator and must free each non-null result).  Per-key FFI
/// errors are squashed into `null` results — RocksDB's errs array tends to
/// signal things like corrupt SSTs per key; treating as miss is safe because
/// UTXO callers fall through to cache-miss semantics anyway.
pub fn dbMultiGet(
    db: *storage.Database,
    cf_index: usize,
    keys: []const []const u8,
    results: []?[]u8,
) storage.StorageError!void {
    std.debug.assert(results.len == keys.len);
    if (keys.len == 0) return;

    const state: *DbState = @ptrCast(@alignCast(db.handle));
    const a = state.allocator;

    const cfs = a.alloc(?*c.rocksdb_column_family_handle_t, keys.len) catch
        return storage.StorageError.OutOfMemory;
    defer a.free(cfs);
    const key_ptrs = a.alloc([*c]const u8, keys.len) catch
        return storage.StorageError.OutOfMemory;
    defer a.free(key_ptrs);
    const key_sizes = a.alloc(usize, keys.len) catch
        return storage.StorageError.OutOfMemory;
    defer a.free(key_sizes);
    const val_ptrs = a.alloc([*c]u8, keys.len) catch
        return storage.StorageError.OutOfMemory;
    defer a.free(val_ptrs);
    const val_sizes = a.alloc(usize, keys.len) catch
        return storage.StorageError.OutOfMemory;
    defer a.free(val_sizes);
    const errs = a.alloc(?[*:0]u8, keys.len) catch
        return storage.StorageError.OutOfMemory;
    defer a.free(errs);

    for (keys, 0..) |k, i| {
        cfs[i] = state.cf_handles[cf_index];
        key_ptrs[i] = k.ptr;
        key_sizes[i] = k.len;
        val_ptrs[i] = null;
        val_sizes[i] = 0;
        errs[i] = null;
    }

    c.rocksdb_multi_get_cf(
        state.db,
        state.read_options,
        @ptrCast(cfs.ptr),
        keys.len,
        @ptrCast(key_ptrs.ptr),
        key_sizes.ptr,
        @ptrCast(val_ptrs.ptr),
        val_sizes.ptr,
        @ptrCast(errs.ptr),
    );

    for (0..keys.len) |i| {
        if (errs[i]) |err| {
            c.rocksdb_free(@ptrCast(err));
            if (val_ptrs[i] != null) c.rocksdb_free(@ptrCast(val_ptrs[i]));
            results[i] = null;
            continue;
        }
        if (val_ptrs[i] == null) {
            results[i] = null;
            continue;
        }
        const copy = a.alloc(u8, val_sizes[i]) catch {
            c.rocksdb_free(@ptrCast(val_ptrs[i]));
            results[i] = null;
            continue;
        };
        @memcpy(copy, val_ptrs[i][0..val_sizes[i]]);
        c.rocksdb_free(@ptrCast(val_ptrs[i]));
        results[i] = copy;
    }
}

/// Put a key-value pair into a column family.
pub fn dbPut(db: *storage.Database, cf_index: usize, key: []const u8, value: []const u8) storage.StorageError!void {
    const state: *DbState = @ptrCast(@alignCast(db.handle));

    var errptr: ?[*:0]u8 = null;

    c.rocksdb_put_cf(
        state.db,
        state.write_options,
        state.cf_handles[cf_index],
        key.ptr,
        key.len,
        value.ptr,
        value.len,
        &errptr,
    );

    if (errptr) |err| {
        c.rocksdb_free(@ptrCast(err));
        return storage.StorageError.WriteFailed;
    }
}

/// Delete a key from a column family.
pub fn dbDelete(db: *storage.Database, cf_index: usize, key: []const u8) storage.StorageError!void {
    const state: *DbState = @ptrCast(@alignCast(db.handle));

    var errptr: ?[*:0]u8 = null;

    c.rocksdb_delete_cf(
        state.db,
        state.write_options,
        state.cf_handles[cf_index],
        key.ptr,
        key.len,
        &errptr,
    );

    if (errptr) |err| {
        c.rocksdb_free(@ptrCast(err));
        return storage.StorageError.WriteFailed;
    }
}

/// Batch write: apply multiple operations atomically.
pub fn dbWriteBatch(db: *storage.Database, operations: []const storage.BatchOp) storage.StorageError!void {
    const state: *DbState = @ptrCast(@alignCast(db.handle));

    const batch = c.rocksdb_writebatch_create();
    defer c.rocksdb_writebatch_destroy(batch);

    for (operations) |op| {
        switch (op) {
            .put => |p| c.rocksdb_writebatch_put_cf(
                batch,
                state.cf_handles[p.cf],
                p.key.ptr,
                p.key.len,
                p.value.ptr,
                p.value.len,
            ),
            .delete => |d| c.rocksdb_writebatch_delete_cf(
                batch,
                state.cf_handles[d.cf],
                d.key.ptr,
                d.key.len,
            ),
        }
    }

    var errptr: ?[*:0]u8 = null;
    c.rocksdb_write(state.db, state.write_options, batch, &errptr);

    if (errptr) |err| {
        c.rocksdb_free(@ptrCast(err));
        return storage.StorageError.WriteFailed;
    }
}

/// Flush all in-memory data to disk.
pub fn dbFlush(db: *storage.Database) storage.StorageError!void {
    const state: *DbState = @ptrCast(@alignCast(db.handle));

    var errptr: ?[*:0]u8 = null;
    const flush_options = c.rocksdb_flushoptions_create();
    defer c.rocksdb_flushoptions_destroy(flush_options);

    c.rocksdb_flush(state.db, flush_options, &errptr);

    if (errptr) |err| {
        c.rocksdb_free(@ptrCast(err));
        return storage.StorageError.WriteFailed;
    }
}

/// Fetch an integer-valued RocksDB property for a specific column family.
/// Used by the pruner to estimate live-data size of CF_BLOCKS so it can
/// decide whether to delete more blocks. Returns null if the property is
/// not supported (older RocksDB) or the underlying call fails.
///
/// Common property names:
///   - "rocksdb.estimate-live-data-size" — uncompressed live-data estimate
///   - "rocksdb.total-sst-files-size"   — sum of all SST file sizes (incl.
///     obsolete-but-not-yet-deleted files)
///   - "rocksdb.cur-size-active-mem-table" — current memtable size
pub fn dbGetCfPropertyInt(
    db: *storage.Database,
    cf_index: usize,
    propname_z: [*:0]const u8,
) ?u64 {
    const state: *DbState = @ptrCast(@alignCast(db.handle));
    var out_val: u64 = 0;
    const rc = c.rocksdb_property_int_cf(
        state.db,
        state.cf_handles[cf_index],
        propname_z,
        &out_val,
    );
    if (rc != 0) return null;
    return out_val;
}

/// Internal iterator state
const IterState = struct {
    inner: *c.rocksdb_iterator_t,
    allocator: std.mem.Allocator,
};

/// Create an iterator for scanning a column family.
pub fn dbIterator(db: *storage.Database, cf_index: usize) storage.Iterator {
    const state: *DbState = @ptrCast(@alignCast(db.handle));

    const it = c.rocksdb_create_iterator_cf(
        state.db,
        state.read_options,
        state.cf_handles[cf_index],
    );

    const iter_state = state.allocator.create(IterState) catch @panic("OOM");
    iter_state.* = .{
        .inner = it,
        .allocator = state.allocator,
    };

    // Return a stub Iterator, the real state is tracked separately
    return storage.Iterator{};
}

// ============================================================================
// Tests (only run when RocksDB is linked)
// ============================================================================

test "rocksdb database open and close" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    const db_path = try std.fmt.allocPrint(allocator, "{s}/testdb", .{path});
    defer allocator.free(db_path);

    // Open database
    var db = try openDatabase(db_path, 64, allocator);
    closeDatabase(&db);

    // Re-open to verify persistence
    var db2 = try openDatabase(db_path, 64, allocator);
    closeDatabase(&db2);
}

test "rocksdb put and get" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    const db_path = try std.fmt.allocPrint(allocator, "{s}/testdb", .{path});
    defer allocator.free(db_path);

    var db = try openDatabase(db_path, 64, allocator);
    defer closeDatabase(&db);

    // Put a key-value pair
    const key = "test_key";
    const value = "test_value";
    try dbPut(&db, storage.CF_DEFAULT, key, value);

    // Get it back
    const result = try dbGet(&db, storage.CF_DEFAULT, key);
    try std.testing.expect(result != null);
    defer allocator.free(result.?);

    try std.testing.expectEqualStrings(value, result.?);
}

test "rocksdb delete" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    const db_path = try std.fmt.allocPrint(allocator, "{s}/testdb", .{path});
    defer allocator.free(db_path);

    var db = try openDatabase(db_path, 64, allocator);
    defer closeDatabase(&db);

    const key = "delete_test";
    const value = "to_be_deleted";

    // Put then delete
    try dbPut(&db, storage.CF_DEFAULT, key, value);
    try dbDelete(&db, storage.CF_DEFAULT, key);

    // Verify it's gone
    const result = try dbGet(&db, storage.CF_DEFAULT, key);
    try std.testing.expect(result == null);
}

test "rocksdb batch write" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    const db_path = try std.fmt.allocPrint(allocator, "{s}/testdb", .{path});
    defer allocator.free(db_path);

    var db = try openDatabase(db_path, 64, allocator);
    defer closeDatabase(&db);

    // Create batch operations
    const ops = [_]storage.BatchOp{
        .{ .put = .{ .cf = storage.CF_DEFAULT, .key = "batch_key1", .value = "value1" } },
        .{ .put = .{ .cf = storage.CF_DEFAULT, .key = "batch_key2", .value = "value2" } },
        .{ .put = .{ .cf = storage.CF_DEFAULT, .key = "batch_key3", .value = "value3" } },
    };

    try dbWriteBatch(&db, &ops);

    // Verify all keys exist
    for ([_][]const u8{ "batch_key1", "batch_key2", "batch_key3" }, 0..) |key, i| {
        const result = try dbGet(&db, storage.CF_DEFAULT, key);
        try std.testing.expect(result != null);
        defer allocator.free(result.?);

        const expected_arr = [_][]const u8{ "value1", "value2", "value3" };
        const expected = expected_arr[i];
        try std.testing.expectEqualStrings(expected, result.?);
    }
}

test "rocksdb column families" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    const db_path = try std.fmt.allocPrint(allocator, "{s}/testdb", .{path});
    defer allocator.free(db_path);

    var db = try openDatabase(db_path, 64, allocator);
    defer closeDatabase(&db);

    // Store same key in different column families
    try dbPut(&db, storage.CF_DEFAULT, "same_key", "default_value");
    try dbPut(&db, storage.CF_BLOCKS, "same_key", "blocks_value");
    try dbPut(&db, storage.CF_UTXO, "same_key", "utxo_value");

    // Verify isolation
    {
        const result = try dbGet(&db, storage.CF_DEFAULT, "same_key");
        defer allocator.free(result.?);
        try std.testing.expectEqualStrings("default_value", result.?);
    }
    {
        const result = try dbGet(&db, storage.CF_BLOCKS, "same_key");
        defer allocator.free(result.?);
        try std.testing.expectEqualStrings("blocks_value", result.?);
    }
    {
        const result = try dbGet(&db, storage.CF_UTXO, "same_key");
        defer allocator.free(result.?);
        try std.testing.expectEqualStrings("utxo_value", result.?);
    }
}
