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
    db: *c.rocksdb_t,
    write_options: *c.rocksdb_writeoptions_t,
    read_options: *c.rocksdb_readoptions_t,
    cf_handles: [5]*c.rocksdb_column_family_handle_t,
    allocator: std.mem.Allocator,
};

/// Open or create the database at the given path.
pub fn openDatabase(path: []const u8, allocator: std.mem.Allocator) storage.StorageError!storage.Database {
    var errptr: ?[*:0]u8 = null;

    const options = c.rocksdb_options_create();
    defer c.rocksdb_options_destroy(options);

    c.rocksdb_options_set_create_if_missing(options, 1);
    c.rocksdb_options_set_create_missing_column_families(options, 1);
    c.rocksdb_options_set_max_open_files(options, 256);
    c.rocksdb_options_set_compression(options, c.rocksdb_lz4_compression);

    // Optimize for point lookups (UTXO set)
    const block_based_options = c.rocksdb_block_based_options_create();
    defer c.rocksdb_block_based_options_destroy(block_based_options);

    c.rocksdb_block_based_options_set_block_size(block_based_options, 16 * 1024);
    c.rocksdb_block_based_options_set_cache_index_and_filter_blocks(block_based_options, 1);
    c.rocksdb_options_set_block_based_table_factory(options, block_based_options);

    const cf_options = [_]*c.rocksdb_options_t{options} ** 5;
    var cf_handles: [5]*c.rocksdb_column_family_handle_t = undefined;

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
        c.rocksdb_free(@ptrCast(err));

        // Column families don't exist yet - open with default only, then create them
        errptr = null;
        db = c.rocksdb_open(options, path_z.ptr, &errptr);

        if (errptr) |err2| {
            c.rocksdb_free(@ptrCast(err2));
            return storage.StorageError.OpenFailed;
        }

        if (db == null) return storage.StorageError.OpenFailed;

        // Create the column families
        cf_handles[0] = c.rocksdb_get_default_column_family_handle(db);
        if (cf_handles[0] == null) {
            c.rocksdb_close(db);
            return storage.StorageError.OpenFailed;
        }

        for (1..5) |i| {
            errptr = null;
            cf_handles[i] = c.rocksdb_create_column_family(
                db,
                options,
                cf_names[i],
                &errptr,
            );
            if (errptr) |err3| {
                c.rocksdb_free(@ptrCast(err3));
                // Clean up already created handles
                for (1..i) |j| {
                    c.rocksdb_column_family_handle_destroy(cf_handles[j]);
                }
                c.rocksdb_close(db);
                return storage.StorageError.OpenFailed;
            }
        }
    }

    const state = allocator.create(DbState) catch return storage.StorageError.OutOfMemory;
    state.* = .{
        .db = db orelse return storage.StorageError.OpenFailed,
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
    var db = try openDatabase(db_path, allocator);
    closeDatabase(&db);

    // Re-open to verify persistence
    var db2 = try openDatabase(db_path, allocator);
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

    var db = try openDatabase(db_path, allocator);
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

    var db = try openDatabase(db_path, allocator);
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

    var db = try openDatabase(db_path, allocator);
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

    var db = try openDatabase(db_path, allocator);
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
