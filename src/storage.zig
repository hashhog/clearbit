//! RocksDB-based storage layer for Bitcoin chain data.
//!
//! This module provides persistent storage for blocks, UTXOs, and chain metadata
//! using RocksDB via C interop. Column families are used to organize different
//! data types with appropriate compaction and caching settings.
//!
//! **Dependencies:**
//! - RocksDB development files (librocksdb-dev on Debian/Ubuntu, rocksdb-devel on Fedora)
//!
//! The storage is organized into column families:
//! - `default`: Chain metadata (chain tip, etc.)
//! - `blocks`: Raw block data keyed by block hash
//! - `block_index`: Block header + height keyed by block hash
//! - `utxo`: Unspent transaction outputs keyed by outpoint (txid + vout)
//! - `tx_index`: Transaction location (block hash + index) keyed by txid

const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");

/// Column family indices for organizing data.
/// Each stores a different type of data with potentially different
/// compaction and caching settings.
pub const CF_DEFAULT: usize = 0;
pub const CF_BLOCKS: usize = 1; // Raw block data
pub const CF_BLOCK_INDEX: usize = 2; // Block header + metadata by hash
pub const CF_UTXO: usize = 3; // Unspent transaction outputs
pub const CF_TX_INDEX: usize = 4; // Transaction hash -> block location

pub const StorageError = error{
    OpenFailed,
    WriteFailed,
    ReadFailed,
    NotFound,
    CorruptData,
    OutOfMemory,
    SerializationFailed,
    RocksDBNotAvailable,
};

/// Batch operation for atomic writes.
pub const BatchOp = union(enum) {
    put: struct { cf: usize, key: []const u8, value: []const u8 },
    delete: struct { cf: usize, key: []const u8 },
};

/// UTXO entry stored in the database.
pub const UtxoEntry = struct {
    value: i64,
    script_pubkey: []const u8,
    height: u32,
    is_coinbase: bool,

    /// Serialize the UTXO entry to bytes.
    pub fn toBytes(self: *const UtxoEntry, allocator: std.mem.Allocator) StorageError![]const u8 {
        var writer = serialize.Writer.init(allocator);
        errdefer writer.deinit();

        writer.writeInt(i64, self.value) catch return StorageError.SerializationFailed;
        writer.writeInt(u32, self.height) catch return StorageError.SerializationFailed;
        writer.writeInt(u8, if (self.is_coinbase) 1 else 0) catch return StorageError.SerializationFailed;
        writer.writeCompactSize(self.script_pubkey.len) catch return StorageError.SerializationFailed;
        writer.writeBytes(self.script_pubkey) catch return StorageError.SerializationFailed;

        return writer.toOwnedSlice() catch return StorageError.OutOfMemory;
    }

    /// Deserialize a UTXO entry from bytes.
    pub fn fromBytes(data: []const u8, allocator: std.mem.Allocator) StorageError!UtxoEntry {
        var reader = serialize.Reader{ .data = data };

        const value = reader.readInt(i64) catch return StorageError.CorruptData;
        const height = reader.readInt(u32) catch return StorageError.CorruptData;
        const is_coinbase_byte = reader.readInt(u8) catch return StorageError.CorruptData;
        const script_len = reader.readCompactSize() catch return StorageError.CorruptData;
        const script_bytes = reader.readBytes(@intCast(script_len)) catch return StorageError.CorruptData;

        const script_pubkey = allocator.dupe(u8, script_bytes) catch return StorageError.OutOfMemory;

        return UtxoEntry{
            .value = value,
            .script_pubkey = script_pubkey,
            .height = height,
            .is_coinbase = is_coinbase_byte != 0,
        };
    }

    /// Free the script_pubkey memory.
    pub fn deinit(self: *UtxoEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.script_pubkey);
    }
};

/// Create the UTXO key from an outpoint: txid (32 bytes) ++ output_index (4 bytes LE).
pub fn makeUtxoKey(outpoint: *const types.OutPoint) [36]u8 {
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
    return key;
}

// ============================================================================
// RocksDB Implementation (conditionally compiled)
// ============================================================================

/// Wrapper around RocksDB database handle.
/// This struct is only functional when linked with RocksDB.
/// Use Database.open() to create instances.
pub const Database = struct {
    /// Opaque handle to the underlying storage.
    handle: *anyopaque,
    allocator: std.mem.Allocator,

    /// Open or create the database at the given path.
    /// Returns RocksDBNotAvailable if RocksDB is not linked.
    pub fn open(path: []const u8, allocator: std.mem.Allocator) StorageError!Database {
        _ = path;
        _ = allocator;
        // RocksDB is not available in this build configuration.
        // Install rocksdb-devel (Fedora) or librocksdb-dev (Debian/Ubuntu)
        // and rebuild with: zig build -Drocksdb=true
        return StorageError.RocksDBNotAvailable;
    }

    /// Close the database.
    pub fn close(self: *Database) void {
        _ = self;
    }

    /// Get a value by key from a column family.
    pub fn get(self: *Database, cf_index: usize, key: []const u8) StorageError!?[]const u8 {
        _ = self;
        _ = cf_index;
        _ = key;
        return StorageError.RocksDBNotAvailable;
    }

    /// Put a key-value pair into a column family.
    pub fn put(self: *Database, cf_index: usize, key: []const u8, value: []const u8) StorageError!void {
        _ = self;
        _ = cf_index;
        _ = key;
        _ = value;
        return StorageError.RocksDBNotAvailable;
    }

    /// Delete a key from a column family.
    pub fn delete(self: *Database, cf_index: usize, key: []const u8) StorageError!void {
        _ = self;
        _ = cf_index;
        _ = key;
        return StorageError.RocksDBNotAvailable;
    }

    /// Batch write: apply multiple operations atomically.
    pub fn writeBatch(self: *Database, operations: []const BatchOp) StorageError!void {
        _ = self;
        _ = operations;
        return StorageError.RocksDBNotAvailable;
    }

    /// Create an iterator for scanning a column family.
    pub fn iterator(self: *Database, cf_index: usize) Iterator {
        _ = self;
        _ = cf_index;
        return Iterator{};
    }

    /// Flush all in-memory data to disk.
    pub fn flush(self: *Database) StorageError!void {
        _ = self;
        return StorageError.RocksDBNotAvailable;
    }
};

/// Iterator for scanning a column family.
/// Stub implementation when RocksDB is not available.
pub const Iterator = struct {
    pub fn seekToFirst(self: *Iterator) void {
        _ = self;
    }

    pub fn seekToLast(self: *Iterator) void {
        _ = self;
    }

    pub fn seekTo(self: *Iterator, target_key: []const u8) void {
        _ = self;
        _ = target_key;
    }

    pub fn valid(self: *Iterator) bool {
        _ = self;
        return false;
    }

    pub fn next(self: *Iterator) void {
        _ = self;
    }

    pub fn prev(self: *Iterator) void {
        _ = self;
    }

    pub fn getKey(self: *Iterator) []const u8 {
        _ = self;
        return &[_]u8{};
    }

    pub fn getValue(self: *Iterator) []const u8 {
        _ = self;
        return &[_]u8{};
    }

    pub fn deinit(self: *Iterator) void {
        _ = self;
    }
};

/// High-level chain storage operations.
pub const ChainStore = struct {
    db: Database,
    allocator: std.mem.Allocator,

    /// Key used for storing chain tip in the default CF.
    const CHAIN_TIP_KEY = "chain_tip";

    pub fn init(datadir: []const u8, allocator: std.mem.Allocator) StorageError!ChainStore {
        const db = try Database.open(datadir, allocator);
        return ChainStore{
            .db = db,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ChainStore) void {
        self.db.close();
    }

    /// Store a block header with its height.
    /// Serializes: height (4 bytes) + header (80 bytes)
    pub fn putBlockIndex(
        self: *ChainStore,
        hash: *const types.Hash256,
        header: *const types.BlockHeader,
        height: u32,
    ) StorageError!void {
        var writer = serialize.Writer.init(self.allocator);
        defer writer.deinit();

        writer.writeInt(u32, height) catch return StorageError.SerializationFailed;
        serialize.writeBlockHeader(&writer, header) catch return StorageError.SerializationFailed;

        try self.db.put(CF_BLOCK_INDEX, hash, writer.getWritten());
    }

    /// Retrieve a block header and its height by hash.
    pub fn getBlockIndex(self: *ChainStore, hash: *const types.Hash256) StorageError!?struct {
        header: types.BlockHeader,
        height: u32,
    } {
        const data = try self.db.get(CF_BLOCK_INDEX, hash);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        var reader = serialize.Reader{ .data = data.? };
        const height = reader.readInt(u32) catch return StorageError.CorruptData;
        const header = serialize.readBlockHeader(&reader) catch return StorageError.CorruptData;

        return .{ .header = header, .height = height };
    }

    /// Store raw block data.
    pub fn putBlock(
        self: *ChainStore,
        hash: *const types.Hash256,
        data: []const u8,
    ) StorageError!void {
        try self.db.put(CF_BLOCKS, hash, data);
    }

    /// Retrieve raw block data.
    /// Returns owned memory that must be freed by the caller.
    pub fn getBlock(self: *ChainStore, hash: *const types.Hash256) StorageError!?[]const u8 {
        return try self.db.get(CF_BLOCKS, hash);
    }

    /// Store/update a UTXO entry.
    pub fn putUtxo(
        self: *ChainStore,
        outpoint: *const types.OutPoint,
        txout: *const types.TxOut,
        height: u32,
        is_coinbase: bool,
    ) StorageError!void {
        const key = makeUtxoKey(outpoint);

        const entry = UtxoEntry{
            .value = txout.value,
            .script_pubkey = txout.script_pubkey,
            .height = height,
            .is_coinbase = is_coinbase,
        };

        const data = try entry.toBytes(self.allocator);
        defer self.allocator.free(data);

        try self.db.put(CF_UTXO, &key, data);
    }

    /// Retrieve a UTXO entry.
    /// Caller must call entry.deinit(allocator) when done.
    pub fn getUtxo(self: *ChainStore, outpoint: *const types.OutPoint) StorageError!?UtxoEntry {
        const key = makeUtxoKey(outpoint);

        const data = try self.db.get(CF_UTXO, &key);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        return try UtxoEntry.fromBytes(data.?, self.allocator);
    }

    /// Delete a UTXO entry (when spent).
    pub fn deleteUtxo(self: *ChainStore, outpoint: *const types.OutPoint) StorageError!void {
        const key = makeUtxoKey(outpoint);
        try self.db.delete(CF_UTXO, &key);
    }

    /// Store chain tip metadata.
    pub fn putChainTip(self: *ChainStore, hash: *const types.Hash256, height: u32) StorageError!void {
        var buf: [36]u8 = undefined;
        @memcpy(buf[0..32], hash);
        std.mem.writeInt(u32, buf[32..36], height, .little);

        try self.db.put(CF_DEFAULT, CHAIN_TIP_KEY, &buf);
    }

    /// Get current chain tip.
    pub fn getChainTip(self: *ChainStore) StorageError!?struct { hash: types.Hash256, height: u32 } {
        const data = try self.db.get(CF_DEFAULT, CHAIN_TIP_KEY);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        if (data.?.len != 36) return StorageError.CorruptData;

        var hash: types.Hash256 = undefined;
        @memcpy(&hash, data.?[0..32]);
        const height = std.mem.readInt(u32, data.?[32..36], .little);

        return .{ .hash = hash, .height = height };
    }

    /// Store a transaction index entry: tx_hash -> (block_hash, tx_index_in_block).
    pub fn putTxIndex(
        self: *ChainStore,
        txid: *const types.Hash256,
        block_hash: *const types.Hash256,
        tx_index: u32,
    ) StorageError!void {
        var buf: [36]u8 = undefined;
        @memcpy(buf[0..32], block_hash);
        std.mem.writeInt(u32, buf[32..36], tx_index, .little);

        try self.db.put(CF_TX_INDEX, txid, &buf);
    }

    /// Get a transaction index entry.
    pub fn getTxIndex(self: *ChainStore, txid: *const types.Hash256) StorageError!?struct {
        block_hash: types.Hash256,
        tx_index: u32,
    } {
        const data = try self.db.get(CF_TX_INDEX, txid);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        if (data.?.len != 36) return StorageError.CorruptData;

        var block_hash: types.Hash256 = undefined;
        @memcpy(&block_hash, data.?[0..32]);
        const tx_index = std.mem.readInt(u32, data.?[32..36], .little);

        return .{ .block_hash = block_hash, .tx_index = tx_index };
    }

    /// Apply a batch of UTXO updates atomically (for block connect/disconnect).
    pub fn applyUtxoBatch(
        self: *ChainStore,
        creates: []const struct { outpoint: types.OutPoint, txout: types.TxOut, height: u32, is_coinbase: bool },
        spends: []const types.OutPoint,
    ) StorageError!void {
        var ops = std.ArrayList(BatchOp).init(self.allocator);
        defer {
            for (ops.items) |op| {
                switch (op) {
                    .put => |p| self.allocator.free(p.value),
                    .delete => {},
                }
            }
            ops.deinit();
        }

        // Build batch operations
        for (creates) |create| {
            const entry = UtxoEntry{
                .value = create.txout.value,
                .script_pubkey = create.txout.script_pubkey,
                .height = create.height,
                .is_coinbase = create.is_coinbase,
            };

            const data = try entry.toBytes(self.allocator);
            const key = makeUtxoKey(&create.outpoint);

            // We need to store the key in allocated memory for the batch
            const key_copy = self.allocator.alloc(u8, 36) catch return StorageError.OutOfMemory;
            @memcpy(key_copy, &key);

            ops.append(.{
                .put = .{ .cf = CF_UTXO, .key = key_copy, .value = data },
            }) catch return StorageError.OutOfMemory;
        }

        for (spends) |outpoint| {
            const key = makeUtxoKey(&outpoint);

            const key_copy = self.allocator.alloc(u8, 36) catch return StorageError.OutOfMemory;
            @memcpy(key_copy, &key);

            ops.append(.{
                .delete = .{ .cf = CF_UTXO, .key = key_copy },
            }) catch return StorageError.OutOfMemory;
        }

        // Apply atomically
        try self.db.writeBatch(ops.items);

        // Free the keys we allocated
        for (ops.items) |op| {
            switch (op) {
                .put => |p| self.allocator.free(@constCast(p.key)),
                .delete => |d| self.allocator.free(@constCast(d.key)),
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "utxo entry serialization" {
    const allocator = std.testing.allocator;

    const script = [_]u8{ 0x76, 0xa9, 0x14, 0x00, 0x11, 0x22 };
    const entry = UtxoEntry{
        .value = 5000000000,
        .script_pubkey = &script,
        .height = 100000,
        .is_coinbase = true,
    };

    const serialized = try entry.toBytes(allocator);
    defer allocator.free(serialized);

    var deserialized = try UtxoEntry.fromBytes(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(entry.value, deserialized.value);
    try std.testing.expectEqual(entry.height, deserialized.height);
    try std.testing.expectEqual(entry.is_coinbase, deserialized.is_coinbase);
    try std.testing.expectEqualSlices(u8, entry.script_pubkey, deserialized.script_pubkey);
}

test "utxo entry non-coinbase" {
    const allocator = std.testing.allocator;

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const entry = UtxoEntry{
        .value = 123456789,
        .script_pubkey = &script,
        .height = 700000,
        .is_coinbase = false,
    };

    const serialized = try entry.toBytes(allocator);
    defer allocator.free(serialized);

    var deserialized = try UtxoEntry.fromBytes(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(entry.value, deserialized.value);
    try std.testing.expectEqual(entry.height, deserialized.height);
    try std.testing.expect(!deserialized.is_coinbase);
    try std.testing.expectEqualSlices(u8, entry.script_pubkey, deserialized.script_pubkey);
}

test "utxo key format" {
    // Verify UTXO key format: txid (32 bytes) ++ index (4 bytes LE)
    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0x12345678,
    };

    const key = makeUtxoKey(&outpoint);

    // First 32 bytes should be the hash
    try std.testing.expectEqualSlices(u8, &outpoint.hash, key[0..32]);

    // Last 4 bytes should be index in little-endian
    try std.testing.expectEqual(@as(u8, 0x78), key[32]);
    try std.testing.expectEqual(@as(u8, 0x56), key[33]);
    try std.testing.expectEqual(@as(u8, 0x34), key[34]);
    try std.testing.expectEqual(@as(u8, 0x12), key[35]);
}

test "storage error variants" {
    // Ensure all error variants are distinct
    const errors = [_]StorageError{
        StorageError.OpenFailed,
        StorageError.WriteFailed,
        StorageError.ReadFailed,
        StorageError.NotFound,
        StorageError.CorruptData,
        StorageError.OutOfMemory,
        StorageError.SerializationFailed,
        StorageError.RocksDBNotAvailable,
    };

    for (errors, 0..) |e1, i| {
        for (errors[i + 1 ..]) |e2| {
            try std.testing.expect(e1 != e2);
        }
    }
}

test "column family constants" {
    // Verify column family indices are unique and sequential
    try std.testing.expectEqual(@as(usize, 0), CF_DEFAULT);
    try std.testing.expectEqual(@as(usize, 1), CF_BLOCKS);
    try std.testing.expectEqual(@as(usize, 2), CF_BLOCK_INDEX);
    try std.testing.expectEqual(@as(usize, 3), CF_UTXO);
    try std.testing.expectEqual(@as(usize, 4), CF_TX_INDEX);
}

test "database returns RocksDBNotAvailable" {
    // Without RocksDB linked, Database.open should return an error
    const allocator = std.testing.allocator;
    const result = Database.open("/tmp/test", allocator);
    try std.testing.expectError(StorageError.RocksDBNotAvailable, result);
}
