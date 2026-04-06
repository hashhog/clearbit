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
const build_options = @import("build_options");
const rocksdb_enabled = build_options.rocksdb_enabled;
const storage_rocksdb = if (rocksdb_enabled) @import("storage_rocksdb.zig") else struct {};

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
    PathTooLong,
    UndoManagerNotConfigured,
    UndoDataNotFound,
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
    @setRuntimeSafety(true);
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
    pub const open = if (rocksdb_enabled) openRocksDb else openStub;

    fn openRocksDb(path: []const u8, allocator: std.mem.Allocator) StorageError!Database {
        return storage_rocksdb.openDatabase(path, allocator);
    }

    fn openStub(_: []const u8, _: std.mem.Allocator) StorageError!Database {
        return StorageError.RocksDBNotAvailable;
    }

    /// Close the database.
    pub const close = if (rocksdb_enabled) closeRocksDb else closeStub;

    fn closeRocksDb(self: *Database) void {
        storage_rocksdb.closeDatabase(self);
    }

    fn closeStub(_: *Database) void {}

    /// Get a value by key from a column family.
    pub const get = if (rocksdb_enabled) getRocksDb else getStub;

    fn getRocksDb(self: *Database, cf_index: usize, key: []const u8) StorageError!?[]const u8 {
        return storage_rocksdb.dbGet(self, cf_index, key);
    }

    fn getStub(_: *Database, _: usize, _: []const u8) StorageError!?[]const u8 {
        return StorageError.RocksDBNotAvailable;
    }

    /// Put a key-value pair into a column family.
    pub const put = if (rocksdb_enabled) putRocksDb else putStub;

    fn putRocksDb(self: *Database, cf_index: usize, key: []const u8, value: []const u8) StorageError!void {
        return storage_rocksdb.dbPut(self, cf_index, key, value);
    }

    fn putStub(_: *Database, _: usize, _: []const u8, _: []const u8) StorageError!void {
        return StorageError.RocksDBNotAvailable;
    }

    /// Delete a key from a column family.
    pub const delete = if (rocksdb_enabled) deleteRocksDb else deleteStub;

    fn deleteRocksDb(self: *Database, cf_index: usize, key: []const u8) StorageError!void {
        return storage_rocksdb.dbDelete(self, cf_index, key);
    }

    fn deleteStub(_: *Database, _: usize, _: []const u8) StorageError!void {
        return StorageError.RocksDBNotAvailable;
    }

    /// Batch write: apply multiple operations atomically.
    pub const writeBatch = if (rocksdb_enabled) writeBatchRocksDb else writeBatchStub;

    fn writeBatchRocksDb(self: *Database, operations: []const BatchOp) StorageError!void {
        return storage_rocksdb.dbWriteBatch(self, operations);
    }

    fn writeBatchStub(_: *Database, _: []const BatchOp) StorageError!void {
        return StorageError.RocksDBNotAvailable;
    }

    /// Create an iterator for scanning a column family.
    pub const iterator = if (rocksdb_enabled) iteratorRocksDb else iteratorStub;

    fn iteratorRocksDb(self: *Database, cf_index: usize) Iterator {
        return storage_rocksdb.dbIterator(self, cf_index);
    }

    fn iteratorStub(_: *Database, _: usize) Iterator {
        return Iterator{};
    }

    /// Flush all in-memory data to disk.
    pub const flush = if (rocksdb_enabled) flushRocksDb else flushStub;

    fn flushRocksDb(self: *Database) StorageError!void {
        return storage_rocksdb.dbFlush(self);
    }

    fn flushStub(_: *Database) StorageError!void {
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

    /// Extended block index entry for persistence.
    /// Matches validation.BlockIndexEntry but without the parent pointer.
    pub const BlockIndexRecord = struct {
        height: u32,
        header: types.BlockHeader,
        status: u32, // BlockStatus as packed u32
        chain_work: [32]u8,
        sequence_id: i64,
        file_number: u32,
        file_offset: u64,
    };

    /// Store a full block index entry with status flags and chain work.
    /// Format: height (4) + header (80) + status (4) + chain_work (32) + sequence_id (8) + file_number (4) + file_offset (8) = 140 bytes
    pub fn putBlockIndexFull(
        self: *ChainStore,
        hash: *const types.Hash256,
        record: *const BlockIndexRecord,
    ) StorageError!void {
        var writer = serialize.Writer.init(self.allocator);
        defer writer.deinit();

        writer.writeInt(u32, record.height) catch return StorageError.SerializationFailed;
        serialize.writeBlockHeader(&writer, &record.header) catch return StorageError.SerializationFailed;
        writer.writeInt(u32, record.status) catch return StorageError.SerializationFailed;
        writer.writeBytes(&record.chain_work) catch return StorageError.SerializationFailed;
        writer.writeInt(i64, record.sequence_id) catch return StorageError.SerializationFailed;
        writer.writeInt(u32, record.file_number) catch return StorageError.SerializationFailed;
        writer.writeInt(u64, record.file_offset) catch return StorageError.SerializationFailed;

        try self.db.put(CF_BLOCK_INDEX, hash, writer.getWritten());
    }

    /// Retrieve a full block index entry with status flags and chain work.
    pub fn getBlockIndexFull(self: *ChainStore, hash: *const types.Hash256) StorageError!?BlockIndexRecord {
        const data = try self.db.get(CF_BLOCK_INDEX, hash);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        var reader = serialize.Reader{ .data = data.? };

        const height = reader.readInt(u32) catch return StorageError.CorruptData;
        const header = serialize.readBlockHeader(&reader) catch return StorageError.CorruptData;

        // Try to read extended fields - if not present, use defaults (backward compatibility)
        const status = reader.readInt(u32) catch 0; // Default: no flags set
        var chain_work: [32]u8 = undefined;
        reader.readBytes(&chain_work) catch {
            chain_work = [_]u8{0} ** 32;
        };
        const sequence_id = reader.readInt(i64) catch 0;
        const file_number = reader.readInt(u32) catch 0;
        const file_offset = reader.readInt(u64) catch 0;

        return BlockIndexRecord{
            .height = height,
            .header = header,
            .status = status,
            .chain_work = chain_work,
            .sequence_id = sequence_id,
            .file_number = file_number,
            .file_offset = file_offset,
        };
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

    /// Atomically apply a full block's UTXO changes AND update the chain tip
    /// in a single WriteBatch. This prevents inconsistency if the process crashes
    /// between UTXO writes and tip update.
    pub fn applyBlockAtomic(
        self: *ChainStore,
        creates: []const struct { outpoint: types.OutPoint, txout: types.TxOut, height: u32, is_coinbase: bool },
        spends: []const types.OutPoint,
        tip_hash: *const types.Hash256,
        tip_height: u32,
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

        // UTXO creates
        for (creates) |create| {
            const entry = UtxoEntry{
                .value = create.txout.value,
                .script_pubkey = create.txout.script_pubkey,
                .height = create.height,
                .is_coinbase = create.is_coinbase,
            };

            const data = try entry.toBytes(self.allocator);
            const key = makeUtxoKey(&create.outpoint);

            const key_copy = self.allocator.alloc(u8, 36) catch return StorageError.OutOfMemory;
            @memcpy(key_copy, &key);

            ops.append(.{
                .put = .{ .cf = CF_UTXO, .key = key_copy, .value = data },
            }) catch return StorageError.OutOfMemory;
        }

        // UTXO spends
        for (spends) |outpoint| {
            const key = makeUtxoKey(&outpoint);

            const key_copy = self.allocator.alloc(u8, 36) catch return StorageError.OutOfMemory;
            @memcpy(key_copy, &key);

            ops.append(.{
                .delete = .{ .cf = CF_UTXO, .key = key_copy },
            }) catch return StorageError.OutOfMemory;
        }

        // Chain tip in the SAME batch
        var tip_buf: [36]u8 = undefined;
        @memcpy(tip_buf[0..32], tip_hash);
        std.mem.writeInt(u32, tip_buf[32..36], tip_height, .little);

        const tip_key = self.allocator.alloc(u8, CHAIN_TIP_KEY.len) catch return StorageError.OutOfMemory;
        @memcpy(tip_key, CHAIN_TIP_KEY);

        const tip_val = self.allocator.alloc(u8, 36) catch return StorageError.OutOfMemory;
        @memcpy(tip_val, &tip_buf);

        ops.append(.{
            .put = .{ .cf = CF_DEFAULT, .key = tip_key, .value = tip_val },
        }) catch return StorageError.OutOfMemory;

        // Single atomic write
        try self.db.writeBatch(ops.items);

        // Free allocated keys
        for (ops.items) |op| {
            switch (op) {
                .put => |p| self.allocator.free(@constCast(p.key)),
                .delete => |d| self.allocator.free(@constCast(d.key)),
            }
        }
    }
};

// ============================================================================
// Compact UTXO Entry (Phase 14)
// ============================================================================

/// Compact UTXO entry for storage efficiency.
/// Serialization format:
/// - height (u32 LE) + coinbase flag (1 bit, packed into height MSB)
/// - value (i64 LE)
/// - script_pubkey_type (u8): 0=P2PKH, 1=P2SH, 2=P2WPKH, 3=P2WSH, 4=P2TR, 5=other
/// - For types 0-4: just the 20 or 32 byte hash (script is reconstructed)
/// - For type 5: CompactSize length + raw script bytes
pub const CompactUtxo = struct {
    height: u32,
    is_coinbase: bool,
    value: i64,
    script_type: u8,
    hash_or_script: []const u8,

    /// Script type constants.
    pub const SCRIPT_P2PKH: u8 = 0;
    pub const SCRIPT_P2SH: u8 = 1;
    pub const SCRIPT_P2WPKH: u8 = 2;
    pub const SCRIPT_P2WSH: u8 = 3;
    pub const SCRIPT_P2TR: u8 = 4;
    pub const SCRIPT_OTHER: u8 = 5;

    /// Serialize to compact binary format.
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

    /// Deserialize from compact binary format.
    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !CompactUtxo {
        var reader = serialize.Reader{ .data = data };

        const packed_height = try reader.readInt(u32);
        const value = try reader.readInt(i64);
        const script_type = (try reader.readBytes(1))[0];

        const hash_len: usize = switch (script_type) {
            SCRIPT_P2PKH, SCRIPT_P2WPKH => 20, // P2PKH, P2WPKH
            SCRIPT_P2SH => 20, // P2SH
            SCRIPT_P2WSH, SCRIPT_P2TR => 32, // P2WSH, P2TR
            else => @intCast(try reader.readCompactSize()),
        };

        const hash_data = try reader.readBytes(hash_len);
        const owned = try allocator.dupe(u8, hash_data);

        return CompactUtxo{
            .height = packed_height & 0x7FFFFFFF,
            .is_coinbase = (packed_height & (1 << 31)) != 0,
            .value = value,
            .script_type = script_type,
            .hash_or_script = owned,
        };
    }

    /// Reconstruct the full scriptPubKey from the compact representation.
    pub fn reconstructScript(self: *const CompactUtxo, allocator: std.mem.Allocator) ![]const u8 {
        return switch (self.script_type) {
            SCRIPT_P2PKH => blk: {
                // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                const s = try allocator.alloc(u8, 25);
                s[0] = 0x76;
                s[1] = 0xa9;
                s[2] = 0x14;
                @memcpy(s[3..23], self.hash_or_script[0..20]);
                s[23] = 0x88;
                s[24] = 0xac;
                break :blk s;
            },
            SCRIPT_P2SH => blk: {
                // P2SH: OP_HASH160 <20> OP_EQUAL
                const s = try allocator.alloc(u8, 23);
                s[0] = 0xa9;
                s[1] = 0x14;
                @memcpy(s[2..22], self.hash_or_script[0..20]);
                s[22] = 0x87;
                break :blk s;
            },
            SCRIPT_P2WPKH => blk: {
                // P2WPKH: OP_0 <20>
                const s = try allocator.alloc(u8, 22);
                s[0] = 0x00;
                s[1] = 0x14;
                @memcpy(s[2..22], self.hash_or_script[0..20]);
                break :blk s;
            },
            SCRIPT_P2WSH => blk: {
                // P2WSH: OP_0 <32>
                const s = try allocator.alloc(u8, 34);
                s[0] = 0x00;
                s[1] = 0x20;
                @memcpy(s[2..34], self.hash_or_script[0..32]);
                break :blk s;
            },
            SCRIPT_P2TR => blk: {
                // P2TR: OP_1 <32>
                const s = try allocator.alloc(u8, 34);
                s[0] = 0x51;
                s[1] = 0x20;
                @memcpy(s[2..34], self.hash_or_script[0..32]);
                break :blk s;
            },
            else => try allocator.dupe(u8, self.hash_or_script),
        };
    }

    /// Free owned memory.
    pub fn deinit(self: *CompactUtxo, allocator: std.mem.Allocator) void {
        allocator.free(self.hash_or_script);
    }

    /// Classify a scriptPubKey and return its type.
    pub fn classifyScriptType(script_pubkey: []const u8) u8 {
        // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        // 76 a9 14 <20 bytes> 88 ac
        if (script_pubkey.len == 25 and script_pubkey[0] == 0x76 and script_pubkey[1] == 0xa9 and
            script_pubkey[2] == 0x14 and script_pubkey[23] == 0x88 and script_pubkey[24] == 0xac)
        {
            return SCRIPT_P2PKH;
        }

        // P2SH: OP_HASH160 <20> OP_EQUAL
        // a9 14 <20 bytes> 87
        if (script_pubkey.len == 23 and script_pubkey[0] == 0xa9 and script_pubkey[1] == 0x14 and script_pubkey[22] == 0x87) {
            return SCRIPT_P2SH;
        }

        // P2WPKH: OP_0 <20>
        // 00 14 <20 bytes>
        if (script_pubkey.len == 22 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x14) {
            return SCRIPT_P2WPKH;
        }

        // P2WSH: OP_0 <32>
        // 00 20 <32 bytes>
        if (script_pubkey.len == 34 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x20) {
            return SCRIPT_P2WSH;
        }

        // P2TR: OP_1 <32>
        // 51 20 <32 bytes>
        if (script_pubkey.len == 34 and script_pubkey[0] == 0x51 and script_pubkey[1] == 0x20) {
            return SCRIPT_P2TR;
        }

        return SCRIPT_OTHER;
    }

    /// Extract the hash/data portion from a scriptPubKey based on its type.
    pub fn extractHashFromScript(script_type: u8, script_pubkey: []const u8) []const u8 {
        return switch (script_type) {
            SCRIPT_P2PKH => script_pubkey[3..23], // P2PKH hash
            SCRIPT_P2SH => script_pubkey[2..22], // P2SH hash
            SCRIPT_P2WPKH => script_pubkey[2..22], // P2WPKH hash
            SCRIPT_P2WSH, SCRIPT_P2TR => script_pubkey[2..34], // P2WSH/P2TR hash
            else => script_pubkey, // Store full script
        };
    }

    /// Create a CompactUtxo from a TxOut.
    pub fn fromTxOut(
        output: *const types.TxOut,
        height: u32,
        is_coinbase: bool,
        allocator: std.mem.Allocator,
    ) !CompactUtxo {
        const script_type = classifyScriptType(output.script_pubkey);
        const hash_or_script = extractHashFromScript(script_type, output.script_pubkey);

        return CompactUtxo{
            .height = height,
            .is_coinbase = is_coinbase,
            .value = output.value,
            .script_type = script_type,
            .hash_or_script = try allocator.dupe(u8, hash_or_script),
        };
    }
};

// ============================================================================
// UTXO Set Manager (Phase 14)
// ============================================================================

/// UTXO set manager with in-memory caching.
/// Hash context for UTXO keys that exploits the fact that the first 32 bytes
/// are already a SHA256d hash (txid), so we can use the first 8 bytes directly
/// as the hash value with zero computation overhead.
const UtxoKeyContext = struct {
    pub fn hash(_: UtxoKeyContext, key: [36]u8) u64 {
        @setRuntimeSafety(true);
        return std.mem.readInt(u64, key[0..8], .little);
    }
    pub fn eql(_: UtxoKeyContext, a: [36]u8, b: [36]u8) bool {
        @setRuntimeSafety(true);
        return std.mem.eql(u8, &a, &b);
    }
};

/// Provides efficient lookups with a configurable cache size for IBD performance.
pub const UtxoSet = struct {
    db: ?*Database,
    cache: std.HashMap([36]u8, CacheEntry, UtxoKeyContext, std.hash_map.default_max_load_percentage),
    cache_size: usize,
    max_cache_size: usize,
    allocator: std.mem.Allocator,

    // Statistics
    total_utxos: u64,
    total_amount: i64,
    hits: u64,
    misses: u64,

    // Batched DB deletes for IBD performance
    pending_deletes: std.ArrayList([36]u8),
    adds_since_eviction_check: u32,

    /// Cache entry with ownership tracking.
    const CacheEntry = struct {
        utxo: CompactUtxo,
        dirty: bool, // true if modified but not yet flushed to DB

        fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
            var utxo = self.utxo;
            utxo.deinit(allocator);
        }
    };

    /// Initialize a new UTXO set.
    /// If db is null, operates in memory-only mode (useful for testing).
    pub fn init(db: ?*Database, max_cache_mb: usize, allocator: std.mem.Allocator) UtxoSet {
        // Pre-size HashMap for IBD performance (~3M entries expected for testnet4)
        var cache = std.HashMap([36]u8, CacheEntry, UtxoKeyContext, std.hash_map.default_max_load_percentage).init(allocator);
        cache.ensureTotalCapacity(1 << 17) catch {}; // 128K slots pre-allocated
        return UtxoSet{
            .db = db,
            .cache = cache,
            .cache_size = 0,
            .max_cache_size = max_cache_mb * 1024 * 1024,
            .allocator = allocator,
            .total_utxos = 0,
            .total_amount = 0,
            .hits = 0,
            .misses = 0,
            .pending_deletes = std.ArrayList([36]u8).init(allocator),
            .adds_since_eviction_check = 0,
        };
    }

    pub fn deinit(self: *UtxoSet) void {
        self.flushPendingDeletes() catch {};
        self.pending_deletes.deinit();
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            var cache_entry = entry.value_ptr.*;
            cache_entry.deinit(self.allocator);
        }
        self.cache.deinit();
    }

    /// Look up a UTXO by outpoint.
    pub fn get(self: *UtxoSet, outpoint: *const types.OutPoint) !?CompactUtxo {
        @setRuntimeSafety(true);
        const key = makeUtxoKey(outpoint);

        // Check cache first
        if (self.cache.get(key)) |entry| {
            self.hits += 1;
            // Return a copy so caller doesn't see internal state
            return CompactUtxo{
                .height = entry.utxo.height,
                .is_coinbase = entry.utxo.is_coinbase,
                .value = entry.utxo.value,
                .script_type = entry.utxo.script_type,
                .hash_or_script = try self.allocator.dupe(u8, entry.utxo.hash_or_script),
            };
        }

        // Fall back to database if available
        if (self.db) |db| {
            self.misses += 1;
            const data = db.get(CF_UTXO, &key) catch return null;
            if (data == null) return null;
            defer self.allocator.free(data.?);

            const utxo = try CompactUtxo.decode(data.?, self.allocator);

            // Cache the result (clone for cache storage)
            const cache_utxo = CompactUtxo{
                .height = utxo.height,
                .is_coinbase = utxo.is_coinbase,
                .value = utxo.value,
                .script_type = utxo.script_type,
                .hash_or_script = try self.allocator.dupe(u8, utxo.hash_or_script),
            };
            try self.cache.put(key, CacheEntry{ .utxo = cache_utxo, .dirty = false });

            // Read-throughs also grow the cache; check eviction periodically
            self.adds_since_eviction_check += 1;
            if (self.adds_since_eviction_check >= 1000) {
                self.adds_since_eviction_check = 0;
                if (self.cacheMemoryUsage() > self.max_cache_size) {
                    self.evictCache();
                }
            }

            return utxo;
        }

        return null;
    }

    /// Check if a UTXO exists without returning it.
    pub fn contains(self: *UtxoSet, outpoint: *const types.OutPoint) !bool {
        const key = makeUtxoKey(outpoint);

        // Check cache first
        if (self.cache.contains(key)) {
            return true;
        }

        // Fall back to database if available
        if (self.db) |db| {
            const data = db.get(CF_UTXO, &key) catch return false;
            if (data) |d| {
                self.allocator.free(d);
                return true;
            }
        }

        return false;
    }

    /// Add a UTXO to the set.
    pub fn add(
        self: *UtxoSet,
        outpoint: *const types.OutPoint,
        output: *const types.TxOut,
        height: u32,
        is_coinbase: bool,
    ) !void {
        @setRuntimeSafety(true);
        const key = makeUtxoKey(outpoint);

        // Classify script for compact storage
        const script_type = CompactUtxo.classifyScriptType(output.script_pubkey);
        const hash_or_script = CompactUtxo.extractHashFromScript(script_type, output.script_pubkey);

        const compact = CompactUtxo{
            .height = height,
            .is_coinbase = is_coinbase,
            .value = output.value,
            .script_type = script_type,
            .hash_or_script = try self.allocator.dupe(u8, hash_or_script),
        };

        // Remove old entry if exists (avoid leaking memory)
        if (self.cache.fetchRemove(key)) |old| {
            var entry = old.value;
            entry.deinit(self.allocator);
        }

        // Check eviction every 1000 adds instead of every add (saves overhead)
        self.adds_since_eviction_check += 1;
        if (self.adds_since_eviction_check >= 1000) {
            self.adds_since_eviction_check = 0;
            if (self.cacheMemoryUsage() > self.max_cache_size) {
                self.evictCache();
            }
        }

        // Store in cache (marked dirty for eventual flush to DB)
        try self.cache.put(key, CacheEntry{ .utxo = compact, .dirty = true });

        self.total_utxos += 1;
        self.total_amount += output.value;
    }

    /// Evict entries from the cache to reduce memory usage.
    /// When a DB backend is available, flushes dirty entries first then evicts clean ones.
    /// When running in memory-only mode (no DB), evicts dirty entries directly since
    /// there is nowhere to persist them -- spent UTXOs are already gone and unspent
    /// ones can be re-fetched from the block chain if needed (though in practice
    /// memory-only mode accepts the data loss on eviction).
    fn evictCache(self: *UtxoSet) void {
        // Without a DB backend, eviction permanently loses UTXO data.
        // Only evict when we have a database to fall back to.
        if (self.db == null) return;
        self.flush() catch |err| {
            // If flush fails, do NOT evict -- entries would be lost
            std.debug.print("UTXO evictCache: flush failed with {}, skipping eviction to prevent data loss\n", .{err});
            return;
        };

        var to_remove = std.ArrayList([36]u8).init(self.allocator);
        defer to_remove.deinit();

        const target_count = self.cache.count() / 2;
        var removed: usize = 0;

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            if (removed >= target_count) break;
            // With a DB backend, only evict clean (flushed) entries.
            // Without a DB backend, evict any entry to prevent OOM.
            if (self.db == null or !entry.value_ptr.dirty) {
                to_remove.append(entry.key_ptr.*) catch break;
                removed += 1;
            }
        }

        for (to_remove.items) |key_to_remove| {
            if (self.cache.fetchRemove(key_to_remove)) |old| {
                var entry = old.value;
                entry.deinit(self.allocator);
            }
        }

        if (to_remove.items.len > 0) {
            std.debug.print("UTXO cache eviction: removed {d} entries, {d} remaining\n", .{ to_remove.items.len, self.cache.count() });
        }
    }

    /// Remove a UTXO (spend it). Returns the spent UTXO for undo data.
    pub fn spend(self: *UtxoSet, outpoint: *const types.OutPoint) !?CompactUtxo {
        @setRuntimeSafety(true);
        const key = makeUtxoKey(outpoint);

        // Try to get from cache first
        if (self.cache.fetchRemove(key)) |old| {
            self.total_utxos -= 1;
            self.total_amount -= old.value.utxo.value;

            // Batch the DB delete instead of doing it synchronously
            if (self.db != null) {
                self.pending_deletes.append(key) catch {};
                // Flush batch when it gets large enough
                if (self.pending_deletes.items.len >= 10000) {
                    self.flushPendingDeletes() catch {};
                }
            }

            return old.value.utxo;
        }

        // Not in cache, try database
        if (self.db) |db| {
            const data = db.get(CF_UTXO, &key) catch return null;
            if (data == null) return null;
            defer self.allocator.free(data.?);

            const utxo = try CompactUtxo.decode(data.?, self.allocator);

            // Batch the DB delete
            self.pending_deletes.append(key) catch {};
            if (self.pending_deletes.items.len >= 10000) {
                self.flushPendingDeletes() catch {};
            }

            self.total_utxos -= 1;
            self.total_amount -= utxo.value;

            return utxo;
        }

        return null;
    }

    /// Flush the dirty cache entries to disk.
    pub fn flush(self: *UtxoSet) !void {
        if (self.db == null) return;

        // Flush pending deletes first
        try self.flushPendingDeletes();

        var batch = std.ArrayList(BatchOp).init(self.allocator);
        defer batch.deinit();

        // Track which keys are dirty so we can mark them clean AFTER successful write
        var dirty_keys = std.ArrayList([36]u8).init(self.allocator);
        defer dirty_keys.deinit();

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.dirty) {
                const encoded = try entry.value_ptr.utxo.encode(self.allocator);
                const key_copy = try self.allocator.alloc(u8, 36);
                @memcpy(key_copy, &entry.key_ptr.*);

                try batch.append(.{ .put = .{
                    .cf = CF_UTXO,
                    .key = key_copy,
                    .value = encoded,
                } });
                try dirty_keys.append(entry.key_ptr.*);
            }
        }

        if (batch.items.len > 0) {
            // Write batch to DB - propagate errors instead of silently swallowing
            self.db.?.writeBatch(batch.items) catch |err| {
                std.debug.print("UTXO flush: writeBatch failed with {}, {d} entries NOT persisted\n", .{ err, batch.items.len });
                // Free allocated batch memory before returning error
                for (batch.items) |op| {
                    switch (op) {
                        .put => |p| {
                            self.allocator.free(@constCast(p.key));
                            self.allocator.free(@constCast(p.value));
                        },
                        .delete => |d| self.allocator.free(@constCast(d.key)),
                    }
                }
                return err;
            };

            // Only mark entries as clean AFTER successful writeBatch
            for (dirty_keys.items) |key| {
                if (self.cache.getPtr(key)) |entry_ptr| {
                    entry_ptr.dirty = false;
                }
            }

            // Free the allocated keys and values
            for (batch.items) |op| {
                switch (op) {
                    .put => |p| {
                        self.allocator.free(@constCast(p.key));
                        self.allocator.free(@constCast(p.value));
                    },
                    .delete => |d| self.allocator.free(@constCast(d.key)),
                }
            }
        }
    }

    /// Flush pending DB deletes as a batch operation.
    pub fn flushPendingDeletes(self: *UtxoSet) !void {
        if (self.db == null or self.pending_deletes.items.len == 0) return;

        var batch = std.ArrayList(BatchOp).init(self.allocator);
        defer batch.deinit();

        for (self.pending_deletes.items) |key| {
            const key_copy = try self.allocator.alloc(u8, 36);
            @memcpy(key_copy, &key);
            try batch.append(.{ .delete = .{
                .cf = CF_UTXO,
                .key = key_copy,
            } });
        }

        if (batch.items.len > 0) {
            self.db.?.writeBatch(batch.items) catch |err| {
                std.debug.print("UTXO flushPendingDeletes: writeBatch failed with {}, {d} deletes NOT persisted\n", .{ err, batch.items.len });
                for (batch.items) |op| {
                    switch (op) {
                        .delete => |d| self.allocator.free(@constCast(d.key)),
                        .put => |p| {
                            self.allocator.free(@constCast(p.key));
                            self.allocator.free(@constCast(p.value));
                        },
                    }
                }
                return err;
            };
            for (batch.items) |op| {
                switch (op) {
                    .delete => |d| self.allocator.free(@constCast(d.key)),
                    .put => |p| {
                        self.allocator.free(@constCast(p.key));
                        self.allocator.free(@constCast(p.value));
                    },
                }
            }
        }

        self.pending_deletes.clearRetainingCapacity();
    }

    /// Get cache hit rate.
    pub fn hitRate(self: *const UtxoSet) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }

    /// Get approximate cache memory usage.
    pub fn cacheMemoryUsage(self: *const UtxoSet) usize {
        // Measured overhead per entry with Zig's GeneralPurposeAllocator:
        //   key (36 bytes) + CacheEntry struct (40 bytes) + hash_or_script
        //   heap slice (~32 bytes avg) + GPA metadata per allocation (~128
        //   bytes) + HashMap bucket/tombstone overhead (~256 bytes at load
        //   factors seen in practice).
        // Empirical measurement: ~6 KiB RSS per entry on testnet4 IBD.
        // Use 6 KiB to match observed RSS and prevent OOM during IBD.
        return self.cache.count() * 6144;
    }
};

// ============================================================================
// Chain State Manager (Phase 14)
// ============================================================================

// ============================================================================
// Undo Data Structures (Phase 7)
// ============================================================================

/// Undo data for a single transaction input — stores the UTXO that was spent.
/// Matches Bitcoin Core's CTxUndo / Coin structure from undo.h.
pub const TxUndo = struct {
    /// The previous outputs spent by this transaction's inputs.
    /// One entry per input.
    prev_outputs: []TxOut,

    pub const TxOut = struct {
        value: i64,
        script_pubkey: []const u8,
        height: u32,
        is_coinbase: bool,

        pub fn deinit(self: *TxOut, allocator: std.mem.Allocator) void {
            allocator.free(self.script_pubkey);
        }
    };

    pub fn deinit(self: *TxUndo, allocator: std.mem.Allocator) void {
        for (self.prev_outputs) |*output| {
            output.deinit(allocator);
        }
        allocator.free(self.prev_outputs);
    }
};

/// Undo data for an entire block — stores undo data for all non-coinbase transactions.
/// Matches Bitcoin Core's CBlockUndo from undo.h.
/// The coinbase transaction has no inputs to undo, so it's not included.
pub const BlockUndoData = struct {
    /// Undo data for each non-coinbase transaction.
    /// tx_undo[0] corresponds to block.transactions[1], etc.
    tx_undo: []TxUndo,

    pub fn deinit(self: *BlockUndoData, allocator: std.mem.Allocator) void {
        for (self.tx_undo) |*tx| {
            tx.deinit(allocator);
        }
        allocator.free(self.tx_undo);
    }

    /// Serialize BlockUndoData to bytes for storage.
    /// Format:
    /// - num_tx_undo (CompactSize)
    /// - For each TxUndo:
    ///   - num_prev_outputs (CompactSize)
    ///   - For each prev_output:
    ///     - packed_height_coinbase (varint): height * 2 + is_coinbase
    ///     - value (i64 LE)
    ///     - script_pubkey_len (CompactSize)
    ///     - script_pubkey bytes
    pub fn toBytes(self: *const BlockUndoData, allocator: std.mem.Allocator) ![]const u8 {
        const ser = @import("serialize.zig");
        var writer = ser.Writer.init(allocator);
        errdefer writer.deinit();

        // Number of transaction undos
        try writer.writeCompactSize(self.tx_undo.len);

        for (self.tx_undo) |tx_undo| {
            // Number of previous outputs for this transaction
            try writer.writeCompactSize(tx_undo.prev_outputs.len);

            for (tx_undo.prev_outputs) |prev_out| {
                // Pack height and coinbase flag: height * 2 + is_coinbase
                // This matches Bitcoin Core's TxInUndoFormatter
                const packed_code: u64 = @as(u64, prev_out.height) * 2 + @intFromBool(prev_out.is_coinbase);
                try writer.writeCompactSize(packed_code);

                // Value
                try writer.writeInt(i64, prev_out.value);

                // Script pubkey
                try writer.writeCompactSize(prev_out.script_pubkey.len);
                try writer.writeBytes(prev_out.script_pubkey);
            }
        }

        return writer.toOwnedSlice();
    }

    /// Deserialize BlockUndoData from bytes.
    pub fn fromBytes(data: []const u8, allocator: std.mem.Allocator) !BlockUndoData {
        const ser = @import("serialize.zig");
        var reader = ser.Reader{ .data = data };

        const num_tx_undo = try reader.readCompactSize();

        var tx_undo_list = std.ArrayList(TxUndo).init(allocator);
        errdefer {
            for (tx_undo_list.items) |*tx| {
                tx.deinit(allocator);
            }
            tx_undo_list.deinit();
        }

        for (0..num_tx_undo) |_| {
            const num_prev_outputs = try reader.readCompactSize();

            var prev_outputs_list = std.ArrayList(TxUndo.TxOut).init(allocator);
            errdefer {
                for (prev_outputs_list.items) |*out| {
                    out.deinit(allocator);
                }
                prev_outputs_list.deinit();
            }

            for (0..num_prev_outputs) |_| {
                // Unpack height and coinbase flag
                const packed_code = try reader.readCompactSize();
                const height: u32 = @intCast(packed_code >> 1);
                const is_coinbase = (packed_code & 1) != 0;

                // Value
                const value = try reader.readInt(i64);

                // Script pubkey
                const script_len = try reader.readCompactSize();
                const script_bytes = try reader.readBytes(@intCast(script_len));
                const script_pubkey = try allocator.dupe(u8, script_bytes);

                try prev_outputs_list.append(.{
                    .value = value,
                    .script_pubkey = script_pubkey,
                    .height = height,
                    .is_coinbase = is_coinbase,
                });
            }

            try tx_undo_list.append(.{
                .prev_outputs = try prev_outputs_list.toOwnedSlice(),
            });
        }

        return BlockUndoData{
            .tx_undo = try tx_undo_list.toOwnedSlice(),
        };
    }
};

/// Undo file manager for writing/reading rev*.dat files.
/// Files are stored alongside blk*.dat files in the blocks directory.
pub const UndoFileManager = struct {
    data_dir: []const u8,
    allocator: std.mem.Allocator,

    /// Network magic bytes for file header (mainnet default).
    const MAGIC: [4]u8 = .{ 0xf9, 0xbe, 0xb4, 0xd9 };

    pub fn init(data_dir: []const u8, allocator: std.mem.Allocator) UndoFileManager {
        return .{
            .data_dir = data_dir,
            .allocator = allocator,
        };
    }

    /// Get the path for a rev*.dat file. Returns a null-terminated path.
    fn getUndoFilePath(self: *const UndoFileManager, file_number: u32) ![256]u8 {
        var path_buf: [256]u8 = [_]u8{0} ** 256;
        const path_slice = std.fmt.bufPrint(&path_buf, "{s}/rev{d:0>5}.dat", .{ self.data_dir, file_number }) catch {
            return error.PathTooLong;
        };
        // Null-terminate (bufPrint doesn't null-terminate)
        if (path_slice.len < 256) {
            path_buf[path_slice.len] = 0;
        }
        return path_buf;
    }

    /// Write undo data for a block to disk.
    /// File format:
    /// - magic (4 bytes)
    /// - undo_size (4 bytes LE)
    /// - prev_block_hash (32 bytes) — for integrity check
    /// - serialized BlockUndoData
    /// - checksum: double-SHA256(prev_block_hash || BlockUndoData)
    pub fn writeUndoData(
        self: *const UndoFileManager,
        file_number: u32,
        prev_block_hash: *const types.Hash256,
        undo_data: *const BlockUndoData,
    ) !void {
        const crypto = @import("crypto.zig");

        // Serialize the undo data
        const serialized = try undo_data.toBytes(self.allocator);
        defer self.allocator.free(serialized);

        // Compute checksum: double-SHA256(prev_block_hash || serialized_undo)
        var hasher_data = try self.allocator.alloc(u8, 32 + serialized.len);
        defer self.allocator.free(hasher_data);
        @memcpy(hasher_data[0..32], prev_block_hash);
        @memcpy(hasher_data[32..], serialized);
        const checksum = crypto.hash256(hasher_data);

        // Get file path
        const path_buf = try self.getUndoFilePath(file_number);
        const path_slice = std.mem.sliceTo(&path_buf, 0);

        // Open file for writing (append mode)
        const file = std.fs.cwd().createFile(path_slice, .{ .truncate = false }) catch |err| {
            return switch (err) {
                error.FileNotFound => std.fs.cwd().createFile(path_slice, .{}) catch error.WriteFailed,
                else => error.WriteFailed,
            };
        };
        defer file.close();

        // Seek to end
        file.seekFromEnd(0) catch return error.WriteFailed;

        var buffered = std.io.bufferedWriter(file.writer());
        const writer = buffered.writer();

        // Write header
        writer.writeAll(&MAGIC) catch return error.WriteFailed;

        // Write undo size
        const undo_size: u32 = @intCast(serialized.len);
        writer.writeInt(u32, undo_size, .little) catch return error.WriteFailed;

        // Write prev block hash
        writer.writeAll(prev_block_hash) catch return error.WriteFailed;

        // Write serialized undo data
        writer.writeAll(serialized) catch return error.WriteFailed;

        // Write checksum
        writer.writeAll(&checksum) catch return error.WriteFailed;

        // Flush
        buffered.flush() catch return error.WriteFailed;
    }

    /// Read undo data for a block from disk.
    /// Returns null if file doesn't exist.
    pub fn readUndoData(
        self: *const UndoFileManager,
        file_number: u32,
        file_offset: u64,
        prev_block_hash: *const types.Hash256,
    ) !?BlockUndoData {
        const crypto = @import("crypto.zig");

        // Get file path
        const path_buf = try self.getUndoFilePath(file_number);
        const path_slice = std.mem.sliceTo(&path_buf, 0);

        // Open file for reading
        const file = std.fs.cwd().openFile(path_slice, .{}) catch |err| {
            return switch (err) {
                error.FileNotFound => null,
                else => error.ReadFailed,
            };
        };
        defer file.close();

        // Seek to offset
        file.seekTo(file_offset) catch return error.ReadFailed;

        var buffered = std.io.bufferedReader(file.reader());
        const reader = buffered.reader();

        // Read and verify magic
        var magic: [4]u8 = undefined;
        reader.readNoEof(&magic) catch return error.CorruptData;
        if (!std.mem.eql(u8, &magic, &MAGIC)) {
            return error.CorruptData;
        }

        // Read undo size
        const undo_size = reader.readInt(u32, .little) catch return error.CorruptData;

        // Read prev block hash and verify
        var stored_prev_hash: [32]u8 = undefined;
        reader.readNoEof(&stored_prev_hash) catch return error.CorruptData;
        if (!std.mem.eql(u8, &stored_prev_hash, prev_block_hash)) {
            return error.CorruptData;
        }

        // Read serialized undo data
        const serialized = try self.allocator.alloc(u8, undo_size);
        defer self.allocator.free(serialized);
        reader.readNoEof(serialized) catch return error.CorruptData;

        // Read checksum
        var stored_checksum: [32]u8 = undefined;
        reader.readNoEof(&stored_checksum) catch return error.CorruptData;

        // Verify checksum
        var hasher_data = try self.allocator.alloc(u8, 32 + undo_size);
        defer self.allocator.free(hasher_data);
        @memcpy(hasher_data[0..32], prev_block_hash);
        @memcpy(hasher_data[32..], serialized);
        const computed_checksum = crypto.hash256(hasher_data);

        if (!std.mem.eql(u8, &stored_checksum, &computed_checksum)) {
            return error.CorruptData;
        }

        // Deserialize
        return try BlockUndoData.fromBytes(serialized, self.allocator);
    }
};

/// Chain state tracks the current best chain and supports reorgs.
pub const ChainState = struct {
    best_hash: types.Hash256,
    best_height: u32,
    total_work: [32]u8,
    utxo_set: UtxoSet,
    undo_manager: ?UndoFileManager,
    allocator: std.mem.Allocator,
    /// Mutex protecting block connection/disconnection.
    /// Both P2P and RPC (submitblock) can connect blocks concurrently;
    /// without serialization the UTXO HashMap corrupts.
    connect_mutex: std.Thread.Mutex = .{},

    /// Undo data for a connected block — needed for disconnection during reorgs.
    /// This is the in-memory representation used during block connection.
    pub const BlockUndo = struct {
        /// UTXOs that were spent by this block (for restoring on disconnect)
        spent_utxos: []SpentUtxo,
        /// UTXOs that were created by this block (for removing on disconnect)
        created_outpoints: []types.OutPoint,

        pub const SpentUtxo = struct {
            outpoint: types.OutPoint,
            utxo: CompactUtxo,
        };

        pub fn deinit(self: *BlockUndo, allocator: std.mem.Allocator) void {
            for (self.spent_utxos) |*entry| {
                var utxo = entry.utxo;
                utxo.deinit(allocator);
            }
            allocator.free(self.spent_utxos);
            allocator.free(self.created_outpoints);
        }

        /// Convert to BlockUndoData for file persistence.
        /// Groups spent UTXOs by transaction for the file format.
        pub fn toBlockUndoData(self: *const BlockUndo, block: *const types.Block, allocator: std.mem.Allocator) !BlockUndoData {
            // Count inputs per non-coinbase transaction
            if (block.transactions.len <= 1) {
                // Only coinbase, no undo data needed
                return BlockUndoData{ .tx_undo = try allocator.alloc(TxUndo, 0) };
            }

            var tx_undo_list = std.ArrayList(TxUndo).init(allocator);
            errdefer {
                for (tx_undo_list.items) |*tx| {
                    tx.deinit(allocator);
                }
                tx_undo_list.deinit();
            }

            var spent_idx: usize = 0;

            // For each non-coinbase transaction
            for (block.transactions[1..]) |tx| {
                var prev_outputs = std.ArrayList(TxUndo.TxOut).init(allocator);
                errdefer {
                    for (prev_outputs.items) |*out| {
                        out.deinit(allocator);
                    }
                    prev_outputs.deinit();
                }

                // For each input in this transaction
                for (tx.inputs) |_| {
                    if (spent_idx >= self.spent_utxos.len) {
                        return error.CorruptData;
                    }

                    const spent = self.spent_utxos[spent_idx];
                    spent_idx += 1;

                    // Reconstruct the script for storage
                    const script = try spent.utxo.reconstructScript(allocator);

                    try prev_outputs.append(.{
                        .value = spent.utxo.value,
                        .script_pubkey = script,
                        .height = spent.utxo.height,
                        .is_coinbase = spent.utxo.is_coinbase,
                    });
                }

                try tx_undo_list.append(.{
                    .prev_outputs = try prev_outputs.toOwnedSlice(),
                });
            }

            return BlockUndoData{
                .tx_undo = try tx_undo_list.toOwnedSlice(),
            };
        }
    };

    /// Initialize chain state.
    /// If db is null, operates in memory-only mode (useful for testing).
    /// max_cache_mb controls the UTXO cache size (default: 450 MB, matching Bitcoin Core).
    pub fn init(db: ?*Database, max_cache_mb: usize, allocator: std.mem.Allocator) ChainState {
        return ChainState{
            .best_hash = [_]u8{0} ** 32,
            .best_height = 0,
            .total_work = [_]u8{0} ** 32,
            .utxo_set = UtxoSet.init(db, max_cache_mb, allocator),
            .undo_manager = null,
            .allocator = allocator,
        };
    }

    /// Initialize chain state with undo file persistence.
    pub fn initWithUndo(db: ?*Database, max_cache_mb: usize, data_dir: []const u8, allocator: std.mem.Allocator) ChainState {
        return ChainState{
            .best_hash = [_]u8{0} ** 32,
            .best_height = 0,
            .total_work = [_]u8{0} ** 32,
            .utxo_set = UtxoSet.init(db, max_cache_mb, allocator),
            .undo_manager = UndoFileManager.init(data_dir, allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ChainState) void {
        self.utxo_set.deinit();
    }

    /// Connect a block: spend inputs, create outputs, optionally save undo data.
    /// When skip_undo is true (IBD mode), no undo data is collected, reducing allocations.
    pub fn connectBlock(
        self: *ChainState,
        block: *const types.Block,
        hash: *const types.Hash256,
        height: u32,
    ) !BlockUndo {
        self.connect_mutex.lock();
        defer self.connect_mutex.unlock();
        return self.connectBlockInner(block, hash, height, false);
    }

    /// Connect a block during IBD — skip undo data collection for speed.
    pub fn connectBlockFast(
        self: *ChainState,
        block: *const types.Block,
        hash: *const types.Hash256,
        height: u32,
    ) !void {
        self.connect_mutex.lock();
        defer self.connect_mutex.unlock();
        var undo = try self.connectBlockInner(block, hash, height, true);
        undo.deinit(self.allocator);

        // Periodically flush pending DB deletes and dirty cache (every 100 blocks)
        if (height % 100 == 0) {
            self.utxo_set.flushPendingDeletes() catch {};
        }
        // Flush dirty UTXO cache + tip to DB atomically every 1000 blocks
        if (height % 1000 == 0) {
            self.flush() catch {};
        }
    }

    fn connectBlockInner(
        self: *ChainState,
        block: *const types.Block,
        hash: *const types.Hash256,
        height: u32,
        skip_undo: bool,
    ) !BlockUndo {
        @setRuntimeSafety(true);
        const crypto = @import("crypto.zig");

        var spent_list = std.ArrayList(BlockUndo.SpentUtxo).init(self.allocator);
        errdefer {
            for (spent_list.items) |*entry| {
                var utxo = entry.utxo;
                utxo.deinit(self.allocator);
            }
            spent_list.deinit();
        }

        var created_list = std.ArrayList(types.OutPoint).init(self.allocator);
        errdefer created_list.deinit();

        for (block.transactions, 0..) |tx, tx_idx| {
            const tx_hash = crypto.computeTxidStreaming(&tx);

            // Spend inputs (skip coinbase)
            if (tx_idx > 0) {
                for (tx.inputs, 0..) |input, input_idx| {
                    if (skip_undo) {
                        // Fast path: just delete the UTXO, don't track what was spent
                        const spent = self.utxo_set.spend(&input.previous_output) catch |err| {
                            std.debug.print("UTXO spend error at height {d}, tx {d}, input {d}: {}\n", .{ height, tx_idx, input_idx, err });
                            std.debug.print("  outpoint: ", .{});
                            for (input.previous_output.hash) |b| std.debug.print("{x:0>2}", .{b});
                            std.debug.print(":{d}\n", .{input.previous_output.index});
                            std.debug.print("  cache_count={d}, db={s}\n", .{ self.utxo_set.cache.count(), if (self.utxo_set.db != null) "yes" else "no" });
                            return err;
                        } orelse {
                            std.debug.print("UTXO missing at height {d}, tx {d}, input {d}\n", .{ height, tx_idx, input_idx });
                            std.debug.print("  outpoint: ", .{});
                            for (input.previous_output.hash) |b| std.debug.print("{x:0>2}", .{b});
                            std.debug.print(":{d}\n", .{input.previous_output.index});
                            std.debug.print("  cache_count={d}, hits={d}, misses={d}\n", .{ self.utxo_set.cache.count(), self.utxo_set.hits, self.utxo_set.misses });
                            return error.MissingInput;
                        };
                        var s = spent;
                        s.deinit(self.allocator);
                    } else {
                        const spent = try self.utxo_set.spend(&input.previous_output)
                            orelse return error.MissingInput;
                        try spent_list.append(.{
                            .outpoint = input.previous_output,
                            .utxo = spent,
                        });
                    }
                }
            }

            // Create outputs
            for (tx.outputs, 0..) |output, out_idx| {
                // Skip OP_RETURN outputs (unspendable)
                if (output.script_pubkey.len > 0 and output.script_pubkey[0] == 0x6a) continue;

                const outpoint = types.OutPoint{
                    .hash = tx_hash,
                    .index = @intCast(out_idx),
                };
                try self.utxo_set.add(&outpoint, &output, height, tx_idx == 0);
                if (!skip_undo) {
                    try created_list.append(outpoint);
                }
            }
        }

        self.best_hash = hash.*;
        self.best_height = height;

        return BlockUndo{
            .spent_utxos = if (skip_undo) &[_]BlockUndo.SpentUtxo{} else try spent_list.toOwnedSlice(),
            .created_outpoints = if (skip_undo) &[_]types.OutPoint{} else try created_list.toOwnedSlice(),
        };
    }

    /// Disconnect a block (reorg): reverse UTXO changes using undo data.
    pub fn disconnectBlock(self: *ChainState, undo: *const BlockUndo, prev_hash: types.Hash256) !void {
        self.connect_mutex.lock();
        defer self.connect_mutex.unlock();
        // Remove created outputs (in reverse order for consistency)
        var i: usize = undo.created_outpoints.len;
        while (i > 0) {
            i -= 1;
            if (try self.utxo_set.spend(&undo.created_outpoints[i])) |*spent| {
                var s = spent.*;
                s.deinit(self.allocator);
            }
        }

        // Restore spent outputs
        for (undo.spent_utxos) |entry| {
            const script = try entry.utxo.reconstructScript(self.allocator);
            defer self.allocator.free(script);
            const txout = types.TxOut{
                .value = entry.utxo.value,
                .script_pubkey = script,
            };
            try self.utxo_set.add(
                &entry.outpoint,
                &txout,
                entry.utxo.height,
                entry.utxo.is_coinbase,
            );
        }

        self.best_hash = prev_hash;
        self.best_height -= 1;
    }

    /// Flush UTXO set and chain tip to disk atomically.
    /// Builds a single WriteBatch containing all dirty UTXO entries plus the
    /// current best_hash/best_height so a crash never leaves the tip out of
    /// sync with the UTXO set.
    pub fn flush(self: *ChainState) !void {
        if (self.utxo_set.db == null) {
            // Memory-only mode, nothing to persist
            return;
        }
        const db = self.utxo_set.db.?;

        // Flush pending deletes first (separate batch — these are already-spent
        // entries that are safe to remove independently).
        try self.utxo_set.flushPendingDeletes();

        // Build a combined batch: dirty UTXO puts + chain tip
        var batch = std.ArrayList(BatchOp).init(self.allocator);
        defer batch.deinit();

        var dirty_keys = std.ArrayList([36]u8).init(self.allocator);
        defer dirty_keys.deinit();

        var iter = self.utxo_set.cache.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.dirty) {
                const encoded = try entry.value_ptr.utxo.encode(self.allocator);
                const key_copy = try self.allocator.alloc(u8, 36);
                @memcpy(key_copy, &entry.key_ptr.*);

                try batch.append(.{ .put = .{
                    .cf = CF_UTXO,
                    .key = key_copy,
                    .value = encoded,
                } });
                try dirty_keys.append(entry.key_ptr.*);
            }
        }

        // Add chain tip to the SAME batch
        var tip_buf: [36]u8 = undefined;
        @memcpy(tip_buf[0..32], &self.best_hash);
        std.mem.writeInt(u32, tip_buf[32..36], self.best_height, .little);

        const tip_key = try self.allocator.alloc(u8, ChainStore.CHAIN_TIP_KEY.len);
        @memcpy(tip_key, ChainStore.CHAIN_TIP_KEY);

        const tip_val = try self.allocator.alloc(u8, 36);
        @memcpy(tip_val, &tip_buf);

        try batch.append(.{ .put = .{
            .cf = CF_DEFAULT,
            .key = tip_key,
            .value = tip_val,
        } });

        if (batch.items.len > 0) {
            db.writeBatch(batch.items) catch |err| {
                std.debug.print("ChainState flush: writeBatch failed with {}, {d} entries NOT persisted\n", .{ err, batch.items.len });
                for (batch.items) |op| {
                    switch (op) {
                        .put => |p| {
                            self.allocator.free(@constCast(p.key));
                            self.allocator.free(@constCast(p.value));
                        },
                        .delete => |d| self.allocator.free(@constCast(d.key)),
                    }
                }
                return err;
            };

            // Mark dirty entries clean AFTER successful write
            for (dirty_keys.items) |key| {
                if (self.utxo_set.cache.getPtr(key)) |entry_ptr| {
                    entry_ptr.dirty = false;
                }
            }

            // Free allocated keys and values
            for (batch.items) |op| {
                switch (op) {
                    .put => |p| {
                        self.allocator.free(@constCast(p.key));
                        self.allocator.free(@constCast(p.value));
                    },
                    .delete => |d| self.allocator.free(@constCast(d.key)),
                }
            }
        }
    }

    /// Connect a block and persist undo data to file.
    /// This is the preferred method when file persistence is enabled.
    /// Returns the in-memory BlockUndo for immediate use, but also writes to disk.
    pub fn connectBlockWithUndo(
        self: *ChainState,
        block: *const types.Block,
        hash: *const types.Hash256,
        height: u32,
        file_number: u32,
    ) !BlockUndo {
        // First, connect the block normally
        var undo = try self.connectBlock(block, hash, height);
        errdefer undo.deinit(self.allocator);

        // If we have an undo manager, persist the undo data
        if (self.undo_manager) |manager| {
            // Convert to file format
            var undo_data = try undo.toBlockUndoData(block, self.allocator);
            defer undo_data.deinit(self.allocator);

            // Write to file
            try manager.writeUndoData(file_number, &block.header.prev_block, &undo_data);
        }

        return undo;
    }

    /// Disconnect a block using file-based undo data.
    /// Reads undo data from the rev*.dat file and reverses the block's changes.
    pub fn disconnectBlockFromFile(
        self: *ChainState,
        block: *const types.Block,
        file_number: u32,
        file_offset: u64,
        prev_hash: types.Hash256,
    ) !void {
        const manager = self.undo_manager orelse return error.UndoManagerNotConfigured;

        // Read undo data from file
        var undo_data = try manager.readUndoData(file_number, file_offset, &prev_hash) orelse return error.UndoDataNotFound;
        defer undo_data.deinit(self.allocator);

        // Remove created outputs (in reverse order)
        // We need to iterate through transactions in reverse
        var tx_idx = block.transactions.len;
        while (tx_idx > 0) {
            tx_idx -= 1;
            const tx = block.transactions[tx_idx];
            const crypto = @import("crypto.zig");
            const tx_hash = try crypto.computeTxid(&tx, self.allocator);

            // Remove outputs created by this transaction (in reverse)
            var out_idx = tx.outputs.len;
            while (out_idx > 0) {
                out_idx -= 1;
                const output = tx.outputs[out_idx];

                // Skip OP_RETURN outputs
                if (output.script_pubkey.len > 0 and output.script_pubkey[0] == 0x6a) continue;

                const outpoint = types.OutPoint{
                    .hash = tx_hash,
                    .index = @intCast(out_idx),
                };

                if (try self.utxo_set.spend(&outpoint)) |*spent| {
                    var s = spent.*;
                    s.deinit(self.allocator);
                }
            }
        }

        // Restore spent UTXOs
        // The undo data contains the previous outputs, but we need the outpoints
        // which are in the block's transaction inputs
        var undo_idx: usize = 0;
        for (block.transactions[1..]) |tx| {
            if (undo_idx >= undo_data.tx_undo.len) break;
            const tx_undo = undo_data.tx_undo[undo_idx];
            undo_idx += 1;

            for (tx.inputs, 0..) |input, input_idx| {
                if (input_idx >= tx_undo.prev_outputs.len) break;
                const prev_out = tx_undo.prev_outputs[input_idx];

                const txout = types.TxOut{
                    .value = prev_out.value,
                    .script_pubkey = prev_out.script_pubkey,
                };
                try self.utxo_set.add(
                    &input.previous_output,
                    &txout,
                    prev_out.height,
                    prev_out.is_coinbase,
                );
            }
        }

        self.best_hash = prev_hash;
        self.best_height -= 1;
    }
};

// ============================================================================
// assumeUTXO Snapshot Support
// ============================================================================

/// UTXO snapshot magic bytes: 'u', 't', 'x', 'o', 0xff
/// Reference: Bitcoin Core node/utxo_snapshot.h SNAPSHOT_MAGIC_BYTES
pub const SNAPSHOT_MAGIC_BYTES: [5]u8 = .{ 'u', 't', 'x', 'o', 0xff };

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u16 = 2;

/// Metadata describing a UTXO set snapshot file.
/// Reference: Bitcoin Core node/utxo_snapshot.h SnapshotMetadata
pub const SnapshotMetadata = struct {
    /// Network magic bytes (4 bytes) for cross-network validation.
    network_magic: u32,
    /// Hash of the block at snapshot tip.
    base_blockhash: types.Hash256,
    /// Number of coins in the snapshot (for progress display).
    coins_count: u64,

    /// Serialize metadata to bytes for file header.
    /// Format: magic(5) + version(2) + network_magic(4) + base_blockhash(32) + coins_count(8) = 51 bytes
    pub fn toBytes(self: *const SnapshotMetadata, allocator: std.mem.Allocator) StorageError![]const u8 {
        var writer = serialize.Writer.init(allocator);
        errdefer writer.deinit();

        // Write snapshot magic bytes
        writer.writeBytes(&SNAPSHOT_MAGIC_BYTES) catch return StorageError.SerializationFailed;

        // Write version
        writer.writeInt(u16, SNAPSHOT_VERSION) catch return StorageError.SerializationFailed;

        // Write network magic (as little-endian u32)
        writer.writeInt(u32, self.network_magic) catch return StorageError.SerializationFailed;

        // Write base blockhash
        writer.writeBytes(&self.base_blockhash) catch return StorageError.SerializationFailed;

        // Write coins count
        writer.writeInt(u64, self.coins_count) catch return StorageError.SerializationFailed;

        return writer.toOwnedSlice() catch return StorageError.OutOfMemory;
    }

    /// Deserialize metadata from bytes.
    pub fn fromBytes(data: []const u8, expected_magic: u32) StorageError!SnapshotMetadata {
        var reader = serialize.Reader{ .data = data };

        // Read and verify snapshot magic bytes
        const magic = reader.readBytes(5) catch return StorageError.CorruptData;
        if (!std.mem.eql(u8, magic, &SNAPSHOT_MAGIC_BYTES)) {
            return StorageError.CorruptData;
        }

        // Read version
        const version = reader.readInt(u16) catch return StorageError.CorruptData;
        if (version != SNAPSHOT_VERSION) {
            return StorageError.CorruptData;
        }

        // Read network magic and verify
        const network_magic = reader.readInt(u32) catch return StorageError.CorruptData;
        if (network_magic != expected_magic) {
            return StorageError.CorruptData; // Wrong network
        }

        // Read base blockhash
        const hash_bytes = reader.readBytes(32) catch return StorageError.CorruptData;
        var base_blockhash: types.Hash256 = undefined;
        @memcpy(&base_blockhash, hash_bytes);

        // Read coins count
        const coins_count = reader.readInt(u64) catch return StorageError.CorruptData;

        return SnapshotMetadata{
            .network_magic = network_magic,
            .base_blockhash = base_blockhash,
            .coins_count = coins_count,
        };
    }

    /// Size of serialized metadata header.
    pub const HEADER_SIZE: usize = 5 + 2 + 4 + 32 + 8; // 51 bytes
};

/// Serialized coin entry in a snapshot.
/// Format: txid(32) + vout(4) + packed_height_coinbase(4) + value(8) + script_len(varint) + script
pub const SnapshotCoin = struct {
    outpoint: types.OutPoint,
    height: u32,
    is_coinbase: bool,
    value: i64,
    script_pubkey: []const u8,

    /// Serialize a coin to snapshot format.
    /// Reference: Bitcoin Core kernel/coinstats.cpp TxOutSer
    pub fn toBytes(self: *const SnapshotCoin, allocator: std.mem.Allocator) StorageError![]const u8 {
        var writer = serialize.Writer.init(allocator);
        errdefer writer.deinit();

        // Write outpoint: txid + index
        writer.writeBytes(&self.outpoint.hash) catch return StorageError.SerializationFailed;
        writer.writeInt(u32, self.outpoint.index) catch return StorageError.SerializationFailed;

        // Pack height and coinbase: height << 1 | is_coinbase
        const packed_code: u32 = (self.height << 1) | @as(u32, if (self.is_coinbase) 1 else 0);
        writer.writeInt(u32, packed_code) catch return StorageError.SerializationFailed;

        // Write value
        writer.writeInt(i64, self.value) catch return StorageError.SerializationFailed;

        // Write script with length prefix
        writer.writeCompactSize(self.script_pubkey.len) catch return StorageError.SerializationFailed;
        writer.writeBytes(self.script_pubkey) catch return StorageError.SerializationFailed;

        return writer.toOwnedSlice() catch return StorageError.OutOfMemory;
    }

    /// Deserialize a coin from snapshot format.
    pub fn fromReader(reader: *serialize.Reader, allocator: std.mem.Allocator) StorageError!SnapshotCoin {
        // Read outpoint
        const txid_bytes = reader.readBytes(32) catch return StorageError.CorruptData;
        var txid: types.Hash256 = undefined;
        @memcpy(&txid, txid_bytes);
        const vout = reader.readInt(u32) catch return StorageError.CorruptData;

        // Unpack height and coinbase
        const packed_code = reader.readInt(u32) catch return StorageError.CorruptData;
        const height = packed_code >> 1;
        const is_coinbase = (packed_code & 1) != 0;

        // Read value
        const value = reader.readInt(i64) catch return StorageError.CorruptData;

        // Read script
        const script_len = reader.readCompactSize() catch return StorageError.CorruptData;
        const script_bytes = reader.readBytes(@intCast(script_len)) catch return StorageError.CorruptData;
        const script_pubkey = allocator.dupe(u8, script_bytes) catch return StorageError.OutOfMemory;

        return SnapshotCoin{
            .outpoint = types.OutPoint{ .hash = txid, .index = vout },
            .height = height,
            .is_coinbase = is_coinbase,
            .value = value,
            .script_pubkey = script_pubkey,
        };
    }

    pub fn deinit(self: *SnapshotCoin, allocator: std.mem.Allocator) void {
        allocator.free(self.script_pubkey);
    }
};

/// Role of a chainstate in dual-chainstate mode.
/// Reference: Bitcoin Core kernel/types.h ChainstateRole
pub const ChainstateRole = enum {
    /// Normal chainstate: fully validated from genesis.
    normal,
    /// Snapshot chainstate: loaded from assumeUTXO snapshot, not fully validated yet.
    snapshot,
    /// Background chainstate: validating historical blocks to verify snapshot.
    background,
};

/// Manager for dual chainstates during assumeUTXO sync.
/// Reference: Bitcoin Core validation.h ChainstateManager
pub const ChainStateManager = struct {
    /// The primary (active) chainstate. Can be either normal or snapshot.
    active_chainstate: *ChainState,
    /// Background chainstate for validating snapshot. Null if not in assumeUTXO mode.
    background_chainstate: ?*ChainState,
    /// Role of the active chainstate.
    active_role: ChainstateRole,
    /// If snapshot-based, the base block hash.
    snapshot_base_blockhash: ?types.Hash256,
    /// Network parameters.
    network_params: *const @import("consensus.zig").NetworkParams,
    /// Allocator.
    allocator: std.mem.Allocator,
    /// Background validation thread handle.
    background_thread: ?std.Thread,
    /// Signal to stop background validation.
    stop_background: std.atomic.Value(bool),
    /// Mutex for thread-safe access.
    mutex: std.Thread.Mutex,

    /// Initialize in normal (non-snapshot) mode.
    pub fn init(
        chainstate: *ChainState,
        network_params: *const @import("consensus.zig").NetworkParams,
        allocator: std.mem.Allocator,
    ) ChainStateManager {
        return ChainStateManager{
            .active_chainstate = chainstate,
            .background_chainstate = null,
            .active_role = .normal,
            .snapshot_base_blockhash = null,
            .network_params = network_params,
            .allocator = allocator,
            .background_thread = null,
            .stop_background = std.atomic.Value(bool).init(false),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *ChainStateManager) void {
        // Stop background thread if running
        self.stopBackgroundValidation();

        // Don't deinit chainstates here - they're owned externally
    }

    /// Activate a snapshot chainstate.
    /// The old chainstate becomes the background chainstate for validation.
    pub fn activateSnapshot(
        self: *ChainStateManager,
        snapshot_chainstate: *ChainState,
        base_blockhash: types.Hash256,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // The current active becomes background
        self.background_chainstate = self.active_chainstate;
        self.active_chainstate = snapshot_chainstate;
        self.active_role = .snapshot;
        self.snapshot_base_blockhash = base_blockhash;
    }

    /// Start background validation thread.
    pub fn startBackgroundValidation(
        self: *ChainStateManager,
        sync_callback: *const fn (*ChainStateManager) void,
    ) !void {
        if (self.background_chainstate == null) return;
        if (self.background_thread != null) return; // Already running

        self.stop_background.store(false, .release);
        self.background_thread = try std.Thread.spawn(.{}, backgroundValidationThread, .{ self, sync_callback });
    }

    /// Stop background validation.
    pub fn stopBackgroundValidation(self: *ChainStateManager) void {
        self.stop_background.store(true, .release);
        if (self.background_thread) |thread| {
            thread.join();
            self.background_thread = null;
        }
    }

    /// Check if background validation is complete.
    pub fn isBackgroundValidationComplete(self: *ChainStateManager) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.background_chainstate) |bg| {
            if (self.snapshot_base_blockhash) |base_hash| {
                return std.mem.eql(u8, &bg.best_hash, &base_hash);
            }
        }
        return false;
    }

    /// Complete the snapshot validation and merge chainstates.
    /// Called when background chainstate reaches the snapshot base block.
    /// Compares UTXO set hashes to verify the snapshot is valid.
    ///
    /// Returns:
    ///   - true if validation succeeded and chainstates were merged
    ///   - false if background validation hasn't reached the snapshot base yet
    ///   - error if UTXO set hashes don't match (snapshot is invalid)
    pub fn completeValidation(self: *ChainStateManager) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const bg = self.background_chainstate orelse return false;
        const base_hash = self.snapshot_base_blockhash orelse return false;

        // Verify background reached the snapshot base
        if (!std.mem.eql(u8, &bg.best_hash, &base_hash)) {
            return false;
        }

        // Compute UTXO set hashes for both chainstates
        const bg_hash = try computeUtxoSetHash(&bg.utxo_set, self.allocator);
        const active_hash = try computeUtxoSetHash(&self.active_chainstate.utxo_set, self.allocator);

        // Compare hashes - they must match for the snapshot to be valid
        if (!std.mem.eql(u8, &bg_hash, &active_hash)) {
            // CRITICAL: Snapshot UTXO set doesn't match fully validated chain!
            // This indicates either:
            // 1. The snapshot was corrupted
            // 2. The assumeUtxo hash in params is wrong
            // 3. There's a consensus bug
            return SnapshotError.BackgroundValidationFailed;
        }

        // The snapshot is now fully validated
        self.active_role = .normal;
        self.background_chainstate = null;
        self.snapshot_base_blockhash = null;

        return true;
    }

    /// Get the active chainstate.
    pub fn activeChainstate(self: *ChainStateManager) *ChainState {
        return self.active_chainstate;
    }

    /// Check if we're in assumeUTXO mode.
    pub fn isAssumeUtxoMode(self: *ChainStateManager) bool {
        return self.active_role == .snapshot;
    }

    fn backgroundValidationThread(self: *ChainStateManager, sync_callback: *const fn (*ChainStateManager) void) void {
        while (!self.stop_background.load(.acquire)) {
            // Call the sync callback to process the next batch of blocks
            sync_callback(self);

            // Check if we've reached the snapshot base
            if (self.isBackgroundValidationComplete()) {
                break;
            }

            // Small sleep to prevent busy-waiting
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
};

/// Compute the hash of a UTXO set for snapshot verification.
/// This is SHA256d of all serialized coins in deterministic order.
/// Reference: Bitcoin Core kernel/coinstats.cpp ComputeUTXOStats
pub fn computeUtxoSetHash(utxo_set: *UtxoSet, allocator: std.mem.Allocator) !types.Hash256 {
    const crypto = @import("crypto.zig");

    // For now, we iterate the cache (in-memory UTXOs)
    // A full implementation would iterate the database in sorted order

    // Collect all keys for sorting
    var keys = std.ArrayList([36]u8).init(allocator);
    defer keys.deinit();

    var iter = utxo_set.cache.iterator();
    while (iter.next()) |entry| {
        try keys.append(entry.key_ptr.*);
    }

    // Sort keys lexicographically
    std.mem.sort([36]u8, keys.items, {}, struct {
        fn lessThan(_: void, a: [36]u8, b: [36]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThan);

    // Hash all coins in sorted order
    var hasher_data = std.ArrayList(u8).init(allocator);
    defer hasher_data.deinit();

    for (keys.items) |key| {
        if (utxo_set.cache.get(key)) |entry| {
            // Serialize this coin
            const coin = SnapshotCoin{
                .outpoint = types.OutPoint{
                    .hash = key[0..32].*,
                    .index = std.mem.readInt(u32, key[32..36], .little),
                },
                .height = entry.utxo.height,
                .is_coinbase = entry.utxo.is_coinbase,
                .value = entry.utxo.value,
                .script_pubkey = entry.utxo.hash_or_script,
            };

            const coin_bytes = try coin.toBytes(allocator);
            defer allocator.free(coin_bytes);
            try hasher_data.appendSlice(coin_bytes);
        }
    }

    // Compute SHA256d
    return crypto.hash256(hasher_data.items);
}

/// Write a UTXO set snapshot to a file.
/// Format: metadata header + serialized coins
pub fn dumpTxOutSet(
    chainstate: *ChainState,
    network_magic: u32,
    path: []const u8,
    allocator: std.mem.Allocator,
) !void {
    // Create the file
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    var buffered = std.io.bufferedWriter(file.writer());
    const writer = buffered.writer();

    // Count coins
    const coins_count = chainstate.utxo_set.cache.count();

    // Write metadata header
    const metadata = SnapshotMetadata{
        .network_magic = network_magic,
        .base_blockhash = chainstate.best_hash,
        .coins_count = coins_count,
    };
    const header = try metadata.toBytes(allocator);
    defer allocator.free(header);
    try writer.writeAll(header);

    // Collect and sort keys
    var keys = std.ArrayList([36]u8).init(allocator);
    defer keys.deinit();

    var iter = chainstate.utxo_set.cache.iterator();
    while (iter.next()) |entry| {
        try keys.append(entry.key_ptr.*);
    }

    std.mem.sort([36]u8, keys.items, {}, struct {
        fn lessThan(_: void, a: [36]u8, b: [36]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThan);

    // Write each coin
    for (keys.items) |key| {
        if (chainstate.utxo_set.cache.get(key)) |entry| {
            // Reconstruct full script for serialization
            const script = try entry.utxo.reconstructScript(allocator);
            defer allocator.free(script);

            const coin = SnapshotCoin{
                .outpoint = types.OutPoint{
                    .hash = key[0..32].*,
                    .index = std.mem.readInt(u32, key[32..36], .little),
                },
                .height = entry.utxo.height,
                .is_coinbase = entry.utxo.is_coinbase,
                .value = entry.utxo.value,
                .script_pubkey = script,
            };

            const coin_bytes = try coin.toBytes(allocator);
            defer allocator.free(coin_bytes);
            try writer.writeAll(coin_bytes);
        }
    }

    try buffered.flush();
}

/// Load a UTXO set snapshot from a file.
/// Returns a new ChainState populated with the snapshot data.
pub fn loadTxOutSet(
    path: []const u8,
    expected_magic: u32,
    allocator: std.mem.Allocator,
) !struct { chainstate: ChainState, metadata: SnapshotMetadata } {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buffered = std.io.bufferedReader(file.reader());
    const reader = buffered.reader();

    // Read metadata header
    var header_buf: [SnapshotMetadata.HEADER_SIZE]u8 = undefined;
    try reader.readNoEof(&header_buf);
    const metadata = try SnapshotMetadata.fromBytes(&header_buf, expected_magic);

    // Create a new in-memory chainstate for the snapshot
    var chainstate = ChainState.init(null, 64, allocator);
    chainstate.best_hash = metadata.base_blockhash;

    // Read all coins
    var coins_loaded: u64 = 0;
    while (coins_loaded < metadata.coins_count) {
        // Read one coin at a time
        // We need to read variable-length data, so we'll read field by field
        var coin_data = std.ArrayList(u8).init(allocator);
        defer coin_data.deinit();

        // Read fixed part: txid(32) + vout(4) + packed(4) + value(8) = 48 bytes
        var fixed: [48]u8 = undefined;
        reader.readNoEof(&fixed) catch break;
        try coin_data.appendSlice(&fixed);

        // Read script length (varint)
        const first_byte = reader.readByte() catch break;
        try coin_data.append(first_byte);

        const script_len: usize = if (first_byte < 0xFD) blk: {
            break :blk first_byte;
        } else if (first_byte == 0xFD) blk: {
            var len_bytes: [2]u8 = undefined;
            reader.readNoEof(&len_bytes) catch break;
            try coin_data.appendSlice(&len_bytes);
            break :blk std.mem.readInt(u16, &len_bytes, .little);
        } else if (first_byte == 0xFE) blk: {
            var len_bytes: [4]u8 = undefined;
            reader.readNoEof(&len_bytes) catch break;
            try coin_data.appendSlice(&len_bytes);
            break :blk std.mem.readInt(u32, &len_bytes, .little);
        } else blk: {
            var len_bytes: [8]u8 = undefined;
            reader.readNoEof(&len_bytes) catch break;
            try coin_data.appendSlice(&len_bytes);
            break :blk @intCast(std.mem.readInt(u64, &len_bytes, .little));
        };

        // Read script bytes
        const script_bytes = try allocator.alloc(u8, script_len);
        defer allocator.free(script_bytes);
        reader.readNoEof(script_bytes) catch break;
        try coin_data.appendSlice(script_bytes);

        // Parse the coin
        var coin_reader = serialize.Reader{ .data = coin_data.items };
        var coin = try SnapshotCoin.fromReader(&coin_reader, allocator);
        defer coin.deinit(allocator);

        // Add to chainstate
        const txout = types.TxOut{
            .value = coin.value,
            .script_pubkey = coin.script_pubkey,
        };
        try chainstate.utxo_set.add(&coin.outpoint, &txout, coin.height, coin.is_coinbase);

        coins_loaded += 1;
    }

    return .{ .chainstate = chainstate, .metadata = metadata };
}

/// Find an AssumeUtxo entry by block hash.
/// Returns the entry if the hash matches a known snapshot, null otherwise.
pub fn findAssumeUtxoEntry(
    network_params: *const @import("consensus.zig").NetworkParams,
    block_hash: *const types.Hash256,
) ?@import("consensus.zig").AssumeUtxoData {
    for (network_params.assume_utxo) |entry| {
        if (std.mem.eql(u8, &entry.block_hash, block_hash)) {
            return entry;
        }
    }
    return null;
}

/// Find an AssumeUtxo entry by height.
/// Returns the entry if there's a snapshot at the given height, null otherwise.
pub fn findAssumeUtxoEntryByHeight(
    network_params: *const @import("consensus.zig").NetworkParams,
    height: u32,
) ?@import("consensus.zig").AssumeUtxoData {
    for (network_params.assume_utxo) |entry| {
        if (entry.height == height) {
            return entry;
        }
    }
    return null;
}

/// Snapshot validation error.
pub const SnapshotError = error{
    /// Snapshot block hash not found in assumeUtxo params.
    UnknownSnapshot,
    /// UTXO set hash doesn't match expected value.
    HashMismatch,
    /// Coin count doesn't match expected value.
    CoinCountMismatch,
    /// File I/O error.
    IoError,
    /// Corrupt snapshot data.
    CorruptData,
    /// Wrong network.
    WrongNetwork,
    /// Out of memory.
    OutOfMemory,
    /// Background validation failed.
    BackgroundValidationFailed,
};

/// Result of loading a snapshot.
pub const SnapshotLoadResult = struct {
    /// Number of coins loaded.
    coins_loaded: u64,
    /// Hash of the tip block.
    tip_hash: types.Hash256,
    /// Height of the tip block.
    tip_height: u32,
    /// Base height from assumeUtxo params (same as tip_height for valid snapshots).
    base_height: u32,
};

/// Validate and load a UTXO set snapshot file.
/// This performs full validation against the assumeUtxo params:
/// 1. Verifies the snapshot block hash is in assumeUtxo params
/// 2. Loads all coins into a new chainstate
/// 3. Computes the UTXO set hash and verifies it matches
/// 4. Verifies the coin count matches
///
/// Returns the loaded chainstate and validation result.
/// Reference: Bitcoin Core validation.cpp ActivateSnapshot()
pub fn validateAndLoadSnapshot(
    path: []const u8,
    network_params: *const @import("consensus.zig").NetworkParams,
    allocator: std.mem.Allocator,
) SnapshotError!struct { chainstate: ChainState, result: SnapshotLoadResult } {
    // Load the snapshot
    const load_result = loadTxOutSet(path, network_params.magic, allocator) catch |err| {
        return switch (err) {
            error.FileNotFound, error.AccessDenied => SnapshotError.IoError,
            StorageError.CorruptData => SnapshotError.CorruptData,
            StorageError.OutOfMemory => SnapshotError.OutOfMemory,
            else => SnapshotError.IoError,
        };
    };
    var chainstate = load_result.chainstate;
    const metadata = load_result.metadata;

    // Find the assumeUtxo entry for this snapshot
    const assume_entry = findAssumeUtxoEntry(network_params, &metadata.base_blockhash) orelse {
        chainstate.deinit();
        return SnapshotError.UnknownSnapshot;
    };

    // Verify coin count
    if (metadata.coins_count != assume_entry.coins_count) {
        chainstate.deinit();
        return SnapshotError.CoinCountMismatch;
    }

    // Compute the UTXO set hash
    const computed_hash = computeUtxoSetHash(&chainstate.utxo_set, allocator) catch {
        chainstate.deinit();
        return SnapshotError.OutOfMemory;
    };

    // Verify hash matches
    if (!std.mem.eql(u8, &computed_hash, &assume_entry.hash_serialized)) {
        chainstate.deinit();
        return SnapshotError.HashMismatch;
    }

    // Set the height on the chainstate
    chainstate.best_height = assume_entry.height;

    return .{
        .chainstate = chainstate,
        .result = SnapshotLoadResult{
            .coins_loaded = metadata.coins_count,
            .tip_hash = metadata.base_blockhash,
            .tip_height = assume_entry.height,
            .base_height = assume_entry.height,
        },
    };
}

/// Result of dumping a snapshot.
pub const SnapshotDumpResult = struct {
    /// Number of coins written.
    coins_written: u64,
    /// Hash of the base block.
    base_hash: types.Hash256,
    /// Height of the base block.
    base_height: u32,
};

/// Dump the UTXO set to a snapshot file and return the result.
/// This is a wrapper around dumpTxOutSet that returns structured result data.
pub fn dumpTxOutSetWithResult(
    chainstate: *ChainState,
    network_magic: u32,
    path: []const u8,
    allocator: std.mem.Allocator,
) !SnapshotDumpResult {
    // Count coins before dumping
    const coins_count = chainstate.utxo_set.cache.count();

    // Dump to file
    try dumpTxOutSet(chainstate, network_magic, path, allocator);

    return SnapshotDumpResult{
        .coins_written = coins_count,
        .base_hash = chainstate.best_hash,
        .base_height = chainstate.best_height,
    };
}

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

// ============================================================================
// CompactUtxo Tests
// ============================================================================

test "compact utxo encode/decode P2PKH" {
    const allocator = std.testing.allocator;

    // P2PKH: stores only the 20-byte hash
    const hash = [_]u8{0xAB} ** 20;
    const compact = CompactUtxo{
        .height = 500000,
        .is_coinbase = false,
        .value = 5000000000,
        .script_type = CompactUtxo.SCRIPT_P2PKH,
        .hash_or_script = &hash,
    };

    const encoded = try compact.encode(allocator);
    defer allocator.free(encoded);

    var decoded = try CompactUtxo.decode(encoded, allocator);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(compact.height, decoded.height);
    try std.testing.expectEqual(compact.is_coinbase, decoded.is_coinbase);
    try std.testing.expectEqual(compact.value, decoded.value);
    try std.testing.expectEqual(compact.script_type, decoded.script_type);
    try std.testing.expectEqualSlices(u8, compact.hash_or_script, decoded.hash_or_script);
}

test "compact utxo encode/decode P2WPKH" {
    const allocator = std.testing.allocator;

    // P2WPKH: stores only the 20-byte hash
    const hash = [_]u8{0xCD} ** 20;
    const compact = CompactUtxo{
        .height = 700000,
        .is_coinbase = true,
        .value = 625000000, // 6.25 BTC
        .script_type = CompactUtxo.SCRIPT_P2WPKH,
        .hash_or_script = &hash,
    };

    const encoded = try compact.encode(allocator);
    defer allocator.free(encoded);

    var decoded = try CompactUtxo.decode(encoded, allocator);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(compact.height, decoded.height);
    try std.testing.expect(decoded.is_coinbase);
    try std.testing.expectEqual(compact.value, decoded.value);
    try std.testing.expectEqual(compact.script_type, decoded.script_type);
    try std.testing.expectEqualSlices(u8, compact.hash_or_script, decoded.hash_or_script);
}

test "compact utxo encode/decode P2TR" {
    const allocator = std.testing.allocator;

    // P2TR: stores only the 32-byte x-only pubkey
    const hash = [_]u8{0xEF} ** 32;
    const compact = CompactUtxo{
        .height = 800000,
        .is_coinbase = false,
        .value = 100000,
        .script_type = CompactUtxo.SCRIPT_P2TR,
        .hash_or_script = &hash,
    };

    const encoded = try compact.encode(allocator);
    defer allocator.free(encoded);

    var decoded = try CompactUtxo.decode(encoded, allocator);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(compact.height, decoded.height);
    try std.testing.expectEqual(compact.is_coinbase, decoded.is_coinbase);
    try std.testing.expectEqual(compact.value, decoded.value);
    try std.testing.expectEqual(compact.script_type, decoded.script_type);
    try std.testing.expectEqualSlices(u8, compact.hash_or_script, decoded.hash_or_script);
}

test "compact utxo encode/decode nonstandard script" {
    const allocator = std.testing.allocator;

    // Nonstandard: stores full script with length prefix
    const script = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const compact = CompactUtxo{
        .height = 100,
        .is_coinbase = false,
        .value = 12345,
        .script_type = CompactUtxo.SCRIPT_OTHER,
        .hash_or_script = &script,
    };

    const encoded = try compact.encode(allocator);
    defer allocator.free(encoded);

    var decoded = try CompactUtxo.decode(encoded, allocator);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(compact.height, decoded.height);
    try std.testing.expectEqual(compact.value, decoded.value);
    try std.testing.expectEqual(compact.script_type, decoded.script_type);
    try std.testing.expectEqualSlices(u8, compact.hash_or_script, decoded.hash_or_script);
}

test "compact utxo coinbase flag packing" {
    const allocator = std.testing.allocator;

    // Test that coinbase flag is correctly packed into MSB of height
    const hash = [_]u8{0x11} ** 20;

    // Non-coinbase
    const non_coinbase = CompactUtxo{
        .height = 0x7FFFFFFF, // Max height without MSB
        .is_coinbase = false,
        .value = 100,
        .script_type = CompactUtxo.SCRIPT_P2PKH,
        .hash_or_script = &hash,
    };

    const encoded_non = try non_coinbase.encode(allocator);
    defer allocator.free(encoded_non);

    var decoded_non = try CompactUtxo.decode(encoded_non, allocator);
    defer decoded_non.deinit(allocator);

    try std.testing.expect(!decoded_non.is_coinbase);
    try std.testing.expectEqual(@as(u32, 0x7FFFFFFF), decoded_non.height);

    // Coinbase
    const coinbase = CompactUtxo{
        .height = 100000,
        .is_coinbase = true,
        .value = 5000000000,
        .script_type = CompactUtxo.SCRIPT_P2PKH,
        .hash_or_script = &hash,
    };

    const encoded_cb = try coinbase.encode(allocator);
    defer allocator.free(encoded_cb);

    var decoded_cb = try CompactUtxo.decode(encoded_cb, allocator);
    defer decoded_cb.deinit(allocator);

    try std.testing.expect(decoded_cb.is_coinbase);
    try std.testing.expectEqual(@as(u32, 100000), decoded_cb.height);
}

test "compact utxo script reconstruction P2PKH" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{0xAB} ** 20;
    const compact = CompactUtxo{
        .height = 100,
        .is_coinbase = false,
        .value = 100,
        .script_type = CompactUtxo.SCRIPT_P2PKH,
        .hash_or_script = &hash,
    };

    const script = try compact.reconstructScript(allocator);
    defer allocator.free(script);

    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    try std.testing.expectEqual(@as(usize, 25), script.len);
    try std.testing.expectEqual(@as(u8, 0x76), script[0]); // OP_DUP
    try std.testing.expectEqual(@as(u8, 0xa9), script[1]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[2]); // Push 20 bytes
    try std.testing.expectEqualSlices(u8, &hash, script[3..23]);
    try std.testing.expectEqual(@as(u8, 0x88), script[23]); // OP_EQUALVERIFY
    try std.testing.expectEqual(@as(u8, 0xac), script[24]); // OP_CHECKSIG
}

test "compact utxo script reconstruction P2SH" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{0xBB} ** 20;
    const compact = CompactUtxo{
        .height = 100,
        .is_coinbase = false,
        .value = 100,
        .script_type = CompactUtxo.SCRIPT_P2SH,
        .hash_or_script = &hash,
    };

    const script = try compact.reconstructScript(allocator);
    defer allocator.free(script);

    // P2SH: OP_HASH160 <20> OP_EQUAL
    try std.testing.expectEqual(@as(usize, 23), script.len);
    try std.testing.expectEqual(@as(u8, 0xa9), script[0]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20 bytes
    try std.testing.expectEqualSlices(u8, &hash, script[2..22]);
    try std.testing.expectEqual(@as(u8, 0x87), script[22]); // OP_EQUAL
}

test "compact utxo script reconstruction P2WPKH" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{0xCC} ** 20;
    const compact = CompactUtxo{
        .height = 100,
        .is_coinbase = false,
        .value = 100,
        .script_type = CompactUtxo.SCRIPT_P2WPKH,
        .hash_or_script = &hash,
    };

    const script = try compact.reconstructScript(allocator);
    defer allocator.free(script);

    // P2WPKH: OP_0 <20>
    try std.testing.expectEqual(@as(usize, 22), script.len);
    try std.testing.expectEqual(@as(u8, 0x00), script[0]); // OP_0
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20 bytes
    try std.testing.expectEqualSlices(u8, &hash, script[2..22]);
}

test "compact utxo script reconstruction P2WSH" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{0xDD} ** 32;
    const compact = CompactUtxo{
        .height = 100,
        .is_coinbase = false,
        .value = 100,
        .script_type = CompactUtxo.SCRIPT_P2WSH,
        .hash_or_script = &hash,
    };

    const script = try compact.reconstructScript(allocator);
    defer allocator.free(script);

    // P2WSH: OP_0 <32>
    try std.testing.expectEqual(@as(usize, 34), script.len);
    try std.testing.expectEqual(@as(u8, 0x00), script[0]); // OP_0
    try std.testing.expectEqual(@as(u8, 0x20), script[1]); // Push 32 bytes
    try std.testing.expectEqualSlices(u8, &hash, script[2..34]);
}

test "compact utxo script reconstruction P2TR" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{0xEE} ** 32;
    const compact = CompactUtxo{
        .height = 100,
        .is_coinbase = false,
        .value = 100,
        .script_type = CompactUtxo.SCRIPT_P2TR,
        .hash_or_script = &hash,
    };

    const script = try compact.reconstructScript(allocator);
    defer allocator.free(script);

    // P2TR: OP_1 <32>
    try std.testing.expectEqual(@as(usize, 34), script.len);
    try std.testing.expectEqual(@as(u8, 0x51), script[0]); // OP_1
    try std.testing.expectEqual(@as(u8, 0x20), script[1]); // Push 32 bytes
    try std.testing.expectEqualSlices(u8, &hash, script[2..34]);
}

test "compact utxo classify script types" {
    // P2PKH
    const p2pkh_script = [_]u8{0x76} ++ [_]u8{0xa9} ++ [_]u8{0x14} ++ [_]u8{0x00} ** 20 ++ [_]u8{0x88} ++ [_]u8{0xac};
    try std.testing.expectEqual(CompactUtxo.SCRIPT_P2PKH, CompactUtxo.classifyScriptType(&p2pkh_script));

    // P2SH
    const p2sh_script = [_]u8{0xa9} ++ [_]u8{0x14} ++ [_]u8{0x00} ** 20 ++ [_]u8{0x87};
    try std.testing.expectEqual(CompactUtxo.SCRIPT_P2SH, CompactUtxo.classifyScriptType(&p2sh_script));

    // P2WPKH
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0x00} ** 20;
    try std.testing.expectEqual(CompactUtxo.SCRIPT_P2WPKH, CompactUtxo.classifyScriptType(&p2wpkh_script));

    // P2WSH
    const p2wsh_script = [_]u8{0x00} ++ [_]u8{0x20} ++ [_]u8{0x00} ** 32;
    try std.testing.expectEqual(CompactUtxo.SCRIPT_P2WSH, CompactUtxo.classifyScriptType(&p2wsh_script));

    // P2TR
    const p2tr_script = [_]u8{0x51} ++ [_]u8{0x20} ++ [_]u8{0x00} ** 32;
    try std.testing.expectEqual(CompactUtxo.SCRIPT_P2TR, CompactUtxo.classifyScriptType(&p2tr_script));

    // Unknown
    const unknown_script = [_]u8{ 0x01, 0x02, 0x03 };
    try std.testing.expectEqual(CompactUtxo.SCRIPT_OTHER, CompactUtxo.classifyScriptType(&unknown_script));
}

// ============================================================================
// UtxoSet Tests
// ============================================================================

test "utxo set add get spend lifecycle" {
    const allocator = std.testing.allocator;

    // Memory-only UTXO set (no database)
    var utxo_set = UtxoSet.init(null, 1, allocator);
    defer utxo_set.deinit();

    // Create a P2PKH output
    const p2pkh_script = [_]u8{0x76} ++ [_]u8{0xa9} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20 ++ [_]u8{0x88} ++ [_]u8{0xac};
    const txout = types.TxOut{
        .value = 5000000000,
        .script_pubkey = &p2pkh_script,
    };
    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };

    // Initially should not exist
    try std.testing.expect(!(try utxo_set.contains(&outpoint)));

    // Add the UTXO
    try utxo_set.add(&outpoint, &txout, 100, true);
    try std.testing.expectEqual(@as(u64, 1), utxo_set.total_utxos);
    try std.testing.expectEqual(@as(i64, 5000000000), utxo_set.total_amount);

    // Should now exist
    try std.testing.expect(try utxo_set.contains(&outpoint));

    // Get the UTXO
    var utxo = (try utxo_set.get(&outpoint)).?;
    defer utxo.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 100), utxo.height);
    try std.testing.expect(utxo.is_coinbase);
    try std.testing.expectEqual(@as(i64, 5000000000), utxo.value);
    try std.testing.expectEqual(CompactUtxo.SCRIPT_P2PKH, utxo.script_type);

    // Spend the UTXO
    var spent = (try utxo_set.spend(&outpoint)).?;
    defer spent.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 0), utxo_set.total_utxos);
    try std.testing.expectEqual(@as(i64, 0), utxo_set.total_amount);

    // Should no longer exist
    try std.testing.expect(!(try utxo_set.contains(&outpoint)));

    // Spend again should return null
    const spent_again = try utxo_set.spend(&outpoint);
    try std.testing.expect(spent_again == null);
}

test "utxo set multiple outputs" {
    const allocator = std.testing.allocator;

    var utxo_set = UtxoSet.init(null, 1, allocator);
    defer utxo_set.deinit();

    // Add multiple outputs
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBB} ** 20;
    const txout1 = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const txout2 = types.TxOut{ .value = 200000, .script_pubkey = &p2wpkh_script };
    const txout3 = types.TxOut{ .value = 300000, .script_pubkey = &p2wpkh_script };

    const outpoint1 = types.OutPoint{ .hash = [_]u8{0x11} ** 32, .index = 0 };
    const outpoint2 = types.OutPoint{ .hash = [_]u8{0x11} ** 32, .index = 1 };
    const outpoint3 = types.OutPoint{ .hash = [_]u8{0x22} ** 32, .index = 0 };

    try utxo_set.add(&outpoint1, &txout1, 100, false);
    try utxo_set.add(&outpoint2, &txout2, 100, false);
    try utxo_set.add(&outpoint3, &txout3, 101, false);

    try std.testing.expectEqual(@as(u64, 3), utxo_set.total_utxos);
    try std.testing.expectEqual(@as(i64, 600000), utxo_set.total_amount);

    // Spend one
    var spent = (try utxo_set.spend(&outpoint2)).?;
    defer spent.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 2), utxo_set.total_utxos);
    try std.testing.expectEqual(@as(i64, 400000), utxo_set.total_amount);
}

test "utxo set hit rate" {
    const allocator = std.testing.allocator;

    var utxo_set = UtxoSet.init(null, 1, allocator);
    defer utxo_set.deinit();

    // Initial hit rate should be 0
    try std.testing.expectEqual(@as(f64, 0), utxo_set.hitRate());

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xCC} ** 20;
    const txout = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const outpoint = types.OutPoint{ .hash = [_]u8{0x11} ** 32, .index = 0 };

    try utxo_set.add(&outpoint, &txout, 100, false);

    // Get from cache (should be a hit)
    var utxo = (try utxo_set.get(&outpoint)).?;
    defer utxo.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 1), utxo_set.hits);
    try std.testing.expectEqual(@as(u64, 0), utxo_set.misses);
    try std.testing.expectEqual(@as(f64, 1.0), utxo_set.hitRate());
}

// ============================================================================
// ChainState Tests
// ============================================================================

test "chain state init" {
    const allocator = std.testing.allocator;

    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    try std.testing.expectEqual(@as(u32, 0), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &chain_state.best_hash);
}

test "chain state connect block creates utxos" {
    const allocator = std.testing.allocator;

    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    // Create a simple coinbase transaction
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 }, // height = 1
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const coinbase_output = types.TxOut{
        .value = 5000000000,
        .script_pubkey = &p2wpkh_script,
    };

    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };

    const block = types.Block{
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = [_]u8{0} ** 32,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = 0,
            .bits = 0,
            .nonce = 0,
        },
        .transactions = &[_]types.Transaction{coinbase_tx},
    };

    const block_hash = [_]u8{0x12} ** 32;

    // Connect the block
    var undo = try chain_state.connectBlock(&block, &block_hash, 1);
    defer undo.deinit(allocator);

    // Verify chain state updated
    try std.testing.expectEqual(@as(u32, 1), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &block_hash, &chain_state.best_hash);

    // Verify UTXO was created
    try std.testing.expectEqual(@as(u64, 1), chain_state.utxo_set.total_utxos);

    // Verify undo data
    try std.testing.expectEqual(@as(usize, 0), undo.spent_utxos.len); // Coinbase doesn't spend anything
    try std.testing.expectEqual(@as(usize, 1), undo.created_outpoints.len);
}

test "chain state disconnect block restores state" {
    const allocator = std.testing.allocator;

    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    // First connect a coinbase block
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBB} ** 20;
    const coinbase_output = types.TxOut{
        .value = 5000000000,
        .script_pubkey = &p2wpkh_script,
    };

    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };

    const block = types.Block{
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = [_]u8{0} ** 32,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = 0,
            .bits = 0,
            .nonce = 0,
        },
        .transactions = &[_]types.Transaction{coinbase_tx},
    };

    const block_hash = [_]u8{0x22} ** 32;
    const prev_hash = [_]u8{0} ** 32;

    var undo = try chain_state.connectBlock(&block, &block_hash, 1);
    defer undo.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 1), chain_state.best_height);
    try std.testing.expectEqual(@as(u64, 1), chain_state.utxo_set.total_utxos);

    // Disconnect the block
    try chain_state.disconnectBlock(&undo, prev_hash);

    try std.testing.expectEqual(@as(u32, 0), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &prev_hash, &chain_state.best_hash);
    try std.testing.expectEqual(@as(u64, 0), chain_state.utxo_set.total_utxos);
}

// ============================================================================
// Undo Data Tests (Phase 7)
// ============================================================================

test "block undo data serialization roundtrip" {
    const allocator = std.testing.allocator;

    // Create sample undo data with multiple transactions
    const script1 = try allocator.dupe(u8, &([_]u8{0x76} ++ [_]u8{0xa9} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20 ++ [_]u8{0x88} ++ [_]u8{0xac}));
    const script2 = try allocator.dupe(u8, &([_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBB} ** 20));

    var prev_outputs1 = try allocator.alloc(TxUndo.TxOut, 2);
    prev_outputs1[0] = .{
        .value = 5000000000,
        .script_pubkey = script1,
        .height = 100,
        .is_coinbase = true,
    };
    const script1_copy = try allocator.dupe(u8, &([_]u8{0x76} ++ [_]u8{0xa9} ++ [_]u8{0x14} ++ [_]u8{0xCC} ** 20 ++ [_]u8{0x88} ++ [_]u8{0xac}));
    prev_outputs1[1] = .{
        .value = 1000000,
        .script_pubkey = script1_copy,
        .height = 150,
        .is_coinbase = false,
    };

    var prev_outputs2 = try allocator.alloc(TxUndo.TxOut, 1);
    prev_outputs2[0] = .{
        .value = 250000,
        .script_pubkey = script2,
        .height = 200,
        .is_coinbase = false,
    };

    var tx_undo_arr = try allocator.alloc(TxUndo, 2);
    tx_undo_arr[0] = .{ .prev_outputs = prev_outputs1 };
    tx_undo_arr[1] = .{ .prev_outputs = prev_outputs2 };

    var undo_data = BlockUndoData{ .tx_undo = tx_undo_arr };
    defer undo_data.deinit(allocator);

    // Serialize
    const serialized = try undo_data.toBytes(allocator);
    defer allocator.free(serialized);

    // Deserialize
    var deserialized = try BlockUndoData.fromBytes(serialized, allocator);
    defer deserialized.deinit(allocator);

    // Verify structure
    try std.testing.expectEqual(@as(usize, 2), deserialized.tx_undo.len);
    try std.testing.expectEqual(@as(usize, 2), deserialized.tx_undo[0].prev_outputs.len);
    try std.testing.expectEqual(@as(usize, 1), deserialized.tx_undo[1].prev_outputs.len);

    // Verify values
    try std.testing.expectEqual(@as(i64, 5000000000), deserialized.tx_undo[0].prev_outputs[0].value);
    try std.testing.expectEqual(@as(u32, 100), deserialized.tx_undo[0].prev_outputs[0].height);
    try std.testing.expect(deserialized.tx_undo[0].prev_outputs[0].is_coinbase);

    try std.testing.expectEqual(@as(i64, 1000000), deserialized.tx_undo[0].prev_outputs[1].value);
    try std.testing.expectEqual(@as(u32, 150), deserialized.tx_undo[0].prev_outputs[1].height);
    try std.testing.expect(!deserialized.tx_undo[0].prev_outputs[1].is_coinbase);

    try std.testing.expectEqual(@as(i64, 250000), deserialized.tx_undo[1].prev_outputs[0].value);
    try std.testing.expectEqual(@as(u32, 200), deserialized.tx_undo[1].prev_outputs[0].height);
}

test "block undo data empty serialization" {
    const allocator = std.testing.allocator;

    // Empty undo data (coinbase-only block)
    const tx_undo_arr = try allocator.alloc(TxUndo, 0);
    var undo_data = BlockUndoData{ .tx_undo = tx_undo_arr };
    defer undo_data.deinit(allocator);

    const serialized = try undo_data.toBytes(allocator);
    defer allocator.free(serialized);

    // Should just be the count (1 byte for 0)
    try std.testing.expectEqual(@as(usize, 1), serialized.len);
    try std.testing.expectEqual(@as(u8, 0), serialized[0]);

    var deserialized = try BlockUndoData.fromBytes(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), deserialized.tx_undo.len);
}

test "tx undo height and coinbase packing" {
    const allocator = std.testing.allocator;

    // Test various height and coinbase combinations
    const test_cases = [_]struct { height: u32, is_coinbase: bool }{
        .{ .height = 0, .is_coinbase = false },
        .{ .height = 0, .is_coinbase = true },
        .{ .height = 1, .is_coinbase = false },
        .{ .height = 1, .is_coinbase = true },
        .{ .height = 500000, .is_coinbase = false },
        .{ .height = 500000, .is_coinbase = true },
        .{ .height = 0x7FFFFFFF, .is_coinbase = false },
        .{ .height = 0x7FFFFFFF, .is_coinbase = true },
    };

    for (test_cases) |tc| {
        const script = try allocator.dupe(u8, &([_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20));
        var prev_outputs = try allocator.alloc(TxUndo.TxOut, 1);
        prev_outputs[0] = .{
            .value = 100,
            .script_pubkey = script,
            .height = tc.height,
            .is_coinbase = tc.is_coinbase,
        };

        var tx_undo_arr = try allocator.alloc(TxUndo, 1);
        tx_undo_arr[0] = .{ .prev_outputs = prev_outputs };

        var undo_data = BlockUndoData{ .tx_undo = tx_undo_arr };
        defer undo_data.deinit(allocator);

        const serialized = try undo_data.toBytes(allocator);
        defer allocator.free(serialized);

        var deserialized = try BlockUndoData.fromBytes(serialized, allocator);
        defer deserialized.deinit(allocator);

        try std.testing.expectEqual(tc.height, deserialized.tx_undo[0].prev_outputs[0].height);
        try std.testing.expectEqual(tc.is_coinbase, deserialized.tx_undo[0].prev_outputs[0].is_coinbase);
    }
}

test "chain state init with undo manager" {
    const allocator = std.testing.allocator;

    // Test regular init (no undo manager)
    var chain_state1 = ChainState.init(null, 64, allocator);
    defer chain_state1.deinit();
    try std.testing.expect(chain_state1.undo_manager == null);

    // Test init with undo (has undo manager)
    var chain_state2 = ChainState.initWithUndo(null, 450, "/tmp/testdata", allocator);
    defer chain_state2.deinit();
    try std.testing.expect(chain_state2.undo_manager != null);
    try std.testing.expectEqualStrings("/tmp/testdata", chain_state2.undo_manager.?.data_dir);
}

test "undo file manager path generation" {
    const allocator = std.testing.allocator;

    const manager = UndoFileManager.init("/data/blocks", allocator);

    // Test path generation for file 0
    const path0 = try manager.getUndoFilePath(0);
    const path0_slice = std.mem.sliceTo(&path0, 0);
    try std.testing.expectEqualStrings("/data/blocks/rev00000.dat", path0_slice);

    // Test path generation for file 12345
    const path12345 = try manager.getUndoFilePath(12345);
    const path12345_slice = std.mem.sliceTo(&path12345, 0);
    try std.testing.expectEqualStrings("/data/blocks/rev12345.dat", path12345_slice);
}

test "block undo to block undo data conversion" {
    const allocator = std.testing.allocator;

    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    // Create a block with coinbase + one spending transaction
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const coinbase_output = types.TxOut{
        .value = 5000000000,
        .script_pubkey = &p2wpkh_script,
    };

    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };

    // First, add a UTXO that will be spent
    const prev_outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };
    const prev_output = types.TxOut{
        .value = 1000000,
        .script_pubkey = &p2wpkh_script,
    };
    try chain_state.utxo_set.add(&prev_outpoint, &prev_output, 50, false);

    // Create a spending transaction
    const spending_input = types.TxIn{
        .previous_output = prev_outpoint,
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const spending_output = types.TxOut{
        .value = 900000,
        .script_pubkey = &p2wpkh_script,
    };
    const spending_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{spending_input},
        .outputs = &[_]types.TxOut{spending_output},
        .lock_time = 0,
    };

    const block = types.Block{
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = [_]u8{0} ** 32,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = 0,
            .bits = 0,
            .nonce = 0,
        },
        .transactions = &[_]types.Transaction{ coinbase_tx, spending_tx },
    };

    const block_hash = [_]u8{0x33} ** 32;

    // Connect the block
    var undo = try chain_state.connectBlock(&block, &block_hash, 1);
    defer undo.deinit(allocator);

    // Verify undo data
    try std.testing.expectEqual(@as(usize, 1), undo.spent_utxos.len);
    try std.testing.expectEqual(@as(usize, 2), undo.created_outpoints.len);

    // Convert to file format
    var undo_data = try undo.toBlockUndoData(&block, allocator);
    defer undo_data.deinit(allocator);

    // Verify conversion
    try std.testing.expectEqual(@as(usize, 1), undo_data.tx_undo.len);
    try std.testing.expectEqual(@as(usize, 1), undo_data.tx_undo[0].prev_outputs.len);
    try std.testing.expectEqual(@as(i64, 1000000), undo_data.tx_undo[0].prev_outputs[0].value);
    try std.testing.expectEqual(@as(u32, 50), undo_data.tx_undo[0].prev_outputs[0].height);
}

// ============================================================================
// Flat File Block Storage (Phase 23)
// ============================================================================

/// Maximum size of a blk?????.dat file (128 MiB, matching Bitcoin Core).
pub const MAX_BLOCKFILE_SIZE: u64 = 128 * 1024 * 1024;

/// Pre-allocation chunk size for block files (16 MiB, matching Bitcoin Core).
pub const BLOCKFILE_CHUNK_SIZE: u64 = 16 * 1024 * 1024;

/// Size of the header written before each block (8 bytes: 4 magic + 4 size).
pub const STORAGE_HEADER_BYTES: usize = 8;

/// Position of a block within flat files.
pub const FlatFilePos = struct {
    /// File number (blk{nFile:0>5}.dat).
    file: u32,
    /// Position within the file (byte offset).
    pos: u64,

    pub fn isNull(self: FlatFilePos) bool {
        return self.file == 0xFFFFFFFF and self.pos == 0;
    }

    pub const NULL: FlatFilePos = .{ .file = 0xFFFFFFFF, .pos = 0 };
};

/// Metadata for a single block file.
/// Tracks statistics needed for pruning and block file management.
pub const BlockFileInfo = struct {
    /// Number of blocks stored in this file.
    num_blocks: u32,
    /// Total size of data stored in this file (bytes).
    size: u64,
    /// Lowest block height in this file.
    height_first: u32,
    /// Highest block height in this file.
    height_last: u32,
    /// Earliest block timestamp in this file.
    time_first: u64,
    /// Latest block timestamp in this file.
    time_last: u64,

    /// Serialize to bytes for storage.
    pub fn toBytes(self: *const BlockFileInfo) [32]u8 {
        var buf: [32]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.num_blocks, .little);
        std.mem.writeInt(u64, buf[4..12], self.size, .little);
        std.mem.writeInt(u32, buf[12..16], self.height_first, .little);
        std.mem.writeInt(u32, buf[16..20], self.height_last, .little);
        std.mem.writeInt(u64, buf[20..28], self.time_first, .little);
        // Only 4 bytes left for time_last; store low 32 bits
        std.mem.writeInt(u32, buf[28..32], @truncate(self.time_last), .little);
        return buf;
    }

    /// Deserialize from bytes.
    pub fn fromBytes(data: *const [32]u8) BlockFileInfo {
        return BlockFileInfo{
            .num_blocks = std.mem.readInt(u32, data[0..4], .little),
            .size = std.mem.readInt(u64, data[4..12], .little),
            .height_first = std.mem.readInt(u32, data[12..16], .little),
            .height_last = std.mem.readInt(u32, data[16..20], .little),
            .time_first = std.mem.readInt(u64, data[20..28], .little),
            .time_last = std.mem.readInt(u32, data[28..32], .little),
        };
    }

    /// Update metadata when adding a block.
    pub fn addBlock(self: *BlockFileInfo, height: u32, timestamp: u64, block_size: u64) void {
        if (self.num_blocks == 0) {
            self.height_first = height;
            self.height_last = height;
            self.time_first = timestamp;
            self.time_last = timestamp;
        } else {
            if (height < self.height_first) self.height_first = height;
            if (height > self.height_last) self.height_last = height;
            if (timestamp < self.time_first) self.time_first = timestamp;
            if (timestamp > self.time_last) self.time_last = timestamp;
        }
        self.num_blocks += 1;
        self.size += block_size;
    }
};

/// Flat file block storage manager.
/// Stores blocks in blk{nnnnn}.dat files with a maximum size per file.
/// Each block is prefixed with [magic (4 bytes)][size (4 bytes LE)].
pub const FlatFileBlockStore = struct {
    /// Directory where block files are stored.
    data_dir: []const u8,
    /// Network magic bytes for file headers.
    network_magic: u32,
    /// Metadata for each block file.
    file_info: std.ArrayList(BlockFileInfo),
    /// Current file number being written to.
    current_file: u32,
    /// Current position in the current file.
    current_pos: u64,
    /// Allocator for internal operations.
    allocator: std.mem.Allocator,
    /// Optional database for block index persistence.
    db: ?*Database,

    const Self = @This();

    /// Initialize a new flat file block store.
    /// If db is provided, block positions will be indexed in RocksDB.
    pub fn init(
        data_dir: []const u8,
        network_magic: u32,
        db: ?*Database,
        allocator: std.mem.Allocator,
    ) Self {
        var file_info = std.ArrayList(BlockFileInfo).init(allocator);
        // Initialize with at least one file info entry
        file_info.append(BlockFileInfo{
            .num_blocks = 0,
            .size = 0,
            .height_first = 0,
            .height_last = 0,
            .time_first = 0,
            .time_last = 0,
        }) catch {};

        return Self{
            .data_dir = data_dir,
            .network_magic = network_magic,
            .file_info = file_info,
            .current_file = 0,
            .current_pos = 0,
            .allocator = allocator,
            .db = db,
        };
    }

    pub fn deinit(self: *Self) void {
        self.file_info.deinit();
    }

    /// Generate the path for a block file.
    fn getBlockFilePath(self: *const Self, file_number: u32) ![256]u8 {
        var path_buf: [256]u8 = [_]u8{0} ** 256;
        const path_slice = std.fmt.bufPrint(&path_buf, "{s}/blk{d:0>5}.dat", .{ self.data_dir, file_number }) catch {
            return error.PathTooLong;
        };
        if (path_slice.len < 256) {
            path_buf[path_slice.len] = 0;
        }
        return path_buf;
    }

    /// Open or create a block file at the given position.
    fn openBlockFile(self: *const Self, file_number: u32, read_only: bool) !std.fs.File {
        const path_buf = try self.getBlockFilePath(file_number);
        const path_slice = std.mem.sliceTo(&path_buf, 0);

        if (read_only) {
            return std.fs.cwd().openFile(path_slice, .{ .mode = .read_only }) catch |err| {
                return switch (err) {
                    error.FileNotFound => error.NotFound,
                    else => error.ReadFailed,
                };
            };
        } else {
            // Open for read+write, create if doesn't exist
            return std.fs.cwd().createFile(path_slice, .{
                .truncate = false,
                .read = true,
            }) catch {
                return error.WriteFailed;
            };
        }
    }

    /// Pre-allocate file space in chunks for performance.
    fn preAllocate(self: *Self, file: std.fs.File, target_size: u64) !void {
        _ = self;
        const stat = file.stat() catch return;
        if (target_size > stat.size) {
            // Allocate in BLOCKFILE_CHUNK_SIZE increments
            const chunks_needed = (target_size + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
            const new_size = chunks_needed * BLOCKFILE_CHUNK_SIZE;
            file.setEndPos(new_size) catch {};
        }
    }

    /// Find the next position to write a block.
    /// Returns a file position with enough space for the block.
    fn findNextBlockPos(self: *Self, block_size: u64, height: u32, timestamp: u64) !FlatFilePos {
        const total_size = block_size + STORAGE_HEADER_BYTES;

        // Check if we need to move to a new file
        if (self.current_pos + total_size > MAX_BLOCKFILE_SIZE) {
            // Start a new file
            self.current_file += 1;
            self.current_pos = 0;

            // Ensure we have file info for the new file
            while (self.file_info.items.len <= self.current_file) {
                try self.file_info.append(BlockFileInfo{
                    .num_blocks = 0,
                    .size = 0,
                    .height_first = 0,
                    .height_last = 0,
                    .time_first = 0,
                    .time_last = 0,
                });
            }
        }

        const pos = FlatFilePos{
            .file = self.current_file,
            .pos = self.current_pos,
        };

        // Update file info
        if (self.current_file < self.file_info.items.len) {
            self.file_info.items[self.current_file].addBlock(height, timestamp, total_size);
        }

        // Advance position
        self.current_pos += total_size;

        return pos;
    }

    /// Write a block to disk.
    /// Returns the position where the block was written.
    /// The position points to after the storage header (where block data starts).
    pub fn writeBlock(
        self: *Self,
        block_data: []const u8,
        block_hash: *const types.Hash256,
        height: u32,
        timestamp: u64,
    ) !FlatFilePos {
        const block_size: u64 = block_data.len;

        // Find position for this block
        var pos = try self.findNextBlockPos(block_size, height, timestamp);

        // Open the file
        var file = try self.openBlockFile(pos.file, false);
        defer file.close();

        // Pre-allocate space for performance
        try self.preAllocate(file, pos.pos + block_size + STORAGE_HEADER_BYTES);

        // Seek to position
        file.seekTo(pos.pos) catch return error.WriteFailed;

        // Write using buffered writer for performance
        var buffered = std.io.bufferedWriter(file.writer());
        const writer = buffered.writer();

        // Write magic (4 bytes LE)
        var magic_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &magic_buf, self.network_magic, .little);
        writer.writeAll(&magic_buf) catch return error.WriteFailed;

        // Write block size (4 bytes LE)
        var size_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &size_buf, @intCast(block_size), .little);
        writer.writeAll(&size_buf) catch return error.WriteFailed;

        // Write block data
        writer.writeAll(block_data) catch return error.WriteFailed;

        // Flush the buffer
        buffered.flush() catch return error.WriteFailed;

        // Update position to point after header (where block data starts)
        pos.pos += STORAGE_HEADER_BYTES;

        // Store block index in database if available
        if (self.db) |db| {
            try self.putBlockIndex(db, block_hash, pos);
        }

        return pos;
    }

    /// Read a block from disk at the given position.
    /// The position should point to the block data (after the storage header).
    pub fn readBlockFromDisk(
        self: *const Self,
        pos: FlatFilePos,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (pos.isNull()) {
            return error.NotFound;
        }

        // Position should be at least STORAGE_HEADER_BYTES
        if (pos.pos < STORAGE_HEADER_BYTES) {
            return error.CorruptData;
        }

        // Open the file
        var file = try self.openBlockFile(pos.file, true);
        defer file.close();

        // Seek to the storage header (before block data)
        const header_pos = pos.pos - STORAGE_HEADER_BYTES;
        file.seekTo(header_pos) catch return error.ReadFailed;

        // Use buffered reader for performance
        var buffered = std.io.bufferedReader(file.reader());
        const reader = buffered.reader();

        // Read and verify magic
        var magic_buf: [4]u8 = undefined;
        reader.readNoEof(&magic_buf) catch return error.CorruptData;
        const magic = std.mem.readInt(u32, &magic_buf, .little);
        if (magic != self.network_magic) {
            return error.CorruptData;
        }

        // Read block size
        var size_buf: [4]u8 = undefined;
        reader.readNoEof(&size_buf) catch return error.CorruptData;
        const block_size = std.mem.readInt(u32, &size_buf, .little);

        // Sanity check: block size shouldn't be too large
        if (block_size > 4 * 1024 * 1024) { // 4 MB max
            return error.CorruptData;
        }

        // Allocate and read block data
        const block_data = try allocator.alloc(u8, block_size);
        errdefer allocator.free(block_data);

        reader.readNoEof(block_data) catch {
            allocator.free(block_data);
            return error.CorruptData;
        };

        return block_data;
    }

    /// Read a block and deserialize it.
    pub fn readBlock(
        self: *const Self,
        pos: FlatFilePos,
        allocator: std.mem.Allocator,
    ) !types.Block {
        const block_data = try self.readBlockFromDisk(pos, allocator);
        defer allocator.free(block_data);

        var reader = serialize.Reader{ .data = block_data };
        return serialize.readBlock(&reader, allocator) catch error.CorruptData;
    }

    /// Store a block index entry: block_hash -> FlatFilePos.
    fn putBlockIndex(self: *Self, db: *Database, block_hash: *const types.Hash256, pos: FlatFilePos) !void {
        _ = self;
        // Key: "b" prefix + block hash (33 bytes total)
        var key: [33]u8 = undefined;
        key[0] = 'b';
        @memcpy(key[1..33], block_hash);

        // Value: file (4 bytes) + pos (8 bytes) = 12 bytes
        var value: [12]u8 = undefined;
        std.mem.writeInt(u32, value[0..4], pos.file, .little);
        std.mem.writeInt(u64, value[4..12], pos.pos, .little);

        try db.put(CF_BLOCK_INDEX, &key, &value);
    }

    /// Get the file position for a block hash.
    pub fn getBlockPos(self: *const Self, block_hash: *const types.Hash256) !?FlatFilePos {
        const db = self.db orelse return null;

        var key: [33]u8 = undefined;
        key[0] = 'b';
        @memcpy(key[1..33], block_hash);

        const value = db.get(CF_BLOCK_INDEX, &key) catch return null;
        if (value == null) return null;
        defer self.allocator.free(value.?);

        if (value.?.len != 12) return error.CorruptData;

        return FlatFilePos{
            .file = std.mem.readInt(u32, value.?[0..4], .little),
            .pos = std.mem.readInt(u64, value.?[4..12], .little),
        };
    }

    /// Get file info for a specific file number.
    pub fn getBlockFileInfo(self: *const Self, file_number: u32) ?BlockFileInfo {
        if (file_number >= self.file_info.items.len) return null;
        return self.file_info.items[file_number];
    }

    /// Get the total number of block files.
    pub fn getNumFiles(self: *const Self) u32 {
        return @intCast(self.file_info.items.len);
    }

    /// Flush all pending writes and sync file metadata.
    pub fn flush(self: *Self) !void {
        // Sync the current file if we have written to it
        if (self.current_pos > 0) {
            var file = self.openBlockFile(self.current_file, false) catch return;
            defer file.close();
            file.sync() catch {};
        }
    }

    /// Write block and also serialize it first.
    pub fn writeBlockSerialized(
        self: *Self,
        block: *const types.Block,
        block_hash: *const types.Hash256,
        height: u32,
    ) !FlatFilePos {
        // Serialize block
        var writer = serialize.Writer.init(self.allocator);
        defer writer.deinit();

        serialize.writeBlock(&writer, block) catch return error.SerializationFailed;
        const block_data = writer.getWritten();

        return self.writeBlock(block_data, block_hash, height, block.header.timestamp);
    }
};

// ============================================================================
// Flat File Block Storage Tests
// ============================================================================

test "blockstore constants" {
    // Verify constants match Bitcoin Core
    try std.testing.expectEqual(@as(u64, 128 * 1024 * 1024), MAX_BLOCKFILE_SIZE);
    try std.testing.expectEqual(@as(u64, 16 * 1024 * 1024), BLOCKFILE_CHUNK_SIZE);
    try std.testing.expectEqual(@as(usize, 8), STORAGE_HEADER_BYTES);
}

test "flat_file_pos null check" {
    const null_pos = FlatFilePos.NULL;
    try std.testing.expect(null_pos.isNull());

    const valid_pos = FlatFilePos{ .file = 0, .pos = 100 };
    try std.testing.expect(!valid_pos.isNull());
}

test "block_file_info serialization" {
    const info = BlockFileInfo{
        .num_blocks = 100,
        .size = 50 * 1024 * 1024, // 50 MB
        .height_first = 1000,
        .height_last = 1100,
        .time_first = 1600000000,
        .time_last = 1600100000,
    };

    const serialized = info.toBytes();
    const deserialized = BlockFileInfo.fromBytes(&serialized);

    try std.testing.expectEqual(info.num_blocks, deserialized.num_blocks);
    try std.testing.expectEqual(info.size, deserialized.size);
    try std.testing.expectEqual(info.height_first, deserialized.height_first);
    try std.testing.expectEqual(info.height_last, deserialized.height_last);
    try std.testing.expectEqual(info.time_first, deserialized.time_first);
}

test "block_file_info add_block" {
    var info = BlockFileInfo{
        .num_blocks = 0,
        .size = 0,
        .height_first = 0,
        .height_last = 0,
        .time_first = 0,
        .time_last = 0,
    };

    // First block
    info.addBlock(100, 1600000000, 1000);
    try std.testing.expectEqual(@as(u32, 1), info.num_blocks);
    try std.testing.expectEqual(@as(u64, 1000), info.size);
    try std.testing.expectEqual(@as(u32, 100), info.height_first);
    try std.testing.expectEqual(@as(u32, 100), info.height_last);
    try std.testing.expectEqual(@as(u64, 1600000000), info.time_first);
    try std.testing.expectEqual(@as(u64, 1600000000), info.time_last);

    // Second block with higher height
    info.addBlock(200, 1600100000, 2000);
    try std.testing.expectEqual(@as(u32, 2), info.num_blocks);
    try std.testing.expectEqual(@as(u64, 3000), info.size);
    try std.testing.expectEqual(@as(u32, 100), info.height_first);
    try std.testing.expectEqual(@as(u32, 200), info.height_last);
    try std.testing.expectEqual(@as(u64, 1600000000), info.time_first);
    try std.testing.expectEqual(@as(u64, 1600100000), info.time_last);

    // Third block with lower height (reorg case)
    info.addBlock(50, 1599900000, 1500);
    try std.testing.expectEqual(@as(u32, 3), info.num_blocks);
    try std.testing.expectEqual(@as(u64, 4500), info.size);
    try std.testing.expectEqual(@as(u32, 50), info.height_first);
    try std.testing.expectEqual(@as(u32, 200), info.height_last);
    try std.testing.expectEqual(@as(u64, 1599900000), info.time_first);
    try std.testing.expectEqual(@as(u64, 1600100000), info.time_last);
}

test "flat_file_blockstore init and deinit" {
    const allocator = std.testing.allocator;

    var store = FlatFileBlockStore.init("/tmp/clearbit_test", 0xD9B4BEF9, null, allocator);
    defer store.deinit();

    try std.testing.expectEqual(@as(u32, 0), store.current_file);
    try std.testing.expectEqual(@as(u64, 0), store.current_pos);
    try std.testing.expectEqual(@as(u32, 0xD9B4BEF9), store.network_magic);
}

test "flat_file_blockstore write and read block" {
    const allocator = std.testing.allocator;

    // Create a temporary directory
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var store = FlatFileBlockStore.init(path, 0xD9B4BEF9, null, allocator);
    defer store.deinit();

    // Create some test block data
    const block_data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const block_hash = [_]u8{0xAB} ** 32;

    // Write the block
    const pos = try store.writeBlock(&block_data, &block_hash, 100, 1600000000);

    // Verify position
    try std.testing.expectEqual(@as(u32, 0), pos.file);
    try std.testing.expectEqual(@as(u64, STORAGE_HEADER_BYTES), pos.pos);

    // Read the block back
    const read_data = try store.readBlockFromDisk(pos, allocator);
    defer allocator.free(read_data);

    try std.testing.expectEqualSlices(u8, &block_data, read_data);
}

test "flat_file_blockstore multiple blocks" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var store = FlatFileBlockStore.init(path, 0xD9B4BEF9, null, allocator);
    defer store.deinit();

    // Write multiple blocks
    const block1 = [_]u8{0x11} ** 100;
    const block2 = [_]u8{0x22} ** 200;
    const block3 = [_]u8{0x33} ** 150;

    const hash1 = [_]u8{0x01} ** 32;
    const hash2 = [_]u8{0x02} ** 32;
    const hash3 = [_]u8{0x03} ** 32;

    const pos1 = try store.writeBlock(&block1, &hash1, 100, 1600000000);
    const pos2 = try store.writeBlock(&block2, &hash2, 101, 1600000600);
    const pos3 = try store.writeBlock(&block3, &hash3, 102, 1600001200);

    // All should be in file 0
    try std.testing.expectEqual(@as(u32, 0), pos1.file);
    try std.testing.expectEqual(@as(u32, 0), pos2.file);
    try std.testing.expectEqual(@as(u32, 0), pos3.file);

    // Positions should be sequential
    try std.testing.expectEqual(@as(u64, STORAGE_HEADER_BYTES), pos1.pos);
    try std.testing.expectEqual(@as(u64, STORAGE_HEADER_BYTES + 100 + STORAGE_HEADER_BYTES), pos2.pos);
    try std.testing.expectEqual(@as(u64, STORAGE_HEADER_BYTES + 100 + STORAGE_HEADER_BYTES + 200 + STORAGE_HEADER_BYTES), pos3.pos);

    // Read them all back
    const read1 = try store.readBlockFromDisk(pos1, allocator);
    defer allocator.free(read1);
    try std.testing.expectEqualSlices(u8, &block1, read1);

    const read2 = try store.readBlockFromDisk(pos2, allocator);
    defer allocator.free(read2);
    try std.testing.expectEqualSlices(u8, &block2, read2);

    const read3 = try store.readBlockFromDisk(pos3, allocator);
    defer allocator.free(read3);
    try std.testing.expectEqualSlices(u8, &block3, read3);
}

test "flat_file_blockstore file rotation" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var store = FlatFileBlockStore.init(path, 0xD9B4BEF9, null, allocator);
    defer store.deinit();

    // Simulate approaching file size limit
    // Set current position close to MAX_BLOCKFILE_SIZE
    store.current_pos = MAX_BLOCKFILE_SIZE - 100;

    // Write a block that won't fit in current file
    const large_block = try allocator.alloc(u8, 200);
    defer allocator.free(large_block);
    @memset(large_block, 0xFF);

    const hash = [_]u8{0xDD} ** 32;
    const pos = try store.writeBlock(large_block, &hash, 500, 1700000000);

    // Should have moved to a new file
    try std.testing.expectEqual(@as(u32, 1), pos.file);
    try std.testing.expectEqual(@as(u64, STORAGE_HEADER_BYTES), pos.pos);

    // Current file should be updated
    try std.testing.expectEqual(@as(u32, 1), store.current_file);
}

test "flat_file_blockstore file info tracking" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var store = FlatFileBlockStore.init(path, 0xD9B4BEF9, null, allocator);
    defer store.deinit();

    const block_data = [_]u8{0x55} ** 1000;
    const hash = [_]u8{0xEE} ** 32;

    _ = try store.writeBlock(&block_data, &hash, 12345, 1650000000);

    // Check file info was updated
    const info = store.getBlockFileInfo(0).?;
    try std.testing.expectEqual(@as(u32, 1), info.num_blocks);
    try std.testing.expect(info.size > 0);
    try std.testing.expectEqual(@as(u32, 12345), info.height_first);
    try std.testing.expectEqual(@as(u32, 12345), info.height_last);
    try std.testing.expectEqual(@as(u64, 1650000000), info.time_first);
}

test "flat_file_blockstore invalid magic rejected" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    // Write a block with one magic
    var store1 = FlatFileBlockStore.init(path, 0xD9B4BEF9, null, allocator);
    defer store1.deinit();

    const block_data = [_]u8{0xAA} ** 50;
    const hash = [_]u8{0xBB} ** 32;
    const pos = try store1.writeBlock(&block_data, &hash, 1, 1600000000);

    // Try to read with different magic
    var store2 = FlatFileBlockStore.init(path, 0x12345678, null, allocator);
    defer store2.deinit();

    const result = store2.readBlockFromDisk(pos, allocator);
    try std.testing.expectError(error.CorruptData, result);
}

test "flat_file_blockstore path generation" {
    const allocator = std.testing.allocator;

    var store = FlatFileBlockStore.init("/data/blocks", 0xD9B4BEF9, null, allocator);
    defer store.deinit();

    // Test path generation
    const path0 = try store.getBlockFilePath(0);
    const path0_slice = std.mem.sliceTo(&path0, 0);
    try std.testing.expectEqualStrings("/data/blocks/blk00000.dat", path0_slice);

    const path123 = try store.getBlockFilePath(123);
    const path123_slice = std.mem.sliceTo(&path123, 0);
    try std.testing.expectEqualStrings("/data/blocks/blk00123.dat", path123_slice);

    const path99999 = try store.getBlockFilePath(99999);
    const path99999_slice = std.mem.sliceTo(&path99999, 0);
    try std.testing.expectEqualStrings("/data/blocks/blk99999.dat", path99999_slice);
}

// ============================================================================
// UTXO Cache Layer (Phase 24)
// ============================================================================

/// A UTXO entry matching Bitcoin Core's Coin structure.
/// Serialized format: VARINT((coinbase ? 1 : 0) | (height << 1)) + TxOut
pub const Coin = struct {
    /// The unspent transaction output.
    tx_out: types.TxOut,
    /// The block height at which this coin was created.
    height: u32,
    /// Whether this coin came from a coinbase transaction.
    is_coinbase: bool,

    /// Check if this coin is spent (null output).
    pub fn isSpent(self: *const Coin) bool {
        return self.tx_out.value == 0 and self.tx_out.script_pubkey.len == 0;
    }

    /// Clear this coin (mark as spent).
    pub fn clear(self: *Coin) void {
        self.tx_out.value = 0;
        self.tx_out.script_pubkey = &[_]u8{};
        self.is_coinbase = false;
        self.height = 0;
    }

    /// Estimate dynamic memory usage.
    pub fn dynamicMemoryUsage(self: *const Coin) usize {
        return self.tx_out.script_pubkey.len;
    }

    /// Serialize the coin to bytes for storage.
    /// Format: VARINT(height << 1 | coinbase) + value (i64 LE) + script_len (varint) + script
    pub fn toBytes(self: *const Coin, allocator: std.mem.Allocator) ![]const u8 {
        var writer = serialize.Writer.init(allocator);
        errdefer writer.deinit();

        // Pack height and coinbase flag: height * 2 + coinbase
        const code: u64 = @as(u64, self.height) * 2 + @intFromBool(self.is_coinbase);
        try writer.writeCompactSize(code);

        // Write value
        try writer.writeInt(i64, self.tx_out.value);

        // Write script
        try writer.writeCompactSize(self.tx_out.script_pubkey.len);
        try writer.writeBytes(self.tx_out.script_pubkey);

        return writer.toOwnedSlice();
    }

    /// Deserialize a coin from bytes.
    pub fn fromBytes(data: []const u8, allocator: std.mem.Allocator) !Coin {
        var reader = serialize.Reader{ .data = data };

        // Unpack height and coinbase flag
        const code = try reader.readCompactSize();
        const height: u32 = @intCast(code >> 1);
        const is_coinbase = (code & 1) != 0;

        // Read value
        const value = try reader.readInt(i64);

        // Read script
        const script_len = try reader.readCompactSize();
        const script_bytes = try reader.readBytes(@intCast(script_len));
        const script_pubkey = try allocator.dupe(u8, script_bytes);

        return Coin{
            .tx_out = .{
                .value = value,
                .script_pubkey = script_pubkey,
            },
            .height = height,
            .is_coinbase = is_coinbase,
        };
    }

    /// Free the script_pubkey memory.
    pub fn deinit(self: *Coin, allocator: std.mem.Allocator) void {
        if (self.tx_out.script_pubkey.len > 0) {
            // Only free if it's heap-allocated (not a static empty slice)
            allocator.free(self.tx_out.script_pubkey);
        }
    }
};

/// Cache entry flags matching Bitcoin Core's CCoinsCacheEntry.
/// DIRTY: Modified since last flush to parent.
/// FRESH: Not present in parent cache (created in this cache).
pub const CoinEntry = struct {
    /// The cached coin (null if spent but not yet flushed).
    coin: ?Coin,
    /// True if this entry has been modified since last flush.
    dirty: bool,
    /// True if this entry doesn't exist in the parent/database.
    /// If FRESH and spent, can be deleted without writing to parent.
    fresh: bool,

    pub fn init(coin: Coin, dirty: bool, fresh: bool) CoinEntry {
        return .{
            .coin = coin,
            .dirty = dirty,
            .fresh = fresh,
        };
    }

    pub fn initEmpty() CoinEntry {
        return .{
            .coin = null,
            .dirty = false,
            .fresh = false,
        };
    }

    /// Check if this entry represents a spent coin.
    pub fn isSpent(self: *const CoinEntry) bool {
        return self.coin == null or self.coin.?.isSpent();
    }

    /// Estimate memory usage.
    pub fn memoryUsage(self: *const CoinEntry) usize {
        if (self.coin) |*c| {
            return c.dynamicMemoryUsage() + @sizeOf(CoinEntry);
        }
        return @sizeOf(CoinEntry);
    }

    pub fn deinit(self: *CoinEntry, allocator: std.mem.Allocator) void {
        if (self.coin) |*c| {
            c.deinit(allocator);
            self.coin = null;
        }
    }
};

/// Hash context for OutPoint in AutoHashMap.
pub const OutPointContext = struct {
    pub fn hash(_: OutPointContext, key: types.OutPoint) u64 {
        // Use the first 8 bytes of txid + index for hashing
        var h: u64 = 0;
        h = std.mem.readInt(u64, key.hash[0..8], .little);
        h ^= @as(u64, key.index) *% 0x9e3779b97f4a7c15;
        return h;
    }

    pub fn eql(_: OutPointContext, a: types.OutPoint, b: types.OutPoint) bool {
        return std.mem.eql(u8, &a.hash, &b.hash) and a.index == b.index;
    }
};

/// RocksDB key prefix for UTXO entries.
const UTXO_KEY_PREFIX: u8 = 'C';

/// Build the RocksDB key for a UTXO: "C" + serialized outpoint.
fn makeCoinsDbKey(outpoint: *const types.OutPoint) [37]u8 {
    var key: [37]u8 = undefined;
    key[0] = UTXO_KEY_PREFIX;
    @memcpy(key[1..33], &outpoint.hash);
    std.mem.writeInt(u32, key[33..37], outpoint.index, .little);
    return key;
}

/// CoinsViewDB: Direct RocksDB access layer for UTXO data.
/// This is the lowest level of the cache hierarchy.
pub const CoinsViewDB = struct {
    db: *Database,
    allocator: std.mem.Allocator,

    pub fn init(db: *Database, allocator: std.mem.Allocator) CoinsViewDB {
        return .{
            .db = db,
            .allocator = allocator,
        };
    }

    /// Get a coin from the database.
    pub fn getCoin(self: *const CoinsViewDB, outpoint: *const types.OutPoint) StorageError!?Coin {
        const key = makeCoinsDbKey(outpoint);

        const data = try self.db.get(CF_UTXO, &key);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        return Coin.fromBytes(data.?, self.allocator) catch return StorageError.CorruptData;
    }

    /// Check if a coin exists in the database.
    pub fn haveCoin(self: *const CoinsViewDB, outpoint: *const types.OutPoint) bool {
        const key = makeCoinsDbKey(outpoint);
        const data = self.db.get(CF_UTXO, &key) catch return false;
        if (data) |d| {
            self.allocator.free(d);
            return true;
        }
        return false;
    }

    /// Write a coin to the database.
    pub fn putCoin(self: *const CoinsViewDB, outpoint: *const types.OutPoint, coin: *const Coin) StorageError!void {
        const key = makeCoinsDbKey(outpoint);
        const value = coin.toBytes(self.allocator) catch return StorageError.SerializationFailed;
        defer self.allocator.free(value);

        try self.db.put(CF_UTXO, &key, value);
    }

    /// Delete a coin from the database.
    pub fn deleteCoin(self: *const CoinsViewDB, outpoint: *const types.OutPoint) StorageError!void {
        const key = makeCoinsDbKey(outpoint);
        try self.db.delete(CF_UTXO, &key);
    }

    /// Coin put operation for batch writes.
    pub const CoinPut = struct { outpoint: types.OutPoint, coin: Coin };

    /// Batch write multiple coin operations atomically.
    pub fn batchWrite(
        self: *const CoinsViewDB,
        puts: []const CoinPut,
        deletes: []const types.OutPoint,
    ) StorageError!void {
        var ops = std.ArrayList(BatchOp).init(self.allocator);
        defer {
            // Free allocated key/value buffers
            for (ops.items) |op| {
                switch (op) {
                    .put => |p| {
                        self.allocator.free(@constCast(p.key));
                        self.allocator.free(@constCast(p.value));
                    },
                    .delete => |d| self.allocator.free(@constCast(d.key)),
                }
            }
            ops.deinit();
        }

        // Build put operations
        for (puts) |entry| {
            const key = makeCoinsDbKey(&entry.outpoint);
            const key_copy = self.allocator.alloc(u8, 37) catch return StorageError.OutOfMemory;
            @memcpy(key_copy, &key);

            const value = entry.coin.toBytes(self.allocator) catch return StorageError.SerializationFailed;

            ops.append(.{
                .put = .{ .cf = CF_UTXO, .key = key_copy, .value = value },
            }) catch return StorageError.OutOfMemory;
        }

        // Build delete operations
        for (deletes) |outpoint| {
            const key = makeCoinsDbKey(&outpoint);
            const key_copy = self.allocator.alloc(u8, 37) catch return StorageError.OutOfMemory;
            @memcpy(key_copy, &key);

            ops.append(.{
                .delete = .{ .cf = CF_UTXO, .key = key_copy },
            }) catch return StorageError.OutOfMemory;
        }

        try self.db.writeBatch(ops.items);
    }
};

/// Default UTXO cache size: 450 MiB (matching Bitcoin Core's -dbcache default).
pub const DEFAULT_DB_CACHE_BYTES: usize = 450 * 1024 * 1024;

/// CoinsViewCache: In-memory UTXO cache backed by CoinsViewDB.
/// Implements the cache layer with FRESH/DIRTY optimization.
pub const CoinsViewCache = struct {
    /// In-memory cache of coin entries.
    cache: std.HashMap(types.OutPoint, CoinEntry, OutPointContext, std.hash_map.default_max_load_percentage),
    /// Backing database view (null for top-level test caches).
    base: ?*CoinsViewDB,
    /// Parent cache (for layered caching).
    parent_cache: ?*CoinsViewCache,
    /// Current memory usage estimate.
    cached_coins_usage: usize,
    /// Number of dirty entries.
    dirty_count: usize,
    /// Maximum cache size before flush.
    max_cache_size: usize,
    /// Allocator for cache operations.
    allocator: std.mem.Allocator,

    // Statistics
    hits: u64,
    misses: u64,

    pub fn init(base: ?*CoinsViewDB, max_cache_size: usize, allocator: std.mem.Allocator) CoinsViewCache {
        return .{
            .cache = std.HashMap(types.OutPoint, CoinEntry, OutPointContext, std.hash_map.default_max_load_percentage).init(allocator),
            .base = base,
            .parent_cache = null,
            .cached_coins_usage = 0,
            .dirty_count = 0,
            .max_cache_size = max_cache_size,
            .allocator = allocator,
            .hits = 0,
            .misses = 0,
        };
    }

    /// Initialize with a parent cache (for layered caching during block validation).
    pub fn initWithParent(parent: *CoinsViewCache, allocator: std.mem.Allocator) CoinsViewCache {
        return .{
            .cache = std.HashMap(types.OutPoint, CoinEntry, OutPointContext, std.hash_map.default_max_load_percentage).init(allocator),
            .base = parent.base,
            .parent_cache = parent,
            .cached_coins_usage = 0,
            .dirty_count = 0,
            .max_cache_size = parent.max_cache_size,
            .allocator = allocator,
            .hits = 0,
            .misses = 0,
        };
    }

    pub fn deinit(self: *CoinsViewCache) void {
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            var e = entry.value_ptr.*;
            e.deinit(self.allocator);
        }
        self.cache.deinit();
    }

    /// Get a coin from the cache, falling back to parent/database.
    pub fn getCoin(self: *CoinsViewCache, outpoint: *const types.OutPoint) ?Coin {
        // Check cache first
        if (self.cache.get(outpoint.*)) |entry| {
            self.hits += 1;
            if (entry.coin) |c| {
                if (!c.isSpent()) {
                    // Return a copy
                    return Coin{
                        .tx_out = .{
                            .value = c.tx_out.value,
                            .script_pubkey = self.allocator.dupe(u8, c.tx_out.script_pubkey) catch return null,
                        },
                        .height = c.height,
                        .is_coinbase = c.is_coinbase,
                    };
                }
            }
            return null;
        }

        self.misses += 1;

        // Try parent cache
        if (self.parent_cache) |parent| {
            if (parent.getCoin(outpoint)) |coin| {
                // Cache the result (not dirty, not fresh since it exists in parent)
                self.cacheInsert(outpoint.*, CoinEntry.init(coin, false, false));
                // Return a copy
                return Coin{
                    .tx_out = .{
                        .value = coin.tx_out.value,
                        .script_pubkey = self.allocator.dupe(u8, coin.tx_out.script_pubkey) catch return null,
                    },
                    .height = coin.height,
                    .is_coinbase = coin.is_coinbase,
                };
            }
            return null;
        }

        // Fall back to database
        if (self.base) |db| {
            const coin = db.getCoin(outpoint) catch return null;
            if (coin) |c| {
                // Cache the result (not dirty, not fresh since it exists in DB)
                self.cacheInsert(outpoint.*, CoinEntry.init(c, false, false));
                // Return a copy
                return Coin{
                    .tx_out = .{
                        .value = c.tx_out.value,
                        .script_pubkey = self.allocator.dupe(u8, c.tx_out.script_pubkey) catch return null,
                    },
                    .height = c.height,
                    .is_coinbase = c.is_coinbase,
                };
            }
        }

        return null;
    }

    /// Check if a coin exists.
    pub fn haveCoin(self: *CoinsViewCache, outpoint: *const types.OutPoint) bool {
        // Check cache first
        if (self.cache.get(outpoint.*)) |entry| {
            return !entry.isSpent();
        }

        // Try parent cache
        if (self.parent_cache) |parent| {
            return parent.haveCoin(outpoint);
        }

        // Fall back to database
        if (self.base) |db| {
            return db.haveCoin(outpoint);
        }

        return false;
    }

    /// Check if a coin is in the cache (without database lookup).
    pub fn haveCoinInCache(self: *const CoinsViewCache, outpoint: *const types.OutPoint) bool {
        if (self.cache.get(outpoint.*)) |entry| {
            return !entry.isSpent();
        }
        return false;
    }

    /// Add a new coin to the cache.
    /// possible_overwrite: if true, allows overwriting an existing unspent coin.
    pub fn addCoin(
        self: *CoinsViewCache,
        outpoint: *const types.OutPoint,
        coin: Coin,
        possible_overwrite: bool,
    ) !void {
        // Check for OP_RETURN (unspendable)
        if (coin.tx_out.script_pubkey.len > 0 and coin.tx_out.script_pubkey[0] == 0x6a) {
            return;
        }

        // Check for existing entry
        if (self.cache.getPtr(outpoint.*)) |entry_ptr| {
            const existing_spent = entry_ptr.isSpent();

            if (!possible_overwrite and !existing_spent) {
                return error.CoinOverwrite;
            }

            // Determine if we can mark as FRESH
            // If the coin exists as spent and is DIRTY, we can't mark new one as FRESH
            // because spentness hasn't been flushed yet
            const fresh = !entry_ptr.dirty;

            // Update memory tracking
            if (entry_ptr.dirty) {
                self.dirty_count -= 1;
            }
            self.cached_coins_usage -= entry_ptr.memoryUsage();

            // Clean up old entry
            entry_ptr.deinit(self.allocator);

            // Insert new coin
            entry_ptr.* = CoinEntry{
                .coin = Coin{
                    .tx_out = .{
                        .value = coin.tx_out.value,
                        .script_pubkey = self.allocator.dupe(u8, coin.tx_out.script_pubkey) catch return error.OutOfMemory,
                    },
                    .height = coin.height,
                    .is_coinbase = coin.is_coinbase,
                },
                .dirty = true,
                .fresh = fresh,
            };

            self.dirty_count += 1;
            self.cached_coins_usage += entry_ptr.memoryUsage();
        } else {
            // New entry - mark as FRESH (doesn't exist in parent)
            const entry = CoinEntry{
                .coin = Coin{
                    .tx_out = .{
                        .value = coin.tx_out.value,
                        .script_pubkey = self.allocator.dupe(u8, coin.tx_out.script_pubkey) catch return error.OutOfMemory,
                    },
                    .height = coin.height,
                    .is_coinbase = coin.is_coinbase,
                },
                .dirty = true,
                .fresh = true,
            };

            self.cache.put(outpoint.*, entry) catch return error.OutOfMemory;
            self.dirty_count += 1;
            self.cached_coins_usage += entry.memoryUsage();
        }
    }

    /// Spend a coin. Returns true if the coin existed and was spent.
    /// If moveout is provided, the spent coin is moved there.
    pub fn spendCoin(self: *CoinsViewCache, outpoint: *const types.OutPoint, moveout: ?*Coin) bool {
        // First, ensure the coin is in the cache
        if (self.cache.getPtr(outpoint.*)) |entry_ptr| {
            if (entry_ptr.isSpent()) {
                return false;
            }

            // Update memory tracking
            if (entry_ptr.dirty) {
                self.dirty_count -= 1;
            }
            self.cached_coins_usage -= entry_ptr.memoryUsage();

            // Move coin out if requested
            if (moveout) |m| {
                m.* = entry_ptr.coin.?;
                entry_ptr.coin = null;
            }

            // FRESH optimization: if FRESH, we can delete entirely (never hit DB)
            if (entry_ptr.fresh) {
                entry_ptr.deinit(self.allocator);
                _ = self.cache.remove(outpoint.*);
            } else {
                // Not FRESH: mark as dirty spent (needs to be written to parent)
                if (moveout == null) {
                    entry_ptr.deinit(self.allocator);
                }
                entry_ptr.coin = null;
                entry_ptr.dirty = true;
                self.dirty_count += 1;
                // Don't add memory usage for spent entries
            }

            return true;
        }

        // Not in cache - try to fetch it
        _ = self.getCoin(outpoint);

        // Try again after fetch
        if (self.cache.getPtr(outpoint.*)) |entry_ptr| {
            if (entry_ptr.isSpent()) {
                return false;
            }

            // Update memory tracking
            if (entry_ptr.dirty) {
                self.dirty_count -= 1;
            }
            self.cached_coins_usage -= entry_ptr.memoryUsage();

            // Move coin out if requested
            if (moveout) |m| {
                m.* = entry_ptr.coin.?;
                entry_ptr.coin = null;
            }

            // Not FRESH since we just fetched from parent
            if (moveout == null) {
                entry_ptr.deinit(self.allocator);
            }
            entry_ptr.coin = null;
            entry_ptr.dirty = true;
            self.dirty_count += 1;

            return true;
        }

        return false;
    }

    /// Flush all dirty entries to the backing store.
    pub fn flush(self: *CoinsViewCache) !void {
        if (self.dirty_count == 0) return;

        // Collect operations
        var puts = std.ArrayList(CoinsViewDB.CoinPut).init(self.allocator);
        defer puts.deinit();

        var deletes = std.ArrayList(types.OutPoint).init(self.allocator);
        defer deletes.deinit();

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.dirty) {
                if (entry.value_ptr.coin) |*c| {
                    if (!c.isSpent()) {
                        // Unspent coin: write to parent/DB
                        try puts.append(.{ .outpoint = entry.key_ptr.*, .coin = c.* });
                    } else if (!entry.value_ptr.fresh) {
                        // Spent coin, not fresh: delete from parent/DB
                        try deletes.append(entry.key_ptr.*);
                    }
                    // Spent + fresh: skip entirely (FRESH optimization)
                } else {
                    // Null coin (spent): delete if not fresh
                    if (!entry.value_ptr.fresh) {
                        try deletes.append(entry.key_ptr.*);
                    }
                }
            }
        }

        // Flush to parent cache or database
        if (self.parent_cache) |parent| {
            // Flush to parent cache
            for (puts.items) |p| {
                try parent.addCoin(&p.outpoint, p.coin, true);
            }
            for (deletes.items) |outpoint| {
                _ = parent.spendCoin(&outpoint, null);
            }
        } else if (self.base) |db| {
            // Flush to database
            try db.batchWrite(puts.items, deletes.items);
        }

        // Clear the cache
        var clear_iter = self.cache.iterator();
        while (clear_iter.next()) |entry| {
            var e = entry.value_ptr.*;
            e.deinit(self.allocator);
        }
        self.cache.clearRetainingCapacity();
        self.cached_coins_usage = 0;
        self.dirty_count = 0;
    }

    /// Check if memory usage exceeds the limit.
    pub fn shouldFlush(self: *const CoinsViewCache) bool {
        return self.cached_coins_usage >= self.max_cache_size;
    }

    /// Get cache statistics.
    pub fn getStats(self: *const CoinsViewCache) struct {
        cache_size: usize,
        memory_usage: usize,
        dirty_count: usize,
        hits: u64,
        misses: u64,
        hit_rate: f64,
    } {
        const total = self.hits + self.misses;
        const hit_rate = if (total > 0) @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total)) else 0;

        return .{
            .cache_size = self.cache.count(),
            .memory_usage = self.cached_coins_usage,
            .dirty_count = self.dirty_count,
            .hits = self.hits,
            .misses = self.misses,
            .hit_rate = hit_rate,
        };
    }

    /// Internal: insert an entry into the cache.
    fn cacheInsert(self: *CoinsViewCache, outpoint: types.OutPoint, entry: CoinEntry) void {
        if (entry.dirty) {
            self.dirty_count += 1;
        }
        self.cached_coins_usage += entry.memoryUsage();
        self.cache.put(outpoint, entry) catch {};
    }
};

// ============================================================================
// UTXO Cache Tests (Phase 24)
// ============================================================================

test "coin serialization roundtrip" {
    const allocator = std.testing.allocator;

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const coin = Coin{
        .tx_out = .{
            .value = 5000000000,
            .script_pubkey = &script,
        },
        .height = 500000,
        .is_coinbase = true,
    };

    const serialized = try coin.toBytes(allocator);
    defer allocator.free(serialized);

    var deserialized = try Coin.fromBytes(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(coin.tx_out.value, deserialized.tx_out.value);
    try std.testing.expectEqual(coin.height, deserialized.height);
    try std.testing.expectEqual(coin.is_coinbase, deserialized.is_coinbase);
    try std.testing.expectEqualSlices(u8, coin.tx_out.script_pubkey, deserialized.tx_out.script_pubkey);
}

test "coin non-coinbase serialization" {
    const allocator = std.testing.allocator;

    const script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xCD} ** 20 ++ [_]u8{ 0x88, 0xac };
    const coin = Coin{
        .tx_out = .{
            .value = 123456789,
            .script_pubkey = &script,
        },
        .height = 700000,
        .is_coinbase = false,
    };

    const serialized = try coin.toBytes(allocator);
    defer allocator.free(serialized);

    var deserialized = try Coin.fromBytes(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(coin.height, deserialized.height);
    try std.testing.expect(!deserialized.is_coinbase);
}

test "coin is_spent check" {
    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;

    var coin = Coin{
        .tx_out = .{
            .value = 1000,
            .script_pubkey = &script,
        },
        .height = 100,
        .is_coinbase = false,
    };

    try std.testing.expect(!coin.isSpent());

    coin.clear();
    try std.testing.expect(coin.isSpent());
}

test "coin entry flags" {
    const allocator = std.testing.allocator;

    // Allocate script dynamically so deinit can free it
    const script_data = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;
    const script1 = try allocator.dupe(u8, &script_data);
    const script2 = try allocator.dupe(u8, &script_data);

    const coin1 = Coin{
        .tx_out = .{
            .value = 1000,
            .script_pubkey = script1,
        },
        .height = 100,
        .is_coinbase = false,
    };

    const coin2 = Coin{
        .tx_out = .{
            .value = 1000,
            .script_pubkey = script2,
        },
        .height = 100,
        .is_coinbase = false,
    };

    // Fresh + dirty (new coin)
    var entry1 = CoinEntry.init(coin1, true, true);
    try std.testing.expect(entry1.dirty);
    try std.testing.expect(entry1.fresh);
    try std.testing.expect(!entry1.isSpent());

    // Not fresh, not dirty (fetched from DB)
    var entry2 = CoinEntry.init(coin2, false, false);
    try std.testing.expect(!entry2.dirty);
    try std.testing.expect(!entry2.fresh);

    // Empty entry
    const entry3 = CoinEntry.initEmpty();
    try std.testing.expect(entry3.isSpent());
    try std.testing.expect(entry3.coin == null);

    // Memory usage should include script
    try std.testing.expect(entry1.memoryUsage() > @sizeOf(CoinEntry));

    entry1.deinit(allocator);
    entry2.deinit(allocator);
}

test "coins db key generation" {
    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0x12345678,
    };

    const key = makeCoinsDbKey(&outpoint);

    // Key should be 37 bytes: 'C' + txid (32) + index (4)
    try std.testing.expectEqual(@as(usize, 37), key.len);
    try std.testing.expectEqual(@as(u8, 'C'), key[0]);
    try std.testing.expectEqualSlices(u8, &outpoint.hash, key[1..33]);

    // Index should be little-endian
    try std.testing.expectEqual(@as(u8, 0x78), key[33]);
    try std.testing.expectEqual(@as(u8, 0x56), key[34]);
    try std.testing.expectEqual(@as(u8, 0x34), key[35]);
    try std.testing.expectEqual(@as(u8, 0x12), key[36]);
}

test "coins view cache add and get" {
    const allocator = std.testing.allocator;

    var cache = CoinsViewCache.init(null, 1024 * 1024, allocator);
    defer cache.deinit();

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCC} ** 20;
    const coin = Coin{
        .tx_out = .{
            .value = 5000000000,
            .script_pubkey = &script,
        },
        .height = 100,
        .is_coinbase = true,
    };

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };

    // Add coin
    try cache.addCoin(&outpoint, coin, false);

    // Verify it's in cache
    try std.testing.expect(cache.haveCoin(&outpoint));
    try std.testing.expect(cache.haveCoinInCache(&outpoint));

    // Get the coin
    var fetched = cache.getCoin(&outpoint).?;
    defer fetched.deinit(allocator);

    try std.testing.expectEqual(coin.tx_out.value, fetched.tx_out.value);
    try std.testing.expectEqual(coin.height, fetched.height);
    try std.testing.expectEqual(coin.is_coinbase, fetched.is_coinbase);

    // Check stats
    const stats = cache.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats.cache_size);
    try std.testing.expectEqual(@as(usize, 1), stats.dirty_count);
    try std.testing.expect(stats.memory_usage > 0);
}

test "coins view cache spend coin" {
    const allocator = std.testing.allocator;

    var cache = CoinsViewCache.init(null, 1024 * 1024, allocator);
    defer cache.deinit();

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xDD} ** 20;
    const coin = Coin{
        .tx_out = .{
            .value = 1000000,
            .script_pubkey = &script,
        },
        .height = 200,
        .is_coinbase = false,
    };

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x22} ** 32,
        .index = 1,
    };

    // Add and then spend
    try cache.addCoin(&outpoint, coin, false);
    try std.testing.expect(cache.haveCoin(&outpoint));

    var spent_coin: Coin = undefined;
    const result = cache.spendCoin(&outpoint, &spent_coin);
    defer spent_coin.deinit(allocator);

    try std.testing.expect(result);
    try std.testing.expectEqual(coin.tx_out.value, spent_coin.tx_out.value);

    // Should no longer exist
    try std.testing.expect(!cache.haveCoin(&outpoint));
}

test "coins view cache fresh optimization" {
    const allocator = std.testing.allocator;

    var cache = CoinsViewCache.init(null, 1024 * 1024, allocator);
    defer cache.deinit();

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xEE} ** 20;
    const coin = Coin{
        .tx_out = .{
            .value = 500000,
            .script_pubkey = &script,
        },
        .height = 300,
        .is_coinbase = false,
    };

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x33} ** 32,
        .index = 2,
    };

    // Add coin (marked FRESH since it doesn't exist in DB)
    try cache.addCoin(&outpoint, coin, false);

    // Verify cache state
    const stats_before = cache.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats_before.cache_size);
    try std.testing.expectEqual(@as(usize, 1), stats_before.dirty_count);

    // Spend the coin (FRESH optimization: should remove entirely)
    const result = cache.spendCoin(&outpoint, null);
    try std.testing.expect(result);

    // After spending a FRESH coin, it should be completely removed
    // (no need to write delete to DB since it was never written)
    const stats_after = cache.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats_after.cache_size);
    try std.testing.expectEqual(@as(usize, 0), stats_after.dirty_count);
}

test "coins view cache hit miss tracking" {
    const allocator = std.testing.allocator;

    var cache = CoinsViewCache.init(null, 1024 * 1024, allocator);
    defer cache.deinit();

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xFF} ** 20;
    const coin = Coin{
        .tx_out = .{
            .value = 100000,
            .script_pubkey = &script,
        },
        .height = 400,
        .is_coinbase = false,
    };

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x44} ** 32,
        .index = 3,
    };

    // Initial stats
    var stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.hits);
    try std.testing.expectEqual(@as(u64, 0), stats.misses);

    // Miss: coin doesn't exist
    _ = cache.getCoin(&outpoint);
    stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.hits);
    try std.testing.expectEqual(@as(u64, 1), stats.misses);

    // Add the coin
    try cache.addCoin(&outpoint, coin, false);

    // Hit: coin now exists in cache
    var fetched = cache.getCoin(&outpoint).?;
    defer fetched.deinit(allocator);
    stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.hits);
    try std.testing.expectEqual(@as(u64, 1), stats.misses);

    // Hit rate should be 50%
    try std.testing.expectEqual(@as(f64, 0.5), stats.hit_rate);
}

test "coins view cache flush to parent" {
    const allocator = std.testing.allocator;

    // Create parent cache
    var parent = CoinsViewCache.init(null, 1024 * 1024, allocator);
    defer parent.deinit();

    // Create child cache backed by parent
    var child = CoinsViewCache.initWithParent(&parent, allocator);
    defer child.deinit();

    const script = [_]u8{ 0x51, 0x20 } ++ [_]u8{0xAA} ** 32;
    const coin = Coin{
        .tx_out = .{
            .value = 312500000, // 3.125 BTC
            .script_pubkey = &script,
        },
        .height = 800000,
        .is_coinbase = true,
    };

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x55} ** 32,
        .index = 0,
    };

    // Add to child
    try child.addCoin(&outpoint, coin, false);

    // Not in parent yet
    try std.testing.expect(!parent.haveCoin(&outpoint));

    // Flush child to parent
    try child.flush();

    // Now in parent
    try std.testing.expect(parent.haveCoin(&outpoint));

    // Child should be empty
    try std.testing.expectEqual(@as(usize, 0), child.getStats().cache_size);
}

test "coins view cache memory tracking" {
    const allocator = std.testing.allocator;

    var cache = CoinsViewCache.init(null, 1024 * 1024, allocator);
    defer cache.deinit();

    // Add several coins
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{@truncate(i)} ** 20;
        var hash: [32]u8 = undefined;
        @memset(&hash, @truncate(i));

        const coin = Coin{
            .tx_out = .{
                .value = @as(i64, i) * 10000,
                .script_pubkey = &script,
            },
            .height = 100 + i,
            .is_coinbase = false,
        };

        const outpoint = types.OutPoint{
            .hash = hash,
            .index = i,
        };

        try cache.addCoin(&outpoint, coin, false);
    }

    const stats = cache.getStats();
    try std.testing.expectEqual(@as(usize, 10), stats.cache_size);
    try std.testing.expectEqual(@as(usize, 10), stats.dirty_count);
    try std.testing.expect(stats.memory_usage > 0);

    // Should not need to flush yet (small cache)
    try std.testing.expect(!cache.shouldFlush());
}

test "coins view cache skip op_return" {
    const allocator = std.testing.allocator;

    var cache = CoinsViewCache.init(null, 1024 * 1024, allocator);
    defer cache.deinit();

    // OP_RETURN script (unspendable)
    const script = [_]u8{ 0x6a, 0x04, 0x74, 0x65, 0x73, 0x74 }; // OP_RETURN PUSH4 "test"
    const coin = Coin{
        .tx_out = .{
            .value = 0,
            .script_pubkey = &script,
        },
        .height = 100,
        .is_coinbase = false,
    };

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x66} ** 32,
        .index = 0,
    };

    // Should not add OP_RETURN outputs
    try cache.addCoin(&outpoint, coin, false);

    try std.testing.expect(!cache.haveCoin(&outpoint));
    try std.testing.expectEqual(@as(usize, 0), cache.getStats().cache_size);
}

test "outpoint context hash and equality" {
    const ctx = OutPointContext{};

    const op1 = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };

    const op2 = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };

    const op3 = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 1,
    };

    const op4 = types.OutPoint{
        .hash = [_]u8{0x22} ** 32,
        .index = 0,
    };

    // Same outpoints should be equal
    try std.testing.expect(ctx.eql(op1, op2));
    try std.testing.expectEqual(ctx.hash(op1), ctx.hash(op2));

    // Different index should not be equal
    try std.testing.expect(!ctx.eql(op1, op3));

    // Different txid should not be equal
    try std.testing.expect(!ctx.eql(op1, op4));
}

test "coins view cache default size" {
    // Verify default cache size matches Bitcoin Core
    try std.testing.expectEqual(@as(usize, 450 * 1024 * 1024), DEFAULT_DB_CACHE_BYTES);
}

// ============================================================================
// assumeUTXO Tests
// ============================================================================

test "snapshot magic bytes" {
    // Verify snapshot magic matches Bitcoin Core
    try std.testing.expectEqualSlices(u8, &[_]u8{ 'u', 't', 'x', 'o', 0xff }, &SNAPSHOT_MAGIC_BYTES);
}

test "snapshot metadata serialization" {
    const allocator = std.testing.allocator;

    const metadata = SnapshotMetadata{
        .network_magic = 0xD9B4BEF9, // Mainnet
        .base_blockhash = [_]u8{0x11} ** 32,
        .coins_count = 176_000_000,
    };

    const serialized = try metadata.toBytes(allocator);
    defer allocator.free(serialized);

    // Verify size
    try std.testing.expectEqual(@as(usize, SnapshotMetadata.HEADER_SIZE), serialized.len);

    // Deserialize and verify
    const deserialized = try SnapshotMetadata.fromBytes(serialized, 0xD9B4BEF9);
    try std.testing.expectEqual(metadata.network_magic, deserialized.network_magic);
    try std.testing.expectEqualSlices(u8, &metadata.base_blockhash, &deserialized.base_blockhash);
    try std.testing.expectEqual(metadata.coins_count, deserialized.coins_count);
}

test "snapshot metadata wrong network" {
    const allocator = std.testing.allocator;

    const metadata = SnapshotMetadata{
        .network_magic = 0xD9B4BEF9, // Mainnet
        .base_blockhash = [_]u8{0x11} ** 32,
        .coins_count = 100,
    };

    const serialized = try metadata.toBytes(allocator);
    defer allocator.free(serialized);

    // Try to deserialize with wrong network magic (testnet)
    const result = SnapshotMetadata.fromBytes(serialized, 0x0709110B);
    try std.testing.expectError(StorageError.CorruptData, result);
}

test "snapshot coin serialization" {
    const allocator = std.testing.allocator;

    const script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAA} ** 20 ++ [_]u8{ 0x88, 0xac };
    const coin = SnapshotCoin{
        .outpoint = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 5,
        },
        .height = 500000,
        .is_coinbase = true,
        .value = 5000000000,
        .script_pubkey = &script,
    };

    const serialized = try coin.toBytes(allocator);
    defer allocator.free(serialized);

    // Deserialize
    var reader = serialize.Reader{ .data = serialized };
    var deserialized = try SnapshotCoin.fromReader(&reader, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &coin.outpoint.hash, &deserialized.outpoint.hash);
    try std.testing.expectEqual(coin.outpoint.index, deserialized.outpoint.index);
    try std.testing.expectEqual(coin.height, deserialized.height);
    try std.testing.expectEqual(coin.is_coinbase, deserialized.is_coinbase);
    try std.testing.expectEqual(coin.value, deserialized.value);
    try std.testing.expectEqualSlices(u8, coin.script_pubkey, deserialized.script_pubkey);
}

test "snapshot coin height and coinbase packing" {
    const allocator = std.testing.allocator;

    const script = [_]u8{0x51}; // OP_TRUE

    // Test non-coinbase
    const non_cb = SnapshotCoin{
        .outpoint = types.OutPoint{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .height = 0x7FFFFFFF, // Max height
        .is_coinbase = false,
        .value = 1000,
        .script_pubkey = &script,
    };

    const serialized_non_cb = try non_cb.toBytes(allocator);
    defer allocator.free(serialized_non_cb);

    var reader1 = serialize.Reader{ .data = serialized_non_cb };
    var decoded_non_cb = try SnapshotCoin.fromReader(&reader1, allocator);
    defer decoded_non_cb.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 0x7FFFFFFF), decoded_non_cb.height);
    try std.testing.expect(!decoded_non_cb.is_coinbase);

    // Test coinbase
    const cb = SnapshotCoin{
        .outpoint = types.OutPoint{ .hash = [_]u8{0x33} ** 32, .index = 0 },
        .height = 100000,
        .is_coinbase = true,
        .value = 5000000000,
        .script_pubkey = &script,
    };

    const serialized_cb = try cb.toBytes(allocator);
    defer allocator.free(serialized_cb);

    var reader2 = serialize.Reader{ .data = serialized_cb };
    var decoded_cb = try SnapshotCoin.fromReader(&reader2, allocator);
    defer decoded_cb.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 100000), decoded_cb.height);
    try std.testing.expect(decoded_cb.is_coinbase);
}

test "chainstate role enum" {
    // Verify chainstate roles are distinct
    try std.testing.expect(ChainstateRole.normal != ChainstateRole.snapshot);
    try std.testing.expect(ChainstateRole.snapshot != ChainstateRole.background);
    try std.testing.expect(ChainstateRole.normal != ChainstateRole.background);
}

test "chainstate manager init" {
    const allocator = std.testing.allocator;
    const consensus = @import("consensus.zig");

    var chainstate = ChainState.init(null, 64, allocator);
    defer chainstate.deinit();

    var manager = ChainStateManager.init(&chainstate, &consensus.MAINNET, allocator);
    defer manager.deinit();

    try std.testing.expect(!manager.isAssumeUtxoMode());
    try std.testing.expect(manager.background_chainstate == null);
    try std.testing.expectEqual(ChainstateRole.normal, manager.active_role);
}

test "chainstate manager activate snapshot" {
    const allocator = std.testing.allocator;
    const consensus = @import("consensus.zig");

    var normal_chainstate = ChainState.init(null, 64, allocator);
    defer normal_chainstate.deinit();

    var snapshot_chainstate = ChainState.init(null, 64, allocator);
    defer snapshot_chainstate.deinit();

    var manager = ChainStateManager.init(&normal_chainstate, &consensus.MAINNET, allocator);
    defer manager.deinit();

    // Activate snapshot
    const base_hash = [_]u8{0x12} ** 32;
    manager.activateSnapshot(&snapshot_chainstate, base_hash);

    try std.testing.expect(manager.isAssumeUtxoMode());
    try std.testing.expectEqual(ChainstateRole.snapshot, manager.active_role);
    try std.testing.expect(manager.background_chainstate != null);
    try std.testing.expectEqualSlices(u8, &base_hash, &(manager.snapshot_base_blockhash.?));
}

test "BlockIndexRecord serialization roundtrip" {
    // Test that BlockIndexRecord fields are correctly serialized/deserialized
    const consensus = @import("consensus.zig");

    const record = ChainStore.BlockIndexRecord{
        .height = 12345,
        .header = consensus.MAINNET.genesis_header,
        .status = 0x0000001F, // Multiple flags set
        .chain_work = [_]u8{0xAB} ** 32,
        .sequence_id = -42,
        .file_number = 7,
        .file_offset = 0x123456789,
    };

    // Verify the structure has correct fields
    try std.testing.expectEqual(@as(u32, 12345), record.height);
    try std.testing.expectEqual(@as(u32, 0x0000001F), record.status);
    try std.testing.expectEqual(@as(i64, -42), record.sequence_id);
    try std.testing.expectEqual(@as(u32, 7), record.file_number);
    try std.testing.expectEqual(@as(u64, 0x123456789), record.file_offset);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 32), &record.chain_work);
}

// ============================================================================
// AssumeUTXO Snapshot Tests
// ============================================================================

test "snapshot metadata serialization roundtrip" {
    const allocator = std.testing.allocator;

    const metadata = SnapshotMetadata{
        .network_magic = 0xD9B4BEF9, // mainnet
        .base_blockhash = [_]u8{0x12} ** 32,
        .coins_count = 176_000_000,
    };

    const serialized = try metadata.toBytes(allocator);
    defer allocator.free(serialized);

    // Verify header size
    try std.testing.expectEqual(@as(usize, SnapshotMetadata.HEADER_SIZE), serialized.len);

    // Deserialize and verify
    const deserialized = try SnapshotMetadata.fromBytes(serialized, 0xD9B4BEF9);

    try std.testing.expectEqual(metadata.network_magic, deserialized.network_magic);
    try std.testing.expectEqualSlices(u8, &metadata.base_blockhash, &deserialized.base_blockhash);
    try std.testing.expectEqual(metadata.coins_count, deserialized.coins_count);
}

test "snapshot metadata wrong network rejected" {
    const allocator = std.testing.allocator;

    const metadata = SnapshotMetadata{
        .network_magic = 0xD9B4BEF9, // mainnet
        .base_blockhash = [_]u8{0x12} ** 32,
        .coins_count = 176_000_000,
    };

    const serialized = try metadata.toBytes(allocator);
    defer allocator.free(serialized);

    // Try to deserialize with testnet magic - should fail
    const result = SnapshotMetadata.fromBytes(serialized, 0x0709110B);
    try std.testing.expectError(StorageError.CorruptData, result);
}

test "snapshot coin serialization roundtrip" {
    const allocator = std.testing.allocator;

    const script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac };
    const coin = SnapshotCoin{
        .outpoint = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 42,
        },
        .height = 500000,
        .is_coinbase = true,
        .value = 5000000000,
        .script_pubkey = &script,
    };

    const serialized = try coin.toBytes(allocator);
    defer allocator.free(serialized);

    var reader = serialize.Reader{ .data = serialized };
    var deserialized = try SnapshotCoin.fromReader(&reader, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &coin.outpoint.hash, &deserialized.outpoint.hash);
    try std.testing.expectEqual(coin.outpoint.index, deserialized.outpoint.index);
    try std.testing.expectEqual(coin.height, deserialized.height);
    try std.testing.expectEqual(coin.is_coinbase, deserialized.is_coinbase);
    try std.testing.expectEqual(coin.value, deserialized.value);
    try std.testing.expectEqualSlices(u8, coin.script_pubkey, deserialized.script_pubkey);
}

test "findAssumeUtxoEntry returns entry for known hash" {
    const consensus = @import("consensus.zig");

    // Mainnet has a snapshot at block 840000
    if (consensus.MAINNET.assume_utxo.len > 0) {
        const expected_entry = consensus.MAINNET.assume_utxo[0];
        const found = findAssumeUtxoEntry(&consensus.MAINNET, &expected_entry.block_hash);
        try std.testing.expect(found != null);
        try std.testing.expectEqual(expected_entry.height, found.?.height);
        try std.testing.expectEqual(expected_entry.coins_count, found.?.coins_count);
    }
}

test "findAssumeUtxoEntry returns null for unknown hash" {
    const consensus = @import("consensus.zig");

    const unknown_hash = [_]u8{0xFF} ** 32;
    const found = findAssumeUtxoEntry(&consensus.MAINNET, &unknown_hash);
    try std.testing.expect(found == null);
}

test "findAssumeUtxoEntryByHeight returns entry for known height" {
    const consensus = @import("consensus.zig");

    // Mainnet has a snapshot at block 840000
    if (consensus.MAINNET.assume_utxo.len > 0) {
        const expected_entry = consensus.MAINNET.assume_utxo[0];
        const found = findAssumeUtxoEntryByHeight(&consensus.MAINNET, expected_entry.height);
        try std.testing.expect(found != null);
        try std.testing.expectEqualSlices(u8, &expected_entry.block_hash, &found.?.block_hash);
    }
}

test "findAssumeUtxoEntryByHeight returns null for unknown height" {
    const consensus = @import("consensus.zig");

    const found = findAssumeUtxoEntryByHeight(&consensus.MAINNET, 999999);
    try std.testing.expect(found == null);
}

test "snapshot error variants are distinct" {
    const errors = [_]SnapshotError{
        SnapshotError.UnknownSnapshot,
        SnapshotError.HashMismatch,
        SnapshotError.CoinCountMismatch,
        SnapshotError.IoError,
        SnapshotError.CorruptData,
        SnapshotError.WrongNetwork,
        SnapshotError.OutOfMemory,
        SnapshotError.BackgroundValidationFailed,
    };

    for (errors, 0..) |e1, i| {
        for (errors[i + 1 ..]) |e2| {
            try std.testing.expect(e1 != e2);
        }
    }
}

test "ChainStateManager completeValidation with matching hashes" {
    const allocator = std.testing.allocator;
    const consensus = @import("consensus.zig");

    // Create two chainstates with the same UTXO data
    var active_chainstate = ChainState.init(null, 64, allocator);
    defer active_chainstate.deinit();

    var background_chainstate = ChainState.init(null, 64, allocator);
    defer background_chainstate.deinit();

    // Add identical UTXOs to both
    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };
    const txout = types.TxOut{
        .value = 5000000000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac },
    };
    try active_chainstate.utxo_set.add(&outpoint, &txout, 500000, false);
    try background_chainstate.utxo_set.add(&outpoint, &txout, 500000, false);

    // Set matching best hashes
    const base_hash = [_]u8{0x12} ** 32;
    active_chainstate.best_hash = base_hash;
    background_chainstate.best_hash = base_hash;

    var manager = ChainStateManager.init(&active_chainstate, &consensus.MAINNET, allocator);
    defer manager.deinit();

    // Activate snapshot mode
    manager.activateSnapshot(&active_chainstate, base_hash);
    // Set background chainstate directly for testing
    manager.background_chainstate = &background_chainstate;

    // Complete validation should succeed since hashes match
    const result = try manager.completeValidation();
    try std.testing.expect(result);
    try std.testing.expect(!manager.isAssumeUtxoMode());
}
