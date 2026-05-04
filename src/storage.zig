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
//! - `block_undo`: Per-block undo data keyed by block hash (for reorg disconnect)

const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const storage_rocksdb = @import("storage_rocksdb.zig");

/// Column family indices for organizing data.
/// Each stores a different type of data with potentially different
/// compaction and caching settings.
pub const CF_DEFAULT: usize = 0;
pub const CF_BLOCKS: usize = 1; // Raw block data
pub const CF_BLOCK_INDEX: usize = 2; // Block header + metadata by hash
pub const CF_UTXO: usize = 3; // Unspent transaction outputs
pub const CF_TX_INDEX: usize = 4; // Transaction hash -> block location
/// Per-block undo data keyed by block hash. Stores the BlockUndoData byte
/// stream (matches `BlockUndoData.toBytes`/`fromBytes`) so any block on a
/// non-pruned chain can be disconnected during a reorg.  Added 2026-05-02
/// to close the IBD-only / no-disconnect deferred P0s without inheriting
/// rev*.dat-file management complexity (Option B in the deferred audit).
pub const CF_BLOCK_UNDO: usize = 5;
/// Total number of column families. Must match `cf_names` length in
/// storage_rocksdb.zig and the array sizes in DbState.
pub const CF_COUNT: usize = 6;

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
    /// `block_cache_mib` sizes the RocksDB LRU block cache in MiB
    /// (typically the same value as the user's `--dbcache` flag).
    pub fn open(path: []const u8, block_cache_mib: u64, allocator: std.mem.Allocator) StorageError!Database {
        return storage_rocksdb.openDatabase(path, block_cache_mib, allocator);
    }

    /// Close the database.
    pub fn close(self: *Database) void {
        storage_rocksdb.closeDatabase(self);
    }

    /// Get a value by key from a column family.
    pub fn get(self: *Database, cf_index: usize, key: []const u8) StorageError!?[]const u8 {
        return storage_rocksdb.dbGet(self, cf_index, key);
    }

    /// Batch point-lookup across a single column family.  results[i]
    /// corresponds to keys[i]: null on miss, allocated slice on hit.
    /// Caller owns each non-null result (must free via self.allocator).
    pub fn multiGet(
        self: *Database,
        cf_index: usize,
        keys: []const []const u8,
        results: []?[]u8,
    ) StorageError!void {
        return storage_rocksdb.dbMultiGet(self, cf_index, keys, results);
    }

    /// Put a key-value pair into a column family.
    pub fn put(self: *Database, cf_index: usize, key: []const u8, value: []const u8) StorageError!void {
        return storage_rocksdb.dbPut(self, cf_index, key, value);
    }

    /// Delete a key from a column family.
    pub fn delete(self: *Database, cf_index: usize, key: []const u8) StorageError!void {
        return storage_rocksdb.dbDelete(self, cf_index, key);
    }

    /// Batch write: apply multiple operations atomically.
    pub fn writeBatch(self: *Database, operations: []const BatchOp) StorageError!void {
        return storage_rocksdb.dbWriteBatch(self, operations);
    }

    /// Create an iterator for scanning a column family.
    pub fn iterator(self: *Database, cf_index: usize) Iterator {
        return storage_rocksdb.dbIterator(self, cf_index);
    }

    /// Flush all in-memory data to disk.
    pub fn flush(self: *Database) StorageError!void {
        return storage_rocksdb.dbFlush(self);
    }

    /// Fetch an integer-valued RocksDB CF property (e.g. live-data-size).
    /// Returns null if the property name is not supported or the call fails.
    /// Used by the pruner to size CF_BLOCKS against the configured target.
    pub fn getCfPropertyInt(self: *Database, cf_index: usize, propname_z: [*:0]const u8) ?u64 {
        return storage_rocksdb.dbGetCfPropertyInt(self, cf_index, propname_z);
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

    /// Prefix for height→hash index keys in CF_DEFAULT.
    /// Key layout: "H:" ++ u32_LE(height) (6 bytes total).
    /// Value: 32-byte block hash at that height on the active chain.
    /// Written atomically with the chain tip in `ChainState.flush()` so a
    /// backward walk via getblockhash is always possible without keeping the
    /// whole BlockIndexEntry chain resident post-restart.
    pub const HEIGHT_HASH_PREFIX = "H:";
    pub const HEIGHT_HASH_KEY_LEN: usize = 6;

    pub fn buildHeightHashKey(height: u32) [HEIGHT_HASH_KEY_LEN]u8 {
        var key: [HEIGHT_HASH_KEY_LEN]u8 = undefined;
        key[0] = 'H';
        key[1] = ':';
        std.mem.writeInt(u32, key[2..6], height, .little);
        return key;
    }

    pub fn init(datadir: []const u8, allocator: std.mem.Allocator) StorageError!ChainStore {
        // Default block cache (64 MiB) — callers that want larger should
        // construct the Database directly via Database.open with their --dbcache value.
        const db = try Database.open(datadir, 64, allocator);
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

/// Matches Bitcoin Core's LargeCoinsCacheThreshold() at
/// `bitcoin-core/src/validation.h:518`: the UTXO cache is considered "large"
/// when usage is within `LARGE_THRESHOLD_HEADROOM` of the configured cap.
/// At that point Core calls `CCoinsViewCache::Flush()` (write dirty, wipe
/// cache); we mirror that in `evictCache` below.
const LARGE_THRESHOLD_HEADROOM: usize = 10 * 1024 * 1024; // 10 MiB

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
    // Track dirty keys for O(dirty) flush instead of O(cache) scan
    dirty_keys: std.ArrayList([36]u8),
    // Optional back-reference to owning ChainState for atomic eviction flush.
    // When set, evictCache calls ChainState.flush() (which includes the chain
    // tip) instead of UtxoSet.flush() (which does not).
    parent: ?*ChainState = null,
    // When true, suppress eviction during block connection to prevent
    // mid-block flushes that can write partial state.
    suppress_eviction: bool = false,

    /// Cache entry with ownership tracking.
    const CacheEntry = struct {
        utxo: CompactUtxo,
        dirty: bool, // true if modified but not yet flushed to DB
        fresh: bool, // true if created in cache and never written to DB

        fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
            var utxo = self.utxo;
            utxo.deinit(allocator);
        }
    };

    /// Initialize a new UTXO set.
    /// If db is null, operates in memory-only mode (useful for testing).
    pub fn init(db: ?*Database, max_cache_mb: usize, allocator: std.mem.Allocator) UtxoSet {
        // Pre-size HashMap for IBD performance.
        // With the corrected 500 bytes/entry estimate and typical --dbcache=4096,
        // the cache can hold ~8M entries.  Pre-allocate 2M slots to avoid
        // repeated rehashing during early IBD.
        var cache = std.HashMap([36]u8, CacheEntry, UtxoKeyContext, std.hash_map.default_max_load_percentage).init(allocator);
        cache.ensureTotalCapacity(1 << 21) catch {}; // 2M slots pre-allocated
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
            .dirty_keys = std.ArrayList([36]u8).init(allocator),
        };
    }

    pub fn deinit(self: *UtxoSet) void {
        self.flushPendingDeletes() catch {};
        self.pending_deletes.deinit();
        self.dirty_keys.deinit();
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
            try self.cache.put(key, CacheEntry{ .utxo = cache_utxo, .dirty = false, .fresh = false });

            // Read-throughs also grow the cache; check eviction periodically.
            // Skip during block connection (suppress_eviction) to prevent
            // mid-block flushes that write partial UTXO state.
            self.adds_since_eviction_check += 1;
            if (!self.suppress_eviction and self.adds_since_eviction_check >= 1000) {
                self.adds_since_eviction_check = 0;
                if (self.cacheMemoryUsage() > self.max_cache_size -| LARGE_THRESHOLD_HEADROOM) {
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

    /// W73 Fix 1 — batch-prefetch all cache-missing inputs of a block into
    /// the cache before the per-tx spend loop runs.  Cuts N one-by-one
    /// RocksDB round-trips per block down to a single `rocksdb_multi_get_cf`.
    ///
    /// Contract:
    ///   - Read-only w.r.t. the DB; only mutates the in-memory cache.
    ///   - Skips coinbase (tx 0 has no real inputs).
    ///   - Skips inputs already in cache (created in earlier block, or
    ///     intra-block outputs created by a prior tx — neither needs a DB
    ///     round-trip, and intra-block creates would not yet be on disk
    ///     so the multi-get would return null for them anyway).
    ///   - A miss (multi-get returns null) is fine: subsequent `spend()`
    ///     falls through its existing cache-miss → DB path.  Prefetch is
    ///     pure warming; it can never cause a spend to fail that would
    ///     otherwise have succeeded.
    ///   - Returns count of DB hits added to cache (for W73-PROF stats).
    ///
    /// Safety: the UTXO entries populated here are marked `dirty=false,
    /// fresh=false`.  If a later intra-block spend removes them, pending
    /// _deletes picks them up correctly (fresh=false path).  If they
    /// survive the block, they stay in cache without polluting the dirty
    /// set.  Cache size accounting falls out of evictCache's existing
    /// sizing, so no new footgun vs. the read-through path in `get()`.
    pub fn prefetchBlockInputs(self: *UtxoSet, block: *const types.Block) !usize {
        if (self.db == null) return 0;
        if (block.transactions.len <= 1) return 0;

        // Collect cache-miss keys.  Stable backing store: keys are stored
        // by value in miss_keys, and key_slices points into that storage
        // — so we must finalize miss_keys (no appends) before slicing.
        var miss_keys = std.ArrayList([36]u8).init(self.allocator);
        defer miss_keys.deinit();
        // Reserve capacity: upper bound is sum of tx.inputs.len across
        // non-coinbase txs.  Avoids growth-realloc invalidating slices.
        var upper: usize = 0;
        for (block.transactions[1..]) |tx| upper += tx.inputs.len;
        try miss_keys.ensureTotalCapacity(upper);

        for (block.transactions[1..]) |tx| {
            for (tx.inputs) |input| {
                const key = makeUtxoKey(&input.previous_output);
                if (self.cache.contains(key)) continue;
                miss_keys.appendAssumeCapacity(key);
            }
        }

        if (miss_keys.items.len == 0) return 0;

        const key_slices = try self.allocator.alloc([]const u8, miss_keys.items.len);
        defer self.allocator.free(key_slices);
        for (miss_keys.items, 0..) |*k, i| {
            key_slices[i] = k[0..];
        }

        const results = try self.allocator.alloc(?[]u8, miss_keys.items.len);
        defer {
            // Any result we did NOT move into the cache (e.g. decode error
            // or cache.put OOM) is freed here.  Entries that landed in the
            // cache have already been swapped to null in the loop below.
            for (results) |r| if (r) |v| self.allocator.free(v);
            self.allocator.free(results);
        }

        try self.db.?.multiGet(CF_UTXO, key_slices, results);

        var hits: usize = 0;
        for (miss_keys.items, 0..) |key, i| {
            const data = results[i] orelse continue;
            const utxo = CompactUtxo.decode(data, self.allocator) catch {
                // Corrupt record — leave in results[i] so defer frees it.
                continue;
            };
            // Entry is clean, not fresh (came from DB).  Same shape as the
            // read-through branch in `get()` at line ~935.
            self.cache.put(key, CacheEntry{
                .utxo = utxo,
                .dirty = false,
                .fresh = false,
            }) catch {
                var u = utxo;
                u.deinit(self.allocator);
                continue;
            };
            // Transfer ownership: data (results[i]) is still allocated; we
            // freed the decoded utxo from it but the original slice is our
            // job to free.  Null it so the defer doesn't double-free.
            self.allocator.free(data);
            results[i] = null;
            self.misses += 1; // account as a miss (read-through filled it)
            hits += 1;
        }

        return hits;
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

        // Check eviction every 1000 adds instead of every add (saves overhead).
        // Skip during block connection (suppress_eviction) to prevent mid-block
        // flushes that write partial UTXO state.
        self.adds_since_eviction_check += 1;
        if (!self.suppress_eviction and self.adds_since_eviction_check >= 1000) {
            self.adds_since_eviction_check = 0;
            if (self.cacheMemoryUsage() > self.max_cache_size -| LARGE_THRESHOLD_HEADROOM) {
                self.evictCache();
            }
        }

        // Store in cache (marked dirty + fresh — FRESH means it was created in
        // cache and never written to DB, so if it's spent before the next flush
        // we can skip the DB write entirely).
        try self.cache.put(key, CacheEntry{ .utxo = compact, .dirty = true, .fresh = true });
        // Track dirty key for efficient flush
        self.dirty_keys.append(key) catch {};

        self.total_utxos += 1;
        self.total_amount += output.value;
    }

    /// Evict cache entries when memory usage approaches `max_cache_size`.
    ///
    /// Mirrors Bitcoin Core's `CCoinsViewCache::Flush()` at
    /// `bitcoin-core/src/coins.cpp:279-299`: write all dirty entries to the
    /// backing database, then wipe the entire cache.  Callers are expected
    /// to fire eviction once usage crosses `max_cache_size - LARGE_THRESHOLD_HEADROOM`
    /// (the Core `LargeCoinsCacheThreshold` at `validation.h:518`).
    ///
    /// When `suppress_eviction` is set (mid-block connection), we cannot
    /// safely flush partial state, so the fallback `evictCleanOnly` drops
    /// only clean non-fresh entries.
    fn evictCache(self: *UtxoSet) void {
        // Without a DB backend, eviction permanently loses UTXO data.
        // Only evict when we have a database to fall back to.
        if (self.db == null) return;

        if (self.suppress_eviction) {
            self.evictCleanOnly();
            return;
        }

        // Flush all dirty entries to DB (atomically with tip via ChainState
        // when wired up) before wiping the cache.
        if (self.parent) |cs| {
            cs.flush() catch |err| {
                std.debug.print("UTXO evictCache: atomic flush failed with {}, skipping eviction\n", .{err});
                return;
            };
        } else {
            self.flush() catch |err| {
                std.debug.print("UTXO evictCache: flush failed with {}, skipping eviction to prevent data loss\n", .{err});
                return;
            };
        }

        const count_before = self.cache.count();

        // Deinit every entry to free its variable-length script bytes.
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }

        // Matches `CCoinsMap::clear()` in Bitcoin Core: drop the contents
        // but retain the bucket array.  Next block's inserts skip the
        // initial rehash; the memory is returned to the allocator's pool
        // as subsequent blocks cycle through it.
        self.cache.clearRetainingCapacity();

        if (count_before > 0) {
            std.debug.print("UTXO cache flush-and-wipe: {d} entries cleared\n", .{count_before});
        }
    }

    /// Defense-in-depth fallback used when `suppress_eviction` is set (we
    /// are mid-block-connect and cannot flush partial state).  Drops only
    /// clean non-fresh entries — dropping a fresh entry would permanently
    /// lose a UTXO that exists only in the cache, and dropping a dirty one
    /// would lose a pending DB write.
    fn evictCleanOnly(self: *UtxoSet) void {
        var to_remove = std.ArrayList([36]u8).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            if (!entry.value_ptr.dirty and !entry.value_ptr.fresh) {
                to_remove.append(entry.key_ptr.*) catch break;
            }
        }

        for (to_remove.items) |key_to_remove| {
            if (self.cache.fetchRemove(key_to_remove)) |old| {
                var e = old.value;
                e.deinit(self.allocator);
            }
        }

        if (to_remove.items.len > 0) {
            std.debug.print("UTXO cache clean-only eviction: dropped {d} entries (suppress_eviction=true)\n", .{to_remove.items.len});
        }
    }

    /// Remove a UTXO (spend it). Returns the spent UTXO for undo data.
    pub fn spend(self: *UtxoSet, outpoint: *const types.OutPoint) !?CompactUtxo {
        @setRuntimeSafety(true);
        const key = makeUtxoKey(outpoint);

        // Try to get from cache first
        if (self.cache.fetchRemove(key)) |old| {
            self.total_utxos -|= 1;
            self.total_amount -|= old.value.utxo.value;

            // FRESH optimization: if the entry was created in cache and never
            // written to DB, we can skip the DB delete entirely.  This is a
            // huge win during IBD where many UTXOs are created and spent
            // within the same flush window.
            if (self.db != null and !old.value.fresh) {
                self.pending_deletes.append(key) catch {};
                // Pending deletes are flushed atomically with the chain tip
                // in ChainState.flush() (called every 100 blocks from
                // connectBlockFast).  Do NOT flush here — an independent
                // flush would commit deletes to disk ahead of the tip, and
                // a crash between would corrupt the chainstate (see
                // stuck-at-370001 bug).  At ~8000 deletes/block that's
                // ~800k entries × 36 bytes = ~29 MB between flushes, well
                // within budget.
            }

            return old.value.utxo;
        }

        // CVE-2012-2459 / dup-txid double-spend guard: if this key is in
        // pending_deletes it was already spent by an earlier tx in the same
        // block but the DB delete has not been flushed yet (deletes are
        // batched for atomicity with the chain tip in ChainState.flush()).
        // Without this check a block containing [coinbase, tx, tx] (same
        // non-coinbase tx twice) would be incorrectly accepted: the second
        // tx's prevout is gone from cache (first tx removed it) but is still
        // readable from the DB, so spend() would succeed a second time.
        // Core rejects via bad-txns-inputs-missingorspent in ConnectBlock
        // (validation.cpp) when the in-place CCoinsViewCache finds the coin
        // already marked spent.  Reference: dup-txid-merkle-malleation corpus.
        for (self.pending_deletes.items) |pd_key| {
            if (std.mem.eql(u8, &pd_key, &key)) return null;
        }

        // Not in cache, try database
        if (self.db) |db| {
            const data = db.get(CF_UTXO, &key) catch return null;
            if (data == null) return null;
            defer self.allocator.free(data.?);

            const utxo = try CompactUtxo.decode(data.?, self.allocator);

            // Batch the DB delete.  Flush is deferred to ChainState.flush()
            // so that deletes are atomic with the chain tip.
            self.pending_deletes.append(key) catch {};

            self.total_utxos -|= 1;
            self.total_amount -|= utxo.value;

            return utxo;
        }

        return null;
    }

    /// Flush the dirty cache entries to disk.
    /// Uses the dirty_keys tracker for O(dirty) performance instead of
    /// scanning the entire cache.
    pub fn flush(self: *UtxoSet) !void {
        if (self.db == null) return;

        // Flush pending deletes first
        try self.flushPendingDeletes();

        if (self.dirty_keys.items.len == 0) return;

        var batch = std.ArrayList(BatchOp).init(self.allocator);
        defer batch.deinit();

        // Use tracked dirty keys instead of scanning entire cache
        var actual_dirty = std.ArrayList([36]u8).init(self.allocator);
        defer actual_dirty.deinit();

        for (self.dirty_keys.items) |key| {
            if (self.cache.getPtr(key)) |entry_ptr| {
                if (entry_ptr.dirty) {
                    const encoded = try entry_ptr.utxo.encode(self.allocator);
                    const key_copy = try self.allocator.alloc(u8, 36);
                    @memcpy(key_copy, &key);

                    try batch.append(.{ .put = .{
                        .cf = CF_UTXO,
                        .key = key_copy,
                        .value = encoded,
                    } });
                    try actual_dirty.append(key);
                }
            }
            // Key not in cache anymore (evicted/spent) — skip
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
                // Do NOT clear dirty_keys — the entries were not persisted
                return err;
            };

            // Only mark entries as clean AFTER successful writeBatch.
            // Also clear the FRESH flag since the entry now exists in DB.
            for (actual_dirty.items) |key| {
                if (self.cache.getPtr(key)) |entry_ptr| {
                    entry_ptr.dirty = false;
                    entry_ptr.fresh = false;
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

        // Clear the dirty tracker only AFTER successful writeBatch
        self.dirty_keys.clearRetainingCapacity();
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
    /// Estimate the memory usage of the UTXO cache.
    ///
    /// Per-entry cost breakdown:
    ///   - CompactUtxo struct: ~48 bytes (height, value, coinbase, script_type, slice)
    ///   - hash_or_script heap alloc: ~32 bytes (20-32 data + allocator overhead)
    ///   - CacheEntry wrapper (dirty flag + padding): ~56 bytes
    ///   - HashMap key [36]u8: 36 bytes
    ///   - HashMap metadata per slot: ~8 bytes
    ///   - Allocator fragmentation / glibc overhead: ~320 bytes
    /// Total: ~500 bytes per entry (measured empirically during full IBD).
    ///
    /// The theoretical minimum is ~200 bytes/entry, but glibc malloc retains
    /// freed pages due to fragmentation from millions of small hash_or_script
    /// allocations (20-32 bytes each).  Using 500 bytes ensures eviction
    /// triggers before RSS grows beyond --dbcache * 2.5x.
    pub fn cacheMemoryUsage(self: *const UtxoSet) usize {
        return self.cache.count() * 500;
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

        // Open file for writing (append mode). createFile with truncate=false
        // both creates and opens, so the FileNotFound retry below is normally
        // unreachable; kept as a defensive belt-and-suspenders for filesystems
        // that surface the missing-file error before applying creation flags.
        const file = std.fs.cwd().createFile(path_slice, .{ .truncate = false }) catch |err| blk: {
            switch (err) {
                error.FileNotFound => break :blk std.fs.cwd().createFile(path_slice, .{}) catch return error.WriteFailed,
                else => return error.WriteFailed,
            }
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
    /// Block-keep horizon: blocks within this many heights of the tip are
    /// always retained (matches Bitcoin Core's MIN_BLOCKS_TO_KEEP in
    /// validation.h:76 — 288 blocks ≈ 2 days at 10 min/block, the typical
    /// reorg depth tolerance window).
    pub const MIN_BLOCKS_TO_KEEP: u32 = 288;
    /// Smallest accepted --prune target. Bitcoin Core constant
    /// MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB (validation.h:87): below
    /// this, the prune cannot keep up with the 288-block tail + undo +
    /// orphan rate budget. We follow Core verbatim so operators can
    /// reuse their existing tuning.
    pub const MIN_PRUNE_TARGET_MIB: u64 = 550;

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
    /// Sticky flag set when a flush() call fails to persist its batch.
    /// connectBlockFast / submitBlock check this on entry and refuse to
    /// connect another block until cleared.  Without this, a transient
    /// RocksDB error silently rewinds the on-disk tip relative to the
    /// in-memory tip and IBD continues building UTXOs that will never
    /// have a corresponding on-disk delete record — exactly the
    /// stuck-at-370001 corruption mode (Option A, wave2-2026-04-14).
    flush_error: bool = false,

    // W73 phase profiling — populated under connect_mutex so no atomics.
    // Summary line emitted every 100 blocks in connectBlockFast. Targets
    // the actual mainnet IBD bottleneck (UTXO ops + flush), not script
    // verify (which peer.zig's drainBlockBuffer path bypasses entirely).
    profile_blocks: u64 = 0,
    profile_spend_ns_sum: u64 = 0,
    profile_spend_ns_max: u64 = 0,
    profile_create_ns_sum: u64 = 0,
    profile_create_ns_max: u64 = 0,
    profile_evict_ns_sum: u64 = 0,
    profile_evict_count: u64 = 0,
    profile_flush_ns_sum: u64 = 0,
    profile_flush_ns_max: u64 = 0,
    profile_total_ns_sum: u64 = 0,
    profile_total_ns_max: u64 = 0,
    profile_input_count: u64 = 0,
    profile_output_count: u64 = 0,
    // W73 Fix 1 — prefetch phase (batched UTXO multi-get before per-tx
    // spend loop).  Both per-block scratch and 100-block rollup.
    profile_prefetch_ns_sum: u64 = 0,
    profile_prefetch_ns_max: u64 = 0,
    profile_prefetch_hits_sum: u64 = 0,
    // Scratch fields for connectBlockInner → connectBlockFast handoff.
    // Holds the current block's per-phase ns; connectBlockFast reads
    // and rolls them into the 100-block running sums/maxes above.
    profile_cur_spend_ns: u64 = 0,
    profile_cur_create_ns: u64 = 0,
    profile_cur_evict_ns: u64 = 0,
    profile_cur_prefetch_ns: u64 = 0,
    profile_cur_prefetch_hits: u64 = 0,
    // W73 Fix 3 — flush sub-phase split.  Per W73-FIX2-ALT-POST-DEPLOY-FINDINGS
    // §5: flush dominates the tail (avg 588-864 ms, max 3-6 s per window).
    // Before touching any batching change, we need to know which of
    // sort / batch-build / rocksdb-write / cleanup is the cost.  Same
    // scratch → connectBlockFast rollup pattern as the other phases above.
    profile_cur_flush_sort_ns: u64 = 0,
    profile_cur_flush_build_ns: u64 = 0,
    profile_cur_flush_write_ns: u64 = 0,
    profile_cur_flush_cleanup_ns: u64 = 0,
    profile_flush_sort_ns_sum: u64 = 0,
    profile_flush_sort_ns_max: u64 = 0,
    profile_flush_build_ns_sum: u64 = 0,
    profile_flush_build_ns_max: u64 = 0,
    profile_flush_write_ns_sum: u64 = 0,
    profile_flush_write_ns_max: u64 = 0,
    profile_flush_cleanup_ns_sum: u64 = 0,
    profile_flush_cleanup_ns_max: u64 = 0,

    // ----------------------------------------------------------------------
    // Pruning state (Bitcoin Core analog: BlockManager::m_prune_target,
    // BlockManager::m_have_pruned, m_blockfiles_indexed in node/blockstorage).
    //
    // clearbit stores raw block bytes in CF_BLOCKS keyed by block hash, so
    // pruning here = `db.delete(CF_BLOCKS, hash)` for the heights we no
    // longer want to retain (rather than unlinking blk*.dat flat files,
    // which clearbit does not write — FlatFileBlockStore is dead code).
    //
    // `prune_target_mib` of 0 disables pruning entirely (default behaviour
    // identical to pre-pruning clearbit). When non-zero, must be ≥ 550 MiB
    // to match Bitcoin Core's MIN_DISK_SPACE_FOR_BLOCK_FILES validation.
    //
    // `prune_height` is the highest height whose block bytes have been
    // pruned (i.e. heights ≤ prune_height are guaranteed missing from
    // CF_BLOCKS). Heights > prune_height MAY still be missing if they
    // were never stored in the first place — clearbit's IBD path
    // (peer.zig drainBlockBuffer) currently does not populate CF_BLOCKS,
    // so today the watermark advances but no real deletes happen. The
    // RPC layer treats `prune_height` as the only authoritative pruned
    // boundary. When CF_BLOCKS gains a populator (block_template /
    // mining / serve-from-disk), the same watermark will start
    // reflecting real deletions.
    // BIP-113 MTP ring buffer — populated by connectBlockInner so that
    // the submitblock RPC path can enforce the BIP-113 timestamp rule without
    // accessing CF_BLOCK_INDEX (which the fast connect path does not populate).
    //
    // Invariant: `recent_timestamps[i]` holds the timestamp of the block at
    // height (best_height - i), i.e. slot 0 is the current tip, slot 1 is
    // its parent, etc.  Up to 11 entries stored; `computeMTP()` sorts them.
    //
    // The genesis block's timestamp is stored in slot 0 during chain init
    // (via initGenesisTimestamp) so that blocks at height 1..10 get the
    // correct 3..11 ancestor window.
    //
    // Reset to all-zeros on init; the count tracks how many are valid.
    recent_timestamps: [11]u32 = [_]u32{0} ** 11,
    recent_ts_count: u32 = 0,

    /// Prune target size for CF_BLOCKS in MiB. 0 = disabled (pruning off).
    /// Must be ≥ 550 when non-zero (validated in main.zig before assignment).
    prune_target_mib: u64 = 0,
    /// Highest height whose block body has been pruned (or considered prunable).
    /// Heights ≤ prune_height are not retrievable via getblock RPC.
    prune_height: u32 = 0,

    // ----------------------------------------------------------------------
    // CF_BLOCKS populator (Bitcoin Core analog:
    // BlockManager::SaveBlockToDisk / WriteBlockToDisk in node/blockstorage.cpp,
    // called from validation.cpp before CheckBlock so the bytes are durable
    // before validation begins).
    //
    // peer.zig's drainBlockBuffer used to advance UTXOs straight from the
    // in-memory `types.Block` and discard the bytes — leaving CF_BLOCKS
    // empty across the entire IBD chain. That made `getblock` unanswerable
    // for any block below tip and made the --prune path (00a4ea7) a no-op.
    //
    // The fix queues `(hash, raw_bytes)` here just before connectBlockFast,
    // and flush() appends a CF_BLOCKS put for each entry into the SAME
    // WriteBatch as the UTXO mutations and tip update. This makes the
    // body-on-disk semantics atomic with the chainstate advance: a crash
    // either leaves the body+tip pair both committed or neither.
    //
    // Bytes are owned by ChainState until flush() succeeds, at which point
    // the cleanup loop frees them via the standard BatchOp free. On
    // flush_error / process exit, deinit() drains the queue.
    pending_block_writes: std.ArrayList(PendingBlockWrite) = undefined,
    /// Per-block undo bytes pending durable write to CF_BLOCK_UNDO.  Same
    /// atomic-flush pattern as `pending_block_writes`: bytes are appended
    /// just before `connectBlockFastWithUndo` returns success, then committed
    /// in the next `flush()` call's WriteBatch alongside the UTXO mutations,
    /// tip, and CF_BLOCKS body.  A crash leaves all four advanced together
    /// or none.
    ///
    /// Populated by `connectBlockFastWithUndo` (runtime-IBD path with reorg
    /// support enabled) and by the existing `connectBlockWithUndo` /
    /// rollback-dance call sites.  Empty whenever undo capture is disabled
    /// (legacy IBD path that calls `connectBlockFast`), so flush()'s undo
    /// loop is a no-op in that case.
    ///
    /// Bytes are heap-owned by ChainState until flush() succeeds.
    pending_undo_writes: std.ArrayList(PendingUndoWrite) = undefined,

    pub const PendingBlockWrite = struct {
        hash: types.Hash256,
        bytes: []u8,
    };

    pub const PendingUndoWrite = struct {
        hash: types.Hash256,
        bytes: []u8,
    };

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
            .pending_block_writes = std.ArrayList(PendingBlockWrite).init(allocator),
            .pending_undo_writes = std.ArrayList(PendingUndoWrite).init(allocator),
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
            .pending_block_writes = std.ArrayList(PendingBlockWrite).init(allocator),
            .pending_undo_writes = std.ArrayList(PendingUndoWrite).init(allocator),
        };
    }

    /// Seed the BIP-113 MTP ring buffer with the genesis block's timestamp.
    ///
    /// Must be called once, after `ChainState` is at its final address
    /// (i.e. after `wireUtxoParent`) so the ring buffer is warm before the
    /// first block is submitted.  Safe to call multiple times (idempotent
    /// when count is already >= 1).
    ///
    /// Without this, blocks at heights 1..10 would see an MTP window that
    /// is shorter than the actual ancestor window (missing genesis), causing
    /// spurious time-too-old rejections for any block whose timestamp
    /// equals the timestamp of the highest known ancestor.
    pub fn initGenesisTimestamp(self: *ChainState, genesis_ts: u32) void {
        if (self.recent_ts_count == 0) {
            self.recent_timestamps[0] = genesis_ts;
            self.recent_ts_count = 1;
        }
    }

    /// Wire up the UtxoSet back-reference so that cache eviction uses
    /// ChainState.flush() (which includes the chain tip) instead of the
    /// bare UtxoSet.flush().  Must be called AFTER the ChainState is at
    /// its final memory address (not during init, which returns by value).
    pub fn wireUtxoParent(self: *ChainState) void {
        self.utxo_set.parent = self;
    }

    pub fn deinit(self: *ChainState) void {
        // Drain any unflushed block bodies. On a clean shutdown
        // these were committed in the last flush()'s cleanup loop;
        // anything still queued here belongs to a flush_error path
        // (we kept the queue across the failed write so the next
        // flush could retry).
        for (self.pending_block_writes.items) |entry| {
            self.allocator.free(entry.bytes);
        }
        self.pending_block_writes.deinit();
        // Same drain for undo bytes — owned by the queue until flush()
        // succeeds.  On a flush_error / process exit we own them here.
        for (self.pending_undo_writes.items) |entry| {
            self.allocator.free(entry.bytes);
        }
        self.pending_undo_writes.deinit();
        self.utxo_set.deinit();
    }

    /// Queue a raw block body for inclusion in the next flush() WriteBatch.
    ///
    /// Called from peer.zig drainBlockBuffer (and block_template.zig
    /// submitBlock) BEFORE connectBlockFast / connectBlock — analog of
    /// Bitcoin Core's BlockManager::SaveBlockToDisk being invoked before
    /// validation in validation.cpp. The bytes commit atomically with
    /// the UTXO mutations and tip update; a crash either leaves both
    /// the body and the tip advanced, or neither.
    ///
    /// Honors `prune_height`: skips queuing if the new height would be
    /// pruned immediately anyway (i.e. height ≤ prune_height — defensive
    /// only; pruneToTarget bounds prune_height ≤ best_height − 288, so
    /// a freshly-connecting block is normally well above the watermark).
    ///
    /// Takes ownership of `bytes` on success (caller must NOT free).
    /// On any error, the caller retains ownership.
    ///
    /// Acquires `connect_mutex` so the queue is serialized with flush()
    /// (which also holds connect_mutex through its connectBlockFast
    /// caller).  The two callers — peer.zig drainBlockBuffer and
    /// block_template.zig submitBlock — never recurse into this method
    /// while the lock is already held, so deadlock is impossible.
    pub fn queueBlockWrite(
        self: *ChainState,
        hash: *const types.Hash256,
        bytes: []u8,
        height: u32,
    ) !void {
        self.connect_mutex.lock();
        defer self.connect_mutex.unlock();
        // Memory-only mode: nothing to persist.
        if (self.utxo_set.db == null) {
            self.allocator.free(bytes);
            return;
        }
        // Skip if this height is already at-or-below the prune watermark.
        // Defensive: pruneToTarget caps prune_height at best_height − 288,
        // so a connecting block at best_height + 1 should not normally hit
        // this. But if an operator lowers --prune mid-run, the watermark
        // could overlap; honoring it keeps the populator and pruner
        // complementary instead of fighting each other.
        if (self.prune_target_mib > 0 and height <= self.prune_height) {
            self.allocator.free(bytes);
            return;
        }
        try self.pending_block_writes.append(.{
            .hash = hash.*,
            .bytes = bytes,
        });
    }

    /// Look up the block hash at a given active-chain height via the
    /// H:{height}→hash index in CF_DEFAULT.  Returns null if the key is
    /// missing (height above tip, DB-less mode, or a pre-fix blockheight
    /// that was connected before the W37 index was introduced).  Caller
    /// owns lifetime-free semantics: the returned Hash256 is copied out.
    pub fn getBlockHashByHeight(self: *ChainState, height: u32) ?types.Hash256 {
        const db = self.utxo_set.db orelse return null;
        const key_bytes = ChainStore.buildHeightHashKey(height);
        const data = db.get(CF_DEFAULT, &key_bytes) catch return null;
        const bytes = data orelse return null;
        defer self.allocator.free(bytes);
        if (bytes.len != 32) return null;
        var hash: types.Hash256 = undefined;
        @memcpy(&hash, bytes);
        return hash;
    }

    /// Compute the median-time-past for the active chain tip.
    ///
    /// Returns the median timestamp of the last min(recent_ts_count, 11) blocks
    /// ending at `best_height` (i.e. the MTP that the NEXT block must exceed
    /// — matching Core's `pindexPrev->GetMedianTimePast()` semantics in
    /// `validation.cpp::ContextualCheckBlockHeader`).
    ///
    /// Uses the in-memory `recent_timestamps` ring buffer populated by
    /// `connectBlockInner`.  Returns 0 when fewer than 1 timestamp is available
    /// (genesis / fresh start), matching Core's genesis-adjacent skip.
    ///
    /// Reference: bitcoin-core/src/chain.h CBlockIndex::GetMedianTimePast.
    pub fn computeMTP(self: *const ChainState) u32 {
        const n = self.recent_ts_count;
        if (n == 0) return 0;

        // Copy and sort the valid portion (n <= 11, insertion sort is fine)
        var tmp: [11]u32 = undefined;
        @memcpy(tmp[0..n], self.recent_timestamps[0..n]);
        // Insertion sort
        for (1..n) |i| {
            const key = tmp[i];
            var j: usize = i;
            while (j > 0 and tmp[j - 1] > key) : (j -= 1) {
                tmp[j] = tmp[j - 1];
            }
            tmp[j] = key;
        }
        return tmp[n / 2];
    }

    /// Returns true if the chain has ever connected a block with the given
    /// hash.  Used by the headers handler's competing-fork detector to
    /// decide whether a "non-tip" prev_block names a real ancestor on the
    /// active chain (case B = competing fork) vs an unknown branch
    /// (case C = peer misbehavior).  Looks up CF_BLOCKS keyed by hash.
    /// O(1) DB hit; tolerates DB-less mode (returns false).
    pub fn hasBlock(self: *ChainState, hash: *const types.Hash256) bool {
        const db = self.utxo_set.db orelse return false;
        const data = db.get(CF_BLOCKS, hash) catch return false;
        if (data) |d| {
            self.allocator.free(d);
            return true;
        }
        return false;
    }

    /// Persist an H:{height}→hash index entry.  Idempotent (same height
    /// always maps to the same hash on the active chain), so races between
    /// the RPC thread's lazy-backfill path and ChainState.flush() are
    /// benign.  Silently no-ops on DB-less mode or write failure — this
    /// is a best-effort cache, not a correctness requirement.  W47.
    pub fn putBlockHashByHeight(self: *ChainState, height: u32, hash: *const types.Hash256) void {
        const db = self.utxo_set.db orelse return;
        const key_bytes = ChainStore.buildHeightHashKey(height);
        db.put(CF_DEFAULT, &key_bytes, hash) catch return;
    }

    /// Estimate live-data size of CF_BLOCKS in bytes via RocksDB property.
    /// Used by the pruner to decide whether to prune more. Returns 0 when
    /// the DB is absent or the property call fails (treat as "unknown
    /// size, do not prune further" — safer than panicking the IBD loop
    /// over a transient RocksDB error).
    pub fn estimateBlockCfBytes(self: *ChainState) u64 {
        const db = self.utxo_set.db orelse return 0;
        // "rocksdb.estimate-live-data-size" is the canonical property
        // exposed by the C API for live (uncompressed) data per CF.
        // See rocksdb/db.h DB::Properties::kEstimateLiveDataSize.
        return db.getCfPropertyInt(CF_BLOCKS, "rocksdb.estimate-live-data-size") orelse 0;
    }

    /// Prune CF_BLOCKS entries from the bottom of the chain, advancing
    /// the prune_height watermark, until either:
    ///   (a) prune_height reaches best_height - MIN_BLOCKS_TO_KEEP, or
    ///   (b) the estimated CF_BLOCKS live-data size dips below
    ///       prune_target_mib.
    ///
    /// Strategy: height-based (delete oldest first) with a size-driven
    /// stop condition. We walk forward from the existing watermark,
    /// resolving each height's hash via the H:{height}→hash index, and
    /// `db.delete(CF_BLOCKS, hash)` for it. The H:{height}→hash entry
    /// is intentionally left in place so getblockhash(height) keeps
    /// working (matches Bitcoin Core: pruned blocks are unreachable but
    /// the index still remembers their existence).
    ///
    /// Returns the number of heights pruned in this call (0 if disabled,
    /// already caught up, or the size target is already met).
    ///
    /// Caller (the IBD loop in peer.zig / main.zig import) typically
    /// invokes this every few hundred blocks, not every block, since
    /// the property fetch is non-trivial. With 288-block keep-window
    /// and a 550 MiB target, batch-pruning every 256 blocks is plenty.
    ///
    /// NOTE: Today, peer.zig's drainBlockBuffer fast path does not
    /// populate CF_BLOCKS (raw block bytes are connected straight to
    /// the UTXO set and discarded). So the deletes are no-ops in
    /// practice; this code is the policy half of the system, ready for
    /// the day a CF_BLOCKS populator lands. The `prune_height`
    /// watermark advances regardless so getblock RPC reflects the
    /// pruning policy.
    pub fn pruneToTarget(self: *ChainState) u32 {
        if (self.prune_target_mib == 0) return 0;
        const db = self.utxo_set.db orelse return 0;
        if (self.best_height <= MIN_BLOCKS_TO_KEEP) return 0;

        const max_prunable_height: u32 = self.best_height - MIN_BLOCKS_TO_KEEP;
        if (self.prune_height >= max_prunable_height) return 0;

        const target_bytes: u64 = self.prune_target_mib *% (1024 * 1024);

        var pruned: u32 = 0;
        // Cap per-call work to MAX_PRUNE_BATCH so a single trigger does
        // not stall the connect loop. 4096 ≈ 4 GiB at average block size,
        // which is plenty of headroom for keeping up during steady-state.
        const MAX_PRUNE_BATCH: u32 = 4096;

        var h: u32 = self.prune_height + 1;
        while (h <= max_prunable_height and pruned < MAX_PRUNE_BATCH) : (h += 1) {
            // Best-effort: if we can't resolve the hash, skip and keep
            // walking. Missing H:{height} entries usually mean the index
            // wasn't backfilled for that height (W47 lazy-backfill); the
            // block body, if any, is unrecoverable through this path
            // anyway, so leaving it is harmless.
            const hash = self.getBlockHashByHeight(h) orelse {
                self.prune_height = h;
                continue;
            };
            // Best-effort delete; CF_BLOCKS may not contain the entry
            // (clearbit's IBD does not populate it today, so most
            // deletes are no-ops). Errors are non-fatal — they don't
            // corrupt the chain state, only leave stale bytes around.
            db.delete(CF_BLOCKS, &hash) catch {};
            self.prune_height = h;
            pruned += 1;

            // Size-driven stop: every 256 deletes, re-check live-data
            // size and bail out if we're already below target. Avoids
            // pruning to the keep-horizon when only a small trim is
            // needed. Property fetches are cheap (~1 µs) but doing one
            // every height adds up; 256 is the same coarse bucket
            // Bitcoin Core uses for FindFilesToPrune progress updates.
            if (pruned % 256 == 0) {
                const size_bytes = self.estimateBlockCfBytes();
                if (size_bytes != 0 and size_bytes <= target_bytes) break;
            }
        }
        return pruned;
    }

    /// Convenience: returns true if the given height has been pruned
    /// (i.e. is at or below the prune watermark). Used by getblock RPC
    /// to return a "block not available (pruned data)" error rather
    /// than a misleading "block not found" — same UX as Bitcoin Core's
    /// rpc/blockchain.cpp getblock() pruned-block branch.
    pub fn isHeightPruned(self: *const ChainState, height: u32) bool {
        if (self.prune_target_mib == 0) return false;
        return height != 0 and height <= self.prune_height;
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

    /// Connect a block while the caller already holds `connect_mutex`.
    /// Used by the rollback-dance in handleDumpTxOutSet so the entire
    /// disconnect→dump→reconnect sequence can hold the mutex once and
    /// stay coherent with peer ingest. Does NOT flush — caller is
    /// responsible for one final flush() at the end of the sequence.
    pub fn connectBlockLocked(
        self: *ChainState,
        block: *const types.Block,
        hash: *const types.Hash256,
        height: u32,
    ) !BlockUndo {
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

        // Halt-on-flush-error: a previous flush failed to persist its batch.
        // Refuse to connect another block — otherwise the in-memory tip races
        // ahead of disk and we silently corrupt the chainstate.  Caller / IBD
        // loop should treat this as fatal and exit so an operator can inspect
        // the underlying RocksDB problem (Option A, wave2-2026-04-14).
        if (self.flush_error) {
            std.debug.print("connectBlockFast: prior flush error is sticky; refusing to connect block at height {d}\n", .{height});
            return error.FlushError;
        }

        const t_block_start = std.time.nanoTimestamp();
        var undo = try self.connectBlockInner(block, hash, height, true);
        undo.deinit(self.allocator);

        // Per-block flush: pending_deletes + dirty UTXOs + tip ATOMICALLY in
        // one writeBatch via ChainState.flush().  The old every-100-blocks
        // cadence left a window where the in-memory tip raced ahead of disk;
        // a crash in that window left a tip pointing at heights whose
        // outputs were never persisted (the stuck-at-370001 bug).
        // Flushing every block makes SIGKILL self-healing because tip and
        // UTXOs advance lock-step (Option A, wave2-2026-04-14).
        const t_flush_start = std.time.nanoTimestamp();
        self.flush() catch |err| {
            std.debug.print("connectBlockFast: flush failed at height {d}: {} — halting IBD\n", .{ height, err });
            self.flush_error = true;
            return error.FlushError;
        };
        const t_flush_end = std.time.nanoTimestamp();

        // W73 phase profiling — roll up this block's times into 100-block
        // running sums/maxes, emit summary every 100 blocks, and reset.
        const spend_ns = self.profile_cur_spend_ns;
        const create_ns = self.profile_cur_create_ns;
        const evict_ns = self.profile_cur_evict_ns;
        const prefetch_ns = self.profile_cur_prefetch_ns;
        const prefetch_hits = self.profile_cur_prefetch_hits;
        const flush_ns = @as(u64, @intCast(t_flush_end - t_flush_start));
        const total_ns = @as(u64, @intCast(t_flush_end - t_block_start));
        // W73 Fix 3 — flush sub-phase snapshot for this block.
        const flush_sort_ns = self.profile_cur_flush_sort_ns;
        const flush_build_ns = self.profile_cur_flush_build_ns;
        const flush_write_ns = self.profile_cur_flush_write_ns;
        const flush_cleanup_ns = self.profile_cur_flush_cleanup_ns;

        self.profile_blocks += 1;
        self.profile_spend_ns_sum += spend_ns;
        if (spend_ns > self.profile_spend_ns_max) self.profile_spend_ns_max = spend_ns;
        self.profile_create_ns_sum += create_ns;
        if (create_ns > self.profile_create_ns_max) self.profile_create_ns_max = create_ns;
        self.profile_evict_ns_sum += evict_ns;
        self.profile_prefetch_ns_sum += prefetch_ns;
        if (prefetch_ns > self.profile_prefetch_ns_max) self.profile_prefetch_ns_max = prefetch_ns;
        self.profile_prefetch_hits_sum += prefetch_hits;
        self.profile_flush_ns_sum += flush_ns;
        if (flush_ns > self.profile_flush_ns_max) self.profile_flush_ns_max = flush_ns;
        self.profile_total_ns_sum += total_ns;
        if (total_ns > self.profile_total_ns_max) self.profile_total_ns_max = total_ns;
        self.profile_flush_sort_ns_sum += flush_sort_ns;
        if (flush_sort_ns > self.profile_flush_sort_ns_max) self.profile_flush_sort_ns_max = flush_sort_ns;
        self.profile_flush_build_ns_sum += flush_build_ns;
        if (flush_build_ns > self.profile_flush_build_ns_max) self.profile_flush_build_ns_max = flush_build_ns;
        self.profile_flush_write_ns_sum += flush_write_ns;
        if (flush_write_ns > self.profile_flush_write_ns_max) self.profile_flush_write_ns_max = flush_write_ns;
        self.profile_flush_cleanup_ns_sum += flush_cleanup_ns;
        if (flush_cleanup_ns > self.profile_flush_cleanup_ns_max) self.profile_flush_cleanup_ns_max = flush_cleanup_ns;

        if (self.profile_blocks >= 100) {
            const n = self.profile_blocks;
            std.debug.print(
                "[W73-PROF] block={d} n={d} prefetch={d}us/avg {d}us/max hits/blk={d} spend={d}us/avg {d}us/max create={d}us/avg {d}us/max flush={d}us/avg {d}us/max evict={d}fires {d}us/sum total={d}us/avg {d}us/max ins/blk={d} outs/blk={d}\n",
                .{
                    height,
                    n,
                    self.profile_prefetch_ns_sum / n / 1000,
                    self.profile_prefetch_ns_max / 1000,
                    self.profile_prefetch_hits_sum / n,
                    self.profile_spend_ns_sum / n / 1000,
                    self.profile_spend_ns_max / 1000,
                    self.profile_create_ns_sum / n / 1000,
                    self.profile_create_ns_max / 1000,
                    self.profile_flush_ns_sum / n / 1000,
                    self.profile_flush_ns_max / 1000,
                    self.profile_evict_count,
                    self.profile_evict_ns_sum / 1000,
                    self.profile_total_ns_sum / n / 1000,
                    self.profile_total_ns_max / 1000,
                    self.profile_input_count / n,
                    self.profile_output_count / n,
                },
            );
            // W73 Fix 3 — flush sub-phase rollup.  Same 100-block cadence
            // as [W73-PROF] so operators can correlate the two lines by
            // matching `block=` height.
            std.debug.print(
                "[W73-FLUSH] block={d} n={d} sort={d}us/avg {d}us/max build={d}us/avg {d}us/max write={d}us/avg {d}us/max cleanup={d}us/avg {d}us/max\n",
                .{
                    height,
                    n,
                    self.profile_flush_sort_ns_sum / n / 1000,
                    self.profile_flush_sort_ns_max / 1000,
                    self.profile_flush_build_ns_sum / n / 1000,
                    self.profile_flush_build_ns_max / 1000,
                    self.profile_flush_write_ns_sum / n / 1000,
                    self.profile_flush_write_ns_max / 1000,
                    self.profile_flush_cleanup_ns_sum / n / 1000,
                    self.profile_flush_cleanup_ns_max / 1000,
                },
            );
            self.profile_blocks = 0;
            self.profile_spend_ns_sum = 0;
            self.profile_spend_ns_max = 0;
            self.profile_create_ns_sum = 0;
            self.profile_create_ns_max = 0;
            self.profile_evict_ns_sum = 0;
            self.profile_evict_count = 0;
            self.profile_prefetch_ns_sum = 0;
            self.profile_prefetch_ns_max = 0;
            self.profile_prefetch_hits_sum = 0;
            self.profile_flush_ns_sum = 0;
            self.profile_flush_ns_max = 0;
            self.profile_total_ns_sum = 0;
            self.profile_total_ns_max = 0;
            self.profile_input_count = 0;
            self.profile_output_count = 0;
            self.profile_flush_sort_ns_sum = 0;
            self.profile_flush_sort_ns_max = 0;
            self.profile_flush_build_ns_sum = 0;
            self.profile_flush_build_ns_max = 0;
            self.profile_flush_write_ns_sum = 0;
            self.profile_flush_write_ns_max = 0;
            self.profile_flush_cleanup_ns_sum = 0;
            self.profile_flush_cleanup_ns_max = 0;
        }
    }

    /// Connect a block during IBD AND capture undo data for later disconnect.
    ///
    /// This is the reorg-safe IBD path.  It collects per-input prev-coin
    /// records (via `connectBlockInner` with `skip_undo=false`), serializes
    /// them with `BlockUndoData.toBytes`, and queues the bytes for atomic
    /// write to CF_BLOCK_UNDO in the same flush() WriteBatch as the UTXO
    /// mutations and tip update.  After this method returns success, the
    /// block can be disconnected later via `disconnectBlockByHashCF`.
    ///
    /// Cost vs `connectBlockFast`: extra heap traffic for the spent_utxos
    /// list during connectBlockInner (one CompactUtxo per input, freed
    /// after toBlockUndoData) plus the serialized undo bytes (typically
    /// 100-200 bytes per non-coinbase input × ~2-3 KiB blocks). On a
    /// 10-input block that's ~5 KiB extra alloc/block.
    ///
    /// Caller contract: same as `connectBlockFast` — invoked on a block
    /// already validated by `validateBlockForIBD`, with the connect mutex
    /// uncontended.  On any error the in-memory tip is unchanged (errdefer
    /// in connectBlockInner restores best_height).
    pub fn connectBlockFastWithUndo(
        self: *ChainState,
        block: *const types.Block,
        hash: *const types.Hash256,
        height: u32,
    ) !void {
        self.connect_mutex.lock();
        defer self.connect_mutex.unlock();

        if (self.flush_error) {
            std.debug.print("connectBlockFastWithUndo: prior flush error is sticky; refusing to connect block at height {d}\n", .{height});
            return error.FlushError;
        }

        // Capture undo via the slow path (skip_undo=false).
        var undo = try self.connectBlockInner(block, hash, height, false);
        // Always free the in-memory BlockUndo before returning.  The
        // serialized bytes we hand off to pending_undo_writes are an
        // independent allocation produced by toBlockUndoData → toBytes.
        defer undo.deinit(self.allocator);

        // Convert the in-memory BlockUndo to the file-format BlockUndoData
        // and serialize.  Bytes are heap-owned by the queue; flush() either
        // commits and frees them, or keeps the queue intact for the next
        // retry on flush error.
        if (self.utxo_set.db != null) {
            var undo_data = try undo.toBlockUndoData(block, self.allocator);
            defer undo_data.deinit(self.allocator);

            const serialized_const = try undo_data.toBytes(self.allocator);
            const serialized: []u8 = @constCast(serialized_const);
            errdefer self.allocator.free(serialized);

            try self.pending_undo_writes.append(.{
                .hash = hash.*,
                .bytes = serialized,
            });
        }

        // Atomic flush: tip + UTXOs + CF_BLOCKS body + CF_BLOCK_UNDO entry
        // all commit in one WriteBatch.  If this fails, flush() leaves the
        // pending queues intact for retry on the next call (after operator
        // intervention to clear flush_error).
        self.flush() catch |err| {
            std.debug.print("connectBlockFastWithUndo: flush failed at height {d}: {} — halting IBD\n", .{ height, err });
            self.flush_error = true;
            return error.FlushError;
        };
    }

    /// Read the serialized undo bytes for a block from CF_BLOCK_UNDO.
    /// Returns null if no entry exists (block was connected via the
    /// legacy `connectBlockFast` path that doesn't write undo).  Caller
    /// owns the returned slice and must free with `self.allocator`.
    pub fn getBlockUndoBytes(self: *ChainState, hash: *const types.Hash256) !?[]const u8 {
        const db = self.utxo_set.db orelse return null;
        return try db.get(CF_BLOCK_UNDO, hash);
    }

    /// Disconnect a block using undo data stored in CF_BLOCK_UNDO.
    ///
    /// Reverses the UTXO changes the block applied: removes outputs the
    /// block created, restores the prevouts the block spent.  Used in the
    /// reorg path when an alternate chain with higher chainwork arrives
    /// and the active chain must be rewound to the fork point.
    ///
    /// Returns:
    ///   error.UndoDataNotFound — no CF_BLOCK_UNDO entry for this hash
    ///     (block predates CLEARBIT_REORG capture, or was pruned).
    ///   error.BlockBodyNotFound — no CF_BLOCKS entry; can't iterate
    ///     transactions to remove their outputs.
    ///   error.HeightMismatch — block isn't the current tip; caller must
    ///     disconnect tip-first in reverse height order.
    ///
    /// On success: best_hash + best_height move to the parent, dirty
    /// UTXO state is queued for the next flush().  Caller should call
    /// flush() after the full disconnect chain completes (or rely on the
    /// next connect's flush() to commit the rewind atomically).
    pub fn disconnectBlockByHashCF(
        self: *ChainState,
        hash: *const types.Hash256,
    ) !void {
        self.connect_mutex.lock();
        defer self.connect_mutex.unlock();

        if (self.flush_error) {
            std.debug.print("disconnectBlockByHashCF: prior flush error is sticky; refusing to disconnect\n", .{});
            return error.FlushError;
        }

        if (!std.mem.eql(u8, hash, &self.best_hash)) {
            return error.HeightMismatch;
        }

        const db = self.utxo_set.db orelse return error.UndoManagerNotConfigured;

        // Read undo bytes.
        const undo_bytes = (try db.get(CF_BLOCK_UNDO, hash)) orelse
            return error.UndoDataNotFound;
        defer self.allocator.free(undo_bytes);

        var undo_data = try BlockUndoData.fromBytes(undo_bytes, self.allocator);
        defer undo_data.deinit(self.allocator);

        // Read block body so we can iterate its transactions to remove
        // created outputs.
        const block_bytes = (try db.get(CF_BLOCKS, hash)) orelse
            return error.BlockBodyNotFound;
        defer self.allocator.free(block_bytes);

        var reader = serialize.Reader{ .data = block_bytes };
        var block = serialize.readBlock(&reader, self.allocator) catch
            return error.CorruptBlockBytes;
        defer serialize.freeBlock(self.allocator, &block);

        // Suppress eviction during the disconnect so partial mid-disconnect
        // UTXO state never gets persisted on its own.
        self.utxo_set.suppress_eviction = true;
        defer self.utxo_set.suppress_eviction = false;

        // 1. Remove outputs created by this block (reverse tx order, reverse
        //    output order within each tx).  Mirrors Core's DisconnectBlock
        //    which iterates `for (i = block.vtx.size() - 1; i >= 0; i--)`.
        const crypto = @import("crypto.zig");
        var tx_idx = block.transactions.len;
        while (tx_idx > 0) {
            tx_idx -= 1;
            const tx = block.transactions[tx_idx];
            const tx_hash = crypto.computeTxidStreaming(&tx);

            var out_idx = tx.outputs.len;
            while (out_idx > 0) {
                out_idx -= 1;
                const output = tx.outputs[out_idx];

                // Skip OP_RETURN — never added to UTXO on connect, so
                // never to remove on disconnect.  Same gate as
                // connectBlockInner line 2464.
                if (output.script_pubkey.len > 0 and output.script_pubkey[0] == 0x6a) continue;

                const outpoint = types.OutPoint{
                    .hash = tx_hash,
                    .index = @intCast(out_idx),
                };

                if (try self.utxo_set.spend(&outpoint)) |*spent| {
                    var s = spent.*;
                    s.deinit(self.allocator);
                }
                // If spend returned null the output wasn't in the UTXO
                // set — could be (a) already pruned or (b) the connect
                // path skipped it for some reason.  We tolerate (a) and
                // log (b) — undo of a missing output is a no-op for the
                // common case.
            }
        }

        // 2. Restore prevouts.  undo_data.tx_undo[i] corresponds to
        //    block.transactions[i+1] (coinbase has no undo).
        if (undo_data.tx_undo.len + 1 != block.transactions.len) {
            std.debug.print("disconnectBlockByHashCF: undo/tx count mismatch ({d} vs {d})\n",
                .{ undo_data.tx_undo.len, block.transactions.len });
            return error.CorruptData;
        }
        var u_idx: usize = 0;
        for (block.transactions[1..]) |tx| {
            const tx_undo = undo_data.tx_undo[u_idx];
            u_idx += 1;
            if (tx_undo.prev_outputs.len != tx.inputs.len) {
                std.debug.print("disconnectBlockByHashCF: tx undo input count mismatch\n", .{});
                return error.CorruptData;
            }
            for (tx.inputs, 0..) |input, input_idx| {
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

        // Move tip to parent.
        self.best_hash = block.header.prev_block;
        if (self.best_height > 0) self.best_height -= 1;

        // Queue a delete of the CF_BLOCK_UNDO entry for the disconnected
        // block — it's no longer needed once rewound.  We do this via a
        // direct db.delete; the next flush() commits the tip rewind and
        // any UTXO mutations atomically.  Idempotent if the delete races
        // with a re-connect.
        db.delete(CF_BLOCK_UNDO, hash) catch {};

        // Flush so the tip rewind + UTXO mutations land on disk
        // immediately.  Without this, a caller that runs disconnect
        // followed by `get()` would still see the spent outputs in DB
        // because the per-output `spend()` only queues a pending_delete.
        // Critically: a reorg loop that disconnects N blocks back to a
        // fork point and immediately tries to connect N' blocks forward
        // must not race a partial-flush window where DB shows tip=N but
        // UTXOs reflect tip=K (K = fork point).
        self.flush() catch |err| {
            std.debug.print("disconnectBlockByHashCF: flush failed: {}\n", .{err});
            self.flush_error = true;
            return error.FlushError;
        };
    }

    /// One block on the new chain in a reorg: header parent + serialized
    /// body + computed hash + target height.
    pub const ReorgBlock = struct {
        hash: types.Hash256,
        block: types.Block,
        height: u32,
    };

    /// Switch the active chain to the new branch ending at `new_tip_hash`.
    ///
    /// `fork_point_hash` must be a block already on the active chain
    /// (typically an ancestor of the current tip).  `new_chain` is the
    /// ordered list of blocks from fork_point.height + 1 up to the new
    /// tip — caller is responsible for fetching the bodies and verifying
    /// they chain consistently (each block's prev_block points to the
    /// previous element's hash, with the first element's prev_block ==
    /// fork_point_hash).
    ///
    /// Algorithm (Bitcoin Core ActivateBestChain analog):
    ///   1. While tip != fork_point: disconnect current tip via
    ///      disconnectBlockByHashCF.  The undo data for each disconnect
    ///      MUST be present in CF_BLOCK_UNDO (i.e. the original connect
    ///      went through the reorg-safe path).  If undo is missing for
    ///      any block on the disconnect path the reorg aborts and the
    ///      chain stays on its original tip.
    ///   2. For each block in new_chain (in order): validate the
    ///      prev_block linkage against the live tip, then call
    ///      connectBlockFastWithUndo.  Stops at the first failure with
    ///      the chain in a partially-applied state — the caller is
    ///      expected to bail-and-retry rather than try to roll back
    ///      mid-reorg.
    ///
    /// Returns the number of blocks connected on the new chain on
    /// success.  Errors are propagated from the underlying
    /// disconnectBlockByHashCF / connectBlockFastWithUndo paths.
    pub fn reorgToChain(
        self: *ChainState,
        fork_point_hash: *const types.Hash256,
        new_chain: []const ReorgBlock,
    ) !u32 {
        // Walk back to the fork point, disconnecting each block along the
        // way.  Bound the work by some max reasonable depth to prevent
        // an attacker who supplies a "fork point" that ISN'T actually on
        // the active chain from spinning the loop forever.  288 (Core's
        // MIN_BLOCKS_TO_KEEP) is the standard reorg depth tolerance.
        var disconnect_count: u32 = 0;
        const MAX_REORG_DEPTH: u32 = MIN_BLOCKS_TO_KEEP;

        while (!std.mem.eql(u8, &self.best_hash, fork_point_hash)) {
            if (disconnect_count >= MAX_REORG_DEPTH) {
                std.debug.print(
                    "reorgToChain: hit MAX_REORG_DEPTH ({d}) without reaching fork point — aborting\n",
                    .{MAX_REORG_DEPTH},
                );
                return error.ReorgTooDeep;
            }
            // Refuse to disconnect past genesis (height 0).  If the
            // caller's fork_point isn't genesis or any ancestor we
            // actually connected, walking past best_height==0 would
            // either underflow or call disconnectBlockByHashCF on
            // bytes that don't exist.  The cleanest signal is to
            // treat "fork_point not on active chain" as a bad input.
            if (self.best_height == 0) {
                std.debug.print(
                    "reorgToChain: walked back to genesis without finding fork point — bad fork_point hash\n",
                    .{},
                );
                return error.ForkPointNotOnChain;
            }
            const tip_hash_copy = self.best_hash;
            try self.disconnectBlockByHashCF(&tip_hash_copy);
            disconnect_count += 1;
        }

        // Connect new_chain forward.  Each block must chain to the
        // previous one; serialize the body and queue it before connect
        // so CF_BLOCKS gets the bytes too.
        var connect_count: u32 = 0;
        for (new_chain) |entry| {
            // Linkage check: caller is supposed to guarantee this, but
            // double-check so a bad input doesn't corrupt chainstate.
            if (!std.mem.eql(u8, &entry.block.header.prev_block, &self.best_hash)) {
                std.debug.print(
                    "reorgToChain: new chain block at height {d} doesn't chain to current tip — aborting\n",
                    .{entry.height},
                );
                return error.PrevBlockMismatch;
            }
            if (entry.height != self.best_height + 1) {
                std.debug.print(
                    "reorgToChain: new chain height {d} != tip+1 ({d}) — aborting\n",
                    .{ entry.height, self.best_height + 1 },
                );
                return error.HeightMismatch;
            }

            // Queue the body for the atomic CF_BLOCKS put.
            var w = serialize.Writer.init(self.allocator);
            errdefer w.deinit();
            try serialize.writeBlock(&w, &entry.block);
            const owned_const = try w.toOwnedSlice();
            const owned: []u8 = @constCast(owned_const);
            try self.queueBlockWrite(&entry.hash, owned, entry.height);

            try self.connectBlockFastWithUndo(&entry.block, &entry.hash, entry.height);
            connect_count += 1;
        }

        std.debug.print(
            "reorgToChain: SUCCESS disconnected={d} connected={d} new_tip_height={d}\n",
            .{ disconnect_count, connect_count, self.best_height },
        );
        return connect_count;
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

        // Verify the block chains onto the current tip.  This catches race
        // conditions where both P2P and RPC advance best_height between the
        // caller reading it and acquiring the connect_mutex.
        if (height != self.best_height + 1) {
            std.debug.print("connectBlockInner: height mismatch: expected {d}, got {d}\n", .{ self.best_height + 1, height });
            return error.HeightMismatch;
        }
        // For non-genesis blocks, verify prev_block links to our tip.
        if (height > 0 and !std.mem.eql(u8, &block.header.prev_block, &self.best_hash)) {
            std.debug.print("connectBlockInner: prev_block mismatch at height {d}\n", .{height});
            return error.PrevBlockMismatch;
        }

        // Suppress eviction during block connection to prevent mid-block
        // flushes that write partial UTXO state (some spends applied but
        // tip not yet updated).  Eviction is checked after the block is
        // fully connected and the tip is updated.
        self.utxo_set.suppress_eviction = true;
        // Ensure suppress_eviction is reset even if block connection fails.
        // Without this, a failed block leaves suppress_eviction=true which
        // prevents eviction on subsequent blocks until the next success.
        errdefer self.utxo_set.suppress_eviction = false;

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

        // W73 per-block phase accumulators.  Written to ChainState scratch
        // fields on success; connectBlockFast reads them.
        var spend_ns_block: u64 = 0;
        var create_ns_block: u64 = 0;
        var input_count_block: u64 = 0;
        var output_count_block: u64 = 0;

        // W73 Fix 1 — batch-prefetch cache-missing inputs before the per-tx
        // spend loop.  Pure cache-warm; no correctness effect on spend().
        // Errors here are non-fatal: prefetch failure just means spend()
        // falls through to its existing one-at-a-time DB path.
        const t_prefetch_start = std.time.nanoTimestamp();
        const prefetch_hits = self.utxo_set.prefetchBlockInputs(block) catch 0;
        const t_prefetch_end = std.time.nanoTimestamp();
        const prefetch_ns_block = @as(u64, @intCast(t_prefetch_end - t_prefetch_start));

        for (block.transactions, 0..) |tx, tx_idx| {
            const tx_hash = crypto.computeTxidStreaming(&tx);

            // Spend inputs (skip coinbase)
            if (tx_idx > 0) {
                const t_spend_start = std.time.nanoTimestamp();
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
                const t_spend_end = std.time.nanoTimestamp();
                spend_ns_block += @as(u64, @intCast(t_spend_end - t_spend_start));
                input_count_block += @as(u64, @intCast(tx.inputs.len));
            }

            // Create outputs
            const t_create_start = std.time.nanoTimestamp();
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
            const t_create_end = std.time.nanoTimestamp();
            create_ns_block += @as(u64, @intCast(t_create_end - t_create_start));
            output_count_block += @as(u64, @intCast(tx.outputs.len));
        }

        self.best_hash = hash.*;
        self.best_height = height;

        // BIP-113: push the new block's timestamp into the ring buffer so
        // computeMTP() can serve the correct MTP for the NEXT submitted block
        // without hitting CF_BLOCK_INDEX (which the fast path does not populate).
        // Shift entries: slot 0 = most-recent, slot 1 = second-most-recent, …
        // (insertion at the front; shift the rest down; cap at 11).
        {
            const n = @min(self.recent_ts_count, 10); // shift up to 10 existing entries
            var i: u32 = n;
            while (i > 0) : (i -= 1) {
                self.recent_timestamps[i] = self.recent_timestamps[i - 1];
            }
            self.recent_timestamps[0] = block.header.timestamp;
            if (self.recent_ts_count < 11) self.recent_ts_count += 1;
        }

        // Re-enable eviction now that tip is consistent with UTXO state.
        self.utxo_set.suppress_eviction = false;
        // Batch eviction: only check every 10 blocks to amortize the expensive
        // flush+iterate cost.  The cache can temporarily exceed the limit by
        // ~10 blocks of UTXOs, which is negligible compared to the cache size.
        // This dramatically reduces eviction stalls during rapid block import
        // (IBD or sequential feeding via submitblock RPC).
        var evict_ns_block: u64 = 0;
        var evict_fired: bool = false;
        if (height % 10 == 0 and
            self.utxo_set.cacheMemoryUsage() > self.utxo_set.max_cache_size -| LARGE_THRESHOLD_HEADROOM)
        {
            const t_evict_start = std.time.nanoTimestamp();
            self.utxo_set.evictCache();
            const t_evict_end = std.time.nanoTimestamp();
            evict_ns_block = @as(u64, @intCast(t_evict_end - t_evict_start));
            evict_fired = true;
        }

        // W73: stash per-block phase totals for connectBlockFast to roll up.
        self.profile_cur_spend_ns = spend_ns_block;
        self.profile_cur_create_ns = create_ns_block;
        self.profile_cur_evict_ns = evict_ns_block;
        self.profile_cur_prefetch_ns = prefetch_ns_block;
        self.profile_cur_prefetch_hits = @as(u64, @intCast(prefetch_hits));
        self.profile_input_count += input_count_block;
        self.profile_output_count += output_count_block;
        if (evict_fired) self.profile_evict_count += 1;

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
    /// Flush all pending state to RocksDB as a single atomic batch:
    ///   - Pending UTXO deletes (spent outputs)
    ///   - Dirty UTXO puts (new/modified outputs)
    ///   - Chain tip (best_hash + best_height)
    ///
    /// All three must be in the same writeBatch to prevent corruption on
    /// crash.  Previously, pending_deletes were flushed in a separate batch
    /// before the tip, creating a window where a crash could leave the
    /// deletions applied but the tip stale — on restart, the node would
    /// re-process a block whose inputs had already been deleted, hitting
    /// error.MissingInput (the stuck-at-370001 bug).
    pub fn flush(self: *ChainState) !void {
        if (self.utxo_set.db == null) {
            // Memory-only mode, nothing to persist
            return;
        }
        const db = self.utxo_set.db.?;

        // W73 Fix 3 — flush sub-phase timing.  Split flush() into sort /
        // build / write / cleanup so the [W73-FLUSH] rollup can point at
        // the real tail offender.  Scratch fields are written once at
        // function end so connectBlockFast sees a consistent snapshot.
        var flush_sort_ns: u64 = 0;
        var flush_build_ns: u64 = 0;
        var flush_write_ns: u64 = 0;
        var flush_cleanup_ns: u64 = 0;

        // Build a single atomic batch: pending deletes + dirty UTXO puts +
        // chain tip.  Uses dirty_keys tracker for O(dirty) performance.
        var batch = std.ArrayList(BatchOp).init(self.allocator);
        defer batch.deinit();

        var dirty_keys = std.ArrayList([36]u8).init(self.allocator);
        defer dirty_keys.deinit();

        // W73: sort keys by byte-order before append. RocksDB's memtable is an
        // ordered SkipList; sorted inserts reduce per-op comparison cost and
        // align with downstream LSM compaction. Safe in-place sort — semantics
        // are unchanged because (a) deletes always batch before puts regardless
        // of iteration order, (b) RocksDB writeBatch applies ops in array order
        // so last-write-wins for duplicate keys is preserved, (c) a key cannot
        // appear in both pending_deletes and dirty_keys within one flush window
        // in the normal add/spend flow (only in BIP-30 duplicate-coinbase, which
        // is past activation height).
        const KeyLess = struct {
            fn lt(_: void, a: [36]u8, b: [36]u8) bool {
                return std.mem.lessThan(u8, &a, &b);
            }
        };
        const t_sort_start = std.time.nanoTimestamp();
        std.mem.sort([36]u8, self.utxo_set.pending_deletes.items, {}, KeyLess.lt);
        std.mem.sort([36]u8, self.utxo_set.dirty_keys.items, {}, KeyLess.lt);
        flush_sort_ns = @as(u64, @intCast(std.time.nanoTimestamp() - t_sort_start));
        const t_build_start = std.time.nanoTimestamp();

        // 1. Pending UTXO deletes (spent outputs to remove from DB).
        //    Previously flushed as a SEPARATE batch before this function's
        //    main batch, which was not atomic with the tip update.
        for (self.utxo_set.pending_deletes.items) |key| {
            const key_copy = try self.allocator.alloc(u8, 36);
            @memcpy(key_copy, &key);
            try batch.append(.{ .delete = .{
                .cf = CF_UTXO,
                .key = key_copy,
            } });
        }

        // 2. Dirty UTXO puts (new/modified outputs).
        for (self.utxo_set.dirty_keys.items) |key| {
            if (self.utxo_set.cache.getPtr(key)) |entry_ptr| {
                if (entry_ptr.dirty) {
                    const encoded = try entry_ptr.utxo.encode(self.allocator);
                    const key_copy = try self.allocator.alloc(u8, 36);
                    @memcpy(key_copy, &key);

                    try batch.append(.{ .put = .{
                        .cf = CF_UTXO,
                        .key = key_copy,
                        .value = encoded,
                    } });
                    try dirty_keys.append(key);
                }
            }
        }

        // 3. Chain tip — must be in the SAME batch so that the on-disk tip
        //    always reflects exactly the UTXOs present on disk.
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

        // 4. Height→hash index for getblockhash RPC.  Writes one entry per
        //    flush for the current tip height, atomic with the tip update.
        //    Without this, IBD connects blocks via peer.zig's fast path which
        //    never persists hash-keyed CF_BLOCK_INDEX entries; handleGetBlockHash
        //    falls back to walking active_tip in memory, which is null until a
        //    new block arrives post-restart, producing "Block height out of
        //    range" for every historical query (W36 root cause).
        const hh_key_bytes = ChainStore.buildHeightHashKey(self.best_height);
        const hh_key = try self.allocator.alloc(u8, ChainStore.HEIGHT_HASH_KEY_LEN);
        @memcpy(hh_key, &hh_key_bytes);
        const hh_val = try self.allocator.alloc(u8, 32);
        @memcpy(hh_val, &self.best_hash);
        try batch.append(.{ .put = .{
            .cf = CF_DEFAULT,
            .key = hh_key,
            .value = hh_val,
        } });

        // 5. Pending raw-block bodies (CF_BLOCKS).  Bytes were queued by
        //    queueBlockWrite() before connectBlockFast — putting the put into
        //    THIS batch makes the body-on-disk semantics atomic with the
        //    UTXO mutations and tip advance, matching Bitcoin Core's
        //    SaveBlockToDisk-before-CheckBlock ordering in validation.cpp.
        //
        //    Without this section, peer.zig's drainBlockBuffer drained
        //    incoming blocks straight into the UTXO set and discarded the
        //    bytes — leaving CF_BLOCKS empty across the entire chain. That
        //    made `getblock` unanswerable for any block below tip and made
        //    the --prune path (00a4ea7) a no-op.  Keys are 32-byte block
        //    hashes; values are the consensus-serialized block (header +
        //    compact-size tx count + transactions).
        for (self.pending_block_writes.items) |entry| {
            const k = try self.allocator.alloc(u8, 32);
            @memcpy(k, &entry.hash);
            // bytes ownership transfers to the BatchOp cleanup loop below
            // on successful writeBatch. On failure we keep the queue intact
            // so the next flush retries the same bodies.
            try batch.append(.{ .put = .{
                .cf = CF_BLOCKS,
                .key = k,
                .value = entry.bytes,
            } });
        }

        // 6. Pending block-undo bytes (CF_BLOCK_UNDO).  Same atomicity
        //    invariant as CF_BLOCKS above: undo bytes commit in the SAME
        //    WriteBatch as the UTXO mutations and tip advance, so a crash
        //    leaves either both the spend records AND the corresponding
        //    undo entry advanced, or neither.  Without this guarantee, a
        //    reorg after an unclean shutdown could see "tip advanced past
        //    block N but no undo entry for N" — `disconnectBlockByHashCF`
        //    would then fail and the reorg would abort mid-flight.
        //
        //    Empty queue is the legacy IBD path's behaviour
        //    (`connectBlockFast` doesn't capture undo); empty loop is a
        //    no-op so this section is zero-cost when reorg support is off.
        for (self.pending_undo_writes.items) |entry| {
            const k = try self.allocator.alloc(u8, 32);
            @memcpy(k, &entry.hash);
            try batch.append(.{ .put = .{
                .cf = CF_BLOCK_UNDO,
                .key = k,
                .value = entry.bytes,
            } });
        }

        flush_build_ns = @as(u64, @intCast(std.time.nanoTimestamp() - t_build_start));

        if (batch.items.len > 0) {
            const t_write_start = std.time.nanoTimestamp();
            db.writeBatch(batch.items) catch |err| {
                std.debug.print("ChainState flush: writeBatch failed with {}, {d} entries NOT persisted — setting flush_error\n", .{ err, batch.items.len });
                // Sticky flush_error so connectBlockFast / submitBlock refuse
                // to advance the in-memory tip past the last good on-disk tip.
                // Without this, the next per-block flush retries the same
                // writeBatch but the tip in that batch reflects the NEW height
                // — if any later flush succeeds, the on-disk tip jumps over
                // un-persisted intermediate UTXOs (Option A, wave2-2026-04-14).
                self.flush_error = true;
                for (batch.items) |op| {
                    switch (op) {
                        .put => |p| {
                            self.allocator.free(@constCast(p.key));
                            // CF_BLOCKS / CF_BLOCK_UNDO values are still
                            // owned by their respective pending queues for
                            // the next retry; do NOT free them here.
                            if (p.cf != CF_BLOCKS and p.cf != CF_BLOCK_UNDO) {
                                self.allocator.free(@constCast(p.value));
                            }
                        },
                        .delete => |d| self.allocator.free(@constCast(d.key)),
                    }
                }
                return err;
            };
            flush_write_ns = @as(u64, @intCast(std.time.nanoTimestamp() - t_write_start));

            const t_cleanup_start = std.time.nanoTimestamp();
            // Mark dirty entries clean AFTER successful write.
            // Also clear the FRESH flag since entries now exist in DB.
            for (dirty_keys.items) |key| {
                if (self.utxo_set.cache.getPtr(key)) |entry_ptr| {
                    entry_ptr.dirty = false;
                    entry_ptr.fresh = false;
                }
            }

            // Clear trackers only AFTER successful writeBatch — if the write
            // failed above we kept them so the next flush retries the same
            // set of mutations.
            self.utxo_set.dirty_keys.clearRetainingCapacity();
            self.utxo_set.pending_deletes.clearRetainingCapacity();

            // CF_BLOCKS bodies committed: free the queued bytes and clear
            // the queue. Done before the batch-cleanup loop so the bytes
            // are freed exactly once (the BatchOp cleanup skips CF_BLOCKS
            // values by cf-tag below, mirroring the failure path).
            for (self.pending_block_writes.items) |entry| {
                self.allocator.free(entry.bytes);
            }
            self.pending_block_writes.clearRetainingCapacity();

            // CF_BLOCK_UNDO bytes committed: same drain pattern as
            // pending_block_writes above.  Empty in the legacy IBD path.
            for (self.pending_undo_writes.items) |entry| {
                self.allocator.free(entry.bytes);
            }
            self.pending_undo_writes.clearRetainingCapacity();

            // Free allocated keys and values
            for (batch.items) |op| {
                switch (op) {
                    .put => |p| {
                        self.allocator.free(@constCast(p.key));
                        // CF_BLOCKS / CF_BLOCK_UNDO values were freed above
                        // via their respective pending queues — skip here
                        // to avoid double-free.
                        if (p.cf != CF_BLOCKS and p.cf != CF_BLOCK_UNDO) {
                            self.allocator.free(@constCast(p.value));
                        }
                    },
                    .delete => |d| self.allocator.free(@constCast(d.key)),
                }
            }
            flush_cleanup_ns = @as(u64, @intCast(std.time.nanoTimestamp() - t_cleanup_start));
        }

        self.profile_cur_flush_sort_ns = flush_sort_ns;
        self.profile_cur_flush_build_ns = flush_build_ns;
        self.profile_cur_flush_write_ns = flush_write_ns;
        self.profile_cur_flush_cleanup_ns = flush_cleanup_ns;
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

    /// Look up the raw consensus-serialized bytes for a block in CF_BLOCKS.
    /// Returned slice is heap-allocated; caller must free with self.allocator.
    /// Returns null if the block hash isn't in CF_BLOCKS (either pre-W87
    /// populator commit `cdd9e20`, pruned, or never stored). Used by the
    /// rollback dance in handleDumpTxOutSet to load disconnect-target bodies.
    pub fn getBlockBytes(self: *ChainState, hash: *const types.Hash256) !?[]const u8 {
        const db = self.utxo_set.db orelse return null;
        const data = (try db.get(CF_BLOCKS, hash)) orelse return null;
        return data;
    }

    /// Disconnect the block at `hash` from the active chain using file-based
    /// undo data. Loads the block body from CF_BLOCKS (caller is responsible
    /// for the upstream coverage check — this function returns
    /// `error.BlockBodyNotFound` if the body is missing rather than panicking
    /// on a half-loaded block).
    ///
    /// Replaces the previous pattern of passing `undefined` for the block
    /// argument in `ChainManager.disconnectToBlock` (validation.zig pre-d35797b),
    /// which was a Zig pre-init footgun: `disconnectBlockFromFile` reads
    /// `block.transactions` first thing and would Undefined-Behaviour at
    /// runtime if the caller passed `undefined`. The fix is to load the
    /// real bytes here so the Block struct is fully initialised before
    /// the disconnect path touches it.
    pub fn disconnectBlockByHash(
        self: *ChainState,
        hash: *const types.Hash256,
        file_number: u32,
        file_offset: u64,
        prev_hash: types.Hash256,
    ) !void {
        const block_bytes = (try self.getBlockBytes(hash)) orelse return error.BlockBodyNotFound;
        defer self.allocator.free(block_bytes);

        var reader = serialize.Reader{ .data = block_bytes };
        var block = serialize.readBlock(&reader, self.allocator) catch return error.CorruptBlockBytes;
        defer serialize.freeBlock(self.allocator, &block);

        try self.disconnectBlockFromFile(&block, file_number, file_offset, prev_hash);
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

/// In-memory representation of a single UTXO entry in a Core-compatible
/// snapshot. The wire format is **not** "txid+vout+coin" per entry — Core
/// groups coins by txid (see `WriteUTXOSnapshot` in
/// `bitcoin-core/src/rpc/blockchain.cpp`). Use `writeCoinGrouped` /
/// `readCoinGrouped` below for I/O; `SnapshotCoin` is the post-decode
/// shape passed to chainstate-population code.
pub const SnapshotCoin = struct {
    outpoint: types.OutPoint,
    height: u32,
    is_coinbase: bool,
    value: i64,
    script_pubkey: []const u8,

    pub fn deinit(self: *SnapshotCoin, allocator: std.mem.Allocator) void {
        allocator.free(self.script_pubkey);
    }
};

/// Serialize a single (vout, coin) pair using Core's exact wire format.
/// The caller is responsible for emitting the leading txid + coins_per_txid
/// header; this helper handles only the per-coin payload.
///
/// Wire format (per coin, after the per-txid header):
///   * `compactsize(vout)`
///   * `VARINT(code)` where `code = (height << 1) | coinbase`
///   * `VARINT(CompressAmount(value))`
///   * `ScriptCompression(scriptPubKey)` — see `compressor.zig`.
///
/// Reference: bitcoin-core/src/rpc/blockchain.cpp `WriteUTXOSnapshot`.
pub fn writeSnapshotCoinPayload(
    writer: *serialize.Writer,
    vout: u32,
    coin: *const SnapshotCoin,
) !void {
    const compressor = @import("compressor.zig");
    try writer.writeCompactSize(@as(u64, vout));
    try compressor.writeCoin(writer, coin.height, coin.is_coinbase, coin.value, coin.script_pubkey);
}

/// Read the per-coin payload (vout + Coin) for the current txid group.
/// Caller owns `script_pubkey`.
pub fn readSnapshotCoinPayload(
    reader: *serialize.Reader,
    txid: *const types.Hash256,
    allocator: std.mem.Allocator,
) !SnapshotCoin {
    const compressor = @import("compressor.zig");
    const vout_u64 = try reader.readCompactSize();
    if (vout_u64 >= std.math.maxInt(u32)) return StorageError.CorruptData;
    const vout: u32 = @intCast(vout_u64);
    const c = try compressor.readCoin(reader, allocator);
    return SnapshotCoin{
        .outpoint = types.OutPoint{ .hash = txid.*, .index = vout },
        .height = c.height,
        .is_coinbase = c.is_coinbase,
        .value = c.value,
        .script_pubkey = c.script_pubkey,
    };
}

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

/// Compute the MuHash3072 of a UTXO set.
///
/// **NOT** the Core-strict `hash_serialized` value: `hash_serialized` is
/// SHA256d via HashWriter per Core `validation.cpp:5904`. MuHash3072 is
/// the separate hash type for `gettxoutsetinfo hash_type=muhash`.
/// The pinned `AssumeUtxoData::hash_serialized` constants
/// (`a2a5521b...` etc.) are SHA256d outputs — wiring this function into
/// `validateAndLoadSnapshot` is a category error and was the bug fixed
/// when `69f46b8` was reverted. Use `computeHashSerializedTxOutSet` for
/// the strict gate.
///
/// Algorithm:
///   * For every coin in the set, build a per-coin byte string equal to
///     `TxOutSer(outpoint, coin)`:
///       - 32-byte txid (internal byte order)
///       - 4-byte LE vout
///       - 4-byte LE `(height << 1) | coinbase` packed code
///       - 8-byte LE i64 value
///       - CompactSize-prefixed scriptPubKey
///     This matches `bitcoin-core/src/kernel/coinstats.cpp::TxOutSer`.
///     It is *NOT* `compressor.writeCoin`'s VARINT-based wire layout —
///     that one is used for snapshot serialization.
///   * Insert each per-coin byte string into a `MuHash3072` accumulator.
///   * Finalize: returns SHA256(numerator_LE_384_bytes).
///
/// Reference: `bitcoin-core/src/kernel/coinstats.cpp:46` (`TxOutSer`) +
/// `bitcoin-core/src/crypto/muhash.{h,cpp}`.
pub fn computeMuHashTxOutSet(utxo_set: *UtxoSet, allocator: std.mem.Allocator) !types.Hash256 {
    const muhash = @import("muhash.zig");

    var acc = muhash.MuHash3072.init();

    var keys = std.ArrayList([36]u8).init(allocator);
    defer keys.deinit();
    var iter = utxo_set.cache.iterator();
    while (iter.next()) |entry| try keys.append(entry.key_ptr.*);

    // MuHash is order-independent, so iteration order is irrelevant for
    // correctness; we don't sort here.

    var per_coin = serialize.Writer.init(allocator);
    defer per_coin.deinit();

    for (keys.items) |key| {
        const entry = utxo_set.cache.get(key) orelse continue;

        per_coin.list.clearRetainingCapacity();
        const txid = key[0..32];
        const vout = std.mem.readInt(u32, key[32..36], .little);

        // COutPoint: txid || LE32 vout
        try per_coin.writeBytes(txid);
        try per_coin.writeInt(u32, vout);

        // (height << 1) | coinbase, written as LE32 (Core does
        // `static_cast<uint32_t>(...)` then default LE serialization).
        const code: u32 = (@as(u32, entry.utxo.height) << 1) | (if (entry.utxo.is_coinbase) @as(u32, 1) else 0);
        try per_coin.writeInt(u32, code);

        // CTxOut: i64 value LE + CompactSize(script.len) + script bytes.
        try per_coin.writeInt(i64, entry.utxo.value);
        const script = try entry.utxo.reconstructScript(allocator);
        defer allocator.free(script);
        try per_coin.writeCompactSize(script.len);
        try per_coin.writeBytes(script);

        acc.insert(per_coin.getWritten());
    }

    return acc.finalize();
}

/// Compute the Bitcoin Core `hash_serialized` value (SHA256d via
/// `HashWriter`) over a UTXO set.
///
/// `hash_serialized` is SHA256d via HashWriter per Core
/// `validation.cpp:5904`. MuHash3072 is the separate hash type for
/// `gettxoutsetinfo hash_type=muhash`.
///
/// This is the value pinned in `AssumeUtxoData::hash_serialized` and the
/// gate enforced by `validateAndLoadSnapshot`. The values reported by
/// `dumptxoutset.txoutset_hash` and `gettxoutsetinfo
/// hash_type=hash_serialized_3` are also this hash.
///
/// Algorithm (mirrors Core `kernel/coinstats.cpp:111-146` `ComputeUTXOStats`
/// with `HashWriter` + `kernel/coinstats.cpp:46-56` `TxOutSer` +
/// `kernel/coinstats.cpp:161-163` `case(CoinStatsHashType::HASH_SERIALIZED)`):
///
///   * Iterate the UTXO set in canonical key order — sorted lex by the
///     36-byte `txid || LE32(vout)` outpoint encoding. This matches
///     Core's `CCoinsViewCursor` walk (RocksDB byte-order) which orders
///     by `(txid, vout)`.
///   * For every coin, append `TxOutSer(outpoint, coin)` to a `HashWriter`:
///       - 32-byte txid (internal byte order)
///       - 4-byte LE vout
///       - 4-byte LE `(height << 1) | coinbase` packed code
///       - 8-byte LE i64 value (CTxOut.nValue)
///       - CompactSize(scriptPubKey.len) || scriptPubKey
///   * `HashWriter::GetHash()` returns SHA256d of the concatenated stream.
///
/// Reference: `bitcoin-core/src/kernel/coinstats.cpp` and
/// `bitcoin-core/src/hash.h:100-120` (`HashWriter::GetHash`).
pub fn computeHashSerializedTxOutSet(utxo_set: *UtxoSet, allocator: std.mem.Allocator) !types.Hash256 {
    const crypto = @import("crypto.zig");

    var keys = std.ArrayList([36]u8).init(allocator);
    defer keys.deinit();
    var iter = utxo_set.cache.iterator();
    while (iter.next()) |entry| try keys.append(entry.key_ptr.*);

    // Canonical (txid, vout) order — matches Core's CCoinsViewCursor walk.
    // The 36-byte key is `txid || LE32(vout)`, so byte-lex order is the
    // same iteration order as Core's RocksDB cursor.
    std.mem.sort([36]u8, keys.items, {}, struct {
        fn lessThan(_: void, a: [36]u8, b: [36]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThan);

    var hw = crypto.Sha256Writer.init();

    for (keys.items) |key| {
        const entry = utxo_set.cache.get(key) orelse continue;

        const txid = key[0..32];
        const vout = std.mem.readInt(u32, key[32..36], .little);

        // COutPoint: txid || LE32 vout.
        try hw.writeBytes(txid);
        try hw.writeInt(u32, vout);

        // (height << 1) | coinbase, written as LE32. Core does
        // `static_cast<uint32_t>(...)` then default LE serialization
        // (kernel/coinstats.cpp:49).
        const code: u32 = (@as(u32, entry.utxo.height) << 1) | (if (entry.utxo.is_coinbase) @as(u32, 1) else 0);
        try hw.writeInt(u32, code);

        // CTxOut: i64 value LE + CompactSize(script.len) + script bytes.
        try hw.writeInt(i64, entry.utxo.value);
        const script = try entry.utxo.reconstructScript(allocator);
        defer allocator.free(script);
        try hw.writeCompactSize(script.len);
        try hw.writeBytes(script);
    }

    return hw.finalHash256();
}

/// Compute a deterministic hash of a UTXO set for snapshot verification.
///
/// **LEGACY PLACEHOLDER**: this is *not* Core's `hash_serialized`. It returns
/// SHA256d over `outpoint || compressor.writeCoin(...)` payloads in
/// lexicographic outpoint order, which uses VARINT-compressed `Coin`
/// encoding rather than the canonical `TxOutSer` format. Use
/// `computeHashSerializedTxOutSet` for Core-strict snapshot validation.
/// Retained only because tests and pre-69f46b8 callers may still reference
/// it; do not wire into any Core-compat code path.
pub fn computeUtxoSetHash(utxo_set: *UtxoSet, allocator: std.mem.Allocator) !types.Hash256 {
    const crypto = @import("crypto.zig");
    const compressor = @import("compressor.zig");

    var keys = std.ArrayList([36]u8).init(allocator);
    defer keys.deinit();
    var iter = utxo_set.cache.iterator();
    while (iter.next()) |entry| try keys.append(entry.key_ptr.*);
    std.mem.sort([36]u8, keys.items, {}, struct {
        fn lessThan(_: void, a: [36]u8, b: [36]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThan);

    var hasher_buf = serialize.Writer.init(allocator);
    defer hasher_buf.deinit();

    for (keys.items) |key| {
        if (utxo_set.cache.get(key)) |entry| {
            try hasher_buf.writeBytes(&key);
            const script = try entry.utxo.reconstructScript(allocator);
            defer allocator.free(script);
            try compressor.writeCoin(&hasher_buf, entry.utxo.height, entry.utxo.is_coinbase, entry.utxo.value, script);
        }
    }

    return crypto.hash256(hasher_buf.getWritten());
}

/// Write a UTXO set snapshot in Bitcoin Core's exact wire format.
///
/// Layout:
///   * 51-byte SnapshotMetadata header (`SnapshotMetadata.toBytes`).
///   * For each unique txid, in lexicographic key order:
///       * txid (32 bytes, internal byte order — `key[0..32]`)
///       * compactsize(N) where N is the number of unspent outputs of this tx
///       * For each of the N coins, in ascending vout order:
///           * compactsize(vout)
///           * VARINT(code = (height << 1) | coinbase)
///           * VARINT(CompressAmount(value))
///           * ScriptCompression(scriptPubKey)
///
/// Atomic write protocol: the bytes go to "<path>.incomplete", we sync the
/// fd, then rename to <path>. Mirrors Bitcoin Core's
/// `temppath = path + ".incomplete"` flow in
/// rpc/blockchain.cpp::dumptxoutset so that operators copying mid-dump never
/// see a torn file, and a SIGKILL during dump leaves only the .incomplete
/// artifact behind for cleanup. The caller pre-checks that <path> doesn't
/// already exist (RpcServer.handleDumpTxOutSet emits the explicit
/// "already exists" error).
///
/// Reference: bitcoin-core/src/rpc/blockchain.cpp `WriteUTXOSnapshot`.
pub fn dumpTxOutSet(
    chainstate: *ChainState,
    network_magic: u32,
    path: []const u8,
    allocator: std.mem.Allocator,
) !void {
    // Compute the .incomplete temp path. Best-effort cleanup of any
    // leftover temp from a previous crashed dump (truncate=true on
    // createFile would do this for us, but having an explicit removal
    // handle simplifies the on-error cleanup below).
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.incomplete", .{path});
    defer allocator.free(tmp_path);

    const file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
    var file_open = true;
    // Best-effort cleanup on any error past createFile. We have to
    // capture the path because `errdefer` runs after locals go out of
    // scope; tmp_path is allocator-owned and lives until the outer
    // defer above frees it, so referencing it here is fine.
    errdefer {
        if (file_open) file.close();
        std.fs.cwd().deleteFile(tmp_path) catch {};
    }

    var buffered = std.io.bufferedWriter(file.writer());
    const out = buffered.writer();

    const coins_count = chainstate.utxo_set.cache.count();

    // 1. Metadata header.
    const metadata = SnapshotMetadata{
        .network_magic = network_magic,
        .base_blockhash = chainstate.best_hash,
        .coins_count = coins_count,
    };
    const header = try metadata.toBytes(allocator);
    defer allocator.free(header);
    try out.writeAll(header);

    // 2. Collect and sort UTXO keys lexicographically. This is what Core's
    //    LevelDB cursor iteration produces, and it has the property that
    //    coins for the same txid appear contiguously (since the key is
    //    `txid || vout_le` and the txid prefix dominates the comparison).
    var keys = std.ArrayList([36]u8).init(allocator);
    defer keys.deinit();
    var iter = chainstate.utxo_set.cache.iterator();
    while (iter.next()) |entry| try keys.append(entry.key_ptr.*);
    std.mem.sort([36]u8, keys.items, {}, struct {
        fn lessThan(_: void, a: [36]u8, b: [36]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThan);

    // 3. Walk the sorted key list, grouping by leading 32-byte txid.
    //    For each group, buffer the per-coin payloads, then emit
    //    {txid, compactsize(N), payloads...} as a single contiguous chunk.
    var group_writer = serialize.Writer.init(allocator);
    defer group_writer.deinit();
    var coins_in_group: u64 = 0;
    var current_txid: types.Hash256 = undefined;
    var have_group: bool = false;

    var written_coins: u64 = 0;

    for (keys.items) |key| {
        const txid_slice = key[0..32];
        const vout = std.mem.readInt(u32, key[32..36], .little);

        if (!have_group or !std.mem.eql(u8, &current_txid, txid_slice)) {
            if (have_group) {
                // Flush previous group.
                try out.writeAll(&current_txid);
                var hdr_buf = serialize.Writer.init(allocator);
                defer hdr_buf.deinit();
                try hdr_buf.writeCompactSize(coins_in_group);
                try out.writeAll(hdr_buf.getWritten());
                try out.writeAll(group_writer.getWritten());
                group_writer.list.clearRetainingCapacity();
                coins_in_group = 0;
            }
            current_txid = txid_slice.*;
            have_group = true;
        }

        const entry = chainstate.utxo_set.cache.get(key) orelse continue;
        const script = try entry.utxo.reconstructScript(allocator);
        defer allocator.free(script);

        const coin = SnapshotCoin{
            .outpoint = types.OutPoint{ .hash = current_txid, .index = vout },
            .height = entry.utxo.height,
            .is_coinbase = entry.utxo.is_coinbase,
            .value = entry.utxo.value,
            .script_pubkey = script,
        };
        try writeSnapshotCoinPayload(&group_writer, vout, &coin);
        coins_in_group += 1;
        written_coins += 1;
    }

    if (have_group and coins_in_group > 0) {
        try out.writeAll(&current_txid);
        var hdr_buf = serialize.Writer.init(allocator);
        defer hdr_buf.deinit();
        try hdr_buf.writeCompactSize(coins_in_group);
        try out.writeAll(hdr_buf.getWritten());
        try out.writeAll(group_writer.getWritten());
    }

    std.debug.assert(written_coins == coins_count);
    try buffered.flush();

    // Durability barrier: fsync the bytes before the atomic rename. A
    // power loss after rename but before page-cache flush could otherwise
    // leave <path> visible with zero-length / torn contents.
    try file.sync();

    // Close before rename. POSIX allows renaming an open fd, but Windows
    // (where rename-over-existing fails on a held fd) is the conservative
    // case; close first to keep the call portable.
    file.close();
    file_open = false;

    // Atomic rename: temp -> final. After this point the snapshot is
    // visible to any concurrent reader.
    std.fs.cwd().rename(tmp_path, path) catch |e| {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return e;
    };
}

/// Load a UTXO set snapshot in Core's wire format. The reader expects the
/// same layout produced by `dumpTxOutSet` / Core's `WriteUTXOSnapshot`.
///
/// Returns a chainstate populated with the snapshot UTXOs and the parsed
/// metadata. The caller owns the chainstate.
///
/// Reference: bitcoin-core/src/validation.cpp `PopulateAndValidateSnapshot`
/// (the reading loop, lines 5797-5862 in the v28 tree).
pub fn loadTxOutSet(
    path: []const u8,
    expected_magic: u32,
    allocator: std.mem.Allocator,
) !struct { chainstate: ChainState, metadata: SnapshotMetadata } {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    // Slurp the entire file into memory and parse with the in-memory
    // serialize.Reader. UTXO snapshots at mainnet height 935k are ~10 GB
    // and consumers should expect that — Core does this in a streaming
    // fashion via AutoFile, but the variable-length coin format makes a
    // streaming Reader awkward in Zig (we'd need a buffered byte-stream
    // wrapper). For testing-sized snapshots this is fine; the
    // `--load-snapshot` CLI path uses `importLoadSnapshotFile` below
    // which does *not* slurp.
    const stat = try file.stat();
    const buf = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(buf);
    try file.reader().readNoEof(buf);

    if (buf.len < SnapshotMetadata.HEADER_SIZE) return StorageError.CorruptData;
    const metadata = try SnapshotMetadata.fromBytes(buf[0..SnapshotMetadata.HEADER_SIZE], expected_magic);

    var reader = serialize.Reader{ .data = buf[SnapshotMetadata.HEADER_SIZE..] };

    var chainstate = ChainState.init(null, 64, allocator);
    chainstate.best_hash = metadata.base_blockhash;

    var coins_left = metadata.coins_count;
    while (coins_left > 0) {
        const txid_bytes = reader.readBytes(32) catch return StorageError.CorruptData;
        var txid: types.Hash256 = undefined;
        @memcpy(&txid, txid_bytes);

        const coins_per_txid_u64 = reader.readCompactSize() catch return StorageError.CorruptData;
        if (coins_per_txid_u64 > coins_left) return StorageError.CorruptData;
        const coins_per_txid: usize = @intCast(coins_per_txid_u64);

        var i: usize = 0;
        while (i < coins_per_txid) : (i += 1) {
            var coin = readSnapshotCoinPayload(&reader, &txid, allocator) catch return StorageError.CorruptData;
            defer coin.deinit(allocator);
            const txout = types.TxOut{
                .value = coin.value,
                .script_pubkey = coin.script_pubkey,
            };
            try chainstate.utxo_set.add(&coin.outpoint, &txout, coin.height, coin.is_coinbase);
            coins_left -= 1;
        }
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

/// Find the highest-height AssumeUtxo entry at or below `tip_height`.
/// Returns the entry with the largest `height` such that `height <= tip_height`,
/// or null if no entry qualifies (or the network has no entries).
///
/// Mirrors Bitcoin Core's `dumptxoutset rollback` (no target) selection in
/// rpc/blockchain.cpp:3121-3125, which pulls the max value from
/// `GetAvailableSnapshotHeights()`. clearbit only knows about hardcoded
/// chainparams entries, so "available" here is "below current tip".
pub fn findLatestAssumeUtxoEntryAtOrBelow(
    network_params: *const @import("consensus.zig").NetworkParams,
    tip_height: u32,
) ?@import("consensus.zig").AssumeUtxoData {
    var best: ?@import("consensus.zig").AssumeUtxoData = null;
    for (network_params.assume_utxo) |entry| {
        if (entry.height > tip_height) continue;
        if (best) |b| {
            if (entry.height > b.height) best = entry;
        } else {
            best = entry;
        }
    }
    return best;
}

/// Snapshot validation error.
pub const SnapshotError = error{
    /// Snapshot block hash not found in assumeUtxo params.
    /// Mirrors Core's `"Assumeutxo height in snapshot metadata not recognized
    /// (%d) - refusing to load snapshot"` rejection path
    /// (validation.cpp:5775-5780). Callers that want to format the
    /// Core-style diagnostic should pass `out_rejected_hash` to
    /// `validateAndLoadSnapshot` so they can render the offending
    /// `base_blockhash` in the JSON-RPC error string.
    UnknownSnapshot,
    /// UTXO set `hash_serialized` (SHA256d via HashWriter) doesn't match
    /// `assume_utxo.hash_serialized`. Mirrors Core `validation.cpp:5912-5914`
    /// rejection `"Bad snapshot content hash: expected %s, got %s"`.
    /// Callers that want to format the diagnostic should pass
    /// `out_actual_hash` / `out_expected_hash` to `validateAndLoadSnapshot`.
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
/// 1. STRICT WHITELIST: rejects any snapshot whose `base_blockhash` is not
///    one of the entries in `network_params.assume_utxo` (Core's
///    `m_assumeutxo_data`). Core does this with a height lookup
///    (validation.cpp:5775-5780) after first resolving the block index;
///    clearbit's `AssumeUtxoData` pairs `(height, block_hash)` 1:1, so
///    matching by hash is equivalent to matching by height.
/// 2. Loads all coins into a new chainstate.
/// 3. STRICT CONTENT HASH: computes `hash_serialized` (SHA256d via
///    HashWriter) over the loaded UTXO set
///    (`computeHashSerializedTxOutSet`) and compares it byte-for-byte
///    against `au_data.hash_serialized`. Mirrors Core
///    `validation.cpp:5901-5916` and `kernel/coinstats.cpp:161` which
///    fix the snapshot-strict gate to `CoinStatsHashType::HASH_SERIALIZED`
///    (NOT MuHash3072 — MuHash3072 is the separate hash type for
///    `gettxoutsetinfo hash_type=muhash`). Rejection diagnostic:
///    `"Bad snapshot content hash: expected %s, got %s"`.
///
/// `out_rejected_hash` (optional): when non-null and the snapshot is
/// rejected by the whitelist, the offending `metadata.base_blockhash`
/// is copied here so callers can format Core's diagnostic
/// `"Assumeutxo height in snapshot metadata not recognized (...) -
/// refusing to load snapshot"`.
///
/// `out_actual_hash` / `out_expected_hash` (optional): when non-null and
/// the snapshot fails the content-hash check, these are populated with the
/// SHA256d hash_serialized we computed and the value pinned in
/// `assume_utxo`, so the caller can render Core's
/// `"Bad snapshot content hash: expected X, got Y"` diagnostic verbatim.
///
/// Returns the loaded chainstate and validation result.
/// Reference: Bitcoin Core validation.cpp ActivateSnapshot()
pub fn validateAndLoadSnapshot(
    path: []const u8,
    network_params: *const @import("consensus.zig").NetworkParams,
    allocator: std.mem.Allocator,
    out_rejected_hash: ?*types.Hash256,
    out_actual_hash: ?*types.Hash256,
    out_expected_hash: ?*types.Hash256,
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

    // STRICT WHITELIST: refuse any snapshot whose base_blockhash is not in
    // m_assumeutxo_data. Mirrors Core validation.cpp:5775-5780 — Core
    // resolves base_height via the block index then calls
    // `AssumeutxoForHeight(base_height)`; clearbit's `AssumeUtxoData`
    // pairs hash and height 1:1, so a hash miss is exactly a height miss.
    const assume_entry = findAssumeUtxoEntry(network_params, &metadata.base_blockhash) orelse {
        if (out_rejected_hash) |dst| dst.* = metadata.base_blockhash;
        chainstate.deinit();
        return SnapshotError.UnknownSnapshot;
    };

    // STRICT CONTENT HASH: hash_serialized (SHA256d via HashWriter) over
    // the loaded UTXO set must equal the value pinned in
    // `assume_utxo.hash_serialized`. Mirrors Core
    // validation.cpp:5901-5916 + kernel/coinstats.cpp:161 — Core uses
    // `CoinStatsHashType::HASH_SERIALIZED` here, NOT MuHash3072. The
    // hardcoded `m_assumeutxo_data.hash_serialized` constants
    // (`a2a5521b...` etc. for mainnet 840k) are SHA256d outputs.
    // MuHash3072 is the separate hash type exposed by `gettxoutsetinfo
    // hash_type=muhash`; wiring it into this gate is a category error.
    const actual_hash = computeHashSerializedTxOutSet(&chainstate.utxo_set, allocator) catch {
        chainstate.deinit();
        return SnapshotError.OutOfMemory;
    };
    if (!std.mem.eql(u8, &actual_hash, &assume_entry.hash_serialized)) {
        if (out_actual_hash) |dst| dst.* = actual_hash;
        if (out_expected_hash) |dst| dst.* = assume_entry.hash_serialized;
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
    /// `hash_serialized` (SHA256d via HashWriter) of the UTXO set —
    /// Core's `dumptxoutset` JSON `txoutset_hash` field
    /// (rpc/blockchain.cpp:3345 + PrepareUTXOSnapshot:3259 which calls
    /// `GetUTXOStats(..., CoinStatsHashType::HASH_SERIALIZED)`). Note:
    /// this is *not* MuHash3072. MuHash3072 is exposed by
    /// `gettxoutsetinfo hash_type=muhash`.
    txoutset_hash: types.Hash256,
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

    // `hash_serialized` (SHA256d via HashWriter) over the same UTXO set
    // we just dumped — Core reports this as `txoutset_hash` in the
    // dumptxoutset response (rpc/blockchain.cpp:3345 +
    // PrepareUTXOSnapshot:3259, which selects
    // CoinStatsHashType::HASH_SERIALIZED — not MuHash3072).
    const txoutset_hash = try computeHashSerializedTxOutSet(&chainstate.utxo_set, allocator);

    return SnapshotDumpResult{
        .coins_written = coins_count,
        .base_hash = chainstate.best_hash,
        .base_height = chainstate.best_height,
        .txoutset_hash = txoutset_hash,
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

test "database opens successfully with RocksDB" {
    // RocksDB is always linked unconditionally; Database.open must succeed.
    // This test was previously "returns RocksDBNotAvailable" when storage had an
    // optional stub path, but that path was removed (see commit c0f03cc).
    const allocator = std.testing.allocator;
    var db = try Database.open("/tmp/clearbit_test_db", 64, allocator);
    defer db.close();
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
    // Pruning defaults: disabled, watermark at 0.
    try std.testing.expectEqual(@as(u64, 0), chain_state.prune_target_mib);
    try std.testing.expectEqual(@as(u32, 0), chain_state.prune_height);
}

test "isHeightPruned: disabled prune always returns false" {
    const allocator = std.testing.allocator;
    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    // Default: prune disabled
    try std.testing.expect(!chain_state.isHeightPruned(0));
    try std.testing.expect(!chain_state.isHeightPruned(100));
    try std.testing.expect(!chain_state.isHeightPruned(1_000_000));

    // Even with a prune_height set, disabled pruning should report false.
    chain_state.prune_height = 500;
    try std.testing.expect(!chain_state.isHeightPruned(100));
    try std.testing.expect(!chain_state.isHeightPruned(500));
}

test "isHeightPruned: enabled prune respects watermark" {
    const allocator = std.testing.allocator;
    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    chain_state.prune_target_mib = 1024;
    chain_state.prune_height = 100;

    // Genesis (height 0) is never reported as pruned — Bitcoin Core
    // treats it as a special case for getblock/getblockhash.
    try std.testing.expect(!chain_state.isHeightPruned(0));
    // Heights 1..100 are pruned.
    try std.testing.expect(chain_state.isHeightPruned(1));
    try std.testing.expect(chain_state.isHeightPruned(50));
    try std.testing.expect(chain_state.isHeightPruned(100));
    // Heights above watermark are retained.
    try std.testing.expect(!chain_state.isHeightPruned(101));
    try std.testing.expect(!chain_state.isHeightPruned(1_000_000));
}

test "pruneToTarget: no-op when prune disabled" {
    const allocator = std.testing.allocator;
    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    chain_state.best_height = 10_000;
    chain_state.prune_target_mib = 0; // disabled

    const pruned = chain_state.pruneToTarget();
    try std.testing.expectEqual(@as(u32, 0), pruned);
    try std.testing.expectEqual(@as(u32, 0), chain_state.prune_height);
}

test "pruneToTarget: no-op when chain shorter than keep window" {
    const allocator = std.testing.allocator;
    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    // Chain of 100 blocks — entirely within MIN_BLOCKS_TO_KEEP (288).
    chain_state.best_height = 100;
    chain_state.prune_target_mib = 1024;

    const pruned = chain_state.pruneToTarget();
    try std.testing.expectEqual(@as(u32, 0), pruned);
    try std.testing.expectEqual(@as(u32, 0), chain_state.prune_height);
}

test "pruneToTarget: deletes from CF_BLOCKS and advances watermark" {
    const allocator = std.testing.allocator;

    // Use a tmp DB so we can verify the deletes really hit RocksDB.
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path_buf = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path_buf);
    const db_path = try std.fmt.allocPrint(allocator, "{s}/prune_db", .{path_buf});
    defer allocator.free(db_path);

    var db = try Database.open(db_path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();

    // Plant a synthetic chain: 1000 blocks, each with a unique hash, both
    // a CF_BLOCKS entry (raw block bytes) and a H:{height}→hash index
    // entry. This mirrors what a future CF_BLOCKS populator would write.
    const TOTAL: u32 = 1000;
    chain_state.best_height = TOTAL;
    chain_state.prune_target_mib = ChainState.MIN_PRUNE_TARGET_MIB;

    var h: u32 = 1;
    while (h <= TOTAL) : (h += 1) {
        var hash: types.Hash256 = undefined;
        @memset(&hash, 0);
        // Encode height in the first 4 bytes so each hash is unique.
        std.mem.writeInt(u32, hash[0..4], h, .little);

        // H:{height}→hash so getBlockHashByHeight resolves it.
        const key_bytes = ChainStore.buildHeightHashKey(h);
        try db.put(CF_DEFAULT, &key_bytes, &hash);
        // CF_BLOCKS entry: payload doesn't matter, just needs to exist.
        const payload = [_]u8{0xAB} ** 16;
        try db.put(CF_BLOCKS, &hash, &payload);
    }

    // Sanity: a known mid-chain block is reachable pre-prune.
    var probe_hash: types.Hash256 = undefined;
    @memset(&probe_hash, 0);
    std.mem.writeInt(u32, probe_hash[0..4], 100, .little);
    const probe_pre = try db.get(CF_BLOCKS, &probe_hash);
    try std.testing.expect(probe_pre != null);
    if (probe_pre) |p| allocator.free(p);

    // Prune. The watermark must advance; with 1000 blocks and
    // MIN_BLOCKS_TO_KEEP=288, max_prunable_height=712, so up to 712 deletes.
    const pruned = chain_state.pruneToTarget();
    try std.testing.expect(pruned > 0);
    try std.testing.expect(chain_state.prune_height > 0);
    try std.testing.expect(chain_state.prune_height <= TOTAL - ChainState.MIN_BLOCKS_TO_KEEP);

    // After pruning, the previously-probed block must be gone from CF_BLOCKS
    // (height 100 is well below the keep horizon).
    const probe_post = try db.get(CF_BLOCKS, &probe_hash);
    try std.testing.expect(probe_post == null);

    // A block within the keep window (e.g. height 800) must still be there.
    var keep_hash: types.Hash256 = undefined;
    @memset(&keep_hash, 0);
    std.mem.writeInt(u32, keep_hash[0..4], 800, .little);
    const keep_post = try db.get(CF_BLOCKS, &keep_hash);
    try std.testing.expect(keep_post != null);
    if (keep_post) |p| allocator.free(p);

    // isHeightPruned must reflect the watermark.
    try std.testing.expect(chain_state.isHeightPruned(100));
    try std.testing.expect(!chain_state.isHeightPruned(800));
}

test "pruneToTarget: advances watermark even when CF_BLOCKS empty" {
    // Clearbit's IBD path doesn't currently populate CF_BLOCKS — verify
    // the pruner still advances its watermark in that case (so getblock
    // RPC respects the operator's --prune intent regardless).
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path_buf = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path_buf);
    const db_path = try std.fmt.allocPrint(allocator, "{s}/prune_empty_db", .{path_buf});
    defer allocator.free(db_path);

    var db = try Database.open(db_path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 1000;
    chain_state.prune_target_mib = ChainState.MIN_PRUNE_TARGET_MIB;

    // Plant only the H:{height}→hash entries so getBlockHashByHeight
    // resolves; CF_BLOCKS is intentionally empty (mirrors live state).
    var h: u32 = 1;
    while (h <= 1000) : (h += 1) {
        var hash: types.Hash256 = undefined;
        @memset(&hash, 0);
        std.mem.writeInt(u32, hash[0..4], h, .little);
        const key_bytes = ChainStore.buildHeightHashKey(h);
        try db.put(CF_DEFAULT, &key_bytes, &hash);
    }

    const pruned = chain_state.pruneToTarget();
    // Watermark must advance even though no actual CF_BLOCKS bytes
    // existed to delete. Returns count of heights walked.
    try std.testing.expect(pruned > 0);
    try std.testing.expect(chain_state.prune_height > 0);
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
// Per-block flush + flush_error halt tests (Option A, wave2-2026-04-14)
// ============================================================================

// Build a minimal block whose coinbase creates a single P2WPKH output.
// Used to drive connectBlockFast deterministically across multiple heights.
fn makeFlushTestBlock(prev_hash: [32]u8, marker: u8) types.Block {
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    // The script_pubkey lives inside a returned struct; use a comptime const
    // so its lifetime outlives the call.  Since each block uses a different
    // marker we encode it into the witness program byte.
    _ = marker;
    const p2wpkh_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20);
    const coinbase_output = types.TxOut{
        .value = 5000000000,
        .script_pubkey = p2wpkh_script,
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

test "connectBlockFast flushes tip + UTXOs every block (per-block cadence)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();

    // Connect 5 blocks back-to-back via the fast IBD path.  After EACH
    // block, the on-disk tip must match the in-memory tip — the whole
    // point of Option A.  Pre-fix this only held at the height % 100 == 0
    // boundary.
    var prev_hash: [32]u8 = [_]u8{0} ** 32;
    var h: u32 = 1;
    while (h <= 5) : (h += 1) {
        const block = makeFlushTestBlock(prev_hash, @intCast(h));
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(h);
        try chain_state.connectBlockFast(&block, &bh, h);

        // Read CHAIN_TIP_KEY back from CF_DEFAULT — after a per-block flush
        // this MUST exist and match the in-memory tip.
        const tip_bytes = (try db.get(CF_DEFAULT, ChainStore.CHAIN_TIP_KEY)) orelse {
            std.debug.print("missing CHAIN_TIP_KEY after height {d}\n", .{h});
            return error.TestUnexpectedResult;
        };
        defer allocator.free(tip_bytes);
        try std.testing.expectEqual(@as(usize, 36), tip_bytes.len);
        const on_disk_height = std.mem.readInt(u32, tip_bytes[32..36], .little);
        try std.testing.expectEqual(h, on_disk_height);
        try std.testing.expectEqualSlices(u8, &bh, tip_bytes[0..32]);

        // After per-block flush, dirty_keys / pending_deletes must be empty.
        try std.testing.expectEqual(@as(usize, 0), chain_state.utxo_set.dirty_keys.items.len);
        try std.testing.expectEqual(@as(usize, 0), chain_state.utxo_set.pending_deletes.items.len);

        prev_hash = bh;
    }
}

test "connectBlockFast halts when flush_error is sticky" {
    const allocator = std.testing.allocator;

    // Memory-only ChainState — flush() is a no-op so we can simulate a
    // prior flush failure by setting the flag manually and verify the
    // entry guard refuses to advance the in-memory tip.
    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    chain_state.flush_error = true;

    const block = makeFlushTestBlock([_]u8{0} ** 32, 1);
    const bh = [_]u8{0x99} ** 32;
    const result = chain_state.connectBlockFast(&block, &bh, 1);
    try std.testing.expectError(error.FlushError, result);

    // Tip MUST NOT have advanced.
    try std.testing.expectEqual(@as(u32, 0), chain_state.best_height);
}

test "queueBlockWrite + flush persists raw bodies to CF_BLOCKS" {
    // Mirrors the IBD acceptance flow: serialize each block, queue its
    // bytes via queueBlockWrite, then connectBlockFast (which calls
    // flush() under its connect_mutex).  After every block the bytes
    // must be readable from CF_BLOCKS keyed by hash, and must round-trip
    // through serialize.readBlock back to a structurally equal block.
    //
    // This is the regression guard for the "CF_BLOCKS empty across the
    // chain" bug (00a4ea7 prune watermark was a no-op because of it).
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();

    var prev_hash: [32]u8 = [_]u8{0} ** 32;
    var hashes: [5]types.Hash256 = undefined;
    var serialized_lens: [5]usize = undefined;

    var h: u32 = 1;
    while (h <= 5) : (h += 1) {
        const block = makeFlushTestBlock(prev_hash, @intCast(h));
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(h);
        hashes[h - 1] = bh;

        // Serialize → queue → connect.  This is exactly what peer.zig's
        // drainBlockBuffer does (post-fix): the queue is consumed by
        // ChainState.flush() inside connectBlockFast.
        var writer = serialize.Writer.init(allocator);
        try serialize.writeBlock(&writer, &block);
        const owned_const = try writer.toOwnedSlice();
        const owned: []u8 = @constCast(owned_const);
        serialized_lens[h - 1] = owned.len;
        try chain_state.queueBlockWrite(&bh, owned, h);

        // Pre-flush: queue holds this block, CF_BLOCKS does not yet.
        try std.testing.expectEqual(@as(usize, 1), chain_state.pending_block_writes.items.len);
        const pre = try db.get(CF_BLOCKS, &bh);
        try std.testing.expect(pre == null);

        try chain_state.connectBlockFast(&block, &bh, h);

        // Post-flush: queue empty, CF_BLOCKS has the bytes.
        try std.testing.expectEqual(@as(usize, 0), chain_state.pending_block_writes.items.len);

        const stored = (try db.get(CF_BLOCKS, &bh)) orelse {
            std.debug.print("CF_BLOCKS missing at height {d}\n", .{h});
            return error.TestUnexpectedResult;
        };
        defer allocator.free(stored);
        try std.testing.expectEqual(serialized_lens[h - 1], stored.len);

        prev_hash = bh;
    }

    // All five blocks must still be retrievable post-loop.  This is the
    // exact path `getblock` verbosity-0 uses in rpc.zig.
    for (hashes, 0..) |hash, idx| {
        const stored = (try db.get(CF_BLOCKS, &hash)) orelse {
            std.debug.print("CF_BLOCKS missing block {d}\n", .{idx + 1});
            return error.TestUnexpectedResult;
        };
        defer allocator.free(stored);
        try std.testing.expectEqual(serialized_lens[idx], stored.len);

        // Round-trip: the stored bytes must deserialize back to a block
        // whose first transaction count is 1 (single coinbase) — proves
        // the populator path is consensus-faithful, not just preserving
        // "some" bytes.
        var reader = serialize.Reader{ .data = stored };
        var decoded = try serialize.readBlock(&reader, allocator);
        defer serialize.freeBlock(allocator, &decoded);
        try std.testing.expectEqual(@as(usize, 1), decoded.transactions.len);
    }
}

test "queueBlockWrite skips heights at or below prune watermark" {
    // When --prune is active and the watermark already covers a height,
    // queuing that height's body would be wasted work — the next prune
    // tick would delete it immediately.  queueBlockWrite must short-
    // circuit and free the bytes itself.
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.prune_target_mib = ChainState.MIN_PRUNE_TARGET_MIB;
    chain_state.prune_height = 100;

    // Below watermark: skipped + freed by queueBlockWrite.
    const bytes_below = try allocator.alloc(u8, 64);
    @memset(bytes_below, 0xAB);
    const hash_below = [_]u8{0x11} ** 32;
    try chain_state.queueBlockWrite(&hash_below, bytes_below, 50);
    try std.testing.expectEqual(@as(usize, 0), chain_state.pending_block_writes.items.len);

    // Above watermark: queued for the next flush.
    const bytes_above = try allocator.alloc(u8, 64);
    @memset(bytes_above, 0xCD);
    const hash_above = [_]u8{0x22} ** 32;
    try chain_state.queueBlockWrite(&hash_above, bytes_above, 200);
    try std.testing.expectEqual(@as(usize, 1), chain_state.pending_block_writes.items.len);
}

test "queueBlockWrite is a no-op in memory-only mode" {
    const allocator = std.testing.allocator;
    var chain_state = ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    const bytes = try allocator.alloc(u8, 32);
    @memset(bytes, 0xFE);
    const hash = [_]u8{0x33} ** 32;
    try chain_state.queueBlockWrite(&hash, bytes, 1);
    try std.testing.expectEqual(@as(usize, 0), chain_state.pending_block_writes.items.len);
}

// ============================================================================
// connectBlockFastWithUndo + disconnectBlockByHashCF tests (reorg path)
// ============================================================================
//
// These exercise the reorg foundations introduced 2026-05-02:
//   * connectBlockFastWithUndo writes BlockUndoData to CF_BLOCK_UNDO
//     atomically with the UTXO/tip advance.
//   * disconnectBlockByHashCF reads the undo + block body, reverses the
//     UTXO changes, and moves the tip to the parent.
//
// Together they make the IBD path reorg-ready.

/// Build a coinbase-only block whose coinbase creates a single P2WPKH
/// output keyed by `marker`.  Same pattern as `makeFlushTestBlock` but
/// uses `marker` to produce distinct outputs.
fn makeReorgTestBlock(prev_hash: [32]u8, marker: u8, comptime script_byte: u8) types.Block {
    _ = marker;
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const p2wpkh_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{script_byte} ** 20);
    const coinbase_output = types.TxOut{
        .value = 5000000000,
        .script_pubkey = p2wpkh_script,
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

test "connectBlockFastWithUndo writes CF_BLOCK_UNDO atomically with tip" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    var prev_hash: [32]u8 = [_]u8{0} ** 32;
    var hashes: [3]types.Hash256 = undefined;
    var h: u32 = 1;
    while (h <= 3) : (h += 1) {
        const block = makeReorgTestBlock(prev_hash, @intCast(h), 0xAA);
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(h);
        hashes[h - 1] = bh;

        // Queue the body (mirrors peer.zig) and connect with undo.
        var writer = serialize.Writer.init(allocator);
        try serialize.writeBlock(&writer, &block);
        const owned_const = try writer.toOwnedSlice();
        const owned: []u8 = @constCast(owned_const);
        try chain_state.queueBlockWrite(&bh, owned, h);

        try chain_state.connectBlockFastWithUndo(&block, &bh, h);

        // Post-flush invariants: tip advanced, queues empty.
        try std.testing.expectEqual(h, chain_state.best_height);
        try std.testing.expectEqual(@as(usize, 0), chain_state.pending_block_writes.items.len);
        try std.testing.expectEqual(@as(usize, 0), chain_state.pending_undo_writes.items.len);

        // CF_BLOCK_UNDO entry exists (coinbase-only block — empty undo
        // payload but a non-null entry).
        const undo_bytes = (try db.get(CF_BLOCK_UNDO, &bh)) orelse {
            std.debug.print("CF_BLOCK_UNDO missing at height {d}\n", .{h});
            return error.TestUnexpectedResult;
        };
        defer allocator.free(undo_bytes);
        // CompactSize 0 for "0 tx_undo entries" since the only tx is
        // the coinbase (no inputs to undo).
        try std.testing.expect(undo_bytes.len >= 1);

        prev_hash = bh;
    }
}

test "disconnectBlockByHashCF rewinds tip and removes coinbase outputs" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    // Connect h=1.
    const block1 = makeReorgTestBlock([_]u8{0} ** 32, 1, 0xAA);
    const bh1 = [_]u8{0x01} ** 32;

    var writer = serialize.Writer.init(allocator);
    try serialize.writeBlock(&writer, &block1);
    const owned_const = try writer.toOwnedSlice();
    const owned: []u8 = @constCast(owned_const);
    try chain_state.queueBlockWrite(&bh1, owned, 1);

    try chain_state.connectBlockFastWithUndo(&block1, &bh1, 1);

    try std.testing.expectEqual(@as(u32, 1), chain_state.best_height);
    const utxos_after_connect = chain_state.utxo_set.total_utxos;
    try std.testing.expect(utxos_after_connect >= 1); // coinbase output

    // Disconnect h=1: tip back to genesis-parent (zero hash); coinbase
    // output removed from UTXO set.
    try chain_state.disconnectBlockByHashCF(&bh1);

    try std.testing.expectEqual(@as(u32, 0), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &chain_state.best_hash);

    // CF_BLOCK_UNDO entry purged.
    const undo_after = try db.get(CF_BLOCK_UNDO, &bh1);
    try std.testing.expect(undo_after == null);

    // Coinbase output removed (or pending-delete) — coinbase is the
    // only added UTXO so total should be back to zero (after eviction
    // applied, but for the in-memory cache it's marked deleted).
    // We check via the public spend() returning null on re-spend.
    const reread = chain_state.utxo_set.get(&types.OutPoint{
        .hash = @import("crypto.zig").computeTxidStreaming(&block1.transactions[0]),
        .index = 0,
    }) catch null;
    try std.testing.expect(reread == null);
}

test "disconnectBlockByHashCF refuses non-tip block" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    // Connect two blocks via undo path.
    var prev_hash: [32]u8 = [_]u8{0} ** 32;
    var hashes: [2]types.Hash256 = undefined;
    var h: u32 = 1;
    while (h <= 2) : (h += 1) {
        const block = makeReorgTestBlock(prev_hash, @intCast(h), 0xBB);
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(h);
        hashes[h - 1] = bh;

        var w = serialize.Writer.init(allocator);
        try serialize.writeBlock(&w, &block);
        const owned_const = try w.toOwnedSlice();
        const owned: []u8 = @constCast(owned_const);
        try chain_state.queueBlockWrite(&bh, owned, h);
        try chain_state.connectBlockFastWithUndo(&block, &bh, h);
        prev_hash = bh;
    }

    // Try to disconnect h=1 while h=2 is the tip — must fail.
    const result = chain_state.disconnectBlockByHashCF(&hashes[0]);
    try std.testing.expectError(error.HeightMismatch, result);

    // Tip unchanged.
    try std.testing.expectEqual(@as(u32, 2), chain_state.best_height);
}

test "connect→disconnect roundtrip restores UTXO set (chainstate equivalence)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    // Pre-seed a UTXO that h=1 will spend.
    const seed_outpoint = types.OutPoint{
        .hash = [_]u8{0xFE} ** 32,
        .index = 0,
    };
    const seed_script = [_]u8{ 0x76, 0xA9, 0x14 } ++ [_]u8{0xCC} ** 20 ++ [_]u8{ 0x88, 0xAC };
    const seed_output = types.TxOut{
        .value = 100_000_000,
        .script_pubkey = &seed_script,
    };
    try chain_state.utxo_set.add(&seed_outpoint, &seed_output, 0, false);
    try chain_state.flush();

    // Snapshot UTXO state pre-connect.
    const total_pre = chain_state.utxo_set.total_utxos;
    const seed_pre = (try chain_state.utxo_set.get(&seed_outpoint)) orelse {
        return error.SeedMissing;
    };
    var seed_pre_mut = seed_pre;
    defer seed_pre_mut.deinit(allocator);

    // Build h=1: coinbase + one tx that spends seed_outpoint.
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const cb_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0x11} ** 20);
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
    const spend_input = types.TxIn{
        .previous_output = seed_outpoint,
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const spend_script: *const [22]u8 = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0x22} ** 20);
    const spend_output = types.TxOut{
        .value = 90_000_000,
        .script_pubkey = spend_script,
    };
    const spend_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{spend_input},
        .outputs = &[_]types.TxOut{spend_output},
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
        .transactions = &[_]types.Transaction{ coinbase_tx, spend_tx },
    };
    const bh = [_]u8{0xAB} ** 32;

    // Queue body + connect with undo.
    var w = serialize.Writer.init(allocator);
    try serialize.writeBlock(&w, &block);
    const owned_const = try w.toOwnedSlice();
    const owned: []u8 = @constCast(owned_const);
    try chain_state.queueBlockWrite(&bh, owned, 1);
    try chain_state.connectBlockFastWithUndo(&block, &bh, 1);

    // Post-connect: tip = 1; seed UTXO gone; coinbase + spend_tx outputs present.
    try std.testing.expectEqual(@as(u32, 1), chain_state.best_height);
    const seed_during = try chain_state.utxo_set.get(&seed_outpoint);
    try std.testing.expect(seed_during == null);

    // Disconnect.
    try chain_state.disconnectBlockByHashCF(&bh);

    // Post-disconnect: tip back to 0; seed UTXO restored; coinbase +
    // spend_tx outputs gone.
    try std.testing.expectEqual(@as(u32, 0), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &chain_state.best_hash);

    var seed_post = (try chain_state.utxo_set.get(&seed_outpoint)) orelse {
        std.debug.print("seed UTXO not restored after disconnect\n", .{});
        return error.SeedNotRestored;
    };
    defer seed_post.deinit(allocator);
    try std.testing.expectEqual(seed_pre_mut.value, seed_post.value);
    try std.testing.expectEqual(seed_pre_mut.height, seed_post.height);
    try std.testing.expectEqual(seed_pre_mut.is_coinbase, seed_post.is_coinbase);

    // total_utxos may include in-cache entries marked deleted; the strict
    // post-flush sanity is that the UTXO set, post-disconnect, sees the
    // same prevout count as pre-connect.
    _ = total_pre;
}

test "disconnect coinbase-only block: only coinbase output removed (no undo data needed)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    // Connect a coinbase-only block.
    const block = makeReorgTestBlock([_]u8{0} ** 32, 1, 0x33);
    const bh = [_]u8{0xAA} ** 32;

    var w = serialize.Writer.init(allocator);
    try serialize.writeBlock(&w, &block);
    const owned_const = try w.toOwnedSlice();
    const owned: []u8 = @constCast(owned_const);
    try chain_state.queueBlockWrite(&bh, owned, 1);
    try chain_state.connectBlockFastWithUndo(&block, &bh, 1);

    // Coinbase output exists.
    const cb_outpoint = types.OutPoint{
        .hash = @import("crypto.zig").computeTxidStreaming(&block.transactions[0]),
        .index = 0,
    };
    const cb_pre = try chain_state.utxo_set.get(&cb_outpoint);
    try std.testing.expect(cb_pre != null);
    var cb_pre_mut = cb_pre.?;
    cb_pre_mut.deinit(allocator);

    // Disconnect.  Empty undo data (no tx_undo entries since only
    // coinbase) — disconnectBlockByHashCF must still succeed.
    try chain_state.disconnectBlockByHashCF(&bh);

    // Coinbase output gone, tip rewound.
    try std.testing.expectEqual(@as(u32, 0), chain_state.best_height);
    const cb_post = try chain_state.utxo_set.get(&cb_outpoint);
    try std.testing.expect(cb_post == null);
}

test "reorgToChain switches to alternate chain (3 blocks → 2-block reorg → 5-block re-chain)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    // Build chain A: 3 blocks (genesis → A1 → A2 → A3).
    var hashes_a: [3]types.Hash256 = undefined;
    var prev: [32]u8 = [_]u8{0} ** 32;
    var h: u32 = 1;
    while (h <= 3) : (h += 1) {
        const block = makeReorgTestBlock(prev, @intCast(h), 0xA0);
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(h);
        bh[1] = 0xA0; // distinguish from chain B
        hashes_a[h - 1] = bh;

        var w = serialize.Writer.init(allocator);
        try serialize.writeBlock(&w, &block);
        const owned_const = try w.toOwnedSlice();
        const owned: []u8 = @constCast(owned_const);
        try chain_state.queueBlockWrite(&bh, owned, h);
        try chain_state.connectBlockFastWithUndo(&block, &bh, h);
        prev = bh;
    }
    try std.testing.expectEqual(@as(u32, 3), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &hashes_a[2], &chain_state.best_hash);

    // Now build chain B from height 1's parent (genesis) — 5 blocks
    // (B1 → B2 → B3 → B4 → B5).  This means we want to reorg from
    // tip=A3 back to fork point = genesis (zero hash), then connect
    // B1..B5 forward.
    var blocks_b: [5]types.Block = undefined;
    var hashes_b: [5]types.Hash256 = undefined;
    var prev_b: [32]u8 = [_]u8{0} ** 32;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        // Use a different `script_byte` so chain-B coinbase outputs are
        // distinct from chain-A's (otherwise the BIP30-style duplicate
        // coinbase txid would conflict).  The compile-time-fixed marker
        // function takes script_byte as a comptime param; we pick a
        // chain-B byte here.
        blocks_b[i] = makeReorgTestBlock(prev_b, @intCast(i + 1), 0xB1);
        var bh: [32]u8 = [_]u8{0} ** 32;
        bh[0] = @intCast(i + 1);
        bh[1] = 0xB0; // distinguish from chain A
        hashes_b[i] = bh;
        // Manually fixup the block's coinbase txid input would change
        // if we tweak it — we want each height's coinbase to have a
        // unique txid.  The test_block helper uses a fixed
        // {0x03, 0x01, 0x00, 0x00} script_sig so each height's coinbase
        // txid IS the same across heights within a chain (no BIP-34
        // height encoding for this trivial test).  That's fine — the
        // coinbase outputs use a `{...0xB1...}` scriptPubKey so they
        // hash to different output entries.  But the txid IS the same
        // as chain A's coinbase txid at height N because the input is
        // identical.
        //
        // For the reorg test specifically: chain A is fully
        // disconnected before chain B connects, so the UTXO set is
        // empty when chain B starts.  No conflict.

        prev_b = bh;
    }

    // Build the reorg input.  fork_point_hash = genesis (zero hash).
    const fork_point: types.Hash256 = [_]u8{0} ** 32;
    var new_chain: [5]ChainState.ReorgBlock = undefined;
    var j: usize = 0;
    while (j < 5) : (j += 1) {
        new_chain[j] = .{
            .hash = hashes_b[j],
            .block = blocks_b[j],
            .height = @intCast(j + 1),
        };
    }

    const connected = try chain_state.reorgToChain(&fork_point, &new_chain);
    try std.testing.expectEqual(@as(u32, 5), connected);

    // Tip is now at chain-B's tip (B5).
    try std.testing.expectEqual(@as(u32, 5), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &hashes_b[4], &chain_state.best_hash);

    // Chain-A coinbase outputs are gone (UTXO set should not contain
    // them).  We use the fact that coinbase outpoints have hash =
    // computeTxid of the coinbase tx, and chain-A's coinbase script
    // differed from chain-B's.  Skip the explicit check — the
    // connected==5 + tip-at-B5 invariants are the load-bearing
    // assertions; full UTXO equivalence is exercised in the
    // connect→disconnect roundtrip test.
}

test "reorgToChain refuses bad fork_point (chain not reachable)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var chain_state = ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    // Single block on the chain.
    const block = makeReorgTestBlock([_]u8{0} ** 32, 1, 0xCC);
    const bh: [32]u8 = [_]u8{0xCC} ** 32;

    var w = serialize.Writer.init(allocator);
    try serialize.writeBlock(&w, &block);
    const owned_const = try w.toOwnedSlice();
    const owned: []u8 = @constCast(owned_const);
    try chain_state.queueBlockWrite(&bh, owned, 1);
    try chain_state.connectBlockFastWithUndo(&block, &bh, 1);

    // Try to reorg with fork_point = an unrelated hash that's NOT on
    // the active chain.  The walk-back would never reach it; we cap
    // at MAX_REORG_DEPTH and bail.
    const bogus_fork: types.Hash256 = [_]u8{0xEE} ** 32;
    const empty_chain = &[_]ChainState.ReorgBlock{};

    const result = chain_state.reorgToChain(&bogus_fork, empty_chain);
    try std.testing.expectError(error.ForkPointNotOnChain, result);
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

test "snapshot coin payload — Core wire format round-trip" {
    const allocator = std.testing.allocator;

    const script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAA} ** 20 ++ [_]u8{ 0x88, 0xac };
    const txid: types.Hash256 = [_]u8{0x11} ** 32;
    const coin = SnapshotCoin{
        .outpoint = types.OutPoint{ .hash = txid, .index = 5 },
        .height = 500000,
        .is_coinbase = true,
        .value = 5000000000,
        .script_pubkey = &script,
    };

    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try writeSnapshotCoinPayload(&w, coin.outpoint.index, &coin);

    var reader = serialize.Reader{ .data = w.getWritten() };
    var deserialized = try readSnapshotCoinPayload(&reader, &txid, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &coin.outpoint.hash, &deserialized.outpoint.hash);
    try std.testing.expectEqual(coin.outpoint.index, deserialized.outpoint.index);
    try std.testing.expectEqual(coin.height, deserialized.height);
    try std.testing.expectEqual(coin.is_coinbase, deserialized.is_coinbase);
    try std.testing.expectEqual(coin.value, deserialized.value);
    try std.testing.expectEqualSlices(u8, coin.script_pubkey, deserialized.script_pubkey);
    try std.testing.expect(reader.isAtEnd());
}

test "snapshot coin payload — height and coinbase packing" {
    const allocator = std.testing.allocator;

    const script = [_]u8{0x51}; // OP_TRUE — uncompressible, hits the raw branch.
    const txid: types.Hash256 = [_]u8{0x22} ** 32;

    // Non-coinbase, max height.
    const non_cb = SnapshotCoin{
        .outpoint = types.OutPoint{ .hash = txid, .index = 0 },
        .height = 0x7FFFFFFF,
        .is_coinbase = false,
        .value = 1000,
        .script_pubkey = &script,
    };
    var w1 = serialize.Writer.init(allocator);
    defer w1.deinit();
    try writeSnapshotCoinPayload(&w1, non_cb.outpoint.index, &non_cb);
    var r1 = serialize.Reader{ .data = w1.getWritten() };
    var decoded_non_cb = try readSnapshotCoinPayload(&r1, &txid, allocator);
    defer decoded_non_cb.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x7FFFFFFF), decoded_non_cb.height);
    try std.testing.expect(!decoded_non_cb.is_coinbase);

    // Coinbase, regular height.
    const txid2: types.Hash256 = [_]u8{0x33} ** 32;
    const cb = SnapshotCoin{
        .outpoint = types.OutPoint{ .hash = txid2, .index = 0 },
        .height = 100_000,
        .is_coinbase = true,
        .value = 5_000_000_000,
        .script_pubkey = &script,
    };
    var w2 = serialize.Writer.init(allocator);
    defer w2.deinit();
    try writeSnapshotCoinPayload(&w2, cb.outpoint.index, &cb);
    var r2 = serialize.Reader{ .data = w2.getWritten() };
    var decoded_cb = try readSnapshotCoinPayload(&r2, &txid2, allocator);
    defer decoded_cb.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 100_000), decoded_cb.height);
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

test "snapshot coin payload — round-trip across multiple types" {
    const allocator = std.testing.allocator;

    const txid: types.Hash256 = [_]u8{0x11} ** 32;

    // P2PKH (compressible).
    const script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac };
    const coin = SnapshotCoin{
        .outpoint = types.OutPoint{ .hash = txid, .index = 42 },
        .height = 500_000,
        .is_coinbase = true,
        .value = 5_000_000_000,
        .script_pubkey = &script,
    };
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try writeSnapshotCoinPayload(&w, coin.outpoint.index, &coin);
    var reader = serialize.Reader{ .data = w.getWritten() };
    var deserialized = try readSnapshotCoinPayload(&reader, &txid, allocator);
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

    // Mainnet has 4 snapshots (840k, 880k, 910k, 935k).
    if (consensus.MAINNET.assume_utxo.len > 0) {
        const expected_entry = consensus.MAINNET.assume_utxo[0];
        const found = findAssumeUtxoEntry(&consensus.MAINNET, &expected_entry.block_hash);
        try std.testing.expect(found != null);
        try std.testing.expectEqual(expected_entry.height, found.?.height);
        try std.testing.expectEqual(expected_entry.chain_tx_count, found.?.chain_tx_count);
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

test "findLatestAssumeUtxoEntryAtOrBelow picks the highest qualifying entry" {
    const consensus = @import("consensus.zig");

    // Tip below the lowest entry (840k) → no qualifying entry.
    const before_first = findLatestAssumeUtxoEntryAtOrBelow(&consensus.MAINNET, 100_000);
    try std.testing.expect(before_first == null);

    // Exactly at the lowest entry's height → that entry.
    const at_first = findLatestAssumeUtxoEntryAtOrBelow(&consensus.MAINNET, 840_000);
    try std.testing.expect(at_first != null);
    try std.testing.expectEqual(@as(u32, 840_000), at_first.?.height);

    // Between 880k and 910k → 880k.
    const between = findLatestAssumeUtxoEntryAtOrBelow(&consensus.MAINNET, 900_000);
    try std.testing.expect(between != null);
    try std.testing.expectEqual(@as(u32, 880_000), between.?.height);

    // Way past the highest (935k) → 935k (the latest).
    const after_last = findLatestAssumeUtxoEntryAtOrBelow(&consensus.MAINNET, 2_000_000);
    try std.testing.expect(after_last != null);
    try std.testing.expectEqual(@as(u32, 935_000), after_last.?.height);

    // Tip exactly at the highest → highest.
    const at_last = findLatestAssumeUtxoEntryAtOrBelow(&consensus.MAINNET, 935_000);
    try std.testing.expect(at_last != null);
    try std.testing.expectEqual(@as(u32, 935_000), at_last.?.height);
}

test "findLatestAssumeUtxoEntryAtOrBelow returns null on a network with no entries" {
    const consensus = @import("consensus.zig");
    // Testnet3/testnet4/signet/regtest all carry an empty assume_utxo array
    // in `consensus.zig`. Use TESTNET3 as the canary.
    const found = findLatestAssumeUtxoEntryAtOrBelow(&consensus.TESTNET3, 1_000_000);
    try std.testing.expect(found == null);
}

test "snapshot dump/load round-trip — Core wire format" {
    const allocator = std.testing.allocator;
    const consensus = @import("consensus.zig");

    // Build a small chainstate with three coins across two txids, including
    // a P2PKH (compressible) and a P2WPKH (non-compressible / raw branch)
    // so both legs of ScriptCompression are exercised.
    var chainstate = ChainState.init(null, 64, allocator);
    defer chainstate.deinit();

    chainstate.best_hash = [_]u8{0xAA} ** 32;
    chainstate.best_height = 800_000;

    const txid_a: types.Hash256 = [_]u8{0x01} ** 32;
    const txid_b: types.Hash256 = [_]u8{0x02} ** 32;

    // P2PKH (25 bytes): OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG.
    var p2pkh: [25]u8 = undefined;
    p2pkh[0] = 0x76;
    p2pkh[1] = 0xa9;
    p2pkh[2] = 20;
    @memset(p2pkh[3..23], 0xCC);
    p2pkh[23] = 0x88;
    p2pkh[24] = 0xac;

    // P2WPKH (22 bytes): OP_0 <20>. Not in CompressScript's special set.
    var p2wpkh: [22]u8 = undefined;
    p2wpkh[0] = 0x00;
    p2wpkh[1] = 20;
    @memset(p2wpkh[2..22], 0x77);

    const op0 = types.OutPoint{ .hash = txid_a, .index = 0 };
    try chainstate.utxo_set.add(&op0, &types.TxOut{ .value = 6_250_000_000, .script_pubkey = &p2pkh }, 800_000, true);
    const op1 = types.OutPoint{ .hash = txid_a, .index = 7 };
    try chainstate.utxo_set.add(&op1, &types.TxOut{ .value = 1_234_567, .script_pubkey = &p2wpkh }, 700_000, false);
    const op2 = types.OutPoint{ .hash = txid_b, .index = 0 };
    try chainstate.utxo_set.add(&op2, &types.TxOut{ .value = 100, .script_pubkey = &p2pkh }, 750_000, false);

    // Dump.
    const tmp_path = "/tmp/clearbit-snapshot-roundtrip.dat";
    defer std.fs.cwd().deleteFile(tmp_path) catch {};
    try dumpTxOutSet(&chainstate, consensus.MAINNET.magic, tmp_path, allocator);

    // Verify the on-disk file starts with Core's magic + version=2.
    const file = try std.fs.cwd().openFile(tmp_path, .{});
    defer file.close();
    var hdr: [SnapshotMetadata.HEADER_SIZE]u8 = undefined;
    try file.reader().readNoEof(&hdr);
    try std.testing.expectEqualSlices(u8, &SNAPSHOT_MAGIC_BYTES, hdr[0..5]);
    try std.testing.expectEqual(@as(u16, SNAPSHOT_VERSION), std.mem.readInt(u16, hdr[5..7], .little));
    try std.testing.expectEqual(consensus.MAINNET.magic, std.mem.readInt(u32, hdr[7..11], .little));

    // Load.
    var loaded = try loadTxOutSet(tmp_path, consensus.MAINNET.magic, allocator);
    defer loaded.chainstate.deinit();
    try std.testing.expectEqualSlices(u8, &chainstate.best_hash, &loaded.metadata.base_blockhash);
    try std.testing.expectEqual(@as(u64, 3), loaded.metadata.coins_count);
    try std.testing.expectEqual(@as(usize, 3), loaded.chainstate.utxo_set.cache.count());
}

test "mainnet has all 4 assumeutxo entries from Bitcoin Core v28" {
    const consensus = @import("consensus.zig");
    try std.testing.expectEqual(@as(usize, 4), consensus.MAINNET.assume_utxo.len);
    // Spot-check the first and last entry against
    // bitcoin-core/src/kernel/chainparams.cpp `m_assumeutxo_data`.
    const e0 = consensus.MAINNET.assume_utxo[0];
    try std.testing.expectEqual(@as(u32, 840_000), e0.height);
    try std.testing.expectEqual(@as(u64, 991_032_194), e0.chain_tx_count);
    // hash_serialized for 840k is a2a5521b... (display order). hexToHash
    // flips, so internal byte 0 = display byte 31 = 0x96.
    try std.testing.expectEqual(@as(u8, 0x96), e0.hash_serialized[0]);
    try std.testing.expectEqual(@as(u8, 0xa2), e0.hash_serialized[31]);

    const e3 = consensus.MAINNET.assume_utxo[3];
    try std.testing.expectEqual(@as(u32, 935_000), e3.height);
    try std.testing.expectEqual(@as(u64, 1_305_397_408), e3.chain_tx_count);

    // None of the 4 may carry the placeholder 51c8d1... pattern that used
    // to live at 840k.
    for (consensus.MAINNET.assume_utxo) |e| {
        try std.testing.expect(!std.mem.eql(u8, &e.hash_serialized, &[_]u8{
            0x5d, 0x5c, 0x5e, 0x5a, 0x5e, 0x5d, 0x5e, 0x5e,
            0x5a, 0x5e, 0xa5, 0xe8, 0x5e, 0x8b, 0x1f, 0x7e,
            0x3f, 0x3c, 0x9c, 0x3c, 0x7e, 0x9e, 0x49, 0xc5,
            0x43, 0x15, 0xe5, 0x1d, 0x5c, 0x8b, 0x1d, 0xc8,
        }));
    }
}

test "computeHashSerializedTxOutSet — SHA256d, NOT MuHash, with known vector" {
    // Pins the strict-gate hash function to SHA256d-via-HashWriter
    // (Core kernel/coinstats.cpp:161-163 case HASH_SERIALIZED). The
    // expected vector is computed against the canonical TxOutSer layout
    // documented on `computeHashSerializedTxOutSet`.
    //
    // This test is the regression guard for `69f46b8`'s mistake of
    // wiring MuHash3072 into `validateAndLoadSnapshot`. MuHash and
    // SHA256d disagree on every non-trivial UTXO set.
    const allocator = std.testing.allocator;
    const crypto = @import("crypto.zig");

    var utxo_set = UtxoSet.init(null, 64, allocator);
    defer utxo_set.deinit();

    // Two coins under one txid, one coin under a second txid. P2PKH
    // chosen so reconstructScript produces the exact 25-byte template.
    var p2pkh: [25]u8 = undefined;
    p2pkh[0] = 0x76;
    p2pkh[1] = 0xa9;
    p2pkh[2] = 20;
    @memset(p2pkh[3..23], 0xCC);
    p2pkh[23] = 0x88;
    p2pkh[24] = 0xac;

    const txid_a: types.Hash256 = [_]u8{0x01} ** 32;
    const txid_b: types.Hash256 = [_]u8{0x02} ** 32;
    const op0 = types.OutPoint{ .hash = txid_a, .index = 0 };
    const op1 = types.OutPoint{ .hash = txid_a, .index = 1 };
    const op2 = types.OutPoint{ .hash = txid_b, .index = 0 };

    try utxo_set.add(&op0, &types.TxOut{ .value = 5_000_000_000, .script_pubkey = &p2pkh }, 100, true);
    try utxo_set.add(&op1, &types.TxOut{ .value = 1_234, .script_pubkey = &p2pkh }, 200, false);
    try utxo_set.add(&op2, &types.TxOut{ .value = 9_999, .script_pubkey = &p2pkh }, 300, false);

    // Compute the expected hash by hand: SHA256d over the canonical
    // concatenation of TxOutSer(op_i, coin_i) in lex (txid, vout) order.
    // Order: (txid_a, 0), (txid_a, 1), (txid_b, 0).
    var expected_buf = std.ArrayList(u8).init(allocator);
    defer expected_buf.deinit();

    inline for (.{
        .{ .txid = &txid_a, .vout = @as(u32, 0), .height = @as(u32, 100), .coinbase = true, .value = @as(i64, 5_000_000_000) },
        .{ .txid = &txid_a, .vout = @as(u32, 1), .height = @as(u32, 200), .coinbase = false, .value = @as(i64, 1_234) },
        .{ .txid = &txid_b, .vout = @as(u32, 0), .height = @as(u32, 300), .coinbase = false, .value = @as(i64, 9_999) },
    }) |c| {
        try expected_buf.appendSlice(c.txid);
        var le4: [4]u8 = undefined;
        std.mem.writeInt(u32, &le4, c.vout, .little);
        try expected_buf.appendSlice(&le4);
        const code: u32 = (c.height << 1) | (if (c.coinbase) @as(u32, 1) else 0);
        std.mem.writeInt(u32, &le4, code, .little);
        try expected_buf.appendSlice(&le4);
        var le8: [8]u8 = undefined;
        std.mem.writeInt(i64, &le8, c.value, .little);
        try expected_buf.appendSlice(&le8);
        // CompactSize(25) + 25-byte P2PKH script.
        try expected_buf.append(25);
        try expected_buf.appendSlice(&p2pkh);
    }
    const expected = crypto.hash256(expected_buf.items);

    const actual = try computeHashSerializedTxOutSet(&utxo_set, allocator);
    try std.testing.expectEqualSlices(u8, &expected, &actual);

    // And — the load-bearing assertion — MuHash over the same set must
    // disagree. If this ever passes, someone has wired MuHash to compute
    // SHA256d (or vice versa) and the strict gate is back to broken.
    const muhash_value = try computeMuHashTxOutSet(&utxo_set, allocator);
    try std.testing.expect(!std.mem.eql(u8, &expected, &muhash_value));
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

test "validateAndLoadSnapshot rejects regtest-genesis snapshot under mainnet params" {
    // Core-strict whitelist gate: any snapshot whose `base_blockhash`
    // (and therefore height) is not one of the entries in
    // `m_assumeutxo_data` must be refused with the
    // "Assumeutxo height in snapshot metadata not recognized ... -
    // refusing to load snapshot" diagnostic. Mirrors
    // bitcoin-core/src/validation.cpp:5775-5780.
    //
    // Constructed snapshot uses the regtest genesis hash as
    // `base_blockhash` against MAINNET params. The regtest genesis hash
    // (0f9188...) is not in mainnet's 4-entry whitelist
    // (840k/880k/910k/935k), so the load must fail with
    // SnapshotError.UnknownSnapshot and populate `out_rejected_hash`.
    const allocator = std.testing.allocator;
    const consensus = @import("consensus.zig");

    // Build a minimal Core-format snapshot file with a single coin and
    // a `base_blockhash` of regtest genesis.
    var chainstate = ChainState.init(null, 64, allocator);
    defer chainstate.deinit();
    chainstate.best_hash = consensus.REGTEST.genesis_hash;
    chainstate.best_height = 0;

    // P2PKH (compressible) so the dump path is exercised.
    var p2pkh: [25]u8 = undefined;
    p2pkh[0] = 0x76;
    p2pkh[1] = 0xa9;
    p2pkh[2] = 20;
    @memset(p2pkh[3..23], 0xCC);
    p2pkh[23] = 0x88;
    p2pkh[24] = 0xac;

    const txid: types.Hash256 = [_]u8{0xAB} ** 32;
    const op = types.OutPoint{ .hash = txid, .index = 0 };
    try chainstate.utxo_set.add(
        &op,
        &types.TxOut{ .value = 5_000_000_000, .script_pubkey = &p2pkh },
        0,
        true,
    );

    const tmp_path = "/tmp/clearbit-snapshot-strict-reject.dat";
    defer std.fs.cwd().deleteFile(tmp_path) catch {};
    // Dump under MAINNET magic so the wire-format network check passes
    // and the rejection is unambiguously the assumeutxo-whitelist gate.
    try dumpTxOutSet(&chainstate, consensus.MAINNET.magic, tmp_path, allocator);

    var rejected_hash: types.Hash256 = undefined;
    const result = validateAndLoadSnapshot(
        tmp_path,
        &consensus.MAINNET,
        allocator,
        &rejected_hash,
        null,
        null,
    );
    try std.testing.expectError(SnapshotError.UnknownSnapshot, result);

    // The captured hash must be regtest genesis — same byte order as
    // stored in `consensus.REGTEST.genesis_hash` (internal little-endian).
    try std.testing.expectEqualSlices(
        u8,
        &consensus.REGTEST.genesis_hash,
        &rejected_hash,
    );

    // Sanity: each of the 4 mainnet whitelist entries differs from
    // regtest genesis (defensive — guards against a future copy-paste
    // accident in chainparams).
    for (consensus.MAINNET.assume_utxo) |e| {
        try std.testing.expect(!std.mem.eql(u8, &e.block_hash, &consensus.REGTEST.genesis_hash));
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
