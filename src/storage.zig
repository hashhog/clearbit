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
/// Provides efficient lookups with a configurable cache size for IBD performance.
pub const UtxoSet = struct {
    db: ?*Database,
    cache: std.AutoHashMap([36]u8, CacheEntry),
    cache_size: usize,
    max_cache_size: usize,
    allocator: std.mem.Allocator,

    // Statistics
    total_utxos: u64,
    total_amount: i64,
    hits: u64,
    misses: u64,

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
        return UtxoSet{
            .db = db,
            .cache = std.AutoHashMap([36]u8, CacheEntry).init(allocator),
            .cache_size = 0,
            .max_cache_size = max_cache_mb * 1024 * 1024,
            .allocator = allocator,
            .total_utxos = 0,
            .total_amount = 0,
            .hits = 0,
            .misses = 0,
        };
    }

    pub fn deinit(self: *UtxoSet) void {
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            var cache_entry = entry.value_ptr.*;
            cache_entry.deinit(self.allocator);
        }
        self.cache.deinit();
    }

    /// Look up a UTXO by outpoint.
    pub fn get(self: *UtxoSet, outpoint: *const types.OutPoint) !?CompactUtxo {
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

        // Store in cache (marked dirty for eventual flush to DB)
        try self.cache.put(key, CacheEntry{ .utxo = compact, .dirty = true });

        self.total_utxos += 1;
        self.total_amount += output.value;
    }

    /// Remove a UTXO (spend it). Returns the spent UTXO for undo data.
    pub fn spend(self: *UtxoSet, outpoint: *const types.OutPoint) !?CompactUtxo {
        const key = makeUtxoKey(outpoint);

        // Try to get from cache first
        if (self.cache.fetchRemove(key)) |old| {
            self.total_utxos -= 1;
            self.total_amount -= old.value.utxo.value;

            // Delete from DB if we have one
            if (self.db) |db| {
                db.delete(CF_UTXO, &key) catch {};
            }

            return old.value.utxo;
        }

        // Not in cache, try database
        if (self.db) |db| {
            const data = db.get(CF_UTXO, &key) catch return null;
            if (data == null) return null;
            defer self.allocator.free(data.?);

            const utxo = try CompactUtxo.decode(data.?, self.allocator);

            // Delete from database
            db.delete(CF_UTXO, &key) catch {};

            self.total_utxos -= 1;
            self.total_amount -= utxo.value;

            return utxo;
        }

        return null;
    }

    /// Flush the dirty cache entries to disk.
    pub fn flush(self: *UtxoSet) !void {
        if (self.db == null) return;

        var batch = std.ArrayList(BatchOp).init(self.allocator);
        defer batch.deinit();

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
                entry.value_ptr.dirty = false;
            }
        }

        if (batch.items.len > 0) {
            self.db.?.writeBatch(batch.items) catch {};

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

    /// Get cache hit rate.
    pub fn hitRate(self: *const UtxoSet) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }

    /// Get approximate cache memory usage.
    pub fn cacheMemoryUsage(self: *const UtxoSet) usize {
        // Rough estimate: key (36) + value overhead (~50 per entry)
        return self.cache.count() * 86;
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
    /// If data_dir is provided, undo data will be persisted to rev*.dat files.
    pub fn init(db: ?*Database, allocator: std.mem.Allocator) ChainState {
        return ChainState{
            .best_hash = [_]u8{0} ** 32,
            .best_height = 0,
            .total_work = [_]u8{0} ** 32,
            .utxo_set = UtxoSet.init(db, 450, allocator), // 450 MB UTXO cache
            .undo_manager = null,
            .allocator = allocator,
        };
    }

    /// Initialize chain state with undo file persistence.
    pub fn initWithUndo(db: ?*Database, data_dir: []const u8, allocator: std.mem.Allocator) ChainState {
        return ChainState{
            .best_hash = [_]u8{0} ** 32,
            .best_height = 0,
            .total_work = [_]u8{0} ** 32,
            .utxo_set = UtxoSet.init(db, 450, allocator),
            .undo_manager = UndoFileManager.init(data_dir, allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ChainState) void {
        self.utxo_set.deinit();
    }

    /// Connect a block: spend inputs, create outputs, save undo data.
    pub fn connectBlock(
        self: *ChainState,
        block: *const types.Block,
        hash: *const types.Hash256,
        height: u32,
    ) !BlockUndo {
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
            const tx_hash = try crypto.computeTxid(&tx, self.allocator);

            // Spend inputs (skip coinbase)
            if (tx_idx > 0) {
                for (tx.inputs) |input| {
                    const spent = try self.utxo_set.spend(&input.previous_output)
                        orelse return error.MissingInput;
                    try spent_list.append(.{
                        .outpoint = input.previous_output,
                        .utxo = spent,
                    });
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
                try created_list.append(outpoint);
            }
        }

        self.best_hash = hash.*;
        self.best_height = height;

        return BlockUndo{
            .spent_utxos = try spent_list.toOwnedSlice(),
            .created_outpoints = try created_list.toOwnedSlice(),
        };
    }

    /// Disconnect a block (reorg): reverse UTXO changes using undo data.
    pub fn disconnectBlock(self: *ChainState, undo: *const BlockUndo, prev_hash: types.Hash256) !void {
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

    /// Flush UTXO set to disk.
    pub fn flush(self: *ChainState) !void {
        try self.utxo_set.flush();
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

    var chain_state = ChainState.init(null, allocator);
    defer chain_state.deinit();

    try std.testing.expectEqual(@as(u32, 0), chain_state.best_height);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &chain_state.best_hash);
}

test "chain state connect block creates utxos" {
    const allocator = std.testing.allocator;

    var chain_state = ChainState.init(null, allocator);
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

    var chain_state = ChainState.init(null, allocator);
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
    var chain_state1 = ChainState.init(null, allocator);
    defer chain_state1.deinit();
    try std.testing.expect(chain_state1.undo_manager == null);

    // Test init with undo (has undo manager)
    var chain_state2 = ChainState.initWithUndo(null, "/tmp/testdata", allocator);
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

    var chain_state = ChainState.init(null, allocator);
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
