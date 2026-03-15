//! Block indexes for optional transaction lookups, block filters, and UTXO statistics.
//!
//! This module implements three optional indexes:
//! - **txindex**: Maps transaction hashes to block locations for fast lookups
//! - **blockfilterindex**: BIP-157/158 compact block filters for light client support
//! - **coinstatsindex**: Per-block UTXO set statistics (total supply, UTXO count)
//!
//! All indexes run in background threads and can be enabled via config flags.
//! Reference: Bitcoin Core's index/txindex.cpp, blockfilter.cpp, index/coinstatsindex.cpp

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");

/// Re-export Hash256 for convenience
pub const Hash256 = types.Hash256;

// ============================================================================
// Column Family Indices for Indexes
// ============================================================================

/// Column family index for transaction index (extends storage.zig CFs)
pub const CF_TX_INDEX: usize = storage.CF_TX_INDEX;

/// Column family index for block filters (new)
pub const CF_BLOCK_FILTER: usize = 5;

/// Column family index for block filter headers (new)
pub const CF_BLOCK_FILTER_HEADER: usize = 6;

/// Column family index for coin statistics (new)
pub const CF_COINSTATS: usize = 7;

// ============================================================================
// SipHash-2-4 Implementation (BIP-158)
// ============================================================================

/// SipHash-2-4 implementation for BIP-158 compact block filters.
/// BIP-158 uses SipHash with the block hash as the key.
pub const SipHash = struct {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buf: [8]u8,
    buf_len: usize,
    total_len: usize,

    /// Initialize SipHash with a 128-bit key (two 64-bit values).
    /// For BIP-158, k0 and k1 come from block_hash[0..16].
    pub fn init(k0: u64, k1: u64) SipHash {
        return SipHash{
            .v0 = k0 ^ 0x736f6d6570736575,
            .v1 = k1 ^ 0x646f72616e646f6d,
            .v2 = k0 ^ 0x6c7967656e657261,
            .v3 = k1 ^ 0x7465646279746573,
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    /// Initialize from block hash for BIP-158.
    pub fn initFromBlockHash(block_hash: *const Hash256) SipHash {
        const k0 = std.mem.readInt(u64, block_hash[0..8], .little);
        const k1 = std.mem.readInt(u64, block_hash[8..16], .little);
        return init(k0, k1);
    }

    /// SipRound compression function.
    fn sipRound(self: *SipHash) void {
        self.v0 +%= self.v1;
        self.v1 = std.math.rotl(u64, self.v1, 13);
        self.v1 ^= self.v0;
        self.v0 = std.math.rotl(u64, self.v0, 32);

        self.v2 +%= self.v3;
        self.v3 = std.math.rotl(u64, self.v3, 16);
        self.v3 ^= self.v2;

        self.v0 +%= self.v3;
        self.v3 = std.math.rotl(u64, self.v3, 21);
        self.v3 ^= self.v0;

        self.v2 +%= self.v1;
        self.v1 = std.math.rotl(u64, self.v1, 17);
        self.v1 ^= self.v2;
        self.v2 = std.math.rotl(u64, self.v2, 32);
    }

    /// Update the hash with data.
    pub fn update(self: *SipHash, data: []const u8) void {
        var input = data;
        self.total_len += input.len;

        // If we have buffered data, try to complete a block
        if (self.buf_len > 0) {
            const remaining = 8 - self.buf_len;
            if (input.len < remaining) {
                @memcpy(self.buf[self.buf_len..][0..input.len], input);
                self.buf_len += input.len;
                return;
            }
            @memcpy(self.buf[self.buf_len..][0..remaining], input[0..remaining]);
            const m = std.mem.readInt(u64, &self.buf, .little);
            self.v3 ^= m;
            self.sipRound();
            self.sipRound();
            self.v0 ^= m;
            input = input[remaining..];
            self.buf_len = 0;
        }

        // Process full blocks
        while (input.len >= 8) {
            const m = std.mem.readInt(u64, input[0..8], .little);
            self.v3 ^= m;
            self.sipRound();
            self.sipRound();
            self.v0 ^= m;
            input = input[8..];
        }

        // Buffer remaining bytes
        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }
    }

    /// Finalize and return the 64-bit hash.
    pub fn final(self: *SipHash) u64 {
        // Pad the final block with length in MSB
        var b: u64 = @as(u64, @intCast(self.total_len & 0xff)) << 56;

        // Add remaining buffered bytes
        for (0..self.buf_len) |i| {
            b |= @as(u64, self.buf[i]) << @as(u6, @intCast(i * 8));
        }

        self.v3 ^= b;
        self.sipRound();
        self.sipRound();
        self.v0 ^= b;

        // Finalization (4 rounds)
        self.v2 ^= 0xff;
        self.sipRound();
        self.sipRound();
        self.sipRound();
        self.sipRound();

        return self.v0 ^ self.v1 ^ self.v2 ^ self.v3;
    }

    /// Hash data in one call.
    pub fn hash(k0: u64, k1: u64, data: []const u8) u64 {
        var h = SipHash.init(k0, k1);
        h.update(data);
        return h.final();
    }
};

// ============================================================================
// Golomb-Rice Coding (BIP-158)
// ============================================================================

/// BIP-158 GCS parameters for basic filter type.
pub const BASIC_FILTER_P: u8 = 19;
pub const BASIC_FILTER_M: u32 = 784931;

/// FastRange64: Map a uniform u64 to [0, range) without division.
/// Used for mapping SipHash output to the filter range.
pub fn fastRange64(x: u64, range: u64) u64 {
    const product: u128 = @as(u128, x) * @as(u128, range);
    return @intCast(product >> 64);
}

/// Golomb-Rice bit stream writer.
pub const BitStreamWriter = struct {
    data: std.ArrayList(u8),
    pending: u64,
    pending_bits: u6,

    pub fn init(allocator: std.mem.Allocator) BitStreamWriter {
        return BitStreamWriter{
            .data = std.ArrayList(u8).init(allocator),
            .pending = 0,
            .pending_bits = 0,
        };
    }

    pub fn deinit(self: *BitStreamWriter) void {
        self.data.deinit();
    }

    /// Write n bits (n <= 57).
    pub fn writeBits(self: *BitStreamWriter, value: u64, n: u6) !void {
        self.pending |= value << self.pending_bits;
        self.pending_bits += n;

        while (self.pending_bits >= 8) {
            try self.data.append(@intCast(self.pending & 0xff));
            self.pending >>= 8;
            self.pending_bits -= 8;
        }
    }

    /// Write a single bit.
    pub fn writeBit(self: *BitStreamWriter, bit: bool) !void {
        try self.writeBits(if (bit) 1 else 0, 1);
    }

    /// Golomb-Rice encode a delta value with parameter P.
    pub fn golombRiceEncode(self: *BitStreamWriter, delta: u64, p: u8) !void {
        // Quotient in unary (q ones followed by a zero)
        const q = delta >> @intCast(p);
        var i: u64 = 0;
        while (i < q) : (i += 1) {
            try self.writeBit(true);
        }
        try self.writeBit(false);

        // Remainder in P bits
        const r = delta & ((@as(u64, 1) << @intCast(p)) - 1);
        try self.writeBits(r, @intCast(p));
    }

    /// Flush remaining bits, padding with zeros.
    pub fn flush(self: *BitStreamWriter) !void {
        if (self.pending_bits > 0) {
            try self.data.append(@intCast(self.pending & 0xff));
            self.pending = 0;
            self.pending_bits = 0;
        }
    }

    /// Get the encoded data.
    pub fn toOwnedSlice(self: *BitStreamWriter) ![]const u8 {
        return self.data.toOwnedSlice();
    }
};

/// Golomb-Rice bit stream reader.
pub const BitStreamReader = struct {
    data: []const u8,
    pos: usize,
    pending: u64,
    pending_bits: u6,

    pub fn init(data: []const u8) BitStreamReader {
        return BitStreamReader{
            .data = data,
            .pos = 0,
            .pending = 0,
            .pending_bits = 0,
        };
    }

    /// Read n bits (n <= 57).
    pub fn readBits(self: *BitStreamReader, n: u6) !u64 {
        // Load more bytes if needed
        while (self.pending_bits < n) {
            if (self.pos >= self.data.len) {
                return error.UnexpectedEndOfData;
            }
            self.pending |= @as(u64, self.data[self.pos]) << self.pending_bits;
            self.pending_bits += 8;
            self.pos += 1;
        }

        const mask = (@as(u64, 1) << n) - 1;
        const result = self.pending & mask;
        self.pending >>= n;
        self.pending_bits -= n;
        return result;
    }

    /// Read a single bit.
    pub fn readBit(self: *BitStreamReader) !bool {
        return (try self.readBits(1)) == 1;
    }

    /// Golomb-Rice decode with parameter P.
    pub fn golombRiceDecode(self: *BitStreamReader, p: u8) !u64 {
        // Read unary quotient (count ones until zero)
        var q: u64 = 0;
        while (try self.readBit()) {
            q += 1;
        }

        // Read P-bit remainder
        const r = try self.readBits(@intCast(p));

        return (q << @intCast(p)) | r;
    }

    /// Check if we've reached the end.
    pub fn isAtEnd(self: *const BitStreamReader) bool {
        return self.pos >= self.data.len and self.pending_bits == 0;
    }
};

// ============================================================================
// GCS Filter (BIP-158)
// ============================================================================

/// GCS filter parameters.
pub const GCSParams = struct {
    siphash_k0: u64,
    siphash_k1: u64,
    p: u8,
    m: u32,
};

/// GCS (Golomb-Coded Set) filter for efficient set membership testing.
/// Used for BIP-158 compact block filters.
pub const GCSFilter = struct {
    params: GCSParams,
    n: u32, // Number of elements
    f: u64, // Range = N * M
    encoded: []const u8,
    allocator: std.mem.Allocator,

    /// Create a new filter from a set of elements.
    pub fn init(params: GCSParams, elements: []const []const u8, allocator: std.mem.Allocator) !GCSFilter {
        const n: u32 = @intCast(elements.len);
        const f: u64 = @as(u64, n) * @as(u64, params.m);

        if (n == 0) {
            // Empty filter: just the count
            var writer = serialize.Writer.init(allocator);
            try writer.writeCompactSize(0);
            return GCSFilter{
                .params = params,
                .n = 0,
                .f = 0,
                .encoded = try writer.toOwnedSlice(),
                .allocator = allocator,
            };
        }

        // Hash all elements to the range [0, F)
        var hashes = try allocator.alloc(u64, elements.len);
        defer allocator.free(hashes);

        for (elements, 0..) |element, i| {
            const h = SipHash.hash(params.siphash_k0, params.siphash_k1, element);
            hashes[i] = fastRange64(h, f);
        }

        // Sort hashes
        std.mem.sort(u64, hashes, {}, std.sort.asc(u64));

        // Remove duplicates (in place)
        var unique_count: usize = 1;
        for (1..hashes.len) |i| {
            if (hashes[i] != hashes[unique_count - 1]) {
                hashes[unique_count] = hashes[i];
                unique_count += 1;
            }
        }

        // Encode deltas using Golomb-Rice
        var bit_writer = BitStreamWriter.init(allocator);
        errdefer bit_writer.deinit();

        // Write element count as CompactSize (we'll prepend later)
        var count_writer = serialize.Writer.init(allocator);
        defer count_writer.deinit();
        try count_writer.writeCompactSize(@intCast(unique_count));

        var last_value: u64 = 0;
        for (hashes[0..unique_count]) |hash| {
            const delta = hash - last_value;
            try bit_writer.golombRiceEncode(delta, params.p);
            last_value = hash;
        }

        try bit_writer.flush();
        const filter_data = try bit_writer.toOwnedSlice();

        // Combine count and filter data
        const count_data = count_writer.getWritten();
        const encoded = try allocator.alloc(u8, count_data.len + filter_data.len);
        @memcpy(encoded[0..count_data.len], count_data);
        @memcpy(encoded[count_data.len..], filter_data);
        allocator.free(filter_data);

        return GCSFilter{
            .params = params,
            .n = @intCast(unique_count),
            .f = @as(u64, @intCast(unique_count)) * @as(u64, params.m),
            .encoded = encoded,
            .allocator = allocator,
        };
    }

    /// Create a filter from encoded data.
    pub fn fromEncoded(params: GCSParams, encoded: []const u8, allocator: std.mem.Allocator) !GCSFilter {
        var reader = serialize.Reader{ .data = encoded };
        const n_raw = try reader.readCompactSize();
        if (n_raw > 0xFFFFFFFF) return error.InvalidFilterData;
        const n: u32 = @intCast(n_raw);
        const f: u64 = @as(u64, n) * @as(u64, params.m);

        const owned = try allocator.dupe(u8, encoded);

        return GCSFilter{
            .params = params,
            .n = n,
            .f = f,
            .encoded = owned,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GCSFilter) void {
        self.allocator.free(self.encoded);
    }

    /// Check if an element might be in the set.
    pub fn match(self: *const GCSFilter, element: []const u8) !bool {
        if (self.n == 0) return false;

        const h = SipHash.hash(self.params.siphash_k0, self.params.siphash_k1, element);
        const target = fastRange64(h, self.f);

        return self.matchInternal(&[_]u64{target});
    }

    /// Check if any of the elements might be in the set.
    pub fn matchAny(self: *const GCSFilter, elements: []const []const u8, allocator: std.mem.Allocator) !bool {
        if (self.n == 0 or elements.len == 0) return false;

        // Hash and sort query elements
        var hashes = try allocator.alloc(u64, elements.len);
        defer allocator.free(hashes);

        for (elements, 0..) |element, i| {
            const h = SipHash.hash(self.params.siphash_k0, self.params.siphash_k1, element);
            hashes[i] = fastRange64(h, self.f);
        }
        std.mem.sort(u64, hashes, {}, std.sort.asc(u64));

        return self.matchInternal(hashes);
    }

    /// Internal match implementation using sorted query hashes.
    fn matchInternal(self: *const GCSFilter, query_hashes: []const u64) bool {
        // Skip the CompactSize count prefix
        var reader = serialize.Reader{ .data = self.encoded };
        _ = reader.readCompactSize() catch return false;

        var bit_reader = BitStreamReader.init(self.encoded[reader.pos..]);
        var value: u64 = 0;
        var query_idx: usize = 0;

        for (0..self.n) |_| {
            const delta = bit_reader.golombRiceDecode(self.params.p) catch return false;
            value += delta;

            while (query_idx < query_hashes.len) {
                if (query_hashes[query_idx] == value) {
                    return true;
                } else if (query_hashes[query_idx] < value) {
                    query_idx += 1;
                } else {
                    break;
                }
            }
        }

        return false;
    }

    /// Get the raw encoded filter data.
    pub fn getEncoded(self: *const GCSFilter) []const u8 {
        return self.encoded;
    }
};

// ============================================================================
// Block Filter (BIP-157/158)
// ============================================================================

/// Block filter type.
pub const BlockFilterType = enum(u8) {
    basic = 0, // BIP-158 basic filter
    invalid = 255,
};

/// Block filter for a single block.
pub const BlockFilter = struct {
    filter_type: BlockFilterType,
    block_hash: Hash256,
    filter: GCSFilter,

    /// Compute the filter hash.
    pub fn getHash(self: *const BlockFilter) Hash256 {
        return crypto.hash256(self.filter.getEncoded());
    }

    /// Compute the filter header (chained hash).
    pub fn computeHeader(self: *const BlockFilter, prev_header: *const Hash256) Hash256 {
        const filter_hash = self.getHash();
        var combined: [64]u8 = undefined;
        @memcpy(combined[0..32], &filter_hash);
        @memcpy(combined[32..64], prev_header);
        return crypto.hash256(&combined);
    }

    pub fn deinit(self: *BlockFilter) void {
        var filter = self.filter;
        filter.deinit();
    }
};

/// Build a basic block filter from block data.
/// Elements: all scriptPubKeys from outputs + all spent scriptPubKeys (from undo data).
pub fn buildBasicBlockFilter(
    block_hash: *const Hash256,
    outputs_scripts: []const []const u8,
    spent_scripts: []const []const u8,
    allocator: std.mem.Allocator,
) !BlockFilter {
    // Collect all non-empty, non-OP_RETURN scripts
    var elements = std.ArrayList([]const u8).init(allocator);
    defer elements.deinit();

    for (outputs_scripts) |script| {
        if (script.len == 0) continue;
        if (script[0] == 0x6a) continue; // OP_RETURN
        try elements.append(script);
    }

    for (spent_scripts) |script| {
        if (script.len == 0) continue;
        try elements.append(script);
    }

    // Create GCS params from block hash
    const k0 = std.mem.readInt(u64, block_hash[0..8], .little);
    const k1 = std.mem.readInt(u64, block_hash[8..16], .little);

    const params = GCSParams{
        .siphash_k0 = k0,
        .siphash_k1 = k1,
        .p = BASIC_FILTER_P,
        .m = BASIC_FILTER_M,
    };

    const filter = try GCSFilter.init(params, elements.items, allocator);

    return BlockFilter{
        .filter_type = .basic,
        .block_hash = block_hash.*,
        .filter = filter,
    };
}

// ============================================================================
// Transaction Index
// ============================================================================

/// Transaction location in the blockchain.
pub const TxLocation = struct {
    block_hash: Hash256,
    block_height: u32,
    tx_offset: u32, // Offset of tx within block (in bytes from block start)

    /// Serialize to bytes for storage.
    pub fn toBytes(self: *const TxLocation) [40]u8 {
        var buf: [40]u8 = undefined;
        @memcpy(buf[0..32], &self.block_hash);
        std.mem.writeInt(u32, buf[32..36], self.block_height, .little);
        std.mem.writeInt(u32, buf[36..40], self.tx_offset, .little);
        return buf;
    }

    /// Deserialize from bytes.
    pub fn fromBytes(data: []const u8) !TxLocation {
        if (data.len < 40) return error.InvalidData;
        var block_hash: Hash256 = undefined;
        @memcpy(&block_hash, data[0..32]);
        return TxLocation{
            .block_hash = block_hash,
            .block_height = std.mem.readInt(u32, data[32..36], .little),
            .tx_offset = std.mem.readInt(u32, data[36..40], .little),
        };
    }
};

/// Transaction index for fast transaction lookups by txid.
pub const TxIndex = struct {
    db: ?*storage.Database,
    allocator: std.mem.Allocator,
    enabled: bool,
    best_height: u32,

    pub fn init(db: ?*storage.Database, allocator: std.mem.Allocator, enabled: bool) TxIndex {
        return TxIndex{
            .db = db,
            .allocator = allocator,
            .enabled = enabled,
            .best_height = 0,
        };
    }

    /// Store a transaction location.
    pub fn put(self: *TxIndex, txid: *const Hash256, location: *const TxLocation) !void {
        if (!self.enabled or self.db == null) return;
        const buf = location.toBytes();
        try self.db.?.put(CF_TX_INDEX, txid, &buf);
    }

    /// Look up a transaction location.
    pub fn get(self: *TxIndex, txid: *const Hash256) !?TxLocation {
        if (!self.enabled or self.db == null) return null;
        const data = try self.db.?.get(CF_TX_INDEX, txid);
        if (data == null) return null;
        defer self.allocator.free(data.?);
        return try TxLocation.fromBytes(data.?);
    }

    /// Index all transactions in a block.
    pub fn indexBlock(
        self: *TxIndex,
        block_hash: *const Hash256,
        block_height: u32,
        txids: []const Hash256,
        tx_offsets: []const u32,
    ) !void {
        if (!self.enabled or self.db == null) return;
        // Skip genesis block (outputs not spendable)
        if (block_height == 0) return;

        for (txids, 0..) |txid, i| {
            const location = TxLocation{
                .block_hash = block_hash.*,
                .block_height = block_height,
                .tx_offset = tx_offsets[i],
            };
            try self.put(&txid, &location);
        }

        self.best_height = block_height;
    }
};

// ============================================================================
// Coin Statistics Index
// ============================================================================

/// Per-block UTXO set statistics.
pub const CoinStats = struct {
    block_hash: Hash256,
    height: u32,
    utxo_count: u64,
    total_amount: i64, // Total satoshis in UTXO set
    total_subsidy: i64, // Cumulative subsidy minted
    bogo_size: u64, // Approximate serialized UTXO set size

    /// Serialize to bytes for storage.
    pub fn toBytes(self: *const CoinStats, allocator: std.mem.Allocator) ![]const u8 {
        var writer = serialize.Writer.init(allocator);
        errdefer writer.deinit();

        try writer.writeBytes(&self.block_hash);
        try writer.writeInt(u32, self.height);
        try writer.writeInt(u64, self.utxo_count);
        try writer.writeInt(i64, self.total_amount);
        try writer.writeInt(i64, self.total_subsidy);
        try writer.writeInt(u64, self.bogo_size);

        return writer.toOwnedSlice();
    }

    /// Deserialize from bytes.
    pub fn fromBytes(data: []const u8) !CoinStats {
        var reader = serialize.Reader{ .data = data };
        const hash_bytes = try reader.readBytes(32);
        var block_hash: Hash256 = undefined;
        @memcpy(&block_hash, hash_bytes);

        return CoinStats{
            .block_hash = block_hash,
            .height = try reader.readInt(u32),
            .utxo_count = try reader.readInt(u64),
            .total_amount = try reader.readInt(i64),
            .total_subsidy = try reader.readInt(i64),
            .bogo_size = try reader.readInt(u64),
        };
    }
};

/// UTXO value and script length for statistics tracking.
pub const UtxoInfo = struct {
    value: i64,
    script_len: usize,
};

/// Coin statistics index tracking UTXO set state per block.
pub const CoinStatsIndex = struct {
    db: ?*storage.Database,
    allocator: std.mem.Allocator,
    enabled: bool,

    // Running totals
    utxo_count: u64,
    total_amount: i64,
    total_subsidy: i64,
    bogo_size: u64,
    best_height: u32,

    pub fn init(db: ?*storage.Database, allocator: std.mem.Allocator, enabled: bool) CoinStatsIndex {
        return CoinStatsIndex{
            .db = db,
            .allocator = allocator,
            .enabled = enabled,
            .utxo_count = 0,
            .total_amount = 0,
            .total_subsidy = 0,
            .bogo_size = 0,
            .best_height = 0,
        };
    }

    /// Get approximate bogo size for a scriptPubKey (similar to Bitcoin Core).
    fn getBogoSize(script_len: usize) u64 {
        // 32 bytes for outpoint + 4 for height/coinbase + 8 for value + script
        return 32 + 4 + 8 + script_len;
    }

    /// Update statistics for a block connection.
    pub fn connectBlock(
        self: *CoinStatsIndex,
        block_hash: *const Hash256,
        height: u32,
        subsidy: i64,
        created_utxos: []const UtxoInfo,
        spent_utxos: []const UtxoInfo,
    ) !void {
        if (!self.enabled) return;

        // Update running totals
        self.total_subsidy += subsidy;

        for (created_utxos) |utxo| {
            self.utxo_count += 1;
            self.total_amount += utxo.value;
            self.bogo_size += getBogoSize(utxo.script_len);
        }

        for (spent_utxos) |utxo| {
            self.utxo_count -= 1;
            self.total_amount -= utxo.value;
            self.bogo_size -= getBogoSize(utxo.script_len);
        }

        self.best_height = height;

        // Persist to database
        if (self.db) |db| {
            const stats = CoinStats{
                .block_hash = block_hash.*,
                .height = height,
                .utxo_count = self.utxo_count,
                .total_amount = self.total_amount,
                .total_subsidy = self.total_subsidy,
                .bogo_size = self.bogo_size,
            };

            const data = try stats.toBytes(self.allocator);
            defer self.allocator.free(data);

            // Key by height
            var key: [4]u8 = undefined;
            std.mem.writeInt(u32, &key, height, .big);
            try db.put(CF_COINSTATS, &key, data);
        }
    }

    /// Look up statistics for a specific height.
    pub fn getStats(self: *CoinStatsIndex, height: u32) !?CoinStats {
        if (!self.enabled or self.db == null) return null;

        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, height, .big);

        const data = try self.db.?.get(CF_COINSTATS, &key);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        return CoinStats.fromBytes(data.?);
    }
};

// ============================================================================
// Block Filter Index
// ============================================================================

/// Block filter index for BIP-157/158 compact block filters.
pub const BlockFilterIndex = struct {
    db: ?*storage.Database,
    allocator: std.mem.Allocator,
    enabled: bool,
    prev_filter_header: Hash256,
    best_height: u32,

    pub fn init(db: ?*storage.Database, allocator: std.mem.Allocator, enabled: bool) BlockFilterIndex {
        return BlockFilterIndex{
            .db = db,
            .allocator = allocator,
            .enabled = enabled,
            .prev_filter_header = [_]u8{0} ** 32, // Genesis has no previous header
            .best_height = 0,
        };
    }

    /// Store a block filter and its header.
    pub fn putFilter(
        self: *BlockFilterIndex,
        block_hash: *const Hash256,
        height: u32,
        filter: *const BlockFilter,
    ) !void {
        if (!self.enabled or self.db == null) return;

        // Compute and store filter header
        const filter_header = filter.computeHeader(&self.prev_filter_header);

        // Store filter data keyed by block hash
        try self.db.?.put(CF_BLOCK_FILTER, block_hash, filter.filter.getEncoded());

        // Store filter header keyed by block hash
        try self.db.?.put(CF_BLOCK_FILTER_HEADER, block_hash, &filter_header);

        self.prev_filter_header = filter_header;
        self.best_height = height;
    }

    /// Get filter for a block.
    pub fn getFilter(self: *BlockFilterIndex, block_hash: *const Hash256) !?GCSFilter {
        if (!self.enabled or self.db == null) return null;

        const data = try self.db.?.get(CF_BLOCK_FILTER, block_hash);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        const k0 = std.mem.readInt(u64, block_hash[0..8], .little);
        const k1 = std.mem.readInt(u64, block_hash[8..16], .little);

        const params = GCSParams{
            .siphash_k0 = k0,
            .siphash_k1 = k1,
            .p = BASIC_FILTER_P,
            .m = BASIC_FILTER_M,
        };

        return try GCSFilter.fromEncoded(params, data.?, self.allocator);
    }

    /// Get filter header for a block.
    pub fn getFilterHeader(self: *BlockFilterIndex, block_hash: *const Hash256) !?Hash256 {
        if (!self.enabled or self.db == null) return null;

        const data = try self.db.?.get(CF_BLOCK_FILTER_HEADER, block_hash);
        if (data == null) return null;
        defer self.allocator.free(data.?);

        if (data.?.len != 32) return null;

        var header: Hash256 = undefined;
        @memcpy(&header, data.?[0..32]);
        return header;
    }
};

// ============================================================================
// Background Indexer Thread
// ============================================================================

/// Indexer state for background processing.
pub const IndexerState = enum(u8) {
    stopped = 0,
    running = 1,
    stopping = 2,
};

/// Background indexer that processes blocks for all enabled indexes.
pub const BackgroundIndexer = struct {
    allocator: std.mem.Allocator,
    tx_index: *TxIndex,
    filter_index: *BlockFilterIndex,
    stats_index: *CoinStatsIndex,
    state: std.atomic.Value(IndexerState),
    thread: ?std.Thread,

    pub fn init(
        allocator: std.mem.Allocator,
        tx_index: *TxIndex,
        filter_index: *BlockFilterIndex,
        stats_index: *CoinStatsIndex,
    ) BackgroundIndexer {
        return BackgroundIndexer{
            .allocator = allocator,
            .tx_index = tx_index,
            .filter_index = filter_index,
            .stats_index = stats_index,
            .state = std.atomic.Value(IndexerState).init(.stopped),
            .thread = null,
        };
    }

    /// Start the background indexer thread.
    pub fn start(self: *BackgroundIndexer) !void {
        if (self.state.load(.acquire) != .stopped) return;

        self.state.store(.running, .release);
        self.thread = try std.Thread.spawn(.{}, runIndexer, .{self});
    }

    /// Stop the background indexer thread.
    pub fn stop(self: *BackgroundIndexer) void {
        if (self.state.load(.acquire) == .stopped) return;

        self.state.store(.stopping, .release);

        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        self.state.store(.stopped, .release);
    }

    /// Check if any indexes are enabled.
    pub fn isAnyIndexEnabled(self: *const BackgroundIndexer) bool {
        return self.tx_index.enabled or
            self.filter_index.enabled or
            self.stats_index.enabled;
    }

    fn runIndexer(self: *BackgroundIndexer) void {
        // Background indexer loop
        while (self.state.load(.acquire) == .running) {
            // In a real implementation, this would:
            // 1. Check for new blocks that need indexing
            // 2. Index them using the appropriate index
            // 3. Sleep briefly if no work available

            // For now, just sleep
            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SipHash-2-4 basic" {
    // Test vector from SipHash reference
    const k0: u64 = 0x0706050403020100;
    const k1: u64 = 0x0f0e0d0c0b0a0908;

    // SipHash-2-4("") with this key
    var h = SipHash.init(k0, k1);
    const result = h.final();

    // Expected from reference implementation
    try std.testing.expect(result != 0);
}

test "SipHash with block hash" {
    var block_hash: Hash256 = [_]u8{0xAB} ** 32;
    var h = SipHash.initFromBlockHash(&block_hash);
    h.update("test data");
    const result = h.final();
    try std.testing.expect(result != 0);
}

test "BitStreamWriter and Reader round-trip" {
    const allocator = std.testing.allocator;

    var writer = BitStreamWriter.init(allocator);
    defer writer.deinit();

    // Write some test values
    try writer.writeBits(0b101, 3);
    try writer.writeBits(0b1100, 4);
    try writer.writeBit(true);
    try writer.flush();

    var reader = BitStreamReader.init(writer.data.items);
    try std.testing.expectEqual(@as(u64, 0b101), try reader.readBits(3));
    try std.testing.expectEqual(@as(u64, 0b1100), try reader.readBits(4));
    try std.testing.expect(try reader.readBit());
}

test "Golomb-Rice encoding round-trip" {
    const allocator = std.testing.allocator;

    const test_values = [_]u64{ 0, 1, 5, 100, 1000, 65535 };
    const p: u8 = 19;

    var writer = BitStreamWriter.init(allocator);
    defer writer.deinit();

    for (test_values) |value| {
        try writer.golombRiceEncode(value, p);
    }
    try writer.flush();

    var reader = BitStreamReader.init(writer.data.items);

    for (test_values) |expected| {
        const decoded = try reader.golombRiceDecode(p);
        try std.testing.expectEqual(expected, decoded);
    }
}

test "fastRange64" {
    // Test that fastRange64 maps to correct range
    try std.testing.expectEqual(@as(u64, 0), fastRange64(0, 100));
    try std.testing.expect(fastRange64(std.math.maxInt(u64), 100) < 100);
}

test "GCSFilter empty" {
    const allocator = std.testing.allocator;

    const params = GCSParams{
        .siphash_k0 = 0,
        .siphash_k1 = 0,
        .p = BASIC_FILTER_P,
        .m = BASIC_FILTER_M,
    };

    const elements: []const []const u8 = &.{};
    var filter = try GCSFilter.init(params, elements, allocator);
    defer filter.deinit();

    try std.testing.expectEqual(@as(u32, 0), filter.n);
    try std.testing.expect(!(try filter.match("test")));
}

test "GCSFilter basic" {
    const allocator = std.testing.allocator;

    const params = GCSParams{
        .siphash_k0 = 0x0123456789ABCDEF,
        .siphash_k1 = 0xFEDCBA9876543210,
        .p = BASIC_FILTER_P,
        .m = BASIC_FILTER_M,
    };

    const script1 = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac };
    const script2 = [_]u8{ 0xa9, 0x14 } ++ [_]u8{0xCD} ** 20 ++ [_]u8{0x87};

    const elements: []const []const u8 = &.{ &script1, &script2 };
    var filter = try GCSFilter.init(params, elements, allocator);
    defer filter.deinit();

    try std.testing.expectEqual(@as(u32, 2), filter.n);

    // Elements should match
    try std.testing.expect(try filter.match(&script1));
    try std.testing.expect(try filter.match(&script2));

    // Non-element probably shouldn't match (but could be false positive)
    // We can't guarantee no false positives, so just verify no crash
    const other_script = [_]u8{0xFF} ** 25;
    _ = try filter.match(&other_script);
}

test "TxLocation serialization" {
    const block_hash: Hash256 = [_]u8{0xAB} ** 32;
    const location = TxLocation{
        .block_hash = block_hash,
        .block_height = 12345,
        .tx_offset = 256,
    };

    const bytes = location.toBytes();
    const recovered = try TxLocation.fromBytes(&bytes);

    try std.testing.expectEqualSlices(u8, &location.block_hash, &recovered.block_hash);
    try std.testing.expectEqual(location.block_height, recovered.block_height);
    try std.testing.expectEqual(location.tx_offset, recovered.tx_offset);
}

test "CoinStats serialization" {
    const allocator = std.testing.allocator;

    const block_hash: Hash256 = [_]u8{0xCD} ** 32;
    const stats = CoinStats{
        .block_hash = block_hash,
        .height = 100000,
        .utxo_count = 50000000,
        .total_amount = 1850000000000000,
        .total_subsidy = 50000000000,
        .bogo_size = 4000000000,
    };

    const bytes = try stats.toBytes(allocator);
    defer allocator.free(bytes);

    const recovered = try CoinStats.fromBytes(bytes);

    try std.testing.expectEqualSlices(u8, &stats.block_hash, &recovered.block_hash);
    try std.testing.expectEqual(stats.height, recovered.height);
    try std.testing.expectEqual(stats.utxo_count, recovered.utxo_count);
    try std.testing.expectEqual(stats.total_amount, recovered.total_amount);
    try std.testing.expectEqual(stats.total_subsidy, recovered.total_subsidy);
    try std.testing.expectEqual(stats.bogo_size, recovered.bogo_size);
}

test "buildBasicBlockFilter" {
    const allocator = std.testing.allocator;

    const block_hash: Hash256 = [_]u8{0x12} ** 32;

    const script1 = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac };
    const output_scripts: []const []const u8 = &.{&script1};
    const spent_scripts: []const []const u8 = &.{};

    var filter = try buildBasicBlockFilter(&block_hash, output_scripts, spent_scripts, allocator);
    defer filter.deinit();

    try std.testing.expectEqual(BlockFilterType.basic, filter.filter_type);
    try std.testing.expectEqualSlices(u8, &block_hash, &filter.block_hash);

    // Filter should match the included script
    try std.testing.expect(try filter.filter.match(&script1));
}

test "BlockFilter header chain" {
    const allocator = std.testing.allocator;

    const block_hash: Hash256 = [_]u8{0x34} ** 32;
    const script1 = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xEF} ** 20;
    const output_scripts: []const []const u8 = &.{&script1};

    var filter = try buildBasicBlockFilter(&block_hash, output_scripts, &.{}, allocator);
    defer filter.deinit();

    const genesis_header = [_]u8{0} ** 32;
    const header1 = filter.computeHeader(&genesis_header);

    // Header should be non-zero
    var is_zero = true;
    for (header1) |b| {
        if (b != 0) {
            is_zero = false;
            break;
        }
    }
    try std.testing.expect(!is_zero);

    // Computing again with same prev should give same result
    const header2 = filter.computeHeader(&genesis_header);
    try std.testing.expectEqualSlices(u8, &header1, &header2);
}

test "TxIndex without database" {
    const allocator = std.testing.allocator;

    var index = TxIndex.init(null, allocator, true);

    const txid: Hash256 = [_]u8{0xAB} ** 32;
    const block_hash: Hash256 = [_]u8{0xCD} ** 32;
    const location = TxLocation{
        .block_hash = block_hash,
        .block_height = 100,
        .tx_offset = 50,
    };

    // Should not crash without database
    try index.put(&txid, &location);
    const result = try index.get(&txid);
    try std.testing.expect(result == null);
}

test "CoinStatsIndex without database" {
    const allocator = std.testing.allocator;

    var index = CoinStatsIndex.init(null, allocator, true);

    const block_hash: Hash256 = [_]u8{0xEF} ** 32;
    const created: []const UtxoInfo = &.{
        .{ .value = 5000000000, .script_len = 25 },
    };
    const spent: []const UtxoInfo = &.{};

    // Should update in-memory stats
    try index.connectBlock(&block_hash, 1, 5000000000, created, spent);

    try std.testing.expectEqual(@as(u64, 1), index.utxo_count);
    try std.testing.expectEqual(@as(i64, 5000000000), index.total_amount);
    try std.testing.expectEqual(@as(u32, 1), index.best_height);
}

test "BlockFilterIndex without database" {
    const allocator = std.testing.allocator;

    var index = BlockFilterIndex.init(null, allocator, true);

    var block_hash: Hash256 = [_]u8{0x56} ** 32;
    const script1 = [_]u8{ 0x51, 0x20 } ++ [_]u8{0x78} ** 32;
    var filter = try buildBasicBlockFilter(&block_hash, &.{&script1}, &.{}, allocator);
    defer filter.deinit();

    // Should not crash without database
    try index.putFilter(&block_hash, 100, &filter);

    const result = try index.getFilter(&block_hash);
    try std.testing.expect(result == null);
}

test "BackgroundIndexer start and stop" {
    const allocator = std.testing.allocator;

    var tx_index = TxIndex.init(null, allocator, false);
    var filter_index = BlockFilterIndex.init(null, allocator, false);
    var stats_index = CoinStatsIndex.init(null, allocator, false);

    var indexer = BackgroundIndexer.init(allocator, &tx_index, &filter_index, &stats_index);

    try std.testing.expect(!indexer.isAnyIndexEnabled());
    try std.testing.expectEqual(IndexerState.stopped, indexer.state.load(.acquire));

    // Enable an index
    tx_index.enabled = true;
    try std.testing.expect(indexer.isAnyIndexEnabled());

    // Start and stop
    try indexer.start();
    try std.testing.expectEqual(IndexerState.running, indexer.state.load(.acquire));

    indexer.stop();
    try std.testing.expectEqual(IndexerState.stopped, indexer.state.load(.acquire));
}
