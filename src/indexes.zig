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

/// Column family index for block filters — BIP-158 basic filter encoded bytes
/// keyed by block hash.  Sourced from storage.zig so we don't drift from the
/// canonical CF table.  Pre-2026-05-05 this was a duplicate `5` constant that
/// silently aliased CF_BLOCK_UNDO; harmless when the index was unwired but
/// would have corrupted both indexes the moment putFilter() was called.
pub const CF_BLOCK_FILTER: usize = storage.CF_BLOCK_FILTER;

/// Column family index for block filter headers — BIP-157 chained
/// hash256(filter_hash || prev_header) keyed by block hash.
pub const CF_BLOCK_FILTER_HEADER: usize = storage.CF_BLOCK_FILTER_HEADER;

/// Column family index for coin statistics — not yet wired into the storage
/// CF table; this constant is a placeholder for the eventual coinstatsindex.
/// Reserving 8 = CF_COUNT keeps it out of the active range until then.
pub const CF_COINSTATS: usize = storage.CF_COUNT;

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

/// Golomb-Rice bit stream writer — MSB-first, matching Bitcoin Core's BitStreamWriter
/// (src/streams.h).  Bitcoin Core comment: "The next bit to be written to is at
/// m_offset from the most significant bit position."
///
/// W90 bug fixed: the previous implementation used LSB-first bit ordering.  That
/// produced bit-reversed output, making every encoded filter incompatible with Core
/// (different bytes, wrong match results for all elements).
pub const BitStreamWriter = struct {
    data: std.ArrayList(u8),
    /// Buffered byte being assembled; bits filled from MSB downward.
    buffer: u8,
    /// How many HIGH-ORDER bits of `buffer` have been written so far (0..8).
    /// When offset == 8 the byte is complete and is flushed.
    offset: u8,

    pub fn init(allocator: std.mem.Allocator) BitStreamWriter {
        return BitStreamWriter{
            .data = std.ArrayList(u8).init(allocator),
            .buffer = 0,
            .offset = 0,
        };
    }

    pub fn deinit(self: *BitStreamWriter) void {
        self.data.deinit();
    }

    /// Write the `n` least-significant bits of `value`, MSB first (n <= 57).
    /// Mirrors Core's BitStreamWriter::Write (streams.h:329).
    pub fn writeBits(self: *BitStreamWriter, value: u64, n: u6) !void {
        var remaining: u32 = n; // use u32 to avoid narrow-type arithmetic traps
        while (remaining > 0) {
            const avail: u32 = 8 - @as(u32, self.offset);
            const bits: u32 = @min(avail, remaining);
            // Extract `bits` bits from the MSB side of the remaining `remaining`
            // bits of value and place them in the MSB side of buffer.
            // Core: m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset)
            // `remaining > 0` so `64 - remaining <= 63` (fits u6).
            // `self.offset < 8` so `64 - 8 + self.offset <= 63` (fits u6).
            const ls: u6 = @intCast(64 - remaining);
            const rs: u6 = @intCast(64 - 8 + @as(u32, self.offset));
            const shift_in: u64 = (value << ls) >> rs;
            self.buffer |= @as(u8, @intCast(shift_in & 0xff));
            self.offset += @as(u8, @intCast(bits));
            remaining -= bits;
            if (self.offset == 8) {
                try self.data.append(self.buffer);
                self.buffer = 0;
                self.offset = 0;
            }
        }
    }

    /// Write a single bit.
    pub fn writeBit(self: *BitStreamWriter, bit: bool) !void {
        try self.writeBits(if (bit) 1 else 0, 1);
    }

    /// Golomb-Rice encode a delta value with parameter P.
    pub fn golombRiceEncode(self: *BitStreamWriter, delta: u64, p: u8) !void {
        // Quotient in unary: q 1-bits followed by one 0-bit.
        const q = delta >> @intCast(p);
        // Write q ones in chunks of up to 64 to match Core's batch-write path.
        var ones_left: u64 = q;
        while (ones_left > 0) {
            const batch: u6 = @intCast(@min(ones_left, 57)); // keep within writeBits range
            try self.writeBits(~@as(u64, 0), batch);
            ones_left -= batch;
        }
        try self.writeBit(false); // terminating zero

        // Remainder in P bits (MSB first).
        const r = delta & ((@as(u64, 1) << @intCast(p)) - 1);
        try self.writeBits(r, @intCast(p));
    }

    /// Flush remaining bits, padding low-order bits with zeros (MSB-first).
    pub fn flush(self: *BitStreamWriter) !void {
        if (self.offset > 0) {
            try self.data.append(self.buffer);
            self.buffer = 0;
            self.offset = 0;
        }
    }

    /// Get the encoded data.
    pub fn toOwnedSlice(self: *BitStreamWriter) ![]const u8 {
        return self.data.toOwnedSlice();
    }
};

/// Golomb-Rice bit stream reader — MSB-first, matching Bitcoin Core's BitStreamReader
/// (src/streams.h).  Bitcoin Core comment: "m_offset … number of high order bits
/// in m_buffer already returned by previous Read() calls."
///
/// W90 bug fixed: the previous implementation used LSB-first ordering, so decoded
/// values from any Core-produced filter were garbage.
pub const BitStreamReader = struct {
    data: []const u8,
    pos: usize,
    /// Buffered byte; bits consumed from MSB downward.
    buffer: u8,
    /// How many HIGH-ORDER bits of `buffer` have already been consumed (0..8).
    /// When offset == 8 we need to load the next byte.
    offset: u8, // 0..8

    pub fn init(data: []const u8) BitStreamReader {
        return BitStreamReader{
            .data = data,
            .pos = 0,
            .buffer = 0,
            .offset = 8, // force load on first read
        };
    }

    /// Read `n` bits, returned in the `n` LSBs of the result (MSB-first from stream).
    /// Mirrors Core's BitStreamReader::Read (streams.h:281).
    pub fn readBits(self: *BitStreamReader, n: u6) !u64 {
        var result: u64 = 0;
        var remaining: u32 = n; // u32 to avoid narrow arithmetic traps
        while (remaining > 0) {
            if (self.offset == 8) {
                if (self.pos >= self.data.len) return error.UnexpectedEndOfData;
                self.buffer = self.data[self.pos];
                self.pos += 1;
                self.offset = 0;
            }
            const avail: u32 = 8 - @as(u32, self.offset);
            const bits: u32 = @min(avail, remaining);
            // Core: data <<= bits; data |= (uint8_t)(m_buffer << m_offset) >> (8 - bits)
            result <<= @intCast(bits);
            const shifted: u8 = @as(u8, self.buffer << @as(u3, @intCast(self.offset))) >> @as(u3, @intCast(8 - bits));
            result |= shifted;
            self.offset += @as(u8, @intCast(bits));
            remaining -= bits;
        }
        return result;
    }

    /// Read a single bit.
    pub fn readBit(self: *BitStreamReader) !bool {
        return (try self.readBits(1)) == 1;
    }

    /// Golomb-Rice decode with parameter P.
    pub fn golombRiceDecode(self: *BitStreamReader, p: u8) !u64 {
        // Read unary quotient (count 1-bits until a 0-bit).
        var q: u64 = 0;
        while (try self.readBit()) {
            q += 1;
        }
        // Read P-bit remainder.
        const r = try self.readBits(@intCast(p));
        return (q << @intCast(p)) | r;
    }

    /// Check if we've reached the end of the data (no bits remaining).
    pub fn isAtEnd(self: *const BitStreamReader) bool {
        return self.pos >= self.data.len and self.offset == 8;
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
    ///
    /// Mirrors Core's GCSFilter constructor (blockfilter.cpp): elements are treated as
    /// a set — duplicates are removed by content before N and F are computed.  Core uses
    /// ElementSet (std::unordered_set<Element>) which deduplicates at insertion; we
    /// replicate that by sorting element slices and removing consecutive equal entries.
    ///
    /// Bug fixed (W90): the previous implementation computed F = raw_element_count * M
    /// before deduplication, then stored N = unique_count with F = unique_count * M.
    /// This meant hashes were mapped to [0, F_wrong) at build time but to [0, F_correct)
    /// during match() — making every element appear absent from its own filter.
    pub fn init(params: GCSParams, elements: []const []const u8, allocator: std.mem.Allocator) !GCSFilter {
        if (elements.len == 0) {
            // Empty filter: just the CompactSize(0) count byte.
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

        // Step 1: deduplicate elements by content (Core uses ElementSet / unordered_set).
        // Sort a copy of the slice-pointers by content, then unique-compact.
        var dedup_ptrs = try allocator.alloc([]const u8, elements.len);
        defer allocator.free(dedup_ptrs);
        @memcpy(dedup_ptrs, elements);

        const LexLess = struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        };
        std.mem.sort([]const u8, dedup_ptrs, {}, LexLess.less);

        var dedup_count: usize = 1;
        for (1..dedup_ptrs.len) |i| {
            if (!std.mem.eql(u8, dedup_ptrs[i], dedup_ptrs[dedup_count - 1])) {
                dedup_ptrs[dedup_count] = dedup_ptrs[i];
                dedup_count += 1;
            }
        }
        const unique_elements = dedup_ptrs[0..dedup_count];

        // Step 2: now that N is the deduplicated count, compute F = N * M (Core blockfilter.cpp:82).
        const n: u32 = @intCast(unique_elements.len);
        const f: u64 = @as(u64, n) * @as(u64, params.m);

        // Step 3: hash each unique element to [0, F) and sort.
        var hashes = try allocator.alloc(u64, unique_elements.len);
        defer allocator.free(hashes);

        for (unique_elements, 0..) |element, i| {
            const h = SipHash.hash(params.siphash_k0, params.siphash_k1, element);
            hashes[i] = fastRange64(h, f);
        }
        std.mem.sort(u64, hashes, {}, std.sort.asc(u64));

        // Step 4: encode as Golomb-Rice deltas (CompactSize(N) ++ GR-encoded deltas).
        var count_writer = serialize.Writer.init(allocator);
        defer count_writer.deinit();
        try count_writer.writeCompactSize(n);

        var bit_writer = BitStreamWriter.init(allocator);
        errdefer bit_writer.deinit();

        var last_value: u64 = 0;
        for (hashes) |hash| {
            const delta = hash - last_value;
            try bit_writer.golombRiceEncode(delta, params.p);
            last_value = hash;
        }
        try bit_writer.flush();
        const filter_data = try bit_writer.toOwnedSlice();

        // Combine CompactSize(N) prefix with Golomb-Rice body.
        const count_data = count_writer.getWritten();
        const encoded = try allocator.alloc(u8, count_data.len + filter_data.len);
        @memcpy(encoded[0..count_data.len], count_data);
        @memcpy(encoded[count_data.len..], filter_data);
        allocator.free(filter_data);

        return GCSFilter{
            .params = params,
            .n = n,
            .f = f,
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

test "SipHash-2-4 reference vector empty" {
    // SipHash-2-4 reference test vector from the paper (also checked in
    // Bitcoin Core's hash_tests.cpp:84).
    // Key = 0x000102...0f split as k0=0x0706050403020100, k1=0x0f0e0d0c0b0a0908.
    // SipHash-2-4("") == 0x726fdb47dd0e0e31.
    const k0: u64 = 0x0706050403020100;
    const k1: u64 = 0x0f0e0d0c0b0a0908;

    var h = SipHash.init(k0, k1);
    const result = h.final();

    try std.testing.expectEqual(@as(u64, 0x726fdb47dd0e0e31), result);
}

test "SipHash-2-4 single byte 0x00" {
    // Feed a single byte 0x00; expected = second entry in the SipHash
    // reference test-vector table (hash_tests.cpp:87 — testvec[1]).
    const k0: u64 = 0x0706050403020100;
    const k1: u64 = 0x0f0e0d0c0b0a0908;

    var h = SipHash.init(k0, k1);
    const input = [_]u8{0x00};
    h.update(&input);
    const result = h.final();

    try std.testing.expectEqual(@as(u64, 0x74f839c593dc67fd), result);
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

test "GCSFilter duplicate elements are deduplicated before F computation" {
    // W90 regression test: building a filter with two identical elements must
    // produce the same encoded bytes as building with one element.  The pre-fix
    // code mapped hashes using F = 2*M then stored N=1 with F = 1*M, causing
    // every match to fail because the stored hash was mapped to the wrong range.
    const allocator = std.testing.allocator;

    const params = GCSParams{
        .siphash_k0 = 0xDEADBEEFCAFEBABE,
        .siphash_k1 = 0x0102030405060708,
        .p = BASIC_FILTER_P,
        .m = BASIC_FILTER_M,
    };

    const script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x55} ** 20 ++ [_]u8{ 0x88, 0xac };
    const one_elem: []const []const u8 = &.{&script};
    const two_elem: []const []const u8 = &.{ &script, &script }; // duplicate

    var f1 = try GCSFilter.init(params, one_elem, allocator);
    defer f1.deinit();
    var f2 = try GCSFilter.init(params, two_elem, allocator);
    defer f2.deinit();

    // Deduplicated count must be 1 in both cases.
    try std.testing.expectEqual(@as(u32, 1), f1.n);
    try std.testing.expectEqual(@as(u32, 1), f2.n);

    // Encoded bytes must be identical.
    try std.testing.expectEqualSlices(u8, f1.getEncoded(), f2.getEncoded());

    // The element must match in both filters.
    try std.testing.expect(try f1.match(&script));
    try std.testing.expect(try f2.match(&script));
}

test "GCSFilter match fails before W90 dedup fix (regression guard)" {
    // Demonstrates that the old code would produce N=1 but F=2*M, meaning the
    // hash was stored at position fastRange64(h, 2*M) but looked up at
    // fastRange64(h, 1*M).  With the fix, match must succeed.
    const allocator = std.testing.allocator;

    const params = GCSParams{
        .siphash_k0 = 0x1111222233334444,
        .siphash_k1 = 0x5555666677778888,
        .p = BASIC_FILTER_P,
        .m = BASIC_FILTER_M,
    };

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;
    const elems: []const []const u8 = &.{ &script, &script }; // two duplicates

    var filter = try GCSFilter.init(params, elems, allocator);
    defer filter.deinit();

    // After the fix: N=1, match must succeed.
    try std.testing.expectEqual(@as(u32, 1), filter.n);
    try std.testing.expect(try filter.match(&script));
}

test "BIP-158 genesis block test vector" {
    // From Bitcoin Core's test/data/blockfilters.json (first non-comment entry).
    //
    // Block 0 (genesis, testnet3 — same format as mainnet genesis filter):
    //   block_hash = 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
    //   prev_filter_header = 0000...0000 (32 zero bytes)
    //   basic_filter_hex = 019dfca8
    //   basic_header_hex = 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
    //
    // The genesis coinbase has a single output whose scriptPubKey begins with
    // OP_CHECKSIG (not OP_RETURN), so it must be included in the filter.
    const allocator = std.testing.allocator;

    // Genesis block hash (display order → internal byte order)
    var block_hash: Hash256 = undefined;
    const hash_hex = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
    for (0..32) |i| {
        const hi = std.fmt.charToDigit(hash_hex[(31 - i) * 2], 16) catch unreachable;
        const lo = std.fmt.charToDigit(hash_hex[(31 - i) * 2 + 1], 16) catch unreachable;
        block_hash[i] = (hi << 4) | lo;
    }

    // Genesis coinbase scriptPubKey (67 bytes).
    // Extracted from block hex in test/data/blockfilters.json (testnet3 block 0).
    // scriptPubKey = OP_PUSH65 <65-byte uncompressed pubkey> OP_CHECKSIG.
    // Verified against raw block hex: ...43 4104678afdb0fe55 48271967f1a67130
    // b7105cd6a828e039 09a67962e0ea1f61 deb649f6bc3f4cef 38c4f35504e51ec1
    // 12de5c384df7ba0b 8d578a4c702b6bf1 1d5fac ...
    const genesis_spk = [_]u8{
        0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30,
        0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61,
        0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1,
        0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1,
        0x1d, 0x5f, 0xac,
    };
    const output_scripts: []const []const u8 = &.{&genesis_spk};

    var block_filter = try buildBasicBlockFilter(&block_hash, output_scripts, &.{}, allocator);
    defer block_filter.deinit();

    // Expected encoded filter: 019dfca8
    const expected_encoded = [_]u8{ 0x01, 0x9d, 0xfc, 0xa8 };
    try std.testing.expectEqualSlices(u8, &expected_encoded, block_filter.filter.getEncoded());

    // Filter must match the genesis scriptPubKey.
    try std.testing.expect(try block_filter.filter.match(&genesis_spk));

    // Compute filter header: Hash256(filter_hash || prev_header_zero)
    const genesis_prev_header = [_]u8{0} ** 32;
    const computed_header = block_filter.computeHeader(&genesis_prev_header);

    // Expected filter header (from blockfilters.json):
    // 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
    //
    // Note: this is in display (big-endian) order, so we reverse it to get
    // the internal byte order used by clearbit's hash256 output (which matches
    // Core's uint256 internal representation — i.e., byte[0] is the LSB).
    var expected_header: Hash256 = undefined;
    const hdr_hex = "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750";
    for (0..32) |i| {
        const hi = std.fmt.charToDigit(hdr_hex[(31 - i) * 2], 16) catch unreachable;
        const lo = std.fmt.charToDigit(hdr_hex[(31 - i) * 2 + 1], 16) catch unreachable;
        expected_header[i] = (hi << 4) | lo;
    }
    try std.testing.expectEqualSlices(u8, &expected_header, &computed_header);
}

test "NODE_COMPACT_FILTERS service bit value" {
    // Sanity-check: Core defines NODE_COMPACT_FILTERS = (1 << 6) = 64 (protocol.h:323).
    const p2p = @import("p2p.zig");
    try std.testing.expectEqual(@as(u64, 64), p2p.NODE_COMPACT_FILTERS);
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
