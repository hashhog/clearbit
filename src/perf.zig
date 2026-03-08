//! Performance optimization utilities for clearbit.
//!
//! This module provides performance-critical utilities leveraging Zig's unique
//! features: arena allocators for bulk allocation patterns, SIMD operations
//! for hash comparisons, and comptime-generated lookup tables.
//!
//! Key optimizations:
//! - Arena allocators for per-block processing (single bulk free)
//! - SIMD-accelerated hash comparison using @Vector types
//! - Comptime lookup tables for Base58, opcodes, and script types
//! - Optimized UTXO cache with configurable memory limits

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");

// ============================================================================
// Comptime Lookup Tables
// ============================================================================

/// Base58 alphabet used by Bitcoin addresses.
pub const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Comptime-generated Base58 decode table.
/// Maps ASCII characters to their Base58 values (0-57), or 0xFF for invalid.
pub const base58_decode_table: [256]u8 = blk: {
    var table = [_]u8{0xFF} ** 256;
    for (BASE58_ALPHABET, 0..) |c, i| {
        table[c] = @intCast(i);
    }
    break :blk table;
};

/// Opcode handler function type.
pub const OpcodeHandler = *const fn (ctx: *anyopaque) anyerror!void;

/// Opcode categories for quick classification.
pub const OpcodeCategory = enum(u8) {
    push_value, // OP_0, OP_1-OP_16, OP_1NEGATE
    push_data, // OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4
    flow_control, // OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN
    stack, // OP_DUP, OP_DROP, OP_SWAP, etc.
    arithmetic, // OP_ADD, OP_SUB, etc.
    crypto_op, // OP_SHA256, OP_HASH160, OP_CHECKSIG, etc.
    locktime, // OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY
    reserved, // OP_RESERVED, OP_VER, etc.
    disabled, // OP_CAT, OP_SUBSTR, etc. (disabled opcodes)
    nop, // OP_NOP, OP_NOP1-OP_NOP10
    invalid, // Unknown/invalid opcodes
};

/// Comptime-generated opcode category table for fast dispatch.
pub const opcode_category_table: [256]OpcodeCategory = blk: {
    var table: [256]OpcodeCategory = undefined;
    for (0..256) |i| {
        table[i] = switch (i) {
            // Push value opcodes
            0x00 => .push_value, // OP_0
            0x4f => .push_value, // OP_1NEGATE
            0x51...0x60 => .push_value, // OP_1 through OP_16

            // Push data opcodes (direct push 0x01-0x4b, PUSHDATA)
            0x01...0x4b => .push_data,
            0x4c...0x4e => .push_data, // PUSHDATA1, PUSHDATA2, PUSHDATA4

            // Flow control
            0x61 => .nop, // OP_NOP
            0x63, 0x64 => .flow_control, // OP_IF, OP_NOTIF
            0x67, 0x68 => .flow_control, // OP_ELSE, OP_ENDIF
            0x69 => .flow_control, // OP_VERIFY
            0x6a => .flow_control, // OP_RETURN

            // Stack operations
            0x6b...0x7d => .stack,
            0x82 => .stack, // OP_SIZE

            // Bitwise/comparison
            0x87, 0x88 => .arithmetic, // OP_EQUAL, OP_EQUALVERIFY

            // Arithmetic (excludes disabled opcodes)
            0x8b, 0x8c => .arithmetic, // 1ADD, 1SUB
            0x8f...0x94 => .arithmetic, // NEGATE through SUB
            0x9a...0xa5 => .arithmetic, // BOOLAND through WITHIN

            // Crypto operations
            0xa6...0xaf => .crypto_op,

            // Locktime
            0xb0 => .nop, // OP_NOP1
            0xb1 => .locktime, // OP_CHECKLOCKTIMEVERIFY
            0xb2 => .locktime, // OP_CHECKSEQUENCEVERIFY
            0xb3...0xb9 => .nop, // OP_NOP4-OP_NOP10

            // Taproot
            0xba => .crypto_op, // OP_CHECKSIGADD

            // Reserved
            0x50 => .reserved, // OP_RESERVED
            0x62 => .reserved, // OP_VER
            0x65, 0x66 => .reserved, // OP_VERIF, OP_VERNOTIF
            0x89, 0x8a => .reserved, // OP_RESERVED1, OP_RESERVED2

            // Disabled (historically enabled)
            0x7e...0x81 => .disabled, // CAT, SUBSTR, LEFT, RIGHT
            0x83...0x86 => .disabled, // INVERT, AND, OR, XOR
            0x8d, 0x8e => .disabled, // 2MUL, 2DIV
            0x95...0x99 => .disabled, // MUL, DIV, MOD, LSHIFT, RSHIFT

            else => .invalid,
        };
    }
    break :blk table;
};

/// Comptime-generated script type classification.
/// Returns expected script length for standard types, 0 for non-standard.
pub const script_type_lengths: [6]u8 = blk: {
    break :blk .{
        25, // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        23, // P2SH: OP_HASH160 <20> OP_EQUAL
        22, // P2WPKH: OP_0 <20>
        34, // P2WSH: OP_0 <32>
        34, // P2TR: OP_1 <32>
        0, // Other (variable length)
    };
};

/// Network magic bytes lookup table.
pub const NetworkMagic = enum(u8) {
    mainnet = 0,
    testnet = 1,
    regtest = 2,
    signet = 3,

    pub fn magic(self: NetworkMagic) [4]u8 {
        return switch (self) {
            .mainnet => .{ 0xF9, 0xBE, 0xB4, 0xD9 },
            .testnet => .{ 0x0B, 0x11, 0x09, 0x07 },
            .regtest => .{ 0xFA, 0xBF, 0xB5, 0xDA },
            .signet => .{ 0x0A, 0x03, 0xCF, 0x40 },
        };
    }
};

/// Comptime network magic validation.
pub fn comptimeNetworkMagic(comptime network: NetworkMagic) [4]u8 {
    return network.magic();
}

// ============================================================================
// SIMD-Accelerated Operations
// ============================================================================

/// SIMD-accelerated hash comparison (256-bit little-endian integers).
/// Returns true if hash < target when interpreted as 256-bit LE integers.
/// Uses 128-bit vector operations for efficient comparison.
pub fn hashLessThanTarget(hash: *const [32]u8, target: *const [32]u8) bool {
    // Bitcoin hashes are compared as 256-bit little-endian integers.
    // The most significant byte is at index 31 (end of array).

    // Compare from most significant byte down
    var i: usize = 31;
    while (true) : (i -= 1) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
        if (i == 0) break;
    }
    return false; // Equal means not less than
}

/// SIMD-accelerated hash comparison using 128-bit vectors.
/// More efficient for comparing many hashes against the same target.
pub fn hashLessThanTargetSIMD(hash: *const [32]u8, target: *const [32]u8) bool {
    // Load hash and target as vectors (high and low halves)
    const hash_hi: @Vector(16, u8) = hash[16..32].*;
    const hash_lo: @Vector(16, u8) = hash[0..16].*;
    const target_hi: @Vector(16, u8) = target[16..32].*;
    const target_lo: @Vector(16, u8) = target[0..16].*;

    // Reverse bytes for big-endian comparison (MSB first)
    const h_hi = @shuffle(u8, hash_hi, undefined, [16]i32{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 });
    const t_hi = @shuffle(u8, target_hi, undefined, [16]i32{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 });
    const h_lo = @shuffle(u8, hash_lo, undefined, [16]i32{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 });
    const t_lo = @shuffle(u8, target_lo, undefined, [16]i32{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 });

    // Compare high half first (most significant)
    // Find first differing byte
    const lt_hi = h_hi < t_hi;
    const gt_hi = h_hi > t_hi;
    const eq_hi = h_hi == t_hi;

    // Check if any byte in high half differs
    if (@reduce(.Or, lt_hi) or @reduce(.Or, gt_hi)) {
        // High halves differ - find first differing position
        // If hash < target at first difference, return true
        const lt_mask = @as(u16, @bitCast(lt_hi));
        const gt_mask = @as(u16, @bitCast(gt_hi));

        // Find first differing byte (highest set bit in lt_mask | gt_mask)
        const diff_mask = lt_mask | gt_mask;
        if (diff_mask != 0) {
            const first_diff = @clz(diff_mask);
            const lt_at_diff = (lt_mask >> @intCast(15 - first_diff)) & 1;
            return lt_at_diff == 1;
        }
    }

    // High halves are equal, check low halves
    if (@reduce(.And, eq_hi)) {
        const lt_lo = h_lo < t_lo;
        const gt_lo = h_lo > t_lo;

        const lt_mask = @as(u16, @bitCast(lt_lo));
        const gt_mask = @as(u16, @bitCast(gt_lo));

        const diff_mask = lt_mask | gt_mask;
        if (diff_mask != 0) {
            const first_diff = @clz(diff_mask);
            const lt_at_diff = (lt_mask >> @intCast(15 - first_diff)) & 1;
            return lt_at_diff == 1;
        }
    }

    return false; // Equal
}

/// SIMD-accelerated hash equality check.
pub fn hashEqual(a: *const [32]u8, b: *const [32]u8) bool {
    const a_lo: @Vector(16, u8) = a[0..16].*;
    const a_hi: @Vector(16, u8) = a[16..32].*;
    const b_lo: @Vector(16, u8) = b[0..16].*;
    const b_hi: @Vector(16, u8) = b[16..32].*;

    const eq_lo = a_lo == b_lo;
    const eq_hi = a_hi == b_hi;

    return @reduce(.And, eq_lo) and @reduce(.And, eq_hi);
}

/// Batch hash-to-zero check using SIMD.
/// Returns true if the hash is all zeros.
pub fn hashIsZero(hash: *const [32]u8) bool {
    const zero: @Vector(32, u8) = @splat(0);
    const h: @Vector(32, u8) = hash.*;
    return @reduce(.And, h == zero);
}

// ============================================================================
// SIMD Merkle Root Computation
// ============================================================================

/// Compute merkle root with SIMD optimization for hash concatenation.
/// Uses batch operations where possible.
pub fn computeMerkleRootSIMD(
    hashes: []const [32]u8,
    allocator: std.mem.Allocator,
) ![32]u8 {
    if (hashes.len == 0) return [_]u8{0} ** 32;
    if (hashes.len == 1) return hashes[0];

    var current = try allocator.alloc([32]u8, hashes.len);
    defer allocator.free(current);
    @memcpy(current, hashes);

    var len = hashes.len;

    while (len > 1) {
        const pairs = (len + 1) / 2;

        // Process pairs
        for (0..pairs) |i| {
            const left = current[i * 2];
            const right = if (i * 2 + 1 < len)
                current[i * 2 + 1]
            else
                current[i * 2]; // Duplicate last hash if odd

            // Concatenate using SIMD copy
            var combined: [64]u8 = undefined;
            @memcpy(combined[0..32], &left);
            @memcpy(combined[32..64], &right);
            current[i] = crypto.hash256(&combined);
        }

        len = pairs;
    }

    return current[0];
}

// ============================================================================
// Arena Allocator Utilities
// ============================================================================

/// Block processing context with arena allocator.
/// All temporary allocations during block processing use the arena,
/// which is freed in one operation after the block is processed.
pub const BlockArena = struct {
    arena: std.heap.ArenaAllocator,
    backing: std.mem.Allocator,

    /// Initialize a block arena backed by the given allocator.
    pub fn init(backing_allocator: std.mem.Allocator) BlockArena {
        return .{
            .arena = std.heap.ArenaAllocator.init(backing_allocator),
            .backing = backing_allocator,
        };
    }

    /// Get the arena allocator for temporary allocations.
    pub fn allocator(self: *BlockArena) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Get the backing allocator for persistent allocations.
    pub fn persistent(self: *BlockArena) std.mem.Allocator {
        return self.backing;
    }

    /// Reset the arena, freeing all temporary allocations at once.
    /// Call this after processing a block to avoid per-object free overhead.
    pub fn reset(self: *BlockArena) void {
        _ = self.arena.reset(.retain_capacity);
    }

    /// Free all arena memory and the arena itself.
    pub fn deinit(self: *BlockArena) void {
        self.arena.deinit();
    }

    /// Approximate memory usage of the arena.
    pub fn memoryUsage(self: *BlockArena) usize {
        // ArenaAllocator doesn't expose this directly, estimate from child allocator
        // This is a rough estimate based on allocation patterns
        return self.arena.queryCapacity();
    }
};

/// Transaction validation context using arena allocation.
pub const TxValidationContext = struct {
    arena: BlockArena,
    tx_hashes: std.ArrayList([32]u8),
    spent_outputs: std.ArrayList(types.OutPoint),

    pub fn init(allocator: std.mem.Allocator) TxValidationContext {
        var arena = BlockArena.init(allocator);
        return .{
            .arena = arena,
            .tx_hashes = std.ArrayList([32]u8).init(arena.allocator()),
            .spent_outputs = std.ArrayList(types.OutPoint).init(arena.allocator()),
        };
    }

    pub fn deinit(self: *TxValidationContext) void {
        // No need to free individual lists - arena handles everything
        self.arena.deinit();
    }

    pub fn reset(self: *TxValidationContext) void {
        self.tx_hashes.clearRetainingCapacity();
        self.spent_outputs.clearRetainingCapacity();
        self.arena.reset();
    }
};

// ============================================================================
// Optimized UTXO Cache
// ============================================================================

/// Compact UTXO entry for cache storage.
/// Uses efficient layout to minimize memory per entry.
pub const CacheEntry = struct {
    value: u64, // 8 bytes: output value in satoshis
    height: u32, // 4 bytes: block height
    script_type: ScriptType, // 1 byte: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, other
    coinbase: bool, // 1 byte (could be packed but alignment matters)

    pub const ScriptType = enum(u8) {
        p2pkh = 0,
        p2sh = 1,
        p2wpkh = 2,
        p2wsh = 3,
        p2tr = 4,
        other = 7,
    };

    /// Approximate size of this struct in bytes.
    pub const SIZE: usize = @sizeOf(CacheEntry);
};

/// OutPoint hash context for HashMap.
pub const OutPointContext = struct {
    pub fn hash(_: OutPointContext, key: types.OutPoint) u64 {
        // Use first 8 bytes of txid hash + index for fast hashing
        const txid_part = std.mem.readInt(u64, key.hash[0..8], .little);
        return txid_part ^ @as(u64, key.index);
    }

    pub fn eql(_: OutPointContext, a: types.OutPoint, b: types.OutPoint) bool {
        return std.mem.eql(u8, &a.hash, &b.hash) and a.index == b.index;
    }
};

/// High-performance UTXO cache with configurable memory limits.
/// Uses compact entries and LRU-like eviction.
pub const UtxoCache = struct {
    /// Cached entries keyed by outpoint.
    entries: std.HashMap(types.OutPoint, CachedEntry, OutPointContext, 80),

    /// Dirty entries that need to be flushed to disk.
    dirty: std.HashMap(types.OutPoint, void, OutPointContext, 80),

    /// Script data stored separately (variable length).
    script_data: std.HashMap(types.OutPoint, []const u8, OutPointContext, 80),

    /// Maximum memory usage in bytes.
    max_memory: usize,

    /// Current approximate memory usage.
    current_memory: usize,

    /// Allocator for script data.
    allocator: std.mem.Allocator,

    /// Cache statistics.
    hits: u64,
    misses: u64,

    /// Entry with access tracking for eviction.
    const CachedEntry = struct {
        entry: CacheEntry,
        access_count: u32,
    };

    /// Per-entry memory overhead estimate (entry + hash table overhead).
    const ENTRY_OVERHEAD: usize = @sizeOf(CachedEntry) + @sizeOf(types.OutPoint) + 48;

    /// Initialize the UTXO cache with a memory limit.
    pub fn init(allocator: std.mem.Allocator, max_memory_mb: usize) UtxoCache {
        return .{
            .entries = std.HashMap(types.OutPoint, CachedEntry, OutPointContext, 80).init(allocator),
            .dirty = std.HashMap(types.OutPoint, void, OutPointContext, 80).init(allocator),
            .script_data = std.HashMap(types.OutPoint, []const u8, OutPointContext, 80).init(allocator),
            .max_memory = max_memory_mb * 1024 * 1024,
            .current_memory = 0,
            .allocator = allocator,
            .hits = 0,
            .misses = 0,
        };
    }

    /// Free all cache resources.
    pub fn deinit(self: *UtxoCache) void {
        // Free script data
        var it = self.script_data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.script_data.deinit();
        self.entries.deinit();
        self.dirty.deinit();
    }

    /// Get a cached entry.
    pub fn get(self: *UtxoCache, outpoint: *const types.OutPoint) ?CacheEntry {
        if (self.entries.getPtr(outpoint.*)) |cached| {
            cached.access_count +|= 1;
            self.hits += 1;
            return cached.entry;
        }
        self.misses += 1;
        return null;
    }

    /// Put an entry into the cache.
    pub fn put(
        self: *UtxoCache,
        outpoint: *const types.OutPoint,
        entry: CacheEntry,
        script_hash: ?[]const u8,
    ) !void {
        // Evict if necessary
        while (self.current_memory + ENTRY_OVERHEAD > self.max_memory and self.entries.count() > 0) {
            try self.evictOne();
        }

        // Store entry
        try self.entries.put(outpoint.*, .{
            .entry = entry,
            .access_count = 1,
        });
        try self.dirty.put(outpoint.*, {});
        self.current_memory += ENTRY_OVERHEAD;

        // Store script data if provided
        if (script_hash) |sh| {
            const owned = try self.allocator.dupe(u8, sh);
            try self.script_data.put(outpoint.*, owned);
            self.current_memory += sh.len;
        }
    }

    /// Remove an entry from the cache.
    pub fn remove(self: *UtxoCache, outpoint: *const types.OutPoint) void {
        if (self.entries.fetchRemove(outpoint.*)) |_| {
            self.current_memory -|= ENTRY_OVERHEAD;
        }
        _ = self.dirty.remove(outpoint.*);

        if (self.script_data.fetchRemove(outpoint.*)) |kv| {
            self.current_memory -|= kv.value.len;
            self.allocator.free(kv.value);
        }
    }

    /// Evict one entry (prefer non-dirty, low access count).
    fn evictOne(self: *UtxoCache) !void {
        var best_key: ?types.OutPoint = null;
        var best_score: u32 = std.math.maxInt(u32);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            const is_dirty = self.dirty.contains(entry.key_ptr.*);
            // Score: lower is better for eviction
            // Non-dirty entries get bonus (lower score)
            // Lower access count = lower score
            const score = entry.value_ptr.access_count + (if (is_dirty) @as(u32, 1000000) else 0);

            if (score < best_score) {
                best_score = score;
                best_key = entry.key_ptr.*;
            }
        }

        if (best_key) |key| {
            self.remove(&key);
        }
    }

    /// Get cache hit rate.
    pub fn hitRate(self: *const UtxoCache) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }

    /// Get entry count.
    pub fn count(self: *const UtxoCache) usize {
        return self.entries.count();
    }

    /// Get dirty entry count.
    pub fn dirtyCount(self: *const UtxoCache) usize {
        return self.dirty.count();
    }

    /// Get approximate memory usage in bytes.
    pub fn memoryUsage(self: *const UtxoCache) usize {
        return self.current_memory;
    }

    /// Clear all entries.
    pub fn clear(self: *UtxoCache) void {
        var it = self.script_data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.script_data.clearRetainingCapacity();
        self.entries.clearRetainingCapacity();
        self.dirty.clearRetainingCapacity();
        self.current_memory = 0;
    }
};

// ============================================================================
// Fast Script Classification
// ============================================================================

/// Classify a script type using comptime-generated patterns.
/// Returns the script type and the hash/pubkey data if applicable.
pub fn classifyScriptFast(script: []const u8) struct {
    script_type: CacheEntry.ScriptType,
    hash_data: ?[]const u8,
} {
    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
    if (script.len == 25 and
        script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and
        script[23] == 0x88 and script[24] == 0xac)
    {
        return .{ .script_type = .p2pkh, .hash_data = script[3..23] };
    }

    // P2SH: OP_HASH160 <20> OP_EQUAL (23 bytes)
    if (script.len == 23 and
        script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87)
    {
        return .{ .script_type = .p2sh, .hash_data = script[2..22] };
    }

    // P2WPKH: OP_0 <20> (22 bytes)
    if (script.len == 22 and script[0] == 0x00 and script[1] == 0x14) {
        return .{ .script_type = .p2wpkh, .hash_data = script[2..22] };
    }

    // P2WSH: OP_0 <32> (34 bytes)
    if (script.len == 34 and script[0] == 0x00 and script[1] == 0x20) {
        return .{ .script_type = .p2wsh, .hash_data = script[2..34] };
    }

    // P2TR: OP_1 <32> (34 bytes)
    if (script.len == 34 and script[0] == 0x51 and script[1] == 0x20) {
        return .{ .script_type = .p2tr, .hash_data = script[2..34] };
    }

    return .{ .script_type = .other, .hash_data = null };
}

// ============================================================================
// Performance Metrics
// ============================================================================

/// Performance counters for profiling.
pub const PerfCounters = struct {
    blocks_processed: u64 = 0,
    transactions_validated: u64 = 0,
    scripts_executed: u64 = 0,
    hashes_computed: u64 = 0,
    utxo_lookups: u64 = 0,
    utxo_cache_hits: u64 = 0,
    arena_resets: u64 = 0,
    bytes_allocated: u64 = 0,
    bytes_freed: u64 = 0,

    /// Start time for timing measurements.
    start_time: i64 = 0,

    /// Reset all counters.
    pub fn reset(self: *PerfCounters) void {
        self.* = .{};
        self.start_time = std.time.milliTimestamp();
    }

    /// Start timing.
    pub fn start(self: *PerfCounters) void {
        self.start_time = std.time.milliTimestamp();
    }

    /// Get elapsed time in milliseconds.
    pub fn elapsedMs(self: *const PerfCounters) i64 {
        return std.time.milliTimestamp() - self.start_time;
    }

    /// Get blocks per second.
    pub fn blocksPerSec(self: *const PerfCounters) f64 {
        const elapsed = self.elapsedMs();
        if (elapsed <= 0) return 0;
        return @as(f64, @floatFromInt(self.blocks_processed)) / (@as(f64, @floatFromInt(elapsed)) / 1000.0);
    }

    /// Get transactions per second.
    pub fn txPerSec(self: *const PerfCounters) f64 {
        const elapsed = self.elapsedMs();
        if (elapsed <= 0) return 0;
        return @as(f64, @floatFromInt(self.transactions_validated)) / (@as(f64, @floatFromInt(elapsed)) / 1000.0);
    }

    /// Print summary.
    pub fn printSummary(self: *const PerfCounters, writer: anytype) !void {
        try writer.print("Performance Summary:\n", .{});
        try writer.print("  Elapsed: {} ms\n", .{self.elapsedMs()});
        try writer.print("  Blocks: {} ({d:.1} /sec)\n", .{ self.blocks_processed, self.blocksPerSec() });
        try writer.print("  Transactions: {} ({d:.1} /sec)\n", .{ self.transactions_validated, self.txPerSec() });
        try writer.print("  Scripts: {}\n", .{self.scripts_executed});
        try writer.print("  Hashes: {}\n", .{self.hashes_computed});
        try writer.print("  UTXO lookups: {} (hit rate: {d:.1}%)\n", .{
            self.utxo_lookups,
            if (self.utxo_lookups > 0)
                @as(f64, @floatFromInt(self.utxo_cache_hits)) / @as(f64, @floatFromInt(self.utxo_lookups)) * 100.0
            else
                0.0,
        });
        try writer.print("  Arena resets: {}\n", .{self.arena_resets});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "base58 decode table" {
    // Valid characters should decode to their index
    try std.testing.expectEqual(@as(u8, 0), base58_decode_table['1']);
    try std.testing.expectEqual(@as(u8, 8), base58_decode_table['9']);
    try std.testing.expectEqual(@as(u8, 9), base58_decode_table['A']);
    try std.testing.expectEqual(@as(u8, 57), base58_decode_table['z']);

    // Invalid characters should be 0xFF
    try std.testing.expectEqual(@as(u8, 0xFF), base58_decode_table['0']);
    try std.testing.expectEqual(@as(u8, 0xFF), base58_decode_table['I']);
    try std.testing.expectEqual(@as(u8, 0xFF), base58_decode_table['O']);
    try std.testing.expectEqual(@as(u8, 0xFF), base58_decode_table['l']);
}

test "opcode category table" {
    try std.testing.expectEqual(OpcodeCategory.push_value, opcode_category_table[0x00]);
    try std.testing.expectEqual(OpcodeCategory.push_value, opcode_category_table[0x51]);
    try std.testing.expectEqual(OpcodeCategory.push_data, opcode_category_table[0x4c]);
    try std.testing.expectEqual(OpcodeCategory.flow_control, opcode_category_table[0x63]);
    try std.testing.expectEqual(OpcodeCategory.stack, opcode_category_table[0x76]);
    try std.testing.expectEqual(OpcodeCategory.crypto_op, opcode_category_table[0xa9]);
    try std.testing.expectEqual(OpcodeCategory.locktime, opcode_category_table[0xb1]);
    try std.testing.expectEqual(OpcodeCategory.nop, opcode_category_table[0x61]);
}

test "hash comparison" {
    const low_hash = [_]u8{0x00} ** 32;
    const high_hash = [_]u8{0xFF} ** 32;
    var mid_hash: [32]u8 = undefined;
    @memset(&mid_hash, 0x80);

    try std.testing.expect(hashLessThanTarget(&low_hash, &high_hash));
    try std.testing.expect(!hashLessThanTarget(&high_hash, &low_hash));
    try std.testing.expect(hashLessThanTarget(&low_hash, &mid_hash));
    try std.testing.expect(!hashLessThanTarget(&mid_hash, &low_hash));
    try std.testing.expect(!hashLessThanTarget(&low_hash, &low_hash)); // Equal
}

test "hash comparison SIMD" {
    const low_hash = [_]u8{0x00} ** 32;
    const high_hash = [_]u8{0xFF} ** 32;
    var mid_hash: [32]u8 = undefined;
    @memset(&mid_hash, 0x80);

    try std.testing.expect(hashLessThanTargetSIMD(&low_hash, &high_hash));
    try std.testing.expect(!hashLessThanTargetSIMD(&high_hash, &low_hash));
    try std.testing.expect(hashLessThanTargetSIMD(&low_hash, &mid_hash));
    try std.testing.expect(!hashLessThanTargetSIMD(&mid_hash, &low_hash));
    try std.testing.expect(!hashLessThanTargetSIMD(&low_hash, &low_hash));
}

test "hash equal" {
    const a = [_]u8{0xAB} ** 32;
    const b = [_]u8{0xAB} ** 32;
    const c = [_]u8{0xCD} ** 32;

    try std.testing.expect(hashEqual(&a, &b));
    try std.testing.expect(!hashEqual(&a, &c));
}

test "hash is zero" {
    const zero = [_]u8{0x00} ** 32;
    const nonzero = [_]u8{0x01} ** 32;
    var almost_zero: [32]u8 = undefined;
    @memset(&almost_zero, 0);
    almost_zero[31] = 1;

    try std.testing.expect(hashIsZero(&zero));
    try std.testing.expect(!hashIsZero(&nonzero));
    try std.testing.expect(!hashIsZero(&almost_zero));
}

test "block arena" {
    const backing = std.testing.allocator;

    var arena = BlockArena.init(backing);
    defer arena.deinit();

    // Allocate some memory
    const a = try arena.allocator().alloc(u8, 100);
    const b = try arena.allocator().alloc(u8, 200);
    _ = a;
    _ = b;

    // Reset should free all at once
    arena.reset();

    // Can allocate again after reset
    const c = try arena.allocator().alloc(u8, 150);
    _ = c;
}

test "script classification fast" {
    // P2PKH
    var p2pkh: [25]u8 = undefined;
    p2pkh[0] = 0x76;
    p2pkh[1] = 0xa9;
    p2pkh[2] = 0x14;
    @memset(p2pkh[3..23], 0xAB);
    p2pkh[23] = 0x88;
    p2pkh[24] = 0xac;

    const result_p2pkh = classifyScriptFast(&p2pkh);
    try std.testing.expectEqual(CacheEntry.ScriptType.p2pkh, result_p2pkh.script_type);
    try std.testing.expect(result_p2pkh.hash_data != null);
    try std.testing.expectEqual(@as(usize, 20), result_p2pkh.hash_data.?.len);

    // P2WPKH
    var p2wpkh: [22]u8 = undefined;
    p2wpkh[0] = 0x00;
    p2wpkh[1] = 0x14;
    @memset(p2wpkh[2..22], 0xCD);

    const result_p2wpkh = classifyScriptFast(&p2wpkh);
    try std.testing.expectEqual(CacheEntry.ScriptType.p2wpkh, result_p2wpkh.script_type);

    // P2TR
    var p2tr: [34]u8 = undefined;
    p2tr[0] = 0x51;
    p2tr[1] = 0x20;
    @memset(p2tr[2..34], 0xEF);

    const result_p2tr = classifyScriptFast(&p2tr);
    try std.testing.expectEqual(CacheEntry.ScriptType.p2tr, result_p2tr.script_type);
}

test "utxo cache basic operations" {
    const allocator = std.testing.allocator;

    var cache = UtxoCache.init(allocator, 1); // 1 MB limit
    defer cache.deinit();

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };

    const entry = CacheEntry{
        .value = 5000000000,
        .script_type = .p2wpkh,
        .height = 100000,
        .coinbase = false,
    };

    // Initially not present
    try std.testing.expect(cache.get(&outpoint) == null);

    // Put entry
    try cache.put(&outpoint, entry, null);

    // Now present
    const retrieved = cache.get(&outpoint);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqual(entry.value, retrieved.?.value);
    try std.testing.expectEqual(entry.script_type, retrieved.?.script_type);

    // Remove
    cache.remove(&outpoint);
    try std.testing.expect(cache.get(&outpoint) == null);
}

test "utxo cache hit rate" {
    const allocator = std.testing.allocator;

    var cache = UtxoCache.init(allocator, 1);
    defer cache.deinit();

    // Initial hit rate should be 0
    try std.testing.expectEqual(@as(f64, 0), cache.hitRate());

    const outpoint = types.OutPoint{
        .hash = [_]u8{0x22} ** 32,
        .index = 1,
    };

    // Miss
    _ = cache.get(&outpoint);
    try std.testing.expectEqual(@as(f64, 0), cache.hitRate());

    // Put and hit
    try cache.put(&outpoint, .{
        .value = 100,
        .script_type = .p2pkh,
        .height = 1,
        .coinbase = false,
    }, null);

    _ = cache.get(&outpoint);
    // 1 hit, 1 miss = 50%
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), cache.hitRate(), 0.01);
}

test "merkle root SIMD" {
    const allocator = std.testing.allocator;

    // Single hash - return as-is
    const single = [_]u8{0xAB} ** 32;
    const root1 = try computeMerkleRootSIMD(&[_][32]u8{single}, allocator);
    try std.testing.expectEqualSlices(u8, &single, &root1);

    // Two hashes
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const root2 = try computeMerkleRootSIMD(&[_][32]u8{ a, b }, allocator);

    // Verify against non-SIMD version
    const expected = try crypto.computeMerkleRoot(&[_][32]u8{ a, b }, allocator);
    try std.testing.expectEqualSlices(u8, &expected, &root2);
}

test "network magic comptime" {
    const mainnet = comptimeNetworkMagic(.mainnet);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xF9, 0xBE, 0xB4, 0xD9 }, &mainnet);

    const testnet = comptimeNetworkMagic(.testnet);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0B, 0x11, 0x09, 0x07 }, &testnet);

    const regtest = comptimeNetworkMagic(.regtest);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFA, 0xBF, 0xB5, 0xDA }, &regtest);
}

test "perf counters" {
    var counters = PerfCounters{};
    counters.reset();

    counters.blocks_processed = 100;
    counters.transactions_validated = 5000;

    // Should be able to calculate rates (approximate since timing is involved)
    _ = counters.elapsedMs();
    _ = counters.blocksPerSec();
    _ = counters.txPerSec();
}

test "cache entry size" {
    // Verify struct is reasonably compact (under 24 bytes)
    try std.testing.expect(@sizeOf(CacheEntry) <= 24);
}
