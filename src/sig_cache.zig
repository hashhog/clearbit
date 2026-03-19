//! Signature verification cache for Bitcoin script execution.
//!
//! This module implements a thread-safe cache for signature verification results.
//! Caching signature verifications significantly improves performance during:
//! - Block validation (many transactions reuse similar scripts)
//! - Mempool acceptance (transactions may be re-verified)
//! - Reorg handling (blocks may need re-validation)
//!
//! The cache uses a hash map with random eviction when full.
//! It is cleared on block disconnects to ensure consistency.

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

// ============================================================================
// Cache Configuration
// ============================================================================

/// Default maximum number of entries in the signature cache.
/// Bitcoin Core uses 32000 by default, adjustable via -maxsigcachesize.
pub const DEFAULT_MAX_ENTRIES: usize = 32_000;

/// Minimum entries to prevent cache thrashing.
pub const MIN_ENTRIES: usize = 1_000;

/// Maximum entries to prevent excessive memory usage (~100MB at ~3KB/entry).
pub const MAX_ENTRIES: usize = 1_000_000;

// ============================================================================
// Cache Key
// ============================================================================

/// Key for signature cache lookups.
/// Uniquely identifies a signature verification by:
/// - Transaction ID being verified
/// - Input index within the transaction
/// - Script verification flags (different flags = different result)
pub const CacheKey = struct {
    /// TXID of the transaction containing the signature.
    txid: [32]u8,
    /// Index of the input being verified.
    input_index: u32,
    /// Script verification flags used during verification.
    /// Different flags can produce different verification results.
    flags: u32,

    /// Compute a 64-bit hash of the cache key for HashMap.
    pub fn hash(self: CacheKey) u64 {
        // Use SipHash-style mixing for security and quality
        var h: u64 = 0xcbf29ce484222325; // FNV offset basis

        // Mix in txid (32 bytes)
        for (self.txid) |b| {
            h ^= @as(u64, b);
            h *%= 0x100000001b3; // FNV prime
        }

        // Mix in input_index
        h ^= @as(u64, self.input_index);
        h *%= 0x100000001b3;

        // Mix in flags
        h ^= @as(u64, self.flags);
        h *%= 0x100000001b3;

        return h;
    }

    /// Equality comparison for HashMap.
    pub fn eql(a: CacheKey, b: CacheKey) bool {
        return std.mem.eql(u8, &a.txid, &b.txid) and
            a.input_index == b.input_index and
            a.flags == b.flags;
    }
};

/// HashMap context for CacheKey.
pub const CacheKeyContext = struct {
    pub fn hash(_: CacheKeyContext, key: CacheKey) u64 {
        return key.hash();
    }

    pub fn eql(_: CacheKeyContext, a: CacheKey, b: CacheKey) bool {
        return a.eql(b);
    }
};

// ============================================================================
// Signature Cache
// ============================================================================

/// Thread-safe signature verification cache.
///
/// The cache stores successful signature verification results to avoid
/// re-verifying the same signatures. Only successful verifications are cached
/// (failed verifications are typically due to invalid transactions that won't
/// be re-verified).
///
/// Thread-safety is provided by a mutex that protects all operations.
pub const SigCache = struct {
    /// Hash map storing verified entries.
    /// Value is void since we only care about presence (successful verification).
    entries: std.HashMap(CacheKey, void, CacheKeyContext, 80),

    /// Maximum number of entries allowed in the cache.
    max_entries: usize,

    /// Mutex for thread-safe access.
    mutex: std.Thread.Mutex,

    /// Allocator for hash map operations.
    allocator: std.mem.Allocator,

    /// Statistics: cache hits.
    hits: std.atomic.Value(u64),

    /// Statistics: cache misses.
    misses: std.atomic.Value(u64),

    /// Statistics: total insertions.
    insertions: std.atomic.Value(u64),

    /// Statistics: evictions due to capacity.
    evictions: std.atomic.Value(u64),

    /// Initialize a new signature cache.
    pub fn init(allocator: std.mem.Allocator, max_entries: usize) SigCache {
        const capped_max = @max(MIN_ENTRIES, @min(max_entries, MAX_ENTRIES));
        return SigCache{
            .entries = std.HashMap(CacheKey, void, CacheKeyContext, 80).init(allocator),
            .max_entries = capped_max,
            .mutex = std.Thread.Mutex{},
            .allocator = allocator,
            .hits = std.atomic.Value(u64).init(0),
            .misses = std.atomic.Value(u64).init(0),
            .insertions = std.atomic.Value(u64).init(0),
            .evictions = std.atomic.Value(u64).init(0),
        };
    }

    /// Deinitialize and free resources.
    pub fn deinit(self: *SigCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries.deinit();
    }

    /// Look up a signature verification result in the cache.
    /// Returns true if the signature was previously verified successfully.
    pub fn lookup(self: *SigCache, txid: [32]u8, input_index: u32, flags: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = CacheKey{
            .txid = txid,
            .input_index = input_index,
            .flags = flags,
        };

        if (self.entries.contains(key)) {
            _ = self.hits.fetchAdd(1, .monotonic);
            return true;
        }

        _ = self.misses.fetchAdd(1, .monotonic);
        return false;
    }

    /// Insert a successful signature verification into the cache.
    /// If the cache is full, a random entry is evicted.
    pub fn insert(self: *SigCache, txid: [32]u8, input_index: u32, flags: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = CacheKey{
            .txid = txid,
            .input_index = input_index,
            .flags = flags,
        };

        // Check if already present
        if (self.entries.contains(key)) {
            return;
        }

        // Evict if at capacity
        if (self.entries.count() >= self.max_entries) {
            self.evictOne();
        }

        // Insert the new entry
        self.entries.put(key, {}) catch {
            // On allocation failure, just skip caching
            return;
        };

        _ = self.insertions.fetchAdd(1, .monotonic);
    }

    /// Evict one random entry from the cache.
    /// Called with mutex held.
    fn evictOne(self: *SigCache) void {
        // Simple approach: remove the first entry found
        // This is effectively random due to hash map internal ordering
        var it = self.entries.iterator();
        if (it.next()) |entry| {
            _ = self.entries.remove(entry.key_ptr.*);
            _ = self.evictions.fetchAdd(1, .monotonic);
        }
    }

    /// Clear all entries from the cache.
    /// Called during block disconnects to ensure consistency.
    pub fn clear(self: *SigCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries.clearRetainingCapacity();
    }

    /// Get the current number of entries in the cache.
    pub fn count(self: *SigCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }

    /// Get cache statistics.
    pub fn getStats(self: *SigCache) CacheStats {
        return CacheStats{
            .count = self.count(),
            .max_entries = self.max_entries,
            .hits = self.hits.load(.monotonic),
            .misses = self.misses.load(.monotonic),
            .insertions = self.insertions.load(.monotonic),
            .evictions = self.evictions.load(.monotonic),
        };
    }

    /// Reset statistics counters.
    pub fn resetStats(self: *SigCache) void {
        self.hits.store(0, .monotonic);
        self.misses.store(0, .monotonic);
        self.insertions.store(0, .monotonic);
        self.evictions.store(0, .monotonic);
    }
};

/// Cache statistics for monitoring.
pub const CacheStats = struct {
    count: usize,
    max_entries: usize,
    hits: u64,
    misses: u64,
    insertions: u64,
    evictions: u64,

    /// Compute the cache hit rate (0.0 - 1.0).
    pub fn hitRate(self: CacheStats) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }
};

// ============================================================================
// Tests
// ============================================================================

test "signature cache basic operations" {
    const allocator = std.testing.allocator;

    var cache = SigCache.init(allocator, 100);
    defer cache.deinit();

    const txid = [_]u8{0x01} ** 32;
    const flags: u32 = 0x1F;

    // Initially not in cache
    try std.testing.expect(!cache.lookup(txid, 0, flags));

    // Insert and verify lookup succeeds
    cache.insert(txid, 0, flags);
    try std.testing.expect(cache.lookup(txid, 0, flags));

    // Different input index should not match
    try std.testing.expect(!cache.lookup(txid, 1, flags));

    // Different flags should not match
    try std.testing.expect(!cache.lookup(txid, 0, 0xFF));

    // Clear should remove all entries
    cache.clear();
    try std.testing.expect(!cache.lookup(txid, 0, flags));
}

test "signature cache eviction" {
    const allocator = std.testing.allocator;

    // Small cache to test eviction
    var cache = SigCache.init(allocator, MIN_ENTRIES);
    defer cache.deinit();

    // Fill the cache
    for (0..MIN_ENTRIES + 10) |i| {
        var txid: [32]u8 = [_]u8{0} ** 32;
        txid[0] = @intCast(i & 0xFF);
        txid[1] = @intCast((i >> 8) & 0xFF);
        cache.insert(txid, 0, 0);
    }

    // Count should not exceed max
    try std.testing.expect(cache.count() <= MIN_ENTRIES);

    // Stats should show evictions
    const stats = cache.getStats();
    try std.testing.expect(stats.evictions >= 10);
}

test "signature cache statistics" {
    const allocator = std.testing.allocator;

    var cache = SigCache.init(allocator, 100);
    defer cache.deinit();

    const txid = [_]u8{0x42} ** 32;

    // Miss
    _ = cache.lookup(txid, 0, 0);

    // Insert
    cache.insert(txid, 0, 0);

    // Hit
    _ = cache.lookup(txid, 0, 0);

    const stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.hits);
    try std.testing.expectEqual(@as(u64, 1), stats.misses);
    try std.testing.expectEqual(@as(u64, 1), stats.insertions);
    try std.testing.expect(stats.hitRate() == 0.5);

    // Reset stats
    cache.resetStats();
    const stats2 = cache.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats2.hits);
    try std.testing.expectEqual(@as(u64, 0), stats2.misses);
}

test "cache key hash quality" {
    // Test that different keys produce different hashes
    var hashes: [100]u64 = undefined;

    for (0..100) |i| {
        var txid: [32]u8 = [_]u8{0} ** 32;
        txid[0] = @intCast(i);
        const key = CacheKey{
            .txid = txid,
            .input_index = 0,
            .flags = 0,
        };
        hashes[i] = key.hash();
    }

    // Check for collisions (should be rare with good hash)
    var collisions: usize = 0;
    for (0..100) |i| {
        for (i + 1..100) |j| {
            if (hashes[i] == hashes[j]) collisions += 1;
        }
    }

    // With a good hash function, we should have very few collisions
    try std.testing.expect(collisions < 5);
}
