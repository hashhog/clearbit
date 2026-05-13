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
//!
//! W105 G19/G20 fix: cache key is now SHA256(nonce || sighash || pubkey || sig || flags_le)
//! — a per-startup CSPRNG nonce prevents HashDoS, and committing to actual
//! signature + pubkey bytes prevents cache-collision attacks.
//! Reference: bitcoin-core/src/script/sigcache.h (CSignatureCache random 256-bit
//! nonce, key = SHA256(nonce || sig || pubkey || hash || flags)).

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
// Cache Key (opaque 64-bit hash)
// ============================================================================

/// A 64-bit opaque cache key derived from SHA256 of all sig material.
/// The full entropy lives in the 256-bit hash; we use the first 8 bytes
/// as the HashMap key (collision probability is negligible).
///
/// This type is kept public so that the W105 audit tests can reference
/// the module-level constant name `CacheKey`, but callers MUST use
/// SigCache.lookup / SigCache.insert — never construct a key by hand.
pub const CacheKey = struct {
    /// First 8 bytes of SHA256(nonce || sighash || pubkey || sig || flags_le).
    raw: u64,

    /// HashMap hash: the raw value is already a cryptographic hash, so return it.
    pub fn hash(self: CacheKey) u64 {
        return self.raw;
    }

    /// Equality comparison for HashMap.
    pub fn eql(a: CacheKey, b: CacheKey) bool {
        return a.raw == b.raw;
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
///
/// Security: a 32-byte CSPRNG nonce is generated at init() time and mixed into
/// every key via SHA256, preventing:
///   - HashDoS: attacker cannot pre-compute colliding keys (G20 fix).
///   - Collision attacks: keys commit to the actual sig + pubkey bytes, so a
///     forged signature on the same (txid, index, flags) cannot get a cache hit
///     (G19 fix).
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

    /// Per-startup 32-byte CSPRNG nonce.
    /// Mixed into every key via SHA256, preventing HashDoS and pre-computation.
    /// Reference: sigcache.h — CSignatureCache random 256-bit nonce.
    nonce: [32]u8,

    /// Statistics: cache hits.
    hits: std.atomic.Value(u64),

    /// Statistics: cache misses.
    misses: std.atomic.Value(u64),

    /// Statistics: total insertions.
    insertions: std.atomic.Value(u64),

    /// Statistics: evictions due to capacity.
    evictions: std.atomic.Value(u64),

    /// Initialize a new signature cache.
    /// Generates a fresh CSPRNG nonce for this cache instance.
    pub fn init(allocator: std.mem.Allocator, max_entries: usize) SigCache {
        const capped_max = @max(MIN_ENTRIES, @min(max_entries, MAX_ENTRIES));
        var nonce: [32]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        return SigCache{
            .entries = std.HashMap(CacheKey, void, CacheKeyContext, 80).init(allocator),
            .max_entries = capped_max,
            .mutex = std.Thread.Mutex{},
            .allocator = allocator,
            .nonce = nonce,
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

    /// Compute the salted cache key for a signature verification.
    ///
    /// key = first 8 bytes of SHA256(nonce || sighash || pubkey_bytes || sig_bytes || flags_le)
    ///
    /// This matches Core's CSignatureCache::ComputeEntryECDSA / ComputeEntrySchnorr
    /// pattern: all material that distinguishes a valid signature is committed to,
    /// and the random nonce prevents pre-computation of collisions.
    ///
    /// Marked pub so W105 G20 audit tests can verify the nonce randomness property.
    pub fn computeKey(
        self: *const SigCache,
        sighash: [32]u8,
        pubkey_bytes: []const u8,
        sig_bytes: []const u8,
        flags: u32,
    ) CacheKey {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&self.nonce);
        h.update(&sighash);
        h.update(pubkey_bytes);
        h.update(sig_bytes);
        var flags_le: [4]u8 = undefined;
        std.mem.writeInt(u32, &flags_le, flags, .little);
        h.update(&flags_le);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        return CacheKey{ .raw = std.mem.readInt(u64, digest[0..8], .little) };
    }

    /// Look up a signature verification result in the cache.
    ///
    /// Parameters:
    ///   sighash      — the 32-byte sighash (txid or taproot sighash) for this input
    ///   pubkey_bytes — raw public key bytes (33 bytes compressed, 65 uncompressed,
    ///                  or 32 bytes x-only for Schnorr)
    ///   sig_bytes    — raw DER/compact signature bytes
    ///   flags        — script verification flags
    ///
    /// Returns true if the signature was previously verified successfully.
    pub fn lookup(
        self: *SigCache,
        sighash: [32]u8,
        pubkey_bytes: []const u8,
        sig_bytes: []const u8,
        flags: u32,
    ) bool {
        const key = self.computeKey(sighash, pubkey_bytes, sig_bytes, flags);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.entries.contains(key)) {
            _ = self.hits.fetchAdd(1, .monotonic);
            return true;
        }

        _ = self.misses.fetchAdd(1, .monotonic);
        return false;
    }

    /// Insert a successful signature verification into the cache.
    /// If the cache is full, a random entry is evicted.
    ///
    /// Parameters mirror those of lookup().
    pub fn insert(
        self: *SigCache,
        sighash: [32]u8,
        pubkey_bytes: []const u8,
        sig_bytes: []const u8,
        flags: u32,
    ) void {
        const key = self.computeKey(sighash, pubkey_bytes, sig_bytes, flags);

        self.mutex.lock();
        defer self.mutex.unlock();

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

    const sighash = [_]u8{0x01} ** 32;
    const pubkey = [_]u8{0x02} ++ [_]u8{0xAB} ** 32; // compressed pubkey
    const sig = [_]u8{0x30, 0x44} ++ [_]u8{0x55} ** 68; // DER sig
    const flags: u32 = 0x1F;

    // Initially not in cache
    try std.testing.expect(!cache.lookup(sighash, &pubkey, &sig, flags));

    // Insert and verify lookup succeeds
    cache.insert(sighash, &pubkey, &sig, flags);
    try std.testing.expect(cache.lookup(sighash, &pubkey, &sig, flags));

    // Different pubkey should not match
    const pubkey2 = [_]u8{0x03} ++ [_]u8{0xAB} ** 32;
    try std.testing.expect(!cache.lookup(sighash, &pubkey2, &sig, flags));

    // Different sig should not match
    const sig2 = [_]u8{0x30, 0x45} ++ [_]u8{0x55} ** 69;
    try std.testing.expect(!cache.lookup(sighash, &pubkey, &sig2, flags));

    // Different flags should not match
    try std.testing.expect(!cache.lookup(sighash, &pubkey, &sig, 0xFF));

    // Clear should remove all entries
    cache.clear();
    try std.testing.expect(!cache.lookup(sighash, &pubkey, &sig, flags));
}

test "signature cache eviction" {
    const allocator = std.testing.allocator;

    // Small cache to test eviction
    var cache = SigCache.init(allocator, MIN_ENTRIES);
    defer cache.deinit();

    // Fill the cache
    for (0..MIN_ENTRIES + 10) |i| {
        var sighash: [32]u8 = [_]u8{0} ** 32;
        sighash[0] = @intCast(i & 0xFF);
        sighash[1] = @intCast((i >> 8) & 0xFF);
        const pubkey = [_]u8{0x02} ++ [_]u8{0x01} ** 32;
        const sig = [_]u8{0x30} ++ [_]u8{0x01} ** 10;
        cache.insert(sighash, &pubkey, &sig, 0);
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

    const sighash = [_]u8{0x42} ** 32;
    const pubkey = [_]u8{0x02} ++ [_]u8{0x99} ** 32;
    const sig = [_]u8{0x30} ++ [_]u8{0x55} ** 10;

    // Miss
    _ = cache.lookup(sighash, &pubkey, &sig, 0);

    // Insert
    cache.insert(sighash, &pubkey, &sig, 0);

    // Hit
    _ = cache.lookup(sighash, &pubkey, &sig, 0);

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
    // Test that different sig material produces different keys
    var cache = SigCache.init(std.testing.allocator, 100);
    defer cache.deinit();

    var keys: [100]CacheKey = undefined;
    for (0..100) |i| {
        var sighash: [32]u8 = [_]u8{0} ** 32;
        sighash[0] = @intCast(i);
        const pubkey = [_]u8{0x02} ++ [_]u8{0x01} ** 32;
        const sig = [_]u8{0x30} ++ [_]u8{0x01} ** 10;
        keys[i] = cache.computeKey(sighash, &pubkey, &sig, 0);
    }

    // Check for collisions (should be rare with a cryptographic hash)
    var collisions: usize = 0;
    for (0..100) |i| {
        for (i + 1..100) |j| {
            if (keys[i].raw == keys[j].raw) collisions += 1;
        }
    }

    // With SHA256 as the hash, collisions across 100 distinct inputs are impossible
    try std.testing.expect(collisions == 0);
}

// ============================================================================
// W105 G19 + G20 fixed tests
// ============================================================================

// W105 G19 FIX: cache key now commits to sig + pubkey bytes.
// A different signature on the same (sighash, index, flags) must be a MISS.
test "w105 G19 fixed: different sig/pubkey bytes produce different cache key (no collision)" {
    var cache = SigCache.init(std.testing.allocator, 100);
    defer cache.deinit();

    const sighash = [_]u8{0x01} ** 32;
    const flags: u32 = 0x1F;

    // Two different pubkeys for the same sighash+flags
    const pubkey_a = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const pubkey_b = [_]u8{0x02} ++ [_]u8{0xBB} ** 32;
    const sig_a = [_]u8{0x30, 0x44} ++ [_]u8{0xCC} ** 68;
    const sig_b = [_]u8{0x30, 0x44} ++ [_]u8{0xDD} ** 68;

    // Insert using (sighash, pubkey_a, sig_a, flags)
    cache.insert(sighash, &pubkey_a, &sig_a, flags);
    try std.testing.expect(cache.lookup(sighash, &pubkey_a, &sig_a, flags));

    // A different pubkey on the same sighash must be a MISS (G19 fix).
    // Before the fix, CacheKey was (txid, index, flags) — no sig/pubkey —
    // so this would have returned a cache HIT, bypassing verification.
    try std.testing.expect(!cache.lookup(sighash, &pubkey_b, &sig_a, flags));

    // A different sig on the same sighash must also be a MISS (G19 fix).
    try std.testing.expect(!cache.lookup(sighash, &pubkey_a, &sig_b, flags));

    // A completely different (pubkey, sig) pair must be a MISS.
    try std.testing.expect(!cache.lookup(sighash, &pubkey_b, &sig_b, flags));
}

// W105 G20 FIX: per-startup CSPRNG nonce in cache key prevents HashDoS.
// Two SigCache instances (each with a fresh nonce) must produce DIFFERENT
// keys for the same input material.
test "w105 G20 fixed: CSPRNG nonce means different cache instances produce different keys" {
    // Two independent caches — each call to init() generates a fresh CSPRNG nonce.
    var cache_a = SigCache.init(std.testing.allocator, 100);
    defer cache_a.deinit();
    var cache_b = SigCache.init(std.testing.allocator, 100);
    defer cache_b.deinit();

    const sighash = [_]u8{0x01} ** 32;
    const pubkey = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;
    const sig = [_]u8{0x30, 0x44} ++ [_]u8{0x55} ** 68;
    const flags: u32 = 0x1F;

    // Nonces are different (probability of collision is 1/2^256)
    try std.testing.expect(!std.mem.eql(u8, &cache_a.nonce, &cache_b.nonce));

    // Keys for the same material differ between cache instances (non-deterministic)
    const key_a = cache_a.computeKey(sighash, &pubkey, &sig, flags);
    const key_b = cache_b.computeKey(sighash, &pubkey, &sig, flags);
    try std.testing.expect(key_a.raw != key_b.raw);

    // Within the same cache, identical material always produces the same key
    const key_a2 = cache_a.computeKey(sighash, &pubkey, &sig, flags);
    try std.testing.expectEqual(key_a.raw, key_a2.raw);
}
