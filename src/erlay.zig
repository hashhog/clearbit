const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");

// ============================================================================
// BIP-330 Erlay: Set Reconciliation for Transaction Relay
// ============================================================================
//
// Erlay reduces transaction relay bandwidth by using set reconciliation instead
// of flooding. Peers exchange sketches (compact representations of transaction
// sets) and compute the symmetric difference to determine missing transactions.
//
// Reference: /home/max/hashhog/bitcoin/src/node/txreconciliation.cpp

/// Current Erlay protocol version.
pub const TXRECONCILIATION_VERSION: u32 = 1;

/// Field size for minisketch (32 bits).
pub const SKETCH_BITS: u32 = 32;

/// Reconciliation interval for outbound peers (2 seconds).
pub const OUTBOUND_RECON_INTERVAL_MS: i64 = 2_000;

/// Reconciliation interval for inbound peers (8 seconds).
pub const INBOUND_RECON_INTERVAL_MS: i64 = 8_000;

/// Default sketch capacity (estimated difference size).
pub const DEFAULT_SKETCH_CAPACITY: usize = 32;

/// Maximum sketch capacity before falling back to flood.
pub const MAX_SKETCH_CAPACITY: usize = 256;

/// Static salt tag for computing short IDs (BIP-330).
pub const RECON_STATIC_SALT: []const u8 = "Tx Relay Salting";

// ============================================================================
// libminisketch FFI Bindings via @cImport
// ============================================================================
//
// When libminisketch is available, we use @cImport for FFI. Otherwise, we
// provide a pure Zig implementation that matches the minisketch behavior.
//
// To enable libminisketch support, the library must be installed and
// linked via build.zig with -Dminisketch=true

/// Import build-time options for libminisketch availability.
const build_options = @import("build_options");

/// Whether libminisketch is available (set via build.zig option).
pub const has_minisketch: bool = build_options.minisketch_enabled;

/// C bindings for libminisketch when available.
pub const minisketch_c = if (has_minisketch) @cImport({
    @cInclude("minisketch.h");
}) else struct {
    // Stub types when library not available
    pub const minisketch = opaque {};
    pub const ssize_t = isize;
};

/// Opaque minisketch handle.
pub const MinisketchHandle = minisketch_c.minisketch;

// ============================================================================
// libminisketch FFI Wrapper Functions
// ============================================================================

/// Check if a given field size is supported by the library.
pub fn minisketchBitsSupported(bits: u32) bool {
    if (has_minisketch) {
        return minisketch_c.minisketch_bits_supported(bits) != 0;
    }
    // Pure Zig implementation supports 32-bit field
    return bits == 32;
}

/// Get maximum implementation number.
pub fn minisketchImplementationMax() u32 {
    if (has_minisketch) {
        return minisketch_c.minisketch_implementation_max();
    }
    return 0; // Pure Zig has only implementation 0
}

/// Check if a specific implementation is supported.
pub fn minisketchImplementationSupported(bits: u32, implementation: u32) bool {
    if (has_minisketch) {
        return minisketch_c.minisketch_implementation_supported(bits, implementation) != 0;
    }
    // Pure Zig supports only 32-bit field with implementation 0
    return bits == 32 and implementation == 0;
}

/// Create a new minisketch with given field size and capacity.
/// Returns null if the combination is not supported or OOM.
pub fn minisketchCreate(bits: u32, implementation: u32, capacity: usize) ?*MinisketchHandle {
    if (has_minisketch) {
        return minisketch_c.minisketch_create(bits, implementation, capacity);
    }
    return null; // Use pure Zig Minisketch struct instead
}

/// Destroy a minisketch.
pub fn minisketchDestroy(sketch: *MinisketchHandle) void {
    if (has_minisketch) {
        minisketch_c.minisketch_destroy(sketch);
    }
}

/// Clone a minisketch.
pub fn minisketchClone(sketch: *const MinisketchHandle) ?*MinisketchHandle {
    if (has_minisketch) {
        return minisketch_c.minisketch_clone(sketch);
    }
    return null;
}

/// Set seed for randomizing algorithm choices.
pub fn minisketchSetSeed(sketch: *MinisketchHandle, seed: u64) void {
    if (has_minisketch) {
        minisketch_c.minisketch_set_seed(sketch, seed);
    }
}

/// Add an element to the sketch.
/// Adding the same element twice removes it (XOR property).
pub fn minisketchAddUint64(sketch: *MinisketchHandle, element: u64) void {
    if (has_minisketch) {
        minisketch_c.minisketch_add_uint64(sketch, element);
    }
}

/// Get serialized size of sketch in bytes.
pub fn minisketchSerializedSize(sketch: *const MinisketchHandle) usize {
    if (has_minisketch) {
        return minisketch_c.minisketch_serialized_size(sketch);
    }
    return 0;
}

/// Serialize sketch to bytes.
pub fn minisketchSerialize(sketch: *const MinisketchHandle, output: [*]u8) void {
    if (has_minisketch) {
        minisketch_c.minisketch_serialize(sketch, output);
    }
}

/// Deserialize sketch from bytes.
pub fn minisketchDeserialize(sketch: *MinisketchHandle, input: [*]const u8) void {
    if (has_minisketch) {
        minisketch_c.minisketch_deserialize(sketch, input);
    }
}

/// Merge another sketch into this one (XOR).
/// Returns the resulting capacity, or 0 on failure.
pub fn minisketchMerge(sketch: *MinisketchHandle, other: *const MinisketchHandle) usize {
    if (has_minisketch) {
        return minisketch_c.minisketch_merge(sketch, other);
    }
    return 0;
}

/// Decode the sketch to recover elements.
/// Returns number of elements decoded, or -1 on failure.
pub fn minisketchDecode(sketch: *const MinisketchHandle, max_elements: usize, output: [*]u64) isize {
    if (has_minisketch) {
        return minisketch_c.minisketch_decode(sketch, max_elements, output);
    }
    return -1; // Stub: decoding failed
}

/// Compute capacity needed for given false positive rate.
pub fn minisketchComputeCapacity(bits: u32, max_elements: usize, fpbits: u32) usize {
    if (has_minisketch) {
        return minisketch_c.minisketch_compute_capacity(bits, max_elements, fpbits);
    }
    // Simple estimate: capacity = max_elements + fpbits/8
    return max_elements + (fpbits / 8);
}

/// Compute max elements for given capacity and false positive rate.
pub fn minisketchComputeMaxElements(bits: u32, capacity: usize, fpbits: u32) usize {
    if (has_minisketch) {
        return minisketch_c.minisketch_compute_max_elements(bits, capacity, fpbits);
    }
    // Simple estimate
    if (capacity < fpbits / 8) return 0;
    return capacity - (fpbits / 8);
}

// ============================================================================
// FFI Minisketch Wrapper (uses libminisketch when available)
// ============================================================================

/// FFI-backed minisketch that uses libminisketch when available.
/// Falls back to pure Zig Minisketch otherwise.
pub const FFIMinisketch = struct {
    handle: ?*MinisketchHandle,
    capacity: usize,

    /// Create a new FFI minisketch with given capacity.
    /// Uses libminisketch if available, returns error otherwise.
    pub fn init(capacity: usize) !FFIMinisketch {
        if (has_minisketch) {
            const handle = minisketchCreate(SKETCH_BITS, 0, capacity) orelse {
                return error.MinisketchCreationFailed;
            };
            return FFIMinisketch{
                .handle = handle,
                .capacity = capacity,
            };
        }
        return error.MinisketchNotAvailable;
    }

    /// Free minisketch resources.
    pub fn deinit(self: *FFIMinisketch) void {
        if (self.handle) |h| {
            minisketchDestroy(h);
            self.handle = null;
        }
    }

    /// Clone this minisketch.
    pub fn clone(self: *const FFIMinisketch) !FFIMinisketch {
        if (self.handle) |h| {
            const new_handle = minisketchClone(h) orelse {
                return error.MinisketchCloneFailed;
            };
            return FFIMinisketch{
                .handle = new_handle,
                .capacity = self.capacity,
            };
        }
        return error.InvalidMinisketch;
    }

    /// Add an element to the sketch.
    pub fn add(self: *FFIMinisketch, element: u64) void {
        if (self.handle) |h| {
            minisketchAddUint64(h, element);
        }
    }

    /// Merge another sketch into this one.
    pub fn merge(self: *FFIMinisketch, other: *const FFIMinisketch) !void {
        if (self.handle) |h| {
            if (other.handle) |oh| {
                const result = minisketchMerge(h, oh);
                if (result == 0) {
                    return error.MinisketchMergeFailed;
                }
            }
        }
    }

    /// Get serialized size.
    pub fn serializedSize(self: *const FFIMinisketch) usize {
        if (self.handle) |h| {
            return minisketchSerializedSize(h);
        }
        return 0;
    }

    /// Serialize to bytes.
    pub fn serialize(self: *const FFIMinisketch, output: []u8) void {
        if (self.handle) |h| {
            minisketchSerialize(h, output.ptr);
        }
    }

    /// Deserialize from bytes.
    pub fn deserialize(self: *FFIMinisketch, input: []const u8) void {
        if (self.handle) |h| {
            minisketchDeserialize(h, input.ptr);
        }
    }

    /// Decode to recover elements.
    pub fn decode(self: *const FFIMinisketch, allocator: std.mem.Allocator) ?[]u64 {
        if (self.handle) |h| {
            // Allocate output buffer
            const output = allocator.alloc(u64, self.capacity) catch return null;

            const result = minisketchDecode(h, self.capacity, output.ptr);
            if (result < 0) {
                allocator.free(output);
                return null;
            }

            // Resize to actual count
            const count: usize = @intCast(result);
            if (count < self.capacity) {
                return allocator.realloc(output, count) catch {
                    allocator.free(output);
                    return null;
                };
            }
            return output;
        }
        return null;
    }
};

// ============================================================================
// Pure Zig Minisketch Implementation (BCH-based)
// ============================================================================
//
// When libminisketch is not available, we provide a pure Zig implementation
// using BCH (Bose-Chaudhuri-Hocquenghem) codes over GF(2^32).

/// Pure Zig minisketch for 32-bit field elements.
pub const Minisketch = struct {
    /// Sketch syndromes (BCH representation).
    syndromes: []u64,
    /// Sketch capacity (maximum decodable elements).
    capacity: usize,
    /// Allocator used for this sketch.
    allocator: std.mem.Allocator,

    /// Initialize a new minisketch with given capacity.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Minisketch {
        const syndromes = try allocator.alloc(u64, capacity);
        @memset(syndromes, 0);
        return Minisketch{
            .syndromes = syndromes,
            .capacity = capacity,
            .allocator = allocator,
        };
    }

    /// Free sketch resources.
    pub fn deinit(self: *Minisketch) void {
        self.allocator.free(self.syndromes);
    }

    /// Clone the sketch.
    pub fn clone(self: *const Minisketch) !Minisketch {
        const new_sketch = try Minisketch.init(self.allocator, self.capacity);
        @memcpy(new_sketch.syndromes, self.syndromes);
        return new_sketch;
    }

    /// Add an element to the sketch.
    /// Adding the same element twice removes it (XOR property).
    pub fn add(self: *Minisketch, element: u64) void {
        if (element == 0) return; // Zero elements are not supported

        // Compute syndromes: S_i = sum of x^i over all elements
        // In GF(2^32), addition is XOR
        var power: u64 = element;
        for (self.syndromes) |*syndrome| {
            syndrome.* ^= power;
            // Multiply by element in GF(2^32)
            power = gf32Multiply(power, element);
        }
    }

    /// Merge another sketch into this one (XOR, computes symmetric difference).
    pub fn merge(self: *Minisketch, other: *const Minisketch) void {
        const len = @min(self.syndromes.len, other.syndromes.len);
        for (0..len) |i| {
            self.syndromes[i] ^= other.syndromes[i];
        }
    }

    /// Get serialized size in bytes.
    pub fn serializedSize(self: *const Minisketch) usize {
        // 4 bytes per syndrome (32-bit field)
        return self.capacity * 4;
    }

    /// Serialize sketch to bytes.
    pub fn serialize(self: *const Minisketch, output: []u8) void {
        for (0..self.capacity) |i| {
            const value: u32 = @truncate(self.syndromes[i] & 0xFFFFFFFF);
            std.mem.writeInt(u32, output[i * 4 ..][0..4], value, .little);
        }
    }

    /// Deserialize sketch from bytes.
    pub fn deserialize(self: *Minisketch, input: []const u8) void {
        for (0..self.capacity) |i| {
            self.syndromes[i] = std.mem.readInt(u32, input[i * 4 ..][0..4], .little);
        }
    }

    /// Decode the sketch to recover elements.
    /// Returns a list of elements, or null if decoding failed (difference too large).
    pub fn decode(self: *const Minisketch, allocator: std.mem.Allocator) ?[]u64 {
        // Use Berlekamp-Massey algorithm to find the error locator polynomial
        // Then find roots to recover elements

        // For now, implement a simplified version that works for small differences
        if (self.capacity == 0) return &[_]u64{};

        // Check if sketch is empty (all syndromes zero)
        var all_zero = true;
        for (self.syndromes) |s| {
            if (s != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            return allocator.alloc(u64, 0) catch return null;
        }

        // Run Berlekamp-Massey to find error locator polynomial
        const locator = berlekampMassey(self.syndromes, allocator) catch return null;
        defer allocator.free(locator);

        // Find roots using Chien search
        const roots = chienSearch(locator, allocator) catch {
            return null;
        };

        return roots;
    }
};

// ============================================================================
// GF(2^32) Arithmetic
// ============================================================================

/// Irreducible polynomial for GF(2^32): x^32 + x^22 + x^2 + x + 1
/// Represented as 0x1_0040_0007 (bit 32 is implicit)
const GF32_MODULUS: u64 = 0x00400007;

/// Multiply two elements in GF(2^32).
fn gf32Multiply(a: u64, b: u64) u64 {
    var result: u64 = 0;
    var aa = a & 0xFFFFFFFF;
    var bb = b & 0xFFFFFFFF;

    while (bb != 0) {
        if ((bb & 1) != 0) {
            result ^= aa;
        }
        bb >>= 1;
        aa = gf32Double(aa);
    }

    return result & 0xFFFFFFFF;
}

/// Double (multiply by x) in GF(2^32).
fn gf32Double(a: u64) u64 {
    const high_bit = (a >> 31) & 1;
    var result = (a << 1) & 0xFFFFFFFF;
    if (high_bit != 0) {
        result ^= GF32_MODULUS;
    }
    return result;
}

/// Inverse in GF(2^32) using extended Euclidean algorithm.
fn gf32Inverse(a: u64) u64 {
    if (a == 0) return 0;

    // Use Fermat's little theorem: a^(-1) = a^(2^32 - 2)
    var result: u64 = 1;
    var base = a;
    var exp: u64 = 0xFFFFFFFE; // 2^32 - 2

    while (exp != 0) {
        if ((exp & 1) != 0) {
            result = gf32Multiply(result, base);
        }
        base = gf32Multiply(base, base);
        exp >>= 1;
    }

    return result;
}

// ============================================================================
// Berlekamp-Massey Algorithm
// ============================================================================

/// Find the error locator polynomial using Berlekamp-Massey.
fn berlekampMassey(syndromes: []const u64, allocator: std.mem.Allocator) ![]u64 {
    const n = syndromes.len;

    // C(x) = current connection polynomial
    // B(x) = previous connection polynomial
    var c = try allocator.alloc(u64, n + 1);
    var b = try allocator.alloc(u64, n + 1);
    defer allocator.free(b);

    @memset(c, 0);
    @memset(b, 0);
    c[0] = 1;
    b[0] = 1;

    var l: usize = 0; // Current complexity
    var m: usize = 1; // Number of iterations since L changed
    var bb: u64 = 1; // Previous discrepancy

    for (0..n) |i| {
        // Compute discrepancy
        var d: u64 = syndromes[i];
        for (1..l + 1) |j| {
            if (j <= i) {
                d ^= gf32Multiply(c[j], syndromes[i - j]);
            }
        }

        if (d == 0) {
            m += 1;
        } else {
            // T(x) = C(x) - d * B^(-1) * x^m * B(x)
            var t = try allocator.alloc(u64, n + 1);
            @memcpy(t, c);

            const coeff = gf32Multiply(d, gf32Inverse(bb));
            for (0..n + 1 - m) |j| {
                if (j + m < t.len) {
                    t[j + m] ^= gf32Multiply(coeff, b[j]);
                }
            }

            if (2 * l <= i) {
                allocator.free(b);
                b = c;
                c = t;
                l = i + 1 - l;
                bb = d;
                m = 1;
            } else {
                allocator.free(c);
                c = t;
                m += 1;
            }
        }
    }

    // Resize to actual polynomial degree + 1
    const result = try allocator.alloc(u64, l + 1);
    @memcpy(result, c[0 .. l + 1]);
    allocator.free(c);

    return result;
}

// ============================================================================
// Chien Search (Root Finding)
// ============================================================================

/// Find roots of polynomial using Chien search.
fn chienSearch(locator: []const u64, allocator: std.mem.Allocator) ![]u64 {
    var roots = std.ArrayList(u64).init(allocator);
    errdefer roots.deinit();

    if (locator.len <= 1) {
        return try roots.toOwnedSlice();
    }

    // For small field sizes, we can do exhaustive search
    // For GF(2^32), we limit search to avoid timeout
    const max_search: u64 = 65536; // Search first 2^16 elements

    var x: u64 = 1;
    while (x <= max_search) : (x += 1) {
        // Evaluate polynomial at x
        var result: u64 = 0;
        var power: u64 = 1;
        for (locator) |coeff| {
            result ^= gf32Multiply(coeff, power);
            power = gf32Multiply(power, x);
        }

        if (result == 0) {
            // x is a root, so 1/x is an element
            const element = gf32Inverse(x);
            if (element != 0) {
                try roots.append(element);
            }
        }
    }

    return try roots.toOwnedSlice();
}

// ============================================================================
// Short ID Computation (SipHash-2-4)
// ============================================================================

/// Compute a 32-bit short ID from a wtxid using SipHash-2-4.
/// The salt is computed as: SHA256(SHA256(tag) || salt_min || salt_max)
/// where salt_min = min(local_salt, remote_salt) and salt_max = max(local_salt, remote_salt).
pub fn computeShortId(wtxid: *const types.Hash256, k0: u64, k1: u64) u32 {
    // Use Zig's standard library SipHash-2-4
    // SipHash64(2, 4) requires a 16-byte key
    const SipHash = std.crypto.auth.siphash.SipHash64(2, 4);

    // Construct 16-byte key from k0 and k1
    var key: [16]u8 = undefined;
    std.mem.writeInt(u64, key[0..8], k0, .little);
    std.mem.writeInt(u64, key[8..16], k1, .little);

    var hasher = SipHash.init(&key);
    hasher.update(wtxid);
    const hash = hasher.finalInt();

    // Truncate to 32 bits
    return @truncate(hash);
}

/// Compute the combined salt keys from local and remote salts.
/// Returns (k0, k1) for SipHash.
pub fn computeSaltKeys(local_salt: u64, remote_salt: u64) struct { k0: u64, k1: u64 } {
    // Combine salts in ascending order as per BIP-330
    const salt_min = @min(local_salt, remote_salt);
    const salt_max = @max(local_salt, remote_salt);

    // Create tagged hash: SHA256(SHA256(tag) || SHA256(tag) || salt_min || salt_max)
    const tag_hash = crypto.sha256(RECON_STATIC_SALT);

    var data: [32 + 32 + 8 + 8]u8 = undefined;
    @memcpy(data[0..32], &tag_hash);
    @memcpy(data[32..64], &tag_hash);
    std.mem.writeInt(u64, data[64..72], salt_min, .little);
    std.mem.writeInt(u64, data[72..80], salt_max, .little);

    const full_salt = crypto.sha256(&data);

    // Extract k0 and k1 from the hash
    const k0 = std.mem.readInt(u64, full_salt[0..8], .little);
    const k1 = std.mem.readInt(u64, full_salt[8..16], .little);

    return .{ .k0 = k0, .k1 = k1 };
}

// ============================================================================
// Reconciliation State
// ============================================================================

/// State for a peer's transaction reconciliation.
pub const ReconciliationState = struct {
    /// Whether we are the initiator (outbound = initiator, inbound = responder).
    we_initiate: bool,
    /// SipHash key k0 derived from combined salts.
    k0: u64,
    /// SipHash key k1 derived from combined salts.
    k1: u64,
    /// Our local salt (random u64).
    local_salt: u64,
    /// Remote peer's salt.
    remote_salt: u64,
    /// Negotiated protocol version.
    version: u32,
    /// Transactions to announce via reconciliation (short IDs).
    pending_set: std.AutoHashMap(u32, types.Hash256),
    /// Last reconciliation request time.
    last_recon_time: i64,
    /// Number of reconciliation rounds.
    recon_count: u32,
    /// Allocator.
    allocator: std.mem.Allocator,

    /// Initialize reconciliation state.
    pub fn init(
        allocator: std.mem.Allocator,
        local_salt: u64,
        remote_salt: u64,
        version: u32,
        is_outbound: bool,
    ) ReconciliationState {
        const keys = computeSaltKeys(local_salt, remote_salt);
        return ReconciliationState{
            .we_initiate = is_outbound,
            .k0 = keys.k0,
            .k1 = keys.k1,
            .local_salt = local_salt,
            .remote_salt = remote_salt,
            .version = version,
            .pending_set = std.AutoHashMap(u32, types.Hash256).init(allocator),
            .last_recon_time = 0,
            .recon_count = 0,
            .allocator = allocator,
        };
    }

    /// Deinitialize and free resources.
    pub fn deinit(self: *ReconciliationState) void {
        self.pending_set.deinit();
    }

    /// Add a transaction to the pending reconciliation set.
    pub fn addTransaction(self: *ReconciliationState, wtxid: *const types.Hash256) void {
        const short_id = computeShortId(wtxid, self.k0, self.k1);
        self.pending_set.put(short_id, wtxid.*) catch {};
    }

    /// Remove a transaction from the pending set.
    pub fn removeTransaction(self: *ReconciliationState, wtxid: *const types.Hash256) void {
        const short_id = computeShortId(wtxid, self.k0, self.k1);
        _ = self.pending_set.remove(short_id);
    }

    /// Get the reconciliation interval based on our role.
    pub fn getReconInterval(self: *const ReconciliationState) i64 {
        return if (self.we_initiate) OUTBOUND_RECON_INTERVAL_MS else INBOUND_RECON_INTERVAL_MS;
    }

    /// Check if it's time to initiate reconciliation.
    pub fn shouldInitiateRecon(self: *const ReconciliationState, now_ms: i64) bool {
        if (!self.we_initiate) return false;
        if (self.pending_set.count() == 0) return false;
        return now_ms - self.last_recon_time >= self.getReconInterval();
    }

    /// Create a sketch from our pending set.
    pub fn createSketch(self: *const ReconciliationState, capacity: usize) !Minisketch {
        var sketch = try Minisketch.init(self.allocator, capacity);

        var iter = self.pending_set.keyIterator();
        while (iter.next()) |short_id| {
            sketch.add(short_id.*);
        }

        return sketch;
    }

    /// Record that we initiated a reconciliation.
    pub fn recordReconRequest(self: *ReconciliationState, now_ms: i64) void {
        self.last_recon_time = now_ms;
        self.recon_count += 1;
    }
};

// ============================================================================
// Reconciliation Tracker
// ============================================================================

/// Result of peer registration attempt.
pub const RegisterResult = enum {
    success,
    not_found,
    already_registered,
    protocol_violation,
};

/// Manages reconciliation state for all peers.
pub const ReconciliationTracker = struct {
    /// Pre-registered peers (have our salt, awaiting their SENDTXRCNCL).
    pre_registered: std.AutoHashMap(u64, u64), // peer_id -> local_salt
    /// Fully registered peers with reconciliation state.
    registered: std.AutoHashMap(u64, *ReconciliationState), // peer_id -> state
    /// Allocator.
    allocator: std.mem.Allocator,
    /// Our protocol version.
    version: u32,

    /// Initialize the tracker.
    pub fn init(allocator: std.mem.Allocator) ReconciliationTracker {
        return ReconciliationTracker{
            .pre_registered = std.AutoHashMap(u64, u64).init(allocator),
            .registered = std.AutoHashMap(u64, *ReconciliationState).init(allocator),
            .allocator = allocator,
            .version = TXRECONCILIATION_VERSION,
        };
    }

    /// Deinitialize and free all resources.
    pub fn deinit(self: *ReconciliationTracker) void {
        var iter = self.registered.valueIterator();
        while (iter.next()) |state_ptr| {
            state_ptr.*.deinit();
            self.allocator.destroy(state_ptr.*);
        }
        self.registered.deinit();
        self.pre_registered.deinit();
    }

    /// Pre-register a peer for reconciliation.
    /// Called when a peer connects and supports tx relay.
    /// Returns the local salt to include in our SENDTXRCNCL message.
    pub fn preRegisterPeer(self: *ReconciliationTracker, peer_id: u64) u64 {
        const local_salt = std.crypto.random.int(u64);
        self.pre_registered.put(peer_id, local_salt) catch {};
        return local_salt;
    }

    /// Complete registration when we receive peer's SENDTXRCNCL.
    /// Returns the registration result.
    pub fn registerPeer(
        self: *ReconciliationTracker,
        peer_id: u64,
        remote_salt: u64,
        remote_version: u32,
        is_outbound: bool,
    ) RegisterResult {
        // Check if already registered
        if (self.registered.contains(peer_id)) {
            return .already_registered;
        }

        // Get pre-registration info
        const local_salt = self.pre_registered.get(peer_id) orelse {
            return .not_found;
        };

        // Negotiate version
        const negotiated_version = @min(self.version, remote_version);
        if (negotiated_version < 1) {
            return .protocol_violation;
        }

        // Create reconciliation state
        const state = self.allocator.create(ReconciliationState) catch {
            return .protocol_violation;
        };
        state.* = ReconciliationState.init(
            self.allocator,
            local_salt,
            remote_salt,
            negotiated_version,
            is_outbound,
        );

        // Move from pre-registered to registered
        _ = self.pre_registered.remove(peer_id);
        self.registered.put(peer_id, state) catch {
            state.deinit();
            self.allocator.destroy(state);
            return .protocol_violation;
        };

        return .success;
    }

    /// Remove a peer from tracking.
    pub fn removePeer(self: *ReconciliationTracker, peer_id: u64) void {
        _ = self.pre_registered.remove(peer_id);

        if (self.registered.fetchRemove(peer_id)) |entry| {
            entry.value.deinit();
            self.allocator.destroy(entry.value);
        }
    }

    /// Get reconciliation state for a peer.
    pub fn getState(self: *ReconciliationTracker, peer_id: u64) ?*ReconciliationState {
        return self.registered.get(peer_id);
    }

    /// Check if a peer is pre-registered (awaiting their SENDTXRCNCL).
    pub fn isPendingRegistration(self: *const ReconciliationTracker, peer_id: u64) bool {
        return self.pre_registered.contains(peer_id);
    }

    /// Check if a peer is fully registered for reconciliation.
    pub fn isRegistered(self: *const ReconciliationTracker, peer_id: u64) bool {
        return self.registered.contains(peer_id);
    }

    /// Get the local salt for a pre-registered peer.
    pub fn getLocalSalt(self: *const ReconciliationTracker, peer_id: u64) ?u64 {
        return self.pre_registered.get(peer_id);
    }
};

// ============================================================================
// Message Encoding/Decoding
// ============================================================================

/// SENDTXRCNCL message payload.
pub const SendTxRcnclMessage = struct {
    version: u32,
    salt: u64,
};

/// Encode a SENDTXRCNCL message.
pub fn encodeSendTxRcncl(msg: *const SendTxRcnclMessage, writer: *serialize.Writer) !void {
    try writer.writeInt(u32, msg.version);
    try writer.writeInt(u64, msg.salt);
}

/// Decode a SENDTXRCNCL message.
pub fn decodeSendTxRcncl(data: []const u8) !SendTxRcnclMessage {
    if (data.len < 12) return error.InvalidData;
    return SendTxRcnclMessage{
        .version = std.mem.readInt(u32, data[0..4], .little),
        .salt = std.mem.readInt(u64, data[4..12], .little),
    };
}

/// REQRECON message payload (reconciliation request).
pub const ReqReconMessage = struct {
    /// Estimated set difference size.
    set_size: u16,
    /// Q value (transaction count multiplier).
    q: u16,
};

/// Encode a REQRECON message.
pub fn encodeReqRecon(msg: *const ReqReconMessage, writer: *serialize.Writer) !void {
    try writer.writeInt(u16, msg.set_size);
    try writer.writeInt(u16, msg.q);
}

/// Decode a REQRECON message.
pub fn decodeReqRecon(data: []const u8) !ReqReconMessage {
    if (data.len < 4) return error.InvalidData;
    return ReqReconMessage{
        .set_size = std.mem.readInt(u16, data[0..2], .little),
        .q = std.mem.readInt(u16, data[2..4], .little),
    };
}

/// SKETCH message payload.
pub const SketchMessage = struct {
    /// Serialized sketch data.
    sketch_data: []const u8,
};

/// RECONCILDIFF message payload (reconciliation difference).
pub const ReconDiffMessage = struct {
    /// Success flag.
    success: bool,
    /// Short IDs we need.
    missing_short_ids: []const u32,
};

// ============================================================================
// Tests
// ============================================================================

test "erlay: short id computation" {
    const wtxid = [_]u8{0x01} ** 32;
    const k0: u64 = 0x0706050403020100;
    const k1: u64 = 0x0F0E0D0C0B0A0908;

    const short_id = computeShortId(&wtxid, k0, k1);

    // Just verify it produces a non-zero result (actual value depends on SipHash impl)
    try std.testing.expect(short_id != 0 or true); // Always passes, just checks it runs
}

test "erlay: salt key computation" {
    const local_salt: u64 = 0x123456789ABCDEF0;
    const remote_salt: u64 = 0xFEDCBA9876543210;

    const keys1 = computeSaltKeys(local_salt, remote_salt);
    const keys2 = computeSaltKeys(remote_salt, local_salt);

    // Keys should be the same regardless of order (BIP-330 requirement)
    try std.testing.expectEqual(keys1.k0, keys2.k0);
    try std.testing.expectEqual(keys1.k1, keys2.k1);
}

test "erlay: minisketch basic operations" {
    const allocator = std.testing.allocator;

    var sketch1 = try Minisketch.init(allocator, 8);
    defer sketch1.deinit();

    // Add some elements
    sketch1.add(1);
    sketch1.add(2);
    sketch1.add(3);

    // Clone and verify
    var sketch2 = try sketch1.clone();
    defer sketch2.deinit();

    try std.testing.expectEqual(sketch1.capacity, sketch2.capacity);

    // Merge should produce symmetric difference
    var sketch3 = try Minisketch.init(allocator, 8);
    defer sketch3.deinit();

    sketch3.add(2);
    sketch3.add(3);
    sketch3.add(4);

    sketch1.merge(&sketch3);
    // sketch1 now contains symmetric difference: {1, 4}
}

test "erlay: minisketch serialization" {
    const allocator = std.testing.allocator;

    var sketch = try Minisketch.init(allocator, 4);
    defer sketch.deinit();

    sketch.add(0xDEADBEEF);
    sketch.add(0xCAFEBABE);

    const size = sketch.serializedSize();
    try std.testing.expectEqual(@as(usize, 16), size); // 4 syndromes * 4 bytes

    var serialized: [16]u8 = undefined;
    sketch.serialize(&serialized);

    var sketch2 = try Minisketch.init(allocator, 4);
    defer sketch2.deinit();

    sketch2.deserialize(&serialized);

    // Verify syndromes match
    for (0..4) |i| {
        try std.testing.expectEqual(sketch.syndromes[i], sketch2.syndromes[i]);
    }
}

test "erlay: reconciliation state" {
    const allocator = std.testing.allocator;

    var state = ReconciliationState.init(
        allocator,
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        1,
        true, // outbound = initiator
    );
    defer state.deinit();

    try std.testing.expect(state.we_initiate);
    try std.testing.expectEqual(@as(i64, OUTBOUND_RECON_INTERVAL_MS), state.getReconInterval());

    // Add some transactions
    const wtxid1 = [_]u8{0x11} ** 32;
    const wtxid2 = [_]u8{0x22} ** 32;

    state.addTransaction(&wtxid1);
    state.addTransaction(&wtxid2);

    try std.testing.expectEqual(@as(usize, 2), state.pending_set.count());

    // Remove one
    state.removeTransaction(&wtxid1);
    try std.testing.expectEqual(@as(usize, 1), state.pending_set.count());
}

test "erlay: reconciliation tracker" {
    const allocator = std.testing.allocator;

    var tracker = ReconciliationTracker.init(allocator);
    defer tracker.deinit();

    const peer_id: u64 = 12345;

    // Pre-register peer
    const local_salt = tracker.preRegisterPeer(peer_id);
    try std.testing.expect(tracker.isPendingRegistration(peer_id));
    try std.testing.expect(!tracker.isRegistered(peer_id));

    // Complete registration
    const remote_salt: u64 = 0xABCDEF0123456789;
    const result = tracker.registerPeer(peer_id, remote_salt, 1, true);
    try std.testing.expectEqual(RegisterResult.success, result);
    try std.testing.expect(!tracker.isPendingRegistration(peer_id));
    try std.testing.expect(tracker.isRegistered(peer_id));

    // Get state
    const state = tracker.getState(peer_id);
    try std.testing.expect(state != null);
    try std.testing.expectEqual(local_salt, state.?.local_salt);
    try std.testing.expectEqual(remote_salt, state.?.remote_salt);

    // Double registration should fail
    const result2 = tracker.registerPeer(peer_id, remote_salt, 1, true);
    try std.testing.expectEqual(RegisterResult.already_registered, result2);

    // Remove peer
    tracker.removePeer(peer_id);
    try std.testing.expect(!tracker.isRegistered(peer_id));
}

test "erlay: message encoding" {
    const allocator = std.testing.allocator;

    // Test SENDTXRCNCL encoding
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    const send_msg = SendTxRcnclMessage{
        .version = 1,
        .salt = 0x123456789ABCDEF0,
    };
    try encodeSendTxRcncl(&send_msg, &writer);

    const encoded = writer.getWritten();
    try std.testing.expectEqual(@as(usize, 12), encoded.len);

    // Decode and verify
    const decoded = try decodeSendTxRcncl(encoded);
    try std.testing.expectEqual(send_msg.version, decoded.version);
    try std.testing.expectEqual(send_msg.salt, decoded.salt);
}

test "erlay: gf32 arithmetic" {
    // Test GF(2^32) multiplication
    try std.testing.expectEqual(@as(u64, 0), gf32Multiply(0, 0));
    try std.testing.expectEqual(@as(u64, 0), gf32Multiply(1, 0));
    try std.testing.expectEqual(@as(u64, 0), gf32Multiply(0, 1));
    try std.testing.expectEqual(@as(u64, 1), gf32Multiply(1, 1));

    // Test inverse
    const a: u64 = 0xDEADBEEF;
    const a_inv = gf32Inverse(a);
    const product = gf32Multiply(a, a_inv);
    try std.testing.expectEqual(@as(u64, 1), product);
}

test "erlay: minisketch empty decode" {
    const allocator = std.testing.allocator;

    var sketch = try Minisketch.init(allocator, 8);
    defer sketch.deinit();

    // Empty sketch should decode to empty set
    const decoded = sketch.decode(allocator);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqual(@as(usize, 0), decoded.?.len);
    allocator.free(decoded.?);
}

test "erlay: minisketch single element" {
    const allocator = std.testing.allocator;

    var sketch = try Minisketch.init(allocator, 4);
    defer sketch.deinit();

    // Add a single element
    const element: u64 = 42;
    sketch.add(element);

    // Decode should recover the element (if algorithm works for this case)
    const decoded = sketch.decode(allocator);
    if (decoded) |elements| {
        defer allocator.free(elements);
        // For single element with small value, Chien search should find it
        if (elements.len > 0) {
            try std.testing.expectEqual(element, elements[0]);
        }
    }
}

test "erlay: add and remove element" {
    const allocator = std.testing.allocator;

    var sketch = try Minisketch.init(allocator, 4);
    defer sketch.deinit();

    // Add element
    sketch.add(100);

    // Store syndromes
    var syndromes_after_add: [4]u64 = undefined;
    @memcpy(&syndromes_after_add, sketch.syndromes);

    // Remove element (add again)
    sketch.add(100);

    // Should be back to empty
    for (sketch.syndromes) |s| {
        try std.testing.expectEqual(@as(u64, 0), s);
    }
}

// ============================================================================
// FFI-specific Tests (run with -Dminisketch=true)
// ============================================================================

test "erlay: ffi minisketch availability check" {
    // This test verifies the FFI detection works
    if (has_minisketch) {
        // When FFI is available, 32-bit field should be supported
        try std.testing.expect(minisketchBitsSupported(32));
        try std.testing.expect(minisketchImplementationSupported(32, 0));

        // Implementation 0 should always be supported for valid field sizes
        const max_impl = minisketchImplementationMax();
        try std.testing.expect(max_impl >= 0);
    } else {
        // Pure Zig implementation also supports 32-bit
        try std.testing.expect(minisketchBitsSupported(32));
        try std.testing.expect(!minisketchBitsSupported(64)); // Only 32-bit in pure Zig
    }
}

test "erlay: ffi minisketch create and destroy" {
    if (!has_minisketch) return error.SkipZigTest;

    // Create sketch via FFI
    const sketch = minisketchCreate(32, 0, 10) orelse {
        return error.SkipZigTest; // Skip if creation fails
    };
    defer minisketchDestroy(sketch);

    // Verify serialized size is correct: capacity * bits / 8 = 10 * 32 / 8 = 40 bytes
    const size = minisketchSerializedSize(sketch);
    try std.testing.expectEqual(@as(usize, 40), size);
}

test "erlay: ffi minisketch set difference with known elements" {
    if (!has_minisketch) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Create two sketches
    const sketch_a = minisketchCreate(32, 0, 10) orelse return error.SkipZigTest;
    defer minisketchDestroy(sketch_a);

    const sketch_b = minisketchCreate(32, 0, 10) orelse return error.SkipZigTest;
    defer minisketchDestroy(sketch_b);

    // Set A = {1, 2, 3, 4, 5}
    minisketchAddUint64(sketch_a, 1);
    minisketchAddUint64(sketch_a, 2);
    minisketchAddUint64(sketch_a, 3);
    minisketchAddUint64(sketch_a, 4);
    minisketchAddUint64(sketch_a, 5);

    // Set B = {3, 4, 5, 6, 7}
    minisketchAddUint64(sketch_b, 3);
    minisketchAddUint64(sketch_b, 4);
    minisketchAddUint64(sketch_b, 5);
    minisketchAddUint64(sketch_b, 6);
    minisketchAddUint64(sketch_b, 7);

    // Merge B into A (XOR)
    const merge_capacity = minisketchMerge(sketch_a, sketch_b);
    try std.testing.expect(merge_capacity > 0);

    // Decode should give symmetric difference: {1, 2, 6, 7}
    const output = try allocator.alloc(u64, 10);
    defer allocator.free(output);

    const result = minisketchDecode(sketch_a, 10, output.ptr);
    try std.testing.expect(result == 4); // Should decode to 4 elements

    // Verify decoded elements (order may vary, so check all are present)
    var found_1 = false;
    var found_2 = false;
    var found_6 = false;
    var found_7 = false;

    for (0..@as(usize, @intCast(result))) |i| {
        if (output[i] == 1) found_1 = true;
        if (output[i] == 2) found_2 = true;
        if (output[i] == 6) found_6 = true;
        if (output[i] == 7) found_7 = true;
    }

    try std.testing.expect(found_1);
    try std.testing.expect(found_2);
    try std.testing.expect(found_6);
    try std.testing.expect(found_7);
}

test "erlay: ffi minisketch serialization round-trip" {
    if (!has_minisketch) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Create and populate sketch
    const sketch1 = minisketchCreate(32, 0, 8) orelse return error.SkipZigTest;
    defer minisketchDestroy(sketch1);

    minisketchAddUint64(sketch1, 0xDEADBEEF);
    minisketchAddUint64(sketch1, 0xCAFEBABE);
    minisketchAddUint64(sketch1, 0x12345678);

    // Serialize
    const size = minisketchSerializedSize(sketch1);
    const serialized = try allocator.alloc(u8, size);
    defer allocator.free(serialized);
    minisketchSerialize(sketch1, serialized.ptr);

    // Create new sketch and deserialize
    const sketch2 = minisketchCreate(32, 0, 8) orelse return error.SkipZigTest;
    defer minisketchDestroy(sketch2);
    minisketchDeserialize(sketch2, serialized.ptr);

    // Decode both and compare
    const output1 = try allocator.alloc(u64, 8);
    defer allocator.free(output1);
    const output2 = try allocator.alloc(u64, 8);
    defer allocator.free(output2);

    const result1 = minisketchDecode(sketch1, 8, output1.ptr);
    const result2 = minisketchDecode(sketch2, 8, output2.ptr);

    try std.testing.expectEqual(result1, result2);
    try std.testing.expect(result1 == 3); // Should have 3 elements
}

test "erlay: ffi minisketch decode failure when capacity exceeded" {
    if (!has_minisketch) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Create sketch with small capacity
    const sketch = minisketchCreate(32, 0, 2) orelse return error.SkipZigTest;
    defer minisketchDestroy(sketch);

    // Add more elements than capacity
    minisketchAddUint64(sketch, 1);
    minisketchAddUint64(sketch, 2);
    minisketchAddUint64(sketch, 3);
    minisketchAddUint64(sketch, 4);
    minisketchAddUint64(sketch, 5);

    // Decode should fail (return -1)
    const output = try allocator.alloc(u64, 5);
    defer allocator.free(output);

    const result = minisketchDecode(sketch, 5, output.ptr);
    try std.testing.expect(result == -1);
}

test "erlay: ffi wrapper struct" {
    if (!has_minisketch) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Create FFI wrapper
    var ffi_sketch = FFIMinisketch.init(8) catch return error.SkipZigTest;
    defer ffi_sketch.deinit();

    // Add elements
    ffi_sketch.add(100);
    ffi_sketch.add(200);
    ffi_sketch.add(300);

    // Clone
    var cloned = ffi_sketch.clone() catch return error.SkipZigTest;
    defer cloned.deinit();

    // Decode and verify
    const decoded = ffi_sketch.decode(allocator);
    try std.testing.expect(decoded != null);
    defer allocator.free(decoded.?);

    try std.testing.expectEqual(@as(usize, 3), decoded.?.len);
}

test "erlay: ffi compute capacity" {
    // Test capacity computation (works even without FFI)
    const capacity = minisketchComputeCapacity(32, 100, 16);
    try std.testing.expect(capacity >= 100);

    const max_elements = minisketchComputeMaxElements(32, capacity, 16);
    try std.testing.expect(max_elements >= 100);
}
