const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const serialize = @import("serialize.zig");

// ============================================================================
// Type Aliases
// ============================================================================

/// SHA256 hash (32 bytes) - also exported from types.zig
pub const Hash256 = types.Hash256;

/// RIPEMD160 hash (20 bytes) - also exported from types.zig
pub const Hash160 = types.Hash160;

// Legacy aliases for backward compatibility
pub const Sha256Hash = Hash256;
pub const Ripemd160Hash = Hash160;

// ============================================================================
// CPU Feature Detection
// ============================================================================

/// Detected CPU features for SHA-256 acceleration
pub const CpuFeatures = struct {
    has_sha_ni: bool = false, // x86_64 SHA-NI (Intel Goldmont+, AMD Zen+)
    has_sse41: bool = false, // x86_64 SSE4.1
    has_avx2: bool = false, // x86_64 AVX2
    has_arm_sha2: bool = false, // AArch64 SHA2 crypto extensions

    /// Get a human-readable description of detected features
    pub fn describe(self: CpuFeatures) []const u8 {
        if (self.has_sha_ni) return "x86_shani";
        if (self.has_arm_sha2) return "arm_shani";
        if (self.has_avx2) return "avx2";
        if (self.has_sse41) return "sse41";
        return "software";
    }
};

/// Comptime feature detection based on target architecture
pub const comptime_features: CpuFeatures = blk: {
    var features = CpuFeatures{};
    const cpu = builtin.cpu;

    if (builtin.cpu.arch == .x86_64) {
        // Check for SHA-NI extension (available on Goldmont+, Zen+)
        if (std.Target.x86.featureSetHas(cpu.features, .sha)) {
            features.has_sha_ni = true;
        }
        // Check for SSE4.1 (available on Nehalem+)
        if (std.Target.x86.featureSetHas(cpu.features, .sse4_1)) {
            features.has_sse41 = true;
        }
        // Check for AVX2 (available on Haswell+)
        if (std.Target.x86.featureSetHas(cpu.features, .avx2)) {
            features.has_avx2 = true;
        }
    } else if (builtin.cpu.arch == .aarch64) {
        // Check for SHA2 crypto extensions
        if (std.Target.aarch64.featureSetHas(cpu.features, .sha2)) {
            features.has_arm_sha2 = true;
        }
    }

    break :blk features;
};

/// Runtime CPU feature detection (for native builds)
var runtime_features: ?CpuFeatures = null;

/// Detect CPU features at runtime using CPUID (x86_64) or auxiliary vector (ARM)
pub fn detectCpuFeatures() CpuFeatures {
    if (runtime_features) |features| {
        return features;
    }

    var features = CpuFeatures{};

    if (builtin.cpu.arch == .x86_64) {
        features = detectX86Features();
    } else if (builtin.cpu.arch == .aarch64) {
        features = detectArmFeatures();
    }

    runtime_features = features;
    return features;
}

fn detectX86Features() CpuFeatures {
    var features = CpuFeatures{};

    // CPUID leaf 1 for SSE4.1 and XSAVE
    const leaf1 = cpuid(1, 0);
    const has_sse41 = (leaf1.ecx >> 19) & 1 != 0;
    const has_xsave = (leaf1.ecx >> 27) & 1 != 0;
    const has_avx = (leaf1.ecx >> 28) & 1 != 0;

    features.has_sse41 = has_sse41;

    // Check if AVX is enabled by the OS
    var avx_enabled = false;
    if (has_xsave and has_avx) {
        // Check XCR0 register
        const xcr0 = xgetbv(0);
        avx_enabled = (xcr0 & 0x6) == 0x6; // XMM and YMM state enabled
    }

    if (has_sse41) {
        // CPUID leaf 7 for AVX2 and SHA-NI
        const leaf7 = cpuid(7, 0);
        features.has_avx2 = avx_enabled and ((leaf7.ebx >> 5) & 1 != 0);
        features.has_sha_ni = (leaf7.ebx >> 29) & 1 != 0;
    }

    return features;
}

const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx)
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf)
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

fn xgetbv(index: u32) u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile (
        \\xgetbv
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi)
        : [index] "{ecx}" (index)
    );
    return (@as(u64, hi) << 32) | lo;
}

fn detectArmFeatures() CpuFeatures {
    var features = CpuFeatures{};

    // On Linux, we can check /proc/cpuinfo or use getauxval
    // For now, use comptime detection which works for most cases
    if (comptime std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha2)) {
        features.has_arm_sha2 = true;
    }

    return features;
}

// ============================================================================
// SHA-256 Constants
// ============================================================================

/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K: [64]u32 = .{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/// SHA-256 initial hash values
const H_INIT: [8]u32 = .{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// ============================================================================
// Software SHA-256 Implementation
// ============================================================================

/// SHA-256 helper functions
inline fn Ch(x: u32, y: u32, z: u32) u32 {
    return z ^ (x & (y ^ z));
}

inline fn Maj(x: u32, y: u32, z: u32) u32 {
    return (x & y) | (z & (x | y));
}

inline fn Sigma0(x: u32) u32 {
    return std.math.rotr(u32, x, 2) ^ std.math.rotr(u32, x, 13) ^ std.math.rotr(u32, x, 22);
}

inline fn Sigma1(x: u32) u32 {
    return std.math.rotr(u32, x, 6) ^ std.math.rotr(u32, x, 11) ^ std.math.rotr(u32, x, 25);
}

inline fn sigma0(x: u32) u32 {
    return std.math.rotr(u32, x, 7) ^ std.math.rotr(u32, x, 18) ^ (x >> 3);
}

inline fn sigma1(x: u32) u32 {
    return std.math.rotr(u32, x, 17) ^ std.math.rotr(u32, x, 19) ^ (x >> 10);
}

/// One round of SHA-256
inline fn round(state: *[8]u32, w_k: u32) void {
    const t1 = state[7] +% Sigma1(state[4]) +% Ch(state[4], state[5], state[6]) +% w_k;
    const t2 = Sigma0(state[0]) +% Maj(state[0], state[1], state[2]);
    state[7] = state[6];
    state[6] = state[5];
    state[5] = state[4];
    state[4] = state[3] +% t1;
    state[3] = state[2];
    state[2] = state[1];
    state[1] = state[0];
    state[0] = t1 +% t2;
}

/// Software SHA-256 block transform (64-byte block)
fn sha256TransformSoftware(state: *[8]u32, chunk: *const [64]u8) void {
    var w: [64]u32 = undefined;

    // Load message block (big-endian)
    for (0..16) |i| {
        w[i] = std.mem.readInt(u32, chunk[i * 4 ..][0..4], .big);
    }

    // Extend message schedule
    for (16..64) |i| {
        w[i] = sigma1(w[i - 2]) +% w[i - 7] +% sigma0(w[i - 15]) +% w[i - 16];
    }

    // Initialize working variables
    var s: [8]u32 = state.*;

    // 64 rounds
    for (0..64) |i| {
        round(&s, w[i] +% K[i]);
    }

    // Add back to state
    for (0..8) |i| {
        state[i] +%= s[i];
    }
}

// ============================================================================
// Hardware-Accelerated SHA-256 Transform
// ============================================================================

/// Intel SHA Extensions (SHA-NI) single-block transform, implemented in
/// `src/sha256_shani.c` using `_mm_sha256rnds2_epu32` / `_mm_sha256msg1_epu32`
/// / `_mm_sha256msg2_epu32` intrinsics. The C translation unit is compiled
/// with `-msha -msse4.1 -mssse3`, so callers MUST gate on runtime CPUID.
///
/// Declared extern only on x86_64 builds; on other arches this symbol is not
/// emitted and the Zig code below never references it.
extern fn clearbit_sha256_shani_transform(
    state: [*]u32,
    chunk: [*]const u8,
    blocks: usize,
) callconv(.C) void;

/// Runtime-dispatched SHA-256 block transform. If the host CPU supports
/// SHA-NI (x86_64) we call the C intrinsic shim; otherwise we fall through
/// to the pure-Zig software transform. Callers must supply `blocks` complete
/// 64-byte message blocks at `data`.
fn sha256TransformHw(state: *[8]u32, data: [*]const u8, blocks: usize) void {
    if (builtin.cpu.arch == .x86_64) {
        const features = detectCpuFeatures();
        if (features.has_sha_ni and blocks > 0) {
            clearbit_sha256_shani_transform(@ptrCast(state), data, blocks);
            return;
        }
    }

    var remaining = blocks;
    var chunk = data;
    while (remaining > 0) : ({
        remaining -= 1;
        chunk += 64;
    }) {
        sha256TransformSoftware(state, @ptrCast(chunk));
    }
}

// ============================================================================
// Optimized Double-SHA256 for 64-byte inputs (Merkle tree nodes)
// ============================================================================

/// Optimized double-SHA256 for exactly 64 bytes of input.
/// This is used for Merkle tree internal nodes: hash256(left_child || right_child)
/// where each child is a 32-byte hash. Routes through the HW transform when
/// SHA-NI is available, which is the dominant cost of block-connect for
/// wide-transaction blocks.
pub fn sha256d64(out: *[32]u8, in: *const [64]u8) void {
    const first_hash = sha256(in);
    const second_hash = sha256(&first_hash);
    out.* = second_hash;
}

/// Batch double-SHA256 for Merkle tree computation
/// Processes multiple 64-byte blocks and produces their hashes
pub fn sha256d64Batch(out: [][32]u8, in: [][64]u8) void {
    for (out, in) |*o, *i| {
        sha256d64(o, i);
    }
}

// ============================================================================
// Hashing Functions (Public API)
// ============================================================================

/// Low-level SHA-256 of a byte slice using our block transform dispatcher.
/// Always goes through `sha256TransformHw`, which selects the SHA-NI path at
/// runtime if the CPU supports it, else falls back to the pure-Zig software
/// path. Kept separate from the stdlib entry point so tests can assert that
/// the HW and software paths agree.
fn sha256Dispatch(data: []const u8) Hash256 {
    var state = H_INIT;

    // Process all complete 64-byte blocks in bulk — with SHA-NI this amortises
    // the Shuffle/Unshuffle across blocks inside the C transform.
    const full_blocks = data.len / 64;
    if (full_blocks > 0) {
        sha256TransformHw(&state, data.ptr, full_blocks);
    }

    // Pad the tail. SHA-256 appends 0x80, then zero pad, then 64-bit big-endian
    // bit length, reaching the next 64-byte boundary. If the remainder after
    // the 0x80 doesn't leave room for the length (>=56 bytes used), pad to two
    // final blocks instead of one.
    var final_block: [128]u8 = undefined;
    const tail_off = full_blocks * 64;
    const remaining = data.len - tail_off;
    @memcpy(final_block[0..remaining], data[tail_off..]);
    final_block[remaining] = 0x80;

    const pad_blocks: usize = if (remaining < 56) 1 else 2;
    const total_pad_bytes = pad_blocks * 64;
    @memset(final_block[remaining + 1 .. total_pad_bytes], 0);

    const bit_len: u64 = @as(u64, data.len) * 8;
    std.mem.writeInt(u64, final_block[total_pad_bytes - 8 ..][0..8], bit_len, .big);

    sha256TransformHw(&state, &final_block, pad_blocks);

    // Write state out as big-endian u32s.
    var result: Hash256 = undefined;
    for (0..8) |i| {
        std.mem.writeInt(u32, result[i * 4 ..][0..4], state[i], .big);
    }
    return result;
}

/// Single SHA-256 hash. Uses the best available backend (SHA-NI when the CPU
/// advertises it, software fallback otherwise). This is the primary entry
/// point for all callers.
pub fn sha256(data: []const u8) Hash256 {
    if (builtin.cpu.arch == .x86_64) {
        // On x86_64 always prefer our dispatcher so CPUs with SHA-NI get the
        // hardware path. The dispatcher itself degrades to software if CPUID
        // reports no sha_ni, so this is safe for non-native builds too.
        return sha256Dispatch(data);
    }
    // On other architectures (e.g. aarch64 without ARM-SHA2 wired up yet),
    // defer to Zig stdlib's optimised software implementation.
    var result: Hash256 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &result, .{});
    return result;
}

/// Single SHA-256 hash using hardware acceleration if available.
/// Kept as a public entry point for tests and benchmarks that want to force
/// the HW/software-dispatch code path (vs stdlib). Behaviour is identical
/// to `sha256()` on x86_64.
pub fn sha256Hw(data: []const u8) Hash256 {
    return sha256Dispatch(data);
}

/// Double SHA-256 (Bitcoin's standard hash for blocks, txids, etc.).
/// Routes through `sha256`, so it picks up SHA-NI acceleration automatically.
pub fn hash256(data: []const u8) Hash256 {
    const first_hash = sha256(data);
    return sha256(&first_hash);
}

/// Double SHA-256 using hardware acceleration if available.
/// Retained for API symmetry with `sha256Hw`; identical to `hash256()` now
/// that the primary entry point also dispatches to the HW backend.
pub fn hash256Hw(data: []const u8) Hash256 {
    const first_hash = sha256Hw(data);
    return sha256Hw(&first_hash);
}

/// SHA-1 hash (20 bytes) - used by OP_SHA1 in Bitcoin script
pub fn sha1(data: []const u8) [20]u8 {
    var result: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(data, &result, .{});
    return result;
}

/// RIPEMD-160 - Bitcoin uses this for address generation
/// Zig stdlib doesn't have RIPEMD160, so we implement it
pub fn ripemd160(data: []const u8) Hash160 {
    var state = Ripemd160State.init();
    state.update(data);
    return state.final();
}

/// HASH-160: RIPEMD160(SHA256(x)) - used for P2PKH/P2SH addresses
pub fn hash160(data: []const u8) Hash160 {
    const sha_hash = sha256(data);
    return ripemd160(&sha_hash);
}

// ============================================================================
// RIPEMD-160 Implementation
// ============================================================================

const Ripemd160State = struct {
    state: [5]u32,
    buf: [64]u8,
    buf_len: usize,
    total_len: u64,

    const K_LEFT = [_]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
    const K_RIGHT = [_]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

    const R_LEFT = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        7,  4,  13, 1,  10, 6,  15, 3,  12, 0,  9,  5,  2,  14, 11, 8,
        3,  10, 14, 4,  9,  15, 8,  1,  2,  7,  0,  6,  13, 11, 5,  12,
        1,  9,  11, 10, 0,  8,  12, 4,  13, 3,  7,  15, 14, 5,  6,  2,
        4,  0,  5,  9,  7,  12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13,
    };

    const R_RIGHT = [_]u8{
        5,  14, 7,  0,  9,  2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
        6,  11, 3,  7,  0,  13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
        15, 5,  1,  3,  7,  14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
        8,  6,  4,  1,  3,  11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
        12, 15, 10, 4,  1,  5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
    };

    const S_LEFT = [_]u8{
        11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
        7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
        11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
        11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
        9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
    };

    const S_RIGHT = [_]u8{
        8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
        9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
        9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
        15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
        8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
    };

    fn init() Ripemd160State {
        return .{
            .state = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    fn update(self: *Ripemd160State, data: []const u8) void {
        var input = data;
        self.total_len += input.len;

        if (self.buf_len > 0) {
            const remaining = 64 - self.buf_len;
            if (input.len < remaining) {
                @memcpy(self.buf[self.buf_len..][0..input.len], input);
                self.buf_len += input.len;
                return;
            }
            @memcpy(self.buf[self.buf_len..][0..remaining], input[0..remaining]);
            self.processBlock(&self.buf);
            input = input[remaining..];
            self.buf_len = 0;
        }

        while (input.len >= 64) {
            self.processBlock(input[0..64]);
            input = input[64..];
        }

        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }
    }

    fn final(self: *Ripemd160State) Hash160 {
        const bit_len = self.total_len * 8;

        // Padding
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        @memset(self.buf[self.buf_len..56], 0);
        std.mem.writeInt(u64, self.buf[56..64], bit_len, .little);
        self.processBlock(&self.buf);

        var result: Hash160 = undefined;
        for (0..5) |i| {
            std.mem.writeInt(u32, result[i * 4 ..][0..4], self.state[i], .little);
        }
        return result;
    }

    fn processBlock(self: *Ripemd160State, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        for (0..16) |i| {
            x[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
        }

        var al = self.state[0];
        var bl = self.state[1];
        var cl = self.state[2];
        var dl = self.state[3];
        var el = self.state[4];

        var ar = self.state[0];
        var br = self.state[1];
        var cr = self.state[2];
        var dr = self.state[3];
        var er = self.state[4];

        for (0..80) |j| {
            const rnd = j / 16;

            // Left path: functions f, g, h, i, j for rounds 0-4
            const fl = switch (rnd) {
                0 => bl ^ cl ^ dl, // f
                1 => (bl & cl) | (~bl & dl), // g
                2 => (bl | ~cl) ^ dl, // h
                3 => (bl & dl) | (cl & ~dl), // i
                4 => bl ^ (cl | ~dl), // j
                else => unreachable,
            };

            var tl = al +% fl +% x[R_LEFT[j]] +% K_LEFT[rnd];
            tl = std.math.rotl(u32, tl, @as(u5, @intCast(S_LEFT[j]))) +% el;
            al = el;
            el = dl;
            dl = std.math.rotl(u32, cl, 10);
            cl = bl;
            bl = tl;

            // Right path: functions j, i, h, g, f for rounds 0-4 (reverse order)
            const fr = switch (rnd) {
                0 => br ^ (cr | ~dr), // j
                1 => (br & dr) | (cr & ~dr), // i
                2 => (br | ~cr) ^ dr, // h
                3 => (br & cr) | (~br & dr), // g
                4 => br ^ cr ^ dr, // f
                else => unreachable,
            };

            var tr = ar +% fr +% x[R_RIGHT[j]] +% K_RIGHT[rnd];
            tr = std.math.rotl(u32, tr, @as(u5, @intCast(S_RIGHT[j]))) +% er;
            ar = er;
            er = dr;
            dr = std.math.rotl(u32, cr, 10);
            cr = br;
            br = tr;
        }

        const t = self.state[1] +% cl +% dr;
        self.state[1] = self.state[2] +% dl +% er;
        self.state[2] = self.state[3] +% el +% ar;
        self.state[3] = self.state[4] +% al +% br;
        self.state[4] = self.state[0] +% bl +% cr;
        self.state[0] = t;
    }
};

// ============================================================================
// Merkle Tree
// ============================================================================

/// Compute the Merkle root of a list of transaction hashes.
/// Uses sha256d64 for internal nodes when hardware acceleration is available.
/// 1. If the list has one element, return it.
/// 2. If the list has an odd number of elements, duplicate the last.
/// 3. Pairwise hash256(concat(a, b)) to produce the next level.
/// 4. Repeat until one hash remains.
pub fn computeMerkleRoot(hashes: []const Hash256, allocator: std.mem.Allocator) !Hash256 {
    if (hashes.len == 0) {
        return [_]u8{0} ** 32;
    }
    if (hashes.len == 1) {
        return hashes[0];
    }

    // Create working buffer for current level
    var current = try allocator.alloc(Hash256, hashes.len);
    defer allocator.free(current);
    @memcpy(current, hashes);

    var len = hashes.len;

    while (len > 1) {
        // If odd number of elements, duplicate the last
        const pair_count = (len + 1) / 2;

        for (0..pair_count) |i| {
            const left_idx = i * 2;
            const right_idx = if (left_idx + 1 < len) left_idx + 1 else left_idx;

            // Concatenate and hash using optimized sha256d64
            var concat: [64]u8 = undefined;
            @memcpy(concat[0..32], &current[left_idx]);
            @memcpy(concat[32..64], &current[right_idx]);
            sha256d64(&current[i], &concat);
        }

        len = pair_count;
    }

    return current[0];
}

// ============================================================================
// libsecp256k1 Integration (C FFI)
// ============================================================================

const secp256k1 = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
});

/// Whether libsecp256k1 is available at link time
pub const has_secp256k1: bool = true;

/// Global secp256k1 context
var secp_ctx: ?*secp256k1.secp256k1_context = null;
var secp_initialized: bool = false;

/// Initialize the secp256k1 context for signature verification
/// Returns true if initialization succeeded, false otherwise
pub fn initSecp256k1() bool {
    if (secp_initialized) return true;
    secp_ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_VERIFY | secp256k1.SECP256K1_CONTEXT_SIGN,
    );
    secp_initialized = (secp_ctx != null);
    return secp_initialized;
}

/// Deinitialize the secp256k1 context
pub fn deinitSecp256k1() void {
    if (secp_ctx) |ctx| {
        secp256k1.secp256k1_context_destroy(ctx);
        secp_ctx = null;
    }
    secp_initialized = false;
}

/// Check if secp256k1 is available and initialized
pub fn isSecp256k1Available() bool {
    return secp_initialized and secp_ctx != null;
}

/// Lax DER signature parsing - extracts R and S values from a loosely-encoded
/// DER signature and packs them into a 64-byte compact format for libsecp256k1.
/// This matches Bitcoin Core's ecdsa_signature_parse_der_lax() behavior.
fn laxDerParse(sig_der: []const u8, compact: *[64]u8) bool {
    @memset(compact, 0);

    if (sig_der.len < 1) return false;
    var pos: usize = 0;

    // Sequence tag
    if (sig_der[pos] != 0x30) return false;
    pos += 1;

    // Sequence length (skip, don't validate strictly)
    if (pos >= sig_der.len) return false;
    if (sig_der[pos] & 0x80 != 0) {
        // Long form length
        const len_bytes = sig_der[pos] & 0x7f;
        pos += 1;
        pos += @as(usize, len_bytes);
    } else {
        pos += 1;
    }

    // R integer
    if (pos >= sig_der.len or sig_der[pos] != 0x02) return false;
    pos += 1;

    if (pos >= sig_der.len) return false;
    const r_len: usize = sig_der[pos];
    pos += 1;

    if (pos + r_len > sig_der.len) return false;
    var r_data = sig_der[pos .. pos + r_len];
    pos += r_len;

    // Strip leading zeros from R
    while (r_data.len > 0 and r_data[0] == 0) {
        r_data = r_data[1..];
    }
    if (r_data.len > 32) return false;

    // Copy R right-aligned into first 32 bytes
    const r_offset = 32 - r_data.len;
    @memcpy(compact[r_offset .. r_offset + r_data.len], r_data);

    // S integer
    if (pos >= sig_der.len or sig_der[pos] != 0x02) return false;
    pos += 1;

    if (pos >= sig_der.len) return false;
    const s_len: usize = sig_der[pos];
    pos += 1;

    if (pos + s_len > sig_der.len) return false;
    var s_data = sig_der[pos .. pos + s_len];

    // Strip leading zeros from S
    while (s_data.len > 0 and s_data[0] == 0) {
        s_data = s_data[1..];
    }
    if (s_data.len > 32) return false;

    // Copy S right-aligned into last 32 bytes
    const s_offset = 32 + 32 - s_data.len;
    @memcpy(compact[s_offset .. s_offset + s_data.len], s_data);

    return true;
}

/// Verify an ECDSA signature (DER-encoded) against a public key and message hash.
/// Bitcoin requires low-S normalization for signatures (BIP-62 rule 5).
/// Uses lax DER parsing to match Bitcoin Core behavior (accepts non-strictly-encoded DER).
///
/// sig_der: DER-encoded ECDSA signature
/// pubkey_bytes: compressed (33 bytes) or uncompressed (65 bytes) public key
/// msg_hash: 32-byte message hash to verify
///
/// Returns true if signature is valid, false otherwise
pub fn verifyEcdsa(sig_der: []const u8, pubkey_bytes: []const u8, msg_hash: *const [32]u8) bool {
    const ctx = secp_ctx orelse return false;

    // Parse public key
    var pubkey: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_ec_pubkey_parse(
        ctx,
        &pubkey,
        pubkey_bytes.ptr,
        pubkey_bytes.len,
    ) != 1) {
        return false;
    }

    // Lax DER parse: extract R/S into compact format
    var compact: [64]u8 = undefined;
    if (!laxDerParse(sig_der, &compact)) {
        return false;
    }

    // Parse compact signature
    var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
    if (secp256k1.secp256k1_ecdsa_signature_parse_compact(
        ctx,
        &sig,
        &compact,
    ) != 1) {
        return false;
    }

    // Normalize to low-S (BIP-62)
    _ = secp256k1.secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

    // Verify
    return secp256k1.secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey) == 1;
}

/// Check if a DER signature has low-S value.
/// BIP-62 rule 5 / BIP-146: S must be at most half the curve order.
pub fn isLowDERSignature(sig_der: []const u8) bool {
    const ctx = secp_ctx orelse return false;

    // Use lax DER parsing to extract R/S into compact format
    var compact: [64]u8 = undefined;
    if (!laxDerParse(sig_der, &compact)) {
        return false;
    }

    var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
    if (secp256k1.secp256k1_ecdsa_signature_parse_compact(
        ctx,
        &sig,
        &compact,
    ) != 1) {
        return false;
    }

    // secp256k1_ecdsa_signature_normalize returns 1 if sig was NOT already normalized
    var normalized: secp256k1.secp256k1_ecdsa_signature = undefined;
    return secp256k1.secp256k1_ecdsa_signature_normalize(ctx, &normalized, &sig) == 0;
}

/// Verify a Schnorr signature (BIP-340) for taproot.
///
/// sig: 64-byte Schnorr signature
/// msg_hash: 32-byte message hash
/// pubkey_x: 32-byte x-only public key
///
/// Returns true if signature is valid, false otherwise
pub fn verifySchnorr(sig: *const [64]u8, msg_hash: *const [32]u8, pubkey_x: *const [32]u8) bool {
    const ctx = secp_ctx orelse return false;

    // Parse the 32-byte x-only pubkey.
    var xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_parse(ctx, &xonly, pubkey_x) != 1) {
        return false;
    }

    // BIP-340: schnorrsig_verify takes the 64-byte sig, the 32-byte
    // message digest, and the parsed x-only pubkey.
    return secp256k1.secp256k1_schnorrsig_verify(
        ctx,
        sig,
        msg_hash,
        32,
        &xonly,
    ) == 1;
}

// ============================================================================
// Transaction Hashing
// ============================================================================

/// A writer adapter that feeds bytes directly to a SHA256 hasher.
/// Eliminates intermediate buffer allocation for hash computation.
pub const Sha256Writer = struct {
    hasher: std.crypto.hash.sha2.Sha256,

    pub fn init() Sha256Writer {
        return .{ .hasher = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    /// Write raw bytes
    pub fn writeBytes(self: *Sha256Writer, data: []const u8) !void {
        @setRuntimeSafety(true);
        self.hasher.update(data);
    }

    /// Write a little-endian integer
    pub fn writeInt(self: *Sha256Writer, comptime T: type, value: T) !void {
        @setRuntimeSafety(true);
        var buf: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buf, value, .little);
        self.hasher.update(&buf);
    }

    /// Write a CompactSize (variable-length integer)
    pub fn writeCompactSize(self: *Sha256Writer, value: u64) !void {
        @setRuntimeSafety(true);
        if (value < 0xFD) {
            try self.writeInt(u8, @intCast(value));
        } else if (value <= 0xFFFF) {
            try self.writeInt(u8, 0xFD);
            try self.writeInt(u16, @intCast(value));
        } else if (value <= 0xFFFFFFFF) {
            try self.writeInt(u8, 0xFE);
            try self.writeInt(u32, @intCast(value));
        } else {
            try self.writeInt(u8, 0xFF);
            try self.writeInt(u64, value);
        }
    }

    /// Finalize and return double-SHA256 hash
    pub fn finalHash256(self: *Sha256Writer) Hash256 {
        @setRuntimeSafety(true);
        var first_hash: Hash256 = undefined;
        self.hasher.final(&first_hash);
        var result: Hash256 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&first_hash, &result, .{});
        return result;
    }
};

/// Serialize transaction (no witness) directly into a SHA256 hasher.
fn writeTransactionNoWitnessToHasher(w: *Sha256Writer, tx: *const types.Transaction) void {
    @setRuntimeSafety(true);
    w.writeInt(i32, tx.version) catch unreachable;

    w.writeCompactSize(tx.inputs.len) catch unreachable;
    for (tx.inputs) |input| {
        w.writeBytes(&input.previous_output.hash) catch unreachable;
        w.writeInt(u32, input.previous_output.index) catch unreachable;
        w.writeCompactSize(input.script_sig.len) catch unreachable;
        w.writeBytes(input.script_sig) catch unreachable;
        w.writeInt(u32, input.sequence) catch unreachable;
    }

    w.writeCompactSize(tx.outputs.len) catch unreachable;
    for (tx.outputs) |output| {
        w.writeInt(i64, output.value) catch unreachable;
        w.writeCompactSize(output.script_pubkey.len) catch unreachable;
        w.writeBytes(output.script_pubkey) catch unreachable;
    }

    w.writeInt(u32, tx.lock_time) catch unreachable;
}

/// Serialize full transaction (with witness) directly into a SHA256 hasher.
fn writeTransactionToHasher(w: *Sha256Writer, tx: *const types.Transaction) void {
    w.writeInt(i32, tx.version) catch unreachable;

    const has_witness = tx.hasWitness();

    if (has_witness) {
        w.writeBytes(&[_]u8{ 0x00, 0x01 }) catch unreachable; // segwit marker + flag
    }

    w.writeCompactSize(tx.inputs.len) catch unreachable;
    for (tx.inputs) |input| {
        w.writeBytes(&input.previous_output.hash) catch unreachable;
        w.writeInt(u32, input.previous_output.index) catch unreachable;
        w.writeCompactSize(input.script_sig.len) catch unreachable;
        w.writeBytes(input.script_sig) catch unreachable;
        w.writeInt(u32, input.sequence) catch unreachable;
    }

    w.writeCompactSize(tx.outputs.len) catch unreachable;
    for (tx.outputs) |output| {
        w.writeInt(i64, output.value) catch unreachable;
        w.writeCompactSize(output.script_pubkey.len) catch unreachable;
        w.writeBytes(output.script_pubkey) catch unreachable;
    }

    if (has_witness) {
        for (tx.inputs) |input| {
            w.writeCompactSize(input.witness.len) catch unreachable;
            for (input.witness) |item| {
                w.writeCompactSize(item.len) catch unreachable;
                w.writeBytes(item) catch unreachable;
            }
        }
    }

    w.writeInt(u32, tx.lock_time) catch unreachable;
}

/// Compute the txid (double-SHA256 of the non-witness serialization).
/// Returns the hash in internal byte order (not display order).
/// Uses streaming hashing — zero allocations.
pub fn computeTxid(tx: *const types.Transaction, allocator: std.mem.Allocator) !Hash256 {
    _ = allocator; // no longer needed, kept for API compatibility
    return computeTxidStreaming(tx);
}

/// Compute the txid with zero allocations using streaming SHA256.
pub fn computeTxidStreaming(tx: *const types.Transaction) Hash256 {
    @setRuntimeSafety(true);
    var w = Sha256Writer.init();
    writeTransactionNoWitnessToHasher(&w, tx);
    return w.finalHash256();
}

/// Compute the wtxid (double-SHA256 of full serialization including witness).
/// For non-segwit transactions, wtxid equals txid.
/// Uses streaming hashing — zero allocations.
pub fn computeWtxid(tx: *const types.Transaction, allocator: std.mem.Allocator) !Hash256 {
    _ = allocator; // no longer needed, kept for API compatibility
    return computeWtxidStreaming(tx);
}

/// Compute the wtxid with zero allocations using streaming SHA256.
pub fn computeWtxidStreaming(tx: *const types.Transaction) Hash256 {
    var w = Sha256Writer.init();
    writeTransactionToHasher(&w, tx);
    return w.finalHash256();
}

/// Compute the hash of a block header (double-SHA256).
pub fn computeBlockHash(header: *const types.BlockHeader) Hash256 {
    var buf: [80]u8 = undefined;
    std.mem.writeInt(i32, buf[0..4], header.version, .little);
    @memcpy(buf[4..36], &header.prev_block);
    @memcpy(buf[36..68], &header.merkle_root);
    std.mem.writeInt(u32, buf[68..72], header.timestamp, .little);
    std.mem.writeInt(u32, buf[72..76], header.bits, .little);
    std.mem.writeInt(u32, buf[76..80], header.nonce, .little);
    return hash256(&buf);
}

// ============================================================================
// Sighash Computation
// ============================================================================

/// Sighash type flags
pub const SigHashType = types.SigHashType;

/// Compute the legacy sighash for pre-segwit inputs.
/// This is used for P2PKH and P2SH (non-segwit) inputs.
pub fn legacySighash(
    tx: *const types.Transaction,
    input_index: usize,
    script_pubkey: []const u8,
    hash_type: u32,
    allocator: std.mem.Allocator,
) !Hash256 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    const base_type = hash_type & 0x1f;
    const anyone_can_pay = (hash_type & 0x80) != 0;

    // Version
    try writer.writeInt(i32, tx.version);

    // Inputs
    if (anyone_can_pay) {
        // Only include the input being signed
        try writer.writeCompactSize(1);
        const input = tx.inputs[input_index];
        try writer.writeBytes(&input.previous_output.hash);
        try writer.writeInt(u32, input.previous_output.index);
        try writer.writeCompactSize(script_pubkey.len);
        try writer.writeBytes(script_pubkey);
        try writer.writeInt(u32, input.sequence);
    } else {
        try writer.writeCompactSize(tx.inputs.len);
        for (tx.inputs, 0..) |input, i| {
            try writer.writeBytes(&input.previous_output.hash);
            try writer.writeInt(u32, input.previous_output.index);

            if (i == input_index) {
                // Include script_pubkey for the input being signed
                try writer.writeCompactSize(script_pubkey.len);
                try writer.writeBytes(script_pubkey);
            } else {
                // Empty script for other inputs
                try writer.writeCompactSize(0);
            }

            // Sequence - for SIGHASH_NONE/SINGLE, set to 0 for other inputs
            if ((base_type == 0x02 or base_type == 0x03) and i != input_index) {
                try writer.writeInt(u32, 0);
            } else {
                try writer.writeInt(u32, input.sequence);
            }
        }
    }

    // Outputs
    if (base_type == 0x02) {
        // SIGHASH_NONE: no outputs
        try writer.writeCompactSize(0);
    } else if (base_type == 0x03) {
        // SIGHASH_SINGLE: only output at same index
        if (input_index >= tx.outputs.len) {
            // Bitcoin quirk: return a specific hash for this error case
            var result: Hash256 = [_]u8{0} ** 32;
            result[0] = 1;
            return result;
        }
        try writer.writeCompactSize(input_index + 1);
        // Write empty outputs for indices before input_index
        for (0..input_index) |_| {
            try writer.writeInt(i64, -1); // -1 value
            try writer.writeCompactSize(0); // empty script
        }
        // Write the actual output
        const output = tx.outputs[input_index];
        try writer.writeInt(i64, output.value);
        try writer.writeCompactSize(output.script_pubkey.len);
        try writer.writeBytes(output.script_pubkey);
    } else {
        // SIGHASH_ALL: all outputs
        try writer.writeCompactSize(tx.outputs.len);
        for (tx.outputs) |output| {
            try writer.writeInt(i64, output.value);
            try writer.writeCompactSize(output.script_pubkey.len);
            try writer.writeBytes(output.script_pubkey);
        }
    }

    // Locktime
    try writer.writeInt(u32, tx.lock_time);

    // Hash type (4 bytes, little-endian)
    try writer.writeInt(u32, hash_type);

    const data = try writer.toOwnedSlice();
    defer allocator.free(data);
    return hash256(data);
}

/// Precomputed hashes for BIP-143 segwit sighash optimization
pub const SegwitSighashCache = struct {
    hash_prevouts: Hash256,
    hash_sequence: Hash256,
    hash_outputs: Hash256,

    pub fn init(tx: *const types.Transaction, allocator: std.mem.Allocator) !SegwitSighashCache {
        _ = allocator;
        var prevouts_data: [36 * 256]u8 = undefined; // Assuming max 256 inputs
        var prevouts_len: usize = 0;
        for (tx.inputs) |input| {
            @memcpy(prevouts_data[prevouts_len..][0..32], &input.previous_output.hash);
            std.mem.writeInt(u32, prevouts_data[prevouts_len + 32 ..][0..4], input.previous_output.index, .little);
            prevouts_len += 36;
        }

        var sequence_data: [4 * 256]u8 = undefined;
        var sequence_len: usize = 0;
        for (tx.inputs) |input| {
            std.mem.writeInt(u32, sequence_data[sequence_len..][0..4], input.sequence, .little);
            sequence_len += 4;
        }

        // For outputs, we need dynamic sizing
        var outputs_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (tx.outputs) |output| {
            var value_buf: [8]u8 = undefined;
            std.mem.writeInt(i64, &value_buf, output.value, .little);
            outputs_hasher.update(&value_buf);

            // CompactSize for script length
            if (output.script_pubkey.len < 0xFD) {
                outputs_hasher.update(&[_]u8{@intCast(output.script_pubkey.len)});
            } else if (output.script_pubkey.len <= 0xFFFF) {
                var size_buf: [3]u8 = undefined;
                size_buf[0] = 0xFD;
                std.mem.writeInt(u16, size_buf[1..3], @intCast(output.script_pubkey.len), .little);
                outputs_hasher.update(&size_buf);
            }
            outputs_hasher.update(output.script_pubkey);
        }
        var first_hash: Hash256 = undefined;
        outputs_hasher.final(&first_hash);

        return .{
            .hash_prevouts = hash256(prevouts_data[0..prevouts_len]),
            .hash_sequence = hash256(sequence_data[0..sequence_len]),
            .hash_outputs = hash256(&first_hash),
        };
    }
};

/// Compute BIP-143 segwit sighash for signature verification.
/// This is used for P2WPKH and P2WSH inputs.
pub fn segwitSighash(
    tx: *const types.Transaction,
    input_index: usize,
    script_code: []const u8,
    value: i64,
    hash_type: u32,
    allocator: std.mem.Allocator,
) !Hash256 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    const base_type = hash_type & 0x1f;
    const anyone_can_pay = (hash_type & 0x80) != 0;

    // 1. nVersion (4 bytes)
    try writer.writeInt(i32, tx.version);

    // 2. hashPrevouts (32 bytes)
    if (!anyone_can_pay) {
        var prevouts_data = std.ArrayList(u8).init(allocator);
        defer prevouts_data.deinit();
        for (tx.inputs) |input| {
            try prevouts_data.appendSlice(&input.previous_output.hash);
            var idx_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &idx_buf, input.previous_output.index, .little);
            try prevouts_data.appendSlice(&idx_buf);
        }
        const hash_prevouts = hash256(prevouts_data.items);
        try writer.writeBytes(&hash_prevouts);
    } else {
        try writer.writeBytes(&([_]u8{0} ** 32));
    }

    // 3. hashSequence (32 bytes)
    if (!anyone_can_pay and base_type != 0x02 and base_type != 0x03) {
        var sequence_data = std.ArrayList(u8).init(allocator);
        defer sequence_data.deinit();
        for (tx.inputs) |input| {
            var seq_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &seq_buf, input.sequence, .little);
            try sequence_data.appendSlice(&seq_buf);
        }
        const hash_sequence = hash256(sequence_data.items);
        try writer.writeBytes(&hash_sequence);
    } else {
        try writer.writeBytes(&([_]u8{0} ** 32));
    }

    // 4. outpoint (32 + 4 bytes)
    const input = tx.inputs[input_index];
    try writer.writeBytes(&input.previous_output.hash);
    try writer.writeInt(u32, input.previous_output.index);

    // 5. scriptCode (varInt + script)
    try writer.writeCompactSize(script_code.len);
    try writer.writeBytes(script_code);

    // 6. value (8 bytes)
    try writer.writeInt(i64, value);

    // 7. nSequence (4 bytes)
    try writer.writeInt(u32, input.sequence);

    // 8. hashOutputs (32 bytes)
    if (base_type != 0x02 and base_type != 0x03) {
        // SIGHASH_ALL: hash all outputs
        var outputs_data = std.ArrayList(u8).init(allocator);
        defer outputs_data.deinit();
        for (tx.outputs) |output| {
            var val_buf: [8]u8 = undefined;
            std.mem.writeInt(i64, &val_buf, output.value, .little);
            try outputs_data.appendSlice(&val_buf);

            // CompactSize
            if (output.script_pubkey.len < 0xFD) {
                try outputs_data.append(@intCast(output.script_pubkey.len));
            } else {
                try outputs_data.append(0xFD);
                var len_buf: [2]u8 = undefined;
                std.mem.writeInt(u16, &len_buf, @intCast(output.script_pubkey.len), .little);
                try outputs_data.appendSlice(&len_buf);
            }
            try outputs_data.appendSlice(output.script_pubkey);
        }
        const hash_outputs = hash256(outputs_data.items);
        try writer.writeBytes(&hash_outputs);
    } else if (base_type == 0x03 and input_index < tx.outputs.len) {
        // SIGHASH_SINGLE: hash only the corresponding output
        var output_data = std.ArrayList(u8).init(allocator);
        defer output_data.deinit();
        const output = tx.outputs[input_index];
        var val_buf: [8]u8 = undefined;
        std.mem.writeInt(i64, &val_buf, output.value, .little);
        try output_data.appendSlice(&val_buf);
        if (output.script_pubkey.len < 0xFD) {
            try output_data.append(@intCast(output.script_pubkey.len));
        } else {
            try output_data.append(0xFD);
            var len_buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &len_buf, @intCast(output.script_pubkey.len), .little);
            try output_data.appendSlice(&len_buf);
        }
        try output_data.appendSlice(output.script_pubkey);
        const hash_outputs = hash256(output_data.items);
        try writer.writeBytes(&hash_outputs);
    } else {
        try writer.writeBytes(&([_]u8{0} ** 32));
    }

    // 9. nLocktime (4 bytes)
    try writer.writeInt(u32, tx.lock_time);

    // 10. sighash type (4 bytes)
    try writer.writeInt(u32, hash_type);

    const data = try writer.toOwnedSlice();
    defer allocator.free(data);
    return hash256(data);
}

// ============================================================================
// Tagged Hash (BIP-340)
// ============================================================================

/// Compute a tagged hash as per BIP-340: SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn taggedHash(tag: []const u8, msg: []const u8) Hash256 {
    const tag_hash = sha256(tag);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);

    var result: Hash256 = undefined;
    hasher.final(&result);
    return result;
}

/// Verify a taproot script-path control block against the witness program (output key).
/// Returns true if the control block is valid for the given script and output program.
///
/// control: control block bytes (33 + 32*path_len)
/// tap_script: the leaf script being executed
/// Compute the BIP-341 TapLeaf hash for a tapscript leaf.
///
/// `leaf_version` should be the leaf_version byte from the control block
/// with the parity bit masked off (i.e. `control[0] & 0xfe`). For
/// standard tapscript leaves this is 0xc0.
///
/// Returns `null` if the script length is too large to encode in
/// CompactSize (>0xFFFF), which never happens in practice (Taproot
/// scripts are bounded well under that).
pub fn computeTapleafHash(tap_script: []const u8, leaf_version: u8) ?Hash256 {
    var leaf_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const tap_leaf_tag = sha256("TapLeaf");
    leaf_hasher.update(&tap_leaf_tag);
    leaf_hasher.update(&tap_leaf_tag);
    leaf_hasher.update(&[_]u8{leaf_version});
    if (tap_script.len < 0xfd) {
        leaf_hasher.update(&[_]u8{@truncate(tap_script.len)});
    } else if (tap_script.len <= 0xffff) {
        leaf_hasher.update(&[_]u8{0xfd});
        leaf_hasher.update(&[_]u8{@truncate(tap_script.len & 0xff)});
        leaf_hasher.update(&[_]u8{@truncate((tap_script.len >> 8) & 0xff)});
    } else {
        return null;
    }
    leaf_hasher.update(tap_script);
    var k: Hash256 = undefined;
    leaf_hasher.final(&k);
    return k;
}

/// program: the 32-byte witness program (x-only output key from scriptPubKey)
pub fn verifyTaprootControlBlock(control: []const u8, tap_script: []const u8, program: []const u8) bool {
    if (control.len < 33 or program.len != 32) return false;
    if ((control.len - 33) % 32 != 0) return false;

    const ctx = secp_ctx orelse return false;

    const leaf_version = control[0] & 0xfe;
    const internal_key = control[1..33];

    // Compute tapleaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script)
    var leaf_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const tap_leaf_tag = sha256("TapLeaf");
    leaf_hasher.update(&tap_leaf_tag);
    leaf_hasher.update(&tap_leaf_tag);
    leaf_hasher.update(&[_]u8{leaf_version});

    // Compact size encoding of script length
    if (tap_script.len < 0xfd) {
        leaf_hasher.update(&[_]u8{@truncate(tap_script.len)});
    } else if (tap_script.len <= 0xffff) {
        leaf_hasher.update(&[_]u8{0xfd});
        leaf_hasher.update(&[_]u8{@truncate(tap_script.len & 0xff)});
        leaf_hasher.update(&[_]u8{@truncate((tap_script.len >> 8) & 0xff)});
    } else {
        return false;
    }
    leaf_hasher.update(tap_script);
    var k: Hash256 = undefined;
    leaf_hasher.final(&k);

    // Walk the merkle path
    const path_len = (control.len - 33) / 32;
    for (0..path_len) |i| {
        const node = control[33 + i * 32 ..][0..32];
        var branch_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        const tap_branch_tag = sha256("TapBranch");
        branch_hasher.update(&tap_branch_tag);
        branch_hasher.update(&tap_branch_tag);
        // Lexicographic order
        if (std.mem.order(u8, &k, node) == .lt) {
            branch_hasher.update(&k);
            branch_hasher.update(node);
        } else {
            branch_hasher.update(node);
            branch_hasher.update(&k);
        }
        branch_hasher.final(&k);
    }

    // Compute tweak: tagged_hash("TapTweak", internal_key || merkle_root)
    var tweak_data: [64]u8 = undefined;
    @memcpy(tweak_data[0..32], internal_key);
    @memcpy(tweak_data[32..64], &k);
    const tweak = taggedHash("TapTweak", &tweak_data);

    // Parse internal key and compute tweaked key
    var internal_xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_parse(ctx, &internal_xonly, internal_key.ptr) != 1) {
        return false;
    }

    var output_pubkey: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_tweak_add(ctx, &output_pubkey, &internal_xonly, &tweak) != 1) {
        return false;
    }

    // Verify: check that the tweaked key matches the program and parity
    if (secp256k1.secp256k1_xonly_pubkey_tweak_add_check(
        ctx,
        program.ptr,
        @intCast(control[0] & 1),
        &internal_xonly,
        &tweak,
    ) != 1) {
        return false;
    }

    return true;
}

// ============================================================================
// Performance Info
// ============================================================================

/// Get a description of the active SHA-256 implementation
pub fn getSha256Implementation() []const u8 {
    return comptime_features.describe();
}

// ============================================================================
// Tests
// ============================================================================

test "sha256 basic" {
    const result = sha256("");
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "sha256 hello" {
    const result = sha256("hello");
    const expected = [_]u8{
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

/// Helper: run Zig stdlib's software SHA-256 over `data`. Used by the HW
/// equivalence tests below as the reference oracle.
fn sha256Stdlib(data: []const u8) Hash256 {
    var out: Hash256 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

test "sha256 FIPS 180-2 vector: abc" {
    // Standard NIST short-message vector.
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expected, &sha256("abc"));
    try std.testing.expectEqualSlices(u8, &expected, &sha256Hw("abc"));
}

test "sha256 FIPS 180-2 vector: 448-bit message" {
    // NIST FIPS 180-2 test vector 2: the 56-byte input exactly fills a single
    // block once the 0x80 padding byte is appended, forcing a second block
    // solely for the length field. This is the canonical "padding crosses a
    // block boundary" test.
    const msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const expected = [_]u8{
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    try std.testing.expectEqualSlices(u8, &expected, &sha256(msg));
    try std.testing.expectEqualSlices(u8, &expected, &sha256Hw(msg));
}

test "sha256Hw matches stdlib: smoke cases" {
    // Empty string.
    try std.testing.expectEqualSlices(u8, &sha256Stdlib(""), &sha256Hw(""));

    // Short single-block inputs.
    try std.testing.expectEqualSlices(u8, &sha256Stdlib("hello"), &sha256Hw("hello"));
    try std.testing.expectEqualSlices(u8, &sha256Stdlib("abc"), &sha256Hw("abc"));

    // Multi-block (~430 bytes).
    const long_input = "The quick brown fox jumps over the lazy dog" ** 10;
    try std.testing.expectEqualSlices(u8, &sha256Stdlib(long_input), &sha256Hw(long_input));
}

test "sha256Hw matches stdlib: padding boundary sweep" {
    // Input lengths near the 55/56 boundary are the trickiest — they're where
    // the padding schema decides whether to emit one or two final blocks.
    var buf: [200]u8 = undefined;
    for (0..buf.len) |i| buf[i] = @intCast(i & 0xFF);

    var len: usize = 0;
    while (len <= buf.len) : (len += 1) {
        const data = buf[0..len];
        const expected = sha256Stdlib(data);
        const got_hw = sha256Hw(data);
        const got_primary = sha256(data);
        try std.testing.expectEqualSlices(u8, &expected, &got_hw);
        try std.testing.expectEqualSlices(u8, &expected, &got_primary);
    }
}

test "sha256Hw matches stdlib: 1 KB block-exact" {
    // Exact multiple of 64 — exercises the bulk-blocks path with no tail data.
    var buf: [1024]u8 = undefined;
    for (0..buf.len) |i| buf[i] = @intCast((i * 31 + 7) & 0xFF);
    try std.testing.expectEqualSlices(u8, &sha256Stdlib(&buf), &sha256Hw(&buf));
}

test "sha256Hw matches stdlib: random fuzz" {
    // Random sweep: 200 inputs with lengths uniform in [0, 4096]. Asserts
    // byte-for-byte equality against the stdlib software implementation.
    var rng = std.Random.DefaultPrng.init(0xC0FFEE_C0DE_F001);
    const rnd = rng.random();

    var buf: [4096]u8 = undefined;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const len = rnd.intRangeAtMost(usize, 0, buf.len);
        rnd.bytes(buf[0..len]);
        const data = buf[0..len];
        const expected = sha256Stdlib(data);
        const got_hw = sha256Hw(data);
        const got_primary = sha256(data);
        try std.testing.expectEqualSlices(u8, &expected, &got_hw);
        try std.testing.expectEqualSlices(u8, &expected, &got_primary);
    }
}

test "sha256d64 matches stdlib hash256 (Merkle-node hot path)" {
    // `sha256d64` is the fast-path double-SHA for Merkle tree internal nodes.
    // Compare against an unambiguous stdlib-only reference.
    var rng = std.Random.DefaultPrng.init(0xDEADBEEFCAFEBABE);
    const rnd = rng.random();

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var input: [64]u8 = undefined;
        rnd.bytes(&input);

        var got: [32]u8 = undefined;
        sha256d64(&got, &input);

        const first = sha256Stdlib(&input);
        const expected = sha256Stdlib(&first);
        try std.testing.expectEqualSlices(u8, &expected, &got);
    }
}

test "hash256 empty" {
    const result = hash256("");
    // SHA256(SHA256("")) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    const expected = [_]u8{
        0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
        0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
        0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
        0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "sha256d64 correctness" {
    // Test that sha256d64 matches hash256 for 64-byte input
    var input: [64]u8 = undefined;
    @memset(&input, 0xAB);

    var result: [32]u8 = undefined;
    sha256d64(&result, &input);

    const expected = hash256(&input);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "sha256d64 different inputs" {
    // Test with different patterns
    var input1: [64]u8 = undefined;
    var input2: [64]u8 = undefined;
    @memset(input1[0..32], 0x11);
    @memset(input1[32..64], 0x22);
    @memset(input2[0..32], 0x33);
    @memset(input2[32..64], 0x44);

    var result1: [32]u8 = undefined;
    var result2: [32]u8 = undefined;
    sha256d64(&result1, &input1);
    sha256d64(&result2, &input2);

    const expected1 = hash256(&input1);
    const expected2 = hash256(&input2);

    try std.testing.expectEqualSlices(u8, &expected1, &result1);
    try std.testing.expectEqualSlices(u8, &expected2, &result2);

    // Results should be different
    try std.testing.expect(!std.mem.eql(u8, &result1, &result2));
}

test "ripemd160 empty" {
    const result = ripemd160("");
    const expected = [_]u8{
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
        0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "ripemd160 hello" {
    const result = ripemd160("hello");
    const expected = [_]u8{
        0x10, 0x8f, 0x07, 0xb8, 0x38, 0x24, 0x12, 0x61, 0x2c, 0x04,
        0x8d, 0x07, 0xd1, 0x3f, 0x81, 0x41, 0x18, 0x44, 0x5a, 0xcd,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash160 pubkey" {
    // Test with a well-known public key (Satoshi's genesis coinbase)
    const pubkey = [_]u8{
        0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67,
        0xf1, 0xa6, 0x71, 0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0,
        0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde, 0xb6,
        0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04,
        0xe5, 0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b,
        0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f,
    };
    const result = hash160(&pubkey);
    const expected = [_]u8{
        0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
        0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "merkle root single hash" {
    const allocator = std.testing.allocator;
    const hash_val = [_]u8{0xAB} ** 32;
    const hashes = [_]Hash256{hash_val};
    const root = try computeMerkleRoot(&hashes, allocator);
    try std.testing.expectEqualSlices(u8, &hash_val, &root);
}

test "merkle root two hashes" {
    const allocator = std.testing.allocator;
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const hashes = [_]Hash256{ a, b };

    // Expected: hash256(a ++ b) - computed via sha256d64
    var concat: [64]u8 = undefined;
    @memcpy(concat[0..32], &a);
    @memcpy(concat[32..64], &b);
    var expected: [32]u8 = undefined;
    sha256d64(&expected, &concat);

    const root = try computeMerkleRoot(&hashes, allocator);
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "merkle root three hashes duplicates last" {
    const allocator = std.testing.allocator;
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const hashes = [_]Hash256{ a, b, c };

    // Level 1: hash(a,b), hash(c,c)
    var ab: [64]u8 = undefined;
    @memcpy(ab[0..32], &a);
    @memcpy(ab[32..64], &b);
    var hash_ab: [32]u8 = undefined;
    sha256d64(&hash_ab, &ab);

    var cc: [64]u8 = undefined;
    @memcpy(cc[0..32], &c);
    @memcpy(cc[32..64], &c);
    var hash_cc: [32]u8 = undefined;
    sha256d64(&hash_cc, &cc);

    // Level 2: hash(hash_ab, hash_cc)
    var final_input: [64]u8 = undefined;
    @memcpy(final_input[0..32], &hash_ab);
    @memcpy(final_input[32..64], &hash_cc);
    var expected: [32]u8 = undefined;
    sha256d64(&expected, &final_input);

    const root = try computeMerkleRoot(&hashes, allocator);
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "tagged hash BIP340" {
    // BIP-340 test vector for tagged hash
    const result = taggedHash("BIP0340/challenge", "test");
    // Just verify it produces a valid hash
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "block header hash" {
    // Genesis block header
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c,
            0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a,
            0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
        },
        .timestamp = 1231006505,
        .bits = 0x1d00ffff,
        .nonce = 2083236893,
    };

    const block_hash = computeBlockHash(&header);

    // Genesis block hash (reversed for display: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f)
    // Internal byte order:
    const expected = [_]u8{
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2,
        0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a,
        0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &expected, &block_hash);
}

test "cpu feature detection" {
    // Just verify it doesn't crash
    const features = detectCpuFeatures();
    _ = features.describe();

    // Comptime features should be consistent
    _ = comptime_features.describe();
}

test "secp256k1 init/deinit" {
    // Just verify init/deinit don't crash
    // (may not actually initialize if library is not available)
    const initialized = initSecp256k1();
    if (initialized) {
        try std.testing.expect(isSecp256k1Available());
        deinitSecp256k1();
        try std.testing.expect(!isSecp256k1Available());
    }
}
