// MuHash3072 — multiplicative set hash for the Bitcoin UTXO set.
//
// Reference: bitcoin-core/src/crypto/muhash.{h,cpp} (Pieter Wuille, 2017).
// Per-coin serialization: bitcoin-core/src/kernel/coinstats.cpp `TxOutSer`.
//
// The hash represents a multiset over a 3072-bit cyclic group whose modulus
// is the safe prime `p = 2^3072 - 1103717`. Each element is mapped into the
// group via SHA256 of the canonical TxOutSer bytes, expanded to 384 bytes by
// a single ChaCha20 keystream draw, and that 384-byte little-endian integer
// is multiplied into a numerator (`Insert`) or denominator (`Remove`)
// accumulator. `Finalize` computes `numerator * inverse(denominator) mod p`,
// serializes the result LE, and returns SHA256 of those bytes.
//
// This module is the Zig analogue of `Num3072` and `MuHash3072`. The 3072-bit
// modular arithmetic is implemented by hand with 48 little-endian u64 limbs
// (Zig has no built-in big-int). On x86_64 / aarch64 we use `u128` for the
// double-limb intermediate type, mirroring the `__SIZEOF_INT128__` branch
// of Core's header.
//
// Inversion: Core uses safegcd (libsecp256k1-style divsteps). For correctness
// and code simplicity here we instead use Fermat's little theorem
// (`a^(p-2) mod p`) — `Finalize` is rare (once per `dumptxoutset` /
// `gettxoutsetinfo`, never on a hot path), so the ~3072 squarings + ~3072
// multiplies are not load-bearing.

const std = @import("std");
const crypto = @import("crypto.zig");
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;

// =========================================================================
// Num3072 — 3072-bit unsigned integer mod (2^3072 - MAX_PRIME_DIFF).
// Storage layout matches Core: 48 little-endian u64 limbs covering 384 bytes.
// =========================================================================

/// Difference between 2^3072 and the modulus. Core: `MAX_PRIME_DIFF = 1103717`
/// (`bitcoin-core/src/crypto/muhash.cpp:33`).
const MAX_PRIME_DIFF: u64 = 1103717;

pub const Num3072 = struct {
    pub const BYTE_SIZE: usize = 384;
    pub const LIMBS: usize = 48;

    limbs: [LIMBS]u64,

    /// Multiplicative identity (the value 1).
    pub fn one() Num3072 {
        var n: Num3072 = undefined;
        n.setToOne();
        return n;
    }

    pub fn setToOne(self: *Num3072) void {
        self.limbs[0] = 1;
        var i: usize = 1;
        while (i < LIMBS) : (i += 1) self.limbs[i] = 0;
    }

    /// Construct from 384 little-endian bytes (raw 3072-bit value, may exceed
    /// the modulus — `Multiply` reduces lazily).
    pub fn fromBytes(data: *const [BYTE_SIZE]u8) Num3072 {
        var n: Num3072 = undefined;
        var i: usize = 0;
        while (i < LIMBS) : (i += 1) {
            n.limbs[i] = std.mem.readInt(u64, data[i * 8 ..][0..8], .little);
        }
        return n;
    }

    /// Serialize to 384 little-endian bytes.
    pub fn toBytes(self: *const Num3072, out: *[BYTE_SIZE]u8) void {
        var i: usize = 0;
        while (i < LIMBS) : (i += 1) {
            std.mem.writeInt(u64, out[i * 8 ..][0..8], self.limbs[i], .little);
        }
    }

    /// Returns true when the represented value is `≥ p` (i.e. lies in the
    /// rare overflow range `[p, 2^3072)`). Core: `Num3072::IsOverflow`.
    fn isOverflow(self: *const Num3072) bool {
        if (self.limbs[0] <= std.math.maxInt(u64) - MAX_PRIME_DIFF) return false;
        var i: usize = 1;
        while (i < LIMBS) : (i += 1) {
            if (self.limbs[i] != std.math.maxInt(u64)) return false;
        }
        return true;
    }

    /// Reduce *this once by adding `MAX_PRIME_DIFF` (i.e. subtracting `p`)
    /// and propagating the carry. Core: `Num3072::FullReduce`.
    fn fullReduce(self: *Num3072) void {
        var c0: u64 = MAX_PRIME_DIFF;
        var c1: u64 = 0;
        var i: usize = 0;
        while (i < LIMBS) : (i += 1) {
            addnextract2(&c0, &c1, self.limbs[i], &self.limbs[i]);
        }
    }

    /// `*this = *this * a (mod p)`. Direct port of Core's
    /// `Num3072::Multiply` from `bitcoin-core/src/crypto/muhash.cpp:456`.
    pub fn multiply(self: *Num3072, a: *const Num3072) void {
        var c0: u64 = 0;
        var c1: u64 = 0;
        var c2: u64 = 0;
        var tmp: Num3072 = undefined;

        // Compute limbs 0..N-2 of `self * a` into `tmp`, including one
        // reduction (multiply the high half by MAX_PRIME_DIFF and fold in).
        var j: usize = 0;
        while (j < LIMBS - 1) : (j += 1) {
            var d0: u64 = 0;
            var d1: u64 = 0;
            var d2: u64 = 0;
            mul(&d0, &d1, self.limbs[1 + j], a.limbs[LIMBS + j - (1 + j)]);
            var i: usize = 2 + j;
            while (i < LIMBS) : (i += 1) muladd3(&d0, &d1, &d2, self.limbs[i], a.limbs[LIMBS + j - i]);
            mulnadd3(&c0, &c1, &c2, &d0, &d1, &d2, MAX_PRIME_DIFF);
            i = 0;
            while (i < j + 1) : (i += 1) muladd3(&c0, &c1, &c2, self.limbs[i], a.limbs[j - i]);
            extract3(&c0, &c1, &c2, &tmp.limbs[j]);
        }

        // Compute limb N-1 of self*a into tmp.
        std.debug.assert(c2 == 0);
        var i: usize = 0;
        while (i < LIMBS) : (i += 1) muladd3(&c0, &c1, &c2, self.limbs[i], a.limbs[LIMBS - 1 - i]);
        extract3(&c0, &c1, &c2, &tmp.limbs[LIMBS - 1]);

        // Second reduction: c0/c1 still hold the residual high bits, so
        // multiply them by MAX_PRIME_DIFF and add limb-by-limb back into self.
        muln2(&c0, &c1, MAX_PRIME_DIFF);
        j = 0;
        while (j < LIMBS) : (j += 1) {
            addnextract2(&c0, &c1, tmp.limbs[j], &self.limbs[j]);
        }

        std.debug.assert(c1 == 0);
        std.debug.assert(c0 == 0 or c0 == 1);

        // Up to two more reductions if either internal state overflows.
        if (self.isOverflow()) self.fullReduce();
        if (c0 != 0) self.fullReduce();
    }

    /// `*this = *this / a (mod p)`. Computes inverse(a) and multiplies.
    pub fn divide(self: *Num3072, a: *const Num3072) void {
        if (self.isOverflow()) self.fullReduce();

        var inv: Num3072 = undefined;
        if (a.isOverflow()) {
            var b = a.*;
            b.fullReduce();
            inv = b.getInverse();
        } else {
            inv = a.getInverse();
        }

        self.multiply(&inv);
        if (self.isOverflow()) self.fullReduce();
    }

    /// Modular inverse via Fermat's little theorem: `a^(p-2) mod p`.
    ///
    /// Core uses safegcd (libsecp256k1-style divsteps; see `Num3072::GetInverse`
    /// in `muhash.cpp`). Fermat is ~6× slower for a 3072-bit modulus but is
    /// trivially correct from the prime modulus alone, with no extra invariants
    /// to maintain. `Finalize` is the only call site, and it runs once per
    /// `dumptxoutset` / `gettxoutsetinfo` — not on any hot path.
    ///
    /// `p - 2 = 2^3072 - 1103719`. We square-and-multiply MSB-first across
    /// the 48 limbs (top limb first, top bit first). When a bit is set we
    /// multiply the running result by `*this`.
    fn getInverse(self: *const Num3072) Num3072 {
        // Build the exponent `p - 2` as 48 LE u64 limbs.
        // 2^3072 in this limb form is "all zeros + 1 in a 49th limb"; subtracting
        // (MAX_PRIME_DIFF + 2) from it underflows the bottom limb and borrows
        // upward across every remaining all-zero limb, producing
        // `[~(MAX_PRIME_DIFF+1), 0xFF..FF, 0xFF..FF, ..., 0xFF..FF]`.
        var exp: [LIMBS]u64 = undefined;
        // limb[0] = 0 - (MAX_PRIME_DIFF + 2) (mod 2^64)
        exp[0] = 0 -% (MAX_PRIME_DIFF + 2);
        var k: usize = 1;
        while (k < LIMBS) : (k += 1) exp[k] = std.math.maxInt(u64);

        var result = Num3072.one();
        // Square-and-multiply MSB-first.
        var li: usize = LIMBS;
        while (li > 0) {
            li -= 1;
            const limb = exp[li];
            var bit: i32 = 63;
            while (bit >= 0) : (bit -= 1) {
                var sq = result;
                result.multiply(&sq);
                if (((limb >> @intCast(bit)) & 1) != 0) {
                    sq = self.*;
                    result.multiply(&sq);
                }
            }
        }
        // Bring result fully into [0, p) — multiply already keeps it
        // canonical-or-overflow, but be paranoid.
        if (result.isOverflow()) result.fullReduce();
        return result;
    }
};

// =========================================================================
// Limb arithmetic primitives — direct ports of the static helpers in
// bitcoin-core/src/crypto/muhash.cpp:38..111.
// =========================================================================

const u128_t = u128;

/// Extract the lowest limb of [c0,c1,c2] into n, then left-shift by one limb.
inline fn extract3(c0: *u64, c1: *u64, c2: *u64, n: *u64) void {
    n.* = c0.*;
    c0.* = c1.*;
    c1.* = c2.*;
    c2.* = 0;
}

/// `[c0,c1] = a * b`.
inline fn mul(c0: *u64, c1: *u64, a: u64, b: u64) void {
    const t: u128_t = @as(u128_t, a) * @as(u128_t, b);
    c1.* = @intCast(t >> 64);
    c0.* = @truncate(t);
}

/// `[c0,c1,c2] += n * [d0,d1,d2]`. c2 is assumed 0 on entry.
inline fn mulnadd3(c0: *u64, c1: *u64, c2: *u64, d0: *u64, d1: *u64, d2: *u64, n: u64) void {
    var t: u128_t = @as(u128_t, d0.*) * @as(u128_t, n) + @as(u128_t, c0.*);
    c0.* = @truncate(t);
    t >>= 64;
    t += @as(u128_t, d1.*) * @as(u128_t, n) + @as(u128_t, c1.*);
    c1.* = @truncate(t);
    t >>= 64;
    c2.* = @truncate(t +% @as(u128_t, d2.*) *% @as(u128_t, n));
}

/// `[c0,c1] *= n`.
inline fn muln2(c0: *u64, c1: *u64, n: u64) void {
    var t: u128_t = @as(u128_t, c0.*) * @as(u128_t, n);
    c0.* = @truncate(t);
    t >>= 64;
    t += @as(u128_t, c1.*) * @as(u128_t, n);
    c1.* = @truncate(t);
}

/// `[c0,c1,c2] += a * b`.
inline fn muladd3(c0: *u64, c1: *u64, c2: *u64, a: u64, b: u64) void {
    const t: u128_t = @as(u128_t, a) * @as(u128_t, b);
    const th: u64 = @intCast(t >> 64);
    const tl: u64 = @truncate(t);

    const c0_old = c0.*;
    c0.* = c0.* +% tl;
    var th_carry: u64 = th;
    if (c0.* < tl) th_carry +%= 1;
    _ = c0_old;
    const c1_old = c1.*;
    c1.* = c1.* +% th_carry;
    var c2_carry: u64 = 0;
    if (c1.* < th_carry) c2_carry = 1;
    _ = c1_old;
    c2.* +%= c2_carry;
}

/// `[c0,c1] += a`, then extract lowest limb of `[c0,c1]` into `n` and
/// left-shift `[c0,c1]` by one limb.
inline fn addnextract2(c0: *u64, c1: *u64, a: u64, n: *u64) void {
    var c2: u64 = 0;
    const c0_old = c0.*;
    c0.* = c0.* +% a;
    if (c0.* < a) {
        c1.* +%= 1;
        if (c1.* == 0) c2 = 1;
    }
    _ = c0_old;
    n.* = c0.*;
    c0.* = c1.*;
    c1.* = c2;
}

// =========================================================================
// MuHash3072 — multiplicative set accumulator.
// =========================================================================

pub const MuHash3072 = struct {
    numerator: Num3072 = Num3072{ .limbs = [_]u64{0} ** Num3072.LIMBS },
    denominator: Num3072 = Num3072{ .limbs = [_]u64{0} ** Num3072.LIMBS },

    /// Empty multiset (numerator = denominator = 1).
    pub fn init() MuHash3072 {
        return .{
            .numerator = Num3072.one(),
            .denominator = Num3072.one(),
        };
    }

    /// Singleton containing `data` (Core: `MuHash3072(span)`).
    pub fn initWith(data: []const u8) MuHash3072 {
        var m = MuHash3072.init();
        m.numerator = toNum3072(data);
        return m;
    }

    /// Insert one element into the multiset.
    pub fn insert(self: *MuHash3072, data: []const u8) void {
        var v = toNum3072(data);
        self.numerator.multiply(&v);
    }

    /// Remove one element from the multiset.
    pub fn remove(self: *MuHash3072, data: []const u8) void {
        var v = toNum3072(data);
        self.denominator.multiply(&v);
    }

    /// Multiply (set union of two multisets).
    pub fn mulAssign(self: *MuHash3072, other: *const MuHash3072) void {
        self.numerator.multiply(&other.numerator);
        self.denominator.multiply(&other.denominator);
    }

    /// Divide (set difference).
    pub fn divAssign(self: *MuHash3072, other: *const MuHash3072) void {
        self.numerator.multiply(&other.denominator);
        self.denominator.multiply(&other.numerator);
    }

    /// Finalize: compute `numerator / denominator`, serialize LE, return
    /// SHA256 of those 384 bytes. Resets `denominator` to 1 so the object
    /// remains usable. Matches Core's `MuHash3072::Finalize`.
    pub fn finalize(self: *MuHash3072) [32]u8 {
        self.numerator.divide(&self.denominator);
        self.denominator.setToOne();
        var bytes: [Num3072.BYTE_SIZE]u8 = undefined;
        self.numerator.toBytes(&bytes);
        return crypto.sha256(&bytes);
    }

    /// Byte size of the UN-finalized accumulator (numerator ‖ denominator),
    /// each a 384-byte little-endian `Num3072`.  This is what Core persists in
    /// `DBVal`/`DB_MUHASH` (the un-finalized `MuHash3072`), NOT the 32-byte
    /// finalized digest — so that the multiset accumulator can keep growing
    /// across restarts and be exactly reversed on reorg.
    pub const SERIALIZED_SIZE: usize = Num3072.BYTE_SIZE * 2;

    /// Serialize the un-finalized accumulator into `out` (768 bytes):
    /// numerator (384 LE) ‖ denominator (384 LE).  Non-mutating, unlike
    /// `finalize` — call this to checkpoint a still-accumulating MuHash.
    pub fn toBytes(self: *const MuHash3072, out: *[SERIALIZED_SIZE]u8) void {
        self.numerator.toBytes(out[0..Num3072.BYTE_SIZE]);
        self.denominator.toBytes(out[Num3072.BYTE_SIZE..][0..Num3072.BYTE_SIZE]);
    }

    /// Inverse of `toBytes`: reconstruct an un-finalized accumulator from its
    /// 768-byte numerator ‖ denominator serialization.
    pub fn fromBytes(data: *const [SERIALIZED_SIZE]u8) MuHash3072 {
        return .{
            .numerator = Num3072.fromBytes(data[0..Num3072.BYTE_SIZE]),
            .denominator = Num3072.fromBytes(data[Num3072.BYTE_SIZE..][0..Num3072.BYTE_SIZE]),
        };
    }
};

/// Map an arbitrary-length byte string to a Num3072 element.
///
/// Algorithm (Core: `MuHash3072::ToNum3072`):
///   1. `key = SHA256(data)` — 32 bytes.
///   2. `tmp[0..384] = ChaCha20Keystream(key=key, nonce=0, counter=0)`.
///   3. Interpret `tmp` as a 3072-bit little-endian integer.
fn toNum3072(data: []const u8) Num3072 {
    const key = crypto.sha256(data);
    var tmp: [Num3072.BYTE_SIZE]u8 = [_]u8{0} ** Num3072.BYTE_SIZE;
    // ChaCha20IETF nonce: 12 bytes of zero. Encrypting zero plaintext
    // produces the keystream, which is what `Keystream()` does in Core.
    const nonce: [12]u8 = [_]u8{0} ** 12;
    ChaCha20.xor(&tmp, &tmp, 0, key, nonce);
    return Num3072.fromBytes(&tmp);
}

// =========================================================================
// Tests — Core test vectors from
// bitcoin-core/src/test/crypto_tests.cpp `muhash_tests` (line 1201).
// =========================================================================

const testing = std.testing;

fn fromInt(i: u8) MuHash3072 {
    var tmp: [32]u8 = [_]u8{0} ** 32;
    tmp[0] = i;
    return MuHash3072.initWith(&tmp);
}

test "Num3072 setToOne / one" {
    const n = Num3072.one();
    try testing.expectEqual(@as(u64, 1), n.limbs[0]);
    var i: usize = 1;
    while (i < Num3072.LIMBS) : (i += 1) try testing.expectEqual(@as(u64, 0), n.limbs[i]);
}

test "Num3072 fromBytes / toBytes round trip" {
    var bytes: [Num3072.BYTE_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < Num3072.BYTE_SIZE) : (i += 1) bytes[i] = @intCast(i & 0xFF);
    const n = Num3072.fromBytes(&bytes);
    var out: [Num3072.BYTE_SIZE]u8 = undefined;
    n.toBytes(&out);
    try testing.expectEqualSlices(u8, &bytes, &out);
}

test "Num3072 multiply 1 * x = x" {
    var bytes: [Num3072.BYTE_SIZE]u8 = [_]u8{0} ** Num3072.BYTE_SIZE;
    bytes[0] = 7;
    bytes[100] = 42;
    bytes[200] = 99;
    const x = Num3072.fromBytes(&bytes);
    var one_v = Num3072.one();
    one_v.multiply(&x);
    try testing.expectEqual(x.limbs, one_v.limbs);
}

test "Num3072 multiply commutative" {
    var ba: [Num3072.BYTE_SIZE]u8 = [_]u8{0} ** Num3072.BYTE_SIZE;
    var bb: [Num3072.BYTE_SIZE]u8 = [_]u8{0} ** Num3072.BYTE_SIZE;
    ba[0] = 5;
    ba[10] = 17;
    bb[0] = 13;
    bb[20] = 31;
    var a = Num3072.fromBytes(&ba);
    var b = Num3072.fromBytes(&bb);
    var ab = a;
    ab.multiply(&b);
    var ba2 = b;
    ba2.multiply(&a);
    try testing.expectEqual(ab.limbs, ba2.limbs);
}

test "Num3072 inverse: x * x^-1 = 1" {
    var bytes: [Num3072.BYTE_SIZE]u8 = [_]u8{0} ** Num3072.BYTE_SIZE;
    bytes[0] = 7;
    bytes[5] = 11;
    const x = Num3072.fromBytes(&bytes);
    const inv = x.getInverse();
    var prod = x;
    prod.multiply(&inv);
    if (prod.isOverflow()) prod.fullReduce();
    var expect = Num3072.one();
    if (expect.isOverflow()) expect.fullReduce();
    try testing.expectEqual(expect.limbs, prod.limbs);
}

test "MuHash3072 empty finalize is deterministic" {
    var a = MuHash3072.init();
    var b = MuHash3072.init();
    const ha = a.finalize();
    const hb = b.finalize();
    try testing.expectEqualSlices(u8, &ha, &hb);
}

test "MuHash3072 add then remove cancels" {
    var a = MuHash3072.init();
    const empty_hash = blk: {
        var e = MuHash3072.init();
        break :blk e.finalize();
    };

    var tmp: [32]u8 = [_]u8{0} ** 32;
    tmp[0] = 0x42;
    a.insert(&tmp);
    a.remove(&tmp);
    const ha = a.finalize();
    try testing.expectEqualSlices(u8, &empty_hash, &ha);
}

test "MuHash3072 commutative under permutation (Core randomized loop)" {
    // Mirrors crypto_tests.cpp:1205 — for any sequence of inserts/removes,
    // the finalized hash is independent of order. We use a fixed sequence
    // to stay reproducible in unit tests.
    const ops = [_]struct { op: u8, val: u8 }{
        .{ .op = 0, .val = 1 },
        .{ .op = 0, .val = 2 },
        .{ .op = 1, .val = 3 },
        .{ .op = 0, .val = 4 },
    };

    var first_hash: [32]u8 = undefined;
    var iter: usize = 0;
    while (iter < 4) : (iter += 1) {
        var acc = MuHash3072.init();
        var k: usize = 0;
        while (k < ops.len) : (k += 1) {
            const op_idx = (k + iter) % ops.len;
            var tmp: [32]u8 = [_]u8{0} ** 32;
            tmp[0] = ops[op_idx].val;
            if (ops[op_idx].op == 0) acc.insert(&tmp) else acc.remove(&tmp);
        }
        const h = acc.finalize();
        if (iter == 0) {
            @memcpy(&first_hash, &h);
        } else {
            try testing.expectEqualSlices(u8, &first_hash, &h);
        }
    }
}

test "MuHash3072 known vector: insert(0) * insert(1) / insert(2)" {
    // From bitcoin-core/src/test/crypto_tests.cpp:1245-1249:
    //   acc = FromInt(0); acc *= FromInt(1); acc /= FromInt(2);
    //   acc.Finalize(out) == 0x10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863
    // Note Core's uint256 prints in display (reversed) order; the raw byte
    // sequence written by SHA256 over the serialized Num3072 is the literal
    // hex above read MSB-first. uint256{"abc..."} parses that hex as the
    // display string, so the in-memory bytes are reversed.
    var acc = fromInt(0);
    var b1 = fromInt(1);
    acc.mulAssign(&b1);
    var b2 = fromInt(2);
    acc.divAssign(&b2);
    const out = acc.finalize();

    // uint256 display string -> internal bytes are reversed.
    const display_hex = "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863";
    var expected_display: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected_display, display_hex) catch unreachable;
    var expected_internal: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) expected_internal[i] = expected_display[31 - i];

    try testing.expectEqualSlices(u8, &expected_internal, &out);
}

test "MuHash3072 Insert/Remove == operator*= / operator/= equivalence" {
    // Core: lines 1251-1257 — Insert/Remove should give the same hash as
    // *=/= constructed from FromInt.
    var acc1 = fromInt(0);
    var b1 = fromInt(1);
    acc1.mulAssign(&b1);
    var b2 = fromInt(2);
    acc1.divAssign(&b2);
    const h1 = acc1.finalize();

    var acc2 = fromInt(0);
    var tmp1: [32]u8 = [_]u8{0} ** 32;
    tmp1[0] = 1;
    acc2.insert(&tmp1);
    var tmp2: [32]u8 = [_]u8{0} ** 32;
    tmp2[0] = 2;
    acc2.remove(&tmp2);
    const h2 = acc2.finalize();

    try testing.expectEqualSlices(u8, &h1, &h2);
}

test "MuHash3072 z = x*y / (y*x) finalizes to identity" {
    // Core: lines 1229-1242 — z initialized empty, multiply by x and y,
    // then divide by (y*x); should equal the empty hash.
    var x = fromInt(3);
    var y = fromInt(5);
    var z = MuHash3072.init();
    z.mulAssign(&x);
    z.mulAssign(&y);
    var yx = y;
    yx.mulAssign(&x);
    z.divAssign(&yx);
    const h_z = z.finalize();

    var empty = MuHash3072.init();
    const h_empty = empty.finalize();

    try testing.expectEqualSlices(u8, &h_empty, &h_z);
}
