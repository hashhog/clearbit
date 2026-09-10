//! Genesis-scale chainwork: Core GetBlockProof / nChainWork as 32-byte BE.
//!
//! Bitcoin Core (`chain.cpp` GetBitsProof, formerly `pow.cpp` GetBlockProof):
//!   work = (~target / (target + 1)) + 1
//! Cumulative nChainWork at a block is the sum of GetBlockProof from genesis
//! through that block (LoadBlockIndexDB / AddToBlockIndex).  Stored and
//! compared big-endian so byte order matches `arith_uint256::GetHex()`.
//!
//! `NetworkParams.min_chain_work` is stored via `hexToHash` (display hex
//! reversed, same as hashes).  Use `minChainWorkBE` before comparing it
//! against values produced here.

const std = @import("std");
const consensus = @import("consensus.zig");

/// In-place big-endian 256-bit add: a += b.  Drops a final carry (overflow
/// of cumulative chainwork is not reachable at Bitcoin difficulties).
pub fn addChainWorkBE(a: *[32]u8, b: *const [32]u8) void {
    var carry: u16 = 0;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        const sum = @as(u16, a[i]) + @as(u16, b[i]) + carry;
        a[i] = @intCast(sum & 0xFF);
        carry = sum >> 8;
    }
}

/// In-place big-endian 256-bit subtract: a -= b.  Saturates at zero on
/// underflow (a disconnect against an unseeded total_work).
pub fn subChainWorkBE(a: *[32]u8, b: *const [32]u8) void {
    var borrow: i16 = 0;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        const diff: i16 = @as(i16, a[i]) - @as(i16, b[i]) - borrow;
        if (diff < 0) {
            a[i] = @intCast(diff + 256);
            borrow = 1;
        } else {
            a[i] = @intCast(diff);
            borrow = 0;
        }
    }
    if (borrow != 0) @memset(a, 0);
}

/// Compare two 256-bit big-endian chain-work values.  >0 if a > b, <0 if
/// a < b, 0 if equal.
pub fn cmpChainWorkBE(a: *const [32]u8, b: *const [32]u8) i32 {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

pub fn isZero(w: *const [32]u8) bool {
    return std.mem.allEqual(u8, w, 0);
}

/// Restore Core GetHex / BE order from `NetworkParams.min_chain_work`
/// (stored via hexToHash, i.e. byte-reversed).
pub fn minChainWorkBE(min_stored: *const [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (0..32) |i| out[i] = min_stored[31 - i];
    return out;
}

/// Core `arith_uint256::getdouble` on a 32-byte big-endian work value.
pub fn workToF64(w: *const [32]u8) f64 {
    var acc: f64 = 0;
    for (w.*) |b| {
        acc = acc * 256.0 + @as(f64, @floatFromInt(b));
    }
    return acc;
}

/// Core GetBitsProof / GetBlockProof: `(~target / (target + 1)) + 1`.
/// Returns 32-byte big-endian work; zero on a zero/negative/overflow target.
pub fn workFromBits(bits: u32) [32]u8 {
    const zero: [32]u8 = [_]u8{0} ** 32;
    const target_le = consensus.bitsToTarget(bits);
    var target_be: [32]u8 = undefined;
    {
        var i: usize = 0;
        while (i < 32) : (i += 1) target_be[i] = target_le[31 - i];
    }
    var nonzero = false;
    for (target_be) |b| {
        if (b != 0) {
            nonzero = true;
            break;
        }
    }
    if (!nonzero) return zero;

    var nt: [32]u8 = undefined;
    {
        var i: usize = 0;
        while (i < 32) : (i += 1) nt[i] = ~target_be[i];
    }

    var t_plus_1: [32]u8 = target_be;
    {
        var carry: u16 = 1;
        var j: usize = 32;
        while (j > 0 and carry != 0) {
            j -= 1;
            const sum = @as(u16, t_plus_1[j]) + carry;
            t_plus_1[j] = @intCast(sum & 0xFF);
            carry = sum >> 8;
        }
    }

    var quotient: [32]u8 = [_]u8{0} ** 32;
    var remainder: [32]u8 = [_]u8{0} ** 32;

    var bit_i: usize = 0;
    while (bit_i < 256) : (bit_i += 1) {
        var carry_bit: u8 = 0;
        var j: usize = 32;
        while (j > 0) {
            j -= 1;
            const new_carry: u8 = (remainder[j] >> 7) & 1;
            remainder[j] = (remainder[j] << 1) | carry_bit;
            carry_bit = new_carry;
        }
        const byte_i: usize = bit_i / 8;
        const bit_off: u3 = @intCast(7 - (bit_i % 8));
        const next_bit: u8 = (nt[byte_i] >> bit_off) & 1;
        remainder[31] |= next_bit;

        if (cmpChainWorkBE(&remainder, &t_plus_1) >= 0) {
            var borrow: i16 = 0;
            var k: usize = 32;
            while (k > 0) {
                k -= 1;
                const diff: i16 = @as(i16, remainder[k]) - @as(i16, t_plus_1[k]) - borrow;
                if (diff < 0) {
                    remainder[k] = @intCast(diff + 256);
                    borrow = 1;
                } else {
                    remainder[k] = @intCast(diff);
                    borrow = 0;
                }
            }
            quotient[byte_i] |= (@as(u8, 1) << bit_off);
        }
    }

    {
        var carry: u16 = 1;
        var j: usize = 32;
        while (j > 0 and carry != 0) {
            j -= 1;
            const sum = @as(u16, quotient[j]) + carry;
            quotient[j] = @intCast(sum & 0xFF);
            carry = sum >> 8;
        }
    }

    return quotient;
}

/// Lowercase hex of a 32-byte BE chainwork (Core GetHex, no 0x prefix).
pub fn toHex(w: *const [32]u8) [64]u8 {
    var out: [64]u8 = undefined;
    const digits = "0123456789abcdef";
    for (w.*, 0..) |b, i| {
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0x0F];
    }
    return out;
}

test "workFromBits: genesis bits 0x1d00ffff is Core GetBlockProof 0x100010001" {
    const w = workFromBits(0x1d00ffff);
    var expected: [32]u8 = [_]u8{0} ** 32;
    expected[27] = 0x01;
    expected[28] = 0x00;
    expected[29] = 0x01;
    expected[30] = 0x00;
    expected[31] = 0x01;
    try std.testing.expectEqualSlices(u8, &expected, &w);
    const hex = toHex(&w);
    try std.testing.expectEqualStrings(
        "0000000000000000000000000000000000000000000000000000000100010001",
        &hex,
    );
}

test "workFromBits: zero bits → zero work" {
    const w = workFromBits(0);
    try std.testing.expect(isZero(&w));
}

test "addChainWorkBE / subChainWorkBE roundtrip" {
    const g = workFromBits(0x1d00ffff);
    var acc = g;
    addChainWorkBE(&acc, &g);
    var want: [32]u8 = [_]u8{0} ** 32;
    want[27] = 0x02;
    want[29] = 0x02;
    want[31] = 0x02;
    try std.testing.expectEqualSlices(u8, &want, &acc);
    subChainWorkBE(&acc, &g);
    try std.testing.expectEqualSlices(u8, &g, &acc);
}

test "minChainWorkBE undoes hexToHash reversal" {
    const stored = consensus.MAINNET.min_chain_work;
    const be = minChainWorkBE(&stored);
    try std.testing.expectEqual(@as(u8, 0x00), be[0]);
    try std.testing.expectEqual(@as(u8, 0x30), be[31]);
    try std.testing.expect(cmpChainWorkBE(&be, &stored) != 0);
    const genesis = workFromBits(0x1d00ffff);
    try std.testing.expect(cmpChainWorkBE(&genesis, &be) < 0);
}
