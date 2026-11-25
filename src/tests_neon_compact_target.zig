//! Compact-target (nBits) checks from the 2026-11-24 independent audit of
//! clearbit (finding 8), pinned against Bitcoin Core v31.1.
//!
//! The PoW gate decoded nBits without Core's SetCompact overflow and zero
//! checks.  Core's CheckProofOfWorkImpl (pow.cpp) refuses
//! `fNegative || bnTarget == 0 || fOverflow || bnTarget > powLimit`.
//! clearbit's bitsToTarget drops mantissa bytes shifted past byte 31, so
//! regtest bits 0x21010001 (size 33, word 0x010001: overflow) decoded to
//! 2^240, under regtest's powLimit, and a header meeting 2^240 passed.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const validation = @import("validation.zig");
const consensus = @import("consensus.zig");

// ---------------------------------------------------------------------------
// F8
// ---------------------------------------------------------------------------

/// consensus.compactTargetValid is added by the fix; on master this file must
/// still compile and the tests that need it must FAIL (not skip).
fn compactValid(bits: u32) !bool {
    if (comptime @hasDecl(consensus, "compactTargetValid")) return consensus.compactTargetValid(bits);
    return error.CompactTargetGateMissing;
}

/// Grind the nonce until the header hash is <= 2^240 (top two bytes zero),
/// which meets both the overflowed 0x21010001 target as clearbit decoded it
/// and regtest's real 0x207fffff target.
fn grind(bits: u32) !types.BlockHeader {
    var h = types.BlockHeader{
        .version = 4,
        .prev_block = [_]u8{0x33} ** 32,
        .merkle_root = [_]u8{0x44} ** 32,
        .timestamp = 1_700_000_000,
        .bits = bits,
        .nonce = 0,
    };
    while (h.nonce < (1 << 26)) : (h.nonce += 1) {
        const hash = crypto.computeBlockHash(&h);
        if (hash[31] == 0 and hash[30] == 0) return h;
    }
    return error.NoNonce;
}

test "neon F8: nBits 0x21010001 (SetCompact overflow) fails the PoW gate on regtest" {
    // Core: nSize=33, nWord=0x010001 > 0xffff && nSize > 32 -> fOverflow ->
    // CheckProofOfWorkImpl false ("high-hash").
    const h = try grind(0x21010001);
    try testing.expectError(validation.ValidationError.BadDifficulty, validation.checkBlockHeader(&h, &consensus.REGTEST));
    try testing.expect(!consensus.validateProofOfWork(&h, &consensus.REGTEST));
}

test "neon F8: nBits with a zero target (0x01003456) fails the PoW gate" {
    // Core: nSize=1 -> nWord >>= 16 -> 0 -> bnTarget == 0 -> false.  A hash
    // can't be 0, so this pins the explicit zero check, not a reachable split.
    try testing.expect(!try compactValid(0x01003456));
    try testing.expect(!try compactValid(0x00000000));
}

test "neon F8: SetCompact overflow boundaries match Core" {
    // Not overflow: size 32 any word; size 33 word <= 0xffff; size 34 word <= 0xff.
    try testing.expect(try compactValid(0x207fffff));
    try testing.expect(try compactValid(0x2100ffff));
    try testing.expect(try compactValid(0x220000ff));
    // Overflow.
    try testing.expect(!try compactValid(0x21010000));
    try testing.expect(!try compactValid(0x22000100));
    try testing.expect(!try compactValid(0x23000001));
    // Size > 34 with a zero word is zero, not overflow -> still invalid (zero).
    try testing.expect(!try compactValid(0x23000000));
    // Negative.
    try testing.expect(!try compactValid(0x04923456));
    // Mainnet genesis bits.
    try testing.expect(try compactValid(0x1d00ffff));
}

test "neon F8 control: a regtest header at 0x207fffff meeting its target passes" {
    const h = try grind(0x207fffff);
    try validation.checkBlockHeader(&h, &consensus.REGTEST);
    try testing.expect(consensus.validateProofOfWork(&h, &consensus.REGTEST));
}
