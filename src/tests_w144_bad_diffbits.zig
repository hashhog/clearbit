//! W144 — bad-diffbits enforcement: dead checkDifficulty → live gate threaded.
//!
//! Bitcoin Core reference:
//!   validation.cpp:4088  ContextualCheckBlockHeader "bad-diffbits"
//!   pow.cpp:14           GetNextWorkRequired
//!
//! BEFORE this fix:
//!   - IBDValidationContext.expected_bits was always 0 (the "skip" sentinel) on
//!     every live call path (peer.zig + rpc.zig) because no caller computed it.
//!   - contextualCheckBlockHeader (validation.zig:1299) had the gate wired but it
//!     was dead: `if (ctx.expected_bits != 0 and ...)` never fired.
//!   - validateHeaderContextual returned only ok / mtp_violation / future_time;
//!     wrong nBits at header-receipt time passed silently.
//!
//! AFTER this fix:
//!   - PeerManager.computeExpectedBits walks header_index + persisted headers to
//!     compute GetNextWorkRequired for any block.
//!   - validateBlockForIBDOrReject passes the result as expected_bits.
//!   - validateHeaderContextual checks bad-diffbits for the first header in each
//!     batch (when the prev block is already in header_index).
//!   - AcceptBlockOptions.expected_bits threads through acceptBlock to IBDValidationContext.
//!
//! Run with: `zig build test-w144`

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const validation = @import("validation.zig");

const PeerManager = peer_mod.PeerManager;
const BlockHeaderEntry = peer_mod.BlockHeaderEntry;

// ============================================================================
// Helpers
// ============================================================================

/// Build a simple BlockHeaderEntry with the given bits and height.
fn makeEntry(
    hash: types.Hash256,
    prev: types.Hash256,
    h: u32,
    bits: u32,
    ts: u32,
) BlockHeaderEntry {
    return BlockHeaderEntry{
        .hash = hash,
        .prev_hash = prev,
        .height = h,
        .chain_work = [_]u8{0} ** 32,
        .timestamp = ts,
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = prev,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = ts,
            .bits = bits,
            .nonce = 0,
        },
        .last_seen = 0,
    };
}

/// Mainnet difficulty bits for a real block (compact target, used as sentinel).
const MAINNET_BITS: u32 = 0x1d00ffff; // genesis / early mainnet compact target

// ============================================================================
// Test 1 — computeExpectedBits returns 0 when prev_hash not known (skip gate)
// ============================================================================

test "W144: computeExpectedBits returns 0 when prev unknown → gate skipped" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // header_index is empty; chain_state is null (pm.chain_state == null after init).
    const unknown: types.Hash256 = [_]u8{0xDE} ** 32;
    const result = pm.computeExpectedBits(unknown, 1, 1_231_006_505 + 600);
    // Should return 0 (skip sentinel) because prev_hash is not resolvable.
    try testing.expectEqual(@as(u32, 0), result);
}

// ============================================================================
// Test 2 — computeExpectedBits correctly returns prev.bits for mainnet
//           non-retarget block (height % 2016 != 0)
// ============================================================================

test "W144: computeExpectedBits mainnet non-retarget returns prev bits" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // height 5 → non-retarget (5 % 2016 != 0).
    // Seed header_index with entries at heights 1..4, all with MAINNET_BITS.
    var prev: types.Hash256 = [_]u8{0xAA} ** 32;
    var i: u32 = 1;
    while (i <= 4) : (i += 1) {
        const h: types.Hash256 = blk: {
            var hh = [_]u8{0} ** 32;
            hh[0] = @intCast(i);
            break :blk hh;
        };
        try pm.header_index.put(h, makeEntry(h, prev, i, MAINNET_BITS, 1_231_006_505 + i * 600));
        prev = h;
    }
    // `prev` is now the hash of height-4 entry; height-5 block's prev_block = prev.
    const block_ts: u32 = 1_231_006_505 + 5 * 600;
    const expected = pm.computeExpectedBits(prev, 5, block_ts);
    // Non-retarget mainnet: expected == prev.bits == MAINNET_BITS.
    try testing.expectEqual(MAINNET_BITS, expected);
}

// ============================================================================
// Test 3 — validateHeaderContextual returns .bad_diffbits for wrong bits
//           when prev block is in header_index
// ============================================================================

test "W144: validateHeaderContextual returns bad_diffbits when header.bits wrong" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // Seed one ancestor at height 0 with MAINNET_BITS.
    const prev_hash: types.Hash256 = [_]u8{0xBB} ** 32;
    try pm.header_index.put(prev_hash, makeEntry(
        prev_hash,
        [_]u8{0} ** 32,
        0,
        MAINNET_BITS,
        1_231_006_505,
    ));

    // Block at height 1, prev = prev_hash.  Correct bits would be MAINNET_BITS
    // (non-retarget on mainnet).  Submit wrong bits instead.
    const wrong_bits: u32 = 0x1c00ffff; // harder than MAINNET_BITS
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = prev_hash,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_231_006_505 + 600,
        .bits = wrong_bits,
        .nonce = 0,
    };

    const verdict = pm.validateHeaderContextual(&header, 2_000_000_000);
    try testing.expectEqual(PeerManager.HeaderTimeReject.bad_diffbits, verdict);
}

// ============================================================================
// Test 4 — validateHeaderContextual returns .ok when header.bits is correct
// ============================================================================

test "W144: validateHeaderContextual accepts correct nBits" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const prev_hash: types.Hash256 = [_]u8{0xCC} ** 32;
    try pm.header_index.put(prev_hash, makeEntry(
        prev_hash,
        [_]u8{0} ** 32,
        0,
        MAINNET_BITS,
        1_231_006_505,
    ));

    // Correct bits for height-1 non-retarget mainnet block == MAINNET_BITS.
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = prev_hash,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_231_006_505 + 600,
        .bits = MAINNET_BITS, // correct
        .nonce = 0,
    };

    const verdict = pm.validateHeaderContextual(&header, 2_000_000_000);
    try testing.expectEqual(PeerManager.HeaderTimeReject.ok, verdict);
}

// ============================================================================
// Test 5 — validateHeaderContextual skips bad-diffbits when prev unknown
//           (mid-batch or pre-sync — must not false-reject)
// ============================================================================

test "W144: validateHeaderContextual skips bad-diffbits when prev unknown" {
    const allocator = testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // prev_block unknown — header_index is empty.
    const unknown_prev: types.Hash256 = [_]u8{0xDD} ** 32;
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = unknown_prev,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_600_000_000,
        .bits = 0x1c0fafaf, // obviously wrong bits, but prev unknown so skip
        .nonce = 0,
    };

    const verdict = pm.validateHeaderContextual(&header, 2_000_000_000);
    // Must return .ok (not .bad_diffbits) when prev is unknown.
    try testing.expectEqual(PeerManager.HeaderTimeReject.ok, verdict);
}

// ============================================================================
// Test 6 — contextualCheckBlockHeader (validation.zig:1299) rejects wrong bits
//           when expected_bits != 0.  Proves the EFFECTIVE gate fires.
// ============================================================================

test "W144 EFFECTIVE: contextualCheckBlockHeader rejects block with wrong expected_bits" {
    // This test exercises the exact gate in validation.zig:1299:
    //   if (ctx.expected_bits != 0 and header.bits != ctx.expected_bits)
    //       return ValidationError.BadDifficulty
    // which was dead before this wave because expected_bits was always 0.
    const params = &consensus.MAINNET;

    const hdr = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_231_006_505 + 600,
        .bits = 0x1c0fafaf, // wrong bits
        .nonce = 0,
    };

    // Pass expected_bits = MAINNET_BITS; header.bits != MAINNET_BITS → reject.
    const ctx = validation.ContextualHeaderCtx{
        .expected_bits = MAINNET_BITS,
        .prev_mtp = 0,
        .prev_block_timestamp = 0,
        .current_time = 0,
    };

    const result = validation.contextualCheckBlockHeader(&hdr, 1, params, ctx);
    try testing.expectError(validation.ValidationError.BadDifficulty, result);
}

// ============================================================================
// Test 7 — contextualCheckBlockHeader accepts when bits are correct
// ============================================================================

test "W144: contextualCheckBlockHeader accepts correct bits" {
    const params = &consensus.MAINNET;

    const hdr = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_231_006_505 + 600,
        .bits = MAINNET_BITS, // correct
        .nonce = 0,
    };

    const ctx = validation.ContextualHeaderCtx{
        .expected_bits = MAINNET_BITS,
        .prev_mtp = 0,
        .prev_block_timestamp = 0,
        .current_time = 0,
    };

    try validation.contextualCheckBlockHeader(&hdr, 1, params, ctx);
}

// ============================================================================
// Test 8 — contextualCheckBlockHeader skips when expected_bits == 0 (sentinel)
// ============================================================================

test "W144: contextualCheckBlockHeader skips bad-diffbits when expected_bits==0" {
    const params = &consensus.MAINNET;

    const hdr = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_231_006_505 + 600,
        .bits = 0x1c0fafaf, // wrong bits, but expected_bits == 0 → skip
        .nonce = 0,
    };

    const ctx = validation.ContextualHeaderCtx{
        .expected_bits = 0, // sentinel: skip the gate
        .prev_mtp = 0,
        .prev_block_timestamp = 0,
        .current_time = 0,
    };

    // Should NOT return BadDifficulty when expected_bits is 0.
    try validation.contextualCheckBlockHeader(&hdr, 1, params, ctx);
}
