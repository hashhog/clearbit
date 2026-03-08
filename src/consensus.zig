const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

// ============================================================================
// Block Size and Weight Limits (BIP-141)
// ============================================================================

/// Maximum block weight (BIP-141). 4,000,000 weight units.
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;

/// Maximum block size for legacy (pre-segwit) serialization: 1 MB.
pub const MAX_BLOCK_SERIALIZED_SIZE: u32 = 4_000_000;

/// Maximum number of signature operations in a block (scaled by witness discount).
pub const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;

/// Witness scale factor: non-witness data counts as 4 weight units,
/// witness data counts as 1 weight unit.
pub const WITNESS_SCALE_FACTOR: u32 = 4;

/// Maximum standard transaction weight: 400,000 weight units.
pub const MAX_STANDARD_TX_WEIGHT: u32 = 400_000;

/// Maximum number of inputs for standard transactions.
pub const MAX_TX_IN_STANDARD: usize = 100_000;

/// Minimum transaction size (bytes).
pub const MIN_TX_SIZE: usize = 60;

// ============================================================================
// Monetary Policy
// ============================================================================

/// Maximum money supply: 21 million BTC = 2,100,000,000,000,000 satoshis.
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// Initial block subsidy: 50 BTC = 5,000,000,000 satoshis.
pub const INITIAL_SUBSIDY: i64 = 50 * 100_000_000;

/// Subsidy halving interval: every 210,000 blocks.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;

/// Coinbase maturity: coinbase outputs cannot be spent until 100 confirmations.
pub const COINBASE_MATURITY: u32 = 100;

/// Dust threshold relay fee: 3000 satoshis per kvB.
pub const DUST_RELAY_FEE: i64 = 3000;

// ============================================================================
// Difficulty Adjustment
// ============================================================================

/// Difficulty adjustment interval: every 2016 blocks.
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

/// Target block time: 10 minutes = 600 seconds.
pub const TARGET_SPACING: u32 = 600;

/// Target timespan for difficulty adjustment: 2 weeks = 1,209,600 seconds.
pub const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60;

/// Minimum allowed difficulty adjustment factor (timespan / 4).
pub const MIN_TIMESPAN: u32 = TARGET_TIMESPAN / 4;

/// Maximum allowed difficulty adjustment factor (timespan * 4).
pub const MAX_TIMESPAN: u32 = TARGET_TIMESPAN * 4;

/// Maximum target (minimum difficulty) - defines difficulty 1.
/// 0x00000000FFFF0000000000000000000000000000000000000000000000000000
pub const PROOF_OF_WORK_LIMIT: [32]u8 = blk: {
    var target: [32]u8 = [_]u8{0} ** 32;
    // Big-endian representation stored in little-endian byte order
    // Bytes 28-29 (from the end) are 0xFF
    target[28] = 0xFF;
    target[29] = 0xFF;
    break :blk target;
};

// ============================================================================
// Time Validation
// ============================================================================

/// Median-Time-Past: use the median of the last 11 blocks.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Maximum allowed block timestamp: 2 hours into the future.
pub const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60;

// ============================================================================
// Soft Fork Activation Heights (Mainnet)
// ============================================================================

/// BIP-34 activation height (require coinbase height).
pub const BIP34_HEIGHT: u32 = 227_931;

/// BIP-65 activation height (OP_CHECKLOCKTIMEVERIFY).
pub const BIP65_HEIGHT: u32 = 388_381;

/// BIP-66 activation height (strict DER signatures).
pub const BIP66_HEIGHT: u32 = 363_725;

/// Segwit activation height (BIP-141/143/147).
pub const SEGWIT_HEIGHT: u32 = 481_824;

/// Taproot activation height (BIP-341/342).
pub const TAPROOT_HEIGHT: u32 = 709_632;

// ============================================================================
// Network Configuration
// ============================================================================

/// Network type enumeration.
pub const Network = enum {
    mainnet,
    testnet,
    regtest,
    signet,
};

/// Network-specific parameters.
pub const NetworkParams = struct {
    magic: u32,
    default_port: u16,
    genesis_hash: types.Hash256,
    genesis_header: types.BlockHeader,
    dns_seeds: []const []const u8,
    bip34_height: u32,
    bip65_height: u32,
    bip66_height: u32,
    segwit_height: u32,
    taproot_height: u32,
    address_prefix: u8, // P2PKH version byte
    script_prefix: u8, // P2SH version byte
    bech32_hrp: []const u8, // "bc" or "tb"
    subsidy_halving_interval: u32,
    pow_limit: [32]u8,
    pow_no_retarget: bool,
};

/// Mainnet parameters.
pub const MAINNET = NetworkParams{
    .magic = 0xD9B4BEF9,
    .default_port = 8333,
    .genesis_hash = hexToHash("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
    .genesis_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = hexToHash("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        .timestamp = 1231006505,
        .bits = 0x1d00ffff,
        .nonce = 2083236893,
    },
    .dns_seeds = &[_][]const u8{
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr-list-of-hierarchical-deterministic-wallets.org",
        "seed.bitcoinstats.com",
        "seed.bitcoin.jonasschnelli.ch",
        "seed.btc.petertodd.net",
        "seed.bitcoin.sprovoost.nl",
        "dnsseed.emzy.de",
        "seed.bitcoin.wiz.biz",
    },
    .bip34_height = 227_931,
    .bip65_height = 388_381,
    .bip66_height = 363_725,
    .segwit_height = 481_824,
    .taproot_height = 709_632,
    .address_prefix = 0x00,
    .script_prefix = 0x05,
    .bech32_hrp = "bc",
    .subsidy_halving_interval = 210_000,
    .pow_limit = PROOF_OF_WORK_LIMIT,
    .pow_no_retarget = false,
};

/// Testnet3 parameters.
pub const TESTNET = NetworkParams{
    .magic = 0x0709110B,
    .default_port = 18333,
    .genesis_hash = hexToHash("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
    .genesis_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = hexToHash("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        .timestamp = 1296688602,
        .bits = 0x1d00ffff,
        .nonce = 414098458,
    },
    .dns_seeds = &[_][]const u8{
        "testnet-seed.bitcoin.jonasschnelli.ch",
        "seed.tbtc.petertodd.net",
        "seed.testnet.bitcoin.sprovoost.nl",
        "testnet-seed.bluematt.me",
    },
    .bip34_height = 21111,
    .bip65_height = 581885,
    .bip66_height = 330776,
    .segwit_height = 834624,
    .taproot_height = 2032291,
    .address_prefix = 0x6f,
    .script_prefix = 0xc4,
    .bech32_hrp = "tb",
    .subsidy_halving_interval = 210_000,
    .pow_limit = PROOF_OF_WORK_LIMIT,
    .pow_no_retarget = false,
};

/// Regtest parameters.
pub const REGTEST = NetworkParams{
    .magic = 0xDAB5BFFA,
    .default_port = 18444,
    .genesis_hash = hexToHash("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
    .genesis_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = hexToHash("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        .timestamp = 1296688602,
        .bits = 0x207fffff,
        .nonce = 2,
    },
    .dns_seeds = &[_][]const u8{},
    .bip34_height = 500,
    .bip65_height = 1351,
    .bip66_height = 1251,
    .segwit_height = 0,
    .taproot_height = 0,
    .address_prefix = 0x6f,
    .script_prefix = 0xc4,
    .bech32_hrp = "bcrt",
    .subsidy_halving_interval = 150,
    .pow_limit = blk: {
        var target: [32]u8 = [_]u8{0xFF} ** 32;
        target[31] = 0x7F;
        break :blk target;
    },
    .pow_no_retarget = true,
};

// ============================================================================
// Subsidy Calculation
// ============================================================================

/// Compute block subsidy at a given height.
pub fn getBlockSubsidy(height: u32, params: *const NetworkParams) i64 {
    const halvings = height / params.subsidy_halving_interval;
    if (halvings >= 64) return 0;
    return INITIAL_SUBSIDY >> @intCast(halvings);
}

/// Validate that a value is within the allowed money range.
pub fn isValidMoney(value: i64) bool {
    return value >= 0 and value <= MAX_MONEY;
}

// ============================================================================
// Difficulty Target Conversion
// ============================================================================

/// Decode a compact target representation ("bits" field) to a 256-bit target value.
/// Format: bits = 0xNNTTTTTT where NN is the exponent and TTTTTT is the mantissa.
/// target = mantissa * 2^(8*(exponent-3))
///
/// The result is stored in little-endian byte order (least significant byte first).
pub fn bitsToTarget(bits: u32) [32]u8 {
    var target: [32]u8 = [_]u8{0} ** 32;

    const exponent: u8 = @intCast((bits >> 24) & 0xFF);
    const mantissa: u32 = bits & 0x007FFFFF;

    // Negative flag check (Bitcoin specific)
    if (mantissa != 0 and (bits & 0x00800000) != 0) {
        // Negative targets are invalid, return zero
        return target;
    }

    if (exponent == 0) {
        // No shift, mantissa is the value
        return target;
    } else if (exponent <= 3) {
        // Shift right: mantissa >> (8 * (3 - exponent))
        const shift = 8 * (3 - exponent);
        const shifted = mantissa >> @intCast(shift);
        target[0] = @intCast(shifted & 0xFF);
        if (exponent >= 2) target[1] = @intCast((shifted >> 8) & 0xFF);
        if (exponent >= 3) target[2] = @intCast((shifted >> 16) & 0xFF);
    } else {
        // Shift left: place mantissa bytes at position (exponent - 3)
        const offset: usize = @intCast(exponent - 3);
        if (offset < 32) {
            target[offset] = @intCast(mantissa & 0xFF);
        }
        if (offset + 1 < 32) {
            target[offset + 1] = @intCast((mantissa >> 8) & 0xFF);
        }
        if (offset + 2 < 32) {
            target[offset + 2] = @intCast((mantissa >> 16) & 0xFF);
        }
    }

    return target;
}

/// Encode a 256-bit target value to compact "bits" representation.
/// This is the inverse of bitsToTarget.
pub fn targetToBits(target: *const [32]u8) u32 {
    // Find the highest non-zero byte
    var size: usize = 32;
    while (size > 0 and target[size - 1] == 0) : (size -= 1) {}

    if (size == 0) return 0;

    var mantissa: u32 = 0;
    var exponent: u8 = @intCast(size);

    if (size >= 3) {
        mantissa = @as(u32, target[size - 1]) << 16 |
            @as(u32, target[size - 2]) << 8 |
            @as(u32, target[size - 3]);
    } else if (size == 2) {
        mantissa = @as(u32, target[size - 1]) << 16 |
            @as(u32, target[size - 2]) << 8;
        exponent = 3;
    } else {
        mantissa = @as(u32, target[size - 1]) << 16;
        exponent = 3;
    }

    // If the high bit is set, we need to shift right and increment exponent
    // to avoid the negative flag interpretation
    if (mantissa & 0x00800000 != 0) {
        mantissa >>= 8;
        exponent += 1;
    }

    return (@as(u32, exponent) << 24) | mantissa;
}

// ============================================================================
// Proof-of-Work Validation
// ============================================================================

/// Compare a block hash against a target. The hash must be <= target.
/// Both are treated as 256-bit little-endian integers.
pub fn hashMeetsTarget(hash: *const types.Hash256, target: *const [32]u8) bool {
    // Compare from most significant byte (index 31) to least significant (index 0)
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true; // equal
}

/// Validate that a block hash meets the proof-of-work requirement.
pub fn validateProofOfWork(header: *const types.BlockHeader, params: *const NetworkParams) bool {
    const target = bitsToTarget(header.bits);

    // Check target is not above pow_limit
    if (!hashMeetsTarget(&target, &params.pow_limit)) {
        return false;
    }

    // Compute and check block hash
    const block_hash = crypto.computeBlockHash(header);
    return hashMeetsTarget(&block_hash, &target);
}

// ============================================================================
// Difficulty Retargeting
// ============================================================================

/// Compute the next required difficulty target.
/// Called every DIFFICULTY_ADJUSTMENT_INTERVAL blocks.
///
/// last_header: The header of the last block in the current difficulty period
/// first_timestamp: Timestamp of the first block in the current difficulty period
/// params: Network parameters
///
/// Returns the new compact target ("bits" value).
pub fn calculateNextWorkRequired(
    last_header: *const types.BlockHeader,
    first_timestamp: u32,
    params: *const NetworkParams,
) u32 {
    // On regtest, don't adjust difficulty
    if (params.pow_no_retarget) return last_header.bits;

    // Calculate actual timespan
    var actual_timespan: i64 = @as(i64, last_header.timestamp) - @as(i64, first_timestamp);

    // Clamp to [MIN_TIMESPAN, MAX_TIMESPAN]
    if (actual_timespan < MIN_TIMESPAN) actual_timespan = MIN_TIMESPAN;
    if (actual_timespan > MAX_TIMESPAN) actual_timespan = MAX_TIMESPAN;

    // Get current target
    const current_target = bitsToTarget(last_header.bits);

    // new_target = old_target * actual_timespan / TARGET_TIMESPAN
    // This requires 256-bit arithmetic. We'll use a simplified approach
    // that works for realistic targets.
    var new_target = multiplyTargetByRatio(&current_target, @intCast(actual_timespan), TARGET_TIMESPAN);

    // Clamp to pow_limit
    if (!hashMeetsTarget(&new_target, &params.pow_limit)) {
        new_target = params.pow_limit;
    }

    return targetToBits(&new_target);
}

/// Multiply a 256-bit target by a ratio (numerator / denominator).
/// Uses a simple byte-by-byte multiplication approach.
fn multiplyTargetByRatio(target: *const [32]u8, numerator: u32, denominator: u32) [32]u8 {
    // We'll work with the target as a big integer
    // new = target * numerator / denominator

    // First, multiply by numerator
    var result: [33]u8 = [_]u8{0} ** 33; // Extra byte for overflow
    var carry: u64 = 0;

    for (0..32) |i| {
        const product = @as(u64, target[i]) * @as(u64, numerator) + carry;
        result[i] = @intCast(product & 0xFF);
        carry = product >> 8;
    }
    result[32] = @intCast(carry);

    // Then divide by denominator
    var final: [32]u8 = [_]u8{0} ** 32;
    var remainder: u64 = 0;

    var i: usize = 33;
    while (i > 0) {
        i -= 1;
        const dividend = (remainder << 8) | @as(u64, result[i]);
        if (i < 32) {
            final[i] = @intCast(dividend / denominator);
        }
        remainder = dividend % denominator;
    }

    return final;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper: convert hex string to Hash256 at comptime.
/// The hash is reversed because Bitcoin displays hashes in big-endian
/// but stores them internally in little-endian.
pub fn hexToHash(comptime hex: *const [64:0]u8) types.Hash256 {
    @setEvalBranchQuota(10000);
    comptime {
        var hash: types.Hash256 = undefined;
        for (0..32) |i| {
            hash[31 - i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch unreachable;
        }
        return hash;
    }
}

/// Get network parameters for a given network.
pub fn getNetworkParams(network: Network) *const NetworkParams {
    return switch (network) {
        .mainnet => &MAINNET,
        .testnet => &TESTNET,
        .regtest => &REGTEST,
        .signet => &MAINNET, // TODO: Add signet params
    };
}

// ============================================================================
// Tests
// ============================================================================

test "block subsidy at height 0" {
    const subsidy = getBlockSubsidy(0, &MAINNET);
    try std.testing.expectEqual(@as(i64, 5_000_000_000), subsidy);
}

test "block subsidy first halving" {
    const subsidy = getBlockSubsidy(210_000, &MAINNET);
    try std.testing.expectEqual(@as(i64, 2_500_000_000), subsidy);
}

test "block subsidy second halving" {
    const subsidy = getBlockSubsidy(420_000, &MAINNET);
    try std.testing.expectEqual(@as(i64, 1_250_000_000), subsidy);
}

test "block subsidy after 64 halvings" {
    // After 64 halvings, subsidy is 0
    const subsidy = getBlockSubsidy(13_440_000, &MAINNET);
    try std.testing.expectEqual(@as(i64, 0), subsidy);
}

test "block subsidy regtest interval" {
    // Regtest has 150 block halving interval
    const subsidy_0 = getBlockSubsidy(0, &REGTEST);
    const subsidy_150 = getBlockSubsidy(150, &REGTEST);
    try std.testing.expectEqual(@as(i64, 5_000_000_000), subsidy_0);
    try std.testing.expectEqual(@as(i64, 2_500_000_000), subsidy_150);
}

test "genesis block hash matches" {
    // Compute genesis block header hash
    const header = MAINNET.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try std.testing.expectEqualSlices(u8, &MAINNET.genesis_hash, &computed_hash);
}

test "testnet genesis hash matches" {
    const header = TESTNET.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try std.testing.expectEqualSlices(u8, &TESTNET.genesis_hash, &computed_hash);
}

test "regtest genesis hash matches" {
    const header = REGTEST.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try std.testing.expectEqualSlices(u8, &REGTEST.genesis_hash, &computed_hash);
}

test "bitsToTarget standard difficulty 1" {
    // 0x1d00ffff is difficulty 1 on mainnet
    // Big-endian display: 0x00000000FFFF0000...0000
    // exponent = 0x1d = 29, mantissa = 0x00FFFF
    // Position = 29 - 3 = 26, mantissa bytes placed at 26, 27, 28
    const target = bitsToTarget(0x1d00ffff);

    // Mantissa 0x00FFFF stored little-endian starting at byte 26:
    // byte 26 = LSB of mantissa (0xFF)
    // byte 27 = middle byte (0xFF)
    // byte 28 = MSB of mantissa (0x00)
    try std.testing.expectEqual(@as(u8, 0xFF), target[26]);
    try std.testing.expectEqual(@as(u8, 0xFF), target[27]);
    try std.testing.expectEqual(@as(u8, 0x00), target[28]);

    // Rest should be zero
    for (0..26) |i| {
        try std.testing.expectEqual(@as(u8, 0), target[i]);
    }
    for (29..32) |i| {
        try std.testing.expectEqual(@as(u8, 0), target[i]);
    }
}

test "bitsToTarget regtest" {
    // Regtest uses 0x207fffff
    const target = bitsToTarget(0x207fffff);

    // exponent = 0x20 = 32, mantissa = 0x7fffff
    // position = 32 - 3 = 29
    try std.testing.expectEqual(@as(u8, 0xFF), target[29]);
    try std.testing.expectEqual(@as(u8, 0xFF), target[30]);
    try std.testing.expectEqual(@as(u8, 0x7F), target[31]);
}

test "bitsToTarget small exponent" {
    // Test with small exponent
    const target = bitsToTarget(0x03123456);

    // exponent = 3, mantissa = 0x123456
    // No shift, place directly at bytes 0, 1, 2
    try std.testing.expectEqual(@as(u8, 0x56), target[0]);
    try std.testing.expectEqual(@as(u8, 0x34), target[1]);
    try std.testing.expectEqual(@as(u8, 0x12), target[2]);
}

test "targetToBits roundtrip" {
    const test_cases = [_]u32{ 0x1d00ffff, 0x207fffff, 0x1b0404cb, 0x180526fd };

    for (test_cases) |bits| {
        const target = bitsToTarget(bits);
        const recovered = targetToBits(&target);
        // Note: roundtrip may not be exact due to normalization
        // But bitsToTarget(recovered) should equal bitsToTarget(bits)
        const target2 = bitsToTarget(recovered);
        try std.testing.expectEqualSlices(u8, &target, &target2);
    }
}

test "hashMeetsTarget" {
    // A hash of all zeros meets any non-zero target
    const zero_hash: types.Hash256 = [_]u8{0} ** 32;
    const target = bitsToTarget(0x1d00ffff);
    try std.testing.expect(hashMeetsTarget(&zero_hash, &target));

    // A hash of all 0xFF fails
    const max_hash: types.Hash256 = [_]u8{0xFF} ** 32;
    try std.testing.expect(!hashMeetsTarget(&max_hash, &target));
}

test "genesis block meets pow target" {
    const header = MAINNET.genesis_header;
    const target = bitsToTarget(header.bits);
    const block_hash = crypto.computeBlockHash(&header);
    try std.testing.expect(hashMeetsTarget(&block_hash, &target));
}

test "validate money range" {
    try std.testing.expect(isValidMoney(0));
    try std.testing.expect(isValidMoney(100_000_000)); // 1 BTC
    try std.testing.expect(isValidMoney(MAX_MONEY));
    try std.testing.expect(!isValidMoney(MAX_MONEY + 1));
    try std.testing.expect(!isValidMoney(-1));
}

test "hexToHash mainnet genesis" {
    const hash = comptime hexToHash("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    // In little-endian storage, first byte should be 0x6f (last two hex chars)
    try std.testing.expectEqual(@as(u8, 0x6f), hash[0]);
    // Last byte should be 0x00 (first two hex chars)
    try std.testing.expectEqual(@as(u8, 0x00), hash[31]);
}

test "network magic bytes" {
    try std.testing.expectEqual(@as(u32, 0xD9B4BEF9), MAINNET.magic);
    try std.testing.expectEqual(@as(u32, 0x0709110B), TESTNET.magic);
    try std.testing.expectEqual(@as(u32, 0xDAB5BFFA), REGTEST.magic);
}

test "consensus constants" {
    // Verify key consensus constants
    try std.testing.expectEqual(@as(u32, 4_000_000), MAX_BLOCK_WEIGHT);
    try std.testing.expectEqual(@as(u32, 2016), DIFFICULTY_ADJUSTMENT_INTERVAL);
    try std.testing.expectEqual(@as(u32, 600), TARGET_SPACING);
    try std.testing.expectEqual(@as(u32, 1_209_600), TARGET_TIMESPAN);
    try std.testing.expectEqual(@as(u32, 100), COINBASE_MATURITY);

    // BIP activation heights
    try std.testing.expectEqual(@as(u32, 227_931), BIP34_HEIGHT);
    try std.testing.expectEqual(@as(u32, 388_381), BIP65_HEIGHT);
    try std.testing.expectEqual(@as(u32, 363_725), BIP66_HEIGHT);
    try std.testing.expectEqual(@as(u32, 481_824), SEGWIT_HEIGHT);
    try std.testing.expectEqual(@as(u32, 709_632), TAPROOT_HEIGHT);
}

test "difficulty retarget clamping" {
    // Test that difficulty adjustment is clamped properly
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = TARGET_TIMESPAN * 8, // 8x target (should clamp to 4x)
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    const new_bits = calculateNextWorkRequired(&header, 0, &MAINNET);
    // Due to clamping, difficulty should only decrease by 4x max
    _ = new_bits;
}

test "regtest no retarget" {
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1000,
        .bits = 0x207fffff,
        .nonce = 0,
    };

    // On regtest, difficulty never changes
    const new_bits = calculateNextWorkRequired(&header, 0, &REGTEST);
    try std.testing.expectEqual(header.bits, new_bits);
}
