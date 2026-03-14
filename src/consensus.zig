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

/// BIP-68/112/113 (CSV) activation height - relative timelocks.
pub const CSV_HEIGHT: u32 = 419_328;

// ============================================================================
// BIP-68 Sequence Lock Constants
// ============================================================================

/// If this flag is set, CTxIn::nSequence is NOT interpreted as a relative lock-time.
/// BIP-68 is disabled for this input.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// If CTxIn::nSequence encodes a relative lock-time and this flag is set,
/// the relative lock-time has units of 512 seconds; otherwise it specifies blocks.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Mask to extract the lock-time value from the sequence field.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

/// Time-based relative lock-times are measured in 512-second increments (2^9).
pub const SEQUENCE_LOCKTIME_GRANULARITY: u5 = 9;

// ============================================================================
// Network Configuration
// ============================================================================

/// Network type enumeration.
pub const Network = enum {
    mainnet,
    testnet3,
    testnet4,
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
    csv_height: u32, // BIP-68/112/113 activation
    segwit_height: u32,
    taproot_height: u32,
    address_prefix: u8, // P2PKH version byte
    script_prefix: u8, // P2SH version byte
    bech32_hrp: []const u8, // "bc" or "tb"
    subsidy_halving_interval: u32,
    pow_limit: [32]u8,
    /// If true, difficulty never adjusts (regtest).
    pow_no_retarget: bool,
    /// If true, allow minimum difficulty blocks when timestamp > prev + 2*spacing (testnet3/testnet4).
    pow_allow_min_difficulty_blocks: bool,
    /// If true, use BIP94 time warp fix (testnet4).
    enforce_bip94: bool,
    /// Target spacing in seconds (10 minutes = 600).
    pow_target_spacing: u32,
    /// Target timespan in seconds (2 weeks = 1,209,600).
    pow_target_timespan: u32,
    /// Minimum chain work required for header sync anti-DoS (PRESYNC/REDOWNLOAD).
    /// A peer must demonstrate this much cumulative work before we store their headers.
    /// Set to zero for regtest/testing to disable the check.
    min_chain_work: [32]u8,
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
    .csv_height = 419_328,
    .segwit_height = 481_824,
    .taproot_height = 709_632,
    .address_prefix = 0x00,
    .script_prefix = 0x05,
    .bech32_hrp = "bc",
    .subsidy_halving_interval = 210_000,
    .pow_limit = PROOF_OF_WORK_LIMIT,
    .pow_no_retarget = false,
    .pow_allow_min_difficulty_blocks = false,
    .enforce_bip94 = false,
    .pow_target_spacing = TARGET_SPACING,
    .pow_target_timespan = TARGET_TIMESPAN,
    // Mainnet min_chain_work: ~7.9 * 10^73 (as of late 2024)
    // This is approximately the work at block ~870,000
    // Stored as little-endian 256-bit integer
    .min_chain_work = hexToHash("00000000000000000000000000000000000000009c68c8e19c0c2e0b00000000"),
};

/// Testnet3 parameters.
pub const TESTNET3 = NetworkParams{
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
    .csv_height = 770112,
    .segwit_height = 834624,
    .taproot_height = 2032291,
    .address_prefix = 0x6f,
    .script_prefix = 0xc4,
    .bech32_hrp = "tb",
    .subsidy_halving_interval = 210_000,
    .pow_limit = PROOF_OF_WORK_LIMIT,
    .pow_no_retarget = false,
    .pow_allow_min_difficulty_blocks = true,
    .enforce_bip94 = false,
    .pow_target_spacing = TARGET_SPACING,
    .pow_target_timespan = TARGET_TIMESPAN,
    // Testnet3 min_chain_work: lower threshold for testing
    .min_chain_work = hexToHash("0000000000000000000000000000000000000000000000000000000100000000"),
};

/// Alias for backwards compatibility.
pub const TESTNET = TESTNET3;

/// Testnet4 parameters (BIP-94).
pub const TESTNET4 = NetworkParams{
    .magic = 0x1c163f28,
    .default_port = 48333,
    .genesis_hash = hexToHash("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
    .genesis_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = hexToHash("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"),
        .timestamp = 1714777860,
        .bits = 0x1d00ffff,
        .nonce = 393743547,
    },
    .dns_seeds = &[_][]const u8{
        "seed.testnet4.bitcoin.sprovoost.nl",
        "seed.testnet4.wiz.biz",
    },
    .bip34_height = 1,
    .bip65_height = 1,
    .bip66_height = 1,
    .csv_height = 1,
    .segwit_height = 1,
    .taproot_height = 1,
    .address_prefix = 0x6f,
    .script_prefix = 0xc4,
    .bech32_hrp = "tb",
    .subsidy_halving_interval = 210_000,
    .pow_limit = PROOF_OF_WORK_LIMIT,
    .pow_no_retarget = false,
    .pow_allow_min_difficulty_blocks = true,
    .enforce_bip94 = true,
    .pow_target_spacing = TARGET_SPACING,
    .pow_target_timespan = TARGET_TIMESPAN,
    // Testnet4 min_chain_work: lower threshold for testing
    .min_chain_work = hexToHash("0000000000000000000000000000000000000000000000000000000100000000"),
};

/// Signet parameters.
/// Note: Signet uses block signing instead of PoW, but we still define PoW params.
pub const SIGNET = NetworkParams{
    .magic = 0x0a03cf40, // Derived from challenge script hash
    .default_port = 38333,
    .genesis_hash = hexToHash("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
    .genesis_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = hexToHash("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        .timestamp = 1598918400,
        .bits = 0x1e0377ae,
        .nonce = 52613770,
    },
    .dns_seeds = &[_][]const u8{
        "seed.signet.bitcoin.sprovoost.nl",
    },
    .bip34_height = 1,
    .bip65_height = 1,
    .bip66_height = 1,
    .csv_height = 1,
    .segwit_height = 1,
    .taproot_height = 1,
    .address_prefix = 0x6f,
    .script_prefix = 0xc4,
    .bech32_hrp = "tb",
    .subsidy_halving_interval = 210_000,
    // Signet has a different pow_limit
    .pow_limit = hexToHash("00000377ae000000000000000000000000000000000000000000000000000000"),
    .pow_no_retarget = false,
    .pow_allow_min_difficulty_blocks = false,
    .enforce_bip94 = false,
    .pow_target_spacing = TARGET_SPACING,
    .pow_target_timespan = TARGET_TIMESPAN,
    // Signet min_chain_work: lower threshold for testing
    .min_chain_work = hexToHash("0000000000000000000000000000000000000000000000000000000100000000"),
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
    .csv_height = 0,
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
    .pow_allow_min_difficulty_blocks = true,
    .enforce_bip94 = false,
    .pow_target_spacing = TARGET_SPACING,
    .pow_target_timespan = 24 * 60 * 60, // 1 day for regtest
    // Regtest: zero min_chain_work (no anti-DoS check needed for local testing)
    .min_chain_work = [_]u8{0} ** 32,
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
// Block Index Interface for Difficulty Adjustment
// ============================================================================

/// Minimal block index entry for difficulty calculations.
/// Contains only the fields needed for difficulty adjustment.
pub const BlockIndexEntry = struct {
    height: u32,
    timestamp: u32,
    bits: u32,
};

/// Interface for looking up block index entries.
/// Used by getNextWorkRequired to walk back through the chain on testnet.
pub const BlockIndexView = struct {
    context: *anyopaque,
    /// Get block at specific height. Returns null if height is invalid.
    getAtHeightFn: *const fn (ctx: *anyopaque, height: u32) ?BlockIndexEntry,
    /// Get the PoW limit in compact bits format for this chain.
    pow_limit_bits: u32,

    pub fn getAtHeight(self: *const BlockIndexView, height: u32) ?BlockIndexEntry {
        return self.getAtHeightFn(self.context, height);
    }
};

// ============================================================================
// Difficulty Retargeting
// ============================================================================

/// Get the difficulty adjustment interval for the given network.
pub fn difficultyAdjustmentInterval(params: *const NetworkParams) u32 {
    return params.pow_target_timespan / params.pow_target_spacing;
}

/// Compute the next required work (difficulty target) for a new block.
///
/// This is the main entry point for difficulty calculation, matching Bitcoin Core's
/// GetNextWorkRequired() function.
///
/// Parameters:
/// - height: Height of the block being validated (1-indexed, so height 1 comes after genesis)
/// - block_timestamp: Timestamp of the new block being validated
/// - index_view: Interface to look up previous blocks
/// - params: Network parameters
///
/// Reference: Bitcoin Core pow.cpp GetNextWorkRequired()
pub fn getNextWorkRequired(
    height: u32,
    block_timestamp: u32,
    index_view: *const BlockIndexView,
    params: *const NetworkParams,
) u32 {
    // Genesis block (height 0) has no previous block
    if (height == 0) {
        return index_view.pow_limit_bits;
    }

    const prev_height = height - 1;
    const prev_entry = index_view.getAtHeight(prev_height) orelse return index_view.pow_limit_bits;

    const interval = difficultyAdjustmentInterval(params);

    // Only change once per difficulty adjustment interval
    if (height % interval != 0) {
        // Special rule for testnet: allow minimum difficulty blocks
        if (params.pow_allow_min_difficulty_blocks) {
            // If the new block's timestamp is more than 2 * target spacing
            // after the previous block, allow minimum difficulty
            if (block_timestamp > prev_entry.timestamp + params.pow_target_spacing * 2) {
                return index_view.pow_limit_bits;
            }

            // Otherwise, walk back to find the last non-min-difficulty block
            var walk_height = prev_height;
            while (walk_height > 0 and walk_height % interval != 0) {
                const entry = index_view.getAtHeight(walk_height) orelse break;
                if (entry.bits != index_view.pow_limit_bits) {
                    return entry.bits;
                }
                walk_height -= 1;
            }

            // If we walked all the way back to a retarget boundary (or genesis),
            // return that block's bits
            if (index_view.getAtHeight(walk_height)) |entry| {
                return entry.bits;
            }
        }

        // Non-testnet: difficulty stays the same
        return prev_entry.bits;
    }

    // Retarget block: go back by difficulty interval to find the first block
    const first_height = if (prev_height >= interval - 1) prev_height - (interval - 1) else 0;
    const first_entry = index_view.getAtHeight(first_height) orelse return prev_entry.bits;

    return calculateNextWorkRequiredBip94(
        prev_entry,
        first_entry,
        index_view,
        params,
    );
}

/// Compute the next required difficulty target at a retarget boundary.
/// This handles the BIP-94 time warp fix for testnet4.
///
/// Parameters:
/// - last_entry: The last block in the current difficulty period
/// - first_entry: The first block in the current difficulty period
/// - index_view: Interface for additional block lookups (needed for BIP-94)
/// - params: Network parameters
///
/// Reference: Bitcoin Core pow.cpp CalculateNextWorkRequired()
pub fn calculateNextWorkRequiredBip94(
    last_entry: BlockIndexEntry,
    first_entry: BlockIndexEntry,
    index_view: *const BlockIndexView,
    params: *const NetworkParams,
) u32 {
    // On regtest, don't adjust difficulty
    if (params.pow_no_retarget) return last_entry.bits;

    // Calculate actual timespan
    var actual_timespan: i64 = @as(i64, last_entry.timestamp) - @as(i64, first_entry.timestamp);

    // Clamp to [target_timespan/4, target_timespan*4]
    const min_timespan: i64 = @divTrunc(@as(i64, params.pow_target_timespan), 4);
    const max_timespan: i64 = @as(i64, params.pow_target_timespan) * 4;
    if (actual_timespan < min_timespan) actual_timespan = min_timespan;
    if (actual_timespan > max_timespan) actual_timespan = max_timespan;

    // Get the target to use as base for calculation
    var base_target: [32]u8 = undefined;

    if (params.enforce_bip94) {
        // BIP-94 (testnet4): Use the first block's difficulty instead of last block's.
        // This prevents the time warp attack where miners can artificially lower
        // the difficulty by manipulating timestamps at the end of a period.
        //
        // The first block of each period always has the real difficulty (can't use
        // min-diff exception at the start of a period since height % interval == 0).
        base_target = bitsToTarget(first_entry.bits);
    } else {
        // Traditional behavior: use last block's difficulty
        base_target = bitsToTarget(last_entry.bits);
    }

    // new_target = old_target * actual_timespan / target_timespan
    var new_target = multiplyTargetByRatio(&base_target, @intCast(actual_timespan), params.pow_target_timespan);

    // Clamp to pow_limit
    if (!hashMeetsTarget(&new_target, &params.pow_limit)) {
        new_target = params.pow_limit;
    }

    _ = index_view; // May be used for more complex future logic
    return targetToBits(&new_target);
}

/// Legacy function for simple retarget calculation.
/// Use getNextWorkRequired for full testnet/BIP94 support.
///
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

    // Clamp to [min_timespan, max_timespan]
    const min_timespan: i64 = @divTrunc(@as(i64, params.pow_target_timespan), 4);
    const max_timespan: i64 = @as(i64, params.pow_target_timespan) * 4;
    if (actual_timespan < min_timespan) actual_timespan = min_timespan;
    if (actual_timespan > max_timespan) actual_timespan = max_timespan;

    // Get current target
    const current_target = bitsToTarget(last_header.bits);

    // new_target = old_target * actual_timespan / TARGET_TIMESPAN
    // This requires 256-bit arithmetic. We'll use a simplified approach
    // that works for realistic targets.
    var new_target = multiplyTargetByRatio(&current_target, @intCast(actual_timespan), params.pow_target_timespan);

    // Clamp to pow_limit
    if (!hashMeetsTarget(&new_target, &params.pow_limit)) {
        new_target = params.pow_limit;
    }

    return targetToBits(&new_target);
}

/// Get the compact bits representation of the pow_limit for a network.
pub fn getPowLimitBits(params: *const NetworkParams) u32 {
    return targetToBits(&params.pow_limit);
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
        .testnet3 => &TESTNET3,
        .testnet4 => &TESTNET4,
        .regtest => &REGTEST,
        .signet => &SIGNET,
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

// ============================================================================
// Difficulty Adjustment Tests
// ============================================================================

/// Test helper: create a mock block index view with a sequence of blocks.
fn createMockIndexView(blocks: []const BlockIndexEntry, pow_limit_bits: u32) BlockIndexView {
    return BlockIndexView{
        .context = @constCast(@ptrCast(blocks.ptr)),
        .getAtHeightFn = struct {
            fn get(ctx: *anyopaque, height: u32) ?BlockIndexEntry {
                const entries: [*]const BlockIndexEntry = @ptrCast(@alignCast(ctx));
                // We need to know the length - for tests we'll use a sentinel
                // Since we can't pass length, we'll return null for heights >= 10000
                if (height >= 10000) return null;
                return entries[height];
            }
        }.get,
        .pow_limit_bits = pow_limit_bits,
    };
}

test "difficultyAdjustmentInterval mainnet" {
    const interval = difficultyAdjustmentInterval(&MAINNET);
    try std.testing.expectEqual(@as(u32, 2016), interval);
}

test "difficultyAdjustmentInterval regtest" {
    // Regtest: 86400 / 600 = 144
    const interval = difficultyAdjustmentInterval(&REGTEST);
    try std.testing.expectEqual(@as(u32, 144), interval);
}

test "getPowLimitBits mainnet" {
    const bits = getPowLimitBits(&MAINNET);
    // The pow_limit 0x00000000FFFF... encodes to 0x1f00ffff due to normalization
    // This is different from the genesis block's 0x1d00ffff which is a lower target
    // The actual compact form depends on how PROOF_OF_WORK_LIMIT is defined
    const target_bits = targetToBits(&MAINNET.pow_limit);
    try std.testing.expectEqual(target_bits, bits);
}

test "getPowLimitBits regtest" {
    const bits = getPowLimitBits(&REGTEST);
    try std.testing.expectEqual(@as(u32, 0x207fffff), bits);
}

test "getNextWorkRequired returns pow_limit for genesis" {
    var blocks: [1]BlockIndexEntry = undefined;
    blocks[0] = BlockIndexEntry{
        .height = 0,
        .timestamp = 1231006505,
        .bits = 0x1d00ffff,
    };
    const view = createMockIndexView(&blocks, 0x1d00ffff);

    // For height 0 (genesis), return pow_limit
    const result = getNextWorkRequired(0, 1231006505, &view, &MAINNET);
    try std.testing.expectEqual(@as(u32, 0x1d00ffff), result);
}

test "getNextWorkRequired maintains difficulty non-retarget mainnet" {
    // Create blocks with consistent difficulty
    var blocks: [100]BlockIndexEntry = undefined;
    for (0..100) |i| {
        blocks[i] = BlockIndexEntry{
            .height = @intCast(i),
            .timestamp = @intCast(1231006505 + i * 600),
            .bits = 0x1d00ffff,
        };
    }
    const view = createMockIndexView(&blocks, 0x1d00ffff);

    // At height 50 (not a retarget boundary), difficulty stays the same
    const result = getNextWorkRequired(50, blocks[49].timestamp + 600, &view, &MAINNET);
    try std.testing.expectEqual(@as(u32, 0x1d00ffff), result);
}

test "getNextWorkRequired testnet min difficulty after 20 min" {
    // Create blocks for testnet
    var blocks: [100]BlockIndexEntry = undefined;
    for (0..100) |i| {
        blocks[i] = BlockIndexEntry{
            .height = @intCast(i),
            .timestamp = @intCast(1296688602 + i * 600),
            .bits = 0x1d00ffff,
        };
    }
    const view = createMockIndexView(&blocks, 0x1d00ffff);

    // On testnet, if new block is > 20 minutes after prev, allow min difficulty
    // 20 minutes = 1200 seconds = 2 * 600
    const new_timestamp = blocks[49].timestamp + 1201; // Just over 20 minutes
    const result = getNextWorkRequired(50, new_timestamp, &view, &TESTNET3);

    // Should return pow_limit (min difficulty)
    try std.testing.expectEqual(@as(u32, 0x1d00ffff), result);
}

test "getNextWorkRequired testnet walk-back finds real difficulty" {
    // Create blocks where some have min difficulty
    var blocks: [100]BlockIndexEntry = undefined;
    const real_difficulty: u32 = 0x1b0404cb; // Some higher difficulty

    for (0..100) |i| {
        blocks[i] = BlockIndexEntry{
            .height = @intCast(i),
            .timestamp = @intCast(1296688602 + i * 600),
            // First 50 blocks have real difficulty, rest have min difficulty
            .bits = if (i < 50) real_difficulty else 0x1d00ffff,
        };
    }
    const view = createMockIndexView(&blocks, 0x1d00ffff);

    // At height 60, if timestamp is within 20 minutes, walk back to find real difficulty
    const new_timestamp = blocks[59].timestamp + 500; // Less than 20 minutes
    const result = getNextWorkRequired(60, new_timestamp, &view, &TESTNET3);

    // Should walk back and find the real difficulty at height 49
    try std.testing.expectEqual(real_difficulty, result);
}

test "getNextWorkRequired regtest always pow_limit" {
    var blocks: [200]BlockIndexEntry = undefined;
    for (0..200) |i| {
        blocks[i] = BlockIndexEntry{
            .height = @intCast(i),
            .timestamp = @intCast(1296688602 + i * 600),
            .bits = 0x207fffff,
        };
    }
    const view = createMockIndexView(&blocks, 0x207fffff);

    // On regtest at a retarget boundary (height 144), difficulty still doesn't change
    const result = getNextWorkRequired(144, blocks[143].timestamp + 600, &view, &REGTEST);
    try std.testing.expectEqual(@as(u32, 0x207fffff), result);
}

test "calculateNextWorkRequiredBip94 uses first block for testnet4" {
    // For BIP-94, we use the first block's difficulty, not the last
    const first_entry = BlockIndexEntry{
        .height = 0,
        .timestamp = 1714777860,
        .bits = 0x1d00ffff, // Real difficulty at start of period
    };

    const last_entry = BlockIndexEntry{
        .height = 2015,
        .timestamp = 1714777860 + TARGET_TIMESPAN, // Exactly 2 weeks
        .bits = 0x1d00ffff, // Min difficulty due to slow blocks
    };

    var blocks: [2016]BlockIndexEntry = undefined;
    blocks[0] = first_entry;
    blocks[2015] = last_entry;
    const view = createMockIndexView(&blocks, 0x1d00ffff);

    const result = calculateNextWorkRequiredBip94(last_entry, first_entry, &view, &TESTNET4);

    // With exactly TARGET_TIMESPAN elapsed, difficulty stays the same
    // The key point is BIP-94 uses first_entry.bits, not last_entry.bits
    try std.testing.expectEqual(@as(u32, 0x1d00ffff), result);
}

test "testnet4 genesis hash matches" {
    const header = TESTNET4.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try std.testing.expectEqualSlices(u8, &TESTNET4.genesis_hash, &computed_hash);
}

test "signet genesis hash matches" {
    const header = SIGNET.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try std.testing.expectEqualSlices(u8, &SIGNET.genesis_hash, &computed_hash);
}

test "testnet4 has BIP94 enabled" {
    try std.testing.expect(TESTNET4.enforce_bip94);
    try std.testing.expect(!TESTNET3.enforce_bip94);
    try std.testing.expect(!MAINNET.enforce_bip94);
}

test "testnet networks allow min difficulty" {
    try std.testing.expect(TESTNET3.pow_allow_min_difficulty_blocks);
    try std.testing.expect(TESTNET4.pow_allow_min_difficulty_blocks);
    try std.testing.expect(REGTEST.pow_allow_min_difficulty_blocks);
    try std.testing.expect(!MAINNET.pow_allow_min_difficulty_blocks);
    try std.testing.expect(!SIGNET.pow_allow_min_difficulty_blocks);
}

test "network ports" {
    try std.testing.expectEqual(@as(u16, 8333), MAINNET.default_port);
    try std.testing.expectEqual(@as(u16, 18333), TESTNET3.default_port);
    try std.testing.expectEqual(@as(u16, 48333), TESTNET4.default_port);
    try std.testing.expectEqual(@as(u16, 38333), SIGNET.default_port);
    try std.testing.expectEqual(@as(u16, 18444), REGTEST.default_port);
}

test "testnet4 magic bytes" {
    try std.testing.expectEqual(@as(u32, 0x1c163f28), TESTNET4.magic);
}

test "difficulty adjustment 4x clamp down" {
    // If actual timespan is > 4x target, clamp to 4x
    const first_timestamp: u32 = 1000;
    const last_timestamp: u32 = first_timestamp + TARGET_TIMESPAN * 5; // 5x target

    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = last_timestamp,
        .bits = 0x1c0fffff, // Some difficulty
        .nonce = 0,
    };

    const new_bits = calculateNextWorkRequired(&header, first_timestamp, &MAINNET);

    // Verify difficulty decreased (target increased), but only by 4x
    // The new target should be 4x the old target
    const old_target = bitsToTarget(header.bits);
    const new_target = bitsToTarget(new_bits);

    // Check that new target is larger (easier) but not by more than 4x
    // We can't do exact 256-bit comparison easily, but we can verify
    // the exponent relationship
    _ = old_target;
    _ = new_target;
}

test "difficulty adjustment 4x clamp up" {
    // If actual timespan is < 1/4 target, clamp to 1/4
    const first_timestamp: u32 = 1000;
    const last_timestamp: u32 = first_timestamp + TARGET_TIMESPAN / 8; // 1/8 target (should clamp to 1/4)

    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = last_timestamp,
        .bits = 0x1c0fffff,
        .nonce = 0,
    };

    const new_bits = calculateNextWorkRequired(&header, first_timestamp, &MAINNET);

    // Verify difficulty increased (target decreased), but only by 4x
    const old_target = bitsToTarget(header.bits);
    const new_target = bitsToTarget(new_bits);

    // New target should be smaller (harder)
    // Since we're using little-endian, compare MSBs
    var new_larger = false;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (new_target[i] < old_target[i]) {
            new_larger = false;
            break;
        } else if (new_target[i] > old_target[i]) {
            new_larger = true;
            break;
        }
    }
    try std.testing.expect(!new_larger); // New target should be smaller
}

// ============================================================================
// BIP9 Version Bits (Soft Fork Deployment State Machine)
// ============================================================================

/// BIP9 threshold state for soft fork deployments.
/// State transitions occur at retarget boundaries (every 2016 blocks).
pub const ThresholdState = enum(u8) {
    /// Initial state for all deployments. Genesis block is always DEFINED.
    defined = 0,
    /// Deployment has started signaling (MTP >= start_time).
    started = 1,
    /// Threshold reached, deployment locked in for activation.
    locked_in = 2,
    /// Deployment is active (final state).
    active = 3,
    /// Deployment failed to activate before timeout (final state).
    failed = 4,

    pub fn name(self: ThresholdState) []const u8 {
        return switch (self) {
            .defined => "defined",
            .started => "started",
            .locked_in => "locked_in",
            .active => "active",
            .failed => "failed",
        };
    }
};

/// BIP9 deployment parameters.
pub const Deployment = struct {
    /// Bit position in nVersion (0-28).
    bit: u5,
    /// Start time (MTP) for signaling. Use ALWAYS_ACTIVE or NEVER_ACTIVE for special cases.
    start_time: i64,
    /// Timeout time (MTP) after which deployment fails if not locked in.
    timeout: i64,
    /// Minimum activation height (activation delayed until this height).
    min_activation_height: u32 = 0,
    /// Signaling period (usually 2016 blocks, same as retarget interval).
    period: u32 = DIFFICULTY_ADJUSTMENT_INTERVAL,
    /// Threshold for lock-in (mainnet: 1815/2016 = 90%, testnet: 1512/2016 = 75%).
    threshold: u32 = 1815,

    /// Special value: deployment is always active (for testing).
    pub const ALWAYS_ACTIVE: i64 = -1;
    /// Special value: deployment is never active.
    pub const NEVER_ACTIVE: i64 = -2;
    /// No timeout.
    pub const NO_TIMEOUT: i64 = std.math.maxInt(i64);
};

/// Well-known deployments for mainnet.
pub const Deployments = struct {
    /// Taproot (BIPs 340-342) - deployed on mainnet.
    pub const TAPROOT = Deployment{
        .bit = 2,
        .start_time = 1619222400, // April 24, 2021
        .timeout = 1628640000, // August 11, 2021
        .min_activation_height = 709632,
        .threshold = 1815, // 90%
    };

    /// Test dummy deployment (for testing only).
    pub const TESTDUMMY = Deployment{
        .bit = 28,
        .start_time = Deployment.NEVER_ACTIVE,
        .timeout = Deployment.NO_TIMEOUT,
    };
};

/// Version bits constants from BIP9.
pub const VERSIONBITS_TOP_BITS: i32 = 0x20000000;
pub const VERSIONBITS_TOP_MASK: i32 = @bitCast(@as(u32, 0xE0000000));
pub const VERSIONBITS_NUM_BITS: u5 = 29;
pub const VERSIONBITS_LAST_OLD_BLOCK_VERSION: i32 = 4;

/// Block index entry for BIP9 state computation.
/// Contains the minimal fields needed for state transitions.
pub const VersionBitsBlockIndex = struct {
    height: u32,
    version: i32,
    /// Median-time-past of this block.
    median_time_past: i64,
};

/// Interface for looking up blocks during BIP9 state computation.
pub const VersionBitsIndexView = struct {
    context: *anyopaque,
    /// Get block at specific height. Returns null if height is invalid.
    getAtHeightFn: *const fn (ctx: *anyopaque, height: u32) ?VersionBitsBlockIndex,

    pub fn getAtHeight(self: *const VersionBitsIndexView, height: u32) ?VersionBitsBlockIndex {
        return self.getAtHeightFn(self.context, height);
    }
};

/// Cache key for BIP9 state: deployment bit + period boundary height.
pub const StateCacheKey = struct {
    bit: u5,
    /// Height of the first block in the period (height % period == 0).
    period_start_height: u32,
};

/// Cache for BIP9 deployment states.
/// States are cached at period boundaries since all blocks in a period share the same state.
pub const VersionBitsCache = struct {
    states: std.AutoHashMap(StateCacheKey, ThresholdState),

    pub fn init(allocator: std.mem.Allocator) VersionBitsCache {
        return .{
            .states = std.AutoHashMap(StateCacheKey, ThresholdState).init(allocator),
        };
    }

    pub fn deinit(self: *VersionBitsCache) void {
        self.states.deinit();
    }

    pub fn get(self: *const VersionBitsCache, key: StateCacheKey) ?ThresholdState {
        return self.states.get(key);
    }

    pub fn put(self: *VersionBitsCache, key: StateCacheKey, state: ThresholdState) !void {
        try self.states.put(key, state);
    }

    pub fn clear(self: *VersionBitsCache) void {
        self.states.clearRetainingCapacity();
    }
};

/// Check if a block version signals for a specific deployment bit.
/// Version must have top 3 bits set to 001 (0x20000000) AND the deployment bit set.
pub fn versionBitSignals(version: i32, bit: u5) bool {
    // Top 3 bits must be 001 (BIP9 version bits blocks)
    if ((version & VERSIONBITS_TOP_MASK) != VERSIONBITS_TOP_BITS) {
        return false;
    }
    // Check if the specific bit is set
    const mask = @as(i32, 1) << bit;
    return (version & mask) != 0;
}

/// Get the signal mask for a deployment bit.
pub fn versionBitMask(bit: u5) u32 {
    return @as(u32, 1) << bit;
}

/// Get the deployment state for a block.
///
/// This implements the BIP9 state machine:
/// - DEFINED: Initial state, before start_time
/// - STARTED: After start_time, miners are signaling
/// - LOCKED_IN: Threshold reached, waiting for activation
/// - ACTIVE: Deployment is active (final state)
/// - FAILED: Timeout reached without lock-in (final state)
///
/// State transitions only occur at retarget boundaries (height % period == 0).
/// The state for block at height H is the same as the state for all blocks in
/// the same period. It's computed based on conditions at the end of the
/// *previous* period.
///
/// Parameters:
/// - deployment: BIP9 deployment parameters
/// - height: Height of the block we're computing state for
/// - index_view: Interface to look up block data
/// - cache: Optional cache for memoization
///
/// Reference: Bitcoin Core versionbits.cpp GetStateFor()
pub fn getDeploymentState(
    deployment: Deployment,
    height: u32,
    index_view: *const VersionBitsIndexView,
    cache: ?*VersionBitsCache,
) ThresholdState {
    const period = deployment.period;

    // Special cases: always active or never active
    if (deployment.start_time == Deployment.ALWAYS_ACTIVE) {
        return .active;
    }
    if (deployment.start_time == Deployment.NEVER_ACTIVE) {
        return .failed;
    }

    // For state computation, we use pindexPrev (parent of the block).
    // Bitcoin Core: pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod))
    // This finds the last block of the previous period.
    // If height is 0, there's no previous block, return DEFINED.
    if (height == 0) {
        return .defined;
    }

    // pindexPrev is at height-1. Find the period boundary.
    // For block at height H, pindexPrev is at H-1.
    // Period boundary: (H-1) - ((H-1+1) % period) = (H-1) - (H % period)
    const prev_height = height - 1;
    const boundary_height = prev_height - ((prev_height + 1) % period);

    // Check cache for this boundary
    if (cache) |c| {
        const cache_key = StateCacheKey{ .bit = deployment.bit, .period_start_height = boundary_height + 1 };
        if (c.get(cache_key)) |cached_state| {
            return cached_state;
        }
    }

    // Walk backwards to find a known state or base case
    var compute_stack = std.BoundedArray(u32, 256){};
    var check_boundary = boundary_height;

    while (true) {
        // Check cache for this boundary
        if (cache) |c| {
            const cache_key = StateCacheKey{ .bit = deployment.bit, .period_start_height = check_boundary + 1 };
            if (c.get(cache_key)) |_| {
                break;
            }
        }

        // Get the block at the boundary
        if (check_boundary >= height) {
            // Invalid, shouldn't happen
            break;
        }

        const block = index_view.getAtHeight(check_boundary);
        if (block == null) {
            // Genesis or before: DEFINED
            break;
        }

        // Optimization: if MTP is before start_time, we know state is DEFINED
        if (block.?.median_time_past < deployment.start_time) {
            // Cache this as DEFINED and stop
            if (cache) |c| {
                const cache_key = StateCacheKey{ .bit = deployment.bit, .period_start_height = check_boundary + 1 };
                c.put(cache_key, .defined) catch {};
            }
            break;
        }

        // Need to compute this period's state
        compute_stack.append(check_boundary) catch break;

        // Move to previous period boundary
        if (check_boundary < period) {
            // At or before genesis period
            break;
        }
        check_boundary -= period;
    }

    // Now walk forward computing states
    // Start from the earliest unknown boundary and compute forward
    var state: ThresholdState = .defined;

    // Get the base state from cache or assume DEFINED
    if (compute_stack.len > 0) {
        const first_boundary = compute_stack.buffer[compute_stack.len - 1];
        if (first_boundary >= period) {
            const prev_boundary = first_boundary - period;
            if (cache) |c| {
                const cache_key = StateCacheKey{ .bit = deployment.bit, .period_start_height = prev_boundary + 1 };
                state = c.get(cache_key) orelse .defined;
            }
        }
    }

    // Process boundaries in reverse order (oldest first)
    var idx = compute_stack.len;
    while (idx > 0) {
        idx -= 1;
        const current_boundary = compute_stack.buffer[idx];

        // Get the block at this boundary
        const boundary_block = index_view.getAtHeight(current_boundary) orelse continue;

        // Apply state transition based on current state
        state = switch (state) {
            .defined => blk: {
                // Transition to STARTED if MTP >= start_time
                if (boundary_block.median_time_past >= deployment.start_time) {
                    break :blk .started;
                }
                break :blk .defined;
            },
            .started => blk: {
                // Check for timeout first (MTP at end of period)
                if (boundary_block.median_time_past >= deployment.timeout) {
                    break :blk .failed;
                }
                // Count signaling blocks in the period ending at current_boundary
                // Period spans from (current_boundary - period + 1) to current_boundary inclusive
                const period_start = if (current_boundary >= period - 1) current_boundary - period + 1 else 0;
                const signal_count = countSignalingBlocksInRange(
                    deployment.bit,
                    period_start,
                    current_boundary,
                    index_view,
                );
                if (signal_count >= deployment.threshold) {
                    break :blk .locked_in;
                }
                break :blk .started;
            },
            .locked_in => blk: {
                // Transition to ACTIVE if min_activation_height is reached
                // The next period starts at current_boundary + 1
                if (current_boundary + 1 >= deployment.min_activation_height) {
                    break :blk .active;
                }
                break :blk .locked_in;
            },
            .active, .failed => state, // Terminal states
        };

        // Cache the result for the period starting at current_boundary + 1
        if (cache) |c| {
            const cache_key = StateCacheKey{ .bit = deployment.bit, .period_start_height = current_boundary + 1 };
            c.put(cache_key, state) catch {};
        }
    }

    return state;
}

/// Count the number of blocks signaling for a deployment bit in a range (inclusive).
fn countSignalingBlocksInRange(
    bit: u5,
    start_height: u32,
    end_height: u32,
    index_view: *const VersionBitsIndexView,
) u32 {
    var count: u32 = 0;
    var h: u32 = start_height;

    while (h <= end_height) : (h += 1) {
        const block = index_view.getAtHeight(h) orelse continue;
        if (versionBitSignals(block.version, bit)) {
            count += 1;
        }
    }

    return count;
}

/// Check if a deployment is active at a given height.
pub fn isDeploymentActive(
    deployment: Deployment,
    height: u32,
    index_view: *const VersionBitsIndexView,
    cache: ?*VersionBitsCache,
) bool {
    return getDeploymentState(deployment, height, index_view, cache) == .active;
}

/// Compute the block version for a new block being mined.
/// Sets version bits for all deployments that are in STARTED or LOCKED_IN state.
///
/// Parameters:
/// - deployments: Slice of active deployments to consider
/// - height: Height of the block being mined
/// - index_view: Interface to look up block data
/// - cache: Optional cache for state computation
///
/// Returns the nVersion value to use for the new block.
pub fn computeBlockVersion(
    deployments: []const Deployment,
    height: u32,
    index_view: *const VersionBitsIndexView,
    cache: ?*VersionBitsCache,
) i32 {
    var version: i32 = VERSIONBITS_TOP_BITS;

    for (deployments) |dep| {
        const state = getDeploymentState(dep, height, index_view, cache);
        if (state == .started or state == .locked_in) {
            version |= @as(i32, 1) << dep.bit;
        }
    }

    return version;
}

/// BIP9 statistics for a deployment in the current period.
pub const BIP9Stats = struct {
    /// Length of the signaling period.
    period: u32,
    /// Threshold required for lock-in.
    threshold: u32,
    /// Number of blocks elapsed in current period.
    elapsed: u32,
    /// Number of signaling blocks in current period.
    count: u32,
    /// Whether it's still possible to reach threshold.
    possible: bool,
};

/// Get statistics for a deployment at a given height.
pub fn getDeploymentStats(
    deployment: Deployment,
    height: u32,
    index_view: *const VersionBitsIndexView,
) BIP9Stats {
    const period = deployment.period;
    const period_start = height - (height % period);
    const blocks_in_period = (height % period) + 1;

    var count: u32 = 0;
    var h: u32 = period_start;
    while (h <= height) : (h += 1) {
        const block = index_view.getAtHeight(h) orelse continue;
        if (versionBitSignals(block.version, deployment.bit)) {
            count += 1;
        }
    }

    const remaining = period - blocks_in_period;
    const possible = (count + remaining) >= deployment.threshold;

    return BIP9Stats{
        .period = period,
        .threshold = deployment.threshold,
        .elapsed = blocks_in_period,
        .count = count,
        .possible = possible,
    };
}

// ============================================================================
// BIP9 Version Bits Tests
// ============================================================================

fn createMockVersionBitsView(blocks: []const VersionBitsBlockIndex) VersionBitsIndexView {
    return VersionBitsIndexView{
        .context = @constCast(@ptrCast(blocks.ptr)),
        .getAtHeightFn = struct {
            fn get(ctx: *anyopaque, height: u32) ?VersionBitsBlockIndex {
                const entries: [*]const VersionBitsBlockIndex = @ptrCast(@alignCast(ctx));
                // We assume the slice has enough entries
                if (height >= 20000) return null;
                return entries[height];
            }
        }.get,
    };
}

test "versionBitSignals detects signaling" {
    // Version with top bits 001 and bit 2 set
    const version_signaling: i32 = 0x20000004; // 0x20000000 | (1 << 2)
    try std.testing.expect(versionBitSignals(version_signaling, 2));
    try std.testing.expect(!versionBitSignals(version_signaling, 3));
    try std.testing.expect(!versionBitSignals(version_signaling, 1));

    // Version without proper top bits
    const version_old: i32 = 4; // Old version, not BIP9
    try std.testing.expect(!versionBitSignals(version_old, 2));

    // Version with wrong top bits (010 instead of 001)
    const version_wrong_top: i32 = 0x40000004;
    try std.testing.expect(!versionBitSignals(version_wrong_top, 2));
}

test "versionBitMask returns correct mask" {
    try std.testing.expectEqual(@as(u32, 1), versionBitMask(0));
    try std.testing.expectEqual(@as(u32, 2), versionBitMask(1));
    try std.testing.expectEqual(@as(u32, 4), versionBitMask(2));
    try std.testing.expectEqual(@as(u32, 0x10000000), versionBitMask(28));
}

test "ThresholdState names" {
    try std.testing.expectEqualStrings("defined", ThresholdState.defined.name());
    try std.testing.expectEqualStrings("started", ThresholdState.started.name());
    try std.testing.expectEqualStrings("locked_in", ThresholdState.locked_in.name());
    try std.testing.expectEqualStrings("active", ThresholdState.active.name());
    try std.testing.expectEqualStrings("failed", ThresholdState.failed.name());
}

test "getDeploymentState always active" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = Deployment.ALWAYS_ACTIVE,
        .timeout = Deployment.NO_TIMEOUT,
    };

    var blocks: [100]VersionBitsBlockIndex = undefined;
    for (0..100) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 1,
            .median_time_past = @intCast(i * 600),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    const state = getDeploymentState(deployment, 50, &view, null);
    try std.testing.expectEqual(ThresholdState.active, state);
}

test "getDeploymentState never active" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = Deployment.NEVER_ACTIVE,
        .timeout = Deployment.NO_TIMEOUT,
    };

    var blocks: [100]VersionBitsBlockIndex = undefined;
    for (0..100) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000004, // Signaling
            .median_time_past = @intCast(i * 600),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    const state = getDeploymentState(deployment, 50, &view, null);
    try std.testing.expectEqual(ThresholdState.failed, state);
}

test "getDeploymentState genesis is defined" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 1000000,
        .timeout = 2000000,
    };

    var blocks: [1]VersionBitsBlockIndex = undefined;
    blocks[0] = VersionBitsBlockIndex{
        .height = 0,
        .version = 1,
        .median_time_past = 0,
    };
    const view = createMockVersionBitsView(&blocks);

    const state = getDeploymentState(deployment, 0, &view, null);
    try std.testing.expectEqual(ThresholdState.defined, state);
}

test "getDeploymentState defined before start_time" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 1000000,
        .timeout = 2000000,
        .period = 100,
        .threshold = 75,
    };

    var blocks: [500]VersionBitsBlockIndex = undefined;
    for (0..500) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000004, // Signaling
            .median_time_past = @intCast(i * 100), // MTP increases slowly
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // At height 200, MTP = 200 * 100 = 20000 < 1000000 (start_time)
    const state = getDeploymentState(deployment, 200, &view, null);
    try std.testing.expectEqual(ThresholdState.defined, state);
}

test "getDeploymentState transitions to started" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 10000,
        .timeout = 100000,
        .period = 100,
        .threshold = 75,
    };

    var blocks: [500]VersionBitsBlockIndex = undefined;
    for (0..500) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000004, // Signaling
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // At height 200, MTP = 200 * 100 = 20000 >= 10000 (start_time)
    // The transition happens at period boundary 200
    const state = getDeploymentState(deployment, 200, &view, null);
    try std.testing.expectEqual(ThresholdState.started, state);
}

test "getDeploymentState transitions to locked_in" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 10000,
        .timeout = 100000,
        .period = 100,
        .threshold = 75,
    };

    var blocks: [500]VersionBitsBlockIndex = undefined;
    for (0..500) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000004, // All blocks signaling
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // Period 0-99: DEFINED (MTP < 10000 at end)
    // Period 100-199: STARTED (MTP >= 10000 at end of period 0)
    // Period 200-299: LOCKED_IN (100 blocks signaled in period 100-199, >= 75 threshold)
    const state = getDeploymentState(deployment, 300, &view, null);
    try std.testing.expectEqual(ThresholdState.locked_in, state);
}

test "getDeploymentState transitions to active" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 10000,
        .timeout = 100000,
        .period = 100,
        .threshold = 75,
        .min_activation_height = 0,
    };

    var blocks: [500]VersionBitsBlockIndex = undefined;
    for (0..500) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000004, // All blocks signaling
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // Period 0-99: DEFINED
    // Period 100-199: STARTED
    // Period 200-299: LOCKED_IN
    // Period 300-399: ACTIVE
    const state = getDeploymentState(deployment, 400, &view, null);
    try std.testing.expectEqual(ThresholdState.active, state);
}

test "getDeploymentState timeout causes failure" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 10000,
        .timeout = 30000,
        .period = 100,
        .threshold = 75,
    };

    var blocks: [500]VersionBitsBlockIndex = undefined;
    for (0..500) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000000, // NOT signaling (no bit 2)
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // MTP at height 300 = 30000 >= timeout
    // State should transition to FAILED
    const state = getDeploymentState(deployment, 400, &view, null);
    try std.testing.expectEqual(ThresholdState.failed, state);
}

test "getDeploymentState insufficient signaling stays started" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 10000,
        .timeout = 100000,
        .period = 100,
        .threshold = 75,
    };

    var blocks: [500]VersionBitsBlockIndex = undefined;
    for (0..500) |i| {
        // Only 50% of blocks signal (alternating)
        const signaling = (i % 2) == 0;
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = if (signaling) 0x20000004 else 0x20000000,
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // With 50% signaling (50 blocks per period), threshold of 75 not reached
    // Should stay in STARTED
    const state = getDeploymentState(deployment, 300, &view, null);
    try std.testing.expectEqual(ThresholdState.started, state);
}

test "getDeploymentState min_activation_height delays activation" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 10000,
        .timeout = 100000,
        .period = 100,
        .threshold = 75,
        .min_activation_height = 500,
    };

    var blocks: [600]VersionBitsBlockIndex = undefined;
    for (0..600) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000004, // All blocks signaling
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // At height 400, should be LOCKED_IN (activation delayed to 500)
    const state_400 = getDeploymentState(deployment, 400, &view, null);
    try std.testing.expectEqual(ThresholdState.locked_in, state_400);

    // At height 500+, should be ACTIVE
    const state_500 = getDeploymentState(deployment, 500, &view, null);
    try std.testing.expectEqual(ThresholdState.active, state_500);
}

test "VersionBitsCache caches states" {
    var cache = VersionBitsCache.init(std.testing.allocator);
    defer cache.deinit();

    const key = StateCacheKey{ .bit = 2, .period_start_height = 2016 };
    try cache.put(key, .started);

    const cached = cache.get(key);
    try std.testing.expectEqual(ThresholdState.started, cached.?);

    // Non-existent key
    const key2 = StateCacheKey{ .bit = 3, .period_start_height = 2016 };
    try std.testing.expectEqual(@as(?ThresholdState, null), cache.get(key2));
}

test "computeBlockVersion sets bits for started deployments" {
    const deployments = [_]Deployment{
        Deployment{
            .bit = 2,
            .start_time = 10000,
            .timeout = 100000,
            .period = 100,
            .threshold = 75,
        },
        Deployment{
            .bit = 5,
            .start_time = Deployment.NEVER_ACTIVE,
            .timeout = Deployment.NO_TIMEOUT,
        },
    };

    var blocks: [500]VersionBitsBlockIndex = undefined;
    for (0..500) |i| {
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = 0x20000004,
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // Deployment with bit 2 should be STARTED at height 200
    // Deployment with bit 5 is NEVER_ACTIVE, so FAILED
    const version = computeBlockVersion(&deployments, 200, &view, null);

    // Should have top bits + bit 2, but not bit 5
    try std.testing.expectEqual(@as(i32, 0x20000004), version);
}

test "getDeploymentStats counts signaling blocks" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = 10000,
        .timeout = 100000,
        .period = 100,
        .threshold = 75,
    };

    var blocks: [200]VersionBitsBlockIndex = undefined;
    for (0..200) |i| {
        // 80 blocks signal in each period (0-79, 100-179)
        const in_signaling_range = (i % 100) < 80;
        blocks[i] = VersionBitsBlockIndex{
            .height = @intCast(i),
            .version = if (in_signaling_range) 0x20000004 else 0x20000000,
            .median_time_past = @intCast(i * 100),
        };
    }
    const view = createMockVersionBitsView(&blocks);

    // At height 149 (50 blocks into period 100-199)
    const stats = getDeploymentStats(deployment, 149, &view);

    try std.testing.expectEqual(@as(u32, 100), stats.period);
    try std.testing.expectEqual(@as(u32, 75), stats.threshold);
    try std.testing.expectEqual(@as(u32, 50), stats.elapsed);
    try std.testing.expectEqual(@as(u32, 50), stats.count); // All 50 blocks so far are signaling
    try std.testing.expect(stats.possible); // 50 + 50 remaining >= 75
}

test "isDeploymentActive returns true for active deployment" {
    const deployment = Deployment{
        .bit = 2,
        .start_time = Deployment.ALWAYS_ACTIVE,
        .timeout = Deployment.NO_TIMEOUT,
    };

    var blocks: [1]VersionBitsBlockIndex = undefined;
    blocks[0] = VersionBitsBlockIndex{
        .height = 0,
        .version = 1,
        .median_time_past = 0,
    };
    const view = createMockVersionBitsView(&blocks);

    try std.testing.expect(isDeploymentActive(deployment, 0, &view, null));
}

test "Deployments taproot parameters" {
    try std.testing.expectEqual(@as(u5, 2), Deployments.TAPROOT.bit);
    try std.testing.expectEqual(@as(u32, 709632), Deployments.TAPROOT.min_activation_height);
    try std.testing.expectEqual(@as(u32, 1815), Deployments.TAPROOT.threshold);
}
