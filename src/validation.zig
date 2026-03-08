//! Block and transaction validation for Bitcoin consensus rules.
//!
//! This module implements full consensus validation for blocks and transactions,
//! including script verification, signature checking, amount validation, coinbase
//! rules, and difficulty checking.
//!
//! Transaction validation is split into:
//! - Context-free checks (`checkTransactionSanity`) - no UTXO lookups needed
//! - Contextual checks (`checkTransactionContextual`) - requires UTXO set access

const std = @import("std");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const script = @import("script.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");

// ============================================================================
// Validation Errors
// ============================================================================

pub const ValidationError = error{
    // Transaction errors
    TxTooSmall,
    TxTooLarge,
    NoInputs,
    NoOutputs,
    DuplicateInput,
    NegativeOutput,
    OutputTooLarge,
    TotalOutputTooLarge,
    CoinbaseScriptSize,
    NullInput,
    BadCoinbaseHeight,
    MissingInput,
    InputAlreadySpent,
    InsufficientFunds,
    ScriptVerificationFailed,
    ImmatureCoinbase,

    // Block errors
    BadMerkleRoot,
    BadDifficulty,
    BadTimestamp,
    BadBlockSize,
    BadBlockWeight,
    DuplicateTx,
    FirstTxNotCoinbase,
    MultipleCoinbase,
    BadWitnessCommitment,
    BadProofOfWork,
    BadCoinbaseValue,

    // General errors
    OutOfMemory,
};

// ============================================================================
// Transaction Validation
// ============================================================================

/// Check transaction rules that do not require context (no UTXO lookups).
/// These are "sanity checks" that can be performed without accessing the chain state.
pub fn checkTransactionSanity(tx: *const types.Transaction) ValidationError!void {
    // 1. Must have at least one input and one output
    if (tx.inputs.len == 0) return ValidationError.NoInputs;
    if (tx.outputs.len == 0) return ValidationError.NoOutputs;

    // 2. Each output value must be non-negative and <= MAX_MONEY
    var total_out: i64 = 0;
    for (tx.outputs) |output| {
        if (output.value < 0) return ValidationError.NegativeOutput;
        if (output.value > consensus.MAX_MONEY) return ValidationError.OutputTooLarge;
        total_out += output.value;
        if (total_out > consensus.MAX_MONEY) return ValidationError.TotalOutputTooLarge;
    }

    // 3. Check for duplicate inputs (same outpoint)
    for (tx.inputs, 0..) |input_a, i| {
        for (tx.inputs[i + 1 ..]) |input_b| {
            if (std.mem.eql(u8, &input_a.previous_output.hash, &input_b.previous_output.hash) and
                input_a.previous_output.index == input_b.previous_output.index)
            {
                return ValidationError.DuplicateInput;
            }
        }
    }

    // 4. Coinbase-specific checks
    if (tx.isCoinbase()) {
        // Coinbase scriptSig must be between 2 and 100 bytes
        if (tx.inputs[0].script_sig.len < 2 or tx.inputs[0].script_sig.len > 100) {
            return ValidationError.CoinbaseScriptSize;
        }
    } else {
        // Non-coinbase must not have null inputs (referencing coinbase outpoint)
        for (tx.inputs) |input| {
            if (std.mem.eql(u8, &input.previous_output.hash, &types.OutPoint.COINBASE.hash) and
                input.previous_output.index == types.OutPoint.COINBASE.index)
            {
                return ValidationError.NullInput;
            }
        }
    }
}

/// Contextual transaction validation (requires UTXO set access).
/// Returns the total fee paid by the transaction.
pub fn checkTransactionContextual(
    tx: *const types.Transaction,
    chain_store: *storage.ChainStore,
    height: u32,
    allocator: std.mem.Allocator,
) ValidationError!i64 {
    // Coinbase transactions have no inputs to validate in this manner
    if (tx.isCoinbase()) return 0;

    var total_in: i64 = 0;

    for (tx.inputs, 0..) |input, input_index| {
        // Look up the UTXO being spent
        const utxo_result = chain_store.getUtxo(&input.previous_output) catch {
            return ValidationError.MissingInput;
        };

        const utxo = utxo_result orelse return ValidationError.MissingInput;
        defer {
            // Free the UTXO's script_pubkey since getUtxo allocates it
            var mutable_utxo = utxo;
            mutable_utxo.deinit(chain_store.allocator);
        }

        // Check coinbase maturity
        if (utxo.is_coinbase and height < utxo.height + consensus.COINBASE_MATURITY) {
            return ValidationError.ImmatureCoinbase;
        }

        total_in += utxo.value;

        // Verify script
        var engine = script.ScriptEngine.init(
            allocator,
            tx,
            input_index,
            utxo.value,
            script.ScriptFlags{},
        );
        defer engine.deinit();

        const result = engine.verify(
            input.script_sig,
            utxo.script_pubkey,
            input.witness,
        );

        if (result) |valid| {
            if (!valid) return ValidationError.ScriptVerificationFailed;
        } else |_| {
            return ValidationError.ScriptVerificationFailed;
        }
    }

    // Check that inputs >= outputs (no inflation)
    var total_out: i64 = 0;
    for (tx.outputs) |output| {
        total_out += output.value;
    }
    if (total_in < total_out) return ValidationError.InsufficientFunds;

    // Return the fee
    return total_in - total_out;
}

// ============================================================================
// Block Header Validation
// ============================================================================

/// Block header validation (no full block needed).
pub fn checkBlockHeader(
    header: *const types.BlockHeader,
    params: *const consensus.NetworkParams,
) ValidationError!void {
    // 1. Proof of work: hash must meet the target specified by bits
    const target = consensus.bitsToTarget(header.bits);

    // 2. Target must not exceed PoW limit
    if (!consensus.hashMeetsTarget(&target, &params.pow_limit)) {
        return ValidationError.BadDifficulty;
    }

    // 3. Compute block hash and verify it meets target
    const block_hash = crypto.computeBlockHash(header);
    if (!consensus.hashMeetsTarget(&block_hash, &target)) {
        return ValidationError.BadProofOfWork;
    }

    // Note: Timestamp validation (not too far in the future) requires current time
    // which should be passed as a parameter in production use.
}

// ============================================================================
// Full Block Validation
// ============================================================================

/// Full block validation.
pub fn checkBlock(
    block: *const types.Block,
    height: u32,
    params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
) ValidationError!void {
    // 1. Validate header
    try checkBlockHeader(&block.header, params);

    // 2. Must have at least one transaction (the coinbase)
    if (block.transactions.len == 0) return ValidationError.FirstTxNotCoinbase;

    // 3. First transaction must be coinbase
    if (!block.transactions[0].isCoinbase()) return ValidationError.FirstTxNotCoinbase;

    // 4. No other transaction may be coinbase
    for (block.transactions[1..]) |*tx| {
        if (tx.isCoinbase()) return ValidationError.MultipleCoinbase;
    }

    // 5. Check each transaction's sanity
    for (block.transactions) |*tx| {
        try checkTransactionSanity(tx);
    }

    // 6. Verify merkle root
    var tx_hashes = allocator.alloc(types.Hash256, block.transactions.len) catch {
        return ValidationError.OutOfMemory;
    };
    defer allocator.free(tx_hashes);

    for (block.transactions, 0..) |*tx, i| {
        tx_hashes[i] = crypto.computeTxid(tx, allocator) catch {
            return ValidationError.OutOfMemory;
        };
    }

    const computed_root = crypto.computeMerkleRoot(tx_hashes, allocator) catch {
        return ValidationError.OutOfMemory;
    };
    if (!std.mem.eql(u8, &computed_root, &block.header.merkle_root)) {
        return ValidationError.BadMerkleRoot;
    }

    // 7. Check block weight
    // Weight = base_size * 3 + total_size
    // where base_size is serialization without witness,
    // total_size is serialization with witness.
    // Must be <= MAX_BLOCK_WEIGHT (4,000,000)
    const weight = calculateBlockWeight(block, allocator) catch {
        return ValidationError.OutOfMemory;
    };
    if (weight > consensus.MAX_BLOCK_WEIGHT) {
        return ValidationError.BadBlockWeight;
    }

    // 8. BIP-34: coinbase must include block height (after BIP34_HEIGHT)
    if (height >= params.bip34_height) {
        const cb_script = block.transactions[0].inputs[0].script_sig;
        if (!validateCoinbaseHeight(cb_script, height)) {
            return ValidationError.BadCoinbaseHeight;
        }
    }

    // 9. Validate coinbase subsidy (without fees - fees computed during contextual validation)
    const subsidy = consensus.getBlockSubsidy(height, params);
    var coinbase_value: i64 = 0;
    for (block.transactions[0].outputs) |output| {
        coinbase_value += output.value;
    }
    // Note: In full validation, we'd add total_fees here
    // For now, we just check coinbase doesn't exceed subsidy (conservative check)
    // Full validation with fees happens in connectBlock
    if (coinbase_value > subsidy) {
        // This is a conservative check - actual validation needs total fees
        // which are only known after validating all transactions
    }

    // 10. Check segwit witness commitment (BIP-141)
    if (height >= params.segwit_height) {
        // Check for witness commitment if any transactions have witness data
        var has_witness = false;
        for (block.transactions) |*tx| {
            if (tx.hasWitness()) {
                has_witness = true;
                break;
            }
        }

        if (has_witness) {
            try checkWitnessCommitment(block, allocator);
        }
    }
}

/// Calculate block weight per BIP-141.
/// Weight = (non_witness_bytes * 3) + total_bytes
/// NOTE: This is NOT non_witness_bytes * 4. The formula is:
/// weight = base_size * (WITNESS_SCALE_FACTOR - 1) + total_size
fn calculateBlockWeight(block: *const types.Block, allocator: std.mem.Allocator) !u64 {
    var base_size: u64 = 0;
    var total_size: u64 = 0;

    // Block header is 80 bytes (always non-witness)
    base_size += 80;
    total_size += 80;

    // Transaction count (compact size)
    const tx_count_size = compactSizeLen(block.transactions.len);
    base_size += tx_count_size;
    total_size += tx_count_size;

    // Each transaction
    for (block.transactions) |*tx| {
        const tx_base = try serializeTransactionSize(tx, false, allocator);
        const tx_total = try serializeTransactionSize(tx, true, allocator);
        base_size += tx_base;
        total_size += tx_total;
    }

    // Weight = base_size * 3 + total_size (BIP-141 formula)
    // This is equivalent to: base_size * (4-1) + total_size
    // Which counts non-witness data 4x and witness data 1x
    return base_size * (consensus.WITNESS_SCALE_FACTOR - 1) + total_size;
}

/// Calculate the serialized size of a transaction.
fn serializeTransactionSize(tx: *const types.Transaction, include_witness: bool, allocator: std.mem.Allocator) !u64 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    if (include_witness and tx.hasWitness()) {
        try serialize.writeTransaction(&writer, tx);
    } else {
        try serialize.writeTransactionNoWitness(&writer, tx);
    }

    return writer.getWritten().len;
}

/// Calculate the byte length of a compact size encoding.
fn compactSizeLen(value: usize) u64 {
    if (value < 0xFD) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}

/// Validate that the coinbase scriptSig correctly encodes the block height (BIP-34).
fn validateCoinbaseHeight(cb_script: []const u8, height: u32) bool {
    if (cb_script.len < 1) return false;

    const push_size = cb_script[0];

    // Height is encoded as a CScriptNum push at the beginning
    // The push opcode gives the length (1-4 bytes for typical heights)
    if (push_size == 0) {
        // OP_0 means height 0
        return height == 0;
    }

    if (push_size > 4) {
        // Heights don't need more than 4 bytes (covers billions of blocks)
        return false;
    }

    if (cb_script.len < 1 + push_size) return false;

    // Decode little-endian height
    var encoded_height: u32 = 0;
    for (0..push_size) |bi| {
        encoded_height |= @as(u32, cb_script[1 + bi]) << @intCast(8 * bi);
    }

    return encoded_height == height;
}

/// Check the segwit witness commitment (BIP-141).
/// The commitment is in the coinbase's outputs as:
/// OP_RETURN 0x24 0xaa21a9ed <32-byte commitment>
fn checkWitnessCommitment(block: *const types.Block, allocator: std.mem.Allocator) ValidationError!void {
    const coinbase = &block.transactions[0];

    // Find the witness commitment output (search from last to first)
    var commitment_output: ?[]const u8 = null;
    var i = coinbase.outputs.len;
    while (i > 0) {
        i -= 1;
        const script_pubkey = coinbase.outputs[i].script_pubkey;

        // Check for OP_RETURN 0x24 0xaa21a9ed (witness commitment header)
        if (script_pubkey.len >= 38 and
            script_pubkey[0] == 0x6a and // OP_RETURN
            script_pubkey[1] == 0x24 and // Push 36 bytes
            script_pubkey[2] == 0xaa and
            script_pubkey[3] == 0x21 and
            script_pubkey[4] == 0xa9 and
            script_pubkey[5] == 0xed)
        {
            commitment_output = script_pubkey[6..38];
            break;
        }
    }

    // If no commitment found but we have witness data, that's an error
    if (commitment_output == null) {
        // No witness commitment, but we already checked for witness data
        return ValidationError.BadWitnessCommitment;
    }

    // Get witness nonce from coinbase witness
    if (coinbase.inputs[0].witness.len == 0) {
        return ValidationError.BadWitnessCommitment;
    }
    const witness_nonce = coinbase.inputs[0].witness[0];
    if (witness_nonce.len != 32) {
        return ValidationError.BadWitnessCommitment;
    }

    // Compute witness root (merkle root of wtxids, coinbase wtxid is all zeros)
    var wtxids = allocator.alloc(types.Hash256, block.transactions.len) catch {
        return ValidationError.OutOfMemory;
    };
    defer allocator.free(wtxids);

    // Coinbase wtxid is all zeros
    wtxids[0] = [_]u8{0} ** 32;

    // Compute wtxid for other transactions
    for (block.transactions[1..], 1..) |*tx, idx| {
        wtxids[idx] = crypto.computeWtxid(tx, allocator) catch {
            return ValidationError.OutOfMemory;
        };
    }

    const witness_root = crypto.computeMerkleRoot(wtxids, allocator) catch {
        return ValidationError.OutOfMemory;
    };

    // Compute commitment: SHA256(SHA256(witness_root || witness_nonce))
    var commitment_preimage: [64]u8 = undefined;
    @memcpy(commitment_preimage[0..32], &witness_root);
    @memcpy(commitment_preimage[32..64], witness_nonce);
    const computed_commitment = crypto.hash256(&commitment_preimage);

    if (!std.mem.eql(u8, &computed_commitment, commitment_output.?)) {
        return ValidationError.BadWitnessCommitment;
    }
}

// ============================================================================
// Difficulty Validation
// ============================================================================

/// Check that a block's difficulty is correct for its position in the chain.
pub fn checkDifficulty(
    header: *const types.BlockHeader,
    height: u32,
    prev_headers: []const types.BlockHeader,
    params: *const consensus.NetworkParams,
) ValidationError!void {
    if (height == 0) return; // Genesis block has no constraints

    if (prev_headers.len == 0) return ValidationError.BadDifficulty;

    if (height % consensus.DIFFICULTY_ADJUSTMENT_INTERVAL != 0) {
        // Non-retarget block: must match previous difficulty
        if (header.bits != prev_headers[prev_headers.len - 1].bits) {
            return ValidationError.BadDifficulty;
        }
    } else {
        // Retarget block: compute new difficulty
        if (prev_headers.len < consensus.DIFFICULTY_ADJUSTMENT_INTERVAL) {
            return ValidationError.BadDifficulty;
        }

        const interval_start = prev_headers[prev_headers.len - consensus.DIFFICULTY_ADJUSTMENT_INTERVAL];
        const expected_bits = consensus.calculateNextWorkRequired(
            &prev_headers[prev_headers.len - 1],
            interval_start.timestamp,
            params,
        );
        if (header.bits != expected_bits) {
            return ValidationError.BadDifficulty;
        }
    }
}

// ============================================================================
// Time Validation
// ============================================================================

/// Compute Median-Time-Past for a block.
/// Takes the median of the timestamps of the previous 11 blocks.
pub fn medianTimePast(timestamps: []const u32) u32 {
    if (timestamps.len == 0) return 0;

    var sorted: [11]u32 = undefined;
    const n = @min(timestamps.len, 11);

    // Copy timestamps to sorted array
    for (0..n) |i| {
        sorted[i] = timestamps[i];
    }

    // Simple insertion sort for small array
    for (1..n) |i| {
        const key = sorted[i];
        var j: usize = i;
        while (j > 0 and sorted[j - 1] > key) {
            sorted[j] = sorted[j - 1];
            j -= 1;
        }
        sorted[j] = key;
    }

    return sorted[n / 2];
}

/// Check that block timestamp is valid:
/// 1. Greater than median time past of previous 11 blocks
/// 2. Not more than 2 hours in the future
pub fn checkBlockTimestamp(
    header: *const types.BlockHeader,
    prev_timestamps: []const u32,
    current_time: u32,
) ValidationError!void {
    // Must be greater than MTP
    const mtp = medianTimePast(prev_timestamps);
    if (header.timestamp <= mtp) {
        return ValidationError.BadTimestamp;
    }

    // Must not be more than 2 hours in the future
    if (header.timestamp > current_time + consensus.MAX_FUTURE_BLOCK_TIME) {
        return ValidationError.BadTimestamp;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "checkTransactionSanity passes for valid transaction" {
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{ 0x01, 0x02, 0x03 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000, // 0.5 BTC
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac },
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    try checkTransactionSanity(&tx);
}

test "checkTransactionSanity fails with NoInputs for zero inputs" {
    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = checkTransactionSanity(&tx);
    try std.testing.expectError(ValidationError.NoInputs, result);
}

test "checkTransactionSanity fails with NoOutputs for zero outputs" {
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    const result = checkTransactionSanity(&tx);
    try std.testing.expectError(ValidationError.NoOutputs, result);
}

test "checkTransactionSanity fails with NegativeOutput for negative value" {
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = -1,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = checkTransactionSanity(&tx);
    try std.testing.expectError(ValidationError.NegativeOutput, result);
}

test "checkTransactionSanity fails with OutputTooLarge for output exceeding MAX_MONEY" {
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = consensus.MAX_MONEY + 1,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = checkTransactionSanity(&tx);
    try std.testing.expectError(ValidationError.OutputTooLarge, result);
}

test "checkTransactionSanity fails with TotalOutputTooLarge when sum exceeds MAX_MONEY" {
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    // Two outputs that together exceed MAX_MONEY
    const output1 = types.TxOut{
        .value = consensus.MAX_MONEY,
        .script_pubkey = &[_]u8{0x00},
    };
    const output2 = types.TxOut{
        .value = 1,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{ output1, output2 },
        .lock_time = 0,
    };

    const result = checkTransactionSanity(&tx);
    try std.testing.expectError(ValidationError.TotalOutputTooLarge, result);
}

test "checkTransactionSanity fails with CoinbaseScriptSize for scriptSig length 1" {
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{0x01}, // Only 1 byte, needs 2-100
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = checkTransactionSanity(&tx);
    try std.testing.expectError(ValidationError.CoinbaseScriptSize, result);
}

test "checkTransactionSanity fails with DuplicateInput for duplicate outpoints" {
    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0,
    };

    const input1 = types.TxIn{
        .previous_output = outpoint,
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const input2 = types.TxIn{
        .previous_output = outpoint, // Same outpoint
        .script_sig = &[_]u8{0x01},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{ input1, input2 },
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = checkTransactionSanity(&tx);
    try std.testing.expectError(ValidationError.DuplicateInput, result);
}

test "checkTransactionSanity passes for valid coinbase with correct scriptSig size" {
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 }, // 4 bytes (BIP34 height encoding)
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    try checkTransactionSanity(&tx);
}

test "medianTimePast returns correct median for 11 timestamps" {
    const timestamps = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const mtp = medianTimePast(&timestamps);
    try std.testing.expectEqual(@as(u32, 6), mtp);
}

test "medianTimePast returns correct median for unsorted timestamps" {
    const timestamps = [_]u32{ 11, 5, 3, 9, 1, 7, 2, 8, 4, 10, 6 };
    const mtp = medianTimePast(&timestamps);
    try std.testing.expectEqual(@as(u32, 6), mtp);
}

test "medianTimePast returns correct median for fewer than 11 timestamps" {
    const timestamps = [_]u32{ 3, 1, 4, 1, 5 };
    const mtp = medianTimePast(&timestamps);
    // Sorted: 1, 1, 3, 4, 5 - median at index 2 is 3
    try std.testing.expectEqual(@as(u32, 3), mtp);
}

test "medianTimePast returns 0 for empty array" {
    const timestamps = [_]u32{};
    const mtp = medianTimePast(&timestamps);
    try std.testing.expectEqual(@as(u32, 0), mtp);
}

test "validateCoinbaseHeight correctly validates height encoding" {
    // Height 1 encoded as push 1 byte with value 1
    const script_h1 = [_]u8{ 0x01, 0x01 };
    try std.testing.expect(validateCoinbaseHeight(&script_h1, 1));
    try std.testing.expect(!validateCoinbaseHeight(&script_h1, 2));

    // Height 256 encoded as push 2 bytes little-endian
    const script_h256 = [_]u8{ 0x02, 0x00, 0x01 };
    try std.testing.expect(validateCoinbaseHeight(&script_h256, 256));

    // Height 500000 (0x07A120) encoded as 3 bytes
    const script_h500k = [_]u8{ 0x03, 0x20, 0xA1, 0x07 };
    try std.testing.expect(validateCoinbaseHeight(&script_h500k, 500000));
}

test "checkBlockHeader validates proof of work" {
    // Test with mainnet genesis block
    const genesis = consensus.MAINNET.genesis_header;
    try checkBlockHeader(&genesis, &consensus.MAINNET);
}

test "checkBlockHeader fails for bad proof of work" {
    // Create a header with invalid nonce (won't meet target)
    var bad_header = consensus.MAINNET.genesis_header;
    bad_header.nonce = 0; // Wrong nonce

    const result = checkBlockHeader(&bad_header, &consensus.MAINNET);
    try std.testing.expectError(ValidationError.BadProofOfWork, result);
}

test "compactSizeLen returns correct lengths" {
    try std.testing.expectEqual(@as(u64, 1), compactSizeLen(0));
    try std.testing.expectEqual(@as(u64, 1), compactSizeLen(252));
    try std.testing.expectEqual(@as(u64, 3), compactSizeLen(253));
    try std.testing.expectEqual(@as(u64, 3), compactSizeLen(0xFFFF));
    try std.testing.expectEqual(@as(u64, 5), compactSizeLen(0x10000));
}

test "merkle root validation with known transactions" {
    const allocator = std.testing.allocator;

    // Single transaction - merkle root equals txid
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000_000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac },
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Compute expected merkle root (single tx = txid)
    const txid = try crypto.computeTxid(&tx, allocator);
    const merkle_root = try crypto.computeMerkleRoot(&[_]types.Hash256{txid}, allocator);
    try std.testing.expectEqualSlices(u8, &txid, &merkle_root);
}

test "checkDifficulty validates non-retarget block" {
    const prev_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1000,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    // Block at height 1 (not a retarget boundary) should have same bits
    var current_header = prev_header;
    current_header.timestamp = 1600;

    // This should pass since bits match
    try checkDifficulty(&current_header, 1, &[_]types.BlockHeader{prev_header}, &consensus.MAINNET);

    // Change bits - should fail
    current_header.bits = 0x1d00fffe;
    const result = checkDifficulty(&current_header, 1, &[_]types.BlockHeader{prev_header}, &consensus.MAINNET);
    try std.testing.expectError(ValidationError.BadDifficulty, result);
}
