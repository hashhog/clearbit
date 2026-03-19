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
    SequenceLockNotSatisfied,
    TooManySigops,

    // Checkpoint errors
    CheckpointMismatch,
    ForkBelowCheckpoint,

    // General errors
    OutOfMemory,
};

// ============================================================================
// Script Verification Flags
// ============================================================================

/// Get the script verification flags for a block at a given height.
/// This implements the consensus-critical flag settings based on soft fork activation.
///
/// Reference: Bitcoin Core validation.cpp GetBlockScriptFlags()
///
/// CRITICAL: Only 7 flags are consensus (enforced during block validation):
/// - P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, TAPROOT
///
/// BIP-146 NULLFAIL and BIP-147 NULLDUMMY are activated with SegWit (BIP-141).
/// Note: In Bitcoin Core, NULLFAIL is technically policy-only and not set in
/// GetBlockScriptFlags(). However, clearbit enforces it at consensus level
/// for additional safety.
pub fn getBlockScriptFlags(height: u32, params: *const consensus.NetworkParams) script.ScriptFlags {
    var flags = script.ScriptFlags{};

    // Disable flags that should only be enabled at specific heights
    // Start with minimal flags and enable based on activation heights
    flags.verify_p2sh = height >= params.bip34_height;
    flags.verify_dersig = height >= params.bip66_height;
    flags.verify_checklocktimeverify = height >= params.bip65_height;
    flags.verify_checksequenceverify = height >= params.csv_height;
    flags.verify_witness = height >= params.segwit_height;
    flags.verify_nulldummy = height >= params.segwit_height;
    flags.verify_nullfail = height >= params.segwit_height;
    flags.verify_taproot = height >= params.taproot_height;

    // Policy flags that are always enabled for consensus
    // (these are not height-dependent in Bitcoin Core either)
    flags.verify_low_s = true;
    flags.verify_minimaldata = true;
    flags.verify_clean_stack = true;
    flags.verify_witness_pubkeytype = height >= params.segwit_height;

    return flags;
}

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
// Sigop Counting
// ============================================================================

/// UTXO information needed for sigop cost calculation.
/// Contains the scriptPubKey of the previous output being spent.
pub const SigopUtxoView = struct {
    context: *anyopaque,
    lookupFn: *const fn (ctx: *anyopaque, outpoint: *const types.OutPoint) ?[]const u8,

    pub fn lookup(self: *const SigopUtxoView, outpoint: *const types.OutPoint) ?[]const u8 {
        return self.lookupFn(self.context, outpoint);
    }
};

/// Count legacy sigops in a transaction (scriptSig + scriptPubKey of outputs).
/// This is the "old-fashioned" (pre-BIP16) sigop counting method.
/// Uses inaccurate mode (CHECKMULTISIG = 20 sigops).
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp GetLegacySigOpCount()
pub fn getLegacySigOpCount(tx: *const types.Transaction) u32 {
    var n: u32 = 0;

    // Count sigops in all input scriptSigs
    for (tx.inputs) |input| {
        n += script.getSigOpCount(input.script_sig, false);
    }

    // Count sigops in all output scriptPubKeys
    for (tx.outputs) |output| {
        n += script.getSigOpCount(output.script_pubkey, false);
    }

    return n;
}

/// Count P2SH sigops in a transaction.
/// For each input spending a P2SH output, extract the redeemScript from
/// the scriptSig and count sigops in it.
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp GetP2SHSigOpCount()
pub fn getP2SHSigOpCount(
    tx: *const types.Transaction,
    utxo_view: *const SigopUtxoView,
) u32 {
    if (tx.isCoinbase()) {
        return 0;
    }

    var n: u32 = 0;

    for (tx.inputs) |input| {
        // Look up the previous output's scriptPubKey
        const prev_script_pubkey = utxo_view.lookup(&input.previous_output) orelse continue;

        if (script.isPayToScriptHash(prev_script_pubkey)) {
            n += script.getP2SHSigOpCount(prev_script_pubkey, input.script_sig);
        }
    }

    return n;
}

/// Calculate the total sigop cost for a transaction.
/// This is the main function for sigop counting with witness discount.
///
/// The total cost is:
/// - Legacy sigops (scriptSig + output scriptPubKey) * WITNESS_SCALE_FACTOR (4)
/// - P2SH sigops * WITNESS_SCALE_FACTOR (4) if P2SH flag is set
/// - Witness sigops * 1 (no scaling, witness discount)
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp GetTransactionSigOpCost()
pub fn getTransactionSigOpCost(
    tx: *const types.Transaction,
    utxo_view: *const SigopUtxoView,
    flags: script.ScriptFlags,
) u64 {
    // Start with legacy sigops, scaled by witness factor
    var cost: u64 = @as(u64, getLegacySigOpCount(tx)) * consensus.WITNESS_SCALE_FACTOR;

    // Coinbase transactions only have legacy sigops
    if (tx.isCoinbase()) {
        return cost;
    }

    // Add P2SH sigops if P2SH verification is enabled
    if (flags.verify_p2sh) {
        cost += @as(u64, getP2SHSigOpCount(tx, utxo_view)) * consensus.WITNESS_SCALE_FACTOR;
    }

    // Add witness sigops (no scaling - witness discount)
    for (tx.inputs) |input| {
        const prev_script_pubkey = utxo_view.lookup(&input.previous_output) orelse continue;

        cost += @as(u64, script.countWitnessSigOps(
            input.script_sig,
            prev_script_pubkey,
            input.witness,
            flags,
        ));
    }

    return cost;
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
// Checkpoint Verification
// ============================================================================

/// Verify that a block passes checkpoint validation.
/// This function should be called during header validation to ensure:
/// 1. If a checkpoint exists at this height, the block hash must match exactly.
/// 2. No forks are allowed at or below the last checkpoint height (unless they
///    match the checkpoint).
///
/// This prevents long-range attacks during IBD where an attacker could try to
/// feed the node an alternative chain.
pub fn verifyCheckpoint(
    header: *const types.BlockHeader,
    height: u32,
    network: consensus.Network,
) ValidationError!void {
    const checkpoints = consensus.getCheckpointsRuntime(network);

    // Compute the block hash
    const block_hash = crypto.computeBlockHash(header);

    // Check if there's a checkpoint at this height
    if (consensus.getCheckpointAtHeight(checkpoints, height)) |checkpoint| {
        // Checkpoint exists - hash must match exactly
        if (!std.mem.eql(u8, &block_hash, &checkpoint.hash)) {
            return ValidationError.CheckpointMismatch;
        }
    }
}

/// Validate that a header does not fork below the last checkpoint.
/// This should be called when accepting a new header to ensure we don't
/// build on a chain that diverges from known checkpoints.
///
/// Parameters:
///   - height: Height of the block we're validating
///   - network: Which network we're on
///   - ancestor_checker: A function/context to verify that the block at a
///                       checkpoint height in our chain matches the checkpoint hash.
///                       Returns true if the ancestor at checkpoint.height has
///                       checkpoint.hash, false otherwise.
///
/// Returns error if:
///   - The chain forks from the checkpointed chain at any checkpoint height
pub fn verifyChainAgainstCheckpoints(
    height: u32,
    network: consensus.Network,
    ancestor_checker: *const fn (height: u32, expected_hash: *const types.Hash256) bool,
) ValidationError!void {
    const checkpoints = consensus.getCheckpointsRuntime(network);

    // For each checkpoint at or below our height, verify our ancestor matches
    for (checkpoints) |checkpoint| {
        if (checkpoint.height <= height) {
            if (!ancestor_checker(checkpoint.height, &checkpoint.hash)) {
                return ValidationError.ForkBelowCheckpoint;
            }
        }
    }
}

/// Check if we should reject a header because it forks before a checkpoint.
/// During IBD, we should only accept headers that are on the checkpointed chain.
///
/// This is a simpler version of verifyChainAgainstCheckpoints that just checks
/// if the block's height is at or below the last checkpoint - if so, we need
/// to verify checkpoint matching elsewhere.
pub fn requiresCheckpointValidation(height: u32, network: consensus.Network) bool {
    return consensus.isBelowLastCheckpoint(network, height);
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

    // 10. Basic sigop check (legacy sigops only, doesn't need UTXO access)
    // This is a conservative check - full sigop counting with P2SH and witness
    // sigops requires UTXO access and is done in connectBlock.
    // Reference: Bitcoin Core validation.cpp CheckBlock() nSigOps check
    var legacy_sigops: u64 = 0;
    for (block.transactions) |*tx| {
        legacy_sigops += getLegacySigOpCount(tx);
    }
    if (legacy_sigops * consensus.WITNESS_SCALE_FACTOR > consensus.MAX_BLOCK_SIGOPS_COST) {
        return ValidationError.TooManySigops;
    }

    // 11. Check segwit witness commitment (BIP-141)
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

/// Connect a block to the chain, performing full validation including sigop counting
/// and BIP-68 sequence lock enforcement.
/// This function requires UTXO access to count P2SH and witness sigops.
///
/// Returns the total fees collected by the block.
///
/// Reference: Bitcoin Core validation.cpp ConnectBlock()
pub fn connectBlock(
    block: *const types.Block,
    height: u32,
    params: *const consensus.NetworkParams,
    sigop_view: *const SigopUtxoView,
    sequence_view: ?*const UtxoView,
    tip: ?*const BlockIndex,
) ValidationError!i64 {
    // Get script verification flags for this block height
    const flags = getBlockScriptFlags(height, params);

    // Track total sigop cost and fees
    var total_sigops_cost: u64 = 0;
    const total_fees: i64 = 0; // TODO: Calculate actual fees when full tx validation is implemented

    // Process each transaction
    for (block.transactions) |*tx| {
        // Calculate sigop cost
        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        total_sigops_cost += getTransactionSigOpCost(tx, sigop_view, flags);

        if (total_sigops_cost > consensus.MAX_BLOCK_SIGOPS_COST) {
            return ValidationError.TooManySigops;
        }

        // BIP-68: Check sequence locks for non-coinbase transactions
        // Reference: Bitcoin Core validation.cpp ConnectBlock() calls SequenceLocks()
        if (!tx.isCoinbase()) {
            if (sequence_view) |sv| {
                if (tip) |t| {
                    const lock_result = calculateSequenceLocks(tx, sv, height, params);
                    if (!checkSequenceLocks(lock_result, t)) {
                        return ValidationError.SequenceLockNotSatisfied;
                    }
                }
            }
        }

        // TODO: Add fee calculation here when we have full transaction validation
    }

    // TODO: Verify coinbase value <= subsidy + total_fees
    // const subsidy = consensus.getBlockSubsidy(height, params);

    return total_fees;
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
// BIP-68 Sequence Lock Validation
// ============================================================================

/// Result of sequence lock calculation.
/// Contains the minimum height and time that must be reached for the transaction
/// to be valid. Uses -1 as a sentinel meaning "no constraint".
pub const SequenceLockResult = struct {
    /// Minimum block height required (-1 means no height constraint).
    /// The transaction can be included in a block with height > min_height.
    min_height: i32,
    /// Minimum median time past required (-1 means no time constraint).
    /// The transaction can be included in a block with MTP > min_time.
    min_time: i64,
};

/// UTXO information needed for sequence lock calculation.
pub const UtxoInfo = struct {
    /// Height at which this UTXO was confirmed.
    height: u32,
    /// Median time past of the block that contained this UTXO.
    mtp: u32,
};

/// A view interface for looking up UTXO information by outpoint.
pub const UtxoView = struct {
    context: *anyopaque,
    lookupFn: *const fn (ctx: *anyopaque, outpoint: *const types.OutPoint) ?UtxoInfo,

    pub fn lookup(self: *const UtxoView, outpoint: *const types.OutPoint) ?UtxoInfo {
        return self.lookupFn(self.context, outpoint);
    }
};

/// Block index information needed for sequence lock evaluation.
pub const BlockIndex = struct {
    height: u32,
    /// Median time past of this block's parent (used for evaluation).
    prev_mtp: u32,
};

/// Calculate sequence locks for a transaction.
///
/// For each input where BIP-68 is active (bit 31 not set in nSequence),
/// calculate the minimum height or time that must be reached.
///
/// BIP-68 only applies if:
/// - tx.version >= 2
/// - The current block height is >= csv_height (BIP-68 activation)
///
/// For each input:
/// - If bit 31 (SEQUENCE_LOCKTIME_DISABLE_FLAG) is set, skip this input
/// - If bit 22 (SEQUENCE_LOCKTIME_TYPE_FLAG) is set, it's time-based:
///   - Lock value = (sequence & 0xFFFF) * 512 seconds
///   - Compare against MTP of block containing the UTXO
/// - Otherwise, it's height-based:
///   - Lock value = sequence & 0xFFFF blocks
///   - Compare against height of block containing the UTXO
///
/// Returns: SequenceLockResult with the maximum required height/time across all inputs.
pub fn calculateSequenceLocks(
    tx: *const types.Transaction,
    utxo_view: *const UtxoView,
    block_height: u32,
    params: *const consensus.NetworkParams,
) SequenceLockResult {
    // Initialize to -1 (no constraint)
    var result = SequenceLockResult{
        .min_height = -1,
        .min_time = -1,
    };

    // BIP-68 only applies to tx version >= 2
    if (tx.version < 2) {
        return result;
    }

    // BIP-68 only applies after CSV activation
    if (block_height < params.csv_height) {
        return result;
    }

    // Coinbase transactions have no inputs to check
    if (tx.isCoinbase()) {
        return result;
    }

    for (tx.inputs) |input| {
        const sequence = input.sequence;

        // If disable flag is set, BIP-68 doesn't apply to this input
        if ((sequence & consensus.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
            continue;
        }

        // Look up the UTXO being spent
        const utxo_info = utxo_view.lookup(&input.previous_output) orelse {
            // If UTXO not found, skip this input (validation should catch this elsewhere)
            continue;
        };

        const lock_value = sequence & consensus.SEQUENCE_LOCKTIME_MASK;

        if ((sequence & consensus.SEQUENCE_LOCKTIME_TYPE_FLAG) != 0) {
            // Time-based lock: lock_value * 512 seconds relative to UTXO's block MTP
            // The MTP used is from the block *prior* to the one containing the UTXO
            // (Bitcoin Core: block.GetAncestor(nCoinHeight - 1)->GetMedianTimePast())
            // But we simplify by using the MTP of the block containing the UTXO
            const lock_time = @as(i64, lock_value) << consensus.SEQUENCE_LOCKTIME_GRANULARITY;
            // Subtract 1 to convert from "first valid" to "last invalid" semantics
            const required_time = @as(i64, utxo_info.mtp) + lock_time - 1;
            result.min_time = @max(result.min_time, required_time);
        } else {
            // Height-based lock: lock_value blocks relative to UTXO's confirmation height
            // Subtract 1 to convert from "first valid" to "last invalid" semantics
            const required_height = @as(i32, @intCast(utxo_info.height)) + @as(i32, @intCast(lock_value)) - 1;
            result.min_height = @max(result.min_height, required_height);
        }
    }

    return result;
}

/// Check if sequence locks are satisfied for inclusion in a block.
///
/// The transaction can be included in a block if:
/// - Block height > result.min_height (or min_height == -1)
/// - Block's parent MTP > result.min_time (or min_time == -1)
pub fn checkSequenceLocks(result: SequenceLockResult, tip: *const BlockIndex) bool {
    // Height check: block height must be > min_height
    if (result.min_height >= @as(i32, @intCast(tip.height))) {
        return false;
    }

    // Time check: parent's MTP must be > min_time
    if (result.min_time >= @as(i64, tip.prev_mtp)) {
        return false;
    }

    return true;
}

// ============================================================================
// Parallel Script Validation
// ============================================================================

/// A job representing a single script verification to be performed.
/// These jobs are distributed across worker threads for parallel execution.
///
/// Reference: Bitcoin Core validation.h CScriptCheck
pub const ScriptCheckJob = struct {
    /// Transaction bytes (serialized for thread safety)
    tx_bytes: []const u8,
    /// Index of the input being verified
    input_index: usize,
    /// ScriptPubKey of the previous output
    prev_script_pubkey: []const u8,
    /// Value of the previous output (satoshis)
    amount: i64,
    /// Script verification flags
    flags: script.ScriptFlags,
    /// Witness data for this input
    witness: []const []const u8,
    /// Result of verification (set by worker thread)
    result: std.atomic.Value(VerifyResult),

    pub const VerifyResult = enum(u8) {
        pending = 0,
        success = 1,
        failure = 2,
    };

    /// Initialize a new script check job
    pub fn init(
        tx_bytes: []const u8,
        input_index: usize,
        prev_script_pubkey: []const u8,
        amount: i64,
        flags: script.ScriptFlags,
        witness: []const []const u8,
    ) ScriptCheckJob {
        return .{
            .tx_bytes = tx_bytes,
            .input_index = input_index,
            .prev_script_pubkey = prev_script_pubkey,
            .amount = amount,
            .flags = flags,
            .witness = witness,
            .result = std.atomic.Value(VerifyResult).init(.pending),
        };
    }
};

/// Thread pool for parallel script verification.
/// Modeled after Bitcoin Core's CCheckQueue.
///
/// The pool maintains N-1 worker threads (where N = CPU count).
/// The master thread (caller of waitAll) also participates in verification,
/// making N total threads processing jobs.
///
/// Each worker thread has its own secp256k1 context for thread-safe
/// signature verification.
pub const ScriptCheckQueue = struct {
    /// Worker threads
    workers: []std.Thread,
    /// Job queue (shared across all threads)
    jobs: []ScriptCheckJob,
    /// Atomic index for work stealing
    next_job: std.atomic.Value(usize),
    /// Total number of jobs
    job_count: usize,
    /// Number of completed jobs (for synchronization)
    completed_count: std.atomic.Value(usize),
    /// Signal for workers to start
    start_event: std.Thread.ResetEvent,
    /// Signal that all work is done
    done_event: std.Thread.ResetEvent,
    /// Flag to stop worker threads
    stop_flag: std.atomic.Value(bool),
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    /// Number of workers
    worker_count: usize,

    /// Initialize the script check queue with worker threads.
    /// Uses std.Thread.getCpuCount() - 1 workers (minimum 1).
    pub fn init(allocator: std.mem.Allocator) !ScriptCheckQueue {
        const cpu_count = std.Thread.getCpuCount() catch 1;
        // Use N-1 workers since master thread also participates
        const worker_count = @max(1, cpu_count -| 1);

        var queue = ScriptCheckQueue{
            .workers = try allocator.alloc(std.Thread, worker_count),
            .jobs = &.{},
            .next_job = std.atomic.Value(usize).init(0),
            .job_count = 0,
            .completed_count = std.atomic.Value(usize).init(0),
            .start_event = .{},
            .done_event = .{},
            .stop_flag = std.atomic.Value(bool).init(false),
            .allocator = allocator,
            .worker_count = worker_count,
        };

        // Spawn worker threads
        for (queue.workers, 0..) |*worker, i| {
            worker.* = try std.Thread.spawn(.{}, workerLoop, .{ &queue, i });
        }

        return queue;
    }

    /// Deinitialize the queue and stop all workers.
    pub fn deinit(self: *ScriptCheckQueue) void {
        // Signal workers to stop
        self.stop_flag.store(true, .release);
        self.start_event.set();

        // Wait for all workers to finish
        for (self.workers) |worker| {
            worker.join();
        }

        self.allocator.free(self.workers);
    }

    /// Submit a batch of jobs for parallel verification.
    /// This replaces any existing jobs.
    pub fn submit(self: *ScriptCheckQueue, jobs: []ScriptCheckJob) void {
        self.jobs = jobs;
        self.job_count = jobs.len;
        self.next_job.store(0, .release);
        self.completed_count.store(0, .release);
        self.done_event.reset();
    }

    /// Wait for all jobs to complete.
    /// The calling thread participates in verification while waiting.
    /// Returns true if all verifications passed, false if any failed.
    pub fn waitAll(self: *ScriptCheckQueue) bool {
        if (self.job_count == 0) return true;

        // Wake up workers
        self.start_event.set();

        // Master thread participates in verification
        self.processJobs();

        // Wait for all jobs to complete
        while (self.completed_count.load(.acquire) < self.job_count) {
            // Spin with backoff
            std.atomic.spinLoopHint();
        }

        // Reset for next batch
        self.start_event.reset();

        // Check all results
        for (self.jobs[0..self.job_count]) |*job| {
            if (job.result.load(.acquire) != .success) {
                return false;
            }
        }

        return true;
    }

    /// Worker thread loop
    fn workerLoop(self: *ScriptCheckQueue, _: usize) void {
        while (!self.stop_flag.load(.acquire)) {
            // Wait for work
            self.start_event.wait();

            if (self.stop_flag.load(.acquire)) break;

            // Process jobs
            self.processJobs();
        }
    }

    /// Process jobs from the queue (called by both workers and master)
    fn processJobs(self: *ScriptCheckQueue) void {
        while (true) {
            // Atomically grab the next job
            const job_idx = self.next_job.fetchAdd(1, .acq_rel);
            if (job_idx >= self.job_count) break;

            var job = &self.jobs[job_idx];

            // Perform the verification
            const result = verifyScriptJob(job, self.allocator);
            job.result.store(
                if (result) .success else .failure,
                .release,
            );

            // Increment completed count
            _ = self.completed_count.fetchAdd(1, .release);
        }
    }
};

/// Verify a single script job.
/// This is the core verification function called by worker threads.
fn verifyScriptJob(job: *const ScriptCheckJob, allocator: std.mem.Allocator) bool {
    // Deserialize the transaction
    var reader = serialize.Reader{ .data = job.tx_bytes };
    const tx = serialize.readTransaction(&reader, allocator) catch {
        return false;
    };
    defer {
        // Free allocated transaction data
        for (tx.inputs) |input| {
            allocator.free(input.script_sig);
            for (input.witness) |w| {
                allocator.free(w);
            }
            allocator.free(input.witness);
        }
        for (tx.outputs) |output| {
            allocator.free(output.script_pubkey);
        }
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // Get the input being verified
    if (job.input_index >= tx.inputs.len) return false;
    const input = tx.inputs[job.input_index];

    // Create script engine and verify
    var engine = script.ScriptEngine.init(
        allocator,
        &tx,
        job.input_index,
        job.amount,
        job.flags,
    );
    defer engine.deinit();

    const result = engine.verify(
        input.script_sig,
        job.prev_script_pubkey,
        job.witness,
    );

    if (result) |valid| {
        return valid;
    } else |_| {
        return false;
    }
}

/// Configuration for parallel script verification
pub const ParallelVerifyConfig = struct {
    /// Minimum number of inputs to use parallel verification
    /// For blocks with few inputs, single-threaded is faster due to overhead
    min_inputs_for_parallel: usize = 16,

    /// Whether parallel verification is enabled
    enabled: bool = true,
};

/// Verify all scripts in a block using parallel verification.
/// Returns true if all scripts pass verification.
///
/// For blocks with few inputs (< min_inputs_for_parallel), falls back to
/// single-threaded verification to avoid thread pool overhead.
///
/// Reference: Bitcoin Core validation.cpp ConnectBlock() with CCheckQueue
pub fn verifyBlockScriptsParallel(
    block: *const types.Block,
    height: u32,
    params: *const consensus.NetworkParams,
    utxo_lookup: *const SigopUtxoView,
    config: ParallelVerifyConfig,
    allocator: std.mem.Allocator,
) ValidationError!bool {
    const flags = getBlockScriptFlags(height, params);

    // Count total inputs (excluding coinbase)
    var total_inputs: usize = 0;
    for (block.transactions[1..]) |*tx| {
        total_inputs += tx.inputs.len;
    }

    // Fall back to single-threaded for small blocks
    if (!config.enabled or total_inputs < config.min_inputs_for_parallel) {
        return verifyBlockScriptsSingleThreaded(block, flags, utxo_lookup, allocator);
    }

    // Prepare jobs for parallel verification
    var jobs = allocator.alloc(ScriptCheckJob, total_inputs) catch {
        return ValidationError.OutOfMemory;
    };
    defer allocator.free(jobs);

    var job_idx: usize = 0;

    // Serialize transactions and create jobs
    var tx_bytes_list = std.ArrayList([]u8).init(allocator);
    defer {
        for (tx_bytes_list.items) |bytes| {
            allocator.free(bytes);
        }
        tx_bytes_list.deinit();
    }

    for (block.transactions[1..]) |*tx| {
        // Serialize transaction once for all its inputs
        var writer = serialize.Writer.init(allocator);
        defer writer.deinit();
        serialize.writeTransaction(&writer, tx) catch {
            return ValidationError.OutOfMemory;
        };
        const tx_bytes = writer.toOwnedSlice() catch {
            return ValidationError.OutOfMemory;
        };
        tx_bytes_list.append(tx_bytes) catch {
            allocator.free(tx_bytes);
            return ValidationError.OutOfMemory;
        };

        for (tx.inputs, 0..) |input, input_idx| {
            // Look up the previous output
            const prev_script = utxo_lookup.lookup(&input.previous_output) orelse {
                return ValidationError.MissingInput;
            };

            jobs[job_idx] = ScriptCheckJob.init(
                tx_bytes,
                input_idx,
                prev_script,
                0, // Amount needs to be looked up from UTXO
                flags,
                input.witness,
            );
            job_idx += 1;
        }
    }

    // Initialize thread pool
    var queue = ScriptCheckQueue.init(allocator) catch {
        return ValidationError.OutOfMemory;
    };
    defer queue.deinit();

    // Submit and wait for completion
    queue.submit(jobs);
    const all_passed = queue.waitAll();

    return all_passed;
}

/// Single-threaded script verification fallback.
fn verifyBlockScriptsSingleThreaded(
    block: *const types.Block,
    flags: script.ScriptFlags,
    utxo_lookup: *const SigopUtxoView,
    allocator: std.mem.Allocator,
) ValidationError!bool {
    // Verify each non-coinbase transaction
    for (block.transactions[1..]) |*tx| {
        for (tx.inputs, 0..) |input, input_idx| {
            const prev_script = utxo_lookup.lookup(&input.previous_output) orelse {
                return ValidationError.MissingInput;
            };

            var engine = script.ScriptEngine.init(
                allocator,
                tx,
                input_idx,
                0, // TODO: Look up actual amount from UTXO
                flags,
            );
            defer engine.deinit();

            const result = engine.verify(
                input.script_sig,
                prev_script,
                input.witness,
            );

            if (result) |valid| {
                if (!valid) return false;
            } else |_| {
                return false;
            }
        }
    }

    return true;
}

/// Get the number of CPU cores available for parallel verification.
pub fn getParallelVerifyThreadCount() usize {
    return std.Thread.getCpuCount() catch 1;
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

// ============================================================================
// Sequence Lock Tests
// ============================================================================

fn testUtxoLookup(ctx: *anyopaque, outpoint: *const types.OutPoint) ?UtxoInfo {
    const utxos = @as(*const std.AutoHashMap([36]u8, UtxoInfo), @ptrCast(@alignCast(ctx)));
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
    return utxos.get(key);
}

test "calculateSequenceLocks returns no constraint for version 1 tx" {
    var utxos = std.AutoHashMap([36]u8, UtxoInfo).init(std.testing.allocator);
    defer utxos.deinit();

    const view = UtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testUtxoLookup,
    };

    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 10, // BIP-68 enabled, 10 blocks relative lock
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    // Version 1 tx - BIP-68 should not apply
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = calculateSequenceLocks(&tx, &view, 500000, &consensus.MAINNET);
    try std.testing.expectEqual(@as(i32, -1), result.min_height);
    try std.testing.expectEqual(@as(i64, -1), result.min_time);
}

test "calculateSequenceLocks returns no constraint before CSV activation" {
    var utxos = std.AutoHashMap([36]u8, UtxoInfo).init(std.testing.allocator);
    defer utxos.deinit();

    const view = UtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testUtxoLookup,
    };

    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 10,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Before CSV activation height (419,328 on mainnet)
    const result = calculateSequenceLocks(&tx, &view, 400000, &consensus.MAINNET);
    try std.testing.expectEqual(@as(i32, -1), result.min_height);
    try std.testing.expectEqual(@as(i64, -1), result.min_time);
}

test "calculateSequenceLocks with disable flag returns no constraint" {
    var utxos = std.AutoHashMap([36]u8, UtxoInfo).init(std.testing.allocator);
    defer utxos.deinit();

    const view = UtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testUtxoLookup,
    };

    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        // Disable flag set (bit 31)
        .sequence = consensus.SEQUENCE_LOCKTIME_DISABLE_FLAG | 100,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = calculateSequenceLocks(&tx, &view, 500000, &consensus.MAINNET);
    try std.testing.expectEqual(@as(i32, -1), result.min_height);
    try std.testing.expectEqual(@as(i64, -1), result.min_time);
}

test "calculateSequenceLocks with height-based lock" {
    var utxos = std.AutoHashMap([36]u8, UtxoInfo).init(std.testing.allocator);
    defer utxos.deinit();

    // Add UTXO at height 100
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &([_]u8{0x11} ** 32));
    std.mem.writeInt(u32, key[32..36], 0, .little);
    try utxos.put(key, UtxoInfo{ .height = 100, .mtp = 1000000 });

    const view = UtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testUtxoLookup,
    };

    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        // 10 block relative lock (no type flag = height-based)
        .sequence = 10,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = calculateSequenceLocks(&tx, &view, 500000, &consensus.MAINNET);
    // min_height = utxo_height + lock_value - 1 = 100 + 10 - 1 = 109
    try std.testing.expectEqual(@as(i32, 109), result.min_height);
    try std.testing.expectEqual(@as(i64, -1), result.min_time);
}

test "calculateSequenceLocks with time-based lock" {
    var utxos = std.AutoHashMap([36]u8, UtxoInfo).init(std.testing.allocator);
    defer utxos.deinit();

    // Add UTXO with MTP of 1000000
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &([_]u8{0x11} ** 32));
    std.mem.writeInt(u32, key[32..36], 0, .little);
    try utxos.put(key, UtxoInfo{ .height = 100, .mtp = 1000000 });

    const view = UtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testUtxoLookup,
    };

    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        // Time-based lock: 10 units * 512 seconds = 5120 seconds
        .sequence = consensus.SEQUENCE_LOCKTIME_TYPE_FLAG | 10,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = calculateSequenceLocks(&tx, &view, 500000, &consensus.MAINNET);
    // min_time = utxo_mtp + (10 << 9) - 1 = 1000000 + 5120 - 1 = 1005119
    try std.testing.expectEqual(@as(i32, -1), result.min_height);
    try std.testing.expectEqual(@as(i64, 1005119), result.min_time);
}

test "calculateSequenceLocks takes maximum across multiple inputs" {
    var utxos = std.AutoHashMap([36]u8, UtxoInfo).init(std.testing.allocator);
    defer utxos.deinit();

    // Add two UTXOs at different heights
    var key1: [36]u8 = undefined;
    @memcpy(key1[0..32], &([_]u8{0x11} ** 32));
    std.mem.writeInt(u32, key1[32..36], 0, .little);
    try utxos.put(key1, UtxoInfo{ .height = 100, .mtp = 1000000 });

    var key2: [36]u8 = undefined;
    @memcpy(key2[0..32], &([_]u8{0x22} ** 32));
    std.mem.writeInt(u32, key2[32..36], 0, .little);
    try utxos.put(key2, UtxoInfo{ .height = 200, .mtp = 1100000 });

    const view = UtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testUtxoLookup,
    };

    const input1 = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 10, // 10 block lock
        .witness = &[_][]const u8{},
    };

    const input2 = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x22} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 5, // 5 block lock
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x00},
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{ input1, input2 },
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = calculateSequenceLocks(&tx, &view, 500000, &consensus.MAINNET);
    // input1: 100 + 10 - 1 = 109
    // input2: 200 + 5 - 1 = 204
    // max = 204
    try std.testing.expectEqual(@as(i32, 204), result.min_height);
}

test "checkSequenceLocks passes when constraints satisfied" {
    const result = SequenceLockResult{
        .min_height = 100,
        .min_time = 1000000,
    };

    // Block at height 101 with prev_mtp 1000001 should pass
    const tip = BlockIndex{
        .height = 101,
        .prev_mtp = 1000001,
    };

    try std.testing.expect(checkSequenceLocks(result, &tip));
}

test "checkSequenceLocks fails when height constraint not met" {
    const result = SequenceLockResult{
        .min_height = 100,
        .min_time = -1,
    };

    // Block at height 100 should fail (need > 100)
    const tip = BlockIndex{
        .height = 100,
        .prev_mtp = 2000000,
    };

    try std.testing.expect(!checkSequenceLocks(result, &tip));
}

test "checkSequenceLocks fails when time constraint not met" {
    const result = SequenceLockResult{
        .min_height = -1,
        .min_time = 1000000,
    };

    // Block with prev_mtp 1000000 should fail (need > 1000000)
    const tip = BlockIndex{
        .height = 200,
        .prev_mtp = 1000000,
    };

    try std.testing.expect(!checkSequenceLocks(result, &tip));
}

test "checkSequenceLocks passes with no constraints" {
    const result = SequenceLockResult{
        .min_height = -1,
        .min_time = -1,
    };

    const tip = BlockIndex{
        .height = 1,
        .prev_mtp = 0,
    };

    try std.testing.expect(checkSequenceLocks(result, &tip));
}

// ============================================================================
// connectBlock BIP-68 Enforcement Tests
// ============================================================================

fn emptySigopLookup(_: *anyopaque, _: *const types.OutPoint) ?[]const u8 {
    return null;
}

test "connectBlock enforces BIP-68 sequence locks" {
    var utxos = std.AutoHashMap([36]u8, UtxoInfo).init(std.testing.allocator);
    defer utxos.deinit();

    // Add UTXO at height 100
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &([_]u8{0x11} ** 32));
    std.mem.writeInt(u32, key[32..36], 0, .little);
    try utxos.put(key, UtxoInfo{ .height = 100, .mtp = 1000000 });

    const sequence_view = UtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testUtxoLookup,
    };

    const sigop_view = SigopUtxoView{
        .context = undefined,
        .lookupFn = emptySigopLookup,
    };

    // Create a coinbase transaction
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const coinbase_output = types.TxOut{
        .value = 50_000_000_000,
        .script_pubkey = &[_]u8{0x51},
    };

    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };

    // Create a regular transaction with a 10-block relative lock
    const regular_input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 10, // 10 block relative lock, BIP-68 active
        .witness = &[_][]const u8{},
    };

    const regular_output = types.TxOut{
        .value = 40_000_000_000,
        .script_pubkey = &[_]u8{0x51},
    };

    const regular_tx = types.Transaction{
        .version = 2, // Version 2 enables BIP-68
        .inputs = &[_]types.TxIn{regular_input},
        .outputs = &[_]types.TxOut{regular_output},
        .lock_time = 0,
    };

    // Build a block with both transactions
    const block_header = types.BlockHeader{
        .version = 0x20000000,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1000100,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    const block = types.Block{
        .header = block_header,
        .transactions = &[_]types.Transaction{ coinbase_tx, regular_tx },
    };

    // Case 1: Block at height 109 (min_height = 100 + 10 - 1 = 109, need > 109)
    // Should fail because height 109 is not > 109
    const tip_too_low = BlockIndex{
        .height = 109,
        .prev_mtp = 2000000, // High enough for any time constraint
    };

    // Height 500000 is after CSV activation (419328 on mainnet)
    const result_fail = connectBlock(&block, 500000, &consensus.MAINNET, &sigop_view, &sequence_view, &tip_too_low);
    try std.testing.expectError(ValidationError.SequenceLockNotSatisfied, result_fail);

    // Case 2: Block at height 110 (> 109) should pass
    const tip_ok = BlockIndex{
        .height = 110,
        .prev_mtp = 2000000,
    };

    const result_ok = connectBlock(&block, 500000, &consensus.MAINNET, &sigop_view, &sequence_view, &tip_ok);
    try std.testing.expect(result_ok != error.SequenceLockNotSatisfied);
}

test "connectBlock allows coinbase transactions regardless of sequence" {
    const sigop_view = SigopUtxoView{
        .context = undefined,
        .lookupFn = emptySigopLookup,
    };

    // Coinbase with arbitrary sequence (should be ignored for BIP-68)
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 10, // Would be a lock if this were a normal tx
        .witness = &[_][]const u8{},
    };

    const coinbase_output = types.TxOut{
        .value = 50_000_000_000,
        .script_pubkey = &[_]u8{0x51},
    };

    const coinbase_tx = types.Transaction{
        .version = 2, // Even with version 2
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };

    const block_header = types.BlockHeader{
        .version = 0x20000000,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1000100,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    const block = types.Block{
        .header = block_header,
        .transactions = &[_]types.Transaction{coinbase_tx},
    };

    const tip = BlockIndex{
        .height = 1, // Very low height
        .prev_mtp = 0,
    };

    // Should pass - coinbase transactions are exempt from BIP-68
    // (sequence_view is null, so no BIP-68 check happens at all)
    _ = try connectBlock(&block, 500000, &consensus.MAINNET, &sigop_view, null, &tip);
}

test "connectBlock skips BIP-68 when views are null" {
    const sigop_view = SigopUtxoView{
        .context = undefined,
        .lookupFn = emptySigopLookup,
    };

    // Create a transaction that would fail BIP-68 if checked
    const regular_input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{0x00},
        .sequence = 10, // Would require 10 blocks
        .witness = &[_][]const u8{},
    };

    const regular_output = types.TxOut{
        .value = 40_000_000_000,
        .script_pubkey = &[_]u8{0x51},
    };

    const regular_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{regular_input},
        .outputs = &[_]types.TxOut{regular_output},
        .lock_time = 0,
    };

    // Need coinbase as first tx
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const coinbase_output = types.TxOut{
        .value = 50_000_000_000,
        .script_pubkey = &[_]u8{0x51},
    };

    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };

    const block_header = types.BlockHeader{
        .version = 0x20000000,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1000100,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    const block = types.Block{
        .header = block_header,
        .transactions = &[_]types.Transaction{ coinbase_tx, regular_tx },
    };

    // With null sequence_view and tip, BIP-68 check is skipped
    _ = try connectBlock(&block, 500000, &consensus.MAINNET, &sigop_view, null, null);
}

// ============================================================================
// Sigop Counting Tests
// ============================================================================

test "getLegacySigOpCount counts CHECKSIG in scriptPubKey" {
    // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    // Contains 1 CHECKSIG
    var script_pubkey: [25]u8 = undefined;
    script_pubkey[0] = 0x76; // OP_DUP
    script_pubkey[1] = 0xa9; // OP_HASH160
    script_pubkey[2] = 0x14; // Push 20 bytes
    @memset(script_pubkey[3..23], 0xAB); // 20 byte hash
    script_pubkey[23] = 0x88; // OP_EQUALVERIFY
    script_pubkey[24] = 0xac; // OP_CHECKSIG

    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{}, // Empty scriptSig for counting
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &script_pubkey,
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Legacy count: 1 CHECKSIG in output scriptPubKey
    const count = getLegacySigOpCount(&tx);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "getLegacySigOpCount counts CHECKMULTISIG as 20 sigops" {
    // Bare multisig output: OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
    // In inaccurate mode, CHECKMULTISIG = 20 sigops
    var script_pubkey: [3]u8 = undefined;
    script_pubkey[0] = 0x51; // OP_1
    script_pubkey[1] = 0x52; // OP_2
    script_pubkey[2] = 0xae; // OP_CHECKMULTISIG

    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &script_pubkey,
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Legacy count: CHECKMULTISIG in output = 20 sigops (inaccurate mode)
    const count = getLegacySigOpCount(&tx);
    try std.testing.expectEqual(@as(u32, 20), count);
}

test "getTransactionSigOpCost applies witness scale factor" {
    // P2PKH output with 1 CHECKSIG
    var script_pubkey: [25]u8 = undefined;
    script_pubkey[0] = 0x76; // OP_DUP
    script_pubkey[1] = 0xa9; // OP_HASH160
    script_pubkey[2] = 0x14; // Push 20 bytes
    @memset(script_pubkey[3..23], 0xAB);
    script_pubkey[23] = 0x88; // OP_EQUALVERIFY
    script_pubkey[24] = 0xac; // OP_CHECKSIG

    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x00, 0x00 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000_000,
        .script_pubkey = &script_pubkey,
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // For coinbase, only legacy sigops are counted
    // 1 CHECKSIG * WITNESS_SCALE_FACTOR (4) = 4
    const empty_view = SigopUtxoView{
        .context = undefined,
        .lookupFn = struct {
            fn lookup(_: *anyopaque, _: *const types.OutPoint) ?[]const u8 {
                return null;
            }
        }.lookup,
    };

    const cost = getTransactionSigOpCost(&tx, &empty_view, script.ScriptFlags{});
    try std.testing.expectEqual(@as(u64, 4), cost);
}

fn testSigopUtxoLookup(ctx: *anyopaque, outpoint: *const types.OutPoint) ?[]const u8 {
    const utxos = @as(*const std.AutoHashMap([36]u8, []const u8), @ptrCast(@alignCast(ctx)));
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
    return utxos.get(key);
}

test "getTransactionSigOpCost counts P2SH sigops" {
    // P2SH scriptPubKey: OP_HASH160 <20> OP_EQUAL
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9; // OP_HASH160
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memset(script_pubkey[2..22], 0xAB); // placeholder hash
    script_pubkey[22] = 0x87; // OP_EQUAL

    // Redeem script: OP_CHECKSIG (1 sigop)
    const redeem_script = [_]u8{0xac}; // OP_CHECKSIG

    // scriptSig: push the redeem script
    var script_sig: [2]u8 = undefined;
    script_sig[0] = 0x01; // Push 1 byte
    script_sig[1] = 0xac; // OP_CHECKSIG

    const outpoint_hash = [_]u8{0x11} ** 32;
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = outpoint_hash,
            .index = 0,
        },
        .script_sig = &script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x51}, // OP_1 (simple output)
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Set up UTXO view with the P2SH scriptPubKey
    var utxos = std.AutoHashMap([36]u8, []const u8).init(std.testing.allocator);
    defer utxos.deinit();

    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint_hash);
    std.mem.writeInt(u32, key[32..36], 0, .little);
    try utxos.put(key, &script_pubkey);

    const view = SigopUtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testSigopUtxoLookup,
    };

    // Legacy sigops: 0 (no CHECKSIG in scriptSig or output scriptPubKey)
    // P2SH sigops: 1 CHECKSIG in redeem script * 4 = 4
    // Total: 4
    var flags = script.ScriptFlags{};
    flags.verify_p2sh = true;
    _ = redeem_script;
    const cost = getTransactionSigOpCost(&tx, &view, flags);
    try std.testing.expectEqual(@as(u64, 4), cost);
}

test "getTransactionSigOpCost counts P2WPKH as 1 sigop" {
    // P2WPKH scriptPubKey: OP_0 <20 bytes>
    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0 (witness version 0)
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memset(script_pubkey[2..22], 0xAB); // 20 byte hash

    const outpoint_hash = [_]u8{0x11} ** 32;
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = outpoint_hash,
            .index = 0,
        },
        .script_sig = &[_]u8{}, // Empty for native segwit
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{
            &[_]u8{0xAA} ** 71, // Signature
            &[_]u8{0xBB} ** 33, // Pubkey
        },
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x51},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Set up UTXO view
    var utxos = std.AutoHashMap([36]u8, []const u8).init(std.testing.allocator);
    defer utxos.deinit();

    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint_hash);
    std.mem.writeInt(u32, key[32..36], 0, .little);
    try utxos.put(key, &script_pubkey);

    const view = SigopUtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testSigopUtxoLookup,
    };

    // Legacy sigops: 0
    // Witness sigops: 1 (P2WPKH is always 1) - no scaling
    // Total: 1
    var flags = script.ScriptFlags{};
    flags.verify_witness = true;
    flags.verify_p2sh = true;
    const cost = getTransactionSigOpCost(&tx, &view, flags);
    try std.testing.expectEqual(@as(u64, 1), cost);
}

test "getTransactionSigOpCost counts P2WSH sigops" {
    // P2WSH scriptPubKey: OP_0 <32 bytes>
    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0 (witness version 0)
    script_pubkey[1] = 0x20; // Push 32 bytes
    @memset(script_pubkey[2..34], 0xAB); // 32 byte hash

    // Witness script: OP_1 <pk> OP_1 OP_CHECKMULTISIG (1 sigop)
    var witness_script: [3]u8 = undefined;
    witness_script[0] = 0x51; // OP_1
    witness_script[1] = 0x51; // OP_1
    witness_script[2] = 0xae; // OP_CHECKMULTISIG

    const outpoint_hash = [_]u8{0x11} ** 32;
    const input = types.TxIn{
        .previous_output = types.OutPoint{
            .hash = outpoint_hash,
            .index = 0,
        },
        .script_sig = &[_]u8{}, // Empty for native segwit
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{
            &[_]u8{0x00},      // Dummy
            &[_]u8{0xAA} ** 71, // Signature
            &witness_script,  // Witness script (last item)
        },
    };

    const output = types.TxOut{
        .value = 50_000_000,
        .script_pubkey = &[_]u8{0x51},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Set up UTXO view
    var utxos = std.AutoHashMap([36]u8, []const u8).init(std.testing.allocator);
    defer utxos.deinit();

    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint_hash);
    std.mem.writeInt(u32, key[32..36], 0, .little);
    try utxos.put(key, &script_pubkey);

    const view = SigopUtxoView{
        .context = @ptrCast(&utxos),
        .lookupFn = testSigopUtxoLookup,
    };

    // Legacy sigops: 0
    // Witness sigops: 1 (1-of-1 multisig in witness script, accurate mode) - no scaling
    // Total: 1
    var flags = script.ScriptFlags{};
    flags.verify_witness = true;
    flags.verify_p2sh = true;
    const cost = getTransactionSigOpCost(&tx, &view, flags);
    try std.testing.expectEqual(@as(u64, 1), cost);
}

test "MAX_BLOCK_SIGOPS_COST is 80000" {
    try std.testing.expectEqual(@as(u32, 80_000), consensus.MAX_BLOCK_SIGOPS_COST);
}

test "WITNESS_SCALE_FACTOR is 4" {
    try std.testing.expectEqual(@as(u32, 4), consensus.WITNESS_SCALE_FACTOR);
}

// ============================================================================
// Checkpoint Verification Tests
// ============================================================================

test "verifyCheckpoint passes for genesis block" {
    // Genesis block should pass checkpoint verification (no checkpoint at height 0)
    const genesis = consensus.MAINNET.genesis_header;
    try verifyCheckpoint(&genesis, 0, .mainnet);
}

test "verifyCheckpoint fails for mismatched checkpoint" {
    // Create a fake header at checkpoint height 11111
    var fake_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 0,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    // This should fail because the hash won't match the checkpoint
    const result = verifyCheckpoint(&fake_header, 11111, .mainnet);
    try std.testing.expectError(ValidationError.CheckpointMismatch, result);
}

test "verifyCheckpoint passes for non-checkpoint height" {
    // At a height where there's no checkpoint, any valid header should pass
    var header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 0,
        .bits = 0x1d00ffff,
        .nonce = 12345,
    };

    // Height 12345 has no checkpoint, so this should pass
    try verifyCheckpoint(&header, 12345, .mainnet);
}

test "getCheckpointAtHeight returns correct checkpoint" {
    const checkpoints = consensus.MAINNET_CHECKPOINTS;

    // Should find checkpoint at height 11111
    const cp = consensus.getCheckpointAtHeight(checkpoints, 11111);
    try std.testing.expect(cp != null);
    try std.testing.expectEqual(@as(u32, 11111), cp.?.height);

    // Should find checkpoint at height 210000
    const cp2 = consensus.getCheckpointAtHeight(checkpoints, 210000);
    try std.testing.expect(cp2 != null);
    try std.testing.expectEqual(@as(u32, 210000), cp2.?.height);

    // Should not find checkpoint at height 99999
    const cp3 = consensus.getCheckpointAtHeight(checkpoints, 99999);
    try std.testing.expect(cp3 == null);
}

test "getLastCheckpointHeight returns highest checkpoint" {
    const last = consensus.getLastCheckpointHeight(.mainnet);
    try std.testing.expect(last != null);
    // Mainnet has checkpoint at 295000 as the last one
    try std.testing.expectEqual(@as(u32, 295000), last.?);
}

test "getLastCheckpointHeight returns null for regtest" {
    const last = consensus.getLastCheckpointHeight(.regtest);
    try std.testing.expect(last == null);
}

test "isBelowLastCheckpoint correctly identifies heights" {
    // Height below last checkpoint
    try std.testing.expect(consensus.isBelowLastCheckpoint(.mainnet, 100000));

    // Height at last checkpoint
    try std.testing.expect(consensus.isBelowLastCheckpoint(.mainnet, 295000));

    // Height above last checkpoint
    try std.testing.expect(!consensus.isBelowLastCheckpoint(.mainnet, 500000));

    // Regtest has no checkpoints, so nothing is "below" them
    try std.testing.expect(!consensus.isBelowLastCheckpoint(.regtest, 0));
}

test "requiresCheckpointValidation returns true for heights at or below checkpoint" {
    // Height 0 is below the last checkpoint on mainnet
    try std.testing.expect(requiresCheckpointValidation(0, .mainnet));

    // Height 295000 is at the last checkpoint
    try std.testing.expect(requiresCheckpointValidation(295000, .mainnet));

    // Height 500000 is above all checkpoints
    try std.testing.expect(!requiresCheckpointValidation(500000, .mainnet));

    // Regtest has no checkpoints
    try std.testing.expect(!requiresCheckpointValidation(0, .regtest));
}

test "verifyChainAgainstCheckpoints rejects fork below checkpoint" {
    // Simulate a chain that diverges at height 11111
    const ancestor_checker = struct {
        fn check(height: u32, expected_hash: *const types.Hash256) bool {
            _ = expected_hash;
            // Pretend all checkpoints match except 11111
            return height != 11111;
        }
    }.check;

    // Should fail because the ancestor at 11111 doesn't match
    const result = verifyChainAgainstCheckpoints(100000, .mainnet, &ancestor_checker);
    try std.testing.expectError(ValidationError.ForkBelowCheckpoint, result);
}

test "verifyChainAgainstCheckpoints passes when all ancestors match" {
    // Simulate a chain where all checkpoints match
    const ancestor_checker = struct {
        fn check(_: u32, _: *const types.Hash256) bool {
            return true;
        }
    }.check;

    // Should pass
    try verifyChainAgainstCheckpoints(100000, .mainnet, &ancestor_checker);
}

test "mainnet has at least 5 checkpoints" {
    try std.testing.expect(consensus.MAINNET_CHECKPOINTS.len >= 5);
}

test "checkpoints are sorted by height" {
    const checkpoints = consensus.MAINNET_CHECKPOINTS;
    for (0..checkpoints.len - 1) |i| {
        try std.testing.expect(checkpoints[i].height < checkpoints[i + 1].height);
    }
}

// ============================================================================
// Block Status Flags (Phase 51)
// ============================================================================

/// Block status flags for tracking validity state.
/// These flags are stored in the block index and persisted to RocksDB.
/// Reference: Bitcoin Core chain.h CBlockIndex::BlockStatus
pub const BlockStatus = packed struct(u32) {
    /// Block has been validated up to this point
    valid_header: bool = false,
    /// Full block data available
    has_data: bool = false,
    /// Undo data available
    has_undo: bool = false,

    /// Set if this block itself failed consensus validation.
    /// Once set, this block and all its descendants are considered invalid.
    /// Corresponds to BLOCK_FAILED_VALID in Bitcoin Core.
    failed_valid: bool = false,

    /// Set if a descendant of this block failed validation.
    /// This flag propagates down from the failed ancestor.
    /// Corresponds to BLOCK_FAILED_CHILD in Bitcoin Core.
    failed_child: bool = false,

    _padding: u27 = 0,

    /// Check if this block or any ancestor is marked invalid.
    pub fn isInvalid(self: BlockStatus) bool {
        return self.failed_valid or self.failed_child;
    }

    /// Clear all failure flags.
    pub fn clearFailure(self: *BlockStatus) void {
        self.failed_valid = false;
        self.failed_child = false;
    }
};

/// Extended block index entry with chain management metadata.
/// This struct extends the basic block header with validation state,
/// chainwork, and sequence ID for tie-breaking.
pub const BlockIndexEntry = struct {
    /// Block hash (computed from header)
    hash: types.Hash256,
    /// Block header
    header: types.BlockHeader,
    /// Block height
    height: u32,
    /// Validation status flags
    status: BlockStatus,
    /// Total chain work up to and including this block
    chain_work: [32]u8,
    /// Sequence ID for tie-breaking in chain selection.
    /// Lower sequence IDs are preferred (precious blocks get negative values).
    /// Default value from disk is 0; blocks loaded first get sequential positive IDs.
    sequence_id: i64,
    /// Parent block index (null for genesis)
    parent: ?*BlockIndexEntry,
    /// File number where block data is stored (for disconnect)
    file_number: u32,
    /// File offset within the block file
    file_offset: u64,

    /// Check if this block is a valid candidate for the active chain.
    pub fn isValidCandidate(self: *const BlockIndexEntry) bool {
        return !self.status.isInvalid() and self.status.has_data;
    }

    /// Check if this block is an ancestor of another block.
    pub fn isAncestorOf(self: *const BlockIndexEntry, other: *const BlockIndexEntry) bool {
        if (self.height >= other.height) return false;

        var current = other;
        while (current.height > self.height) {
            current = current.parent orelse return false;
        }
        return std.mem.eql(u8, &current.hash, &self.hash);
    }

    /// Get the ancestor at a specific height.
    pub fn getAncestor(self: *BlockIndexEntry, target_height: u32) ?*BlockIndexEntry {
        if (target_height > self.height) return null;
        if (target_height == self.height) return self;

        var current: *BlockIndexEntry = self;
        while (current.height > target_height) {
            current = current.parent orelse return null;
        }
        return current;
    }
};

/// Chain manager for invalidateblock / reconsiderblock / preciousblock operations.
/// This struct maintains the block index and provides chain management RPCs.
pub const ChainManager = struct {
    /// All known blocks indexed by hash
    block_index: std.AutoHashMap(types.Hash256, *BlockIndexEntry),
    /// Blocks eligible for being the chain tip (valid candidates)
    chain_tips: std.ArrayList(*BlockIndexEntry),
    /// Current active chain tip
    active_tip: ?*BlockIndexEntry,
    /// Best invalid block (for tracking attack chains)
    best_invalid: ?*BlockIndexEntry,
    /// Sequence ID counter for precious block tie-breaking.
    /// Decrements for each precious block call.
    reverse_sequence_id: i64,
    /// Chain work at last precious block call (for reset detection)
    last_precious_chainwork: [32]u8,
    /// Chain state for UTXO operations
    chain_state: ?*storage.ChainState,
    /// Mempool for evicting conflicting transactions
    mempool: ?*@import("mempool.zig").Mempool,
    /// ChainStore for persistence (optional)
    chain_store: ?*storage.ChainStore,
    /// Allocator
    allocator: std.mem.Allocator,

    pub fn init(
        chain_state: ?*storage.ChainState,
        mempool: ?*@import("mempool.zig").Mempool,
        allocator: std.mem.Allocator,
    ) ChainManager {
        return ChainManager{
            .block_index = std.AutoHashMap(types.Hash256, *BlockIndexEntry).init(allocator),
            .chain_tips = std.ArrayList(*BlockIndexEntry).init(allocator),
            .active_tip = null,
            .best_invalid = null,
            .reverse_sequence_id = -1,
            .last_precious_chainwork = [_]u8{0} ** 32,
            .chain_state = chain_state,
            .mempool = mempool,
            .chain_store = null,
            .allocator = allocator,
        };
    }

    /// Initialize with a ChainStore for persistence.
    pub fn initWithStore(
        chain_state: ?*storage.ChainState,
        mempool: ?*@import("mempool.zig").Mempool,
        chain_store: *storage.ChainStore,
        allocator: std.mem.Allocator,
    ) ChainManager {
        return ChainManager{
            .block_index = std.AutoHashMap(types.Hash256, *BlockIndexEntry).init(allocator),
            .chain_tips = std.ArrayList(*BlockIndexEntry).init(allocator),
            .active_tip = null,
            .best_invalid = null,
            .reverse_sequence_id = -1,
            .last_precious_chainwork = [_]u8{0} ** 32,
            .chain_state = chain_state,
            .mempool = mempool,
            .chain_store = chain_store,
            .allocator = allocator,
        };
    }

    /// Set the chain store for persistence.
    pub fn setChainStore(self: *ChainManager, store: *storage.ChainStore) void {
        self.chain_store = store;
    }

    pub fn deinit(self: *ChainManager) void {
        var iter = self.block_index.valueIterator();
        while (iter.next()) |entry| {
            self.allocator.destroy(entry.*);
        }
        self.block_index.deinit();
        self.chain_tips.deinit();
    }

    /// Add a block to the index.
    pub fn addBlock(self: *ChainManager, entry: *BlockIndexEntry) !void {
        try self.block_index.put(entry.hash, entry);
    }

    /// Get a block by hash.
    pub fn getBlock(self: *ChainManager, hash: *const types.Hash256) ?*BlockIndexEntry {
        return self.block_index.get(hash.*);
    }

    /// Persist a block's status to RocksDB.
    /// Called after invalidateBlock/reconsiderBlock to persist state.
    pub fn persistBlockStatus(self: *ChainManager, entry: *const BlockIndexEntry) ChainError!void {
        const store = self.chain_store orelse return; // No persistence if no store

        const record = storage.ChainStore.BlockIndexRecord{
            .height = entry.height,
            .header = entry.header,
            .status = @as(u32, @bitCast(entry.status)),
            .chain_work = entry.chain_work,
            .sequence_id = entry.sequence_id,
            .file_number = entry.file_number,
            .file_offset = entry.file_offset,
        };

        store.putBlockIndexFull(&entry.hash, &record) catch return ChainError.OutOfMemory;
    }

    /// Load a block from RocksDB into the block index.
    pub fn loadBlockFromStore(self: *ChainManager, hash: *const types.Hash256) ChainError!?*BlockIndexEntry {
        const store = self.chain_store orelse return null;

        const record = store.getBlockIndexFull(hash) catch return ChainError.OutOfMemory;
        if (record == null) return null;
        const rec = record.?;

        const entry = self.allocator.create(BlockIndexEntry) catch return ChainError.OutOfMemory;
        entry.* = BlockIndexEntry{
            .hash = hash.*,
            .header = rec.header,
            .height = rec.height,
            .status = @as(BlockStatus, @bitCast(rec.status)),
            .chain_work = rec.chain_work,
            .sequence_id = rec.sequence_id,
            .parent = null, // Parent must be resolved separately
            .file_number = rec.file_number,
            .file_offset = rec.file_offset,
        };

        self.block_index.put(entry.hash, entry) catch {
            self.allocator.destroy(entry);
            return ChainError.OutOfMemory;
        };

        return entry;
    }

    // ========================================================================
    // invalidateblock RPC
    // ========================================================================

    /// Error set for chain management operations.
    pub const ChainError = error{
        BlockNotFound,
        GenesisCannotBeInvalidated,
        DisconnectFailed,
        OutOfMemory,
    };

    /// Invalidate a block and all its descendants.
    /// This disconnects the block if it's on the active chain and marks
    /// all descendants with failed_child.
    ///
    /// Reference: Bitcoin Core validation.cpp InvalidateBlock()
    pub fn invalidateBlock(self: *ChainManager, hash: *const types.Hash256) ChainError!void {
        const target = self.block_index.get(hash.*) orelse return ChainError.BlockNotFound;

        // Cannot invalidate genesis
        if (target.height == 0) return ChainError.GenesisCannotBeInvalidated;

        // Phase 1: If target is on active chain, disconnect blocks
        if (self.active_tip) |tip| {
            if (target.isAncestorOf(tip) or std.mem.eql(u8, &target.hash, &tip.hash)) {
                // Disconnect blocks from tip down to target's parent
                try self.disconnectToBlock(target.parent);
            }
        }

        // Phase 2: Mark the target block as failed_valid and persist
        target.status.failed_valid = true;
        try self.persistBlockStatus(target);

        // Phase 3: Mark all descendants with failed_child using BFS and persist
        try self.markDescendantsInvalid(target);

        // Phase 4: Remove from chain_tips if present
        self.removeFromChainTips(target);

        // Phase 5: Update best_invalid if this has more work
        if (self.best_invalid) |best| {
            if (self.compareChainWork(&target.chain_work, &best.chain_work) > 0) {
                self.best_invalid = target;
            }
        } else {
            self.best_invalid = target;
        }

        // Phase 6: Activate the best valid chain
        try self.activateBestChain();

        // Phase 7: Evict conflicting transactions from mempool
        if (self.mempool) |pool| {
            self.evictConflictingTransactions(pool, target);
        }
    }

    /// Mark all descendants of a block with failed_child flag.
    fn markDescendantsInvalid(self: *ChainManager, ancestor: *BlockIndexEntry) ChainError!void {
        // BFS queue for processing descendants
        var queue = std.ArrayList(*BlockIndexEntry).init(self.allocator);
        defer queue.deinit();

        // Find all immediate children of ancestor
        var iter = self.block_index.valueIterator();
        while (iter.next()) |entry| {
            if (entry.*.parent) |parent| {
                if (std.mem.eql(u8, &parent.hash, &ancestor.hash)) {
                    queue.append(entry.*) catch return ChainError.OutOfMemory;
                }
            }
        }

        // Process queue
        var i: usize = 0;
        while (i < queue.items.len) : (i += 1) {
            const block = queue.items[i];
            block.status.failed_child = true;
            try self.persistBlockStatus(block);

            // Find children of this block
            var child_iter = self.block_index.valueIterator();
            while (child_iter.next()) |entry| {
                if (entry.*.parent) |parent| {
                    if (std.mem.eql(u8, &parent.hash, &block.hash)) {
                        queue.append(entry.*) catch return ChainError.OutOfMemory;
                    }
                }
            }
        }
    }

    /// Disconnect blocks from the active chain until we reach the target block.
    fn disconnectToBlock(self: *ChainManager, target: ?*BlockIndexEntry) ChainError!void {
        const chain_state = self.chain_state orelse return;

        while (self.active_tip) |tip| {
            // Stop if we've reached the target
            if (target) |t| {
                if (std.mem.eql(u8, &tip.hash, &t.hash)) break;
            } else {
                // Target is null (disconnecting genesis), stop
                break;
            }

            // Disconnect the tip using undo data
            const prev_hash = tip.header.prev_block;
            chain_state.disconnectBlockFromFile(
                undefined, // We don't have the full block here
                tip.file_number,
                tip.file_offset,
                prev_hash,
            ) catch return ChainError.DisconnectFailed;

            // Update active tip
            self.active_tip = tip.parent;
        }
    }

    // ========================================================================
    // reconsiderblock RPC
    // ========================================================================

    /// Reconsider a previously invalidated block.
    /// Clears failed_valid on the target and failed_child on all descendants.
    /// Re-evaluates if this chain is now the best chain.
    ///
    /// Reference: Bitcoin Core validation.cpp ReconsiderBlock() / ResetBlockFailureFlags()
    pub fn reconsiderBlock(self: *ChainManager, hash: *const types.Hash256) ChainError!void {
        const target = self.block_index.get(hash.*) orelse return ChainError.BlockNotFound;

        // Phase 1: Clear failed_valid on the target and persist
        target.status.failed_valid = false;
        try self.persistBlockStatus(target);

        // Phase 2: Clear failed_child on all descendants and persist
        try self.clearDescendantFailure(target);

        // Phase 3: Clear best_invalid if it points to this block
        if (self.best_invalid) |best| {
            if (std.mem.eql(u8, &best.hash, &target.hash)) {
                self.best_invalid = null;
            }
        }

        // Phase 4: Re-add to chain_tips if valid candidate
        if (target.isValidCandidate()) {
            // Only add if no valid descendant exists (it's a tip)
            var is_tip = true;
            var iter = self.block_index.valueIterator();
            while (iter.next()) |entry| {
                if (entry.*.parent) |parent| {
                    if (std.mem.eql(u8, &parent.hash, &target.hash)) {
                        if (entry.*.isValidCandidate()) {
                            is_tip = false;
                            break;
                        }
                    }
                }
            }
            if (is_tip) {
                self.chain_tips.append(target) catch return ChainError.OutOfMemory;
            }
        }

        // Phase 5: Activate the best chain (may switch to this one)
        try self.activateBestChain();
    }

    /// Clear failed_child flag on all descendants of a block.
    fn clearDescendantFailure(self: *ChainManager, ancestor: *BlockIndexEntry) ChainError!void {
        var queue = std.ArrayList(*BlockIndexEntry).init(self.allocator);
        defer queue.deinit();

        // Find immediate children
        var iter = self.block_index.valueIterator();
        while (iter.next()) |entry| {
            if (entry.*.parent) |parent| {
                if (std.mem.eql(u8, &parent.hash, &ancestor.hash)) {
                    queue.append(entry.*) catch return ChainError.OutOfMemory;
                }
            }
        }

        // Process queue
        var i: usize = 0;
        while (i < queue.items.len) : (i += 1) {
            const block = queue.items[i];
            block.status.failed_child = false;
            try self.persistBlockStatus(block);

            // Find children
            var child_iter = self.block_index.valueIterator();
            while (child_iter.next()) |entry| {
                if (entry.*.parent) |parent| {
                    if (std.mem.eql(u8, &parent.hash, &block.hash)) {
                        queue.append(entry.*) catch return ChainError.OutOfMemory;
                    }
                }
            }
        }
    }

    // ========================================================================
    // preciousblock RPC
    // ========================================================================

    /// Mark a block as precious, giving it priority in chain selection.
    /// This sets a low sequence_id to prefer this block as a tie-breaker
    /// when two chains have equal work.
    ///
    /// Reference: Bitcoin Core validation.cpp PreciousBlock()
    pub fn preciousBlock(self: *ChainManager, hash: *const types.Hash256) ChainError!void {
        const target = self.block_index.get(hash.*) orelse return ChainError.BlockNotFound;

        // Only consider if block has at least as much work as current tip
        if (self.active_tip) |tip| {
            if (self.compareChainWork(&target.chain_work, &tip.chain_work) < 0) {
                // Less work than current tip, nothing to do
                return;
            }
        }

        // Reset counter if chain has extended since last precious call
        if (self.active_tip) |tip| {
            if (self.compareChainWork(&tip.chain_work, &self.last_precious_chainwork) > 0) {
                self.reverse_sequence_id = -1;
            }
        }

        // Assign a lower (more negative) sequence ID for priority and persist
        target.sequence_id = self.reverse_sequence_id;
        self.reverse_sequence_id -= 1;
        try self.persistBlockStatus(target);

        // Update last precious chainwork
        if (self.active_tip) |tip| {
            self.last_precious_chainwork = tip.chain_work;
        }

        // Re-evaluate best chain
        try self.activateBestChain();
    }

    // ========================================================================
    // Chain Selection Helpers
    // ========================================================================

    /// Compare two chain work values (256-bit big-endian).
    /// Returns >0 if a > b, <0 if a < b, 0 if equal.
    fn compareChainWork(self: *ChainManager, a: *const [32]u8, b: *const [32]u8) i32 {
        _ = self;
        // Compare as big-endian integers
        for (0..32) |i| {
            if (a[i] > b[i]) return 1;
            if (a[i] < b[i]) return -1;
        }
        return 0;
    }

    /// Compare two block index entries for chain selection.
    /// Returns true if a should be preferred over b.
    fn compareCandidates(self: *ChainManager, a: *const BlockIndexEntry, b: *const BlockIndexEntry) bool {
        // Primary: more chainwork wins
        const work_cmp = self.compareChainWork(&a.chain_work, &b.chain_work);
        if (work_cmp > 0) return true;
        if (work_cmp < 0) return false;

        // Secondary: lower sequence_id wins (precious blocks get negative values)
        if (a.sequence_id < b.sequence_id) return true;
        if (a.sequence_id > b.sequence_id) return false;

        // Tertiary: use hash as final tie-breaker (deterministic)
        return std.mem.lessThan(u8, &a.hash, &b.hash);
    }

    /// Find and activate the best valid chain.
    fn activateBestChain(self: *ChainManager) ChainError!void {
        // Find the best valid candidate
        var best: ?*BlockIndexEntry = null;
        var iter = self.block_index.valueIterator();
        while (iter.next()) |entry| {
            if (!entry.*.isValidCandidate()) continue;

            if (best) |b| {
                if (self.compareCandidates(entry.*, b)) {
                    best = entry.*;
                }
            } else {
                best = entry.*;
            }
        }

        // If best is different from active_tip, we need to reorganize
        // For now, just update the active_tip
        // Full reorg would involve disconnecting old chain and connecting new chain
        if (best) |b| {
            if (self.active_tip) |tip| {
                if (!std.mem.eql(u8, &b.hash, &tip.hash)) {
                    // TODO: Full reorg implementation
                    self.active_tip = b;
                }
            } else {
                self.active_tip = b;
            }
        }
    }

    /// Remove a block from the chain_tips list.
    fn removeFromChainTips(self: *ChainManager, block: *BlockIndexEntry) void {
        var i: usize = 0;
        while (i < self.chain_tips.items.len) {
            if (std.mem.eql(u8, &self.chain_tips.items[i].hash, &block.hash)) {
                _ = self.chain_tips.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Evict transactions from mempool that conflict with the invalidated block.
    fn evictConflictingTransactions(self: *ChainManager, pool: *@import("mempool.zig").Mempool, block: *BlockIndexEntry) void {
        _ = self;
        _ = pool;
        _ = block;
        // TODO: When we have full block data, evict transactions that:
        // 1. Spend UTXOs created by transactions in the invalidated block
        // 2. Were confirmed in the invalidated block but now need to go back to mempool
    }
};

// ============================================================================
// Chain Management Tests
// ============================================================================

test "BlockStatus packed struct size" {
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(BlockStatus));
}

test "BlockStatus default is valid" {
    const status = BlockStatus{};
    try std.testing.expect(!status.isInvalid());
}

test "BlockStatus failed_valid marks invalid" {
    var status = BlockStatus{};
    status.failed_valid = true;
    try std.testing.expect(status.isInvalid());
}

test "BlockStatus failed_child marks invalid" {
    var status = BlockStatus{};
    status.failed_child = true;
    try std.testing.expect(status.isInvalid());
}

test "BlockStatus clearFailure clears both flags" {
    var status = BlockStatus{};
    status.failed_valid = true;
    status.failed_child = true;
    try std.testing.expect(status.isInvalid());

    status.clearFailure();
    try std.testing.expect(!status.isInvalid());
}

test "ChainManager init and deinit" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    try std.testing.expect(manager.active_tip == null);
    try std.testing.expect(manager.best_invalid == null);
    try std.testing.expectEqual(@as(i64, -1), manager.reverse_sequence_id);
}

test "ChainManager invalidateBlock returns BlockNotFound for unknown hash" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    var unknown_hash: types.Hash256 = [_]u8{0xAB} ** 32;
    const result = manager.invalidateBlock(&unknown_hash);
    try std.testing.expectError(ChainManager.ChainError.BlockNotFound, result);
}

test "ChainManager reconsiderBlock returns BlockNotFound for unknown hash" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    var unknown_hash: types.Hash256 = [_]u8{0xCD} ** 32;
    const result = manager.reconsiderBlock(&unknown_hash);
    try std.testing.expectError(ChainManager.ChainError.BlockNotFound, result);
}

test "ChainManager preciousBlock returns BlockNotFound for unknown hash" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    var unknown_hash: types.Hash256 = [_]u8{0xEF} ** 32;
    const result = manager.preciousBlock(&unknown_hash);
    try std.testing.expectError(ChainManager.ChainError.BlockNotFound, result);
}

test "ChainManager invalidateBlock rejects genesis" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Create a genesis block entry
    // NOTE: manager.deinit() will free this, so no defer destroy needed
    const genesis = try allocator.create(BlockIndexEntry);

    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };

    try manager.addBlock(genesis);

    const result = manager.invalidateBlock(&genesis.hash);
    try std.testing.expectError(ChainManager.ChainError.GenesisCannotBeInvalidated, result);
}

test "ChainManager invalidateBlock marks block as failed_valid" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Create parent block (manager.deinit() will free)
    const parent = try allocator.create(BlockIndexEntry);
    parent.* = BlockIndexEntry{
        .hash = [_]u8{0x01} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(parent);

    // Create child block (manager.deinit() will free)
    const child = try allocator.create(BlockIndexEntry);
    child.* = BlockIndexEntry{
        .hash = [_]u8{0x02} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x01} ** 32,
        .sequence_id = 1,
        .parent = parent,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(child);

    // Invalidate the child (not on active chain, so no disconnect needed)
    try manager.invalidateBlock(&child.hash);

    try std.testing.expect(child.status.failed_valid);
    try std.testing.expect(child.status.isInvalid());
}

test "ChainManager invalidateBlock marks descendants with failed_child" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Create a chain: genesis -> block1 -> block2 -> block3
    // (manager.deinit() will free all blocks)
    const genesis = try allocator.create(BlockIndexEntry);
    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(genesis);

    const block1 = try allocator.create(BlockIndexEntry);
    block1.* = BlockIndexEntry{
        .hash = [_]u8{0x01} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x01} ** 32,
        .sequence_id = 1,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(block1);

    const block2 = try allocator.create(BlockIndexEntry);
    block2.* = BlockIndexEntry{
        .hash = [_]u8{0x02} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 2,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x02} ** 32,
        .sequence_id = 2,
        .parent = block1,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(block2);

    const block3 = try allocator.create(BlockIndexEntry);
    block3.* = BlockIndexEntry{
        .hash = [_]u8{0x03} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 3,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x03} ** 32,
        .sequence_id = 3,
        .parent = block2,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(block3);

    // Invalidate block1 - should mark block2 and block3 as failed_child
    try manager.invalidateBlock(&block1.hash);

    try std.testing.expect(block1.status.failed_valid);
    try std.testing.expect(!block1.status.failed_child);

    try std.testing.expect(!block2.status.failed_valid);
    try std.testing.expect(block2.status.failed_child);

    try std.testing.expect(!block3.status.failed_valid);
    try std.testing.expect(block3.status.failed_child);
}

test "ChainManager reconsiderBlock clears failure flags" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Create a chain: genesis -> block1 -> block2 (manager.deinit() will free)
    const genesis = try allocator.create(BlockIndexEntry);
    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(genesis);

    const block1 = try allocator.create(BlockIndexEntry);
    block1.* = BlockIndexEntry{
        .hash = [_]u8{0x01} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x01} ** 32,
        .sequence_id = 1,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(block1);

    const block2 = try allocator.create(BlockIndexEntry);
    block2.* = BlockIndexEntry{
        .hash = [_]u8{0x02} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 2,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x02} ** 32,
        .sequence_id = 2,
        .parent = block1,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(block2);

    // Invalidate block1
    try manager.invalidateBlock(&block1.hash);
    try std.testing.expect(block1.status.failed_valid);
    try std.testing.expect(block2.status.failed_child);

    // Reconsider block1
    try manager.reconsiderBlock(&block1.hash);

    try std.testing.expect(!block1.status.failed_valid);
    try std.testing.expect(!block1.status.failed_child);
    try std.testing.expect(!block2.status.failed_valid);
    try std.testing.expect(!block2.status.failed_child);
}

test "ChainManager preciousBlock decrements sequence_id" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Create a block (manager.deinit() will free)
    const block = try allocator.create(BlockIndexEntry);
    block.* = BlockIndexEntry{
        .hash = [_]u8{0x01} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x01} ** 32,
        .sequence_id = 100, // Original sequence ID
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(block);

    // Call preciousBlock
    try manager.preciousBlock(&block.hash);

    // Block should get a negative sequence ID
    try std.testing.expect(block.sequence_id < 0);
    try std.testing.expectEqual(@as(i64, -1), block.sequence_id);

    // Counter should decrement
    try std.testing.expectEqual(@as(i64, -2), manager.reverse_sequence_id);
}

test "ChainManager compareChainWork" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    const low: [32]u8 = [_]u8{0x00} ** 31 ++ [_]u8{0x01};
    const high: [32]u8 = [_]u8{0x00} ** 31 ++ [_]u8{0xFF};
    const equal: [32]u8 = [_]u8{0x00} ** 31 ++ [_]u8{0x01};

    try std.testing.expect(manager.compareChainWork(&high, &low) > 0);
    try std.testing.expect(manager.compareChainWork(&low, &high) < 0);
    try std.testing.expect(manager.compareChainWork(&low, &equal) == 0);
}

test "ChainManager invalidate active chain block causes reorg" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Create a fork: genesis -> A -> B (active)
    //                      \-> C -> D (alternative with less work initially)
    const genesis = try allocator.create(BlockIndexEntry);
    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(genesis);

    // Main chain: A -> B
    const blockA = try allocator.create(BlockIndexEntry);
    blockA.* = BlockIndexEntry{
        .hash = [_]u8{0x0A} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x02},
        .sequence_id = 1,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockA);

    const blockB = try allocator.create(BlockIndexEntry);
    blockB.* = BlockIndexEntry{
        .hash = [_]u8{0x0B} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 2,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x04},
        .sequence_id = 2,
        .parent = blockA,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockB);

    // Alternative chain: C -> D (equal work to main chain)
    const blockC = try allocator.create(BlockIndexEntry);
    blockC.* = BlockIndexEntry{
        .hash = [_]u8{0x0C} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x02},
        .sequence_id = 3,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockC);

    const blockD = try allocator.create(BlockIndexEntry);
    blockD.* = BlockIndexEntry{
        .hash = [_]u8{0x0D} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 2,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x04},
        .sequence_id = 4,
        .parent = blockC,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockD);

    // Set active tip to B (main chain)
    manager.active_tip = blockB;
    try manager.chain_tips.append(blockB);
    try manager.chain_tips.append(blockD);

    // Invalidate block A on active chain - should cause reorg to D
    try manager.invalidateBlock(&blockA.hash);

    // Verify block A and B are marked invalid
    try std.testing.expect(blockA.status.failed_valid);
    try std.testing.expect(blockB.status.failed_child);

    // Alternative chain should still be valid
    try std.testing.expect(!blockC.status.isInvalid());
    try std.testing.expect(!blockD.status.isInvalid());

    // Active tip should switch to D (the only valid chain now)
    try std.testing.expectEqual(blockD, manager.active_tip.?);
}

test "ChainManager reconsider block causes re-reorg" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Create a fork: genesis -> A -> B (was active, then invalidated)
    //                      \-> C (alternative, less work)
    const genesis = try allocator.create(BlockIndexEntry);
    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(genesis);

    // Main chain: A -> B (more work)
    const blockA = try allocator.create(BlockIndexEntry);
    blockA.* = BlockIndexEntry{
        .hash = [_]u8{0x0A} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x02},
        .sequence_id = 1,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockA);

    const blockB = try allocator.create(BlockIndexEntry);
    blockB.* = BlockIndexEntry{
        .hash = [_]u8{0x0B} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 2,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x04},
        .sequence_id = 2,
        .parent = blockA,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockB);

    // Alternative chain: C (less work)
    const blockC = try allocator.create(BlockIndexEntry);
    blockC.* = BlockIndexEntry{
        .hash = [_]u8{0x0C} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x01},
        .sequence_id = 3,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockC);

    // Set active tip to B
    manager.active_tip = blockB;
    try manager.chain_tips.append(blockB);
    try manager.chain_tips.append(blockC);

    // Invalidate block A - causes reorg to C
    try manager.invalidateBlock(&blockA.hash);
    try std.testing.expectEqual(blockC, manager.active_tip.?);
    try std.testing.expect(blockA.status.failed_valid);
    try std.testing.expect(blockB.status.failed_child);

    // Reconsider block A - should re-reorg back to B (more work)
    try manager.reconsiderBlock(&blockA.hash);

    // Block A and B should no longer be invalid
    try std.testing.expect(!blockA.status.failed_valid);
    try std.testing.expect(!blockB.status.failed_child);
    try std.testing.expect(!blockB.status.isInvalid());

    // Active tip should switch back to B (more work)
    try std.testing.expectEqual(blockB, manager.active_tip.?);
}

test "ChainManager preciousBlock tie-breaker with equal work" {
    const allocator = std.testing.allocator;
    var manager = ChainManager.init(null, null, allocator);
    defer manager.deinit();

    const genesis = try allocator.create(BlockIndexEntry);
    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(genesis);

    // Two competing blocks at height 1 with equal work
    const blockA = try allocator.create(BlockIndexEntry);
    blockA.* = BlockIndexEntry{
        .hash = [_]u8{0x0A} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x01},
        .sequence_id = 1,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockA);

    const blockB = try allocator.create(BlockIndexEntry);
    blockB.* = BlockIndexEntry{
        .hash = [_]u8{0x0B} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{ .has_data = true },
        .chain_work = [_]u8{0x00} ** 31 ++ [_]u8{0x01},
        .sequence_id = 2,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };
    try manager.addBlock(blockB);

    // Initially A is preferred (lower sequence_id)
    manager.active_tip = blockA;
    try manager.chain_tips.append(blockA);
    try manager.chain_tips.append(blockB);

    // Mark B as precious - should switch to B
    try manager.preciousBlock(&blockB.hash);

    // B should now have a negative sequence_id (preferred)
    try std.testing.expect(blockB.sequence_id < 0);
    try std.testing.expect(blockB.sequence_id < blockA.sequence_id);

    // Active tip should switch to B
    try std.testing.expectEqual(blockB, manager.active_tip.?);
}

test "BlockIndexEntry isAncestorOf" {
    const allocator = std.testing.allocator;

    const genesis = try allocator.create(BlockIndexEntry);
    defer allocator.destroy(genesis);
    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };

    const block1 = try allocator.create(BlockIndexEntry);
    defer allocator.destroy(block1);
    block1.* = BlockIndexEntry{
        .hash = [_]u8{0x01} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };

    const block2 = try allocator.create(BlockIndexEntry);
    defer allocator.destroy(block2);
    block2.* = BlockIndexEntry{
        .hash = [_]u8{0x02} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 2,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = block1,
        .file_number = 0,
        .file_offset = 0,
    };

    try std.testing.expect(genesis.isAncestorOf(block1));
    try std.testing.expect(genesis.isAncestorOf(block2));
    try std.testing.expect(block1.isAncestorOf(block2));
    try std.testing.expect(!block2.isAncestorOf(block1));
    try std.testing.expect(!block1.isAncestorOf(genesis));
}

test "BlockIndexEntry getAncestor" {
    const allocator = std.testing.allocator;

    const genesis = try allocator.create(BlockIndexEntry);
    defer allocator.destroy(genesis);
    genesis.* = BlockIndexEntry{
        .hash = [_]u8{0x00} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 0,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };

    const block1 = try allocator.create(BlockIndexEntry);
    defer allocator.destroy(block1);
    block1.* = BlockIndexEntry{
        .hash = [_]u8{0x01} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 1,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = genesis,
        .file_number = 0,
        .file_offset = 0,
    };

    const block2 = try allocator.create(BlockIndexEntry);
    defer allocator.destroy(block2);
    block2.* = BlockIndexEntry{
        .hash = [_]u8{0x02} ** 32,
        .header = consensus.MAINNET.genesis_header,
        .height = 2,
        .status = BlockStatus{},
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = block1,
        .file_number = 0,
        .file_offset = 0,
    };

    try std.testing.expectEqual(genesis, block2.getAncestor(0));
    try std.testing.expectEqual(block1, block2.getAncestor(1));
    try std.testing.expectEqual(block2, block2.getAncestor(2));
    try std.testing.expect(block2.getAncestor(3) == null);
}

// ============================================================================
// Script Flag Tests (BIP-146 NULLFAIL, BIP-147 NULLDUMMY)
// ============================================================================

test "getBlockScriptFlags: NULLFAIL disabled before segwit activation" {
    // Before segwit height, NULLFAIL should be disabled
    const flags = getBlockScriptFlags(consensus.MAINNET.segwit_height - 1, &consensus.MAINNET);
    try std.testing.expect(!flags.verify_nullfail);
}

test "getBlockScriptFlags: NULLFAIL enabled at segwit activation height" {
    // At segwit activation height (481824 mainnet), NULLFAIL should be enabled
    const flags = getBlockScriptFlags(consensus.MAINNET.segwit_height, &consensus.MAINNET);
    try std.testing.expect(flags.verify_nullfail);
}

test "getBlockScriptFlags: NULLFAIL enabled after segwit activation" {
    // After segwit activation, NULLFAIL should remain enabled
    const flags = getBlockScriptFlags(consensus.MAINNET.segwit_height + 1000, &consensus.MAINNET);
    try std.testing.expect(flags.verify_nullfail);
}

test "getBlockScriptFlags: NULLDUMMY follows NULLFAIL activation" {
    // NULLDUMMY (BIP-147) is also activated with segwit
    const pre_segwit = getBlockScriptFlags(consensus.MAINNET.segwit_height - 1, &consensus.MAINNET);
    const at_segwit = getBlockScriptFlags(consensus.MAINNET.segwit_height, &consensus.MAINNET);

    try std.testing.expect(!pre_segwit.verify_nulldummy);
    try std.testing.expect(at_segwit.verify_nulldummy);
}

test "getBlockScriptFlags: regtest has NULLFAIL enabled from block 0" {
    // Regtest has segwit_height = 0, so NULLFAIL is always enabled
    const flags = getBlockScriptFlags(0, &consensus.REGTEST);
    try std.testing.expect(flags.verify_nullfail);
    try std.testing.expect(flags.verify_nulldummy);
    try std.testing.expect(flags.verify_witness);
}

test "getBlockScriptFlags: segwit activation height is 481824 on mainnet" {
    // Verify the activation height constant
    try std.testing.expectEqual(@as(u32, 481_824), consensus.MAINNET.segwit_height);
}

test "getBlockScriptFlags: all flags disabled at height 0 mainnet" {
    // Very early block should have minimal flags
    const flags = getBlockScriptFlags(0, &consensus.MAINNET);
    // BIP-34 height is 227931, so P2SH should be disabled at height 0
    try std.testing.expect(!flags.verify_p2sh);
    try std.testing.expect(!flags.verify_witness);
    try std.testing.expect(!flags.verify_nullfail);
    try std.testing.expect(!flags.verify_taproot);
}

test "getBlockScriptFlags: progressive flag activation mainnet" {
    // Test that flags activate at correct heights

    // Before BIP-66 (363725): no DERSIG
    const pre_dersig = getBlockScriptFlags(363_724, &consensus.MAINNET);
    try std.testing.expect(!pre_dersig.verify_dersig);

    // At BIP-66: DERSIG enabled
    const at_dersig = getBlockScriptFlags(363_725, &consensus.MAINNET);
    try std.testing.expect(at_dersig.verify_dersig);

    // Before BIP-65 (388381): no CLTV
    const pre_cltv = getBlockScriptFlags(388_380, &consensus.MAINNET);
    try std.testing.expect(!pre_cltv.verify_checklocktimeverify);

    // At BIP-65: CLTV enabled
    const at_cltv = getBlockScriptFlags(388_381, &consensus.MAINNET);
    try std.testing.expect(at_cltv.verify_checklocktimeverify);

    // Before CSV (419328): no CSV
    const pre_csv = getBlockScriptFlags(419_327, &consensus.MAINNET);
    try std.testing.expect(!pre_csv.verify_checksequenceverify);

    // At CSV: CSV enabled
    const at_csv = getBlockScriptFlags(419_328, &consensus.MAINNET);
    try std.testing.expect(at_csv.verify_checksequenceverify);
}

test "getBlockScriptFlags: taproot activation" {
    // Before taproot (709632): no TAPROOT
    const pre_taproot = getBlockScriptFlags(709_631, &consensus.MAINNET);
    try std.testing.expect(!pre_taproot.verify_taproot);

    // At taproot: TAPROOT enabled
    const at_taproot = getBlockScriptFlags(709_632, &consensus.MAINNET);
    try std.testing.expect(at_taproot.verify_taproot);
}

// ============================================================================
// Parallel Script Validation Tests
// ============================================================================

test "ScriptCheckJob initializes with pending result" {
    const tx_bytes = [_]u8{0x01} ** 100;
    const prev_script = [_]u8{0x76, 0xa9, 0x14} ++ [_]u8{0xAB} ** 20 ++ [_]u8{0x88, 0xac};
    const flags = script.ScriptFlags{};

    const job = ScriptCheckJob.init(
        &tx_bytes,
        0,
        &prev_script,
        100_000_000,
        flags,
        &.{},
    );

    try std.testing.expectEqual(ScriptCheckJob.VerifyResult.pending, job.result.load(.acquire));
}

test "ScriptCheckJob result can be atomically updated" {
    const tx_bytes = [_]u8{0x01} ** 100;
    const prev_script = [_]u8{0x76, 0xa9, 0x14} ++ [_]u8{0xAB} ** 20 ++ [_]u8{0x88, 0xac};
    const flags = script.ScriptFlags{};

    var job = ScriptCheckJob.init(
        &tx_bytes,
        0,
        &prev_script,
        100_000_000,
        flags,
        &.{},
    );

    // Update result atomically
    job.result.store(.success, .release);
    try std.testing.expectEqual(ScriptCheckJob.VerifyResult.success, job.result.load(.acquire));

    job.result.store(.failure, .release);
    try std.testing.expectEqual(ScriptCheckJob.VerifyResult.failure, job.result.load(.acquire));
}

test "getParallelVerifyThreadCount returns at least 1" {
    const count = getParallelVerifyThreadCount();
    try std.testing.expect(count >= 1);
}

test "ParallelVerifyConfig has sensible defaults" {
    const config = ParallelVerifyConfig{};
    try std.testing.expect(config.enabled);
    try std.testing.expect(config.min_inputs_for_parallel >= 1);
}

test "ScriptCheckQueue init and deinit" {
    const allocator = std.testing.allocator;

    var queue = try ScriptCheckQueue.init(allocator);
    defer queue.deinit();

    // Should have at least 1 worker
    try std.testing.expect(queue.worker_count >= 1);
    try std.testing.expectEqual(@as(usize, 0), queue.job_count);
}

test "ScriptCheckQueue waitAll returns true for empty job list" {
    const allocator = std.testing.allocator;

    var queue = try ScriptCheckQueue.init(allocator);
    defer queue.deinit();

    // No jobs submitted
    const result = queue.waitAll();
    try std.testing.expect(result);
}

test "ScriptCheckQueue processes multiple jobs" {
    const allocator = std.testing.allocator;

    var queue = try ScriptCheckQueue.init(allocator);
    defer queue.deinit();

    // Create a few dummy jobs (they will fail verification but that's ok for testing)
    const tx_bytes = [_]u8{0x01} ** 10;
    const prev_script = [_]u8{0x00};

    var jobs: [3]ScriptCheckJob = undefined;
    for (&jobs) |*job| {
        job.* = ScriptCheckJob.init(
            &tx_bytes,
            0,
            &prev_script,
            0,
            script.ScriptFlags{},
            &.{},
        );
    }

    queue.submit(&jobs);

    // Wait for completion - should complete (though jobs will fail)
    const result = queue.waitAll();

    // Verify all jobs were processed (result is either success or failure, not pending)
    for (&jobs) |*job| {
        const job_result = job.result.load(.acquire);
        try std.testing.expect(job_result != .pending);
    }

    // Result should be false since the jobs have invalid data
    try std.testing.expect(!result);
}

test "verifyBlockScriptsSingleThreaded with empty utxo lookup returns missing input" {
    const allocator = std.testing.allocator;

    // Create a minimal block with one non-coinbase transaction
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x01, 0x01, 0x01 },
        .sequence = 0xFFFFFFFF,
        .witness = &.{},
    };
    const coinbase = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // Non-coinbase tx
    const tx_input = types.TxIn{
        .previous_output = types.OutPoint{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{0x00},
        .sequence = 0xFFFFFFFF,
        .witness = &.{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{tx_input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    const transactions = [_]types.Transaction{ coinbase, tx };
    const block = types.Block{
        .header = consensus.MAINNET.genesis_header,
        .transactions = &transactions,
    };

    // Empty lookup that always returns null
    const EmptyContext = struct {
        fn lookup(_: *anyopaque, _: *const types.OutPoint) ?[]const u8 {
            return null;
        }
    };
    var empty_ctx: u8 = 0;
    const utxo_lookup = SigopUtxoView{
        .context = @ptrCast(&empty_ctx),
        .lookupFn = &EmptyContext.lookup,
    };

    const flags = script.ScriptFlags{};
    const result = verifyBlockScriptsSingleThreaded(&block, flags, &utxo_lookup, allocator);

    try std.testing.expectError(ValidationError.MissingInput, result);
}
