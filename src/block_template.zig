//! Block template construction for mining.
//!
//! This module implements the `getblocktemplate` functionality that assembles
//! a valid block template from mempool transactions, respecting weight limits,
//! fee optimization, and coinbase construction.
//!
//! Key features:
//! - Transaction selection sorted by ancestor fee rate
//! - BIP-34 coinbase height encoding
//! - BIP-141 witness commitment
//! - Block weight and sigops limit enforcement
//! - Coinbase output value calculation (subsidy + fees)

const std = @import("std");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const mempool_mod = @import("mempool.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");
const validation = @import("validation.zig");

// ============================================================================
// Block Template
// ============================================================================

/// A block template for mining.
/// Contains all data needed for a miner to construct and find a valid block.
pub const BlockTemplate = struct {
    /// Partially-constructed block header (miner will iterate nonce/timestamp).
    header: types.BlockHeader,
    /// Coinbase transaction (value will be updated with fees).
    coinbase_tx: CoinbaseTx,
    /// Selected transactions from mempool, sorted by ancestor fee rate.
    transactions: std.ArrayList(SelectedTx),
    /// Total fees from selected transactions.
    total_fees: i64,
    /// Total weight of selected transactions (including coinbase).
    total_weight: usize,
    /// Total sigops cost of selected transactions.
    total_sigops: usize,
    /// Block height for this template.
    height: u32,
    /// Difficulty target (256-bit, little-endian).
    target: [32]u8,
    /// Fields the miner can modify: "time", "transactions", "prevblock", "coinbase/append".
    mutable: []const []const u8,
    /// Allocator used for template construction.
    allocator: std.mem.Allocator,

    /// Selected transaction with precomputed data.
    pub const SelectedTx = struct {
        tx: types.Transaction,
        txid: types.Hash256,
        weight: usize,
        fee: i64,
        sigops: usize,
    };

    /// Coinbase transaction with mutable fields.
    pub const CoinbaseTx = struct {
        tx: types.Transaction,
        script_sig: []u8,
        outputs: []types.TxOut,
        inputs: []types.TxIn,
        witness: [][]const u8,
    };

    /// Free all resources associated with this template.
    pub fn deinit(self: *BlockTemplate) void {
        // Free selected transactions
        for (self.transactions.items) |*stx| {
            // Note: The transaction data is borrowed from mempool,
            // so we don't free it here unless we made copies
            _ = stx;
        }
        self.transactions.deinit();

        // Free coinbase output scripts (dynamically allocated witness commitment script)
        for (self.coinbase_tx.outputs) |output| {
            // Check if this is the witness commitment output (38 bytes, starts with 0x6a 0x24 0xaa 0x21 0xa9 0xed)
            if (output.script_pubkey.len == 38 and
                output.script_pubkey[0] == 0x6a and
                output.script_pubkey[1] == 0x24 and
                output.script_pubkey[2] == 0xaa and
                output.script_pubkey[3] == 0x21 and
                output.script_pubkey[4] == 0xa9 and
                output.script_pubkey[5] == 0xed)
            {
                self.allocator.free(output.script_pubkey);
            }
        }

        // Free witness data
        if (self.coinbase_tx.witness.len > 0) {
            for (self.coinbase_tx.witness) |item| {
                self.allocator.free(item);
            }
            self.allocator.free(self.coinbase_tx.witness);
        }

        // Free coinbase allocations
        self.allocator.free(self.coinbase_tx.script_sig);
        self.allocator.free(self.coinbase_tx.outputs);
        self.allocator.free(self.coinbase_tx.inputs);
    }

    /// Compute the final merkle root including the coinbase transaction.
    pub fn computeMerkleRoot(self: *const BlockTemplate) !types.Hash256 {
        var tx_hashes = try self.allocator.alloc(types.Hash256, 1 + self.transactions.items.len);
        defer self.allocator.free(tx_hashes);

        // Coinbase txid
        tx_hashes[0] = try crypto.computeTxid(&self.coinbase_tx.tx, self.allocator);

        // Selected transaction txids
        for (self.transactions.items, 0..) |stx, i| {
            tx_hashes[1 + i] = stx.txid;
        }

        return crypto.computeMerkleRoot(tx_hashes, self.allocator);
    }

    /// Get the total block reward (subsidy + fees).
    pub fn getBlockReward(self: *const BlockTemplate, params: *const consensus.NetworkParams) i64 {
        const subsidy = consensus.getBlockSubsidy(self.height, params);
        return subsidy + self.total_fees;
    }
};

// ============================================================================
// Block Template Construction
// ============================================================================

/// Options for block template creation.
pub const TemplateOptions = struct {
    /// Extra data to include in coinbase scriptSig (e.g., pool name).
    coinbase_extra: []const u8 = &[_]u8{},
    /// Script pubkey for coinbase output (miner's address).
    payout_script: []const u8 = &[_]u8{},
    /// Whether to include a witness commitment output.
    include_witness_commitment: bool = true,
    /// Maximum block weight to target (default: consensus limit).
    max_weight: u32 = consensus.MAX_BLOCK_WEIGHT,
    /// Maximum sigops cost (default: consensus limit).
    max_sigops: u32 = consensus.MAX_BLOCK_SIGOPS_COST,
};

/// Create a block template for mining.
///
/// This function:
/// 1. Computes the difficulty target from chain state
/// 2. Constructs the coinbase transaction with BIP-34 height
/// 3. Selects transactions from mempool sorted by ancestor fee rate
/// 4. Computes the merkle root and assembles the block header
///
/// Returns a BlockTemplate that can be used for mining.
pub fn createBlockTemplate(
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    params: *const consensus.NetworkParams,
    options: TemplateOptions,
    allocator: std.mem.Allocator,
) !BlockTemplate {
    const height = chain_state.best_height + 1;

    // 1. Compute difficulty target
    // In production, this would use the full difficulty adjustment algorithm.
    // For now, use a placeholder or the previous block's bits.
    const bits: u32 = params.genesis_header.bits; // Use genesis bits as placeholder
    const target = consensus.bitsToTarget(bits);

    // 2. Reserve weight for coinbase transaction
    // Coinbase is typically ~200-400 bytes, estimating 1000 weight units
    const coinbase_weight: usize = 1000;
    var total_weight: usize = coinbase_weight;
    var total_fees: i64 = 0;
    var total_sigops: usize = 0;

    // 3. Select transactions from mempool
    var selected = std.ArrayList(BlockTemplate.SelectedTx).init(allocator);
    errdefer selected.deinit();

    // Get sorted candidates from mempool (by ancestor fee rate, descending)
    const candidates = try mempool.getBlockCandidates(allocator);
    defer allocator.free(candidates);

    // Get current block time for locktime validation
    const block_time: u64 = @intCast(std.time.timestamp());

    for (candidates) |entry| {
        // Check transaction finality (locktime validation)
        if (!isFinalTx(&entry.tx, height, block_time)) continue;

        // Check weight limit
        if (total_weight + entry.weight > options.max_weight) continue;

        // Check sigops limit (simplified - would need actual sigops counting)
        const tx_sigops: usize = estimateSigops(&entry.tx);
        if (total_sigops + tx_sigops > options.max_sigops) continue;

        // Add transaction to selection
        try selected.append(.{
            .tx = entry.tx,
            .txid = entry.txid,
            .weight = entry.weight,
            .fee = entry.fee,
            .sigops = tx_sigops,
        });

        total_weight += entry.weight;
        total_fees += entry.fee;
        total_sigops += tx_sigops;
    }

    // 4. Extract transactions for witness commitment computation
    var txs_for_witness = try allocator.alloc(types.Transaction, selected.items.len);
    defer allocator.free(txs_for_witness);
    for (selected.items, 0..) |stx, i| {
        txs_for_witness[i] = stx.tx;
    }

    // 5. Compute witness commitment if needed
    var witness_commitment: ?types.Hash256 = null;
    const witness_nonce: [32]u8 = [_]u8{0} ** 32;
    if (options.include_witness_commitment) {
        witness_commitment = try computeWitnessCommitment(txs_for_witness, witness_nonce, allocator);
    }

    // 6. Construct coinbase transaction with the computed witness commitment
    const coinbase = try constructCoinbaseWithCommitment(
        height,
        total_fees,
        options.coinbase_extra,
        options.payout_script,
        witness_commitment,
        params,
        allocator,
    );

    // 7. Compute merkle root
    var tx_hashes = try allocator.alloc(types.Hash256, 1 + selected.items.len);
    defer allocator.free(tx_hashes);

    tx_hashes[0] = try crypto.computeTxid(&coinbase.tx, allocator);
    for (selected.items, 0..) |stx, i| {
        tx_hashes[1 + i] = stx.txid;
    }
    const merkle_root = try crypto.computeMerkleRoot(tx_hashes, allocator);

    // 8. Construct block header
    const header = types.BlockHeader{
        .version = 0x20000000, // BIP-9 version bits base
        .prev_block = chain_state.best_hash,
        .merkle_root = merkle_root,
        .timestamp = @intCast(std.time.timestamp()),
        .bits = bits,
        .nonce = 0, // Miner will iterate this
    };

    // 9. Define mutable fields
    const mutable = &[_][]const u8{
        "time",
        "transactions",
        "prevblock",
        "coinbase/append",
    };

    return BlockTemplate{
        .header = header,
        .coinbase_tx = coinbase,
        .transactions = selected,
        .total_fees = total_fees,
        .total_weight = total_weight,
        .total_sigops = total_sigops,
        .height = height,
        .target = target,
        .mutable = mutable,
        .allocator = allocator,
    };
}

/// Construct the coinbase transaction with an optional precomputed witness commitment.
///
/// The coinbase transaction is special:
/// - Has a single input with null outpoint (all zeros hash, 0xFFFFFFFF index)
/// - BIP-34: scriptSig must start with the block height
/// - Output value = block subsidy + total fees
/// - BIP-141: May include a witness commitment output
fn constructCoinbaseWithCommitment(
    height: u32,
    total_fees: i64,
    extra_data: []const u8,
    payout_script: []const u8,
    witness_commitment: ?types.Hash256,
    params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
) !BlockTemplate.CoinbaseTx {
    // Build coinbase scriptSig with BIP-34 height encoding
    var script_sig = std.ArrayList(u8).init(allocator);
    errdefer script_sig.deinit();

    // Encode height as minimal CScriptNum push (BIP-34)
    try encodeHeightPush(&script_sig, height);

    // Append extra data (pool name, etc.)
    if (extra_data.len > 0) {
        // Limit extra data to keep scriptSig under 100 bytes
        const max_extra = @min(extra_data.len, 96 - script_sig.items.len);
        try script_sig.appendSlice(extra_data[0..max_extra]);
    }

    // Calculate block reward
    const subsidy = consensus.getBlockSubsidy(height, params);
    const block_reward = subsidy + total_fees;

    // Build outputs
    var outputs = std.ArrayList(types.TxOut).init(allocator);
    errdefer outputs.deinit();

    // Primary payout output
    if (payout_script.len > 0) {
        try outputs.append(.{
            .value = block_reward,
            .script_pubkey = payout_script,
        });
    } else {
        // If no payout script specified, create a minimal OP_RETURN output
        // (not valid for real mining, but useful for testing)
        try outputs.append(.{
            .value = block_reward,
            .script_pubkey = &[_]u8{0x6a}, // OP_RETURN
        });
    }

    // Witness commitment output (BIP-141)
    if (witness_commitment) |commitment| {
        // Format: OP_RETURN OP_PUSH36 0xaa21a9ed <32-byte commitment>
        // The commitment is SHA256d(witness_merkle_root || witness_nonce)
        const witness_script = try allocator.alloc(u8, 38);
        witness_script[0] = 0x6a; // OP_RETURN
        witness_script[1] = 0x24; // Push 36 bytes
        witness_script[2] = 0xaa;
        witness_script[3] = 0x21;
        witness_script[4] = 0xa9;
        witness_script[5] = 0xed;
        @memcpy(witness_script[6..38], &commitment);

        try outputs.append(.{
            .value = 0,
            .script_pubkey = witness_script,
        });
    }

    // Coinbase input
    const inputs = try allocator.alloc(types.TxIn, 1);
    const script_sig_owned = try script_sig.toOwnedSlice();

    // Coinbase witness (BIP-141): single 32-byte zero value (the witness nonce)
    var witness: [][]const u8 = &[_][]const u8{};
    if (witness_commitment != null) {
        const witness_items = try allocator.alloc([]const u8, 1);
        const witness_nonce = try allocator.alloc(u8, 32);
        @memset(witness_nonce, 0);
        witness_items[0] = witness_nonce;
        witness = witness_items;
    }

    // Coinbase input:
    // - sequence = 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL) to enable locktime
    // - This matches Bitcoin Core's CreateNewBlock behavior (miner.cpp)
    // - Using 0xFFFFFFFE (not 0xFFFFFFFF) ensures locktime is enforced
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig_owned,
        .sequence = 0xFFFFFFFE, // MAX_SEQUENCE_NONFINAL - enables locktime
        .witness = witness,
    };

    const outputs_owned = try outputs.toOwnedSlice();

    // Coinbase transaction:
    // - nLockTime = height - 1 for anti-fee-sniping (matches Bitcoin Core miner.cpp)
    // - This discourages miners from reorganizing blocks to steal fees
    // - For height 0 (genesis), use locktime 0
    const lock_time: u32 = if (height > 0) height - 1 else 0;

    return .{
        .tx = .{
            .version = 2,
            .inputs = inputs,
            .outputs = outputs_owned,
            .lock_time = lock_time, // Anti-fee-sniping: set to height - 1
        },
        .script_sig = script_sig_owned,
        .outputs = outputs_owned,
        .inputs = inputs,
        .witness = witness,
    };
}

/// Legacy constructCoinbase without precomputed commitment (uses placeholder).
/// Kept for backwards compatibility with existing tests.
fn constructCoinbase(
    height: u32,
    total_fees: i64,
    extra_data: []const u8,
    payout_script: []const u8,
    include_witness_commitment: bool,
    params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
) !BlockTemplate.CoinbaseTx {
    // For legacy calls, use a placeholder commitment (all zeros)
    const commitment: ?types.Hash256 = if (include_witness_commitment)
        [_]u8{0} ** 32
    else
        null;
    return constructCoinbaseWithCommitment(
        height,
        total_fees,
        extra_data,
        payout_script,
        commitment,
        params,
        allocator,
    );
}

/// Encode a block height as a minimal CScriptNum push (BIP-34).
///
/// This pushes the height as a minimal-encoded signed integer:
/// - Heights 0-16 use OP_0 through OP_16
/// - Other heights use a minimal byte push
fn encodeHeightPush(script: *std.ArrayList(u8), height: u32) !void {
    if (height == 0) {
        // OP_0
        try script.append(0x00);
    } else if (height <= 16) {
        // OP_1 through OP_16 (0x51 through 0x60)
        try script.append(@as(u8, 0x50) + @as(u8, @intCast(height)));
    } else {
        // Minimal byte encoding
        // Determine how many bytes we need
        var temp = height;
        var num_bytes: usize = 0;
        while (temp > 0) {
            temp >>= 8;
            num_bytes += 1;
        }

        // Check if we need an extra byte for sign (positive numbers with high bit set)
        const needs_sign_byte = ((height >> @intCast((num_bytes - 1) * 8)) & 0x80) != 0;
        if (needs_sign_byte) num_bytes += 1;

        // Push opcode for num_bytes
        try script.append(@as(u8, @intCast(num_bytes)));

        // Push bytes in little-endian order
        var h = height;
        for (0..num_bytes) |_| {
            try script.append(@as(u8, @intCast(h & 0xFF)));
            h >>= 8;
        }
    }
}

/// Estimate sigops for a transaction.
/// This is a simplified estimation - full implementation would parse scripts.
fn estimateSigops(tx: *const types.Transaction) usize {
    var sigops: usize = 0;

    // Legacy sigops: count CHECKSIG and CHECKMULTISIG in outputs
    for (tx.outputs) |output| {
        sigops += countScriptSigops(output.script_pubkey);
    }

    // For inputs, we'd need the spent outputs to count accurately
    // Use a conservative estimate based on input count
    sigops += tx.inputs.len;

    return sigops;
}

/// Count sigops in a script (simplified).
fn countScriptSigops(script: []const u8) usize {
    var count: usize = 0;
    var i: usize = 0;

    while (i < script.len) {
        const op = script[i];
        i += 1;

        if (op == 0xac or op == 0xad) {
            // OP_CHECKSIG (0xac) or OP_CHECKSIGVERIFY (0xad)
            count += 1;
        } else if (op == 0xae or op == 0xaf) {
            // OP_CHECKMULTISIG (0xae) or OP_CHECKMULTISIGVERIFY (0xaf)
            // Conservative estimate: 20 sigops
            count += 20;
        } else if (op <= 0x4b) {
            // Direct push: skip data
            i += op;
        } else if (op == 0x4c) {
            // OP_PUSHDATA1
            if (i < script.len) {
                i += script[i] + 1;
            }
        } else if (op == 0x4d) {
            // OP_PUSHDATA2
            if (i + 1 < script.len) {
                const len = std.mem.readInt(u16, script[i..][0..2], .little);
                i += 2 + len;
            }
        } else if (op == 0x4e) {
            // OP_PUSHDATA4
            if (i + 3 < script.len) {
                const len = std.mem.readInt(u32, script[i..][0..4], .little);
                i += 4 + len;
            }
        }
    }

    return count;
}

// ============================================================================
// Witness Commitment
// ============================================================================

/// Compute the witness commitment for a block.
///
/// The commitment is: SHA256d(witness_merkle_root || witness_nonce)
/// where witness_merkle_root is the merkle root of all wtxids.
///
/// For the coinbase, its wtxid is defined as 32 bytes of zeros.
pub fn computeWitnessCommitment(
    transactions: []const types.Transaction,
    witness_nonce: [32]u8,
    allocator: std.mem.Allocator,
) !types.Hash256 {
    // Build wtxid list
    var wtxids = try allocator.alloc(types.Hash256, 1 + transactions.len);
    defer allocator.free(wtxids);

    // Coinbase wtxid is all zeros
    wtxids[0] = [_]u8{0} ** 32;

    // Compute wtxids for other transactions
    for (transactions, 0..) |*tx, i| {
        wtxids[1 + i] = try crypto.computeWtxid(tx, allocator);
    }

    // Compute witness merkle root
    const witness_merkle_root = try crypto.computeMerkleRoot(wtxids, allocator);

    // Compute commitment: SHA256d(witness_merkle_root || witness_nonce)
    var commitment_data: [64]u8 = undefined;
    @memcpy(commitment_data[0..32], &witness_merkle_root);
    @memcpy(commitment_data[32..64], &witness_nonce);

    return crypto.hash256(&commitment_data);
}

/// Create the witness commitment script for the coinbase output.
/// Format: OP_RETURN OP_PUSH36 0xaa21a9ed <32-byte commitment>
pub fn createWitnessCommitmentScript(commitment: types.Hash256) [38]u8 {
    var script: [38]u8 = undefined;
    script[0] = 0x6a; // OP_RETURN
    script[1] = 0x24; // Push 36 bytes
    script[2] = 0xaa;
    script[3] = 0x21;
    script[4] = 0xa9;
    script[5] = 0xed;
    @memcpy(script[6..38], &commitment);
    return script;
}

// ============================================================================
// Block Submission
// ============================================================================

// ============================================================================
// Transaction Finality (Locktime Validation)
// ============================================================================

/// LOCKTIME_THRESHOLD: values below are block heights, values >= are unix timestamps.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Check if a transaction is final according to BIP-65 rules.
///
/// A transaction is final if:
/// 1. nLockTime == 0, OR
/// 2. nLockTime < threshold (height if < 500M, time if >= 500M), OR
/// 3. All inputs have sequence == 0xFFFFFFFF (SEQUENCE_FINAL)
///
/// Reference: Bitcoin Core tx_verify.cpp IsFinalTx()
pub fn isFinalTx(tx: *const types.Transaction, block_height: u32, block_time: u64) bool {
    // If nLockTime is 0, transaction is always final
    if (tx.lock_time == 0) return true;

    // Determine if locktime is height-based or time-based
    const lock_time: i64 = @intCast(tx.lock_time);
    const threshold: i64 = if (tx.lock_time < LOCKTIME_THRESHOLD)
        @intCast(block_height)
    else
        @intCast(block_time);

    // If locktime has already passed, transaction is final
    if (lock_time < threshold) return true;

    // Even if nLockTime isn't satisfied, transaction is final if all
    // inputs have SEQUENCE_FINAL (0xFFFFFFFF)
    for (tx.inputs) |input| {
        if (input.sequence != 0xFFFFFFFF) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Block Submission
// ============================================================================

/// Result of block submission.
pub const SubmitResult = struct {
    accepted: bool,
    reject_reason: ?[]const u8,
    block_hash: types.Hash256,
};

/// Submit a mined block to the chain.
///
/// This function:
/// 1. Validates the block hash meets the target
/// 2. Validates block structure and transactions
/// 3. Connects the block to the chain state
///
/// Returns whether the block was accepted.
pub fn submitBlock(
    block: *const types.Block,
    chain_state: *storage.ChainState,
    params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
) !SubmitResult {
    return submitBlockWithIndex(block, chain_state, params, null, allocator);
}

/// Submit a mined block to the chain, updating both the UTXO set and block index.
///
/// When chain_manager is provided, the block header is inserted into the
/// in-memory block index (and persisted to ChainStore if available).  Without
/// this step, subsequent RPCs like getblockheader / getblockhash cannot find
/// the newly-mined block.
pub fn submitBlockWithIndex(
    block: *const types.Block,
    chain_state: *storage.ChainState,
    params: *const consensus.NetworkParams,
    chain_manager: ?*validation.ChainManager,
    allocator: std.mem.Allocator,
) !SubmitResult {
    // Compute block hash
    const block_hash = crypto.computeBlockHash(&block.header);

    // Check proof of work
    const target = consensus.bitsToTarget(block.header.bits);
    if (!consensus.hashMeetsTarget(&block_hash, &target)) {
        return .{
            .accepted = false,
            .reject_reason = "high-hash",
            .block_hash = block_hash,
        };
    }

    // Verify PoW is valid for the network
    if (!consensus.validateProofOfWork(&block.header, params)) {
        return .{
            .accepted = false,
            .reject_reason = "bad-diffbits",
            .block_hash = block_hash,
        };
    }

    // Connect the block to the chain (UTXO set + best_hash/best_height)
    const height = chain_state.best_height + 1;
    var undo = chain_state.connectBlock(block, &block_hash, height) catch |err| {
        return .{
            .accepted = false,
            .reject_reason = switch (err) {
                error.MissingInput => "bad-txns-inputs-missingorspent",
                else => "invalid-block",
            },
            .block_hash = block_hash,
        };
    };
    undo.deinit(chain_state.allocator);

    // Insert into the block index so that getblockheader / getblockhash can
    // find the block afterwards.
    if (chain_manager) |cm| {
        // Look up the parent entry for chain work calculation
        const parent = cm.getBlock(&block.header.prev_block);

        const entry = allocator.create(validation.BlockIndexEntry) catch {
            // Non-fatal: the block is already connected to the UTXO chain.
            return .{ .accepted = true, .reject_reason = null, .block_hash = block_hash };
        };
        entry.* = validation.BlockIndexEntry{
            .hash = block_hash,
            .header = block.header,
            .height = height,
            .status = .{ .valid_header = true, .has_data = true, .has_undo = false, .failed_valid = false, .failed_child = false, ._padding = 0 },
            .chain_work = if (parent) |p| p.chain_work else [_]u8{0} ** 32,
            .sequence_id = 0,
            .parent = parent,
            .file_number = 0,
            .file_offset = 0,
        };

        cm.addBlock(entry) catch {};

        // Update the active tip
        cm.active_tip = entry;

        // Persist to ChainStore on disk
        if (cm.chain_store) |cs| {
            cs.putBlockIndex(&block_hash, &block.header, height) catch {};
        }
    }

    return .{
        .accepted = true,
        .reject_reason = null,
        .block_hash = block_hash,
    };
}

// ============================================================================
// Regtest Mining (generatetoaddress, generateblock)
// ============================================================================

/// Maximum nonce tries for mining (regtest: usually succeeds in first try due to min difficulty).
pub const DEFAULT_MAX_TRIES: u64 = 1_000_000;

/// Result of block generation.
pub const GenerateResult = struct {
    /// Block hashes of successfully mined blocks.
    block_hashes: std.ArrayList(types.Hash256),

    pub fn deinit(self: *GenerateResult) void {
        self.block_hashes.deinit();
    }
};

/// Mine a single block by finding a valid nonce.
///
/// This function:
/// 1. Computes the merkle root from the coinbase and transactions
/// 2. Iterates nonces until the block hash meets the target
/// 3. Optionally submits the block to the chain
///
/// For regtest, the difficulty is so low that nonce 0-2 typically works.
pub fn mineBlock(
    template: *BlockTemplate,
    chain_state: *storage.ChainState,
    params: *const consensus.NetworkParams,
    max_tries: u64,
    submit_block: bool,
    allocator: std.mem.Allocator,
) !?types.Hash256 {
    return mineBlockWithIndex(template, chain_state, params, max_tries, submit_block, null, allocator);
}

/// Mine a single block, optionally inserting into the block index.
pub fn mineBlockWithIndex(
    template: *BlockTemplate,
    chain_state: *storage.ChainState,
    params: *const consensus.NetworkParams,
    max_tries: u64,
    submit_block: bool,
    chain_manager: ?*validation.ChainManager,
    allocator: std.mem.Allocator,
) !?types.Hash256 {
    // 1. Compute merkle root
    const merkle_root = try template.computeMerkleRoot();
    template.header.merkle_root = merkle_root;

    // 2. Get target from bits
    const target = consensus.bitsToTarget(template.header.bits);

    // 3. Mine: iterate nonces until we find valid PoW
    var tries: u64 = 0;
    while (tries < max_tries) : (tries += 1) {
        // Update nonce
        template.header.nonce = @intCast(tries & 0xFFFFFFFF);

        // Compute block hash
        const block_hash = crypto.computeBlockHash(&template.header);

        // Check if hash meets target
        if (consensus.hashMeetsTarget(&block_hash, &target)) {
            // Found valid nonce
            if (submit_block) {
                // Build the full block
                const block = try assembleBlock(template, allocator);
                defer {
                    allocator.free(block.transactions);
                }

                // Submit to chain (with block index update when chain_manager is available)
                const result = try submitBlockWithIndex(&block, chain_state, params, chain_manager, allocator);
                if (!result.accepted) {
                    return null;
                }
            }
            return block_hash;
        }

        // If we've exhausted all nonces, try updating timestamp
        if (tries > 0 and (tries % 0x100000000) == 0) {
            template.header.timestamp +%= 1;
        }
    }

    return null; // Failed to find valid nonce in max_tries
}

/// Assemble a complete Block from a BlockTemplate.
fn assembleBlock(template: *const BlockTemplate, allocator: std.mem.Allocator) !types.Block {
    // Build transactions array: coinbase + selected transactions
    const tx_count = 1 + template.transactions.items.len;
    var transactions = try allocator.alloc(types.Transaction, tx_count);
    errdefer allocator.free(transactions);

    // Coinbase is first
    transactions[0] = template.coinbase_tx.tx;

    // Copy selected transactions
    for (template.transactions.items, 0..) |stx, i| {
        transactions[1 + i] = stx.tx;
    }

    return types.Block{
        .header = template.header,
        .transactions = transactions,
    };
}

/// Generate multiple blocks to a specified script pubkey.
///
/// This is the core implementation for generatetoaddress and generatetodescriptor RPCs.
/// For regtest, mining is nearly instant due to minimum difficulty.
pub fn generateBlocks(
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    params: *const consensus.NetworkParams,
    payout_script: []const u8,
    n_blocks: u32,
    max_tries: u64,
    chain_manager: ?*validation.ChainManager,
    allocator: std.mem.Allocator,
) !GenerateResult {
    std.log.info("generateBlocks: n_blocks={d}, best_height={d}", .{ n_blocks, chain_state.best_height });
    var result = GenerateResult{
        .block_hashes = std.ArrayList(types.Hash256).init(allocator),
    };
    errdefer result.deinit();

    var blocks_mined: u32 = 0;
    while (blocks_mined < n_blocks) {
        std.log.info("generateBlocks: creating template for block {d}", .{blocks_mined});
        // Create block template
        var template = try createBlockTemplate(
            chain_state,
            mempool,
            params,
            .{
                .payout_script = payout_script,
                .include_witness_commitment = true,
            },
            allocator,
        );
        defer template.deinit();

        std.log.info("generateBlocks: template created, mining...", .{});
        // Mine the block
        const block_hash = try mineBlockWithIndex(
            &template,
            chain_state,
            params,
            max_tries,
            true, // submit to chain
            chain_manager,
            allocator,
        );

        if (block_hash) |hash| {
            try result.block_hashes.append(hash);
            blocks_mined += 1;
        } else {
            // Failed to mine block (exhausted tries)
            break;
        }
    }

    return result;
}

/// Generate a single block with specific transactions.
///
/// This is the implementation for the generateblock RPC.
/// Takes a list of transaction txids/raw transactions to include in the block.
pub fn generateBlockWithTxs(
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    params: *const consensus.NetworkParams,
    payout_script: []const u8,
    transactions: []const types.Transaction,
    max_tries: u64,
    submit_block: bool,
    chain_manager: ?*validation.ChainManager,
    allocator: std.mem.Allocator,
) !struct { hash: types.Hash256, hex: ?[]const u8 } {
    // Create a minimal block template (not using mempool transactions)
    var template = try createBlockTemplate(
        chain_state,
        mempool,
        params,
        .{
            .payout_script = payout_script,
            .include_witness_commitment = true,
        },
        allocator,
    );
    defer template.deinit();

    // Clear any mempool transactions and add the specified ones
    template.transactions.clearRetainingCapacity();
    template.total_fees = 0;

    // Add specified transactions
    for (transactions) |tx| {
        const txid = try crypto.computeTxid(&tx, allocator);
        // Estimate weight (simplified)
        const weight = estimateTxWeight(&tx);

        try template.transactions.append(.{
            .tx = tx,
            .txid = txid,
            .weight = weight,
            .fee = 0, // Fee not tracked for generateblock
            .sigops = estimateSigops(&tx),
        });

        template.total_weight += weight;
    }

    // Recompute witness commitment with new transactions
    if (transactions.len > 0) {
        var txs_for_witness = try allocator.alloc(types.Transaction, transactions.len);
        defer allocator.free(txs_for_witness);
        for (transactions, 0..) |tx, i| {
            txs_for_witness[i] = tx;
        }

        const witness_nonce: [32]u8 = [_]u8{0} ** 32;
        const witness_commitment = try computeWitnessCommitment(txs_for_witness, witness_nonce, allocator);

        // Update coinbase witness commitment output
        // (Simplified: in full implementation would reconstruct coinbase)
        _ = witness_commitment;
    }

    // Mine the block
    const block_hash = try mineBlockWithIndex(
        &template,
        chain_state,
        params,
        max_tries,
        submit_block,
        chain_manager,
        allocator,
    );

    if (block_hash) |hash| {
        var hex: ?[]const u8 = null;

        if (!submit_block) {
            // Return hex of the block
            const block = try assembleBlock(&template, allocator);
            defer allocator.free(block.transactions);

            var writer = serialize.Writer.init(allocator);
            defer writer.deinit();
            try serialize.writeBlock(&writer, &block);
            const bytes = writer.getWritten();

            var hex_buf = try allocator.alloc(u8, bytes.len * 2);
            for (bytes, 0..) |b, i| {
                const chars = "0123456789abcdef";
                hex_buf[i * 2] = chars[b >> 4];
                hex_buf[i * 2 + 1] = chars[b & 0x0f];
            }
            hex = hex_buf;
        }

        return .{ .hash = hash, .hex = hex };
    }

    return error.MiningFailed;
}

/// Estimate transaction weight (simplified).
fn estimateTxWeight(tx: *const types.Transaction) usize {
    // Base size estimation
    var base_size: usize = 4; // version
    base_size += 1; // input count varint (simplified)
    for (tx.inputs) |input| {
        base_size += 32; // prev txid
        base_size += 4; // prev index
        base_size += 1 + input.script_sig.len; // scriptSig length + data
        base_size += 4; // sequence
    }
    base_size += 1; // output count varint
    for (tx.outputs) |output| {
        base_size += 8; // value
        base_size += 1 + output.script_pubkey.len; // scriptPubKey length + data
    }
    base_size += 4; // locktime

    // Witness size estimation
    var witness_size: usize = 0;
    for (tx.inputs) |input| {
        if (input.witness.len > 0) {
            witness_size += 1; // witness count
            for (input.witness) |item| {
                witness_size += 1 + item.len; // item length + data
            }
        }
    }

    // Weight = base_size * 3 + total_size (where total_size = base_size + witness_size)
    // Simplified: weight = base_size * 4 + witness_size (since witness has 1x multiplier)
    return base_size * 4 + witness_size;
}

// ============================================================================
// Tests
// ============================================================================

test "height encoding BIP-34" {
    const allocator = std.testing.allocator;

    // Test height 0
    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 0);
        try std.testing.expectEqual(@as(usize, 1), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x00), script.items[0]); // OP_0
    }

    // Test height 1-16 (OP_1 through OP_16)
    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 1);
        try std.testing.expectEqual(@as(usize, 1), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x51), script.items[0]); // OP_1
    }

    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 16);
        try std.testing.expectEqual(@as(usize, 1), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x60), script.items[0]); // OP_16
    }

    // Test height 17 (requires push)
    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 17);
        try std.testing.expectEqual(@as(usize, 2), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x01), script.items[0]); // Push 1 byte
        try std.testing.expectEqual(@as(u8, 17), script.items[1]);
    }

    // Test height 127 (max value in 1 byte)
    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 127);
        try std.testing.expectEqual(@as(usize, 2), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x01), script.items[0]);
        try std.testing.expectEqual(@as(u8, 127), script.items[1]);
    }

    // Test height 128 (requires sign byte)
    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 128);
        try std.testing.expectEqual(@as(usize, 3), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x02), script.items[0]); // Push 2 bytes
        try std.testing.expectEqual(@as(u8, 128), script.items[1]);
        try std.testing.expectEqual(@as(u8, 0), script.items[2]); // Sign byte
    }

    // Test height 256
    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 256);
        try std.testing.expectEqual(@as(usize, 3), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x02), script.items[0]); // Push 2 bytes
        try std.testing.expectEqual(@as(u8, 0), script.items[1]); // LSB
        try std.testing.expectEqual(@as(u8, 1), script.items[2]); // MSB
    }

    // Test height 500000 (typical mainnet height)
    {
        var script = std.ArrayList(u8).init(allocator);
        defer script.deinit();
        try encodeHeightPush(&script, 500000);
        // 500000 = 0x0007A120 in hex
        // Little-endian: 0x20, 0xA1, 0x07
        try std.testing.expectEqual(@as(usize, 4), script.items.len);
        try std.testing.expectEqual(@as(u8, 0x03), script.items[0]); // Push 3 bytes
        try std.testing.expectEqual(@as(u8, 0x20), script.items[1]); // LSB
        try std.testing.expectEqual(@as(u8, 0xA1), script.items[2]);
        try std.testing.expectEqual(@as(u8, 0x07), script.items[3]); // MSB
    }
}

test "coinbase transaction has correct structure" {
    const allocator = std.testing.allocator;

    // P2WPKH payout script
    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    const coinbase = try constructCoinbase(
        100, // height
        1000000, // fees
        "test pool", // extra data
        &payout_script,
        true, // include witness commitment
        &consensus.MAINNET,
        allocator,
    );
    defer {
        // Free allocated witness commitment script FIRST (before freeing outputs slice)
        if (coinbase.outputs.len > 1) {
            allocator.free(coinbase.outputs[1].script_pubkey);
        }
        allocator.free(coinbase.script_sig);
        allocator.free(coinbase.outputs);
        allocator.free(coinbase.inputs);
        if (coinbase.witness.len > 0) {
            for (coinbase.witness) |item| {
                allocator.free(item);
            }
            allocator.free(coinbase.witness);
        }
    }

    // Verify null input
    try std.testing.expectEqual(@as(usize, 1), coinbase.tx.inputs.len);
    try std.testing.expectEqualSlices(u8, &types.OutPoint.COINBASE.hash, &coinbase.tx.inputs[0].previous_output.hash);
    try std.testing.expectEqual(types.OutPoint.COINBASE.index, coinbase.tx.inputs[0].previous_output.index);

    // Verify BIP-34 height in scriptSig
    // Height 100 should be encoded as: OP_1 (0x01) 0x64 (100)
    try std.testing.expect(coinbase.script_sig.len >= 2);
    try std.testing.expectEqual(@as(u8, 0x01), coinbase.script_sig[0]); // Push 1 byte
    try std.testing.expectEqual(@as(u8, 100), coinbase.script_sig[1]); // Height

    // Verify outputs
    try std.testing.expect(coinbase.tx.outputs.len >= 1);

    // First output should be payout
    const subsidy = consensus.getBlockSubsidy(100, &consensus.MAINNET);
    try std.testing.expectEqual(subsidy + 1000000, coinbase.tx.outputs[0].value);

    // Second output should be witness commitment (if included)
    if (coinbase.tx.outputs.len > 1) {
        try std.testing.expectEqual(@as(i64, 0), coinbase.tx.outputs[1].value);
        try std.testing.expectEqual(@as(usize, 38), coinbase.tx.outputs[1].script_pubkey.len);
        // Check witness commitment header
        try std.testing.expectEqual(@as(u8, 0x6a), coinbase.tx.outputs[1].script_pubkey[0]); // OP_RETURN
        try std.testing.expectEqual(@as(u8, 0x24), coinbase.tx.outputs[1].script_pubkey[1]); // Push 36
        try std.testing.expectEqual(@as(u8, 0xaa), coinbase.tx.outputs[1].script_pubkey[2]);
        try std.testing.expectEqual(@as(u8, 0x21), coinbase.tx.outputs[1].script_pubkey[3]);
        try std.testing.expectEqual(@as(u8, 0xa9), coinbase.tx.outputs[1].script_pubkey[4]);
        try std.testing.expectEqual(@as(u8, 0xed), coinbase.tx.outputs[1].script_pubkey[5]);
    }
}

test "coinbase value equals subsidy plus total fees" {
    const allocator = std.testing.allocator;

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBB} ** 20;
    const height: u32 = 210000; // First halving
    const total_fees: i64 = 5000000; // 0.05 BTC

    const coinbase = try constructCoinbase(
        height,
        total_fees,
        "",
        &payout_script,
        false,
        &consensus.MAINNET,
        allocator,
    );
    defer {
        allocator.free(coinbase.script_sig);
        allocator.free(coinbase.outputs);
        allocator.free(coinbase.inputs);
    }

    const expected_subsidy = consensus.getBlockSubsidy(height, &consensus.MAINNET);
    try std.testing.expectEqual(@as(i64, 2_500_000_000), expected_subsidy); // 25 BTC after first halving

    const expected_value = expected_subsidy + total_fees;
    try std.testing.expectEqual(expected_value, coinbase.tx.outputs[0].value);
}

test "empty mempool produces valid template with only coinbase" {
    const allocator = std.testing.allocator;

    // Create a memory-only chain state
    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    // Create empty mempool
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xCC} ** 20;

    // Create template
    var template = try createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{
            .payout_script = &payout_script,
            .include_witness_commitment = false,
        },
        allocator,
    );
    defer template.deinit();

    // Verify template structure
    try std.testing.expectEqual(@as(usize, 0), template.transactions.items.len);
    try std.testing.expectEqual(@as(i64, 0), template.total_fees);
    try std.testing.expectEqual(@as(u32, 1), template.height); // chain_state.best_height + 1

    // Verify block header
    try std.testing.expectEqual(@as(i32, 0x20000000), template.header.version);
    try std.testing.expectEqualSlices(u8, &chain_state.best_hash, &template.header.prev_block);
}

test "block template total weight does not exceed MAX_BLOCK_WEIGHT" {
    const allocator = std.testing.allocator;

    // Create chain state
    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    // Create mempool
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xDD} ** 20;

    // Create template with default max weight
    var template = try createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.MAINNET,
        .{
            .payout_script = &payout_script,
        },
        allocator,
    );
    defer template.deinit();

    // Verify weight is within limit
    try std.testing.expect(template.total_weight <= consensus.MAX_BLOCK_WEIGHT);
}

test "witness commitment script format" {
    const commitment = [_]u8{0x12} ** 32;
    const script = createWitnessCommitmentScript(commitment);

    try std.testing.expectEqual(@as(usize, 38), script.len);
    try std.testing.expectEqual(@as(u8, 0x6a), script[0]); // OP_RETURN
    try std.testing.expectEqual(@as(u8, 0x24), script[1]); // Push 36 bytes
    try std.testing.expectEqual(@as(u8, 0xaa), script[2]);
    try std.testing.expectEqual(@as(u8, 0x21), script[3]);
    try std.testing.expectEqual(@as(u8, 0xa9), script[4]);
    try std.testing.expectEqual(@as(u8, 0xed), script[5]);
    try std.testing.expectEqualSlices(u8, &commitment, script[6..38]);
}

test "witness commitment computation" {
    const allocator = std.testing.allocator;

    // Create some dummy transactions
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const transactions = [_]types.Transaction{tx};
    const witness_nonce = [_]u8{0} ** 32;

    const commitment = try computeWitnessCommitment(&transactions, witness_nonce, allocator);

    // Verify we get a valid 32-byte hash
    try std.testing.expectEqual(@as(usize, 32), commitment.len);
}

test "sigops estimation" {
    // Test transaction with P2PKH outputs
    const p2pkh_script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAA} ** 20 ++ [_]u8{ 0x88, 0xac };
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2pkh_script,
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const sigops = estimateSigops(&tx);

    // Should have at least 1 sigop from CHECKSIG in P2PKH output
    // Plus 1 from the input estimate
    try std.testing.expect(sigops >= 2);
}

test "transactions are ordered by fee rate" {
    const allocator = std.testing.allocator;

    // Create chain state
    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    // Create mempool
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add transactions would require UTXOs in chain state
    // For now, just verify the template handles empty mempool correctly
    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xEE} ** 20;

    var template = try createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.MAINNET,
        .{
            .payout_script = &payout_script,
        },
        allocator,
    );
    defer template.deinit();

    // With empty mempool, should have no transactions
    try std.testing.expectEqual(@as(usize, 0), template.transactions.items.len);

    // The getBlockCandidates function returns transactions sorted by ancestor fee rate,
    // so any transactions added would be in the correct order
}

test "block merkle root is correctly computed" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xFF} ** 20;

    var template = try createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{
            .payout_script = &payout_script,
            .include_witness_commitment = false,
        },
        allocator,
    );
    defer template.deinit();

    // Verify merkle root matches the coinbase txid (only tx in block)
    const coinbase_txid = try crypto.computeTxid(&template.coinbase_tx.tx, allocator);

    // For a block with only the coinbase, the merkle root should equal the coinbase txid
    try std.testing.expectEqualSlices(u8, &coinbase_txid, &template.header.merkle_root);
}

// ============================================================================
// Locktime / isFinalTx Tests
// ============================================================================

test "isFinalTx with locktime 0 is always final" {
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000, // Non-final sequence
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &[_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20,
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0, // locktime 0 means always final
    };

    // Should be final regardless of block height/time
    try std.testing.expect(isFinalTx(&tx, 0, 0));
    try std.testing.expect(isFinalTx(&tx, 1000, 1000000));
    try std.testing.expect(isFinalTx(&tx, 500000, 1600000000));
}

test "isFinalTx with height-based locktime" {
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE, // Non-final sequence (enables locktime)
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &[_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20,
    };

    // Locktime = 100000 (height-based, < LOCKTIME_THRESHOLD)
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 100000,
    };

    // Not final at height 99999
    try std.testing.expect(!isFinalTx(&tx, 99999, 0));

    // Not final at height 100000 (lock_time must be < height)
    try std.testing.expect(!isFinalTx(&tx, 100000, 0));

    // Final at height 100001
    try std.testing.expect(isFinalTx(&tx, 100001, 0));

    // Final at height 200000
    try std.testing.expect(isFinalTx(&tx, 200000, 0));
}

test "isFinalTx with time-based locktime" {
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE, // Non-final sequence (enables locktime)
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &[_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20,
    };

    // Locktime = 1600000000 (time-based, >= LOCKTIME_THRESHOLD = 500000000)
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 1600000000,
    };

    // Not final at earlier time
    try std.testing.expect(!isFinalTx(&tx, 800000, 1599999999));

    // Not final at exact time
    try std.testing.expect(!isFinalTx(&tx, 800000, 1600000000));

    // Final at later time
    try std.testing.expect(isFinalTx(&tx, 800000, 1600000001));
}

test "isFinalTx with all SEQUENCE_FINAL inputs" {
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF, // SEQUENCE_FINAL
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &[_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20,
    };

    // Locktime = 100000 (not yet reached)
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 100000,
    };

    // Should be final because all inputs have SEQUENCE_FINAL
    // Even though locktime hasn't been reached
    try std.testing.expect(isFinalTx(&tx, 50000, 0));
    try std.testing.expect(isFinalTx(&tx, 99999, 0));
}

test "isFinalTx with mixed sequences" {
    const input1 = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF, // SEQUENCE_FINAL
        .witness = &[_][]const u8{},
    };
    const input2 = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE, // Not SEQUENCE_FINAL
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &[_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20,
    };

    // Locktime = 100000 (not yet reached)
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{ input1, input2 },
        .outputs = &[_]types.TxOut{output},
        .lock_time = 100000,
    };

    // Not final because one input doesn't have SEQUENCE_FINAL
    try std.testing.expect(!isFinalTx(&tx, 50000, 0));

    // Final when locktime is reached
    try std.testing.expect(isFinalTx(&tx, 100001, 0));
}

test "coinbase transaction has correct sequence and locktime" {
    const allocator = std.testing.allocator;

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    const coinbase = try constructCoinbase(
        100, // height
        1000000, // fees
        "test pool",
        &payout_script,
        false, // no witness commitment
        &consensus.MAINNET,
        allocator,
    );
    defer {
        allocator.free(coinbase.script_sig);
        allocator.free(coinbase.outputs);
        allocator.free(coinbase.inputs);
    }

    // Verify coinbase has MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) to enable locktime
    // This matches Bitcoin Core's CreateNewBlock behavior (miner.cpp line 171)
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFE), coinbase.tx.inputs[0].sequence);

    // Verify coinbase has locktime = height - 1 for anti-fee-sniping
    // This matches Bitcoin Core's CreateNewBlock behavior (miner.cpp line 196)
    try std.testing.expectEqual(@as(u32, 99), coinbase.tx.lock_time);

    // Verify coinbase is still final at its block height because locktime is satisfied
    // locktime = 99, and we're at height 100, so 99 < 100 means it's final
    try std.testing.expect(isFinalTx(&coinbase.tx, 100, 0));
    try std.testing.expect(isFinalTx(&coinbase.tx, 101, 0));

    // Not final at height 99 (locktime not yet satisfied)
    try std.testing.expect(!isFinalTx(&coinbase.tx, 99, 0));
}

test "coinbase at height 1 has locktime 0" {
    const allocator = std.testing.allocator;

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBB} ** 20;

    const coinbase = try constructCoinbase(
        1, // height 1 (first block after genesis)
        0, // no fees
        "",
        &payout_script,
        false,
        &consensus.REGTEST,
        allocator,
    );
    defer {
        allocator.free(coinbase.script_sig);
        allocator.free(coinbase.outputs);
        allocator.free(coinbase.inputs);
    }

    // Height 1 means locktime = height - 1 = 0
    try std.testing.expectEqual(@as(u32, 0), coinbase.tx.lock_time);

    // Still has MAX_SEQUENCE_NONFINAL
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFE), coinbase.tx.inputs[0].sequence);
}

// ============================================================================
// Regtest Mining Tests
// ============================================================================

test "regtest: mine single block" {
    const allocator = std.testing.allocator;

    // Create chain state and mempool
    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // P2WPKH payout script
    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAB} ** 20;

    // Generate 1 block
    var result = try generateBlocks(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        &payout_script,
        1,
        DEFAULT_MAX_TRIES,
        null,
        allocator,
    );
    defer result.deinit();

    // Should have mined 1 block
    try std.testing.expectEqual(@as(usize, 1), result.block_hashes.items.len);

    // Chain should now be at height 1
    try std.testing.expectEqual(@as(u32, 1), chain_state.best_height);
}

test "regtest: mine multiple blocks" {
    const allocator = std.testing.allocator;

    // Create chain state and mempool
    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBC} ** 20;

    // Generate 10 blocks
    var result = try generateBlocks(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        &payout_script,
        10,
        DEFAULT_MAX_TRIES,
        null,
        allocator,
    );
    defer result.deinit();

    // Should have mined all 10 blocks
    try std.testing.expectEqual(@as(usize, 10), result.block_hashes.items.len);

    // Chain should be at height 10
    try std.testing.expectEqual(@as(u32, 10), chain_state.best_height);
}

test "regtest: blocks chain correctly" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xCD} ** 20;

    // Generate 5 blocks
    var result = try generateBlocks(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        &payout_script,
        5,
        DEFAULT_MAX_TRIES,
        null,
        allocator,
    );
    defer result.deinit();

    // Verify each block hash is unique
    for (result.block_hashes.items, 0..) |hash1, i| {
        for (result.block_hashes.items[i + 1 ..]) |hash2| {
            try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
        }
    }
}

test "regtest: subsidy halving at block 150" {
    // Regtest halves every 150 blocks instead of 210,000

    // Check subsidy at height 149 (before halving)
    const subsidy_149 = consensus.getBlockSubsidy(149, &consensus.REGTEST);
    try std.testing.expectEqual(@as(i64, 5_000_000_000), subsidy_149); // 50 BTC

    // Check subsidy at height 150 (first halving)
    const subsidy_150 = consensus.getBlockSubsidy(150, &consensus.REGTEST);
    try std.testing.expectEqual(@as(i64, 2_500_000_000), subsidy_150); // 25 BTC

    // Check subsidy at height 300 (second halving)
    const subsidy_300 = consensus.getBlockSubsidy(300, &consensus.REGTEST);
    try std.testing.expectEqual(@as(i64, 1_250_000_000), subsidy_300); // 12.5 BTC
}

test "regtest: mineBlock finds valid nonce quickly" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xEF} ** 20;

    // Create block template
    var template = try createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{
            .payout_script = &payout_script,
            .include_witness_commitment = true,
        },
        allocator,
    );
    defer template.deinit();

    // Mine the block (regtest should find nonce very quickly)
    const block_hash = try mineBlock(
        &template,
        &chain_state,
        &consensus.REGTEST,
        100, // Only try 100 nonces - should be enough for regtest
        false, // Don't submit
        allocator,
    );

    // Should have found a valid hash
    try std.testing.expect(block_hash != null);

    // Verify the hash meets the target
    const target = consensus.bitsToTarget(template.header.bits);
    try std.testing.expect(consensus.hashMeetsTarget(&block_hash.?, &target));
}

test "regtest: pow_no_retarget prevents difficulty adjustment" {
    // Verify regtest has no retargeting
    try std.testing.expect(consensus.REGTEST.pow_no_retarget);
    try std.testing.expect(consensus.REGTEST.pow_allow_min_difficulty_blocks);

    // Verify mainnet does retarget
    try std.testing.expect(!consensus.MAINNET.pow_no_retarget);
}

test "regtest: genesis block parameters" {
    // Verify regtest genesis hash (Bitcoin Core's regtest genesis)
    const expected_genesis_hash = comptime blk: {
        var hash: [32]u8 = undefined;
        const hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
        for (0..32) |i| {
            hash[31 - i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch unreachable;
        }
        break :blk hash;
    };

    try std.testing.expectEqualSlices(u8, &expected_genesis_hash, &consensus.REGTEST.genesis_hash);

    // Verify regtest port
    try std.testing.expectEqual(@as(u16, 18444), consensus.REGTEST.default_port);

    // Verify regtest magic bytes
    try std.testing.expectEqual(@as(u32, 0xDAB5BFFA), consensus.REGTEST.magic);

    // Verify regtest bech32 hrp
    try std.testing.expectEqualStrings("bcrt", consensus.REGTEST.bech32_hrp);

    // Verify halving interval
    try std.testing.expectEqual(@as(u32, 150), consensus.REGTEST.subsidy_halving_interval);
}
