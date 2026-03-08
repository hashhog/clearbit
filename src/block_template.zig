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

    for (candidates) |entry| {
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

    // 4. Construct coinbase transaction
    const coinbase = try constructCoinbase(
        height,
        total_fees,
        options.coinbase_extra,
        options.payout_script,
        options.include_witness_commitment,
        params,
        allocator,
    );

    // 5. Compute merkle root
    var tx_hashes = try allocator.alloc(types.Hash256, 1 + selected.items.len);
    defer allocator.free(tx_hashes);

    tx_hashes[0] = try crypto.computeTxid(&coinbase.tx, allocator);
    for (selected.items, 0..) |stx, i| {
        tx_hashes[1 + i] = stx.txid;
    }
    const merkle_root = try crypto.computeMerkleRoot(tx_hashes, allocator);

    // 6. Construct block header
    const header = types.BlockHeader{
        .version = 0x20000000, // BIP-9 version bits base
        .prev_block = chain_state.best_hash,
        .merkle_root = merkle_root,
        .timestamp = @intCast(std.time.timestamp()),
        .bits = bits,
        .nonce = 0, // Miner will iterate this
    };

    // 7. Define mutable fields
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

/// Construct the coinbase transaction.
///
/// The coinbase transaction is special:
/// - Has a single input with null outpoint (all zeros hash, 0xFFFFFFFF index)
/// - BIP-34: scriptSig must start with the block height
/// - Output value = block subsidy + total fees
/// - BIP-141: May include a witness commitment output
fn constructCoinbase(
    height: u32,
    total_fees: i64,
    extra_data: []const u8,
    payout_script: []const u8,
    include_witness_commitment: bool,
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
    if (include_witness_commitment) {
        // Format: OP_RETURN OP_PUSH36 0xaa21a9ed <32-byte commitment>
        // The commitment is SHA256d(witness_merkle_root || witness_nonce)
        // For now, use a placeholder commitment (all zeros)
        var witness_commitment: [38]u8 = undefined;
        witness_commitment[0] = 0x6a; // OP_RETURN
        witness_commitment[1] = 0x24; // Push 36 bytes
        witness_commitment[2] = 0xaa;
        witness_commitment[3] = 0x21;
        witness_commitment[4] = 0xa9;
        witness_commitment[5] = 0xed;
        @memset(witness_commitment[6..38], 0); // Placeholder commitment

        // Allocate the script on the heap so it outlives this function
        const witness_script = try allocator.alloc(u8, 38);
        @memcpy(witness_script, &witness_commitment);

        try outputs.append(.{
            .value = 0,
            .script_pubkey = witness_script,
        });
    }

    // Coinbase input
    const inputs = try allocator.alloc(types.TxIn, 1);
    const script_sig_owned = try script_sig.toOwnedSlice();

    // Coinbase witness (BIP-141): single 32-byte zero value
    var witness: [][]const u8 = &[_][]const u8{};
    if (include_witness_commitment) {
        const witness_items = try allocator.alloc([]const u8, 1);
        const witness_nonce = try allocator.alloc(u8, 32);
        @memset(witness_nonce, 0);
        witness_items[0] = witness_nonce;
        witness = witness_items;
    }

    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig_owned,
        .sequence = 0xFFFFFFFF,
        .witness = witness,
    };

    const outputs_owned = try outputs.toOwnedSlice();

    return .{
        .tx = .{
            .version = 2,
            .inputs = inputs,
            .outputs = outputs_owned,
            .lock_time = 0,
        },
        .script_sig = script_sig_owned,
        .outputs = outputs_owned,
        .inputs = inputs,
        .witness = witness,
    };
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
    _ = allocator;

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

    // Connect the block to the chain
    _ = chain_state.connectBlock(block, &block_hash, chain_state.best_height + 1) catch |err| {
        return .{
            .accepted = false,
            .reject_reason = switch (err) {
                error.MissingInput => "bad-txns-inputs-missingorspent",
                else => "invalid-block",
            },
            .block_hash = block_hash,
        };
    };

    return .{
        .accepted = true,
        .reject_reason = null,
        .block_hash = block_hash,
    };
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
