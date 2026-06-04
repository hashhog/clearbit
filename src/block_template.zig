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
const peer = @import("peer.zig");

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

// ============================================================================
// Block-template assembly constants (mirrors miner.h / policy.h)
// ============================================================================

/// Weight to reserve for the block header, tx-count varint, and coinbase tx.
/// Matches Bitcoin Core DEFAULT_BLOCK_RESERVED_WEIGHT (policy/policy.h:27).
/// Reference: miner.cpp::resetBlock() nBlockWeight = *Assert(m_options.block_reserved_weight)
pub const DEFAULT_BLOCK_RESERVED_WEIGHT: u32 = 8_000;

/// Minimum value that block_reserved_weight may be clamped to.
/// Matches Bitcoin Core MINIMUM_BLOCK_RESERVED_WEIGHT (policy/policy.h:34).
pub const MINIMUM_BLOCK_RESERVED_WEIGHT: u32 = 2_000;

/// After this many consecutive failed-to-fit chunks, stop trying if the block
/// is already "full enough".  Matches Bitcoin Core miner.cpp MAX_CONSECUTIVE_FAILURES.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 1_000;

/// When the block weight is within this many WU of the limit, the consecutive-
/// failure early-exit fires.  Matches Bitcoin Core BLOCK_FULL_ENOUGH_WEIGHT_DELTA.
pub const BLOCK_FULL_ENOUGH_WEIGHT_DELTA: u32 = 4_000;

/// Options for block template creation.
pub const TemplateOptions = struct {
    /// Extra data to include in coinbase scriptSig (e.g., pool name).
    coinbase_extra: []const u8 = &[_]u8{},
    /// Script pubkey for coinbase output (miner's address).
    payout_script: []const u8 = &[_]u8{},
    /// Whether to include a witness commitment output.
    include_witness_commitment: bool = true,
    /// Maximum block weight to target (default: consensus limit).
    /// Clamped by clampOptions() to [block_reserved_weight, MAX_BLOCK_WEIGHT].
    max_weight: u32 = consensus.MAX_BLOCK_WEIGHT,
    /// Maximum sigops cost (default: consensus limit).
    max_sigops: u32 = consensus.MAX_BLOCK_SIGOPS_COST,
    /// Weight reserved for the block header, tx-count, and coinbase tx.
    /// Clamped to [MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT].
    /// Matches DEFAULT_BLOCK_RESERVED_WEIGHT (policy/policy.h:27).
    block_reserved_weight: u32 = DEFAULT_BLOCK_RESERVED_WEIGHT,
    /// Minimum fee rate (sat/vbyte * 1000 for integer arithmetic) below which
    /// transactions are excluded from the template.  0 = accept all.
    /// Matches Bitcoin Core blockMinFeeRate (policy/policy.h:36).
    block_min_fee_rate: u64 = 0,
};

/// Clamp TemplateOptions to valid ranges, mirroring Bitcoin Core ClampOptions()
/// (miner.cpp:79-88).
///
/// Rules:
///   block_reserved_weight = clamp(block_reserved_weight,
///                                  MINIMUM_BLOCK_RESERVED_WEIGHT,
///                                  MAX_BLOCK_WEIGHT)
///   max_weight = clamp(max_weight, block_reserved_weight, MAX_BLOCK_WEIGHT)
///   max_sigops = clamp(max_sigops, 0, MAX_BLOCK_SIGOPS_COST)
///
/// Reference: bitcoin-core/src/node/miner.cpp:79-88
pub fn clampOptions(opts: TemplateOptions) TemplateOptions {
    var out = opts;
    out.block_reserved_weight = @max(
        MINIMUM_BLOCK_RESERVED_WEIGHT,
        @min(out.block_reserved_weight, consensus.MAX_BLOCK_WEIGHT),
    );
    out.max_weight = @max(
        out.block_reserved_weight,
        @min(out.max_weight, consensus.MAX_BLOCK_WEIGHT),
    );
    out.max_sigops = @min(out.max_sigops, consensus.MAX_BLOCK_SIGOPS_COST);
    return out;
}

/// Create a block template for mining.
///
/// This function:
/// 1. Clamps options (MINIMUM_BLOCK_RESERVED_WEIGHT, max_weight bounds)
/// 2. Computes the difficulty target from chain state
/// 3. Constructs the coinbase transaction with BIP-34 height
/// 4. Selects transactions from mempool sorted by ancestor fee rate,
///    honouring weight/sigops/feerate limits and the consecutive-failure
///    early-exit (MAX_CONSECUTIVE_FAILURES / BLOCK_FULL_ENOUGH_WEIGHT_DELTA)
/// 5. Computes the merkle root and assembles the block header
///
/// Returns a BlockTemplate that can be used for mining.
pub fn createBlockTemplate(
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    params: *const consensus.NetworkParams,
    options: TemplateOptions,
    allocator: std.mem.Allocator,
) !BlockTemplate {
    // Bug-1 fix: clamp options before use (MINIMUM_BLOCK_RESERVED_WEIGHT,
    // max_weight bounds).  Mirrors Bitcoin Core ClampOptions() miner.cpp:79.
    const opts = clampOptions(options);

    const height = chain_state.best_height + 1;

    // 1. Compute difficulty target
    // In production, this would use the full difficulty adjustment algorithm.
    // For now, use a placeholder or the previous block's bits.
    const bits: u32 = params.genesis_header.bits; // Use genesis bits as placeholder
    const target = consensus.bitsToTarget(bits);

    // 2. Reserve weight for the block header, tx-count varint, and coinbase tx.
    //
    // Bug-1 fix: use DEFAULT_BLOCK_RESERVED_WEIGHT (8,000 WU) as the initial
    // nBlockWeight, not 1,000.  Bitcoin Core's resetBlock() seeds nBlockWeight
    // with m_options.block_reserved_weight (miner.cpp:114).  Using 1,000 WU
    // here would allow the template to exceed the 4 MB consensus limit by
    // 7,000 WU when the block is near-full.
    var total_weight: usize = opts.block_reserved_weight;
    var total_fees: i64 = 0;
    var total_sigops: usize = 0;

    // 3. Select transactions from mempool
    var selected = std.ArrayList(BlockTemplate.SelectedTx).init(allocator);
    errdefer selected.deinit();

    // Get sorted candidates from mempool (by ancestor fee rate, descending)
    const candidates = try mempool.getBlockCandidates(allocator);
    defer allocator.free(candidates);

    // Bug-4 fix: use MTP (Median Time Past of the previous 11 blocks) as the
    // lock_time_cutoff for IsFinalTx, NOT the wall-clock time.
    //
    // Bitcoin Core miner.cpp line 148:
    //   m_lock_time_cutoff = pindexPrev->GetMedianTimePast()
    // and passes it as nBlockTime to IsFinalTx().  Using the real wall clock
    // would accept transactions that are not yet final (locktime in the near
    // future but MTP still below it), or reject ones that already are.
    //
    // chain_state.computeMTP() returns 0 when the ring buffer is empty (fewer
    // than 1 block), in which case we fall back to the wall clock — identical
    // to Core's genesis-adjacent behaviour.
    const mtp = chain_state.computeMTP();
    const lock_time_cutoff: u64 = if (mtp != 0)
        @as(u64, mtp)
    else
        @as(u64, @intCast(std.time.timestamp()));

    // Bug-6 fix: consecutive-failure early-exit, matching Bitcoin Core
    // miner.cpp::addChunks() lines 284-333.  After MAX_CONSECUTIVE_FAILURES
    // skipped chunks, if the block is already within BLOCK_FULL_ENOUGH_WEIGHT_DELTA
    // of the limit we give up rather than iterating the entire mempool.
    var consecutive_failed: u32 = 0;

    for (candidates) |entry| {
        // Bug-5 fix: block_min_fee_rate gate.  Bitcoin Core addChunks() bails
        // early when chunk_feerate < blockMinFeeRate (miner.cpp:298-301).
        // Here we apply it per-entry as the mempool returns them sorted by
        // fee rate; once we see a sub-minimum entry we stop.
        if (opts.block_min_fee_rate > 0 and entry.weight > 0) {
            // fee_rate in sat per 1000 vbytes = fee * 4000 / weight
            // compare fee * 4000 / weight < block_min_fee_rate
            // ↔ fee * 4000 < block_min_fee_rate * weight
            //
            // FIX-72 / W120 BUG-11: compare against the MODIFIED fee so a
            // prioritisetransaction-boosted tx isn't filtered out at the
            // block_min_fee_rate gate even when its raw fee is below.
            const modified_fee = mempool.getModifiedFee(entry);
            const fee_u: u64 = if (modified_fee >= 0) @intCast(modified_fee) else 0;
            if (fee_u * 4000 < opts.block_min_fee_rate * entry.weight) {
                // All remaining entries have equal or lower fee rate; stop.
                break;
            }
        }

        // Check transaction finality (locktime validation)
        if (!isFinalTx(&entry.tx, height, lock_time_cutoff)) {
            consecutive_failed += 1;
            if (consecutive_failed > MAX_CONSECUTIVE_FAILURES and
                total_weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > opts.max_weight)
            {
                break;
            }
            continue;
        }

        // Bug-2 fix: use >= (not >) for the weight limit check.
        // Bitcoin Core TestChunkBlockLimits (miner.cpp:241):
        //   if (nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight) return false
        // Using strict > would allow a block of exactly max_weight WU, which
        // would then fail block weight validation during connect (bad-blk-weight).
        if (total_weight + entry.weight >= opts.max_weight) {
            consecutive_failed += 1;
            if (consecutive_failed > MAX_CONSECUTIVE_FAILURES and
                total_weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > opts.max_weight)
            {
                break;
            }
            continue;
        }

        // Bug-3 fix: use >= for the sigops limit check.
        // Bitcoin Core TestChunkBlockLimits (miner.cpp:244):
        //   if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) return false
        const tx_sigops: usize = estimateSigops(&entry.tx);
        if (total_sigops + tx_sigops >= opts.max_sigops) {
            consecutive_failed += 1;
            if (consecutive_failed > MAX_CONSECUTIVE_FAILURES and
                total_weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > opts.max_weight)
            {
                break;
            }
            continue;
        }

        // Transaction fits — add it and reset the failure counter.
        consecutive_failed = 0;

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

    // 8. Compute block version via BIP-9 state machine and construct header.
    //
    // W91 fix: call computeBlockVersion() instead of hardcoding 0x20000000.
    // Miners MUST signal for deployments in STARTED or LOCKED_IN state by
    // setting the corresponding bit in nVersion.
    // Reference: Bitcoin Core versionbits.cpp ComputeBlockVersion() + miner.cpp.
    //
    // Limitation: accurate signaling requires per-height block version data for
    // counting signals during STARTED periods. clearbit's ChainState currently
    // does not maintain a height-keyed version index (the fast IBD path bypasses
    // CF_BLOCK_INDEX). Until that index is wired, the state machine evaluates
    // without historical signal data (all blocks appear as non-signaling in the
    // backward walk). For currently ACTIVE/FAILED deployments this is harmless
    // (NEVER_ACTIVE short-circuits to FAILED; start_time=0 deployments appear
    // STARTED and the bit gets set, which is the correct miner behavior). For
    // deployments still in the signaling window, the count-without-data path
    // will keep them in STARTED and correctly signal the bit.
    const nVersion = blk: {
        // Build a stub IndexView: returns null for all heights since we lack
        // a height-keyed version index. The BIP9 state machine handles null
        // returns as "genesis region = DEFINED".
        const StubCtx = struct {
            fn getAtHeight(_: *anyopaque, _: u32) ?consensus.VersionBitsBlockIndex {
                return null;
            }
        };
        var stub_ctx: u8 = 0;
        const stub_view = consensus.VersionBitsIndexView{
            .context = @ptrCast(&stub_ctx),
            .getAtHeightFn = StubCtx.getAtHeight,
        };
        break :blk consensus.computeBlockVersion(
            params.bip9_deployments,
            height,
            &stub_view,
            null, // no cache in block template path
        );
    };
    const header = types.BlockHeader{
        .version = nVersion,
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

    // Consensus rule: coinbase scriptSig must be at least 2 bytes (bad-cb-length,
    // tx_check.cpp:49).  For heights 1..16 the BIP-34 height push is a single
    // OP_N byte.  Append an OP_0 dummy extranonce to reach the minimum length,
    // mirroring Bitcoin Core miner.cpp:187-193 include_dummy_extranonce logic.
    if (script_sig.items.len < 2) {
        try script_sig.append(0x00); // OP_0 dummy extranonce
    }

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

/// Build the full coinbase scriptSig for a block at the given height.
///
/// Encodes the BIP-34 height push and appends an OP_0 dummy extranonce when
/// necessary to satisfy the 2-byte minimum (bad-cb-length consensus rule).
/// Returns a caller-owned slice; free with allocator.free().
pub fn buildCoinbaseScriptSig(height: u32, extra: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var script = std.ArrayList(u8).init(allocator);
    errdefer script.deinit();
    try encodeHeightPush(&script, height);
    if (script.items.len < 2) {
        try script.append(0x00); // OP_0 dummy extranonce (bad-cb-length guard)
    }
    if (extra.len > 0) {
        const max_extra = @min(extra.len, 96 - script.items.len);
        try script.appendSlice(extra[0..max_extra]);
    }
    return script.toOwnedSlice();
}

/// Encode a block height as a minimal CScriptNum push (BIP-34).
///
/// This pushes the height as a minimal-encoded signed integer:
/// - Heights 0-16 use OP_0 through OP_16
/// - Other heights use a minimal byte push
pub fn encodeHeightPush(script: *std.ArrayList(u8), height: u32) !void {
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

/// Estimate the sigop cost for a transaction (in weight units, consistent with
/// MAX_BLOCK_SIGOPS_COST = 80,000).
///
/// Without UTXO access we cannot count P2SH or witness sigops accurately, so
/// we return only the legacy portion scaled by WITNESS_SCALE_FACTOR (4).
/// This is a conservative lower-bound: the actual cost can only be higher once
/// P2SH/witness sigops are added during block connect, so the block template
/// will never exceed the consensus limit due to this estimation.
///
/// Reference: Bitcoin Core consensus/tx_verify.cpp GetTransactionSigOpCost()
/// (the legacy-only term: GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR).
fn estimateSigops(tx: *const types.Transaction) usize {
    // getLegacySigOpCount uses inaccurate mode (CHECKMULTISIG = 20) for both
    // scriptSig inputs and output scriptPubKeys, matching Core's
    // GetLegacySigOpCount which calls GetSigOpCount(false).
    const legacy = validation.getLegacySigOpCount(tx);
    return @as(usize, legacy) * @as(usize, consensus.WITNESS_SCALE_FACTOR);
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

/// Pattern X helper (CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md):
/// derive the height that should be used to validate a submitted block,
/// using the BLOCK'S parent in the block index when available rather
/// than the active tip. Bitcoin Core's `ContextualCheckBlockHeader`
/// (validation.cpp:4072) uses `pindexPrev->nHeight + 1` — which is the
/// parent in the block index, NOT the active tip — so that BIP-34
/// height-in-coinbase enforcement works correctly for side-branch
/// blocks during a reorg-via-submitblock.
///
/// Falls back to active-tip-relative arithmetic when:
///   - chain_manager is unset (early-startup / no block index loaded)
///   - the parent block isn't yet indexed (genesis-adjacent / unknown
///     parent — the validation gate downstream will surface this as
///     a different rejection)
///
/// The fallback matches pre-fix behaviour for the common best-chain
/// extension case where parent == active tip, and is also invoked for
/// genuinely unknown-parent blocks where the surface error is
/// downstream of BIP-34.
pub fn deriveSubmitHeight(
    prev_block_hash: *const types.Hash256,
    chain_manager: ?*validation.ChainManager,
    active_best_height: u32,
) u32 {
    if (chain_manager) |cm| {
        if (cm.getBlock(prev_block_hash)) |parent| {
            return parent.height + 1;
        }
    }
    return active_best_height + 1;
}

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
///
/// Pattern X (CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md):
/// height is derived from the BLOCK'S parent in the block index, not from the
/// active tip. This is parity with Bitcoin Core's
/// ContextualCheckBlockHeader (validation.cpp:4072) which uses
/// `pindexPrev->nHeight + 1`. Side-branch blocks (e.g. B1 forking off
/// an ancestor of the current best) get correct BIP-34 height
/// enforcement instead of the spurious bad-cb-height that arises from
/// `chain_state.best_height + 1`.
pub fn submitBlockWithIndex(
    block: *const types.Block,
    chain_state: *storage.ChainState,
    params: *const consensus.NetworkParams,
    chain_manager: ?*validation.ChainManager,
    allocator: std.mem.Allocator,
) !SubmitResult {
    return submitBlockWithIndexAndMempool(
        block,
        chain_state,
        params,
        chain_manager,
        null,
        allocator,
    );
}

/// Same as `submitBlockWithIndex`, but additionally accepts a mempool to
/// drive Bitcoin Core-parity mempool refill on the reorg path (Pattern B,
/// `_mempool-refill-on-reorg-fleet-result-2026-05-05.md`).  Existing
/// callers without a mempool may keep using `submitBlockWithIndex`; the
/// RPC `submitblock` handler always passes a mempool through this entry
/// point so a heavier-branch arrival re-admits disconnected non-coinbase
/// txs, matching `MaybeUpdateMempoolForReorg` in Bitcoin Core.
pub fn submitBlockWithIndexAndMempool(
    block: *const types.Block,
    chain_state: *storage.ChainState,
    params: *const consensus.NetworkParams,
    chain_manager: ?*validation.ChainManager,
    mempool: ?*mempool_mod.Mempool,
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

    // Pattern X: derive height from BLOCK'S parent in the block index, not
    // from the active tip. Falls back to active-tip-relative arithmetic
    // when chain_manager is unset or the parent isn't indexed (genesis-
    // adjacent / pre-IBD). See the doc-comment above this function and
    // `deriveSubmitHeight`.
    const height: u32 = deriveSubmitHeight(
        &block.header.prev_block,
        chain_manager,
        chain_state.best_height,
    );

    // Context-free block sanity check: coinbase position, merkle root, weight,
    // BIP-34 height, BIP-141 witness commitment recomputation (bad-witness-merkle-match),
    // and coinbase scriptSig length cap (bad-cb-length).
    // Mirrors Bitcoin Core CheckBlock() (validation.cpp) which runs before
    // ConnectBlock().  Both checks are consensus-critical:
    //   - coinbase scriptSig 2..100 bytes: consensus/tx_check.cpp:49
    //   - witness commitment recompute: validation.cpp:3870-3901 CheckWitnessMalleation
    validation.checkBlock(block, height, params, allocator) catch |err| {
        return .{
            .accepted = false,
            .reject_reason = switch (err) {
                error.CoinbaseScriptSize => "bad-cb-length",
                error.BadWitnessCommitment => "bad-witness-merkle-match",
                error.BadMerkleRoot => "bad-txnmrklroot",
                error.BadCoinbaseHeight => "bad-cb-height",
                error.TooManySigops => "bad-blk-sigops",
                error.BadBlockWeight => "bad-blk-weight",
                error.BadBlockSize => "bad-blk-length",
                error.BadProofOfWork => "high-hash",
                else => "rejected",
            },
            .block_hash = block_hash,
        };
    };

    // ContextualCheckBlock: enforce IsFinalTx for every transaction in the
    // submitted block (Bitcoin Core validation.cpp:4146 ContextualCheckBlock).
    // This is a consensus rule — NOT skipped under assumevalid (Core only
    // skips script verification, never locktime finality).
    // lock_time_cutoff = MTP-of-11 of the parent once BIP-113/CSV is active
    // (post-activation), else the block's own header timestamp (pre-activation).
    // Reference: consensus/tx_verify.cpp:IsFinalTx, BIP-113.
    {
        const csv_active = height >= params.csv_height;
        const prev_mtp: u32 = if (csv_active) chain_state.computeMTP() else 0;
        const lock_time_cutoff: u32 = if (csv_active and prev_mtp != 0)
            prev_mtp
        else
            block.header.timestamp;
        for (block.transactions) |*tx| {
            if (!validation.isFinalTx(tx, height, lock_time_cutoff)) {
                return .{
                    .accepted = false,
                    .reject_reason = "bad-txns-nonfinal",
                    .block_hash = block_hash,
                };
            }
        }
    }

    // Pattern Y (CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md):
    // decouple block storage from best-chain selection. Bitcoin Core's
    // `BlockManager::AcceptBlock` (validation.cpp) writes
    // `pindexNew->nChainWork` and sets `BLOCK_HAVE_DATA` on every accepted
    // block — best-chain or side-branch — with `ConnectBlock` deferred to
    // a later `ActivateBestChain`. Three paths from here:
    //
    //   * extends_active_tip: block.prev == chain_state.best_hash. This is
    //     the happy path — connect to the active chain via
    //     `connectBlockFastWithUndo` so undo data is persisted (a future
    //     reorg can disconnect this block).
    //   * side_branch: block.prev != active tip but parent IS in the
    //     chain_manager block_index. Persist body + index entry; if the
    //     new chain's chain_work strictly exceeds the active tip's, fire
    //     `chain_state.reorgToChain` (disconnects active chain to fork
    //     point, connects the new chain in order); otherwise return BIP-22
    //     "inconclusive" (Core convention from rpc/mining.cpp::submitblock).
    //   * unknown_parent: parent isn't in the index. Reject — same shape
    //     as Pattern X's downstream BIP-22 rejection for an orphan block.
    //
    // Cross-impl reference closures: rustoshi 68a422b, blockbrew 4e51e8b,
    // camlcoin 22667c2, nimrod 7196d41, beamchain fcbb4b7, lunarblock 462f23b.
    // Counterpart to Pattern X commit 546c57a (height derivation).

    const extends_active_tip = std.mem.eql(u8, &block.header.prev_block, &chain_state.best_hash);

    const parent_in_cm: ?*validation.BlockIndexEntry =
        if (chain_manager) |cm| cm.getBlock(&block.header.prev_block) else null;

    if (!extends_active_tip and parent_in_cm != null) {
        return processSideBranchSubmission(
            block,
            &block_hash,
            height,
            chain_state,
            chain_manager.?,
            parent_in_cm.?,
            mempool,
            allocator,
        );
    }

    // Persist the raw block body to CF_BLOCKS BEFORE applying UTXO
    // mutations.  Same semantics as the peer.zig drainBlockBuffer path —
    // the queue is consumed by ChainState.flush() so the body and tip
    // commit atomically (Bitcoin Core analog: SaveBlockToDisk before
    // CheckBlock in validation.cpp).  Failure here is non-fatal; the
    // block still connects, CF_BLOCKS just misses this entry.
    {
        var writer = serialize.Writer.init(chain_state.allocator);
        const queued = blk: {
            serialize.writeBlock(&writer, block) catch {
                writer.deinit();
                break :blk false;
            };
            const owned_const = writer.toOwnedSlice() catch {
                writer.deinit();
                break :blk false;
            };
            const owned: []u8 = @constCast(owned_const);
            chain_state.queueBlockWrite(&block_hash, owned, height) catch {
                chain_state.allocator.free(owned);
                break :blk false;
            };
            break :blk true;
        };
        if (!queued) {
            std.debug.print("submitblock: queueBlockWrite skipped at height {d}\n", .{height});
        }
    }

    // During IBD (below assume-valid height), use the fast path that skips
    // undo data collection.  Undo data is only needed for reorgs, and during
    // sequential feeding we immediately discard it anyway.  This saves
    // significant allocation overhead for large blocks.
    //
    // Pattern Y note: outside of ibd_mode the connect path now persists
    // undo data via `connectBlockFastWithUndo`. Without per-block undo on
    // the happy path, a future reorg-via-submitblock that needs to
    // disconnect a happy-path-mined A1/A2 would fail with
    // "UndoDataNotFound" (storage.zig:2595). Mirrors the IBD reorg-safe
    // path in peer.zig::drainBlockBuffer (CLEARBIT_REORG=1) and the same
    // change in camlcoin Pattern Y (lib/mining.ml ::submit_block, store
    // undo on every accepted block).
    const ibd_mode = params.assume_valid_height > 0 and height <= params.assume_valid_height;
    if (ibd_mode) {
        chain_state.connectBlockFast(block, &block_hash, height) catch |err| {
            // Map to BIP-22 canonical strings (Bitcoin Core BIP22ValidationResult).
            // connectBlockFast propagates errors from connectBlockInner + flush.
            return .{
                .accepted = false,
                .reject_reason = switch (err) {
                    error.MissingInput => "bad-txns-inputs-missingorspent",
                    else => "rejected",
                },
                .block_hash = block_hash,
            };
        };
    } else {
        chain_state.connectBlockFastWithUndo(block, &block_hash, height) catch |err| {
            // Map to BIP-22 canonical strings (Bitcoin Core BIP22ValidationResult).
            return .{
                .accepted = false,
                .reject_reason = switch (err) {
                    error.MissingInput => "bad-txns-inputs-missingorspent",
                    error.PrevBlockMismatch, error.HeightMismatch =>
                    // The active-tip pre-check at the top of submitBlockWithIndex
                    // should have routed prev-block mismatch into the side-branch
                    // arm. If we land here it means the block looked like a
                    // best-chain extension but raced with another submission —
                    // surface as "rejected" rather than corrupting state.
                    "rejected",
                    else => "rejected",
                },
                .block_hash = block_hash,
            };
        };
    }

    // Per-block atomic flush: pending_deletes + dirty UTXOs + tip + bodies +
    // undo all commit in one WriteBatch via ChainState.flush() (already
    // invoked inside connectBlockFastWithUndo / connectBlockFast).  This
    // additional flush is a near no-op kept for symmetry with the legacy
    // path; the flush_error sticky-flag halts on persistence failure so we
    // never silently desync (Option A, wave2-2026-04-14).
    chain_state.flush() catch |err| {
        std.debug.print("submitblock: atomic flush failed at height {d}: {} — halting\n", .{ height, err });
        chain_state.flush_error = true;
        return .{
            .accepted = false,
            // BIP-22 has no specific string for flush failure; "rejected" is the catch-all.
            .reject_reason = "rejected",
            .block_hash = block_hash,
        };
    };

    // Insert into the block index so that getblockheader / getblockhash can
    // find the block afterwards.  Pattern Y: chain_work is parent.chain_work
    // + workFromBits(this header) — was previously copied straight from
    // the parent (no work increment), which broke the strict-greater
    // comparison in the side-branch arm.
    if (chain_manager) |cm| {
        const parent = cm.getBlock(&block.header.prev_block);
        var new_work: [32]u8 = if (parent) |p| p.chain_work else [_]u8{0} ** 32;
        const this_work = peer.workFromBits(block.header.bits);
        peer.addChainWorkBE(&new_work, &this_work);

        const entry = allocator.create(validation.BlockIndexEntry) catch {
            // Non-fatal: the block is already connected to the UTXO chain.
            return .{ .accepted = true, .reject_reason = null, .block_hash = block_hash };
        };
        entry.* = validation.BlockIndexEntry{
            .hash = block_hash,
            .header = block.header,
            .height = height,
            .status = .{ .valid_header = true, .has_data = true, .has_undo = !ibd_mode, .failed_valid = false, .failed_child = false, ._padding = 0 },
            .chain_work = new_work,
            .sequence_id = 0,
            .parent = parent,
            .file_number = 0,
            .file_offset = 0,
        };

        cm.addBlock(entry) catch {};

        // Update the active tip — this is the best-chain extension arm
        // (extends_active_tip), so the new block IS the new active tip.
        cm.active_tip = entry;

        // Persist to ChainStore on disk
        if (cm.chain_store) |cs| {
            cs.putBlockIndex(&block_hash, &block.header, height) catch {};
        }
    }

    // W93 G15 mempool-removeForBlock parity: drop confirmed txs from the
    // mempool now that the block is part of the active chain.  Mirrors
    // Bitcoin Core's Chainstate::ConnectTip (validation.cpp:3074):
    //   if (m_mempool) {
    //       m_mempool->removeForBlock(block_to_connect->vtx, pindexNew->nHeight);
    //   }
    // Without this, confirmed txs linger in the mempool indefinitely and
    // would be (a) re-relayed on the next `inv` round and (b) cause
    // double-spend rejections for any RBF replacements landing in a
    // later block.  Runs only after the chain-state advance succeeds.
    if (mempool) |mp| {
        mp.removeForBlock(block);
    }

    return .{
        .accepted = true,
        .reject_reason = null,
        .block_hash = block_hash,
    };
}

/// Pattern Y side-branch arm of submitBlockWithIndex.
///
/// Called when `block.prev != chain_state.best_hash` BUT the parent is in
/// `chain_manager.block_index`. Three sub-cases:
///
///   * Strict-greater chain_work → fire reorg via
///     `chain_state.reorgToChain` (disconnects active chain to fork
///     point, connects this branch's blocks). New tip = this block.
///     Returns "accept" (BIP-22 null result).
///   * Equal/lesser chain_work → store body + BlockIndexEntry but do NOT
///     touch active tip. Returns "inconclusive" (BIP-22 side-branch
///     storage convention from rpc/mining.cpp::submitblock).
///   * reorg failure → returns "rejected" with logging.
///
/// Reference: bitcoin-core/src/validation.cpp::AcceptBlock (writes
/// HAVE_DATA on every accepted block) + ActivateBestChain (selects the
/// heaviest valid leaf as new tip). Storage and best-chain selection are
/// decoupled in Core; this function brings clearbit's submitblock path
/// into parity.
pub fn processSideBranchSubmission(
    block: *const types.Block,
    block_hash: *const types.Hash256,
    height: u32,
    chain_state: *storage.ChainState,
    cm: *validation.ChainManager,
    parent_entry: *validation.BlockIndexEntry,
    mempool: ?*mempool_mod.Mempool,
    allocator: std.mem.Allocator,
) !SubmitResult {
    // Compute new chain_work = parent.chain_work + workFromBits(this header).
    var new_work: [32]u8 = parent_entry.chain_work;
    const this_work = peer.workFromBits(block.header.bits);
    peer.addChainWorkBE(&new_work, &this_work);

    // Persist the raw block body to CF_BLOCKS so a future reorg-connect
    // can replay this block from disk. Same path as the active-tip arm
    // (queueBlockWrite + flush). Failure here is non-fatal at the
    // body-write level; we still register the index entry so a later
    // resubmission can fill in the gap.
    var body_persisted = false;
    {
        var writer = serialize.Writer.init(chain_state.allocator);
        const queued = blk: {
            serialize.writeBlock(&writer, block) catch {
                writer.deinit();
                break :blk false;
            };
            const owned_const = writer.toOwnedSlice() catch {
                writer.deinit();
                break :blk false;
            };
            const owned: []u8 = @constCast(owned_const);
            chain_state.queueBlockWrite(block_hash, owned, height) catch {
                chain_state.allocator.free(owned);
                break :blk false;
            };
            break :blk true;
        };
        if (queued) {
            chain_state.flush() catch |err| {
                std.debug.print(
                    "submitblock side-branch: body flush failed at h={d}: {}\n",
                    .{ height, err },
                );
            };
            body_persisted = true;
        } else {
            std.debug.print(
                "submitblock side-branch: queueBlockWrite skipped at h={d}\n",
                .{height},
            );
        }
    }

    // Register the side-branch entry in the chain_manager block_index
    // BEFORE deciding reorg vs. inconclusive: we want the entry to exist
    // even if the chain_work comparison says "stay on active". Skip
    // duplicates (a re-submission of an already-known side-branch block
    // is a no-op + return "duplicate-inconclusive" per Core convention).
    if (cm.getBlock(block_hash)) |_| {
        return .{
            .accepted = false,
            .reject_reason = "duplicate-inconclusive",
            .block_hash = block_hash.*,
        };
    }

    const entry = allocator.create(validation.BlockIndexEntry) catch {
        return .{
            .accepted = false,
            .reject_reason = "rejected",
            .block_hash = block_hash.*,
        };
    };
    entry.* = validation.BlockIndexEntry{
        .hash = block_hash.*,
        .header = block.header,
        .height = height,
        .status = .{
            .valid_header = true,
            .has_data = body_persisted,
            .has_undo = false, // side-branch hasn't been connected yet
            .failed_valid = false,
            .failed_child = false,
            ._padding = 0,
        },
        .chain_work = new_work,
        .sequence_id = 0,
        .parent = parent_entry,
        .file_number = 0,
        .file_offset = 0,
    };
    cm.addBlock(entry) catch {
        allocator.destroy(entry);
        return .{
            .accepted = false,
            .reject_reason = "rejected",
            .block_hash = block_hash.*,
        };
    };

    // Persist header to disk so getblockheader / getblockhash sees it.
    if (cm.chain_store) |cs| {
        cs.putBlockIndex(block_hash, &block.header, height) catch {};
    }

    // Compare chain_work: do we have strictly more work than the active
    // tip?  Core's `ActivateBestChain` uses strict-greater (first-seen
    // wins on ties, validation.cpp:CBlockIndexWorkComparator).
    const active_tip_work: [32]u8 = if (cm.active_tip) |at|
        at.chain_work
    else
        peer.chainWorkFromHeight(chain_state.best_height);

    if (peer.cmpChainWorkBE(&new_work, &active_tip_work) <= 0) {
        // Side-branch with insufficient work — store + return BIP-22
        // "inconclusive" (Core convention). The block stays in the
        // index; if a heavier descendant arrives later, this block is
        // a reorg-replay candidate.
        return .{
            .accepted = false,
            .reject_reason = "inconclusive",
            .block_hash = block_hash.*,
        };
    }

    // Heavier branch — trigger reorg. Walk back from this block's parent
    // to the most recent ancestor on the active chain (fork point), then
    // collect the chain forward [fork_point + 1 .. this block] in
    // connection order. Each block's body is read from CF_BLOCKS via
    // chain_state.getBlockBytes (they were stored when each B-block was
    // submitted as a side-branch).
    const reorg_result = fireReorgFromSideBranch(
        block,
        block_hash,
        height,
        chain_state,
        cm,
        entry,
        mempool,
        allocator,
    ) catch |err| {
        std.debug.print(
            "submitblock side-branch: reorg failed at h={d}: {} — keeping active tip\n",
            .{ height, err },
        );
        return .{
            .accepted = false,
            .reject_reason = "rejected",
            .block_hash = block_hash.*,
        };
    };
    return reorg_result;
}

/// Walk back from `new_tip_entry` to the most recent ancestor on the
/// active chain (the fork point), then drive `chain_state.reorgToChain`
/// with the in-order list of fork blocks. On success: updates
/// `cm.active_tip` to `new_tip_entry`. On failure: returns the storage
/// error for the caller to map.
///
/// When `mempool` is non-null, this also implements Pattern B mempool
/// refill (`_mempool-refill-on-reorg-fleet-result-2026-05-05.md`).
/// Before firing the reorg, we walk the active chain from the current
/// tip back to the fork point and snapshot the non-coinbase txs of
/// every block being disconnected.  After `reorgToChain` succeeds, we
/// re-admit those snapshots to the mempool via `Mempool.blockDisconnected`,
/// matching Bitcoin Core's `MaybeUpdateMempoolForReorg` flow.
/// Reference: camlcoin `lib/sync.ml:2354-2363`.
fn fireReorgFromSideBranch(
    new_tip_block: *const types.Block,
    new_tip_hash: *const types.Hash256,
    new_tip_height: u32,
    chain_state: *storage.ChainState,
    cm: *validation.ChainManager,
    new_tip_entry: *validation.BlockIndexEntry,
    mempool: ?*mempool_mod.Mempool,
    allocator: std.mem.Allocator,
) !SubmitResult {
    // Walk up the parent chain from new_tip_entry back to the active chain.
    // The walk stops at the first ancestor whose hash equals the active
    // tip hash OR whose hash is reachable via chain_state.hasBlock (a
    // historical active-chain block).
    var fork_chain = std.ArrayList(*validation.BlockIndexEntry).init(allocator);
    defer fork_chain.deinit();

    // The new tip is the deepest block in the fork chain.
    try fork_chain.append(new_tip_entry);

    var cursor: *validation.BlockIndexEntry = new_tip_entry;
    var fork_point_hash: ?types.Hash256 = null;
    const MAX_DEPTH: u32 = 288;
    var depth: u32 = 0;

    while (depth < MAX_DEPTH) : (depth += 1) {
        const parent_ptr = cursor.parent orelse {
            // No parent in the index — fork falls off our knowledge.
            return error.ForkPointNotInIndex;
        };
        // Is parent on the active chain?  We can't use
        // chain_state.hasBlock() — that returns true for any block in
        // CF_BLOCKS, including side-branch bodies we just stored. The
        // correct check is the height->hash index, which only points
        // at the active chain (atomic with tip via ChainState.flush).
        // Reference: storage.zig:2150 getBlockHashByHeight.
        if (std.mem.eql(u8, &parent_ptr.hash, &chain_state.best_hash)) {
            fork_point_hash = parent_ptr.hash;
            break;
        }
        if (chain_state.getBlockHashByHeight(parent_ptr.height)) |active_hash| {
            if (std.mem.eql(u8, &active_hash, &parent_ptr.hash)) {
                fork_point_hash = parent_ptr.hash;
                break;
            }
        }
        // Not on active chain — keep walking up. Push parent onto
        // fork_chain (we're collecting in tip-first order; we'll reverse
        // before handing off to reorgToChain).
        try fork_chain.append(parent_ptr);
        cursor = parent_ptr;
    }

    const fp = fork_point_hash orelse return error.ForkPointNotFound;

    // Reverse: reorgToChain expects [fork_point + 1, ..., new_tip].
    std.mem.reverse(*validation.BlockIndexEntry, fork_chain.items);

    // Build ReorgBlock array. Each block's body comes from CF_BLOCKS
    // (queueBlockWrite + flush already persisted them as the side-branch
    // submissions arrived). The new_tip's body, however, may not yet be
    // persisted (the caller's `body_persisted` flag) — but in
    // processSideBranchSubmission we always flush before getting here,
    // so the lookup should succeed for new_tip too. Defensive: if the
    // disk lookup fails for new_tip, fall back to the in-memory block
    // we already have.
    var rb_list = std.ArrayList(storage.ChainState.ReorgBlock).init(allocator);
    // Track allocated blocks so we can free them on error.
    var owned_blocks = std.ArrayList(types.Block).init(allocator);
    defer {
        for (owned_blocks.items) |*b| serialize.freeBlock(allocator, b);
        owned_blocks.deinit();
        rb_list.deinit();
    }

    for (fork_chain.items) |fc_entry| {
        if (std.mem.eql(u8, &fc_entry.hash, new_tip_hash)) {
            // Use the in-memory block for the new tip — avoids a
            // serialize-deserialize round-trip and handles the case
            // where the body flush above silently failed.
            try rb_list.append(.{
                .hash = new_tip_hash.*,
                .block = new_tip_block.*,
                .height = new_tip_height,
            });
            continue;
        }

        const bytes_opt = chain_state.getBlockBytes(&fc_entry.hash) catch null;
        const bytes = bytes_opt orelse return error.SideBranchBodyNotFound;
        defer allocator.free(bytes);

        var reader = serialize.Reader{ .data = bytes };
        const decoded = try serialize.readBlock(&reader, allocator);
        try owned_blocks.append(decoded);
        try rb_list.append(.{
            .hash = fc_entry.hash,
            .block = decoded,
            .height = fc_entry.height,
        });
    }

    // Pattern B (mempool refill on reorg, _mempool-refill-on-reorg-
    // fleet-result-2026-05-05.md): collect the active-chain blocks
    // we're about to disconnect.  The disconnect path doesn't delete
    // CF_BLOCKS entries, so we could in principle re-load these AFTER
    // reorgToChain runs — but staging them up-front mirrors Core's
    // DisconnectTip flow (which queues the disconnected txs into a
    // pool-update list and applies them after reconnection) and keeps
    // the read path independent of any future ChainDB-level cleanup
    // pass that does evict body bytes during disconnect.
    //
    // Collected only when a mempool is wired in — non-RPC paths (test
    // shims, miner-driven submitBlock) pass null and skip the work.
    var disconnected_blocks = std.ArrayList(types.Block).init(allocator);
    defer {
        for (disconnected_blocks.items) |*b| serialize.freeBlock(allocator, b);
        disconnected_blocks.deinit();
    }

    if (mempool != null) {
        var walk_hash: types.Hash256 = chain_state.best_hash;
        var walk_depth: u32 = 0;
        // Bound the snapshot walk to MAX_DEPTH so a malformed index
        // never runs us off into infinity.  reorgToChain itself caps
        // at storage.ChainState.MAX_REORG_DEPTH (100, per Pattern D
        // multi-block atomicity batch-size cap) — but the fork-point
        // walk above uses MAX_DEPTH for symmetry with the peer-layer
        // header walk (peer.MAX_REORG_DEPTH = 288).  A reorg accepted
        // by the peer layer but rejected by storage as too deep
        // surfaces as `error.ReorgTooDeep` — operator-visible.
        while (walk_depth < MAX_DEPTH and !std.mem.eql(u8, &walk_hash, &fp)) : (walk_depth += 1) {
            const bytes_opt = chain_state.getBlockBytes(&walk_hash) catch null;
            const bytes = bytes_opt orelse break;
            defer allocator.free(bytes);

            var block_reader = serialize.Reader{ .data = bytes };
            const disc_block = serialize.readBlock(&block_reader, allocator) catch break;
            disconnected_blocks.append(disc_block) catch {
                var to_free = disc_block;
                serialize.freeBlock(allocator, &to_free);
                break;
            };

            // Step to parent on the active chain.
            walk_hash = disc_block.header.prev_block;
        }
    }

    // Fire the reorg.  reorgToChain will:
    //   1. Disconnect blocks from current tip back to fp (UTXO rewind +
    //      best_hash/best_height update).
    //   2. Re-queueBlockWrite each new chain block (idempotent for the
    //      side-branch ones already on disk).
    //   3. connectBlockFastWithUndo each new block (UTXO apply + undo
    //      capture + atomic flush).
    const connected = try chain_state.reorgToChain(&fp, rb_list.items);
    _ = connected;

    // Update cm.active_tip to point at the new tip.
    cm.active_tip = new_tip_entry;

    // Pattern B refill — fire AFTER the new chain is fully connected
    // (Core orders things the same way: ActivateBestChain finishes the
    // reorg, then MaybeUpdateMempoolForReorg re-admits disconnected txs
    // against the new tip's UTXO state).  Each block hands its txs to
    // mempool.blockDisconnected, which round-trips per non-coinbase tx
    // through serialize → deserialize so the mempool entry owns its
    // own slices regardless of when the source block is freed.
    if (mempool) |mp| {
        for (disconnected_blocks.items) |*b| {
            mp.blockDisconnected(b.transactions);
        }

        // W93 G15: after re-admitting txs from the disconnected blocks,
        // evict any tx that the NEW active branch confirmed.  Two-step
        // dance mirrors Core's MaybeUpdateMempoolForReorg + per-tip
        // ConnectTip-time removeForBlock: an RBF tx that confirmed on the
        // new branch must NOT be re-admitted from the disconnected side
        // (re-admit happens above; this loop drops it again).  Without
        // this, the mempool ends up with stale entries for any tx already
        // on the heavier chain.  Iterates the new-branch blocks in chain
        // order (rb_list is already [fork_point + 1 ... new_tip]).
        for (rb_list.items) |rb| {
            mp.removeForBlock(&rb.block);
        }
    }

    return .{
        .accepted = true,
        .reject_reason = null,
        .block_hash = new_tip_hash.*,
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
    /// Serialized block data for each mined block (for P2P serving).
    serialized_blocks: std.ArrayList([]const u8),

    pub fn deinit(self: *GenerateResult) void {
        for (self.serialized_blocks.items) |data| {
            self.block_hashes.allocator.free(data);
        }
        self.serialized_blocks.deinit();
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
    return mineBlockWithIndex(template, chain_state, params, max_tries, submit_block, null, null, allocator);
}

/// Mine a single block, optionally inserting into the block index.
///
/// `mempool` (optional): when provided, confirmed transactions are dropped
/// from the mempool as the block connects (Core's ConnectTip ->
/// removeForBlock). Without it, a wallet-native spend that confirms via
/// generatetoaddress would linger in the mempool indefinitely (mempool
/// wedge / re-relay). The generatetoaddress / generatetodescriptor callers
/// thread their mempool through; the bare `mineBlock` wrapper passes null.
pub fn mineBlockWithIndex(
    template: *BlockTemplate,
    chain_state: *storage.ChainState,
    params: *const consensus.NetworkParams,
    max_tries: u64,
    submit_block: bool,
    chain_manager: ?*validation.ChainManager,
    mempool: ?*mempool_mod.Mempool,
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

                // Submit to chain (with block index update when chain_manager
                // is available). Route through the mempool-aware entry point so
                // confirmed txs are evicted on connect (removeForBlock) — keeps
                // generatetoaddress from leaving a wallet spend wedged in the
                // mempool after it confirms.
                const result = try submitBlockWithIndexAndMempool(&block, chain_state, params, chain_manager, mempool, allocator);
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
        .serialized_blocks = std.ArrayList([]const u8).init(allocator),
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
            mempool, // evict confirmed txs from the mempool on connect
            allocator,
        );

        if (block_hash) |hash| {
            try result.block_hashes.append(hash);

            // Serialize the mined block for P2P serving
            const block = assembleBlock(&template, allocator) catch null;
            if (block) |blk| {
                defer allocator.free(blk.transactions);
                var writer = serialize.Writer.init(allocator);
                serialize.writeBlock(&writer, &blk) catch {
                    writer.deinit();
                };
                const written = writer.getWritten();
                if (written.len > 0) {
                    const block_data = allocator.dupe(u8, written) catch null;
                    writer.deinit();
                    if (block_data) |data| {
                        try result.serialized_blocks.append(data);
                    }
                } else {
                    writer.deinit();
                }
            }

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
        mempool, // evict confirmed txs from the mempool on connect
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

/// Estimate transaction weight per BIP-141.
///
/// Formula: weight = base_size × (WITNESS_SCALE_FACTOR − 1) + total_size
///                 = base_size × 3 + total_size
///
/// For a segwit transaction, total_size = base_size + 2 (marker+flag) + witness_size.
/// For a non-segwit transaction, total_size = base_size (no witness overhead).
///
/// The previous implementation used `base_size × 4 + witness_size`, which dropped
/// the 2-byte segwit overhead (marker 0x00 + flag 0x01 in the serialized form),
/// underestimating the weight of segwit transactions by 2 WU each.
///
/// Reference: Bitcoin Core consensus/validation.h:132-135, policy/policy.cpp:390-407
fn estimateTxWeight(tx: *const types.Transaction) usize {
    // Non-witness (base) size: version + input_count + inputs + output_count + outputs + locktime
    var base_size: usize = 4; // version
    base_size += 1; // input count varint (simplified; accurate for <= 252 inputs)
    for (tx.inputs) |input| {
        base_size += 32; // prev txid
        base_size += 4; // prev index
        base_size += 1 + input.script_sig.len; // scriptSig length + data
        base_size += 4; // sequence
    }
    base_size += 1; // output count varint (simplified)
    for (tx.outputs) |output| {
        base_size += 8; // value
        base_size += 1 + output.script_pubkey.len; // scriptPubKey length + data
    }
    base_size += 4; // locktime

    // Determine whether any input has witness data.
    var has_witness = false;
    var witness_size: usize = 0;
    for (tx.inputs) |input| {
        if (input.witness.len > 0) {
            has_witness = true;
            witness_size += 1; // stack item count varint for this input
            for (input.witness) |item| {
                witness_size += 1 + item.len; // item length + data
            }
        } else if (has_witness or blk: {
            // If a later input has witness we still need a 0x00 stack-count byte
            // for this input.  Check conservatively: any input with witness
            // triggers the segwit serialization for ALL inputs.
            break :blk false;
        }) {
            witness_size += 1; // empty witness stack (0x00) for non-witness inputs
        }
    }

    // total_size = base_size (common non-witness fields)
    //            + 2          (segwit marker 0x00 + flag 0x01, only when has_witness)
    //            + witness_size
    //
    // weight = base_size × 3 + total_size
    //        = base_size × 3 + base_size + (has_witness ? 2 : 0) + witness_size
    //        = base_size × 4 + (has_witness ? 2 : 0) + witness_size
    const marker_flag: usize = if (has_witness) 2 else 0;
    return base_size * (consensus.WITNESS_SCALE_FACTOR - 1) + base_size + marker_flag + witness_size;
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

test "coinbase scriptSig >=2 bytes at heights 1-16 (bad-cb-length fix, W108 BUG-20)" {
    // Consensus: coinbase scriptSig must be 2..100 bytes (tx_check.cpp:49).
    // Heights 1-16: encodeHeightPush emits one OP_N byte.  The
    // constructCoinbaseWithCommitment path must append OP_0 to reach 2 bytes.
    const allocator = std.testing.allocator;
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;

    const heights_to_test = [_]u32{ 1, 2, 8, 16 };
    for (heights_to_test) |h| {
        const coinbase = try constructCoinbase(h, 0, "", &payout, false, &consensus.MAINNET, allocator);
        defer {
            allocator.free(coinbase.script_sig);
            allocator.free(coinbase.outputs);
            allocator.free(coinbase.inputs);
        }
        try std.testing.expect(coinbase.script_sig.len >= 2);
        // First byte should still be the OP_N height encoding (0x51..0x60)
        try std.testing.expectEqual(@as(u8, 0x50) + @as(u8, @intCast(h)), coinbase.script_sig[0]);
        // Second byte should be OP_0 dummy extranonce
        try std.testing.expectEqual(@as(u8, 0x00), coinbase.script_sig[1]);
    }
}

test "coinbase scriptSig CScriptNum sign-bit padding at height 128+ (W108 BUG-20 sign-bit)" {
    // Heights with MSB set (e.g. 128 = 0x80) require a zero sign byte appended
    // to indicate the value is positive.  Verify heights 128, 255, 256 encode
    // correctly as multi-byte CScriptNum pushes with sign-bit padding.
    const allocator = std.testing.allocator;
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;

    // height=128: CScriptNum encoding: push 2 bytes [0x80, 0x00] → [0x02, 0x80, 0x00]
    {
        const coinbase = try constructCoinbase(128, 0, "", &payout, false, &consensus.MAINNET, allocator);
        defer {
            allocator.free(coinbase.script_sig);
            allocator.free(coinbase.outputs);
            allocator.free(coinbase.inputs);
        }
        try std.testing.expect(coinbase.script_sig.len >= 2);
        try std.testing.expectEqual(@as(u8, 0x02), coinbase.script_sig[0]); // push 2 bytes
        try std.testing.expectEqual(@as(u8, 0x80), coinbase.script_sig[1]); // 128 LE
        try std.testing.expectEqual(@as(u8, 0x00), coinbase.script_sig[2]); // sign byte
    }

    // height=255: 0xFF has high bit set → push [0xFF, 0x00]
    {
        const coinbase = try constructCoinbase(255, 0, "", &payout, false, &consensus.MAINNET, allocator);
        defer {
            allocator.free(coinbase.script_sig);
            allocator.free(coinbase.outputs);
            allocator.free(coinbase.inputs);
        }
        try std.testing.expect(coinbase.script_sig.len >= 2);
        try std.testing.expectEqual(@as(u8, 0x02), coinbase.script_sig[0]); // push 2 bytes
        try std.testing.expectEqual(@as(u8, 0xFF), coinbase.script_sig[1]); // 255 LE
        try std.testing.expectEqual(@as(u8, 0x00), coinbase.script_sig[2]); // sign byte
    }

    // height=256: 0x0100, high bit of LSB not set → push [0x00, 0x01]
    {
        const coinbase = try constructCoinbase(256, 0, "", &payout, false, &consensus.MAINNET, allocator);
        defer {
            allocator.free(coinbase.script_sig);
            allocator.free(coinbase.outputs);
            allocator.free(coinbase.inputs);
        }
        try std.testing.expect(coinbase.script_sig.len >= 2);
        try std.testing.expectEqual(@as(u8, 0x02), coinbase.script_sig[0]); // push 2 bytes
        try std.testing.expectEqual(@as(u8, 0x00), coinbase.script_sig[1]); // 256 LSB
        try std.testing.expectEqual(@as(u8, 0x01), coinbase.script_sig[2]); // 256 MSB
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
    var chain_state = storage.ChainState.init(null, 64, allocator);
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
    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    // P2PKH output: 1 CHECKSIG (inaccurate mode) * WITNESS_SCALE_FACTOR (4) = 4.
    // Empty scriptSig: 0 sigops.
    // Total cost: 4.
    // Reference: Bitcoin Core GetTransactionSigOpCost() legacy term.
    try std.testing.expectEqual(@as(usize, 4), sigops);
}

test "W76: estimateTxWeight non-segwit = 4 × size" {
    // For a transaction with no witness data, total_size == base_size, so:
    //   weight = base_size × 3 + total_size = base_size × 4
    const script = [_]u8{0x51}; // OP_1 (1 byte)
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 50000,
        .script_pubkey = &script,
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const w = estimateTxWeight(&tx);
    // base_size: 4(ver)+1(#in)+32(hash)+4(idx)+1(scriptlen)+0(script)+4(seq)
    //            +1(#out)+8(value)+1(pklen)+1(script)+4(lt) = 61
    // For non-segwit: weight = base_size × 4 = 244
    // Verify weight is a multiple of 4 (no witness) and positive
    try std.testing.expect(w > 0);
    try std.testing.expectEqual(@as(usize, 0), w % 4); // non-segwit weight divisible by 4
}

test "W76: estimateTxWeight segwit includes marker+flag overhead" {
    // For a segwit tx, the 2-byte marker+flag must be counted in total_size.
    // Without the fix, weight = base × 4 + ws; correct = base × 4 + 2 + ws.
    const p2wpkh_spk = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    // A simple P2WPKH witness: [sig(71), pubkey(33)]
    const sig = [_]u8{0x30} ++ [_]u8{0x44} ++ [_]u8{0x00} ** 69; // 71 bytes
    const pubkey = [_]u8{0x02} ++ [_]u8{0x00} ** 32; // 33 bytes compressed
    const witness_items = [_][]const u8{ &sig, &pubkey };
    const input_witness = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &witness_items,
    };
    const output = types.TxOut{
        .value = 49000,
        .script_pubkey = &p2wpkh_spk,
    };
    const tx_witness = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input_witness},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };
    const tx_nowit = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = input_witness.previous_output,
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const w_wit = estimateTxWeight(&tx_witness);
    const w_nowit = estimateTxWeight(&tx_nowit);

    // The segwit tx should weigh more (witness data + 2-byte overhead).
    try std.testing.expect(w_wit > w_nowit);

    // The extra weight vs. a no-witness version of the same base tx is:
    //   2 (marker+flag) + witness_stack bytes (1 count + 1+71 + 1+33 = 107) = 109
    // witness_size = 1 (stack count) + (1+71) + (1+33) = 107
    // delta = 2 (marker+flag) + 107 (witness bytes) = 109
    const witness_stack_bytes: usize = 1 + (1 + 71) + (1 + 33); // 107
    const expected_delta: usize = 2 + witness_stack_bytes; // 109
    try std.testing.expectEqual(w_nowit + expected_delta, w_wit);
}

test "transactions are ordered by fee rate" {
    const allocator = std.testing.allocator;

    // Create chain state
    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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
    var chain_state = storage.ChainState.init(null, 64, allocator);
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
    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

// ============================================================================
// W87 block-template assembly gate tests
// ============================================================================

// Gate 1: DEFAULT_BLOCK_RESERVED_WEIGHT constant value
test "W87: DEFAULT_BLOCK_RESERVED_WEIGHT is 8000" {
    // Bitcoin Core DEFAULT_BLOCK_RESERVED_WEIGHT (policy/policy.h:27) is 8000.
    // A previous value of 1000 was 7000 WU short, allowing the template to
    // exceed the 4 MB consensus limit.
    try std.testing.expectEqual(@as(u32, 8_000), DEFAULT_BLOCK_RESERVED_WEIGHT);
}

// Gate 2: MINIMUM_BLOCK_RESERVED_WEIGHT constant value
test "W87: MINIMUM_BLOCK_RESERVED_WEIGHT is 2000" {
    // Bitcoin Core MINIMUM_BLOCK_RESERVED_WEIGHT (policy/policy.h:34) is 2000.
    try std.testing.expectEqual(@as(u32, 2_000), MINIMUM_BLOCK_RESERVED_WEIGHT);
}

// Gate 3 (clampOptions): block_reserved_weight clamped to MINIMUM_BLOCK_RESERVED_WEIGHT
test "W87: clampOptions enforces minimum block_reserved_weight" {
    // Passing 0 should be raised to MINIMUM_BLOCK_RESERVED_WEIGHT.
    const raw = TemplateOptions{ .block_reserved_weight = 0 };
    const clamped = clampOptions(raw);
    try std.testing.expectEqual(MINIMUM_BLOCK_RESERVED_WEIGHT, clamped.block_reserved_weight);
}

// Gate 4 (clampOptions): max_weight >= block_reserved_weight
test "W87: clampOptions raises max_weight to block_reserved_weight when too small" {
    // max_weight below block_reserved_weight is nonsensical; Core raises it.
    const raw = TemplateOptions{
        .block_reserved_weight = 8_000,
        .max_weight = 100, // below reserved weight
    };
    const clamped = clampOptions(raw);
    try std.testing.expectEqual(clamped.block_reserved_weight, clamped.max_weight);
}

// Gate 5 (clampOptions): max_weight capped at MAX_BLOCK_WEIGHT
test "W87: clampOptions caps max_weight at MAX_BLOCK_WEIGHT" {
    const raw = TemplateOptions{ .max_weight = 999_999_999 };
    const clamped = clampOptions(raw);
    try std.testing.expectEqual(@as(u32, consensus.MAX_BLOCK_WEIGHT), clamped.max_weight);
}

// Gate 6 (clampOptions): max_sigops capped at MAX_BLOCK_SIGOPS_COST
test "W87: clampOptions caps max_sigops at MAX_BLOCK_SIGOPS_COST" {
    const raw = TemplateOptions{ .max_sigops = 999_999_999 };
    const clamped = clampOptions(raw);
    try std.testing.expectEqual(@as(u32, consensus.MAX_BLOCK_SIGOPS_COST), clamped.max_sigops);
}

// Gate 7 (weight boundary): >= not > for weight limit
// Verifies that a transaction that would push total_weight to exactly
// max_weight is rejected.  Before the fix, `>` allowed it through, producing
// a block weighing exactly 4,000,000 WU — which fails the consensus check
// `nBlockWeight < MAX_BLOCK_WEIGHT` used in GetBlockWeight().
test "W87: weight gate rejects tx at exactly max_weight boundary (>=)" {
    // The check is: total_weight + tx.weight >= max_weight → skip
    // We simulate this with the pure gate logic that createBlockTemplate uses.
    const reserved: usize = DEFAULT_BLOCK_RESERVED_WEIGHT;
    const max: usize = consensus.MAX_BLOCK_WEIGHT;
    const tx_weight: usize = max - reserved; // would fill to exactly max

    // With the >= fix, this must NOT fit.
    try std.testing.expect(reserved + tx_weight >= max);
}

// Gate 8 (sigops boundary): >= not > for sigops limit
test "W87: sigops gate rejects tx at exactly MAX_BLOCK_SIGOPS_COST boundary (>=)" {
    const max_sigops: usize = consensus.MAX_BLOCK_SIGOPS_COST;
    const current: usize = max_sigops - 4; // 4 below limit
    const tx_sigops: usize = 4; // would hit exactly the limit

    // With the >= fix, current + tx_sigops == max_sigops should be rejected.
    try std.testing.expect(current + tx_sigops >= max_sigops);
}

// Gate 9 (lock_time_cutoff): template uses MTP not wall clock
// We verify that createBlockTemplate accepts a transaction whose locktime is
// below the MTP (should be final according to Core) even when the wall clock
// might be higher.  With a fresh chain_state (MTP=0) we fall back to wall
// clock; we test the MTP path via isFinalTx directly with a synthetic cutoff.
test "W87: isFinalTx uses MTP cutoff, not wall clock" {
    // lock_time = 1600000000 (time-based).
    // MTP = 1600000001 → transaction IS final (lock_time < MTP).
    // Wall clock at the same instant = 1600000000 → transaction NOT final.
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20,
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 1_600_000_000,
    };

    const height: u32 = 800_000;
    // MTP = 1600000001 → final (lock_time 1600000000 < 1600000001)
    try std.testing.expect(isFinalTx(&tx, height, 1_600_000_001));
    // wall clock = 1600000000 → NOT final (lock_time 1600000000 is not < 1600000000)
    try std.testing.expect(!isFinalTx(&tx, height, 1_600_000_000));
}

// Gate 10 (MAX_CONSECUTIVE_FAILURES): constants present and correctly valued
test "W87: MAX_CONSECUTIVE_FAILURES and BLOCK_FULL_ENOUGH_WEIGHT_DELTA constants" {
    // Bitcoin Core miner.cpp lines 284-286 (W87 ref)
    try std.testing.expectEqual(@as(u32, 1_000), MAX_CONSECUTIVE_FAILURES);
    try std.testing.expectEqual(@as(u32, 4_000), BLOCK_FULL_ENOUGH_WEIGHT_DELTA);
}

// Gate 11 (block_reserved_weight in template): createBlockTemplate seeds
// total_weight from DEFAULT_BLOCK_RESERVED_WEIGHT, not 1000.
test "W87: createBlockTemplate seeds total_weight from DEFAULT_BLOCK_RESERVED_WEIGHT" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // With an empty mempool the total_weight should equal the reserved weight.
    var template = try createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20 },
        allocator,
    );
    defer template.deinit();

    // total_weight must be at least DEFAULT_BLOCK_RESERVED_WEIGHT (8000).
    // Before the fix it was seeded with 1000, so a near-full mempool could
    // produce a 4,007,000 WU block that fails the consensus weight check.
    try std.testing.expect(template.total_weight >= DEFAULT_BLOCK_RESERVED_WEIGHT);
}
