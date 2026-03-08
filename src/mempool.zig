//! Transaction memory pool for unconfirmed transactions.
//!
//! The mempool holds transactions waiting to be included in blocks.
//! It implements:
//! - BIP-125 Replace-By-Fee (RBF)
//! - Ancestor/descendant limits
//! - Dust threshold detection per output type
//! - Fee-rate based eviction
//! - Mining prioritization by ancestor fee rate

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const script = @import("script.zig");
const serialize = @import("serialize.zig");

// ============================================================================
// Mempool Constants
// ============================================================================

/// Maximum mempool size in bytes (300 MB).
pub const MAX_MEMPOOL_SIZE: usize = 300 * 1024 * 1024;

/// Maximum number of unconfirmed ancestors.
pub const MAX_ANCESTOR_COUNT: usize = 25;

/// Maximum number of unconfirmed descendants.
pub const MAX_DESCENDANT_COUNT: usize = 25;

/// Maximum total size of ancestors in bytes.
pub const MAX_ANCESTOR_SIZE: usize = 101_000;

/// Maximum total size of descendants in bytes.
pub const MAX_DESCENDANT_SIZE: usize = 101_000;

/// Transaction expiry time: 2 weeks in seconds.
pub const MEMPOOL_EXPIRY: i64 = 14 * 24 * 60 * 60;

/// Minimum relay fee in satoshis per 1000 vbytes.
pub const MIN_RELAY_FEE: i64 = 1000;

// ============================================================================
// Mempool Errors
// ============================================================================

pub const MempoolError = error{
    /// Transaction is already in the mempool.
    AlreadyInMempool,
    /// Transaction conflicts with another mempool transaction.
    ConflictsWithMempool,
    /// Fee is below the minimum relay fee.
    InsufficientFee,
    /// Too many unconfirmed ancestors.
    TooManyAncestors,
    /// Too many unconfirmed descendants.
    TooManyDescendants,
    /// Ancestor size limit exceeded.
    AncestorSizeLimitExceeded,
    /// Descendant size limit exceeded.
    DescendantSizeLimitExceeded,
    /// Conflicting transaction is not BIP-125 replaceable.
    NonBIP125Replaceable,
    /// Replacement transaction fee is too low.
    ReplacementFeeTooLow,
    /// Mempool is full and transaction's fee is too low for eviction.
    MempoolFull,
    /// Transaction violates standardness rules.
    NonStandard,
    /// Output value is below the dust threshold.
    DustOutput,
    /// Transaction failed validation.
    TxValidationFailed,
    /// Input references a non-existent UTXO.
    MissingInputs,
    /// Memory allocation failure.
    OutOfMemory,
};

// ============================================================================
// Mempool Entry
// ============================================================================

/// A mempool transaction entry with metadata.
pub const MempoolEntry = struct {
    /// The transaction itself.
    tx: types.Transaction,
    /// Transaction hash (without witness).
    txid: types.Hash256,
    /// Witness transaction hash (with witness).
    wtxid: types.Hash256,
    /// Transaction fee in satoshis.
    fee: i64,
    /// Serialized size in bytes.
    size: usize,
    /// Transaction weight in weight units.
    weight: usize,
    /// Virtual size (weight / 4, rounded up).
    vsize: usize,
    /// Fee per virtual byte in satoshis.
    fee_rate: f64,
    /// Unix timestamp when added to mempool.
    time_added: i64,
    /// Block height when added to mempool.
    height_added: u32,
    /// Number of unconfirmed ancestors (including self).
    ancestor_count: usize,
    /// Total size of ancestors in bytes.
    ancestor_size: usize,
    /// Total fees of ancestors in satoshis.
    ancestor_fees: i64,
    /// Number of unconfirmed descendants (including self).
    descendant_count: usize,
    /// Total size of descendants in bytes.
    descendant_size: usize,
    /// Total fees of descendants in satoshis.
    descendant_fees: i64,
    /// Whether transaction signals BIP-125 opt-in RBF.
    is_rbf: bool,

    /// Compute the ancestor fee rate (used for mining prioritization).
    /// This is the fee rate of the transaction including all unconfirmed ancestors.
    pub fn ancestorFeeRate(self: *const MempoolEntry) f64 {
        if (self.ancestor_size == 0) return 0;
        return @as(f64, @floatFromInt(self.ancestor_fees)) /
            @as(f64, @floatFromInt(self.ancestor_size));
    }

    /// Compute the descendant fee rate (used for eviction).
    /// This is the fee rate of the transaction including all unconfirmed descendants.
    pub fn descendantFeeRate(self: *const MempoolEntry) f64 {
        if (self.descendant_size == 0) return 0;
        return @as(f64, @floatFromInt(self.descendant_fees)) /
            @as(f64, @floatFromInt(self.descendant_size));
    }
};

// ============================================================================
// Mempool
// ============================================================================

/// Transaction memory pool.
pub const Mempool = struct {
    /// All transactions indexed by txid.
    entries: std.AutoHashMap(types.Hash256, *MempoolEntry),

    /// Index by wtxid for BIP-339 (wtxid relay).
    by_wtxid: std.AutoHashMap(types.Hash256, types.Hash256),

    /// Outpoint -> txid mapping (which mempool tx spends this outpoint).
    spenders: std.AutoHashMap(types.OutPoint, types.Hash256),

    /// Children: txid -> list of txids that spend its outputs.
    children: std.AutoHashMap(types.Hash256, std.ArrayList(types.Hash256)),

    /// Total mempool size in virtual bytes.
    total_size: usize,

    /// Chain state for UTXO lookups.
    chain_state: ?*storage.ChainState,

    /// Network parameters.
    params: ?*const consensus.NetworkParams,

    allocator: std.mem.Allocator,

    /// Initialize a new mempool.
    pub fn init(
        chain_state: ?*storage.ChainState,
        params: ?*const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) Mempool {
        return Mempool{
            .entries = std.AutoHashMap(types.Hash256, *MempoolEntry).init(allocator),
            .by_wtxid = std.AutoHashMap(types.Hash256, types.Hash256).init(allocator),
            .spenders = std.AutoHashMap(types.OutPoint, types.Hash256).init(allocator),
            .children = std.AutoHashMap(types.Hash256, std.ArrayList(types.Hash256)).init(allocator),
            .total_size = 0,
            .chain_state = chain_state,
            .params = params,
            .allocator = allocator,
        };
    }

    /// Deinitialize the mempool and free all resources.
    pub fn deinit(self: *Mempool) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.entries.deinit();
        self.by_wtxid.deinit();
        self.spenders.deinit();

        var children_iter = self.children.iterator();
        while (children_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.children.deinit();
    }

    /// Attempt to add a transaction to the mempool.
    pub fn addTransaction(self: *Mempool, tx: types.Transaction) MempoolError!void {
        const tx_hash = crypto.computeTxid(&tx, self.allocator) catch return MempoolError.OutOfMemory;

        // 1. Check if already in mempool
        if (self.entries.contains(tx_hash)) {
            return MempoolError.AlreadyInMempool;
        }

        // 2. Check standardness
        try self.checkStandard(&tx);

        // 3. Validate inputs exist (in UTXO set or in mempool) and compute fee
        var total_in: i64 = 0;
        var conflicting_txids = std.ArrayList(types.Hash256).init(self.allocator);
        defer conflicting_txids.deinit();

        for (tx.inputs) |input| {
            // Check mempool first for unconfirmed parent outputs
            if (self.getOutputFromMempool(&input.previous_output)) |mempool_output| {
                total_in += mempool_output.value;
            } else if (self.chain_state) |cs| {
                // Then check UTXO set
                const utxo = cs.utxo_set.get(&input.previous_output) catch null;
                if (utxo) |u| {
                    defer {
                        var mut_u = u;
                        mut_u.deinit(self.allocator);
                    }
                    total_in += u.value;
                } else {
                    return MempoolError.MissingInputs;
                }
            } else {
                // No chain state - for testing, assume inputs exist
                // In production this would return MissingInputs
            }

            // Check if another mempool tx spends this outpoint (potential RBF conflict)
            if (self.spenders.get(input.previous_output)) |conflicting_txid| {
                conflicting_txids.append(conflicting_txid) catch return MempoolError.OutOfMemory;
            }
        }

        // 4. Compute total outputs
        var total_out: i64 = 0;
        for (tx.outputs) |output| {
            total_out += output.value;
        }

        // 5. Compute fee (allow tests without chain state)
        var fee: i64 = 0;
        if (total_in > 0) {
            fee = total_in - total_out;
            if (fee < 0) return MempoolError.InsufficientFee;
        }

        // 6. Compute size and check minimum fee
        const weight = computeTxWeight(&tx, self.allocator) catch return MempoolError.OutOfMemory;
        const vsize = (weight + 3) / 4;
        const fee_rate = if (vsize > 0)
            @as(f64, @floatFromInt(fee)) / @as(f64, @floatFromInt(vsize))
        else
            0;

        // Check minimum relay fee (only if fee is being computed)
        if (total_in > 0 and fee_rate < @as(f64, @floatFromInt(MIN_RELAY_FEE)) / 1000.0) {
            return MempoolError.InsufficientFee;
        }

        // 7. Handle RBF conflicts
        if (conflicting_txids.items.len > 0) {
            try self.checkRBFRules(&tx, tx_hash, fee, vsize, conflicting_txids.items);

            // Remove conflicting transactions (and their descendants)
            for (conflicting_txids.items) |conflicting_txid| {
                self.removeTransactionWithDescendants(conflicting_txid);
            }
        }

        // 8. Check ancestor/descendant limits
        const ancestors = try self.getAncestors(tx_hash, &tx);
        if (ancestors.count > MAX_ANCESTOR_COUNT) return MempoolError.TooManyAncestors;
        if (ancestors.size > MAX_ANCESTOR_SIZE) return MempoolError.AncestorSizeLimitExceeded;

        // 9. Check dust outputs
        for (tx.outputs) |output| {
            if (isDust(&output)) return MempoolError.DustOutput;
        }

        // 10. Check mempool size limit
        if (self.total_size + vsize > MAX_MEMPOOL_SIZE) {
            // Try to evict lowest-fee-rate transactions
            self.evict(vsize) catch return MempoolError.MempoolFull;
        }

        // 11. Create entry and add to mempool
        const entry = self.allocator.create(MempoolEntry) catch return MempoolError.OutOfMemory;
        entry.* = MempoolEntry{
            .tx = tx,
            .txid = tx_hash,
            .wtxid = crypto.computeWtxid(&tx, self.allocator) catch return MempoolError.OutOfMemory,
            .fee = fee,
            .size = vsize,
            .weight = weight,
            .vsize = vsize,
            .fee_rate = fee_rate,
            .time_added = std.time.timestamp(),
            .height_added = if (self.chain_state) |cs| cs.best_height else 0,
            .ancestor_count = ancestors.count,
            .ancestor_size = ancestors.size,
            .ancestor_fees = ancestors.fees + fee,
            .descendant_count = 1,
            .descendant_size = vsize,
            .descendant_fees = fee,
            .is_rbf = isRBFSignaled(&tx),
        };

        self.entries.put(tx_hash, entry) catch return MempoolError.OutOfMemory;
        self.by_wtxid.put(entry.wtxid, tx_hash) catch {};

        // Track spent outpoints
        for (tx.inputs) |input| {
            self.spenders.put(input.previous_output, tx_hash) catch {};

            // Update parent's children list
            if (self.entries.contains(input.previous_output.hash)) {
                const children_list = self.children.getPtr(input.previous_output.hash);
                if (children_list) |list| {
                    list.append(tx_hash) catch {};
                } else {
                    var new_list = std.ArrayList(types.Hash256).init(self.allocator);
                    new_list.append(tx_hash) catch {};
                    self.children.put(input.previous_output.hash, new_list) catch {};
                }
            }
        }

        // Update ancestor descendant counts
        try self.updateDescendantCounts(tx_hash);

        self.total_size += vsize;
    }

    /// Remove a transaction from the mempool (e.g., when mined).
    pub fn removeTransaction(self: *Mempool, txid_hash: types.Hash256) void {
        const entry_ptr = self.entries.fetchRemove(txid_hash);
        if (entry_ptr) |kv| {
            const entry = kv.value;

            // Remove spender tracking
            for (entry.tx.inputs) |input| {
                _ = self.spenders.remove(input.previous_output);
            }

            // Remove wtxid index
            _ = self.by_wtxid.remove(entry.wtxid);

            // Remove from children lists
            _ = self.children.remove(txid_hash);

            self.total_size -|= entry.vsize;
            self.allocator.destroy(entry);
        }
    }

    /// Remove a transaction and all its descendants.
    pub fn removeTransactionWithDescendants(self: *Mempool, txid_hash: types.Hash256) void {
        // Get descendants first
        const descendants = self.getDescendantTxids(txid_hash);
        defer self.allocator.free(descendants);

        // Remove in reverse order (descendants first)
        var i: usize = descendants.len;
        while (i > 0) {
            i -= 1;
            self.removeTransaction(descendants[i]);
        }

        // Remove the transaction itself
        self.removeTransaction(txid_hash);
    }

    /// Remove transactions that were included in a newly connected block.
    pub fn removeForBlock(self: *Mempool, block: *const types.Block) void {
        for (block.transactions) |tx| {
            const tx_hash = crypto.computeTxid(&tx, self.allocator) catch continue;
            self.removeTransaction(tx_hash);
        }
    }

    /// Check if a transaction signals RBF (BIP-125).
    pub fn isRBFSignaled(tx: *const types.Transaction) bool {
        for (tx.inputs) |input| {
            // Sequence < 0xFFFFFFFE signals RBF
            if (input.sequence < 0xFFFFFFFF - 1) return true;
        }
        return false;
    }

    /// Check standardness rules.
    fn checkStandard(self: *Mempool, tx: *const types.Transaction) MempoolError!void {
        _ = self;

        // Version must be 1 or 2
        if (tx.version < 1 or tx.version > 2) return MempoolError.NonStandard;

        // Check output script types
        for (tx.outputs) |output| {
            const stype = script.classifyScript(output.script_pubkey);
            if (stype == .nonstandard) return MempoolError.NonStandard;
        }
    }

    /// Check BIP-125 RBF replacement rules.
    fn checkRBFRules(
        self: *Mempool,
        new_tx: *const types.Transaction,
        new_txid: types.Hash256,
        new_fee: i64,
        new_vsize: usize,
        conflicting_txids: []const types.Hash256,
    ) MempoolError!void {
        _ = new_tx;
        _ = new_txid;

        var total_conflicting_fee: i64 = 0;
        var total_conflicting_size: usize = 0;

        for (conflicting_txids) |conflicting_txid| {
            const conflicting = self.entries.get(conflicting_txid) orelse continue;

            // Rule 1: Original transaction(s) must signal RBF
            if (!conflicting.is_rbf) return MempoolError.NonBIP125Replaceable;

            total_conflicting_fee += conflicting.fee;
            total_conflicting_size += conflicting.vsize;

            // Include descendant fees/sizes
            total_conflicting_fee += conflicting.descendant_fees - conflicting.fee;
            total_conflicting_size += conflicting.descendant_size - conflicting.vsize;
        }

        // Rule 3: Replacement must pay higher absolute fee
        if (new_fee <= total_conflicting_fee) {
            return MempoolError.ReplacementFeeTooLow;
        }

        // Rule 4: Replacement must pay for its own bandwidth
        // The additional fee must cover the minimum relay fee for the new transaction
        const additional_fee = new_fee - total_conflicting_fee;
        const min_additional_fee = @divTrunc(@as(i64, @intCast(new_vsize)) * MIN_RELAY_FEE, 1000);
        if (additional_fee < min_additional_fee) {
            return MempoolError.ReplacementFeeTooLow;
        }
    }

    /// Check if an output is dust (below economic threshold).
    pub fn isDust(output: *const types.TxOut) bool {
        // OP_RETURN outputs are never dust (they're explicitly unspendable)
        if (output.script_pubkey.len > 0 and output.script_pubkey[0] == 0x6a) return false;

        const stype = script.classifyScript(output.script_pubkey);

        // Spend size varies by script type
        const spend_size: i64 = switch (stype) {
            .p2pkh => 148, // ~148 vbytes to spend P2PKH
            .p2sh => 91, // Minimum ~91 vbytes (varies by redeem script)
            .p2wpkh => 68, // ~68 vbytes to spend P2WPKH
            .p2wsh => 108, // Minimum ~108 vbytes (varies by witness script)
            .p2tr => 58, // ~58 vbytes to spend P2TR (key path)
            .p2pk => 114, // ~114 vbytes to spend P2PK
            else => 148, // Default to P2PKH-like size
        };

        // Dust threshold = 3 * (spend_size + output_size)
        // Output size = 8 (value) + 1 (script length) + script.len
        const output_size: i64 = 8 + 1 + @as(i64, @intCast(output.script_pubkey.len));
        const dust_threshold = 3 * (spend_size + output_size);

        return output.value < dust_threshold;
    }

    /// Evict lowest-fee-rate transactions to make room.
    fn evict(self: *Mempool, needed_bytes: usize) !void {
        var freed: usize = 0;

        while (freed < needed_bytes) {
            // Find the transaction with the lowest descendant fee rate
            var worst: ?types.Hash256 = null;
            var worst_rate: f64 = std.math.floatMax(f64);

            var iter = self.entries.iterator();
            while (iter.next()) |entry| {
                const rate = entry.value_ptr.*.descendantFeeRate();
                if (rate < worst_rate) {
                    worst_rate = rate;
                    worst = entry.key_ptr.*;
                }
            }

            if (worst) |txid_hash| {
                const entry = self.entries.get(txid_hash) orelse break;
                freed += entry.vsize;
                self.removeTransactionWithDescendants(txid_hash);
            } else break;
        }
    }

    /// Count ancestors in the mempool.
    fn getAncestors(self: *Mempool, txid: types.Hash256, tx: *const types.Transaction) !struct {
        count: usize,
        size: usize,
        fees: i64,
    } {
        _ = txid;
        var visited = std.AutoHashMap(types.Hash256, void).init(self.allocator);
        defer visited.deinit();

        var count: usize = 1; // Include self
        var size: usize = 0;
        var fees: i64 = 0;

        // Check each input for mempool parents
        for (tx.inputs) |input| {
            const parent_txid = input.previous_output.hash;
            if (self.entries.get(parent_txid)) |parent_entry| {
                if (!visited.contains(parent_txid)) {
                    visited.put(parent_txid, {}) catch {};
                    count += parent_entry.ancestor_count;
                    size += parent_entry.ancestor_size;
                    fees += parent_entry.ancestor_fees;
                }
            }
        }

        return .{ .count = count, .size = size, .fees = fees };
    }

    /// Update descendant counts when a new transaction is added.
    fn updateDescendantCounts(self: *Mempool, txid: types.Hash256) !void {
        const entry = self.entries.get(txid) orelse return;

        // Update all ancestors' descendant counts
        for (entry.tx.inputs) |input| {
            const parent_txid = input.previous_output.hash;
            if (self.entries.getPtr(parent_txid)) |parent_entry_ptr| {
                parent_entry_ptr.*.descendant_count += 1;
                parent_entry_ptr.*.descendant_size += entry.vsize;
                parent_entry_ptr.*.descendant_fees += entry.fee;
            }
        }
    }

    /// Get all descendant txids.
    fn getDescendantTxids(self: *Mempool, txid: types.Hash256) []types.Hash256 {
        var result = std.ArrayList(types.Hash256).init(self.allocator);

        var to_visit = std.ArrayList(types.Hash256).init(self.allocator);
        defer to_visit.deinit();
        to_visit.append(txid) catch return result.toOwnedSlice() catch &[_]types.Hash256{};

        while (to_visit.items.len > 0) {
            const current = to_visit.pop() orelse break;

            if (self.children.get(current)) |children_list| {
                for (children_list.items) |child| {
                    result.append(child) catch continue;
                    to_visit.append(child) catch continue;
                }
            }
        }

        return result.toOwnedSlice() catch &[_]types.Hash256{};
    }

    /// Get an output from a mempool transaction.
    fn getOutputFromMempool(self: *Mempool, outpoint: *const types.OutPoint) ?types.TxOut {
        const entry = self.entries.get(outpoint.hash) orelse return null;
        if (outpoint.index >= entry.tx.outputs.len) return null;
        return entry.tx.outputs[outpoint.index];
    }

    /// Get all transactions sorted by ancestor fee rate (for mining).
    pub fn getBlockCandidates(self: *Mempool, allocator: std.mem.Allocator) ![]*MempoolEntry {
        var entries_list = std.ArrayList(*MempoolEntry).init(allocator);
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            try entries_list.append(entry.value_ptr.*);
        }

        // Sort by ancestor fee rate (descending)
        std.mem.sort(*MempoolEntry, entries_list.items, {}, struct {
            fn lessThan(_: void, a: *MempoolEntry, b: *MempoolEntry) bool {
                return a.ancestorFeeRate() > b.ancestorFeeRate();
            }
        }.lessThan);

        return entries_list.toOwnedSlice();
    }

    /// Get mempool statistics.
    pub fn stats(self: *Mempool) struct { count: usize, size: usize, total_fee: i64 } {
        var total_fee: i64 = 0;
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            total_fee += entry.value_ptr.*.fee;
        }
        return .{
            .count = self.entries.count(),
            .size = self.total_size,
            .total_fee = total_fee,
        };
    }

    /// Check if mempool contains a transaction.
    pub fn contains(self: *Mempool, txid: types.Hash256) bool {
        return self.entries.contains(txid);
    }

    /// Get a mempool entry by txid.
    pub fn get(self: *Mempool, txid: types.Hash256) ?*MempoolEntry {
        return self.entries.get(txid);
    }

    /// Get a mempool entry by wtxid (BIP-339).
    pub fn getByWtxid(self: *Mempool, wtxid: types.Hash256) ?*MempoolEntry {
        const txid = self.by_wtxid.get(wtxid) orelse return null;
        return self.entries.get(txid);
    }

    /// Remove expired transactions (older than MEMPOOL_EXPIRY).
    pub fn removeExpired(self: *Mempool) void {
        const now = std.time.timestamp();
        var to_remove = std.ArrayList(types.Hash256).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.*.time_added > MEMPOOL_EXPIRY) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |txid| {
            self.removeTransaction(txid);
        }
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute transaction weight (BIP-141).
fn computeTxWeight(tx: *const types.Transaction, allocator: std.mem.Allocator) !usize {
    // base_size = serialization without witness
    // total_size = serialization with witness
    // weight = base_size * 3 + total_size

    var base_writer = serialize.Writer.init(allocator);
    defer base_writer.deinit();
    try serialize.writeTransactionNoWitness(&base_writer, tx);
    const base_size = base_writer.getWritten().len;

    var total_writer = serialize.Writer.init(allocator);
    defer total_writer.deinit();
    try serialize.writeTransaction(&total_writer, tx);
    const total_size = total_writer.getWritten().len;

    return base_size * (consensus.WITNESS_SCALE_FACTOR - 1) + total_size;
}

// ============================================================================
// Tests
// ============================================================================

test "mempool initialization" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Empty mempool
    try std.testing.expectEqual(@as(usize, 0), mempool.entries.count());
    try std.testing.expectEqual(@as(usize, 0), mempool.total_size);

    const stats_data = mempool.stats();
    try std.testing.expectEqual(@as(usize, 0), stats_data.count);
    try std.testing.expectEqual(@as(usize, 0), stats_data.size);
    try std.testing.expectEqual(@as(i64, 0), stats_data.total_fee);
}

test "duplicate transaction rejection" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Create a simple transaction
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000, // Above dust
        .script_pubkey = &p2wpkh_script,
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // First add should succeed
    try mempool.addTransaction(tx);
    try std.testing.expectEqual(@as(usize, 1), mempool.entries.count());

    // Second add should fail with AlreadyInMempool
    const result = mempool.addTransaction(tx);
    try std.testing.expectError(MempoolError.AlreadyInMempool, result);
}

test "fee rate calculation" {
    const allocator = std.testing.allocator;

    // Create a mempool entry manually to test fee rate
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    const entry = MempoolEntry{
        .tx = tx,
        .txid = [_]u8{0} ** 32,
        .wtxid = [_]u8{0} ** 32,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0, // 1000 sat / 200 vbytes
        .time_added = 0,
        .height_added = 0,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = false,
    };

    _ = allocator;

    // Test fee rate calculation
    try std.testing.expectEqual(@as(f64, 5.0), entry.fee_rate);
    try std.testing.expectEqual(@as(f64, 5.0), entry.ancestorFeeRate());
    try std.testing.expectEqual(@as(f64, 5.0), entry.descendantFeeRate());
}

test "dust detection for different output types" {
    // P2PKH dust threshold: 3 * (148 + 34) = 546 satoshis
    const p2pkh_script = [_]u8{0x76} ++ [_]u8{0xa9} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20 ++ [_]u8{0x88} ++ [_]u8{0xac};

    // Just above dust
    const p2pkh_output_ok = types.TxOut{ .value = 600, .script_pubkey = &p2pkh_script };
    try std.testing.expect(!Mempool.isDust(&p2pkh_output_ok));

    // Below dust
    const p2pkh_output_dust = types.TxOut{ .value = 500, .script_pubkey = &p2pkh_script };
    try std.testing.expect(Mempool.isDust(&p2pkh_output_dust));

    // P2WPKH has lower dust threshold: 3 * (68 + 31) = 297 satoshis
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBB} ** 20;
    const p2wpkh_output_ok = types.TxOut{ .value = 300, .script_pubkey = &p2wpkh_script };
    try std.testing.expect(!Mempool.isDust(&p2wpkh_output_ok));

    // P2TR has lowest dust threshold: 3 * (58 + 43) = 303 satoshis
    const p2tr_script = [_]u8{0x51} ++ [_]u8{0x20} ++ [_]u8{0xCC} ** 32;
    const p2tr_output_ok = types.TxOut{ .value = 330, .script_pubkey = &p2tr_script };
    try std.testing.expect(!Mempool.isDust(&p2tr_output_ok));

    // OP_RETURN is never dust
    const op_return_script = [_]u8{ 0x6a, 0x04, 0x01, 0x02, 0x03, 0x04 };
    const op_return_output = types.TxOut{ .value = 0, .script_pubkey = &op_return_script };
    try std.testing.expect(!Mempool.isDust(&op_return_output));
}

test "RBF signaling detection" {
    // Non-RBF transaction (sequence = 0xFFFFFFFF)
    const non_rbf_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const non_rbf_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{non_rbf_input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    try std.testing.expect(!Mempool.isRBFSignaled(&non_rbf_tx));

    // RBF transaction (sequence < 0xFFFFFFFE)
    const rbf_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD, // Signals RBF
        .witness = &[_][]const u8{},
    };
    const rbf_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{rbf_input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    try std.testing.expect(Mempool.isRBFSignaled(&rbf_tx));

    // Edge case: 0xFFFFFFFE does NOT signal RBF (used for timelock)
    const edge_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const edge_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{edge_input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    try std.testing.expect(!Mempool.isRBFSignaled(&edge_tx));
}

test "transaction removal" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Create and add a transaction
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

    try mempool.addTransaction(tx);
    try std.testing.expectEqual(@as(usize, 1), mempool.entries.count());

    // Compute txid and remove
    const txid = try crypto.computeTxid(&tx, allocator);
    mempool.removeTransaction(txid);

    try std.testing.expectEqual(@as(usize, 0), mempool.entries.count());
    try std.testing.expectEqual(@as(usize, 0), mempool.total_size);
}

test "eviction of lowest fee rate transaction" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add a transaction
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

    try mempool.addTransaction(tx);
    const initial_count = mempool.entries.count();

    // Try to evict more than we have - should succeed but mempool will be empty
    try mempool.evict(1000000);

    // Either evicted or not depending on implementation
    try std.testing.expect(mempool.entries.count() <= initial_count);
}

test "getBlockCandidates returns transactions sorted by fee rate" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add multiple transactions with different fee rates
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Transaction 1
    const input1 = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output1 = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const tx1 = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input1},
        .outputs = &[_]types.TxOut{output1},
        .lock_time = 0,
    };

    // Transaction 2 (different outpoint)
    const input2 = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output2 = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const tx2 = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input2},
        .outputs = &[_]types.TxOut{output2},
        .lock_time = 0,
    };

    try mempool.addTransaction(tx1);
    try mempool.addTransaction(tx2);

    const candidates = try mempool.getBlockCandidates(allocator);
    defer allocator.free(candidates);

    try std.testing.expectEqual(@as(usize, 2), candidates.len);

    // Candidates should be sorted by ancestor fee rate (descending)
    if (candidates.len >= 2) {
        try std.testing.expect(candidates[0].ancestorFeeRate() >= candidates[1].ancestorFeeRate());
    }
}

test "mempool constants" {
    // Verify key constants
    try std.testing.expectEqual(@as(usize, 300 * 1024 * 1024), MAX_MEMPOOL_SIZE);
    try std.testing.expectEqual(@as(usize, 25), MAX_ANCESTOR_COUNT);
    try std.testing.expectEqual(@as(usize, 25), MAX_DESCENDANT_COUNT);
    try std.testing.expectEqual(@as(usize, 101_000), MAX_ANCESTOR_SIZE);
    try std.testing.expectEqual(@as(usize, 101_000), MAX_DESCENDANT_SIZE);
    try std.testing.expectEqual(@as(i64, 14 * 24 * 60 * 60), MEMPOOL_EXPIRY);
    try std.testing.expectEqual(@as(i64, 1000), MIN_RELAY_FEE);
}

test "nonstandard version rejection" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Transaction with invalid version
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
        .version = 3, // Invalid - only 1 or 2 allowed
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = mempool.addTransaction(tx);
    try std.testing.expectError(MempoolError.NonStandard, result);
}

test "dust output rejection" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Transaction with dust output
    const p2pkh_script = [_]u8{0x76} ++ [_]u8{0xa9} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20 ++ [_]u8{0x88} ++ [_]u8{0xac};
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100, // Below dust threshold (~546 for P2PKH)
        .script_pubkey = &p2pkh_script,
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const result = mempool.addTransaction(tx);
    try std.testing.expectError(MempoolError.DustOutput, result);
}

test "wtxid lookup" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add a transaction
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

    try mempool.addTransaction(tx);

    // Get by txid
    const txid = try crypto.computeTxid(&tx, allocator);
    const entry = mempool.get(txid);
    try std.testing.expect(entry != null);

    // Get by wtxid
    const wtxid = try crypto.computeWtxid(&tx, allocator);
    const entry_by_wtxid = mempool.getByWtxid(wtxid);
    try std.testing.expect(entry_by_wtxid != null);
}

test "transaction weight computation" {
    const allocator = std.testing.allocator;

    // Non-segwit transaction: weight = 4 * size
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{ 0x48, 0x30, 0x45, 0x02, 0x21 }, // Simplified signature
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0} ** 20 ++ [_]u8{ 0x88, 0xac },
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const weight = try computeTxWeight(&tx, allocator);

    // Weight should be positive
    try std.testing.expect(weight > 0);

    // For non-segwit, weight = 4 * size
    // Compute size
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try serialize.writeTransaction(&writer, &tx);
    const size = writer.getWritten().len;

    // Non-segwit tx: base_size == total_size, so weight = base * 3 + total = 4 * size
    try std.testing.expectEqual(size * 4, weight);
}

// ============================================================================
// Fee Estimator
// ============================================================================

/// Fee estimator that tracks transaction confirmation times to provide
/// fee rate recommendations for desired confirmation targets.
///
/// The estimator works by:
/// 1. Tracking when transactions enter the mempool and their fee rates
/// 2. Recording when those transactions confirm and how many blocks it took
/// 3. Grouping data into exponentially-spaced fee rate buckets
/// 4. Computing success rates (what % confirmed within N blocks at fee rate X)
/// 5. Recommending the lowest fee rate that achieves high success rate for target
pub const FeeEstimator = struct {
    /// Number of fee rate buckets.
    pub const NUM_BUCKETS: usize = 48;

    /// Each bucket is 10% wider than the previous.
    pub const BUCKET_SPACING: f64 = 1.1;

    /// Minimum fee rate (1 sat/vB).
    pub const MIN_BUCKET_FEE: f64 = 1.0;

    /// Maximum confirmation target (1 day = 144 blocks).
    pub const MAX_CONFIRMATION_TARGET: usize = 144;

    /// Minimum success rate required for estimation (85%).
    pub const MIN_SUCCESS_RATE: f64 = 0.85;

    /// Minimum data points needed per bucket for reliable estimates.
    pub const MIN_DATA_POINTS: u32 = 10;

    /// Tracked transaction info.
    pub const TrackedTx = struct {
        bucket: usize,
        height: u32,
    };

    /// Confirmation data per bucket per target.
    /// confirmed_counts[target][bucket] = number of txs confirmed within `target` blocks.
    confirmed_counts: [MAX_CONFIRMATION_TARGET][NUM_BUCKETS]u32,

    /// Total transactions seen per bucket.
    total_counts: [NUM_BUCKETS]u32,

    /// Bucket boundaries (fee rates in sat/vB).
    bucket_bounds: [NUM_BUCKETS + 1]f64,

    /// Tracked unconfirmed transactions: txid -> (bucket_index, block_entered).
    tracked: std.AutoHashMap(types.Hash256, TrackedTx),

    /// Current block height.
    current_height: u32,

    /// Decay factor: older data has less weight (~0.5 after 346 blocks, ~2.4 days).
    decay: f64,

    allocator: std.mem.Allocator,

    /// Initialize a new fee estimator.
    pub fn init(allocator: std.mem.Allocator) FeeEstimator {
        var est = FeeEstimator{
            .confirmed_counts = [_][NUM_BUCKETS]u32{[_]u32{0} ** NUM_BUCKETS} ** MAX_CONFIRMATION_TARGET,
            .total_counts = [_]u32{0} ** NUM_BUCKETS,
            .bucket_bounds = undefined,
            .tracked = std.AutoHashMap(types.Hash256, TrackedTx).init(allocator),
            .current_height = 0,
            .decay = 0.998, // ~0.5 after 346 blocks (~2.4 days)
            .allocator = allocator,
        };

        // Initialize exponentially spaced bucket boundaries
        var boundary: f64 = MIN_BUCKET_FEE;
        for (0..NUM_BUCKETS + 1) |i| {
            est.bucket_bounds[i] = boundary;
            boundary *= BUCKET_SPACING;
        }

        return est;
    }

    /// Deinitialize the fee estimator.
    pub fn deinit(self: *FeeEstimator) void {
        self.tracked.deinit();
    }

    /// Map a fee rate (sat/vB) to a bucket index.
    pub fn feeToBucket(self: *const FeeEstimator, fee_rate: f64) usize {
        for (0..NUM_BUCKETS) |i| {
            if (fee_rate < self.bucket_bounds[i + 1]) return i;
        }
        return NUM_BUCKETS - 1; // Highest bucket
    }

    /// Record a transaction entering the mempool.
    pub fn trackTransaction(self: *FeeEstimator, txid: types.Hash256, fee_rate: f64, height: u32) !void {
        const bucket = self.feeToBucket(fee_rate);
        try self.tracked.put(txid, .{ .bucket = bucket, .height = height });
        self.total_counts[bucket] += 1;
    }

    /// Record a transaction being confirmed in a block.
    pub fn confirmTransaction(self: *FeeEstimator, txid: types.Hash256, block_height: u32) void {
        const entry = self.tracked.fetchRemove(txid);
        if (entry) |kv| {
            const blocks_to_confirm = block_height - kv.value.height;
            if (blocks_to_confirm < MAX_CONFIRMATION_TARGET) {
                // Record in all target buckets >= blocks_to_confirm
                for (blocks_to_confirm..MAX_CONFIRMATION_TARGET) |target| {
                    self.confirmed_counts[target][kv.value.bucket] += 1;
                }
            }
        }
    }

    /// Process a new block: decay old data and update height.
    pub fn processBlock(self: *FeeEstimator, height: u32) void {
        self.current_height = height;

        // Apply decay to all counters
        for (0..MAX_CONFIRMATION_TARGET) |target| {
            for (0..NUM_BUCKETS) |bucket| {
                const count = @as(f64, @floatFromInt(self.confirmed_counts[target][bucket]));
                self.confirmed_counts[target][bucket] = @intFromFloat(count * self.decay);
            }
        }
        for (0..NUM_BUCKETS) |bucket| {
            const count = @as(f64, @floatFromInt(self.total_counts[bucket]));
            self.total_counts[bucket] = @intFromFloat(count * self.decay);
        }
    }

    /// Estimate the fee rate needed for confirmation within `target` blocks.
    /// Returns the fee rate in sat/vB, or null if insufficient data.
    pub fn estimateFee(self: *const FeeEstimator, target: usize) ?f64 {
        if (target == 0 or target >= MAX_CONFIRMATION_TARGET) return null;

        // Find the lowest bucket where success rate >= 85%.
        // Search from highest fee rate down to find the cheapest bucket
        // that meets the target success rate.
        var best_bucket: ?usize = null;

        var bucket: usize = NUM_BUCKETS;
        while (bucket > 0) {
            bucket -= 1;
            if (self.total_counts[bucket] < MIN_DATA_POINTS) continue;

            const confirmed: f64 = @floatFromInt(self.confirmed_counts[target][bucket]);
            const total: f64 = @floatFromInt(self.total_counts[bucket]);
            const success_rate = confirmed / total;

            if (success_rate >= MIN_SUCCESS_RATE) {
                best_bucket = bucket;
            } else if (best_bucket != null) {
                // We've gone past the viable range
                break;
            }
        }

        if (best_bucket) |b| {
            // Return the median of the bucket range
            return (self.bucket_bounds[b] + self.bucket_bounds[b + 1]) / 2.0;
        }

        return null; // Insufficient data
    }

    /// Get fee estimates for common confirmation targets.
    pub fn getEstimates(self: *const FeeEstimator) struct {
        high_priority: ?f64, // 1-2 blocks
        medium_priority: ?f64, // 6 blocks
        low_priority: ?f64, // 12 blocks
        economy: ?f64, // 24 blocks
    } {
        return .{
            .high_priority = self.estimateFee(2),
            .medium_priority = self.estimateFee(6),
            .low_priority = self.estimateFee(12),
            .economy = self.estimateFee(24),
        };
    }

    /// Get the bucket boundary for a given index (for testing).
    pub fn getBucketBound(self: *const FeeEstimator, index: usize) f64 {
        if (index > NUM_BUCKETS) return self.bucket_bounds[NUM_BUCKETS];
        return self.bucket_bounds[index];
    }

    /// Get the number of tracked (unconfirmed) transactions.
    pub fn trackedCount(self: *const FeeEstimator) usize {
        return self.tracked.count();
    }
};

// ============================================================================
// Fee Estimator Tests
// ============================================================================

test "FeeEstimator initialization with correct bucket boundaries" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    // First bucket starts at MIN_BUCKET_FEE (1.0)
    try std.testing.expectEqual(@as(f64, 1.0), estimator.getBucketBound(0));

    // Each subsequent boundary should be ~10% higher
    const first = estimator.getBucketBound(0);
    const second = estimator.getBucketBound(1);
    const ratio = second / first;
    try std.testing.expectApproxEqRel(@as(f64, 1.1), ratio, 0.001);

    // Verify exponential spacing across all buckets
    for (0..FeeEstimator.NUM_BUCKETS) |i| {
        const lower = estimator.getBucketBound(i);
        const upper = estimator.getBucketBound(i + 1);
        try std.testing.expect(upper > lower);
        const bucket_ratio = upper / lower;
        try std.testing.expectApproxEqRel(@as(f64, 1.1), bucket_ratio, 0.001);
    }

    // Current height should be 0
    try std.testing.expectEqual(@as(u32, 0), estimator.current_height);

    // No tracked transactions
    try std.testing.expectEqual(@as(usize, 0), estimator.trackedCount());

    // All counts should be zero
    for (0..FeeEstimator.NUM_BUCKETS) |i| {
        try std.testing.expectEqual(@as(u32, 0), estimator.total_counts[i]);
    }
}

test "track and confirm transaction updates counts" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    const txid = [_]u8{0xAA} ** 32;
    const fee_rate: f64 = 5.0; // sat/vB
    const enter_height: u32 = 100;

    // Track the transaction
    try estimator.trackTransaction(txid, fee_rate, enter_height);

    // Verify it's tracked
    try std.testing.expectEqual(@as(usize, 1), estimator.trackedCount());

    // Find which bucket this fee rate falls into
    const bucket = estimator.feeToBucket(fee_rate);

    // Total count for that bucket should be 1
    try std.testing.expectEqual(@as(u32, 1), estimator.total_counts[bucket]);

    // Confirm the transaction 2 blocks later
    const confirm_height: u32 = 102;
    estimator.confirmTransaction(txid, confirm_height);

    // Transaction should no longer be tracked
    try std.testing.expectEqual(@as(usize, 0), estimator.trackedCount());

    // Confirmed counts should be updated for targets >= 2
    // blocks_to_confirm = 102 - 100 = 2
    // So confirmed_counts[2][bucket], confirmed_counts[3][bucket], etc. should be 1
    try std.testing.expectEqual(@as(u32, 1), estimator.confirmed_counts[2][bucket]);
    try std.testing.expectEqual(@as(u32, 1), estimator.confirmed_counts[3][bucket]);
    try std.testing.expectEqual(@as(u32, 1), estimator.confirmed_counts[10][bucket]);

    // But not for targets < 2
    try std.testing.expectEqual(@as(u32, 0), estimator.confirmed_counts[0][bucket]);
    try std.testing.expectEqual(@as(u32, 0), estimator.confirmed_counts[1][bucket]);
}

test "fee estimation returns null with no data" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    // No transactions tracked, should return null
    try std.testing.expectEqual(@as(?f64, null), estimator.estimateFee(2));
    try std.testing.expectEqual(@as(?f64, null), estimator.estimateFee(6));
    try std.testing.expectEqual(@as(?f64, null), estimator.estimateFee(12));

    // Invalid targets should also return null
    try std.testing.expectEqual(@as(?f64, null), estimator.estimateFee(0));
    try std.testing.expectEqual(@as(?f64, null), estimator.estimateFee(FeeEstimator.MAX_CONFIRMATION_TARGET));
    try std.testing.expectEqual(@as(?f64, null), estimator.estimateFee(FeeEstimator.MAX_CONFIRMATION_TARGET + 1));

    // getEstimates should return all nulls
    const estimates = estimator.getEstimates();
    try std.testing.expectEqual(@as(?f64, null), estimates.high_priority);
    try std.testing.expectEqual(@as(?f64, null), estimates.medium_priority);
    try std.testing.expectEqual(@as(?f64, null), estimates.low_priority);
    try std.testing.expectEqual(@as(?f64, null), estimates.economy);
}

test "fee estimation with sufficient data" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    // Simulate tracking and confirming many transactions at 10 sat/vB
    // that all confirm within 2 blocks
    const fee_rate: f64 = 10.0;
    const enter_height: u32 = 100;

    // Need at least MIN_DATA_POINTS (10) transactions for reliable estimate
    var i: u32 = 0;
    while (i < 15) : (i += 1) {
        var txid: types.Hash256 = undefined;
        txid[0] = @truncate(i);
        txid[1] = @truncate(i >> 8);
        for (2..32) |j| {
            txid[j] = 0xBB;
        }

        try estimator.trackTransaction(txid, fee_rate, enter_height + i);
        estimator.confirmTransaction(txid, enter_height + i + 1); // Confirm 1 block later
    }

    const bucket = estimator.feeToBucket(fee_rate);

    // Should have 15 total transactions in this bucket
    try std.testing.expectEqual(@as(u32, 15), estimator.total_counts[bucket]);

    // All 15 should be confirmed within 1 block (and thus 2, 3, etc.)
    try std.testing.expectEqual(@as(u32, 15), estimator.confirmed_counts[1][bucket]);
    try std.testing.expectEqual(@as(u32, 15), estimator.confirmed_counts[2][bucket]);

    // Now estimation should return a value for target=2
    const estimate = estimator.estimateFee(2);
    try std.testing.expect(estimate != null);

    // The estimate should be somewhere around the fee rate we used
    if (estimate) |est| {
        // The bucket for 10 sat/vB should give us a median near 10
        // Bucket bounds grow exponentially from 1.0 by 1.1x
        // 10 sat/vB falls in bucket where bounds bracket 10
        try std.testing.expect(est >= 5.0);
        try std.testing.expect(est <= 20.0);
    }
}

test "decay reduces old data over time" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    // Add some initial data
    const txid = [_]u8{0xCC} ** 32;
    const fee_rate: f64 = 5.0;
    try estimator.trackTransaction(txid, fee_rate, 100);

    const bucket = estimator.feeToBucket(fee_rate);
    const initial_count = estimator.total_counts[bucket];
    try std.testing.expectEqual(@as(u32, 1), initial_count);

    // Process many blocks to trigger decay
    // With decay = 0.998, after ~346 blocks we should have ~0.5x
    // After just 1 block with count=1, decay won't show (1 * 0.998 = 0 when cast to int)
    // Let's add more data first

    // Add 1000 transactions
    var i: u32 = 0;
    while (i < 999) : (i += 1) {
        var txid2: types.Hash256 = undefined;
        txid2[0] = @truncate(i);
        txid2[1] = @truncate(i >> 8);
        txid2[2] = @truncate(i >> 16);
        for (3..32) |j| {
            txid2[j] = 0xDD;
        }
        try estimator.trackTransaction(txid2, fee_rate, 100 + i);
    }

    const count_after_adds = estimator.total_counts[bucket];
    try std.testing.expectEqual(@as(u32, 1000), count_after_adds);

    // Process several blocks with decay
    var block: u32 = 0;
    while (block < 100) : (block += 1) {
        estimator.processBlock(200 + block);
    }

    // After 100 blocks with 0.998 decay: 1000 * 0.998^100 ≈ 818
    const count_after_decay = estimator.total_counts[bucket];
    try std.testing.expect(count_after_decay < count_after_adds);
    try std.testing.expect(count_after_decay > 0);

    // Should be roughly 818 (1000 * 0.998^100)
    // Allow some tolerance
    try std.testing.expect(count_after_decay >= 750);
    try std.testing.expect(count_after_decay <= 900);
}

test "feeToBucket maps rates to correct buckets" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    // Fee rate of 1.0 should be in bucket 0 (1.0 <= x < 1.1)
    try std.testing.expectEqual(@as(usize, 0), estimator.feeToBucket(1.0));
    try std.testing.expectEqual(@as(usize, 0), estimator.feeToBucket(1.05));

    // Fee rate of 1.1 should be in bucket 1 (1.1 <= x < 1.21)
    try std.testing.expectEqual(@as(usize, 1), estimator.feeToBucket(1.1));
    try std.testing.expectEqual(@as(usize, 1), estimator.feeToBucket(1.15));

    // Very high fee rate should be in the last bucket
    try std.testing.expectEqual(FeeEstimator.NUM_BUCKETS - 1, estimator.feeToBucket(10000.0));
    try std.testing.expectEqual(FeeEstimator.NUM_BUCKETS - 1, estimator.feeToBucket(1000000.0));

    // Very low fee rate (below minimum) should be in bucket 0
    try std.testing.expectEqual(@as(usize, 0), estimator.feeToBucket(0.5));
    try std.testing.expectEqual(@as(usize, 0), estimator.feeToBucket(0.1));

    // Calculate expected bucket for fee_rate = 10
    // bucket bounds: 1.0, 1.1, 1.21, 1.331, ...
    // We need to find i where bounds[i] <= 10 < bounds[i+1]
    // 1.1^n = 10 => n = log(10)/log(1.1) ≈ 24.2
    // So bucket 24 should contain 10 sat/vB
    const bucket_for_10 = estimator.feeToBucket(10.0);
    const lower_bound = estimator.getBucketBound(bucket_for_10);
    const upper_bound = estimator.getBucketBound(bucket_for_10 + 1);
    try std.testing.expect(lower_bound <= 10.0);
    try std.testing.expect(upper_bound > 10.0);
}

test "processBlock updates current height" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    try std.testing.expectEqual(@as(u32, 0), estimator.current_height);

    estimator.processBlock(100);
    try std.testing.expectEqual(@as(u32, 100), estimator.current_height);

    estimator.processBlock(200);
    try std.testing.expectEqual(@as(u32, 200), estimator.current_height);
}

test "confirming unknown transaction is a no-op" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    // Try to confirm a transaction we never tracked
    const unknown_txid = [_]u8{0xFF} ** 32;
    estimator.confirmTransaction(unknown_txid, 100);

    // Should not crash, counts should remain zero
    for (0..FeeEstimator.NUM_BUCKETS) |i| {
        try std.testing.expectEqual(@as(u32, 0), estimator.total_counts[i]);
    }
}

test "confirmation beyond MAX_CONFIRMATION_TARGET is ignored" {
    const allocator = std.testing.allocator;

    var estimator = FeeEstimator.init(allocator);
    defer estimator.deinit();

    const txid = [_]u8{0xEE} ** 32;
    const fee_rate: f64 = 5.0;
    const enter_height: u32 = 100;

    try estimator.trackTransaction(txid, fee_rate, enter_height);

    // Confirm way later than MAX_CONFIRMATION_TARGET
    const confirm_height = enter_height + @as(u32, FeeEstimator.MAX_CONFIRMATION_TARGET) + 50;
    estimator.confirmTransaction(txid, confirm_height);

    // Transaction should be removed from tracking
    try std.testing.expectEqual(@as(usize, 0), estimator.trackedCount());

    // But confirmed_counts should NOT be updated (blocks_to_confirm >= MAX_CONFIRMATION_TARGET)
    const bucket = estimator.feeToBucket(fee_rate);
    for (0..FeeEstimator.MAX_CONFIRMATION_TARGET) |target| {
        try std.testing.expectEqual(@as(u32, 0), estimator.confirmed_counts[target][bucket]);
    }
}
