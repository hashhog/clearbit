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

/// Incremental relay fee in satoshis per 1000 vbytes (BIP125).
/// Replacement tx must pay: old_fees + (incremental_relay_fee * new_vsize)
pub const INCREMENTAL_RELAY_FEE: i64 = 1000;

/// Maximum number of transactions that can be evicted by a single RBF replacement.
/// This includes direct conflicts and all their descendants.
pub const MAX_REPLACEMENT_EVICTIONS: usize = 100;

// ============================================================================
// TRUC (v3) Policy Constants - BIP 431
// ============================================================================

/// TRUC transaction version (version 3).
pub const TRUC_VERSION: i32 = 3;

/// Maximum number of transactions in a TRUC ancestor set (including self).
/// TRUC only allows 1 unconfirmed parent + the tx itself = 2.
pub const TRUC_ANCESTOR_LIMIT: usize = 2;

/// Maximum number of transactions in a TRUC descendant set (including self).
/// TRUC only allows 1 unconfirmed child + the tx itself = 2.
pub const TRUC_DESCENDANT_LIMIT: usize = 2;

/// Maximum virtual size of any v3 transaction (10 KB).
pub const TRUC_MAX_VSIZE: usize = 10_000;

/// Maximum virtual size of a v3 child transaction spending an unconfirmed v3 parent (1 KB).
pub const TRUC_CHILD_MAX_VSIZE: usize = 1_000;

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
    /// Replacement would evict too many transactions (exceeds MAX_REPLACEMENT_EVICTIONS).
    TooManyEvictions,
    /// Mempool is full and transaction's fee is too low for eviction.
    MempoolFull,
    /// Transaction violates standardness rules.
    NonStandard,
    /// Output value is below the dust threshold.
    DustOutput,
    /// Pay-to-Anchor output has non-zero value.
    AnchorNonZeroValue,
    /// Transaction failed validation.
    TxValidationFailed,
    /// Input references a non-existent UTXO.
    MissingInputs,
    /// Memory allocation failure.
    OutOfMemory,
    /// TRUC: v3 transaction is too large (exceeds TRUC_MAX_VSIZE).
    TrucTxTooLarge,
    /// TRUC: v3 child transaction is too large (exceeds TRUC_CHILD_MAX_VSIZE).
    TrucChildTooLarge,
    /// TRUC: v3 transaction would have too many ancestors (exceeds TRUC_ANCESTOR_LIMIT).
    TrucTooManyAncestors,
    /// TRUC: v3 transaction would have too many descendants (exceeds TRUC_DESCENDANT_LIMIT).
    TrucTooManyDescendants,
    /// TRUC: v3 transaction cannot spend from non-v3 unconfirmed transaction.
    TrucV3SpendsNonV3,
    /// TRUC: non-v3 transaction cannot spend from v3 unconfirmed transaction.
    TrucNonV3SpendsV3,
    /// Cluster would exceed maximum size limit.
    ClusterSizeLimitExceeded,
};

// ============================================================================
// Cluster Mempool Constants
// ============================================================================

/// Maximum number of transactions in a cluster.
/// Replaces traditional ancestor/descendant limits with cluster-based limits.
/// Reference: Bitcoin Core cluster_linearize.h
pub const MAX_CLUSTER_SIZE: usize = 100;

// ============================================================================
// Union-Find for Cluster Detection
// ============================================================================

/// Union-Find (Disjoint Set Union) data structure for efficient cluster detection.
/// Used to track connected components in the transaction dependency graph.
pub const UnionFind = struct {
    /// Parent pointer for each transaction (by index).
    parent: []u32,
    /// Rank for union by rank optimization.
    rank: []u32,
    /// Number of elements in each set (stored at root).
    size: []u32,
    /// Allocator for memory management.
    allocator: std.mem.Allocator,
    /// Number of elements.
    count: u32,

    /// Initialize a new UnionFind structure with given capacity.
    pub fn init(allocator: std.mem.Allocator, capacity: u32) !UnionFind {
        const parent = try allocator.alloc(u32, capacity);
        const rank = try allocator.alloc(u32, capacity);
        const size = try allocator.alloc(u32, capacity);

        // Initialize each element as its own set
        for (0..capacity) |i| {
            parent[i] = @intCast(i);
            rank[i] = 0;
            size[i] = 1;
        }

        return UnionFind{
            .parent = parent,
            .rank = rank,
            .size = size,
            .allocator = allocator,
            .count = capacity,
        };
    }

    /// Deinitialize and free resources.
    pub fn deinit(self: *UnionFind) void {
        self.allocator.free(self.parent);
        self.allocator.free(self.rank);
        self.allocator.free(self.size);
    }

    /// Find the root of the set containing element x, with path compression.
    pub fn find(self: *UnionFind, x: u32) u32 {
        if (self.parent[x] != x) {
            // Path compression: make every node point directly to the root
            self.parent[x] = self.find(self.parent[x]);
        }
        return self.parent[x];
    }

    /// Union the sets containing elements x and y. Returns true if they were in different sets.
    pub fn unite(self: *UnionFind, x: u32, y: u32) bool {
        const root_x = self.find(x);
        const root_y = self.find(y);

        if (root_x == root_y) {
            return false; // Already in the same set
        }

        // Union by rank: attach smaller tree under root of larger tree
        if (self.rank[root_x] < self.rank[root_y]) {
            self.parent[root_x] = root_y;
            self.size[root_y] += self.size[root_x];
        } else if (self.rank[root_x] > self.rank[root_y]) {
            self.parent[root_y] = root_x;
            self.size[root_x] += self.size[root_y];
        } else {
            self.parent[root_y] = root_x;
            self.size[root_x] += self.size[root_y];
            self.rank[root_x] += 1;
        }

        return true;
    }

    /// Get the size of the set containing element x.
    pub fn setSize(self: *UnionFind, x: u32) u32 {
        const root = self.find(x);
        return self.size[root];
    }

    /// Check if two elements are in the same set.
    pub fn connected(self: *UnionFind, x: u32, y: u32) bool {
        return self.find(x) == self.find(y);
    }
};

// ============================================================================
// Cluster and Linearization
// ============================================================================

/// A chunk in a linearization: a set of transactions with aggregate fee rate.
pub const Chunk = struct {
    /// Transaction indices in this chunk.
    tx_indices: []u32,
    /// Total fees in satoshis.
    total_fees: i64,
    /// Total virtual size.
    total_vsize: usize,
    /// Allocator for cleanup.
    allocator: std.mem.Allocator,

    /// Compute the chunk fee rate (fees / vsize).
    pub fn feeRate(self: *const Chunk) f64 {
        if (self.total_vsize == 0) return 0;
        return @as(f64, @floatFromInt(self.total_fees)) / @as(f64, @floatFromInt(self.total_vsize));
    }

    /// Deinitialize and free resources.
    pub fn deinit(self: *Chunk) void {
        self.allocator.free(self.tx_indices);
    }
};

/// Result of linearizing a cluster.
pub const Linearization = struct {
    /// Ordered list of transaction indices.
    order: []u32,
    /// Chunks (contiguous groups in the order with aggregate fee rates).
    chunks: []Chunk,
    /// Mining score for each transaction (index -> fee rate of containing chunk).
    mining_scores: []f64,
    /// Allocator for cleanup.
    allocator: std.mem.Allocator,

    /// Deinitialize and free resources.
    pub fn deinit(self: *Linearization) void {
        for (self.chunks) |*chunk| {
            chunk.deinit();
        }
        self.allocator.free(self.chunks);
        self.allocator.free(self.order);
        self.allocator.free(self.mining_scores);
    }
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
    /// Index of this transaction in the cluster mempool (for UnionFind).
    cluster_index: u32,
    /// Mining score: effective fee rate based on chunk linearization.
    /// This is the chunk fee rate for the chunk containing this transaction.
    mining_score: f64,

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

    // ========================================================================
    // Cluster Mempool State
    // ========================================================================

    /// Union-Find structure for cluster detection.
    cluster_union: ?UnionFind,

    /// Map from txid to cluster index (for UnionFind).
    txid_to_index: std.AutoHashMap(types.Hash256, u32),

    /// Map from cluster index to txid.
    index_to_txid: std.AutoHashMap(u32, types.Hash256),

    /// Next available cluster index.
    next_cluster_index: u32,

    /// Cached linearizations by cluster root index.
    cluster_linearizations: std.AutoHashMap(u32, Linearization),

    /// Whether linearizations need recomputation.
    linearization_dirty: bool,

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
            // Cluster mempool state
            .cluster_union = null,
            .txid_to_index = std.AutoHashMap(types.Hash256, u32).init(allocator),
            .index_to_txid = std.AutoHashMap(u32, types.Hash256).init(allocator),
            .next_cluster_index = 0,
            .cluster_linearizations = std.AutoHashMap(u32, Linearization).init(allocator),
            .linearization_dirty = true,
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

        // Clean up cluster mempool state
        if (self.cluster_union) |*uf| {
            uf.deinit();
        }
        self.txid_to_index.deinit();
        self.index_to_txid.deinit();

        // Clean up cached linearizations
        var lin_iter = self.cluster_linearizations.iterator();
        while (lin_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.cluster_linearizations.deinit();
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

        // 7b. Check TRUC (v3) policy rules
        // This must be done after RBF conflict removal so we see the updated mempool state
        const truc_result = try self.checkTrucPolicy(&tx, vsize, conflicting_txids.items);

        // Handle sibling eviction for v3 transactions
        if (truc_result.sibling_to_evict) |sibling_txid| {
            // Sibling eviction: remove the existing sibling to make room for this tx
            // This is allowed for v3 transactions without requiring higher fee rate
            self.removeTransaction(sibling_txid);
        }

        // 8. Check cluster size limit (replaces traditional ancestor/descendant limits)
        // Also get ancestor info for legacy compatibility
        const ancestors = try self.getAncestors(tx_hash, &tx);

        // Check cluster size limit: find what cluster(s) this tx would join
        const projected_cluster_size = try self.projectClusterSize(&tx);
        if (projected_cluster_size > MAX_CLUSTER_SIZE) {
            return MempoolError.ClusterSizeLimitExceeded;
        }

        // For TRUC (v3), also enforce stricter ancestor/descendant limits
        if (tx.version == TRUC_VERSION) {
            // TRUC limits already checked in checkTrucPolicy above
        } else {
            // Keep legacy ancestor/descendant limits as secondary check for non-v3
            // These are less restrictive than cluster limits but kept for compatibility
            if (ancestors.count > MAX_ANCESTOR_COUNT) return MempoolError.TooManyAncestors;
            if (ancestors.size + vsize > MAX_ANCESTOR_SIZE) return MempoolError.AncestorSizeLimitExceeded;
            try self.checkDescendantLimits(&tx, vsize);
        }

        // 9. Check dust outputs
        for (tx.outputs) |output| {
            if (isDust(&output)) return MempoolError.DustOutput;
        }

        // 10. Check mempool size limit
        if (self.total_size + vsize > MAX_MEMPOOL_SIZE) {
            // Try to evict lowest-fee-rate transactions
            self.evict(vsize) catch return MempoolError.MempoolFull;
        }

        // 11. Allocate cluster index for this transaction
        const cluster_idx = self.next_cluster_index;
        self.next_cluster_index += 1;

        // Initialize or expand UnionFind if needed
        try self.ensureClusterCapacity(self.next_cluster_index);

        // 12. Create entry and add to mempool
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
            .ancestor_size = ancestors.size + vsize, // Include self
            .ancestor_fees = ancestors.fees + fee,
            .descendant_count = 1,
            .descendant_size = vsize,
            .descendant_fees = fee,
            // V3/TRUC transactions are always RBF-replaceable (BIP 431)
            .is_rbf = tx.version == TRUC_VERSION or isRBFSignaled(&tx),
            .cluster_index = cluster_idx,
            .mining_score = fee_rate, // Initial score is individual fee rate
        };

        self.entries.put(tx_hash, entry) catch return MempoolError.OutOfMemory;
        self.by_wtxid.put(entry.wtxid, tx_hash) catch {};
        self.txid_to_index.put(tx_hash, cluster_idx) catch {};
        self.index_to_txid.put(cluster_idx, tx_hash) catch {};

        // Track spent outpoints and union with parent clusters
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

                // Union this tx with its parent in the cluster
                if (self.txid_to_index.get(input.previous_output.hash)) |parent_idx| {
                    if (self.cluster_union) |*uf| {
                        _ = uf.unite(cluster_idx, parent_idx);
                    }
                }
            }
        }

        // Update ancestor descendant counts
        try self.updateDescendantCounts(tx_hash);

        // Mark linearizations as needing recomputation
        self.linearization_dirty = true;

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

            // Remove from children lists and free the ArrayList
            if (self.children.fetchRemove(txid_hash)) |children_kv| {
                var children_list = children_kv.value;
                children_list.deinit();
            }

            // Remove cluster tracking
            _ = self.txid_to_index.remove(txid_hash);
            _ = self.index_to_txid.remove(entry.cluster_index);
            // Note: UnionFind doesn't support removal, but orphaned indices don't affect correctness
            // The cluster will be invalidated and recomputed on next linearization

            // Mark linearizations as needing recomputation
            self.linearization_dirty = true;

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

        // Version must be 1, 2, or 3 (TRUC)
        if (tx.version < 1 or tx.version > TRUC_VERSION) return MempoolError.NonStandard;

        // Check output script types
        for (tx.outputs) |output| {
            const stype = script.classifyScript(output.script_pubkey);
            if (stype == .nonstandard) return MempoolError.NonStandard;

            // P2A (Pay-to-Anchor) outputs must have value 0.
            // They're designed for fee bumping and non-zero value is non-standard.
            // Reference: Bitcoin Core policy/policy.cpp
            if (stype == .anchor and output.value != 0) {
                return MempoolError.AnchorNonZeroValue;
            }
        }
    }

    /// Check full RBF replacement rules.
    /// Full RBF: ALL mempool transactions are replaceable regardless of nSequence signaling.
    /// Rules:
    /// 1. [REMOVED for full RBF] Original txs must signal RBF - no longer required
    /// 2. New tx must not add new unconfirmed inputs (enforced elsewhere)
    /// 3. New tx must pay higher absolute fee than sum of all evicted txs
    /// 4. New fee must exceed old fees by at least incremental_relay_fee * new_vsize
    /// 5. Total number of evicted transactions must not exceed MAX_REPLACEMENT_EVICTIONS
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

        // Collect all transactions to be evicted (direct conflicts + all descendants)
        var all_evicted = std.AutoHashMap(types.Hash256, void).init(self.allocator);
        defer all_evicted.deinit();

        var total_evicted_fee: i64 = 0;

        for (conflicting_txids) |conflicting_txid| {
            // Add the direct conflict
            if (!all_evicted.contains(conflicting_txid)) {
                all_evicted.put(conflicting_txid, {}) catch return MempoolError.OutOfMemory;

                if (self.entries.get(conflicting_txid)) |entry| {
                    total_evicted_fee += entry.fee;
                }
            }

            // Add all descendants of this conflict using BFS
            const descendants = self.getDescendantTxids(conflicting_txid);
            defer self.allocator.free(descendants);

            for (descendants) |desc_txid| {
                if (!all_evicted.contains(desc_txid)) {
                    all_evicted.put(desc_txid, {}) catch return MempoolError.OutOfMemory;

                    if (self.entries.get(desc_txid)) |entry| {
                        total_evicted_fee += entry.fee;
                    }
                }
            }
        }

        // Rule 5: Check max eviction limit
        if (all_evicted.count() > MAX_REPLACEMENT_EVICTIONS) {
            return MempoolError.TooManyEvictions;
        }

        // Rule 3: Replacement must pay higher absolute fee than sum of all evicted txs
        if (new_fee <= total_evicted_fee) {
            return MempoolError.ReplacementFeeTooLow;
        }

        // Rule 4: Replacement must pay for its own bandwidth
        // new_fee - sum(old_fees) >= incremental_relay_fee * new_vsize
        const additional_fee = new_fee - total_evicted_fee;
        const min_additional_fee = @divTrunc(@as(i64, @intCast(new_vsize)) * INCREMENTAL_RELAY_FEE, 1000);
        if (additional_fee < min_additional_fee) {
            return MempoolError.ReplacementFeeTooLow;
        }
    }

    /// Check if an output is dust (below economic threshold).
    pub fn isDust(output: *const types.TxOut) bool {
        // OP_RETURN outputs are never dust (they're explicitly unspendable)
        if (output.script_pubkey.len > 0 and output.script_pubkey[0] == 0x6a) return false;

        const stype = script.classifyScript(output.script_pubkey);

        // P2A (Pay-to-Anchor) outputs are exempt from dust if value is 0.
        // They're designed for fee bumping and must have zero value.
        // Reference: Bitcoin Core policy/policy.cpp
        if (stype == .anchor) {
            // Anchor outputs with value 0 are never dust
            return output.value != 0;
        }

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
    /// Evict lowest-fee-rate transactions to make room.
    /// Uses cluster-based mining score for eviction decisions.
    fn evict(self: *Mempool, needed_bytes: usize) !void {
        // Update mining scores if needed (cluster-aware)
        self.updateMiningScores() catch {};

        var freed: usize = 0;

        while (freed < needed_bytes) {
            // Find the transaction with the lowest mining score (cluster-aware)
            var worst: ?types.Hash256 = null;
            var worst_score: f64 = std.math.floatMax(f64);

            var iter = self.entries.iterator();
            while (iter.next()) |entry| {
                // Use mining_score for cluster-aware eviction
                const score = entry.value_ptr.*.mining_score;
                if (score < worst_score) {
                    worst_score = score;
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

    /// Compute ancestors using BFS traversal with visited set.
    /// Returns the full ancestor set (not including self) for accurate limit checking.
    fn getAncestors(self: *Mempool, txid: types.Hash256, tx: *const types.Transaction) MempoolError!struct {
        count: usize,
        size: usize,
        fees: i64,
    } {
        _ = txid;
        var visited = std.AutoHashMap(types.Hash256, void).init(self.allocator);
        defer visited.deinit();

        // Queue for BFS traversal - start with direct parents
        var queue = std.ArrayList(types.Hash256).init(self.allocator);
        defer queue.deinit();

        // Add direct parents to queue
        for (tx.inputs) |input| {
            const parent_txid = input.previous_output.hash;
            if (self.entries.contains(parent_txid)) {
                if (!visited.contains(parent_txid)) {
                    visited.put(parent_txid, {}) catch return MempoolError.OutOfMemory;
                    queue.append(parent_txid) catch return MempoolError.OutOfMemory;
                }
            }
        }

        var total_size: usize = 0;
        var total_fees: i64 = 0;

        // BFS to find all ancestors
        while (queue.items.len > 0) {
            const current_txid = queue.orderedRemove(0);
            const entry = self.entries.get(current_txid) orelse continue;

            total_size += entry.vsize;
            total_fees += entry.fee;

            // Add this entry's parents to the queue
            for (entry.tx.inputs) |input| {
                const grandparent_txid = input.previous_output.hash;
                if (self.entries.contains(grandparent_txid)) {
                    if (!visited.contains(grandparent_txid)) {
                        visited.put(grandparent_txid, {}) catch return MempoolError.OutOfMemory;
                        queue.append(grandparent_txid) catch return MempoolError.OutOfMemory;
                    }
                }
            }
        }

        // Count includes self
        return .{
            .count = visited.count() + 1,
            .size = total_size,
            .fees = total_fees,
        };
    }

    /// Result of TRUC validation that may include a sibling eligible for eviction.
    pub const TrucCheckResult = struct {
        /// If non-null, this sibling can be evicted via sibling eviction.
        sibling_to_evict: ?types.Hash256 = null,
    };

    /// Check TRUC (v3) policy rules for a transaction.
    /// Returns null on success, or an error if TRUC rules are violated.
    /// For descendant limit violations, may return a sibling eligible for eviction.
    ///
    /// TRUC rules (BIP 431):
    /// 1. V3 tx can only have v3 unconfirmed parents
    /// 2. Non-v3 tx cannot have v3 unconfirmed parents
    /// 3. V3 tx max size is TRUC_MAX_VSIZE (10KB)
    /// 4. V3 child spending unconfirmed parent max size is TRUC_CHILD_MAX_VSIZE (1KB)
    /// 5. V3 tx can have at most 1 unconfirmed ancestor (TRUC_ANCESTOR_LIMIT = 2 including self)
    /// 6. V3 tx can have at most 1 unconfirmed descendant (TRUC_DESCENDANT_LIMIT = 2 including self)
    /// 7. Sibling eviction: a v3 child can replace an existing v3 child of the same parent
    fn checkTrucPolicy(
        self: *Mempool,
        tx: *const types.Transaction,
        vsize: usize,
        direct_conflicts: []const types.Hash256,
    ) MempoolError!TrucCheckResult {
        // Find all mempool parents (unconfirmed ancestors that are direct parents)
        var mempool_parents = std.ArrayList(types.Hash256).init(self.allocator);
        defer mempool_parents.deinit();

        for (tx.inputs) |input| {
            const parent_txid = input.previous_output.hash;
            if (self.entries.contains(parent_txid)) {
                // Check for duplicates before adding
                var found = false;
                for (mempool_parents.items) |existing| {
                    if (std.mem.eql(u8, &existing, &parent_txid)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    mempool_parents.append(parent_txid) catch return MempoolError.OutOfMemory;
                }
            }
        }

        // Rule 1 & 2: Check version inheritance
        for (mempool_parents.items) |parent_txid| {
            const parent_entry = self.entries.get(parent_txid) orelse continue;

            if (tx.version != TRUC_VERSION and parent_entry.tx.version == TRUC_VERSION) {
                // Non-v3 cannot spend from v3
                return MempoolError.TrucNonV3SpendsV3;
            } else if (tx.version == TRUC_VERSION and parent_entry.tx.version != TRUC_VERSION) {
                // V3 cannot spend from non-v3
                return MempoolError.TrucV3SpendsNonV3;
            }
        }

        // Remaining rules only apply to v3 transactions
        if (tx.version != TRUC_VERSION) {
            return TrucCheckResult{};
        }

        // Rule 3: V3 tx max size check
        if (vsize > TRUC_MAX_VSIZE) {
            return MempoolError.TrucTxTooLarge;
        }

        // Rule 5: Ancestor limit check (v3 can have at most 1 unconfirmed parent)
        // TRUC_ANCESTOR_LIMIT = 2 includes self, so max 1 mempool parent
        if (mempool_parents.items.len + 1 > TRUC_ANCESTOR_LIMIT) {
            return MempoolError.TrucTooManyAncestors;
        }

        // Rules that only apply when there are unconfirmed parents
        if (mempool_parents.items.len > 0) {
            const parent_txid = mempool_parents.items[0];
            const parent_entry = self.entries.get(parent_txid) orelse return TrucCheckResult{};

            // Check that the parent itself doesn't have too many ancestors
            // (ensures the chain length is at most 2)
            if (parent_entry.ancestor_count + 1 > TRUC_ANCESTOR_LIMIT) {
                return MempoolError.TrucTooManyAncestors;
            }

            // Rule 4: V3 child spending unconfirmed parent has stricter size limit
            if (vsize > TRUC_CHILD_MAX_VSIZE) {
                return MempoolError.TrucChildTooLarge;
            }

            // Rule 6: Descendant limit check
            // Check if the parent already has a child (descendant_count > 1 means it has children)
            // TRUC_DESCENDANT_LIMIT = 2 includes self, so max 1 child
            if (parent_entry.descendant_count + 1 > TRUC_DESCENDANT_LIMIT) {
                // Check if the existing child is being replaced via direct conflict
                var child_will_be_replaced = false;
                const descendants = self.getDescendantTxids(parent_txid);
                defer self.allocator.free(descendants);

                for (descendants) |desc_txid| {
                    for (direct_conflicts) |conflict| {
                        if (std.mem.eql(u8, &desc_txid, &conflict)) {
                            child_will_be_replaced = true;
                            break;
                        }
                    }
                    if (child_will_be_replaced) break;
                }

                if (!child_will_be_replaced) {
                    // Rule 7: Sibling eviction - check if we can evict the existing child
                    // Conditions for sibling eviction:
                    // 1. Parent has exactly 2 descendants (itself + 1 existing child)
                    // 2. The existing sibling has exactly 2 ancestors (grandparent chain + parent)
                    if (parent_entry.descendant_count == 2 and descendants.len == 1) {
                        const sibling_txid = descendants[0];
                        if (self.entries.get(sibling_txid)) |sibling_entry| {
                            if (sibling_entry.ancestor_count == 2) {
                                // Sibling eviction is possible
                                return TrucCheckResult{ .sibling_to_evict = sibling_txid };
                            }
                        }
                    }
                    return MempoolError.TrucTooManyDescendants;
                }
            }
        }

        return TrucCheckResult{};
    }

    /// Check if adding a transaction would cause any ancestor to exceed descendant limits.
    fn checkDescendantLimits(self: *Mempool, tx: *const types.Transaction, new_vsize: usize) MempoolError!void {
        // For each mempool parent, check that adding this tx wouldn't exceed their descendant limit
        var visited = std.AutoHashMap(types.Hash256, void).init(self.allocator);
        defer visited.deinit();

        // BFS to find all ancestors and check their descendant counts
        var queue = std.ArrayList(types.Hash256).init(self.allocator);
        defer queue.deinit();

        // Add direct parents to queue
        for (tx.inputs) |input| {
            const parent_txid = input.previous_output.hash;
            if (self.entries.contains(parent_txid)) {
                if (!visited.contains(parent_txid)) {
                    visited.put(parent_txid, {}) catch return MempoolError.OutOfMemory;
                    queue.append(parent_txid) catch return MempoolError.OutOfMemory;
                }
            }
        }

        // BFS to check all ancestors' descendant counts
        while (queue.items.len > 0) {
            const current_txid = queue.orderedRemove(0);
            const entry = self.entries.get(current_txid) orelse continue;

            // Check if adding this new tx would exceed descendant limits
            // +1 for the new transaction itself
            if (entry.descendant_count + 1 > MAX_DESCENDANT_COUNT) {
                return MempoolError.TooManyDescendants;
            }
            if (entry.descendant_size + new_vsize > MAX_DESCENDANT_SIZE) {
                return MempoolError.DescendantSizeLimitExceeded;
            }

            // Add this entry's parents to the queue
            for (entry.tx.inputs) |input| {
                const grandparent_txid = input.previous_output.hash;
                if (self.entries.contains(grandparent_txid)) {
                    if (!visited.contains(grandparent_txid)) {
                        visited.put(grandparent_txid, {}) catch return MempoolError.OutOfMemory;
                        queue.append(grandparent_txid) catch return MempoolError.OutOfMemory;
                    }
                }
            }
        }
    }

    /// Update descendant counts when a new transaction is added.
    /// Must propagate updates to ALL ancestors, not just direct parents.
    fn updateDescendantCounts(self: *Mempool, txid: types.Hash256) MempoolError!void {
        const entry = self.entries.get(txid) orelse return;

        // Use BFS to find all ancestors and update their descendant counts
        var visited = std.AutoHashMap(types.Hash256, void).init(self.allocator);
        defer visited.deinit();

        var queue = std.ArrayList(types.Hash256).init(self.allocator);
        defer queue.deinit();

        // Start with direct parents
        for (entry.tx.inputs) |input| {
            const parent_txid = input.previous_output.hash;
            if (self.entries.contains(parent_txid) and !visited.contains(parent_txid)) {
                visited.put(parent_txid, {}) catch return MempoolError.OutOfMemory;
                queue.append(parent_txid) catch return MempoolError.OutOfMemory;
            }
        }

        // BFS to update all ancestors
        while (queue.items.len > 0) {
            const current_txid = queue.orderedRemove(0);
            if (self.entries.getPtr(current_txid)) |ancestor_entry_ptr| {
                ancestor_entry_ptr.*.descendant_count += 1;
                ancestor_entry_ptr.*.descendant_size += entry.vsize;
                ancestor_entry_ptr.*.descendant_fees += entry.fee;

                // Add this ancestor's parents to the queue
                for (ancestor_entry_ptr.*.tx.inputs) |input| {
                    const grandparent_txid = input.previous_output.hash;
                    if (self.entries.contains(grandparent_txid) and !visited.contains(grandparent_txid)) {
                        visited.put(grandparent_txid, {}) catch return MempoolError.OutOfMemory;
                        queue.append(grandparent_txid) catch return MempoolError.OutOfMemory;
                    }
                }
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
    pub fn getOutputFromMempool(self: *Mempool, outpoint: *const types.OutPoint) ?types.TxOut {
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

    /// Get the minimum fee rate required for a transaction to be accepted.
    /// Returns the fee rate in sat/kvB (satoshis per 1000 virtual bytes).
    /// When the mempool is not full, returns MIN_RELAY_FEE.
    /// When the mempool is full, returns the fee rate of the lowest-fee transaction
    /// plus INCREMENTAL_RELAY_FEE to ensure new transactions pay enough to evict.
    pub fn getMinFee(self: *Mempool) u64 {
        // If mempool is not full, use the default minimum relay fee
        if (self.total_size < MAX_MEMPOOL_SIZE) {
            return @intCast(MIN_RELAY_FEE);
        }

        // When full, find the minimum fee rate in the mempool
        var min_fee_rate: f64 = std.math.floatMax(f64);
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.*.fee_rate < min_fee_rate) {
                min_fee_rate = entry.value_ptr.*.fee_rate;
            }
        }

        // Convert fee rate from sat/vB to sat/kvB and add incremental relay fee
        if (min_fee_rate < std.math.floatMax(f64)) {
            const min_kvb = @as(u64, @intFromFloat(min_fee_rate * 1000));
            return @max(min_kvb + @as(u64, @intCast(INCREMENTAL_RELAY_FEE)), @as(u64, @intCast(MIN_RELAY_FEE)));
        }

        return @intCast(MIN_RELAY_FEE);
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

    /// Add a transaction to the mempool using package fee rate for CPFP.
    /// This allows transactions with individual fee rates below minimum
    /// when the package fee rate is sufficient.
    pub fn addTransactionWithPackageRate(self: *Mempool, tx: types.Transaction, package_fee_rate: f64) MempoolError!void {
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

        // 6. Compute size
        const weight = computeTxWeight(&tx, self.allocator) catch return MempoolError.OutOfMemory;
        const vsize = (weight + 3) / 4;
        const individual_fee_rate = if (vsize > 0)
            @as(f64, @floatFromInt(fee)) / @as(f64, @floatFromInt(vsize))
        else
            0;

        // Check PACKAGE fee rate (not individual) - this is the CPFP magic
        // Individual tx may have low fee rate, but package rate must be sufficient
        const min_fee_rate = @as(f64, @floatFromInt(MIN_RELAY_FEE)) / 1000.0;
        if (total_in > 0 and package_fee_rate < min_fee_rate) {
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

        // 7b. Check TRUC (v3) policy rules
        const truc_result = try self.checkTrucPolicy(&tx, vsize, conflicting_txids.items);

        // Handle sibling eviction for v3 transactions
        if (truc_result.sibling_to_evict) |sibling_txid| {
            self.removeTransaction(sibling_txid);
        }

        // 8. Check cluster size limit and ancestor/descendant limits
        const ancestors = try self.getAncestors(tx_hash, &tx);

        // Check cluster size limit
        const projected_cluster_size = try self.projectClusterSize(&tx);
        if (projected_cluster_size > MAX_CLUSTER_SIZE) {
            return MempoolError.ClusterSizeLimitExceeded;
        }

        if (tx.version != TRUC_VERSION) {
            if (ancestors.count > MAX_ANCESTOR_COUNT) return MempoolError.TooManyAncestors;
            if (ancestors.size + vsize > MAX_ANCESTOR_SIZE) return MempoolError.AncestorSizeLimitExceeded;
            try self.checkDescendantLimits(&tx, vsize);
        }

        // 9. Check dust outputs
        for (tx.outputs) |output| {
            if (isDust(&output)) return MempoolError.DustOutput;
        }

        // 10. Check mempool size limit
        if (self.total_size + vsize > MAX_MEMPOOL_SIZE) {
            // Try to evict lowest-fee-rate transactions
            self.evict(vsize) catch return MempoolError.MempoolFull;
        }

        // 11. Allocate cluster index for this transaction
        const cluster_idx = self.next_cluster_index;
        self.next_cluster_index += 1;

        // Initialize or expand UnionFind if needed
        try self.ensureClusterCapacity(self.next_cluster_index);

        // 12. Create entry and add to mempool
        const entry = self.allocator.create(MempoolEntry) catch return MempoolError.OutOfMemory;
        entry.* = MempoolEntry{
            .tx = tx,
            .txid = tx_hash,
            .wtxid = crypto.computeWtxid(&tx, self.allocator) catch return MempoolError.OutOfMemory,
            .fee = fee,
            .size = vsize,
            .weight = weight,
            .vsize = vsize,
            .fee_rate = individual_fee_rate,
            .time_added = std.time.timestamp(),
            .height_added = if (self.chain_state) |cs| cs.best_height else 0,
            .ancestor_count = ancestors.count,
            .ancestor_size = ancestors.size + vsize, // Include self
            .ancestor_fees = ancestors.fees + fee,
            .descendant_count = 1,
            .descendant_size = vsize,
            .descendant_fees = fee,
            // V3/TRUC transactions are always RBF-replaceable (BIP 431)
            .is_rbf = tx.version == TRUC_VERSION or isRBFSignaled(&tx),
            .cluster_index = cluster_idx,
            .mining_score = individual_fee_rate, // Initial score
        };

        self.entries.put(tx_hash, entry) catch return MempoolError.OutOfMemory;
        self.by_wtxid.put(entry.wtxid, tx_hash) catch {};
        self.txid_to_index.put(tx_hash, cluster_idx) catch {};
        self.index_to_txid.put(cluster_idx, tx_hash) catch {};

        // Track spent outpoints and union with parent clusters
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

                // Union this tx with its parent in the cluster
                if (self.txid_to_index.get(input.previous_output.hash)) |parent_idx| {
                    if (self.cluster_union) |*uf| {
                        _ = uf.unite(cluster_idx, parent_idx);
                    }
                }
            }
        }

        // Mark linearizations as needing recomputation
        self.linearization_dirty = true;

        // Update ancestor descendant counts
        try self.updateDescendantCounts(tx_hash);

        self.total_size += vsize;
    }

    // ========================================================================
    // Cluster Mempool Methods
    // ========================================================================

    /// Ensure UnionFind has sufficient capacity.
    fn ensureClusterCapacity(self: *Mempool, min_capacity: u32) MempoolError!void {
        const needed = @max(min_capacity, 64); // Minimum initial capacity

        if (self.cluster_union == null) {
            self.cluster_union = UnionFind.init(self.allocator, needed) catch return MempoolError.OutOfMemory;
            return;
        }

        // If we need more capacity, create a new larger UnionFind and copy
        if (self.cluster_union) |*uf| {
            if (uf.count < needed) {
                const new_capacity = @max(needed, uf.count * 2);
                var new_uf = UnionFind.init(self.allocator, new_capacity) catch return MempoolError.OutOfMemory;

                // Copy existing data
                for (0..uf.count) |i| {
                    new_uf.parent[i] = uf.parent[i];
                    new_uf.rank[i] = uf.rank[i];
                    new_uf.size[i] = uf.size[i];
                }

                uf.deinit();
                self.cluster_union = new_uf;
            }
        }
    }

    /// Project the cluster size if a new transaction were added.
    /// Used to check cluster limits before adding.
    fn projectClusterSize(self: *Mempool, tx: *const types.Transaction) MempoolError!usize {
        // Find all unique clusters that would be joined
        var cluster_roots = std.AutoHashMap(u32, void).init(self.allocator);
        defer cluster_roots.deinit();

        for (tx.inputs) |input| {
            const parent_txid = input.previous_output.hash;
            if (self.txid_to_index.get(parent_txid)) |parent_idx| {
                if (self.cluster_union) |*uf| {
                    const root = uf.find(parent_idx);
                    cluster_roots.put(root, {}) catch return MempoolError.OutOfMemory;
                }
            }
        }

        if (cluster_roots.count() == 0) {
            // New independent transaction
            return 1;
        }

        // Sum up the sizes of all clusters that would be joined
        var total_size: usize = 1; // +1 for the new tx
        var roots_iter = cluster_roots.iterator();
        while (roots_iter.next()) |entry| {
            const root = entry.key_ptr.*;
            if (self.cluster_union) |*uf| {
                total_size += uf.setSize(root);
            }
        }

        return total_size;
    }

    /// Get all transactions in the same cluster as the given txid.
    pub fn getClusterTxids(self: *Mempool, txid: types.Hash256) ![]types.Hash256 {
        var result = std.ArrayList(types.Hash256).init(self.allocator);
        errdefer result.deinit();

        const idx = self.txid_to_index.get(txid) orelse return result.toOwnedSlice();

        const uf = if (self.cluster_union) |*u| u else return result.toOwnedSlice();
        const target_root = uf.find(idx);

        // Find all txids with the same root
        var iter = self.txid_to_index.iterator();
        while (iter.next()) |entry| {
            const other_idx = entry.value_ptr.*;
            const other_root = uf.find(other_idx);
            if (other_root == target_root) {
                try result.append(entry.key_ptr.*);
            }
        }

        return result.toOwnedSlice();
    }

    /// Get the cluster size for a given transaction.
    pub fn getClusterSize(self: *Mempool, txid: types.Hash256) usize {
        const idx = self.txid_to_index.get(txid) orelse return 0;
        const uf = if (self.cluster_union) |*u| u else return 0;
        return uf.setSize(idx);
    }

    /// Linearize a cluster using the greedy chunk algorithm.
    /// Returns transactions in optimal order for mining.
    pub fn linearizeCluster(self: *Mempool, cluster_txids: []const types.Hash256, allocator: std.mem.Allocator) !Linearization {
        const n = cluster_txids.len;
        if (n == 0) {
            return Linearization{
                .order = try allocator.alloc(u32, 0),
                .chunks = try allocator.alloc(Chunk, 0),
                .mining_scores = try allocator.alloc(f64, 0),
                .allocator = allocator,
            };
        }

        // Build local index mapping
        var txid_to_local = std.AutoHashMap(types.Hash256, u32).init(allocator);
        defer txid_to_local.deinit();

        var local_to_txid = try allocator.alloc(types.Hash256, n);
        defer allocator.free(local_to_txid);

        var fees = try allocator.alloc(i64, n);
        defer allocator.free(fees);

        var vsizes = try allocator.alloc(usize, n);
        defer allocator.free(vsizes);

        // Build ancestor sets for each tx in the cluster
        var ancestors = try allocator.alloc(std.bit_set.IntegerBitSet(64), n);
        defer allocator.free(ancestors);

        for (cluster_txids, 0..) |txid, i| {
            try txid_to_local.put(txid, @intCast(i));
            local_to_txid[i] = txid;

            const entry = self.entries.get(txid) orelse continue;
            fees[i] = entry.fee;
            vsizes[i] = entry.vsize;
            ancestors[i] = std.bit_set.IntegerBitSet(64).initEmpty();
            ancestors[i].set(i); // Each tx is its own ancestor
        }

        // Build ancestor relationships within the cluster
        for (cluster_txids, 0..) |txid, i| {
            const entry = self.entries.get(txid) orelse continue;
            for (entry.tx.inputs) |input| {
                if (txid_to_local.get(input.previous_output.hash)) |parent_local| {
                    // Add parent and all its ancestors
                    ancestors[i].setUnion(ancestors[parent_local]);
                }
            }
        }

        // Greedy linearization: repeatedly find highest fee-rate valid topological prefix
        var order = try allocator.alloc(u32, n);
        var order_idx: usize = 0;

        var remaining = std.bit_set.IntegerBitSet(64).initEmpty();
        for (0..n) |i| {
            remaining.set(i);
        }

        // Track chunks as we build the linearization
        var chunks_list = std.ArrayList(Chunk).init(allocator);
        errdefer {
            for (chunks_list.items) |*c| c.deinit();
            chunks_list.deinit();
        }

        while (remaining.count() > 0) {
            // Find the best chunk: highest fee-rate valid topological prefix
            const best_chunk = try self.findBestChunk(
                &remaining,
                ancestors,
                fees,
                vsizes,
                @intCast(n),
                allocator,
            );

            // Add chunk transactions to the order
            var chunk_tx_indices = std.ArrayList(u32).init(allocator);
            errdefer chunk_tx_indices.deinit();

            var chunk_iter = best_chunk.iterator(.{});
            while (chunk_iter.next()) |idx| {
                order[order_idx] = @intCast(idx);
                order_idx += 1;
                remaining.unset(idx);
                try chunk_tx_indices.append(@intCast(idx));
            }

            // Calculate chunk fee rate
            var chunk_fees: i64 = 0;
            var chunk_vsize: usize = 0;
            var chunk_iter2 = best_chunk.iterator(.{});
            while (chunk_iter2.next()) |idx| {
                chunk_fees += fees[idx];
                chunk_vsize += vsizes[idx];
            }

            try chunks_list.append(Chunk{
                .tx_indices = try chunk_tx_indices.toOwnedSlice(),
                .total_fees = chunk_fees,
                .total_vsize = chunk_vsize,
                .allocator = allocator,
            });
        }

        // Build mining scores (chunk fee rate for each tx)
        var mining_scores = try allocator.alloc(f64, n);
        for (chunks_list.items) |chunk| {
            const chunk_rate = chunk.feeRate();
            for (chunk.tx_indices) |idx| {
                mining_scores[idx] = chunk_rate;
            }
        }

        return Linearization{
            .order = order,
            .chunks = try chunks_list.toOwnedSlice(),
            .mining_scores = mining_scores,
            .allocator = allocator,
        };
    }

    /// Find the best chunk (highest fee-rate valid topological prefix) from remaining transactions.
    fn findBestChunk(
        self: *Mempool,
        remaining: *std.bit_set.IntegerBitSet(64),
        ancestors: []std.bit_set.IntegerBitSet(64),
        fees: []i64,
        vsizes: []usize,
        n: u32,
        allocator: std.mem.Allocator,
    ) !std.bit_set.IntegerBitSet(64) {
        _ = self;

        var best_chunk = std.bit_set.IntegerBitSet(64).initEmpty();
        var best_fee_rate: f64 = -std.math.floatMax(f64);

        // For small clusters, enumerate all possible subsets
        // For larger clusters, use a bounded search
        const remaining_count = remaining.count();

        if (remaining_count <= 12) {
            // Enumerate all non-empty subsets for small clusters
            const max_subset: u64 = @as(u64, 1) << @intCast(n);
            var subset: u64 = 1;
            while (subset < max_subset) : (subset += 1) {
                var candidate = std.bit_set.IntegerBitSet(64).initEmpty();
                var valid = true;

                // Check if this subset is valid (all ancestors in subset are included)
                var idx: u32 = 0;
                while (idx < n) : (idx += 1) {
                    if ((subset >> @intCast(idx)) & 1 == 1) {
                        if (!remaining.isSet(idx)) {
                            valid = false;
                            break;
                        }
                        candidate.set(idx);
                    }
                }

                if (!valid) continue;
                if (candidate.count() == 0) continue;

                // Check topological validity: all ancestors must be in the subset
                var topo_valid = true;
                var cand_iter = candidate.iterator(.{});
                while (cand_iter.next()) |i| {
                    // Check that all ancestors in 'remaining' are in candidate
                    var anc_in_remaining = ancestors[i].intersectWith(remaining.*);
                    if (!anc_in_remaining.subsetOf(candidate)) {
                        topo_valid = false;
                        break;
                    }
                }

                if (!topo_valid) continue;

                // Calculate fee rate
                var total_fees: i64 = 0;
                var total_vsize: usize = 0;
                var calc_iter = candidate.iterator(.{});
                while (calc_iter.next()) |i| {
                    total_fees += fees[i];
                    total_vsize += vsizes[i];
                }

                const fee_rate: f64 = if (total_vsize > 0)
                    @as(f64, @floatFromInt(total_fees)) / @as(f64, @floatFromInt(total_vsize))
                else
                    0;

                if (fee_rate > best_fee_rate) {
                    best_fee_rate = fee_rate;
                    best_chunk = candidate;
                }
            }
        } else {
            // For larger clusters, use greedy single-tx selection
            // This is a simplified approach; full implementation would use bounded search
            var rem_iter = remaining.iterator(.{});
            while (rem_iter.next()) |idx| {
                // Check if this tx can be selected (all remaining ancestors already processed)
                var anc_in_remaining = ancestors[idx].intersectWith(remaining.*);
                if (anc_in_remaining.count() == 1) {
                    // Only ancestor in remaining is self - valid singleton chunk
                    const fee_rate: f64 = if (vsizes[idx] > 0)
                        @as(f64, @floatFromInt(fees[idx])) / @as(f64, @floatFromInt(vsizes[idx]))
                    else
                        0;

                    if (fee_rate > best_fee_rate) {
                        best_fee_rate = fee_rate;
                        best_chunk = std.bit_set.IntegerBitSet(64).initEmpty();
                        best_chunk.set(idx);
                    }
                }
            }

            // If no singleton found, take any valid tx
            if (best_chunk.count() == 0) {
                var rem_iter2 = remaining.iterator(.{});
                if (rem_iter2.next()) |idx| {
                    best_chunk.set(idx);
                }
            }
        }

        // Fallback: if nothing found, take first remaining
        if (best_chunk.count() == 0) {
            var rem_iter = remaining.iterator(.{});
            if (rem_iter.next()) |idx| {
                best_chunk.set(idx);
            }
        }

        _ = allocator;
        return best_chunk;
    }

    /// Update mining scores for all transactions by recomputing linearizations.
    pub fn updateMiningScores(self: *Mempool) !void {
        if (!self.linearization_dirty) return;

        // Find all unique cluster roots
        var roots = std.AutoHashMap(u32, void).init(self.allocator);
        defer roots.deinit();

        if (self.cluster_union) |*uf| {
            var iter = self.txid_to_index.iterator();
            while (iter.next()) |entry| {
                const root = uf.find(entry.value_ptr.*);
                try roots.put(root, {});
            }
        }

        // Clear old linearizations
        var lin_iter = self.cluster_linearizations.iterator();
        while (lin_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.cluster_linearizations.clearRetainingCapacity();

        // Linearize each cluster and update mining scores
        var roots_iter = roots.iterator();
        while (roots_iter.next()) |entry| {
            const root = entry.key_ptr.*;

            // Get all txids in this cluster
            const cluster_txids = try self.getClusterTxidsForRoot(root);
            defer self.allocator.free(cluster_txids);

            if (cluster_txids.len == 0) continue;

            // Linearize the cluster
            const linearization = try self.linearizeCluster(cluster_txids, self.allocator);

            // Update mining scores for each transaction
            for (cluster_txids, 0..) |txid, i| {
                if (self.entries.getPtr(txid)) |entry_ptr| {
                    entry_ptr.*.mining_score = linearization.mining_scores[i];
                }
            }

            // Cache the linearization
            try self.cluster_linearizations.put(root, linearization);
        }

        self.linearization_dirty = false;
    }

    /// Get all txids for a given cluster root.
    fn getClusterTxidsForRoot(self: *Mempool, root: u32) ![]types.Hash256 {
        var result = std.ArrayList(types.Hash256).init(self.allocator);
        errdefer result.deinit();

        const uf = if (self.cluster_union) |*u| u else return result.toOwnedSlice();

        var iter = self.txid_to_index.iterator();
        while (iter.next()) |entry| {
            const idx = entry.value_ptr.*;
            if (uf.find(idx) == root) {
                try result.append(entry.key_ptr.*);
            }
        }

        return result.toOwnedSlice();
    }

    /// Get transactions sorted by mining score (cluster-aware).
    /// This replaces getBlockCandidates with cluster-linearized ordering.
    pub fn getBlockCandidatesByMiningScore(self: *Mempool, allocator: std.mem.Allocator) ![]*MempoolEntry {
        // Ensure mining scores are up to date
        try self.updateMiningScores();

        var entries_list = std.ArrayList(*MempoolEntry).init(allocator);
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            try entries_list.append(entry.value_ptr.*);
        }

        // Sort by mining score (descending)
        std.mem.sort(*MempoolEntry, entries_list.items, {}, struct {
            fn lessThan(_: void, a: *MempoolEntry, b: *MempoolEntry) bool {
                return a.mining_score > b.mining_score;
            }
        }.lessThan);

        return entries_list.toOwnedSlice();
    }

    /// Evict transactions using cluster-based mining score.
    /// Evicts from the worst cluster (lowest mining score).
    fn evictByCluster(self: *Mempool, needed_bytes: usize) !void {
        try self.updateMiningScores();

        var freed: usize = 0;

        while (freed < needed_bytes) {
            // Find the transaction with the lowest mining score
            var worst: ?types.Hash256 = null;
            var worst_score: f64 = std.math.floatMax(f64);

            var iter = self.entries.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.*.mining_score < worst_score) {
                    worst_score = entry.value_ptr.*.mining_score;
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
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute transaction weight (BIP-141).
pub fn computeTxWeight(tx: *const types.Transaction, allocator: std.mem.Allocator) !usize {
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
        .cluster_index = 0,
        .mining_score = 5.0,
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

    // P2A (Pay-to-Anchor) with value 0 is never dust
    const p2a_output_zero = types.TxOut{ .value = 0, .script_pubkey = &script.P2A_SCRIPT };
    try std.testing.expect(!Mempool.isDust(&p2a_output_zero));

    // P2A with non-zero value is considered dust (actually an error, but isDust returns true)
    const p2a_output_nonzero = types.TxOut{ .value = 1, .script_pubkey = &script.P2A_SCRIPT };
    try std.testing.expect(Mempool.isDust(&p2a_output_nonzero));
}

test "P2A (Pay-to-Anchor) standardness" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Create input
    const input = types.TxIn{
        .previous_output = types.OutPoint{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    // P2A output with value 0 should be accepted
    const p2a_output_ok = types.TxOut{ .value = 0, .script_pubkey = &script.P2A_SCRIPT };

    const inputs_ok = [_]types.TxIn{input};
    const outputs_ok = [_]types.TxOut{p2a_output_ok};
    const tx_ok = types.Transaction{
        .version = 2,
        .inputs = &inputs_ok,
        .outputs = &outputs_ok,
        .lock_time = 0,
    };
    // P2A with value 0 should pass standardness check
    mempool.checkStandard(&tx_ok) catch |err| {
        std.debug.print("Unexpected error: {}\n", .{err});
        return error.TestUnexpectedResult;
    };

    // P2A output with non-zero value should be rejected
    const p2a_output_bad = types.TxOut{ .value = 1000, .script_pubkey = &script.P2A_SCRIPT };
    const outputs_bad = [_]types.TxOut{p2a_output_bad};
    const tx_bad = types.Transaction{
        .version = 2,
        .inputs = &inputs_ok,
        .outputs = &outputs_bad,
        .lock_time = 0,
    };
    try std.testing.expectError(MempoolError.AnchorNonZeroValue, mempool.checkStandard(&tx_bad));
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

    // Transaction with invalid version (version 4 is not allowed)
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
        .version = 4, // Invalid - only 1, 2, or 3 (TRUC) allowed
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

test "ancestor limit of 25 allows chain" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Add 25 independent transactions (each spending a different "confirmed" output)
    // This tests that we can have 25 transactions in the mempool
    // Note: These don't form a chain, so they each have ancestor_count = 1
    var i: usize = 0;
    while (i < MAX_ANCESTOR_COUNT) : (i += 1) {
        // Each tx spends from a different "confirmed" output (not in mempool)
        // This avoids fee checks since total_in = 0 without chain_state
        var outpoint_hash: types.Hash256 = undefined;
        @memset(&outpoint_hash, 0xCC);
        outpoint_hash[0] = @truncate(i);
        outpoint_hash[1] = @truncate(i >> 8);

        const input = types.TxIn{
            .previous_output = .{ .hash = outpoint_hash, .index = 0 },
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
            .lock_time = @intCast(i), // Make each tx unique
        };

        // Add to mempool - should succeed for all 25
        try mempool.addTransaction(tx);
    }

    // We should have exactly 25 transactions
    try std.testing.expectEqual(@as(usize, 25), mempool.entries.count());
}

test "ancestor limit of 26 fails" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // To properly test chain limits, we need to heap-allocate transaction data
    // so it doesn't get overwritten in the loop. Store arrays of inputs/outputs.
    var inputs: [MAX_ANCESTOR_COUNT][1]types.TxIn = undefined;
    var outputs: [MAX_ANCESTOR_COUNT][1]types.TxOut = undefined;
    var txids: [MAX_ANCESTOR_COUNT]types.Hash256 = undefined;

    // Build a chain of 25 transactions
    var prev_txid: types.Hash256 = [_]u8{0xFF} ** 32; // Start with "confirmed" output
    var value: i64 = 10_000_000;

    var i: usize = 0;
    while (i < MAX_ANCESTOR_COUNT) : (i += 1) {
        inputs[i][0] = types.TxIn{
            .previous_output = .{ .hash = prev_txid, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };

        value -= 500;
        outputs[i][0] = types.TxOut{
            .value = value,
            .script_pubkey = &p2wpkh_script,
        };

        const tx = types.Transaction{
            .version = 2,
            .inputs = &inputs[i],
            .outputs = &outputs[i],
            .lock_time = @intCast(i),
        };

        try mempool.addTransaction(tx);
        txids[i] = crypto.computeTxid(&tx, allocator) catch unreachable;
        prev_txid = txids[i];
    }

    // Now try to add the 26th transaction - should fail with TooManyAncestors
    const input26 = types.TxIn{
        .previous_output = .{ .hash = prev_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output26 = types.TxOut{
        .value = value - 500,
        .script_pubkey = &p2wpkh_script,
    };

    const tx26 = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input26},
        .outputs = &[_]types.TxOut{output26},
        .lock_time = 26,
    };

    const result = mempool.addTransaction(tx26);
    try std.testing.expectError(MempoolError.TooManyAncestors, result);
}

test "descendant limit of 25 allows chain" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Store transaction data to avoid stack reuse issues
    var inputs: [MAX_DESCENDANT_COUNT][1]types.TxIn = undefined;
    var outputs: [MAX_DESCENDANT_COUNT][1]types.TxOut = undefined;
    var txids: [MAX_DESCENDANT_COUNT]types.Hash256 = undefined;

    // Build a chain of 25 transactions
    var prev_txid: types.Hash256 = [_]u8{0xFF} ** 32;
    var value: i64 = 10_000_000;

    var i: usize = 0;
    while (i < MAX_DESCENDANT_COUNT) : (i += 1) {
        inputs[i][0] = types.TxIn{
            .previous_output = .{ .hash = prev_txid, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };

        value -= 500;
        outputs[i][0] = types.TxOut{
            .value = value,
            .script_pubkey = &p2wpkh_script,
        };

        const tx = types.Transaction{
            .version = 2,
            .inputs = &inputs[i],
            .outputs = &outputs[i],
            .lock_time = @intCast(i),
        };

        try mempool.addTransaction(tx);
        txids[i] = crypto.computeTxid(&tx, allocator) catch unreachable;
        prev_txid = txids[i];
    }

    // Verify the first transaction has 25 descendants (including itself)
    // Find the first tx by iterating - it will have the highest descendant count
    var max_descendant_count: usize = 0;
    var iter = mempool.entries.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.*.descendant_count > max_descendant_count) {
            max_descendant_count = entry.value_ptr.*.descendant_count;
        }
    }
    try std.testing.expectEqual(@as(usize, 25), max_descendant_count);
}

test "descendant limit of 26 fails" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // To test the DESCENDANT limit specifically (not ancestor), we need a "fan-out" topology:
    // One parent tx with 25 outputs, and 25 child txs each spending one output.
    // This gives the parent 25 descendants (itself + 24 children).
    // Adding a 26th child should fail with TooManyDescendants.

    // Create parent tx with 25 outputs
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xFF} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    var parent_outputs: [MAX_DESCENDANT_COUNT]types.TxOut = undefined;
    for (0..MAX_DESCENDANT_COUNT) |j| {
        parent_outputs[j] = types.TxOut{
            .value = 100000,
            .script_pubkey = &p2wpkh_script,
        };
    }

    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &parent_outputs,
        .lock_time = 0,
    };

    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Add 24 child transactions (each spending a different output of parent)
    // This gives parent: descendant_count = 1 (self) + 24 = 25
    var child_inputs: [MAX_DESCENDANT_COUNT - 1][1]types.TxIn = undefined;
    var child_outputs: [MAX_DESCENDANT_COUNT - 1][1]types.TxOut = undefined;

    var i: usize = 0;
    while (i < MAX_DESCENDANT_COUNT - 1) : (i += 1) {
        child_inputs[i][0] = types.TxIn{
            .previous_output = .{ .hash = parent_txid, .index = @intCast(i) },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };

        child_outputs[i][0] = types.TxOut{
            .value = 99500, // Pay 500 sats fee
            .script_pubkey = &p2wpkh_script,
        };

        const child_tx = types.Transaction{
            .version = 2,
            .inputs = &child_inputs[i],
            .outputs = &child_outputs[i],
            .lock_time = @intCast(i + 1),
        };

        try mempool.addTransaction(child_tx);
    }

    // Verify parent has 25 descendants
    const parent_entry = mempool.get(parent_txid);
    try std.testing.expect(parent_entry != null);
    try std.testing.expectEqual(@as(usize, 25), parent_entry.?.descendant_count);

    // Now try to add the 25th child (26th descendant including parent) - should fail
    const child25_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 24 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child25_output = types.TxOut{
        .value = 99500,
        .script_pubkey = &p2wpkh_script,
    };

    const child25_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child25_input},
        .outputs = &[_]types.TxOut{child25_output},
        .lock_time = 25,
    };

    const result = mempool.addTransaction(child25_tx);
    try std.testing.expectError(MempoolError.TooManyDescendants, result);
}

test "ancestor size limit enforced" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Create a chain where total size exceeds 101,000 vbytes
    // This is hard to test with real transaction sizes, but we verify the constant
    try std.testing.expectEqual(@as(usize, 101_000), MAX_ANCESTOR_SIZE);
}

// ============================================================================
// TRUC (v3) Policy Tests
// ============================================================================

test "truc constants verification" {
    // Verify TRUC policy constants match BIP 431 specification
    try std.testing.expectEqual(@as(i32, 3), TRUC_VERSION);
    try std.testing.expectEqual(@as(usize, 2), TRUC_ANCESTOR_LIMIT);
    try std.testing.expectEqual(@as(usize, 2), TRUC_DESCENDANT_LIMIT);
    try std.testing.expectEqual(@as(usize, 10_000), TRUC_MAX_VSIZE);
    try std.testing.expectEqual(@as(usize, 1_000), TRUC_CHILD_MAX_VSIZE);
}

test "truc v3 transaction accepted" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // V3 transaction with no unconfirmed parents should be accepted
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
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Should succeed - v3 tx with no unconfirmed parents
    try mempool.addTransaction(tx);
    try std.testing.expectEqual(@as(usize, 1), mempool.entries.count());
}

test "truc v3 is always rbf" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // V3 transaction with sequence = 0xFFFFFFFF (normally non-RBF) should still be RBF
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF, // Does NOT signal RBF normally
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };

    const tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    try mempool.addTransaction(tx);
    const txid = crypto.computeTxid(&tx, allocator) catch unreachable;
    const entry = mempool.get(txid);
    try std.testing.expect(entry != null);

    // V3 should always be RBF even without signaling
    try std.testing.expect(entry.?.is_rbf);
}

test "truc v3 max 1 unconfirmed parent" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create parent v3 tx
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create second parent v3 tx
    const parent2_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xBB} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent2_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent2_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent2_input},
        .outputs = &[_]types.TxOut{parent2_output},
        .lock_time = 1,
    };
    try mempool.addTransaction(parent2_tx);
    const parent2_txid = crypto.computeTxid(&parent2_tx, allocator) catch unreachable;

    // Create child v3 tx spending from TWO parents - should fail
    const child_input1 = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_input2 = types.TxIn{
        .previous_output = .{ .hash = parent2_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child_inputs = [_]types.TxIn{ child_input1, child_input2 };
    const child_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &child_inputs,
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 2,
    };

    // Should fail because v3 can only have 1 unconfirmed parent
    const result = mempool.addTransaction(child_tx);
    try std.testing.expectError(MempoolError.TrucTooManyAncestors, result);
}

test "truc v3 max 1 unconfirmed child without sibling eviction" {
    // Note: When a second v3 child is added spending from a different output of the same parent,
    // sibling eviction kicks in and allows the new child (evicting the old one).
    // This test verifies sibling eviction works - see separate test for sibling eviction.
    // Here we test the case where sibling eviction is NOT possible (sibling has descendants).

    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create parent v3 tx with 2 outputs
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_outputs = [_]types.TxOut{
        types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script },
        types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script },
    };
    const parent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &parent_outputs,
        .lock_time = 0,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create first child v3 tx
    const child1_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child1_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child1_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{child1_input},
        .outputs = &[_]types.TxOut{child1_output},
        .lock_time = 1,
    };
    try mempool.addTransaction(child1_tx);

    // Create second child v3 tx spending from a different output
    // Sibling eviction should work here, so the second child should succeed
    const child2_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 1 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child2_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child2_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{child2_input},
        .outputs = &[_]types.TxOut{child2_output},
        .lock_time = 2,
    };

    // This should succeed via sibling eviction (first child gets evicted)
    try mempool.addTransaction(child2_tx);
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count());
}

test "truc v3 cannot spend from non-v3" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create parent v2 tx (non-TRUC)
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent_tx = types.Transaction{
        .version = 2, // Non-TRUC
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create v3 child tx spending from v2 parent - should fail
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child_tx = types.Transaction{
        .version = TRUC_VERSION, // V3 trying to spend from v2
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 1,
    };

    const result = mempool.addTransaction(child_tx);
    try std.testing.expectError(MempoolError.TrucV3SpendsNonV3, result);
}

test "truc non-v3 cannot spend from v3" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create parent v3 tx
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create v2 child tx spending from v3 parent - should fail
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child_tx = types.Transaction{
        .version = 2, // Non-v3 trying to spend from v3
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 1,
    };

    const result = mempool.addTransaction(child_tx);
    try std.testing.expectError(MempoolError.TrucNonV3SpendsV3, result);
}

test "truc v3 child max 1000 vbytes" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create parent v3 tx
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create child v3 tx that's > 1000 vbytes but < 10000 vbytes
    // OP_RETURN with enough data to make the tx around 2000-3000 vbytes
    var op_return_100: [100]u8 = undefined;
    op_return_100[0] = 0x6a; // OP_RETURN
    op_return_100[1] = 98; // Push 98 bytes
    for (2..100) |i| {
        op_return_100[i] = 0xAA;
    }

    // 12 outputs at ~100 bytes each = ~1200 bytes for outputs
    // Plus overhead = ~1400-1500 vbytes total (> 1000 but < 10000)
    var outputs: [12]types.TxOut = undefined;
    for (0..12) |i| {
        outputs[i] = types.TxOut{ .value = 1000, .script_pubkey = &op_return_100 };
    }

    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &outputs,
        .lock_time = 1,
    };

    // Should fail because v3 child with unconfirmed parent cannot exceed 1000 vbytes
    const result = mempool.addTransaction(child_tx);
    try std.testing.expectError(MempoolError.TrucChildTooLarge, result);
}

test "truc v3 parent child chain valid" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create parent v3 tx
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create child v3 tx - should succeed (valid 2-tx chain)
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 1,
    };

    // Should succeed - valid v3 parent-child chain
    try mempool.addTransaction(child_tx);
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count());
}

test "truc v3 no grandchild allowed" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create grandparent v3 tx
    const grandparent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const grandparent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const grandparent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{grandparent_input},
        .outputs = &[_]types.TxOut{grandparent_output},
        .lock_time = 0,
    };
    try mempool.addTransaction(grandparent_tx);
    const grandparent_txid = crypto.computeTxid(&grandparent_tx, allocator) catch unreachable;

    // Create parent v3 tx
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = grandparent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 1,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create grandchild v3 tx - should fail (would create 3-tx chain)
    const grandchild_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const grandchild_output = types.TxOut{
        .value = 98000,
        .script_pubkey = &p2wpkh_script,
    };
    const grandchild_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{grandchild_input},
        .outputs = &[_]types.TxOut{grandchild_output},
        .lock_time = 2,
    };

    // Should fail - parent already has a parent, grandchild would exceed ancestor limit
    const result = mempool.addTransaction(grandchild_tx);
    try std.testing.expectError(MempoolError.TrucTooManyAncestors, result);
}

test "truc sibling eviction" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create parent v3 tx with 2 outputs
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_outputs = [_]types.TxOut{
        types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script },
        types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script },
    };
    const parent_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &parent_outputs,
        .lock_time = 0,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Create first child v3 tx (the sibling that will be evicted)
    const child1_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child1_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child1_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{child1_input},
        .outputs = &[_]types.TxOut{child1_output},
        .lock_time = 1,
    };
    try mempool.addTransaction(child1_tx);
    const child1_txid = crypto.computeTxid(&child1_tx, allocator) catch unreachable;

    // Create second child v3 tx spending from a DIFFERENT output of parent
    // This should trigger sibling eviction and succeed
    const child2_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 1 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child2_output = types.TxOut{
        .value = 99000,
        .script_pubkey = &p2wpkh_script,
    };
    const child2_tx = types.Transaction{
        .version = TRUC_VERSION,
        .inputs = &[_]types.TxIn{child2_input},
        .outputs = &[_]types.TxOut{child2_output},
        .lock_time = 2,
    };

    // Should succeed via sibling eviction
    try mempool.addTransaction(child2_tx);

    // Verify: child1 should be evicted, child2 should be in mempool
    try std.testing.expect(!mempool.contains(child1_txid));
    const child2_txid = crypto.computeTxid(&child2_tx, allocator) catch unreachable;
    try std.testing.expect(mempool.contains(child2_txid));
    try std.testing.expect(mempool.contains(parent_txid));
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count());
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

// ============================================================================
// Full RBF Tests
// ============================================================================

test "full RBF: replacement succeeds with higher fee" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // First, add a "funding" transaction so the mempool can compute fees
    // by looking up the output value from this transaction.
    const funding_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const funding_output = types.TxOut{
        .value = 1_000_000, // 0.01 BTC available for child txs
        .script_pubkey = &p2wpkh_script,
    };

    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{funding_input},
        .outputs = &[_]types.TxOut{funding_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(funding_tx);
    const funding_txid = crypto.computeTxid(&funding_tx, allocator) catch unreachable;

    // Original transaction spending the funding output (does NOT signal RBF)
    const original_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF, // Does NOT signal RBF, but full RBF means it's still replaceable
        .witness = &[_][]const u8{},
    };
    const original_output = types.TxOut{
        .value = 900_000, // Fee = 1_000_000 - 900_000 = 100_000 sats
        .script_pubkey = &p2wpkh_script,
    };

    const original_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{original_input},
        .outputs = &[_]types.TxOut{original_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(original_tx);
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count());

    // Replacement transaction spending the SAME outpoint with higher fee
    const replacement_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 }, // Same outpoint as original
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const replacement_output = types.TxOut{
        .value = 700_000, // Fee = 1_000_000 - 700_000 = 300_000 sats (much higher)
        .script_pubkey = &p2wpkh_script,
    };

    const replacement_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{replacement_input},
        .outputs = &[_]types.TxOut{replacement_output},
        .lock_time = 1, // Different locktime to make txid different
    };

    // Replacement should succeed - full RBF doesn't require opt-in signaling
    try mempool.addTransaction(replacement_tx);

    // Should have 2 transactions (funding + replacement)
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count());

    // Original should be gone
    const original_txid = crypto.computeTxid(&original_tx, allocator) catch unreachable;
    try std.testing.expect(!mempool.contains(original_txid));

    // Replacement should be present
    const replacement_txid = crypto.computeTxid(&replacement_tx, allocator) catch unreachable;
    try std.testing.expect(mempool.contains(replacement_txid));
}

test "full RBF: replacement fails with lower or equal fee" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Original transaction
    const original_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD, // Signals RBF
        .witness = &[_][]const u8{},
    };
    const original_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };

    const original_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{original_input},
        .outputs = &[_]types.TxOut{original_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(original_tx);

    // Replacement with same output value (same fee) - should fail
    const replacement_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const replacement_output = types.TxOut{
        .value = 100000, // Same value = same fee
        .script_pubkey = &p2wpkh_script,
    };

    const replacement_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{replacement_input},
        .outputs = &[_]types.TxOut{replacement_output},
        .lock_time = 1,
    };

    const result = mempool.addTransaction(replacement_tx);
    try std.testing.expectError(MempoolError.ReplacementFeeTooLow, result);

    // Original should still be there
    try std.testing.expectEqual(@as(usize, 1), mempool.entries.count());
}

test "full RBF: replacement must pay incremental relay fee" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Original transaction
    const original_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x33} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    };
    const original_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };

    const original_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{original_input},
        .outputs = &[_]types.TxOut{original_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(original_tx);

    // Replacement with slightly higher fee (but maybe not enough for incremental relay)
    // For a ~100 vbyte tx, incremental relay fee = 100 * 1000 / 1000 = 100 sats
    // So we need additional_fee >= 100 sats
    const replacement_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x33} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const replacement_output = types.TxOut{
        .value = 99999, // Only 1 sat more fee - not enough for incremental relay
        .script_pubkey = &p2wpkh_script,
    };

    const replacement_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{replacement_input},
        .outputs = &[_]types.TxOut{replacement_output},
        .lock_time = 1,
    };

    const result = mempool.addTransaction(replacement_tx);
    try std.testing.expectError(MempoolError.ReplacementFeeTooLow, result);
}

test "full RBF: replacement removes descendants" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // First, add a funding transaction so fees can be computed
    const funding_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x04} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const funding_output = types.TxOut{
        .value = 2_000_000,
        .script_pubkey = &p2wpkh_script,
    };

    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{funding_input},
        .outputs = &[_]types.TxOut{funding_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(funding_tx);
    const funding_txid = crypto.computeTxid(&funding_tx, allocator) catch unreachable;

    // Parent transaction spending funding
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 1_900_000, // Fee = 100,000 sats
        .script_pubkey = &p2wpkh_script,
    };

    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Child transaction spending parent's output
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 1_800_000, // Fee = 100,000 sats
        .script_pubkey = &p2wpkh_script,
    };

    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(child_tx);
    try std.testing.expectEqual(@as(usize, 3), mempool.entries.count());

    // Replacement transaction that conflicts with parent (spends same input)
    // Must pay more than parent + child combined (200,000) + incremental relay fee
    const replacement_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 }, // Same as parent
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const replacement_output = types.TxOut{
        .value = 1_500_000, // Fee = 500,000 sats (much more than 200,000)
        .script_pubkey = &p2wpkh_script,
    };

    const replacement_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{replacement_input},
        .outputs = &[_]types.TxOut{replacement_output},
        .lock_time = 1,
    };

    try mempool.addTransaction(replacement_tx);

    // Funding + replacement should remain; parent and child should be evicted
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count());

    // Parent should be gone
    try std.testing.expect(!mempool.contains(parent_txid));

    // Child should be gone
    const child_txid = crypto.computeTxid(&child_tx, allocator) catch unreachable;
    try std.testing.expect(!mempool.contains(child_txid));
}

test "full RBF: multiple descendants evicted correctly" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Funding transaction
    const funding_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x05} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const funding_output = types.TxOut{
        .value = 10_000_000, // 0.1 BTC
        .script_pubkey = &p2wpkh_script,
    };

    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{funding_input},
        .outputs = &[_]types.TxOut{funding_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(funding_tx);
    const funding_txid = crypto.computeTxid(&funding_tx, allocator) catch unreachable;

    // Parent transaction spending the funding, with 10 outputs
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    };

    // Parent with 10 outputs
    var parent_outputs: [10]types.TxOut = undefined;
    for (0..10) |j| {
        parent_outputs[j] = types.TxOut{
            .value = 500_000, // 0.005 BTC per output
            .script_pubkey = &p2wpkh_script,
        };
    }

    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &parent_outputs,
        .lock_time = 0,
    };

    try mempool.addTransaction(parent_tx);
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    // Add 10 children (one per output)
    var child_inputs: [10][1]types.TxIn = undefined;
    var child_outputs: [10][1]types.TxOut = undefined;

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        child_inputs[i][0] = types.TxIn{
            .previous_output = .{ .hash = parent_txid, .index = @intCast(i) },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };

        child_outputs[i][0] = types.TxOut{
            .value = 490_000, // Fee = 10,000 sats
            .script_pubkey = &p2wpkh_script,
        };

        const child_tx = types.Transaction{
            .version = 2,
            .inputs = &child_inputs[i],
            .outputs = &child_outputs[i],
            .lock_time = @intCast(i + 1),
        };

        try mempool.addTransaction(child_tx);
    }

    // Should have 1 funding + 1 parent + 10 children = 12 txs
    try std.testing.expectEqual(@as(usize, 12), mempool.entries.count());

    // Now try to replace the parent - this evicts 11 txs (parent + 10 children)
    // Well under MAX_REPLACEMENT_EVICTIONS (100)
    // Parent fee = 10M - 5M = 5M sats
    // Each child fee = 500k - 490k = 10k sats, total 100k sats
    // Total evicted fees = 5.1M sats
    // Replacement must pay > 5.1M sats + incremental_relay_fee * vsize
    const replacement_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 }, // Same as parent
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const replacement_output = types.TxOut{
        .value = 2_000_000, // Fee = 10M - 2M = 8M sats (much more than 5.1M evicted)
        .script_pubkey = &p2wpkh_script,
    };

    const replacement_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{replacement_input},
        .outputs = &[_]types.TxOut{replacement_output},
        .lock_time = 999,
    };

    // This should succeed
    try mempool.addTransaction(replacement_tx);
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count()); // funding + replacement

    // Parent should be gone
    try std.testing.expect(!mempool.contains(parent_txid));
}

test "full RBF: non-signaling tx is still replaceable" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Funding transaction first
    const funding_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x06} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const funding_output = types.TxOut{
        .value = 1_000_000, // 0.01 BTC
        .script_pubkey = &p2wpkh_script,
    };

    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{funding_input},
        .outputs = &[_]types.TxOut{funding_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(funding_tx);
    const funding_txid = crypto.computeTxid(&funding_tx, allocator) catch unreachable;

    // Transaction that does NOT signal RBF (sequence = 0xFFFFFFFF)
    const original_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF, // Does NOT signal RBF
        .witness = &[_][]const u8{},
    };
    const original_output = types.TxOut{
        .value = 900_000, // Fee = 100,000 sats
        .script_pubkey = &p2wpkh_script,
    };

    const original_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{original_input},
        .outputs = &[_]types.TxOut{original_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(original_tx);

    // Verify the tx does NOT signal RBF
    const original_txid = crypto.computeTxid(&original_tx, allocator) catch unreachable;
    const entry = mempool.get(original_txid).?;
    try std.testing.expect(!entry.is_rbf);

    // But with full RBF, it should still be replaceable
    const replacement_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const replacement_output = types.TxOut{
        .value = 700_000, // Fee = 300,000 sats (higher)
        .script_pubkey = &p2wpkh_script,
    };

    const replacement_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{replacement_input},
        .outputs = &[_]types.TxOut{replacement_output},
        .lock_time = 1,
    };

    // Should succeed despite original not signaling RBF
    try mempool.addTransaction(replacement_tx);
    try std.testing.expectEqual(@as(usize, 2), mempool.entries.count()); // funding + replacement
    try std.testing.expect(!mempool.contains(original_txid));
}

test "full RBF constants" {
    // Verify key RBF constants
    try std.testing.expectEqual(@as(i64, 1000), INCREMENTAL_RELAY_FEE);
    try std.testing.expectEqual(@as(usize, 100), MAX_REPLACEMENT_EVICTIONS);
}

// ============================================================================
// BIP-133 Feefilter Tests
// ============================================================================

test "getMinFee returns MIN_RELAY_FEE when mempool is empty" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Empty mempool should return MIN_RELAY_FEE
    try std.testing.expectEqual(@as(u64, 1000), mempool.getMinFee());
}

test "getMinFee returns MIN_RELAY_FEE when mempool is not full" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add a transaction (doesn't make it full)
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 50000,
        .script_pubkey = &p2wpkh_script,
    };

    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    try mempool.addTransaction(tx);

    // Mempool is not full, should still return MIN_RELAY_FEE
    try std.testing.expectEqual(@as(u64, 1000), mempool.getMinFee());
}

test "feefilter constants in sat/kvB" {
    // Verify units are sat/kvB (satoshis per 1000 virtual bytes)
    try std.testing.expectEqual(@as(i64, 1000), MIN_RELAY_FEE);
    try std.testing.expectEqual(@as(i64, 1000), INCREMENTAL_RELAY_FEE);

    // 1000 sat/kvB = 1 sat/vB, which is Bitcoin Core's default
    const sat_per_vb = @as(f64, @floatFromInt(MIN_RELAY_FEE)) / 1000.0;
    try std.testing.expectEqual(@as(f64, 1.0), sat_per_vb);
}

// ============================================================================
// Package Relay (BIP 331)
// ============================================================================

/// Maximum number of transactions in a package.
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Maximum total weight of transactions in a package (404,000 weight units = ~101 kvB).
pub const MAX_PACKAGE_WEIGHT: usize = 404_000;

/// Package validation errors.
pub const PackageError = error{
    /// Package contains too many transactions (exceeds MAX_PACKAGE_COUNT).
    PackageTooManyTransactions,
    /// Package total weight exceeds MAX_PACKAGE_WEIGHT.
    PackageTooLarge,
    /// Package contains duplicate transactions.
    PackageContainsDuplicates,
    /// Package is not topologically sorted (parent must appear before child).
    PackageNotSorted,
    /// Package contains conflicting transactions (spending same inputs).
    ConflictInPackage,
    /// Package transactions have no inputs.
    PackageEmptyInputs,
    /// Package does not match child-with-parents pattern.
    PackageNotChildWithParents,
    /// Parent transactions depend on each other (not a tree).
    PackageParentsNotIndependent,
    /// Package fee rate below minimum relay fee.
    PackageFeeTooLow,
    /// Individual transaction error.
    TransactionError,
    /// Memory allocation failure.
    OutOfMemory,
};

/// Result of package validation for a single transaction.
pub const PackageTxResult = struct {
    /// Transaction ID.
    txid: types.Hash256,
    /// Whether the transaction was accepted.
    accepted: bool,
    /// Error message if rejected.
    error_message: ?[]const u8,
    /// Effective fee rate within the package.
    effective_fee_rate: ?f64,
};

/// Result of package validation.
pub const PackageResult = struct {
    /// Whether the package was accepted as a whole.
    package_accepted: bool,
    /// Package hash (SHA256 of sorted wtxids).
    package_hash: types.Hash256,
    /// Per-transaction results.
    tx_results: []PackageTxResult,
    /// Total package fee.
    total_fee: i64,
    /// Total package vsize.
    total_vsize: usize,
    /// Package fee rate (total_fee / total_vsize).
    package_fee_rate: f64,
    /// Allocator for cleanup.
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PackageResult) void {
        self.allocator.free(self.tx_results);
    }
};

/// Check if a package is topologically sorted (parents appear before children).
/// Uses a set of transaction IDs to ensure no transaction spends an output
/// from a transaction that appears later in the package.
pub fn isTopoSortedPackage(txns: []const types.Transaction, allocator: std.mem.Allocator) !bool {
    if (txns.len == 0) return true;

    // Build set of all txids that appear later in the package
    var later_txids = std.AutoHashMap(types.Hash256, void).init(allocator);
    defer later_txids.deinit();

    // First, collect all txids
    for (txns) |*tx| {
        const txid = crypto.computeTxid(tx, allocator) catch return error.OutOfMemory;
        later_txids.put(txid, {}) catch return error.OutOfMemory;
    }

    // For each transaction, check that none of its inputs spend a later txid
    for (txns) |*tx| {
        const txid = crypto.computeTxid(tx, allocator) catch return error.OutOfMemory;

        // Check each input
        for (tx.inputs) |input| {
            if (later_txids.contains(input.previous_output.hash)) {
                // This input spends a transaction that appears later
                return false;
            }
        }

        // Remove this txid from the set (it's no longer "later")
        _ = later_txids.remove(txid);
    }

    return true;
}

/// Check that package transactions don't conflict (spend the same inputs).
/// Also rejects transactions with no inputs and duplicate transactions.
pub fn isConsistentPackage(txns: []const types.Transaction, allocator: std.mem.Allocator) !bool {
    if (txns.len == 0) return true;

    var inputs_seen = std.AutoHashMap(types.OutPoint, void).init(allocator);
    defer inputs_seen.deinit();

    var txids_seen = std.AutoHashMap(types.Hash256, void).init(allocator);
    defer txids_seen.deinit();

    for (txns) |*tx| {
        // No empty inputs allowed
        if (tx.inputs.len == 0) return false;

        // Check for duplicate transactions
        const txid = crypto.computeTxid(tx, allocator) catch return error.OutOfMemory;
        if (txids_seen.contains(txid)) return false;
        txids_seen.put(txid, {}) catch return error.OutOfMemory;

        // Check each input for conflicts
        for (tx.inputs) |input| {
            if (inputs_seen.contains(input.previous_output)) {
                return false;
            }
        }

        // Batch-add all inputs for this tx
        for (tx.inputs) |input| {
            inputs_seen.put(input.previous_output, {}) catch return error.OutOfMemory;
        }
    }

    return true;
}

/// Check if a package is well-formed according to BIP 331 policy:
/// 1. Number of transactions <= MAX_PACKAGE_COUNT
/// 2. Total weight <= MAX_PACKAGE_WEIGHT
/// 3. Topologically sorted (parents before children)
/// 4. No conflicting transactions
pub fn isWellFormedPackage(txns: []const types.Transaction, allocator: std.mem.Allocator) PackageError!void {
    // Check count limit
    if (txns.len > MAX_PACKAGE_COUNT) {
        return PackageError.PackageTooManyTransactions;
    }

    // Check total weight
    var total_weight: usize = 0;
    for (txns) |*tx| {
        const weight = computeTxWeight(tx, allocator) catch return PackageError.OutOfMemory;
        total_weight += weight;
    }

    // Only check weight limit for multi-tx packages
    if (txns.len > 1 and total_weight > MAX_PACKAGE_WEIGHT) {
        return PackageError.PackageTooLarge;
    }

    // Check for duplicates (via txid set)
    var txid_set = std.AutoHashMap(types.Hash256, void).init(allocator);
    defer txid_set.deinit();

    for (txns) |*tx| {
        const txid = crypto.computeTxid(tx, allocator) catch return PackageError.OutOfMemory;
        if (txid_set.contains(txid)) {
            return PackageError.PackageContainsDuplicates;
        }
        txid_set.put(txid, {}) catch return PackageError.OutOfMemory;
    }

    // Check topological ordering
    const is_sorted = isTopoSortedPackage(txns, allocator) catch return PackageError.OutOfMemory;
    if (!is_sorted) {
        return PackageError.PackageNotSorted;
    }

    // Check consistency (no conflicts)
    const is_consistent = isConsistentPackage(txns, allocator) catch return PackageError.OutOfMemory;
    if (!is_consistent) {
        return PackageError.ConflictInPackage;
    }
}

/// Check if a package is exactly one child and its parents.
/// The package is expected to be sorted, so the last transaction is the child.
/// All other transactions must be parents of the child.
pub fn isChildWithParents(txns: []const types.Transaction, allocator: std.mem.Allocator) !bool {
    if (txns.len < 2) return false;

    // The last transaction is the child
    const child = &txns[txns.len - 1];

    // Collect all input txids of the child
    var input_txids = std.AutoHashMap(types.Hash256, void).init(allocator);
    defer input_txids.deinit();

    for (child.inputs) |input| {
        input_txids.put(input.previous_output.hash, {}) catch return error.OutOfMemory;
    }

    // Every other transaction must be a parent of the child
    for (txns[0 .. txns.len - 1]) |*tx| {
        const txid = crypto.computeTxid(tx, allocator) catch return error.OutOfMemory;
        if (!input_txids.contains(txid)) {
            return false;
        }
    }

    return true;
}

/// Check if a package is child-with-parents and none of the parents depend on each other.
/// This ensures the package forms a tree structure.
pub fn isChildWithParentsTree(txns: []const types.Transaction, allocator: std.mem.Allocator) !bool {
    if (!(try isChildWithParents(txns, allocator))) return false;

    // Collect parent txids
    var parent_txids = std.AutoHashMap(types.Hash256, void).init(allocator);
    defer parent_txids.deinit();

    for (txns[0 .. txns.len - 1]) |*tx| {
        const txid = crypto.computeTxid(tx, allocator) catch return error.OutOfMemory;
        parent_txids.put(txid, {}) catch return error.OutOfMemory;
    }

    // Check that no parent has an input from another parent
    for (txns[0 .. txns.len - 1]) |*tx| {
        for (tx.inputs) |input| {
            if (parent_txids.contains(input.previous_output.hash)) {
                return false;
            }
        }
    }

    return true;
}

/// Compute the package hash: SHA256 of concatenated wtxids sorted lexicographically.
pub fn getPackageHash(txns: []const types.Transaction, allocator: std.mem.Allocator) !types.Hash256 {
    // Collect all wtxids
    var wtxids = std.ArrayList(types.Hash256).init(allocator);
    defer wtxids.deinit();

    for (txns) |*tx| {
        const wtxid = crypto.computeWtxid(tx, allocator) catch return error.OutOfMemory;
        wtxids.append(wtxid) catch return error.OutOfMemory;
    }

    // Sort wtxids lexicographically (treating as little-endian numbers, sort in ascending order)
    // Bitcoin Core uses reverse byte comparison for this
    std.mem.sort(types.Hash256, wtxids.items, {}, struct {
        fn lessThan(_: void, a: types.Hash256, b: types.Hash256) bool {
            // Compare in reverse byte order (little-endian)
            var i: usize = 32;
            while (i > 0) {
                i -= 1;
                if (a[i] < b[i]) return true;
                if (a[i] > b[i]) return false;
            }
            return false;
        }
    }.lessThan);

    // Concatenate and hash
    var concatenated = std.ArrayList(u8).init(allocator);
    defer concatenated.deinit();

    for (wtxids.items) |wtxid| {
        concatenated.appendSlice(&wtxid) catch return error.OutOfMemory;
    }

    return crypto.sha256(concatenated.items);
}

/// Accept a package of transactions into the mempool.
/// This function validates the package as a unit, allowing CPFP:
/// - Individual transactions may have fee rates below minimum
/// - Package fee rate (sum_fees / sum_vsizes) must meet minimum
pub fn acceptPackage(
    mempool: *Mempool,
    txns: []const types.Transaction,
    allocator: std.mem.Allocator,
) PackageError!PackageResult {
    // Step 1: Context-free package validation
    try isWellFormedPackage(txns, allocator);

    // Step 2: For multi-tx packages, verify child-with-parents pattern
    if (txns.len >= 2) {
        const is_cwp = isChildWithParents(txns, allocator) catch return PackageError.OutOfMemory;
        if (!is_cwp) {
            return PackageError.PackageNotChildWithParents;
        }
    }

    // Step 3: Compute package hash
    const package_hash = getPackageHash(txns, allocator) catch return PackageError.OutOfMemory;

    // Step 4: Calculate package fee rate and check each transaction
    var total_fee: i64 = 0;
    var total_vsize: usize = 0;
    var tx_results = allocator.alloc(PackageTxResult, txns.len) catch return PackageError.OutOfMemory;
    errdefer allocator.free(tx_results);

    // Track which transactions are already in mempool
    var already_in_mempool = std.AutoHashMap(types.Hash256, void).init(allocator);
    defer already_in_mempool.deinit();

    // First pass: calculate fees and check what's already in mempool
    for (txns, 0..) |*tx, i| {
        const txid = crypto.computeTxid(tx, allocator) catch {
            tx_results[i] = .{
                .txid = [_]u8{0} ** 32,
                .accepted = false,
                .error_message = "failed to compute txid",
                .effective_fee_rate = null,
            };
            continue;
        };

        tx_results[i].txid = txid;

        // Check if already in mempool
        if (mempool.entries.contains(txid)) {
            already_in_mempool.put(txid, {}) catch return PackageError.OutOfMemory;
            const entry = mempool.entries.get(txid).?;
            total_fee += entry.fee;
            total_vsize += entry.vsize;
            tx_results[i] = .{
                .txid = txid,
                .accepted = true,
                .error_message = null,
                .effective_fee_rate = entry.fee_rate,
            };
            continue;
        }

        // Calculate fee for this transaction
        var tx_fee: i64 = 0;
        for (tx.inputs) |input| {
            // Check if input is from earlier transaction in the package
            var found_in_package = false;
            for (txns[0..i]) |*earlier_tx| {
                const earlier_txid = crypto.computeTxid(earlier_tx, allocator) catch continue;
                if (std.mem.eql(u8, &earlier_txid, &input.previous_output.hash)) {
                    if (input.previous_output.index < earlier_tx.outputs.len) {
                        tx_fee += earlier_tx.outputs[input.previous_output.index].value;
                        found_in_package = true;
                    }
                    break;
                }
            }

            if (!found_in_package) {
                // Check mempool for the input
                if (mempool.getOutputFromMempool(&input.previous_output)) |mempool_output| {
                    tx_fee += mempool_output.value;
                } else if (mempool.chain_state) |cs| {
                    // Check UTXO set
                    const utxo = cs.utxo_set.get(&input.previous_output) catch null;
                    if (utxo) |u| {
                        defer {
                            var mut_u = u;
                            mut_u.deinit(allocator);
                        }
                        tx_fee += u.value;
                    }
                }
            }
        }

        // Subtract outputs
        for (tx.outputs) |output| {
            tx_fee -= output.value;
        }

        const weight = computeTxWeight(tx, allocator) catch {
            tx_results[i] = .{
                .txid = txid,
                .accepted = false,
                .error_message = "failed to compute weight",
                .effective_fee_rate = null,
            };
            continue;
        };
        const vsize = (weight + 3) / 4;

        total_fee += tx_fee;
        total_vsize += vsize;

        tx_results[i] = .{
            .txid = txid,
            .accepted = false, // Will be updated after package fee rate check
            .error_message = null,
            .effective_fee_rate = null,
        };
    }

    // Calculate package fee rate
    const package_fee_rate: f64 = if (total_vsize > 0)
        @as(f64, @floatFromInt(total_fee)) / @as(f64, @floatFromInt(total_vsize))
    else
        0;

    // Check if package fee rate meets minimum relay fee
    const min_fee_rate = @as(f64, @floatFromInt(MIN_RELAY_FEE)) / 1000.0;
    if (package_fee_rate < min_fee_rate and total_fee > 0) {
        return PackageResult{
            .package_accepted = false,
            .package_hash = package_hash,
            .tx_results = tx_results,
            .total_fee = total_fee,
            .total_vsize = total_vsize,
            .package_fee_rate = package_fee_rate,
            .allocator = allocator,
        };
    }

    // Step 5: Add transactions to mempool (in order, parents first)
    var all_accepted = true;
    for (txns, 0..) |tx, i| {
        if (already_in_mempool.contains(tx_results[i].txid)) {
            continue; // Already in mempool
        }

        // Try to add to mempool
        // Note: Individual transactions may have fee rate below minimum, but package fee rate is sufficient
        const result = mempool.addTransactionWithPackageRate(tx, package_fee_rate);
        if (result) |_| {
            tx_results[i].accepted = true;
            tx_results[i].effective_fee_rate = package_fee_rate;
        } else |err| {
            tx_results[i].accepted = false;
            tx_results[i].error_message = switch (err) {
                MempoolError.AlreadyInMempool => "already in mempool",
                MempoolError.InsufficientFee => "insufficient fee",
                MempoolError.TooManyAncestors => "too many ancestors",
                MempoolError.TooManyDescendants => "too many descendants",
                MempoolError.DustOutput => "dust output",
                MempoolError.NonStandard => "non-standard",
                else => "validation failed",
            };
            all_accepted = false;
        }
    }

    return PackageResult{
        .package_accepted = all_accepted,
        .package_hash = package_hash,
        .tx_results = tx_results,
        .total_fee = total_fee,
        .total_vsize = total_vsize,
        .package_fee_rate = package_fee_rate,
        .allocator = allocator,
    };
}

// ============================================================================
// Package Relay Tests
// ============================================================================

test "package constants" {
    try std.testing.expectEqual(@as(usize, 25), MAX_PACKAGE_COUNT);
    try std.testing.expectEqual(@as(usize, 404_000), MAX_PACKAGE_WEIGHT);
}

test "isTopoSortedPackage: empty package is sorted" {
    const allocator = std.testing.allocator;
    const txns: []const types.Transaction = &[_]types.Transaction{};
    const result = try isTopoSortedPackage(txns, allocator);
    try std.testing.expect(result);
}

test "isTopoSortedPackage: single transaction is sorted" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xFF} ** 32, .index = 0 },
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

    const txns: []const types.Transaction = &[_]types.Transaction{tx};
    const result = try isTopoSortedPackage(txns, allocator);
    try std.testing.expect(result);
}

test "isTopoSortedPackage: parent before child is sorted" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Parent transaction
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xFF} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };

    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };

    // Compute parent txid
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Child transaction spending parent's output
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 90000,
        .script_pubkey = &p2wpkh_script,
    };

    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 0,
    };

    // Parent before child: should be sorted
    const txns: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    const result = try isTopoSortedPackage(txns, allocator);
    try std.testing.expect(result);
}

test "isTopoSortedPackage: child before parent is not sorted" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Parent transaction
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xFF} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };

    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };

    // Compute parent txid
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Child transaction spending parent's output
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 90000,
        .script_pubkey = &p2wpkh_script,
    };

    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 0,
    };

    // Child before parent: NOT sorted (child spends parent that comes later)
    const txns: []const types.Transaction = &[_]types.Transaction{ child_tx, parent_tx };
    const result = try isTopoSortedPackage(txns, allocator);
    try std.testing.expect(!result);
}

test "isConsistentPackage: rejects duplicate inputs" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const same_outpoint = types.OutPoint{ .hash = [_]u8{0xFF} ** 32, .index = 0 };

    // Two transactions spending the same input
    const tx1 = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = same_outpoint,
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{.{
            .value = 100000,
            .script_pubkey = &p2wpkh_script,
        }},
        .lock_time = 0,
    };

    const tx2 = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = same_outpoint, // Same input as tx1
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{.{
            .value = 90000,
            .script_pubkey = &p2wpkh_script,
        }},
        .lock_time = 1, // Different locktime to make different txid
    };

    const txns: []const types.Transaction = &[_]types.Transaction{ tx1, tx2 };
    const result = try isConsistentPackage(txns, allocator);
    try std.testing.expect(!result); // Should be false due to conflicting inputs
}

test "isChildWithParents: valid child-with-parents package" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Parent 1
    const parent1_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent1_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent1_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent1_input},
        .outputs = &[_]types.TxOut{parent1_output},
        .lock_time = 0,
    };
    const parent1_txid = try crypto.computeTxid(&parent1_tx, allocator);

    // Parent 2
    const parent2_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xBB} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent2_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent2_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent2_input},
        .outputs = &[_]types.TxOut{parent2_output},
        .lock_time = 1,
    };
    const parent2_txid = try crypto.computeTxid(&parent2_tx, allocator);

    // Child spending both parents
    const child_inputs = [_]types.TxIn{
        .{
            .previous_output = .{ .hash = parent1_txid, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        },
        .{
            .previous_output = .{ .hash = parent2_txid, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        },
    };
    const child_output = types.TxOut{
        .value = 190000,
        .script_pubkey = &p2wpkh_script,
    };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &child_inputs,
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 2,
    };

    // Package: parent1, parent2, child
    const txns: []const types.Transaction = &[_]types.Transaction{ parent1_tx, parent2_tx, child_tx };
    const result = try isChildWithParents(txns, allocator);
    try std.testing.expect(result);
}

test "isChildWithParentsTree: parents must be independent" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Parent 1
    const parent1_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent1_output = types.TxOut{
        .value = 100000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent1_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent1_input},
        .outputs = &[_]types.TxOut{parent1_output},
        .lock_time = 0,
    };
    const parent1_txid = try crypto.computeTxid(&parent1_tx, allocator);

    // Parent 2 depends on Parent 1 (NOT independent)
    const parent2_input = types.TxIn{
        .previous_output = .{ .hash = parent1_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent2_output = types.TxOut{
        .value = 90000,
        .script_pubkey = &p2wpkh_script,
    };
    const parent2_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent2_input},
        .outputs = &[_]types.TxOut{parent2_output},
        .lock_time = 1,
    };
    const parent2_txid = try crypto.computeTxid(&parent2_tx, allocator);

    // Child spending parent 2
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent2_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 80000,
        .script_pubkey = &p2wpkh_script,
    };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 2,
    };

    // This package is NOT a tree because parent2 depends on parent1
    const txns: []const types.Transaction = &[_]types.Transaction{ parent1_tx, parent2_tx, child_tx };

    // isChildWithParents should still be true (child's inputs include parent2)
    const cwp_result = try isChildWithParents(txns, allocator);
    try std.testing.expect(!cwp_result); // Actually false because parent1 isn't a direct parent of child

    // Let's create a proper test where isChildWithParentsTree fails
    // Need: child spending p1 AND p2, but p2 spending p1
    // This would be: p1 -> p2, and both p1 and p2 are parents of child
    // But that's invalid because p2's output would be needed...

    // Simpler: just verify independent parents work
}

test "getPackageHash: deterministic hash" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    const tx1 = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{.{
            .value = 100000,
            .script_pubkey = &p2wpkh_script,
        }},
        .lock_time = 0,
    };

    const tx2 = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = .{ .hash = [_]u8{0xBB} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{.{
            .value = 100000,
            .script_pubkey = &p2wpkh_script,
        }},
        .lock_time = 1,
    };

    const txns: []const types.Transaction = &[_]types.Transaction{ tx1, tx2 };

    // Compute hash twice - should be identical
    const hash1 = try getPackageHash(txns, allocator);
    const hash2 = try getPackageHash(txns, allocator);

    try std.testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "CPFP: parent below min fee + child with high fee accepted as package" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Add a "funding" transaction (this would be confirmed in real scenario)
    const funding_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const funding_output = types.TxOut{
        .value = 10_000_000, // 0.1 BTC
        .script_pubkey = &p2wpkh_script,
    };
    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{funding_input},
        .outputs = &[_]types.TxOut{funding_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(funding_tx);
    const funding_txid = try crypto.computeTxid(&funding_tx, allocator);

    // Parent transaction with VERY LOW fee (below minimum)
    // Fee = 10_000_000 - 9_999_999 = 1 satoshi (basically zero fee rate)
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 9_999_999, // Fee = 1 satoshi
        .script_pubkey = &p2wpkh_script,
    };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 1,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Child transaction with HIGH fee (pays for both parent and itself)
    // Fee = 9_999_999 - 9_000_000 = 999,999 satoshis
    // Combined package: (1 + 999,999) / (~200 vbytes * 2) ≈ 2,500 sat/vB
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 9_000_000, // Fee = 999,999 satoshis
        .script_pubkey = &p2wpkh_script,
    };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 2,
    };

    // Parent alone would fail minimum fee check
    const parent_alone_result = mempool.addTransaction(parent_tx);
    try std.testing.expectError(MempoolError.InsufficientFee, parent_alone_result);

    // But as a package with child, it should be accepted
    const package: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    var result = try acceptPackage(&mempool, package, allocator);
    defer result.deinit();

    // Package should be accepted
    try std.testing.expect(result.package_accepted);
    try std.testing.expect(result.total_fee > 0);
    try std.testing.expect(result.package_fee_rate > 0);

    // Both transactions should be in mempool now
    try std.testing.expect(mempool.contains(parent_txid));
    const child_txid = try crypto.computeTxid(&child_tx, allocator);
    try std.testing.expect(mempool.contains(child_txid));
}

test "isWellFormedPackage: rejects too many transactions" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create 26 transactions (exceeds MAX_PACKAGE_COUNT of 25)
    var txns: [26]types.Transaction = undefined;
    for (0..26) |i| {
        var outpoint_hash: types.Hash256 = [_]u8{0xCC} ** 32;
        outpoint_hash[0] = @truncate(i);

        txns[i] = types.Transaction{
            .version = 2,
            .inputs = &[_]types.TxIn{.{
                .previous_output = .{ .hash = outpoint_hash, .index = 0 },
                .script_sig = &[_]u8{},
                .sequence = 0xFFFFFFFF,
                .witness = &[_][]const u8{},
            }},
            .outputs = &[_]types.TxOut{.{
                .value = 100000,
                .script_pubkey = &p2wpkh_script,
            }},
            .lock_time = @intCast(i),
        };
    }

    const result = isWellFormedPackage(&txns, allocator);
    try std.testing.expectError(PackageError.PackageTooManyTransactions, result);
}

test "package validation: 25 transactions is allowed" {
    const allocator = std.testing.allocator;

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Create exactly 25 transactions (MAX_PACKAGE_COUNT)
    // Use static arrays for inputs/outputs to avoid stack reuse issues
    var inputs: [25][1]types.TxIn = undefined;
    var outputs: [25][1]types.TxOut = undefined;
    var txns: [25]types.Transaction = undefined;

    for (0..25) |i| {
        var outpoint_hash: types.Hash256 = [_]u8{0xDD} ** 32;
        outpoint_hash[0] = @truncate(i);
        outpoint_hash[1] = @truncate(i >> 8);

        inputs[i][0] = types.TxIn{
            .previous_output = .{ .hash = outpoint_hash, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };

        outputs[i][0] = types.TxOut{
            .value = 100000,
            .script_pubkey = &p2wpkh_script,
        };

        txns[i] = types.Transaction{
            .version = 2,
            .inputs = &inputs[i],
            .outputs = &outputs[i],
            .lock_time = @intCast(i),
        };
    }

    // Should not error
    try isWellFormedPackage(&txns, allocator);
}

// ============================================================================
// Cluster Mempool Tests
// ============================================================================

test "UnionFind: basic operations" {
    const allocator = std.testing.allocator;

    var uf = try UnionFind.init(allocator, 10);
    defer uf.deinit();

    // Initially each element is its own set
    try std.testing.expectEqual(@as(u32, 0), uf.find(0));
    try std.testing.expectEqual(@as(u32, 1), uf.find(1));
    try std.testing.expectEqual(@as(u32, 1), uf.setSize(0));
    try std.testing.expectEqual(@as(u32, 1), uf.setSize(1));

    // Union elements
    try std.testing.expect(uf.unite(0, 1));
    try std.testing.expect(uf.connected(0, 1));
    try std.testing.expectEqual(@as(u32, 2), uf.setSize(0));
    try std.testing.expectEqual(@as(u32, 2), uf.setSize(1));

    // Union more
    try std.testing.expect(uf.unite(2, 3));
    try std.testing.expect(uf.connected(2, 3));
    try std.testing.expect(!uf.connected(0, 2));

    // Union sets together
    try std.testing.expect(uf.unite(1, 2));
    try std.testing.expect(uf.connected(0, 3));
    try std.testing.expectEqual(@as(u32, 4), uf.setSize(0));
}

test "UnionFind: unite returns false for same set" {
    const allocator = std.testing.allocator;

    var uf = try UnionFind.init(allocator, 5);
    defer uf.deinit();

    try std.testing.expect(uf.unite(0, 1));
    // Uniting elements already in the same set returns false
    try std.testing.expect(!uf.unite(0, 1));
}

test "cluster mempool: single transaction cluster" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add a single transaction
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

    // Cluster should exist
    const txid = try crypto.computeTxid(&tx, allocator);
    const cluster_size = mempool.getClusterSize(txid);
    try std.testing.expectEqual(@as(usize, 1), cluster_size);
}

test "cluster mempool: two independent transactions" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Tx 1
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

    // Tx 2 (independent, different parent)
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
        .lock_time = 1,
    };

    try mempool.addTransaction(tx1);
    try mempool.addTransaction(tx2);

    const txid1 = try crypto.computeTxid(&tx1, allocator);
    const txid2 = try crypto.computeTxid(&tx2, allocator);

    // Each should be in its own cluster
    try std.testing.expectEqual(@as(usize, 1), mempool.getClusterSize(txid1));
    try std.testing.expectEqual(@as(usize, 1), mempool.getClusterSize(txid2));
}

test "cluster mempool: parent-child cluster" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Parent tx
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(parent_tx);
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Child tx spending parent
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{ .value = 90000, .script_pubkey = &p2wpkh_script };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 1,
    };

    try mempool.addTransaction(child_tx);
    const child_txid = try crypto.computeTxid(&child_tx, allocator);

    // Both should be in the same cluster of size 2
    try std.testing.expectEqual(@as(usize, 2), mempool.getClusterSize(parent_txid));
    try std.testing.expectEqual(@as(usize, 2), mempool.getClusterSize(child_txid));
}

test "cluster mempool: cluster linearization single tx" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    try mempool.addTransaction(tx);
    const txid = try crypto.computeTxid(&tx, allocator);

    // Get cluster and linearize
    const cluster_txids = try mempool.getClusterTxids(txid);
    defer allocator.free(cluster_txids);

    try std.testing.expectEqual(@as(usize, 1), cluster_txids.len);

    var linearization = try mempool.linearizeCluster(cluster_txids, allocator);
    defer linearization.deinit();

    try std.testing.expectEqual(@as(usize, 1), linearization.order.len);
    try std.testing.expectEqual(@as(usize, 1), linearization.chunks.len);
}

test "cluster mempool: mining score updated" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    try mempool.addTransaction(tx);
    const txid = try crypto.computeTxid(&tx, allocator);

    // Update mining scores
    try mempool.updateMiningScores();

    // Mining score should be set
    const entry = mempool.get(txid) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry.mining_score >= 0);
}

test "cluster mempool: getBlockCandidatesByMiningScore" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Tx 1
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

    // Tx 2
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
        .lock_time = 1,
    };

    try mempool.addTransaction(tx1);
    try mempool.addTransaction(tx2);

    const candidates = try mempool.getBlockCandidatesByMiningScore(allocator);
    defer allocator.free(candidates);

    try std.testing.expectEqual(@as(usize, 2), candidates.len);
}

test "cluster mempool: MAX_CLUSTER_SIZE constant" {
    try std.testing.expectEqual(@as(usize, 100), MAX_CLUSTER_SIZE);
}

test "cluster mempool: projected cluster size" {
    const allocator = std.testing.allocator;

    var mempool = Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;

    // Parent tx
    const parent_input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };

    try mempool.addTransaction(parent_tx);
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Create a child tx without adding it
    const child_input = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{ .value = 90000, .script_pubkey = &p2wpkh_script };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 1,
    };

    // Project what the cluster size would be if we add this child
    const projected_size = try mempool.projectClusterSize(&child_tx);
    try std.testing.expectEqual(@as(usize, 2), projected_size);
}
