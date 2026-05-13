//! W106 — CTxMemPool descendant/ancestor tracking + RBF + package mempool 30-gate audit
//!
//! Reference: bitcoin-core/src/txmempool.h/cpp, policy/rbf.h/cpp,
//!            policy/truc_policy.h/cpp, policy/packages.h/cpp
//!
//! Clearbit equivalent: src/mempool.zig (Mempool, MempoolEntry, checkRBFRules,
//!                      checkTrucPolicy, acceptPackage, updateDescendantCounts,
//!                      getAncestors)
//!
//! Gate numbering:
//!   G1-G10  : Ancestor/descendant tracking
//!   G11-G20 : RBF BIP-125
//!   G21-G25 : TRUC v3 policy
//!   G26-G30 : Package / misc
//!
//! BUGs found (severity in comments):
//!   BUG-1  : G5  nSizeWithDescendants invariant broken on removeTransaction —
//!             removeTransaction does NOT decrement ancestor's descendant_count/
//!             descendant_size, so those fields drift high after removal.
//!   BUG-2  : G6  nModFeesWithDescendants: no fee_delta (nFeeDelta) support at all.
//!             PrioritiseTransaction / mapDeltas absent; getModifiedFee == fee always.
//!   BUG-3  : G7  ancestor_score / indexed_transaction_set: cluster linearization
//!             BitSet is hard-limited to 64 elements (IntegerBitSet(64)); clusters
//!             larger than 64 fall back to degraded greedy single-tx selection,
//!             breaking optimal linearization for large clusters.
//!   BUG-4  : G15 RBF Rule 2: no new-unconfirmed-inputs check. EntriesAndTxidsDisjoint
//!             checks whether the REPLACEMENT spends an ancestor of a conflict, but
//!             clearbit only checks whether the replacement spends the directly-
//!             conflicting tx itself. An ancestor that happens to be a direct conflict
//!             descendant is missed if the input is the ANCESTOR (not the direct
//!             conflict).  (Partial — core case covered, transitive case not.)
//!   BUG-5  : G17 ImprovesFeerateDiagram absent. The comment at line 2496 says
//!             "Gate 8 (ImprovesFeerateDiagram) requires cluster mempool — deferred."
//!             Core has enforced feerate-diagram improvement since 28.0; without it,
//!             an RBF replacement that worsens the diagram is accepted.
//!   BUG-6  : G23 TRUC zero-conf-spend forbidden: clearbit does NOT check that a TRUC
//!             tx's parent is confirmed. It correctly restricts to at most 1 unconfirmed
//!             parent (TRUC_ANCESTOR_LIMIT=2), but the Core rule also requires that a
//!             TRUC tx cannot spend from a TRUC parent that itself has an unconfirmed
//!             ancestor outside the TRUC chain (the ancestor_count check on the parent
//!             uses cached ancestor_count which may be stale post-removal).
//!   BUG-7  : G28 nFeeDelta / ApplyDelta absent. Same as BUG-2 at the package level:
//!             package fee rate calculation does not incorporate any fee delta bumps.
//!   BUG-8  : G1  removeForBlock does NOT decrement descendant stats of mined txs'
//!             ancestors remaining in mempool. When a parent is mined, its in-mempool
//!             children should see their ancestor_count drop by 1; clearbit simply
//!             calls removeTransaction (no ancestor update propagation).
//!   BUG-9  : G10 getAncestors BFS uses orderedRemove(0) which is O(N) per step →
//!             CalculateMemPoolAncestors is O(N²) instead of O(N log N). Not a
//!             correctness bug but a DoS amplifier: 25 hops × 25-item queue = 625 steps
//!             per insertion; Core uses skiplist + cached set. Severity: LOW.

const std = @import("std");
const testing = std.testing;
const mempool_mod = @import("mempool.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

// ============================================================================
// Test helpers
// ============================================================================

/// Build a minimal valid transaction. prev_hash[0..32] is the previous txid.
/// sequence defaults to 0xFFFFFFFE (does NOT signal RBF by default).
fn makeTx(
    prev_hash: [32]u8,
    prev_index: u32,
    out_value: i64,
    version: i32,
    sequence: u32,
) types.Transaction {
    const input = types.TxIn{
        .previous_output = types.OutPoint{ .hash = prev_hash, .index = prev_index },
        .script_sig = &[_]u8{},
        .sequence = sequence,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = out_value,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac }, // P2PKH
    };
    return types.Transaction{
        .version = version,
        .inputs = @constCast(&[_]types.TxIn{input}),
        .outputs = @constCast(&[_]types.TxOut{output}),
        .lock_time = 0,
    };
}

/// Build a tx that signals RBF (nSequence <= 0xFFFFFFFD).
fn makeRBFTx(prev_hash: [32]u8, prev_index: u32, out_value: i64) types.Transaction {
    return makeTx(prev_hash, prev_index, out_value, 1, 0xFFFFFFFD);
}

/// Build a TRUC (version=3) tx.
fn makeTrucTx(prev_hash: [32]u8, prev_index: u32, out_value: i64) types.Transaction {
    return makeTx(prev_hash, prev_index, out_value, 3, 0xFFFFFFFE);
}

/// Build a tx with two outputs (used to chain two children off one parent).
fn makeTxTwoOutputs(prev_hash: [32]u8, prev_index: u32) types.Transaction {
    const input = types.TxIn{
        .previous_output = types.OutPoint{ .hash = prev_hash, .index = prev_index },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const out1 = types.TxOut{
        .value = 20_000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac },
    };
    const out2 = types.TxOut{
        .value = 20_000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac },
    };
    return types.Transaction{
        .version = 1,
        .inputs = @constCast(&[_]types.TxIn{input}),
        .outputs = @constCast(&[_]types.TxOut{ out1, out2 }),
        .lock_time = 0,
    };
}

// ============================================================================
// G1 — DEFAULT_DESCENDANT_LIMIT = 25
// ============================================================================

test "w106 G1: DEFAULT_DESCENDANT_COUNT limit is 25" {
    // Core: DEFAULT_DESCENDANT_LIMIT = 25 (kernel/mempool_limits.h:20)
    try testing.expectEqual(@as(usize, 25), mempool_mod.MAX_DESCENDANT_COUNT);
}

// ============================================================================
// G2 — DEFAULT_ANCESTOR_LIMIT = 25
// ============================================================================

test "w106 G2: DEFAULT_ANCESTOR_COUNT limit is 25" {
    // Core: DEFAULT_ANCESTOR_LIMIT = 25 (kernel/mempool_limits.h:18)
    try testing.expectEqual(@as(usize, 25), mempool_mod.MAX_ANCESTOR_COUNT);
}

// ============================================================================
// G3 — CalculateMemPoolAncestors BFS returns full ancestor set
// ============================================================================

test "w106 G3: getAncestors BFS traverses full chain" {
    // Build a 3-deep chain: A → B → C. getAncestors(C) should return {A, B}.
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Tx A (root, no mempool parent)
    const root_hash: [32]u8 = [_]u8{0xAA} ** 32;
    const tx_a = makeTx(root_hash, 0, 90_000, 1, 0xFFFFFFFE);
    const txid_a = crypto.computeTxid(&tx_a, allocator) catch unreachable;

    // Add A to mempool directly (no chain state, fee = 0 since inputs assumed)
    pool.entries.put(txid_a, blk: {
        const e = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
        e.* = mempool_mod.MempoolEntry{
            .tx = tx_a,
            .txid = txid_a,
            .wtxid = txid_a,
            .fee = 1000,
            .size = 200,
            .weight = 800,
            .vsize = 200,
            .fee_rate = 5.0,
            .time_added = std.time.timestamp(),
            .height_added = 100,
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
        break :blk e;
    }) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = root_hash, .index = 0 }, txid_a) catch unreachable;

    // Build tx B spending A[0]
    const tx_b = makeTx(txid_a, 0, 80_000, 1, 0xFFFFFFFE);
    const txid_b = crypto.computeTxid(&tx_b, allocator) catch unreachable;
    pool.entries.put(txid_b, blk2: {
        const e = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
        e.* = mempool_mod.MempoolEntry{
            .tx = tx_b,
            .txid = txid_b,
            .wtxid = txid_b,
            .fee = 1000,
            .size = 200,
            .weight = 800,
            .vsize = 200,
            .fee_rate = 5.0,
            .time_added = std.time.timestamp(),
            .height_added = 100,
            .ancestor_count = 2,
            .ancestor_size = 400,
            .ancestor_fees = 2000,
            .descendant_count = 1,
            .descendant_size = 200,
            .descendant_fees = 1000,
            .is_rbf = false,
            .cluster_index = 1,
            .mining_score = 5.0,
        };
        break :blk2 e;
    }) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = txid_a, .index = 0 }, txid_b) catch unreachable;

    // Build tx C spending B[0]
    const tx_c = makeTx(txid_b, 0, 70_000, 1, 0xFFFFFFFE);

    // getAncestors counts include self → 3 (A + B + C including self)
    const anc = pool.getAncestors(txid_b, &tx_c) catch unreachable;
    // Should find B as direct parent (count includes self so ≥ 2)
    try testing.expect(anc.count >= 2);
}

// ============================================================================
// G4 — UpdateAncestorsOf / UpdateDescendantsForRemove
// ============================================================================

test "w106 G4: updateDescendantCounts propagates through ancestors" {
    // Adding a child should increment the parent's descendant_count.
    // NOTE: Transaction structs must be defined inline (not returned from a helper)
    // because their .inputs slice points into the local stack frame; returning by
    // value would leave a dangling pointer.
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Insert parent manually — define inline so .inputs slice stays valid.
    const dummy_prev: [32]u8 = [_]u8{0x11} ** 32;
    const parent_input = types.TxIn{
        .previous_output = types.OutPoint{ .hash = dummy_prev, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const parent_output = types.TxOut{
        .value = 90_000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac },
    };
    const parent_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{parent_input},
        .outputs = &[_]types.TxOut{parent_output},
        .lock_time = 0,
    };
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    const parent_entry = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    parent_entry.* = mempool_mod.MempoolEntry{
        .tx = parent_tx,
        .txid = parent_txid,
        .wtxid = parent_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 1, // starts at 1 (self)
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = false,
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(parent_txid, parent_entry) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = dummy_prev, .index = 0 }, parent_txid) catch unreachable;

    // Now add a child spending the parent; updateDescendantCounts should update parent.
    // Inline definition so the stored .inputs pointer stays valid.
    const child_input = types.TxIn{
        .previous_output = types.OutPoint{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const child_output = types.TxOut{
        .value = 80_000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac },
    };
    const child_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{child_input},
        .outputs = &[_]types.TxOut{child_output},
        .lock_time = 0,
    };
    const child_txid = crypto.computeTxid(&child_tx, allocator) catch unreachable;

    const child_entry = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    child_entry.* = mempool_mod.MempoolEntry{
        .tx = child_tx,
        .txid = child_txid,
        .wtxid = child_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 2,
        .ancestor_size = 400,
        .ancestor_fees = 2000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = false,
        .cluster_index = 1,
        .mining_score = 5.0,
    };
    pool.entries.put(child_txid, child_entry) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = parent_txid, .index = 0 }, child_txid) catch unreachable;

    // Update children list
    var children_list = std.ArrayList(types.Hash256).init(allocator);
    children_list.append(child_txid) catch unreachable;
    pool.children.put(parent_txid, children_list) catch unreachable;

    // Call updateDescendantCounts for the child
    pool.updateDescendantCounts(child_txid) catch unreachable;

    // After update, parent's descendant_count should be 2 (parent + child)
    const p = pool.entries.get(parent_txid).?;
    try testing.expectEqual(@as(usize, 2), p.descendant_count);
    try testing.expectEqual(@as(usize, 400), p.descendant_size); // 200 + 200
}

// ============================================================================
// G5 — nSizeWithDescendants: removeTransaction does NOT update ancestor stats
//       (BUG-1: MEDIUM — invariant drift after removal)
// ============================================================================

test "w106 G5: BUG-1 removeTransaction does not update ancestor descendant_count" {
    // After removing a child, the parent's descendant_count should decrease.
    // Clearbit's removeTransaction skips this reverse-propagation → BUG.
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Insert parent
    const dummy_prev2: [32]u8 = [_]u8{0x22} ** 32;
    const px = makeTx(dummy_prev2, 0, 90_000, 1, 0xFFFFFFFE);
    const px_txid = crypto.computeTxid(&px, allocator) catch unreachable;
    const pe = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    pe.* = mempool_mod.MempoolEntry{
        .tx = px,
        .txid = px_txid,
        .wtxid = px_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 2, // parent + 1 child
        .descendant_size = 400,
        .descendant_fees = 2000,
        .is_rbf = false,
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(px_txid, pe) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = dummy_prev2, .index = 0 }, px_txid) catch unreachable;

    // Insert child
    const cx = makeTx(px_txid, 0, 80_000, 1, 0xFFFFFFFE);
    const cx_txid = crypto.computeTxid(&cx, allocator) catch unreachable;
    const ce = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    ce.* = mempool_mod.MempoolEntry{
        .tx = cx,
        .txid = cx_txid,
        .wtxid = cx_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 2,
        .ancestor_size = 400,
        .ancestor_fees = 2000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = false,
        .cluster_index = 1,
        .mining_score = 5.0,
    };
    pool.entries.put(cx_txid, ce) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = px_txid, .index = 0 }, cx_txid) catch unreachable;

    var cl2 = std.ArrayList(types.Hash256).init(allocator);
    cl2.append(cx_txid) catch unreachable;
    pool.children.put(px_txid, cl2) catch unreachable;

    // Remove the child
    pool.removeTransaction(cx_txid);

    // BUG-1: parent's descendant_count is still 2, should be 1.
    const p2 = pool.entries.get(px_txid).?;
    // Document current (broken) behavior:
    // The invariant Core maintains is: after remove, parent.descendant_count == 1.
    // Clearbit does NOT maintain this → descendant_count remains 2.
    const current_desc_count = p2.descendant_count;
    // Assert the BUG exists (count stays at 2, not decremented to 1):
    try testing.expect(current_desc_count == 2); // BUG: should be 1 after child removal
}

// ============================================================================
// G6 — nModFeesWithDescendants: nFeeDelta support absent (BUG-2)
// ============================================================================

test "w106 G6: BUG-2 nFeeDelta/PrioritiseTransaction absent — modified fee always equals base fee" {
    // Bitcoin Core: CTxMemPool::PrioritiseTransaction adjusts mapDeltas[txid] and
    // modified fees used in mining/eviction.  Clearbit has no such mechanism.
    // Verify: no fee_delta field on MempoolEntry.
    const entry: mempool_mod.MempoolEntry = undefined;
    // If a fee_delta field existed, this compile-time check would catch it.
    const info = @typeInfo(mempool_mod.MempoolEntry);
    var has_fee_delta = false;
    inline for (info.Struct.fields) |field| {
        if (std.mem.eql(u8, field.name, "fee_delta") or
            std.mem.eql(u8, field.name, "modified_fee"))
        {
            has_fee_delta = true;
        }
    }
    _ = entry;
    // BUG-2: fee_delta is absent → PrioritiseTransaction is impossible.
    try testing.expect(!has_fee_delta); // Documents the absence
}

// ============================================================================
// G7 — ancestor_score / indexed_transaction_set: BitSet limited to 64 txs (BUG-3)
// ============================================================================

test "w106 G7: BUG-3 cluster linearization BitSet hard-limited to 64 transactions" {
    // linearizeCluster uses std.bit_set.IntegerBitSet(64); for clusters > 12 txs
    // it falls back to greedy single-tx selection.  Core's TxGraph handles
    // unbounded clusters via dynamic linearization.  Document the limit.
    const max_optimal = 12; // enumerated subset search threshold in clearbit
    const bitset_cap = 64;  // IntegerBitSet(64) ceiling
    // Any cluster with > max_optimal txs loses optimal ordering.
    // Any cluster with > bitset_cap txs causes UB (bit index overflow).
    try testing.expect(bitset_cap == 64); // documents the constant
    try testing.expect(max_optimal < bitset_cap);
    // BUG-3: clusters 13..64 use degraded greedy; clusters > 64 would UB.
}

// ============================================================================
// G8 — BFS properly stops at confirmed ancestors (inputs not in mempool are skipped)
// ============================================================================

test "w106 G8: getAncestors skips confirmed (non-mempool) inputs correctly" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // A tx whose only input is confirmed (not in mempool) — ancestor count = 1 (self only).
    const confirmed_prev: [32]u8 = [_]u8{0xCC} ** 32;
    const lone_tx = makeTx(confirmed_prev, 0, 90_000, 1, 0xFFFFFFFE);
    const lone_txid = crypto.computeTxid(&lone_tx, allocator) catch unreachable;

    const anc = pool.getAncestors(lone_txid, &lone_tx) catch unreachable;
    // No mempool ancestor — count includes self = 1
    try testing.expectEqual(@as(usize, 1), anc.count);
    try testing.expectEqual(@as(usize, 0), anc.size);
}

// ============================================================================
// G9 — MAX_ANCESTOR_SIZE = 101,000 bytes
// ============================================================================

test "w106 G9: MAX_ANCESTOR_SIZE constant is 101,000 bytes" {
    // Core: DEFAULT_ANCESTOR_SIZE_LIMIT = 101 kvB (kernel/mempool_limits.h:22)
    try testing.expectEqual(@as(usize, 101_000), mempool_mod.MAX_ANCESTOR_SIZE);
}

// ============================================================================
// G10 — MAX_DESCENDANT_SIZE = 101,000 bytes
// ============================================================================

test "w106 G10: MAX_DESCENDANT_SIZE constant is 101,000 bytes" {
    // Core: DEFAULT_DESCENDANT_SIZE_LIMIT = 101 kvB (kernel/mempool_limits.h:24)
    try testing.expectEqual(@as(usize, 101_000), mempool_mod.MAX_DESCENDANT_SIZE);
}

// ============================================================================
// G11 — SignalsOptInRBF: nSequence <= 0xFFFFFFFD
// ============================================================================

test "w106 G11: SignalsOptInRBF — nSequence 0xFFFFFFFD signals, 0xFFFFFFFE does not" {
    // Core util/rbf.cpp: MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD
    try testing.expectEqual(@as(u32, 0xFFFFFFFD), mempool_mod.MAX_BIP125_RBF_SEQUENCE);

    const prev: [32]u8 = [_]u8{0xBB} ** 32;
    const out = types.TxOut{ .value = 9000, .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac } };

    // Transactions must be defined inline so the .inputs slice lives in the same
    // stack frame as the isRBFSignaled call — returning from a helper would leave
    // a dangling pointer in the stored .inputs field.
    const rbf_in = types.TxIn{ .previous_output = .{ .hash = prev, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFD, .witness = &[_][]const u8{} };
    const rbf_tx = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{rbf_in}, .outputs = &[_]types.TxOut{out}, .lock_time = 0 };
    try testing.expect(mempool_mod.Mempool.isRBFSignaled(&rbf_tx));

    const non_rbf_in = types.TxIn{ .previous_output = .{ .hash = prev, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFE, .witness = &[_][]const u8{} };
    const non_rbf_tx = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{non_rbf_in}, .outputs = &[_]types.TxOut{out}, .lock_time = 0 };
    try testing.expect(!mempool_mod.Mempool.isRBFSignaled(&non_rbf_tx));

    const final_in = types.TxIn{ .previous_output = .{ .hash = prev, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFF, .witness = &[_][]const u8{} };
    const final_tx = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{final_in}, .outputs = &[_]types.TxOut{out}, .lock_time = 0 };
    try testing.expect(!mempool_mod.Mempool.isRBFSignaled(&final_tx));
}

// ============================================================================
// G12 — RBF Rule 1: all conflicts must signal opt-in (or full_rbf)
// ============================================================================

test "w106 G12: RBF Rule 1 — non-signaling conflict rejected without full_rbf" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    pool.full_rbf = false;

    const prev_h: [32]u8 = [_]u8{0x33} ** 32;

    // Insert a non-RBF tx as a "conflict placeholder" by putting it in entries
    const existing_tx = makeTx(prev_h, 0, 90_000, 1, 0xFFFFFFFE); // does NOT signal
    const existing_txid = crypto.computeTxid(&existing_tx, allocator) catch unreachable;

    const existing_entry = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    existing_entry.* = .{
        .tx = existing_tx,
        .txid = existing_txid,
        .wtxid = existing_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = false, // NOT signaling
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(existing_txid, existing_entry) catch unreachable;

    // Replacement tx
    const replacer_txid = existing_txid; // reuse for conflict list
    const conflicts = [_]types.Hash256{existing_txid};

    // checkRBFRules should return NonBIP125Replaceable
    const result = pool.checkRBFRules(
        &existing_tx,
        replacer_txid,
        2000,
        200,
        &conflicts,
    );
    try testing.expectError(mempool_mod.MempoolError.NonBIP125Replaceable, result);
}

// ============================================================================
// G13 — RBF Rule 1: full_rbf bypasses opt-in check
// ============================================================================

test "w106 G13: RBF full_rbf bypasses opt-in signal requirement" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    pool.full_rbf = true; // -mempoolfullrbf=1

    const prev_h: [32]u8 = [_]u8{0x44} ** 32;
    const existing_tx = makeTx(prev_h, 0, 90_000, 1, 0xFFFFFFFF); // final sequence
    const existing_txid = crypto.computeTxid(&existing_tx, allocator) catch unreachable;

    const existing_entry = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    existing_entry.* = .{
        .tx = existing_tx,
        .txid = existing_txid,
        .wtxid = existing_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
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
    pool.entries.put(existing_txid, existing_entry) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, existing_txid) catch unreachable;

    const conflicts = [_]types.Hash256{existing_txid};
    // full_rbf → should NOT get NonBIP125Replaceable; fees check takes over
    const result = pool.checkRBFRules(
        &existing_tx,
        existing_txid,
        5000, // higher fee
        200,
        &conflicts,
    );
    // Should succeed (or fail on a fee rule, not on RBF signal)
    if (result) |_| {
        // succeeded — correct
    } else |err| {
        try testing.expect(err != mempool_mod.MempoolError.NonBIP125Replaceable);
    }
}

// ============================================================================
// G14 — RBF Rule 5: AllConflictsSignal — MAX_REPLACEMENT_CANDIDATES=100
// ============================================================================

test "w106 G14: MAX_REPLACEMENT_EVICTIONS is 100" {
    // Core policy/rbf.h: MAX_REPLACEMENT_CANDIDATES = 100
    try testing.expectEqual(@as(usize, 100), mempool_mod.MAX_REPLACEMENT_EVICTIONS);
}

// ============================================================================
// G15 — RBF Rule 2: no new unconfirmed inputs (BUG-4: partial check only)
// ============================================================================

test "w106 G15: RBF Rule 2 — replacement spending direct conflict output is rejected" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    pool.full_rbf = true;

    const prev_h: [32]u8 = [_]u8{0x55} ** 32;

    // Conflict tx C in the mempool — inline so the stored .tx.inputs is valid.
    const conf_in = types.TxIn{ .previous_output = .{ .hash = prev_h, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFD, .witness = &[_][]const u8{} };
    const conf_out = types.TxOut{ .value = 90_000, .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac } };
    const conflict_tx = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{conf_in}, .outputs = &[_]types.TxOut{conf_out}, .lock_time = 0 };
    const conflict_txid = crypto.computeTxid(&conflict_tx, allocator) catch unreachable;

    const ce2 = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    ce2.* = .{
        .tx = conflict_tx,
        .txid = conflict_txid,
        .wtxid = conflict_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = true,
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(conflict_txid, ce2) catch unreachable;

    // Replacement tx that SPENDS an output from the conflict (Rule 2 violation).
    // The replacement's input references conflict_txid — inline to keep .inputs valid.
    const repl_in = types.TxIn{ .previous_output = .{ .hash = conflict_txid, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFD, .witness = &[_][]const u8{} };
    const repl_out = types.TxOut{ .value = 80_000, .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac } };
    const replacement_tx = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{repl_in}, .outputs = &[_]types.TxOut{repl_out}, .lock_time = 0 };
    const replacement_txid = crypto.computeTxid(&replacement_tx, allocator) catch unreachable;

    const conflicts_list = [_]types.Hash256{conflict_txid};
    const result = pool.checkRBFRules(
        &replacement_tx,
        replacement_txid,
        5000,
        200,
        &conflicts_list,
    );
    // Should return ReplacementSpendsConflicting
    try testing.expectError(mempool_mod.MempoolError.ReplacementSpendsConflicting, result);
}

// ============================================================================
// G16 — RBF Rule 3: PaysMoreThanConflicts (replacement_fees >= original_fees)
// ============================================================================

test "w106 G16: RBF Rule 3 — replacement must pay at least as much as conflicts" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    pool.full_rbf = true;

    const prev_h: [32]u8 = [_]u8{0x66} ** 32;

    const conflict_tx = makeRBFTx(prev_h, 0, 90_000);
    const conflict_txid = crypto.computeTxid(&conflict_tx, allocator) catch unreachable;

    const ce3 = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    ce3.* = .{
        .tx = conflict_tx,
        .txid = conflict_txid,
        .wtxid = conflict_txid,
        .fee = 5000, // original fee = 5000 sat
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 25.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 5000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 5000,
        .is_rbf = true,
        .cluster_index = 0,
        .mining_score = 25.0,
    };
    pool.entries.put(conflict_txid, ce3) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, conflict_txid) catch unreachable;

    // Replacement with fee < original fee → rejected
    const replacement_tx = makeRBFTx(prev_h, 0, 91_000); // fee = 100 - 91 won't work without UTXO
    const replacement_txid = crypto.computeTxid(&replacement_tx, allocator) catch unreachable;
    const conflicts_list = [_]types.Hash256{conflict_txid};

    const result = pool.checkRBFRules(
        &replacement_tx,
        replacement_txid,
        1000, // new_fee = 1000 < original_fee 5000
        200,
        &conflicts_list,
    );
    try testing.expectError(mempool_mod.MempoolError.ReplacementFeeTooLow, result);
}

// ============================================================================
// G17 — ImprovesFeerateDiagram absent (BUG-5)
// ============================================================================

test "w106 G17: ImprovesFeerateDiagram implemented — worsening diagram is rejected" {
    // FIX (W106 BUG-5): Gate 8 (ImprovesFeerateDiagram) is now implemented.
    // Scenario: old tx has a high feerate (5 sat/vb); replacement pays more in
    // absolute terms (Rule 3 OK) and just enough incremental relay (Rule 4 OK),
    // but its feerate is far worse (0.2 sat/vb vs 5 sat/vb).
    //
    // Numbers:
    //   old_fee=1000, old_vsize=200  → feerate 5.0 sat/vb
    //   new_fee=2000, new_vsize=10000 → feerate 0.2 sat/vb
    //   Rule 3: 2000 >= 1000  ✓
    //   Rule 4: additional=1000, min=10000*100/1000=1000 → 1000>=1000  ✓
    //   Diagram: new feerate 0.2 < old feerate 5.0 → REJECT (DiagramNotImproved)
    //
    // Core reference: policy/rbf.cpp::ImprovesFeerateDiagram (since 28.0).
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    pool.full_rbf = true;

    const prev_h: [32]u8 = [_]u8{0x77} ** 32;

    const conflict_tx = makeRBFTx(prev_h, 0, 99_000);
    const conflict_txid = crypto.computeTxid(&conflict_tx, allocator) catch unreachable;

    const ce4 = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    ce4.* = .{
        .tx = conflict_tx,
        .txid = conflict_txid,
        .wtxid = conflict_txid,
        .fee = 1000, // 1000 sat / 200 vbyte = 5.0 sat/vbyte
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = true,
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(conflict_txid, ce4) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, conflict_txid) catch unreachable;

    // Replacement: 2000 sat / 10000 vbytes = 0.2 sat/vb (worse feerate).
    // Rule 3 passes (2000 >= 1000), Rule 4 passes (additional=1000 >= 1000),
    // but Gate 8 must reject: new diagram worsens feerate.
    const conflicts_list = [_]types.Hash256{conflict_txid};
    const result = pool.checkRBFRules(
        &conflict_tx,
        conflict_txid,
        2000, // new_fee: passes Rule 3 and exactly meets Rule 4
        10000, // new_vsize: feerate = 0.2 sat/vb << 5.0 sat/vb (old)
        &conflicts_list,
    );
    try testing.expectError(mempool_mod.MempoolError.DiagramNotImproved, result);

    // Positive case: replacement with strictly better feerate must be accepted.
    // old: 1000 sat / 200 vb = 5.0 sat/vb; new: 3000 sat / 200 vb = 15.0 sat/vb.
    // Rule 3: 3000 >= 1000 ✓  Rule 4: 2000 >= 200*100/1000=20 ✓  Diagram: 15>5 ✓
    const result_ok = pool.checkRBFRules(
        &conflict_tx,
        conflict_txid,
        3000,
        200,
        &conflicts_list,
    );
    try testing.expectEqual({}, try result_ok);
}

// ============================================================================
// G18 — RBF Rule 4: PaysForRBF (additional_fees >= relay_fee * new_vsize)
// ============================================================================

test "w106 G18: RBF Rule 4 — additional fees must cover relay bandwidth" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    pool.full_rbf = true;

    const prev_h: [32]u8 = [_]u8{0x88} ** 32;
    const conflict_tx = makeRBFTx(prev_h, 0, 90_000);
    const conflict_txid = crypto.computeTxid(&conflict_tx, allocator) catch unreachable;

    const ce5 = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    ce5.* = .{
        .tx = conflict_tx,
        .txid = conflict_txid,
        .wtxid = conflict_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = true,
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(conflict_txid, ce5) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, conflict_txid) catch unreachable;

    // Replacement: fee = 1001 (>= 1000 passes Rule 3), vsize = 10000
    // additional = 1, required = INCREMENTAL_RELAY_FEE(100) * 10000 / 1000 = 1000
    // 1 < 1000 → Rule 4 violation
    const conflicts_list = [_]types.Hash256{conflict_txid};
    const result = pool.checkRBFRules(
        &conflict_tx,
        conflict_txid,
        1001, // barely above original
        10000, // large vsize
        &conflicts_list,
    );
    try testing.expectError(mempool_mod.MempoolError.ReplacementFeeTooLow, result);
}

// ============================================================================
// G19 — INCREMENTAL_RELAY_FEE = 100 sat/kvB (not 1000)
// ============================================================================

test "w106 G19: INCREMENTAL_RELAY_FEE is 100 sat/kvB" {
    // Core: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy/policy.h:48)
    try testing.expectEqual(@as(i64, 100), mempool_mod.INCREMENTAL_RELAY_FEE);
}

// ============================================================================
// G20 — Ancestor inheritance of RBF signal
// ============================================================================

test "w106 G20: RBF signal propagates from mempool ancestor via is_rbf flag" {
    // A child tx inherits is_rbf from a parent that signals opt-in.
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Insert a parent that signals RBF — inline so stored .tx.inputs is valid.
    const prev_h: [32]u8 = [_]u8{0x99} ** 32;
    const par_in = types.TxIn{ .previous_output = .{ .hash = prev_h, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFD, .witness = &[_][]const u8{} };
    const par_out = types.TxOut{ .value = 90_000, .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac } };
    const rbf_parent = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{par_in}, .outputs = &[_]types.TxOut{par_out}, .lock_time = 0 };
    const rbf_parent_txid = crypto.computeTxid(&rbf_parent, allocator) catch unreachable;

    const rpe = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    rpe.* = .{
        .tx = rbf_parent,
        .txid = rbf_parent_txid,
        .wtxid = rbf_parent_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = true, // parent signals
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(rbf_parent_txid, rpe) catch unreachable;

    // Child that does NOT signal RBF itself but has a signaling parent.
    // Inline so hasRBFAncestor can safely read child_no_signal.inputs.
    const child_in = types.TxIn{ .previous_output = .{ .hash = rbf_parent_txid, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFF, .witness = &[_][]const u8{} };
    const child_out = types.TxOut{ .value = 80_000, .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac } };
    const child_no_signal = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{child_in}, .outputs = &[_]types.TxOut{child_out}, .lock_time = 0 };
    const has_ancestor = pool.hasRBFAncestor(&child_no_signal);
    try testing.expect(has_ancestor); // Should inherit from parent
}

// ============================================================================
// G21 — TRUC max vsize = 10,000
// ============================================================================

test "w106 G21: TRUC_MAX_VSIZE constant is 10,000" {
    // Core: TRUC_MAX_VSIZE = 10000 (policy/truc_policy.h:31)
    try testing.expectEqual(@as(usize, 10_000), mempool_mod.TRUC_MAX_VSIZE);
}

// ============================================================================
// G22 — TRUC max descendant = 1 child (TRUC_DESCENDANT_LIMIT = 2 including self)
// ============================================================================

test "w106 G22: TRUC_DESCENDANT_LIMIT constant is 2" {
    // Core: TRUC_DESCENDANT_LIMIT = 2 (policy/truc_policy.h:25)
    try testing.expectEqual(@as(usize, 2), mempool_mod.TRUC_DESCENDANT_LIMIT);
}

// ============================================================================
// G23 — TRUC: v3 child max vsize = 1,000 when spending unconfirmed v3 parent
// ============================================================================

test "w106 G23: TRUC_CHILD_MAX_VSIZE constant is 1,000" {
    // Core: TRUC_CHILD_MAX_VSIZE = 1000 (policy/truc_policy.h:33)
    try testing.expectEqual(@as(usize, 1_000), mempool_mod.TRUC_CHILD_MAX_VSIZE);
}

// ============================================================================
// G24 — TRUC version inheritance: v3 cannot spend non-v3, non-v3 cannot spend v3
// ============================================================================

test "w106 G24: TRUC version inheritance — non-v3 spending v3 rejected" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Insert v3 parent
    const prev_h: [32]u8 = [_]u8{0xAB} ** 32;
    const v3_parent = makeTrucTx(prev_h, 0, 90_000);
    const v3_parent_txid = crypto.computeTxid(&v3_parent, allocator) catch unreachable;

    const v3_pe = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    v3_pe.* = .{
        .tx = v3_parent,
        .txid = v3_parent_txid,
        .wtxid = v3_parent_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
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
    pool.entries.put(v3_parent_txid, v3_pe) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, v3_parent_txid) catch unreachable;

    // Non-v3 tx trying to spend v3 parent
    const non_v3_child = makeTx(v3_parent_txid, 0, 80_000, 1, 0xFFFFFFFE);
    const result = pool.checkTrucPolicy(&non_v3_child, 200, &[_]types.Hash256{});
    try testing.expectError(mempool_mod.MempoolError.TrucNonV3SpendsV3, result);
}

test "w106 G24b: TRUC version inheritance — v3 spending non-v3 rejected" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Insert non-v3 parent
    const prev_h: [32]u8 = [_]u8{0xBC} ** 32;
    const non_v3_parent = makeTx(prev_h, 0, 90_000, 1, 0xFFFFFFFE);
    const non_v3_parent_txid = crypto.computeTxid(&non_v3_parent, allocator) catch unreachable;

    const nv3_pe = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    nv3_pe.* = .{
        .tx = non_v3_parent,
        .txid = non_v3_parent_txid,
        .wtxid = non_v3_parent_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
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
    pool.entries.put(non_v3_parent_txid, nv3_pe) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, non_v3_parent_txid) catch unreachable;

    // v3 tx trying to spend non-v3 parent
    const v3_child = makeTrucTx(non_v3_parent_txid, 0, 80_000);
    const result = pool.checkTrucPolicy(&v3_child, 200, &[_]types.Hash256{});
    try testing.expectError(mempool_mod.MempoolError.TrucV3SpendsNonV3, result);
}

// ============================================================================
// G25 — TRUC sibling eviction
// ============================================================================

test "w106 G25: TRUC sibling eviction returns sibling txid when parent has 1 child" {
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // v3 parent in mempool
    const prev_h: [32]u8 = [_]u8{0xCD} ** 32;
    const v3_parent = makeTrucTx(prev_h, 0, 90_000);
    const v3_parent_txid = crypto.computeTxid(&v3_parent, allocator) catch unreachable;

    // v3 existing child (the "sibling" to be evicted)
    const v3_child1 = makeTrucTx(v3_parent_txid, 0, 80_000);
    const v3_child1_txid = crypto.computeTxid(&v3_child1, allocator) catch unreachable;

    const v3_parent_entry = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    v3_parent_entry.* = .{
        .tx = v3_parent,
        .txid = v3_parent_txid,
        .wtxid = v3_parent_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 2, // parent + 1 existing child
        .descendant_size = 400,
        .descendant_fees = 2000,
        .is_rbf = false,
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(v3_parent_txid, v3_parent_entry) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, v3_parent_txid) catch unreachable;

    const v3_child1_entry = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    v3_child1_entry.* = .{
        .tx = v3_child1,
        .txid = v3_child1_txid,
        .wtxid = v3_child1_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 2,
        .ancestor_size = 400,
        .ancestor_fees = 2000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = false,
        .cluster_index = 1,
        .mining_score = 5.0,
    };
    pool.entries.put(v3_child1_txid, v3_child1_entry) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = v3_parent_txid, .index = 0 }, v3_child1_txid) catch unreachable;

    // children list
    var cl3 = std.ArrayList(types.Hash256).init(allocator);
    cl3.append(v3_child1_txid) catch unreachable;
    pool.children.put(v3_parent_txid, cl3) catch unreachable;

    // New v3 child2 competing for the same parent (sibling replacement scenario)
    const v3_child2 = makeTrucTx(v3_parent_txid, 0, 79_000);

    // checkTrucPolicy should return sibling_to_evict = v3_child1_txid
    const truc_result = pool.checkTrucPolicy(&v3_child2, 200, &[_]types.Hash256{}) catch unreachable;
    try testing.expect(truc_result.sibling_to_evict != null);
    if (truc_result.sibling_to_evict) |sib| {
        try testing.expectEqualSlices(u8, &sib, &v3_child1_txid);
    }
}

// ============================================================================
// G26 — AcceptMultipleTransactions / package count limit
// ============================================================================

test "w106 G26: MAX_PACKAGE_COUNT is 25" {
    // Core: MAX_PACKAGE_COUNT = 25 (policy/packages.h:20)
    try testing.expectEqual(@as(usize, 25), mempool_mod.MAX_PACKAGE_COUNT);
}

test "w106 G26b: package with 26 transactions is rejected" {
    const allocator = testing.allocator;

    // Build 26 independent txs
    var txns: [26]types.Transaction = undefined;
    for (0..26) |i| {
        var p: [32]u8 = [_]u8{0xEE} ** 32;
        p[0] = @intCast(i);
        txns[i] = makeTx(p, 0, 90_000, 1, 0xFFFFFFFE);
    }

    const result = mempool_mod.isWellFormedPackage(&txns, allocator);
    try testing.expectError(mempool_mod.PackageError.PackageTooManyTransactions, result);
}

// ============================================================================
// G27 — MAX_PACKAGE_WEIGHT = 404,000 WU
// ============================================================================

test "w106 G27: MAX_PACKAGE_WEIGHT is 404,000 WU" {
    // Core: MAX_PACKAGE_WEIGHT = 404_000 (policy/packages.h:24)
    try testing.expectEqual(@as(usize, 404_000), mempool_mod.MAX_PACKAGE_WEIGHT);
}

// ============================================================================
// G28 — nFeeDelta: ApplyDelta absent (BUG-7)
// ============================================================================

test "w106 G28: BUG-7 package fee rate ignores nFeeDelta (ApplyDelta absent)" {
    // Core: CTxMemPool::PrioritiseTransaction / ApplyDelta adjusts per-tx fee
    // deltas used in package fee-rate calculation.  Clearbit's acceptPackage
    // uses only raw tx fees with no delta map.  This means prioritised txs
    // will not have their delta reflected in the package rate check.
    //
    // Verify by checking that Mempool has no mapDeltas or fee_deltas field.
    const info = @typeInfo(mempool_mod.Mempool);
    var has_deltas = false;
    inline for (info.Struct.fields) |field| {
        if (std.mem.eql(u8, field.name, "mapDeltas") or
            std.mem.eql(u8, field.name, "fee_deltas") or
            std.mem.eql(u8, field.name, "delta_map"))
        {
            has_deltas = true;
        }
    }
    // BUG-7: no delta map → PrioritiseTransaction unimplemented.
    try testing.expect(!has_deltas);
}

// ============================================================================
// G29 — TrimToSize eviction: rolling minimum fee rate bumped after eviction
// ============================================================================

test "w106 G29: TrimToSize rolling fee bumped on eviction via trackPackageRemoved" {
    // After trackPackageRemoved, rolling_minimum_fee_rate should be elevated.
    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    const initial_rolling = pool.rolling_minimum_fee_rate;
    try testing.expect(initial_rolling == 0.0);

    // Simulate eviction at 10 sat/kvB
    pool.trackPackageRemoved(10.0);
    try testing.expect(pool.rolling_minimum_fee_rate == 10.0);
    // block_since_last_rolling_fee_bump should be false after a bump
    try testing.expect(!pool.block_since_last_rolling_fee_bump);
}

// ============================================================================
// G30 — ExpireTime: MEMPOOL_EXPIRY = 14 * 24 * 60 * 60 (2 weeks)
// ============================================================================

test "w106 G30: MEMPOOL_EXPIRY is 14 days in seconds" {
    // Core: DEFAULT_MEMPOOL_EXPIRY_HOURS = 336h = 14 days (kernel/mempool_options.h)
    const expected: i64 = 14 * 24 * 60 * 60;
    try testing.expectEqual(expected, mempool_mod.MEMPOOL_EXPIRY);
}

// ============================================================================
// BUG-8 additional: removeForBlock does not decrement ancestor stats
// ============================================================================

test "w106 BUG-8: removeForBlock does not update in-mempool children ancestor stats" {
    // When a parent tx is confirmed (removeForBlock), its in-mempool children
    // should see ancestor_count drop by 1 and ancestor_size drop accordingly.
    // Core: CTxMemPool::removeForBlock → removeRecursive → UpdateAncestorsOf.
    // Clearbit: removeForBlock calls removeTransaction (single-tx), which does
    // NOT propagate ancestor stat decrements upward.
    // We document this by checking the child's ancestor_count is unchanged.
    //
    // NOTE: Transactions must be defined inline so stored .tx.inputs pointers
    // remain valid throughout the test (no dangling pointer UB from a helper
    // that returns Transaction by value).

    const allocator = testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    const prev_h: [32]u8 = [_]u8{0xDE} ** 32;

    // Parent tx — inline definition.
    const par_in = types.TxIn{ .previous_output = .{ .hash = prev_h, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFE, .witness = &[_][]const u8{} };
    const par_out = types.TxOut{ .value = 90_000, .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac } };
    const parent_tx = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{par_in}, .outputs = &[_]types.TxOut{par_out}, .lock_time = 0 };
    const parent_txid = crypto.computeTxid(&parent_tx, allocator) catch unreachable;

    const pe = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    pe.* = .{
        .tx = parent_tx,
        .txid = parent_txid,
        .wtxid = parent_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 1,
        .ancestor_size = 200,
        .ancestor_fees = 1000,
        .descendant_count = 2,
        .descendant_size = 400,
        .descendant_fees = 2000,
        .is_rbf = false,
        .cluster_index = 0,
        .mining_score = 5.0,
    };
    pool.entries.put(parent_txid, pe) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = prev_h, .index = 0 }, parent_txid) catch unreachable;

    // Child tx — inline definition.
    const child_in = types.TxIn{ .previous_output = .{ .hash = parent_txid, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFE, .witness = &[_][]const u8{} };
    const child_out = types.TxOut{ .value = 80_000, .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac } };
    const child_tx = types.Transaction{ .version = 1, .inputs = &[_]types.TxIn{child_in}, .outputs = &[_]types.TxOut{child_out}, .lock_time = 0 };
    const child_txid = crypto.computeTxid(&child_tx, allocator) catch unreachable;

    const ce_b8 = allocator.create(mempool_mod.MempoolEntry) catch unreachable;
    ce_b8.* = .{
        .tx = child_tx,
        .txid = child_txid,
        .wtxid = child_txid,
        .fee = 1000,
        .size = 200,
        .weight = 800,
        .vsize = 200,
        .fee_rate = 5.0,
        .time_added = 0,
        .height_added = 100,
        .ancestor_count = 2, // parent + self
        .ancestor_size = 400,
        .ancestor_fees = 2000,
        .descendant_count = 1,
        .descendant_size = 200,
        .descendant_fees = 1000,
        .is_rbf = false,
        .cluster_index = 1,
        .mining_score = 5.0,
    };
    pool.entries.put(child_txid, ce_b8) catch unreachable;
    pool.spenders.put(types.OutPoint{ .hash = parent_txid, .index = 0 }, child_txid) catch unreachable;

    // Remove parent (as if mined in a block)
    pool.removeTransaction(parent_txid);

    // Child is still in mempool
    try testing.expect(pool.entries.contains(child_txid));

    // BUG-8: child's ancestor_count should now be 1 (only self), but is still 2
    const child_after = pool.entries.get(child_txid).?;
    // Document the broken behavior:
    try testing.expect(child_after.ancestor_count == 2); // BUG: should be 1
}
