//! A replacement refused by a gate that runs after the RBF rules must leave
//! the mempool untouched: the txs it conflicts with (and their descendants)
//! are evicted only once every gate has passed.
//!
//! Run via `zig build test-rbf-evict-after-gates` (also part of `zig build test`).
//!
//! Core v31.1 MemPoolAccept (validation.cpp) stages the conflicts' removal in
//! `m_subpackage.m_changeset` (StageRemoval in ReplacementChecks) and applies
//! it only in Finalize (`m_subpackage.m_changeset->Apply()`), after PreChecks
//! (IsStandardTx incl. dust, SingleTRUCChecks), ReplacementChecks, the
//! cluster limit check and the script checks have all passed. A rejection at
//! any of those leaves the pool as it was.
//!
//! clearbit used to call removeTransactionWithDescendants for every conflict
//! right after checkRBFRules, before the TRUC, cluster and dust gates, so a
//! replacement that paid the RBF fee but was then refused (e.g. a dust
//! output) still wiped out the original and its CPFP child.

const std = @import("std");
const testing = std.testing;

const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

const MempoolError = mempool_mod.MempoolError;

const COIN_VALUE: i64 = 1_000_000;
const PARENT_FEE: i64 = 2_000;
const CHILD_FEE: i64 = 2_000;
/// Far above PARENT_FEE + CHILD_FEE + incremental relay on R's size, so R
/// clears every RBF rule (Core rules 3/4 and the feerate diagram).
const REPLACEMENT_FEE: i64 = 100_000;
const DUST_VALUE: i64 = 100; // P2SH dust threshold is 540 sat

const REDEEM_TRUE = [_]u8{0x51}; // OP_TRUE
const SIG_TRUE = [_]u8{ 0x01, 0x51 };
const PREV = [_]u8{0x42} ** 32;

fn p2shTrue(a: std.mem.Allocator) ![]const u8 {
    const h = crypto.hash160(&REDEEM_TRUE);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

/// Spend `prev` into `n_out` P2SH(OP_TRUE) outputs paying `fee`; when
/// `dust` is set, one extra output of DUST_VALUE is added. BIP125-signalling.
fn spend(a: std.mem.Allocator, version: i32, prev: types.OutPoint, in_value: i64, fee: i64, n_out: usize, dust: bool) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = prev,
        .script_sig = &SIG_TRUE,
        .sequence = 0xFFFFFFFD,
        .witness = &.{},
    };
    const spk = try p2shTrue(a);
    const n_total = n_out + @as(usize, if (dust) 1 else 0);
    const outs = try a.alloc(types.TxOut, n_total);
    const spendable = in_value - fee - (if (dust) DUST_VALUE else 0);
    const each = @divTrunc(spendable, @as(i64, @intCast(n_out)));
    for (outs[0..n_out], 0..) |*o, i| {
        const extra: i64 = if (i == 0) spendable - each * @as(i64, @intCast(n_out)) else 0;
        o.* = .{ .value = each + extra, .script_pubkey = spk };
    }
    if (dust) outs[n_out] = .{ .value = DUST_VALUE, .script_pubkey = spk };
    return .{ .version = version, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

const Rig = struct {
    mp: *mempool_mod.Mempool,
    a_txid: types.Hash256,
    c_txid: types.Hash256,
};

/// A chain holding PREV:0 (P2SH(OP_TRUE), not a coinbase) and a pool holding
/// parent A (spends PREV:0, opt-in RBF) and its CPFP child C (spends A:0).
fn rig(a: std.mem.Allocator) !Rig {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const out = types.TxOut{ .value = COIN_VALUE, .script_pubkey = try p2shTrue(a) };
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    try cs.utxo_set.add(&op, &out, 799_000, false);

    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);

    const tx_a = try spend(a, 2, op, COIN_VALUE, PARENT_FEE, 1, false);
    try mp.addTransaction(tx_a);
    const a_txid = try crypto.computeTxid(&tx_a, a);

    const tx_c = try spend(a, 2, .{ .hash = a_txid, .index = 0 }, COIN_VALUE - PARENT_FEE, CHILD_FEE, 1, false);
    try mp.addTransaction(tx_c);
    const c_txid = try crypto.computeTxid(&tx_c, a);

    try testing.expectEqual(@as(usize, 2), mp.entries.count());
    return .{ .mp = mp, .a_txid = a_txid, .c_txid = c_txid };
}

fn expectOriginalsKept(r: Rig) !void {
    try testing.expectEqual(@as(usize, 2), r.mp.entries.count());
    try testing.expect(r.mp.entries.get(r.a_txid) != null);
    try testing.expect(r.mp.entries.get(r.c_txid) != null);
    // A's outpoint is still owned by A, and C is still A's descendant.
    try testing.expect(std.mem.eql(u8, &r.mp.spenders.get(.{ .hash = PREV, .index = 0 }).?, &r.a_txid));
    try testing.expectEqual(@as(usize, 2), r.mp.entries.get(r.a_txid).?.descendant_count);
}

const PREV_OP = types.OutPoint{ .hash = PREV, .index = 0 };

test "tests_rbf_evict_after_gates addTransaction: a replacement with a dust output is rejected and A + its CPFP child stay" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const replacement = try spend(a, 2, PREV_OP, COIN_VALUE, REPLACEMENT_FEE, 1, true);
    try testing.expectError(MempoolError.DustOutput, r.mp.addTransaction(replacement));
    try expectOriginalsKept(r);
}

test "tests_rbf_evict_after_gates package path: a replacement with a dust output is rejected and A + its CPFP child stay" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const replacement = try spend(a, 2, PREV_OP, COIN_VALUE, REPLACEMENT_FEE, 1, true);
    try testing.expectError(MempoolError.DustOutput, r.mp.addTransactionWithPackageRate(replacement, 100.0));
    try expectOriginalsKept(r);
}

test "tests_rbf_evict_after_gates addTransaction: a replacement refused by the TRUC gate leaves A + its CPFP child" {
    // R is v3 and over TRUC_MAX_VSIZE (10,000 vB): checkTrucPolicy refuses it
    // after checkRBFRules has passed.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const replacement = try spend(a, 3, PREV_OP, COIN_VALUE, REPLACEMENT_FEE * 3, 330, false);
    try testing.expectError(MempoolError.TrucTxTooLarge, r.mp.addTransaction(replacement));
    try expectOriginalsKept(r);
}

test "tests_rbf_evict_after_gates control: the same replacement without the dust output evicts A and C" {
    // Proves the rejections above come from the dust/TRUC gate after the RBF
    // rules passed, not from the RBF rules themselves.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const replacement = try spend(a, 2, PREV_OP, COIN_VALUE, REPLACEMENT_FEE, 1, false);
    try r.mp.addTransaction(replacement);
    const r_txid = try crypto.computeTxid(&replacement, a);
    try testing.expectEqual(@as(usize, 1), r.mp.entries.count());
    try testing.expect(r.mp.entries.get(r_txid) != null);
    try testing.expect(r.mp.entries.get(r.a_txid) == null);
    try testing.expect(r.mp.entries.get(r.c_txid) == null);
    // R records both evicted txs (direct conflict A + its descendant C).
    try testing.expectEqual(@as(usize, 2), r.mp.entries.get(r_txid).?.replaces.?.len);
}

test "tests_rbf_evict_after_gates control: the v3 replacement under the TRUC size limit evicts A and C" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const replacement = try spend(a, 3, PREV_OP, COIN_VALUE, REPLACEMENT_FEE * 3, 2, false);
    try r.mp.addTransaction(replacement);
    try testing.expectEqual(@as(usize, 1), r.mp.entries.count());
    try testing.expect(r.mp.entries.get(r.a_txid) == null);
    try testing.expect(r.mp.entries.get(r.c_txid) == null);
}
