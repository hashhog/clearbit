//! Mempool time-lock fix — tests of the NEW API (ChainState.mtpAtActiveHeight /
//! rewindMtpRingAfterDisconnect / tipMtp, Mempool.removeForReorg).  The
//! base-comparable half (fail on e1753e4, pass on the fix) is
//! tests_mtp_bip68.zig; the fail-before evidence for the reorg eviction is the
//! process harness (invalidateblock on regtest) recorded in the receipt.
//!
//! Core reference for the eviction predicate: validation.cpp
//! MaybeUpdateMempoolForReorg → filter_final_and_mature (CheckFinalTxAtTip,
//! CheckSequenceLocksAtTip on recomputed lock points, coinbase maturity at
//! tip+1), removing the entry and all its descendants.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const base = @import("tests_mtp_bip68.zig");

const Mempool = mempool_mod.Mempool;
const TIP = base.TIP;
const TYPE_FLAG: u32 = consensus.SEQUENCE_LOCKTIME_TYPE_FLAG;
const P2WPKH_OUT = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCD} ** 20;

/// Disconnect the tip of the DB-less fixture the way the real disconnect
/// paths do: step best_hash / best_height back, then rewind the ring.
fn simulateDisconnect(cs: *storage.ChainState) void {
    cs.best_height -= 1;
    cs.best_hash = [_]u8{@truncate(cs.best_height)} ** 32;
    cs.rewindMtpRingAfterDisconnect();
}

test "mtp-fix: mtpAtActiveHeight answers MTP(h) from the active chain; tipMtp == MTP(tip)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    base.setupChain(&cs);
    try testing.expectEqual(base.mtpOf(TIP), cs.tipMtp());
    try testing.expectEqual(base.mtpOf(TIP - 21), cs.mtpAtActiveHeight(TIP - 21).?);
    // Above the tip / outside the resolvable window → null (never a guess).
    try testing.expect(cs.mtpAtActiveHeight(TIP + 1) == null);
    try testing.expect(cs.mtpAtActiveHeight(TIP - 55) == null);
}

test "mtp-fix: rewindMtpRingAfterDisconnect rebuilds the window of the new tip" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    base.setupChain(&cs);
    simulateDisconnect(&cs);
    try testing.expectEqual(base.mtpOf(TIP - 1), cs.computeMTP());
    try testing.expect(cs.mtpRingCoversTip());
    simulateDisconnect(&cs);
    try testing.expectEqual(base.mtpOf(TIP - 2), cs.computeMTP());
}

test "mtp-fix: unresolvable window after a disconnect → ring drops the old tip slot, tipMtp fails closed (0)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    // Ring only — no retarget-ring / DB history to rebuild from.
    cs.best_height = TIP;
    var i: u32 = 0;
    while (i < 11) : (i += 1) cs.recent_timestamps[i] = base.tsAt(TIP - i);
    cs.recent_ts_count = 11;
    cs.best_height -= 1;
    cs.rewindMtpRingAfterDisconnect();
    try testing.expectEqual(@as(u32, 10), cs.recent_ts_count);
    try testing.expectEqual(base.tsAt(TIP - 1), cs.recent_timestamps[0]);
    try testing.expect(!cs.mtpRingCoversTip());
    try testing.expectEqual(@as(u32, 0), cs.tipMtp());
}

const Fx = struct {
    cs: storage.ChainState,
    pool: Mempool,
    wsh: [34]u8,
};

fn accept(pool: *Mempool, tx: types.Transaction) !types.Hash256 {
    const r = pool.acceptToMemoryPool(tx, false);
    if (!r.accepted) std.debug.print("unexpected reject: {s}\n", .{r.reject_reason orelse "?"});
    try testing.expect(r.accepted);
    return r.txid;
}

test "mtp-fix: removeForReorg evicts txs no longer final at the new tip (nLockTime height, BIP-68 height + time) with descendants; final txs stay" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    base.setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();
    const wsh = base.opTrueP2wsh();

    // (1) nLockTime = TIP: final at TIP+1, not at TIP.  Its child must go too.
    const c1 = try base.addCoin(&cs, 0x51, TIP - 300, &wsh);
    var ib1: [1]types.TxIn = undefined;
    var ob1: [1]types.TxOut = undefined;
    const t1 = try accept(&pool, base.spend(c1, 0xFFFF_FFFE, TIP, 95_000, &wsh, &ib1, &ob1));
    var ib1c: [1]types.TxIn = undefined;
    var ob1c: [1]types.TxOut = undefined;
    const t1c = try accept(&pool, base.spend(.{ .hash = t1, .index = 0 }, 0xFFFF_FFFF, 0, 90_000, &P2WPKH_OUT, &ib1c, &ob1c));

    // (2) relative HEIGHT lock just matured: coin at TIP-20, lock 21.
    const c2 = try base.addCoin(&cs, 0x52, TIP - 20, &wsh);
    var ib2: [1]types.TxIn = undefined;
    var ob2: [1]types.TxOut = undefined;
    const t2 = try accept(&pool, base.spend(c2, 21, 0, 90_000, &P2WPKH_OUT, &ib2, &ob2));

    // (3) relative TIME lock with 312 s of slack at TIP (12288 of 12600 s):
    //     after one disconnect the slack is 12000 s < 12288 → not final.
    const c3 = try base.addCoin(&cs, 0x53, TIP - 20, &wsh);
    var ib3: [1]types.TxIn = undefined;
    var ob3: [1]types.TxOut = undefined;
    const t3 = try accept(&pool, base.spend(c3, TYPE_FLAG | 24, 0, 90_000, &P2WPKH_OUT, &ib3, &ob3));

    // Controls that stay final after one disconnect: no locks; a height lock
    // with slack; a time lock with slack (16 units = 8192 s < 12000 s).
    const c4 = try base.addCoin(&cs, 0x54, TIP - 300, &wsh);
    var ib4: [1]types.TxIn = undefined;
    var ob4: [1]types.TxOut = undefined;
    const t4 = try accept(&pool, base.spend(c4, 0xFFFF_FFFF, 0, 90_000, &P2WPKH_OUT, &ib4, &ob4));
    const c5 = try base.addCoin(&cs, 0x55, TIP - 20, &wsh);
    var ib5: [1]types.TxIn = undefined;
    var ob5: [1]types.TxOut = undefined;
    const t5 = try accept(&pool, base.spend(c5, 10, 0, 90_000, &P2WPKH_OUT, &ib5, &ob5));
    const c6 = try base.addCoin(&cs, 0x56, TIP - 20, &wsh);
    var ib6: [1]types.TxIn = undefined;
    var ob6: [1]types.TxOut = undefined;
    const t6 = try accept(&pool, base.spend(c6, TYPE_FLAG | 16, 0, 90_000, &P2WPKH_OUT, &ib6, &ob6));

    try testing.expectEqual(@as(usize, 7), pool.entries.count());
    // No-op at the unchanged tip (negative control for the predicate).
    try testing.expectEqual(@as(usize, 0), pool.removeForReorg());

    simulateDisconnect(&cs);
    const removed = pool.removeForReorg();
    try testing.expectEqual(@as(usize, 4), removed);
    try testing.expect(!pool.entries.contains(t1));
    try testing.expect(!pool.entries.contains(t1c));
    try testing.expect(!pool.entries.contains(t2));
    try testing.expect(!pool.entries.contains(t3));
    try testing.expect(pool.entries.contains(t4));
    try testing.expect(pool.entries.contains(t5));
    try testing.expect(pool.entries.contains(t6));
}

test "mtp-fix: removeForReorg evicts a coinbase spend that is immature at the new tip and a tx whose input vanished" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    base.setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();
    const wsh = base.opTrueP2wsh();

    // Coinbase at TIP-100: spendable at TIP+1 (age 101 ≥ 100 under clearbit's
    // admission rule); after TWO disconnects the next block is TIP-1 → age 99.
    const cb_op = types.OutPoint{ .hash = [_]u8{0x61} ** 32, .index = 0 };
    const cb_out = types.TxOut{ .value = 100_000, .script_pubkey = &wsh };
    try cs.utxo_set.add(&cb_op, &cb_out, TIP - 100, true);
    var ib1: [1]types.TxIn = undefined;
    var ob1: [1]types.TxOut = undefined;
    const t1 = try accept(&pool, base.spend(cb_op, 0xFFFF_FFFF, 0, 90_000, &P2WPKH_OUT, &ib1, &ob1));

    const c2 = try base.addCoin(&cs, 0x62, TIP - 300, &wsh);
    var ib2: [1]types.TxIn = undefined;
    var ob2: [1]types.TxOut = undefined;
    const t2 = try accept(&pool, base.spend(c2, 0xFFFF_FFFF, 0, 90_000, &P2WPKH_OUT, &ib2, &ob2));

    simulateDisconnect(&cs);
    try testing.expectEqual(@as(usize, 0), pool.removeForReorg()); // next=TIP: age 100, mature
    simulateDisconnect(&cs);
    // The coin t2 spends was spent by the new branch.
    if (try cs.utxo_set.spend(&c2)) |u| {
        var m = u;
        m.deinit(allocator);
    }
    try testing.expectEqual(@as(usize, 2), pool.removeForReorg());
    try testing.expect(!pool.entries.contains(t1));
    try testing.expect(!pool.entries.contains(t2));
}
