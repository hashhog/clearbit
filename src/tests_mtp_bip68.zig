//! Mempool time-lock (BIP-113 nLockTime / BIP-68 relative lock) tests —
//! 2026-10-05 fleet sweep (QUEUES.md "FLEET SWEEP — mempool MTP / BIP68",
//! clearbit item).  BASE-COMPARABLE: only APIs that exist on the deployed
//! commit e1753e4 are used (Mempool.addTransaction / acceptToMemoryPool,
//! ChainState.connectBlockFastWithUndo / disconnectBlockByHashCF /
//! reorgToChain / computeMTP), so every test compiles on both trees and can
//! be shown to FAIL before the fix and PASS after.
//!
//! Core references:
//!   validation.cpp CheckFinalTxAtTip        — nLockTime vs tip MTP at tip+1
//!   validation.cpp CalculateLockPointsAtTip — mempool coin → tip+1
//!   consensus/tx_verify.cpp CalculateSequenceLocks — confirmed coin time =
//!       GetAncestor(max(nCoinHeight-1,0))->GetMedianTimePast()
//!   validation.cpp CheckSequenceLocksAtTip  — evaluated at tip+1, prev MTP = tip MTP
//!
//! Controls (must pass on BOTH trees): a lock one unit too long is still
//! refused; nLockTime == tip MTP is still non-final; a relative height lock
//! of 1 on a MEMPOOL parent is refused (clearbit already used tip+1 there);
//! a zero relative lock on a mempool parent is accepted.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");
const mempool_mod = @import("mempool.zig");
const validation = @import("validation.zig");

const Mempool = mempool_mod.Mempool;
const MempoolError = mempool_mod.MempoolError;

// ----------------------------------------------------------------------------
// Fixture: a DB-less chain at mainnet height TIP (CSV active) whose last 60
// blocks are spaced 600 s apart.  MTP(h) = median of ts(h-10..h) = ts(h-5).
// ----------------------------------------------------------------------------

pub const TIP: u32 = 800_000;
const T0: u32 = 1_700_000_000;
const FIRST: u32 = TIP - 60;

pub fn tsAt(h: u32) u32 {
    return T0 + 600 * (h - FIRST);
}

/// MTP OF the block at height h (h >= FIRST + 10).
pub fn mtpOf(h: u32) u32 {
    return tsAt(h - 5);
}

pub fn setupChain(cs: *storage.ChainState) void {
    cs.best_height = TIP;
    cs.best_hash = [_]u8{0xB7} ** 32;
    var h: u32 = FIRST;
    while (h <= TIP) : (h += 1) cs.recordRetargetEntry(h, tsAt(h), 0x1d00ffff);
    var i: u32 = 0;
    while (i < 11) : (i += 1) cs.recent_timestamps[i] = tsAt(TIP - i);
    cs.recent_ts_count = 11;
}

/// P2WSH(OP_TRUE): spendable with witness [OP_TRUE], standard, no signature.
pub fn opTrueP2wsh() [34]u8 {
    var out: [34]u8 = undefined;
    out[0] = 0x00;
    out[1] = 0x20;
    std.crypto.hash.sha2.Sha256.hash(&[_]u8{0x51}, out[2..34], .{});
    return out;
}

const OP_TRUE_WITNESS_ITEM = [_]u8{0x51};
pub const op_true_witness = [_][]const u8{&OP_TRUE_WITNESS_ITEM};

const P2WPKH_OUT = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCC} ** 20;

pub fn addCoin(cs: *storage.ChainState, tag: u8, height: u32, script: []const u8) !types.OutPoint {
    const op = types.OutPoint{ .hash = [_]u8{tag} ** 32, .index = 0 };
    const out = types.TxOut{ .value = 100_000, .script_pubkey = script };
    try cs.utxo_set.add(&op, &out, height, false);
    return op;
}

/// Build a one-in one-out v2 spend of `prev` (an OP_TRUE P2WSH coin).
/// `in_buf` / `out_buf` are caller storage so the returned slices stay valid.
pub fn spend(
    prev: types.OutPoint,
    sequence: u32,
    lock_time: u32,
    value: i64,
    out_script: []const u8,
    in_buf: *[1]types.TxIn,
    out_buf: *[1]types.TxOut,
) types.Transaction {
    in_buf[0] = .{
        .previous_output = prev,
        .script_sig = &[_]u8{},
        .sequence = sequence,
        .witness = &op_true_witness,
    };
    out_buf[0] = .{ .value = value, .script_pubkey = out_script };
    return .{ .version = 2, .inputs = in_buf, .outputs = out_buf, .lock_time = lock_time };
}

const TYPE_FLAG: u32 = consensus.SEQUENCE_LOCKTIME_TYPE_FLAG;

// Coin confirmed at C = TIP - 20.  nCoinTime = MTP(C-1) = ts(C-6); tip MTP =
// ts(TIP-5).  Slack = (TIP-5 - (C-6)) * 600 = 21 * 600 = 12600 s.
// A lock of 24 units (12288 s) is satisfied: 12288 - 1 < 12600.
// A lock of 25 units (12800 s) is not.
const COIN_H: u32 = TIP - 20;

test "mtp-bip68: matured TIME-type relative lock on a CONFIRMED coin is ACCEPTED (coin time = MTP(coinHeight-1), not tip MTP)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();

    const wsh = opTrueP2wsh();
    const coin = try addCoin(&cs, 0x31, COIN_H, &wsh);
    var ib: [1]types.TxIn = undefined;
    var ob: [1]types.TxOut = undefined;
    const tx = spend(coin, TYPE_FLAG | 24, 0, 90_000, &P2WPKH_OUT, &ib, &ob);

    // testmempoolaccept (dry run) must agree with sendrawtransaction.
    const dry = pool.acceptToMemoryPool(tx, true);
    if (!dry.accepted) std.debug.print("dry-run rejected: {s}\n", .{dry.reject_reason orelse "?"});
    try testing.expect(dry.accepted);
    const res = pool.acceptToMemoryPool(tx, false);
    if (!res.accepted) std.debug.print("rejected: {s}\n", .{res.reject_reason orelse "?"});
    try testing.expect(res.accepted);
    try testing.expectEqual(@as(usize, 1), pool.entries.count());
}

test "mtp-bip68: CONTROL — a time lock one unit too long on a confirmed coin is REJECTED non-BIP68-final" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();

    const wsh = opTrueP2wsh();
    const coin = try addCoin(&cs, 0x32, COIN_H, &wsh);
    var ib: [1]types.TxIn = undefined;
    var ob: [1]types.TxOut = undefined;
    const tx = spend(coin, TYPE_FLAG | 25, 0, 90_000, &P2WPKH_OUT, &ib, &ob);
    const res = pool.acceptToMemoryPool(tx, false);
    try testing.expect(!res.accepted);
    try testing.expectEqualStrings("non-BIP68-final", res.reject_reason.?);
}

test "mtp-bip68: CONTROL — matured HEIGHT-type relative lock on a confirmed coin is ACCEPTED, one block short REJECTED" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();

    const wsh = opTrueP2wsh();
    const coin = try addCoin(&cs, 0x33, COIN_H, &wsh);
    var ib: [1]types.TxIn = undefined;
    var ob: [1]types.TxOut = undefined;
    // Next block = TIP+1; coin at TIP-20 → 21 confirmations then. Lock 22 fails, 21 passes.
    const bad = spend(coin, 22, 0, 90_000, &P2WPKH_OUT, &ib, &ob);
    const r1 = pool.acceptToMemoryPool(bad, false);
    try testing.expect(!r1.accepted);
    try testing.expectEqualStrings("non-BIP68-final", r1.reject_reason.?);
    var ib2: [1]types.TxIn = undefined;
    var ob2: [1]types.TxOut = undefined;
    const good = spend(coin, 21, 0, 90_000, &P2WPKH_OUT, &ib2, &ob2);
    const r2 = pool.acceptToMemoryPool(good, false);
    try testing.expect(r2.accepted);
}

/// Put a parent (spending a deep confirmed coin) into the mempool and return
/// its txid; its output 0 is an OP_TRUE P2WSH coin the child can spend.
fn addMempoolParent(pool: *Mempool, cs: *storage.ChainState, tag: u8, wsh: []const u8, ib: *[1]types.TxIn, ob: *[1]types.TxOut) !types.Hash256 {
    const coin = try addCoin(cs, tag, TIP - 200, wsh);
    const parent = spend(coin, 0xFFFF_FFFF, 0, 95_000, wsh, ib, ob);
    const r = pool.acceptToMemoryPool(parent, false);
    if (!r.accepted) std.debug.print("parent rejected: {s}\n", .{r.reject_reason orelse "?"});
    try testing.expect(r.accepted);
    return r.txid;
}

test "mtp-bip68: child of an UNCONFIRMED parent with a relative HEIGHT lock of 1 is REJECTED non-BIP68-final (coin height = tip+1)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();

    const wsh = opTrueP2wsh();
    var pib: [1]types.TxIn = undefined;
    var pob: [1]types.TxOut = undefined;
    const ptxid = try addMempoolParent(&pool, &cs, 0x41, &wsh, &pib, &pob);
    const pout = types.OutPoint{ .hash = ptxid, .index = 0 };

    var ib: [1]types.TxIn = undefined;
    var ob: [1]types.TxOut = undefined;
    const child = spend(pout, 1, 0, 85_000, &P2WPKH_OUT, &ib, &ob);
    const dry = pool.acceptToMemoryPool(child, true);
    try testing.expect(!dry.accepted);
    try testing.expectEqualStrings("non-BIP68-final", dry.reject_reason.?);
    const res = pool.acceptToMemoryPool(child, false);
    try testing.expect(!res.accepted);
    try testing.expectEqualStrings("non-BIP68-final", res.reject_reason.?);

    // Same for a 1-unit (512 s) TIME lock: nCoinTime = tip MTP for a mempool coin.
    var ib3: [1]types.TxIn = undefined;
    var ob3: [1]types.TxOut = undefined;
    const child_t = spend(pout, TYPE_FLAG | 1, 0, 85_000, &P2WPKH_OUT, &ib3, &ob3);
    const rt = pool.acceptToMemoryPool(child_t, false);
    try testing.expect(!rt.accepted);
    try testing.expectEqualStrings("non-BIP68-final", rt.reject_reason.?);

    // Control: relative lock 0 on the same mempool parent is final.
    var ib2: [1]types.TxIn = undefined;
    var ob2: [1]types.TxOut = undefined;
    const child0 = spend(pout, 0, 0, 85_000, &P2WPKH_OUT, &ib2, &ob2);
    const r0 = pool.acceptToMemoryPool(child0, false);
    if (!r0.accepted) std.debug.print("lock-0 child rejected: {s}\n", .{r0.reject_reason orelse "?"});
    try testing.expect(r0.accepted);
}

test "mtp-bip68: testmempoolaccept (dry run) REJECTS a non-BIP68-final spend of a confirmed coin (was allowed=true)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();

    const wsh = opTrueP2wsh();
    const coin = try addCoin(&cs, 0x34, COIN_H, &wsh);
    var ib: [1]types.TxIn = undefined;
    var ob: [1]types.TxOut = undefined;
    // Height lock of 30 on a coin with 21 confirmations at the next block.
    const tx = spend(coin, 30, 0, 90_000, &P2WPKH_OUT, &ib, &ob);
    const dry = pool.acceptToMemoryPool(tx, true);
    try testing.expect(!dry.accepted);
    try testing.expectEqualStrings("non-BIP68-final", dry.reject_reason.?);
}

test "mtp-bip68: nLockTime = tip MTP - 1 is ACCEPTED, nLockTime = tip MTP is REJECTED non-final (control)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    setupChain(&cs);
    var pool = Mempool.init(&cs, &consensus.MAINNET, allocator);
    defer pool.deinit();

    const tip_mtp = mtpOf(TIP);
    const wsh = opTrueP2wsh();
    const c1 = try addCoin(&cs, 0x35, TIP - 300, &wsh);
    const c2 = try addCoin(&cs, 0x36, TIP - 300, &wsh);

    var ib: [1]types.TxIn = undefined;
    var ob: [1]types.TxOut = undefined;
    const ok = spend(c1, 0xFFFF_FFFE, tip_mtp - 1, 90_000, &P2WPKH_OUT, &ib, &ob);
    const r1 = pool.acceptToMemoryPool(ok, false);
    if (!r1.accepted) std.debug.print("mtp-1 rejected: {s}\n", .{r1.reject_reason orelse "?"});
    try testing.expect(r1.accepted);

    var ib2: [1]types.TxIn = undefined;
    var ob2: [1]types.TxOut = undefined;
    const bad = spend(c2, 0xFFFF_FFFE, tip_mtp, 90_000, &P2WPKH_OUT, &ib2, &ob2);
    // testmempoolaccept answers Core's token "non-final"; the full path's
    // token is clearbit's own "bad-txns-nonfinal" (pre-existing, unchanged).
    const d2 = pool.acceptToMemoryPool(bad, true);
    try testing.expect(!d2.accepted);
    try testing.expectEqualStrings("non-final", d2.reject_reason.?);
    const r2 = pool.acceptToMemoryPool(bad, false);
    try testing.expect(!r2.accepted);
    try testing.expectEqualStrings("bad-txns-nonfinal", r2.reject_reason.?);
}

// ----------------------------------------------------------------------------
// MTP ring after a disconnect / reorg (DB-backed ChainState, real connect +
// disconnect paths).  Timestamps are NON-monotone so every window has a
// distinct median.
// ----------------------------------------------------------------------------

pub const RING_TS = [_]u32{
    1_600_000_000, // h1
    1_600_000_900,
    1_600_000_300,
    1_600_002_000,
    1_600_001_100,
    1_600_003_500,
    1_600_002_700,
    1_600_004_100,
    1_600_003_900,
    1_600_005_600,
    1_600_004_800,
    1_600_006_900,
    1_600_006_000,
    1_600_008_200,
    1_600_007_300,
    1_600_009_100, // h16
};

/// Core GetMedianTimePast for the block at height h of `ts` (ts[0] = height 1),
/// window min(11, h) because the test chain has no genesis entry in the ring
/// (ChainState.init leaves it empty; heights start at 1).
pub fn expectedMtp(ts: []const u32, h: u32) u32 {
    const n: usize = @min(@as(usize, 11), @as(usize, h));
    var w: [11]u32 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) w[i] = ts[h - 1 - i];
    return validation.medianTimePast(w[0..n]);
}

pub const BlockStore = struct {
    cb_in: [1]types.TxIn = undefined,
    cb_out: [1]types.TxOut = undefined,
    txs: [1]types.Transaction = undefined,
    sig: [5]u8 = undefined,
};

pub fn makeBlock(st: *BlockStore, prev: types.Hash256, height: u32, ts: u32, salt: u8) types.Block {
    st.sig = .{ 0x04, @truncate(height), @truncate(height >> 8), @truncate(height >> 16), salt };
    st.cb_in[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &st.sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    st.cb_out[0] = .{ .value = 5_000_000_000, .script_pubkey = &P2WPKH_OUT };
    st.txs[0] = .{ .version = 1, .inputs = &st.cb_in, .outputs = &st.cb_out, .lock_time = 0 };
    return .{
        .header = .{
            .version = 1,
            .prev_block = prev,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = ts,
            .bits = 0,
            .nonce = 0,
        },
        .transactions = &st.txs,
    };
}

pub fn hashFor(height: u32, salt: u8) types.Hash256 {
    var h = [_]u8{0} ** 32;
    h[0] = @truncate(height);
    h[1] = @truncate(height >> 8);
    h[31] = salt;
    return h;
}

pub fn connectChain(allocator: std.mem.Allocator, cs: *storage.ChainState, stores: []BlockStore, ts: []const u32) !void {
    var prev = [_]u8{0} ** 32;
    for (ts, 0..) |t, i| {
        const h: u32 = @intCast(i + 1);
        const block = makeBlock(&stores[i], prev, h, t, 0xA0);
        const bh = hashFor(h, 0xA0);
        var w = serialize.Writer.init(allocator);
        try serialize.writeBlock(&w, &block);
        const owned: []u8 = @constCast(try w.toOwnedSlice());
        try cs.queueBlockWrite(&bh, owned, h);
        try cs.connectBlockFastWithUndo(&block, &bh, h);
        prev = bh;
    }
}

test "mtp-ring: after disconnecting 3 blocks the tip MTP equals the recomputed median of the NEW tip (no stale ring)" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    var stores: [RING_TS.len]BlockStore = undefined;
    try connectChain(allocator, &cs, &stores, &RING_TS);
    const top: u32 = RING_TS.len;
    try testing.expectEqual(top, cs.best_height);
    try testing.expectEqual(expectedMtp(&RING_TS, top), cs.computeMTP());

    var h: u32 = top;
    while (h > top - 3) : (h -= 1) {
        const bh = hashFor(h, 0xA0);
        try cs.disconnectBlockByHashCF(&bh);
        try testing.expectEqual(h - 1, cs.best_height);
        const want = expectedMtp(&RING_TS, h - 1);
        if (cs.computeMTP() != want) {
            std.debug.print("after disconnect to h={d}: ring MTP {d}, true MTP {d}\n", .{ h - 1, cs.computeMTP(), want });
        }
        try testing.expectEqual(want, cs.computeMTP());
    }
}

test "mtp-ring: after a reorg (2 disconnected, 3 connected) the tip MTP equals the recomputed median of the new branch" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    var stores: [RING_TS.len]BlockStore = undefined;
    try connectChain(allocator, &cs, &stores, &RING_TS);
    const top: u32 = RING_TS.len;
    const fork_h: u32 = top - 2;
    const fork_hash = hashFor(fork_h, 0xA0);

    // New branch: 3 blocks on top of fork_h, with timestamps far below the
    // old branch's (still > the fork's MTP) so a stale ring is visible.
    const new_ts = [_]u32{ 1_600_009_000, 1_600_008_000, 1_600_009_500 };
    var nstores: [3]BlockStore = undefined;
    var rbs: [3]storage.ChainState.ReorgBlock = undefined;
    var prev = fork_hash;
    for (new_ts, 0..) |t, i| {
        const hh: u32 = fork_h + @as(u32, @intCast(i)) + 1;
        rbs[i] = .{ .hash = hashFor(hh, 0xB0), .block = makeBlock(&nstores[i], prev, hh, t, 0xB0), .height = hh };
        prev = rbs[i].hash;
    }
    _ = try cs.reorgToChain(&fork_hash, &rbs);
    try testing.expectEqual(fork_h + 3, cs.best_height);

    var all: [RING_TS.len + 1]u32 = undefined;
    @memcpy(all[0..fork_h], RING_TS[0..fork_h]);
    @memcpy(all[fork_h .. fork_h + 3], &new_ts);
    const want = expectedMtp(all[0 .. fork_h + 3], fork_h + 3);
    if (cs.computeMTP() != want) {
        std.debug.print("after reorg: ring MTP {d}, true MTP {d}\n", .{ cs.computeMTP(), want });
    }
    try testing.expectEqual(want, cs.computeMTP());
}
