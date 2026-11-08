//! testmempoolaccept with more than one transaction vs Core v31.1.
//!
//! Run via `zig build test-tma-package` (also part of `zig build test`).
//!
//! Core's testmempoolaccept hands a multi-tx array to ProcessNewPackage
//! (test_accept=true) -> AcceptMultipleTransactions (validation.cpp). That
//! path does NOT use package feerates (ATMPArgs::PackageTestAccept sets
//! m_package_feerates=false): every tx must pay the relay minimum on its own,
//! PreChecks run for every tx first, then script checks, and the first
//! failure ends validation. The failing tx gets allowed=false with its reject
//! reason; every tx after it is "unfinished" and is reported with only txid
//! and wtxid (rpc/mempool.cpp testmempoolaccept).
//!
//! Ratchet rows (seed_submitpackage/*/accept):
//!   valid-cpfp:[0]       Core rejects the 1-sat parent "min relay fee not met"
//!                        ("1 < 11"); clearbit allowed it through CPFP
//!   valid-cpfp:[1]       Core: unfinished (no allowed); clearbit allowed
//!   invalid-sig-parent:[1] Core: unfinished; clearbit allowed=false

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");

const COIN_VALUE: i64 = 1_000_000;

/// P2SH scriptPubKey for a one-byte redeem script.
fn p2shOf(a: std.mem.Allocator, redeem: []const u8) ![]const u8 {
    const h = crypto.hash160(redeem);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

const REDEEM_TRUE = [_]u8{0x51}; // OP_TRUE: spends succeed
const REDEEM_FALSE = [_]u8{0x00}; // OP_0: spends fail script checks
const SIG_TRUE = [_]u8{ 0x01, 0x51 };
const SIG_FALSE = [_]u8{ 0x01, 0x00 };

fn spend(a: std.mem.Allocator, prev: types.Hash256, script_sig: []const u8, value: i64) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = .{ .hash = prev, .index = 0 },
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFD,
        .witness = &.{},
    };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = value, .script_pubkey = try p2shOf(a, &REDEEM_TRUE) };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

fn hexOf(a: std.mem.Allocator, tx: *const types.Transaction) ![]const u8 {
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, tx);
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
}

/// Chain state holding one confirmed (non-coinbase) coin of COIN_VALUE at
/// outpoint `prev`:0, locked to P2SH(`redeem`).
fn chainWithCoin(a: std.mem.Allocator, prev: types.Hash256, redeem: []const u8) !*storage.ChainState {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const out = types.TxOut{ .value = COIN_VALUE, .script_pubkey = try p2shOf(a, redeem) };
    const op = types.OutPoint{ .hash = prev, .index = 0 };
    try cs.utxo_set.add(&op, &out, 799_000, false);
    return cs;
}

fn testAccept(a: std.mem.Allocator, cs: *storage.ChainState, hexes: []const []const u8) !std.json.Parsed(std.json.Value) {
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});
    var req = std.ArrayList(u8).init(a);
    try req.appendSlice("{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[");
    for (hexes, 0..) |h, i| {
        if (i > 0) try req.append(',');
        try req.writer().print("\"{s}\"", .{h});
    }
    try req.appendSlice("]]}");
    const resp = try srv.dispatch(req.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
    // The call must not leave anything in the pool (test_accept semantics).
    try testing.expectEqual(@as(usize, 0), mp.entries.count());
    return parsed;
}

const PREV = [_]u8{0x42} ** 32;

test "tests_tma_package a 1-sat parent is rejected alone (min relay fee not met) and its CPFP child is unfinished" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try chainWithCoin(a, PREV, &REDEEM_TRUE);

    const parent = try spend(a, PREV, &SIG_TRUE, COIN_VALUE - 1);
    const parent_id = try crypto.computeTxid(&parent, a);
    const child = try spend(a, parent_id, &SIG_TRUE, COIN_VALUE - 1 - 20_000);
    const p = try testAccept(a, cs, &.{ try hexOf(a, &parent), try hexOf(a, &child) });

    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(@as(usize, 2), rows.len);
    const r0 = rows[0].object;
    try testing.expect(!r0.get("allowed").?.bool);
    try testing.expectEqualStrings("min relay fee not met", r0.get("reject-reason").?.string);
    // Core: "%d < %d" of the modified fee and min_relay_feerate.GetFee(vsize)
    // (100 sat/kvB, rounded up).
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, &parent);
    const vsize: i64 = @intCast(w.list.items.len); // no witness: vsize == size
    const min_fee = @divTrunc(100 * vsize + 999, 1000);
    const details = try std.fmt.allocPrint(a, "min relay fee not met, 1 < {d}", .{min_fee});
    try testing.expectEqualStrings(details, r0.get("reject-details").?.string);
    try testing.expect(r0.get("fees") == null);
    try testing.expect(r0.get("vsize") == null);

    // The child is unfinished: txid and wtxid only.
    const r1 = rows[1].object;
    try testing.expect(r1.get("txid") != null);
    try testing.expect(r1.get("wtxid") != null);
    try testing.expect(r1.get("allowed") == null);
    try testing.expectEqual(@as(usize, 2), r1.count());
}

test "tests_tma_package a parent failing its script check leaves the child unfinished" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try chainWithCoin(a, PREV, &REDEEM_FALSE);

    const parent = try spend(a, PREV, &SIG_FALSE, COIN_VALUE - 20_000);
    const parent_id = try crypto.computeTxid(&parent, a);
    const child = try spend(a, parent_id, &SIG_TRUE, COIN_VALUE - 40_000);
    const p = try testAccept(a, cs, &.{ try hexOf(a, &parent), try hexOf(a, &child) });

    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(@as(usize, 2), rows.len);
    const r0 = rows[0].object;
    try testing.expect(!r0.get("allowed").?.bool);
    try testing.expect(r0.get("reject-reason") != null);
    const r1 = rows[1].object;
    try testing.expect(r1.get("allowed") == null);
    try testing.expectEqual(@as(usize, 2), r1.count());
}

test "tests_tma_package a child failing its script check is rejected after its parent is allowed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try chainWithCoin(a, PREV, &REDEEM_TRUE);

    // Parent pays to P2SH(OP_0) so the child's spend fails script checks.
    var parent = try spend(a, PREV, &SIG_TRUE, COIN_VALUE - 20_000);
    const pouts = try a.alloc(types.TxOut, 1);
    pouts[0] = .{ .value = COIN_VALUE - 20_000, .script_pubkey = try p2shOf(a, &REDEEM_FALSE) };
    parent.outputs = pouts;
    const parent_id = try crypto.computeTxid(&parent, a);
    const child = try spend(a, parent_id, &SIG_FALSE, COIN_VALUE - 40_000);
    const p = try testAccept(a, cs, &.{ try hexOf(a, &parent), try hexOf(a, &child) });

    const rows = p.value.object.get("result").?.array.items;
    const r0 = rows[0].object;
    try testing.expect(r0.get("allowed").?.bool);
    // Each tx pays for itself: its own fee and feerate, includes only itself.
    const f0 = r0.get("fees").?.object;
    try testing.expectApproxEqAbs(@as(f64, 0.0002), f0.get("base").?.float, 1e-12);
    try testing.expectEqual(@as(usize, 1), f0.get("effective-includes").?.array.items.len);
    const r1 = rows[1].object;
    try testing.expect(!r1.get("allowed").?.bool);
    try testing.expect(r1.get("reject-reason") != null);
    try testing.expect(r1.get("fees") == null);
}

test "tests_tma_package a parent and child that each pay the relay minimum are both allowed with their own fees" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try chainWithCoin(a, PREV, &REDEEM_TRUE);

    const parent = try spend(a, PREV, &SIG_TRUE, COIN_VALUE - 20_000);
    const parent_id = try crypto.computeTxid(&parent, a);
    const child = try spend(a, parent_id, &SIG_TRUE, COIN_VALUE - 50_000);
    const p = try testAccept(a, cs, &.{ try hexOf(a, &parent), try hexOf(a, &child) });

    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(@as(usize, 2), rows.len);
    const r0 = rows[0].object;
    const r1 = rows[1].object;
    try testing.expect(r0.get("allowed").?.bool);
    try testing.expect(r1.get("allowed").?.bool);
    try testing.expectApproxEqAbs(@as(f64, 0.0002), r0.get("fees").?.object.get("base").?.float, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.0003), r1.get("fees").?.object.get("base").?.float, 1e-12);
    const inc1 = r1.get("fees").?.object.get("effective-includes").?.array.items;
    try testing.expectEqual(@as(usize, 1), inc1.len);
    try testing.expectEqualStrings(r1.get("wtxid").?.string, inc1[0].string);
}

test "tests_tma_package a parent that conflicts with a mempool tx is bip125-replacement-disallowed and the pool is untouched" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try chainWithCoin(a, PREV, &REDEEM_TRUE);
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});

    // O spends the coin and signals RBF; it is in the pool.
    const original = try spend(a, PREV, &SIG_TRUE, COIN_VALUE - 10_000);
    const original_id = try crypto.computeTxid(&original, a);
    try mp.addTransaction(original);
    try testing.expect(mp.entries.contains(original_id));

    // P double-spends the coin with a higher fee (a valid BIP125 replacement
    // on its own), C spends P.  Core's PackageTestAccept has
    // allow_replacement=false (validation.cpp ATMPArgs), so PreChecks refuses
    // P with "bip125-replacement-disallowed" and C is unfinished.
    const parent = try spend(a, PREV, &SIG_TRUE, COIN_VALUE - 40_000);
    const parent_id = try crypto.computeTxid(&parent, a);
    const child = try spend(a, parent_id, &SIG_TRUE, COIN_VALUE - 70_000);
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\",\"{s}\"]]}}", .{ try hexOf(a, &parent), try hexOf(a, &child) });
    const resp = try srv.dispatch(req);
    const p = try std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(@as(usize, 2), rows.len);
    const r0 = rows[0].object;
    try testing.expect(!r0.get("allowed").?.bool);
    try testing.expectEqualStrings("bip125-replacement-disallowed", r0.get("reject-reason").?.string);
    try testing.expectEqualStrings("bip125-replacement-disallowed", r0.get("reject-details").?.string);
    try testing.expect(rows[1].object.get("allowed") == null);
    try testing.expectEqual(@as(usize, 2), rows[1].object.count());

    // test_accept: the conflicting tx is still there and nothing was added.
    try testing.expect(mp.entries.contains(original_id));
    try testing.expectEqual(@as(usize, 1), mp.entries.count());
}
