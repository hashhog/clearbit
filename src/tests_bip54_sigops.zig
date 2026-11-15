//! BIP54 non-witness sigop policy limit (MAX_TX_LEGACY_SIGOPS = 2,500) vs
//! Core v31.1.
//!
//! Run via `zig build test-bip54-sigops` (also part of `zig build test`).
//!
//! Core policy/policy.cpp CheckSigopsBIP54, called first in
//! ValidateInputsStandardness, counts per input
//!   txin.scriptSig.GetSigOpCount(true)
//!   + prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig)
//! i.e. the sigops that run when the tx is VALIDATED: its scriptSigs and the
//! scriptPubKeys it spends (P2SH: the redeemScript).  The tx's own output
//! scriptPubKeys are not counted; they execute only when a later tx spends
//! them.  Over the limit: "bad-txns-nonstandard-inputs" (TX_INPUTS_NOT_STANDARD).
//!
//! Ratchet rows: package_rbf/{over,at-limit}/* and package_rbf/control.  Each
//! package tx there carries 126 or 127 bare 1-of-1 multisig outputs (20
//! inaccurate legacy sigops each, so 2,520+ counted the old way) and spends
//! P2SH(OP_TRUE) coins (0 sigops the BIP54 way).

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

/// secp256k1 generator, compressed.
const G = [_]u8{
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
};
/// OP_1 <G> OP_1 OP_CHECKMULTISIG: standard bare 1-of-1, 20 inaccurate sigops.
const BARE_1OF1 = [_]u8{ 0x51, 0x21 } ++ G ++ [_]u8{ 0x51, 0xae };
/// OP_1 <G> <G> <G> OP_3 OP_CHECKMULTISIG: bare 1-of-3, 3 accurate sigops.
const BARE_1OF3 = [_]u8{ 0x51, 0x21 } ++ G ++ [_]u8{0x21} ++ G ++ [_]u8{0x21} ++ G ++ [_]u8{ 0x53, 0xae };
/// Push of the redeem script OP_TRUE: spends P2SH(OP_TRUE).
const ACS_SCRIPTSIG = [_]u8{ 0x01, 0x51 };
/// OP_0 OP_0: a 1-of-N CHECKMULTISIG spend with an empty signature.  Push-only,
/// so standard, and it fails the script check (empty signature).
const EMPTY_MULTISIG_SIG = [_]u8{ 0x00, 0x00 };

const RBF_SEQUENCE: u32 = 0xFFFFFFFD;
const SUBSIDY: i64 = 5_000_000_000;
const OUTPUT_SATS: i64 = 1_000;

fn p2shTrue(a: std.mem.Allocator) ![]const u8 {
    const h = crypto.hash160(&[_]u8{0x51});
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

fn hexOf(a: std.mem.Allocator, tx: *const types.Transaction) ![]const u8 {
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, tx);
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
}

fn displayHex(a: std.mem.Allocator, h: types.Hash256) ![]const u8 {
    var r = h;
    std.mem.reverse(u8, &r);
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(&r)});
}

fn newChain(a: std.mem.Allocator) !*storage.ChainState {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    return cs;
}

fn addCoin(cs: *storage.ChainState, prev: types.Hash256, index: u32, value: i64, spk: []const u8) !void {
    const out = types.TxOut{ .value = value, .script_pubkey = spk };
    const op = types.OutPoint{ .hash = prev, .index = index };
    try cs.utxo_set.add(&op, &out, 799_000, false);
}

const Rig = struct { mp: *mempool_mod.Mempool, srv: *rpc.RpcServer };

fn rig(a: std.mem.Allocator, cs: *storage.ChainState) !Rig {
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});
    return .{ .mp = mp, .srv = srv };
}

fn call(a: std.mem.Allocator, srv: *rpc.RpcServer, method: []const u8, txs: []const *const types.Transaction) !std.json.Parsed(std.json.Value) {
    var req = std.ArrayList(u8).init(a);
    try req.writer().print("{{\"id\":1,\"method\":\"{s}\",\"params\":[[", .{method});
    for (txs, 0..) |tx, i| {
        if (i > 0) try req.append(',');
        try req.writer().print("\"{s}\"", .{try hexOf(a, tx)});
    }
    try req.appendSlice("]]}");
    const resp = try srv.dispatch(req.items);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

/// One-input tx: change to P2SH(OP_TRUE) first, then `n` outputs of `extra`.
fn fanOut(a: std.mem.Allocator, prev: types.Hash256, value: i64, fee: i64, n: usize, extra: []const u8) !types.Transaction {
    const acs = try p2shTrue(a);
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = .{ .hash = prev, .index = 0 },
        .script_sig = &ACS_SCRIPTSIG,
        .sequence = RBF_SEQUENCE,
        .witness = &.{},
    };
    const outs = try a.alloc(types.TxOut, n + 1);
    outs[0] = .{ .value = value - fee - @as(i64, @intCast(n)) * OUTPUT_SATS, .script_pubkey = acs };
    for (outs[1..]) |*o| o.* = .{ .value = OUTPUT_SATS, .script_pubkey = extra };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

/// testmempoolaccept of one tx: (allowed, reject-reason or "").
fn tmaOne(a: std.mem.Allocator, srv: *rpc.RpcServer, tx: *const types.Transaction) !struct { allowed: bool, reason: []const u8 } {
    const p = try call(a, srv, "testmempoolaccept", &.{tx});
    const row = p.value.object.get("result").?.array.items[0].object;
    const reason = if (row.get("reject-reason")) |r| r.string else "";
    return .{ .allowed = row.get("allowed").?.bool, .reason = reason };
}

const COIN = [_]u8{0x42} ** 32;

test "tests_bip54_sigops a tx creating 126 bare multisig outputs is standard: outputs are not BIP54 sigops" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try newChain(a);
    try addCoin(cs, COIN, 0, SUBSIDY, try p2shTrue(a));
    const r = try rig(a, cs);

    // 126 x 20 = 2,520 inaccurate output sigops; 0 sigops spent.  Core allows it.
    const tx = try fanOut(a, COIN, SUBSIDY, 300_000, 126, &BARE_1OF1);
    const res = try tmaOne(a, r.srv, &tx);
    try testing.expectEqualStrings("", res.reason);
    try testing.expect(res.allowed);
}

/// A tx spending `n` bare 1-of-3 multisig coins (3 accurate sigops each) with
/// an empty signature.
fn spendBareMultisig(a: std.mem.Allocator, cs: *storage.ChainState, n: usize) !types.Transaction {
    const ins = try a.alloc(types.TxIn, n);
    for (ins, 0..) |*in, i| {
        var prev = [_]u8{0x55} ** 32;
        std.mem.writeInt(u32, prev[0..4], @intCast(i), .little);
        try addCoin(cs, prev, 0, 100_000, &BARE_1OF3);
        in.* = .{
            .previous_output = .{ .hash = prev, .index = 0 },
            .script_sig = &EMPTY_MULTISIG_SIG,
            .sequence = 0xFFFFFFFF,
            .witness = &.{},
        };
    }
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = @as(i64, @intCast(n)) * 100_000 - 1_000_000, .script_pubkey = try p2shTrue(a) };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

test "tests_bip54_sigops spending 2,502 accurate sigops is bip54-nonstandard before the script check" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try newChain(a);
    // 834 x 3 = 2,502 > 2,500.  Core: CheckSigopsBIP54 fails first in
    // ValidateInputsStandardness, so the tx is non-standard and its (bad)
    // signatures are never checked.  (Full admission path: the single-tx
    // testmempoolaccept dry run does not reach the input checks.)
    const tx = try spendBareMultisig(a, cs, 834);
    const r = try rig(a, cs);
    try testing.expectError(mempool_mod.MempoolError.NonStandard, r.mp.addTransaction(tx));
}

test "tests_bip54_sigops spending 2,499 accurate sigops passes the BIP54 limit and reaches the script check" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try newChain(a);
    // 833 x 3 = 2,499 <= 2,500 (counted accurately, not 20 per CHECKMULTISIG):
    // standard, so the script check runs and rejects the empty signatures.
    const tx = try spendBareMultisig(a, cs, 833);
    const r = try rig(a, cs);
    try testing.expectError(mempool_mod.MempoolError.ScriptVerifyFailed, r.mp.addTransaction(tx));
}

// --- The package_rbf ratchet scenario (harness/scenarios/package_rbf.py) ---

const CONFLICT_OUTPUTS = 600;
const CONFLICT_FEE: i64 = 20_000;
const DESCENDANT_FEE: i64 = 1_000;
const PARENT_FEE: i64 = 6_000;
const CHILD_FEE: i64 = 200_000;

const Pkg = struct { o: types.Transaction, d: types.Transaction, p: types.Transaction, c: types.Transaction };

fn buildReplacement(a: std.mem.Allocator, parent_outputs: usize, child_outputs: usize) !Pkg {
    const acs = try p2shTrue(a);
    const o = try fanOut(a, COIN, SUBSIDY, CONFLICT_FEE, CONFLICT_OUTPUTS, acs);
    const o_id = try crypto.computeTxid(&o, a);
    const d = try fanOut(a, o_id, o.outputs[0].value, DESCENDANT_FEE, 0, acs);
    const p = try fanOut(a, COIN, SUBSIDY, PARENT_FEE, parent_outputs, &BARE_1OF1);
    const p_id = try crypto.computeTxid(&p, a);
    const c = try fanOut(a, p_id, p.outputs[0].value, CHILD_FEE, child_outputs, &BARE_1OF1);
    return .{ .o = o, .d = d, .p = p, .c = c };
}

fn jsonNum(v: std.json.Value) f64 {
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        .number_string => |t| std.fmt.parseFloat(f64, t) catch std.math.nan(f64),
        else => std.math.nan(f64),
    };
}

fn inPool(a: std.mem.Allocator, mp: *mempool_mod.Mempool, tx: *const types.Transaction) !bool {
    return mp.entries.contains(try crypto.computeTxid(tx, a));
}

fn submitReplacement(a: std.mem.Allocator, parent_outputs: usize, child_outputs: usize) !struct { r: Rig, pkg: Pkg, res: std.json.ObjectMap } {
    const cs = try newChain(a);
    try addCoin(cs, COIN, 0, SUBSIDY, try p2shTrue(a));
    const r = try rig(a, cs);
    const pkg = try buildReplacement(a, parent_outputs, child_outputs);
    try r.mp.addTransaction(pkg.o);
    try r.mp.addTransaction(pkg.d);
    const p = try call(a, r.srv, "submitpackage", &.{ &pkg.p, &pkg.c });
    return .{ .r = r, .pkg = pkg, .res = p.value.object.get("result").?.object };
}

test "tests_bip54_sigops package_rbf at-limit: a 126+126 bare-multisig package replaces its conflict and descendant" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try submitReplacement(a, 126, 126);

    try testing.expectEqualStrings("success", s.res.get("package_msg").?.string);
    const replaced = s.res.get("replaced-transactions").?.array.items;
    try testing.expectEqual(@as(usize, 2), replaced.len);
    const o_hex = try displayHex(a, try crypto.computeTxid(&s.pkg.o, a));
    const d_hex = try displayHex(a, try crypto.computeTxid(&s.pkg.d, a));
    for (replaced) |v| try testing.expect(std.mem.eql(u8, v.string, o_hex) or std.mem.eql(u8, v.string, d_hex));

    // Core's per-tx vsize is sigop-adjusted: 126 x 20 x 4 x 20 / 4 = 50,400.
    // Both share the package feerate floor(206,000 x 1000 / 100,800) sat/kvB
    // = 2,043 = 0.00002043 BTC/kvB, and list both wtxids, parent first.
    const results = s.res.get("tx-results").?.object;
    const p_w = try displayHex(a, try crypto.computeWtxid(&s.pkg.p, a));
    const c_w = try displayHex(a, try crypto.computeWtxid(&s.pkg.c, a));
    const bases = [_]f64{ 0.00006, 0.002 };
    for ([_]*const types.Transaction{ &s.pkg.p, &s.pkg.c }, 0..) |tx, k| {
        const row = results.get(try displayHex(a, try crypto.computeWtxid(tx, a))).?.object;
        try testing.expect(row.get("error") == null);
        try testing.expectEqual(@as(i64, 50_400), row.get("vsize").?.integer);
        const fees = row.get("fees").?.object;
        try testing.expectApproxEqAbs(bases[k], jsonNum(fees.get("base").?), 1e-12);
        try testing.expectApproxEqAbs(@as(f64, 0.00002043), jsonNum(fees.get("effective-feerate").?), 1e-12);
        const inc = fees.get("effective-includes").?.array.items;
        try testing.expectEqual(@as(usize, 2), inc.len);
        try testing.expectEqualStrings(p_w, inc[0].string);
        try testing.expectEqualStrings(c_w, inc[1].string);
    }

    try testing.expect(try inPool(a, s.r.mp, &s.pkg.p));
    try testing.expect(try inPool(a, s.r.mp, &s.pkg.c));
    try testing.expect(!try inPool(a, s.r.mp, &s.pkg.o));
    try testing.expect(!try inPool(a, s.r.mp, &s.pkg.d));
}

test "tests_bip54_sigops package_rbf over: a 127+126 package is too-large-cluster and the conflict stays" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try submitReplacement(a, 127, 126);

    // 404,800 sigop-adjusted weight > 404,000 (-limitclustersize 101 kvB).
    try testing.expectEqualStrings("too-large-cluster", s.res.get("package_msg").?.string);
    // Each tx keeps the error it got alone (Core AcceptPackage
    // individual_results_nonfinal): the parent cannot pay for O + D, the
    // child's parent is missing.
    const results = s.res.get("tx-results").?.object;
    const p_row = results.get(try displayHex(a, try crypto.computeWtxid(&s.pkg.p, a))).?.object;
    const p_msg = try std.fmt.allocPrint(a, "insufficient fee, rejecting replacement {s}, less fees than conflicting txs; 0.00006 < 0.00021", .{try displayHex(a, try crypto.computeTxid(&s.pkg.p, a))});
    try testing.expectEqualStrings(p_msg, p_row.get("error").?.string);
    const c_row = results.get(try displayHex(a, try crypto.computeWtxid(&s.pkg.c, a))).?.object;
    try testing.expectEqualStrings("bad-txns-inputs-missingorspent", c_row.get("error").?.string);
    try testing.expect(try inPool(a, s.r.mp, &s.pkg.o));
    try testing.expect(try inPool(a, s.r.mp, &s.pkg.d));
    try testing.expect(!try inPool(a, s.r.mp, &s.pkg.p));
    try testing.expect(!try inPool(a, s.r.mp, &s.pkg.c));
}

// --- What package RBF must still refuse (the pool stays as it was) ---

fn expectPoolKept(a: std.mem.Allocator, mp: *mempool_mod.Mempool, pkg: *const Pkg) !void {
    try testing.expect(try inPool(a, mp, &pkg.o));
    try testing.expect(try inPool(a, mp, &pkg.d));
    try testing.expect(!try inPool(a, mp, &pkg.p));
    try testing.expect(!try inPool(a, mp, &pkg.c));
}

test "tests_bip54_sigops package RBF that does not cover the evicted fees is insufficient anti-DoS fees" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try newChain(a);
    try addCoin(cs, COIN, 0, SUBSIDY, try p2shTrue(a));
    const r = try rig(a, cs);
    const acs = try p2shTrue(a);
    var pkg = try buildReplacement(a, 1, 1);
    // Package fee 6,000 + 1,000 = 7,000 < the 21,000 it would evict.
    pkg.c = try fanOut(a, try crypto.computeTxid(&pkg.p, a), pkg.p.outputs[0].value, 1_000, 0, acs);
    try r.mp.addTransaction(pkg.o);
    try r.mp.addTransaction(pkg.d);
    const p = try call(a, r.srv, "submitpackage", &.{ &pkg.p, &pkg.c });
    const res = p.value.object.get("result").?.object;
    try testing.expectEqualStrings("package RBF failed: insufficient anti-DoS fees", res.get("package_msg").?.string);
    try expectPoolKept(a, r.mp, &pkg);
}

test "tests_bip54_sigops package RBF whose parent has a mempool parent is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try newChain(a);
    const acs = try p2shTrue(a);
    try addCoin(cs, COIN, 0, SUBSIDY, acs);
    const OTHER = [_]u8{0x43} ** 32;
    try addCoin(cs, OTHER, 0, SUBSIDY, acs);
    const r = try rig(a, cs);
    var pkg = try buildReplacement(a, 1, 1);
    // M is in the pool; the parent spends M:0 as well as O's coin.
    const m = try fanOut(a, OTHER, SUBSIDY, 10_000, 0, acs);
    try r.mp.addTransaction(m);
    try r.mp.addTransaction(pkg.o);
    try r.mp.addTransaction(pkg.d);
    const ins = try a.alloc(types.TxIn, 2);
    ins[0] = pkg.p.inputs[0];
    ins[1] = .{ .previous_output = .{ .hash = try crypto.computeTxid(&m, a), .index = 0 }, .script_sig = &ACS_SCRIPTSIG, .sequence = RBF_SEQUENCE, .witness = &.{} };
    const p_outs = try a.alloc(types.TxOut, 1);
    p_outs[0] = .{ .value = SUBSIDY + m.outputs[0].value - PARENT_FEE, .script_pubkey = acs };
    pkg.p = .{ .version = 2, .inputs = ins, .outputs = p_outs, .lock_time = 0 };
    pkg.c = try fanOut(a, try crypto.computeTxid(&pkg.p, a), pkg.p.outputs[0].value, CHILD_FEE, 0, acs);
    const p = try call(a, r.srv, "submitpackage", &.{ &pkg.p, &pkg.c });
    const res = p.value.object.get("result").?.object;
    try testing.expectEqualStrings("package RBF failed: new transaction cannot have mempool ancestors", res.get("package_msg").?.string);
    try expectPoolKept(a, r.mp, &pkg);
    try testing.expect(try inPool(a, r.mp, &m));
}

test "tests_bip54_sigops package RBF whose child fails its script check keeps the conflict" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try newChain(a);
    try addCoin(cs, COIN, 0, SUBSIDY, try p2shTrue(a));
    const r = try rig(a, cs);
    var pkg = try buildReplacement(a, 1, 1);
    // The child spends P(OP_TRUE) with a scriptSig whose redeem script is
    // OP_0: the hash does not match, so its script check fails.
    pkg.c.inputs = blk: {
        const ins = try a.alloc(types.TxIn, 1);
        ins[0] = pkg.c.inputs[0];
        ins[0].script_sig = &[_]u8{ 0x01, 0x00 };
        break :blk ins;
    };
    try r.mp.addTransaction(pkg.o);
    try r.mp.addTransaction(pkg.d);
    const p = try call(a, r.srv, "submitpackage", &.{ &pkg.p, &pkg.c });
    const res = p.value.object.get("result").?.object;
    try testing.expectEqualStrings("transaction failed", res.get("package_msg").?.string);
    try expectPoolKept(a, r.mp, &pkg);
}
