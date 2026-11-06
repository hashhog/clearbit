//! submitpackage response shape vs Core v31.1 (rpc/mempool.cpp submitpackage).
//!
//! Run via `zig build test-submitpackage-shape`.
//!
//! Ratchet rows (package/control/submitpackage:$, seed_submitpackage/*):
//!   package_msg      Core "success" / "transaction failed", node was ""
//!   package_feerate  Core omits it
//!   tx-results.*     Core: vsize + fees{base,effective-feerate,effective-includes},
//!                    no "allowed"; a failed tx gets a string "error"

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

// 1-in/1-out segwit tx (valid serialization, fee 10_000 sat once its input coin exists).
const TX = "020000000001018ad2bbf537bbf9ed2bed6cd4b4e5e032e2fd239df5884c14c2d2b5e9a9be0e800000000000fdffffff01f0ca052a01000000160014751e76e8199196d454941c45d1b3a323f1433bd602473044022021e92e30619a66ea56ba3e4aea655d8088f0e537eafa938ccb0e377ba4c98a34022078463df67b3103b868c41bbe3fc11d1cd9f1ee2fc1ecfa9c8f0adb9d013dd9bf01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";

fn decodeTx(a: std.mem.Allocator, hex: []const u8) !types.Transaction {
    const bytes = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(bytes, hex);
    var r = serialize.Reader{ .data = bytes };
    return serialize.readTransaction(&r, a);
}

/// Chain state whose UTXO set holds `TX`'s input (spendable) when `with_input`.
fn chainWith(a: std.mem.Allocator, with_input: bool) !*storage.ChainState {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const tx = try decodeTx(a, TX);
    const spk = [_]u8{ 0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 };
    if (with_input) {
        const out = types.TxOut{ .value = 5_000_000_000, .script_pubkey = &spk };
        try cs.utxo_set.add(&tx.inputs[0].previous_output, &out, 799_000, false);
    }
    return cs;
}

fn newServer(a: std.mem.Allocator, cs: *storage.ChainState) !*rpc.RpcServer {
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});
    return srv;
}

fn submit(a: std.mem.Allocator, srv: *rpc.RpcServer) !std.json.Parsed(std.json.Value) {
    const resp = try srv.dispatch("{\"id\":1,\"method\":\"submitpackage\",\"params\":[[\"" ++ TX ++ "\"]]}");
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

test "tests_submitpackage_shape accepted tx has package_msg success and Core per-tx fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const srv = try newServer(a, try chainWith(a, true));
    const p = try submit(a, srv);
    const res = p.value.object.get("result").?.object;
    try testing.expectEqualStrings("success", res.get("package_msg").?.string);
    try testing.expect(res.get("package_feerate") == null);
    try testing.expect(res.get("replaced-transactions") != null);
    var it = res.get("tx-results").?.object.iterator();
    const entry = it.next().?;
    const row = entry.value_ptr.*.object;
    // Not vacuous: the input coin exists, so the tx was accepted.
    try testing.expect(row.get("txid") != null);
    try testing.expect(row.get("allowed") == null);
    const vsize = row.get("vsize").?.integer;
    const fees = row.get("fees").?.object;
    try testing.expectApproxEqAbs(@as(f64, 0.0001), fees.get("base").?.float, 1e-12);
    // Core: CFeeRate(fee, vsize).GetFeePerK() = floor(fee*1000/vsize) sat/kvB, in BTC.
    const per_k: f64 = @floatFromInt(@divTrunc(@as(i64, 10_000) * 1000, vsize));
    try testing.expectApproxEqAbs(per_k / 1e8, fees.get("effective-feerate").?.float, 1e-12);
    const inc = fees.get("effective-includes").?.array.items;
    try testing.expectEqual(@as(usize, 1), inc.len);
    try testing.expectEqualStrings(entry.key_ptr.*, inc[0].string);
}

test "tests_submitpackage_shape tx already in the pool gets vsize and fees.base only" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const srv = try newServer(a, try chainWith(a, true));
    _ = try submit(a, srv);
    const p = try submit(a, srv);
    const res = p.value.object.get("result").?.object;
    try testing.expectEqualStrings("success", res.get("package_msg").?.string);
    var it = res.get("tx-results").?.object.iterator();
    const row = it.next().?.value_ptr.*.object;
    try testing.expect(row.get("allowed") == null);
    try testing.expect(row.get("vsize") != null);
    const fees = row.get("fees").?.object;
    try testing.expect(fees.get("base") != null);
    try testing.expect(fees.get("effective-feerate") == null);
    try testing.expect(fees.get("effective-includes") == null);
}

test "tests_submitpackage_shape failed tx has package_msg transaction failed and a string error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const srv = try newServer(a, try chainWith(a, false)); // input coin missing
    const p = try submit(a, srv);
    const res = p.value.object.get("result").?.object;
    try testing.expectEqualStrings("transaction failed", res.get("package_msg").?.string);
    try testing.expect(res.get("package_feerate") == null);
    var it = res.get("tx-results").?.object.iterator();
    const row = it.next().?.value_ptr.*.object;
    try testing.expect(row.get("allowed") == null);
    try testing.expect(row.get("error").?.string.len > 0);
    try testing.expect(row.get("fees") == null);
}

const P2WPKH: []const u8 = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;

fn mkTx(a: std.mem.Allocator, prev: types.Hash256, value: i64, lock_time: u32) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = .{ .hash = prev, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = value, .script_pubkey = P2WPKH };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = lock_time };
}

fn body0() !void {
    // Core AcceptPackage: a tx that passes alone keeps its own feerate and
    // effective-includes; a below-minimum parent and the child that depends
    // on it are evaluated together (CPFP) and share one feerate.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const funding = try mkTx(allocator, [_]u8{0x88} ** 32, 10_000_000, 0);
    try mempool.addTransaction(funding);
    const funding_txid = try crypto.computeTxid(&funding, allocator);

    const parent = try mkTx(allocator, funding_txid, 9_999_999, 1); // fee 1 sat: below relay minimum
    const parent_txid = try crypto.computeTxid(&parent, allocator);
    const child = try mkTx(allocator, parent_txid, 9_980_000, 2); // fee 19_999 sat
    const pkg: []const types.Transaction = &[_]types.Transaction{ parent, child };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();
    try testing.expect(result.package_accepted);
    try testing.expectEqual(@as(i64, 1), result.tx_results[0].fee);
    try testing.expectEqual(@as(i64, 19_999), result.tx_results[1].fee);
    try testing.expect(result.tx_results[0].vsize > 0);
    try testing.expect(result.tx_results[0].package_eval);
    try testing.expect(result.tx_results[1].package_eval); // joins its parent
    try testing.expect(!result.tx_results[0].was_in_mempool);
}

test "tests_submitpackage_shape package_eval groups the sub-minimum parent with its child, not a self-sufficient tx" {
    if (comptime !@hasField(mempool_mod.PackageTxResult, "package_eval")) return error.PackageTxResultLacksPackageEval;
    try body0();
}

fn body1() !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const funding = try mkTx(allocator, [_]u8{0x88} ** 32, 10_000_000, 0);
    try mempool.addTransaction(funding);
    const funding_txid = try crypto.computeTxid(&funding, allocator);
    const parent = try mkTx(allocator, funding_txid, 9_990_000, 1); // fee 10_000
    const parent_txid = try crypto.computeTxid(&parent, allocator);
    const child = try mkTx(allocator, parent_txid, 9_980_000, 2); // fee 10_000
    const pkg: []const types.Transaction = &[_]types.Transaction{ parent, child };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();
    try testing.expect(result.package_accepted);
    try testing.expect(!result.tx_results[0].package_eval);
    try testing.expect(!result.tx_results[1].package_eval);
}

test "tests_submitpackage_shape a package of two self-sufficient txs is not grouped" {
    if (comptime !@hasField(mempool_mod.PackageTxResult, "package_eval")) return error.PackageTxResultLacksPackageEval;
    try body1();
}
