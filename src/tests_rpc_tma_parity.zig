//! testmempoolaccept parity with Core v31.1 (rpc/mempool.cpp).
//!
//! Run via `zig build test-tma-parity`.
//!
//! Ratchet rows (operator/testmempoolaccept/*):
//!   empty-array:code          Core -8 (RPC_INVALID_PARAMETER), node was -32602
//!   not-an-array:code/message Core -3 "Wrong type passed:" (central type check)
//!   valid:[0].fees.effective-feerate / effective-includes  were missing
//!   *:[0].reject-details      was missing on every reject but missing-inputs

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

// 1-in/1-out segwit tx from the ratchet row (valid serialization).
const TX = "020000000001018ad2bbf537bbf9ed2bed6cd4b4e5e032e2fd239df5884c14c2d2b5e9a9be0e800000000000fdffffff01f0ca052a01000000160014751e76e8199196d454941c45d1b3a323f1433bd602473044022021e92e30619a66ea56ba3e4aea655d8088f0e537eafa938ccb0e377ba4c98a34022078463df67b3103b868c41bbe3fc11d1cd9f1ee2fc1ecfa9c8f0adb9d013dd9bf01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";

/// `cs` may carry coins; null builds an empty chain state.
fn callWith(a: std.mem.Allocator, cs_in: ?*storage.ChainState, params_json: []const u8) !std.json.Parsed(std.json.Value) {
    const cs = cs_in orelse blk: {
        const c = try a.create(storage.ChainState);
        c.* = storage.ChainState.init(null, 64, a);
        break :blk c;
    };
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":{s}}}", .{params_json});
    const resp = try srv.dispatch(req);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

fn call(a: std.mem.Allocator, params_json: []const u8) !std.json.Parsed(std.json.Value) {
    return callWith(a, null, params_json);
}

fn decodeTx(a: std.mem.Allocator, hex: []const u8) !types.Transaction {
    const bytes = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(bytes, hex);
    var r = serialize.Reader{ .data = bytes };
    return serialize.readTransaction(&r, a);
}

/// Chain state whose UTXO set holds `TX`'s input (spendable) when `with_input`,
/// and `TX`'s own output 0 when `with_output` (i.e. TX is already confirmed).
fn chainWith(a: std.mem.Allocator, with_input: bool, with_output: bool) !*storage.ChainState {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const tx = try decodeTx(a, TX);
    const spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x75} ** 20;
    if (with_input) {
        const out = types.TxOut{ .value = 5_000_000_000, .script_pubkey = &spk };
        try cs.utxo_set.add(&tx.inputs[0].previous_output, &out, 799_000, false);
    }
    if (with_output) {
        const txid = try crypto.computeTxid(&tx, a);
        const op = types.OutPoint{ .hash = txid, .index = 0 };
        try cs.utxo_set.add(&op, &tx.outputs[0], 799_500, false);
    }
    return cs;
}

test "tests_tma_parity empty array is -8 with Core's message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "[[]]");
    const e = p.value.object.get("error").?.object;
    try testing.expectEqual(@as(i64, -8), e.get("code").?.integer);
    try testing.expectEqualStrings("Array must contain between 1 and 25 transactions.", e.get("message").?.string);
}

test "tests_tma_parity non-array rawtxs is -3 Wrong type passed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "[\"" ++ TX ++ "\"]");
    const e = p.value.object.get("error").?.object;
    try testing.expectEqual(@as(i64, -3), e.get("code").?.integer);
    try testing.expectEqualStrings(
        "Wrong type passed:\n{\n    \"Position 1 (rawtxs)\": \"JSON value of type string is not of expected type array\"\n}",
        e.get("message").?.string,
    );
}

test "tests_tma_parity an allowed tx reports effective-feerate and effective-includes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try chainWith(a, true, false);
    const p = try callWith(a, cs, "[[\"" ++ TX ++ "\"]]");
    const row = p.value.object.get("result").?.array.items[0].object;
    // Not vacuous: the input coin exists, so the tx must be allowed.
    try testing.expect(row.get("allowed").?.bool);
    const fees = row.get("fees").?.object;
    try testing.expect(fees.get("effective-feerate") != null);
    try testing.expect(fees.get("effective-includes") != null);
    // fee 10_000 sat; Core's CFeeRate floors fee*1000/vsize (sat/kvB), shown in BTC/kvB.
    const vsize: i64 = row.get("vsize").?.integer;
    const per_k: f64 = @floatFromInt(@divTrunc(@as(i64, 10_000) * 1000, vsize));
    try testing.expectApproxEqAbs(per_k / 1e8, fees.get("effective-feerate").?.float, 1e-12);
    const inc = fees.get("effective-includes").?.array.items;
    try testing.expectEqual(@as(usize, 1), inc.len);
    try testing.expectEqualStrings(row.get("wtxid").?.string, inc[0].string);
}

test "tests_tma_parity a standard tx whose outputs are already coins is txn-already-known" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Input spent (absent), output present: Core PreChecks "Are inputs missing
    // because we already have the tx?" -> txn-already-known (+ details).
    const cs = try chainWith(a, false, true);
    const p = try callWith(a, cs, "[[\"" ++ TX ++ "\"]]");
    const row = p.value.object.get("result").?.array.items[0].object;
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("txn-already-known", row.get("reject-reason").?.string);
    try testing.expect(row.get("reject-details") != null);
    try testing.expectEqualStrings("txn-already-known", row.get("reject-details").?.string);
}

test "tests_tma_parity missing inputs without a known output stays missing-inputs with no details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try chainWith(a, false, false);
    const p = try callWith(a, cs, "[[\"" ++ TX ++ "\"]]");
    const row = p.value.object.get("result").?.array.items[0].object;
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("missing-inputs", row.get("reject-reason").?.string);
    try testing.expect(row.get("reject-details") == null);
}

test "tests_tma_parity standardness is checked before txn-already-known" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Version 5 is non-standard.  Core runs IsStandardTx before the
    // missing-inputs / already-known probe, so even with the tx's output
    // present the answer is "version", with reject-details equal to it.
    const v5 = "05" ++ TX[2..];
    const tx5 = try decodeTx(a, v5);
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    const txid = try crypto.computeTxid(&tx5, a);
    const op = types.OutPoint{ .hash = txid, .index = 0 };
    try cs.utxo_set.add(&op, &tx5.outputs[0], 799_500, false);
    const p = try callWith(a, cs, "[[\"" ++ v5 ++ "\"]]");
    const row = p.value.object.get("result").?.array.items[0].object;
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("version", row.get("reject-reason").?.string);
    try testing.expectEqualStrings("version", row.get("reject-details").?.string);
}

fn hexOf(a: std.mem.Allocator, tx: *const types.Transaction) ![]u8 {
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, tx);
    const bytes = try w.toOwnedSlice();
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(bytes)});
}

// Core rpc/mempool.cpp testmempoolaccept: every allowed tx of a package carries
// fees{base, effective-feerate, effective-includes}.  Rows (package/accept/
// parent-child:[0|1].fees.*): base was a hard 0.0 and the other two were absent.
test "tests_tma_parity package members report base fee and effective-* fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Signature-free fixture: every output is P2WSH(OP_TRUE) (a standard
    // prevout), spent with witness [OP_TRUE].
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const coin_op = types.OutPoint{ .hash = [_]u8{0xAB} ** 32, .index = 0 };
    const op_true = [_]u8{0x51};
    const wsh_hash = crypto.sha256(&op_true);
    const wsh_spk = [_]u8{ 0x00, 0x20 } ++ wsh_hash;
    const coin = types.TxOut{ .value = 1_000_000, .script_pubkey = &wsh_spk };
    try cs.utxo_set.add(&coin_op, &coin, 799_000, false);
    const wit = [_][]const u8{&op_true};
    const wpkh_spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x75} ** 20;
    const parent = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = coin_op,
            .script_sig = &[_]u8{},
            .sequence = 0xFFFF_FFFD,
            .witness = &wit,
        }},
        .outputs = &[_]types.TxOut{.{ .value = 990_000, .script_pubkey = &wsh_spk }},
        .lock_time = 0,
    };
    const ptxid = try crypto.computeTxid(&parent, a);
    const child = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = .{ .hash = ptxid, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFF_FFFD,
            .witness = &wit,
        }},
        .outputs = &[_]types.TxOut{.{ .value = 980_000, .script_pubkey = &wpkh_spk }},
        .lock_time = 0,
    };
    const params = try std.fmt.allocPrint(a, "[[\"{s}\",\"{s}\"]]", .{ try hexOf(a, &parent), try hexOf(a, &child) });
    const p = try callWith(a, cs, params);
    const rows = (p.value.object.get("result") orelse return error.TestUnexpectedResult).array.items;
    try testing.expectEqual(@as(usize, 2), rows.len);
    for (rows) |r| {
        const row = r.object;
        // Not vacuous: both members must be allowed for fees to be emitted.
        try testing.expect(row.get("allowed").?.bool);
        const fees = row.get("fees").?.object;
        try testing.expectApproxEqAbs(@as(f64, 0.0001), fees.get("base").?.float, 1e-12);
        const vsize: i64 = row.get("vsize").?.integer;
        const per_k: f64 = @floatFromInt(@divTrunc(@as(i64, 10_000) * 1000, vsize));
        try testing.expectApproxEqAbs(per_k / 1e8, fees.get("effective-feerate").?.float, 1e-12);
        const inc = fees.get("effective-includes").?.array.items;
        try testing.expectEqual(@as(usize, 1), inc.len);
        try testing.expectEqualStrings(row.get("wtxid").?.string, inc[0].string);
    }
}
