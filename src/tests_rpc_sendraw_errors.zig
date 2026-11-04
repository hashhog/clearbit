//! sendrawtransaction error code/message parity with Bitcoin Core v31.1.
//! Run via `zig build test-sendraw-errors`.
//!
//! Ratchet rows (operator/sendrawtransaction/*): not-hex:message,
//! bad-maxfeerate:code+message, missing-inputs:code+message,
//! confirmed:message. Core: DecodeHexTx failure is -22 "TX decode failed.
//! Make sure the tx has at least one input."; maxfeerate goes through
//! AmountFromValue (-3 "Invalid amount"); MISSING_INPUTS is -25
//! "bad-txns-inputs-missingorspent"; already-confirmed is -27
//! "Transaction outputs already in utxo set".

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");

const TX = "020000000001018ad2bbf537bbf9ed2bed6cd4b4e5e032e2fd239df5884c14c2d2b5e9a9be0e800000000000fdffffff01f0ca052a01000000160014751e76e8199196d454941c45d1b3a323f1433bd602473044022021e92e30619a66ea56ba3e4aea655d8088f0e537eafa938ccb0e377ba4c98a34022078463df67b3103b868c41bbe3fc11d1cd9f1ee2fc1ecfa9c8f0adb9d013dd9bf01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";
const DECODE_MSG = "TX decode failed. Make sure the tx has at least one input.";

fn call(a: std.mem.Allocator, params_json: []const u8) !std.json.Parsed(std.json.Value) {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.MAINNET, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.MAINNET);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.MAINNET, .{});
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":{s}}}", .{params_json});
    const resp = try srv.dispatch(req);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

fn expectErr(p: std.json.Parsed(std.json.Value), code: i64, msg: []const u8) !void {
    const e = p.value.object.get("error") orelse return error.NoError;
    try testing.expect(e == .object);
    try testing.expectEqual(code, e.object.get("code").?.integer);
    try testing.expectEqualStrings(msg, e.object.get("message").?.string);
}

test "tests_sendraw_errors non-hex string is -22 decode failed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try expectErr(try call(arena.allocator(), "[\"zz\"]"), -22, DECODE_MSG);
}

test "tests_sendraw_errors odd-length hex is -22 decode failed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try expectErr(try call(arena.allocator(), "[\"abc\"]"), -22, DECODE_MSG);
}

test "tests_sendraw_errors bad maxfeerate string is -3 Invalid amount" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try expectErr(try call(arena.allocator(), "[\"" ++ TX ++ "\",\"abc\"]"), -3, "Invalid amount");
}

test "tests_sendraw_errors missing inputs is -25 bad-txns-inputs-missingorspent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try expectErr(try call(arena.allocator(), "[\"" ++ TX ++ "\"]"), -25, "bad-txns-inputs-missingorspent");
}

test "tests_sendraw_errors control: valid maxfeerate number is not -3" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "[\"" ++ TX ++ "\",0.1]");
    const e = p.value.object.get("error") orelse return;
    try testing.expect(e == .object);
    try testing.expect(e.object.get("code").?.integer != -3);
}
