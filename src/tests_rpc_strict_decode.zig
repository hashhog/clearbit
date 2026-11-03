//! Strict-input parity: calls Core rejects that clearbit used to accept.
//!
//! Run via `zig build test-strict-decode`.
//!
//! The Core regtest ratchet reports these as `node_error` rows (one side an
//! RPC error, the other a success):
//!   operator/getblockheader/bad-verbose        getblockheader <hash> "x"
//!   operator/sendrawtransaction/trailing       raw tx + one trailing byte
//!   operator/testmempoolaccept/trailing        raw tx + one trailing byte
//!
//! Core: RPCHelpMan::HandleRequest type-checks `verbose` as BOOL (-3 "Wrong
//! type passed"), and DecodeHexTx (core_read.cpp) requires the whole buffer
//! be consumed, else -22 "TX decode failed".

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");

const GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
// 1-in/1-out segwit tx from the ratchet row (valid serialization).
const TX = "020000000001018ad2bbf537bbf9ed2bed6cd4b4e5e032e2fd239df5884c14c2d2b5e9a9be0e800000000000fdffffff01f0ca052a01000000160014751e76e8199196d454941c45d1b3a323f1433bd602473044022021e92e30619a66ea56ba3e4aea655d8088f0e537eafa938ccb0e377ba4c98a34022078463df67b3103b868c41bbe3fc11d1cd9f1ee2fc1ecfa9c8f0adb9d013dd9bf01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";

/// Everything allocates from the caller's arena: the accept path of the
/// handlers under test keeps tx memory by design (mempool owns it), which the
/// leak-checking testing allocator would flag as a failure unrelated to this item.
fn call(a: std.mem.Allocator, method: []const u8, params_json: []const u8) !std.json.Parsed(std.json.Value) {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(null, null, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.MAINNET);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.MAINNET, .{});
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
    const resp = try srv.dispatch(req);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

fn errCode(p: std.json.Parsed(std.json.Value)) ?i64 {
    const e = p.value.object.get("error") orelse return null;
    if (e != .object) return null;
    return e.object.get("code").?.integer;
}

test "tests_strict_decode getblockheader verbose string is -3" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "getblockheader", "[\"" ++ GENESIS ++ "\",\"x\"]");
    try testing.expectEqual(@as(?i64, -3), errCode(p));
}

test "tests_strict_decode getblockheader verbose bool control still answers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "getblockheader", "[\"" ++ GENESIS ++ "\",false]");
    try testing.expectEqual(@as(?i64, null), errCode(p));
}

test "tests_strict_decode sendrawtransaction trailing byte is -22" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "sendrawtransaction", "[\"" ++ TX ++ "00\"]");
    try testing.expectEqual(@as(?i64, -22), errCode(p));
}

test "tests_strict_decode testmempoolaccept trailing byte is -22" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "testmempoolaccept", "[[\"" ++ TX ++ "00\"]]");
    try testing.expectEqual(@as(?i64, -22), errCode(p));
}

test "tests_strict_decode testmempoolaccept exact tx control is not a decode error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "testmempoolaccept", "[[\"" ++ TX ++ "\"]]");
    try testing.expectEqual(@as(?i64, null), errCode(p));
}

test "tests_strict_decode sendrawtransaction exact tx control is not a decode error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try call(arena.allocator(), "sendrawtransaction", "[\"" ++ TX ++ "\"]");
    try testing.expect(errCode(p) != @as(?i64, -22));
}
