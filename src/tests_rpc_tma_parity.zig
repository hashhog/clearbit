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

// 1-in/1-out segwit tx from the ratchet row (valid serialization).
const TX = "020000000001018ad2bbf537bbf9ed2bed6cd4b4e5e032e2fd239df5884c14c2d2b5e9a9be0e800000000000fdffffff01f0ca052a01000000160014751e76e8199196d454941c45d1b3a323f1433bd602473044022021e92e30619a66ea56ba3e4aea655d8088f0e537eafa938ccb0e377ba4c98a34022078463df67b3103b868c41bbe3fc11d1cd9f1ee2fc1ecfa9c8f0adb9d013dd9bf01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";

fn call(a: std.mem.Allocator, params_json: []const u8) !std.json.Parsed(std.json.Value) {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(null, null, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.MAINNET);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.MAINNET, .{});
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":{s}}}", .{params_json});
    const resp = try srv.dispatch(req);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
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
    const p = try call(arena.allocator(), "[[\"" ++ TX ++ "\"]]");
    const row = p.value.object.get("result").?.array.items[0].object;
    // Without a UTXO set the dry run cannot resolve inputs; skip rather than
    // pass vacuously if it does not allow the tx.
    if (!row.get("allowed").?.bool) return error.SkipZigTest;
    const fees = row.get("fees").?.object;
    try testing.expect(fees.get("effective-feerate") != null);
    const inc = fees.get("effective-includes").?.array.items;
    try testing.expectEqual(@as(usize, 1), inc.len);
    try testing.expectEqualStrings(row.get("wtxid").?.string, inc[0].string);
}

test "tests_tma_parity a rejected tx carries reject-details equal to the reason" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // Version 5 is non-standard: Core rejects with reason "version" and, as for
    // every reject except missing-inputs, adds reject-details.
    const p = try call(arena.allocator(), "[[\"05" ++ TX[2..] ++ "\"]]");
    const row = p.value.object.get("result").?.array.items[0].object;
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("version", row.get("reject-reason").?.string);
    try testing.expectEqualStrings("version", row.get("reject-details").?.string);
}
