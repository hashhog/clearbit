//! R5 "accepts input Core rejects" class — rejection tests per method.
//!
//! Encodes the seven `tools/r5_probe.py` probes whose FAIL is
//! `expected error, call succeeded` (artifact 20260917T053617Z):
//!   T1 getnetworkhashps type-error
//!   T1 getblocktemplate missing-segwit-rule
//!   T1 testmempoolaccept decode-error
//!   T2 combinerawtransaction unknown-input
//!   T2 deriveaddresses missing-checksum / range-on-unranged
//!   T2 getindexinfo wrong-type-arg
//!   T2 signrawtransactionwithkey bad-privkey
//!
//! CONTROL: `zig build test-r5-accepts-invalid --summary new`
//! Filter `r5_accepts_invalid` so imported rpc/peer/wallet tests do not run.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");

fn r5Server(
    allocator: std.mem.Allocator,
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    peer_manager: *peer_mod.PeerManager,
) rpc.RpcServer {
    return rpc.RpcServer.init(
        allocator,
        chain_state,
        mempool,
        peer_manager,
        &consensus.MAINNET,
        .{},
    );
}

fn r5Dispatch(
    allocator: std.mem.Allocator,
    method: []const u8,
    params: []const u8,
) ![]const u8 {
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();
    var server = r5Server(allocator, &chain_state, &mempool, &peer_manager);
    defer server.deinit();

    const req = try std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"{s}\",\"params\":{s}}}",
        .{ method, params },
    );
    defer allocator.free(req);
    return server.dispatch(req);
}

fn r5ErrCode(body: []const u8) !i32 {
    const key = "\"code\":";
    const at = std.mem.indexOf(u8, body, key) orelse return error.TestUnexpectedResult;
    var i = at + key.len;
    while (i < body.len and (body[i] == ' ')) i += 1;
    const start = i;
    if (i < body.len and body[i] == '-') i += 1;
    while (i < body.len and body[i] >= '0' and body[i] <= '9') i += 1;
    return std.fmt.parseInt(i32, body[start..i], 10);
}

fn r5ExpectError(
    method: []const u8,
    params: []const u8,
    want_code: i32,
    want_msg: []const u8,
) !void {
    const allocator = testing.allocator;
    const result = try r5Dispatch(allocator, method, params);
    defer allocator.free(result);
    try testing.expectEqual(want_code, try r5ErrCode(result));
    try testing.expect(std.mem.indexOf(u8, result, want_msg) != null);
}

// Probe hex: unsigned 1-in/1-out spending all-0xaa prevout (unknown-input /
// signrawtransactionwithkey bad-privkey).
const UNKNOWN_TX_HEX =
    "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000";

const UNRANGED_WPKh_NO_CS =
    "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)";
const UNRANGED_WPKh_CS =
    "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#e72f49hy";

// ---------------------------------------------------------------------------
// T1 — already rejected in HEAD (61caa89); keep them in this class control.
// ---------------------------------------------------------------------------

test "r5_accepts_invalid getnetworkhashps type-error is RPC_TYPE_ERROR -3" {
    try r5ExpectError(
        "getnetworkhashps",
        "[\"foo\"]",
        rpc.RPC_TYPE_ERROR,
        "JSON value of type string is not of expected type number",
    );
}

test "r5_accepts_invalid getblocktemplate missing-segwit-rule is RPC_INVALID_PARAMETER -8" {
    try r5ExpectError(
        "getblocktemplate",
        "[{}]",
        rpc.RPC_INVALID_PARAMETER,
        "getblocktemplate must be called with the segwit rule set",
    );
}

test "r5_accepts_invalid testmempoolaccept decode-error is RPC_DESERIALIZATION_ERROR -22" {
    try r5ExpectError(
        "testmempoolaccept",
        "[[\"deadbeef\"]]",
        rpc.RPC_DESERIALIZATION_ERROR,
        "TX decode failed",
    );
}

// ---------------------------------------------------------------------------
// T2 — currently accepted; must match Core's reject.
// ---------------------------------------------------------------------------

test "r5_accepts_invalid combinerawtransaction unknown-input is RPC_VERIFY_ERROR -25" {
    const allocator = testing.allocator;
    const params = try std.fmt.allocPrint(
        allocator,
        "[[\"{s}\",\"{s}\"]]",
        .{ UNKNOWN_TX_HEX, UNKNOWN_TX_HEX },
    );
    defer allocator.free(params);
    try r5ExpectError(
        "combinerawtransaction",
        params,
        rpc.RPC_VERIFY_ERROR,
        "Input not found or already spent",
    );
}

test "r5_accepts_invalid deriveaddresses missing-checksum is RPC_INVALID_ADDRESS_OR_KEY -5" {
    const allocator = testing.allocator;
    const params = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{UNRANGED_WPKh_NO_CS});
    defer allocator.free(params);
    try r5ExpectError(
        "deriveaddresses",
        params,
        rpc.RPC_INVALID_ADDRESS_OR_KEY,
        "Missing checksum",
    );
}

test "r5_accepts_invalid deriveaddresses range-on-unranged is RPC_INVALID_PARAMETER -8" {
    const allocator = testing.allocator;
    const params = try std.fmt.allocPrint(
        allocator,
        "[\"{s}\",[0,2]]",
        .{UNRANGED_WPKh_CS},
    );
    defer allocator.free(params);
    try r5ExpectError(
        "deriveaddresses",
        params,
        rpc.RPC_INVALID_PARAMETER,
        "Range should not be specified for an un-ranged descriptor",
    );
}

test "r5_accepts_invalid getindexinfo wrong-type-arg is RPC_TYPE_ERROR -3" {
    try r5ExpectError(
        "getindexinfo",
        "[123]",
        rpc.RPC_TYPE_ERROR,
        "JSON value of type number is not of expected type string",
    );
}

test "r5_accepts_invalid signrawtransactionwithkey bad-privkey is RPC_INVALID_ADDRESS_OR_KEY -5" {
    const allocator = testing.allocator;
    const params = try std.fmt.allocPrint(
        allocator,
        "[\"{s}\",[\"notakey\"]]",
        .{UNKNOWN_TX_HEX},
    );
    defer allocator.free(params);
    try r5ExpectError(
        "signrawtransactionwithkey",
        params,
        rpc.RPC_INVALID_ADDRESS_OR_KEY,
        "Invalid private key",
    );
}

// Regression: the checksummed unranged descriptor must still derive, not
// trip the new require-checksum / range gates.
test "r5_accepts_invalid deriveaddresses checksummed unranged still derives" {
    const allocator = testing.allocator;
    const params = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{UNRANGED_WPKh_CS});
    defer allocator.free(params);
    const result = try r5Dispatch(allocator, "deriveaddresses", params);
    defer allocator.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "\"error\":null") != null or
        std.mem.indexOf(u8, result, "\"error\": null") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\"code\":") == null);
}

test "r5_accepts_invalid getindexinfo no-arg still succeeds" {
    const allocator = testing.allocator;
    const result = try r5Dispatch(allocator, "getindexinfo", "[]");
    defer allocator.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "\"code\":") == null);
}
