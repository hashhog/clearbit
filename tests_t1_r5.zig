//! T1 R5 probe parity + deferred 1.0.1 min-chainwork / checkpoint controls.
//!
//! Encodes the remaining T1 FAILs from the 2026-09-01 `tools/r5_probe.py`
//! sweep (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`) plus
//! the two deferred-from-1.0.1 production-path gaps:
//!   * min-chainwork gate skipped for every node past an assumeUTXO height
//!   * `verifyCheckpoint` had no production caller
//!
//! CONTROL: `zig build test-t1-r5 --summary new`
//! Rooted at the project root so `src/wallet.zig`'s `@embedFile` resolves
//! (same layout as tests_rpc.zig). Filter `t1_r5` so imported modules' tests
//! do not run.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const validation = @import("src/validation.zig");
const types = @import("src/types.zig");
const crypto = @import("src/crypto.zig");

fn t1Server(
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

fn t1Dispatch(
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
    var server = t1Server(allocator, &chain_state, &mempool, &peer_manager);
    defer server.deinit();

    const req = try std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"{s}\",\"params\":{s}}}",
        .{ method, params },
    );
    defer allocator.free(req);
    return server.dispatch(req);
}

fn t1ErrCode(body: []const u8) !i32 {
    const key = "\"code\":";
    const at = std.mem.indexOf(u8, body, key) orelse return error.TestUnexpectedResult;
    var i = at + key.len;
    while (i < body.len and (body[i] == ' ')) i += 1;
    const start = i;
    if (i < body.len and body[i] == '-') i += 1;
    while (i < body.len and body[i] >= '0' and body[i] <= '9') i += 1;
    return std.fmt.parseInt(i32, body[start..i], 10);
}

// ===========================================================================
// T1 probe FAILs (r5-probes.d)
// ===========================================================================

test "t1_r5 gettxoutsetinfo bad-hashtype is RPC_INVALID_PARAMETER -8" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "gettxoutsetinfo", "[\"bogus\"]");
    defer allocator.free(result);
    try testing.expectEqual(@as(i32, -8), try t1ErrCode(result));
    try testing.expect(std.mem.indexOf(u8, result, "'bogus' is not a valid hash_type") != null);
}

test "t1_r5 addnode invalid-command is RPC_MISC_ERROR -1" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "addnode", "[\"192.0.2.1:8333\",\"notacommand\"]");
    defer allocator.free(result);
    try testing.expectEqual(@as(i32, -1), try t1ErrCode(result));
    try testing.expect(std.mem.indexOf(u8, result, "addnode ") != null);
}

test "t1_r5 clearbanned is listed in help" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "help", "[]");
    defer allocator.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "clearbanned") != null);
}

test "t1_r5 getnetworkhashps type-error is RPC_TYPE_ERROR -3" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "getnetworkhashps", "[\"foo\"]");
    defer allocator.free(result);
    try testing.expectEqual(@as(i32, -3), try t1ErrCode(result));
    try testing.expect(std.mem.indexOf(u8, result, "JSON value of type string is not of expected type number") != null);
}

test "t1_r5 getnetworkhashps nblocks 0 is RPC_INVALID_PARAMETER -8" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "getnetworkhashps", "[0]");
    defer allocator.free(result);
    try testing.expectEqual(@as(i32, -8), try t1ErrCode(result));
    try testing.expect(std.mem.indexOf(u8, result, "Invalid nblocks") != null);
}

test "t1_r5 getnetworkhashps height above tip is RPC_INVALID_PARAMETER -8" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "getnetworkhashps", "[120, 999]");
    defer allocator.free(result);
    try testing.expectEqual(@as(i32, -8), try t1ErrCode(result));
    try testing.expect(std.mem.indexOf(u8, result, "Block does not exist at specified height") != null);
}

test "t1_r5 getblocktemplate missing-segwit-rule is RPC_INVALID_PARAMETER -8" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "getblocktemplate", "[{}]");
    defer allocator.free(result);
    try testing.expectEqual(@as(i32, -8), try t1ErrCode(result));
    try testing.expect(std.mem.indexOf(
        u8,
        result,
        "getblocktemplate must be called with the segwit rule set",
    ) != null);
}

test "t1_r5 getblocktemplate with segwit rule is not the missing-segwit error" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "getblocktemplate", "[{\"rules\":[\"segwit\"]}]");
    defer allocator.free(result);
    if (std.mem.indexOf(u8, result, "\"code\":-8") != null) {
        try testing.expect(std.mem.indexOf(u8, result, "segwit rule set") == null);
    }
}

test "t1_r5 testmempoolaccept decode-error is RPC_DESERIALIZATION_ERROR -22" {
    const allocator = testing.allocator;
    const result = try t1Dispatch(allocator, "testmempoolaccept", "[[\"deadbeef\"]]");
    defer allocator.free(result);
    try testing.expectEqual(@as(i32, -22), try t1ErrCode(result));
    try testing.expect(std.mem.indexOf(u8, result, "TX decode failed") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\"allowed\":false") == null);
}

// ===========================================================================
// Deferred 1.0.1: min-chainwork gate skip + verifyCheckpoint production caller
// ===========================================================================

test "t1_r5 min-chainwork gate is not skipped merely for being past assumeutxo" {
    // A mainnet node at tip is past every assumeUTXO height. Skipping the
    // anti-DoS gate on that predicate disabled it for every live node.
    // Skip only when parent chainwork is the synthetic active-tip fallback.
    const src = @embedFile("src/peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "past_snapshot_base") == null);
    try testing.expect(std.mem.indexOf(u8, src, "shouldSkipMinChainWorkGate") != null);
    try testing.expect(std.mem.indexOf(u8, src, "minChainWorkBE") != null);
}

test "t1_r5 verifyCheckpoint is called from insertHeader" {
    const src = @embedFile("src/peer.zig");
    const start = std.mem.indexOf(u8, src, "pub fn insertHeader(") orelse
        return error.TestUnexpectedResult;
    const body = src[start..@min(start + 2500, src.len)];
    try testing.expect(std.mem.indexOf(u8, body, "verifyCheckpoint") != null);
}

test "t1_r5 verifyCheckpoint is called from validateBlockForIBD" {
    const src = @embedFile("src/validation.zig");
    const start = std.mem.indexOf(u8, src, "pub fn validateBlockForIBD(") orelse
        return error.TestUnexpectedResult;
    const body = src[start..@min(start + 4000, src.len)];
    try testing.expect(std.mem.indexOf(u8, body, "verifyCheckpoint") != null);
}

test "t1_r5 shouldSkipMinChainWorkGate only when parent work is synthetic" {
    try testing.expect(!peer_mod.shouldSkipMinChainWorkGate(true, false));
    try testing.expect(!peer_mod.shouldSkipMinChainWorkGate(true, true));
    try testing.expect(!peer_mod.shouldSkipMinChainWorkGate(false, false));
    try testing.expect(peer_mod.shouldSkipMinChainWorkGate(false, true));
}

test "t1_r5 insertHeader rejects a checkpoint-mismatch at height 11111" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    var parent_hdr = std.mem.zeroes(types.BlockHeader);
    parent_hdr.bits = 0x1d00ffff;
    const parent_hash = [_]u8{0x11} ** 32;
    try pm.header_index.put(parent_hash, .{
        .hash = parent_hash,
        .prev_hash = [_]u8{0} ** 32,
        .height = 11110,
        .chain_work = [_]u8{0} ** 32,
        .timestamp = 1,
        .header = parent_hdr,
        .last_seen = 1,
    });

    var fake = std.mem.zeroes(types.BlockHeader);
    fake.prev_block = parent_hash;
    fake.bits = 0x1d00ffff;
    fake.nonce = 1;
    const fake_hash = crypto.computeBlockHash(&fake);
    try testing.expectError(error.CheckpointMismatch, pm.insertHeader(&fake, &fake_hash));
}

test "t1_r5 G19d unrequested low chainwork is TooLittleChainwork" {
    const allocator = testing.allocator;
    var fake = std.mem.zeroes(types.BlockHeader);
    fake.bits = 0x1d00ffff;
    const block_hash = crypto.computeBlockHash(&fake);
    const block = types.Block{ .header = fake, .transactions = &.{} };
    var dummy: u8 = 0;
    var low_work = [_]u8{0} ** 32;
    low_work[31] = 1;
    const ctx = validation.IBDValidationContext{
        .block_hash = block_hash,
        .height = 1,
        .params = &consensus.MAINNET,
        .prevout_lookup_ctx = @ptrCast(&dummy),
        .prevout_lookupFn = struct {
            fn lookup(_: *anyopaque, _: *const types.OutPoint) ?validation.PrevOutInfo {
                return null;
            }
        }.lookup,
        .active_chain = null,
        .best_tip_chain_work = [_]u8{0} ** 32,
        .best_tip_timestamp = 0,
        .prev_mtp = 0,
        .is_requested = false,
        .block_chain_work = low_work,
    };
    try testing.expectError(
        validation.ValidationError.TooLittleChainwork,
        validation.validateBlockForIBD(&block, &ctx, allocator),
    );
}

test "t1_r5 validateBlockForIBD rejects a checkpoint-mismatch at height 11111" {
    const allocator = testing.allocator;
    var fake = std.mem.zeroes(types.BlockHeader);
    fake.bits = 0x1d00ffff;
    const block_hash = crypto.computeBlockHash(&fake);
    const block = types.Block{ .header = fake, .transactions = &.{} };
    var dummy: u8 = 0;
    const ctx = validation.IBDValidationContext{
        .block_hash = block_hash,
        .height = 11111,
        .params = &consensus.MAINNET,
        .prevout_lookup_ctx = @ptrCast(&dummy),
        .prevout_lookupFn = struct {
            fn lookup(_: *anyopaque, _: *const types.OutPoint) ?validation.PrevOutInfo {
                return null;
            }
        }.lookup,
        .active_chain = null,
        .best_tip_chain_work = [_]u8{0} ** 32,
        .best_tip_timestamp = 0,
        .prev_mtp = 0,
        .is_requested = true,
    };
    try testing.expectError(
        validation.ValidationError.CheckpointMismatch,
        validation.validateBlockForIBD(&block, &ctx, allocator),
    );
}
