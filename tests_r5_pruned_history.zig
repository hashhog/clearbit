//! Snapshot-boot / missing-history honesty for getblockchaininfo + getblockhash.
//!
//! Live mainnet (2026-09-17): getblockhash(1) and getblockhash(500000) return
//! -8 "Block height out of range" while the tip is at ~967441; the height→hash
//! index starts at 944172 (baked assumeUTXO base-tail). getblockchaininfo
//! reports pruned=false with no pruneheight — a silent wrong answer.
//!
//! Core (rpc/blockchain.cpp): pruned is true when the node does not hold the
//! full chain; pruneheight is the first height with complete data. getblockhash
//! -8 is only for height < 0 or height > tip; an in-range height the node
//! simply does not retain is -1 "Block not available (pruned data)"
//! (same string Core's getblock uses for pruned bodies).
//!
//! This commit reports the truth. It does not backfill genesis→floor; Core
//! keeps a second chainstate for that. STATUS next: background header+block
//! backfill of the snapshot prefix.
//!
//! CONTROL: `zig build test-r5-pruned-history --summary new`
//! Filter `r5_pruned_history` so imported rpc/peer/wallet tests do not run.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const types = @import("src/types.zig");

fn errCode(body: []const u8) !i32 {
    const key = "\"code\":";
    const at = std.mem.indexOf(u8, body, key) orelse return error.TestUnexpectedResult;
    var i = at + key.len;
    while (i < body.len and body[i] == ' ') i += 1;
    const start = i;
    if (i < body.len and body[i] == '-') i += 1;
    while (i < body.len and body[i] >= '0' and body[i] <= '9') i += 1;
    return std.fmt.parseInt(i32, body[start..i], 10);
}

fn has(body: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, body, needle) != null;
}

const Fixture = struct {
    chain_state: storage.ChainState,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    server: rpc.RpcServer,
    allocator: std.mem.Allocator,

    fn init(self: *Fixture, allocator: std.mem.Allocator) void {
        self.allocator = allocator;
        self.chain_state = storage.ChainState.init(null, 64, allocator);
        self.mempool = mempool_mod.Mempool.init(null, null, allocator);
        self.peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
        self.server = rpc.RpcServer.init(
            allocator,
            &self.chain_state,
            &self.mempool,
            &self.peer_manager,
            &consensus.MAINNET,
            .{},
        );
    }

    fn deinit(self: *Fixture) void {
        self.server.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
    }
};

test "r5_pruned_history complete chain reports pruned false" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.chain_state.best_height = 100;
    fx.chain_state.best_hash = [_]u8{0xAB} ** 32;

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}");
    defer testing.allocator.free(body);
    try testing.expect(has(body, "\"pruned\":false"));
    try testing.expect(!has(body, "\"pruneheight\":"));
}

test "r5_pruned_history snapshot floor reports pruned true and pruneheight" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.chain_state.best_height = 967_441;
    fx.chain_state.best_hash = [_]u8{0xCD} ** 32;
    fx.chain_state.setHistoryFloor(944_172);

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}");
    defer testing.allocator.free(body);
    try testing.expect(has(body, "\"pruned\":true"));
    try testing.expect(has(body, "\"pruneheight\":944172"));
    try testing.expect(!has(body, "\"pruned\":false"));
}

test "r5_pruned_history prune mode reports pruneheight as first unpruned" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.chain_state.best_height = 1000;
    fx.chain_state.prune_target_mib = 1024;
    fx.chain_state.prune_height = 100;

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}");
    defer testing.allocator.free(body);
    try testing.expect(has(body, "\"pruned\":true"));
    try testing.expect(has(body, "\"pruneheight\":101"));
    try testing.expect(has(body, "\"automatic_pruning\":true"));
}

test "r5_pruned_history getblockhash below floor is -1 not -8" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.chain_state.best_height = 967_441;
    fx.chain_state.setHistoryFloor(944_172);

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockhash\",\"params\":[1]}");
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(i32, rpc.RPC_MISC_ERROR), try errCode(body));
    try testing.expect(has(body, "Block not available (pruned data)"));
    try testing.expect(!has(body, "Block height out of range"));
}

test "r5_pruned_history getblockhash 500000 below floor is -1 not -8" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.chain_state.best_height = 967_441;
    fx.chain_state.setHistoryFloor(944_172);

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockhash\",\"params\":[500000]}");
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(i32, rpc.RPC_MISC_ERROR), try errCode(body));
    try testing.expect(has(body, "Block not available (pruned data)"));
}

test "r5_pruned_history getblockhash above tip is still -8" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.chain_state.best_height = 200;
    fx.chain_state.setHistoryFloor(90);

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockhash\",\"params\":[999999]}");
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_PARAMETER), try errCode(body));
    try testing.expect(has(body, "Block height out of range"));
}

test "r5_pruned_history getblockhash 0 still returns genesis" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.chain_state.best_height = 967_441;
    fx.chain_state.setHistoryFloor(944_172);

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockhash\",\"params\":[0]}");
    defer testing.allocator.free(body);
    try testing.expect(has(body, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
    try testing.expect(!has(body, "\"error\":{"));
}

test "r5_pruned_history discover + RPC: floor hash works, below floor is -1" {
    const allocator = testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();

    const floor_h: u32 = 90;
    const tip_h: u32 = 100;
    var floor_hash: types.Hash256 = [_]u8{0x22} ** 32;
    floor_hash[0] = 0x90;
    var h: u32 = floor_h;
    while (h <= tip_h) : (h += 1) {
        var hash: types.Hash256 = [_]u8{0x22} ** 32;
        hash[0] = @intCast(h);
        const key = storage.ChainStore.buildHeightHashKey(h);
        try db.put(storage.CF_DEFAULT, &key, &hash);
    }

    var chain_state = storage.ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = tip_h;
    chain_state.best_hash = [_]u8{0x22} ** 32;
    chain_state.discoverHistoryFloor();
    try testing.expectEqual(floor_h, chain_state.history_floor);

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();
    var server = rpc.RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const info = try server.dispatch("{\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}");
    defer allocator.free(info);
    try testing.expect(has(info, "\"pruned\":true"));
    try testing.expect(has(info, "\"pruneheight\":90"));

    const missing = try server.dispatch("{\"id\":1,\"method\":\"getblockhash\",\"params\":[1]}");
    defer allocator.free(missing);
    try testing.expectEqual(@as(i32, rpc.RPC_MISC_ERROR), try errCode(missing));
    try testing.expect(has(missing, "Block not available (pruned data)"));

    const ok = try server.dispatch("{\"id\":1,\"method\":\"getblockhash\",\"params\":[90]}");
    defer allocator.free(ok);
    try testing.expect(has(ok, "\"error\":null"));
    try testing.expect(!has(ok, "\"code\":"));
}
