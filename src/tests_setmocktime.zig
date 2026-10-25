//! setmocktime: regtest-only clock override, Core rpc/node.cpp.
//!
//! At the parent commit every test below fails with "Method not found"
//! (-32601); the mainnet-refusal test fails the same way because the method
//! does not exist to refuse.

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");

const Rig = struct {
    allocator: std.mem.Allocator,
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    peer_manager: *peer_mod.PeerManager,
    server: *rpc.RpcServer,

    fn init(allocator: std.mem.Allocator, params: *const consensus.NetworkParams) !Rig {
        const cs = try allocator.create(storage.ChainState);
        cs.* = storage.ChainState.init(null, 64, allocator);
        const mp = try allocator.create(mempool_mod.Mempool);
        mp.* = mempool_mod.Mempool.init(null, null, allocator);
        const pm = try allocator.create(peer_mod.PeerManager);
        pm.* = peer_mod.PeerManager.init(allocator, params);
        const srv = try allocator.create(rpc.RpcServer);
        srv.* = rpc.RpcServer.init(allocator, cs, mp, pm, params, .{});
        return .{ .allocator = allocator, .chain_state = cs, .mempool = mp, .peer_manager = pm, .server = srv };
    }
    fn deinit(self: *Rig) void {
        self.server.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
        self.allocator.destroy(self.server);
        self.allocator.destroy(self.peer_manager);
        self.allocator.destroy(self.mempool);
        self.allocator.destroy(self.chain_state);
    }
    fn dispatch(self: *Rig, method: []const u8, params_json: []const u8) ![]const u8 {
        const req = try std.fmt.allocPrint(self.allocator,
            "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        defer self.allocator.free(req);
        return self.server.dispatch(req);
    }
};

/// Returns the parsed reply; caller deinits.
fn call(rig: *Rig, params_json: []const u8) !std.json.Parsed(std.json.Value) {
    const resp = try rig.dispatch("setmocktime", params_json);
    defer rig.allocator.free(resp);
    return std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{ .allocate = .alloc_always });
}

fn expectOk(params_json: []const u8) !void {
    var rig = try Rig.init(testing.allocator, &consensus.REGTEST);
    defer rig.deinit();
    var p = try call(&rig, params_json);
    defer p.deinit();
    const err_v = p.value.object.get("error") orelse std.json.Value{ .null = {} };
    try testing.expect(err_v == .null);
    try testing.expect(p.value.object.get("result").? == .null);
}

fn expectErr(params: *const consensus.NetworkParams, params_json: []const u8, code: i64, msg: []const u8) !void {
    var rig = try Rig.init(testing.allocator, params);
    defer rig.deinit();
    var p = try call(&rig, params_json);
    defer p.deinit();
    const err_v = p.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v != .object) return error.ExpectedRpcError;
    try testing.expectEqual(code, err_v.object.get("code").?.integer);
    try testing.expectEqualStrings(msg, err_v.object.get("message").?.string);
}

test "tests_setmocktime: regtest accepts a timestamp and returns null" {
    defer mempool_mod.setMockTime(0);
    try expectOk("[1700000000]");
}

test "tests_setmocktime: 0 restores the system clock" {
    var rig = try Rig.init(testing.allocator, &consensus.REGTEST);
    defer rig.deinit();
    defer mempool_mod.setMockTime(0);
    var p = try call(&rig, "[1700000000]");
    p.deinit();
    try testing.expectEqual(@as(i64, 1700000000), mempool_mod.currentTime());
    var q = try call(&rig, "[0]");
    q.deinit();
    try testing.expect(mempool_mod.currentTime() > 1700000000 + 1000);
}

test "tests_setmocktime: negative is -8 with Core's message" {
    try expectErr(&consensus.REGTEST, "[-1]", -8, "Mocktime must be in the range [0, 9223372036], not -1.");
}

test "tests_setmocktime: above nanoseconds::max in seconds is -8" {
    try expectErr(&consensus.REGTEST, "[9223372037]", -8, "Mocktime must be in the range [0, 9223372036], not 9223372037.");
}

test "tests_setmocktime: CONTROL upper bound itself is accepted" {
    defer mempool_mod.setMockTime(0);
    try expectOk("[9223372036]");
}

test "tests_setmocktime: mainnet refuses with -1" {
    try expectErr(&consensus.MAINNET, "[1700000000]", -1, "setmocktime is for regression testing (-regtest mode) only");
}
