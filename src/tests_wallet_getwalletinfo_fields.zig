//! Core v31.1 getwalletinfo (wallet/rpc/wallet.cpp) has no `balance`,
//! `unconfirmed_balance` or `immature_balance`; those live in getbalances.

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const wallet_mod = @import("wallet.zig");

fn hasKey(allocator: std.mem.Allocator, key: []const u8) !bool {
    const cs = try allocator.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, allocator);
    defer { cs.deinit(); allocator.destroy(cs); }
    const mp = try allocator.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(null, null, allocator);
    defer { mp.deinit(); allocator.destroy(mp); }
    const pm = try allocator.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    defer { pm.deinit(); allocator.destroy(pm); }
    const srv = try allocator.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(allocator, cs, mp, pm, &consensus.REGTEST, .{});
    defer { srv.deinit(); allocator.destroy(srv); }

    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();
    srv.wallet = &w;

    const resp = try srv.dispatch("{\"id\":1,\"method\":\"getwalletinfo\",\"params\":[]}");
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const result = parsed.value.object.get("result") orelse return error.NoResult;
    return result.object.get(key) != null;
}

test "tests_wallet_getwalletinfo_fields: no legacy balance fields" {
    try testing.expect(!(try hasKey(testing.allocator, "balance")));
    try testing.expect(!(try hasKey(testing.allocator, "unconfirmed_balance")));
    try testing.expect(!(try hasKey(testing.allocator, "immature_balance")));
}

test "tests_wallet_getwalletinfo_fields: CONTROL Core fields still present" {
    for ([_][]const u8{ "walletname", "walletversion", "format", "txcount", "keypoolsize", "private_keys_enabled", "avoid_reuse", "scanning", "descriptors" }) |k| {
        try testing.expect(try hasKey(testing.allocator, k));
    }
}
