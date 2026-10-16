//! listunspent coinbase maturity must match Core's off-by-one exactly.
//!
//! Core (wallet/receive.cpp / transaction.cpp):
//!   GetBlocksToMaturity = max(0, (COINBASE_MATURITY + 1) - depth)
//!   immature <=> GetBlocksToMaturity > 0 <=> depth <= 100
//! where depth = tip - height + 1 is what listunspent reports as
//! "confirmations". After `generatetoaddress 101` to a wallet address only the
//! block-1 coinbase (101 confs) is spendable; block 2 (100 confs) is still
//! immature. clearbit compared `confirmations < 100`, so it also listed the
//! 100-conf coinbase: the nightly wallet-import arm saw 2 UTXOs where Core
//! gives 1 (and getbalance, which uses tip - height < 100, already agreed
//! with Core at 50 BTC).

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const wallet_mod = @import("wallet.zig");

fn countListUnspent(allocator: std.mem.Allocator, tip: u32, cb_heights: []const u32) !usize {
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
    cs.best_height = tip;
    w.setTipHeight(tip);
    for (cb_heights, 0..) |h, i| {
        try w.addUtxo(.{
            .outpoint = .{ .hash = [_]u8{@intCast(i + 1)} ** 32, .index = 0 },
            .output = .{ .value = 5_000_000_000, .script_pubkey = &[_]u8{} },
            .key_index = 0,
            .address_type = .p2wpkh,
            .confirmations = tip - h + 1,
            .is_coinbase = true,
            .height = h,
        });
    }

    const resp = try srv.dispatch("{\"id\":1,\"method\":\"listunspent\",\"params\":[]}");
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    return parsed.value.object.get("result").?.array.items.len;
}

test "tests_listunspent_maturity: tip 101, coinbases at 1 and 2 -> only block 1 is mature" {
    // block 1: 101 confs (mature); block 2: 100 confs (Core: immature).
    try testing.expectEqual(@as(usize, 1), try countListUnspent(testing.allocator, 101, &.{ 1, 2 }));
}

test "tests_listunspent_maturity: CONTROL 101-conf coinbase is listed" {
    try testing.expectEqual(@as(usize, 1), try countListUnspent(testing.allocator, 101, &.{1}));
}

test "tests_listunspent_maturity: CONTROL 99-conf coinbase is not listed" {
    try testing.expectEqual(@as(usize, 0), try countListUnspent(testing.allocator, 101, &.{3}));
}
