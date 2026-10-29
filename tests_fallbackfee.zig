//! Core-style -fallbackfee: wallet sends take their fee rate from the fee
//! estimator, then -fallbackfee, and fail like Core when neither exists
//! (spend.cpp:1164 "Fee estimation failed. Fallbackfee is disabled...",
//! thrown as RPC_WALLET_INSUFFICIENT_FUNDS -6). Pre-fix sendtoaddress/send
//! used a hardcoded 5 sat/vB and never failed.
//!
//! Run with `zig build test-fallbackfee`. Filter `fallbackfee`.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const wallet_mod = @import("src/wallet.zig");
const types = @import("src/types.zig");

fn has(body: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, body, needle) != null;
}

const Fixture = struct {
    chain_state: storage.ChainState,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    wm: wallet_mod.WalletManager,
    server: rpc.RpcServer,
    dir: []const u8,
    allocator: std.mem.Allocator,

    fn init(self: *Fixture, allocator: std.mem.Allocator, suffix: []const u8, fallback: u64) !void {
        const dir = try std.fmt.allocPrint(allocator, "/tmp/clearbit_fallbackfee_{s}", .{suffix});
        errdefer {
            std.fs.deleteTreeAbsolute(dir) catch {};
            allocator.free(dir);
        }
        std.fs.deleteTreeAbsolute(dir) catch {};

        self.allocator = allocator;
        self.dir = dir;
        self.chain_state = storage.ChainState.init(null, 64, allocator);
        errdefer self.chain_state.deinit();
        self.mempool = mempool_mod.Mempool.init(null, null, allocator);
        errdefer self.mempool.deinit();
        self.peer_manager = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
        errdefer self.peer_manager.deinit();
        self.wm = try wallet_mod.WalletManager.init(allocator, dir, .regtest);
        errdefer self.wm.deinit();
        self.server = rpc.RpcServer.initWithWalletManager(
            allocator,
            &self.chain_state,
            &self.mempool,
            &self.peer_manager,
            &consensus.REGTEST,
            &self.wm,
            .{ .fallback_fee_sat_per_kvb = fallback },
        );
    }

    fn deinit(self: *Fixture) void {
        self.server.deinit();
        self.wm.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
        std.fs.deleteTreeAbsolute(self.dir) catch {};
        self.allocator.free(self.dir);
    }

    fn dispatch(self: *Fixture, body: []const u8) ![]const u8 {
        return self.server.dispatch(body);
    }
};


const DEST = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const FEE_ERR = "Fee estimation failed. Fallbackfee is disabled";

fn fund(fx: *Fixture, allocator: std.mem.Allocator) !void {
    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"w\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));
    const w = fx.wm.getWallet("w").?;
    const ki = try w.generateKey();
    const spk = try w.getScriptPubKey(ki, .p2wpkh);
    defer allocator.free(spk);
    try w.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0xA1} ** 32, .index = 0 },
        .output = .{ .value = 5_000_000_000, .script_pubkey = try allocator.dupe(u8, spk) },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 200,
    });
}

test "fallbackfee sendtoaddress with no estimate and no fallback fails -6" {
    // Arena: the post-fee error paths in the send handlers (mempool reject on
    // this empty fixture) leak by design of the existing code; not under test.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fx: Fixture = undefined;
    try fx.init(allocator, "s0", 0);
    defer fx.deinit();
    try fund(&fx, allocator);
    const resp = try fx.dispatch("{\"id\":2,\"method\":\"sendtoaddress\",\"params\":[\"" ++ DEST ++ "\",1.0]}");
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"code\":-6"));
    try testing.expect(has(resp, FEE_ERR));
}

test "fallbackfee sendtoaddress with a fallback gets past the fee check" {
    // Arena: the post-fee error paths in the send handlers (mempool reject on
    // this empty fixture) leak by design of the existing code; not under test.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fx: Fixture = undefined;
    try fx.init(allocator, "s1", 20_000);
    defer fx.deinit();
    try fund(&fx, allocator);
    const resp = try fx.dispatch("{\"id\":2,\"method\":\"sendtoaddress\",\"params\":[\"" ++ DEST ++ "\",1.0]}");
    defer allocator.free(resp);
    try testing.expect(!has(resp, FEE_ERR));
}

test "fallbackfee send with no estimate and no fallback fails -6" {
    // Arena: the post-fee error paths in the send handlers (mempool reject on
    // this empty fixture) leak by design of the existing code; not under test.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fx: Fixture = undefined;
    try fx.init(allocator, "d0", 0);
    defer fx.deinit();
    try fund(&fx, allocator);
    const resp = try fx.dispatch("{\"id\":2,\"method\":\"send\",\"params\":[[{\"" ++ DEST ++ "\":1.0}]]}");
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"code\":-6"));
    try testing.expect(has(resp, FEE_ERR));
}

test "fallbackfee send with explicit fee_rate needs no fallback" {
    // Arena: the post-fee error paths in the send handlers (mempool reject on
    // this empty fixture) leak by design of the existing code; not under test.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fx: Fixture = undefined;
    try fx.init(allocator, "d1", 0);
    defer fx.deinit();
    try fund(&fx, allocator);
    const resp = try fx.dispatch("{\"id\":2,\"method\":\"send\",\"params\":[[{\"" ++ DEST ++ "\":1.0}],null,null,10]}");
    defer allocator.free(resp);
    try testing.expect(!has(resp, FEE_ERR));
}

test "fallbackfee rate selection: estimate wins, fallback rounds up, 0 disables" {
    try testing.expectEqual(@as(?u64, 20), rpc.walletFeeRate(null, 20_000));
    try testing.expectEqual(@as(?u64, 21), rpc.walletFeeRate(null, 20_001));
    try testing.expectEqual(@as(?u64, 7), rpc.walletFeeRate(6.2, 20_000));
    try testing.expectEqual(@as(?u64, null), rpc.walletFeeRate(null, 0));
}

test "fallbackfee parse BTC/kvB to sat/kvB" {
    try testing.expectEqual(@as(?u64, 20_000), rpc.parseFallbackFee("0.0002"));
    try testing.expectEqual(@as(?u64, 0), rpc.parseFallbackFee("0"));
    try testing.expectEqual(@as(?u64, 100_000_000), rpc.parseFallbackFee("1"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("abc"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee(""));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("0.123456789"));
}
