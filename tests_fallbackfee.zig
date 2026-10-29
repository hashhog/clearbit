//! Core-style -fallbackfee: wallet sends take their fee rate from the fee
//! estimator, then -fallbackfee, and fail like Core when neither exists
//! (spend.cpp:1166 "Fee estimation failed. Fallbackfee is disabled...":
//! sendtoaddress surfaces it as RPC_WALLET_INSUFFICIENT_FUNDS -6, `send`
//! throws RPC_WALLET_ERROR -4 at wallet/rpc/spend.cpp:1438). Pre-fix
//! sendtoaddress/send used a hardcoded 5 sat/vB and never failed. The rate is
//! GetMinimumFeeRate's: exact sat/kvB, raised to the mempool and required
//! minimums; -fallbackfee is ParseMoney'd and a bad one refuses startup.
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
const main_mod = @import("src/main.zig");

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

test "fallbackfee send with no estimate and no fallback fails -4" {
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
    try testing.expect(has(resp, "\"code\":-4"));
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

test "fallbackfee sendtoaddress keeps a fractional fallback rate" {
    // 1001 sat/kvB = 1.001 sat/vB. Core keeps it: a 68-vB P2WPKH input costs
    // ceil(68 * 1.001) = 69 sat, so 50 BTC covers 49.999999 BTC (100 sat
    // spare). Rounding the rate up to 2 sat/vB charges 136 and reports
    // "Insufficient funds".
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var fx: Fixture = undefined;
    try fx.init(allocator, "fr", 1001);
    defer fx.deinit();
    try fund(&fx, allocator);
    const resp = try fx.dispatch("{\"id\":2,\"method\":\"sendtoaddress\",\"params\":[\"" ++ DEST ++ "\",49.999999]}");
    defer allocator.free(resp);
    try testing.expect(!has(resp, FEE_ERR));
    try testing.expect(!has(resp, "Insufficient funds"));
}

test "fallbackfee parse refuses what Core ParseMoney refuses" {
    // MAX_MONEY is the ceiling, even though 21000001 BTC fits in a u64.
    try testing.expectEqual(@as(?u64, 2_100_000_000_000_000), rpc.parseFallbackFee("21000000"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("21000000.00000001"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("21000001"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("99999999999"));
    // Surrounding whitespace is trimmed; anything else is junk.
    try testing.expectEqual(@as(?u64, 20_000), rpc.parseFallbackFee(" \t0.0002\n"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("   "));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("0. 0002"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("0 .0002"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("-0.0002"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("+0.0002"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("0.0002x"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("0.0002.1"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("1e-4"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("0.0002\x00"));
    // Core accepts these edge forms.
    try testing.expectEqual(@as(?u64, 100_000_000), rpc.parseFallbackFee("1."));
    try testing.expectEqual(@as(?u64, 50_000_000), rpc.parseFallbackFee(".5"));
    try testing.expectEqual(@as(?u64, 1), rpc.parseFallbackFee("0.00000001"));
}

fn writeConf(dir: []const u8, body: []const u8) !void {
    std.fs.deleteTreeAbsolute(dir) catch {};
    try std.fs.makeDirAbsolute(dir);
    var d = try std.fs.openDirAbsolute(dir, .{});
    defer d.close();
    try d.writeFile(.{ .sub_path = "clearbit.conf", .data = body });
}

test "fallbackfee bad config-file value refuses startup" {
    const dir = "/tmp/clearbit_fallbackfee_conf_bad";
    defer std.fs.deleteTreeAbsolute(dir) catch {};
    try writeConf(dir, "fallbackfee=21000001\n");
    var config = main_mod.Config{};
    try testing.expectError(error.InvalidFallbackFee, main_mod.loadConfigFile(dir, &config, testing.allocator));
    try writeConf(dir, "fallbackfee=abc\n");
    try testing.expectError(error.InvalidFallbackFee, main_mod.loadConfigFile(dir, &config, testing.allocator));
}

test "fallbackfee high config-file value is kept, not refused" {
    const dir = "/tmp/clearbit_fallbackfee_conf_high";
    defer std.fs.deleteTreeAbsolute(dir) catch {};
    // 0.02 BTC/kvB > HIGH_TX_FEE_PER_KB (0.01): Core warns and stores it.
    try writeConf(dir, "fallbackfee=0.02\n");
    var config = main_mod.Config{};
    try main_mod.loadConfigFile(dir, &config, testing.allocator);
    try testing.expectEqual(@as(u64, 2_000_000), config.fallbackfee_sat_per_kvb);
}

test "fallbackfee rate selection keeps the feerate, raises to mempool and required minimums" {
    // walletFeeRate(estimate, fallback, mempool_min, relay_min), all sat/kvB.
    // Estimate wins; with no estimate the fallback, unrounded.
    try testing.expectEqual(@as(?u64, 6200), rpc.walletFeeRate(6200, 20_000, 100, 100));
    try testing.expectEqual(@as(?u64, 20_001), rpc.walletFeeRate(null, 20_001, 100, 100));
    try testing.expectEqual(@as(?u64, 20_000), rpc.walletFeeRate(0, 20_000, 100, 100));
    // A zero fallback is disabled, never raised to a minimum.
    try testing.expectEqual(@as(?u64, null), rpc.walletFeeRate(null, 0, 5000, 100));
    // Raised to the mempool minimum fee...
    try testing.expectEqual(@as(?u64, 5000), rpc.walletFeeRate(3000, 0, 5000, 100));
    try testing.expectEqual(@as(?u64, 5000), rpc.walletFeeRate(null, 3000, 5000, 100));
    // ...then to the required fee, max(-mintxfee 1000, relay minimum).
    try testing.expectEqual(@as(?u64, 1000), rpc.walletFeeRate(null, 500, 100, 100));
    try testing.expectEqual(@as(?u64, 1500), rpc.walletFeeRate(null, 500, 100, 1500));
}

test "fallbackfee parse BTC/kvB to sat/kvB" {
    try testing.expectEqual(@as(?u64, 20_000), rpc.parseFallbackFee("0.0002"));
    try testing.expectEqual(@as(?u64, 0), rpc.parseFallbackFee("0"));
    try testing.expectEqual(@as(?u64, 100_000_000), rpc.parseFallbackFee("1"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("abc"));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee(""));
    try testing.expectEqual(@as(?u64, null), rpc.parseFallbackFee("0.123456789"));
}
