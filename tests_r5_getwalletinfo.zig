//! R5 T3 getwalletinfo — Core-parity txcount, shape, and arity.
//!
//! Encodes the regtest-lane probes in tools/r5-probes.d/wallet.jsonl:
//!   shape            getwalletinfo [] → walletname/txcount/flags/lastprocessedblock
//!   counts-funding   getwalletinfo [] after 3 wallet txs → txcount=3
//!                    (NOT keys.len — pre-fix reported 1 after getnewaddress)
//!   wrong-arity      getwalletinfo ["unexpected"] → -1
//!
//! Core: bitcoin-core/src/wallet/rpc/wallet.cpp:91 (txcount = mapWallet.size)
//! and rpc/util.cpp:644 (wrong arity → -1). Pre-fix the handler used
//! keys.items.len for txcount, omitted walletname/lastprocessedblock, and
//! dropped surplus args because getwalletinfo was absent from core-arity.json.
//!
//! CONTROL: `zig build test-r5-getwalletinfo --summary new`
//! Filter `r5_getwalletinfo` so imported rpc/peer/wallet tests do not run.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const wallet_mod = @import("src/wallet.zig");

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

fn pushDummyTx(wallet: *wallet_mod.Wallet, n: u8) !void {
    var txid = [_]u8{0} ** 32;
    txid[0] = n;
    try wallet.tx_history.append(.{
        .txid = txid,
        .is_coinbase = false,
        .is_from_me = false,
        .height = n,
        .block_hash = [_]u8{0} ** 32,
        .block_time = 0,
        .net_credit = 50_000,
        .debit = 0,
        .fee = 0,
        .raw_hex = try wallet.allocator.dupe(u8, ""),
        .details = std.ArrayList(wallet_mod.WalletTxDetail).init(wallet.allocator),
    });
}

const Fixture = struct {
    chain_state: storage.ChainState,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    wm: wallet_mod.WalletManager,
    server: rpc.RpcServer,
    dir: []const u8,
    allocator: std.mem.Allocator,

    fn init(self: *Fixture, allocator: std.mem.Allocator, suffix: []const u8) !void {
        const dir = try std.fmt.allocPrint(allocator, "/tmp/clearbit_r5_gwi_{s}", .{suffix});
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
            .{},
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

test "r5_getwalletinfo wrong-arity is RPC_MISC_ERROR -1" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "arity");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"getwalletinfo\",\"params\":[\"unexpected\"]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_MISC_ERROR), try errCode(resp));
}

test "r5_getwalletinfo shape has walletname flags lastprocessedblock" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "shape");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const info = try fx.dispatch("{\"id\":2,\"method\":\"getwalletinfo\",\"params\":[]}");
    defer allocator.free(info);
    try testing.expect(has(info, "\"error\":null"));
    try testing.expect(has(info, "\"walletname\":\"r5\""));
    try testing.expect(has(info, "\"walletversion\":"));
    try testing.expect(has(info, "\"format\":\"sqlite\""));
    try testing.expect(has(info, "\"txcount\":0"));
    try testing.expect(has(info, "\"keypoolsize\":"));
    try testing.expect(has(info, "\"private_keys_enabled\":true"));
    try testing.expect(has(info, "\"avoid_reuse\":false"));
    try testing.expect(has(info, "\"scanning\":false"));
    try testing.expect(has(info, "\"descriptors\":true"));
    try testing.expect(has(info, "\"external_signer\":false"));
    try testing.expect(has(info, "\"blank\":false"));
    try testing.expect(has(info, "\"flags\":[\"descriptors\"]"));
    try testing.expect(has(info, "\"lastprocessedblock\":{\"hash\":\""));
    try testing.expect(has(info, "\"height\":"));
}

test "r5_getwalletinfo txcount is wallet txs not key count" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "txcount");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const w = fx.wm.getWallet("r5") orelse return error.TestUnexpectedResult;
    const addr = try w.getnewaddress(.p2wpkh, false);
    defer w.allocator.free(addr.address);
    try testing.expectEqual(@as(usize, 1), w.keys.items.len);

    try pushDummyTx(w, 1);
    try pushDummyTx(w, 2);
    try pushDummyTx(w, 3);
    try testing.expectEqual(@as(usize, 3), w.tx_history.items.len);

    const info = try fx.dispatch("{\"id\":2,\"method\":\"getwalletinfo\",\"params\":[]}");
    defer allocator.free(info);
    try testing.expect(has(info, "\"error\":null"));
    try testing.expect(has(info, "\"txcount\":3"));
    try testing.expect(!has(info, "\"txcount\":1"));
    try testing.expect(has(info, "\"walletname\":\"r5\""));
}
