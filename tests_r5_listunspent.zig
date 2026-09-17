//! R5 T3 listunspent — Core-parity filters and funded-entry shape.
//!
//! Encodes the regtest-lane probes in tools/r5-probes.d/wallet.jsonl:
//!   invalid-address       [1, 9999999, ["notanaddress"]] → -5
//!   duplicate-address     [1, 9999999, [bcrt1q…080, same]] → -8
//!   minconf-excludes-all  [9999999] on 6-conf coins → []
//!   filter-by-own-address [1, 9999999, [own]] → 3 coins (a 4th at
//!                         another address is excluded)
//!   success-funded        [] → 4 coins with label/desc/parent_descs/safe
//!
//! Core: bitcoin-core/src/wallet/rpc/coins.cpp:525-548 (arg parse) and
//! :609-687 (entry shape). Pre-fix the handler ignored params entirely
//! (`_ = params`) and omitted label/desc/parent_descs.
//!
//! CONTROL: `zig build test-r5-listunspent --summary new`
//! Filter `r5_listunspent` so imported rpc/peer/wallet tests do not run.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const wallet_mod = @import("src/wallet.zig");

const DUP_ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const OWN_SPK = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x11} ** 20;
const OTHER_SPK = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x22} ** 20;

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

fn countObjects(body: []const u8) usize {
    // Count `{"txid":` occurrences in the result array.
    var n: usize = 0;
    var rest = body;
    while (std.mem.indexOf(u8, rest, "{\"txid\":")) |at| {
        n += 1;
        rest = rest[at + 1 ..];
    }
    return n;
}

fn fundOwnThree(w: *wallet_mod.Wallet) !void {
    var i: u8 = 1;
    while (i <= 3) : (i += 1) {
        var txid = [_]u8{0} ** 32;
        txid[0] = i;
        try w.utxos.append(.{
            .outpoint = .{ .hash = txid, .index = 0 },
            .output = .{ .value = 250_000_000, .script_pubkey = &OWN_SPK },
            .key_index = 0,
            .address_type = .p2wpkh,
            .confirmations = 0,
            .height = 1,
        });
    }
}

fn fundOtherOne(w: *wallet_mod.Wallet) !void {
    var txid = [_]u8{0} ** 32;
    txid[0] = 9;
    try w.utxos.append(.{
        .outpoint = .{ .hash = txid, .index = 0 },
        .output = .{ .value = 100_000_000, .script_pubkey = &OTHER_SPK },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 0,
        .height = 1,
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
        const dir = try std.fmt.allocPrint(allocator, "/tmp/clearbit_r5_lu_{s}", .{suffix});
        errdefer {
            std.fs.deleteTreeAbsolute(dir) catch {};
            allocator.free(dir);
        }
        std.fs.deleteTreeAbsolute(dir) catch {};

        self.allocator = allocator;
        self.dir = dir;
        self.chain_state = storage.ChainState.init(null, 64, allocator);
        errdefer self.chain_state.deinit();
        self.chain_state.best_height = 6;
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

test "r5_listunspent invalid-address is RPC_INVALID_ADDRESS_OR_KEY -5" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "inv");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"listunspent\",\"params\":[1,9999999,[\"notanaddress\"]]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_ADDRESS_OR_KEY), try errCode(resp));
    try testing.expect(has(resp, "Invalid Bitcoin address: notanaddress"));
}

test "r5_listunspent duplicate-address is RPC_INVALID_PARAMETER -8" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "dup");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"listunspent\",\"params\":[1,9999999,[\"" ++ DUP_ADDR ++ "\",\"" ++ DUP_ADDR ++ "\"]]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_PARAMETER), try errCode(resp));
    try testing.expect(has(resp, "Invalid parameter, duplicated address: " ++ DUP_ADDR));
}

test "r5_listunspent minconf-excludes-all returns empty" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "minconf");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const w = fx.wm.getWallet("r5") orelse return error.TestUnexpectedResult;
    try fundOwnThree(w);

    const resp = try fx.dispatch("{\"id\":2,\"method\":\"listunspent\",\"params\":[9999999]}");
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expect(has(resp, "\"result\":[]"));
    try testing.expectEqual(@as(usize, 0), countObjects(resp));
}

test "r5_listunspent filter-by-own-address returns 3 of 4" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "filter");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const w = fx.wm.getWallet("r5") orelse return error.TestUnexpectedResult;
    try fundOwnThree(w);
    try fundOtherOne(w);

    const own = (try wallet_mod.scriptToAddress(&OWN_SPK, .regtest, allocator)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(own);

    const all = try fx.dispatch("{\"id\":2,\"method\":\"listunspent\",\"params\":[]}");
    defer allocator.free(all);
    try testing.expect(has(all, "\"error\":null"));
    try testing.expectEqual(@as(usize, 4), countObjects(all));

    const req = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":3,\"method\":\"listunspent\",\"params\":[1,9999999,[\"{s}\"]]}}",
        .{own},
    );
    defer allocator.free(req);
    const filtered = try fx.dispatch(req);
    defer allocator.free(filtered);
    try testing.expect(has(filtered, "\"error\":null"));
    try testing.expectEqual(@as(usize, 3), countObjects(filtered));
}

test "r5_listunspent success-funded has label desc parent_descs safe" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "shape");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const w = fx.wm.getWallet("r5") orelse return error.TestUnexpectedResult;
    try fundOwnThree(w);

    const own = (try wallet_mod.scriptToAddress(&OWN_SPK, .regtest, allocator)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(own);

    const resp = try fx.dispatch("{\"id\":2,\"method\":\"listunspent\",\"params\":[]}");
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expectEqual(@as(usize, 3), countObjects(resp));
    try testing.expect(has(resp, "\"label\":\""));
    try testing.expect(has(resp, "\"desc\":\""));
    try testing.expect(has(resp, "\"parent_descs\":"));
    try testing.expect(has(resp, "\"safe\":true"));
    try testing.expect(has(resp, "\"spendable\":true"));
    try testing.expect(has(resp, "\"solvable\":true"));
    try testing.expect(has(resp, own));
}
