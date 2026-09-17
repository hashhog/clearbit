//! R5 T3 remaining Core-parity probes after send/backup/restore.
//!
//! Encodes the still-failing wallet.jsonl probes:
//!   getnewaddress        ["", "bogustype"]                         → -5
//!   getaddressinfo       ["notanaddress"]                          → -5
//!   getaddressinfo       [notmine]                                 → iswitness + witness_program
//!   getaddressinfo       [own]                                     → desc, parent_desc, iswitness
//!   getbalances          shape lastprocessedblock; ["unexpected"]  → -1
//!   listwallets          ["unexpected"]                            → -1
//!   walletcreatefundedpsbt [[], []]                                → -8
//!   listtransactions     ["*", -1] / ["*", 10, -1]                 → -8
//!   sendtoaddress        [addr, -1]                                → -3
//!   loadwallet           already-loaded                            → -35
//!   help-parity          walletprocesspsbt / getaddressinfo / getbalances listed
//!
//! Core: addresses.cpp ParseOutputType/DecodeDestination/DescribeAddress,
//! coins.cpp AppendLastProcessedBlock, spend.cpp FundTransaction empty
//! recipients, transactions.cpp Negative count/from, rpc/util.cpp
//! AmountFromValue, wallet.cpp loadwallet already-loaded, rpc/util.cpp:644
//! arity.
//!
//! CONTROL: `zig build test-r5-t3-remaining --summary new`
//! Filter `r5_t3_remaining` so imported rpc/peer/wallet tests do not run.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const wallet_mod = @import("src/wallet.zig");

const NOTMINE = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const NOTMINE_PROG = "751e76e8199196d454941c45d1b3a323f1433bd6";

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
    wm: wallet_mod.WalletManager,
    server: rpc.RpcServer,
    dir: []const u8,
    allocator: std.mem.Allocator,

    fn init(self: *Fixture, allocator: std.mem.Allocator, suffix: []const u8) !void {
        const dir = try std.fmt.allocPrint(allocator, "/tmp/clearbit_r5_t3_{s}", .{suffix});
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

    fn createR5(self: *Fixture) !void {
        const created = try self.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
        defer self.allocator.free(created);
        try testing.expect(has(created, "\"error\":null"));
    }
};

test "r5_t3_remaining getnewaddress bad-address-type is -5" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "newtype");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"getnewaddress\",\"params\":[\"\",\"bogustype\"]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_ADDRESS_OR_KEY), try errCode(resp));
    try testing.expect(has(resp, "Unknown address type 'bogustype'"));
}

test "r5_t3_remaining getaddressinfo invalid-address is -5" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "ainv");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"getaddressinfo\",\"params\":[\"notanaddress\"]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_ADDRESS_OR_KEY), try errCode(resp));
}

test "r5_t3_remaining getaddressinfo notmine has iswitness" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "anotmine");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"getaddressinfo\",\"params\":[\"" ++ NOTMINE ++ "\"]}",
    );
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expect(has(resp, "\"ismine\":false"));
    try testing.expect(has(resp, "\"iswitness\":true"));
    try testing.expect(has(resp, "\"witness_version\":0"));
    try testing.expect(has(resp, "\"witness_program\":\"" ++ NOTMINE_PROG ++ "\""));
}

test "r5_t3_remaining getaddressinfo mine has desc parent_desc iswitness" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "amine");
    defer fx.deinit();
    try fx.createR5();

    const w = fx.wm.getWallet("r5") orelse return error.TestUnexpectedResult;
    const got = try w.getnewaddress(.p2wpkh, false);
    defer w.allocator.free(got.address);

    const req = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":2,\"method\":\"getaddressinfo\",\"params\":[\"{s}\"]}}",
        .{got.address},
    );
    defer allocator.free(req);
    const resp = try fx.dispatch(req);
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expect(has(resp, "\"ismine\":true"));
    try testing.expect(has(resp, "\"solvable\":true"));
    try testing.expect(has(resp, "\"desc\":"));
    try testing.expect(has(resp, "\"parent_desc\":"));
    try testing.expect(has(resp, "\"iswitness\":true"));
    try testing.expect(has(resp, "\"witness_version\":0"));
}

test "r5_t3_remaining getbalances has lastprocessedblock" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "gbshape");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch("{\"id\":2,\"method\":\"getbalances\",\"params\":[]}");
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expect(has(resp, "\"mine\":{"));
    try testing.expect(has(resp, "\"lastprocessedblock\":{\"hash\":\""));
    try testing.expect(has(resp, "\"height\":"));
}

test "r5_t3_remaining getbalances wrong-arity is -1" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "gbarity");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"getbalances\",\"params\":[\"unexpected\"]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_MISC_ERROR), try errCode(resp));
}

test "r5_t3_remaining listwallets wrong-arity is -1" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "lwarity");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"listwallets\",\"params\":[\"unexpected\"]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_MISC_ERROR), try errCode(resp));
}

test "r5_t3_remaining walletcreatefundedpsbt no-outputs is -8" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "wcfpempty");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"walletcreatefundedpsbt\",\"params\":[[],[]]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_PARAMETER), try errCode(resp));
}

test "r5_t3_remaining listtransactions negative count/skip is -8" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "ltneg");
    defer fx.deinit();
    try fx.createR5();

    const count = try fx.dispatch(
        "{\"id\":2,\"method\":\"listtransactions\",\"params\":[\"*\",-1]}",
    );
    defer allocator.free(count);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_PARAMETER), try errCode(count));
    try testing.expect(has(count, "Negative count"));

    const skip = try fx.dispatch(
        "{\"id\":3,\"method\":\"listtransactions\",\"params\":[\"*\",10,-1]}",
    );
    defer allocator.free(skip);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_PARAMETER), try errCode(skip));
    try testing.expect(has(skip, "Negative from"));
}

test "r5_t3_remaining sendtoaddress invalid-amount is -3" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "stamt");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"sendtoaddress\",\"params\":[\"" ++ NOTMINE ++ "\",-1]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_TYPE_ERROR), try errCode(resp));
}

test "r5_t3_remaining loadwallet already-loaded is -35" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "lwloaded");
    defer fx.deinit();
    try fx.createR5();

    const resp = try fx.dispatch("{\"id\":2,\"method\":\"loadwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_WALLET_ALREADY_LOADED), try errCode(resp));
}

test "r5_t3_remaining help lists walletprocesspsbt getaddressinfo getbalances" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "help");
    defer fx.deinit();

    const resp = try fx.dispatch("{\"id\":1,\"method\":\"help\",\"params\":[]}");
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expect(has(resp, "walletprocesspsbt\\n") or has(resp, "walletprocesspsbt "));
    try testing.expect(has(resp, "getaddressinfo\\n") or has(resp, "getaddressinfo "));
    try testing.expect(has(resp, "getbalances\\n") or has(resp, "getbalances "));
}
