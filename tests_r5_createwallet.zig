//! R5 T3 createwallet — Core-parity rejection of legacy wallets.
//!
//! Encodes the regtest-lane probes in tools/r5-probes.d/wallet.jsonl:
//!   success-shape     createwallet ["r5"] → {name:"r5"}
//!   already-exists    createwallet ["r5"] again → -4
//!   legacy-refused    createwallet [name, null, null, null, null, false] → -4
//!                     and the refused name is NOT left loaded
//!   no-name           createwallet [] → -1 (arity HelpResult)
//!
//! Core: bitcoin-core/src/wallet/rpc/wallet.cpp:402-405 (legacy -4) and
//! rpc/util.cpp:644 (wrong arity → -1). Pre-fix the handler created a
//! descriptors=false wallet and returned -32602 on missing name.
//!
//! CONTROL: `zig build test-r5-createwallet --summary new`
//! Filter `r5_createwallet` so imported rpc/peer/wallet tests do not run.

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

const Fixture = struct {
    chain_state: storage.ChainState,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    wm: wallet_mod.WalletManager,
    server: rpc.RpcServer,
    dir: []const u8,
    allocator: std.mem.Allocator,

    /// Initialise in place so RpcServer's pointers into the other fields stay
    /// valid (returning a Fixture by value would move them and dangle).
    fn init(self: *Fixture, allocator: std.mem.Allocator, suffix: []const u8) !void {
        const dir = try std.fmt.allocPrint(allocator, "/tmp/clearbit_r5_cw_{s}", .{suffix});
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

test "r5_createwallet legacy-refused is RPC_WALLET_ERROR -4 and does not load" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "legacy");
    defer fx.deinit();

    const resp = try fx.dispatch(
        "{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5legacy\",null,null,null,null,false]}",
    );
    defer allocator.free(resp);

    try testing.expectEqual(@as(i32, rpc.RPC_WALLET_ERROR), try errCode(resp));
    try testing.expect(std.mem.indexOf(u8, resp, "descriptors argument must be set to") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "legacy wallet") != null);
    try testing.expectEqual(@as(usize, 0), fx.wm.count());
}

test "r5_createwallet no-name is RPC_MISC_ERROR -1" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "noname");
    defer fx.deinit();

    const resp = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[]}");
    defer allocator.free(resp);

    try testing.expectEqual(@as(i32, rpc.RPC_MISC_ERROR), try errCode(resp));
}

test "r5_createwallet success-shape then already-exists -4" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "ok");
    defer fx.deinit();

    const ok = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(ok);
    try testing.expect(std.mem.indexOf(u8, ok, "\"error\":null") != null);
    try testing.expect(std.mem.indexOf(u8, ok, "\"name\":\"r5\"") != null);
    try testing.expectEqual(@as(usize, 1), fx.wm.count());

    const dup = try fx.dispatch("{\"id\":2,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(dup);
    try testing.expectEqual(@as(i32, rpc.RPC_WALLET_ERROR), try errCode(dup));

    // A subsequent legacy create still must not load a second wallet.
    const legacy = try fx.dispatch(
        "{\"id\":3,\"method\":\"createwallet\",\"params\":[\"r5legacy\",null,null,null,null,false]}",
    );
    defer allocator.free(legacy);
    try testing.expectEqual(@as(i32, rpc.RPC_WALLET_ERROR), try errCode(legacy));
    try testing.expectEqual(@as(usize, 1), fx.wm.count());
    try testing.expect(fx.wm.getWallet("r5legacy") == null);
}
