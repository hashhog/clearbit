//! R5 T3 missing surface — send / backupwallet / restorewallet.
//!
//! Encodes the regtest-lane probes in tools/r5-probes.d/wallet.jsonl:
//!   send no-outputs          [[]]                              → -8
//!   send invalid-address     [[{"notanaddress": 0.001}]]       → -5
//!   backupwallet bad-dest    ["/nonexistent-r5probe-dir/…"]    → -4
//!   backupwallet success     ["<file>"]                        → null
//!   restorewallet missing    ["r5probe_fresh", "/nonexistent/…"] → -8
//!   restorewallet success    ["r5restored", "<backup>"]        → {name:"r5restored"}
//!   restorewallet exists     ["r5", "<backup>"]                → -36
//!   help-parity              send, backupwallet, restorewallet listed
//!
//! Core: bitcoin-core/src/wallet/rpc/spend.cpp send (:680 empty outputs),
//! rawtransaction_util.cpp ParseOutputs (:120 invalid address),
//! wallet/rpc/backup.cpp backupwallet/restorewallet,
//! wallet.cpp RestoreWallet (missing backup first, then already-exists).
//! Pre-fix these methods returned -32601 Method not found.
//!
//! CONTROL: `zig build test-r5-send-backup-restore --summary new`
//! Filter `r5_send_backup_restore` so imported rpc/peer/wallet tests do not run.

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

const Fixture = struct {
    chain_state: storage.ChainState,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    wm: wallet_mod.WalletManager,
    server: rpc.RpcServer,
    dir: []const u8,
    allocator: std.mem.Allocator,

    fn init(self: *Fixture, allocator: std.mem.Allocator, suffix: []const u8) !void {
        const dir = try std.fmt.allocPrint(allocator, "/tmp/clearbit_r5_sbr_{s}", .{suffix});
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

test "r5_send_backup_restore send no-outputs is RPC_INVALID_PARAMETER -8" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "noout");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.dispatch("{\"id\":2,\"method\":\"send\",\"params\":[[]]}");
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_PARAMETER), try errCode(resp));
}

test "r5_send_backup_restore send invalid-address is RPC_INVALID_ADDRESS_OR_KEY -5" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "baddr");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"send\",\"params\":[[{\"notanaddress\":0.001}]]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_ADDRESS_OR_KEY), try errCode(resp));
    try testing.expect(has(resp, "Invalid Bitcoin address: notanaddress"));
}

test "r5_send_backup_restore backupwallet bad-destination is RPC_WALLET_ERROR -4" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "baddest");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"backupwallet\",\"params\":[\"/nonexistent-r5probe-dir/backup.dat\"]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_WALLET_ERROR), try errCode(resp));
}

test "r5_send_backup_restore backupwallet success-null writes the file" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "baksucc");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const bak = try std.fmt.allocPrint(allocator, "{s}/wallet.bak", .{fx.dir});
    defer allocator.free(bak);
    const req = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":2,\"method\":\"backupwallet\",\"params\":[\"{s}\"]}}",
        .{bak},
    );
    defer allocator.free(req);
    const resp = try fx.dispatch(req);
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expect(has(resp, "\"result\":null"));
    std.fs.accessAbsolute(bak, .{}) catch return error.TestUnexpectedResult;
}

test "r5_send_backup_restore restorewallet backup-missing is -8" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "missbak");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.dispatch(
        "{\"id\":2,\"method\":\"restorewallet\",\"params\":[\"r5probe_fresh\",\"/nonexistent/r5probe-nope.bak\"]}",
    );
    defer allocator.free(resp);
    try testing.expectEqual(@as(i32, rpc.RPC_INVALID_PARAMETER), try errCode(resp));
}

test "r5_send_backup_restore restorewallet success-shape and already-exists -36" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "rest");
    defer fx.deinit();

    const created = try fx.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"r5\"]}");
    defer allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const bak = try std.fmt.allocPrint(allocator, "{s}/wallet.bak", .{fx.dir});
    defer allocator.free(bak);
    const bak_req = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":2,\"method\":\"backupwallet\",\"params\":[\"{s}\"]}}",
        .{bak},
    );
    defer allocator.free(bak_req);
    const bak_resp = try fx.dispatch(bak_req);
    defer allocator.free(bak_resp);
    try testing.expect(has(bak_resp, "\"error\":null"));

    const rest_req = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":3,\"method\":\"restorewallet\",\"params\":[\"r5restored\",\"{s}\"]}}",
        .{bak},
    );
    defer allocator.free(rest_req);
    const rest_resp = try fx.dispatch(rest_req);
    defer allocator.free(rest_resp);
    try testing.expect(has(rest_resp, "\"error\":null"));
    try testing.expect(has(rest_resp, "\"name\":\"r5restored\""));

    const exists_req = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":4,\"method\":\"restorewallet\",\"params\":[\"r5\",\"{s}\"]}}",
        .{bak},
    );
    defer allocator.free(exists_req);
    const exists_resp = try fx.dispatch(exists_req);
    defer allocator.free(exists_resp);
    try testing.expectEqual(@as(i32, -36), try errCode(exists_resp));
}

test "r5_send_backup_restore help lists send backupwallet restorewallet" {
    const allocator = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(allocator, "help");
    defer fx.deinit();

    const resp = try fx.dispatch("{\"id\":1,\"method\":\"help\",\"params\":[]}");
    defer allocator.free(resp);
    try testing.expect(has(resp, "\"error\":null"));
    try testing.expect(has(resp, "backupwallet"));
    try testing.expect(has(resp, "restorewallet"));
    // First-token match: a line whose first word is exactly "send", not sendtoaddress.
    try testing.expect(has(resp, "send\\n") or has(resp, "send "));
}
