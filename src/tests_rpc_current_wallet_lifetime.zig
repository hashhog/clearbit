//! RPC wallet routing is resolved per request, not once per HTTP body
//! (skill record clearbit/rpc/current-wallet-stale-pointer).
//!
//! Core resolves the target wallet inside each request
//! (wallet/rpc/util.cpp GetWalletForJSONRPCRequest) into a refcounted
//! std::shared_ptr<CWallet>, so `unloadwallet` cannot free a wallet that a
//! later request still uses, and every request sees the wallet its own URI
//! names.  clearbit resolved `RpcServer.current_wallet` once per HTTP body
//! and reused the raw pointer for every batch element:
//!
//!   1. `[unloadwallet "w", getwalletinfo]` POSTed to /wallet/w: the first
//!      element freed the wallet (WalletManager.unloadWallet destroys it) and
//!      the second dereferenced the freed pointer.
//!   2. A body containing "waitfor is served on its own thread outside
//!      serve_mutex.  Its wallet elements read the shared field after the
//!      wait, by which time another connection had rewritten it to a
//!      different wallet, so the call ran against the wrong wallet.
//!
//! Both tests go through the real HTTP server (handleConnection), because
//! that is where the per-body resolution lived.  Both fail at the parent
//! commit on their assertions; under the Debug GeneralPurposeAllocator the
//! freed wallet is also poisoned, so test 1 reads garbage there.
//!
//! Run: zig build test-unit -Dtest-filter=current_wallet

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const wallet_mod = @import("wallet.zig");

const Live = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    wallets_dir: []u8,
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    peer_manager: *peer_mod.PeerManager,
    wm: *wallet_mod.WalletManager,
    server: *rpc.RpcServer,
    thread: std.Thread,
    port: u16,

    fn start(allocator: std.mem.Allocator, wallet_names: []const []const u8) !*Live {
        const self = try allocator.create(Live);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.tmp = std.testing.tmpDir(.{});
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const root = try self.tmp.dir.realpath(".", &buf);
        self.wallets_dir = try std.fs.path.join(allocator, &.{ root, "wallets" });

        self.chain_state = try allocator.create(storage.ChainState);
        self.chain_state.* = storage.ChainState.init(null, 64, allocator);
        self.mempool = try allocator.create(mempool_mod.Mempool);
        self.mempool.* = mempool_mod.Mempool.init(null, null, allocator);
        self.peer_manager = try allocator.create(peer_mod.PeerManager);
        self.peer_manager.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
        self.wm = try allocator.create(wallet_mod.WalletManager);
        self.wm.* = try wallet_mod.WalletManager.init(allocator, self.wallets_dir, .regtest);
        for (wallet_names) |n| _ = try self.wm.createWallet(n, .{});

        self.server = try allocator.create(rpc.RpcServer);
        self.server.* = rpc.RpcServer.initWithWalletManager(
            allocator,
            self.chain_state,
            self.mempool,
            self.peer_manager,
            &consensus.REGTEST,
            self.wm,
            .{ .port = 0 },
        );
        try self.server.start();
        self.port = self.server.listener.?.listen_address.getPort();
        self.thread = try std.Thread.spawn(.{}, runServer, .{self.server});
        return self;
    }
    fn runServer(srv: *rpc.RpcServer) void {
        srv.run() catch {};
    }
    fn stop(self: *Live) void {
        const a = self.allocator;
        self.server.stop();
        self.thread.join();
        if (self.server.listener) |*l| l.deinit();
        self.server.listener = null;
        self.server.deinit();
        self.wm.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
        a.destroy(self.server);
        a.destroy(self.wm);
        a.destroy(self.peer_manager);
        a.destroy(self.mempool);
        a.destroy(self.chain_state);
        a.free(self.wallets_dir);
        self.tmp.cleanup();
        a.destroy(self);
    }

    /// POST `body` to `path`; returns the HTTP body (caller frees).
    fn post(self: *Live, path: []const u8, body: []const u8) ![]u8 {
        const s = try std.net.tcpConnectToAddress(try std.net.Address.parseIp("127.0.0.1", self.port));
        defer s.close();
        const tv = std.posix.timeval{ .tv_sec = 20, .tv_usec = 0 };
        std.posix.setsockopt(s.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        var hdr: [256]u8 = undefined;
        const h = try std.fmt.bufPrint(&hdr, "POST {s} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{ path, body.len });
        try s.writeAll(h);
        try s.writeAll(body);
        var reply = std.ArrayList(u8).init(self.allocator);
        defer reply.deinit();
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = s.read(&chunk) catch |e| {
                if (e == error.WouldBlock) return error.RpcDidNotAnswerInTime;
                return e;
            };
            if (n == 0) break;
            try reply.appendSlice(chunk[0..n]);
        }
        const at = (std.mem.indexOf(u8, reply.items, "\r\n\r\n") orelse return error.NoHttpReply) + 4;
        return self.allocator.dupe(u8, reply.items[at..]);
    }
};

fn errorCode(v: std.json.Value) ?i64 {
    if (v != .object) return null;
    const e = v.object.get("error") orelse return null;
    if (e != .object) return null;
    const c = e.object.get("code") orelse return null;
    return if (c == .integer) c.integer else null;
}

fn walletName(v: std.json.Value) ?[]const u8 {
    if (v != .object) return null;
    const r = v.object.get("result") orelse return null;
    if (r != .object) return null;
    const n = r.object.get("walletname") orelse return null;
    return if (n == .string) n.string else null;
}

test "current_wallet unloadwallet then getwalletinfo in one batch to /wallet/w returns -18, not freed memory" {
    const allocator = testing.allocator;
    const live = try Live.start(allocator, &.{"w"});
    defer live.stop();

    const resp = try live.post(
        "/wallet/w",
        "[{\"id\":1,\"method\":\"unloadwallet\",\"params\":[\"w\"]},{\"id\":2,\"method\":\"getwalletinfo\",\"params\":[]}]",
    );
    defer allocator.free(resp);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    if (parsed.value != .array or parsed.value.array.items.len != 2) {
        std.debug.print("\nreply: {s}\n", .{resp});
        return error.NotABatchReplyOfTwo;
    }
    const first = parsed.value.array.items[0];
    const second = parsed.value.array.items[1];
    // The unload itself succeeds.
    if (errorCode(first) != null) {
        std.debug.print("\nunloadwallet: {s}\n", .{resp});
        return error.UnloadFailed;
    }
    // Core: the next request resolves /wallet/w afresh, finds nothing, and
    // throws RPC_WALLET_NOT_FOUND (-18).
    if (errorCode(second) != -18) {
        std.debug.print("\ngetwalletinfo after unload answered: {s}\n", .{resp});
        return error.UnloadedWalletStillUsed;
    }
    try testing.expectEqual(@as(usize, 0), live.wm.count());
}

test "current_wallet a waitfor batch to /wallet/w runs its wallet call on w even after a /wallet/v request" {
    const allocator = testing.allocator;
    const live = try Live.start(allocator, &.{ "w", "v" });
    defer live.stop();

    const Waiter = struct {
        fn run(l: *Live, out: *?[]u8) void {
            // Height far above the tip, 4 s timeout: the wait times out and
            // the batch then runs getwalletinfo, all on the wait thread.
            out.* = l.post(
                "/wallet/w",
                "[{\"id\":1,\"method\":\"waitforblockheight\",\"params\":[1000000,4000]},{\"id\":2,\"method\":\"getwalletinfo\",\"params\":[]}]",
            ) catch null;
        }
    };
    var waiter_reply: ?[]u8 = null;
    const th = try std.Thread.spawn(.{}, Waiter.run, .{ live, &waiter_reply });

    // While the batch is parked in its wait, another connection targets v.
    std.time.sleep(400 * std.time.ns_per_ms);
    const other = try live.post("/wallet/v", "{\"id\":9,\"method\":\"getwalletinfo\",\"params\":[]}");
    defer allocator.free(other);
    {
        const p = try std.json.parseFromSlice(std.json.Value, allocator, other, .{});
        defer p.deinit();
        try testing.expectEqualStrings("v", walletName(p.value) orelse "<none>");
    }

    th.join();
    const resp = waiter_reply orelse return error.WaitBatchGotNoReply;
    defer allocator.free(resp);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    if (parsed.value != .array or parsed.value.array.items.len != 2) {
        std.debug.print("\nreply: {s}\n", .{resp});
        return error.NotABatchReplyOfTwo;
    }
    const got = walletName(parsed.value.array.items[1]) orelse "<none>";
    if (!std.mem.eql(u8, got, "w")) {
        std.debug.print("\n/wallet/w batch ran getwalletinfo on wallet \"{s}\": {s}\n", .{ got, resp });
        return error.WrongWallet;
    }
}

test "current_wallet CONTROL a plain request to /wallet/missing still answers -18" {
    const allocator = testing.allocator;
    const live = try Live.start(allocator, &.{"w"});
    defer live.stop();
    const resp = try live.post("/wallet/missing", "{\"id\":1,\"method\":\"getwalletinfo\",\"params\":[]}");
    defer allocator.free(resp);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(?i64, -18), errorCode(parsed.value));
}

test "current_wallet CONTROL a batch to /wallet/w answers every element on w" {
    const allocator = testing.allocator;
    const live = try Live.start(allocator, &.{ "w", "v" });
    defer live.stop();
    const resp = try live.post(
        "/wallet/w",
        "[{\"id\":1,\"method\":\"getwalletinfo\",\"params\":[]},{\"id\":2,\"method\":\"getblockcount\",\"params\":[]},{\"id\":3,\"method\":\"getwalletinfo\",\"params\":[]}]",
    );
    defer allocator.free(resp);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .array and parsed.value.array.items.len == 3);
    try testing.expectEqualStrings("w", walletName(parsed.value.array.items[0]) orelse "<none>");
    try testing.expectEqual(@as(?i64, null), errorCode(parsed.value.array.items[1]));
    try testing.expectEqualStrings("w", walletName(parsed.value.array.items[2]) orelse "<none>");
}
