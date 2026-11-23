//! The RPC server must bound the WHOLE header read, not each read() alone
//! (security audit H5 residual).
//!
//! `handleConnection` sets SO_RCVTIMEO = 30s on the client socket.  That
//! bounds one read(); every byte that arrives starts the 30s again.  A client
//! that sends one header byte per second therefore holds a connection worker
//! indefinitely, and 64 such clients fill MAX_CONN_WORKERS so every later
//! client is answered 503 "Work queue depth exceeded".
//!
//! The tests drive the REAL HTTP path: an `RpcServer` on an ephemeral
//! loopback port with its accept loop on a thread.
//!
//! Run: `zig build test-rpc-header-deadline` (also folded into `zig build test`).

const std = @import("std");
const testing = std.testing;
const peer_mod = @import("peer.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const mempool_mod = @import("mempool.zig");
const rpc = @import("rpc.zig");

/// The item's bar: a one-byte-per-second drip must be cut off within 70s.
const DRIP_BUDGET_S: u64 = 70;

const Fixture = struct {
    allocator: std.mem.Allocator,
    params: consensus.NetworkParams,
    tmp_dir: testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: peer_mod.PeerManager,
    mp: mempool_mod.Mempool,
    server: rpc.RpcServer,
    server_thread: ?std.Thread = null,
    port: u16 = 0,

    fn init(self: *Fixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.server_thread = null;
        self.params = consensus.REGTEST;
        self.tmp_dir = testing.tmpDir(.{});
        self.path = try self.tmp_dir.dir.realpathAlloc(allocator, ".");
        self.db = try storage.Database.open(self.path, 64, allocator);
        self.cs = storage.ChainState.init(&self.db, 64, allocator);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(&self.params);
        self.cs.best_hash = self.params.genesis_hash;
        self.cs.initGenesisTimestamp(self.params.genesis_header.timestamp);
        self.pm = peer_mod.PeerManager.init(allocator, &self.params);
        self.pm.anchors_path = "/dev/null";
        self.pm.chain_state = &self.cs;
        self.mp = mempool_mod.Mempool.init(&self.cs, &self.params, allocator);
        self.pm.mempool = &self.mp;
        self.server = rpc.RpcServer.init(allocator, &self.cs, &self.mp, &self.pm, &self.params, .{ .port = 0 });
        try self.server.start();
        self.port = self.server.listener.?.listen_address.getPort();
        self.server.config.port = self.port;
        self.server_thread = try std.Thread.spawn(.{}, serverRun, .{&self.server});
    }

    fn serverRun(s: *rpc.RpcServer) void {
        s.run() catch {};
    }

    fn deinit(self: *Fixture) void {
        self.server.stop();
        if (self.server_thread) |t| t.join();
        self.server.deinit();
        self.pm.deinit();
        self.mp.deinit();
        self.cs.deinit();
        self.db.close();
        self.allocator.free(self.path);
        self.tmp_dir.cleanup();
    }

    fn connect(self: *Fixture) !std.net.Stream {
        return std.net.tcpConnectToAddress(std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, self.port));
    }

    /// Plain request on a fresh connection; returns the full reply.
    fn request(self: *Fixture, allocator: std.mem.Allocator, req: []const u8) ![]u8 {
        const conn = try self.connect();
        defer conn.close();
        try conn.writeAll(req);
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = conn.read(&buf) catch break;
            if (n == 0) break;
            try out.appendSlice(buf[0..n]);
        }
        return out.toOwnedSlice();
    }
};

/// True once the server has closed `fd` (EOF or reset on our side).
fn peerClosed(fd: std.posix.fd_t, wait_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const r = std.posix.poll(&fds, wait_ms) catch return true;
    if (r == 0) return false;
    if (fds[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR) != 0) return true;
    var b: [256]u8 = undefined;
    const n = std.posix.recv(fd, &b, std.posix.MSG.DONTWAIT) catch |e| switch (e) {
        error.WouldBlock => return false,
        else => return true,
    };
    return n == 0;
}

/// Drip `prefix` (and then filler header bytes) one byte per second; return
/// the seconds until the server closed the connection, or null if it was
/// still open after `budget_s`.
fn dripUntilClosed(f: *Fixture, budget_s: u64) !?u64 {
    const conn = try f.connect();
    defer conn.close();
    const prefix = "POST / HTTP/1.1\r\nX-Drip: ";
    const t0 = try std.time.Instant.now();
    var i: usize = 0;
    while (true) {
        const elapsed_s = (try std.time.Instant.now()).since(t0) / std.time.ns_per_s;
        if (elapsed_s >= budget_s) return null;
        const byte: u8 = if (i < prefix.len) prefix[i] else 'a';
        i += 1;
        _ = std.posix.send(conn.handle, &[_]u8{byte}, std.posix.MSG.NOSIGNAL) catch {
            return (try std.time.Instant.now()).since(t0) / std.time.ns_per_s;
        };
        if (peerClosed(conn.handle, 1000)) {
            return (try std.time.Instant.now()).since(t0) / std.time.ns_per_s;
        }
    }
}

test "tests_rpc_header_deadline: a one-byte-per-second header drip is closed within 70s" {
    const allocator = testing.allocator;
    var f: Fixture = undefined;
    try f.init(allocator);
    defer f.deinit();

    const closed_after = try dripUntilClosed(&f, DRIP_BUDGET_S);
    if (closed_after) |s| {
        std.debug.print("drip connection closed by server after {d}s\n", .{s});
        // Instrument check: the drip must have been ACCEPTED and tolerated
        // for a while.  A close in the first seconds would mean the server
        // refused the connection for some other reason (503, parse error),
        // and this test would be measuring that instead of the deadline.
        try testing.expect(s >= 20);
    } else {
        std.debug.print("RED: drip connection still open after {d}s (no overall header deadline)\n", .{DRIP_BUDGET_S});
        return error.TestUnexpectedResult;
    }

    // The server is still serving: an ordinary request gets an answer.
    const reply = try f.request(allocator, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    defer allocator.free(reply);
    try testing.expect(std.mem.startsWith(u8, reply, "HTTP/1.1 405"));
}

test "tests_rpc_header_deadline: a client that sends its headers promptly is still answered" {
    // Control: the deadline must not cut off a normal client, including one
    // whose headers arrive in several writes.
    const allocator = testing.allocator;
    var f: Fixture = undefined;
    try f.init(allocator);
    defer f.deinit();

    const conn = try f.connect();
    defer conn.close();
    try conn.writeAll("GET / HTTP/1.1\r\n");
    std.time.sleep(200 * std.time.ns_per_ms);
    try conn.writeAll("Host: 127.0.0.1\r\n");
    std.time.sleep(200 * std.time.ns_per_ms);
    try conn.writeAll("\r\n");
    var buf: [4096]u8 = undefined;
    const n = try conn.read(&buf);
    try testing.expect(std.mem.startsWith(u8, buf[0..n], "HTTP/1.1 405"));
}
