//! Outbound dials must not block the P2P message thread.
//!
//! QUEUES clearbit item 0 (2026-10-03 p2p-join review): `maintainOutbound`
//! dialled inline, so one step could spend up to 8 x (5 s connect + 10 s v2
//! handshake + 60 s v1 fallback) with no message processing — a likely cause
//! of multi-minute header-processing silence.
//!
//! Instrument: the peers are "tarpits" — loopback listeners that complete the
//! TCP handshake in the kernel backlog and then never read or answer, so a
//! synchronous dial sits in the version handshake.  A watchdog thread calls
//! stop() after WATCHDOG_MS so that, on the pre-fix code, the call returns
//! (stop interrupts the handshake) instead of hanging the suite for minutes;
//! the elapsed time then still exceeds the bound and the test fails by name.
//!
//! CONTROL: `zig build test-async-dials --summary new`

const std = @import("std");
const testing = std.testing;
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");

const WATCHDOG_MS: u64 = 3000;
/// maintainOutbound must hand the dials off and return well inside this.
const RETURN_BOUND_MS: i64 = 1000;

const Tarpit = struct {
    server: std.net.Server,

    fn open() !Tarpit {
        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        return .{ .server = try addr.listen(.{ .reuse_address = true, .force_nonblocking = true }) };
    }
    fn close(self: *Tarpit) void {
        self.server.deinit();
    }
    fn address(self: *const Tarpit) std.net.Address {
        return self.server.listen_address;
    }
    /// True if a dial reached this listener's backlog.
    fn dialled(self: *Tarpit) bool {
        const c = self.server.accept() catch return false;
        c.stream.close();
        return true;
    }
};

fn watchdog(pm: *peer_mod.PeerManager, delay_ms: u64) void {
    std.time.sleep(delay_ms * std.time.ns_per_ms);
    pm.stop();
}

fn addKnown(pm: *peer_mod.PeerManager, addr: std.net.Address) !void {
    try pm.known_addresses.put(peer_mod.PeerManager.addressKey(addr), .{
        .address = addr,
        .services = 1,
        .last_seen = std.time.timestamp(),
        .last_tried = 0,
        .attempts = 0,
        .success = false,
        .source = .peer_addr,
    });
}

test "async_dials: maintainOutbound returns at once with unresponsive peers in the address book" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    var tarpits: [3]Tarpit = undefined;
    for (&tarpits) |*t| t.* = try Tarpit.open();
    defer for (&tarpits) |*t| t.close();
    for (&tarpits) |*t| try addKnown(&pm, t.address());

    const wd = try std.Thread.spawn(.{}, watchdog, .{ &pm, WATCHDOG_MS });
    defer wd.join();

    const start = std.time.milliTimestamp();
    try pm.maintainOutbound();
    const elapsed = std.time.milliTimestamp() - start;
    pm.stop();

    try testing.expect(elapsed < RETURN_BOUND_MS);
}

test "async_dials: concurrent dials are bounded" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    var tarpits: [8]Tarpit = undefined;
    for (&tarpits) |*t| t.* = try Tarpit.open();
    defer for (&tarpits) |*t| t.close();
    for (&tarpits) |*t| try addKnown(&pm, t.address());

    const wd = try std.Thread.spawn(.{}, watchdog, .{ &pm, WATCHDOG_MS });
    defer wd.join();

    // Several ticks, as the run loop would make them.
    var tick: usize = 0;
    while (tick < 5 and !pm.stop_requested.load(.acquire)) : (tick += 1) {
        try pm.maintainOutbound();
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    var reached: usize = 0;
    for (&tarpits) |*t| {
        if (t.dialled()) reached += 1;
    }
    pm.stop();

    try testing.expect(reached >= 1); // the instrument saw dials at all
    try testing.expect(reached <= peer_mod.MAX_CONCURRENT_OUTBOUND_DIALS);
}

test "async_dials: stop interrupts in-flight dials promptly" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);

    var tarpits: [3]Tarpit = undefined;
    for (&tarpits) |*t| t.* = try Tarpit.open();
    defer for (&tarpits) |*t| t.close();
    for (&tarpits) |*t| try addKnown(&pm, t.address());

    try pm.maintainOutbound();
    std.time.sleep(300 * std.time.ns_per_ms); // dials are now in the handshake

    const start = std.time.milliTimestamp();
    pm.stop();
    pm.deinit(); // joins (bounded) the dial workers
    const elapsed = std.time.milliTimestamp() - start;
    try testing.expect(elapsed < 2000);
}

// ---------------------------------------------------------------------------
// hashhog/clearbit#17 review (Warden, 2026-10-18).
// ---------------------------------------------------------------------------

fn socketPeer(allocator: std.mem.Allocator, addr: std.net.Address, far_ends: *std.ArrayList(std.posix.fd_t)) !*peer_mod.Peer {
    var fds: [2]i32 = undefined;
    if (std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0, &fds) != 0)
        return error.SocketPair;
    try far_ends.append(fds[1]);
    const p = try allocator.create(peer_mod.Peer);
    p.* = peer_mod.Peer.fromOutboundStream(.{ .handle = fds[0] }, addr, &consensus.MAINNET, allocator);
    return p;
}

// A dial result queued after its slot was filled must not push the
// outbound count past the target.  maintainOutbound used to count only
// running workers, so a dial that queued its result between the adopt and
// the count was in neither, a second dial started, and both were adopted.
test "async_dials: a finished dial is not adopted past the outbound target" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();
    var far_ends = std.ArrayList(std.posix.fd_t).init(allocator);
    defer {
        for (far_ends.items) |fd| std.posix.close(fd);
        far_ends.deinit();
    }

    const target: usize = peer_mod.MAX_OUTBOUND_CONNECTIONS;
    try testing.expect(!pm.try_new_outbound);
    var i: usize = 0;
    while (i < target) : (i += 1) {
        const a = std.net.Address.initIp4(.{ 10, @intCast(i + 1), 0, 1 }, 8333);
        try pm.peers.append(try socketPeer(allocator, a, &far_ends));
    }

    // One more dial finished and queued its (successful) result.
    const extra = std.net.Address.initIp4(.{ 10, 200, 0, 1 }, 8333);
    const R = std.meta.Elem(@TypeOf(pm.dial_done.items));
    try pm.dial_done.append(allocator, R{ .addr = extra, .peer = try socketPeer(allocator, extra, &far_ends), .v1_fallback = false });

    pm.adoptOutboundDials();

    var outbound: usize = 0;
    for (pm.peers.items) |p| {
        if (p.direction == .outbound) outbound += 1;
    }
    try testing.expectEqual(target, outbound);
}

// A dial worker parked in the SOCKS5 exchange must be woken by stop().
// The proxy is a tarpit: the TCP connect to it succeeds (kernel backlog) and
// the SOCKS5 greeting is never answered, so each read blocks for
// SOCKS5_RECV_TIMEOUT_SEC (20 s).  Before the fix that socket was not in the
// peer-fd registry until connectViaProxy returned, stop() could not reach
// it, and deinit's bounded wait then freed the manager under the worker.
// This test waits for the worker itself before deinit, so the pre-fix run
// fails on the expectation instead of on the use-after-free.
test "async_dials: stop interrupts a dial blocked in an unanswered SOCKS5 exchange" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);

    var proxy = try Tarpit.open();
    defer proxy.close();
    var spec_buf: [32]u8 = undefined;
    const spec = try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{proxy.address().getPort()});
    pm.initProxy(spec, null, null);
    try testing.expect(pm.proxy_manager != null);

    // The target itself is never contacted: the proxy never answers.
    try addKnown(&pm, std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 18333));

    try pm.maintainOutbound();
    try testing.expectEqual(@as(u32, 1), pm.dial_workers.load(.acquire));
    std.time.sleep(300 * std.time.ns_per_ms); // worker is in the SOCKS5 read
    // Instrument: the dial reached the proxy.  The accepted end is HELD open:
    // closing it would end the SOCKS5 read by EOF, and the test would pass
    // without stop() doing anything.
    const held = try proxy.server.accept();
    defer held.stream.close();

    pm.stop();
    var waited: u64 = 0;
    while (pm.dial_workers.load(.acquire) != 0 and waited < 3000) : (waited += 10)
        std.time.sleep(10 * std.time.ns_per_ms);
    const alive_after_stop = pm.dial_workers.load(.acquire);
    // Pre-fix: let the worker run out its recv timeouts before freeing.
    while (pm.dial_workers.load(.acquire) != 0) std.time.sleep(50 * std.time.ns_per_ms);
    pm.deinit();

    try testing.expectEqual(@as(u32, 0), alive_after_stop);
}

// stop() + deinit() never return with a dial worker still alive, proxied
// dial included (deinit used to give up after 10 s and free regardless).
test "async_dials: deinit returns only after every proxied dial worker exited" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);

    var proxy = try Tarpit.open();
    defer proxy.close();
    var spec_buf: [32]u8 = undefined;
    const spec = try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{proxy.address().getPort()});
    pm.initProxy(spec, null, null);
    try addKnown(&pm, std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 18333));

    try pm.maintainOutbound();
    std.time.sleep(300 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u32, 1), pm.dial_workers.load(.acquire));

    const start = std.time.milliTimestamp();
    pm.stop();
    pm.deinit();
    const elapsed = std.time.milliTimestamp() - start;
    // `pm` is a stack value: its atomic stays readable after deinit.
    const alive_after_deinit = pm.dial_workers.load(.acquire);
    // Pre-fix: the worker outlives deinit; keep this frame (and `pm`) alive
    // until it is gone so its use-after-free lands in this test, not a later
    // one.  This test is last in the file for the same reason.
    while (pm.dial_workers.load(.acquire) != 0) std.time.sleep(50 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u32, 0), alive_after_deinit);
    try testing.expect(elapsed < 2000);
}
