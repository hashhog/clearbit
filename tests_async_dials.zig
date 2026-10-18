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
