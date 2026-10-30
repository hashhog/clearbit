//! Security audit H7 (audits/security/clearbit-2026-10-29.md): the Prometheus
//! metrics listener bound 0.0.0.0, had no read timeout on its single-threaded
//! accept loop, and answered any request with the /metrics body.
//!
//! Each test is gated on the API the fix adds, so this file compiles on a
//! base commit and every test there fails by name with the reason.

const std = @import("std");
const testing = std.testing;
const main_mod = @import("main.zig");

const has_fix = @hasField(main_mod.Config, "metrics_bind") and @hasDecl(main_mod, "serveMetrics");

fn missingFix(what: []const u8) error{TestUnexpectedResult} {
    std.debug.print("H7 not fixed on this commit: {s}\n", .{what});
    return error.TestUnexpectedResult;
}

const FixedSource = struct {
    fn height(_: *anyopaque) u32 {
        return 4242;
    }
    fn snapshot(_: *anyopaque) main_mod.MetricsSnapshot {
        return .{ .height = 4242, .peers = 7, .mempool_count = 3 };
    }
};

/// A metrics listener on 127.0.0.1:<ephemeral> served by its own thread.
const Harness = struct {
    server: std.net.Server,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: std.Thread = undefined,
    dummy: u8 = 0,

    fn start(self: *Harness) !void {
        self.server = try main_mod.metricsListen("127.0.0.1", 0);
        self.thread = try std.Thread.spawn(.{}, main_mod.serveMetrics, .{
            &self.server,
            main_mod.MetricsSource{
                .ctx = &self.dummy,
                .heightFn = FixedSource.height,
                .snapshotFn = FixedSource.snapshot,
            },
            &self.stop,
        });
    }

    fn port(self: *Harness) u16 {
        return self.server.listen_address.getPort();
    }

    fn finish(self: *Harness) void {
        self.stop.store(true, .release);
        // Wake the blocked accept so the loop sees `stop`.
        if (std.net.tcpConnectToAddress(self.server.listen_address)) |s| s.close() else |_| {}
        self.thread.join();
        self.server.deinit();
    }
};

fn connect(port: u16) !std.net.Stream {
    const s = try std.net.tcpConnectToAddress(try std.net.Address.parseIp("127.0.0.1", port));
    // Bound the test client too, so a regression fails instead of hanging.
    const tv = std.posix.timeval{ .tv_sec = 20, .tv_usec = 0 };
    try std.posix.setsockopt(s.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    return s;
}

/// Send `request`, read to EOF. Returns the bytes read (caller frees).
fn roundTrip(port: u16, request: []const u8) ![]u8 {
    const s = try connect(port);
    defer s.close();
    try s.writeAll(request);
    return s.reader().readAllAlloc(testing.allocator, 1 << 16);
}

test "H7 metrics binds 127.0.0.1 by default, not 0.0.0.0" {
    if (comptime !has_fix) return missingFix("no metrics bind setting; metricsServerThread binds 0.0.0.0");
    const cfg = main_mod.Config{};
    try testing.expectEqualStrings("127.0.0.1", cfg.metrics_bind);

    var server = try main_mod.metricsListen(cfg.metrics_bind, 0);
    defer server.deinit();
    const ip = std.mem.asBytes(&server.listen_address.in.sa.addr);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, ip);
}

test "H7 metricsListen honours an explicit bind and rejects a non-address" {
    if (comptime !has_fix) return missingFix("no metricsListen(bind, port)");
    var server = try main_mod.metricsListen("0.0.0.0", 0);
    server.deinit();
    try testing.expectError(error.InvalidIPAddressFormat, main_mod.metricsListen("not-an-ip", 0));
}

test "H7 a silent client does not wedge the metrics listener" {
    if (comptime !has_fix) return missingFix("stream.read has no timeout; one silent client holds the accept loop");
    var h = Harness{ .server = undefined };
    try h.start();
    defer h.finish();

    // A connects and sends nothing; it is accepted first.
    const silent = try connect(h.port());
    defer silent.close();
    std.time.sleep(200 * std.time.ns_per_ms);

    var timer = try std.time.Timer.start();
    const resp = try roundTrip(h.port(), "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
    defer testing.allocator.free(resp);
    const ms = timer.read() / std.time.ns_per_ms;
    std.debug.print("H7 silent: /metrics answered after {d} ms\n", .{ms});

    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, resp, "bitcoin_blocks_total 4242\n") != null);
    // The silent client is dropped at METRICS_IO_TIMEOUT_MS (+1 s read slice).
    try testing.expect(ms <= main_mod.METRICS_IO_TIMEOUT_MS + 2_000);
}

fn trickle(s: std.net.Stream, stop: *std.atomic.Value(bool)) void {
    while (!stop.load(.acquire)) {
        _ = s.write("G") catch return;
        std.time.sleep(300 * std.time.ns_per_ms);
    }
}

test "H7 a trickling client cannot hold the metrics listener past the deadline" {
    if (comptime !has_fix) return missingFix("no total read deadline on the metrics request");
    var h = Harness{ .server = undefined };
    try h.start();
    defer h.finish();

    const slow = try connect(h.port());
    defer slow.close();
    var stop_trickle = std.atomic.Value(bool).init(false);
    const t = try std.Thread.spawn(.{}, trickle, .{ slow, &stop_trickle });
    defer {
        stop_trickle.store(true, .release);
        t.join();
    }
    std.time.sleep(200 * std.time.ns_per_ms);

    var timer = try std.time.Timer.start();
    const resp = try roundTrip(h.port(), "GET /health HTTP/1.1\r\n\r\n");
    defer testing.allocator.free(resp);
    const ms = timer.read() / std.time.ns_per_ms;
    std.debug.print("H7 trickle: /health answered after {d} ms\n", .{ms});

    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, resp, "\"height\":4242") != null);
    try testing.expect(ms <= main_mod.METRICS_IO_TIMEOUT_MS + 2_000);
}

test "H7 only GET /metrics and GET /health are answered" {
    if (comptime !has_fix) return missingFix("every request gets the /metrics body");
    try testing.expectEqual(main_mod.MetricsRoute.metrics, main_mod.metricsRoute("GET /metrics HTTP/1.1"));
    try testing.expectEqual(main_mod.MetricsRoute.metrics, main_mod.metricsRoute("GET /metrics?x=1 HTTP/1.1"));
    try testing.expectEqual(main_mod.MetricsRoute.health, main_mod.metricsRoute("GET /health HTTP/1.0"));
    try testing.expectEqual(main_mod.MetricsRoute.not_found, main_mod.metricsRoute("GET / HTTP/1.1"));
    try testing.expectEqual(main_mod.MetricsRoute.not_found, main_mod.metricsRoute("GET /metricsx HTTP/1.1"));
    try testing.expectEqual(main_mod.MetricsRoute.not_found, main_mod.metricsRoute("GET /x/health HTTP/1.1"));
    try testing.expectEqual(main_mod.MetricsRoute.bad_method, main_mod.metricsRoute("POST /metrics HTTP/1.1"));
    try testing.expectEqual(main_mod.MetricsRoute.bad_method, main_mod.metricsRoute(""));

    var h = Harness{ .server = undefined };
    try h.start();
    defer h.finish();

    const cases = [_]struct { req: []const u8, status: []const u8 }{
        .{ .req = "GET / HTTP/1.1\r\n\r\n", .status = "HTTP/1.1 404 Not Found\r\n" },
        .{ .req = "POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n", .status = "HTTP/1.1 405 Method Not Allowed\r\n" },
        .{ .req = "GET /metrics HTTP/1.1\r\n\r\n", .status = "HTTP/1.1 200 OK\r\n" },
        .{ .req = "GET /health HTTP/1.1\r\n\r\n", .status = "HTTP/1.1 200 OK\r\n" },
    };
    for (cases) |c| {
        const resp = try roundTrip(h.port(), c.req);
        defer testing.allocator.free(resp);
        if (!std.mem.startsWith(u8, resp, c.status)) {
            std.debug.print("H7 route: {s} -> {s}\n", .{ c.req, resp });
            return error.TestUnexpectedResult;
        }
    }
}
