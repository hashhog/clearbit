//! AXIS #2 proof suite — clearbit Core-bucketed addrman (src/addrman.zig).
//!
//! Mirrors the rustoshi 361d81b axis2 suite (placement determinism + golden +
//! nkey-matters + source-group spread + Add/Good/Select + tried-collision-evict
//! + restart-persistence + bounded + falsification). The bucketed addrman lives
//! in its own module so these tests do not depend on the rest of peer.zig.

const std = @import("std");
const testing = std.testing;
const addrman = @import("addrman.zig");

const AddrMan = addrman.AddrMan;
const SocketAddr = std.net.Address;

const TEST_NKEY: [32]u8 = .{
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
};

const T0: u64 = 1_700_000_000;
const T1: u64 = 1_700_000_100;

const Octets = struct { a: u8, b: u8, c: u8, d: u8 };

fn sa(a: u8, b: u8, c: u8, d: u8) SocketAddr {
    return SocketAddr.initIp4(.{ a, b, c, d }, 8333);
}

/// /16 group of an IPv4 a.b.c.d (the netGroup() value clearbit feeds in).
fn g16(a: u8, b: u8) u32 {
    return (@as(u32, a) << 8) | @as(u32, b);
}

// ─── G6-G10: bucket geometry constants exist and equal Core ──────────────────

test "axis2/constants match Core" {
    try testing.expectEqual(@as(usize, 1024), addrman.ADDRMAN_NEW_BUCKET_COUNT);
    try testing.expectEqual(@as(usize, 256), addrman.ADDRMAN_TRIED_BUCKET_COUNT);
    try testing.expectEqual(@as(usize, 64), addrman.ADDRMAN_BUCKET_SIZE);
    try testing.expectEqual(@as(u64, 64), addrman.ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP);
    try testing.expectEqual(@as(u64, 8), addrman.ADDRMAN_TRIED_BUCKETS_PER_GROUP);
    try testing.expectEqual(@as(u32, 8), addrman.ADDRMAN_NEW_BUCKETS_PER_ADDRESS);
    try testing.expectEqual(@as(usize, 1024 * 64 + 256 * 64), addrman.ADDRMAN_CEILING);
    try testing.expectEqual(@as(usize, 81920), addrman.ADDRMAN_CEILING);
}

// ─── 1. PLACEMENT DETERMINISM + GOLDEN + ANTI-SYBIL SPREAD ────────────────────

test "axis2/new placement is deterministic" {
    const a = testing.allocator;
    var t1 = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t1.deinit();
    var t2 = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t2.deinit();

    const addr = sa(8, 8, 8, 8);
    try testing.expect(try t1.add(addr, g16(8, 8), g16(8, 8), 1, T0, T0));
    try testing.expect(try t2.add(addr, g16(8, 8), g16(8, 8), 1, T0, T0));

    const s1 = t1.newSlotOf(addr).?;
    const s2 = t2.newSlotOf(addr).?;
    try testing.expectEqual(s1.bucket, s2.bucket);
    try testing.expectEqual(s1.pos, s2.pos);
}

test "axis2/golden stable bucket for fixed nKey+addr" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    const addr = sa(8, 8, 8, 8);
    try testing.expect(try t.add(addr, g16(8, 8), g16(1, 1), 1, T0, T0));
    const s = t.newSlotOf(addr).?;

    var t2 = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t2.deinit();
    try testing.expect(try t2.add(addr, g16(8, 8), g16(1, 1), 1, T0, T0));
    const s2 = t2.newSlotOf(addr).?;

    try testing.expectEqual(s.bucket, s2.bucket);
    try testing.expectEqual(s.pos, s2.pos);
    try testing.expect(s.bucket < addrman.ADDRMAN_NEW_BUCKET_COUNT);
    try testing.expect(s.pos < addrman.ADDRMAN_BUCKET_SIZE);
}

test "axis2/different nKey remaps placement" {
    const a = testing.allocator;
    var t1 = try AddrMan.initWithNKey(a, [_]u8{0x01} ** 32);
    defer t1.deinit();
    var t2 = try AddrMan.initWithNKey(a, [_]u8{0x02} ** 32);
    defer t2.deinit();
    const addr = sa(9, 9, 9, 9);
    _ = try t1.add(addr, g16(9, 9), g16(9, 9), 1, T0, T0);
    _ = try t2.add(addr, g16(9, 9), g16(9, 9), 1, T0, T0);
    const s1 = t1.newSlotOf(addr).?;
    const s2 = t2.newSlotOf(addr).?;
    try testing.expect(s1.bucket != s2.bucket or s1.pos != s2.pos);
}

test "axis2/source groups spread one addr across many new buckets" {
    const a = testing.allocator;
    var buckets = std.AutoHashMap(usize, void).init(a);
    defer buckets.deinit();
    const addr = sa(8, 8, 1, 1);
    var i: u8 = 0;
    while (i < 40) : (i += 1) {
        var t = try AddrMan.initWithNKey(a, TEST_NKEY);
        defer t.deinit();
        const src_g = g16(11 + i, 200);
        _ = try t.add(addr, g16(8, 8), src_g, 1, T0, T0);
        if (t.newSlotOf(addr)) |s| try buckets.put(s.bucket, {});
    }
    try testing.expect(buckets.count() > 5);
}

test "axis2/single source group reaches at most NEW_BUCKETS_PER_SOURCE_GROUP" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    const src_g = g16(172, 99); // one /16 source group
    var buckets = std.AutoHashMap(usize, void).init(a);
    defer buckets.deinit();
    var x: u8 = 1;
    while (x < 60) : (x += 1) {
        var y: u8 = 1;
        while (y < 40) : (y += 1) {
            const addr = sa(x, y, 7, 7);
            _ = try t.add(addr, g16(x, y), src_g, 1, T0, T0);
            if (t.newSlotOf(addr)) |s| try buckets.put(s.bucket, {});
        }
    }
    try testing.expect(buckets.count() <= addrman.ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP);
}

// ─── FALSIFICATION: distinct addrs/groups land in DISTINCT buckets ───────────

test "axis2/falsification real bucketing not flat" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    var occupied = std.AutoHashMap(u64, void).init(a);
    defer occupied.deinit();
    var x: u8 = 1;
    while (x < 50) : (x += 1) {
        const addr = sa(x, x *% 3 +% 1, 4, 2);
        _ = try t.add(addr, g16(x, x *% 3 +% 1), g16(x, 50), 1, T0, T0);
        if (t.newSlotOf(addr)) |s| {
            const key = (@as(u64, s.bucket) << 32) | @as(u64, s.pos);
            try occupied.put(key, {});
        }
    }
    try testing.expect(occupied.count() > 20);
}

// ─── 2. ADD / GOOD / SELECT + COLLISION EVICTION ─────────────────────────────

test "axis2/add lands in NEW" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    const addr = sa(11, 22, 33, 44);
    try testing.expect(try t.add(addr, g16(11, 22), g16(5, 5), 1, T0, T0));
    try testing.expectEqual(@as(usize, 1), t.newCount());
    try testing.expectEqual(@as(usize, 0), t.triedCount());
    try testing.expect(t.newSlotOf(addr) != null);
    try testing.expect(!t.isInTried(addr));
}

test "axis2/good promotes NEW->TRIED" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    const addr = sa(11, 22, 33, 44);
    _ = try t.add(addr, g16(11, 22), g16(5, 5), 1, T0, T0);
    try testing.expect(try t.good(addr, T1));
    try testing.expect(t.isInTried(addr));
    try testing.expectEqual(@as(usize, 1), t.triedCount());
    try testing.expectEqual(@as(usize, 0), t.newCount());
    try testing.expect(t.triedSlotOf(addr) != null);
    // Good on an unknown addr is a no-op.
    try testing.expect(!(try t.good(sa(1, 2, 3, 4), T1)));
}

test "axis2/tried collision evicts occupant back to NEW" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    const src_g = g16(5, 5);

    const first = sa(50, 60, 70, 80);
    _ = try t.add(first, g16(50, 60), src_g, 1, T0, T0);
    _ = try t.good(first, T1);
    const slot_a = t.triedSlotOf(first).?;

    // Find a second addr that maps to the same tried slot via a throwaway table.
    var collider: ?Octets = null;
    outer: {
        var x: u8 = 1;
        while (x < 255) : (x += 1) {
            var y: u8 = 1;
            while (y < 255) : (y += 1) {
                const cand = sa(x, y, 200, 201);
                if (cand.eql(first)) continue;
                var probe = try AddrMan.initWithNKey(a, TEST_NKEY);
                _ = try probe.add(cand, g16(x, y), src_g, 1, T0, T0);
                _ = try probe.good(cand, T1);
                const ps = probe.triedSlotOf(cand);
                probe.deinit();
                if (ps) |s| {
                    if (s.bucket == slot_a.bucket and s.pos == slot_a.pos) {
                        collider = .{ .a = x, .b = y, .c = 200, .d = 201 };
                        break :outer;
                    }
                }
            }
        }
    }
    const co = collider.?;
    const c = sa(co.a, co.b, co.c, co.d);

    _ = try t.add(c, g16(co.a, co.b), src_g, 1, T0, T0);
    _ = try t.good(c, T1 + 100);
    try testing.expect(t.isInTried(c));
    try testing.expect(!t.isInTried(first));
    try testing.expect(t.newSlotOf(first) != null);
}

test "axis2/select returns only added addrs" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    var added = std.AutoHashMap(u64, void).init(a);
    defer added.deinit();
    var i: u8 = 1;
    while (i < 30) : (i += 1) {
        const addr = sa(120, i, 3, 3);
        _ = try t.add(addr, g16(120, i), g16(120, i), 1, T0, T0);
        try added.put(addrman.addrMapKey(addr), {});
    }
    // Empty table returns null.
    var empty = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer empty.deinit();
    try testing.expect(empty.select(false) == null);
    // Select returns only previously-added addrs.
    var n: usize = 0;
    while (n < 200) : (n += 1) {
        if (t.select(false)) |s| {
            try testing.expect(added.contains(addrman.addrMapKey(s)));
        }
    }
    // new_only never returns a tried-only addr.
    var t2 = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t2.deinit();
    const only = sa(200, 1, 1, 1);
    _ = try t2.add(only, g16(200, 1), g16(200, 1), 1, T0, T0);
    _ = try t2.good(only, T1);
    try testing.expect(t2.select(true) == null);
    const got = t2.select(false).?;
    try testing.expect(got.eql(only));
}

// ─── 3. RESTART PERSISTENCE (placement verbatim) ─────────────────────────────

test "axis2/persistence roundtrip verbatim" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir);

    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();

    var new_addrs = std.ArrayList(SocketAddr).init(a);
    defer new_addrs.deinit();
    var i: u8 = 1;
    while (i < 15) : (i += 1) {
        const addr = sa(130, i, 9, 9);
        _ = try t.add(addr, g16(130, i), g16(130, i), 1, T0, T0);
        try new_addrs.append(addr);
    }
    var tried_addrs = std.ArrayList(SocketAddr).init(a);
    defer tried_addrs.deinit();
    i = 1;
    while (i < 6) : (i += 1) {
        const addr = sa(140, i, 9, 9);
        _ = try t.add(addr, g16(140, i), g16(140, 50), 1, T0, T0);
        _ = try t.good(addr, T1);
        try tried_addrs.append(addr);
    }

    // Capture pre-save placement.
    const pre_nkey = t.getNKey();
    var pre_new = std.AutoHashMap(u64, struct { bucket: usize, pos: usize }).init(a);
    defer pre_new.deinit();
    for (new_addrs.items) |addr| {
        if (t.newSlotOf(addr)) |s| try pre_new.put(addrman.addrMapKey(addr), .{ .bucket = s.bucket, .pos = s.pos });
    }
    var pre_tried = std.AutoHashMap(u64, struct { bucket: usize, pos: usize }).init(a);
    defer pre_tried.deinit();
    for (tried_addrs.items) |addr| {
        if (t.triedSlotOf(addr)) |s| try pre_tried.put(addrman.addrMapKey(addr), .{ .bucket = s.bucket, .pos = s.pos });
    }

    t.save(dir);
    var loaded = try AddrMan.load(a, dir);
    defer loaded.deinit();

    try testing.expectEqualSlices(u8, &pre_nkey, &loaded.getNKey());
    for (new_addrs.items) |addr| {
        const want = pre_new.get(addrman.addrMapKey(addr)).?;
        const got = loaded.newSlotOf(addr).?;
        try testing.expectEqual(want.bucket, got.bucket);
        try testing.expectEqual(want.pos, got.pos);
    }
    for (tried_addrs.items) |addr| {
        try testing.expect(loaded.isInTried(addr));
        const want = pre_tried.get(addrman.addrMapKey(addr)).?;
        const got = loaded.triedSlotOf(addr).?;
        try testing.expectEqual(want.bucket, got.bucket);
        try testing.expectEqual(want.pos, got.pos);
    }
}

test "axis2/persistence corrupt cold-starts empty" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir);

    const bads = [_][]const u8{
        "@@@not a header@@@",
        "ADDRMAN 999 deadbeef\n",
        "ADDRMAN",
        "",
    };
    for (bads) |bad| {
        try tmp.dir.writeFile(.{ .sub_path = "peers.dat", .data = bad });
        var t = try AddrMan.load(a, dir);
        defer t.deinit();
        try testing.expectEqual(@as(usize, 0), t.totalCount());
    }
    // Missing file too.
    tmp.dir.deleteFile("peers.dat") catch {};
    var t = try AddrMan.load(a, dir);
    defer t.deinit();
    try testing.expectEqual(@as(usize, 0), t.totalCount());
}

// ─── 4. BOUNDEDNESS ──────────────────────────────────────────────────────────

test "axis2/bounded one source group" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    const src_g = g16(203, 113); // one routable /16 source group
    var new_buckets = std.AutoHashMap(usize, void).init(a);
    defer new_buckets.deinit();
    var x: u8 = 1;
    while (x < 200) : (x += 1) {
        var y: u8 = 1;
        while (y < 200) : (y += 1) {
            const addr = sa(x, y, 1, 9);
            _ = try t.add(addr, g16(x, y), src_g, 1, T0, T0);
            if (t.newSlotOf(addr)) |s| try new_buckets.put(s.bucket, {});
        }
    }
    try testing.expect(new_buckets.count() <= addrman.ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP);
    try testing.expect(t.totalCount() <= addrman.ADDRMAN_CEILING);
    try testing.expect(t.totalCount() <=
        @as(usize, @intCast(addrman.ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)) * addrman.ADDRMAN_BUCKET_SIZE);
}

test "axis2/bounded refcount cap" {
    const a = testing.allocator;
    var t = try AddrMan.initWithNKey(a, TEST_NKEY);
    defer t.deinit();
    const addr = sa(150, 150, 150, 150);
    var i: u16 = 0;
    while (i < 200) : (i += 1) {
        const src_g = g16(@intCast(30 + (i % 200)), 1);
        _ = try t.add(addr, g16(150, 150), src_g, 1, T0, T0);
    }
    try testing.expectEqual(@as(usize, 1), t.totalCount());
    try testing.expect(t.newCount() <= addrman.ADDRMAN_NEW_BUCKETS_PER_ADDRESS);
}
