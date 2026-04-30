//! Debug-category logging for clearbit.
//!
//! Mirrors Bitcoin Core's BCLog::LogFlags categories (logging.h) and the
//! `-debug=<category>` flag in init.cpp. Operators pass one or more
//! categories on the CLI / config:
//!
//!   --debug=net                 # enable a single category
//!   --debug=net --debug=mempool # enable two
//!   --debug=all                 # everything
//!   --debug                     # legacy: same as --debug=all
//!
//! The check is a single 64-bit AND so the hot path (`enabled(.NET)`) is
//! free in release builds.
//!
//! Wiring: main.zig calls debug_log.parseCategory() per --debug=<cat>
//! occurrence and stores the OR-combined mask in `active_mask`. The mask is
//! a global atomic so any thread can probe it without locking.

const std = @import("std");

/// One bit per category. Identical names to BCLog::LogFlags so cross-impl
/// debug categories are interchangeable. We only enumerate categories
/// clearbit actually emits today; unknown categories are accepted (so
/// scripts targetting Bitcoin Core flags don't crash) but contribute
/// no extra output.
pub const Category = enum(u64) {
    NONE = 0,
    NET = 1 << 0,
    TOR = 1 << 1,
    MEMPOOL = 1 << 2,
    HTTP = 1 << 3,
    BENCH = 1 << 4,
    ZMQ = 1 << 5,
    WALLETDB = 1 << 6,
    RPC = 1 << 7,
    ESTIMATEFEE = 1 << 8,
    ADDRMAN = 1 << 9,
    SELECTCOINS = 1 << 10,
    REINDEX = 1 << 11,
    CMPCTBLOCK = 1 << 12,
    RAND = 1 << 13,
    PRUNE = 1 << 14,
    PROXY = 1 << 15,
    MEMPOOLREJ = 1 << 16,
    LIBEVENT = 1 << 17,
    COINDB = 1 << 18,
    QT = 1 << 19,
    LEVELDB = 1 << 20,
    VALIDATION = 1 << 21,
    I2P = 1 << 22,
    IPC = 1 << 23,
    LOCK = 1 << 24,
    UTIL = 1 << 25,
    BLOCKSTORAGE = 1 << 26,
    TXRECONCILIATION = 1 << 27,
    SCAN = 1 << 28,
    TXPACKAGES = 1 << 29,
    ALL = ~@as(u64, 0),

    pub fn toBit(self: Category) u64 {
        return @intFromEnum(self);
    }
};

/// Process-wide active-category mask. Toggled at startup by parseCategory().
/// Loads in `enabled()` are relaxed: a stale read just delays the next
/// log line by a few µs, never corrupts state.
pub var active_mask = std.atomic.Value(u64).init(0);

/// Parse a single `--debug=<value>` argument and OR its bit into the mask.
/// Unknown categories return false (caller logs a warning). "all", "1",
/// or empty string (`--debug` with no value) → ALL. "0" or "none" clears.
pub fn parseAndApply(value: []const u8) bool {
    const bits = parseCategory(value) orelse {
        return false;
    };
    if (value.len == 0 or std.mem.eql(u8, value, "0") or std.mem.eql(u8, value, "none")) {
        active_mask.store(0, .release);
        return true;
    }
    _ = active_mask.fetchOr(bits, .acq_rel);
    return true;
}

/// Look up a category name and return its bitmask.
/// Returns null when the name is unrecognized so callers can warn.
pub fn parseCategory(name: []const u8) ?u64 {
    if (name.len == 0) return @intFromEnum(Category.ALL);
    if (std.mem.eql(u8, name, "1") or std.mem.eql(u8, name, "all")) return @intFromEnum(Category.ALL);
    if (std.mem.eql(u8, name, "0") or std.mem.eql(u8, name, "none")) return @intFromEnum(Category.NONE);

    // Lowercase comparison — Bitcoin Core also uses lowercase.
    const Map = struct { name: []const u8, cat: Category };
    const table = [_]Map{
        .{ .name = "net", .cat = .NET },
        .{ .name = "tor", .cat = .TOR },
        .{ .name = "mempool", .cat = .MEMPOOL },
        .{ .name = "http", .cat = .HTTP },
        .{ .name = "bench", .cat = .BENCH },
        .{ .name = "zmq", .cat = .ZMQ },
        .{ .name = "walletdb", .cat = .WALLETDB },
        .{ .name = "rpc", .cat = .RPC },
        .{ .name = "estimatefee", .cat = .ESTIMATEFEE },
        .{ .name = "addrman", .cat = .ADDRMAN },
        .{ .name = "selectcoins", .cat = .SELECTCOINS },
        .{ .name = "reindex", .cat = .REINDEX },
        .{ .name = "cmpctblock", .cat = .CMPCTBLOCK },
        .{ .name = "rand", .cat = .RAND },
        .{ .name = "prune", .cat = .PRUNE },
        .{ .name = "proxy", .cat = .PROXY },
        .{ .name = "mempoolrej", .cat = .MEMPOOLREJ },
        .{ .name = "libevent", .cat = .LIBEVENT },
        .{ .name = "coindb", .cat = .COINDB },
        .{ .name = "qt", .cat = .QT },
        .{ .name = "leveldb", .cat = .LEVELDB },
        .{ .name = "validation", .cat = .VALIDATION },
        .{ .name = "i2p", .cat = .I2P },
        .{ .name = "ipc", .cat = .IPC },
        .{ .name = "lock", .cat = .LOCK },
        .{ .name = "util", .cat = .UTIL },
        .{ .name = "blockstorage", .cat = .BLOCKSTORAGE },
        .{ .name = "txreconciliation", .cat = .TXRECONCILIATION },
        .{ .name = "scan", .cat = .SCAN },
        .{ .name = "txpackages", .cat = .TXPACKAGES },
    };
    for (table) |m| {
        if (std.mem.eql(u8, name, m.name)) return @intFromEnum(m.cat);
    }
    return null;
}

/// Probe whether a category is currently enabled.
pub fn enabled(cat: Category) bool {
    const m = active_mask.load(.acquire);
    return (m & @intFromEnum(cat)) != 0;
}

/// Reset (used by tests).
pub fn reset() void {
    active_mask.store(0, .release);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseCategory recognises core categories" {
    try std.testing.expectEqual(@as(?u64, 1 << 0), parseCategory("net"));
    try std.testing.expectEqual(@as(?u64, 1 << 2), parseCategory("mempool"));
    try std.testing.expectEqual(@as(?u64, 1 << 5), parseCategory("zmq"));
}

test "parseCategory all + none + 1 + 0 + empty" {
    try std.testing.expectEqual(@as(?u64, ~@as(u64, 0)), parseCategory("all"));
    try std.testing.expectEqual(@as(?u64, ~@as(u64, 0)), parseCategory("1"));
    try std.testing.expectEqual(@as(?u64, ~@as(u64, 0)), parseCategory(""));
    try std.testing.expectEqual(@as(?u64, 0), parseCategory("none"));
    try std.testing.expectEqual(@as(?u64, 0), parseCategory("0"));
}

test "parseCategory unknown returns null" {
    try std.testing.expectEqual(@as(?u64, null), parseCategory("definitely_not_a_real_category"));
}

test "parseAndApply ORs bits across calls" {
    reset();
    try std.testing.expect(parseAndApply("net"));
    try std.testing.expect(enabled(.NET));
    try std.testing.expect(!enabled(.MEMPOOL));
    try std.testing.expect(parseAndApply("mempool"));
    try std.testing.expect(enabled(.NET));
    try std.testing.expect(enabled(.MEMPOOL));
    try std.testing.expect(!enabled(.RPC));
    reset();
}

test "parseAndApply all enables everything" {
    reset();
    try std.testing.expect(parseAndApply("all"));
    try std.testing.expect(enabled(.NET));
    try std.testing.expect(enabled(.MEMPOOL));
    try std.testing.expect(enabled(.VALIDATION));
    reset();
}

test "parseAndApply unknown returns false and leaves mask unchanged" {
    reset();
    try std.testing.expect(parseAndApply("net"));
    const m_before = active_mask.load(.acquire);
    try std.testing.expect(!parseAndApply("totally_made_up"));
    const m_after = active_mask.load(.acquire);
    try std.testing.expectEqual(m_before, m_after);
    reset();
}

test "parseAndApply 0/none clears mask" {
    reset();
    try std.testing.expect(parseAndApply("all"));
    try std.testing.expect(enabled(.NET));
    try std.testing.expect(parseAndApply("none"));
    try std.testing.expect(!enabled(.NET));
    reset();
}
