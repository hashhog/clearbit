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
// Runtime-mutable category control (for the `logging` RPC, Core node.cpp:218)
// ---------------------------------------------------------------------------
//
// Bitcoin Core's `logging` RPC mutates `BCLog::Logger::m_categories` in
// memory, taking effect immediately with no restart. clearbit's equivalent
// is the single global `active_mask` above: every `enabled()` call reads it
// LIVE (relaxed atomic load) on each probe, so a bit flipped here is honoured
// by the next log-site check with no restart and no re-attachment. This is the
// "no snapshot trap" property — nothing caches the mask at construction, so a
// toggle here is genuinely live for any site that gates on `enabled(.CAT)`.

/// Canonical ordered list of the REAL categories clearbit exposes, paired with
/// the lowercase name used on the wire. Kept in ALPHABETICAL order so the
/// `logging` RPC's `{category: bool}` object is emitted with byte-stable,
/// alphabetically-sorted keys (Core iterates a `std::map`, hence alphabetical).
///
/// These are exactly the bits of `Category` (excluding the synthetic NONE/ALL).
/// The special input-only tokens ("all"/"1"/""/"none"/"0") are NOT here — they
/// are accepted as inputs but are never emitted as output keys (Core parity).
pub const CategoryName = struct { name: []const u8, cat: Category };
pub const CATEGORY_LIST = [_]CategoryName{
    .{ .name = "addrman", .cat = .ADDRMAN },
    .{ .name = "bench", .cat = .BENCH },
    .{ .name = "blockstorage", .cat = .BLOCKSTORAGE },
    .{ .name = "cmpctblock", .cat = .CMPCTBLOCK },
    .{ .name = "coindb", .cat = .COINDB },
    .{ .name = "estimatefee", .cat = .ESTIMATEFEE },
    .{ .name = "http", .cat = .HTTP },
    .{ .name = "i2p", .cat = .I2P },
    .{ .name = "ipc", .cat = .IPC },
    .{ .name = "leveldb", .cat = .LEVELDB },
    .{ .name = "libevent", .cat = .LIBEVENT },
    .{ .name = "lock", .cat = .LOCK },
    .{ .name = "mempool", .cat = .MEMPOOL },
    .{ .name = "mempoolrej", .cat = .MEMPOOLREJ },
    .{ .name = "net", .cat = .NET },
    .{ .name = "proxy", .cat = .PROXY },
    .{ .name = "prune", .cat = .PRUNE },
    .{ .name = "qt", .cat = .QT },
    .{ .name = "rand", .cat = .RAND },
    .{ .name = "reindex", .cat = .REINDEX },
    .{ .name = "rpc", .cat = .RPC },
    .{ .name = "scan", .cat = .SCAN },
    .{ .name = "selectcoins", .cat = .SELECTCOINS },
    .{ .name = "tor", .cat = .TOR },
    .{ .name = "txpackages", .cat = .TXPACKAGES },
    .{ .name = "txreconciliation", .cat = .TXRECONCILIATION },
    .{ .name = "util", .cat = .UTIL },
    .{ .name = "validation", .cat = .VALIDATION },
    .{ .name = "walletdb", .cat = .WALLETDB },
    .{ .name = "zmq", .cat = .ZMQ },
};

/// Mask of every REAL exposed category OR'd together. NB this is NOT `ALL`
/// (which is `~0`, all 64 bits) — it is precisely the bits backed by an
/// exposed name, so `enabled()` on an exposed category after "all" is true and
/// the reported map can show every key true without relying on phantom bits.
pub fn allExposedMask() u64 {
    var m: u64 = 0;
    for (CATEGORY_LIST) |c| m |= @intFromEnum(c.cat);
    return m;
}

/// Special input-only tokens that map to the full mask (Core logging.cpp:
/// "all"/"1"/""), plus the disable-side "none"/"0" that clear it. These are
/// accepted as inputs to `logging` include/exclude but are NEVER output keys.
pub fn isAllToken(name: []const u8) bool {
    return name.len == 0 or
        std.mem.eql(u8, name, "all") or
        std.mem.eql(u8, name, "1");
}
pub fn isNoneToken(name: []const u8) bool {
    return std.mem.eql(u8, name, "none") or std.mem.eql(u8, name, "0");
}

/// Resolve an exposed category name -> its bit. Returns null for names that
/// are not exposed REAL categories (special tokens handled separately by the
/// caller). Used by the `logging` RPC to detect an unknown category (-> -8).
pub fn lookupExposed(name: []const u8) ?Category {
    for (CATEGORY_LIST) |c| {
        if (std.mem.eql(u8, name, c.name)) return c.cat;
    }
    return null;
}

/// Enable a single exposed category in the live mask (Core EnableCategory).
pub fn enableCategory(cat: Category) void {
    _ = active_mask.fetchOr(@intFromEnum(cat), .acq_rel);
}

/// Disable a single exposed category in the live mask (Core DisableCategory).
pub fn disableCategory(cat: Category) void {
    _ = active_mask.fetchAnd(~@intFromEnum(cat), .acq_rel);
}

/// Enable every exposed category (the "all"/"1"/"" include token).
pub fn enableAll() void {
    _ = active_mask.fetchOr(allExposedMask(), .acq_rel);
}

/// Disable every exposed category (the "all"/"1"/"" exclude token, i.e. the
/// `logging [], ["all"]` "none" effect). Clears precisely the exposed bits.
pub fn disableAll() void {
    _ = active_mask.fetchAnd(~allExposedMask(), .acq_rel);
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

test "CATEGORY_LIST is alphabetical" {
    var i: usize = 1;
    while (i < CATEGORY_LIST.len) : (i += 1) {
        try std.testing.expect(std.mem.lessThan(u8, CATEGORY_LIST[i - 1].name, CATEGORY_LIST[i].name));
    }
}

test "logging-style enable/disable single category is live" {
    reset();
    const net = lookupExposed("net").?;
    try std.testing.expect(!enabled(.NET));
    enableCategory(net);
    try std.testing.expect(enabled(.NET));
    try std.testing.expect(!enabled(.MEMPOOL));
    disableCategory(net);
    try std.testing.expect(!enabled(.NET));
    reset();
}

test "logging-style enableAll / disableAll over exposed set" {
    reset();
    enableAll();
    // Every exposed category reads enabled.
    for (CATEGORY_LIST) |c| try std.testing.expect(enabled(c.cat));
    disableAll();
    for (CATEGORY_LIST) |c| try std.testing.expect(!enabled(c.cat));
    reset();
}

test "lookupExposed rejects special tokens and unknowns" {
    try std.testing.expect(lookupExposed("all") == null);
    try std.testing.expect(lookupExposed("1") == null);
    try std.testing.expect(lookupExposed("") == null);
    try std.testing.expect(lookupExposed("none") == null);
    try std.testing.expect(lookupExposed("bogus_xyz") == null);
    try std.testing.expect(lookupExposed("net") != null);
}

test "token classifiers" {
    try std.testing.expect(isAllToken(""));
    try std.testing.expect(isAllToken("all"));
    try std.testing.expect(isAllToken("1"));
    try std.testing.expect(!isAllToken("net"));
    try std.testing.expect(isNoneToken("none"));
    try std.testing.expect(isNoneToken("0"));
    try std.testing.expect(!isNoneToken("all"));
}
