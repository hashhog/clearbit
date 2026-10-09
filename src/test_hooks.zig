//! TEST-ONLY park points for deterministic concurrency reproducers.
//!
//! Every hook is `if (!builtin.is_test) return;` first, so a non-test build
//! compiles each call site to nothing: production behaviour is unchanged.
//!
//! A test `arm()`s a point (optionally with a 36-byte key filter); the FIRST
//! thread that reaches the armed point with a matching key parks there until
//! the test calls `release()`.  Arming is one-shot, so every other thread (and
//! every later call on the same thread) passes straight through.  This lets a
//! test freeze one thread at an exact instruction boundary — "after the coin
//! was read from the DB, before it is cached", "after the parent check, before
//! validation" — and then drive a second thread through the code it races.

const std = @import("std");
const builtin = @import("builtin");

pub const Point = enum(u8) {
    /// UtxoSet.get: coin decoded from CF_UTXO, not yet inserted in the cache.
    utxo_get_after_db_read,
    /// Mempool.addTransaction: all checks done (conflicts collected), before
    /// any mutation of the pool.
    mempool_pre_insert,
    /// RpcServer.handleGetPeerInfo: holding a `*Peer` from the list, before
    /// any field of it is read.
    getpeerinfo_peer,
    /// PeerManager.drainBlockBuffer: the queued block passed the "extends the
    /// active tip" check, before it is validated and connected.
    drain_after_parent_check,
    /// CF_UTXO cursor walk (countCoinsInDb / forEachCoinInDbOrder), at entry,
    /// before the first coin is read.  One-shot, so a dump's later passes do
    /// not park again.
    utxo_db_walk,
};

const N = @typeInfo(Point).Enum.fields.len;

const Parker = struct {
    armed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    parked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    go: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    has_key: bool = false,
    key_len: usize = 0,
    key: [36]u8 = [_]u8{0} ** 36,
};

var parkers: [N]Parker = [_]Parker{.{}} ** N;

/// Arm `point`.  With `key` set, only a call passing an equal key parks.
pub fn arm(point: Point, key: ?[]const u8) void {
    const p = &parkers[@intFromEnum(point)];
    p.parked.store(false, .seq_cst);
    p.go.store(false, .seq_cst);
    if (key) |k| {
        p.has_key = true;
        p.key_len = @min(k.len, 36);
        @memset(&p.key, 0);
        @memcpy(p.key[0..p.key_len], k[0..p.key_len]);
    } else {
        p.has_key = false;
    }
    p.armed.store(true, .seq_cst);
}

/// Wait (polling) until some thread is parked at `point`.  False on timeout.
pub fn waitParked(point: Point, timeout_ms: u64) bool {
    const p = &parkers[@intFromEnum(point)];
    var waited: u64 = 0;
    while (!p.parked.load(.seq_cst)) {
        if (waited >= timeout_ms) return false;
        std.time.sleep(std.time.ns_per_ms);
        waited += 1;
    }
    return true;
}

/// Let the parked thread continue (no-op if nothing parked).
pub fn release(point: Point) void {
    parkers[@intFromEnum(point)].go.store(true, .seq_cst);
}

/// Disarm everything (test teardown).
pub fn reset() void {
    for (&parkers) |*p| {
        p.armed.store(false, .seq_cst);
        p.go.store(true, .seq_cst);
        p.parked.store(false, .seq_cst);
    }
}

/// The hook.  Compiled to nothing outside `zig build test`.
pub inline fn park(point: Point, key: ?[]const u8) void {
    if (!builtin.is_test) return;
    parkSlow(point, key);
}

fn parkSlow(point: Point, key: ?[]const u8) void {
    const p = &parkers[@intFromEnum(point)];
    if (!p.armed.load(.seq_cst)) return;
    if (p.has_key) {
        const k = key orelse return;
        if (k.len != p.key_len or !std.mem.eql(u8, k, p.key[0..p.key_len])) return;
    }
    // One-shot: only the first matching caller parks.
    if (p.armed.cmpxchgStrong(true, false, .seq_cst, .seq_cst) != null) return;
    p.parked.store(true, .seq_cst);
    // Bounded: never wedge a test binary forever if the test forgot release().
    var waited: u64 = 0;
    while (!p.go.load(.seq_cst) and waited < 60_000) : (waited += 1) {
        std.time.sleep(std.time.ns_per_ms);
    }
}
