//! Gate 6: a system fault is never a consensus verdict.
//!
//! Core's model (bitcoin-core/src/validation.cpp:2136 FatalError/AbortNode,
//! coins.cpp:415 CCoinsViewErrorCatcher): a failed disk read or write, an
//! allocation failure, or an internal error while checking a block is NOT a
//! statement about the block.  The block is never marked invalid, no peer is
//! punished, and the node stops — it does not keep running on a chainstate it
//! could not read or write.
//!
//! This module is that stop.  `abortNode` sets a process-wide latch.  Every
//! chain-changing entry point checks `isLatched()` and refuses:
//!   * P2P block drain / reorg (peer.zig) stop connecting;
//!   * submitblock returns RPC_VERIFY_ERROR (-25), never a BIP-22 token;
//!   * the mempool refuses new transactions;
//!   * main's loop sees the latch, shuts down WITHOUT the final chainstate
//!     flush (the in-memory state is exactly what could not be committed) and
//!     exits non-zero so systemd (Restart=on-failure) restarts from the last
//!     durable state.
//!
//! `noteSystemFault` is the "retry once" half: a non-verdict system fault on a
//! block is retried (the block is re-fetched / re-submitted); the SAME block
//! faulting a second time in a row latches the node.

const std = @import("std");

var latched = std.atomic.Value(bool).init(false);
var reason_buf: [512]u8 = undefined;
var reason_len: usize = 0;
var reason_mutex: std.Thread.Mutex = .{};

/// Last block that hit a non-verdict system fault, for the retry-once rule.
var last_fault_key: ?[32]u8 = null;
var fault_mutex: std.Thread.Mutex = .{};

/// Latch the node (Core AbortNode).  Idempotent: the first reason wins.
pub fn abortNode(comptime fmt: []const u8, args: anytype) void {
    reason_mutex.lock();
    defer reason_mutex.unlock();
    if (latched.load(.acquire)) return;
    const s = std.fmt.bufPrint(&reason_buf, fmt, args) catch reason_buf[0..];
    reason_len = s.len;
    latched.store(true, .release);
    std.debug.print(
        "*** FATAL (AbortNode): {s} — not a block verdict; nothing marked, no peer punished. " ++
            "Stopping block connection, refusing submitblock/mempool; the node will exit non-zero " ++
            "WITHOUT flushing the chainstate. Check the disk / memory, then restart. ***\n",
        .{reason_buf[0..reason_len]},
    );
}

pub fn isLatched() bool {
    return latched.load(.acquire);
}

/// The reason given to the first abortNode call ("" when not latched).
pub fn reason() []const u8 {
    reason_mutex.lock();
    defer reason_mutex.unlock();
    return reason_buf[0..reason_len];
}

/// Retry-once accounting for a non-verdict system fault while validating or
/// connecting `key` (a block hash).  The first fault on a block is retried by
/// the caller; the same block faulting again with no success in between
/// latches the node.  Returns true when this call latched.
pub fn noteSystemFault(key: *const [32]u8, comptime what: []const u8, err: anyerror) bool {
    if (isLatched()) return true; // already halting; nothing to retry
    fault_mutex.lock();
    const repeat = if (last_fault_key) |k| std.mem.eql(u8, &k, key) else false;
    last_fault_key = key.*;
    fault_mutex.unlock();
    if (repeat) {
        abortNode(what ++ " failed twice on the same block ({s})", .{@errorName(err)});
        return true;
    }
    std.debug.print(
        "gate6: system fault ({s}) during " ++ what ++ " — NOT a verdict; will retry once, a second failure halts the node\n",
        .{@errorName(err)},
    );
    return false;
}

/// A block connected (or was judged) cleanly: the retry window resets.
pub fn clearSystemFault() void {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    last_fault_key = null;
}

/// Test-only: clear the latch and retry window between tests.
pub fn resetForTest() void {
    reason_mutex.lock();
    latched.store(false, .release);
    reason_len = 0;
    reason_mutex.unlock();
    clearSystemFault();
}

test "fatal: abortNode latches once, first reason wins" {
    resetForTest();
    defer resetForTest();
    try std.testing.expect(!isLatched());
    abortNode("disk {s}", .{"full"});
    try std.testing.expect(isLatched());
    abortNode("second {d}", .{2});
    try std.testing.expectEqualStrings("disk full", reason());
}

test "fatal: noteSystemFault retries once, latches on the same block twice" {
    resetForTest();
    defer resetForTest();
    const a = [_]u8{0xAA} ** 32;
    const b = [_]u8{0xBB} ** 32;
    try std.testing.expect(!noteSystemFault(&a, "test", error.ReadFailed));
    try std.testing.expect(!isLatched());
    // a different block in between resets the "same block" rule
    try std.testing.expect(!noteSystemFault(&b, "test", error.ReadFailed));
    try std.testing.expect(!noteSystemFault(&a, "test", error.ReadFailed));
    try std.testing.expect(!isLatched());
    // success in between resets the window
    clearSystemFault();
    try std.testing.expect(!noteSystemFault(&a, "test", error.ReadFailed));
    try std.testing.expect(noteSystemFault(&a, "test", error.ReadFailed));
    try std.testing.expect(isLatched());
}
