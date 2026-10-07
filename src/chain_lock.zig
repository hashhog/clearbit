//! The chain lock (`cs_main`) and the mempool lock, and the lock-order /
//! lock-held instrument around them.
//!
//! clearbit runs real OS threads: the P2P loop (validation, connect, flush,
//! ATMP, peers), the RPC server, `waitfor*` workers, the metrics server,
//! inbound-handshake workers, the wallet-reconcile thread and the script-check
//! pool.  Before this module the only chainstate lock (`connect_mutex`) was
//! taken by block connect/disconnect/flush and by NO reader, so `gettxout` on
//! the RPC thread mutated the coin cache (read-through insert, eviction,
//! flush) while the P2P thread connected blocks (audit 2026-10-07 CB-1/2/9/
//! 10/11); the mempool lock was taken by readers but not writers (CB-3).
//!
//! Bitcoin Core's model, reproduced here:
//!   * `cs_main` (validation.cpp) is a RecursiveMutex held across
//!     ProcessNewBlock/ActivateBestChainStep/FlushStateToDisk, by every RPC
//!     that reads chain or coin state (rpc/blockchain.cpp gettxout:
//!     `LOCK(cs_main)` then `LOCK(mempool.cs)`), and by mempool admission.
//!   * `CTxMemPool::cs` (txmempool.h) is a RecursiveMutex held by writers
//!     AND readers.
//!   * Lock order: cs_main -> mempool.cs (never the reverse).
//!
//! Both locks here are recursive (Zig's std.Thread.Mutex is not, and the
//! existing code takes `connect_mutex` deep inside call chains that callers
//! now also hold it across) and FAIR (FIFO tickets): the P2P thread re-takes
//! cs_main every few milliseconds, and an unfair futex lets the releasing
//! thread win the re-acquire every time, starving RPC.
//!
//! Instrument: `debug_checks` (env CLEARBIT_LOCK_DEBUG=1, or set by tests)
//! makes `assertHeld` report any coin-cache access without cs_main; the lock
//! order is checked on every non-recursive acquire regardless.  Both report
//! to stderr with a stack trace and count into `violations`.

const std = @import("std");
const builtin = @import("builtin");

/// Lower rank is acquired first.  cs_main -> mempool.cs.
pub const Rank = enum(u8) {
    chain = 0,
    mempool = 1,

    fn bit(self: Rank) u8 {
        return @as(u8, 1) << @intCast(@intFromEnum(self));
    }
    fn name(self: Rank) []const u8 {
        return switch (self) {
            .chain => "cs_main",
            .mempool => "mempool.cs",
        };
    }
};

/// Turn on `assertHeld` reporting (CLEARBIT_LOCK_DEBUG=1 / tests).
pub var debug_checks = std.atomic.Value(bool).init(false);
/// Lock-order + lock-held violations seen by this process.
pub var violations = std.atomic.Value(u64).init(0);
var reports_left = std.atomic.Value(u32).init(32);

/// Ranks this thread currently holds (any depth).
threadlocal var held_mask: u8 = 0;

fn report(comptime fmt: []const u8, args: anytype) void {
    _ = violations.fetchAdd(1, .monotonic);
    if (reports_left.load(.monotonic) == 0) return;
    _ = reports_left.fetchSub(1, .monotonic);
    std.debug.print("LOCK-CHECK: " ++ fmt ++ "\n", args);
    std.debug.dumpCurrentStackTrace(@returnAddress());
}

pub fn setDebugFromEnv() void {
    const v = std.posix.getenv("CLEARBIT_LOCK_DEBUG") orelse return;
    if (v.len > 0 and v[0] != '0') debug_checks.store(true, .release);
}

pub const RecursiveMutex = struct {
    rank: Rank,
    inner: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    /// Owning thread id, 0 = free.  Written under `inner`; read lock-free
    /// only to answer "do *I* own it" (no other thread can store my id).
    owner: std.atomic.Value(std.Thread.Id) = std.atomic.Value(std.Thread.Id).init(0),
    /// Recursion depth.  Touched only by the owner.
    depth: u32 = 0,
    next_ticket: u64 = 0,
    serving: u64 = 0,
    waiters: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn init(rank: Rank) RecursiveMutex {
        return .{ .rank = rank };
    }

    pub fn heldByCurrentThread(self: *const RecursiveMutex) bool {
        return self.owner.load(.acquire) == std.Thread.getCurrentId();
    }

    pub fn lock(self: *RecursiveMutex) void {
        const me = std.Thread.getCurrentId();
        if (self.owner.load(.acquire) == me) {
            self.depth += 1;
            return;
        }
        // Lock order: never take a lower rank while holding a higher one.
        const higher: u8 = held_mask & ~((self.rank.bit() << 1) - 1);
        if (higher != 0) {
            report("lock-order violation: acquiring {s} while holding a later lock (mask 0x{x})", .{ self.rank.name(), held_mask });
        }
        self.inner.lock();
        const ticket = self.next_ticket;
        self.next_ticket += 1;
        if (self.serving != ticket) {
            _ = self.waiters.fetchAdd(1, .monotonic);
            while (self.serving != ticket) self.cond.wait(&self.inner);
            _ = self.waiters.fetchSub(1, .monotonic);
        }
        self.owner.store(me, .release);
        self.depth = 1;
        self.inner.unlock();
        held_mask |= self.rank.bit();
    }

    pub fn unlock(self: *RecursiveMutex) void {
        if (std.debug.runtime_safety) std.debug.assert(self.heldByCurrentThread());
        self.depth -= 1;
        if (self.depth > 0) return;
        held_mask &= ~self.rank.bit();
        self.inner.lock();
        self.owner.store(0, .release);
        self.serving += 1;
        self.inner.unlock();
        self.cond.broadcast();
    }

    /// Core REVERSE_LOCK: fully release a lock this thread may hold (any
    /// depth) around blocking I/O.  Returns the depth to hand to
    /// `reacquire`; 0 (no-op) when this thread does not hold it.
    pub fn releaseAll(self: *RecursiveMutex) u32 {
        if (!self.heldByCurrentThread()) return 0;
        const d = self.depth;
        self.depth = 1;
        self.unlock();
        return d;
    }

    pub fn reacquire(self: *RecursiveMutex, depth: u32) void {
        if (depth == 0) return;
        self.lock();
        self.depth = depth;
    }

    /// Let a waiting thread in at a safe point (the owner's state is
    /// consistent and it holds no pointer another thread may invalidate).
    pub fn yieldIfContended(self: *RecursiveMutex) void {
        if (self.waiters.load(.monotonic) == 0) return;
        const d = self.releaseAll();
        self.reacquire(d);
    }

    pub fn assertHeld(self: *const RecursiveMutex, comptime where: []const u8) void {
        if (!debug_checks.load(.monotonic)) return;
        if (!self.heldByCurrentThread()) {
            report("{s} without {s} (thread {d})", .{ where, self.rank.name(), std.Thread.getCurrentId() });
        }
    }
};

/// A scope in which a held lock is released for blocking I/O.
pub const IoWindow = struct {
    m: ?*RecursiveMutex,
    depth: u32,

    pub fn begin(m: ?*RecursiveMutex) IoWindow {
        const mm = m orelse return .{ .m = null, .depth = 0 };
        return .{ .m = mm, .depth = mm.releaseAll() };
    }
    pub fn end(self: IoWindow) void {
        if (self.m) |mm| mm.reacquire(self.depth);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "chain_lock: recursive, releaseAll/reacquire restores depth" {
    var m = RecursiveMutex.init(.chain);
    m.lock();
    m.lock();
    try std.testing.expect(m.heldByCurrentThread());
    const d = m.releaseAll();
    try std.testing.expectEqual(@as(u32, 2), d);
    try std.testing.expect(!m.heldByCurrentThread());
    m.reacquire(d);
    m.unlock();
    try std.testing.expect(m.heldByCurrentThread());
    m.unlock();
    try std.testing.expect(!m.heldByCurrentThread());
    try std.testing.expectEqual(@as(u32, 0), m.releaseAll());
}

test "chain_lock: excludes another thread and is FIFO-fair" {
    var m = RecursiveMutex.init(.chain);
    const Ctx = struct {
        m: *RecursiveMutex,
        got: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        fn run(c: *@This()) void {
            c.m.lock();
            c.got.store(true, .seq_cst);
            c.m.unlock();
        }
    };
    m.lock();
    var c = Ctx{ .m = &m };
    const t = try std.Thread.spawn(.{}, Ctx.run, .{&c});
    std.time.sleep(50 * std.time.ns_per_ms);
    try std.testing.expect(!c.got.load(.seq_cst));
    try std.testing.expectEqual(@as(u32, 1), m.waiters.load(.seq_cst));
    // Fairness: release and immediately re-acquire; the waiter goes first.
    m.unlock();
    m.lock();
    try std.testing.expect(c.got.load(.seq_cst));
    m.unlock();
    t.join();
}

test "chain_lock: lock-order violation is counted" {
    var chain = RecursiveMutex.init(.chain);
    var pool = RecursiveMutex.init(.mempool);
    const before = violations.load(.seq_cst);
    chain.lock();
    pool.lock();
    pool.unlock();
    chain.unlock();
    try std.testing.expectEqual(before, violations.load(.seq_cst));
    pool.lock();
    chain.lock(); // mempool.cs -> cs_main: inverted
    chain.unlock();
    pool.unlock();
    try std.testing.expectEqual(before + 1, violations.load(.seq_cst));
}
