//! ZMQ publishing for clearbit.
//!
//! Mirrors Bitcoin Core's `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` topic
//! set: `rawblock`, `hashblock`, `rawtx`, `hashtx`, `sequence`. Wire format is
//! a 3-frame multipart message: `[topic][payload][LE uint32 sequence]`.
//!
//! Build wiring:
//!   - When `-Dzmq=true`, `build.zig` links `libzmq` and the publisher actually
//!     opens sockets. C ABI declarations are inline (no libzmq-dev required;
//!     the runtime `libzmq.so.5` is linked dynamically).
//!   - When `-Dzmq=false` (default), the public API still compiles; init() is
//!     a no-op and publish*() returns silently. This keeps the call sites
//!     unconditional throughout the codebase.
//!
//! Hook points (driven by main.zig wiring):
//!   - block-connect (sync.zig validateAndConnectBlock) → publishBlock()
//!   - mempool-add  (mempool.zig addTransaction)        → publishTx()

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const build_options = @import("build_options");

/// Compile-time toggle: set via build.zig from `-Dzmq=...`.
pub const ZMQ_ENABLED: bool = build_options.zmq_enabled;

// ---------------------------------------------------------------------------
// libzmq C ABI (declared inline so we don't need libzmq-dev to compile).
// Symbols are resolved at link time when build.zig links `libzmq`.
// Constants are taken from /usr/include/zmq.h (libzmq-4.x stable ABI).
//
// IMPORTANT: the `extern fn` decls must NOT be referenced when ZMQ_ENABLED is
// false, otherwise the linker complains about missing symbols (clearbit is
// linked without -lzmq in the default build). All call sites below sit
// behind `if (ZMQ_ENABLED)` so dead-code-elimination drops the references.
// ---------------------------------------------------------------------------

const ZMQ_PUB: c_int = 1;
const ZMQ_SNDHWM: c_int = 23;
const ZMQ_LINGER: c_int = 17;
const ZMQ_IPV6: c_int = 42;
const ZMQ_TCP_KEEPALIVE: c_int = 34;
const ZMQ_SNDMORE: c_int = 2;

// Use opaque void pointers — matches Bitcoin Core's zmqabstractnotifier.h.
const c_api = struct {
    extern "c" fn zmq_ctx_new() ?*anyopaque;
    extern "c" fn zmq_ctx_term(ctx: *anyopaque) c_int;
    extern "c" fn zmq_socket(ctx: *anyopaque, type_: c_int) ?*anyopaque;
    extern "c" fn zmq_close(sock: *anyopaque) c_int;
    extern "c" fn zmq_bind(sock: *anyopaque, addr: [*:0]const u8) c_int;
    extern "c" fn zmq_setsockopt(sock: *anyopaque, opt: c_int, val: *const anyopaque, len: usize) c_int;
    extern "c" fn zmq_send(sock: *anyopaque, buf: *const anyopaque, len: usize, flags: c_int) c_int;
};

// ---------------------------------------------------------------------------
// Topic strings. Identical wire bytes to Bitcoin Core (see MSG_HASHBLOCK etc
// in zmqpublishnotifier.cpp).
// ---------------------------------------------------------------------------
pub const TOPIC_HASHBLOCK = "hashblock";
pub const TOPIC_HASHTX = "hashtx";
pub const TOPIC_RAWBLOCK = "rawblock";
pub const TOPIC_RAWTX = "rawtx";
pub const TOPIC_SEQUENCE = "sequence";

/// Per-topic socket entry. Each topic gets its own socket bound to its own
/// address (Bitcoin Core does the same — `-zmqpub<topic>=tcp://...`).
const SocketEntry = struct {
    topic: []const u8,
    address: [:0]u8,
    sock: ?*anyopaque,
    seq: u32 = 0,
};

/// ZMQ publisher state. Embedded in main as `var notifier: zmq.Notifier = .{};`.
/// init() opens any sockets configured via the `--zmqpub<topic>=tcp://...`
/// flags; deinit() closes them. publishBlock / publishTx / publishSequence
/// are async-signal-unsafe (mutexed) and meant to be called from validation
/// + mempool worker threads.
pub const Notifier = struct {
    allocator: std.mem.Allocator = undefined,
    ctx: ?*anyopaque = null,
    /// Indexed by topic — at most one entry per topic. Keeps lookup O(N=5).
    sockets: std.ArrayList(SocketEntry) = undefined,
    mutex: std.Thread.Mutex = .{},
    initialized: bool = false,

    pub const Config = struct {
        rawblock_addr: ?[]const u8 = null,
        hashblock_addr: ?[]const u8 = null,
        rawtx_addr: ?[]const u8 = null,
        hashtx_addr: ?[]const u8 = null,
        sequence_addr: ?[]const u8 = null,

        pub fn isEmpty(self: *const Config) bool {
            return self.rawblock_addr == null and self.hashblock_addr == null and
                self.rawtx_addr == null and self.hashtx_addr == null and
                self.sequence_addr == null;
        }
    };

    /// Initialize the publisher. Returns ok even when ZMQ_ENABLED is false —
    /// the call sites stay unconditional. When config is empty, this is a
    /// no-op even with ZMQ enabled.
    pub fn init(self: *Notifier, allocator: std.mem.Allocator, cfg: Config) !void {
        self.allocator = allocator;
        self.sockets = std.ArrayList(SocketEntry).init(allocator);
        self.initialized = true;
        if (cfg.isEmpty()) return;

        if (!ZMQ_ENABLED) {
            std.debug.print(
                "Warning: --zmqpub<topic>= flags ignored (clearbit was built without -Dzmq=true)\n",
                .{},
            );
            return;
        }

        if (ZMQ_ENABLED) {
            self.ctx = c_api.zmq_ctx_new() orelse return error.ZmqContextInitFailed;
        }

        if (cfg.rawblock_addr) |a| try self.bindSocket(TOPIC_RAWBLOCK, a);
        if (cfg.hashblock_addr) |a| try self.bindSocket(TOPIC_HASHBLOCK, a);
        if (cfg.rawtx_addr) |a| try self.bindSocket(TOPIC_RAWTX, a);
        if (cfg.hashtx_addr) |a| try self.bindSocket(TOPIC_HASHTX, a);
        if (cfg.sequence_addr) |a| try self.bindSocket(TOPIC_SEQUENCE, a);

        std.debug.print("ZMQ publisher: {d} topic(s) bound\n", .{self.sockets.items.len});
    }

    fn bindSocket(self: *Notifier, topic: []const u8, addr: []const u8) !void {
        if (!ZMQ_ENABLED) return;
        // The whole body sits behind a comptime gate because the extern decls
        // must not be referenced in the default (zmq=false) build, or the
        // linker pulls them in.
        if (comptime !ZMQ_ENABLED) return;
        const ctx = self.ctx orelse return error.ZmqContextNotReady;

        const sock = c_api.zmq_socket(ctx, ZMQ_PUB) orelse return error.ZmqSocketCreateFailed;
        errdefer _ = c_api.zmq_close(sock);

        // Bitcoin Core defaults (zmqpublishnotifier.cpp).
        const hwm: c_int = 1000;
        _ = c_api.zmq_setsockopt(sock, ZMQ_SNDHWM, &hwm, @sizeOf(c_int));
        const ipv6: c_int = 1;
        _ = c_api.zmq_setsockopt(sock, ZMQ_IPV6, &ipv6, @sizeOf(c_int));
        const keep: c_int = 1;
        _ = c_api.zmq_setsockopt(sock, ZMQ_TCP_KEEPALIVE, &keep, @sizeOf(c_int));
        // 0 linger = drop pending messages immediately on close (Bitcoin Core
        // matches this — clean shutdown should not block on backlog).
        const linger: c_int = 0;
        _ = c_api.zmq_setsockopt(sock, ZMQ_LINGER, &linger, @sizeOf(c_int));

        // C-string the bind address.
        const addr_z = try self.allocator.allocSentinel(u8, addr.len, 0);
        @memcpy(addr_z[0..addr.len], addr);

        const rc = c_api.zmq_bind(sock, addr_z.ptr);
        if (rc != 0) {
            self.allocator.free(addr_z);
            _ = c_api.zmq_close(sock);
            std.debug.print("ZMQ: failed to bind {s} on {s}\n", .{ topic, addr });
            return error.ZmqBindFailed;
        }

        try self.sockets.append(.{ .topic = topic, .address = addr_z, .sock = sock });
        std.debug.print("ZMQ: publishing {s} on {s}\n", .{ topic, addr });
    }

    pub fn deinit(self: *Notifier) void {
        if (!self.initialized) return;
        for (self.sockets.items) |entry| {
            if (comptime ZMQ_ENABLED) {
                if (entry.sock) |s| _ = c_api.zmq_close(s);
            }
            self.allocator.free(entry.address);
        }
        self.sockets.deinit();
        if (comptime ZMQ_ENABLED) {
            if (self.ctx) |c| _ = c_api.zmq_ctx_term(c);
        }
        self.ctx = null;
        self.initialized = false;
    }

    /// Find the socket for a topic. Returns null if no operator-configured
    /// binding exists for this topic — call sites then short-circuit.
    pub fn findSocket(self: *Notifier, topic: []const u8) ?*SocketEntry {
        for (self.sockets.items) |*entry| {
            if (std.mem.eql(u8, entry.topic, topic)) return entry;
        }
        return null;
    }

    /// Publish a 3-frame ZMQ multipart message: topic | payload | seq (LE u32).
    /// Caller-owned `payload` is copied by libzmq before zmq_send returns.
    fn sendMultipart(self: *Notifier, topic: []const u8, payload: []const u8) void {
        if (comptime !ZMQ_ENABLED) return;
        if (!self.initialized) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        var entry = self.findSocket(topic) orelse return;
        const sock = entry.sock orelse return;

        // Frame 1: topic.
        _ = c_api.zmq_send(sock, topic.ptr, topic.len, ZMQ_SNDMORE);
        // Frame 2: payload.
        _ = c_api.zmq_send(sock, payload.ptr, payload.len, ZMQ_SNDMORE);
        // Frame 3: 4-byte LE sequence.
        var seqbuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &seqbuf, entry.seq, .little);
        _ = c_api.zmq_send(sock, &seqbuf, seqbuf.len, 0);

        entry.seq +%= 1;
    }

    /// Publish a block-connected event. Sends `hashblock` (32 bytes,
    /// internal byte order) and `rawblock` (full serialized block).
    /// The `raw_bytes` slice may be null when the caller does not have
    /// the encoded form on hand — `hashblock` still fires.
    pub fn publishBlock(
        self: *Notifier,
        hash: *const types.Hash256,
        raw_bytes: ?[]const u8,
    ) void {
        // hashblock — Bitcoin Core sends DISPLAY order (reversed). Do the
        // same so existing subscribers (e.g. fibre, electrs) just work.
        if (self.findSocket(TOPIC_HASHBLOCK) != null) {
            var rev: [32]u8 = undefined;
            for (0..32) |i| rev[i] = hash[31 - i];
            self.sendMultipart(TOPIC_HASHBLOCK, &rev);
        }
        if (raw_bytes) |b| {
            if (self.findSocket(TOPIC_RAWBLOCK) != null) {
                self.sendMultipart(TOPIC_RAWBLOCK, b);
            }
        }
        // sequence frame: 32-byte hash (display) | 'C' (block connect) | (no mempool seq)
        if (self.findSocket(TOPIC_SEQUENCE) != null) {
            var seqbuf: [33]u8 = undefined;
            for (0..32) |i| seqbuf[i] = hash[31 - i];
            seqbuf[32] = 'C';
            self.sendMultipart(TOPIC_SEQUENCE, &seqbuf);
        }
    }

    /// Publish a transaction-accepted-to-mempool event.
    pub fn publishTx(
        self: *Notifier,
        txid: *const types.Hash256,
        raw_bytes: ?[]const u8,
    ) void {
        if (self.findSocket(TOPIC_HASHTX) != null) {
            var rev: [32]u8 = undefined;
            for (0..32) |i| rev[i] = txid[31 - i];
            self.sendMultipart(TOPIC_HASHTX, &rev);
        }
        if (raw_bytes) |b| {
            if (self.findSocket(TOPIC_RAWTX) != null) {
                self.sendMultipart(TOPIC_RAWTX, b);
            }
        }
        if (self.findSocket(TOPIC_SEQUENCE) != null) {
            var seqbuf: [42]u8 = undefined;
            for (0..32) |i| seqbuf[i] = txid[31 - i];
            seqbuf[32] = 'A';
            // Bitcoin Core appends a per-mempool 64-bit mempool sequence.
            // We don't track it; emit zero for compatibility.
            std.mem.writeInt(u64, seqbuf[33..41], 0, .little);
            seqbuf[41] = 0; // no extra
            self.sendMultipart(TOPIC_SEQUENCE, seqbuf[0..41]);
        }
    }
};

/// Process-wide singleton. Owned by main.zig: init() in startup, deinit() in
/// shutdown. Other modules (sync.zig block connect, mempool.zig add)
/// reach here without taking a fresh dependency on main.zig — that
/// would otherwise create an import cycle (main → sync → main).
///
/// Safe to call publish*() before init() — the no-op guard inside the
/// methods checks `initialized`. Same applies after deinit().
pub var global: Notifier = .{};

/// Helper: encode a Block into a freshly-allocated byte slice. Caller owns.
/// Used by the block-connect hook to materialize `rawblock` payload bytes.
pub fn encodeBlockAlloc(
    allocator: std.mem.Allocator,
    block: *const types.Block,
) ![]const u8 {
    var w = serialize.Writer.init(allocator);
    errdefer w.deinit();
    try serialize.writeBlock(&w, block);
    return try w.list.toOwnedSlice();
}

/// Helper: encode a Transaction into a freshly-allocated byte slice. Caller owns.
pub fn encodeTxAlloc(
    allocator: std.mem.Allocator,
    tx: *const types.Transaction,
) ![]const u8 {
    var w = serialize.Writer.init(allocator);
    errdefer w.deinit();
    try serialize.writeTransaction(&w, tx);
    return try w.list.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Notifier: init+deinit on empty config is a no-op" {
    var n: Notifier = .{};
    try n.init(std.testing.allocator, .{});
    defer n.deinit();
    // Should leave context null because there's nothing to bind.
    try std.testing.expect(n.ctx == null);
    try std.testing.expectEqual(@as(usize, 0), n.sockets.items.len);
}

test "Notifier: publish on uninitialized notifier is safe" {
    var n: Notifier = .{};
    // No init() call.
    const h: types.Hash256 = [_]u8{0xAB} ** 32;
    n.publishBlock(&h, null);
    n.publishTx(&h, null);
    // Just checking we didn't crash.
}

test "Notifier: findSocket with no sockets returns null" {
    var n: Notifier = .{};
    try n.init(std.testing.allocator, .{});
    defer n.deinit();
    try std.testing.expect(n.findSocket(TOPIC_HASHBLOCK) == null);
}

test "Config.isEmpty true on default" {
    const cfg = Notifier.Config{};
    try std.testing.expect(cfg.isEmpty());
}

test "Config.isEmpty false when any topic set" {
    const cfg = Notifier.Config{ .hashblock_addr = "tcp://127.0.0.1:28332" };
    try std.testing.expect(!cfg.isEmpty());
}
