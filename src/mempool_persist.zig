//! Bitcoin Core-compatible mempool persistence (mempool.dat).
//!
//! Implements byte-for-byte compatibility with `bitcoin-core/src/node/
//! mempool_persist.cpp`. The on-disk format mirrors what Bitcoin Core 25+
//! writes via its `AutoFile` + `Obfuscation` machinery, so a clearbit-
//! produced mempool.dat is loadable by Core (and vice versa).
//!
//! File layout (v2, the default since Core ~25):
//!
//!   [u64 LE]         version (=2)         -- UNOBFUSCATED
//!   [CompactSize=8]  obfuscation key len  -- UNOBFUSCATED (vector<byte> prefix)
//!   [8 bytes]        obfuscation key      -- UNOBFUSCATED
//!   ---- from here on, every byte at file-offset N is XOR-ed with key[N % 8] ----
//!   [u64 LE]         total tx count
//!   for each tx:
//!     <CTransaction with witness>         -- standard segwit serialization
//!     [i64 LE]       nTime (seconds since epoch)
//!     [i64 LE]       nFeeDelta (priority delta in satoshis; 0 if unset)
//!   <map<Txid, CAmount>>                  -- mapDeltas (CompactSize + entries)
//!   <set<Txid>>                           -- unbroadcast_txids (CompactSize + entries)
//!
//! Where map/set/pair/Txid serialization follows Core's serialize.h:
//!   map  := CompactSize(N) || N * (key || value)
//!   set  := CompactSize(N) || N * key
//!   Txid := 32 raw bytes (internal byte order, NOT reversed)
//!
//! v1 (no XOR key) is also accepted on load for backwards compatibility.
//!
//! FIX-76 (2026-05-16): standalone mapDeltas tail block is now actively
//! populated on dump and applied via `prioritiseTransaction` on load.
//! Prior to FIX-76 the dump path emitted `CompactSize(0)` here and the load
//! path read-and-discarded it, so an operator's priority deltas (set via
//! the `prioritisetransaction` RPC) were dropped on restart. Core has
//! always persisted these — see `bitcoin-core/src/node/mempool_persist.cpp`
//! lines 101 (DumpMempool: `file << mapDeltas`) and 124-130 (LoadMempool:
//! `for (const auto& i : mapDeltas) pool.PrioritiseTransaction(i.first, i.second)`).
//! The on-disk layout is unchanged; only the contents are now correct.

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const mempool_mod = @import("mempool.zig");

/// Current mempool dump format version (matches Core's MEMPOOL_DUMP_VERSION).
pub const MEMPOOL_DUMP_VERSION: u64 = 2;
/// Legacy (pre-XOR) format version (matches Core's MEMPOOL_DUMP_VERSION_NO_XOR_KEY).
pub const MEMPOOL_DUMP_VERSION_NO_XOR_KEY: u64 = 1;

/// Size of the obfuscation XOR key, in bytes (matches Core's Obfuscation::KEY_SIZE).
pub const OBFUSCATION_KEY_SIZE: usize = 8;

pub const Error = error{
    InvalidFormat,
    InvalidCompactSize,
    OversizedVector,
    UnsupportedVersion,
    InvalidObfuscationKey,
    UnexpectedEof,
    OutOfMemory,
} || std.fs.File.OpenError || std.fs.File.WriteError || std.fs.File.ReadError ||
    std.fs.Dir.RenameError || std.fs.Dir.DeleteFileError;

/// Apply XOR-obfuscation to `data`, where `data[0]` corresponds to absolute
/// file offset `file_offset`. Matches `Obfuscation::operator()` byte-by-byte:
/// byte at file offset N is XORed with `key[N % 8]`. Pass an all-zero key to
/// skip obfuscation (matches v1 dumps and Core's Obfuscation null state).
fn applyObfuscation(data: []u8, file_offset: u64, key: [OBFUSCATION_KEY_SIZE]u8) void {
    // All-zero key = no obfuscation (Core's `if (!*this) return`).
    var any_nonzero: bool = false;
    for (key) |b| {
        if (b != 0) {
            any_nonzero = true;
            break;
        }
    }
    if (!any_nonzero) return;

    for (data, 0..) |*b, i| {
        b.* ^= key[(file_offset + i) % OBFUSCATION_KEY_SIZE];
    }
}

/// Buffered, position-tracking writer that XOR-obfuscates output.
///
/// The backing `list` IS the entire on-disk file: `list[i]` corresponds to
/// file offset `i`. We don't need a separate base_offset because the obfu-
/// scation key index is derived directly from each byte's position in the
/// list, which equals its file offset.
const ObfWriter = struct {
    list: *std.ArrayList(u8),
    key: [OBFUSCATION_KEY_SIZE]u8,

    fn writeObfuscated(self: *ObfWriter, src: []const u8) !void {
        const start = self.list.items.len;
        try self.list.appendSlice(src);
        // Obfuscate the freshly-appended slice in place using its file
        // position (which equals its index in the backing list).
        applyObfuscation(self.list.items[start..], @intCast(start), self.key);
    }

    fn writeU64(self: *ObfWriter, v: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, v, .little);
        try self.writeObfuscated(&buf);
    }

    fn writeI64(self: *ObfWriter, v: i64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(i64, &buf, v, .little);
        try self.writeObfuscated(&buf);
    }

    fn writeCompactSize(self: *ObfWriter, value: u64) !void {
        var buf: [9]u8 = undefined;
        var n: usize = 0;
        if (value < 0xFD) {
            buf[0] = @intCast(value);
            n = 1;
        } else if (value <= 0xFFFF) {
            buf[0] = 0xFD;
            std.mem.writeInt(u16, buf[1..3], @intCast(value), .little);
            n = 3;
        } else if (value <= 0xFFFFFFFF) {
            buf[0] = 0xFE;
            std.mem.writeInt(u32, buf[1..5], @intCast(value), .little);
            n = 5;
        } else {
            buf[0] = 0xFF;
            std.mem.writeInt(u64, buf[1..9], value, .little);
            n = 9;
        }
        try self.writeObfuscated(buf[0..n]);
    }
};

/// Buffered reader that XOR-deobfuscates input.
///
/// The backing `data` IS the entire on-disk file: `data[i]` corresponds to
/// file offset `i`. The obfuscation key index for any byte is therefore
/// just `i % 8`.
const ObfReader = struct {
    data: []const u8,
    pos: usize,
    key: [OBFUSCATION_KEY_SIZE]u8,

    fn readObfuscated(self: *ObfReader, dst: []u8) Error!void {
        if (self.pos + dst.len > self.data.len) return Error.UnexpectedEof;
        @memcpy(dst, self.data[self.pos .. self.pos + dst.len]);
        applyObfuscation(dst, @intCast(self.pos), self.key);
        self.pos += dst.len;
    }

    fn readU64(self: *ObfReader) Error!u64 {
        var buf: [8]u8 = undefined;
        try self.readObfuscated(&buf);
        return std.mem.readInt(u64, &buf, .little);
    }

    fn readI64(self: *ObfReader) Error!i64 {
        var buf: [8]u8 = undefined;
        try self.readObfuscated(&buf);
        return std.mem.readInt(i64, &buf, .little);
    }

    fn readU8(self: *ObfReader) Error!u8 {
        var buf: [1]u8 = undefined;
        try self.readObfuscated(&buf);
        return buf[0];
    }

    fn readCompactSize(self: *ObfReader) Error!u64 {
        const first = try self.readU8();
        // 1-byte form: always canonical and within MAX_SIZE.
        if (first < 0xFD) return first;
        const value: u64 = switch (first) {
            0xFD => blk: {
                var b: [2]u8 = undefined;
                try self.readObfuscated(&b);
                const v = @as(u64, std.mem.readInt(u16, &b, .little));
                // Non-canonical: value fits in 1-byte form.
                if (v < 0xFD) return Error.InvalidCompactSize;
                break :blk v;
            },
            0xFE => blk: {
                var b: [4]u8 = undefined;
                try self.readObfuscated(&b);
                const v = @as(u64, std.mem.readInt(u32, &b, .little));
                // Non-canonical: value fits in 3-byte (0xFD) form.
                if (v < 0x10000) return Error.InvalidCompactSize;
                break :blk v;
            },
            else => blk: { // 0xFF
                var b: [8]u8 = undefined;
                try self.readObfuscated(&b);
                const v = std.mem.readInt(u64, &b, .little);
                // Non-canonical: value fits in 5-byte (0xFE) form.
                if (v < 0x100000000) return Error.InvalidCompactSize;
                break :blk v;
            },
        };
        // MAX_SIZE range check (Core: range_check=true by default).
        if (value > serialize.MAX_SIZE) return Error.OversizedVector;
        return value;
    }
};

/// Read a witness-format CTransaction from the obfuscated stream.
///
/// We deobfuscate enough bytes lazily into a scratch buffer, then defer to
/// `serialize.readTransaction`. The scratch contains the entire tx (we pre-
/// scan to find its end). This keeps tx-format parsing in serialize.zig and
/// avoids re-implementing it here.
fn readObfuscatedTransaction(
    reader: *ObfReader,
    scratch: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) Error!types.Transaction {
    // Strategy: deobfuscate the tail of the stream (from current pos onward)
    // into the scratch buffer, hand it to serialize.readTransaction, then
    // advance our reader by the consumed byte count. This is O(N) extra
    // memory in the size of the largest single tx, which is bounded by
    // MAX_BLOCK_WEIGHT/4 in practice. Since the obfuscation is just a XOR
    // mask, deobfuscating ahead is cheap and correctness-preserving.
    const tail_len = reader.data.len - reader.pos;
    scratch.clearRetainingCapacity();
    try scratch.resize(tail_len);
    @memcpy(scratch.items, reader.data[reader.pos..]);
    applyObfuscation(scratch.items, @intCast(reader.pos), reader.key);

    var inner = serialize.Reader{ .data = scratch.items };
    const tx = serialize.readTransaction(&inner, allocator) catch |e| switch (e) {
        error.EndOfStream => return Error.UnexpectedEof,
        error.InvalidCompactSize, error.InvalidSegwitMarker, error.OversizedVector, error.SuperfluousWitnessRecord => return Error.InvalidFormat,
        error.OutOfMemory => return Error.OutOfMemory,
    };
    reader.pos += inner.pos;
    return tx;
}

/// Dump the mempool in Bitcoin Core mempool.dat format (v2 with XOR
/// obfuscation). Writes to `<path>.new` then atomically renames to `path`,
/// matching Core's Commit + RenameOver dance.
///
/// FIX-76: persists operator-set priority deltas (set via the
/// `prioritisetransaction` RPC) per Core's
/// `bitcoin-core/src/node/mempool_persist.cpp` :88-101 — entries that ARE in
/// the mempool carry their delta inline as the per-tx `nFeeDelta` field;
/// entries that are NOT in the mempool (operator pre-prioritised a txid
/// before it arrived) go into the standalone `mapDeltas` tail block.
///
/// Returns the number of transactions written.
pub fn dumpMempool(
    pool: *mempool_mod.Mempool,
    path: []const u8,
    allocator: std.mem.Allocator,
) !usize {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    // Generate a random 8-byte XOR key. Core uses FastRandomContext; we use
    // std.crypto.random which is OS-seeded. The key is NOT secret — its
    // purpose is to randomize on-disk byte patterns so naive AV/malware
    // scanners don't false-positive on tx data. A zero key is valid (means
    // "no obfuscation") but we always generate a non-zero one to match Core
    // v2 behavior and ensure obfuscation actually runs.
    var key: [OBFUSCATION_KEY_SIZE]u8 = undefined;
    while (true) {
        std.crypto.random.bytes(&key);
        // Reject the all-zero key — Core treats {0,0,0,0,0,0,0,0} as the
        // "no obfuscation" sentinel, and we want a true v2 dump.
        var is_zero = true;
        for (key) |b| {
            if (b != 0) {
                is_zero = false;
                break;
            }
        }
        if (!is_zero) break;
    }

    // Phase 1: write the unobfuscated header (version + key vector).
    var version_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &version_buf, MEMPOOL_DUMP_VERSION, .little);
    try buf.appendSlice(&version_buf);

    // CompactSize prefix for the key vector<byte> (always 8, encoded as 0x08).
    try buf.append(@intCast(OBFUSCATION_KEY_SIZE));
    try buf.appendSlice(&key);

    // Phase 2: write the obfuscated body. The backing list IS the file, so
    // each appended byte's index in `buf` equals its absolute file offset
    // and that's what feeds the obfuscation key lookup.
    var w = ObfWriter{
        .list = &buf,
        .key = key,
    };

    // Snapshot the mempool under its mutex. We collect entries first so the
    // file write doesn't hold the mempool lock for I/O.
    //
    // FIX-76 / Core mempool_persist.cpp:88-95: we also snapshot mapDeltas
    // into a working copy. The per-entry write loop drains entries that ARE
    // in the mempool out of this map (matching Core's `mapDeltas.erase(...)`
    // at :100), and the standalone-deltas tail block writes what remains.
    var entries = std.ArrayList(*mempool_mod.MempoolEntry).init(allocator);
    defer entries.deinit();
    var working_deltas = std.AutoHashMap(types.Hash256, i64).init(allocator);
    defer working_deltas.deinit();
    {
        pool.mutex.lock();
        defer pool.mutex.unlock();
        try entries.ensureTotalCapacity(pool.entries.count());
        var it = pool.entries.iterator();
        while (it.next()) |kv| {
            entries.appendAssumeCapacity(kv.value_ptr.*);
        }
        try working_deltas.ensureTotalCapacity(pool.map_deltas.count());
        var dit = pool.map_deltas.iterator();
        while (dit.next()) |dkv| {
            working_deltas.putAssumeCapacity(dkv.key_ptr.*, dkv.value_ptr.*);
        }
    }

    try w.writeU64(@intCast(entries.items.len));

    // Tx-with-witness + nTime + nFeeDelta per Core mempool_persist.cpp:98-101.
    // FIX-76 / W120 BUG-11: the per-entry nFeeDelta is now sourced from the
    // working mapDeltas snapshot. Entries whose txid has a recorded priority
    // delta carry it inline and are removed from the working map so the tail
    // block below contains only the truly standalone deltas (operator-set
    // priorities for txids that are NOT currently in the mempool — Core
    // allows pre-prioritising a txid before it arrives).
    var tx_writer = serialize.Writer.init(allocator);
    defer tx_writer.deinit();
    for (entries.items) |entry| {
        tx_writer.list.clearRetainingCapacity();
        try serialize.writeTransaction(&tx_writer, &entry.tx);
        try w.writeObfuscated(tx_writer.getWritten());
        try w.writeI64(entry.time_added);
        // Per-entry nFeeDelta from the operator-set priority map.
        const fee_delta_for_entry: i64 = working_deltas.get(entry.txid) orelse 0;
        try w.writeI64(fee_delta_for_entry);
        // Match Core's `mapDeltas.erase(i.tx->GetHash())` (mempool_persist.cpp:100):
        // we've consumed this delta inline, so it must NOT appear again in the
        // standalone tail block.
        _ = working_deltas.remove(entry.txid);
    }

    // FIX-76: standalone mapDeltas tail block — operator-set priorities for
    // txids that are not currently in the mempool. Format matches Core's
    // `std::map<Txid, CAmount>` serializer: CompactSize(N) || N * (32-byte
    // txid || i64 LE delta). Sorted order is preserved by Core (std::map
    // iterates in key order) but the on-load Apply step (PrioritiseTransaction)
    // is order-independent, so we emit in whatever order the AutoHashMap
    // iterator hands them back — interop with Core is preserved because Core
    // reads the map into a std::map and then iterates regardless of write
    // order.
    try w.writeCompactSize(working_deltas.count());
    var rem_it = working_deltas.iterator();
    while (rem_it.next()) |rkv| {
        try w.writeObfuscated(&rkv.key_ptr.*);
        try w.writeI64(rkv.value_ptr.*);
    }

    // unbroadcast_txids (empty — clearbit doesn't yet track unbroadcast set).
    try w.writeCompactSize(0);

    // Phase 3: atomic write — file.new -> rename -> file.
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.new", .{path});
    defer allocator.free(tmp_path);

    {
        const f = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(buf.items);
        // Best-effort fsync. Failure isn't fatal for a mempool dump.
        f.sync() catch {};
    }
    std.fs.cwd().rename(tmp_path, path) catch |e| {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return e;
    };

    return entries.items.len;
}

/// Result of a successful loadMempool call.
pub const LoadResult = struct {
    /// Number of transactions read from the file.
    total: usize,
    /// Number actually accepted into the mempool (rest expired or rejected).
    accepted: usize,
    /// Number rejected because their nTime was older than mempool expiry.
    expired: usize,
    /// Number rejected by the mempool (e.g. weight, dust, etc).
    failed: usize,
};

/// Load a Bitcoin Core mempool.dat. Accepts both v1 (no XOR) and v2 (XOR
/// obfuscation) on-disk formats. Returns Error.InvalidFormat for any other
/// version, malformed CompactSize, or truncated file.
///
/// Each transaction is fed through `pool.acceptToMemoryPool`. Standardness +
/// weight + dust checks therefore apply identically to load-time tx and to
/// freshly-relayed tx — that's the only sane behaviour for a node that
/// might be loading a dump from a peer running a different policy.
pub fn loadMempool(
    pool: *mempool_mod.Mempool,
    path: []const u8,
    allocator: std.mem.Allocator,
) !LoadResult {
    const file = std.fs.cwd().openFile(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return LoadResult{
            .total = 0,
            .accepted = 0,
            .expired = 0,
            .failed = 0,
        },
        else => return e,
    };
    defer file.close();

    const size_u64 = try file.getEndPos();
    if (size_u64 > std.math.maxInt(usize)) return Error.InvalidFormat;
    const size: usize = @intCast(size_u64);
    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    const n = try file.readAll(buf);
    if (n != size) return Error.UnexpectedEof;

    var reader = ObfReader{
        .data = buf,
        .pos = 0,
        .key = [_]u8{0} ** OBFUSCATION_KEY_SIZE, // start with no obfuscation
    };

    // Read the version field (always raw, regardless of v1/v2).
    const version = blk: {
        if (reader.pos + 8 > reader.data.len) return Error.UnexpectedEof;
        const v = std.mem.readInt(u64, reader.data[reader.pos..][0..8], .little);
        reader.pos += 8;
        break :blk v;
    };

    if (version == MEMPOOL_DUMP_VERSION_NO_XOR_KEY) {
        // v1: no obfuscation key in the file. Key stays all-zero.
    } else if (version == MEMPOOL_DUMP_VERSION) {
        // v2: read 8-byte XOR key (preceded by CompactSize=8). Both bytes
        // are still UNOBFUSCATED at this point — Core's SetObfuscation only
        // takes effect on subsequent reads.
        if (reader.pos >= reader.data.len) return Error.UnexpectedEof;
        const key_len_first = reader.data[reader.pos];
        reader.pos += 1;
        const key_len: u64 = if (key_len_first < 0xFD) blk: {
            break :blk key_len_first;
        } else if (key_len_first == 0xFD) blk: {
            if (reader.pos + 2 > reader.data.len) return Error.UnexpectedEof;
            const v: u64 = std.mem.readInt(u16, reader.data[reader.pos..][0..2], .little);
            reader.pos += 2;
            break :blk v;
        } else {
            // Anything larger than a u16 size for the obfuscation key vector
            // is wildly malformed — Core writes it as exactly 0x08.
            return Error.InvalidObfuscationKey;
        };
        if (key_len != OBFUSCATION_KEY_SIZE) return Error.InvalidObfuscationKey;
        if (reader.pos + OBFUSCATION_KEY_SIZE > reader.data.len) return Error.UnexpectedEof;
        @memcpy(&reader.key, reader.data[reader.pos .. reader.pos + OBFUSCATION_KEY_SIZE]);
        reader.pos += OBFUSCATION_KEY_SIZE;
    } else {
        return Error.UnsupportedVersion;
    }

    const total_txns: u64 = try reader.readU64();
    const total_usz: usize = @intCast(@min(total_txns, @as(u64, std.math.maxInt(usize))));

    var result = LoadResult{ .total = total_usz, .accepted = 0, .expired = 0, .failed = 0 };

    var scratch = std.ArrayList(u8).init(allocator);
    defer scratch.deinit();

    const now: i64 = std.time.timestamp();

    var i: usize = 0;
    while (i < total_usz) : (i += 1) {
        const tx = readObfuscatedTransaction(&reader, &scratch, allocator) catch |e| {
            // A truncated/garbage tail is the most common failure mode for
            // dumps from a different version; bail out and surface the
            // error so the caller can log it. Any txs already accepted into
            // the mempool stay there; their slice allocations are owned by
            // the mempool from this point forward.
            return e;
        };
        const tx_time: i64 = try reader.readI64();
        const fee_delta: i64 = try reader.readI64();

        // FIX-76: apply the per-entry priority delta BEFORE attempting to
        // accept. Mirrors Core mempool_persist.cpp:100-103:
        //     CAmount amountdelta = nFeeDelta;
        //     if (amountdelta && opts.apply_fee_delta_priority) {
        //         pool.PrioritiseTransaction(tx->GetHash(), amountdelta);
        //     }
        // The delta sticks in `map_deltas` regardless of whether the tx
        // itself is accepted — Core's intent is that an operator's
        // priority survives even if the tx is currently un-admitted.
        if (fee_delta != 0) {
            // Compute txid up-front since the delta sticks regardless of
            // accept-outcome. `computeTxidStreaming` is alloc-free; we
            // don't need to thread the allocator through.
            const persisted_txid = crypto.computeTxidStreaming(&tx);
            _ = pool.prioritiseTransaction(persisted_txid, fee_delta) catch |e| switch (e) {
                error.OutOfMemory => return Error.OutOfMemory,
            };
        }

        // Drop expired txs before bothering to validate them — matches
        // Core's `if (nTime > now - expiry)` gate.
        if (now > 0 and tx_time + mempool_mod.MEMPOOL_EXPIRY < now) {
            serialize.freeTransaction(allocator, &tx);
            result.expired += 1;
            continue;
        }

        // Hand the tx through the normal accept path. The mempool stores
        // the tx struct (and its input/output/witness slices) by reference;
        // see addTransaction in mempool.zig where `.tx = tx` is a shallow
        // copy. On accept, ownership of those allocations transfers to the
        // mempool's allocator (freed at process shutdown / pool.deinit).
        // On reject, we free them here.
        const accept = pool.acceptToMemoryPool(tx, false);
        if (accept.accepted) {
            result.accepted += 1;
        } else {
            serialize.freeTransaction(allocator, &tx);
            result.failed += 1;
        }
    }

    // FIX-76 / Core mempool_persist.cpp:124-130: standalone mapDeltas tail
    // block. Each (txid, delta) pair is applied via
    // `pool.prioritiseTransaction(txid, delta)` so an operator's pre-
    // prioritisation for a txid that has not yet hit the mempool survives
    // a restart. Was: read-and-discard, dropping the delta silently.
    {
        const map_count = try reader.readCompactSize();
        var j: u64 = 0;
        while (j < map_count) : (j += 1) {
            var txid: types.Hash256 = undefined;
            try reader.readObfuscated(&txid);
            const delta: i64 = try reader.readI64();
            _ = pool.prioritiseTransaction(txid, delta) catch |e| switch (e) {
                error.OutOfMemory => return Error.OutOfMemory,
            };
        }
    }

    // unbroadcast_txids — read and discard for now (no unbroadcast tracking).
    {
        const set_count = try reader.readCompactSize();
        var j: u64 = 0;
        while (j < set_count) : (j += 1) {
            var txid: [32]u8 = undefined;
            try reader.readObfuscated(&txid);
        }
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "obfuscation: round-trip a buffer" {
    var data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xFF, 0x00 };
    const original = data;
    const key = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

    applyObfuscation(&data, 0, key);
    try std.testing.expect(!std.mem.eql(u8, &data, &original));
    applyObfuscation(&data, 0, key);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "obfuscation: offset-based key indexing matches Core" {
    // Core's Obfuscation: byte at file offset N is XORed with key[N % 8].
    // Verify a partial buffer starting at offset 3 uses key[3..] then wraps.
    var data = [_]u8{0x00} ** 16;
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    applyObfuscation(&data, 3, key);

    // Expected bytes: data[0] (file-offset 3) ^= key[3], data[1] ^= key[4], etc
    const expected = [_]u8{
        0x04, 0x05, 0x06, 0x07, 0x08, // file offsets 3..7
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // file offsets 8..15
        0x01, 0x02, 0x03, // file offsets 16..18
    };
    try std.testing.expectEqualSlices(u8, &expected, &data);
}

test "obfuscation: zero-key is a no-op" {
    var data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const original = data;
    const key = [_]u8{0x00} ** 8;
    applyObfuscation(&data, 0, key);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "dump+load round-trip: empty mempool" {
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();

    const path_rel = "mempool.dat";
    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ real_path, path_rel });
    defer allocator.free(path);

    const written = try dumpMempool(&pool, path, allocator);
    try std.testing.expectEqual(@as(usize, 0), written);

    var pool2 = mempool_mod.Mempool.init(null, null, allocator);
    defer pool2.deinit();

    const result = try loadMempool(&pool2, path, allocator);
    try std.testing.expectEqual(@as(usize, 0), result.total);
    try std.testing.expectEqual(@as(usize, 0), result.accepted);
    try std.testing.expectEqual(@as(usize, 0), result.expired);
    try std.testing.expectEqual(@as(usize, 0), result.failed);
}

test "dump+load round-trip: single tx survives obfuscation" {
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Standard P2WPKH-output tx that passes mempool acceptance with no
    // chain state plumbed in (no fee check fires when total_in == 0).
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x42} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 100_000,
        .script_pubkey = &p2wpkh_script,
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };
    try pool.addTransaction(tx);

    const original_count = pool.entries.count();
    try std.testing.expectEqual(@as(usize, 1), original_count);

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();

    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/mempool.dat", .{real_path});
    defer allocator.free(path);

    const written = try dumpMempool(&pool, path, allocator);
    try std.testing.expectEqual(@as(usize, 1), written);

    // Sanity-check the file: first 8 bytes are version 2 (raw u64 LE).
    {
        const f = try std.fs.cwd().openFile(path, .{});
        defer f.close();
        var hdr: [9]u8 = undefined;
        const read = try f.readAll(&hdr);
        try std.testing.expectEqual(@as(usize, 9), read);
        const ver = std.mem.readInt(u64, hdr[0..8], .little);
        try std.testing.expectEqual(@as(u64, MEMPOOL_DUMP_VERSION), ver);
        // CompactSize for the 8-byte XOR key vector.
        try std.testing.expectEqual(@as(u8, 0x08), hdr[8]);
    }

    var pool2 = mempool_mod.Mempool.init(null, null, allocator);
    defer pool2.deinit();
    const result = try loadMempool(&pool2, path, allocator);
    try std.testing.expectEqual(@as(usize, 1), result.total);
    try std.testing.expectEqual(@as(usize, 1), result.accepted);
    try std.testing.expectEqual(@as(usize, 0), result.expired);
    try std.testing.expectEqual(@as(usize, 0), result.failed);
    try std.testing.expectEqual(@as(usize, 1), pool2.entries.count());

    // The reloaded tx must have the same txid as the original.
    const original_txid = try crypto.computeTxid(&tx, allocator);
    try std.testing.expect(pool2.entries.contains(original_txid));

    // Free the slices owned by the reloaded mempool entries before
    // pool2.deinit (which only destroys MempoolEntry structs, not the
    // tx slices). In production the GeneralPurposeAllocator outlives
    // the mempool and these allocations are reclaimed on process exit;
    // under std.testing.allocator we have to free them explicitly.
    var iter = pool2.entries.iterator();
    while (iter.next()) |kv| {
        serialize.freeTransaction(allocator, &kv.value_ptr.*.tx);
    }
}

test "load: missing file is a no-op" {
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();

    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/does-not-exist.dat", .{real_path});
    defer allocator.free(path);

    const result = try loadMempool(&pool, path, allocator);
    try std.testing.expectEqual(@as(usize, 0), result.total);
    try std.testing.expectEqual(@as(usize, 0), result.accepted);
}

test "load: unsupported version errors out" {
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();
    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/bad.dat", .{real_path});
    defer allocator.free(path);

    // Write a version=99 file.
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        var ver_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &ver_buf, 99, .little);
        try f.writeAll(&ver_buf);
    }

    try std.testing.expectError(Error.UnsupportedVersion, loadMempool(&pool, path, allocator));
}

// ============================================================================
// FIX-76 — mapDeltas (operator-set priority deltas) persistence.
// Reference: bitcoin-core/src/node/mempool_persist.cpp:88-103 (DumpMempool
// writes the per-entry nFeeDelta + erases from mapDeltas; the surviving
// mapDeltas entries are written as the standalone tail block) and :100-130
// (LoadMempool calls PrioritiseTransaction for both the inline per-entry
// delta and the standalone tail block entries).
//
// Pre-FIX-76 the dump path emitted CompactSize(0) for the tail block and
// the load path read-and-discarded both inline + tail deltas — so an
// operator's priority survived in-memory but was lost on restart.
// ============================================================================

test "FIX-76: standalone delta for absent txid survives dump+load" {
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Pre-prioritise a txid that has NOT entered the mempool yet — Core
    // explicitly supports this; the delta is parked in mapDeltas until the
    // tx arrives.
    const absent_txid: types.Hash256 = .{0xAB} ** 32;
    const delta: i64 = 42_000;
    _ = try pool.prioritiseTransaction(absent_txid, delta);
    try std.testing.expectEqual(delta, pool.applyDelta(absent_txid));

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();
    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/mempool.dat", .{real_path});
    defer allocator.free(path);

    const written = try dumpMempool(&pool, path, allocator);
    try std.testing.expectEqual(@as(usize, 0), written); // no entries

    // Fresh pool — the standalone delta should be applied during load.
    var pool2 = mempool_mod.Mempool.init(null, null, allocator);
    defer pool2.deinit();
    const r = try loadMempool(&pool2, path, allocator);
    try std.testing.expectEqual(@as(usize, 0), r.total);
    try std.testing.expectEqual(@as(usize, 0), r.accepted);

    // The delta must be restored.
    try std.testing.expectEqual(delta, pool2.applyDelta(absent_txid));
    try std.testing.expect(pool2.map_deltas.contains(absent_txid));
}

test "FIX-76: in-mempool delta survives dump+load via per-entry nFeeDelta" {
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Same standardness-passing tx shape as the single-tx round-trip test
    // above (P2WPKH out, no chain state plumbed = no fee check fires).
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xCD} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x77} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{
        .value = 50_000,
        .script_pubkey = &p2wpkh_script,
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };
    try pool.addTransaction(tx);

    const txid = try crypto.computeTxid(&tx, allocator);
    const delta: i64 = 9_999;
    _ = try pool.prioritiseTransaction(txid, delta);

    // Sanity: getModifiedFee reflects the delta pre-dump.
    const entry_pre = pool.entries.get(txid) orelse return error.MissingEntry;
    try std.testing.expectEqual(entry_pre.fee + delta, pool.getModifiedFee(entry_pre));

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();
    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/mempool.dat", .{real_path});
    defer allocator.free(path);

    const written = try dumpMempool(&pool, path, allocator);
    try std.testing.expectEqual(@as(usize, 1), written);

    var pool2 = mempool_mod.Mempool.init(null, null, allocator);
    defer pool2.deinit();
    const r = try loadMempool(&pool2, path, allocator);
    try std.testing.expectEqual(@as(usize, 1), r.total);
    try std.testing.expectEqual(@as(usize, 1), r.accepted);

    // Delta must be restored AND the entry reflects the modified fee.
    try std.testing.expectEqual(delta, pool2.applyDelta(txid));
    const entry_post = pool2.entries.get(txid) orelse return error.MissingEntry;
    try std.testing.expectEqual(entry_post.fee + delta, pool2.getModifiedFee(entry_post));

    // Free the slices owned by the reloaded mempool entries — testing
    // allocator is strict.
    var iter = pool2.entries.iterator();
    while (iter.next()) |kv| {
        serialize.freeTransaction(allocator, &kv.value_ptr.*.tx);
    }
}

test "FIX-76: empty map_deltas survives dump+load (negative case)" {
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    try std.testing.expectEqual(@as(u32, 0), pool.map_deltas.count());

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();
    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/mempool.dat", .{real_path});
    defer allocator.free(path);

    _ = try dumpMempool(&pool, path, allocator);

    var pool2 = mempool_mod.Mempool.init(null, null, allocator);
    defer pool2.deinit();
    _ = try loadMempool(&pool2, path, allocator);
    try std.testing.expectEqual(@as(u32, 0), pool2.map_deltas.count());
}

test "FIX-76: mixed in-mempool + standalone deltas round-trip independently" {
    // The dump path partitions map_deltas into (a) per-entry inline (txid
    // currently in mempool) and (b) standalone tail (txid absent). Both
    // paths must restore the delta on load without overlap.
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // (a) in-mempool entry with a positive delta.
    const p2wpkh = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xEF} ** 20;
    const tx_in_pool = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 1 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{.{ .value = 60_000, .script_pubkey = &p2wpkh }},
        .lock_time = 0,
    };
    try pool.addTransaction(tx_in_pool);
    const live_txid = try crypto.computeTxid(&tx_in_pool, allocator);
    const live_delta: i64 = 12345;
    _ = try pool.prioritiseTransaction(live_txid, live_delta);

    // (b) absent txid with a negative delta — exercises sign preservation
    // through the i64 LE round-trip.
    const absent_txid: types.Hash256 = .{0xBE} ** 32;
    const absent_delta: i64 = -777;
    _ = try pool.prioritiseTransaction(absent_txid, absent_delta);

    // map_deltas now has 2 entries; one live, one absent.
    try std.testing.expectEqual(@as(u32, 2), pool.map_deltas.count());

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();
    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/mempool.dat", .{real_path});
    defer allocator.free(path);

    _ = try dumpMempool(&pool, path, allocator);

    var pool2 = mempool_mod.Mempool.init(null, null, allocator);
    defer pool2.deinit();
    _ = try loadMempool(&pool2, path, allocator);

    try std.testing.expectEqual(live_delta, pool2.applyDelta(live_txid));
    try std.testing.expectEqual(absent_delta, pool2.applyDelta(absent_txid));
    try std.testing.expectEqual(@as(u32, 2), pool2.map_deltas.count());

    // Free reloaded tx slices.
    var iter = pool2.entries.iterator();
    while (iter.next()) |kv| {
        serialize.freeTransaction(allocator, &kv.value_ptr.*.tx);
    }
}

test "FIX-76: old-format file (pre-FIX-76 empty tail) loads cleanly" {
    // Pre-FIX-76 dumps wrote CompactSize(0) for both mapDeltas and
    // unbroadcast_txids tails. The format is unchanged — FIX-76 only changes
    // CONTENTS. A pre-FIX-76 file written by the OLD dump path therefore
    // has an empty tail block. We assert that the FIX-76 load path handles
    // this without error and leaves map_deltas empty.
    //
    // We simulate by writing a file with the current dump path while the
    // mempool has no deltas; that is bitwise-identical to a pre-FIX-76 dump
    // of an empty-delta mempool.
    const allocator = std.testing.allocator;
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    try std.testing.expectEqual(@as(u32, 0), pool.map_deltas.count());

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();
    const real_path = try tmpdir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(real_path);
    const path = try std.fmt.allocPrint(allocator, "{s}/old_fmt.dat", .{real_path});
    defer allocator.free(path);

    _ = try dumpMempool(&pool, path, allocator);

    var pool2 = mempool_mod.Mempool.init(null, null, allocator);
    defer pool2.deinit();
    _ = try loadMempool(&pool2, path, allocator);
    try std.testing.expectEqual(@as(u32, 0), pool2.map_deltas.count());
}

test "FIX-76: forward-regression source guard" {
    // Pin the FIX-76 wiring at the source level. A drive-by revert that
    // re-introduces a hardcoded `writeI64(0)` for the per-entry nFeeDelta,
    // or that drops the prioritiseTransaction call on load, would fail
    // this test FIRST (before silently dropping operator deltas in prod).
    const src = @embedFile("mempool_persist.zig");

    // Dump path: per-entry delta lookup from working snapshot.
    const dump_inline = "const fee_delta_for_entry: i64 = working_deltas.get(entry.txid)";
    try std.testing.expect(std.mem.indexOf(u8, src, dump_inline) != null);

    // Dump path: standalone tail loop emits the remaining deltas.
    const dump_tail = "try w.writeCompactSize(working_deltas.count());";
    try std.testing.expect(std.mem.indexOf(u8, src, dump_tail) != null);

    // Load path: per-entry prioritiseTransaction call.
    const load_inline = "pool.prioritiseTransaction(persisted_txid, fee_delta)";
    try std.testing.expect(std.mem.indexOf(u8, src, load_inline) != null);

    // Load path: standalone-tail prioritiseTransaction call.
    const load_tail = "pool.prioritiseTransaction(txid, delta)";
    try std.testing.expect(std.mem.indexOf(u8, src, load_tail) != null);

    // The legacy "not tracked yet" form for the per-entry nFeeDelta write
    // must NOT be present in the dump path — its survival means an in-
    // mempool entry's delta is silently zeroed on dump. We split the
    // literal across two `++` halves so this guard test does NOT trip
    // over its OWN source string when @embedFile-scanning the module.
    const dead_form = "writeI64(0); " ++ "// nFeeDelta — not tracked yet";
    try std.testing.expect(std.mem.indexOf(u8, src, dead_form) == null);
}
