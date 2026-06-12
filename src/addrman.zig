//! Core-bucketed address manager (CAddrMan port) — clearbit (Zig 0.13)
//!
//! A faithful port of Bitcoin Core's CAddrMan (bitcoin-core/src/addrman.cpp +
//! addrman_impl.h): two id-indexed bucket tables (NEW[1024][64] +
//! TRIED[256][64]) keyed off a per-manager 256-bit salt `nkey`, with the
//! deterministic GetNewBucket / GetTriedBucket / GetBucketPosition placement,
//! Add / Good / Select, IsTerrible eviction, and a versioned, corrupt-safe,
//! bounded peers.dat-equivalent persistence.
//!
//! This is wired UNDER clearbit's existing public addr API in peer.zig
//! (addAddress / selectPeerToConnect / knownAddressCount / the gossip walk /
//! the rpc.zig getnodeaddresses + addpeeraddress iterators). The legacy
//! `known_addresses` flat map in PeerManager is retained for the rich
//! getnodeaddresses / addr-sharing metadata; THIS table is the placement +
//! anti-Sybil engine + persistence. The public method signatures of peer.zig /
//! rpc.zig are unaffected.
//!
//! NOTE: the cheap hash here is impl-internal (single SHA-256 truncated to the
//! low 8 bytes, little-endian). peers.dat is a LOCAL file (never wire/RPC), so
//! byte-identical Core bucket numbers are not required and not claimed; the
//! golden test pins THIS impl's chosen hash.
//!
//! Mirrors rustoshi 361d81b (crates/network/src/peer_manager.rs AddrManTable)
//! and nimrod 534cc6c / blockbrew 6c5a463.

const std = @import("std");
const crypto = @import("crypto.zig");

const Allocator = std.mem.Allocator;
const SocketAddr = std.net.Address;

// ============================================================================
// Core constants (addrman.h / addrman_impl.h)
// ============================================================================

/// Number of new-address buckets (Core ADDRMAN_NEW_BUCKET_COUNT = 1 << 10).
pub const ADDRMAN_NEW_BUCKET_COUNT: usize = 1024;
/// Number of tried-address buckets (Core ADDRMAN_TRIED_BUCKET_COUNT = 1 << 8).
pub const ADDRMAN_TRIED_BUCKET_COUNT: usize = 256;
/// Positions per bucket (Core ADDRMAN_BUCKET_SIZE = 1 << 6).
pub const ADDRMAN_BUCKET_SIZE: usize = 64;
/// New buckets a single source group can reach (Core
/// ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP). Anti-Sybil cap.
pub const ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 64;
/// Tried buckets a single addr group can reach (Core
/// ADDRMAN_TRIED_BUCKETS_PER_GROUP). Anti-Sybil cap.
pub const ADDRMAN_TRIED_BUCKETS_PER_GROUP: u64 = 8;
/// Max new buckets one address may simultaneously occupy (Core
/// ADDRMAN_NEW_BUCKETS_PER_ADDRESS).
pub const ADDRMAN_NEW_BUCKETS_PER_ADDRESS: u32 = 8;
/// Addresses not seen in this long are terrible (Core ADDRMAN_HORIZON = 30 d).
pub const ADDRMAN_HORIZON_SECS: u64 = 30 * 24 * 60 * 60;
/// Tries after which a never-successful address is terrible (Core
/// ADDRMAN_RETRIES).
pub const ADDRMAN_RETRIES: u32 = 3;
/// Failed-attempt count after which a long-failing address is terrible (Core
/// ADDRMAN_MAX_FAILURES).
pub const ADDRMAN_MAX_FAILURES: u32 = 10;
/// Minimum time since last success before MAX_FAILURES applies (Core
/// ADDRMAN_MIN_FAIL = 7 d).
pub const ADDRMAN_MIN_FAIL_SECS: u64 = 7 * 24 * 60 * 60;

/// Hard slot ceiling: every id occupies at most one slot per table, and no
/// table can grow past its fixed bucket geometry. This is the bounded ceiling.
pub const ADDRMAN_CEILING: usize = ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE +
    ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE;

/// On-disk format version for the peers.dat-equiv. Bumping invalidates older
/// files (they load as an empty cold start, never a hard-down).
pub const ADDRMAN_DAT_VERSION: u32 = 1;
/// Filename for the bucketed addrman persistence (peers.dat-equiv).
pub const PEERS_DATABASE_FILENAME: []const u8 = "peers.dat";

/// Integer node id (Core nid_type). `-1` is the empty-slot sentinel.
pub const NId = i64;
const EMPTY: NId = -1;

// ============================================================================
// AddrManEntry (Core AddrInfo bookkeeping)
// ============================================================================

/// One address record held by the bucketed addrman. Mirrors Core AddrInfo's
/// bookkeeping fields (refcount, in_tried, attempt/success/seen times).
pub const AddrManEntry = struct {
    /// The socket address (IPv4/IPv6 only in this pilot).
    addr: SocketAddr,
    /// Services bitfield.
    services: u64,
    /// /16 (v4) or /32 (v6) network group of the address itself (Core
    /// NetGroupManager::GetGroup(addr)).
    addr_group: u32,
    /// Network group of the source that first told us about this address.
    src_group: u32,
    /// Last-seen unix timestamp (seconds).
    time_unix: u64,
    /// Last-success unix timestamp (0 = never).
    last_success_unix: u64,
    /// Last-try unix timestamp (0 = never).
    last_try_unix: u64,
    /// Consecutive connection attempts.
    attempts: u32,
    /// How many new buckets reference this id (Core nRefCount). 0 once in tried.
    ref_count: u32,
    /// Whether this id currently lives in the tried table.
    in_tried: bool,

    /// Core IsTerrible: should this entry be eviction-preferred? Ports the five
    /// Core conditions (addrman.cpp:49-72) using `now` as unix seconds.
    pub fn isTerrible(self: *const AddrManEntry, now: u64) bool {
        // never remove things tried in the last minute
        if (self.last_try_unix != 0 and now -| self.last_try_unix <= 60) {
            return false;
        }
        // came in a flying DeLorean
        if (self.time_unix > now + 10 * 60) {
            return true;
        }
        // not seen in recent history
        if (now -| self.time_unix > ADDRMAN_HORIZON_SECS) {
            return true;
        }
        // tried N times and never a success
        if (self.last_success_unix == 0 and self.attempts >= ADDRMAN_RETRIES) {
            return true;
        }
        // N successive failures in the last week
        if (self.last_success_unix != 0 and
            now -| self.last_success_unix > ADDRMAN_MIN_FAIL_SECS and
            self.attempts >= ADDRMAN_MAX_FAILURES)
        {
            return true;
        }
        return false;
    }
};

// ============================================================================
// Address key helpers (Core CService::GetKey analogue)
// ============================================================================

/// Stable 18-byte key for an address: 16-byte IPv6 representation (IPv4 is
/// IPv4-mapped) + 2-byte big-endian port. Mirrors Core CService::GetKey.
pub fn addrKey(addr: SocketAddr) [18]u8 {
    var v = [_]u8{0} ** 18;
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
            const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            v[10] = 0xFF;
            v[11] = 0xFF;
            v[12] = ip_bytes[0];
            v[13] = ip_bytes[1];
            v[14] = ip_bytes[2];
            v[15] = ip_bytes[3];
            // ip4.port is stored network-order (big-endian) already.
            const port_be = std.mem.bigToNative(u16, ip4.port);
            std.mem.writeInt(u16, v[16..18], port_be, .big);
        },
        std.posix.AF.INET6 => {
            const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
            @memcpy(v[0..16], &ip6.addr);
            const port_be = std.mem.bigToNative(u16, ip6.port);
            std.mem.writeInt(u16, v[16..18], port_be, .big);
        },
        else => {},
    }
    return v;
}

/// Compact u64 map key for an address (Core mapAddr key). Equivalent to
/// peer.zig PeerManager.addressKey but computed from the 18-byte stable key so
/// IPv6 collisions are vanishingly unlikely.
pub fn addrMapKey(addr: SocketAddr) u64 {
    const k = addrKey(addr);
    const h = crypto.sha256(&k);
    return std.mem.readInt(u64, h[0..8], .little);
}

// ============================================================================
// AddrMan (Core CAddrMan: NEW/TRIED tables + id maps + salt)
// ============================================================================

/// Core-bucketed address manager: the NEW/TRIED tables + id maps + salt.
///
/// Heap-allocates the bucket tables (each is ~512 KB / ~128 KB of i64) to avoid
/// a stack-overflow at construct (Core stores them behind the heap-allocated
/// AddrManImpl).
pub const AddrMan = struct {
    allocator: Allocator,
    /// 256-bit per-manager salt (Core nKey). Persisted; drives all placement.
    nkey: [32]u8,
    /// NEW table: vv_new[bucket][pos] = id (or -1). Heap-allocated.
    vv_new: []NId,
    /// TRIED table: vv_tried[bucket][pos] = id (or -1). Heap-allocated.
    vv_tried: []NId,
    /// id -> entry (Core mapInfo).
    map_info: std.AutoHashMap(NId, AddrManEntry),
    /// addr-map-key -> id (Core mapAddr).
    map_addr: std.AutoHashMap(u64, NId),
    /// Next id to allocate (Core nIdCount).
    id_count: NId,
    /// Count of ids in the new table (Core nNew).
    n_new: usize,
    /// Count of ids in the tried table (Core nTried).
    n_tried: usize,
    /// Deterministic RNG for Select / multiplicity gating (seeded from nkey so
    /// tests are reproducible; not security-sensitive).
    rng: std.Random.DefaultPrng,

    const Self = @This();

    fn idx(bucket: usize, pos: usize) usize {
        return bucket * ADDRMAN_BUCKET_SIZE + pos;
    }

    /// Create an empty table with a random salt.
    pub fn init(allocator: Allocator) !Self {
        var nkey: [32]u8 = undefined;
        std.crypto.random.bytes(&nkey);
        return initWithNKey(allocator, nkey);
    }

    /// Create an empty table with a fixed salt (deterministic; for tests +
    /// persistence restore).
    pub fn initWithNKey(allocator: Allocator, nkey: [32]u8) !Self {
        const vv_new = try allocator.alloc(NId, ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE);
        errdefer allocator.free(vv_new);
        const vv_tried = try allocator.alloc(NId, ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE);
        @memset(vv_new, EMPTY);
        @memset(vv_tried, EMPTY);
        // Seed the RNG from the salt so deterministic builds are reproducible.
        const seed = std.mem.readInt(u64, nkey[0..8], .little);
        return Self{
            .allocator = allocator,
            .nkey = nkey,
            .vv_new = vv_new,
            .vv_tried = vv_tried,
            .map_info = std.AutoHashMap(NId, AddrManEntry).init(allocator),
            .map_addr = std.AutoHashMap(u64, NId).init(allocator),
            .id_count = 0,
            .n_new = 0,
            .n_tried = 0,
            .rng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.vv_new);
        self.allocator.free(self.vv_tried);
        self.map_info.deinit();
        self.map_addr.deinit();
    }

    // --- cheap hash + placement (Core HashWriter::GetCheapHash analogue) -----

    /// Single SHA-256 of the concatenated parts, low 8 bytes interpreted
    /// little-endian (Core GetCheapHash analogue).
    fn cheapHash(parts: []const []const u8) u64 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (parts) |p| hasher.update(p);
        var h: [32]u8 = undefined;
        hasher.final(&h);
        return std.mem.readInt(u64, h[0..8], .little);
    }

    fn groupBytes(group: u32) [4]u8 {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, group, .little);
        return b;
    }

    /// Core AddrInfo::GetNewBucket.
    pub fn getNewBucket(self: *const Self, addr_group: u32, src_group: u32) usize {
        const ag = groupBytes(addr_group);
        const sg = groupBytes(src_group);
        const hash1 = cheapHash(&[_][]const u8{ &self.nkey, &ag, &sg });
        const h1mod = groupBytes(@intCast(hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP));
        const hash2 = cheapHash(&[_][]const u8{ &self.nkey, &sg, &h1mod });
        return @intCast(hash2 % ADDRMAN_NEW_BUCKET_COUNT);
    }

    /// Core AddrInfo::GetTriedBucket.
    pub fn getTriedBucket(self: *const Self, addr: SocketAddr, addr_group: u32) usize {
        const k = addrKey(addr);
        const ag = groupBytes(addr_group);
        const hash1 = cheapHash(&[_][]const u8{ &self.nkey, &k });
        const h1mod = groupBytes(@intCast(hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP));
        const hash2 = cheapHash(&[_][]const u8{ &self.nkey, &ag, &h1mod });
        return @intCast(hash2 % ADDRMAN_TRIED_BUCKET_COUNT);
    }

    /// Core AddrInfo::GetBucketPosition.
    pub fn getBucketPosition(self: *const Self, f_new: bool, bucket: usize, addr: SocketAddr) usize {
        const tag = [_]u8{if (f_new) @as(u8, 'N') else @as(u8, 'K')};
        const bb = groupBytes(@intCast(bucket));
        const k = addrKey(addr);
        const hash1 = cheapHash(&[_][]const u8{ &self.nkey, &tag, &bb, &k });
        return @intCast(hash1 % ADDRMAN_BUCKET_SIZE);
    }

    // --- internal map helpers (Core Find / Create / Delete / ClearNew) -------

    fn find(self: *const Self, addr: SocketAddr) ?NId {
        return self.map_addr.get(addrMapKey(addr));
    }

    fn create(
        self: *Self,
        addr: SocketAddr,
        addr_group: u32,
        src_group: u32,
        services: u64,
        time_unix: u64,
    ) !NId {
        const id = self.id_count;
        self.id_count += 1;
        try self.map_info.put(id, AddrManEntry{
            .addr = addr,
            .services = services,
            .addr_group = addr_group,
            .src_group = src_group,
            .time_unix = time_unix,
            .last_success_unix = 0,
            .last_try_unix = 0,
            .attempts = 0,
            .ref_count = 0,
            .in_tried = false,
        });
        try self.map_addr.put(addrMapKey(addr), id);
        return id;
    }

    fn delete(self: *Self, id: NId) void {
        if (self.map_info.get(id)) |info| {
            if (info.ref_count == 0 and !info.in_tried) {
                _ = self.map_addr.remove(addrMapKey(info.addr));
                _ = self.map_info.remove(id);
            }
        }
    }

    fn clearNew(self: *Self, bucket: usize, pos: usize) void {
        const id = self.vv_new[idx(bucket, pos)];
        if (id == EMPTY) return;
        self.vv_new[idx(bucket, pos)] = EMPTY;
        if (self.map_info.getPtr(id)) |info| {
            if (info.ref_count > 0) info.ref_count -= 1;
            if (info.ref_count == 0) {
                self.n_new -|= 1;
                self.delete(id);
            }
        }
    }

    // --- public API: Add / Good / Attempt / Select ---------------------------

    /// Core Add_/AddSingle: place a heard-about address in the NEW table.
    /// Returns true if a fresh slot insertion occurred. The bounded-ceiling
    /// guard causes a `false` return. Caller is responsible for routability
    /// filtering (clearbit does this in PeerManager.addAddress via isRoutable);
    /// addr_group/src_group are the netGroup() values for the address & source.
    pub fn add(
        self: *Self,
        addr: SocketAddr,
        addr_group: u32,
        src_group: u32,
        services: u64,
        time_unix: u64,
        now: u64,
    ) !bool {
        const existing = self.find(addr);
        var id: NId = undefined;
        if (existing) |eid| {
            if (self.map_info.getPtr(eid)) |info| {
                if (time_unix > info.time_unix) info.time_unix = time_unix;
                info.services |= services;
                if (info.in_tried) return false;
                if (info.ref_count >= ADDRMAN_NEW_BUCKETS_PER_ADDRESS) return false;
                // stochastic multiplicity gate: 2^refcount harder each time.
                if (info.ref_count > 0) {
                    const factor = @as(u32, 1) << @intCast(info.ref_count);
                    if (self.rng.random().int(u32) % factor != 0) return false;
                }
            }
            id = eid;
        } else {
            // Bounded-ceiling guard: never allocate past the table capacity.
            if (self.map_info.count() >= ADDRMAN_CEILING) return false;
            id = try self.create(addr, addr_group, src_group, services, time_unix);
        }

        const bucket = self.getNewBucket(addr_group, src_group);
        const pos = self.getBucketPosition(true, bucket, addr);
        const occupant = self.vv_new[idx(bucket, pos)];

        var insert = occupant == EMPTY;
        if (occupant == id) {
            return insert;
        }
        if (!insert) {
            // Collision: overwrite iff occupant terrible, or occupant
            // multiply-referenced while the newcomer is fresh (Core rule).
            if (self.map_info.get(occupant)) |o| {
                const new_rc = if (self.map_info.get(id)) |n| n.ref_count else 0;
                insert = o.isTerrible(now) or (o.ref_count > 1 and new_rc == 0);
            } else {
                insert = true;
            }
        }
        if (insert) {
            self.clearNew(bucket, pos);
            if (self.map_info.getPtr(id)) |info| info.ref_count += 1;
            self.vv_new[idx(bucket, pos)] = id;
            self.n_new += 1;
            return true;
        } else {
            // newly-created but not inserted -> drop it.
            if (self.map_info.get(id)) |i| {
                if (i.ref_count == 0) self.delete(id);
            }
            return false;
        }
    }

    /// Core Good_/MakeTried: promote an address from NEW to TRIED, evicting the
    /// existing tried occupant back to its NEW bucket on collision.
    pub fn good(self: *Self, addr: SocketAddr, now: u64) !bool {
        const id = self.find(addr) orelse return false;
        if (self.map_info.getPtr(id)) |info| {
            info.last_success_unix = now;
            info.last_try_unix = now;
            info.attempts = 0;
            if (info.in_tried) return false;
            if (info.ref_count == 0) return false;
        }

        // Remove the id from ALL its new buckets (Core MakeTried loop).
        const ag = self.map_info.get(id).?.addr_group;
        const sg = self.map_info.get(id).?.src_group;
        const start = self.getNewBucket(ag, sg);
        var n: usize = 0;
        while (n < ADDRMAN_NEW_BUCKET_COUNT) : (n += 1) {
            const b = (start + n) % ADDRMAN_NEW_BUCKET_COUNT;
            const p = self.getBucketPosition(true, b, addr);
            if (self.vv_new[idx(b, p)] == id) {
                self.vv_new[idx(b, p)] = EMPTY;
                if (self.map_info.getPtr(id)) |info| {
                    if (info.ref_count > 0) info.ref_count -= 1;
                    if (info.ref_count == 0) break;
                }
            }
        }
        self.n_new -|= 1;
        if (self.map_info.getPtr(id)) |info| info.ref_count = 0;

        // Compute the tried slot.
        const k_bucket = self.getTriedBucket(addr, ag);
        const k_pos = self.getBucketPosition(false, k_bucket, addr);

        // On collision evict the existing tried occupant back to NEW.
        const evict = self.vv_tried[idx(k_bucket, k_pos)];
        if (evict != EMPTY) {
            self.vv_tried[idx(k_bucket, k_pos)] = EMPTY;
            self.n_tried -|= 1;
            const eag = self.map_info.get(evict).?.addr_group;
            const esg = self.map_info.get(evict).?.src_group;
            const eaddr = self.map_info.get(evict).?.addr;
            if (self.map_info.getPtr(evict)) |old| old.in_tried = false;
            const ob = self.getNewBucket(eag, esg);
            const op = self.getBucketPosition(true, ob, eaddr);
            self.clearNew(ob, op);
            if (self.map_info.getPtr(evict)) |old| old.ref_count = 1;
            self.vv_new[idx(ob, op)] = evict;
            self.n_new += 1;
        }

        // Place the promoted id into tried.
        self.vv_tried[idx(k_bucket, k_pos)] = id;
        self.n_tried += 1;
        if (self.map_info.getPtr(id)) |info| info.in_tried = true;
        return true;
    }

    /// Core Attempt_: record a (possibly-failed) connection attempt.
    pub fn attempt(self: *Self, addr: SocketAddr, now: u64) void {
        if (self.find(addr)) |id| {
            if (self.map_info.getPtr(id)) |info| {
                info.last_try_unix = now;
                info.attempts += 1;
            }
        }
    }

    /// Core Select_ (simplified, bounded): 50/50 new-vs-tried when both are
    /// non-empty, then scan a random bucket from a random position and return
    /// the first occupant. Bounded (at most bucket_count * BUCKET_SIZE slots)
    /// and guaranteed to return an occupant whenever one exists.
    pub fn select(self: *Self, new_only: bool) ?SocketAddr {
        if (self.map_info.count() == 0) return null;
        if (new_only and self.n_new == 0) return null;
        if (self.n_new + self.n_tried == 0) return null;

        var r = self.rng.random();
        const search_tried = blk: {
            if (new_only or self.n_tried == 0) break :blk false;
            if (self.n_new == 0) break :blk true;
            break :blk r.boolean();
        };

        const table = if (search_tried) self.vv_tried else self.vv_new;
        const bucket_count: usize = if (search_tried) ADDRMAN_TRIED_BUCKET_COUNT else ADDRMAN_NEW_BUCKET_COUNT;

        const start_bucket = r.intRangeLessThan(usize, 0, bucket_count);
        const initial_pos = r.intRangeLessThan(usize, 0, ADDRMAN_BUCKET_SIZE);
        var nb: usize = 0;
        while (nb < bucket_count) : (nb += 1) {
            const bucket = (start_bucket + nb) % bucket_count;
            var i: usize = 0;
            while (i < ADDRMAN_BUCKET_SIZE) : (i += 1) {
                const pos = (initial_pos + i) % ADDRMAN_BUCKET_SIZE;
                const id = table[idx(bucket, pos)];
                if (id != EMPTY) {
                    if (self.map_info.get(id)) |info| return info.addr;
                }
            }
        }
        return null;
    }

    // --- inspection helpers (counts + slot lookups; test/RPC support) --------

    pub fn newCount(self: *const Self) usize {
        return self.n_new;
    }
    pub fn triedCount(self: *const Self) usize {
        return self.n_tried;
    }
    pub fn totalCount(self: *const Self) usize {
        return self.map_info.count();
    }
    pub fn isInTried(self: *const Self, addr: SocketAddr) bool {
        if (self.find(addr)) |id| {
            if (self.map_info.get(id)) |i| return i.in_tried;
        }
        return false;
    }

    /// Recompute the (bucket, pos) an address currently occupies in NEW.
    /// Returns null if not in NEW.
    pub fn newSlotOf(self: *const Self, addr: SocketAddr) ?struct { bucket: usize, pos: usize } {
        const id = self.find(addr) orelse return null;
        const info = self.map_info.get(id) orelse return null;
        if (info.in_tried) return null;
        const start = self.getNewBucket(info.addr_group, info.src_group);
        var n: usize = 0;
        while (n < ADDRMAN_NEW_BUCKET_COUNT) : (n += 1) {
            const b = (start + n) % ADDRMAN_NEW_BUCKET_COUNT;
            const p = self.getBucketPosition(true, b, addr);
            if (self.vv_new[idx(b, p)] == id) return .{ .bucket = b, .pos = p };
        }
        return null;
    }

    /// The (bucket, pos) an address occupies in TRIED. null if not in TRIED.
    pub fn triedSlotOf(self: *const Self, addr: SocketAddr) ?struct { bucket: usize, pos: usize } {
        const id = self.find(addr) orelse return null;
        const info = self.map_info.get(id) orelse return null;
        if (!info.in_tried) return null;
        const kb = self.getTriedBucket(addr, info.addr_group);
        const kp = self.getBucketPosition(false, kb, addr);
        return .{ .bucket = kb, .pos = kp };
    }

    /// Look up the rich entry for an address (for getnodeaddresses parity).
    pub fn getEntry(self: *const Self, addr: SocketAddr) ?AddrManEntry {
        const id = self.find(addr) orelse return null;
        return self.map_info.get(id);
    }

    /// Iterator over all entries (for the gossip walk / getnodeaddresses).
    pub fn entryIterator(self: *const Self) std.AutoHashMap(NId, AddrManEntry).ValueIterator {
        return self.map_info.valueIterator();
    }

    // --- persistence (peers.dat-equiv) ---------------------------------------

    /// Serialize to a versioned, line-oriented text format. Format:
    ///   line 0: "ADDRMAN <version> <nkey-hex>"
    ///   then one record per id:
    ///     "<n|t> <addr> <services> <addr_group> <src_group> <time> <last_success> <last_try> <attempts> <ref_count>"
    /// New records are re-placed via add() on load; tried records are
    /// re-promoted via good() so placement is recomputed deterministically from
    /// the same nkey.
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        const w = buf.writer();
        var hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{s}", .{std.fmt.fmtSliceHexLower(&self.nkey)}) catch unreachable;
        try w.print("ADDRMAN {d} {s}\n", .{ ADDRMAN_DAT_VERSION, hex });
        var it = self.map_info.valueIterator();
        while (it.next()) |info| {
            const tag: u8 = if (info.in_tried) 't' else 'n';
            try w.print("{c} {any} {d} {d} {d} {d} {d} {d} {d} {d}\n", .{
                tag,
                info.addr,
                info.services,
                info.addr_group,
                info.src_group,
                info.time_unix,
                info.last_success_unix,
                info.last_try_unix,
                info.attempts,
                info.ref_count,
            });
        }
        return buf.toOwnedSlice();
    }

    /// Atomic save to `<data_dir>/peers.dat` (temp + rename). Best-effort;
    /// failures are logged, never fatal.
    pub fn save(self: *const Self, data_dir: []const u8) void {
        const path = std.fs.path.join(self.allocator, &[_][]const u8{ data_dir, PEERS_DATABASE_FILENAME }) catch return;
        defer self.allocator.free(path);
        const tmp = std.fmt.allocPrint(self.allocator, "{s}.tmp", .{path}) catch return;
        defer self.allocator.free(tmp);

        const bytes = self.serialize(self.allocator) catch {
            std.log.warn("addrman: failed to serialize peers.dat", .{});
            return;
        };
        defer self.allocator.free(bytes);

        std.fs.cwd().makePath(data_dir) catch {};
        const f = std.fs.cwd().createFile(tmp, .{}) catch |e| {
            std.log.warn("addrman: failed to create {s}: {}", .{ tmp, e });
            return;
        };
        {
            defer f.close();
            f.writeAll(bytes) catch |e| {
                std.log.warn("addrman: failed to write {s}: {}", .{ tmp, e });
                std.fs.cwd().deleteFile(tmp) catch {};
                return;
            };
        }
        std.fs.cwd().rename(tmp, path) catch |e| {
            std.log.warn("addrman: failed to rename {s} -> {s}: {}", .{ tmp, path, e });
            std.fs.cwd().deleteFile(tmp) catch {};
        };
    }

    /// Load from `<data_dir>/peers.dat`, re-bucketing via add()/good() so
    /// placement is recomputed from the persisted nkey. Corrupt / truncated /
    /// wrong-version / missing files yield a graceful empty cold start (never a
    /// panic, never a hard-down). Bounded by ADDRMAN_CEILING.
    pub fn load(allocator: Allocator, data_dir: []const u8) !Self {
        const path = std.fs.path.join(allocator, &[_][]const u8{ data_dir, PEERS_DATABASE_FILENAME }) catch return init(allocator);
        defer allocator.free(path);
        const contents = std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024) catch {
            return init(allocator);
        };
        defer allocator.free(contents);
        if (try parse(allocator, contents)) |t| return t;
        std.log.warn("addrman: peers.dat at {s} corrupt or unsupported; starting cold", .{path});
        return init(allocator);
    }

    /// Parse the serialized form. Returns null on any structural problem so the
    /// caller can cold-start. Separated from `load` for in-process tests.
    pub fn parse(allocator: Allocator, contents: []const u8) !?Self {
        var lines = std.mem.splitScalar(u8, contents, '\n');
        const header = lines.next() orelse return null;
        var hp = std.mem.tokenizeScalar(u8, header, ' ');
        const magic = hp.next() orelse return null;
        if (!std.mem.eql(u8, magic, "ADDRMAN")) return null;
        const version = std.fmt.parseInt(u32, hp.next() orelse return null, 10) catch return null;
        if (version != ADDRMAN_DAT_VERSION) return null;
        const nkey_hex = hp.next() orelse return null;
        if (nkey_hex.len != 64) return null;
        var nkey: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&nkey, nkey_hex) catch return null;

        var table = try initWithNKey(allocator, nkey);
        errdefer table.deinit();

        const now = nowUnixSecs();
        // Collect tried addrs to promote after all NEW placements.
        var tried_addrs = std.ArrayList(SocketAddr).init(allocator);
        defer tried_addrs.deinit();

        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            if (table.map_info.count() >= ADDRMAN_CEILING) break;
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const tag = f.next() orelse return parseFail(&table);
            // The address token may contain spaces in std.net.Address formatting
            // is not the case (it prints as "ip:port"); take the next token.
            const addr_tok = f.next() orelse return parseFail(&table);
            const addr = parseSockAddr(addr_tok) orelse continue;
            const services = std.fmt.parseInt(u64, f.next() orelse return parseFail(&table), 10) catch return parseFail(&table);
            const addr_group = std.fmt.parseInt(u32, f.next() orelse return parseFail(&table), 10) catch return parseFail(&table);
            const src_group = std.fmt.parseInt(u32, f.next() orelse return parseFail(&table), 10) catch return parseFail(&table);
            const time_unix = std.fmt.parseInt(u64, f.next() orelse return parseFail(&table), 10) catch return parseFail(&table);
            const last_success = std.fmt.parseInt(u64, f.next() orelse return parseFail(&table), 10) catch return parseFail(&table);
            const last_try = std.fmt.parseInt(u64, f.next() orelse return parseFail(&table), 10) catch return parseFail(&table);
            const attempts = std.fmt.parseInt(u32, f.next() orelse return parseFail(&table), 10) catch return parseFail(&table);
            // ref_count optional/ignored (recomputed on placement).

            _ = try table.add(addr, addr_group, src_group, services, time_unix, now);
            // Restore the attempt/success bookkeeping that add() does not carry.
            if (table.find(addr)) |id| {
                if (table.map_info.getPtr(id)) |info| {
                    info.last_success_unix = last_success;
                    info.last_try_unix = last_try;
                    info.attempts = attempts;
                }
            }
            if (std.mem.eql(u8, tag, "t")) try tried_addrs.append(addr);
        }
        for (tried_addrs.items) |a| {
            _ = try table.good(a, now);
        }
        return table;
    }

    fn parseFail(table: *Self) ?Self {
        table.deinit();
        return null;
    }

    /// nkey accessor (test/persistence helper).
    pub fn getNKey(self: *const Self) [32]u8 {
        return self.nkey;
    }
};

// ============================================================================
// Small helpers
// ============================================================================

fn nowUnixSecs() u64 {
    const t = std.time.timestamp();
    return if (t < 0) 0 else @intCast(t);
}

/// Parse "ip:port" (IPv4) or "[ip]:port" (IPv6) into a std.net.Address. Returns
/// null on any malformed input. Matches std.net.Address's own Display format.
fn parseSockAddr(tok: []const u8) ?SocketAddr {
    // IPv6 bracketed form: [addr]:port
    if (tok.len > 0 and tok[0] == '[') {
        const close = std.mem.indexOfScalar(u8, tok, ']') orelse return null;
        const ip = tok[1..close];
        if (close + 2 > tok.len or tok[close + 1] != ':') return null;
        const port = std.fmt.parseInt(u16, tok[close + 2 ..], 10) catch return null;
        return std.net.Address.parseIp6(ip, port) catch return null;
    }
    // IPv4 form: a.b.c.d:port
    const colon = std.mem.lastIndexOfScalar(u8, tok, ':') orelse return null;
    const ip = tok[0..colon];
    const port = std.fmt.parseInt(u16, tok[colon + 1 ..], 10) catch return null;
    return std.net.Address.parseIp4(ip, port) catch return null;
}
