//! Self-address advertisement: the local address table (Bitcoin Core parity).
//!
//! A listening node must tell the network where it can be reached, or nobody
//! ever dials it: peers learn addresses only from addr/addrv2 gossip, and the
//! only gossip source for OUR address is us. Core does this in three parts;
//! this file holds part 1, the rest live on `PeerManager` in peer.zig:
//!
//!  1. A table of local addresses (Core net.cpp mapLocalHost / AddLocal /
//!     SeenLocal). Entries come from `--externalip` (score LOCAL_MANUAL) and
//!     from discovery: an OUTBOUND peer's VERSION carries addr_recv, the
//!     address it sees us at. A discovered entry's score is the number of
//!     DISTINCT peer netgroups that confirmed it, so one peer (or one /16)
//!     cannot talk us into advertising an address; it must be confirmed by
//!     MIN_DISCOVERED_LOCAL_SCORE groups before it is used, and it ages out
//!     after DISCOVERED_LOCAL_ADDR_TTL_SECS without a fresh confirmation, so a
//!     changed public IP replaces the old one. Inbound peers only score an
//!     entry that already exists (Core SeenLocal).
//!  2. The per-peer choice of address (Core GetLocalAddrForPeer,
//!     net.cpp:240-268) — `PeerManager.localAddrForPeer`.
//!  3. The send (Core MaybeSendAddr, net_processing.cpp:5445-5479) —
//!     `PeerManager.maybeSendLocalAddr`.
//!
//! The table is fixed-size and allocation-free (no allocator, no frees, so no
//! double-free class under ReleaseFast), and mutex-guarded because the RPC
//! thread reads it (getnetworkinfo.localaddresses) while the P2P thread writes.
//! Callers are responsible for the routability checks (PeerManager.isRoutable)
//! — the table stores what it is given.
//!
//! Addresses are the 16-byte wire form (IPv4 as ::ffff:a.b.c.d), exactly as in
//! types.NetworkAddress, so VERSION addr_recv can be stored without conversion.

const std = @import("std");

/// Local address scores (Core net.h enum LOCAL_NONE..LOCAL_MANUAL).
pub const LOCAL_NONE: u32 = 0;
pub const LOCAL_MANUAL: u32 = 4;

/// Mean of the exponential delay between self-announcements to one peer
/// (Core net_processing.cpp AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24h).
pub const AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL_SECS: f64 = 24.0 * 60.0 * 60.0;

/// A discovered (non-manual) entry not confirmed by any peer for this long is
/// dropped. Outbound churn re-confirms a stable address many times per hour,
/// so this only bites after the public IP changes.
pub const DISCOVERED_LOCAL_ADDR_TTL_SECS: i64 = 3 * 60 * 60;

/// How many distinct peer netgroups must confirm a discovered address before
/// it is advertised to OTHER peers.
pub const MIN_DISCOVERED_LOCAL_SCORE: u32 = 2;

/// Cap on discovered entries so peers cannot grow the table; the weakest
/// (lowest score, then oldest) entry is evicted.
pub const MAX_DISCOVERED_LOCAL_ADDRS: usize = 8;

/// Cap on manual (--externalip) entries.
pub const MAX_MANUAL_LOCAL_ADDRS: usize = 8;

/// Cap on the per-entry confirmer set (score ceiling).
pub const MAX_LOCAL_ADDR_CONFIRMERS: usize = 64;

const MAX_ENTRIES: usize = MAX_DISCOVERED_LOCAL_ADDRS + MAX_MANUAL_LOCAL_ADDRS;

/// One row of getnetworkinfo.localaddresses.
pub const LocalAddress = struct {
    ip: [16]u8,
    port: u16,
    score: u32,
};

const Entry = struct {
    used: bool = false,
    ip: [16]u8 = [_]u8{0} ** 16,
    port: u16 = 0,
    manual: bool = false,
    confirmers: [MAX_LOCAL_ADDR_CONFIRMERS]u32 = undefined,
    n_confirmers: usize = 0,
    last_seen: i64 = 0,

    fn score(self: *const Entry) u32 {
        const base: u32 = if (self.manual) LOCAL_MANUAL else LOCAL_NONE;
        // n_confirmers <= MAX_LOCAL_ADDR_CONFIRMERS (64): cannot overflow u32.
        return base + @as(u32, @truncate(self.n_confirmers));
    }

    /// May this entry be advertised to arbitrary peers?
    fn usable(self: *const Entry) bool {
        return self.manual or self.n_confirmers >= MIN_DISCOVERED_LOCAL_SCORE;
    }

    fn hasConfirmer(self: *const Entry, group: u32) bool {
        for (self.confirmers[0..self.n_confirmers]) |g| {
            if (g == group) return true;
        }
        return false;
    }
};

/// True when `ip` is an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
pub fn isIpv4Mapped(ip: *const [16]u8) bool {
    for (ip[0..10]) |b| if (b != 0) return false;
    return ip[10] == 0xff and ip[11] == 0xff;
}

/// Convert a 16-byte wire address to a std.net.Address (so the node's own
/// PeerManager.isRoutable check can be reused on it).
pub fn toStdAddress(ip: *const [16]u8, port: u16) std.net.Address {
    if (isIpv4Mapped(ip)) {
        return std.net.Address.initIp4(ip[12..16].*, port);
    }
    return std.net.Address.initIp6(ip.*, port, 0, 0);
}

/// Convert a std.net.Address to the 16-byte wire form. Null for non-IP.
pub fn fromStdAddress(address: std.net.Address) ?[16]u8 {
    var out = [_]u8{0} ** 16;
    switch (address.any.family) {
        std.posix.AF.INET => {
            const b: *const [4]u8 = @ptrCast(&address.in.sa.addr);
            out[10] = 0xff;
            out[11] = 0xff;
            @memcpy(out[12..16], b);
            return out;
        },
        std.posix.AF.INET6 => return address.in6.sa.addr,
        else => return null,
    }
}

/// Format the IP part of a wire address the way Core's CNetAddr::ToStringAddr
/// does: dotted quad for IPv4, RFC 5952 compressed hex for IPv6.
pub fn formatIp(ip: *const [16]u8, buf: []u8) []const u8 {
    if (isIpv4Mapped(ip)) {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[12], ip[13], ip[14], ip[15] }) catch buf[0..0];
    }
    var groups: [8]u16 = undefined;
    for (0..8) |i| groups[i] = (@as(u16, ip[2 * i]) << 8) | ip[2 * i + 1];
    // Longest run of >= 2 zero groups (first one on ties) collapses to "::".
    var best_start: usize = 8;
    var best_len: usize = 0;
    var i: usize = 0;
    while (i < 8) {
        if (groups[i] != 0) {
            i += 1;
            continue;
        }
        var j = i;
        while (j < 8 and groups[j] == 0) j += 1;
        if (j - i > best_len) {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    if (best_len < 2) best_start = 8;
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    var k: usize = 0;
    while (k < 8) {
        if (k == best_start) {
            w.writeAll("::") catch return buf[0..0];
            k += best_len;
            continue;
        }
        if (k != 0 and k != best_start + best_len) w.writeByte(':') catch return buf[0..0];
        w.print("{x}", .{groups[k]}) catch return buf[0..0];
        k += 1;
    }
    return fbs.getWritten();
}

/// The node's set of known local addresses (Core mapLocalHost). Keyed by IP
/// only, like Core (map<CNetAddr, LocalServiceInfo>).
pub const LocalAddrTable = struct {
    mutex: std.Thread.Mutex = .{},
    entries: [MAX_ENTRIES]Entry = [_]Entry{.{}} ** MAX_ENTRIES,

    fn findLocked(self: *LocalAddrTable, ip: *const [16]u8) ?*Entry {
        for (&self.entries) |*e| {
            if (e.used and std.mem.eql(u8, &e.ip, ip)) return e;
        }
        return null;
    }

    fn countLocked(self: *const LocalAddrTable, manual: bool) usize {
        var n: usize = 0;
        for (&self.entries) |*e| {
            if (e.used and e.manual == manual) n += 1;
        }
        return n;
    }

    fn freeSlotLocked(self: *LocalAddrTable) ?*Entry {
        for (&self.entries) |*e| {
            if (!e.used) return e;
        }
        return null;
    }

    fn expireLocked(self: *LocalAddrTable, now: i64) void {
        for (&self.entries) |*e| {
            if (e.used and !e.manual and now - e.last_seen > DISCOVERED_LOCAL_ADDR_TTL_SECS) {
                e.* = .{};
            }
        }
    }

    /// Evict the weakest (lowest score, then oldest) discovered entry when the
    /// discovered set is full.
    fn makeRoomLocked(self: *LocalAddrTable) void {
        if (self.countLocked(false) < MAX_DISCOVERED_LOCAL_ADDRS) return;
        var worst: ?*Entry = null;
        for (&self.entries) |*e| {
            if (!e.used or e.manual) continue;
            if (worst) |w| {
                if (e.score() < w.score() or (e.score() == w.score() and e.last_seen < w.last_seen)) worst = e;
            } else worst = e;
        }
        if (worst) |w| w.* = .{};
    }

    /// Record an operator-specified address (--externalip) at LOCAL_MANUAL.
    /// The caller has already checked routability. Returns false only when
    /// the manual set is full.
    pub fn addManual(self: *LocalAddrTable, ip: [16]u8, port: u16) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.findLocked(&ip)) |e| {
            if (!e.manual and self.countLocked(true) >= MAX_MANUAL_LOCAL_ADDRS) return false;
            e.manual = true;
            e.port = port;
            return true;
        }
        if (self.countLocked(true) >= MAX_MANUAL_LOCAL_ADDRS) return false;
        const slot = self.freeSlotLocked() orelse return false;
        slot.* = .{ .used = true, .ip = ip, .port = port, .manual = true, .n_confirmers = 0, .last_seen = 0 };
        return true;
    }

    /// Record that a peer in netgroup `group` sees us at `ip`. With
    /// `create = false` (inbound peers, Core SeenLocal) only an existing entry
    /// is scored; with `create = true` (outbound addr_recv discovery) a new
    /// entry is created with `port` (our listen port). The caller has already
    /// checked that both ends are routable. Returns true when an entry was
    /// created or scored.
    pub fn confirm(self: *LocalAddrTable, ip: [16]u8, port: u16, group: u32, create: bool, now: i64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
        const e = self.findLocked(&ip) orelse blk: {
            if (!create) return false;
            self.makeRoomLocked();
            const slot = self.freeSlotLocked() orelse return false;
            slot.* = .{ .used = true, .ip = ip, .port = port, .manual = false, .n_confirmers = 0, .last_seen = now };
            break :blk slot;
        };
        if (!e.hasConfirmer(group) and e.n_confirmers < MAX_LOCAL_ADDR_CONFIRMERS) {
            e.confirmers[e.n_confirmers] = group;
            e.n_confirmers += 1;
        }
        e.last_seen = now;
        return true;
    }

    /// Best usable local address (Core GetLocal): same address family as the
    /// peer first (`peer_is_ipv4 == null` = no preference), then the highest
    /// score, then the most recently confirmed.
    pub fn best(self: *LocalAddrTable, peer_is_ipv4: ?bool, now: i64) ?LocalAddress {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
        var b: ?*const Entry = null;
        for (&self.entries) |*e| {
            if (!e.used or !e.usable()) continue;
            if (b) |cur| {
                const re = reach(e, peer_is_ipv4);
                const rc = reach(cur, peer_is_ipv4);
                if (re > rc or (re == rc and (e.score() > cur.score() or
                    (e.score() == cur.score() and e.last_seen > cur.last_seen))))
                {
                    b = e;
                }
            } else b = e;
        }
        const w = b orelse return null;
        return .{ .ip = w.ip, .port = w.port, .score = w.score() };
    }

    fn reach(e: *const Entry, peer_is_ipv4: ?bool) u8 {
        const v4 = peer_is_ipv4 orelse return 0;
        return if (isIpv4Mapped(&e.ip) == v4) 1 else 0;
    }

    /// Copy every entry into `out`, highest score first (getnetworkinfo).
    /// Returns the number written (at most out.len).
    pub fn list(self: *LocalAddrTable, out: []LocalAddress, now: i64) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
        var n: usize = 0;
        for (&self.entries) |*e| {
            if (!e.used) continue;
            if (n >= out.len) break;
            out[n] = .{ .ip = e.ip, .port = e.port, .score = e.score() };
            n += 1;
        }
        std.mem.sort(LocalAddress, out[0..n], {}, struct {
            fn lt(_: void, a: LocalAddress, b: LocalAddress) bool {
                if (a.score != b.score) return a.score > b.score;
                return std.mem.order(u8, &a.ip, &b.ip) == .lt;
            }
        }.lt);
        return n;
    }

    pub const MAX_LIST: usize = MAX_ENTRIES;
};

/// Draw the Poisson inter-announcement delay in seconds (Core
/// rand_exp_duration(AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL)). `u` in [0,1).
/// Clamped to [1s, 30d] before the float->int conversion so it can never trap.
pub fn nextLocalAddrDelaySecs(u: f64) i64 {
    const one_minus = 1.0 - u;
    if (!(one_minus > 0.0)) return 30 * 24 * 60 * 60;
    const d = -@log(one_minus) * AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL_SECS;
    const clamped = std.math.clamp(d, 1.0, 30.0 * 24.0 * 60.0 * 60.0);
    return @intFromFloat(clamped);
}

/// Parse one `--externalip` value: "<ipv4>", "<ipv4>:<port>", "<ipv6>",
/// "[<ipv6>]" or "[<ipv6>]:<port>". Port 0 in the result means "use the
/// listen port". Null on malformed input (including an explicit port 0).
pub fn parseExternalIp(raw: []const u8) ?struct { ip: [16]u8, port: u16 } {
    const v = std.mem.trim(u8, raw, " \t");
    if (v.len == 0) return null;
    var host: []const u8 = v;
    var port: u16 = 0;
    if (v[0] == '[') {
        const close = std.mem.indexOfScalar(u8, v, ']') orelse return null;
        host = v[1..close];
        const rest = v[close + 1 ..];
        if (rest.len > 0) {
            if (rest[0] != ':' or rest.len < 2) return null;
            port = std.fmt.parseInt(u16, rest[1..], 10) catch return null;
            if (port == 0) return null;
        }
    } else if (std.mem.count(u8, v, ":") == 1) {
        const colon = std.mem.indexOfScalar(u8, v, ':').?;
        host = v[0..colon];
        port = std.fmt.parseInt(u16, v[colon + 1 ..], 10) catch return null;
        if (port == 0) return null;
    }
    const addr = std.net.Address.parseIp(host, 0) catch return null;
    return .{ .ip = fromStdAddress(addr) orelse return null, .port = port };
}

// ============================================================================
// Tests (pure table logic; the PeerManager wiring is tested in
// tests_selfadv.zig)
// ============================================================================

fn testV4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    var out = [_]u8{0} ** 16;
    out[10] = 0xff;
    out[11] = 0xff;
    out[12] = a;
    out[13] = b;
    out[14] = c;
    out[15] = d;
    return out;
}

test "tests_selfadv localaddr: discovered entry needs 2 distinct netgroups to be usable" {
    var t = LocalAddrTable{};
    const ip = testV4(1, 2, 3, 4);
    try std.testing.expect(t.confirm(ip, 8333, 0x0101, true, 1000));
    try std.testing.expect(t.best(null, 1000) == null);
    // Same netgroup again: still one confirmer.
    try std.testing.expect(t.confirm(ip, 8333, 0x0101, true, 1001));
    try std.testing.expect(t.best(null, 1001) == null);
    try std.testing.expect(t.confirm(ip, 8333, 0x0202, true, 1002));
    const b = t.best(null, 1002).?;
    try std.testing.expectEqual(@as(u16, 8333), b.port);
    try std.testing.expectEqual(@as(u32, 2), b.score);
}

test "tests_selfadv localaddr: inbound (create=false) only scores an existing entry" {
    var t = LocalAddrTable{};
    try std.testing.expect(!t.confirm(testV4(1, 2, 3, 4), 8333, 1, false, 10));
    var out: [LocalAddrTable.MAX_LIST]LocalAddress = undefined;
    try std.testing.expectEqual(@as(usize, 0), t.list(&out, 10));
}

test "tests_selfadv localaddr: discovered entry expires after TTL, manual does not" {
    var t = LocalAddrTable{};
    _ = t.confirm(testV4(1, 2, 3, 4), 8333, 1, true, 0);
    try std.testing.expect(t.addManual(testV4(5, 6, 7, 8), 8456));
    var out: [LocalAddrTable.MAX_LIST]LocalAddress = undefined;
    try std.testing.expectEqual(@as(usize, 2), t.list(&out, DISCOVERED_LOCAL_ADDR_TTL_SECS));
    try std.testing.expectEqual(@as(usize, 1), t.list(&out, DISCOVERED_LOCAL_ADDR_TTL_SECS + 1));
    try std.testing.expectEqual(@as(u32, LOCAL_MANUAL), out[0].score);
}

test "tests_selfadv localaddr: discovered set capped at 8" {
    var t = LocalAddrTable{};
    var i: u8 = 0;
    while (i < 20) : (i += 1) _ = t.confirm(testV4(1, 2, 3, i), 8333, i, true, @as(i64, i));
    var out: [LocalAddrTable.MAX_LIST]LocalAddress = undefined;
    try std.testing.expectEqual(MAX_DISCOVERED_LOCAL_ADDRS, t.list(&out, 20));
}

test "tests_selfadv localaddr: best prefers the peer's address family" {
    var t = LocalAddrTable{};
    try std.testing.expect(t.addManual(testV4(1, 2, 3, 4), 8333));
    var ip6 = [_]u8{0} ** 16;
    ip6[0] = 0x20;
    ip6[1] = 0x01;
    ip6[2] = 0x04;
    ip6[15] = 1;
    try std.testing.expect(t.addManual(ip6, 8333));
    try std.testing.expect(isIpv4Mapped(&t.best(true, 0).?.ip));
    try std.testing.expect(!isIpv4Mapped(&t.best(false, 0).?.ip));
}

test "tests_selfadv localaddr: parseExternalIp forms" {
    const a = parseExternalIp("1.2.3.4").?;
    try std.testing.expectEqualSlices(u8, &testV4(1, 2, 3, 4), &a.ip);
    try std.testing.expectEqual(@as(u16, 0), a.port);
    const b = parseExternalIp("1.2.3.4:8456").?;
    try std.testing.expectEqual(@as(u16, 8456), b.port);
    const c = parseExternalIp("[2001:4::1]:9000").?;
    try std.testing.expectEqual(@as(u16, 9000), c.port);
    try std.testing.expectEqual(@as(u8, 0x20), c.ip[0]);
    const d = parseExternalIp("2001:4::1").?;
    try std.testing.expectEqual(@as(u16, 0), d.port);
    try std.testing.expect(parseExternalIp("1.2.3.4:0") == null);
    try std.testing.expect(parseExternalIp("1.2.3.4:99999") == null);
    try std.testing.expect(parseExternalIp("not-an-ip") == null);
    try std.testing.expect(parseExternalIp("") == null);
}

test "tests_selfadv localaddr: formatIp v4 and compressed v6" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("1.2.3.4", formatIp(&testV4(1, 2, 3, 4), &buf));
    const d = parseExternalIp("2001:4::1").?;
    try std.testing.expectEqualStrings("2001:4::1", formatIp(&d.ip, &buf));
    const e = parseExternalIp("2001:4:0:1:0:0:0:1").?;
    try std.testing.expectEqualStrings("2001:4:0:1::1", formatIp(&e.ip, &buf));
}

test "tests_selfadv localaddr: Poisson delay is clamped and finite" {
    try std.testing.expectEqual(@as(i64, 1), nextLocalAddrDelaySecs(0.0));
    try std.testing.expectEqual(@as(i64, 30 * 24 * 60 * 60), nextLocalAddrDelaySecs(1.0));
    const mid = nextLocalAddrDelaySecs(1.0 - std.math.exp(-1.0)); // -ln(e^-1) = 1 mean
    try std.testing.expect(mid > 86_000 and mid < 86_800);
}
