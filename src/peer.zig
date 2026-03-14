const std = @import("std");
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const banlist = @import("banlist.zig");

// ============================================================================
// Peer Manager Constants
// ============================================================================

/// Maximum number of outbound connections (8 full-relay as per Bitcoin Core).
pub const MAX_OUTBOUND_CONNECTIONS: usize = 8;

/// Maximum number of inbound connections.
pub const MAX_INBOUND_CONNECTIONS: usize = 117;

/// Maximum total connections (125 as per Bitcoin Core).
pub const MAX_TOTAL_CONNECTIONS: usize = MAX_OUTBOUND_CONNECTIONS + MAX_INBOUND_CONNECTIONS;

/// Peer rotation interval in seconds (30 minutes).
pub const PEER_ROTATION_INTERVAL: i64 = 30 * 60;

/// DNS seed resolution timeout in seconds.
pub const DNS_SEED_TIMEOUT: u32 = 10;

/// Default ban duration in seconds (24 hours).
pub const DEFAULT_BAN_DURATION: i64 = 24 * 60 * 60;

/// Minimum time between connection attempts to the same address (10 minutes).
pub const MIN_RECONNECT_INTERVAL: i64 = 10 * 60;

/// Ping interval for idle peers (2 minutes).
pub const PING_INTERVAL: i64 = 2 * 60;

/// Maximum number of block-relay-only anchor connections.
pub const MAX_BLOCK_RELAY_ONLY_ANCHORS: usize = 2;

/// Maximum number of block-relay-only connections.
pub const MAX_BLOCK_RELAY_ONLY_CONNECTIONS: usize = 2;

/// Hardcoded fallback peers for testnet4 (DNS seeds unreliable).
pub const TESTNET_FALLBACK_PEERS: []const []const u8 = &[_][]const u8{
    "127.0.0.1", // Placeholder - would be real testnet4 peers
};

// ============================================================================
// Eclipse Attack Protection Constants
// ============================================================================

/// Number of peers to protect by fastest ping time.
pub const EVICTION_PROTECT_PING: usize = 4;

/// Number of peers to protect by most recent transaction relay.
pub const EVICTION_PROTECT_TX: usize = 4;

/// Number of peers to protect by most recent block relay.
pub const EVICTION_PROTECT_BLOCK: usize = 4;

/// Number of peers to protect by longest connection time.
pub const EVICTION_PROTECT_TIME: usize = 8;

/// Number of peers to protect by distinct netgroups.
pub const EVICTION_PROTECT_NETGROUP: usize = 4;

// ============================================================================
// Network Group Functions (Eclipse Attack Protection)
// ============================================================================

/// Compute network group for an address.
/// For IPv4: returns /16 subnet identifier (first 2 octets).
/// For IPv6: returns /32 identifier (first 4 bytes).
/// This is used to ensure outbound connection diversity.
pub fn netGroup(address: std.net.Address) u32 {
    switch (address.any.family) {
        std.posix.AF.INET => {
            // IPv4: use /16 prefix (first 2 octets)
            const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
            const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
            return (@as(u32, ip_bytes[0]) << 8) | @as(u32, ip_bytes[1]);
        },
        std.posix.AF.INET6 => {
            // IPv6: use /32 prefix (first 4 bytes)
            const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address.any)));
            return (@as(u32, ip6.addr[0]) << 24) |
                (@as(u32, ip6.addr[1]) << 16) |
                (@as(u32, ip6.addr[2]) << 8) |
                @as(u32, ip6.addr[3]);
        },
        else => return 0,
    }
}

/// Check if two addresses are in the same network group.
pub fn sameNetGroup(addr1: std.net.Address, addr2: std.net.Address) bool {
    return netGroup(addr1) == netGroup(addr2);
}

// ============================================================================
// Peer State Machine
// ============================================================================

pub const PeerState = enum {
    connecting,
    connected,
    version_sent,
    version_received,
    handshake_complete,
    disconnecting,
    disconnected,
};

pub const PeerDirection = enum {
    inbound,
    outbound,
};

/// Connection type for more granular tracking (as per Bitcoin Core).
pub const ConnectionType = enum {
    /// Standard inbound connection.
    inbound,
    /// Full-relay outbound connection (8 slots).
    outbound_full_relay,
    /// Block-relay-only outbound connection (2 slots).
    block_relay,
    /// Manual connection (-addnode).
    manual,
    /// Feeler connection (short-lived address validation).
    feeler,
    /// Address fetch connection.
    addr_fetch,
};

// ============================================================================
// Peer Errors
// ============================================================================

pub const PeerError = error{
    ConnectionFailed,
    HandshakeFailed,
    Timeout,
    BadMagic,
    BadChecksum,
    MessageTooLarge,
    ProtocolViolation,
    ConnectionClosed,
    OutOfMemory,
};

// ============================================================================
// Peer Connection
// ============================================================================

/// Represents a single peer connection.
pub const Peer = struct {
    stream: std.net.Stream,
    address: std.net.Address,
    state: PeerState,
    direction: PeerDirection,
    version_info: ?p2p.VersionMessage,
    services: u64,
    last_ping_time: i64,
    last_pong_time: i64,
    last_ping_nonce: u64,
    last_message_time: i64,
    bytes_sent: u64,
    bytes_received: u64,
    start_height: i32,
    network_params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
    recv_buffer: std.ArrayList(u8),
    is_witness_capable: bool,
    is_headers_first: bool,
    ban_score: u32,
    should_ban: bool,
    /// Connection type for eclipse protection.
    conn_type: ConnectionType,
    /// Time of last block received from this peer.
    last_block_time: i64,
    /// Time of last transaction received from this peer.
    last_tx_time: i64,
    /// Minimum ping time observed (in seconds).
    min_ping_time: i64,
    /// Whether this peer relays transactions.
    relay_txs: bool,
    /// Whether this is a protected peer (cannot be evicted).
    is_protected: bool,
    /// Time when connection was established.
    connect_time: i64,

    /// Connect to a remote peer.
    pub fn connect(
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) PeerError!Peer {
        const stream = std.net.tcpConnectToAddress(address) catch
            return PeerError.ConnectionFailed;

        // Set socket options for timeouts (30 seconds)
        const timeout = std.posix.timeval{ .sec = 30, .usec = 0 };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.SNDTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};

        const now = std.time.timestamp();
        return Peer{
            .stream = stream,
            .address = address,
            .state = .connecting,
            .direction = .outbound,
            .version_info = null,
            .services = 0,
            .last_ping_time = 0,
            .last_pong_time = 0,
            .last_ping_nonce = 0,
            .last_message_time = now,
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .is_witness_capable = false,
            .is_headers_first = false,
            .ban_score = 0,
            .should_ban = false,
            .conn_type = .outbound_full_relay,
            .last_block_time = 0,
            .last_tx_time = 0,
            .min_ping_time = std.math.maxInt(i64),
            .relay_txs = true,
            .is_protected = false,
            .connect_time = now,
        };
    }

    /// Accept an inbound connection.
    pub fn accept(
        stream: std.net.Stream,
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) Peer {
        const now = std.time.timestamp();
        return Peer{
            .stream = stream,
            .address = address,
            .state = .connected,
            .direction = .inbound,
            .version_info = null,
            .services = 0,
            .last_ping_time = 0,
            .last_pong_time = 0,
            .last_ping_nonce = 0,
            .last_message_time = now,
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .is_witness_capable = false,
            .is_headers_first = false,
            .ban_score = 0,
            .should_ban = false,
            .conn_type = .inbound,
            .last_block_time = 0,
            .last_tx_time = 0,
            .min_ping_time = std.math.maxInt(i64),
            .relay_txs = true,
            .is_protected = false,
            .connect_time = now,
        };
    }

    /// Send a P2P message over the connection.
    pub fn sendMessage(self: *Peer, msg: *const p2p.Message) PeerError!void {
        const data = p2p.encodeMessage(msg, self.network_params.magic, self.allocator) catch
            return PeerError.OutOfMemory;
        defer self.allocator.free(data);

        self.stream.writeAll(data) catch return PeerError.ConnectionClosed;
        self.bytes_sent += data.len;
        self.last_message_time = std.time.timestamp();
    }

    /// Receive the next P2P message from the connection.
    pub fn receiveMessage(self: *Peer) PeerError!p2p.Message {
        // Read header (24 bytes)
        var header_buf: [24]u8 = undefined;
        self.readExact(&header_buf) catch return PeerError.ConnectionClosed;

        const header = p2p.MessageHeader.decode(&header_buf);

        // Validate magic
        if (header.magic != self.network_params.magic)
            return PeerError.BadMagic;

        // Validate payload size
        if (header.length > p2p.MAX_MESSAGE_SIZE)
            return PeerError.MessageTooLarge;

        // Read payload
        const payload = self.allocator.alloc(u8, header.length) catch
            return PeerError.OutOfMemory;
        defer self.allocator.free(payload);

        if (header.length > 0) {
            self.readExact(payload) catch return PeerError.ConnectionClosed;
        }

        // Verify checksum
        const computed_hash = crypto.hash256(payload);
        if (!std.mem.eql(u8, &header.checksum, computed_hash[0..4]))
            return PeerError.BadChecksum;

        self.bytes_received += 24 + header.length;
        self.last_message_time = std.time.timestamp();

        // Parse payload
        const command = header.commandName();
        return p2p.decodePayload(command, payload, self.allocator) catch
            return PeerError.ProtocolViolation;
    }

    /// Perform the version/verack handshake.
    /// Outbound: send version, wait for version+verack, send verack.
    /// Inbound: wait for version, send version+verack, wait for verack.
    pub fn performHandshake(self: *Peer, our_height: i32) PeerError!void {
        const now = std.time.timestamp();

        if (self.direction == .outbound) {
            // Send our version
            const version_msg = p2p.Message{ .version = p2p.VersionMessage{
                .version = p2p.PROTOCOL_VERSION,
                .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
                .timestamp = now,
                .addr_recv = types.NetworkAddress{
                    .services = 0,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .addr_from = types.NetworkAddress{
                    .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .nonce = std.crypto.random.int(u64),
                .user_agent = p2p.USER_AGENT,
                .start_height = our_height,
                .relay = true,
            } };
            try self.sendMessage(&version_msg);
            self.state = .version_sent;

            // Wait for their version
            const their_version = try self.receiveMessage();
            switch (their_version) {
                .version => |v| {
                    if (v.version < p2p.MIN_PROTOCOL_VERSION)
                        return PeerError.HandshakeFailed;
                    self.version_info = v;
                    self.services = v.services;
                    self.start_height = v.start_height;
                    self.is_witness_capable = (v.services & p2p.NODE_WITNESS) != 0;
                },
                else => return PeerError.HandshakeFailed,
            }

            // Send verack
            const verack = p2p.Message{ .verack = {} };
            try self.sendMessage(&verack);

            // Send wtxidrelay (BIP-339) before verack is received
            const wtxid = p2p.Message{ .wtxidrelay = {} };
            try self.sendMessage(&wtxid);

            // Send sendaddrv2 (BIP-155)
            const addrv2 = p2p.Message{ .sendaddrv2 = {} };
            try self.sendMessage(&addrv2);

            // Wait for their verack
            while (true) {
                const msg = try self.receiveMessage();
                switch (msg) {
                    .verack => break,
                    .wtxidrelay, .sendaddrv2, .sendcmpct, .sendheaders, .feefilter => {
                        // Accept these during handshake but no action needed
                    },
                    .ping => |ping| {
                        // Handle ping during handshake
                        const pong = p2p.Message{ .pong = ping };
                        try self.sendMessage(&pong);
                    },
                    else => {},
                }
            }
        } else {
            // Inbound: wait for version first
            const their_version = try self.receiveMessage();
            switch (their_version) {
                .version => |v| {
                    if (v.version < p2p.MIN_PROTOCOL_VERSION)
                        return PeerError.HandshakeFailed;
                    self.version_info = v;
                    self.services = v.services;
                    self.start_height = v.start_height;
                    self.is_witness_capable = (v.services & p2p.NODE_WITNESS) != 0;
                },
                else => return PeerError.HandshakeFailed,
            }

            // Send our version
            const version_msg = p2p.Message{ .version = p2p.VersionMessage{
                .version = p2p.PROTOCOL_VERSION,
                .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
                .timestamp = now,
                .addr_recv = types.NetworkAddress{
                    .services = self.services,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .addr_from = types.NetworkAddress{
                    .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .nonce = std.crypto.random.int(u64),
                .user_agent = p2p.USER_AGENT,
                .start_height = our_height,
                .relay = true,
            } };
            try self.sendMessage(&version_msg);

            // Send verack
            const verack = p2p.Message{ .verack = {} };
            try self.sendMessage(&verack);

            // Wait for their verack
            while (true) {
                const msg = try self.receiveMessage();
                switch (msg) {
                    .verack => break,
                    else => {},
                }
            }
        }

        self.state = .handshake_complete;

        // Send sendheaders (BIP-130) - request headers announcements
        const sh = p2p.Message{ .sendheaders = {} };
        try self.sendMessage(&sh);
    }

    /// Send a ping and record the nonce.
    pub fn sendPing(self: *Peer) PeerError!void {
        self.last_ping_nonce = std.crypto.random.int(u64);
        self.last_ping_time = std.time.timestamp();
        const msg = p2p.Message{ .ping = .{ .nonce = self.last_ping_nonce } };
        try self.sendMessage(&msg);
    }

    /// Handle an incoming pong message.
    pub fn handlePong(self: *Peer, nonce: u64) void {
        if (nonce == self.last_ping_nonce) {
            self.last_pong_time = std.time.timestamp();
            // Update minimum ping time for eviction scoring
            const latency = self.last_pong_time - self.last_ping_time;
            if (latency >= 0 and latency < self.min_ping_time) {
                self.min_ping_time = latency;
            }
        }
    }

    /// Disconnect from the peer.
    pub fn disconnect(self: *Peer) void {
        self.state = .disconnected;
        self.stream.close();
        self.recv_buffer.deinit();
    }

    /// Read exactly n bytes from the stream.
    fn readExact(self: *Peer, buf: []u8) !void {
        var total: usize = 0;
        while (total < buf.len) {
            const n = self.stream.read(buf[total..]) catch return error.ConnectionClosed;
            if (n == 0) return error.ConnectionClosed;
            total += n;
        }
    }

    /// Check if the peer has timed out (no messages for 20 minutes, no pong for 5 minutes).
    pub fn isTimedOut(self: *const Peer) bool {
        const now = std.time.timestamp();
        // No message in 20 minutes
        if (now - self.last_message_time > 20 * 60) return true;
        // Ping sent but no pong in 5 minutes
        if (self.last_ping_time > 0 and self.last_pong_time < self.last_ping_time and
            now - self.last_ping_time > 5 * 60) return true;
        return false;
    }

    /// Add to ban score; return true if peer should be banned (score >= 100).
    pub fn addBanScore(self: *Peer, score: u32) bool {
        self.ban_score += score;
        if (self.ban_score >= 100) {
            self.should_ban = true;
            return true;
        }
        return false;
    }

    /// Record misbehavior with a reason. Adds to ban score and logs. If score >= 100, marks for ban.
    pub fn misbehaving(self: *Peer, howmuch: u32, message: []const u8) void {
        self.ban_score += howmuch;
        if (self.ban_score >= 100) {
            self.should_ban = true;
            var addr_buf: [64]u8 = undefined;
            const addr_str = self.getAddressString(&addr_buf);
            std.log.warn("Misbehaving: peer={s} score={d}: {s}", .{ addr_str, self.ban_score, message });
        } else {
            var addr_buf: [64]u8 = undefined;
            const addr_str = self.getAddressString(&addr_buf);
            std.log.info("Misbehaving: peer={s} score={d}: {s}", .{ addr_str, self.ban_score, message });
        }
    }

    /// Get the latency in milliseconds based on last ping/pong.
    pub fn getLatencyMs(self: *const Peer) ?i64 {
        if (self.last_pong_time > 0 and self.last_ping_time > 0 and
            self.last_pong_time >= self.last_ping_time)
        {
            return (self.last_pong_time - self.last_ping_time) * 1000;
        }
        return null;
    }

    /// Check if the peer is fully connected and ready.
    pub fn isReady(self: *const Peer) bool {
        return self.state == .handshake_complete;
    }

    /// Get a human-readable address string.
    pub fn getAddressString(self: *const Peer, buf: []u8) []const u8 {
        const formatted = std.fmt.bufPrint(buf, "{}", .{self.address}) catch return "unknown";
        return formatted;
    }
};

// ============================================================================
// Eviction Candidate (Eclipse Attack Protection)
// ============================================================================

/// Candidate for inbound connection eviction.
/// Contains all the metrics used to decide which peer to evict.
pub const EvictionCandidate = struct {
    peer_index: usize,
    net_group: u32,
    min_ping_time: i64,
    last_block_time: i64,
    last_tx_time: i64,
    connect_time: i64,
    relay_txs: bool,
    is_protected: bool,
};

/// Build eviction candidate list from inbound peers.
pub fn buildEvictionCandidates(peers: []*Peer, allocator: std.mem.Allocator) ![]EvictionCandidate {
    var candidates = std.ArrayList(EvictionCandidate).init(allocator);
    errdefer candidates.deinit();

    for (peers, 0..) |peer, i| {
        // Only consider inbound connections for eviction
        if (peer.direction != .inbound) continue;
        // Skip protected peers
        if (peer.is_protected) continue;

        try candidates.append(.{
            .peer_index = i,
            .net_group = netGroup(peer.address),
            .min_ping_time = peer.min_ping_time,
            .last_block_time = peer.last_block_time,
            .last_tx_time = peer.last_tx_time,
            .connect_time = peer.connect_time,
            .relay_txs = peer.relay_txs,
            .is_protected = false,
        });
    }

    return candidates.toOwnedSlice();
}

/// Comparison function for sorting by min ping time (ascending - lower is better).
fn comparePingTime(a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.min_ping_time < b.min_ping_time;
}

/// Comparison function for sorting by last tx time (descending - more recent is better).
fn compareTxTime(a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.last_tx_time > b.last_tx_time;
}

/// Comparison function for sorting by last block time (descending - more recent is better).
fn compareBlockTime(a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.last_block_time > b.last_block_time;
}

/// Comparison function for sorting by connect time (ascending - longer connected is better).
fn compareConnectTime(a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.connect_time < b.connect_time;
}

/// Comparison function for sorting by netgroup.
fn compareNetGroup(a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.net_group < b.net_group;
}

/// Select an inbound peer to evict using Bitcoin Core's eviction algorithm.
/// Protects peers by category:
/// - 4 with fastest ping time
/// - 4 with most recent tx relay
/// - 4 with most recent block relay
/// - 8 longest-connected
/// - 4 from distinct netgroups
/// Returns the index of the peer to evict, or null if no eviction candidate.
pub fn selectEvictionCandidate(candidates: []EvictionCandidate, allocator: std.mem.Allocator) ?usize {
    if (candidates.len == 0) return null;

    // Make a mutable copy for protection marking
    var working = allocator.dupe(EvictionCandidate, candidates) catch return null;
    defer allocator.free(working);

    // Mark protected candidates
    var protected = std.AutoHashMap(usize, void).init(allocator);
    defer protected.deinit();

    // 1. Protect 4 peers with fastest ping time
    std.mem.sort(EvictionCandidate, working, {}, comparePingTime);
    for (0..@min(EVICTION_PROTECT_PING, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 2. Protect 4 peers with most recent tx relay
    std.mem.sort(EvictionCandidate, working, {}, compareTxTime);
    for (0..@min(EVICTION_PROTECT_TX, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 3. Protect 4 peers with most recent block relay
    std.mem.sort(EvictionCandidate, working, {}, compareBlockTime);
    for (0..@min(EVICTION_PROTECT_BLOCK, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 4. Protect 8 longest-connected peers
    std.mem.sort(EvictionCandidate, working, {}, compareConnectTime);
    for (0..@min(EVICTION_PROTECT_TIME, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 5. Protect 4 peers from distinct netgroups
    std.mem.sort(EvictionCandidate, working, {}, compareNetGroup);
    var seen_netgroups = std.AutoHashMap(u32, void).init(allocator);
    defer seen_netgroups.deinit();
    var netgroup_protected: usize = 0;
    for (working) |c| {
        if (netgroup_protected >= EVICTION_PROTECT_NETGROUP) break;
        if (!seen_netgroups.contains(c.net_group)) {
            seen_netgroups.put(c.net_group, {}) catch {};
            protected.put(c.peer_index, {}) catch {};
            netgroup_protected += 1;
        }
    }

    // Find unprotected candidates
    var unprotected = std.ArrayList(EvictionCandidate).init(allocator);
    defer unprotected.deinit();
    for (candidates) |c| {
        if (!protected.contains(c.peer_index)) {
            unprotected.append(c) catch {};
        }
    }

    if (unprotected.items.len == 0) return null;

    // Group by netgroup and find the netgroup with most connections
    var netgroup_counts = std.AutoHashMap(u32, usize).init(allocator);
    defer netgroup_counts.deinit();
    var netgroup_youngest = std.AutoHashMap(u32, EvictionCandidate).init(allocator);
    defer netgroup_youngest.deinit();

    for (unprotected.items) |c| {
        const count = netgroup_counts.get(c.net_group) orelse 0;
        netgroup_counts.put(c.net_group, count + 1) catch {};

        if (netgroup_youngest.get(c.net_group)) |existing| {
            // Keep the youngest (most recent connect_time)
            if (c.connect_time > existing.connect_time) {
                netgroup_youngest.put(c.net_group, c) catch {};
            }
        } else {
            netgroup_youngest.put(c.net_group, c) catch {};
        }
    }

    // Find netgroup with most connections
    var max_group: u32 = 0;
    var max_count: usize = 0;
    var max_youngest_time: i64 = 0;
    var iter = netgroup_counts.iterator();
    while (iter.next()) |entry| {
        const count = entry.value_ptr.*;
        const youngest = netgroup_youngest.get(entry.key_ptr.*) orelse continue;
        if (count > max_count or (count == max_count and youngest.connect_time > max_youngest_time)) {
            max_count = count;
            max_group = entry.key_ptr.*;
            max_youngest_time = youngest.connect_time;
        }
    }

    // Evict the youngest peer from the most-connected netgroup
    if (netgroup_youngest.get(max_group)) |victim| {
        return victim.peer_index;
    }

    return null;
}

// ============================================================================
// Address Info
// ============================================================================

/// Source of a peer address.
pub const AddressSource = enum {
    dns_seed,
    peer_addr,
    manual,
};

/// Tracked information about a known peer address.
pub const AddressInfo = struct {
    address: std.net.Address,
    services: u64,
    last_seen: i64,
    last_tried: i64,
    attempts: u32,
    success: bool,
    source: AddressSource,
};

// ============================================================================
// Peer Manager
// ============================================================================

/// Manages multiple peer connections with discovery and connection management.
pub const PeerManager = struct {
    peers: std.ArrayList(*Peer),
    known_addresses: std.AutoHashMap(u64, AddressInfo),
    ban_list: banlist.BanList,
    listener: ?std.net.Server,
    network_params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
    our_height: i32,
    running: std.atomic.Value(bool),
    last_rotation_time: i64,
    /// Set of netgroups for current outbound connections (for diversity).
    outbound_netgroups: std.AutoHashMap(u32, void),
    /// Path to anchor connections file.
    anchors_path: []const u8,
    /// Anchor addresses to connect on startup.
    anchor_addresses: std.ArrayList(std.net.Address),
    /// Data directory for persistence.
    data_dir: ?[]const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        params: *const consensus.NetworkParams,
    ) PeerManager {
        return .{
            .peers = std.ArrayList(*Peer).init(allocator),
            .known_addresses = std.AutoHashMap(u64, AddressInfo).init(allocator),
            .ban_list = banlist.BanList.init(allocator, "banlist.json"),
            .listener = null,
            .network_params = params,
            .allocator = allocator,
            .our_height = 0,
            .running = std.atomic.Value(bool).init(false),
            .last_rotation_time = 0,
            .outbound_netgroups = std.AutoHashMap(u32, void).init(allocator),
            .anchors_path = "anchors.dat",
            .anchor_addresses = std.ArrayList(std.net.Address).init(allocator),
            .data_dir = null,
        };
    }

    pub fn deinit(self: *PeerManager) void {
        // Save ban list and anchors before shutdown
        self.ban_list.save() catch {};
        self.saveAnchors() catch {};
        for (self.peers.items) |peer| {
            peer.disconnect();
            self.allocator.destroy(peer);
        }
        self.peers.deinit();
        self.known_addresses.deinit();
        self.ban_list.deinit();
        self.outbound_netgroups.deinit();
        self.anchor_addresses.deinit();
        if (self.listener) |*l| l.deinit();
    }

    /// Load ban list from disk.
    pub fn loadBanList(self: *PeerManager) !void {
        try self.ban_list.load();
    }

    /// Save ban list to disk.
    pub fn saveBanList(self: *PeerManager) !void {
        try self.ban_list.save();
    }

    /// Hash an address for use as a map key.
    pub fn addressKey(address: std.net.Address) u64 {
        // For IPv4, combine IP and port into a u64
        // For IPv6, use a simple hash
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                const ip_u32 = std.mem.readInt(u32, ip_bytes, .big);
                const port = std.mem.bigToNative(u16, ip4.port);
                return (@as(u64, ip_u32) << 16) | @as(u64, port);
            },
            std.posix.AF.INET6 => {
                const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address.any)));
                var hash: u64 = 0;
                for (ip6.addr, 0..) |b, i| {
                    hash ^= @as(u64, b) << @intCast((i % 8) * 8);
                }
                hash ^= @as(u64, std.mem.bigToNative(u16, ip6.port));
                return hash;
            },
            else => return 0,
        }
    }

    /// Extract IPv4 as u32 for ban tracking.
    pub fn ipv4AsU32(address: std.net.Address) ?u32 {
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                return std.mem.readInt(u32, ip_bytes, .big);
            },
            else => return null,
        }
    }

    /// Extract IPv4 bytes for ban tracking.
    pub fn ipv4AsBytes(address: std.net.Address) ?[4]u8 {
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                return ip_bytes.*;
            },
            else => return null,
        }
    }

    /// Perform DNS seed resolution to discover initial peers.
    pub fn dnsSeeds(self: *PeerManager) !void {
        for (self.network_params.dns_seeds) |seed| {
            // Resolve DNS seed to list of addresses
            const addrs = std.net.getAddressList(self.allocator, seed, self.network_params.default_port) catch continue;
            defer addrs.deinit();

            for (addrs.addrs) |addr| {
                self.addAddress(addr, 0, .dns_seed) catch continue;
            }
        }
    }

    /// Add a known address.
    pub fn addAddress(
        self: *PeerManager,
        address: std.net.Address,
        services: u64,
        source: AddressSource,
    ) !void {
        const key = addressKey(address);
        if (self.known_addresses.contains(key)) return;

        // Check if IP is banned
        if (self.ban_list.isAddressBanned(address)) return;

        try self.known_addresses.put(key, AddressInfo{
            .address = address,
            .services = services,
            .last_seen = std.time.timestamp(),
            .last_tried = 0,
            .attempts = 0,
            .success = false,
            .source = source,
        });
    }

    /// Check if an address is already connected.
    fn isConnected(self: *const PeerManager, address: std.net.Address) bool {
        const key = addressKey(address);
        for (self.peers.items) |peer| {
            if (addressKey(peer.address) == key) return true;
        }
        return false;
    }

    /// Select an address to connect to (prefer untried, recent addresses).
    /// Enforces netgroup diversity: rejects addresses from netgroups we already have.
    pub fn selectPeerToConnect(self: *PeerManager) ?std.net.Address {
        const now = std.time.timestamp();
        var best: ?*AddressInfo = null;
        var best_key: u64 = 0;

        var iter = self.known_addresses.iterator();
        while (iter.next()) |entry| {
            const info = entry.value_ptr;

            // Skip already connected addresses
            if (self.isConnected(info.address)) continue;

            // Skip recently tried addresses
            if (info.last_tried > 0 and now - info.last_tried < MIN_RECONNECT_INTERVAL) continue;

            // Skip banned IPs
            if (self.ban_list.isAddressBanned(info.address)) continue;

            // Eclipse protection: skip addresses from netgroups we already have
            if (self.violatesNetgroupDiversity(info.address)) continue;

            // Prefer addresses with fewer attempts
            if (best == null or info.attempts < best.?.attempts) {
                best = info;
                best_key = entry.key_ptr.*;
            }
        }

        if (best) |b| {
            // Update last_tried and attempts via the map
            if (self.known_addresses.getPtr(best_key)) |info_ptr| {
                info_ptr.last_tried = now;
                info_ptr.attempts += 1;
            }
            return b.address;
        }
        return null;
    }

    /// Start listening for inbound connections.
    pub fn startListening(self: *PeerManager, port: u16) !void {
        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        self.listener = try addr.listen(.{
            .reuse_address = true,
        });
    }

    /// Ban an IP address with a reason.
    pub fn banIP(self: *PeerManager, address: std.net.Address, duration: i64, reason: []const u8) !void {
        try self.ban_list.banAddress(address, duration, reason);
    }

    /// Unban an IP address.
    pub fn unbanIP(self: *PeerManager, address: std.net.Address) bool {
        return self.ban_list.unbanAddress(address);
    }

    /// Check if an IP is banned.
    pub fn isIPBanned(self: *PeerManager, address: std.net.Address) bool {
        return self.ban_list.isAddressBanned(address);
    }

    /// Get the ban list for RPC.
    pub fn getBanList(self: *PeerManager) *banlist.BanList {
        return &self.ban_list;
    }

    // ========================================================================
    // Eclipse Attack Protection: Anchor Connections
    // ========================================================================

    /// Load anchor connections from disk (anchors.dat).
    pub fn loadAnchors(self: *PeerManager) !void {
        var file = std.fs.cwd().openFile(self.anchors_path, .{}) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch |err| {
            std.log.warn("Failed to parse anchors.dat: {}", .{err});
            return;
        };
        defer parsed.deinit();

        const root = parsed.value;
        if (root != .object) return;

        const anchors_array = root.object.get("anchors") orelse return;
        if (anchors_array != .array) return;

        for (anchors_array.array.items) |item| {
            if (item != .object) continue;

            const ip_str = item.object.get("ip") orelse continue;
            const port_val = item.object.get("port") orelse continue;

            if (ip_str != .string or port_val != .integer) continue;

            // Parse IP address
            var ip_parts: [4]u8 = undefined;
            var part_iter = std.mem.splitSequence(u8, ip_str.string, ".");
            var i: usize = 0;
            while (part_iter.next()) |part| : (i += 1) {
                if (i >= 4) break;
                ip_parts[i] = std.fmt.parseInt(u8, part, 10) catch continue;
            }
            if (i != 4) continue;

            const port: u16 = @intCast(@as(i64, @truncate(port_val.integer)));
            const addr = std.net.Address.initIp4(ip_parts, port);
            self.anchor_addresses.append(addr) catch continue;
        }

        std.log.info("Loaded {} anchor connections from {s}", .{ self.anchor_addresses.items.len, self.anchors_path });
    }

    /// Save current block-relay-only connections as anchors.
    pub fn saveAnchors(self: *PeerManager) !void {
        var file = std.fs.cwd().createFile(self.anchors_path, .{}) catch |err| {
            std.log.err("Failed to create anchors file: {}", .{err});
            return err;
        };
        defer file.close();

        var writer = file.writer();
        try writer.writeAll("{\n  \"anchors\": [\n");

        var first = true;
        var count: usize = 0;
        for (self.peers.items) |peer| {
            // Save block-relay-only outbound peers as anchors
            if (peer.conn_type == .block_relay and count < MAX_BLOCK_RELAY_ONLY_ANCHORS) {
                if (!first) {
                    try writer.writeAll(",\n");
                }
                first = false;

                switch (peer.address.any.family) {
                    std.posix.AF.INET => {
                        const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&peer.address.any)));
                        const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                        const port = std.mem.bigToNative(u16, ip4.port);
                        try writer.print("    {{\"ip\": \"{d}.{d}.{d}.{d}\", \"port\": {d}}}", .{
                            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
                        });
                        count += 1;
                    },
                    else => {},
                }
            }
        }

        try writer.writeAll("\n  ]\n}\n");
        std.log.info("Saved {} anchor connections to {s}", .{ count, self.anchors_path });
    }

    /// Connect to anchor peers first on startup.
    pub fn connectToAnchors(self: *PeerManager) void {
        for (self.anchor_addresses.items) |addr| {
            if (self.isConnected(addr)) continue;
            if (self.ban_list.isAddressBanned(addr)) continue;

            const peer = self.allocator.create(Peer) catch continue;
            peer.* = Peer.connect(addr, self.network_params, self.allocator) catch {
                self.allocator.destroy(peer);
                continue;
            };
            peer.conn_type = .block_relay;

            peer.performHandshake(self.our_height) catch {
                peer.disconnect();
                self.allocator.destroy(peer);
                continue;
            };

            // Track netgroup
            self.outbound_netgroups.put(netGroup(addr), {}) catch {};

            self.peers.append(peer) catch {
                peer.disconnect();
                self.allocator.destroy(peer);
                continue;
            };

            std.log.info("Connected to anchor peer: {}", .{addr});
        }
    }

    // ========================================================================
    // Eclipse Attack Protection: Netgroup Diversity
    // ========================================================================

    /// Check if adding a peer from the given address would violate netgroup diversity.
    pub fn violatesNetgroupDiversity(self: *const PeerManager, address: std.net.Address) bool {
        const group = netGroup(address);
        return self.outbound_netgroups.contains(group);
    }

    /// Update netgroup tracking when a peer is connected.
    fn trackOutboundNetgroup(self: *PeerManager, peer: *const Peer) void {
        if (peer.direction == .outbound) {
            self.outbound_netgroups.put(netGroup(peer.address), {}) catch {};
        }
    }

    /// Remove netgroup tracking when a peer is disconnected.
    fn untrackOutboundNetgroup(self: *PeerManager, peer: *const Peer) void {
        if (peer.direction == .outbound) {
            _ = self.outbound_netgroups.remove(netGroup(peer.address));
        }
    }

    /// Connect to peers until we have MAX_OUTBOUND_CONNECTIONS outbound.
    /// Enforces netgroup diversity by tracking connected netgroups.
    pub fn maintainOutbound(self: *PeerManager) !void {
        var outbound_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .outbound) outbound_count += 1;
        }

        while (outbound_count < MAX_OUTBOUND_CONNECTIONS) {
            const addr = self.selectPeerToConnect() orelse break;
            const peer = self.allocator.create(Peer) catch break;
            peer.* = Peer.connect(addr, self.network_params, self.allocator) catch {
                self.allocator.destroy(peer);
                continue;
            };
            peer.performHandshake(self.our_height) catch {
                peer.disconnect();
                self.allocator.destroy(peer);
                continue;
            };

            // Mark address as successful
            const key = addressKey(addr);
            if (self.known_addresses.getPtr(key)) |info| {
                info.success = true;
                info.last_seen = std.time.timestamp();
            }

            // Track netgroup for diversity enforcement
            self.trackOutboundNetgroup(peer);

            self.peers.append(peer) catch {
                self.untrackOutboundNetgroup(peer);
                peer.disconnect();
                self.allocator.destroy(peer);
                break;
            };
            outbound_count += 1;
        }
    }

    /// Accept a waiting inbound connection if available (non-blocking).
    /// When inbound slots are full, uses eviction protection algorithm.
    pub fn acceptInbound(self: *PeerManager) !void {
        if (self.listener == null) return;

        // Try to accept without blocking
        const conn = self.listener.?.accept() catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return err,
            }
        };

        // Check if IP is banned
        if (self.ban_list.isAddressBanned(conn.address)) {
            conn.stream.close();
            return;
        }

        // Count inbound connections
        var inbound_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .inbound) inbound_count += 1;
        }

        // If inbound slots are full, try to evict a peer
        if (inbound_count >= MAX_INBOUND_CONNECTIONS) {
            // Build eviction candidates
            const candidates = buildEvictionCandidates(self.peers.items, self.allocator) catch {
                conn.stream.close();
                return;
            };
            defer self.allocator.free(candidates);

            // Select victim
            if (selectEvictionCandidate(candidates, self.allocator)) |victim_idx| {
                std.log.info("Evicting inbound peer to make room for new connection", .{});
                self.removePeerByIndex(victim_idx);
            } else {
                // No victim found, reject new connection
                conn.stream.close();
                return;
            }
        }

        const peer = try self.allocator.create(Peer);
        peer.* = Peer.accept(conn.stream, conn.address, self.network_params, self.allocator);
        peer.performHandshake(self.our_height) catch {
            peer.disconnect();
            self.allocator.destroy(peer);
            return;
        };
        try self.peers.append(peer);
    }

    /// Process messages from all connected peers.
    pub fn processAllMessages(self: *PeerManager) !void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];

            // Check if peer should be banned from previous misbehavior
            if (peer.should_ban) {
                self.banIP(peer.address, DEFAULT_BAN_DURATION, "misbehavior threshold reached") catch {};
                self.removePeerByIndex(i);
                continue;
            }

            const msg = peer.receiveMessage() catch |err| {
                switch (err) {
                    PeerError.ConnectionClosed, PeerError.Timeout => {
                        self.removePeerByIndex(i);
                        continue;
                    },
                    PeerError.BadMagic => {
                        peer.misbehaving(100, "invalid network magic");
                    },
                    PeerError.BadChecksum => {
                        peer.misbehaving(50, "bad message checksum");
                    },
                    PeerError.MessageTooLarge => {
                        peer.misbehaving(50, "oversized message");
                    },
                    PeerError.ProtocolViolation => {
                        peer.misbehaving(20, "protocol violation");
                    },
                    else => {
                        peer.misbehaving(10, "message receive error");
                    },
                }

                // Check if should be banned after misbehavior
                if (peer.should_ban) {
                    self.banIP(peer.address, DEFAULT_BAN_DURATION, "misbehavior threshold reached") catch {};
                    self.removePeerByIndex(i);
                    continue;
                }

                i += 1;
                continue;
            };

            self.handleMessage(peer, msg) catch {};
            i += 1;
        }
    }

    /// Handle a received message.
    fn handleMessage(self: *PeerManager, peer: *Peer, msg: p2p.Message) !void {
        switch (msg) {
            .ping => |pp| {
                const pong = p2p.Message{ .pong = pp };
                try peer.sendMessage(&pong);
            },
            .pong => |pp| peer.handlePong(pp.nonce),
            .addr => |a| {
                for (a.addrs) |entry| {
                    // Convert TimestampedAddr to std.net.Address
                    // Check if it's an IPv4-mapped IPv6 address
                    if (std.mem.eql(u8, entry.addr.ip[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                        const addr = std.net.Address.initIp4(
                            entry.addr.ip[12..16].*,
                            entry.addr.port,
                        );
                        self.addAddress(addr, entry.addr.services, .peer_addr) catch continue;
                    }
                }
            },
            .inv => {
                // Forward to sync manager for block/tx handling (TODO)
            },
            .headers => {
                // Forward to sync manager (TODO)
            },
            .getaddr => {
                // Send some known addresses back
                try self.sendAddresses(peer);
            },
            else => {},
        }
    }

    /// Send known addresses to a peer.
    fn sendAddresses(self: *PeerManager, peer: *Peer) !void {
        var addrs = std.ArrayList(p2p.TimestampedAddr).init(self.allocator);
        defer addrs.deinit();

        var iter = self.known_addresses.iterator();
        var count: usize = 0;
        while (iter.next()) |entry| : (count += 1) {
            if (count >= 100) break; // Limit to 100 addresses

            const info = entry.value_ptr;
            if (!info.success) continue; // Only send successfully connected addresses

            // Convert std.net.Address to NetworkAddress
            var net_addr = types.NetworkAddress{
                .services = info.services,
                .ip = [_]u8{0} ** 16,
                .port = 0,
            };

            switch (info.address.any.family) {
                std.posix.AF.INET => {
                    const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&info.address.any)));
                    // IPv4-mapped IPv6 format
                    net_addr.ip[10] = 0xff;
                    net_addr.ip[11] = 0xff;
                    const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                    @memcpy(net_addr.ip[12..16], ip_bytes);
                    net_addr.port = std.mem.bigToNative(u16, ip4.port);
                },
                else => continue,
            }

            try addrs.append(p2p.TimestampedAddr{
                .timestamp = @intCast(@as(i64, @truncate(info.last_seen))),
                .addr = net_addr,
            });
        }

        if (addrs.items.len > 0) {
            const msg = p2p.Message{ .addr = .{ .addrs = addrs.items } };
            try peer.sendMessage(&msg);
        }
    }

    /// Send pings to peers that have been idle for > PING_INTERVAL.
    pub fn sendPings(self: *PeerManager) !void {
        const now = std.time.timestamp();
        for (self.peers.items) |peer| {
            if (peer.state == .handshake_complete and now - peer.last_ping_time > PING_INTERVAL) {
                peer.sendPing() catch continue;
            }
        }
    }

    /// Disconnect stale or timed-out peers.
    pub fn disconnectStale(self: *PeerManager) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            if (self.peers.items[i].isTimedOut()) {
                self.removePeerByIndex(i);
            } else {
                i += 1;
            }
        }
    }

    /// Rotate peers: disconnect longest-connected outbound and connect a new one.
    pub fn rotatePeers(self: *PeerManager) void {
        const now = std.time.timestamp();
        if (now - self.last_rotation_time < PEER_ROTATION_INTERVAL) return;
        self.last_rotation_time = now;

        // Find the oldest outbound peer
        var oldest_idx: ?usize = null;
        var oldest_time: i64 = now;

        for (self.peers.items, 0..) |peer, i| {
            if (peer.direction == .outbound and peer.state == .handshake_complete) {
                // Use last_message_time as a proxy for connection age
                if (peer.last_message_time < oldest_time) {
                    oldest_time = peer.last_message_time;
                    oldest_idx = i;
                }
            }
        }

        // Disconnect the oldest if we have enough outbound connections
        var outbound_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .outbound) outbound_count += 1;
        }

        if (oldest_idx != null and outbound_count >= MAX_OUTBOUND_CONNECTIONS) {
            self.removePeerByIndex(oldest_idx.?);
        }
    }

    /// Remove and disconnect a peer by index.
    fn removePeerByIndex(self: *PeerManager, index: usize) void {
        const peer = self.peers.swapRemove(index);
        // Untrack netgroup for outbound connections
        self.untrackOutboundNetgroup(peer);
        peer.disconnect();
        self.allocator.destroy(peer);
    }

    /// Main peer management loop.
    pub fn run(self: *PeerManager) !void {
        self.running.store(true, .release);

        // Load anchor connections from disk
        self.loadAnchors() catch {};

        // Connect to anchor peers first (priority)
        self.connectToAnchors();

        // Initial DNS seeding
        self.dnsSeeds() catch {};

        while (self.running.load(.acquire)) {
            // 1. Open new outbound connections if needed
            self.maintainOutbound() catch {};

            // 2. Accept inbound connections
            self.acceptInbound() catch {};

            // 3. Process messages from all peers
            self.processAllMessages() catch {};

            // 4. Send pings to idle peers
            self.sendPings() catch {};

            // 5. Disconnect timed-out peers
            self.disconnectStale();

            // 6. Peer rotation
            self.rotatePeers();

            // 7. Brief sleep to avoid busy-loop
            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }

    /// Stop the peer manager.
    pub fn stop(self: *PeerManager) void {
        self.running.store(false, .release);
    }

    // ========================================================================
    // Legacy API compatibility
    // ========================================================================

    /// Connect to a new peer (legacy API).
    pub fn connectToPeer(self: *PeerManager, address: std.net.Address) !*Peer {
        if (self.peers.items.len >= MAX_TOTAL_CONNECTIONS) {
            return error.TooManyPeers;
        }

        const peer = try self.allocator.create(Peer);
        peer.* = try Peer.connect(address, self.network_params, self.allocator);
        try self.peers.append(peer);
        return peer;
    }

    /// Remove a peer from the manager (legacy API).
    pub fn removePeer(self: *PeerManager, peer: *Peer) void {
        for (self.peers.items, 0..) |p, i| {
            if (p == peer) {
                peer.disconnect();
                _ = self.peers.swapRemove(i);
                self.allocator.destroy(peer);
                return;
            }
        }
    }

    /// Get the number of connected peers.
    pub fn connectedCount(self: *const PeerManager) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.isReady()) count += 1;
        }
        return count;
    }

    /// Get the number of outbound peers.
    pub fn outboundCount(self: *const PeerManager) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .outbound) count += 1;
        }
        return count;
    }

    /// Get the number of inbound peers.
    pub fn inboundCount(self: *const PeerManager) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .inbound) count += 1;
        }
        return count;
    }

    /// Get number of known addresses.
    pub fn knownAddressCount(self: *const PeerManager) usize {
        return self.known_addresses.count();
    }

    /// Disconnect timed-out peers (legacy API).
    pub fn pruneTimedOut(self: *PeerManager) void {
        self.disconnectStale();
    }

    /// Broadcast a message to all connected peers.
    pub fn broadcast(self: *PeerManager, msg: *const p2p.Message) void {
        for (self.peers.items) |peer| {
            if (peer.state == .handshake_complete) {
                peer.sendMessage(msg) catch continue;
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "peer struct initialization with default values" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    // Create a mock stream by using a dummy file descriptor
    // Since we can't create a real socket in tests without a server,
    // we test the accept path with a placeholder

    // Test that PeerState enum has expected values
    try std.testing.expectEqual(PeerState.connecting, PeerState.connecting);
    try std.testing.expectEqual(PeerState.handshake_complete, PeerState.handshake_complete);

    // Test PeerDirection enum
    try std.testing.expectEqual(PeerDirection.inbound, PeerDirection.inbound);
    try std.testing.expectEqual(PeerDirection.outbound, PeerDirection.outbound);

    // Test peer initialization values directly without a real socket
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const dummy_peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8333),
        .state = .connecting,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 12345,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 12345,
    };

    try std.testing.expectEqual(PeerState.connecting, dummy_peer.state);
    try std.testing.expectEqual(PeerDirection.outbound, dummy_peer.direction);
    try std.testing.expectEqual(@as(u64, 0), dummy_peer.services);
    try std.testing.expectEqual(@as(i64, 0), dummy_peer.last_ping_time);
    try std.testing.expectEqual(@as(u64, 0), dummy_peer.bytes_sent);
    try std.testing.expectEqual(@as(i32, 0), dummy_peer.start_height);
    try std.testing.expect(!dummy_peer.is_witness_capable);
    try std.testing.expect(!dummy_peer.is_headers_first);
    try std.testing.expectEqual(@as(u32, 0), dummy_peer.ban_score);
}

test "peer state transitions" {
    // Test that all PeerState values are valid
    const states = [_]PeerState{
        .connecting,
        .connected,
        .version_sent,
        .version_received,
        .handshake_complete,
        .disconnecting,
        .disconnected,
    };

    for (states, 0..) |state, i| {
        try std.testing.expectEqual(states[i], state);
    }

    // Test state enum tag values
    try std.testing.expect(@intFromEnum(PeerState.connecting) == 0);
    try std.testing.expect(@intFromEnum(PeerState.connected) == 1);
    try std.testing.expect(@intFromEnum(PeerState.disconnected) == 6);
}

test "version message construction with correct protocol version" {
    const version_msg = p2p.VersionMessage{
        .version = p2p.PROTOCOL_VERSION,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .timestamp = 1234567890,
        .addr_recv = types.NetworkAddress{
            .services = 0,
            .ip = [_]u8{0} ** 16,
            .port = 0,
        },
        .addr_from = types.NetworkAddress{
            .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
            .ip = [_]u8{0} ** 16,
            .port = 8333,
        },
        .nonce = 0x123456789ABCDEF0,
        .user_agent = p2p.USER_AGENT,
        .start_height = 700000,
        .relay = true,
    };

    try std.testing.expectEqual(@as(i32, 70016), version_msg.version);
    try std.testing.expectEqual(@as(u64, p2p.NODE_NETWORK | p2p.NODE_WITNESS), version_msg.services);
    try std.testing.expectEqual(@as(i64, 1234567890), version_msg.timestamp);
    try std.testing.expectEqual(@as(i32, 700000), version_msg.start_height);
    try std.testing.expect(version_msg.relay);
    try std.testing.expectEqualStrings("/clearbit:0.1.0/", version_msg.user_agent);

    // Verify services bitmap
    try std.testing.expect((version_msg.services & p2p.NODE_NETWORK) != 0);
    try std.testing.expect((version_msg.services & p2p.NODE_WITNESS) != 0);
}

test "ban score accumulation" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333),
        .state = .connected,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
    };

    // Initial score is 0
    try std.testing.expectEqual(@as(u32, 0), peer.ban_score);

    // Add 25 points, should not be banned
    try std.testing.expect(!peer.addBanScore(25));
    try std.testing.expectEqual(@as(u32, 25), peer.ban_score);

    // Add 25 more, still not banned
    try std.testing.expect(!peer.addBanScore(25));
    try std.testing.expectEqual(@as(u32, 50), peer.ban_score);

    // Add 49 more, still not banned (99 total)
    try std.testing.expect(!peer.addBanScore(49));
    try std.testing.expectEqual(@as(u32, 99), peer.ban_score);

    // Add 1 more, now banned (100 total)
    try std.testing.expect(peer.addBanScore(1));
    try std.testing.expectEqual(@as(u32, 100), peer.ban_score);
}

test "peer timeout detection" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const now = std.time.timestamp();

    // Test peer with recent message - not timed out
    var active_peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = p2p.NODE_NETWORK,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = now,
        .bytes_sent = 1000,
        .bytes_received = 2000,
        .start_height = 700000,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = true,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = now,
    };

    try std.testing.expect(!active_peer.isTimedOut());

    // Test peer with old last message - timed out (20+ minutes ago)
    var stale_peer = active_peer;
    stale_peer.last_message_time = now - (21 * 60);
    try std.testing.expect(stale_peer.isTimedOut());

    // Test peer with ping sent but no pong - timed out (5+ minutes ago)
    var ping_peer = active_peer;
    ping_peer.last_message_time = now;
    ping_peer.last_ping_time = now - (6 * 60);
    ping_peer.last_pong_time = now - (10 * 60); // Pong before ping
    try std.testing.expect(ping_peer.isTimedOut());

    // Test peer with ping sent and pong received - not timed out
    var healthy_peer = active_peer;
    healthy_peer.last_ping_time = now - 60;
    healthy_peer.last_pong_time = now - 59;
    try std.testing.expect(!healthy_peer.isTimedOut());
}

test "peer ready check" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .connecting,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };

    // Connecting state - not ready
    try std.testing.expect(!peer.isReady());

    // Connected state - not ready
    peer.state = .connected;
    try std.testing.expect(!peer.isReady());

    // Version sent - not ready
    peer.state = .version_sent;
    try std.testing.expect(!peer.isReady());

    // Handshake complete - ready!
    peer.state = .handshake_complete;
    try std.testing.expect(peer.isReady());

    // Disconnecting - not ready
    peer.state = .disconnecting;
    try std.testing.expect(!peer.isReady());
}

test "handle pong message" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 1000,
        .last_pong_time = 0,
        .last_ping_nonce = 0x123456789ABCDEF0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };

    // Wrong nonce - should not update pong time
    peer.handlePong(0xDEADBEEF);
    try std.testing.expectEqual(@as(i64, 0), peer.last_pong_time);

    // Correct nonce - should update pong time
    peer.handlePong(0x123456789ABCDEF0);
    try std.testing.expect(peer.last_pong_time > 0);
}

test "peer latency calculation" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };

    // No ping/pong yet - no latency
    try std.testing.expect(peer.getLatencyMs() == null);

    // Set ping time
    peer.last_ping_time = 1000;
    try std.testing.expect(peer.getLatencyMs() == null);

    // Set pong time (50ms later)
    peer.last_pong_time = 1000;
    const latency = peer.getLatencyMs();
    try std.testing.expect(latency != null);
    try std.testing.expectEqual(@as(i64, 0), latency.?);
}

test "peer manager initialization" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    try std.testing.expectEqual(@as(usize, 0), manager.peers.items.len);
    try std.testing.expectEqual(@as(usize, 0), manager.connectedCount());
    try std.testing.expectEqual(@as(usize, 0), manager.knownAddressCount());
    try std.testing.expectEqual(@as(i32, 0), manager.our_height);
}

test "peer direction enum" {
    // Test that direction enum values work correctly
    const inbound: PeerDirection = .inbound;
    const outbound: PeerDirection = .outbound;

    try std.testing.expect(inbound != outbound);
    try std.testing.expectEqual(PeerDirection.inbound, inbound);
    try std.testing.expectEqual(PeerDirection.outbound, outbound);
}

test "peer error types" {
    // Test that all error types are distinct
    const err1: PeerError = PeerError.ConnectionFailed;
    const err2: PeerError = PeerError.HandshakeFailed;
    const err3: PeerError = PeerError.BadMagic;

    try std.testing.expect(err1 != err2);
    try std.testing.expect(err2 != err3);
    try std.testing.expect(err1 != err3);
}

// ============================================================================
// Peer Manager Discovery Tests
// ============================================================================

test "peer manager constants" {
    // Verify constants match Bitcoin Core defaults
    try std.testing.expectEqual(@as(usize, 8), MAX_OUTBOUND_CONNECTIONS);
    try std.testing.expectEqual(@as(usize, 117), MAX_INBOUND_CONNECTIONS);
    try std.testing.expectEqual(@as(usize, 125), MAX_TOTAL_CONNECTIONS);
    try std.testing.expectEqual(@as(i64, 30 * 60), PEER_ROTATION_INTERVAL);
    try std.testing.expectEqual(@as(u32, 10), DNS_SEED_TIMEOUT);
    try std.testing.expectEqual(@as(i64, 24 * 60 * 60), DEFAULT_BAN_DURATION);
}

test "address info struct" {
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);

    const info = AddressInfo{
        .address = addr,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .last_seen = 1234567890,
        .last_tried = 0,
        .attempts = 0,
        .success = false,
        .source = .dns_seed,
    };

    try std.testing.expectEqual(@as(u64, p2p.NODE_NETWORK | p2p.NODE_WITNESS), info.services);
    try std.testing.expectEqual(@as(i64, 1234567890), info.last_seen);
    try std.testing.expectEqual(@as(u32, 0), info.attempts);
    try std.testing.expect(!info.success);
    try std.testing.expectEqual(AddressSource.dns_seed, info.source);
}

test "address source enum" {
    const dns: AddressSource = .dns_seed;
    const peer: AddressSource = .peer_addr;
    const manual: AddressSource = .manual;

    try std.testing.expect(dns != peer);
    try std.testing.expect(peer != manual);
    try std.testing.expect(dns != manual);
}

test "peer manager address tracking - add and dedup" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 2 }, 8333);

    // Add first address
    try manager.addAddress(addr1, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());

    // Add same address again - should be deduplicated
    try manager.addAddress(addr1, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());

    // Add different address
    try manager.addAddress(addr2, p2p.NODE_WITNESS, .peer_addr);
    try std.testing.expectEqual(@as(usize, 2), manager.knownAddressCount());
}

test "peer manager address selection" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // No addresses - should return null
    try std.testing.expect(manager.selectPeerToConnect() == null);

    // Add an address
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    try manager.addAddress(addr, p2p.NODE_NETWORK, .dns_seed);

    // Should select the address
    const selected = manager.selectPeerToConnect();
    try std.testing.expect(selected != null);

    // After selection, attempts should be incremented
    // Cannot easily verify this without internal access, but selection happened
}

test "peer manager ban ip" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 8333);

    // Add address first
    try manager.addAddress(addr, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());

    // Ban the IP
    try manager.banIP(addr, DEFAULT_BAN_DURATION, "test ban");

    // Adding a new address with same IP should be rejected
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 18333); // Same IP, different port
    try manager.addAddress(addr2, p2p.NODE_NETWORK, .dns_seed);
    // Still only 1 address since same IP is banned
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());
}

test "peer manager outbound/inbound count" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // No peers initially
    try std.testing.expectEqual(@as(usize, 0), manager.outboundCount());
    try std.testing.expectEqual(@as(usize, 0), manager.inboundCount());
    try std.testing.expectEqual(@as(usize, 0), manager.connectedCount());
}

test "peer manager address key generation" {
    // Test that different addresses produce different keys
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 2 }, 8333);
    const addr3 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8334); // Same IP, different port

    const key1 = PeerManager.addressKey(addr1);
    const key2 = PeerManager.addressKey(addr2);
    const key3 = PeerManager.addressKey(addr3);

    try std.testing.expect(key1 != key2);
    try std.testing.expect(key1 != key3);
    try std.testing.expect(key2 != key3);

    // Same address should produce same key
    const key1_again = PeerManager.addressKey(addr1);
    try std.testing.expectEqual(key1, key1_again);
}

test "peer manager ipv4 extraction" {
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 8333);

    const ip_u32 = PeerManager.ipv4AsU32(addr);
    try std.testing.expect(ip_u32 != null);

    // 192.168.1.100 in big-endian u32
    const expected: u32 = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    try std.testing.expectEqual(expected, ip_u32.?);
}

test "peer manager running state" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // Initially not running
    try std.testing.expect(!manager.running.load(.acquire));

    // Start and immediately stop
    manager.running.store(true, .release);
    try std.testing.expect(manager.running.load(.acquire));

    manager.stop();
    try std.testing.expect(!manager.running.load(.acquire));
}

// ============================================================================
// Misbehavior Scoring Tests
// ============================================================================

test "misbehaving function increments score and sets should_ban" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = p2p.NODE_NETWORK,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
    };

    // Initially not marked for ban
    try std.testing.expect(!peer.should_ban);
    try std.testing.expectEqual(@as(u32, 0), peer.ban_score);

    // Add misbehavior with 50 points
    peer.misbehaving(50, "test misbehavior");
    try std.testing.expectEqual(@as(u32, 50), peer.ban_score);
    try std.testing.expect(!peer.should_ban);

    // Add another 50 points - now at 100, should be banned
    peer.misbehaving(50, "second misbehavior");
    try std.testing.expectEqual(@as(u32, 100), peer.ban_score);
    try std.testing.expect(peer.should_ban);
}

test "misbehaving with 100 points immediately bans" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 5 }, 8333),
        .state = .handshake_complete,
        .direction = .inbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .inbound,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
    };

    // Invalid block header = 100 points = immediate ban
    peer.misbehaving(100, "invalid block header");
    try std.testing.expectEqual(@as(u32, 100), peer.ban_score);
    try std.testing.expect(peer.should_ban);
}

test "addBanScore sets should_ban at threshold" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 172, 16, 0, 1 }, 8333),
        .state = .connected,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };

    // Add 99 points - not banned yet
    try std.testing.expect(!peer.addBanScore(99));
    try std.testing.expect(!peer.should_ban);

    // Add 1 more - now banned
    try std.testing.expect(peer.addBanScore(1));
    try std.testing.expect(peer.should_ban);
}

test "peer manager ban integration" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 50, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 50, 2 }, 8333);

    // Add addresses
    try manager.addAddress(addr1, p2p.NODE_NETWORK, .dns_seed);
    try manager.addAddress(addr2, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 2), manager.knownAddressCount());

    // Ban addr1
    try manager.banIP(addr1, DEFAULT_BAN_DURATION, "protocol violation");

    // Verify addr1 is banned
    try std.testing.expect(manager.isIPBanned(addr1));
    try std.testing.expect(!manager.isIPBanned(addr2));

    // Can't add same IP again
    const addr1_different_port = std.net.Address.initIp4([4]u8{ 192, 168, 50, 1 }, 9999);
    try manager.addAddress(addr1_different_port, p2p.NODE_NETWORK, .manual);
    // Count should still be 2
    try std.testing.expectEqual(@as(usize, 2), manager.knownAddressCount());

    // Unban addr1
    try std.testing.expect(manager.unbanIP(addr1));
    try std.testing.expect(!manager.isIPBanned(addr1));
}

// ============================================================================
// Eclipse Attack Protection Tests
// ============================================================================

test "eclipse protection: netGroup returns /16 for IPv4" {
    // 192.168.1.1 should have netgroup (192 << 8) | 168 = 49320
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const group1 = netGroup(addr1);
    const expected1: u32 = (192 << 8) | 168;
    try std.testing.expectEqual(expected1, group1);

    // 192.168.2.2 should have same netgroup (same /16)
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 2, 2 }, 8333);
    const group2 = netGroup(addr2);
    try std.testing.expectEqual(group1, group2);

    // 10.0.0.1 should have different netgroup
    const addr3 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333);
    const group3 = netGroup(addr3);
    const expected3: u32 = (10 << 8) | 0;
    try std.testing.expectEqual(expected3, group3);
    try std.testing.expect(group1 != group3);
}

test "eclipse protection: sameNetGroup compares correctly" {
    // Same /16 subnet
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 255, 255 }, 8333);
    try std.testing.expect(sameNetGroup(addr1, addr2));

    // Different /16 subnet
    const addr3 = std.net.Address.initIp4([4]u8{ 192, 169, 1, 1 }, 8333);
    try std.testing.expect(!sameNetGroup(addr1, addr3));
}

test "eclipse protection: netgroup diversity tracking" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // Initially no netgroups tracked
    try std.testing.expectEqual(@as(usize, 0), manager.outbound_netgroups.count());

    // Add an address from 192.168.x.x
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    manager.outbound_netgroups.put(netGroup(addr1), {}) catch unreachable;
    try std.testing.expectEqual(@as(usize, 1), manager.outbound_netgroups.count());

    // Same netgroup should violate diversity
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 2, 2 }, 8333);
    try std.testing.expect(manager.violatesNetgroupDiversity(addr2));

    // Different netgroup should not violate
    const addr3 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333);
    try std.testing.expect(!manager.violatesNetgroupDiversity(addr3));
}

test "eclipse protection: eviction candidate building" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    // Create mock peers
    var peers: [3]*Peer = undefined;
    var buffers: [3]std.ArrayList(u8) = undefined;
    for (0..3) |i| {
        buffers[i] = std.ArrayList(u8).init(allocator);
        peers[i] = allocator.create(Peer) catch unreachable;
        peers[i].* = .{
            .stream = undefined,
            .address = std.net.Address.initIp4([4]u8{ 192, 168, @intCast(i), 1 }, 8333),
            .state = .handshake_complete,
            .direction = if (i == 0) .outbound else .inbound,
            .version_info = null,
            .services = p2p.NODE_NETWORK,
            .last_ping_time = 0,
            .last_pong_time = 0,
            .last_ping_nonce = 0,
            .last_message_time = 1000,
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = buffers[i],
            .is_witness_capable = true,
            .is_headers_first = false,
            .ban_score = 0,
            .should_ban = false,
            .conn_type = if (i == 0) .outbound_full_relay else .inbound,
            .last_block_time = @as(i64, @intCast(i)) * 100,
            .last_tx_time = @as(i64, @intCast(i)) * 50,
            .min_ping_time = @as(i64, @intCast(3 - i)) * 10,
            .relay_txs = true,
            .is_protected = false,
            .connect_time = @as(i64, @intCast(i)) * 200,
        };
    }
    defer {
        for (0..3) |i| {
            buffers[i].deinit();
            allocator.destroy(peers[i]);
        }
    }

    const candidates = try buildEvictionCandidates(&peers, allocator);
    defer allocator.free(candidates);

    // Should only include inbound peers (2 of 3)
    try std.testing.expectEqual(@as(usize, 2), candidates.len);

    // Verify candidates are inbound only
    for (candidates) |c| {
        try std.testing.expect(peers[c.peer_index].direction == .inbound);
    }
}

test "eclipse protection: eviction algorithm protects by categories" {
    const allocator = std.testing.allocator;

    // Create a set of candidates with different characteristics
    var candidates = [_]EvictionCandidate{
        // Fast ping (should be protected)
        .{ .peer_index = 0, .net_group = 1, .min_ping_time = 10, .last_block_time = 0, .last_tx_time = 0, .connect_time = 1000, .relay_txs = true, .is_protected = false },
        // Recent tx (should be protected)
        .{ .peer_index = 1, .net_group = 2, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 900, .connect_time = 500, .relay_txs = true, .is_protected = false },
        // Recent block (should be protected)
        .{ .peer_index = 2, .net_group = 3, .min_ping_time = 100, .last_block_time = 800, .last_tx_time = 0, .connect_time = 600, .relay_txs = true, .is_protected = false },
        // Long connection (should be protected)
        .{ .peer_index = 3, .net_group = 4, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 100, .relay_txs = true, .is_protected = false },
        // Distinct netgroup (should be protected)
        .{ .peer_index = 4, .net_group = 5, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 700, .relay_txs = true, .is_protected = false },
        // Unprotected - same netgroup as another, no special characteristics
        .{ .peer_index = 5, .net_group = 1, .min_ping_time = 200, .last_block_time = 0, .last_tx_time = 0, .connect_time = 800, .relay_txs = true, .is_protected = false },
        // Another unprotected - same netgroup
        .{ .peer_index = 6, .net_group = 1, .min_ping_time = 300, .last_block_time = 0, .last_tx_time = 0, .connect_time = 900, .relay_txs = true, .is_protected = false },
    };

    const victim = selectEvictionCandidate(&candidates, allocator);

    // Should select a victim (the algorithm will pick from netgroup 1 which has most connections)
    try std.testing.expect(victim != null);
    // The victim should be from netgroup 1 (most connections)
    if (victim) |v| {
        try std.testing.expect(v == 5 or v == 6); // One of the unprotected peers in netgroup 1
    }
}

test "eclipse protection: eviction returns null when all protected" {
    const allocator = std.testing.allocator;

    // Create candidates that will all be protected
    // 4 distinct netgroups, each with unique characteristics
    var candidates = [_]EvictionCandidate{
        .{ .peer_index = 0, .net_group = 1, .min_ping_time = 10, .last_block_time = 100, .last_tx_time = 100, .connect_time = 100, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 1, .net_group = 2, .min_ping_time = 20, .last_block_time = 200, .last_tx_time = 200, .connect_time = 200, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 2, .net_group = 3, .min_ping_time = 30, .last_block_time = 300, .last_tx_time = 300, .connect_time = 300, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 3, .net_group = 4, .min_ping_time = 40, .last_block_time = 400, .last_tx_time = 400, .connect_time = 400, .relay_txs = true, .is_protected = false },
    };

    // With only 4 candidates and protection for ping(4), tx(4), block(4), time(8), netgroup(4)
    // all 4 should be protected
    const victim = selectEvictionCandidate(&candidates, allocator);

    // All protected, no victim
    try std.testing.expect(victim == null);
}

test "eclipse protection: connection type enum" {
    // Test all connection types are distinct
    const types_arr = [_]ConnectionType{
        .inbound,
        .outbound_full_relay,
        .block_relay,
        .manual,
        .feeler,
        .addr_fetch,
    };

    for (types_arr, 0..) |t1, i| {
        for (types_arr, 0..) |t2, j| {
            if (i == j) {
                try std.testing.expectEqual(t1, t2);
            } else {
                try std.testing.expect(t1 != t2);
            }
        }
    }
}

test "eclipse protection: eclipse constants match Bitcoin Core" {
    // Verify protection limits match Bitcoin Core defaults
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_PING);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_TX);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_BLOCK);
    try std.testing.expectEqual(@as(usize, 8), EVICTION_PROTECT_TIME);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_NETGROUP);
    try std.testing.expectEqual(@as(usize, 2), MAX_BLOCK_RELAY_ONLY_ANCHORS);
}
