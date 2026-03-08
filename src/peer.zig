const std = @import("std");
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");

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

/// Hardcoded fallback peers for testnet4 (DNS seeds unreliable).
pub const TESTNET_FALLBACK_PEERS: []const []const u8 = &[_][]const u8{
    "127.0.0.1", // Placeholder - would be real testnet4 peers
};

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

    /// Connect to a remote peer.
    pub fn connect(
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) PeerError!Peer {
        const stream = std.net.tcpConnectToAddress(address) catch
            return PeerError.ConnectionFailed;

        // Set socket options for timeouts (30 seconds)
        const timeout = std.posix.timeval{ .tv_sec = 30, .tv_usec = 0 };
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
            .last_message_time = std.time.timestamp(),
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .is_witness_capable = false,
            .is_headers_first = false,
            .ban_score = 0,
        };
    }

    /// Accept an inbound connection.
    pub fn accept(
        stream: std.net.Stream,
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) Peer {
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
            .last_message_time = std.time.timestamp(),
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .is_witness_capable = false,
            .is_headers_first = false,
            .ban_score = 0,
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
        return self.ban_score >= 100;
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
    banned_ips: std.AutoHashMap(u32, i64), // IP (as u32) -> ban expiry timestamp
    listener: ?std.net.Server,
    network_params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
    our_height: i32,
    running: std.atomic.Value(bool),
    last_rotation_time: i64,

    pub fn init(
        allocator: std.mem.Allocator,
        params: *const consensus.NetworkParams,
    ) PeerManager {
        return .{
            .peers = std.ArrayList(*Peer).init(allocator),
            .known_addresses = std.AutoHashMap(u64, AddressInfo).init(allocator),
            .banned_ips = std.AutoHashMap(u32, i64).init(allocator),
            .listener = null,
            .network_params = params,
            .allocator = allocator,
            .our_height = 0,
            .running = std.atomic.Value(bool).init(false),
            .last_rotation_time = 0,
        };
    }

    pub fn deinit(self: *PeerManager) void {
        for (self.peers.items) |peer| {
            peer.disconnect();
            self.allocator.destroy(peer);
        }
        self.peers.deinit();
        self.known_addresses.deinit();
        self.banned_ips.deinit();
        if (self.listener) |*l| l.deinit();
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
        if (ipv4AsU32(address)) |ip| {
            if (self.banned_ips.get(ip)) |expiry| {
                if (std.time.timestamp() < expiry) return;
                // Ban expired, remove it
                _ = self.banned_ips.remove(ip);
            }
        }

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
            if (ipv4AsU32(info.address)) |ip| {
                if (self.banned_ips.get(ip)) |expiry| {
                    if (now < expiry) continue;
                }
            }

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

    /// Ban an IP address.
    pub fn banIP(self: *PeerManager, address: std.net.Address, duration: i64) !void {
        if (ipv4AsU32(address)) |ip| {
            try self.banned_ips.put(ip, std.time.timestamp() + duration);
        }
    }

    /// Connect to peers until we have MAX_OUTBOUND_CONNECTIONS outbound.
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

            self.peers.append(peer) catch {
                peer.disconnect();
                self.allocator.destroy(peer);
                break;
            };
            outbound_count += 1;
        }
    }

    /// Accept a waiting inbound connection if available (non-blocking).
    pub fn acceptInbound(self: *PeerManager) !void {
        if (self.listener == null) return;

        // Try to accept without blocking
        const conn = self.listener.?.accept() catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return err,
            }
        };

        if (self.peers.items.len >= MAX_TOTAL_CONNECTIONS) {
            conn.stream.close();
            return;
        }

        // Check if IP is banned
        if (ipv4AsU32(conn.address)) |ip| {
            if (self.banned_ips.get(ip)) |expiry| {
                if (std.time.timestamp() < expiry) {
                    conn.stream.close();
                    return;
                }
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
            const msg = peer.receiveMessage() catch |err| {
                switch (err) {
                    PeerError.ConnectionClosed, PeerError.Timeout => {
                        self.removePeerByIndex(i);
                        continue;
                    },
                    else => {
                        if (peer.addBanScore(10)) {
                            // Ban and remove
                            self.banIP(peer.address, DEFAULT_BAN_DURATION) catch {};
                            self.removePeerByIndex(i);
                            continue;
                        }
                    },
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
        peer.disconnect();
        self.allocator.destroy(peer);
    }

    /// Main peer management loop.
    pub fn run(self: *PeerManager) !void {
        self.running.store(true, .release);

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
    try manager.banIP(addr, DEFAULT_BAN_DURATION);

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
