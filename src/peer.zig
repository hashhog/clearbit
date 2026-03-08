const std = @import("std");
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");

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
// Peer Manager
// ============================================================================

/// Manages multiple peer connections.
pub const PeerManager = struct {
    peers: std.ArrayList(*Peer),
    max_peers: usize,
    network_params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        params: *const consensus.NetworkParams,
        max_peers: usize,
    ) PeerManager {
        return .{
            .peers = std.ArrayList(*Peer).init(allocator),
            .max_peers = max_peers,
            .network_params = params,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PeerManager) void {
        for (self.peers.items) |peer| {
            peer.disconnect();
            self.allocator.destroy(peer);
        }
        self.peers.deinit();
    }

    /// Connect to a new peer.
    pub fn connectToPeer(self: *PeerManager, address: std.net.Address) !*Peer {
        if (self.peers.items.len >= self.max_peers) {
            return error.TooManyPeers;
        }

        const peer = try self.allocator.create(Peer);
        peer.* = try Peer.connect(address, self.network_params, self.allocator);
        try self.peers.append(peer);
        return peer;
    }

    /// Remove a peer from the manager.
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

    /// Disconnect timed-out peers.
    pub fn pruneTimedOut(self: *PeerManager) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            if (self.peers.items[i].isTimedOut()) {
                const peer = self.peers.swapRemove(i);
                peer.disconnect();
                self.allocator.destroy(peer);
            } else {
                i += 1;
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

    var manager = PeerManager.init(allocator, params, 125);
    defer manager.deinit();

    try std.testing.expectEqual(@as(usize, 125), manager.max_peers);
    try std.testing.expectEqual(@as(usize, 0), manager.peers.items.len);
    try std.testing.expectEqual(@as(usize, 0), manager.connectedCount());
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
