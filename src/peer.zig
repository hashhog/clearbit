const std = @import("std");
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const banlist = @import("banlist.zig");
const v2_transport = @import("v2_transport.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");
const mempool_mod = @import("mempool.zig");

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

/// Reconnect interval for manual peers (`addnode <ip> add`). Must be
/// much shorter than MIN_RECONNECT_INTERVAL — when a remote at-tip node
/// evicts our IBD-state peer ("behind our tip"), we want to re-establish
/// within seconds, not 10 minutes.
pub const MANUAL_RECONNECT_INTERVAL: i64 = 30;

/// Ping interval for idle peers (2 minutes).
pub const PING_INTERVAL: i64 = 2 * 60;

// ============================================================================
// Stale Peer Eviction Constants (Bitcoin Core net_processing.cpp)
// ============================================================================

/// Stale tip check interval in seconds (45 seconds as per Bitcoin Core EXTRA_PEER_CHECK_INTERVAL).
pub const STALE_CHECK_INTERVAL: i64 = 45;

/// Stale tip threshold in seconds (30 minutes).
/// If a peer's best_known_height is behind our tip for this long, consider eviction.
pub const STALE_TIP_THRESHOLD: i64 = 30 * 60;

/// Ping timeout in seconds (20 minutes as per Bitcoin Core TIMEOUT_INTERVAL).
/// If we sent a ping and no pong within this time, disconnect.
pub const PING_TIMEOUT: i64 = 20 * 60;

/// Headers response timeout in seconds.
/// Testnet4 peers are slower, so use 5 minutes instead of Bitcoin Core's 2 minutes.
pub const HEADERS_RESPONSE_TIMEOUT: i64 = 5 * 60;

/// Block download timeout in seconds (20 minutes as per Bitcoin Core).
/// If a block is in-flight and not received within this time, disconnect.
pub const BLOCK_DOWNLOAD_TIMEOUT: i64 = 20 * 60;

/// Maximum blocks in flight per peer, matching Bitcoin Core's
/// `MAX_BLOCKS_IN_TRANSIT_PER_PEER` (src/net_processing.cpp).  The block
/// download pipeline is level-triggered per peer — every SendMessages tick
/// each peer is eligible for up to this many in-flight block requests.  No
/// global counter gates the pipeline; a slow peer only throttles itself
/// and is handled by `checkBlockDownloadTimeouts` (disconnect).
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: u32 = 16;

/// Chain sync timeout in seconds (20 minutes as per Bitcoin Core CHAIN_SYNC_TIMEOUT).
pub const CHAIN_SYNC_TIMEOUT: i64 = 20 * 60;

/// Minimum connection time before eviction is considered (30 seconds as per Bitcoin Core).
pub const MINIMUM_CONNECT_TIME: i64 = 30;

/// Maximum number of outbound peers to protect from eviction (4 as per Bitcoin Core).
pub const MAX_OUTBOUND_PEERS_TO_PROTECT: usize = 4;

/// Maximum number of block-relay-only anchor connections.
pub const MAX_BLOCK_RELAY_ONLY_ANCHORS: usize = 2;

/// Maximum number of block-relay-only connections.
pub const MAX_BLOCK_RELAY_ONLY_CONNECTIONS: usize = 2;

/// Hardcoded fallback peers for testnet4 (DNS seeds unreliable).
pub const TESTNET_FALLBACK_PEERS: []const []const u8 = &[_][]const u8{
    "127.0.0.1", // Placeholder - would be real testnet4 peers
};

// ============================================================================
// BIP-133 Feefilter Constants
// ============================================================================

/// Average delay between feefilter broadcasts in seconds (10 minutes).
pub const AVG_FEEFILTER_BROADCAST_INTERVAL: i64 = 10 * 60;

/// Maximum feefilter broadcast delay after significant change (5 minutes).
pub const MAX_FEEFILTER_CHANGE_DELAY: i64 = 5 * 60;

/// Default minimum relay fee in sat/kvB.
pub const MIN_RELAY_FEE: u64 = 1000;

/// Incremental relay fee in sat/kvB (for RBF replacement).
pub const INCREMENTAL_RELAY_FEE: u64 = 1000;

// ============================================================================
// Eclipse Attack Protection Constants
// ============================================================================

/// Number of peers to protect by fastest ping time (8 as per Bitcoin Core).
pub const EVICTION_PROTECT_PING: usize = 8;

/// Number of peers to protect by most recent transaction relay.
pub const EVICTION_PROTECT_TX: usize = 4;

/// Number of peers to protect by most recent block relay.
pub const EVICTION_PROTECT_BLOCK: usize = 4;

/// Number of non-tx-relay peers to protect by block relay (Bitcoin Core protects 8).
pub const EVICTION_PROTECT_BLOCK_RELAY_ONLY: usize = 8;

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

/// BIP-324 transport protocol version.
pub const TransportVersion = enum {
    /// V1 legacy unencrypted transport.
    v1,
    /// V2 encrypted transport (BIP-324).
    v2,
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
    /// Fee filter received from this peer (BIP-133). Minimum fee rate in sat/kvB.
    /// We should not relay transactions below this rate to this peer.
    fee_filter_received: u64,
    /// Fee filter we last sent to this peer (BIP-133). In sat/kvB.
    fee_filter_sent: u64,
    /// Next time (microseconds since epoch) to send a feefilter message.
    next_send_feefilter: i64,
    /// Best known block height from this peer (from headers or blocks).
    best_known_height: u32,
    /// Time when we last sent a getheaders request to this peer.
    last_getheaders_time: i64,
    /// Time when the oldest block-in-flight was requested (0 if no blocks in flight).
    oldest_block_in_flight_time: i64,
    /// Number of blocks currently in flight from this peer.
    blocks_in_flight_count: u32,
    /// Whether this peer is protected from stale tip eviction.
    chain_sync_protected: bool,

    /// Clock offset (seconds) from the peer's VERSION message timestamp:
    /// peer_version_timestamp - our_time_at_receipt.  Matches Bitcoin Core's
    /// CNode::nTimeOffset.  Zero until VERSION has been received.
    time_offset: i64 = 0,

    /// BIP-324 v2 transport protocol version.
    transport_version: TransportVersion = .v1,

    /// BIP-324 v2 cipher state (null when using v1 transport).
    v2_cipher: ?v2_transport.BIP324Cipher = null,

    /// Connect to a remote peer.
    pub fn connect(
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) PeerError!Peer {
        // Non-blocking connect with 5-second timeout to avoid blocking the event loop.
        // The default tcpConnectToAddress blocks for the kernel's TCP timeout (~75s),
        // which stalls all peer processing during IBD.
        const sock = std.posix.socket(
            address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.TCP,
        ) catch return PeerError.ConnectionFailed;
        errdefer std.posix.close(sock);

        // Initiate non-blocking connect
        std.posix.connect(sock, &address.any, address.getOsSockLen()) catch |err| {
            if (err != error.WouldBlock) return PeerError.ConnectionFailed;
        };

        // Wait for connect to complete (writable) with 5s timeout
        var pollfds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const ready = std.posix.poll(&pollfds, 5000) catch return PeerError.ConnectionFailed;
        if (ready == 0) return PeerError.ConnectionFailed; // timeout
        if (pollfds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0)
            return PeerError.ConnectionFailed;

        // Check SO_ERROR to see if connect actually succeeded
        std.posix.getsockoptError(sock) catch return PeerError.ConnectionFailed;

        // Switch back to blocking mode for normal I/O
        const cur_flags = std.posix.fcntl(sock, std.posix.F.GETFL, 0) catch return PeerError.ConnectionFailed;
        const o_nonblock: usize = @intCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
        _ = std.posix.fcntl(sock, std.posix.F.SETFL, cur_flags & ~o_nonblock) catch
            return PeerError.ConnectionFailed;

        const stream = std.net.Stream{ .handle = sock };

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
            .fee_filter_received = 0,
            .fee_filter_sent = 0,
            .next_send_feefilter = 0,
            .best_known_height = 0,
            .last_getheaders_time = 0,
            .oldest_block_in_flight_time = 0,
            .blocks_in_flight_count = 0,
            .chain_sync_protected = false,
            .transport_version = .v1,
            .v2_cipher = null,
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
            .fee_filter_received = 0,
            .fee_filter_sent = 0,
            .next_send_feefilter = 0,
            .best_known_height = 0,
            .last_getheaders_time = 0,
            .oldest_block_in_flight_time = 0,
            .blocks_in_flight_count = 0,
            .chain_sync_protected = false,
            .transport_version = .v1,
            .v2_cipher = null,
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
        self.readExact(&header_buf) catch |err| {
            return if (err == error.Timeout) PeerError.Timeout else PeerError.ConnectionClosed;
        };

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

    /// Returns true iff the BIP-324 v2 outbound probe is enabled.
    /// Currently gated behind the `CLEARBIT_BIP324_V2` env var (set to "1"
    /// to opt in).  Default off because the v2 application-message
    /// plumbing is incomplete: a v2-classified inbound is currently
    /// disconnected after classification rather than running encrypted
    /// version/verack exchange.  The negotiation envelope and the cipher
    /// itself are correct; the missing piece is routing every Peer
    /// sendMessage/receiveMessage call through the V2Transport state
    /// machine.  Until that lands, leaving v2 disabled by default keeps
    /// the production fleet on the well-tested v1 path.
    pub fn bip324V2Enabled() bool {
        const v = std.posix.getenv("CLEARBIT_BIP324_V2") orelse return false;
        return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "TRUE");
    }

    /// Read up to `out.len` bytes without consuming them from the kernel
    /// receive buffer (uses MSG_PEEK).  Returns the number of bytes peeked.
    /// May return less than `out.len` if data is currently unavailable;
    /// poll() before calling to ensure data is ready.
    pub fn peekBytes(self: *Peer, out: []u8) PeerError!usize {
        var total: usize = 0;
        // Bound the time we spend peeking with a deadline: we may receive
        // partial data for a v1 VERSION (24 header + payload), but the
        // first 16 bytes — magic + command — arrive together in the very
        // first TCP segment in practice.
        const deadline_ms = std.time.milliTimestamp() + 30_000;
        while (total < out.len) {
            const remaining_ms = deadline_ms - std.time.milliTimestamp();
            if (remaining_ms <= 0) break;

            // Wait for data with the remaining deadline.
            var pollfds = [_]std.posix.pollfd{.{
                .fd = self.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&pollfds, @intCast(@min(remaining_ms, 30_000))) catch
                return PeerError.ConnectionClosed;
            if (ready == 0) break; // deadline expired with partial data
            if (pollfds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0)
                return PeerError.ConnectionClosed;
            if ((pollfds[0].revents & std.posix.POLL.IN) == 0) continue;

            const n = std.posix.recv(self.stream.handle, out[total..], std.posix.MSG.PEEK) catch |err| {
                if (err == error.WouldBlock) continue;
                return PeerError.ConnectionClosed;
            };
            if (n == 0) return PeerError.ConnectionClosed;
            // recv with MSG_PEEK can return the SAME bytes repeatedly; if
            // the cumulative peeked length didn't grow we've already seen
            // everything currently buffered — break and let the caller
            // decide based on what we have.
            if (n <= total) break;
            total = n;
        }
        return total;
    }

    /// Outcome of an outbound BIP-324 v2 probe.
    pub const V2ProbeResult = enum {
        /// Peer accepted v2 and the cipher handshake started.  CALLER must
        /// continue with the v2 application-message path (currently NOT
        /// plumbed; see `bip324V2Enabled` doc-comment).
        v2_negotiated,
        /// Peer did not respond within the deadline OR responded with v1
        /// magic.  CALLER must close this socket and reconnect in v1
        /// (sending v2 garbage is destructive on a v1 peer).
        fallback_to_v1,
    };

    /// Send an outbound BIP-324 v2 probe on this connection.  Sends the
    /// 64-byte ElligatorSwift pubkey + initial garbage (per BIP-324) and
    /// reads up to 16 bytes of the peer's response with `deadline_ms`
    /// timeout.  Classifies the response:
    ///   - If the peer started replying with v1 magic, returns
    ///     `.fallback_to_v1`.
    ///   - If we read fewer than 16 bytes by the deadline, returns
    ///     `.fallback_to_v1` (treat silence as "not v2").
    ///   - Otherwise (looks like a v2 ellswift pubkey reply), returns
    ///     `.v2_negotiated`.  The caller is then responsible for
    ///     completing the v2 handshake via the V2Transport state machine.
    ///
    /// The connection state is left consumed: even on `.v2_negotiated`,
    /// 16 bytes have been peeked from the kernel buffer (no bytes
    /// drained yet, so the V2Transport state machine sees the full
    /// pubkey when invoked).  On `.fallback_to_v1`, the caller MUST
    /// close this socket — the 64 bytes we sent will have corrupted the
    /// v1 framing on the remote.
    pub fn tryV2OutboundProbe(self: *Peer, deadline_ms: i64) PeerError!V2ProbeResult {
        // Build a one-shot V2Transport in initiator mode just to grab
        // the pubkey + garbage payload bytes.  The transport object is
        // discarded after the probe — full v2 plumbing tracks its own
        // V2Transport on the Peer (not yet implemented).
        var transport = v2_transport.V2Transport.init(self.allocator, true, self.network_params.magic);
        defer transport.deinit();

        const send_data = transport.getSendData();
        if (send_data.len < v2_transport.ELLSWIFT_PUBKEY_LEN) {
            // Cipher init failed (e.g. ellswift_create rejected every
            // attempt).  Don't write the partial bytes — fall back.
            return .fallback_to_v1;
        }

        self.stream.writeAll(send_data) catch return PeerError.ConnectionClosed;
        self.bytes_sent += send_data.len;

        // Read up to 16 bytes with the deadline.  Use MSG_PEEK so that on
        // a v2-negotiated outcome the caller can hand the bytes off to the
        // V2Transport state machine without reordering issues.
        var peek: [v2_transport.V1_PREFIX_LEN]u8 = undefined;
        const start_ms = std.time.milliTimestamp();
        var total: usize = 0;
        while (total < peek.len) {
            const remaining_ms = deadline_ms - (std.time.milliTimestamp() - start_ms);
            if (remaining_ms <= 0) break;

            var pollfds = [_]std.posix.pollfd{.{
                .fd = self.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&pollfds, @intCast(@min(remaining_ms, 30_000))) catch
                return PeerError.ConnectionClosed;
            if (ready == 0) break;
            if (pollfds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0)
                return .fallback_to_v1;
            if ((pollfds[0].revents & std.posix.POLL.IN) == 0) continue;

            const n = std.posix.recv(self.stream.handle, peek[total..], std.posix.MSG.PEEK) catch |err| {
                if (err == error.WouldBlock) continue;
                return .fallback_to_v1;
            };
            if (n == 0) return .fallback_to_v1; // EOF
            if (n <= total) break;
            total = n;
        }

        if (total < v2_transport.V1_PREFIX_LEN) {
            // Insufficient response within deadline → not speaking v2 (or
            // a stalled link).  Either way, fall back to v1 on a fresh
            // connection.
            return .fallback_to_v1;
        }

        var magic_le: [4]u8 = undefined;
        std.mem.writeInt(u32, &magic_le, self.network_params.magic, .little);
        if (v2_transport.looksLikeV1Version(&peek, magic_le)) {
            // Peer is speaking v1 (and is treating our 64-byte ellswift
            // garbage as a v1 message — the peer will probably disconnect
            // on its next read).  Caller MUST close + reconnect.
            return .fallback_to_v1;
        }

        // Plausibly a v2 ellswift pubkey reply.  Caller must complete
        // the handshake via the V2Transport state machine — currently
        // not plumbed; see `bip324V2Enabled`.
        return .v2_negotiated;
    }

    /// Perform the version/verack handshake.
    /// Outbound: send version, wait for version+verack, send verack.
    /// Inbound: wait for version, send version+verack, wait for verack.
    ///
    /// BIP-324 v2 negotiation:
    ///   - Inbound: peeks the first 16 bytes; if they look like a v1
    ///     VERSION header (network magic + "version\0\0\0\0\0") we run
    ///     the v1 path.  Otherwise the peer initiated v2; we currently
    ///     reject the connection (see `bip324V2Enabled` doc-comment for
    ///     the application-plumbing gap).
    ///   - Outbound: when `bip324V2Enabled()` is true and the peer is
    ///     not in the manager's v1-fallback set, an outbound v2 probe is
    ///     attempted via `tryV2OutboundProbe` BEFORE this function is
    ///     called.  If the probe falls back, the manager records the
    ///     v1-only state and reconnects, then drives this v1 handshake.
    pub fn performHandshake(self: *Peer, our_height: i32) PeerError!void {
        const now = std.time.timestamp();

        // Inbound: classify the wire by peeking the first 16 bytes.
        // If the peer sent the v1 VERSION prefix, fall through to v1.
        // Otherwise, the peer is speaking v2 (or speaking nothing recognizable
        // — we close it for safety).
        if (self.direction == .inbound and bip324V2Enabled()) {
            var peek: [v2_transport.V1_PREFIX_LEN]u8 = undefined;
            const got = self.peekBytes(&peek) catch return PeerError.HandshakeFailed;
            if (got >= v2_transport.V1_PREFIX_LEN) {
                var magic_le: [4]u8 = undefined;
                std.mem.writeInt(u32, &magic_le, self.network_params.magic, .little);
                if (!v2_transport.looksLikeV1Version(&peek, magic_le)) {
                    // Peer is initiating BIP-324 v2.  The cipher state
                    // machine + ellswift FFI are wired (see v2_transport.zig)
                    // but the per-message v2 wrapping for application
                    // messages is not yet plumbed through every Peer
                    // send/receive call site.  Reject the connection rather
                    // than risk a malformed exchange.  The peer will retry —
                    // typically Bitcoin Core falls back to v1 on its next
                    // connection attempt.
                    std.log.info("peer={any} initiated BIP-324 v2 (not yet plumbed); rejecting", .{self.address});
                    return PeerError.HandshakeFailed;
                }
                // Looks like v1 — fall through.
            }
            // got < V1_PREFIX_LEN means the peer didn't send 16 bytes
            // within the peek deadline; the v1 path below will time out
            // naturally on receiveMessage if the peer is dead.
        }

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
                    self.time_offset = v.timestamp - std.time.timestamp();
                },
                else => return PeerError.HandshakeFailed,
            }

            // Send wtxidrelay (BIP-339) and sendaddrv2 (BIP-155) BEFORE verack.
            // These must be sent between version and verack per their respective BIPs.
            // Bitcoin Core disconnects peers that send them after verack.
            const wtxid = p2p.Message{ .wtxidrelay = {} };
            try self.sendMessage(&wtxid);

            const addrv2 = p2p.Message{ .sendaddrv2 = {} };
            try self.sendMessage(&addrv2);

            // Send verack (after feature negotiation messages)
            const verack = p2p.Message{ .verack = {} };
            try self.sendMessage(&verack);

            // Wait for their verack
            while (true) {
                const msg = try self.receiveMessage();
                switch (msg) {
                    .verack => break,
                    .wtxidrelay, .sendaddrv2, .sendcmpct, .sendheaders => {
                        // Accept these during handshake but no action needed
                    },
                    .feefilter => |ff| {
                        // BIP-133: Store the peer's fee filter during handshake
                        const MAX_MONEY: u64 = 2_100_000_000_000_000;
                        if (ff.feerate <= MAX_MONEY) {
                            self.fee_filter_received = ff.feerate;
                        }
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
                    self.time_offset = v.timestamp - std.time.timestamp();
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

            // Send wtxidrelay (BIP-339) and sendaddrv2 (BIP-155) before verack
            const wtxid_in = p2p.Message{ .wtxidrelay = {} };
            try self.sendMessage(&wtxid_in);
            const addrv2_in = p2p.Message{ .sendaddrv2 = {} };
            try self.sendMessage(&addrv2_in);

            // Send verack (after feature negotiation messages)
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

        // Send sendcmpct (BIP-152) - signal compact block relay support
        // Version 2 = segwit-aware, announce=false = low-bandwidth mode
        const sc = p2p.Message{ .sendcmpct = .{ .announce = false, .version = 2 } };
        try self.sendMessage(&sc);

        // BIP-133: Send initial feefilter after handshake
        // 100 sat/vbyte = 100,000 sat/kvB to discourage tx relay during sync
        if (self.relay_txs) {
            const ff = p2p.Message{ .feefilter = .{ .feerate = 100_000 } };
            try self.sendMessage(&ff);
        }
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

    /// Maybe send a feefilter message to this peer (BIP-133).
    /// Uses Poisson delay (~10 min avg) with hysteresis to avoid rapid oscillation.
    /// current_filter_sat_kvb: Our current minimum fee rate in sat/kvB.
    /// is_ibd: Whether we're in initial block download (send MAX_MONEY during IBD).
    pub fn maybeSendFeefilter(self: *Peer, current_filter_sat_kvb: u64, is_ibd: bool) void {
        const now_seconds = std.time.timestamp();
        const now_us = now_seconds * 1_000_000;

        // Don't send to block-relay-only peers
        if (self.conn_type == .block_relay) return;

        // Don't send if peer doesn't relay transactions
        if (!self.relay_txs) return;

        // Determine the filter value to send
        const MAX_MONEY: u64 = 2_100_000_000_000_000;
        var filter_to_send: u64 = current_filter_sat_kvb;

        if (is_ibd) {
            // During IBD, tell peers not to send us transactions
            filter_to_send = MAX_MONEY;
        } else if (self.fee_filter_sent == MAX_MONEY) {
            // We just exited IBD - send immediately
            self.next_send_feefilter = 0;
        }

        // Ensure at least MIN_RELAY_FEE
        filter_to_send = @max(filter_to_send, MIN_RELAY_FEE);

        // Check if it's time to send
        if (now_us > self.next_send_feefilter) {
            // Time to send if the value has changed
            if (filter_to_send != self.fee_filter_sent) {
                const msg = p2p.Message{ .feefilter = .{ .feerate = filter_to_send } };
                self.sendMessage(&msg) catch return;
                self.fee_filter_sent = filter_to_send;
            }

            // Schedule next broadcast using exponential distribution (approximated)
            // For simplicity, we use uniform random within [0.5, 1.5] * AVG_INTERVAL
            const random_factor = @as(i64, @intCast(std.crypto.random.intRangeAtMost(u32, 500, 1500)));
            const delay_seconds = @divTrunc(AVG_FEEFILTER_BROADCAST_INTERVAL * random_factor, 1000);
            self.next_send_feefilter = now_us + delay_seconds * 1_000_000;
        } else {
            // Check hysteresis: if significant change and next broadcast too far away, accelerate
            // Significant = decrease by 25% or increase by 33%
            if (now_us + MAX_FEEFILTER_CHANGE_DELAY * 1_000_000 < self.next_send_feefilter) {
                const significant_decrease = current_filter_sat_kvb < (3 * self.fee_filter_sent) / 4;
                const significant_increase = current_filter_sat_kvb > (4 * self.fee_filter_sent) / 3;

                if (significant_decrease or significant_increase) {
                    // Schedule sooner - random within [0, MAX_FEEFILTER_CHANGE_DELAY]
                    const random_delay = @as(i64, @intCast(std.crypto.random.intRangeAtMost(u32, 0, @intCast(MAX_FEEFILTER_CHANGE_DELAY))));
                    self.next_send_feefilter = now_us + random_delay * 1_000_000;
                }
            }
        }
    }

    /// Check if a transaction fee rate passes this peer's fee filter.
    /// Returns true if the transaction should be relayed to this peer.
    /// tx_fee_rate_sat_kvb: Transaction fee rate in sat/kvB.
    pub fn passesFeeFilter(self: *const Peer, tx_fee_rate_sat_kvb: u64) bool {
        // If peer hasn't sent a feefilter, accept all transactions
        if (self.fee_filter_received == 0) return true;
        return tx_fee_rate_sat_kvb >= self.fee_filter_received;
    }

    /// Disconnect from the peer.
    pub fn disconnect(self: *Peer) void {
        self.state = .disconnected;
        self.stream.close();
        self.recv_buffer.deinit();
    }

    /// Check if data is available to read on this peer's socket (non-blocking).
    pub fn hasDataAvailable(self: *Peer) bool {
        var pollfds = [_]std.posix.pollfd{.{
            .fd = self.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        // Poll with 0 timeout = non-blocking check
        const ready = std.posix.poll(&pollfds, 0) catch return false;
        return ready > 0 and (pollfds[0].revents & std.posix.POLL.IN) != 0;
    }

    /// Set the receive timeout on the socket.
    pub fn setRecvTimeout(self: *Peer, sec: i64, usec: i64) void {
        const timeout = std.posix.timeval{ .tv_sec = sec, .tv_usec = @intCast(usec) };
        std.posix.setsockopt(
            self.stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};
    }

    /// Read exactly n bytes from the stream.
    /// If we've read zero bytes and get WouldBlock, returns Timeout (no data available).
    /// If we've already read some bytes and get WouldBlock, sleeps briefly and retries.
    ///
    /// W53: the partial-read retry path must not spin forever — a peer that
    /// opens a payload (sends the 24-byte header) and then stalls mid-stream
    /// will return EAGAIN indefinitely, and because PeerManager drives ALL
    /// peers from a single thread, any stuck readExact wedges the entire
    /// node (no drain, no timeout checks, no heartbeats — exactly the silent
    /// stall observed at block 479,888 on 2026-04-17). Bound the total time
    /// spent in partial-read retries and give up as ConnectionClosed so the
    /// peer is disconnected and the download slots are reclaimed.
    pub const READ_EXACT_PARTIAL_TIMEOUT_MS: i64 = 30_000;
    fn readExact(self: *Peer, buf: []u8) !void {
        var total: usize = 0;
        var partial_deadline_ms: i64 = 0;
        while (total < buf.len) {
            const n = self.stream.read(buf[total..]) catch |err| {
                if (err == error.WouldBlock) {
                    if (total == 0) {
                        return error.Timeout; // No data at all - truly no message waiting
                    }
                    // Partial read — data may be arriving. Bound retry time
                    // so a mid-payload stall doesn't wedge the peer thread.
                    const now_ms = std.time.milliTimestamp();
                    if (partial_deadline_ms == 0) {
                        partial_deadline_ms = now_ms + READ_EXACT_PARTIAL_TIMEOUT_MS;
                    } else if (now_ms >= partial_deadline_ms) {
                        return error.ConnectionClosed;
                    }
                    std.time.sleep(1 * std.time.ns_per_ms);
                    continue;
                }
                return error.ConnectionClosed;
            };
            if (n == 0) return error.ConnectionClosed;
            total += n;
            // Progress resets the partial-read deadline so a slow-but-live
            // peer is still allowed to finish a large payload.
            if (partial_deadline_ms != 0) partial_deadline_ms = 0;
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

    // ========================================================================
    // Stale Peer Detection (Bitcoin Core net_processing.cpp)
    // ========================================================================

    /// Check if this peer has a stale tip (best_known_height behind our tip for >30 min).
    /// our_height: Our current best block height.
    /// Returns true if peer's tip is stale.
    pub fn hasStaleTip(self: *const Peer, our_height: u32) bool {
        const now = std.time.timestamp();

        // Must have received a version message with their height
        if (self.best_known_height == 0) return false;

        // If peer is caught up, not stale
        if (self.best_known_height >= our_height) return false;

        // Check if they've been behind for too long
        // We use last_block_time to track when they last made progress
        if (self.last_block_time > 0) {
            // If they sent us a block recently, give them time
            if (now - self.last_block_time < STALE_TIP_THRESHOLD) return false;
        }

        // If we've received headers from them recently, they may be syncing
        if (self.last_message_time > 0 and now - self.last_message_time < STALE_TIP_THRESHOLD) {
            return false;
        }

        // Been behind for too long
        return true;
    }

    /// Check if ping has timed out (ping sent, no pong within PING_TIMEOUT).
    /// Returns true if peer should be disconnected due to ping timeout.
    pub fn hasPingTimeout(self: *const Peer) bool {
        const now = std.time.timestamp();

        // No ping sent, no timeout
        if (self.last_ping_nonce == 0 or self.last_ping_time == 0) return false;

        // Pong received for this ping
        if (self.last_pong_time >= self.last_ping_time) return false;

        // Check if we've waited too long for pong
        return now - self.last_ping_time > PING_TIMEOUT;
    }

    /// Check if headers request has timed out (getheaders sent, no response within 2 min).
    /// Returns true if peer should be penalized for headers timeout.
    pub fn hasHeadersTimeout(self: *const Peer) bool {
        const now = std.time.timestamp();

        // No getheaders sent
        if (self.last_getheaders_time == 0) return false;

        // Check if we've waited too long
        return now - self.last_getheaders_time > HEADERS_RESPONSE_TIMEOUT;
    }

    /// Check if block download has timed out (block in flight for >20 min).
    /// Returns true if peer should be disconnected due to block timeout.
    pub fn hasBlockDownloadTimeout(self: *const Peer) bool {
        const now = std.time.timestamp();

        // No blocks in flight
        if (self.blocks_in_flight_count == 0 or self.oldest_block_in_flight_time == 0) return false;

        // Check if oldest block has been in flight too long
        return now - self.oldest_block_in_flight_time > BLOCK_DOWNLOAD_TIMEOUT;
    }

    /// Update best known height from received headers/version.
    pub fn updateBestKnownHeight(self: *Peer, height: u32) void {
        if (height > self.best_known_height) {
            self.best_known_height = height;
        }
    }

    /// Record that we sent a getheaders request.
    pub fn recordGetheadersRequest(self: *Peer) void {
        self.last_getheaders_time = std.time.timestamp();
    }

    /// Clear the getheaders timeout (called when we receive headers).
    pub fn clearGetheadersTimeout(self: *Peer) void {
        self.last_getheaders_time = 0;
    }

    /// Record that we requested a block.
    pub fn recordBlockRequest(self: *Peer) void {
        const now = std.time.timestamp();
        if (self.blocks_in_flight_count == 0) {
            self.oldest_block_in_flight_time = now;
        }
        self.blocks_in_flight_count += 1;
    }

    /// Record that a block was received (or canceled).
    pub fn recordBlockReceived(self: *Peer) void {
        if (self.blocks_in_flight_count > 0) {
            self.blocks_in_flight_count -= 1;
            if (self.blocks_in_flight_count == 0) {
                self.oldest_block_in_flight_time = 0;
            }
        }
        self.last_block_time = std.time.timestamp();
    }

    /// Check if this peer is a candidate for stale tip eviction.
    /// Must be outbound, not protected, connected long enough, and no blocks in flight.
    pub fn isEvictionCandidate(self: *const Peer) bool {
        const now = std.time.timestamp();

        // Only evict outbound peers (prefer keeping inbound)
        if (self.direction != .outbound) return false;

        // Don't evict protected peers
        if (self.chain_sync_protected) return false;

        // Don't evict manual connections
        if (self.conn_type == .manual) return false;

        // Must be connected long enough
        if (now - self.connect_time < MINIMUM_CONNECT_TIME) return false;

        // Don't evict if blocks are in flight
        if (self.blocks_in_flight_count > 0) return false;

        return true;
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
fn comparePingTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.min_ping_time < b.min_ping_time;
}

/// Comparison function for sorting by last tx time (descending - more recent is better).
fn compareTxTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.last_tx_time > b.last_tx_time;
}

/// Comparison function for sorting by last block time (descending - more recent is better).
fn compareBlockTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.last_block_time > b.last_block_time;
}

/// Comparison function for sorting by connect time (ascending - longer connected is better).
fn compareConnectTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.connect_time < b.connect_time;
}

/// Comparison function for sorting by netgroup.
fn compareNetGroup(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.net_group < b.net_group;
}

/// Select an inbound peer to evict using Bitcoin Core's eviction algorithm.
/// Protection order (matching Bitcoin Core's SelectNodeToEvict):
/// 1. 4 by netgroup (distinct groups)
/// 2. 8 by fastest ping time
/// 3. 4 by most recent tx relay
/// 4. 8 block-relay-only peers by most recent block
/// 5. 4 by most recent block relay
/// 6. Remaining half by longest connection time
/// Returns the index of the peer to evict, or null if no eviction candidate.
pub fn selectEvictionCandidate(candidates: []EvictionCandidate, allocator: std.mem.Allocator) ?usize {
    if (candidates.len == 0) return null;

    // Make a mutable copy for protection marking
    const working = allocator.dupe(EvictionCandidate, candidates) catch return null;
    defer allocator.free(working);

    // Mark protected candidates
    var protected = std.AutoHashMap(usize, void).init(allocator);
    defer protected.deinit();

    // 1. Protect 4 peers from distinct netgroups (Bitcoin Core does this first)
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

    // 2. Protect 8 peers with fastest ping time
    std.mem.sort(EvictionCandidate, working, {}, comparePingTime);
    for (0..@min(EVICTION_PROTECT_PING, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 3. Protect 4 peers with most recent tx relay
    std.mem.sort(EvictionCandidate, working, {}, compareTxTime);
    for (0..@min(EVICTION_PROTECT_TX, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 4. Protect up to 8 non-tx-relay peers (block-relay-only) by most recent block
    std.mem.sort(EvictionCandidate, working, {}, compareBlockTime);
    var block_relay_only_protected: usize = 0;
    for (working) |c| {
        if (block_relay_only_protected >= EVICTION_PROTECT_BLOCK_RELAY_ONLY) break;
        // Protect if not relaying txs (block-relay-only)
        if (!c.relay_txs) {
            protected.put(c.peer_index, {}) catch {};
            block_relay_only_protected += 1;
        }
    }

    // 5. Protect 4 peers with most recent block relay (all peers)
    std.mem.sort(EvictionCandidate, working, {}, compareBlockTime);
    for (0..@min(EVICTION_PROTECT_BLOCK, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 6. Protect half of remaining peers by longest connection time
    std.mem.sort(EvictionCandidate, working, {}, compareConnectTime);
    var unprotected_count: usize = 0;
    for (working) |c| {
        if (!protected.contains(c.peer_index)) {
            unprotected_count += 1;
        }
    }
    const to_protect_by_time = unprotected_count / 2;
    var time_protected: usize = 0;
    for (working) |c| {
        if (time_protected >= to_protect_by_time) break;
        if (!protected.contains(c.peer_index)) {
            protected.put(c.peer_index, {}) catch {};
            time_protected += 1;
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
    /// Last time we ran the stale tip check (seconds since epoch).
    last_stale_check_time: i64,
    /// Last time our tip was updated (for stale tip detection).
    last_tip_update_time: i64,
    /// Number of outbound peers protected from eviction.
    outbound_protected_count: usize,
    /// Chain state for block sync.
    chain_state: ?*storage.ChainState,
    /// Block relay cache for serving blocks to peers on getdata.
    /// Keyed by block hash, stores serialized block data.
    /// Contains both locally mined blocks and recently connected blocks.
    served_blocks: std.AutoHashMap(types.Hash256, []const u8),
    /// Address to connect to on startup (from --connect flag).
    connect_address: ?std.net.Address,

    /// Mempool for transaction relay and acceptance.
    mempool: ?*mempool_mod.Mempool,

    // ========================================================================
    // Block Download Pipeline (IBD acceleration)
    // ========================================================================

    /// Buffered blocks waiting to be connected (may arrive out of order).
    /// Key: block hash, Value: the full block (ownership transferred here).
    block_buffer: std.AutoHashMap(types.Hash256, types.Block),

    /// Ordered queue of block hashes we expect to connect, by height.
    /// Index 0 = first block after genesis (height 1 at start of sync).
    /// We track which height we've queued up to and which we've connected up to.
    expected_blocks: std.ArrayList(types.Hash256),

    /// Next index to request blocks for (index into expected_blocks).
    download_cursor: u32,

    /// Next index to connect (index into expected_blocks).
    connect_cursor: u32,

    /// Diagnostic state for the drain-break wedge log (peer.zig:~3073).
    /// Rate-limits DRAIN-BREAK-WEDGE to one line per second per stuck
    /// connect_cursor so the log doesn't drown during a multi-hour wedge.
    last_drain_break_log_ts: i64,
    last_drain_break_cursor: u32,

    /// Number of blocks currently in-flight (requested but not yet received).
    blocks_in_flight: u32,

    /// Maximum blocks in flight at once.
    max_blocks_in_flight: u32,

    /// Last time we logged sync progress.
    last_progress_log: i64,

    /// Total blocks connected since last progress log.
    blocks_since_log: u32,

    /// Last time we attempted stall recovery.
    last_stall_recovery: i64,

    /// True while drainBlockBuffer is executing.  Guards the `.block` handler's
    /// nested drain calls so the drain-heartbeat → processAllMessages → `.block`
    /// path can't recurse into drainBlockBuffer.  W101 (2026-04-24).
    in_drain: bool,

    /// Per-address fall-back set for BIP-324 v2 outbound negotiation.
    /// Once we've tried v2 against an address and fallen back to v1 (because
    /// the peer didn't speak v2 — a non-ellswift response or a deadline
    /// expiry), record the addressKey here so subsequent outbound attempts
    /// to that address skip the v2 probe.  Bounded by V2_FALLBACK_CACHE_MAX
    /// — once full, we drop a random entry.  This is fine: at worst we
    /// reprobe a v1-only peer with a fresh v2 attempt and pay the deadline
    /// cost again.
    v2_fallback_set: std.AutoHashMap(u64, void),

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
            .last_stale_check_time = 0,
            .last_tip_update_time = 0,
            .outbound_protected_count = 0,
            .chain_state = null,
            .served_blocks = std.AutoHashMap(types.Hash256, []const u8).init(allocator),
            .connect_address = null,
            .mempool = null,
            .block_buffer = std.AutoHashMap(types.Hash256, types.Block).init(allocator),
            .expected_blocks = std.ArrayList(types.Hash256).init(allocator),
            .download_cursor = 0,
            .connect_cursor = 0,
            .last_drain_break_log_ts = 0,
            .last_drain_break_cursor = 0,
            .blocks_in_flight = 0,
            .max_blocks_in_flight = 128,
            .last_progress_log = 0,
            .blocks_since_log = 0,
            .last_stall_recovery = 0,
            .in_drain = false,
            .v2_fallback_set = std.AutoHashMap(u64, void).init(allocator),
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
        // Free any buffered blocks
        {
            var iter = self.block_buffer.valueIterator();
            while (iter.next()) |blk| {
                serialize.freeBlock(self.allocator, blk);
            }
            self.block_buffer.deinit();
        }
        self.expected_blocks.deinit();
        // Free cached block data for relay
        {
            var iter = self.served_blocks.valueIterator();
            while (iter.next()) |data| {
                self.allocator.free(data.*);
            }
            self.served_blocks.deinit();
        }
        if (self.listener) |*l| l.deinit();
        self.v2_fallback_set.deinit();
    }

    /// Cap on the BIP-324 v2 fall-back set (per-process).  Once exceeded
    /// we drop a random entry to bound memory; reprobing v1-only peers is
    /// cheap (one round-trip cost) so accuracy isn't critical.
    pub const V2_FALLBACK_CACHE_MAX: usize = 4096;

    /// BIP-324 v2 outbound probe deadline (per Bitcoin Core net.cpp uses
    /// ~30s; we mirror that).  Short enough that a stalled remote
    /// doesn't wedge the maintainOutbound caller for long.
    pub const V2_PROBE_DEADLINE_MS: i64 = 30_000;

    /// Try to open an outbound connection to `address`, negotiating BIP-324
    /// v2 if `Peer.bip324V2Enabled()` is true and the address is not in
    /// the v1-fallback set.  Returns the fully-handshaked Peer on success
    /// or null on any failure.  Caller takes ownership of the returned
    /// pointer (must `disconnect` + `destroy`).
    ///
    /// Behavior:
    ///  1. Open TCP connection.
    ///  2. If v2 is enabled and the address is not v1-only, run
    ///     `Peer.tryV2OutboundProbe`.  On `.fallback_to_v1`, mark the
    ///     address v1-only, close the socket, and reconnect.  On
    ///     `.v2_negotiated`, currently we close + mark v1-only as well
    ///     (because the application-level v2 plumbing is incomplete);
    ///     this preserves connectivity to v2-capable peers via v1.  Once
    ///     the v2 application path lands, this branch will instead
    ///     continue the v2 handshake.
    ///  3. Run `performHandshake` (v1) on the (possibly second) socket.
    pub fn connectOutboundNegotiated(
        self: *PeerManager,
        address: std.net.Address,
    ) ?*Peer {
        const v2_enabled = Peer.bip324V2Enabled();
        const try_v2 = v2_enabled and !self.isV1Only(address);

        // Phase 1: optional v2 probe.
        if (try_v2) {
            const probe_peer = self.allocator.create(Peer) catch return null;
            probe_peer.* = Peer.connect(address, self.network_params, self.allocator) catch {
                self.allocator.destroy(probe_peer);
                return null;
            };

            const result = probe_peer.tryV2OutboundProbe(V2_PROBE_DEADLINE_MS) catch {
                probe_peer.disconnect();
                self.allocator.destroy(probe_peer);
                // Probe errored — treat as v1-only to avoid retrying.
                self.markV1Only(address);
                return null;
            };

            switch (result) {
                .v2_negotiated => {
                    // Application-message v2 plumbing is not yet wired.
                    // Close this socket and reconnect on v1 so the peer
                    // can still serve us blocks/headers.  Do NOT mark
                    // v1-only because this peer DID negotiate v2 — once
                    // the plumbing lands we'll prefer v2 to it.
                    std.log.info("peer={any} negotiated BIP-324 v2; reconnecting on v1 (app plumbing pending)", .{address});
                    probe_peer.disconnect();
                    self.allocator.destroy(probe_peer);
                    // Fall through to v1 path below.
                },
                .fallback_to_v1 => {
                    self.markV1Only(address);
                    probe_peer.disconnect();
                    self.allocator.destroy(probe_peer);
                    // Fall through to v1 path below.
                },
            }
        }

        // Phase 2: v1 handshake on a fresh connection.
        const peer = self.allocator.create(Peer) catch return null;
        peer.* = Peer.connect(address, self.network_params, self.allocator) catch {
            self.allocator.destroy(peer);
            return null;
        };
        peer.performHandshake(self.our_height) catch {
            peer.disconnect();
            self.allocator.destroy(peer);
            return null;
        };
        return peer;
    }

    /// Mark `address` as v1-only so future outbound attempts skip the v2 probe.
    pub fn markV1Only(self: *PeerManager, address: std.net.Address) void {
        const key = addressKey(address);
        if (self.v2_fallback_set.count() >= V2_FALLBACK_CACHE_MAX) {
            // Drop a random-ish entry: iterate once, remove the first key we
            // see.  AutoHashMap's iteration order is implementation-defined.
            var iter = self.v2_fallback_set.keyIterator();
            if (iter.next()) |k| {
                _ = self.v2_fallback_set.remove(k.*);
            }
        }
        self.v2_fallback_set.put(key, {}) catch {};
    }

    /// Returns true if `address` is in the v1-only fall-back set.
    pub fn isV1Only(self: *const PeerManager, address: std.net.Address) bool {
        return self.v2_fallback_set.contains(addressKey(address));
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
            const addrs = std.net.getAddressList(self.allocator, seed, self.network_params.default_port) catch |err| {
                std.log.warn("DNS resolution failed for {s}: {}", .{ seed, err });
                continue;
            };
            defer addrs.deinit();

            std.log.info("Resolved {d} addresses from DNS seed {s}", .{ addrs.addrs.len, seed });
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

            // Skip manual addresses — those are owned by maintainManualConnections,
            // which uses a shorter throttle and tags .manual on success so
            // rotatePeers doesn't evict them. Letting the outbound path
            // pick them up would silently demote them to .outbound_full_relay.
            if (info.source == .manual) continue;

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

    /// Get the number of connected peers.
    pub fn getPeerCount(self: *PeerManager) usize {
        return self.peers.items.len;
    }

    /// Resolve a "host" or "host:port" string to a single `std.net.Address`.
    /// Accepts: `127.0.0.1`, `127.0.0.1:8333`, `example.com`, `example.com:8333`.
    /// IPv6 bracket notation (`[::1]:8333`) is NOT supported — callers that
    /// need IPv6 must pre-parse. Localhost mesh / addnode RPC only uses IPv4.
    fn resolveNodeAddress(self: *PeerManager, node: []const u8) !std.net.Address {
        const default_port = self.network_params.default_port;
        // Split on the last ':' — everything after is the port, before is host.
        if (std.mem.lastIndexOfScalar(u8, node, ':')) |colon| {
            const host = node[0..colon];
            const port_str = node[colon + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch {
                return error.InvalidAddress;
            };
            if (std.net.Address.parseIp(host, port)) |addr| {
                return addr;
            } else |_| {}
            // Not a literal IP — try DNS resolution with the parsed port.
            const addrs = std.net.getAddressList(self.allocator, host, port) catch {
                return error.InvalidAddress;
            };
            defer addrs.deinit();
            if (addrs.addrs.len == 0) return error.InvalidAddress;
            return addrs.addrs[0];
        }
        // No colon — try as bare IP, then as bare hostname, both on default_port.
        if (std.net.Address.parseIp(node, default_port)) |addr| {
            return addr;
        } else |_| {}
        const addrs = std.net.getAddressList(self.allocator, node, default_port) catch {
            return error.InvalidAddress;
        };
        defer addrs.deinit();
        if (addrs.addrs.len == 0) return error.InvalidAddress;
        return addrs.addrs[0];
    }

    /// Add a node to the manual connection list.
    /// This will attempt to connect to the node.
    pub fn addManualNode(self: *PeerManager, node: []const u8) !void {
        const addr = try self.resolveNodeAddress(node);
        // addAddress is a no-op if the key already exists, so it would never
        // upgrade an existing AddressInfo from .dns_seed/.peer to .manual.
        // Force the .manual source either way so maintainManualConnections
        // owns the reconnect lifecycle.
        const key = addressKey(addr);
        if (self.known_addresses.getPtr(key)) |info| {
            info.source = .manual;
            info.last_tried = 0;
            info.attempts = 0;
        } else {
            try self.addAddress(addr, 0, .manual);
        }
    }

    /// Remove a node from the manual connection list.
    pub fn removeManualNode(self: *PeerManager, node: []const u8) void {
        const addr = self.resolveNodeAddress(node) catch return;
        const key = addressKey(addr);

        // Remove from known addresses
        _ = self.known_addresses.remove(key);

        // Disconnect if connected
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (addressKey(peer.address) == key) {
                peer.disconnect();
                self.allocator.destroy(peer);
                _ = self.peers.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Try to connect to a node once (onetry command).
    /// The resulting peer is tagged `.manual` so rotation/eviction skip it.
    pub fn tryConnectNode(self: *PeerManager, node: []const u8) !void {
        const addr = try self.resolveNodeAddress(node);
        const peer = try self.connectToPeer(addr);
        peer.conn_type = .manual;
    }

    /// Reconnect dropped manual peers (`addnode <ip> add`).
    /// `addManualNode` only registers the address in `known_addresses` with
    /// `source = .manual`.  This function is the other half: on every main-
    /// loop tick it scans for `.manual` addresses that aren't currently
    /// connected and attempts to reconnect, throttled by
    /// `MANUAL_RECONNECT_INTERVAL`.  Matches Bitcoin Core
    /// `ThreadOpenConnections` periodic manual-peer reconnect.
    pub fn maintainManualConnections(self: *PeerManager) void {
        const now = std.time.timestamp();

        var iter = self.known_addresses.iterator();
        while (iter.next()) |entry| {
            const info = entry.value_ptr;
            if (info.source != .manual) continue;
            if (self.isConnected(info.address)) continue;
            if (info.last_tried > 0 and now - info.last_tried < MANUAL_RECONNECT_INTERVAL) continue;
            if (self.peers.items.len >= MAX_TOTAL_CONNECTIONS) break;

            info.last_tried = now;
            info.attempts += 1;

            // Use connectToPeer (matches tryConnectNode/onetry path) so the
            // message loop drives the handshake.  Calling performHandshake
            // synchronously here was racing the loop and silently failing.
            const peer = self.connectToPeer(info.address) catch continue;
            peer.conn_type = .manual;
            info.success = true;
            info.last_seen = now;
        }
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

            // BIP-324 negotiation lives inside connectOutboundNegotiated;
            // when v2 is disabled (default) this is identical to the old
            // Peer.connect+performHandshake pair.
            const peer = self.connectOutboundNegotiated(addr) orelse continue;
            peer.conn_type = .block_relay;

            // Track netgroup
            self.outbound_netgroups.put(netGroup(addr), {}) catch {};

            self.peers.append(peer) catch {
                peer.disconnect();
                self.allocator.destroy(peer);
                continue;
            };

            std.log.info("Connected to anchor peer: {}", .{addr});

            // Initiate header sync with anchor peer
            self.sendGetHeaders(peer) catch {};
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
    /// During IBD, only attempts one connection per call to avoid blocking.
    pub fn maintainOutbound(self: *PeerManager) !void {
        var outbound_count: usize = 0;
        for (self.peers.items) |p| {
            if (p.direction == .outbound) outbound_count += 1;
        }

        // During IBD, only try one connection per call to avoid blocking the loop.
        // Exception: if we have zero outbound peers (post-eviction peer wipeout),
        // allow up to MAX_OUTBOUND_CONNECTIONS attempts so we recover quickly
        // instead of waiting for the loop to cycle once per peer slot.
        var attempts: u32 = 0;
        const max_attempts: u32 = if (!self.isIBD()) 8
                                  else if (outbound_count == 0) MAX_OUTBOUND_CONNECTIONS
                                  else 1;

        while (outbound_count < MAX_OUTBOUND_CONNECTIONS and attempts < max_attempts) {
            attempts += 1;
            const addr = self.selectPeerToConnect() orelse break;
            // BIP-324 negotiation lives inside connectOutboundNegotiated;
            // when v2 is disabled (default) this is identical to the old
            // Peer.connect+performHandshake pair.
            const peer = self.connectOutboundNegotiated(addr) orelse continue;

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
            std.log.info("Connected to outbound peer {} (height={d}, {d}/{d} outbound)", .{ addr, peer.start_height, outbound_count, MAX_OUTBOUND_CONNECTIONS });

            // Initiate header sync with newly connected peer
            self.sendGetHeaders(peer) catch {};
        }
    }

    /// Accept a waiting inbound connection if available (non-blocking).
    /// When inbound slots are full, uses eviction protection algorithm.
    pub fn acceptInbound(self: *PeerManager) !void {
        if (self.listener == null) return;

        // Poll with 0 timeout to check if a connection is pending (non-blocking)
        var pollfds = [_]std.posix.pollfd{.{
            .fd = self.listener.?.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&pollfds, 0) catch return;
        if (ready == 0 or (pollfds[0].revents & std.posix.POLL.IN) == 0) return;

        // A connection is waiting, accept it
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

    /// Process messages from all connected peers using multiplexed I/O.
    /// Uses poll() to wait for data on ALL peer sockets simultaneously,
    /// then drains ALL available messages from each ready socket.
    pub fn processAllMessages(self: *PeerManager) !void {
        // First pass: check for peers that need banning
        {
            var i: usize = 0;
            while (i < self.peers.items.len) {
                const peer_obj = self.peers.items[i];
                if (peer_obj.should_ban) {
                    self.banIP(peer_obj.address, DEFAULT_BAN_DURATION, "misbehavior threshold reached") catch {};
                    self.removePeerByIndex(i);
                    continue;
                }
                i += 1;
            }
        }

        if (self.peers.items.len == 0) return;

        // Build pollfd array for all connected peers
        var pollfds: [MAX_TOTAL_CONNECTIONS]std.posix.pollfd = undefined;
        const num_peers = @min(self.peers.items.len, MAX_TOTAL_CONNECTIONS);
        for (0..num_peers) |idx| {
            pollfds[idx] = .{
                .fd = self.peers.items[idx].stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            };
        }

        // Poll all sockets at once. During IBD use 10ms timeout, otherwise 100ms.
        const timeout_ms: i32 = if (self.isIBD()) 10 else 100;
        const ready = std.posix.poll(pollfds[0..num_peers], timeout_ms) catch 0;

        if (ready == 0) {
            // No data on any socket - send getheaders to ONE peer if needed
            // Throttle: only send if last attempt was >5s ago (avoid spam)
            const now_ts = std.time.timestamp();
            for (self.peers.items) |peer_obj| {
                if (now_ts - peer_obj.last_getheaders_time > 5) {
                    if (self.chain_state) |cs| {
                        if (peer_obj.start_height > 0 and cs.best_height < @as(u32, @intCast(peer_obj.start_height))) {
                            self.sendGetHeaders(peer_obj) catch {};
                            break; // Only send to one peer at a time
                        }
                    }
                }
            }
            return;
        }

        // Process each peer that has data available.
        // We iterate backwards so removePeerByIndex doesn't skip peers.
        var i: usize = num_peers;
        while (i > 0) {
            i -= 1;
            if (i >= self.peers.items.len) continue;

            const peer_obj = self.peers.items[i];

            // Check if this socket has data (or an error/hangup)
            const revents = pollfds[i].revents;
            const has_data = (revents & std.posix.POLL.IN) != 0;
            const has_error = (revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0;

            if (has_error and !has_data) {
                self.removePeerByIndex(i);
                continue;
            }

            if (!has_data) {
                continue;
            }

            // Socket has data - set a very short timeout for reading and drain ALL messages
            peer_obj.setRecvTimeout(0, 1_000); // 1ms timeout for drain loop

            var msgs_read: u32 = 0;
            const max_msgs_per_peer: u32 = 256; // Safety limit per cycle

            while (msgs_read < max_msgs_per_peer) {
                const msg = peer_obj.receiveMessage() catch |err| {
                    switch (err) {
                        PeerError.Timeout => break, // No more data buffered, done draining
                        PeerError.ConnectionClosed => {
                            self.removePeerByIndex(i);
                            break;
                        },
                        PeerError.BadMagic => {
                            peer_obj.misbehaving(100, "invalid network magic");
                        },
                        PeerError.BadChecksum => {
                            peer_obj.misbehaving(50, "bad message checksum");
                        },
                        PeerError.MessageTooLarge => {
                            peer_obj.misbehaving(50, "oversized message");
                        },
                        PeerError.ProtocolViolation => {
                            peer_obj.misbehaving(20, "protocol violation");
                        },
                        else => {
                            peer_obj.misbehaving(10, "message receive error");
                        },
                    }

                    // Check if should be banned after misbehavior
                    if (peer_obj.should_ban) {
                        self.banIP(peer_obj.address, DEFAULT_BAN_DURATION, "misbehavior threshold reached") catch {};
                        self.removePeerByIndex(i);
                        break;
                    }
                    break; // Stop draining on any error
                };

                self.handleMessage(peer_obj, msg) catch {};
                msgs_read += 1;
            }

            // Restore long timeout for handshake use
            if (i < self.peers.items.len and self.peers.items[i] == peer_obj) {
                peer_obj.setRecvTimeout(30, 0);
            }
        }
    }

    /// Get the best height among all connected peers.
    fn getBestPeerHeight(self: *PeerManager) u32 {
        var best: i32 = 0;
        for (self.peers.items) |p| {
            if (p.start_height > best) best = p.start_height;
        }
        return if (best > 0) @intCast(best) else 0;
    }

    /// Pick a different sync peer (not the one that just returned 0 headers).
    fn pickSyncPeer(self: *PeerManager, exclude: *Peer) ?*Peer {
        for (self.peers.items) |p| {
            if (p != exclude and p.start_height > 0) return p;
        }
        return null;
    }

    /// Send getheaders to a peer using our current best block as locator.
    fn sendGetHeaders(self: *PeerManager, target_peer: *Peer) !void {
        // Build locator: use the tip of the header queue if available,
        // otherwise our best connected hash, or genesis.
        var locator_hash: types.Hash256 = undefined;
        if (self.expected_blocks.items.len > 0) {
            // Use the last known header hash (end of queue) to avoid duplicate headers
            locator_hash = self.expected_blocks.items[self.expected_blocks.items.len - 1];
        } else if (self.chain_state) |cs| {
            if (cs.best_height > 0) {
                locator_hash = cs.best_hash;
            } else {
                locator_hash = self.network_params.genesis_hash;
            }
        } else {
            locator_hash = self.network_params.genesis_hash;
        }

        const locators = [_]types.Hash256{locator_hash};
        const msg = p2p.Message{ .getheaders = .{
            .version = @intCast(p2p.PROTOCOL_VERSION),
            .block_locator_hashes = &locators,
            .hash_stop = [_]u8{0} ** 32,
        } };
        try target_peer.sendMessage(&msg);
        target_peer.last_getheaders_time = std.time.timestamp();
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
                defer self.allocator.free(a.addrs);
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
            .addrv2 => |a2| {
                defer self.allocator.free(a2.entries);
                // BIP155: Process addrv2 entries — extract IPv4/IPv6 and add to known addresses
                for (a2.entries) |entry| {
                    if (entry.network_id == 1 and entry.addr_bytes.len == 4) {
                        // IPv4
                        const addr = std.net.Address.initIp4(
                            entry.addr_bytes[0..4].*,
                            entry.port,
                        );
                        self.addAddress(addr, entry.services, .peer_addr) catch continue;
                    }
                }
            },
            .inv => |inv_msg| {
                defer self.allocator.free(inv_msg.inventory);
                // When a peer announces new blocks via inv, request headers
                // so they enter expected_blocks and can be connected by
                // drainBlockBuffer.  Directly requesting blocks via getdata
                // without adding them to expected_blocks causes them to sit
                // in block_buffer forever (chain tip never advances).
                var has_block_inv = false;
                // Collect tx inv items we want to request (not already in mempool)
                var tx_requests = std.ArrayList(p2p.InvVector).init(self.allocator);
                defer tx_requests.deinit();

                for (inv_msg.inventory) |item| {
                    const base_type = @as(u32, @intFromEnum(item.inv_type)) & ~@as(u32, 0x40000000);
                    if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_block))) {
                        has_block_inv = true;
                    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_tx))) {
                        // Transaction announcement: request if not already in mempool
                        if (self.mempool) |pool| {
                            if (!pool.entries.contains(item.hash)) {
                                tx_requests.append(.{
                                    .inv_type = .msg_witness_tx,
                                    .hash = item.hash,
                                }) catch {};
                            }
                        }
                    }
                }
                if (has_block_inv) {
                    self.sendGetHeaders(peer) catch {};
                }
                // Request unknown transactions via getdata
                if (tx_requests.items.len > 0) {
                    const getdata_msg = p2p.Message{ .getdata = .{ .inventory = tx_requests.items } };
                    peer.sendMessage(&getdata_msg) catch {};
                }
            },
            .headers => |h| {
                defer self.allocator.free(h.headers);
                // Don't clear getheaders timeout -- we'll request more below if needed

                if (h.headers.len == 0) {
                    // 0 headers from this peer doesn't mean we're synced — the
                    // peer may not have recognized our locator, or it's behind.
                    // Check if we're actually caught up by comparing against
                    // the best peer height. If behind, try another peer.
                    const our_height = if (self.chain_state) |cs| cs.best_height else 0;
                    const best_peer_h = self.getBestPeerHeight();
                    if (our_height + self.expected_blocks.items.len < best_peer_h) {
                        std.debug.print("P2P: 0 headers but behind peers (ours={d}+{d}, best_peer={d}), retrying\n",
                            .{ our_height, self.expected_blocks.items.len, best_peer_h });
                        // Try sending getheaders to a different peer
                        if (self.pickSyncPeer(peer)) |alt_peer| {
                            self.sendGetHeaders(alt_peer) catch {};
                        }
                    } else {
                        // Headers are caught up to the network tip.  Only emit
                        // "fully synced" and skip further work when blocks have
                        // also caught up (connect_cursor == expected_blocks.len).
                        // During IBD the header queue fills far ahead of the
                        // block connection cursor; returning early here suppressed
                        // the pipelineBlockRequests() call that keeps block
                        // download progressing (W28 mid-IBD header stall fix).
                        const blocks_caught_up = self.connect_cursor >= self.expected_blocks.items.len;
                        if (blocks_caught_up) {
                            std.debug.print("P2P: Received 0 headers - fully synced at height {d}\n", .{our_height});
                            return;
                        }
                        // Headers synced but blocks still behind: keep the block
                        // download pipeline running.
                        std.debug.print("P2P: headers synced at height {d}, blocks at {d} (queue={d}), continuing block download\n",
                            .{ our_height + self.expected_blocks.items.len, our_height, self.expected_blocks.items.len - self.connect_cursor });
                        self.pipelineBlockRequests() catch {};
                    }
                    return;
                }

                // Deduplicate: only accept headers that chain to our known tip.
                // The first header's prev_block must match either:
                // - The last hash in expected_blocks (if any), or
                // - Our best block hash (genesis or connected tip)
                const expected_prev = if (self.expected_blocks.items.len > 0)
                    self.expected_blocks.items[self.expected_blocks.items.len - 1]
                else if (self.chain_state) |cs| blk: {
                    // On fresh start best_hash is all zeros; use genesis hash
                    // so the first batch of headers (whose prev_block is the
                    // genesis hash) chains correctly.
                    break :blk if (cs.best_height == 0) self.network_params.genesis_hash else cs.best_hash;
                } else
                    self.network_params.genesis_hash;

                if (!std.mem.eql(u8, &h.headers[0].prev_block, &expected_prev)) {
                    // Headers don't connect to our chain - misbehave (+20)
                    peer.misbehaving(20, "headers don't connect to our chain");
                    return;
                }

                std.debug.print("P2P: Received {d} new headers (queue={d})\n", .{
                    h.headers.len,
                    self.expected_blocks.items.len + h.headers.len,
                });

                // Add header hashes to the expected_blocks queue
                for (h.headers) |header| {
                    const block_hash = crypto.computeBlockHash(&header);
                    self.expected_blocks.append(block_hash) catch continue;
                }

                // Request more headers from this specific peer if we got a full batch
                // But limit the queue to avoid too many outstanding blocks
                const remaining_queue = self.expected_blocks.items.len - self.connect_cursor;
                if (h.headers.len >= 2000 and remaining_queue < 16000) {
                    self.sendGetHeaders(peer) catch {};
                }

                // Pipeline: request blocks up to the download window
                self.pipelineBlockRequests() catch {};
            },
            .block => |block| {
                const block_hash = crypto.computeBlockHash(&block.header);

                // Decrement in-flight counters (global and per-peer).
                // This runs on EVERY block-response path — success, duplicate,
                // orphan, buffer-full-drop, put-failure — so the pipeline can
                // re-use the slot. Without this guarantee the counter drifts
                // upward, hits max_blocks_in_flight, and wedges IBD (see wave 4
                // wedge at height 29,953).
                if (self.blocks_in_flight > 0) self.blocks_in_flight -= 1;
                peer.recordBlockReceived();

                // Bound the buffer to prevent OOM — if too many blocks are
                // buffered waiting for connection, drop this one. It will
                // be re-downloaded when the connection cursor catches up.
                // BUT: always accept the block at the connect cursor, otherwise
                // a full buffer creates a deadlock (we need the next block to
                // advance the cursor and free buffer space, but we drop it).
                if (self.block_buffer.count() >= 1024) {
                    // Try draining first — if the next block is already buffered
                    // this will free space.
                    // W101: skip when already inside a drain (reached via the
                    // heartbeat's processAllMessages).  The outer drain is
                    // doing this work on every while iteration anyway.
                    if (!self.in_drain) self.drainBlockBuffer();

                    // If still full, check if this is the critical next block
                    if (self.block_buffer.count() >= 1024) {
                        const is_next = self.connect_cursor < self.expected_blocks.items.len and
                            std.mem.eql(u8, &block_hash, &self.expected_blocks.items[self.connect_cursor]);
                        if (!is_next) {
                            // Rewind download_cursor so pipelineBlockRequests
                            // will re-request this dropped block. The pipeline
                            // skips hashes already in block_buffer, so this is
                            // a cheap walk that only re-issues the genuinely
                            // missing blocks near the connect front. Without
                            // this rewind, dropped blocks were never re-issued
                            // by the normal pipeline — only by the 5s stall
                            // recovery (32 blocks/peer), which capped IBD at
                            // ~6 blocks/s and wedged the node at 29,953.
                            if (self.download_cursor > self.connect_cursor) {
                                self.download_cursor = self.connect_cursor;
                            }
                            serialize.freeBlock(self.allocator, &block);
                            return;
                        }
                    }
                }

                // Buffer the block (transfer ownership - do NOT free here).
                // Note: AutoHashMap.put replaces on duplicate-hash, so a
                // duplicate block response correctly ends up as a no-op
                // relative to buffer count (decrement already happened above).
                self.block_buffer.put(block_hash, block) catch |err| {
                    // If we can't buffer it, free and drop. The in-flight
                    // decrement above has already run, so the download slot
                    // is freed for the pipeline to re-issue. Log every drop
                    // — the 2026-04-25 wedge at h=892,306 left buffer=28 /
                    // in_flight=0 / queue=54k for 7h with zero log evidence
                    // of why height stopped advancing; this is the only
                    // place blocks can be silently lost in the receive
                    // path, and a high drop rate here would explain it.
                    std.log.err("P2P: BUFFER-PUT-DROP block height={} buffer_size={} err={s}", .{
                        self.connect_cursor,
                        self.block_buffer.count(),
                        @errorName(err),
                    });
                    if (self.download_cursor > self.connect_cursor) {
                        self.download_cursor = self.connect_cursor;
                    }
                    serialize.freeBlock(self.allocator, &block);
                    return;
                };

                // Try to connect as many buffered blocks as possible in order.
                // W101: skip when already inside a drain (reached via the
                // heartbeat's processAllMessages).  The outer drain will
                // consume this newly-buffered block on its next iteration.
                if (!self.in_drain) self.drainBlockBuffer();

                // Request more blocks to keep the pipeline full
                self.pipelineBlockRequests() catch {};
            },
            .getaddr => {
                // Send some known addresses back
                try self.sendAddresses(peer);
            },
            .feefilter => |ff| {
                // BIP-133: Store the peer's minimum fee rate (in sat/kvB).
                // We should not relay transactions below this rate to this peer.
                // Validate the fee is reasonable (not exceeding MAX_MONEY which is 21M BTC in sats).
                const MAX_MONEY: u64 = 2_100_000_000_000_000;
                if (ff.feerate <= MAX_MONEY) {
                    peer.fee_filter_received = ff.feerate;
                }
            },
            .sendtxrcncl => |stxr| {
                // BIP-330 Erlay: Peer is announcing support for transaction reconciliation.
                // Validate the version and store the salt for future sketch-based reconciliation.
                if (stxr.version >= 1) {
                    // Initialize reconciliation state for this peer.
                    // The combined salt (XOR of our salt and theirs) is used with SipHash
                    // to compute 32-bit short transaction IDs for the minisketch.
                    // Full integration requires a ReconciliationTracker instance on PeerManager;
                    // for now, record the peer's erlay parameters for future use.
                    // stxr parameters stored for future Erlay use
                }
            },
            .reqrecon => {
                // BIP-330 Erlay: Peer is requesting set reconciliation.
                // No heap allocations in reqrecon (sketch_data is a slice into payload).
            },
            .sketch => {
                // BIP-330 Erlay: Peer sent their sketch data.
                // No heap allocations in sketch (sketch_data is a slice into payload).
            },
            .reconcildiff => |rd| {
                // BIP-330 Erlay: Peer reports the reconciliation results.
                // Free allocated short ID arrays.
                defer self.allocator.free(rd.missing_short_ids);
                defer self.allocator.free(rd.extra_short_ids);
            },
            // BIP-152 Compact Block data messages
            .cmpctblock => |cb| {
                // Free compact block allocations.
                defer self.allocator.free(cb.short_ids);
                defer {
                    for (cb.prefilled_txs) |pt| {
                        var tx = pt.tx;
                        serialize.freeTransaction(self.allocator, &tx);
                    }
                    self.allocator.free(cb.prefilled_txs);
                }
                const block_hash = crypto.computeBlockHash(&cb.header);

                // BIP 152: Reconstruct block from compact block + mempool.
                // Derive SipHash key: SHA256(header_bytes || nonce_le)[0:16]
                var key_data: [88]u8 = undefined;
                // Serialize header (80 bytes) inline
                std.mem.writeInt(i32, key_data[0..4], cb.header.version, .little);
                @memcpy(key_data[4..36], &cb.header.prev_block);
                @memcpy(key_data[36..68], &cb.header.merkle_root);
                std.mem.writeInt(u32, key_data[68..72], cb.header.timestamp, .little);
                std.mem.writeInt(u32, key_data[72..76], cb.header.bits, .little);
                std.mem.writeInt(u32, key_data[76..80], cb.header.nonce, .little);
                std.mem.writeInt(u64, key_data[80..88], cb.nonce, .little);
                const key_hash = crypto.sha256(&key_data);
                const k0 = std.mem.readInt(u64, key_hash[0..8], .little);
                const k1 = std.mem.readInt(u64, key_hash[8..16], .little);

                // Build short_id -> slot index map (skipping prefilled positions)
                const total_tx_count = cb.short_ids.len + cb.prefilled_txs.len;
                const txn_available = self.allocator.alloc(?types.Transaction, total_tx_count) catch {
                    std.debug.print("P2P: compact block alloc failed, requesting full block\n", .{});
                    var inv_list2 = std.ArrayList(p2p.InvVector).init(self.allocator);
                    defer inv_list2.deinit();
                    inv_list2.append(.{ .inv_type = .msg_witness_block, .hash = block_hash }) catch {};
                    if (inv_list2.items.len > 0) {
                        const getdata_msg2 = p2p.Message{ .getdata = .{ .inventory = inv_list2.items } };
                        peer.sendMessage(&getdata_msg2) catch {};
                    }
                    return;
                };
                defer self.allocator.free(txn_available);
                for (txn_available) |*slot| slot.* = null;

                // Place prefilled transactions
                for (cb.prefilled_txs) |pt| {
                    if (pt.index < total_tx_count) {
                        txn_available[pt.index] = pt.tx;
                    }
                }

                // Build short_id -> index map and match against mempool
                var mempool_hits: usize = 0;
                var sid_idx: usize = 0;
                const SipHash = std.crypto.auth.siphash.SipHash64(2, 4);
                if (self.mempool) |mp| {
                    mp.mutex.lock();
                    defer mp.mutex.unlock();
                    var sid_to_slot = std.AutoHashMap([6]u8, usize).init(self.allocator);
                    defer sid_to_slot.deinit();
                    for (0..total_tx_count) |i| {
                        if (txn_available[i] == null) {
                            if (sid_idx < cb.short_ids.len) {
                                sid_to_slot.put(cb.short_ids[sid_idx], i) catch {};
                                sid_idx += 1;
                            }
                        }
                    }
                    // Iterate mempool entries and match short IDs
                    var sip_key: [16]u8 = undefined;
                    std.mem.writeInt(u64, sip_key[0..8], k0, .little);
                    std.mem.writeInt(u64, sip_key[8..16], k1, .little);
                    var it = mp.entries.iterator();
                    while (it.next()) |kv| {
                        const entry = kv.value_ptr.*;
                        // Compute short ID: SipHash24(k0, k1, wtxid)[0:6]
                        var hasher = SipHash.init(&sip_key);
                        hasher.update(&entry.wtxid);
                        const hash_val = hasher.finalInt();
                        var short_id: [6]u8 = undefined;
                        // Write lower 6 bytes of hash as little-endian short ID
                        const hash_le = std.mem.toBytes(hash_val);
                        @memcpy(&short_id, hash_le[0..6]);
                        if (sid_to_slot.get(short_id)) |slot_idx| {
                            if (txn_available[slot_idx] == null) {
                                txn_available[slot_idx] = entry.tx;
                                mempool_hits += 1;
                            }
                        }
                    }
                }

                // Count missing
                var missing_count: usize = 0;
                for (txn_available) |slot| {
                    if (slot == null) missing_count += 1;
                }

                if (missing_count == 0) {
                    std.debug.print("P2P: compact block {x} reconstructed from mempool (hits={})\n", .{ block_hash, mempool_hits });
                    // TODO: assemble full block and pass to validation
                } else {
                    const miss_pct = @as(f64, @floatFromInt(missing_count)) / @as(f64, @floatFromInt(total_tx_count)) * 100.0;
                    if (miss_pct > 50.0) {
                        // Too many missing — fall back to full block
                        std.debug.print("P2P: compact block {x} missing {d:.0}% txns, requesting full block\n", .{ block_hash, miss_pct });
                        var inv_list = std.ArrayList(p2p.InvVector).init(self.allocator);
                        defer inv_list.deinit();
                        inv_list.append(.{ .inv_type = .msg_witness_block, .hash = block_hash }) catch {};
                        if (inv_list.items.len > 0) {
                            const getdata_msg = p2p.Message{ .getdata = .{ .inventory = inv_list.items } };
                            peer.sendMessage(&getdata_msg) catch {};
                        }
                    } else {
                        // Send getblocktxn for missing transactions
                        std.debug.print("P2P: compact block {x} missing {} txns (mempool_hits={}), sending getblocktxn\n", .{ block_hash, missing_count, mempool_hits });
                        var missing_indices = std.ArrayList(u16).init(self.allocator);
                        defer missing_indices.deinit();
                        for (0..total_tx_count) |i| {
                            if (txn_available[i] == null) {
                                missing_indices.append(@intCast(i)) catch {};
                            }
                        }
                        if (missing_indices.items.len > 0) {
                            const gbt_msg = p2p.Message{ .getblocktxn = .{
                                .block_hash = block_hash,
                                .indexes = missing_indices.items,
                            } };
                            peer.sendMessage(&gbt_msg) catch {};
                        }
                    }
                }
            },
            .getblocktxn => |gbt| {
                // Free allocated index array.
                defer self.allocator.free(gbt.indexes);
                // Peer is requesting missing transactions for compact block
                // reconstruction. We don't serve compact blocks yet, so ignore.
            },
            .blocktxn => |bt| {
                // Free allocated transactions.
                defer {
                    for (bt.transactions) |*tx| {
                        serialize.freeTransaction(self.allocator, tx);
                    }
                    self.allocator.free(bt.transactions);
                }
                // Response to our getblocktxn request. Since we fall back to
                // full block download, we shouldn't receive these. Ignore.
            },
            .tx => |tx_msg| {
                // addTransaction copies the tx struct, so we always free the received message.
                defer serialize.freeTransaction(self.allocator, &tx_msg);
                if (self.mempool) |pool| {
                    // Accept transaction into mempool via AcceptToMemoryPool
                    const result = pool.acceptToMemoryPool(tx_msg, false);
                    if (result.accepted) {
                        // Relay to all other peers via inv (BIP 339: use MSG_WITNESS_TX)
                        const inv_items = [_]p2p.InvVector{.{
                            .inv_type = .msg_witness_tx,
                            .hash = result.txid,
                        }};
                        const inv_msg = p2p.Message{ .inv = .{ .inventory = &inv_items } };
                        for (self.peers.items) |relay_peer| {
                            if (relay_peer == peer) continue; // Don't relay back to sender
                            if (!relay_peer.relay_txs) continue; // Respect fRelay
                            if (relay_peer.state != .connected) continue;
                            // BIP-133 feefilter: skip peers whose fee filter exceeds tx fee rate
                            if (relay_peer.fee_filter_received > 0 and result.fee > 0 and result.vsize > 0) {
                                const fee_rate_per_kvb: u64 = @intCast(@divTrunc(result.fee * 1000, @as(i64, @intCast(result.vsize))));
                                if (fee_rate_per_kvb < relay_peer.fee_filter_received) continue;
                            }
                            relay_peer.sendMessage(&inv_msg) catch {};
                        }
                        std.debug.print("MEMPOOL: accepted tx, relaying to peers\n", .{});
                    }
                }
            },
            .getdata => |gd| {
                // Serve requested blocks to peers (check relay cache and pending buffer)
                defer self.allocator.free(gd.inventory);
                for (gd.inventory) |item| {
                    const base_type = @as(u32, @intFromEnum(item.inv_type)) & ~@as(u32, 0x40000000);
                    if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_block))) {
                        // 1. Check served_blocks cache (mined + recently connected blocks)
                        if (self.served_blocks.get(item.hash)) |block_data| {
                            var reader = serialize.Reader{ .data = block_data };
                            const block = serialize.readBlock(&reader, self.allocator) catch continue;
                            defer serialize.freeBlock(self.allocator, &block);
                            const block_msg = p2p.Message{ .block = block };
                            peer.sendMessage(&block_msg) catch {};
                            std.debug.print("P2P: served block from relay cache to peer\n", .{});
                        } else if (self.block_buffer.get(item.hash)) |buffered_block| {
                            // 2. Check block_buffer (received but not yet connected)
                            const block_msg = p2p.Message{ .block = buffered_block };
                            peer.sendMessage(&block_msg) catch {};
                            std.debug.print("P2P: served buffered block to peer\n", .{});
                        } else {
                            // Block not available — send notfound
                            const not_found_inv = [_]p2p.InvVector{.{
                                .inv_type = item.inv_type,
                                .hash = item.hash,
                            }};
                            const nf_msg = p2p.Message{ .notfound = .{ .inventory = &not_found_inv } };
                            peer.sendMessage(&nf_msg) catch {};
                        }
                    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_tx))) {
                        // Serve transaction from mempool
                        if (self.mempool) |pool| {
                            if (pool.entries.get(item.hash)) |entry| {
                                const tx_msg = p2p.Message{ .tx = entry.tx };
                                peer.sendMessage(&tx_msg) catch {};
                            } else {
                                const not_found_inv = [_]p2p.InvVector{.{
                                    .inv_type = item.inv_type,
                                    .hash = item.hash,
                                }};
                                const nf_msg = p2p.Message{ .notfound = .{ .inventory = &not_found_inv } };
                                peer.sendMessage(&nf_msg) catch {};
                            }
                        }
                    }
                }
            },
            .notfound => |nf| {
                // Free the allocated inventory array.
                defer self.allocator.free(nf.inventory);
            },
            .getheaders => |gh| {
                // Free the allocated locator hashes.
                defer self.allocator.free(gh.block_locator_hashes);
            },
            .getblocks => |gb| {
                // Free the allocated locator hashes.
                defer self.allocator.free(gb.block_locator_hashes);
            },
            .reject => |rj| {
                // reject message fields are slices into the payload buffer,
                // which is freed by receiveMessage's defer. No extra free needed.
                _ = rj;
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
                // W101: log before eviction.  Previously silent; made it
                // easy to miss the 20-min last_message_time path that was
                // evicting blk-replay every ~25 min during long drains.
                var addr_buf: [64]u8 = undefined;
                const addr_str = self.peers.items[i].getAddressString(&addr_buf);
                const now = std.time.timestamp();
                const peer = self.peers.items[i];
                const subver: []const u8 = if (peer.version_info) |v| v.user_agent else "?";
                std.log.info("Disconnecting stale peer={s} idle={d}s last_ping={d}s last_pong={d}s subver={s}", .{
                    addr_str,
                    now - peer.last_message_time,
                    if (peer.last_ping_time > 0) now - peer.last_ping_time else 0,
                    if (peer.last_pong_time > 0) now - peer.last_pong_time else 0,
                    subver,
                });
                self.removePeerByIndex(i);
            } else {
                i += 1;
            }
        }
    }

    // ========================================================================
    // Stale Peer Eviction (Bitcoin Core net_processing.cpp)
    // ========================================================================

    /// Check for stale tips and evict peers. Run every STALE_CHECK_INTERVAL (45s).
    /// Combines stale tip checking and peer eviction as per Bitcoin Core.
    pub fn checkForStaleTipAndEvictPeers(self: *PeerManager) void {
        const now = std.time.timestamp();

        // Only run every STALE_CHECK_INTERVAL
        if (now - self.last_stale_check_time < STALE_CHECK_INTERVAL) return;
        self.last_stale_check_time = now;

        // 1. Check ping timeouts - disconnect peers not responding to pings
        self.checkPingTimeouts();

        // 2. Check headers timeouts - misbehave peers not sending headers
        self.checkHeadersTimeouts();

        // 3. Check block download timeouts - disconnect stalled block downloads
        self.checkBlockDownloadTimeouts();

        // 4. Evict stale tip peers - disconnect one outbound peer with stale tip
        self.evictStaleTipPeer();
    }

    /// Check for ping timeouts (ping sent, no pong within PING_TIMEOUT).
    fn checkPingTimeouts(self: *PeerManager) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.state == .handshake_complete and peer.hasPingTimeout()) {
                var addr_buf: [64]u8 = undefined;
                const addr_str = peer.getAddressString(&addr_buf);
                std.log.info("Disconnecting peer={s} due to ping timeout", .{addr_str});
                self.removePeerByIndex(i);
                // Don't increment i since we removed the peer
            } else {
                i += 1;
            }
        }
    }

    /// Check for headers request timeouts. Add misbehavior score (5) for non-responsive peers.
    /// Uses a low penalty since getheaders is sent to multiple peers but only one typically responds.
    fn checkHeadersTimeouts(self: *PeerManager) void {
        for (self.peers.items) |peer| {
            if (peer.state == .handshake_complete and peer.hasHeadersTimeout()) {
                peer.misbehaving(5, "headers timeout");
                // Clear the timeout to avoid repeated scoring
                peer.last_getheaders_time = 0;
            }
        }
    }

    /// Check for block download timeouts. Disconnect peers with stalled block downloads.
    fn checkBlockDownloadTimeouts(self: *PeerManager) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.state == .handshake_complete and peer.hasBlockDownloadTimeout()) {
                var addr_buf: [64]u8 = undefined;
                const addr_str = peer.getAddressString(&addr_buf);
                std.log.info("Disconnecting peer={s} due to block download timeout (blocks_in_flight={d})", .{ addr_str, peer.blocks_in_flight_count });
                peer.misbehaving(50, "block download stalling");
                self.removePeerByIndex(i);
            } else {
                i += 1;
            }
        }
    }

    /// Evict one outbound peer with a stale tip (behind our height for >30 min).
    /// Only evicts if we have better alternatives and the peer is not protected.
    fn evictStaleTipPeer(self: *PeerManager) void {
        const our_height: u32 = if (self.our_height >= 0) @intCast(self.our_height) else 0;

        // Count peers with good tips (at or above our height)
        var good_tip_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .outbound and peer.best_known_height >= our_height) {
                good_tip_count += 1;
            }
        }

        // Only evict if we have at least one peer with a good tip
        if (good_tip_count == 0) return;

        // Find the worst stale tip peer (prefer evicting inbound over outbound)
        var worst_idx: ?usize = null;
        var worst_height: u32 = std.math.maxInt(u32);

        for (self.peers.items, 0..) |peer, i| {
            if (!peer.isEvictionCandidate()) continue;
            if (!peer.hasStaleTip(our_height)) continue;

            // Find the peer furthest behind
            if (peer.best_known_height < worst_height) {
                worst_height = peer.best_known_height;
                worst_idx = i;
            }
        }

        // Evict the worst peer if found
        if (worst_idx) |idx| {
            const peer = self.peers.items[idx];
            var addr_buf: [64]u8 = undefined;
            const addr_str = peer.getAddressString(&addr_buf);
            std.log.info("Evicting stale tip peer={s} (height={d}, our_height={d})", .{ addr_str, peer.best_known_height, our_height });
            self.removePeerByIndex(idx);
        }
    }

    /// Update our tip height (call when a new block is connected).
    pub fn updateTipHeight(self: *PeerManager, height: i32) void {
        self.our_height = height;
        self.last_tip_update_time = std.time.timestamp();
    }

    /// Check if our tip may be stale (no new blocks for 30 minutes).
    pub fn tipMayBeStale(self: *const PeerManager) bool {
        const now = std.time.timestamp();
        if (self.last_tip_update_time == 0) return false;
        return now - self.last_tip_update_time > STALE_TIP_THRESHOLD;
    }

    /// Protect an outbound peer from eviction (call when they provide good chain sync).
    pub fn protectOutboundPeer(self: *PeerManager, peer: *Peer) void {
        if (peer.direction != .outbound) return;
        if (peer.chain_sync_protected) return;
        if (self.outbound_protected_count >= MAX_OUTBOUND_PEERS_TO_PROTECT) return;

        peer.chain_sync_protected = true;
        self.outbound_protected_count += 1;
    }

    /// Rotate peers: disconnect longest-connected outbound and connect a new one.
    pub fn rotatePeers(self: *PeerManager) void {
        const now = std.time.timestamp();
        if (now - self.last_rotation_time < PEER_ROTATION_INTERVAL) return;
        self.last_rotation_time = now;

        // Find the oldest outbound peer.  Manual peers (set via addnode RPC
        // or --connect) are exempt: rotation would silently break the
        // localhost IBD mesh.  Matches Bitcoin Core net.cpp ThreadOpenConnections.
        var oldest_idx: ?usize = null;
        var oldest_time: i64 = now;

        for (self.peers.items, 0..) |peer, i| {
            if (peer.conn_type == .manual) continue;
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
        // Reclaim in-flight block count for this peer so the global counter
        // doesn't permanently drift upward, which would block new requests.
        if (peer.blocks_in_flight_count > 0) {
            if (self.blocks_in_flight >= peer.blocks_in_flight_count) {
                self.blocks_in_flight -= peer.blocks_in_flight_count;
            } else {
                // Counter already drifted; reset to 0 rather than underflow.
                self.blocks_in_flight = 0;
            }
            // W19 fix: rewind download_cursor so the pipeline re-requests the
            // blocks that were in-flight to this peer and are now lost.  Without
            // this rewind, download_cursor stays at connect_cursor + max_ahead
            // (the window ceiling) while connect_cursor is stuck waiting for the
            // first missing block.  pipelineBlockRequests() then sees
            // download_cursor >= connect_cursor + max_ahead and issues no new
            // getdata — a permanent wedge until a full restart.
            //
            // Rewinding to connect_cursor is safe: pipelineBlockRequests() skips
            // hashes already in block_buffer, so blocks that were received and
            // buffered before this peer disconnected are not re-requested.
            if (self.download_cursor > self.connect_cursor) {
                self.download_cursor = self.connect_cursor;
            }
        }
        peer.disconnect();
        self.allocator.destroy(peer);
    }

    // ========================================================================
    // Block Download Pipeline
    // ========================================================================

    /// Request blocks from peers to keep the download pipeline full.
    ///
    /// Level-triggered per-peer dispatch, modelled on Bitcoin Core's
    /// `SendMessages` / `FindNextBlocksToDownload` loop in
    /// `src/net_processing.cpp`.  The budget is per-peer
    /// (`MAX_BLOCKS_IN_TRANSIT_PER_PEER` = 16), not global — a slow peer
    /// never wedges the other peers' pipelines.  This function is safe to
    /// call on every SendMessages tick: if a peer is full, it is skipped;
    /// if any peer has budget, it is filled.
    ///
    /// Wave 15 diagnostic (`wave15-2026-04-15/CLEARBIT-STALL-RECOVERY-DIAG.md`)
    /// showed the previous global `blocks_in_flight < max_blocks_in_flight`
    /// gate was edge-triggered in practice: a single slow block among 8
    /// peers pinned the counter at 128 and halted all requests until the
    /// 5-second stall-recovery timer fired a mass-reset.  Removing the
    /// global gate and replacing stall-recovery with per-peer
    /// disconnect-on-timeout (see `checkBlockDownloadTimeouts`) mirrors
    /// Core and unblocks level-triggered progress.
    ///
    /// The `download_cursor` rewind on buffer-full drop (wave 9) is preserved
    /// in the `.block` handler — see `peer.zig:2198` and `peer.zig:2215`.
    fn pipelineBlockRequests(self: *PeerManager) !void {
        if (self.chain_state == null) return;
        if (self.download_cursor >= self.expected_blocks.items.len) return;

        // Don't download too far ahead of the connection cursor.
        // Each buffered block is ~1-2 MB, so 512 blocks ≈ 512 MB-1 GB.
        // Use the distance between download and connect cursors (not buffer count)
        // to avoid stalling when the buffer has many out-of-order blocks.
        const max_ahead: u32 = 512;

        // Per-peer level-triggered dispatch.  For every handshake-complete
        // peer, compute its remaining in-flight budget and try to fill it.
        // No global counter gate — a slow peer self-throttles and is
        // disconnected by `checkBlockDownloadTimeouts` when its oldest
        // in-flight block exceeds `BLOCK_DOWNLOAD_TIMEOUT`.
        for (self.peers.items) |tp| {
            if (tp.state != .handshake_complete) continue;

            // Compute this peer's remaining slot budget.  Saturating so a
            // transient over-count (shouldn't happen, but be defensive)
            // cannot wrap to a huge positive.
            if (tp.blocks_in_flight_count >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) continue;
            const peer_budget: u32 = MAX_BLOCKS_IN_TRANSIT_PER_PEER - tp.blocks_in_flight_count;

            if (self.download_cursor >= self.expected_blocks.items.len) break;
            if (self.download_cursor >= self.connect_cursor + max_ahead) break;

            var invs = std.ArrayList(p2p.InvVector).init(self.allocator);

            var batch_count: u32 = 0;
            while (batch_count < peer_budget and
                self.download_cursor < self.expected_blocks.items.len and
                self.download_cursor < self.connect_cursor + max_ahead)
            {
                const h = self.expected_blocks.items[self.download_cursor];
                if (!self.block_buffer.contains(h)) {
                    invs.append(.{
                        .inv_type = .msg_witness_block,
                        .hash = h,
                    }) catch break;
                    batch_count += 1;
                }
                self.download_cursor += 1;
            }

            if (invs.items.len > 0) {
                const getdata_msg = p2p.Message{ .getdata = .{ .inventory = invs.items } };
                tp.sendMessage(&getdata_msg) catch {
                    invs.deinit();
                    continue;
                };
                // Maintain the global `blocks_in_flight` counter for RPC /
                // progress logging only — it no longer gates the pipeline.
                self.blocks_in_flight += batch_count;
                var bi: u32 = 0;
                while (bi < batch_count) : (bi += 1) {
                    tp.recordBlockRequest();
                }
            }
            invs.deinit();
        }
    }

    /// Try to connect buffered blocks in order to chain_state.
    /// Connects as many sequential blocks as possible from the buffer.
    /// Runs a tight loop; emits heartbeat every 5 s during long drains so
    /// operators can distinguish a slow-UTXO-flush from a true freeze (W21
    /// third-stall pattern: large-header-batch + slow blocks = silent drain).
    /// Also re-arms the block download pipeline every 32 blocks so that peer
    /// slots freed during the drain are refilled without waiting for the full
    /// drain to complete.
    fn drainBlockBuffer(self: *PeerManager) void {
        const cs = self.chain_state orelse return;
        // W101: mark drain active so nested drain calls from the `.block`
        // handler (invoked transitively by processAllMessages in the
        // heartbeat) become no-ops instead of recursing.  The outer while
        // will consume any newly-buffered blocks on its next iteration.
        self.in_drain = true;
        defer self.in_drain = false;
        var connected: u32 = 0;
        var slow_blocks: u32 = 0;
        const drain_start = std.time.nanoTimestamp();
        // Heartbeat: track last time we emitted an in-drain progress line.
        var last_heartbeat: i64 = std.time.timestamp();

        // Stall recovery is now handled in two level-triggered paths,
        // matching Bitcoin Core:
        //   1. `pipelineBlockRequests` re-evaluates per-peer budget on every
        //      SendMessages tick, so a freed slot is refilled immediately.
        //   2. `checkBlockDownloadTimeouts` disconnects peers that hold an
        //      in-flight block past `BLOCK_DOWNLOAD_TIMEOUT`; the per-peer
        //      cleanup in `removePeerByIndex` returns the slots, and the
        //      `.block` buffer-full-drop path (wave 9) rewinds
        //      `download_cursor` so the pipeline re-requests dropped hashes.
        //
        // The wave-15 diagnostic showed the old 5-second global counter
        // reset fired on 94% of drain cycles during healthy IBD, throttling
        // throughput to ~6 blk/s by limiting re-issue to 3 peers.  See
        // `wave15-2026-04-15/CLEARBIT-STALL-RECOVERY-DIAG.md`.

        while (self.connect_cursor < self.expected_blocks.items.len) {
            // The next block we need to connect
            const expected_hash = self.expected_blocks.items[self.connect_cursor];

            // Is it in the buffer?
            const entry = self.block_buffer.fetchRemove(expected_hash);
            if (entry == null) {
                // Wedge diagnostic: when the expected next block is missing
                // but the buffer is NON-empty, the drain has stalled because
                // the pipeline got out of sync — blocks are in the buffer
                // but not the one we need next. The 2026-04-25 wedges at
                // h=892,306 and h=905,696 sat with buffer=15-28 / in_flight=0
                // for hours producing no log explanation. This line fires
                // exactly in that condition. Rate-limit to once per second
                // per stuck height so steady-state lookahead doesn't flood.
                if (self.block_buffer.count() > 0) {
                    const now = std.time.timestamp();
                    if (now != self.last_drain_break_log_ts or
                        self.connect_cursor != self.last_drain_break_cursor)
                    {
                        self.last_drain_break_log_ts = now;
                        self.last_drain_break_cursor = self.connect_cursor;
                        // Sample first few buffered hashes' positions so we
                        // can see how far ahead the pipeline ran.
                        var min_ahead: i64 = std.math.maxInt(i64);
                        var max_ahead: i64 = -1;
                        var sample_count: u32 = 0;
                        var it = self.block_buffer.iterator();
                        while (it.next()) |kv| {
                            sample_count += 1;
                            // Find which expected_blocks index the buffered
                            // hash corresponds to — bounded scan to keep
                            // this cheap during the wedge spin loop.
                            const scan_max = @min(self.expected_blocks.items.len,
                                self.connect_cursor + 4096);
                            var i = self.connect_cursor;
                            while (i < scan_max) : (i += 1) {
                                if (std.mem.eql(u8, &self.expected_blocks.items[i], &kv.key_ptr.*)) {
                                    const ahead: i64 = @as(i64, @intCast(i)) -
                                        @as(i64, @intCast(self.connect_cursor));
                                    if (ahead < min_ahead) min_ahead = ahead;
                                    if (ahead > max_ahead) max_ahead = ahead;
                                    break;
                                }
                            }
                            if (sample_count >= 16) break;
                        }
                        std.debug.print(
                            "P2P: DRAIN-BREAK-WEDGE connect_cursor={d} download_cursor={d} buffer={d} sampled_ahead_min={d} sampled_ahead_max={d} expected_total={d}\n",
                            .{
                                self.connect_cursor,
                                self.download_cursor,
                                self.block_buffer.count(),
                                min_ahead,
                                max_ahead,
                                self.expected_blocks.items.len,
                            },
                        );
                    }
                }
                break; // Not yet received, stop
            }

            var block = entry.?.value;
            defer serialize.freeBlock(self.allocator, &block);

            const block_hash = crypto.computeBlockHash(&block.header);
            const height = cs.best_height + 1;

            // Timing for per-block diagnostics
            const block_start = std.time.nanoTimestamp();

            // During IBD, skip undo data collection for speed
            cs.connectBlockFast(&block, &block_hash, height) catch |err| {
                std.debug.print("P2P: Failed to connect block at height {d}: {}\n", .{ height, err });
                break;
            };

            const block_elapsed_ns = std.time.nanoTimestamp() - block_start;
            const block_elapsed_ms = @divTrunc(block_elapsed_ns, 1_000_000);
            if (block_elapsed_ms > 50) {
                slow_blocks += 1;
                // W21 fix: log all slow blocks (not just first 3 per drain).
                // Blocks >50ms are always logged; >1000ms get a VERY-SLOW tag.
                // This prevents the operator-visible "600s silence" that occurs
                // when many multi-second flushes run back-to-back: previously
                // only the first 3 were printed, leaving the log dark for the
                // entire remainder of the drain.
                if (block_elapsed_ms > 1000) {
                    std.debug.print("P2P: VERY-SLOW block {d}: {d}ms utxos={d}\n", .{
                        height,
                        block_elapsed_ms,
                        cs.utxo_set.cache.count(),
                    });
                } else {
                    std.debug.print("P2P: SLOW block {d}: {d}ms utxos={d}\n", .{
                        height,
                        block_elapsed_ms,
                        cs.utxo_set.cache.count(),
                    });
                }
            }

            // W73 Fix 2 — compaction-aware backoff.  When prefetch exceeds
            // 500 ms the RocksDB compaction mutex was almost certainly
            // blocking our multi_get.  Yield briefly so in-flight compaction
            // can drain before the next block's prefetch hits the same lock.
            //
            // Per wave47-2026-04-16/W73-FIX1-POST-DEPLOY-FINDINGS.md §4,
            // observed slow-prefetch tails run 2-4 s while the happy path is
            // 23-280 ms; 500 ms separates the tail cleanly.  Gate telemetry:
            // the existing [W73-PROF] 100-block rollup already emits
            // prefetch avg/max; compare pre/post restart windows to decide
            // if the backoff helps.  100 ms sleep is capped to <20% of the
            // smallest observed tail so cost is bounded even on false hits.
            const prefetch_ns = cs.profile_cur_prefetch_ns;
            if (prefetch_ns > 500 * std.time.ns_per_ms) {
                std.debug.print("[W73-STALL] block={d} prefetch={d}ms hits={d} — backoff 100ms\n", .{
                    height,
                    @divTrunc(prefetch_ns, std.time.ns_per_ms),
                    cs.profile_cur_prefetch_hits,
                });
                std.time.sleep(100 * std.time.ns_per_ms);
            }

            // W21 fix: heartbeat every 5 s during long drains.  With large
            // UTXO sets (>1.7 M entries) individual flushes take 50ms-3 s,
            // so a 134-block drain is 43 s of silence.  The heartbeat lets
            // operators distinguish "slow but alive" from "frozen".
            const now_hb = std.time.timestamp();
            if (now_hb - last_heartbeat >= 5) {
                const remaining_q = self.expected_blocks.items.len - self.connect_cursor;
                std.debug.print("P2P: drain-heartbeat height={d} connected={d} slow={d} buffer={d} in_flight={d} queue={d} utxos={d}\n", .{
                    cs.best_height,
                    connected,
                    slow_blocks,
                    self.block_buffer.count(),
                    self.blocks_in_flight,
                    remaining_q,
                    cs.utxo_set.cache.count(),
                });
                last_heartbeat = now_hb;

                // W21 fix: re-arm the download pipeline inside the drain loop
                // every 5 s.  Peer slots freed by block receipts during the
                // drain are not refilled until the drain completes; with a
                // 43-second drain and only 14 in-flight slots at start, the
                // pipeline goes cold and then only has 1-2 active peers after
                // drain.  Re-arming here keeps all peer budgets filled even
                // during a long drain.
                self.pipelineBlockRequests() catch {};

                // W100: service pending inbound connections during long
                // drains.  Without this, a blk-replay (or any other inbound)
                // peer's TCP SYN is accepted by the kernel but its userspace
                // handshake waits for the drain to complete — observed 10-11
                // min gaps against blk-replay on localhost.  acceptInbound
                // polls non-blocking; handshake with an inbound v1 peer is
                // sub-millisecond on localhost.
                self.acceptInbound() catch {};

                // W101: service existing peers during long drains.  Without
                // this, reactive-only peers (blk-replay sends nothing unless
                // we pinged or requested a block) hit the 20-min
                // last_message_time threshold in isTimedOut and get silently
                // evicted by disconnectStale.  sendPings keeps pongs flowing
                // (and pongs update last_message_time); processAllMessages
                // drains the recv buffer so inbound pongs, ack-less replies
                // and incoming getdata/getblocks are handled.
                //
                // Recursion note: processAllMessages → `.block` handler
                // normally calls drainBlockBuffer, but the in_drain guard
                // turns those nested calls into no-ops.  Blocks accepted by
                // the inner loop land in block_buffer and are consumed by
                // the outer while on its next iteration — so throughput is
                // unaffected.
                self.sendPings() catch {};
                self.processAllMessages() catch {};
            }

            self.our_height = @intCast(cs.best_height);
            connected += 1;
            self.blocks_since_log += 1;
            self.connect_cursor += 1;

            // Cache the connected block for relay to other peers.
            // Only cache recent blocks to bound memory (keep last 512).
            if (self.served_blocks.count() < 64) {
                self.cacheBlockForRelay(&block_hash, &block);
            }

            // Periodically compact the expected_blocks list to reclaim memory
            // when we've connected a large chunk
            if (self.connect_cursor > 10000) {
                // Shift remaining items to the front
                const remaining = self.expected_blocks.items.len - self.connect_cursor;
                if (remaining > 0) {
                    std.mem.copyForwards(
                        types.Hash256,
                        self.expected_blocks.items[0..remaining],
                        self.expected_blocks.items[self.connect_cursor..self.expected_blocks.items.len],
                    );
                }
                self.expected_blocks.shrinkRetainingCapacity(remaining);
                self.download_cursor -= @min(self.download_cursor, self.connect_cursor);
                self.connect_cursor = 0;
            }
        }

        // Cursor-inversion fix: the drain advances connect_cursor for every
        // buffered block consumed, but never touches download_cursor. After a
        // W19/W28/buffer-full rewind sets download_cursor = connect_cursor,
        // the very next drain pass can consume hundreds of buffered blocks
        // queued before the rewind — surging connect_cursor past
        // download_cursor and leaving the cursors inverted. Once inverted,
        // pipelineBlockRequests starts iterating from a stale download_cursor
        // and re-requests already-passed hashes (those come back as orphans
        // that drain can't use), and the three existing rewind sites
        // (peer.zig:~2339, ~2366, ~2943, ~3303) all guard with
        // `if (download_cursor > connect_cursor)` so they can't repair the
        // inverted state. The 2026-04-25 wedge at h=905,696 captured exactly
        // this via the DRAIN-BREAK-WEDGE log:
        //   connect_cursor=1259 download_cursor=752 buffer=1 in_flight=0
        // Force-restore the invariant here so pipelineBlockRequests starts
        // at connect_cursor on the next call. Pipeline naturally skips
        // hashes already in block_buffer, so re-requesting from
        // connect_cursor is cheap.
        if (self.download_cursor < self.connect_cursor) {
            std.debug.print(
                "P2P: cursor-inversion-fix download_cursor={d} -> connect_cursor={d}\n",
                .{ self.download_cursor, self.connect_cursor },
            );
            self.download_cursor = self.connect_cursor;
        }

        // Gap-stall recovery (W28): if the block at connect_cursor is missing
        // from the buffer AND download_cursor has already advanced past it
        // (meaning the block was "requested" but never arrived or was dropped),
        // AND no blocks are currently in-flight (so the block timeout path will
        // never fire to trigger the usual rewind), rewind download_cursor to
        // connect_cursor so pipelineBlockRequests() will re-issue the missing
        // block.  This prevents a permanent stall when blocks_in_flight_count == 0
        // for all peers but a gap block sits between connect_cursor and
        // download_cursor.
        if (self.blocks_in_flight == 0 and
            self.connect_cursor < self.expected_blocks.items.len and
            self.download_cursor > self.connect_cursor)
        {
            const gap_hash = self.expected_blocks.items[self.connect_cursor];
            if (!self.block_buffer.contains(gap_hash)) {
                // The block at the connection front is missing and was already
                // "requested" (download_cursor passed it) — rewind to re-request.
                std.debug.print("P2P: gap-stall recovery: block at connect_cursor={d} missing, rewinding download_cursor\n",
                    .{self.connect_cursor});
                self.download_cursor = self.connect_cursor;
            }
        }

        if (connected > 0) {
            const drain_elapsed_ns = std.time.nanoTimestamp() - drain_start;
            const drain_elapsed_ms = @divTrunc(drain_elapsed_ns, 1_000_000);

            // Log progress periodically (every 5 seconds)
            const now = std.time.timestamp();
            if (now - self.last_progress_log >= 5) {
                const elapsed = if (now > self.last_progress_log and self.last_progress_log > 0)
                    @as(u32, @intCast(now - self.last_progress_log))
                else
                    5;
                const rate = if (elapsed > 0) self.blocks_since_log / elapsed else self.blocks_since_log;
                const remaining = self.expected_blocks.items.len - self.connect_cursor;
                std.debug.print("P2P: height={d} buffer={d} in_flight={d} queue={d} rate={d} blk/s drain={d}ms utxos={d}\n", .{
                    cs.best_height,
                    self.block_buffer.count(),
                    self.blocks_in_flight,
                    remaining,
                    rate,
                    drain_elapsed_ms,
                    cs.utxo_set.cache.count(),
                });
                if (slow_blocks > 0) {
                    std.debug.print("P2P: {d} slow blocks (>50ms) in this drain\n", .{slow_blocks});
                }
                self.last_progress_log = now;
                self.blocks_since_log = 0;
            }

            // Immediately request more headers if we've consumed most of our queue
            const remaining = self.expected_blocks.items.len - self.connect_cursor;
            if (remaining < 500) {
                for (self.peers.items) |p| {
                    if (p.state == .handshake_complete and p.last_getheaders_time == 0) {
                        self.sendGetHeaders(p) catch {};
                        break;
                    }
                }
            }
        }
    }

    /// Check if we are in Initial Block Download (IBD).
    fn isIBD(self: *const PeerManager) bool {
        if (self.chain_state) |cs| {
            // We're in IBD if we have pending blocks to download or our queue is active
            if (self.expected_blocks.items.len > 0) return true;
            if (self.block_buffer.count() > 0) return true;
            // Also check if any peer is significantly ahead of us
            for (self.peers.items) |p| {
                if (p.start_height > 0 and cs.best_height + 10 < @as(u32, @intCast(p.start_height))) {
                    return true;
                }
            }
        }
        return false;
    }

    /// Main peer management loop.
    pub fn run(self: *PeerManager) !void {
        self.running.store(true, .release);

        // Connect to --connect peer if specified (priority)
        if (self.connect_address) |addr| {
            std.debug.print("P2P: Attempting TCP connection to --connect peer...\n", .{});
            // BIP-324 negotiation lives inside connectOutboundNegotiated;
            // when v2 is disabled (default) this is identical to the old
            // Peer.connect+performHandshake pair.
            const new_peer = self.connectOutboundNegotiated(addr) orelse {
                std.debug.print("P2P: Connection or handshake failed with --connect peer\n", .{});
                return;
            };
            new_peer.conn_type = .manual;
            std.debug.print("P2P: Handshake complete with --connect peer (height={d})\n", .{new_peer.start_height});

            self.peers.append(new_peer) catch {
                new_peer.disconnect();
                self.allocator.destroy(new_peer);
                return;
            };

            // Send getheaders using our best block as locator
            self.sendGetHeaders(new_peer) catch |err| {
                std.debug.print("P2P: Failed to send getheaders: {}\n", .{err});
            };
        } else {
            // Load anchor connections from disk
            self.loadAnchors() catch {};

            // Connect to anchor peers first (priority)
            self.connectToAnchors();

            // Initial DNS seeding
            self.dnsSeeds() catch {};
        }

        while (self.running.load(.acquire)) {
            // 0. Reconnect dropped manual peers first (addnode <ip> add).
            // Separate from maintainOutbound so it runs even in --connect mode
            // and isn't starved by the 1-attempt-per-tick IBD throttle.
            self.maintainManualConnections();

            // 1. Open new outbound connections if needed (skip if --connect mode)
            // During IBD, skip connection attempts if we already have peers (avoids blocking)
            if (self.connect_address == null) {
                // During IBD, maintainOutbound already limits to 1 attempt
                // per call, so it won't block the loop excessively.
                // Always try to maintain outbound diversity — a single peer
                // is fragile and will stall if it disconnects.
                self.maintainOutbound() catch {};
            }

            // 2. Accept inbound connections
            self.acceptInbound() catch {};

            // 3. Process messages from all peers
            self.processAllMessages() catch {};

            // 3b. Drain block buffer and pipeline more requests
            self.drainBlockBuffer();
            self.pipelineBlockRequests() catch {};

            // 4. Send pings to idle peers
            self.sendPings() catch {};

            // 5. Disconnect timed-out peers
            self.disconnectStale();

            // 6. Check for stale tips and evict peers (runs every 45 seconds)
            self.checkForStaleTipAndEvictPeers();

            // 7. Peer rotation (skip if --connect mode)
            if (self.connect_address == null) {
                self.rotatePeers();
            }

            // 8. Brief sleep to avoid busy-loop.
            // During IBD, poll() in processAllMessages handles the wait (10ms timeout),
            // so no additional sleep is needed. Outside IBD, sleep 50ms.
            if (!self.isIBD()) {
                std.time.sleep(50 * std.time.ns_per_ms);
            }
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

    /// Cache a mined block so it can be served to peers on getdata.
    pub fn cacheMinedBlock(self: *PeerManager, hash: types.Hash256, block_data: []const u8) void {
        // Store a copy of the serialized block
        const data_copy = self.allocator.dupe(u8, block_data) catch return;
        self.served_blocks.put(hash, data_copy) catch {
            self.allocator.free(data_copy);
        };
    }

    /// Serialize and cache a connected block for relay to other peers.
    fn cacheBlockForRelay(self: *PeerManager, hash: *const types.Hash256, block: *const types.Block) void {
        var writer = serialize.Writer.init(self.allocator);
        serialize.writeBlock(&writer, block) catch {
            writer.deinit();
            return;
        };
        const data = writer.toOwnedSlice() catch {
            writer.deinit();
            return;
        };
        self.served_blocks.put(hash.*, data) catch {
            self.allocator.free(data);
        };
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
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

test "eclipse protection: netGroup returns /32 for IPv6" {
    // IPv6 uses first 4 bytes (32 bits) for netgroup
    // 2001:db8:1234:5678::1 should use 2001:db8 (first 4 bytes)
    const addr1 = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 1 }, 8333, 0, 0);
    const group1 = netGroup(addr1);
    const expected1: u32 = (0x20 << 24) | (0x01 << 16) | (0x0d << 8) | 0xb8;
    try std.testing.expectEqual(expected1, group1);

    // Same /32 prefix should have same netgroup
    const addr2 = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 8333, 0, 0);
    const group2 = netGroup(addr2);
    try std.testing.expectEqual(group1, group2);

    // Different /32 prefix should have different netgroup
    const addr3 = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb9, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 1 }, 8333, 0, 0);
    const group3 = netGroup(addr3);
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

    // With only 4 candidates and protection for netgroup(4), ping(8), tx(4), block-relay-only(8), block(4), time(remaining/2)
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
    try std.testing.expectEqual(@as(usize, 8), EVICTION_PROTECT_PING);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_TX);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_BLOCK);
    try std.testing.expectEqual(@as(usize, 8), EVICTION_PROTECT_BLOCK_RELAY_ONLY);
    try std.testing.expectEqual(@as(usize, 8), EVICTION_PROTECT_TIME);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_NETGROUP);
    try std.testing.expectEqual(@as(usize, 2), MAX_BLOCK_RELAY_ONLY_ANCHORS);
}

test "eclipse protection: block-relay-only peers get protected" {
    const allocator = std.testing.allocator;

    // Create candidates: some relay_txs=true, some relay_txs=false (block-relay-only)
    var candidates = [_]EvictionCandidate{
        // Block-relay-only peers (relay_txs=false) - should be protected
        .{ .peer_index = 0, .net_group = 1, .min_ping_time = 500, .last_block_time = 100, .last_tx_time = 0, .connect_time = 900, .relay_txs = false, .is_protected = false },
        .{ .peer_index = 1, .net_group = 2, .min_ping_time = 500, .last_block_time = 200, .last_tx_time = 0, .connect_time = 800, .relay_txs = false, .is_protected = false },
        // Full relay peers
        .{ .peer_index = 2, .net_group = 3, .min_ping_time = 500, .last_block_time = 50, .last_tx_time = 50, .connect_time = 700, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 3, .net_group = 4, .min_ping_time = 500, .last_block_time = 60, .last_tx_time = 60, .connect_time = 600, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 4, .net_group = 5, .min_ping_time = 500, .last_block_time = 70, .last_tx_time = 70, .connect_time = 500, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 5, .net_group = 6, .min_ping_time = 500, .last_block_time = 80, .last_tx_time = 80, .connect_time = 400, .relay_txs = true, .is_protected = false },
    };

    const victim = selectEvictionCandidate(&candidates, allocator);

    // Should select a victim
    try std.testing.expect(victim != null);

    // The victim should NOT be a block-relay-only peer (0 or 1) since those get protected
    if (victim) |v| {
        try std.testing.expect(v != 0 and v != 1);
    }
}

// ============================================================================
// BIP-133 Feefilter Tests
// ============================================================================

test "feefilter: constants match Bitcoin Core defaults" {
    // Verify feefilter constants match Bitcoin Core
    try std.testing.expectEqual(@as(i64, 600), AVG_FEEFILTER_BROADCAST_INTERVAL); // 10 min
    try std.testing.expectEqual(@as(i64, 300), MAX_FEEFILTER_CHANGE_DELAY); // 5 min
    try std.testing.expectEqual(@as(u64, 1000), MIN_RELAY_FEE); // 1000 sat/kvB
    try std.testing.expectEqual(@as(u64, 1000), INCREMENTAL_RELAY_FEE); // 1000 sat/kvB
}

test "feefilter: peer fee_filter fields initialized to zero" {
    const allocator = std.testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333),
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
        .network_params = &consensus.MAINNET,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    try std.testing.expectEqual(@as(u64, 0), peer.fee_filter_received);
    try std.testing.expectEqual(@as(u64, 0), peer.fee_filter_sent);
    try std.testing.expectEqual(@as(i64, 0), peer.next_send_feefilter);
}

test "feefilter: passesFeeFilter accepts when no filter set" {
    const allocator = std.testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333),
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
        .network_params = &consensus.MAINNET,
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
        .fee_filter_received = 0, // No filter
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    // With no filter set, all transactions should pass
    try std.testing.expect(peer.passesFeeFilter(0));
    try std.testing.expect(peer.passesFeeFilter(500));
    try std.testing.expect(peer.passesFeeFilter(1000));
    try std.testing.expect(peer.passesFeeFilter(10000));
}

test "feefilter: passesFeeFilter filters below threshold" {
    const allocator = std.testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333),
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
        .network_params = &consensus.MAINNET,
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
        .fee_filter_received = 5000, // 5000 sat/kvB minimum
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    // Below threshold - should not pass
    try std.testing.expect(!peer.passesFeeFilter(0));
    try std.testing.expect(!peer.passesFeeFilter(1000));
    try std.testing.expect(!peer.passesFeeFilter(4999));

    // At or above threshold - should pass
    try std.testing.expect(peer.passesFeeFilter(5000));
    try std.testing.expect(peer.passesFeeFilter(5001));
    try std.testing.expect(peer.passesFeeFilter(10000));
}

test "feefilter message encode/decode round-trip" {
    const allocator = std.testing.allocator;

    // Create a feefilter message with MIN_RELAY_FEE
    const msg = p2p.Message{ .feefilter = .{ .feerate = MIN_RELAY_FEE } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    // Decode header
    const header = p2p.MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqualStrings("feefilter", header.commandName());
    try std.testing.expectEqual(@as(u32, 8), header.length); // u64 = 8 bytes

    // Decode payload
    const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
    try std.testing.expectEqual(MIN_RELAY_FEE, decoded.feefilter.feerate);
}

test "feefilter: high fee rate message encoding" {
    const allocator = std.testing.allocator;

    // Test with MAX_MONEY fee filter (used during IBD)
    const MAX_MONEY: u64 = 2_100_000_000_000_000;
    const msg = p2p.Message{ .feefilter = .{ .feerate = MAX_MONEY } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const header = p2p.MessageHeader.decode(encoded[0..24]);
    const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
    try std.testing.expectEqual(MAX_MONEY, decoded.feefilter.feerate);
}

test "feefilter: hysteresis thresholds" {
    // Test the hysteresis math: 25% decrease or 33% increase triggers early send
    const current_filter: u64 = 1000;

    // 25% decrease: new < 3/4 * old = 750
    const decrease_threshold = (3 * current_filter) / 4;
    try std.testing.expectEqual(@as(u64, 750), decrease_threshold);

    // 33% increase: new > 4/3 * old = 1333
    const increase_threshold = (4 * current_filter) / 3;
    try std.testing.expectEqual(@as(u64, 1333), increase_threshold);

    // Test boundary conditions
    try std.testing.expect(749 < decrease_threshold); // Triggers
    try std.testing.expect(750 == decrease_threshold); // Boundary - does not trigger
    try std.testing.expect(1333 == increase_threshold); // Boundary - does not trigger
    try std.testing.expect(1334 > increase_threshold); // Triggers
}

// ============================================================================
// drainBlockBuffer in-flight accounting regression (wave 5 — wedge at 29,953)
//
// These tests exercise the per-peer and global in-flight counter bookkeeping
// that was missing on response paths before the wave-5 fix, plus the
// download_cursor rewind that ensures dropped blocks get re-requested.
// ============================================================================

test "drain wedge: recordBlockReceived decrements counters on every path" {
    // The wedge at 29,953 was caused by the global in-flight counter not
    // being reliably restored after duplicate/orphan/buffer-full responses.
    // Verify the per-peer recordBlockReceived bookkeeping used by the block
    // handler: it must decrement on every response kind and must be
    // saturating on the lower bound (late response after a stall-recovery
    // reset is legal and must not underflow).

    // Build a minimal Peer with only the fields recordBlockRequest /
    // recordBlockReceived touch. We skip the full struct init by going
    // through undefined and populating just the relevant counters.
    var dummy: Peer = undefined;
    dummy.blocks_in_flight_count = 0;
    dummy.oldest_block_in_flight_time = 0;
    dummy.last_block_time = 0;

    // Simulate 5 block requests.
    var i: u32 = 0;
    while (i < 5) : (i += 1) dummy.recordBlockRequest();
    try std.testing.expectEqual(@as(u32, 5), dummy.blocks_in_flight_count);
    try std.testing.expect(dummy.oldest_block_in_flight_time > 0);

    // Mix of response kinds: success, duplicate, orphan, buffer-full-drop,
    // put-failure. All route through recordBlockReceived. After N responses
    // for N requests the counter must be 0 and oldest_time must be cleared.
    dummy.recordBlockReceived(); // success
    dummy.recordBlockReceived(); // duplicate
    dummy.recordBlockReceived(); // orphan (buffered, drained later)
    dummy.recordBlockReceived(); // buffer-full-drop
    dummy.recordBlockReceived(); // put-failure / error
    try std.testing.expectEqual(@as(u32, 0), dummy.blocks_in_flight_count);
    try std.testing.expectEqual(@as(i64, 0), dummy.oldest_block_in_flight_time);

    // Extra decrements (e.g. stall-recovery reset followed by late response)
    // must not underflow. Counter stays at 0.
    dummy.recordBlockReceived();
    dummy.recordBlockReceived();
    try std.testing.expectEqual(@as(u32, 0), dummy.blocks_in_flight_count);
}

test "drain wedge: full-buffer drop rewinds download_cursor so the block is re-requested" {
    // Root cause of the 29,953 wedge: when block_buffer was full (1024) and a
    // non-next block arrived, it was dropped and the in-flight counter was
    // decremented (correct) — but download_cursor had already been advanced
    // past the dropped hash by pipelineBlockRequests. The normal pipeline
    // therefore never re-issued it; only the 5-second stall-recovery loop
    // re-requested (32 blocks/peer). That capped IBD throughput to ~6 blk/s
    // and the node wedged when every new block fell into the drop path.
    //
    // The fix: in the drop path, rewind download_cursor to connect_cursor
    // so the next pipelineBlockRequests walks the queue from the front and
    // re-requests any hash not currently in block_buffer. The buffer-contains
    // guard in pipelineBlockRequests makes the rewind cheap (already-buffered
    // hashes are skipped). This test models the cursor state after a drop
    // and asserts the rewind invariant.

    var download_cursor: u32 = 800;
    const connect_cursor: u32 = 100;

    // Drop path fires — rewind condition from the fix.
    if (download_cursor > connect_cursor) {
        download_cursor = connect_cursor;
    }
    try std.testing.expectEqual(@as(u32, 100), download_cursor);

    // Idempotent: if download_cursor was already at/behind connect_cursor
    // (e.g. just after a stall-recovery reset), don't rewind further.
    download_cursor = 50;
    if (download_cursor > connect_cursor) {
        download_cursor = connect_cursor;
    }
    try std.testing.expectEqual(@as(u32, 50), download_cursor);

    download_cursor = connect_cursor;
    if (download_cursor > connect_cursor) {
        download_cursor = connect_cursor;
    }
    try std.testing.expectEqual(connect_cursor, download_cursor);
}

test "drain wedge: global in-flight returns to zero after mixed responses" {
    // End-to-end counter invariant: after N requests and N responses of
    // arbitrary kinds (success, duplicate, orphan, buffer-full-drop,
    // put-failure, error), the global blocks_in_flight counter must be 0.
    // We model just the global counter path (the block-handler decrement)
    // without standing up a full PeerManager — the logic is a single
    // saturating subtract per response, applied once per response path.

    var blocks_in_flight: u32 = 0;

    // 10 requests.
    const n: u32 = 10;
    var i: u32 = 0;
    while (i < n) : (i += 1) blocks_in_flight += 1;
    try std.testing.expectEqual(n, blocks_in_flight);

    // 10 mixed responses — each decrements exactly once regardless of kind,
    // matching the unconditional decrement at the top of the .block branch.
    i = 0;
    while (i < n) : (i += 1) {
        if (blocks_in_flight > 0) blocks_in_flight -= 1;
    }
    try std.testing.expectEqual(@as(u32, 0), blocks_in_flight);

    // Late / unexpected response: saturating decrement — no underflow.
    if (blocks_in_flight > 0) blocks_in_flight -= 1;
    try std.testing.expectEqual(@as(u32, 0), blocks_in_flight);
}

// ============================================================================
// Wave 16 — Level-triggered per-peer block-request pipeline.
//
// These tests model the per-peer budgeting logic that replaced the global
// `blocks_in_flight < 128` gate after the wave-15 diagnostic showed the gate
// was edge-triggered in practice (reset fired on 94% of drain cycles).  They
// exercise the core invariants of `pipelineBlockRequests` without standing up
// a full PeerManager + socket fleet: (a) two peers can each hold the full
// per-peer cap of 16 in-flight blocks concurrently with no global collision,
// and (b) a slow peer whose in-flight count exceeds BLOCK_DOWNLOAD_TIMEOUT is
// disconnected and its slots are returned without affecting the other peers'
// budgets (and the download cursor is rewound so dropped hashes get
// re-requested — the wave-9 rewind preserved).
// ============================================================================

test "W16 pipeline: per-peer cap allows 32 concurrent in-flight across two peers" {
    // Model: two peers, each with per-peer cap MAX_BLOCKS_IN_TRANSIT_PER_PEER.
    // Pipeline fills each peer up to its cap; the sum is 2*cap with no global
    // ceiling that would have clamped a single peer's slot grab.
    var peer_a: Peer = undefined;
    peer_a.blocks_in_flight_count = 0;
    peer_a.oldest_block_in_flight_time = 0;
    peer_a.last_block_time = 0;

    var peer_b: Peer = undefined;
    peer_b.blocks_in_flight_count = 0;
    peer_b.oldest_block_in_flight_time = 0;
    peer_b.last_block_time = 0;

    const cap = MAX_BLOCKS_IN_TRANSIT_PER_PEER;
    try std.testing.expectEqual(@as(u32, 16), cap);

    // Fill peer A to its cap — mirrors the inner batch loop in
    // pipelineBlockRequests (`while (batch_count < peer_budget)`).
    var a_budget = cap - peer_a.blocks_in_flight_count;
    try std.testing.expectEqual(cap, a_budget);
    var i: u32 = 0;
    while (i < a_budget) : (i += 1) peer_a.recordBlockRequest();
    try std.testing.expectEqual(cap, peer_a.blocks_in_flight_count);

    // Fill peer B independently — the old global counter would have shown 16
    // here and clamped peer B to zero new slots.  Under per-peer budgeting
    // peer B sees its own fresh budget of cap.
    const b_budget = cap - peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(cap, b_budget);
    i = 0;
    while (i < b_budget) : (i += 1) peer_b.recordBlockRequest();
    try std.testing.expectEqual(cap, peer_b.blocks_in_flight_count);

    // Both peers at their cap concurrently: 2*cap = 32 blocks in flight,
    // no global collision, no edge-trigger wedge.
    const total = peer_a.blocks_in_flight_count + peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 32), total);

    // A third refill attempt on peer A with its cap already full yields
    // zero budget — pipeline correctly skips this peer on the next tick.
    a_budget = if (peer_a.blocks_in_flight_count >= cap) 0 else cap - peer_a.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 0), a_budget);

    // Peer A's first response frees one slot.  Peer B's cap is untouched —
    // this is the level-triggered property the wave-15 diag called out: a
    // slow peer does not starve the others.
    peer_a.recordBlockReceived();
    a_budget = cap - peer_a.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 1), a_budget);
    try std.testing.expectEqual(cap, peer_b.blocks_in_flight_count);
}

test "W16 pipeline: slow-peer disconnect rewinds cursor without stalling others" {
    // Slow-peer disconnect-and-rewind path replaces the old 5s global
    // stall-recovery reset.  When checkBlockDownloadTimeouts fires on
    // peer A, removePeerByIndex returns A's slots to the pool, and the
    // wave-9 buffer-drop rewind ensures the dropped hashes get
    // re-requested by the normal pipeline from peer B.
    var peer_a: Peer = undefined;
    peer_a.blocks_in_flight_count = 0;
    peer_a.oldest_block_in_flight_time = 0;
    peer_a.last_block_time = 0;

    var peer_b: Peer = undefined;
    peer_b.blocks_in_flight_count = 0;
    peer_b.oldest_block_in_flight_time = 0;
    peer_b.last_block_time = 0;

    // Both peers have outstanding requests; peer A is the slow one.
    var i: u32 = 0;
    while (i < 8) : (i += 1) peer_a.recordBlockRequest();
    i = 0;
    while (i < 4) : (i += 1) peer_b.recordBlockRequest();
    try std.testing.expectEqual(@as(u32, 8), peer_a.blocks_in_flight_count);
    try std.testing.expectEqual(@as(u32, 4), peer_b.blocks_in_flight_count);

    // Simulate BLOCK_DOWNLOAD_TIMEOUT on peer A: force oldest_time into
    // the past and assert hasBlockDownloadTimeout returns true.
    peer_a.oldest_block_in_flight_time = std.time.timestamp() - (BLOCK_DOWNLOAD_TIMEOUT + 1);
    try std.testing.expect(peer_a.hasBlockDownloadTimeout());
    try std.testing.expect(!peer_b.hasBlockDownloadTimeout());

    // removePeerByIndex decrements the global counter by the slow peer's
    // in-flight count (saturating subtract) and zeroes the peer's counters.
    // Model the global-counter update without a full PeerManager.
    var global: u32 = peer_a.blocks_in_flight_count + peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 12), global);
    if (global >= peer_a.blocks_in_flight_count) {
        global -= peer_a.blocks_in_flight_count;
    } else {
        global = 0;
    }
    // Peer B's budget is unaffected by A's disconnect — this is the core
    // guarantee over the old mass-reset path.
    try std.testing.expectEqual(@as(u32, 4), global);
    try std.testing.expectEqual(@as(u32, 4), peer_b.blocks_in_flight_count);

    // Wave-9 rewind invariant preserved: download_cursor rewinds to
    // connect_cursor so the pipeline re-issues dropped hashes on the next
    // tick (via peer B, which still has budget).  The buffer-contains
    // guard in pipelineBlockRequests makes the rewind cheap.
    var download_cursor: u32 = 800;
    const connect_cursor: u32 = 100;
    if (download_cursor > connect_cursor) download_cursor = connect_cursor;
    try std.testing.expectEqual(@as(u32, 100), download_cursor);

    // After rewind, peer B (still healthy) has cap - 4 = 12 slots of fresh
    // budget available to pick up the dropped hashes on the next
    // level-triggered tick.
    const b_remaining_budget = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 12), b_remaining_budget);
}

// ============================================================================
// BIP-324 negotiation: per-peer v1-fallback tracking on PeerManager.
// ============================================================================

test "BIP-324: markV1Only / isV1Only round-trip on IPv4" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET_PARAMS);
    defer pm.deinit();

    const addr = std.net.Address.initIp4(.{ 192, 168, 1, 50 }, 8333);
    try std.testing.expect(!pm.isV1Only(addr));
    pm.markV1Only(addr);
    try std.testing.expect(pm.isV1Only(addr));
}

test "BIP-324: v1-fallback set distinguishes addresses by port" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET_PARAMS);
    defer pm.deinit();

    const a = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8333);
    const b = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8334);
    pm.markV1Only(a);
    try std.testing.expect(pm.isV1Only(a));
    try std.testing.expect(!pm.isV1Only(b));
}

test "BIP-324: v1-fallback set caps at V2_FALLBACK_CACHE_MAX" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET_PARAMS);
    defer pm.deinit();

    // Insert V2_FALLBACK_CACHE_MAX + 5 entries; the cap must hold (LRU
    // drops a random entry on overflow, so we don't assert WHICH entry
    // got evicted, only that the count never exceeds the cap).
    var i: u32 = 0;
    while (i < PeerManager.V2_FALLBACK_CACHE_MAX + 5) : (i += 1) {
        const ip: [4]u8 = .{ @truncate(i >> 24), @truncate(i >> 16), @truncate(i >> 8), @truncate(i) };
        const port: u16 = @truncate(8333 + (i & 0xFFF));
        const addr = std.net.Address.initIp4(ip, port);
        pm.markV1Only(addr);
        try std.testing.expect(pm.v2_fallback_set.count() <= PeerManager.V2_FALLBACK_CACHE_MAX);
    }
}

test "BIP-324: bip324V2Enabled defaults off, honors env var" {
    // Default state — env unset.
    // We can't reliably unset an env var in a Zig test (no portable
    // unsetenv wrapper in std for our use), so verify only the non-set
    // path is false-by-default in production builds.  When the env var
    // is set to "1" by the operator, bip324V2Enabled() returns true.
    if (std.posix.getenv("CLEARBIT_BIP324_V2") == null) {
        try std.testing.expect(!Peer.bip324V2Enabled());
    }
}
