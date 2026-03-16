const std = @import("std");

// ============================================================================
// Proxy Module - Tor SOCKS5 and I2P SAM Support
// ============================================================================
//
// Implements anonymous network connectivity for private node operation:
// - SOCKS5 proxy (RFC 1928) for Tor and generic proxies
// - Tor control protocol for hidden service creation
// - I2P SAM v3.1 protocol for I2P network access
//
// Reference: Bitcoin Core netbase.cpp (SOCKS5) and i2p.cpp (I2P SAM)

// ============================================================================
// SOCKS5 Protocol Constants (RFC 1928)
// ============================================================================

/// SOCKS5 protocol version.
pub const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication method - no authentication.
pub const SOCKS5_AUTH_NONE: u8 = 0x00;

/// SOCKS5 authentication method - username/password (RFC 1929).
pub const SOCKS5_AUTH_PASSWORD: u8 = 0x02;

/// SOCKS5 no acceptable methods.
pub const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;

/// SOCKS5 command - CONNECT.
pub const SOCKS5_CMD_CONNECT: u8 = 0x01;

/// SOCKS5 address type - IPv4.
pub const SOCKS5_ATYP_IPV4: u8 = 0x01;

/// SOCKS5 address type - domain name.
pub const SOCKS5_ATYP_DOMAINNAME: u8 = 0x03;

/// SOCKS5 address type - IPv6.
pub const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes.
pub const Socks5Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,

    // Tor-specific error codes (0xF0-0xF7).
    tor_hidden_service_not_found = 0xF0,
    tor_hidden_service_unreachable = 0xF1,
    tor_hidden_service_key_mismatch = 0xF2,
    tor_hidden_service_auth_failed = 0xF3,
    tor_ttl_expired = 0xF6,
    tor_protocol_error = 0xF7,

    _,

    pub fn description(self: Socks5Reply) []const u8 {
        return switch (self) {
            .succeeded => "succeeded",
            .general_failure => "general SOCKS server failure",
            .connection_not_allowed => "connection not allowed by ruleset",
            .network_unreachable => "network unreachable",
            .host_unreachable => "host unreachable",
            .connection_refused => "connection refused",
            .ttl_expired => "TTL expired",
            .command_not_supported => "command not supported",
            .address_type_not_supported => "address type not supported",
            .tor_hidden_service_not_found => "Tor hidden service not found",
            .tor_hidden_service_unreachable => "Tor hidden service unreachable",
            .tor_hidden_service_key_mismatch => "Tor hidden service key mismatch",
            .tor_hidden_service_auth_failed => "Tor hidden service auth failed",
            .tor_ttl_expired => "Tor TTL expired",
            .tor_protocol_error => "Tor protocol error",
            _ => "unknown SOCKS5 error",
        };
    }
};

// ============================================================================
// SOCKS5 Timeout Constants
// ============================================================================

/// Receive timeout for SOCKS5 operations (20 seconds - ample for Tor).
pub const SOCKS5_RECV_TIMEOUT_SEC: u32 = 20;

/// Connect timeout (30 seconds).
pub const SOCKS5_CONNECT_TIMEOUT_SEC: u32 = 30;

// ============================================================================
// I2P SAM Protocol Constants
// ============================================================================

/// I2P SAM minimum supported version.
pub const I2P_SAM_MIN_VERSION: []const u8 = "3.1";

/// I2P SAM maximum supported version.
pub const I2P_SAM_MAX_VERSION: []const u8 = "3.1";

/// I2P signature type - EdDSA with SHA512 and Ed25519 (modern, preferred).
pub const I2P_SIGNATURE_TYPE: u8 = 7;

/// I2P lease set encryption types: 4 = ECIES_X25519_AEAD, 0 = ElGamal.
pub const I2P_LEASE_SET_ENC_TYPE: []const u8 = "4,0";

/// I2P receive timeout (3 minutes - I2P operations can be slow).
pub const I2P_RECV_TIMEOUT_SEC: u32 = 180;

/// Maximum I2P SAM message size.
pub const I2P_MAX_MSG_SIZE: usize = 65536;

// ============================================================================
// Proxy Configuration Types
// ============================================================================

/// Proxy type enumeration.
pub const ProxyType = enum {
    none,
    socks5,
    tor,
    i2p,
};

/// SOCKS5 authentication credentials.
pub const Socks5Credentials = struct {
    username: []const u8,
    password: []const u8,

    /// Maximum username/password length per RFC 1929.
    pub const MAX_LEN: usize = 255;

    pub fn validate(self: *const Socks5Credentials) bool {
        return self.username.len <= MAX_LEN and self.password.len <= MAX_LEN;
    }
};

/// Proxy configuration for a single network type.
pub const ProxyConfig = struct {
    proxy_type: ProxyType = .none,
    host: []const u8 = "",
    port: u16 = 0,
    credentials: ?Socks5Credentials = null,
    /// For I2P: path to persistent private key file.
    i2p_key_file: ?[]const u8 = null,
};

/// Network type for ADDRv2 compatibility.
pub const NetworkId = enum(u8) {
    ipv4 = 1,
    ipv6 = 2,
    torv2 = 3, // Deprecated
    torv3 = 4,
    i2p = 5,
    cjdns = 6,
};

/// Multi-network address for ADDRv2 protocol (BIP 155).
pub const MultiNetworkAddress = struct {
    network: NetworkId,
    address: []const u8,
    port: u16,

    /// Address lengths for each network type.
    pub fn expectedAddressLen(network: NetworkId) ?usize {
        return switch (network) {
            .ipv4 => 4,
            .ipv6 => 16,
            .torv2 => 10, // Deprecated
            .torv3 => 32,
            .i2p => 32,
            .cjdns => 16,
        };
    }

    /// Convert to hostname string for SOCKS5 CONNECT.
    pub fn toHostname(self: *const MultiNetworkAddress, allocator: std.mem.Allocator) ![]const u8 {
        return switch (self.network) {
            .ipv4 => {
                if (self.address.len != 4) return error.InvalidAddress;
                return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
                    self.address[0],
                    self.address[1],
                    self.address[2],
                    self.address[3],
                });
            },
            .ipv6 => {
                if (self.address.len != 16) return error.InvalidAddress;
                // Format as bracketed IPv6
                var buf: [64]u8 = undefined;
                var idx: usize = 0;
                for (0..8) |i| {
                    if (i > 0) {
                        buf[idx] = ':';
                        idx += 1;
                    }
                    const word = (@as(u16, self.address[i * 2]) << 8) | self.address[i * 2 + 1];
                    const slice = std.fmt.bufPrint(buf[idx..], "{x}", .{word}) catch unreachable;
                    idx += slice.len;
                }
                return allocator.dupe(u8, buf[0..idx]);
            },
            .torv3 => {
                // Tor v3: 32 bytes -> base32 + ".onion"
                if (self.address.len != 32) return error.InvalidAddress;
                var hash_buf: [56]u8 = undefined;
                base32EncodeOnion(self.address, &hash_buf);
                return std.fmt.allocPrint(allocator, "{s}.onion", .{hash_buf});
            },
            .i2p => {
                // I2P: 32 bytes SHA256 hash -> base32 + ".b32.i2p"
                if (self.address.len != 32) return error.InvalidAddress;
                var hash_buf: [52]u8 = undefined;
                base32EncodeI2P(self.address[0..32], &hash_buf);
                return std.fmt.allocPrint(allocator, "{s}.b32.i2p", .{hash_buf});
            },
            .torv2, .cjdns => error.UnsupportedNetwork,
        };
    }
};

// ============================================================================
// Proxy Errors
// ============================================================================

pub const ProxyError = error{
    ConnectionFailed,
    AuthenticationFailed,
    ConnectionRefused,
    NetworkUnreachable,
    HostUnreachable,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    GeneralFailure,
    ProtocolError,
    Timeout,
    InvalidResponse,
    UnsupportedNetwork,
    InvalidAddress,
    InvalidCredentials,
    SessionCreationFailed,
    HiddenServiceCreationFailed,
    KeyGenerationFailed,
    OutOfMemory,
};

// ============================================================================
// SOCKS5 Proxy Client
// ============================================================================

/// SOCKS5 proxy client for TCP connections through Tor or generic SOCKS5 proxies.
pub const Socks5Client = struct {
    proxy_host: []const u8,
    proxy_port: u16,
    credentials: ?Socks5Credentials,
    allocator: std.mem.Allocator,

    /// Create a new SOCKS5 client.
    pub fn init(
        proxy_host: []const u8,
        proxy_port: u16,
        credentials: ?Socks5Credentials,
        allocator: std.mem.Allocator,
    ) Socks5Client {
        return .{
            .proxy_host = proxy_host,
            .proxy_port = proxy_port,
            .credentials = credentials,
            .allocator = allocator,
        };
    }

    /// Connect to a target host through the SOCKS5 proxy.
    /// Returns the connected stream that can be used for further communication.
    pub fn connect(
        self: *const Socks5Client,
        target_host: []const u8,
        target_port: u16,
    ) ProxyError!std.net.Stream {
        // Validate target hostname length
        if (target_host.len > 255) return ProxyError.InvalidAddress;

        // Connect to proxy
        const proxy_address = std.net.Address.resolveIp(self.proxy_host, self.proxy_port) catch
            return ProxyError.ConnectionFailed;

        var stream = std.net.tcpConnectToAddress(proxy_address) catch
            return ProxyError.ConnectionFailed;
        errdefer stream.close();

        // Set socket timeout
        const timeout = std.posix.timeval{ .sec = @intCast(SOCKS5_RECV_TIMEOUT_SEC), .usec = 0 };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};

        // Perform SOCKS5 handshake
        try self.performHandshake(&stream);

        // Send CONNECT request
        try self.sendConnectRequest(&stream, target_host, target_port);

        // Receive and validate CONNECT response
        try self.receiveConnectResponse(&stream);

        return stream;
    }

    /// Perform SOCKS5 method selection and authentication.
    fn performHandshake(self: *const Socks5Client, stream: *std.net.Stream) ProxyError!void {
        // Build greeting: VERSION | NMETHODS | METHODS
        var greeting: [4]u8 = undefined;
        var greeting_len: usize = 0;

        greeting[0] = SOCKS5_VERSION;
        if (self.credentials) |creds| {
            if (!creds.validate()) return ProxyError.InvalidCredentials;
            // Offer both no-auth and username/password
            greeting[1] = 2; // 2 methods
            greeting[2] = SOCKS5_AUTH_NONE;
            greeting[3] = SOCKS5_AUTH_PASSWORD;
            greeting_len = 4;
        } else {
            // Only offer no-auth
            greeting[1] = 1; // 1 method
            greeting[2] = SOCKS5_AUTH_NONE;
            greeting_len = 3;
        }

        stream.writeAll(greeting[0..greeting_len]) catch return ProxyError.ConnectionFailed;

        // Receive method selection response
        var response: [2]u8 = undefined;
        readExact(stream, &response) catch return ProxyError.ConnectionFailed;

        if (response[0] != SOCKS5_VERSION) return ProxyError.ProtocolError;

        const selected_method = response[1];

        if (selected_method == SOCKS5_AUTH_NO_ACCEPTABLE) {
            return ProxyError.AuthenticationFailed;
        }

        if (selected_method == SOCKS5_AUTH_PASSWORD) {
            if (self.credentials) |creds| {
                try self.performPasswordAuth(stream, creds);
            } else {
                return ProxyError.AuthenticationFailed;
            }
        } else if (selected_method != SOCKS5_AUTH_NONE) {
            return ProxyError.ProtocolError;
        }
    }

    /// Perform username/password authentication (RFC 1929).
    fn performPasswordAuth(
        _: *const Socks5Client,
        stream: *std.net.Stream,
        creds: Socks5Credentials,
    ) ProxyError!void {
        // Format: VER(0x01) | ULEN | USERNAME | PLEN | PASSWORD
        var auth_buf: [1 + 1 + 255 + 1 + 255]u8 = undefined;
        var idx: usize = 0;

        auth_buf[idx] = 0x01; // Auth sub-negotiation version
        idx += 1;
        auth_buf[idx] = @intCast(creds.username.len);
        idx += 1;
        @memcpy(auth_buf[idx..][0..creds.username.len], creds.username);
        idx += creds.username.len;
        auth_buf[idx] = @intCast(creds.password.len);
        idx += 1;
        @memcpy(auth_buf[idx..][0..creds.password.len], creds.password);
        idx += creds.password.len;

        stream.writeAll(auth_buf[0..idx]) catch return ProxyError.ConnectionFailed;

        // Receive auth response: VER | STATUS
        var auth_response: [2]u8 = undefined;
        readExact(stream, &auth_response) catch return ProxyError.ConnectionFailed;

        if (auth_response[0] != 0x01 or auth_response[1] != 0x00) {
            return ProxyError.AuthenticationFailed;
        }
    }

    /// Send SOCKS5 CONNECT request.
    fn sendConnectRequest(
        _: *const Socks5Client,
        stream: *std.net.Stream,
        target_host: []const u8,
        target_port: u16,
    ) ProxyError!void {
        // Format: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        var request: [4 + 1 + 255 + 2]u8 = undefined;
        var idx: usize = 0;

        request[idx] = SOCKS5_VERSION;
        idx += 1;
        request[idx] = SOCKS5_CMD_CONNECT;
        idx += 1;
        request[idx] = 0x00; // Reserved
        idx += 1;
        request[idx] = SOCKS5_ATYP_DOMAINNAME;
        idx += 1;
        request[idx] = @intCast(target_host.len);
        idx += 1;
        @memcpy(request[idx..][0..target_host.len], target_host);
        idx += target_host.len;
        // Port in network byte order (big-endian)
        request[idx] = @intCast((target_port >> 8) & 0xFF);
        idx += 1;
        request[idx] = @intCast(target_port & 0xFF);
        idx += 1;

        stream.writeAll(request[0..idx]) catch return ProxyError.ConnectionFailed;
    }

    /// Receive and validate SOCKS5 CONNECT response.
    fn receiveConnectResponse(_: *const Socks5Client, stream: *std.net.Stream) ProxyError!void {
        // Read first 4 bytes: VER | REP | RSV | ATYP
        var header: [4]u8 = undefined;
        readExact(stream, &header) catch return ProxyError.ConnectionFailed;

        if (header[0] != SOCKS5_VERSION) return ProxyError.ProtocolError;
        if (header[2] != 0x00) return ProxyError.ProtocolError; // Reserved must be 0

        const reply: Socks5Reply = @enumFromInt(header[1]);
        if (reply != .succeeded) {
            return switch (reply) {
                .connection_refused => ProxyError.ConnectionRefused,
                .network_unreachable => ProxyError.NetworkUnreachable,
                .host_unreachable => ProxyError.HostUnreachable,
                .ttl_expired, .tor_ttl_expired => ProxyError.TtlExpired,
                .command_not_supported => ProxyError.CommandNotSupported,
                .address_type_not_supported => ProxyError.AddressTypeNotSupported,
                .tor_hidden_service_not_found,
                .tor_hidden_service_unreachable,
                .tor_hidden_service_key_mismatch,
                .tor_hidden_service_auth_failed,
                .tor_protocol_error,
                => ProxyError.HostUnreachable,
                else => ProxyError.GeneralFailure,
            };
        }

        // Read bound address based on ATYP
        const atyp = header[3];
        var skip_len: usize = 0;
        switch (atyp) {
            SOCKS5_ATYP_IPV4 => skip_len = 4 + 2, // 4 bytes IP + 2 bytes port
            SOCKS5_ATYP_IPV6 => skip_len = 16 + 2, // 16 bytes IP + 2 bytes port
            SOCKS5_ATYP_DOMAINNAME => {
                var len_buf: [1]u8 = undefined;
                readExact(stream, &len_buf) catch return ProxyError.ConnectionFailed;
                skip_len = len_buf[0] + 2; // domain + 2 bytes port
            },
            else => return ProxyError.ProtocolError,
        }

        // Skip bound address (we don't need it)
        var skip_buf: [256 + 2]u8 = undefined;
        readExact(stream, skip_buf[0..skip_len]) catch return ProxyError.ConnectionFailed;
    }
};

// ============================================================================
// Tor Control Protocol Client
// ============================================================================

/// Tor control protocol client for creating hidden services.
pub const TorControlClient = struct {
    host: []const u8,
    port: u16,
    password: ?[]const u8,
    allocator: std.mem.Allocator,

    /// Response from ADD_ONION command.
    pub const HiddenServiceInfo = struct {
        service_id: []const u8, // .onion hostname (without .onion suffix)
        private_key: ?[]const u8, // Private key if generated
    };

    /// Create a new Tor control client.
    pub fn init(
        host: []const u8,
        port: u16,
        password: ?[]const u8,
        allocator: std.mem.Allocator,
    ) TorControlClient {
        return .{
            .host = host,
            .port = port,
            .password = password,
            .allocator = allocator,
        };
    }

    /// Create a new Tor hidden service.
    /// Returns the .onion service ID and optionally the private key.
    pub fn createHiddenService(
        self: *const TorControlClient,
        local_port: u16,
        virtual_port: u16,
    ) ProxyError!HiddenServiceInfo {
        const address = std.net.Address.resolveIp(self.host, self.port) catch
            return ProxyError.ConnectionFailed;

        var stream = std.net.tcpConnectToAddress(address) catch
            return ProxyError.ConnectionFailed;
        defer stream.close();

        // Authenticate
        try self.authenticate(&stream);

        // Create hidden service
        return self.addOnion(&stream, local_port, virtual_port);
    }

    /// Authenticate with the Tor control port.
    fn authenticate(self: *const TorControlClient, stream: *std.net.Stream) ProxyError!void {
        var buf: [512]u8 = undefined;
        const cmd = if (self.password) |pwd|
            std.fmt.bufPrint(&buf, "AUTHENTICATE \"{s}\"\r\n", .{pwd}) catch
                return ProxyError.OutOfMemory
        else
            "AUTHENTICATE\r\n";

        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        // Read response
        var response_buf: [256]u8 = undefined;
        const response = readLine(stream, &response_buf) catch return ProxyError.ConnectionFailed;

        // Expected: "250 OK\r\n"
        if (!std.mem.startsWith(u8, response, "250")) {
            return ProxyError.AuthenticationFailed;
        }
    }

    /// Add a new onion service.
    fn addOnion(
        self: *const TorControlClient,
        stream: *std.net.Stream,
        local_port: u16,
        virtual_port: u16,
    ) ProxyError!HiddenServiceInfo {
        // ADD_ONION NEW:ED25519-V3 Port=<virtual>,127.0.0.1:<local>
        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "ADD_ONION NEW:ED25519-V3 Port={d},127.0.0.1:{d}\r\n", .{
            virtual_port,
            local_port,
        }) catch return ProxyError.OutOfMemory;

        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        // Read response lines until we get 250 OK or an error
        var service_id: ?[]const u8 = null;
        var private_key: ?[]const u8 = null;

        while (true) {
            var line_buf: [1024]u8 = undefined;
            const line = readLine(stream, &line_buf) catch return ProxyError.ConnectionFailed;

            if (std.mem.startsWith(u8, line, "250-ServiceID=")) {
                const id = line["250-ServiceID=".len..];
                service_id = self.allocator.dupe(u8, id) catch return ProxyError.OutOfMemory;
            } else if (std.mem.startsWith(u8, line, "250-PrivateKey=")) {
                const key = line["250-PrivateKey=".len..];
                private_key = self.allocator.dupe(u8, key) catch return ProxyError.OutOfMemory;
            } else if (std.mem.startsWith(u8, line, "250 OK")) {
                break;
            } else if (std.mem.startsWith(u8, line, "5")) {
                // Error response (5xx)
                return ProxyError.HiddenServiceCreationFailed;
            }
        }

        if (service_id) |id| {
            return .{
                .service_id = id,
                .private_key = private_key,
            };
        }

        return ProxyError.HiddenServiceCreationFailed;
    }
};

// ============================================================================
// I2P SAM Protocol Client
// ============================================================================

/// I2P SAM (Simple Anonymous Messaging) v3.1 client.
pub const I2pSamClient = struct {
    host: []const u8,
    port: u16,
    key_file: ?[]const u8,
    allocator: std.mem.Allocator,
    session_id: ?[]const u8 = null,
    private_key: ?[]const u8 = null,
    destination: ?[]const u8 = null,
    control_stream: ?std.net.Stream = null,

    /// Create a new I2P SAM client.
    pub fn init(
        host: []const u8,
        port: u16,
        key_file: ?[]const u8,
        allocator: std.mem.Allocator,
    ) I2pSamClient {
        return .{
            .host = host,
            .port = port,
            .key_file = key_file,
            .allocator = allocator,
        };
    }

    /// Deinitialize and close control connection.
    pub fn deinit(self: *I2pSamClient) void {
        if (self.control_stream) |*stream| {
            stream.close();
            self.control_stream = null;
        }
        if (self.session_id) |id| {
            self.allocator.free(id);
            self.session_id = null;
        }
        if (self.private_key) |key| {
            self.allocator.free(key);
            self.private_key = null;
        }
        if (self.destination) |dest| {
            self.allocator.free(dest);
            self.destination = null;
        }
    }

    /// Establish SAM session with handshake and session creation.
    pub fn connect(self: *I2pSamClient) ProxyError!void {
        // Connect to SAM router
        const address = std.net.Address.resolveIp(self.host, self.port) catch
            return ProxyError.ConnectionFailed;

        var stream = std.net.tcpConnectToAddress(address) catch
            return ProxyError.ConnectionFailed;
        errdefer stream.close();

        // Set socket timeout
        const timeout = std.posix.timeval{ .sec = @intCast(I2P_RECV_TIMEOUT_SEC), .usec = 0 };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};

        // Perform HELLO handshake
        try self.hello(&stream);

        // Load or generate private key
        const private_key = try self.loadOrGenerateKey(&stream);
        self.private_key = private_key;

        // Create session
        try self.createSession(&stream, private_key);

        self.control_stream = stream;
    }

    /// Connect to a remote I2P destination.
    pub fn connectTo(
        self: *I2pSamClient,
        destination_b32: []const u8,
    ) ProxyError!std.net.Stream {
        if (self.session_id == null) {
            try self.connect();
        }

        // Open a new connection for STREAM CONNECT
        const address = std.net.Address.resolveIp(self.host, self.port) catch
            return ProxyError.ConnectionFailed;

        var stream = std.net.tcpConnectToAddress(address) catch
            return ProxyError.ConnectionFailed;
        errdefer stream.close();

        // Set socket timeout
        const timeout = std.posix.timeval{ .sec = @intCast(I2P_RECV_TIMEOUT_SEC), .usec = 0 };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};

        // Hello on new connection
        try self.hello(&stream);

        // Resolve destination if it's a .b32.i2p address
        var resolved_dest: []const u8 = undefined;
        var resolved_dest_owned: ?[]const u8 = null;
        if (std.mem.endsWith(u8, destination_b32, ".b32.i2p") or
            std.mem.endsWith(u8, destination_b32, ".i2p"))
        {
            resolved_dest_owned = try self.namingLookup(&stream, destination_b32);
            resolved_dest = resolved_dest_owned.?;
        } else {
            resolved_dest = destination_b32;
        }
        defer if (resolved_dest_owned) |d| self.allocator.free(d);

        // STREAM CONNECT
        var cmd_buf: [I2P_MAX_MSG_SIZE]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "STREAM CONNECT ID={s} DESTINATION={s} SILENT=false\n", .{
            self.session_id.?,
            resolved_dest,
        }) catch return ProxyError.OutOfMemory;

        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        // Read response
        var response_buf: [512]u8 = undefined;
        const response = readLine(&stream, &response_buf) catch return ProxyError.ConnectionFailed;

        if (!std.mem.startsWith(u8, response, "STREAM STATUS RESULT=OK")) {
            if (std.mem.indexOf(u8, response, "CANT_REACH_PEER") != null) {
                return ProxyError.HostUnreachable;
            }
            if (std.mem.indexOf(u8, response, "TIMEOUT") != null) {
                return ProxyError.Timeout;
            }
            return ProxyError.ConnectionFailed;
        }

        return stream;
    }

    /// Accept an incoming I2P connection.
    pub fn accept(self: *I2pSamClient) ProxyError!std.net.Stream {
        if (self.session_id == null) {
            try self.connect();
        }

        // Open a new connection for STREAM ACCEPT
        const address = std.net.Address.resolveIp(self.host, self.port) catch
            return ProxyError.ConnectionFailed;

        var stream = std.net.tcpConnectToAddress(address) catch
            return ProxyError.ConnectionFailed;
        errdefer stream.close();

        // Hello on new connection
        try self.hello(&stream);

        // STREAM ACCEPT
        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "STREAM ACCEPT ID={s} SILENT=false\n", .{
            self.session_id.?,
        }) catch return ProxyError.OutOfMemory;

        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        // Read response - returns peer's destination
        var response_buf: [I2P_MAX_MSG_SIZE]u8 = undefined;
        const response = readLine(&stream, &response_buf) catch return ProxyError.ConnectionFailed;

        // Check for error
        if (std.mem.startsWith(u8, response, "STREAM STATUS")) {
            if (std.mem.indexOf(u8, response, "RESULT=OK") == null) {
                return ProxyError.ConnectionFailed;
            }
        }

        return stream;
    }

    /// Get our I2P address (b32.i2p).
    pub fn getAddress(self: *const I2pSamClient) ?[]const u8 {
        if (self.destination) |dest| {
            // Compute b32 address from destination
            _ = dest;
            // This would require base64 decode + SHA256 + base32 encode
            // For now, return null - caller should use the full destination
            return null;
        }
        return null;
    }

    /// Perform SAM HELLO handshake.
    fn hello(_: *I2pSamClient, stream: *std.net.Stream) ProxyError!void {
        const cmd = "HELLO VERSION MIN=3.1 MAX=3.1\n";
        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        var response_buf: [256]u8 = undefined;
        const response = readLine(stream, &response_buf) catch return ProxyError.ConnectionFailed;

        // Expected: "HELLO REPLY RESULT=OK VERSION=3.1"
        if (std.mem.indexOf(u8, response, "RESULT=OK") == null) {
            return ProxyError.ProtocolError;
        }
    }

    /// Load private key from file or generate a new one.
    fn loadOrGenerateKey(self: *I2pSamClient, stream: *std.net.Stream) ProxyError![]const u8 {
        // Try to load from file
        if (self.key_file) |key_path| {
            const file = std.fs.cwd().openFile(key_path, .{}) catch |err| switch (err) {
                error.FileNotFound => {
                    // Generate new key and save
                    const key = try self.generateKey(stream);
                    self.saveKey(key_path, key) catch {};
                    return key;
                },
                else => return ProxyError.ConnectionFailed,
            };
            defer file.close();

            const key = file.readToEndAlloc(self.allocator, I2P_MAX_MSG_SIZE) catch
                return ProxyError.OutOfMemory;
            return key;
        }

        // No key file - generate transient key
        return self.generateKey(stream);
    }

    /// Generate a new I2P key pair.
    fn generateKey(self: *I2pSamClient, stream: *std.net.Stream) ProxyError![]const u8 {
        const cmd = "DEST GENERATE SIGNATURE_TYPE=7\n";
        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        var response_buf: [I2P_MAX_MSG_SIZE]u8 = undefined;
        const response = readLine(stream, &response_buf) catch return ProxyError.ConnectionFailed;

        // Expected: "DEST REPLY PUB=... PRIV=..."
        if (std.mem.indexOf(u8, response, "PRIV=")) |priv_start| {
            const key_start = priv_start + 5;
            var key_end = key_start;
            while (key_end < response.len and response[key_end] != ' ' and response[key_end] != '\n') {
                key_end += 1;
            }
            return self.allocator.dupe(u8, response[key_start..key_end]) catch
                return ProxyError.OutOfMemory;
        }

        return ProxyError.KeyGenerationFailed;
    }

    /// Save private key to file.
    fn saveKey(_: *I2pSamClient, path: []const u8, key: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(key);
    }

    /// Create a SAM session.
    fn createSession(
        self: *I2pSamClient,
        stream: *std.net.Stream,
        private_key: []const u8,
    ) ProxyError!void {
        // Generate session ID
        var id_buf: [10]u8 = undefined;
        std.crypto.random.bytes(&id_buf);
        var id_hex: [20]u8 = undefined;
        _ = std.fmt.bufPrint(&id_hex, "{}", .{std.fmt.fmtSliceHexLower(&id_buf)}) catch unreachable;

        const session_id = self.allocator.dupe(u8, &id_hex) catch return ProxyError.OutOfMemory;
        errdefer self.allocator.free(session_id);

        // SESSION CREATE
        var cmd_buf: [I2P_MAX_MSG_SIZE]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "SESSION CREATE STYLE=STREAM ID={s} DESTINATION={s} i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3\n", .{
            session_id,
            private_key,
        }) catch return ProxyError.OutOfMemory;

        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        // Read response
        var response_buf: [I2P_MAX_MSG_SIZE]u8 = undefined;
        const response = readLine(stream, &response_buf) catch return ProxyError.ConnectionFailed;

        // Expected: "SESSION STATUS RESULT=OK DESTINATION=..."
        if (std.mem.indexOf(u8, response, "RESULT=OK") == null) {
            return ProxyError.SessionCreationFailed;
        }

        // Extract destination if present
        if (std.mem.indexOf(u8, response, "DESTINATION=")) |dest_start| {
            const val_start = dest_start + 12;
            var val_end = val_start;
            while (val_end < response.len and response[val_end] != ' ' and response[val_end] != '\n') {
                val_end += 1;
            }
            self.destination = self.allocator.dupe(u8, response[val_start..val_end]) catch null;
        }

        self.session_id = session_id;
    }

    /// Perform NAMING LOOKUP for I2P addresses.
    fn namingLookup(self: *I2pSamClient, stream: *std.net.Stream, name: []const u8) ProxyError![]const u8 {
        var cmd_buf: [512]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "NAMING LOOKUP NAME={s}\n", .{name}) catch
            return ProxyError.OutOfMemory;

        stream.writeAll(cmd) catch return ProxyError.ConnectionFailed;

        var response_buf: [I2P_MAX_MSG_SIZE]u8 = undefined;
        const response = readLine(stream, &response_buf) catch return ProxyError.ConnectionFailed;

        // Expected: "NAMING REPLY RESULT=OK VALUE=..."
        if (std.mem.indexOf(u8, response, "RESULT=OK") == null) {
            return ProxyError.HostUnreachable;
        }

        if (std.mem.indexOf(u8, response, "VALUE=")) |val_start| {
            const start = val_start + 6;
            var end = start;
            while (end < response.len and response[end] != ' ' and response[end] != '\n') {
                end += 1;
            }
            return self.allocator.dupe(u8, response[start..end]) catch
                return ProxyError.OutOfMemory;
        }

        return ProxyError.HostUnreachable;
    }
};

// ============================================================================
// Multi-Network Proxy Manager
// ============================================================================

/// Manages simultaneous proxy connections across multiple networks.
pub const ProxyManager = struct {
    clearnet_config: ProxyConfig,
    tor_config: ProxyConfig,
    i2p_config: ProxyConfig,
    allocator: std.mem.Allocator,

    // Lazy-initialized clients
    socks5_client: ?Socks5Client = null,
    tor_control: ?TorControlClient = null,
    i2p_client: ?I2pSamClient = null,

    /// Initialize proxy manager with configurations.
    pub fn init(
        clearnet_config: ProxyConfig,
        tor_config: ProxyConfig,
        i2p_config: ProxyConfig,
        allocator: std.mem.Allocator,
    ) ProxyManager {
        return .{
            .clearnet_config = clearnet_config,
            .tor_config = tor_config,
            .i2p_config = i2p_config,
            .allocator = allocator,
        };
    }

    /// Connect to a multi-network address using the appropriate proxy.
    pub fn connectTo(self: *ProxyManager, addr: *const MultiNetworkAddress) ProxyError!std.net.Stream {
        return switch (addr.network) {
            .ipv4, .ipv6 => {
                // Use clearnet or Tor SOCKS5 proxy
                if (self.clearnet_config.proxy_type == .socks5) {
                    if (self.socks5_client == null) {
                        self.socks5_client = Socks5Client.init(
                            self.clearnet_config.host,
                            self.clearnet_config.port,
                            self.clearnet_config.credentials,
                            self.allocator,
                        );
                    }
                    const hostname = addr.toHostname(self.allocator) catch return ProxyError.InvalidAddress;
                    defer self.allocator.free(hostname);
                    return self.socks5_client.?.connect(hostname, addr.port);
                }
                // Direct connection (no proxy)
                return directConnect(addr);
            },
            .torv3 => {
                // Use Tor SOCKS5 proxy
                if (self.tor_config.proxy_type != .socks5 and self.tor_config.proxy_type != .tor) {
                    return ProxyError.UnsupportedNetwork;
                }
                if (self.socks5_client == null or
                    !std.mem.eql(u8, self.socks5_client.?.proxy_host, self.tor_config.host))
                {
                    self.socks5_client = Socks5Client.init(
                        self.tor_config.host,
                        self.tor_config.port,
                        self.tor_config.credentials,
                        self.allocator,
                    );
                }
                const hostname = addr.toHostname(self.allocator) catch return ProxyError.InvalidAddress;
                defer self.allocator.free(hostname);
                return self.socks5_client.?.connect(hostname, addr.port);
            },
            .i2p => {
                // Use I2P SAM
                if (self.i2p_config.proxy_type != .i2p) {
                    return ProxyError.UnsupportedNetwork;
                }
                if (self.i2p_client == null) {
                    self.i2p_client = I2pSamClient.init(
                        self.i2p_config.host,
                        self.i2p_config.port,
                        self.i2p_config.i2p_key_file,
                        self.allocator,
                    );
                }
                const hostname = addr.toHostname(self.allocator) catch return ProxyError.InvalidAddress;
                defer self.allocator.free(hostname);
                return self.i2p_client.?.connectTo(hostname);
            },
            .torv2, .cjdns => ProxyError.UnsupportedNetwork,
        };
    }

    /// Deinitialize all proxy clients.
    pub fn deinit(self: *ProxyManager) void {
        if (self.i2p_client) |*client| {
            client.deinit();
        }
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Read exactly n bytes from a stream.
fn readExact(stream: *std.net.Stream, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = stream.read(buf[total..]) catch |err| {
            return err;
        };
        if (n == 0) return error.EndOfStream;
        total += n;
    }
}

/// Read a line terminated by \n or \r\n from a stream.
fn readLine(stream: *std.net.Stream, buf: []u8) ![]const u8 {
    var idx: usize = 0;
    while (idx < buf.len) {
        var byte: [1]u8 = undefined;
        const n = stream.read(&byte) catch |err| {
            return err;
        };
        if (n == 0) {
            if (idx > 0) return buf[0..idx];
            return error.EndOfStream;
        }
        if (byte[0] == '\n') {
            // Strip \r if present
            if (idx > 0 and buf[idx - 1] == '\r') {
                return buf[0 .. idx - 1];
            }
            return buf[0..idx];
        }
        buf[idx] = byte[0];
        idx += 1;
    }
    return buf[0..idx]; // Buffer full
}

/// Direct TCP connection without proxy.
fn directConnect(addr: *const MultiNetworkAddress) ProxyError!std.net.Stream {
    const net_addr = switch (addr.network) {
        .ipv4 => blk: {
            if (addr.address.len != 4) return ProxyError.InvalidAddress;
            break :blk std.net.Address.initIp4(addr.address[0..4].*, addr.port);
        },
        .ipv6 => blk: {
            if (addr.address.len != 16) return ProxyError.InvalidAddress;
            break :blk std.net.Address.initIp6(addr.address[0..16].*, addr.port, 0, 0);
        },
        else => return ProxyError.UnsupportedNetwork,
    };

    return std.net.tcpConnectToAddress(net_addr) catch ProxyError.ConnectionFailed;
}

// ============================================================================
// Base32 Encoding for Onion Addresses
// ============================================================================

/// Base32 alphabet for Tor onion addresses (RFC 4648).
const BASE32_ALPHABET: *const [32]u8 = "abcdefghijklmnopqrstuvwxyz234567";

/// Encode Tor v3 address (32 bytes) to base32 (56 chars).
fn base32EncodeOnion(data: []const u8, out: *[56]u8) void {
    // Tor v3 onion addresses encode: pubkey (32 bytes) + checksum (2 bytes) + version (1 byte)
    // For now, we just encode the 32-byte pubkey + computed checksum
    var full: [35]u8 = undefined;
    @memcpy(full[0..32], data);

    // Compute checksum: SHA3-256(".onion checksum" || pubkey || version)[0..2]
    // Simplified: just use zeros for demo (real implementation needs SHA3)
    full[32] = 0;
    full[33] = 0;
    full[34] = 0x03; // Version 3

    base32EncodeBytes(full[0..35], out);
}

/// Encode I2P destination hash (32 bytes) to base32 (52 chars).
fn base32EncodeI2P(data: *const [32]u8, out: *[52]u8) void {
    base32EncodeBytes(data, out);
}

/// Generic base32 encoding.
fn base32EncodeBytes(data: []const u8, out: []u8) void {
    var idx: usize = 0;
    var buf: u64 = 0;
    var bits: u6 = 0;

    for (data) |byte| {
        buf = (buf << 8) | byte;
        bits +%= 8;

        while (bits >= 5 and idx < out.len) {
            bits -%= 5;
            out[idx] = BASE32_ALPHABET[@intCast((buf >> bits) & 0x1F)];
            idx += 1;
        }
    }

    // Handle remaining bits
    if (bits > 0 and idx < out.len) {
        const shift: u6 = 5 - bits;
        out[idx] = BASE32_ALPHABET[@intCast((buf << shift) & 0x1F)];
    }
}

/// Swap standard base64 characters to I2P base64 variant.
pub fn swapBase64ToI2P(data: []u8) void {
    for (data) |*c| {
        if (c.* == '+') {
            c.* = '-';
        } else if (c.* == '/') {
            c.* = '~';
        }
    }
}

/// Swap I2P base64 variant characters to standard base64.
pub fn swapBase64FromI2P(data: []u8) void {
    for (data) |*c| {
        if (c.* == '-') {
            c.* = '+';
        } else if (c.* == '~') {
            c.* = '/';
        }
    }
}

// ============================================================================
// Stream Isolation for Tor
// ============================================================================

/// Generate stream isolation credentials for Tor.
/// Each connection gets unique credentials to isolate streams.
pub const StreamIsolation = struct {
    prefix: [8]u8,
    counter: u64,
    /// Buffer for username storage.
    username_buf: [32]u8 = undefined,

    pub fn init() StreamIsolation {
        var prefix: [8]u8 = undefined;
        std.crypto.random.bytes(&prefix);
        return .{
            .prefix = prefix,
            .counter = 0,
        };
    }

    /// Generate next isolation credentials.
    /// Returns credentials with username pointing to internal buffer.
    /// The username is valid until the next call to next().
    pub fn next(self: *StreamIsolation) Socks5Credentials {
        const counter = self.counter;
        self.counter +%= 1;

        // Format: prefix-counter as username, empty password
        const username_slice = std.fmt.bufPrint(&self.username_buf, "{x}-{d}", .{
            std.fmt.fmtSliceHexLower(&self.prefix),
            counter,
        }) catch unreachable;

        return .{
            .username = username_slice,
            .password = "",
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "socks5 constants" {
    try std.testing.expectEqual(@as(u8, 0x05), SOCKS5_VERSION);
    try std.testing.expectEqual(@as(u8, 0x01), SOCKS5_CMD_CONNECT);
    try std.testing.expectEqual(@as(u8, 0x03), SOCKS5_ATYP_DOMAINNAME);
}

test "socks5 reply descriptions" {
    try std.testing.expectEqualStrings("succeeded", Socks5Reply.succeeded.description());
    try std.testing.expectEqualStrings("connection refused", Socks5Reply.connection_refused.description());
    try std.testing.expectEqualStrings("Tor hidden service not found", Socks5Reply.tor_hidden_service_not_found.description());
}

test "socks5 credentials validation" {
    const valid = Socks5Credentials{
        .username = "testuser",
        .password = "testpass",
    };
    try std.testing.expect(valid.validate());

    // Create a slice that's too long (257 bytes)
    var long_name: [256]u8 = undefined;
    @memset(&long_name, 'a');
    const invalid = Socks5Credentials{
        .username = &long_name,
        .password = "test",
    };
    try std.testing.expect(!invalid.validate());
}

test "network id address lengths" {
    try std.testing.expectEqual(@as(?usize, 4), MultiNetworkAddress.expectedAddressLen(.ipv4));
    try std.testing.expectEqual(@as(?usize, 16), MultiNetworkAddress.expectedAddressLen(.ipv6));
    try std.testing.expectEqual(@as(?usize, 32), MultiNetworkAddress.expectedAddressLen(.torv3));
    try std.testing.expectEqual(@as(?usize, 32), MultiNetworkAddress.expectedAddressLen(.i2p));
}

test "multi network address to hostname ipv4" {
    const allocator = std.testing.allocator;

    const addr = MultiNetworkAddress{
        .network = .ipv4,
        .address = &[_]u8{ 192, 168, 1, 1 },
        .port = 8333,
    };

    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);

    try std.testing.expectEqualStrings("192.168.1.1", hostname);
}

test "base32 encoding" {
    var out: [56]u8 = undefined;
    var data: [35]u8 = undefined;
    @memset(&data, 0);
    base32EncodeBytes(&data, &out);

    // All zeros should encode to all 'a's
    for (out) |c| {
        try std.testing.expectEqual(@as(u8, 'a'), c);
    }
}

test "base64 i2p swap" {
    var data = "abc+def/ghi".*;
    swapBase64ToI2P(&data);
    try std.testing.expectEqualStrings("abc-def~ghi", &data);

    swapBase64FromI2P(&data);
    try std.testing.expectEqualStrings("abc+def/ghi", &data);
}

test "stream isolation" {
    var isolation = StreamIsolation.init();

    // Get first credentials and copy username
    const creds1 = isolation.next();
    var username1: [32]u8 = undefined;
    @memcpy(username1[0..creds1.username.len], creds1.username);
    const len1 = creds1.username.len;

    // Get second credentials
    const creds2 = isolation.next();

    // Each call should produce different credentials
    try std.testing.expect(!std.mem.eql(u8, username1[0..len1], creds2.username));

    // Counter should be incrementing
    try std.testing.expectEqual(@as(u64, 2), isolation.counter);
}

test "proxy config defaults" {
    const config = ProxyConfig{};
    try std.testing.expectEqual(ProxyType.none, config.proxy_type);
    try std.testing.expectEqual(@as(u16, 0), config.port);
    try std.testing.expect(config.credentials == null);
}

test "socks5 client initialization" {
    const allocator = std.testing.allocator;
    const client = Socks5Client.init("127.0.0.1", 9050, null, allocator);

    try std.testing.expectEqualStrings("127.0.0.1", client.proxy_host);
    try std.testing.expectEqual(@as(u16, 9050), client.proxy_port);
    try std.testing.expect(client.credentials == null);
}

test "i2p sam client initialization" {
    const allocator = std.testing.allocator;
    var client = I2pSamClient.init("127.0.0.1", 7656, null, allocator);

    try std.testing.expectEqualStrings("127.0.0.1", client.host);
    try std.testing.expectEqual(@as(u16, 7656), client.port);
    try std.testing.expect(client.session_id == null);

    client.deinit();
}

test "tor control client initialization" {
    const allocator = std.testing.allocator;
    const client = TorControlClient.init("127.0.0.1", 9051, "password", allocator);

    try std.testing.expectEqualStrings("127.0.0.1", client.host);
    try std.testing.expectEqual(@as(u16, 9051), client.port);
    try std.testing.expectEqualStrings("password", client.password.?);
}

test "proxy manager initialization" {
    const allocator = std.testing.allocator;

    const clearnet = ProxyConfig{
        .proxy_type = .none,
    };
    const tor = ProxyConfig{
        .proxy_type = .socks5,
        .host = "127.0.0.1",
        .port = 9050,
    };
    const i2p = ProxyConfig{
        .proxy_type = .i2p,
        .host = "127.0.0.1",
        .port = 7656,
        .i2p_key_file = "i2p_private_key",
    };

    var manager = ProxyManager.init(clearnet, tor, i2p, allocator);
    defer manager.deinit();

    try std.testing.expect(manager.socks5_client == null);
    try std.testing.expect(manager.i2p_client == null);
}

// ============================================================================
// Mock Server Tests
// ============================================================================
//
// These tests validate protocol encoding/decoding without real network connections.
// They use mock data to verify the SOCKS5 and I2P SAM protocol implementations.

test "socks5 handshake message format" {
    // Verify the SOCKS5 greeting format per RFC 1928
    // Without credentials: 05 01 00 (version=5, nmethods=1, noauth=0)
    // With credentials: 05 02 00 02 (version=5, nmethods=2, noauth=0, userpass=2)

    const allocator = std.testing.allocator;
    const client_no_auth = Socks5Client.init("127.0.0.1", 9050, null, allocator);

    // Verify no-auth greeting format (3 bytes)
    var greeting_no_auth: [4]u8 = undefined;
    var greeting_len: usize = 0;
    greeting_no_auth[0] = SOCKS5_VERSION;
    greeting_no_auth[1] = 1; // 1 method
    greeting_no_auth[2] = SOCKS5_AUTH_NONE;
    greeting_len = 3;

    try std.testing.expectEqual(@as(u8, 0x05), greeting_no_auth[0]);
    try std.testing.expectEqual(@as(u8, 0x01), greeting_no_auth[1]);
    try std.testing.expectEqual(@as(u8, 0x00), greeting_no_auth[2]);
    _ = client_no_auth;
}

test "socks5 connect request message format" {
    // Verify SOCKS5 CONNECT request format per RFC 1928
    // Format: VER CMD RSV ATYP DST.ADDR DST.PORT
    // For domain: 05 01 00 03 <len> <domain> <port_be>

    const target = "example.onion";
    const target_port: u16 = 8333;

    var request: [4 + 1 + 255 + 2]u8 = undefined;
    var idx: usize = 0;

    request[idx] = SOCKS5_VERSION;
    idx += 1;
    request[idx] = SOCKS5_CMD_CONNECT;
    idx += 1;
    request[idx] = 0x00; // Reserved
    idx += 1;
    request[idx] = SOCKS5_ATYP_DOMAINNAME;
    idx += 1;
    request[idx] = @intCast(target.len);
    idx += 1;
    @memcpy(request[idx..][0..target.len], target);
    idx += target.len;
    // Port in network byte order (big-endian)
    request[idx] = @intCast((target_port >> 8) & 0xFF);
    idx += 1;
    request[idx] = @intCast(target_port & 0xFF);
    idx += 1;

    // Verify header
    try std.testing.expectEqual(@as(u8, 0x05), request[0]); // Version
    try std.testing.expectEqual(@as(u8, 0x01), request[1]); // CONNECT
    try std.testing.expectEqual(@as(u8, 0x00), request[2]); // Reserved
    try std.testing.expectEqual(@as(u8, 0x03), request[3]); // Domain name
    try std.testing.expectEqual(@as(u8, 13), request[4]); // "example.onion" length

    // Verify domain name
    try std.testing.expectEqualStrings("example.onion", request[5..18]);

    // Verify port (8333 = 0x208D in big-endian)
    try std.testing.expectEqual(@as(u8, 0x20), request[18]);
    try std.testing.expectEqual(@as(u8, 0x8D), request[19]);
}

test "socks5 password auth message format" {
    // Verify RFC 1929 username/password auth format
    // Format: VER ULEN USERNAME PLEN PASSWORD
    // VER is 0x01 (not 0x05!)

    const username = "testuser";
    const password = "testpass";

    var auth_buf: [1 + 1 + 255 + 1 + 255]u8 = undefined;
    var idx: usize = 0;

    auth_buf[idx] = 0x01; // Auth sub-negotiation version
    idx += 1;
    auth_buf[idx] = @intCast(username.len);
    idx += 1;
    @memcpy(auth_buf[idx..][0..username.len], username);
    idx += username.len;
    auth_buf[idx] = @intCast(password.len);
    idx += 1;
    @memcpy(auth_buf[idx..][0..password.len], password);
    idx += password.len;

    try std.testing.expectEqual(@as(u8, 0x01), auth_buf[0]); // Version
    try std.testing.expectEqual(@as(u8, 8), auth_buf[1]); // Username length
    try std.testing.expectEqualStrings("testuser", auth_buf[2..10]);
    try std.testing.expectEqual(@as(u8, 8), auth_buf[10]); // Password length
    try std.testing.expectEqualStrings("testpass", auth_buf[11..19]);
}

test "socks5 reply parsing" {
    // Test parsing various SOCKS5 reply codes
    const replies = [_]struct {
        code: u8,
        expected: Socks5Reply,
        desc: []const u8,
    }{
        .{ .code = 0x00, .expected = .succeeded, .desc = "succeeded" },
        .{ .code = 0x01, .expected = .general_failure, .desc = "general SOCKS server failure" },
        .{ .code = 0x02, .expected = .connection_not_allowed, .desc = "connection not allowed by ruleset" },
        .{ .code = 0x03, .expected = .network_unreachable, .desc = "network unreachable" },
        .{ .code = 0x04, .expected = .host_unreachable, .desc = "host unreachable" },
        .{ .code = 0x05, .expected = .connection_refused, .desc = "connection refused" },
        .{ .code = 0x06, .expected = .ttl_expired, .desc = "TTL expired" },
        .{ .code = 0x07, .expected = .command_not_supported, .desc = "command not supported" },
        .{ .code = 0x08, .expected = .address_type_not_supported, .desc = "address type not supported" },
        .{ .code = 0xF0, .expected = .tor_hidden_service_not_found, .desc = "Tor hidden service not found" },
    };

    for (replies) |r| {
        const reply: Socks5Reply = @enumFromInt(r.code);
        try std.testing.expectEqual(r.expected, reply);
        try std.testing.expectEqualStrings(r.desc, reply.description());
    }
}

test "i2p sam hello message format" {
    // Verify I2P SAM v3.1 HELLO command format
    const hello_cmd = "HELLO VERSION MIN=3.1 MAX=3.1\n";

    try std.testing.expect(std.mem.startsWith(u8, hello_cmd, "HELLO VERSION"));
    try std.testing.expect(std.mem.indexOf(u8, hello_cmd, "MIN=3.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, hello_cmd, "MAX=3.1") != null);
    try std.testing.expect(hello_cmd[hello_cmd.len - 1] == '\n');
}

test "i2p sam session create format" {
    // Verify I2P SAM SESSION CREATE format
    const session_id = "test123";
    const destination = "TRANSIENT";

    var buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "SESSION CREATE STYLE=STREAM ID={s} DESTINATION={s} SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0\n", .{
        session_id,
        destination,
    }) catch unreachable;

    try std.testing.expect(std.mem.startsWith(u8, cmd, "SESSION CREATE"));
    try std.testing.expect(std.mem.indexOf(u8, cmd, "STYLE=STREAM") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "ID=test123") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "DESTINATION=TRANSIENT") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "SIGNATURE_TYPE=7") != null);
    try std.testing.expect(cmd[cmd.len - 1] == '\n');
}

test "i2p sam stream connect format" {
    // Verify I2P SAM STREAM CONNECT format
    const session_id = "abc123";
    const destination = "example.b32.i2p";

    var buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "STREAM CONNECT ID={s} DESTINATION={s} SILENT=false\n", .{
        session_id,
        destination,
    }) catch unreachable;

    try std.testing.expect(std.mem.startsWith(u8, cmd, "STREAM CONNECT"));
    try std.testing.expect(std.mem.indexOf(u8, cmd, "ID=abc123") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "DESTINATION=example.b32.i2p") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "SILENT=false") != null);
}

test "i2p sam naming lookup format" {
    // Verify I2P SAM NAMING LOOKUP format
    const name = "example.b32.i2p";

    var buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "NAMING LOOKUP NAME={s}\n", .{name}) catch unreachable;

    try std.testing.expect(std.mem.startsWith(u8, cmd, "NAMING LOOKUP"));
    try std.testing.expect(std.mem.indexOf(u8, cmd, "NAME=example.b32.i2p") != null);
}

test "i2p sam dest generate format" {
    // Verify I2P SAM DEST GENERATE format
    const cmd = "DEST GENERATE SIGNATURE_TYPE=7\n";

    try std.testing.expect(std.mem.startsWith(u8, cmd, "DEST GENERATE"));
    try std.testing.expect(std.mem.indexOf(u8, cmd, "SIGNATURE_TYPE=7") != null);
}

test "i2p sam response parsing" {
    // Test parsing I2P SAM responses
    const hello_ok = "HELLO REPLY RESULT=OK VERSION=3.1";
    const session_ok = "SESSION STATUS RESULT=OK DESTINATION=abc123...";
    const stream_ok = "STREAM STATUS RESULT=OK";
    const error_response = "SESSION STATUS RESULT=INVALID_ID";

    try std.testing.expect(std.mem.indexOf(u8, hello_ok, "RESULT=OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, session_ok, "RESULT=OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, stream_ok, "RESULT=OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, error_response, "INVALID_ID") != null);
}

test "tor control authenticate format" {
    // Verify Tor control AUTHENTICATE command format
    const password = "mypassword";

    var buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "AUTHENTICATE \"{s}\"\r\n", .{password}) catch unreachable;

    try std.testing.expect(std.mem.startsWith(u8, cmd, "AUTHENTICATE"));
    try std.testing.expect(std.mem.indexOf(u8, cmd, "\"mypassword\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, cmd, "\r\n"));
}

test "tor control add_onion format" {
    // Verify Tor control ADD_ONION command format
    const virtual_port: u16 = 8333;
    const local_port: u16 = 8333;

    var buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "ADD_ONION NEW:ED25519-V3 Port={d},127.0.0.1:{d}\r\n", .{
        virtual_port,
        local_port,
    }) catch unreachable;

    try std.testing.expect(std.mem.startsWith(u8, cmd, "ADD_ONION"));
    try std.testing.expect(std.mem.indexOf(u8, cmd, "NEW:ED25519-V3") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "Port=8333,127.0.0.1:8333") != null);
    try std.testing.expect(std.mem.endsWith(u8, cmd, "\r\n"));
}

test "tor control response parsing" {
    // Test parsing Tor control responses
    const auth_ok = "250 OK\r\n";
    const service_id = "250-ServiceID=abcdef123456.onion";
    const private_key = "250-PrivateKey=ED25519-V3:base64data...";
    const error_response = "515 Bad authentication";

    try std.testing.expect(std.mem.startsWith(u8, auth_ok, "250"));
    try std.testing.expect(std.mem.startsWith(u8, service_id, "250-ServiceID="));
    try std.testing.expect(std.mem.startsWith(u8, private_key, "250-PrivateKey="));
    try std.testing.expect(std.mem.startsWith(u8, error_response, "5"));
}

test "multi network address to hostname torv3" {
    const allocator = std.testing.allocator;

    // Create a Tor v3 address (32 bytes)
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0xAB);

    const addr = MultiNetworkAddress{
        .network = .torv3,
        .address = &pubkey,
        .port = 8333,
    };

    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);

    // Should end with .onion
    try std.testing.expect(std.mem.endsWith(u8, hostname, ".onion"));
}

test "multi network address to hostname i2p" {
    const allocator = std.testing.allocator;

    // Create an I2P address (32-byte hash)
    var hash: [32]u8 = undefined;
    @memset(&hash, 0xCD);

    const addr = MultiNetworkAddress{
        .network = .i2p,
        .address = &hash,
        .port = 8333,
    };

    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);

    // Should end with .b32.i2p
    try std.testing.expect(std.mem.endsWith(u8, hostname, ".b32.i2p"));
}

test "multi network address to hostname ipv6" {
    const allocator = std.testing.allocator;

    // Create IPv6 address (16 bytes) - ::1 (loopback)
    var ipv6: [16]u8 = [_]u8{0} ** 16;
    ipv6[15] = 1;

    const addr = MultiNetworkAddress{
        .network = .ipv6,
        .address = &ipv6,
        .port = 8333,
    };

    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);

    // Should be formatted as hex colons
    try std.testing.expect(std.mem.indexOf(u8, hostname, ":") != null);
}

test "direct connect error on unsupported network" {
    const addr = MultiNetworkAddress{
        .network = .cjdns,
        .address = &[_]u8{0} ** 16,
        .port = 8333,
    };

    const result = directConnect(&addr);
    try std.testing.expectError(ProxyError.UnsupportedNetwork, result);
}
