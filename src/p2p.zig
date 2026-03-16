const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");

// ============================================================================
// Protocol Constants
// ============================================================================

pub const PROTOCOL_VERSION: i32 = 70016;
pub const MIN_PROTOCOL_VERSION: i32 = 70001;
pub const NODE_NETWORK: u64 = 1;
pub const NODE_WITNESS: u64 = 8;
pub const NODE_NETWORK_LIMITED: u64 = 1024;
pub const USER_AGENT: []const u8 = "/clearbit:0.1.0/";
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32 MB
pub const MAX_INV_SIZE: usize = 50000;
pub const MAX_HEADERS_SIZE: usize = 2000;
pub const MAX_ADDR_SIZE: usize = 1000;

/// Network magic bytes for different networks
pub const NetworkMagic = struct {
    pub const MAINNET: u32 = 0xD9B4BEF9;
    pub const TESTNET: u32 = 0x0709110B;
    pub const REGTEST: u32 = 0xDAB5BFFA;
    pub const SIGNET: u32 = 0x40CF030A;
};

// ============================================================================
// Message Header
// ============================================================================

/// Message header structure (24 bytes total).
/// Field          Size    Description
/// magic          4       Network magic bytes (e.g., 0xD9B4BEF9 for mainnet)
/// command        12      ASCII command name, null-padded
/// length         4       Payload length in bytes (LE u32)
/// checksum       4       First 4 bytes of hash256(payload)
pub const MessageHeader = struct {
    magic: u32,
    command: [12]u8,
    length: u32,
    checksum: [4]u8,

    /// Serialize header to 24 bytes.
    pub fn encode(self: *const MessageHeader) [24]u8 {
        var buf: [24]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.magic, .little);
        @memcpy(buf[4..16], &self.command);
        std.mem.writeInt(u32, buf[16..20], self.length, .little);
        @memcpy(buf[20..24], &self.checksum);
        return buf;
    }

    /// Deserialize header from 24 bytes.
    pub fn decode(data: *const [24]u8) MessageHeader {
        return MessageHeader{
            .magic = std.mem.readInt(u32, data[0..4], .little),
            .command = data[4..16].*,
            .length = std.mem.readInt(u32, data[16..20], .little),
            .checksum = data[20..24].*,
        };
    }

    /// Create a header for a given command and payload.
    pub fn create(magic: u32, command: []const u8, payload: []const u8) MessageHeader {
        var cmd: [12]u8 = [_]u8{0} ** 12;
        const copy_len = @min(command.len, 12);
        @memcpy(cmd[0..copy_len], command[0..copy_len]);
        const hash = crypto.hash256(payload);
        return MessageHeader{
            .magic = magic,
            .command = cmd,
            .length = @intCast(payload.len),
            .checksum = hash[0..4].*,
        };
    }

    /// Extract command name (strip null padding).
    pub fn commandName(self: *const MessageHeader) []const u8 {
        var end: usize = 12;
        while (end > 0 and self.command[end - 1] == 0) end -= 1;
        return self.command[0..end];
    }

    /// Verify checksum matches payload.
    pub fn verifyChecksum(self: *const MessageHeader, payload: []const u8) bool {
        const hash = crypto.hash256(payload);
        return std.mem.eql(u8, &self.checksum, hash[0..4]);
    }
};

// ============================================================================
// Message Types
// ============================================================================

/// All P2P message types using a tagged union.
pub const Message = union(enum) {
    version: VersionMessage,
    verack: void,
    ping: PingPong,
    pong: PingPong,
    getaddr: void,
    addr: AddrMessage,
    inv: InvMessage,
    getdata: InvMessage, // Same format as inv
    notfound: InvMessage, // Same format as inv
    getheaders: GetHeadersMessage,
    headers: HeadersMessage,
    getblocks: GetHeadersMessage, // Same format as getheaders
    block: types.Block,
    tx: types.Transaction,
    sendheaders: void,
    sendcmpct: SendCmpctMessage,
    feefilter: FeeFilterMessage,
    wtxidrelay: void,
    sendaddrv2: void,
    reject: RejectMessage,
    mempool: void,
    // BIP-331 Package relay messages
    sendpackages: SendPackagesMessage,
    ancpkginfo: AncPkgInfoMessage,
    getpkgtxns: GetPkgTxnsMessage,
    pkgtxns: PkgTxnsMessage,
};

/// Version message - exchanged during handshake.
pub const VersionMessage = struct {
    version: i32, // Protocol version (70016)
    services: u64, // Services bitmap
    timestamp: i64, // Unix timestamp
    addr_recv: types.NetworkAddress, // Address of receiving node
    addr_from: types.NetworkAddress, // Address of sending node
    nonce: u64, // Random nonce for self-detection
    user_agent: []const u8, // Software name/version
    start_height: i32, // Last block height known to sender
    relay: bool, // Whether to relay transactions (BIP-37)
};

/// Ping/Pong - nonce echo for keepalive.
pub const PingPong = struct {
    nonce: u64,
};

/// Inventory vector type - identifies a data object type.
pub const InvType = enum(u32) {
    error_type = 0,
    msg_tx = 1,
    msg_block = 2,
    msg_filtered_block = 3,
    msg_cmpct_block = 4,
    msg_witness_tx = 0x40000001,
    msg_witness_block = 0x40000002,
    msg_witness_filtered_block = 0x40000003,
    _,
};

/// Inventory vector - identifies a data object.
pub const InvVector = struct {
    inv_type: InvType,
    hash: types.Hash256,
};

/// Inv / getdata / notfound message.
pub const InvMessage = struct {
    inventory: []const InvVector,
};

/// Getheaders / getblocks message.
pub const GetHeadersMessage = struct {
    version: u32,
    block_locator_hashes: []const types.Hash256,
    hash_stop: types.Hash256,
};

/// Headers message - up to 2000 headers.
pub const HeadersMessage = struct {
    headers: []const types.BlockHeader,
};

/// Addr message - peer addresses.
pub const AddrMessage = struct {
    addrs: []const TimestampedAddr,
};

/// Timestamped network address for addr message.
pub const TimestampedAddr = struct {
    timestamp: u32,
    addr: types.NetworkAddress,
};

/// Sendcmpct message (BIP-152).
pub const SendCmpctMessage = struct {
    announce: bool,
    version: u64,
};

/// Feefilter message (BIP-133).
pub const FeeFilterMessage = struct {
    feerate: u64, // Minimum fee rate in sat/kvB
};

/// Reject message (deprecated but still sent by some nodes).
pub const RejectMessage = struct {
    message: []const u8,
    code: u8,
    reason: []const u8,
    data: []const u8,
};

// ============================================================================
// BIP-331 Package Relay Messages
// ============================================================================

/// Maximum number of transactions in a package (BIP-331).
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Maximum total package weight (BIP-331): 404,000 weight units.
pub const MAX_PACKAGE_WEIGHT: usize = 404_000;

/// sendpackages message - negotiate package relay support during handshake.
/// Sent after verack. Version 1 indicates support for child-with-parents packages.
pub const SendPackagesMessage = struct {
    /// Package relay protocol version (currently 1).
    version: u32,
};

/// ancpkginfo message - announce a package by its hash.
/// Sent when a node has a package ready to relay.
/// The package_hash is SHA256 of sorted wtxids concatenated.
pub const AncPkgInfoMessage = struct {
    /// Package hash (SHA256 of sorted wtxids).
    package_hash: types.Hash256,
    /// WTXID of the child transaction (last tx in package).
    child_wtxid: types.Hash256,
    /// Count of parent transactions (not including child).
    parent_count: u32,
};

/// getpkgtxns message - request package transactions by their wtxids.
/// Sent in response to ancpkginfo or proactively when orphan resolution fails.
pub const GetPkgTxnsMessage = struct {
    /// List of wtxids to request.
    wtxids: []const types.Hash256,
};

/// pkgtxns message - provide package transactions.
/// Sent in response to getpkgtxns.
pub const PkgTxnsMessage = struct {
    /// List of transactions in topological order (parents before child).
    transactions: []const types.Transaction,
};

// ============================================================================
// Encoding
// ============================================================================

/// Serialize a message to bytes (header + payload).
pub fn encodeMessage(
    msg: *const Message,
    magic: u32,
    allocator: std.mem.Allocator,
) ![]const u8 {
    var payload_writer = serialize.Writer.init(allocator);
    defer payload_writer.deinit();

    const command_name: []const u8 = switch (msg.*) {
        .version => "version",
        .verack => "verack",
        .ping => "ping",
        .pong => "pong",
        .getaddr => "getaddr",
        .addr => "addr",
        .inv => "inv",
        .getdata => "getdata",
        .notfound => "notfound",
        .getheaders => "getheaders",
        .headers => "headers",
        .getblocks => "getblocks",
        .block => "block",
        .tx => "tx",
        .sendheaders => "sendheaders",
        .sendcmpct => "sendcmpct",
        .feefilter => "feefilter",
        .wtxidrelay => "wtxidrelay",
        .sendaddrv2 => "sendaddrv2",
        .reject => "reject",
        .mempool => "mempool",
        // BIP-331 Package relay messages
        .sendpackages => "sendpackages",
        .ancpkginfo => "ancpkginfo",
        .getpkgtxns => "getpkgtxns",
        .pkgtxns => "pkgtxns",
    };

    // Encode payload based on message type
    switch (msg.*) {
        .version => |v| {
            try payload_writer.writeInt(i32, v.version);
            try payload_writer.writeInt(u64, v.services);
            try payload_writer.writeInt(i64, v.timestamp);
            try encodeNetworkAddress(&payload_writer, &v.addr_recv);
            try encodeNetworkAddress(&payload_writer, &v.addr_from);
            try payload_writer.writeInt(u64, v.nonce);
            try payload_writer.writeCompactSize(v.user_agent.len);
            try payload_writer.writeBytes(v.user_agent);
            try payload_writer.writeInt(i32, v.start_height);
            try payload_writer.writeBytes(&[_]u8{if (v.relay) 1 else 0});
        },
        .verack, .getaddr, .sendheaders, .wtxidrelay, .sendaddrv2, .mempool => {
            // Empty payload
        },
        .ping, .pong => |pp| {
            try payload_writer.writeInt(u64, pp.nonce);
        },
        .inv, .getdata, .notfound => |inv| {
            try payload_writer.writeCompactSize(inv.inventory.len);
            for (inv.inventory) |item| {
                try payload_writer.writeInt(u32, @intFromEnum(item.inv_type));
                try payload_writer.writeBytes(&item.hash);
            }
        },
        .getheaders, .getblocks => |gh| {
            try payload_writer.writeInt(u32, gh.version);
            try payload_writer.writeCompactSize(gh.block_locator_hashes.len);
            for (gh.block_locator_hashes) |hash| {
                try payload_writer.writeBytes(&hash);
            }
            try payload_writer.writeBytes(&gh.hash_stop);
        },
        .headers => |h| {
            try payload_writer.writeCompactSize(h.headers.len);
            for (h.headers) |header| {
                try serialize.writeBlockHeader(&payload_writer, &header);
                try payload_writer.writeCompactSize(0); // tx_count always 0 in headers msg
            }
        },
        .sendcmpct => |sc| {
            try payload_writer.writeBytes(&[_]u8{if (sc.announce) 1 else 0});
            try payload_writer.writeInt(u64, sc.version);
        },
        .feefilter => |ff| {
            try payload_writer.writeInt(u64, ff.feerate);
        },
        .block => |blk| {
            try serialize.writeBlock(&payload_writer, &blk);
        },
        .tx => |transaction| {
            try serialize.writeTransaction(&payload_writer, &transaction);
        },
        .addr => |a| {
            try payload_writer.writeCompactSize(a.addrs.len);
            for (a.addrs) |entry| {
                try payload_writer.writeInt(u32, entry.timestamp);
                try encodeNetworkAddress(&payload_writer, &entry.addr);
            }
        },
        .reject => |r| {
            try payload_writer.writeCompactSize(r.message.len);
            try payload_writer.writeBytes(r.message);
            try payload_writer.writeBytes(&[_]u8{r.code});
            try payload_writer.writeCompactSize(r.reason.len);
            try payload_writer.writeBytes(r.reason);
            try payload_writer.writeBytes(r.data);
        },
        // BIP-331 Package relay messages
        .sendpackages => |sp| {
            try payload_writer.writeInt(u32, sp.version);
        },
        .ancpkginfo => |api| {
            try payload_writer.writeBytes(&api.package_hash);
            try payload_writer.writeBytes(&api.child_wtxid);
            try payload_writer.writeInt(u32, api.parent_count);
        },
        .getpkgtxns => |gpkt| {
            try payload_writer.writeCompactSize(gpkt.wtxids.len);
            for (gpkt.wtxids) |wtxid| {
                try payload_writer.writeBytes(&wtxid);
            }
        },
        .pkgtxns => |pkt| {
            try payload_writer.writeCompactSize(pkt.transactions.len);
            for (pkt.transactions) |transaction| {
                try serialize.writeTransaction(&payload_writer, &transaction);
            }
        },
    }

    const payload = try payload_writer.toOwnedSlice();
    defer allocator.free(payload);

    const header = MessageHeader.create(magic, command_name, payload);
    const header_bytes = header.encode();

    var result = try allocator.alloc(u8, 24 + payload.len);
    @memcpy(result[0..24], &header_bytes);
    @memcpy(result[24..], payload);
    return result;
}

/// Encode a network address (26 bytes: services + ip + port).
fn encodeNetworkAddress(writer: *serialize.Writer, addr: *const types.NetworkAddress) !void {
    try writer.writeInt(u64, addr.services);
    try writer.writeBytes(&addr.ip);
    // Port is big-endian in the protocol (network byte order)
    try writer.writeBytes(&[2]u8{
        @intCast((addr.port >> 8) & 0xFF),
        @intCast(addr.port & 0xFF),
    });
}

// ============================================================================
// Decoding
// ============================================================================

/// Error type for P2P message parsing.
pub const ParseError = error{
    EndOfStream,
    InvalidCompactSize,
    InvalidSegwitMarker,
    InvalidData,
    UnknownCommand,
    OutOfMemory,
};

/// Deserialize a message payload given the command name.
pub fn decodePayload(
    command: []const u8,
    payload: []const u8,
    allocator: std.mem.Allocator,
) ParseError!Message {
    var reader = serialize.Reader{ .data = payload };

    if (std.mem.eql(u8, command, "version")) {
        return Message{ .version = VersionMessage{
            .version = try reader.readInt(i32),
            .services = try reader.readInt(u64),
            .timestamp = try reader.readInt(i64),
            .addr_recv = try decodeNetworkAddress(&reader),
            .addr_from = try decodeNetworkAddress(&reader),
            .nonce = try reader.readInt(u64),
            .user_agent = blk: {
                const len = try reader.readCompactSize();
                break :blk try reader.readBytes(@intCast(len));
            },
            .start_height = try reader.readInt(i32),
            .relay = if (reader.pos < payload.len) (try reader.readBytes(1))[0] != 0 else true,
        } };
    } else if (std.mem.eql(u8, command, "verack")) {
        return Message{ .verack = {} };
    } else if (std.mem.eql(u8, command, "ping")) {
        return Message{ .ping = .{ .nonce = try reader.readInt(u64) } };
    } else if (std.mem.eql(u8, command, "pong")) {
        return Message{ .pong = .{ .nonce = try reader.readInt(u64) } };
    } else if (std.mem.eql(u8, command, "inv")) {
        return Message{ .inv = try decodeInv(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "getdata")) {
        return Message{ .getdata = try decodeInv(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "notfound")) {
        return Message{ .notfound = try decodeInv(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "getheaders")) {
        return Message{ .getheaders = try decodeGetHeaders(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "getblocks")) {
        return Message{ .getblocks = try decodeGetHeaders(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "headers")) {
        return Message{ .headers = try decodeHeaders(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "sendheaders")) {
        return Message{ .sendheaders = {} };
    } else if (std.mem.eql(u8, command, "sendcmpct")) {
        return Message{ .sendcmpct = .{
            .announce = (try reader.readBytes(1))[0] != 0,
            .version = try reader.readInt(u64),
        } };
    } else if (std.mem.eql(u8, command, "feefilter")) {
        return Message{ .feefilter = .{ .feerate = try reader.readInt(u64) } };
    } else if (std.mem.eql(u8, command, "block")) {
        return Message{ .block = try serialize.readBlock(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "tx")) {
        return Message{ .tx = try serialize.readTransaction(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "wtxidrelay")) {
        return Message{ .wtxidrelay = {} };
    } else if (std.mem.eql(u8, command, "sendaddrv2")) {
        return Message{ .sendaddrv2 = {} };
    } else if (std.mem.eql(u8, command, "mempool")) {
        return Message{ .mempool = {} };
    } else if (std.mem.eql(u8, command, "getaddr")) {
        return Message{ .getaddr = {} };
    } else if (std.mem.eql(u8, command, "addr")) {
        return Message{ .addr = try decodeAddr(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "reject")) {
        return Message{ .reject = try decodeReject(&reader, allocator) };
    }

    return ParseError.UnknownCommand;
}

/// Decode a network address (26 bytes).
fn decodeNetworkAddress(reader: *serialize.Reader) !types.NetworkAddress {
    return types.NetworkAddress{
        .services = try reader.readInt(u64),
        .ip = (try reader.readBytes(16))[0..16].*,
        .port = blk: {
            const port_bytes = try reader.readBytes(2);
            break :blk (@as(u16, port_bytes[0]) << 8) | @as(u16, port_bytes[1]);
        },
    };
}

/// Decode inv/getdata/notfound message.
fn decodeInv(reader: *serialize.Reader, allocator: std.mem.Allocator) ParseError!InvMessage {
    const count = try reader.readCompactSize();
    if (count > MAX_INV_SIZE) return ParseError.InvalidData;
    var inventory = try allocator.alloc(InvVector, @intCast(count));
    for (0..@intCast(count)) |i| {
        inventory[i] = InvVector{
            .inv_type = @enumFromInt(try reader.readInt(u32)),
            .hash = try reader.readHash(),
        };
    }
    return InvMessage{ .inventory = inventory };
}

/// Decode getheaders/getblocks message.
fn decodeGetHeaders(reader: *serialize.Reader, allocator: std.mem.Allocator) ParseError!GetHeadersMessage {
    const version = try reader.readInt(u32);
    const count = try reader.readCompactSize();
    var locators = try allocator.alloc(types.Hash256, @intCast(count));
    for (0..@intCast(count)) |i| {
        locators[i] = try reader.readHash();
    }
    return GetHeadersMessage{
        .version = version,
        .block_locator_hashes = locators,
        .hash_stop = try reader.readHash(),
    };
}

/// Decode headers message.
fn decodeHeaders(reader: *serialize.Reader, allocator: std.mem.Allocator) ParseError!HeadersMessage {
    const count = try reader.readCompactSize();
    if (count > MAX_HEADERS_SIZE) return ParseError.InvalidData;
    var headers = try allocator.alloc(types.BlockHeader, @intCast(count));
    for (0..@intCast(count)) |i| {
        headers[i] = try serialize.readBlockHeader(reader);
        _ = try reader.readCompactSize(); // tx_count (always 0)
    }
    return HeadersMessage{ .headers = headers };
}

/// Decode addr message.
fn decodeAddr(reader: *serialize.Reader, allocator: std.mem.Allocator) ParseError!AddrMessage {
    const count = try reader.readCompactSize();
    if (count > MAX_ADDR_SIZE) return ParseError.InvalidData;
    var addrs = try allocator.alloc(TimestampedAddr, @intCast(count));
    for (0..@intCast(count)) |i| {
        addrs[i] = TimestampedAddr{
            .timestamp = try reader.readInt(u32),
            .addr = try decodeNetworkAddress(reader),
        };
    }
    return AddrMessage{ .addrs = addrs };
}

/// Decode reject message.
fn decodeReject(reader: *serialize.Reader, allocator: std.mem.Allocator) ParseError!RejectMessage {
    const msg_len = try reader.readCompactSize();
    const message = try reader.readBytes(@intCast(msg_len));
    const code = (try reader.readBytes(1))[0];
    const reason_len = try reader.readCompactSize();
    const reason = try reader.readBytes(@intCast(reason_len));
    // Data field is optional and variable length (remaining bytes)
    const data = if (reader.remaining() > 0)
        try reader.readBytes(reader.remaining())
    else
        &[_]u8{};
    _ = allocator; // Data is borrowed from the reader
    return RejectMessage{
        .message = message,
        .code = code,
        .reason = reason,
        .data = data,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "message header round-trip" {
    const magic = NetworkMagic.MAINNET;
    const payload = "test payload";
    const header = MessageHeader.create(magic, "version", payload);

    // Verify header fields
    try std.testing.expectEqual(magic, header.magic);
    try std.testing.expectEqual(@as(u32, 12), header.length);
    try std.testing.expectEqualStrings("version", header.commandName());

    // Verify checksum is hash256(payload)[0..4]
    const expected_checksum = crypto.hash256(payload)[0..4];
    try std.testing.expectEqualSlices(u8, &expected_checksum.*, &header.checksum);

    // Round-trip through encode/decode
    const encoded = header.encode();
    try std.testing.expectEqual(@as(usize, 24), encoded.len);

    const decoded = MessageHeader.decode(&encoded);
    try std.testing.expectEqual(header.magic, decoded.magic);
    try std.testing.expectEqualSlices(u8, &header.command, &decoded.command);
    try std.testing.expectEqual(header.length, decoded.length);
    try std.testing.expectEqualSlices(u8, &header.checksum, &decoded.checksum);

    // Verify checksum verification works
    try std.testing.expect(decoded.verifyChecksum(payload));
    try std.testing.expect(!decoded.verifyChecksum("wrong payload"));
}

test "empty payload checksum" {
    // For empty payloads, checksum is hash256("")[0..4] = 0x5df6e0e2
    const header = MessageHeader.create(NetworkMagic.MAINNET, "verack", "");
    const expected = [_]u8{ 0x5d, 0xf6, 0xe0, 0xe2 };
    try std.testing.expectEqualSlices(u8, &expected, &header.checksum);
}

test "version message encode/decode round-trip" {
    const allocator = std.testing.allocator;

    const version_msg = VersionMessage{
        .version = PROTOCOL_VERSION,
        .services = NODE_NETWORK | NODE_WITNESS,
        .timestamp = 1234567890,
        .addr_recv = types.NetworkAddress{
            .services = NODE_NETWORK,
            .ip = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 },
            .port = 8333,
        },
        .addr_from = types.NetworkAddress{
            .services = NODE_NETWORK | NODE_WITNESS,
            .ip = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1 },
            .port = 8333,
        },
        .nonce = 0xDEADBEEFCAFEBABE,
        .user_agent = USER_AGENT,
        .start_height = 700000,
        .relay = true,
    };

    const msg = Message{ .version = version_msg };
    const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    // Decode header
    const header = MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqual(NetworkMagic.MAINNET, header.magic);
    try std.testing.expectEqualStrings("version", header.commandName());

    // Verify checksum
    const payload = encoded[24..];
    try std.testing.expect(header.verifyChecksum(payload));

    // Decode payload
    const decoded_msg = try decodePayload(header.commandName(), payload, allocator);
    const decoded = decoded_msg.version;

    try std.testing.expectEqual(version_msg.version, decoded.version);
    try std.testing.expectEqual(version_msg.services, decoded.services);
    try std.testing.expectEqual(version_msg.timestamp, decoded.timestamp);
    try std.testing.expectEqual(version_msg.nonce, decoded.nonce);
    try std.testing.expectEqual(version_msg.start_height, decoded.start_height);
    try std.testing.expectEqual(version_msg.relay, decoded.relay);
    try std.testing.expectEqualSlices(u8, version_msg.user_agent, decoded.user_agent);
    try std.testing.expectEqual(version_msg.addr_recv.port, decoded.addr_recv.port);
    try std.testing.expectEqual(version_msg.addr_from.port, decoded.addr_from.port);
}

test "ping/pong encode/decode round-trip" {
    const allocator = std.testing.allocator;

    const nonce: u64 = 0x123456789ABCDEF0;

    // Test ping
    {
        const msg = Message{ .ping = .{ .nonce = nonce } };
        const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        const header = MessageHeader.decode(encoded[0..24]);
        try std.testing.expectEqualStrings("ping", header.commandName());
        try std.testing.expectEqual(@as(u32, 8), header.length);

        const decoded = try decodePayload(header.commandName(), encoded[24..], allocator);
        try std.testing.expectEqual(nonce, decoded.ping.nonce);
    }

    // Test pong
    {
        const msg = Message{ .pong = .{ .nonce = nonce } };
        const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        const header = MessageHeader.decode(encoded[0..24]);
        try std.testing.expectEqualStrings("pong", header.commandName());

        const decoded = try decodePayload(header.commandName(), encoded[24..], allocator);
        try std.testing.expectEqual(nonce, decoded.pong.nonce);
    }
}

test "inv message with 3 inventory vectors" {
    const allocator = std.testing.allocator;

    const inv_items = [_]InvVector{
        .{ .inv_type = .msg_tx, .hash = [_]u8{0x11} ** 32 },
        .{ .inv_type = .msg_block, .hash = [_]u8{0x22} ** 32 },
        .{ .inv_type = .msg_witness_tx, .hash = [_]u8{0x33} ** 32 },
    };

    const msg = Message{ .inv = .{ .inventory = &inv_items } };
    const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const header = MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqualStrings("inv", header.commandName());
    // 1 byte compact size + 3 * (4 bytes type + 32 bytes hash) = 1 + 108 = 109
    try std.testing.expectEqual(@as(u32, 109), header.length);

    const decoded = try decodePayload(header.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.inv.inventory);

    try std.testing.expectEqual(@as(usize, 3), decoded.inv.inventory.len);
    try std.testing.expectEqual(InvType.msg_tx, decoded.inv.inventory[0].inv_type);
    try std.testing.expectEqual(InvType.msg_block, decoded.inv.inventory[1].inv_type);
    try std.testing.expectEqual(InvType.msg_witness_tx, decoded.inv.inventory[2].inv_type);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x11} ** 32, &decoded.inv.inventory[0].hash);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x22} ** 32, &decoded.inv.inventory[1].hash);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x33} ** 32, &decoded.inv.inventory[2].hash);
}

test "headers message with 1 header" {
    const allocator = std.testing.allocator;

    const header_item = types.BlockHeader{
        .version = 536870912, // 0x20000000
        .prev_block = [_]u8{0xAA} ** 32,
        .merkle_root = [_]u8{0xBB} ** 32,
        .timestamp = 1609459200,
        .bits = 0x1d00ffff,
        .nonce = 12345,
    };

    const headers_list = [_]types.BlockHeader{header_item};
    const msg = Message{ .headers = .{ .headers = &headers_list } };
    const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const msg_header = MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqualStrings("headers", msg_header.commandName());
    // 1 byte compact size + 1 * (80 bytes header + 1 byte tx_count) = 1 + 81 = 82
    try std.testing.expectEqual(@as(u32, 82), msg_header.length);

    const decoded = try decodePayload(msg_header.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.headers.headers);

    try std.testing.expectEqual(@as(usize, 1), decoded.headers.headers.len);
    const decoded_header = decoded.headers.headers[0];
    try std.testing.expectEqual(header_item.version, decoded_header.version);
    try std.testing.expectEqualSlices(u8, &header_item.prev_block, &decoded_header.prev_block);
    try std.testing.expectEqualSlices(u8, &header_item.merkle_root, &decoded_header.merkle_root);
    try std.testing.expectEqual(header_item.timestamp, decoded_header.timestamp);
    try std.testing.expectEqual(header_item.bits, decoded_header.bits);
    try std.testing.expectEqual(header_item.nonce, decoded_header.nonce);
}

test "empty-payload messages produce correct 24-byte output" {
    const allocator = std.testing.allocator;

    // Test verack
    {
        const msg = Message{ .verack = {} };
        const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        try std.testing.expectEqual(@as(usize, 24), encoded.len);
        const header = MessageHeader.decode(encoded[0..24]);
        try std.testing.expectEqualStrings("verack", header.commandName());
        try std.testing.expectEqual(@as(u32, 0), header.length);
    }

    // Test sendheaders
    {
        const msg = Message{ .sendheaders = {} };
        const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        try std.testing.expectEqual(@as(usize, 24), encoded.len);
        const header = MessageHeader.decode(encoded[0..24]);
        try std.testing.expectEqualStrings("sendheaders", header.commandName());
        try std.testing.expectEqual(@as(u32, 0), header.length);
    }

    // Test getaddr
    {
        const msg = Message{ .getaddr = {} };
        const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        try std.testing.expectEqual(@as(usize, 24), encoded.len);
        const header = MessageHeader.decode(encoded[0..24]);
        try std.testing.expectEqualStrings("getaddr", header.commandName());
        try std.testing.expectEqual(@as(u32, 0), header.length);
    }

    // Test wtxidrelay
    {
        const msg = Message{ .wtxidrelay = {} };
        const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        try std.testing.expectEqual(@as(usize, 24), encoded.len);
        const header = MessageHeader.decode(encoded[0..24]);
        try std.testing.expectEqualStrings("wtxidrelay", header.commandName());
    }

    // Test mempool
    {
        const msg = Message{ .mempool = {} };
        const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        try std.testing.expectEqual(@as(usize, 24), encoded.len);
        const header = MessageHeader.decode(encoded[0..24]);
        try std.testing.expectEqualStrings("mempool", header.commandName());
    }
}

test "getheaders message encode/decode" {
    const allocator = std.testing.allocator;

    const locators = [_]types.Hash256{
        [_]u8{0x11} ** 32,
        [_]u8{0x22} ** 32,
    };
    const hash_stop = [_]u8{0x00} ** 32;

    const msg = Message{ .getheaders = .{
        .version = PROTOCOL_VERSION,
        .block_locator_hashes = &locators,
        .hash_stop = hash_stop,
    } };

    const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const header = MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqualStrings("getheaders", header.commandName());

    const decoded = try decodePayload(header.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.getheaders.block_locator_hashes);

    try std.testing.expectEqual(@as(u32, @intCast(PROTOCOL_VERSION)), decoded.getheaders.version);
    try std.testing.expectEqual(@as(usize, 2), decoded.getheaders.block_locator_hashes.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00} ** 32, &decoded.getheaders.hash_stop);
}

test "sendcmpct message encode/decode" {
    const allocator = std.testing.allocator;

    const msg = Message{ .sendcmpct = .{
        .announce = true,
        .version = 2,
    } };

    const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const header = MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqualStrings("sendcmpct", header.commandName());
    // 1 byte announce + 8 bytes version = 9
    try std.testing.expectEqual(@as(u32, 9), header.length);

    const decoded = try decodePayload(header.commandName(), encoded[24..], allocator);
    try std.testing.expectEqual(true, decoded.sendcmpct.announce);
    try std.testing.expectEqual(@as(u64, 2), decoded.sendcmpct.version);
}

test "feefilter message encode/decode" {
    const allocator = std.testing.allocator;

    const msg = Message{ .feefilter = .{ .feerate = 1000 } };

    const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const header = MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqualStrings("feefilter", header.commandName());
    try std.testing.expectEqual(@as(u32, 8), header.length);

    const decoded = try decodePayload(header.commandName(), encoded[24..], allocator);
    try std.testing.expectEqual(@as(u64, 1000), decoded.feefilter.feerate);
}

test "network address big-endian port" {
    const allocator = std.testing.allocator;

    // Create a version message with specific port
    const version_msg = VersionMessage{
        .version = PROTOCOL_VERSION,
        .services = NODE_NETWORK,
        .timestamp = 0,
        .addr_recv = types.NetworkAddress{
            .services = 0,
            .ip = [_]u8{0} ** 16,
            .port = 8333, // 0x208D in big-endian: 0x20, 0x8D
        },
        .addr_from = types.NetworkAddress{
            .services = 0,
            .ip = [_]u8{0} ** 16,
            .port = 18333, // 0x479D in big-endian: 0x47, 0x9D
        },
        .nonce = 0,
        .user_agent = "",
        .start_height = 0,
        .relay = true,
    };

    const msg = Message{ .version = version_msg };
    const encoded = try encodeMessage(&msg, NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    // Verify port bytes are big-endian in the encoded payload
    // After header (24 bytes): version(4) + services(8) + timestamp(8) + services(8) + ip(16) = 44 bytes
    // Then port at offset 24 + 44 = 68, 2 bytes
    try std.testing.expectEqual(@as(u8, 0x20), encoded[68]); // High byte of 8333
    try std.testing.expectEqual(@as(u8, 0x8D), encoded[69]); // Low byte of 8333

    // Decode and verify ports are correct
    const header = MessageHeader.decode(encoded[0..24]);
    const decoded = try decodePayload(header.commandName(), encoded[24..], allocator);
    try std.testing.expectEqual(@as(u16, 8333), decoded.version.addr_recv.port);
    try std.testing.expectEqual(@as(u16, 18333), decoded.version.addr_from.port);
}

test "command name null padding" {
    // Short command
    const short_header = MessageHeader.create(NetworkMagic.MAINNET, "tx", "");
    try std.testing.expectEqualStrings("tx", short_header.commandName());
    try std.testing.expectEqual(@as(u8, 0), short_header.command[2]);
    try std.testing.expectEqual(@as(u8, 0), short_header.command[11]);

    // 12-char command (max length)
    const long_header = MessageHeader.create(NetworkMagic.MAINNET, "sendheaders", "");
    try std.testing.expectEqualStrings("sendheaders", long_header.commandName());
}

test "network magic values" {
    try std.testing.expectEqual(@as(u32, 0xD9B4BEF9), NetworkMagic.MAINNET);
    try std.testing.expectEqual(@as(u32, 0x0709110B), NetworkMagic.TESTNET);
    try std.testing.expectEqual(@as(u32, 0xDAB5BFFA), NetworkMagic.REGTEST);
    try std.testing.expectEqual(@as(u32, 0x40CF030A), NetworkMagic.SIGNET);
}
