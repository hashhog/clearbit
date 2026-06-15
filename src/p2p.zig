const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");
const erlay_mod = @import("erlay.zig");

// ============================================================================
// Protocol Constants
// ============================================================================

pub const PROTOCOL_VERSION: i32 = 70016;
pub const MIN_PROTOCOL_VERSION: i32 = 70001;
pub const NODE_NETWORK: u64 = 1;
/// NODE_COMPACT_FILTERS (BIP-157): node serves getcfilters/getcfheaders/getcfcheckpt.
/// Value = 1 << 6 = 64.  Core protocol.h:323.
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
/// BIP-37 / BIP-35: signals that the node supports bloom-filtered mempool
/// queries.  Required for serving the `mempool` message per BIP-35.
pub const NODE_BLOOM: u64 = 4;
pub const NODE_WITNESS: u64 = 8;
pub const NODE_NETWORK_LIMITED: u64 = 1024;
/// NODE_P2P_V2 (BIP-324): node supports the v2 encrypted transport protocol.
/// Value = 1 << 11 = 2048.  Core protocol.h:329.  Advertised only when the
/// node genuinely runs the v2 transport (clearbit: `bip324V2Enabled()`).
pub const NODE_P2P_V2: u64 = 1 << 11;
pub const USER_AGENT: []const u8 = "/clearbit:0.1.0/";
/// Maximum protocol message payload length accepted from a peer.
/// Matches Bitcoin Core net.h: MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000.
/// W99 G23 fix: was 32 * 1024 * 1024 (32 MiB, 8× too large).
pub const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 4 * 1000 * 1000; // 4,000,000 bytes
/// Alias for backward compatibility within this file.
pub const MAX_MESSAGE_SIZE: usize = MAX_PROTOCOL_MESSAGE_LENGTH;
pub const MAX_INV_SIZE: usize = 50000;
/// Maximum items in a single getdata message.
/// Core protocol.h:482: static const unsigned int MAX_GETDATA_SZ = 1000.
/// Incoming getdata over this limit triggers Misbehaving(100).
/// Outgoing getdata is batched at this size.
pub const MAX_GETDATA_SZ: usize = 1000;
pub const MAX_HEADERS_SIZE: usize = 2000;
pub const MAX_ADDR_SIZE: usize = 1000;
/// Maximum depth (tip.height - block.height) at which we will serve a
/// cmpctblock in response to a MSG_CMPCT_BLOCK getdata.  Deeper blocks
/// are served as full blocks instead (peer's mempool won't match anyway).
/// Reference: bitcoin-core/src/net_processing.cpp:138 MAX_CMPCTBLOCK_DEPTH = 5.
/// FIX-42 / W112 BUG-4.
pub const MAX_CMPCTBLOCK_DEPTH: u32 = 5;
/// Maximum depth (tip.height - block.height) at which we will serve
/// blocktxn in response to a getblocktxn.  Deeper requests get a full
/// block via MSG_WITNESS_BLOCK getdata instead.
/// Reference: bitcoin-core/src/net_processing.cpp:140 MAX_BLOCKTXN_DEPTH = 10.
/// FIX-42 / W112 BUG-8.
pub const MAX_BLOCKTXN_DEPTH: u32 = 10;
/// BIP-130 / Core MAX_LOCATOR_SZ (chain.h): cap on locator hashes in
/// a `getheaders` / `getblocks` message.  Anti-DoS: an attacker could
/// otherwise force unbounded `Hash256` allocation.
pub const MAX_LOCATOR_SIZE: usize = 101;

// ============================================================================
// BIP-157 Compact Filter P2P Limits (Core net_processing.cpp:184-186)
// ============================================================================

/// Maximum height range that may be requested in a single `getcfilters`
/// message: a peer must not ask for more than 1000 filters at once.
/// Reference: bitcoin-core/src/net_processing.cpp:184
///   static constexpr uint32_t MAX_GETCFILTERS_SIZE = 1000;
/// Violations trigger Misbehaving(100)+disconnect via PrepareBlockFilterRequest.
pub const MAX_GETCFILTERS_SIZE: u32 = 1000;

/// Maximum height range that may be requested in a single `getcfheaders`
/// message: 2000 filter hashes per response.
/// Reference: bitcoin-core/src/net_processing.cpp:186
///   static constexpr uint32_t MAX_GETCFHEADERS_SIZE = 2000;
pub const MAX_GETCFHEADERS_SIZE: u32 = 2000;

/// Spacing between checkpointed filter headers in `cfcheckpt` responses.
/// Reference: bitcoin-core/src/index/blockfilterindex.h:31
///   static constexpr int CFCHECKPT_INTERVAL = 1000;
pub const CFCHECKPT_INTERVAL: u32 = 1000;

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
    addrv2: AddrV2Message,
    reject: RejectMessage,
    mempool: void,
    // BIP-331 Package relay messages
    sendpackages: SendPackagesMessage,
    ancpkginfo: AncPkgInfoMessage,
    getpkgtxns: GetPkgTxnsMessage,
    pkgtxns: PkgTxnsMessage,
    // BIP-330 Erlay transaction reconciliation
    sendtxrcncl: SendTxRcnclMessage,
    reqrecon: ReqReconMessage,
    sketch: SketchMessage,
    reconcildiff: ReconcilDiffMessage,
    // BIP-152 Compact Block data messages
    cmpctblock: CmpctBlockMessage,
    getblocktxn: GetBlockTxnMessage,
    blocktxn: BlockTxnMessage,
    // BIP-37 / BIP-111 bloom filter messages (received from peers).
    // We do NOT implement CBloomFilter; these variants exist solely so the
    // message decoder does not return ParseError.UnknownCommand and so the
    // peer handler can apply the BIP-111 disconnect gate
    // (net_processing.cpp:4964 / 4990 / 5018: disconnect when NODE_BLOOM not
    // advertised).  The payload bytes are kept opaque — no full parse needed.
    filterload: BloomFilterRawMessage,
    filteradd: BloomFilterRawMessage,
    filterclear: void,
    // merkleblock is a server→client message; receiving one is unusual
    // (buggy peer).  We keep the variant to avoid ParseError.UnknownCommand
    // and log+drop it in the handler.
    merkleblock: BloomFilterRawMessage,
    // BIP-157 Compact Block Filter messages (FIX-84).
    // getcfilters / getcfheaders / getcfcheckpt are inbound requests we serve
    // from the block-filter index; cfilter / cfheaders / cfcheckpt are the
    // matching responses.  We support both directions so peers can act as
    // BIP-157 clients OR servers, and so test harnesses can round-trip the
    // wire encoding.
    getcfilters: GetCFiltersMessage,
    cfilter: CFilterMessage,
    getcfheaders: GetCFHeadersMessage,
    cfheaders: CFHeadersMessage,
    getcfcheckpt: GetCFCheckPtMessage,
    cfcheckpt: CFCheckPtMessage,
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
    /// BIP-339: wtxid-relay inv type (=5). Used for mempool tx relay to peers
    /// that negotiated wtxidrelay. Distinct from MSG_WITNESS_TX (0x40000001)
    /// which is a getdata-only flag for witness-serialised block data.
    /// Reference: bitcoin-core/src/protocol.h:481.
    msg_wtx = 5,
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

/// BIP155 addrv2 entry.
pub const AddrV2Entry = struct {
    timestamp: u32,
    services: u64,
    network_id: u8,
    addr_bytes: []const u8,
    port: u16,
};

/// BIP155 addrv2 message.
pub const AddrV2Message = struct {
    entries: []const AddrV2Entry,
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
// BIP-330 Erlay Messages
// ============================================================================

/// sendtxrcncl message - negotiate transaction reconciliation (BIP-330).
/// Sent during handshake to indicate support for Erlay.
pub const SendTxRcnclMessage = struct {
    /// Reconciliation protocol version (currently 1).
    version: u32,
    /// Salt for computing short transaction IDs.
    salt: u64,
};

/// reqrecon message - request set reconciliation from peer (BIP-330).
/// Sent by the initiator to start a reconciliation round.
pub const ReqReconMessage = struct {
    /// Number of transactions in our local reconciliation set.
    set_size: u16,
    /// Requested sketch capacity (number of differences we can handle).
    q: u16,
    /// Serialized minisketch of our transaction set.
    sketch_data: []const u8,
};

/// sketch message - send minisketch data to peer (BIP-330).
/// Sent by the responder in response to reqrecon.
pub const SketchMessage = struct {
    /// Serialized minisketch data.
    sketch_data: []const u8,
};

/// reconcildiff message - report reconciliation differences (BIP-330).
/// Sent after decoding the combined sketch to report missing/extra txids.
pub const ReconcilDiffMessage = struct {
    /// Whether reconciliation succeeded (sketch decoded).
    success: bool,
    /// Short IDs of transactions the peer is missing (we have, they don't).
    missing_short_ids: []const u32,
    /// Short IDs of transactions we are missing (they have, we don't).
    extra_short_ids: []const u32,
};

// ============================================================================
// BIP-152 Compact Block Data Messages
// ============================================================================

/// cmpctblock message (BIP-152) - a compact representation of a block.
/// Contains the header, a nonce for computing short IDs, the short IDs of
/// transactions, and prefilled transactions (coinbase at minimum).
pub const CmpctBlockMessage = struct {
    /// Block header (80 bytes).
    header: types.BlockHeader,
    /// Nonce for computing short transaction IDs.
    nonce: u64,
    /// Short transaction IDs (6 bytes each, truncated SipHash).
    short_ids: []const [6]u8,
    /// Prefilled transactions (index + full transaction).
    prefilled_txs: []const PrefilledTransaction,
};

/// A prefilled transaction in a compact block.
pub const PrefilledTransaction = struct {
    /// Differentially encoded index in the block.
    index: u16,
    /// The full transaction.
    tx: types.Transaction,
};

/// getblocktxn message (BIP-152) - request missing transactions for a compact block.
pub const GetBlockTxnMessage = struct {
    /// Hash of the block for which transactions are requested.
    block_hash: types.Hash256,
    /// Indices of the requested transactions (differentially encoded varints).
    indexes: []const u16,
};

/// blocktxn message (BIP-152) - provide missing transactions for compact block reconstruction.
pub const BlockTxnMessage = struct {
    /// Hash of the block these transactions belong to.
    block_hash: types.Hash256,
    /// The requested transactions.
    transactions: []const types.Transaction,
};

/// BIP-37 / BIP-111 opaque bloom-filter message payload.
///
/// We do not parse the bloom filter wire format — clearbit has no CBloomFilter
/// implementation.  The payload is kept as raw bytes so the peer handler can
/// apply the BIP-111 disconnect gate without ever touching filter internals.
/// Lifetime: payload slice points into a caller-managed buffer; the caller is
/// responsible for freeing it (use allocator.free(msg.payload)).
pub const BloomFilterRawMessage = struct {
    /// Raw wire payload bytes (opaque; do not interpret).
    payload: []const u8,
};

// ============================================================================
// BIP-157 Compact Block Filter Messages (FIX-84)
// ============================================================================
//
// Reference: bitcoin-core/src/net_processing.cpp
//   ProcessGetCFilters / ProcessGetCFHeaders / ProcessGetCFCheckPt.
// All six payload encodings exactly mirror Core's wire format.

/// `getcfilters` — request filters for the height range
/// `[start_height, stop_index.height]` where `stop_index = LookupBlockIndex(stop_hash)`.
/// Wire payload: filter_type (u8) || start_height (u32 LE) || stop_hash (32B).
pub const GetCFiltersMessage = struct {
    filter_type: u8,
    start_height: u32,
    stop_hash: types.Hash256,
};

/// `cfilter` — single filter response.  One sent per height in
/// the requested range (so a getcfilters covering 5 heights yields
/// 5 cfilter messages).
/// Wire payload: filter_type (u8) || block_hash (32B) || filter (var_str).
pub const CFilterMessage = struct {
    filter_type: u8,
    block_hash: types.Hash256,
    /// Raw GCS-encoded filter bytes (already includes the CompactSize(N)
    /// prefix per BIP-158).  Owned by the message; freed by the receiver.
    filter: []const u8,
};

/// `getcfheaders` — request filter-header chain for a height range.
/// Wire payload: filter_type (u8) || start_height (u32 LE) || stop_hash (32B).
pub const GetCFHeadersMessage = struct {
    filter_type: u8,
    start_height: u32,
    stop_hash: types.Hash256,
};

/// `cfheaders` — filter-header chain response.  `prev_filter_header` is
/// the chained header at (start_height - 1) so the requester can verify
/// the entire chain back to genesis without refetching earlier filters;
/// `filter_hashes` are the 32-byte filter content hashes (NOT chained
/// headers — Core's CFHEADERS message format).
/// Wire payload: filter_type (u8) || stop_hash (32B) || prev_filter_header (32B)
///               || count (CompactSize) || filter_hashes (32B each).
pub const CFHeadersMessage = struct {
    filter_type: u8,
    stop_hash: types.Hash256,
    prev_filter_header: types.Hash256,
    filter_hashes: []const types.Hash256,
};

/// `getcfcheckpt` — request checkpointed filter headers
/// (every CFCHECKPT_INTERVAL=1000 blocks).
/// Wire payload: filter_type (u8) || stop_hash (32B).
pub const GetCFCheckPtMessage = struct {
    filter_type: u8,
    stop_hash: types.Hash256,
};

/// `cfcheckpt` — checkpointed filter-header response.  One header per
/// CFCHECKPT_INTERVAL blocks up to (but not including) stop_index.
/// Wire payload: filter_type (u8) || stop_hash (32B)
///               || count (CompactSize) || headers (32B each).
pub const CFCheckPtMessage = struct {
    filter_type: u8,
    stop_hash: types.Hash256,
    filter_headers: []const types.Hash256,
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
        .addrv2 => "addrv2",
        .reject => "reject",
        .mempool => "mempool",
        // BIP-331 Package relay messages
        .sendpackages => "sendpackages",
        .ancpkginfo => "ancpkginfo",
        .getpkgtxns => "getpkgtxns",
        .pkgtxns => "pkgtxns",
        // BIP-330 Erlay
        .sendtxrcncl => "sendtxrcncl",
        .reqrecon => "reqrecon",
        .sketch => "sketch",
        .reconcildiff => "reconcildiff",
        // BIP-152 Compact Block data messages
        .cmpctblock => "cmpctblock",
        .getblocktxn => "getblocktxn",
        .blocktxn => "blocktxn",
        // BIP-37 / BIP-111: never sent by us; included for exhaustive switch.
        .filterload => "filterload",
        .filteradd => "filteradd",
        .filterclear => "filterclear",
        .merkleblock => "merkleblock",
        // BIP-157 compact filter messages (FIX-84).
        .getcfilters => "getcfilters",
        .cfilter => "cfilter",
        .getcfheaders => "getcfheaders",
        .cfheaders => "cfheaders",
        .getcfcheckpt => "getcfcheckpt",
        .cfcheckpt => "cfcheckpt",
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
        .addrv2 => |a2| {
            try payload_writer.writeCompactSize(a2.entries.len);
            for (a2.entries) |entry| {
                try payload_writer.writeInt(u32, entry.timestamp);
                try payload_writer.writeCompactSize(entry.services);
                try payload_writer.writeBytes(&[_]u8{entry.network_id});
                try payload_writer.writeCompactSize(entry.addr_bytes.len);
                try payload_writer.writeBytes(entry.addr_bytes);
                // Port is big-endian in addrv2 (network byte order)
                var port_buf: [2]u8 = undefined;
                std.mem.writeInt(u16, &port_buf, entry.port, .big);
                try payload_writer.writeBytes(&port_buf);
            }
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
        // BIP-330 Erlay
        .sendtxrcncl => |stxr| {
            try payload_writer.writeInt(u32, stxr.version);
            try payload_writer.writeInt(u64, stxr.salt);
        },
        .reqrecon => |rr| {
            try payload_writer.writeInt(u16, rr.set_size);
            try payload_writer.writeInt(u16, rr.q);
            try payload_writer.writeCompactSize(rr.sketch_data.len);
            try payload_writer.writeBytes(rr.sketch_data);
        },
        .sketch => |sk| {
            try payload_writer.writeCompactSize(sk.sketch_data.len);
            try payload_writer.writeBytes(sk.sketch_data);
        },
        .reconcildiff => |rd| {
            try payload_writer.writeBytes(&[_]u8{if (rd.success) 1 else 0});
            try payload_writer.writeCompactSize(rd.missing_short_ids.len);
            for (rd.missing_short_ids) |sid| {
                try payload_writer.writeInt(u32, sid);
            }
            try payload_writer.writeCompactSize(rd.extra_short_ids.len);
            for (rd.extra_short_ids) |sid| {
                try payload_writer.writeInt(u32, sid);
            }
        },
        // BIP-152 Compact Block data messages
        .cmpctblock => |cb| {
            try serialize.writeBlockHeader(&payload_writer, &cb.header);
            try payload_writer.writeInt(u64, cb.nonce);
            try payload_writer.writeCompactSize(cb.short_ids.len);
            for (cb.short_ids) |sid| {
                try payload_writer.writeBytes(&sid);
            }
            try payload_writer.writeCompactSize(cb.prefilled_txs.len);
            for (cb.prefilled_txs) |ptx| {
                try payload_writer.writeCompactSize(ptx.index);
                try serialize.writeTransaction(&payload_writer, &ptx.tx);
            }
        },
        .getblocktxn => |gbt| {
            try payload_writer.writeBytes(&gbt.block_hash);
            try payload_writer.writeCompactSize(gbt.indexes.len);
            // Core blockencodings.h DifferenceFormatter: encode each index as
            // a delta from (previous_absolute_index + 1).  shift starts at 0.
            var shift: u64 = 0;
            for (gbt.indexes) |idx| {
                const abs: u64 = @intCast(idx);
                // abs >= shift is guaranteed by sorted ascending indices
                try payload_writer.writeCompactSize(abs - shift);
                shift = abs + 1;
            }
        },
        .blocktxn => |bt| {
            try payload_writer.writeBytes(&bt.block_hash);
            try payload_writer.writeCompactSize(bt.transactions.len);
            for (bt.transactions) |transaction| {
                try serialize.writeTransaction(&payload_writer, &transaction);
            }
        },
        // BIP-37 / BIP-111: we never SEND these; write raw payload back verbatim
        // (used only in tests that round-trip; in production these are inbound only).
        .filterload, .filteradd, .merkleblock => |bfm| {
            try payload_writer.writeBytes(bfm.payload);
        },
        .filterclear => {
            // filterclear has an empty payload per BIP-37.
        },
        // BIP-157 compact filter messages (FIX-84).
        .getcfilters => |gc| {
            try payload_writer.writeBytes(&[_]u8{gc.filter_type});
            try payload_writer.writeInt(u32, gc.start_height);
            try payload_writer.writeBytes(&gc.stop_hash);
        },
        .cfilter => |cf| {
            try payload_writer.writeBytes(&[_]u8{cf.filter_type});
            try payload_writer.writeBytes(&cf.block_hash);
            try payload_writer.writeCompactSize(cf.filter.len);
            try payload_writer.writeBytes(cf.filter);
        },
        .getcfheaders => |gch| {
            try payload_writer.writeBytes(&[_]u8{gch.filter_type});
            try payload_writer.writeInt(u32, gch.start_height);
            try payload_writer.writeBytes(&gch.stop_hash);
        },
        .cfheaders => |cfh| {
            try payload_writer.writeBytes(&[_]u8{cfh.filter_type});
            try payload_writer.writeBytes(&cfh.stop_hash);
            try payload_writer.writeBytes(&cfh.prev_filter_header);
            try payload_writer.writeCompactSize(cfh.filter_hashes.len);
            for (cfh.filter_hashes) |h| {
                try payload_writer.writeBytes(&h);
            }
        },
        .getcfcheckpt => |gcc| {
            try payload_writer.writeBytes(&[_]u8{gcc.filter_type});
            try payload_writer.writeBytes(&gcc.stop_hash);
        },
        .cfcheckpt => |cfc| {
            try payload_writer.writeBytes(&[_]u8{cfc.filter_type});
            try payload_writer.writeBytes(&cfc.stop_hash);
            try payload_writer.writeCompactSize(cfc.filter_headers.len);
            for (cfc.filter_headers) |h| {
                try payload_writer.writeBytes(&h);
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
    OversizedVector,
    InvalidSegwitMarker,
    SuperfluousWitnessRecord,
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
    } else if (std.mem.eql(u8, command, "addrv2")) {
        return Message{ .addrv2 = try decodeAddrV2(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "mempool")) {
        return Message{ .mempool = {} };
    } else if (std.mem.eql(u8, command, "getaddr")) {
        return Message{ .getaddr = {} };
    } else if (std.mem.eql(u8, command, "addr")) {
        return Message{ .addr = try decodeAddr(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "reject")) {
        return Message{ .reject = try decodeReject(&reader, allocator) };
    } else if (std.mem.eql(u8, command, "sendtxrcncl")) {
        return Message{ .sendtxrcncl = .{
            .version = try reader.readInt(u32),
            .salt = try reader.readInt(u64),
        } };
    } else if (std.mem.eql(u8, command, "reqrecon")) {
        const set_size = try reader.readInt(u16);
        const q = try reader.readInt(u16);
        const sketch_len = try reader.readCompactSize();
        const sketch_data = try reader.readBytes(@intCast(sketch_len));
        return Message{ .reqrecon = .{
            .set_size = set_size,
            .q = q,
            .sketch_data = sketch_data,
        } };
    } else if (std.mem.eql(u8, command, "sketch")) {
        const sketch_len = try reader.readCompactSize();
        const sketch_data = try reader.readBytes(@intCast(sketch_len));
        return Message{ .sketch = .{
            .sketch_data = sketch_data,
        } };
    } else if (std.mem.eql(u8, command, "reconcildiff")) {
        const success = (try reader.readBytes(1))[0] != 0;
        const missing_count = try reader.readCompactSize();
        var missing_ids = try allocator.alloc(u32, @intCast(missing_count));
        for (0..@intCast(missing_count)) |i| {
            missing_ids[i] = try reader.readInt(u32);
        }
        const extra_count = try reader.readCompactSize();
        var extra_ids = try allocator.alloc(u32, @intCast(extra_count));
        for (0..@intCast(extra_count)) |i| {
            extra_ids[i] = try reader.readInt(u32);
        }
        return Message{ .reconcildiff = .{
            .success = success,
            .missing_short_ids = missing_ids,
            .extra_short_ids = extra_ids,
        } };
    } else if (std.mem.eql(u8, command, "cmpctblock")) {
        const header = try serialize.readBlockHeader(&reader);
        const nonce = try reader.readInt(u64);
        const short_id_count = try reader.readCompactSize();
        // BIP-152 / Core blockencodings.cpp:64: guard against DoS via huge
        // short-id vector.  MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TX_WEIGHT = 100000.
        // Also guard: short_id_count alone must not overflow uint16_t (Core
        // blockencodings.h:125 — BlockTxCount() must fit in uint16).
        if (short_id_count > 100_000) return ParseError.InvalidData;
        if (short_id_count > 0xffff) return ParseError.InvalidData;
        var short_ids = try allocator.alloc([6]u8, @intCast(short_id_count));
        errdefer allocator.free(short_ids);
        for (0..@intCast(short_id_count)) |i| {
            short_ids[i] = (try reader.readBytes(6))[0..6].*;
        }
        const prefilled_count = try reader.readCompactSize();
        if (prefilled_count > 100_000) return ParseError.InvalidData;
        if (prefilled_count > 0xffff) return ParseError.InvalidData;
        // Core blockencodings.h:125: BlockTxCount() = shorttxids.size() +
        // prefilledtxn.size() must fit in uint16_t (≤ 65535).
        if (short_id_count + prefilled_count > 0xffff) return ParseError.InvalidData;
        var prefilled_txs = try allocator.alloc(PrefilledTransaction, @intCast(prefilled_count));
        errdefer allocator.free(prefilled_txs);
        for (0..@intCast(prefilled_count)) |i| {
            // Index is a compact-size differential offset from the previous
            // prefilled position (Core blockencodings.h DifferenceFormatter).
            const index = try reader.readCompactSize();
            if (index > 0xffff) return ParseError.InvalidData;
            const transaction = try serialize.readTransaction(&reader, allocator);
            prefilled_txs[i] = .{
                .index = @intCast(index),
                .tx = transaction,
            };
        }
        return Message{ .cmpctblock = .{
            .header = header,
            .nonce = nonce,
            .short_ids = short_ids,
            .prefilled_txs = prefilled_txs,
        } };
    } else if (std.mem.eql(u8, command, "getblocktxn")) {
        const block_hash = try reader.readHash();
        const index_count = try reader.readCompactSize();
        var indexes = try allocator.alloc(u16, @intCast(index_count));
        errdefer allocator.free(indexes);
        // Core blockencodings.h DifferenceFormatter: each encoded value is the
        // delta from (previous_absolute_index + 1), so we accumulate.
        var shift: u64 = 0;
        for (0..@intCast(index_count)) |i| {
            const delta = try reader.readCompactSize();
            shift += delta;
            if (shift > 0xffff) return ParseError.InvalidData;
            indexes[i] = @intCast(shift);
            shift += 1; // DifferenceFormatter increments shift after each value
        }
        return Message{ .getblocktxn = .{
            .block_hash = block_hash,
            .indexes = indexes,
        } };
    } else if (std.mem.eql(u8, command, "blocktxn")) {
        const block_hash = try reader.readHash();
        const tx_count = try reader.readCompactSize();
        var transactions = try allocator.alloc(types.Transaction, @intCast(tx_count));
        for (0..@intCast(tx_count)) |i| {
            transactions[i] = try serialize.readTransaction(&reader, allocator);
        }
        return Message{ .blocktxn = .{
            .block_hash = block_hash,
            .transactions = transactions,
        } };
    }

    // BIP-37 / BIP-111 bloom filter messages.
    //
    // We do not parse the filter wire format.  The payload is kept as a raw
    // slice so the peer handler can apply the BIP-111 disconnect gate
    // (net_processing.cpp:4964 / 4990 / 5018).  The slice's backing store is
    // the `payload` argument — the caller (receiveMessage) uses `defer
    // allocator.free(payload)`, so the caller must NOT free the buffer when
    // one of these variants is returned; instead the peer handler frees
    // msg.filterload.payload (or .filteradd.payload / .merkleblock.payload).
    // For filterclear the payload is empty — no allocation needed.
    if (std.mem.eql(u8, command, "filterload")) {
        const owned = try allocator.dupe(u8, payload);
        return Message{ .filterload = .{ .payload = owned } };
    } else if (std.mem.eql(u8, command, "filteradd")) {
        const owned = try allocator.dupe(u8, payload);
        return Message{ .filteradd = .{ .payload = owned } };
    } else if (std.mem.eql(u8, command, "filterclear")) {
        return Message{ .filterclear = {} };
    } else if (std.mem.eql(u8, command, "merkleblock")) {
        const owned = try allocator.dupe(u8, payload);
        return Message{ .merkleblock = .{ .payload = owned } };
    }

    // ========================================================================
    // BIP-157 Compact Filter Messages (FIX-84)
    // ========================================================================
    //
    // Wire formats mirror Bitcoin Core's net_processing.cpp exactly so a
    // BIP-157 light client (Neutrino, BFD, rust-lightning) can round-trip
    // requests + responses against clearbit identically to Core.
    if (std.mem.eql(u8, command, "getcfilters")) {
        const filter_type = (try reader.readBytes(1))[0];
        const start_height = try reader.readInt(u32);
        const stop_hash = try reader.readHash();
        return Message{ .getcfilters = .{
            .filter_type = filter_type,
            .start_height = start_height,
            .stop_hash = stop_hash,
        } };
    } else if (std.mem.eql(u8, command, "cfilter")) {
        const filter_type = (try reader.readBytes(1))[0];
        const block_hash = try reader.readHash();
        const flen = try reader.readCompactSize();
        // Safety: cap at MAX_MESSAGE_SIZE; the header.length check upstream
        // already bounds this but a malicious encoder could embed a too-large
        // CompactSize without the actual bytes.  readBytes will error if the
        // payload is short — that's the real guard.
        const fbytes = try reader.readBytes(@intCast(flen));
        const owned = try allocator.dupe(u8, fbytes);
        return Message{ .cfilter = .{
            .filter_type = filter_type,
            .block_hash = block_hash,
            .filter = owned,
        } };
    } else if (std.mem.eql(u8, command, "getcfheaders")) {
        const filter_type = (try reader.readBytes(1))[0];
        const start_height = try reader.readInt(u32);
        const stop_hash = try reader.readHash();
        return Message{ .getcfheaders = .{
            .filter_type = filter_type,
            .start_height = start_height,
            .stop_hash = stop_hash,
        } };
    } else if (std.mem.eql(u8, command, "cfheaders")) {
        const filter_type = (try reader.readBytes(1))[0];
        const stop_hash = try reader.readHash();
        const prev_filter_header = try reader.readHash();
        const count = try reader.readCompactSize();
        // Anti-DoS: count is bounded by MAX_GETCFHEADERS_SIZE = 2000.  Reject
        // BEFORE allocating to prevent unbounded memory allocation via a
        // crafted message.
        if (count > MAX_GETCFHEADERS_SIZE) return ParseError.InvalidData;
        var hashes = try allocator.alloc(types.Hash256, @intCast(count));
        for (0..@intCast(count)) |i| {
            hashes[i] = try reader.readHash();
        }
        return Message{ .cfheaders = .{
            .filter_type = filter_type,
            .stop_hash = stop_hash,
            .prev_filter_header = prev_filter_header,
            .filter_hashes = hashes,
        } };
    } else if (std.mem.eql(u8, command, "getcfcheckpt")) {
        const filter_type = (try reader.readBytes(1))[0];
        const stop_hash = try reader.readHash();
        return Message{ .getcfcheckpt = .{
            .filter_type = filter_type,
            .stop_hash = stop_hash,
        } };
    } else if (std.mem.eql(u8, command, "cfcheckpt")) {
        const filter_type = (try reader.readBytes(1))[0];
        const stop_hash = try reader.readHash();
        const count = try reader.readCompactSize();
        // Anti-DoS: bound by absolute height ceiling.  A peer claiming
        // millions of checkpoints would overrun memory.  ~3.4M is the
        // theoretical absolute max (UINT32_MAX/CFCHECKPT_INTERVAL ≈ 4.2M)
        // — use 200_000 as a conservative cap (well above 2026 tip).
        if (count > 200_000) return ParseError.InvalidData;
        var hashes = try allocator.alloc(types.Hash256, @intCast(count));
        for (0..@intCast(count)) |i| {
            hashes[i] = try reader.readHash();
        }
        return Message{ .cfcheckpt = .{
            .filter_type = filter_type,
            .stop_hash = stop_hash,
            .filter_headers = hashes,
        } };
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
    // Anti-DoS: Bitcoin Core MAX_LOCATOR_SZ = 101 (chain.h).  Reject
    // before allocating to prevent unbounded memory allocation via a
    // crafted `getheaders` / `getblocks` message.
    if (count > MAX_LOCATOR_SIZE) return ParseError.InvalidData;
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

/// Decode BIP155 addrv2 message.
fn decodeAddrV2(reader: *serialize.Reader, allocator: std.mem.Allocator) ParseError!AddrV2Message {
    const count = try reader.readCompactSize();
    if (count > MAX_ADDR_SIZE) return ParseError.InvalidData;
    var entries = try allocator.alloc(AddrV2Entry, @intCast(count));
    for (0..@intCast(count)) |i| {
        const timestamp = try reader.readInt(u32);
        // BIP-155 §2 / Bitcoin Core protocol.h:446: the services field in
        // addrv2 is a 64-bit bitfield encoded as CompactSize with NO range
        // check (CompactSizeFormatter<false>).  Using the range-checked
        // readCompactSize() here wrongly disconnects peers advertising any
        // service bit >= 26 (value > MAX_SIZE = 0x02000000).
        const services = try reader.readCompactSizeNoLimit();
        const network_id = (try reader.readBytes(1))[0];
        const addr_len = try reader.readCompactSize();
        if (addr_len > 512) return ParseError.InvalidData;
        const addr_bytes = try reader.readBytes(@intCast(addr_len));
        // Port is big-endian in addrv2 (network byte order)
        const port_bytes = try reader.readBytes(2);
        const port = std.mem.readInt(u16, port_bytes[0..2], .big);
        entries[i] = AddrV2Entry{
            .timestamp = timestamp,
            .services = services,
            .network_id = network_id,
            .addr_bytes = addr_bytes,
            .port = port,
        };
    }
    return AddrV2Message{ .entries = entries };
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

test "addrv2 services field accepts values above MAX_SIZE (7A regression)" {
    // Bitcoin Core reads the addrv2 `services` field with CompactSizeFormatter<false>
    // (protocol.h:446), i.e. NO range check.  Values > MAX_SIZE (0x02000000) are
    // valid 64-bit service bitmasks, not container lengths.  Before this fix,
    // decodeAddrV2 used readCompactSize() (range_check=true), which returned
    // OversizedVector for any service bit >= 26 and caused the connection to be
    // torn down — wrongly disconnecting well-behaved peers.
    //
    // This test encodes an addrv2 entry with services = 0x80000000 (bit 31 set,
    // which encodes as a 5-byte CompactSize 0xFE + LE32) and verifies the decoder
    // accepts it without error and preserves the value exactly.
    // Without the fix: decodeAddrV2 returns OversizedVector (= ParseError.InvalidData).
    // With the fix: decodes successfully, services == 0x80000000.
    const allocator = std.testing.allocator;

    // Manually encode an addrv2 payload:
    //   compact_size(count=1)  = 0x01
    //   timestamp(u32 LE)      = 00 00 00 00
    //   services (CompactSize, no range check):
    //     0x80000000 > 0xFFFF but fits in u32 → 0xFE prefix + LE32
    //     = FE 00 00 00 80
    //   network_id(u8)         = 0x01 (IPv4)
    //   addr_len(CompactSize)  = 0x04
    //   addr_bytes(4)          = 7F 00 00 01  (127.0.0.1)
    //   port(u16 BE)           = 20 8D        (8333)
    const payload = [_]u8{
        0x01,                   // count = 1
        0x00, 0x00, 0x00, 0x00, // timestamp = 0
        0xFE, 0x00, 0x00, 0x00, 0x80, // services = 0x80000000 (5-byte CompactSize)
        0x01,                   // network_id = 1 (IPv4)
        0x04,                   // addr_len = 4
        0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
        0x20, 0x8D,             // port = 8333 (big-endian)
    };

    const msg = try decodePayload("addrv2", &payload, allocator);
    defer allocator.free(msg.addrv2.entries);

    try std.testing.expectEqual(@as(usize, 1), msg.addrv2.entries.len);
    try std.testing.expectEqual(@as(u64, 0x80000000), msg.addrv2.entries[0].services);
    try std.testing.expectEqual(@as(u16, 8333), msg.addrv2.entries[0].port);

    // Also verify the all-bits-set case (u64 max, 9-byte CompactSize FF + LE64).
    // This would encode as: FF FF FF FF FF FF FF FF FF
    const payload_allbits = [_]u8{
        0x01,
        0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // services = u64::MAX
        0x01,
        0x04,
        0x7F, 0x00, 0x00, 0x01,
        0x20, 0x8D,
    };

    const msg2 = try decodePayload("addrv2", &payload_allbits, allocator);
    defer allocator.free(msg2.addrv2.entries);

    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), msg2.addrv2.entries[0].services);
}
