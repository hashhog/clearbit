//! Bitcoin Core-compatible JSON-RPC server over HTTP.
//!
//! This module implements a JSON-RPC server that exposes Bitcoin Core-compatible
//! RPC methods for wallets, miners, and block explorers.
//!
//! Key features:
//! - Bitcoin Core JSON-RPC 1.0 compatibility
//! - HTTP Basic Authentication support
//! - Essential RPC methods (getblockchaininfo, getblock, sendrawtransaction, etc.)
//! - Mining support (getblocktemplate, submitblock)

const std = @import("std");
const types = @import("types.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const banlist = @import("banlist.zig");
const serialize = @import("serialize.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const block_template = @import("block_template.zig");
const validation = @import("validation.zig");
const wallet_mod = @import("wallet.zig");

// ============================================================================
// RPC Error Codes (Bitcoin Core conventions)
// ============================================================================

/// Standard JSON-RPC errors.
pub const RPC_INVALID_REQUEST: i32 = -32600;
pub const RPC_METHOD_NOT_FOUND: i32 = -32601;
pub const RPC_INVALID_PARAMS: i32 = -32602;
pub const RPC_INTERNAL_ERROR: i32 = -32603;
pub const RPC_PARSE_ERROR: i32 = -32700;

/// Bitcoin-specific errors.
pub const RPC_MISC_ERROR: i32 = -1;
pub const RPC_FORBIDDEN_BY_SAFE_MODE: i32 = -2;
pub const RPC_TYPE_ERROR: i32 = -3;
pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;
pub const RPC_OUT_OF_MEMORY: i32 = -7;
pub const RPC_INVALID_PARAMETER: i32 = -8;
pub const RPC_DATABASE_ERROR: i32 = -20;
pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
pub const RPC_VERIFY_ERROR: i32 = -25;
pub const RPC_VERIFY_REJECTED: i32 = -26;
pub const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;
pub const RPC_IN_WARMUP: i32 = -28;

/// Wallet-specific errors.
pub const RPC_WALLET_ERROR: i32 = -4;
pub const RPC_WALLET_INSUFFICIENT_FUNDS: i32 = -6;
pub const RPC_WALLET_KEYPOOL_RAN_OUT: i32 = -12;
pub const RPC_WALLET_UNLOCK_NEEDED: i32 = -13;
pub const RPC_WALLET_PASSPHRASE_INCORRECT: i32 = -14;
pub const RPC_WALLET_WRONG_ENC_STATE: i32 = -15;
pub const RPC_WALLET_ENCRYPTION_FAILED: i32 = -16;
pub const RPC_WALLET_ALREADY_UNLOCKED: i32 = -17;
pub const RPC_WALLET_NOT_FOUND: i32 = -18;
pub const RPC_WALLET_NOT_SPECIFIED: i32 = -19;

// ============================================================================
// RPC Server
// ============================================================================

/// JSON-RPC server configuration.
pub const RpcConfig = struct {
    bind_address: []const u8 = "127.0.0.1",
    port: u16 = 8332,
    auth_token: ?[]const u8 = null, // Base64-encoded "user:pass"
    max_request_size: usize = 1 << 20, // 1 MB
};

/// RPC Server error set.
pub const RpcError = error{
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    OutOfMemory,
    Unauthorized,
    ConnectionError,
};

/// JSON-RPC server over HTTP.
pub const RpcServer = struct {
    listener: ?std.net.Server,
    allocator: std.mem.Allocator,
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    peer_manager: *peer_mod.PeerManager,
    network_params: *const consensus.NetworkParams,
    wallet: ?*wallet_mod.Wallet,
    config: RpcConfig,
    running: std.atomic.Value(bool),

    /// Initialize the RPC server.
    pub fn init(
        allocator: std.mem.Allocator,
        chain_state: *storage.ChainState,
        mempool: *mempool_mod.Mempool,
        peer_manager: *peer_mod.PeerManager,
        network_params: *const consensus.NetworkParams,
        config: RpcConfig,
    ) RpcServer {
        return RpcServer{
            .listener = null,
            .allocator = allocator,
            .chain_state = chain_state,
            .mempool = mempool,
            .peer_manager = peer_manager,
            .network_params = network_params,
            .wallet = null,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    /// Initialize the RPC server with a wallet.
    pub fn initWithWallet(
        allocator: std.mem.Allocator,
        chain_state: *storage.ChainState,
        mempool: *mempool_mod.Mempool,
        peer_manager: *peer_mod.PeerManager,
        network_params: *const consensus.NetworkParams,
        wallet: *wallet_mod.Wallet,
        config: RpcConfig,
    ) RpcServer {
        return RpcServer{
            .listener = null,
            .allocator = allocator,
            .chain_state = chain_state,
            .mempool = mempool,
            .peer_manager = peer_manager,
            .network_params = network_params,
            .wallet = wallet,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    /// Start listening for connections.
    pub fn start(self: *RpcServer) !void {
        const addr = try std.net.Address.parseIp(self.config.bind_address, self.config.port);
        self.listener = try addr.listen(.{
            .reuse_address = true,
        });
        self.running.store(true, .release);
    }

    /// Deinitialize the server.
    pub fn deinit(self: *RpcServer) void {
        self.stop();
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
    }

    /// Stop the server.
    pub fn stop(self: *RpcServer) void {
        self.running.store(false, .release);
    }

    /// Main server loop - accept and handle connections.
    pub fn run(self: *RpcServer) !void {
        while (self.running.load(.acquire)) {
            const conn = self.listener.?.accept() catch |err| {
                switch (err) {
                    error.WouldBlock => continue,
                    error.ConnectionAborted => continue,
                    else => return err,
                }
            };

            // Handle connection in-thread for simplicity
            // In production, would spawn a thread or use async
            self.handleConnection(conn) catch {};
        }
    }

    /// Handle a single HTTP connection.
    fn handleConnection(self: *RpcServer, conn: std.net.Server.Connection) !void {
        defer conn.stream.close();

        // Read HTTP request
        var buf: [65536]u8 = undefined;
        var total_read: usize = 0;

        // Read until we have the full headers
        while (total_read < buf.len) {
            const n = conn.stream.read(buf[total_read..]) catch return;
            if (n == 0) return;
            total_read += n;

            // Check for end of headers
            if (std.mem.indexOf(u8, buf[0..total_read], "\r\n\r\n")) |_| break;
        }

        // Parse HTTP request
        const request_data = buf[0..total_read];

        // Find headers end
        const headers_end = std.mem.indexOf(u8, request_data, "\r\n\r\n") orelse return;
        const headers = request_data[0..headers_end];

        // Check method is POST
        if (!std.mem.startsWith(u8, headers, "POST")) {
            try self.sendHttpError(conn.stream, 405, "Method Not Allowed");
            return;
        }

        // Check authentication if configured
        if (self.config.auth_token) |expected_token| {
            const auth_header = findHeader(headers, "Authorization") orelse {
                try self.sendHttpError(conn.stream, 401, "Unauthorized");
                return;
            };
            if (!std.mem.startsWith(u8, auth_header, "Basic ")) {
                try self.sendHttpError(conn.stream, 401, "Unauthorized");
                return;
            }
            if (!std.mem.eql(u8, auth_header[6..], expected_token)) {
                try self.sendHttpError(conn.stream, 401, "Unauthorized");
                return;
            }
        }

        // Get Content-Length
        const content_length_str = findHeader(headers, "Content-Length") orelse {
            try self.sendHttpError(conn.stream, 400, "Bad Request: Missing Content-Length");
            return;
        };
        const content_length = std.fmt.parseInt(usize, content_length_str, 10) catch {
            try self.sendHttpError(conn.stream, 400, "Bad Request: Invalid Content-Length");
            return;
        };

        if (content_length > self.config.max_request_size) {
            try self.sendHttpError(conn.stream, 413, "Request Entity Too Large");
            return;
        }

        // Read body
        const body_start = headers_end + 4;
        var body: []u8 = undefined;

        if (body_start + content_length <= total_read) {
            // Already have full body
            body = @constCast(request_data[body_start .. body_start + content_length]);
        } else {
            // Need to read more
            _ = content_length - (total_read - body_start); // remaining bytes needed
            var body_buf = self.allocator.alloc(u8, content_length) catch {
                try self.sendHttpError(conn.stream, 500, "Internal Server Error");
                return;
            };
            defer self.allocator.free(body_buf);

            @memcpy(body_buf[0 .. total_read - body_start], request_data[body_start..total_read]);
            var offset = total_read - body_start;
            while (offset < content_length) {
                const n = conn.stream.read(body_buf[offset..]) catch return;
                if (n == 0) return;
                offset += n;
            }
            body = body_buf;
        }

        // Process JSON-RPC request
        const response = self.dispatch(body) catch |err| {
            const error_response = self.jsonRpcError(
                RPC_INTERNAL_ERROR,
                @errorName(err),
                null,
            ) catch return;
            defer self.allocator.free(error_response);
            try self.sendHttpResponse(conn.stream, 200, error_response);
            return;
        };
        defer self.allocator.free(response);

        try self.sendHttpResponse(conn.stream, 200, response);
    }

    /// Send an HTTP error response.
    fn sendHttpError(self: *RpcServer, stream: std.net.Stream, status: u16, message: []const u8) !void {
        _ = self;
        var response_buf: [256]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{ status, message }) catch return;
        stream.writeAll(response) catch {};
    }

    /// Send an HTTP response with JSON body.
    fn sendHttpResponse(self: *RpcServer, stream: std.net.Stream, status: u16, body: []const u8) !void {
        _ = self;
        var header_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 {d} OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, body.len }) catch return;
        stream.writeAll(header) catch {};
        stream.writeAll(body) catch {};
    }

    /// Dispatch a JSON-RPC request to the appropriate handler.
    pub fn dispatch(self: *RpcServer, body: []const u8) ![]const u8 {
        // Parse JSON
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch {
            return self.jsonRpcError(RPC_PARSE_ERROR, "Parse error", null);
        };
        defer parsed.deinit();

        const root = parsed.value;

        // Handle batch requests (array of requests)
        if (root == .array) {
            return self.handleBatch(root.array.items);
        }

        // Single request
        if (root != .object) {
            return self.jsonRpcError(RPC_INVALID_REQUEST, "Invalid Request", null);
        }

        return self.handleSingleRequest(root.object);
    }

    /// Handle a single JSON-RPC request.
    fn handleSingleRequest(self: *RpcServer, obj: std.json.ObjectMap) ![]const u8 {
        // Get method
        const method_value = obj.get("method") orelse {
            return self.jsonRpcError(RPC_INVALID_REQUEST, "Missing method", null);
        };
        if (method_value != .string) {
            return self.jsonRpcError(RPC_INVALID_REQUEST, "Method must be string", null);
        }
        const method = method_value.string;

        // Get id (can be null, number, or string)
        const id = obj.get("id");

        // Get params (optional, defaults to empty array)
        const params = obj.get("params") orelse std.json.Value{ .array = std.json.Array.init(self.allocator) };

        // Dispatch by method name
        if (std.mem.eql(u8, method, "getblockchaininfo")) {
            return self.handleGetBlockchainInfo(id);
        } else if (std.mem.eql(u8, method, "getblockcount")) {
            return self.handleGetBlockCount(id);
        } else if (std.mem.eql(u8, method, "getblockhash")) {
            return self.handleGetBlockHash(params, id);
        } else if (std.mem.eql(u8, method, "getblock")) {
            return self.handleGetBlock(params, id);
        } else if (std.mem.eql(u8, method, "getbestblockhash")) {
            return self.handleGetBestBlockHash(id);
        } else if (std.mem.eql(u8, method, "getpeerinfo")) {
            return self.handleGetPeerInfo(id);
        } else if (std.mem.eql(u8, method, "getnetworkinfo")) {
            return self.handleGetNetworkInfo(id);
        } else if (std.mem.eql(u8, method, "getmempoolinfo")) {
            return self.handleGetMempoolInfo(id);
        } else if (std.mem.eql(u8, method, "getmempoolentry")) {
            return self.handleGetMempoolEntry(params, id);
        } else if (std.mem.eql(u8, method, "sendrawtransaction")) {
            return self.handleSendRawTransaction(params, id);
        } else if (std.mem.eql(u8, method, "getrawtransaction")) {
            return self.handleGetRawTransaction(params, id);
        } else if (std.mem.eql(u8, method, "getblocktemplate")) {
            return self.handleGetBlockTemplate(params, id);
        } else if (std.mem.eql(u8, method, "submitblock")) {
            return self.handleSubmitBlock(params, id);
        } else if (std.mem.eql(u8, method, "getdifficulty")) {
            return self.handleGetDifficulty(id);
        } else if (std.mem.eql(u8, method, "listbanned")) {
            return self.handleListBanned(id);
        } else if (std.mem.eql(u8, method, "setban")) {
            return self.handleSetBan(params, id);
        } else if (std.mem.eql(u8, method, "clearbanned")) {
            return self.handleClearBanned(id);
        } else if (std.mem.eql(u8, method, "stop")) {
            self.stop();
            return self.jsonRpcResult("\"clearbit stopping\"", id);
        }
        // Wallet RPC methods
        else if (std.mem.eql(u8, method, "encryptwallet")) {
            return self.handleEncryptWallet(params, id);
        } else if (std.mem.eql(u8, method, "walletpassphrase")) {
            return self.handleWalletPassphrase(params, id);
        } else if (std.mem.eql(u8, method, "walletlock")) {
            return self.handleWalletLock(id);
        } else if (std.mem.eql(u8, method, "walletpassphrasechange")) {
            return self.handleWalletPassphraseChange(params, id);
        } else if (std.mem.eql(u8, method, "setlabel")) {
            return self.handleSetLabel(params, id);
        } else if (std.mem.eql(u8, method, "getaddressinfo")) {
            return self.handleGetAddressInfo(params, id);
        } else if (std.mem.eql(u8, method, "getwalletinfo")) {
            return self.handleGetWalletInfo(id);
        } else {
            return self.jsonRpcError(RPC_METHOD_NOT_FOUND, "Method not found", id);
        }
    }

    /// Maximum batch size (matching Bitcoin Core).
    pub const MAX_BATCH_SIZE: usize = 1000;

    /// Handle batch requests.
    fn handleBatch(self: *RpcServer, requests: []std.json.Value) ![]const u8 {
        // Empty batch is an error (per JSON-RPC spec)
        if (requests.len == 0) {
            return self.jsonRpcError(RPC_INVALID_REQUEST, "Empty batch request", null);
        }

        // Limit batch size to prevent DoS
        if (requests.len > MAX_BATCH_SIZE) {
            return self.jsonRpcError(RPC_INVALID_REQUEST, "Batch too large (max 1000)", null);
        }

        var responses = std.ArrayList(u8).init(self.allocator);
        errdefer responses.deinit();

        try responses.append('[');

        for (requests, 0..) |req, i| {
            if (i > 0) try responses.append(',');

            if (req != .object) {
                const err_resp = try self.jsonRpcError(RPC_INVALID_REQUEST, "Invalid Request", null);
                defer self.allocator.free(err_resp);
                try responses.appendSlice(err_resp);
            } else {
                const resp = try self.handleSingleRequest(req.object);
                defer self.allocator.free(resp);
                try responses.appendSlice(resp);
            }
        }

        try responses.append(']');
        return responses.toOwnedSlice();
    }

    // ========================================================================
    // Blockchain Info Methods
    // ========================================================================

    fn handleGetBlockchainInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        const chain_name = switch (self.network_params.magic) {
            consensus.MAINNET.magic => "main",
            consensus.TESTNET.magic => "test",
            consensus.REGTEST.magic => "regtest",
            else => "unknown",
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"chain\":\"{s}\",\"blocks\":{d},\"headers\":{d},\"bestblockhash\":\"", .{
            chain_name,
            self.chain_state.best_height,
            self.chain_state.best_height,
        });
        try writeHashHex(writer, &self.chain_state.best_hash);
        try writer.print("\",\"difficulty\":{d},\"verificationprogress\":1.0,\"pruned\":false}}", .{
            getDifficulty(self.network_params.genesis_header.bits),
        });

        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetBlockCount(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf: [32]u8 = undefined;
        const result = std.fmt.bufPrint(&buf, "{d}", .{self.chain_state.best_height}) catch return error.OutOfMemory;
        return self.jsonRpcResult(result, id);
    }

    fn handleGetBestBlockHash(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('"');
        try writeHashHex(writer, &self.chain_state.best_hash);
        try writer.writeByte('"');

        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetBlockHash(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract height parameter
        const height = blk: {
            if (params == .array and params.array.items.len > 0) {
                const h = params.array.items[0];
                if (h == .integer) break :blk @as(u32, @intCast(h.integer));
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid height parameter", id);
        };

        // Height 0 always returns genesis hash
        if (height == 0) {
            var buf = std.ArrayList(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();

            try writer.writeByte('"');
            try writeHashHex(writer, &self.network_params.genesis_hash);
            try writer.writeByte('"');

            return self.jsonRpcResult(buf.items, id);
        }

        // For now, we only know the best block hash
        // A full implementation would look up the block index
        if (height == self.chain_state.best_height) {
            var buf = std.ArrayList(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();

            try writer.writeByte('"');
            try writeHashHex(writer, &self.chain_state.best_hash);
            try writer.writeByte('"');

            return self.jsonRpcResult(buf.items, id);
        }

        return self.jsonRpcError(RPC_INVALID_PARAMETER, "Block height out of range", id);
    }

    fn handleGetBlock(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract blockhash and verbosity
        var blockhash_hex: []const u8 = undefined;
        var verbosity: i64 = 1; // Default

        if (params == .array) {
            if (params.array.items.len > 0) {
                const h = params.array.items[0];
                if (h == .string) {
                    blockhash_hex = h.string;
                } else {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash", id);
                }
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing blockhash", id);
            }

            if (params.array.items.len > 1) {
                const v = params.array.items[1];
                if (v == .integer) {
                    verbosity = v.integer;
                } else if (v == .bool) {
                    verbosity = if (v.bool) 1 else 0;
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid params", id);
        }

        // Parse blockhash
        if (blockhash_hex.len != 64) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash length", id);
        }

        var blockhash: types.Hash256 = undefined;
        for (0..32) |i| {
            blockhash[31 - i] = std.fmt.parseInt(u8, blockhash_hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash hex", id);
            };
        }

        // For now, we can only return info about genesis or best block
        // A full implementation would look up the block from storage
        const is_genesis = std.mem.eql(u8, &blockhash, &self.network_params.genesis_hash);
        const is_best = std.mem.eql(u8, &blockhash, &self.chain_state.best_hash);

        if (!is_genesis and !is_best) {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id);
        }

        const header = if (is_genesis) self.network_params.genesis_header else self.network_params.genesis_header;
        const height: u32 = if (is_genesis) 0 else self.chain_state.best_height;

        if (verbosity == 0) {
            // Return raw hex-encoded block
            // For simplicity, just return header hex for now
            var buf = std.ArrayList(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();

            try writer.writeByte('"');
            try writeBlockHeaderHex(writer, &header);
            // A full implementation would append transaction data here
            try writer.writeByte('"');

            return self.jsonRpcResult(buf.items, id);
        }

        // Verbosity 1 or 2: return JSON
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"hash\":\"", .{});
        try writeHashHex(writer, &blockhash);
        try writer.print("\",\"confirmations\":{d},\"height\":{d},\"version\":{d},\"merkleroot\":\"", .{
            self.chain_state.best_height - height + 1,
            height,
            header.version,
        });
        try writeHashHex(writer, &header.merkle_root);
        try writer.print("\",\"time\":{d},\"nonce\":{d},\"bits\":\"{x:0>8}\",\"difficulty\":{d},\"previousblockhash\":\"", .{
            header.timestamp,
            header.nonce,
            header.bits,
            getDifficulty(header.bits),
        });
        try writeHashHex(writer, &header.prev_block);
        try writer.print("\",\"nTx\":1,\"tx\":[", .{});

        // For verbosity 1, just list txids
        // For verbosity 2, include full tx details
        // Using placeholder for genesis coinbase
        if (verbosity >= 2) {
            // Full tx details would go here
            try writer.print("{{\"txid\":\"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b\"}}", .{});
        } else {
            try writer.print("\"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b\"", .{});
        }

        try writer.print("]}}", .{});

        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetDifficulty(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf: [64]u8 = undefined;
        const result = std.fmt.bufPrint(&buf, "{d}", .{getDifficulty(self.network_params.genesis_header.bits)}) catch return error.OutOfMemory;
        return self.jsonRpcResult(result, id);
    }

    // ========================================================================
    // Network Info Methods
    // ========================================================================

    fn handleGetPeerInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');

        for (self.peer_manager.peers.items, 0..) |peer, i| {
            if (i > 0) try writer.writeByte(',');

            var addr_buf: [64]u8 = undefined;
            const addr_str = peer.getAddressString(&addr_buf);

            try writer.print("{{\"id\":{d},\"addr\":\"{s}\",\"version\":{d},\"subver\":\"{s}\",\"inbound\":{},\"startingheight\":{d},\"synced_headers\":{d},\"synced_blocks\":{d}}}", .{
                i,
                addr_str,
                if (peer.version_info) |v| v.version else 0,
                if (peer.version_info) |v| v.user_agent else "",
                peer.direction == .inbound,
                peer.start_height,
                self.chain_state.best_height,
                self.chain_state.best_height,
            });
        }

        try writer.writeByte(']');
        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetNetworkInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"version\":10000,\"subversion\":\"/clearbit:0.1.0/\",\"protocolversion\":70016,\"connections\":{d},\"networks\":[{{\"name\":\"ipv4\",\"limited\":false,\"reachable\":true}}],\"relayfee\":0.00001,\"localaddresses\":[]}}", .{
            self.peer_manager.peers.items.len,
        });

        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetMempoolInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        const mempool_stats = self.mempool.stats();

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"loaded\":true,\"size\":{d},\"bytes\":{d},\"usage\":{d},\"maxmempool\":{d},\"mempoolminfee\":0.00001}}", .{
            mempool_stats.count,
            mempool_stats.size,
            mempool_stats.size,
            mempool_mod.MAX_MEMPOOL_SIZE,
        });

        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetMempoolEntry(self: *RpcServer, params: ?std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Parse txid from params
        const txid_hex = blk: {
            if (params) |p| {
                if (p == .array and p.array.items.len > 0) {
                    if (p.array.items[0] == .string) {
                        break :blk p.array.items[0].string;
                    }
                }
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing txid parameter", id);
        };

        if (txid_hex.len != 64) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid length", id);
        }

        var txid: types.Hash256 = undefined;
        for (0..32) |i| {
            const high = std.fmt.charToDigit(txid_hex[i * 2], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid hex", id);
            };
            const low = std.fmt.charToDigit(txid_hex[i * 2 + 1], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid hex", id);
            };
            // Bitcoin txids are displayed in reverse byte order
            txid[31 - i] = (high << 4) | low;
        }

        const entry = self.mempool.get(txid) orelse {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool", id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        // Compute BIP125 replaceability: with full RBF, all transactions are replaceable
        // However, we still track if the tx signals RBF for the bip125-replaceable field
        const bip125_replaceable = true; // Full RBF: all mempool txs are replaceable

        try writer.print("{{\"vsize\":{d},\"weight\":{d},\"fee\":{d}.{d:0>8},\"modifiedfee\":{d}.{d:0>8},\"time\":{d},\"height\":{d},\"descendantcount\":{d},\"descendantsize\":{d},\"descendantfees\":{d},\"ancestorcount\":{d},\"ancestorsize\":{d},\"ancestorfees\":{d},\"wtxid\":\"", .{
            entry.vsize,
            entry.weight,
            @divTrunc(entry.fee, 100_000_000),
            @as(u64, @intCast(@mod(entry.fee, 100_000_000))),
            @divTrunc(entry.fee, 100_000_000),
            @as(u64, @intCast(@mod(entry.fee, 100_000_000))),
            entry.time_added,
            entry.height_added,
            entry.descendant_count,
            entry.descendant_size,
            entry.descendant_fees,
            entry.ancestor_count,
            entry.ancestor_size,
            entry.ancestor_fees,
        });

        // Write wtxid in reverse byte order
        for (0..32) |i| {
            try writer.print("{x:0>2}", .{entry.wtxid[31 - i]});
        }

        try writer.print("\",\"depends\":[],\"spentby\":[],\"bip125-replaceable\":{s}}}", .{
            if (bip125_replaceable) "true" else "false",
        });

        return self.jsonRpcResult(buf.items, id);
    }

    // ========================================================================
    // Ban Management Methods
    // ========================================================================

    fn handleListBanned(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');

        var ban_list = self.peer_manager.getBanList();
        var iter = ban_list.iterator();
        var first = true;
        while (iter.next()) |entry| {
            // Skip expired entries
            const now = std.time.timestamp();
            if (now >= entry.value_ptr.ban_until) continue;

            if (!first) try writer.writeByte(',');
            first = false;

            const ip = entry.value_ptr.ip;
            try writer.print("{{\"address\":\"{d}.{d}.{d}.{d}\",\"ban_created\":{d},\"banned_until\":{d},\"ban_reason\":\"", .{
                ip[0], ip[1], ip[2], ip[3],
                entry.value_ptr.create_time,
                entry.value_ptr.ban_until,
            });
            // Escape the reason string
            for (entry.value_ptr.reason) |c| {
                if (c == '"') {
                    try writer.writeAll("\\\"");
                } else if (c == '\\') {
                    try writer.writeAll("\\\\");
                } else {
                    try writer.writeByte(c);
                }
            }
            try writer.writeAll("\"}");
        }

        try writer.writeByte(']');
        return self.jsonRpcResult(buf.items, id);
    }

    fn handleSetBan(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // setban "ip" "add|remove" [bantime] [absolute]
        if (params != .array or params.array.items.len < 2) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "setban requires ip and command", id);
        }

        const ip_str = blk: {
            const item = params.array.items[0];
            if (item == .string) break :blk item.string;
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid IP address", id);
        };

        const command = blk: {
            const item = params.array.items[1];
            if (item == .string) break :blk item.string;
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid command", id);
        };

        // Parse IP address
        var ip_parts: [4]u8 = undefined;
        var part_iter = std.mem.splitSequence(u8, ip_str, ".");
        var i: usize = 0;
        while (part_iter.next()) |part| : (i += 1) {
            if (i >= 4) break;
            ip_parts[i] = std.fmt.parseInt(u8, part, 10) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid IP address format", id);
            };
        }
        if (i != 4) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid IP address format", id);
        }

        const address = std.net.Address.initIp4(ip_parts, 0);

        if (std.mem.eql(u8, command, "add")) {
            // Get optional ban time (default 24 hours)
            var ban_time: i64 = banlist.DEFAULT_BAN_DURATION;
            if (params.array.items.len >= 3) {
                const bt = params.array.items[2];
                if (bt == .integer) {
                    ban_time = bt.integer;
                }
            }

            self.peer_manager.banIP(address, ban_time, "manual ban via RPC") catch {
                return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to add ban", id);
            };

            return self.jsonRpcResult("null", id);
        } else if (std.mem.eql(u8, command, "remove")) {
            if (!self.peer_manager.unbanIP(address)) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "IP not found in ban list", id);
            }
            return self.jsonRpcResult("null", id);
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid command (use add or remove)", id);
        }
    }

    fn handleClearBanned(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        self.peer_manager.getBanList().clearAll();
        return self.jsonRpcResult("null", id);
    }

    // ========================================================================
    // Wallet Methods
    // ========================================================================

    /// Check if wallet is available
    fn requireWallet(self: *RpcServer, id: ?std.json.Value) ?[]const u8 {
        if (self.wallet == null) {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id) catch null;
        }
        return null;
    }

    /// encryptwallet "passphrase"
    /// Encrypts the wallet with a passphrase. This is for first time encryption.
    fn handleEncryptWallet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.wallet.?;

        // Extract passphrase parameter
        const passphrase = blk: {
            if (params == .array and params.array.items.len > 0) {
                const p = params.array.items[0];
                if (p == .string) break :blk p.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing passphrase", id);
        };

        // Check if already encrypted
        if (wallet.encrypted) {
            return self.jsonRpcError(RPC_WALLET_WRONG_ENC_STATE, "Wallet is already encrypted", id);
        }

        // Encrypt the wallet
        wallet.encryptWallet(passphrase) catch |err| {
            return self.jsonRpcError(RPC_WALLET_ENCRYPTION_FAILED, @errorName(err), id);
        };

        return self.jsonRpcResult("\"Wallet encrypted; restart required\"", id);
    }

    /// walletpassphrase "passphrase" timeout
    /// Unlocks the wallet for timeout seconds.
    fn handleWalletPassphrase(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.wallet.?;

        // Extract passphrase and timeout
        var passphrase: []const u8 = undefined;
        var timeout: u32 = 60; // default 60 seconds

        if (params == .array and params.array.items.len >= 1) {
            const p = params.array.items[0];
            if (p == .string) {
                passphrase = p.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid passphrase", id);
            }

            if (params.array.items.len >= 2) {
                const t = params.array.items[1];
                if (t == .integer and t.integer > 0) {
                    timeout = @intCast(t.integer);
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing passphrase", id);
        }

        // Check if wallet is encrypted
        if (!wallet.encrypted) {
            return self.jsonRpcError(RPC_WALLET_WRONG_ENC_STATE, "Wallet is not encrypted", id);
        }

        // Unlock the wallet
        wallet.unlockWallet(passphrase, timeout) catch |err| {
            if (err == error.WrongPassphrase) {
                return self.jsonRpcError(RPC_WALLET_PASSPHRASE_INCORRECT, "The wallet passphrase entered was incorrect", id);
            }
            return self.jsonRpcError(RPC_WALLET_ERROR, @errorName(err), id);
        };

        return self.jsonRpcResult("null", id);
    }

    /// walletlock
    /// Locks the wallet.
    fn handleWalletLock(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.wallet.?;

        if (!wallet.encrypted) {
            return self.jsonRpcError(RPC_WALLET_WRONG_ENC_STATE, "Wallet is not encrypted", id);
        }

        wallet.lockWallet();
        return self.jsonRpcResult("null", id);
    }

    /// walletpassphrasechange "oldpassphrase" "newpassphrase"
    /// Changes the wallet passphrase.
    fn handleWalletPassphraseChange(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.wallet.?;

        // Extract old and new passphrases
        var old_passphrase: []const u8 = undefined;
        var new_passphrase: []const u8 = undefined;

        if (params == .array and params.array.items.len >= 2) {
            const old = params.array.items[0];
            const new = params.array.items[1];
            if (old == .string and new == .string) {
                old_passphrase = old.string;
                new_passphrase = new.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid passphrase parameters", id);
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing passphrase parameters", id);
        }

        if (!wallet.encrypted) {
            return self.jsonRpcError(RPC_WALLET_WRONG_ENC_STATE, "Wallet is not encrypted", id);
        }

        wallet.changePassphrase(old_passphrase, new_passphrase) catch |err| {
            if (err == error.WrongPassphrase) {
                return self.jsonRpcError(RPC_WALLET_PASSPHRASE_INCORRECT, "The wallet passphrase entered was incorrect", id);
            }
            return self.jsonRpcError(RPC_WALLET_ERROR, @errorName(err), id);
        };

        return self.jsonRpcResult("null", id);
    }

    /// setlabel "address" "label"
    /// Sets the label associated with the given address.
    fn handleSetLabel(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.wallet.?;

        // Extract address and label
        var addr: []const u8 = undefined;
        var label: []const u8 = "";

        if (params == .array and params.array.items.len >= 1) {
            const a = params.array.items[0];
            if (a == .string) {
                addr = a.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid address", id);
            }

            if (params.array.items.len >= 2) {
                const l = params.array.items[1];
                if (l == .string) {
                    label = l.string;
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing address", id);
        }

        wallet.setLabel(addr, label) catch {
            return self.jsonRpcError(RPC_WALLET_ERROR, "Failed to set label", id);
        };

        return self.jsonRpcResult("null", id);
    }

    /// getaddressinfo "address"
    /// Returns information about the given address.
    fn handleGetAddressInfo(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.wallet.?;

        // Extract address
        const addr = blk: {
            if (params == .array and params.array.items.len > 0) {
                const a = params.array.items[0];
                if (a == .string) break :blk a.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing address", id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"address\":\"{s}\"", .{addr});

        // Add label if exists
        if (wallet.getLabel(addr)) |label| {
            try writer.print(",\"label\":\"{s}\"", .{label});
        }

        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    /// getwalletinfo
    /// Returns information about the wallet.
    fn handleGetWalletInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.wallet.?;

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        const balance = wallet.getBalance();
        const spendable = wallet.getSpendableBalance();
        const immature = wallet.getImmatureBalance();
        const unlocked = wallet.isUnlocked();

        try writer.print("{{\"balance\":{d}.{d:0>8},\"unconfirmed_balance\":0.0,\"immature_balance\":{d}.{d:0>8}", .{
            @divTrunc(balance, 100_000_000),
            @abs(@rem(balance, 100_000_000)),
            @divTrunc(immature, 100_000_000),
            @abs(@rem(immature, 100_000_000)),
        });

        try writer.print(",\"txcount\":{d}", .{wallet.keys.items.len});
        try writer.print(",\"keypoolsize\":{d}", .{wallet.keys.items.len});

        if (wallet.encrypted) {
            try writer.writeAll(",\"unlocked_until\":");
            if (wallet.unlock_until) |until| {
                try writer.print("{d}", .{until});
            } else {
                try writer.writeByte('0');
            }
        }

        _ = spendable;
        _ = unlocked;

        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    // ========================================================================
    // Transaction Methods
    // ========================================================================

    /// Default max fee rate: 0.10 BTC/kvB = 10,000,000 satoshis per 1000 vbytes
    /// This matches Bitcoin Core's DEFAULT_MAX_RAW_TX_FEE_RATE
    const DEFAULT_MAX_FEERATE: i64 = 10_000_000;

    fn handleSendRawTransaction(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract hex-encoded raw transaction
        var hex: []const u8 = undefined;
        var max_feerate: i64 = DEFAULT_MAX_FEERATE; // satoshis per 1000 vbytes

        if (params == .array and params.array.items.len > 0) {
            const h = params.array.items[0];
            if (h == .string) {
                hex = h.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid hex string", id);
            }

            // Parse optional maxfeerate parameter (BTC/kvB)
            if (params.array.items.len > 1) {
                const feerate_param = params.array.items[1];
                if (feerate_param == .float) {
                    // Convert BTC/kvB to satoshis/kvB
                    const btc_per_kvb = feerate_param.float;
                    max_feerate = @intFromFloat(btc_per_kvb * 100_000_000.0);
                } else if (feerate_param == .integer) {
                    // Assume already in satoshis/kvB
                    max_feerate = feerate_param.integer;
                } else if (feerate_param == .string) {
                    // Parse string as float (BTC/kvB)
                    const btc_per_kvb = std.fmt.parseFloat(f64, feerate_param.string) catch {
                        return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid maxfeerate", id);
                    };
                    max_feerate = @intFromFloat(btc_per_kvb * 100_000_000.0);
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing hex string", id);
        }

        // Decode hex to bytes
        if (hex.len % 2 != 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex length", id);
        }

        if (hex.len == 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.", id);
        }

        const raw = self.allocator.alloc(u8, hex.len / 2) catch {
            return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
        };
        defer self.allocator.free(raw);

        for (0..raw.len) |i| {
            raw[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex character", id);
            };
        }

        // Deserialize transaction
        var reader = serialize.Reader{ .data = raw };
        const tx = serialize.readTransaction(&reader, self.allocator) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.", id);
        };
        defer {
            // Free transaction memory if we don't add it to mempool
            // (mempool takes ownership on success)
        }

        // Basic validation: tx must have at least one input and output
        if (tx.inputs.len == 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.", id);
        }
        if (tx.outputs.len == 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Transaction has no outputs.", id);
        }

        // Compute txid
        const txid = crypto.computeTxid(&tx, self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to compute txid", id);
        };

        // Check if transaction is already in mempool - return txid (not an error)
        if (self.mempool.contains(txid)) {
            // Transaction already in mempool, re-announce and return txid
            return self.returnTxidAndBroadcast(txid, id);
        }

        // Check if transaction is already confirmed (outputs exist in UTXO set)
        // Bitcoin Core checks if any output of this tx exists in the UTXO set
        const is_confirmed = self.isTransactionConfirmed(&txid, &tx);
        if (is_confirmed) {
            return self.jsonRpcError(RPC_VERIFY_ALREADY_IN_CHAIN, "Transaction already in block chain", id);
        }

        // Compute transaction weight and vsize for fee rate validation
        const weight = mempool_mod.computeTxWeight(&tx, self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to compute tx weight", id);
        };
        const vsize = (weight + 3) / 4;

        // Compute fee by looking up input values (if chain state available)
        var fee: i64 = 0;
        var have_fee = false;
        if (self.chain_state.utxo_set.db != null or self.mempool.chain_state != null) {
            var total_in: i64 = 0;
            var inputs_found = true;

            for (tx.inputs) |input| {
                // Check mempool first
                if (self.mempool.getOutputFromMempool(&input.previous_output)) |output| {
                    total_in += output.value;
                } else {
                    // Check UTXO set
                    const utxo = self.chain_state.utxo_set.get(&input.previous_output) catch null;
                    if (utxo) |u| {
                        var mut_u = u;
                        defer mut_u.deinit(self.allocator);
                        total_in += u.value;
                    } else {
                        inputs_found = false;
                        break;
                    }
                }
            }

            if (inputs_found) {
                var total_out: i64 = 0;
                for (tx.outputs) |output| {
                    total_out += output.value;
                }
                fee = total_in - total_out;
                have_fee = true;

                // Validate fee rate against maxfeerate (if fee is positive and maxfeerate > 0)
                if (fee > 0 and max_feerate > 0 and vsize > 0) {
                    // fee_rate = fee / vsize, compare to max_feerate / 1000
                    // Equivalent: fee * 1000 > max_feerate * vsize
                    const fee_rate_check = @as(i128, fee) * 1000;
                    const max_fee_check = @as(i128, max_feerate) * @as(i128, @intCast(vsize));
                    if (fee_rate_check > max_fee_check) {
                        return self.jsonRpcError(RPC_VERIFY_REJECTED, "Fee exceeds maximum configured by user (maxfeerate)", id);
                    }
                }
            }
        }

        // Add to mempool
        self.mempool.addTransaction(tx) catch |err| {
            return switch (err) {
                mempool_mod.MempoolError.AlreadyInMempool => {
                    // Should have been caught above, but handle anyway
                    return self.returnTxidAndBroadcast(txid, id);
                },
                mempool_mod.MempoolError.InsufficientFee => self.jsonRpcError(RPC_VERIFY_REJECTED, "min relay fee not met", id),
                mempool_mod.MempoolError.DustOutput => self.jsonRpcError(RPC_VERIFY_REJECTED, "dust output", id),
                mempool_mod.MempoolError.NonStandard => self.jsonRpcError(RPC_VERIFY_REJECTED, "non-standard transaction", id),
                mempool_mod.MempoolError.MissingInputs => self.jsonRpcError(RPC_VERIFY_REJECTED, "missing inputs", id),
                mempool_mod.MempoolError.TooManyAncestors => self.jsonRpcError(RPC_VERIFY_REJECTED, "too many unconfirmed ancestors", id),
                mempool_mod.MempoolError.TooManyDescendants => self.jsonRpcError(RPC_VERIFY_REJECTED, "too many unconfirmed descendants", id),
                mempool_mod.MempoolError.AncestorSizeLimitExceeded => self.jsonRpcError(RPC_VERIFY_REJECTED, "ancestor size limit exceeded", id),
                mempool_mod.MempoolError.DescendantSizeLimitExceeded => self.jsonRpcError(RPC_VERIFY_REJECTED, "descendant size limit exceeded", id),
                mempool_mod.MempoolError.NonBIP125Replaceable => self.jsonRpcError(RPC_VERIFY_REJECTED, "txn-mempool-conflict", id),
                mempool_mod.MempoolError.ReplacementFeeTooLow => self.jsonRpcError(RPC_VERIFY_REJECTED, "insufficient fee for replacement", id),
                mempool_mod.MempoolError.TooManyEvictions => self.jsonRpcError(RPC_VERIFY_REJECTED, "too many potential replacements", id),
                mempool_mod.MempoolError.MempoolFull => self.jsonRpcError(RPC_VERIFY_REJECTED, "mempool full", id),
                mempool_mod.MempoolError.ConflictsWithMempool => self.jsonRpcError(RPC_VERIFY_REJECTED, "txn-mempool-conflict", id),
                mempool_mod.MempoolError.TxValidationFailed => self.jsonRpcError(RPC_VERIFY_REJECTED, "transaction validation failed", id),
                mempool_mod.MempoolError.OutOfMemory => self.jsonRpcError(RPC_OUT_OF_MEMORY, "out of memory", id),
            };
        };

        // Transaction accepted - broadcast inv to peers and return txid
        return self.returnTxidAndBroadcast(txid, id);
    }

    /// Check if a transaction is already confirmed in the blockchain.
    /// Following Bitcoin Core's approach: check if any output of this tx exists in UTXO set.
    fn isTransactionConfirmed(self: *RpcServer, txid: *const types.Hash256, tx: *const types.Transaction) bool {
        // Check each output index - if any exists in UTXO set, tx is confirmed
        for (0..tx.outputs.len) |i| {
            const outpoint = types.OutPoint{
                .hash = txid.*,
                .index = @intCast(i),
            };
            const exists = self.chain_state.utxo_set.contains(&outpoint) catch false;
            if (exists) return true;
        }
        return false;
    }

    /// Return txid as JSON result and queue inv relay to peers.
    fn returnTxidAndBroadcast(self: *RpcServer, txid: types.Hash256, id: ?std.json.Value) ![]const u8 {
        // Queue inv message to all connected peers
        self.broadcastTxInv(&txid);

        // Return txid as hex string
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('"');
        try writeHashHex(writer, &txid);
        try writer.writeByte('"');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Broadcast transaction inv to all connected peers.
    fn broadcastTxInv(self: *RpcServer, txid: *const types.Hash256) void {
        // Create inv message with MSG_WITNESS_TX type (for SegWit-aware peers)
        const inv_item = p2p.InvVector{
            .inv_type = .msg_witness_tx,
            .hash = txid.*,
        };

        // Allocate inventory array on stack
        const inventory = [_]p2p.InvVector{inv_item};

        const inv_msg = p2p.Message{
            .inv = p2p.InvMessage{ .inventory = &inventory },
        };

        // Broadcast to all connected peers
        self.peer_manager.broadcast(&inv_msg);
    }

    fn handleGetRawTransaction(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract txid and verbose flag
        var txid_hex: []const u8 = undefined;
        var verbose: bool = false;

        if (params == .array) {
            if (params.array.items.len > 0) {
                const h = params.array.items[0];
                if (h == .string) {
                    txid_hex = h.string;
                } else {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid", id);
                }
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing txid", id);
            }

            if (params.array.items.len > 1) {
                const v = params.array.items[1];
                if (v == .bool) {
                    verbose = v.bool;
                } else if (v == .integer) {
                    verbose = v.integer != 0;
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid params", id);
        }

        // Parse txid
        if (txid_hex.len != 64) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid length", id);
        }

        var txid: types.Hash256 = undefined;
        for (0..32) |i| {
            txid[31 - i] = std.fmt.parseInt(u8, txid_hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid hex", id);
            };
        }

        // Check mempool first
        if (self.mempool.get(txid)) |entry| {
            var buf = std.ArrayList(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();

            if (verbose) {
                try writer.print("{{\"txid\":\"", .{});
                try writeHashHex(writer, &entry.txid);
                try writer.print("\",\"size\":{d},\"vsize\":{d},\"weight\":{d},\"version\":{d},\"locktime\":{d}}}", .{
                    entry.size,
                    entry.vsize,
                    entry.weight,
                    entry.tx.version,
                    entry.tx.lock_time,
                });
            } else {
                // Return raw hex
                var tx_writer = serialize.Writer.init(self.allocator);
                defer tx_writer.deinit();
                serialize.writeTransaction(&tx_writer, &entry.tx) catch {
                    return self.jsonRpcError(RPC_INTERNAL_ERROR, "Serialization failed", id);
                };
                const tx_bytes = tx_writer.getWritten();

                try writer.writeByte('"');
                for (tx_bytes) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                try writer.writeByte('"');
            }

            return self.jsonRpcResult(buf.items, id);
        }

        // TODO: Check block storage for confirmed transactions
        return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "No such mempool or blockchain transaction", id);
    }

    // ========================================================================
    // Mining Methods
    // ========================================================================

    fn handleGetBlockTemplate(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        _ = params; // Template request params (capabilities, rules) - not fully implemented

        // Create block template
        const payout_script = [_]u8{ 0x6a }; // OP_RETURN (placeholder)
        var template = block_template.createBlockTemplate(
            self.chain_state,
            self.mempool,
            self.network_params,
            .{
                .payout_script = &payout_script,
                .include_witness_commitment = true,
            },
            self.allocator,
        ) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to create block template", id);
        };
        defer template.deinit();

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        // Format BIP-22/23 response
        try writer.print("{{\"capabilities\":[\"proposal\"],\"version\":{d},\"previousblockhash\":\"", .{
            template.header.version,
        });
        try writeHashHex(writer, &template.header.prev_block);
        try writer.print("\",\"transactions\":[", .{});

        for (template.transactions.items, 0..) |tx, i| {
            if (i > 0) try writer.writeByte(',');

            // Serialize transaction to hex
            var tx_writer = serialize.Writer.init(self.allocator);
            defer tx_writer.deinit();
            serialize.writeTransaction(&tx_writer, &tx.tx) catch continue;
            const tx_bytes = tx_writer.getWritten();

            try writer.print("{{\"data\":\"", .{});
            for (tx_bytes) |byte| {
                try writer.print("{x:0>2}", .{byte});
            }
            try writer.print("\",\"txid\":\"", .{});
            try writeHashHex(writer, &tx.txid);
            try writer.print("\",\"fee\":{d},\"weight\":{d}}}", .{
                tx.fee,
                tx.weight,
            });
        }

        try writer.print("],\"coinbasevalue\":{d},\"target\":\"", .{
            template.getBlockReward(self.network_params),
        });

        // Write target as hex (big-endian display)
        for (0..32) |i| {
            try writer.print("{x:0>2}", .{template.target[31 - i]});
        }

        try writer.print("\",\"mintime\":{d},\"curtime\":{d},\"bits\":\"{x:0>8}\",\"height\":{d},\"mutable\":[\"time\",\"transactions\",\"prevblock\"]}}", .{
            template.header.timestamp,
            template.header.timestamp,
            template.header.bits,
            template.height,
        });

        return self.jsonRpcResult(buf.items, id);
    }

    fn handleSubmitBlock(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract hex-encoded block
        var hex: []const u8 = undefined;

        if (params == .array and params.array.items.len > 0) {
            const h = params.array.items[0];
            if (h == .string) {
                hex = h.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid hex string", id);
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing hex string", id);
        }

        // Decode hex to bytes
        if (hex.len % 2 != 0 or hex.len < 160) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid block hex", id);
        }

        const raw = self.allocator.alloc(u8, hex.len / 2) catch {
            return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
        };
        defer self.allocator.free(raw);

        for (0..raw.len) |i| {
            raw[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex", id);
            };
        }

        // Deserialize block
        var reader = serialize.Reader{ .data = raw };
        const block_data = serialize.readBlock(&reader, self.allocator) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Block decode failed", id);
        };

        // Submit block
        const result = block_template.submitBlock(&block_data, self.chain_state, self.network_params, self.allocator) catch {
            return self.jsonRpcError(RPC_VERIFY_ERROR, "Block verification failed", id);
        };

        if (result.accepted) {
            // Success - return null (Bitcoin Core convention)
            return self.jsonRpcResult("null", id);
        } else {
            // Rejection
            return self.jsonRpcError(RPC_VERIFY_REJECTED, result.reject_reason orelse "Block rejected", id);
        }
    }

    // ========================================================================
    // JSON-RPC Response Helpers
    // ========================================================================

    /// Create a JSON-RPC success response.
    pub fn jsonRpcResult(self: *RpcServer, result: []const u8, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"result\":{s},\"error\":null,\"id\":", .{result});
        try writeJsonValue(writer, id);
        try writer.writeByte('}');

        return buf.toOwnedSlice();
    }

    /// Create a JSON-RPC error response.
    pub fn jsonRpcError(self: *RpcServer, code: i32, message: []const u8, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"result\":null,\"error\":{{\"code\":{d},\"message\":\"{s}\"}},\"id\":", .{ code, message });
        try writeJsonValue(writer, id);
        try writer.writeByte('}');

        return buf.toOwnedSlice();
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Find an HTTP header value by name.
fn findHeader(headers: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            const colon_idx = std.mem.indexOf(u8, line, ":") orelse continue;
            var value = line[colon_idx + 1 ..];
            // Trim leading whitespace
            while (value.len > 0 and value[0] == ' ') {
                value = value[1..];
            }
            return value;
        }
    }
    return null;
}

/// Write a hash as hex in reverse byte order (big-endian display).
fn writeHashHex(writer: anytype, hash: *const types.Hash256) !void {
    for (0..32) |i| {
        try writer.print("{x:0>2}", .{hash[31 - i]});
    }
}

/// Write a block header as hex.
fn writeBlockHeaderHex(writer: anytype, header: *const types.BlockHeader) !void {
    // version (4 bytes LE)
    try writer.print("{x:0>8}", .{@byteSwap(@as(u32, @bitCast(header.version)))});
    // prev_block (32 bytes)
    for (header.prev_block) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
    // merkle_root (32 bytes)
    for (header.merkle_root) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
    // timestamp (4 bytes LE)
    try writer.print("{x:0>8}", .{@byteSwap(header.timestamp)});
    // bits (4 bytes LE)
    try writer.print("{x:0>8}", .{@byteSwap(header.bits)});
    // nonce (4 bytes LE)
    try writer.print("{x:0>8}", .{@byteSwap(header.nonce)});
}

/// Write a JSON value.
fn writeJsonValue(writer: anytype, value: ?std.json.Value) !void {
    if (value == null) {
        try writer.writeAll("null");
        return;
    }

    switch (value.?) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |i| try writer.print("{d}", .{i}),
        .float => |f| try writer.print("{d}", .{f}),
        .string => |s| {
            try writer.writeByte('"');
            try writer.writeAll(s);
            try writer.writeByte('"');
        },
        .number_string => |s| try writer.writeAll(s),
        .array => try writer.writeAll("[]"),
        .object => try writer.writeAll("{}"),
    }
}

/// Calculate difficulty from compact bits representation.
fn getDifficulty(bits: u32) f64 {
    const exponent: u32 = (bits >> 24) & 0xFF;
    const mantissa: u32 = bits & 0x007FFFFF;

    if (mantissa == 0) return 0;

    // difficulty_1_target = 0x00000000FFFF... (at exponent 0x1d)
    // difficulty = difficulty_1_target / current_target
    const shift: i32 = @as(i32, 0x1d) - @as(i32, @intCast(exponent));

    var diff: f64 = @as(f64, @floatFromInt(@as(u32, 0x00FFFF))) / @as(f64, @floatFromInt(mantissa));

    if (shift > 0) {
        diff *= std.math.pow(f64, 256.0, @as(f64, @floatFromInt(shift)));
    } else if (shift < 0) {
        diff /= std.math.pow(f64, 256.0, @as(f64, @floatFromInt(-shift)));
    }

    return diff;
}

// ============================================================================
// Tests
// ============================================================================

test "JSON-RPC result formatting" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const result = try server.jsonRpcResult("123", null);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"result\":123") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"error\":null") != null);
}

test "JSON-RPC error formatting" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const result = try server.jsonRpcError(RPC_METHOD_NOT_FOUND, "Method not found", null);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"result\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"code\":-32601") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"message\":\"Method not found\"") != null);
}

test "dispatch method not found" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"nonexistent\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "-32601") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Method not found") != null);
}

test "dispatch parse error" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "not valid json";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "-32700") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Parse error") != null);
}

test "getblockchaininfo returns correct height and hash" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    // Set some chain state
    chain_state.best_height = 100;
    chain_state.best_hash = [_]u8{0xAB} ** 32;

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should contain correct height
    try std.testing.expect(std.mem.indexOf(u8, result, "\"blocks\":100") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"chain\":\"main\"") != null);
}

test "getblockcount returns height" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 500000;

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "{\"id\":1,\"method\":\"getblockcount\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"result\":500000") != null);
}

test "getblockhash with height 0 returns genesis" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "{\"id\":1,\"method\":\"getblockhash\",\"params\":[0]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should contain genesis hash (reversed for display)
    try std.testing.expect(std.mem.indexOf(u8, result, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") != null);
}

test "getmempoolinfo returns stats" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "{\"id\":1,\"method\":\"getmempoolinfo\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"loaded\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"size\":0") != null);
}

test "sendrawtransaction rejects invalid hex" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"invalid\"]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should return deserialization error
    try std.testing.expect(std.mem.indexOf(u8, result, "-22") != null or
        std.mem.indexOf(u8, result, "error") != null);
}

test "batch request handling" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "[{\"id\":1,\"method\":\"getblockcount\",\"params\":[]},{\"id\":2,\"method\":\"getdifficulty\",\"params\":[]}]";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should be an array response
    try std.testing.expect(result[0] == '[');
    try std.testing.expect(result[result.len - 1] == ']');
}

test "batch request empty array returns error" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    const request = "[]";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should return error for empty batch
    try std.testing.expect(std.mem.indexOf(u8, result, "error") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Empty batch") != null);
}

test "batch request with mixed success and failure" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    // One valid method, one invalid
    const request = "[{\"id\":1,\"method\":\"getblockcount\",\"params\":[]},{\"id\":2,\"method\":\"nonexistent_method\",\"params\":[]}]";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should be array response
    try std.testing.expect(result[0] == '[');
    // Should contain both a result and an error
    try std.testing.expect(std.mem.indexOf(u8, result, "\"result\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Method not found") != null);
}

test "batch request with invalid element type" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    // Array with non-object element
    const request = "[{\"id\":1,\"method\":\"getblockcount\",\"params\":[]},\"not_an_object\"]";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should be array response with error for invalid element
    try std.testing.expect(result[0] == '[');
    try std.testing.expect(std.mem.indexOf(u8, result, "Invalid Request") != null);
}

test "batch request preserves request order" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    // Multiple requests with different IDs
    const request = "[{\"id\":\"first\",\"method\":\"getblockcount\",\"params\":[]},{\"id\":\"second\",\"method\":\"getdifficulty\",\"params\":[]}]";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Verify order by checking that "first" appears before "second"
    const first_pos = std.mem.indexOf(u8, result, "\"first\"").?;
    const second_pos = std.mem.indexOf(u8, result, "\"second\"").?;
    try std.testing.expect(first_pos < second_pos);
}

test "findHeader extracts header value" {
    const headers = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n";

    const content_type = findHeader(headers, "Content-Type");
    try std.testing.expect(content_type != null);
    try std.testing.expectEqualStrings("application/json", content_type.?);

    const content_length = findHeader(headers, "Content-Length");
    try std.testing.expect(content_length != null);
    try std.testing.expectEqualStrings("100", content_length.?);

    const missing = findHeader(headers, "X-Custom");
    try std.testing.expect(missing == null);
}

test "getDifficulty calculation" {
    // Difficulty 1 target
    const diff1 = getDifficulty(0x1d00ffff);
    try std.testing.expect(diff1 >= 0.99 and diff1 <= 1.01);

    // Regtest minimum difficulty
    const regtest_diff = getDifficulty(0x207fffff);
    try std.testing.expect(regtest_diff > 0);
}

test "writeHashHex produces correct output" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    const hash = [_]u8{ 0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00 };

    try writeHashHex(buf.writer(), &hash);

    // Should be reversed (big-endian display)
    try std.testing.expectEqualStrings("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", buf.items);
}

test "RPC error codes" {
    try std.testing.expectEqual(@as(i32, -32600), RPC_INVALID_REQUEST);
    try std.testing.expectEqual(@as(i32, -32601), RPC_METHOD_NOT_FOUND);
    try std.testing.expectEqual(@as(i32, -32602), RPC_INVALID_PARAMS);
    try std.testing.expectEqual(@as(i32, -32603), RPC_INTERNAL_ERROR);
    try std.testing.expectEqual(@as(i32, -32700), RPC_PARSE_ERROR);
    try std.testing.expectEqual(@as(i32, -25), RPC_VERIFY_ERROR);
    try std.testing.expectEqual(@as(i32, -26), RPC_VERIFY_REJECTED);
    try std.testing.expectEqual(@as(i32, -27), RPC_VERIFY_ALREADY_IN_CHAIN);
}

test "sendrawtransaction rejects odd-length hex string" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    // Odd-length hex string
    const request = "{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"abc\"]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should return deserialization error for invalid hex length
    try std.testing.expect(std.mem.indexOf(u8, result, "-22") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Invalid hex length") != null);
}

test "sendrawtransaction rejects empty hex string" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    // Empty hex string
    const request = "{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"\"]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should return deserialization error
    try std.testing.expect(std.mem.indexOf(u8, result, "-22") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "TX decode failed") != null);
}

test "sendrawtransaction rejects missing params" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    // Missing params
    const request = "{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should return invalid params error
    try std.testing.expect(std.mem.indexOf(u8, result, "-32602") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Missing hex string") != null);
}

test "sendrawtransaction default maxfeerate constant" {
    // Verify DEFAULT_MAX_FEERATE matches Bitcoin Core's 0.10 BTC/kvB
    // 0.10 BTC = 10_000_000 satoshis per 1000 vbytes
    try std.testing.expectEqual(@as(i64, 10_000_000), RpcServer.DEFAULT_MAX_FEERATE);
}

test "sendrawtransaction with non-string hex param" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.MAINNET,
        .{},
    );
    defer server.deinit();

    // Numeric instead of string
    const request = "{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[12345]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Should return invalid params error
    try std.testing.expect(std.mem.indexOf(u8, result, "-32602") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Invalid hex string") != null);
}
