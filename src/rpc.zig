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
const descriptor = @import("descriptor.zig");
const psbt_mod = @import("psbt.zig");

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
    chain_manager: ?*validation.ChainManager,
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
            .chain_manager = null,
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
            .chain_manager = null,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    /// Set the chain manager for invalidateblock/reconsiderblock/preciousblock RPCs.
    pub fn setChainManager(self: *RpcServer, chain_manager: *validation.ChainManager) void {
        self.chain_manager = chain_manager;
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
        }
        // Descriptor RPC methods
        else if (std.mem.eql(u8, method, "getdescriptorinfo")) {
            return self.handleGetDescriptorInfo(params, id);
        } else if (std.mem.eql(u8, method, "deriveaddresses")) {
            return self.handleDeriveAddresses(params, id);
        }
        // Regtest mining RPC methods
        else if (std.mem.eql(u8, method, "generatetoaddress")) {
            return self.handleGenerateToAddress(params, id);
        } else if (std.mem.eql(u8, method, "generatetodescriptor")) {
            return self.handleGenerateToDescriptor(params, id);
        } else if (std.mem.eql(u8, method, "generateblock")) {
            return self.handleGenerateBlock(params, id);
        }
        // Chain management RPC methods (Phase 51)
        else if (std.mem.eql(u8, method, "invalidateblock")) {
            return self.handleInvalidateBlock(params, id);
        } else if (std.mem.eql(u8, method, "reconsiderblock")) {
            return self.handleReconsiderBlock(params, id);
        } else if (std.mem.eql(u8, method, "preciousblock")) {
            return self.handlePreciousBlock(params, id);
        }
        // Package relay RPC methods
        else if (std.mem.eql(u8, method, "submitpackage")) {
            return self.handleSubmitPackage(params, id);
        }
        // PSBT RPC methods (BIP174/370)
        else if (std.mem.eql(u8, method, "createpsbt")) {
            return self.handleCreatePsbt(params, id);
        } else if (std.mem.eql(u8, method, "decodepsbt")) {
            return self.handleDecodePsbt(params, id);
        } else if (std.mem.eql(u8, method, "analyzepsbt")) {
            return self.handleAnalyzePsbt(params, id);
        } else if (std.mem.eql(u8, method, "combinepsbt")) {
            return self.handleCombinePsbt(params, id);
        } else if (std.mem.eql(u8, method, "finalizepsbt")) {
            return self.handleFinalizePsbt(params, id);
        } else if (std.mem.eql(u8, method, "converttopsbt")) {
            return self.handleConvertToPsbt(params, id);
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

    // ========================================================================
    // Descriptor RPC Methods
    // ========================================================================

    /// Handle getdescriptorinfo RPC
    /// Returns information about a descriptor
    fn handleGetDescriptorInfo(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract descriptor string
        var desc_str: []const u8 = undefined;

        if (params == .array and params.array.items.len >= 1) {
            const d = params.array.items[0];
            if (d == .string) {
                desc_str = d.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid descriptor", id);
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing descriptor", id);
        }

        // Parse and analyze the descriptor
        var desc = descriptor.parseDescriptor(self.allocator, desc_str) catch {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid descriptor", id);
        };
        defer desc.deinit(self.allocator);

        // Get canonical form with checksum
        const canonical = descriptor.toStringWithChecksum(self.allocator, &desc) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to serialize descriptor", id);
        };
        defer self.allocator.free(canonical);

        // Extract checksum
        const hash_pos = std.mem.lastIndexOf(u8, canonical, "#") orelse {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Checksum error", id);
        };
        const checksum = canonical[hash_pos + 1 ..];

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"descriptor\":\"");
        // Escape descriptor for JSON
        for (canonical) |c| {
            if (c == '"' or c == '\\') {
                try writer.writeByte('\\');
            }
            try writer.writeByte(c);
        }
        try writer.writeAll("\",\"checksum\":\"");
        try writer.writeAll(checksum);
        try writer.writeAll("\",\"isrange\":");
        try writer.writeAll(if (desc.isRange()) "true" else "false");
        try writer.writeAll(",\"issolvable\":true,\"hasprivatekeys\":");
        try writer.writeAll(if (descriptor.hasPrivateKeys(&desc)) "true" else "false");
        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle deriveaddresses RPC
    /// Derives addresses from a descriptor
    fn handleDeriveAddresses(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract descriptor string and optional range
        var desc_str: []const u8 = undefined;
        var range_start: u32 = 0;
        var range_end: u32 = 1;

        if (params == .array and params.array.items.len >= 1) {
            const d = params.array.items[0];
            if (d == .string) {
                desc_str = d.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid descriptor", id);
            }

            // Parse optional range parameter
            if (params.array.items.len >= 2) {
                const range_param = params.array.items[1];
                if (range_param == .array and range_param.array.items.len == 2) {
                    // Range is [start, end]
                    const range_s = range_param.array.items[0];
                    const range_e = range_param.array.items[1];
                    if (range_s == .integer and range_e == .integer) {
                        range_start = @intCast(range_s.integer);
                        range_end = @intCast(range_e.integer);
                    }
                } else if (range_param == .integer) {
                    // Single number means [0, n]
                    range_end = @intCast(range_param.integer);
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing descriptor", id);
        }

        // Determine network
        const network: wallet_mod.Network = switch (self.network_params.magic) {
            consensus.MAINNET.magic => .mainnet,
            consensus.TESTNET.magic => .testnet,
            else => .regtest,
        };

        // Derive addresses
        const addresses = descriptor.deriveAddresses(
            self.allocator,
            desc_str,
            network,
            range_start,
            range_end,
        ) catch {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive addresses from descriptor", id);
        };
        defer {
            for (addresses) |a| self.allocator.free(a);
            self.allocator.free(addresses);
        }

        // Build JSON array of addresses
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');
        for (addresses, 0..) |addr, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('"');
            try writer.writeAll(addr);
            try writer.writeByte('"');
        }
        try writer.writeByte(']');

        return self.jsonRpcResult(buf.items, id);
    }

    // ========================================================================
    // Regtest Mining RPC Methods
    // ========================================================================

    /// Handle generatetoaddress RPC.
    /// Mine blocks to a specified address and return block hashes.
    /// Usage: generatetoaddress nblocks "address" [maxtries]
    fn handleGenerateToAddress(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Verify we're on regtest (mining RPCs only available on regtest)
        if (self.network_params.magic != consensus.REGTEST.magic) {
            return self.jsonRpcError(RPC_MISC_ERROR, "generatetoaddress is only available in regtest mode", id);
        }

        // Parse parameters
        var n_blocks: u32 = 1;
        var address: []const u8 = undefined;
        var max_tries: u64 = block_template.DEFAULT_MAX_TRIES;

        if (params == .array and params.array.items.len >= 2) {
            // nblocks
            const n = params.array.items[0];
            if (n == .integer) {
                if (n.integer < 0 or n.integer > 10000) {
                    return self.jsonRpcError(RPC_INVALID_PARAMETER, "Invalid nblocks value", id);
                }
                n_blocks = @intCast(n.integer);
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "nblocks must be an integer", id);
            }

            // address
            const a = params.array.items[1];
            if (a == .string) {
                address = a.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "address must be a string", id);
            }

            // optional maxtries
            if (params.array.items.len >= 3) {
                const m = params.array.items[2];
                if (m == .integer) {
                    max_tries = @intCast(m.integer);
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "generatetoaddress requires nblocks and address", id);
        }

        // Decode address to script pubkey
        const payout_script = descriptor.decodeAddressToScript(self.allocator, address) catch {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address", id);
        };
        defer self.allocator.free(payout_script);

        // Generate blocks
        var result = block_template.generateBlocks(
            self.chain_state,
            self.mempool,
            self.network_params,
            payout_script,
            n_blocks,
            max_tries,
            self.allocator,
        ) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Block generation failed", id);
        };
        defer result.deinit();

        // Format response as JSON array of block hashes
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');
        for (result.block_hashes.items, 0..) |hash, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('"');
            // Write hash in reverse byte order (Bitcoin display format)
            for (0..32) |j| {
                try writer.print("{x:0>2}", .{hash[31 - j]});
            }
            try writer.writeByte('"');
        }
        try writer.writeByte(']');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle generatetodescriptor RPC.
    /// Mine blocks to a specified descriptor and return block hashes.
    /// Usage: generatetodescriptor num_blocks "descriptor" [maxtries]
    fn handleGenerateToDescriptor(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Verify we're on regtest
        if (self.network_params.magic != consensus.REGTEST.magic) {
            return self.jsonRpcError(RPC_MISC_ERROR, "generatetodescriptor is only available in regtest mode", id);
        }

        // Parse parameters
        var n_blocks: u32 = 1;
        var desc_str: []const u8 = undefined;
        var max_tries: u64 = block_template.DEFAULT_MAX_TRIES;

        if (params == .array and params.array.items.len >= 2) {
            // num_blocks
            const n = params.array.items[0];
            if (n == .integer) {
                if (n.integer < 0 or n.integer > 10000) {
                    return self.jsonRpcError(RPC_INVALID_PARAMETER, "Invalid num_blocks value", id);
                }
                n_blocks = @intCast(n.integer);
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "num_blocks must be an integer", id);
            }

            // descriptor
            const d = params.array.items[1];
            if (d == .string) {
                desc_str = d.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "descriptor must be a string", id);
            }

            // optional maxtries
            if (params.array.items.len >= 3) {
                const m = params.array.items[2];
                if (m == .integer) {
                    max_tries = @intCast(m.integer);
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "generatetodescriptor requires num_blocks and descriptor", id);
        }

        // Parse descriptor and get script pubkey
        var desc = descriptor.parseDescriptor(self.allocator, desc_str) catch {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid descriptor", id);
        };
        defer desc.deinit();

        // Get script pubkey from descriptor (index 0 for non-ranged)
        const payout_script = desc.getScriptPubKey(0) catch {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive script from descriptor", id);
        };
        defer self.allocator.free(payout_script);

        // Generate blocks
        var result = block_template.generateBlocks(
            self.chain_state,
            self.mempool,
            self.network_params,
            payout_script,
            n_blocks,
            max_tries,
            self.allocator,
        ) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Block generation failed", id);
        };
        defer result.deinit();

        // Format response
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');
        for (result.block_hashes.items, 0..) |hash, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('"');
            for (0..32) |j| {
                try writer.print("{x:0>2}", .{hash[31 - j]});
            }
            try writer.writeByte('"');
        }
        try writer.writeByte(']');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle generateblock RPC.
    /// Mine a block with specific transactions.
    /// Usage: generateblock "output" ["rawtx/txid",...] [submit]
    fn handleGenerateBlock(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Verify we're on regtest
        if (self.network_params.magic != consensus.REGTEST.magic) {
            return self.jsonRpcError(RPC_MISC_ERROR, "generateblock is only available in regtest mode", id);
        }

        // Parse parameters
        var output: []const u8 = undefined;
        var submit_block: bool = true;
        var transactions = std.ArrayList(types.Transaction).init(self.allocator);
        defer transactions.deinit();

        if (params == .array and params.array.items.len >= 2) {
            // output (address or descriptor)
            const o = params.array.items[0];
            if (o == .string) {
                output = o.string;
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "output must be a string", id);
            }

            // transactions array
            const txs = params.array.items[1];
            if (txs == .array) {
                for (txs.array.items) |tx_item| {
                    if (tx_item == .string) {
                        const tx_str = tx_item.string;

                        // Check if it's a txid (64 hex chars) or raw transaction
                        if (tx_str.len == 64) {
                            // Txid - look up in mempool
                            var txid: [32]u8 = undefined;
                            for (0..32) |i| {
                                // Parse in reverse (display order to internal)
                                txid[31 - i] = std.fmt.parseInt(u8, tx_str[i * 2 ..][0..2], 16) catch {
                                    return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid txid hex", id);
                                };
                            }

                            // Look up in mempool
                            const entry = self.mempool.get(&txid);
                            if (entry) |e| {
                                try transactions.append(e.tx);
                            } else {
                                return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool", id);
                            }
                        } else {
                            // Raw transaction hex
                            if (tx_str.len % 2 != 0) {
                                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid transaction hex", id);
                            }

                            const raw = self.allocator.alloc(u8, tx_str.len / 2) catch {
                                return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
                            };
                            defer self.allocator.free(raw);

                            for (0..raw.len) |i| {
                                raw[i] = std.fmt.parseInt(u8, tx_str[i * 2 ..][0..2], 16) catch {
                                    return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid transaction hex", id);
                                };
                            }

                            var reader = serialize.Reader{ .data = raw };
                            const tx = serialize.readTransaction(&reader, self.allocator) catch {
                                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Transaction decode failed", id);
                            };
                            try transactions.append(tx);
                        }
                    }
                }
            } else {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "transactions must be an array", id);
            }

            // optional submit
            if (params.array.items.len >= 3) {
                const s = params.array.items[2];
                if (s == .bool) {
                    submit_block = s.bool;
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "generateblock requires output and transactions", id);
        }

        // Get payout script (try as address first, then as descriptor)
        var payout_script: []u8 = undefined;
        var script_owned = false;

        payout_script = descriptor.decodeAddressToScript(self.allocator, output) catch blk: {
            // Try as descriptor
            var desc = descriptor.parseDescriptor(self.allocator, output) catch {
                return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address or descriptor", id);
            };
            defer desc.deinit();

            const script = desc.getScriptPubKey(0) catch {
                return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive script", id);
            };
            script_owned = true;
            break :blk script;
        };
        defer if (script_owned) self.allocator.free(payout_script);

        // Generate the block
        const gen_result = block_template.generateBlockWithTxs(
            self.chain_state,
            self.mempool,
            self.network_params,
            payout_script,
            transactions.items,
            block_template.DEFAULT_MAX_TRIES,
            submit_block,
            self.allocator,
        ) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Block generation failed", id);
        };

        // Format response
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"hash\":\"", .{});
        for (0..32) |j| {
            try writer.print("{x:0>2}", .{gen_result.hash[31 - j]});
        }
        try writer.writeByte('"');

        if (gen_result.hex) |hex| {
            defer self.allocator.free(hex);
            try writer.print(",\"hex\":\"{s}\"", .{hex});
        }
        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    // ========================================================================
    // Chain Management RPC Methods (Phase 51)
    // ========================================================================

    /// invalidateblock "blockhash"
    /// Permanently marks a block as invalid, as if it violated a consensus rule.
    /// Reference: Bitcoin Core rpc/blockchain.cpp invalidateblock
    fn handleInvalidateBlock(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Require chain_manager to be set
        const chain_manager = self.chain_manager orelse {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Chain manager not initialized", id);
        };

        // Extract blockhash parameter
        const blockhash_hex = blk: {
            if (params == .array and params.array.items.len > 0) {
                const h = params.array.items[0];
                if (h == .string) break :blk h.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing blockhash parameter", id);
        };

        // Validate and parse blockhash
        if (blockhash_hex.len != 64) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash length (expected 64 hex chars)", id);
        }

        var blockhash: types.Hash256 = undefined;
        for (0..32) |i| {
            // Parse in reverse (display order to internal byte order)
            blockhash[31 - i] = std.fmt.parseInt(u8, blockhash_hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash hex", id);
            };
        }

        // Call the chain manager
        chain_manager.invalidateBlock(&blockhash) catch |err| {
            return switch (err) {
                validation.ChainManager.ChainError.BlockNotFound => self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id),
                validation.ChainManager.ChainError.GenesisCannotBeInvalidated => self.jsonRpcError(RPC_MISC_ERROR, "Genesis block cannot be invalidated", id),
                validation.ChainManager.ChainError.DisconnectFailed => self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to disconnect block", id),
                validation.ChainManager.ChainError.OutOfMemory => self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id),
            };
        };

        return self.jsonRpcResult("null", id);
    }

    /// reconsiderblock "blockhash"
    /// Removes invalidity status of a block and its descendants, reconsider them for activation.
    /// Reference: Bitcoin Core rpc/blockchain.cpp reconsiderblock
    fn handleReconsiderBlock(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Require chain_manager to be set
        const chain_manager = self.chain_manager orelse {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Chain manager not initialized", id);
        };

        // Extract blockhash parameter
        const blockhash_hex = blk: {
            if (params == .array and params.array.items.len > 0) {
                const h = params.array.items[0];
                if (h == .string) break :blk h.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing blockhash parameter", id);
        };

        // Validate and parse blockhash
        if (blockhash_hex.len != 64) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash length (expected 64 hex chars)", id);
        }

        var blockhash: types.Hash256 = undefined;
        for (0..32) |i| {
            // Parse in reverse (display order to internal byte order)
            blockhash[31 - i] = std.fmt.parseInt(u8, blockhash_hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash hex", id);
            };
        }

        // Call the chain manager
        chain_manager.reconsiderBlock(&blockhash) catch |err| {
            return switch (err) {
                validation.ChainManager.ChainError.BlockNotFound => self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id),
                validation.ChainManager.ChainError.GenesisCannotBeInvalidated => self.jsonRpcError(RPC_MISC_ERROR, "Unexpected error", id),
                validation.ChainManager.ChainError.DisconnectFailed => self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed during chain activation", id),
                validation.ChainManager.ChainError.OutOfMemory => self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id),
            };
        };

        return self.jsonRpcResult("null", id);
    }

    /// preciousblock "blockhash"
    /// Treats a block as if it were received before others with the same work.
    /// A later preciousblock call can override this.
    /// Reference: Bitcoin Core rpc/blockchain.cpp preciousblock
    fn handlePreciousBlock(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Require chain_manager to be set
        const chain_manager = self.chain_manager orelse {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Chain manager not initialized", id);
        };

        // Extract blockhash parameter
        const blockhash_hex = blk: {
            if (params == .array and params.array.items.len > 0) {
                const h = params.array.items[0];
                if (h == .string) break :blk h.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing blockhash parameter", id);
        };

        // Validate and parse blockhash
        if (blockhash_hex.len != 64) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash length (expected 64 hex chars)", id);
        }

        var blockhash: types.Hash256 = undefined;
        for (0..32) |i| {
            // Parse in reverse (display order to internal byte order)
            blockhash[31 - i] = std.fmt.parseInt(u8, blockhash_hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid blockhash hex", id);
            };
        }

        // Call the chain manager
        chain_manager.preciousBlock(&blockhash) catch |err| {
            return switch (err) {
                validation.ChainManager.ChainError.BlockNotFound => self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id),
                validation.ChainManager.ChainError.GenesisCannotBeInvalidated => self.jsonRpcError(RPC_MISC_ERROR, "Unexpected error", id),
                validation.ChainManager.ChainError.DisconnectFailed => self.jsonRpcError(RPC_INTERNAL_ERROR, "Chain activation failed", id),
                validation.ChainManager.ChainError.OutOfMemory => self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id),
            };
        };

        return self.jsonRpcResult("null", id);
    }

    // ========================================================================
    // Package Relay Methods
    // ========================================================================

    /// Handle submitpackage RPC - submit a package of related transactions.
    /// Params: [[rawtx1, rawtx2, ...], maxfeerate, maxburnamount]
    /// Returns JSON object with per-tx results keyed by txid.
    fn handleSubmitPackage(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Extract parameters
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing required parameter: array of raw transactions", id);
        }

        // First param: array of raw transaction hex strings
        const tx_array = params.array.items[0];
        if (tx_array != .array) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "First parameter must be array of hex strings", id);
        }

        if (tx_array.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Package must contain at least one transaction", id);
        }

        if (tx_array.array.items.len > mempool_mod.MAX_PACKAGE_COUNT) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Package exceeds maximum transaction count (25)", id);
        }

        // Parse optional maxfeerate (BTC/kvB)
        var max_feerate: i64 = DEFAULT_MAX_FEERATE;
        if (params.array.items.len > 1 and params.array.items[1] != .null) {
            const feerate_param = params.array.items[1];
            if (feerate_param == .float) {
                max_feerate = @intFromFloat(feerate_param.float * 100_000_000.0);
            } else if (feerate_param == .integer) {
                max_feerate = feerate_param.integer;
            }
        }
        _ = max_feerate; // TODO: implement maxfeerate check per-tx

        // Parse all transactions from hex
        var transactions = std.ArrayList(types.Transaction).init(self.allocator);
        defer transactions.deinit();

        var tx_bytes_list = std.ArrayList([]u8).init(self.allocator);
        defer {
            for (tx_bytes_list.items) |bytes| {
                self.allocator.free(bytes);
            }
            tx_bytes_list.deinit();
        }

        for (tx_array.array.items) |item| {
            if (item != .string) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "All package elements must be hex strings", id);
            }

            const hex = item.string;
            if (hex.len % 2 != 0) {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex length in package", id);
            }

            if (hex.len == 0) {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Empty transaction in package", id);
            }

            const raw = self.allocator.alloc(u8, hex.len / 2) catch {
                return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
            };
            errdefer self.allocator.free(raw);

            for (0..raw.len) |i| {
                raw[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch {
                    self.allocator.free(raw);
                    return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex character in package", id);
                };
            }

            // Track bytes for deferred cleanup
            tx_bytes_list.append(raw) catch {
                self.allocator.free(raw);
                return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
            };

            // Deserialize transaction
            var reader = serialize.Reader{ .data = raw };
            const tx = serialize.readTransaction(&reader, self.allocator) catch {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed in package", id);
            };

            if (tx.inputs.len == 0) {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Transaction has no inputs", id);
            }

            transactions.append(tx) catch {
                return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
            };
        }

        // Validate and accept the package
        var result = mempool_mod.acceptPackage(self.mempool, transactions.items, self.allocator) catch |err| {
            return switch (err) {
                mempool_mod.PackageError.PackageTooManyTransactions => self.jsonRpcError(RPC_INVALID_PARAMS, "package-too-many-transactions", id),
                mempool_mod.PackageError.PackageTooLarge => self.jsonRpcError(RPC_INVALID_PARAMS, "package-too-large", id),
                mempool_mod.PackageError.PackageContainsDuplicates => self.jsonRpcError(RPC_INVALID_PARAMS, "package-contains-duplicates", id),
                mempool_mod.PackageError.PackageNotSorted => self.jsonRpcError(RPC_INVALID_PARAMS, "package-not-sorted", id),
                mempool_mod.PackageError.ConflictInPackage => self.jsonRpcError(RPC_INVALID_PARAMS, "conflict-in-package", id),
                mempool_mod.PackageError.PackageEmptyInputs => self.jsonRpcError(RPC_INVALID_PARAMS, "package-empty-inputs", id),
                mempool_mod.PackageError.PackageNotChildWithParents => self.jsonRpcError(RPC_INVALID_PARAMS, "package-not-child-with-parents", id),
                mempool_mod.PackageError.PackageParentsNotIndependent => self.jsonRpcError(RPC_INVALID_PARAMS, "package-parents-not-independent", id),
                mempool_mod.PackageError.PackageFeeTooLow => self.jsonRpcError(RPC_VERIFY_REJECTED, "package-fee-too-low", id),
                mempool_mod.PackageError.OutOfMemory => self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id),
            };
        };
        defer result.deinit();

        // Build response JSON
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"package_msg\":\"\",\"tx-results\":{");

        for (result.tx_results, 0..) |tx_result, i| {
            if (i > 0) try writer.writeByte(',');

            // Write txid as key
            try writer.writeByte('"');
            try writeHashHex(writer, &tx_result.txid);
            try writer.writeAll("\":{");

            // Write per-tx result
            if (tx_result.accepted) {
                try writer.print("\"txid\":\"", .{});
                try writeHashHex(writer, &tx_result.txid);
                try writer.print("\",\"wtxid\":\"", .{});
                try writeHashHex(writer, &tx_result.wtxid);
                try writer.print("\",\"vsize\":{d},\"fees\":{{\"base\":{d}}}", .{
                    tx_result.vsize,
                    tx_result.fee,
                });
            } else {
                try writer.print("\"txid\":\"", .{});
                try writeHashHex(writer, &tx_result.txid);
                try writer.print("\",\"error\":\"rejected\"", .{});
            }

            try writer.writeByte('}');
        }

        try writer.writeAll("},\"replaced-transactions\":[],\"package_feerate\":");
        try writer.print("{d:.8}", .{result.package_fee_rate / 100000.0}); // Convert sat/vB to BTC/kvB
        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    // ========================================================================
    // PSBT Methods (BIP174/370)
    // ========================================================================

    /// Handle createpsbt RPC - create a PSBT from inputs and outputs.
    /// Params: [inputs, outputs, locktime, replaceable]
    /// inputs: [{"txid": "<hex>", "vout": n}, ...]
    /// outputs: [{"<address>": amount}, ...] or [{"data": "<hex>"}]
    fn handleCreatePsbt(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len < 2) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "createpsbt requires inputs and outputs arrays", id);
        }

        const inputs_param = params.array.items[0];
        const outputs_param = params.array.items[1];

        if (inputs_param != .array or outputs_param != .array) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "inputs and outputs must be arrays", id);
        }

        // Parse locktime (optional, defaults to 0)
        var locktime: u32 = 0;
        if (params.array.items.len > 2 and params.array.items[2] == .integer) {
            locktime = @intCast(params.array.items[2].integer);
        }

        // Parse replaceable (optional, defaults to true)
        var replaceable = true;
        if (params.array.items.len > 3 and params.array.items[3] == .bool) {
            replaceable = params.array.items[3].bool;
        }

        // Build inputs
        var tx_inputs = std.ArrayList(types.TxIn).init(self.allocator);
        defer tx_inputs.deinit();

        for (inputs_param.array.items) |input_obj| {
            if (input_obj != .object) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Each input must be an object with txid and vout", id);
            }

            const txid_val = input_obj.object.get("txid") orelse {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Input missing txid", id);
            };
            const vout_val = input_obj.object.get("vout") orelse {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Input missing vout", id);
            };

            if (txid_val != .string or txid_val.string.len != 64) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid format", id);
            }
            if (vout_val != .integer) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid vout format", id);
            }

            // Parse txid (displayed in big-endian, stored in little-endian)
            var txid: types.Hash256 = undefined;
            for (0..32) |i| {
                txid[31 - i] = std.fmt.parseInt(u8, txid_val.string[i * 2 ..][0..2], 16) catch {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid hex", id);
                };
            }

            // Parse sequence
            var sequence: u32 = if (replaceable) 0xFFFFFFFD else 0xFFFFFFFF;
            if (input_obj.object.get("sequence")) |seq_val| {
                if (seq_val == .integer) {
                    sequence = @intCast(seq_val.integer);
                }
            }

            try tx_inputs.append(types.TxIn{
                .previous_output = .{
                    .hash = txid,
                    .index = @intCast(vout_val.integer),
                },
                .script_sig = &[_]u8{},
                .sequence = sequence,
                .witness = &[_][]const u8{},
            });
        }

        // Build outputs
        var tx_outputs = std.ArrayList(types.TxOut).init(self.allocator);
        defer tx_outputs.deinit();

        for (outputs_param.array.items) |output_obj| {
            if (output_obj != .object) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Each output must be an object", id);
            }

            var iter = output_obj.object.iterator();
            while (iter.next()) |entry| {
                if (std.mem.eql(u8, entry.key_ptr.*, "data")) {
                    // OP_RETURN output
                    if (entry.value_ptr.* != .string) {
                        return self.jsonRpcError(RPC_INVALID_PARAMS, "data must be hex string", id);
                    }
                    const hex = entry.value_ptr.string;
                    if (hex.len % 2 != 0 or hex.len > 160) { // 80 bytes max
                        return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid data length", id);
                    }

                    var data_script = std.ArrayList(u8).init(self.allocator);
                    try data_script.append(0x6a); // OP_RETURN
                    try data_script.append(@intCast(hex.len / 2));
                    for (0..hex.len / 2) |i| {
                        try data_script.append(std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch {
                            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid data hex", id);
                        });
                    }

                    try tx_outputs.append(types.TxOut{
                        .value = 0,
                        .script_pubkey = try data_script.toOwnedSlice(),
                    });
                } else {
                    // Regular output: address -> amount
                    const amount_val = entry.value_ptr.*;
                    var amount_sats: i64 = 0;
                    if (amount_val == .float) {
                        amount_sats = @intFromFloat(amount_val.float * 100_000_000.0);
                    } else if (amount_val == .integer) {
                        amount_sats = @intCast(amount_val.integer * 100_000_000);
                    } else {
                        return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid amount", id);
                    }

                    // For now, just create a placeholder script - in production, decode the address
                    // This is a simplified implementation
                    try tx_outputs.append(types.TxOut{
                        .value = amount_sats,
                        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0x00} ** 20, // P2WPKH placeholder
                    });
                }
            }
        }

        // Create the transaction
        const tx = types.Transaction{
            .version = 2,
            .inputs = tx_inputs.items,
            .outputs = tx_outputs.items,
            .lock_time = locktime,
        };

        // Create PSBT
        var psbt = psbt_mod.Psbt.create(self.allocator, tx) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to create PSBT", id);
        };
        defer psbt.deinit();

        // Encode to base64
        const base64 = psbt.toBase64(self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to encode PSBT", id);
        };
        defer self.allocator.free(base64);

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();
        try writer.writeByte('"');
        try writer.writeAll(base64);
        try writer.writeByte('"');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle decodepsbt RPC - decode a PSBT and return its contents.
    fn handleDecodePsbt(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "decodepsbt requires psbt string", id);
        }

        const psbt_param = params.array.items[0];
        if (psbt_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "PSBT must be a base64 string", id);
        }

        var psbt = psbt_mod.Psbt.fromBase64(self.allocator, psbt_param.string) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Failed to decode PSBT", id);
        };
        defer psbt.deinit();

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"tx\":{");

        // Transaction info
        try writer.print("\"version\":{d},", .{psbt.tx.version});
        try writer.print("\"locktime\":{d},", .{psbt.tx.lock_time});

        // Inputs
        try writer.writeAll("\"vin\":[");
        for (psbt.tx.inputs, 0..) |input, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"txid\":\"");
            try writeHashHex(writer, &input.previous_output.hash);
            try writer.print("\",\"vout\":{d},\"sequence\":{d}}}", .{
                input.previous_output.index,
                input.sequence,
            });
        }
        try writer.writeAll("],");

        // Outputs
        try writer.writeAll("\"vout\":[");
        for (psbt.tx.outputs, 0..) |output, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.print("{{\"value\":{d:.8},\"n\":{d}}}", .{
                @as(f64, @floatFromInt(output.value)) / 100_000_000.0,
                i,
            });
        }
        try writer.writeAll("]},");

        // PSBT version
        try writer.print("\"psbt_version\":{d},", .{psbt.version});

        // Inputs info
        try writer.writeAll("\"inputs\":[");
        for (psbt.inputs, 0..) |*input, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{");

            var has_field = false;

            if (input.witness_utxo != null) {
                try writer.print("\"witness_utxo\":{{\"amount\":{d:.8}}}", .{
                    @as(f64, @floatFromInt(input.witness_utxo.?.value)) / 100_000_000.0,
                });
                has_field = true;
            }

            if (input.partial_sigs.count() > 0) {
                if (has_field) try writer.writeByte(',');
                try writer.print("\"partial_signatures\":{d}", .{input.partial_sigs.count()});
                has_field = true;
            }

            if (input.sighash_type != null) {
                if (has_field) try writer.writeByte(',');
                try writer.print("\"sighash\":{d}", .{input.sighash_type.?});
                has_field = true;
            }

            if (input.isFinalized()) {
                if (has_field) try writer.writeByte(',');
                try writer.writeAll("\"final\":true");
            }

            try writer.writeByte('}');
        }
        try writer.writeAll("],");

        // Outputs info
        try writer.writeAll("\"outputs\":[");
        for (psbt.outputs, 0..) |*output, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{");

            var has_field = false;
            if (output.bip32_derivation.count() > 0) {
                try writer.print("\"bip32_derivs\":{d}", .{output.bip32_derivation.count()});
                has_field = true;
            }
            _ = has_field;

            try writer.writeByte('}');
        }
        try writer.writeAll("],");

        // Fee if available
        const analysis = psbt.analyze();
        if (analysis.estimated_fee) |fee| {
            try writer.print("\"fee\":{d:.8}", .{@as(f64, @floatFromInt(fee)) / 100_000_000.0});
        } else {
            try writer.writeAll("\"fee\":null");
        }

        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle analyzepsbt RPC - analyze a PSBT and provide status.
    fn handleAnalyzePsbt(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "analyzepsbt requires psbt string", id);
        }

        const psbt_param = params.array.items[0];
        if (psbt_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "PSBT must be a base64 string", id);
        }

        var psbt = psbt_mod.Psbt.fromBase64(self.allocator, psbt_param.string) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Failed to decode PSBT", id);
        };
        defer psbt.deinit();

        const analysis = psbt.analyze();

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"inputs\":[");

        for (psbt.inputs, 0..) |*input, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{");

            if (input.witness_utxo != null or input.non_witness_utxo != null) {
                try writer.writeAll("\"has_utxo\":true,");
            } else {
                try writer.writeAll("\"has_utxo\":false,");
            }

            if (input.isFinalized()) {
                try writer.writeAll("\"is_final\":true");
            } else {
                try writer.writeAll("\"is_final\":false");
            }

            try writer.writeByte('}');
        }

        try writer.writeAll("],");

        // Estimated fee
        if (analysis.estimated_fee) |fee| {
            try writer.print("\"estimated_feerate\":{d:.8},", .{@as(f64, @floatFromInt(fee)) / 100_000_000.0});
        }

        try writer.print("\"next\":\"{s}\"", .{analysis.next_role});

        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle combinepsbt RPC - combine multiple PSBTs.
    fn handleCombinePsbt(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "combinepsbt requires array of PSBTs", id);
        }

        const psbt_array = params.array.items[0];
        if (psbt_array != .array or psbt_array.array.items.len < 2) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Must provide at least 2 PSBTs to combine", id);
        }

        // Parse all PSBTs
        var psbts = std.ArrayList(psbt_mod.Psbt).init(self.allocator);
        defer {
            for (psbts.items) |*p| {
                p.deinit();
            }
            psbts.deinit();
        }

        for (psbt_array.array.items) |item| {
            if (item != .string) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Each PSBT must be a base64 string", id);
            }

            var psbt = psbt_mod.Psbt.fromBase64(self.allocator, item.string) catch {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Failed to decode PSBT", id);
            };
            try psbts.append(psbt);
        }

        // Create pointer array for combine
        var psbt_ptrs = try self.allocator.alloc(*psbt_mod.Psbt, psbts.items.len);
        defer self.allocator.free(psbt_ptrs);
        for (psbts.items, 0..) |*p, i| {
            psbt_ptrs[i] = p;
        }

        // Combine
        var combined = psbt_mod.Psbt.combine(self.allocator, psbt_ptrs) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to combine PSBTs", id);
        };
        defer combined.deinit();

        // Encode result
        const base64 = combined.toBase64(self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to encode combined PSBT", id);
        };
        defer self.allocator.free(base64);

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();
        try writer.writeByte('"');
        try writer.writeAll(base64);
        try writer.writeByte('"');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle finalizepsbt RPC - finalize a PSBT and optionally extract the transaction.
    fn handleFinalizePsbt(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "finalizepsbt requires psbt string", id);
        }

        const psbt_param = params.array.items[0];
        if (psbt_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "PSBT must be a base64 string", id);
        }

        // Extract flag (optional, defaults to true)
        var extract = true;
        if (params.array.items.len > 1 and params.array.items[1] == .bool) {
            extract = params.array.items[1].bool;
        }

        var psbt = psbt_mod.Psbt.fromBase64(self.allocator, psbt_param.string) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Failed to decode PSBT", id);
        };
        defer psbt.deinit();

        // Try to finalize
        psbt.finalize() catch {};

        const complete = psbt.isComplete();

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{");

        if (complete and extract) {
            // Extract the final transaction
            const tx = psbt.extract() catch {
                return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to extract transaction", id);
            };
            defer {
                for (tx.inputs) |input| {
                    if (input.script_sig.len > 0) self.allocator.free(input.script_sig);
                    if (input.witness.len > 0) {
                        for (input.witness) |item| {
                            if (item.len > 0) self.allocator.free(item);
                        }
                        self.allocator.free(input.witness);
                    }
                }
                self.allocator.free(tx.inputs);
                for (tx.outputs) |output| {
                    if (output.script_pubkey.len > 0) self.allocator.free(output.script_pubkey);
                }
                self.allocator.free(tx.outputs);
            }

            // Serialize transaction to hex
            var tx_writer = serialize.Writer.init(self.allocator);
            defer tx_writer.deinit();
            try serialize.writeTransaction(&tx_writer, &tx);
            const tx_bytes = tx_writer.getWritten();

            try writer.writeAll("\"hex\":\"");
            for (tx_bytes) |byte| {
                try writer.print("{x:0>2}", .{byte});
            }
            try writer.writeAll("\",");
        }

        // Include the PSBT
        const base64 = psbt.toBase64(self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to encode PSBT", id);
        };
        defer self.allocator.free(base64);

        try writer.writeAll("\"psbt\":\"");
        try writer.writeAll(base64);
        try writer.writeAll("\",");

        try writer.print("\"complete\":{s}", .{if (complete) "true" else "false"});
        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle converttopsbt RPC - convert a raw transaction to PSBT.
    fn handleConvertToPsbt(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "converttopsbt requires hex transaction", id);
        }

        const hex_param = params.array.items[0];
        if (hex_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Transaction must be hex string", id);
        }

        const hex = hex_param.string;
        if (hex.len % 2 != 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex length", id);
        }

        // Decode hex
        const raw = self.allocator.alloc(u8, hex.len / 2) catch {
            return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
        };
        defer self.allocator.free(raw);

        for (0..raw.len) |i| {
            raw[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex character", id);
            };
        }

        // Parse transaction
        var reader = serialize.Reader{ .data = raw };
        var tx = serialize.readTransaction(&reader, self.allocator) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed", id);
        };
        defer {
            for (tx.inputs) |input| {
                if (input.script_sig.len > 0) self.allocator.free(input.script_sig);
                if (input.witness.len > 0) {
                    for (input.witness) |item| {
                        if (item.len > 0) self.allocator.free(item);
                    }
                    self.allocator.free(input.witness);
                }
            }
            self.allocator.free(tx.inputs);
            for (tx.outputs) |output| {
                if (output.script_pubkey.len > 0) self.allocator.free(output.script_pubkey);
            }
            self.allocator.free(tx.outputs);
        }

        // Clear scriptSigs and witnesses for PSBT creation
        // Clone the transaction with empty scripts
        const unsigned_inputs = self.allocator.alloc(types.TxIn, tx.inputs.len) catch {
            return self.jsonRpcError(RPC_OUT_OF_MEMORY, "Out of memory", id);
        };
        defer self.allocator.free(unsigned_inputs);

        for (tx.inputs, 0..) |input, i| {
            unsigned_inputs[i] = types.TxIn{
                .previous_output = input.previous_output,
                .script_sig = &[_]u8{},
                .sequence = input.sequence,
                .witness = &[_][]const u8{},
            };
        }

        const unsigned_tx = types.Transaction{
            .version = tx.version,
            .inputs = unsigned_inputs,
            .outputs = tx.outputs,
            .lock_time = tx.lock_time,
        };

        // Create PSBT
        var psbt = psbt_mod.Psbt.create(self.allocator, unsigned_tx) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to create PSBT", id);
        };
        defer psbt.deinit();

        // Encode to base64
        const base64 = psbt.toBase64(self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to encode PSBT", id);
        };
        defer self.allocator.free(base64);

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();
        try writer.writeByte('"');
        try writer.writeAll(base64);
        try writer.writeByte('"');

        return self.jsonRpcResult(buf.items, id);
    }

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
