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
const address_mod = @import("address.zig");
const script_mod = @import("script.zig");

// ============================================================================
// Hex Decoding Helper
// ============================================================================

/// Fast hex digit to integer conversion using a lookup table.
/// Returns null for invalid hex characters.
fn hexDigitToInt(ch: u8) ?u4 {
    return switch (ch) {
        '0'...'9' => @intCast(ch - '0'),
        'a'...'f' => @intCast(ch - 'a' + 10),
        'A'...'F' => @intCast(ch - 'A' + 10),
        else => null,
    };
}

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
    cookie_token: ?[]const u8 = null, // Base64-encoded "__cookie__:<hex>" from .cookie file
    max_request_size: usize = 1 << 24, // 16 MB (needed for submitblock with large blocks)
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
    wallet_manager: ?*wallet_mod.WalletManager,
    chain_manager: ?*validation.ChainManager,
    config: RpcConfig,
    running: std.atomic.Value(bool),

    // Per-request state (for wallet targeting)
    current_wallet: ?*wallet_mod.Wallet = null,

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
            .wallet_manager = null,
            .chain_manager = null,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .current_wallet = null,
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
            .wallet_manager = null,
            .chain_manager = null,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .current_wallet = null,
        };
    }

    /// Initialize the RPC server with a wallet manager (multi-wallet).
    pub fn initWithWalletManager(
        allocator: std.mem.Allocator,
        chain_state: *storage.ChainState,
        mempool: *mempool_mod.Mempool,
        peer_manager: *peer_mod.PeerManager,
        network_params: *const consensus.NetworkParams,
        wallet_manager: *wallet_mod.WalletManager,
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
            .wallet_manager = wallet_manager,
            .chain_manager = null,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .current_wallet = null,
        };
    }

    /// Set the chain manager for invalidateblock/reconsiderblock/preciousblock RPCs.
    pub fn setChainManager(self: *RpcServer, chain_manager: *validation.ChainManager) void {
        self.chain_manager = chain_manager;
    }

    /// Set the wallet manager for multi-wallet support.
    pub fn setWalletManager(self: *RpcServer, wallet_manager: *wallet_mod.WalletManager) void {
        self.wallet_manager = wallet_manager;
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

        // Parse HTTP method and URL path from request line
        const request_line_end = std.mem.indexOf(u8, headers, "\r\n") orelse headers.len;
        const request_line = headers[0..request_line_end];

        // Extract method
        const is_get = std.mem.startsWith(u8, request_line, "GET ");
        const is_post = std.mem.startsWith(u8, request_line, "POST ");

        // Extract path from request line
        var url_path: []const u8 = "/";
        if (std.mem.indexOf(u8, request_line, " ")) |path_start| {
            const path_content = request_line[path_start + 1 ..];
            if (std.mem.indexOf(u8, path_content, " ")) |path_end| {
                url_path = path_content[0..path_end];
            }
        }

        // Handle REST API requests (GET /rest/...)
        if (is_get and std.mem.startsWith(u8, url_path, "/rest/")) {
            self.handleRestRequest(conn.stream, url_path) catch {
                try self.sendHttpError(conn.stream, 500, "Internal Server Error");
            };
            return;
        }

        // For non-REST requests, require POST method
        if (!is_post) {
            try self.sendHttpError(conn.stream, 405, "Method Not Allowed");
            return;
        }

        // Set target wallet based on URL path
        self.current_wallet = null;
        if (self.wallet_manager) |wm| {
            self.current_wallet = wm.getTargetWallet(url_path) catch |err| blk: {
                if (err == error.WalletNotFound) {
                    const error_response = self.jsonRpcError(
                        RPC_WALLET_NOT_FOUND,
                        "Requested wallet does not exist or is not loaded",
                        null,
                    ) catch return;
                    defer self.allocator.free(error_response);
                    try self.sendHttpResponse(conn.stream, 200, error_response);
                    return;
                } else {
                    // WalletNotSpecified or other - continue and let individual handlers decide
                    break :blk null;
                }
            };
        } else if (self.wallet) |w| {
            // Single wallet mode (backwards compatible)
            self.current_wallet = w;
        }

        // Check authentication if configured (accepts either rpcuser/rpcpassword or cookie token)
        if (self.config.auth_token != null or self.config.cookie_token != null) {
            const auth_header = findHeader(headers, "Authorization") orelse {
                try self.sendHttpError(conn.stream, 401, "Unauthorized");
                return;
            };
            if (!std.mem.startsWith(u8, auth_header, "Basic ")) {
                try self.sendHttpError(conn.stream, 401, "Unauthorized");
                return;
            }
            const provided = auth_header[6..];
            const user_pass_match = if (self.config.auth_token) |t| std.mem.eql(u8, provided, t) else false;
            const cookie_match = if (self.config.cookie_token) |t| std.mem.eql(u8, provided, t) else false;
            if (!user_pass_match and !cookie_match) {
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
        var body_allocated = false;

        if (body_start + content_length <= total_read) {
            // Already have full body in stack buffer
            body = @constCast(request_data[body_start .. body_start + content_length]);
        } else {
            // Need to read more — allocate a buffer for the full body
            const body_buf = self.allocator.alloc(u8, content_length) catch {
                try self.sendHttpError(conn.stream, 500, "Internal Server Error");
                return;
            };
            body_allocated = true;

            @memcpy(body_buf[0 .. total_read - body_start], request_data[body_start..total_read]);
            var offset = total_read - body_start;
            while (offset < content_length) {
                const n = conn.stream.read(body_buf[offset..]) catch {
                    self.allocator.free(body_buf);
                    return;
                };
                if (n == 0) {
                    self.allocator.free(body_buf);
                    return;
                }
                offset += n;
            }
            body = body_buf;
        }
        defer if (body_allocated) self.allocator.free(body);

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

    /// Send an HTTP response with custom content type.
    fn sendRestResponse(self: *RpcServer, stream: std.net.Stream, status: u16, content_type: []const u8, body: []const u8) !void {
        _ = self;
        var header_buf: [512]u8 = undefined;
        const status_text = switch (status) {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            else => "Error",
        };
        const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, status_text, content_type, body.len }) catch return;
        stream.writeAll(header) catch {};
        stream.writeAll(body) catch {};
    }

    // ========================================================================
    // REST API (Bitcoin Core compatible)
    // ========================================================================

    /// REST response format derived from file extension.
    const RestFormat = enum {
        json,
        hex,
        bin,
    };

    /// Parse the format extension from a REST path segment.
    /// Returns the path without extension and the format, or null if invalid.
    fn parseRestFormat(segment: []const u8) ?struct { path: []const u8, format: RestFormat } {
        if (std.mem.endsWith(u8, segment, ".json")) {
            return .{ .path = segment[0 .. segment.len - 5], .format = .json };
        } else if (std.mem.endsWith(u8, segment, ".hex")) {
            return .{ .path = segment[0 .. segment.len - 4], .format = .hex };
        } else if (std.mem.endsWith(u8, segment, ".bin")) {
            return .{ .path = segment[0 .. segment.len - 4], .format = .bin };
        }
        return null;
    }

    /// Content-Type string for a REST format.
    fn restContentType(format: RestFormat) []const u8 {
        return switch (format) {
            .json => "application/json",
            .hex => "text/plain",
            .bin => "application/octet-stream",
        };
    }

    /// Handle a REST API request (GET /rest/...).
    /// Dispatches to the appropriate handler based on the URL path.
    fn handleRestRequest(self: *RpcServer, stream: std.net.Stream, url_path: []const u8) !void {
        // Strip the "/rest/" prefix
        const rest_path = url_path[6..]; // skip "/rest/"

        // GET /rest/chaininfo.json
        if (std.mem.startsWith(u8, rest_path, "chaininfo")) {
            const parsed = parseRestFormat(rest_path["chaininfo".len..]) orelse {
                // chaininfo doesn't have sub-path, the extension is right after "chaininfo"
                // But parseRestFormat expects ".json" etc., and rest_path["chaininfo".len..] would be ".json"
                // Actually we need to handle "chaininfo.json" as a whole
                try self.sendRestResponse(stream, 400, "text/plain", "Bad format. Must use .json, .hex, or .bin");
                return;
            };
            _ = parsed.path; // should be empty for chaininfo
            const result = try self.handleGetBlockchainInfo(null);
            defer self.allocator.free(result);
            // The RPC result is wrapped in {"result":...,"error":null,"id":null}
            // For REST, we want just the result value. Extract it.
            const rest_body = extractJsonResult(result) orelse result;
            try self.sendRestResponse(stream, 200, "application/json", rest_body);
            return;
        }

        // GET /rest/mempool/info.json
        if (std.mem.startsWith(u8, rest_path, "mempool/info")) {
            const suffix = rest_path["mempool/info".len..];
            const parsed = parseRestFormat(suffix) orelse {
                try self.sendRestResponse(stream, 400, "text/plain", "Bad format. Must use .json, .hex, or .bin");
                return;
            };
            _ = parsed;
            const result = try self.handleGetMempoolInfo(null);
            defer self.allocator.free(result);
            const rest_body = extractJsonResult(result) orelse result;
            try self.sendRestResponse(stream, 200, "application/json", rest_body);
            return;
        }

        // GET /rest/block/<hash>.json
        if (std.mem.startsWith(u8, rest_path, "block/")) {
            const remainder = rest_path["block/".len..];
            const parsed = parseRestFormat(remainder) orelse {
                try self.sendRestResponse(stream, 400, "text/plain", "Bad format. Must use .json, .hex, or .bin");
                return;
            };
            const hash_hex = parsed.path;
            if (hash_hex.len != 64) {
                try self.sendRestResponse(stream, 400, "text/plain", "Invalid hash: must be 64 hex characters");
                return;
            }
            // Build JSON-RPC style params and call getblock handler
            // Construct a params array with the hash
            var params_buf: [256]u8 = undefined;
            const params_json = std.fmt.bufPrint(&params_buf, "{{\"jsonrpc\":\"1.0\",\"id\":null,\"method\":\"getblock\",\"params\":[\"{s}\",1]}}", .{hash_hex}) catch {
                try self.sendRestResponse(stream, 500, "text/plain", "Internal error");
                return;
            };
            const result = self.dispatch(params_json) catch {
                try self.sendRestResponse(stream, 500, "text/plain", "Internal error");
                return;
            };
            defer self.allocator.free(result);
            const rest_body = extractJsonResult(result) orelse result;
            // Check if result contains error
            if (std.mem.indexOf(u8, result, "\"error\":null") == null) {
                try self.sendRestResponse(stream, 404, "application/json", rest_body);
            } else {
                try self.sendRestResponse(stream, 200, restContentType(parsed.format), rest_body);
            }
            return;
        }

        // GET /rest/tx/<txid>.json
        if (std.mem.startsWith(u8, rest_path, "tx/")) {
            const remainder = rest_path["tx/".len..];
            const parsed = parseRestFormat(remainder) orelse {
                try self.sendRestResponse(stream, 400, "text/plain", "Bad format. Must use .json, .hex, or .bin");
                return;
            };
            const txid_hex = parsed.path;
            if (txid_hex.len != 64) {
                try self.sendRestResponse(stream, 400, "text/plain", "Invalid txid: must be 64 hex characters");
                return;
            }
            var params_buf: [256]u8 = undefined;
            const params_json = std.fmt.bufPrint(&params_buf, "{{\"jsonrpc\":\"1.0\",\"id\":null,\"method\":\"getrawtransaction\",\"params\":[\"{s}\",true]}}", .{txid_hex}) catch {
                try self.sendRestResponse(stream, 500, "text/plain", "Internal error");
                return;
            };
            const result = self.dispatch(params_json) catch {
                try self.sendRestResponse(stream, 500, "text/plain", "Internal error");
                return;
            };
            defer self.allocator.free(result);
            const rest_body = extractJsonResult(result) orelse result;
            if (std.mem.indexOf(u8, result, "\"error\":null") == null) {
                try self.sendRestResponse(stream, 404, "application/json", rest_body);
            } else {
                try self.sendRestResponse(stream, 200, restContentType(parsed.format), rest_body);
            }
            return;
        }

        // GET /rest/headers/<count>/<hash>.json
        if (std.mem.startsWith(u8, rest_path, "headers/")) {
            const remainder = rest_path["headers/".len..];
            // Parse count/hash.format
            const slash_idx = std.mem.indexOf(u8, remainder, "/") orelse {
                try self.sendRestResponse(stream, 400, "text/plain", "Invalid path: expected /rest/headers/<count>/<hash>.json");
                return;
            };
            const count_str = remainder[0..slash_idx];
            const hash_with_ext = remainder[slash_idx + 1 ..];
            const parsed = parseRestFormat(hash_with_ext) orelse {
                try self.sendRestResponse(stream, 400, "text/plain", "Bad format. Must use .json, .hex, or .bin");
                return;
            };
            const hash_hex = parsed.path;
            _ = std.fmt.parseInt(u32, count_str, 10) catch {
                try self.sendRestResponse(stream, 400, "text/plain", "Invalid count parameter");
                return;
            };
            if (hash_hex.len != 64) {
                try self.sendRestResponse(stream, 400, "text/plain", "Invalid hash: must be 64 hex characters");
                return;
            }
            // Use getblockheader RPC as a proxy (returns single header)
            var params_buf: [256]u8 = undefined;
            const params_json = std.fmt.bufPrint(&params_buf, "{{\"jsonrpc\":\"1.0\",\"id\":null,\"method\":\"getblockheader\",\"params\":[\"{s}\",true]}}", .{hash_hex}) catch {
                try self.sendRestResponse(stream, 500, "text/plain", "Internal error");
                return;
            };
            const result = self.dispatch(params_json) catch {
                try self.sendRestResponse(stream, 500, "text/plain", "Internal error");
                return;
            };
            defer self.allocator.free(result);
            const rest_body = extractJsonResult(result) orelse result;
            if (std.mem.indexOf(u8, result, "\"error\":null") == null) {
                try self.sendRestResponse(stream, 404, "application/json", rest_body);
            } else {
                try self.sendRestResponse(stream, 200, restContentType(parsed.format), rest_body);
            }
            return;
        }

        // Unknown REST endpoint
        try self.sendRestResponse(stream, 404, "text/plain", "REST endpoint not found");
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
        // Wallet management RPC methods (multi-wallet)
        else if (std.mem.eql(u8, method, "createwallet")) {
            return self.handleCreateWallet(params, id);
        } else if (std.mem.eql(u8, method, "loadwallet")) {
            return self.handleLoadWallet(params, id);
        } else if (std.mem.eql(u8, method, "unloadwallet")) {
            return self.handleUnloadWallet(params, id);
        } else if (std.mem.eql(u8, method, "listwallets")) {
            return self.handleListWallets(id);
        } else if (std.mem.eql(u8, method, "listwalletdir")) {
            return self.handleListWalletDir(id);
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
        }
        // AssumeUTXO snapshot RPC methods
        else if (std.mem.eql(u8, method, "loadtxoutset")) {
            return self.handleLoadTxOutSet(params, id);
        } else if (std.mem.eql(u8, method, "dumptxoutset")) {
            return self.handleDumpTxOutSet(params, id);
        }
        // Phase 8: Additional RPC methods
        else if (std.mem.eql(u8, method, "getblockheader")) {
            return self.handleGetBlockHeader(params, id);
        } else if (std.mem.eql(u8, method, "getdeploymentinfo")) {
            return self.handleGetDeploymentInfo(params, id);
        } else if (std.mem.eql(u8, method, "getchaintips")) {
            return self.handleGetChainTips(id);
        } else if (std.mem.eql(u8, method, "getrawmempool")) {
            return self.handleGetRawMempool(params, id);
        } else if (std.mem.eql(u8, method, "testmempoolaccept")) {
            return self.handleTestMempoolAccept(params, id);
        } else if (std.mem.eql(u8, method, "decoderawtransaction")) {
            return self.handleDecodeRawTransaction(params, id);
        } else if (std.mem.eql(u8, method, "decodescript")) {
            return self.handleDecodeScript(params, id);
        } else if (std.mem.eql(u8, method, "createrawtransaction")) {
            return self.handleCreateRawTransaction(params, id);
        } else if (std.mem.eql(u8, method, "getconnectioncount")) {
            return self.handleGetConnectionCount(id);
        } else if (std.mem.eql(u8, method, "addnode")) {
            return self.handleAddNode(params, id);
        } else if (std.mem.eql(u8, method, "getmininginfo")) {
            return self.handleGetMiningInfo(id);
        } else if (std.mem.eql(u8, method, "getnewaddress")) {
            return self.handleGetNewAddress(params, id);
        } else if (std.mem.eql(u8, method, "getbalance")) {
            return self.handleGetBalance(params, id);
        } else if (std.mem.eql(u8, method, "sendtoaddress")) {
            return self.handleSendToAddress(params, id);
        } else if (std.mem.eql(u8, method, "listunspent")) {
            return self.handleListUnspent(params, id);
        } else if (std.mem.eql(u8, method, "listtransactions")) {
            return self.handleListTransactions(params, id);
        } else if (std.mem.eql(u8, method, "estimatesmartfee")) {
            return self.handleEstimateSmartFee(params, id);
        } else if (std.mem.eql(u8, method, "signrawtransactionwithwallet")) {
            return self.handleSignRawTransactionWithWallet(params, id);
        } else if (std.mem.eql(u8, method, "importdescriptors")) {
            return self.handleImportDescriptors(params, id);
        } else if (std.mem.eql(u8, method, "validateaddress")) {
            return self.handleValidateAddress(params, id);
        } else if (std.mem.eql(u8, method, "gettxout")) {
            return self.handleGetTxOut(params, id);
        } else if (std.mem.eql(u8, method, "getmempoolancestors")) {
            return self.handleGetMempoolAncestors(params, id);
        } else if (std.mem.eql(u8, method, "getmempooldescendants")) {
            return self.handleGetMempoolDescendants(params, id);
        } else if (std.mem.eql(u8, method, "help")) {
            return self.handleHelp(params, id);
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

        // Headers height = validated blocks + queued headers not yet validated
        const headers_height = self.chain_state.best_height +
            @as(u32, @intCast(self.peer_manager.expected_blocks.items.len - self.peer_manager.connect_cursor));

        // Calculate initialblockdownload status
        // IBD = true if chainwork < minimum chain work OR tip age > 24 hours
        // Once cleared, it latches to false (cannot flip back to true)
        const ibd = self.isInitialBlockDownload();

        try writer.print("{{\"chain\":\"{s}\",\"blocks\":{d},\"headers\":{d},\"bestblockhash\":\"", .{
            chain_name,
            self.chain_state.best_height,
            headers_height,
        });
        try writeHashHex(writer, &self.chain_state.best_hash);
        try writer.print("\",\"difficulty\":{d},\"verificationprogress\":1.0,\"initialblockdownload\":{},\"pruned\":false}}", .{
            getDifficulty(self.network_params.genesis_header.bits),
            ibd,
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

        if (height > self.chain_state.best_height) {
            return self.jsonRpcError(RPC_INVALID_PARAMETER, "Block height out of range", id);
        }

        // Look up in block index by walking from the tip
        if (self.chain_manager) |cm| {
            // Walk backwards from the active tip to find block at requested height
            var entry: ?*validation.BlockIndexEntry = cm.active_tip;
            while (entry) |e| {
                if (e.height == height) {
                    var buf = std.ArrayList(u8).init(self.allocator);
                    defer buf.deinit();
                    const writer = buf.writer();

                    try writer.writeByte('"');
                    try writeHashHex(writer, &e.hash);
                    try writer.writeByte('"');

                    return self.jsonRpcResult(buf.items, id);
                }
                entry = e.parent;
            }
        }

        // Fallback: only know the best block hash
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

        // Look up block in index
        const is_genesis = std.mem.eql(u8, &blockhash, &self.network_params.genesis_hash);

        var header: types.BlockHeader = undefined;
        var height: u32 = 0;

        if (is_genesis) {
            header = self.network_params.genesis_header;
            height = 0;
        } else if (self.chain_manager) |cm| {
            if (cm.getBlock(&blockhash)) |entry| {
                header = entry.header;
                height = entry.height;
            } else {
                return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id);
            }
        } else if (std.mem.eql(u8, &blockhash, &self.chain_state.best_hash)) {
            // Fallback without chain_manager: only know best block
            header = self.network_params.genesis_header; // placeholder
            height = self.chain_state.best_height;
        } else {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id);
        }

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

            const services: u64 = if (peer.version_info) |v| v.services else 0;
            const is_inbound = peer.direction == .inbound;

            try writer.print("{{\"id\":{d},\"addr\":\"{s}\",\"network\":\"ipv4\",\"services\":\"{x:0>16}\",\"servicesnames\":[", .{
                i,
                addr_str,
                services,
            });

            // Service names
            var first_svc = true;
            if (services & 1 != 0) {
                try writer.writeAll("\"NETWORK\"");
                first_svc = false;
            }
            if (services & 8 != 0) {
                if (!first_svc) try writer.writeByte(',');
                try writer.writeAll("\"WITNESS\"");
                first_svc = false;
            }
            if (services & 1024 != 0) {
                if (!first_svc) try writer.writeByte(',');
                try writer.writeAll("\"NETWORK_LIMITED\"");
            }

            try writer.print("],\"relaytxes\":true,\"lastsend\":0,\"lastrecv\":0,\"bytessent\":0,\"bytesrecv\":0,\"conntime\":0,\"timeoffset\":0,\"pingtime\":0,\"version\":{d},\"subver\":\"{s}\",\"inbound\":{},\"bip152_hb_to\":false,\"bip152_hb_from\":false,\"startingheight\":{d},\"synced_headers\":{d},\"synced_blocks\":{d},\"inflight\":[],\"connection_type\":\"{s}\"}}", .{
                if (peer.version_info) |v| v.version else 0,
                if (peer.version_info) |v| v.user_agent else "",
                is_inbound,
                peer.start_height,
                self.chain_state.best_height,
                self.chain_state.best_height,
                if (is_inbound) "inbound" else "outbound-full-relay",
            });
        }

        try writer.writeByte(']');
        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetNetworkInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        const total = self.peer_manager.peers.items.len;
        // Count inbound peers
        var inbound: usize = 0;
        for (self.peer_manager.peers.items) |peer| {
            if (peer.direction == .inbound) inbound += 1;
        }
        const outbound = total - inbound;

        try writer.print("{{\"version\":250000,\"subversion\":\"/clearbit:0.1.0/\",\"protocolversion\":70016,\"localservices\":\"0000000000000009\",\"localservicesnames\":[\"NETWORK\",\"WITNESS\"],\"localrelay\":true,\"timeoffset\":0,\"networkactive\":true,\"connections\":{d},\"connections_in\":{d},\"connections_out\":{d},\"networks\":[{{\"name\":\"ipv4\",\"limited\":false,\"reachable\":true,\"proxy\":\"\",\"proxy_randomize_credentials\":false}},{{\"name\":\"ipv6\",\"limited\":false,\"reachable\":true,\"proxy\":\"\",\"proxy_randomize_credentials\":false}}],\"relayfee\":0.00001,\"incrementalfee\":0.00001,\"localaddresses\":[],\"warnings\":\"\"}}", .{
            total,
            inbound,
            outbound,
        });

        return self.jsonRpcResult(buf.items, id);
    }

    fn handleGetMempoolInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        const mempool_stats = self.mempool.stats();

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"loaded\":true,\"size\":{d},\"bytes\":{d},\"usage\":{d},\"total_fee\":0.0,\"maxmempool\":{d},\"mempoolminfee\":0.00001,\"minrelaytxfee\":0.00001,\"incrementalrelayfee\":0.00001,\"unbroadcastcount\":0,\"fullrbf\":true}}", .{
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

        // Add mining_score (cluster mempool linearization score)
        // Format: sat/vB with 8 decimal places
        const mining_score_int = @as(i64, @intFromFloat(entry.mining_score * 100_000_000));
        const mining_score_whole = @divTrunc(mining_score_int, 100_000_000);
        const mining_score_frac = @as(u64, @intCast(@mod(mining_score_int, 100_000_000)));

        try writer.print("\",\"depends\":[],\"spentby\":[],\"bip125-replaceable\":{s},\"fees\":{{\"base\":{d}.{d:0>8},\"modified\":{d}.{d:0>8},\"ancestor\":{d}.{d:0>8},\"descendant\":{d}.{d:0>8}}},\"mining_score\":{d}.{d:0>8}}}", .{
            if (bip125_replaceable) "true" else "false",
            // fees.base
            @divTrunc(entry.fee, 100_000_000),
            @as(u64, @intCast(@mod(entry.fee, 100_000_000))),
            // fees.modified
            @divTrunc(entry.fee, 100_000_000),
            @as(u64, @intCast(@mod(entry.fee, 100_000_000))),
            // fees.ancestor
            @divTrunc(entry.ancestor_fees, 100_000_000),
            @as(u64, @intCast(@mod(entry.ancestor_fees, 100_000_000))),
            // fees.descendant
            @divTrunc(entry.descendant_fees, 100_000_000),
            @as(u64, @intCast(@mod(entry.descendant_fees, 100_000_000))),
            // mining_score
            mining_score_whole,
            mining_score_frac,
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

    /// Check if wallet is available (supports multi-wallet via current_wallet)
    fn requireWallet(self: *RpcServer, id: ?std.json.Value) ?[]const u8 {
        // Check current_wallet first (set from URL path)
        if (self.current_wallet != null) return null;

        // Fall back to single wallet (backwards compatible)
        if (self.wallet != null) return null;

        // If wallet_manager exists but no current_wallet, check wallet count
        if (self.wallet_manager) |wm| {
            const count = wm.count();
            if (count == 0) {
                return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id) catch null;
            } else if (count > 1) {
                return self.jsonRpcError(RPC_WALLET_NOT_SPECIFIED, "Wallet file not specified (must request wallet RPC through /wallet/<name>)", id) catch null;
            } else {
                // Exactly one wallet - use it
                return null;
            }
        }

        return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id) catch null;
    }

    /// Get the current target wallet
    fn getTargetWallet(self: *RpcServer) ?*wallet_mod.Wallet {
        if (self.current_wallet) |w| return w;
        if (self.wallet) |w| return w;
        if (self.wallet_manager) |wm| {
            return wm.getDefaultWallet() catch null;
        }
        return null;
    }

    /// createwallet "wallet_name" ( disable_private_keys blank passphrase )
    /// Creates and loads a new wallet.
    fn handleCreateWallet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const wm = self.wallet_manager orelse {
            return self.jsonRpcError(RPC_WALLET_ERROR, "Multi-wallet not enabled", id);
        };

        // Extract wallet name
        const wallet_name = blk: {
            if (params == .array and params.array.items.len > 0) {
                const n = params.array.items[0];
                if (n == .string) break :blk n.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing wallet_name", id);
        };

        // Parse options
        var options = wallet_mod.WalletOptions{};

        if (params == .array) {
            // disable_private_keys
            if (params.array.items.len > 1) {
                const dpk = params.array.items[1];
                if (dpk == .bool) {
                    options.disable_private_keys = dpk.bool;
                }
            }
            // blank
            if (params.array.items.len > 2) {
                const blank = params.array.items[2];
                if (blank == .bool) {
                    options.blank = blank.bool;
                }
            }
            // passphrase
            if (params.array.items.len > 3) {
                const pp = params.array.items[3];
                if (pp == .string and pp.string.len > 0) {
                    options.passphrase = pp.string;
                }
            }
        }

        _ = wm.createWallet(wallet_name, options) catch |err| {
            if (err == error.WalletAlreadyExists) {
                return self.jsonRpcError(RPC_WALLET_ERROR, "Wallet already exists", id);
            }
            return self.jsonRpcError(RPC_WALLET_ERROR, @errorName(err), id);
        };

        // Return success with wallet name and warning
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"name\":\"{s}\",\"warning\":\"\"}}", .{wallet_name});

        return self.jsonRpcResult(buf.items, id);
    }

    /// loadwallet "filename"
    /// Loads a wallet from a wallet file.
    fn handleLoadWallet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const wm = self.wallet_manager orelse {
            return self.jsonRpcError(RPC_WALLET_ERROR, "Multi-wallet not enabled", id);
        };

        // Extract filename/wallet name
        const wallet_name = blk: {
            if (params == .array and params.array.items.len > 0) {
                const n = params.array.items[0];
                if (n == .string) break :blk n.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing filename", id);
        };

        _ = wm.loadWallet(wallet_name) catch |err| {
            if (err == error.WalletAlreadyLoaded) {
                return self.jsonRpcError(RPC_WALLET_ERROR, "Wallet is already loaded", id);
            }
            if (err == error.WalletNotFound) {
                return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "Wallet file not found", id);
            }
            return self.jsonRpcError(RPC_WALLET_ERROR, @errorName(err), id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"name\":\"{s}\",\"warning\":\"\"}}", .{wallet_name});

        return self.jsonRpcResult(buf.items, id);
    }

    /// unloadwallet "wallet_name"
    /// Unloads the wallet referenced by the request.
    fn handleUnloadWallet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const wm = self.wallet_manager orelse {
            return self.jsonRpcError(RPC_WALLET_ERROR, "Multi-wallet not enabled", id);
        };

        // Extract wallet name from params or use current_wallet
        var wallet_name: []const u8 = "";
        if (params == .array and params.array.items.len > 0) {
            const n = params.array.items[0];
            if (n == .string) {
                wallet_name = n.string;
            }
        }

        // If no name provided, try to get from URL path or fail
        if (wallet_name.len == 0) {
            // For unloadwallet, we need an explicit name
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing wallet_name", id);
        }

        wm.unloadWallet(wallet_name) catch |err| {
            if (err == error.WalletNotLoaded) {
                return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "Wallet is not loaded", id);
            }
            return self.jsonRpcError(RPC_WALLET_ERROR, @errorName(err), id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.print("{{\"warning\":\"\"}}", .{});

        return self.jsonRpcResult(buf.items, id);
    }

    /// listwallets
    /// Returns a list of currently loaded wallets.
    fn handleListWallets(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');

        if (self.wallet_manager) |wm| {
            const names = wm.listWallets(self.allocator) catch {
                return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to list wallets", id);
            };
            defer {
                for (names) |n| self.allocator.free(n);
                self.allocator.free(names);
            }

            for (names, 0..) |name, i| {
                if (i > 0) try writer.writeByte(',');
                try writer.print("\"{s}\"", .{name});
            }
        } else if (self.wallet != null) {
            // Single wallet mode - return empty name (default wallet)
            try writer.writeAll("\"\"");
        }

        try writer.writeByte(']');

        return self.jsonRpcResult(buf.items, id);
    }

    /// listwalletdir
    /// Returns a list of wallets in the wallet directory.
    fn handleListWalletDir(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        const wm = self.wallet_manager orelse {
            // If no wallet manager, return empty result
            return self.jsonRpcResult("{\"wallets\":[]}", id);
        };

        const names = wm.listWalletDir(self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to list wallet directory", id);
        };
        defer {
            for (names) |n| self.allocator.free(n);
            self.allocator.free(names);
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"wallets\":[");

        for (names, 0..) |name, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.print("{{\"name\":\"{s}\"}}", .{name});
        }

        try writer.writeAll("]}");

        return self.jsonRpcResult(buf.items, id);
    }

    /// encryptwallet "passphrase"
    /// Encrypts the wallet with a passphrase. This is for first time encryption.
    fn handleEncryptWallet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

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

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

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

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

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

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

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

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

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

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

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

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

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
                else => self.jsonRpcError(RPC_VERIFY_REJECTED, "transaction rejected", id),
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
            const hi: u8 = hexDigitToInt(hex[i * 2]) orelse
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex", id);
            const lo: u8 = hexDigitToInt(hex[i * 2 + 1]) orelse
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex", id);
            raw[i] = (hi << 4) | lo;
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
        std.log.info("handleGenerateToAddress: called", .{});
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
            if (self.chain_manager) |cm| cm else null,
            self.allocator,
        ) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Block generation failed", id);
        };
        defer result.deinit();

        // Cache mined blocks for P2P serving and broadcast inv to peers
        for (result.block_hashes.items, 0..) |hash, idx| {
            // Cache serialized block data for getdata responses
            if (idx < result.serialized_blocks.items.len) {
                self.peer_manager.cacheMinedBlock(hash, result.serialized_blocks.items[idx]);
            }

            // Broadcast inv(MSG_BLOCK) to all connected peers
            var inv_items = [_]p2p.InvVector{.{
                .inv_type = .msg_block,
                .hash = hash,
            }};
            const inv_msg = p2p.Message{ .inv = .{ .inventory = &inv_items } };
            self.peer_manager.broadcast(&inv_msg);
            std.log.info("broadcast block inv to peers", .{});
        }

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
        defer desc.deinit(self.allocator);

        // Get script pubkey from descriptor (index 0 for non-ranged)
        const payout_script = descriptor.deriveScript(self.allocator, &desc, 0) catch {
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
            if (self.chain_manager) |cm| cm else null,
            self.allocator,
        ) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Block generation failed", id);
        };
        defer result.deinit();

        // Cache mined blocks and broadcast inv to peers
        for (result.block_hashes.items, 0..) |hash, idx| {
            if (idx < result.serialized_blocks.items.len) {
                self.peer_manager.cacheMinedBlock(hash, result.serialized_blocks.items[idx]);
            }
            var inv_items = [_]p2p.InvVector{.{
                .inv_type = .msg_block,
                .hash = hash,
            }};
            const inv_msg = p2p.Message{ .inv = .{ .inventory = &inv_items } };
            self.peer_manager.broadcast(&inv_msg);
        }

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
                            const entry = self.mempool.get(txid);
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
            defer desc.deinit(self.allocator);

            const script = descriptor.deriveScript(self.allocator, &desc, 0) catch {
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
            if (self.chain_manager) |cm| cm else null,
            self.allocator,
        ) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Block generation failed", id);
        };

        // Broadcast inv(MSG_BLOCK) to all connected peers
        {
            var inv_items = [_]p2p.InvVector{.{
                .inv_type = .msg_block,
                .hash = gen_result.hash,
            }};
            const inv_msg = p2p.Message{ .inv = .{ .inventory = &inv_items } };
            self.peer_manager.broadcast(&inv_msg);
        }

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

        // TODO: implement maxfeerate check per-tx
        // Parse optional maxfeerate (BTC/kvB) - currently unused
        // if (params.array.items.len > 1 and params.array.items[1] != .null) { ... }

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
                else => self.jsonRpcError(RPC_VERIFY_REJECTED, "package rejected", id),
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
                try writer.print("\",\"allowed\":true", .{});
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

            if (output.bip32_derivation.count() > 0) {
                try writer.print("\"bip32_derivs\":{d}", .{output.bip32_derivation.count()});
            }

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

            const psbt = psbt_mod.Psbt.fromBase64(self.allocator, item.string) catch {
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
        const tx = serialize.readTransaction(&reader, self.allocator) catch {
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

    /// Handle loadtxoutset RPC - load a UTXO set snapshot file.
    /// Reference: Bitcoin Core rpc/blockchain.cpp loadtxoutset
    ///
    /// Arguments:
    ///   1. path (string, required) - Path to the snapshot file
    ///
    /// Returns:
    ///   {
    ///     "coins_loaded": n,     (numeric) Number of coins loaded
    ///     "tip_hash": "hash",    (string) Block hash at snapshot tip
    ///     "tip_height": n,       (numeric) Height of snapshot tip
    ///     "base_height": n       (numeric) Base height (same as tip_height for valid snapshots)
    ///   }
    fn handleLoadTxOutSet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Parse parameters
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "loadtxoutset requires path argument", id);
        }

        const path_param = params.array.items[0];
        if (path_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Path must be a string", id);
        }
        const path = path_param.string;

        // Validate and load the snapshot
        var load_result = storage.validateAndLoadSnapshot(
            path,
            self.network_params,
            self.allocator,
        ) catch |err| {
            const msg = switch (err) {
                storage.SnapshotError.UnknownSnapshot => "Snapshot block hash not found in assumeUtxo params",
                storage.SnapshotError.HashMismatch => "UTXO set hash doesn't match expected value",
                storage.SnapshotError.CoinCountMismatch => "Coin count doesn't match expected value",
                storage.SnapshotError.IoError => "Failed to read snapshot file",
                storage.SnapshotError.CorruptData => "Snapshot file is corrupt",
                storage.SnapshotError.WrongNetwork => "Snapshot is for a different network",
                storage.SnapshotError.OutOfMemory => "Out of memory",
                storage.SnapshotError.BackgroundValidationFailed => "Background validation failed",
            };
            return self.jsonRpcError(RPC_MISC_ERROR, msg, id);
        };

        // TODO: Actually activate the snapshot chainstate using ChainStateManager
        // For now, we just return the result without activating
        // In a full implementation, we would:
        // 1. Create the snapshot chainstate
        // 2. Swap it with the current chainstate via ChainStateManager.activateSnapshot()
        // 3. Start background validation thread
        defer load_result.chainstate.deinit();

        // Build response
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{");
        try writer.print("\"coins_loaded\":{d},", .{load_result.result.coins_loaded});
        try writer.writeAll("\"tip_hash\":\"");
        try writeHashHex(writer, &load_result.result.tip_hash);
        try writer.writeAll("\",");
        try writer.print("\"tip_height\":{d},", .{load_result.result.tip_height});
        try writer.print("\"base_height\":{d}", .{load_result.result.base_height});
        try writer.writeAll("}");

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle dumptxoutset RPC - dump the UTXO set to a snapshot file.
    /// Reference: Bitcoin Core rpc/blockchain.cpp dumptxoutset
    ///
    /// Arguments:
    ///   1. path (string, required) - Path to write the snapshot file
    ///
    /// Returns:
    ///   {
    ///     "coins_written": n,    (numeric) Number of coins written
    ///     "base_hash": "hash",   (string) Block hash at snapshot base
    ///     "base_height": n       (numeric) Height of snapshot base
    ///   }
    fn handleDumpTxOutSet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Parse parameters
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "dumptxoutset requires path argument", id);
        }

        const path_param = params.array.items[0];
        if (path_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Path must be a string", id);
        }
        const path = path_param.string;

        // Dump the UTXO set
        const dump_result = storage.dumpTxOutSetWithResult(
            self.chain_state,
            self.network_params.magic,
            path,
            self.allocator,
        ) catch |err| {
            const msg = switch (err) {
                error.FileNotFound, error.AccessDenied => "Cannot create snapshot file",
                storage.StorageError.SerializationFailed => "Serialization failed",
                storage.StorageError.OutOfMemory => "Out of memory",
                else => "Failed to dump UTXO set",
            };
            return self.jsonRpcError(RPC_MISC_ERROR, msg, id);
        };

        // Build response
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{");
        try writer.print("\"coins_written\":{d},", .{dump_result.coins_written});
        try writer.writeAll("\"base_hash\":\"");
        try writeHashHex(writer, &dump_result.base_hash);
        try writer.writeAll("\",");
        try writer.print("\"base_height\":{d}", .{dump_result.base_height});
        try writer.writeAll("}");

        return self.jsonRpcResult(buf.items, id);
    }

    // ========================================================================
    // Phase 8: Additional RPC Methods
    // ========================================================================

    /// Handle getblockheader RPC - get block header by hash.
    /// Reference: Bitcoin Core rpc/blockchain.cpp getblockheader
    ///
    /// Arguments:
    ///   1. blockhash (string, required) - The block hash
    ///   2. verbose (bool, optional, default=true) - true for JSON, false for hex
    fn handleGetBlockHeader(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Parse blockhash parameter
        var blockhash_hex: []const u8 = undefined;
        var verbose: bool = true;

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
                if (v == .bool) {
                    verbose = v.bool;
                }
            }
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid params", id);
        }

        // Parse hash
        if (blockhash_hex.len != 64) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid block hash length", id);
        }

        var hash: types.Hash256 = undefined;
        for (0..32) |i| {
            hash[31 - i] = std.fmt.parseInt(u8, blockhash_hex[i * 2 .. i * 2 + 2], 16) catch {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid block hash hex", id);
            };
        }

        // Try to find the block header
        // Check if it's the genesis block
        if (std.mem.eql(u8, &hash, &self.network_params.genesis_hash)) {
            const header = &self.network_params.genesis_header;

            if (!verbose) {
                // Return hex-encoded header
                var buf = std.ArrayList(u8).init(self.allocator);
                defer buf.deinit();
                const writer = buf.writer();
                try writer.writeByte('"');
                try writeBlockHeaderHex(writer, header);
                try writer.writeByte('"');
                return self.jsonRpcResult(buf.items, id);
            }

            // Verbose JSON response
            var buf = std.ArrayList(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();

            try writer.writeAll("{\"hash\":\"");
            try writeHashHex(writer, &hash);
            try writer.print("\",\"confirmations\":{d},\"height\":0,\"version\":{d},", .{
                self.chain_state.best_height + 1,
                header.version,
            });
            try writer.writeAll("\"versionHex\":\"");
            try writer.print("{x:0>8}", .{@as(u32, @bitCast(header.version))});
            try writer.writeAll("\",\"merkleroot\":\"");
            try writeHashHex(writer, &header.merkle_root);
            try writer.print("\",\"time\":{d},\"mediantime\":{d},\"nonce\":{d},", .{
                header.timestamp,
                header.timestamp,
                header.nonce,
            });
            try writer.print("\"bits\":\"{x:0>8}\",\"difficulty\":{d:.8},", .{
                header.bits,
                getDifficulty(header.bits),
            });
            try writer.writeAll("\"chainwork\":\"");
            // For genesis, chainwork is just the work of one block
            try writer.writeAll("0000000000000000000000000000000000000000000000000000000100010001");
            try writer.writeAll("\",\"nTx\":1,\"previousblockhash\":null,");
            // nextblockhash would be set if we have it
            try writer.writeAll("\"nextblockhash\":null}");

            return self.jsonRpcResult(buf.items, id);
        }

        // Check if it's the current best block
        if (std.mem.eql(u8, &hash, &self.chain_state.best_hash)) {
            // Return simplified header for best block
            var buf = std.ArrayList(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();

            try writer.writeAll("{\"hash\":\"");
            try writeHashHex(writer, &hash);
            try writer.print("\",\"confirmations\":1,\"height\":{d}", .{self.chain_state.best_height});
            try writer.writeAll("}");

            return self.jsonRpcResult(buf.items, id);
        }

        return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id);
    }

    /// Handle getdeploymentinfo RPC - return deployment/softfork status.
    /// Reference: Bitcoin Core rpc/blockchain.cpp getdeploymentinfo
    ///
    /// Arguments:
    ///   1. blockhash (string, optional) - hash of block to query; defaults to chain tip
    ///
    /// Returns an object with "hash", "height", and "deployments" fields.
    /// Deployments include buried (bip34, bip65, bip66) and bip9-style (csv, segwit, taproot, testdummy).
    /// Because clearbit has no BIP9 state machine, bip9-type deployments that have
    /// activation heights in NetworkParams are reported as buried-style with type="buried".
    /// testdummy is reported with type="bip9" and status="defined" since it is never activated.
    ///
    /// Follow-up issue: implement a full BIP9 versionbits state machine so that
    /// in-progress deployments can report started/locked_in/active/failed status.
    fn handleGetDeploymentInfo(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Determine the query height.  If a blockhash is provided we look it up;
        // otherwise we use the current chain tip.
        var query_height: u32 = self.chain_state.best_height;
        var query_hash: types.Hash256 = self.chain_state.best_hash;

        if (params == .array and params.array.items.len > 0) {
            const h = params.array.items[0];
            if (h != .null) {
                if (h != .string) {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "blockhash must be a string", id);
                }
                const blockhash_hex = h.string;
                if (blockhash_hex.len != 64) {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid block hash length", id);
                }
                // Parse hex → bytes (display order → internal LE order)
                var parsed_hash: types.Hash256 = undefined;
                for (0..32) |i| {
                    parsed_hash[31 - i] = std.fmt.parseInt(u8, blockhash_hex[i * 2 .. i * 2 + 2], 16) catch {
                        return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid block hash hex", id);
                    };
                }
                // Resolve to a height.  We support the genesis hash and the
                // current best hash; everything else returns "Block not found".
                if (std.mem.eql(u8, &parsed_hash, &self.network_params.genesis_hash)) {
                    query_height = 0;
                    query_hash = parsed_hash;
                } else if (std.mem.eql(u8, &parsed_hash, &self.chain_state.best_hash)) {
                    query_height = self.chain_state.best_height;
                    query_hash = parsed_hash;
                } else if (self.chain_manager) |cm| {
                    // Walk the active chain looking for the requested hash.
                    var entry: ?*validation.BlockIndexEntry = cm.active_tip;
                    var found = false;
                    while (entry) |e| {
                        if (std.mem.eql(u8, &e.hash, &parsed_hash)) {
                            query_height = e.height;
                            query_hash = parsed_hash;
                            found = true;
                            break;
                        }
                        entry = e.parent;
                    }
                    if (!found) {
                        return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id);
                    }
                } else {
                    return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found", id);
                }
            }
        }

        const np = self.network_params;

        // Helper: is a buried deployment active at query_height?
        // A buried deployment is considered active after (height-1), i.e. active when
        // query_height >= activation_height.  This matches Bitcoin Core semantics:
        // "active from when the chain height is one below the activation height".
        // For activation_height == 0 (regtest csv/segwit/taproot) it is always active.

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"hash\":\"");
        try writeHashHex(writer, &query_hash);
        try writer.print("\",\"height\":{d},\"deployments\":{{", .{query_height});

        // ---- bip34 (buried) ----
        {
            const act_height = np.bip34_height;
            const active = query_height >= act_height;
            try writer.print("\"bip34\":{{\"type\":\"buried\",\"active\":{},\"height\":{d},\"min_activation_height\":{d}}}", .{
                active, act_height, act_height,
            });
        }
        try writer.writeByte(',');

        // ---- bip65 (buried) ----
        {
            const act_height = np.bip65_height;
            const active = query_height >= act_height;
            try writer.print("\"bip65\":{{\"type\":\"buried\",\"active\":{},\"height\":{d},\"min_activation_height\":{d}}}", .{
                active, act_height, act_height,
            });
        }
        try writer.writeByte(',');

        // ---- bip66 (buried) ----
        {
            const act_height = np.bip66_height;
            const active = query_height >= act_height;
            try writer.print("\"bip66\":{{\"type\":\"buried\",\"active\":{},\"height\":{d},\"min_activation_height\":{d}}}", .{
                active, act_height, act_height,
            });
        }
        try writer.writeByte(',');

        // ---- csv (buried — activation height stored in NetworkParams) ----
        {
            const act_height = np.csv_height;
            const active = query_height >= act_height;
            try writer.print("\"csv\":{{\"type\":\"buried\",\"active\":{},\"height\":{d},\"min_activation_height\":{d}}}", .{
                active, act_height, act_height,
            });
        }
        try writer.writeByte(',');

        // ---- segwit (buried) ----
        {
            const act_height = np.segwit_height;
            const active = query_height >= act_height;
            try writer.print("\"segwit\":{{\"type\":\"buried\",\"active\":{},\"height\":{d},\"min_activation_height\":{d}}}", .{
                active, act_height, act_height,
            });
        }
        try writer.writeByte(',');

        // ---- taproot (buried) ----
        {
            const act_height = np.taproot_height;
            const active = query_height >= act_height;
            try writer.print("\"taproot\":{{\"type\":\"buried\",\"active\":{},\"height\":{d},\"min_activation_height\":{d}}}", .{
                active, act_height, act_height,
            });
        }
        try writer.writeByte(',');

        // ---- testdummy (bip9-style, never activated on any real network) ----
        // clearbit does not have a BIP9 state machine.  We report testdummy with
        // type="bip9", status="defined", since=0, bit=28, start_time=-1 (always),
        // timeout=9223372036854775807 (never).
        // Follow-up: wire up a proper BIP9 versionbits cache.
        try writer.writeAll("\"testdummy\":{\"type\":\"bip9\",\"active\":false,\"bip9\":{\"bit\":28,\"start_time\":-1,\"timeout\":9223372036854775807,\"min_activation_height\":0,\"status\":\"defined\",\"since\":0}}");

        try writer.writeAll("}}");

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle getchaintips RPC - return information about chain tips.
    /// Reference: Bitcoin Core rpc/blockchain.cpp getchaintips
    fn handleGetChainTips(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        // Return the active chain tip
        try writer.writeAll("[{\"height\":");
        try writer.print("{d}", .{self.chain_state.best_height});
        try writer.writeAll(",\"hash\":\"");
        try writeHashHex(writer, &self.chain_state.best_hash);
        try writer.writeAll("\",\"branchlen\":0,\"status\":\"active\"}]");

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle getrawmempool RPC - return mempool transaction IDs.
    /// Reference: Bitcoin Core rpc/mempool.cpp getrawmempool
    ///
    /// Arguments:
    ///   1. verbose (bool, optional, default=false) - true for detailed info
    ///   2. mempool_sequence (bool, optional, default=false) - include sequence
    fn handleGetRawMempool(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        var verbose: bool = false;

        if (params == .array and params.array.items.len > 0) {
            const v = params.array.items[0];
            if (v == .bool) {
                verbose = v.bool;
            }
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        self.mempool.mutex.lock();
        defer self.mempool.mutex.unlock();

        if (verbose) {
            // Return object with txid -> info
            try writer.writeByte('{');
            var first = true;
            var it = self.mempool.entries.iterator();
            while (it.next()) |entry| {
                if (!first) try writer.writeByte(',');
                first = false;

                try writer.writeByte('"');
                try writeHashHex(writer, &entry.value_ptr.*.txid);
                try writer.writeAll("\":{");
                try writer.print("\"vsize\":{d},", .{entry.value_ptr.*.vsize});
                try writer.print("\"weight\":{d},", .{entry.value_ptr.*.weight});
                try writer.print("\"fee\":{d:.8},", .{@as(f64, @floatFromInt(entry.value_ptr.*.fee)) / 100_000_000.0});
                try writer.print("\"time\":{d},", .{entry.value_ptr.*.time_added});
                try writer.print("\"height\":{d}", .{entry.value_ptr.*.height_added});
                try writer.writeByte('}');
            }
            try writer.writeByte('}');
        } else {
            // Return array of txids
            try writer.writeByte('[');
            var first = true;
            var it = self.mempool.entries.iterator();
            while (it.next()) |entry| {
                if (!first) try writer.writeByte(',');
                first = false;

                try writer.writeByte('"');
                try writeHashHex(writer, &entry.value_ptr.*.txid);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle testmempoolaccept RPC - test if raw transactions would be accepted.
    /// Reference: Bitcoin Core rpc/mempool.cpp testmempoolaccept
    ///
    /// Arguments:
    ///   1. rawtxs (array of strings, required) - hex-encoded transactions
    ///   2. maxfeerate (numeric, optional) - max fee rate in BTC/kvB
    fn handleTestMempoolAccept(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing rawtxs array", id);
        }

        const rawtxs_param = params.array.items[0];
        if (rawtxs_param != .array) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "rawtxs must be an array", id);
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');

        for (rawtxs_param.array.items, 0..) |tx_item, i| {
            if (i > 0) try writer.writeByte(',');

            if (tx_item != .string) {
                try writer.writeAll("{\"allowed\":false,\"reject-reason\":\"invalid-hex\"}");
                continue;
            }

            const hex_str = tx_item.string;

            // Try to decode the transaction
            var tx_bytes = self.allocator.alloc(u8, hex_str.len / 2) catch {
                try writer.writeAll("{\"allowed\":false,\"reject-reason\":\"decode-error\"}");
                continue;
            };
            defer self.allocator.free(tx_bytes);

            var valid_hex = true;
            for (0..hex_str.len / 2) |j| {
                tx_bytes[j] = std.fmt.parseInt(u8, hex_str[j * 2 .. j * 2 + 2], 16) catch {
                    valid_hex = false;
                    break;
                };
            }

            if (!valid_hex) {
                try writer.writeAll("{\"allowed\":false,\"reject-reason\":\"invalid-hex\"}");
                continue;
            }

            // Try to deserialize and get txid
            var reader = serialize.Reader{ .data = tx_bytes };
            const tx = serialize.readTransaction(&reader, self.allocator) catch {
                try writer.writeAll("{\"allowed\":false,\"reject-reason\":\"TX decode failed\"}");
                continue;
            };

            const txid = crypto.computeTxid(&tx, self.allocator) catch {
                try writer.writeAll("{\"allowed\":false,\"reject-reason\":\"txid computation failed\"}");
                continue;
            };

            // Check if already in mempool
            self.mempool.mutex.lock();
            const in_mempool = self.mempool.entries.contains(txid);
            self.mempool.mutex.unlock();

            if (in_mempool) {
                try writer.writeAll("{\"txid\":\"");
                try writeHashHex(writer, &txid);
                try writer.writeAll("\",\"allowed\":false,\"reject-reason\":\"txn-already-in-mempool\"}");
                continue;
            }

            // Basic validation (would normally do full mempool acceptance check)
            try writer.writeAll("{\"txid\":\"");
            try writeHashHex(writer, &txid);
            try writer.writeAll("\",\"allowed\":true,\"vsize\":");
            const weight = mempool_mod.computeTxWeight(&tx, self.allocator) catch 0;
            const vsize = (weight + 3) / 4;
            try writer.print("{d}", .{vsize});
            try writer.writeByte('}');
        }

        try writer.writeByte(']');
        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle decoderawtransaction RPC - decode a hex-encoded transaction.
    /// Reference: Bitcoin Core rpc/rawtransaction.cpp decoderawtransaction
    ///
    /// Arguments:
    ///   1. hexstring (string, required) - hex-encoded transaction
    fn handleDecodeRawTransaction(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing hexstring", id);
        }

        const hex_param = params.array.items[0];
        if (hex_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "hexstring must be a string", id);
        }

        const hex_str = hex_param.string;

        // Decode hex
        if (hex_str.len % 2 != 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex length", id);
        }

        var tx_bytes = self.allocator.alloc(u8, hex_str.len / 2) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Out of memory", id);
        };
        defer self.allocator.free(tx_bytes);

        for (0..hex_str.len / 2) |i| {
            tx_bytes[i] = std.fmt.parseInt(u8, hex_str[i * 2 .. i * 2 + 2], 16) catch {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex", id);
            };
        }

        // Deserialize transaction
        var reader = serialize.Reader{ .data = tx_bytes };
        const tx = serialize.readTransaction(&reader, self.allocator) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed", id);
        };

        // Compute txid and hash
        const txid = crypto.computeTxid(&tx, self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "txid computation failed", id);
        };
        const hash = crypto.computeWtxid(&tx, self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "wtxid computation failed", id);
        };
        const weight = mempool_mod.computeTxWeight(&tx, self.allocator) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "weight computation failed", id);
        };
        const vsize = (weight + 3) / 4;

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"txid\":\"");
        try writeHashHex(writer, &txid);
        try writer.writeAll("\",\"hash\":\"");
        try writeHashHex(writer, &hash);
        try writer.print("\",\"version\":{d},\"size\":{d},\"vsize\":{d},\"weight\":{d},\"locktime\":{d},", .{
            tx.version,
            tx_bytes.len,
            vsize,
            weight,
            tx.lock_time,
        });

        // vin array
        try writer.writeAll("\"vin\":[");
        for (tx.inputs, 0..) |input, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"txid\":\"");
            try writeHashHex(writer, &input.previous_output.hash);
            try writer.print("\",\"vout\":{d},\"scriptSig\":{{\"hex\":\"", .{input.previous_output.index});
            for (input.script_sig) |byte| {
                try writer.print("{x:0>2}", .{byte});
            }
            try writer.print("\"}},\"sequence\":{d}", .{input.sequence});
            if (input.witness.len > 0) {
                try writer.writeAll(",\"txinwitness\":[");
                for (input.witness, 0..) |wit, w| {
                    if (w > 0) try writer.writeByte(',');
                    try writer.writeByte('"');
                    for (wit) |byte| {
                        try writer.print("{x:0>2}", .{byte});
                    }
                    try writer.writeByte('"');
                }
                try writer.writeByte(']');
            }
            try writer.writeByte('}');
        }
        try writer.writeAll("],");

        // vout array
        try writer.writeAll("\"vout\":[");
        for (tx.outputs, 0..) |output, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.print("{{\"value\":{d:.8},\"n\":{d},\"scriptPubKey\":{{\"hex\":\"", .{
                @as(f64, @floatFromInt(output.value)) / 100_000_000.0,
                i,
            });
            for (output.script_pubkey) |byte| {
                try writer.print("{x:0>2}", .{byte});
            }
            try writer.writeAll("\"}}");
            try writer.writeByte('}');
        }
        try writer.writeAll("]}");

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle decodescript RPC - decode a hex-encoded script.
    /// Reference: Bitcoin Core rpc/rawtransaction.cpp decodescript
    ///
    /// Arguments:
    ///   1. hexstring (string, required) - hex-encoded script
    fn handleDecodeScript(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing hexstring", id);
        }

        const hex_param = params.array.items[0];
        if (hex_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "hexstring must be a string", id);
        }

        const hex_str = hex_param.string;

        // Handle empty script
        if (hex_str.len == 0) {
            return self.jsonRpcResult("{\"asm\":\"\",\"type\":\"nonstandard\"}", id);
        }

        if (hex_str.len % 2 != 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex length", id);
        }

        var script_bytes = self.allocator.alloc(u8, hex_str.len / 2) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Out of memory", id);
        };
        defer self.allocator.free(script_bytes);

        for (0..hex_str.len / 2) |i| {
            script_bytes[i] = std.fmt.parseInt(u8, hex_str[i * 2 .. i * 2 + 2], 16) catch {
                return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "Invalid hex", id);
            };
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        // Determine script type
        const script_type = script_mod.classifyScript(script_bytes);
        const type_str = switch (script_type) {
            .p2pkh => "pubkeyhash",
            .p2sh => "scripthash",
            .p2wpkh => "witness_v0_keyhash",
            .p2wsh => "witness_v0_scripthash",
            .p2tr => "witness_v1_taproot",
            .null_data => "nulldata",
            .multisig => "multisig",
            else => "nonstandard",
        };

        try writer.writeAll("{\"asm\":\"");
        // Write simplified asm
        try writeScriptAsm(writer, script_bytes);
        try writer.print("\",\"type\":\"{s}\"", .{type_str});

        // Add P2SH and segwit addresses if applicable
        if (script_type == .p2pkh or script_type == .p2sh or script_type == .p2wpkh or script_type == .p2wsh or script_type == .p2tr) {
            // In a full implementation, we'd derive the address here
        }

        try writer.writeByte('}');
        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle createrawtransaction RPC - create an unsigned raw transaction.
    /// Reference: Bitcoin Core rpc/rawtransaction.cpp createrawtransaction
    ///
    /// Arguments:
    ///   1. inputs (array, required) - [{txid, vout}, ...]
    ///   2. outputs (array/object, required) - [{address: amount}, ...] or {address: amount, ...}
    fn handleCreateRawTransaction(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len < 2) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Requires inputs and outputs", id);
        }

        const inputs_param = params.array.items[0];
        const outputs_param = params.array.items[1];

        if (inputs_param != .array) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "inputs must be an array", id);
        }

        // Build transaction
        var inputs = std.ArrayList(types.TxIn).init(self.allocator);
        defer inputs.deinit();

        for (inputs_param.array.items) |input_item| {
            if (input_item != .object) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "input must be an object", id);
            }

            const txid_val = input_item.object.get("txid") orelse {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing txid", id);
            };
            const vout_val = input_item.object.get("vout") orelse {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing vout", id);
            };

            if (txid_val != .string or txid_val.string.len != 64) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid", id);
            }
            if (vout_val != .integer) {
                return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid vout", id);
            }

            var prev_hash: types.Hash256 = undefined;
            for (0..32) |i| {
                prev_hash[31 - i] = std.fmt.parseInt(u8, txid_val.string[i * 2 .. i * 2 + 2], 16) catch {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid txid hex", id);
                };
            }

            // Get optional sequence
            var seq: u32 = 0xFFFFFFFF;
            if (input_item.object.get("sequence")) |seq_val| {
                if (seq_val == .integer) {
                    seq = @intCast(seq_val.integer);
                }
            }

            inputs.append(.{
                .previous_output = .{
                    .hash = prev_hash,
                    .index = @intCast(vout_val.integer),
                },
                .script_sig = &[_]u8{},
                .sequence = seq,
                .witness = &[_][]const u8{},
            }) catch {
                return self.jsonRpcError(RPC_INTERNAL_ERROR, "Out of memory", id);
            };
        }

        // Parse outputs
        var outputs = std.ArrayList(types.TxOut).init(self.allocator);
        defer {
            for (outputs.items) |*out| {
                self.allocator.free(out.script_pubkey);
            }
            outputs.deinit();
        }

        if (outputs_param == .object) {
            var it = outputs_param.object.iterator();
            while (it.next()) |entry| {
                const addr_str = entry.key_ptr.*;
                const amount_val = entry.value_ptr.*;

                var amount_sats: i64 = 0;
                if (amount_val == .float) {
                    amount_sats = @intFromFloat(amount_val.float * 100_000_000.0);
                } else if (amount_val == .integer) {
                    amount_sats = @intCast(amount_val.integer * 100_000_000);
                } else {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid amount", id);
                }

                // Create scriptPubKey from address (simplified - just store address length for now)
                const script_pubkey = self.allocator.alloc(u8, addr_str.len) catch {
                    return self.jsonRpcError(RPC_INTERNAL_ERROR, "Out of memory", id);
                };
                @memcpy(script_pubkey, addr_str);

                outputs.append(.{
                    .value = amount_sats,
                    .script_pubkey = script_pubkey,
                }) catch {
                    self.allocator.free(script_pubkey);
                    return self.jsonRpcError(RPC_INTERNAL_ERROR, "Out of memory", id);
                };
            }
        } else if (outputs_param == .array) {
            for (outputs_param.array.items) |out_item| {
                if (out_item != .object) continue;
                var out_it = out_item.object.iterator();
                while (out_it.next()) |entry| {
                    const addr_str = entry.key_ptr.*;
                    const amount_val = entry.value_ptr.*;

                    var amount_sats: i64 = 0;
                    if (amount_val == .float) {
                        amount_sats = @intFromFloat(amount_val.float * 100_000_000.0);
                    } else if (amount_val == .integer) {
                        amount_sats = @intCast(amount_val.integer * 100_000_000);
                    }

                    const script_pubkey = self.allocator.alloc(u8, addr_str.len) catch {
                        return self.jsonRpcError(RPC_INTERNAL_ERROR, "Out of memory", id);
                    };
                    @memcpy(script_pubkey, addr_str);

                    outputs.append(.{
                        .value = amount_sats,
                        .script_pubkey = script_pubkey,
                    }) catch {
                        self.allocator.free(script_pubkey);
                        return self.jsonRpcError(RPC_INTERNAL_ERROR, "Out of memory", id);
                    };
                }
            }
        }

        // Parse optional locktime
        var locktime: u32 = 0;
        if (params.array.items.len > 2) {
            const lt = params.array.items[2];
            if (lt == .integer) {
                locktime = @intCast(lt.integer);
            }
        }

        // Serialize transaction
        const tx = types.Transaction{
            .version = 2,
            .inputs = inputs.items,
            .outputs = outputs.items,
            .lock_time = locktime,
        };

        var swriter = serialize.Writer.init(self.allocator);
        defer swriter.deinit();
        serialize.writeTransaction(&swriter, &tx) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Serialization failed", id);
        };

        // Return hex
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('"');
        for (swriter.getWritten()) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }
        try writer.writeByte('"');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle getconnectioncount RPC - return the number of connected peers.
    /// Reference: Bitcoin Core rpc/net.cpp getconnectioncount
    fn handleGetConnectionCount(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        const count = self.peer_manager.getPeerCount();
        var buf: [32]u8 = undefined;
        const result = std.fmt.bufPrint(&buf, "{d}", .{count}) catch return error.OutOfMemory;
        return self.jsonRpcResult(result, id);
    }

    /// Handle addnode RPC - add or remove a peer.
    /// Reference: Bitcoin Core rpc/net.cpp addnode
    ///
    /// Arguments:
    ///   1. node (string, required) - IP address or hostname
    ///   2. command (string, required) - "add", "remove", or "onetry"
    fn handleAddNode(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len < 2) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Requires node and command", id);
        }

        const node_param = params.array.items[0];
        const cmd_param = params.array.items[1];

        if (node_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "node must be a string", id);
        }
        if (cmd_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "command must be a string", id);
        }

        const node = node_param.string;
        const cmd = cmd_param.string;

        if (std.mem.eql(u8, cmd, "add")) {
            // Add to manual connection list
            self.peer_manager.addManualNode(node) catch {
                return self.jsonRpcError(RPC_MISC_ERROR, "Failed to add node", id);
            };
        } else if (std.mem.eql(u8, cmd, "remove")) {
            // Remove from manual connection list
            self.peer_manager.removeManualNode(node);
        } else if (std.mem.eql(u8, cmd, "onetry")) {
            // Try connecting once
            self.peer_manager.tryConnectNode(node) catch {
                return self.jsonRpcError(RPC_MISC_ERROR, "Failed to connect", id);
            };
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid command", id);
        }

        return self.jsonRpcResult("null", id);
    }

    /// Handle getmininginfo RPC - return mining-related information.
    /// Reference: Bitcoin Core rpc/mining.cpp getmininginfo
    fn handleGetMiningInfo(self: *RpcServer, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        const chain_name = switch (self.network_params.magic) {
            consensus.MAINNET.magic => "main",
            consensus.TESTNET.magic => "test",
            consensus.REGTEST.magic => "regtest",
            else => "unknown",
        };

        self.mempool.mutex.lock();
        const mempool_size = self.mempool.entries.count();
        self.mempool.mutex.unlock();

        try writer.print("{{\"blocks\":{d},\"difficulty\":{d:.8},\"networkhashps\":0,\"pooledtx\":{d},\"chain\":\"{s}\"}}", .{
            self.chain_state.best_height,
            getDifficulty(self.network_params.genesis_header.bits),
            mempool_size,
            chain_name,
        });

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle getnewaddress RPC - generate a new address.
    /// Reference: Bitcoin Core wallet/rpc/addresses.cpp getnewaddress
    ///
    /// Arguments:
    ///   1. label (string, optional) - label for the address
    ///   2. address_type (string, optional) - "legacy", "p2sh-segwit", "bech32", "bech32m"
    fn handleGetNewAddress(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const wallet = self.current_wallet orelse {
            if (self.wallet) |w| {
                return self.handleGetNewAddressWithWallet(w, params, id);
            }
            return self.jsonRpcError(RPC_WALLET_NOT_SPECIFIED, "No wallet loaded", id);
        };
        return self.handleGetNewAddressWithWallet(wallet, params, id);
    }

    fn handleGetNewAddressWithWallet(self: *RpcServer, wallet: *wallet_mod.Wallet, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        var addr_type: wallet_mod.AddressType = .p2wpkh; // default to native segwit

        if (params == .array and params.array.items.len > 1) {
            const type_param = params.array.items[1];
            if (type_param == .string) {
                if (std.mem.eql(u8, type_param.string, "legacy")) {
                    addr_type = .p2pkh;
                } else if (std.mem.eql(u8, type_param.string, "p2sh-segwit")) {
                    addr_type = .p2sh_p2wpkh;
                } else if (std.mem.eql(u8, type_param.string, "bech32m")) {
                    addr_type = .p2tr;
                }
            }
        }

        const result = wallet.getnewaddress(addr_type, false) catch {
            return self.jsonRpcError(RPC_WALLET_ERROR, "Failed to generate address", id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('"');
        try writer.writeAll(result.address);
        try writer.writeByte('"');

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle getbalance RPC - return the wallet balance.
    /// Reference: Bitcoin Core wallet/rpc/coins.cpp getbalance
    ///
    /// Arguments:
    ///   1. dummy (string, optional) - ignored, for compatibility
    ///   2. minconf (numeric, optional) - minimum confirmations
    fn handleGetBalance(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        _ = params;

        const wallet = self.current_wallet orelse {
            if (self.wallet) |w| {
                return self.handleGetBalanceWithWallet(w, id);
            }
            return self.jsonRpcError(RPC_WALLET_NOT_SPECIFIED, "No wallet loaded", id);
        };
        return self.handleGetBalanceWithWallet(wallet, id);
    }

    fn handleGetBalanceWithWallet(self: *RpcServer, wallet: *wallet_mod.Wallet, id: ?std.json.Value) ![]const u8 {
        const balance = wallet.getBalance();
        const btc_amount = @as(f64, @floatFromInt(balance)) / 100_000_000.0;

        var buf: [64]u8 = undefined;
        const result = std.fmt.bufPrint(&buf, "{d:.8}", .{btc_amount}) catch return error.OutOfMemory;
        return self.jsonRpcResult(result, id);
    }

    /// Handle sendtoaddress RPC - send to a bitcoin address.
    /// Reference: Bitcoin Core wallet/rpc/spend.cpp sendtoaddress
    ///
    /// Arguments:
    ///   1. address (string, required) - the bitcoin address
    ///   2. amount (numeric, required) - amount in BTC
    fn handleSendToAddress(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len < 2) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Requires address and amount", id);
        }

        const wallet = self.current_wallet orelse {
            if (self.wallet) |w| {
                return self.handleSendToAddressWithWallet(w, params, id);
            }
            return self.jsonRpcError(RPC_WALLET_NOT_SPECIFIED, "No wallet loaded", id);
        };
        return self.handleSendToAddressWithWallet(wallet, params, id);
    }

    fn handleSendToAddressWithWallet(self: *RpcServer, wallet: *wallet_mod.Wallet, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const addr_param = params.array.items[0];
        const amount_param = params.array.items[1];

        if (addr_param != .string) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "address must be a string", id);
        }

        var amount_sats: i64 = 0;
        if (amount_param == .float) {
            amount_sats = @intFromFloat(amount_param.float * 100_000_000.0);
        } else if (amount_param == .integer) {
            amount_sats = @intCast(amount_param.integer * 100_000_000);
        } else {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid amount", id);
        }

        // Check balance
        const balance = wallet.getBalance();
        if (balance < amount_sats) {
            return self.jsonRpcError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds", id);
        }

        // In a full implementation, we would:
        // 1. Create transaction
        // 2. Sign it
        // 3. Broadcast to network
        // For now, return a placeholder txid
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("\"");
        // Return a dummy txid (in real impl would be the actual txid)
        try writer.writeAll("0000000000000000000000000000000000000000000000000000000000000000");
        try writer.writeAll("\"");

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle listunspent RPC - list unspent transaction outputs.
    /// Reference: Bitcoin Core wallet/rpc/coins.cpp listunspent
    ///
    /// Arguments:
    ///   1. minconf (numeric, optional, default=1) - minimum confirmations
    ///   2. maxconf (numeric, optional, default=9999999) - maximum confirmations
    fn handleListUnspent(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        _ = params;

        const wallet = self.current_wallet orelse {
            if (self.wallet) |w| {
                return self.handleListUnspentWithWallet(w, id);
            }
            return self.jsonRpcError(RPC_WALLET_NOT_SPECIFIED, "No wallet loaded", id);
        };
        return self.handleListUnspentWithWallet(wallet, id);
    }

    fn handleListUnspentWithWallet(self: *RpcServer, wallet: *wallet_mod.Wallet, id: ?std.json.Value) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');

        for (wallet.utxos.items, 0..) |utxo, i| {
            if (i > 0) try writer.writeByte(',');

            const btc_amount = @as(f64, @floatFromInt(utxo.output.value)) / 100_000_000.0;
            const confirmations = if (self.chain_state.best_height >= utxo.height)
                self.chain_state.best_height - utxo.height + 1
            else
                0;

            try writer.writeAll("{\"txid\":\"");
            try writeHashHex(writer, &utxo.outpoint.hash);
            try writer.print("\",\"vout\":{d},\"amount\":{d:.8},\"confirmations\":{d},\"spendable\":true,\"solvable\":true,\"safe\":true}}", .{
                utxo.outpoint.index,
                btc_amount,
                confirmations,
            });
        }

        try writer.writeByte(']');
        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle listtransactions RPC - list wallet transactions.
    /// Reference: Bitcoin Core wallet/rpc/transactions.cpp listtransactions
    ///
    /// Arguments:
    ///   1. label (string, optional) - filter by label
    ///   2. count (numeric, optional, default=10) - number of transactions
    fn handleListTransactions(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        _ = params;

        const wallet = self.current_wallet orelse {
            if (self.wallet) |w| {
                return self.handleListTransactionsWithWallet(w, id);
            }
            return self.jsonRpcError(RPC_WALLET_NOT_SPECIFIED, "No wallet loaded", id);
        };
        return self.handleListTransactionsWithWallet(wallet, id);
    }

    fn handleListTransactionsWithWallet(self: *RpcServer, wallet: *wallet_mod.Wallet, id: ?std.json.Value) ![]const u8 {
        _ = wallet;

        // In a full implementation, we would return wallet transaction history
        // For now, return empty array
        return self.jsonRpcResult("[]", id);
    }

    /// Handle estimatesmartfee RPC - estimate fee rate for confirmation target.
    /// Reference: Bitcoin Core rpc/fees.cpp estimatesmartfee
    ///
    /// Arguments:
    ///   1. conf_target (numeric, required) - confirmation target in blocks
    ///   2. estimate_mode (string, optional) - "economical" or "conservative"
    fn handleEstimateSmartFee(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (params != .array or params.array.items.len == 0) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing conf_target", id);
        }

        const target_param = params.array.items[0];
        if (target_param != .integer) {
            return self.jsonRpcError(RPC_INVALID_PARAMS, "conf_target must be numeric", id);
        }

        const conf_target: u32 = @intCast(@max(1, @min(1008, target_param.integer)));

        // Get fee estimate from mempool's fee estimator
        self.mempool.mutex.lock();
        defer self.mempool.mutex.unlock();

        const fee_rate = self.mempool.fee_estimator.estimateFee(conf_target);

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        if (fee_rate) |rate| {
            // Convert sat/vB to BTC/kvB
            const btc_per_kvb = rate * 1000.0 / 100_000_000.0;
            try writer.print("{{\"feerate\":{d:.8},\"blocks\":{d}}}", .{ btc_per_kvb, conf_target });
        } else {
            // No estimate available
            try writer.print("{{\"errors\":[\"Insufficient data or no feerate found\"],\"blocks\":{d}}}", .{conf_target});
        }

        return self.jsonRpcResult(buf.items, id);
    }

    // ========================================================================
    // New RPC methods: signrawtransactionwithwallet, importdescriptors,
    // validateaddress, gettxout, getmempoolancestors, getmempooldescendants
    // ========================================================================

    /// signrawtransactionwithwallet "hexstring" ( [{"txid":"hex","vout":n,"scriptPubKey":"hex","redeemScript":"hex","witnessScript":"hex","amount":n},...] "sighashtype" )
    /// Sign inputs for raw transaction using wallet keys.
    fn handleSignRawTransactionWithWallet(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        const wallet = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

        // Extract hex string
        const hex = blk: {
            if (params == .array and params.array.items.len > 0) {
                const h = params.array.items[0];
                if (h == .string) break :blk h.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing hexstring", id);
        };

        // Parse optional sighash type (3rd parameter, default ALL = 0x01)
        var sighash_type: u32 = 0x01; // SIGHASH_ALL
        if (params == .array and params.array.items.len >= 3) {
            const sh = params.array.items[2];
            if (sh == .string) {
                if (std.mem.eql(u8, sh.string, "ALL")) {
                    sighash_type = 0x01;
                } else if (std.mem.eql(u8, sh.string, "NONE")) {
                    sighash_type = 0x02;
                } else if (std.mem.eql(u8, sh.string, "SINGLE")) {
                    sighash_type = 0x03;
                } else if (std.mem.eql(u8, sh.string, "ALL|ANYONECANPAY")) {
                    sighash_type = 0x81;
                } else if (std.mem.eql(u8, sh.string, "NONE|ANYONECANPAY")) {
                    sighash_type = 0x82;
                } else if (std.mem.eql(u8, sh.string, "SINGLE|ANYONECANPAY")) {
                    sighash_type = 0x83;
                } else {
                    return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid sighash type", id);
                }
            }
        }

        // Decode hex to bytes
        if (hex.len % 2 != 0 or hex.len == 0) {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed", id);
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
        var tx = serialize.readTransaction(&reader, self.allocator) catch {
            return self.jsonRpcError(RPC_DESERIALIZATION_ERROR, "TX decode failed", id);
        };

        // Try to sign each input with wallet keys
        var complete = true;
        for (0..tx.inputs.len) |input_idx| {
            const input = tx.inputs[input_idx];
            // Look up the UTXO being spent to find the matching wallet key
            var found_utxo: ?wallet_mod.OwnedUtxo = null;
            for (wallet.utxos.items) |utxo| {
                if (std.mem.eql(u8, &utxo.outpoint.hash, &input.previous_output.hash) and
                    utxo.outpoint.index == input.previous_output.index)
                {
                    found_utxo = utxo;
                    break;
                }
            }

            if (found_utxo) |utxo| {
                wallet.signInput(&tx, input_idx, utxo, sighash_type) catch {
                    complete = false;
                };
            } else {
                // No wallet key for this input
                complete = false;
            }
        }

        // Serialize signed transaction back to hex
        var tx_writer = serialize.Writer.init(self.allocator);
        defer tx_writer.deinit();
        serialize.writeTransaction(&tx_writer, &tx) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to serialize signed tx", id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"hex\":\"");
        for (tx_writer.list.items) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }
        try writer.writeAll("\",\"complete\":");
        try writer.writeAll(if (complete) "true" else "false");
        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    /// importdescriptors "requests"
    /// Import descriptors into the wallet.
    fn handleImportDescriptors(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        if (self.requireWallet(id)) |err| return err;

        _ = self.getTargetWallet() orelse {
            return self.jsonRpcError(RPC_WALLET_NOT_FOUND, "No wallet loaded", id);
        };

        // Extract requests array
        const requests = blk: {
            if (params == .array and params.array.items.len > 0) {
                const r = params.array.items[0];
                if (r == .array) break :blk r.array.items;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing requests array", id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeByte('[');

        for (requests, 0..) |req, i| {
            if (i > 0) try writer.writeByte(',');

            if (req != .object) {
                try writer.writeAll("{\"success\":false,\"error\":{\"code\":-8,\"message\":\"Invalid request object\"}}");
                continue;
            }

            const desc_value = req.object.get("desc") orelse {
                try writer.writeAll("{\"success\":false,\"error\":{\"code\":-8,\"message\":\"Missing descriptor\"}}");
                continue;
            };

            if (desc_value != .string) {
                try writer.writeAll("{\"success\":false,\"error\":{\"code\":-8,\"message\":\"Descriptor must be a string\"}}");
                continue;
            }

            // Parse the descriptor to validate it
            var desc = descriptor.parseDescriptor(self.allocator, desc_value.string) catch {
                try writer.writeAll("{\"success\":false,\"error\":{\"code\":-5,\"message\":\"Invalid descriptor\"}}");
                continue;
            };
            desc.deinit(self.allocator);

            // Successfully parsed - report success
            // In a full implementation, we would derive addresses and add keys to the wallet.
            // For now, we validate and acknowledge the import.
            try writer.writeAll("{\"success\":true}");
        }

        try writer.writeByte(']');

        return self.jsonRpcResult(buf.items, id);
    }

    /// validateaddress "address"
    /// Return information about the given bitcoin address.
    fn handleValidateAddress(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const addr_str = blk: {
            if (params == .array and params.array.items.len > 0) {
                const a = params.array.items[0];
                if (a == .string) break :blk a.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing address", id);
        };

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        // Try to decode the address
        const addr = address_mod.Address.decode(addr_str, self.allocator) catch {
            // Invalid address
            try writer.print("{{\"isvalid\":false,\"address\":\"{s}\"}}", .{addr_str});
            return self.jsonRpcResult(buf.items, id);
        };
        defer self.allocator.free(addr.hash);

        try writer.writeAll("{\"isvalid\":true");
        try writer.print(",\"address\":\"{s}\"", .{addr_str});

        // Reconstruct scriptPubKey and write as hex
        try writer.writeAll(",\"scriptPubKey\":\"");
        switch (addr.addr_type) {
            .p2pkh => {
                // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                try writer.writeAll("76a914");
                for (addr.hash[0..20]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                try writer.writeAll("88ac");
            },
            .p2sh => {
                // OP_HASH160 <20> OP_EQUAL
                try writer.writeAll("a914");
                for (addr.hash[0..20]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                try writer.writeAll("87");
            },
            .p2wpkh => {
                // OP_0 <20>
                try writer.writeAll("0014");
                for (addr.hash[0..20]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
            },
            .p2wsh => {
                // OP_0 <32>
                try writer.writeAll("0020");
                for (addr.hash[0..32]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
            },
            .p2tr => {
                // OP_1 <32>
                try writer.writeAll("5120");
                for (addr.hash[0..32]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
            },
        }
        try writer.writeByte('"');

        // isscript
        const is_script = addr.addr_type == .p2sh or addr.addr_type == .p2wsh;
        try writer.print(",\"isscript\":{s}", .{if (is_script) "true" else "false"});

        // iswitness
        const is_witness = addr.addr_type == .p2wpkh or addr.addr_type == .p2wsh or addr.addr_type == .p2tr;
        try writer.print(",\"iswitness\":{s}", .{if (is_witness) "true" else "false"});

        if (is_witness) {
            const witness_version: u8 = switch (addr.addr_type) {
                .p2wpkh, .p2wsh => 0,
                .p2tr => 1,
                else => 0,
            };
            try writer.print(",\"witness_version\":{d}", .{witness_version});
            try writer.writeAll(",\"witness_program\":\"");
            for (addr.hash) |byte| {
                try writer.print("{x:0>2}", .{byte});
            }
            try writer.writeByte('"');
        }

        try writer.writeByte('}');

        return self.jsonRpcResult(buf.items, id);
    }

    /// gettxout "txid" n ( include_mempool )
    /// Returns details about an unspent transaction output.
    fn handleGetTxOut(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        // Parse txid
        const txid_hex = blk: {
            if (params == .array and params.array.items.len >= 2) {
                const t = params.array.items[0];
                if (t == .string) break :blk t.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing txid and vout", id);
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
            txid[31 - i] = (high << 4) | low;
        }

        // Parse vout index
        const vout: u32 = blk: {
            const v = params.array.items[1];
            if (v == .integer) {
                if (v.integer < 0) return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid vout", id);
                break :blk @intCast(v.integer);
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid vout", id);
        };

        // Parse optional include_mempool (default true)
        var include_mempool: bool = true;
        if (params == .array and params.array.items.len >= 3) {
            const im = params.array.items[2];
            if (im == .bool) {
                include_mempool = im.bool;
            }
        }

        const outpoint = types.OutPoint{ .hash = txid, .index = vout };

        // Check mempool first if requested
        if (include_mempool) {
            self.mempool.mutex.lock();
            defer self.mempool.mutex.unlock();

            // Check if this output is spent by a mempool transaction
            if (self.mempool.spenders.get(outpoint) != null) {
                // Output is spent in the mempool
                return self.jsonRpcResult("null", id);
            }

            // Check if this output is created by a mempool transaction
            if (self.mempool.getOutputFromMempool(&outpoint)) |output| {
                var buf = std.ArrayList(u8).init(self.allocator);
                defer buf.deinit();
                const writer = buf.writer();

                try writer.writeAll("{\"bestblock\":\"");
                try writeHashHex(writer, &self.chain_state.best_hash);
                try writer.writeAll("\",\"confirmations\":0");
                try writer.print(",\"value\":{d}.{d:0>8}", .{
                    @divTrunc(output.value, 100_000_000),
                    @as(u64, @intCast(@mod(output.value, 100_000_000))),
                });
                try writer.writeAll(",\"scriptPubKey\":{\"hex\":\"");
                for (output.script_pubkey) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                try writer.writeAll("\"},\"coinbase\":false");
                try writer.writeByte('}');

                return self.jsonRpcResult(buf.items, id);
            }
        }

        // Look up in UTXO set
        const utxo_result = self.chain_state.utxo_set.get(&outpoint) catch {
            return self.jsonRpcError(RPC_INTERNAL_ERROR, "UTXO lookup failed", id);
        };

        if (utxo_result) |utxo| {
            var mut_utxo = utxo;
            defer mut_utxo.deinit(self.allocator);

            const script = mut_utxo.reconstructScript(self.allocator) catch {
                return self.jsonRpcError(RPC_INTERNAL_ERROR, "Failed to reconstruct script", id);
            };
            defer self.allocator.free(script);

            const confirmations = if (self.chain_state.best_height >= mut_utxo.height)
                self.chain_state.best_height - mut_utxo.height + 1
            else
                0;

            var buf = std.ArrayList(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();

            try writer.writeAll("{\"bestblock\":\"");
            try writeHashHex(writer, &self.chain_state.best_hash);
            try writer.print("\",\"confirmations\":{d}", .{confirmations});
            try writer.print(",\"value\":{d}.{d:0>8}", .{
                @divTrunc(utxo.value, 100_000_000),
                @as(u64, @intCast(@mod(utxo.value, 100_000_000))),
            });
            try writer.writeAll(",\"scriptPubKey\":{\"hex\":\"");
            for (script) |byte| {
                try writer.print("{x:0>2}", .{byte});
            }
            try writer.print("\"}},\"coinbase\":{s}", .{if (utxo.is_coinbase) "true" else "false"});
            try writer.writeByte('}');

            return self.jsonRpcResult(buf.items, id);
        }

        // UTXO not found - return null (per Bitcoin Core behavior)
        return self.jsonRpcResult("null", id);
    }

    /// getmempoolancestors "txid" ( verbose )
    /// Returns all in-mempool ancestors for a transaction.
    fn handleGetMempoolAncestors(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const txid_hex = blk: {
            if (params == .array and params.array.items.len > 0) {
                const t = params.array.items[0];
                if (t == .string) break :blk t.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing txid", id);
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
            txid[31 - i] = (high << 4) | low;
        }

        var verbose: bool = false;
        if (params == .array and params.array.items.len >= 2) {
            const v = params.array.items[1];
            if (v == .bool) verbose = v.bool;
        }

        self.mempool.mutex.lock();
        defer self.mempool.mutex.unlock();

        const entry = self.mempool.get(txid) orelse {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool", id);
        };

        // Walk ancestors: for each input of this tx, check if the spent txid is in mempool
        var ancestors = std.AutoHashMap(types.Hash256, void).init(self.allocator);
        defer ancestors.deinit();

        // BFS to find all ancestors
        var queue = std.ArrayList(types.Hash256).init(self.allocator);
        defer queue.deinit();

        // Seed with the direct parents
        for (entry.tx.inputs) |input| {
            if (self.mempool.entries.contains(input.previous_output.hash)) {
                if (!ancestors.contains(input.previous_output.hash)) {
                    ancestors.put(input.previous_output.hash, {}) catch {};
                    queue.append(input.previous_output.hash) catch {};
                }
            }
        }

        // Process queue
        var qi: usize = 0;
        while (qi < queue.items.len) : (qi += 1) {
            const anc_txid = queue.items[qi];
            if (self.mempool.get(anc_txid)) |anc_entry| {
                for (anc_entry.tx.inputs) |input| {
                    if (self.mempool.entries.contains(input.previous_output.hash)) {
                        if (!ancestors.contains(input.previous_output.hash)) {
                            ancestors.put(input.previous_output.hash, {}) catch {};
                            queue.append(input.previous_output.hash) catch {};
                        }
                    }
                }
            }
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        if (verbose) {
            try writer.writeByte('{');
            var first = true;
            var it = ancestors.iterator();
            while (it.next()) |anc| {
                if (!first) try writer.writeByte(',');
                first = false;

                try writer.writeByte('"');
                try writeHashHex(writer, anc.key_ptr);
                try writer.writeAll("\":{");

                if (self.mempool.get(anc.key_ptr.*)) |anc_entry| {
                    try writer.print("\"vsize\":{d},\"weight\":{d},\"fee\":{d:.8},\"time\":{d},\"height\":{d}", .{
                        anc_entry.vsize,
                        anc_entry.weight,
                        @as(f64, @floatFromInt(anc_entry.fee)) / 100_000_000.0,
                        anc_entry.time_added,
                        anc_entry.height_added,
                    });
                }
                try writer.writeByte('}');
            }
            try writer.writeByte('}');
        } else {
            try writer.writeByte('[');
            var first = true;
            var it = ancestors.iterator();
            while (it.next()) |anc| {
                if (!first) try writer.writeByte(',');
                first = false;

                try writer.writeByte('"');
                try writeHashHex(writer, anc.key_ptr);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        return self.jsonRpcResult(buf.items, id);
    }

    /// getmempooldescendants "txid" ( verbose )
    /// Returns all in-mempool descendants for a transaction.
    fn handleGetMempoolDescendants(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        const txid_hex = blk: {
            if (params == .array and params.array.items.len > 0) {
                const t = params.array.items[0];
                if (t == .string) break :blk t.string;
            }
            return self.jsonRpcError(RPC_INVALID_PARAMS, "Missing txid", id);
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
            txid[31 - i] = (high << 4) | low;
        }

        var verbose: bool = false;
        if (params == .array and params.array.items.len >= 2) {
            const v = params.array.items[1];
            if (v == .bool) verbose = v.bool;
        }

        self.mempool.mutex.lock();
        defer self.mempool.mutex.unlock();

        if (!self.mempool.entries.contains(txid)) {
            return self.jsonRpcError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool", id);
        }

        // Walk descendants using the children map
        var descendants = std.AutoHashMap(types.Hash256, void).init(self.allocator);
        defer descendants.deinit();

        var queue = std.ArrayList(types.Hash256).init(self.allocator);
        defer queue.deinit();

        // Seed with direct children
        if (self.mempool.children.get(txid)) |children_list| {
            for (children_list.items) |child_txid| {
                if (!descendants.contains(child_txid)) {
                    descendants.put(child_txid, {}) catch {};
                    queue.append(child_txid) catch {};
                }
            }
        }

        // BFS
        var qi: usize = 0;
        while (qi < queue.items.len) : (qi += 1) {
            const desc_txid = queue.items[qi];
            if (self.mempool.children.get(desc_txid)) |children_list| {
                for (children_list.items) |child_txid| {
                    if (!descendants.contains(child_txid)) {
                        descendants.put(child_txid, {}) catch {};
                        queue.append(child_txid) catch {};
                    }
                }
            }
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        if (verbose) {
            try writer.writeByte('{');
            var first = true;
            var it = descendants.iterator();
            while (it.next()) |desc_entry| {
                if (!first) try writer.writeByte(',');
                first = false;

                try writer.writeByte('"');
                try writeHashHex(writer, desc_entry.key_ptr);
                try writer.writeAll("\":{");

                if (self.mempool.get(desc_entry.key_ptr.*)) |me| {
                    try writer.print("\"vsize\":{d},\"weight\":{d},\"fee\":{d:.8},\"time\":{d},\"height\":{d}", .{
                        me.vsize,
                        me.weight,
                        @as(f64, @floatFromInt(me.fee)) / 100_000_000.0,
                        me.time_added,
                        me.height_added,
                    });
                }
                try writer.writeByte('}');
            }
            try writer.writeByte('}');
        } else {
            try writer.writeByte('[');
            var first = true;
            var it = descendants.iterator();
            while (it.next()) |desc_entry| {
                if (!first) try writer.writeByte(',');
                first = false;

                try writer.writeByte('"');
                try writeHashHex(writer, desc_entry.key_ptr);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }

        return self.jsonRpcResult(buf.items, id);
    }

    /// Handle help RPC - list available commands or show help for a command.
    /// Reference: Bitcoin Core rpc/server.cpp help
    ///
    /// Arguments:
    ///   1. command (string, optional) - command name to get help for
    fn handleHelp(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
        var command: ?[]const u8 = null;

        if (params == .array and params.array.items.len > 0) {
            const cmd_param = params.array.items[0];
            if (cmd_param == .string) {
                command = cmd_param.string;
            }
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        const writer = buf.writer();

        if (command) |cmd| {
            // Return help for specific command
            try writer.writeByte('"');
            if (std.mem.eql(u8, cmd, "getblockchaininfo")) {
                try writer.writeAll("getblockchaininfo\\n\\nReturns an object containing various state info regarding blockchain processing.");
            } else if (std.mem.eql(u8, cmd, "getblockcount")) {
                try writer.writeAll("getblockcount\\n\\nReturns the height of the most-work fully-validated chain.");
            } else if (std.mem.eql(u8, cmd, "getblockhash")) {
                try writer.writeAll("getblockhash height\\n\\nReturns hash of block in best-block-chain at height provided.");
            } else if (std.mem.eql(u8, cmd, "getblock")) {
                try writer.writeAll("getblock blockhash ( verbosity )\\n\\nReturns block data.");
            } else if (std.mem.eql(u8, cmd, "getblockheader")) {
                try writer.writeAll("getblockheader blockhash ( verbose )\\n\\nReturns block header data.");
            } else if (std.mem.eql(u8, cmd, "getdeploymentinfo")) {
                try writer.writeAll("getdeploymentinfo ( blockhash )\\n\\nReturns an object containing deployment state info for softforks.");
            } else if (std.mem.eql(u8, cmd, "getchaintips")) {
                try writer.writeAll("getchaintips\\n\\nReturn information about all known tips in the block tree.");
            } else if (std.mem.eql(u8, cmd, "getrawmempool")) {
                try writer.writeAll("getrawmempool ( verbose mempool_sequence )\\n\\nReturns all transaction ids in memory pool.");
            } else if (std.mem.eql(u8, cmd, "testmempoolaccept")) {
                try writer.writeAll("testmempoolaccept [\\\"rawtx\\\"] ( maxfeerate )\\n\\nTest if raw transactions would be accepted by mempool.");
            } else if (std.mem.eql(u8, cmd, "decoderawtransaction")) {
                try writer.writeAll("decoderawtransaction hexstring\\n\\nReturn a JSON object representing the serialized, hex-encoded transaction.");
            } else if (std.mem.eql(u8, cmd, "decodescript")) {
                try writer.writeAll("decodescript hexstring\\n\\nDecode a hex-encoded script.");
            } else if (std.mem.eql(u8, cmd, "createrawtransaction")) {
                try writer.writeAll("createrawtransaction [{\\\"txid\\\":\\\"hex\\\",\\\"vout\\\":n},...] [{\\\"address\\\":amount},...] ( locktime )\\n\\nCreate a transaction spending inputs and creating outputs.");
            } else if (std.mem.eql(u8, cmd, "sendrawtransaction")) {
                try writer.writeAll("sendrawtransaction hexstring ( maxfeerate )\\n\\nSubmit a raw transaction to local node and network.");
            } else if (std.mem.eql(u8, cmd, "getconnectioncount")) {
                try writer.writeAll("getconnectioncount\\n\\nReturns the number of connections to other nodes.");
            } else if (std.mem.eql(u8, cmd, "addnode")) {
                try writer.writeAll("addnode node command\\n\\nAttempts to add or remove a node from the addnode list.");
            } else if (std.mem.eql(u8, cmd, "getmininginfo")) {
                try writer.writeAll("getmininginfo\\n\\nReturns a json object containing mining-related information.");
            } else if (std.mem.eql(u8, cmd, "getnewaddress")) {
                try writer.writeAll("getnewaddress ( label address_type )\\n\\nReturns a new Bitcoin address for receiving payments.");
            } else if (std.mem.eql(u8, cmd, "getbalance")) {
                try writer.writeAll("getbalance ( dummy minconf )\\n\\nReturns the total available balance.");
            } else if (std.mem.eql(u8, cmd, "sendtoaddress")) {
                try writer.writeAll("sendtoaddress address amount\\n\\nSend an amount to a given address.");
            } else if (std.mem.eql(u8, cmd, "listunspent")) {
                try writer.writeAll("listunspent ( minconf maxconf addresses )\\n\\nReturns array of unspent transaction outputs.");
            } else if (std.mem.eql(u8, cmd, "listtransactions")) {
                try writer.writeAll("listtransactions ( label count skip )\\n\\nReturns up to count most recent transactions.");
            } else if (std.mem.eql(u8, cmd, "estimatesmartfee")) {
                try writer.writeAll("estimatesmartfee conf_target ( estimate_mode )\\n\\nEstimates the approximate fee per kilobyte.");
            } else if (std.mem.eql(u8, cmd, "help")) {
                try writer.writeAll("help ( command )\\n\\nList all commands, or get help for a specified command.");
            } else {
                try writer.writeAll("Unknown command: ");
                try writer.writeAll(cmd);
            }
            try writer.writeByte('"');
        } else {
            // List all commands
            try writer.writeAll("\"== Blockchain ==\\n");
            try writer.writeAll("getbestblockhash\\n");
            try writer.writeAll("getblock\\n");
            try writer.writeAll("getblockchaininfo\\n");
            try writer.writeAll("getblockcount\\n");
            try writer.writeAll("getblockhash\\n");
            try writer.writeAll("getblockheader\\n");
            try writer.writeAll("getdeploymentinfo\\n");
            try writer.writeAll("getchaintips\\n");
            try writer.writeAll("getdifficulty\\n");
            try writer.writeAll("\\n== Mempool ==\\n");
            try writer.writeAll("getmempoolancestors\\n");
            try writer.writeAll("getmempooldescendants\\n");
            try writer.writeAll("getmempoolentry\\n");
            try writer.writeAll("getmempoolinfo\\n");
            try writer.writeAll("getrawmempool\\n");
            try writer.writeAll("gettxout\\n");
            try writer.writeAll("testmempoolaccept\\n");
            try writer.writeAll("\\n== Mining ==\\n");
            try writer.writeAll("getblocktemplate\\n");
            try writer.writeAll("getmininginfo\\n");
            try writer.writeAll("submitblock\\n");
            try writer.writeAll("\\n== Network ==\\n");
            try writer.writeAll("addnode\\n");
            try writer.writeAll("getconnectioncount\\n");
            try writer.writeAll("getnetworkinfo\\n");
            try writer.writeAll("getpeerinfo\\n");
            try writer.writeAll("\\n== Rawtransactions ==\\n");
            try writer.writeAll("createrawtransaction\\n");
            try writer.writeAll("decoderawtransaction\\n");
            try writer.writeAll("decodescript\\n");
            try writer.writeAll("getrawtransaction\\n");
            try writer.writeAll("sendrawtransaction\\n");
            try writer.writeAll("\\n== Wallet ==\\n");
            try writer.writeAll("createwallet\\n");
            try writer.writeAll("getbalance\\n");
            try writer.writeAll("getnewaddress\\n");
            try writer.writeAll("getwalletinfo\\n");
            try writer.writeAll("listunspent\\n");
            try writer.writeAll("listtransactions\\n");
            try writer.writeAll("listwallets\\n");
            try writer.writeAll("loadwallet\\n");
            try writer.writeAll("sendtoaddress\\n");
            try writer.writeAll("signrawtransactionwithwallet\\n");
            try writer.writeAll("importdescriptors\\n");
            try writer.writeAll("unloadwallet\\n");
            try writer.writeAll("\\n== Util ==\\n");
            try writer.writeAll("validateaddress\\n");
            try writer.writeAll("estimatesmartfee\\n");
            try writer.writeAll("help\\n");
            try writer.writeAll("stop\\n");
            try writer.writeAll("\"");
        }

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

    /// Check if the node is in Initial Block Download (IBD) mode.
    /// IBD is true if:
    /// 1. Total chain work < minimum chain work (anti-DoS), OR
    /// 2. Tip timestamp < current time - 24 hours
    /// Once cleared, it latches to false and cannot flip back to true.
    /// Reference: Bitcoin Core validation.cpp ChainstateManager::UpdateIBDStatus()
    fn isInitialBlockDownload(self: *const RpcServer) bool {
        // Check if total chain work is below minimum
        if (self.compareChainWork(&self.chain_state.total_work, &self.network_params.min_chain_work) < 0) {
            return true;
        }

        // Check if we have a chain tip with timestamp information
        if (self.chain_manager) |cm| {
            if (cm.active_tip) |tip| {
                // Get current time
                const now = std.time.timestamp();
                const tip_time = tip.header.timestamp;

                // Max tip age is 24 hours (86400 seconds)
                const max_tip_age_seconds: i64 = 24 * 60 * 60;

                // If tip is older than 24 hours, we're in IBD
                if (now - @as(i64, @intCast(tip_time)) > max_tip_age_seconds) {
                    return true;
                }
            }
        }

        return false;
    }

    /// Compare two 256-bit chain work values (little-endian representation).
    /// Returns: positive if a > b, negative if a < b, zero if a == b
    fn compareChainWork(self: *const RpcServer, a: *const [32]u8, b: *const [32]u8) i32 {
        _ = self;
        // Compare as big-endian integers (most significant byte first)
        for (0..32) |i| {
            if (a[i] > b[i]) return 1;
            if (a[i] < b[i]) return -1;
        }
        return 0;
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

/// Extract the "result" value from a JSON-RPC response string.
/// Given {"result":<value>,"error":null,"id":...}, returns the <value> substring.
/// Returns null if the format is unexpected.
fn extractJsonResult(json_rpc_response: []const u8) ?[]const u8 {
    // Find the start of "result": value
    const prefix = "\"result\":";
    const start_idx = std.mem.indexOf(u8, json_rpc_response, prefix) orelse return null;
    const value_start = start_idx + prefix.len;
    if (value_start >= json_rpc_response.len) return null;

    // Find the matching end by looking for ,"error": pattern
    const error_marker = ",\"error\":";
    const end_idx = std.mem.indexOf(u8, json_rpc_response[value_start..], error_marker) orelse return null;

    return json_rpc_response[value_start .. value_start + end_idx];
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

/// Write script as disassembled opcodes (simplified ASM output).
fn writeScriptAsm(writer: anytype, script_bytes: []const u8) !void {
    var i: usize = 0;
    var first = true;
    while (i < script_bytes.len) {
        if (!first) try writer.writeByte(' ');
        first = false;

        const op = script_bytes[i];
        i += 1;

        if (op == 0) {
            try writer.writeAll("OP_0");
        } else if (op >= 1 and op <= 75) {
            // Direct push
            const len = op;
            if (i + len <= script_bytes.len) {
                for (script_bytes[i .. i + len]) |byte| {
                    try writer.print("{x:0>2}", .{byte});
                }
                i += len;
            }
        } else if (op == 0x4c) {
            // OP_PUSHDATA1
            if (i < script_bytes.len) {
                const len = script_bytes[i];
                i += 1;
                if (i + len <= script_bytes.len) {
                    for (script_bytes[i .. i + len]) |byte| {
                        try writer.print("{x:0>2}", .{byte});
                    }
                    i += len;
                }
            }
        } else if (op == 0x4d) {
            // OP_PUSHDATA2
            if (i + 2 <= script_bytes.len) {
                const len = @as(u16, script_bytes[i]) | (@as(u16, script_bytes[i + 1]) << 8);
                i += 2;
                if (i + len <= script_bytes.len) {
                    for (script_bytes[i .. i + len]) |byte| {
                        try writer.print("{x:0>2}", .{byte});
                    }
                    i += len;
                }
            }
        } else if (op == 0x51) {
            try writer.writeAll("OP_1");
        } else if (op >= 0x52 and op <= 0x60) {
            try writer.print("OP_{d}", .{op - 0x50});
        } else if (op == 0x76) {
            try writer.writeAll("OP_DUP");
        } else if (op == 0x87) {
            try writer.writeAll("OP_EQUAL");
        } else if (op == 0x88) {
            try writer.writeAll("OP_EQUALVERIFY");
        } else if (op == 0xa9) {
            try writer.writeAll("OP_HASH160");
        } else if (op == 0xac) {
            try writer.writeAll("OP_CHECKSIG");
        } else if (op == 0x6a) {
            try writer.writeAll("OP_RETURN");
        } else {
            try writer.print("0x{x:0>2}", .{op});
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "JSON-RPC result formatting" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

test "getblockchaininfo includes initialblockdownload field" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    // Set chain state with low chain work (should indicate IBD)
    chain_state.best_height = 100;
    chain_state.best_hash = [_]u8{0xAB} ** 32;
    chain_state.total_work = [_]u8{0x00} ** 32; // Zero work

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

    // Should contain the initialblockdownload field
    try std.testing.expect(std.mem.indexOf(u8, result, "\"initialblockdownload\"") != null);
    // With zero work, should be in IBD (true)
    try std.testing.expect(std.mem.indexOf(u8, result, "\"initialblockdownload\":true") != null);
}

test "getblockcount returns height" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

test "getdeploymentinfo regtest returns non-empty deployments with segwit and taproot" {
    // Verifies that getdeploymentinfo on regtest:
    //   - returns a valid JSON-RPC result (no error field populated)
    //   - includes "segwit" and "taproot" keys in the deployments object
    //   - marks both segwit and taproot as active (they activate at height 0 on regtest)
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.REGTEST,
        .{},
    );
    defer server.deinit();

    // No blockhash param — defaults to chain tip (height 0 on a fresh chain).
    const request = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getdeploymentinfo\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    // Must be a success response
    try std.testing.expect(std.mem.indexOf(u8, result, "\"error\":null") != null);

    // deployments object must not be empty
    try std.testing.expect(std.mem.indexOf(u8, result, "\"deployments\":{") != null);

    // segwit and taproot must be present
    try std.testing.expect(std.mem.indexOf(u8, result, "\"segwit\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"taproot\":{") != null);

    // On regtest both activate at height 0, so active=true at any height
    // We match the substring that appears inside the segwit object.
    try std.testing.expect(std.mem.indexOf(u8, result, "\"segwit\":{\"type\":\"buried\",\"active\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"taproot\":{\"type\":\"buried\",\"active\":true") != null);
}

test "getdeploymentinfo mainnet segwit and taproot not yet active at height 0" {
    // On mainnet at height 0, segwit (481824) and taproot (709632) are not yet
    // active.  The deployment objects must still be present but active=false.
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
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

    const request = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getdeploymentinfo\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"error\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"segwit\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"taproot\":{") != null);
    // At height 0 neither is active on mainnet
    try std.testing.expect(std.mem.indexOf(u8, result, "\"segwit\":{\"type\":\"buried\",\"active\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"taproot\":{\"type\":\"buried\",\"active\":false") != null);
}

test "getdeploymentinfo testdummy has bip9 type and defined status" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.REGTEST,
        .{},
    );
    defer server.deinit();

    const request = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getdeploymentinfo\",\"params\":[]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"error\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"testdummy\":{\"type\":\"bip9\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"status\":\"defined\"") != null);
}

test "getdeploymentinfo invalid blockhash returns error" {
    const allocator = std.testing.allocator;

    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    defer peer_manager.deinit();

    var server = RpcServer.init(
        allocator,
        &chain_state,
        &mempool,
        &peer_manager,
        &consensus.REGTEST,
        .{},
    );
    defer server.deinit();

    // 63-char hash (too short)
    const request = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getdeploymentinfo\",\"params\":[\"000000000000000000000000000000000000000000000000000000000000abc\"]}";
    const result = try server.dispatch(request);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"result\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Invalid block hash length") != null);
}
