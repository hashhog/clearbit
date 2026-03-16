const std = @import("std");
const crypto = @import("crypto.zig");
const address = @import("address.zig");
const wallet = @import("wallet.zig");
const miniscript = @import("miniscript.zig");
const builtin = @import("builtin");

// ============================================================================
// libsecp256k1 bindings (optional)
// ============================================================================
//
// To enable WIF and xpub/xprv key derivation in descriptors, build with:
//   zig build -Dsecp256k1=true
//
// Without -Dsecp256k1=true, descriptor parsing works but resolving keys
// from WIF or extended keys will return an error.
// ============================================================================

const secp256k1 = if (builtin.is_test or !@hasDecl(@import("root"), "secp256k1_enabled"))
    // Stub implementation for testing without libsecp256k1
    struct {
        pub const secp256k1_context = opaque {};
        pub const secp256k1_pubkey = extern struct {
            data: [64]u8,
        };
        pub const SECP256K1_CONTEXT_SIGN: c_uint = 0x0201;
        pub const SECP256K1_CONTEXT_VERIFY: c_uint = 0x0101;
        pub const SECP256K1_EC_COMPRESSED: c_uint = 0x0102;
        pub const SECP256K1_EC_UNCOMPRESSED: c_uint = 0x0002;

        // Stub functions that return failure
        pub fn secp256k1_context_create(_: c_uint) ?*secp256k1_context {
            return null;
        }
        pub fn secp256k1_ec_pubkey_create(_: ?*secp256k1_context, _: *secp256k1_pubkey, _: *const [32]u8) c_int {
            return 0;
        }
        pub fn secp256k1_ec_pubkey_serialize(_: ?*secp256k1_context, _: [*]u8, _: *usize, _: *const secp256k1_pubkey, _: c_uint) c_int {
            return 0;
        }
        pub fn secp256k1_ec_pubkey_parse(_: ?*secp256k1_context, _: *secp256k1_pubkey, _: [*]const u8, _: usize) c_int {
            return 0;
        }
        pub fn secp256k1_ec_seckey_tweak_add(_: ?*secp256k1_context, _: *[32]u8, _: *const [32]u8) c_int {
            return 0;
        }
        pub fn secp256k1_ec_pubkey_tweak_add(_: ?*secp256k1_context, _: *secp256k1_pubkey, _: *const [32]u8) c_int {
            return 0;
        }
    }
else
    // Real implementation via @cImport when secp256k1 is linked
    @cImport({
        @cInclude("secp256k1.h");
        @cInclude("secp256k1_extrakeys.h");
    });

// Thread-local secp256k1 context for descriptor key operations
var secp_ctx: ?*secp256k1.secp256k1_context = null;

fn getSecpContext() !*secp256k1.secp256k1_context {
    if (secp_ctx) |ctx| {
        return ctx;
    }
    secp_ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    ) orelse return error.Secp256k1NotAvailable;
    return secp_ctx.?;
}

// ============================================================================
// Output Descriptors (BIP-380 through BIP-386)
// ============================================================================
//
// Output descriptors are a language for describing collections of output scripts.
// They enable wallets to import/export address generation rules.
//
// Examples:
//   pk(KEY)           - P2PK
//   pkh(KEY)          - P2PKH
//   wpkh(KEY)         - P2WPKH (native segwit v0)
//   sh(wpkh(KEY))     - P2SH-P2WPKH (wrapped segwit)
//   wsh(SCRIPT)       - P2WSH (native segwit v0)
//   tr(KEY)           - P2TR (taproot key-path only)
//   tr(KEY,TREE)      - P2TR (taproot with script tree)
//   multi(k,KEY,...)  - k-of-n multisig
//   sortedmulti(...)  - sorted k-of-n multisig
//   addr(ADDRESS)     - raw address
//   raw(HEX)          - raw scriptPubKey
//   combo(KEY)        - all standard output types for a key

// ============================================================================
// Descriptor Checksum (BCH-based)
// ============================================================================

/// Input character set for descriptor checksum (positions in GF(32))
/// Designed so that common descriptor characters are in the first 32 positions
const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}" ++
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" ++
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// Checksum output character set (same as bech32)
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Compute the polymod for descriptor checksum
/// Based on a cyclic error-detecting code over GF(32)
fn polyMod(c: u64, val: u5) u64 {
    const c0: u8 = @truncate(c >> 35);
    var result = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1 != 0) result ^= 0xf5dee51989;
    if (c0 & 2 != 0) result ^= 0xa9fdca3312;
    if (c0 & 4 != 0) result ^= 0x1bab10e32d;
    if (c0 & 8 != 0) result ^= 0x3706b1677a;
    if (c0 & 16 != 0) result ^= 0x644d626ffd;
    return result;
}

/// Find position of character in INPUT_CHARSET
fn charsetPos(ch: u8) ?u8 {
    for (INPUT_CHARSET, 0..) |c, i| {
        if (c == ch) return @intCast(i);
    }
    return null;
}

/// Compute the 8-character checksum for a descriptor string
pub fn computeChecksum(desc: []const u8) ?[8]u8 {
    var c: u64 = 1;
    var cls: u8 = 0;
    var clscount: u8 = 0;

    for (desc) |ch| {
        const pos = charsetPos(ch) orelse return null;
        c = polyMod(c, @truncate(pos & 31));
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if (clscount == 3) {
            c = polyMod(c, @truncate(cls));
            cls = 0;
            clscount = 0;
        }
    }

    if (clscount > 0) c = polyMod(c, @truncate(cls));

    // Shift further to determine checksum
    for (0..8) |_| {
        c = polyMod(c, 0);
    }
    c ^= 1; // Prevent appending zeros from not affecting checksum

    var result: [8]u8 = undefined;
    for (0..8) |j| {
        const idx: u5 = @truncate(c >> @intCast(5 * (7 - j)));
        result[j] = CHECKSUM_CHARSET[idx];
    }
    return result;
}

/// Verify a descriptor checksum
pub fn verifyChecksum(desc_with_checksum: []const u8) bool {
    // Find the '#' separator
    const hash_pos = std.mem.lastIndexOf(u8, desc_with_checksum, "#") orelse return false;
    if (hash_pos + 9 != desc_with_checksum.len) return false;

    const desc = desc_with_checksum[0..hash_pos];
    const checksum = desc_with_checksum[hash_pos + 1 ..];

    const computed = computeChecksum(desc) orelse return false;
    return std.mem.eql(u8, &computed, checksum);
}

/// Add checksum to descriptor string
pub fn addChecksum(allocator: std.mem.Allocator, desc: []const u8) ![]const u8 {
    const checksum = computeChecksum(desc) orelse return error.InvalidDescriptorCharacter;
    const result = try allocator.alloc(u8, desc.len + 1 + 8);
    @memcpy(result[0..desc.len], desc);
    result[desc.len] = '#';
    @memcpy(result[desc.len + 1 ..][0..8], &checksum);
    return result;
}

// ============================================================================
// Key Expression Types
// ============================================================================

/// Origin info: [fingerprint/path]
pub const KeyOrigin = struct {
    fingerprint: [4]u8,
    path: []const u32,

    pub fn deinit(self: *KeyOrigin, allocator: std.mem.Allocator) void {
        if (self.path.len > 0) {
            allocator.free(self.path);
        }
    }

    pub fn format(self: KeyOrigin, allocator: std.mem.Allocator) ![]const u8 {
        var result = std.ArrayList(u8).init(allocator);
        errdefer result.deinit();

        try result.append('[');

        // Fingerprint as hex
        const hex_chars = "0123456789abcdef";
        for (self.fingerprint) |b| {
            try result.append(hex_chars[b >> 4]);
            try result.append(hex_chars[b & 0xf]);
        }

        // Path components
        for (self.path) |idx| {
            try result.append('/');
            const hardened = idx >= 0x80000000;
            const val = if (hardened) idx - 0x80000000 else idx;
            var buf: [16]u8 = undefined;
            const num_str = std.fmt.bufPrint(&buf, "{d}", .{val}) catch unreachable;
            try result.appendSlice(num_str);
            if (hardened) try result.append('\'');
        }

        try result.append(']');
        return result.toOwnedSlice();
    }
};

/// Derivation type for ranged keys
pub const DeriveType = enum {
    non_ranged, // No wildcard
    unhardened, // Ends with /*
    hardened, // Ends with /*' or /*h
};

/// Key expression types
pub const KeyExpression = union(enum) {
    /// Raw hex public key (33 or 65 bytes compressed/uncompressed)
    pubkey: struct {
        data: []const u8,
        x_only: bool, // For taproot (32 bytes)
    },
    /// WIF-encoded private key
    wif: []const u8,
    /// Extended public key (xpub/tpub)
    xpub: struct {
        key: []const u8, // Base58-encoded xpub
        path: []const u32, // Derivation path after xpub
        derive_type: DeriveType,
    },
    /// Extended private key (xprv/tprv)
    xprv: struct {
        key: []const u8, // Base58-encoded xprv
        path: []const u32, // Derivation path after xprv
        derive_type: DeriveType,
    },

    pub fn deinit(self: *KeyExpression, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .pubkey => |*p| allocator.free(p.data),
            .wif => |w| allocator.free(w),
            .xpub => |*x| {
                allocator.free(x.key);
                if (x.path.len > 0) allocator.free(x.path);
            },
            .xprv => |*x| {
                allocator.free(x.key);
                if (x.path.len > 0) allocator.free(x.path);
            },
        }
    }

    pub fn isRange(self: KeyExpression) bool {
        return switch (self) {
            .xpub => |x| x.derive_type != .non_ranged,
            .xprv => |x| x.derive_type != .non_ranged,
            else => false,
        };
    }
};

/// Full key with optional origin
pub const Key = struct {
    origin: ?KeyOrigin,
    key: KeyExpression,

    pub fn deinit(self: *Key, allocator: std.mem.Allocator) void {
        if (self.origin) |*o| o.deinit(allocator);
        self.key.deinit(allocator);
    }

    pub fn isRange(self: Key) bool {
        return self.key.isRange();
    }
};

// ============================================================================
// Multisig Descriptor
// ============================================================================

pub const MultiDescriptor = struct {
    threshold: u32,
    keys: []Key,
    sorted: bool,

    pub fn deinit(self: *MultiDescriptor, allocator: std.mem.Allocator) void {
        for (self.keys) |*k| k.deinit(allocator);
        allocator.free(self.keys);
    }
};

// ============================================================================
// Taproot Tree
// ============================================================================

/// Taproot script tree node
pub const TapLeaf = struct {
    depth: u8,
    script: *Descriptor,
};

/// Taproot descriptor
pub const TrDescriptor = struct {
    internal_key: Key,
    leaves: []TapLeaf,

    pub fn deinit(self: *TrDescriptor, allocator: std.mem.Allocator) void {
        self.internal_key.deinit(allocator);
        for (self.leaves) |*leaf| {
            leaf.script.deinit(allocator);
            allocator.destroy(leaf.script);
        }
        if (self.leaves.len > 0) allocator.free(self.leaves);
    }
};

// ============================================================================
// Main Descriptor Type
// ============================================================================

/// Miniscript descriptor for wsh() and tapscript
pub const MiniscriptDescriptor = struct {
    node: *miniscript.MiniNode,
    ctx: miniscript.ScriptContext,

    pub fn deinit(self: *MiniscriptDescriptor, allocator: std.mem.Allocator) void {
        self.node.deinit();
        allocator.destroy(self.node);
    }

    pub fn toScript(self: *const MiniscriptDescriptor, allocator: std.mem.Allocator) ![]u8 {
        return self.node.toScript(allocator, self.ctx);
    }

    pub fn maxWitnessSize(self: *MiniscriptDescriptor) u32 {
        return self.node.computeMaxWitnessSize(self.ctx);
    }

    pub fn isValid(self: *const MiniscriptDescriptor) bool {
        return self.node.isValidTopLevel(self.ctx);
    }

    pub fn isNonMalleable(self: *const MiniscriptDescriptor) bool {
        return self.node.isNonMalleable();
    }

    pub fn needsSignature(self: *const MiniscriptDescriptor) bool {
        return self.node.needsSignature();
    }
};

/// Output descriptor AST
pub const Descriptor = union(enum) {
    /// pk(KEY) - Pay to public key
    pk: Key,
    /// pkh(KEY) - Pay to public key hash
    pkh: Key,
    /// wpkh(KEY) - Pay to witness public key hash (native segwit v0)
    wpkh: Key,
    /// sh(SCRIPT) - Pay to script hash
    sh: *Descriptor,
    /// wsh(SCRIPT) - Pay to witness script hash (native segwit v0)
    wsh: *Descriptor,
    /// wsh with miniscript
    wsh_miniscript: MiniscriptDescriptor,
    /// tr(KEY) or tr(KEY,TREE) - Pay to taproot
    tr: TrDescriptor,
    /// multi(k,KEY,...) - k-of-n multisig
    multi: MultiDescriptor,
    /// sortedmulti(k,KEY,...) - sorted k-of-n multisig
    sorted_multi: MultiDescriptor,
    /// addr(ADDRESS) - raw address
    addr: []const u8,
    /// raw(HEX) - raw scriptPubKey
    raw: []const u8,
    /// combo(KEY) - all standard output types
    combo: Key,

    pub fn deinit(self: *Descriptor, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .pk => |*k| k.deinit(allocator),
            .pkh => |*k| k.deinit(allocator),
            .wpkh => |*k| k.deinit(allocator),
            .sh => |s| {
                s.deinit(allocator);
                allocator.destroy(s);
            },
            .wsh => |s| {
                s.deinit(allocator);
                allocator.destroy(s);
            },
            .wsh_miniscript => |*m| m.deinit(allocator),
            .tr => |*t| t.deinit(allocator),
            .multi => |*m| m.deinit(allocator),
            .sorted_multi => |*m| m.deinit(allocator),
            .addr => |a| allocator.free(a),
            .raw => |r| allocator.free(r),
            .combo => |*k| k.deinit(allocator),
        }
    }

    /// Check if this descriptor contains wildcards
    pub fn isRange(self: Descriptor) bool {
        return switch (self) {
            .pk => |k| k.isRange(),
            .pkh => |k| k.isRange(),
            .wpkh => |k| k.isRange(),
            .sh => |s| s.isRange(),
            .wsh => |s| s.isRange(),
            .wsh_miniscript => false, // Miniscript doesn't support ranged keys directly
            .tr => |t| blk: {
                if (t.internal_key.isRange()) break :blk true;
                for (t.leaves) |leaf| {
                    if (leaf.script.isRange()) break :blk true;
                }
                break :blk false;
            },
            .multi => |m| blk: {
                for (m.keys) |k| if (k.isRange()) break :blk true;
                break :blk false;
            },
            .sorted_multi => |m| blk: {
                for (m.keys) |k| if (k.isRange()) break :blk true;
                break :blk false;
            },
            .addr => false,
            .raw => false,
            .combo => |k| k.isRange(),
        };
    }

    /// Check if this descriptor uses miniscript
    pub fn isMiniscript(self: Descriptor) bool {
        return self == .wsh_miniscript;
    }
};

// ============================================================================
// Parser
// ============================================================================

pub const ParseError = error{
    UnexpectedEndOfInput,
    InvalidCharacter,
    InvalidDescriptorCharacter,
    ExpectedOpenParen,
    ExpectedCloseParen,
    ExpectedComma,
    InvalidFunctionName,
    InvalidKeyExpression,
    InvalidHexString,
    InvalidThreshold,
    InvalidAddress,
    InvalidPath,
    InvalidFingerprint,
    NestedShNotAllowed,
    NestedWshNotAllowed,
    UncompressedNotAllowed,
    OutOfMemory,
    BufferTooSmall,
};

/// Parser state
pub const Parser = struct {
    input: []const u8,
    pos: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, input: []const u8) Parser {
        return .{
            .input = input,
            .pos = 0,
            .allocator = allocator,
        };
    }

    fn peek(self: *Parser) ?u8 {
        if (self.pos >= self.input.len) return null;
        return self.input[self.pos];
    }

    fn advance(self: *Parser) ?u8 {
        if (self.pos >= self.input.len) return null;
        const c = self.input[self.pos];
        self.pos += 1;
        return c;
    }

    fn skipWhitespace(self: *Parser) void {
        while (self.peek()) |c| {
            if (c != ' ' and c != '\t' and c != '\n' and c != '\r') break;
            _ = self.advance();
        }
    }

    fn expect(self: *Parser, c: u8) !void {
        self.skipWhitespace();
        if (self.advance() != c) return error.InvalidCharacter;
    }

    fn readUntil(self: *Parser, delimiter: u8) []const u8 {
        const start = self.pos;
        while (self.peek()) |c| {
            if (c == delimiter) break;
            _ = self.advance();
        }
        return self.input[start..self.pos];
    }

    fn readIdentifier(self: *Parser) []const u8 {
        const start = self.pos;
        while (self.peek()) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '_') break;
            _ = self.advance();
        }
        return self.input[start..self.pos];
    }

    /// Parse a complete descriptor
    pub fn parse(self: *Parser) !Descriptor {
        self.skipWhitespace();
        return self.parseDescriptor(.top);
    }

    const Context = enum {
        top,
        sh,
        wsh,
        tr,
    };

    fn parseDescriptor(self: *Parser, ctx: Context) ParseError!Descriptor {
        const name = self.readIdentifier();

        if (std.mem.eql(u8, name, "pk")) {
            try self.expect('(');
            const key = try self.parseKey(ctx);
            try self.expect(')');
            return .{ .pk = key };
        } else if (std.mem.eql(u8, name, "pkh")) {
            try self.expect('(');
            const key = try self.parseKey(ctx);
            try self.expect(')');
            return .{ .pkh = key };
        } else if (std.mem.eql(u8, name, "wpkh")) {
            if (ctx == .sh) {
                // sh(wpkh(...)) is allowed
            } else if (ctx != .top) {
                return error.NestedWshNotAllowed;
            }
            try self.expect('(');
            const key = try self.parseKey(ctx);
            try self.expect(')');
            return .{ .wpkh = key };
        } else if (std.mem.eql(u8, name, "sh")) {
            if (ctx != .top) return error.NestedShNotAllowed;
            try self.expect('(');
            const inner = try self.allocator.create(Descriptor);
            errdefer self.allocator.destroy(inner);
            inner.* = try self.parseDescriptor(.sh);
            try self.expect(')');
            return .{ .sh = inner };
        } else if (std.mem.eql(u8, name, "wsh")) {
            if (ctx == .wsh) return error.NestedWshNotAllowed;
            try self.expect('(');
            const inner = try self.allocator.create(Descriptor);
            errdefer self.allocator.destroy(inner);
            inner.* = try self.parseDescriptor(.wsh);
            try self.expect(')');
            return .{ .wsh = inner };
        } else if (std.mem.eql(u8, name, "tr")) {
            try self.expect('(');
            const internal_key = try self.parseKey(.tr);

            var leaves = std.ArrayList(TapLeaf).init(self.allocator);
            errdefer {
                for (leaves.items) |*leaf| {
                    leaf.script.deinit(self.allocator);
                    self.allocator.destroy(leaf.script);
                }
                leaves.deinit();
            }

            // Check for optional script tree
            self.skipWhitespace();
            if (self.peek() == ',') {
                _ = self.advance();
                try self.parseTapTree(&leaves, 0);
            }

            try self.expect(')');
            return .{
                .tr = .{
                    .internal_key = internal_key,
                    .leaves = try leaves.toOwnedSlice(),
                },
            };
        } else if (std.mem.eql(u8, name, "multi")) {
            return self.parseMulti(false);
        } else if (std.mem.eql(u8, name, "sortedmulti")) {
            return self.parseMulti(true);
        } else if (std.mem.eql(u8, name, "addr")) {
            try self.expect('(');
            const addr_str = self.readUntil(')');
            const addr_copy = try self.allocator.dupe(u8, addr_str);
            try self.expect(')');
            return .{ .addr = addr_copy };
        } else if (std.mem.eql(u8, name, "raw")) {
            try self.expect('(');
            const hex_str = self.readUntil(')');
            // Validate hex
            for (hex_str) |c| {
                if (!std.ascii.isHex(c)) return error.InvalidHexString;
            }
            const hex_copy = try self.allocator.dupe(u8, hex_str);
            try self.expect(')');
            return .{ .raw = hex_copy };
        } else if (std.mem.eql(u8, name, "combo")) {
            try self.expect('(');
            const key = try self.parseKey(ctx);
            try self.expect(')');
            return .{ .combo = key };
        } else {
            return error.InvalidFunctionName;
        }
    }

    fn parseMulti(self: *Parser, sorted: bool) ParseError!Descriptor {
        try self.expect('(');

        // Parse threshold
        const threshold_str = self.readUntil(',');
        const threshold = std.fmt.parseInt(u32, threshold_str, 10) catch return error.InvalidThreshold;
        try self.expect(',');

        // Parse keys
        var keys = std.ArrayList(Key).init(self.allocator);
        errdefer {
            for (keys.items) |*k| k.deinit(self.allocator);
            keys.deinit();
        }

        while (true) {
            const key = try self.parseKey(.top);
            try keys.append(key);

            self.skipWhitespace();
            if (self.peek() == ')') break;
            try self.expect(',');
        }

        try self.expect(')');

        const multi = MultiDescriptor{
            .threshold = threshold,
            .keys = try keys.toOwnedSlice(),
            .sorted = sorted,
        };

        if (sorted) {
            return .{ .sorted_multi = multi };
        } else {
            return .{ .multi = multi };
        }
    }

    fn parseTapTree(self: *Parser, leaves: *std.ArrayList(TapLeaf), depth: u8) ParseError!void {
        self.skipWhitespace();

        if (self.peek() == '{') {
            // Branch node: {left,right}
            _ = self.advance();
            try self.parseTapTree(leaves, depth + 1);
            try self.expect(',');
            try self.parseTapTree(leaves, depth + 1);
            try self.expect('}');
        } else {
            // Leaf node: a script descriptor
            const script = try self.allocator.create(Descriptor);
            errdefer self.allocator.destroy(script);
            script.* = try self.parseDescriptor(.tr);
            try leaves.append(.{ .depth = depth, .script = script });
        }
    }

    fn parseKey(self: *Parser, ctx: Context) ParseError!Key {
        _ = ctx;
        self.skipWhitespace();

        var origin: ?KeyOrigin = null;

        // Check for origin info [fingerprint/path]
        if (self.peek() == '[') {
            origin = try self.parseOrigin();
        }

        // Parse the key itself
        const key_expr = try self.parseKeyExpression();

        return .{
            .origin = origin,
            .key = key_expr,
        };
    }

    fn parseOrigin(self: *Parser) ParseError!KeyOrigin {
        try self.expect('[');

        // Read fingerprint (8 hex chars = 4 bytes)
        var fingerprint: [4]u8 = undefined;
        for (0..4) |i| {
            const hi = self.advance() orelse return error.UnexpectedEndOfInput;
            const lo = self.advance() orelse return error.UnexpectedEndOfInput;
            const hi_val = hexDigit(hi) orelse return error.InvalidFingerprint;
            const lo_val = hexDigit(lo) orelse return error.InvalidFingerprint;
            fingerprint[i] = (@as(u8, hi_val) << 4) | lo_val;
        }

        // Parse path
        var path = std.ArrayList(u32).init(self.allocator);
        errdefer path.deinit();

        while (self.peek() == '/') {
            _ = self.advance();
            const idx = try self.parsePathComponent();
            try path.append(idx);
        }

        try self.expect(']');

        return .{
            .fingerprint = fingerprint,
            .path = try path.toOwnedSlice(),
        };
    }

    fn parsePathComponent(self: *Parser) ParseError!u32 {
        const start = self.pos;
        while (self.peek()) |c| {
            if (!std.ascii.isDigit(c)) break;
            _ = self.advance();
        }
        const num_str = self.input[start..self.pos];
        if (num_str.len == 0) return error.InvalidPath;

        const num = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidPath;

        // Check for hardened marker
        const hardened = if (self.peek()) |c| c == '\'' or c == 'h' else false;
        if (hardened) _ = self.advance();

        if (hardened) {
            return num | 0x80000000;
        } else {
            return num;
        }
    }

    fn parseKeyExpression(self: *Parser) ParseError!KeyExpression {
        self.skipWhitespace();
        const start = self.pos;

        // Find end of key expression
        while (self.peek()) |c| {
            if (c == ')' or c == ',' or c == ']' or c == '}' or c == '#') break;
            _ = self.advance();
        }

        const key_str = std.mem.trim(u8, self.input[start..self.pos], " \t\n\r");
        if (key_str.len == 0) return error.InvalidKeyExpression;

        // Check if it's an xpub/xprv (starts with x/t and contains derivation path)
        if (isExtendedKey(key_str)) {
            return self.parseExtendedKey(key_str);
        }

        // Check if it's a hex pubkey
        if (isHexPubkey(key_str)) {
            const x_only = key_str.len == 64; // 32 bytes = x-only for taproot
            const data = try self.allocator.dupe(u8, key_str);
            return .{ .pubkey = .{ .data = data, .x_only = x_only } };
        }

        // Assume it's a WIF private key
        const wif = try self.allocator.dupe(u8, key_str);
        return .{ .wif = wif };
    }

    fn parseExtendedKey(self: *Parser, key_str: []const u8) ParseError!KeyExpression {
        // Split on '/'
        var parts = std.mem.splitScalar(u8, key_str, '/');
        const base_key = parts.next() orelse return error.InvalidKeyExpression;

        // Determine if xpub or xprv
        const is_xprv = std.mem.startsWith(u8, base_key, "xprv") or
            std.mem.startsWith(u8, base_key, "tprv");

        var path = std.ArrayList(u32).init(self.allocator);
        errdefer path.deinit();

        var derive_type: DeriveType = .non_ranged;

        // Parse remaining path components
        while (parts.next()) |component| {
            if (std.mem.eql(u8, component, "*")) {
                derive_type = .unhardened;
            } else if (std.mem.eql(u8, component, "*'") or std.mem.eql(u8, component, "*h")) {
                derive_type = .hardened;
            } else {
                // Parse as path index
                const hardened = std.mem.endsWith(u8, component, "'") or
                    std.mem.endsWith(u8, component, "h");
                const num_str = if (hardened) component[0 .. component.len - 1] else component;
                const num = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidPath;
                const idx = if (hardened) num | 0x80000000 else num;
                try path.append(idx);
            }
        }

        const key_copy = try self.allocator.dupe(u8, base_key);
        const path_slice = try path.toOwnedSlice();

        if (is_xprv) {
            return .{ .xprv = .{ .key = key_copy, .path = path_slice, .derive_type = derive_type } };
        } else {
            return .{ .xpub = .{ .key = key_copy, .path = path_slice, .derive_type = derive_type } };
        }
    }
};

fn hexDigit(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @intCast(c - '0');
    if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @intCast(c - 'A' + 10);
    return null;
}

fn isExtendedKey(s: []const u8) bool {
    // Extended keys start with xpub, xprv, tpub, tprv
    if (s.len < 4) return false;
    const prefix = s[0..4];
    return std.mem.eql(u8, prefix, "xpub") or
        std.mem.eql(u8, prefix, "xprv") or
        std.mem.eql(u8, prefix, "tpub") or
        std.mem.eql(u8, prefix, "tprv");
}

fn isHexPubkey(s: []const u8) bool {
    // Hex pubkeys are 66 chars (33 bytes compressed) or 130 chars (65 bytes uncompressed)
    // or 64 chars (32 bytes x-only for taproot)
    if (s.len != 64 and s.len != 66 and s.len != 130) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

// ============================================================================
// Script Generation
// ============================================================================

/// Generate scriptPubKey from descriptor at a specific index (for ranged descriptors)
pub fn deriveScript(allocator: std.mem.Allocator, desc: *const Descriptor, index: u32) ![]u8 {
    var script = std.ArrayList(u8).init(allocator);
    errdefer script.deinit();

    switch (desc.*) {
        .pk => |key| {
            // P2PK: <pubkey> OP_CHECKSIG
            const pubkey = try resolveKeyToPubkey(allocator, key, index);
            defer allocator.free(pubkey);
            try pushData(&script, pubkey);
            try script.append(0xac); // OP_CHECKSIG
        },
        .pkh => |key| {
            // P2PKH: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
            const pubkey = try resolveKeyToPubkey(allocator, key, index);
            defer allocator.free(pubkey);
            const hash = crypto.hash160(pubkey);
            try script.append(0x76); // OP_DUP
            try script.append(0xa9); // OP_HASH160
            try script.append(0x14); // Push 20 bytes
            try script.appendSlice(&hash);
            try script.append(0x88); // OP_EQUALVERIFY
            try script.append(0xac); // OP_CHECKSIG
        },
        .wpkh => |key| {
            // P2WPKH: OP_0 <hash160>
            const pubkey = try resolveKeyToPubkey(allocator, key, index);
            defer allocator.free(pubkey);
            const hash = crypto.hash160(pubkey);
            try script.append(0x00); // OP_0
            try script.append(0x14); // Push 20 bytes
            try script.appendSlice(&hash);
        },
        .sh => |inner| {
            // P2SH: OP_HASH160 <hash160(redeem_script)> OP_EQUAL
            const redeem_script = try deriveScript(allocator, inner, index);
            defer allocator.free(redeem_script);
            const hash = crypto.hash160(redeem_script);
            try script.append(0xa9); // OP_HASH160
            try script.append(0x14); // Push 20 bytes
            try script.appendSlice(&hash);
            try script.append(0x87); // OP_EQUAL
        },
        .wsh => |inner| {
            // P2WSH: OP_0 <sha256(witness_script)>
            const witness_script = try deriveScript(allocator, inner, index);
            defer allocator.free(witness_script);
            const hash = crypto.sha256(witness_script);
            try script.append(0x00); // OP_0
            try script.append(0x20); // Push 32 bytes
            try script.appendSlice(&hash);
        },
        .wsh_miniscript => |m| {
            // P2WSH with miniscript: OP_0 <sha256(witness_script)>
            const witness_script = try m.node.toScript(allocator, m.ctx);
            defer allocator.free(witness_script);
            const hash = crypto.sha256(witness_script);
            try script.append(0x00); // OP_0
            try script.append(0x20); // Push 32 bytes
            try script.appendSlice(&hash);
        },
        .tr => |t| {
            // P2TR: OP_1 <x-only-pubkey>
            // For key-path only, output the tweaked key
            const pubkey = try resolveKeyToXOnlyPubkey(allocator, t.internal_key, index);
            defer allocator.free(pubkey);
            try script.append(0x51); // OP_1
            try script.append(0x20); // Push 32 bytes
            try script.appendSlice(pubkey);
        },
        .multi, .sorted_multi => |m| {
            // multisig: <threshold> <pubkey1> ... <pubkeyn> <n> OP_CHECKMULTISIG
            try script.append(@intCast(0x50 + m.threshold)); // OP_1..OP_16

            // Get all pubkeys
            var pubkeys = std.ArrayList([]const u8).init(allocator);
            defer {
                for (pubkeys.items) |pk| allocator.free(pk);
                pubkeys.deinit();
            }

            for (m.keys) |key| {
                const pk = try resolveKeyToPubkey(allocator, key, index);
                try pubkeys.append(pk);
            }

            // Sort if needed
            if (m.sorted) {
                std.mem.sort([]const u8, pubkeys.items, {}, struct {
                    fn cmp(_: void, a: []const u8, b: []const u8) bool {
                        return std.mem.order(u8, a, b) == .lt;
                    }
                }.cmp);
            }

            for (pubkeys.items) |pk| {
                try pushData(&script, pk);
            }

            try script.append(@intCast(0x50 + m.keys.len)); // OP_1..OP_16
            try script.append(0xae); // OP_CHECKMULTISIG
        },
        .addr => |addr_str| {
            // Decode address to scriptPubKey
            const spk = try decodeAddressToScript(allocator, addr_str);
            try script.appendSlice(spk);
            allocator.free(spk);
        },
        .raw => |hex_str| {
            // Decode hex to raw script
            const decoded = try decodeHex(allocator, hex_str);
            try script.appendSlice(decoded);
            allocator.free(decoded);
        },
        .combo => |key| {
            // combo() returns multiple scripts - for now just return P2PKH
            const pubkey = try resolveKeyToPubkey(allocator, key, index);
            defer allocator.free(pubkey);
            const hash = crypto.hash160(pubkey);
            try script.append(0x76); // OP_DUP
            try script.append(0xa9); // OP_HASH160
            try script.append(0x14); // Push 20 bytes
            try script.appendSlice(&hash);
            try script.append(0x88); // OP_EQUALVERIFY
            try script.append(0xac); // OP_CHECKSIG
        },
    }

    return script.toOwnedSlice();
}

fn pushData(script: *std.ArrayList(u8), data: []const u8) !void {
    if (data.len < 0x4c) {
        try script.append(@intCast(data.len));
    } else if (data.len <= 0xff) {
        try script.append(0x4c); // OP_PUSHDATA1
        try script.append(@intCast(data.len));
    } else if (data.len <= 0xffff) {
        try script.append(0x4d); // OP_PUSHDATA2
        try script.appendSlice(&std.mem.toBytes(@as(u16, @intCast(data.len))));
    } else {
        try script.append(0x4e); // OP_PUSHDATA4
        try script.appendSlice(&std.mem.toBytes(@as(u32, @intCast(data.len))));
    }
    try script.appendSlice(data);
}

/// Decode a WIF private key and derive the corresponding public key
fn decodeWifToPubkey(allocator: std.mem.Allocator, wif: []const u8) ![]const u8 {
    // Decode base58check
    const decoded = address.base58CheckDecode(wif, allocator) catch return error.InvalidKeyExpression;
    defer allocator.free(decoded.data);

    // WIF format: version(1) + privkey(32) + [compressed flag(1)]
    // Version 0x80 = mainnet, 0xEF = testnet
    if (decoded.version != 0x80 and decoded.version != 0xEF) {
        return error.InvalidKeyExpression;
    }

    var privkey: [32]u8 = undefined;
    var compressed = true;

    if (decoded.data.len == 32) {
        // Uncompressed key
        @memcpy(&privkey, decoded.data);
        compressed = false;
    } else if (decoded.data.len == 33 and decoded.data[32] == 0x01) {
        // Compressed key
        @memcpy(&privkey, decoded.data[0..32]);
    } else {
        return error.InvalidKeyExpression;
    }

    // Derive public key using secp256k1
    const ctx = try getSecpContext();

    var pubkey: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pubkey, &privkey) != 1) {
        return error.InvalidKeyExpression;
    }

    // Serialize public key
    if (compressed) {
        const result = try allocator.alloc(u8, 33);
        errdefer allocator.free(result);
        var len: usize = 33;
        _ = secp256k1.secp256k1_ec_pubkey_serialize(
            ctx,
            result.ptr,
            &len,
            &pubkey,
            secp256k1.SECP256K1_EC_COMPRESSED,
        );
        return result;
    } else {
        const result = try allocator.alloc(u8, 65);
        errdefer allocator.free(result);
        var len: usize = 65;
        _ = secp256k1.secp256k1_ec_pubkey_serialize(
            ctx,
            result.ptr,
            &len,
            &pubkey,
            secp256k1.SECP256K1_EC_UNCOMPRESSED,
        );
        return result;
    }
}

/// Decode extended key (xpub/xprv) and derive the public key at the specified index
fn decodeExtendedKeyToPubkey(allocator: std.mem.Allocator, key_str: []const u8, path: []const u32, derive_type: DeriveType, index: u32, is_xprv: bool) ![]const u8 {
    // Decode base58check
    const decoded = address.base58CheckDecode(key_str, allocator) catch return error.InvalidKeyExpression;
    defer allocator.free(decoded.data);

    // Extended key format: 4 bytes version + 1 byte depth + 4 bytes fingerprint +
    //                      4 bytes child number + 32 bytes chain code + 33 bytes key
    // Total: 78 bytes payload (version already stripped by base58CheckDecode)
    if (decoded.data.len != 77) {
        return error.InvalidKeyExpression;
    }

    // Parse extended key components
    // Bytes 0: depth
    // Bytes 1-4: parent fingerprint
    // Bytes 5-8: child number
    // Bytes 9-40: chain code (32 bytes)
    // Bytes 41-72: key (33 bytes) - for xprv: 0x00 + 32-byte key, for xpub: 33-byte pubkey
    const depth = decoded.data[0];
    _ = depth;
    const chain_code = decoded.data[9..41];
    const key_data = decoded.data[41..74];

    const ctx = try getSecpContext();

    // Start with the extended key's key material
    var current_chain_code: [32]u8 = undefined;
    @memcpy(&current_chain_code, chain_code);

    var current_key: [32]u8 = undefined;
    var current_pubkey: [33]u8 = undefined;

    if (is_xprv) {
        // xprv: key_data starts with 0x00, followed by 32-byte private key
        if (key_data[0] != 0x00) {
            return error.InvalidKeyExpression;
        }
        @memcpy(&current_key, key_data[1..33]);

        // Derive public key from private key
        var pubkey: secp256k1.secp256k1_pubkey = undefined;
        if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pubkey, &current_key) != 1) {
            return error.InvalidKeyExpression;
        }
        var len: usize = 33;
        _ = secp256k1.secp256k1_ec_pubkey_serialize(ctx, &current_pubkey, &len, &pubkey, secp256k1.SECP256K1_EC_COMPRESSED);
    } else {
        // xpub: key_data is 33-byte compressed public key
        @memcpy(&current_pubkey, key_data[0..33]);
    }

    // Derive along the path
    for (path) |child_index| {
        const hardened = child_index >= 0x80000000;

        if (hardened and !is_xprv) {
            // Cannot derive hardened child from public key
            return error.InvalidKeyExpression;
        }

        // Prepare data for HMAC
        var hmac_data: [37]u8 = undefined;
        if (hardened) {
            hmac_data[0] = 0x00;
            @memcpy(hmac_data[1..33], &current_key);
        } else {
            @memcpy(hmac_data[0..33], &current_pubkey);
        }
        std.mem.writeInt(u32, hmac_data[33..37], child_index, .big);

        // HMAC-SHA512
        const HmacSha512 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha512);
        var hmac_result: [64]u8 = undefined;
        HmacSha512.create(&hmac_result, &hmac_data, &current_chain_code);

        const il = hmac_result[0..32];
        @memcpy(&current_chain_code, hmac_result[32..64]);

        if (is_xprv) {
            // Add il to current private key (mod n)
            if (secp256k1.secp256k1_ec_seckey_tweak_add(ctx, &current_key, il) != 1) {
                return error.InvalidKeyExpression;
            }
            // Update public key
            var pubkey: secp256k1.secp256k1_pubkey = undefined;
            if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pubkey, &current_key) != 1) {
                return error.InvalidKeyExpression;
            }
            var len: usize = 33;
            _ = secp256k1.secp256k1_ec_pubkey_serialize(ctx, &current_pubkey, &len, &pubkey, secp256k1.SECP256K1_EC_COMPRESSED);
        } else {
            // Tweak public key by il
            var pubkey: secp256k1.secp256k1_pubkey = undefined;
            if (secp256k1.secp256k1_ec_pubkey_parse(ctx, &pubkey, &current_pubkey, 33) != 1) {
                return error.InvalidKeyExpression;
            }
            if (secp256k1.secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, il) != 1) {
                return error.InvalidKeyExpression;
            }
            var len: usize = 33;
            _ = secp256k1.secp256k1_ec_pubkey_serialize(ctx, &current_pubkey, &len, &pubkey, secp256k1.SECP256K1_EC_COMPRESSED);
        }
    }

    // Now handle the wildcard derivation at index
    if (derive_type != .non_ranged) {
        const child_index: u32 = if (derive_type == .hardened) index | 0x80000000 else index;
        const hardened = child_index >= 0x80000000;

        if (hardened and !is_xprv) {
            return error.InvalidKeyExpression;
        }

        var hmac_data: [37]u8 = undefined;
        if (hardened) {
            hmac_data[0] = 0x00;
            @memcpy(hmac_data[1..33], &current_key);
        } else {
            @memcpy(hmac_data[0..33], &current_pubkey);
        }
        std.mem.writeInt(u32, hmac_data[33..37], child_index, .big);

        const HmacSha512 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha512);
        var hmac_result: [64]u8 = undefined;
        HmacSha512.create(&hmac_result, &hmac_data, &current_chain_code);

        const il = hmac_result[0..32];

        if (is_xprv) {
            if (secp256k1.secp256k1_ec_seckey_tweak_add(ctx, &current_key, il) != 1) {
                return error.InvalidKeyExpression;
            }
            var pubkey: secp256k1.secp256k1_pubkey = undefined;
            if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pubkey, &current_key) != 1) {
                return error.InvalidKeyExpression;
            }
            var len: usize = 33;
            _ = secp256k1.secp256k1_ec_pubkey_serialize(ctx, &current_pubkey, &len, &pubkey, secp256k1.SECP256K1_EC_COMPRESSED);
        } else {
            var pubkey: secp256k1.secp256k1_pubkey = undefined;
            if (secp256k1.secp256k1_ec_pubkey_parse(ctx, &pubkey, &current_pubkey, 33) != 1) {
                return error.InvalidKeyExpression;
            }
            if (secp256k1.secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, il) != 1) {
                return error.InvalidKeyExpression;
            }
            var len: usize = 33;
            _ = secp256k1.secp256k1_ec_pubkey_serialize(ctx, &current_pubkey, &len, &pubkey, secp256k1.SECP256K1_EC_COMPRESSED);
        }
    }

    // Return the final public key
    const result = try allocator.alloc(u8, 33);
    @memcpy(result, &current_pubkey);
    return result;
}

/// Resolve a key expression to a public key at the given derivation index
fn resolveKeyToPubkey(allocator: std.mem.Allocator, key: Key, index: u32) ![]const u8 {
    switch (key.key) {
        .pubkey => |p| {
            // Decode hex pubkey
            return try decodeHex(allocator, p.data);
        },
        .wif => |wif| {
            return try decodeWifToPubkey(allocator, wif);
        },
        .xpub => |x| {
            return try decodeExtendedKeyToPubkey(allocator, x.key, x.path, x.derive_type, index, false);
        },
        .xprv => |x| {
            return try decodeExtendedKeyToPubkey(allocator, x.key, x.path, x.derive_type, index, true);
        },
    }
}

/// Resolve a key expression to an x-only public key (for taproot)
fn resolveKeyToXOnlyPubkey(allocator: std.mem.Allocator, key: Key, index: u32) ![]const u8 {
    // First get the full public key
    const pubkey = try resolveKeyToPubkey(allocator, key, index);
    defer allocator.free(pubkey);

    if (pubkey.len == 32) {
        // Already x-only
        const result = try allocator.alloc(u8, 32);
        @memcpy(result, pubkey);
        return result;
    } else if (pubkey.len == 33) {
        // Extract x-coordinate from compressed pubkey
        const result = try allocator.alloc(u8, 32);
        @memcpy(result, pubkey[1..33]);
        return result;
    } else if (pubkey.len == 65) {
        // Extract x-coordinate from uncompressed pubkey
        const result = try allocator.alloc(u8, 32);
        @memcpy(result, pubkey[1..33]);
        return result;
    }
    return error.InvalidKeyExpression;
}

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.InvalidHexString;
    const result = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(result);

    for (0..result.len) |i| {
        const hi = hexDigit(hex[i * 2]) orelse return error.InvalidHexString;
        const lo = hexDigit(hex[i * 2 + 1]) orelse return error.InvalidHexString;
        result[i] = (@as(u8, hi) << 4) | lo;
    }
    return result;
}

// ============================================================================
// Descriptor String Formatting
// ============================================================================

/// Convert descriptor to canonical string form
pub fn toString(allocator: std.mem.Allocator, desc: *const Descriptor) ![]const u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    try writeDescriptor(&result, desc);
    return result.toOwnedSlice();
}

/// Convert descriptor to string with checksum
pub fn toStringWithChecksum(allocator: std.mem.Allocator, desc: *const Descriptor) ![]const u8 {
    const str = try toString(allocator, desc);
    defer allocator.free(str);
    return addChecksum(allocator, str);
}

fn writeDescriptor(out: *std.ArrayList(u8), desc: *const Descriptor) !void {
    switch (desc.*) {
        .pk => |key| {
            try out.appendSlice("pk(");
            try writeKey(out, key);
            try out.append(')');
        },
        .pkh => |key| {
            try out.appendSlice("pkh(");
            try writeKey(out, key);
            try out.append(')');
        },
        .wpkh => |key| {
            try out.appendSlice("wpkh(");
            try writeKey(out, key);
            try out.append(')');
        },
        .sh => |inner| {
            try out.appendSlice("sh(");
            try writeDescriptor(out, inner);
            try out.append(')');
        },
        .wsh => |inner| {
            try out.appendSlice("wsh(");
            try writeDescriptor(out, inner);
            try out.append(')');
        },
        .wsh_miniscript => {
            // Miniscript descriptors use wsh() wrapper
            // Full serialization would need to walk the miniscript tree
            try out.appendSlice("wsh(...)");
        },
        .tr => |t| {
            try out.appendSlice("tr(");
            try writeKey(out, t.internal_key);
            if (t.leaves.len > 0) {
                try out.append(',');
                try writeTapTree(out, t.leaves);
            }
            try out.append(')');
        },
        .multi => |m| {
            try out.appendSlice("multi(");
            try writeMulti(out, m);
            try out.append(')');
        },
        .sorted_multi => |m| {
            try out.appendSlice("sortedmulti(");
            try writeMulti(out, m);
            try out.append(')');
        },
        .addr => |a| {
            try out.appendSlice("addr(");
            try out.appendSlice(a);
            try out.append(')');
        },
        .raw => |r| {
            try out.appendSlice("raw(");
            try out.appendSlice(r);
            try out.append(')');
        },
        .combo => |key| {
            try out.appendSlice("combo(");
            try writeKey(out, key);
            try out.append(')');
        },
    }
}

fn writeKey(out: *std.ArrayList(u8), key: Key) !void {
    // Write origin if present
    if (key.origin) |origin| {
        try out.append('[');
        const hex_chars = "0123456789abcdef";
        for (origin.fingerprint) |b| {
            try out.append(hex_chars[b >> 4]);
            try out.append(hex_chars[b & 0xf]);
        }
        for (origin.path) |idx| {
            try out.append('/');
            const hardened = idx >= 0x80000000;
            const val = if (hardened) idx - 0x80000000 else idx;
            var buf: [16]u8 = undefined;
            const num_str = std.fmt.bufPrint(&buf, "{d}", .{val}) catch unreachable;
            try out.appendSlice(num_str);
            if (hardened) try out.append('\'');
        }
        try out.append(']');
    }

    // Write key expression
    switch (key.key) {
        .pubkey => |p| try out.appendSlice(p.data),
        .wif => |w| try out.appendSlice(w),
        .xpub => |x| {
            try out.appendSlice(x.key);
            for (x.path) |idx| {
                try out.append('/');
                const hardened = idx >= 0x80000000;
                const val = if (hardened) idx - 0x80000000 else idx;
                var buf: [16]u8 = undefined;
                const num_str = std.fmt.bufPrint(&buf, "{d}", .{val}) catch unreachable;
                try out.appendSlice(num_str);
                if (hardened) try out.append('\'');
            }
            switch (x.derive_type) {
                .non_ranged => {},
                .unhardened => try out.appendSlice("/*"),
                .hardened => try out.appendSlice("/*'"),
            }
        },
        .xprv => |x| {
            try out.appendSlice(x.key);
            for (x.path) |idx| {
                try out.append('/');
                const hardened = idx >= 0x80000000;
                const val = if (hardened) idx - 0x80000000 else idx;
                var buf: [16]u8 = undefined;
                const num_str = std.fmt.bufPrint(&buf, "{d}", .{val}) catch unreachable;
                try out.appendSlice(num_str);
                if (hardened) try out.append('\'');
            }
            switch (x.derive_type) {
                .non_ranged => {},
                .unhardened => try out.appendSlice("/*"),
                .hardened => try out.appendSlice("/*'"),
            }
        },
    }
}

fn writeMulti(out: *std.ArrayList(u8), m: MultiDescriptor) !void {
    var buf: [16]u8 = undefined;
    const threshold_str = std.fmt.bufPrint(&buf, "{d}", .{m.threshold}) catch unreachable;
    try out.appendSlice(threshold_str);
    for (m.keys) |key| {
        try out.append(',');
        try writeKey(out, key);
    }
}

fn writeTapTree(out: *std.ArrayList(u8), leaves: []const TapLeaf) std.mem.Allocator.Error!void {
    // Simplified tree writing - proper implementation needs to reconstruct tree structure
    if (leaves.len == 1) {
        try writeDescriptor(out, leaves[0].script);
    } else if (leaves.len > 1) {
        try out.append('{');
        // Write first half
        const mid = leaves.len / 2;
        try writeTapTree(out, leaves[0..mid]);
        try out.append(',');
        // Write second half
        try writeTapTree(out, leaves[mid..]);
        try out.append('}');
    }
}

// ============================================================================
// High-level API
// ============================================================================

/// Parse a descriptor string (with or without checksum)
pub fn parseDescriptor(allocator: std.mem.Allocator, input: []const u8) !Descriptor {
    // Strip checksum if present
    var desc_str = input;
    if (std.mem.lastIndexOf(u8, input, "#")) |hash_pos| {
        // Verify checksum
        if (!verifyChecksum(input)) {
            return error.InvalidDescriptorCharacter;
        }
        desc_str = input[0..hash_pos];
    }

    var parser = Parser.init(allocator, desc_str);
    return parser.parse();
}

/// Get descriptor info (for getdescriptorinfo RPC)
pub const DescriptorInfo = struct {
    descriptor: []const u8, // Canonical descriptor with checksum
    checksum: [8]u8,
    is_range: bool,
    is_solvable: bool,
    has_private_keys: bool,
};

pub fn getDescriptorInfo(allocator: std.mem.Allocator, input: []const u8) !DescriptorInfo {
    var desc = try parseDescriptor(allocator, input);
    defer desc.deinit(allocator);

    const canonical = try toStringWithChecksum(allocator, &desc);
    defer allocator.free(canonical);

    // Extract checksum
    const hash_pos = std.mem.lastIndexOf(u8, canonical, "#") orelse return error.InvalidDescriptorCharacter;
    var checksum: [8]u8 = undefined;
    @memcpy(&checksum, canonical[hash_pos + 1 ..][0..8]);

    return .{
        .descriptor = try allocator.dupe(u8, canonical),
        .checksum = checksum,
        .is_range = desc.isRange(),
        .is_solvable = true, // Simplified - would need to check key availability
        .has_private_keys = hasPrivateKeys(&desc),
    };
}

pub fn hasPrivateKeys(desc: *const Descriptor) bool {
    return switch (desc.*) {
        .pk, .pkh, .wpkh, .combo => |k| k.key == .wif or k.key == .xprv,
        .sh, .wsh => |inner| hasPrivateKeys(inner),
        .wsh_miniscript => false, // Miniscript keys tracked separately
        .tr => |t| t.internal_key.key == .wif or t.internal_key.key == .xprv,
        .multi, .sorted_multi => |m| {
            for (m.keys) |k| {
                if (k.key == .wif or k.key == .xprv) return true;
            }
            return false;
        },
        .addr, .raw => false,
    };
}

/// Derive addresses from a descriptor (for deriveaddresses RPC)
pub fn deriveAddresses(
    allocator: std.mem.Allocator,
    input: []const u8,
    network: wallet.Network,
    range_start: u32,
    range_end: u32,
) ![][]const u8 {
    var desc = try parseDescriptor(allocator, input);
    defer desc.deinit(allocator);

    var addresses = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (addresses.items) |a| allocator.free(a);
        addresses.deinit();
    }

    const count = if (desc.isRange()) range_end - range_start else 1;

    for (0..count) |i| {
        const index = range_start + @as(u32, @intCast(i));
        const script = try deriveScript(allocator, &desc, index);
        defer allocator.free(script);

        const addr = try scriptToAddress(allocator, script, network);
        try addresses.append(addr);
    }

    return addresses.toOwnedSlice();
}

/// Decode an address string to its scriptPubKey
pub fn decodeAddressToScript(allocator: std.mem.Allocator, addr_str: []const u8) ![]u8 {
    // Use Address.decode from address module
    var addr = try address.Address.decode(addr_str, allocator);
    defer addr.deinit(allocator);

    var script = std.ArrayList(u8).init(allocator);
    errdefer script.deinit();

    switch (addr.addr_type) {
        .p2pkh => {
            try script.append(0x76); // OP_DUP
            try script.append(0xa9); // OP_HASH160
            try script.append(0x14); // Push 20 bytes
            try script.appendSlice(addr.hash);
            try script.append(0x88); // OP_EQUALVERIFY
            try script.append(0xac); // OP_CHECKSIG
        },
        .p2sh => {
            try script.append(0xa9); // OP_HASH160
            try script.append(0x14); // Push 20 bytes
            try script.appendSlice(addr.hash);
            try script.append(0x87); // OP_EQUAL
        },
        .p2wpkh => {
            try script.append(0x00); // OP_0
            try script.append(0x14); // Push 20 bytes
            try script.appendSlice(addr.hash);
        },
        .p2wsh => {
            try script.append(0x00); // OP_0
            try script.append(0x20); // Push 32 bytes
            try script.appendSlice(addr.hash);
        },
        .p2tr => {
            try script.append(0x51); // OP_1
            try script.append(0x20); // Push 32 bytes
            try script.appendSlice(addr.hash);
        },
    }

    return script.toOwnedSlice();
}

fn scriptToAddress(allocator: std.mem.Allocator, script: []const u8, network: wallet.Network) ![]const u8 {
    const hrp: []const u8 = switch (network) {
        .mainnet => "bc",
        .testnet => "tb",
        .regtest => "bcrt",
    };

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (script.len == 25 and script[0] == 0x76 and script[1] == 0xa9 and
        script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac)
    {
        const version: u8 = switch (network) {
            .mainnet => 0x00,
            .testnet, .regtest => 0x6f,
        };
        return address.base58CheckEncode(version, script[3..23], allocator);
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if (script.len == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87) {
        const version: u8 = switch (network) {
            .mainnet => 0x05,
            .testnet, .regtest => 0xc4,
        };
        return address.base58CheckEncode(version, script[2..22], allocator);
    }

    // P2WPKH: OP_0 <20 bytes>
    if (script.len == 22 and script[0] == 0x00 and script[1] == 0x14) {
        return address.segwitEncode(hrp, 0, script[2..22], allocator);
    }

    // P2WSH: OP_0 <32 bytes>
    if (script.len == 34 and script[0] == 0x00 and script[1] == 0x20) {
        return address.segwitEncode(hrp, 0, script[2..34], allocator);
    }

    // P2TR: OP_1 <32 bytes>
    if (script.len == 34 and script[0] == 0x51 and script[1] == 0x20) {
        return address.segwitEncode(hrp, 1, script[2..34], allocator);
    }

    return error.InvalidAddress;
}

// ============================================================================
// Tests
// ============================================================================

test "descriptor checksum computation" {
    const allocator = std.testing.allocator;

    // Test vectors from Bitcoin Core
    const test_cases = [_]struct { desc: []const u8, expected: []const u8 }{
        .{ .desc = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", .expected = "gn28ywm7" },
        .{ .desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)", .expected = "8fhd9pwu" },
        .{ .desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)", .expected = "8zl0zxma" },
        .{ .desc = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)", .expected = "hzhjw406" },
    };

    for (test_cases) |tc| {
        const checksum = computeChecksum(tc.desc) orelse {
            try std.testing.expect(false);
            continue;
        };
        try std.testing.expectEqualStrings(tc.expected, &checksum);

        // Test with checksum
        const with_checksum = try addChecksum(allocator, tc.desc);
        defer allocator.free(with_checksum);
        try std.testing.expect(verifyChecksum(with_checksum));
    }
}

test "parse simple pk descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .pk);
    try std.testing.expect(desc.pk.origin == null);
    try std.testing.expect(desc.pk.key == .pubkey);
}

test "parse pkh descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .pkh);
}

test "parse wpkh descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .wpkh);
}

test "parse sh(wpkh) descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .sh);
    try std.testing.expect(desc.sh.* == .wpkh);
}

test "parse multi descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "multi(2,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .multi);
    try std.testing.expectEqual(@as(u32, 2), desc.multi.threshold);
    try std.testing.expectEqual(@as(usize, 2), desc.multi.keys.len);
}

test "parse sortedmulti descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "sortedmulti(2,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .sorted_multi);
    try std.testing.expect(desc.sorted_multi.sorted);
}

test "parse tr descriptor" {
    const allocator = std.testing.allocator;

    // Simple key-path only taproot
    var desc = try parseDescriptor(allocator, "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .tr);
    try std.testing.expectEqual(@as(usize, 0), desc.tr.leaves.len);
}

test "parse descriptor with origin" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .pkh);
    try std.testing.expect(desc.pkh.origin != null);

    const origin = desc.pkh.origin.?;
    try std.testing.expectEqual(@as(u8, 0xd3), origin.fingerprint[0]);
    try std.testing.expectEqual(@as(u8, 0x4d), origin.fingerprint[1]);
    try std.testing.expectEqual(@as(u8, 0xb3), origin.fingerprint[2]);
    try std.testing.expectEqual(@as(u8, 0x3f), origin.fingerprint[3]);
}

test "parse raw descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "raw(76a914000000000000000000000000000000000000000088ac)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .raw);
}

test "parse addr descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .addr);
}

test "descriptor isRange" {
    const allocator = std.testing.allocator;

    // Non-ranged descriptor
    var desc1 = try parseDescriptor(allocator, "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)");
    defer desc1.deinit(allocator);
    try std.testing.expect(!desc1.isRange());

    // Ranged descriptor with wildcard
    var desc2 = try parseDescriptor(allocator, "pkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)");
    defer desc2.deinit(allocator);
    try std.testing.expect(desc2.isRange());
}

test "descriptor toString roundtrip" {
    const allocator = std.testing.allocator;

    const test_cases = [_][]const u8{
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        "multi(2,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)",
    };

    for (test_cases) |tc| {
        var desc = try parseDescriptor(allocator, tc);
        defer desc.deinit(allocator);

        const str = try toString(allocator, &desc);
        defer allocator.free(str);

        try std.testing.expectEqualStrings(tc, str);
    }
}

test "verify known checksums" {
    // Test with known valid checksums
    try std.testing.expect(verifyChecksum("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7"));
    try std.testing.expect(verifyChecksum("pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#8fhd9pwu"));
    try std.testing.expect(verifyChecksum("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#8zl0zxma"));

    // Test with invalid checksums
    try std.testing.expect(!verifyChecksum("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#xxxxxxxx"));
    try std.testing.expect(!verifyChecksum("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm8"));
}

test "parse wsh descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "wsh(pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .wsh);
    try std.testing.expect(desc.wsh.* == .pk);
}

test "parse sh(wsh) descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "sh(wsh(pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .sh);
    try std.testing.expect(desc.sh.* == .wsh);
}

test "parse tr descriptor with script tree" {
    const allocator = std.testing.allocator;

    // tr(KEY,{SCRIPT,SCRIPT}) format
    var desc = try parseDescriptor(allocator, "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .tr);
    try std.testing.expectEqual(@as(usize, 2), desc.tr.leaves.len);
}

test "parse combo descriptor" {
    const allocator = std.testing.allocator;

    var desc = try parseDescriptor(allocator, "combo(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .combo);
}

test "getDescriptorInfo" {
    const allocator = std.testing.allocator;

    const info = try getDescriptorInfo(allocator, "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)");
    defer allocator.free(info.descriptor);

    try std.testing.expect(!info.is_range);
    try std.testing.expect(info.is_solvable);
    try std.testing.expect(!info.has_private_keys);
    try std.testing.expectEqualStrings("8fhd9pwu", &info.checksum);
}

test "miniscript descriptor integration" {
    const allocator = std.testing.allocator;

    // Parse a miniscript expression
    const node = try miniscript.parse(
        allocator,
        "and_v(v:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),older(144))",
        .p2wsh,
    );

    // Create a wsh_miniscript descriptor
    var desc = Descriptor{
        .wsh_miniscript = .{
            .node = node,
            .ctx = .p2wsh,
        },
    };
    defer desc.deinit(allocator);

    // Verify descriptor properties
    try std.testing.expect(!desc.isRange());
    try std.testing.expect(desc.isMiniscript());
    try std.testing.expect(!hasPrivateKeys(&desc));

    // Compile to scriptPubKey (P2WSH)
    const script_pubkey = try deriveScript(allocator, &desc, 0);
    defer allocator.free(script_pubkey);

    // P2WSH: OP_0 <32-byte hash>
    try std.testing.expectEqual(@as(usize, 34), script_pubkey.len);
    try std.testing.expectEqual(@as(u8, 0x00), script_pubkey[0]); // OP_0
    try std.testing.expectEqual(@as(u8, 0x20), script_pubkey[1]); // push 32
}

test "miniscript descriptor analysis" {
    const allocator = std.testing.allocator;

    const node = try miniscript.parse(
        allocator,
        "multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        .p2wsh,
    );

    var mini_desc = MiniscriptDescriptor{
        .node = node,
        .ctx = .p2wsh,
    };
    defer mini_desc.deinit(allocator);

    // Check properties
    try std.testing.expect(mini_desc.isValid());
    try std.testing.expect(mini_desc.needsSignature());

    // Witness size should be k signatures + dummy
    const witness_size = mini_desc.maxWitnessSize();
    try std.testing.expect(witness_size > 0);
}

test "derive P2PKH script from hex pubkey descriptor" {
    const allocator = std.testing.allocator;

    // Parse a pkh descriptor with hex pubkey
    var desc = try parseDescriptor(allocator, "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)");
    defer desc.deinit(allocator);

    // Derive the scriptPubKey
    const script = try deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    try std.testing.expectEqual(@as(usize, 25), script.len);
    try std.testing.expectEqual(@as(u8, 0x76), script[0]); // OP_DUP
    try std.testing.expectEqual(@as(u8, 0xa9), script[1]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[2]); // Push 20 bytes
    try std.testing.expectEqual(@as(u8, 0x88), script[23]); // OP_EQUALVERIFY
    try std.testing.expectEqual(@as(u8, 0xac), script[24]); // OP_CHECKSIG
}

test "derive P2WPKH script from hex pubkey descriptor" {
    const allocator = std.testing.allocator;

    // Parse a wpkh descriptor with hex pubkey
    var desc = try parseDescriptor(allocator, "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)");
    defer desc.deinit(allocator);

    // Derive the scriptPubKey
    const script = try deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // P2WPKH: OP_0 <20 bytes>
    try std.testing.expectEqual(@as(usize, 22), script.len);
    try std.testing.expectEqual(@as(u8, 0x00), script[0]); // OP_0
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20 bytes
}

test "derive P2SH-P2WPKH script from descriptor" {
    const allocator = std.testing.allocator;

    // Parse a sh(wpkh()) descriptor
    var desc = try parseDescriptor(allocator, "sh(wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))");
    defer desc.deinit(allocator);

    // Derive the scriptPubKey
    const script = try deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    try std.testing.expectEqual(@as(usize, 23), script.len);
    try std.testing.expectEqual(@as(u8, 0xa9), script[0]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20 bytes
    try std.testing.expectEqual(@as(u8, 0x87), script[22]); // OP_EQUAL
}

test "derive P2TR script from x-only pubkey descriptor" {
    const allocator = std.testing.allocator;

    // Parse a tr descriptor with 32-byte x-only pubkey
    var desc = try parseDescriptor(allocator, "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)");
    defer desc.deinit(allocator);

    // Derive the scriptPubKey
    const script = try deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // P2TR: OP_1 <32 bytes>
    try std.testing.expectEqual(@as(usize, 34), script.len);
    try std.testing.expectEqual(@as(u8, 0x51), script[0]); // OP_1
    try std.testing.expectEqual(@as(u8, 0x20), script[1]); // Push 32 bytes
}

test "parse and resolve WIF key requires secp256k1" {
    const allocator = std.testing.allocator;

    // Parse a descriptor with a WIF key
    // This is a testnet WIF key
    var desc = try parseDescriptor(allocator, "pkh(cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .pkh);
    try std.testing.expect(desc.pkh.key == .wif);

    // Attempting to derive the script will fail without secp256k1
    // (in test mode, the stub implementation returns null context)
    const result = deriveScript(allocator, &desc, 0);
    try std.testing.expectError(error.Secp256k1NotAvailable, result);
}

test "parse xpub descriptor with derivation path" {
    const allocator = std.testing.allocator;

    // Parse an xpub descriptor with derivation path
    var desc = try parseDescriptor(allocator, "pkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .pkh);
    try std.testing.expect(desc.pkh.key == .xpub);
    try std.testing.expect(desc.isRange()); // Has wildcard

    const xpub_key = desc.pkh.key.xpub;
    try std.testing.expectEqual(@as(usize, 1), xpub_key.path.len);
    try std.testing.expectEqual(@as(u32, 0), xpub_key.path[0]);
    try std.testing.expect(xpub_key.derive_type == .unhardened);
}

test "parse xpub descriptor non-ranged" {
    const allocator = std.testing.allocator;

    // Parse an xpub descriptor without wildcard
    var desc = try parseDescriptor(allocator, "pkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/1)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .pkh);
    try std.testing.expect(desc.pkh.key == .xpub);
    try std.testing.expect(!desc.isRange()); // No wildcard

    const xpub_key = desc.pkh.key.xpub;
    try std.testing.expectEqual(@as(usize, 2), xpub_key.path.len);
    try std.testing.expect(xpub_key.derive_type == .non_ranged);
}

test "descriptor checksum case sensitivity" {
    // Checksum should be case-sensitive for letters
    // Valid descriptor with valid checksum
    try std.testing.expect(verifyChecksum("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7"));

    // Invalid: wrong case in checksum
    try std.testing.expect(!verifyChecksum("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#GN28YWM7"));
}

test "importdescriptors format parsing" {
    const allocator = std.testing.allocator;

    // Test that descriptors from importdescriptors RPC work
    const desc_str = "wpkh([d34db33f/84'/0'/0']xpub6CUGRUonZSQ4TWtTMmzXdrXDtyEWKnTaKNkJmxGhaDFSzFx7qkJKvFPGX2H5n8qjRNqM7VqDnkKxNvCgrPVL7GBhE5MSnFVnAJB3MH82K1M/0/*)";
    var desc = try parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .wpkh);
    try std.testing.expect(desc.wpkh.origin != null);
    try std.testing.expect(desc.wpkh.key == .xpub);
    try std.testing.expect(desc.isRange());

    const origin = desc.wpkh.origin.?;
    try std.testing.expectEqual(@as(usize, 3), origin.path.len);
    // 84' = 84 | 0x80000000
    try std.testing.expectEqual(@as(u32, 84 | 0x80000000), origin.path[0]);
}
