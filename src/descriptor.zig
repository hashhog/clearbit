const std = @import("std");
const crypto = @import("crypto.zig");
const address = @import("address.zig");
const wallet = @import("wallet.zig");
const miniscript = @import("miniscript.zig");
const builtin = @import("builtin");
const secp = @import("secp.zig");

// ============================================================================
// libsecp256k1 bindings
// ============================================================================
//
// Phase 2 (clearbit unfreeze plan): this module previously carried its own
// `@cImport` block for libsecp256k1, producing a distinct opaque-type tree
// from `wallet.zig` / `crypto.zig` / `v2_transport.zig`. We now alias
// `secp.c` (the single tree-wide cImport) so every `secp256k1_context` /
// `secp256k1_pubkey` produced here has the same compile-time identity as
// every other module's. See `src/secp.zig` for design rationale.
//
// Test builds: the central `secp.zig` test stub already covers the call
// sites we use here (`secp256k1_ec_pubkey_create`, `_parse`, `_serialize`,
// `_seckey_tweak_add`, `_pubkey_tweak_add`, `_context_randomize`).
// ============================================================================

const secp256k1 = secp.c;

fn getSecpContext() !*secp.Context {
    return secp.context() orelse error.Secp256k1NotAvailable;
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
    /// rawtr(XONLY_HEX) - raw taproot key-spend (BIP-386)
    rawtr: []const u8,
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
            .rawtr => |r| allocator.free(r),
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
            .rawtr => false,
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
    /// multi()/sortedmulti() key count outside 1..MAX_PUBKEYS_PER_MULTISIG.
    MultiKeyCount,
    /// multi()/sortedmulti() threshold of 0.
    MultiThresholdZero,
    /// multi()/sortedmulti() threshold larger than the key count.
    MultiThresholdTooLarge,
    /// Top-level (bare) multi()/sortedmulti() with more than 3 keys.
    BareMultiTooManyKeys,
    /// sh(multi()) redeem script larger than MAX_SCRIPT_ELEMENT_SIZE.
    P2shScriptTooLarge,
    OutOfMemory,
    BufferTooSmall,
};

/// Core MAX_PUBKEYS_PER_MULTISIG (script/script.h).
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
/// Core MAX_SCRIPT_ELEMENT_SIZE (script/script.h); bounds an sh() redeem script.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Optional human-readable reason for a parse failure, worded as Core's
/// ParseScript error string so RPCs can return it verbatim. Only set for the
/// errors that carry one (today: the multi() bounds).
pub const Diagnostic = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const Diagnostic) ?[]const u8 {
        if (self.len == 0) return null;
        return self.buf[0..self.len];
    }

    fn set(self: *Diagnostic, comptime fmt: []const u8, args: anytype) void {
        const out = std.fmt.bufPrint(&self.buf, fmt, args) catch {
            self.len = 0;
            return;
        };
        self.len = out.len;
    }
};

/// Parser state
pub const Parser = struct {
    input: []const u8,
    pos: usize,
    allocator: std.mem.Allocator,
    diag: ?*Diagnostic = null,

    pub fn init(allocator: std.mem.Allocator, input: []const u8) Parser {
        return .{
            .input = input,
            .pos = 0,
            .allocator = allocator,
        };
    }

    fn fail(self: *Parser, err: ParseError, comptime fmt: []const u8, args: anytype) ParseError {
        if (self.diag) |d| d.set(fmt, args);
        return err;
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
            return self.parseMulti(false, ctx);
        } else if (std.mem.eql(u8, name, "sortedmulti")) {
            return self.parseMulti(true, ctx);
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
        } else if (std.mem.eql(u8, name, "rawtr")) {
            // rawtr(XONLY_HEX) - BIP-386: raw taproot x-only pubkey key-spend
            // The argument is a 32-byte x-only pubkey as 64 hex chars.
            try self.expect('(');
            const hex_str = self.readUntil(')');
            // Validate: must be exactly 64 lowercase hex chars (32 bytes x-only pubkey)
            if (hex_str.len != 64) return error.InvalidKeyExpression;
            for (hex_str) |c| {
                if (!std.ascii.isHex(c)) return error.InvalidKeyExpression;
            }
            const hex_copy = try self.allocator.dupe(u8, hex_str);
            try self.expect(')');
            return .{ .rawtr = hex_copy };
        } else if (std.mem.eql(u8, name, "combo")) {
            try self.expect('(');
            const key = try self.parseKey(ctx);
            try self.expect(')');
            return .{ .combo = key };
        } else {
            return error.InvalidFunctionName;
        }
    }

    fn parseMulti(self: *Parser, sorted: bool, ctx: Context) ParseError!Descriptor {
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

        // Core ParseScript (script/descriptor.cpp), same check order: key
        // count, threshold >= 1, threshold <= n, bare n <= 3, then the sh()
        // redeem-script size. Without these, deriveScript encoded k=0 as
        // OP_RESERVED (0x50), n in 17..20 as OP_NOP-range bytes, and k or
        // n >= 176 overflowed the u8 in @intCast (UB in ReleaseFast).
        const n = keys.items.len;
        if (n == 0 or n > MAX_PUBKEYS_PER_MULTISIG) {
            return self.fail(error.MultiKeyCount, "Cannot have {d} keys in multisig; must have between 1 and {d} keys, inclusive", .{ n, MAX_PUBKEYS_PER_MULTISIG });
        }
        if (threshold < 1) {
            return self.fail(error.MultiThresholdZero, "Multisig threshold cannot be {d}, must be at least 1", .{threshold});
        }
        if (threshold > n) {
            return self.fail(error.MultiThresholdTooLarge, "Multisig threshold cannot be larger than the number of keys; threshold is {d} but only {d} keys specified", .{ threshold, n });
        }
        if (ctx == .top and n > 3) {
            return self.fail(error.BareMultiTooManyKeys, "Cannot have {d} pubkeys in bare multisig; only at most 3 pubkeys", .{n});
        }
        if (ctx == .sh) {
            // Core: script_size = sum(pubkey size + 1 push byte), plus 3 for
            // <k> <n> OP_CHECKMULTISIG. Limits compressed keys to 15.
            var script_size: usize = 0;
            for (keys.items) |k| script_size += multiKeySize(k.key) + 1;
            if (script_size + 3 > MAX_SCRIPT_ELEMENT_SIZE) {
                return self.fail(error.P2shScriptTooLarge, "P2SH script is too large, {d} bytes is larger than {d} bytes", .{ script_size + 3, MAX_SCRIPT_ELEMENT_SIZE });
            }
        }

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

/// BIP-341 tapleaf version for tapscript (Core TAPROOT_LEAF_TAPSCRIPT).
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Core TAPROOT_CONTROL_MAX_NODE_COUNT: deepest allowed leaf.
const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;

/// Leaf script of a tr() sub-descriptor. Inside tapscript every key is
/// x-only (Core ParseScriptContext::P2TR): pk(K) is `<32-byte K> OP_CHECKSIG`
/// and pkh(K) (miniscript pkh) hashes the 32-byte x-only key. Any other leaf
/// type is refused rather than hashed into a wrong (unspendable) output key.
fn deriveTapLeafScript(allocator: std.mem.Allocator, leaf: *const Descriptor, index: u32) ![]u8 {
    var script = std.ArrayList(u8).init(allocator);
    errdefer script.deinit();
    switch (leaf.*) {
        .pk => |key| {
            const xonly = try resolveKeyToXOnlyPubkey(allocator, key, index);
            defer allocator.free(xonly);
            if (xonly.len != 32) return error.InvalidKeyExpression;
            try script.append(0x20);
            try script.appendSlice(xonly);
            try script.append(0xac); // OP_CHECKSIG
        },
        .pkh => |key| {
            const xonly = try resolveKeyToXOnlyPubkey(allocator, key, index);
            defer allocator.free(xonly);
            if (xonly.len != 32) return error.InvalidKeyExpression;
            const hash = crypto.hash160(xonly);
            try script.append(0x76); // OP_DUP
            try script.append(0xa9); // OP_HASH160
            try script.append(0x14);
            try script.appendSlice(&hash);
            try script.append(0x88); // OP_EQUALVERIFY
            try script.append(0xac); // OP_CHECKSIG
        },
        else => return error.UnsupportedTapLeaf,
    }
    return script.toOwnedSlice();
}

fn tapBranchHash(a: *const [32]u8, b: *const [32]u8) [32]u8 {
    var buf: [64]u8 = undefined;
    // BIP-341: children are sorted lexicographically before hashing.
    if (std.mem.order(u8, a, b) == .lt) {
        @memcpy(buf[0..32], a);
        @memcpy(buf[32..64], b);
    } else {
        @memcpy(buf[0..32], b);
        @memcpy(buf[32..64], a);
    }
    return crypto.taggedHash("TapBranch", &buf);
}

/// Merkle root of a tr() script tree given its leaves in depth-first order
/// with their depths, as Core's TaprootBuilder::Add/Finalize builds it: each
/// leaf is placed at its depth and merged upward with any sibling already
/// waiting at that depth.
fn computeTapTreeMerkleRoot(allocator: std.mem.Allocator, leaves: []const TapLeaf, index: u32) ![32]u8 {
    var pending: [TAPROOT_CONTROL_MAX_NODE_COUNT + 1]?[32]u8 = .{null} ** (TAPROOT_CONTROL_MAX_NODE_COUNT + 1);
    var complete = false;
    for (leaves) |leaf| {
        if (complete) return error.InvalidTapTree;
        if (leaf.depth > TAPROOT_CONTROL_MAX_NODE_COUNT) return error.InvalidTapTree;
        const leaf_script = try deriveTapLeafScript(allocator, leaf.script, index);
        defer allocator.free(leaf_script);
        var node = crypto.computeTapleafHash(leaf_script, TAPROOT_LEAF_TAPSCRIPT) orelse return error.InvalidTapTree;
        var d: usize = leaf.depth;
        while (true) {
            if (pending[d]) |sibling| {
                pending[d] = null;
                node = tapBranchHash(&sibling, &node);
                if (d == 0) return error.InvalidTapTree;
                d -= 1;
            } else {
                pending[d] = node;
                break;
            }
        }
        if (d == 0) complete = true;
    }
    if (!complete) return error.InvalidTapTree;
    for (pending[1..]) |p| if (p != null) return error.InvalidTapTree;
    return pending[0].?;
}

/// Q = P + int(H_TapTweak(P || merkle_root))·G, x-only (BIP-341).
fn tapTweakXOnlyWithRoot(ctx: *secp.Context, internal_xonly: *const [32]u8, merkle_root: *const [32]u8) ![32]u8 {
    var internal: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_parse(ctx, &internal, internal_xonly) != 1) {
        return error.InvalidInternalKey;
    }
    var data: [64]u8 = undefined;
    @memcpy(data[0..32], internal_xonly);
    @memcpy(data[32..64], merkle_root);
    const tweak = crypto.taggedHash("TapTweak", &data);
    var tweaked_full: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full, &internal, &tweak) != 1) {
        return error.TaprootTweakFailed;
    }
    var tweaked_xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, null, &tweaked_full) != 1) {
        return error.TaprootTweakFailed;
    }
    var out: [32]u8 = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_serialize(ctx, &out, &tweaked_xonly) != 1) {
        return error.TaprootTweakFailed;
    }
    return out;
}

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
            // P2TR: OP_1 <32-byte TWEAKED output key>.
            // BIP-341/BIP-86: the on-chain key is NOT the raw internal key P —
            // it is Q = P + int(H_TapTweak(P))·G, with an EMPTY merkle root for a
            // key-path-only tr(KEY) descriptor. Emitting the untweaked internal
            // key yields the wrong (Core-unspendable) address. Cross-ref:
            // bitcoin-core/src/key.cpp ComputeTapTweakHash + script/descriptor.cpp.
            const internal_xonly = try resolveKeyToXOnlyPubkey(allocator, t.internal_key, index);
            defer allocator.free(internal_xonly);
            if (internal_xonly.len != 32) return error.InvalidKeyExpression;
            var ik: [32]u8 = undefined;
            @memcpy(&ik, internal_xonly);
            const ctx = try getSecpContext();
            // tr(KEY,TREE): the output key commits to the script tree, so the
            // tweak is H_TapTweak(P || merkle_root) (Core TRDescriptor::
            // MakeScripts → TaprootBuilder::Finalize). Only a key-path-only
            // tr(KEY) uses the empty-root BIP-86 tweak.
            const output_key = if (t.leaves.len == 0)
                try wallet.bip86TweakXOnly(ctx, &ik)
            else blk: {
                const root = try computeTapTreeMerkleRoot(allocator, t.leaves, index);
                break :blk try tapTweakXOnlyWithRoot(ctx, &ik, &root);
            };
            try script.append(0x51); // OP_1
            try script.append(0x20); // Push 32 bytes
            try script.appendSlice(&output_key);
        },
        .multi, .sorted_multi => |m| {
            // multisig: <threshold> <pubkey1> ... <pubkeyn> <n> OP_CHECKMULTISIG
            // Core GetScriptForMultisig: `script << nRequired` pushes a
            // script number (OP_1..OP_16, else a minimal data push).
            try pushScriptInt(&script, m.threshold);

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

            try pushScriptInt(&script, m.keys.len);
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
        .rawtr => |hex_str| {
            // rawtr(XONLY_HEX) → OP_1 <32-byte-x-only-pubkey> (P2TR key-spend)
            const pk_bytes = try decodeHex(allocator, hex_str);
            defer allocator.free(pk_bytes);
            if (pk_bytes.len != 32) return error.InvalidKeyExpression;
            try script.append(0x51); // OP_1 (segwit version 1)
            try script.append(0x20); // push 32 bytes
            try script.appendSlice(pk_bytes);
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

/// Push a non-negative integer the way Core's `CScript << int64` does:
/// OP_0 for 0, OP_1..OP_16 for 1..16, else a minimal CScriptNum data push.
fn pushScriptInt(script: *std.ArrayList(u8), value: u64) !void {
    if (value == 0) return script.append(0x00);
    if (value <= 16) return script.append(@intCast(0x50 + value));
    var buf: [9]u8 = undefined;
    var len: usize = 0;
    var v = value;
    while (v > 0) : (v >>= 8) {
        buf[len] = @truncate(v);
        len += 1;
    }
    // A set top bit would read as negative; add a 0x00 sign byte.
    if (buf[len - 1] & 0x80 != 0) {
        buf[len] = 0x00;
        len += 1;
    }
    try pushData(script, buf[0..len]);
}

/// Serialized pubkey size Core counts for the sh(multi()) size limit
/// (PubkeyProvider::GetSize): 65 for an uncompressed key, else 33.
fn multiKeySize(k: KeyExpression) usize {
    return switch (k) {
        .pubkey => |p| if (p.data.len == 130) 65 else 33,
        // Base58 WIF: 51 chars = uncompressed, 52 = compressed (0x01 suffix).
        .wif => |w| if (w.len == 51) 65 else 33,
        .xpub, .xprv => 33,
    };
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
    const d = try deriveExtendedKey(allocator, key_str, path, derive_type, index, is_xprv);
    const result = try allocator.alloc(u8, 33);
    @memcpy(result, &d.pubkey);
    return result;
}

/// A BIP-32 derivation result: the derived key pair plus the ROOT (serialized)
/// key's pubkey, whose hash160 prefix is Core's origin fingerprint for an
/// extended key written without an explicit [origin].
pub const ExtDerived = struct { pubkey: [33]u8, privkey: ?[32]u8, root_pubkey: [33]u8 };

fn deriveExtendedKey(allocator: std.mem.Allocator, key_str: []const u8, path: []const u32, derive_type: DeriveType, index: u32, is_xprv: bool) !ExtDerived {
    // BIP-32 extended keys carry a 4-BYTE version prefix — unlike the 1-byte
    // address version that base58CheckDecode strips — so decode RAW and verify
    // both the 4-byte double-SHA256 checksum and the 4-byte version ourselves.
    // Serialization (BIP-32): 4 version + 1 depth + 4 fingerprint + 4 child +
    // 32 chaincode + 33 key = 78-byte payload, + 4-byte checksum = 82 bytes.
    // Cross-ref: bitcoin-core/src/key_io.cpp DecodeExtKey/DecodeExtPubKey
    // (DecodeBase58Check -> BIP32_EXTKEY_SIZE(74) body after the 4-byte prefix).
    const raw = address.base58Decode(key_str, allocator) catch return error.InvalidKeyExpression;
    defer allocator.free(raw);

    if (raw.len != 82) {
        return error.InvalidKeyExpression;
    }
    const payload = raw[0..78];
    const cksum = raw[78..82];
    const computed = crypto.hash256(payload);
    if (!std.mem.eql(u8, cksum, computed[0..4])) {
        return error.InvalidKeyExpression;
    }

    // 4-byte version prefix (BIP-32): xpub 0x0488B21E / xprv 0x0488ADE4 on
    // mainnet, tpub 0x043587CF / tprv 0x04358394 on testnet+regtest. It must
    // match the key TYPE the descriptor asked for (xprv vs xpub).
    const version = (@as(u32, payload[0]) << 24) | (@as(u32, payload[1]) << 16) |
        (@as(u32, payload[2]) << 8) | @as(u32, payload[3]);
    if (is_xprv) {
        if (version != 0x0488ADE4 and version != 0x04358394) return error.InvalidKeyExpression;
    } else {
        if (version != 0x0488B21E and version != 0x043587CF) return error.InvalidKeyExpression;
    }

    // Body = the 74 bytes after the 4-byte version. The field offsets
    // (depth=[0], fingerprint=[1..5], child=[5..9], chaincode=[9..41],
    // key=[41..74]) are correct once all 4 version bytes are removed.
    const body = payload[4..78];
    const depth = body[0];
    _ = depth;
    const chain_code = body[9..41];
    const key_data = body[41..74];

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

    const root_pubkey = current_pubkey;

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

    return .{
        .pubkey = current_pubkey,
        .privkey = if (is_xprv) current_key else null,
        .root_pubkey = root_pubkey,
    };
}

/// Everything a signing provider needs from one key expression at `index`
/// (Core descriptor.cpp PubkeyProvider::GetPubKey + GetPrivKey):
///   pubkey       the derived public key (33 or 65 bytes, owned)
///   privkey      the derived secret, when the expression carries one
///   fingerprint/path  the KeyOriginInfo Core records: an explicit [origin]
///                is prefixed to the derivation steps; without one, an
///                extended key's own fingerprint (hash160(root pubkey)[0..4])
///                and a bare key's hash160(pubkey)[0..4] with an empty path.
pub const ResolvedKey = struct {
    pubkey: []u8,
    privkey: ?[32]u8,
    fingerprint: [4]u8,
    path: []u32,

    pub fn deinit(self: *ResolvedKey, allocator: std.mem.Allocator) void {
        allocator.free(self.pubkey);
        allocator.free(self.path);
        if (self.privkey) |*k| @memset(k, 0);
    }
};

pub fn resolveKey(allocator: std.mem.Allocator, key: Key, index: u32) !ResolvedKey {
    var steps = std.ArrayList(u32).init(allocator);
    defer steps.deinit();
    var pubkey: []u8 = undefined;
    var privkey: ?[32]u8 = null;
    var own_fp: [4]u8 = undefined;
    switch (key.key) {
        .pubkey => |p| {
            const pk = try decodeHex(allocator, p.data);
            pubkey = @constCast(pk);
            const h = crypto.hash160(pubkey);
            @memcpy(&own_fp, h[0..4]);
        },
        .wif => |wif| {
            const pk = try decodeWifToPubkey(allocator, wif);
            pubkey = @constCast(pk);
            privkey = try decodeWifPrivkey(allocator, wif);
            const h = crypto.hash160(pubkey);
            @memcpy(&own_fp, h[0..4]);
        },
        .xpub, .xprv => {
            const is_xprv = key.key == .xprv;
            const kstr: []const u8 = if (is_xprv) key.key.xprv.key else key.key.xpub.key;
            const kpath: []const u32 = if (is_xprv) key.key.xprv.path else key.key.xpub.path;
            const kdt: DeriveType = if (is_xprv) key.key.xprv.derive_type else key.key.xpub.derive_type;
            const d = try deriveExtendedKey(allocator, kstr, kpath, kdt, index, is_xprv);
            pubkey = try allocator.dupe(u8, &d.pubkey);
            privkey = d.privkey;
            const h = crypto.hash160(&d.root_pubkey);
            @memcpy(&own_fp, h[0..4]);
            try steps.appendSlice(kpath);
            switch (kdt) {
                .non_ranged => {},
                .unhardened => try steps.append(index),
                .hardened => try steps.append(index | 0x80000000),
            }
        },
    }
    errdefer allocator.free(pubkey);
    var path = std.ArrayList(u32).init(allocator);
    errdefer path.deinit();
    var fp = own_fp;
    if (key.origin) |o| {
        fp = o.fingerprint;
        try path.appendSlice(o.path);
    }
    try path.appendSlice(steps.items);
    return .{ .pubkey = pubkey, .privkey = privkey, .fingerprint = fp, .path = try path.toOwnedSlice() };
}

fn decodeWifPrivkey(allocator: std.mem.Allocator, wif: []const u8) ![32]u8 {
    const decoded = address.base58CheckDecode(wif, allocator) catch return error.InvalidKeyExpression;
    defer allocator.free(decoded.data);
    if (decoded.version != 0x80 and decoded.version != 0xEF) return error.InvalidKeyExpression;
    if (decoded.data.len != 32 and !(decoded.data.len == 33 and decoded.data[32] == 0x01)) return error.InvalidKeyExpression;
    var out: [32]u8 = undefined;
    @memcpy(&out, decoded.data[0..32]);
    return out;
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
        .rawtr => |r| {
            try out.appendSlice("rawtr(");
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
    return parseDescriptorDiag(allocator, input, null);
}

/// parseDescriptor that also fills `diag` with Core's ParseScript wording when
/// the failure carries one (see Diagnostic).
pub fn parseDescriptorDiag(allocator: std.mem.Allocator, input: []const u8, diag: ?*Diagnostic) !Descriptor {
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
    parser.diag = diag;
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

    // `checksum` is Core's GetDescriptorChecksum(input): the checksum of the
    // descriptor AS GIVEN (input minus any provided #checksum), NOT the checksum
    // of the canonical re-serialization (the h vs ' hardened marker differs).
    // Cross-ref: bitcoin-core/src/rpc/output_script.cpp:215.
    const cs_body = if (std.mem.indexOfScalar(u8, input, '#')) |hp| input[0..hp] else input;
    const checksum = computeChecksum(cs_body) orelse return error.InvalidDescriptorCharacter;

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
        .addr, .raw, .rawtr => false,
    };
}

/// Return whether this descriptor is solvable (can we construct a scriptSig/witness?).
/// addr() and raw() are not solvable — they describe a script but provide no signing info.
/// rawtr() IS solvable — it specifies a key-path spend directly.
pub fn isSolvable(desc: *const Descriptor) bool {
    return switch (desc.*) {
        .addr, .raw => false,
        else => true,
    };
}

/// Return the descriptor string Core's `listdescriptors` shows for a
/// descriptor imported with private keys, with a fresh `#checksum`. This is
/// `Descriptor::ToNormalizedString` (script/descriptor.cpp), which
/// DescriptorScriptPubKeyMan::GetDescriptorString uses for priv=false:
///
///  - xprv/tprv become xpub/tpub and WIF keys become hex pubkeys;
///  - a BIP-32 key whose path has a hardened step is re-rooted at the LAST
///    hardened step: the xpub of that node, and the hardened prefix moved into
///    the origin (`[<root fp>/84h/1h/0h]tpub.../0/*`; an existing origin is
///    extended instead, `[d34db33f/44h/1h/1h]tpub.../2/*`);
///  - a hardened-ranged key (`/*'`) keeps the root xpub and its path;
///  - hardened markers in origins and in hardened-ranged paths print as `h`;
///  - a WIF inside `tr(...)` (internal key or tap leaf) prints x-only, 64 hex
///    (ConstPubkeyProvider m_xonly in P2TR context).
///
/// Everything outside key expressions (script structure, miniscript, tap
/// trees, addresses) is copied byte for byte, which is why this works on the
/// string rather than through `toString`. A token counts as a key only when it
/// decodes as a checksummed BIP-32 key or WIF private key; other tokens are
/// copied. Fails (and the caller refuses the import) rather than return a
/// string that still holds a private key.
pub fn toPublicDescriptor(allocator: std.mem.Allocator, desc_str: []const u8) ![]const u8 {
    const body = if (std.mem.indexOfScalar(u8, desc_str, '#')) |h| desc_str[0..h] else desc_str;
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    // One entry per open '(' : is that script fragment in P2TR context?
    var tr_stack: [64]bool = undefined;
    var depth: usize = 0;
    var i: usize = 0;
    while (i < body.len) {
        const c = body[i];
        const in_tr = depth > 0 and tr_stack[depth - 1];
        if (c == '[') {
            const close = std.mem.indexOfScalarPos(u8, body, i, ']') orelse return error.InvalidKeyExpression;
            var k = close + 1;
            while (k < body.len and std.ascii.isAlphanumeric(body[k])) : (k += 1) {}
            const pe = keyPathEnd(body, k);
            try writeNormalizedKey(&out, body[i + 1 .. close], body[close + 1 .. k], body[k..pe], in_tr);
            i = pe;
        } else if (std.ascii.isAlphanumeric(c)) {
            var k = i;
            while (k < body.len and std.ascii.isAlphanumeric(body[k])) : (k += 1) {}
            const tok = body[i..k];
            if (decodeKeyToken(tok) != .none) {
                const pe = keyPathEnd(body, k);
                try writeNormalizedKey(&out, null, tok, body[k..pe], in_tr);
                i = pe;
            } else {
                try out.appendSlice(tok);
                i = k;
                if (i < body.len and body[i] == '(') {
                    if (depth == tr_stack.len) return error.InvalidKeyExpression;
                    tr_stack[depth] = in_tr or std.mem.eql(u8, tok, "tr") or std.mem.eql(u8, tok, "rawtr");
                    depth += 1;
                    try out.append('(');
                    i += 1;
                }
            }
        } else {
            if (c == ')' and depth > 0) depth -= 1;
            try out.append(c);
            i += 1;
        }
    }
    return addChecksum(allocator, out.items);
}

/// End of a key's `/NUM['h]...` path and optional `/*['h]` suffix.
fn keyPathEnd(body: []const u8, start: usize) usize {
    var k = start;
    while (k + 1 < body.len and body[k] == '/') {
        var j = k + 1;
        if (body[j] == '*') {
            j += 1;
        } else if (std.ascii.isDigit(body[j])) {
            while (j < body.len and std.ascii.isDigit(body[j])) : (j += 1) {}
        } else break;
        if (j < body.len and (body[j] == '\'' or body[j] == 'h' or body[j] == 'H')) j += 1;
        k = j;
    }
    return k;
}

const ExtKeyBytes = struct {
    is_priv: bool,
    payload: [78]u8, // BIP-32 serialization without the checksum
};

const KeyToken = union(enum) {
    none,
    ext: ExtKeyBytes,
    wif: struct { pubkey: [65]u8, len: usize },
};

/// Classify a token: checksummed BIP-32 extended key, WIF private key, or
/// neither. Never allocates: tokens longer than 111 chars are not keys.
fn decodeKeyToken(tok: []const u8) KeyToken {
    if (tok.len < 50 or tok.len > 111) return .none;
    for (tok) |ch| if (!isBase58Char(ch)) return .none;
    var buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const raw = address.base58Decode(tok, fba.allocator()) catch return .none;
    defer @memset(&buf, 0);
    if (raw.len == 82) {
        const computed = crypto.hash256(raw[0..78]);
        if (!std.mem.eql(u8, raw[78..82], computed[0..4])) return .none;
        const version = std.mem.readInt(u32, raw[0..4], .big);
        const is_priv = switch (version) {
            0x0488ADE4, 0x04358394 => true,
            0x0488B21E, 0x043587CF => false,
            else => return .none,
        };
        if (is_priv and raw[45] != 0x00) return .none;
        var e = ExtKeyBytes{ .is_priv = is_priv, .payload = undefined };
        @memcpy(&e.payload, raw[0..78]);
        return .{ .ext = e };
    }
    // WIF: version(1) + key(32) [+ 0x01] + checksum(4).
    if (raw.len != 37 and raw.len != 38) return .none;
    if (raw[0] != 0x80 and raw[0] != 0xEF) return .none;
    const n = raw.len - 4;
    const computed = crypto.hash256(raw[0..n]);
    if (!std.mem.eql(u8, raw[n..], computed[0..4])) return .none;
    const compressed = raw.len == 38;
    if (compressed and raw[33] != 0x01) return .none;
    const ctx = getSecpContext() catch return .none;
    var pk: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pk, raw[1..33].ptr) != 1) return .none;
    var w: KeyToken = .{ .wif = .{ .pubkey = undefined, .len = if (compressed) 33 else 65 } };
    var len: usize = w.wif.len;
    _ = secp256k1.secp256k1_ec_pubkey_serialize(ctx, &w.wif.pubkey, &len, &pk, if (compressed) secp256k1.SECP256K1_EC_COMPRESSED else secp256k1.SECP256K1_EC_UNCOMPRESSED);
    return w;
}

/// Core OriginString(normalized=true): lowercase hex fingerprint, each path
/// element printed from its parsed value (`044'` -> `44h`), `h` marker.
fn writeNormalizedOrigin(out: *std.ArrayList(u8), origin: []const u8) !void {
    var it = std.mem.splitScalar(u8, origin, '/');
    const fp = it.first();
    for (fp) |ch| try out.append(std.ascii.toLower(ch));
    while (it.next()) |el| {
        var digits = el;
        var hard = false;
        if (el.len > 0 and (el[el.len - 1] == '\'' or el[el.len - 1] == 'h' or el[el.len - 1] == 'H')) {
            digits = el[0 .. el.len - 1];
            hard = true;
        }
        const v = std.fmt.parseInt(u32, digits, 10) catch return error.InvalidKeyExpression;
        if (v >> 31 != 0) return error.InvalidKeyExpression;
        try out.writer().print("/{d}", .{v});
        if (hard) try out.append('h');
    }
}

fn writeSteps(out: *std.ArrayList(u8), steps: []const u32) !void {
    for (steps) |s| {
        try out.writer().print("/{d}", .{s & 0x7fffffff});
        if (s >> 31 != 0) try out.append('h');
    }
}

fn writeNormalizedKey(out: *std.ArrayList(u8), origin: ?[]const u8, key: []const u8, suffix: []const u8, xonly: bool) !void {
    const kt = decodeKeyToken(key);
    switch (kt) {
        .none => {
            // Hex pubkey (or anything else that holds no private key): Core
            // prints it as written, with a normalized origin.
            if (origin) |o| {
                try out.append('[');
                try writeNormalizedOrigin(out, o);
                try out.append(']');
            }
            try out.appendSlice(key);
            try out.appendSlice(suffix);
        },
        .wif => |w| {
            if (suffix.len != 0) return error.InvalidKeyExpression;
            if (origin) |o| {
                try out.append('[');
                try writeNormalizedOrigin(out, o);
                try out.append(']');
            }
            // P2TR context: Core prints the x-only key (drop the parity byte).
            const pk = if (xonly and w.len == 33) w.pubkey[1..33] else w.pubkey[0..w.len];
            try out.writer().print("{s}", .{std.fmt.fmtSliceHexLower(pk)});
        },
        .ext => |e| try writeNormalizedExtKey(out, origin, e, suffix),
    }
}

fn writeNormalizedExtKey(out: *std.ArrayList(u8), origin: ?[]const u8, e: ExtKeyBytes, suffix: []const u8) !void {
    // Parse the path suffix.
    var steps_buf: [256]u32 = undefined;
    var n_steps: usize = 0;
    var ranged = false;
    var hardened_range = false;
    var k: usize = 0;
    while (k < suffix.len) {
        if (suffix[k] != '/' or ranged) return error.InvalidKeyExpression;
        k += 1;
        if (k >= suffix.len) return error.InvalidKeyExpression;
        var hard = false;
        var val: u32 = 0;
        if (suffix[k] == '*') {
            ranged = true;
            k += 1;
        } else {
            const ds = k;
            while (k < suffix.len and std.ascii.isDigit(suffix[k])) : (k += 1) {}
            val = std.fmt.parseInt(u32, suffix[ds..k], 10) catch return error.InvalidKeyExpression;
            if (val >> 31 != 0) return error.InvalidKeyExpression;
        }
        if (k < suffix.len and (suffix[k] == '\'' or suffix[k] == 'h' or suffix[k] == 'H')) {
            hard = true;
            k += 1;
        }
        if (ranged) {
            hardened_range = hard;
        } else {
            if (n_steps == steps_buf.len) return error.InvalidKeyExpression;
            steps_buf[n_steps] = if (hard) val | 0x80000000 else val;
            n_steps += 1;
        }
    }
    const steps = steps_buf[0..n_steps];

    const ctx = try getSecpContext();
    var key = e.payload;
    defer @memset(&key, 0);
    const pub_version: u32 = switch (std.mem.readInt(u32, key[0..4], .big)) {
        0x0488ADE4 => 0x0488B21E,
        0x04358394 => 0x043587CF,
        else => |v| v,
    };
    // Root public key.
    var root_pub: [33]u8 = undefined;
    if (e.is_priv) {
        try pubFromSecret(ctx, key[46..78], &root_pub);
    } else {
        @memcpy(&root_pub, key[45..78]);
    }

    var last_hard: ?usize = null;
    for (steps, 0..) |s, idx| {
        if (s >> 31 != 0) last_hard = idx;
    }

    if (hardened_range or last_hard == null) {
        // Root xpub + path as written (all steps print with `h` here).
        if (origin) |o| {
            try out.append('[');
            try writeNormalizedOrigin(out, o);
            try out.append(']');
        }
        try writeXpub(out, pub_version, key[4..45], &root_pub);
        try writeSteps(out, steps);
        if (ranged) try out.appendSlice(if (hardened_range) "/*h" else "/*");
        return;
    }

    // Re-root at the last hardened step (needs the private key).
    if (!e.is_priv) return error.InvalidKeyExpression;
    const li = last_hard.?;
    // BIP-32 depth is one byte; Core refuses to derive past 255
    // (CExtKey::Derive, key.cpp).
    if (@as(usize, key[4]) + li + 1 > 255) return error.InvalidKeyExpression;
    var secret: [32]u8 = undefined;
    defer @memset(&secret, 0);
    @memcpy(&secret, key[46..78]);
    var chain: [32]u8 = undefined;
    defer @memset(&chain, 0);
    @memcpy(&chain, key[13..45]);
    var parent_pub: [33]u8 = root_pub;
    for (steps[0 .. li + 1]) |s| {
        try pubFromSecret(ctx, &secret, &parent_pub);
        var data: [37]u8 = undefined;
        defer @memset(&data, 0);
        if (s >> 31 != 0) {
            data[0] = 0x00;
            @memcpy(data[1..33], &secret);
        } else {
            @memcpy(data[0..33], &parent_pub);
        }
        std.mem.writeInt(u32, data[33..37], s, .big);
        const HmacSha512 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha512);
        var I: [64]u8 = undefined;
        defer @memset(&I, 0);
        HmacSha512.create(&I, &data, &chain);
        if (secp256k1.secp256k1_ec_seckey_tweak_add(ctx, &secret, I[0..32].ptr) != 1) return error.InvalidKeyExpression;
        @memcpy(&chain, I[32..64]);
    }
    var child_pub: [33]u8 = undefined;
    try pubFromSecret(ctx, &secret, &child_pub);

    try out.append('[');
    if (origin) |o| {
        try writeNormalizedOrigin(out, o);
    } else {
        const fp = crypto.hash160(&root_pub);
        try out.writer().print("{s}", .{std.fmt.fmtSliceHexLower(fp[0..4])});
    }
    try writeSteps(out, steps[0 .. li + 1]);
    try out.append(']');
    var meta: [41]u8 = undefined; // depth, parent fp, child number, chain code
    meta[0] = @intCast(@as(usize, key[4]) + li + 1);
    const pfp = crypto.hash160(&parent_pub);
    @memcpy(meta[1..5], pfp[0..4]);
    std.mem.writeInt(u32, meta[5..9], steps[li], .big);
    @memcpy(meta[9..41], &chain);
    try writeXpub(out, pub_version, &meta, &child_pub);
    try writeSteps(out, steps[li + 1 ..]);
    if (ranged) try out.appendSlice("/*");
}

fn pubFromSecret(ctx: *secp.Context, secret: []const u8, out: *[33]u8) !void {
    var pk: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pk, secret.ptr) != 1) return error.InvalidKeyExpression;
    var len: usize = 33;
    _ = secp256k1.secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk, secp256k1.SECP256K1_EC_COMPRESSED);
}

/// Base58check-encode version(4) || meta(41: depth, parent fp, child, chain
/// code) || pubkey(33).
fn writeXpub(out: *std.ArrayList(u8), version: u32, meta: []const u8, pubkey: *const [33]u8) !void {
    var ext: [82]u8 = undefined;
    std.mem.writeInt(u32, ext[0..4], version, .big);
    @memcpy(ext[4..45], meta[0..41]);
    @memcpy(ext[45..78], pubkey);
    const ck = crypto.hash256(ext[0..78]);
    @memcpy(ext[78..82], ck[0..4]);
    var buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const s = try address.base58Encode(&ext, fba.allocator());
    try out.appendSlice(s);
}

fn isBase58Char(c: u8) bool {
    return switch (c) {
        '1'...'9', 'A'...'H', 'J'...'N', 'P'...'Z', 'a'...'k', 'm'...'z' => true,
        else => false,
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

    // Core's deriveaddresses range is [begin,end] INCLUSIVE — it loops
    // `for (i = range_begin; i <= range_end; ++i)` (bitcoin-core/src/rpc/
    // output_script.cpp:228), so an [0,19] range yields 20 addresses. Using an
    // exclusive count drops the final address (fund-loss class on the change
    // chain). Mirrors rustoshi's start..=end fix (finding #1).
    const count = if (desc.isRange()) range_end - range_start + 1 else 1;

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

test "parse and resolve WIF key produces P2PKH script" {
    // Phase 2 (single-FFI secp module): the pre-Phase-2 version of this test
    // was pinned to the test-mode stub's behavior of returning
    // `error.Secp256k1NotAvailable` from `deriveScript`. The stub is gone
    // (the central `secp` module always uses the real libsecp256k1, which
    // build.zig always links) so derivation now succeeds. The test was
    // testing the absence of libsecp256k1 in tests — a build-config
    // assertion, not a descriptor-semantics assertion — and has been
    // updated to verify the actually-useful property: that a WIF descriptor
    // resolves to a well-formed P2PKH scriptPubKey.
    const allocator = std.testing.allocator;

    // Parse a descriptor with a WIF key (testnet WIF format).
    var desc = try parseDescriptor(allocator, "pkh(cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy)");
    defer desc.deinit(allocator);

    try std.testing.expect(desc == .pkh);
    try std.testing.expect(desc.pkh.key == .wif);

    // Derive the scriptPubKey at index 0 (non-ranged descriptor so index ignored).
    const script = try deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // P2PKH layout: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    try std.testing.expectEqual(@as(usize, 25), script.len);
    try std.testing.expectEqual(@as(u8, 0x76), script[0]); // OP_DUP
    try std.testing.expectEqual(@as(u8, 0xa9), script[1]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[2]); // Push 20 bytes
    try std.testing.expectEqual(@as(u8, 0x88), script[23]); // OP_EQUALVERIFY
    try std.testing.expectEqual(@as(u8, 0xac), script[24]); // OP_CHECKSIG
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

// ----------------------------------------------------------------------------
// tr(KEY,TREE): the output key commits to the script tree (BIP-386 / BIP-341).
// Expected values are the BIP-386 test vectors; every one was also re-derived
// with Bitcoin Core v31.1 `deriveaddresses` + `validateaddress` (mainnet).
// ----------------------------------------------------------------------------

const tr_tree_test_K = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd";

fn trTreeExpectSpk(desc_str: []const u8, index: u32, expected_hex: []const u8) !void {
    const allocator = std.testing.allocator;
    var desc = try parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    const spk = try deriveScript(allocator, &desc, index);
    defer allocator.free(spk);
    const got = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(spk)});
    defer allocator.free(got);
    try std.testing.expectEqualStrings(expected_hex, got);
}

test "tr_script_tree: deriveaddresses of tr(KEY,pk(...)) equals Core's address (BIP-386)" {
    const allocator = std.testing.allocator;
    const addrs = try deriveAddresses(
        allocator,
        "tr(" ++ tr_tree_test_K ++ ",pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))",
        .mainnet,
        0,
        0,
    );
    defer {
        for (addrs) |a| allocator.free(a);
        allocator.free(addrs);
    }
    try std.testing.expectEqual(@as(usize, 1), addrs.len);
    // Core v31.1 deriveaddresses. The key-path-only address for this internal
    // key (what master produced) is bc1pw74tdcrxlzn5r8z6...0gs8zu.
    try std.testing.expectEqualStrings("bc1pzl833kecrkpkmzfrkx7my3k0ekqcmgdf7rnw0yrlrplsktunwa2q7vxsg5", addrs[0]);
}

test "tr_script_tree: BIP-386 nested tree vector" {
    try trTreeExpectSpk(
        "tr(" ++ tr_tree_test_K ++ ",{pk(xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0),{{pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),pk(02df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076)},pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)}})",
        0,
        "512071fff39599a7b78bc02623cbe814efebf1a404f5d8ad34ea80f213bd8943f574",
    );
}

test "tr_script_tree: BIP-386 ranged tr(xprv/0/*,pk(xprv/1/*)) indices 0..2" {
    const R = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc";
    const d = "tr(" ++ R ++ "/0/*,pk(" ++ R ++ "/1/*))";
    try trTreeExpectSpk(d, 0, "512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12");
    try trTreeExpectSpk(d, 1, "512001f0a02a17808c20134b78faab80ef93ffba82261ccef0a2314f5d62b6438f11");
    try trTreeExpectSpk(d, 2, "512021024954fcec88237a9386fce80ef2ced5f1e91b422b26c59ccfc174c8d1ad25");
}

test "tr_script_tree: Core descriptor_tests compressed-key tree vector" {
    // bitcoin-core/src/test/descriptor_tests.cpp: 33-byte keys inside tr()
    // are used x-only, both as internal key and in pk() leaves.
    try trTreeExpectSpk(
        "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})",
        0,
        "51201497ae16f30dacb88523ed9301bff17773b609e8a90518a3f96ea328a47d1500",
    );
}

test "tr_script_tree: pkh() leaf hashes the x-only key (Core v31.1)" {
    // BIP-386 lists this as valid without an output; value from Core v31.1.
    try trTreeExpectSpk(
        "tr(" ++ tr_tree_test_K ++ ",pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))",
        0,
        "51207cb44493f9a28e2d53656c2eb6fb3a053afaa05f8ae3ef474392d8759cd78b7a",
    );
}

test "tr_script_tree: sibling order does not change the root (TapBranch sorts)" {
    const expected = "5120c895d68a6e7881fa5e8ad4e554bab6b313705773bc6262117d92f70942a336cd";
    try trTreeExpectSpk("tr(" ++ tr_tree_test_K ++ ",{pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0),pk(" ++ tr_tree_test_K ++ ")})", 0, expected);
    try trTreeExpectSpk("tr(" ++ tr_tree_test_K ++ ",{pk(" ++ tr_tree_test_K ++ "),pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0)})", 0, expected);
}

test "tr_script_tree: tr(KEY) key-path-only is unchanged (BIP-386)" {
    try trTreeExpectSpk("tr(" ++ tr_tree_test_K ++ ")", 0, "512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11");
    try trTreeExpectSpk("tr(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)", 0, "512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11");
}

test "tr_script_tree: unsupported leaf type is refused, not hashed into a wrong key" {
    // multi() is not valid inside tr() (Core: only multi_a/sortedmulti_a).
    // Producing an address that ignores or mis-encodes the leaf would be a
    // wrong (unspendable-by-script-path) address, so derivation must fail.
    const allocator = std.testing.allocator;
    // The parser still accepts multi() here; this pins the derive step.
    var desc = try parseDescriptor(allocator, "tr(" ++ tr_tree_test_K ++ ",multi(1,669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))");
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .tr);
    try std.testing.expectEqual(@as(usize, 1), desc.tr.leaves.len);
    if (deriveScript(allocator, &desc, 0)) |spk| {
        allocator.free(spk);
        return error.TestExpectedError;
    } else |err| {
        try std.testing.expect(@as(anyerror, err) == error.UnsupportedTapLeaf);
    }
}

// ----------------------------------------------------------------------------
// multi_bounds: multi()/sortedmulti() threshold and key-count bounds (Core
// ParseScript, script/descriptor.cpp) and script-number encoding of k and n
// (Core GetScriptForMultisig, script/solver.cpp).
//
// Every expected address and message below is Bitcoin Core v31.1 regtest
// `deriveaddresses` output. The keys are the compressed (mk_K) and
// uncompressed (mk_U) pubkeys of private keys 1..21 / 1..8; mk_W are the
// uncompressed regtest WIFs of 1..8.
// ----------------------------------------------------------------------------

const mk_K1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const mk_K2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const mk_K3 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const mk_K4 = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";
const mk_K5 = "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4";
const mk_K6 = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";
const mk_K7 = "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc";
const mk_K8 = "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01";
const mk_K9 = "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe";
const mk_K10 = "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7";
const mk_K11 = "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb";
const mk_K12 = "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a";
const mk_K13 = "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8";
const mk_K14 = "03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4";
const mk_K15 = "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e";
const mk_K16 = "03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a";
const mk_K17 = "03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34";
const mk_K18 = "025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc";
const mk_K19 = "022b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c";
const mk_K20 = "024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97";
const mk_K21 = "02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5";
const mk_U1 = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const mk_U2 = "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a";
const mk_U3 = "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672";
const mk_U4 = "04e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1351ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922";
const mk_U5 = "042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6";
const mk_U6 = "04fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297";
const mk_U7 = "045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da";
const mk_U8 = "042f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a015c4da8a741539949293d082a132d13b4c2e213d6ba5b7617b5da2cb76cbde904";
const mk_W1 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx";
const mk_W2 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgww7vXtT";
const mk_W3 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgx3cTMqe";
const mk_W4 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgx9rcrL7";
const mk_W5 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgxCZY6u6";
const mk_W6 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgxPr9P7A";
const mk_W7 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgxVDHN1P";
const mk_W8 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgxZRghKv";

fn mkJoin(comptime prefix: []const u8, comptime n: usize) []const u8 {
    comptime {
        var s: []const u8 = "";
        for (1..n + 1) |i| {
            s = s ++ (if (i > 1) "," else "") ++ @field(@This(), prefix ++ std.fmt.comptimePrint("{d}", .{i}));
        }
        return s;
    }
}

fn multiBoundsExpectAddr(desc_str: []const u8, expected: []const u8) !void {
    const allocator = std.testing.allocator;
    const addrs = try deriveAddresses(allocator, desc_str, .regtest, 0, 0);
    defer {
        for (addrs) |a| allocator.free(a);
        allocator.free(addrs);
    }
    try std.testing.expectEqual(@as(usize, 1), addrs.len);
    try std.testing.expectEqualStrings(expected, addrs[0]);
}

/// The descriptor must be refused with `expected_err`, and the parser must
/// report Core's ParseScript message (what deriveaddresses returns as -5).
fn multiBoundsExpectRefused(desc_str: []const u8, expected_err: anyerror, expected_msg: []const u8) !void {
    const allocator = std.testing.allocator;
    if (deriveAddresses(allocator, desc_str, .regtest, 0, 0)) |addrs| {
        defer {
            for (addrs) |a| allocator.free(a);
            allocator.free(addrs);
        }
        std.debug.print("accepted, derived {s}; Core refuses with \"{s}\"\n", .{ addrs[0], expected_msg });
        return error.TestExpectedError;
    } else |err| {
        try std.testing.expectEqual(expected_err, err);
    }
    // Message check. Guarded so this file still compiles where the
    // diagnostic API does not exist (the test then fails by assertion).
    if (comptime @hasDecl(@This(), "parseDescriptorDiag")) {
        var diag: @field(@This(), "Diagnostic") = .{};
        if (@field(@This(), "parseDescriptorDiag")(allocator, desc_str, &diag)) |d| {
            var dd = d;
            dd.deinit(allocator);
            return error.TestExpectedError;
        } else |_| {}
        try std.testing.expectEqualStrings(expected_msg, diag.message() orelse "");
    } else {
        return error.NoParseDiagnostic;
    }
}

test "multi_bounds: multi(0,K1,K2) is refused (k=0 encoded OP_RESERVED)" {
    try multiBoundsExpectRefused("multi(0," ++ comptime mkJoin("mk_K", 2) ++ ")", error.MultiThresholdZero, "Multisig threshold cannot be 0, must be at least 1");
}

test "multi_bounds: multi(3,K1,K2) is refused (threshold > keys)" {
    try multiBoundsExpectRefused("multi(3," ++ comptime mkJoin("mk_K", 2) ++ ")", error.MultiThresholdTooLarge, "Multisig threshold cannot be larger than the number of keys; threshold is 3 but only 2 keys specified");
}

test "multi_bounds: bare multi() with 4 keys is refused" {
    try multiBoundsExpectRefused("multi(1," ++ comptime mkJoin("mk_K", 4) ++ ")", error.BareMultiTooManyKeys, "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys");
}

test "multi_bounds: wsh(multi()) with 21 keys is refused" {
    try multiBoundsExpectRefused("wsh(multi(1," ++ comptime mkJoin("mk_K", 21) ++ "))", error.MultiKeyCount, "Cannot have 21 keys in multisig; must have between 1 and 20 keys, inclusive");
}

test "multi_bounds: key count is checked before the threshold (Core order)" {
    try multiBoundsExpectRefused("wsh(multi(0," ++ comptime mkJoin("mk_K", 21) ++ "))", error.MultiKeyCount, "Cannot have 21 keys in multisig; must have between 1 and 20 keys, inclusive");
}

test "multi_bounds: wsh(multi(0,...)) is refused" {
    try multiBoundsExpectRefused("wsh(multi(0," ++ comptime mkJoin("mk_K", 2) ++ "))", error.MultiThresholdZero, "Multisig threshold cannot be 0, must be at least 1");
}

test "multi_bounds: sh(sortedmulti(0,...)) is refused" {
    try multiBoundsExpectRefused("sh(sortedmulti(0," ++ comptime mkJoin("mk_K", 2) ++ "))", error.MultiThresholdZero, "Multisig threshold cannot be 0, must be at least 1");
}

test "multi_bounds: sh(multi()) with 16 compressed keys exceeds 520 bytes" {
    try multiBoundsExpectRefused("sh(multi(1," ++ comptime mkJoin("mk_K", 16) ++ "))", error.P2shScriptTooLarge, "P2SH script is too large, 547 bytes is larger than 520 bytes");
}

test "multi_bounds: sh(multi()) with 8 uncompressed hex keys exceeds 520 bytes" {
    try multiBoundsExpectRefused("sh(multi(1," ++ comptime mkJoin("mk_U", 8) ++ "))", error.P2shScriptTooLarge, "P2SH script is too large, 531 bytes is larger than 520 bytes");
}

test "multi_bounds: sh(multi()) with 8 uncompressed WIF keys exceeds 520 bytes" {
    try multiBoundsExpectRefused("sh(multi(1," ++ comptime mkJoin("mk_W", 8) ++ "))", error.P2shScriptTooLarge, "P2SH script is too large, 531 bytes is larger than 520 bytes");
}

test "multi_bounds: 17-key wsh(multi(1,...)) equals Core's address" {
    try multiBoundsExpectAddr("wsh(multi(1," ++ comptime mkJoin("mk_K", 17) ++ "))", "bcrt1qeqlqzd940c9qs38wp7tlavdlmh6v6gwsdtt4peauvgeuue499h7ql6dwyw");
}

test "multi_bounds: wsh(multi(17,17 keys)) equals Core's address" {
    try multiBoundsExpectAddr("wsh(multi(17," ++ comptime mkJoin("mk_K", 17) ++ "))", "bcrt1q930ak48grylg2ef572yxe244psx8psgyw6p0pxv3j7xm8vepqwlse2gzs5");
}

test "multi_bounds: wsh(multi(20,20 keys)) equals Core's address" {
    try multiBoundsExpectAddr("wsh(multi(20," ++ comptime mkJoin("mk_K", 20) ++ "))", "bcrt1qtcukuehq2r6sev2rf26mlndsr98ttphpt8nv30ejymqyvsr7w6cqgeekdm");
}

test "multi_bounds: wsh(sortedmulti(18,18 keys)) equals Core's address" {
    try multiBoundsExpectAddr("wsh(sortedmulti(18," ++ comptime mkJoin("mk_K", 18) ++ "))", "bcrt1qdmmxnlch3ca0zt2nuclzektkyk2d5tkujhdhethga5x4tspcrehsas4u9h");
}

test "multi_bounds: sh(wsh(multi(1,17 keys))) equals Core's address" {
    try multiBoundsExpectAddr("sh(wsh(multi(1," ++ comptime mkJoin("mk_K", 17) ++ ")))", "2Mu3zGUV6z9FHXh8q6vVC7TZF2Ztkdb4Dgk");
}

test "multi_bounds: control: wsh(multi(16,16 keys)) unchanged" {
    try multiBoundsExpectAddr("wsh(multi(16," ++ comptime mkJoin("mk_K", 16) ++ "))", "bcrt1qj6hhveadu5vhq3qz7hkk07dppc03pzsqsn0jgqf06yptmxc5yldsuzsvh9");
}

test "multi_bounds: control: sh(multi(1,15 keys)) still accepted" {
    try multiBoundsExpectAddr("sh(multi(1," ++ comptime mkJoin("mk_K", 15) ++ "))", "2MsdqUB2wSVARYcGjQQ3j6pdz9B6yib7DWN");
}

test "multi_bounds: control: sh(multi(1,7 uncompressed keys)) still accepted" {
    try multiBoundsExpectAddr("sh(multi(1," ++ comptime mkJoin("mk_U", 7) ++ "))", "2N9SEpRaeYtAQXSTtxMxDgmaPbDRQ1EWj2H");
}

test "multi_bounds: k and n of 17 are pushed as script numbers, not OP_NOP bytes" {
    const allocator = std.testing.allocator;
    var desc = try parseDescriptor(allocator, "wsh(multi(17," ++ comptime mkJoin("mk_K", 17) ++ "))");
    defer desc.deinit(allocator);
    const ws = try deriveScript(allocator, desc.wsh, 0);
    defer allocator.free(ws);
    // Core: `script << 17` = 0x01 0x11 (one-byte push), never 0x61 (OP_NOP).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x11 }, ws[0..2]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x11, 0xae }, ws[ws.len - 3 ..]);
    try std.testing.expectEqual(@as(usize, 2 + 17 * 34 + 3), ws.len);
}

// Last on purpose: on a build without the bound this aborts the test
// binary (@intCast panic), so every other multi_bounds test runs first.
test "multi_bounds: wsh(multi(176,K1,K2)) is refused, not a u8 overflow" {
    try multiBoundsExpectRefused("wsh(multi(176," ++ comptime mkJoin("mk_K", 2) ++ "))", error.MultiThresholdTooLarge, "Multisig threshold cannot be larger than the number of keys; threshold is 176 but only 2 keys specified");
}
