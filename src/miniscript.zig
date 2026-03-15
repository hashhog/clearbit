const std = @import("std");
const crypto = @import("crypto.zig");
const script = @import("script.zig");
const descriptor = @import("descriptor.zig");

// ============================================================================
// Miniscript: Structured Bitcoin Script Representation
// ============================================================================
//
// Miniscript is a language for writing (a subset of) Bitcoin Scripts in a
// structured way, enabling analysis, composition, and generic signing.
//
// Reference: Bitcoin Core /src/script/miniscript.cpp
//
// Key features:
// - Type system (B, V, K, W) for compositional correctness
// - Non-malleable satisfaction computation
// - Witness size analysis
// - Script compilation
//
// ============================================================================

/// Script context - P2WSH or Tapscript have different rules
pub const ScriptContext = enum {
    p2wsh, // Witness Script Hash (BIP-141)
    tapscript, // Taproot script path (BIP-342)
};

// ============================================================================
// Type System
// ============================================================================

/// Node type properties - following Bitcoin Core's 19-bit type system
/// Basic types are mutually exclusive: B, V, K, W
pub const NodeType = enum {
    B, // Base: consumes top stack element, pushes nonzero (sat) or zero (dsat)
    V, // Verify: consumes top stack element, pushes nothing (sat), cannot dissatisfy
    K, // Key: pushes a public key for which a signature is to be provided
    W, // Wrapped: consumes element below top, pushes result at same level
};

/// Type properties - for efficiency
pub const TypeProperties = struct {
    // Basic type (one of B, V, K, W)
    base_type: NodeType = .B,

    // Stack argument properties
    z: bool = false, // Zero-arg: consumes exactly 0 stack elements
    o: bool = false, // One-arg: consumes exactly 1 stack element
    n: bool = false, // Nonzero: satisfactions don't need zero top element

    // Dissatisfaction properties
    d: bool = false, // Dissatisfiable: easy dissatisfaction exists
    e: bool = false, // Expression: dissatisfaction is non-malleable

    // Satisfaction properties
    f: bool = false, // Forced: dissatisfactions involve ≥1 signature
    s: bool = false, // Safe: satisfactions involve ≥1 signature
    m: bool = false, // Nonmalleable: non-malleable satisfaction exists
    u: bool = false, // Unit: satisfaction pushes exactly 1 (not just nonzero)

    // Implementation detail
    x: bool = false, // Expensive verify: last opcode is not EQUAL/CHECKSIG/etc

    // Timelock tracking
    has_time_lock: bool = false, // Contains time-based lock
    has_height_lock: bool = false, // Contains height-based lock


    /// Check if type is valid (no contradictions)
    pub fn isValid(self: TypeProperties) bool {
        // z conflicts with o and n
        if (self.z and (self.o or self.n)) return false;
        // n conflicts with W
        if (self.n and self.base_type == .W) return false;
        // V conflicts with d, e, u
        if (self.base_type == .V and (self.d or self.e or self.u)) return false;
        // K implies u and s
        if (self.base_type == .K and (!self.u or !self.s)) return false;
        return true;
    }

    /// Check if types are compatible for substitution
    pub fn isSubtypeOf(self: TypeProperties, other: TypeProperties) bool {
        if (self.base_type != other.base_type) return false;
        // All required properties in other must be present in self
        if (other.z and !self.z) return false;
        if (other.o and !self.o) return false;
        if (other.n and !self.n) return false;
        if (other.d and !self.d) return false;
        if (other.e and !self.e) return false;
        if (other.f and !self.f) return false;
        if (other.s and !self.s) return false;
        if (other.m and !self.m) return false;
        if (other.u and !self.u) return false;
        return true;
    }
};

// ============================================================================
// Key Type
// ============================================================================

/// Key representation for miniscript
pub const Key = union(enum) {
    /// Raw public key bytes (33 bytes compressed, 32 bytes x-only for taproot)
    pubkey: []const u8,
    /// Reference to descriptor key by index
    descriptor_key: usize,

    pub fn deinit(self: *Key, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .pubkey => |p| allocator.free(p),
            .descriptor_key => {},
        }
    }

    pub fn clone(self: Key, allocator: std.mem.Allocator) !Key {
        return switch (self) {
            .pubkey => |p| .{ .pubkey = try allocator.dupe(u8, p) },
            .descriptor_key => |idx| .{ .descriptor_key = idx },
        };
    }

    pub fn eql(self: Key, other: Key) bool {
        return switch (self) {
            .pubkey => |p| switch (other) {
                .pubkey => |o| std.mem.eql(u8, p, o),
                .descriptor_key => false,
            },
            .descriptor_key => |idx| switch (other) {
                .pubkey => false,
                .descriptor_key => |o| idx == o,
            },
        };
    }
};

// ============================================================================
// Miniscript AST Node
// ============================================================================

/// Fragment types - all possible miniscript constructs
pub const Fragment = enum {
    // Leaf fragments
    just_0, // 0
    just_1, // 1
    pk_k, // pk_k(key)
    pk_h, // pk_h(key)
    older, // older(n)
    after, // after(n)
    sha256, // sha256(hash)
    hash256, // hash256(hash)
    ripemd160, // ripemd160(hash)
    hash160, // hash160(hash)

    // Wrappers
    wrap_a, // a:X (alt stack)
    wrap_s, // s:X (swap)
    wrap_c, // c:X (checksig)
    wrap_d, // d:X (dup-if)
    wrap_v, // v:X (verify)
    wrap_j, // j:X (non-zero check)
    wrap_n, // n:X (zero-not-equal)

    // Binary combinators
    and_v, // and_v(X,Y)
    and_b, // and_b(X,Y)
    or_b, // or_b(X,Y)
    or_c, // or_c(X,Y)
    or_d, // or_d(X,Y)
    or_i, // or_i(X,Y)

    // Ternary
    andor, // andor(X,Y,Z)

    // Threshold
    thresh, // thresh(k,X1,...,Xn)

    // Multisig
    multi, // multi(k,key1,...,keyn) - P2WSH only
    multi_a, // multi_a(k,key1,...,keyn) - Tapscript only
};

/// Miniscript AST node
pub const MiniNode = struct {
    fragment: Fragment,
    // Fragment-specific data
    k: u32 = 0, // threshold for multi/thresh, time for older/after
    keys: []Key = &[_]Key{}, // keys for pk_k/pk_h/multi/multi_a
    hash: ?*const [32]u8 = null, // hash for sha256/hash256
    hash20: ?*const [20]u8 = null, // hash for ripemd160/hash160
    subs: []*MiniNode = &[_]*MiniNode{}, // child nodes

    // Cached properties
    typ: TypeProperties = .{},
    script_size: u32 = 0,
    max_witness_size: ?u32 = null,

    allocator: std.mem.Allocator,

    /// Create a new node
    pub fn create(allocator: std.mem.Allocator, fragment: Fragment) !*MiniNode {
        const node = try allocator.create(MiniNode);
        node.* = .{
            .fragment = fragment,
            .allocator = allocator,
        };
        return node;
    }

    /// Free node and all children
    pub fn deinit(self: *MiniNode) void {
        // Free children recursively
        for (self.subs) |sub| {
            sub.deinit();
            self.allocator.destroy(sub);
        }
        if (self.subs.len > 0) {
            self.allocator.free(self.subs);
        }

        // Free keys
        for (self.keys) |*k| {
            var key = k.*;
            key.deinit(self.allocator);
        }
        if (self.keys.len > 0) {
            self.allocator.free(self.keys);
        }

        // Free hash data
        if (self.hash) |h| {
            const h_ptr: [*]const u8 = @ptrCast(h);
            self.allocator.free(h_ptr[0..32]);
        }
        if (self.hash20) |h| {
            const h_ptr: [*]const u8 = @ptrCast(h);
            self.allocator.free(h_ptr[0..20]);
        }
    }

    // ========================================================================
    // Type Computation
    // ========================================================================

    /// Compute and cache type properties for this node
    pub fn computeType(self: *MiniNode, ctx: ScriptContext) void {
        self.typ = computeTypeForFragment(self.fragment, self.subs, self.k, ctx);
    }

    // ========================================================================
    // Script Compilation
    // ========================================================================

    /// Compile miniscript to Bitcoin Script
    pub fn toScript(self: *const MiniNode, allocator: std.mem.Allocator, ctx: ScriptContext) ![]u8 {
        var result = std.ArrayList(u8).init(allocator);
        errdefer result.deinit();

        try self.toScriptInner(&result, ctx, false);
        return result.toOwnedSlice();
    }

    fn toScriptInner(self: *const MiniNode, out: *std.ArrayList(u8), ctx: ScriptContext, verify: bool) !void {
        switch (self.fragment) {
            .just_0 => try out.append(0x00), // OP_0
            .just_1 => try out.append(0x51), // OP_1

            .pk_k => {
                // Push pubkey
                if (self.keys.len > 0) {
                    switch (self.keys[0]) {
                        .pubkey => |pk| try pushData(out, pk),
                        .descriptor_key => {},
                    }
                }
            },

            .pk_h => {
                // OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY
                try out.append(0x76); // OP_DUP
                try out.append(0xa9); // OP_HASH160
                if (self.keys.len > 0) {
                    switch (self.keys[0]) {
                        .pubkey => |pk| {
                            const hash = crypto.hash160(pk);
                            try out.append(0x14); // push 20 bytes
                            try out.appendSlice(&hash);
                        },
                        .descriptor_key => {},
                    }
                }
                try out.append(0x88); // OP_EQUALVERIFY
            },

            .older => {
                // <n> OP_CHECKSEQUENCEVERIFY
                try pushNumber(out, @intCast(self.k));
                try out.append(0xb2); // OP_CHECKSEQUENCEVERIFY
            },

            .after => {
                // <n> OP_CHECKLOCKTIMEVERIFY
                try pushNumber(out, @intCast(self.k));
                try out.append(0xb1); // OP_CHECKLOCKTIMEVERIFY
            },

            .sha256 => {
                // OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
                try out.append(0x82); // OP_SIZE
                try pushNumber(out, 32);
                try out.append(0x88); // OP_EQUALVERIFY
                try out.append(0xa8); // OP_SHA256
                if (self.hash) |h| {
                    try out.append(0x20); // push 32 bytes
                    try out.appendSlice(h);
                }
                try out.append(if (verify) 0x88 else 0x87); // OP_EQUALVERIFY or OP_EQUAL
            },

            .hash256 => {
                try out.append(0x82); // OP_SIZE
                try pushNumber(out, 32);
                try out.append(0x88); // OP_EQUALVERIFY
                try out.append(0xaa); // OP_HASH256
                if (self.hash) |h| {
                    try out.append(0x20);
                    try out.appendSlice(h);
                }
                try out.append(if (verify) 0x88 else 0x87);
            },

            .ripemd160 => {
                try out.append(0x82); // OP_SIZE
                try pushNumber(out, 32);
                try out.append(0x88); // OP_EQUALVERIFY
                try out.append(0xa6); // OP_RIPEMD160
                if (self.hash20) |h| {
                    try out.append(0x14); // push 20 bytes
                    try out.appendSlice(h);
                }
                try out.append(if (verify) 0x88 else 0x87);
            },

            .hash160 => {
                try out.append(0x82); // OP_SIZE
                try pushNumber(out, 32);
                try out.append(0x88); // OP_EQUALVERIFY
                try out.append(0xa9); // OP_HASH160
                if (self.hash20) |h| {
                    try out.append(0x14);
                    try out.appendSlice(h);
                }
                try out.append(if (verify) 0x88 else 0x87);
            },

            .wrap_a => {
                // OP_TOALTSTACK [X] OP_FROMALTSTACK
                try out.append(0x6b); // OP_TOALTSTACK
                if (self.subs.len > 0) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                }
                try out.append(0x6c); // OP_FROMALTSTACK
            },

            .wrap_s => {
                // OP_SWAP [X]
                try out.append(0x7c); // OP_SWAP
                if (self.subs.len > 0) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                }
            },

            .wrap_c => {
                // [X] OP_CHECKSIG(VERIFY)
                if (self.subs.len > 0) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                }
                try out.append(if (verify) 0xad else 0xac); // OP_CHECKSIGVERIFY or OP_CHECKSIG
            },

            .wrap_d => {
                // OP_DUP OP_IF [X] OP_ENDIF
                try out.append(0x76); // OP_DUP
                try out.append(0x63); // OP_IF
                if (self.subs.len > 0) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                }
                try out.append(0x68); // OP_ENDIF
            },

            .wrap_v => {
                // [X] OP_VERIFY (or use VERIFY version of last opcode)
                if (self.subs.len > 0) {
                    // Check if child's last opcode can be converted to VERIFY version
                    const child = self.subs[0];
                    const can_verify = switch (child.fragment) {
                        .wrap_c, .and_b, .or_b, .thresh => true,
                        else => false,
                    };
                    if (can_verify) {
                        try child.toScriptInner(out, ctx, true);
                    } else {
                        try child.toScriptInner(out, ctx, false);
                        try out.append(0x69); // OP_VERIFY
                    }
                }
            },

            .wrap_j => {
                // OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
                try out.append(0x82); // OP_SIZE
                try out.append(0x92); // OP_0NOTEQUAL
                try out.append(0x63); // OP_IF
                if (self.subs.len > 0) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                }
                try out.append(0x68); // OP_ENDIF
            },

            .wrap_n => {
                // [X] OP_0NOTEQUAL
                if (self.subs.len > 0) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                }
                try out.append(0x92); // OP_0NOTEQUAL
            },

            .and_v => {
                // [X] [Y]
                if (self.subs.len >= 2) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    try self.subs[1].toScriptInner(out, ctx, verify);
                }
            },

            .and_b => {
                // [X] [Y] OP_BOOLAND
                if (self.subs.len >= 2) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    try self.subs[1].toScriptInner(out, ctx, false);
                }
                try out.append(if (verify) 0x9a else 0x9a); // OP_BOOLAND (then VERIFY if needed)
                if (verify) try out.append(0x69);
            },

            .or_b => {
                // [X] [Y] OP_BOOLOR
                if (self.subs.len >= 2) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    try self.subs[1].toScriptInner(out, ctx, false);
                }
                try out.append(0x9b); // OP_BOOLOR
                if (verify) try out.append(0x69);
            },

            .or_c => {
                // [X] OP_NOTIF [Y] OP_ENDIF
                if (self.subs.len >= 2) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    try out.append(0x64); // OP_NOTIF
                    try self.subs[1].toScriptInner(out, ctx, false);
                    try out.append(0x68); // OP_ENDIF
                }
            },

            .or_d => {
                // [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
                if (self.subs.len >= 2) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    try out.append(0x73); // OP_IFDUP
                    try out.append(0x64); // OP_NOTIF
                    try self.subs[1].toScriptInner(out, ctx, false);
                    try out.append(0x68); // OP_ENDIF
                }
            },

            .or_i => {
                // OP_IF [X] OP_ELSE [Y] OP_ENDIF
                try out.append(0x63); // OP_IF
                if (self.subs.len >= 2) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    try out.append(0x67); // OP_ELSE
                    try self.subs[1].toScriptInner(out, ctx, false);
                }
                try out.append(0x68); // OP_ENDIF
            },

            .andor => {
                // [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
                if (self.subs.len >= 3) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    try out.append(0x64); // OP_NOTIF
                    try self.subs[2].toScriptInner(out, ctx, false);
                    try out.append(0x67); // OP_ELSE
                    try self.subs[1].toScriptInner(out, ctx, false);
                    try out.append(0x68); // OP_ENDIF
                }
            },

            .thresh => {
                // [X1] [X2] OP_ADD ... [Xn] OP_ADD <k> OP_EQUAL
                if (self.subs.len > 0) {
                    try self.subs[0].toScriptInner(out, ctx, false);
                    for (self.subs[1..]) |sub| {
                        try sub.toScriptInner(out, ctx, false);
                        try out.append(0x93); // OP_ADD
                    }
                }
                try pushNumber(out, @intCast(self.k));
                try out.append(if (verify) 0x88 else 0x87); // OP_EQUALVERIFY or OP_EQUAL
            },

            .multi => {
                // <k> <key1> ... <keyn> <n> OP_CHECKMULTISIG
                try pushNumber(out, @intCast(self.k));
                for (self.keys) |key| {
                    switch (key) {
                        .pubkey => |pk| try pushData(out, pk),
                        .descriptor_key => {},
                    }
                }
                try pushNumber(out, @intCast(self.keys.len));
                try out.append(if (verify) 0xaf else 0xae); // OP_CHECKMULTISIGVERIFY or OP_CHECKMULTISIG
            },

            .multi_a => {
                // Tapscript: <key1> OP_CHECKSIG <key2> OP_CHECKSIGADD ... <k> OP_NUMEQUAL
                if (self.keys.len > 0) {
                    // First key
                    switch (self.keys[0]) {
                        .pubkey => |pk| try pushData(out, pk),
                        .descriptor_key => {},
                    }
                    try out.append(0xac); // OP_CHECKSIG

                    // Remaining keys use CHECKSIGADD
                    for (self.keys[1..]) |key| {
                        switch (key) {
                            .pubkey => |pk| try pushData(out, pk),
                            .descriptor_key => {},
                        }
                        try out.append(0xba); // OP_CHECKSIGADD
                    }
                }
                try pushNumber(out, @intCast(self.k));
                try out.append(if (verify) 0x9d else 0x9c); // OP_NUMEQUALVERIFY or OP_NUMEQUAL
            },
        }
    }

    // ========================================================================
    // Analysis Functions
    // ========================================================================

    /// Compute maximum witness size for satisfaction
    pub fn computeMaxWitnessSize(self: *MiniNode, ctx: ScriptContext) u32 {
        if (self.max_witness_size) |size| {
            return size;
        }

        const size = computeWitnessSizeForFragment(self, ctx);
        self.max_witness_size = size;
        return size;
    }

    /// Compute script size
    pub fn computeScriptSize(self: *MiniNode, ctx: ScriptContext) u32 {
        if (self.script_size > 0) {
            return self.script_size;
        }

        const size = computeScriptSizeForFragment(self, ctx);
        self.script_size = size;
        return size;
    }

    /// Check if this miniscript is valid
    pub fn isValid(self: *const MiniNode, ctx: ScriptContext) bool {
        // Check type validity
        if (!self.typ.isValid()) return false;

        // Check script size limits
        const max_script_size: u32 = switch (ctx) {
            .p2wsh => 10000,
            .tapscript => 10000, // Tapscript has no inherent limit but keep reasonable
        };
        if (self.script_size > max_script_size) return false;

        return true;
    }

    /// Check if this is a valid top-level expression
    pub fn isValidTopLevel(self: *const MiniNode, ctx: ScriptContext) bool {
        if (!self.isValid(ctx)) return false;
        // Top-level must be B type
        return self.typ.base_type == .B;
    }

    /// Check if non-malleable satisfaction exists
    pub fn isNonMalleable(self: *const MiniNode) bool {
        return self.typ.m;
    }

    /// Check if satisfaction requires a signature
    pub fn needsSignature(self: *const MiniNode) bool {
        return self.typ.s;
    }

    /// Check for timelock mixing issues
    pub fn checkTimeLocksMix(self: *const MiniNode) bool {
        // Simple check - real implementation would track through tree
        return !(self.typ.has_time_lock and self.typ.has_height_lock);
    }
};

// ============================================================================
// Satisfaction Provider
// ============================================================================

/// Interface for providing signatures and preimages
pub const SatisfactionProvider = struct {
    ctx: *anyopaque,
    signFn: *const fn (ctx: *anyopaque, key: Key, allocator: std.mem.Allocator) ?[]const u8,
    preimagesFn: *const fn (ctx: *anyopaque, hash: []const u8) ?[]const u8,

    pub fn sign(self: SatisfactionProvider, key: Key, allocator: std.mem.Allocator) ?[]const u8 {
        return self.signFn(self.ctx, key, allocator);
    }

    pub fn getPreimage(self: SatisfactionProvider, hash: []const u8) ?[]const u8 {
        return self.preimagesFn(self.ctx, hash);
    }
};

// ============================================================================
// Satisfaction
// ============================================================================

/// Witness stack for satisfaction
pub const Witness = struct {
    stack: [][]const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Witness {
        return .{
            .stack = &[_][]const u8{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Witness) void {
        for (self.stack) |item| {
            self.allocator.free(item);
        }
        if (self.stack.len > 0) {
            self.allocator.free(self.stack);
        }
    }

    pub fn append(self: *Witness, item: []const u8) !void {
        const new_stack = try self.allocator.alloc([]const u8, self.stack.len + 1);
        @memcpy(new_stack[0..self.stack.len], self.stack);
        new_stack[self.stack.len] = try self.allocator.dupe(u8, item);
        if (self.stack.len > 0) {
            self.allocator.free(self.stack);
        }
        self.stack = new_stack;
    }

    pub fn size(self: *const Witness) u32 {
        var total: u32 = 0;
        for (self.stack) |item| {
            total += @intCast(item.len);
            // Add varint length encoding
            if (item.len < 253) {
                total += 1;
            } else if (item.len < 65536) {
                total += 3;
            } else {
                total += 5;
            }
        }
        return total;
    }
};

/// Satisfaction result
pub const SatisfactionResult = union(enum) {
    success: Witness,
    impossible,
    needs_more_data,

    pub fn deinit(self: *SatisfactionResult) void {
        switch (self.*) {
            .success => |*w| w.deinit(),
            else => {},
        }
    }
};

/// Attempt to satisfy a miniscript expression
pub fn satisfy(
    node: *const MiniNode,
    provider: SatisfactionProvider,
    allocator: std.mem.Allocator,
) SatisfactionResult {
    return satisfyInner(node, provider, allocator, false);
}

fn satisfyInner(
    node: *const MiniNode,
    provider: SatisfactionProvider,
    allocator: std.mem.Allocator,
    dissatisfy: bool,
) SatisfactionResult {
    _ = dissatisfy;
    switch (node.fragment) {
        .just_0 => {
            // Dissatisfaction: nothing needed (script pushes 0)
            return .{ .success = Witness.init(allocator) };
        },

        .just_1 => {
            // Satisfaction: nothing needed (script pushes 1)
            return .{ .success = Witness.init(allocator) };
        },

        .pk_k => {
            // Satisfaction: signature
            if (node.keys.len > 0) {
                if (provider.sign(node.keys[0], allocator)) |sig| {
                    var witness = Witness.init(allocator);
                    witness.append(sig) catch return .impossible;
                    allocator.free(sig);
                    return .{ .success = witness };
                }
            }
            return .needs_more_data;
        },

        .pk_h => {
            // Satisfaction: signature + pubkey
            if (node.keys.len > 0) {
                if (provider.sign(node.keys[0], allocator)) |sig| {
                    var witness = Witness.init(allocator);
                    witness.append(sig) catch {
                        allocator.free(sig);
                        return .impossible;
                    };
                    allocator.free(sig);

                    switch (node.keys[0]) {
                        .pubkey => |pk| {
                            witness.append(pk) catch return .impossible;
                        },
                        .descriptor_key => {},
                    }
                    return .{ .success = witness };
                }
            }
            return .needs_more_data;
        },

        .sha256, .hash256, .ripemd160, .hash160 => {
            // Satisfaction: preimage
            const hash_bytes: []const u8 = if (node.hash) |h| h else if (node.hash20) |h| h else return .impossible;
            if (provider.getPreimage(hash_bytes)) |preimage| {
                var witness = Witness.init(allocator);
                witness.append(preimage) catch return .impossible;
                return .{ .success = witness };
            }
            return .needs_more_data;
        },

        .older, .after => {
            // Satisfaction: empty (timelock checked against tx)
            return .{ .success = Witness.init(allocator) };
        },

        .wrap_c => {
            // Satisfaction: satisfy child (pushes key), then signature check
            if (node.subs.len > 0) {
                return satisfyInner(node.subs[0], provider, allocator, false);
            }
            return .impossible;
        },

        .wrap_v, .wrap_n, .wrap_s, .wrap_a => {
            // Pass through to child
            if (node.subs.len > 0) {
                return satisfyInner(node.subs[0], provider, allocator, false);
            }
            return .impossible;
        },

        .wrap_d => {
            // Satisfaction: satisfy child, push 1
            // Dissatisfaction: push 0
            if (node.subs.len > 0) {
                var result = satisfyInner(node.subs[0], provider, allocator, false);
                switch (result) {
                    .success => |*w| {
                        w.append(&[_]u8{0x01}) catch return .impossible;
                        return result;
                    },
                    else => return result,
                }
            }
            return .impossible;
        },

        .wrap_j => {
            // Satisfaction: satisfy child with non-zero input
            if (node.subs.len > 0) {
                return satisfyInner(node.subs[0], provider, allocator, false);
            }
            return .impossible;
        },

        .and_v, .and_b => {
            // Satisfaction: satisfy both children
            if (node.subs.len >= 2) {
                var result1 = satisfyInner(node.subs[0], provider, allocator, false);
                switch (result1) {
                    .success => |*w1| {
                        var result2 = satisfyInner(node.subs[1], provider, allocator, false);
                        switch (result2) {
                            .success => |*w2| {
                                // Combine witnesses (Y's witness first, then X's)
                                var combined = Witness.init(allocator);
                                for (w2.stack) |item| {
                                    combined.append(item) catch {
                                        w1.deinit();
                                        w2.deinit();
                                        combined.deinit();
                                        return .impossible;
                                    };
                                }
                                for (w1.stack) |item| {
                                    combined.append(item) catch {
                                        w1.deinit();
                                        w2.deinit();
                                        combined.deinit();
                                        return .impossible;
                                    };
                                }
                                w1.deinit();
                                w2.deinit();
                                return .{ .success = combined };
                            },
                            else => {
                                w1.deinit();
                                return result2;
                            },
                        }
                    },
                    else => return result1,
                }
            }
            return .impossible;
        },

        .or_b, .or_c, .or_d => {
            // Try to satisfy first branch, fall back to second
            if (node.subs.len >= 2) {
                var result1 = satisfyInner(node.subs[0], provider, allocator, false);
                switch (result1) {
                    .success => return result1,
                    else => {
                        result1.deinit();
                        return satisfyInner(node.subs[1], provider, allocator, false);
                    },
                }
            }
            return .impossible;
        },

        .or_i => {
            // OP_IF [X] OP_ELSE [Y] OP_ENDIF
            // Satisfaction: 1 + satisfy(X) OR 0 + satisfy(Y)
            if (node.subs.len >= 2) {
                // Try X first
                var result1 = satisfyInner(node.subs[0], provider, allocator, false);
                switch (result1) {
                    .success => |*w1| {
                        w1.append(&[_]u8{0x01}) catch {
                            w1.deinit();
                            return .impossible;
                        };
                        return result1;
                    },
                    else => {
                        result1.deinit();
                        // Try Y
                        var result2 = satisfyInner(node.subs[1], provider, allocator, false);
                        switch (result2) {
                            .success => |*w2| {
                                w2.append(&[_]u8{}) catch {
                                    w2.deinit();
                                    return .impossible;
                                };
                                return result2;
                            },
                            else => return result2,
                        }
                    },
                }
            }
            return .impossible;
        },

        .andor => {
            // andor(X,Y,Z): if X then Y else Z
            if (node.subs.len >= 3) {
                // Try X && Y
                var result_x = satisfyInner(node.subs[0], provider, allocator, false);
                switch (result_x) {
                    .success => |*wx| {
                        var result_y = satisfyInner(node.subs[1], provider, allocator, false);
                        switch (result_y) {
                            .success => |*wy| {
                                // Combine
                                var combined = Witness.init(allocator);
                                for (wy.stack) |item| {
                                    combined.append(item) catch {
                                        wx.deinit();
                                        wy.deinit();
                                        combined.deinit();
                                        return .impossible;
                                    };
                                }
                                for (wx.stack) |item| {
                                    combined.append(item) catch {
                                        wx.deinit();
                                        wy.deinit();
                                        combined.deinit();
                                        return .impossible;
                                    };
                                }
                                wx.deinit();
                                wy.deinit();
                                return .{ .success = combined };
                            },
                            else => {
                                wx.deinit();
                            },
                        }
                    },
                    else => {},
                }
                result_x.deinit();

                // Fall back to Z
                return satisfyInner(node.subs[2], provider, allocator, false);
            }
            return .impossible;
        },

        .thresh => {
            // Need exactly k satisfactions
            if (node.subs.len == 0) return .impossible;

            var satisfied_count: u32 = 0;
            var combined = Witness.init(allocator);

            for (node.subs) |sub| {
                var result = satisfyInner(sub, provider, allocator, false);
                switch (result) {
                    .success => |*w| {
                        satisfied_count += 1;
                        for (w.stack) |item| {
                            combined.append(item) catch {
                                w.deinit();
                                combined.deinit();
                                return .impossible;
                            };
                        }
                        w.deinit();
                    },
                    else => {
                        // Push empty for dissatisfaction
                        combined.append(&[_]u8{}) catch {
                            combined.deinit();
                            return .impossible;
                        };
                    },
                }
            }

            if (satisfied_count >= node.k) {
                return .{ .success = combined };
            } else {
                combined.deinit();
                return .needs_more_data;
            }
        },

        .multi => {
            // Need k signatures for multi
            var sigs = std.ArrayList([]const u8).init(allocator);
            defer sigs.deinit();

            for (node.keys) |key| {
                if (provider.sign(key, allocator)) |sig| {
                    sigs.append(sig) catch {
                        for (sigs.items) |s| allocator.free(s);
                        return .impossible;
                    };
                    if (sigs.items.len >= node.k) break;
                }
            }

            if (sigs.items.len >= node.k) {
                var witness = Witness.init(allocator);
                // Push dummy for CHECKMULTISIG bug
                witness.append(&[_]u8{}) catch {
                    for (sigs.items) |s| allocator.free(s);
                    return .impossible;
                };
                for (sigs.items) |sig| {
                    witness.append(sig) catch {
                        for (sigs.items) |s| allocator.free(s);
                        witness.deinit();
                        return .impossible;
                    };
                }
                for (sigs.items) |s| allocator.free(s);
                return .{ .success = witness };
            }

            for (sigs.items) |s| allocator.free(s);
            return .needs_more_data;
        },

        .multi_a => {
            // Tapscript multi: need k signatures
            var witness = Witness.init(allocator);
            var sig_count: u32 = 0;

            // Keys are checked in reverse order for CHECKSIGADD
            var i: usize = node.keys.len;
            while (i > 0) {
                i -= 1;
                const key = node.keys[i];
                if (sig_count < node.k) {
                    if (provider.sign(key, allocator)) |sig| {
                        witness.append(sig) catch {
                            allocator.free(sig);
                            witness.deinit();
                            return .impossible;
                        };
                        allocator.free(sig);
                        sig_count += 1;
                        continue;
                    }
                }
                // Push empty for non-signing keys
                witness.append(&[_]u8{}) catch {
                    witness.deinit();
                    return .impossible;
                };
            }

            if (sig_count >= node.k) {
                return .{ .success = witness };
            }
            witness.deinit();
            return .needs_more_data;
        },
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Push data with appropriate push opcode
fn pushData(out: *std.ArrayList(u8), data: []const u8) !void {
    if (data.len < 0x4c) {
        try out.append(@intCast(data.len));
    } else if (data.len <= 0xff) {
        try out.append(0x4c); // OP_PUSHDATA1
        try out.append(@intCast(data.len));
    } else if (data.len <= 0xffff) {
        try out.append(0x4d); // OP_PUSHDATA2
        try out.appendSlice(&std.mem.toBytes(@as(u16, @intCast(data.len))));
    } else {
        try out.append(0x4e); // OP_PUSHDATA4
        try out.appendSlice(&std.mem.toBytes(@as(u32, @intCast(data.len))));
    }
    try out.appendSlice(data);
}

/// Push a number using minimal encoding
fn pushNumber(out: *std.ArrayList(u8), n: i64) !void {
    if (n == 0) {
        try out.append(0x00); // OP_0
    } else if (n >= 1 and n <= 16) {
        try out.append(@intCast(0x50 + n)); // OP_1 through OP_16
    } else if (n == -1) {
        try out.append(0x4f); // OP_1NEGATE
    } else {
        // Encode as script number
        var buf: [9]u8 = undefined;
        const len = encodeScriptNum(n, &buf);
        try out.append(@intCast(len));
        try out.appendSlice(buf[0..len]);
    }
}

fn encodeScriptNum(value: i64, buf: *[9]u8) usize {
    if (value == 0) return 0;

    const negative = value < 0;
    var abs_val: u64 = if (negative) @intCast(-value) else @intCast(value);

    var len: usize = 0;
    while (abs_val > 0) {
        buf[len] = @truncate(abs_val);
        abs_val >>= 8;
        len += 1;
    }

    // Add sign bit if needed
    if (buf[len - 1] & 0x80 != 0) {
        buf[len] = if (negative) 0x80 else 0x00;
        len += 1;
    } else if (negative) {
        buf[len - 1] |= 0x80;
    }

    return len;
}

/// Compute type for a fragment
fn computeTypeForFragment(
    fragment: Fragment,
    subs: []*MiniNode,
    k: u32,
    ctx: ScriptContext,
) TypeProperties {
    _ = k;
    _ = ctx;

    switch (fragment) {
        .just_0 => return .{
            .base_type = .B,
            .z = true,
            .d = true,
            .e = true,
            .u = true,
        },

        .just_1 => return .{
            .base_type = .B,
            .z = true,
            .u = true,
        },

        .pk_k => return .{
            .base_type = .K,
            .o = true,
            .n = true,
            .d = true,
            .u = true,
            .e = true,
            .m = true,
            .s = true,
            .x = true,
        },

        .pk_h => return .{
            .base_type = .K,
            .n = true,
            .d = true,
            .u = true,
            .e = true,
            .m = true,
            .s = true,
            .x = true,
        },

        .older, .after => return .{
            .base_type = .B,
            .z = true,
            .f = true,
            .m = true,
        },

        .sha256, .hash256, .ripemd160, .hash160 => return .{
            .base_type = .B,
            .o = true,
            .n = true,
            .d = true,
            .u = true,
            .m = true,
        },

        .wrap_a => {
            if (subs.len > 0) {
                const x = subs[0].typ;
                return .{
                    .base_type = if (x.base_type == .B) .W else x.base_type,
                    .d = x.d,
                    .e = x.e,
                    .f = x.f,
                    .s = x.s,
                    .m = x.m,
                    .u = x.u,
                    .x = true,
                };
            }
            return .{};
        },

        .wrap_s => {
            if (subs.len > 0) {
                const x = subs[0].typ;
                return .{
                    .base_type = if (x.base_type == .B) .W else x.base_type,
                    .o = x.o,
                    .d = x.d,
                    .e = x.e,
                    .f = x.f,
                    .s = x.s,
                    .m = x.m,
                    .u = x.u,
                    .x = x.x,
                };
            }
            return .{};
        },

        .wrap_c => {
            if (subs.len > 0) {
                const x = subs[0].typ;
                if (x.base_type == .K) {
                    return .{
                        .base_type = .B,
                        .o = x.o,
                        .n = x.n,
                        .d = x.d,
                        .u = true,
                        .e = x.e,
                        .m = x.m,
                        .s = true,
                    };
                }
            }
            return .{};
        },

        .wrap_d => {
            if (subs.len > 0) {
                const x = subs[0].typ;
                if (x.base_type == .V) {
                    return .{
                        .base_type = .B,
                        .o = x.o,
                        .e = true,
                        .d = true,
                        .u = true,
                        .f = x.f,
                        .m = x.m,
                        .s = x.s,
                    };
                }
            }
            return .{};
        },

        .wrap_v => {
            if (subs.len > 0) {
                const x = subs[0].typ;
                if (x.base_type == .B) {
                    return .{
                        .base_type = .V,
                        .z = x.z,
                        .o = x.o,
                        .n = x.n,
                        .f = true,
                        .m = x.m,
                        .s = x.s,
                        .x = x.x,
                    };
                }
            }
            return .{};
        },

        .wrap_j => {
            if (subs.len > 0) {
                const x = subs[0].typ;
                if (x.base_type == .B and x.n) {
                    return .{
                        .base_type = .B,
                        .o = x.o,
                        .e = true,
                        .d = true,
                        .u = true,
                        .f = x.f,
                        .m = x.m,
                        .s = x.s,
                    };
                }
            }
            return .{};
        },

        .wrap_n => {
            if (subs.len > 0) {
                const x = subs[0].typ;
                if (x.base_type == .B) {
                    return .{
                        .base_type = .B,
                        .z = x.z,
                        .o = x.o,
                        .n = x.n,
                        .d = x.d,
                        .u = true,
                        .e = x.e,
                        .f = x.f,
                        .m = x.m,
                        .s = x.s,
                        .x = true,
                    };
                }
            }
            return .{};
        },

        .and_v => {
            if (subs.len >= 2) {
                const x = subs[0].typ;
                const y = subs[1].typ;
                if (x.base_type == .V) {
                    return .{
                        .base_type = y.base_type,
                        .z = x.z and y.z,
                        .o = (x.z and y.o) or (x.o and y.z),
                        .n = x.n or (x.z and y.n),
                        .u = y.u,
                        .f = y.f or x.s,
                        .m = x.m and y.m and (x.s or !y.f),
                        .s = x.s or y.s,
                        .x = y.x,
                    };
                }
            }
            return .{};
        },

        .and_b => {
            if (subs.len >= 2) {
                const x = subs[0].typ;
                const y = subs[1].typ;
                if (x.base_type == .B and y.base_type == .W) {
                    return .{
                        .base_type = .B,
                        .z = x.z and y.z,
                        .o = (x.z and y.o) or (x.o and y.z),
                        .n = x.n or (x.z and y.n),
                        .d = x.d and y.d,
                        .u = true,
                        .e = x.e and y.e and (x.s or y.s),
                        .f = x.f and y.f,
                        .m = x.m and y.m and (x.e and y.e) and (x.s or y.s),
                        .s = x.s or y.s,
                        .x = true,
                    };
                }
            }
            return .{};
        },

        .or_b => {
            if (subs.len >= 2) {
                const x = subs[0].typ;
                const y = subs[1].typ;
                if (x.base_type == .B and y.base_type == .W and x.d and y.d) {
                    return .{
                        .base_type = .B,
                        .z = x.z and y.z,
                        .o = (x.z and y.o) or (x.o and y.z),
                        .d = true,
                        .u = true,
                        .e = x.e and y.e,
                        .m = x.m and y.m and x.e and y.e and (x.s or y.s),
                        .s = x.s and y.s,
                        .x = true,
                    };
                }
            }
            return .{};
        },

        .or_c => {
            if (subs.len >= 2) {
                const x = subs[0].typ;
                const y = subs[1].typ;
                if (x.base_type == .B and y.base_type == .V and x.d) {
                    return .{
                        .base_type = .V,
                        .z = x.z and y.z,
                        .o = x.o and y.z,
                        .f = true,
                        .m = x.m and y.m and x.e and (x.s or y.s),
                        .s = x.s and y.s,
                        .x = true,
                    };
                }
            }
            return .{};
        },

        .or_d => {
            if (subs.len >= 2) {
                const x = subs[0].typ;
                const y = subs[1].typ;
                if (x.base_type == .B and y.base_type == .B and x.d and x.u) {
                    return .{
                        .base_type = .B,
                        .z = x.z and y.z,
                        .o = x.o and y.z,
                        .d = y.d,
                        .u = y.u,
                        .e = x.e and y.e,
                        .f = y.f,
                        .m = x.m and y.m and x.e and (x.s or y.s),
                        .s = x.s and y.s,
                        .x = true,
                    };
                }
            }
            return .{};
        },

        .or_i => {
            if (subs.len >= 2) {
                const x = subs[0].typ;
                const y = subs[1].typ;
                if (x.base_type == y.base_type) {
                    return .{
                        .base_type = x.base_type,
                        .o = x.z and y.z,
                        .d = x.d or y.d,
                        .u = x.u and y.u,
                        .e = (x.e and y.f) or (x.f and y.e) or (x.e and y.e and x.s and y.s),
                        .f = x.f and y.f,
                        .m = x.m and y.m and (x.s or y.s),
                        .s = x.s and y.s,
                        .x = true,
                    };
                }
            }
            return .{};
        },

        .andor => {
            if (subs.len >= 3) {
                const x = subs[0].typ;
                const y = subs[1].typ;
                const z = subs[2].typ;
                if (x.base_type == .B and y.base_type == z.base_type and x.d and x.u) {
                    return .{
                        .base_type = y.base_type,
                        .z = x.z and y.z and z.z,
                        .o = (x.z and y.o and z.o) or (x.o and y.z and z.z),
                        .d = z.d,
                        .u = y.u and z.u,
                        .e = x.e and z.e and (x.s or z.s),
                        .f = z.f and (x.s or y.f),
                        .m = x.m and y.m and z.m and x.e and (x.s or y.s) and (x.s or z.s),
                        .s = z.s and (x.s or y.s),
                        .x = true,
                    };
                }
            }
            return .{};
        },

        .thresh => {
            // Threshold type computation is more complex
            var result = TypeProperties{
                .base_type = .B,
                .z = true,
                .o = false,
                .m = true,
                .s = false,
                .d = true,
                .u = true,
                .x = true,
            };

            for (subs) |sub| {
                result.z = result.z and sub.typ.z;
                result.m = result.m and sub.typ.m;
                result.s = result.s or sub.typ.s;
                result.d = result.d and sub.typ.d;
            }

            return result;
        },

        .multi, .multi_a => return .{
            .base_type = .B,
            .n = true,
            .d = true,
            .u = true,
            .e = true,
            .m = true,
            .s = true,
        },
    }
}

/// Compute witness size for a fragment
fn computeWitnessSizeForFragment(node: *MiniNode, ctx: ScriptContext) u32 {
    const sig_size: u32 = switch (ctx) {
        .p2wsh => 73, // ECDSA signature + sighash byte
        .tapscript => 65, // Schnorr signature + sighash byte
    };

    switch (node.fragment) {
        .just_0, .just_1, .older, .after => return 0,

        .pk_k => return sig_size,
        .pk_h => return sig_size + 34, // signature + pubkey

        .sha256, .hash256, .ripemd160, .hash160 => return 33, // 32-byte preimage + length

        .wrap_a, .wrap_s, .wrap_c, .wrap_v, .wrap_j, .wrap_n => {
            if (node.subs.len > 0) {
                return node.subs[0].computeMaxWitnessSize(ctx);
            }
            return 0;
        },

        .wrap_d => {
            if (node.subs.len > 0) {
                return node.subs[0].computeMaxWitnessSize(ctx) + 1;
            }
            return 1;
        },

        .and_v, .and_b => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeMaxWitnessSize(ctx);
            }
            return total;
        },

        .or_b, .or_c, .or_d, .or_i => {
            if (node.subs.len >= 2) {
                const w1 = node.subs[0].computeMaxWitnessSize(ctx);
                const w2 = node.subs[1].computeMaxWitnessSize(ctx);
                return @max(w1, w2) + 1; // +1 for branch selector
            }
            return 0;
        },

        .andor => {
            if (node.subs.len >= 3) {
                const wx = node.subs[0].computeMaxWitnessSize(ctx);
                const wy = node.subs[1].computeMaxWitnessSize(ctx);
                const wz = node.subs[2].computeMaxWitnessSize(ctx);
                return @max(wx + wy, wz);
            }
            return 0;
        },

        .thresh => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeMaxWitnessSize(ctx);
            }
            return total;
        },

        .multi => {
            // k signatures + dummy
            return node.k * sig_size + 1;
        },

        .multi_a => {
            // k signatures + (n-k) empty pushes
            const n: u32 = @intCast(node.keys.len);
            return node.k * sig_size + (n - node.k);
        },
    }
}

/// Compute script size for a fragment
fn computeScriptSizeForFragment(node: *MiniNode, ctx: ScriptContext) u32 {
    const key_size: u32 = switch (ctx) {
        .p2wsh => 34, // compressed pubkey + push
        .tapscript => 33, // x-only pubkey + push
    };

    switch (node.fragment) {
        .just_0, .just_1 => return 1,

        .pk_k => return key_size,
        .pk_h => return 24, // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY

        .older, .after => {
            // <n> OP_CSV or OP_CLTV
            return scriptNumSize(@intCast(node.k)) + 1;
        },

        .sha256, .hash256 => {
            // OP_SIZE <32> OP_EQUALVERIFY OP_SHA256/OP_HASH256 <32> OP_EQUAL
            return 1 + 2 + 1 + 1 + 33 + 1;
        },

        .ripemd160, .hash160 => {
            // OP_SIZE <32> OP_EQUALVERIFY OP_RIPEMD160/OP_HASH160 <20> OP_EQUAL
            return 1 + 2 + 1 + 1 + 21 + 1;
        },

        .wrap_a => {
            if (node.subs.len > 0) {
                return node.subs[0].computeScriptSize(ctx) + 2;
            }
            return 2;
        },

        .wrap_s, .wrap_c, .wrap_n => {
            if (node.subs.len > 0) {
                return node.subs[0].computeScriptSize(ctx) + 1;
            }
            return 1;
        },

        .wrap_d => {
            if (node.subs.len > 0) {
                return node.subs[0].computeScriptSize(ctx) + 3;
            }
            return 3;
        },

        .wrap_v => {
            if (node.subs.len > 0) {
                // May merge with child's last opcode
                return node.subs[0].computeScriptSize(ctx) + 1;
            }
            return 1;
        },

        .wrap_j => {
            if (node.subs.len > 0) {
                return node.subs[0].computeScriptSize(ctx) + 4;
            }
            return 4;
        },

        .and_v => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeScriptSize(ctx);
            }
            return total;
        },

        .and_b, .or_b => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeScriptSize(ctx);
            }
            return total + 1; // +OP_BOOLAND or OP_BOOLOR
        },

        .or_c => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeScriptSize(ctx);
            }
            return total + 2; // +OP_NOTIF +OP_ENDIF
        },

        .or_d => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeScriptSize(ctx);
            }
            return total + 3; // +OP_IFDUP +OP_NOTIF +OP_ENDIF
        },

        .or_i => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeScriptSize(ctx);
            }
            return total + 3; // +OP_IF +OP_ELSE +OP_ENDIF
        },

        .andor => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeScriptSize(ctx);
            }
            return total + 3; // +OP_NOTIF +OP_ELSE +OP_ENDIF
        },

        .thresh => {
            var total: u32 = 0;
            for (node.subs) |sub| {
                total += sub.computeScriptSize(ctx);
            }
            // Add OP_ADDs and final comparison
            return total + @as(u32, @intCast(node.subs.len)) - 1 + scriptNumSize(@intCast(node.k)) + 1;
        },

        .multi => {
            // <k> <key1> ... <keyn> <n> OP_CHECKMULTISIG
            const n: u32 = @intCast(node.keys.len);
            return scriptNumSize(@intCast(node.k)) + n * key_size + scriptNumSize(@intCast(n)) + 1;
        },

        .multi_a => {
            // <key1> OP_CHECKSIG (<keyn> OP_CHECKSIGADD)* <k> OP_NUMEQUAL
            const n: u32 = @intCast(node.keys.len);
            return n * (key_size + 1) + scriptNumSize(@intCast(node.k)) + 1;
        },
    }
}

fn scriptNumSize(n: i64) u32 {
    if (n == 0) return 1;
    if (n >= 1 and n <= 16) return 1;
    if (n == -1) return 1;

    var abs_n: u64 = if (n < 0) @intCast(-n) else @intCast(n);
    var size: u32 = 0;
    while (abs_n > 0) {
        size += 1;
        abs_n >>= 8;
    }
    return size + 1; // +1 for push opcode
}

// ============================================================================
// Parser
// ============================================================================

pub const ParseError = error{
    InvalidSyntax,
    UnknownFragment,
    ExpectedOpenParen,
    ExpectedCloseParen,
    ExpectedComma,
    InvalidNumber,
    InvalidKey,
    InvalidHash,
    OutOfMemory,
    UnexpectedEnd,
};

/// Parse a miniscript string into an AST
pub fn parse(allocator: std.mem.Allocator, input: []const u8, ctx: ScriptContext) ParseError!*MiniNode {
    var parser = Parser{
        .input = input,
        .pos = 0,
        .allocator = allocator,
        .ctx = ctx,
    };
    return parser.parseExpr();
}

const Parser = struct {
    input: []const u8,
    pos: usize,
    allocator: std.mem.Allocator,
    ctx: ScriptContext,

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
            if (c != ' ' and c != '\t' and c != '\n') break;
            _ = self.advance();
        }
    }

    fn readIdent(self: *Parser) []const u8 {
        const start = self.pos;
        while (self.peek()) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '_') break;
            _ = self.advance();
        }
        return self.input[start..self.pos];
    }

    fn expect(self: *Parser, c: u8) ParseError!void {
        self.skipWhitespace();
        if (self.advance() != c) {
            return if (c == '(') ParseError.ExpectedOpenParen else if (c == ')') ParseError.ExpectedCloseParen else ParseError.InvalidSyntax;
        }
    }

    fn parseExpr(self: *Parser) ParseError!*MiniNode {
        self.skipWhitespace();

        // Check for wrappers (single letter followed by colon)
        if (self.pos + 1 < self.input.len and self.input[self.pos + 1] == ':') {
            const wrapper = self.input[self.pos];
            self.pos += 2; // skip 'X:'

            const inner = try self.parseExpr();
            errdefer {
                inner.deinit();
                self.allocator.destroy(inner);
            }

            const fragment: Fragment = switch (wrapper) {
                'a' => .wrap_a,
                's' => .wrap_s,
                'c' => .wrap_c,
                'd' => .wrap_d,
                'v' => .wrap_v,
                'j' => .wrap_j,
                'n' => .wrap_n,
                't' => {
                    // t:X = and_v(X,1)
                    const one = MiniNode.create(self.allocator, .just_1) catch return ParseError.OutOfMemory;
                    const subs = self.allocator.alloc(*MiniNode, 2) catch return ParseError.OutOfMemory;
                    subs[0] = inner;
                    subs[1] = one;
                    const node = MiniNode.create(self.allocator, .and_v) catch return ParseError.OutOfMemory;
                    node.subs = subs;
                    node.computeType(self.ctx);
                    return node;
                },
                'l' => {
                    // l:X = or_i(0,X)
                    const zero = MiniNode.create(self.allocator, .just_0) catch return ParseError.OutOfMemory;
                    const subs = self.allocator.alloc(*MiniNode, 2) catch return ParseError.OutOfMemory;
                    subs[0] = zero;
                    subs[1] = inner;
                    const node = MiniNode.create(self.allocator, .or_i) catch return ParseError.OutOfMemory;
                    node.subs = subs;
                    node.computeType(self.ctx);
                    return node;
                },
                'u' => {
                    // u:X = or_i(X,0)
                    const zero = MiniNode.create(self.allocator, .just_0) catch return ParseError.OutOfMemory;
                    const subs = self.allocator.alloc(*MiniNode, 2) catch return ParseError.OutOfMemory;
                    subs[0] = inner;
                    subs[1] = zero;
                    const node = MiniNode.create(self.allocator, .or_i) catch return ParseError.OutOfMemory;
                    node.subs = subs;
                    node.computeType(self.ctx);
                    return node;
                },
                else => return ParseError.UnknownFragment,
            };

            const subs = self.allocator.alloc(*MiniNode, 1) catch return ParseError.OutOfMemory;
            subs[0] = inner;

            const node = MiniNode.create(self.allocator, fragment) catch return ParseError.OutOfMemory;
            node.subs = subs;
            node.computeType(self.ctx);
            return node;
        }

        // Parse fragment name
        const name = self.readIdent();

        if (std.mem.eql(u8, name, "0")) {
            const node = MiniNode.create(self.allocator, .just_0) catch return ParseError.OutOfMemory;
            node.computeType(self.ctx);
            return node;
        }

        if (std.mem.eql(u8, name, "1")) {
            const node = MiniNode.create(self.allocator, .just_1) catch return ParseError.OutOfMemory;
            node.computeType(self.ctx);
            return node;
        }

        try self.expect('(');

        const fragment: Fragment = getFragment(name) orelse return ParseError.UnknownFragment;

        var node = MiniNode.create(self.allocator, fragment) catch return ParseError.OutOfMemory;
        errdefer {
            node.deinit();
            self.allocator.destroy(node);
        }

        // Parse arguments based on fragment type
        switch (fragment) {
            .pk_k, .pk_h => {
                const key = try self.parseKey();
                node.keys = self.allocator.alloc(Key, 1) catch return ParseError.OutOfMemory;
                node.keys[0] = key;
            },

            .older, .after => {
                node.k = try self.parseNumber();
            },

            .sha256, .hash256 => {
                const hash = try self.parseHash32();
                const hash_ptr = self.allocator.create([32]u8) catch return ParseError.OutOfMemory;
                hash_ptr.* = hash;
                node.hash = hash_ptr;
            },

            .ripemd160, .hash160 => {
                const hash = try self.parseHash20();
                const hash_ptr = self.allocator.create([20]u8) catch return ParseError.OutOfMemory;
                hash_ptr.* = hash;
                node.hash20 = hash_ptr;
            },

            .and_v, .and_b, .or_b, .or_c, .or_d, .or_i => {
                const x = try self.parseExpr();
                try self.expect(',');
                const y = try self.parseExpr();
                node.subs = self.allocator.alloc(*MiniNode, 2) catch return ParseError.OutOfMemory;
                node.subs[0] = x;
                node.subs[1] = y;
            },

            .andor => {
                const x = try self.parseExpr();
                try self.expect(',');
                const y = try self.parseExpr();
                try self.expect(',');
                const z = try self.parseExpr();
                node.subs = self.allocator.alloc(*MiniNode, 3) catch return ParseError.OutOfMemory;
                node.subs[0] = x;
                node.subs[1] = y;
                node.subs[2] = z;
            },

            .thresh => {
                node.k = try self.parseNumber();
                try self.expect(',');

                var subs_list = std.ArrayList(*MiniNode).init(self.allocator);
                errdefer {
                    for (subs_list.items) |s| {
                        s.deinit();
                        self.allocator.destroy(s);
                    }
                    subs_list.deinit();
                }

                while (true) {
                    const sub = try self.parseExpr();
                    subs_list.append(sub) catch return ParseError.OutOfMemory;
                    self.skipWhitespace();
                    if (self.peek() == ')') break;
                    try self.expect(',');
                }

                node.subs = subs_list.toOwnedSlice() catch return ParseError.OutOfMemory;
            },

            .multi, .multi_a => {
                node.k = try self.parseNumber();
                try self.expect(',');

                var keys_list = std.ArrayList(Key).init(self.allocator);
                errdefer {
                    for (keys_list.items) |*k| {
                        k.deinit(self.allocator);
                    }
                    keys_list.deinit();
                }

                while (true) {
                    const key = try self.parseKey();
                    keys_list.append(key) catch return ParseError.OutOfMemory;
                    self.skipWhitespace();
                    if (self.peek() == ')') break;
                    try self.expect(',');
                }

                node.keys = keys_list.toOwnedSlice() catch return ParseError.OutOfMemory;
            },

            else => {},
        }

        try self.expect(')');
        node.computeType(self.ctx);
        return node;
    }

    fn parseKey(self: *Parser) ParseError!Key {
        self.skipWhitespace();
        const start = self.pos;

        // Read until delimiter
        while (self.peek()) |c| {
            if (c == ',' or c == ')') break;
            _ = self.advance();
        }

        const key_str = std.mem.trim(u8, self.input[start..self.pos], " \t\n");
        if (key_str.len == 0) return ParseError.InvalidKey;

        // Check if it's hex
        if (isHex(key_str)) {
            const decoded = decodeHex(self.allocator, key_str) catch return ParseError.InvalidKey;
            return .{ .pubkey = decoded };
        }

        // Otherwise treat as descriptor key reference
        return .{ .descriptor_key = 0 };
    }

    fn parseNumber(self: *Parser) ParseError!u32 {
        self.skipWhitespace();
        const start = self.pos;

        while (self.peek()) |c| {
            if (!std.ascii.isDigit(c)) break;
            _ = self.advance();
        }

        const num_str = self.input[start..self.pos];
        return std.fmt.parseInt(u32, num_str, 10) catch return ParseError.InvalidNumber;
    }

    fn parseHash32(self: *Parser) ParseError![32]u8 {
        self.skipWhitespace();
        const start = self.pos;

        while (self.peek()) |c| {
            if (!std.ascii.isHex(c)) break;
            _ = self.advance();
        }

        const hex_str = self.input[start..self.pos];
        if (hex_str.len != 64) return ParseError.InvalidHash;

        var result: [32]u8 = undefined;
        for (0..32) |i| {
            const hi = hexDigit(hex_str[i * 2]) orelse return ParseError.InvalidHash;
            const lo = hexDigit(hex_str[i * 2 + 1]) orelse return ParseError.InvalidHash;
            result[i] = (@as(u8, hi) << 4) | lo;
        }
        return result;
    }

    fn parseHash20(self: *Parser) ParseError![20]u8 {
        self.skipWhitespace();
        const start = self.pos;

        while (self.peek()) |c| {
            if (!std.ascii.isHex(c)) break;
            _ = self.advance();
        }

        const hex_str = self.input[start..self.pos];
        if (hex_str.len != 40) return ParseError.InvalidHash;

        var result: [20]u8 = undefined;
        for (0..20) |i| {
            const hi = hexDigit(hex_str[i * 2]) orelse return ParseError.InvalidHash;
            const lo = hexDigit(hex_str[i * 2 + 1]) orelse return ParseError.InvalidHash;
            result[i] = (@as(u8, hi) << 4) | lo;
        }
        return result;
    }
};

fn getFragment(name: []const u8) ?Fragment {
    const map = std.StaticStringMap(Fragment).initComptime(.{
        .{ "pk_k", .pk_k },
        .{ "pk_h", .pk_h },
        .{ "pk", .pk_k }, // alias
        .{ "pkh", .pk_h }, // alias
        .{ "older", .older },
        .{ "after", .after },
        .{ "sha256", .sha256 },
        .{ "hash256", .hash256 },
        .{ "ripemd160", .ripemd160 },
        .{ "hash160", .hash160 },
        .{ "and_v", .and_v },
        .{ "and_b", .and_b },
        .{ "or_b", .or_b },
        .{ "or_c", .or_c },
        .{ "or_d", .or_d },
        .{ "or_i", .or_i },
        .{ "andor", .andor },
        .{ "thresh", .thresh },
        .{ "multi", .multi },
        .{ "multi_a", .multi_a },
    });
    return map.get(name);
}

fn isHex(s: []const u8) bool {
    if (s.len % 2 != 0) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, hex.len / 2);
    for (0..result.len) |i| {
        const hi = hexDigit(hex[i * 2]) orelse return error.InvalidHex;
        const lo = hexDigit(hex[i * 2 + 1]) orelse return error.InvalidHex;
        result[i] = (@as(u8, hi) << 4) | lo;
    }
    return result;
}

fn hexDigit(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @intCast(c - '0');
    if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @intCast(c - 'A' + 10);
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "miniscript type properties validation" {
    // B type with valid properties
    var typ = TypeProperties{ .base_type = .B, .z = false, .o = true, .d = true };
    try std.testing.expect(typ.isValid());

    // Invalid: z and o conflict
    typ = TypeProperties{ .base_type = .B, .z = true, .o = true };
    try std.testing.expect(!typ.isValid());

    // K type must have u and s
    typ = TypeProperties{ .base_type = .K, .u = true, .s = true };
    try std.testing.expect(typ.isValid());

    typ = TypeProperties{ .base_type = .K, .u = false, .s = true };
    try std.testing.expect(!typ.isValid());
}

test "miniscript parse pk_k" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.pk_k, node.fragment);
    try std.testing.expectEqual(@as(usize, 1), node.keys.len);
    try std.testing.expectEqual(NodeType.K, node.typ.base_type);
}

test "miniscript parse older" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "older(144)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.older, node.fragment);
    try std.testing.expectEqual(@as(u32, 144), node.k);
    try std.testing.expectEqual(NodeType.B, node.typ.base_type);
}

test "miniscript parse and_v" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "and_v(v:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),older(144))", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.and_v, node.fragment);
    try std.testing.expectEqual(@as(usize, 2), node.subs.len);
}

test "miniscript parse thresh" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "thresh(2,pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),s:pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5),s:pk_k(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.thresh, node.fragment);
    try std.testing.expectEqual(@as(u32, 2), node.k);
    try std.testing.expectEqual(@as(usize, 3), node.subs.len);
}

test "miniscript parse multi" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.multi, node.fragment);
    try std.testing.expectEqual(@as(u32, 2), node.k);
    try std.testing.expectEqual(@as(usize, 2), node.keys.len);
}

test "miniscript script compilation pk_k" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    const compiled = try node.toScript(allocator, .p2wsh);
    defer allocator.free(compiled);

    // Should be: <33 bytes push> <pubkey>
    try std.testing.expectEqual(@as(usize, 34), compiled.len);
    try std.testing.expectEqual(@as(u8, 0x21), compiled[0]); // 33 bytes push
}

test "miniscript script compilation older" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "older(144)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    const compiled = try node.toScript(allocator, .p2wsh);
    defer allocator.free(compiled);

    // Should be: <push 144> OP_CSV
    try std.testing.expect(compiled.len >= 2);
    try std.testing.expectEqual(@as(u8, 0xb2), compiled[compiled.len - 1]); // OP_CSV
}

test "miniscript witness size computation" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    const size = node.computeMaxWitnessSize(.p2wsh);
    try std.testing.expectEqual(@as(u32, 73), size); // ECDSA signature size
}

test "miniscript script size computation" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    const size = node.computeScriptSize(.p2wsh);
    try std.testing.expectEqual(@as(u32, 34), size); // 33-byte pubkey + 1 byte push
}

test "miniscript tapscript multi_a" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "multi_a(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)", .tapscript);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.multi_a, node.fragment);

    const compiled = try node.toScript(allocator, .tapscript);
    defer allocator.free(compiled);

    // Should contain OP_CHECKSIG and OP_CHECKSIGADD
    var has_checksig = false;
    var has_checksigadd = false;
    for (compiled) |op| {
        if (op == 0xac) has_checksig = true;
        if (op == 0xba) has_checksigadd = true;
    }
    try std.testing.expect(has_checksig);
    try std.testing.expect(has_checksigadd);
}

test "miniscript wrappers" {
    const allocator = std.testing.allocator;

    // Test c: wrapper (checksig)
    var node = try parse(allocator, "c:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.wrap_c, node.fragment);
    try std.testing.expectEqual(NodeType.B, node.typ.base_type);

    const compiled = try node.toScript(allocator, .p2wsh);
    defer allocator.free(compiled);

    // Should end with OP_CHECKSIG
    try std.testing.expectEqual(@as(u8, 0xac), compiled[compiled.len - 1]);
}

test "miniscript or_i" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "or_i(pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.or_i, node.fragment);
    try std.testing.expectEqual(@as(usize, 2), node.subs.len);

    const compiled = try node.toScript(allocator, .p2wsh);
    defer allocator.free(compiled);

    // Should start with OP_IF
    try std.testing.expectEqual(@as(u8, 0x63), compiled[0]);
}

test "miniscript hash challenge" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "sha256(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.sha256, node.fragment);
    try std.testing.expect(node.hash != null);

    const compiled = try node.toScript(allocator, .p2wsh);
    defer allocator.free(compiled);

    // Should contain OP_SHA256
    var has_sha256 = false;
    for (compiled) |op| {
        if (op == 0xa8) has_sha256 = true;
    }
    try std.testing.expect(has_sha256);
}

test "miniscript andor" {
    const allocator = std.testing.allocator;

    var node = try parse(allocator, "andor(pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),older(144),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))", .p2wsh);
    defer {
        node.deinit();
        allocator.destroy(node);
    }

    try std.testing.expectEqual(Fragment.andor, node.fragment);
    try std.testing.expectEqual(@as(usize, 3), node.subs.len);
}
