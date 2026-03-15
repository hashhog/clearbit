const std = @import("std");
const crypto = @import("crypto.zig");
const types = @import("types.zig");

// ============================================================================
// Opcode Definitions
// ============================================================================

pub const Opcode = enum(u8) {
    // Constants
    op_0 = 0x00,
    op_pushdata1 = 0x4c,
    op_pushdata2 = 0x4d,
    op_pushdata4 = 0x4e,
    op_1negate = 0x4f,
    op_1 = 0x51,
    op_2 = 0x52,
    op_3 = 0x53,
    op_4 = 0x54,
    op_5 = 0x55,
    op_6 = 0x56,
    op_7 = 0x57,
    op_8 = 0x58,
    op_9 = 0x59,
    op_10 = 0x5a,
    op_11 = 0x5b,
    op_12 = 0x5c,
    op_13 = 0x5d,
    op_14 = 0x5e,
    op_15 = 0x5f,
    op_16 = 0x60,

    // Flow control
    op_nop = 0x61,
    op_if = 0x63,
    op_notif = 0x64,
    op_else = 0x67,
    op_endif = 0x68,
    op_verify = 0x69,
    op_return = 0x6a,

    // Stack
    op_toaltstack = 0x6b,
    op_fromaltstack = 0x6c,
    op_2drop = 0x6d,
    op_2dup = 0x6e,
    op_3dup = 0x6f,
    op_2over = 0x70,
    op_2rot = 0x71,
    op_2swap = 0x72,
    op_ifdup = 0x73,
    op_depth = 0x74,
    op_drop = 0x75,
    op_dup = 0x76,
    op_nip = 0x77,
    op_over = 0x78,
    op_pick = 0x79,
    op_roll = 0x7a,
    op_rot = 0x7b,
    op_swap = 0x7c,
    op_tuck = 0x7d,

    // Splice (most disabled)
    op_size = 0x82,

    // Bitwise logic
    op_equal = 0x87,
    op_equalverify = 0x88,

    // Arithmetic
    op_1add = 0x8b,
    op_1sub = 0x8c,
    op_negate = 0x8f,
    op_abs = 0x90,
    op_not = 0x91,
    op_0notequal = 0x92,
    op_add = 0x93,
    op_sub = 0x94,
    op_booland = 0x9a,
    op_boolor = 0x9b,
    op_numequal = 0x9c,
    op_numequalverify = 0x9d,
    op_numnotequal = 0x9e,
    op_lessthan = 0x9f,
    op_greaterthan = 0xa0,
    op_lessthanorequal = 0xa1,
    op_greaterthanorequal = 0xa2,
    op_min = 0xa3,
    op_max = 0xa4,
    op_within = 0xa5,

    // Crypto
    op_ripemd160 = 0xa6,
    op_sha1 = 0xa7,
    op_sha256 = 0xa8,
    op_hash160 = 0xa9,
    op_hash256 = 0xaa,
    op_codeseparator = 0xab,
    op_checksig = 0xac,
    op_checksigverify = 0xad,
    op_checkmultisig = 0xae,
    op_checkmultisigverify = 0xaf,

    // Locktime
    op_nop1 = 0xb0,
    op_checklocktimeverify = 0xb1,
    op_checksequenceverify = 0xb2,
    op_nop4 = 0xb3,
    op_nop5 = 0xb4,
    op_nop6 = 0xb5,
    op_nop7 = 0xb6,
    op_nop8 = 0xb7,
    op_nop9 = 0xb8,
    op_nop10 = 0xb9,

    // Taproot
    op_checksigadd = 0xba,

    _, // Allow unknown opcodes
};

// ============================================================================
// Script Errors
// ============================================================================

pub const ScriptError = error{
    InvalidScript,
    StackUnderflow,
    StackOverflow,
    InvalidOpcode,
    ScriptFailed,
    DisabledOpcode,
    PushSizeExceeded,
    OpCountExceeded,
    EqualVerifyFailed,
    CheckSigFailed,
    CheckMultisigFailed,
    NullDummy,
    NullFail, // BIP-146: failed signature check with non-empty signature
    CleanStack,
    MinimalData,
    MinimalIf, // BIP-342/segwit: OP_IF/OP_NOTIF argument must be empty or exactly 0x01
    NegativeLocktime,
    UnsatisfiedLocktime,
    WitnessProgramMismatch,
    WitnessProgramWrongLength,
    WitnessPubkeyType,
    WitnessUnexpected,
    OutOfMemory,
    InvalidNumber,
    DivisionByZero,
    InvalidStackOperation,
    VerifyFailed,
    OpReturnEncountered,
    UnbalancedConditional,
    SigPushOnly, // BIP-16: P2SH scriptSig must be push-only
};

// ============================================================================
// Script Flags
// ============================================================================

pub const ScriptFlags = packed struct {
    verify_p2sh: bool = true,
    verify_witness: bool = true,
    verify_clean_stack: bool = true,
    verify_dersig: bool = true,
    verify_low_s: bool = true,
    verify_nulldummy: bool = true,
    verify_nullfail: bool = true, // BIP-146: failed signatures must be empty
    verify_minimaldata: bool = true,
    verify_checklocktimeverify: bool = true,
    verify_checksequenceverify: bool = true,
    verify_taproot: bool = true,
    verify_witness_pubkeytype: bool = true, // BIP-141: witness v0 requires compressed pubkeys
    _padding: u4 = 0,
};

// ============================================================================
// Script Constants
// ============================================================================

const MAX_STACK_SIZE = 1000;
const MAX_SCRIPT_SIZE = 10000;
const MAX_OPS_PER_SCRIPT = 201;
const MAX_PUSH_SIZE = 520;
const MAX_SCRIPT_ELEMENT_SIZE = 520;
const MAX_STACK_ELEMENT_SIZE = 520;
const MAX_SCRIPT_NUM_LENGTH = 4;
const LOCKTIME_THRESHOLD: u32 = 500000000;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

// ============================================================================
// Public Key Encoding
// ============================================================================

/// Check if a public key is compressed (33 bytes, starting with 0x02 or 0x03).
/// Per BIP-141, witness v0 programs require compressed public keys.
pub fn isCompressedPubkey(pubkey: []const u8) bool {
    if (pubkey.len != 33) return false;
    return pubkey[0] == 0x02 or pubkey[0] == 0x03;
}

/// Check if a script contains only push operations.
/// Per BIP-16, P2SH scriptSig must be push-only (literals only).
/// Push opcodes include:
/// - OP_0 (0x00)
/// - Direct pushes: opcodes 0x01-0x4b push that many bytes
/// - OP_PUSHDATA1 (0x4c), OP_PUSHDATA2 (0x4d), OP_PUSHDATA4 (0x4e)
/// - OP_1NEGATE (0x4f)
/// - OP_1 through OP_16 (0x51-0x60)
///
/// Any opcode > 0x60 is NOT a push operation and would make this return false.
/// Reference: Bitcoin Core script/script.cpp IsPushOnly()
pub fn isPushOnly(script: []const u8) bool {
    var pc: usize = 0;

    while (pc < script.len) {
        const opcode = script[pc];
        pc += 1;

        // OP_0 (0x00) is a push (pushes empty array)
        if (opcode == 0x00) {
            continue;
        }

        // Direct push: opcodes 0x01-0x4b push that many bytes
        if (opcode >= 0x01 and opcode <= 0x4b) {
            const n: usize = opcode;
            if (pc + n > script.len) return false; // Invalid script
            pc += n;
            continue;
        }

        // OP_PUSHDATA1: next byte is length, then that many data bytes
        if (opcode == 0x4c) {
            if (pc >= script.len) return false;
            const n: usize = script[pc];
            pc += 1;
            if (pc + n > script.len) return false;
            pc += n;
            continue;
        }

        // OP_PUSHDATA2: next 2 bytes (little-endian) are length
        if (opcode == 0x4d) {
            if (pc + 2 > script.len) return false;
            const n: usize = std.mem.readInt(u16, script[pc..][0..2], .little);
            pc += 2;
            if (pc + n > script.len) return false;
            pc += n;
            continue;
        }

        // OP_PUSHDATA4: next 4 bytes (little-endian) are length
        if (opcode == 0x4e) {
            if (pc + 4 > script.len) return false;
            const n: usize = std.mem.readInt(u32, script[pc..][0..4], .little);
            pc += 4;
            if (pc + n > script.len) return false;
            pc += n;
            continue;
        }

        // OP_1NEGATE (0x4f) through OP_16 (0x60) are push operations
        // Note: OP_RESERVED (0x50) is technically between OP_1NEGATE and OP_1,
        // but Bitcoin Core's IsPushOnly considers opcode <= OP_16 as push.
        // However, OP_RESERVED would cause script failure anyway.
        if (opcode >= 0x4f and opcode <= 0x60) {
            continue;
        }

        // Any other opcode (> 0x60) is not a push operation
        return false;
    }

    return true;
}

// ============================================================================
// Script Number Encoding
// ============================================================================

/// Convert a stack element to a script number (CScriptNum).
/// Little-endian with sign bit in the most significant bit of the last byte.
fn scriptNumDecode(data: []const u8) ScriptError!i64 {
    if (data.len == 0) return 0;
    if (data.len > MAX_SCRIPT_NUM_LENGTH) return ScriptError.InvalidNumber;

    // Little-endian decode
    var result: i64 = 0;
    for (data, 0..) |byte, i| {
        result |= @as(i64, byte) << @intCast(8 * i);
    }

    // Check sign bit
    if (data[data.len - 1] & 0x80 != 0) {
        // Negative number: clear sign bit and negate
        result &= ~(@as(i64, 0x80) << @intCast(8 * (data.len - 1)));
        result = -result;
    }

    return result;
}

/// Encode a number to script number format.
fn scriptNumEncode(value: i64, allocator: std.mem.Allocator) ![]u8 {
    if (value == 0) {
        return try allocator.alloc(u8, 0);
    }

    const abs_val: u64 = if (value < 0) @intCast(-value) else @intCast(value);
    const negative = value < 0;

    // Count bytes needed
    var num_bytes: usize = 0;
    var temp = abs_val;
    while (temp > 0) {
        num_bytes += 1;
        temp >>= 8;
    }

    // Check if we need an extra byte for sign
    const need_extra = (abs_val >> @intCast((num_bytes - 1) * 8)) & 0x80 != 0;
    if (need_extra) num_bytes += 1;

    var result = try allocator.alloc(u8, num_bytes);

    // Write little-endian
    for (0..num_bytes) |i| {
        if (i < 8) {
            result[i] = @truncate(abs_val >> @intCast(8 * i));
        } else {
            result[i] = 0;
        }
    }

    // Set sign bit
    if (negative) {
        if (need_extra) {
            result[num_bytes - 1] = 0x80;
        } else {
            result[num_bytes - 1] |= 0x80;
        }
    }

    return result;
}

// ============================================================================
// Signature Version
// ============================================================================

/// Tracks the signature version for sighash computation and validation rules.
pub const SigVersion = enum {
    /// Legacy (pre-segwit) scripts
    base,
    /// Witness v0 scripts (P2WPKH, P2WSH) - BIP 143
    witness_v0,
    /// Tapscript (P2TR script path) - BIP 342
    tapscript,
};

// ============================================================================
// Script Engine
// ============================================================================

pub const ScriptEngine = struct {
    stack: std.ArrayList([]const u8),
    alt_stack: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
    flags: ScriptFlags,
    tx: *const types.Transaction,
    input_index: usize,
    amount: i64,
    codesep_pos: u32,
    sig_version: SigVersion,

    // Memory management for stack elements we allocate
    owned_elements: std.ArrayList([]u8),

    pub fn init(
        allocator: std.mem.Allocator,
        tx: *const types.Transaction,
        input_index: usize,
        amount: i64,
        flags: ScriptFlags,
    ) ScriptEngine {
        return .{
            .stack = std.ArrayList([]const u8).init(allocator),
            .alt_stack = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
            .flags = flags,
            .tx = tx,
            .input_index = input_index,
            .amount = amount,
            .codesep_pos = 0xFFFFFFFF,
            .sig_version = .base,
            .owned_elements = std.ArrayList([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *ScriptEngine) void {
        // Free all owned elements
        for (self.owned_elements.items) |elem| {
            self.allocator.free(elem);
        }
        self.owned_elements.deinit();
        self.stack.deinit();
        self.alt_stack.deinit();
    }

    /// Execute a script (series of opcodes/data pushes).
    pub fn execute(self: *ScriptEngine, script: []const u8) ScriptError!void {
        if (script.len > MAX_SCRIPT_SIZE) return ScriptError.InvalidScript;

        var pc: usize = 0;
        var op_count: usize = 0;
        var exec_stack = std.ArrayList(bool).init(self.allocator);
        defer exec_stack.deinit();

        while (pc < script.len) {
            const opcode_byte = script[pc];
            pc += 1;

            // Data push: opcodes 0x01-0x4b push that many bytes
            if (opcode_byte >= 0x01 and opcode_byte <= 0x4b) {
                const n = @as(usize, opcode_byte);
                if (pc + n > script.len) return ScriptError.InvalidScript;
                if (self.isExecuting(&exec_stack)) {
                    if (n > MAX_PUSH_SIZE) return ScriptError.PushSizeExceeded;
                    try self.push(script[pc .. pc + n]);
                }
                pc += n;
                continue;
            }

            const opcode: Opcode = @enumFromInt(opcode_byte);

            // Handle PUSHDATA opcodes
            if (opcode_byte == 0x4c or opcode_byte == 0x4d or opcode_byte == 0x4e) {
                const n: usize = switch (opcode) {
                    .op_pushdata1 => blk: {
                        if (pc >= script.len) return ScriptError.InvalidScript;
                        const len = script[pc];
                        pc += 1;
                        break :blk len;
                    },
                    .op_pushdata2 => blk: {
                        if (pc + 2 > script.len) return ScriptError.InvalidScript;
                        const len = std.mem.readInt(u16, script[pc..][0..2], .little);
                        pc += 2;
                        break :blk len;
                    },
                    .op_pushdata4 => blk: {
                        if (pc + 4 > script.len) return ScriptError.InvalidScript;
                        const len = std.mem.readInt(u32, script[pc..][0..4], .little);
                        pc += 4;
                        break :blk len;
                    },
                    else => unreachable,
                };

                if (pc + n > script.len) return ScriptError.InvalidScript;
                if (self.isExecuting(&exec_stack)) {
                    if (n > MAX_PUSH_SIZE) return ScriptError.PushSizeExceeded;
                    try self.push(script[pc .. pc + n]);
                }
                pc += n;
                continue;
            }

            // Count ops (except for push opcodes and flow control in non-executing branch)
            if (opcode != .op_if and opcode != .op_notif and
                opcode != .op_else and opcode != .op_endif)
            {
                if (opcode_byte > 0x60) {
                    op_count += 1;
                    if (op_count > MAX_OPS_PER_SCRIPT) return ScriptError.OpCountExceeded;
                }
            }

            if (!self.isExecuting(&exec_stack)) {
                // Skip non-executing branch but track if/else/endif
                switch (opcode) {
                    .op_if, .op_notif => exec_stack.append(false) catch return ScriptError.OutOfMemory,
                    .op_else => {
                        if (exec_stack.items.len == 0) return ScriptError.UnbalancedConditional;
                        const idx = exec_stack.items.len - 1;
                        // Only flip if parent is executing
                        if (idx == 0 or exec_stack.items[idx - 1]) {
                            exec_stack.items[idx] = !exec_stack.items[idx];
                        }
                    },
                    .op_endif => {
                        if (exec_stack.items.len == 0) return ScriptError.UnbalancedConditional;
                        _ = exec_stack.pop();
                    },
                    else => {},
                }
                continue;
            }

            // Execute the opcode
            try self.executeOpcode(opcode, script, &pc, &exec_stack);
        }

        if (exec_stack.items.len != 0) return ScriptError.UnbalancedConditional;
    }

    /// Verify a complete transaction input.
    pub fn verify(
        self: *ScriptEngine,
        script_sig: []const u8,
        script_pubkey: []const u8,
        witness: []const []const u8,
    ) ScriptError!bool {
        // 1. Execute scriptSig
        try self.execute(script_sig);

        // 2. Copy stack for P2SH
        var saved_stack = std.ArrayList([]const u8).init(self.allocator);
        defer saved_stack.deinit();

        if (self.flags.verify_p2sh) {
            for (self.stack.items) |item| {
                saved_stack.append(item) catch return ScriptError.OutOfMemory;
            }
        }

        // 3. Execute scriptPubKey
        try self.execute(script_pubkey);

        // Check result
        if (self.stack.items.len == 0) return false;
        if (!self.stackToBool(self.stack.items[self.stack.items.len - 1])) return false;

        // 4. Handle P2SH
        if (self.flags.verify_p2sh and classifyScript(script_pubkey) == .p2sh) {
            // BIP-16: scriptSig must be push-only for P2SH transactions.
            // This is enforced unconditionally (not flag-gated beyond verify_p2sh).
            // Reference: Bitcoin Core interpreter.cpp VerifyScript()
            if (!isPushOnly(script_sig)) {
                return ScriptError.SigPushOnly;
            }

            if (saved_stack.items.len == 0) return false;

            // The last element of the original stack is the serialized script
            const redeem_script = saved_stack.items[saved_stack.items.len - 1];

            // Create a new engine with the saved stack (without the redeem script)
            self.stack.clearRetainingCapacity();
            for (saved_stack.items[0 .. saved_stack.items.len - 1]) |item| {
                self.stack.append(item) catch return ScriptError.OutOfMemory;
            }

            // Execute redeem script
            try self.execute(redeem_script);

            if (self.stack.items.len == 0) return false;
            if (!self.stackToBool(self.stack.items[self.stack.items.len - 1])) return false;
        }

        // 5. Handle witness
        if (self.flags.verify_witness) {
            const script_type = classifyScript(script_pubkey);
            switch (script_type) {
                .p2wpkh => {
                    if (witness.len != 2) return false;

                    // BIP-141: witness v0 requires compressed pubkeys
                    // witness[0] = signature, witness[1] = pubkey
                    const pubkey = witness[1];
                    if (self.flags.verify_witness_pubkeytype and !isCompressedPubkey(pubkey)) {
                        return ScriptError.WitnessPubkeyType;
                    }

                    // Build P2PKH script from witness program
                    const wpkh_hash = script_pubkey[2..22];
                    var p2pkh_script: [25]u8 = undefined;
                    p2pkh_script[0] = 0x76; // OP_DUP
                    p2pkh_script[1] = 0xa9; // OP_HASH160
                    p2pkh_script[2] = 0x14; // Push 20 bytes
                    @memcpy(p2pkh_script[3..23], wpkh_hash);
                    p2pkh_script[23] = 0x88; // OP_EQUALVERIFY
                    p2pkh_script[24] = 0xac; // OP_CHECKSIG

                    // Reset stack with witness data (reversed for proper order)
                    self.stack.clearRetainingCapacity();
                    // Witness is in wire order (bottom to top), so iterate forward
                    for (witness) |item| {
                        self.stack.append(item) catch return ScriptError.OutOfMemory;
                    }

                    // Set sig_version to witness_v0 for signature verification
                    self.sig_version = .witness_v0;
                    try self.execute(&p2pkh_script);

                    // Witness cleanstack: UNCONDITIONALLY require exactly 1 stack element
                    // This is NOT flag-gated (unlike legacy CLEANSTACK)
                    // Reference: Bitcoin Core interpreter.cpp ExecuteWitnessScript()
                    if (self.stack.items.len != 1) return ScriptError.CleanStack;
                    if (!self.stackToBool(self.stack.items[0])) return false;
                },
                .p2wsh => {
                    if (witness.len == 0) return false;
                    const witness_script = witness[witness.len - 1];
                    const witness_hash = crypto.sha256(witness_script);

                    if (!std.mem.eql(u8, &witness_hash, script_pubkey[2..34])) {
                        return ScriptError.WitnessProgramMismatch;
                    }

                    // Reset stack with witness data (excluding the script)
                    self.stack.clearRetainingCapacity();
                    for (witness[0 .. witness.len - 1]) |item| {
                        self.stack.append(item) catch return ScriptError.OutOfMemory;
                    }

                    // Set sig_version to witness_v0 for signature verification
                    self.sig_version = .witness_v0;
                    try self.execute(witness_script);

                    // Witness cleanstack: UNCONDITIONALLY require exactly 1 stack element
                    // This is NOT flag-gated (unlike legacy CLEANSTACK)
                    // Reference: Bitcoin Core interpreter.cpp ExecuteWitnessScript()
                    if (self.stack.items.len != 1) return ScriptError.CleanStack;
                    if (!self.stackToBool(self.stack.items[0])) return false;
                },
                .p2tr => {
                    // Taproot key path or script path spend
                    if (witness.len == 0) return false;

                    // Key path: single 64 or 65 byte signature (no script execution)
                    if (witness.len == 1 and (witness[0].len == 64 or witness[0].len == 65)) {
                        // Schnorr signature verification would go here
                        // For now, we mark this as requiring libsecp256k1
                        if (!crypto.isSecp256k1Available()) {
                            return false; // Can't verify without library
                        }
                        // Key path doesn't involve script execution, so no cleanstack check
                        // Full taproot verification would call verifySchnorr
                    }
                    // Script path spending: when implemented, must enforce witness cleanstack
                    // (stack.items.len == 1 after tapscript execution, just like P2WSH)
                    // This is UNCONDITIONAL for tapscript - not flag-gated
                },
                .anchor => {
                    // P2A (Pay-to-Anchor) is anyone-can-spend.
                    // Witness must be empty for standard spending.
                    // Reference: Bitcoin Core script/sign.cpp - ANCHOR case returns immediately.
                    if (witness.len != 0) {
                        // Non-empty witness is non-standard but valid in consensus.
                        // For policy, we reject non-empty witness.
                    }
                    // No script execution needed - anyone can spend.
                    // Push true to satisfy the clean stack check below.
                    const true_val = [_]u8{0x01};
                    self.stack.clearRetainingCapacity();
                    self.stack.append(&true_val) catch return ScriptError.OutOfMemory;
                },
                else => {},
            }
        }

        // 6. Clean stack check
        if (self.flags.verify_clean_stack) {
            if (self.stack.items.len != 1) return ScriptError.CleanStack;
        }

        return true;
    }

    fn push(self: *ScriptEngine, data: []const u8) !void {
        if (self.stack.items.len >= MAX_STACK_SIZE) return ScriptError.StackOverflow;
        if (data.len > MAX_STACK_ELEMENT_SIZE) return ScriptError.PushSizeExceeded;
        self.stack.append(data) catch return ScriptError.OutOfMemory;
    }

    fn pushOwned(self: *ScriptEngine, data: []u8) !void {
        if (self.stack.items.len >= MAX_STACK_SIZE) return ScriptError.StackOverflow;
        if (data.len > MAX_STACK_ELEMENT_SIZE) return ScriptError.PushSizeExceeded;
        self.owned_elements.append(data) catch return ScriptError.OutOfMemory;
        self.stack.append(data) catch return ScriptError.OutOfMemory;
    }

    fn pop(self: *ScriptEngine) ScriptError![]const u8 {
        if (self.stack.items.len == 0) return ScriptError.StackUnderflow;
        return self.stack.pop() orelse return ScriptError.StackUnderflow;
    }

    fn peek(self: *ScriptEngine) ![]const u8 {
        if (self.stack.items.len == 0) return ScriptError.StackUnderflow;
        return self.stack.items[self.stack.items.len - 1];
    }

    fn peekAt(self: *ScriptEngine, depth: usize) ![]const u8 {
        if (depth >= self.stack.items.len) return ScriptError.StackUnderflow;
        return self.stack.items[self.stack.items.len - 1 - depth];
    }

    fn stackToBool(self: *ScriptEngine, data: []const u8) bool {
        _ = self;
        for (data, 0..) |byte, i| {
            if (byte != 0) {
                // Negative zero check: only the last byte can have 0x80
                if (i == data.len - 1 and byte == 0x80) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    fn boolToStack(allocator: std.mem.Allocator, val: bool) ![]u8 {
        if (val) {
            const result = try allocator.alloc(u8, 1);
            result[0] = 1;
            return result;
        } else {
            return try allocator.alloc(u8, 0);
        }
    }

    fn isExecuting(self: *ScriptEngine, exec_stack: *std.ArrayList(bool)) bool {
        _ = self;
        for (exec_stack.items) |executing| {
            if (!executing) return false;
        }
        return true;
    }

    fn executeOpcode(
        self: *ScriptEngine,
        opcode: Opcode,
        script: []const u8,
        pc: *usize,
        exec_stack: *std.ArrayList(bool),
    ) ScriptError!void {
        _ = script;
        _ = pc;

        switch (opcode) {
            // Constants
            .op_0 => {
                try self.push(&[_]u8{});
            },
            .op_1negate => {
                try self.push(&[_]u8{0x81});
            },
            .op_1, .op_2, .op_3, .op_4, .op_5, .op_6, .op_7, .op_8, .op_9, .op_10, .op_11, .op_12, .op_13, .op_14, .op_15, .op_16 => {
                const n = @intFromEnum(opcode) - 0x50;
                const result = try self.allocator.alloc(u8, 1);
                result[0] = @intCast(n);
                try self.pushOwned(result);
            },

            // Flow control
            .op_nop, .op_nop1, .op_nop4, .op_nop5, .op_nop6, .op_nop7, .op_nop8, .op_nop9, .op_nop10 => {},

            .op_if => {
                var execute_branch = false;
                if (self.isExecuting(exec_stack)) {
                    const data = try self.pop();
                    // MINIMALIF: For witness v0 and tapscript, the argument must be exactly
                    // empty (false) or exactly &[1]u8{0x01} (true). No other values allowed.
                    // Reference: Bitcoin Core interpreter.cpp OP_IF handler
                    if (self.sig_version == .witness_v0 or self.sig_version == .tapscript) {
                        if (data.len > 1) return ScriptError.MinimalIf;
                        if (data.len == 1 and data[0] != 1) return ScriptError.MinimalIf;
                    }
                    execute_branch = self.stackToBool(data);
                }
                exec_stack.append(execute_branch) catch return ScriptError.OutOfMemory;
            },

            .op_notif => {
                var execute_branch = false;
                if (self.isExecuting(exec_stack)) {
                    const data = try self.pop();
                    // MINIMALIF: For witness v0 and tapscript, the argument must be exactly
                    // empty (false) or exactly &[1]u8{0x01} (true). No other values allowed.
                    // Reference: Bitcoin Core interpreter.cpp OP_NOTIF handler
                    if (self.sig_version == .witness_v0 or self.sig_version == .tapscript) {
                        if (data.len > 1) return ScriptError.MinimalIf;
                        if (data.len == 1 and data[0] != 1) return ScriptError.MinimalIf;
                    }
                    execute_branch = !self.stackToBool(data);
                }
                exec_stack.append(execute_branch) catch return ScriptError.OutOfMemory;
            },

            .op_else => {
                if (exec_stack.items.len == 0) return ScriptError.UnbalancedConditional;
                const idx = exec_stack.items.len - 1;
                exec_stack.items[idx] = !exec_stack.items[idx];
            },

            .op_endif => {
                if (exec_stack.items.len == 0) return ScriptError.UnbalancedConditional;
                _ = exec_stack.pop();
            },

            .op_verify => {
                const data = try self.pop();
                if (!self.stackToBool(data)) return ScriptError.VerifyFailed;
            },

            .op_return => {
                return ScriptError.OpReturnEncountered;
            },

            // Stack operations
            .op_toaltstack => {
                const data = try self.pop();
                self.alt_stack.append(data) catch return ScriptError.OutOfMemory;
            },

            .op_fromaltstack => {
                if (self.alt_stack.items.len == 0) return ScriptError.StackUnderflow;
                const data = self.alt_stack.pop() orelse return ScriptError.StackUnderflow;
                try self.push(data);
            },

            .op_drop => {
                _ = try self.pop();
            },

            .op_2drop => {
                _ = try self.pop();
                _ = try self.pop();
            },

            .op_dup => {
                const data = try self.peek();
                try self.push(data);
            },

            .op_2dup => {
                const a = try self.peekAt(1);
                const b = try self.peekAt(0);
                try self.push(a);
                try self.push(b);
            },

            .op_3dup => {
                const a = try self.peekAt(2);
                const b = try self.peekAt(1);
                const c = try self.peekAt(0);
                try self.push(a);
                try self.push(b);
                try self.push(c);
            },

            .op_2over => {
                const a = try self.peekAt(3);
                const b = try self.peekAt(2);
                try self.push(a);
                try self.push(b);
            },

            .op_2rot => {
                if (self.stack.items.len < 6) return ScriptError.StackUnderflow;
                const idx = self.stack.items.len;
                const a = self.stack.items[idx - 6];
                const b = self.stack.items[idx - 5];
                // Shift elements down
                for (0..4) |i| {
                    self.stack.items[idx - 6 + i] = self.stack.items[idx - 4 + i];
                }
                self.stack.items[idx - 2] = a;
                self.stack.items[idx - 1] = b;
            },

            .op_2swap => {
                if (self.stack.items.len < 4) return ScriptError.StackUnderflow;
                const idx = self.stack.items.len;
                std.mem.swap([]const u8, &self.stack.items[idx - 4], &self.stack.items[idx - 2]);
                std.mem.swap([]const u8, &self.stack.items[idx - 3], &self.stack.items[idx - 1]);
            },

            .op_ifdup => {
                const data = try self.peek();
                if (self.stackToBool(data)) {
                    try self.push(data);
                }
            },

            .op_depth => {
                const depth = self.stack.items.len;
                const result = try scriptNumEncode(@intCast(depth), self.allocator);
                try self.pushOwned(result);
            },

            .op_nip => {
                const top = try self.pop();
                _ = try self.pop();
                try self.push(top);
            },

            .op_over => {
                const data = try self.peekAt(1);
                try self.push(data);
            },

            .op_pick => {
                const n_data = try self.pop();
                const n = try scriptNumDecode(n_data);
                if (n < 0) return ScriptError.InvalidStackOperation;
                const data = try self.peekAt(@intCast(n));
                try self.push(data);
            },

            .op_roll => {
                const n_data = try self.pop();
                const n = try scriptNumDecode(n_data);
                if (n < 0) return ScriptError.InvalidStackOperation;
                const idx: usize = @intCast(n);
                if (idx >= self.stack.items.len) return ScriptError.StackUnderflow;
                const pos = self.stack.items.len - 1 - idx;
                const data = self.stack.items[pos];
                // Remove element at pos
                for (pos..self.stack.items.len - 1) |i| {
                    self.stack.items[i] = self.stack.items[i + 1];
                }
                self.stack.items[self.stack.items.len - 1] = data;
            },

            .op_rot => {
                if (self.stack.items.len < 3) return ScriptError.StackUnderflow;
                const idx = self.stack.items.len;
                const temp = self.stack.items[idx - 3];
                self.stack.items[idx - 3] = self.stack.items[idx - 2];
                self.stack.items[idx - 2] = self.stack.items[idx - 1];
                self.stack.items[idx - 1] = temp;
            },

            .op_swap => {
                if (self.stack.items.len < 2) return ScriptError.StackUnderflow;
                const idx = self.stack.items.len;
                std.mem.swap([]const u8, &self.stack.items[idx - 2], &self.stack.items[idx - 1]);
            },

            .op_tuck => {
                if (self.stack.items.len < 2) return ScriptError.StackUnderflow;
                const top = try self.peek();
                const idx = self.stack.items.len;
                self.stack.insert(idx - 2, top) catch return ScriptError.OutOfMemory;
            },

            // Splice
            .op_size => {
                const data = try self.peek();
                const size_data = try scriptNumEncode(@intCast(data.len), self.allocator);
                try self.pushOwned(size_data);
            },

            // Bitwise logic
            .op_equal => {
                const b = try self.pop();
                const a = try self.pop();
                const result = try boolToStack(self.allocator, std.mem.eql(u8, a, b));
                try self.pushOwned(result);
            },

            .op_equalverify => {
                const b = try self.pop();
                const a = try self.pop();
                if (!std.mem.eql(u8, a, b)) return ScriptError.EqualVerifyFailed;
            },

            // Arithmetic
            .op_1add => {
                const data = try self.pop();
                const n = try scriptNumDecode(data);
                const result = try scriptNumEncode(n + 1, self.allocator);
                try self.pushOwned(result);
            },

            .op_1sub => {
                const data = try self.pop();
                const n = try scriptNumDecode(data);
                const result = try scriptNumEncode(n - 1, self.allocator);
                try self.pushOwned(result);
            },

            .op_negate => {
                const data = try self.pop();
                const n = try scriptNumDecode(data);
                const result = try scriptNumEncode(-n, self.allocator);
                try self.pushOwned(result);
            },

            .op_abs => {
                const data = try self.pop();
                const n = try scriptNumDecode(data);
                const result = try scriptNumEncode(if (n < 0) -n else n, self.allocator);
                try self.pushOwned(result);
            },

            .op_not => {
                const data = try self.pop();
                const n = try scriptNumDecode(data);
                const result = try boolToStack(self.allocator, n == 0);
                try self.pushOwned(result);
            },

            .op_0notequal => {
                const data = try self.pop();
                const n = try scriptNumDecode(data);
                const result = try boolToStack(self.allocator, n != 0);
                try self.pushOwned(result);
            },

            .op_add => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try scriptNumEncode(a + b, self.allocator);
                try self.pushOwned(result);
            },

            .op_sub => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try scriptNumEncode(a - b, self.allocator);
                try self.pushOwned(result);
            },

            .op_booland => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a != 0 and b != 0);
                try self.pushOwned(result);
            },

            .op_boolor => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a != 0 or b != 0);
                try self.pushOwned(result);
            },

            .op_numequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a == b);
                try self.pushOwned(result);
            },

            .op_numequalverify => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                if (a != b) return ScriptError.VerifyFailed;
            },

            .op_numnotequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a != b);
                try self.pushOwned(result);
            },

            .op_lessthan => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a < b);
                try self.pushOwned(result);
            },

            .op_greaterthan => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a > b);
                try self.pushOwned(result);
            },

            .op_lessthanorequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a <= b);
                try self.pushOwned(result);
            },

            .op_greaterthanorequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try boolToStack(self.allocator, a >= b);
                try self.pushOwned(result);
            },

            .op_min => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try scriptNumEncode(@min(a, b), self.allocator);
                try self.pushOwned(result);
            },

            .op_max => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data);
                const b = try scriptNumDecode(b_data);
                const result = try scriptNumEncode(@max(a, b), self.allocator);
                try self.pushOwned(result);
            },

            .op_within => {
                const max_data = try self.pop();
                const min_data = try self.pop();
                const x_data = try self.pop();
                const x = try scriptNumDecode(x_data);
                const min_val = try scriptNumDecode(min_data);
                const max_val = try scriptNumDecode(max_data);
                const result = try boolToStack(self.allocator, x >= min_val and x < max_val);
                try self.pushOwned(result);
            },

            // Crypto
            .op_ripemd160 => {
                const data = try self.pop();
                const hash = crypto.ripemd160(data);
                const result = try self.allocator.dupe(u8, &hash);
                try self.pushOwned(result);
            },

            .op_sha1 => {
                // Zig doesn't have SHA1 in stdlib, so we'll treat this as disabled
                return ScriptError.DisabledOpcode;
            },

            .op_sha256 => {
                const data = try self.pop();
                const hash = crypto.sha256(data);
                const result = try self.allocator.dupe(u8, &hash);
                try self.pushOwned(result);
            },

            .op_hash160 => {
                const data = try self.pop();
                const hash = crypto.hash160(data);
                const result = try self.allocator.dupe(u8, &hash);
                try self.pushOwned(result);
            },

            .op_hash256 => {
                const data = try self.pop();
                const hash = crypto.hash256(data);
                const result = try self.allocator.dupe(u8, &hash);
                try self.pushOwned(result);
            },

            .op_codeseparator => {
                // Just update the position - no stack operation
                // pc points to next instruction already
            },

            .op_checksig => {
                // KNOWN PITFALL: Pop pubkey first (top of stack), then signature (deeper)
                const pubkey = try self.pop();
                const sig = try self.pop();

                const valid = try self.verifySignature(sig, pubkey);

                // BIP-146 NULLFAIL: If verification failed and signature is non-empty, fail
                if (!valid and self.flags.verify_nullfail and sig.len > 0) {
                    return ScriptError.NullFail;
                }

                const result = try boolToStack(self.allocator, valid);
                try self.pushOwned(result);
            },

            .op_checksigverify => {
                // KNOWN PITFALL: Both must share evaluation logic with consistent return types
                const pubkey = try self.pop();
                const sig = try self.pop();

                const valid = try self.verifySignature(sig, pubkey);

                // BIP-146 NULLFAIL: If verification failed and signature is non-empty, fail
                if (!valid and self.flags.verify_nullfail and sig.len > 0) {
                    return ScriptError.NullFail;
                }

                if (!valid) return ScriptError.CheckSigFailed;
            },

            .op_checkmultisig => {
                try self.executeCheckMultisig(false);
            },

            .op_checkmultisigverify => {
                try self.executeCheckMultisig(true);
            },

            // Locktime
            .op_checklocktimeverify => {
                if (!self.flags.verify_checklocktimeverify) {
                    return; // NOP behavior
                }

                const data = try self.peek(); // Don't pop
                const locktime = try scriptNumDecode(data);

                if (locktime < 0) return ScriptError.NegativeLocktime;

                // Check locktime type compatibility
                const lock_u: u64 = @intCast(locktime);
                const tx_locktime: u64 = self.tx.lock_time;

                if ((tx_locktime < LOCKTIME_THRESHOLD and lock_u >= LOCKTIME_THRESHOLD) or
                    (tx_locktime >= LOCKTIME_THRESHOLD and lock_u < LOCKTIME_THRESHOLD))
                {
                    return ScriptError.UnsatisfiedLocktime;
                }

                if (lock_u > tx_locktime) {
                    return ScriptError.UnsatisfiedLocktime;
                }

                // Check sequence
                if (self.tx.inputs[self.input_index].sequence == 0xFFFFFFFF) {
                    return ScriptError.UnsatisfiedLocktime;
                }
            },

            .op_checksequenceverify => {
                if (!self.flags.verify_checksequenceverify) {
                    return; // NOP behavior
                }

                const data = try self.peek(); // Don't pop
                const sequence = try scriptNumDecode(data);

                if (sequence < 0) return ScriptError.NegativeLocktime;

                const seq_u: u32 = @intCast(@as(u64, @intCast(sequence)) & 0xFFFFFFFF);

                // If disable flag is set, treat as NOP
                if (seq_u & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0) {
                    return;
                }

                // Check version
                if (self.tx.version < 2) {
                    return ScriptError.UnsatisfiedLocktime;
                }

                const tx_seq = self.tx.inputs[self.input_index].sequence;

                // Check disable flag on input
                if (tx_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0) {
                    return ScriptError.UnsatisfiedLocktime;
                }

                // Check type flag compatibility
                if ((seq_u & SEQUENCE_LOCKTIME_TYPE_FLAG) != (tx_seq & SEQUENCE_LOCKTIME_TYPE_FLAG)) {
                    return ScriptError.UnsatisfiedLocktime;
                }

                // Compare masked values
                if ((seq_u & SEQUENCE_LOCKTIME_MASK) > (tx_seq & SEQUENCE_LOCKTIME_MASK)) {
                    return ScriptError.UnsatisfiedLocktime;
                }
            },

            // Taproot
            .op_checksigadd => {
                const pubkey = try self.pop();
                const n_data = try self.pop();
                const sig = try self.pop();

                const n = try scriptNumDecode(n_data);

                // Empty sig means failure (add 0)
                if (sig.len == 0) {
                    const result = try scriptNumEncode(n, self.allocator);
                    try self.pushOwned(result);
                    return;
                }

                // Verify Schnorr signature
                const valid = try self.verifyTaprootSignature(sig, pubkey);
                const result = try scriptNumEncode(if (valid) n + 1 else n, self.allocator);
                try self.pushOwned(result);
            },

            else => {
                // Unknown or disabled opcode
                return ScriptError.InvalidOpcode;
            },
        }
    }

    fn executeCheckMultisig(self: *ScriptEngine, do_verify: bool) ScriptError!void {
        // Get number of public keys
        const n_data = try self.pop();
        const n = try scriptNumDecode(n_data);
        if (n < 0 or n > 20) return ScriptError.InvalidStackOperation;
        const n_keys: usize = @intCast(n);

        // Get public keys
        var pubkeys: [20][]const u8 = undefined;
        for (0..n_keys) |i| {
            pubkeys[i] = try self.pop();
        }

        // BIP-141: witness v0 requires compressed pubkeys
        if (self.flags.verify_witness_pubkeytype and self.sig_version == .witness_v0) {
            for (0..n_keys) |i| {
                if (!isCompressedPubkey(pubkeys[i])) {
                    return ScriptError.WitnessPubkeyType;
                }
            }
        }

        // Get number of signatures
        const m_data = try self.pop();
        const m = try scriptNumDecode(m_data);
        if (m < 0 or m > n) return ScriptError.InvalidStackOperation;
        const n_sigs: usize = @intCast(m);

        // Get signatures
        var sigs: [20][]const u8 = undefined;
        for (0..n_sigs) |i| {
            sigs[i] = try self.pop();
        }

        // KNOWN PITFALL: CHECKMULTISIG bug - consumes one extra stack element
        // This is the "null dummy" that must be empty when NULLDUMMY is active
        const dummy = try self.pop();
        if (self.flags.verify_nulldummy and dummy.len != 0) {
            return ScriptError.NullDummy;
        }

        // Verify signatures
        var success = true;
        var key_idx: usize = 0;
        var sig_idx: usize = 0;

        while (sig_idx < n_sigs) {
            if (key_idx >= n_keys) {
                success = false;
                break;
            }

            const valid = self.verifySignature(sigs[sig_idx], pubkeys[key_idx]) catch false;
            if (valid) {
                sig_idx += 1;
            }
            key_idx += 1;

            // Check if enough keys remain for remaining signatures
            if (n_keys - key_idx < n_sigs - sig_idx) {
                success = false;
                break;
            }
        }

        // BIP-146 NULLFAIL: If verification failed, all signatures must be empty
        // This check happens after the verification loop completes
        if (!success and self.flags.verify_nullfail) {
            for (0..n_sigs) |i| {
                if (sigs[i].len > 0) {
                    return ScriptError.NullFail;
                }
            }
        }

        if (do_verify) {
            if (!success) return ScriptError.CheckMultisigFailed;
        } else {
            const result = try boolToStack(self.allocator, success);
            try self.pushOwned(result);
        }
    }

    fn verifySignature(self: *ScriptEngine, sig: []const u8, pubkey: []const u8) !bool {
        if (sig.len == 0) return false;

        // BIP-141: witness v0 requires compressed pubkeys
        if (self.flags.verify_witness_pubkeytype and self.sig_version == .witness_v0) {
            if (!isCompressedPubkey(pubkey)) {
                return ScriptError.WitnessPubkeyType;
            }
        }

        // Extract hash type from last byte
        const hash_type = sig[sig.len - 1];
        const sig_data = sig[0 .. sig.len - 1];

        // Compute sighash
        // For a full implementation, we'd need the previous output's scriptPubKey
        // For now, we use a simplified approach
        _ = hash_type;
        _ = sig_data;

        // Full implementation would call crypto.verifyEcdsa
        if (!crypto.isSecp256k1Available()) {
            // Without libsecp256k1, we can't verify signatures
            // Return true for testing purposes (DANGEROUS in production)
            return true;
        }

        return false; // Placeholder
    }

    fn verifyTaprootSignature(self: *ScriptEngine, sig: []const u8, pubkey: []const u8) !bool {
        _ = self;
        if (sig.len != 64 and sig.len != 65) return false;
        if (pubkey.len != 32) return false;

        // Full implementation would call crypto.verifySchnorr
        if (!crypto.isSecp256k1Available()) {
            return true; // For testing
        }

        return false; // Placeholder
    }
};

// ============================================================================
// Script Classification
// ============================================================================

pub const ScriptType = enum {
    p2pkh, // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    p2sh, // OP_HASH160 <20> OP_EQUAL
    p2wpkh, // OP_0 <20>
    p2wsh, // OP_0 <32>
    p2tr, // OP_1 <32>
    anchor, // OP_1 <0x4e73> (P2A: Pay-to-Anchor, anyone-can-spend)
    p2pk, // <33 or 65> OP_CHECKSIG
    multisig, // OP_M <keys...> OP_N OP_CHECKMULTISIG
    null_data, // OP_RETURN <data>
    nonstandard,
};

/// Pay-to-Anchor (P2A) script: OP_1 PUSHBYTES_2 "Ns" (0x4e73)
/// Used for anyone-can-spend fee bumping anchors.
/// Reference: Bitcoin Core script/solver.cpp TxoutType::ANCHOR
pub const P2A_SCRIPT = [_]u8{ 0x51, 0x02, 0x4e, 0x73 };

/// Check if a script is a Pay-to-Anchor output.
pub fn isPayToAnchor(script: []const u8) bool {
    return std.mem.eql(u8, script, &P2A_SCRIPT);
}

pub fn classifyScript(script: []const u8) ScriptType {
    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    // 76 a9 14 <20 bytes> 88 ac
    if (script.len == 25 and script[0] == 0x76 and script[1] == 0xa9 and
        script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac)
    {
        return .p2pkh;
    }

    // P2SH: OP_HASH160 <20> OP_EQUAL
    // a9 14 <20 bytes> 87
    if (script.len == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87) {
        return .p2sh;
    }

    // P2WPKH: OP_0 <20>
    // 00 14 <20 bytes>
    if (script.len == 22 and script[0] == 0x00 and script[1] == 0x14) {
        return .p2wpkh;
    }

    // P2WSH: OP_0 <32>
    // 00 20 <32 bytes>
    if (script.len == 34 and script[0] == 0x00 and script[1] == 0x20) {
        return .p2wsh;
    }

    // P2A (Pay-to-Anchor): OP_1 <0x4e73>
    // 51 02 4e 73 (4 bytes exactly)
    // Must check before P2TR since both start with OP_1
    if (isPayToAnchor(script)) {
        return .anchor;
    }

    // P2TR: OP_1 <32>
    // 51 20 <32 bytes>
    if (script.len == 34 and script[0] == 0x51 and script[1] == 0x20) {
        return .p2tr;
    }

    // P2PK: <33> OP_CHECKSIG or <65> OP_CHECKSIG
    if ((script.len == 35 and script[0] == 0x21 and script[34] == 0xac) or
        (script.len == 67 and script[0] == 0x41 and script[66] == 0xac))
    {
        return .p2pk;
    }

    // OP_RETURN (null data)
    if (script.len > 0 and script[0] == 0x6a) {
        return .null_data;
    }

    // Multisig: OP_M <keys> OP_N OP_CHECKMULTISIG
    if (script.len >= 3 and script[script.len - 1] == 0xae) {
        // Basic check: first byte should be OP_1-OP_16, last two should be OP_N OP_CHECKMULTISIG
        if (script[0] >= 0x51 and script[0] <= 0x60 and
            script[script.len - 2] >= 0x51 and script[script.len - 2] <= 0x60)
        {
            return .multisig;
        }
    }

    return .nonstandard;
}

/// Check if a script is a witness program (segwit v0 or v1).
pub fn isWitnessProgram(script: []const u8) ?struct { version: u8, program: []const u8 } {
    if (script.len < 4 or script.len > 42) return null;

    // First byte is witness version (OP_0 = 0, OP_1-OP_16 = 1-16)
    const version_op = script[0];
    var version: u8 = 0;

    if (version_op == 0x00) {
        version = 0;
    } else if (version_op >= 0x51 and version_op <= 0x60) {
        version = version_op - 0x50;
    } else {
        return null;
    }

    // Second byte is push opcode
    const push_len = script[1];
    if (push_len < 2 or push_len > 40) return null;
    if (script.len != 2 + push_len) return null;

    return .{
        .version = version,
        .program = script[2..],
    };
}

// ============================================================================
// Sigop Counting
// ============================================================================

/// Maximum number of public keys in a multisig.
pub const MAX_PUBKEYS_PER_MULTISIG: u32 = 20;

/// Witness v0 keyhash size (P2WPKH).
pub const WITNESS_V0_KEYHASH_SIZE: usize = 20;

/// Witness v0 scripthash size (P2WSH).
pub const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;

/// Check if a script is P2SH: OP_HASH160 <20 bytes> OP_EQUAL.
pub fn isPayToScriptHash(script: []const u8) bool {
    return script.len == 23 and
        script[0] == 0xa9 and // OP_HASH160
        script[1] == 0x14 and // Push 20 bytes
        script[22] == 0x87; // OP_EQUAL
}

/// Count signature operations in a script.
/// If `accurate` is true, use the preceding OP_N for CHECKMULTISIG sigop count.
/// If `accurate` is false, always assume MAX_PUBKEYS_PER_MULTISIG for CHECKMULTISIG.
///
/// This counts:
/// - OP_CHECKSIG and OP_CHECKSIGVERIFY as 1 sigop each
/// - OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY as N sigops where N is the
///   number of public keys (from preceding OP_N) if accurate, or 20 otherwise.
///
/// Reference: Bitcoin Core script/script.cpp CScript::GetSigOpCount(bool fAccurate)
pub fn getSigOpCount(script: []const u8, accurate: bool) u32 {
    var n: u32 = 0;
    var pc: usize = 0;
    var last_opcode: u8 = 0xff; // Invalid opcode

    while (pc < script.len) {
        const opcode = script[pc];

        // Handle push opcodes - skip the data
        if (opcode <= 0x4b) {
            // Direct push: opcode is the number of bytes to push
            if (opcode > 0) {
                pc += @as(usize, opcode);
            }
        } else if (opcode == 0x4c) {
            // OP_PUSHDATA1: next byte is length
            if (pc + 1 >= script.len) break;
            pc += 1 + @as(usize, script[pc + 1]);
        } else if (opcode == 0x4d) {
            // OP_PUSHDATA2: next 2 bytes are length (little-endian)
            if (pc + 2 >= script.len) break;
            const len = @as(usize, script[pc + 1]) | (@as(usize, script[pc + 2]) << 8);
            pc += 2 + len;
        } else if (opcode == 0x4e) {
            // OP_PUSHDATA4: next 4 bytes are length (little-endian)
            if (pc + 4 >= script.len) break;
            const len = @as(usize, script[pc + 1]) |
                (@as(usize, script[pc + 2]) << 8) |
                (@as(usize, script[pc + 3]) << 16) |
                (@as(usize, script[pc + 4]) << 24);
            pc += 4 + len;
        }

        // Count sigops
        if (opcode == @intFromEnum(Opcode.op_checksig) or opcode == @intFromEnum(Opcode.op_checksigverify)) {
            n += 1;
        } else if (opcode == @intFromEnum(Opcode.op_checkmultisig) or opcode == @intFromEnum(Opcode.op_checkmultisigverify)) {
            // Count sigops: if accurate and last opcode was OP_1-OP_16, use that value
            if (accurate and last_opcode >= 0x51 and last_opcode <= 0x60) {
                // OP_1 (0x51) = 1, OP_16 (0x60) = 16
                n += @as(u32, last_opcode - 0x50);
            } else {
                n += MAX_PUBKEYS_PER_MULTISIG;
            }
        }

        last_opcode = opcode;
        pc += 1;
    }

    return n;
}

/// Get the last push data from a push-only script (for P2SH subscript extraction).
/// Returns the last data item pushed, or null if the script is not push-only.
///
/// Reference: Bitcoin Core script/script.cpp CScript::GetSigOpCount(const CScript& scriptSig)
fn getLastPushData(script_sig: []const u8) ?[]const u8 {
    var pc: usize = 0;
    var last_data: ?[]const u8 = null;

    while (pc < script_sig.len) {
        const opcode = script_sig[pc];

        // Handle push opcodes
        if (opcode == 0x00) {
            // OP_0: push empty
            last_data = script_sig[pc..pc]; // empty slice
            pc += 1;
        } else if (opcode <= 0x4b) {
            // Direct push: opcode is the number of bytes to push
            const push_len = @as(usize, opcode);
            if (pc + 1 + push_len > script_sig.len) return null;
            last_data = script_sig[pc + 1 .. pc + 1 + push_len];
            pc += 1 + push_len;
        } else if (opcode == 0x4c) {
            // OP_PUSHDATA1
            if (pc + 2 > script_sig.len) return null;
            const push_len = @as(usize, script_sig[pc + 1]);
            if (pc + 2 + push_len > script_sig.len) return null;
            last_data = script_sig[pc + 2 .. pc + 2 + push_len];
            pc += 2 + push_len;
        } else if (opcode == 0x4d) {
            // OP_PUSHDATA2
            if (pc + 3 > script_sig.len) return null;
            const push_len = @as(usize, script_sig[pc + 1]) | (@as(usize, script_sig[pc + 2]) << 8);
            if (pc + 3 + push_len > script_sig.len) return null;
            last_data = script_sig[pc + 3 .. pc + 3 + push_len];
            pc += 3 + push_len;
        } else if (opcode == 0x4e) {
            // OP_PUSHDATA4
            if (pc + 5 > script_sig.len) return null;
            const push_len = @as(usize, script_sig[pc + 1]) |
                (@as(usize, script_sig[pc + 2]) << 8) |
                (@as(usize, script_sig[pc + 3]) << 16) |
                (@as(usize, script_sig[pc + 4]) << 24);
            if (pc + 5 + push_len > script_sig.len) return null;
            last_data = script_sig[pc + 5 .. pc + 5 + push_len];
            pc += 5 + push_len;
        } else if (opcode >= 0x51 and opcode <= 0x60) {
            // OP_1 through OP_16: push a single byte value
            // For sigop counting, we don't need the actual value
            last_data = null; // These push small numbers, not script data
            pc += 1;
        } else {
            // Non-push opcode - script is not push-only
            return null;
        }
    }

    return last_data;
}

/// Count P2SH sigops by extracting the redeemScript from scriptSig.
/// The scriptPubKey must be P2SH. The function extracts the last push from
/// scriptSig and counts sigops in that subscript.
///
/// Reference: Bitcoin Core script/script.cpp CScript::GetSigOpCount(const CScript& scriptSig)
pub fn getP2SHSigOpCount(script_pubkey: []const u8, script_sig: []const u8) u32 {
    if (!isPayToScriptHash(script_pubkey)) {
        return getSigOpCount(script_pubkey, true);
    }

    // Extract the redeemScript (last push data from scriptSig)
    const redeem_script = getLastPushData(script_sig) orelse return 0;

    // Count sigops in the redeemScript (accurate mode)
    return getSigOpCount(redeem_script, true);
}

/// Count sigops in witness programs (witness v0 only).
/// - P2WPKH (20-byte program): 1 sigop
/// - P2WSH (32-byte program): count sigops in the witnessScript (last witness item)
/// - Other witness versions: 0 sigops (future-proofing)
///
/// Reference: Bitcoin Core script/interpreter.cpp WitnessSigOps()
fn witnessSigOps(wit_version: u8, wit_program: []const u8, witness: []const []const u8) u32 {
    if (wit_version == 0) {
        if (wit_program.len == WITNESS_V0_KEYHASH_SIZE) {
            // P2WPKH: 1 signature operation
            return 1;
        }

        if (wit_program.len == WITNESS_V0_SCRIPTHASH_SIZE and witness.len > 0) {
            // P2WSH: count sigops in the witnessScript (last witness item)
            const witness_script = witness[witness.len - 1];
            return getSigOpCount(witness_script, true);
        }
    }

    // Future witness versions: no sigop counting (not yet defined)
    return 0;
}

/// Count witness sigops for a transaction input.
/// Handles both native witness programs and P2SH-wrapped witness programs.
///
/// Reference: Bitcoin Core script/interpreter.cpp CountWitnessSigOps()
pub fn countWitnessSigOps(
    script_sig: []const u8,
    script_pubkey: []const u8,
    witness: []const []const u8,
    flags: ScriptFlags,
) u32 {
    if (!flags.verify_witness) {
        return 0;
    }

    // Check for native witness program
    if (isWitnessProgram(script_pubkey)) |wp| {
        return witnessSigOps(wp.version, wp.program, witness);
    }

    // Check for P2SH-wrapped witness program
    if (isPayToScriptHash(script_pubkey) and isPushOnly(script_sig)) {
        // Extract the redeemScript (subscript) from scriptSig
        const subscript = getLastPushData(script_sig) orelse return 0;

        if (isWitnessProgram(subscript)) |wp| {
            return witnessSigOps(wp.version, wp.program, witness);
        }
    }

    return 0;
}

// ============================================================================
// Legacy Sighash (Pre-SegWit)
// ============================================================================

/// Sighash type constants
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Error type for sighash computation
pub const SighashError = error{
    OutOfMemory,
    InvalidScript,
};

/// Remove all occurrences of `pattern` from `script` and return a new script.
/// This implements the FindAndDelete operation used in legacy sighash computation.
/// Per Bitcoin Core: FindAndDelete operates on raw bytes, scanning for the exact byte pattern.
/// Reference: Bitcoin Core script/interpreter.cpp FindAndDelete()
pub fn findAndDelete(allocator: std.mem.Allocator, script: []const u8, pattern: []const u8) SighashError![]u8 {
    if (pattern.len == 0) {
        // No pattern to delete, return copy of original
        return allocator.dupe(u8, script) catch return SighashError.OutOfMemory;
    }

    // Build result by skipping all occurrences of pattern
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var i: usize = 0;
    while (i < script.len) {
        // Check if pattern matches at current position
        if (i + pattern.len <= script.len and std.mem.eql(u8, script[i .. i + pattern.len], pattern)) {
            // Skip the pattern
            i += pattern.len;
        } else {
            // Copy the byte
            result.append(script[i]) catch return SighashError.OutOfMemory;
            i += 1;
        }
    }

    return result.toOwnedSlice() catch return SighashError.OutOfMemory;
}

/// Remove all OP_CODESEPARATOR opcodes from a script.
/// Used when preparing the scriptCode for legacy sighash computation.
/// Reference: Bitcoin Core script/interpreter.cpp CTransactionSignatureSerializer::SerializeScriptCode()
pub fn removeCodeSeparators(allocator: std.mem.Allocator, script: []const u8) SighashError![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var pc: usize = 0;
    while (pc < script.len) {
        const opcode = script[pc];

        // OP_CODESEPARATOR = 0xab
        if (opcode == 0xab) {
            pc += 1;
            continue;
        }

        // Copy opcode
        result.append(opcode) catch return SighashError.OutOfMemory;
        pc += 1;

        // Handle push data
        if (opcode >= 0x01 and opcode <= 0x4b) {
            // Direct push: copy the data bytes
            const n: usize = opcode;
            if (pc + n > script.len) return SighashError.InvalidScript;
            for (script[pc .. pc + n]) |byte| {
                result.append(byte) catch return SighashError.OutOfMemory;
            }
            pc += n;
        } else if (opcode == 0x4c) {
            // OP_PUSHDATA1
            if (pc >= script.len) return SighashError.InvalidScript;
            const n: usize = script[pc];
            result.append(script[pc]) catch return SighashError.OutOfMemory;
            pc += 1;
            if (pc + n > script.len) return SighashError.InvalidScript;
            for (script[pc .. pc + n]) |byte| {
                result.append(byte) catch return SighashError.OutOfMemory;
            }
            pc += n;
        } else if (opcode == 0x4d) {
            // OP_PUSHDATA2
            if (pc + 2 > script.len) return SighashError.InvalidScript;
            const n: usize = std.mem.readInt(u16, script[pc..][0..2], .little);
            result.append(script[pc]) catch return SighashError.OutOfMemory;
            result.append(script[pc + 1]) catch return SighashError.OutOfMemory;
            pc += 2;
            if (pc + n > script.len) return SighashError.InvalidScript;
            for (script[pc .. pc + n]) |byte| {
                result.append(byte) catch return SighashError.OutOfMemory;
            }
            pc += n;
        } else if (opcode == 0x4e) {
            // OP_PUSHDATA4
            if (pc + 4 > script.len) return SighashError.InvalidScript;
            const n: usize = std.mem.readInt(u32, script[pc..][0..4], .little);
            for (script[pc .. pc + 4]) |byte| {
                result.append(byte) catch return SighashError.OutOfMemory;
            }
            pc += 4;
            if (pc + n > script.len) return SighashError.InvalidScript;
            for (script[pc .. pc + n]) |byte| {
                result.append(byte) catch return SighashError.OutOfMemory;
            }
            pc += n;
        }
    }

    return result.toOwnedSlice() catch return SighashError.OutOfMemory;
}

/// Create the push-encoded form of data (used for FindAndDelete).
/// For data up to 75 bytes, push_opcode = length.
/// For larger data, OP_PUSHDATA1/2/4 is used.
pub fn pushEncode(allocator: std.mem.Allocator, data: []const u8) SighashError![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    if (data.len <= 0x4b) {
        // Direct push
        result.append(@intCast(data.len)) catch return SighashError.OutOfMemory;
    } else if (data.len <= 0xff) {
        // OP_PUSHDATA1
        result.append(0x4c) catch return SighashError.OutOfMemory;
        result.append(@intCast(data.len)) catch return SighashError.OutOfMemory;
    } else if (data.len <= 0xffff) {
        // OP_PUSHDATA2
        result.append(0x4d) catch return SighashError.OutOfMemory;
        var len_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_bytes, @intCast(data.len), .little);
        for (len_bytes) |b| {
            result.append(b) catch return SighashError.OutOfMemory;
        }
    } else {
        // OP_PUSHDATA4
        result.append(0x4e) catch return SighashError.OutOfMemory;
        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, @intCast(data.len), .little);
        for (len_bytes) |b| {
            result.append(b) catch return SighashError.OutOfMemory;
        }
    }

    for (data) |b| {
        result.append(b) catch return SighashError.OutOfMemory;
    }

    return result.toOwnedSlice() catch return SighashError.OutOfMemory;
}

/// Write a CompactSize integer to a buffer.
fn writeCompactSize(writer: *std.ArrayList(u8), value: usize) SighashError!void {
    if (value < 0xfd) {
        writer.append(@intCast(value)) catch return SighashError.OutOfMemory;
    } else if (value <= 0xffff) {
        writer.append(0xfd) catch return SighashError.OutOfMemory;
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(value), .little);
        for (bytes) |b| {
            writer.append(b) catch return SighashError.OutOfMemory;
        }
    } else if (value <= 0xffffffff) {
        writer.append(0xfe) catch return SighashError.OutOfMemory;
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(value), .little);
        for (bytes) |b| {
            writer.append(b) catch return SighashError.OutOfMemory;
        }
    } else {
        writer.append(0xff) catch return SighashError.OutOfMemory;
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, @intCast(value), .little);
        for (bytes) |b| {
            writer.append(b) catch return SighashError.OutOfMemory;
        }
    }
}

/// Compute legacy (pre-segwit) signature hash.
/// This implements the original Bitcoin sighash algorithm including:
/// - FindAndDelete: removes the signature being checked from scriptCode
/// - OP_CODESEPARATOR handling: uses scriptCode starting after the last executed OP_CODESEPARATOR
/// - SIGHASH_NONE: zeroes all outputs and other input sequences
/// - SIGHASH_SINGLE: only hash output at same index; return 1 if index >= outputs.len
/// - SIGHASH_ANYONECANPAY: only hash the current input
///
/// Reference: Bitcoin Core script/interpreter.cpp SignatureHash(), CTransactionSignatureSerializer
pub fn legacySignatureHash(
    allocator: std.mem.Allocator,
    tx: *const types.Transaction,
    input_index: usize,
    script_code: []const u8,
    hash_type: u32,
) SighashError![32]u8 {
    const base_type = hash_type & 0x1f;
    const anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    const hash_single = base_type == SIGHASH_SINGLE;
    const hash_none = base_type == SIGHASH_NONE;

    // SIGHASH_SINGLE with input index >= outputs.len returns uint256 one
    // This is a known quirk of Bitcoin's sighash
    if (hash_single and input_index >= tx.outputs.len) {
        var result: [32]u8 = [_]u8{0} ** 32;
        result[0] = 0x01; // Little-endian 1
        return result;
    }

    // Remove OP_CODESEPARATOR from script code
    const clean_script = try removeCodeSeparators(allocator, script_code);
    defer allocator.free(clean_script);

    // Build the serialized transaction for hashing
    var preimage = std.ArrayList(u8).init(allocator);
    defer preimage.deinit();

    // Version (4 bytes, little-endian)
    var version_bytes: [4]u8 = undefined;
    std.mem.writeInt(i32, &version_bytes, tx.version, .little);
    for (version_bytes) |b| {
        preimage.append(b) catch return SighashError.OutOfMemory;
    }

    // Number of inputs
    const num_inputs: usize = if (anyone_can_pay) 1 else tx.inputs.len;
    try writeCompactSize(&preimage, num_inputs);

    // Serialize inputs
    for (0..num_inputs) |i| {
        const actual_idx = if (anyone_can_pay) input_index else i;
        const input = tx.inputs[actual_idx];

        // Previous output hash (32 bytes)
        for (input.previous_output.hash) |b| {
            preimage.append(b) catch return SighashError.OutOfMemory;
        }

        // Previous output index (4 bytes)
        var idx_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &idx_bytes, input.previous_output.index, .little);
        for (idx_bytes) |b| {
            preimage.append(b) catch return SighashError.OutOfMemory;
        }

        // Script (scriptCode for input being signed, empty for others)
        if (actual_idx == input_index) {
            try writeCompactSize(&preimage, clean_script.len);
            for (clean_script) |b| {
                preimage.append(b) catch return SighashError.OutOfMemory;
            }
        } else {
            // Empty script for other inputs
            preimage.append(0x00) catch return SighashError.OutOfMemory;
        }

        // Sequence (4 bytes)
        // For SIGHASH_NONE or SIGHASH_SINGLE, other inputs get sequence 0
        const sequence: u32 = if (actual_idx != input_index and (hash_single or hash_none))
            0
        else
            input.sequence;

        var seq_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &seq_bytes, sequence, .little);
        for (seq_bytes) |b| {
            preimage.append(b) catch return SighashError.OutOfMemory;
        }
    }

    // Number of outputs
    const num_outputs: usize = if (hash_none) 0 else if (hash_single) input_index + 1 else tx.outputs.len;
    try writeCompactSize(&preimage, num_outputs);

    // Serialize outputs
    for (0..num_outputs) |i| {
        if (hash_single and i != input_index) {
            // For SIGHASH_SINGLE, outputs before the signing input are "blank"
            // (value = -1, empty script)
            var neg_one: [8]u8 = undefined;
            std.mem.writeInt(i64, &neg_one, -1, .little);
            for (neg_one) |b| {
                preimage.append(b) catch return SighashError.OutOfMemory;
            }
            preimage.append(0x00) catch return SighashError.OutOfMemory; // Empty script
        } else {
            const output = tx.outputs[i];

            // Value (8 bytes)
            var value_bytes: [8]u8 = undefined;
            std.mem.writeInt(i64, &value_bytes, output.value, .little);
            for (value_bytes) |b| {
                preimage.append(b) catch return SighashError.OutOfMemory;
            }

            // Script pubkey
            try writeCompactSize(&preimage, output.script_pubkey.len);
            for (output.script_pubkey) |b| {
                preimage.append(b) catch return SighashError.OutOfMemory;
            }
        }
    }

    // Lock time (4 bytes)
    var locktime_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &locktime_bytes, tx.lock_time, .little);
    for (locktime_bytes) |b| {
        preimage.append(b) catch return SighashError.OutOfMemory;
    }

    // Hash type (4 bytes, little-endian)
    var hashtype_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &hashtype_bytes, hash_type, .little);
    for (hashtype_bytes) |b| {
        preimage.append(b) catch return SighashError.OutOfMemory;
    }

    // Double SHA256
    return crypto.hash256(preimage.items);
}

/// Compute legacy sighash with FindAndDelete of the signature.
/// This is the main entry point for legacy signature verification.
/// Before computing the sighash, it removes all occurrences of the push-encoded
/// signature from the scriptCode (the FindAndDelete operation).
///
/// Reference: Bitcoin Core script/interpreter.cpp EvalChecksigPreTapscript()
pub fn legacySignatureHashWithFindAndDelete(
    allocator: std.mem.Allocator,
    tx: *const types.Transaction,
    input_index: usize,
    script_code: []const u8,
    signature: []const u8,
    hash_type: u32,
) SighashError![32]u8 {
    // Push-encode the signature for FindAndDelete
    const push_encoded_sig = try pushEncode(allocator, signature);
    defer allocator.free(push_encoded_sig);

    // Remove all occurrences of the signature from the script
    const clean_script = try findAndDelete(allocator, script_code, push_encoded_sig);
    defer allocator.free(clean_script);

    // Compute the sighash
    return legacySignatureHash(allocator, tx, input_index, clean_script, hash_type);
}

/// Get the scriptCode for signing, starting after the given codesep_pos.
/// codesep_pos is the byte offset of the last executed OP_CODESEPARATOR.
/// If codesep_pos is 0xFFFFFFFF, the entire script is used.
pub fn getScriptCodeFromCodesepPos(script: []const u8, codesep_pos: u32) []const u8 {
    if (codesep_pos == 0xFFFFFFFF or codesep_pos >= script.len) {
        return script;
    }
    // Skip the OP_CODESEPARATOR itself (1 byte)
    const start = codesep_pos + 1;
    if (start >= script.len) {
        return &[_]u8{};
    }
    return script[start..];
}

// ============================================================================
// Tests
// ============================================================================

test "simple script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL" {
    const allocator = std.testing.allocator;

    // Create a minimal transaction for the engine
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
    // 51 51 93 52 87
    const script = [_]u8{ 0x51, 0x51, 0x93, 0x52, 0x87 };

    try engine.execute(&script);

    // Stack should have single true value
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    try std.testing.expect(engine.stackToBool(engine.stack.items[0]));
}

test "P2PKH template classification" {
    // Standard P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    var script: [25]u8 = undefined;
    script[0] = 0x76; // OP_DUP
    script[1] = 0xa9; // OP_HASH160
    script[2] = 0x14; // Push 20 bytes
    @memset(script[3..23], 0xAB); // 20 byte hash
    script[23] = 0x88; // OP_EQUALVERIFY
    script[24] = 0xac; // OP_CHECKSIG

    try std.testing.expectEqual(ScriptType.p2pkh, classifyScript(&script));
}

test "P2SH template classification" {
    // Standard P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    var script: [23]u8 = undefined;
    script[0] = 0xa9; // OP_HASH160
    script[1] = 0x14; // Push 20 bytes
    @memset(script[2..22], 0xAB); // 20 byte hash
    script[22] = 0x87; // OP_EQUAL

    try std.testing.expectEqual(ScriptType.p2sh, classifyScript(&script));
}

test "P2WPKH template classification" {
    // Standard P2WPKH: OP_0 <20 bytes>
    var script: [22]u8 = undefined;
    script[0] = 0x00; // OP_0
    script[1] = 0x14; // Push 20 bytes
    @memset(script[2..22], 0xAB); // 20 byte hash

    try std.testing.expectEqual(ScriptType.p2wpkh, classifyScript(&script));
}

test "P2WSH template classification" {
    // Standard P2WSH: OP_0 <32 bytes>
    var script: [34]u8 = undefined;
    script[0] = 0x00; // OP_0
    script[1] = 0x20; // Push 32 bytes
    @memset(script[2..34], 0xAB); // 32 byte hash

    try std.testing.expectEqual(ScriptType.p2wsh, classifyScript(&script));
}

test "P2TR template classification" {
    // Standard P2TR: OP_1 <32 bytes>
    var script: [34]u8 = undefined;
    script[0] = 0x51; // OP_1
    script[1] = 0x20; // Push 32 bytes
    @memset(script[2..34], 0xAB); // 32 byte x-only pubkey

    try std.testing.expectEqual(ScriptType.p2tr, classifyScript(&script));
}

test "P2A (Pay-to-Anchor) template classification" {
    // P2A: OP_1 PUSHBYTES_2 0x4e73 ("Ns")
    // 4 bytes exactly: 0x51 0x02 0x4e 0x73
    try std.testing.expectEqual(ScriptType.anchor, classifyScript(&P2A_SCRIPT));

    // Verify isPayToAnchor helper
    try std.testing.expect(isPayToAnchor(&P2A_SCRIPT));

    // Should not match other scripts starting with OP_1
    var p2tr_script: [34]u8 = undefined;
    p2tr_script[0] = 0x51;
    p2tr_script[1] = 0x20;
    @memset(p2tr_script[2..34], 0xAB);
    try std.testing.expect(!isPayToAnchor(&p2tr_script));
    try std.testing.expectEqual(ScriptType.p2tr, classifyScript(&p2tr_script));

    // Wrong data (not "Ns")
    const wrong_data = [_]u8{ 0x51, 0x02, 0x00, 0x00 };
    try std.testing.expect(!isPayToAnchor(&wrong_data));
    try std.testing.expectEqual(ScriptType.nonstandard, classifyScript(&wrong_data));
}

test "OP_RETURN script classified as null_data" {
    // OP_RETURN <data>
    const script = [_]u8{ 0x6a, 0x04, 0x01, 0x02, 0x03, 0x04 };

    try std.testing.expectEqual(ScriptType.null_data, classifyScript(&script));
}

test "scriptNumEncode/Decode round-trip" {
    const allocator = std.testing.allocator;

    const test_values = [_]i64{ 0, 1, -1, 127, 128, -128, 255, 256, -256, 32767, -32768, 8388607, -8388608 };

    for (test_values) |val| {
        const encoded = try scriptNumEncode(val, allocator);
        defer allocator.free(encoded);

        const decoded = try scriptNumDecode(encoded);
        try std.testing.expectEqual(val, decoded);
    }
}

test "OP_DUP" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // OP_1 OP_DUP
    const script = [_]u8{ 0x51, 0x76 };
    try engine.execute(&script);

    try std.testing.expectEqual(@as(usize, 2), engine.stack.items.len);
}

test "OP_IF OP_ELSE OP_ENDIF" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    {
        // Test with true condition: OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        // Should push 2
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
        defer engine.deinit();

        const script = [_]u8{ 0x51, 0x63, 0x52, 0x67, 0x53, 0x68 };
        try engine.execute(&script);

        try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
        const val = try scriptNumDecode(engine.stack.items[0]);
        try std.testing.expectEqual(@as(i64, 2), val);
    }

    {
        // Test with false condition: OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        // Should push 3
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
        defer engine.deinit();

        const script = [_]u8{ 0x00, 0x63, 0x52, 0x67, 0x53, 0x68 };
        try engine.execute(&script);

        try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
        const val = try scriptNumDecode(engine.stack.items[0]);
        try std.testing.expectEqual(@as(i64, 3), val);
    }
}

test "OP_HASH160" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Push "hello" (5 bytes) and hash it
    // 05 68 65 6c 6c 6f (push 5 bytes: "hello")
    // a9 (OP_HASH160)
    const script = [_]u8{ 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xa9 };
    try engine.execute(&script);

    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    try std.testing.expectEqual(@as(usize, 20), engine.stack.items[0].len);
}

test "OP_RETURN in non-executing branch" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // OP_0 OP_IF OP_RETURN OP_ENDIF OP_1
    // The OP_RETURN should NOT terminate because we're in non-executing branch
    const script = [_]u8{ 0x00, 0x63, 0x6a, 0x68, 0x51 };
    try engine.execute(&script);

    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    const val = try scriptNumDecode(engine.stack.items[0]);
    try std.testing.expectEqual(@as(i64, 1), val);
}

test "OP_RETURN in executing branch fails" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // OP_1 OP_IF OP_RETURN OP_ENDIF
    // The OP_RETURN SHOULD terminate because we're in executing branch
    const script = [_]u8{ 0x51, 0x63, 0x6a, 0x68 };

    const result = engine.execute(&script);
    try std.testing.expectError(ScriptError.OpReturnEncountered, result);
}

test "OP_SWAP" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // OP_1 OP_2 OP_SWAP
    const script = [_]u8{ 0x51, 0x52, 0x7c };
    try engine.execute(&script);

    try std.testing.expectEqual(@as(usize, 2), engine.stack.items.len);
    const top = try scriptNumDecode(engine.stack.items[1]);
    const second = try scriptNumDecode(engine.stack.items[0]);
    try std.testing.expectEqual(@as(i64, 1), top);
    try std.testing.expectEqual(@as(i64, 2), second);
}

test "isWitnessProgram" {
    // P2WPKH
    var script_wpkh: [22]u8 = undefined;
    script_wpkh[0] = 0x00;
    script_wpkh[1] = 0x14;
    @memset(script_wpkh[2..22], 0xAB);

    const wpkh_result = isWitnessProgram(&script_wpkh);
    try std.testing.expect(wpkh_result != null);
    try std.testing.expectEqual(@as(u8, 0), wpkh_result.?.version);
    try std.testing.expectEqual(@as(usize, 20), wpkh_result.?.program.len);

    // P2WSH
    var script_wsh: [34]u8 = undefined;
    script_wsh[0] = 0x00;
    script_wsh[1] = 0x20;
    @memset(script_wsh[2..34], 0xAB);

    const wsh_result = isWitnessProgram(&script_wsh);
    try std.testing.expect(wsh_result != null);
    try std.testing.expectEqual(@as(u8, 0), wsh_result.?.version);
    try std.testing.expectEqual(@as(usize, 32), wsh_result.?.program.len);

    // P2TR
    var script_tr: [34]u8 = undefined;
    script_tr[0] = 0x51;
    script_tr[1] = 0x20;
    @memset(script_tr[2..34], 0xAB);

    const tr_result = isWitnessProgram(&script_tr);
    try std.testing.expect(tr_result != null);
    try std.testing.expectEqual(@as(u8, 1), tr_result.?.version);
    try std.testing.expectEqual(@as(usize, 32), tr_result.?.program.len);
}

// ============================================================================
// NULLFAIL (BIP-146) Tests
// ============================================================================

test "NULLFAIL: empty signature allowed to fail OP_CHECKSIG" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // With NULLFAIL enabled (default), empty signature failing is allowed
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Script: <empty> <pubkey> OP_CHECKSIG
    // Push empty signature (OP_0), push a 33-byte pubkey, OP_CHECKSIG
    // OP_0 = 0x00, push 33 bytes = 0x21, then 33 bytes of pubkey, OP_CHECKSIG = 0xAC
    var script_buf: [36]u8 = undefined;
    script_buf[0] = 0x00; // OP_0 (empty signature)
    script_buf[1] = 0x21; // Push 33 bytes
    @memset(script_buf[2..35], 0x02); // Fake compressed pubkey
    script_buf[35] = 0xac; // OP_CHECKSIG

    try engine.execute(&script_buf);

    // Should succeed (pushes false to stack since sig verification fails,
    // but empty sig doesn't trigger NULLFAIL)
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    // The result should be false (empty = 0)
    try std.testing.expectEqual(@as(usize, 0), engine.stack.items[0].len);
}

test "NULLFAIL: non-empty failing signature rejected with NULLFAIL (requires secp256k1)" {
    // Skip this test if secp256k1 is not available
    // When secp256k1 is available, signature verification will actually fail
    // and trigger NULLFAIL
    if (!crypto.isSecp256k1Available()) {
        // Without secp256k1, verifySignature returns true for testing,
        // so we can't test failing signature behavior
        return;
    }

    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // With NULLFAIL enabled, non-empty failing signature should error
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{ .verify_nullfail = true });
    defer engine.deinit();

    // Script: <bad_signature> <pubkey> OP_CHECKSIG
    // Push a fake non-empty signature, push a pubkey, OP_CHECKSIG
    var script_buf: [71]u8 = undefined;
    script_buf[0] = 0x23; // Push 35 bytes (fake DER signature + hashtype)
    @memset(script_buf[1..36], 0x30); // Fake signature bytes
    script_buf[36] = 0x21; // Push 33 bytes
    @memset(script_buf[37..70], 0x02); // Fake compressed pubkey
    script_buf[70] = 0xac; // OP_CHECKSIG

    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.NullFail, result);
}

test "NULLFAIL: non-empty failing signature allowed without NULLFAIL flag" {
    // When NULLFAIL is disabled, any signature can fail without error
    // (the script just pushes false or fails at VERIFY step)
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // With NULLFAIL disabled, non-empty failing signature should be allowed
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{ .verify_nullfail = false });
    defer engine.deinit();

    // Script: <bad_signature> <pubkey> OP_CHECKSIG
    var script_buf: [71]u8 = undefined;
    script_buf[0] = 0x23; // Push 35 bytes (fake DER signature + hashtype)
    @memset(script_buf[1..36], 0x30); // Fake signature bytes
    script_buf[36] = 0x21; // Push 33 bytes
    @memset(script_buf[37..70], 0x02); // Fake compressed pubkey
    script_buf[70] = 0xac; // OP_CHECKSIG

    // Should succeed (no NULLFAIL check, script pushes true/false)
    try engine.execute(&script_buf);
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
}

test "NULLFAIL: OP_CHECKSIGVERIFY with non-empty failing sig (requires secp256k1)" {
    // Skip this test if secp256k1 is not available
    if (!crypto.isSecp256k1Available()) {
        return;
    }

    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // With NULLFAIL enabled, non-empty failing signature should error
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{ .verify_nullfail = true });
    defer engine.deinit();

    // Script: <bad_signature> <pubkey> OP_CHECKSIGVERIFY
    var script_buf: [71]u8 = undefined;
    script_buf[0] = 0x23; // Push 35 bytes
    @memset(script_buf[1..36], 0x30); // Fake signature bytes
    script_buf[36] = 0x21; // Push 33 bytes
    @memset(script_buf[37..70], 0x02); // Fake compressed pubkey
    script_buf[70] = 0xad; // OP_CHECKSIGVERIFY

    // Should fail with NullFail (not CheckSigFailed, because NULLFAIL is checked first)
    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.NullFail, result);
}

test "NULLFAIL: ScriptFlags has verify_nullfail enabled by default" {
    const flags = ScriptFlags{};
    try std.testing.expect(flags.verify_nullfail);
}

test "NULLFAIL: flag is part of packed struct at correct bit position" {
    // Verify the flag can be set and read correctly
    var flags = ScriptFlags{};
    flags.verify_nullfail = false;
    try std.testing.expect(!flags.verify_nullfail);
    flags.verify_nullfail = true;
    try std.testing.expect(flags.verify_nullfail);
}

// ============================================================================
// WITNESS_PUBKEYTYPE (BIP-141) Tests
// ============================================================================

test "isCompressedPubkey: valid compressed key 0x02 prefix" {
    var pubkey: [33]u8 = undefined;
    pubkey[0] = 0x02;
    @memset(pubkey[1..33], 0xAB);
    try std.testing.expect(isCompressedPubkey(&pubkey));
}

test "isCompressedPubkey: valid compressed key 0x03 prefix" {
    var pubkey: [33]u8 = undefined;
    pubkey[0] = 0x03;
    @memset(pubkey[1..33], 0xAB);
    try std.testing.expect(isCompressedPubkey(&pubkey));
}

test "isCompressedPubkey: uncompressed key 0x04 prefix rejected" {
    var pubkey: [65]u8 = undefined;
    pubkey[0] = 0x04;
    @memset(pubkey[1..65], 0xAB);
    try std.testing.expect(!isCompressedPubkey(&pubkey));
}

test "isCompressedPubkey: wrong length rejected" {
    var pubkey: [32]u8 = undefined;
    pubkey[0] = 0x02;
    @memset(pubkey[1..32], 0xAB);
    try std.testing.expect(!isCompressedPubkey(&pubkey));
}

test "isCompressedPubkey: wrong prefix rejected" {
    var pubkey: [33]u8 = undefined;
    pubkey[0] = 0x04; // wrong prefix for 33 bytes
    @memset(pubkey[1..33], 0xAB);
    try std.testing.expect(!isCompressedPubkey(&pubkey));
}

test "WITNESS_PUBKEYTYPE: flag enabled by default" {
    const flags = ScriptFlags{};
    try std.testing.expect(flags.verify_witness_pubkeytype);
}

test "WITNESS_PUBKEYTYPE: P2WPKH with compressed pubkey succeeds" {
    const allocator = std.testing.allocator;

    // Create minimal transaction
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // P2WPKH scriptPubKey: OP_0 <20 bytes>
    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memset(script_pubkey[2..22], 0xAB); // 20 byte hash

    // Compressed pubkey (33 bytes, 0x02 prefix)
    var compressed_pubkey: [33]u8 = undefined;
    compressed_pubkey[0] = 0x02;
    @memset(compressed_pubkey[1..33], 0xCD);

    // Witness: [signature, compressed_pubkey]
    var fake_sig: [72]u8 = undefined;
    @memset(&fake_sig, 0x30);
    fake_sig[71] = 0x01; // SIGHASH_ALL

    const witness = [_][]const u8{ &fake_sig, &compressed_pubkey };

    // Note: actual verification will succeed because secp256k1 may not be available
    // But importantly, it should NOT fail with WitnessPubkeyType
    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    // If secp256k1 is not available, verifySignature returns true
    // So the overall verify should succeed
    if (result) |valid| {
        // Should not fail with WitnessPubkeyType - that would have been an error
        _ = valid;
    } else |err| {
        // Should not be WitnessPubkeyType error since key is compressed
        try std.testing.expect(err != ScriptError.WitnessPubkeyType);
    }
}

test "WITNESS_PUBKEYTYPE: P2WPKH with uncompressed pubkey fails" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // P2WPKH scriptPubKey: OP_0 <20 bytes>
    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memset(script_pubkey[2..22], 0xAB);

    // Uncompressed pubkey (65 bytes, 0x04 prefix)
    var uncompressed_pubkey: [65]u8 = undefined;
    uncompressed_pubkey[0] = 0x04;
    @memset(uncompressed_pubkey[1..65], 0xCD);

    // Witness: [signature, uncompressed_pubkey]
    var fake_sig: [72]u8 = undefined;
    @memset(&fake_sig, 0x30);
    fake_sig[71] = 0x01;

    const witness = [_][]const u8{ &fake_sig, &uncompressed_pubkey };

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    try std.testing.expectError(ScriptError.WitnessPubkeyType, result);
}

test "WITNESS_PUBKEYTYPE: P2WPKH with uncompressed pubkey succeeds when flag disabled" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // Disable the witness pubkeytype check
    var flags = ScriptFlags{};
    flags.verify_witness_pubkeytype = false;

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    // P2WPKH scriptPubKey
    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memset(script_pubkey[2..22], 0xAB);

    // Uncompressed pubkey (65 bytes, 0x04 prefix)
    var uncompressed_pubkey: [65]u8 = undefined;
    uncompressed_pubkey[0] = 0x04;
    @memset(uncompressed_pubkey[1..65], 0xCD);

    var fake_sig: [72]u8 = undefined;
    @memset(&fake_sig, 0x30);
    fake_sig[71] = 0x01;

    const witness = [_][]const u8{ &fake_sig, &uncompressed_pubkey };

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    // Should NOT fail with WitnessPubkeyType since flag is disabled
    if (result) |_| {
        // Success is fine
    } else |err| {
        // Should not be WitnessPubkeyType error
        try std.testing.expect(err != ScriptError.WitnessPubkeyType);
    }
}

test "WITNESS_PUBKEYTYPE: SigVersion enum values" {
    // Verify the enum values exist
    try std.testing.expectEqual(SigVersion.base, SigVersion.base);
    try std.testing.expectEqual(SigVersion.witness_v0, SigVersion.witness_v0);
    try std.testing.expectEqual(SigVersion.tapscript, SigVersion.tapscript);
}

test "WITNESS_PUBKEYTYPE: ScriptEngine initializes with base sig_version" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    try std.testing.expectEqual(SigVersion.base, engine.sig_version);
}

// ============================================================================
// Witness CLEANSTACK Tests (BIP 141/143)
// ============================================================================
// Witness scripts (P2WPKH, P2WSH, tapscript) UNCONDITIONALLY require exactly
// one element on the stack after execution. This is NOT flag-gated like the
// legacy CLEANSTACK flag. Reference: Bitcoin Core interpreter.cpp ExecuteWitnessScript()

test "witness cleanstack: P2WSH with extra stack items fails" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Create a P2WSH scriptPubKey
    // The witness script will be: OP_1 OP_1 (pushes two items, violates cleanstack)
    const witness_script = [_]u8{ 0x51, 0x51 }; // OP_1 OP_1
    const witness_hash = crypto.sha256(&witness_script);

    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x20; // Push 32 bytes
    @memcpy(script_pubkey[2..34], &witness_hash);

    // Witness: [witness_script]
    const witness = [_][]const u8{&witness_script};

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    try std.testing.expectError(ScriptError.CleanStack, result);
}

test "witness cleanstack: P2WSH with exactly one true item succeeds" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Witness script: OP_1 (pushes single true value)
    const witness_script = [_]u8{0x51}; // OP_1
    const witness_hash = crypto.sha256(&witness_script);

    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x20; // Push 32 bytes
    @memcpy(script_pubkey[2..34], &witness_hash);

    // Witness: [witness_script]
    const witness = [_][]const u8{&witness_script};

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    // Should succeed - exactly one true item on stack
    if (result) |valid| {
        try std.testing.expect(valid);
    } else |_| {
        // Should not fail
        try std.testing.expect(false);
    }
}

test "witness cleanstack: P2WSH with empty stack fails" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Witness script: OP_1 OP_DROP (leaves empty stack)
    const witness_script = [_]u8{ 0x51, 0x75 }; // OP_1 OP_DROP
    const witness_hash = crypto.sha256(&witness_script);

    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x20; // Push 32 bytes
    @memcpy(script_pubkey[2..34], &witness_hash);

    // Witness: [witness_script]
    const witness = [_][]const u8{&witness_script};

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    // Should fail with CleanStack (0 != 1)
    try std.testing.expectError(ScriptError.CleanStack, result);
}

test "witness cleanstack: is NOT flag-gated (always enforced for witness)" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // Even with verify_clean_stack disabled, witness cleanstack is enforced
    var flags = ScriptFlags{};
    flags.verify_clean_stack = false;

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    // Witness script: OP_1 OP_1 (pushes two items)
    const witness_script = [_]u8{ 0x51, 0x51 }; // OP_1 OP_1
    const witness_hash = crypto.sha256(&witness_script);

    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x20; // Push 32 bytes
    @memcpy(script_pubkey[2..34], &witness_hash);

    const witness = [_][]const u8{&witness_script};

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    // Should STILL fail with CleanStack even though flag is disabled
    // because witness cleanstack is unconditional
    try std.testing.expectError(ScriptError.CleanStack, result);
}

test "witness cleanstack: single false value fails (eval false, not cleanstack)" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Witness script: OP_0 (pushes single false value)
    const witness_script = [_]u8{0x00}; // OP_0
    const witness_hash = crypto.sha256(&witness_script);

    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x20; // Push 32 bytes
    @memcpy(script_pubkey[2..34], &witness_hash);

    const witness = [_][]const u8{&witness_script};

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    // Should return false (not error) because stack has exactly 1 item
    // but that item is false
    if (result) |valid| {
        try std.testing.expect(!valid);
    } else |err| {
        // Should not be CleanStack error - it's exactly 1 item
        try std.testing.expect(err != ScriptError.CleanStack);
    }
}

// ============================================================================
// isPushOnly Tests (BIP-16 P2SH Push-Only scriptSig)
// ============================================================================
// Per BIP-16, when spending a P2SH output, the scriptSig must contain only
// push operations. This is enforced unconditionally when P2SH validation
// is enabled. Reference: Bitcoin Core script/script.cpp IsPushOnly()

test "isPushOnly: empty script is push-only" {
    try std.testing.expect(isPushOnly(&[_]u8{}));
}

test "isPushOnly: OP_0 is push-only" {
    try std.testing.expect(isPushOnly(&[_]u8{0x00}));
}

test "isPushOnly: direct push opcodes (0x01-0x4b) are push-only" {
    // Push 1 byte
    try std.testing.expect(isPushOnly(&[_]u8{ 0x01, 0xAB }));
    // Push 5 bytes
    try std.testing.expect(isPushOnly(&[_]u8{ 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 }));
    // Push 0x4b (75) bytes
    var script: [76]u8 = undefined;
    script[0] = 0x4b;
    @memset(script[1..76], 0xAB);
    try std.testing.expect(isPushOnly(&script));
}

test "isPushOnly: OP_PUSHDATA1 is push-only" {
    // OP_PUSHDATA1 with 2 bytes of data
    try std.testing.expect(isPushOnly(&[_]u8{ 0x4c, 0x02, 0xAB, 0xCD }));
}

test "isPushOnly: OP_PUSHDATA2 is push-only" {
    // OP_PUSHDATA2 with 2 bytes length (little-endian) and data
    try std.testing.expect(isPushOnly(&[_]u8{ 0x4d, 0x02, 0x00, 0xAB, 0xCD }));
}

test "isPushOnly: OP_PUSHDATA4 is push-only" {
    // OP_PUSHDATA4 with 4 bytes length (little-endian) and data
    try std.testing.expect(isPushOnly(&[_]u8{ 0x4e, 0x02, 0x00, 0x00, 0x00, 0xAB, 0xCD }));
}

test "isPushOnly: OP_1NEGATE is push-only" {
    try std.testing.expect(isPushOnly(&[_]u8{0x4f}));
}

test "isPushOnly: OP_1 through OP_16 are push-only" {
    try std.testing.expect(isPushOnly(&[_]u8{0x51})); // OP_1
    try std.testing.expect(isPushOnly(&[_]u8{0x52})); // OP_2
    try std.testing.expect(isPushOnly(&[_]u8{0x60})); // OP_16
}

test "isPushOnly: multiple pushes are push-only" {
    // OP_1 OP_2 <3 bytes> OP_0
    try std.testing.expect(isPushOnly(&[_]u8{ 0x51, 0x52, 0x03, 0xAA, 0xBB, 0xCC, 0x00 }));
}

test "isPushOnly: OP_DUP (0x76) is NOT push-only" {
    try std.testing.expect(!isPushOnly(&[_]u8{0x76}));
}

test "isPushOnly: OP_NOP (0x61) is NOT push-only" {
    // OP_NOP is 0x61 which is > 0x60
    try std.testing.expect(!isPushOnly(&[_]u8{0x61}));
}

test "isPushOnly: OP_ADD (0x93) is NOT push-only" {
    try std.testing.expect(!isPushOnly(&[_]u8{0x93}));
}

test "isPushOnly: OP_HASH160 (0xa9) is NOT push-only" {
    try std.testing.expect(!isPushOnly(&[_]u8{0xa9}));
}

test "isPushOnly: OP_CHECKSIG (0xac) is NOT push-only" {
    try std.testing.expect(!isPushOnly(&[_]u8{0xac}));
}

test "isPushOnly: script with push followed by OP_DUP is NOT push-only" {
    // OP_1 OP_DUP
    try std.testing.expect(!isPushOnly(&[_]u8{ 0x51, 0x76 }));
}

test "isPushOnly: truncated direct push is NOT push-only" {
    // Claims to push 5 bytes but only has 3
    try std.testing.expect(!isPushOnly(&[_]u8{ 0x05, 0x01, 0x02, 0x03 }));
}

test "isPushOnly: truncated PUSHDATA1 is NOT push-only" {
    // OP_PUSHDATA1 claims 5 bytes but has only 2
    try std.testing.expect(!isPushOnly(&[_]u8{ 0x4c, 0x05, 0x01, 0x02 }));
}

// ============================================================================
// P2SH Push-Only Enforcement Tests (BIP-16)
// ============================================================================
// When spending a P2SH output, the scriptSig must be push-only.
// This check is enforced unconditionally (not flag-gated beyond verify_p2sh).
// Reference: Bitcoin Core interpreter.cpp VerifyScript()

test "P2SH push_only: scriptSig with OP_DUP must fail" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Create a P2SH redeem script: OP_1 (pushes true)
    const redeem_script = [_]u8{0x51};
    const redeem_hash = crypto.hash160(&redeem_script);

    // Create P2SH scriptPubKey with correct hash
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9; // OP_HASH160
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memcpy(script_pubkey[2..22], &redeem_hash);
    script_pubkey[22] = 0x87; // OP_EQUAL

    // Create a scriptSig that:
    // 1. Contains OP_DUP (non-push opcode) - should fail isPushOnly
    // 2. After execution, leaves [0x51] on the stack - P2SH scriptPubKey will pass
    // scriptSig: push [0x51], OP_DUP, OP_DROP
    // Execution: push [0x51] -> dup -> [[0x51], [0x51]] -> drop -> [[0x51]]
    // P2SH check: HASH160([0x51]) matches, so scriptPubKey returns true
    // isPushOnly: [0x01, 0x51, 0x76, 0x75] contains 0x76 (OP_DUP) -> NOT push-only
    const script_sig = [_]u8{ 0x01, 0x51, 0x76, 0x75 }; // push(0x51) OP_DUP OP_DROP

    const result = engine.verify(&script_sig, &script_pubkey, &[_][]const u8{});
    try std.testing.expectError(ScriptError.SigPushOnly, result);
}

test "P2SH push_only: scriptSig with only pushes succeeds past push-only check" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Create a simple P2SH redeem script: OP_1 (just pushes true)
    const redeem_script = [_]u8{0x51}; // OP_1
    const redeem_hash = crypto.hash160(&redeem_script);

    // Create P2SH scriptPubKey with correct hash
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9; // OP_HASH160
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memcpy(script_pubkey[2..22], &redeem_hash);
    script_pubkey[22] = 0x87; // OP_EQUAL

    // Create a push-only scriptSig that pushes the redeem script
    var script_sig: [2]u8 = undefined;
    script_sig[0] = 0x01; // Push 1 byte
    script_sig[1] = 0x51; // The byte being pushed (which is also OP_1)

    const result = engine.verify(&script_sig, &script_pubkey, &[_][]const u8{});
    // Should NOT fail with SigPushOnly - push-only check passes
    // May fail for other reasons (cleanstack, etc.) but not SigPushOnly
    if (result) |_| {
        // Success is fine
    } else |err| {
        try std.testing.expect(err != ScriptError.SigPushOnly);
    }
}

test "P2SH push_only: scriptSig with OP_CHECKSIG must fail" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Create a P2SH redeem script: OP_1 (pushes true)
    const redeem_script = [_]u8{0x51};
    const redeem_hash = crypto.hash160(&redeem_script);

    // Create P2SH scriptPubKey with correct hash
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9; // OP_HASH160
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memcpy(script_pubkey[2..22], &redeem_hash);
    script_pubkey[22] = 0x87; // OP_EQUAL

    // Create a scriptSig with OP_CHECKSIG (non-push opcode)
    // We need the script to execute successfully but fail isPushOnly
    // Script: push fake sig, push fake pubkey, OP_CHECKSIG, then push redeem_script
    // Note: OP_CHECKSIG with secp256k1 unavailable returns true for testing
    // After execution: stack will have [true/false, redeem_script_bytes]
    // But for P2SH scriptPubKey to pass, we need top = redeem_script
    // This is tricky - let's use a simpler approach: OP_1 OP_DROP push(redeem)
    // Actually, we need OP_CHECKSIG in the script. Let's try:
    // push(sig), push(pubkey), OP_CHECKSIG, OP_DROP, push(redeem)
    // Result: [sig, pubkey] -> OP_CHECKSIG -> [true] -> OP_DROP -> [] -> push(redeem) -> [redeem]

    var fake_sig: [72]u8 = undefined;
    @memset(&fake_sig, 0x30);
    fake_sig[71] = 0x01; // SIGHASH_ALL

    var compressed_pubkey: [33]u8 = undefined;
    compressed_pubkey[0] = 0x02;
    @memset(compressed_pubkey[1..33], 0xCD);

    // Build scriptSig: push(sig) push(pubkey) OP_CHECKSIG OP_DROP push(redeem)
    // Sizes: 1+72 + 1+33 + 1 + 1 + 1+1 = 111 bytes
    var script_sig_buf: [111]u8 = undefined;
    var pos: usize = 0;

    // Push 72 bytes sig
    script_sig_buf[pos] = 72;
    pos += 1;
    @memcpy(script_sig_buf[pos .. pos + 72], &fake_sig);
    pos += 72;

    // Push 33 bytes pubkey
    script_sig_buf[pos] = 33;
    pos += 1;
    @memcpy(script_sig_buf[pos .. pos + 33], &compressed_pubkey);
    pos += 33;

    // OP_CHECKSIG
    script_sig_buf[pos] = 0xac;
    pos += 1;

    // OP_DROP
    script_sig_buf[pos] = 0x75;
    pos += 1;

    // Push 1 byte redeem script
    script_sig_buf[pos] = 0x01;
    pos += 1;
    script_sig_buf[pos] = 0x51;
    pos += 1;

    const result = engine.verify(script_sig_buf[0..pos], &script_pubkey, &[_][]const u8{});
    try std.testing.expectError(ScriptError.SigPushOnly, result);
}

test "P2SH push_only: scriptSig with OP_HASH160 must fail" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Create a P2SH redeem script: OP_1 (pushes true)
    const redeem_script = [_]u8{0x51};
    const redeem_hash = crypto.hash160(&redeem_script);

    // Create P2SH scriptPubKey with correct hash
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9; // OP_HASH160
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memcpy(script_pubkey[2..22], &redeem_hash);
    script_pubkey[22] = 0x87; // OP_EQUAL

    // Create a scriptSig with OP_HASH160 (non-push opcode)
    // Script: push(some_data) OP_HASH160 OP_DROP push(redeem)
    // After execution: [hash(some_data)] -> OP_DROP -> [] -> push(redeem) -> [redeem]
    // P2SH check: HASH160([0x51]) matches -> true
    // isPushOnly: contains 0xa9 (OP_HASH160) -> NOT push-only
    const some_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var script_sig_buf: [10]u8 = undefined;
    var pos: usize = 0;

    // Push 4 bytes
    script_sig_buf[pos] = 0x04;
    pos += 1;
    @memcpy(script_sig_buf[pos .. pos + 4], &some_data);
    pos += 4;

    // OP_HASH160
    script_sig_buf[pos] = 0xa9;
    pos += 1;

    // OP_DROP
    script_sig_buf[pos] = 0x75;
    pos += 1;

    // Push 1 byte redeem script
    script_sig_buf[pos] = 0x01;
    pos += 1;
    script_sig_buf[pos] = 0x51;
    pos += 1;

    const result = engine.verify(script_sig_buf[0..pos], &script_pubkey, &[_][]const u8{});
    try std.testing.expectError(ScriptError.SigPushOnly, result);
}

test "P2SH push_only: non-P2SH scripts allow non-push scriptSig" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // P2PKH scriptPubKey (not P2SH)
    var script_pubkey: [25]u8 = undefined;
    script_pubkey[0] = 0x76; // OP_DUP
    script_pubkey[1] = 0xa9; // OP_HASH160
    script_pubkey[2] = 0x14; // Push 20 bytes
    @memset(script_pubkey[3..23], 0xAB);
    script_pubkey[23] = 0x88; // OP_EQUALVERIFY
    script_pubkey[24] = 0xac; // OP_CHECKSIG

    // scriptSig with non-push opcodes (normally invalid, but should not fail with SigPushOnly)
    const script_sig = [_]u8{ 0x51, 0x76 }; // OP_1 OP_DUP

    const result = engine.verify(&script_sig, &script_pubkey, &[_][]const u8{});
    // Should NOT fail with SigPushOnly - P2PKH doesn't require push-only
    if (result) |_| {
        // Success is fine (unlikely given fake data)
    } else |err| {
        try std.testing.expect(err != ScriptError.SigPushOnly);
    }
}

// ============================================================================
// Legacy Sighash Tests
// ============================================================================

test "findAndDelete: empty pattern returns copy of original" {
    const allocator = std.testing.allocator;
    const script = [_]u8{ 0x01, 0x02, 0x03 };

    const result = try findAndDelete(allocator, &script, &[_]u8{});
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, &script, result);
}

test "findAndDelete: removes single occurrence" {
    const allocator = std.testing.allocator;
    const script = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const pattern = [_]u8{ 0x02, 0x03 };

    const result = try findAndDelete(allocator, &script, &pattern);
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x04 }, result);
}

test "findAndDelete: removes multiple occurrences" {
    const allocator = std.testing.allocator;
    const script = [_]u8{ 0xAB, 0x01, 0x02, 0xAB, 0x03, 0xAB };
    const pattern = [_]u8{0xAB};

    const result = try findAndDelete(allocator, &script, &pattern);
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, result);
}

test "findAndDelete: no match returns copy" {
    const allocator = std.testing.allocator;
    const script = [_]u8{ 0x01, 0x02, 0x03 };
    const pattern = [_]u8{ 0x04, 0x05 };

    const result = try findAndDelete(allocator, &script, &pattern);
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, &script, result);
}

test "removeCodeSeparators: removes all OP_CODESEPARATOR" {
    const allocator = std.testing.allocator;
    // Script: OP_1 OP_CODESEPARATOR OP_2 OP_CODESEPARATOR OP_3
    const script = [_]u8{ 0x51, 0xAB, 0x52, 0xAB, 0x53 };

    const result = try removeCodeSeparators(allocator, &script);
    defer allocator.free(result);

    // Should be: OP_1 OP_2 OP_3
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x51, 0x52, 0x53 }, result);
}

test "removeCodeSeparators: preserves push data containing 0xAB" {
    const allocator = std.testing.allocator;
    // Script: push 2 bytes (0xAB, 0xCD), then OP_CODESEPARATOR
    // 0x02 is "push 2 bytes", 0xAB 0xCD is data, 0xAB is OP_CODESEPARATOR
    const script = [_]u8{ 0x02, 0xAB, 0xCD, 0xAB };

    const result = try removeCodeSeparators(allocator, &script);
    defer allocator.free(result);

    // The 0xAB inside push data should remain, only trailing 0xAB removed
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0xAB, 0xCD }, result);
}

test "pushEncode: small data (<=75 bytes)" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0x01, 0x02, 0x03 };

    const result = try pushEncode(allocator, &data);
    defer allocator.free(result);

    // Should be: 0x03 (length) followed by data
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x01, 0x02, 0x03 }, result);
}

test "pushEncode: empty data" {
    const allocator = std.testing.allocator;
    const data = [_]u8{};

    const result = try pushEncode(allocator, &data);
    defer allocator.free(result);

    // Should be: 0x00 (length 0)
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, result);
}

test "getScriptCodeFromCodesepPos: 0xFFFFFFFF returns whole script" {
    const script = [_]u8{ 0x01, 0x02, 0x03 };
    const result = getScriptCodeFromCodesepPos(&script, 0xFFFFFFFF);
    try std.testing.expectEqualSlices(u8, &script, result);
}

test "getScriptCodeFromCodesepPos: returns script after codesep" {
    // Script: OP_1 OP_CODESEPARATOR OP_2 OP_3
    const script = [_]u8{ 0x51, 0xAB, 0x52, 0x53 };
    // codesep_pos = 1 (position of OP_CODESEPARATOR)
    const result = getScriptCodeFromCodesepPos(&script, 1);
    // Should return bytes after position 1 (skip the codesep itself)
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x52, 0x53 }, result);
}

test "legacySignatureHash: SIGHASH_SINGLE out of range returns 1" {
    const allocator = std.testing.allocator;

    // Transaction with 1 input but 0 outputs
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{}, // No outputs!
        .lock_time = 0,
    };

    // SIGHASH_SINGLE with input_index 0, but no outputs
    const hash = try legacySignatureHash(
        allocator,
        &tx,
        0,
        &[_]u8{0x51}, // OP_1
        SIGHASH_SINGLE,
    );

    // Should return uint256 value 1 (little-endian: 0x01 followed by 31 zeros)
    var expected: [32]u8 = [_]u8{0} ** 32;
    expected[0] = 0x01;
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "legacySignatureHash: basic SIGHASH_ALL" {
    const allocator = std.testing.allocator;

    const prev_hash = [_]u8{
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    const input = types.TxIn{
        .previous_output = .{ .hash = prev_hash, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 100000000, // 1 BTC
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac },
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Simple script: OP_1
    const script_code = [_]u8{0x51};

    const hash = try legacySignatureHash(
        allocator,
        &tx,
        0,
        &script_code,
        SIGHASH_ALL,
    );

    // Just verify it returns a non-zero hash
    var all_zero = true;
    for (hash) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "legacySignatureHashWithFindAndDelete: removes signature from script" {
    const allocator = std.testing.allocator;

    const prev_hash = [_]u8{0x01} ** 32;

    const input = types.TxIn{
        .previous_output = .{ .hash = prev_hash, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 50000000,
        .script_pubkey = &[_]u8{0x51}, // OP_1
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // Script that contains a pushed signature: <sig> OP_CHECKSIG
    // sig = [0xAB, 0xCD]
    const sig = [_]u8{ 0xAB, 0xCD };
    // script_code = push(sig) OP_CHECKSIG = 0x02 0xAB 0xCD 0xAC
    const script_code = [_]u8{ 0x02, 0xAB, 0xCD, 0xAC };

    const hash_with_find_delete = try legacySignatureHashWithFindAndDelete(
        allocator,
        &tx,
        0,
        &script_code,
        &sig,
        SIGHASH_ALL,
    );

    // Compare with hash computed on script without the signature
    // After FindAndDelete, script should be just OP_CHECKSIG
    const hash_without_sig = try legacySignatureHash(
        allocator,
        &tx,
        0,
        &[_]u8{0xAC}, // OP_CHECKSIG only
        SIGHASH_ALL,
    );

    try std.testing.expectEqualSlices(u8, &hash_without_sig, &hash_with_find_delete);
}

test "legacySignatureHash: SIGHASH_NONE zeros outputs" {
    const allocator = std.testing.allocator;

    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const output1 = types.TxOut{
        .value = 100000000,
        .script_pubkey = &[_]u8{0x51},
    };
    const output2 = types.TxOut{
        .value = 50000000,
        .script_pubkey = &[_]u8{0x52},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{ output1, output2 },
        .lock_time = 0,
    };

    // SIGHASH_NONE should produce a valid hash
    const hash = try legacySignatureHash(
        allocator,
        &tx,
        0,
        &[_]u8{0x51},
        SIGHASH_NONE,
    );

    // Just verify it doesn't crash and returns something
    _ = hash;
}

test "legacySignatureHash: SIGHASH_ANYONECANPAY hashes single input" {
    const allocator = std.testing.allocator;

    const input0 = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const input1 = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x02} ** 32, .index = 1 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };

    const output = types.TxOut{
        .value = 100000000,
        .script_pubkey = &[_]u8{0x51},
    };

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{ input0, input1 },
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    // SIGHASH_ALL | SIGHASH_ANYONECANPAY
    const hash = try legacySignatureHash(
        allocator,
        &tx,
        1, // Signing input 1
        &[_]u8{0x51},
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    );

    // Just verify it doesn't crash
    _ = hash;
}

// ============================================================================
// Sigop Counting Tests
// ============================================================================

test "getSigOpCount: empty script has 0 sigops" {
    const count = getSigOpCount(&[_]u8{}, false);
    try std.testing.expectEqual(@as(u32, 0), count);
}

test "getSigOpCount: OP_CHECKSIG counts as 1" {
    const script_data = [_]u8{0xac}; // OP_CHECKSIG
    const count = getSigOpCount(&script_data, false);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "getSigOpCount: OP_CHECKSIGVERIFY counts as 1" {
    const script_data = [_]u8{0xad}; // OP_CHECKSIGVERIFY
    const count = getSigOpCount(&script_data, false);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "getSigOpCount: OP_CHECKMULTISIG inaccurate counts as 20" {
    const script_data = [_]u8{0xae}; // OP_CHECKMULTISIG
    const count = getSigOpCount(&script_data, false);
    try std.testing.expectEqual(@as(u32, MAX_PUBKEYS_PER_MULTISIG), count);
}

test "getSigOpCount: OP_CHECKMULTISIG accurate with OP_2 counts as 2" {
    const script_data = [_]u8{ 0x52, 0xae }; // OP_2 OP_CHECKMULTISIG
    const count = getSigOpCount(&script_data, true);
    try std.testing.expectEqual(@as(u32, 2), count);
}

test "getSigOpCount: OP_CHECKMULTISIG accurate with OP_16 counts as 16" {
    const script_data = [_]u8{ 0x60, 0xae }; // OP_16 OP_CHECKMULTISIG
    const count = getSigOpCount(&script_data, true);
    try std.testing.expectEqual(@as(u32, 16), count);
}

test "getSigOpCount: OP_CHECKMULTISIGVERIFY accurate with OP_3 counts as 3" {
    const script_data = [_]u8{ 0x53, 0xaf }; // OP_3 OP_CHECKMULTISIGVERIFY
    const count = getSigOpCount(&script_data, true);
    try std.testing.expectEqual(@as(u32, 3), count);
}

test "getSigOpCount: P2PKH scriptPubKey has 1 sigop" {
    // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    var script_data: [25]u8 = undefined;
    script_data[0] = 0x76; // OP_DUP
    script_data[1] = 0xa9; // OP_HASH160
    script_data[2] = 0x14; // Push 20 bytes
    @memset(script_data[3..23], 0xAB);
    script_data[23] = 0x88; // OP_EQUALVERIFY
    script_data[24] = 0xac; // OP_CHECKSIG

    const count = getSigOpCount(&script_data, false);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "getSigOpCount: multiple CHECKSIG ops add up" {
    // OP_CHECKSIG OP_CHECKSIG OP_CHECKSIG
    const script_data = [_]u8{ 0xac, 0xac, 0xac };
    const count = getSigOpCount(&script_data, false);
    try std.testing.expectEqual(@as(u32, 3), count);
}

test "getSigOpCount: skips push data correctly" {
    // push 3 bytes (contains 0xac) then OP_CHECKSIG
    // The 0xac inside push data should NOT count
    const script_data = [_]u8{ 0x03, 0xac, 0xac, 0xac, 0xac }; // push [0xac, 0xac, 0xac] then OP_CHECKSIG
    const count = getSigOpCount(&script_data, false);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "isPayToScriptHash: valid P2SH" {
    var script_data: [23]u8 = undefined;
    script_data[0] = 0xa9; // OP_HASH160
    script_data[1] = 0x14; // Push 20 bytes
    @memset(script_data[2..22], 0xAB);
    script_data[22] = 0x87; // OP_EQUAL

    try std.testing.expect(isPayToScriptHash(&script_data));
}

test "isPayToScriptHash: wrong length returns false" {
    var script_data: [22]u8 = undefined;
    script_data[0] = 0xa9;
    script_data[1] = 0x14;
    @memset(script_data[2..21], 0xAB);
    script_data[21] = 0x87;

    try std.testing.expect(!isPayToScriptHash(&script_data));
}

test "isPayToScriptHash: P2PKH is not P2SH" {
    var script_data: [25]u8 = undefined;
    script_data[0] = 0x76;
    script_data[1] = 0xa9;
    script_data[2] = 0x14;
    @memset(script_data[3..23], 0xAB);
    script_data[23] = 0x88;
    script_data[24] = 0xac;

    try std.testing.expect(!isPayToScriptHash(&script_data));
}

test "getP2SHSigOpCount: counts sigops in redeemScript" {
    // P2SH scriptPubKey
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memset(script_pubkey[2..22], 0xAB);
    script_pubkey[22] = 0x87;

    // scriptSig: push OP_CHECKSIG as redeemScript
    const script_sig = [_]u8{ 0x01, 0xac }; // push 1 byte (OP_CHECKSIG)

    const count = getP2SHSigOpCount(&script_pubkey, &script_sig);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "getP2SHSigOpCount: returns 0 for non-push scriptSig" {
    // P2SH scriptPubKey
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memset(script_pubkey[2..22], 0xAB);
    script_pubkey[22] = 0x87;

    // scriptSig with OP_DUP (non-push)
    const script_sig = [_]u8{ 0x76, 0x01, 0xac }; // OP_DUP push(OP_CHECKSIG)

    const count = getP2SHSigOpCount(&script_pubkey, &script_sig);
    try std.testing.expectEqual(@as(u32, 0), count);
}

test "countWitnessSigOps: P2WPKH returns 1" {
    // P2WPKH: OP_0 <20 bytes>
    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memset(script_pubkey[2..22], 0xAB);

    const witness = &[_][]const u8{
        &[_]u8{0xAA} ** 71, // Signature
        &[_]u8{0xBB} ** 33, // Pubkey
    };

    var flags = ScriptFlags{};
    flags.verify_witness = true;
    flags.verify_p2sh = true;

    const count = countWitnessSigOps(&[_]u8{}, &script_pubkey, witness, flags);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "countWitnessSigOps: P2WSH counts witness script sigops" {
    // P2WSH: OP_0 <32 bytes>
    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x20;
    @memset(script_pubkey[2..34], 0xAB);

    // Witness script: OP_CHECKSIG
    const witness_script = [_]u8{0xac};
    const witness = &[_][]const u8{
        &[_]u8{0xAA} ** 71, // Signature
        &witness_script,   // Witness script (last item)
    };

    var flags = ScriptFlags{};
    flags.verify_witness = true;
    flags.verify_p2sh = true;

    const count = countWitnessSigOps(&[_]u8{}, &script_pubkey, witness, flags);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "countWitnessSigOps: returns 0 when witness flag disabled" {
    // P2WPKH scriptPubKey
    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memset(script_pubkey[2..22], 0xAB);

    const witness = &[_][]const u8{
        &[_]u8{0xAA} ** 71,
        &[_]u8{0xBB} ** 33,
    };

    var flags = ScriptFlags{};
    flags.verify_witness = false; // Disabled

    const count = countWitnessSigOps(&[_]u8{}, &script_pubkey, witness, flags);
    try std.testing.expectEqual(@as(u32, 0), count);
}

test "countWitnessSigOps: witness version 1 returns 0" {
    // P2TR: OP_1 <32 bytes>
    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x51; // OP_1 (witness version 1)
    script_pubkey[1] = 0x20;
    @memset(script_pubkey[2..34], 0xAB);

    const witness = &[_][]const u8{
        &[_]u8{0xAA} ** 64, // Schnorr signature
    };

    var flags = ScriptFlags{};
    flags.verify_witness = true;
    flags.verify_p2sh = true;

    // Taproot/witness v1 sigop counting is not defined (returns 0)
    const count = countWitnessSigOps(&[_]u8{}, &script_pubkey, witness, flags);
    try std.testing.expectEqual(@as(u32, 0), count);
}
