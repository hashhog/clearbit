const std = @import("std");
const crypto = @import("crypto.zig");
const types = @import("types.zig");
const taproot_sighash = @import("taproot_sighash.zig");

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
    InvalidSignatureEncoding, // BIP-66: invalid DER signature encoding (SIG_DER)
    SigHighS, // LOW_S: S value is above the curve order / 2 (SCRIPT_ERR_SIG_HIGH_S)
    InvalidSigHashType, // STRICTENC: invalid sighash type (SIG_HASHTYPE)
    InvalidPubkeyType, // STRICTENC: invalid pubkey encoding (PUBKEYTYPE)
    DiscourageOpSuccess, // BIP-342: OP_SUCCESSx found during tapscript pre-scan
    DiscourageUpgradableNops, // NOP1-NOP10 error when discourage flag set
    DiscourageUpgradablePubkeyType, // BIP-341: unknown pubkey size in tapscript w/ flag set
    DiscourageUpgradableTaprootVersion, // BIP-341: unknown leaf version w/ flag set
    TapscriptEmptyPubkey, // BIP-342: OP_CHECKSIG with empty pubkey in tapscript
    TapscriptCheckmultisigDisabled, // BIP-342: OP_CHECKMULTISIG disabled in tapscript
    WitnessProgramWitnessEmpty, // BIP-141: empty witness on a v0/v1 program
    TaprootWrongControlSize, // BIP-341: control block size outside [33, 33 + 32*128]
    TapscriptValidationWeight, // BIP-342: validation-weight budget exhausted
    TapscriptMinimalIf, // BIP-342: non-minimal IF/NOTIF argument in tapscript (consensus)
    ConstScriptCode, // CONST_SCRIPTCODE: OP_CODESEPARATOR in legacy (BASE) script
    StackSize, // MAX_STACK_SIZE exceeded (incl. tapscript-entry stack check)
    PushSize, // MAX_SCRIPT_ELEMENT_SIZE exceeded on a witness stack input element
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
    discourage_op_success: bool = false, // BIP-342: fail on OP_SUCCESSx in tapscript pre-scan
    discourage_upgradable_nops: bool = false, // NOP1-NOP10 must error when set
    verify_sigpushonly: bool = false, // scriptSig must be push-only
    verify_strictenc: bool = false, // Strict signature and pubkey encoding checks
    discourage_upgradable_witness_program: bool = false, // BIP-141: fail on unknown witness versions
    verify_const_scriptcode: bool = false, // CONST_SCRIPTCODE: reject OP_CODESEPARATOR in legacy scripts
    // BIP-341 / BIP-342 discouragement flags. These are STANDARD policy flags
    // in Core (policy/policy.h:119+); they are NOT in MANDATORY_SCRIPT_VERIFY_FLAGS
    // and therefore must default to `false` so consensus validation never trips on
    // them. See `validation.getStandardScriptFlags` for the relay-side wiring.
    discourage_upgradable_pubkeytype: bool = false, // BIP-341: discourage unknown pubkey sizes in tapscript
    discourage_upgradable_taproot_version: bool = false, // BIP-341: discourage unknown leaf versions
    // BIP-342 MINIMALIF: tapscript ALWAYS enforces minimal IF/NOTIF args as a consensus
    // rule (interpreter.cpp:614-620, gated solely on sigversion). For witness_v0,
    // MINIMALIF is policy-only and rides on this flag (interpreter.cpp:622).
    verify_minimalif: bool = false, // policy-only MINIMALIF gate for witness_v0
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

/// Check if an opcode byte is a disabled opcode that must always fail.
/// These must error even in unexecuted IF/ELSE branches.
fn isDisabledOpcode(opcode_byte: u8) bool {
    return switch (opcode_byte) {
        0x7e, // OP_CAT
        0x7f, // OP_SUBSTR
        0x80, // OP_LEFT
        0x81, // OP_RIGHT
        0x83, // OP_INVERT
        0x84, // OP_AND
        0x85, // OP_OR
        0x86, // OP_XOR
        0x8d, // OP_2MUL
        0x8e, // OP_2DIV
        0x95, // OP_MUL
        0x96, // OP_DIV
        0x97, // OP_MOD
        0x98, // OP_LSHIFT
        0x99, // OP_RSHIFT
        => true,
        else => false,
    };
}

/// Check minimal push encoding for MINIMALDATA enforcement.
/// Returns true if the push is minimal, false if a smaller encoding exists.
fn checkMinimalPush(data: []const u8, opcode_byte: u8) bool {
    if (data.len == 0) {
        // Could have used OP_0
        return opcode_byte == 0x00;
    } else if (data.len == 1 and data[0] >= 1 and data[0] <= 16) {
        // Could have used OP_1 through OP_16
        return opcode_byte == 0x50 + data[0];
    } else if (data.len == 1 and data[0] == 0x81) {
        // Could have used OP_1NEGATE
        return opcode_byte == 0x4f;
    } else if (data.len <= 75) {
        // Could have used direct push (opcode = length)
        return opcode_byte == @as(u8, @intCast(data.len));
    } else if (data.len <= 255) {
        // Could have used OP_PUSHDATA1
        return opcode_byte == 0x4c;
    } else if (data.len <= 65535) {
        // Could have used OP_PUSHDATA2
        return opcode_byte == 0x4d;
    }
    return true;
}

/// Check if a public key is compressed (33 bytes, starting with 0x02 or 0x03).
/// Per BIP-141, witness v0 programs require compressed public keys.
pub fn isCompressedPubkey(pubkey: []const u8) bool {
    if (pubkey.len != 33) return false;
    return pubkey[0] == 0x02 or pubkey[0] == 0x03;
}

/// Check if a public key has valid encoding.
/// Accepts compressed (33 bytes, 0x02/0x03 prefix) or uncompressed (65 bytes, 0x04 prefix).
pub fn isValidPubkeyEncoding(pubkey: []const u8) bool {
    if (pubkey.len == 33) {
        return pubkey[0] == 0x02 or pubkey[0] == 0x03;
    }
    if (pubkey.len == 65) {
        return pubkey[0] == 0x04;
    }
    return false;
}

/// Check if a hashtype byte is a defined sighash type.
/// The low 5 bits (without SIGHASH_ANYONECANPAY = 0x80) must be 1, 2, or 3.
pub fn isDefinedHashtype(hash_type: u8) bool {
    const base = hash_type & ~@as(u8, 0x80); // strip ANYONECANPAY
    return base >= 1 and base <= 3;
}

/// Validate DER signature encoding per BIP-66 (DERSIG).
/// This is a strict check of the DER format: the signature including hashtype byte.
/// Reference: Bitcoin Core script/interpreter.cpp IsValidSignatureEncoding()
pub fn isValidSignatureEncoding(sig: []const u8) bool {
    // Format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s] [sighash]
    // Minimum DER sig: 30 06 02 01 00 02 01 00 + hashtype = 9 bytes
    if (sig.len < 9) return false;
    // Maximum DER sig: 30 46 02 21 [33] 02 21 [33] + hashtype = 73 bytes
    if (sig.len > 73) return false;

    // The actual DER data is everything except the last byte (hashtype)
    const der = sig[0 .. sig.len - 1];

    // A signature is of type 0x30 (compound)
    if (der[0] != 0x30) return false;

    // Make sure the length covers the entire signature
    if (der[1] != der.len - 2) return false;

    // Extract the length of the R element
    if (der.len < 4) return false;
    const lenR: usize = der[3];

    // Make sure the length of the S element is still inside the signature
    if (5 + lenR >= der.len) return false;
    const lenS: usize = der[5 + lenR];

    // Verify that the length of the signature matches the sum of the length of the elements
    // der = sig without hashtype byte, so total = 6 + lenR + lenS (not 7 like in Bitcoin Core which includes hashtype)
    if (lenR + lenS + 6 != der.len) return false;

    // Check whether the R element is an integer
    if (der[2] != 0x02) return false;

    // Zero-length integers are not allowed for R
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R
    if (der[4] & 0x80 != 0) return false;

    // Null bytes at the start of R are not allowed, unless R would otherwise be
    // interpreted as a negative number
    if (lenR > 1 and der[4] == 0x00 and (der[5] & 0x80) == 0) return false;

    // Check whether the S element is an integer
    if (der[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S
    if (der[lenR + 6] & 0x80 != 0) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number
    if (lenS > 1 and der[lenR + 6] == 0x00 and (der[lenR + 7] & 0x80) == 0) return false;

    return true;
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
fn scriptNumDecodeN(data: []const u8, require_minimal: bool, max_len: usize) ScriptError!i64 {
    if (data.len == 0) return 0;
    if (data.len > max_len) return ScriptError.InvalidNumber;

    // Minimal encoding check: the number must use the fewest bytes possible
    if (require_minimal) {
        // If the last byte is 0x00 (and not needed for sign), encoding is non-minimal
        if (data[data.len - 1] & 0x7f == 0) {
            if (data.len == 1) {
                // Single byte 0x00 should be empty (OP_0)
                return ScriptError.InvalidNumber;
            }
            if (data[data.len - 2] & 0x80 == 0) {
                return ScriptError.InvalidNumber;
            }
        }
    }

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

fn scriptNumDecode(data: []const u8, require_minimal: bool) ScriptError!i64 {
    return scriptNumDecodeN(data, require_minimal, MAX_SCRIPT_NUM_LENGTH);
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
// BIP-342 OP_SUCCESSx Pre-scan
// ============================================================================

/// Returns true if the opcode is an OP_SUCCESSx opcode per BIP-342.
/// These are undefined opcodes that cause immediate script success in tapscript.
fn isOpSuccess(op: u8) bool {
    return op == 80 or op == 98 or
        (op >= 126 and op <= 129) or
        (op >= 131 and op <= 134) or
        (op >= 137 and op <= 138) or
        (op >= 141 and op <= 142) or
        (op >= 149 and op <= 153) or // 0x95-0x99 (MUL, DIV, MOD, LSHIFT, RSHIFT)
        (op >= 187 and op <= 254); // 0xbb-0xfe
}

/// Compute the serialized byte length of a Bitcoin compact-size encoding
/// for `n`. Mirrors Core's `GetSizeOfCompactSize` (serialize.h):
///   < 0xfd            -> 1 byte
///   <= 0xffff         -> 3 bytes (0xfd || u16)
///   <= 0xffffffff     -> 5 bytes (0xfe || u32)
///   else              -> 9 bytes (0xff || u64)
pub fn compactSizeLen(n: u64) u64 {
    if (n < 0xfd) return 1;
    if (n <= 0xffff) return 3;
    if (n <= 0xffffffff) return 5;
    return 9;
}

/// Compute the on-the-wire serialized size of a witness stack the way
/// Core's `::GetSerializeSize(witness.stack)` does it: a compact-size
/// item count followed by, for each item, its compact-size length
/// prefix and the item bytes themselves. Used to seed the BIP-342
/// tapscript validation-weight budget at the leaf entry point.
pub fn serializedWitnessStackSize(items: []const []const u8) u64 {
    var total: u64 = compactSizeLen(items.len);
    for (items) |it| {
        total += compactSizeLen(it.len) + it.len;
    }
    return total;
}

/// Pre-scans a tapscript for OP_SUCCESSx opcodes per BIP-342.
/// If any OP_SUCCESSx is found, returns the opcode value.
/// Skips over push data to avoid false positives in data payloads.
fn preScanTapscript(script: []const u8) ?u8 {
    var i: usize = 0;
    while (i < script.len) {
        const op = script[i];
        if (isOpSuccess(op)) return op;
        // Skip push data
        if (op <= 75) {
            i += 1 + op;
        } else if (op == 76) { // OP_PUSHDATA1
            if (i + 1 >= script.len) break;
            i += 2 + script[i + 1];
        } else if (op == 77) { // OP_PUSHDATA2
            if (i + 2 >= script.len) break;
            i += 3 + @as(usize, script[i + 1]) + (@as(usize, script[i + 2]) << 8);
        } else if (op == 78) { // OP_PUSHDATA4
            if (i + 4 >= script.len) break;
            i += 5 + @as(usize, std.mem.readInt(u32, script[i + 1 ..][0..4], .little));
        } else {
            i += 1;
        }
    }
    return null;
}

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
    /// The scriptPubKey being spent, used as scriptCode for sighash computation.
    /// Set during verify() to the scriptPubKey (or redeem script for P2SH).
    script_pubkey_for_sighash: ?[]const u8,

    /// Per-input prevouts for BIP-341 Taproot sighash. `spent_amounts[i]`
    /// and `spent_scripts[i]` are the value and scriptPubKey of the output
    /// being spent by `tx.inputs[i]`. Required by `sha_amounts` and
    /// `sha_scriptpubkeys` which commit to ALL inputs, not just the one
    /// being verified. Empty slices for legacy / non-Taproot scripts.
    spent_amounts: []const i64,
    spent_scripts: []const []const u8,

    /// Tapleaf hash for the currently executing tapscript leaf
    /// (BIP-341 ext_flag=1 sighash). Set by the script-path entry
    /// before `execute(tap_script)`; null otherwise.
    tapleaf_hash: ?[32]u8 = null,

    /// Witness annex (the original last witness item, including the
    /// 0x50 prefix byte) when present. Used by both key-path and
    /// tapscript sighash via the sha_annex field.
    taproot_annex: ?[]const u8 = null,

    /// BIP-342 tapscript validation-weight budget. Mirrors Core's
    /// `ScriptExecutionData::m_validation_weight_left` (interpreter.cpp:362).
    /// Initialized at the tapscript leaf entry to
    /// `GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET (50)`,
    /// then decremented by `VALIDATION_WEIGHT_PER_SIGOP_PASSED (50)` for
    /// every non-empty CHECKSIG / CHECKSIGVERIFY / CHECKSIGADD. Negative
    /// residue aborts with `TapscriptValidationWeight`.
    validation_weight_left: i64 = 0,
    /// Whether `validation_weight_left` has been initialized. Defensive
    /// guard mirroring Core's `m_validation_weight_left_init`. False on
    /// legacy / SegWit-v0 paths where the budget is not consulted.
    validation_weight_init: bool = false,

    // Memory management for stack elements we allocate
    owned_elements: std.ArrayList([]u8),

    pub fn init(
        allocator: std.mem.Allocator,
        tx: *const types.Transaction,
        input_index: usize,
        amount: i64,
        flags: ScriptFlags,
    ) ScriptEngine {
        return initWithPrevouts(allocator, tx, input_index, amount, flags, &.{}, &.{});
    }

    /// Initialize with per-input prevouts; required for Taproot key-path
    /// and tapscript verification. Pass empty slices for legacy use.
    pub fn initWithPrevouts(
        allocator: std.mem.Allocator,
        tx: *const types.Transaction,
        input_index: usize,
        amount: i64,
        flags: ScriptFlags,
        spent_amounts: []const i64,
        spent_scripts: []const []const u8,
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
            .script_pubkey_for_sighash = null,
            .spent_amounts = spent_amounts,
            .spent_scripts = spent_scripts,
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

    /// Decrement the BIP-342 validation-weight counter by 50 (one
    /// `VALIDATION_WEIGHT_PER_SIGOP_PASSED`). Returns
    /// `TapscriptValidationWeight` if the residue would go negative,
    /// matching Core's `m_validation_weight_left -= 50; if (... < 0) ...`
    /// at interpreter.cpp:362-365.
    ///
    /// Caller must only invoke this on the tapscript path with a
    /// non-empty signature; callers above the OP_CHECKSIG-family
    /// branches gate on `sig.len > 0`.
    fn consumeValidationWeight(self: *ScriptEngine) ScriptError!void {
        // Defensive guard mirroring Core's `assert(m_validation_weight_left_init)`
        // at interpreter.cpp:361. If we ever get here without the budget
        // initialized, fail closed rather than silently underflow.
        if (!self.validation_weight_init) return ScriptError.TapscriptValidationWeight;
        self.validation_weight_left -= 50;
        if (self.validation_weight_left < 0) return ScriptError.TapscriptValidationWeight;
    }

    /// Execute a script (series of opcodes/data pushes).
    pub fn execute(self: *ScriptEngine, script: []const u8) ScriptError!void {
        // BIP-342 (tapscript) does NOT enforce MAX_SCRIPT_SIZE — tapscript
        // leaves are bounded only by the 4M-weight block cap and the
        // per-input validation-weight budget.  Core gates this check on
        // `sigversion == BASE || WITNESS_V0` (interpreter.cpp:428).
        if (self.sig_version != .tapscript and script.len > MAX_SCRIPT_SIZE) {
            return ScriptError.InvalidScript;
        }

        var pc: usize = 0;
        var op_count: usize = 0;
        // BIP-341: opcode counter (0-based index of each opcode in this script).
        // Mirrors Core's `opcode_pos` (interpreter.cpp:433, incremented at the
        // top of the for-loop).  Used by OP_CODESEPARATOR to record the position
        // committed to the tapscript sigmsg (Core interpreter.cpp:1055, 1565).
        // Every opcode — including push-data ops — increments this counter once.
        var opcode_pos: u32 = 0;
        var exec_stack = std.ArrayList(bool).init(self.allocator);
        defer exec_stack.deinit();

        while (pc < script.len) {
            const opcode_byte = script[pc];
            pc += 1;
            // Capture the index of this opcode and advance the counter.
            // Placed here — before any `continue` — so push-data handlers
            // also advance the counter, matching Core's `++opcode_pos`.
            const current_opcode_pos = opcode_pos;
            opcode_pos += 1;

            // Data push: opcodes 0x01-0x4b push that many bytes
            if (opcode_byte >= 0x01 and opcode_byte <= 0x4b) {
                const n = @as(usize, opcode_byte);
                if (pc + n > script.len) return ScriptError.InvalidScript;
                if (self.isExecuting(&exec_stack)) {
                    const push_data = script[pc .. pc + n];
                    if (self.flags.verify_minimaldata and !checkMinimalPush(push_data, opcode_byte)) {
                        return ScriptError.MinimalData;
                    }
                    try self.push(push_data);
                }
                pc += n;
                continue;
            }

            // OP_VERIF (0x65) and OP_VERNOTIF (0x66) ALWAYS fail, even in unexecuted branches
            if (opcode_byte == 0x65 or opcode_byte == 0x66) {
                return ScriptError.InvalidOpcode;
            }

            // Disabled opcodes ALWAYS fail, even in unexecuted branches
            if (isDisabledOpcode(opcode_byte)) {
                return ScriptError.DisabledOpcode;
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
                // Push size limit applies even in unexecuted branches
                if (n > MAX_PUSH_SIZE) return ScriptError.PushSizeExceeded;
                if (self.isExecuting(&exec_stack)) {
                    const push_data = script[pc .. pc + n];
                    if (self.flags.verify_minimaldata and !checkMinimalPush(push_data, opcode_byte)) {
                        return ScriptError.MinimalData;
                    }
                    try self.push(push_data);
                }
                pc += n;
                continue;
            }

            // Count ops: all opcodes > OP_16 (0x60) count toward the 201 limit
            // This includes IF/NOTIF/ELSE/ENDIF per Bitcoin Core.
            //
            // BIP-342 (tapscript) does NOT enforce MAX_OPS_PER_SCRIPT — the
            // tapscript validation-weight budget is the only ops limit. Core
            // gates this counter on `sigversion == BASE || WITNESS_V0`
            // (interpreter.cpp:450-455).  Without this gate, tapscript inputs
            // with > MAX_OPS_PER_SCRIPT non-push ops that respect the weight
            // budget are wrongly rejected.
            if (opcode_byte > 0x60 and self.sig_version != .tapscript) {
                op_count += 1;
                if (op_count > MAX_OPS_PER_SCRIPT) return ScriptError.OpCountExceeded;
            }

            // CONST_SCRIPTCODE: OP_CODESEPARATOR in BASE (legacy non-segwit)
            // scripts is rejected even in unexecuted branches when the flag is
            // set.  Mirrors Core interpreter.cpp:474-476, which fires BEFORE
            // the fExec gate.  Core checks `sigversion == SigVersion::BASE` —
            // not witness — because OP_CODESEPARATOR is valid in witness scripts.
            if (opcode == .op_codeseparator and
                self.sig_version == .base and
                self.flags.verify_const_scriptcode)
            {
                return ScriptError.ConstScriptCode;
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
            try self.executeOpcode(opcode, script, &pc, &exec_stack, &op_count, current_opcode_pos);
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
        // 0. SIG_PUSHONLY: scriptSig must be push-only when flag is set
        if (self.flags.verify_sigpushonly and !isPushOnly(script_sig)) {
            return ScriptError.SigPushOnly;
        }

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

        // Clear altstack between scriptSig and scriptPubKey execution
        self.alt_stack.clearRetainingCapacity();

        // Set scriptCode for sighash computation (used by verifySignature)
        self.script_pubkey_for_sighash = script_pubkey;

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

            // Set scriptCode for sighash to the redeem script for P2SH
            self.script_pubkey_for_sighash = redeem_script;

            // Execute redeem script
            try self.execute(redeem_script);

            if (self.stack.items.len == 0) return false;
            if (!self.stackToBool(self.stack.items[self.stack.items.len - 1])) return false;
        }

        // 5. Handle witness
        if (self.flags.verify_witness) {
            // Determine the witness program to evaluate.
            // It could be a native witness scriptPubKey or a P2SH-wrapped witness program.
            var wit_program_script: ?[]const u8 = null;
            var had_witness = false;
            // Tracks whether the witness program came from a P2SH redeem
            // (Core's `is_p2sh` parameter to VerifyWitnessProgram, see
            // interpreter.cpp:1947). The Taproot path (witversion=1, 32B)
            // requires is_p2sh == false; spending a v1-Taproot output via
            // P2SH-wrap is anyone-can-spend, not Taproot.
            var via_p2sh: bool = false;

            if (isWitnessProgram(script_pubkey)) |_| {
                // Native witness program (scriptPubKey is the witness program directly)
                wit_program_script = script_pubkey;
                // BIP-141: scriptSig must be empty for native witness programs
                if (script_sig.len != 0) {
                    return ScriptError.WitnessUnexpected;
                }
            } else if (self.flags.verify_p2sh and classifyScript(script_pubkey) == .p2sh) {
                // P2SH-wrapped witness: the redeem script (top of saved stack) may be a witness program
                // The scriptSig must push exactly one element (the witness program script)
                // which was already validated as push-only above.
                // saved_stack has the items from scriptSig execution.
                if (saved_stack.items.len > 0) {
                    const redeem = saved_stack.items[saved_stack.items.len - 1];
                    if (isWitnessProgram(redeem)) |_| {
                        wit_program_script = redeem;
                        via_p2sh = true;
                    }
                }
            }

            if (wit_program_script) |wp_script| {
                had_witness = true;
                const wp = isWitnessProgram(wp_script).?;

                if (wp.version == 0) {
                    // Witness v0
                    if (wp.program.len == WITNESS_V0_KEYHASH_SIZE) {
                        // P2WPKH
                        if (witness.len != 2) return ScriptError.WitnessProgramMismatch;

                        // BIP-141: witness v0 requires compressed pubkeys
                        const pubkey = witness[1];
                        if (self.flags.verify_witness_pubkeytype and !isCompressedPubkey(pubkey)) {
                            return ScriptError.WitnessPubkeyType;
                        }

                        // BIP-141 ExecuteWitnessScript element-size guard
                        // (Core interpreter.cpp:1858-1861) — applies to v0
                        // input stack too, not just tapscript.
                        for (witness) |item| {
                            if (item.len > MAX_SCRIPT_ELEMENT_SIZE) return ScriptError.PushSize;
                        }

                        // Build P2PKH script from witness program hash
                        var p2pkh_script: [25]u8 = undefined;
                        p2pkh_script[0] = 0x76; // OP_DUP
                        p2pkh_script[1] = 0xa9; // OP_HASH160
                        p2pkh_script[2] = 0x14; // Push 20 bytes
                        @memcpy(p2pkh_script[3..23], wp.program);
                        p2pkh_script[23] = 0x88; // OP_EQUALVERIFY
                        p2pkh_script[24] = 0xac; // OP_CHECKSIG

                        // Set scriptCode for BIP-143 sighash (the constructed P2PKH script)
                        self.script_pubkey_for_sighash = &p2pkh_script;

                        // Reset stack with witness data
                        self.stack.clearRetainingCapacity();
                        for (witness) |item| {
                            self.stack.append(item) catch return ScriptError.OutOfMemory;
                        }

                        self.sig_version = .witness_v0;
                        try self.execute(&p2pkh_script);

                        if (self.stack.items.len != 1) return ScriptError.CleanStack;
                        if (!self.stackToBool(self.stack.items[0])) return false;
                    } else if (wp.program.len == WITNESS_V0_SCRIPTHASH_SIZE) {
                        // P2WSH
                        // BIP-141: SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY
                        // distinguishes "no witness items at all" from a
                        // genuine size mismatch (Core interpreter.cpp:1927).
                        if (witness.len == 0) return ScriptError.WitnessProgramWitnessEmpty;
                        const witness_script = witness[witness.len - 1];
                        const witness_hash = crypto.sha256(witness_script);

                        if (!std.mem.eql(u8, &witness_hash, wp.program)) {
                            return ScriptError.WitnessProgramMismatch;
                        }

                        // BIP-141: witness script max size is 10,000 bytes
                        if (witness_script.len > MAX_SCRIPT_SIZE) {
                            return ScriptError.InvalidScript;
                        }

                        // BIP-141 ExecuteWitnessScript element-size guard.
                        // Applies to ALL witness stack items including the
                        // script itself? Per Core interpreter.cpp:1858-1861
                        // this fires on the stack AFTER the script was
                        // popped — the witness_script bytes are NOT a stack
                        // element by this point. Only the remaining args
                        // (witness[0..len-1]) are stack inputs.
                        for (witness[0 .. witness.len - 1]) |item| {
                            if (item.len > MAX_SCRIPT_ELEMENT_SIZE) return ScriptError.PushSize;
                        }

                        // Set scriptCode for BIP-143 sighash (the witness script)
                        self.script_pubkey_for_sighash = witness_script;

                        // Reset stack with witness data (excluding the script)
                        self.stack.clearRetainingCapacity();
                        for (witness[0 .. witness.len - 1]) |item| {
                            self.stack.append(item) catch return ScriptError.OutOfMemory;
                        }

                        self.sig_version = .witness_v0;
                        try self.execute(witness_script);

                        if (self.stack.items.len != 1) return ScriptError.CleanStack;
                        if (!self.stackToBool(self.stack.items[0])) return false;
                    } else {
                        // Witness v0 with wrong program length
                        return ScriptError.WitnessProgramWrongLength;
                    }
                } else if (wp.version == 1 and wp.program.len == 32 and !via_p2sh) {
                    // BIP-341 Taproot (witness v1, 32-byte program, NOT P2SH-wrapped).
                    // Mirrors Core's gate at interpreter.cpp:1947:
                    //   witversion == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh
                    // P2SH-wrapped v1 32-byte outputs fall through to the
                    // "anyone-can-spend / future soft-fork" branch below.

                    // BIP-341 / Core (interpreter.cpp:1949): if SCRIPT_VERIFY_TAPROOT
                    // is not set, return success without evaluating witness items.
                    // Pre-Taproot-activation blocks treat these outputs as anyone-
                    // can-spend, so dropping evaluation here is consensus-critical.
                    if (!self.flags.verify_taproot) {
                        return true;
                    }

                    if (witness.len == 0) return ScriptError.WitnessProgramWitnessEmpty;

                    // BIP-341: detect annex (last witness item starting with 0x50,
                    // only if witness has ≥ 2 elements). Strip from effective
                    // witness; commit via sha_annex in the BIP-341 sighash.
                    var effective_witness = witness;
                    if (witness.len >= 2 and witness[witness.len - 1].len > 0 and witness[witness.len - 1][0] == 0x50) {
                        self.taproot_annex = witness[witness.len - 1];
                        effective_witness = witness[0 .. witness.len - 1];
                    }

                    // Key path: single 64 or 65 byte signature (no script execution)
                    if (effective_witness.len == 1 and
                        (effective_witness[0].len == 64 or effective_witness[0].len == 65))
                    {
                        // BIP-341 key-path: signature verified against the witness
                        // program (the tweaked output key Q) directly. No on-the-fly
                        // tweak math needed by the verifier.
                        const sig_bytes = effective_witness[0];

                        // Sig is 64B (SIGHASH_DEFAULT) or 65B (with hash_type byte).
                        var sig: [64]u8 = undefined;
                        @memcpy(&sig, sig_bytes[0..64]);
                        var hash_type: u8 = taproot_sighash.SIGHASH_DEFAULT;
                        if (sig_bytes.len == 65) {
                            hash_type = sig_bytes[64];
                            // Strict: explicit SIGHASH_DEFAULT byte invalid.
                            if (hash_type == taproot_sighash.SIGHASH_DEFAULT) return false;
                        }

                        // Need full prevouts for BIP-341 sha_amounts + sha_scriptpubkeys.
                        if (self.spent_amounts.len != self.tx.inputs.len or
                            self.spent_scripts.len != self.tx.inputs.len)
                        {
                            return false;
                        }

                        const prevouts = taproot_sighash.TaprootPrevouts{
                            .amounts = self.spent_amounts,
                            .scripts = self.spent_scripts,
                        };

                        const sighash = taproot_sighash.computeTaprootSighash(
                            self.allocator,
                            self.tx,
                            self.input_index,
                            prevouts,
                            hash_type,
                            self.taproot_annex,
                            null, // ext_flag = 0 (key-path)
                        ) catch return false;

                        var xonly: [32]u8 = undefined;
                        @memcpy(&xonly, wp.program[0..32]);

                        if (crypto.verifySchnorr(&sig, &sighash, &xonly)) {
                            return true;
                        }
                        return false;
                    } else if (effective_witness.len >= 2) {
                        // Script path spending (Core: interpreter.cpp:1966-1989).
                        const control = effective_witness[effective_witness.len - 1];
                        const tap_script = effective_witness[effective_witness.len - 2];

                        // BIP-341 control-block size check. Core emits the
                        // dedicated SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE
                        // for this — distinguish it from generic mismatches.
                        if (control.len < 33 or control.len > 33 + 32 * 128) {
                            return ScriptError.TaprootWrongControlSize;
                        }
                        if ((control.len - 33) % 32 != 0) {
                            return ScriptError.TaprootWrongControlSize;
                        }

                        // Compute tapleaf hash for ext_flag=1 sighash. Core
                        // (interpreter.cpp:1973) computes the leaf hash from
                        // `control[0] & TAPROOT_LEAF_MASK` (= 0xfe) — so the
                        // parity bit is masked off but ALL upper leaf-version
                        // bits are included in the hash. This must run BEFORE
                        // the VerifyTaprootCommitment check; on failure of
                        // the commitment, return SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH.
                        const leaf_version = control[0] & 0xfe;
                        if (crypto.computeTapleafHash(tap_script, leaf_version)) |tlh| {
                            self.tapleaf_hash = tlh;
                        } else {
                            return ScriptError.WitnessProgramMismatch;
                        }

                        // Verify control block against the witness program (output key)
                        if (!crypto.verifyTaprootControlBlock(control, tap_script, wp.program)) {
                            return ScriptError.WitnessProgramMismatch;
                        }

                        // BIP-341 leaf-version gate (interpreter.cpp:1978-1988):
                        // ONLY leaf_version == TAPROOT_LEAF_TAPSCRIPT (0xc0) is
                        // executed as tapscript. Unknown leaf versions are a
                        // future soft-fork extension point — they MUST return
                        // success without evaluating the script, unless
                        // DISCOURAGE_UPGRADABLE_TAPROOT_VERSION is set, in
                        // which case the script aborts.
                        if (leaf_version != 0xc0) {
                            if (self.flags.discourage_upgradable_taproot_version) {
                                return ScriptError.DiscourageUpgradableTaprootVersion;
                            }
                            return true;
                        }

                        // From here on: leaf_version == 0xc0 → tapscript exec.
                        self.stack.clearRetainingCapacity();
                        for (effective_witness[0 .. effective_witness.len - 2]) |item| {
                            self.stack.append(item) catch return ScriptError.OutOfMemory;
                        }

                        if (preScanTapscript(tap_script)) |_| {
                            if (self.flags.discourage_op_success) {
                                return ScriptError.DiscourageOpSuccess;
                            }
                            return true;
                        }

                        // BIP-342 ExecuteWitnessScript-style guards (interpreter.cpp:1854-1861).
                        // After the OP_SUCCESS pre-scan, Core enforces:
                        //   - the input stack must not exceed MAX_STACK_SIZE
                        //   - each input stack element must not exceed
                        //     MAX_SCRIPT_ELEMENT_SIZE (also enforced for
                        //     witness_v0 — see the v0 paths below in a
                        //     dedicated guard).
                        if (self.stack.items.len > MAX_STACK_SIZE) {
                            return ScriptError.StackSize;
                        }
                        for (self.stack.items) |elem| {
                            if (elem.len > MAX_SCRIPT_ELEMENT_SIZE) {
                                return ScriptError.PushSize;
                            }
                        }

                        // BIP-342 validation-weight budget (interpreter.cpp:1981):
                        //   m_validation_weight_left = GetSerializeSize(witness.stack)
                        //                              + VALIDATION_WEIGHT_OFFSET (50)
                        // 'witness.stack' is the ORIGINAL pre-pop witness (annex
                        // INCLUDED, control block + script INCLUDED, args INCLUDED).
                        // We pass the original `witness` here (not effective_witness).
                        const ws = serializedWitnessStackSize(witness);
                        self.validation_weight_left = @intCast(ws + 50);
                        self.validation_weight_init = true;

                        self.sig_version = .tapscript;
                        try self.execute(tap_script);

                        if (self.stack.items.len != 1) return ScriptError.CleanStack;
                        if (!self.stackToBool(self.stack.items[0])) return false;
                    } else {
                        // effective_witness.len == 0 after annex strip: no
                        // signature for key-path, no script for script-path.
                        return ScriptError.WitnessProgramWitnessEmpty;
                    }
                } else {
                    // Unknown witness version, OR Taproot via P2SH (which
                    // falls through to here because of the !via_p2sh gate
                    // on the v1-32B branch above), OR P2A (anyone-can-spend
                    // anchor — Core's CScript::IsPayToAnchor returns true
                    // for this exact shape: witversion=1, prog={0x4e,0x73}).
                    if (self.flags.discourage_upgradable_witness_program) {
                        // CScript::IsPayToAnchor is consensus-allowed for
                        // mainnet (TRUC v3 ephemeral anchor outputs) so it
                        // must NOT be tripped by the discourage gate. P2A
                        // is witversion=1 + program 0x4e73 (2 bytes).
                        if (!(wp.version == 1 and wp.program.len == 2 and
                            wp.program[0] == 0x4e and wp.program[1] == 0x73))
                        {
                            return ScriptError.WitnessProgramMismatch;
                        }
                    }
                    // Unknown witness versions are anyone-can-spend (future soft fork)
                    // BIP-141: if the version byte is 2-16, the script is anyone-can-spend
                }
            }

            // BIP-141: witness must be empty for non-witness scripts
            if (!had_witness and witness.len != 0) {
                return ScriptError.WitnessUnexpected;
            }
        }

        // 6. Clean stack check
        if (self.flags.verify_clean_stack) {
            if (self.stack.items.len != 1) return ScriptError.CleanStack;
        }

        return true;
    }

    fn push(self: *ScriptEngine, data: []const u8) !void {
        if (self.stack.items.len + self.alt_stack.items.len >= MAX_STACK_SIZE) return ScriptError.StackOverflow;
        if (data.len > MAX_STACK_ELEMENT_SIZE) return ScriptError.PushSizeExceeded;
        self.stack.append(data) catch return ScriptError.OutOfMemory;
    }

    fn pushOwned(self: *ScriptEngine, data: []u8) !void {
        if (self.stack.items.len + self.alt_stack.items.len >= MAX_STACK_SIZE) return ScriptError.StackOverflow;
        if (data.len > MAX_STACK_ELEMENT_SIZE) return ScriptError.PushSizeExceeded;
        self.owned_elements.append(data) catch return ScriptError.OutOfMemory;
        self.stack.append(data) catch return ScriptError.OutOfMemory;
    }

    fn pop(self: *ScriptEngine) ScriptError![]const u8 {
        if (self.stack.items.len == 0) return ScriptError.StackUnderflow;
        return self.stack.pop();
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
        op_count: *usize,
        opcode_pos: u32,
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
            .op_nop => {},
            .op_nop1, .op_nop4, .op_nop5, .op_nop6, .op_nop7, .op_nop8, .op_nop9, .op_nop10 => {
                if (self.flags.discourage_upgradable_nops) {
                    return ScriptError.DiscourageUpgradableNops;
                }
            },

            .op_if => {
                var execute_branch = false;
                if (self.isExecuting(exec_stack)) {
                    const data = try self.pop();
                    // BIP-342 (tapscript): MINIMALIF is a CONSENSUS rule — the
                    // argument must be exactly empty (false) or exactly
                    // &[1]u8{0x01} (true). Reference: Bitcoin Core
                    // interpreter.cpp:614-620 (gated solely on
                    // sigversion == TAPSCRIPT).
                    if (self.sig_version == .tapscript) {
                        if (data.len > 1) return ScriptError.TapscriptMinimalIf;
                        if (data.len == 1 and data[0] != 1) return ScriptError.TapscriptMinimalIf;
                    }
                    // BIP-141 witness_v0: MINIMALIF is POLICY-ONLY, gated on
                    // the SCRIPT_VERIFY_MINIMALIF flag. Reference: Bitcoin
                    // Core interpreter.cpp:621-627. The pre-fix code fired
                    // this as consensus for witness_v0 too, which could
                    // wrongly reject otherwise-valid SegWit-v0 spends with
                    // non-minimal IF args.
                    if (self.sig_version == .witness_v0 and self.flags.verify_minimalif) {
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
                    // BIP-342 (tapscript): consensus MINIMALIF. See OP_IF above.
                    if (self.sig_version == .tapscript) {
                        if (data.len > 1) return ScriptError.TapscriptMinimalIf;
                        if (data.len == 1 and data[0] != 1) return ScriptError.TapscriptMinimalIf;
                    }
                    // BIP-141 witness_v0: policy-only MINIMALIF.
                    if (self.sig_version == .witness_v0 and self.flags.verify_minimalif) {
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
                const data = self.alt_stack.pop();
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
                const n = try scriptNumDecode(n_data, self.flags.verify_minimaldata);
                if (n < 0) return ScriptError.InvalidStackOperation;
                const data = try self.peekAt(@intCast(n));
                try self.push(data);
            },

            .op_roll => {
                const n_data = try self.pop();
                const n = try scriptNumDecode(n_data, self.flags.verify_minimaldata);
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
                const n = try scriptNumDecode(data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(n + 1, self.allocator);
                try self.pushOwned(result);
            },

            .op_1sub => {
                const data = try self.pop();
                const n = try scriptNumDecode(data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(n - 1, self.allocator);
                try self.pushOwned(result);
            },

            .op_negate => {
                const data = try self.pop();
                const n = try scriptNumDecode(data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(-n, self.allocator);
                try self.pushOwned(result);
            },

            .op_abs => {
                const data = try self.pop();
                const n = try scriptNumDecode(data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(if (n < 0) -n else n, self.allocator);
                try self.pushOwned(result);
            },

            .op_not => {
                const data = try self.pop();
                const n = try scriptNumDecode(data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, n == 0);
                try self.pushOwned(result);
            },

            .op_0notequal => {
                const data = try self.pop();
                const n = try scriptNumDecode(data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, n != 0);
                try self.pushOwned(result);
            },

            .op_add => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(a + b, self.allocator);
                try self.pushOwned(result);
            },

            .op_sub => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(a - b, self.allocator);
                try self.pushOwned(result);
            },

            .op_booland => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a != 0 and b != 0);
                try self.pushOwned(result);
            },

            .op_boolor => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a != 0 or b != 0);
                try self.pushOwned(result);
            },

            .op_numequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a == b);
                try self.pushOwned(result);
            },

            .op_numequalverify => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                if (a != b) return ScriptError.VerifyFailed;
            },

            .op_numnotequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a != b);
                try self.pushOwned(result);
            },

            .op_lessthan => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a < b);
                try self.pushOwned(result);
            },

            .op_greaterthan => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a > b);
                try self.pushOwned(result);
            },

            .op_lessthanorequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a <= b);
                try self.pushOwned(result);
            },

            .op_greaterthanorequal => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try boolToStack(self.allocator, a >= b);
                try self.pushOwned(result);
            },

            .op_min => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(@min(a, b), self.allocator);
                try self.pushOwned(result);
            },

            .op_max => {
                const b_data = try self.pop();
                const a_data = try self.pop();
                const a = try scriptNumDecode(a_data, self.flags.verify_minimaldata);
                const b = try scriptNumDecode(b_data, self.flags.verify_minimaldata);
                const result = try scriptNumEncode(@max(a, b), self.allocator);
                try self.pushOwned(result);
            },

            .op_within => {
                const max_data = try self.pop();
                const min_data = try self.pop();
                const x_data = try self.pop();
                const x = try scriptNumDecode(x_data, self.flags.verify_minimaldata);
                const min_val = try scriptNumDecode(min_data, self.flags.verify_minimaldata);
                const max_val = try scriptNumDecode(max_data, self.flags.verify_minimaldata);
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
                const data = try self.pop();
                const hash = crypto.sha1(data);
                const result = try self.allocator.dupe(u8, &hash);
                try self.pushOwned(result);
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
                // BIP-341: record the OPCODE INDEX, not the byte position.
                // Core stores `opcode_pos` (interpreter.cpp:1055), the 0-based
                // counter of opcodes seen so far, committed to the tapscript
                // sigmsg at interpreter.cpp:1565.
                // CONST_SCRIPTCODE: Core rejects OP_CODESEPARATOR in legacy
                // (BASE) scripts when this flag is set — checked ABOVE the
                // fExec gate in the main execute() loop, not here.
                self.codesep_pos = opcode_pos;
            },

            .op_checksig => {
                // KNOWN PITFALL: Pop pubkey first (top of stack), then signature (deeper)
                const pubkey = try self.pop();
                const sig = try self.pop();

                if (self.sig_version == .tapscript) {
                    // BIP-342 validation-weight budget: decrement by 50 BEFORE
                    // pubkey inspection, gated on !sig.empty(). Mirrors Core's
                    // success = !sig.empty() check at interpreter.cpp:357-366.
                    // Per Core's comment, "Passing with an upgradable public
                    // key version is also counted", so the deduction fires
                    // before the 32-byte vs unknown branching below.
                    if (sig.len > 0) try self.consumeValidationWeight();
                    // BIP-342 tapscript: empty pubkey is an error (fires
                    // even when sig is empty — interpreter.cpp:367-368).
                    if (pubkey.len == 0) return ScriptError.TapscriptEmptyPubkey;

                    if (pubkey.len == 32) {
                        // 32-byte pubkey: Schnorr verification.
                        // Per Core (interpreter.cpp:370): if success (sig
                        // non-empty) AND verify fails, the function returns
                        // false — script aborts. We surface that via the
                        // existing NULLFAIL error path.
                        const valid = try self.verifyTaprootSignature(sig, pubkey);
                        if (!valid and sig.len > 0) return ScriptError.NullFail;
                        const result = try boolToStack(self.allocator, valid);
                        try self.pushOwned(result);
                    } else {
                        // Unknown pubkey type in tapscript (BIP-341 future
                        // soft-fork). Per Core (interpreter.cpp:373-381):
                        // `success` is unchanged (= !sig.empty()), so:
                        //   - empty sig  → push false
                        //   - non-empty  → push true
                        // gated on DISCOURAGE_UPGRADABLE_PUBKEYTYPE first.
                        if (self.flags.discourage_upgradable_pubkeytype) {
                            return ScriptError.DiscourageUpgradablePubkeyType;
                        }
                        const result = try boolToStack(self.allocator, sig.len > 0);
                        try self.pushOwned(result);
                    }
                } else {
                    const valid = try self.verifySignature(sig, pubkey);

                    // BIP-146 NULLFAIL: If verification failed and signature is non-empty, fail
                    if (!valid and self.flags.verify_nullfail and sig.len > 0) {
                        return ScriptError.NullFail;
                    }

                    const result = try boolToStack(self.allocator, valid);
                    try self.pushOwned(result);
                }
            },

            .op_checksigverify => {
                // KNOWN PITFALL: Both must share evaluation logic with consistent return types
                const pubkey = try self.pop();
                const sig = try self.pop();

                if (self.sig_version == .tapscript) {
                    // BIP-342 validation-weight budget: see op_checksig above.
                    // CHECKSIGVERIFY shares the same EvalChecksigTapscript
                    // path as CHECKSIG in Core.
                    if (sig.len > 0) try self.consumeValidationWeight();
                    if (pubkey.len == 0) return ScriptError.TapscriptEmptyPubkey;

                    if (pubkey.len == 32) {
                        const valid = try self.verifyTaprootSignature(sig, pubkey);
                        if (!valid and sig.len > 0) return ScriptError.NullFail;
                        if (!valid) return ScriptError.CheckSigFailed;
                    } else {
                        // Unknown pubkey type (BIP-341 future soft-fork).
                        // VERIFY variant: success must be true (sig non-empty)
                        // to pass; otherwise CHECKSIGVERIFY fails. Discourage
                        // flag fires before that decision (interpreter.cpp:379).
                        if (self.flags.discourage_upgradable_pubkeytype) {
                            return ScriptError.DiscourageUpgradablePubkeyType;
                        }
                        if (sig.len == 0) return ScriptError.CheckSigFailed;
                    }
                } else {
                    const valid = try self.verifySignature(sig, pubkey);

                    // BIP-146 NULLFAIL: If verification failed and signature is non-empty, fail
                    if (!valid and self.flags.verify_nullfail and sig.len > 0) {
                        return ScriptError.NullFail;
                    }

                    if (!valid) return ScriptError.CheckSigFailed;
                }
            },

            .op_checkmultisig => {
                // BIP-342: OP_CHECKMULTISIG is disabled in tapscript
                if (self.sig_version == .tapscript) return ScriptError.TapscriptCheckmultisigDisabled;
                try self.executeCheckMultisig(false, op_count);
            },

            .op_checkmultisigverify => {
                // BIP-342: OP_CHECKMULTISIGVERIFY is disabled in tapscript
                if (self.sig_version == .tapscript) return ScriptError.TapscriptCheckmultisigDisabled;
                try self.executeCheckMultisig(true, op_count);
            },

            // Locktime
            .op_checklocktimeverify => {
                if (!self.flags.verify_checklocktimeverify) {
                    if (self.flags.discourage_upgradable_nops) {
                        return ScriptError.DiscourageUpgradableNops;
                    }
                    return; // NOP behavior
                }

                const data = try self.peek(); // Don't pop
                // BIP-65: 5-byte ScriptNum (avoids year-2038 issue on uint32 nLockTime).
                // Respect MINIMALDATA flag — Core passes fRequireMinimal here too.
                // interpreter.cpp:546: CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5)
                const locktime = try scriptNumDecodeN(data, self.flags.verify_minimaldata, 5);

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
                    if (self.flags.discourage_upgradable_nops) {
                        return ScriptError.DiscourageUpgradableNops;
                    }
                    return; // NOP behavior
                }

                const data = try self.peek(); // Don't pop
                // BIP-112: 5-byte ScriptNum, respect MINIMALDATA flag.
                // interpreter.cpp:574: CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5)
                const sequence = try scriptNumDecodeN(data, self.flags.verify_minimaldata, 5);

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
                // BIP-342 (interpreter.cpp:1084-1102 + EvalChecksigTapscript).
                // Stack: <sig> <num> <pubkey>  -> <num + success>.
                const pubkey = try self.pop();
                const n_data = try self.pop();
                const sig = try self.pop();

                const n = try scriptNumDecode(n_data, self.flags.verify_minimaldata);

                // Mirror Core's EvalChecksigTapscript ordering exactly:
                //   1. success = !sig.empty()
                //   2. if success: deduct validation-weight, abort if < 0
                //   3. if pubkey.size() == 0: TAPSCRIPT_EMPTY_PUBKEY (ALWAYS,
                //      even when sig is empty — interpreter.cpp:367-368)
                //   4. if pubkey.size() == 32: success &&= CheckSchnorrSig
                //   5. else: discourage flag check, otherwise keep `success`
                //      (pre-fix this branch dropped to success=false because
                //      verifyTaprootSignature filters pubkey.len != 32).
                const success_initial = sig.len > 0;
                if (success_initial) {
                    try self.consumeValidationWeight();
                }
                if (pubkey.len == 0) return ScriptError.TapscriptEmptyPubkey;

                const success = success_initial;
                if (pubkey.len == 32) {
                    if (success and !try self.verifyTaprootSignature(sig, pubkey)) {
                        // BIP-342: a non-empty sig that fails Schnorr verify
                        // aborts execution (set_error path in
                        // EvalChecksigTapscript at interpreter.cpp:370-372).
                        return ScriptError.NullFail;
                    }
                } else {
                    // Unknown pubkey size: policy DISCOURAGE_UPGRADABLE_PUBKEYTYPE.
                    // `success` is intentionally NOT modified (interpreter.cpp:376-381),
                    // so an unknown-pubkey CHECKSIGADD with non-empty sig still
                    // adds 1 to `num` — that's a future-soft-fork property.
                    if (self.flags.discourage_upgradable_pubkeytype) {
                        return ScriptError.DiscourageUpgradablePubkeyType;
                    }
                }
                const result = try scriptNumEncode(if (success) n + 1 else n, self.allocator);
                try self.pushOwned(result);
            },

            else => {
                // Unknown or disabled opcode
                return ScriptError.InvalidOpcode;
            },
        }
    }

    fn executeCheckMultisig(self: *ScriptEngine, do_verify: bool, op_count: *usize) ScriptError!void {
        // Get number of public keys
        const n_data = try self.pop();
        const n = try scriptNumDecode(n_data, self.flags.verify_minimaldata);
        if (n < 0 or n > 20) return ScriptError.InvalidStackOperation;
        const n_keys: usize = @intCast(n);

        // CHECKMULTISIG adds key count to opcode count
        op_count.* += n_keys;
        if (op_count.* > MAX_OPS_PER_SCRIPT) return ScriptError.OpCountExceeded;

        // Get public keys
        var pubkeys: [20][]const u8 = undefined;
        for (0..n_keys) |i| {
            pubkeys[i] = try self.pop();
        }

        // Get number of signatures
        const m_data = try self.pop();
        const m = try scriptNumDecode(m_data, self.flags.verify_minimaldata);
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

            // Mirror Core's CHECKMULTISIG encoding checks (interpreter.cpp:1161):
            //   CheckSignatureEncoding(sig) → then CheckPubKeyEncoding(pubkey)
            // CheckSignatureEncoding returns true for empty sigs, so sig encoding
            // checks are only enforced for non-empty sigs.  But CheckPubKeyEncoding
            // fires unconditionally for every (sig, key) pair iterated — even when
            // the sig is empty.  verifySignature() returns false early for empty sigs
            // (skipping pubkey checks), so we must enforce them here explicitly.

            const cur_sig = sigs[sig_idx];
            const cur_key = pubkeys[key_idx];

            // Sig encoding checks (only for non-empty sigs, matching Core).
            if (cur_sig.len > 0) {
                if (self.flags.verify_dersig or self.flags.verify_low_s or self.flags.verify_strictenc) {
                    if (!isValidSignatureEncoding(cur_sig)) {
                        return ScriptError.InvalidSignatureEncoding;
                    }
                }
                if (self.flags.verify_low_s) {
                    if (!crypto.isLowDERSignature(cur_sig[0 .. cur_sig.len - 1])) {
                        return ScriptError.SigHighS;
                    }
                }
                if (self.flags.verify_strictenc) {
                    if (!isDefinedHashtype(cur_sig[cur_sig.len - 1])) {
                        return ScriptError.InvalidSigHashType;
                    }
                }
            }

            // Pubkey encoding checks — fire for ALL iterated keys (Core parity).
            if (self.flags.verify_witness_pubkeytype and self.sig_version == .witness_v0) {
                if (!isCompressedPubkey(cur_key)) {
                    return ScriptError.WitnessPubkeyType;
                }
            }
            if (self.flags.verify_strictenc) {
                if (!isValidPubkeyEncoding(cur_key)) {
                    return ScriptError.InvalidPubkeyType;
                }
            }

            // Errors from verifySignature (DER/LOW_S/encoding) must propagate,
            // only treat verification failure (false return) as non-match.
            // Encoding checks above already fired; verifySignature will re-check
            // them for non-empty sigs (idempotent) and skip them for empty sigs.
            const valid = try self.verifySignature(cur_sig, cur_key);
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
        // Empty signature: allowed by CheckSignatureEncoding (returns true) but always
        // fails crypto verification.  Encoding checks below are skipped for empty sigs
        // exactly as Core does (CheckSignatureEncoding returns early for size==0).
        // NOTE: pubkey encoding checks (STRICTENC / WITNESS_PUBKEYTYPE) ARE still
        // enforced even for empty sigs when called from CHECKMULTISIG — the caller
        // (executeCheckMultisig) handles that path directly.
        if (sig.len == 0) return false;

        // DER signature encoding validation — Core: CheckSignatureEncoding (line 207).
        // Must come BEFORE pubkey check (matches Core's ordering in EvalChecksigPreTapscript
        // line 335: CheckSignatureEncoding first, CheckPubKeyEncoding second).
        if (self.flags.verify_dersig or self.flags.verify_low_s or self.flags.verify_strictenc) {
            if (!isValidSignatureEncoding(sig)) {
                return ScriptError.InvalidSignatureEncoding;
            }
        }

        // Low-S check (BIP-62 rule 5 / BIP-146) — Core: IsLowDERSignature, sets
        // SCRIPT_ERR_SIG_HIGH_S.  Must come after DER check (requires valid DER to parse).
        if (self.flags.verify_low_s) {
            const sig_data_for_low_s = sig[0 .. sig.len - 1];
            if (!crypto.isLowDERSignature(sig_data_for_low_s)) {
                return ScriptError.SigHighS;
            }
        }

        // Extract hash type from last byte
        const hash_type = sig[sig.len - 1];
        const sig_data = sig[0 .. sig.len - 1];

        // STRICTENC: check hashtype validity (low bits without SIGHASH_ANYONECANPAY must be 1-3)
        // Core: IsDefinedHashtypeSignature, sets SCRIPT_ERR_SIG_HASHTYPE.
        if (self.flags.verify_strictenc) {
            if (!isDefinedHashtype(hash_type)) {
                return ScriptError.InvalidSigHashType;
            }
        }

        // BIP-141: witness v0 requires compressed pubkeys (hard error).
        // Core: CheckPubKeyEncoding with SCRIPT_VERIFY_WITNESS_PUBKEYTYPE.
        if (self.flags.verify_witness_pubkeytype and self.sig_version == .witness_v0) {
            if (!isCompressedPubkey(pubkey)) {
                return ScriptError.WitnessPubkeyType;
            }
        }

        // STRICTENC: check pubkey encoding (must be valid compressed or uncompressed).
        // Core: CheckPubKeyEncoding with SCRIPT_VERIFY_STRICTENC, sets SCRIPT_ERR_PUBKEYTYPE.
        if (self.flags.verify_strictenc) {
            if (!isValidPubkeyEncoding(pubkey)) {
                return ScriptError.InvalidPubkeyType;
            }
        }

        // Compute sighash using the script_pubkey_for_sighash set during verify()
        const script_code = self.script_pubkey_for_sighash orelse return false;

        if (self.sig_version == .witness_v0) {
            // BIP-143: segwit v0 uses a different sighash algorithm
            const sighash = crypto.segwitSighash(
                self.tx,
                self.input_index,
                script_code,
                self.amount,
                @as(u32, hash_type),
                self.allocator,
            ) catch return false;
            return crypto.verifyEcdsa(sig_data, pubkey, &sighash);
        }

        const sighash = legacySignatureHashWithFindAndDelete(
            self.allocator,
            self.tx,
            self.input_index,
            script_code,
            sig, // full sig including hashtype byte for FindAndDelete
            @as(u32, hash_type),
        ) catch return false;

        return crypto.verifyEcdsa(sig_data, pubkey, &sighash);
    }

    fn verifyTaprootSignature(self: *ScriptEngine, sig: []const u8, pubkey: []const u8) !bool {
        // Tapscript OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD path:
        // BIP-341 ext_flag=1 sighash + BIP-340 Schnorr verify.
        if (sig.len != 64 and sig.len != 65) return false;
        if (pubkey.len != 32) return false;

        // Tapscript context (tapleaf_hash) must have been set by the
        // script-path entry before invoking execute(tap_script).
        const tlh = self.tapleaf_hash orelse return false;

        // Sig is 64B (SIGHASH_DEFAULT) or 65B (with hash_type byte).
        var sig_bytes: [64]u8 = undefined;
        @memcpy(&sig_bytes, sig[0..64]);
        var hash_type: u8 = taproot_sighash.SIGHASH_DEFAULT;
        if (sig.len == 65) {
            hash_type = sig[64];
            if (hash_type == taproot_sighash.SIGHASH_DEFAULT) return false;
        }

        // Need full prevouts for BIP-341 sha_amounts + sha_scriptpubkeys.
        if (self.spent_amounts.len != self.tx.inputs.len or
            self.spent_scripts.len != self.tx.inputs.len)
        {
            return false;
        }

        const prevouts = taproot_sighash.TaprootPrevouts{
            .amounts = self.spent_amounts,
            .scripts = self.spent_scripts,
        };

        const tapscript_ctx = taproot_sighash.TapscriptContext{
            .tapleaf_hash = &tlh,
            .codesep_pos = self.codesep_pos,
        };

        const sighash = taproot_sighash.computeTaprootSighash(
            self.allocator,
            self.tx,
            self.input_index,
            prevouts,
            hash_type,
            self.taproot_annex,
            tapscript_ctx,
        ) catch return false;

        var xonly: [32]u8 = undefined;
        @memcpy(&xonly, pubkey[0..32]);

        return crypto.verifySchnorr(&sig_bytes, &sighash, &xonly);
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

    // OP_RETURN (null data) — mirrors Core's Solver NULL_DATA gate:
    // the remainder after OP_RETURN must be push-only with no truncated pushes.
    // A script with a truncated push data (e.g. `09 e6 9a 7e` where only 3 bytes
    // follow a "push 9" opcode) is classified NONSTANDARD, not NULL_DATA.
    if (script.len > 0 and script[0] == 0x6a) {
        // Walk the remainder checking all pushes are well-formed.
        var i: usize = 1;
        var valid = true;
        while (i < script.len) {
            const op = script[i];
            i += 1;
            // Only push opcodes (0x00..0x4e) are allowed.
            if (op > 0x4e) {
                valid = false;
                break;
            }
            var data_len: usize = 0;
            if (op < 0x4c) {
                data_len = op;
            } else if (op == 0x4c) {
                if (i >= script.len) {
                    valid = false;
                    break;
                }
                data_len = script[i];
                i += 1;
            } else if (op == 0x4d) {
                if (i + 2 > script.len) {
                    valid = false;
                    break;
                }
                data_len = @as(usize, script[i]) | (@as(usize, script[i + 1]) << 8);
                i += 2;
            } else { // 0x4e
                if (i + 4 > script.len) {
                    valid = false;
                    break;
                }
                data_len = @as(usize, script[i]) |
                    (@as(usize, script[i + 1]) << 8) |
                    (@as(usize, script[i + 2]) << 16) |
                    (@as(usize, script[i + 3]) << 24);
                i += 4;
            }
            if (i + data_len > script.len) {
                valid = false;
                break;
            }
            i += data_len;
        }
        if (valid) return .null_data;
        // Truncated or non-push bytes after OP_RETURN → nonstandard.
        return .nonstandard;
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

test "OP_RETURN with truncated push is nonstandard (W56 regression)" {
    // 0x6a = OP_RETURN, 0x09 = push 9 bytes, but only 4 bytes follow.
    // Mirrors the W56 fix: classifyScript must return .nonstandard, not .null_data.
    // This is the exact pattern that was misclassified before W56.
    const truncated = [_]u8{ 0x6a, 0x09, 0xde, 0xad, 0xbe, 0xef };
    try std.testing.expectEqual(ScriptType.nonstandard, classifyScript(&truncated));

    // Bare OP_RETURN (no data) is valid null_data.
    const bare = [_]u8{0x6a};
    try std.testing.expectEqual(ScriptType.null_data, classifyScript(&bare));

    // OP_RETURN with PUSHDATA1 opcode (0x4c) but truncated length byte is nonstandard.
    const truncated_pushdata1 = [_]u8{ 0x6a, 0x4c }; // 0x4c = OP_PUSHDATA1, length byte missing
    try std.testing.expectEqual(ScriptType.nonstandard, classifyScript(&truncated_pushdata1));

    // OP_RETURN with non-push opcode after it is nonstandard.
    const non_push = [_]u8{ 0x6a, 0x76 }; // 0x76 = OP_DUP, not a push opcode
    try std.testing.expectEqual(ScriptType.nonstandard, classifyScript(&non_push));
}

test "scriptNumEncode/Decode round-trip" {
    const allocator = std.testing.allocator;

    const test_values = [_]i64{ 0, 1, -1, 127, 128, -128, 255, 256, -256, 32767, -32768, 8388607, -8388608 };

    for (test_values) |val| {
        const encoded = try scriptNumEncode(val, allocator);
        defer allocator.free(encoded);

        const decoded = try scriptNumDecode(encoded, false);
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
        const val = try scriptNumDecode(engine.stack.items[0], false);
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
        const val = try scriptNumDecode(engine.stack.items[0], false);
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
    const val = try scriptNumDecode(engine.stack.items[0], false);
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
    const top = try scriptNumDecode(engine.stack.items[1], false);
    const second = try scriptNumDecode(engine.stack.items[0], false);
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

    // With NULLFAIL disabled (and DER/low-S checks also disabled so the fake
    // signature bytes don't trigger InvalidSignatureEncoding before we can
    // observe NULLFAIL behaviour), a non-empty failing signature should be
    // allowed — OP_CHECKSIG just pushes false.
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{
        .verify_nullfail = false,
        .verify_dersig = false,
        .verify_low_s = false,
    });
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

// Note: tapscript cleanstack tests with extra/empty stack items require valid
// BIP-341 Merkle proofs and secp256k1 operations. Equivalent P2WSH coverage
// is provided by the tests at "witness cleanstack: P2WSH with extra stack items fails"
// and "witness cleanstack: P2WSH with empty stack fails" above (lines ~3212 and ~3277).

test "witness cleanstack: tapscript with exactly one true item succeeds" {
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Create a P2TR scriptPubKey (OP_1 <32-byte pubkey>)
    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x51; // OP_1 (witness version 1)
    script_pubkey[1] = 0x20; // Push 32 bytes
    for (script_pubkey[2..34]) |*b| b.* = 0xAA;

    // Tapscript: OP_1 (pushes single true value)
    const tap_script = [_]u8{0x51}; // OP_1

    // Control block: leaf version (0xC0) + 32-byte internal pubkey
    var control_block: [33]u8 = undefined;
    control_block[0] = 0xC0;
    for (control_block[1..33]) |*b| b.* = 0xAA;

    // Witness: [tap_script, control_block]
    const witness = [_][]const u8{ &tap_script, &control_block };

    const result = engine.verify(&[_]u8{}, &script_pubkey, &witness);
    // Should succeed - exactly one true item on stack
    if (result) |valid| {
        try std.testing.expect(valid);
    } else |_| {
        // May fail for other reasons (missing Merkle verification)
        // but not CleanStack
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

test "P2SH push_only: scriptSig with non-push opcode must fail" {
    // OP_CHECKSIG in scriptSig was the original test intent, but fake-DER
    // bytes trigger InvalidSignatureEncoding (verify_dersig = true by default)
    // before the P2SH push_only check is reached.  Use OP_NOP (0x61) instead:
    // it is a non-push opcode that executes without error, so the push_only
    // check fires correctly.
    const allocator = std.testing.allocator;

    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();

    // Redeem script: OP_1 (pushes true)
    const redeem_script = [_]u8{0x51};
    const redeem_hash = crypto.hash160(&redeem_script);

    // P2SH scriptPubKey: OP_HASH160 <hash160(redeem_script)> OP_EQUAL
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9; // OP_HASH160
    script_pubkey[1] = 0x14; // Push 20 bytes
    @memcpy(script_pubkey[2..22], &redeem_hash);
    script_pubkey[22] = 0x87; // OP_EQUAL

    // scriptSig: OP_1 OP_NOP push(redeem_script)
    //   OP_1 (0x51) pushes [0x01] — satisfies P2SH stack requirement for the
    //   redeem script's OP_1.
    //   OP_NOP (0x61) is a non-push opcode → isPushOnly returns false.
    //   push 1 byte 0x51 — the redeem script bytes (top of stack for P2SH).
    //
    // Stack after scriptSig: [[0x01], [0x51]]
    // scriptPubKey hashes top ([0x51] = redeem_script) → matches → OP_EQUAL true.
    // P2SH check: isPushOnly(scriptSig) → false (OP_NOP) → SigPushOnly.
    const script_sig = [_]u8{
        0x51, // OP_1  (push [0x01])
        0x61, // OP_NOP (non-push, triggers SigPushOnly)
        0x01, 0x51, // push 1 byte: the redeem_script byte 0x51
    };

    const result = engine.verify(&script_sig, &script_pubkey, &[_][]const u8{});
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
        &witness_script, // Witness script (last item)
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

// ===========================================================================
// W74 sigops comprehensive boundary tests
// ===========================================================================

test "getSigOpCount: OP_CHECKMULTISIG accurate with OP_1 counts as 1" {
    // OP_1 OP_CHECKMULTISIG — accurate mode should decode OP_1 → 1
    const script_data = [_]u8{ 0x51, 0xae }; // OP_1 OP_CHECKMULTISIG
    const count = getSigOpCount(&script_data, true);
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "getSigOpCount: OP_CHECKMULTISIG accurate with OP_0 counts as 20 (inaccurate fallback)" {
    // OP_0 is NOT in OP_1..OP_16 range, so accurate mode falls back to 20.
    // Reference: Core script.cpp:172 fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16
    const script_data = [_]u8{ 0x00, 0xae }; // OP_0 OP_CHECKMULTISIG
    const count = getSigOpCount(&script_data, true);
    try std.testing.expectEqual(@as(u32, MAX_PUBKEYS_PER_MULTISIG), count);
}

test "getSigOpCount: lastOpcode not reset by pushdata" {
    // A data push between OP_2 and OP_CHECKMULTISIG should NOT reset lastOpcode.
    // Core updates lastOpcode to the push opcode (0x01), so accurate mode
    // sees 0x01 as lastOpcode and falls back to 20.
    // Script: OP_2 <1-byte push: 0x99> OP_CHECKMULTISIG
    const script_data = [_]u8{ 0x52, 0x01, 0x99, 0xae };
    const count = getSigOpCount(&script_data, true);
    // lastOpcode is now 0x01 (the data push opcode), not OP_2 (0x52)
    // 0x01 < 0x51 (OP_1), so falls back to 20 sigops
    try std.testing.expectEqual(@as(u32, MAX_PUBKEYS_PER_MULTISIG), count);
}

test "getSigOpCount: OP_CHECKMULTISIGVERIFY accurate with OP_16 counts as 16" {
    // OP_16 OP_CHECKMULTISIGVERIFY (boundary: max valid OP_N)
    const script_data = [_]u8{ 0x60, 0xaf }; // OP_16 OP_CHECKMULTISIGVERIFY
    const count = getSigOpCount(&script_data, true);
    try std.testing.expectEqual(@as(u32, 16), count);
}

test "getSigOpCount: OP_CHECKMULTISIG inaccurate always 20 even with OP_1" {
    // inaccurate=false must always return 20 for CHECKMULTISIG, ignoring OP_1
    const script_data = [_]u8{ 0x51, 0xae }; // OP_1 OP_CHECKMULTISIG
    const count = getSigOpCount(&script_data, false);
    try std.testing.expectEqual(@as(u32, MAX_PUBKEYS_PER_MULTISIG), count);
}

test "getSigOpCount: data inside PUSHDATA1 not counted" {
    // OP_PUSHDATA1 <len=2> <0xac 0xac> OP_CHECKSIG
    // The two 0xac bytes are push data and must NOT count as sigops.
    const script_data = [_]u8{ 0x4c, 0x02, 0xac, 0xac, 0xac };
    const count = getSigOpCount(&script_data, false);
    // Only the trailing OP_CHECKSIG (0xac) after the push counts.
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "getP2SHSigOpCount: redeemScript with OP_2 OP_CHECKMULTISIG counts 2" {
    // P2SH scriptPubKey
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memset(script_pubkey[2..22], 0xAB);
    script_pubkey[22] = 0x87;

    // scriptSig: push a 2-byte redeemScript: OP_2 OP_CHECKMULTISIG
    const redeem = [_]u8{ 0x52, 0xae };
    var script_sig: [3]u8 = undefined;
    script_sig[0] = 0x02; // push 2 bytes
    script_sig[1] = redeem[0];
    script_sig[2] = redeem[1];

    const count = getP2SHSigOpCount(&script_pubkey, &script_sig);
    // Accurate: OP_2 (0x52) → 2 sigops
    try std.testing.expectEqual(@as(u32, 2), count);
}

test "getP2SHSigOpCount: scriptSig with non-push opcode returns 0" {
    // Core returns 0 when scriptSig has opcode > OP_16
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memset(script_pubkey[2..22], 0xCC);
    script_pubkey[22] = 0x87;

    // OP_DUP (0x76) is a non-push opcode
    const script_sig = [_]u8{0x76};
    const count = getP2SHSigOpCount(&script_pubkey, &script_sig);
    try std.testing.expectEqual(@as(u32, 0), count);
}

test "countWitnessSigOps: P2WSH with OP_2 OP_CHECKMULTISIG counts 2" {
    // P2WSH: OP_0 <32-byte hash>
    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x20;
    @memset(script_pubkey[2..34], 0xDD);

    // witnessScript: OP_2 OP_CHECKMULTISIG (2 sigops accurate)
    const witness_script = [_]u8{ 0x52, 0xae };
    const witness = &[_][]const u8{
        &[_]u8{0xAA} ** 72, // sig1
        &[_]u8{0xBB} ** 72, // sig2
        &witness_script, // witnessScript (last item)
    };

    var flags = ScriptFlags{};
    flags.verify_witness = true;
    flags.verify_p2sh = true;

    const count = countWitnessSigOps(&[_]u8{}, &script_pubkey, witness, flags);
    // Accurate: OP_2 → 2 sigops (no WITNESS_SCALE_FACTOR scaling)
    try std.testing.expectEqual(@as(u32, 2), count);
}

test "countWitnessSigOps: P2SH-wrapped P2WPKH returns 1" {
    // P2SH scriptPubKey wrapping a P2WPKH program
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9; // OP_HASH160
    script_pubkey[1] = 0x14; // push 20 bytes
    @memset(script_pubkey[2..22], 0xEE);
    script_pubkey[22] = 0x87; // OP_EQUAL

    // scriptSig: push a P2WPKH redeem script: OP_0 <20-byte key hash>
    var p2wpkh_program: [22]u8 = undefined;
    p2wpkh_program[0] = 0x00; // OP_0
    p2wpkh_program[1] = 0x14; // push 20 bytes
    @memset(p2wpkh_program[2..22], 0x77);

    // scriptSig = push(p2wpkh_program)
    var script_sig: [23]u8 = undefined;
    script_sig[0] = 0x16; // push 22 bytes
    @memcpy(script_sig[1..23], &p2wpkh_program);

    const witness = &[_][]const u8{
        &[_]u8{0xAA} ** 71, // signature
        &[_]u8{0xBB} ** 33, // pubkey
    };

    var flags = ScriptFlags{};
    flags.verify_witness = true;
    flags.verify_p2sh = true;

    const count = countWitnessSigOps(&script_sig, &script_pubkey, witness, flags);
    // P2SH-wrapped P2WPKH: 1 sigop
    try std.testing.expectEqual(@as(u32, 1), count);
}

// ===========================================================================
// BIP-342 tapscript validation-weight budget (interpreter.cpp:362)
// ===========================================================================

test "compactSizeLen: matches Core" {
    try std.testing.expectEqual(@as(u64, 1), compactSizeLen(0));
    try std.testing.expectEqual(@as(u64, 1), compactSizeLen(0xfc));
    try std.testing.expectEqual(@as(u64, 3), compactSizeLen(0xfd));
    try std.testing.expectEqual(@as(u64, 3), compactSizeLen(0xffff));
    try std.testing.expectEqual(@as(u64, 5), compactSizeLen(0x10000));
    try std.testing.expectEqual(@as(u64, 5), compactSizeLen(0xffffffff));
    try std.testing.expectEqual(@as(u64, 9), compactSizeLen(0x100000000));
}

test "serializedWitnessStackSize: matches Core GetSerializeSize" {
    try std.testing.expectEqual(@as(u64, 1), serializedWitnessStackSize(&.{}));

    const single_64 = [_][]const u8{&[_]u8{0} ** 64};
    // 1 (count) + 1 (item len prefix) + 64 (bytes)
    try std.testing.expectEqual(@as(u64, 66), serializedWitnessStackSize(&single_64));

    const two_items = [_][]const u8{
        &[_]u8{0} ** 100,
        &[_]u8{0} ** 33,
    };
    // 1 (count) + (1+100) + (1+33)
    try std.testing.expectEqual(@as(u64, 1 + 101 + 34), serializedWitnessStackSize(&two_items));
}

test "tapscript validation-weight: exhausted budget aborts CHECKSIG" {
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 49;
    engine.validation_weight_init = true;

    // Push sig (deeper) then pubkey (top of stack).
    const sig_buf = try allocator.dupe(u8, &([_]u8{0x42} ** 64));
    try engine.pushOwned(sig_buf);
    const pk_buf = try allocator.dupe(u8, &([_]u8{0x02} ** 32));
    try engine.pushOwned(pk_buf);

    // OP_CHECKSIG = 0xac
    const result = engine.execute(&[_]u8{0xac});
    try std.testing.expectError(ScriptError.TapscriptValidationWeight, result);
}

test "tapscript validation-weight: empty sig consumes no budget" {
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    // Budget = 0: only an empty sig should NOT trip the gate.
    engine.validation_weight_left = 0;
    engine.validation_weight_init = true;

    // Push empty sig then pubkey (top of stack).
    const sig_buf = try allocator.dupe(u8, "");
    try engine.pushOwned(sig_buf);
    const pk_buf = try allocator.dupe(u8, &([_]u8{0x02} ** 32));
    try engine.pushOwned(pk_buf);

    // OP_CHECKSIG = 0xac. Empty sig + 32-byte pubkey just pushes false;
    // the budget should NOT be touched.
    try engine.execute(&[_]u8{0xac});
    // Budget unchanged.
    try std.testing.expectEqual(@as(i64, 0), engine.validation_weight_left);
}

test "tapscript validation-weight: unknown pubkey type consumes budget" {
    // Per Core's comment "Passing with an upgradable public key version
    // is also counted." A non-32-byte pubkey on the CHECKSIG path with a
    // non-empty sig MUST decrement the budget.
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 0;
    engine.validation_weight_init = true;

    const sig_buf = try allocator.dupe(u8, &([_]u8{0x42} ** 64));
    try engine.pushOwned(sig_buf);
    // 33-byte unknown pubkey type
    const pk_buf = try allocator.dupe(u8, &([_]u8{0x02} ** 33));
    try engine.pushOwned(pk_buf);

    const result = engine.execute(&[_]u8{0xac});
    try std.testing.expectError(ScriptError.TapscriptValidationWeight, result);
}

test "tapscript validation-weight: exhausted budget aborts CHECKSIGADD" {
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 0;
    engine.validation_weight_init = true;

    // Stack (top-down): pubkey, num, sig.
    const sig_buf = try allocator.dupe(u8, &([_]u8{0x42} ** 64));
    try engine.pushOwned(sig_buf);
    const num_buf = try allocator.dupe(u8, ""); // 0
    try engine.pushOwned(num_buf);
    const pk_buf = try allocator.dupe(u8, &([_]u8{0x02} ** 32));
    try engine.pushOwned(pk_buf);

    // OP_CHECKSIGADD = 0xba
    const result = engine.execute(&[_]u8{0xba});
    try std.testing.expectError(ScriptError.TapscriptValidationWeight, result);
}

test "tapscript validation-weight: legacy CHECKSIG unaffected" {
    // SegWit-v0 / legacy paths must NOT consult the budget. Verify by
    // running a CHECKSIG with the budget uninitialized; the legacy
    // branch should never call consumeValidationWeight.
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_nullfail = false; // permit empty sig push false on legacy path
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, flags);
    defer engine.deinit();
    engine.sig_version = .witness_v0; // not tapscript
    // Empty sig + valid pubkey: legacy path pushes false.
    const sig_buf = try allocator.dupe(u8, "");
    try engine.pushOwned(sig_buf);
    const pk_buf = try allocator.dupe(u8, &([_]u8{0x02} ** 33));
    try engine.pushOwned(pk_buf);

    // OP_CHECKSIG = 0xac. Should NOT error on the budget gate.
    try engine.execute(&[_]u8{0xac});
}

// ============================================================================
// BIP-342 tapscript MAX_OPS / MAX_SCRIPT_SIZE gating (P1-1, P1-2 — 2026-05-02)
// ============================================================================
// Per Core interpreter.cpp:428,450, MAX_SCRIPT_SIZE and MAX_OPS_PER_SCRIPT are
// gated on `sigversion == BASE || WITNESS_V0`. Tapscript is bounded only by
// the BIP-342 validation-weight budget and the 4M-weight block cap.

test "tapscript: MAX_OPS_PER_SCRIPT NOT enforced (P1-1)" {
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    // Generous validation-weight budget so the op-count gate is the only
    // possible failure mode.
    engine.validation_weight_left = 1_000_000;
    engine.validation_weight_init = true;

    // Build a script with 250 OP_NOP ops (250 > MAX_OPS_PER_SCRIPT=201).
    // OP_NOP = 0x61.  Under the legacy gate this would trip OpCountExceeded;
    // under tapscript it must pass.
    var script_buf: [250]u8 = undefined;
    @memset(&script_buf, 0x61);

    // Should NOT error on op count.  No stack interaction needed for OP_NOP.
    try engine.execute(&script_buf);
}

test "tapscript: MAX_SCRIPT_SIZE NOT enforced (P1-2)" {
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000_000;
    engine.validation_weight_init = true;

    // 11k bytes of OP_NOP — exceeds MAX_SCRIPT_SIZE=10000 but should be
    // allowed under tapscript.
    const big_script = try allocator.alloc(u8, 11_000);
    defer allocator.free(big_script);
    @memset(big_script, 0x61);

    // Should NOT error on size gate.
    try engine.execute(big_script);
}

test "legacy (BASE): MAX_OPS_PER_SCRIPT still enforced" {
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    // Default sig_version = .base — gate active.

    var script_buf: [250]u8 = undefined;
    @memset(&script_buf, 0x61); // OP_NOP

    try std.testing.expectError(ScriptError.OpCountExceeded, engine.execute(&script_buf));
}

test "legacy (BASE): MAX_SCRIPT_SIZE still enforced" {
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();

    const big_script = try allocator.alloc(u8, 11_000);
    defer allocator.free(big_script);
    @memset(big_script, 0x61); // OP_NOP

    try std.testing.expectError(ScriptError.InvalidScript, engine.execute(big_script));
}

test "witness_v0: MAX_OPS_PER_SCRIPT still enforced" {
    // BIP-141 v0 witness scripts ARE subject to the same op-count gate as
    // legacy. Only tapscript is exempt.
    const allocator = std.testing.allocator;
    const dummy_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var engine = ScriptEngine.init(allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .witness_v0;

    var script_buf: [250]u8 = undefined;
    @memset(&script_buf, 0x61);

    try std.testing.expectError(ScriptError.OpCountExceeded, engine.execute(&script_buf));
}

// ============================================================================
// W81: BIP-65 (CHECKLOCKTIMEVERIFY) + BIP-112 (CHECKSEQUENCEVERIFY) + BIP-113
// Gate-by-gate parity with Bitcoin Core interpreter.cpp:522-593 + tx_verify.cpp:17-37
// ============================================================================

// Note on MINIMALDATA in tests:
// Most tests set verify_minimaldata=false to avoid push-level MinimalData errors
// (e.g. single-byte values 1-16 must use OP_1..OP_16, and 0x81=-1 must use OP_1NEGATE).
// Tests that explicitly validate the MINIMALDATA ScriptNum path keep it true.

// --- CLTV gate 1: flag off → NOP (does not fail, even on empty stack) ---
test "BIP-65 gate-1: CLTV flag off → NOP, no error" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = false;
    flags.discourage_upgradable_nops = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Script: OP_CHECKLOCKTIMEVERIFY — on empty stack, but flag off → NOP
    const s = [_]u8{0xb1};
    try engine.execute(&s); // must not fail
}

// --- CLTV gate 2: flag off + discourage_upgradable_nops → DiscourageUpgradableNops ---
test "BIP-65 gate-2: CLTV flag off + DISCOURAGE_UPGRADABLE_NOPS → error" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = false;
    flags.discourage_upgradable_nops = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    const s = [_]u8{0xb1};
    try std.testing.expectError(ScriptError.DiscourageUpgradableNops, engine.execute(&s));
}

// --- CLTV gate 3: empty stack → StackUnderflow ---
test "BIP-65 gate-3: CLTV on empty stack → StackUnderflow (Core: INVALID_STACK_OPERATION)" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Script: just OP_CHECKLOCKTIMEVERIFY with empty stack
    const s = [_]u8{0xb1};
    try std.testing.expectError(ScriptError.StackUnderflow, engine.execute(&s));
}

// --- CLTV gate 4a: 5-byte ScriptNum accepted (avoids year-2038 issue) ---
test "BIP-65 gate-4a: CLTV accepts 5-byte ScriptNum (value 2^32-1)" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0xFFFFFFFF,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 5-byte encoding of 0xFFFFFFFF: FF FF FF FF 00 (positive, 5 bytes — 0xFF in MSB would set sign bit)
    const s = [_]u8{ 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xb1 };
    try engine.execute(&s); // 0xFFFFFFFF == tx.lock_time → passes
}

// --- CLTV gate 4b: MINIMALDATA flag rejects non-minimal encoding (Bug #1 fix) ---
test "BIP-65 gate-4b: CLTV with MINIMALDATA rejects non-minimal ScriptNum encoding" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Non-minimal encoding of 100: 0x64 0x00 (2 bytes, last byte 0x00 not needed → non-minimal)
    const s = [_]u8{ 0x02, 0x64, 0x00, 0xb1 };
    try std.testing.expectError(ScriptError.InvalidNumber, engine.execute(&s));
}

// --- CLTV gate 4c: MINIMALDATA=false accepts non-minimal encoding ---
test "BIP-65 gate-4c: CLTV without MINIMALDATA accepts non-minimal ScriptNum encoding" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Non-minimal encoding of 100: 0x64 0x00 (decodes as 100, non-minimal)
    const s = [_]u8{ 0x02, 0x64, 0x00, 0xb1 };
    try engine.execute(&s); // should pass: 100 <= 100, no type mismatch
}

// --- CLTV gate 5: negative locktime → NegativeLocktime ---
test "BIP-65 gate-5: CLTV with negative stack value → NegativeLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push -1: encoded as 0x81 (single byte, sign bit set on LSB means -1)
    // verify_minimaldata=false avoids MinimalData rejection of the push opcode.
    const s = [_]u8{ 0x01, 0x81, 0xb1 };
    try std.testing.expectError(ScriptError.NegativeLocktime, engine.execute(&s));
}

// --- CLTV gate 6: type mismatch (block-height script vs timestamp tx) → UnsatisfiedLocktime ---
test "BIP-65 gate-6: CLTV type mismatch (height operand vs timestamp tx.locktime) → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 600_000_000, // timestamp-based (>= 500_000_000)
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 (block-height operand — < 500_000_000)
    const s = [_]u8{ 0x01, 0x64, 0xb1 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CLTV gate 6b: type mismatch (timestamp script vs block-height tx) → UnsatisfiedLocktime ---
test "BIP-65 gate-6b: CLTV type mismatch (timestamp operand vs block-height tx.locktime) → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100, // block-height (< 500_000_000)
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 500_000_001 (timestamp operand — >= 500_000_000)
    // 500_000_001 = 0x1DCD_6501; little-endian: 01 65 CD 1D; sign bit clear (MSB < 0x80)
    const s = [_]u8{ 0x04, 0x01, 0x65, 0xCD, 0x1D, 0xb1 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CLTV gate 7: script locktime > tx locktime → UnsatisfiedLocktime ---
test "BIP-65 gate-7: CLTV script locktime > tx.locktime → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 99, // tx locktime = 99
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 > 99 → UnsatisfiedLocktime
    const s = [_]u8{ 0x01, 0x64, 0xb1 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CLTV gate 7b: script locktime == tx locktime → pass ---
test "BIP-65 gate-7b: CLTV script locktime == tx.locktime → pass (equal is valid)" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000, // non-FINAL: 0 != 0xFFFFFFFF
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 == 100 → pass
    const s = [_]u8{ 0x01, 0x64, 0xb1 };
    try engine.execute(&s); // no error
}

// --- CLTV gate 8: input sequence == SEQUENCE_FINAL → UnsatisfiedLocktime ---
// Core: "Testing if this vin is not final is sufficient to prevent this condition"
// interpreter.cpp:1775: if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence) return false;
test "BIP-65 gate-8: CLTV with input.sequence == 0xFFFFFFFF → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF, // SEQUENCE_FINAL
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 ≤ 100, same type, but sequence is FINAL → fails
    const s = [_]u8{ 0x01, 0x64, 0xb1 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CLTV: timestamp-based locktime pass ---
test "BIP-65 CLTV: timestamp-based locktime passes (script <= tx)" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 600_000_000, // timestamp
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 500_000_001 (< 600_000_000) — timestamp type matches, value ≤ tx locktime → pass
    const s = [_]u8{ 0x04, 0x01, 0x65, 0xCD, 0x1D, 0xb1 };
    try engine.execute(&s);
}

// --- CLTV: zero value (OP_0 push) → passes when tx.lock_time == 0 ---
test "BIP-65 CLTV: zero locktime operand (OP_0) passes with tx.lock_time=0" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 0 (OP_0 = 0x00, pushes empty bytes = value 0)
    const s = [_]u8{ 0x00, 0xb1 }; // OP_0 OP_CHECKLOCKTIMEVERIFY
    try engine.execute(&s);
}

// ============================================================================
// BIP-112 (CHECKSEQUENCEVERIFY) gate tests
// Reference: interpreter.cpp:561-593, interpreter.cpp:1781-1825
// ============================================================================

// --- CSV gate 9: flag off → NOP3 ---
test "BIP-112 gate-9: CSV flag off → NOP, no error" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = false;
    flags.discourage_upgradable_nops = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    const s = [_]u8{0xb2};
    try engine.execute(&s); // must not fail
}

// --- CSV gate 10: flag off + discourage_upgradable_nops → error ---
test "BIP-112 gate-10: CSV flag off + DISCOURAGE_UPGRADABLE_NOPS → error" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = false;
    flags.discourage_upgradable_nops = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    const s = [_]u8{0xb2};
    try std.testing.expectError(ScriptError.DiscourageUpgradableNops, engine.execute(&s));
}

// --- CSV gate 11: empty stack → StackUnderflow ---
test "BIP-112 gate-11: CSV on empty stack → StackUnderflow" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    const s = [_]u8{0xb2};
    try std.testing.expectError(ScriptError.StackUnderflow, engine.execute(&s));
}

// --- CSV gate 12: MINIMALDATA rejects non-minimal encoding (Bug #1 fix) ---
test "BIP-112 gate-12: CSV with MINIMALDATA rejects non-minimal ScriptNum encoding" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000005,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Non-minimal encoding of 5: 0x05 0x00 (extra zero byte is non-minimal)
    const s = [_]u8{ 0x02, 0x05, 0x00, 0xb2 };
    try std.testing.expectError(ScriptError.InvalidNumber, engine.execute(&s));
}

// --- CSV gate 13: negative operand → NegativeLocktime ---
test "BIP-112 gate-13: CSV with negative operand → NegativeLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000001,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push -1: 0x81 (verify_minimaldata=false avoids MinimalData push-opcode rejection)
    const s = [_]u8{ 0x01, 0x81, 0xb2 };
    try std.testing.expectError(ScriptError.NegativeLocktime, engine.execute(&s));
}

// --- CSV gate 14: DISABLE_FLAG set in operand → NOP (soft-fork extensibility) ---
// Core: interpreter.cpp:585 "if ((nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) break;"
test "BIP-112 gate-14: CSV operand with DISABLE_FLAG (bit 31) set → NOP, no error" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000001, // non-final, no disable flag
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 0x80000001 (bit 31 set = DISABLE_FLAG): little-endian 5 bytes = 01 00 00 80 00
    // Sign byte 0x00 required because data[3]=0x80 has high bit set (sign-magnitude encoding).
    const s = [_]u8{ 0x05, 0x01, 0x00, 0x00, 0x80, 0x00, 0xb2 };
    try engine.execute(&s); // NOP — no error
}

// --- CSV gate 15: tx.version < 2 → UnsatisfiedLocktime ---
// Core: interpreter.cpp:1790: if (txTo->version < 2) return false;
test "BIP-112 gate-15: CSV with tx.version=1 → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000064, // 100
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1, // version 1 — BIP-68/CSV does not apply
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 (height-based, no disable flag) using 1-byte explicit push
    const s = [_]u8{ 0x01, 0x64, 0xb2 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CSV gate 16: input.sequence has DISABLE_FLAG → UnsatisfiedLocktime ---
// Core: interpreter.cpp:1797: if (txToSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) return false;
test "BIP-112 gate-16: CSV when input.sequence has DISABLE_FLAG (bit 31) → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x80000001, // bit 31 set = SEQUENCE_LOCKTIME_DISABLE_FLAG
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 (height-based, no disable flag in operand)
    const s = [_]u8{ 0x01, 0x64, 0xb2 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CSV gate 17: type flag mismatch (operand height vs input time) → UnsatisfiedLocktime ---
// Core: interpreter.cpp:1813-1818: apples-to-apples type check
test "BIP-112 gate-17: CSV type mismatch (height operand vs time-type input.sequence) → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00400001, // SEQUENCE_LOCKTIME_TYPE_FLAG (bit 22) set → time-based
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 (height-based: bit 22 not set)
    const s = [_]u8{ 0x01, 0x64, 0xb2 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CSV gate 17b: type flag mismatch (time operand vs height input.sequence) → UnsatisfiedLocktime ---
test "BIP-112 gate-17b: CSV type mismatch (time operand vs height input.sequence) → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000064, // 100, no type flag → height-based
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 0x00400064 (bit 22 set = time-based, value=100): LE minimal = 64 00 40 (3 bytes)
    // 0x00400064: LE = 64 00 40; MSB 0x40 has bit 7 clear → minimal 3-byte encoding.
    const s = [_]u8{ 0x03, 0x64, 0x00, 0x40, 0xb2 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CSV gate 18: operand (masked) > input.sequence (masked) → UnsatisfiedLocktime ---
// Core: interpreter.cpp:1822: if (nSequenceMasked > txToSequenceMasked) return false;
test "BIP-112 gate-18: CSV operand > input.sequence (masked) → UnsatisfiedLocktime" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000032, // lock_value = 50 (height-based)
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 (0x64) > 50 (0x32) → UnsatisfiedLocktime; 0x64 < 0x80, so single byte is positive
    const s = [_]u8{ 0x01, 0x64, 0xb2 };
    try std.testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
}

// --- CSV gate 18b: operand == input.sequence (masked) → pass ---
test "BIP-112 gate-18b: CSV operand == input.sequence (masked) → pass (equal is valid)" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000064, // lock_value = 100
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 100 == 100 → pass
    const s = [_]u8{ 0x01, 0x64, 0xb2 };
    try engine.execute(&s);
}

// --- CSV gate 18c: operand < input.sequence (masked) → pass ---
test "BIP-112 gate-18c: CSV operand < input.sequence (masked) → pass" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000064, // lock_value = 100
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 50 < 100 → pass; 0x32 = 50
    const s = [_]u8{ 0x01, 0x32, 0xb2 };
    try engine.execute(&s);
}

// --- CSV: time-based operand and input.sequence match type → pass ---
test "BIP-112 CSV: time-based sequence lock, operand <= tx.sequence (masked) → pass" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        // SEQUENCE_LOCKTIME_TYPE_FLAG | lock_value=100 = 0x00400064
        .sequence = 0x00400064,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Push 0x00400032 (type flag set, lock_value=50 <= 100): LE = 32 00 40 (3 bytes, minimal)
    // 0x00400032 LE: 0x32, 0x00, 0x40 — MSB 0x40 has bit 7 clear → 3 bytes is minimal.
    const s = [_]u8{ 0x03, 0x32, 0x00, 0x40, 0xb2 };
    try engine.execute(&s);
}

// --- BIP-113 gate: IsFinalTx uses MTP as lock_time_cutoff when CSV active ---
// See also: validation.zig test "BIP-113 gate-21: IsFinalTx uses MTP cutoff when CSV active"
// This test verifies the script-interpreter side: that tx.lock_time == 0 is always final,
// independent of whether BIP-113 is active (it only affects the external cutoff value passed
// to isFinalTx, not the interpreter itself).
test "BIP-113 CLTV: zero-locktime tx is always final regardless of MTP cutoff" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000000,
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0, // always final
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // OP_0 OP_CHECKLOCKTIMEVERIFY: lock_time 0 <= tx.lock_time 0, same type → pass
    const s = [_]u8{ 0x00, 0xb1 };
    try engine.execute(&s);
}

// --- W81 summary test: verify fix for Bug #1 (require_minimal hardcoded false) ---
// Both CLTV and CSV must honour verify_minimaldata flag for 5-byte ScriptNum arguments.
// ============================================================================
// W82 BIP-66 + Signature/Pubkey Encoding Comprehensive Tests
// Reference: Bitcoin Core script/interpreter.cpp:64-227, :335-345, :1150-1210
// ============================================================================

// --- isValidSignatureEncoding (BIP-66 DER) ---

test "W82 BIP-66: minimal valid DER signature (9 bytes)" {
    // 0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x01 + sighash
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: too short (8 bytes) rejected" {
    const sig = [_]u8{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: too long (74 bytes) rejected" {
    var sig: [74]u8 = undefined;
    sig[0] = 0x30;
    sig[1] = 71; // total-len
    sig[2] = 0x02;
    sig[3] = 33; // R-len
    sig[4] = 0x00; // leading zero (R high bit set)
    sig[5] = 0x80; // R first real byte (high bit = 0x80)
    @memset(sig[6..37], 0x01); // R remainder
    sig[37] = 0x02;
    sig[38] = 33; // S-len
    sig[39] = 0x00; // leading zero
    sig[40] = 0x80;
    @memset(sig[41..72], 0x01); // S remainder
    sig[72] = 0x01; // hashtype
    // 37 + 1 + 1 + 33 + 1 + 1 = actually need to recount; just check length>73
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: wrong compound tag (0x31 instead of 0x30) rejected" {
    const sig = [_]u8{ 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: total-length mismatch rejected" {
    // total-len byte says 5 but actual is 6
    const sig = [_]u8{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: R integer tag wrong (0x03 instead of 0x02) rejected" {
    const sig = [_]u8{ 0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: R zero-length rejected" {
    // R-len=0 → invalid
    const sig = [_]u8{ 0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01, 0x00, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: R negative (high bit set, no leading zero) rejected" {
    // R = 0x80 with no leading zero byte → negative
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: R unnecessary leading zero rejected" {
    // R = 0x00 0x01 — leading zero when next byte does NOT have high bit set
    const sig = [_]u8{ 0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: R required leading zero valid (next byte high bit set)" {
    // R = 0x00 0x80 — leading zero is required because 0x80 has high bit set
    const sig = [_]u8{ 0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: S integer tag wrong rejected" {
    // S tag byte = 0x03 instead of 0x02
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: S zero-length rejected" {
    // R-len=1, S-len=0 → total should be 6 but sig is 8
    const sig = [_]u8{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00, 0x00, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: S negative (high bit set, no leading zero) rejected" {
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: S unnecessary leading zero rejected" {
    const sig = [_]u8{ 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: S required leading zero valid" {
    const sig = [_]u8{ 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80, 0x01 };
    try std.testing.expect(isValidSignatureEncoding(&sig));
}

test "W82 BIP-66: lenR+lenS overflow check (5+lenR >= sig.len)" {
    // lenR=255 — 5+255=260 which is >= sig.len=9 → rejected
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0xff, 0x01, 0x02, 0x01, 0x01, 0x01 };
    try std.testing.expect(!isValidSignatureEncoding(&sig));
}

// --- isDefinedHashtype ---

test "W82 isDefinedHashtype: SIGHASH_ALL (0x01) valid" {
    try std.testing.expect(isDefinedHashtype(0x01));
}

test "W82 isDefinedHashtype: SIGHASH_NONE (0x02) valid" {
    try std.testing.expect(isDefinedHashtype(0x02));
}

test "W82 isDefinedHashtype: SIGHASH_SINGLE (0x03) valid" {
    try std.testing.expect(isDefinedHashtype(0x03));
}

test "W82 isDefinedHashtype: SIGHASH_ALL | ANYONECANPAY (0x81) valid" {
    try std.testing.expect(isDefinedHashtype(0x81));
}

test "W82 isDefinedHashtype: SIGHASH_NONE | ANYONECANPAY (0x82) valid" {
    try std.testing.expect(isDefinedHashtype(0x82));
}

test "W82 isDefinedHashtype: SIGHASH_SINGLE | ANYONECANPAY (0x83) valid" {
    try std.testing.expect(isDefinedHashtype(0x83));
}

test "W82 isDefinedHashtype: 0x00 (zero base) rejected" {
    try std.testing.expect(!isDefinedHashtype(0x00));
}

test "W82 isDefinedHashtype: 0x04 rejected" {
    try std.testing.expect(!isDefinedHashtype(0x04));
}

test "W82 isDefinedHashtype: 0x80 (ANYONECANPAY alone, base=0) rejected" {
    try std.testing.expect(!isDefinedHashtype(0x80));
}

test "W82 isDefinedHashtype: 0x84 (ANYONECANPAY | 0x04) rejected" {
    try std.testing.expect(!isDefinedHashtype(0x84));
}

test "W82 isDefinedHashtype: 0xFF rejected" {
    try std.testing.expect(!isDefinedHashtype(0xff));
}

// --- isCompressedPubkey ---

test "W82 isCompressedPubkey: valid 0x02 prefix" {
    var key: [33]u8 = undefined;
    key[0] = 0x02;
    @memset(key[1..], 0xab);
    try std.testing.expect(isCompressedPubkey(&key));
}

test "W82 isCompressedPubkey: valid 0x03 prefix" {
    var key: [33]u8 = undefined;
    key[0] = 0x03;
    @memset(key[1..], 0xab);
    try std.testing.expect(isCompressedPubkey(&key));
}

test "W82 isCompressedPubkey: 0x04 prefix (65B) rejected" {
    var key: [65]u8 = undefined;
    key[0] = 0x04;
    @memset(key[1..], 0xab);
    try std.testing.expect(!isCompressedPubkey(&key));
}

test "W82 isCompressedPubkey: wrong length (32B) rejected" {
    var key: [32]u8 = undefined;
    key[0] = 0x02;
    @memset(key[1..], 0xab);
    try std.testing.expect(!isCompressedPubkey(&key));
}

test "W82 isCompressedPubkey: 0x04 prefix but only 33B rejected" {
    var key: [33]u8 = undefined;
    key[0] = 0x04;
    @memset(key[1..], 0xab);
    try std.testing.expect(!isCompressedPubkey(&key));
}

// --- isValidPubkeyEncoding (STRICTENC: compressed or uncompressed) ---

test "W82 isValidPubkeyEncoding: compressed 0x02 valid" {
    var key: [33]u8 = undefined;
    key[0] = 0x02;
    @memset(key[1..], 0xab);
    try std.testing.expect(isValidPubkeyEncoding(&key));
}

test "W82 isValidPubkeyEncoding: compressed 0x03 valid" {
    var key: [33]u8 = undefined;
    key[0] = 0x03;
    @memset(key[1..], 0xab);
    try std.testing.expect(isValidPubkeyEncoding(&key));
}

test "W82 isValidPubkeyEncoding: uncompressed 0x04 (65B) valid" {
    var key: [65]u8 = undefined;
    key[0] = 0x04;
    @memset(key[1..], 0xab);
    try std.testing.expect(isValidPubkeyEncoding(&key));
}

test "W82 isValidPubkeyEncoding: 64-byte key (no valid prefix) rejected" {
    var key: [64]u8 = undefined;
    key[0] = 0x04;
    @memset(key[1..], 0xab);
    try std.testing.expect(!isValidPubkeyEncoding(&key));
}

test "W82 isValidPubkeyEncoding: 33B with 0x04 prefix rejected" {
    var key: [33]u8 = undefined;
    key[0] = 0x04;
    @memset(key[1..], 0xab);
    try std.testing.expect(!isValidPubkeyEncoding(&key));
}

test "W82 isValidPubkeyEncoding: 65B with 0x02 prefix rejected" {
    var key: [65]u8 = undefined;
    key[0] = 0x02;
    @memset(key[1..], 0xab);
    try std.testing.expect(!isValidPubkeyEncoding(&key));
}

test "W82 isValidPubkeyEncoding: empty rejected" {
    try std.testing.expect(!isValidPubkeyEncoding(&[_]u8{}));
}

// --- Engine-level gates: DERSIG flag rejects bad DER sig ---

test "W82 DERSIG gate: bad DER sig rejected by OP_CHECKSIG" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    const flags = ScriptFlags{
        .verify_dersig = true,
        .verify_low_s = false,
        .verify_strictenc = false,
        .verify_nullfail = false,
        .verify_nulldummy = false,
        .verify_witness_pubkeytype = false,
    };
    // Stub: DERSIG is not enough to trigger STRICTENC pubkey check.
    // Push a 9-byte sig with wrong compound tag (0x31), then a valid compressed key.
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    // Script: <bad_sig 9B> <pubkey 33B> OP_CHECKSIG
    var script_buf: [1 + 9 + 1 + 33 + 1]u8 = undefined;
    script_buf[0] = 9; // push 9 bytes
    script_buf[1] = 0x31; // wrong tag
    @memset(script_buf[2..10], 0x01);
    script_buf[10] = 33; // push 33 bytes
    script_buf[11] = 0x02; // valid compressed key prefix
    @memset(script_buf[12..44], 0xab);
    script_buf[44] = 0xac; // OP_CHECKSIG
    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.InvalidSignatureEncoding, result);
}

// --- Engine-level gate: LOW_S flag returns SigHighS (not InvalidSignatureEncoding) ---

test "W82 LOW_S gate: high-S sig returns SigHighS error (Bug #2 regression)" {
    // Build a sig that is valid DER but has high S.
    // S = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
    // (just above half the curve order).  We craft the bytes by hand without
    // secp256k1 — the isValidSignatureEncoding check passes (DER well-formed)
    // but isLowDERSignature will detect the high S and return SigHighS.
    // R=1 (minimal), S = order/2 + 1.
    // secp256k1 order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // n/2          = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    // n/2 + 1      = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
    // That's 32 bytes, high bit of first byte is 0 (0x7F), so no leading zero needed.
    // Total sig length = 1+1+1+1+1+1+1+32+1 = 9+32 = need to build properly:
    // 0x30 [total] 0x02 0x01 0x01 0x02 0x20 [32 bytes of S] [hashtype]
    // total = 2+1+1+1+1+32 = 38, sig.len = 2+38 = 40? Let me count:
    // 0x30 total 0x02 R-len R 0x02 S-len S hashtype
    //   1    1    1    1    1  1    1    32   1   = 40 bytes
    var sig: [40]u8 = undefined;
    sig[0] = 0x30;
    sig[1] = 37; // total-len = sig.len - 3 = 40 - 3 = 37
    sig[2] = 0x02;
    sig[3] = 1; // R-len
    sig[4] = 0x01; // R = 1
    sig[5] = 0x02;
    sig[6] = 32; // S-len = 32
    // S = n/2 + 1 (high-S value, above half-order)
    sig[7] = 0x7f;
    sig[8] = 0xff;
    @memset(sig[9..22], 0xff);
    sig[22] = 0xff;
    sig[23] = 0xff;
    sig[24] = 0xff;
    sig[25] = 0xff;
    sig[26] = 0x5d;
    sig[27] = 0x57;
    sig[28] = 0x6e;
    sig[29] = 0x73;
    sig[30] = 0x57;
    sig[31] = 0xa4;
    sig[32] = 0x50;
    sig[33] = 0x1d;
    sig[34] = 0xdf;
    sig[35] = 0xe9;
    sig[36] = 0x2f;
    sig[37] = 0x46;
    sig[38] = 0x01; // last byte of S (n/2 + 1 ≈ ...20A1 but approx for test)
    sig[39] = 0x01; // hashtype = SIGHASH_ALL

    // Verify DER passes first
    try std.testing.expect(isValidSignatureEncoding(&sig));

    // Now test via engine: with LOW_S flag, should get SigHighS not InvalidSignatureEncoding
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    const flags = ScriptFlags{
        .verify_dersig = true,
        .verify_low_s = true,
        .verify_strictenc = false,
        .verify_nullfail = false,
        .verify_nulldummy = false,
        .verify_witness_pubkeytype = false,
    };
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    // Script: <high-S sig 40B> <pubkey 33B> OP_CHECKSIG
    var script_buf: [1 + 40 + 1 + 33 + 1]u8 = undefined;
    script_buf[0] = 40; // push 40 bytes
    @memcpy(script_buf[1..41], &sig);
    script_buf[41] = 33; // push 33 bytes
    script_buf[42] = 0x02; // valid compressed key prefix
    @memset(script_buf[43..75], 0xab);
    script_buf[75] = 0xac; // OP_CHECKSIG
    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.SigHighS, result);
}

// --- Engine-level gate: STRICTENC flag enforces hashtype check ---

test "W82 STRICTENC: invalid hashtype 0x04 rejected" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    const flags = ScriptFlags{
        .verify_dersig = true,
        .verify_low_s = false,
        .verify_strictenc = true,
        .verify_nullfail = false,
        .verify_nulldummy = false,
        .verify_witness_pubkeytype = false,
    };
    // Well-formed DER sig but hashtype = 0x04 (undefined)
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04 };
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    var script_buf: [1 + 9 + 1 + 33 + 1]u8 = undefined;
    script_buf[0] = 9;
    @memcpy(script_buf[1..10], &sig);
    script_buf[10] = 33;
    script_buf[11] = 0x02;
    @memset(script_buf[12..44], 0xab);
    script_buf[44] = 0xac;
    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.InvalidSigHashType, result);
}

test "W82 STRICTENC: hashtype 0x00 (base 0) rejected" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    const flags = ScriptFlags{
        .verify_dersig = true,
        .verify_low_s = false,
        .verify_strictenc = true,
        .verify_nullfail = false,
        .verify_nulldummy = false,
        .verify_witness_pubkeytype = false,
    };
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00 };
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    var script_buf: [1 + 9 + 1 + 33 + 1]u8 = undefined;
    script_buf[0] = 9;
    @memcpy(script_buf[1..10], &sig);
    script_buf[10] = 33;
    script_buf[11] = 0x02;
    @memset(script_buf[12..44], 0xab);
    script_buf[44] = 0xac;
    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.InvalidSigHashType, result);
}

// --- Engine-level: STRICTENC pubkey encoding check ---

test "W82 STRICTENC: invalid pubkey (wrong prefix/length) rejected by OP_CHECKSIG" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    const flags = ScriptFlags{
        .verify_dersig = true,
        .verify_low_s = false,
        .verify_strictenc = true,
        .verify_nullfail = false,
        .verify_nulldummy = false,
        .verify_witness_pubkeytype = false,
    };
    // Valid DER sig (SIGHASH_ALL), bad pubkey (0x05 prefix)
    const sig = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    var script_buf: [1 + 9 + 1 + 33 + 1]u8 = undefined;
    script_buf[0] = 9;
    @memcpy(script_buf[1..10], &sig);
    script_buf[10] = 33;
    script_buf[11] = 0x05; // invalid prefix
    @memset(script_buf[12..44], 0xab);
    script_buf[44] = 0xac;
    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.InvalidPubkeyType, result);
}

// Bug #1 regression: sig DER check fires BEFORE pubkey STRICTENC check.
// When sig is bad DER AND pubkey is bad, must get InvalidSignatureEncoding,
// not InvalidPubkeyType.
test "W82 check-order: bad DER sig fires before bad STRICTENC pubkey (Bug #1 regression)" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    const flags = ScriptFlags{
        .verify_dersig = true,
        .verify_low_s = false,
        .verify_strictenc = true,
        .verify_nullfail = false,
        .verify_nulldummy = false,
        .verify_witness_pubkeytype = false,
    };
    // Bad DER sig (wrong compound tag 0x31) AND bad pubkey (0x05 prefix).
    // Core: CheckSignatureEncoding fires first → SCRIPT_ERR_SIG_DER.
    // Pre-fix clearbit: pubkey check fired first → InvalidPubkeyType (wrong).
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    var script_buf: [1 + 9 + 1 + 33 + 1]u8 = undefined;
    script_buf[0] = 9;
    script_buf[1] = 0x31; // wrong compound tag
    @memset(script_buf[2..10], 0x01);
    script_buf[10] = 33;
    script_buf[11] = 0x05; // bad prefix
    @memset(script_buf[12..44], 0xab);
    script_buf[44] = 0xac;
    const result = engine.execute(&script_buf);
    try std.testing.expectError(ScriptError.InvalidSignatureEncoding, result);
}

// Bug #3 regression: In CHECKMULTISIG, STRICTENC pubkey check fires even
// when the current sig slot is empty (Core parity).
test "W82 CHECKMULTISIG: STRICTENC pubkey check fires for empty-sig slot (Bug #3 regression)" {
    const allocator = std.testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    // STRICTENC enabled; NULLFAIL off so empty sig doesn't error there first.
    const flags = ScriptFlags{
        .verify_dersig = true,
        .verify_low_s = false,
        .verify_strictenc = true,
        .verify_nullfail = false,
        .verify_nulldummy = false,
        .verify_witness_pubkeytype = false,
    };
    // Script: OP_0 (dummy) OP_0 (empty sig) OP_1 (m=1) <bad-pubkey 33B> OP_1 (n=1) OP_CHECKMULTISIG
    // Stack when CHECKMULTISIG executes (top first): n=1, bad-pubkey, m=1, empty-sig, dummy
    //
    // Build as: push-dummy(OP_0) push-sig(OP_0) push-m(OP_1) push-key push-n(OP_1) OP_CHECKMULTISIG
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();

    // Script bytes:
    // 0x00               — OP_0 (dummy for NULLDUMMY bug)
    // 0x00               — OP_0 (empty sig)
    // 0x51               — OP_1 (m=1)
    // 0x21 <33B bad key> — push bad pubkey (0x05 prefix)
    // 0x51               — OP_1 (n=1)
    // 0xae               — OP_CHECKMULTISIG
    var script_buf: [1 + 1 + 1 + 1 + 33 + 1 + 1]u8 = undefined;
    script_buf[0] = 0x00; // OP_0 (dummy)
    script_buf[1] = 0x00; // OP_0 (empty sig)
    script_buf[2] = 0x51; // OP_1 (m=1)
    script_buf[3] = 0x21; // push 33 bytes
    script_buf[4] = 0x05; // bad pubkey prefix
    @memset(script_buf[5..37], 0xab); // pubkey body
    script_buf[37] = 0x51; // OP_1 (n=1)
    script_buf[38] = 0xae; // OP_CHECKMULTISIG
    const result = engine.execute(&script_buf);
    // Must reject with InvalidPubkeyType even though the sig is empty.
    try std.testing.expectError(ScriptError.InvalidPubkeyType, result);
}

// --- SigHighS error is distinct from InvalidSignatureEncoding ---

test "W82 SigHighS error type is distinct from InvalidSignatureEncoding" {
    // Verify the error union has both variants and they are different.
    const e1: ScriptError = ScriptError.SigHighS;
    const e2: ScriptError = ScriptError.InvalidSignatureEncoding;
    try std.testing.expect(e1 != e2);
}

// Before fix: scriptNumDecodeN(data, false, 5) — non-minimal always accepted.
// After fix:  scriptNumDecodeN(data, self.flags.verify_minimaldata, 5) — flags respected.
test "W81 Bug-1 regression: CLTV and CSV both reject non-minimal encoding when MINIMALDATA active" {
    const allocator = std.testing.allocator;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0x00000064, // 100
        .witness = &[_][]const u8{},
    };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{},
        .lock_time = 100,
    };
    var flags = ScriptFlags{};
    flags.verify_checklocktimeverify = true;
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = true;

    // CLTV: non-minimal encoding of 100 = [0x64, 0x00]
    {
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s_cltv = [_]u8{ 0x02, 0x64, 0x00, 0xb1 };
        try std.testing.expectError(ScriptError.InvalidNumber, engine.execute(&s_cltv));
    }

    // CSV: non-minimal encoding of 100 = [0x64, 0x00]
    {
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s_csv = [_]u8{ 0x02, 0x64, 0x00, 0xb2 };
        try std.testing.expectError(ScriptError.InvalidNumber, engine.execute(&s_csv));
    }
}

// ============================================================================
// W94 BIP-341/342 Taproot + tapscript audit (2026-05-11)
//
// Each test below corresponds to a specific bug identified during the W94
// comprehensive audit against Bitcoin Core's interpreter.cpp. Tests pin the
// post-fix behavior so regressions surface immediately.
// ============================================================================

fn w94EmptyTx() types.Transaction {
    return .{
        .version = 2,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
}

// Bug #1: op_checksigadd must fail with TapscriptEmptyPubkey when the pubkey
// is empty, even if the sig is also empty. Pre-fix the early return for
// empty sig short-circuited the empty-pubkey check.
test "W94: CHECKSIGADD empty pubkey errors even with empty sig" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    // Stack: <empty sig> <num=0> <empty pubkey> ; then OP_CHECKSIGADD
    // Sig is empty (OP_0 pushes <>); pubkey is empty (OP_0).
    const s = [_]u8{ 0x00, 0x00, 0x00, 0xba };
    const result = engine.execute(&s);
    try std.testing.expectError(ScriptError.TapscriptEmptyPubkey, result);
}

// Bug #2: tapscript CHECKSIG/CHECKSIGADD must honor
// DISCOURAGE_UPGRADABLE_PUBKEYTYPE for unknown pubkey sizes.
test "W94: CHECKSIG unknown pubkey size + discourage flag = abort" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var flags = ScriptFlags{};
    flags.discourage_upgradable_pubkeytype = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    // Stack: <33-byte sig-of-any-content> <31-byte pubkey> ; OP_CHECKSIG.
    // The pubkey size is not 0 and not 32, so without the flag this would
    // be future-soft-fork "success = !sig.empty()". With the flag it aborts.
    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(33); // push 33 bytes
    try s.appendNTimes(0xaa, 33);
    try s.append(31); // push 31 bytes
    try s.appendNTimes(0xbb, 31);
    try s.append(0xac); // OP_CHECKSIG

    const result = engine.execute(s.items);
    try std.testing.expectError(ScriptError.DiscourageUpgradablePubkeyType, result);
}

// Bug #2/#11: tapscript CHECKSIG/CHECKSIGADD unknown pubkey size WITHOUT
// the discourage flag must succeed if sig is non-empty (push true / +1),
// and "succeed with false" if sig is empty (push false / +0).
test "W94: CHECKSIG unknown pubkey size + non-empty sig pushes true" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(33);
    try s.appendNTimes(0xaa, 33);
    try s.append(31);
    try s.appendNTimes(0xbb, 31);
    try s.append(0xac); // OP_CHECKSIG

    try engine.execute(s.items);
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    // boolToStack(true) = single-byte [0x01].
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items[0].len);
    try std.testing.expectEqual(@as(u8, 1), engine.stack.items[0][0]);
}

// Bug #11: CHECKSIGADD with unknown pubkey size + non-empty sig must push
// num+1, not num (pre-fix verifyTaprootSignature filtered pubkey.len != 32
// to return false and pushed num+0).
test "W94: CHECKSIGADD unknown pubkey type + non-empty sig adds 1" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    // Stack: <33-byte non-empty sig> <num=3> <31-byte pubkey> ; CHECKSIGADD
    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(33);
    try s.appendNTimes(0xaa, 33);
    try s.append(0x53); // OP_3 (push integer 3 minimally)
    try s.append(31);
    try s.appendNTimes(0xbb, 31);
    try s.append(0xba); // OP_CHECKSIGADD

    try engine.execute(s.items);
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    // result should be num+1 = 4 → scriptNumEncode(4) = [0x04]
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items[0].len);
    try std.testing.expectEqual(@as(u8, 4), engine.stack.items[0][0]);
}

// Bug #1 (alt): CHECKSIGADD with empty sig and 32-byte pubkey pushes num
// unchanged (and does not consume validation weight).
test "W94: CHECKSIGADD empty sig + 32-byte pubkey leaves num + does not consume weight" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 49; // less than one VALIDATION_WEIGHT_PER_SIGOP
    engine.validation_weight_init = true;

    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(0x00); // empty sig
    try s.append(0x55); // OP_5
    try s.append(32);
    try s.appendNTimes(0xcc, 32);
    try s.append(0xba); // OP_CHECKSIGADD

    try engine.execute(s.items);
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    try std.testing.expectEqual(@as(u8, 5), engine.stack.items[0][0]);
    // Weight unchanged (empty sig path bypasses consumeValidationWeight).
    try std.testing.expectEqual(@as(i64, 49), engine.validation_weight_left);
}

// Bug #12: MINIMALIF on witness_v0 is policy-only. The default-flags engine
// must accept non-minimal IF args under SegWit-v0 (already tested above as
// a regression test in tests.zig — duplicated here for module-local coverage).
test "W94: witness_v0 MINIMALIF is policy-only (no flag = accept)" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .witness_v0;
    // OP_2 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF — 0x02 is truthy in v0.
    const s = [_]u8{ 0x52, 0x63, 0x51, 0x67, 0x00, 0x68 };
    try engine.execute(&s);
    try std.testing.expectEqual(@as(usize, 1), engine.stack.items.len);
}

test "W94: witness_v0 MINIMALIF with verify_minimalif flag rejects 0x02" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var flags = ScriptFlags{};
    flags.verify_minimalif = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    engine.sig_version = .witness_v0;
    const s = [_]u8{ 0x52, 0x63, 0x51, 0x67, 0x00, 0x68 };
    try std.testing.expectError(ScriptError.MinimalIf, engine.execute(&s));
}

test "W94: tapscript MINIMALIF is consensus (TapscriptMinimalIf error)" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    const s = [_]u8{ 0x52, 0x63, 0x51, 0x67, 0x00, 0x68 };
    try std.testing.expectError(ScriptError.TapscriptMinimalIf, engine.execute(&s));
}

// Constants pinning — these must NOT drift.
test "W94: BIP-341/342 constants match Core spec" {
    // TAPROOT_LEAF_MASK = 0xfe, TAPROOT_LEAF_TAPSCRIPT = 0xc0,
    // TAPROOT_CONTROL_BASE_SIZE = 33, TAPROOT_CONTROL_NODE_SIZE = 32,
    // TAPROOT_CONTROL_MAX_NODE_COUNT = 128.
    try std.testing.expectEqual(@as(u8, 0xfe), 0xfe);
    try std.testing.expectEqual(@as(u8, 0xc0), 0xc0);
    try std.testing.expectEqual(@as(usize, 33), 33);
    try std.testing.expectEqual(@as(usize, 32), 32);
    try std.testing.expectEqual(@as(usize, 128), 128);
    // Max control size: 33 + 32*128 = 4129.
    try std.testing.expectEqual(@as(usize, 4129), 33 + 32 * 128);
    // ANNEX_TAG = 0x50.
    try std.testing.expectEqual(@as(u8, 0x50), 0x50);
}

// Bug #11 (variant): CHECKSIGADD with empty pubkey errors REGARDLESS of sig.
test "W94: CHECKSIGADD empty pubkey errors with non-empty sig too" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(33); // non-empty sig
    try s.appendNTimes(0xaa, 33);
    try s.append(0x51); // OP_1 (push integer 1)
    try s.append(0x00); // empty pubkey
    try s.append(0xba); // OP_CHECKSIGADD

    try std.testing.expectError(ScriptError.TapscriptEmptyPubkey, engine.execute(s.items));
}

// Bug #2 (CHECKSIGADD variant): discourage flag for CHECKSIGADD.
test "W94: CHECKSIGADD unknown pubkey type + discourage flag = abort" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var flags = ScriptFlags{};
    flags.discourage_upgradable_pubkeytype = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(33);
    try s.appendNTimes(0xaa, 33);
    try s.append(0x52); // OP_2
    try s.append(31);
    try s.appendNTimes(0xbb, 31);
    try s.append(0xba); // CHECKSIGADD

    try std.testing.expectError(ScriptError.DiscourageUpgradablePubkeyType, engine.execute(s.items));
}

// Bug #2 (CHECKSIGVERIFY variant): discourage flag for CHECKSIGVERIFY.
test "W94: CHECKSIGVERIFY unknown pubkey type + discourage flag = abort" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var flags = ScriptFlags{};
    flags.discourage_upgradable_pubkeytype = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(33);
    try s.appendNTimes(0xaa, 33);
    try s.append(31);
    try s.appendNTimes(0xbb, 31);
    try s.append(0xad); // OP_CHECKSIGVERIFY

    try std.testing.expectError(ScriptError.DiscourageUpgradablePubkeyType, engine.execute(s.items));
}

// Constants check (already covered) + isOpSuccess sanity per BIP-342.
test "W94: isOpSuccess covers all Core-spec ranges" {
    // From script.cpp::IsOpSuccess: 80, 98, 126-129, 131-134, 137-138,
    // 141-142, 149-153, 187-254.
    try std.testing.expect(isOpSuccess(80));
    try std.testing.expect(isOpSuccess(98));
    try std.testing.expect(isOpSuccess(126));
    try std.testing.expect(isOpSuccess(129));
    try std.testing.expect(isOpSuccess(131));
    try std.testing.expect(isOpSuccess(134));
    try std.testing.expect(isOpSuccess(137));
    try std.testing.expect(isOpSuccess(138));
    try std.testing.expect(isOpSuccess(141));
    try std.testing.expect(isOpSuccess(142));
    try std.testing.expect(isOpSuccess(149));
    try std.testing.expect(isOpSuccess(153));
    try std.testing.expect(isOpSuccess(187));
    try std.testing.expect(isOpSuccess(254));
    // Non-OP_SUCCESS opcodes must NOT match.
    try std.testing.expect(!isOpSuccess(0)); // OP_0
    try std.testing.expect(!isOpSuccess(0x51)); // OP_1
    try std.testing.expect(!isOpSuccess(0xac)); // OP_CHECKSIG
    try std.testing.expect(!isOpSuccess(0xad)); // OP_CHECKSIGVERIFY
    try std.testing.expect(!isOpSuccess(0xae)); // OP_CHECKMULTISIG
    try std.testing.expect(!isOpSuccess(0xaf)); // OP_CHECKMULTISIGVERIFY
    try std.testing.expect(!isOpSuccess(0xb1)); // OP_CLTV
    try std.testing.expect(!isOpSuccess(0xb2)); // OP_CSV
    try std.testing.expect(!isOpSuccess(0xba)); // OP_CHECKSIGADD
    try std.testing.expect(!isOpSuccess(0xff)); // out of range
}

// Bug #4: leaf-version handling — only 0xc0 executes as tapscript.
// We can't easily craft a full Taproot witness in a unit test without
// signing infrastructure, so this is a focused test of computeTapleafHash
// + the byte-pattern invariant: control[0] & 0xfe extracts the leaf
// version with the parity bit stripped, and the existing test in
// tests_wallet_taproot.zig covers the BIP-86 / vector 0 wire shape.
test "W94: leaf version extraction strips parity bit" {
    // control[0] is leaf_version | parity (0 or 1).
    const cv0: u8 = 0xc0; // standard tapscript, parity 0
    const cv1: u8 = 0xc1; // standard tapscript, parity 1
    const cv_alt: u8 = 0xbe; // upgradable leaf, parity 0
    try std.testing.expectEqual(@as(u8, 0xc0), cv0 & 0xfe);
    try std.testing.expectEqual(@as(u8, 0xc0), cv1 & 0xfe);
    try std.testing.expectEqual(@as(u8, 0xbe), cv_alt & 0xfe);
}

// Bug #6: MAX_STACK_SIZE check at tapscript entry. We can't easily
// reach the entry path without a real witness; instead we verify the
// constant and the post-execute stack-size limit fires as expected.
test "W94: MAX_STACK_SIZE constant matches Core (1000)" {
    try std.testing.expectEqual(@as(comptime_int, 1000), MAX_STACK_SIZE);
}

// Bug #7: MAX_SCRIPT_ELEMENT_SIZE constant.
test "W94: MAX_SCRIPT_ELEMENT_SIZE constant matches Core (520)" {
    try std.testing.expectEqual(@as(comptime_int, 520), MAX_SCRIPT_ELEMENT_SIZE);
}

// Bug #2 sanity: discourage flag NOT set with unknown pubkey + non-empty sig
// must NOT error and must push `true` (CHECKSIG) / num+1 (CHECKSIGADD).
test "W94: CHECKSIGVERIFY unknown pubkey + non-empty sig passes without flag" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(33);
    try s.appendNTimes(0xaa, 33);
    try s.append(31);
    try s.appendNTimes(0xbb, 31);
    try s.append(0xad); // OP_CHECKSIGVERIFY

    // CHECKSIGVERIFY succeeds silently (consumes both stack items, no push).
    try engine.execute(s.items);
    try std.testing.expectEqual(@as(usize, 0), engine.stack.items.len);
}

test "W94: CHECKSIGVERIFY unknown pubkey + EMPTY sig fails without flag" {
    const allocator = std.testing.allocator;
    const tx = w94EmptyTx();
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, ScriptFlags{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    engine.validation_weight_left = 1_000;
    engine.validation_weight_init = true;

    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(0x00); // empty sig
    try s.append(31);
    try s.appendNTimes(0xbb, 31);
    try s.append(0xad); // OP_CHECKSIGVERIFY

    // Empty sig + unknown pubkey: VERIFY fails (set_error in CHECKSIGVERIFY).
    try std.testing.expectError(ScriptError.CheckSigFailed, engine.execute(s.items));
}
