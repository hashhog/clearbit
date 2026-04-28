//! BIP-341 Taproot signature hash computation.
//!
//! Reference: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
//!
//! This module computes the message that gets fed into Schnorr signature
//! verification for Taproot key-path spends and tapscript OP_CHECKSIG.
//!
//! Validated against bitcoin-core/src/test/data/bip341_wallet_vectors.json
//! via tools/bip341-vector-runner/clearbit-shim — produces byte-perfect
//! sigMsg + sigHash for all 7 keyPathSpending vectors.

const std = @import("std");
const crypto = @import("crypto.zig");
const types = @import("types.zig");

// SIGHASH flag constants (BIP-341).
pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Per BIP-341, the only valid hash_type bytes are these:
/// 0x00 (SIGHASH_DEFAULT), 0x01, 0x02, 0x03, 0x81, 0x82, 0x83.
pub fn isValidTaprootHashType(hash_type: u8) bool {
    const upper = hash_type & ~@as(u8, 0x83);
    if (upper != 0) return false;
    if (hash_type == 0x00) return true;
    return (hash_type & 0x03) != 0x00;
}

pub const TaprootSighashError = error{
    InvalidHashType,
    InputIndexOutOfRange,
    PrevoutsLengthMismatch,
    SighashSingleNoMatchingOutput,
    OutOfMemory,
};

/// Per-input prevout context required by BIP-341.
pub const TaprootPrevouts = struct {
    amounts: []const i64,
    scripts: []const []const u8,
};

/// Optional script-path context (for tapscript OP_CHECKSIG, ext_flag = 1).
pub const TapscriptContext = struct {
    tapleaf_hash: *const [32]u8,
    codesep_pos: u32,
};

/// Compute the BIP-341 Taproot sighash. Returns the 32-byte tagged
/// hash that must equal the message argument of the Schnorr verify.
pub fn computeTaprootSighash(
    allocator: std.mem.Allocator,
    tx: *const types.Transaction,
    input_index: usize,
    prevouts: TaprootPrevouts,
    hash_type: u8,
    annex: ?[]const u8,
    script_path: ?TapscriptContext,
) TaprootSighashError![32]u8 {
    var preimage = std.ArrayList(u8).init(allocator);
    defer preimage.deinit();
    try buildSigMsg(&preimage, tx, input_index, prevouts, hash_type, annex, script_path);
    return crypto.taggedHash("TapSighash", preimage.items);
}

/// Build the BIP-341 "Common signature message" preimage.
///
/// Exposed separately from `computeTaprootSighash` so callers (e.g.
/// the BIP-341 vector validation shim) can inspect the preimage
/// against the test-vector `intermediary.sigMsg` field.
pub fn buildSigMsg(
    out: *std.ArrayList(u8),
    tx: *const types.Transaction,
    input_index: usize,
    prevouts: TaprootPrevouts,
    hash_type: u8,
    annex: ?[]const u8,
    script_path: ?TapscriptContext,
) TaprootSighashError!void {
    if (input_index >= tx.inputs.len) return TaprootSighashError.InputIndexOutOfRange;
    if (prevouts.amounts.len != tx.inputs.len or prevouts.scripts.len != tx.inputs.len) {
        return TaprootSighashError.PrevoutsLengthMismatch;
    }
    if (!isValidTaprootHashType(hash_type)) return TaprootSighashError.InvalidHashType;

    // 0x00 (SIGHASH_DEFAULT) behaves like SIGHASH_ALL for branching, but
    // the byte serialized into the preimage is the original hash_type.
    const output_type: u8 = if (hash_type == SIGHASH_DEFAULT) SIGHASH_ALL else (hash_type & 0x03);
    const anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    const ext_flag: u8 = if (script_path != null) 1 else 0;

    // 1. Epoch byte.
    try out.append(0x00);
    // 2. hash_type (original byte).
    try out.append(hash_type);
    // 3. nVersion (i32 LE).
    try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(i32, tx.version)));
    // 4. nLockTime (u32 LE).
    try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, tx.lock_time)));

    // 5-8. sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences
    if (!anyone_can_pay) {
        // sha_prevouts = SHA256(concat(outpoint serialization for each input))
        var prevouts_buf = std.ArrayList(u8).init(out.allocator);
        defer prevouts_buf.deinit();
        for (tx.inputs) |inp| {
            try prevouts_buf.appendSlice(&inp.previous_output.hash);
            try prevouts_buf.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, inp.previous_output.index)));
        }
        try out.appendSlice(&crypto.sha256(prevouts_buf.items));

        // sha_amounts
        var amounts_buf = std.ArrayList(u8).init(out.allocator);
        defer amounts_buf.deinit();
        for (prevouts.amounts) |amt| {
            try amounts_buf.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(i64, amt)));
        }
        try out.appendSlice(&crypto.sha256(amounts_buf.items));

        // sha_scriptpubkeys
        var scripts_buf = std.ArrayList(u8).init(out.allocator);
        defer scripts_buf.deinit();
        for (prevouts.scripts) |spk| {
            try writeCompactSize(&scripts_buf, spk.len);
            try scripts_buf.appendSlice(spk);
        }
        try out.appendSlice(&crypto.sha256(scripts_buf.items));

        // sha_sequences
        var seqs_buf = std.ArrayList(u8).init(out.allocator);
        defer seqs_buf.deinit();
        for (tx.inputs) |inp| {
            try seqs_buf.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, inp.sequence)));
        }
        try out.appendSlice(&crypto.sha256(seqs_buf.items));
    }

    // 9. sha_outputs (skipped for SIGHASH_NONE/SINGLE).
    if (output_type != SIGHASH_NONE and output_type != SIGHASH_SINGLE) {
        var outputs_buf = std.ArrayList(u8).init(out.allocator);
        defer outputs_buf.deinit();
        for (tx.outputs) |o| {
            try encodeTxOut(&outputs_buf, o);
        }
        try out.appendSlice(&crypto.sha256(outputs_buf.items));
    }

    // 10. spend_type.
    var spend_type: u8 = ext_flag * 2;
    if (annex != null) spend_type |= 1;
    try out.append(spend_type);

    // 11. Per-input data.
    if (anyone_can_pay) {
        const inp = tx.inputs[input_index];
        try out.appendSlice(&inp.previous_output.hash);
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, inp.previous_output.index)));
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(i64, prevouts.amounts[input_index])));
        try writeCompactSize(out, prevouts.scripts[input_index].len);
        try out.appendSlice(prevouts.scripts[input_index]);
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, inp.sequence)));
    } else {
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, @intCast(input_index)))));
    }

    // 12. sha_annex (only when annex present).
    if (annex) |annex_bytes| {
        var annex_buf = std.ArrayList(u8).init(out.allocator);
        defer annex_buf.deinit();
        try writeCompactSize(&annex_buf, annex_bytes.len);
        try annex_buf.appendSlice(annex_bytes);
        try out.appendSlice(&crypto.sha256(annex_buf.items));
    }

    // 13. sha_single_output (only for SIGHASH_SINGLE, AFTER input data + annex).
    if (output_type == SIGHASH_SINGLE) {
        if (input_index >= tx.outputs.len) return TaprootSighashError.SighashSingleNoMatchingOutput;
        var single_buf = std.ArrayList(u8).init(out.allocator);
        defer single_buf.deinit();
        try encodeTxOut(&single_buf, tx.outputs[input_index]);
        try out.appendSlice(&crypto.sha256(single_buf.items));
    }

    // 14. Tapscript extensions (ext_flag = 1).
    if (script_path) |sp| {
        try out.appendSlice(sp.tapleaf_hash);
        try out.append(0x00); // key_version
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, sp.codesep_pos)));
    }
}

fn writeCompactSize(out: *std.ArrayList(u8), n: usize) !void {
    if (n < 0xFD) {
        try out.append(@as(u8, @intCast(n)));
    } else if (n <= 0xFFFF) {
        try out.append(0xFD);
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u16, @as(u16, @intCast(n)))));
    } else if (n <= 0xFFFF_FFFF) {
        try out.append(0xFE);
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, @intCast(n)))));
    } else {
        try out.append(0xFF);
        try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u64, @as(u64, @intCast(n)))));
    }
}

fn encodeTxOut(out: *std.ArrayList(u8), txout: types.TxOut) !void {
    try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(i64, txout.value)));
    try writeCompactSize(out, txout.script_pubkey.len);
    try out.appendSlice(txout.script_pubkey);
}
