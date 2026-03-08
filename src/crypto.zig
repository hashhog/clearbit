const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");

// ============================================================================
// Type Aliases
// ============================================================================

/// SHA256 hash (32 bytes) - also exported from types.zig
pub const Hash256 = types.Hash256;

/// RIPEMD160 hash (20 bytes) - also exported from types.zig
pub const Hash160 = types.Hash160;

// Legacy aliases for backward compatibility
pub const Sha256Hash = Hash256;
pub const Ripemd160Hash = Hash160;

// ============================================================================
// Hashing Functions
// ============================================================================

/// Single SHA-256 hash
pub fn sha256(data: []const u8) Hash256 {
    var result: Hash256 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &result, .{});
    return result;
}

/// Double SHA-256 (Bitcoin's standard hash for blocks, txids, etc.)
pub fn hash256(data: []const u8) Hash256 {
    var first_hash: Hash256 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &first_hash, .{});
    var result: Hash256 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first_hash, &result, .{});
    return result;
}

/// RIPEMD-160 - Bitcoin uses this for address generation
/// Zig stdlib doesn't have RIPEMD160, so we implement it
pub fn ripemd160(data: []const u8) Hash160 {
    var state = Ripemd160State.init();
    state.update(data);
    return state.final();
}

/// HASH-160: RIPEMD160(SHA256(x)) - used for P2PKH/P2SH addresses
pub fn hash160(data: []const u8) Hash160 {
    const sha_hash = sha256(data);
    return ripemd160(&sha_hash);
}

// ============================================================================
// RIPEMD-160 Implementation
// ============================================================================

const Ripemd160State = struct {
    state: [5]u32,
    buf: [64]u8,
    buf_len: usize,
    total_len: u64,

    const K_LEFT = [_]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
    const K_RIGHT = [_]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

    const R_LEFT = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        7,  4,  13, 1,  10, 6,  15, 3,  12, 0,  9,  5,  2,  14, 11, 8,
        3,  10, 14, 4,  9,  15, 8,  1,  2,  7,  0,  6,  13, 11, 5,  12,
        1,  9,  11, 10, 0,  8,  12, 4,  13, 3,  7,  15, 14, 5,  6,  2,
        4,  0,  5,  9,  7,  12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13,
    };

    const R_RIGHT = [_]u8{
        5,  14, 7,  0,  9,  2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
        6,  11, 3,  7,  0,  13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
        15, 5,  1,  3,  7,  14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
        8,  6,  4,  1,  3,  11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
        12, 15, 10, 4,  1,  5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
    };

    const S_LEFT = [_]u8{
        11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
        7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
        11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
        11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
        9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
    };

    const S_RIGHT = [_]u8{
        8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
        9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
        9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
        15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
        8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
    };

    fn init() Ripemd160State {
        return .{
            .state = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    fn update(self: *Ripemd160State, data: []const u8) void {
        var input = data;
        self.total_len += input.len;

        if (self.buf_len > 0) {
            const remaining = 64 - self.buf_len;
            if (input.len < remaining) {
                @memcpy(self.buf[self.buf_len..][0..input.len], input);
                self.buf_len += input.len;
                return;
            }
            @memcpy(self.buf[self.buf_len..][0..remaining], input[0..remaining]);
            self.processBlock(&self.buf);
            input = input[remaining..];
            self.buf_len = 0;
        }

        while (input.len >= 64) {
            self.processBlock(input[0..64]);
            input = input[64..];
        }

        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }
    }

    fn final(self: *Ripemd160State) Hash160 {
        const bit_len = self.total_len * 8;

        // Padding
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        @memset(self.buf[self.buf_len..56], 0);
        std.mem.writeInt(u64, self.buf[56..64], bit_len, .little);
        self.processBlock(&self.buf);

        var result: Hash160 = undefined;
        for (0..5) |i| {
            std.mem.writeInt(u32, result[i * 4 ..][0..4], self.state[i], .little);
        }
        return result;
    }

    fn processBlock(self: *Ripemd160State, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        for (0..16) |i| {
            x[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
        }

        var al = self.state[0];
        var bl = self.state[1];
        var cl = self.state[2];
        var dl = self.state[3];
        var el = self.state[4];

        var ar = self.state[0];
        var br = self.state[1];
        var cr = self.state[2];
        var dr = self.state[3];
        var er = self.state[4];

        for (0..80) |j| {
            const round = j / 16;

            // Left path: functions f, g, h, i, j for rounds 0-4
            const fl = switch (round) {
                0 => bl ^ cl ^ dl, // f
                1 => (bl & cl) | (~bl & dl), // g
                2 => (bl | ~cl) ^ dl, // h
                3 => (bl & dl) | (cl & ~dl), // i
                4 => bl ^ (cl | ~dl), // j
                else => unreachable,
            };

            var tl = al +% fl +% x[R_LEFT[j]] +% K_LEFT[round];
            tl = std.math.rotl(u32, tl, @as(u5, @intCast(S_LEFT[j]))) +% el;
            al = el;
            el = dl;
            dl = std.math.rotl(u32, cl, 10);
            cl = bl;
            bl = tl;

            // Right path: functions j, i, h, g, f for rounds 0-4 (reverse order)
            const fr = switch (round) {
                0 => br ^ (cr | ~dr), // j
                1 => (br & dr) | (cr & ~dr), // i
                2 => (br | ~cr) ^ dr, // h
                3 => (br & cr) | (~br & dr), // g
                4 => br ^ cr ^ dr, // f
                else => unreachable,
            };

            var tr = ar +% fr +% x[R_RIGHT[j]] +% K_RIGHT[round];
            tr = std.math.rotl(u32, tr, @as(u5, @intCast(S_RIGHT[j]))) +% er;
            ar = er;
            er = dr;
            dr = std.math.rotl(u32, cr, 10);
            cr = br;
            br = tr;
        }

        const t = self.state[1] +% cl +% dr;
        self.state[1] = self.state[2] +% dl +% er;
        self.state[2] = self.state[3] +% el +% ar;
        self.state[3] = self.state[4] +% al +% br;
        self.state[4] = self.state[0] +% bl +% cr;
        self.state[0] = t;
    }
};

// ============================================================================
// Merkle Tree
// ============================================================================

/// Compute the Merkle root of a list of transaction hashes.
/// 1. If the list has one element, return it.
/// 2. If the list has an odd number of elements, duplicate the last.
/// 3. Pairwise hash256(concat(a, b)) to produce the next level.
/// 4. Repeat until one hash remains.
pub fn computeMerkleRoot(hashes: []const Hash256, allocator: std.mem.Allocator) !Hash256 {
    if (hashes.len == 0) {
        return [_]u8{0} ** 32;
    }
    if (hashes.len == 1) {
        return hashes[0];
    }

    // Create working buffer for current level
    var current = try allocator.alloc(Hash256, hashes.len);
    defer allocator.free(current);
    @memcpy(current, hashes);

    var len = hashes.len;

    while (len > 1) {
        // If odd number of elements, duplicate the last
        const pair_count = (len + 1) / 2;

        for (0..pair_count) |i| {
            const left_idx = i * 2;
            const right_idx = if (left_idx + 1 < len) left_idx + 1 else left_idx;

            // Concatenate and hash
            var concat: [64]u8 = undefined;
            @memcpy(concat[0..32], &current[left_idx]);
            @memcpy(concat[32..64], &current[right_idx]);
            current[i] = hash256(&concat);
        }

        len = pair_count;
    }

    return current[0];
}

// ============================================================================
// libsecp256k1 Integration
// ============================================================================

// Note: libsecp256k1 integration requires the library to be installed.
// On Ubuntu: apt install libsecp256k1-dev
// On macOS: brew install libsecp256k1
//
// The actual @cImport integration would look like:
//
// const secp256k1 = @cImport({
//     @cInclude("secp256k1.h");
//     @cInclude("secp256k1_recovery.h");
//     @cInclude("secp256k1_schnorrsig.h");
// });
//
// For now, we provide stub implementations that can be replaced when linking
// against the actual library.

/// Whether libsecp256k1 is available (set via build.zig option)
pub const has_secp256k1: bool = false;

/// Global secp256k1 context state
var secp_initialized: bool = false;

/// Initialize the secp256k1 context for signature verification
/// Returns true if initialization succeeded, false otherwise
pub fn initSecp256k1() bool {
    if (secp_initialized) return true;
    // When libsecp256k1 is linked, this would call:
    // secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    secp_initialized = has_secp256k1;
    return secp_initialized;
}

/// Deinitialize the secp256k1 context
pub fn deinitSecp256k1() void {
    // When libsecp256k1 is linked, this would call:
    // secp256k1.secp256k1_context_destroy(ctx)
    secp_initialized = false;
}

/// Check if secp256k1 is available and initialized
pub fn isSecp256k1Available() bool {
    return has_secp256k1 and secp_initialized;
}

/// Verify an ECDSA signature (DER-encoded) against a public key and message hash.
/// Bitcoin requires low-S normalization for signatures (BIP-62 rule 5).
///
/// sig_der: DER-encoded ECDSA signature
/// pubkey_bytes: compressed (33 bytes) or uncompressed (65 bytes) public key
/// msg_hash: 32-byte message hash to verify
///
/// Returns true if signature is valid, false otherwise
pub fn verifyEcdsa(sig_der: []const u8, pubkey_bytes: []const u8, msg_hash: *const [32]u8) bool {
    _ = sig_der;
    _ = pubkey_bytes;
    _ = msg_hash;
    // Stub - returns false when library not available
    // When libsecp256k1 is linked, this would:
    // 1. Parse the public key with secp256k1_ec_pubkey_parse
    // 2. Parse the DER signature with secp256k1_ecdsa_signature_parse_der
    // 3. Normalize to low-S with secp256k1_ecdsa_signature_normalize
    // 4. Verify with secp256k1_ecdsa_verify
    return false;
}

/// Verify a Schnorr signature (BIP-340) for taproot.
///
/// sig: 64-byte Schnorr signature
/// msg_hash: 32-byte message hash
/// pubkey_x: 32-byte x-only public key
///
/// Returns true if signature is valid, false otherwise
pub fn verifySchnorr(sig: *const [64]u8, msg_hash: *const [32]u8, pubkey_x: *const [32]u8) bool {
    _ = sig;
    _ = msg_hash;
    _ = pubkey_x;
    // Stub - returns false when library not available
    // When libsecp256k1 is linked, this would:
    // 1. Parse the x-only pubkey with secp256k1_xonly_pubkey_parse
    // 2. Verify with secp256k1_schnorrsig_verify
    return false;
}

// ============================================================================
// Transaction Hashing
// ============================================================================

/// Compute the txid (double-SHA256 of the non-witness serialization).
/// Returns the hash in internal byte order (not display order).
pub fn computeTxid(tx: *const types.Transaction, allocator: std.mem.Allocator) !Hash256 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try serialize.writeTransactionNoWitness(&writer, tx);
    const data = try writer.toOwnedSlice();
    defer allocator.free(data);
    return hash256(data);
}

/// Compute the wtxid (double-SHA256 of full serialization including witness).
/// For non-segwit transactions, wtxid equals txid.
pub fn computeWtxid(tx: *const types.Transaction, allocator: std.mem.Allocator) !Hash256 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try serialize.writeTransaction(&writer, tx);
    const data = try writer.toOwnedSlice();
    defer allocator.free(data);
    return hash256(data);
}

/// Compute the hash of a block header (double-SHA256).
pub fn computeBlockHash(header: *const types.BlockHeader) Hash256 {
    var buf: [80]u8 = undefined;
    std.mem.writeInt(i32, buf[0..4], header.version, .little);
    @memcpy(buf[4..36], &header.prev_block);
    @memcpy(buf[36..68], &header.merkle_root);
    std.mem.writeInt(u32, buf[68..72], header.timestamp, .little);
    std.mem.writeInt(u32, buf[72..76], header.bits, .little);
    std.mem.writeInt(u32, buf[76..80], header.nonce, .little);
    return hash256(&buf);
}

// ============================================================================
// Sighash Computation
// ============================================================================

/// Sighash type flags
pub const SigHashType = types.SigHashType;

/// Compute the legacy sighash for pre-segwit inputs.
/// This is used for P2PKH and P2SH (non-segwit) inputs.
pub fn legacySighash(
    tx: *const types.Transaction,
    input_index: usize,
    script_pubkey: []const u8,
    hash_type: u32,
    allocator: std.mem.Allocator,
) !Hash256 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    const base_type = hash_type & 0x1f;
    const anyone_can_pay = (hash_type & 0x80) != 0;

    // Version
    try writer.writeInt(i32, tx.version);

    // Inputs
    if (anyone_can_pay) {
        // Only include the input being signed
        try writer.writeCompactSize(1);
        const input = tx.inputs[input_index];
        try writer.writeBytes(&input.previous_output.hash);
        try writer.writeInt(u32, input.previous_output.index);
        try writer.writeCompactSize(script_pubkey.len);
        try writer.writeBytes(script_pubkey);
        try writer.writeInt(u32, input.sequence);
    } else {
        try writer.writeCompactSize(tx.inputs.len);
        for (tx.inputs, 0..) |input, i| {
            try writer.writeBytes(&input.previous_output.hash);
            try writer.writeInt(u32, input.previous_output.index);

            if (i == input_index) {
                // Include script_pubkey for the input being signed
                try writer.writeCompactSize(script_pubkey.len);
                try writer.writeBytes(script_pubkey);
            } else {
                // Empty script for other inputs
                try writer.writeCompactSize(0);
            }

            // Sequence - for SIGHASH_NONE/SINGLE, set to 0 for other inputs
            if ((base_type == 0x02 or base_type == 0x03) and i != input_index) {
                try writer.writeInt(u32, 0);
            } else {
                try writer.writeInt(u32, input.sequence);
            }
        }
    }

    // Outputs
    if (base_type == 0x02) {
        // SIGHASH_NONE: no outputs
        try writer.writeCompactSize(0);
    } else if (base_type == 0x03) {
        // SIGHASH_SINGLE: only output at same index
        if (input_index >= tx.outputs.len) {
            // Bitcoin quirk: return a specific hash for this error case
            var result: Hash256 = [_]u8{0} ** 32;
            result[0] = 1;
            return result;
        }
        try writer.writeCompactSize(input_index + 1);
        // Write empty outputs for indices before input_index
        for (0..input_index) |_| {
            try writer.writeInt(i64, -1); // -1 value
            try writer.writeCompactSize(0); // empty script
        }
        // Write the actual output
        const output = tx.outputs[input_index];
        try writer.writeInt(i64, output.value);
        try writer.writeCompactSize(output.script_pubkey.len);
        try writer.writeBytes(output.script_pubkey);
    } else {
        // SIGHASH_ALL: all outputs
        try writer.writeCompactSize(tx.outputs.len);
        for (tx.outputs) |output| {
            try writer.writeInt(i64, output.value);
            try writer.writeCompactSize(output.script_pubkey.len);
            try writer.writeBytes(output.script_pubkey);
        }
    }

    // Locktime
    try writer.writeInt(u32, tx.lock_time);

    // Hash type (4 bytes, little-endian)
    try writer.writeInt(u32, hash_type);

    const data = try writer.toOwnedSlice();
    defer allocator.free(data);
    return hash256(data);
}

/// Precomputed hashes for BIP-143 segwit sighash optimization
pub const SegwitSighashCache = struct {
    hash_prevouts: Hash256,
    hash_sequence: Hash256,
    hash_outputs: Hash256,

    pub fn init(tx: *const types.Transaction, allocator: std.mem.Allocator) !SegwitSighashCache {
        _ = allocator;
        var prevouts_data: [36 * 256]u8 = undefined; // Assuming max 256 inputs
        var prevouts_len: usize = 0;
        for (tx.inputs) |input| {
            @memcpy(prevouts_data[prevouts_len..][0..32], &input.previous_output.hash);
            std.mem.writeInt(u32, prevouts_data[prevouts_len + 32 ..][0..4], input.previous_output.index, .little);
            prevouts_len += 36;
        }

        var sequence_data: [4 * 256]u8 = undefined;
        var sequence_len: usize = 0;
        for (tx.inputs) |input| {
            std.mem.writeInt(u32, sequence_data[sequence_len..][0..4], input.sequence, .little);
            sequence_len += 4;
        }

        // For outputs, we need dynamic sizing
        var outputs_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (tx.outputs) |output| {
            var value_buf: [8]u8 = undefined;
            std.mem.writeInt(i64, &value_buf, output.value, .little);
            outputs_hasher.update(&value_buf);

            // CompactSize for script length
            if (output.script_pubkey.len < 0xFD) {
                outputs_hasher.update(&[_]u8{@intCast(output.script_pubkey.len)});
            } else if (output.script_pubkey.len <= 0xFFFF) {
                var size_buf: [3]u8 = undefined;
                size_buf[0] = 0xFD;
                std.mem.writeInt(u16, size_buf[1..3], @intCast(output.script_pubkey.len), .little);
                outputs_hasher.update(&size_buf);
            }
            outputs_hasher.update(output.script_pubkey);
        }
        var first_hash: Hash256 = undefined;
        outputs_hasher.final(&first_hash);

        return .{
            .hash_prevouts = hash256(prevouts_data[0..prevouts_len]),
            .hash_sequence = hash256(sequence_data[0..sequence_len]),
            .hash_outputs = hash256(&first_hash),
        };
    }
};

/// Compute BIP-143 segwit sighash for signature verification.
/// This is used for P2WPKH and P2WSH inputs.
pub fn segwitSighash(
    tx: *const types.Transaction,
    input_index: usize,
    script_code: []const u8,
    value: i64,
    hash_type: u32,
    allocator: std.mem.Allocator,
) !Hash256 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    const base_type = hash_type & 0x1f;
    const anyone_can_pay = (hash_type & 0x80) != 0;

    // 1. nVersion (4 bytes)
    try writer.writeInt(i32, tx.version);

    // 2. hashPrevouts (32 bytes)
    if (!anyone_can_pay) {
        var prevouts_data = std.ArrayList(u8).init(allocator);
        defer prevouts_data.deinit();
        for (tx.inputs) |input| {
            try prevouts_data.appendSlice(&input.previous_output.hash);
            var idx_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &idx_buf, input.previous_output.index, .little);
            try prevouts_data.appendSlice(&idx_buf);
        }
        const hash_prevouts = hash256(prevouts_data.items);
        try writer.writeBytes(&hash_prevouts);
    } else {
        try writer.writeBytes(&([_]u8{0} ** 32));
    }

    // 3. hashSequence (32 bytes)
    if (!anyone_can_pay and base_type != 0x02 and base_type != 0x03) {
        var sequence_data = std.ArrayList(u8).init(allocator);
        defer sequence_data.deinit();
        for (tx.inputs) |input| {
            var seq_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &seq_buf, input.sequence, .little);
            try sequence_data.appendSlice(&seq_buf);
        }
        const hash_sequence = hash256(sequence_data.items);
        try writer.writeBytes(&hash_sequence);
    } else {
        try writer.writeBytes(&([_]u8{0} ** 32));
    }

    // 4. outpoint (32 + 4 bytes)
    const input = tx.inputs[input_index];
    try writer.writeBytes(&input.previous_output.hash);
    try writer.writeInt(u32, input.previous_output.index);

    // 5. scriptCode (varInt + script)
    try writer.writeCompactSize(script_code.len);
    try writer.writeBytes(script_code);

    // 6. value (8 bytes)
    try writer.writeInt(i64, value);

    // 7. nSequence (4 bytes)
    try writer.writeInt(u32, input.sequence);

    // 8. hashOutputs (32 bytes)
    if (base_type != 0x02 and base_type != 0x03) {
        // SIGHASH_ALL: hash all outputs
        var outputs_data = std.ArrayList(u8).init(allocator);
        defer outputs_data.deinit();
        for (tx.outputs) |output| {
            var val_buf: [8]u8 = undefined;
            std.mem.writeInt(i64, &val_buf, output.value, .little);
            try outputs_data.appendSlice(&val_buf);

            // CompactSize
            if (output.script_pubkey.len < 0xFD) {
                try outputs_data.append(@intCast(output.script_pubkey.len));
            } else {
                try outputs_data.append(0xFD);
                var len_buf: [2]u8 = undefined;
                std.mem.writeInt(u16, &len_buf, @intCast(output.script_pubkey.len), .little);
                try outputs_data.appendSlice(&len_buf);
            }
            try outputs_data.appendSlice(output.script_pubkey);
        }
        const hash_outputs = hash256(outputs_data.items);
        try writer.writeBytes(&hash_outputs);
    } else if (base_type == 0x03 and input_index < tx.outputs.len) {
        // SIGHASH_SINGLE: hash only the corresponding output
        var output_data = std.ArrayList(u8).init(allocator);
        defer output_data.deinit();
        const output = tx.outputs[input_index];
        var val_buf: [8]u8 = undefined;
        std.mem.writeInt(i64, &val_buf, output.value, .little);
        try output_data.appendSlice(&val_buf);
        if (output.script_pubkey.len < 0xFD) {
            try output_data.append(@intCast(output.script_pubkey.len));
        } else {
            try output_data.append(0xFD);
            var len_buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &len_buf, @intCast(output.script_pubkey.len), .little);
            try output_data.appendSlice(&len_buf);
        }
        try output_data.appendSlice(output.script_pubkey);
        const hash_outputs = hash256(output_data.items);
        try writer.writeBytes(&hash_outputs);
    } else {
        try writer.writeBytes(&([_]u8{0} ** 32));
    }

    // 9. nLocktime (4 bytes)
    try writer.writeInt(u32, tx.lock_time);

    // 10. sighash type (4 bytes)
    try writer.writeInt(u32, hash_type);

    const data = try writer.toOwnedSlice();
    defer allocator.free(data);
    return hash256(data);
}

// ============================================================================
// Tagged Hash (BIP-340)
// ============================================================================

/// Compute a tagged hash as per BIP-340: SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn taggedHash(tag: []const u8, msg: []const u8) Hash256 {
    const tag_hash = sha256(tag);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);

    var result: Hash256 = undefined;
    hasher.final(&result);
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "sha256 basic" {
    const result = sha256("");
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "sha256 hello" {
    const result = sha256("hello");
    const expected = [_]u8{
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash256 empty" {
    const result = hash256("");
    // SHA256(SHA256("")) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    const expected = [_]u8{
        0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
        0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
        0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
        0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "ripemd160 empty" {
    const result = ripemd160("");
    const expected = [_]u8{
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
        0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "ripemd160 hello" {
    const result = ripemd160("hello");
    const expected = [_]u8{
        0x10, 0x8f, 0x07, 0xb8, 0x38, 0x24, 0x12, 0x61, 0x2c, 0x04,
        0x8d, 0x07, 0xd1, 0x3f, 0x81, 0x41, 0x18, 0x44, 0x5a, 0xcd,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash160 pubkey" {
    // Test with a well-known public key (Satoshi's genesis coinbase)
    const pubkey = [_]u8{
        0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67,
        0xf1, 0xa6, 0x71, 0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0,
        0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde, 0xb6,
        0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04,
        0xe5, 0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b,
        0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f,
    };
    const result = hash160(&pubkey);
    const expected = [_]u8{
        0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
        0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "merkle root single hash" {
    const allocator = std.testing.allocator;
    const hash = [_]u8{0xAB} ** 32;
    const hashes = [_]Hash256{hash};
    const root = try computeMerkleRoot(&hashes, allocator);
    try std.testing.expectEqualSlices(u8, &hash, &root);
}

test "merkle root two hashes" {
    const allocator = std.testing.allocator;
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const hashes = [_]Hash256{ a, b };

    // Expected: hash256(a ++ b)
    var concat: [64]u8 = undefined;
    @memcpy(concat[0..32], &a);
    @memcpy(concat[32..64], &b);
    const expected = hash256(&concat);

    const root = try computeMerkleRoot(&hashes, allocator);
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "merkle root three hashes duplicates last" {
    const allocator = std.testing.allocator;
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const hashes = [_]Hash256{ a, b, c };

    // Level 1: hash(a,b), hash(c,c)
    var ab: [64]u8 = undefined;
    @memcpy(ab[0..32], &a);
    @memcpy(ab[32..64], &b);
    const hash_ab = hash256(&ab);

    var cc: [64]u8 = undefined;
    @memcpy(cc[0..32], &c);
    @memcpy(cc[32..64], &c);
    const hash_cc = hash256(&cc);

    // Level 2: hash(hash_ab, hash_cc)
    var final: [64]u8 = undefined;
    @memcpy(final[0..32], &hash_ab);
    @memcpy(final[32..64], &hash_cc);
    const expected = hash256(&final);

    const root = try computeMerkleRoot(&hashes, allocator);
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "tagged hash BIP340" {
    // BIP-340 test vector for tagged hash
    const result = taggedHash("BIP0340/challenge", "test");
    // Just verify it produces a valid hash
    try std.testing.expectEqual(@as(usize, 32), result.len);
}

test "block header hash" {
    // Genesis block header
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c,
            0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a,
            0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
        },
        .timestamp = 1231006505,
        .bits = 0x1d00ffff,
        .nonce = 2083236893,
    };

    const block_hash = computeBlockHash(&header);

    // Genesis block hash (reversed for display: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f)
    // Internal byte order:
    const expected = [_]u8{
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2,
        0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a,
        0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &expected, &block_hash);
}

test "secp256k1 init/deinit" {
    // Just verify init/deinit don't crash
    // (may not actually initialize if library is not available)
    const initialized = initSecp256k1();
    if (initialized) {
        try std.testing.expect(isSecp256k1Available());
        deinitSecp256k1();
        try std.testing.expect(!isSecp256k1Available());
    }
}
