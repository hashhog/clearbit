const std = @import("std");
const crypto = @import("crypto.zig");
const types = @import("types.zig");

// ============================================================================
// Base58 Encoding
// ============================================================================

/// Base58 alphabet (no 0, O, I, l to avoid visual ambiguity)
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reverse lookup table for Base58 decoding
const BASE58_DECODE_TABLE: [256]i8 = blk: {
    var table: [256]i8 = .{-1} ** 256;
    for (BASE58_ALPHABET, 0..) |c, i| {
        table[c] = @intCast(i);
    }
    break :blk table;
};

/// Encode bytes to Base58.
/// Algorithm: treat input as a big-endian big integer, repeatedly divide by 58.
/// Prepend '1' for each leading zero byte in the input.
pub fn base58Encode(data: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    if (data.len == 0) {
        return try allocator.dupe(u8, "");
    }

    // Count leading zeros
    var leading_zeros: usize = 0;
    for (data) |byte| {
        if (byte != 0) break;
        leading_zeros += 1;
    }

    // Allocate enough space for the result (worst case: log_58(256) * len ≈ 1.37 * len)
    const size = data.len * 138 / 100 + 1;
    var buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    @memset(buf, 0);

    // Process each byte (treating input as big-endian number)
    var length: usize = 0;
    for (data) |byte| {
        var carry: u32 = byte;

        // Multiply current result by 256 and add carry
        var i: usize = 0;
        var j: usize = size;
        while (j > 0) {
            j -= 1;
            if (carry == 0 and i >= length) break;
            carry += @as(u32, buf[j]) * 256;
            buf[j] = @intCast(carry % 58);
            carry /= 58;
            i += 1;
        }
        length = i;
    }

    // Skip leading zeros in buffer
    var start: usize = size - length;
    while (start < size and buf[start] == 0) {
        start += 1;
    }

    // Allocate result
    const result_len = leading_zeros + (size - start);
    var result = try allocator.alloc(u8, result_len);

    // Add '1' for each leading zero byte
    for (0..leading_zeros) |i| {
        result[i] = '1';
    }

    // Convert to Base58 characters
    for (start..size, leading_zeros..) |i, j| {
        result[j] = BASE58_ALPHABET[buf[i]];
    }

    return result;
}

/// Decode Base58 string to bytes.
pub fn base58Decode(encoded: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    if (encoded.len == 0) {
        return try allocator.dupe(u8, "");
    }

    // Count leading '1's
    var leading_ones: usize = 0;
    for (encoded) |c| {
        if (c != '1') break;
        leading_ones += 1;
    }

    // Allocate enough space for the result
    const size = encoded.len * 733 / 1000 + 1; // log_256(58) ≈ 0.733
    var buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    @memset(buf, 0);

    // Process each character
    var length: usize = 0;
    for (encoded) |c| {
        const value = BASE58_DECODE_TABLE[c];
        if (value < 0) {
            return error.InvalidBase58Character;
        }

        var carry: u32 = @intCast(value);

        // Multiply current result by 58 and add carry
        var i: usize = 0;
        var j: usize = size;
        while (j > 0) {
            j -= 1;
            if (carry == 0 and i >= length) break;
            carry += @as(u32, buf[j]) * 58;
            buf[j] = @intCast(carry % 256);
            carry /= 256;
            i += 1;
        }
        length = i;
    }

    // Skip leading zeros in buffer
    var start: usize = size - length;
    while (start < size and buf[start] == 0) {
        start += 1;
    }

    // Allocate result
    const result_len = leading_ones + (size - start);
    var result = try allocator.alloc(u8, result_len);

    // Add zero bytes for each leading '1'
    for (0..leading_ones) |i| {
        result[i] = 0;
    }

    // Copy remaining bytes
    @memcpy(result[leading_ones..], buf[start..size]);

    return result;
}

// ============================================================================
// Base58Check Encoding
// ============================================================================

/// Base58Check encode: payload = version_byte ++ data, append first 4 bytes of hash256(payload).
pub fn base58CheckEncode(version: u8, data: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    var payload = try allocator.alloc(u8, 1 + data.len + 4);
    defer allocator.free(payload);

    payload[0] = version;
    @memcpy(payload[1..][0..data.len], data);

    const checksum = crypto.hash256(payload[0 .. 1 + data.len]);
    @memcpy(payload[1 + data.len ..][0..4], checksum[0..4]);

    return base58Encode(payload, allocator);
}

/// Base58Check decode: decode, verify last 4 bytes are hash256(rest)[0..4].
pub fn base58CheckDecode(encoded: []const u8, allocator: std.mem.Allocator) !struct { version: u8, data: []const u8 } {
    const decoded = try base58Decode(encoded, allocator);
    errdefer allocator.free(decoded);

    if (decoded.len < 5) {
        allocator.free(decoded);
        return error.InvalidBase58CheckLength;
    }

    const payload_len = decoded.len - 4;
    const payload = decoded[0..payload_len];
    const checksum = decoded[payload_len..];

    const computed_checksum = crypto.hash256(payload);
    if (!std.mem.eql(u8, checksum, computed_checksum[0..4])) {
        allocator.free(decoded);
        return error.InvalidBase58CheckChecksum;
    }

    // Extract version and data
    const version = payload[0];
    const data = try allocator.dupe(u8, payload[1..]);
    allocator.free(decoded);

    return .{ .version = version, .data = data };
}

// ============================================================================
// Bech32/Bech32m Encoding (BIP-173/BIP-350)
// ============================================================================

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1; // Bech32
const BECH32M_CONST: u32 = 0x2bc830a3; // Bech32m

/// Reverse lookup table for Bech32 decoding
const BECH32_DECODE_TABLE: [256]i8 = blk: {
    var table: [256]i8 = .{-1} ** 256;
    for (BECH32_CHARSET, 0..) |c, i| {
        table[c] = @intCast(i);
        // Also allow uppercase
        if (c >= 'a' and c <= 'z') {
            table[c - 'a' + 'A'] = @intCast(i);
        }
    }
    break :blk table;
};

/// Bech32 polymod computation for checksum.
fn bech32Polymod(values: []const u5) u32 {
    const GEN = [5]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    var chk: u32 = 1;
    for (values) |v| {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ @as(u32, v);
        for (0..5) |i| {
            if ((b >> @intCast(i)) & 1 == 1) {
                chk ^= GEN[i];
            }
        }
    }
    return chk;
}

/// Expand human-readable part for checksum computation.
fn hrpExpand(hrp: []const u8, allocator: std.mem.Allocator) ![]const u5 {
    var result = try allocator.alloc(u5, hrp.len * 2 + 1);

    // High bits of each character
    for (hrp, 0..) |c, i| {
        result[i] = @intCast(c >> 5);
    }
    // Separator
    result[hrp.len] = 0;
    // Low bits of each character
    for (hrp, 0..) |c, i| {
        result[hrp.len + 1 + i] = @truncate(c & 0x1f);
    }

    return result;
}

/// Create checksum for Bech32/Bech32m.
fn createChecksum(hrp: []const u8, data: []const u5, bech32m: bool, allocator: std.mem.Allocator) ![6]u5 {
    const hrp_expanded = try hrpExpand(hrp, allocator);
    defer allocator.free(hrp_expanded);

    var values = try allocator.alloc(u5, hrp_expanded.len + data.len + 6);
    defer allocator.free(values);

    @memcpy(values[0..hrp_expanded.len], hrp_expanded);
    @memcpy(values[hrp_expanded.len..][0..data.len], data);
    @memset(values[hrp_expanded.len + data.len ..], 0);

    const polymod = bech32Polymod(values) ^ (if (bech32m) BECH32M_CONST else BECH32_CONST);

    var checksum: [6]u5 = undefined;
    for (0..6) |i| {
        checksum[i] = @truncate((polymod >> @intCast(5 * (5 - i))) & 31);
    }
    return checksum;
}

/// Verify checksum for Bech32/Bech32m.
fn verifyChecksum(hrp: []const u8, data: []const u5, allocator: std.mem.Allocator) !enum { valid_bech32, valid_bech32m, invalid } {
    const hrp_expanded = try hrpExpand(hrp, allocator);
    defer allocator.free(hrp_expanded);

    var values = try allocator.alloc(u5, hrp_expanded.len + data.len);
    defer allocator.free(values);

    @memcpy(values[0..hrp_expanded.len], hrp_expanded);
    @memcpy(values[hrp_expanded.len..], data);

    const polymod = bech32Polymod(values);

    if (polymod == BECH32_CONST) return .valid_bech32;
    if (polymod == BECH32M_CONST) return .valid_bech32m;
    return .invalid;
}

/// Convert between bit widths (8-bit to 5-bit and back).
fn convertBits(
    data: []const u8,
    comptime from_bits: u4,
    comptime to_bits: u4,
    pad: bool,
    allocator: std.mem.Allocator,
) ![]const u8 {
    var acc: u32 = 0;
    var bits: u5 = 0;

    const max_acc = (1 << (from_bits + to_bits - 1)) - 1;
    const max_v = (1 << to_bits) - 1;

    // Calculate output size
    const total_bits = data.len * from_bits;
    const out_size = (total_bits + to_bits - 1) / to_bits + 1;

    var result = try allocator.alloc(u8, out_size);
    var result_len: usize = 0;

    for (data) |b| {
        acc = ((acc << from_bits) | b) & max_acc;
        bits += from_bits;

        while (bits >= to_bits) {
            bits -= to_bits;
            result[result_len] = @intCast((acc >> bits) & max_v);
            result_len += 1;
        }
    }

    if (pad) {
        if (bits > 0) {
            result[result_len] = @intCast((acc << (to_bits - bits)) & max_v);
            result_len += 1;
        }
    } else if (bits >= from_bits or ((acc << (to_bits - bits)) & max_v) != 0) {
        allocator.free(result);
        return error.InvalidPadding;
    }

    // Shrink to actual size
    if (result_len < result.len) {
        const new_result = try allocator.realloc(result, result_len);
        return new_result;
    }

    return result[0..result_len];
}

/// Convert 5-bit array back to 8-bit bytes.
fn convertBits5to8(data: []const u5, allocator: std.mem.Allocator) ![]const u8 {
    var acc: u32 = 0;
    var bits: u5 = 0;

    const out_size = (data.len * 5) / 8;
    var result = try allocator.alloc(u8, out_size);
    var result_len: usize = 0;

    for (data) |b| {
        acc = (acc << 5) | b;
        bits += 5;

        while (bits >= 8) {
            bits -= 8;
            result[result_len] = @intCast((acc >> bits) & 0xff);
            result_len += 1;
        }
    }

    // Check padding
    const mask: u32 = (@as(u32, 1) << @as(u5, @intCast(bits))) - 1;
    if (bits >= 5 or (acc & mask) != 0) {
        allocator.free(result);
        return error.InvalidPadding;
    }

    // Shrink to actual size
    if (result_len < result.len) {
        const new_result = try allocator.realloc(result, result_len);
        return new_result;
    }

    return result[0..result_len];
}

/// Encode a segwit address.
/// hrp is "bc" for mainnet, "tb" for testnet.
/// witness_version is 0 for P2WPKH/P2WSH, 1 for P2TR.
/// witness_program is 20 bytes for P2WPKH, 32 bytes for P2WSH/P2TR.
/// Use Bech32 for version 0, Bech32m for version 1+.
pub fn segwitEncode(
    hrp: []const u8,
    witness_version: u5,
    witness_program: []const u8,
    allocator: std.mem.Allocator,
) ![]const u8 {
    // Validate witness program length
    if (witness_program.len < 2 or witness_program.len > 40) {
        return error.InvalidWitnessProgramLength;
    }

    // Version 0 requires 20 or 32 bytes
    if (witness_version == 0 and witness_program.len != 20 and witness_program.len != 32) {
        return error.InvalidWitnessProgramLength;
    }

    // Convert 8-bit to 5-bit
    const program_5bit = try convertBits(witness_program, 8, 5, true, allocator);
    defer allocator.free(program_5bit);

    // Build data array: version + program
    var data = try allocator.alloc(u5, 1 + program_5bit.len);
    defer allocator.free(data);
    data[0] = witness_version;
    for (program_5bit, 0..) |b, i| {
        data[1 + i] = @intCast(b);
    }

    // Create checksum (Bech32m for v1+, Bech32 for v0)
    const bech32m = witness_version > 0;
    const checksum = try createChecksum(hrp, data, bech32m, allocator);

    // Build result string: hrp + '1' + data + checksum
    const result_len = hrp.len + 1 + data.len + 6;
    var result = try allocator.alloc(u8, result_len);

    @memcpy(result[0..hrp.len], hrp);
    result[hrp.len] = '1';

    for (data, 0..) |d, i| {
        result[hrp.len + 1 + i] = BECH32_CHARSET[d];
    }
    for (checksum, 0..) |c, i| {
        result[hrp.len + 1 + data.len + i] = BECH32_CHARSET[c];
    }

    return result;
}

/// Decode a segwit address. Returns witness version and program.
pub fn segwitDecode(addr: []const u8, allocator: std.mem.Allocator) !struct {
    hrp: []const u8,
    version: u5,
    program: []const u8,
} {
    // Find separator '1'
    var sep_pos: ?usize = null;
    for (0..addr.len) |i| {
        const idx = addr.len - 1 - i;
        if (addr[idx] == '1') {
            sep_pos = idx;
            break;
        }
    }

    if (sep_pos == null or sep_pos.? < 1 or sep_pos.? + 7 > addr.len) {
        return error.InvalidBech32Address;
    }

    const hrp = addr[0..sep_pos.?];
    const data_part = addr[sep_pos.? + 1 ..];

    // Decode data part
    var data = try allocator.alloc(u5, data_part.len);
    defer allocator.free(data);

    // Check case consistency and decode
    var has_lower = false;
    var has_upper = false;
    for (data_part, 0..) |c, i| {
        if (c >= 'a' and c <= 'z') has_lower = true;
        if (c >= 'A' and c <= 'Z') has_upper = true;

        const value = BECH32_DECODE_TABLE[c];
        if (value < 0) {
            return error.InvalidBech32Character;
        }
        data[i] = @intCast(value);
    }

    if (has_lower and has_upper) {
        return error.MixedCaseBech32;
    }

    // Normalize HRP to lowercase for checksum verification
    var hrp_lower = try allocator.alloc(u8, hrp.len);
    defer allocator.free(hrp_lower);
    for (hrp, 0..) |c, i| {
        hrp_lower[i] = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
    }

    // Verify checksum
    const checksum_result = try verifyChecksum(hrp_lower, data, allocator);
    if (checksum_result == .invalid) {
        return error.InvalidBech32Checksum;
    }

    if (data.len < 7) {
        return error.InvalidBech32DataLength;
    }

    // Extract witness version and program
    const witness_version = data[0];

    // Version 0 requires Bech32, version 1+ requires Bech32m
    if (witness_version == 0 and checksum_result != .valid_bech32) {
        return error.InvalidBech32Variant;
    }
    if (witness_version > 0 and checksum_result != .valid_bech32m) {
        return error.InvalidBech32Variant;
    }

    // Convert 5-bit data (excluding version and checksum) to 8-bit
    const program_5bit = data[1 .. data.len - 6];
    const program = try convertBits5to8(program_5bit, allocator);
    errdefer allocator.free(program);

    // Validate program length
    if (program.len < 2 or program.len > 40) {
        allocator.free(program);
        return error.InvalidWitnessProgramLength;
    }

    if (witness_version == 0 and program.len != 20 and program.len != 32) {
        allocator.free(program);
        return error.InvalidWitnessProgramLength;
    }

    return .{
        .hrp = try allocator.dupe(u8, hrp_lower),
        .version = witness_version,
        .program = program,
    };
}

// ============================================================================
// Address Types
// ============================================================================

pub const AddressType = enum {
    p2pkh, // Pay to Public Key Hash (1...)
    p2sh, // Pay to Script Hash (3...)
    p2wpkh, // Pay to Witness Public Key Hash (bc1q...)
    p2wsh, // Pay to Witness Script Hash (bc1q... 62 chars)
    p2tr, // Pay to Taproot (bc1p...)
};

pub const Network = enum {
    mainnet,
    testnet,
};

pub const Address = struct {
    addr_type: AddressType,
    hash: []const u8, // 20 bytes for P2PKH/P2WPKH, 32 bytes for P2WSH/P2TR
    network: Network,

    /// Encode to string representation.
    pub fn encode(self: *const Address, allocator: std.mem.Allocator) ![]const u8 {
        switch (self.addr_type) {
            .p2pkh => return base58CheckEncode(
                if (self.network == .mainnet) 0x00 else 0x6f,
                self.hash,
                allocator,
            ),
            .p2sh => return base58CheckEncode(
                if (self.network == .mainnet) 0x05 else 0xc4,
                self.hash,
                allocator,
            ),
            .p2wpkh, .p2wsh => return segwitEncode(
                if (self.network == .mainnet) "bc" else "tb",
                0,
                self.hash,
                allocator,
            ),
            .p2tr => return segwitEncode(
                if (self.network == .mainnet) "bc" else "tb",
                1,
                self.hash,
                allocator,
            ),
        }
    }

    /// Decode from string representation.
    pub fn decode(addr_str: []const u8, allocator: std.mem.Allocator) !Address {
        // Check if it's a Bech32/Bech32m address
        if (addr_str.len >= 4) {
            const prefix_lower = blk: {
                var p: [4]u8 = undefined;
                for (addr_str[0..4], 0..) |c, i| {
                    p[i] = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
                }
                break :blk p;
            };

            if (std.mem.eql(u8, prefix_lower[0..3], "bc1") or std.mem.eql(u8, prefix_lower[0..3], "tb1")) {
                const result = try segwitDecode(addr_str, allocator);
                defer allocator.free(result.hrp);
                errdefer allocator.free(result.program);

                const network: Network = if (std.mem.eql(u8, result.hrp, "bc")) .mainnet else .testnet;

                const addr_type: AddressType = switch (result.version) {
                    0 => if (result.program.len == 20) .p2wpkh else .p2wsh,
                    1 => .p2tr,
                    else => return error.UnsupportedWitnessVersion,
                };

                return .{
                    .addr_type = addr_type,
                    .hash = result.program,
                    .network = network,
                };
            }
        }

        // Try Base58Check decode
        const result = try base58CheckDecode(addr_str, allocator);
        errdefer allocator.free(result.data);

        const network: Network = switch (result.version) {
            0x00, 0x05 => .mainnet,
            0x6f, 0xc4 => .testnet,
            else => return error.UnknownVersionByte,
        };

        const addr_type: AddressType = switch (result.version) {
            0x00, 0x6f => .p2pkh,
            0x05, 0xc4 => .p2sh,
            else => return error.UnknownVersionByte,
        };

        // Validate hash length
        if (result.data.len != 20) {
            allocator.free(result.data);
            return error.InvalidHashLength;
        }

        return .{
            .addr_type = addr_type,
            .hash = result.data,
            .network = network,
        };
    }

    /// Free the hash memory.
    pub fn deinit(self: *const Address, allocator: std.mem.Allocator) void {
        allocator.free(self.hash);
    }
};

/// Create a P2PKH address from a public key.
pub fn createP2PKH(pubkey: []const u8, network: Network, allocator: std.mem.Allocator) !Address {
    const hash = crypto.hash160(pubkey);
    const hash_copy = try allocator.dupe(u8, &hash);
    return .{
        .addr_type = .p2pkh,
        .hash = hash_copy,
        .network = network,
    };
}

/// Create a P2WPKH address from a compressed public key.
pub fn createP2WPKH(pubkey: []const u8, network: Network, allocator: std.mem.Allocator) !Address {
    if (pubkey.len != 33) {
        return error.InvalidPublicKeyLength;
    }
    const hash = crypto.hash160(pubkey);
    const hash_copy = try allocator.dupe(u8, &hash);
    return .{
        .addr_type = .p2wpkh,
        .hash = hash_copy,
        .network = network,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "base58 encode/decode round-trip" {
    const allocator = std.testing.allocator;

    const test_cases = [_][]const u8{
        "",
        &[_]u8{0x00},
        &[_]u8{ 0x00, 0x00 },
        &[_]u8{ 0x00, 0x01 },
        &[_]u8{ 0x61, 0x62, 0x63 }, // "abc"
        &[_]u8{0xff} ** 32,
    };

    for (test_cases) |data| {
        const encoded = try base58Encode(data, allocator);
        defer allocator.free(encoded);

        const decoded = try base58Decode(encoded, allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, data, decoded);
    }
}

test "base58 known values" {
    const allocator = std.testing.allocator;

    // Test vector: empty string
    {
        const encoded = try base58Encode("", allocator);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, "", encoded);
    }

    // Test vector: single zero byte -> "1"
    {
        const encoded = try base58Encode(&[_]u8{0x00}, allocator);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, "1", encoded);
    }

    // Test vector: "Hello World!"
    {
        const encoded = try base58Encode("Hello World!", allocator);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, "2NEpo7TZRRrLZSi2U", encoded);
    }
}

test "base58check encode/decode round-trip" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{
        0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
        0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
    };

    const encoded = try base58CheckEncode(0x00, &hash, allocator);
    defer allocator.free(encoded);

    const decoded = try base58CheckDecode(encoded, allocator);
    defer allocator.free(decoded.data);

    try std.testing.expectEqual(@as(u8, 0x00), decoded.version);
    try std.testing.expectEqualSlices(u8, &hash, decoded.data);
}

test "known P2PKH address - genesis coinbase" {
    const allocator = std.testing.allocator;

    // hash160 of Satoshi's genesis coinbase pubkey
    const hash = [_]u8{
        0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
        0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
    };

    const encoded = try base58CheckEncode(0x00, &hash, allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", encoded);
}

test "known Bech32 address - BIP-173 test vector" {
    const allocator = std.testing.allocator;

    // Test vector from BIP-173
    const program = [_]u8{
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
    };

    const encoded = try segwitEncode("bc", 0, &program, allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", encoded);
}

test "bech32 decode - BIP-173 test vector" {
    const allocator = std.testing.allocator;

    const result = try segwitDecode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", allocator);
    defer allocator.free(result.hrp);
    defer allocator.free(result.program);

    try std.testing.expectEqualSlices(u8, "bc", result.hrp);
    try std.testing.expectEqual(@as(u5, 0), result.version);

    const expected_program = [_]u8{
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
    };
    try std.testing.expectEqualSlices(u8, &expected_program, result.program);
}

test "known Bech32m address - taproot" {
    const allocator = std.testing.allocator;

    // Test vector from BIP-350: witness v1 (taproot)
    // This is a 32-byte x-only pubkey
    const program = [_]u8{
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb,
        0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    };

    const encoded = try segwitEncode("bc", 1, &program, allocator);
    defer allocator.free(encoded);

    // BIP-350 test vector
    try std.testing.expectEqualSlices(u8, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", encoded);
}

test "bech32m decode - taproot" {
    const allocator = std.testing.allocator;

    const result = try segwitDecode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", allocator);
    defer allocator.free(result.hrp);
    defer allocator.free(result.program);

    try std.testing.expectEqualSlices(u8, "bc", result.hrp);
    try std.testing.expectEqual(@as(u5, 1), result.version);
    try std.testing.expectEqual(@as(usize, 32), result.program.len);
}

test "address encode - p2pkh mainnet" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{
        0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
        0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
    };

    const addr = Address{
        .addr_type = .p2pkh,
        .hash = &hash,
        .network = .mainnet,
    };

    const encoded = try addr.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", encoded);
}

test "address encode - p2wpkh mainnet" {
    const allocator = std.testing.allocator;

    const hash = [_]u8{
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
    };

    const addr = Address{
        .addr_type = .p2wpkh,
        .hash = &hash,
        .network = .mainnet,
    };

    const encoded = try addr.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", encoded);
}

test "address decode - p2pkh" {
    const allocator = std.testing.allocator;

    const addr = try Address.decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", allocator);
    defer addr.deinit(allocator);

    try std.testing.expectEqual(AddressType.p2pkh, addr.addr_type);
    try std.testing.expectEqual(Network.mainnet, addr.network);

    const expected_hash = [_]u8{
        0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
        0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
    };
    try std.testing.expectEqualSlices(u8, &expected_hash, addr.hash);
}

test "address decode - p2wpkh" {
    const allocator = std.testing.allocator;

    const addr = try Address.decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", allocator);
    defer addr.deinit(allocator);

    try std.testing.expectEqual(AddressType.p2wpkh, addr.addr_type);
    try std.testing.expectEqual(Network.mainnet, addr.network);

    const expected_hash = [_]u8{
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
        0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
    };
    try std.testing.expectEqualSlices(u8, &expected_hash, addr.hash);
}

test "address decode - p2tr" {
    const allocator = std.testing.allocator;

    const addr = try Address.decode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", allocator);
    defer addr.deinit(allocator);

    try std.testing.expectEqual(AddressType.p2tr, addr.addr_type);
    try std.testing.expectEqual(Network.mainnet, addr.network);
    try std.testing.expectEqual(@as(usize, 32), addr.hash.len);
}

test "address round-trip encode/decode" {
    const allocator = std.testing.allocator;

    const test_addrs = [_][]const u8{
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", // P2PKH mainnet
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // P2WPKH mainnet
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", // P2TR mainnet
    };

    for (test_addrs) |addr_str| {
        const addr = try Address.decode(addr_str, allocator);
        defer addr.deinit(allocator);

        const encoded = try addr.encode(allocator);
        defer allocator.free(encoded);

        try std.testing.expectEqualSlices(u8, addr_str, encoded);
    }
}
