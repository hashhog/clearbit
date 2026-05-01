// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// SPDX-License-Identifier: MIT
//
// Zig port of bitcoin-core/src/compressor.{h,cpp}.
//
// Implements `CompressAmount` / `DecompressAmount` and the `ScriptCompression`
// formatter used by `Coin::Serialize` (via `TxOutCompression`). This is the
// exact byte-for-byte format consumed by Bitcoin Core's `dumptxoutset` /
// `loadtxoutset` and stored in the `chainstate` LevelDB.

const std = @import("std");
const serialize = @import("serialize.zig");

/// Number of "special" script type tags reserved by `ScriptCompression`.
/// Reference: bitcoin-core/src/compressor.h `ScriptCompression::nSpecialScripts`.
pub const N_SPECIAL_SCRIPTS: u32 = 6;

/// Compressed-script wire size for each of the 6 special tags. For tags
/// 0/1 the payload is a 20-byte hash160; for tags 2..=5 the payload is a
/// 32-byte pubkey-x. The leading tag byte is included in the on-wire
/// encoding via VARINT and is not counted here.
/// Reference: bitcoin-core/src/compressor.cpp `GetSpecialScriptSize`.
pub fn getSpecialScriptSize(n_size: u32) u32 {
    return switch (n_size) {
        0, 1 => 20,
        2, 3, 4, 5 => 32,
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// CompressAmount / DecompressAmount
// ---------------------------------------------------------------------------

/// Compress a satoshi amount. See compressor.cpp for the algorithm; this is
/// a 1:1 translation.
pub fn compressAmount(n_in: u64) u64 {
    if (n_in == 0) return 0;
    var n = n_in;
    var e: u64 = 0;
    while ((n % 10) == 0 and e < 9) {
        n /= 10;
        e += 1;
    }
    if (e < 9) {
        const d: u64 = n % 10;
        std.debug.assert(d >= 1 and d <= 9);
        n /= 10;
        return 1 + (n * 9 + d - 1) * 10 + e;
    } else {
        return 1 + (n - 1) * 10 + 9;
    }
}

/// Inverse of `compressAmount`. Bytewise identical output to Core's
/// `DecompressAmount` for any well-formed compressed value.
pub fn decompressAmount(x_in: u64) u64 {
    if (x_in == 0) return 0;
    var x = x_in - 1;
    const e: u64 = x % 10;
    x /= 10;
    var n: u64 = 0;
    if (e < 9) {
        const d: u64 = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    var ee = e;
    while (ee > 0) : (ee -= 1) {
        n *= 10;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Script-shape detection (P2PKH / P2SH / P2PK)
// ---------------------------------------------------------------------------
//
// Mirrors compressor.cpp::IsToKeyID / IsToScriptID / IsToPubKey. We
// intentionally reproduce the exact byte checks Core performs — script
// classifiers elsewhere in clearbit are looser (they accept variants that
// CompressScript rejects), and a mismatch here would corrupt the snapshot
// on the wire.

const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_EQUAL: u8 = 0x87;
const OP_CHECKSIG: u8 = 0xac;

fn isToKeyID(script: []const u8) ?[20]u8 {
    if (script.len == 25 and script[0] == OP_DUP and script[1] == OP_HASH160 and script[2] == 20 and script[23] == OP_EQUALVERIFY and script[24] == OP_CHECKSIG) {
        return script[3..23].*;
    }
    return null;
}

fn isToScriptID(script: []const u8) ?[20]u8 {
    if (script.len == 23 and script[0] == OP_HASH160 and script[1] == 20 and script[22] == OP_EQUAL) {
        return script[2..22].*;
    }
    return null;
}

/// Match a P2PK script with a 33-byte (compressed) or 65-byte (uncompressed)
/// pubkey followed by OP_CHECKSIG. Returns the full pubkey on a hit.
fn isToPubKey(script: []const u8) ?struct { pubkey: [65]u8, len: u8 } {
    if (script.len == 35 and script[0] == 33 and script[34] == OP_CHECKSIG and (script[1] == 0x02 or script[1] == 0x03)) {
        var out: [65]u8 = undefined;
        @memcpy(out[0..33], script[1..34]);
        return .{ .pubkey = out, .len = 33 };
    }
    if (script.len == 67 and script[0] == 65 and script[66] == OP_CHECKSIG and script[1] == 0x04) {
        // Core also requires `pubkey.IsFullyValid()` here, which delegates
        // to libsecp256k1. We mirror that requirement at the call site
        // (`compressScript` checks the secp256k1 parser) so this helper
        // returns the candidate without validating it.
        var out: [65]u8 = undefined;
        @memcpy(out[0..65], script[1..66]);
        return .{ .pubkey = out, .len = 65 };
    }
    return null;
}

/// Validate a 65-byte uncompressed secp256k1 public key. Required by
/// `IsToPubKey` / `compressScript` to decide whether the legacy P2PK form
/// is compressible (matches Core's `CPubKey::IsFullyValid`).
fn isFullyValidUncompressedPubkey(pubkey: *const [65]u8) bool {
    // We piggyback on the libsecp256k1 binding already linked into clearbit
    // via `crypto.zig`. A direct C call would also work, but `crypto.zig`
    // owns the secp256k1 context lifetime, so go through it.
    const crypto = @import("crypto.zig");
    return crypto.parseUncompressedPubkey65(pubkey) != null;
}

// ---------------------------------------------------------------------------
// CompressScript
// ---------------------------------------------------------------------------

/// Output buffer for `compressScript`. Up to 33 bytes (compressed pubkey).
pub const CompressedScript = struct {
    bytes: [33]u8,
    len: u8,

    pub fn slice(self: *const CompressedScript) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Compress a scriptPubKey to one of the 6 special wire forms. Returns
/// `null` if the script does not match any compressible shape, in which
/// case the caller must fall back to the raw-script encoding (`size +
/// nSpecialScripts` followed by the raw bytes).
/// Reference: bitcoin-core/src/compressor.cpp `CompressScript`.
pub fn compressScript(script: []const u8) ?CompressedScript {
    if (isToKeyID(script)) |hash| {
        var out = CompressedScript{ .bytes = undefined, .len = 21 };
        out.bytes[0] = 0x00;
        @memcpy(out.bytes[1..21], &hash);
        return out;
    }
    if (isToScriptID(script)) |hash| {
        var out = CompressedScript{ .bytes = undefined, .len = 21 };
        out.bytes[0] = 0x01;
        @memcpy(out.bytes[1..21], &hash);
        return out;
    }
    if (isToPubKey(script)) |pk| {
        var out = CompressedScript{ .bytes = undefined, .len = 33 };
        if (pk.len == 33) {
            // Compressed pubkey: tag = lead byte (0x02/0x03), payload = X(32).
            out.bytes[0] = pk.pubkey[0];
            @memcpy(out.bytes[1..33], pk.pubkey[1..33]);
            return out;
        } else {
            std.debug.assert(pk.len == 65);
            // Uncompressed pubkey: tag = 0x04 | (Y_lsb), payload = X(32).
            // Core also requires pk.IsFullyValid() before compressing.
            if (!isFullyValidUncompressedPubkey(&pk.pubkey)) return null;
            out.bytes[0] = 0x04 | (pk.pubkey[64] & 0x01);
            @memcpy(out.bytes[1..33], pk.pubkey[1..33]);
            return out;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Serializer / deserializer wrappers (TxOutCompression in Core)
// ---------------------------------------------------------------------------

/// Write a scriptPubKey using Core's `ScriptCompression` formatter.
///   * Compressible: write the 21- or 33-byte CompressedScript verbatim
///     (the leading tag byte is interpreted as a VARINT < N_SPECIAL_SCRIPTS).
///   * Otherwise: write VARINT(size + N_SPECIAL_SCRIPTS) followed by the
///     raw script bytes.
pub fn writeCompressedScript(writer: *serialize.Writer, script: []const u8) !void {
    if (compressScript(script)) |compr| {
        try writer.writeBytes(compr.slice());
        return;
    }
    const wire_size: u64 = @as(u64, @intCast(script.len)) + N_SPECIAL_SCRIPTS;
    try writer.writeVarInt(wire_size);
    try writer.writeBytes(script);
}

/// Read a scriptPubKey written by `writeCompressedScript` / Core's
/// `ScriptCompression::Unser`. Returns the *decompressed* scriptPubKey
/// (i.e. the on-chain bytes, not the special-form payload).
///
/// The caller owns the returned buffer.
pub fn readCompressedScript(
    reader: *serialize.Reader,
    allocator: std.mem.Allocator,
) ![]u8 {
    const n_size_u64 = try reader.readVarInt();
    if (n_size_u64 < N_SPECIAL_SCRIPTS) {
        const n_size: u32 = @intCast(n_size_u64);
        const payload_size = getSpecialScriptSize(n_size);
        const payload = try reader.readBytes(payload_size);
        return try decompressScript(allocator, n_size, payload);
    }
    const raw_len_u64 = n_size_u64 - N_SPECIAL_SCRIPTS;
    // Match Core: clamp absurdly long scripts to a single OP_RETURN and
    // skip the rest.  MAX_SCRIPT_SIZE = 10000.
    if (raw_len_u64 > 10000) {
        // Skip raw bytes; emit a 1-byte OP_RETURN script.
        _ = try reader.readBytes(@intCast(raw_len_u64));
        const out = try allocator.alloc(u8, 1);
        out[0] = 0x6a; // OP_RETURN
        return out;
    }
    const raw_len: usize = @intCast(raw_len_u64);
    const raw = try reader.readBytes(raw_len);
    const out = try allocator.alloc(u8, raw_len);
    @memcpy(out, raw);
    return out;
}

/// Reverse of `compressScript` for the special-form payloads. The
/// `n_size` argument is the leading tag (the VARINT byte before the
/// payload); `payload` is the fixed-size hash or pubkey-X.
///
/// Tag 0 → P2PKH (25 bytes). Tag 1 → P2SH (23 bytes). Tags 2/3 → compressed
/// P2PK (35 bytes). Tags 4/5 → uncompressed P2PK (67 bytes); requires
/// libsecp256k1 to decompress the pubkey.
pub fn decompressScript(
    allocator: std.mem.Allocator,
    n_size: u32,
    payload: []const u8,
) ![]u8 {
    switch (n_size) {
        0x00 => {
            std.debug.assert(payload.len == 20);
            const out = try allocator.alloc(u8, 25);
            out[0] = OP_DUP;
            out[1] = OP_HASH160;
            out[2] = 20;
            @memcpy(out[3..23], payload[0..20]);
            out[23] = OP_EQUALVERIFY;
            out[24] = OP_CHECKSIG;
            return out;
        },
        0x01 => {
            std.debug.assert(payload.len == 20);
            const out = try allocator.alloc(u8, 23);
            out[0] = OP_HASH160;
            out[1] = 20;
            @memcpy(out[2..22], payload[0..20]);
            out[22] = OP_EQUAL;
            return out;
        },
        0x02, 0x03 => {
            std.debug.assert(payload.len == 32);
            const out = try allocator.alloc(u8, 35);
            out[0] = 33;
            out[1] = @intCast(n_size);
            @memcpy(out[2..34], payload[0..32]);
            out[34] = OP_CHECKSIG;
            return out;
        },
        0x04, 0x05 => {
            std.debug.assert(payload.len == 32);
            // Reconstruct compressed pubkey: prefix = (n_size - 2) ∈ {0x02, 0x03},
            // X = payload. Decompress via libsecp256k1.
            var compressed: [33]u8 = undefined;
            compressed[0] = @intCast(n_size - 2);
            @memcpy(compressed[1..33], payload[0..32]);
            const crypto = @import("crypto.zig");
            const decompressed = crypto.decompressPubkey33(&compressed) orelse return error.InvalidPubKey;
            const out = try allocator.alloc(u8, 67);
            out[0] = 65;
            @memcpy(out[1..66], &decompressed);
            out[66] = OP_CHECKSIG;
            return out;
        },
        else => return error.InvalidSpecialScript,
    }
}

// ---------------------------------------------------------------------------
// Coin (TxOut + height/coinbase) serialization
// ---------------------------------------------------------------------------
//
// Format: VARINT(code) || VARINT(CompressAmount(value)) || ScriptCompression(scriptPubKey)
// where code = (height << 1) | coinbase.
// Reference: bitcoin-core/src/coins.h Coin::Serialize.

pub fn writeCoin(
    writer: *serialize.Writer,
    height: u32,
    is_coinbase: bool,
    value: i64,
    script_pubkey: []const u8,
) !void {
    const code: u64 = (@as(u64, height) << 1) | (if (is_coinbase) @as(u64, 1) else 0);
    try writer.writeVarInt(code);
    // Amount must be non-negative (assured by the consensus path; the
    // chainstate never holds spent or negative outputs).
    std.debug.assert(value >= 0);
    try writer.writeVarInt(compressAmount(@as(u64, @intCast(value))));
    try writeCompressedScript(writer, script_pubkey);
}

pub const ReadCoin = struct {
    height: u32,
    is_coinbase: bool,
    value: i64,
    script_pubkey: []u8, // owned by caller
};

pub fn readCoin(
    reader: *serialize.Reader,
    allocator: std.mem.Allocator,
) !ReadCoin {
    const code = try reader.readVarInt();
    const height: u32 = @intCast(code >> 1);
    const is_coinbase = (code & 1) != 0;
    const compressed_value = try reader.readVarInt();
    const value: i64 = @intCast(decompressAmount(compressed_value));
    const script = try readCompressedScript(reader, allocator);
    return ReadCoin{
        .height = height,
        .is_coinbase = is_coinbase,
        .value = value,
        .script_pubkey = script,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CompressAmount round-trips against the Core test vectors" {
    // bitcoin-core/src/test/compress_tests.cpp:31-67 — golden table.
    const cases = [_]struct { uncompressed: u64, compressed: u64 }{
        .{ .uncompressed = 0, .compressed = 0x0 },
        .{ .uncompressed = 1, .compressed = 0x1 },
        .{ .uncompressed = 1_000_000, .compressed = 0x7 },
        .{ .uncompressed = 100_000_000, .compressed = 0x9 },
        .{ .uncompressed = 50_000_000_00, .compressed = 0x32 },
        .{ .uncompressed = 21_000_000_00_000_000, .compressed = 0x1406f40 },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.compressed, compressAmount(c.uncompressed));
        try std.testing.expectEqual(c.uncompressed, decompressAmount(c.compressed));
    }
}

test "CompressAmount round-trip — exhaustive small values" {
    var i: u64 = 0;
    while (i < 100_000) : (i += 1) {
        try std.testing.expectEqual(i, decompressAmount(compressAmount(i)));
    }
}

test "CompressScript — P2PKH" {
    var script: [25]u8 = undefined;
    script[0] = 0x76;
    script[1] = 0xa9;
    script[2] = 20;
    @memset(script[3..23], 0xab);
    script[23] = 0x88;
    script[24] = 0xac;
    const compr = compressScript(&script).?;
    try std.testing.expectEqual(@as(u8, 21), compr.len);
    try std.testing.expectEqual(@as(u8, 0x00), compr.bytes[0]);
    try std.testing.expectEqualSlices(u8, script[3..23], compr.bytes[1..21]);
}

test "CompressScript — P2SH" {
    var script: [23]u8 = undefined;
    script[0] = 0xa9;
    script[1] = 20;
    @memset(script[2..22], 0xcd);
    script[22] = 0x87;
    const compr = compressScript(&script).?;
    try std.testing.expectEqual(@as(u8, 21), compr.len);
    try std.testing.expectEqual(@as(u8, 0x01), compr.bytes[0]);
    try std.testing.expectEqualSlices(u8, script[2..22], compr.bytes[1..21]);
}

test "CompressScript — P2WPKH does not compress" {
    // SegWit v0 P2WPKH: OP_0 <20-byte hash>. Not compressible.
    var script: [22]u8 = undefined;
    script[0] = 0x00;
    script[1] = 20;
    @memset(script[2..22], 0x11);
    try std.testing.expect(compressScript(&script) == null);
}

test "CompressScript — OP_RETURN does not compress" {
    var script: [10]u8 = undefined;
    script[0] = 0x6a;
    @memset(script[1..10], 0x42);
    try std.testing.expect(compressScript(&script) == null);
}

test "writeCompressedScript / readCompressedScript — P2PKH round-trip" {
    const allocator = std.testing.allocator;

    var script: [25]u8 = undefined;
    script[0] = 0x76;
    script[1] = 0xa9;
    script[2] = 20;
    @memset(script[3..23], 0xee);
    script[23] = 0x88;
    script[24] = 0xac;

    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try writeCompressedScript(&w, &script);

    // Wire form: 1-byte tag (0x00) + 20-byte hash = 21 bytes.
    try std.testing.expectEqual(@as(usize, 21), w.getWritten().len);
    try std.testing.expectEqual(@as(u8, 0x00), w.getWritten()[0]);

    var r = serialize.Reader{ .data = w.getWritten() };
    const decoded = try readCompressedScript(&r, allocator);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &script, decoded);
}

test "writeCompressedScript / readCompressedScript — non-special round-trip" {
    const allocator = std.testing.allocator;

    // P2WPKH-style script: not compressible — falls into the raw branch.
    var script: [22]u8 = undefined;
    script[0] = 0x00;
    script[1] = 20;
    @memset(script[2..22], 0x33);

    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try writeCompressedScript(&w, &script);

    // Wire form: VARINT(22 + 6 = 28) + 22 bytes. VARINT(28) = 0x1c (1 byte).
    try std.testing.expectEqual(@as(usize, 23), w.getWritten().len);
    try std.testing.expectEqual(@as(u8, 0x1c), w.getWritten()[0]);

    var r = serialize.Reader{ .data = w.getWritten() };
    const decoded = try readCompressedScript(&r, allocator);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &script, decoded);
}

test "writeCoin / readCoin round-trip" {
    const allocator = std.testing.allocator;

    var script: [25]u8 = undefined;
    script[0] = 0x76;
    script[1] = 0xa9;
    script[2] = 20;
    @memset(script[3..23], 0x77);
    script[23] = 0x88;
    script[24] = 0xac;

    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try writeCoin(&w, 800_000, true, 6_250_000_000, &script);

    var r = serialize.Reader{ .data = w.getWritten() };
    const coin = try readCoin(&r, allocator);
    defer allocator.free(coin.script_pubkey);

    try std.testing.expectEqual(@as(u32, 800_000), coin.height);
    try std.testing.expect(coin.is_coinbase);
    try std.testing.expectEqual(@as(i64, 6_250_000_000), coin.value);
    try std.testing.expectEqualSlices(u8, &script, coin.script_pubkey);
}

test "writeVarInt round-trip — Core test vectors" {
    const allocator = std.testing.allocator;
    const cases = [_]u64{ 0, 1, 0x7F, 0x80, 0x1234, 0xFFFF, 0xFFFFFFFF, 0x1234567890ABCDEF };
    for (cases) |v| {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeVarInt(v);
        var r = serialize.Reader{ .data = w.getWritten() };
        const got = try r.readVarInt();
        try std.testing.expectEqual(v, got);
        try std.testing.expect(r.isAtEnd());
    }
}
