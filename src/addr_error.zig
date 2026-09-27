//! Bitcoin Core's address-decoding ERROR TEXT, byte-exact.
//!
//! `validateaddress` reports why an address is invalid: an `error` string and
//! an `error_locations` array.  Both come from Core's
//! `DecodeDestination(str, params, error_str, error_locations)`
//! (src/key_io.cpp) and, for a string carrying the network's Bech32 HRP,
//! `bech32::LocateErrors` (src/bech32.cpp).  This module reproduces that
//! decision tree so clearbit answers with Core's words, not a fixed catch-all.
//!
//! `coreDestinationError` returns null when Core would ACCEPT the string (the
//! caller then renders the valid-address object), else the message and the
//! error locations.
//!
//! LocateErrors: Core finds up to two substitution errors with a GF(1024)
//! syndrome decoder.  The checksum is affine in the data symbols, so the same
//! answer is reached here by precomputing each (position, value) error's
//! effect on the residue: one error is a table hit, two errors are one hit per
//! first-guess.  bech32 is a distance-5 code over these lengths, so a
//! correction of weight <= 2 is unique and both searches name the same
//! positions.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const NetParams = struct {
    hrp: []const u8,
    pubkey_prefix: u8,
    script_prefix: u8,
};

pub const AddrError = struct {
    msg: []u8,
    locations: []usize,

    pub fn deinit(self: *AddrError, allocator: std.mem.Allocator) void {
        allocator.free(self.msg);
        allocator.free(self.locations);
    }
};

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_LIMIT: usize = 90;
const CHECKSUM_SIZE: usize = 6;
const WITNESS_PROG_MAX_LEN: usize = 40;

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0b or c == 0x0c;
}

fn b58Value(c: u8) ?u8 {
    const i = std.mem.indexOfScalar(u8, BASE58_ALPHABET, c) orelse return null;
    return @intCast(i);
}

/// Core base58.cpp DecodeBase58: leading/trailing whitespace allowed, fails on
/// a NUL, a non-alphabet char, or a result longer than `max_ret_len`.
fn decodeBase58(allocator: std.mem.Allocator, str: []const u8, max_ret_len: usize) !?[]u8 {
    if (std.mem.indexOfScalar(u8, str, 0) != null) return null;
    var i: usize = 0;
    while (i < str.len and isSpace(str[i])) i += 1;
    var zeroes: usize = 0;
    while (i < str.len and str[i] == '1') {
        zeroes += 1;
        if (zeroes > max_ret_len) return null;
        i += 1;
    }
    const size = (str.len - i) * 733 / 1000 + 1;
    const b256 = try allocator.alloc(u8, size);
    defer allocator.free(b256);
    @memset(b256, 0);
    var length: usize = 0;
    while (i < str.len and !isSpace(str[i])) : (i += 1) {
        var carry: u32 = b58Value(str[i]) orelse return null;
        var k: usize = 0;
        var j: usize = size;
        while ((carry != 0 or k < length) and j > 0) : (k += 1) {
            j -= 1;
            carry += 58 * @as(u32, b256[j]);
            b256[j] = @intCast(carry % 256);
            carry /= 256;
        }
        length = k;
        if (length + zeroes > max_ret_len) return null;
    }
    while (i < str.len and isSpace(str[i])) i += 1;
    if (i != str.len) return null;
    const out = try allocator.alloc(u8, zeroes + length);
    @memset(out[0..zeroes], 0);
    @memcpy(out[zeroes..], b256[size - length ..]);
    return out;
}

/// Core DecodeBase58Check(str, ret, 21): payload without the 4-byte checksum.
fn decodeBase58Check(allocator: std.mem.Allocator, str: []const u8, max_ret_len: usize) !?[]u8 {
    const raw = (try decodeBase58(allocator, str, max_ret_len + 4)) orelse return null;
    if (raw.len < 4) {
        allocator.free(raw);
        return null;
    }
    const h = crypto.hash256(raw[0 .. raw.len - 4]);
    if (!std.mem.eql(u8, h[0..4], raw[raw.len - 4 ..])) {
        allocator.free(raw);
        return null;
    }
    const payload = try allocator.dupe(u8, raw[0 .. raw.len - 4]);
    allocator.free(raw);
    return payload;
}

fn pmStep(c: u32, v: u8) u32 {
    const c0: u32 = c >> 25;
    var r: u32 = ((c & 0x1ffffff) << 5) ^ v;
    if (c0 & 1 != 0) r ^= 0x3b6a57b2;
    if (c0 & 2 != 0) r ^= 0x26508e6d;
    if (c0 & 4 != 0) r ^= 0x1ea119fa;
    if (c0 & 8 != 0) r ^= 0x3d4233dd;
    if (c0 & 16 != 0) r ^= 0x2a1462b3;
    return r;
}

const Encoding = enum { bech32, bech32m };

fn encodingConstant(e: Encoding) u32 {
    return switch (e) {
        .bech32 => 1,
        .bech32m => 0x2bc830a3,
    };
}

/// Core PolyMod over PreparePolynomialCoefficients(hrp, values).
fn polymod(hrp: []const u8, values: []const u8) u32 {
    var c: u32 = 1;
    for (hrp) |ch| c = pmStep(c, ch >> 5);
    c = pmStep(c, 0);
    for (hrp) |ch| c = pmStep(c, ch & 0x1f);
    for (values) |v| c = pmStep(c, v);
    return c;
}

fn charsetRev(c: u8) ?u8 {
    const lc = std.ascii.toLower(c);
    const i = std.mem.indexOfScalar(u8, BECH32_CHARSET, lc) orelse return null;
    return @intCast(i);
}

/// Core bech32.cpp CheckCharacters: printable ASCII 33..126, no mixed case.
fn checkCharacters(str: []const u8, errors: *std.ArrayList(usize)) !bool {
    var lower = false;
    var upper = false;
    for (str, 0..) |c, i| {
        if (c >= 'a' and c <= 'z') {
            if (upper) try errors.append(i) else lower = true;
        } else if (c >= 'A' and c <= 'Z') {
            if (lower) try errors.append(i) else upper = true;
        } else if (c < 33 or c > 126) {
            try errors.append(i);
        }
    }
    return errors.items.len == 0;
}

const Decoded = struct { encoding: Encoding, hrp: []u8, data: []u8 };

/// Core bech32::Decode; null on any failure.  Caller frees hrp and data.
fn bech32Decode(allocator: std.mem.Allocator, str: []const u8) !?Decoded {
    var errs = std.ArrayList(usize).init(allocator);
    defer errs.deinit();
    if (!try checkCharacters(str, &errs)) return null;
    const pos = std.mem.lastIndexOfScalar(u8, str, '1') orelse return null;
    if (str.len > BECH32_LIMIT) return null;
    if (pos == 0 or pos + CHECKSUM_SIZE >= str.len) return null;
    const values = try allocator.alloc(u8, str.len - 1 - pos);
    errdefer allocator.free(values);
    for (values, 0..) |*v, i| v.* = charsetRev(str[i + pos + 1]) orelse {
        allocator.free(values);
        return null;
    };
    const hrp = try allocator.alloc(u8, pos);
    errdefer allocator.free(hrp);
    for (hrp, 0..) |*h, i| h.* = std.ascii.toLower(str[i]);
    const check = polymod(hrp, values);
    const enc: Encoding = if (check == encodingConstant(.bech32))
        .bech32
    else if (check == encodingConstant(.bech32m))
        .bech32m
    else {
        allocator.free(values);
        allocator.free(hrp);
        return null;
    };
    const data = try allocator.dupe(u8, values[0 .. values.len - CHECKSUM_SIZE]);
    allocator.free(values);
    return .{ .encoding = enc, .hrp = hrp, .data = data };
}

fn mkErr(allocator: std.mem.Allocator, msg: []const u8, locs: []const usize) !AddrError {
    return .{ .msg = try allocator.dupe(u8, msg), .locations = try allocator.dupe(usize, locs) };
}

/// Core bech32::LocateErrors.
fn locateErrors(allocator: std.mem.Allocator, str: []const u8) !AddrError {
    if (str.len > BECH32_LIMIT) {
        const locs = try allocator.alloc(usize, str.len - BECH32_LIMIT);
        for (locs, 0..) |*l, i| l.* = BECH32_LIMIT + i;
        return .{ .msg = try allocator.dupe(u8, "Bech32 string too long"), .locations = locs };
    }
    var errs = std.ArrayList(usize).init(allocator);
    defer errs.deinit();
    if (!try checkCharacters(str, &errs)) {
        return mkErr(allocator, "Invalid character or mixed case", errs.items);
    }
    const pos = std.mem.lastIndexOfScalar(u8, str, '1') orelse
        return mkErr(allocator, "Missing separator", &.{});
    if (pos == 0 or pos + CHECKSUM_SIZE >= str.len) {
        return mkErr(allocator, "Invalid separator position", &.{pos});
    }
    const hrp = try allocator.alloc(u8, pos);
    defer allocator.free(hrp);
    for (hrp, 0..) |*h, i| h.* = std.ascii.toLower(str[i]);
    const length = str.len - 1 - pos;
    const values = try allocator.alloc(u8, length);
    defer allocator.free(values);
    for (pos + 1..str.len) |i| {
        values[i - pos - 1] = charsetRev(str[i]) orelse
            return mkErr(allocator, "Invalid Base 32 character", &.{i});
    }

    // Residue contribution of error value e (1..31) at data index k: the
    // state after [e, 0 x (length-1-k)] from a zero start (PolyMod is affine,
    // so this is exactly how an error at k moves the residue).
    const n_cells = length * 31;
    const contrib = try allocator.alloc(u32, n_cells);
    defer allocator.free(contrib);
    for (0..length) |k| {
        for (1..32) |e| {
            var c: u32 = pmStep(0, @intCast(e));
            for (0..length - 1 - k) |_| c = pmStep(c, 0);
            contrib[k * 31 + (e - 1)] = c;
        }
    }
    var by_contrib = std.AutoHashMap(u32, usize).init(allocator);
    defer by_contrib.deinit();
    for (contrib, 0..) |c, idx| try by_contrib.put(c, idx / 31);

    var best: ?[]usize = null;
    defer if (best) |b| allocator.free(b);
    var best_enc: ?Encoding = null;
    const base = polymod(hrp, values);
    for ([_]Encoding{ .bech32, .bech32m }) |enc| {
        const residue = base ^ encodingConstant(enc);
        if (residue == 0) return mkErr(allocator, "", &.{});
        var possible = std.ArrayList(usize).init(allocator);
        defer possible.deinit();
        if (by_contrib.get(residue)) |k| {
            try possible.append(pos + 1 + k);
        } else {
            for (0..length) |k1| {
                var found = false;
                for (0..31) |e1| {
                    const rest = residue ^ contrib[k1 * 31 + e1];
                    if (by_contrib.get(rest)) |k2| {
                        if (k2 == k1) continue;
                        const a = @min(k1, k2);
                        const b = @max(k1, k2);
                        try possible.append(pos + 1 + a);
                        try possible.append(pos + 1 + b);
                        found = true;
                        break;
                    }
                }
                if (found) break;
            }
        }
        const cur_len: usize = if (best) |b| b.len else 0;
        if (cur_len == 0 or (possible.items.len != 0 and possible.items.len < cur_len)) {
            if (best) |b| allocator.free(b);
            best = try allocator.dupe(usize, possible.items);
            if (possible.items.len != 0) best_enc = enc;
        }
    }
    const msg: []const u8 = if (best_enc) |e| switch (e) {
        .bech32m => "Invalid Bech32m checksum",
        .bech32 => "Invalid Bech32 checksum",
    } else "Invalid checksum";
    const locs = best orelse try allocator.alloc(usize, 0);
    best = null;
    return .{ .msg = try allocator.dupe(u8, msg), .locations = locs };
}

/// Core key_io.cpp DecodeDestination error path.  null = Core accepts `str`.
pub fn coreDestinationError(allocator: std.mem.Allocator, str: []const u8, params: NetParams) !?AddrError {
    const hrp = params.hrp;
    const is_bech32 = str.len >= hrp.len and std.ascii.eqlIgnoreCase(str[0..hrp.len], hrp);

    if (!is_bech32) {
        if (try decodeBase58Check(allocator, str, 21)) |data| {
            defer allocator.free(data);
            if (data.len == 21 and (data[0] == params.pubkey_prefix or data[0] == params.script_prefix)) return null;
            if (data.len >= 1 and (data[0] == params.script_prefix or data[0] == params.pubkey_prefix)) {
                return try mkErr(allocator, "Invalid length for Base58 address (P2PKH or P2SH)", &.{});
            }
            return try mkErr(allocator, "Invalid or unsupported Base58-encoded address.", &.{});
        }
        if (try decodeBase58(allocator, str, 100)) |raw| {
            allocator.free(raw);
            return try mkErr(allocator, "Invalid checksum or length of Base58 address (P2PKH or P2SH)", &.{});
        }
        return try mkErr(allocator, "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", &.{});
    }

    const dec = (try bech32Decode(allocator, str)) orelse {
        var e = try locateErrors(allocator, str);
        if (e.msg.len == 0) {
            // LocateErrors found no error for a string Decode rejected; Core
            // then reports an empty error string (never reached for inputs
            // Decode rejects on checksum alone).
            e.deinit(allocator);
            return try mkErr(allocator, "", &.{});
        }
        return e;
    };
    defer allocator.free(dec.hrp);
    defer allocator.free(dec.data);
    if (dec.data.len == 0) return try mkErr(allocator, "Empty Bech32 data section", &.{});
    if (!std.mem.eql(u8, dec.hrp, hrp)) {
        const m = try std.fmt.allocPrint(allocator, "Invalid or unsupported prefix for Segwit (Bech32) address (expected {s}, got {s}).", .{ hrp, dec.hrp });
        return .{ .msg = m, .locations = try allocator.alloc(usize, 0) };
    }
    const version = dec.data[0];
    if (version == 0 and dec.encoding != .bech32) return try mkErr(allocator, "Version 0 witness address must use Bech32 checksum", &.{});
    if (version != 0 and dec.encoding != .bech32m) return try mkErr(allocator, "Version 1+ witness address must use Bech32m checksum", &.{});

    // ConvertBits<5, 8, false>
    var prog = std.ArrayList(u8).init(allocator);
    defer prog.deinit();
    var acc: u32 = 0;
    var bits: u5 = 0;
    for (dec.data[1..]) |v| {
        acc = ((acc << 5) | v) & 0xfff;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            try prog.append(@intCast((acc >> bits) & 0xff));
        }
    }
    if (bits >= 5 or ((acc << (8 - @as(u5, bits))) & 0xff) != 0) {
        return try mkErr(allocator, "Invalid padding in Bech32 data section", &.{});
    }
    const n = prog.items.len;
    const byte_str: []const u8 = if (n == 1) "byte" else "bytes";
    if (version == 0) {
        if (n == 20 or n == 32) return null;
        const m = try std.fmt.allocPrint(allocator, "Invalid Bech32 v0 address program size ({d} {s}), per BIP141", .{ n, byte_str });
        return .{ .msg = m, .locations = try allocator.alloc(usize, 0) };
    }
    if (version == 1 and n == 32) return null;
    if (version == 1 and n == 2 and prog.items[0] == 0x4e and prog.items[1] == 0x73) return null; // P2A
    if (version > 16) return try mkErr(allocator, "Invalid Bech32 address witness version", &.{});
    if (n < 2 or n > WITNESS_PROG_MAX_LEN) {
        const m = try std.fmt.allocPrint(allocator, "Invalid Bech32 address program size ({d} {s})", .{ n, byte_str });
        return .{ .msg = m, .locations = try allocator.alloc(usize, 0) };
    }
    return null;
}

test "addr_error base58 and bech32 messages match Core" {
    const a = std.testing.allocator;
    const main_net = NetParams{ .hrp = "bc", .pubkey_prefix = 0x00, .script_prefix = 0x05 };
    const Case = struct { s: []const u8, msg: ?[]const u8, locs: []const usize = &.{} };
    const cases = [_]Case{
        .{ .s = "notanaddress", .msg = "Invalid checksum or length of Base58 address (P2PKH or P2SH)" },
        .{ .s = "0OIl", .msg = "Invalid or unsupported Segwit (Bech32) or Base58 encoding." },
        .{ .s = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", .msg = null },
        .{ .s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", .msg = null },
        // one substituted char (last 't4' -> 't5'): Core locates index 41.
        .{ .s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", .msg = "Invalid Bech32 checksum", .locs = &.{41} },
        .{ .s = "bc1", .msg = "Invalid separator position", .locs = &.{2} },
        .{ .s = "bcx", .msg = "Missing separator" },
        .{ .s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb", .msg = "Invalid Base 32 character", .locs = &.{41} },
        .{ .s = "bC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", .msg = "Invalid character or mixed case", .locs = &.{1} },
        // two substituted chars: Core's two-error syndrome search.
        .{ .s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3aa", .msg = "Invalid Bech32 checksum", .locs = &.{ 40, 41 } },
        .{ .s = "bc1zw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", .msg = "Invalid checksum" },
        .{ .s = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", .msg = "Invalid or unsupported Segwit (Bech32) or Base58 encoding." },
        .{ .s = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", .msg = "Invalid or unsupported Base58-encoded address." },
        .{ .s = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL", .msg = "Invalid checksum or length of Base58 address (P2PKH or P2SH)" },
        .{ .s = "1111111111111111111114oLvT2", .msg = null },
    };
    for (cases) |c| {
        var r = try coreDestinationError(a, c.s, main_net);
        if (c.msg) |want| {
            try std.testing.expect(r != null);
            defer r.?.deinit(a);
            try std.testing.expectEqualStrings(want, r.?.msg);
            try std.testing.expectEqualSlices(usize, c.locs, r.?.locations);
        } else {
            if (r) |*e| {
                std.debug.print("unexpected error for {s}: {s}\n", .{ c.s, e.msg });
                e.deinit(a);
                return error.TestUnexpectedResult;
            }
        }
    }
}
