//! ASMap — IP-address-to-ASN mapping for peer bucketing
//!
//! Implements the Bitcoin Core asmap binary trie format:
//!   bitcoin-core/src/util/asmap.h/cpp
//!
//! The asmap file is a bit-packed bytecode trie.  Each IP lookup walks the
//! trie one bit at a time (MSB-first in the IP, LSB-first in the asmap bytes)
//! and terminates at a RETURN instruction whose argument is the ASN.
//!
//! Instruction encoding (2-bit type from LSB-first stream):
//!   RETURN  [0]     — followed by an ASN integer; terminates the lookup.
//!   JUMP    [1,0]   — consumes one IP bit; if 1, skip `offset` bits forward.
//!   MATCH   [1,1,0] — compare next N IP bits against a pattern; mismatch → default_asn.
//!   DEFAULT [1,1,1] — set the default fallback ASN; continues execution.
//!
//! Variable-length integer encoding:
//!   Each integer type has a minimum value, a set of bit-class sizes, and is
//!   encoded as (k one-bits)(optional zero-bit)(k-class mantissa in big-endian).
//!   RETURN/DEFAULT ASNs start at 1; JUMP offsets start at 17; MATCH values at 2.

const std = @import("std");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum asmap file size (8 MiB). Matches Bitcoin Core's effective limit.
pub const MAX_ASMAP_FILESIZE: usize = 8_388_608;

/// Sentinel for decode errors (Core uses 0xFFFFFFFF).
const INVALID: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// Bit-reader helpers
// ---------------------------------------------------------------------------

/// Read one bit from `bytes` at bit position `bitpos` using LSB-first
/// (little-endian) ordering within each byte.  Increments `bitpos`.
/// Mirrors Core's `ConsumeBitLE`.
inline fn consumeBitLE(bitpos: *usize, bytes: []const u8) bool {
    const bit: bool = ((bytes[bitpos.* / 8] >> @intCast(bitpos.* % 8)) & 1) != 0;
    bitpos.* += 1;
    return bit;
}

/// Read one bit from `bytes` at bit position `bitpos` using MSB-first
/// (big-endian) ordering within each byte.  Increments `bitpos`.
/// Used for the IP address bits.  Mirrors Core's `ConsumeBitBE`.
inline fn consumeBitBE(bitpos: *u8, bytes: []const u8) bool {
    const bit: bool = ((bytes[bitpos.* / 8] >> @intCast(7 - (bitpos.* % 8))) & 1) != 0;
    bitpos.* += 1;
    return bit;
}

// ---------------------------------------------------------------------------
// Variable-length integer decoder
// ---------------------------------------------------------------------------

/// Decode a variable-length integer from the asmap bit stream.
/// `minval`    — minimum encodable value for this type.
/// `bit_sizes` — slice of mantissa sizes for each encoding class.
///
/// Encoding: k leading "1" bits select class k; a "0" bit (unless the last
/// class) separates the prefix from the mantissa; mantissa is big-endian
/// within the class.
fn decodeBits(bitpos: *usize, data: []const u8, minval: u32, bit_sizes: []const u8) u32 {
    const endpos: usize = data.len * 8;
    var val: u32 = minval;
    for (bit_sizes, 0..) |class_bits, i| {
        const is_last = (i == bit_sizes.len - 1);
        var continuation: bool = false;
        if (!is_last) {
            if (bitpos.* >= endpos) break; // EOF in exponent
            continuation = consumeBitLE(bitpos, data);
        }
        if (continuation) {
            val += (@as(u32, 1) << @intCast(class_bits));
        } else {
            // Decode mantissa in big-endian within this class.
            var b: u8 = 0;
            while (b < class_bits) : (b += 1) {
                if (bitpos.* >= endpos) return INVALID; // EOF in mantissa
                const mbit = consumeBitLE(bitpos, data);
                const shift: u5 = @intCast(class_bits - 1 - b);
                val +%= if (mbit) (@as(u32, 1) << shift) else 0;
            }
            return val;
        }
    }
    return INVALID; // EOF in exponent
}

// ---------------------------------------------------------------------------
// Per-type decoders (encoding tables from asmap.cpp)
// ---------------------------------------------------------------------------

// Instruction type: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
const TYPE_BIT_SIZES = [_]u8{ 0, 0, 1 };

const Instruction = enum(u32) {
    RETURN = 0,
    JUMP = 1,
    MATCH = 2,
    DEFAULT = 3,
};

fn decodeType(bitpos: *usize, data: []const u8) ?Instruction {
    const raw = decodeBits(bitpos, data, 0, &TYPE_BIT_SIZES);
    if (raw == INVALID) return null;
    return switch (raw) {
        0 => .RETURN,
        1 => .JUMP,
        2 => .MATCH,
        3 => .DEFAULT,
        else => null,
    };
}

// ASN encoding: values 1..~16.7M
const ASN_BIT_SIZES = [_]u8{ 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 };

fn decodeASN(bitpos: *usize, data: []const u8) u32 {
    return decodeBits(bitpos, data, 1, &ASN_BIT_SIZES);
}

// MATCH argument: values in [2, 511]; highest set bit determines match length.
const MATCH_BIT_SIZES = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

fn decodeMatch(bitpos: *usize, data: []const u8) u32 {
    return decodeBits(bitpos, data, 2, &MATCH_BIT_SIZES);
}

// JUMP offset: values in [17, ...] (large variable-length).
const JUMP_BIT_SIZES = [_]u8{
    5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30,
};

fn decodeJump(bitpos: *usize, data: []const u8) u32 {
    return decodeBits(bitpos, data, 17, &JUMP_BIT_SIZES);
}

// ---------------------------------------------------------------------------
// bit_width helper (std.math.log2 floor + 1 for non-zero)
// ---------------------------------------------------------------------------

/// Number of bits required to represent `v` (0 → 0, 1 → 1, 2 → 2, 3 → 2, 4 → 3, …).
/// Mirrors C++ `std::bit_width(v)`.
inline fn bitWidth(v: u32) u6 {
    if (v == 0) return 0;
    return @intCast(32 - @clz(v));
}

// ---------------------------------------------------------------------------
// Public: interpret
// ---------------------------------------------------------------------------

/// Walk the asmap bytecode trie for a 128-bit IP address (stored big-endian,
/// i.e. `ip[0]` is the most-significant byte).
///
/// Returns the ASN if a RETURN instruction is reached, 0 on no-match,
/// or 0 on any decoding error (matches Core's assert-and-return-0 path).
///
/// Reference: bitcoin-core/src/util/asmap.cpp `Interpret()`
pub fn interpret(asmap: []const u8, ip: [16]u8) u32 {
    var pos: usize = 0;
    const endpos: usize = asmap.len * 8;
    var ip_bit: u8 = 0;
    const ip_bits_end: u8 = 128; // 16 bytes × 8 bits
    var default_asn: u32 = 0;

    while (pos < endpos) {
        const opcode = decodeType(&pos, asmap) orelse break;
        switch (opcode) {
            .RETURN => {
                const asn = decodeASN(&pos, asmap);
                if (asn == INVALID) break;
                return asn;
            },
            .JUMP => {
                const jump = decodeJump(&pos, asmap);
                if (jump == INVALID) break;
                if (ip_bit == ip_bits_end) break; // no IP bits left
                if (@as(i64, @intCast(jump)) >= @as(i64, @intCast(endpos - pos))) break; // jump past EOF
                if (consumeBitBE(&ip_bit, &ip)) {
                    pos += jump; // IP bit = 1: take right branch
                }
                // IP bit = 0: fall through to left branch
            },
            .MATCH => {
                const match = decodeMatch(&pos, asmap);
                if (match == INVALID) break;
                const matchlen: u8 = @intCast(@as(u32, bitWidth(match)) - 1);
                if ((@as(u32, ip_bits_end) - @as(u32, ip_bit)) < @as(u32, matchlen)) break; // not enough bits
                var bit: u8 = 0;
                while (bit < matchlen) : (bit += 1) {
                    const ip_mbit = consumeBitBE(&ip_bit, &ip);
                    const pattern_bit = ((match >> @intCast(matchlen - 1 - bit)) & 1) != 0;
                    if (ip_mbit != pattern_bit) return default_asn; // pattern mismatch
                }
                // pattern matched — continue
            },
            .DEFAULT => {
                const asn = decodeASN(&pos, asmap);
                if (asn == INVALID) break;
                default_asn = asn;
            },
        }
    }
    // Reached EOF without RETURN, or encountered a decode error.
    // A sanity-checked asmap should never reach here; return 0 (unknown ASN).
    return 0;
}

// ---------------------------------------------------------------------------
// Public: sanityCheckAsmap
// ---------------------------------------------------------------------------

/// Validate the asmap bytecode by simulating all possible execution paths.
/// `bits` is the number of IP bits the trie is expected to consume (128 for
/// IPv6 / IPv4-mapped).  Returns true iff the bytecode is well-formed.
///
/// Reference: bitcoin-core/src/util/asmap.cpp `SanityCheckAsmap()`
pub fn sanityCheckAsmap(asmap: []const u8, bits_arg: i32) bool {
    var pos: usize = 0;
    const endpos: usize = asmap.len * 8;

    // Stack of (jump_target_bit_offset, remaining_ip_bits) for pending branches.
    var jumps = std.BoundedArray(struct { target: u32, bits: i32 }, 256).init(0) catch return false;

    var bits: i32 = bits_arg;
    var prev_opcode: Instruction = .JUMP;
    var had_incomplete_match: bool = false;

    while (pos != endpos) {
        // Detect a jump landing into the middle of the previous instruction.
        if (jumps.len > 0 and pos >= jumps.get(jumps.len - 1).target) return false;

        const opcode = decodeType(&pos, asmap) orelse return false;
        switch (opcode) {
            .RETURN => {
                // DEFAULT immediately before RETURN is redundant (could be just RETURN).
                if (prev_opcode == .DEFAULT) return false;
                const asn = decodeASN(&pos, asmap);
                if (asn == INVALID) return false;
                if (jumps.len == 0) {
                    // No more branches; we should be at EOF (allow ≤7 zero padding bits).
                    if (endpos - pos > 7) return false;
                    while (pos != endpos) {
                        if (consumeBitLE(&pos, asmap)) return false; // nonzero padding
                    }
                    return true;
                } else {
                    // Continue with the queued jump target.
                    const entry = jumps.get(jumps.len - 1);
                    if (pos != entry.target) return false; // unreachable code between RETURN and jump target
                    bits = entry.bits;
                    jumps.len -= 1;
                    prev_opcode = .JUMP;
                }
            },
            .JUMP => {
                const jump = decodeJump(&pos, asmap);
                if (jump == INVALID) return false;
                if (@as(i64, @intCast(jump)) > @as(i64, @intCast(endpos - pos))) return false; // out of range
                if (bits == 0) return false; // consuming past end of input
                bits -= 1;
                const jump_offset: u32 = @intCast(pos + jump);
                // Jumps must be non-overlapping with each other.
                if (jumps.len > 0 and jump_offset >= jumps.get(jumps.len - 1).target) return false;
                jumps.append(.{ .target = jump_offset, .bits = bits }) catch return false;
                prev_opcode = .JUMP;
            },
            .MATCH => {
                const match = decodeMatch(&pos, asmap);
                if (match == INVALID) return false;
                const matchlen: i32 = @as(i32, bitWidth(match)) - 1;
                if (prev_opcode != .MATCH) had_incomplete_match = false;
                // Within consecutive MATCHes only at most one may be shorter than 8 bits.
                if (matchlen < 8 and had_incomplete_match) return false;
                had_incomplete_match = (matchlen < 8);
                if (bits < matchlen) return false;
                bits -= matchlen;
                prev_opcode = .MATCH;
            },
            .DEFAULT => {
                // Two consecutive DEFAULTs could be merged into one.
                if (prev_opcode == .DEFAULT) return false;
                const asn = decodeASN(&pos, asmap);
                if (asn == INVALID) return false;
                prev_opcode = .DEFAULT;
            },
        }
    }
    return false; // reached EOF without a RETURN
}

/// Convenience wrapper: validate asmap for 128-bit (IPv6) input.
/// Mirrors Core's `CheckStandardAsmap(data)`.
pub fn checkStandardAsmap(data: []const u8) bool {
    return sanityCheckAsmap(data, 128);
}

// ---------------------------------------------------------------------------
// Public: loadAsmap
// ---------------------------------------------------------------------------

/// Read the asmap file at `path` into a freshly allocated slice.
/// Returns an error if the file doesn't exist, exceeds `MAX_ASMAP_FILESIZE`,
/// or fails the standard sanity check.  Caller owns the returned slice.
pub fn loadAsmap(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    if (stat.size > MAX_ASMAP_FILESIZE) return error.AsmapFileTooLarge;
    if (stat.size == 0) return error.AsmapFileEmpty;

    const buf = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(buf);

    const n = try file.readAll(buf);
    if (n != stat.size) return error.AsmapReadTruncated;

    if (!checkStandardAsmap(buf)) return error.AsmapSanityCheckFailed;

    return buf;
}

// ---------------------------------------------------------------------------
// Public: getMappedAS — convenience wrapper
// ---------------------------------------------------------------------------

/// Look up the ASN for a 16-byte big-endian IPv6/IPv4-mapped address.
/// Returns 0 if `asmap_data` is empty, or when the address is unrouted.
pub fn getMappedAS(asmap_data: []const u8, ip: [16]u8) u32 {
    if (asmap_data.len == 0) return 0;
    return interpret(asmap_data, ip);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "asmap: bitWidth helper" {
    const testing = std.testing;
    try testing.expectEqual(@as(u6, 0), bitWidth(0));
    try testing.expectEqual(@as(u6, 1), bitWidth(1));
    try testing.expectEqual(@as(u6, 2), bitWidth(2));
    try testing.expectEqual(@as(u6, 2), bitWidth(3));
    try testing.expectEqual(@as(u6, 3), bitWidth(4));
    try testing.expectEqual(@as(u6, 9), bitWidth(256));
}

test "asmap: interpret returns 0 for empty asmap" {
    const testing = std.testing;
    const ip = [16]u8{ 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectEqual(@as(u32, 0), interpret(&[_]u8{}, ip));
}

test "asmap: getMappedAS returns 0 for empty asmap" {
    const testing = std.testing;
    const ip = [16]u8{ 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectEqual(@as(u32, 0), getMappedAS(&[_]u8{}, ip));
}

// Core reference test vector from bitcoin-core/src/test/netbase_tests.cpp
// `asmap_test_vectors` — 128 ranges, up to 20-bit AS numbers.
// Exported as pub so tests_w115_asmap.zig can build the same asmap bytes.
pub const TEST_ASMAP_HEX =
    "fd38d50f7d5d665357f64bba6bfc190d6078a7e68e5d3ac032edf47f8b5755f87881bfd3633d9aa7c1fa279b3" ++
    "6fe26c63bbc9de44e0f04e5a382d8e1cddbe1c26653bc939d4327f287e8b4d1f8aff33176787cb0ff7cb28e3f" ++
    "daef0f8f47357f801c9f7ff7a99f7f9c9f99de7f3156ae00f23eb27a303bc486aa3ccc31ec19394c2f8a53ddd" ++
    "ea3cc56257f3b7e9b1f488be9c1137db823759aa4e071eef2e984aaf97b52d5f88d0f373dd190fe45e06efef1" ++
    "df7278be680a73a74c76db4dd910f1d30752c57fe2bc9f079f1a1e1b036c2a69219f11c5e11980a3fa51f4f82" ++
    "d36373de73b1863a8c27e36ae0e4f705be3d76ecff038a75bc0f92ba7e7f6f4080f1c47c34d095367ecf4406c" ++
    "1e3bbc17ba4d6f79ea3f031b876799ac268b1e0ea9babf0f9a8e5f6c55e363c6363df46afc696d7afceaf49b6" ++
    "e62df9e9dc27e70664cafe5c53df66dd0b8237678ada90e73f05ec60e6f6e96c3cbb1ea2f9dece115d5bdba10" ++
    "33e53662a7d72a29477b5beb35710591d3e23e5f0379baea62ffdee535bcdf879cbf69b88d7ea37c8015381cf" ++
    "63dc33d28f757a4a5e15d6a08";

// Keep the private alias so in-file tests still compile without change.
const CORE_ASMAP_HEX = TEST_ASMAP_HEX;

fn parseCoreAsmapHex(allocator: std.mem.Allocator) ![]u8 {
    return parseTestAsmapHex(allocator);
}

/// Parse `TEST_ASMAP_HEX` into a freshly allocated byte slice.
/// Caller owns the returned memory (free with allocator.free).
/// Exported so external test files can load the canonical test vector.
pub fn parseTestAsmapHex(allocator: std.mem.Allocator) ![]u8 {
    const hex = TEST_ASMAP_HEX;
    const n = hex.len / 2;
    const buf = try allocator.alloc(u8, n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        buf[i] = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    }
    return buf;
}

fn parseIPv6(comptime s: []const u8) [16]u8 {
    // Parse a simple IPv6 hex string like "00d0:d493:faa0:..." into 16 bytes.
    // Expand short groups with leading zeros.
    var out = [_]u8{0} ** 16;
    var byte_i: usize = 0;
    var it = std.mem.splitScalar(u8, s, ':');
    while (it.next()) |group| {
        if (byte_i >= 16) break;
        const v = std.fmt.parseInt(u16, group, 16) catch 0;
        out[byte_i] = @intCast(v >> 8);
        out[byte_i + 1] = @intCast(v & 0xFF);
        byte_i += 2;
    }
    return out;
}

test "asmap: checkStandardAsmap passes on Core reference vector" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const asmap = try parseCoreAsmapHex(allocator);
    defer allocator.free(asmap);
    try testing.expect(checkStandardAsmap(asmap));
}

test "asmap: Core reference vector — IPv6 lookup vectors" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const asmap = try parseCoreAsmapHex(allocator);
    defer allocator.free(asmap);

    // Test vectors from bitcoin-core/src/test/netbase_tests.cpp:asmap_test_vectors
    const cases = .{
        .{ parseIPv6("0000:1559:0183:3728:224c:65a5:62e6:e991"), @as(u32, 961340) },
        .{ parseIPv6("00d0:d493:faa0:8609:e927:8b75:293c:f5a4"), @as(u32, 961340) },
        .{ parseIPv6("02a0:026f:8b2c:2ee7:c7d1:3b24:4705:3f7f"), @as(u32, 693761) },
        .{ parseIPv6("0a77:7cd4:4be5:a449:89f2:3212:78c6:ee38"), @as(u32, 0) },
        .{ parseIPv6("1336:1ad6:2f26:4fe3:d809:7321:6e0d:4615"), @as(u32, 672176) },
        .{ parseIPv6("1d56:abd0:a52f:a8d5:d5a7:a610:581d:d792"), @as(u32, 499880) },
        .{ parseIPv6("378e:7290:54e5:bd36:4760:971c:e9b9:570d"), @as(u32, 0) },
        .{ parseIPv6("406c:820b:272a:c045:b74e:fc0a:9ef2:cecc"), @as(u32, 248495) },
        .{ parseIPv6("46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac"), @as(u32, 248495) },
        .{ parseIPv6("50d2:3db6:52fa:02e7:12ec:5bc4:1bd1:49f9"), @as(u32, 124471) },
        .{ parseIPv6("53e1:1812:0ffa:dccf:f9f2:64be:75fa:0795"), @as(u32, 539993) },
        .{ parseIPv6("544d:eeba:3990:35d1:ad66:f9a3:576d:8617"), @as(u32, 374443) },
        .{ parseIPv6("6a53:40dc:8f1d:3ffa:efeb:3aa3:df88:b94b"), @as(u32, 435070) },
        .{ parseIPv6("87aa:d1c9:9edb:91e7:aab1:9eb9:baa0:de18"), @as(u32, 244121) },
        .{ parseIPv6("9f00:48fa:88e3:4b67:a6f3:e6d2:5cc1:5be2"), @as(u32, 862116) },
        .{ parseIPv6("c49f:9cc6:86ad:ba08:4580:315e:dbd1:8a62"), @as(u32, 969411) },
        .{ parseIPv6("dff5:8021:061d:b17d:406d:7888:fdac:4a20"), @as(u32, 969411) },
        .{ parseIPv6("e888:6791:2960:d723:bcfd:47e1:2d8c:599f"), @as(u32, 824019) },
        .{ parseIPv6("ffff:d499:8c4b:4941:bc81:d5b9:b51e:85a8"), @as(u32, 824019) },
    };

    inline for (cases) |c| {
        const ip: [16]u8 = c[0];
        const expected: u32 = c[1];
        const got = interpret(asmap, ip);
        try testing.expectEqual(expected, got);
    }
}
