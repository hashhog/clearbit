//! Regression tests for the getpeerinfo subver (user-agent) DoS.
//!
//! A peer's user-agent ("subver") is attacker-controlled: it arrives raw in the
//! VERSION message.  clearbit previously surfaced `version_info.user_agent`
//! UNSANITIZED into the `getpeerinfo` JSON response (rpc.zig handleGetPeerInfo,
//! `"subver":"{s}"`), so a malicious peer advertising a subver containing
//!   - a JSON metacharacter (`"` / `\`), or
//!   - a control byte (e.g. 0x01), or
//!   - a non-UTF8 byte (e.g. 0xff / 0xfe)
//! could poison the operator's RPC output — producing INVALID JSON (a remote
//! DoS on the RPC endpoint) or breaking any client that consumes it.
//!
//! Bitcoin Core sanitizes once at receipt: `cleanSubVer = SanitizeString(...)`
//! with SAFE_CHARS_DEFAULT (net_processing.cpp:3637, util/strencodings.cpp:31),
//! keeping ONLY `[A-Za-z0-9]` + " .,;-_/:?@()", and length-bounds the raw
//! subver to MAX_SUBVERSION_LENGTH=256.
//!
//! clearbit now does the same in `peer.sanitizeSubVer` + `Peer.clean_subver`.
//! These tests prove the sanitizer's output is printable-ASCII, JSON-safe, and
//! that a getpeerinfo-shaped JSON fragment built from it always parses.

const std = @import("std");
const testing = std.testing;
const peer = @import("peer.zig");

/// Every byte the sanitizer is allowed to keep (Core SAFE_CHARS_DEFAULT).
fn isSafeChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        ' ', '.', ',', ';', '-', '_', '/', ':', '?', '@', '(', ')' => true,
        else => false,
    };
}

test "subver-sanitize: helper + constant are exposed (Core cleanSubVer parity)" {
    try testing.expect(@hasDecl(peer, "sanitizeSubVer"));
    try testing.expect(@hasDecl(peer, "MAX_SUBVERSION_LENGTH"));
    try testing.expectEqual(@as(usize, 256), peer.MAX_SUBVERSION_LENGTH);
}

test "subver-sanitize: non-UTF8 + control + JSON metachars are stripped" {
    const a = testing.allocator;

    // A hostile subver: control byte 0x01, raw quote and backslash (would break
    // the JSON string), plus non-UTF8 bytes 0xff / 0xfe, around a benign label.
    const hostile = "/evil\x01:\"\\\xff\xfe0.1/";
    const clean = try peer.sanitizeSubVer(a, hostile);
    defer a.free(clean);

    // Every surviving byte is in the SAFE_CHARS_DEFAULT set (printable ASCII).
    for (clean) |c| {
        try testing.expect(isSafeChar(c));
        try testing.expect(c >= 0x20 and c < 0x7f); // printable ASCII, no controls
    }
    // The dangerous bytes are gone; the benign characters survive.
    try testing.expect(std.mem.indexOfScalar(u8, clean, '"') == null);
    try testing.expect(std.mem.indexOfScalar(u8, clean, '\\') == null);
    try testing.expect(std.mem.indexOfScalar(u8, clean, 0x01) == null);
    try testing.expect(std.mem.indexOfScalar(u8, clean, 0xff) == null);
    try testing.expect(std.mem.indexOfScalar(u8, clean, 0xfe) == null);
    // SAFE_CHARS_DEFAULT keeps '/', ':', '.', and alphanumerics:
    try testing.expectEqualStrings("/evil:0.1/", clean);
}

test "subver-sanitize: a typical Core/Knots subver survives unchanged" {
    const a = testing.allocator;
    const ua = "/Satoshi:27.0.0/";
    const clean = try peer.sanitizeSubVer(a, ua);
    defer a.free(clean);
    try testing.expectEqualStrings(ua, clean);
}

test "subver-sanitize: empty subver yields a valid empty owned slice" {
    const a = testing.allocator;
    const clean = try peer.sanitizeSubVer(a, "");
    defer a.free(clean);
    try testing.expectEqual(@as(usize, 0), clean.len);
}

test "subver-sanitize: oversized subver is bounded to MAX_SUBVERSION_LENGTH" {
    const a = testing.allocator;
    // 1000 safe chars — exceeds the 256 cap.  Core rejects on receipt; we cap
    // the stored clean copy so the operator-facing string never grows unbounded.
    const big = "A" ** 1000;
    const clean = try peer.sanitizeSubVer(a, big);
    defer a.free(clean);
    try testing.expect(clean.len <= peer.MAX_SUBVERSION_LENGTH);
    try testing.expectEqual(peer.MAX_SUBVERSION_LENGTH, clean.len);
}

/// Build the exact getpeerinfo `"subver":"..."` fragment that rpc.zig emits
/// (handleGetPeerInfo splices the value with `{s}` between two quotes), then
/// assert the whole object parses as valid JSON.
fn buildPeerInfoFragment(a: std.mem.Allocator, clean_subver: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        a,
        "{{\"id\":0,\"version\":70016,\"subver\":\"{s}\",\"inbound\":true}}",
        .{clean_subver},
    );
}

test "subver-sanitize: getpeerinfo JSON is valid after a poisoned subver (before/after)" {
    const a = testing.allocator;

    const hostile = "/x\x01\"\\\xff\xfe/";

    // BEFORE (the bug): splice the RAW attacker subver straight into JSON.
    // This MUST fail to parse — proving the original code path was broken.
    {
        const raw_json = try buildPeerInfoFragment(a, hostile);
        defer a.free(raw_json);
        const parsed = std.json.parseFromSlice(std.json.Value, a, raw_json, .{});
        if (parsed) |p| {
            p.deinit();
            return error.RawSubverUnexpectedlyParsed; // would mean the input was harmless
        } else |_| {
            // expected: invalid JSON from the unsanitized control/quote bytes
        }
    }

    // AFTER (the fix): sanitize first, then splice.  MUST parse, and the
    // round-tripped subver field must be exactly the cleaned, printable string.
    {
        const clean = try peer.sanitizeSubVer(a, hostile);
        defer a.free(clean);

        const fixed_json = try buildPeerInfoFragment(a, clean);
        defer a.free(fixed_json);

        var parsed = try std.json.parseFromSlice(std.json.Value, a, fixed_json, .{});
        defer parsed.deinit();

        const obj = parsed.value.object;
        const subver_val = obj.get("subver").?.string;
        try testing.expectEqualStrings(clean, subver_val);
        for (subver_val) |c| try testing.expect(isSafeChar(c));
        // The benign characters survive; the dangerous ones are gone.
        try testing.expectEqualStrings("/x/", subver_val);
    }
}

test "subver-sanitize: fuzz — any byte sequence yields parseable getpeerinfo JSON" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xC1EA_B175_AFE0_DA7A);
    const rng = prng.random();

    var iter: usize = 0;
    while (iter < 500) : (iter += 1) {
        var raw: [64]u8 = undefined;
        const n = rng.intRangeAtMost(usize, 0, raw.len);
        for (0..n) |i| raw[i] = rng.int(u8); // arbitrary bytes incl. 0x00..0xff

        const clean = try peer.sanitizeSubVer(a, raw[0..n]);
        defer a.free(clean);

        const json = try buildPeerInfoFragment(a, clean);
        defer a.free(json);

        // No matter what the peer sent, the resulting JSON always parses.
        var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
        defer parsed.deinit();
        const subver_val = parsed.value.object.get("subver").?.string;
        for (subver_val) |c| try testing.expect(isSafeChar(c));
    }
}
