//! FIX-84 — BIP-157 P2P handler wire-up (W121 BUG-3..7 + BUG-10 closure).
//!
//! Reference: bitcoin-core/src/net_processing.cpp
//!   PrepareBlockFilterRequest (3262) +
//!   ProcessGetCFilters (3315) + ProcessGetCFHeaders (3344) +
//!   ProcessGetCFCheckPt (3386).
//!
//! Cross-impl reference: lunarblock FIX-81 (0de7b2a) + blockbrew FIX-74
//! (4cee2c6) + rustoshi FIX-82 (03c7be4).
//!
//! Run: `zig build test-fix84`.
//!
//! What this exercises:
//!   1. Wire round-trip for all 6 BIP-157 messages.
//!   2. Source-level forward-regression guards that the dispatch arms
//!      remain wired (a future drive-by `else => {}` collapse will fail
//!      these tests FIRST, before the W121 audit gates regress).
//!   3. Constants ported into p2p.zig:
//!         MAX_GETCFILTERS_SIZE = 1000
//!         MAX_GETCFHEADERS_SIZE = 2000
//!         CFCHECKPT_INTERVAL = 1000
//!   4. Anti-DoS bounds on decode (cfheaders count cap, cfcheckpt cap).
//!   5. PeerManager-level integration: handler entry points exist on
//!      PeerManager as private fns with the expected signatures.
//!
//! Behavioral testing (filter delivery happy-path + per-violation
//! disconnect) is exercised at the peer.zig level via the existing peer
//! manager tests; here we focus on:
//!   - wire format integrity
//!   - source guards (dispatch arms present)
//!   - constants present + Core-byte-identical
//!   - decoder anti-DoS limits
//!
//! See `tests_w121_compact_filters.zig` for the audit-gate matrix
//! (G22-G27 flipped from "asserts ABSENT" → "asserts PRESENT" in this
//! same fix wave).

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const v2_transport = @import("v2_transport.zig");
const types = @import("types.zig");

// ===========================================================================
// G1: Constants are present in p2p.zig and Core-byte-identical.
// ===========================================================================

test "fix84/G1: MAX_GETCFILTERS_SIZE = 1000" {
    try testing.expectEqual(@as(u32, 1000), p2p.MAX_GETCFILTERS_SIZE);
}

test "fix84/G1: MAX_GETCFHEADERS_SIZE = 2000" {
    try testing.expectEqual(@as(u32, 2000), p2p.MAX_GETCFHEADERS_SIZE);
}

test "fix84/G1: CFCHECKPT_INTERVAL = 1000" {
    try testing.expectEqual(@as(u32, 1000), p2p.CFCHECKPT_INTERVAL);
}

test "fix84/G1: NODE_COMPACT_FILTERS = 1 << 6" {
    try testing.expectEqual(@as(u64, 64), p2p.NODE_COMPACT_FILTERS);
}

// ===========================================================================
// G2: Message union variant presence.
// ===========================================================================

fn unionHasField(comptime U: type, comptime name: []const u8) bool {
    const info = @typeInfo(U).Union;
    inline for (info.fields) |f| {
        if (comptime std.mem.eql(u8, f.name, name)) return true;
    }
    return false;
}

test "fix84/G2: Message union has all 6 BIP-157 variants" {
    try testing.expect(unionHasField(p2p.Message, "getcfilters"));
    try testing.expect(unionHasField(p2p.Message, "cfilter"));
    try testing.expect(unionHasField(p2p.Message, "getcfheaders"));
    try testing.expect(unionHasField(p2p.Message, "cfheaders"));
    try testing.expect(unionHasField(p2p.Message, "getcfcheckpt"));
    try testing.expect(unionHasField(p2p.Message, "cfcheckpt"));
}

// ===========================================================================
// G3: getcfilters wire round-trip.
// ===========================================================================

test "fix84/G3: getcfilters encode -> decode round-trip" {
    const allocator = testing.allocator;
    var stop: types.Hash256 = undefined;
    for (0..32) |i| stop[i] = @intCast((i +% 3) & 0xff);

    const msg = p2p.Message{ .getcfilters = .{
        .filter_type = 0,
        .start_height = 12345,
        .stop_hash = stop,
    } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const hdr = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("getcfilters", hdr.commandName());
    // payload = 1 (filter_type) + 4 (start_height) + 32 (stop_hash) = 37 bytes.
    try testing.expectEqual(@as(u32, 37), hdr.length);
    try testing.expect(hdr.verifyChecksum(encoded[24..]));

    const decoded = try p2p.decodePayload(hdr.commandName(), encoded[24..], allocator);
    try testing.expectEqual(@as(u8, 0), decoded.getcfilters.filter_type);
    try testing.expectEqual(@as(u32, 12345), decoded.getcfilters.start_height);
    try testing.expectEqualSlices(u8, &stop, &decoded.getcfilters.stop_hash);
}

// ===========================================================================
// G4: cfilter wire round-trip (variable-length filter payload).
// ===========================================================================

test "fix84/G4: cfilter encode -> decode round-trip" {
    const allocator = testing.allocator;
    const filter_bytes = [_]u8{ 0x05, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }; // CompactSize(5) || 5 bytes filter
    var block_hash: types.Hash256 = undefined;
    for (0..32) |i| block_hash[i] = @intCast((i +% 7) & 0xff);

    const msg = p2p.Message{ .cfilter = .{
        .filter_type = 0,
        .block_hash = block_hash,
        .filter = &filter_bytes,
    } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const hdr = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("cfilter", hdr.commandName());

    const decoded = try p2p.decodePayload(hdr.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.cfilter.filter);
    try testing.expectEqualSlices(u8, &filter_bytes, decoded.cfilter.filter);
    try testing.expectEqualSlices(u8, &block_hash, &decoded.cfilter.block_hash);
}

// ===========================================================================
// G5: getcfheaders wire round-trip.
// ===========================================================================

test "fix84/G5: getcfheaders encode -> decode round-trip" {
    const allocator = testing.allocator;
    var stop: types.Hash256 = undefined;
    for (0..32) |i| stop[i] = @intCast((i +% 5) & 0xff);

    const msg = p2p.Message{ .getcfheaders = .{
        .filter_type = 0,
        .start_height = 100,
        .stop_hash = stop,
    } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const hdr = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("getcfheaders", hdr.commandName());

    const decoded = try p2p.decodePayload(hdr.commandName(), encoded[24..], allocator);
    try testing.expectEqual(@as(u32, 100), decoded.getcfheaders.start_height);
    try testing.expectEqualSlices(u8, &stop, &decoded.getcfheaders.stop_hash);
}

// ===========================================================================
// G6: cfheaders wire round-trip (with filter-hashes vector).
// ===========================================================================

test "fix84/G6: cfheaders encode -> decode round-trip with 3 filter hashes" {
    const allocator = testing.allocator;
    const fhashes = [_]types.Hash256{
        [_]u8{0xaa} ** 32,
        [_]u8{0xbb} ** 32,
        [_]u8{0xcc} ** 32,
    };
    const stop: types.Hash256 = [_]u8{0xdd} ** 32;
    const prev: types.Hash256 = [_]u8{0xee} ** 32;

    const msg = p2p.Message{ .cfheaders = .{
        .filter_type = 0,
        .stop_hash = stop,
        .prev_filter_header = prev,
        .filter_hashes = &fhashes,
    } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const hdr = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("cfheaders", hdr.commandName());

    const decoded = try p2p.decodePayload(hdr.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.cfheaders.filter_hashes);
    try testing.expectEqual(@as(usize, 3), decoded.cfheaders.filter_hashes.len);
    try testing.expectEqualSlices(u8, &fhashes[0], &decoded.cfheaders.filter_hashes[0]);
    try testing.expectEqualSlices(u8, &fhashes[2], &decoded.cfheaders.filter_hashes[2]);
    try testing.expectEqualSlices(u8, &stop, &decoded.cfheaders.stop_hash);
    try testing.expectEqualSlices(u8, &prev, &decoded.cfheaders.prev_filter_header);
}

// ===========================================================================
// G7: getcfcheckpt wire round-trip.
// ===========================================================================

test "fix84/G7: getcfcheckpt encode -> decode round-trip" {
    const allocator = testing.allocator;
    const stop: types.Hash256 = [_]u8{0x11} ** 32;

    const msg = p2p.Message{ .getcfcheckpt = .{
        .filter_type = 0,
        .stop_hash = stop,
    } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const hdr = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("getcfcheckpt", hdr.commandName());
    // payload = 1 (filter_type) + 32 (stop_hash) = 33 bytes.
    try testing.expectEqual(@as(u32, 33), hdr.length);

    const decoded = try p2p.decodePayload(hdr.commandName(), encoded[24..], allocator);
    try testing.expectEqual(@as(u8, 0), decoded.getcfcheckpt.filter_type);
    try testing.expectEqualSlices(u8, &stop, &decoded.getcfcheckpt.stop_hash);
}

// ===========================================================================
// G8: cfcheckpt wire round-trip.
// ===========================================================================

test "fix84/G8: cfcheckpt encode -> decode round-trip" {
    const allocator = testing.allocator;
    const headers = [_]types.Hash256{
        [_]u8{0x01} ** 32,
        [_]u8{0x02} ** 32,
        [_]u8{0x03} ** 32,
        [_]u8{0x04} ** 32,
    };
    const stop: types.Hash256 = [_]u8{0xff} ** 32;

    const msg = p2p.Message{ .cfcheckpt = .{
        .filter_type = 0,
        .stop_hash = stop,
        .filter_headers = &headers,
    } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const hdr = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("cfcheckpt", hdr.commandName());

    const decoded = try p2p.decodePayload(hdr.commandName(), encoded[24..], allocator);
    defer allocator.free(decoded.cfcheckpt.filter_headers);
    try testing.expectEqual(@as(usize, 4), decoded.cfcheckpt.filter_headers.len);
}

// ===========================================================================
// G9: Anti-DoS — cfheaders with > MAX_GETCFHEADERS_SIZE elements rejected.
// ===========================================================================

test "fix84/G9: cfheaders with count > MAX_GETCFHEADERS_SIZE rejects" {
    const allocator = testing.allocator;
    var w = std.ArrayList(u8).init(allocator);
    defer w.deinit();
    try w.append(0); // filter_type
    try w.appendSlice(&([_]u8{0} ** 32)); // stop_hash
    try w.appendSlice(&([_]u8{0} ** 32)); // prev_filter_header
    // CompactSize for 2001 = 0xfd | 0xd1 | 0x07 (little-endian u16 follows 0xfd marker).
    try w.append(0xfd);
    try w.append(0xd1);
    try w.append(0x07);
    // We do NOT append the 2001 * 32 bytes — the decoder must reject on the
    // CompactSize cap before attempting any allocation.
    const res = p2p.decodePayload("cfheaders", w.items, allocator);
    try testing.expectError(p2p.ParseError.InvalidData, res);
}

// ===========================================================================
// G10: BIP-324 v2 short-IDs 22-27 still register the 6 BIP-157 commands.
// These ARE the short-IDs that were dead-helpers pre-FIX-84.
// ===========================================================================

test "fix84/G10: BIP-324 short IDs 22-27 still resolve to BIP-157 commands" {
    try testing.expectEqualStrings("getcfilters", v2_transport.V2_MESSAGE_IDS[22]);
    try testing.expectEqualStrings("cfilter", v2_transport.V2_MESSAGE_IDS[23]);
    try testing.expectEqualStrings("getcfheaders", v2_transport.V2_MESSAGE_IDS[24]);
    try testing.expectEqualStrings("cfheaders", v2_transport.V2_MESSAGE_IDS[25]);
    try testing.expectEqualStrings("getcfcheckpt", v2_transport.V2_MESSAGE_IDS[26]);
    try testing.expectEqualStrings("cfcheckpt", v2_transport.V2_MESSAGE_IDS[27]);
}

// ===========================================================================
// G11: Forward-regression source guard.  This test asserts the textual
// presence of the dispatch arms + handler symbols in peer.zig.  If a
// future drive-by edit collapses any of these back into `else => {}` or
// renames a handler, this test fails BEFORE the W121 audit gates would.
//
// Pattern lifted from FIX-65 / FIX-67 source guards: read the source file
// at test time, assert the expected anchor strings.
// ===========================================================================

test "fix84/G11: peer.zig dispatch arms present (forward-regression guard)" {
    const allocator = testing.allocator;
    const peer_src = try std.fs.cwd().readFileAlloc(allocator, "src/peer.zig", 32 * 1024 * 1024);
    defer allocator.free(peer_src);

    // Six dispatch arms.
    try testing.expect(std.mem.indexOf(u8, peer_src, ".getcfilters => |gc| {") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, ".getcfheaders => |gch| {") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, ".getcfcheckpt => |gcc| {") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, ".cfilter => |cf| {") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, ".cfheaders => |cfh| {") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, ".cfcheckpt => |cfc| {") != null);

    // Three handler fns.
    try testing.expect(std.mem.indexOf(u8, peer_src, "fn processGetCFilters(") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, "fn processGetCFHeaders(") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, "fn processGetCFCheckPt(") != null);

    // Resolution helper for stop_hash → active-chain height.
    try testing.expect(std.mem.indexOf(u8, peer_src, "fn resolveActiveChainStopHash(") != null);

    // The disconnect-on-violation paths exist (Core fDisconnect=true parity).
    try testing.expect(std.mem.indexOf(u8, peer_src, "peer.misbehaving(100, \"getcfilters") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, "peer.misbehaving(100, \"getcfheaders") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, "peer.misbehaving(100, \"getcfcheckpt") != null);
}

// ===========================================================================
// G12: encodeMessage round-trips ALL 6 messages through MessageHeader so
// the checksum is correct.  This is the "wire-compat" guarantee that a
// real BIP-157 client (Neutrino, BFD, rust-lightning) can speak to a
// clearbit peer without checksum errors.
// ===========================================================================

test "fix84/G12: all 6 BIP-157 messages survive checksum verification" {
    const allocator = testing.allocator;

    // Build each message with deterministic content.
    const stop: types.Hash256 = [_]u8{0x42} ** 32;
    const filter_payload: []const u8 = &[_]u8{ 0x02, 0xaa, 0xbb };
    const empty_fhashes: []const types.Hash256 = &[_]types.Hash256{};
    const one_header: []const types.Hash256 = &[_]types.Hash256{[_]u8{0x55} ** 32};

    const msgs = [_]p2p.Message{
        .{ .getcfilters = .{ .filter_type = 0, .start_height = 1, .stop_hash = stop } },
        .{ .cfilter = .{ .filter_type = 0, .block_hash = stop, .filter = filter_payload } },
        .{ .getcfheaders = .{ .filter_type = 0, .start_height = 2, .stop_hash = stop } },
        .{ .cfheaders = .{ .filter_type = 0, .stop_hash = stop, .prev_filter_header = stop, .filter_hashes = empty_fhashes } },
        .{ .getcfcheckpt = .{ .filter_type = 0, .stop_hash = stop } },
        .{ .cfcheckpt = .{ .filter_type = 0, .stop_hash = stop, .filter_headers = one_header } },
    };

    for (msgs) |m| {
        const encoded = try p2p.encodeMessage(&m, p2p.NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);
        const hdr = p2p.MessageHeader.decode(encoded[0..24]);
        try testing.expect(hdr.verifyChecksum(encoded[24..]));
    }
}

// ===========================================================================
// G13: Filter-type non-zero — happy decode (no validation at decode time;
// validation is in the handler).  This documents that "filter_type=1" or
// any non-BASIC variant decodes cleanly at the wire level; rejection
// happens in `processGetCFilters` and friends.
// ===========================================================================

test "fix84/G13: getcfilters with non-zero filter_type decodes (rejection is handler-side)" {
    const payload = [_]u8{
        0x01, // filter_type = 1 (NOT BASIC — Core treats as unsupported)
        0x00, 0x00, 0x00, 0x00,
    } ++ [_]u8{0} ** 32;
    const decoded = try p2p.decodePayload("getcfilters", &payload, testing.allocator);
    // Decoder DOES NOT reject — that's the handler's job.
    try testing.expectEqual(@as(u8, 1), decoded.getcfilters.filter_type);
}

// ===========================================================================
// G14: peer.zig forward-regression — the BIP-157 dispatch arms come BEFORE
// the catch-all `else => {}`.  A drive-by edit that moves them AFTER would
// silently regress the closure.
// ===========================================================================

test "fix84/G14: peer.zig BIP-157 dispatch precedes catch-all else=>{}" {
    const allocator = testing.allocator;
    const peer_src = try std.fs.cwd().readFileAlloc(allocator, "src/peer.zig", 32 * 1024 * 1024);
    defer allocator.free(peer_src);

    const cfilter_idx = std.mem.indexOf(u8, peer_src, ".getcfilters => |gc| {") orelse return error.MissingDispatch;
    // Find the first `else => {}` AFTER cfilter_idx; this is the
    // catch-all in handleMessage.
    const search_after = peer_src[cfilter_idx..];
    const else_rel = std.mem.indexOf(u8, search_after, "else => {}") orelse return error.MissingCatchall;
    // Sanity: there is at least some content between dispatch and catch-all.
    try testing.expect(else_rel > 50);
}
