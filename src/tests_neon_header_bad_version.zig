//! Header-receipt `bad-version` from the 2026-11-24 independent audit of
//! clearbit, pinned against Bitcoin Core v31.1.
//!
//! Core's ContextualCheckBlockHeader (validation.cpp) refuses a header whose
//! nVersion is obsolete once BIP34/66/65 are active ("bad-version(0x%08x)",
//! BLOCK_INVALID_HEADER), and AcceptBlockHeader runs it for every header:
//! P2P `headers`, compact blocks and the `submitheader` RPC.  A peer sending
//! one is punished (MaybePunishNodeForBlock: BLOCK_INVALID_HEADER).
//!
//! clearbit's validateHeaderContextualStrict mapped error.BadVersion to `.ok`,
//! so such a header entered the header index (and `submitheader` returned
//! null); only the block body was refused later.

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");

const PeerManager = peer_mod.PeerManager;
const BlockHeaderEntry = peer_mod.BlockHeaderEntry;

const REGTEST_BITS: u32 = 0x207fffff;
const T0: u32 = 1_700_000_000;
const NOW: i64 = 1_700_100_000;

fn seedParent(pm: *PeerManager, hash: types.Hash256, height: u32) !void {
    try pm.header_index.put(hash, BlockHeaderEntry{
        .hash = hash,
        .prev_hash = [_]u8{0} ** 32,
        .height = height,
        .chain_work = [_]u8{0} ** 32,
        .timestamp = T0,
        .header = types.BlockHeader{
            .version = 4,
            .prev_block = [_]u8{0} ** 32,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = T0,
            .bits = REGTEST_BITS,
            .nonce = 0,
        },
        .last_seen = 0,
    });
}

fn child(prev: types.Hash256, version: i32) types.BlockHeader {
    return .{
        .version = version,
        .prev_block = prev,
        .merkle_root = [_]u8{0x5a} ** 32,
        .timestamp = T0 + 600,
        .bits = REGTEST_BITS,
        .nonce = 0,
    };
}

/// The fix adds HeaderTimeReject.bad_version; compare by tag name so this file
/// compiles on master, where the verdict for these headers is `.ok`.
fn expectVerdict(expected: []const u8, got: PeerManager.HeaderTimeReject) !void {
    if (!std.mem.eql(u8, expected, @tagName(got))) {
        std.debug.print("expected verdict .{s}, got .{s}\n", .{ expected, @tagName(got) });
        return error.TestUnexpectedVerdict;
    }
}

test "neon F10: regtest header nVersion 1 at height 1 (BIP34 active) is bad-version at header receipt" {
    var pm = PeerManager.init(testing.allocator, &consensus.REGTEST);
    defer pm.deinit();
    const prev: types.Hash256 = [_]u8{0xA1} ** 32;
    try seedParent(&pm, prev, 0);
    const h = child(prev, 1);
    try expectVerdict("bad_version", pm.validateHeaderContextualStrict(&h, NOW, null));
}

test "neon F10: regtest header nVersion 3 at height 1 (BIP65 active) is bad-version at header receipt" {
    var pm = PeerManager.init(testing.allocator, &consensus.REGTEST);
    defer pm.deinit();
    const prev: types.Hash256 = [_]u8{0xA2} ** 32;
    try seedParent(&pm, prev, 0);
    const h = child(prev, 3);
    try expectVerdict("bad_version", pm.validateHeaderContextualStrict(&h, NOW, null));
}

test "neon F10: validateHeaderBatch stops at a bad-version header" {
    var pm = PeerManager.init(testing.allocator, &consensus.REGTEST);
    defer pm.deinit();
    const prev: types.Hash256 = [_]u8{0xA3} ** 32;
    try seedParent(&pm, prev, 0);
    const hs = [_]types.BlockHeader{child(prev, 2)};
    var overlay = peer_mod.HeaderBatchOverlay.init(testing.allocator);
    defer overlay.deinit();
    const out = pm.validateHeaderBatch(&hs, NOW, &overlay);
    try testing.expectEqual(@as(usize, 0), out.accepted);
    try testing.expect(out.reject != null);
    try expectVerdict("bad_version", out.reject.?);
}

test "neon F10 control: regtest header nVersion 4 at height 1 is accepted" {
    var pm = PeerManager.init(testing.allocator, &consensus.REGTEST);
    defer pm.deinit();
    const prev: types.Hash256 = [_]u8{0xA4} ** 32;
    try seedParent(&pm, prev, 0);
    const h = child(prev, 4);
    try expectVerdict("ok", pm.validateHeaderContextualStrict(&h, NOW, null));
}

test "neon F10 control: mainnet nVersion 1 below BIP34 height is not bad-version" {
    var pm = PeerManager.init(testing.allocator, &consensus.MAINNET);
    defer pm.deinit();
    const prev: types.Hash256 = [_]u8{0xA5} ** 32;
    try pm.header_index.put(prev, BlockHeaderEntry{
        .hash = prev,
        .prev_hash = [_]u8{0} ** 32,
        .height = 0,
        .chain_work = [_]u8{0} ** 32,
        .timestamp = 1_231_006_505,
        .header = .{ .version = 1, .prev_block = [_]u8{0} ** 32, .merkle_root = [_]u8{0} ** 32, .timestamp = 1_231_006_505, .bits = 0x1d00ffff, .nonce = 0 },
        .last_seen = 0,
    });
    const h = types.BlockHeader{ .version = 1, .prev_block = prev, .merkle_root = [_]u8{0} ** 32, .timestamp = 1_231_006_505 + 600, .bits = 0x1d00ffff, .nonce = 0 };
    try expectVerdict("ok", pm.validateHeaderContextualStrict(&h, 2_000_000_000, null));
}
