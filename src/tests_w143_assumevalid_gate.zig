//! W143 — Faithful assumevalid script-skip gate (5-condition Core parity).
//!
//! Bitcoin Core reference: validation.cpp ConnectBlock:2346-2366.
//! The five conditions that must ALL hold to skip script verification:
//!
//!   (1) assumed_valid_hash is configured (non-null).
//!   (2) The AV block IS in our expected-block queue at av_height.
//!   (3) The block being connected is in expected_blocks at its height
//!       AND height <= av_height  (ancestor-of-AV check).
//!   (4) best_header_chain_work >= params.min_chain_work  (eclipse defence).
//!   (5) best_header_timestamp > block_timestamp + 1_209_600s  (DoS defence).
//!
//! KEY FIX vs the old height-only skip: a FORK block at height <= av_height
//! is NOT in expected_blocks at the correct position, so conditions 2/3 fail
//! and its scripts are verified.
//!
//! Run with `zig build test-w143`.

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");

const PeerManager = peer_mod.PeerManager;

// ============================================================================
// Test constants
// ============================================================================

/// A distinctive 32-byte value used as the fake assumevalid hash.
const AV_SENTINEL: [32]u8 = [_]u8{0xCA} ** 32;

/// A fake block hash value to use as a "fork" block hash (not in chain).
const FORK_HASH: [32]u8 = [_]u8{0xBA, 0xDF, 0x00, 0xD0} ++ [_]u8{0x00} ** 28;

/// min_chain_work: just 1 so condition 4 is easy to satisfy or not.
const MIN_WORK_ONE: [32]u8 = [_]u8{0} ** 31 ++ [_]u8{0x01};

/// best_header_chain_work well above min_chain_work (0xFF in last byte)
const LARGE_WORK: [32]u8 = [_]u8{0} ** 31 ++ [_]u8{0xFF};

// ============================================================================
// Helpers
// ============================================================================

/// Build a minimal NetworkParams suitable for gate tests.  We copy REGTEST
/// (no assumed-valid by default) but inject a fake av_hash + av_height and a
/// non-trivial min_chain_work so all five conditions can be exercised.
fn makeGateParams() consensus.NetworkParams {
    // Start from REGTEST (safe defaults, no PoW puzzles).
    var p = consensus.REGTEST;
    p.assumed_valid_hash = AV_SENTINEL;
    p.assume_valid_height = 1000;
    p.min_chain_work = MIN_WORK_ONE;
    return p;
}

/// Return a 32-byte hash with a unique per-index value (for building fake chains).
fn fakeHash(idx: usize) [32]u8 {
    var h: [32]u8 = [_]u8{0} ** 32;
    h[0] = @intCast(idx & 0xFF);
    h[1] = @intCast((idx >> 8) & 0xFF);
    h[31] = 0xCC; // distinctive sentinel so we can tell these from zero hashes
    return h;
}

/// Build a synthetic expected_blocks chain of length `len` rooted at h0+1.
/// Places the AV sentinel at index av_idx = av_height - h0 - 1.
fn buildChain(
    allocator: std.mem.Allocator,
    len: usize,
    av_idx: usize,
) ![]const [32]u8 {
    var chain = try allocator.alloc([32]u8, len);
    for (chain, 0..) |*slot, i| slot.* = fakeHash(i);
    if (av_idx < len) chain[av_idx] = AV_SENTINEL;
    return chain;
}

/// Wire up a PeerManager + in-memory ChainState for gate testing.
/// Caller owns `chain` (passed as a slice) and must free it separately.
/// Returns pm and cs that must be deinitialized by the caller.
fn makePM(
    allocator: std.mem.Allocator,
    params: *const consensus.NetworkParams,
    h0: u32,
    cursor: u32,
    chain: []const [32]u8,
    block_ts: u32,
) !struct { pm: PeerManager, cs: storage.ChainState } {
    var pm = PeerManager.init(allocator, params);
    var cs = storage.ChainState.init(null, 0, allocator);
    cs.best_height = h0 + cursor;
    pm.connect_cursor = cursor;
    // chain_state pointer — cs lives in the returned struct, so the pointer
    // is stable for the lifetime of the struct (caller keeps it alive).
    pm.chain_state = &cs; // This is re-pointed by caller after return below.
    for (chain) |h| try pm.expected_blocks.append(h);
    // Satisfy conditions 4 + 5.
    pm.best_header_chain_work = LARGE_WORK;
    pm.best_header_timestamp = block_ts + 1_209_601 * 3; // 3 × 2 weeks ahead
    return .{ .pm = pm, .cs = cs };
}

// ============================================================================
// Test 1 — EFFECTIVE proof: fork block below av_height → gate returns false
// ============================================================================
//
// A height-only skip would have returned true (height 500 <= av_height 1000).
// The faithful gate must return false because FORK_HASH is not in expected_blocks
// at index 499 (the expected hash is fakeHash(499) there, not FORK_HASH).

test "w143 EFFECTIVE: fork block at height<=av_height is NOT skipped (condition 3 fails)" {
    const allocator = testing.allocator;

    var params = makeGateParams(); // av_height = 1000
    const h0: u32 = 0;
    const cursor: u32 = 499; // currently connecting block 500
    const height: u32 = 500;
    const block_ts: u32 = 1_600_000_000;

    // Build chain long enough to include av_height=1000 (index 999).
    const chain = try buildChain(allocator, 1001, 999);
    defer allocator.free(chain);

    var result_pair = try makePM(allocator, &params, h0, cursor, chain, block_ts);
    result_pair.pm.chain_state = &result_pair.cs; // stable pointer after move
    defer result_pair.pm.deinit();
    defer result_pair.cs.deinit();

    // FORK_HASH is not chain[499] = fakeHash(499).
    const gate = result_pair.pm.faithfulSkipScriptsGate(&FORK_HASH, height, block_ts);

    // Old height-only would say: skip  (height 500 <= av_height 1000)
    // New faithful gate must say: run scripts (fork block, condition 3 fails)
    try testing.expectEqual(false, gate);
}

// ============================================================================
// Test 2 — on-chain block below av_height IS skipped when all conditions hold
// ============================================================================

test "w143: on-chain block at height<=av_height with all conditions satisfied → skipped" {
    const allocator = testing.allocator;

    var params = makeGateParams();
    const h0: u32 = 0;
    const cursor: u32 = 499;
    const height: u32 = 500;
    const block_ts: u32 = 1_600_000_000;

    const chain = try buildChain(allocator, 1001, 999);
    defer allocator.free(chain);

    var pair = try makePM(allocator, &params, h0, cursor, chain, block_ts);
    pair.pm.chain_state = &pair.cs;
    defer pair.pm.deinit();
    defer pair.cs.deinit();

    // On-chain: use the hash that IS in expected_blocks at cursor (index 499).
    const on_chain_hash = chain[499]; // fakeHash(499)

    const gate = pair.pm.faithfulSkipScriptsGate(&on_chain_hash, height, block_ts);
    try testing.expectEqual(true, gate);
}

// ============================================================================
// Test 3 — condition 2 failure: AV hash not in expected_blocks → scripts run
// ============================================================================

test "w143: AV hash absent from expected_blocks → scripts run (condition 2 fails)" {
    const allocator = testing.allocator;

    var params = makeGateParams();
    const h0: u32 = 0;
    const cursor: u32 = 499;
    const height: u32 = 500;
    const block_ts: u32 = 1_600_000_000;

    // Build a chain that does NOT place AV_SENTINEL at index 999.
    const chain = try buildChain(allocator, 1001, 9999); // av_idx out of range
    defer allocator.free(chain);

    var pair = try makePM(allocator, &params, h0, cursor, chain, block_ts);
    pair.pm.chain_state = &pair.cs;
    defer pair.pm.deinit();
    defer pair.cs.deinit();

    const on_chain_hash = chain[499];
    const gate = pair.pm.faithfulSkipScriptsGate(&on_chain_hash, height, block_ts);
    // AV block not found at av_height in expected_blocks → condition 2 fails
    try testing.expectEqual(false, gate);
}

// ============================================================================
// Test 4 — condition 4 failure: best_header chainwork below min_chain_work
// ============================================================================

test "w143: best_header chainwork below min_chain_work → scripts run (eclipse defence)" {
    const allocator = testing.allocator;

    var params = makeGateParams();
    const h0: u32 = 0;
    const cursor: u32 = 499;
    const height: u32 = 500;
    const block_ts: u32 = 1_600_000_000;

    const chain = try buildChain(allocator, 1001, 999);
    defer allocator.free(chain);

    var pair = try makePM(allocator, &params, h0, cursor, chain, block_ts);
    pair.pm.chain_state = &pair.cs;
    defer pair.pm.deinit();
    defer pair.cs.deinit();

    // Override: set best_header chainwork to ZERO (below min_chain_work = 1)
    pair.pm.best_header_chain_work = [_]u8{0} ** 32;

    const on_chain_hash = chain[499];
    const gate = pair.pm.faithfulSkipScriptsGate(&on_chain_hash, height, block_ts);
    try testing.expectEqual(false, gate);
}

// ============================================================================
// Test 5 — condition 5 failure: best_header only 1 week past block → scripts run
// ============================================================================

test "w143: best_header <2 weeks past block → scripts run (DoS defence, condition 5)" {
    const allocator = testing.allocator;

    var params = makeGateParams();
    const h0: u32 = 0;
    const cursor: u32 = 499;
    const height: u32 = 500;
    const block_ts: u32 = 1_600_000_000;

    const chain = try buildChain(allocator, 1001, 999);
    defer allocator.free(chain);

    var pair = try makePM(allocator, &params, h0, cursor, chain, block_ts);
    pair.pm.chain_state = &pair.cs;
    defer pair.pm.deinit();
    defer pair.cs.deinit();

    // Override: best_header only 1 week (604_800 s) ahead — below TWO_WEEKS threshold
    pair.pm.best_header_timestamp = block_ts + 604_800;

    const on_chain_hash = chain[499];
    const gate = pair.pm.faithfulSkipScriptsGate(&on_chain_hash, height, block_ts);
    try testing.expectEqual(false, gate);
}

// ============================================================================
// Test 6 — block above av_height always runs scripts
// ============================================================================

test "w143: block above av_height → scripts always run" {
    const allocator = testing.allocator;

    var params = makeGateParams(); // av_height = 1000
    const h0: u32 = 0;
    const cursor: u32 = 1000; // connecting block 1001 (above av_height)
    const height: u32 = 1001;
    const block_ts: u32 = 1_600_000_000;

    const chain = try buildChain(allocator, 1002, 999);
    defer allocator.free(chain);

    var pair = try makePM(allocator, &params, h0, cursor, chain, block_ts);
    pair.pm.chain_state = &pair.cs;
    defer pair.pm.deinit();
    defer pair.cs.deinit();

    const block_hash = chain[1000]; // index 1000 = height 1001
    const gate = pair.pm.faithfulSkipScriptsGate(&block_hash, height, block_ts);
    try testing.expectEqual(false, gate);
}

// ============================================================================
// Test 7 — insertHeader updates best_header_chain_work (real chain work)
// ============================================================================

test "w143: insertHeader tracks best_header_chain_work from real chain_work" {
    const allocator = testing.allocator;
    const params = consensus.REGTEST;
    var pm = PeerManager.init(allocator, &params);
    defer pm.deinit();

    // Initially zero.
    const zero = [_]u8{0} ** 32;
    try testing.expectEqualSlices(u8, &zero, &pm.best_header_chain_work);

    // Wire genesis into header_index so insertHeader can find the parent.
    const genesis_hash = params.genesis_hash;
    const genesis_ts: u32 = 1_296_688_602;
    try pm.header_index.put(genesis_hash, peer_mod.BlockHeaderEntry{
        .hash = genesis_hash,
        .prev_hash = [_]u8{0} ** 32,
        .height = 0,
        .chain_work = [_]u8{0} ** 32,
        .timestamp = genesis_ts,
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = [_]u8{0} ** 32,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = genesis_ts,
            .bits = 0x207fffff,
            .nonce = 0,
        },
        .last_seen = 0,
    });

    // Build a synthetic hash for block 1 (skip PoW; insertHeader doesn't verify PoW).
    const hash1: [32]u8 = [_]u8{0xBB} ** 32;
    const header1 = types.BlockHeader{
        .version = 1,
        .prev_block = genesis_hash,
        .merkle_root = [_]u8{0x11} ** 32,
        .timestamp = genesis_ts + 600,
        .bits = 0x207fffff,
        .nonce = 1,
    };

    _ = try pm.insertHeader(&header1, &hash1);

    // After insertion, best_header_chain_work must be strictly > 0.
    var all_zero = true;
    for (pm.best_header_chain_work) |b| {
        if (b != 0) { all_zero = false; break; }
    }
    try testing.expect(!all_zero); // condition 4 accessor is real, not stubbed

    // best_header_timestamp must match the inserted header's timestamp.
    try testing.expectEqual(header1.timestamp, pm.best_header_timestamp);
}
