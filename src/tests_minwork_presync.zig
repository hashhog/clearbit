//! Min-chain-work presync gate tests (`evalMinChainWorkGate`).
//!
//! Run via `zig build test-minwork-presync` (also folded into `zig build test`).
//!
//! Reproduces and locks the CRITICAL genesis-IBD divergence: clearbit's
//! per-batch min_chain_work gate used to call `misbehaving(100)` — banning the
//! peer — on the very first genesis-rooted header batch, whose cumulative work
//! is necessarily far below mainnet/testnet4 min_chain_work.  That made
//! bootstrapping from genesis against ANY honest peer impossible (clearbit
//! insta-banned its own block source).
//!
//! Bitcoin Core never Misbehaves on low-work headers: `MaybePunishNodeForBlock`
//! treats BLOCK_HEADER_LOW_WORK with a bare `break` (net_processing.cpp
//! 1913-1916), and `TryLowWorkHeadersSync` (2765-2809) stages a below-threshold
//! chain via presync WITHOUT banning or committing until minimum_chain_work is
//! crossed.  `evalMinChainWorkGate` mirrors that:
//!   * below threshold, still in presync  -> .presync_accept  (tolerate, no ban)
//!   * below threshold, already past min   -> .reject_dos      (steady-state DoS)
//!   * at/above threshold                  -> .commit
//!
//! PRE-FIX these inputs hit `if (cmpChainWorkBE(&cum, &min_cw) < 0) misbehaving(100)`
//! — i.e. the genesis batch was BANNED.  Each test below asserts the batch is
//! now tolerated (or committed) and, for the genesis case, explicitly asserts
//! that the OLD inline predicate would have banned it — pinning the divergence.

const std = @import("std");
const testing = std.testing;
const peer_mod = @import("peer.zig");

// Difficulty-1 (pow-limit) compact target — the nBits every early
// mainnet/testnet header carries.  Each such header contributes ~2^32 work.
const DIFF1_BITS: u32 = 0x1d00ffff;

/// Sum the proof-of-work of `n` difficulty-1 headers (big-endian [32]u8),
/// matching how the live `.headers` handler accumulates `batch_work`.
fn diff1BatchWork(n: usize) [32]u8 {
    var acc: [32]u8 = [_]u8{0} ** 32;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const w = peer_mod.workFromBits(DIFF1_BITS);
        peer_mod.addChainWorkBE(&acc, &w);
    }
    return acc;
}

/// Build a big-endian [32]u8 equal to 2^bit.
fn workPow2(bit: u9) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    const byte_from_lsb: usize = bit / 8; // 0 = least-significant byte
    const idx: usize = 31 - byte_from_lsb; // big-endian index
    out[idx] = @as(u8, 1) << @intCast(bit % 8);
    return out;
}

const ZERO: [32]u8 = [_]u8{0} ** 32;

test "tests_minwork_presync: genesis low-work batch is presync-accepted, NOT banned (Core parity)" {
    // Fresh node at genesis: best header work = 0 (below min), parent = genesis
    // (0).  A full 2000-header difficulty-1 batch has cumulative work ~2^43.
    const min_cw = workPow2(76); // ~ mainnet min_chain_work magnitude (2^76)
    const parent_work = ZERO; // genesis
    const best_header_work = ZERO; // fresh node, still in presync
    const batch_work = diff1BatchWork(2000);

    // The batch really IS below the threshold (this is what tripped the ban).
    var cum: [32]u8 = parent_work;
    peer_mod.addChainWorkBE(&cum, &batch_work);
    try testing.expect(peer_mod.cmpChainWorkBE(&cum, &min_cw) < 0);

    // PRE-FIX behavior that this test pins as WRONG: the old inline gate was
    //   `if (cmpChainWorkBE(&cum, &min_cw) < 0) misbehaving(100)` — a BAN.
    // The predicate above is true, so pre-fix the honest peer was banned.

    // POST-FIX: the gate tolerates the low-work headers during presync.
    const verdict = peer_mod.evalMinChainWorkGate(
        &best_header_work,
        &parent_work,
        &batch_work,
        &min_cw,
    );
    try testing.expectEqual(peer_mod.MinChainWorkVerdict.presync_accept, verdict);
    // Explicitly: it must NOT be the DoS-drop verdict.
    try testing.expect(verdict != .reject_dos);
}

test "tests_minwork_presync: batch that crosses min_chain_work commits" {
    const min_cw = workPow2(60);
    // Parent already just below the threshold; a small batch pushes cum over it.
    const parent_work = workPow2(60); // == min_cw, so cum > min_cw after batch
    const best_header_work = workPow2(60);
    const batch_work = diff1BatchWork(1);

    const verdict = peer_mod.evalMinChainWorkGate(
        &best_header_work,
        &parent_work,
        &batch_work,
        &min_cw,
    );
    try testing.expectEqual(peer_mod.MinChainWorkVerdict.commit, verdict);
}

test "tests_minwork_presync: steady-state low-work chain after min-work reached is dropped" {
    // Node has already synced past min_chain_work (best_header_work >= min_cw).
    // A peer now feeds a low-work chain rooted near genesis (parent 0, tiny
    // batch) whose cumulative work is below the threshold: Core-style DoS drop.
    const min_cw = workPow2(60);
    const best_header_work = workPow2(61); // already well past min
    const parent_work = ZERO; // low-work fork root
    const batch_work = diff1BatchWork(3); // ~2^33.5, far below 2^60

    var cum: [32]u8 = parent_work;
    peer_mod.addChainWorkBE(&cum, &batch_work);
    try testing.expect(peer_mod.cmpChainWorkBE(&cum, &min_cw) < 0);

    const verdict = peer_mod.evalMinChainWorkGate(
        &best_header_work,
        &parent_work,
        &batch_work,
        &min_cw,
    );
    try testing.expectEqual(peer_mod.MinChainWorkVerdict.reject_dos, verdict);
}

test "tests_minwork_presync: zero min_chain_work (regtest) is a no-op -> commit" {
    // Regtest sets min_chain_work = 0; the gate must never fire there.
    const parent_work = ZERO;
    const best_header_work = ZERO;
    const batch_work = diff1BatchWork(1);

    const verdict = peer_mod.evalMinChainWorkGate(
        &best_header_work,
        &parent_work,
        &batch_work,
        &ZERO,
    );
    try testing.expectEqual(peer_mod.MinChainWorkVerdict.commit, verdict);
}
