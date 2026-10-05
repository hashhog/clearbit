//! Mempool time-lock fix — tests of the NEW API (ChainState.mtpAtActiveHeight /
//! rewindMtpRingAfterDisconnect / tipMtp, Mempool.removeForReorg).  The
//! base-comparable half (fail on e1753e4, pass on the fix) is
//! tests_mtp_bip68.zig; the fail-before evidence for the reorg eviction is the
//! process harness (invalidateblock on regtest) recorded in the receipt.
//!
//! Core reference for the eviction predicate: validation.cpp
//! MaybeUpdateMempoolForReorg → filter_final_and_mature (CheckFinalTxAtTip,
//! CheckSequenceLocksAtTip on recomputed lock points, coinbase maturity at
//! tip+1), removing the entry and all its descendants.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const base = @import("tests_mtp_bip68.zig");

const TIP = base.TIP;

/// Disconnect the tip of the DB-less fixture the way the real disconnect
/// paths do: step best_hash / best_height back, then rewind the ring.
fn simulateDisconnect(cs: *storage.ChainState) void {
    cs.best_height -= 1;
    cs.best_hash = [_]u8{@truncate(cs.best_height)} ** 32;
    cs.rewindMtpRingAfterDisconnect();
}

test "mtp-fix: mtpAtActiveHeight answers MTP(h) from the active chain; tipMtp == MTP(tip)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    base.setupChain(&cs);
    try testing.expectEqual(base.mtpOf(TIP), cs.tipMtp());
    try testing.expectEqual(base.mtpOf(TIP - 21), cs.mtpAtActiveHeight(TIP - 21).?);
    // Above the tip / outside the resolvable window → null (never a guess).
    try testing.expect(cs.mtpAtActiveHeight(TIP + 1) == null);
    try testing.expect(cs.mtpAtActiveHeight(TIP - 55) == null);
}

test "mtp-fix: rewindMtpRingAfterDisconnect rebuilds the window of the new tip" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    base.setupChain(&cs);
    simulateDisconnect(&cs);
    try testing.expectEqual(base.mtpOf(TIP - 1), cs.computeMTP());
    try testing.expect(cs.mtpRingCoversTip());
    simulateDisconnect(&cs);
    try testing.expectEqual(base.mtpOf(TIP - 2), cs.computeMTP());
}

test "mtp-fix: unresolvable window after a disconnect → ring drops the old tip slot, tipMtp fails closed (0)" {
    const allocator = testing.allocator;
    var cs = storage.ChainState.init(null, 64, allocator);
    defer cs.deinit();
    // Ring only — no retarget-ring / DB history to rebuild from.
    cs.best_height = TIP;
    var i: u32 = 0;
    while (i < 11) : (i += 1) cs.recent_timestamps[i] = base.tsAt(TIP - i);
    cs.recent_ts_count = 11;
    cs.best_height -= 1;
    cs.rewindMtpRingAfterDisconnect();
    try testing.expectEqual(@as(u32, 10), cs.recent_ts_count);
    try testing.expectEqual(base.tsAt(TIP - 1), cs.recent_timestamps[0]);
    try testing.expect(!cs.mtpRingCoversTip());
    try testing.expectEqual(@as(u32, 0), cs.tipMtp());
}
