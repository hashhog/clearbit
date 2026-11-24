//! BIP-68 version compare from the 2026-11-24 independent audit of clearbit
//! (finding 7), pinned against Bitcoin Core v31.1.
//!
//! txHasTimeBasedLock compared the signed i32 version (`tx.version < 2`).
//! Core's CTransaction::version is uint32_t and BIP-68 applies when
//! `tx.version >= 2` unsigned (consensus/tx_verify.cpp), so 0x80000002
//! carries a BIP-68 lock.  bip68VersionActive already does this; the
//! height-only sequence-lock arm of validateBlockForIBD (used when no MTP
//! source is wired) called the signed check and let a time lock through.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const validation = @import("validation.zig");

// ---------------------------------------------------------------------------
// F7
// ---------------------------------------------------------------------------

/// comptime args keep the input array in static memory (a runtime-built
/// array literal would dangle once this returns).
fn lockTx(comptime version: u32, comptime sequence: u32) types.Transaction {
    const ins = &[_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &.{},
        .sequence = sequence,
        .witness = &.{},
    }};
    return .{ .version = @bitCast(version), .inputs = ins, .outputs = &.{}, .lock_time = 0 };
}

// 512 s time-type relative lock (TYPE flag bit 22 set, DISABLE bit clear).
const TIME_LOCK_SEQ: u32 = 0x00400001;

test "neon F7: txHasTimeBasedLock treats version 0x80000002 as BIP-68 (unsigned, Core uint32_t)" {
    const tx = lockTx(0x80000002, TIME_LOCK_SEQ);
    try testing.expect(validation.txHasTimeBasedLock(&tx));
    const tx_max = lockTx(0xFFFFFFFF, TIME_LOCK_SEQ);
    try testing.expect(validation.txHasTimeBasedLock(&tx_max));
}

test "neon F7 control: version 1 has no BIP-68 lock; version 2 does; disabled sequence never does" {
    const v1 = lockTx(1, TIME_LOCK_SEQ);
    try testing.expect(!validation.txHasTimeBasedLock(&v1));
    const v2 = lockTx(2, TIME_LOCK_SEQ);
    try testing.expect(validation.txHasTimeBasedLock(&v2));
    const disabled = lockTx(0x80000002, TIME_LOCK_SEQ | 0x80000000);
    try testing.expect(!validation.txHasTimeBasedLock(&disabled));
}
