//! W132 — BIP-68 / BIP-112 / BIP-113 audit (30 gates) — clearbit / Zig 0.13.
//!
//! Discovery wave. Audits clearbit's nSequence / OP_CSV / MTP-as-lockTime
//! pipeline against Bitcoin Core.
//!
//! References
//! ----------
//! bitcoin-core/src/consensus/tx_verify.cpp:17-110   IsFinalTx,
//!                                                   CalculateSequenceLocks,
//!                                                   EvaluateSequenceLocks,
//!                                                   SequenceLocks
//! bitcoin-core/src/script/interpreter.cpp:540-593   OP_CLTV / OP_CSV opcode bodies
//! bitcoin-core/src/script/interpreter.cpp:1744-1826 CheckLockTime / CheckSequence
//! bitcoin-core/src/chain.h:226-245                  GetMedianTimePast,
//!                                                   nMedianTimeSpan = 11
//! bitcoin-core/src/primitives/transaction.h:70-114  SEQUENCE_FINAL,
//!                                                   SEQUENCE_LOCKTIME_*
//! bitcoin-core/src/validation.cpp:2478-2562         ConnectBlock's BIP-68 enforcement
//!
//! Status
//! ------
//! XFAIL-style guards (not actively failing). Each test asserts the current
//! observable state — including the bugs — so a future fix wave can flip
//! each gate from MISSING/PARTIAL → PRESENT by deliberately breaking the
//! corresponding test. Failures here mean someone already landed the fix and
//! forgot to update the audit. See `audit/w132_nsequence_csv_mtp.md` for the
//! prose write-up.
//!
//! Run: `zig build test-w132`

const std = @import("std");
const testing = std.testing;

const types = @import("types.zig");
const consensus = @import("consensus.zig");
const validation = @import("validation.zig");
const script = @import("script.zig");

const Transaction = types.Transaction;
const TxIn = types.TxIn;
const TxOut = types.TxOut;
const OutPoint = types.OutPoint;
const ScriptEngine = script.ScriptEngine;
const ScriptFlags = script.ScriptFlags;
const ScriptError = script.ScriptError;
const UtxoInfo = validation.UtxoInfo;
const UtxoView = validation.UtxoView;
const SequenceLockResult = validation.SequenceLockResult;
const BlockIndex = validation.BlockIndex;

// ===========================================================================
// Helpers
// ===========================================================================

fn makeTx(version: i32, sequence: u32, lock_time: u32) Transaction {
    return Transaction{
        .version = version,
        .inputs = makeOneInput(sequence),
        .outputs = &[_]TxOut{},
        .lock_time = lock_time,
    };
}

fn makeOneInput(sequence: u32) []const TxIn {
    const Static = struct {
        var input_buf: [4]TxIn = undefined;
        var seq_buf: [4]u32 = undefined;
        var idx: usize = 0;
    };
    const i = Static.idx;
    Static.idx = (Static.idx + 1) % Static.input_buf.len;
    Static.seq_buf[i] = sequence;
    Static.input_buf[i] = TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = sequence,
        .witness = &[_][]const u8{},
    };
    return Static.input_buf[i .. i + 1];
}

// SeqView backed by a single UtxoInfo, returned for any outpoint.
const FlatSeqView = struct {
    info: UtxoInfo,

    fn lookup(ctx_ptr: *anyopaque, _: *const OutPoint) ?UtxoInfo {
        const me: *@This() = @ptrCast(@alignCast(ctx_ptr));
        return me.info;
    }

    fn view(self: *@This()) UtxoView {
        return .{ .context = @ptrCast(self), .lookupFn = lookup };
    }
};

// SeqView that returns null for every outpoint (forces the "UTXO not found"
// path of validation.calculateSequenceLocks).
const EmptySeqView = struct {
    fn lookup(_: *anyopaque, _: *const OutPoint) ?UtxoInfo {
        return null;
    }
    var sentinel: u8 = 0;
    fn view() UtxoView {
        return .{ .context = @ptrCast(&sentinel), .lookupFn = lookup };
    }
};

// ===========================================================================
// nSequence encoding semantics (G1-G6)
// ===========================================================================

// G1 — SEQUENCE_FINAL = 0xFFFFFFFF.  Used by IsFinalTx + CLTV to detect
// "all-final" tx.  Core: primitives/transaction.h:76.
test "w132 G1: SEQUENCE_FINAL = 0xFFFFFFFF (PRESENT)" {
    // No top-level export — value is hard-coded in validation.isFinalTx
    // (line 305) and script.zig CLTV check (line 1976).  Cross-check by
    // running IsFinalTx with sequence=0xFFFFFFFF and locktime in the future.
    const tx = makeTx(1, 0xFFFFFFFF, 1_000_000_000);
    try testing.expect(validation.isFinalTx(&tx, 0, 0));
    // And one non-final input flips it to false (locktime not yet met).
    const tx_nf = makeTx(1, 0xFFFFFFFE, 1_000_000_000);
    try testing.expect(!validation.isFinalTx(&tx_nf, 0, 0));
}

// G2 — SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31.  Core: tx.h:93.
test "w132 G2: SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000 (PRESENT)" {
    try testing.expectEqual(@as(u32, 0x80000000), consensus.SEQUENCE_LOCKTIME_DISABLE_FLAG);
    try testing.expectEqual(@as(u32, 1) << 31, consensus.SEQUENCE_LOCKTIME_DISABLE_FLAG);
}

// G3 — SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22.  Core: tx.h:99.
test "w132 G3: SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000 (PRESENT)" {
    try testing.expectEqual(@as(u32, 0x00400000), consensus.SEQUENCE_LOCKTIME_TYPE_FLAG);
    try testing.expectEqual(@as(u32, 1) << 22, consensus.SEQUENCE_LOCKTIME_TYPE_FLAG);
}

// G4 — SEQUENCE_LOCKTIME_MASK = 0x0000FFFF.  Core: tx.h:104.
test "w132 G4: SEQUENCE_LOCKTIME_MASK = 0x0000FFFF (PRESENT)" {
    try testing.expectEqual(@as(u32, 0x0000FFFF), consensus.SEQUENCE_LOCKTIME_MASK);
}

// G5 — SEQUENCE_LOCKTIME_GRANULARITY = 9.  Core: tx.h:114.
// (5,12-second time-based-relative-locktime units).
test "w132 G5: SEQUENCE_LOCKTIME_GRANULARITY = 9 (PRESENT)" {
    try testing.expectEqual(@as(u5, 9), consensus.SEQUENCE_LOCKTIME_GRANULARITY);
    // Each unit = 2^9 = 512 seconds.
    try testing.expectEqual(@as(u32, 512), @as(u32, 1) << consensus.SEQUENCE_LOCKTIME_GRANULARITY);
}

// G6 — BIP-125 derivative: MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD (SEQUENCE_FINAL - 2).
// Core: util/rbf.h:12.  Not in BIP-68 itself but in the audit scope since
// it shares the nSequence encoding space.
test "w132 G6: MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD (PRESENT)" {
    const mempool = @import("mempool.zig");
    try testing.expectEqual(@as(u32, 0xFFFFFFFD), mempool.MAX_BIP125_RBF_SEQUENCE);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF - 2), mempool.MAX_BIP125_RBF_SEQUENCE);
}

// ===========================================================================
// CalculateSequenceLocks body (G7-G12)
// ===========================================================================

// G7 — tx.version < 2 returns no-constraint result.  Core: tx_verify.cpp:51.
test "w132 G7: calculateSequenceLocks version<2 returns no-constraint (PRESENT)" {
    const tx = makeTx(1, 100, 0); // version=1, height-lock 100
    var sv = FlatSeqView{ .info = .{ .height = 50, .mtp = 0 } };
    const view = sv.view();
    const r = validation.calculateSequenceLocks(&tx, &view, 500_000, &consensus.MAINNET);
    try testing.expectEqual(@as(i32, -1), r.min_height);
    try testing.expectEqual(@as(i64, -1), r.min_time);
}

// G8 — CSV-not-active short-circuit.  clearbit checks block_height >= csv_height.
// Core uses DeploymentActiveAt(DEPLOYMENT_CSV) — see BUG-13.
test "w132 G8 BUG-13: CSV-active gate uses hard-coded params.csv_height (PARTIAL, MED)" {
    const tx = makeTx(2, 100, 0);
    var sv = FlatSeqView{ .info = .{ .height = 50, .mtp = 0 } };
    const view = sv.view();
    // Below activation: no constraint regardless of inputs.
    const r_before = validation.calculateSequenceLocks(&tx, &view, 419_327, &consensus.MAINNET);
    try testing.expectEqual(@as(i32, -1), r_before.min_height);
    // At/above activation: constraint applies.
    const r_after = validation.calculateSequenceLocks(&tx, &view, 419_328, &consensus.MAINNET);
    try testing.expect(r_after.min_height >= 0);
    // Source-level guard: the gate uses params.csv_height literally, not a
    // BIP-9 deployment-state-machine query.
    const src = @embedFile("validation.zig");
    try testing.expect(std.mem.indexOf(u8, src, "block_height < params.csv_height") != null);
    try testing.expect(std.mem.indexOf(u8, src, "DeploymentActiveAt") == null);
}

// G9 — DISABLE_FLAG-set input is skipped (no constraint contributed).
// Core: tx_verify.cpp:65-69.
test "w132 G9: DISABLE_FLAG input is skipped (PRESENT)" {
    // sequence has DISABLE_FLAG set → no per-input contribution.
    const tx = makeTx(2, 0x80000064, 0);
    var sv = FlatSeqView{ .info = .{ .height = 50, .mtp = 0 } };
    const view = sv.view();
    const r = validation.calculateSequenceLocks(&tx, &view, 500_000, &consensus.MAINNET);
    try testing.expectEqual(@as(i32, -1), r.min_height);
    try testing.expectEqual(@as(i64, -1), r.min_time);
}

// G10 BUG-4 — UTXO-not-found silently `continue`s instead of asserting.
// Core asserts prevHeights.size() == tx.vin.size() (tx_verify.cpp:41).
test "w132 G10 BUG-4: UTXO-not-found silently skipped (PARTIAL, P0-CDIV)" {
    const tx = makeTx(2, 100, 0); // height-lock 100
    const view = EmptySeqView.view();
    const r = validation.calculateSequenceLocks(&tx, &view, 500_000, &consensus.MAINNET);
    // The bug: returns no-constraint despite a non-DISABLE-FLAG input being
    // unresolved.  Core would have asserted/aborted here.
    try testing.expectEqual(@as(i32, -1), r.min_height);
    try testing.expectEqual(@as(i64, -1), r.min_time);

    // Source-level guard: the function uses `continue` on missing UTXO, not
    // `@panic` / `unreachable` / a return-value error path.
    const src = @embedFile("validation.zig");
    const anchor = std.mem.indexOf(u8, src, "utxo_view.lookup(&input.previous_output) orelse") orelse {
        try testing.expect(false);
        return;
    };
    const slice = src[anchor .. anchor + 200];
    try testing.expect(std.mem.indexOf(u8, slice, "continue") != null);
    try testing.expect(std.mem.indexOf(u8, slice, "@panic") == null);
    try testing.expect(std.mem.indexOf(u8, slice, "unreachable") == null);
}

// G11 — Height-based lock formula: nCoinHeight + (seq & MASK) - 1.
// Core: tx_verify.cpp:90.
test "w132 G11: height-based lock = coinHeight + (seq & MASK) - 1 (PRESENT)" {
    // coinHeight = 100, lock_value = 10 → min_height = 100 + 10 - 1 = 109.
    const tx = makeTx(2, 10, 0);
    var sv = FlatSeqView{ .info = .{ .height = 100, .mtp = 0 } };
    const view = sv.view();
    const r = validation.calculateSequenceLocks(&tx, &view, 500_000, &consensus.MAINNET);
    try testing.expectEqual(@as(i32, 109), r.min_height);
    try testing.expectEqual(@as(i64, -1), r.min_time);
}

// G12 BUG-2 — Time-based lock formula uses utxo_info.mtp directly.
// The bug: mempool callers pass `tip MTP` for `utxo_info.mtp` (mempool.zig:1126)
// instead of `GetAncestor(coinHeight-1)->GetMedianTimePast()` (Core line 74).
test "w132 G12 BUG-2: time-based lock arithmetic vs mempool tip-MTP misuse (PARTIAL, P1-CDIV)" {
    // Local sanity: with coin's MTP = 1_600_000_000 and lock_value = 10:
    // required_time = 1_600_000_000 + (10 << 9) - 1 = 1_600_005_119.
    const tx = makeTx(2, consensus.SEQUENCE_LOCKTIME_TYPE_FLAG | 10, 0);
    var sv = FlatSeqView{ .info = .{ .height = 100, .mtp = 1_600_000_000 } };
    const view = sv.view();
    const r = validation.calculateSequenceLocks(&tx, &view, 500_000, &consensus.MAINNET);
    try testing.expectEqual(@as(i32, -1), r.min_height);
    try testing.expectEqual(@as(i64, 1_600_000_000 + (10 << 9) - 1), r.min_time);

    // Source-level guard: mempool.zig populates seq_utxo_infos[i].mtp with
    // cs.computeMTP() (the TIP's MTP), not getMtpAtHeightFn(coinHeight-1).
    const src = @embedFile("mempool.zig");
    try testing.expect(std.mem.indexOf(u8, src, ".mtp = cs.computeMTP()") != null);
    // And the comment acknowledging the divergence:
    try testing.expect(std.mem.indexOf(u8, src, "tip MTP conservatively") != null);
}

// ===========================================================================
// EvaluateSequenceLocks + SequenceLocks integration (G13-G16)
// ===========================================================================

// G13 — checkSequenceLocks rejects when min_height >= block.nHeight.
// Core: tx_verify.cpp:101.
test "w132 G13: checkSequenceLocks fails on min_height >= tip.height (PRESENT)" {
    const r = SequenceLockResult{ .min_height = 100, .min_time = -1 };
    // tip.height = 100 → 100 >= 100 → fail
    try testing.expect(!validation.checkSequenceLocks(r, &.{ .height = 100, .prev_mtp = 0 }));
    // tip.height = 101 → 100 < 101 → pass (height-only, time sentinel)
    try testing.expect(validation.checkSequenceLocks(r, &.{ .height = 101, .prev_mtp = 0 }));
}

// G14 — checkSequenceLocks rejects when min_time >= block.pprev->MTP.
// Core: tx_verify.cpp:101 (lockPair.second >= nBlockTime).
test "w132 G14: checkSequenceLocks fails on min_time >= tip.prev_mtp (PRESENT)" {
    const r = SequenceLockResult{ .min_height = -1, .min_time = 1_600_000_000 };
    try testing.expect(!validation.checkSequenceLocks(r, &.{ .height = 100, .prev_mtp = 1_600_000_000 }));
    try testing.expect(validation.checkSequenceLocks(r, &.{ .height = 100, .prev_mtp = 1_600_000_001 }));
}

// G15 BUG-1 — mtp=0 silently bypasses the time-based BIP-68 check.
// The IBD path at validation.zig:1574-1583 falls back to "height-only" when
// ctx.getMtpAtHeightFn == null.  This permits time-locked txs to admit
// before their delay has expired.
test "w132 G15 BUG-1: time-based BIP-68 bypassed when callback not wired (PARTIAL, P0-CDIV)" {
    // Construct a scenario where the time-lock has NOT been met but the
    // height-only fallback returns "satisfied".
    //
    // - lock_value = 0xFFFF (max) → required_time = 0 + (0xFFFF << 9) - 1
    //   ≈ 33,553,919 seconds ≈ 388 days.
    // - prev_mtp = 1_700_000_000 (some current-era MTP).
    // - 1_700_000_000 > 33_553_919 → the bypass check would say "satisfied"
    //   even though the coin was just created (mtp=0).
    const seq: u32 = consensus.SEQUENCE_LOCKTIME_TYPE_FLAG | 0xFFFF;
    const tx = makeTx(2, seq, 0);
    var sv = FlatSeqView{ .info = .{ .height = 50, .mtp = 0 } }; // mtp=0 (BUG)
    const view = sv.view();
    const r = validation.calculateSequenceLocks(&tx, &view, 500_000, &consensus.MAINNET);

    // The bug: min_time is small because mtp=0 collapses the formula.
    try testing.expect(r.min_time >= 0);
    try testing.expect(r.min_time < 100_000_000); // way less than current chain time

    // Worse: a real-chain prev_mtp > min_time so the gate passes.
    const tip = BlockIndex{ .height = 500_001, .prev_mtp = 1_700_000_000 };
    try testing.expect(validation.checkSequenceLocks(r, &tip)); // BUG: would have rejected with correct mtp

    // Source-level guard: the comment acknowledging the bypass.
    const src = @embedFile("validation.zig");
    try testing.expect(std.mem.indexOf(u8, src, "permissive (always-satisfied)") != null);
    try testing.expect(std.mem.indexOf(u8, src, "full_time_check") != null);
}

// G16 — Composition: SequenceLocks(tx, ...) == EvaluateSequenceLocks(...,
// CalculateSequenceLocks(...)).  Mempool wires this composition.
test "w132 G16: composition: calculate + check matches Core SequenceLocks() (PRESENT)" {
    // height-based, satisfied.
    const tx = makeTx(2, 10, 0);
    var sv = FlatSeqView{ .info = .{ .height = 100, .mtp = 0 } };
    const view = sv.view();
    const r = validation.calculateSequenceLocks(&tx, &view, 500_000, &consensus.MAINNET);
    // min_height = 109 → tip 110 satisfies, tip 109 doesn't.
    try testing.expect(validation.checkSequenceLocks(r, &.{ .height = 110, .prev_mtp = 0 }));
    try testing.expect(!validation.checkSequenceLocks(r, &.{ .height = 109, .prev_mtp = 0 }));
}

// ===========================================================================
// OP_CSV / CheckSequence script-level (G17-G22)
// ===========================================================================

// G17 — flag-off ⇒ NOP3, flag-off + discourage_upgradable_nops ⇒ error.
// Core: interpreter.cpp:561-566, 595-601.
test "w132 G17: OP_CSV flag-off NOP and DISCOURAGE_UPGRADABLE_NOPS (PRESENT)" {
    const allocator = testing.allocator;
    const tx = Transaction{
        .version = 2,
        .inputs = &[_]TxIn{.{
            .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]TxOut{},
        .lock_time = 0,
    };
    // flag-off, no discourage → NOP
    {
        var flags = ScriptFlags{};
        flags.verify_checksequenceverify = false;
        flags.discourage_upgradable_nops = false;
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s = [_]u8{ 0x51, 0xb2 }; // OP_1 OP_CSV
        try engine.execute(&s);
    }
    // flag-off + discourage → error
    {
        var flags = ScriptFlags{};
        flags.verify_checksequenceverify = false;
        flags.discourage_upgradable_nops = true;
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s = [_]u8{ 0x51, 0xb2 };
        try testing.expectError(ScriptError.DiscourageUpgradableNops, engine.execute(&s));
    }
}

// G18 — 5-byte ScriptNum decode + MINIMALDATA respected.
// Core: interpreter.cpp:574 (CScriptNum(stacktop(-1), fRequireMinimal, 5)).
test "w132 G18: OP_CSV 5-byte ScriptNum + MINIMALDATA (PRESENT)" {
    const allocator = testing.allocator;
    const tx = Transaction{
        .version = 2,
        .inputs = &[_]TxIn{.{
            .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 100,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // Non-minimal 2-byte push of value 100 (should be 1-byte): rejected.
    const s = [_]u8{ 0x02, 0x64, 0x00, 0xb2 };
    try testing.expectError(ScriptError.InvalidNumber, engine.execute(&s));
}

// G19 — Negative operand ⇒ NegativeLocktime.
// Core: interpreter.cpp:579-580.
test "w132 G19: OP_CSV negative operand → NegativeLocktime (PRESENT)" {
    const allocator = testing.allocator;
    const tx = Transaction{
        .version = 2,
        .inputs = &[_]TxIn{.{
            .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 100,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // OP_1NEGATE OP_CSV → -1 operand → NegativeLocktime
    const s = [_]u8{ 0x4f, 0xb2 };
    try testing.expectError(ScriptError.NegativeLocktime, engine.execute(&s));
}

// G20 — Operand DISABLE_FLAG ⇒ NOP (soft-fork extensibility).
// Core: interpreter.cpp:585-586.
test "w132 G20: OP_CSV operand DISABLE_FLAG (bit-31) → NOP (PRESENT)" {
    const allocator = testing.allocator;
    const tx = Transaction{
        .version = 2,
        .inputs = &[_]TxIn{.{
            .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0, // would fail Check otherwise
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]TxOut{},
        .lock_time = 0,
    };
    var flags = ScriptFlags{};
    flags.verify_checksequenceverify = true;
    flags.verify_minimaldata = false;
    var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
    defer engine.deinit();
    // 5-byte push: 0x01 0x00 0x00 0x00 0x80 = 0x80000001 with high bit set;
    // BIP-68 5-byte encoding (sign bit + 0x80000000 magnitude).
    // Operand value = -(2^31)+1 in CScriptNum encoding; positive equivalent
    // is 0x80000001 stored as 5 bytes: 01 00 00 00 80
    //
    // Easier: push the value 0x80000001 as a non-negative 5-byte ScriptNum.
    // In CScriptNum, positive 0x80000001 = bytes [0x01, 0x00, 0x00, 0x80, 0x00]
    // (low-byte first; the trailing 0x00 keeps it positive).
    const s = [_]u8{ 0x05, 0x01, 0x00, 0x00, 0x80, 0x00, 0xb2 };
    try engine.execute(&s); // DISABLE_FLAG set → NOP, no error
}

// G21 — tx.version<2 ⇒ UnsatisfiedLocktime; input DISABLE_FLAG ⇒
// UnsatisfiedLocktime.  Core: interpreter.cpp:1790-1798.
test "w132 G21: OP_CSV tx.version<2 and input DISABLE_FLAG → UnsatisfiedLocktime (PRESENT)" {
    const allocator = testing.allocator;
    // version=1 → UnsatisfiedLocktime
    {
        const tx = Transaction{
            .version = 1,
            .inputs = &[_]TxIn{.{
                .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
                .script_sig = &[_]u8{},
                .sequence = 100,
                .witness = &[_][]const u8{},
            }},
            .outputs = &[_]TxOut{},
            .lock_time = 0,
        };
        var flags = ScriptFlags{};
        flags.verify_checksequenceverify = true;
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s = [_]u8{ 0x51, 0xb2 }; // OP_1 OP_CSV
        try testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
    }
    // input has DISABLE_FLAG → UnsatisfiedLocktime
    {
        const tx = Transaction{
            .version = 2,
            .inputs = &[_]TxIn{.{
                .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
                .script_sig = &[_]u8{},
                .sequence = 0x80000001, // DISABLE_FLAG
                .witness = &[_][]const u8{},
            }},
            .outputs = &[_]TxOut{},
            .lock_time = 0,
        };
        var flags = ScriptFlags{};
        flags.verify_checksequenceverify = true;
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s = [_]u8{ 0x51, 0xb2 };
        try testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
    }
}

// G22 BUG-5 — OP_CSV masked comparison.  Verifies type-flag compat
// and value-comparison both fire correctly.  Catches the 5-byte→u32
// truncation site as a source-level guard (defense-in-depth).
test "w132 G22 BUG-5: OP_CSV masked comparison + 5-byte→u32 truncation (PARTIAL, MED)" {
    const allocator = testing.allocator;
    // Type-flag mismatch: operand is height-type, input is time-type → fail.
    {
        const tx = Transaction{
            .version = 2,
            .inputs = &[_]TxIn{.{
                .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
                .script_sig = &[_]u8{},
                .sequence = consensus.SEQUENCE_LOCKTIME_TYPE_FLAG | 1, // time
                .witness = &[_][]const u8{},
            }},
            .outputs = &[_]TxOut{},
            .lock_time = 0,
        };
        var flags = ScriptFlags{};
        flags.verify_checksequenceverify = true;
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s = [_]u8{ 0x51, 0xb2 }; // OP_1 (height) OP_CSV
        try testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
    }
    // Operand value > input.sequence (masked) → fail.
    {
        const tx = Transaction{
            .version = 2,
            .inputs = &[_]TxIn{.{
                .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
                .script_sig = &[_]u8{},
                .sequence = 5,
                .witness = &[_][]const u8{},
            }},
            .outputs = &[_]TxOut{},
            .lock_time = 0,
        };
        var flags = ScriptFlags{};
        flags.verify_checksequenceverify = true;
        flags.verify_minimaldata = false;
        var engine = ScriptEngine.init(allocator, &tx, 0, 0, flags);
        defer engine.deinit();
        const s = [_]u8{ 0x01, 0x06, 0xb2 }; // push 6 > 5
        try testing.expectError(ScriptError.UnsatisfiedLocktime, engine.execute(&s));
    }
    // BUG-5: source-level guard for the truncation site.
    const src = @embedFile("script.zig");
    try testing.expect(std.mem.indexOf(u8, src, "@intCast(@as(u64, @intCast(sequence)) & 0xFFFFFFFF)") != null);
}

// ===========================================================================
// IsFinalTx + BIP-113 MTP-as-lockTime (G23-G26)
// ===========================================================================

// G23 — tx.nLockTime == 0 ⇒ final unconditionally.  Core: tx_verify.cpp:19-20.
test "w132 G23: isFinalTx locktime=0 always final (PRESENT)" {
    const tx = makeTx(1, 0x00000000, 0);
    try testing.expect(validation.isFinalTx(&tx, 0, 0));
    try testing.expect(validation.isFinalTx(&tx, 1_000_000, 2_000_000_000));
}

// G24 — Threshold-flip: tx.nLockTime < 500_000_000 ⇒ height-cutoff,
// else time-cutoff.  Core: tx_verify.cpp:21.
test "w132 G24: isFinalTx threshold flip uses block_height vs lock_time_cutoff (PRESENT)" {
    // Height-style locktime = 100
    const tx_h = makeTx(1, 0, 100);
    // At height 100: locktime not yet < threshold (100 < 100 false) and not all
    // inputs FINAL → not final.
    try testing.expect(!validation.isFinalTx(&tx_h, 100, 0));
    // At height 101: 100 < 101 → final.
    try testing.expect(validation.isFinalTx(&tx_h, 101, 0));

    // Time-style locktime = 1_600_000_000 (>= 500_000_000 threshold).
    const tx_t = makeTx(1, 0, 1_600_000_000);
    // block_height irrelevant; only lock_time_cutoff matters.
    try testing.expect(!validation.isFinalTx(&tx_t, 1_000_000, 1_600_000_000));
    try testing.expect(validation.isFinalTx(&tx_t, 1_000_000, 1_600_000_001));
}

// G25 — All-inputs-FINAL ⇒ final even if locktime not yet met.
// Core: tx_verify.cpp:32-35.
test "w132 G25: isFinalTx all-inputs-SEQUENCE_FINAL bypass (PRESENT)" {
    // locktime in the future (height-style) but all inputs FINAL → still final.
    const tx_all_final = Transaction{
        .version = 1,
        .inputs = &[_]TxIn{
            .{
                .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
                .script_sig = &[_]u8{},
                .sequence = 0xFFFFFFFF,
                .witness = &[_][]const u8{},
            },
            .{
                .previous_output = .{ .hash = [_]u8{1} ** 32, .index = 1 },
                .script_sig = &[_]u8{},
                .sequence = 0xFFFFFFFF,
                .witness = &[_][]const u8{},
            },
        },
        .outputs = &[_]TxOut{},
        .lock_time = 1_000_000, // height-style, far in the future
    };
    try testing.expect(validation.isFinalTx(&tx_all_final, 100, 0));

    // One non-final input flips the result.
    const tx_mixed = Transaction{
        .version = 1,
        .inputs = &[_]TxIn{
            .{
                .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0 },
                .script_sig = &[_]u8{},
                .sequence = 0xFFFFFFFF,
                .witness = &[_][]const u8{},
            },
            .{
                .previous_output = .{ .hash = [_]u8{1} ** 32, .index = 1 },
                .script_sig = &[_]u8{},
                .sequence = 0xFFFFFFFE,
                .witness = &[_][]const u8{},
            },
        },
        .outputs = &[_]TxOut{},
        .lock_time = 1_000_000,
    };
    try testing.expect(!validation.isFinalTx(&tx_mixed, 100, 0));
}

// G26 — BIP-113: lock_time_cutoff = MTP when CSV active, else
// block.header.timestamp.  Core: validation.cpp:4146 (ContextualCheckBlock).
test "w132 G26: BIP-113 lock_time_cutoff = MTP when CSV active (PRESENT)" {
    // Time-style locktime 1_600_000_000:
    // - lock_time_cutoff = 1_600_000_001 (one past) → final.
    // - lock_time_cutoff = 1_600_000_000 (equal) → NOT final (Core: <, not <=).
    const tx_t = makeTx(1, 0, 1_600_000_000);
    try testing.expect(validation.isFinalTx(&tx_t, 1_000_000, 1_600_000_001));
    try testing.expect(!validation.isFinalTx(&tx_t, 1_000_000, 1_600_000_000));

    // Source-level guard: the caller does flip between MTP and block-timestamp
    // based on `csv_active` (validation.zig:895-899, mempool.zig:1051-1054).
    const src_v = @embedFile("validation.zig");
    try testing.expect(std.mem.indexOf(u8, src_v, "if (csv_active)") != null);
    try testing.expect(std.mem.indexOf(u8, src_v, "lock_time_cutoff") != null);
    const src_m = @embedFile("mempool.zig");
    try testing.expect(std.mem.indexOf(u8, src_m, "lock_time_cutoff") != null);
}

// ===========================================================================
// ConnectBlock / Mempool integration + chain MTP (G27-G30)
// ===========================================================================

// G27 — medianTimePast over up to 11 timestamps, returning the upper-median.
// Core: chain.h:231-245.
test "w132 G27: medianTimePast 11-window, sorted, upper-median (PRESENT)" {
    // 11 distinct timestamps → median is the 6th (index 5).
    const ts = [_]u32{ 10, 50, 30, 70, 20, 40, 60, 80, 90, 25, 35 };
    const m = validation.medianTimePast(&ts);
    // Sorted: [10, 20, 25, 30, 35, 40, 50, 60, 70, 80, 90] → index 5 = 40.
    try testing.expectEqual(@as(u32, 40), m);

    // Fewer than 11 (e.g. 3): index 3/2 = 1 → upper-median = middle.
    const ts3 = [_]u32{ 30, 10, 20 };
    const m3 = validation.medianTimePast(&ts3);
    try testing.expectEqual(@as(u32, 20), m3);

    // Empty: 0 sentinel.
    const ts0 = [_]u32{};
    try testing.expectEqual(@as(u32, 0), validation.medianTimePast(&ts0));
}

// G28 — computePrevMtp(prev_hash) walks back up to 11 entries via
// header_index — equals Core's prev->GetMedianTimePast().
// This is structural — the function lives on PeerManager and depends on
// runtime state.  We grep the source as a guard.
test "w132 G28: computePrevMtp walks 11 entries via header_index (PRESENT)" {
    const src = @embedFile("peer.zig");
    // Anchor: function name + 11-window + medianTimePast call.
    try testing.expect(std.mem.indexOf(u8, src, "fn computePrevMtp") != null);
    try testing.expect(std.mem.indexOf(u8, src, "[11]u32") != null);
    try testing.expect(std.mem.indexOf(u8, src, "validation.medianTimePast") != null);
    // The walk traverses prev_hash (not height-based).
    try testing.expect(std.mem.indexOf(u8, src, "cursor = entry.prev_hash") != null);
}

// G29 BUG-1 (storage-layer side) — computeMtpAtHeight returns 0 silently
// on index/cache miss.  The BIP-68 calculator then treats this as
// "nCoinTime = 0" → permissive.  See BUG-1 above.
test "w132 G29 BUG-1: computeMtpAtHeight returns 0 silently on cache miss (PARTIAL, P0-CDIV)" {
    const src = @embedFile("peer.zig");
    // The pattern: function returns 0 on header_index miss without erroring.
    try testing.expect(std.mem.indexOf(u8, src, "fn computeMtpAtHeight") != null);
    try testing.expect(std.mem.indexOf(u8, src, "if (n == 0) return 0;") != null);
    // The trampoline forwards into the same 0-on-miss path.
    try testing.expect(std.mem.indexOf(u8, src, "fn getMtpAtHeightTrampoline") != null);
    // Comment acknowledging the issue:
    try testing.expect(std.mem.indexOf(u8, src, "A 0 return causes the caller to skip time-based BIP-68") != null);
}

// G30 BUG-12 — ConnectBlock BIP-68 enforcement: error label.  Core emits
// `bad-txns-nonfinal`; clearbit emits `ValidationError.SequenceLockNotSatisfied`.
test "w132 G30 BUG-12: BIP-68 error label drift from bad-txns-nonfinal (PARTIAL, LOW)" {
    const src = @embedFile("validation.zig");
    // The error name clearbit emits.
    try testing.expect(std.mem.indexOf(u8, src, "ValidationError.SequenceLockNotSatisfied") != null);
    // Core's canonical reason string is referenced in comments but is NOT the
    // user-visible error.  Comment proves clearbit knows the canonical name:
    try testing.expect(std.mem.indexOf(u8, src, "bad-txns-nonfinal") != null);
    // Mempool path emits a different name still:
    const src_m = @embedFile("mempool.zig");
    try testing.expect(std.mem.indexOf(u8, src_m, "SequenceLockNotSatisfied") != null);
}

// ===========================================================================
// Bonus / cross-cuts (kept inside the 30-gate budget by being inlined-above)
// ===========================================================================

// Sanity: SEQUENCE_FINAL semantics drive both BIP-65 CLTV and BIP-68 IsFinalTx.
test "w132 sanity: SEQUENCE_FINAL constant exercised by IsFinalTx and CLTV" {
    // IsFinalTx behaviour with all-FINAL inputs (G25 above also covers this
    // but a quick sanity reads the constant from validation.isFinalTx via
    // observable behaviour).
    const tx = makeTx(1, 0xFFFFFFFF, 1_000_000_000);
    try testing.expect(validation.isFinalTx(&tx, 0, 0));

    // CLTV: input sequence = SEQUENCE_FINAL causes UnsatisfiedLocktime
    // (BIP-65, interpreter.cpp:1775).  Covered by W105 / W120 in script.zig;
    // we just assert here that the script path uses the same hex constant.
    const src = @embedFile("script.zig");
    try testing.expect(std.mem.indexOf(u8, src, "0xFFFFFFFF") != null);
}
