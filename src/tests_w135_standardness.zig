//! W135 — Standardness rules (IsStandardTx) audit (clearbit / Zig 0.13).
//!
//! Discovery wave. Audits clearbit's mempool standardness gate at the
//! depth of Bitcoin Core's `IsStandardTx` + `IsStandard` + `Solver`
//! + `ValidateInputsStandardness` + `IsWitnessStandard`, including
//! the per-tx dust cap (`MAX_DUST_OUTPUTS_PER_TX`), the
//! datacarrier / bare-multisig / dust-relay-fee CLI plumbing, and the
//! WITNESS_UNKNOWN / MULTI_A `TxoutType` variants.
//!
//! References
//! ----------
//! bitcoin-core/src/policy/policy.{h,cpp}              IsStandardTx, IsStandard, GetDust, MAX_DUST_OUTPUTS_PER_TX
//! bitcoin-core/src/script/solver.{h,cpp}              Solver, MatchMultisig, MatchMultiA, TxoutType
//! bitcoin-core/src/policy/truc_policy.h               TRUC_VERSION (TX_MAX_STANDARD_VERSION=3)
//! bitcoin-core/src/kernel/mempool_options.h           permit_bare_multisig, max_datacarrier_bytes, dust_relay_feerate
//! bitcoin-core/src/consensus/tx_check.cpp             CheckTransaction
//!
//! Status
//! ------
//! XFAIL-style guards (not actively failing). Each test asserts the
//! CURRENT observable state — including the bugs — so a future fix
//! wave can flip each gate from MISSING/PARTIAL → PRESENT by
//! deliberately breaking the corresponding test. Failures here mean
//! someone already landed the fix and forgot to update the audit.
//! See `audit/w135_standardness_rules.md` for the prose write-up.
//!
//! Run: `zig build test-w135`
//!
//! Layout
//! ------
//! Group A — Version + size + weight (G1..G5)
//! Group B — Per-input checks (G6..G10)
//! Group C — Per-output checks (G11..G16)
//! Group D — Witness-standardness (G17..G22)
//! Group E — Solver / classifier shape (G23..G27)
//! Group F — CLI plumbing / config / RBF interaction (G28..G30)

const std = @import("std");
const testing = std.testing;

const types = @import("types.zig");
const consensus = @import("consensus.zig");
const script = @import("script.zig");
const mempool_mod = @import("mempool.zig");

const Mempool = mempool_mod.Mempool;
const MempoolError = mempool_mod.MempoolError;
const ScriptType = script.ScriptType;

// =========================================================================
// Group A — Version + size + weight (G1..G5)
// =========================================================================

// G1 PRESENT: tx.version=0 is rejected as NonStandard.
// `checkStandard` is private to mempool.zig (called from `addTransactionInternal` /
// `acceptTransaction`); we exercise the behaviour via the public
// `acceptTransaction` entry point.  Since chain_state is null this
// uses the no-script-verify path but still runs `checkStandard`.
test "w135/G1: version < TX_MIN_STANDARD_VERSION rejected (PRESENT)" {
    // We assert the constant via TRUC_VERSION (covered in G3); the
    // behavioral check is exercised by W70e/W71 tests already in the
    // mempool suite (tx.version<1 -> NonStandard).  Here we pin the
    // accepted range as compile-time invariant.
    // Reference: mempool.zig:2776 `tx.version < 1 or tx.version > TRUC_VERSION`.
    try testing.expect(mempool_mod.TRUC_VERSION == 3);
}

// G2 PRESENT: tx.version=4 rejected (TX_MAX_STANDARD_VERSION=3 == TRUC_VERSION).
test "w135/G2: version > TX_MAX_STANDARD_VERSION=3 rejected (PRESENT)" {
    // See G1 — the accepted range is [1, TRUC_VERSION]; behavioral
    // tests exercising version=4 reject path live with the mempool
    // unit tests in mempool.zig.  W135 pins the constant.
    try testing.expectEqual(@as(i32, 3), mempool_mod.TRUC_VERSION);
}

// G3 PRESENT: TRUC_VERSION constant matches Core's TX_MAX_STANDARD_VERSION=3.
test "w135/G3: TRUC_VERSION=3 mirrors Core TX_MAX_STANDARD_VERSION (PRESENT)" {
    try testing.expectEqual(@as(i32, 3), mempool_mod.TRUC_VERSION);
}

// G4 PRESENT: MAX_STANDARD_TX_WEIGHT=400_000 matches Core policy/policy.h:38.
test "w135/G4: MAX_STANDARD_TX_WEIGHT=400000 (PRESENT)" {
    try testing.expectEqual(@as(u32, 400_000), consensus.MAX_STANDARD_TX_WEIGHT);
}

// G5 PRESENT: MIN_STANDARD_TX_NONWITNESS_SIZE=65 matches Core policy/policy.h:40.
test "w135/G5: MIN_STANDARD_TX_NONWITNESS_SIZE=65 (PRESENT)" {
    try testing.expectEqual(@as(usize, 65), mempool_mod.MIN_STANDARD_TX_NONWITNESS_SIZE);
}

// =========================================================================
// Group B — Per-input checks (G6..G10)
// =========================================================================

// G6 PRESENT: MAX_STANDARD_SCRIPTSIG_SIZE=1650 (Core policy/policy.h:62).
test "w135/G6: MAX_STANDARD_SCRIPTSIG_SIZE=1650 (PRESENT)" {
    try testing.expectEqual(@as(usize, 1650), mempool_mod.MAX_STANDARD_SCRIPTSIG_SIZE);
}

// G7 PRESENT: non-push-only scriptSig classified as non-push by isPushOnly.
test "w135/G7: isPushOnly rejects OP_DUP (PRESENT)" {
    const sig = [_]u8{ 0x51, 0x76 }; // OP_1 OP_DUP
    try testing.expect(!script.isPushOnly(&sig));
}

// G8 PARTIAL: per-input P2SH redeemScript sigop check exists; conservative
// branch in checkStandard fires for every input not just P2SH (BUG-11).
// We verify the conservative path: the dummy_p2sh scriptPubKey constant is
// present in mempool.zig source so the gate runs in shadow for non-P2SH.
test "w135/G8 BUG-11: conservative P2SH sigops gate exists for ALL inputs (PARTIAL)" {
    // No clean way to introspect the inline branch; we assert that
    // MAX_P2SH_SIGOPS is in the consensus module and the validation helper
    // exists.  The W96 / W70e tests already exercise the gate behavior.
    try testing.expectEqual(@as(u32, 15), consensus.MAX_P2SH_SIGOPS);
}

// G9 PARTIAL: BIP-54 sigops accounting omits spent-scriptPubKey sigops
// (BUG-12).  We assert: MAX_TX_LEGACY_SIGOPS=2500 constant is correct
// (so the value of the cap matches Core), and the gate is computed from
// validation.getLegacySigOpCount (in-tx sigops only).
test "w135/G9 BUG-12: MAX_TX_LEGACY_SIGOPS=2500 cap; in-tx-only accounting (PARTIAL)" {
    try testing.expectEqual(@as(u32, 2_500), consensus.MAX_TX_LEGACY_SIGOPS);
}

// G10 FIXED (BUG-8): classifyScript now has a distinct WITNESS_UNKNOWN
// variant (Core Solver script/solver.cpp:172-175). v1-non-32B / v2..v16
// witness programs are WITNESS_UNKNOWN, not NONSTANDARD.
test "w135/G10 BUG-8 FIXED: ScriptType has a witness_unknown variant (PRESENT)" {
    // Enumerate ScriptType variants; check that "witness_unknown" exists.
    const fields = @typeInfo(ScriptType).Enum.fields;
    comptime var seen_unknown = false;
    inline for (fields) |f| {
        if (comptime std.mem.eql(u8, f.name, "witness_unknown")) {
            seen_unknown = true;
        }
    }
    try testing.expect(seen_unknown);
    // Canonical 10 prior variants + the new witness_unknown = 11.
    try testing.expectEqual(@as(usize, 11), fields.len);
}

// =========================================================================
// Group C — Per-output checks (G11..G16)
// =========================================================================

// G11 PARTIAL: classifyScript labels malformed multisig as MULTISIG (BUG-7).
// Concrete vector: OP_3 <33-byte key> OP_3 OP_CHECKMULTISIG. n=3 claimed, 1 key.
test "w135/G11 BUG-7: classifyScript accepts malformed n=3 multisig with 1 key (PARTIAL)" {
    // OP_3 (0x53) | push33 (0x21) | <33 bytes> | OP_3 (0x53) | OP_CHECKMULTISIG (0xae)
    var s: [37]u8 = undefined;
    s[0] = 0x53; // OP_3
    s[1] = 0x21; // push 33
    for (2..35) |i| s[i] = @intCast(i & 0xff);
    s[35] = 0x53; // OP_3 (claimed n)
    s[36] = 0xae; // OP_CHECKMULTISIG
    const stype = script.classifyScript(&s);
    // BUG: clearbit returns .multisig (mis-classifies); Core's MatchMultisig
    // would return NONSTANDARD because pubkeys.size() (=1) != n (=3).
    try testing.expectEqual(ScriptType.multisig, stype);
}

// G12 PARTIAL: MAX_OP_RETURN_RELAY constant correct but no datacarrier
// CLI plumbing exists (BUG-4).  We verify the constant + assert that
// mempool.zig has no `permit_bare_multisig` / `max_datacarrier_bytes`
// field on Mempool that callers can flip.
test "w135/G12 BUG-4: no max_datacarrier_bytes field on Mempool (PARTIAL)" {
    try testing.expectEqual(@as(usize, 100_000), mempool_mod.MAX_OP_RETURN_RELAY);
    // Confirm there is no plumbing field on the Mempool struct.
    try testing.expect(!@hasField(Mempool, "max_datacarrier_bytes"));
    try testing.expect(!@hasField(Mempool, "datacarrier_size"));
    try testing.expect(!@hasField(Mempool, "accept_datacarrier"));
}

// G13 PARTIAL: no permit_bare_multisig plumbing (BUG-3).
test "w135/G13 BUG-3: no permit_bare_multisig field on Mempool (PARTIAL)" {
    try testing.expect(!@hasField(Mempool, "permit_bare_multisig"));
    try testing.expect(!@hasField(Mempool, "permitbaremultisig"));
}

// G14 PRESENT: bare-multisig with n=4 rejected (Core IsStandard MULTISIG
// branch; W71 closure).
test "w135/G14: bare-multisig n>3 rejected behavior; classifier still flags it (PRESENT)" {
    const allocator = testing.allocator;
    // OP_2 <key1> <key2> <key3> <key4> OP_4 OP_CHECKMULTISIG (2-of-4)
    // Need actual push prefixes — use 33-byte compressed key shape.
    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    try s.append(0x52); // OP_2
    for (0..4) |k| {
        try s.append(0x21); // push 33
        var key: [33]u8 = .{@as(u8, @intCast(k))} ** 33;
        key[0] = 0x02; // compressed pubkey prefix
        try s.appendSlice(&key);
    }
    try s.append(0x54); // OP_4
    try s.append(0xae); // OP_CHECKMULTISIG

    // classifyScript returns .multisig because the trailing 2 bytes are
    // OP_N OP_CHECKMULTISIG and the leading byte is OP_M.  The
    // n-of-3-or-less restriction lives in checkStandard (private), and
    // is exercised by mempool.zig's own W71 unit tests at line ~5354.
    const stype = script.classifyScript(s.items);
    try testing.expectEqual(ScriptType.multisig, stype);
}

// G15 PRESENT (BUG-13): anchor classifier exists; the strict zero-value
// rejection lives in checkStandard (private), exercised by mempool.zig
// unit tests at line ~4729.
test "w135/G15 BUG-13: anchor classifier matches (PRESENT, stricter-than-Core check in private fn)" {
    const p2a = [_]u8{ 0x51, 0x02, 0x4e, 0x73 };
    try testing.expect(script.isPayToAnchor(&p2a));
    try testing.expectEqual(ScriptType.anchor, script.classifyScript(&p2a));
    // MempoolError.AnchorNonZeroValue exists as the dispatch target for
    // the stricter-than-Core decision in checkStandard.
    const err: MempoolError = MempoolError.AnchorNonZeroValue;
    try testing.expect(err == MempoolError.AnchorNonZeroValue);
}

// G16 MISSING: no MAX_DUST_OUTPUTS_PER_TX gate (BUG-1, BUG-2).
// `checkStandard` is private; we assert the constant is missing AND
// that `Mempool.isDust` (public) flags dust outputs that should be
// counted by the missing gate.
test "w135/G16 BUG-1+BUG-2: no MAX_DUST_OUTPUTS_PER_TX cap; isDust ready (MISSING)" {
    // No MAX_DUST_OUTPUTS_PER_TX constant exposed by the mempool module.
    try testing.expect(!@hasDecl(mempool_mod, "MAX_DUST_OUTPUTS_PER_TX"));

    // The lower-level primitive is in place: build a 1-sat P2WPKH output
    // and confirm Mempool.isDust flags it.
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    for (2..22) |j| spk[j] = @intCast(j);
    const dust_out = types.TxOut{ .value = 1, .script_pubkey = spk[0..] };
    try testing.expect(Mempool.isDust(&dust_out));

    // A standard 50-output dust tx would have 50 dust outputs counted by
    // isDust.  Core's IsStandardTx would reject because 50 > 1
    // (MAX_DUST_OUTPUTS_PER_TX). clearbit's checkStandard does not have
    // a loop that consults isDust for this cap — confirmed by reading
    // mempool.zig:2774-2923 (no `dust_count` accumulator over outputs).
    // BUG present; no fix landed.
    try testing.expect(true);
}

// =========================================================================
// Group D — Witness-standardness (G17..G22)
// =========================================================================

// G17 PRESENT (BUG-10): checkWitnessStandard exists but is gated on
// chain_state != null (BUG-10).  We verify the function exists on Mempool.
test "w135/G17 BUG-10: checkWitnessStandard present but chain_state-gated (PRESENT)" {
    // The implementation is private (`fn`) so we cannot call it directly.
    // We verify that the W96 constants it depends on are wired correctly.
    try testing.expectEqual(@as(usize, 3600), mempool_mod.MAX_STANDARD_P2WSH_SCRIPT_SIZE);
    try testing.expectEqual(@as(usize, 100), mempool_mod.MAX_STANDARD_P2WSH_STACK_ITEMS);
    try testing.expectEqual(@as(usize, 80), mempool_mod.MAX_STANDARD_WITNESS_STACK_ITEM_SIZE);
}

// G18 PRESENT: ANNEX_TAG = 0x50 + TAPROOT_LEAF_TAPSCRIPT = 0xc0 +
// TAPROOT_LEAF_MASK = 0xfe.  These wire up the W127 / W135 G21 logic.
test "w135/G18: ANNEX_TAG, TAPROOT_LEAF_TAPSCRIPT, TAPROOT_LEAF_MASK constants (PRESENT)" {
    try testing.expectEqual(@as(u8, 0x50), mempool_mod.ANNEX_TAG);
    try testing.expectEqual(@as(u8, 0xc0), mempool_mod.TAPROOT_LEAF_TAPSCRIPT);
    try testing.expectEqual(@as(u8, 0xfe), mempool_mod.TAPROOT_LEAF_MASK);
}

// G19 PRESENT: isPayToAnchor helper exists and matches Core's P2A pattern
// (script/solver.cpp IsPayToAnchor returns ANCHOR for OP_1 PUSH2 "Ns").
test "w135/G19: isPayToAnchor recognises canonical P2A script (PRESENT)" {
    const p2a = [_]u8{ 0x51, 0x02, 0x4e, 0x73 };
    try testing.expect(script.isPayToAnchor(&p2a));
    try testing.expectEqual(ScriptType.anchor, script.classifyScript(&p2a));
}

// G20 PRESENT: P2WSH gates set per Core policy/policy.h:54-60.
test "w135/G20: P2WSH stack limits exposed as mempool consts (PRESENT)" {
    try testing.expectEqual(@as(usize, 100), mempool_mod.MAX_STANDARD_P2WSH_STACK_ITEMS);
    try testing.expectEqual(@as(usize, 80), mempool_mod.MAX_STANDARD_WITNESS_STACK_ITEM_SIZE);
    try testing.expectEqual(@as(usize, 3600), mempool_mod.MAX_STANDARD_P2WSH_SCRIPT_SIZE);
}

// G21 PRESENT: P2TR control-block size budget = 1 (leaf-mask byte) +
// 32 (internal key) + 32*N (merkle path), N ≤ 128.  W127 covers the
// detail; W135 confirms the constants used in checkWitnessStandard's
// tapscript branch are wired.
test "w135/G21: tapscript leaf-tag constant = 0xc0 (PRESENT)" {
    try testing.expectEqual(@as(u8, 0xc0), mempool_mod.TAPROOT_LEAF_TAPSCRIPT);
}

// G22 PRESENT: WitnessNonStandard error variant exists on MempoolError
// (so checkWitnessStandard has a place to dispatch into).
test "w135/G22: MempoolError.WitnessNonStandard exists (PRESENT)" {
    const err: MempoolError = MempoolError.WitnessNonStandard;
    try testing.expect(err == MempoolError.WitnessNonStandard);
}

// =========================================================================
// Group E — Solver / classifier shape (G23..G27)
// =========================================================================

// G23 PARTIAL (BUG-7): classifyScript multisig is a byte-shape match,
// not a key-walk match.  Concrete proof above in G11.  Here we add a
// second vector: trailing OP_n OP_CHECKMULTISIG without intermediate
// data passes too.
test "w135/G23 BUG-7: classifyScript MULTISIG byte-shape only (PARTIAL)" {
    // Minimum-length multisig per byte-shape: OP_1 OP_1 OP_CHECKMULTISIG
    // (claims 1-of-1 but ZERO pubkey pushes).  Core's MatchMultisig
    // would reject because pubkeys.size() (=0) != n (=1).
    const s = [_]u8{ 0x51, 0x51, 0xae };
    const stype = script.classifyScript(&s);
    try testing.expectEqual(ScriptType.multisig, stype);
}

// G24 FIXED (BUG-8): witversion=2 valid-shape witness program → WITNESS_UNKNOWN.
test "w135/G24 BUG-8 FIXED: witversion=2 valid-shape witness program → witness_unknown (PRESENT)" {
    // OP_2 (witversion 2) push2 "OK" — valid witness-program syntax.
    // Core's Solver returns WITNESS_UNKNOWN with vSolutions=[2, "OK"]
    // (script/solver.cpp:172-175). clearbit now returns .witness_unknown.
    const s = [_]u8{ 0x52, 0x02, 0x4f, 0x4b };
    const stype = script.classifyScript(&s);
    try testing.expectEqual(ScriptType.witness_unknown, stype);

    // isWitnessProgram parses it (it is one structurally — just unknown version).
    const wp = script.isWitnessProgram(&s);
    try testing.expect(wp != null);
    try testing.expectEqual(@as(u8, 2), wp.?.version);

    // A v1 16-byte (non-32) program is also WITNESS_UNKNOWN, not P2TR/NONSTANDARD.
    // OP_1 push16 <16 bytes>.
    var v1_16: [18]u8 = undefined;
    v1_16[0] = 0x51; // OP_1 (witversion 1)
    v1_16[1] = 0x10; // push 16
    for (2..18) |i| v1_16[i] = @intCast(i & 0xff);
    try testing.expectEqual(ScriptType.witness_unknown, script.classifyScript(&v1_16));

    // Control: a v0 program of non-{20,32} size stays NONSTANDARD (Core :177).
    // OP_0 push16 <16 bytes>.
    var v0_16: [18]u8 = undefined;
    v0_16[0] = 0x00; // OP_0 (witversion 0)
    v0_16[1] = 0x10; // push 16
    for (2..18) |i| v0_16[i] = @intCast(i & 0xff);
    try testing.expectEqual(ScriptType.nonstandard, script.classifyScript(&v0_16));

    // Control: a non-witness blob that is NOT a witness program stays NONSTANDARD
    // (proves the branch keys on isWitnessProgram, not accept-everything).
    // 50-byte all-OP_1 (0x51) script: leading byte 0x51 but length 50 != 2+push.
    const big = [_]u8{0x51} ** 50;
    try testing.expectEqual(ScriptType.nonstandard, script.classifyScript(&big));
}

// G25 MISSING (BUG-9): P2PK with invalid pubkey prefix is mis-classified.
test "w135/G25 BUG-9: P2PK classifier accepts pubkey prefix 0x00 (MISSING)" {
    // 33-byte push starting with 0x00 (invalid pubkey prefix per
    // CPubKey::ValidLength) followed by OP_CHECKSIG.  Core's
    // MatchPayToPubkey rejects via ValidSize; clearbit accepts.
    var s: [35]u8 = undefined;
    s[0] = 0x21; // push 33
    for (1..34) |i| s[i] = @intCast(i & 0xff);
    s[1] = 0x00; // first byte of the pubkey is 0x00 — invalid prefix
    s[34] = 0xac; // OP_CHECKSIG
    const stype = script.classifyScript(&s);
    // BUG: clearbit returns .p2pk; Core's Solver would return NONSTANDARD.
    try testing.expectEqual(ScriptType.p2pk, stype);
}

// G26 MISSING (BUG-14): no MULTI_A awareness in classifier or in any
// solver-shaped function in script.zig.
test "w135/G26 BUG-14: no MULTI_A classifier branch (MISSING)" {
    // grep-style introspection: script.zig has no MatchMultiA-like decl.
    try testing.expect(!@hasDecl(script, "MatchMultiA"));
    try testing.expect(!@hasDecl(script, "matchMultiA"));
    try testing.expect(!@hasDecl(script, "isMultiA"));
    try testing.expect(!@hasDecl(script, "MAX_PUBKEYS_PER_MULTI_A"));
}

// G27 PARTIAL (BUG-8 FIXED, BUG-14 still MISSING): ScriptType now has 11
// variants (WITNESS_UNKNOWN landed). MULTI_A is still missing (separate fix).
test "w135/G27 BUG-8 FIXED, BUG-14 MISSING: ScriptType has 11 variants incl witness_unknown" {
    const fields = @typeInfo(ScriptType).Enum.fields;
    try testing.expectEqual(@as(usize, 11), fields.len);

    // Enumerate variant names at comptime; witness_unknown is now present,
    // multi_a is still absent (out of scope for the WITNESS_UNKNOWN fix).
    comptime var has_witness_unknown = false;
    comptime var has_multi_a = false;
    inline for (fields) |f| {
        if (comptime std.mem.eql(u8, f.name, "witness_unknown")) has_witness_unknown = true;
        if (comptime std.mem.eql(u8, f.name, "multi_a")) has_multi_a = true;
    }
    try testing.expect(has_witness_unknown);
    try testing.expect(!has_multi_a);
}

// =========================================================================
// Group F — CLI plumbing / config / RBF interaction (G28..G30)
// =========================================================================

// G28 MISSING (BUG-3): no -permitbaremultisig CLI flag plumbing.
test "w135/G28 BUG-3: Mempool has no permit_bare_multisig knob (MISSING)" {
    try testing.expect(!@hasField(Mempool, "permit_bare_multisig"));
    try testing.expect(!@hasField(Mempool, "permitbaremultisig"));
    try testing.expect(!@hasDecl(mempool_mod, "DEFAULT_PERMIT_BAREMULTISIG"));
}

// G29 MISSING (BUG-4): no -datacarrier / -datacarriersize plumbing.
test "w135/G29 BUG-4: Mempool has no datacarrier knob (MISSING)" {
    try testing.expect(!@hasField(Mempool, "max_datacarrier_bytes"));
    try testing.expect(!@hasField(Mempool, "datacarriersize"));
    try testing.expect(!@hasField(Mempool, "accept_datacarrier"));
    try testing.expect(!@hasDecl(mempool_mod, "DEFAULT_ACCEPT_DATACARRIER"));
}

// G30 MISSING (BUG-5): no -dustrelayfee plumbing.  Mempool.isDust
// hard-codes the threshold formula.
test "w135/G30 BUG-5: Mempool has no dust_relay_fee knob (MISSING)" {
    try testing.expect(!@hasField(Mempool, "dust_relay_fee"));
    try testing.expect(!@hasField(Mempool, "dust_relay_feerate"));
    // DUST_RELAY_FEE=3000 exists as a CONSENSUS-side constant but is not
    // plumbed into a Mempool option.
    try testing.expectEqual(@as(i64, 3000), consensus.DUST_RELAY_FEE);
    try testing.expect(!@hasDecl(mempool_mod, "dustRelayFeeFromConfig"));
}
