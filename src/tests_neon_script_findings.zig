//! Script-interpreter findings from the 2026-11-24 independent audit of
//! clearbit, each pinned against Bitcoin Core v31.1's interpreter.
//!
//! F1 (consensus): OP_CHECKMULTISIG(VERIFY) in BASE scripts skipped
//!     FindAndDelete for an EMPTY signature.  Core runs
//!     `FindAndDelete(scriptCode, CScript() << vchSig)` for every signature,
//!     and `CScript() << {}` is the one byte 0x00 (OP_0).  So an empty sig
//!     deletes every opcode-aligned OP_0 from the scriptCode that the OTHER
//!     signatures are hashed over.  With block flags (DERSIG on, NULLFAIL off)
//!     that splits both ways: a block Core rejects and clearbit accepted, and
//!     a block Core accepts and clearbit rejected.
//! F2 (policy): OP_CHECKSIG(VERIFY) returned false for an empty sig before
//!     CONST_SCRIPTCODE, STRICTENC pubkey and WITNESS_PUBKEYTYPE checks, which
//!     Core runs whatever the sig (EvalChecksigPreTapscript).
//! F3 (policy): a P2SH-wrapped pay-to-anchor escaped
//!     DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.  Core exempts only the NATIVE
//!     anchor (`!is_p2sh && IsPayToAnchor`).
//! F4 (interpreter flags): with CLTV/CSV verification off, OP_NOP2/OP_NOP3
//!     failed under DISCOURAGE_UPGRADABLE_NOPS.  Core treats them as plain
//!     NOPs (`break`) and discourages only NOP1 and NOP4..NOP10.
//!
//! Every "Core:" verdict below is what Core v31.1's EvalScript / VerifyScript
//! returns for the same script, flags and signatures; F1's two blocks are
//! also replayed against a real Core v31.1 regtest node by the companion
//! script in the PR (neon_f1_core_regtest.py).

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const script = @import("script.zig");
const crypto = @import("crypto.zig");
const validation = @import("validation.zig");
const consensus = @import("consensus.zig");

const ScriptError = script.ScriptError;

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_3: u8 = 0x53;
const OP_DROP: u8 = 0x75;
const OP_NOT: u8 = 0x91;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_NOP1: u8 = 0xb0;
const OP_CLTV: u8 = 0xb1;
const OP_CSV: u8 = 0xb2;
const OP_HASH160: u8 = 0xa9;
const OP_EQUAL: u8 = 0x87;

// Private key 1 -> G; 2G and 3G are only ever paired with non-verifying sigs.
const PK1 = hexArr(33, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
const PK2 = hexArr(33, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
const PK3 = hexArr(33, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
// G uncompressed (valid STRICTENC, invalid WITNESS_PUBKEYTYPE).
const PK1_UNCOMPRESSED = hexArr(65, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
// G "hybrid" (0x06 prefix): invalid under STRICTENC (Core PUBKEYTYPE).
const PK1_HYBRID = hexArr(65, "0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

fn hexArr(comptime n: usize, comptime h: []const u8) [n]u8 {
    @setEvalBranchQuota(10_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

const PREV = types.OutPoint{ .hash = [_]u8{0x11} ** 32, .index = 0 };
const OUTS = [_]types.TxOut{.{ .value = 1000, .script_pubkey = &[_]u8{OP_1} }};

fn spendTx(inputs: []const types.TxIn) types.Transaction {
    return .{ .version = 1, .inputs = inputs, .outputs = &OUTS, .lock_time = 0 };
}

/// Block flags at a height where every regtest deployment is active
/// (P2SH, WITNESS, TAPROOT, DERSIG, CLTV, CSV, NULLDUMMY; no NULLFAIL).
fn blockFlags() script.ScriptFlags {
    return validation.getBlockScriptFlags(1000, &consensus.REGTEST);
}

fn standardFlags() script.ScriptFlags {
    return validation.getStandardScriptFlags(1000, &consensus.REGTEST);
}

fn run(tx: *const types.Transaction, flags: script.ScriptFlags, script_sig: []const u8, spk: []const u8, witness: []const []const u8) ScriptError!bool {
    var engine = script.ScriptEngine.init(testing.allocator, tx, 0, 1000, flags);
    defer engine.deinit();
    return engine.verify(script_sig, spk, witness);
}

fn pushData(list: *std.ArrayList(u8), data: []const u8) !void {
    std.debug.assert(data.len < 0x4c);
    try list.append(@intCast(data.len));
    try list.appendSlice(data);
}

// ---------------------------------------------------------------------------
// F1: CHECKMULTISIG FindAndDelete of an empty signature (block consensus)
// ---------------------------------------------------------------------------

/// scriptPubKey: OP_0 OP_DROP OP_3 <PK3> <PK2> <PK1> OP_3 OP_CHECKMULTISIG OP_NOT
fn f1ScriptPubKey(a: std.mem.Allocator) ![]u8 {
    var l = std.ArrayList(u8).init(a);
    errdefer l.deinit();
    try l.appendSlice(&.{ OP_0, OP_DROP, OP_3 });
    try pushData(&l, &PK3);
    try pushData(&l, &PK2);
    try pushData(&l, &PK1);
    try l.appendSlice(&.{ OP_3, OP_CHECKMULTISIG, OP_NOT });
    return l.toOwnedSlice();
}

/// scriptSig: OP_0 (dummy) OP_0 ("" sig) <bad-DER sig> <sig0>
/// -> sigs as Core walks them: [sig0, bad, ""], keys [PK1, PK2, PK3].
fn f1ScriptSig(a: std.mem.Allocator, sig0: []const u8) ![]u8 {
    var l = std.ArrayList(u8).init(a);
    errdefer l.deinit();
    try l.appendSlice(&.{ OP_0, OP_0 });
    try pushData(&l, &[_]u8{ 0x30, 0x00, 0x01 }); // not DER -> SIG_DER under DERSIG
    try pushData(&l, sig0);
    return l.toOwnedSlice();
}

/// sig0 = SIGHASH_ALL signature by key 1 over `script_code`, written to `out`.
fn f1Sig0(out: *[73]u8, tx: *const types.Transaction, script_code: []const u8) ![]const u8 {
    const h = try script.legacySignatureHash(testing.allocator, tx, 0, script_code, 0x01);
    const seckey = [_]u8{0} ** 31 ++ [_]u8{1};
    const der = crypto.ecdsaSignDer(&h, &seckey) orelse return error.SignFailed;
    @memcpy(out[0..der.len], der.bytes[0..der.len]);
    out[der.len] = 0x01; // SIGHASH_ALL
    return out[0 .. der.len + 1];
}

fn f1Case(sign_over_cleaned: bool) anyerror!bool {
    const a = testing.allocator;
    const spk = try f1ScriptPubKey(a);
    defer a.free(spk);
    // Core's scriptCode after FindAndDelete(scriptCode, OP_0): the leading
    // OP_0 is the only opcode-aligned 0x00 in this script.
    const cleaned = spk[1..];

    // The scriptSig does not enter the legacy sighash, so sign over a tx
    // carrying an empty one, then splice the real scriptSig in.
    var ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &.{} }};
    var tx = spendTx(&ins);
    var sig_buf: [73]u8 = undefined;
    const sig0 = try f1Sig0(&sig_buf, &tx, if (sign_over_cleaned) cleaned else spk);

    const ss = try f1ScriptSig(a, sig0);
    defer a.free(ss);
    ins[0].script_sig = ss;
    tx = spendTx(&ins);
    return run(&tx, blockFlags(), ss, spk, &.{});
}

test "neon F1: CHECKMULTISIG empty sig deletes OP_0 from scriptCode - Core REJECTS (SIG_DER), block flags" {
    // sig0 is valid over the OP_0-deleted scriptCode.  Core: (sig0,PK1) passes,
    // (bad,PK2) -> SCRIPT_ERR_SIG_DER -> the input, and the block, are invalid.
    // Master skipped the deletion: sig0 failed, the early-exit fired before the
    // bad sig was looked at, CHECKMULTISIG pushed false, OP_NOT -> accepted.
    try testing.expectError(ScriptError.InvalidSignatureEncoding, f1Case(true));
}

test "neon F1: CHECKMULTISIG empty sig deletes OP_0 from scriptCode - Core ACCEPTS, block flags" {
    // sig0 is valid over the scriptCode WITH OP_0.  Core deletes OP_0, so sig0
    // fails, the early-exit fires before the bad sig, false -> OP_NOT -> true.
    // Master kept OP_0: sig0 verified, then (bad,PK2) -> SIG_DER -> rejected.
    try testing.expect(try f1Case(false));
}

test "neon F1: CHECKMULTISIG empty sig + OP_0 in scriptCode -> SIG_FINDANDDELETE under CONST_SCRIPTCODE" {
    // Core: FindAndDelete(scriptCode, OP_0) finds 1 -> SCRIPT_ERR_SIG_FINDANDDELETE.
    const spk = [_]u8{ OP_0, OP_DROP, OP_1, 0x21 } ++ PK1 ++ [_]u8{ OP_1, OP_CHECKMULTISIG, OP_NOT };
    const ss = [_]u8{ OP_0, OP_0 };
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &ss, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expectError(ScriptError.SigFindAndDelete, run(&tx, standardFlags(), &ss, &spk, &.{}));
}

test "neon F1 control: CHECKMULTISIG empty sig, no OP_0 in scriptCode -> accepted (standard flags)" {
    const spk = [_]u8{ OP_1, 0x21 } ++ PK1 ++ [_]u8{ OP_1, OP_CHECKMULTISIG, OP_NOT };
    const ss = [_]u8{ OP_0, OP_0 };
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &ss, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expect(try run(&tx, standardFlags(), &ss, &spk, &.{}));
}

// ---------------------------------------------------------------------------
// F2: OP_CHECKSIG with an empty signature still runs the encoding checks
// ---------------------------------------------------------------------------

test "neon F2: CHECKSIG empty sig, P2WSH uncompressed pubkey -> WITNESS_PUBKEYTYPE (standard flags)" {
    const ws = [_]u8{0x41} ++ PK1_UNCOMPRESSED ++ [_]u8{ OP_CHECKSIG, OP_NOT };
    const h = crypto.sha256(&ws);
    const spk = [_]u8{ OP_0, 0x20 } ++ h;
    const wit = [_][]const u8{ &.{}, &ws };
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &wit }};
    const tx = spendTx(&ins);
    try testing.expectError(ScriptError.WitnessPubkeyType, run(&tx, standardFlags(), &.{}, &spk, &wit));
}

test "neon F2: CHECKSIG empty sig, hybrid pubkey -> PUBKEYTYPE under STRICTENC (standard flags)" {
    const spk = [_]u8{0x41} ++ PK1_HYBRID ++ [_]u8{ OP_CHECKSIG, OP_NOT };
    const ss = [_]u8{OP_0};
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &ss, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expectError(ScriptError.InvalidPubkeyType, run(&tx, standardFlags(), &ss, &spk, &.{}));
}

test "neon F2: CHECKSIG empty sig + OP_0 in scriptCode -> SIG_FINDANDDELETE under CONST_SCRIPTCODE" {
    const spk = [_]u8{ OP_0, OP_DROP, 0x21 } ++ PK1 ++ [_]u8{ OP_CHECKSIG, OP_NOT };
    const ss = [_]u8{OP_0};
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &ss, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expectError(ScriptError.SigFindAndDelete, run(&tx, standardFlags(), &ss, &spk, &.{}));
}

test "neon F2 control: CHECKSIG empty sig, hybrid pubkey, block flags (no STRICTENC) -> accepted" {
    // Pubkey-type and CONST_SCRIPTCODE checks are policy only: under block
    // flags the same NOT-script is valid in Core and must stay valid.
    const spk = [_]u8{ OP_0, OP_DROP, 0x41 } ++ PK1_HYBRID ++ [_]u8{ OP_CHECKSIG, OP_NOT };
    const ss = [_]u8{OP_0};
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &ss, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expect(try run(&tx, blockFlags(), &ss, &spk, &.{}));
}

// ---------------------------------------------------------------------------
// F3: P2SH-wrapped pay-to-anchor is discouraged, native is not
// ---------------------------------------------------------------------------

const P2A = [_]u8{ OP_1, 0x02, 0x4e, 0x73 };

test "neon F3: P2SH-wrapped P2A -> DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM (standard flags)" {
    const h = crypto.hash160(&P2A);
    const spk = [_]u8{ OP_HASH160, 0x14 } ++ h ++ [_]u8{OP_EQUAL};
    const ss = [_]u8{0x04} ++ P2A;
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &ss, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    // clearbit reports the discourage gate for unknown witness programs as
    // WitnessProgramMismatch (the same gate a v2 program hits).
    try testing.expectError(ScriptError.WitnessProgramMismatch, run(&tx, standardFlags(), &ss, &spk, &.{}));
}

test "neon F3 control: native P2A stays exempt from the discourage gate (standard flags)" {
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expect(try run(&tx, standardFlags(), &.{}, &P2A, &.{}));
}

test "neon F3 control: P2SH-wrapped P2A is valid under block flags" {
    const h = crypto.hash160(&P2A);
    const spk = [_]u8{ OP_HASH160, 0x14 } ++ h ++ [_]u8{OP_EQUAL};
    const ss = [_]u8{0x04} ++ P2A;
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &ss, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expect(try run(&tx, blockFlags(), &ss, &spk, &.{}));
}

// ---------------------------------------------------------------------------
// F4: disabled CLTV/CSV are plain NOPs, not discouraged NOPs
// ---------------------------------------------------------------------------

fn nopFlags() script.ScriptFlags {
    var f = standardFlags();
    f.verify_checklocktimeverify = false;
    f.verify_checksequenceverify = false;
    return f;
}

test "neon F4: OP_CHECKLOCKTIMEVERIFY with CLTV off is a NOP2, not DISCOURAGE_UPGRADABLE_NOPS" {
    const spk = [_]u8{ OP_1, OP_CLTV };
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expect(try run(&tx, nopFlags(), &.{}, &spk, &.{}));
}

test "neon F4: OP_CHECKSEQUENCEVERIFY with CSV off is a NOP3, not DISCOURAGE_UPGRADABLE_NOPS" {
    const spk = [_]u8{ OP_1, OP_CSV };
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expect(try run(&tx, nopFlags(), &.{}, &spk, &.{}));
}

test "neon F4 control: OP_NOP1 is still DISCOURAGE_UPGRADABLE_NOPS" {
    const spk = [_]u8{ OP_1, OP_NOP1 };
    const ins = [_]types.TxIn{.{ .previous_output = PREV, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &.{} }};
    const tx = spendTx(&ins);
    try testing.expectError(ScriptError.DiscourageUpgradableNops, run(&tx, nopFlags(), &.{}, &spk, &.{}));
}
