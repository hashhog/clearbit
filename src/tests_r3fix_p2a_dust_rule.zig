//! r3fix-clearbit-p2a-dust-rule: pay-to-anchor (P2A, `OP_1 <0x4e73>`) outputs
//! follow Core v31.1's ordinary witness-program dust rule.
//!
//! Found by the R3 generating differential fuzzer, night 1 (seed 739943),
//! triage group G3. clearbit had two rules Core does not have:
//!   * checkStandard refused any P2A output with a nonzero value
//!     (AnchorNonZeroValue), so a 545-sat anchor that Core accepts was
//!     "non-standard" (row R45, minimised case below);
//!   * dustThreshold exempted P2A (threshold 0), so a fee-paying tx with a
//!     0-sat anchor passed, where Core refuses it as "dust".
//!
//! Core v31.1:
//!   * policy/policy.cpp:26-63 GetDustThreshold has no P2A case. P2A is a
//!     witness program, so nSize = 13 (serialized txout) + 67 = 80, and at
//!     DUST_RELAY_TX_FEE = 3000 sat/kvB (policy/policy.h:67) the threshold is
//!     240 sat: < 240 is dust.
//!   * IsStandard / IsStandardTx (policy/policy.cpp) have no value rule for
//!     TxoutType::ANCHOR.
//!   * policy/ephemeral_policy.cpp:27 PreCheckEphemeralTx refuses a tx with a
//!     nonzero fee and any dust output: "dust".

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const script = @import("script.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const mempool_mod = @import("mempool.zig");
const Mempool = mempool_mod.Mempool;
const MempoolError = mempool_mod.MempoolError;

/// R45 `mempool/verdict/accept|other:non-standard`, minimised:
/// tapscript [1 1 DROP], outputs 545-sat P2A + 98,000-sat P2WSH.
const R45_HEX = "020000000001011032dfb553c157b24385a71d398ec33ec312df53c251cb4a7ace39951419a9a50000000000feffffff0221020000000000000451024e73d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020351517521c179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";

const P2WSH_SPK = [_]u8{ 0x00, 0x20 } ++ [_]u8{0x4e} ** 32;
const FUND_SPK = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// Put a funding tx (one 1,000,000-sat P2WPKH output) in the pool and return
/// its txid. With no chain state the pool resolves the spend against it.
fn fund(mp: *Mempool, allocator: std.mem.Allocator, tag: u8) !types.Hash256 {
    const funding = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = .{ .hash = [_]u8{tag} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{.{ .value = 1_000_000, .script_pubkey = &FUND_SPK }},
        .lock_time = 0,
    };
    try mp.addTransaction(funding);
    return crypto.computeTxid(&funding, allocator);
}

/// A tx spending `prev:0` with outputs [anchor_value P2A, 900,000 P2WSH]:
/// fee = 1,000,000 - 900,000 - anchor_value > 0, well above min relay.
fn anchorSpend(prev: *const types.Hash256, ins: *[1]types.TxIn, outs: *[2]types.TxOut, anchor_value: i64) types.Transaction {
    ins[0] = .{
        .previous_output = .{ .hash = prev.*, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    };
    outs[0] = .{ .value = anchor_value, .script_pubkey = &script.P2A_SCRIPT };
    outs[1] = .{ .value = 900_000, .script_pubkey = &P2WSH_SPK };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

test "r3fix p2a: P2A dust threshold is Core's witness-program 240 sat (GetDustThreshold has no P2A case)" {
    const at = struct {
        fn out(v: i64) types.TxOut {
            return .{ .value = v, .script_pubkey = &script.P2A_SCRIPT };
        }
    };
    const o = at.out(0);
    try testing.expectEqual(@as(i64, 240), Mempool.dustThreshold(&o, consensus.DUST_RELAY_FEE));
    // < 240 is dust, >= 240 is not (Core IsDust: nValue < GetDustThreshold).
    inline for ([_]i64{ 0, 1, 239 }) |v| {
        const d = at.out(v);
        try testing.expect(Mempool.isDust(&d));
    }
    inline for ([_]i64{ 240, 545, 546 }) |v| {
        const d = at.out(v);
        try testing.expect(!Mempool.isDust(&d));
    }
}

test "r3fix p2a R45: minimised case (545-sat P2A + P2WSH) is allowed by testmempoolaccept and sendrawtransaction" {
    const allocator = testing.allocator;
    const raw = try decodeHex(allocator, R45_HEX);
    defer allocator.free(raw);
    var reader = serialize.Reader{ .data = raw };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const decoded = try serialize.readTransaction(&reader, arena.allocator());

    // The case as the fuzzer sent it.
    try testing.expectEqual(@as(usize, 2), decoded.outputs.len);
    try testing.expectEqual(@as(i64, 545), decoded.outputs[0].value);
    try testing.expect(script.isPayToAnchor(decoded.outputs[0].script_pubkey));

    var mp = Mempool.init(null, null, allocator);
    defer mp.deinit();
    const prev = try fund(&mp, allocator, 0x45);

    // Same outputs and witness; the input is re-pointed at a pool coin so the
    // unit pool (no chain state) can resolve it. Fee = 1,000,000 - 98,545.
    var ins = [_]types.TxIn{decoded.inputs[0]};
    ins[0].previous_output = .{ .hash = prev, .index = 0 };
    const tx = types.Transaction{ .version = decoded.version, .inputs = &ins, .outputs = decoded.outputs, .lock_time = decoded.lock_time };

    const dry = mp.acceptToMemoryPool(tx, true);
    if (!dry.accepted) std.debug.print("testmempoolaccept refused R45: {s} (Core v31.1 allows it)\n", .{dry.reject_reason orelse "?"});
    try testing.expect(dry.accepted);

    try mp.addTransaction(tx);
    try testing.expect(mp.contains(try crypto.computeTxid(&tx, allocator)));
}

test "r3fix p2a: fee-paying tx with a 0-sat or 239-sat P2A is refused as dust (Core PreCheckEphemeralTx)" {
    const allocator = testing.allocator;
    inline for ([_]i64{ 0, 1, 239 }, 0..) |v, i| {
        var mp = Mempool.init(null, null, allocator);
        defer mp.deinit();
        const prev = try fund(&mp, allocator, 0x50 + @as(u8, i));
        var ins: [1]types.TxIn = undefined;
        var outs: [2]types.TxOut = undefined;
        const tx = anchorSpend(&prev, &ins, &outs, v);

        const dry = mp.acceptToMemoryPool(tx, true);
        if (dry.accepted) std.debug.print("testmempoolaccept allowed a fee-paying tx with a {d}-sat P2A (Core: dust)\n", .{v});
        try testing.expect(!dry.accepted);
        try testing.expectEqualStrings("dust", dry.reject_reason.?);

        try testing.expectError(MempoolError.DustOutput, mp.addTransaction(tx));
    }
}

test "r3fix p2a: P2A at or above 240 sat in a fee-paying tx is accepted (no P2A value rule in Core)" {
    const allocator = testing.allocator;
    inline for ([_]i64{ 240, 546, 10_000 }, 0..) |v, i| {
        var mp = Mempool.init(null, null, allocator);
        defer mp.deinit();
        const prev = try fund(&mp, allocator, 0x60 + @as(u8, i));
        var ins: [1]types.TxIn = undefined;
        var outs: [2]types.TxOut = undefined;
        const tx = anchorSpend(&prev, &ins, &outs, v);

        const dry = mp.acceptToMemoryPool(tx, true);
        if (!dry.accepted) std.debug.print("testmempoolaccept refused a {d}-sat P2A: {s} (Core v31.1 allows it)\n", .{ v, dry.reject_reason orelse "?" });
        try testing.expect(dry.accepted);
        try mp.addTransaction(tx);
    }
}

test "r3fix p2a control: non-P2A dust is unchanged (P2WSH 329 dust, 330 not)" {
    const p2wsh_329 = types.TxOut{ .value = 329, .script_pubkey = &P2WSH_SPK };
    const p2wsh_330 = types.TxOut{ .value = 330, .script_pubkey = &P2WSH_SPK };
    try testing.expect(Mempool.isDust(&p2wsh_329));
    try testing.expect(!Mempool.isDust(&p2wsh_330));
}
