//! r3fix-clearbit-ephemeral-dust: Core v31.1's ephemeral-dust policy.
//!
//! Found by the R3 generating differential fuzzer, night 1 (seed 739943),
//! triage group G5.  clearbit refused any tx with a dust output at the
//! IsStandardTx position, before finality, BIP68, CheckTxInputs and the fee
//! floor, so it answered "dust" where Core answers the earlier failure
//! (non-BIP68-final, min relay fee not met, bad-txns-in-belowout), and it had
//! no ephemeral-dust support: a 0-fee parent with one dust output, in a
//! package whose child spends it, was refused.
//!
//! Core v31.1:
//!   * policy/policy.cpp IsStandardTx: at most MAX_DUST_OUTPUTS_PER_TX (= 1,
//!     policy/policy.h) dust outputs, else "dust".
//!   * policy/ephemeral_policy.cpp PreCheckEphemeralTx: a tx with dust and a
//!     nonzero base or modified fee is "dust".  validation.cpp PreChecks runs
//!     it after CheckSequenceLocksAtTip and CheckTxInputs, before
//!     CheckFeeRate.
//!   * policy/ephemeral_policy.cpp CheckEphemeralSpends: every dust output of
//!     a pool or package parent must be spent by the child, else
//!     "missing-ephemeral-spends"; a package reports "unspent-dust".  Single
//!     txs run it in AcceptSingleTransaction (not under bypass_limits),
//!     packages in AcceptMultipleTransactions.
//!
//! Every test runs on a DB-less chain fixture (tests_mtp_bip68.zig, mainnet
//! height 800,000, CSV active) so inputs are valued and BIP68 is evaluated.
//! The tests use only APIs that exist on master, so they compile there and
//! fail by name.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");
const script = @import("script.zig");
const mempool_mod = @import("mempool.zig");
const base = @import("tests_mtp_bip68.zig");

const Mempool = mempool_mod.Mempool;
const MempoolError = mempool_mod.MempoolError;
const TIP = base.TIP;

/// The R3 minimised case of row `R3 mempool/reason/final|nonstandard`:
/// tapscript script=[] v=2, BIP68 sequence 0x0040ffff (a time lock of 65535 *
/// 512 s), fund 2000, one 0-sat P2WSH output.  Core: non-BIP68-final.
const R3_HEX = "020000000001014f62e28aea0bfeb5ef2f78f38b1741adfee7692e61d893715b0a22730350f5940000000000ffff40000100000000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020021c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";

const P2WPKH_OUT = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xE7} ** 20;

const Fx = struct {
    cs: storage.ChainState,
    pool: Mempool,
    wsh: [34]u8,

    fn init(self: *Fx) void {
        self.cs = storage.ChainState.init(null, 64, testing.allocator);
        base.setupChain(&self.cs);
        self.pool = Mempool.init(&self.cs, &consensus.MAINNET, testing.allocator);
        self.wsh = base.opTrueP2wsh();
    }

    fn deinit(self: *Fx) void {
        self.pool.deinit();
        self.cs.deinit();
    }

    /// A confirmed OP_TRUE-P2WSH coin of `value` sat at `height`.
    fn coin(self: *Fx, tag: u8, value: i64, height: u32) !types.OutPoint {
        const op = types.OutPoint{ .hash = [_]u8{tag} ** 32, .index = 0 };
        const out = types.TxOut{ .value = value, .script_pubkey = &self.wsh };
        try self.cs.utxo_set.add(&op, &out, height, false);
        return op;
    }
};

fn opTrueIn(prev: types.OutPoint) types.TxIn {
    return .{
        .previous_output = prev,
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFD,
        .witness = &base.op_true_witness,
    };
}

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn expectDry(pool: *Mempool, tx: types.Transaction, want: []const u8) !void {
    const r = pool.acceptToMemoryPool(tx, true);
    if (r.accepted) {
        std.debug.print("testmempoolaccept allowed the tx; Core v31.1 says \"{s}\"\n", .{want});
        return error.TestUnexpectedResult;
    }
    if (!std.mem.eql(u8, r.reject_reason.?, want))
        std.debug.print("testmempoolaccept said \"{s}\"; Core v31.1 says \"{s}\"\n", .{ r.reject_reason.?, want });
    try testing.expectEqualStrings(want, r.reject_reason.?);
}

/// sendrawtransaction: compared by error name so this compiles on master,
/// where MissingEphemeralSpends does not exist yet.
fn expectFull(pool: *Mempool, tx: types.Transaction, want: []const u8) !void {
    if (pool.addTransaction(tx)) |_| {
        std.debug.print("sendrawtransaction accepted the tx; expected {s}\n", .{want});
        return error.TestUnexpectedResult;
    } else |err| {
        if (!std.mem.eql(u8, @errorName(err), want))
            std.debug.print("sendrawtransaction failed with {s}; expected {s}\n", .{ @errorName(err), want });
        try testing.expectEqualStrings(want, @errorName(err));
    }
}

// ---------------------------------------------------------------------------
// Check order: one dust output is not an IsStandardTx failure
// ---------------------------------------------------------------------------

test "r3fix ephemeral-dust R3 minimised: dust tx with an unmet BIP68 time lock is non-BIP68-final, not dust" {
    const allocator = testing.allocator;
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();

    const raw = try decodeHex(allocator, R3_HEX);
    defer allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var reader = serialize.Reader{ .data = raw };
    const decoded = try serialize.readTransaction(&reader, arena.allocator());
    // The case as the fuzzer sent it: one 0-sat P2WSH output, sequence 0x0040ffff.
    try testing.expectEqual(@as(usize, 1), decoded.outputs.len);
    try testing.expectEqual(@as(i64, 0), decoded.outputs[0].value);
    try testing.expect(Mempool.isDust(&decoded.outputs[0]));
    try testing.expectEqual(@as(u32, 0x0040ffff), decoded.inputs[0].sequence);

    // Same tx, input re-pointed at a 2000-sat coin confirmed at TIP-20: the
    // 65535 * 512 s lock is far from met (fee 2000).
    const prev = try fx.coin(0x31, 2000, TIP - 20);
    var ins = [_]types.TxIn{decoded.inputs[0]};
    ins[0].previous_output = prev;
    const tx = types.Transaction{ .version = decoded.version, .inputs = &ins, .outputs = decoded.outputs, .lock_time = decoded.lock_time };

    try expectDry(&fx.pool, tx, "non-BIP68-final");
    try expectFull(&fx.pool, tx, "SequenceLockNotSatisfied");
}

test "r3fix ephemeral-dust R5: a 0-fee tx with one dust output is min relay fee not met, not dust" {
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    const prev = try fx.coin(0x32, 100_000, TIP - 300);
    var ins = [_]types.TxIn{opTrueIn(prev)};
    var outs = [_]types.TxOut{
        .{ .value = 0, .script_pubkey = &fx.wsh },
        .{ .value = 100_000, .script_pubkey = &P2WPKH_OUT },
    };
    const tx = types.Transaction{ .version = 2, .inputs = &ins, .outputs = &outs, .lock_time = 0 };
    try expectDry(&fx.pool, tx, "min relay fee not met");
    try expectFull(&fx.pool, tx, "InsufficientFee");
}

test "r3fix ephemeral-dust R9: value out > value in with one dust output is bad-txns-in-belowout, not dust" {
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    const prev = try fx.coin(0x33, 100_000, TIP - 300);
    var ins = [_]types.TxIn{opTrueIn(prev)};
    var outs = [_]types.TxOut{
        .{ .value = 0, .script_pubkey = &fx.wsh },
        .{ .value = 200_000, .script_pubkey = &P2WPKH_OUT },
    };
    const tx = types.Transaction{ .version = 2, .inputs = &ins, .outputs = &outs, .lock_time = 0 };
    try expectDry(&fx.pool, tx, "bad-txns-in-belowout");
    try expectFull(&fx.pool, tx, "InputsBelowOutputs");
}

test "r3fix ephemeral-dust: two dust outputs are dust at IsStandardTx, before the fee floor (MAX_DUST_OUTPUTS_PER_TX = 1)" {
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    const prev = try fx.coin(0x34, 100_000, TIP - 300);
    var ins = [_]types.TxIn{opTrueIn(prev)};
    // 0 fee: Core stops at IsStandardTx ("dust"), never reaching CheckFeeRate.
    var outs = [_]types.TxOut{
        .{ .value = 0, .script_pubkey = &fx.wsh },
        .{ .value = 0, .script_pubkey = &fx.wsh },
        .{ .value = 100_000, .script_pubkey = &P2WPKH_OUT },
    };
    const tx = types.Transaction{ .version = 2, .inputs = &ins, .outputs = &outs, .lock_time = 0 };
    try expectDry(&fx.pool, tx, "dust");
    try expectFull(&fx.pool, tx, "DustOutput");
}

test "r3fix ephemeral-dust control: a fee-paying tx with one dust output is dust (Core PreCheckEphemeralTx)" {
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    const prev = try fx.coin(0x35, 100_000, TIP - 300);
    var ins = [_]types.TxIn{opTrueIn(prev)};
    var outs = [_]types.TxOut{
        .{ .value = 0, .script_pubkey = &fx.wsh },
        .{ .value = 99_000, .script_pubkey = &P2WPKH_OUT },
    };
    const tx = types.Transaction{ .version = 2, .inputs = &ins, .outputs = &outs, .lock_time = 0 };
    try expectDry(&fx.pool, tx, "dust");
    try expectFull(&fx.pool, tx, "DustOutput");
}

test "r3fix ephemeral-dust: dust with a nonzero base or modified fee is dust, before the fee floor (prioritisetransaction)" {
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();

    // Base fee 0, modified fee +1000: dust (Core checks mod_fee too).
    const p1 = try fx.coin(0x36, 100_000, TIP - 300);
    var ins1 = [_]types.TxIn{opTrueIn(p1)};
    var outs1 = [_]types.TxOut{
        .{ .value = 0, .script_pubkey = &fx.wsh },
        .{ .value = 100_000, .script_pubkey = &P2WPKH_OUT },
    };
    const t1 = types.Transaction{ .version = 2, .inputs = &ins1, .outputs = &outs1, .lock_time = 0 };
    _ = try fx.pool.prioritiseTransaction(try crypto.computeTxid(&t1, testing.allocator), 1000);
    try expectDry(&fx.pool, t1, "dust");
    try expectFull(&fx.pool, t1, "DustOutput");

    // Base fee 1000, delta -1000 (modified 0): still dust (base_fee != 0).
    const p2 = try fx.coin(0x37, 100_000, TIP - 300);
    var ins2 = [_]types.TxIn{opTrueIn(p2)};
    var outs2 = [_]types.TxOut{
        .{ .value = 0, .script_pubkey = &fx.wsh },
        .{ .value = 99_000, .script_pubkey = &P2WPKH_OUT },
    };
    const t2 = types.Transaction{ .version = 2, .inputs = &ins2, .outputs = &outs2, .lock_time = 0 };
    _ = try fx.pool.prioritiseTransaction(try crypto.computeTxid(&t2, testing.allocator), -1000);
    try expectDry(&fx.pool, t2, "dust");
    try expectFull(&fx.pool, t2, "DustOutput");
}

// ---------------------------------------------------------------------------
// Ephemeral dust in a package (submitpackage)
// ---------------------------------------------------------------------------

/// The 0-fee parent: 100,000-sat coin -> [0-sat OP_TRUE P2WSH (dust),
/// 100,000-sat OP_TRUE P2WSH].
fn dustParent(fx: *Fx, tag: u8, ins: *[1]types.TxIn, outs: *[2]types.TxOut) !types.Transaction {
    const prev = try fx.coin(tag, 100_000, TIP - 300);
    ins[0] = opTrueIn(prev);
    outs[0] = .{ .value = 0, .script_pubkey = &fx.wsh };
    outs[1] = .{ .value = 100_000, .script_pubkey = &fx.wsh };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

test "r3fix ephemeral-dust: a 0-fee parent with one non-P2A dust output and a child that spends it is accepted as a package" {
    const allocator = testing.allocator;
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    var pin: [1]types.TxIn = undefined;
    var pout: [2]types.TxOut = undefined;
    const parent = try dustParent(&fx, 0x41, &pin, &pout);
    const ptxid = try crypto.computeTxid(&parent, allocator);

    // The child spends the dust and the 100,000 output, paying 1,000.
    var cin = [_]types.TxIn{
        opTrueIn(.{ .hash = ptxid, .index = 0 }),
        opTrueIn(.{ .hash = ptxid, .index = 1 }),
    };
    var cout = [_]types.TxOut{.{ .value = 99_000, .script_pubkey = &P2WPKH_OUT }};
    const child = types.Transaction{ .version = 2, .inputs = &cin, .outputs = &cout, .lock_time = 0 };

    var res = try mempool_mod.acceptPackage(&fx.pool, &[_]types.Transaction{ parent, child }, allocator);
    defer res.deinit();
    if (!res.package_accepted) {
        for (res.tx_results, 0..) |r, i| std.debug.print("package tx {d}: {s}\n", .{ i, r.error_message orelse "(accepted)" });
    }
    try testing.expect(res.package_accepted);
    try testing.expect(fx.pool.contains(ptxid));
    try testing.expect(fx.pool.contains(try crypto.computeTxid(&child, allocator)));
}

test "r3fix ephemeral-dust: a child that leaves the parent's dust unspent fails the package as unspent-dust; neither enters the pool" {
    const allocator = testing.allocator;
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    var pin: [1]types.TxIn = undefined;
    var pout: [2]types.TxOut = undefined;
    const parent = try dustParent(&fx, 0x42, &pin, &pout);
    const ptxid = try crypto.computeTxid(&parent, allocator);

    // The child spends only the 100,000 output (fee 1,000).
    var cin = [_]types.TxIn{opTrueIn(.{ .hash = ptxid, .index = 1 })};
    var cout = [_]types.TxOut{.{ .value = 99_000, .script_pubkey = &P2WPKH_OUT }};
    const child = types.Transaction{ .version = 2, .inputs = &cin, .outputs = &cout, .lock_time = 0 };

    var res = try mempool_mod.acceptPackage(&fx.pool, &[_]types.Transaction{ parent, child }, allocator);
    defer res.deinit();
    try testing.expect(!res.package_accepted);
    try testing.expect(!fx.pool.contains(ptxid));
    try testing.expectEqual(@as(usize, 0), fx.pool.entries.count());
    if (res.package_msg == null or !std.mem.eql(u8, res.package_msg.?, "unspent-dust"))
        std.debug.print("package_msg {s}; Core v31.1: unspent-dust\n", .{res.package_msg orelse "(null)"});
    try testing.expectEqualStrings("unspent-dust", res.package_msg orelse "(null)");
    // Child: Core's TxValidationState::ToString.
    const cmsg = res.tx_results[1].error_message orelse "(null)";
    try testing.expect(std.mem.startsWith(u8, cmsg, "missing-ephemeral-spends, tx "));
    try testing.expect(std.mem.endsWith(u8, cmsg, " did not spend parent's ephemeral dust"));
    // Parent: its own failure from the individual try (Core keeps it).
    const pmsg = res.tx_results[0].error_message orelse "(null)";
    try testing.expect(std.mem.startsWith(u8, pmsg, "min relay fee not met, 0 < "));
}

// ---------------------------------------------------------------------------
// A pool parent with dust (as after a reorg re-add, bypass_limits)
// ---------------------------------------------------------------------------

test "r3fix ephemeral-dust: a single tx spending a pool parent must spend its dust (missing-ephemeral-spends); spending it is accepted" {
    const allocator = testing.allocator;
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    var pin: [1]types.TxIn = undefined;
    var pout: [2]types.TxOut = undefined;
    const parent = try dustParent(&fx, 0x43, &pin, &pout);
    const ptxid = try crypto.computeTxid(&parent, allocator);

    // Re-admitted without limits (Core: a disconnected block's tx; the fee
    // floor and CheckEphemeralSpends are skipped, PreCheckEphemeralTx is not).
    fx.pool.bypass_limits = true;
    fx.pool.addTransaction(parent) catch |err| {
        std.debug.print("0-fee parent with one dust output refused under bypass_limits: {s} (Core admits it)\n", .{@errorName(err)});
        return err;
    };
    fx.pool.bypass_limits = false;

    var bin = [_]types.TxIn{opTrueIn(.{ .hash = ptxid, .index = 1 })};
    var bout = [_]types.TxOut{.{ .value = 99_000, .script_pubkey = &P2WPKH_OUT }};
    const bad = types.Transaction{ .version = 2, .inputs = &bin, .outputs = &bout, .lock_time = 0 };
    try expectDry(&fx.pool, bad, "missing-ephemeral-spends");
    try expectFull(&fx.pool, bad, "MissingEphemeralSpends");

    var gin = [_]types.TxIn{
        opTrueIn(.{ .hash = ptxid, .index = 0 }),
        opTrueIn(.{ .hash = ptxid, .index = 1 }),
    };
    var gout = [_]types.TxOut{.{ .value = 99_000, .script_pubkey = &P2WPKH_OUT }};
    const good = types.Transaction{ .version = 2, .inputs = &gin, .outputs = &gout, .lock_time = 0 };
    const dry = fx.pool.acceptToMemoryPool(good, true);
    if (!dry.accepted) std.debug.print("testmempoolaccept refused the dust-spending child: {s}\n", .{dry.reject_reason orelse "?"});
    try testing.expect(dry.accepted);
    try fx.pool.addTransaction(good);
}

test "r3fix ephemeral-dust: testmempoolaccept package whose child leaves a pool parent's dust unspent: missing-ephemeral-spends, the rest unfinished" {
    const allocator = testing.allocator;
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    var pin: [1]types.TxIn = undefined;
    var pout: [2]types.TxOut = undefined;
    const dusty = try dustParent(&fx, 0x44, &pin, &pout);
    const dtxid = try crypto.computeTxid(&dusty, allocator);
    fx.pool.bypass_limits = true;
    fx.pool.addTransaction(dusty) catch |err| {
        std.debug.print("0-fee parent with one dust output refused under bypass_limits: {s} (Core admits it)\n", .{@errorName(err)});
        return err;
    };
    fx.pool.bypass_limits = false;

    // X: an ordinary fee-paying tx.  Y: spends X:0 and dusty:1, not dusty:0.
    const xc = try fx.coin(0x45, 100_000, TIP - 300);
    var xin = [_]types.TxIn{opTrueIn(xc)};
    var xout = [_]types.TxOut{.{ .value = 99_000, .script_pubkey = &fx.wsh }};
    const x = types.Transaction{ .version = 2, .inputs = &xin, .outputs = &xout, .lock_time = 0 };
    const xtxid = try crypto.computeTxid(&x, allocator);
    var yin = [_]types.TxIn{
        opTrueIn(.{ .hash = xtxid, .index = 0 }),
        opTrueIn(.{ .hash = dtxid, .index = 1 }),
    };
    var yout = [_]types.TxOut{.{ .value = 198_000, .script_pubkey = &P2WPKH_OUT }};
    const y = types.Transaction{ .version = 2, .inputs = &yin, .outputs = &yout, .lock_time = 0 };

    const txns = [_]types.Transaction{ x, y };
    var results: [2]Mempool.MultiTestResult = undefined;
    for (&results) |*r| r.* = .{ .txid = std.mem.zeroes(types.Hash256), .wtxid = std.mem.zeroes(types.Hash256) };
    try fx.pool.testAcceptMultiple(&txns, &results, allocator);
    defer for (results) |r| if (r.reject_details) |d| allocator.free(d);

    if (results[1].state != .rejected)
        std.debug.print("tx 1 state {s}; Core v31.1: rejected missing-ephemeral-spends\n", .{@tagName(results[1].state)});
    try testing.expect(results[0].state == .unfinished);
    try testing.expect(results[1].state == .rejected);
    try testing.expectEqualStrings("missing-ephemeral-spends", results[1].reject_reason.?);
}

test "r3fix ephemeral-dust control: a 0-fee parent with a 0-sat P2A anchor and a child that spends it is accepted as a package" {
    // Passes on master (P2A is dust-exempt there) and must keep passing once
    // P2A takes the witness dust threshold (r3fix-clearbit-p2a-dust-rule):
    // then this is ephemeral dust, admitted by the rules above.
    const allocator = testing.allocator;
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    const prev = try fx.coin(0x46, 100_000, TIP - 300);
    var pin = [_]types.TxIn{opTrueIn(prev)};
    var pout = [_]types.TxOut{
        .{ .value = 0, .script_pubkey = &script.P2A_SCRIPT },
        .{ .value = 100_000, .script_pubkey = &fx.wsh },
    };
    const parent = types.Transaction{ .version = 2, .inputs = &pin, .outputs = &pout, .lock_time = 0 };
    const ptxid = try crypto.computeTxid(&parent, allocator);

    // P2A is spent with an empty witness.
    var cin = [_]types.TxIn{
        .{ .previous_output = .{ .hash = ptxid, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFF_FFFD, .witness = &[_][]const u8{} },
        opTrueIn(.{ .hash = ptxid, .index = 1 }),
    };
    var cout = [_]types.TxOut{.{ .value = 99_000, .script_pubkey = &P2WPKH_OUT }};
    const child = types.Transaction{ .version = 2, .inputs = &cin, .outputs = &cout, .lock_time = 0 };

    var res = try mempool_mod.acceptPackage(&fx.pool, &[_]types.Transaction{ parent, child }, allocator);
    defer res.deinit();
    if (!res.package_accepted) {
        for (res.tx_results, 0..) |r, i| std.debug.print("package tx {d}: {s}\n", .{ i, r.error_message orelse "(accepted)" });
    }
    try testing.expect(res.package_accepted);
    try testing.expect(fx.pool.contains(ptxid));
}

const BAD_WITNESS_ITEM = [_]u8{0x52};
const bad_witness = [_][]const u8{&BAD_WITNESS_ITEM};

test "r3fix ephemeral-dust: a child that spends the dust but fails its script check leaves no dust parent in the pool (package evaluation is all-or-nothing)" {
    const allocator = testing.allocator;
    var fx: Fx = undefined;
    fx.init();
    defer fx.deinit();
    var pin: [1]types.TxIn = undefined;
    var pout: [2]types.TxOut = undefined;
    const parent = try dustParent(&fx, 0x47, &pin, &pout);
    const ptxid = try crypto.computeTxid(&parent, allocator);

    // Spends the dust correctly; the second input's witness script (OP_2)
    // does not match the OP_TRUE P2WSH program, so its script check fails.
    var cin = [_]types.TxIn{
        opTrueIn(.{ .hash = ptxid, .index = 0 }),
        .{ .previous_output = .{ .hash = ptxid, .index = 1 }, .script_sig = &[_]u8{}, .sequence = 0xFFFF_FFFD, .witness = &bad_witness },
    };
    var cout = [_]types.TxOut{.{ .value = 99_000, .script_pubkey = &P2WPKH_OUT }};
    const child = types.Transaction{ .version = 2, .inputs = &cin, .outputs = &cout, .lock_time = 0 };

    var res = try mempool_mod.acceptPackage(&fx.pool, &[_]types.Transaction{ parent, child }, allocator);
    defer res.deinit();
    try testing.expect(!res.package_accepted);
    if (fx.pool.contains(ptxid)) std.debug.print("the 0-fee dust parent stayed in the pool without its child (Core admits neither)\n", .{});
    try testing.expect(!fx.pool.contains(ptxid));
    try testing.expectEqual(@as(usize, 0), fx.pool.entries.count());
    // Parent keeps its individual failure (Core: CheckFeeRate, reconsiderable).
    const pmsg = res.tx_results[0].error_message orelse "(null)";
    if (!std.mem.startsWith(u8, pmsg, "min relay fee not met, 0 < ")) std.debug.print("parent error {s}; Core v31.1: min relay fee not met\n", .{pmsg});
    try testing.expect(std.mem.startsWith(u8, pmsg, "min relay fee not met, 0 < "));
    // The child's own error is its script failure.
    try testing.expect(res.tx_results[1].error_message != null);
}
