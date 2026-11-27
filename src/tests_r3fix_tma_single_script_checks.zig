//! Single-tx testmempoolaccept runs every check Core's test_accept runs
//! (r3fix-clearbit-tma-single-script-checks).
//!
//! Run via `zig build test-r3fix-tma-single` (also part of `zig build test`).
//!
//! Core v31.1 single-tx testmempoolaccept is ProcessTransaction(test_accept=
//! true): the full MemPoolAccept::PreChecks (AreInputsStandard
//! "bad-txns-nonstandard-inputs" before CheckFeeRate, IsWitnessStandard, the
//! sigops-cost gate, SingleTRUCChecks "TRUC-violation"), then
//! PolicyScriptChecks / ConsensusScriptChecks, and only then the early return
//! on m_test_accept (validation.cpp PreChecks, AcceptSingleTransactionInternal).
//! clearbit's dry run ran none of the input / script / TRUC checks and
//! answered allowed:true for consensus-invalid spends.
//!
//! R3 rows (gen-fuzz night 1, seed 739943): R34 EVAL_FALSE (the minimised
//! case below, byte for byte), R30 WITNESS_PROGRAM_MISMATCH, R10 nonstandard
//! prevout, R4 nonstandard-vs-fee, R46 TRUC vsize.

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");

/// Core ScriptErrorString texts (script/script_error.cpp).
const EVAL_FALSE_REASON = "mempool-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)";
const MISMATCH_REASON = "mempool-script-verify-flag-failed (Witness program hash mismatch)";

/// The minimised R34 case from night 1: a P2WSH spend whose witness script
/// is OP_0 (consensus-invalid, SCRIPT_ERR_EVAL_FALSE).  Core v31.1:
/// allowed:false, mempool-script-verify-flag-failed (EVAL_FALSE).
const R34_HEX = "020000000001017418f2d1782b7e19c87ed109fec87765c9194bb91425699da6d5eb24039c9d960000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001010000000000";

const SCRIPT_OP_0 = [_]u8{0x00};
const SCRIPT_OP_TRUE = [_]u8{0x51};

fn p2wshOf(a: std.mem.Allocator, witness_script: []const u8) ![]const u8 {
    const h = crypto.sha256(witness_script);
    const spk = try a.alloc(u8, 34);
    spk[0] = 0x00;
    spk[1] = 0x20;
    @memcpy(spk[2..34], &h);
    return spk;
}

fn decodeHex(a: std.mem.Allocator, hex: []const u8) !types.Transaction {
    const bytes = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(bytes, hex);
    var reader = serialize.Reader{ .data = bytes };
    return serialize.readTransaction(&reader, a);
}

fn hexOf(a: std.mem.Allocator, tx: *const types.Transaction) ![]const u8 {
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, tx);
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
}

fn displayHex(a: std.mem.Allocator, h: types.Hash256) ![]const u8 {
    var r = h;
    std.mem.reverse(u8, &r);
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(&r)});
}

/// Core's "<reason>, input 0 of <txid> (wtxid <wtxid>), spending <prev>:<n>".
fn expectedDetails(a: std.mem.Allocator, reason: []const u8, tx: *const types.Transaction) ![]const u8 {
    const txid = try crypto.computeTxid(tx, a);
    const wtxid = try crypto.computeWtxid(tx, a);
    const prev = tx.inputs[0].previous_output;
    return std.fmt.allocPrint(a, "{s}, input 0 of {s} (wtxid {s}), spending {s}:{d}", .{
        reason, try displayHex(a, txid), try displayHex(a, wtxid), try displayHex(a, prev.hash), prev.index,
    });
}

/// A chain at height 800,000 (every soft fork active on regtest) holding one
/// confirmed, non-coinbase coin at `op` locked by `spk`.
fn chainWithCoin(a: std.mem.Allocator, op: types.OutPoint, value: i64, spk: []const u8) !*storage.ChainState {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const out = types.TxOut{ .value = value, .script_pubkey = spk };
    try cs.utxo_set.add(&op, &out, 799_000, false);
    return cs;
}

const Rig = struct { mp: *mempool_mod.Mempool, srv: *rpc.RpcServer };

fn rig(a: std.mem.Allocator, cs: *storage.ChainState) !Rig {
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});
    return .{ .mp = mp, .srv = srv };
}

/// Single-tx testmempoolaccept; returns the one result object.
fn tma(a: std.mem.Allocator, srv: *rpc.RpcServer, tx: *const types.Transaction) !std.json.ObjectMap {
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\"]]}}", .{try hexOf(a, tx)});
    const resp = try srv.dispatch(req);
    const p = try std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(@as(usize, 1), rows.len);
    return rows[0].object;
}

const PREV = [_]u8{0x42} ** 32;

/// One-input tx spending PREV:0 (empty scriptSig, `witness`), paying
/// `n_out` P2WSH(OP_TRUE) outputs of `out_value` each.
fn spend(a: std.mem.Allocator, version: i32, witness: []const []const u8, n_out: usize, out_value: i64) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = .{ .hash = PREV, .index = 0 },
        .script_sig = &.{},
        .sequence = 0xFFFFFFFD,
        .witness = witness,
    };
    const outs = try a.alloc(types.TxOut, n_out);
    const spk = try p2wshOf(a, &SCRIPT_OP_TRUE);
    for (outs) |*o| o.* = .{ .value = out_value, .script_pubkey = spk };
    return .{ .version = version, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

fn expectRejected(row: std.json.ObjectMap, reason: []const u8) !void {
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings(reason, row.get("reject-reason").?.string);
}

test "tests_r3fix_tma_single R34: P2WSH witness script OP_0 (EVAL_FALSE) is refused with Core's reason and details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try decodeHex(a, R34_HEX);
    // The coin it spends: P2WSH(OP_0), 100,000 sat (the tx pays 98,000).
    try testing.expectEqualSlices(u8, &SCRIPT_OP_0, tx.inputs[0].witness[0]);
    const r = try rig(a, try chainWithCoin(a, tx.inputs[0].previous_output, 100_000, try p2wshOf(a, &SCRIPT_OP_0)));

    const row = try tma(a, r.srv, &tx);
    try expectRejected(row, EVAL_FALSE_REASON);
    try testing.expectEqualStrings(try expectedDetails(a, EVAL_FALSE_REASON, &tx), row.get("reject-details").?.string);
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_r3fix_tma_single R30: P2WSH witness script that does not hash to the program is refused (WITNESS_PROGRAM_MISMATCH)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Coin locked by P2WSH(OP_0); the spend reveals OP_TRUE.
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, try p2wshOf(a, &SCRIPT_OP_0)));
    const witness = try a.dupe([]const u8, &.{&SCRIPT_OP_TRUE});
    const tx = try spend(a, 2, witness, 1, 98_000);

    const row = try tma(a, r.srv, &tx);
    try expectRejected(row, MISMATCH_REASON);
    try testing.expectEqualStrings(try expectedDetails(a, MISMATCH_REASON, &tx), row.get("reject-details").?.string);
}

test "tests_r3fix_tma_single control: a valid P2WSH(OP_TRUE) spend is still allowed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, try p2wshOf(a, &SCRIPT_OP_TRUE)));
    const witness = try a.dupe([]const u8, &.{&SCRIPT_OP_TRUE});
    const tx = try spend(a, 2, witness, 1, 98_000);

    const row = try tma(a, r.srv, &tx);
    try testing.expect(row.get("allowed").?.bool);
    try testing.expect(row.get("reject-reason") == null);
    // A dry run adds nothing.
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_r3fix_tma_single R10: spending a bare nonstandard output is bad-txns-nonstandard-inputs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Bare OP_TRUE: TxoutType NONSTANDARD (policy/policy.cpp AreInputsStandard).
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, &SCRIPT_OP_TRUE));
    const tx = try spend(a, 2, &.{}, 1, 98_000);

    const row = try tma(a, r.srv, &tx);
    try expectRejected(row, "bad-txns-nonstandard-inputs");
    // No debug message in Core v31.1 (validation.cpp PreChecks), so
    // reject-details (TxValidationState::ToString) is the reason itself.
    try testing.expectEqualStrings("bad-txns-nonstandard-inputs", row.get("reject-details").?.string);
}

test "tests_r3fix_tma_single R4: a nonstandard input is reported before a zero fee (Core order)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, &SCRIPT_OP_TRUE));
    // Pays no fee: min relay fee not met too, but Core's PreChecks runs
    // AreInputsStandard before CheckFeeRate.
    const tx = try spend(a, 2, &.{}, 1, 100_000);

    const row = try tma(a, r.srv, &tx);
    try expectRejected(row, "bad-txns-nonstandard-inputs");
    try testing.expectEqualStrings("bad-txns-nonstandard-inputs", row.get("reject-details").?.string);
}

/// 240 P2WSH outputs: vsize just over TRUC_MAX_VSIZE (10,000 vB).
const BIG_N_OUT: usize = 240;

test "tests_r3fix_tma_single R46: a v3 tx over 10,000 vB is TRUC-violation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 1_000_000, try p2wshOf(a, &SCRIPT_OP_TRUE)));
    const witness = try a.dupe([]const u8, &.{&SCRIPT_OP_TRUE});
    const tx = try spend(a, 3, witness, BIG_N_OUT, 1_000);
    const weight = try mempool_mod.computeTxWeight(&tx, a);
    try testing.expect((weight + 3) / 4 > mempool_mod.TRUC_MAX_VSIZE);

    try expectRejected(try tma(a, r.srv, &tx), "TRUC-violation");
}

test "tests_r3fix_tma_single order: TRUC-violation is reported before a failing script (Core order)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Coin locked by P2WSH(OP_0) and spent with OP_0 (EVAL_FALSE), in a v3
    // tx over 10,000 vB.  Core v31.1 runs SingleTRUCChecks in PreChecks,
    // before PolicyScriptChecks, so the reason is TRUC-violation.
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 1_000_000, try p2wshOf(a, &SCRIPT_OP_0)));
    const witness = try a.dupe([]const u8, &.{&SCRIPT_OP_0});
    const tx = try spend(a, 3, witness, BIG_N_OUT, 1_000);

    try expectRejected(try tma(a, r.srv, &tx), "TRUC-violation");
}

test "tests_r3fix_tma_single control: the same oversized tx as version 2 is allowed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 1_000_000, try p2wshOf(a, &SCRIPT_OP_TRUE)));
    const witness = try a.dupe([]const u8, &.{&SCRIPT_OP_TRUE});
    const tx = try spend(a, 2, witness, BIG_N_OUT, 1_000);

    const row = try tma(a, r.srv, &tx);
    try testing.expect(row.get("allowed").?.bool);
}

test "tests_r3fix_tma_single order: a fee-paying dust tx is dust before the sigops-cost reject (Core order)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Five P2WSH coins whose witness script is 3,600 OP_CHECKSIG: 18,000
    // witness sigops > MAX_STANDARD_TX_SIGOPS_COST (16,000).  The script
    // is within IsWitnessStandard's 3,600-byte limit, so the inputs pass
    // AreInputsStandard / IsWitnessStandard.  The tx pays a fee and has one
    // dust output.  Core v31.1 PreChecks runs PreCheckEphemeralTx before
    // the sigops reject (validation.cpp), so the reason is dust, not
    // bad-txns-too-many-sigops.
    const N_IN: usize = 5;
    const ws = try a.alloc(u8, 3600);
    @memset(ws, 0xac); // OP_CHECKSIG
    const spk = try p2wshOf(a, ws);
    const cs = try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, spk);
    const ins = try a.alloc(types.TxIn, N_IN);
    for (ins, 0..) |*in, i| {
        const op = types.OutPoint{ .hash = PREV, .index = @intCast(i) };
        if (i > 0) {
            const out = types.TxOut{ .value = 100_000, .script_pubkey = spk };
            try cs.utxo_set.add(&op, &out, 799_000, false);
        }
        in.* = .{
            .previous_output = op,
            .script_sig = &.{},
            .sequence = 0xFFFFFFFD,
            .witness = try a.dupe([]const u8, &.{ws}),
        };
    }
    const r = try rig(a, cs);
    const outs = try a.alloc(types.TxOut, 2);
    const out_spk = try p2wshOf(a, &SCRIPT_OP_TRUE);
    outs[0] = .{ .value = 400_000, .script_pubkey = out_spk };
    outs[1] = .{ .value = 0, .script_pubkey = out_spk }; // the one dust output
    const tx = types.Transaction{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
    try testing.expectEqual(@as(usize, 1), mempool_mod.Mempool.dustOutputCount(&tx));

    try expectRejected(try tma(a, r.srv, &tx), "dust");
}

test "tests_r3fix_tma_single control: the same sigops-heavy tx without the dust output is bad-txns-too-many-sigops" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const N_IN: usize = 5;
    const ws = try a.alloc(u8, 3600);
    @memset(ws, 0xac);
    const spk = try p2wshOf(a, ws);
    const cs = try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, spk);
    const ins = try a.alloc(types.TxIn, N_IN);
    for (ins, 0..) |*in, i| {
        const op = types.OutPoint{ .hash = PREV, .index = @intCast(i) };
        if (i > 0) {
            const out = types.TxOut{ .value = 100_000, .script_pubkey = spk };
            try cs.utxo_set.add(&op, &out, 799_000, false);
        }
        in.* = .{
            .previous_output = op,
            .script_sig = &.{},
            .sequence = 0xFFFFFFFD,
            .witness = try a.dupe([]const u8, &.{ws}),
        };
    }
    const r = try rig(a, cs);
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = 400_000, .script_pubkey = try p2wshOf(a, &SCRIPT_OP_TRUE) };
    const tx = types.Transaction{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };

    try expectRejected(try tma(a, r.srv, &tx), "bad-txns-too-many-sigops");
}
