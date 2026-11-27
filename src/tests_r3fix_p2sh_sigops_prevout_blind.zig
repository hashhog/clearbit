//! The P2SH redeemScript sigop limit applies only to P2SH inputs
//! (r3fix-clearbit-p2sh-sigops-prevout-blind).
//!
//! Run via `zig build test-r3fix-p2sh-sigops` (also part of `zig build test`).
//!
//! Core v31.1 AreInputsStandard (policy/policy.cpp) parses the last scriptSig
//! push as a redeemScript and refuses more than MAX_P2SH_SIGOPS (15) sigops in
//! it ONLY when the spent output is TxoutType::SCRIPTHASH; the reject is
//! "bad-txns-nonstandard-inputs" with no debug message (validation.cpp
//! PreChecks).  clearbit's checkStandard applied the limit to the last push of
//! EVERY input, whatever it spent, so:
//!   - a P2PKH spend whose 33-byte pubkey reads as > 15 sigops was refused
//!     "non-standard" (about 1 compressed key in 32, fixed per key);
//!   - R8 (gen-fuzz night 1, seed 739943): a P2TR spend with a 65-byte
//!     scriptSig push that reads as 20 sigops was refused "non-standard",
//!     where Core fails the script (WITNESS_MALLEATED);
//!   - R2: a real P2SH spend over the limit was refused with "non-standard"
//!     instead of Core's "bad-txns-nonstandard-inputs".

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
const script = @import("script.zig");
const secp = @import("secp.zig");

const NSI = "bad-txns-nonstandard-inputs";

/// The minimised R2 case from night 1, byte for byte: a P2SH spend whose
/// redeemScript is OP_CHECKMULTISIGVERIFY (scriptSig `01af`, 20 sigops).
/// Core v31.1: allowed:false, bad-txns-nonstandard-inputs.
const R2_HEX = "0200000001caf565ba5179557322bb69821d9c5e9308b1972c88517891cec68196f6856b92000000000201affeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";

/// R8 from night 1, byte for byte: spends a P2TR output (script path) with a
/// 65-byte scriptSig push that clearbit's counter reads as 20 sigops.
/// Core v31.1: allowed:false, mempool-script-verify-flag-failed (Witness
/// requires empty scriptSig) -- SCRIPT_ERR_WITNESS_MALLEATED.
const R8_HEX = "0200000000010120ee800cac734d43c12a13e6785f2d23e74dcf1be9a1bce1c8121310a77e459f1c00000042418cbfc0c9afd2e5c29ac8283ad6ae98a3b27de7d5cea50921a37cbef420c7c89d3566ed6dc1b7d19837d8bbd7ae230a65be154228837841bca1f0b67f79146a9982feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260030101fd2d015151635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351635163516351636868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686868686821c179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";

const SCRIPT_OP_TRUE = [_]u8{0x51};

/// A P2SH scriptPubKey (zero hash): makes getP2SHSigOpCount read the last
/// scriptSig push as a redeemScript, as the removed approximation did.
const ANY_P2SH = [_]u8{ 0xa9, 0x14 } ++ [_]u8{0} ** 20 ++ [_]u8{0x87};

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

fn p2wshOf(a: std.mem.Allocator, witness_script: []const u8) ![]const u8 {
    const h = crypto.sha256(witness_script);
    const spk = try a.alloc(u8, 34);
    spk[0] = 0x00;
    spk[1] = 0x20;
    @memcpy(spk[2..34], &h);
    return spk;
}

fn p2shOf(a: std.mem.Allocator, redeem: []const u8) ![]const u8 {
    const h = crypto.hash160(redeem);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

fn p2pkhOf(a: std.mem.Allocator, pubkey: []const u8) ![]const u8 {
    const h = crypto.hash160(pubkey);
    const spk = try a.alloc(u8, 25);
    spk[0] = 0x76;
    spk[1] = 0xa9;
    spk[2] = 0x14;
    @memcpy(spk[3..23], &h);
    spk[23] = 0x88;
    spk[24] = 0xac;
    return spk;
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

/// testmempoolaccept of `txs`; returns the result rows.
fn tma(a: std.mem.Allocator, srv: *rpc.RpcServer, txs: []const types.Transaction) ![]std.json.Value {
    var list = std.ArrayList(u8).init(a);
    for (txs, 0..) |*tx, i| {
        if (i > 0) try list.append(',');
        try list.writer().print("\"{s}\"", .{try hexOf(a, tx)});
    }
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[{s}]]}}", .{list.items});
    const resp = try srv.dispatch(req);
    const p = try std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(txs.len, rows.len);
    return rows;
}

fn tma1(a: std.mem.Allocator, srv: *rpc.RpcServer, tx: types.Transaction) !std.json.ObjectMap {
    return (try tma(a, srv, &.{tx}))[0].object;
}

fn expectRejected(row: std.json.ObjectMap, reason: []const u8) !void {
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings(reason, row.get("reject-reason").?.string);
}

const PREV = [_]u8{0x42} ** 32;

/// One-input tx spending `prev` with `script_sig`, paying one
/// P2WSH(OP_TRUE) output of 98,000 sat.
fn spendOf(a: std.mem.Allocator, prev: types.OutPoint, script_sig: []const u8, out_spk: ?[]const u8) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{ .previous_output = prev, .script_sig = script_sig, .sequence = 0xFFFFFFFD, .witness = &.{} };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = 98_000, .script_pubkey = out_spk orelse try p2wshOf(a, &SCRIPT_OP_TRUE) };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

/// A compressed pubkey that clearbit's sigop counter (Core's
/// GetSigOpCount(true)) reads as more than MAX_P2SH_SIGOPS sigops when the
/// key bytes are parsed as a script, with its secret key.  Deterministic: the
/// first such key in seckey order 1, 2, 3, ...
const Key = struct { sec: [32]u8, pubkey: [33]u8 };

fn sigopHeavyKey() !Key {
    const ctx = secp.context() orelse return error.NoSecp;
    var n: u32 = 1;
    while (n < 100_000) : (n += 1) {
        var sec = [_]u8{0} ** 32;
        std.mem.writeInt(u32, sec[28..32], n, .big);
        var pk: secp.c.secp256k1_pubkey = undefined;
        if (secp.c.secp256k1_ec_pubkey_create(ctx, &pk, &sec) != 1) continue;
        var out: [33]u8 = undefined;
        var len: usize = 33;
        _ = secp.c.secp256k1_ec_pubkey_serialize(ctx, &out, &len, &pk, secp.c.SECP256K1_EC_COMPRESSED);
        if (script.getSigOpCount(&out, true) > consensus.MAX_P2SH_SIGOPS) return .{ .sec = sec, .pubkey = out };
    }
    return error.NoKeyFound;
}

/// A validly signed (SIGHASH_ALL) P2PKH spend of PREV:0 by `key`.
fn signedP2pkhSpend(a: std.mem.Allocator, key: Key, spk: []const u8) !types.Transaction {
    const tx = try spendOf(a, .{ .hash = PREV, .index = 0 }, &.{}, null);
    const sighash = try crypto.legacySighash(&tx, 0, spk, 1, a);
    const sig = crypto.ecdsaSignDer(&sighash, &key.sec) orelse return error.SignFailed;
    var ss = std.ArrayList(u8).init(a);
    try ss.append(@intCast(sig.len + 1));
    try ss.appendSlice(sig.bytes[0..sig.len]);
    try ss.append(0x01);
    try ss.append(33);
    try ss.appendSlice(&key.pubkey);
    @constCast(tx.inputs)[0].script_sig = ss.items;
    return tx;
}

test "tests_r3fix_p2sh_sigops P2PKH: a signed spend whose pubkey reads as >15 sigops is allowed by testmempoolaccept" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = try sigopHeavyKey();
    const spk = try p2pkhOf(a, &key.pubkey);
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, spk));
    const tx = try signedP2pkhSpend(a, key, spk);
    // Precondition: the scriptSig's last push (the pubkey) is what the old
    // approximation parsed, and it counts over the limit.
    try testing.expect(script.getP2SHSigOpCount(&ANY_P2SH, tx.inputs[0].script_sig) > consensus.MAX_P2SH_SIGOPS);

    const row = try tma1(a, r.srv, tx);
    try testing.expect(row.get("reject-reason") == null);
    try testing.expect(row.get("allowed").?.bool);
}

test "tests_r3fix_p2sh_sigops P2PKH: the same spend is accepted into the mempool (full path, scripts run)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = try sigopHeavyKey();
    const spk = try p2pkhOf(a, &key.pubkey);
    const r = try rig(a, try chainWithCoin(a, .{ .hash = PREV, .index = 0 }, 100_000, spk));
    const tx = try signedP2pkhSpend(a, key, spk);

    try r.mp.addTransaction(tx);
    try testing.expectEqual(@as(usize, 1), r.mp.entries.count());
}

test "tests_r3fix_p2sh_sigops R8: a P2TR spend with a 20-sigop-looking scriptSig push fails its script, not non-standard" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try decodeHex(a, R8_HEX);
    // Precondition: the 65-byte push counts 20 sigops (0xae at an opcode
    // position), the triage's re-count.
    try testing.expectEqual(@as(usize, 66), tx.inputs[0].script_sig.len);
    try testing.expectEqual(@as(u32, 20), script.getSigOpCount(tx.inputs[0].script_sig[1..], true));
    // The spent output: any P2TR output key (WITNESS_MALLEATED is checked
    // before the witness program is run).
    var p2tr: [34]u8 = undefined;
    p2tr[0] = 0x51;
    p2tr[1] = 0x20;
    @memset(p2tr[2..], 0x5a);
    const r = try rig(a, try chainWithCoin(a, tx.inputs[0].previous_output, 100_000, &p2tr));

    // Core: SCRIPT_ERR_WITNESS_MALLEATED, a script failure.
    try testing.expectError(mempool_mod.MempoolError.ScriptVerifyFailed, r.mp.addTransaction(tx));
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_r3fix_p2sh_sigops R2: the minimised P2SH spend (redeemScript CHECKMULTISIGVERIFY) is bad-txns-nonstandard-inputs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try decodeHex(a, R2_HEX);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0xaf }, tx.inputs[0].script_sig);
    const r = try rig(a, try chainWithCoin(a, tx.inputs[0].previous_output, 100_000, try p2shOf(a, &[_]u8{0xaf})));

    const row = try tma1(a, r.srv, tx);
    try expectRejected(row, NSI);
    // No debug message in Core v31.1, so reject-details (ToString) is the
    // reason itself.
    try testing.expectEqualStrings(NSI, row.get("reject-details").?.string);
}

test "tests_r3fix_p2sh_sigops control: the R2 spend stays refused on the full path" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try decodeHex(a, R2_HEX);
    const r = try rig(a, try chainWithCoin(a, tx.inputs[0].previous_output, 100_000, try p2shOf(a, &[_]u8{0xaf})));

    try testing.expectError(mempool_mod.MempoolError.NonStandard, r.mp.addTransaction(tx));
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

/// `OP_0 OP_IF <n x OP_CHECKSIG> OP_ENDIF OP_1`: counts n sigops, and
/// evaluates to true (the IF branch never runs), so the spend is valid and
/// only the policy limit can refuse it.
fn skippedSigopsRedeem(a: std.mem.Allocator, n: usize) ![]const u8 {
    const r = try a.alloc(u8, n + 4);
    r[0] = 0x00;
    r[1] = 0x63;
    @memset(r[2 .. 2 + n], 0xac);
    r[2 + n] = 0x68;
    r[3 + n] = 0x51;
    return r;
}

fn pushOf(a: std.mem.Allocator, data: []const u8) ![]const u8 {
    std.debug.assert(data.len < 0x4c);
    const s = try a.alloc(u8, data.len + 1);
    s[0] = @intCast(data.len);
    @memcpy(s[1..], data);
    return s;
}

test "tests_r3fix_p2sh_sigops control: a valid P2SH spend with exactly 15 redeemScript sigops is allowed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const redeem = try skippedSigopsRedeem(a, 15);
    try testing.expectEqual(@as(u32, 15), script.getSigOpCount(redeem, true));
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    const r = try rig(a, try chainWithCoin(a, op, 100_000, try p2shOf(a, redeem)));
    const tx = try spendOf(a, op, try pushOf(a, redeem), null);

    const row = try tma1(a, r.srv, tx);
    try testing.expect(row.get("reject-reason") == null);
    try testing.expect(row.get("allowed").?.bool);
    try r.mp.addTransaction(tx);
    try testing.expectEqual(@as(usize, 1), r.mp.entries.count());
}

test "tests_r3fix_p2sh_sigops control: the same valid P2SH spend with 16 redeemScript sigops is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const redeem = try skippedSigopsRedeem(a, 16);
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    const r = try rig(a, try chainWithCoin(a, op, 100_000, try p2shOf(a, redeem)));
    const tx = try spendOf(a, op, try pushOf(a, redeem), null);

    const row = try tma1(a, r.srv, tx);
    try expectRejected(row, NSI);
    try testing.expectEqualStrings(NSI, row.get("reject-details").?.string);
    try testing.expectError(mempool_mod.MempoolError.NonStandard, r.mp.addTransaction(tx));
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_r3fix_p2sh_sigops order: a 16-sigop P2SH spend paying no fee is refused as nonstandard, not for the fee (full path)" {
    // Core PreChecks runs AreInputsStandard before CheckFeeRate
    // (validation.cpp), so the input-standardness refusal wins.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const redeem = try skippedSigopsRedeem(a, 16);
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    const r = try rig(a, try chainWithCoin(a, op, 100_000, try p2shOf(a, redeem)));
    const tx = try spendOf(a, op, try pushOf(a, redeem), null);
    @constCast(tx.outputs)[0].value = 100_000; // fee 0

    try testing.expectError(mempool_mod.MempoolError.NonStandard, r.mp.addTransaction(tx));
    try testing.expectError(mempool_mod.MempoolError.NonStandard, r.mp.addTransactionWithPackageRate(tx, 0.0));
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_r3fix_p2sh_sigops order: the same zero-fee spend is bad-txns-nonstandard-inputs in testmempoolaccept" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const redeem = try skippedSigopsRedeem(a, 16);
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    const r = try rig(a, try chainWithCoin(a, op, 100_000, try p2shOf(a, redeem)));
    const tx = try spendOf(a, op, try pushOf(a, redeem), null);
    @constCast(tx.outputs)[0].value = 100_000; // fee 0

    const row = try tma1(a, r.srv, tx);
    try expectRejected(row, NSI);
}

test "tests_r3fix_p2sh_sigops package: a child spending its package parent's P2SH output over the limit is bad-txns-nonstandard-inputs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const redeem15 = try skippedSigopsRedeem(a, 15);
    const redeem16 = try skippedSigopsRedeem(a, 16);
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    const r = try rig(a, try chainWithCoin(a, op, 100_000, try p2shOf(a, redeem15)));
    // The parent pays to P2SH(redeem16); the child spends that output, so
    // the child's prevout exists only in the package.
    const parent = try spendOf(a, op, try pushOf(a, redeem15), try p2shOf(a, redeem16));
    const parent_txid = try crypto.computeTxid(&parent, a);
    const child = try spendOf(a, .{ .hash = parent_txid, .index = 0 }, try pushOf(a, redeem16), null);
    @constCast(child.outputs)[0].value = 96_000;

    const rows = try tma(a, r.srv, &.{ parent, child });
    const crow = rows[1].object;
    try expectRejected(crow, NSI);
    try testing.expectEqualStrings(NSI, crow.get("reject-details").?.string);
}
