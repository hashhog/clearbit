//! Core's per-tx error strings in package results (testmempoolaccept with
//! several txs, submitpackage) vs Core v31.1.
//!
//! Run via `zig build test-mempool-error-strings` (also part of `zig build test`).
//!
//! Script-check failures (validation.cpp CheckInputScripts / CScriptCheck):
//!   reject-reason  "mempool-script-verify-flag-failed (<ScriptErrorString>)"
//!   reject-details / submitpackage error: TxValidationState::ToString,
//!                  "<reason>, input N of <txid> (wtxid <wtxid>), spending <prevout>:<n>"
//! Missing inputs in submitpackage: Core's PreChecks token
//!   "bad-txns-inputs-missingorspent" (TxValidationState::ToString, no debug
//!   message).  testmempoolaccept alone renames it "missing-inputs".
//!
//! Ratchet rows: seed_submitpackage/invalid-sig-{parent,child}/{accept,submit}:*,
//! package/submit/missing-input:*.

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

const COIN_VALUE: i64 = 1_000_000;

const NULLFAIL_REASON = "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)";
const EVAL_FALSE_REASON = "mempool-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)";

fn p2shOf(a: std.mem.Allocator, redeem: []const u8) ![]const u8 {
    const h = crypto.hash160(redeem);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

const REDEEM_TRUE = [_]u8{0x51}; // OP_TRUE
const REDEEM_FALSE = [_]u8{0x00}; // OP_0: leaves false (SCRIPT_ERR_EVAL_FALSE)
const SIG_TRUE = [_]u8{ 0x01, 0x51 };
const SIG_FALSE = [_]u8{ 0x01, 0x00 };

/// <G> OP_CHECKSIG, G = the secp256k1 generator (a valid compressed key).
const REDEEM_CHECKSIG = [_]u8{ 0x21, 0x02 } ++ [_]u8{
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
} ++ [_]u8{0xac};
/// scriptSig: a strict-DER, low-S signature (r=1, s=1, SIGHASH_ALL) that does
/// not verify, then the redeem script.  Under NULLFAIL a failed CHECKSIG with
/// a non-empty signature is SCRIPT_ERR_SIG_NULLFAIL.
const SIG_BAD_ECDSA = [_]u8{ 0x09, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x23 } ++ REDEEM_CHECKSIG;

fn spendTo(a: std.mem.Allocator, prev: types.Hash256, index: u32, script_sig: []const u8, value: i64, redeem_out: []const u8) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = .{ .hash = prev, .index = index },
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFD,
        .witness = &.{},
    };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = value, .script_pubkey = try p2shOf(a, redeem_out) };
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

fn hexOf(a: std.mem.Allocator, tx: *const types.Transaction) ![]const u8 {
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, tx);
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
}

/// Display (reversed) hex of a hash.
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

fn chainWithCoin(a: std.mem.Allocator, prev: types.Hash256, redeem: []const u8) !*storage.ChainState {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const out = types.TxOut{ .value = COIN_VALUE, .script_pubkey = try p2shOf(a, redeem) };
    const op = types.OutPoint{ .hash = prev, .index = 0 };
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

fn call(a: std.mem.Allocator, srv: *rpc.RpcServer, method: []const u8, txs: []const *const types.Transaction) !std.json.Parsed(std.json.Value) {
    var req = std.ArrayList(u8).init(a);
    try req.writer().print("{{\"id\":1,\"method\":\"{s}\",\"params\":[[", .{method});
    for (txs, 0..) |tx, i| {
        if (i > 0) try req.append(',');
        try req.writer().print("\"{s}\"", .{try hexOf(a, tx)});
    }
    try req.appendSlice("]]}");
    const resp = try srv.dispatch(req.items);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

/// submitpackage tx-results entry for `tx` (keyed by wtxid).
fn txResult(a: std.mem.Allocator, p: std.json.Parsed(std.json.Value), tx: *const types.Transaction) !std.json.ObjectMap {
    const res = p.value.object.get("result").?.object;
    const key = try displayHex(a, try crypto.computeWtxid(tx, a));
    return res.get("tx-results").?.object.get(key).?.object;
}

const PREV = [_]u8{0x42} ** 32;
const OTHER = [_]u8{0x77} ** 32;

test "tests_mempool_error_strings testmempoolaccept: a parent failing CHECKSIG under NULLFAIL gets Core's reason and details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, PREV, &REDEEM_CHECKSIG));

    const parent = try spendTo(a, PREV, 0, &SIG_BAD_ECDSA, COIN_VALUE - 20_000, &REDEEM_TRUE);
    const child = try spendTo(a, try crypto.computeTxid(&parent, a), 0, &SIG_TRUE, COIN_VALUE - 40_000, &REDEEM_TRUE);
    const p = try call(a, r.srv, "testmempoolaccept", &.{ &parent, &child });

    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(@as(usize, 2), rows.len);
    const r0 = rows[0].object;
    try testing.expect(!r0.get("allowed").?.bool);
    try testing.expectEqualStrings(NULLFAIL_REASON, r0.get("reject-reason").?.string);
    try testing.expectEqualStrings(try expectedDetails(a, NULLFAIL_REASON, &parent), r0.get("reject-details").?.string);
    // The child is unfinished.
    try testing.expect(rows[1].object.get("allowed") == null);
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_mempool_error_strings testmempoolaccept: a child whose script leaves false gets Core's EVAL_FALSE reason and details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, PREV, &REDEEM_TRUE));

    // Parent pays to P2SH(OP_0), so the child's spend leaves false.
    const parent = try spendTo(a, PREV, 0, &SIG_TRUE, COIN_VALUE - 20_000, &REDEEM_FALSE);
    const child = try spendTo(a, try crypto.computeTxid(&parent, a), 0, &SIG_FALSE, COIN_VALUE - 40_000, &REDEEM_TRUE);
    const p = try call(a, r.srv, "testmempoolaccept", &.{ &parent, &child });

    const rows = p.value.object.get("result").?.array.items;
    try testing.expect(rows[0].object.get("allowed").?.bool);
    const r1 = rows[1].object;
    try testing.expect(!r1.get("allowed").?.bool);
    try testing.expectEqualStrings(EVAL_FALSE_REASON, r1.get("reject-reason").?.string);
    try testing.expectEqualStrings(try expectedDetails(a, EVAL_FALSE_REASON, &child), r1.get("reject-details").?.string);
}

test "tests_mempool_error_strings submitpackage: a child failing its script check gets Core's full message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, PREV, &REDEEM_TRUE));

    // Parent pays to P2SH(<G> CHECKSIG); the child's bad signature fails NULLFAIL.
    const parent = try spendTo(a, PREV, 0, &SIG_TRUE, COIN_VALUE - 20_000, &REDEEM_CHECKSIG);
    const child = try spendTo(a, try crypto.computeTxid(&parent, a), 0, &SIG_BAD_ECDSA, COIN_VALUE - 40_000, &REDEEM_TRUE);
    const p = try call(a, r.srv, "submitpackage", &.{ &parent, &child });

    const c = try txResult(a, p, &child);
    try testing.expectEqualStrings(try expectedDetails(a, NULLFAIL_REASON, &child), c.get("error").?.string);
    try testing.expect(c.get("fees") == null);
}

test "tests_mempool_error_strings submitpackage: a parent failing its script check gets Core's full message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, try chainWithCoin(a, PREV, &REDEEM_CHECKSIG));

    const parent = try spendTo(a, PREV, 0, &SIG_BAD_ECDSA, COIN_VALUE - 20_000, &REDEEM_TRUE);
    const child = try spendTo(a, try crypto.computeTxid(&parent, a), 0, &SIG_TRUE, COIN_VALUE - 40_000, &REDEEM_TRUE);
    const p = try call(a, r.srv, "submitpackage", &.{ &parent, &child });

    const pr = try txResult(a, p, &parent);
    try testing.expectEqualStrings(try expectedDetails(a, NULLFAIL_REASON, &parent), pr.get("error").?.string);
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

/// Wraps an allocator and remembers every pointer handed to `free`.
const FreeTracker = struct {
    child: std.mem.Allocator,
    freed: std.ArrayList(usize),

    fn allocator(self: *FreeTracker) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret: usize) ?[*]u8 {
        const self: *FreeTracker = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, ptr_align, ret);
    }
    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret: usize) bool {
        const self: *FreeTracker = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(buf, buf_align, new_len, ret);
    }
    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret: usize) void {
        const self: *FreeTracker = @ptrCast(@alignCast(ctx));
        self.freed.append(@intFromPtr(buf.ptr)) catch {};
        self.child.rawFree(buf, buf_align, ret);
    }
};

test "tests_mempool_error_strings acceptPackage frees the script-check message it allocates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var tracker = FreeTracker{ .child = arena.allocator(), .freed = std.ArrayList(usize).init(testing.allocator) };
    defer tracker.freed.deinit();
    // One allocator for the whole rig: acceptPackage frees UTXO copies with
    // the allocator it is given.
    const a = tracker.allocator();
    const r = try rig(a, try chainWithCoin(a, PREV, &REDEEM_CHECKSIG));

    const parent = try spendTo(a, PREV, 0, &SIG_BAD_ECDSA, COIN_VALUE - 20_000, &REDEEM_TRUE);
    const child = try spendTo(a, try crypto.computeTxid(&parent, a), 0, &SIG_TRUE, COIN_VALUE - 40_000, &REDEEM_TRUE);
    var result = try mempool_mod.acceptPackage(r.mp, &.{ parent, child }, a);
    try testing.expect(!result.tx_results[0].accepted);
    const msg = result.tx_results[0].error_message.?;
    try testing.expectEqualStrings(try expectedDetails(a, NULLFAIL_REASON, &parent), msg);
    const before = tracker.freed.items.len;
    result.deinit();
    // deinit frees the message exactly once.
    var n: usize = 0;
    for (tracker.freed.items[before..]) |ptr| {
        if (ptr == @intFromPtr(msg.ptr)) n += 1;
    }
    try testing.expectEqual(@as(usize, 1), n);
}

test "tests_mempool_error_strings ScriptErrorString table matches Core's text" {
    // Guarded so this file compiles on a tree without the table.
    if (!@hasDecl(script, "scriptErrorString")) {
        return error.TestExpectedCoreScriptErrorString;
    } else {
        const f = script.scriptErrorString;
        try testing.expectEqualStrings("Signature must be zero for failed CHECK(MULTI)SIG operation", f(script.ScriptError.NullFail));
        try testing.expectEqualStrings("Script failed an OP_EQUALVERIFY operation", f(script.ScriptError.EqualVerifyFailed));
        try testing.expectEqualStrings("Non-canonical DER signature", f(script.ScriptError.InvalidSignatureEncoding));
        try testing.expectEqualStrings("Witness program hash mismatch", f(script.ScriptError.WitnessProgramMismatch));
        try testing.expectEqualStrings("Dummy CHECKMULTISIG argument must be zero", f(script.ScriptError.NullDummy));
        try testing.expectEqualStrings("Locktime requirement not satisfied", f(script.ScriptError.UnsatisfiedLocktime));
        try testing.expectEqualStrings("Invalid Schnorr signature size", f(script.ScriptError.SchnorrSigSize));
    }
}
