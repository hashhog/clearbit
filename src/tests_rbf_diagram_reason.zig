//! A replacement refused by the feerate-diagram check reports Core's reason.
//!
//! Run via `zig build test-rbf-diagram-reason` (also part of `zig build test`).
//!
//! Core v31.1 MemPoolAccept::ReplacementChecks (validation.cpp):
//!   if (const auto err_string{ImprovesFeerateDiagram(*m_subpackage.m_changeset)})
//!       return state.Invalid(TX_RECONSIDERABLE, "replacement-failed", err_string->second);
//! with err_string->second = "insufficient feerate: does not improve feerate
//! diagram" (policy/rbf.cpp ImprovesFeerateDiagram).  testmempoolaccept
//! reports reject-reason = GetRejectReason() and reject-details = ToString()
//! (rpc/mempool.cpp); sendrawtransaction's error message is ToString().
//!
//! Ratchet rows: rbf/diagram/accept:[0].reject-reason,
//! rbf/diagram/accept:[0].reject-details, rbf/diagram/submit:message.
//! The txs mirror the harness scenario (scenarios/rbf.py, `diagram`).

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

const COIN_VALUE: i64 = 1_000_000;
const ORIGINAL_FEE: i64 = 5_000;
const WIDE_FEE: i64 = 5_200;
const WIDE_OUTPUTS: usize = 40;

const CORE_REASON = "replacement-failed";
const CORE_DETAILS = "replacement-failed, insufficient feerate: does not improve feerate diagram";

const REDEEM_TRUE = [_]u8{0x51}; // OP_TRUE
const SIG_TRUE = [_]u8{ 0x01, 0x51 };
const PREV = [_]u8{0x42} ** 32;

fn p2shTrue(a: std.mem.Allocator) ![]const u8 {
    const h = crypto.hash160(&REDEEM_TRUE);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

/// Spend PREV:0 (BIP125-signalling) into `n_out` P2SH(OP_TRUE) outputs paying `fee`.
fn spend(a: std.mem.Allocator, fee: i64, n_out: usize) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = .{ .hash = PREV, .index = 0 },
        .script_sig = &SIG_TRUE,
        .sequence = 0xFFFFFFFD,
        .witness = &.{},
    };
    const spk = try p2shTrue(a);
    const outs = try a.alloc(types.TxOut, n_out);
    const spendable = COIN_VALUE - fee;
    const each = @divTrunc(spendable, @as(i64, @intCast(n_out)));
    for (outs, 0..) |*o, i| {
        const extra: i64 = if (i == 0) spendable - each * @as(i64, @intCast(n_out)) else 0;
        o.* = .{ .value = each + extra, .script_pubkey = spk };
    }
    return .{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
}

fn hexOf(a: std.mem.Allocator, tx: *const types.Transaction) ![]const u8 {
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, tx);
    return std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
}

const Rig = struct { mp: *mempool_mod.Mempool, srv: *rpc.RpcServer };

/// A chain holding PREV:0 (P2SH(OP_TRUE), not a coinbase) and a pool holding
/// the original 1-in-1-out spend of it.
fn rigWithOriginal(a: std.mem.Allocator) !struct { rig: Rig, original_txid: types.Hash256 } {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const out = types.TxOut{ .value = COIN_VALUE, .script_pubkey = try p2shTrue(a) };
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    try cs.utxo_set.add(&op, &out, 799_000, false);

    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});

    const original = try spend(a, ORIGINAL_FEE, 1);
    try mp.addTransaction(original);
    return .{ .rig = .{ .mp = mp, .srv = srv }, .original_txid = try crypto.computeTxid(&original, a) };
}

fn rpcCall(a: std.mem.Allocator, srv: *rpc.RpcServer, comptime fmt: []const u8, hex: []const u8) !std.json.Parsed(std.json.Value) {
    const req = try std.fmt.allocPrint(a, fmt, .{hex});
    const resp = try srv.dispatch(req);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

test "tests_rbf_diagram_reason testmempoolaccept: a diagram-worsening replacement is replacement-failed with Core's details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try rigWithOriginal(a);

    const wide = try spend(a, WIDE_FEE, WIDE_OUTPUTS);
    const p = try rpcCall(a, s.rig.srv, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\"]]}}", try hexOf(a, &wide));
    const row = p.value.object.get("result").?.array.items[0].object;
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings(CORE_REASON, row.get("reject-reason").?.string);
    try testing.expectEqualStrings(CORE_DETAILS, row.get("reject-details").?.string);
}

test "tests_rbf_diagram_reason sendrawtransaction: a diagram-worsening replacement fails with Core's message and the original stays" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try rigWithOriginal(a);

    const wide = try spend(a, WIDE_FEE, WIDE_OUTPUTS);
    const p = try rpcCall(a, s.rig.srv, "{{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"{s}\"]}}", try hexOf(a, &wide));
    const err = p.value.object.get("error").?.object;
    // RPC_TRANSACTION_REJECTED (-26), as Core's TransactionError::MEMPOOL_REJECTED.
    try testing.expectEqual(@as(i64, -26), err.get("code").?.integer);
    try testing.expectEqualStrings(CORE_DETAILS, err.get("message").?.string);
    try testing.expectEqual(@as(usize, 1), s.rig.mp.entries.count());
    try testing.expect(s.rig.mp.entries.get(s.original_txid) != null);
}

test "tests_rbf_diagram_reason control: a replacement that improves the diagram is accepted" {
    // The same rig accepts a higher-feerate replacement, so the refusal above
    // is the diagram check and not the rig (Core's rbf/simple control).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try rigWithOriginal(a);

    const better = try spend(a, 10_000, 1);
    const p = try rpcCall(a, s.rig.srv, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\"]]}}", try hexOf(a, &better));
    const row = p.value.object.get("result").?.array.items[0].object;
    try testing.expect(row.get("allowed").?.bool);
}

test "tests_rbf_diagram_reason a replacement paying less than the original stays insufficient fee" {
    // PaysForRBF rule 3 is a different reject (Core "insufficient fee"); the
    // diagram reason must not swallow it.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try rigWithOriginal(a);

    const cheaper = try spend(a, ORIGINAL_FEE - 1_000, 1);
    const p = try rpcCall(a, s.rig.srv, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\"]]}}", try hexOf(a, &cheaper));
    const row = p.value.object.get("result").?.array.items[0].object;
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("insufficient fee", row.get("reject-reason").?.string);
}
