//! A premature coinbase spend reports Core's depth message.
//!
//! Run via `zig build test-maturity-reject-details` (also part of `zig build test`).
//!
//! Core v31.1 Consensus::CheckTxInputs (consensus/tx_verify.cpp):
//!   if (nSpendHeight - coin.nHeight < COINBASE_MATURITY)
//!       return state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
//!           strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
//! The mempool calls it with nSpendHeight = tip + 1 (validation.cpp PreChecks).
//! testmempoolaccept reports reject-details = TxValidationState::ToString(),
//! "<reason>, <debug message>" (rpc/mempool.cpp); sendrawtransaction's error
//! message is the same ToString.
//!
//! Ratchet rows: {seed,warden}_invalidated_submit/maturity/tip99-accept:[0].reject-details,
//! {seed,warden}_invalidated_submit/maturity/tip99-send:message.

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

const COINBASE_VALUE: i64 = 5_000_000_000;
const REDEEM_TRUE = [_]u8{0x51}; // OP_TRUE
const SIG_TRUE = [_]u8{ 0x01, 0x51 };
const CB = [_]u8{0x5c} ** 32;

fn p2shTrue(a: std.mem.Allocator) ![]const u8 {
    const h = crypto.hash160(&REDEEM_TRUE);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

const Rig = struct { cs: *storage.ChainState, mp: *mempool_mod.Mempool, srv: *rpc.RpcServer, spend_hex: []const u8 };

/// A chain at `tip` holding the height-1 coinbase output CB:0
/// (P2SH(OP_TRUE), as the regtest harness pays) and a spend of it.
fn rig(a: std.mem.Allocator, tip: u32) !Rig {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = tip;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const spk = try p2shTrue(a);
    const op = types.OutPoint{ .hash = CB, .index = 0 };
    try cs.utxo_set.add(&op, &types.TxOut{ .value = COINBASE_VALUE, .script_pubkey = spk }, 1, true);

    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});

    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{ .previous_output = op, .script_sig = &SIG_TRUE, .sequence = 0xFFFF_FFFF, .witness = &.{} };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = COINBASE_VALUE - 10_000, .script_pubkey = spk };
    const tx = types.Transaction{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, &tx);
    const hex = try std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
    return .{ .cs = cs, .mp = mp, .srv = srv, .spend_hex = hex };
}

fn testAccept(a: std.mem.Allocator, r: Rig) !std.json.ObjectMap {
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\"]]}}", .{r.spend_hex});
    const p = try std.json.parseFromSlice(std.json.Value, a, try r.srv.dispatch(req), .{ .allocate = .alloc_always });
    return p.value.object.get("result").?.array.items[0].object;
}

fn sendRaw(a: std.mem.Allocator, r: Rig) !std.json.ObjectMap {
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"{s}\"]}}", .{r.spend_hex});
    const p = try std.json.parseFromSlice(std.json.Value, a, try r.srv.dispatch(req), .{ .allocate = .alloc_always });
    return p.value.object;
}

/// A string field, or a test failure (not a panic) when it is absent, so
/// master fails each test on its assertion and the run reports all of them.
fn str(obj: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const v = obj.get(name) orelse {
        std.debug.print("missing field {s}\n", .{name});
        return error.TestExpectedEqual;
    };
    return v.string;
}

const DEPTH_99 = "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99";

test "tests_maturity_reject_details testmempoolaccept at tip 99: reject-details names the depth, as Core" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const row = try testAccept(a, try rig(a, 99));
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("bad-txns-premature-spend-of-coinbase", row.get("reject-reason").?.string);
    try testing.expectEqualStrings(DEPTH_99, (try str(row, "reject-details")));
}

test "tests_maturity_reject_details sendrawtransaction at tip 99: the error message names the depth, as Core" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, 99);
    const resp = try sendRaw(a, r);
    const err = resp.get("error").?.object;
    // RPC_TRANSACTION_REJECTED (-26): Core's TransactionError::MEMPOOL_REJECTED.
    try testing.expectEqual(@as(i64, -26), err.get("code").?.integer);
    try testing.expectEqualStrings(DEPTH_99, err.get("message").?.string);
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_maturity_reject_details the depth is spend height (tip + 1) minus the coin height" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Tip 10: spend height 11, coin height 1, depth 10.
    const row = try testAccept(a, try rig(a, 10));
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 10", (try str(row, "reject-details")));
}

test "tests_maturity_reject_details control: at tip 100 the same spend is allowed and sent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, 100);
    const row = try testAccept(a, r);
    try testing.expect(row.get("allowed").?.bool);
    try testing.expect(row.get("reject-details") == null);
    const resp = try sendRaw(a, r);
    try testing.expect(resp.get("result").? == .string);
    try testing.expectEqual(@as(usize, 1), r.mp.entries.count());
}

test "tests_maturity_reject_details testmempoolaccept with a parent and child: the premature parent gets the same details" {
    // Core's AcceptMultipleTransactions reports the same ToString per tx;
    // the first failure ends validation, so the child stays unfinished.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, 99);

    const raw = try a.alloc(u8, r.spend_hex.len / 2);
    _ = try std.fmt.hexToBytes(raw, r.spend_hex);
    var reader = serialize.Reader{ .data = raw };
    const parent = try serialize.readTransaction(&reader, a);
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{ .previous_output = .{ .hash = try crypto.computeTxid(&parent, a), .index = 0 }, .script_sig = &SIG_TRUE, .sequence = 0xFFFF_FFFF, .witness = &.{} };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = parent.outputs[0].value - 10_000, .script_pubkey = parent.outputs[0].script_pubkey };
    const child = types.Transaction{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, &child);
    const child_hex = try std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});

    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\",\"{s}\"]]}}", .{ r.spend_hex, child_hex });
    const p = try std.json.parseFromSlice(std.json.Value, a, try r.srv.dispatch(req), .{ .allocate = .alloc_always });
    const rows = p.value.object.get("result").?.array.items;
    try testing.expectEqual(@as(usize, 2), rows.len);
    const r0 = rows[0].object;
    try testing.expect(!r0.get("allowed").?.bool);
    try testing.expectEqualStrings("bad-txns-premature-spend-of-coinbase", r0.get("reject-reason").?.string);
    try testing.expectEqualStrings(DEPTH_99, (try str(r0, "reject-details")));
    try testing.expect(rows[1].object.get("allowed") == null);
}
