//! A tx whose inputs are all value-0 coins must still pass value
//! conservation and the relay fee floor.
//!
//! Run via `zig build test-zero-input-conservation` (also part of `zig build test`).
//!
//! Core v31.1 Consensus::CheckTxInputs (consensus/tx_verify.cpp):
//!   if (nValueIn < value_out)
//!       return state.Invalid(TX_CONSENSUS, "bad-txns-in-belowout",
//!           strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
//! It runs for every tx in MemPoolAccept::PreChecks, whatever the input
//! total, and PreChecks then applies CheckFeeRate (min relay fee).
//! clearbit used to compute the fee only `if (total_in > 0)`, so a tx
//! spending only value-0 coins skipped both checks and could create value.

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

const REDEEM_TRUE = [_]u8{0x51}; // OP_TRUE
const SIG_TRUE = [_]u8{ 0x01, 0x51 };
const PREV = [_]u8{0x5d} ** 32;
const OP_RETURN = [_]u8{ 0x6a, 0x01, 0x00 };

fn p2shTrue(a: std.mem.Allocator) ![]const u8 {
    const h = crypto.hash160(&REDEEM_TRUE);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

const Rig = struct {
    cs: *storage.ChainState,
    mp: *mempool_mod.Mempool,
    srv: *rpc.RpcServer,
    tx: types.Transaction,
    hex: []const u8,
};

/// A chain at tip 200 holding a mature, non-coinbase coin PREV:0 of
/// `coin_value` sats (P2SH(OP_TRUE)), and a tx spending it to one output of
/// `out_value` sats (P2SH(OP_TRUE), or OP_RETURN when `out_value` is 0).
fn rig(a: std.mem.Allocator, coin_value: i64, out_value: i64) !Rig {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 200;
    cs.best_hash = [_]u8{0xB8} ** 32;
    const spk = try p2shTrue(a);
    const op = types.OutPoint{ .hash = PREV, .index = 0 };
    try cs.utxo_set.add(&op, &types.TxOut{ .value = coin_value, .script_pubkey = spk }, 10, false);

    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});

    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{ .previous_output = op, .script_sig = &SIG_TRUE, .sequence = 0xFFFF_FFFF, .witness = &.{} };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = out_value, .script_pubkey = if (out_value == 0) &OP_RETURN else spk };
    const tx = types.Transaction{ .version = 2, .inputs = ins, .outputs = outs, .lock_time = 0 };
    var w = serialize.Writer.init(a);
    try serialize.writeTransaction(&w, &tx);
    const hex = try std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(w.list.items)});
    return .{ .cs = cs, .mp = mp, .srv = srv, .tx = tx, .hex = hex };
}

fn testAccept(a: std.mem.Allocator, r: Rig) !std.json.ObjectMap {
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"testmempoolaccept\",\"params\":[[\"{s}\"]]}}", .{r.hex});
    const p = try std.json.parseFromSlice(std.json.Value, a, try r.srv.dispatch(req), .{ .allocate = .alloc_always });
    return p.value.object.get("result").?.array.items[0].object;
}

fn sendRaw(a: std.mem.Allocator, r: Rig) !std.json.ObjectMap {
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"{s}\"]}}", .{r.hex});
    const p = try std.json.parseFromSlice(std.json.Value, a, try r.srv.dispatch(req), .{ .allocate = .alloc_always });
    return p.value.object;
}

/// A string field, or a test failure (not a panic) when it is absent.
fn str(obj: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const v = obj.get(name) orelse {
        std.debug.print("missing field {s}\n", .{name});
        return error.TestExpectedEqual;
    };
    if (v != .string) {
        std.debug.print("field {s} is not a string\n", .{name});
        return error.TestExpectedEqual;
    }
    return v.string;
}

/// The `error` object of an RPC response, or a test failure when the call
/// succeeded (master accepted the tx).
fn rpcError(resp: std.json.ObjectMap) !std.json.ObjectMap {
    const e = resp.get("error") orelse return error.TestExpectedEqual;
    if (e != .object) {
        std.debug.print("call succeeded: result={any}\n", .{resp.get("result")});
        return error.TestExpectedEqual;
    }
    return e.object;
}

const BELOWOUT_0_1000 = "bad-txns-in-belowout, value in (0.00) < value out (0.00001)";

test "tests_zero_input_conservation testmempoolaccept: a value-0 coin spent to 1,000 sats is bad-txns-in-belowout, as Core" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const row = try testAccept(a, try rig(a, 0, 1_000));
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("bad-txns-in-belowout", try str(row, "reject-reason"));
    try testing.expectEqualStrings(BELOWOUT_0_1000, try str(row, "reject-details"));
}

test "tests_zero_input_conservation sendrawtransaction: a value-0 coin spent to 1,000 sats is rejected and not admitted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, 0, 1_000);
    const resp = try sendRaw(a, r);
    const err = try rpcError(resp);
    // RPC_TRANSACTION_REJECTED (-26): Core's TransactionError::MEMPOOL_REJECTED,
    // message = TxValidationState::ToString.
    try testing.expectEqual(@as(i64, -26), err.get("code").?.integer);
    try testing.expectEqualStrings(BELOWOUT_0_1000, err.get("message").?.string);
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_zero_input_conservation package path: a value-0 coin spent to 1,000 sats is refused even at a high package feerate" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, 0, 1_000);
    // A CPFP package feerate far above the floor must not stand in for
    // conservation, which Core checks per tx in PreChecks.
    if (r.mp.addTransactionWithPackageRate(r.tx, 1_000.0)) |_| {
        std.debug.print("package path admitted a value-creating tx\n", .{});
        return error.TestExpectedError;
    } else |err| {
        try testing.expectEqualStrings("InputsBelowOutputs", @errorName(err));
    }
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_zero_input_conservation testmempoolaccept: a value-0 coin spent to a value-0 OP_RETURN pays no fee: min relay fee not met" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const row = try testAccept(a, try rig(a, 0, 0));
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("min relay fee not met", try str(row, "reject-reason"));
}

test "tests_zero_input_conservation sendrawtransaction: a zero-fee spend of a value-0 coin is not admitted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, 0, 0);
    const err = try rpcError(try sendRaw(a, r));
    try testing.expectEqual(@as(i64, -26), err.get("code").?.integer);
    try testing.expectEqual(@as(usize, 0), r.mp.entries.count());
}

test "tests_zero_input_conservation testmempoolaccept: a funded coin spent above its value is bad-txns-in-belowout, as Core" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const row = try testAccept(a, try rig(a, 50_000, 60_000));
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("bad-txns-in-belowout", try str(row, "reject-reason"));
    try testing.expectEqualStrings("bad-txns-in-belowout, value in (0.0005) < value out (0.0006)", try str(row, "reject-details"));
}

test "tests_zero_input_conservation control: a funded coin paying a fee is allowed and sent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a, 50_000, 40_000);
    const row = try testAccept(a, r);
    try testing.expect(row.get("allowed").?.bool);
    const resp = try sendRaw(a, r);
    try testing.expect(resp.get("result").? == .string);
    try testing.expectEqual(@as(usize, 1), r.mp.entries.count());
}

test "tests_zero_input_conservation control: value in == value out exactly is not below-out, only short of the fee floor" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const row = try testAccept(a, try rig(a, 50_000, 50_000));
    try testing.expect(!row.get("allowed").?.bool);
    try testing.expectEqualStrings("min relay fee not met", try str(row, "reject-reason"));
}
