//! sendrawtransaction of an accepted replacement returns the txid string.
//!
//! Run via `zig build test-sendrawtx-replacement-txid` (also part of `zig build test`).
//!
//! Core v31.1 rpc/mempool.cpp sendrawtransaction: after BroadcastTransaction
//! succeeds it returns `tx->GetHash().GetHex()`; its RPCResult is
//! `RPCResult::Type::STR_HEX, "", "The transaction hash in hex"` whether or
//! not the tx replaced anything.  clearbit returned an object
//! `{"txid":..., "replaces":[...]}` when the tx evicted conflicts.
//!
//! Ratchet rows: rbf/broadcast/simple-replacement:$, rbf/clusters/submit:$.
//! The txs mirror the harness scenario (scenarios/rbf.py, `simple`).

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

const REDEEM_TRUE = [_]u8{0x51}; // OP_TRUE
const SIG_TRUE = [_]u8{ 0x01, 0x51 };
const PREV = [_]u8{0x42} ** 32;
const PREV2 = [_]u8{0x43} ** 32;

fn p2shTrue(a: std.mem.Allocator) ![]const u8 {
    const h = crypto.hash160(&REDEEM_TRUE);
    const spk = try a.alloc(u8, 23);
    spk[0] = 0xa9;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &h);
    spk[22] = 0x87;
    return spk;
}

/// 1-in-1-out BIP125-signalling spend of `prev`:0 paying `fee`.
fn spend(a: std.mem.Allocator, prev: types.Hash256, fee: i64) !types.Transaction {
    const ins = try a.alloc(types.TxIn, 1);
    ins[0] = .{
        .previous_output = .{ .hash = prev, .index = 0 },
        .script_sig = &SIG_TRUE,
        .sequence = 0xFFFFFFFD,
        .witness = &.{},
    };
    const outs = try a.alloc(types.TxOut, 1);
    outs[0] = .{ .value = COIN_VALUE - fee, .script_pubkey = try p2shTrue(a) };
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

const Rig = struct { mp: *mempool_mod.Mempool, srv: *rpc.RpcServer };

/// A chain holding PREV:0 and PREV2:0 (P2SH(OP_TRUE), not coinbases).
fn rig(a: std.mem.Allocator) !Rig {
    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 800_000;
    cs.best_hash = [_]u8{0xB7} ** 32;
    const out = types.TxOut{ .value = COIN_VALUE, .script_pubkey = try p2shTrue(a) };
    for ([_]types.Hash256{ PREV, PREV2 }) |h| {
        const op = types.OutPoint{ .hash = h, .index = 0 };
        try cs.utxo_set.add(&op, &out, 799_000, false);
    }
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(cs, &consensus.REGTEST, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});
    return .{ .mp = mp, .srv = srv };
}

fn sendRaw(a: std.mem.Allocator, srv: *rpc.RpcServer, tx: *const types.Transaction) !std.json.Parsed(std.json.Value) {
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"{s}\"]}}", .{try hexOf(a, tx)});
    const resp = try srv.dispatch(req);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

test "tests_sendrawtx_replacement_txid an accepted replacement returns the txid string, as Core" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const original = try spend(a, PREV, 1_000);
    const p0 = try sendRaw(a, r.srv, &original);
    try testing.expectEqualStrings(try displayHex(a, try crypto.computeTxid(&original, a)), p0.value.object.get("result").?.string);

    // Core rbf/simple: the same spend paying 5_000 replaces it.
    const replacement = try spend(a, PREV, 5_000);
    const p1 = try sendRaw(a, r.srv, &replacement);
    const result = p1.value.object.get("result").?;
    try testing.expect(result == .string);
    try testing.expectEqualStrings(try displayHex(a, try crypto.computeTxid(&replacement, a)), result.string);

    // The replacement itself still happened: only it is in the pool.
    try testing.expectEqual(@as(usize, 1), r.mp.entries.count());
    try testing.expect(r.mp.entries.get(try crypto.computeTxid(&replacement, a)) != null);
    try testing.expect(r.mp.entries.get(try crypto.computeTxid(&original, a)) == null);
}

test "tests_sendrawtx_replacement_txid control: a tx with no conflict returns the txid string" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const tx = try spend(a, PREV2, 1_000);
    const p = try sendRaw(a, r.srv, &tx);
    try testing.expectEqualStrings(try displayHex(a, try crypto.computeTxid(&tx, a)), p.value.object.get("result").?.string);
}

test "tests_sendrawtx_replacement_txid the replacement still records what it replaced on its pool entry" {
    // submitpackage's replaced-transactions reads MempoolEntry.replaces; the
    // sendrawtransaction result change must not drop that record.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try rig(a);

    const original = try spend(a, PREV, 1_000);
    _ = try sendRaw(a, r.srv, &original);
    const replacement = try spend(a, PREV, 5_000);
    _ = try sendRaw(a, r.srv, &replacement);
    const entry = r.mp.entries.get(try crypto.computeTxid(&replacement, a)).?;
    const rs = entry.replaces.?;
    try testing.expectEqual(@as(usize, 1), rs.len);
    try testing.expectEqualSlices(u8, &(try crypto.computeTxid(&original, a)), &rs[0]);
}
