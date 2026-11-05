//! getrawtransaction verbosity 2 adds `fee` and each vin's `prevout` from the
//! block's undo data, as Core's TxToUniv SHOW_DETAILS_AND_PREVOUT does.
//!
//! Run via `zig build test-prevout`.
//!
//! Ratchet rows (Core has the field, node was "<missing>"):
//!   operator/getrawtransaction/confirmed-a-v2:fee, :vin[0].prevout
//!   operator/getrawtransaction/confirmed-b-v2:fee, :vin[0].prevout
//!   operator/getblock/bad-verbosity:tx[1].vin[0].prevout (verbosity 9 => 3)
//!   operator/getblock/bad-verbosity:tx[2].vin[0].prevout
//!
//! The wire shape is core_io.cpp TxToUniv: prevout = {generated, height,
//! value, scriptPubKey}, written after txinwitness and before sequence.

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

const BLOCK_HASH: types.Hash256 = [_]u8{0xAB} ** 32;
const BLOCK_HEX = "ab" ** 32;
const SPK = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x75} ** 20; // P2WPKH

fn hexOf(a: std.mem.Allocator, h: types.Hash256) ![]u8 {
    var out = try a.alloc(u8, 64);
    for (0..32) |i| _ = try std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{h[31 - i]});
    return out;
}

/// A regtest server over a tmp RocksDB holding one block (coinbase + one spend
/// of a 50 BTC coinbase output, paying 49.9999 BTC: fee 10_000 sat) and its undo.
const Fixture = struct {
    txid_hex: []u8,
    srv: *rpc.RpcServer,
    db: *storage.Database,
};

fn setup(a: std.mem.Allocator, path: []const u8) !Fixture {
    const db = try a.create(storage.Database);
    db.* = try storage.Database.open(path, 64, a);

    const cb_in = [_]types.TxIn{.{ .previous_output = types.OutPoint.COINBASE, .script_sig = &[_]u8{ 0x01, 0x01 }, .sequence = 0xFFFFFFFF, .witness = &[_][]const u8{} }};
    const cb_out = [_]types.TxOut{.{ .value = 5_000_000_000, .script_pubkey = &SPK }};
    const spend_in = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{&[_]u8{0x30}},
    }};
    const spend_out = [_]types.TxOut{.{ .value = 4_999_990_000, .script_pubkey = &SPK }};
    const txs = [_]types.Transaction{
        .{ .version = 2, .inputs = &cb_in, .outputs = &cb_out, .lock_time = 0 },
        .{ .version = 2, .inputs = &spend_in, .outputs = &spend_out, .lock_time = 0 },
    };
    const block = types.Block{
        .header = .{ .version = 1, .prev_block = [_]u8{0} ** 32, .merkle_root = [_]u8{0} ** 32, .timestamp = 1_700_000_000, .bits = 0x207fffff, .nonce = 0 },
        .transactions = &txs,
    };
    var w = serialize.Writer.init(a);
    try serialize.writeBlock(&w, &block);
    try db.put(storage.CF_BLOCKS, &BLOCK_HASH, w.getWritten());
    var idx: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx, 7, .little);
    try db.put(storage.CF_BLOCK_INDEX, &BLOCK_HASH, &idx);

    var prev = [_]storage.TxUndo.TxOut{.{ .value = 5_000_000_000, .script_pubkey = try a.dupe(u8, &SPK), .height = 3, .is_coinbase = true }};
    var tx_undo = [_]storage.TxUndo{.{ .prev_outputs = &prev }};
    const undo = storage.BlockUndoData{ .tx_undo = &tx_undo };
    try db.put(storage.CF_BLOCK_UNDO, &BLOCK_HASH, try undo.toBytes(a));

    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(db, 64, a);
    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(null, null, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});

    const txid = crypto.computeTxidStreaming(&txs[1]);
    return .{ .txid_hex = try hexOf(a, txid), .srv = srv, .db = db };
}

fn getraw(a: std.mem.Allocator, f: Fixture, verbosity: u8) !std.json.Parsed(std.json.Value) {
    const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"getrawtransaction\",\"params\":[\"{s}\",{d},\"" ++ BLOCK_HEX ++ "\"]}}", .{ f.txid_hex, verbosity });
    const resp = try f.srv.dispatch(req);
    return std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
}

test "tests_prevout getrawtransaction verbosity 2 has fee and vin prevout" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    const f = try setup(a, path);
    defer f.db.close();

    const p = try getraw(a, f, 2);
    const res = p.value.object.get("result").?.object;
    // Explicit presence checks: this builds ReleaseFast, where `.?` on null is
    // undefined behaviour rather than a test failure.
    try testing.expect(res.get("fee") != null);
    try testing.expectApproxEqAbs(@as(f64, 0.0001), res.get("fee").?.float, 1e-12);
    const vin0 = res.get("vin").?.array.items[0].object;
    try testing.expect(vin0.get("prevout") != null);
    const po = vin0.get("prevout").?.object;
    try testing.expectEqual(true, po.get("generated").?.bool);
    try testing.expectEqual(@as(i64, 3), po.get("height").?.integer);
    try testing.expectApproxEqAbs(@as(f64, 50.0), po.get("value").?.float, 1e-12);
    const spk = po.get("scriptPubKey").?.object;
    try testing.expectEqualStrings("0014" ++ "75" ** 20, spk.get("hex").?.string);
    // Core key order: prevout sits between txinwitness and sequence.
    const raw = try f.srv.dispatch(try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"getrawtransaction\",\"params\":[\"{s}\",2,\"" ++ BLOCK_HEX ++ "\"]}}", .{f.txid_hex}));
    const w_at = std.mem.indexOf(u8, raw, "\"txinwitness\"").?;
    const p_at = std.mem.indexOf(u8, raw, "\"prevout\"").?;
    const s_at = std.mem.indexOf(u8, raw, "\"sequence\"").?;
    try testing.expect(w_at < p_at and p_at < s_at);
}

test "tests_prevout getrawtransaction verbosity 1 control has neither fee nor prevout" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    const f = try setup(a, path);
    defer f.db.close();

    const p = try getraw(a, f, 1);
    const res = p.value.object.get("result").?.object;
    // The control must have found the tx, or "no fee" proves nothing.
    try testing.expect(res.get("txid") != null);
    try testing.expect(res.get("fee") == null);
    try testing.expect(res.get("vin").?.array.items[0].object.get("prevout") == null);
}
