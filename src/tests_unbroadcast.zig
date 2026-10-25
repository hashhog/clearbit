//! Unbroadcast set (Core CTxMemPool::m_unbroadcast_txids, txmempool.cpp
//! AddUnbroadcastTx / RemoveUnbroadcastTx; rpc/mempool.cpp entryToJSON and
//! MempoolInfoToJSON report it).

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const mempool_mod = @import("mempool.zig");
const Mempool = mempool_mod.Mempool;

const p2wpkh_script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;

fn mkTx(comptime prev: u8) types.Transaction {
    const input = comptime types.TxIn{
        .previous_output = .{ .hash = [_]u8{prev} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const out = comptime types.TxOut{ .value = 100000, .script_pubkey = &p2wpkh_script };
    return comptime .{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{out},
        .lock_time = 0,
    };
}

test "unbroadcast: starts empty, add requires pool membership" {
    var pool = Mempool.init(null, null, std.testing.allocator);
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), pool.unbroadcastCount());

    const tx = mkTx(0x11);
    const txid = try crypto.computeTxid(&tx, std.testing.allocator);
    pool.addUnbroadcastTx(txid); // not in pool: Core ignores it
    try std.testing.expectEqual(@as(usize, 0), pool.unbroadcastCount());

    try pool.addTransaction(tx);
    try std.testing.expect(!pool.isUnbroadcastTx(txid)); // accepted from a peer
    pool.addUnbroadcastTx(txid);
    try std.testing.expect(pool.isUnbroadcastTx(txid));
    try std.testing.expectEqual(@as(usize, 1), pool.unbroadcastCount());
}

test "unbroadcast: getdata service clears the entry" {
    var pool = Mempool.init(null, null, std.testing.allocator);
    defer pool.deinit();
    const tx = mkTx(0x12);
    const txid = try crypto.computeTxid(&tx, std.testing.allocator);
    try pool.addTransaction(tx);
    pool.addUnbroadcastTx(txid);
    pool.removeUnbroadcastTx(txid);
    try std.testing.expect(!pool.isUnbroadcastTx(txid));
    try std.testing.expectEqual(@as(usize, 0), pool.unbroadcastCount());
}

test "unbroadcast: removing the tx from the pool clears the entry" {
    var pool = Mempool.init(null, null, std.testing.allocator);
    defer pool.deinit();
    const tx = mkTx(0x13);
    const txid = try crypto.computeTxid(&tx, std.testing.allocator);
    try pool.addTransaction(tx);
    pool.addUnbroadcastTx(txid);
    pool.removeTransaction(txid);
    try std.testing.expectEqual(@as(usize, 0), pool.unbroadcastCount());
    try std.testing.expect(!pool.isUnbroadcastTx(txid));
}
