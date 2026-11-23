//! getdata MSG_TX / MSG_WTX serves a mempool tx only if it was in the mempool
//! before the last tx INV sent to that peer.
//!
//! Core: PeerManagerImpl::FindTxForGetData (net_processing.cpp) calls
//! `m_mempool.info_for_relay(id, tx_relay.m_last_inv_sequence)`, which returns
//! the entry only when `entry_sequence < last_sequence` (txmempool.h). The
//! peer's `m_last_inv_sequence` starts at 1 and is set to
//! `m_mempool.GetSequence()` after each tx INV trickle (SendMessages). A tx
//! re-added from a disconnected block (bypass_limits) gets entry_sequence 0
//! and so is always servable. Anything else answers notfound, so a peer cannot
//! probe the mempool for txs we never announced to it.
//!
//! Every test compiles on the pre-fix tree; the fix-only API
//! (`PeerManager.broadcastTxInv`) sits behind a comptime gate.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const peer_mod = @import("peer.zig");
const mempool_mod = @import("mempool.zig");
const Mempool = mempool_mod.Mempool;
const h = @import("tests_tip_liveness.zig");
const addPeer = h.addPeer;
const sendFrom = h.sendFrom;
const countFrames = h.countFrames;

const has_broadcast_tx_inv = @hasDecl(peer_mod.PeerManager, "broadcastTxInv");

const p2wpkh_script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;

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

const Fixture = struct {
    pool: Mempool,
    pm: peer_mod.PeerManager,

    fn init(self: *Fixture, a: std.mem.Allocator) void {
        self.pool = Mempool.init(null, null, a);
        self.pm = h.initPm(a);
        self.pm.mempool = &self.pool;
    }

    fn deinit(self: *Fixture) void {
        self.pm.deinit();
        self.pool.deinit();
    }
};

const Ids = struct { txid: types.Hash256, wtxid: types.Hash256 };

fn addTx(fx: *Fixture, tx: types.Transaction) !Ids {
    try fx.pool.addTransaction(tx);
    return .{
        .txid = try crypto.computeTxid(&tx, testing.allocator),
        .wtxid = try crypto.computeWtxid(&tx, testing.allocator),
    };
}

const Answer = struct { tx: usize, notfound: usize };

/// `remote` asks for one tx; count the tx / notfound frames it gets back.
fn ask(fx: *Fixture, remote: std.posix.fd_t, inv_type: p2p.InvType, hash: types.Hash256) !Answer {
    var inv = [_]p2p.InvVector{.{ .inv_type = inv_type, .hash = hash }};
    try sendFrom(remote, .{ .getdata = .{ .inventory = &inv } });
    try fx.pm.processAllMessages();
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    const tx = try countFrames(remote, &buf, "tx", null);
    return .{ .tx = tx, .notfound = try countFrames(remote, &buf, "notfound", null) };
}

/// Drop whatever the node has sent to `remote` so far (the announcement inv).
fn discard(remote: std.posix.fd_t) !void {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    _ = try countFrames(remote, &buf, "inv", null);
}

test "getdata_tx_announced: MSG_TX for a mempool tx never announced to the peer gets notfound" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    const ids = try addTx(&fx, mkTx(0x21));
    const p = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 1 }, false);
    defer std.posix.close(p.remote);

    const got = try ask(&fx, p.remote, .msg_tx, ids.txid);
    try testing.expectEqual(@as(usize, 0), got.tx);
    try testing.expectEqual(@as(usize, 1), got.notfound);
}

test "getdata_tx_announced: MSG_WTX and MSG_WITNESS_TX for an unannounced mempool tx get notfound" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    const ids = try addTx(&fx, mkTx(0x22));
    const p = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 2 }, false);
    defer std.posix.close(p.remote);

    const by_wtxid = try ask(&fx, p.remote, .msg_wtx, ids.wtxid);
    try testing.expectEqual(@as(usize, 0), by_wtxid.tx);
    try testing.expectEqual(@as(usize, 1), by_wtxid.notfound);
    const witness = try ask(&fx, p.remote, .msg_witness_tx, ids.txid);
    try testing.expectEqual(@as(usize, 0), witness.tx);
    try testing.expectEqual(@as(usize, 1), witness.notfound);
}

test "getdata_tx_announced: a tx that entered the mempool after the last inv to the peer gets notfound" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    const a_ids = try addTx(&fx, mkTx(0x23));
    const p = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 3 }, false);
    defer std.posix.close(p.remote);
    // Announce what the pool holds now (A) to P.
    try peer_mod.sendMempoolInventory(p.peer, &fx.pool, testing.allocator);
    try discard(p.remote);
    // B arrives after that inv and is not announced.
    const b_ids = try addTx(&fx, mkTx(0x24));

    const b = try ask(&fx, p.remote, .msg_tx, b_ids.txid);
    try testing.expectEqual(@as(usize, 0), b.tx);
    try testing.expectEqual(@as(usize, 1), b.notfound);
    // Control: A was announced, so it is still served.
    const a = try ask(&fx, p.remote, .msg_tx, a_ids.txid);
    try testing.expectEqual(@as(usize, 1), a.tx);
    try testing.expectEqual(@as(usize, 0), a.notfound);
}

test "getdata_tx_announced: an announcement to one peer does not open the tx to another" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    const ids = try addTx(&fx, mkTx(0x25));
    const p = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 4 }, false);
    defer std.posix.close(p.remote);
    const q = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 5 }, false);
    defer std.posix.close(q.remote);
    try peer_mod.sendMempoolInventory(p.peer, &fx.pool, testing.allocator);
    try discard(p.remote);

    const at_q = try ask(&fx, q.remote, .msg_wtx, ids.wtxid);
    try testing.expectEqual(@as(usize, 0), at_q.tx);
    try testing.expectEqual(@as(usize, 1), at_q.notfound);
    const at_p = try ask(&fx, p.remote, .msg_wtx, ids.wtxid);
    try testing.expectEqual(@as(usize, 1), at_p.tx);
    try testing.expectEqual(@as(usize, 0), at_p.notfound);
}

test "getdata_tx_announced control: a tx announced by mempool inv is served by txid and by wtxid" {
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    const ids = try addTx(&fx, mkTx(0x26));
    const p = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 6 }, false);
    defer std.posix.close(p.remote);
    try peer_mod.sendMempoolInventory(p.peer, &fx.pool, testing.allocator);
    try discard(p.remote);

    const by_txid = try ask(&fx, p.remote, .msg_tx, ids.txid);
    try testing.expectEqual(@as(usize, 1), by_txid.tx);
    const by_wtxid = try ask(&fx, p.remote, .msg_wtx, ids.wtxid);
    try testing.expectEqual(@as(usize, 1), by_wtxid.tx);
    try testing.expectEqual(@as(usize, 0), by_txid.notfound + by_wtxid.notfound);
}

test "getdata_tx_announced control: a tx re-added from a disconnected block (bypass_limits) is served unannounced" {
    // Core gives such entries entry_sequence 0 (validation.cpp PreChecks), so
    // info_for_relay serves them to every peer.
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    fx.pool.bypass_limits = true;
    const ids = try addTx(&fx, mkTx(0x27));
    fx.pool.bypass_limits = false;
    const p = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 7 }, false);
    defer std.posix.close(p.remote);

    const got = try ask(&fx, p.remote, .msg_tx, ids.txid);
    try testing.expectEqual(@as(usize, 1), got.tx);
    try testing.expectEqual(@as(usize, 0), got.notfound);
}

test "getdata_tx_announced: the RPC broadcast inv (broadcastTxInv) opens the tx to the peers it reached" {
    if (!has_broadcast_tx_inv) return error.SkipZigTest;
    var fx: Fixture = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();
    const ids = try addTx(&fx, mkTx(0x28));
    const p = try addPeer(&fx.pm, testing.allocator, .{ 8, 8, 4, 8 }, false);
    defer std.posix.close(p.remote);
    const inv = [_]p2p.InvVector{.{ .inv_type = .msg_witness_tx, .hash = ids.txid }};
    const msg = p2p.Message{ .inv = .{ .inventory = &inv } };
    fx.pm.broadcastTxInv(&msg);
    try discard(p.remote);

    const got = try ask(&fx, p.remote, .msg_tx, ids.txid);
    try testing.expectEqual(@as(usize, 1), got.tx);
    try testing.expectEqual(@as(usize, 0), got.notfound);
}
