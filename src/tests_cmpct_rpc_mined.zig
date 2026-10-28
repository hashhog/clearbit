//! BIP-152 serving for blocks that never went through P2P header sync
//! (submitblock / generate*): they are absent from `header_index`, so a
//! MSG_CMPCT_BLOCK getdata used to be answered with the full block, and
//! `announceBlock` never pushed `cmpctblock` to high-bandwidth peers.
//!
//! Core: ProcessGetBlockData (IsMsgCmpctBlk, depth <= MAX_CMPCTBLOCK_DEPTH) and
//! PeerManagerImpl::NewPoWValidBlock.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");
const peer_mod = @import("peer.zig");
const h = @import("tests_tip_liveness.zig");
const params = h.params;
const addPeer = h.addPeer;
const sendFrom = h.sendFrom;
const countFrames = h.countFrames;

const Fixture = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: peer_mod.PeerManager,

    fn init(self: *Fixture, a: std.mem.Allocator) !void {
        self.a = a;
        self.tmp = testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(a, ".");
        self.db = try storage.Database.open(self.path, 64, a);
        self.cs = storage.ChainState.init(&self.db, 64, a);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(params);
        self.cs.best_hash = params.genesis_hash;
        self.pm = h.initPm(a);
        self.pm.chain_state = &self.cs;
    }

    fn deinit(self: *Fixture) void {
        self.pm.deinit();
        self.cs.deinit();
        self.db.close();
        self.a.free(self.path);
        self.tmp.cleanup();
    }
};

/// A two-transaction block (coinbase + one spend) so the short-id list is non-empty.
const TwoTxBlock = struct {
    ins: [2]types.TxIn,
    outs: [2]types.TxOut,
    txs: [2]types.Transaction,

    fn make(self: *TwoTxBlock, nonce: u32) types.Block {
        const spk = [_]u8{0x51};
        for (&self.ins, 0..) |*i, k| i.* = .{
            .previous_output = .{ .hash = [_]u8{@intCast(0x40 + k)} ** 32, .index = @intCast(k) },
            .script_sig = &[_]u8{ 0x01, 0x01 },
            .sequence = 0xffffffff,
            .witness = &[_][]const u8{},
        };
        for (&self.outs) |*o| o.* = .{ .value = 1000, .script_pubkey = &spk };
        for (&self.txs, 0..) |*t, k| t.* = .{
            .version = 2,
            .inputs = self.ins[k .. k + 1],
            .outputs = self.outs[k .. k + 1],
            .lock_time = 0,
        };
        var hdr = params.genesis_header;
        hdr.nonce = nonce;
        return .{ .header = hdr, .transactions = &self.txs };
    }
};

fn serializeBlock(a: std.mem.Allocator, b: *const types.Block) ![]u8 {
    var w = serialize.Writer.init(a);
    errdefer w.deinit();
    try serialize.writeBlock(&w, b);
    return @constCast(try w.toOwnedSlice());
}

fn requestCmpct(fx: *Fixture, remote: std.posix.fd_t, hash: types.Hash256) !void {
    var inv = [_]p2p.InvVector{.{ .inv_type = .msg_cmpct_block, .hash = hash }};
    try sendFrom(remote, .{ .getdata = .{ .inventory = &inv } });
    try fx.pm.processAllMessages();
}

// Re-read the socket for several commands without losing frames between calls.
const Counts = struct { cmpct: usize, block: usize, headers: usize, inv: usize, notfound: usize };
fn drain(fd: std.posix.fd_t) !Counts {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    var t: usize = 0;
    const cmpct = try countFrames(fd, &buf, "cmpctblock", &t);
    return .{
        .cmpct = cmpct,
        .block = try countFrames(fd, &buf, "block", null),
        .headers = try countFrames(fd, &buf, "headers", null),
        .inv = try countFrames(fd, &buf, "inv", null),
        .notfound = try countFrames(fd, &buf, "notfound", null),
    };
}

test "cmpct_rpc_mined: getdata MSG_CMPCT_BLOCK for a cached block absent from header_index is answered with cmpctblock" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var tb: TwoTxBlock = undefined;
    const blk = tb.make(7);
    const hash = crypto.computeBlockHash(&blk.header);
    const raw = try serializeBlock(a, &blk);
    defer a.free(raw);
    // What generate*/submitblock leave behind: bytes cached, tip moved, no header_index entry.
    fx.pm.cacheMinedBlock(hash, raw);
    fx.cs.best_hash = hash;
    fx.cs.best_height = 101;
    try testing.expect(fx.pm.header_index.get(hash) == null);

    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 8 }, false);
    defer std.posix.close(p.remote);
    try requestCmpct(&fx, p.remote, hash);
    const c = try drain(p.remote);
    try testing.expectEqual(@as(usize, 1), c.cmpct);
    try testing.expectEqual(@as(usize, 0), c.block);
}

test "cmpct_rpc_mined: a block only in CF_BLOCKS + the block index (not the tip, not cached) is answered with cmpctblock" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var tb: TwoTxBlock = undefined;
    const blk = tb.make(8);
    const hash = crypto.computeBlockHash(&blk.header);
    const raw = try serializeBlock(a, &blk);
    defer a.free(raw);
    try fx.db.put(storage.CF_BLOCKS, &hash, raw);
    var rec: [84]u8 = undefined;
    std.mem.writeInt(u32, rec[0..4], 99, .little);
    var hw = serialize.Writer.init(a);
    defer hw.deinit();
    try serialize.writeBlockHeader(&hw, &blk.header);
    @memcpy(rec[4..84], hw.getWritten());
    try fx.db.put(storage.CF_BLOCK_INDEX, &hash, &rec);
    fx.cs.best_height = 101; // depth 2

    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 9 }, false);
    defer std.posix.close(p.remote);
    try requestCmpct(&fx, p.remote, hash);
    const c = try drain(p.remote);
    try testing.expectEqual(@as(usize, 1), c.cmpct);
    try testing.expectEqual(@as(usize, 0), c.block);
}

test "cmpct_rpc_mined control: deeper than MAX_CMPCTBLOCK_DEPTH is still answered with the full block" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var tb: TwoTxBlock = undefined;
    const blk = tb.make(9);
    const hash = crypto.computeBlockHash(&blk.header);
    const raw = try serializeBlock(a, &blk);
    defer a.free(raw);
    fx.pm.cacheMinedBlock(hash, raw);
    var rec: [84]u8 = undefined;
    std.mem.writeInt(u32, rec[0..4], 50, .little);
    var hw = serialize.Writer.init(a);
    defer hw.deinit();
    try serialize.writeBlockHeader(&hw, &blk.header);
    @memcpy(rec[4..84], hw.getWritten());
    try fx.db.put(storage.CF_BLOCK_INDEX, &hash, &rec);
    fx.cs.best_height = 101; // depth 51

    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 10 }, false);
    defer std.posix.close(p.remote);
    try requestCmpct(&fx, p.remote, hash);
    const c = try drain(p.remote);
    try testing.expectEqual(@as(usize, 0), c.cmpct);
    try testing.expectEqual(@as(usize, 1), c.block);
}

test "cmpct_rpc_mined control: an unknown block hash gets no cmpctblock and no full block" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    const p = try addPeer(&fx.pm, a, .{ 8, 8, 8, 11 }, false);
    defer std.posix.close(p.remote);
    try requestCmpct(&fx, p.remote, [_]u8{0xab} ** 32);
    const c = try drain(p.remote);
    try testing.expectEqual(@as(usize, 0), c.cmpct);
    try testing.expectEqual(@as(usize, 0), c.block);
    try testing.expectEqual(@as(usize, 1), c.notfound);
}

test "cmpct_rpc_mined: announceBlock pushes cmpctblock to a high-bandwidth peer and headers/inv to the others" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var tb: TwoTxBlock = undefined;
    const blk = tb.make(10);
    const hash = crypto.computeBlockHash(&blk.header);
    const raw = try serializeBlock(a, &blk);
    defer a.free(raw);
    fx.pm.cacheMinedBlock(hash, raw);

    const hb = try addPeer(&fx.pm, a, .{ 8, 8, 9, 1 }, false);
    defer std.posix.close(hb.remote);
    hb.peer.bip152_provides_cmpctblocks = true;
    hb.peer.bip152_highbandwidth_from = true;
    hb.peer.send_headers = true;
    const lb = try addPeer(&fx.pm, a, .{ 8, 8, 9, 2 }, false); // low-bandwidth cmpct peer
    defer std.posix.close(lb.remote);
    lb.peer.bip152_provides_cmpctblocks = true;
    lb.peer.send_headers = true;
    const legacy = try addPeer(&fx.pm, a, .{ 8, 8, 9, 3 }, false);
    defer std.posix.close(legacy.remote);

    var hdr = blk.header;
    fx.pm.announceBlock(&hdr, &hash);

    const c_hb = try drain(hb.remote);
    try testing.expectEqual(@as(usize, 1), c_hb.cmpct);
    try testing.expectEqual(@as(usize, 0), c_hb.headers);
    try testing.expectEqual(@as(usize, 0), c_hb.inv);
    const c_lb = try drain(lb.remote);
    try testing.expectEqual(@as(usize, 0), c_lb.cmpct);
    try testing.expectEqual(@as(usize, 1), c_lb.headers);
    const c_legacy = try drain(legacy.remote);
    try testing.expectEqual(@as(usize, 0), c_legacy.cmpct);
    try testing.expectEqual(@as(usize, 1), c_legacy.inv);
}

test "cmpct_rpc_mined control: an HB peer is still announced to (headers) when the block body is unavailable" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var tb: TwoTxBlock = undefined;
    const blk = tb.make(11);
    const hash = crypto.computeBlockHash(&blk.header);
    const hb = try addPeer(&fx.pm, a, .{ 8, 8, 9, 4 }, false);
    defer std.posix.close(hb.remote);
    hb.peer.bip152_provides_cmpctblocks = true;
    hb.peer.bip152_highbandwidth_from = true;
    hb.peer.send_headers = true;
    var hdr = blk.header;
    fx.pm.announceBlock(&hdr, &hash);
    const c = try drain(hb.remote);
    try testing.expectEqual(@as(usize, 0), c.cmpct);
    try testing.expectEqual(@as(usize, 1), c.headers);
}

test "cmpct_rpc_mined: announceBlockWithBody serves a block the caller holds in memory" {
    const a = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(a);
    defer fx.deinit();
    var tb: TwoTxBlock = undefined;
    const blk = tb.make(12);
    const hash = crypto.computeBlockHash(&blk.header);
    const hb = try addPeer(&fx.pm, a, .{ 8, 8, 9, 5 }, false);
    defer std.posix.close(hb.remote);
    hb.peer.bip152_provides_cmpctblocks = true;
    hb.peer.bip152_highbandwidth_from = true;
    fx.pm.announceBlockWithBody(&blk.header, &hash, &blk);
    const c = try drain(hb.remote);
    try testing.expectEqual(@as(usize, 1), c.cmpct);
    try testing.expectEqual(@as(usize, 0), c.inv);
}
