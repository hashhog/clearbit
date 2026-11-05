//! initialblockdownload on regtest follows Core (validation.cpp
//! IsInitialBlockDownload): a tip older than 24h is IBD, with no regtest
//! shortcut.
//!
//! Run via `zig build test-ibd-regtest`.
//!
//! Ratchet rows (Core true, node false before the fix):
//!   chain/info/clean:initialblockdownload
//!   chain/info/final:initialblockdownload
//!   chain/invalidate/info:initialblockdownload

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const validation = @import("validation.zig");
const types = @import("types.zig");

fn ibdFlag(a: std.mem.Allocator, srv: *rpc.RpcServer) !bool {
    const resp = try srv.dispatch("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}");
    defer a.free(resp);
    if (std.mem.indexOf(u8, resp, "\"initialblockdownload\":true") != null) return true;
    if (std.mem.indexOf(u8, resp, "\"initialblockdownload\":false") != null) return false;
    return error.FieldMissing;
}

fn newServer(a: std.mem.Allocator, cs: *storage.ChainState, mp: *mempool_mod.Mempool, pm: *peer_mod.PeerManager) !*rpc.RpcServer {
    const srv = try a.create(rpc.RpcServer);
    srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});
    return srv;
}

test "tests_ibd_regtest stale regtest tip is in initial block download" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 100;
    cs.best_hash = [_]u8{0x33} ** 32;
    cs.total_work = [_]u8{0xFF} ** 32;

    var cm = validation.ChainManager.init(cs, null, a);
    const tip = try a.create(validation.BlockIndexEntry);
    tip.* = .{
        .hash = [_]u8{0x33} ** 32,
        .header = blk: {
            var h = std.mem.zeroes(types.BlockHeader);
            h.timestamp = @intCast(std.time.timestamp() - 30 * 24 * 60 * 60);
            break :blk h;
        },
        .height = 100,
        .status = .{},
        .chain_work = [_]u8{0xFF} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try cm.block_index.put(tip.hash, tip);
    cm.active_tip = tip;

    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(null, null, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try newServer(a, cs, mp, pm);
    srv.setChainManager(&cm);

    try testing.expect(try ibdFlag(a, srv));
}

test "tests_ibd_regtest fresh regtest tip control leaves initial block download" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cs = try a.create(storage.ChainState);
    cs.* = storage.ChainState.init(null, 64, a);
    cs.best_height = 100;
    cs.best_hash = [_]u8{0x33} ** 32;
    cs.total_work = [_]u8{0xFF} ** 32;

    var cm = validation.ChainManager.init(cs, null, a);
    const tip = try a.create(validation.BlockIndexEntry);
    tip.* = .{
        .hash = [_]u8{0x33} ** 32,
        .header = blk: {
            var h = std.mem.zeroes(types.BlockHeader);
            h.timestamp = @intCast(std.time.timestamp());
            break :blk h;
        },
        .height = 100,
        .status = .{},
        .chain_work = [_]u8{0xFF} ** 32,
        .sequence_id = 0,
        .parent = null,
        .file_number = 0,
        .file_offset = 0,
    };
    try cm.block_index.put(tip.hash, tip);
    cm.active_tip = tip;

    const mp = try a.create(mempool_mod.Mempool);
    mp.* = mempool_mod.Mempool.init(null, null, a);
    const pm = try a.create(peer_mod.PeerManager);
    pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
    const srv = try newServer(a, cs, mp, pm);
    srv.setChainManager(&cm);

    try testing.expect(!(try ibdFlag(a, srv)));
}
