//! getchaintips lists headers-only tips: headers accepted through
//! submitheader or a P2P `headers` message whose blocks never arrived.
//!
//! Core (validation.cpp AcceptBlockHeader) adds every accepted header to
//! m_block_index; rpc/blockchain.cpp getchaintips walks m_block_index, so a
//! header with no child is a tip, "headers-only" while it or an ancestor has
//! no data (BLOCK_HAVE_DATA unset).  The index is on disk, so the tip is
//! still listed after a restart (LoadBlockIndex).
//!
//! Same shapes as the core-regtest rows
//! `warden_invalidated_submit/{headers-only,restart,p2p-header}/tips:*`:
//! two headers past the tip (branchlen 2) and a P2P header off the tip.
//!
//! A "restart" reopens the ChainState on the same database and builds a
//! fresh ChainManager, PeerManager and RpcServer, as main.zig does at boot.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const validation = @import("validation.zig");
const rpc = @import("rpc.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");

const params = &consensus.REGTEST;

const Blk = struct { block: types.Block, hash: types.Hash256 };

fn finish(txs: []types.Transaction, prev: types.Hash256, height: u32, tag: u8, allocator: std.mem.Allocator) !Blk {
    const ids = try allocator.alloc(types.Hash256, txs.len);
    for (txs, 0..) |*tx, i| ids[i] = try crypto.computeTxid(tx, allocator);
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeMerkleRoot(ids, allocator),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

fn coinbase(allocator: std.mem.Allocator, height: u32, value: i64, tag: u8) !types.Transaction {
    std.debug.assert(height >= 1 and height <= 16);
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = try allocator.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag }),
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = value, .script_pubkey = try allocator.dupe(u8, &[_]u8{0x51}) };
    return .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
}

/// Coinbase-only block paying the subsidy plus `overpay` sat.
fn mine(allocator: std.mem.Allocator, prev: types.Hash256, height: u32, overpay: i64, tag: u8) !Blk {
    const txs = try allocator.alloc(types.Transaction, 1);
    txs[0] = try coinbase(allocator, height, 5_000_000_000 + overpay, tag);
    return finish(txs, prev, height, tag, allocator);
}

const Node = struct {
    allocator: std.mem.Allocator,
    db: *storage.Database,
    cs: *storage.ChainState,
    cm: *validation.ChainManager,
    pm: *peer_mod.PeerManager,
    mp: *mempool_mod.Mempool,
    srv: *rpc.RpcServer,

    fn boot(allocator: std.mem.Allocator, db: *storage.Database) !Node {
        const cs = try allocator.create(storage.ChainState);
        cs.* = storage.ChainState.init(db, 64, allocator);
        cs.wireUtxoParent();
        cs.setNetworkParams(params);
        cs.best_hash = params.genesis_hash;
        cs.initGenesisTimestamp(params.genesis_header.timestamp);
        cs.initGenesisRetarget(params.genesis_header.timestamp, params.genesis_header.bits);
        cs.seedGenesisTotalWork(params.genesis_header.bits);
        if (try db.get(storage.CF_DEFAULT, "chain_tip")) |data| {
            defer allocator.free(data);
            if (data.len == 36) {
                @memcpy(&cs.best_hash, data[0..32]);
                cs.best_height = std.mem.readInt(u32, data[32..36], .little);
                cs.restoreTotalWork(params);
            }
        }
        const cm = try allocator.create(validation.ChainManager);
        cm.* = validation.ChainManager.init(cs, null, allocator);
        try cm.loadGenesis(params);
        const pm = try allocator.create(peer_mod.PeerManager);
        pm.* = peer_mod.PeerManager.init(allocator, params);
        pm.chain_state = cs;
        const mp = try allocator.create(mempool_mod.Mempool);
        mp.* = mempool_mod.Mempool.init(null, null, allocator);
        const srv = try allocator.create(rpc.RpcServer);
        srv.* = rpc.RpcServer.init(allocator, cs, mp, pm, params, .{});
        srv.setChainManager(cm);
        return .{ .allocator = allocator, .db = db, .cs = cs, .cm = cm, .pm = pm, .mp = mp, .srv = srv };
    }

    fn shutdown(self: *Node) void {
        self.cs.flush() catch {};
        self.srv.deinit();
        self.allocator.destroy(self.srv);
        self.mp.deinit();
        self.allocator.destroy(self.mp);
        self.pm.deinit();
        self.allocator.destroy(self.pm);
        self.cm.deinit();
        self.allocator.destroy(self.cm);
        self.cs.deinit();
        self.allocator.destroy(self.cs);
    }

    fn restart(self: *Node) !void {
        self.shutdown();
        self.* = try Node.boot(self.allocator, self.db);
    }

    /// The `result` of an RPC call with one string param, as JSON text.
    fn call(self: *Node, buf: []u8, method: []const u8, arg: []const u8) ![]const u8 {
        const allocator = testing.allocator;
        const req = try std.fmt.allocPrint(allocator, "{{\"id\":1,\"method\":\"{s}\",\"params\":[\"{s}\"]}}", .{ method, arg });
        defer allocator.free(req);
        const resp = try self.srv.dispatch(req);
        defer allocator.free(resp);
        var p = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
        defer p.deinit();
        const v = p.value.object.get("result") orelse .null;
        var fbs = std.io.fixedBufferStream(buf);
        if (v == .null) {
            if (p.value.object.get("error")) |e| if (e != .null) {
                try std.json.stringify(e, .{}, fbs.writer());
                return fbs.getWritten();
            };
        }
        try std.json.stringify(v, .{}, fbs.writer());
        return fbs.getWritten();
    }

    fn submit(self: *Node, b: *const Blk, want: []const u8) !void {
        const allocator = testing.allocator;
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try serialize.writeBlock(&w, &b.block);
        const hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(w.list.items)});
        defer allocator.free(hex);
        var buf: [512]u8 = undefined;
        const got = try self.call(&buf, "submitblock", hex);
        if (!std.mem.eql(u8, got, want)) {
            std.debug.print("submitblock: got {s}, want {s}\n", .{ got, want });
            return error.TestUnexpectedResult;
        }
    }

    fn reconsider(self: *Node, hash: types.Hash256) ![]const u8 {
        const S = struct {
            var buf: [512]u8 = undefined;
        };
        const id = hashHex(hash);
        return self.call(&S.buf, "reconsiderblock", &id);
    }

    fn expectTip(self: *Node, want: *const Blk, height: u32) !void {
        try testing.expectEqual(height, self.cs.best_height);
        try testing.expectEqualSlices(u8, &want.hash, &self.cs.best_hash);
    }

    /// getchaintips as "<hash8> <height> <branchlen> <status>" lines,
    /// sorted (Core's tips are a set keyed by hash).
    fn tips(self: *Node, arena: std.mem.Allocator) ![]const []const u8 {
        const allocator = testing.allocator;
        const resp = try self.srv.dispatch("{\"id\":1,\"method\":\"getchaintips\",\"params\":[]}");
        defer allocator.free(resp);
        var p = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
        defer p.deinit();
        var out = std.ArrayList([]const u8).init(arena);
        for (p.value.object.get("result").?.array.items) |t| {
            try out.append(try std.fmt.allocPrint(arena, "{s} {d} {d} {s}", .{
                t.object.get("hash").?.string[0..8],
                t.object.get("height").?.integer,
                t.object.get("branchlen").?.integer,
                t.object.get("status").?.string,
            }));
        }
        std.mem.sort([]const u8, out.items, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);
        return out.items;
    }

    fn expectTips(self: *Node, arena: std.mem.Allocator, want: []const []const u8) !void {
        const got = try self.tips(arena);
        const sorted = try arena.dupe([]const u8, want);
        std.mem.sort([]const u8, sorted, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);
        if (got.len != sorted.len) return reportTips(got, sorted);
        for (got, sorted) |g, w| if (!std.mem.eql(u8, g, w)) return reportTips(got, sorted);
    }
};

fn reportTips(got: []const []const u8, want: []const []const u8) error{TestUnexpectedResult} {
    std.debug.print("getchaintips:\n  got:\n", .{});
    for (got) |g| std.debug.print("    {s}\n", .{g});
    std.debug.print("  want:\n", .{});
    for (want) |w| std.debug.print("    {s}\n", .{w});
    return error.TestUnexpectedResult;
}

fn hashHex(hash: types.Hash256) [64]u8 {
    var hex: [64]u8 = undefined;
    for (0..32) |i| _ = std.fmt.bufPrint(hex[i * 2 ..][0..2], "{x:0>2}", .{hash[31 - i]}) catch unreachable;
    return hex;
}

fn row(arena: std.mem.Allocator, b: *const Blk, height: u32, branchlen: u32, status: []const u8) ![]const u8 {
    const h = hashHex(b.hash);
    return std.fmt.allocPrint(arena, "{s} {d} {d} {s}", .{ h[0..8], height, branchlen, status });
}

const Fixture = struct {
    tmp: testing.TmpDir,
    path: []u8,
    db: *storage.Database,
    arena: std.heap.ArenaAllocator,

    fn init() !Fixture {
        const allocator = testing.allocator;
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const path = try tmp.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(path);
        const db = try allocator.create(storage.Database);
        db.* = try storage.Database.open(path, 64, allocator);
        return .{ .tmp = tmp, .path = path, .db = db, .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    fn deinit(self: *Fixture) void {
        const allocator = testing.allocator;
        self.arena.deinit();
        self.db.close();
        allocator.destroy(self.db);
        allocator.free(self.path);
        self.tmp.cleanup();
    }
};

fn headerHex(b: *const Blk) ![160]u8 {
    var w = serialize.Writer.init(testing.allocator);
    defer w.deinit();
    try serialize.writeBlockHeader(&w, &b.block.header);
    var hex: [160]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{}", .{std.fmt.fmtSliceHexLower(w.list.items)});
    return hex;
}

fn submitHeader(node: *Node, b: *const Blk, want: []const u8) !void {
    var buf: [512]u8 = undefined;
    const hex = try headerHex(b);
    const got = try node.call(&buf, "submitheader", &hex);
    if (!std.mem.eql(u8, got, want)) {
        std.debug.print("submitheader: got {s}, want {s}\n", .{ got, want });
        return error.TestUnexpectedResult;
    }
}

// warden_invalidated_submit/headers-only + restart: two headers past the
// tip are one headers-only tip of branchlen 2, before and after a restart.
test "headers_only_tips: submitheader past the tip is a headers-only tip, durably" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const a1 = try mine(a, params.genesis_hash, 1, 0, 0xA1);
    const h2 = try mine(a, a1.hash, 2, 0, 0xA2);
    const h3 = try mine(a, h2.hash, 3, 0, 0xA3);

    try node.submit(&a1, "null");
    try submitHeader(&node, &h2, "null");
    try submitHeader(&node, &h3, "null");
    try node.expectTip(&a1, 1);
    try node.expectTips(a, &.{ try row(a, &a1, 1, 0, "active"), try row(a, &h3, 3, 2, "headers-only") });

    try node.restart();
    try node.expectTip(&a1, 1);
    try node.expectTips(a, &.{ try row(a, &a1, 1, 0, "active"), try row(a, &h3, 3, 2, "headers-only") });

    // Headers-only -> connected control: once the blocks arrive and connect
    // the branch is the active chain and no other tip is left.
    try node.submit(&h2, "null");
    try node.expectTips(a, &.{ try row(a, &h2, 2, 0, "active"), try row(a, &h3, 3, 1, "headers-only") });
    try node.submit(&h3, "null");
    try node.expectTip(&h3, 3);
    try node.expectTips(a, &.{try row(a, &h3, 3, 0, "active")});
}

// warden_invalidated_submit/p2p-header: a header from a P2P `headers`
// message (PeerManager.insertHeader, the store the handler uses) off the
// tip is a headers-only tip next to a submitheader branch.
test "headers_only_tips: a P2P header beside a submitheader branch is its own headers-only tip" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const a1 = try mine(a, params.genesis_hash, 1, 0, 0xA1);
    const h2 = try mine(a, a1.hash, 2, 0, 0xA2);
    const h3 = try mine(a, h2.hash, 3, 0, 0xA3);
    const p2 = try mine(a, a1.hash, 2, 0, 0xB2);

    try node.submit(&a1, "null");
    try submitHeader(&node, &h2, "null");
    try submitHeader(&node, &h3, "null");
    _ = (try node.pm.insertHeader(&p2.block.header, &p2.hash)) orelse return error.TestUnexpectedResult;
    try node.expectTips(a, &.{
        try row(a, &a1, 1, 0, "active"),
        try row(a, &h3, 3, 2, "headers-only"),
        try row(a, &p2, 2, 1, "headers-only"),
    });

    try node.restart();
    try node.expectTips(a, &.{
        try row(a, &a1, 1, 0, "active"),
        try row(a, &h3, 3, 2, "headers-only"),
        try row(a, &p2, 2, 1, "headers-only"),
    });
}

// Negative controls: a rejected header is not a tip (Core stores nothing
// when AcceptBlockHeader fails: bad-prevblk on a failed parent,
// time-too-old), and a header on a failed block's branch is "invalid", not
// "headers-only" (Core: BLOCK_FAILED_CHILD outranks missing data).
test "headers_only_tips: rejected headers are not tips; a header under an invalidated block is invalid" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const a = fx.arena.allocator();
    var node = try Node.boot(testing.allocator, fx.db);
    defer node.shutdown();

    const a1 = try mine(a, params.genesis_hash, 1, 0, 0xA1);
    const a2 = try mine(a, a1.hash, 2, 0, 0xA2);
    const h3 = try mine(a, a2.hash, 3, 0, 0xA3);
    try node.submit(&a1, "null");
    try node.submit(&a2, "null");
    try submitHeader(&node, &h3, "null");

    var old = try mine(a, a2.hash, 3, 0, 0xD3);
    old.block.header.timestamp = params.genesis_header.timestamp - 1;
    while (!consensus.validateProofOfWork(&old.block.header, params)) old.block.header.nonce +%= 1;
    old.hash = crypto.computeBlockHash(&old.block.header);
    try submitHeader(&node, &old, "{\"code\":-25,\"message\":\"time-too-old\"}");
    try node.expectTips(a, &.{ try row(a, &a2, 2, 0, "active"), try row(a, &h3, 3, 1, "headers-only") });

    var buf: [512]u8 = undefined;
    const a2_id = hashHex(a2.hash);
    _ = try node.call(&buf, "invalidateblock", &a2_id);
    try node.expectTip(&a1, 1);
    try node.expectTips(a, &.{ try row(a, &a1, 1, 0, "active"), try row(a, &h3, 3, 2, "invalid") });

    const under = try mine(a, a2.hash, 3, 0, 0xC3);
    try submitHeader(&node, &under, "{\"code\":-25,\"message\":\"bad-prevblk\"}");
    try node.expectTips(a, &.{ try row(a, &a1, 1, 0, "active"), try row(a, &h3, 3, 2, "invalid") });
}
