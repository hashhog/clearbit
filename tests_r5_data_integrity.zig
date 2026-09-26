//! R5 DATA-INTEGRITY class (QUEUES.md clearbit item 0, measured 2026-09-25).
//!
//! Wrong ANSWERS, not error-code cosmetics:
//!   (1) getchaintxstats txcount 110,707,364 vs Core 1,446,603,828 on live
//!       mainnet, window_tx_count +4,787.  Root causes: the cumulative "X:"
//!       index was a process-wide running counter that (a) resumed from the
//!       genesis seed after a --load-snapshot boot and (b) was never rewound
//!       on disconnect, so each reorg inflated every later count.  Core
//!       (validation.cpp ReceivedBlockTransactions, node/blockstorage.cpp
//!       LoadBlockIndex) derives m_chain_tx_count = pprev + nTx and leaves it
//!       0 (unknown) when the parent is unknown.
//!   (2) getdeploymentinfo / getblockfilter (and getchaintxstats on the
//!       deployed build) with a HASH argument answered -5 "Block not found"
//!       for a block getblockheader returns: they resolved the hash only
//!       through the in-memory ChainManager, which the P2P-sync path never
//!       fills.
//!
//! CONTROL: `zig build test-r5-data-integrity --summary new`

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const crypto = @import("src/crypto.zig");
const serialize = @import("src/serialize.zig");
const types = @import("src/types.zig");
const hb = @import("src/historical_backfill.zig");

fn has(body: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, body, needle) != null;
}

fn hashToHex(hash: *const [32]u8, out: *[64]u8) void {
    const hex = "0123456789abcdef";
    for (0..32) |i| {
        const b = hash[31 - i];
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xf];
    }
}

/// A one-coinbase block at `height` whose hash differs per `salt`.
fn coinbaseBlock(height: u32, salt: u8, prev: types.Hash256, script: *const [22]u8, sig: *[4]u8) types.Block {
    sig.* = .{ 0x03, @truncate(height), salt, 0x00 };
    const S = struct {
        var inputs: [2][1]types.TxIn = undefined;
        var outputs: [2][1]types.TxOut = undefined;
        var txs: [2][1]types.Transaction = undefined;
    };
    const slot: usize = salt & 1;
    S.inputs[slot][0] = .{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xffffffff },
        .script_sig = sig,
        .sequence = 0xffffffff,
        .witness = &.{},
    };
    S.outputs[slot][0] = .{ .value = 5_000_000_000, .script_pubkey = script };
    S.txs[slot][0] = .{ .version = 1, .inputs = &S.inputs[slot], .outputs = &S.outputs[slot], .lock_time = 0 };
    return .{
        .header = .{ .version = 1, .prev_block = prev, .merkle_root = [_]u8{salt} ** 32, .timestamp = height, .bits = 0x207fffff, .nonce = salt },
        .transactions = &S.txs[slot],
    };
}

const DbCs = struct {
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,

    fn init(self: *DbCs, allocator: std.mem.Allocator) !void {
        self.tmp = std.testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(allocator, ".");
        self.db = try storage.Database.open(self.path, 64, allocator);
        self.cs = storage.ChainState.init(&self.db, 64, allocator);
    }
    fn deinit(self: *DbCs, allocator: std.mem.Allocator) void {
        self.cs.deinit();
        self.db.close();
        allocator.free(self.path);
        self.tmp.cleanup();
    }
};

test "r5_data_integrity reorg does not inflate the cumulative tx count" {
    const allocator = testing.allocator;
    var fx: DbCs = undefined;
    try fx.init(allocator);
    defer fx.deinit(allocator);
    fx.cs.seedGenesisTxCount(); // X:0 = 1 (fresh chain)

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;
    var sig_a: [4]u8 = undefined;
    var sig_b: [4]u8 = undefined;
    const genesis = [_]u8{0} ** 32;
    const a = coinbaseBlock(1, 0xa0, genesis, &script, &sig_a);
    const b = coinbaseBlock(1, 0xb1, genesis, &script, &sig_b);
    const ha = [_]u8{0xa0} ** 32;
    const hbh = [_]u8{0xb1} ** 32;

    var undo_a = try fx.cs.connectBlock(&a, &ha, 1);
    defer undo_a.deinit(allocator);
    try testing.expectEqual(@as(?u64, 2), fx.cs.getCumulativeTxCount(1));

    // Reorg: A out, B (also one tx) in at the same height.
    try fx.cs.disconnectBlock(&undo_a, genesis);
    var undo_b = try fx.cs.connectBlock(&b, &hbh, 1);
    defer undo_b.deinit(allocator);
    // Core: m_chain_tx_count(B) = m_chain_tx_count(genesis) + nTx(B) = 2.
    // The old running counter answered 3 (A's tx never rewound).
    try testing.expectEqual(@as(?u64, 2), fx.cs.getCumulativeTxCount(1));
}

test "r5_data_integrity snapshot base without a count leaves descendants unknown" {
    const allocator = testing.allocator;
    var fx: DbCs = undefined;
    try fx.init(allocator);
    defer fx.deinit(allocator);
    // Boot order in main.zig: genesis seed first (best_height is still 0),
    // then the persisted tip (a --load-snapshot base at 10) is loaded.
    fx.cs.seedGenesisTxCount();
    fx.cs.best_height = 10;
    fx.cs.best_hash = [_]u8{0x10} ** 32;
    fx.cs.restoreChainTxCount();

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;
    var sig: [4]u8 = undefined;
    const blk = coinbaseBlock(11, 0x11, fx.cs.best_hash, &script, &sig);
    const h11 = [_]u8{0x11} ** 32;
    var undo = try fx.cs.connectBlock(&blk, &h11, 11);
    defer undo.deinit(allocator);
    // Core: unknown (m_chain_tx_count 0 -> txcount omitted).  The old code
    // answered 2 = genesis seed + this block, presented as a chain total.
    try testing.expectEqual(@as(?u64, null), fx.cs.getCumulativeTxCount(11));
}

test "r5_data_integrity snapshot base with a chainparams count seeds descendants" {
    const allocator = testing.allocator;
    var fx: DbCs = undefined;
    try fx.init(allocator);
    defer fx.deinit(allocator);
    fx.cs.seedGenesisTxCount();
    fx.cs.best_height = 10;
    fx.cs.best_hash = [_]u8{0x10} ** 32;
    fx.cs.putCumulativeTxCount(10, 1_000); // what --load-snapshot now writes
    fx.cs.restoreChainTxCount();

    const script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;
    var sig: [4]u8 = undefined;
    const blk = coinbaseBlock(11, 0x11, fx.cs.best_hash, &script, &sig);
    const h11 = [_]u8{0x11} ** 32;
    var undo = try fx.cs.connectBlock(&blk, &h11, 11);
    defer undo.deinit(allocator);
    try testing.expectEqual(@as(?u64, 1_001), fx.cs.getCumulativeTxCount(11));
}

test "r5_data_integrity 944183 bootstrap count is Core's, not the placeholder" {
    const e = storage.findAssumeUtxoEntryByHeight(&consensus.MAINNET, 944_183) orelse blk: {
        for (consensus.MAINNET.snapshot_bootstrap) |x| {
            if (x.height == 944_183) break :blk x;
        }
        return error.TestUnexpectedResult;
    };
    // Core getchaintxstats txcount at 0000…ced817 (2026-09-25).
    try testing.expectEqual(@as(u64, 1_335_914_531), e.chain_tx_count);
}

// ── RPC fixture: blocks known ONLY through the persisted index (the P2P-sync
//    shape: no ChainManager), 1 coinbase each, bodies stored. ──────────────
const RpcFx = struct {
    base: DbCs,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    server: rpc.RpcServer,
    blocks: []types.Block,
    allocator: std.mem.Allocator,

    fn init(self: *RpcFx, allocator: std.mem.Allocator, poison: bool) !void {
        self.allocator = allocator;
        try self.base.init(allocator);
        const cs = &self.base.cs;
        const params = &consensus.REGTEST;
        self.blocks = try hb.buildRegtestChain(allocator, params, 20);
        hb.seedSnapshotHole(cs, self.blocks, 1, 20); // H: + CF_BLOCK_INDEX 0..20
        var h: u32 = 1;
        while (h <= 20) : (h += 1) {
            var w = serialize.Writer.init(allocator);
            defer w.deinit();
            try serialize.writeBlock(&w, &self.blocks[h]);
            const hash = crypto.computeBlockHash(&self.blocks[h].header);
            cs.putBlockBody(&hash, w.getWritten());
            // The old running counter's shape after a snapshot boot: counts
            // from 1 at the base, inflated by one extra reorg at height 7.
            if (poison) cs.putCumulativeTxCount(h, h + 1 + @as(u64, if (h >= 7) 1 else 0));
        }
        cs.blockfilterindex_enabled = true;
        self.mempool = mempool_mod.Mempool.init(null, null, allocator);
        self.peer_manager = peer_mod.PeerManager.init(allocator, params);
        self.peer_manager.chain_state = cs;
        self.server = rpc.RpcServer.init(allocator, cs, &self.mempool, &self.peer_manager, params, .{});
    }
    fn deinit(self: *RpcFx) void {
        self.server.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        hb.freeRegtestChain(self.allocator, self.blocks);
        self.base.deinit(self.allocator);
    }
    fn call(self: *RpcFx, comptime fmt: []const u8, args: anytype) ![]const u8 {
        var buf: [512]u8 = undefined;
        const req = try std.fmt.bufPrint(&buf, fmt, args);
        return self.server.dispatch(req);
    }
};

test "r5_data_integrity getdeploymentinfo resolves a hash known only to the persisted index" {
    var fx: RpcFx = undefined;
    try fx.init(testing.allocator, false);
    defer fx.deinit();
    var hex: [64]u8 = undefined;
    const h15 = crypto.computeBlockHash(&fx.blocks[15].header);
    hashToHex(&h15, &hex);
    const body = try fx.call("{{\"id\":1,\"method\":\"getdeploymentinfo\",\"params\":[\"{s}\"]}}", .{hex});
    defer testing.allocator.free(body);
    try testing.expect(!has(body, "\"error\":{"));
    try testing.expect(has(body, "\"height\":15"));
    try testing.expect(has(body, &hex));

    const nf = try fx.call("{{\"id\":1,\"method\":\"getdeploymentinfo\",\"params\":[\"{s}\"]}}", .{"0000000000000000000000000000000000000000000000000000000000000001"});
    defer testing.allocator.free(nf);
    try testing.expect(has(nf, "\"code\":-5"));
}

test "r5_data_integrity getblockfilter resolves a hash known only to the persisted index" {
    var fx: RpcFx = undefined;
    try fx.init(testing.allocator, false);
    defer fx.deinit();
    var hex: [64]u8 = undefined;
    const h15 = crypto.computeBlockHash(&fx.blocks[15].header);
    hashToHex(&h15, &hex);
    const body = try fx.call("{{\"id\":1,\"method\":\"getblockfilter\",\"params\":[\"{s}\"]}}", .{hex});
    defer testing.allocator.free(body);
    try testing.expect(!has(body, "\"error\":{"));
    try testing.expect(has(body, "\"filter\":\""));
    try testing.expect(has(body, "\"header\":\""));

    const g = try fx.call("{{\"id\":1,\"method\":\"getblockfilter\",\"params\":[\"{s}\"]}}", .{"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"});
    defer testing.allocator.free(g);
    try testing.expect(has(g, "\"filter\":\""));

    const nf = try fx.call("{{\"id\":1,\"method\":\"getblockfilter\",\"params\":[\"{s}\"]}}", .{"0000000000000000000000000000000000000000000000000000000000000001"});
    defer testing.allocator.free(nf);
    try testing.expect(has(nf, "\"code\":-5"));
}

test "r5_data_integrity repair drops the running-counter index and rebuilds from nTx" {
    var fx: RpcFx = undefined;
    try fx.init(testing.allocator, true);
    defer fx.deinit();
    const cs = &fx.base.cs;

    const rebuilt = cs.repairTxCountIndex(&consensus.REGTEST);
    try testing.expectEqual(@as(u32, 20), rebuilt);
    var h: u32 = 1;
    while (h <= 20) : (h += 1) {
        // genesis (1 tx) + one coinbase per block
        try testing.expectEqual(@as(?u64, h + 1), cs.getCumulativeTxCount(h));
    }
    // Idempotent: the v2 marker makes the second boot a no-op.
    try testing.expectEqual(@as(u32, 0), cs.repairTxCountIndex(&consensus.REGTEST));

    var hex: [64]u8 = undefined;
    const h15 = crypto.computeBlockHash(&fx.blocks[15].header);
    hashToHex(&h15, &hex);
    const body = try fx.call("{{\"id\":1,\"method\":\"getchaintxstats\",\"params\":[5,\"{s}\"]}}", .{hex});
    defer testing.allocator.free(body);
    try testing.expect(has(body, "\"txcount\":16"));
    try testing.expect(has(body, "\"window_tx_count\":5"));
    try testing.expect(has(body, "\"window_final_block_height\":15"));
}

test "r5_data_integrity repair with a body gap leaves the rest unknown, never invented" {
    var fx: RpcFx = undefined;
    try fx.init(testing.allocator, true);
    defer fx.deinit();
    const cs = &fx.base.cs;
    // Remove the body at height 12: counts at 12..20 cannot be derived.
    const h12 = crypto.computeBlockHash(&fx.blocks[12].header);
    try fx.base.db.delete(storage.CF_BLOCKS, &h12);

    _ = cs.repairTxCountIndex(&consensus.REGTEST);
    try testing.expectEqual(@as(?u64, 12), cs.getCumulativeTxCount(11));
    try testing.expectEqual(@as(?u64, null), cs.getCumulativeTxCount(12));
    try testing.expectEqual(@as(?u64, null), cs.getCumulativeTxCount(20));

    const body = try fx.call("{{\"id\":1,\"method\":\"getchaintxstats\",\"params\":[]}}", .{});
    defer testing.allocator.free(body);
    try testing.expect(!has(body, "\"error\":{"));
    try testing.expect(!has(body, "\"txcount\""));
    try testing.expect(!has(body, "\"window_tx_count\""));
}
