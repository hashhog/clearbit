//! CHARTER control for genesis→base backfill after a snapshot-index hole.
//!
//! After HistoricalBackfill fills the hole:
//!   (1) getblockhash(1) returns the genesis-child hash and getblockheader succeeds
//!   (2) getblockchaininfo reports pruned:false with no pruneheight
//!   (4) getblock + getchaintxstats on a historical height work
//!
//! Mini-chain analogue of the live mainnet hole (floor 944172).
//! CONTROL: `zig build test-historical-backfill --summary new`

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const crypto = @import("src/crypto.zig");
const hb = @import("src/historical_backfill.zig");

test {
    _ = hb;
}

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

const Fixture = struct {
    db: storage.Database,
    chain_state: storage.ChainState,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    server: rpc.RpcServer,
    allocator: std.mem.Allocator,
    tmp_dir: std.testing.TmpDir,
    path: []u8,
    blocks: []@import("src/types.zig").Block,

    fn init(self: *Fixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.tmp_dir = std.testing.tmpDir(.{});
        self.path = try self.tmp_dir.dir.realpathAlloc(allocator, ".");
        self.db = try storage.Database.open(self.path, 64, allocator);
        self.chain_state = storage.ChainState.init(&self.db, 64, allocator);
        const params = &consensus.REGTEST;
        self.blocks = try hb.buildRegtestChain(allocator, params, 20);
        hb.seedSnapshotHole(&self.chain_state, self.blocks, 10, 20);
        self.chain_state.setHistoryFloor(10);
        self.mempool = mempool_mod.Mempool.init(null, null, allocator);
        self.peer_manager = peer_mod.PeerManager.init(allocator, params);
        self.peer_manager.chain_state = &self.chain_state;
        self.server = rpc.RpcServer.init(
            allocator,
            &self.chain_state,
            &self.mempool,
            &self.peer_manager,
            params,
            .{},
        );
    }

    fn deinit(self: *Fixture) void {
        self.server.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
        self.db.close();
        hb.freeRegtestChain(self.allocator, self.blocks);
        self.allocator.free(self.path);
        self.tmp_dir.cleanup();
    }

    fn fill(self: *Fixture) !void {
        const params = &consensus.REGTEST;
        var bf = hb.HistoricalBackfill.detect(&self.chain_state, params.genesis_hash, 20) orelse
            return error.TestUnexpectedResult;
        defer bf.deinit();
        var hole: [9]@import("src/types.zig").BlockHeader = undefined;
        var i: usize = 0;
        while (i < 9) : (i += 1) hole[i] = self.blocks[i + 1].header;
        _ = try bf.acceptHeaders(&hole, &self.chain_state, params);
        var h: u32 = 1;
        while (h < 10) : (h += 1) {
            _ = try bf.acceptBlock(&self.blocks[h], &self.chain_state);
        }
    }
};

test "snapshot_backfill getblockhash 1 and header after fill" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.fill();

    const body = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockhash\",\"params\":[1]}");
    defer testing.allocator.free(body);
    var hex: [64]u8 = undefined;
    const h1 = crypto.computeBlockHash(&fx.blocks[1].header);
    hashToHex(&h1, &hex);
    try testing.expect(has(body, &hex));
    try testing.expect(!has(body, "\"error\":{"));

    var req_buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "{{\"id\":1,\"method\":\"getblockheader\",\"params\":[\"{s}\",true]}}", .{hex});
    const hdr = try fx.server.dispatch(req);
    defer testing.allocator.free(hdr);
    try testing.expect(has(hdr, "\"height\":1"));
    try testing.expect(has(hdr, &hex));
    try testing.expect(!has(hdr, "\"error\":{"));
}

test "snapshot_backfill getblockchaininfo unpruned after fill" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();

    const before = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}");
    defer testing.allocator.free(before);
    try testing.expect(has(before, "\"pruned\":true"));
    try testing.expect(has(before, "\"pruneheight\":10"));

    try fx.fill();

    const after = try fx.server.dispatch("{\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}");
    defer testing.allocator.free(after);
    try testing.expect(has(after, "\"pruned\":false"));
    try testing.expect(!has(after, "\"pruneheight\":"));
}

test "snapshot_backfill getblock and chaintxstats after fill" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.fill();

    var hex: [64]u8 = undefined;
    const h5 = crypto.computeBlockHash(&fx.blocks[5].header);
    hashToHex(&h5, &hex);

    var req_buf: [160]u8 = undefined;
    const block_req = try std.fmt.bufPrint(&req_buf, "{{\"id\":1,\"method\":\"getblock\",\"params\":[\"{s}\",1]}}", .{hex});
    const block_json = try fx.server.dispatch(block_req);
    defer testing.allocator.free(block_json);
    try testing.expect(has(block_json, "\"height\":5"));
    try testing.expect(has(block_json, &hex));
    try testing.expect(!has(block_json, "\"error\":{"));

    var stats_buf: [180]u8 = undefined;
    const stats_req = try std.fmt.bufPrint(&stats_buf, "{{\"id\":1,\"method\":\"getchaintxstats\",\"params\":[2,\"{s}\"]}}", .{hex});
    const stats = try fx.server.dispatch(stats_req);
    defer testing.allocator.free(stats);
    try testing.expect(has(stats, "\"txcount\"") or has(stats, "\"window_final_block_hash\"") or has(stats, "\"time\""));
    try testing.expect(!has(stats, "Block not found"));
}
