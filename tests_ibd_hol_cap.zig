//! CONTROL for the 60000→91705 range stall (QUEUES.md 2026-09-20).
//!
//! Live shape, binary `40c7759`, range-runner STALLED at tip 60815 after
//! connecting 815 of 31705 with the feeder still serving:
//!   DRAIN-BREAK-WEDGE connect_cursor=815 download_cursor=816 buffer=14
//!   sampled_ahead_min=INT64_MAX sampled_ahead_max=-1 expected_total=30000
//! Recovery cancelled the SAME front hash 26 times (2s→64s doubling) while
//! historical backfill kept issuing genesis-side getheaders/getdata on the
//! only peer (`--connect` replay). sampled_ahead empty means the 14 buffered
//! hashes are NOT in expected_blocks[connect_cursor..+4096] — delivered and
//! not connected (junk occupying the drain buffer) plus requested-and-not-
//! delivered for the front (slots spent on historical getdata).
//!
//! Same class as camlcoin `907680c`: cap the competing request set, drain
//! via the best-header/expected queue not whatever landed in the buffer.
//!
//! CONTROL: `zig build test-ibd-hol-cap --summary new`
//!
//! Rate assertion (ASK 3): while 32 forward hashes sit unconnected, historical
//! in-flight must be 0 so the one-peer 16-slot budget stays on tip+1.

const std = @import("std");
const testing = std.testing;
const peer_mod = @import("src/peer.zig");
const hb = @import("src/historical_backfill.zig");
const storage = @import("src/storage.zig");
const consensus = @import("src/consensus.zig");
const crypto = @import("src/crypto.zig");
const types = @import("src/types.zig");
const serialize = @import("src/serialize.zig");
const p2p = @import("src/p2p.zig");

fn stubPeer(params: *const consensus.NetworkParams, allocator: std.mem.Allocator) peer_mod.Peer {
    return .{
        .stream = .{ .handle = -1 },
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        // A witness peer: block bodies are only requested from NODE_WITNESS
        // peers (Core CanServeWitnesses).
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 100,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .is_witness_capable = true,
        .is_headers_first = true,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = false,
        .is_protected = false,
        .connect_time = 0,
        .advertise_node_bloom = false,
        .transport_version = .v1,
    };
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    tmp_dir: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    chain_state: storage.ChainState,
    pm: peer_mod.PeerManager,
    blocks: []types.Block,
    peer: peer_mod.Peer,

    fn init(self: *Fixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.tmp_dir = std.testing.tmpDir(.{});
        self.path = try self.tmp_dir.dir.realpathAlloc(allocator, ".");
        self.db = try storage.Database.open(self.path, 64, allocator);
        self.chain_state = storage.ChainState.init(&self.db, 64, allocator);
        const params = &consensus.REGTEST;
        self.blocks = try hb.buildRegtestChain(allocator, params, 20);
        hb.seedSnapshotHole(&self.chain_state, self.blocks, 10, 20);
        self.pm = peer_mod.PeerManager.init(allocator, params);
        self.pm.chain_state = &self.chain_state;
        self.pm.armHistoricalBackfill();
        self.peer = stubPeer(params, allocator);
        if (self.pm.historical_backfill == null) return error.TestUnexpectedResult;
    }

    fn deinit(self: *Fixture) void {
        self.peer.recv_buffer.deinit();
        self.pm.deinit();
        self.chain_state.deinit();
        self.db.close();
        hb.freeRegtestChain(self.allocator, self.blocks);
        self.allocator.free(self.path);
        self.tmp_dir.cleanup();
    }

    fn acceptHistoricalHeaders(self: *Fixture) !void {
        var hole: [9]types.BlockHeader = undefined;
        var i: usize = 0;
        while (i < 9) : (i += 1) hole[i] = self.blocks[i + 1].header;
        const bf = if (self.pm.historical_backfill) |*b| b else return error.TestUnexpectedResult;
        _ = try bf.acceptHeaders(&hole, &self.chain_state, &consensus.REGTEST);
    }

    fn historicalInFlight(self: *Fixture) u32 {
        const bf = if (self.pm.historical_backfill) |*b| b else return 0;
        return @intCast(bf.in_flight.count());
    }

    fn queueForwardWindow(self: *Fixture, n: usize) !void {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var h: types.Hash256 = [_]u8{0} ** 32;
            h[0] = @intCast(i + 1);
            h[1] = 0xCB;
            try self.pm.expected_blocks.append(h);
        }
        self.pm.connect_cursor = 0;
        self.pm.download_cursor = 0;
    }
};

test "ibd_hol: historical getdata yields while the forward queue is unconnected" {
    // RATE: 32 unconnected forward hashes → 0 historical in-flight (want the
    // 16-slot budget on tip+1). Live stall requested historical bodies on the
    // same --connect peer until connect_cursor stopped at 815.
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.acceptHistoricalHeaders();
    try fx.queueForwardWindow(32);

    try testing.expect(fx.pm.ibdConnectQueuePending());
    fx.pm.driveHistoricalBackfill(&fx.peer);
    try testing.expectEqual(@as(u32, 0), fx.historicalInFlight());
}

test "ibd_hol: historical getdata resumes once the forward queue is caught up" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.acceptHistoricalHeaders();
    // Empty forward queue AND no peer announcing a higher tip = at rest.
    try testing.expect(!fx.pm.ibdConnectQueuePending());
    fx.pm.driveHistoricalBackfill(&fx.peer);
    try testing.expect(fx.historicalInFlight() > 0);
}

test "ibd_hol: historical bodies are never requested from a non-witness peer" {
    // Same at-rest setup as the "resumes" test above (which requests > 0 from
    // a NODE_WITNESS peer — the control); only the peer's services differ.
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.acceptHistoricalHeaders();
    fx.peer.services = p2p.NODE_NETWORK;
    try testing.expect(!fx.pm.ibdConnectQueuePending());
    fx.pm.driveHistoricalBackfill(&fx.peer);
    try testing.expectEqual(@as(u32, 0), fx.historicalInFlight());
}

test "ibd_hol: historical still yields when the queue is empty but the peer is ahead" {
    // Live freeze at 82655: expected_blocks caught up after a truncated
    // headers batch, historical getheaders stole the --connect peer, 82656+
    // never arrived. Yield on peer_height > our_height even with an empty queue.
    try testing.expect(peer_mod.PeerManager.historicalYieldsToForwardSync(false, 82655, 91705));
    try testing.expect(!peer_mod.PeerManager.historicalYieldsToForwardSync(false, 91705, 91705));
    try testing.expect(peer_mod.PeerManager.historicalYieldsToForwardSync(true, 91705, 91705));
}

test "ibd_hol: unsolicited far-ahead block is dropped, not buffered" {
    // sampled_ahead empty + buffer>0 is this: a body that is not the next
    // expected hash sits in block_buffer and trips DRAIN-BREAK-WEDGE forever.
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    try fx.queueForwardWindow(32);

    const params = &consensus.REGTEST;
    const junk = try hb.mineCoinbaseBlock(
        testing.allocator,
        [_]u8{0xAA} ** 32,
        1,
        params.genesis_header.timestamp + 600,
        params.genesis_header.bits,
        params,
    );
    try fx.pm.ingestBlockMessage(&fx.peer, junk);
    try testing.expectEqual(@as(u32, 0), fx.pm.block_buffer.count());
}

test "ibd_hol: the next expected block is still buffered (negative control)" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    // Do not connect: we are asserting the receive/buffer path, not validation.
    fx.pm.chain_state = null;

    const params = &consensus.REGTEST;
    const nxt = try hb.mineCoinbaseBlock(
        testing.allocator,
        [_]u8{0xBB} ** 32,
        11,
        params.genesis_header.timestamp + 600,
        params.genesis_header.bits,
        params,
    );
    const nxt_hash = crypto.computeBlockHash(&nxt.header);
    try fx.pm.expected_blocks.append(nxt_hash);
    fx.pm.connect_cursor = 0;
    try fx.pm.ingestBlockMessage(&fx.peer, nxt);
    try testing.expectEqual(@as(u32, 1), fx.pm.block_buffer.count());
    try testing.expect(fx.pm.block_buffer.contains(nxt_hash));
}

test "ibd_hol: reverse-order delivery of a 32-block window all land in the drain buffer" {
    // ASK 3 rate: one-peer, 32 bodies delivered newest-first, all 32 present
    // for drain (camlcoin test_gapfill_connect_none reverse-delivery analogue).
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    // Buffer-only: drain would try to connect the front and reject BadVersion
    // on these synthetic coinbases. The rate assertion is "all 32 present".
    fx.pm.chain_state = null;

    const params = &consensus.REGTEST;
    const n: usize = 32;
    var mined: [32]types.Block = undefined;
    var prev: types.Hash256 = [_]u8{0x11} ** 32;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        mined[i] = try hb.mineCoinbaseBlock(
            testing.allocator,
            prev,
            @intCast(21 + i),
            params.genesis_header.timestamp + @as(u32, @intCast(600 * (i + 1))),
            params.genesis_header.bits,
            params,
        );
        prev = crypto.computeBlockHash(&mined[i].header);
        try fx.pm.expected_blocks.append(prev);
    }
    fx.pm.connect_cursor = 0;

    var j: usize = n;
    while (j > 0) {
        j -= 1;
        try fx.pm.ingestBlockMessage(&fx.peer, mined[j]);
        mined[j] = undefined; // ownership moved
    }
    try testing.expectEqual(@as(u32, 32), fx.pm.block_buffer.count());
}

test "ibd_hol: insertHeader persists so LRU eviction keeps retarget ancestors" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    const hdr = fx.blocks[1].header;
    const hash = crypto.computeBlockHash(&hdr);
    _ = try fx.pm.insertHeader(&hdr, &hash) orelse return error.TestUnexpectedResult;
    try testing.expect(fx.pm.header_index.contains(hash));
    _ = fx.pm.header_index.remove(hash);
    try testing.expect(fx.chain_state.getPersistedHeader(&hash) != null);
}

test "ibd_hol: genesis-header prev=0 is a backfill batch while the hole is open" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    const bf = if (fx.pm.historical_backfill) |*b| b else return error.TestUnexpectedResult;
    var hdrs = [_]types.BlockHeader{consensus.REGTEST.genesis_header};
    try testing.expect(bf.isBackfillBatch(&fx.chain_state, &hdrs));
}
