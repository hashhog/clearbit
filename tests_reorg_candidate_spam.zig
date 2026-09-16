//! Control for QUEUES.md clearbit item 0: REORG-CANDIDATE spam loop.
//!
//! A peer re-announcing a 2000-header competing fork whose prev is not a
//! near-tip ancestor (live signature: `prev=...0000`, usually genesis-rooted
//! mainnet headers) must be handled once: the log line is bounded and
//! `getblockcount` keeps responding. Before the fix the `.headers`
//! competing_fork arm re-logged every iteration and `sendGetHeaders` with
//! the active-chain locator re-requested the same batch forever.
//!
//! CONTROL: `zig build test-reorg-candidate-spam --summary new`
//! Rooted at the project root so `src/wallet.zig`'s `@embedFile` resolves
//! (same layout as tests_t1_r5.zig). Filter `reorg_candidate_spam` so
//! imported rpc/peer/wallet tests do not run.

const std = @import("std");
const testing = std.testing;
const peer_mod = @import("src/peer.zig");
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const consensus = @import("src/consensus.zig");
const types = @import("src/types.zig");
const crypto = @import("src/crypto.zig");

const REPEAT: usize = 8;
const BATCH: usize = peer_mod.MAX_HEADERS_RESULTS;

fn stubPeer(params: *const consensus.NetworkParams, allocator: std.mem.Allocator) peer_mod.Peer {
    return .{
        .stream = .{ .handle = -1 },
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 1000,
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
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
        .time_offset = 0,
        .advertise_node_bloom = false,
        .transport_version = .v1,
        .v2_cipher = null,
        .v2_transport = null,
    };
}

fn makeHeaderChain(
    allocator: std.mem.Allocator,
    n: usize,
    prev0: types.Hash256,
    bits: u32,
    ts0: u32,
) ![]types.BlockHeader {
    const hdrs = try allocator.alloc(types.BlockHeader, n);
    var prev = prev0;
    var ts: u32 = ts0;
    for (hdrs, 0..) |*h, i| {
        var merkle = [_]u8{0} ** 32;
        merkle[0] = @intCast(i & 0xff);
        merkle[1] = @intCast((i >> 8) & 0xff);
        merkle[2] = 0xC1;
        h.* = .{
            .version = 1,
            .prev_block = prev,
            .merkle_root = merkle,
            .timestamp = ts,
            .bits = bits,
            .nonce = @intCast(i),
        };
        prev = crypto.computeBlockHash(h);
        ts += 1;
    }
    return hdrs;
}

fn dupeHeaders(allocator: std.mem.Allocator, src: []const types.BlockHeader) ![]types.BlockHeader {
    const out = try allocator.alloc(types.BlockHeader, src.len);
    @memcpy(out, src);
    return out;
}

test "reorg_candidate_spam: shouldContinueCompetingFork refuses too-deep / unresolved" {
    try testing.expect(!peer_mod.shouldContinueCompetingFork(2000, .refused_too_deep, 2000));
    try testing.expect(!peer_mod.shouldContinueCompetingFork(2000, .unresolved, 2000));
    try testing.expect(!peer_mod.shouldContinueCompetingFork(2000, .no_fork_point, 2000));
    try testing.expect(!peer_mod.shouldContinueCompetingFork(2000, .skipped, 2000));
    try testing.expect(!peer_mod.shouldContinueCompetingFork(2000, .armed, 0));
    try testing.expect(!peer_mod.shouldContinueCompetingFork(1999, .armed, 1999));
    try testing.expect(peer_mod.shouldContinueCompetingFork(2000, .armed, 10));
    try testing.expect(peer_mod.shouldContinueCompetingFork(2000, .already_pending, 1));
    try testing.expect(peer_mod.shouldContinueCompetingFork(2000, .refused_lower_work, 5));
}

test "reorg_candidate_spam: shouldLogReorgCandidate rate-limits identical prev" {
    const allocator = testing.allocator;
    var pm = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    defer pm.deinit();
    const prev = consensus.REGTEST.genesis_hash;
    try testing.expect(pm.shouldLogReorgCandidate(prev, 1_000));
    try testing.expect(!pm.shouldLogReorgCandidate(prev, 1_000 + 59));
    try testing.expect(pm.shouldLogReorgCandidate(prev, 1_000 + 60));
    var other = prev;
    other[0] ^= 0x01;
    try testing.expect(pm.shouldLogReorgCandidate(other, 1_000 + 61));
    try testing.expectEqual(@as(u64, 3), pm.reorg_candidate_logs_emitted);
}

test "reorg_candidate_spam: repeated unknown-prev 2000-header fork is handled once and getblockcount stays up" {
    const allocator = testing.allocator;
    const params = consensus.REGTEST;

    var pm = peer_mod.PeerManager.init(allocator, &params);
    defer pm.deinit();

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();
    // Deep enough that a genesis-rooted fork exceeds MAX_REORG_DEPTH_PEER
    // (288). No bodies needed: maybeArmReorg prices depth from best_height.
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 1000;
    pm.chain_state = &cs;

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    var server = rpc.RpcServer.init(allocator, &cs, &mempool, &pm, &params, .{});
    defer server.deinit();

    var peer = stubPeer(&params, allocator);
    defer peer.recv_buffer.deinit();

    const ts0 = params.genesis_header.timestamp + 600;
    const template = try makeHeaderChain(allocator, BATCH, params.genesis_hash, params.genesis_header.bits, ts0);
    defer allocator.free(template);

    var rpc_ok: usize = 0;
    var i: usize = 0;
    while (i < REPEAT) : (i += 1) {
        const batch = try dupeHeaders(allocator, template);
        try pm.ingestHeadersMessage(&peer, batch);

        const body = try server.dispatch(
            "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}",
        );
        defer allocator.free(body);
        try testing.expect(std.mem.indexOf(u8, body, "\"result\":1000") != null);
        rpc_ok += 1;
    }

    try testing.expectEqual(@as(usize, REPEAT), rpc_ok);
    try testing.expectEqual(@as(u64, REPEAT), pm.reorg_candidate_announcements);
    // Bounded: one print for the first announcement, not one per iteration.
    try testing.expect(pm.reorg_candidate_logs_emitted <= 2);
    // Must not re-request the same unresolvable / too-deep fork.
    try testing.expectEqual(@as(u64, 0), pm.fork_getheaders_continues);
    // Must not re-validate the same 2000 headers on every re-announce.
    try testing.expect(pm.header_diffbits_checks <= BATCH);
}
