//! Security audit 2026-10-29 (audits/security/clearbit-2026-10-29.md in the
//! meta-repo), finding C5, the part left after clearbit#38 fixed the
//! overwrite leak.
//!
//! A queued header hash is public during IBD. A peer could answer it with any
//! body: the block handler buffered whatever arrived under the header hash
//! without checking that the transactions hash to the header's merkle root or
//! that the witness data is committed, so up to 1024 junk ~4 MB bodies
//! (~4 GB) sat in `block_buffer` until each reached the connect front.
//!
//! Core runs IsBlockMutated on every received `block` (net_processing.cpp
//! :4785-4791, validation.cpp:4027-4056), punishes the sender ("mutated
//! block") and drops the body before ProcessNewBlock. The fix does the same
//! before the body is stored, and caps `block_buffer` by bytes as well as by
//! count (the connect-front block is always admitted, so the cap cannot wedge
//! the drain).
//!
//! The tests compile on the base commit: the byte cap is read through
//! `@hasField`, and the cap the tests hold the buffer to is a test constant,
//! so the base commit fails them on their assertions, by name.
//!
//! The consensus guards at the bottom pin the other direction: a valid block
//! must never be refused by the receipt check (segwit with a committed
//! witness, an odd transaction count, a pre-segwit block whose coinbase
//! carries a commitment-shaped output, and a block whose parent is unknown).

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const serialize = @import("serialize.zig");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const peer_mod = @import("peer.zig");

/// Byte cap the tests hold the buffer to (set on the PeerManager when the
/// field exists). Far below the 1024 x 64 KiB = 64 MiB the junk adds up to.
const TEST_CAP: u64 = 8 << 20;
const BODY_PAD: usize = 64 << 10;

fn stubPeer(params: *const consensus.NetworkParams, allocator: std.mem.Allocator) peer_mod.Peer {
    return .{
        .stream = .{ .handle = -1 },
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
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

fn initPm(a: std.mem.Allocator, params: *const consensus.NetworkParams) peer_mod.PeerManager {
    var pm = peer_mod.PeerManager.init(a, params);
    // Buffer-only: no chain state, so drain never tries to connect.
    pm.chain_state = null;
    if (@hasField(peer_mod.PeerManager, "block_buffer_max_bytes")) pm.block_buffer_max_bytes = TEST_CAP;
    return pm;
}

// --- owned block builder ----------------------------------------------------

const TxSpec = struct {
    coinbase: bool = false,
    tag: u8,
    pad: usize = 1,
    witness: []const []const u8 = &.{},
    /// Extra coinbase output: 0x6a24aa21a9ed ++ this.
    commitment: ?types.Hash256 = null,
};

fn ownedTx(a: std.mem.Allocator, spec: TxSpec) !types.Transaction {
    const inputs = try a.alloc(types.TxIn, 1);
    errdefer a.free(inputs);
    const wit = if (spec.witness.len == 0) @as([]const []const u8, &.{}) else blk: {
        const w = try a.alloc([]const u8, spec.witness.len);
        for (spec.witness, 0..) |item, i| w[i] = try a.dupe(u8, item);
        break :blk w;
    };
    inputs[0] = .{
        .previous_output = if (spec.coinbase) types.OutPoint.COINBASE else .{ .hash = [_]u8{spec.tag} ** 32, .index = 0 },
        .script_sig = if (spec.coinbase) try a.dupe(u8, &[_]u8{ 0x03, spec.tag, 0, 0 }) else &.{},
        .sequence = 0xffffffff,
        .witness = wit,
    };
    const n_out: usize = if (spec.commitment != null) 2 else 1;
    const outputs = try a.alloc(types.TxOut, n_out);
    const spk = try a.alloc(u8, spec.pad);
    @memset(spk, spec.tag);
    outputs[0] = .{ .value = 1000, .script_pubkey = spk };
    if (spec.commitment) |c| {
        const cspk = try a.alloc(u8, 38);
        @memcpy(cspk[0..6], &[_]u8{ 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed });
        @memcpy(cspk[6..38], &c);
        outputs[1] = .{ .value = 0, .script_pubkey = cspk };
    }
    return .{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
}

fn ownedBlock(a: std.mem.Allocator, prev: types.Hash256, specs: []const TxSpec) !types.Block {
    const txs = try a.alloc(types.Transaction, specs.len);
    for (specs, 0..) |s, i| txs[i] = try ownedTx(a, s);
    return .{ .header = try headerFor(a, prev, txs), .transactions = txs };
}

fn headerFor(a: std.mem.Allocator, prev: types.Hash256, txs: []const types.Transaction) !types.BlockHeader {
    const ids = try a.alloc(types.Hash256, txs.len);
    defer a.free(ids);
    for (txs, 0..) |*tx, i| ids[i] = try crypto.computeTxid(tx, a);
    return .{
        .version = 0x20000000,
        .prev_block = prev,
        .merkle_root = try crypto.computeMerkleRoot(ids, a),
        .timestamp = 1_700_000_000,
        .bits = 0x207fffff,
        .nonce = 0,
    };
}

/// Witness commitment (BIP-141) for a block whose non-coinbase txs are
/// `rest`, with the coinbase witness nonce = 32 zero bytes.
fn commitmentFor(a: std.mem.Allocator, rest: []const TxSpec) !types.Hash256 {
    const w = try a.alloc(types.Hash256, rest.len + 1);
    defer a.free(w);
    w[0] = [_]u8{0} ** 32;
    for (rest, 0..) |s, i| {
        const tx = try ownedTx(a, s);
        defer serialize.freeTransaction(a, &tx);
        w[i + 1] = try crypto.computeWtxid(&tx, a);
    }
    const root = try crypto.computeMerkleRoot(w, a);
    var pre: [64]u8 = [_]u8{0} ** 64;
    @memcpy(pre[0..32], &root);
    return crypto.hash256(&pre);
}

const NONCE: []const u8 = &([_]u8{0} ** 32);

/// Queue `hash` at the back of expected_blocks and mark it requested.
fn queue(pm: *peer_mod.PeerManager, peer: *peer_mod.Peer, hash: types.Hash256) !void {
    try pm.expected_blocks.append(hash);
    try pm.inflight_block_peer.put(hash, @intFromPtr(peer));
    pm.blocks_in_flight += 1;
}

fn bufferedBytes(pm: *peer_mod.PeerManager, a: std.mem.Allocator) !u64 {
    var sum: u64 = 0;
    var it = pm.block_buffer.valueIterator();
    while (it.next()) |b| {
        var w = serialize.Writer.init(a);
        defer w.deinit();
        try serialize.writeBlock(&w, b);
        sum += w.getWritten().len;
    }
    return sum;
}

// --- C5: bodies that are not the queued block -------------------------------

test "sec_p2p_block_buffer: C5 body whose merkle root does not match the queued header is not buffered and the peer is punished" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = initPm(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    const real = try ownedBlock(a, params.genesis_hash, &.{.{ .coinbase = true, .tag = 1 }});
    const h = crypto.computeBlockHash(&real.header);
    try queue(&pm, &peer, h);

    // Same header (so the same queued hash), different coinbase.
    var junk = try ownedBlock(a, params.genesis_hash, &.{.{ .coinbase = true, .tag = 2, .pad = BODY_PAD }});
    junk.header = real.header;
    try pm.ingestBlockMessage(&peer, junk);
    try testing.expectEqual(@as(u32, 0), pm.block_buffer.count());
    try testing.expect(peer.should_ban);

    // The genuine body for the same hash is still accepted afterwards.
    var honest = stubPeer(params, a);
    defer honest.recv_buffer.deinit();
    try pm.ingestBlockMessage(&honest, real);
    try testing.expect(pm.block_buffer.contains(h));
    try testing.expect(!honest.should_ban);
}

test "sec_p2p_block_buffer: C5 1024 junk bodies for queued hashes keep buffered bytes under the cap" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = initPm(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    var i: u32 = 0;
    while (i < 1024) : (i += 1) {
        var junk = try ownedBlock(a, params.genesis_hash, &.{.{ .coinbase = true, .tag = @truncate(i), .pad = BODY_PAD }});
        // A distinct header the body does not hash to.
        junk.header.merkle_root = [_]u8{0xEE} ** 32;
        junk.header.nonce = i;
        try queue(&pm, &peer, crypto.computeBlockHash(&junk.header));
        try pm.ingestBlockMessage(&peer, junk);
    }
    const bytes = try bufferedBytes(&pm, a);
    try testing.expect(bytes <= TEST_CAP);
    try testing.expectEqual(@as(u32, 0), pm.block_buffer.count());
}

test "sec_p2p_block_buffer: C5 witness data the coinbase does not commit to is refused on receipt" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = initPm(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    // Parent = genesis (known), height 1 >= regtest segwit_height: witness
    // commitment is checked. The witness is not in the txid, so swapping it
    // keeps the header hash.
    const rest = [_]TxSpec{.{ .tag = 7, .witness = &.{"good"} }};
    const c = try commitmentFor(a, &rest);
    const specs_good = [_]TxSpec{ .{ .coinbase = true, .tag = 1, .witness = &.{NONCE}, .commitment = c }, rest[0] };
    const specs_bad = [_]TxSpec{ specs_good[0], .{ .tag = 7, .witness = &.{ "junk", "x" ** 4096 } } };
    const good = try ownedBlock(a, params.genesis_hash, &specs_good);
    const bad = try ownedBlock(a, params.genesis_hash, &specs_bad);
    try testing.expectEqualSlices(u8, &good.header.merkle_root, &bad.header.merkle_root);
    const h = crypto.computeBlockHash(&good.header);
    try queue(&pm, &peer, h);

    try pm.ingestBlockMessage(&peer, bad);
    try testing.expectEqual(@as(u32, 0), pm.block_buffer.count());
    try testing.expect(peer.should_ban);

    var honest = stubPeer(params, a);
    defer honest.recv_buffer.deinit();
    try pm.ingestBlockMessage(&honest, good);
    try testing.expect(pm.block_buffer.contains(h));
    try testing.expect(!honest.should_ban);
}

test "sec_p2p_block_buffer: C5 CVE-2012-2459 duplicated-tx body is refused on receipt" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = initPm(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    const real_specs = [_]TxSpec{ .{ .coinbase = true, .tag = 1 }, .{ .tag = 2 }, .{ .tag = 3 } };
    const dup_specs = [_]TxSpec{ real_specs[0], real_specs[1], real_specs[2], real_specs[2] };
    const real = try ownedBlock(a, params.genesis_hash, &real_specs);
    var dup = try ownedBlock(a, params.genesis_hash, &dup_specs);
    // [a,b,c] and [a,b,c,c] share a merkle root.
    try testing.expectEqualSlices(u8, &real.header.merkle_root, &dup.header.merkle_root);
    dup.header = real.header;
    const h = crypto.computeBlockHash(&real.header);
    try queue(&pm, &peer, h);

    try pm.ingestBlockMessage(&peer, dup);
    try testing.expectEqual(@as(u32, 0), pm.block_buffer.count());
    try testing.expect(peer.should_ban);

    var honest = stubPeer(params, a);
    defer honest.recv_buffer.deinit();
    try pm.ingestBlockMessage(&honest, real);
    try testing.expect(pm.block_buffer.contains(h));
}

test "sec_p2p_block_buffer: C5 byte cap bounds merkle-valid bodies and still admits the connect-front block" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = initPm(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    const front = try ownedBlock(a, params.genesis_hash, &.{.{ .coinbase = true, .tag = 0xF0, .pad = BODY_PAD }});
    try queue(&pm, &peer, crypto.computeBlockHash(&front.header));
    pm.connect_cursor = 0;

    // 1023 valid, non-front bodies of ~64 KiB: 64 MiB without a byte cap.
    var i: u32 = 1;
    while (i < 1024) : (i += 1) {
        var b = try ownedBlock(a, params.genesis_hash, &.{.{ .coinbase = true, .tag = @truncate(i), .pad = BODY_PAD }});
        b.header.nonce = i;
        try queue(&pm, &peer, crypto.computeBlockHash(&b.header));
        try pm.ingestBlockMessage(&peer, b);
    }
    try testing.expect(try bufferedBytes(&pm, a) <= TEST_CAP);
    try testing.expect(!peer.should_ban);

    // The front block is admitted even with the buffer at its cap, so the
    // drain can always advance.
    const fh = crypto.computeBlockHash(&front.header);
    try pm.ingestBlockMessage(&peer, front);
    try testing.expect(pm.block_buffer.contains(fh));

    if (@hasField(peer_mod.PeerManager, "block_buffer_bytes")) {
        try testing.expectEqual(try bufferedBytes(&pm, a), pm.block_buffer_bytes);
    }
}

// --- consensus guards: valid blocks are never refused on receipt -------------

test "sec_p2p_block_buffer: consensus guard valid segwit, odd-count and unknown-parent blocks are buffered" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = initPm(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    // Odd tx count (the last leaf is duplicated by the tree, not mutated).
    const odd = try ownedBlock(a, params.genesis_hash, &.{ .{ .coinbase = true, .tag = 1 }, .{ .tag = 2 }, .{ .tag = 3 }, .{ .tag = 4 }, .{ .tag = 5 } });
    // Segwit, parent UNKNOWN: the witness context is unknown, so the witness
    // check must not run (it would see uncommitted witness if it guessed
    // pre-segwit). Here the commitment is valid anyway; also send one with no
    // commitment and witness data to pin that the check is skipped.
    const rest = [_]TxSpec{.{ .tag = 9, .witness = &.{"w"} }};
    const c = try commitmentFor(a, &rest);
    const sw = try ownedBlock(a, params.genesis_hash, &.{ .{ .coinbase = true, .tag = 1, .witness = &.{NONCE}, .commitment = c }, rest[0] });
    const orphan_sw = try ownedBlock(a, [_]u8{0xAB} ** 32, &.{ .{ .coinbase = true, .tag = 3 }, .{ .tag = 9, .witness = &.{"w"} } });

    for ([_]types.Block{ odd, sw, orphan_sw }) |b| try queue(&pm, &peer, crypto.computeBlockHash(&b.header));
    for ([_]types.Block{ odd, sw, orphan_sw }) |b| {
        const h = crypto.computeBlockHash(&b.header);
        try pm.ingestBlockMessage(&peer, b);
        try testing.expect(pm.block_buffer.contains(h));
    }
    try testing.expect(!peer.should_ban);
}

test "sec_p2p_block_buffer: consensus guard pre-segwit block with a commitment-shaped coinbase output is buffered" {
    const a = testing.allocator;
    var params_v = consensus.REGTEST;
    params_v.segwit_height = 1000; // height 1 is pre-segwit
    const params = &params_v;
    var pm = initPm(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    // Valid before segwit: the output is just a script, and the coinbase has
    // no witness nonce. Treating it as a segwit commitment would refuse it
    // (bad-witness-nonce-size).
    const b = try ownedBlock(a, params.genesis_hash, &.{.{ .coinbase = true, .tag = 1, .commitment = [_]u8{0x55} ** 32 }});
    const h = crypto.computeBlockHash(&b.header);
    try queue(&pm, &peer, h);
    try pm.ingestBlockMessage(&peer, b);
    try testing.expect(pm.block_buffer.contains(h));
    try testing.expect(!peer.should_ban);
}
