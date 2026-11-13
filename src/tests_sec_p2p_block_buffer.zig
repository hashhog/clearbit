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

// --- rework of clearbit#72 (Warden) -------------------------------------------
//
// 1. The buffer cap must not strand a pending reorg: the body the reorg needs
//    next is admitted like the connect-front block, and a fork body the cap
//    dropped is asked for again from the drain.
// 2. The historical-backfill store runs only after the mutation check, with
//    the segwit context taken from the block index.

const storage = @import("storage.zig");
const hb = @import("historical_backfill.zig");

const ForkBlock = struct { block: types.Block, hash: types.Hash256 };

/// Coinbase-only regtest block at `height` (<= 16) on `prev`; `tag` makes
/// same-height siblings distinct.  Same shape as tests_reorg_p2p's miner.
fn mineForkBlock(a: std.mem.Allocator, params: *const consensus.NetworkParams, prev: types.Hash256, height: u32, tag: u8) !ForkBlock {
    const inputs = try a.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = try a.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag }),
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outputs = try a.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = try a.dupe(u8, &[_]u8{0x51}) };
    const txs = try a.alloc(types.Transaction, 1);
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeTxid(&txs[0], a),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

/// Heap deep copy (the handlers take ownership of what they are given).
fn cloneBlock(a: std.mem.Allocator, b: *const types.Block) !types.Block {
    var w = serialize.Writer.init(a);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readBlock(&r, a);
}

fn sendHdrs(pm: *peer_mod.PeerManager, a: std.mem.Allocator, from: *peer_mod.Peer, blocks: []const *const ForkBlock) !void {
    const hs = try a.alloc(types.BlockHeader, blocks.len);
    for (blocks, 0..) |b, i| hs[i] = b.block.header;
    try pm.ingestHeadersMessage(from, hs);
}

fn sendBody(pm: *peer_mod.PeerManager, a: std.mem.Allocator, from: *peer_mod.Peer, b: *const ForkBlock) !void {
    try pm.ingestBlockMessage(from, try cloneBlock(a, &b.block));
}

/// Every block hash in the getdata frames readable on `fd` (non-blocking).
fn readGetdata(a: std.mem.Allocator, fd: std.posix.fd_t, out: *std.ArrayList(types.Hash256)) !void {
    var bytes = std.ArrayList(u8).init(a);
    defer bytes.deinit();
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = std.posix.recv(fd, &buf, std.posix.MSG.DONTWAIT) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;
        try bytes.appendSlice(buf[0..n]);
    }
    var off: usize = 0;
    while (bytes.items.len - off >= 24) {
        const hdr = p2p.MessageHeader.decode(bytes.items[off..][0..24]);
        const frame_len = 24 + @as(usize, hdr.length);
        if (bytes.items.len - off < frame_len) break;
        if (std.mem.eql(u8, hdr.commandName(), "getdata")) {
            const msg = try p2p.decodePayload("getdata", bytes.items[off + 24 .. off + frame_len], a);
            defer p2p.freeDecodedMessage(a, msg);
            for (msg.getdata.inventory) |inv| try out.append(inv.hash);
        }
        off += frame_len;
    }
}

fn hasHash(list: []const types.Hash256, h: *const types.Hash256) bool {
    for (list) |x| if (std.mem.eql(u8, &x, h)) return true;
    return false;
}

const CapMode = enum { count, bytes };

/// Active chain G-A1-B1 from H.  The buffer is then filled to its cap (by
/// entry count, or by bytes) with merkle-valid bodies queued behind a front
/// block that never arrives.  X announces the heavier fork A1-B1x-B2x and
/// delivers B2x first (out of order: dropped by the cap), then B1x (the body
/// the reorg needs next: admitted), and the drain must ask X for B2x again;
/// once it arrives the node must reach B2x.  No hash is failed, nobody is
/// punished.
fn runReorgUnderCap(mode: CapMode) !void {
    const a = testing.allocator;
    const params = consensus.REGTEST;
    var pm = peer_mod.PeerManager.init(a, &params);
    defer pm.deinit();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var db = try storage.Database.open(path, 64, a);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, a);
    defer cs.deinit();
    cs.wireUtxoParent();
    cs.setNetworkParams(&params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    pm.chain_state = &cs;

    var h_peer = stubPeer(&params, a);
    defer h_peer.recv_buffer.deinit();
    h_peer.address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 3 }, 18444);
    // X is wired to a socketpair so the getdata it is sent can be read back.
    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
    defer std.posix.close(fds[0]);
    defer std.posix.close(fds[1]);
    var x_peer = stubPeer(&params, a);
    defer x_peer.recv_buffer.deinit();
    x_peer.address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 2 }, 18444);
    x_peer.stream = .{ .handle = fds[0] };
    try pm.peers.append(&h_peer);
    try pm.peers.append(&x_peer);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineForkBlock(a, &params, params.genesis_hash, 1, 0xA1);
    defer serialize.freeBlock(a, &a1.block);
    var b1 = try mineForkBlock(a, &params, a1.hash, 2, 0x11);
    defer serialize.freeBlock(a, &b1.block);
    var b1x = try mineForkBlock(a, &params, a1.hash, 2, 0x21);
    defer serialize.freeBlock(a, &b1x.block);
    var b2x = try mineForkBlock(a, &params, b1x.hash, 3, 0x22);
    defer serialize.freeBlock(a, &b2x.block);

    try sendHdrs(&pm, a, &h_peer, &.{ &a1, &b1 });
    try sendBody(&pm, a, &h_peer, &a1);
    try sendBody(&pm, a, &h_peer, &b1);
    try testing.expectEqual(@as(u32, 2), cs.best_height);

    // Fill the buffer: a front hash that never arrives, then filler bodies
    // queued behind it (so the drain cannot consume them).
    try queue(&pm, &h_peer, [_]u8{0xF0} ** 32);
    const n_fill: u32 = if (mode == .count) 1024 else 8;
    var i: u32 = 0;
    while (i < n_fill) : (i += 1) {
        var f = try ownedBlock(a, [_]u8{0xAB} ** 32, &.{.{ .coinbase = true, .tag = @truncate(i), .pad = if (mode == .bytes) 4096 else 1 }});
        f.header.nonce = i;
        try queue(&pm, &h_peer, crypto.computeBlockHash(&f.header));
        try pm.ingestBlockMessage(&h_peer, f);
    }
    try testing.expectEqual(n_fill, pm.block_buffer.count());
    if (mode == .bytes) {
        // Hold the byte cap at exactly what is buffered: any further non-front
        // body is over it.
        if (@hasField(peer_mod.PeerManager, "block_buffer_max_bytes")) pm.block_buffer_max_bytes = pm.block_buffer_bytes;
    }

    // X announces the heavier fork; a reorg is armed and X is asked for both.
    try sendHdrs(&pm, a, &x_peer, &.{ &b1x, &b2x });
    try testing.expect(pm.pending_reorg != null);
    var sent = std.ArrayList(types.Hash256).init(a);
    defer sent.deinit();
    try readGetdata(a, fds[1], &sent);
    try testing.expect(hasHash(sent.items, &b2x.hash));

    // B2x first: not the body the reorg needs next, so the cap drops it.
    // Dropped is not a verdict.
    try sendBody(&pm, a, &x_peer, &b2x);
    try testing.expect(!pm.block_buffer.contains(b2x.hash));
    try testing.expect(!pm.isBlockFailed(&b2x.hash));
    try testing.expect(!x_peer.should_ban);

    // B1x: the body the reorg needs next is admitted past the cap, and the
    // drain asks X again for the dropped B2x.
    sent.clearRetainingCapacity();
    try sendBody(&pm, a, &x_peer, &b1x);
    try testing.expect(pm.block_buffer.contains(b1x.hash));
    try readGetdata(a, fds[1], &sent);
    try testing.expect(hasHash(sent.items, &b2x.hash));

    // The re-requested B2x arrives: the reorg fires and reaches the fork tip.
    try sendBody(&pm, a, &x_peer, &b2x);
    try testing.expect(pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 3), cs.best_height);
    try testing.expectEqualSlices(u8, &b2x.hash, &cs.best_hash);
    try testing.expect(!pm.isBlockFailed(&b1x.hash));
    try testing.expect(!pm.isBlockFailed(&b2x.hash));
    try testing.expect(!x_peer.should_ban);
    try testing.expect(!h_peer.should_ban);
}

test "sec_p2p_block_buffer: rework a heavier fork delivered with the buffer at its COUNT cap still reaches the fork tip; the dropped fork body is re-requested" {
    try runReorgUnderCap(.count);
}

test "sec_p2p_block_buffer: rework a heavier fork delivered with the buffer at its BYTE cap still reaches the fork tip; the dropped fork body is re-requested" {
    try runReorgUnderCap(.bytes);
}

// --- historical backfill: mutation check before the store --------------------

const BF_FLOOR: u32 = 10;
const BF_TIP: u32 = 14;
const BF_SW: u32 = 5; // hole height carrying a committed segwit tx

/// Regtest chain 0..BF_TIP with an assumeutxo hole 1..BF_FLOOR-1 whose
/// headers are all stored.  Block BF_SW is a segwit block (coinbase with a
/// witness nonce + commitment, one tx with witness); the rest are
/// coinbase-only.
const BfRig = struct {
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: peer_mod.PeerManager,
    blocks: []types.Block,

    fn init(self: *BfRig, a: std.mem.Allocator, params: *const consensus.NetworkParams) !void {
        self.tmp = std.testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(a, ".");
        self.db = try storage.Database.open(self.path, 64, a);
        self.cs = storage.ChainState.init(&self.db, 64, a);
        self.blocks = try hb.buildRegtestChain(a, params, BF_TIP);
        // Replace BF_SW with a segwit block and re-mine everything after it.
        const rest = [_]TxSpec{.{ .tag = 7, .witness = &.{"good"} }};
        const c = try commitmentFor(a, &rest);
        var sw = try ownedBlock(a, crypto.computeBlockHash(&self.blocks[BF_SW - 1].header), &.{ .{ .coinbase = true, .tag = BF_SW, .witness = &.{NONCE}, .commitment = c }, rest[0] });
        sw.header.timestamp = self.blocks[BF_SW].header.timestamp;
        sw.header.bits = self.blocks[BF_SW].header.bits;
        while (!consensus.validateProofOfWork(&sw.header, params)) sw.header.nonce +%= 1;
        serialize.freeBlock(a, &self.blocks[BF_SW]);
        self.blocks[BF_SW] = sw;
        var h: u32 = BF_SW + 1;
        while (h <= BF_TIP) : (h += 1) {
            const ts = self.blocks[h].header.timestamp;
            const bits = self.blocks[h].header.bits;
            serialize.freeBlock(a, &self.blocks[h]);
            self.blocks[h] = try hb.mineCoinbaseBlock(a, crypto.computeBlockHash(&self.blocks[h - 1].header), h, ts, bits, params);
        }
        hb.seedSnapshotHole(&self.cs, self.blocks, BF_FLOOR, BF_TIP);
        self.pm = peer_mod.PeerManager.init(a, params);
        self.pm.anchors_path = "/dev/null";
        self.pm.chain_state = &self.cs;
        self.pm.armHistoricalBackfill();
        const bf = &(self.pm.historical_backfill orelse return error.BackfillNotArmed);
        const hdrs = try a.alloc(types.BlockHeader, BF_FLOOR - 1);
        defer a.free(hdrs);
        for (hdrs, 0..) |*hd, k| hd.* = self.blocks[k + 1].header;
        _ = try bf.acceptHeaders(hdrs, &self.cs, params);
        try testing.expect(bf.headersComplete());
    }

    fn deinit(self: *BfRig, a: std.mem.Allocator) void {
        self.pm.chain_state = null;
        self.pm.deinit();
        hb.freeRegtestChain(a, self.blocks);
        self.cs.deinit();
        self.db.close();
        a.free(self.path);
        self.tmp.cleanup();
    }

    fn hashAt(self: *BfRig, h: u32) types.Hash256 {
        return crypto.computeBlockHash(&self.blocks[h].header);
    }
};

test "sec_p2p_block_buffer: rework historical backfill refuses a mutated body before storing it; the matching body is stored and the hash is not failed" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var r: BfRig = undefined;
    try r.init(a, params);
    defer r.deinit(a);

    // (1) Merkle mismatch: coinbase-only hole block 3 with a different payout.
    const h3 = r.hashAt(3);
    var bad3 = try cloneBlock(a, &r.blocks[3]);
    @constCast(&bad3.transactions[0].outputs[0]).value += 1;
    try testing.expectEqualSlices(u8, &h3, &crypto.computeBlockHash(&bad3.header));
    var p1 = stubPeer(params, a);
    defer p1.recv_buffer.deinit();
    try r.pm.ingestBlockMessage(&p1, bad3);
    try testing.expect(!r.cs.hasBlock(&h3));
    try testing.expect(p1.should_ban);
    try testing.expect(!r.pm.isBlockFailed(&h3));

    // (2) Bad witness commitment: the segwit hole block with its tx witness
    // swapped (wtxid changes, txid and header do not).
    const h5 = r.hashAt(BF_SW);
    var bad5 = try cloneBlock(a, &r.blocks[BF_SW]);
    {
        const wit = try a.alloc([]const u8, 1);
        wit[0] = try a.dupe(u8, "junk");
        const in0 = @constCast(&bad5.transactions[1].inputs[0]);
        for (in0.witness) |item| a.free(item);
        a.free(in0.witness);
        in0.witness = wit;
    }
    try testing.expectEqualSlices(u8, &h5, &crypto.computeBlockHash(&bad5.header));
    var p2 = stubPeer(params, a);
    defer p2.recv_buffer.deinit();
    try r.pm.ingestBlockMessage(&p2, bad5);
    try testing.expect(!r.cs.hasBlock(&h5));
    try testing.expect(p2.should_ban);
    try testing.expect(!r.pm.isBlockFailed(&h5));

    // (3) Unexpected witness: coinbase-only hole block 4 with a coinbase
    // witness and no commitment.
    const h4 = r.hashAt(4);
    var bad4 = try cloneBlock(a, &r.blocks[4]);
    {
        const wit = try a.alloc([]const u8, 1);
        wit[0] = try a.dupe(u8, &([_]u8{0} ** 32));
        @constCast(&bad4.transactions[0].inputs[0]).witness = wit;
    }
    var p3 = stubPeer(params, a);
    defer p3.recv_buffer.deinit();
    try r.pm.ingestBlockMessage(&p3, bad4);
    try testing.expect(!r.cs.hasBlock(&h4));
    try testing.expect(p3.should_ban);
    try testing.expect(!r.pm.isBlockFailed(&h4));

    // The genuine bodies for the same hashes are stored afterwards, and the
    // honest sender is not punished.
    var honest = stubPeer(params, a);
    defer honest.recv_buffer.deinit();
    for ([_]u32{ 3, 4, BF_SW }) |h| {
        try r.pm.ingestBlockMessage(&honest, try cloneBlock(a, &r.blocks[h]));
        const hh = r.hashAt(h);
        try testing.expect(r.cs.hasBlock(&hh));
        try testing.expect(!r.pm.isBlockFailed(&hh));
    }
    try testing.expect(!honest.should_ban);
}
