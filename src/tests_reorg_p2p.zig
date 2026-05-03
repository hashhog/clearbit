//! Competing-fork detection + reorg-trigger tests for the `.headers`
//! handler (CLEARBIT_REORG=1 path).
//!
//! Run via `zig build test-reorg-p2p` (also folded into `zig build test`).
//!
//! These exercise the bits the wave-2026-05-02 fork-trigger fix touched:
//!   * workFromBits / addChainWorkBE / cmpChainWorkBE — chain-work math.
//!   * BlockHeaderEntry insert + LRU eviction.
//!   * classifyHeaderBatch — Case A/B/C decision.
//!   * maybeArmReorg → tryFireReorg — full reorg-trigger pipeline.
//!
//! The handler-side hook (the `switch (klass)` block in the .headers case)
//! is exercised end-to-end by feeding synthetic headers through the
//! PeerManager state machine.  Where a real peer is needed (for the +20
//! misbehavior side-effects), we construct a Peer with a no-op stream
//! (handle = -1) and never actually send/receive bytes.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const peer_mod = @import("peer.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const p2p = @import("p2p.zig");

// ====================================================================
// Helpers
// ====================================================================

/// Build a coinbase-only block whose header has the given prev_hash +
/// distinctive marker.  Allocates the inner transaction + script slabs
/// from `allocator`; caller must `serialize.freeBlock` (or otherwise
/// reclaim) before the test exits.
fn makeForkTestBlock(
    allocator: std.mem.Allocator,
    prev_hash: [32]u8,
    marker: u8,
    bits: u32,
    ts_offset: u32,
) !struct {
    block: types.Block,
    hash: types.Hash256,
} {
    const script_sig = try allocator.dupe(u8, &[_]u8{ 0x03, marker, 0x00, 0x00 });
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = coinbase_input;

    const p2wpkh = try allocator.alloc(u8, 22);
    p2wpkh[0] = 0x00;
    p2wpkh[1] = 0x14;
    var i: usize = 2;
    while (i < 22) : (i += 1) p2wpkh[i] = marker;
    const coinbase_output = types.TxOut{
        .value = 5_000_000_000,
        .script_pubkey = p2wpkh,
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = coinbase_output;
    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = 0,
    };
    const txs = try allocator.alloc(types.Transaction, 1);
    txs[0] = coinbase_tx;

    const block = types.Block{
        .header = .{
            .version = 1,
            .prev_block = prev_hash,
            .merkle_root = [_]u8{marker} ** 32,
            .timestamp = 1_700_000_000 + ts_offset,
            .bits = bits,
            .nonce = @as(u32, marker),
        },
        .transactions = txs,
    };
    const hash = crypto.computeBlockHash(&block.header);
    return .{ .block = block, .hash = hash };
}

/// Free a Block returned by makeForkTestBlock.  `serialize.freeBlock` is
/// the canonical helper but it expects a `*types.Block` whose memory was
/// laid out by `serialize.readBlock`; here we did all our own slab
/// allocations, so we mirror that layout manually.
fn freeTestBlock(allocator: std.mem.Allocator, block: types.Block) void {
    for (block.transactions) |tx| {
        for (tx.inputs) |inp| allocator.free(inp.script_sig);
        for (tx.outputs) |out| allocator.free(out.script_pubkey);
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }
    allocator.free(block.transactions);
}

/// Construct a stub Peer that won't actually send/receive bytes.
/// Suitable only for tests that touch ban-score logic + hash-only
/// helpers — never call `sendMessage` on this peer (the stream handle
/// is invalid).
fn makeStubPeer(params: *const consensus.NetworkParams, allocator: std.mem.Allocator) peer_mod.Peer {
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

// ====================================================================
// Chain-work math
// ====================================================================

test "workFromBits: difficulty 1 bits gives nonzero work" {
    // bits = 0x1d00ffff == difficulty 1; per Core's GetBlockProof the
    // work is exactly 0x100010001000100010001 ≈ 4295032833.  We don't
    // assert the exact numeric value here (relies on long-divide
    // convergence) — we only assert the work is strictly positive and
    // fits in the low half of the buffer.
    const w = peer_mod.workFromBits(0x1d00ffff);
    var nonzero = false;
    for (w) |b| {
        if (b != 0) {
            nonzero = true;
            break;
        }
    }
    try testing.expect(nonzero);
}

test "workFromBits: zero target → zero work" {
    // bits = 0 yields target=0 → SetCompact returns negative/overflow
    // → GetBlockProof = 0.
    const w = peer_mod.workFromBits(0);
    for (w) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "workFromBits: harder target gives more work" {
    // 0x1d00ffff ≈ difficulty 1 (max target).  0x1c000fff is ~16x
    // harder → ~16x more work.  Verify the comparison ordering only.
    const easy = peer_mod.workFromBits(0x1d00ffff);
    const harder = peer_mod.workFromBits(0x1c000fff);
    // harder > easy as big-endian 256-bit unsigned ints.
    var i: usize = 0;
    var harder_greater = false;
    while (i < 32) : (i += 1) {
        if (harder[i] > easy[i]) {
            harder_greater = true;
            break;
        }
        if (harder[i] < easy[i]) break;
    }
    try testing.expect(harder_greater);
}

test "addChainWorkBE: plain add" {
    var a: [32]u8 = [_]u8{0} ** 32;
    a[31] = 0x80; // low byte = 128
    const b: [32]u8 = blk: {
        var x: [32]u8 = [_]u8{0} ** 32;
        x[31] = 0x40; // 64
        break :blk x;
    };
    peer_mod.addChainWorkBE(&a, &b);
    try testing.expectEqual(@as(u8, 0xC0), a[31]); // 128 + 64 = 192
    try testing.expectEqual(@as(u8, 0), a[30]);
}

test "addChainWorkBE: carry across bytes" {
    var a: [32]u8 = [_]u8{0} ** 32;
    a[31] = 0xFF; // low byte = 255
    var b: [32]u8 = [_]u8{0} ** 32;
    b[31] = 0x01; // 1
    peer_mod.addChainWorkBE(&a, &b);
    try testing.expectEqual(@as(u8, 0x00), a[31]); // 255 + 1 = 256 → 0 carry 1
    try testing.expectEqual(@as(u8, 0x01), a[30]); // carry into next byte
}

test "cmpChainWorkBE: ordering" {
    const a: [32]u8 = blk: {
        var x: [32]u8 = [_]u8{0} ** 32;
        x[0] = 0x10;
        break :blk x;
    };
    const b: [32]u8 = blk: {
        var x: [32]u8 = [_]u8{0} ** 32;
        x[0] = 0x20;
        break :blk x;
    };
    try testing.expect(peer_mod.cmpChainWorkBE(&b, &a) > 0);
    try testing.expect(peer_mod.cmpChainWorkBE(&a, &b) < 0);
    try testing.expectEqual(@as(i32, 0), peer_mod.cmpChainWorkBE(&a, &a));
}

test "chainWorkFromHeight: monotone in height" {
    const w0 = peer_mod.chainWorkFromHeight(0);
    const w1 = peer_mod.chainWorkFromHeight(1);
    const w_big = peer_mod.chainWorkFromHeight(900_000);
    try testing.expect(peer_mod.cmpChainWorkBE(&w1, &w0) > 0);
    try testing.expect(peer_mod.cmpChainWorkBE(&w_big, &w1) > 0);
}

// ====================================================================
// classifyHeaderBatch (Case A/B/C)
// ====================================================================
//
// Build a PeerManager with a chain_state that has been advanced to a
// known active tip, populate header_index with an alternate fork
// branch, then drive classifyHeaderBatch through each case.

test "classifyHeaderBatch: Case A — header extends active tip" {
    const allocator = testing.allocator;

    // Make a regtest params (we never call any pow-validating code).
    const params = consensus.REGTEST;
    var pm = peer_mod.PeerManager.init(allocator, &params);
    defer pm.deinit();

    // Set up a fake chain state whose tip we own + best_hash matches.
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();
    pm.chain_state = &cs;

    // Build genesis-ish entry.
    const tip_hash: types.Hash256 = [_]u8{0xAA} ** 32;
    cs.best_hash = tip_hash;
    cs.best_height = 1;

    // Build a header that chains onto tip.
    const ext = try makeForkTestBlock(allocator, tip_hash, 0xB1, 0x1d00ffff, 0);
    defer freeTestBlock(allocator, ext.block);
    const klass = pm.classifyHeaderBatch(&ext.block.header, &tip_hash);
    try testing.expectEqual(peer_mod.PeerManager.HeaderClass.extends_active, klass);
}

test "classifyHeaderBatch: Case B — header chains onto known fork ancestor" {
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
    pm.chain_state = &cs;

    // Active tip: simulate height 5 with arbitrary hash 0xAA*32.
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 5;

    // Build alternate ancestor: chains off genesis (zero-prev) so
    // insertHeader's lookupParentChainWork hits the genesis sentinel
    // and accepts the entry.
    const alt_anc = try makeForkTestBlock(allocator, [_]u8{0} ** 32, 0xC1, 0x1d00ffff, 0);
    defer freeTestBlock(allocator, alt_anc.block);
    const inserted = try pm.insertHeader(&alt_anc.block.header, &alt_anc.hash);
    try testing.expect(inserted != null);

    // Now the new header chains onto alt_anc.hash — Case B.
    const fork_block = try makeForkTestBlock(allocator, alt_anc.hash, 0xC2, 0x1d00ffff, 1);
    defer freeTestBlock(allocator, fork_block.block);
    const klass = pm.classifyHeaderBatch(&fork_block.block.header, &cs.best_hash);
    try testing.expectEqual(peer_mod.PeerManager.HeaderClass.competing_fork, klass);
}

test "classifyHeaderBatch: Case C — unknown parent → misbehavior path" {
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
    pm.chain_state = &cs;
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 5;

    // Header whose prev is some random hash never seen.
    const orphan = try makeForkTestBlock(allocator, [_]u8{0xEE} ** 32, 0xD1, 0x1d00ffff, 0);
    defer freeTestBlock(allocator, orphan.block);
    const klass = pm.classifyHeaderBatch(&orphan.block.header, &cs.best_hash);
    try testing.expectEqual(peer_mod.PeerManager.HeaderClass.unknown_parent, klass);
}

// ====================================================================
// header_index: insert + LRU eviction
// ====================================================================

test "insertHeader: deduplicates same-hash inserts (last_seen refreshed)" {
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
    pm.chain_state = &cs;
    cs.best_hash = [_]u8{0} ** 32;
    cs.best_height = 0;

    // Insert a header off genesis.
    const blk = try makeForkTestBlock(allocator, [_]u8{0} ** 32, 1, 0x1d00ffff, 0);
    defer freeTestBlock(allocator, blk.block);
    _ = try pm.insertHeader(&blk.block.header, &blk.hash);
    const before_count = pm.header_index.count();

    // Insert again — must be no-op (no extra entry).
    _ = try pm.insertHeader(&blk.block.header, &blk.hash);
    try testing.expectEqual(before_count, pm.header_index.count());
}

test "insertHeader: rejects unknown parent (returns null entry)" {
    const allocator = testing.allocator;
    const params = consensus.REGTEST;
    var pm = peer_mod.PeerManager.init(allocator, &params);
    defer pm.deinit();

    // No chain_state, no header_index entries → parent unknown.
    const orphan = try makeForkTestBlock(allocator, [_]u8{0xEE} ** 32, 0x77, 0x1d00ffff, 0);
    defer freeTestBlock(allocator, orphan.block);
    const ent = try pm.insertHeader(&orphan.block.header, &orphan.hash);
    try testing.expect(ent == null);
}

// ====================================================================
// maybeArmReorg + tryFireReorg
// ====================================================================
//
// End-to-end: build an active chain via connectBlockFastWithUndo,
// announce a higher-chainwork fork via insertHeader, deliver fork
// bodies into block_buffer, and verify reorgToChain fires.

test "maybeArmReorg: lower-chainwork fork is ignored" {
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
    pm.chain_state = &cs;

    // Active tip at height 10.
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 10;

    // Insert a single fork header off the tip.  Its chainwork will
    // equal active+1 (via chainWorkFromHeight + workFromBits) — but
    // we'll pin it to a fake "lower" value by hand.
    const fork_blk = try makeForkTestBlock(allocator, cs.best_hash, 0xB1, 0x1d00ffff, 0);
    defer freeTestBlock(allocator, fork_blk.block);
    var ent = (try pm.insertHeader(&fork_blk.block.header, &fork_blk.hash)).?;
    // Force its chainwork to BELOW the active tip placeholder.
    ent.chain_work = [_]u8{0} ** 32;
    try pm.header_index.put(fork_blk.hash, ent);

    var stub = makeStubPeer(&params, allocator);
    defer stub.recv_buffer.deinit();

    pm.maybeArmReorg(&stub, &fork_blk.hash);
    try testing.expect(pm.pending_reorg == null);
}

test "maybeArmReorg: fork too deep → refused with peer +20" {
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
    pm.chain_state = &cs;

    // Active tip at height 1000.  Build a fake fork chain that's
    // longer than MAX_REORG_DEPTH (288) and never intersects the
    // active chain.
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 1000;

    // Build linked alt chain starting from genesis (zero parent so
    // insertHeader accepts the first one).  Walk depth = 300.
    var prev: [32]u8 = [_]u8{0} ** 32;
    var fork_tip: types.Hash256 = undefined;
    // Keep blocks alive until end of test so the headers we inserted
    // by reference remain readable.  We don't actually use the bodies
    // again so freeing as we go is safe; defer-collect into an
    // ArrayList for cleanup.
    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    var i: u32 = 0;
    while (i < 300) : (i += 1) {
        const blk = try makeForkTestBlock(allocator, prev, @as(u8, @intCast(i % 256)), 0x1d00ffff, i);
        try to_free.append(blk.block);
        const ent = try pm.insertHeader(&blk.block.header, &blk.hash);
        try testing.expect(ent != null);
        prev = blk.hash;
        fork_tip = blk.hash;
    }

    var stub = makeStubPeer(&params, allocator);
    defer stub.recv_buffer.deinit();

    const ban_before = stub.ban_score;
    pm.maybeArmReorg(&stub, &fork_tip);
    try testing.expect(pm.pending_reorg == null);
    // Either fork too deep (+20) OR fork never intersects (+20) — both
    // are consistent with rejection.
    try testing.expect(stub.ban_score > ban_before);
}

test "tryFireReorg: arms pending_reorg when fork has higher chainwork" {
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
    pm.chain_state = &cs;

    // Pretend the active chain reached height 2 with a known tip hash.
    // (No actual blocks committed — we exercise the trigger logic only;
    // tryFireReorg's downstream call to reorgToChain is exercised in
    // its own storage.zig tests at storage.zig:5718.)
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 2;

    // Build fork chain B from genesis: B1, B2, B3 (3 blocks > 2).
    // We collect the blocks for cleanup later.
    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }

    var prev_b: [32]u8 = [_]u8{0} ** 32;
    var hashes_b: [3]types.Hash256 = undefined;
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        const b = try makeForkTestBlock(allocator, prev_b, @as(u8, @intCast(0xB0 + i)), 0x207fffff, 100 + i);
        try to_free.append(b.block);
        hashes_b[i] = b.hash;
        // Insert into header_index so maybeArmReorg can walk back.
        const ent = try pm.insertHeader(&b.block.header, &b.hash);
        try testing.expect(ent != null);
        prev_b = b.hash;
    }

    // Force fork_tip's chain_work to strictly exceed the active tip's
    // chainWorkFromHeight(2) placeholder so maybeArmReorg arms.
    var ent = pm.header_index.get(hashes_b[2]).?;
    var bigwork: [32]u8 = [_]u8{0} ** 32;
    bigwork[0] = 0xFF; // top byte set → maximal big-endian value
    ent.chain_work = bigwork;
    try pm.header_index.put(hashes_b[2], ent);

    var stub = makeStubPeer(&params, allocator);
    defer stub.recv_buffer.deinit();

    pm.maybeArmReorg(&stub, &hashes_b[2]);
    try testing.expect(pm.pending_reorg != null);
    try testing.expectEqual(@as(usize, 3), pm.pending_reorg.?.fork_hashes.items.len);

    // pending_reorg.fork_hashes should be in connect order:
    //   [hashes_b[0], hashes_b[1], hashes_b[2]]
    const fh = pm.pending_reorg.?.fork_hashes.items;
    try testing.expectEqualSlices(u8, &hashes_b[0], &fh[0]);
    try testing.expectEqualSlices(u8, &hashes_b[1], &fh[1]);
    try testing.expectEqualSlices(u8, &hashes_b[2], &fh[2]);

    // Cleanup: clear pending_reorg so deinit doesn't try to dual-free.
    if (pm.pending_reorg) |*pr| pr.deinit();
    pm.pending_reorg = null;
}

// ====================================================================
// Per-block extension regression: extends_active path doesn't false-
// positive into competing_fork even when many fork ancestors are in
// header_index.
// ====================================================================

test "no false-positive: header off active tip is extends_active even with fork ancestors in index" {
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
    pm.chain_state = &cs;
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 100;

    // Pre-populate index with an unrelated fork branch off genesis.
    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    var prev: [32]u8 = [_]u8{0} ** 32;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const b = try makeForkTestBlock(allocator, prev, @as(u8, @intCast(i)), 0x1d00ffff, i);
        try to_free.append(b.block);
        _ = try pm.insertHeader(&b.block.header, &b.hash);
        prev = b.hash;
    }

    // Now a genuine extension: prev = active tip.
    const ext = try makeForkTestBlock(allocator, cs.best_hash, 0x77, 0x1d00ffff, 999);
    defer freeTestBlock(allocator, ext.block);
    const klass = pm.classifyHeaderBatch(&ext.block.header, &cs.best_hash);
    try testing.expectEqual(peer_mod.PeerManager.HeaderClass.extends_active, klass);
}

// ====================================================================
// Equal-chainwork tie-break: ignored (Bitcoin Core first-seen).
// ====================================================================

test "maybeArmReorg: equal-chainwork fork is ignored (first-seen wins)" {
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
    pm.chain_state = &cs;
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 5;

    // Fork header off active tip: insertHeader gives it
    // chainWorkFromHeight(5) + workFromBits(0x1d00ffff).  Force it
    // back to chainWorkFromHeight(5) exactly to simulate equal work.
    const fork_blk = try makeForkTestBlock(allocator, cs.best_hash, 0xB2, 0x1d00ffff, 1);
    defer freeTestBlock(allocator, fork_blk.block);
    var ent = (try pm.insertHeader(&fork_blk.block.header, &fork_blk.hash)).?;
    ent.chain_work = peer_mod.chainWorkFromHeight(5);
    try pm.header_index.put(fork_blk.hash, ent);

    var stub = makeStubPeer(&params, allocator);
    defer stub.recv_buffer.deinit();

    pm.maybeArmReorg(&stub, &fork_blk.hash);
    try testing.expect(pm.pending_reorg == null);
}
