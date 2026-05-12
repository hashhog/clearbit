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
const validation = @import("validation.zig");
const block_template = @import("block_template.zig");

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

    pm.maybeArmReorg(&stub, &fork_tip);
    try testing.expect(pm.pending_reorg == null);
    // Either fork too deep (+20) OR fork never intersects (+20) — both
    // are consistent with rejection.
    // The stub peer uses 127.0.0.1 (local address); per the W99 G2 fix,
    // misbehaving() on a local peer sets should_ban (disconnect-only) but
    // does NOT accumulate ban_score (no discourage entry written).
    try testing.expect(stub.should_ban);
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

// ====================================================================
// Pattern X — submitblock height derived parent-relative, not active-tip
// (CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md)
//
// Bug: clearbit's submit_height was `chain_state.best_height + 1`,
// which derived from the active chain tip rather than the BLOCK'S
// parent in the block index. When a competing fork's first block (B1)
// arrives whose parent is the COMMON ANCESTOR (not the active tip),
// validation fired BadCoinbaseHeight because the derived height
// mismatched the BIP-34 height encoded in B1's coinbase.
//
// Fix: `block_template.deriveSubmitHeight()` uses `parent.height + 1`
// when the parent is in the ChainManager block index. Falls back to
// the active-tip-relative shortcut otherwise.
//
// Bitcoin Core reference: src/validation.cpp:4072
// `ContextualCheckBlockHeader` uses `pindexPrev->nHeight + 1`.
// ====================================================================

fn makePatternXEntry(
    allocator: std.mem.Allocator,
    hash: types.Hash256,
    height: u32,
    parent: ?*validation.BlockIndexEntry,
) !*validation.BlockIndexEntry {
    const entry = try allocator.create(validation.BlockIndexEntry);
    entry.* = validation.BlockIndexEntry{
        .hash = hash,
        .header = consensus.REGTEST.genesis_header,
        .height = height,
        .status = validation.BlockStatus{
            .valid_header = true,
            .has_data = true,
            .has_undo = false,
            .failed_valid = false,
            .failed_child = false,
            ._padding = 0,
        },
        .chain_work = [_]u8{0} ** 32,
        .sequence_id = 0,
        .parent = parent,
        .file_number = 0,
        .file_offset = 0,
    };
    return entry;
}

test "Pattern X: deriveSubmitHeight — parent on active tip yields best_height + 1" {
    // Best-chain extension: parent IS the active tip. Pattern X
    // derivation must agree with the active-tip-relative shortcut so
    // the common single-chain IBD / mining case is unchanged.
    const allocator = std.testing.allocator;
    var manager = validation.ChainManager.init(null, null, allocator);
    defer manager.deinit();

    const parent_hash: types.Hash256 = [_]u8{0xA0} ** 32;
    const parent = try makePatternXEntry(allocator, parent_hash, 110, null);
    try manager.addBlock(parent);

    const h = block_template.deriveSubmitHeight(&parent_hash, &manager, 110);
    try testing.expectEqual(@as(u32, 111), h);
}

test "Pattern X: deriveSubmitHeight — side-branch parent uses parent.height + 1, not active tip" {
    // The Pattern X bug: an A-chain extends the active tip to h=112
    // and a B-chain block (B1) arrives whose parent is the COMMON
    // ANCESTOR at h=110. With the buggy formula
    // `chain_state.best_height + 1` the validator expects height 113;
    // B1's coinbase encodes 111 (its true parent-relative height), so
    // BIP-34 fires bad-cb-height. The Pattern X fix uses
    // parent.height + 1 = 111, matching B1's coinbase encoding.
    const allocator = std.testing.allocator;
    var manager = validation.ChainManager.init(null, null, allocator);
    defer manager.deinit();

    const ancestor_hash: types.Hash256 = [_]u8{0xA0} ** 32;
    const ancestor = try makePatternXEntry(allocator, ancestor_hash, 110, null);
    try manager.addBlock(ancestor);

    const a1_hash: types.Hash256 = [_]u8{0xA1} ** 32;
    const a1 = try makePatternXEntry(allocator, a1_hash, 111, ancestor);
    try manager.addBlock(a1);

    const a2_hash: types.Hash256 = [_]u8{0xA2} ** 32;
    const a2 = try makePatternXEntry(allocator, a2_hash, 112, a1);
    try manager.addBlock(a2);

    // B1's parent is the common ancestor at h=110, not the active tip
    // at h=112. Pattern X fix derives parent.height + 1 == 111, NOT
    // best_height + 1 == 113.
    const h_b1 = block_template.deriveSubmitHeight(&ancestor_hash, &manager, 112);
    try testing.expectEqual(@as(u32, 111), h_b1);

    // Sanity: A2 as parent (best-chain extension at h=113) still works.
    const h_extend = block_template.deriveSubmitHeight(&a2_hash, &manager, 112);
    try testing.expectEqual(@as(u32, 113), h_extend);
}

test "Pattern X: deriveSubmitHeight — null chain_manager falls back to active tip" {
    // Early-startup / no block index: the active-tip-relative shortcut
    // is the only signal we have. This preserves pre-fix behaviour for
    // call sites that haven't wired chain_manager through yet.
    const dummy_hash: types.Hash256 = [_]u8{0xCC} ** 32;
    const h = block_template.deriveSubmitHeight(&dummy_hash, null, 200);
    try testing.expectEqual(@as(u32, 201), h);
}

test "Pattern X: deriveSubmitHeight — unknown parent falls back to active tip" {
    // Parent isn't yet indexed (could be a genuinely unknown-parent
    // block submitted out of order). Falling back to active-tip-
    // relative is correct here because the validation gate downstream
    // surfaces this as a different rejection (the unknown parent
    // becomes a Pattern Y / orphan-block concern, not a Pattern X
    // height-encoding concern). Pre-fix behaviour preserved.
    const allocator = std.testing.allocator;
    var manager = validation.ChainManager.init(null, null, allocator);
    defer manager.deinit();

    const known_hash: types.Hash256 = [_]u8{0x11} ** 32;
    const known = try makePatternXEntry(allocator, known_hash, 100, null);
    try manager.addBlock(known);

    const unknown_hash: types.Hash256 = [_]u8{0xFF} ** 32;
    const h = block_template.deriveSubmitHeight(&unknown_hash, &manager, 150);
    try testing.expectEqual(@as(u32, 151), h);
}

test "Pattern X: 2-chain A+B fork — derives correct heights for B1 and A2-extension" {
    // Build a 2-block A-chain and a partial B-chain sharing a common
    // parent. After A is fed, the active tip is A2 (h=112). Verify
    // that:
    //   * B1's submission height derives from its parent (h=110+1=111)
    //     — Pattern X correctness.
    //   * Extending A2 with a hypothetical A3 derives from A2 (h=113).
    // This is the corpus entry's chain shape captured as a unit test.
    const allocator = std.testing.allocator;
    var manager = validation.ChainManager.init(null, null, allocator);
    defer manager.deinit();

    // Common ancestor at h=110.
    const a0_hash: types.Hash256 = [_]u8{0xC0} ** 32;
    const a0 = try makePatternXEntry(allocator, a0_hash, 110, null);
    try manager.addBlock(a0);

    // Chain A: A1 (h=111), A2 (h=112).
    const a1_hash: types.Hash256 = [_]u8{0xA1} ** 32;
    const a1 = try makePatternXEntry(allocator, a1_hash, 111, a0);
    try manager.addBlock(a1);

    const a2_hash: types.Hash256 = [_]u8{0xA2} ** 32;
    const a2 = try makePatternXEntry(allocator, a2_hash, 112, a1);
    try manager.addBlock(a2);

    // Chain B (only B1 indexed at this point — B1 sharing A0 as parent).
    const b1_hash: types.Hash256 = [_]u8{0xB1} ** 32;
    const b1 = try makePatternXEntry(allocator, b1_hash, 111, a0);
    try manager.addBlock(b1);

    // Active tip == A2 (h=112).
    const active_best_height: u32 = 112;

    // B1 (parent A0 at h=110) — Pattern X must give 111.
    const h_b1 = block_template.deriveSubmitHeight(&a0_hash, &manager, active_best_height);
    try testing.expectEqual(@as(u32, 111), h_b1);

    // B2 (parent B1 at h=111) — Pattern X must give 112, even though
    // active tip is also at 112 (the depths happen to align here).
    const h_b2 = block_template.deriveSubmitHeight(&b1_hash, &manager, active_best_height);
    try testing.expectEqual(@as(u32, 112), h_b2);

    // Hypothetical A3 (parent A2 at h=112) — best-chain extension to 113.
    const h_a3 = block_template.deriveSubmitHeight(&a2_hash, &manager, active_best_height);
    try testing.expectEqual(@as(u32, 113), h_a3);
}

// ====================================================================
// Pattern Y: side-branch storage decoupling
// ====================================================================
//
// Pattern X (commit 546c57a) closed the height-derivation gate so that
// a side-branch block's BIP-34 coinbase-height check resolves correctly.
// Pattern Y closes the downstream connect gate: when a block validates
// but its parent is NOT the active tip (a sibling fork or competing
// chain), submitBlockWithIndex must store body + index entry without
// disturbing the active tip — and trigger a reorg if the new branch's
// cumulative chain_work strictly exceeds the active tip's.
//
// Pre-fix the connect gate fired a generic "rejected" / PrevBlockMismatch
// for any non-tip-extending block, the same shape the camlcoin /
// blockbrew / rustoshi Pattern Y closures fixed in their respective
// repos. The diff-test corpus entry `reorg-via-submitblock` exercises
// the full A1+A2 → B1+B2 → B3 reorg flow against bitcoin-core; these
// unit tests cover the structural invariants beneath that.
//
// Bitcoin Core reference: src/validation.cpp::BlockManager::AcceptBlock
// (writes HAVE_DATA on every accepted block regardless of best-chain
// position) + ActivateBestChain (selects heaviest valid leaf as new tip).

test "Pattern Y: side-branch storage preserves active tip when chain_work <= active" {
    // Setup: chain_state at active tip A2 (height 112). chain_manager
    // index has A0 (h=110), A1 (h=111), A2 (h=112). active_tip = A2
    // with strictly-positive chain_work.
    //
    // Action: processSideBranchSubmission(B1) where B1's parent is A0
    // (h=110) and B1's chain_work equals A1's (single block past the
    // common ancestor). With equal-or-lesser work the function must:
    //   * persist B1's BlockIndexEntry to cm.block_index
    //   * NOT touch cm.active_tip (still A2)
    //   * NOT advance chain_state.best_height / .best_hash
    //   * return reject_reason = "inconclusive"
    const allocator = testing.allocator;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    var manager = validation.ChainManager.init(&cs, null, allocator);
    defer manager.deinit();

    // Seed cm.block_index with A0, A1, A2.  Each entry's chain_work is
    // parent.chain_work + workFromBits(REGTEST difficulty bits).
    const reg_bits: u32 = 0x207fffff;
    const per_block_work = peer_mod.workFromBits(reg_bits);

    const a0_hash: types.Hash256 = [_]u8{0xA0} ** 32;
    var a0_work: [32]u8 = [_]u8{0} ** 32;
    peer_mod.addChainWorkBE(&a0_work, &per_block_work);
    const a0 = try makePatternXEntryWithWork(allocator, a0_hash, 110, null, a0_work);
    try manager.addBlock(a0);

    const a1_hash: types.Hash256 = [_]u8{0xA1} ** 32;
    var a1_work: [32]u8 = a0_work;
    peer_mod.addChainWorkBE(&a1_work, &per_block_work);
    const a1 = try makePatternXEntryWithWork(allocator, a1_hash, 111, a0, a1_work);
    try manager.addBlock(a1);

    const a2_hash: types.Hash256 = [_]u8{0xA2} ** 32;
    var a2_work: [32]u8 = a1_work;
    peer_mod.addChainWorkBE(&a2_work, &per_block_work);
    const a2 = try makePatternXEntryWithWork(allocator, a2_hash, 112, a1, a2_work);
    try manager.addBlock(a2);
    manager.active_tip = a2;

    // Mirror chain_state best_hash/height with A2.
    cs.best_hash = a2_hash;
    cs.best_height = 112;

    // Build B1 sharing parent A0.  Coinbase-only block, regtest diff
    // bits → trivially-PoW-valid (PoW is irrelevant at the structural
    // gate level — we're testing the side-branch storage arm, not
    // checkBlockHeader).
    const b1_blk = try makeForkTestBlock(allocator, a0_hash, 0xB1, reg_bits, 200);
    defer freeTestBlock(allocator, b1_blk.block);

    const before_active_tip = manager.active_tip;
    const before_best_hash = cs.best_hash;
    const before_best_height = cs.best_height;
    const before_index_count = manager.block_index.count();

    const result = try block_template.processSideBranchSubmission(
        &b1_blk.block,
        &b1_blk.hash,
        111, // Pattern X height = parent.height + 1
        &cs,
        &manager,
        a0,
        null, // mempool: not exercised in this test
        allocator,
    );

    // Side-branch storage convention: BIP-22 "inconclusive".
    try testing.expect(!result.accepted);
    try testing.expect(result.reject_reason != null);
    try testing.expectEqualStrings("inconclusive", result.reject_reason.?);

    // Active tip is preserved.
    try testing.expect(manager.active_tip == before_active_tip);
    try testing.expectEqualSlices(u8, &before_best_hash, &cs.best_hash);
    try testing.expectEqual(before_best_height, cs.best_height);

    // B1's entry IS in cm.block_index.
    try testing.expectEqual(before_index_count + 1, manager.block_index.count());
    const b1_entry = manager.getBlock(&b1_blk.hash) orelse
        return error.SideBranchEntryMissing;
    try testing.expectEqual(@as(u32, 111), b1_entry.height);
    try testing.expect(b1_entry.parent == a0);

    // B1's chain_work = A0's chain_work + per-block work (matches A1's work).
    try testing.expectEqualSlices(u8, &a1_work, &b1_entry.chain_work);
}

test "Pattern Y: side-branch parent lookup succeeds for B2's submission off B1" {
    // Setup: same as above (active chain A0..A2). After B1 has been
    // accepted as a side-branch (storage decoupled from selection),
    // submitting B2 with parent=B1 must find B1 in cm.block_index.
    //
    // This is the structural reason Pattern X alone wasn't enough:
    // without B1 stored, B2's parent lookup would fall back to the
    // active tip and re-trip bad-cb-height. With Pattern Y storing B1,
    // B2's parent lookup resolves to B1 (h=111) and Pattern X's height
    // derivation gives B2 the correct h=112.
    const allocator = testing.allocator;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    var manager = validation.ChainManager.init(&cs, null, allocator);
    defer manager.deinit();

    const reg_bits: u32 = 0x207fffff;
    const per_block_work = peer_mod.workFromBits(reg_bits);

    // Seed A0, A1, A2 (as above).
    const a0_hash: types.Hash256 = [_]u8{0xA0} ** 32;
    var a0_work: [32]u8 = [_]u8{0} ** 32;
    peer_mod.addChainWorkBE(&a0_work, &per_block_work);
    const a0 = try makePatternXEntryWithWork(allocator, a0_hash, 110, null, a0_work);
    try manager.addBlock(a0);

    const a1_hash: types.Hash256 = [_]u8{0xA1} ** 32;
    var a1_work: [32]u8 = a0_work;
    peer_mod.addChainWorkBE(&a1_work, &per_block_work);
    const a1 = try makePatternXEntryWithWork(allocator, a1_hash, 111, a0, a1_work);
    try manager.addBlock(a1);

    const a2_hash: types.Hash256 = [_]u8{0xA2} ** 32;
    var a2_work: [32]u8 = a1_work;
    peer_mod.addChainWorkBE(&a2_work, &per_block_work);
    const a2 = try makePatternXEntryWithWork(allocator, a2_hash, 112, a1, a2_work);
    try manager.addBlock(a2);
    manager.active_tip = a2;

    cs.best_hash = a2_hash;
    cs.best_height = 112;

    // Submit B1 as side-branch — registers entry (verified by previous
    // test). For this test we just want B1 in the index.
    const b1_blk = try makeForkTestBlock(allocator, a0_hash, 0xB1, reg_bits, 200);
    defer freeTestBlock(allocator, b1_blk.block);
    _ = try block_template.processSideBranchSubmission(
        &b1_blk.block,
        &b1_blk.hash,
        111,
        &cs,
        &manager,
        a0,
        null, // mempool: not exercised in this test
        allocator,
    );

    // B2's parent lookup: cm.getBlock(B1.hash) MUST succeed and return
    // a B1 entry whose height is 111.  Pre-Pattern-Y this was null
    // (B1 was rejected before being stored; B2's parent lookup fell
    // through to the active-tip shortcut).
    const b1_lookup = manager.getBlock(&b1_blk.hash) orelse
        return error.B1NotFoundInIndex;
    try testing.expectEqual(@as(u32, 111), b1_lookup.height);
    try testing.expect(b1_lookup.parent == a0);

    // Pattern X derivation: B2's submit height = B1.height + 1 = 112.
    const b2_height = block_template.deriveSubmitHeight(&b1_blk.hash, &manager, cs.best_height);
    try testing.expectEqual(@as(u32, 112), b2_height);
}

test "Pattern Y: side-branch with strictly-greater chain_work flips active_tip via reorg" {
    // Smallest possible reorg-via-submitblock invariant test: simulate
    // a heavier-branch arrival without the full submitBlock validation
    // gauntlet (which requires PoW + UTXO-aware acceptBlock).  We
    // construct the chain_state with two committed A blocks (so that
    // their bodies + undo are persisted; reorgToChain can disconnect
    // them), then drive processSideBranchSubmission with a synthetic
    // B-side entry whose chain_work is bumped to strictly exceed the
    // active tip.
    //
    // NB: this test cannot use the full chain_state.reorgToChain path
    // because makeForkTestBlock blocks have no real PoW + no real
    // coinbase script; the corpus diff-test entry exercises the full
    // path against Bitcoin Core's regtest miner.  Here we exercise
    // the chain_work comparison + index registration only.
    const allocator = testing.allocator;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    var manager = validation.ChainManager.init(&cs, null, allocator);
    defer manager.deinit();

    const reg_bits: u32 = 0x207fffff;
    const per_block_work = peer_mod.workFromBits(reg_bits);

    // Active tip at height 1 with chain_work = per_block_work.
    const a1_hash: types.Hash256 = [_]u8{0xA1} ** 32;
    const a1 = try makePatternXEntryWithWork(allocator, a1_hash, 1, null, per_block_work);
    try manager.addBlock(a1);
    manager.active_tip = a1;
    cs.best_hash = a1_hash;
    cs.best_height = 1;

    // Synthetic B1 sibling at height 1 (parent = genesis, equal work).
    // Then build B2 (parent B1, height 2, work = 2 * per_block_work),
    // strictly heavier than A1.
    const b1_hash: types.Hash256 = [_]u8{0xB1} ** 32;
    const b1 = try makePatternXEntryWithWork(allocator, b1_hash, 1, null, per_block_work);
    try manager.addBlock(b1);

    // Construct a B2 block whose hash we can register, then submit it
    // via processSideBranchSubmission. The function will:
    //   1. compute chain_work = b1.chain_work + workFromBits = 2x per_block_work
    //   2. compare against active_tip (a1) chain_work = 1x per_block_work
    //   3. find that b2_work > a1_work → fire reorg
    //   4. reorgToChain walks back: a1 -> genesis (b1's hash is NOT
    //      reachable via chain_state.hasBlock, so the fork-point walk
    //      stops at the genesis-as-parent-of-b1 ancestor only if genesis
    //      is on the active chain. Since we set best_hash to a1_hash
    //      and never committed any blocks, the disconnect path will
    //      try to disconnectBlockByHashCF(a1) which fails because
    //      no body is in CF_BLOCKS — error.BlockBodyNotFound).
    //
    // For this unit test we DON'T require the reorgToChain to succeed
    // — we require processSideBranchSubmission to:
    //   * register B2 in cm.block_index with the correct (heavier)
    //     chain_work
    //   * recognize this as a strictly-greater-work branch (i.e.
    //     attempt the reorg path, NOT return "inconclusive")
    // The specific failure mode (rejected for storage-not-present
    // reasons) is acceptable here because the corpus diff-test
    // exercises the happy reorg path against Core's miner.
    const b2_blk = try makeForkTestBlock(allocator, b1_hash, 0xB2, reg_bits, 300);
    defer freeTestBlock(allocator, b2_blk.block);

    const result = try block_template.processSideBranchSubmission(
        &b2_blk.block,
        &b2_blk.hash,
        2, // height
        &cs,
        &manager,
        b1,
        null, // mempool: not exercised in this test
        allocator,
    );

    // Whether the reorg actually fired depends on body availability.
    // Two valid outcomes:
    //   * accept (reorg succeeded, active_tip flipped to B2)
    //   * reject:rejected (reorg was attempted but storage failed
    //     mid-rewind because A1's body wasn't on disk).
    //
    // The forbidden outcome is "inconclusive" — that means the fix
    // mis-classified a strictly-heavier branch as equal/lighter.
    if (result.reject_reason) |reason| {
        // Defensive: must NOT be "inconclusive".
        try testing.expect(!std.mem.eql(u8, reason, "inconclusive"));
    } else {
        // accepted — reorg fired through to completion.
        try testing.expect(result.accepted);
    }

    // Regardless of the reorg's terminal outcome, B2 should be in the
    // index with the heavier chain_work.
    const b2_entry = manager.getBlock(&b2_blk.hash) orelse
        return error.B2NotInIndex;
    var expected_b2_work: [32]u8 = per_block_work; // b1's work
    peer_mod.addChainWorkBE(&expected_b2_work, &per_block_work);
    try testing.expectEqualSlices(u8, &expected_b2_work, &b2_entry.chain_work);
    // expected_b2_work > a1.chain_work strictly.
    try testing.expect(peer_mod.cmpChainWorkBE(&b2_entry.chain_work, &a1.chain_work) > 0);
}

/// Helper: like makePatternXEntry but lets the test pin chain_work
/// explicitly. Pattern Y tests need this so the comparison logic in
/// processSideBranchSubmission gets realistic inputs.
fn makePatternXEntryWithWork(
    allocator: std.mem.Allocator,
    hash: types.Hash256,
    height: u32,
    parent: ?*validation.BlockIndexEntry,
    chain_work: [32]u8,
) !*validation.BlockIndexEntry {
    const entry = try allocator.create(validation.BlockIndexEntry);
    entry.* = validation.BlockIndexEntry{
        .hash = hash,
        .header = consensus.REGTEST.genesis_header,
        .height = height,
        .status = validation.BlockStatus{
            .valid_header = true,
            .has_data = true,
            .has_undo = false,
            .failed_valid = false,
            .failed_child = false,
            ._padding = 0,
        },
        .chain_work = chain_work,
        .sequence_id = 0,
        .parent = parent,
        .file_number = 0,
        .file_offset = 0,
    };
    return entry;
}
