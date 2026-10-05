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
        // Fork bodies are requested from the announcer, which must be a
        // NODE_WITNESS peer (Core CanServeWitnesses).
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
    // We collect the blocks for cleanup later.
    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }

    // Build the ACTIVE chain A (2 blocks) and point ChainState at its tip,
    // so the tip is present in header_index and the reorg comparison has a
    // REAL, same-scale basis.
    //
    // This test used to set `cs.best_hash = 0xAA..` — a hash deliberately NOT
    // in header_index — and its comment said it forced the fork's work "to
    // strictly exceed the active tip's chainWorkFromHeight(2) placeholder".
    // That made the test depend on the synthetic fallback, which is exactly
    // the #46 defect: a value engineered to lose standing in for the active
    // chain. The fallback now refuses instead, so the test states its real
    // intent — a STRICTLY HEAVIER fork arms a reorg — against a basis that
    // actually means something.
    var prev_a: [32]u8 = [_]u8{0} ** 32;
    var a_tip: types.Hash256 = undefined;
    var ai: u32 = 0;
    while (ai < 2) : (ai += 1) {
        const a = try makeForkTestBlock(allocator, prev_a, @as(u8, @intCast(0xA0 + ai)), 0x207fffff, 200 + ai);
        try to_free.append(a.block);
        const aent = try pm.insertHeader(&a.block.header, &a.hash);
        try testing.expect(aent != null);
        prev_a = a.hash;
        a_tip = a.hash;
    }
    cs.best_hash = a_tip;
    cs.best_height = 2;

    // Build fork chain B from genesis: B1, B2, B3 (3 blocks > 2).

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

    // Force fork_tip's chain_work to strictly exceed the ACTIVE TIP's real
    // header_index chain_work so maybeArmReorg arms. Both operands are now on
    // the same scale (chainWorkFromHeight(root) + SUM(workFromBits)).
    var ent = pm.header_index.get(hashes_b[2]).?;
    var bigwork: [32]u8 = [_]u8{0} ** 32;
    bigwork[0] = 0xFF; // top byte set → maximal big-endian value
    ent.chain_work = bigwork;
    try pm.header_index.put(hashes_b[2], ent);

    var stub = makeStubPeer(&params, allocator);
    defer stub.recv_buffer.deinit();

    // A NON-witness announcer of the very same heavier fork must NOT arm:
    // its bodies would be requested from it, and Core never downloads
    // blocks from a peer that cannot serve witnesses.
    stub.services = p2p.NODE_NETWORK;
    pm.last_arm_result = .no_fork_point; // not the default, so the next assert means something
    pm.maybeArmReorg(&stub, &hashes_b[2]);
    try testing.expect(pm.pending_reorg == null);
    try testing.expectEqual(peer_mod.ReorgArmResult.skipped, pm.last_arm_result);
    stub.services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;

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

// ====================================================================
// getheaders responder (processGetHeaders / collectHeadersFromForkPoint)
// ====================================================================
//
// The serving side of the CLEARBIT_REORG fork pipeline: an incoming
// `getheaders` must walk the peer's locator to the fork point and reply
// with OUR active-chain headers from fork_point+1 (cap 2000, honoring a
// non-zero hash_stop).  Without this responder a peer that re-requests a
// competing fork is starved and the reorg never fires.
//
// Reference: bitcoin-core/src/net_processing.cpp ProcessGetHeaders /
// camlcoin lib/sync.ml handle_getheaders_request.

/// Persist a header at `height` into a test ChainState's DB so that
/// getBlockHashByHeight(height) and getPersistedHeader(hash) both resolve
/// — exactly the two accessors the responder reads.  Mirrors the on-disk
/// layout written by ChainStore.putBlockIndex (4-byte LE height prefix +
/// 80-byte header in CF_BLOCK_INDEX) and ChainState.putBlockHashByHeight
/// (H:height → hash in CF_DEFAULT).
fn persistActiveHeader(
    db: *storage.Database,
    allocator: std.mem.Allocator,
    height: u32,
    hash: *const types.Hash256,
    header: *const types.BlockHeader,
) !void {
    // CF_DEFAULT: H:height → hash
    const hkey = storage.ChainStore.buildHeightHashKey(height);
    try db.put(storage.CF_DEFAULT, &hkey, hash);

    // CF_BLOCK_INDEX: hash → u32_LE(height) ++ header(80)
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeInt(u32, height);
    try serialize.writeBlockHeader(&w, header);
    try db.put(storage.CF_BLOCK_INDEX, hash, w.getWritten());
}

/// Build a 3-block active chain (heights 1..3) off genesis, persist it,
/// and return the per-height hashes/headers + the cleanup list.  Caller
/// must free every block in `to_free`.
const BuiltChain = struct {
    hashes: [3]types.Hash256,
    headers: [3]types.BlockHeader,
};

fn buildAndPersistActiveChain(
    db: *storage.Database,
    cs: *storage.ChainState,
    allocator: std.mem.Allocator,
    to_free: *std.ArrayList(types.Block),
    params: *const consensus.NetworkParams,
) !BuiltChain {
    var out: BuiltChain = undefined;
    var prev: types.Hash256 = params.genesis_hash;
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        const blk = try makeForkTestBlock(allocator, prev, @as(u8, @intCast(0xA0 + i)), 0x207fffff, i);
        try to_free.append(blk.block);
        const height = i + 1;
        try persistActiveHeader(db, allocator, height, &blk.hash, &blk.block.header);
        out.hashes[i] = blk.hash;
        out.headers[i] = blk.block.header;
        prev = blk.hash;
    }
    cs.best_hash = out.hashes[2];
    cs.best_height = 3;
    return out;
}

test "getheaders responder: genesis locator → serves full active chain from height 1" {
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

    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    const chain = try buildAndPersistActiveChain(&db, &cs, allocator, &to_free, &params);

    const locator = [_]types.Hash256{params.genesis_hash};
    const zero_stop = [_]u8{0} ** 32;
    const served = pm.collectHeadersFromForkPoint(&locator, &zero_stop) orelse {
        try testing.expect(false); // must serve something
        return;
    };
    defer allocator.free(served);

    try testing.expectEqual(@as(usize, 3), served.len);
    // Headers must be the active chain, in height order 1,2,3.
    for (0..3) |k| {
        const got = crypto.computeBlockHash(&served[k]);
        try testing.expectEqualSlices(u8, &chain.hashes[k], &got);
    }
}

test "getheaders responder: cross-fork disjoint locator → falls back to genesis (reorg-enabling)" {
    // This is the exact reorg scenario: the peer's locator names hashes on
    // a DIFFERENT chain (chain A) that we (R3, on chain B) have never seen.
    // The fork point must resolve to genesis so we serve our heavier chain
    // B from height 1 — block 1's prev=genesis is KNOWN to the requester,
    // so its classifyHeaderBatch returns competing_fork and the reorg arms.
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

    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    const chain = try buildAndPersistActiveChain(&db, &cs, allocator, &to_free, &params);

    // Locator from a disjoint chain A — hashes we have never persisted.
    const locator = [_]types.Hash256{ [_]u8{0xC1} ** 32, [_]u8{0xC2} ** 32 };
    const zero_stop = [_]u8{0} ** 32;

    // Fork point must be genesis (0).
    try testing.expectEqual(@as(u32, 0), pm.getHeadersForkPoint(&locator));

    const served = pm.collectHeadersFromForkPoint(&locator, &zero_stop) orelse {
        try testing.expect(false);
        return;
    };
    defer allocator.free(served);

    // Full chain B served from height 1, and crucially served[0].prev is
    // genesis (KNOWN to the requester) — the reorg-enabling property.
    try testing.expectEqual(@as(usize, 3), served.len);
    try testing.expectEqualSlices(u8, &params.genesis_hash, &served[0].prev_block);
    for (0..3) |k| {
        const got = crypto.computeBlockHash(&served[k]);
        try testing.expectEqualSlices(u8, &chain.hashes[k], &got);
    }
}

test "getheaders responder: locator at active-chain mid-height → serves from fork_point+1" {
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

    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    const chain = try buildAndPersistActiveChain(&db, &cs, allocator, &to_free, &params);

    // Locator names our height-1 hash → fork point is 1, serve 2,3.
    const locator = [_]types.Hash256{chain.hashes[0]};
    const zero_stop = [_]u8{0} ** 32;
    try testing.expectEqual(@as(u32, 1), pm.getHeadersForkPoint(&locator));

    const served = pm.collectHeadersFromForkPoint(&locator, &zero_stop) orelse {
        try testing.expect(false);
        return;
    };
    defer allocator.free(served);

    try testing.expectEqual(@as(usize, 2), served.len);
    try testing.expectEqualSlices(u8, &chain.hashes[1], &crypto.computeBlockHash(&served[0]));
    try testing.expectEqualSlices(u8, &chain.hashes[2], &crypto.computeBlockHash(&served[1]));
}

test "getheaders responder: non-zero hash_stop truncates at the matching header" {
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

    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    const chain = try buildAndPersistActiveChain(&db, &cs, allocator, &to_free, &params);

    // From genesis, stop at height-2's hash → serve only heights 1,2.
    const locator = [_]types.Hash256{params.genesis_hash};
    const served = pm.collectHeadersFromForkPoint(&locator, &chain.hashes[1]) orelse {
        try testing.expect(false);
        return;
    };
    defer allocator.free(served);

    try testing.expectEqual(@as(usize, 2), served.len);
    try testing.expectEqualSlices(u8, &chain.hashes[0], &crypto.computeBlockHash(&served[0]));
    try testing.expectEqualSlices(u8, &chain.hashes[1], &crypto.computeBlockHash(&served[1]));
}

test "getheaders responder: fork point at tip → nothing to serve (null)" {
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

    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    const chain = try buildAndPersistActiveChain(&db, &cs, allocator, &to_free, &params);

    // Locator names the tip → fork point == best_height → serve nothing.
    const locator = [_]types.Hash256{chain.hashes[2]};
    const zero_stop = [_]u8{0} ** 32;
    try testing.expectEqual(@as(u32, 3), pm.getHeadersForkPoint(&locator));
    try testing.expect(pm.collectHeadersFromForkPoint(&locator, &zero_stop) == null);
}

// ====================================================================
// #46: a fork must NOT win when there is no same-scale basis for the
// active chain.
//
// maybeArmReorg used to fall back to `chainWorkFromHeight(cs.best_height)`
// when the active tip was absent from header_index — a synthetic value that
// encodes height+1 into the low 5 bytes and, by construction, LOSES to any
// real chain. That state is reached after every restart or eviction until
// headers re-sync, so the chain the node was actually on was represented by a
// number engineered to lose and the first fork to arrive took the node.
//
// Reading the PERSISTED chain_work instead would be wrong for a different
// reason: header_index accumulates from the sync ROOT
// (chainWorkFromHeight(root) + SUM(work)) while the block index accumulates
// from GENESIS (genesisBlockProof + SUM(work)). Mixing the scales makes the
// active tip win every contest. So the only honest answer is to refuse.
// ====================================================================
test "maybeArmReorg: refuses when the active tip has no comparable chainwork" {
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

    // Active tip is NOT in header_index — the post-restart / post-eviction
    // state. Height 5 keeps the implied reorg well inside the depth cap, so
    // this test isolates the missing-basis path and nothing else.
    cs.best_hash = [_]u8{0xAA} ** 32;
    cs.best_height = 5;

    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }

    // A fork carrying genuinely large work.
    var prev: [32]u8 = [_]u8{0} ** 32;
    var fork_tip: types.Hash256 = undefined;
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        const b = try makeForkTestBlock(allocator, prev, @as(u8, @intCast(0xC0 + i)), 0x207fffff, 700 + i);
        try to_free.append(b.block);
        const e = try pm.insertHeader(&b.block.header, &b.hash);
        try testing.expect(e != null);
        prev = b.hash;
        fork_tip = b.hash;
    }
    var ent = pm.header_index.get(fork_tip).?;
    var bigwork: [32]u8 = [_]u8{0} ** 32;
    bigwork[0] = 0xFF; // maximal big-endian value — beats any placeholder
    ent.chain_work = bigwork;
    try pm.header_index.put(fork_tip, ent);

    var stub = makeStubPeer(&params, allocator);
    defer stub.recv_buffer.deinit();

    pm.maybeArmReorg(&stub, &fork_tip);

    // Pre-fix this armed: bigwork beat chainWorkFromHeight(5). The node must
    // now keep the chain it has until header sync gives it a real basis.
    try testing.expect(pm.pending_reorg == null);
    // And the peer is NOT penalised — offering a fork we cannot yet evaluate
    // is our limitation, not its misbehaviour.
    try testing.expect(!stub.should_ban);
}

// ====================================================================
// 2026-08-26 LIVE INCIDENT REGRESSION: a routine 1-block race must be
// recoverable AFTER A RESTART.
//
// clearbit lost the race at 964181 and sat 48 blocks behind on its stale
// branch. Post-restart the in-memory header_index is empty, so the depth
// check resolved the fork point — OUR OWN active-chain block, found by the
// walk's hasBlock() probe — as height 0. Every reorg then looked ~964k deep:
//
//   REORG: refused — reorg depth 964181 exceeds the cap (288)
//          (fork_point_h=0, active_h=964181)
//   Misbehaving: +20 ... fork too deep      <- banning the honest peers
//
// The fix resolves the fork point's ABSOLUTE height from the persisted block
// index first, and prices both chains above the shared fork point on the
// same scale (persisted headers for our side), so the heavier real chain
// arms a reorg.
// ====================================================================
test "maybeArmReorg: post-restart 1-block race arms a reorg, not a ban" {
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

    // Persisted active chain: fork point at 999, our stale tip at 1000.
    // best_height=1000 makes the OLD height-0 reading exceed the 288 cap.
    // Our STALE TIP is absent from header_index — the post-restart state.
    //
    // The fork point itself is inserted into header_index as a zero-parent
    // root, which gives it the DEGENERATE in-memory height 0 (insertHeader's
    // genesis convention) — exactly what a post-restart served batch
    // produces. The persisted record below carries the TRUE height 999, so
    // this also pins the fix's storage-over-index preference: trusting the
    // in-memory height here would re-create the 1000-deep misread.
    var to_free = std.ArrayList(types.Block).init(allocator);
    defer {
        for (to_free.items) |b| freeTestBlock(allocator, b);
        to_free.deinit();
    }
    const fpb = try makeForkTestBlock(allocator, [_]u8{0} ** 32, 0xF0, 0x207fffff, 299);
    try to_free.append(fpb.block);
    try testing.expect((try pm.insertHeader(&fpb.block.header, &fpb.hash)) != null);
    const fp_hash: types.Hash256 = fpb.hash;
    const stale_tip: types.Hash256 = [_]u8{0xF1} ** 32;

    // CF_BLOCKS body presence is what the fork-point walk probes (hasBlock).
    try db.put(storage.CF_BLOCKS, &fp_hash, &[_]u8{0xEE});

    // CF_BLOCK_INDEX records: height(4 LE) + 80-byte header + padding, the
    // layout getBlockHeightByHash / getPersistedHeader parse. Our stale tip's
    // header carries real regtest bits so the same-scale pricing can read it.
    var rec: [140]u8 = [_]u8{0} ** 140;
    std.mem.writeInt(u32, rec[0..4], 999, .little);
    try db.put(storage.CF_BLOCK_INDEX, &fp_hash, &rec);

    var rec2: [140]u8 = [_]u8{0} ** 140;
    std.mem.writeInt(u32, rec2[0..4], 1000, .little);
    std.mem.writeInt(u32, rec2[4 + 72 ..][0..4], 0x207fffff, .little); // bits
    try db.put(storage.CF_BLOCK_INDEX, &stale_tip, &rec2);

    // Height->hash rows for the same-scale walk (fp+1..best).
    const k1000 = storage.ChainStore.buildHeightHashKey(1000);
    try db.put(storage.CF_DEFAULT, &k1000, &stale_tip);

    cs.best_hash = stale_tip;
    cs.best_height = 1000;

    // The competing branch: 3 headers rooted at the fork point — one block
    // more work than our single stale block.
    var prev: [32]u8 = fp_hash;
    var fork_tip: types.Hash256 = undefined;
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        const b = try makeForkTestBlock(allocator, prev, @as(u8, @intCast(0xD0 + i)), 0x207fffff, 300 + i);
        try to_free.append(b.block);
        const ent = try pm.insertHeader(&b.block.header, &b.hash);
        try testing.expect(ent != null);
        prev = b.hash;
        fork_tip = b.hash;
    }

    var stub = makeStubPeer(&params, allocator);
    defer stub.recv_buffer.deinit();

    pm.maybeArmReorg(&stub, &fork_tip);

    // Pre-fix: fp read as height 0 -> depth 1000 > 288 -> refused + banned.
    try testing.expect(!stub.should_ban);
    try testing.expect(pm.pending_reorg != null);
    try testing.expectEqual(@as(usize, 3), pm.pending_reorg.?.fork_hashes.items.len);
}

// ── 2026-08-26 stall layers L3 + L4 ─────────────────────────────────────
// L1 (fork-point height misread) is pinned by the post-restart-race test
// above. These pin the other two silent layers: the single-hash locator
// (L3) and the silently-nulled competing branch root (L4). Both functions
// were extracted from live paths specifically so these tests exist; at the
// parent commit they fail to compile (method undef) — that is the A/B.

test "buildGetHeadersLocator: post-restart stale tip yields a real locator, not a single hash" {
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

    // Persisted active chain, tip at 1000; height->hash rows for 990..999.
    const tip: types.Hash256 = [_]u8{0xAB} ** 32;
    cs.best_hash = tip;
    cs.best_height = 1000;
    var h: u32 = 990;
    while (h <= 999) : (h += 1) {
        var hh: types.Hash256 = [_]u8{0} ** 32;
        std.mem.writeInt(u32, hh[0..4], h, .little);
        const k = storage.ChainStore.buildHeightHashKey(h);
        try db.put(storage.CF_DEFAULT, &k, &hh);
    }

    var locator = std.ArrayList(types.Hash256).init(allocator);
    defer locator.deinit();
    try pm.buildGetHeadersLocator(&locator);

    // The L3 regression sent exactly ONE hash — a stale tip no peer
    // recognizes, so peers served from genesis and the competing branch
    // could never arrive.
    try testing.expect(locator.items.len > 3);
    try testing.expect(std.mem.eql(u8, &locator.items[0], &tip));
    try testing.expect(std.mem.eql(
        u8,
        &locator.items[locator.items.len - 1],
        &params.genesis_hash,
    ));
    // ...and it must actually walk the persisted chain below the tip.
    var h999: types.Hash256 = [_]u8{0} ** 32;
    std.mem.writeInt(u32, h999[0..4], 999, .little);
    var found = false;
    for (locator.items) |it| {
        if (std.mem.eql(u8, &it, &h999)) found = true;
    }
    try testing.expect(found);
}

test "seedForkRootParent: root parent on the persisted active chain is seeded" {
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

    // Our own block at height 1000 exists ONLY in persisted storage —
    // header_index is empty, the post-restart state that silently nulled
    // the whole 53-header branch on 2026-08-26.
    const want: types.Hash256 = [_]u8{0xC7} ** 32;
    cs.best_hash = want;
    cs.best_height = 1000;
    const k1000 = storage.ChainStore.buildHeightHashKey(1000);
    try db.put(storage.CF_DEFAULT, &k1000, &want);
    var rec: [140]u8 = [_]u8{0} ** 140;
    std.mem.writeInt(u32, rec[0..4], 1000, .little);
    std.mem.writeInt(u32, rec[4 + 72 ..][0..4], 0x207fffff, .little); // bits
    try db.put(storage.CF_BLOCK_INDEX, &want, &rec);

    try testing.expect(pm.header_index.get(want) == null);
    try testing.expect(pm.seedForkRootParent(want));
    const ent = pm.header_index.get(want) orelse return error.TestExpectedSeededEntry;
    try testing.expectEqual(@as(u32, 1000), ent.height);
    // Idempotent: a second call must not re-insert.
    try testing.expect(!pm.seedForkRootParent(want));
}

test "seedForkRootParent: hash not on the active chain is refused" {
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

    const ours: types.Hash256 = [_]u8{0xC7} ** 32;
    cs.best_hash = ours;
    cs.best_height = 1000;
    const k1000 = storage.ChainStore.buildHeightHashKey(1000);
    try db.put(storage.CF_DEFAULT, &k1000, &ours);

    // An attacker-supplied parent that is NOT one of our blocks must never
    // be seeded — that would let a fork root itself anywhere.
    const stranger: types.Hash256 = [_]u8{0x5A} ** 32;
    try testing.expect(!pm.seedForkRootParent(stranger));
    try testing.expect(pm.header_index.get(stranger) == null);
}

// ====================================================================
// Invalid block over P2P (2026-10-03): Core InvalidBlockFound /
// InvalidChainFound / MaybePunishNodeForBlock parity.
//
// Real regtest blocks (valid PoW, BIP-34, subsidy) driven through the real
// `.headers` / `.block` handlers, the drain, and the reorg trigger.
// ====================================================================

const IbBlock = struct { block: types.Block, hash: types.Hash256 };

/// Coinbase-only regtest block at `height` (<= 16) on `prev`, paying
/// subsidy + `overpay` sat.  `tag` makes same-height siblings distinct.
fn mineIbBlock(
    allocator: std.mem.Allocator,
    params: *const consensus.NetworkParams,
    prev: types.Hash256,
    height: u32,
    overpay: i64,
    tag: u8,
) !IbBlock {
    std.debug.assert(height >= 1 and height <= 16);
    const script_sig = try allocator.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag });
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const spk = try allocator.dupe(u8, &[_]u8{0x51});
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000 + overpay, .script_pubkey = spk };
    const txs = try allocator.alloc(types.Transaction, 1);
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeTxid(&txs[0], allocator),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

/// Heap deep copy (the handlers take ownership of what they are given).
fn cloneIbBlock(allocator: std.mem.Allocator, b: *const types.Block) !types.Block {
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readBlock(&r, allocator);
}

fn sendHeaders(pm: *peer_mod.PeerManager, allocator: std.mem.Allocator, from: *peer_mod.Peer, blocks: []const *const IbBlock) !void {
    const hs = try allocator.alloc(types.BlockHeader, blocks.len);
    for (blocks, 0..) |b, i| hs[i] = b.block.header;
    try pm.ingestHeadersMessage(from, hs);
}

fn sendBlock(pm: *peer_mod.PeerManager, allocator: std.mem.Allocator, from: *peer_mod.Peer, b: *const IbBlock) !void {
    try pm.ingestBlockMessage(from, try cloneIbBlock(allocator, &b.block));
}

fn ibPeer(params: *const consensus.NetworkParams, allocator: std.mem.Allocator, ip_last: u8, dir: peer_mod.PeerDirection) !*peer_mod.Peer {
    const p = try allocator.create(peer_mod.Peer);
    p.* = makeStubPeer(params, allocator);
    p.address = std.net.Address.initIp4([4]u8{ 127, 0, 0, ip_last }, 18444);
    p.direction = dir;
    p.conn_type = if (dir == .inbound) .inbound else .outbound_full_relay;
    return p;
}

fn freeIbPeer(allocator: std.mem.Allocator, p: *peer_mod.Peer) void {
    p.recv_buffer.deinit();
    allocator.destroy(p);
}

fn countQueued(pm: *const peer_mod.PeerManager, h: types.Hash256) usize {
    var n: usize = 0;
    var i = pm.connect_cursor;
    while (i < pm.expected_blocks.items.len) : (i += 1) {
        if (std.mem.eql(u8, &pm.expected_blocks.items[i], &h)) n += 1;
    }
    return n;
}

test "tests_reorg_p2p: invalid block from X is marked failed, never re-queued; only X punished; valid sibling then connects" {
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
    cs.setNetworkParams(&params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    pm.chain_state = &cs;

    const h_peer = try ibPeer(&params, allocator, 3, .outbound);
    defer freeIbPeer(allocator, h_peer);
    const x_peer = try ibPeer(&params, allocator, 2, .inbound);
    defer freeIbPeer(allocator, x_peer);
    const x_redial = try ibPeer(&params, allocator, 2, .inbound);
    defer freeIbPeer(allocator, x_redial);
    try pm.peers.append(h_peer);
    try pm.peers.append(x_peer);
    try pm.peers.append(x_redial);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    var b1_bad = try mineIbBlock(allocator, &params, a1.hash, 2, 1, 0xBB); // bad-cb-amount
    defer serialize.freeBlock(allocator, &b1_bad.block);
    var b2_child = try mineIbBlock(allocator, &params, b1_bad.hash, 3, 0, 0xBC);
    defer serialize.freeBlock(allocator, &b2_child.block);
    var b1_ok = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0x11);
    defer serialize.freeBlock(allocator, &b1_ok.block);
    var b2_ok = try mineIbBlock(allocator, &params, b1_ok.hash, 3, 0, 0x12);
    defer serialize.freeBlock(allocator, &b2_ok.block);

    // Honest prefix: A1 from H.
    try sendHeaders(&pm, allocator, h_peer, &.{&a1});
    try sendBlock(&pm, allocator, h_peer, &a1);
    try testing.expectEqual(@as(u32, 1), cs.best_height);

    // X announces + delivers the invalid B1.
    try sendHeaders(&pm, allocator, x_peer, &.{&b1_bad});
    try testing.expectEqual(@as(usize, 1), countQueued(&pm, b1_bad.hash));
    try sendBlock(&pm, allocator, x_peer, &b1_bad);

    // Verdict: tip unchanged, B1 BLOCK_FAILED_VALID, out of the connect queue
    // (so it is never requested again), deliverer punished, H not.
    try testing.expectEqual(@as(u32, 1), cs.best_height);
    try testing.expectEqualSlices(u8, &a1.hash, &cs.best_hash);
    try testing.expect(!cs.flush_error);
    try testing.expect(pm.isBlockFailed(&b1_bad.hash));
    try testing.expectEqual(@as(usize, 0), countQueued(&pm, b1_bad.hash));
    try testing.expect(!pm.inflight_block_peer.contains(b1_bad.hash));
    try testing.expect(x_peer.should_ban);
    try testing.expect(!h_peer.should_ban);

    // X redials (inbound) and re-announces B1: BLOCK_CACHED_INVALID — not
    // queued, not fetched, inbound announcer NOT punished.
    try sendHeaders(&pm, allocator, x_redial, &.{&b1_bad});
    try testing.expectEqual(@as(usize, 0), countQueued(&pm, b1_bad.hash));
    try testing.expect(!x_redial.should_ban);
    // ...and the same headers batch extended by a child of B1: still cut at
    // B1 (cached-invalid, inbound) and the child never queued.
    try sendHeaders(&pm, allocator, x_redial, &.{ &b1_bad, &b2_child });
    try testing.expectEqual(@as(usize, 0), countQueued(&pm, b2_child.hash));
    try testing.expect(!x_redial.should_ban);

    // The honest sibling B1' then B2' connect (most-work valid chain).
    try sendHeaders(&pm, allocator, h_peer, &.{&b1_ok});
    try sendBlock(&pm, allocator, h_peer, &b1_ok);
    try testing.expectEqual(@as(u32, 2), cs.best_height);
    try testing.expectEqualSlices(u8, &b1_ok.hash, &cs.best_hash);
    try sendHeaders(&pm, allocator, h_peer, &.{&b2_ok});
    try sendBlock(&pm, allocator, h_peer, &b2_ok);
    try testing.expectEqual(@as(u32, 3), cs.best_height);
    try testing.expectEqualSlices(u8, &b2_ok.hash, &cs.best_hash);
    try testing.expect(!h_peer.should_ban);
}

test "tests_reorg_p2p: header building on a failed block is bad-prevblk (marked, punished); outbound cached-invalid announcer punished" {
    const allocator = testing.allocator;
    const params = consensus.REGTEST;
    var pm = peer_mod.PeerManager.init(allocator, &params);
    defer pm.deinit();

    const out_peer = try ibPeer(&params, allocator, 4, .outbound);
    defer freeIbPeer(allocator, out_peer);
    const in_peer = try ibPeer(&params, allocator, 5, .inbound);
    defer freeIbPeer(allocator, in_peer);

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    var bad = try mineIbBlock(allocator, &params, a1.hash, 2, 1, 0xBB);
    defer serialize.freeBlock(allocator, &bad.block);
    var child = try mineIbBlock(allocator, &params, bad.hash, 3, 0, 0xBC);
    defer serialize.freeBlock(allocator, &child.block);

    try pm.failed_blocks.put(bad.hash, {});
    const hs = [_]types.BlockHeader{ a1.block.header, bad.block.header, child.block.header };
    const c1 = pm.failedHeaderCut(&hs);
    try testing.expectEqual(@as(usize, 1), c1.index);
    try testing.expectEqual(peer_mod.FailedHeaderReason.cached_invalid, c1.reason);
    const only_child = [_]types.BlockHeader{child.block.header};
    const c2 = pm.failedHeaderCut(&only_child);
    try testing.expectEqual(@as(usize, 0), c2.index);
    try testing.expectEqual(peer_mod.FailedHeaderReason.invalid_prev, c2.reason);
    try testing.expect(pm.isBlockFailed(&child.hash)); // BLOCK_FAILED_CHILD

    // Through the handler: an OUTBOUND peer announcing a cached-invalid block
    // is punished (Core MaybePunishNodeForBlock BLOCK_CACHED_INVALID), an
    // inbound one is not.
    try sendHeaders(&pm, allocator, in_peer, &.{&bad});
    try testing.expect(!in_peer.should_ban);
    try sendHeaders(&pm, allocator, out_peer, &.{&bad});
    try testing.expect(out_peer.should_ban);
}

test "tests_reorg_p2p: failed reorg onto an invalid branch rolls back, punishes only the deliverer, honest extension connects" {
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
    cs.setNetworkParams(&params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    pm.chain_state = &cs;

    const h_peer = try ibPeer(&params, allocator, 3, .outbound);
    defer freeIbPeer(allocator, h_peer);
    const x_peer = try ibPeer(&params, allocator, 2, .inbound);
    defer freeIbPeer(allocator, x_peer);
    try pm.peers.append(h_peer);
    try pm.peers.append(x_peer);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    var b1_ok = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0x11);
    defer serialize.freeBlock(allocator, &b1_ok.block);
    var b2_ok = try mineIbBlock(allocator, &params, b1_ok.hash, 3, 0, 0x12);
    defer serialize.freeBlock(allocator, &b2_ok.block);
    var b1_bad = try mineIbBlock(allocator, &params, a1.hash, 2, 1, 0xBB);
    defer serialize.freeBlock(allocator, &b1_bad.block);
    var b2x = try mineIbBlock(allocator, &params, b1_bad.hash, 3, 0, 0xBC);
    defer serialize.freeBlock(allocator, &b2x.block);

    // Honest chain A1, B1' from H; tip = B1' (h2).
    try sendHeaders(&pm, allocator, h_peer, &.{ &a1, &b1_ok });
    try sendBlock(&pm, allocator, h_peer, &a1);
    try sendBlock(&pm, allocator, h_peer, &b1_ok);
    try testing.expectEqual(@as(u32, 2), cs.best_height);
    const utxos_before = cs.utxo_set.total_utxos;

    // X: [B1, B2x] — heavier branch through the invalid B1.  It arms a reorg
    // and X delivers both bodies.
    try sendHeaders(&pm, allocator, x_peer, &.{ &b1_bad, &b2x });
    try testing.expect(pm.pending_reorg != null);
    try sendBlock(&pm, allocator, x_peer, &b1_bad);
    try sendBlock(&pm, allocator, x_peer, &b2x);

    // The reorg failed on B1: chainstate rolled back and LIVE (no sticky
    // flush_error), tip still B1', B1 failed + B2x failed-child, only X
    // punished.
    try testing.expect(pm.pending_reorg == null);
    try testing.expect(!cs.flush_error);
    try testing.expect(cs.last_reorg_rolled_back);
    try testing.expectEqual(@as(u32, 2), cs.best_height);
    try testing.expectEqualSlices(u8, &b1_ok.hash, &cs.best_hash);
    try testing.expectEqual(utxos_before, cs.utxo_set.total_utxos);
    try testing.expect(pm.isBlockFailed(&b1_bad.hash));
    try testing.expect(pm.isBlockFailed(&b2x.hash));
    try testing.expect(x_peer.should_ban);
    try testing.expect(!h_peer.should_ban);
    // B1' coinbase is spendable again (UTXO view restored from the DB).
    const b1_ok_cb = types.OutPoint{ .hash = try crypto.computeTxid(&b1_ok.block.transactions[0], allocator), .index = 0 };
    var coin = (try cs.utxo_set.get(&b1_ok_cb)) orelse return error.TestExpectedCoin;
    coin.deinit(allocator);

    // A re-announcement of the failed branch does not re-arm.
    try sendHeaders(&pm, allocator, x_peer, &.{ &b1_bad, &b2x });
    try testing.expect(pm.pending_reorg == null);

    // H announces its branch from the shared prefix, [B1', B2'] (the
    // instrument's shape): B2' arrives through the reorg-trigger path (fork
    // point = the active tip B1').  H never punished.
    try sendHeaders(&pm, allocator, h_peer, &.{ &b1_ok, &b2_ok });
    try sendBlock(&pm, allocator, h_peer, &b2_ok);
    try testing.expectEqual(@as(u32, 3), cs.best_height);
    try testing.expectEqualSlices(u8, &b2_ok.hash, &cs.best_hash);
    try testing.expect(!h_peer.should_ban);

    // The same B2' re-announced (headers + body) must not be "connected"
    // again on top of itself and condemned (queue re-based on the new tip);
    // the next honest block extends normally.
    var b3_ok = try mineIbBlock(allocator, &params, b2_ok.hash, 4, 0, 0x13);
    defer serialize.freeBlock(allocator, &b3_ok.block);
    try sendHeaders(&pm, allocator, h_peer, &.{&b2_ok});
    try sendHeaders(&pm, allocator, h_peer, &.{&b3_ok});
    try sendBlock(&pm, allocator, h_peer, &b3_ok);
    try testing.expectEqual(@as(u32, 4), cs.best_height);
    try testing.expectEqualSlices(u8, &b3_ok.hash, &cs.best_hash);
    try testing.expect(!pm.isBlockFailed(&b2_ok.hash));
    try testing.expect(!h_peer.should_ban);
}

fn bip30SelfDupSetup(allocator: std.mem.Allocator, pm: *peer_mod.PeerManager, cs: *storage.ChainState, params: *const consensus.NetworkParams) void {
    cs.wireUtxoParent();
    cs.setNetworkParams(params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    pm.chain_state = cs;
    _ = allocator;
}

// The 2026-10-05 fast-P2P-sync wedge, deterministically: H announces A2
// (queued, body not yet here), then re-announces the OVERLAPPING batch
// [A2, A3].  Pre-fix the overlap was classified as a fork rooted at A1, a
// "reorg" over [A2, A3] was armed, the drain connected A2, the reorg then
// disconnected and re-connected A2 -> Bip30DuplicateOutput on A2's own
// coinbase -> A2 (valid) BLOCK_FAILED_VALID, H punished, node wedged.
test "tests_reorg_p2p: bip30-self-dup — an overlapping header batch EXTENDS the tip (no fork, no reorg, valid blocks never marked)" {
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
    bip30SelfDupSetup(allocator, &pm, &cs, &params);

    const h_peer = try ibPeer(&params, allocator, 3, .outbound);
    defer freeIbPeer(allocator, h_peer);
    try pm.peers.append(h_peer);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    var a2 = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0xA2);
    defer serialize.freeBlock(allocator, &a2.block);
    var a3 = try mineIbBlock(allocator, &params, a2.hash, 3, 0, 0xA3);
    defer serialize.freeBlock(allocator, &a3.block);
    var a4 = try mineIbBlock(allocator, &params, a3.hash, 4, 0, 0xA4);
    defer serialize.freeBlock(allocator, &a4.block);

    try sendHeaders(&pm, allocator, h_peer, &.{&a1});
    try sendBlock(&pm, allocator, h_peer, &a1);
    try testing.expectEqual(@as(u32, 1), cs.best_height);

    try sendHeaders(&pm, allocator, h_peer, &.{&a2}); // queued, body in flight
    const fork_before = pm.reorg_candidate_announcements;
    try sendHeaders(&pm, allocator, h_peer, &.{ &a2, &a3 }); // overlapping batch
    try testing.expectEqual(fork_before, pm.reorg_candidate_announcements); // NOT a fork
    try testing.expect(pm.pending_reorg == null);
    try testing.expectEqual(@as(usize, 1), countQueued(&pm, a2.hash));
    try testing.expectEqual(@as(usize, 1), countQueued(&pm, a3.hash));

    // Bodies arrive (A2 twice, as when a reorg getdata re-requested it).
    try sendBlock(&pm, allocator, h_peer, &a2);
    try sendBlock(&pm, allocator, h_peer, &a2);
    try sendBlock(&pm, allocator, h_peer, &a3);
    try testing.expectEqual(@as(u32, 3), cs.best_height);
    try testing.expectEqualSlices(u8, &a3.hash, &cs.best_hash);

    // A batch overlapping the ACTIVE chain ([A2, A3, A4] with A2, A3
    // connected) is an extension by A4 too.
    try sendHeaders(&pm, allocator, h_peer, &.{ &a2, &a3, &a4 });
    try testing.expectEqual(fork_before, pm.reorg_candidate_announcements);
    try testing.expect(pm.pending_reorg == null);
    try sendBlock(&pm, allocator, h_peer, &a4);
    try testing.expectEqual(@as(u32, 4), cs.best_height);
    try testing.expectEqualSlices(u8, &a4.hash, &cs.best_hash);

    // A pure re-announcement of known headers is a no-op.
    try sendHeaders(&pm, allocator, h_peer, &.{ &a3, &a4 });
    try testing.expectEqual(fork_before, pm.reorg_candidate_announcements);

    try testing.expect(!pm.isBlockFailed(&a2.hash));
    try testing.expect(!pm.isBlockFailed(&a3.hash));
    try testing.expect(!pm.isBlockFailed(&a4.hash));
    try testing.expect(!h_peer.should_ban);
    try testing.expect(!cs.flush_error);
    try testing.expect(pm.committed_header_prefix_skips >= 2);
}

// Fix (2) in isolation: a pending reorg whose fork point went stale (the
// leading fork block got connected by the drain after the reorg was armed)
// must advance its fork point — never disconnect + re-connect that block.
test "tests_reorg_p2p: bip30-self-dup — a pending reorg never re-connects a fork block already on the active chain" {
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
    bip30SelfDupSetup(allocator, &pm, &cs, &params);

    const h_peer = try ibPeer(&params, allocator, 3, .outbound);
    defer freeIbPeer(allocator, h_peer);
    try pm.peers.append(h_peer);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    var a2 = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0xA2);
    defer serialize.freeBlock(allocator, &a2.block);
    var a3 = try mineIbBlock(allocator, &params, a2.hash, 3, 0, 0xA3);
    defer serialize.freeBlock(allocator, &a3.block);

    try sendHeaders(&pm, allocator, h_peer, &.{ &a1, &a2 });
    try sendBlock(&pm, allocator, h_peer, &a1);
    try sendBlock(&pm, allocator, h_peer, &a2);
    try testing.expectEqual(@as(u32, 2), cs.best_height);

    // A reorg armed from A1 over [A2, A3] (stale: A2 is now the tip), with
    // both bodies buffered.
    var hashes = std.ArrayList(types.Hash256).init(allocator);
    try hashes.append(a2.hash);
    try hashes.append(a3.hash);
    pm.pending_reorg = .{
        .fork_point = a1.hash,
        .fork_hashes = hashes,
        .new_tip_chain_work = [_]u8{0xFF} ** 32,
        .source_peer = h_peer,
    };
    try pm.block_buffer.put(a2.hash, try cloneIbBlock(allocator, &a2.block));
    try pm.block_buffer.put(a3.hash, try cloneIbBlock(allocator, &a3.block));
    pm.tryFireReorg();

    try testing.expect(pm.pending_reorg == null);
    try testing.expectEqual(@as(u32, 3), cs.best_height);
    try testing.expectEqualSlices(u8, &a3.hash, &cs.best_hash);
    try testing.expect(!pm.isBlockFailed(&a2.hash));
    try testing.expect(!pm.isBlockFailed(&a3.hash));
    try testing.expect(!h_peer.should_ban);
    try testing.expect(!cs.flush_error);
    try testing.expectEqual(@as(u64, 1), pm.reorg_active_prefix_trims);
    try testing.expect(!pm.block_buffer.contains(a2.hash));
}

test "tests_reorg_p2p: NON-verdict — a mutated copy (unexpected witness) punishes the sender but does NOT mark the block; the genuine copy connects" {
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
    cs.setNetworkParams(&params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    pm.chain_state = &cs;

    const h_peer = try ibPeer(&params, allocator, 3, .outbound);
    defer freeIbPeer(allocator, h_peer);
    const x_peer = try ibPeer(&params, allocator, 2, .inbound);
    defer freeIbPeer(allocator, x_peer);
    try pm.peers.append(h_peer);
    try pm.peers.append(x_peer);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    var b1 = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0x11);
    defer serialize.freeBlock(allocator, &b1.block);

    try sendHeaders(&pm, allocator, h_peer, &.{&a1});
    try sendBlock(&pm, allocator, h_peer, &a1);
    try sendHeaders(&pm, allocator, h_peer, &.{&b1});

    // Mutated copy: same header (same hash), coinbase witness with no
    // commitment -> UnexpectedWitness (Core CheckWitnessMalleation,
    // BLOCK_MUTATED).
    var mutated = try cloneIbBlock(allocator, &b1.block);
    const wit = try allocator.alloc([]const u8, 1);
    wit[0] = try allocator.dupe(u8, &([_]u8{0} ** 32));
    @constCast(&mutated.transactions[0].inputs[0]).witness = wit;
    try testing.expectEqualSlices(u8, &b1.hash, &crypto.computeBlockHash(&mutated.header));
    try pm.ingestBlockMessage(x_peer, mutated);

    try testing.expectEqual(@as(u32, 1), cs.best_height);
    try testing.expect(x_peer.should_ban); // deliverer of the mutated copy
    try testing.expect(!pm.isBlockFailed(&b1.hash)); // the HASH is not condemned
    try testing.expectEqual(@as(usize, 1), countQueued(&pm, b1.hash)); // still wanted

    try sendBlock(&pm, allocator, h_peer, &b1);
    try testing.expectEqual(@as(u32, 2), cs.best_height);
    try testing.expectEqualSlices(u8, &b1.hash, &cs.best_hash);
    try testing.expect(!h_peer.should_ban);
}

test "tests_reorg_p2p: classifyBlockFailure maps errors onto Core's verdict classes" {
    const C = peer_mod.classifyBlockFailure;
    const K = peer_mod.BlockFailureKind;
    try testing.expectEqual(K.consensus_invalid, C(error.BadCoinbaseValue));
    try testing.expectEqual(K.consensus_invalid, C(error.NonFinalTx));
    try testing.expectEqual(K.consensus_invalid, C(error.SequenceLockNotSatisfied));
    try testing.expectEqual(K.consensus_invalid, C(error.ScriptVerificationFailed));
    try testing.expectEqual(K.mutated, C(error.BadMerkleRoot));
    try testing.expectEqual(K.mutated, C(error.DuplicateTx));
    try testing.expectEqual(K.mutated, C(error.BadWitnessCommitment));
    try testing.expectEqual(K.mutated, C(error.BadWitnessNonceSize));
    try testing.expectEqual(K.mutated, C(error.UnexpectedWitness));
    try testing.expectEqual(K.not_a_verdict, C(error.OutOfMemory));
    try testing.expectEqual(K.not_a_verdict, C(error.TooFarAhead));
    try testing.expectEqual(K.not_a_verdict, C(error.TooLittleChainwork));
    try testing.expectEqual(K.not_a_verdict, C(error.FutureTimestamp));
}

// ====================================================================
// A UTXO READ FAILURE is a local fault, not a verdict.
//
// Core: CCoinsViewErrorCatcher::GetCoin turns a coins-DB read failure into
// "Error reading from database, shutting down." + abort; the block is never
// marked BLOCK_FAILED_VALID and no peer is punished.  A coin that is genuinely
// absent IS a verdict (bad-txns-inputs-missingorspent).
//
// The fault is real, not mocked: the spent coin's CF_UTXO record is replaced by
// one undecodable byte, so UtxoSet.get fails in CompactUtxo.decode exactly as
// for a damaged record.  Before this fix both lookup adapters (P2P drain and
// reorg connect) did `utxo_set.get(..) catch return null`, so the coin read as
// MISSING -> MissingInput -> consensus_invalid: block marked failed, sender
// banned.  Each scenario runs twice: `.corrupt` (read error) and `.absent`
// (truly missing — the positive control that must still be a verdict).
// ====================================================================

const CoinState = enum { corrupt, absent };

fn ghostOutpoint(tag: u8) types.OutPoint {
    var h = [_]u8{0} ** 32;
    h[0] = 0xAB;
    h[1] = tag;
    return .{ .hash = h, .index = 0 };
}

/// Regtest block at `height` (<= 16) on `prev`: a valid coinbase plus one tx
/// spending `spend`.
fn mineIbBlockSpending(
    allocator: std.mem.Allocator,
    params: *const consensus.NetworkParams,
    prev: types.Hash256,
    height: u32,
    tag: u8,
    spend: types.OutPoint,
) !IbBlock {
    std.debug.assert(height >= 1 and height <= 16);
    const txs = try allocator.alloc(types.Transaction, 2);
    {
        const inputs = try allocator.alloc(types.TxIn, 1);
        inputs[0] = .{
            .previous_output = types.OutPoint.COINBASE,
            .script_sig = try allocator.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag }),
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };
        const outputs = try allocator.alloc(types.TxOut, 1);
        outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = try allocator.dupe(u8, &[_]u8{0x51}) };
        txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    }
    {
        const inputs = try allocator.alloc(types.TxIn, 1);
        inputs[0] = .{
            .previous_output = spend,
            .script_sig = try allocator.dupe(u8, &[_]u8{0x51}),
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        };
        const outputs = try allocator.alloc(types.TxOut, 1);
        outputs[0] = .{ .value = 1000, .script_pubkey = try allocator.dupe(u8, &[_]u8{0x51}) };
        txs[1] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    }
    const ids = [_]types.Hash256{
        try crypto.computeTxid(&txs[0], allocator),
        try crypto.computeTxid(&txs[1], allocator),
    };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeMerkleRoot(&ids, allocator),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

fn setCoinState(db: *storage.Database, cs: *storage.ChainState, op: types.OutPoint, state: CoinState) !void {
    const key = storage.makeUtxoKey(&op);
    switch (state) {
        .corrupt => {
            try db.put(storage.CF_UTXO, &key, &[_]u8{0x01});
            // Instrument check: the fault is live — the raw read errors.
            if (cs.utxo_set.get(&op)) |got| {
                if (got) |c| {
                    var cc = c;
                    cc.deinit(cs.allocator);
                }
                return error.TestFaultNotInjected;
            } else |_| {}
        },
        .absent => {
            const got = try cs.utxo_set.get(&op);
            try testing.expect(got == null);
        },
    }
}

fn runTipExtensionReadFault(state: CoinState) !void {
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
    cs.setNetworkParams(&params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    pm.chain_state = &cs;

    const h_peer = try ibPeer(&params, allocator, 3, .outbound);
    defer freeIbPeer(allocator, h_peer);
    const x_peer = try ibPeer(&params, allocator, 2, .inbound);
    defer freeIbPeer(allocator, x_peer);
    try pm.peers.append(h_peer);
    try pm.peers.append(x_peer);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    const ghost = ghostOutpoint(0xE1);
    var b1 = try mineIbBlockSpending(allocator, &params, a1.hash, 2, 0xE1, ghost);
    defer serialize.freeBlock(allocator, &b1.block);

    try sendHeaders(&pm, allocator, h_peer, &.{&a1});
    try sendBlock(&pm, allocator, h_peer, &a1);
    try testing.expectEqual(@as(u32, 1), cs.best_height);

    try setCoinState(&db, &cs, ghost, state);
    try sendHeaders(&pm, allocator, x_peer, &.{&b1});
    try sendBlock(&pm, allocator, x_peer, &b1);

    try testing.expectEqual(@as(u32, 1), cs.best_height);
    switch (state) {
        .corrupt => {
            // PRE-FIX: marked failed, dropped from the queue, X banned.
            try testing.expectEqual(@as(?validation.ValidationError, error.UtxoReadError), pm.last_block_reject_err);
            try testing.expect(!pm.isBlockFailed(&b1.hash));
            try testing.expect(!x_peer.should_ban);
            try testing.expectEqual(@as(usize, 1), countQueued(&pm, b1.hash)); // retried
        },
        .absent => {
            try testing.expectEqual(@as(?validation.ValidationError, error.MissingInput), pm.last_block_reject_err);
            try testing.expect(pm.isBlockFailed(&b1.hash));
            try testing.expect(x_peer.should_ban);
            try testing.expectEqual(@as(usize, 0), countQueued(&pm, b1.hash));
        },
    }
    try testing.expect(!h_peer.should_ban);
}

fn runReorgReadFault(state: CoinState) !void {
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
    cs.setNetworkParams(&params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    pm.chain_state = &cs;

    const h_peer = try ibPeer(&params, allocator, 3, .outbound);
    defer freeIbPeer(allocator, h_peer);
    const x_peer = try ibPeer(&params, allocator, 2, .inbound);
    defer freeIbPeer(allocator, x_peer);
    try pm.peers.append(h_peer);
    try pm.peers.append(x_peer);
    defer pm.peers.clearRetainingCapacity();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    var b1_ok = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0x11);
    defer serialize.freeBlock(allocator, &b1_ok.block);
    var b2_ok = try mineIbBlock(allocator, &params, b1_ok.hash, 3, 0, 0x12);
    defer serialize.freeBlock(allocator, &b2_ok.block);
    const ghost = ghostOutpoint(0xE2);
    var b1_x = try mineIbBlockSpending(allocator, &params, a1.hash, 2, 0xE2, ghost);
    defer serialize.freeBlock(allocator, &b1_x.block);
    var b2x = try mineIbBlock(allocator, &params, b1_x.hash, 3, 0, 0xE3);
    defer serialize.freeBlock(allocator, &b2x.block);

    try sendHeaders(&pm, allocator, h_peer, &.{ &a1, &b1_ok });
    try sendBlock(&pm, allocator, h_peer, &a1);
    try sendBlock(&pm, allocator, h_peer, &b1_ok);
    try testing.expectEqual(@as(u32, 2), cs.best_height);
    const utxos_before = cs.utxo_set.total_utxos;

    try setCoinState(&db, &cs, ghost, state);
    try sendHeaders(&pm, allocator, x_peer, &.{ &b1_x, &b2x });
    try testing.expect(pm.pending_reorg != null);
    try sendBlock(&pm, allocator, x_peer, &b1_x);
    try sendBlock(&pm, allocator, x_peer, &b2x);

    // Either way the reorg is abandoned and rolled back cleanly.
    try testing.expect(pm.pending_reorg == null);
    try testing.expect(!cs.flush_error);
    try testing.expect(cs.last_reorg_rolled_back);
    try testing.expectEqual(@as(u32, 2), cs.best_height);
    try testing.expectEqualSlices(u8, &b1_ok.hash, &cs.best_hash);
    try testing.expectEqual(utxos_before, cs.utxo_set.total_utxos);
    switch (state) {
        .corrupt => {
            // PRE-FIX: MissingInput -> ReorgBlockInvalid -> both marked, X banned.
            try testing.expect(!pm.isBlockFailed(&b1_x.hash));
            try testing.expect(!pm.isBlockFailed(&b2x.hash));
            try testing.expect(!x_peer.should_ban);
        },
        .absent => {
            try testing.expect(pm.isBlockFailed(&b1_x.hash));
            try testing.expect(pm.isBlockFailed(&b2x.hash));
            try testing.expect(x_peer.should_ban);
        },
    }
    try testing.expect(!h_peer.should_ban);

    // The honest extension still connects.
    try sendHeaders(&pm, allocator, h_peer, &.{ &b1_ok, &b2_ok });
    try sendBlock(&pm, allocator, h_peer, &b2_ok);
    try testing.expectEqual(@as(u32, 3), cs.best_height);
    try testing.expectEqualSlices(u8, &b2_ok.hash, &cs.best_hash);
}

test "tests_reorg_p2p: UTXO read error at the tip extension is NOT a verdict (not marked, sender not punished, retried)" {
    try runTipExtensionReadFault(.corrupt);
}

test "tests_reorg_p2p: control — a truly missing input at the tip extension IS a verdict (marked, sender punished)" {
    try runTipExtensionReadFault(.absent);
}

test "tests_reorg_p2p: UTXO read error inside a reorg is NOT a verdict (rolled back, nothing marked, nobody punished)" {
    try runReorgReadFault(.corrupt);
}

test "tests_reorg_p2p: control — a truly missing input inside a reorg IS a verdict (fork marked, deliverer punished)" {
    try runReorgReadFault(.absent);
}

test "tests_reorg_p2p: classifyBlockFailure — UtxoReadError is not a verdict, MissingInput is" {
    try testing.expectEqual(peer_mod.BlockFailureKind.not_a_verdict, peer_mod.classifyBlockFailure(error.UtxoReadError));
    try testing.expectEqual(peer_mod.BlockFailureKind.consensus_invalid, peer_mod.classifyBlockFailure(error.MissingInput));
}

// ====================================================================
// Gate 6 (receipts/gate6-resource-limit-audit-2026-10-04.md, clearbit):
// a SYSTEM fault while validating or connecting a block — no usable secp
// context, a failed chainstate write, a block-index read error — is never a
// verdict.  The block is not marked, its sender is not punished, it is never
// ACCEPTED on the strength of a check that did not run; the fault is retried
// once and a second fault on the same block latches the node (fatal.zig,
// Core AbortNode).  Each fault test has a fault-free CONTROL showing the
// verdict for a genuinely invalid block is unchanged.
//
// Faults are injected through test-only hooks compiled out of non-test
// builds: crypto.test_fault_secp_unavailable, storage.Database
// .fault_write_batch_failures / .fault_get_cf_mask.
// ====================================================================

const fatal = @import("fatal.zig");
const secp_c = @import("secp.zig").c;
const script_mod = @import("script.zig");

const G6Key = struct { seckey: [32]u8, pubkey: [33]u8 };

fn g6Key(ctx: *secp_c.secp256k1_context) !G6Key {
    var k = G6Key{ .seckey = [_]u8{0x37} ** 32, .pubkey = undefined };
    var pk: secp_c.secp256k1_pubkey = undefined;
    if (secp_c.secp256k1_ec_pubkey_create(ctx, &pk, &k.seckey) != 1) return error.KeyFailed;
    var len: usize = 33;
    _ = secp_c.secp256k1_ec_pubkey_serialize(ctx, &k.pubkey, &len, &pk, secp_c.SECP256K1_EC_COMPRESSED);
    return k;
}

/// `<pk> CHECKSIG` or `<pk> CHECKSIG NOT`, heap-owned.
fn g6PkScript(allocator: std.mem.Allocator, key: *const G6Key, with_not: bool) ![]u8 {
    const s = try allocator.alloc(u8, if (with_not) 36 else 35);
    s[0] = 33;
    @memcpy(s[1..34], &key.pubkey);
    s[34] = 0xac;
    if (with_not) s[35] = 0x91;
    return s;
}

/// One-input spend of `prevout` (heap-owned slices, freed with the block).
fn g6SpendTx(allocator: std.mem.Allocator, prevout: types.OutPoint, version: i32, sequence: u32) !types.Transaction {
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = prevout,
        .script_sig = try allocator.dupe(u8, &[_]u8{0x51}),
        .sequence = sequence,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 40_000, .script_pubkey = try allocator.dupe(u8, &[_]u8{0x51}) };
    return .{ .version = version, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
}

/// Sign input 0 of `tx` for `coin_spk` (legacy SIGHASH_ALL); `corrupt` makes
/// the signature well-formed DER that does not verify.
fn g6Sign(allocator: std.mem.Allocator, ctx: *secp_c.secp256k1_context, key: *const G6Key, tx: *types.Transaction, coin_spk: []const u8, corrupt: bool) !void {
    const sh = try script_mod.legacySignatureHash(allocator, tx, 0, coin_spk, 1);
    var sig: secp_c.secp256k1_ecdsa_signature = undefined;
    if (secp_c.secp256k1_ecdsa_sign(ctx, &sig, &sh, &key.seckey, null, null) != 1) return error.SignFailed;
    var der: [72]u8 = undefined;
    var len: usize = 72;
    _ = secp_c.secp256k1_ecdsa_signature_serialize_der(ctx, &der, &len, &sig);
    if (corrupt) der[len - 2] ^= 0x01;
    const ss = try allocator.alloc(u8, len + 2);
    ss[0] = @intCast(len + 1);
    @memcpy(ss[1 .. 1 + len], der[0..len]);
    ss[1 + len] = 0x01;
    allocator.free(tx.inputs[0].script_sig);
    @constCast(&tx.inputs[0]).script_sig = ss;
}

/// Regtest block at `height` (<= 16) on `prev`: coinbase + `spend`.
fn g6MineWithTx(allocator: std.mem.Allocator, params: *const consensus.NetworkParams, prev: types.Hash256, height: u32, tag: u8, spend: types.Transaction) !IbBlock {
    std.debug.assert(height >= 1 and height <= 16);
    const txs = try allocator.alloc(types.Transaction, 2);
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = try allocator.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag }),
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = try allocator.dupe(u8, &[_]u8{0x51}) };
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    txs[1] = spend;
    const ids = [_]types.Hash256{
        try crypto.computeTxid(&txs[0], allocator),
        try crypto.computeTxid(&txs[1], allocator),
    };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeMerkleRoot(&ids, allocator),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

/// A regtest node fixture (PeerManager + RocksDB chainstate in a tmp dir +
/// an honest outbound peer H and an inbound peer X).
const G6Node = struct {
    pm: peer_mod.PeerManager,
    tmp_dir: testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    h_peer: *peer_mod.Peer,
    x_peer: *peer_mod.Peer,

    fn init(self: *G6Node, params: *const consensus.NetworkParams) !void {
        const allocator = testing.allocator;
        self.pm = peer_mod.PeerManager.init(allocator, params);
        self.tmp_dir = testing.tmpDir(.{});
        self.path = try self.tmp_dir.dir.realpathAlloc(allocator, ".");
        self.db = try storage.Database.open(self.path, 64, allocator);
        self.cs = storage.ChainState.init(&self.db, 64, allocator);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(params);
        self.cs.best_hash = params.genesis_hash;
        self.cs.initGenesisTimestamp(params.genesis_header.timestamp);
        self.pm.chain_state = &self.cs;
        self.pm.data_dir = self.path; // keep anchors.dat / bans out of the cwd
        self.h_peer = try ibPeer(params, allocator, 3, .outbound);
        self.x_peer = try ibPeer(params, allocator, 2, .inbound);
        try self.pm.peers.append(self.h_peer);
        try self.pm.peers.append(self.x_peer);
    }

    fn deinit(self: *G6Node) void {
        const allocator = testing.allocator;
        self.pm.peers.clearRetainingCapacity();
        self.pm.deinit(); // writes anchors/bans under data_dir: before the dir goes
        freeIbPeer(allocator, self.x_peer);
        freeIbPeer(allocator, self.h_peer);
        self.cs.deinit();
        self.db.close();
        allocator.free(self.path);
        self.tmp_dir.cleanup();
    }
};

const G6Fault = enum { none, secp };

/// Tip extension: block 2 spends an injected coin whose script is
/// `<pk> CHECKSIG [NOT]` with a valid (or corrupted) signature.
fn runG6TipScriptFault(with_not: bool, corrupt_sig: bool, fault: G6Fault) !void {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const allocator = testing.allocator;
    const params = consensus.REGTEST;
    var n: G6Node = undefined;
    try n.init(&params);
    defer n.deinit();

    const ctx = secp_c.secp256k1_context_create(secp_c.SECP256K1_CONTEXT_SIGN | secp_c.SECP256K1_CONTEXT_VERIFY) orelse return error.SecpContextFailed;
    defer secp_c.secp256k1_context_destroy(ctx);
    const key = try g6Key(ctx);

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xA1);
    defer serialize.freeBlock(allocator, &a1.block);
    try sendHeaders(&n.pm, allocator, n.h_peer, &.{&a1});
    try sendBlock(&n.pm, allocator, n.h_peer, &a1);
    try testing.expectEqual(@as(u32, 1), n.cs.best_height);

    const coin = ghostOutpoint(0xC6);
    const coin_spk = try g6PkScript(allocator, &key, with_not);
    defer allocator.free(coin_spk);
    try n.cs.utxo_set.add(&coin, &types.TxOut{ .value = 50_000, .script_pubkey = coin_spk }, 1, false);

    var spend = try g6SpendTx(allocator, coin, 1, 0xFFFFFFFF);
    try g6Sign(allocator, ctx, &key, &spend, coin_spk, corrupt_sig);
    var b2 = try g6MineWithTx(allocator, &params, a1.hash, 2, 0xC6, spend);
    defer serialize.freeBlock(allocator, &b2.block);

    if (fault == .secp) crypto.test_fault_secp_unavailable = true;
    defer crypto.test_fault_secp_unavailable = false;

    try sendHeaders(&n.pm, allocator, n.x_peer, &.{&b2});
    try sendBlock(&n.pm, allocator, n.x_peer, &b2);

    // The script's true verdict: CHECKSIG passes iff the sig is valid;
    // CHECKSIG NOT passes iff the sig is INVALID (NULLFAIL is off for blocks).
    const truly_valid = (!with_not) != corrupt_sig;
    switch (fault) {
        .none => if (truly_valid) {
            try testing.expectEqual(@as(u32, 2), n.cs.best_height);
            try testing.expect(!n.x_peer.should_ban);
        } else {
            // CONTROL: a genuinely invalid script keeps its verdict.
            try testing.expectEqual(@as(u32, 1), n.cs.best_height);
            try testing.expect(n.pm.isBlockFailed(&b2.hash));
            try testing.expect(n.x_peer.should_ban);
        },
        .secp => {
            // Never ACCEPTED on a check that did not run (pre-fix: the
            // `CHECKSIG NOT` block CONNECTED here), never a verdict
            // (pre-fix: the valid CHECKSIG block was marked + X banned).
            try testing.expectEqual(@as(u32, 1), n.cs.best_height);
            try testing.expect(!n.pm.isBlockFailed(&b2.hash));
            try testing.expect(!n.x_peer.should_ban);
            try testing.expectEqual(@as(usize, 1), countQueued(&n.pm, b2.hash)); // still wanted
            // The check was re-run once in place and faulted again: the node
            // is halted (AbortNode), it did not guess.
            try testing.expect(fatal.isLatched());
            try testing.expectEqualStrings("ScriptCheckInternal", @errorName(n.pm.last_block_reject_err orelse return error.NoRejectRecorded));
        },
    }
    try testing.expect(!n.h_peer.should_ban);
}

test "tests_reorg_p2p: gate6 — secp fault on <validsig> <pk> CHECKSIG NOT: block NOT accepted, not marked, sender not punished; retried once then halts" {
    try runG6TipScriptFault(true, false, .secp);
}

test "tests_reorg_p2p: gate6 — secp fault on a VALID <sig> <pk> CHECKSIG spend: not marked, sender not punished; retried once then halts" {
    try runG6TipScriptFault(false, false, .secp);
}

test "tests_reorg_p2p: gate6 control — no fault: <validsig> CHECKSIG NOT is INVALID (marked, sender punished)" {
    try runG6TipScriptFault(true, false, .none);
}

test "tests_reorg_p2p: gate6 control — no fault: a corrupted sig under plain CHECKSIG is INVALID (marked, sender punished)" {
    try runG6TipScriptFault(false, true, .none);
}

test "tests_reorg_p2p: gate6 control — no fault: valid CHECKSIG spend connects; corrupted sig under CHECKSIG NOT connects (NULLFAIL off)" {
    try runG6TipScriptFault(false, false, .none);
    try runG6TipScriptFault(true, true, .none);
}

/// Chainstate write failure while connecting a valid tip block.
fn runG6WriteFault(failures: u32) !void {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const allocator = testing.allocator;
    const params = consensus.REGTEST;
    var n: G6Node = undefined;
    try n.init(&params);
    defer n.deinit();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xB1);
    defer serialize.freeBlock(allocator, &a1.block);
    var a2 = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0xB2);
    defer serialize.freeBlock(allocator, &a2.block);
    try sendHeaders(&n.pm, allocator, n.h_peer, &.{ &a1, &a2 });
    try sendBlock(&n.pm, allocator, n.h_peer, &a1);
    try testing.expectEqual(@as(u32, 1), n.cs.best_height);

    n.db.fault_write_batch_failures = failures;
    try sendBlock(&n.pm, allocator, n.x_peer, &a2);

    try testing.expect(!n.pm.isBlockFailed(&a2.hash));
    try testing.expect(!n.x_peer.should_ban);
    try testing.expect(!n.h_peer.should_ban);
    if (failures <= 1) {
        // A single failed write is retried in place and lands.
        try testing.expect(!fatal.isLatched());
        try testing.expect(!n.cs.flush_error);
        try testing.expectEqual(@as(u32, 2), n.cs.best_height);
    } else {
        // Two failed writes: AbortNode — the node stops (main exits
        // non-zero without flushing), nothing is judged.
        try testing.expect(fatal.isLatched());
        try testing.expect(n.cs.flush_error);
    }
}

test "tests_reorg_p2p: gate6 — one failed chainstate write is retried and the block lands (no verdict, no halt)" {
    try runG6WriteFault(1);
}

test "tests_reorg_p2p: gate6 — a chainstate write failing twice halts the node (latch), never a verdict" {
    try runG6WriteFault(2);
}

/// BIP-68 time lock whose coin MTP needs a block-index read: block 3 spends a
/// coin created at height 2 with a ~388-day relative time lock, so the true
/// verdict is SequenceLockNotSatisfied.  `fault`: the CF_DEFAULT (height ->
/// hash) read fails while the coin's MTP is computed.
fn runG6MtpReadFault(fault: bool) !void {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const allocator = testing.allocator;
    const params = consensus.REGTEST;
    var n: G6Node = undefined;
    try n.init(&params);
    defer n.deinit();

    var a1 = try mineIbBlock(allocator, &params, params.genesis_hash, 1, 0, 0xD1);
    defer serialize.freeBlock(allocator, &a1.block);
    var a2 = try mineIbBlock(allocator, &params, a1.hash, 2, 0, 0xD2);
    defer serialize.freeBlock(allocator, &a2.block);
    try sendHeaders(&n.pm, allocator, n.h_peer, &.{ &a1, &a2 });
    try sendBlock(&n.pm, allocator, n.h_peer, &a1);
    try sendBlock(&n.pm, allocator, n.h_peer, &a2);
    try testing.expectEqual(@as(u32, 2), n.cs.best_height);

    const coin = ghostOutpoint(0xD7);
    try n.cs.utxo_set.add(&coin, &types.TxOut{ .value = 50_000, .script_pubkey = &[_]u8{0x51} }, 2, false);
    // nVersion 2, sequence: type flag (time) | 0xFFFF units of 512 s.
    const spend = try g6SpendTx(allocator, coin, 2, (1 << 22) | 0xFFFF);
    var b3 = try g6MineWithTx(allocator, &params, a2.hash, 3, 0xD7, spend);
    defer serialize.freeBlock(allocator, &b3.block);

    try sendHeaders(&n.pm, allocator, n.x_peer, &.{&b3});
    if (fault) n.db.fault_get_cf_mask = @as(u32, 1) << @intCast(storage.CF_DEFAULT);
    defer n.db.fault_get_cf_mask = 0;
    try sendBlock(&n.pm, allocator, n.x_peer, &b3);

    // Never accepted: pre-fix the read error made the coin's MTP 0, which
    // WAIVED the time lock and connected block 3.
    try testing.expectEqual(@as(u32, 2), n.cs.best_height);
    if (fault) {
        try testing.expect(!n.pm.isBlockFailed(&b3.hash));
        try testing.expect(!n.x_peer.should_ban);
        try testing.expectEqualStrings("BlockIndexReadError", @errorName(n.pm.last_block_reject_err orelse return error.NoRejectRecorded));
    } else {
        // CONTROL: the lock is real and enforced without the fault.
        try testing.expect(n.pm.isBlockFailed(&b3.hash));
        try testing.expect(n.x_peer.should_ban);
        try testing.expectEqualStrings("SequenceLockNotSatisfied", @errorName(n.pm.last_block_reject_err orelse return error.NoRejectRecorded));
    }
}

test "tests_reorg_p2p: gate6 — block-index read error computing a coin's MTP: time lock NOT waived (block not accepted), not marked, not punished" {
    try runG6MtpReadFault(true);
}

test "tests_reorg_p2p: gate6 control — the same unexpired BIP-68 time lock without a fault is a verdict (marked, punished)" {
    try runG6MtpReadFault(false);
}

/// F12: our allocation failing while DECODING a well-formed message is our
/// fault, not a protocol violation by the peer (which is scored 20 and leads
/// to a ban).  A socketpair carries one valid `inv`; the peer's allocator
/// lets the payload buffer through (#0) and fails the decode (#1).
fn runG6ReceiveOom(fail_index: usize) !?anyerror {
    const params = consensus.REGTEST;
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SkipZigTest;
    defer std.posix.close(fds[1]);

    var payload: [37]u8 = undefined;
    payload[0] = 1; // one inventory entry
    std.mem.writeInt(u32, payload[1..5], 2, .little); // MSG_BLOCK
    @memset(payload[5..37], 0x77);
    const hdr = p2p.MessageHeader.create(params.magic, "inv", &payload);
    const hb = hdr.encode();
    _ = try std.posix.write(fds[1], &hb);
    _ = try std.posix.write(fds[1], &payload);

    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
    var p = makeStubPeer(&params, testing.allocator);
    defer p.recv_buffer.deinit();
    p.stream = .{ .handle = fds[0] };
    defer std.posix.close(fds[0]);
    p.allocator = fa.allocator();
    if (p.receiveMessage()) |msg| {
        switch (msg) {
            .inv => |iv| fa.allocator().free(iv.inventory),
            else => {},
        }
        return null;
    } else |e| return @as(?anyerror, e); // the receive result, not a setup error
}

test "tests_reorg_p2p: gate6 F12 — OOM decoding a valid message is OutOfMemory (ours), not ProtocolViolation (the peer's)" {
    // control: no fault decodes cleanly
    if (try runG6ReceiveOom(std.math.maxInt(usize))) |e| return e;
    const e = (try runG6ReceiveOom(1)) orelse return error.FaultNotInjected;
    if (e == error.ProtocolViolation) std.debug.print("gate6 F12: decode OOM reported as ProtocolViolation (pre-fix: +20 misbehaviour, ban path)\n", .{});
    try testing.expectEqualStrings("OutOfMemory", @errorName(e));
}
