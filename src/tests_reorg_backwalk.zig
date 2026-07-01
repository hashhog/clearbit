//! Reorg-BACK (B -> A') via the LIVE submitblock side-branch path.
//!
//! Reproduces the clearbit un-pin blocker found by reorg wave 3 (live
//! regtest bitcoind oracle vs node over submitblock):
//!
//!   * forward reorg A -> B SUCCEEDS, then
//!   * reorg BACK B -> A' FAILS with
//!       "reorgToChain: walked back to genesis without finding fork point"
//!       (error.ForkPointNotOnChain), which latches flush_error sticky and
//!       leaves the node stuck on the B tip instead of switching to A'.
//!
//! Root cause: `ChainState.flush` writes the H:<height>->hash index for the
//! NEW TIP HEIGHT ONLY.  A reorg re-chains every height from fork_point+1 up
//! to the new tip in ONE flush, so the intermediate heights keep pointing at
//! the OLD (disconnected) branch's blocks.  On the next reorg-back,
//! `fireReorgFromSideBranch`'s fork-point walk trusts `getBlockHashByHeight`
//! to decide active-chain membership, gets a false positive on one of those
//! stale entries, and hands `reorgToChain` a fork_point that is NOT on the
//! active chain -> the disconnect walk runs off the end to genesis.
//!
//! This test drives the ACTUAL node reorg path (block_template.
//! processSideBranchSubmission -> fireReorgFromSideBranch -> reorgToChain),
//! NOT a ChainManager unit test, so it exercises the real failure.  The
//! chain is DB-backed (getBlockHashByHeight reads RocksDB), which is required
//! for the stale-index bug to manifest.
//!
//! Pre-fix: the B->A' submit fails (reorg aborts, tip stuck on B).
//! Post-fix: the B->A' submit succeeds and the active tip lands on A'.

const std = @import("std");
const storage = @import("storage.zig");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");
const validation = @import("validation.zig");
const block_template = @import("block_template.zig");
const peer = @import("peer.zig");

const ChainState = storage.ChainState;
const Database = storage.Database;
const BlockIndexEntry = validation.BlockIndexEntry;

const TEST_BITS: u32 = 0x1d00ffff; // difficulty-1 => clean positive per-block work

/// Build a distinct coinbase-only block on top of `prev_hash`.  `marker`
/// makes both the header (merkle_root/nonce) AND the coinbase scriptSig
/// unique, so every block gets a unique block hash AND a unique coinbase
/// txid (no cross-branch UTXO-outpoint collision).  All slices are heap-
/// allocated so the block round-trips through serialize.writeBlock/readBlock
/// (the reorg-connect path re-reads bodies from CF_BLOCKS).
fn makeBlock(
    allocator: std.mem.Allocator,
    prev_hash: [32]u8,
    marker: u8,
) !struct { block: types.Block, hash: types.Hash256 } {
    const script_sig = try allocator.dupe(u8, &[_]u8{ 0x04, marker, 0x00, 0x00, 0x00 });
    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const spk = try allocator.alloc(u8, 22);
    spk[0] = 0x00;
    spk[1] = 0x14;
    var i: usize = 2;
    while (i < 22) : (i += 1) spk[i] = marker;
    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = spk };
    const txs = try allocator.alloc(types.Transaction, 1);
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    const block = types.Block{
        .header = .{
            .version = 1,
            .prev_block = prev_hash,
            .merkle_root = [_]u8{marker} ** 32,
            .timestamp = 1_700_000_000 + @as(u32, marker),
            .bits = TEST_BITS,
            .nonce = @as(u32, marker),
        },
        .transactions = txs,
    };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

fn freeBlock(allocator: std.mem.Allocator, block: types.Block) void {
    for (block.transactions) |tx| {
        for (tx.inputs) |in| allocator.free(in.script_sig);
        for (tx.outputs) |out| allocator.free(out.script_pubkey);
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }
    allocator.free(block.transactions);
}

/// Connect a block onto the active tip (the non-reorg extension path) and
/// register a matching ChainManager entry, so the block index + persisted
/// H:<height> index + UTXO all advance together — mirroring what
/// submitBlockWithIndex's extends_active_tip arm does.
fn connectActive(
    cs: *ChainState,
    cm: *validation.ChainManager,
    block: *const types.Block,
    hash: *const types.Hash256,
    height: u32,
    parent: ?*BlockIndexEntry,
    chain_work: [32]u8,
    allocator: std.mem.Allocator,
) !*BlockIndexEntry {
    var w = serialize.Writer.init(allocator);
    try serialize.writeBlock(&w, block);
    const owned: []u8 = @constCast(try w.toOwnedSlice());
    try cs.queueBlockWrite(hash, owned, height);
    try cs.connectBlockFastWithUndo(block, hash, height);

    const entry = try allocator.create(BlockIndexEntry);
    entry.* = .{
        .hash = hash.*,
        .header = block.header,
        .height = height,
        .status = .{ .valid_header = true, .has_data = true, .has_undo = true },
        .chain_work = chain_work,
        .sequence_id = 0,
        .parent = parent,
        .file_number = 0,
        .file_offset = 0,
    };
    try cm.addBlock(entry);
    cm.active_tip = entry;
    return entry;
}

fn cumWork(n: u32) [32]u8 {
    var acc = [_]u8{0} ** 32;
    const w = peer.workFromBits(TEST_BITS);
    var i: u32 = 0;
    while (i < n) : (i += 1) peer.addChainWorkBE(&acc, &w);
    return acc;
}

// A -> B -> A' over the live submitblock side-branch path.
// Topology (fork point = h1):
//   common: h1
//   A     : h2a, h3a                (active tip after setup)
//   B     : h2b, h3b, h4b           (heavier -> forward reorg A->B)
//   A'    : h2a, h3a, h4a, h5a      (heavier than B -> reorg back B->A')
test "tests_reorg_backwalk: live submitblock B->A' reorg-back lands on A' (H: index refresh)" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try Database.open(path, 64, allocator);
    defer db.close();

    var cs = ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();

    var cm = validation.ChainManager.init(&cs, null, allocator);
    defer cm.deinit();

    const zero = [_]u8{0} ** 32;

    // --- common fork-point block h1 + A branch (h2a, h3a) on the active tip.
    var h1 = try makeBlock(allocator, zero, 0x11);
    defer freeBlock(allocator, h1.block);
    const e1 = try connectActive(&cs, &cm, &h1.block, &h1.hash, 1, null, cumWork(1), allocator);

    var h2a = try makeBlock(allocator, h1.hash, 0x2A);
    defer freeBlock(allocator, h2a.block);
    const e2a = try connectActive(&cs, &cm, &h2a.block, &h2a.hash, 2, e1, cumWork(2), allocator);

    var h3a = try makeBlock(allocator, h2a.hash, 0x3A);
    defer freeBlock(allocator, h3a.block);
    const e3a = try connectActive(&cs, &cm, &h3a.block, &h3a.hash, 3, e2a, cumWork(3), allocator);

    try std.testing.expectEqual(@as(u32, 3), cs.best_height);
    try std.testing.expect(std.mem.eql(u8, &cs.best_hash, &h3a.hash));

    // --- B branch via the LIVE side-branch path: h2b, h3b (inconclusive),
    //     then h4b (heavier) fires the forward reorg A -> B.
    var h2b = try makeBlock(allocator, h1.hash, 0x2B);
    defer freeBlock(allocator, h2b.block);
    const r2b = try block_template.processSideBranchSubmission(
        &h2b.block, &h2b.hash, 2, &cs, &cm, e1, null, allocator,
    );
    try std.testing.expect(!r2b.accepted); // inconclusive: equal/lower work

    var h3b = try makeBlock(allocator, h2b.hash, 0x3B);
    defer freeBlock(allocator, h3b.block);
    const e2b = cm.getBlock(&h2b.hash).?;
    const r3b = try block_template.processSideBranchSubmission(
        &h3b.block, &h3b.hash, 3, &cs, &cm, e2b, null, allocator,
    );
    try std.testing.expect(!r3b.accepted);

    var h4b = try makeBlock(allocator, h3b.hash, 0x4B);
    defer freeBlock(allocator, h4b.block);
    const e3b = cm.getBlock(&h3b.hash).?;
    const r4b = try block_template.processSideBranchSubmission(
        &h4b.block, &h4b.hash, 4, &cs, &cm, e3b, null, allocator,
    );
    // Forward reorg A -> B must succeed and land on the B tip.
    try std.testing.expect(r4b.accepted);
    try std.testing.expectEqual(@as(u32, 4), cs.best_height);
    try std.testing.expect(std.mem.eql(u8, &cs.best_hash, &h4b.hash));

    // --- A' branch via the LIVE side-branch path: extend the (now
    //     disconnected) A branch with h4a (inconclusive) then h5a (heavier),
    //     which must fire the reorg BACK B -> A'.  This is the step that
    //     regresses pre-fix: the fork-point walk resolves h3a (a disconnected
    //     block whose stale H:3 entry still points at it) as the fork point,
    //     and reorgToChain then walks past it to genesis.
    var h4a = try makeBlock(allocator, h3a.hash, 0x4A);
    defer freeBlock(allocator, h4a.block);
    const r4a = try block_template.processSideBranchSubmission(
        &h4a.block, &h4a.hash, 4, &cs, &cm, e3a, null, allocator,
    );
    try std.testing.expect(!r4a.accepted); // equal work to B tip -> inconclusive

    var h5a = try makeBlock(allocator, h4a.hash, 0x5A);
    defer freeBlock(allocator, h5a.block);
    const e4a = cm.getBlock(&h4a.hash).?;
    const r5a = try block_template.processSideBranchSubmission(
        &h5a.block, &h5a.hash, 5, &cs, &cm, e4a, null, allocator,
    );

    // POST-FIX expectations (these all FAIL pre-fix):
    //   * the reorg-back is accepted,
    //   * the active tip lands on A' (h5a, height 5),
    //   * flush_error did NOT latch sticky,
    //   * and the H:<height> index now names the A' blocks, not the stale B
    //     (or original-A) branch.
    try std.testing.expect(r5a.accepted);
    try std.testing.expectEqual(@as(u32, 5), cs.best_height);
    try std.testing.expect(std.mem.eql(u8, &cs.best_hash, &h5a.hash));
    try std.testing.expect(!cs.flush_error);

    try std.testing.expect(std.mem.eql(u8, &(cs.getBlockHashByHeight(2).?), &h2a.hash));
    try std.testing.expect(std.mem.eql(u8, &(cs.getBlockHashByHeight(3).?), &h3a.hash));
    try std.testing.expect(std.mem.eql(u8, &(cs.getBlockHashByHeight(4).?), &h4a.hash));
    try std.testing.expect(std.mem.eql(u8, &(cs.getBlockHashByHeight(5).?), &h5a.hash));
}
