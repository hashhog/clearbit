//! Background backfill of genesis → snapshot-base after assumeUTXO boot.
//!
//! Bitcoin Core's `--loadtxoutset` / `-assumeutxo` path activates the snapshot
//! chainstate for immediate use AND keeps a second, background chainstate that
//! IBDs genesis→base (`validation.cpp` `ChainstateManager` /
//! `MaybeCompleteSnapshotValidation`). When the background chain reaches the
//! snapshot base, the two are reconciled and the node is fully indexed.
//!
//! clearbit's `--load-snapshot` boot writes genesis, a baked assumeutxo tail
//! band (ending at the snapshot base), and then everything after the base.
//! Heights `1..floor-1` are absent from the H:{height} index. That is the
//! live mainnet shape (floor 944172): `getblockhash(1)` returns
//! `-1 "Block not available (pruned data)"` and `getblockchaininfo` reports
//! `pruned:true pruneheight=944172`.
//!
//! This type fills that hole:
//!
//!   1. Request headers from genesis (locator = last contiguous genesis-side
//!      hash; `hash_stop` = the already-stored floor hash).
//!   2. Store connecting headers into CF_BLOCK_INDEX + H:{height} without
//!      touching the snapshot tail or the active tip.
//!   3. Request block bodies for those headers and store them in CF_BLOCKS.
//!   4. When height 1 is indexed and the contiguous genesis chain meets the
//!      previous floor, `history_floor` is cleared and getblockchaininfo
//!      reports `pruned: false`.
//!
//! Header-sync isolation: these headers MUST NOT be fed to the forward
//! header path whose tip is the snapshot tip. A genesis-connecting batch
//! would look like a rewind to height 0 and overwrite the snapshot tail
//! (or, on this node, a too-deep REORG-CANDIDATE). The P2P loop classifies
//! a batch as backfill iff `isBackfillBatch`.
//!
//! UTXO re-derivation of genesis→base is a separate concern
//! (`au_bg_chainstate.zig`). Replaying ~944k mainnet blocks into a RAM
//! HashMap would OOM; this backfill is the operator-visible historical index.
//!
//! CONTROL: `zig build test-historical-backfill --summary new`

const std = @import("std");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const storage = @import("storage.zig");

/// Maximum bodies requested in one getdata burst. Matches Core's default
/// per-peer in-flight cap so historical download cannot starve tip sync.
pub const BACKFILL_BODIES_PER_REQUEST: usize = 16;

pub const BackfillError = error{
    /// Batch does not connect to the genesis-side tip and is not an overlapping
    /// re-send of already-stored historical headers.
    Unconnecting,
    /// Header hash does not meet the target it declares.
    HighHash,
    /// Header nBits does not match GetNextWorkRequired.
    BadDiffBits,
    /// Header timestamp is not strictly greater than the parent MTP.
    TimeTooOld,
    /// Block body does not match a stored historical header.
    UnexpectedBlock,
    OutOfMemory,
};

pub const Locator = struct {
    hashes: [2]types.Hash256,
    len: usize,

    pub fn slice(self: *const Locator) []const types.Hash256 {
        return self.hashes[0..self.len];
    }
};

pub const BodyRequest = struct {
    height: u32,
    hash: types.Hash256,
};

/// Background backfill of the assumeutxo height-index hole.
pub const HistoricalBackfill = struct {
    allocator: std.mem.Allocator,
    genesis_hash: types.Hash256,
    /// Last contiguous height from genesis that we have a header + height-index
    /// row for. Starts at 0; advances toward `target_floor - 1`.
    genesis_tip: u32,
    genesis_tip_hash: types.Hash256,
    /// First indexed height of the snapshot tail (the hole is `1..floor-1`).
    target_floor: u32,
    /// Hash already stored at `target_floor`. Used as getheaders `hash_stop`
    /// and as the linkage check when the hole closes.
    floor_hash: types.Hash256,
    /// First height in `1..floor-1` whose body is still missing.
    next_body_height: u32,
    /// Hashes we have asked a peer for and not yet received.
    in_flight: std.AutoHashMap(types.Hash256, void),

    pub fn deinit(self: *HistoricalBackfill) void {
        self.in_flight.deinit();
    }

    /// Inspect the store. Returns `null` when there is no snapshot hole (and
    /// no in-progress backfill to resume).
    pub fn detect(
        cs: *storage.ChainState,
        genesis_hash: types.Hash256,
        tip: u32,
    ) ?HistoricalBackfill {
        const target_floor = blk: {
            if (cs.loadHistoricalBackfillFloor()) |floor| break :blk floor;
            if (tip == 0) return null;
            if (cs.getBlockHashByHeight(1) != null) return null;
            // Same binary search as discoverHistoryFloor, without the
            // probed-once latch (detect may run after that probe).
            var lo: u32 = 1;
            var hi: u32 = tip;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (cs.getBlockHashByHeight(mid) != null) {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            const floor = if (cs.getBlockHashByHeight(lo) != null) lo else tip;
            if (floor <= 1) return null;
            cs.persistHistoricalBackfillFloor(floor);
            break :blk floor;
        };

        const stored_genesis = cs.getBlockHashByHeight(0) orelse genesis_hash;
        const floor_hash = cs.getBlockHashByHeight(target_floor) orelse return null;

        var genesis_tip: u32 = 0;
        var genesis_tip_hash = stored_genesis;
        while (genesis_tip + 1 < target_floor) {
            if (cs.getBlockHashByHeight(genesis_tip + 1)) |h| {
                genesis_tip += 1;
                genesis_tip_hash = h;
            } else break;
        }

        var next_body_height: u32 = 1;
        while (next_body_height <= genesis_tip and next_body_height < target_floor) {
            if (cs.getBlockHashByHeight(next_body_height)) |h| {
                if (cs.hasBlock(&h)) {
                    next_body_height += 1;
                    continue;
                }
            }
            break;
        }

        if (genesis_tip + 1 >= target_floor and next_body_height >= target_floor) {
            cs.clearHistoricalBackfillFloor();
            cs.setHistoryFloor(0);
            return null;
        }

        return HistoricalBackfill{
            .allocator = cs.allocator,
            .genesis_hash = stored_genesis,
            .genesis_tip = genesis_tip,
            .genesis_tip_hash = genesis_tip_hash,
            .target_floor = target_floor,
            .floor_hash = floor_hash,
            .next_body_height = next_body_height,
            .in_flight = std.AutoHashMap(types.Hash256, void).init(cs.allocator),
        };
    }

    /// Genesis-side locator for `getheaders`. Newest-first: the last
    /// contiguous historical hash, then genesis if different.
    pub fn locator(self: *const HistoricalBackfill) Locator {
        if (std.mem.eql(u8, &self.genesis_tip_hash, &self.genesis_hash)) {
            return .{ .hashes = .{ self.genesis_hash, [_]u8{0} ** 32 }, .len = 1 };
        }
        return .{ .hashes = .{ self.genesis_tip_hash, self.genesis_hash }, .len = 2 };
    }

    pub fn hashStop(self: *const HistoricalBackfill) types.Hash256 {
        return self.floor_hash;
    }

    pub fn genesisTip(self: *const HistoricalBackfill) u32 {
        return self.genesis_tip;
    }

    pub fn targetFloor(self: *const HistoricalBackfill) u32 {
        return self.target_floor;
    }

    pub fn headersComplete(self: *const HistoricalBackfill) bool {
        return self.genesis_tip + 1 >= self.target_floor;
    }

    pub fn bodiesComplete(self: *const HistoricalBackfill) bool {
        return self.next_body_height >= self.target_floor;
    }

    pub fn isComplete(self: *const HistoricalBackfill) bool {
        return self.headersComplete() and self.bodiesComplete();
    }

    /// True when this headers batch belongs to the historical backfill, not
    /// the forward header sync. A genesis-connecting (or overlapping) batch
    /// MUST NOT be given to the snapshot-tip path: that would rewind the
    /// header index to height 0 and wipe the tail band, or classify as a
    /// too-deep REORG-CANDIDATE.
    pub fn isBackfillBatch(
        self: *const HistoricalBackfill,
        cs: *storage.ChainState,
        headers: []const types.BlockHeader,
    ) bool {
        if (headers.len == 0) return false;
        if (std.mem.eql(u8, &headers[0].prev_block, &self.genesis_tip_hash)) return true;
        return self.isHistoricalHash(cs, &headers[0].prev_block);
    }

    /// True when `hash` is a stored historical header whose body we still want.
    pub fn wantsHash(self: *const HistoricalBackfill, cs: *storage.ChainState, hash: *const types.Hash256) bool {
        const height = cs.getBlockHeightByHash(hash) orelse return false;
        return height > 0 and height < self.target_floor;
    }

    /// Apply a headers batch. Stores only missing heights in `1..floor-1`.
    /// Never writes the snapshot tail or moves the active tip.
    ///
    /// Overlapping re-sends of already-stored prefixes are ignored (`0`).
    pub fn acceptHeaders(
        self: *HistoricalBackfill,
        headers: []const types.BlockHeader,
        cs: *storage.ChainState,
        params: *const consensus.NetworkParams,
    ) BackfillError!usize {
        if (headers.len == 0 or self.headersComplete()) return 0;

        var start: usize = 0;
        if (!std.mem.eql(u8, &headers[0].prev_block, &self.genesis_tip_hash)) {
            while (start < headers.len and
                !std.mem.eql(u8, &headers[start].prev_block, &self.genesis_tip_hash))
            {
                start += 1;
            }
            if (start == headers.len) {
                if (self.isHistoricalHash(cs, &headers[0].prev_block)) return 0;
                return BackfillError.Unconnecting;
            }
        }

        var stored: usize = 0;
        for (headers[start..]) |header| {
            if (self.headersComplete()) break;
            const height = self.genesis_tip + 1;
            if (height >= self.target_floor) break;
            if (!std.mem.eql(u8, &header.prev_block, &self.genesis_tip_hash)) {
                return BackfillError.Unconnecting;
            }
            if (!consensus.validateProofOfWork(&header, params)) {
                return BackfillError.HighHash;
            }
            if (expectedBits(cs, params, header.prev_block, height, header.timestamp)) |want| {
                if (header.bits != want) return BackfillError.BadDiffBits;
            }
            if (mtpOf(cs, params, header.prev_block)) |mtp| {
                if (header.timestamp <= mtp) return BackfillError.TimeTooOld;
            }

            const hash = crypto.computeBlockHash(&header);
            cs.putPersistedHeader(&hash, &header, height);
            cs.putBlockHashByHeight(height, &hash);

            self.genesis_tip = height;
            self.genesis_tip_hash = hash;
            stored += 1;
        }

        if (self.headersComplete()) {
            try self.verifyFloorLink(cs);
            cs.setHistoryFloor(0);
        }
        if (self.isComplete()) {
            cs.clearHistoricalBackfillFloor();
        }
        return stored;
    }

    /// Store a historical block body. Does not connect UTXO / does not move
    /// the active tip.
    pub fn acceptBlock(
        self: *HistoricalBackfill,
        block: *const types.Block,
        cs: *storage.ChainState,
    ) BackfillError!bool {
        const hash = crypto.computeBlockHash(&block.header);
        _ = self.in_flight.remove(hash);
        const height = cs.getBlockHeightByHash(&hash) orelse return BackfillError.UnexpectedBlock;
        if (height == 0 or height >= self.target_floor) return BackfillError.UnexpectedBlock;
        if (cs.hasBlock(&hash)) {
            self.advanceBodyCursor(cs);
            self.persistTxCounts(cs);
            if (self.isComplete()) cs.clearHistoricalBackfillFloor();
            return false;
        }

        var writer = serialize.Writer.init(cs.allocator);
        defer writer.deinit();
        serialize.writeBlock(&writer, block) catch return BackfillError.OutOfMemory;
        cs.putBlockBody(&hash, writer.getWritten());
        self.advanceBodyCursor(cs);
        self.persistTxCounts(cs);
        if (self.isComplete()) cs.clearHistoricalBackfillFloor();
        return true;
    }

    /// Next historical bodies to request, up to `out.len`. Records them as
    /// in-flight so a subsequent call does not re-request the same hashes.
    pub fn nextBodyHashes(
        self: *HistoricalBackfill,
        cs: *storage.ChainState,
        out: []BodyRequest,
    ) usize {
        if (self.bodiesComplete() or out.len == 0) return 0;
        var n: usize = 0;
        var h = self.next_body_height;
        while (n < out.len and h < self.target_floor and h <= self.genesis_tip) : (h += 1) {
            const hash = cs.getBlockHashByHeight(h) orelse continue;
            if (cs.hasBlock(&hash)) continue;
            if (self.in_flight.contains(hash)) continue;
            self.in_flight.put(hash, {}) catch continue;
            out[n] = .{ .height = h, .hash = hash };
            n += 1;
        }
        return n;
    }

    pub fn clearInFlight(self: *HistoricalBackfill) void {
        self.in_flight.clearRetainingCapacity();
    }

    fn isHistoricalHash(self: *const HistoricalBackfill, cs: *storage.ChainState, hash: *const types.Hash256) bool {
        const height = cs.getBlockHeightByHash(hash) orelse return false;
        return height < self.target_floor;
    }

    fn verifyFloorLink(self: *const HistoricalBackfill, cs: *storage.ChainState) BackfillError!void {
        const floor_header = cs.getPersistedHeader(&self.floor_hash) orelse
            return BackfillError.Unconnecting;
        if (!std.mem.eql(u8, &floor_header.prev_block, &self.genesis_tip_hash)) {
            return BackfillError.Unconnecting;
        }
    }

    fn advanceBodyCursor(self: *HistoricalBackfill, cs: *storage.ChainState) void {
        while (self.next_body_height < self.target_floor) {
            if (cs.getBlockHashByHeight(self.next_body_height)) |h| {
                if (cs.hasBlock(&h)) {
                    self.next_body_height += 1;
                    continue;
                }
            }
            break;
        }
    }

    fn persistTxCounts(self: *HistoricalBackfill, cs: *storage.ChainState) void {
        var h: u32 = 1;
        while (h < self.next_body_height) : (h += 1) {
            if (cs.getCumulativeTxCount(h) != null) continue;
            const hash = cs.getBlockHashByHeight(h) orelse continue;
            const n_tx = nTxAt(cs, &hash);
            const prev = cs.getCumulativeTxCount(h - 1) orelse break;
            cs.putCumulativeTxCount(h, prev + n_tx);
        }
    }
};

fn nTxAt(cs: *storage.ChainState, hash: *const types.Hash256) u64 {
    const db = cs.utxo_set.db orelse return 1;
    const raw = db.get(storage.CF_BLOCKS, hash) catch return 1;
    const bytes = raw orelse return 1;
    defer cs.allocator.free(bytes);
    if (bytes.len < 81) return 1;
    var reader = serialize.Reader{ .data = bytes[80..] };
    return reader.readCompactSize() catch 1;
}

fn expectedBits(
    cs: *storage.ChainState,
    params: *const consensus.NetworkParams,
    prev_hash: types.Hash256,
    height: u32,
    timestamp: u32,
) ?u32 {
    const Ctx = struct {
        cs: *storage.ChainState,
        params: *const consensus.NetworkParams,
        prev_hash: types.Hash256,
        prev_height: u32,

        fn getAtHeight(ctx: *anyopaque, h: u32) ?consensus.BlockIndexEntry {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (h == 0) {
                return .{
                    .height = 0,
                    .timestamp = self.params.genesis_header.timestamp,
                    .bits = self.params.genesis_header.bits,
                };
            }
            if (h == self.prev_height) {
                const hdr = self.cs.getPersistedHeader(&self.prev_hash) orelse {
                    if (std.mem.eql(u8, &self.prev_hash, &self.params.genesis_hash)) {
                        return .{
                            .height = 0,
                            .timestamp = self.params.genesis_header.timestamp,
                            .bits = self.params.genesis_header.bits,
                        };
                    }
                    return null;
                };
                return .{ .height = h, .timestamp = hdr.timestamp, .bits = hdr.bits };
            }
            const hash = self.cs.getBlockHashByHeight(h) orelse return null;
            const hdr = self.cs.getPersistedHeader(&hash) orelse return null;
            return .{ .height = h, .timestamp = hdr.timestamp, .bits = hdr.bits };
        }
    };
    var ctx = Ctx{
        .cs = cs,
        .params = params,
        .prev_hash = prev_hash,
        .prev_height = height -| 1,
    };
    const view = consensus.BlockIndexView{
        .context = @ptrCast(&ctx),
        .getAtHeightFn = Ctx.getAtHeight,
        .pow_limit_bits = consensus.getPowLimitBits(params),
    };
    return consensus.getNextWorkRequiredChecked(height, timestamp, &view, params);
}

fn mtpOf(cs: *storage.ChainState, params: *const consensus.NetworkParams, tip_hash: types.Hash256) ?u32 {
    var timestamps: [11]u32 = undefined;
    var n: usize = 0;
    var current = tip_hash;
    while (n < 11) {
        if (std.mem.eql(u8, &current, &params.genesis_hash) or
            std.mem.allEqual(u8, &current, 0))
        {
            timestamps[n] = params.genesis_header.timestamp;
            n += 1;
            break;
        }
        const hdr = cs.getPersistedHeader(&current) orelse {
            if (std.mem.eql(u8, &current, &params.genesis_hash)) {
                timestamps[n] = params.genesis_header.timestamp;
                n += 1;
            }
            break;
        };
        timestamps[n] = hdr.timestamp;
        current = hdr.prev_block;
        n += 1;
    }
    if (n == 0) return null;
    var i: usize = 1;
    while (i < n) : (i += 1) {
        const key = timestamps[i];
        var j: usize = i;
        while (j > 0 and timestamps[j - 1] > key) : (j -= 1) {
            timestamps[j] = timestamps[j - 1];
        }
        timestamps[j] = key;
    }
    return timestamps[n / 2];
}

// ===========================================================================
// Tests
// ===========================================================================

pub fn mineCoinbaseBlock(
    allocator: std.mem.Allocator,
    prev: types.Hash256,
    height: u32,
    timestamp: u32,
    bits: u32,
    params: *const consensus.NetworkParams,
) !types.Block {
    const script_sig = try allocator.dupe(u8, &[_]u8{
        0x03,
        @intCast(height & 0xff),
        @intCast((height >> 8) & 0xff),
        @intCast((height >> 16) & 0xff),
    });
    errdefer allocator.free(script_sig);
    const inputs = try allocator.alloc(types.TxIn, 1);
    errdefer allocator.free(inputs);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xffffffff,
        .witness = &.{},
    };
    const spk = try allocator.dupe(u8, &[_]u8{0x51});
    errdefer allocator.free(spk);
    const outputs = try allocator.alloc(types.TxOut, 1);
    errdefer allocator.free(outputs);
    outputs[0] = .{ .value = 50_0000_0000, .script_pubkey = spk };
    const txs = try allocator.alloc(types.Transaction, 1);
    errdefer allocator.free(txs);
    txs[0] = .{
        .version = 1,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = 0,
    };
    const txid = try crypto.computeTxid(&txs[0], allocator);
    var header = types.BlockHeader{
        .version = 1,
        .prev_block = prev,
        .merkle_root = txid,
        .timestamp = timestamp,
        .bits = bits,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) {
        header.nonce +%= 1;
        if (header.nonce == 0) return error.PowFailed;
    }
    return .{ .header = header, .transactions = txs };
}

pub fn buildRegtestChain(allocator: std.mem.Allocator, params: *const consensus.NetworkParams, tip: u32) ![]types.Block {
    var blocks = try allocator.alloc(types.Block, tip + 1);
    blocks[0] = .{ .header = params.genesis_header, .transactions = &.{} };
    var prev = params.genesis_hash;
    var ts = params.genesis_header.timestamp;
    const bits = params.genesis_header.bits;
    var h: u32 = 1;
    while (h <= tip) : (h += 1) {
        ts += 600;
        blocks[h] = try mineCoinbaseBlock(allocator, prev, h, ts, bits, params);
        prev = crypto.computeBlockHash(&blocks[h].header);
    }
    return blocks;
}

pub fn freeRegtestChain(allocator: std.mem.Allocator, blocks: []types.Block) void {
    var i: usize = 1;
    while (i < blocks.len) : (i += 1) {
        serialize.freeBlock(allocator, &blocks[i]);
    }
    allocator.free(blocks);
}

pub fn seedSnapshotHole(cs: *storage.ChainState, blocks: []const types.Block, floor: u32, tip: u32) void {
    const g_hash = crypto.computeBlockHash(&blocks[0].header);
    cs.putPersistedHeader(&g_hash, &blocks[0].header, 0);
    cs.putBlockHashByHeight(0, &g_hash);
    var n: u32 = floor;
    while (n <= tip) : (n += 1) {
        const hash = crypto.computeBlockHash(&blocks[n].header);
        cs.putPersistedHeader(&hash, &blocks[n].header, n);
        cs.putBlockHashByHeight(n, &hash);
    }
    cs.best_height = tip;
    cs.best_hash = crypto.computeBlockHash(&blocks[tip].header);
}

test "historical_backfill detect none when no hole" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    cs.putPersistedHeader(&params.genesis_hash, &params.genesis_header, 0);
    cs.putBlockHashByHeight(0, &params.genesis_hash);
    cs.best_height = 0;
    cs.best_hash = params.genesis_hash;
    try std.testing.expect(HistoricalBackfill.detect(&cs, params.genesis_hash, 0) == null);
}

test "historical_backfill detects assumeutxo hole" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);

    var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20) orelse
        return error.TestUnexpectedResult;
    defer bf.deinit();
    try std.testing.expectEqual(@as(u32, 0), bf.genesisTip());
    try std.testing.expectEqual(@as(u32, 10), bf.targetFloor());
    try std.testing.expect(!bf.headersComplete());
    try std.testing.expect(!bf.isComplete());
    try std.testing.expectEqualSlices(u8, &params.genesis_hash, &bf.locator().slice()[0]);
    const floor_hash = crypto.computeBlockHash(&blocks[10].header);
    try std.testing.expectEqualSlices(u8, &floor_hash, &bf.hashStop());
}

test "historical_backfill headers fill hole and clear floor" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);
    cs.setHistoryFloor(10);

    var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
    defer bf.deinit();
    var hole: [9]types.BlockHeader = undefined;
    var i: usize = 0;
    while (i < 9) : (i += 1) hole[i] = blocks[i + 1].header;
    try std.testing.expect(bf.isBackfillBatch(&cs, &hole));
    const n = try bf.acceptHeaders(&hole, &cs, params);
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expect(bf.headersComplete());
    try std.testing.expectEqual(@as(u32, 9), bf.genesisTip());
    try std.testing.expectEqual(@as(u32, 0), cs.history_floor);
    const h1 = crypto.computeBlockHash(&blocks[1].header);
    try std.testing.expectEqualSlices(u8, &h1, &(cs.getBlockHashByHeight(1) orelse return error.TestUnexpectedResult));
    const h10 = crypto.computeBlockHash(&blocks[10].header);
    try std.testing.expectEqualSlices(u8, &h10, &(cs.getBlockHashByHeight(10) orelse return error.TestUnexpectedResult));
    try std.testing.expectEqual(@as(u32, 20), cs.best_height);
}

test "historical_backfill overlapping batch is ignored" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);

    var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
    defer bf.deinit();
    var hole: [9]types.BlockHeader = undefined;
    var i: usize = 0;
    while (i < 9) : (i += 1) hole[i] = blocks[i + 1].header;
    try std.testing.expectEqual(@as(usize, 9), try bf.acceptHeaders(&hole, &cs, params));
    try std.testing.expectEqual(@as(usize, 0), try bf.acceptHeaders(&hole, &cs, params));
    try std.testing.expectEqual(@as(u32, 9), bf.genesisTip());
}

test "historical_backfill rejects unconnecting headers" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);

    var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
    defer bf.deinit();
    const bogus = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0x11} ** 32,
        .merkle_root = [_]u8{0x22} ** 32,
        .timestamp = 1_700_000_000,
        .bits = params.genesis_header.bits,
        .nonce = 0,
    };
    try std.testing.expectError(BackfillError.Unconnecting, bf.acceptHeaders(&[_]types.BlockHeader{bogus}, &cs, params));
    try std.testing.expectEqual(@as(u32, 0), bf.genesisTip());
    try std.testing.expect(cs.getBlockHashByHeight(1) == null);
}

test "historical_backfill does not rewind snapshot tip" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);
    const tip_hash = cs.best_hash;

    var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
    defer bf.deinit();
    var hole: [9]types.BlockHeader = undefined;
    var i: usize = 0;
    while (i < 9) : (i += 1) hole[i] = blocks[i + 1].header;
    _ = try bf.acceptHeaders(&hole, &cs, params);
    try std.testing.expectEqual(@as(u32, 20), cs.best_height);
    try std.testing.expectEqualSlices(u8, &tip_hash, &cs.best_hash);
    const h10 = crypto.computeBlockHash(&blocks[10].header);
    try std.testing.expectEqualSlices(u8, &h10, &(cs.getBlockHashByHeight(10) orelse return error.TestUnexpectedResult));
}

test "historical_backfill bodies complete the index" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);

    var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
    defer bf.deinit();
    var hole: [9]types.BlockHeader = undefined;
    var i: usize = 0;
    while (i < 9) : (i += 1) hole[i] = blocks[i + 1].header;
    _ = try bf.acceptHeaders(&hole, &cs, params);
    try std.testing.expect(!bf.bodiesComplete());

    var want_buf: [16]BodyRequest = undefined;
    const want_n = bf.nextBodyHashes(&cs, &want_buf);
    try std.testing.expectEqual(@as(usize, 9), want_n);
    try std.testing.expectEqual(@as(u32, 1), want_buf[0].height);

    var h: u32 = 1;
    while (h < 10) : (h += 1) {
        try std.testing.expect(try bf.acceptBlock(&blocks[h], &cs));
    }
    try std.testing.expect(bf.bodiesComplete());
    try std.testing.expect(bf.isComplete());
    const h1 = crypto.computeBlockHash(&blocks[1].header);
    try std.testing.expect(cs.hasBlock(&h1));
    try std.testing.expectEqual(@as(usize, 0), bf.nextBodyHashes(&cs, &want_buf));
}

test "historical_backfill resumes from partial fill" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);

    {
        var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
        defer bf.deinit();
        var first: [4]types.BlockHeader = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) first[i] = blocks[i + 1].header;
        try std.testing.expectEqual(@as(usize, 4), try bf.acceptHeaders(&first, &cs, params));
        try std.testing.expectEqual(@as(u32, 4), bf.genesisTip());
    }

    var bf2 = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
    defer bf2.deinit();
    try std.testing.expectEqual(@as(u32, 4), bf2.genesisTip());
    var rest: [5]types.BlockHeader = undefined;
    var j: usize = 0;
    while (j < 5) : (j += 1) rest[j] = blocks[j + 5].header;
    try std.testing.expect(bf2.isBackfillBatch(&cs, &rest));
    try std.testing.expectEqual(@as(usize, 5), try bf2.acceptHeaders(&rest, &cs, params));
    try std.testing.expect(bf2.headersComplete());
}

test "historical_backfill locator is genesis rooted not tip rooted" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    const params = &consensus.REGTEST;
    const blocks = try buildRegtestChain(allocator, params, 20);
    defer freeRegtestChain(allocator, blocks);
    seedSnapshotHole(&cs, blocks, 10, 20);

    var bf = HistoricalBackfill.detect(&cs, params.genesis_hash, 20).?;
    defer bf.deinit();
    const loc = bf.locator();
    try std.testing.expectEqualSlices(u8, &params.genesis_hash, &loc.slice()[0]);
    const tip_hash = crypto.computeBlockHash(&blocks[20].header);
    var k: usize = 0;
    while (k < loc.len) : (k += 1) {
        try std.testing.expect(!std.mem.eql(u8, &loc.hashes[k], &tip_hash));
    }
    const floor_hash = crypto.computeBlockHash(&blocks[10].header);
    try std.testing.expectEqualSlices(u8, &floor_hash, &bf.hashStop());
    try std.testing.expect(!std.mem.allEqual(u8, &bf.hashStop(), 0));
}
