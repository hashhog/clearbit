//! BIP-68 time-based relative lock: the coin's nCoinTime must come from the
//! connecting block's own ancestor chain (consensus split, false accept).
//!
//! Core, CalculateSequenceLocks (consensus/tx_verify.cpp):
//!   nCoinTime = block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast()
//! GetAncestor walks the block index from the block being connected; it is
//! never missing for a coin on that chain.
//!
//! clearbit read the coin MTP through the H:<height>->hash index
//! (PeerManager.computeMtpAtHeightSink). flush() writes H: only for the tip
//! height (plus a reorg's queue), and IBD / catch-up flushes once every 128
//! blocks, so most heights have no H: entry. A missing key answered 0, which
//! made required_time = 0 + (lock << 9) - 1: every time lock looked expired,
//! and a block spending a coin whose time lock had not expired was accepted.
//!
//! These tests drive the REAL P2P path (`headers` / `block` handlers,
//! drainBlockBuffer, validateBlockForIBDOrReject) over socketpairs on mined
//! regtest blocks. They announce 149 headers at once so the drain connects
//! the first ~21 blocks without a flush and H:19 is never written; the coin
//! is the height-20 coinbase, so its nCoinTime is MTP(19).
//!
//! Only APIs that exist on the pre-fix tree are used by the chain tests, so
//! the same file gives the fail-before run. The fail-closed tests reach the
//! new walk through `@hasDecl` and fail on their assertion on the base commit.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const storage = @import("storage.zig");
const validation = @import("validation.zig");
const peer_mod = @import("peer.zig");
const tl = @import("tests_tip_liveness.zig");
const PeerManager = peer_mod.PeerManager;

const params = &consensus.REGTEST;

/// Height of the coinbase coin the spend consumes. nCoinTime = MTP(COIN_H-1).
const COIN_H: u32 = 20;
/// Height of the block carrying the time-locked spend (COIN_H + 100 + 2, so
/// the coinbase is mature).
const SPEND_H: u32 = 122;
/// Total announced chain length. Larger than SPEND_H + 128 - COIN_H so the
/// drain does not flush while it connects heights 1..COIN_H.
const CHAIN_LEN: u32 = 149;

const Mined = struct { block: types.Block, hash: types.Hash256 };

/// Core `CScript() << nHeight` for the BIP-34 coinbase prefix.
fn bip34Push(buf: *[8]u8, height: u32) []const u8 {
    if (height >= 1 and height <= 16) {
        buf[0] = @as(u8, @intCast(0x50 + height));
        return buf[0..1];
    }
    var n: usize = 0;
    var v = height;
    var bytes: [5]u8 = undefined;
    while (v != 0) : (v >>= 8) {
        bytes[n] = @truncate(v);
        n += 1;
    }
    if (bytes[n - 1] & 0x80 != 0) {
        bytes[n] = 0;
        n += 1;
    }
    buf[0] = @intCast(n);
    @memcpy(buf[1 .. 1 + n], bytes[0..n]);
    return buf[0 .. 1 + n];
}

/// Regtest block at `height` on `prev`, OP_TRUE coinbase paying the subsidy,
/// plus `spend` (already built) when given. nTime = genesis + height*spacing.
fn mine(
    a: std.mem.Allocator,
    prev: types.Hash256,
    height: u32,
    spacing: u32,
    spend: ?types.Transaction,
) !Mined {
    const ntx: usize = if (spend != null) 2 else 1;
    const txs = try a.alloc(types.Transaction, ntx);
    var pbuf: [8]u8 = undefined;
    const push = bip34Push(&pbuf, height);
    const script_sig = try a.alloc(u8, push.len + 2);
    @memcpy(script_sig[0..push.len], push);
    script_sig[push.len] = 0x01;
    script_sig[push.len + 1] = 0xB6;
    const inputs = try a.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outputs = try a.alloc(types.TxOut, 1);
    // Fees of the spend (1000 sat) go unclaimed: allowed (<= subsidy + fees).
    outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = try a.dupe(u8, &[_]u8{0x51}) };
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    if (spend) |s| txs[1] = s;

    var ids: [2]types.Hash256 = undefined;
    for (txs, 0..) |*t, i| ids[i] = try crypto.computeTxid(t, a);
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeMerkleRoot(ids[0..ntx], a),
        .timestamp = params.genesis_header.timestamp + height * spacing,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs };
    return .{ .block = block, .hash = crypto.computeBlockHash(&block.header) };
}

/// Version-2 tx spending output 0 of `coin_txid` (OP_TRUE) with a TIME-based
/// relative lock of `units` * 512 s.
fn timeLockedSpend(a: std.mem.Allocator, coin_txid: types.Hash256, units: u32) !types.Transaction {
    const inputs = try a.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = .{ .hash = coin_txid, .index = 0 },
        .script_sig = try a.dupe(u8, &[_]u8{}),
        .sequence = consensus.SEQUENCE_LOCKTIME_TYPE_FLAG | units,
        .witness = &[_][]const u8{},
    };
    const outputs = try a.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000 - 1000, .script_pubkey = try a.dupe(u8, &[_]u8{0x51}) };
    return .{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
}

fn clone(a: std.mem.Allocator, b: *const types.Block) !types.Block {
    var w = serialize.Writer.init(a);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readBlock(&r, a);
}

/// MTP of the block at height `h` on a chain whose nTime is
/// genesis + height*spacing (genesis itself at height 0).
fn chainMtp(h: u32, spacing: u32) u32 {
    var ts: [11]u32 = undefined;
    const want: u32 = @min(11, h + 1);
    var i: u32 = 0;
    while (i < want) : (i += 1) {
        const hh = h - i;
        ts[i] = if (hh == 0) params.genesis_header.timestamp else params.genesis_header.timestamp + hh * spacing;
    }
    return validation.medianTimePast(ts[0..want]);
}

const Outcome = struct {
    /// Tip after delivering every body.
    best_height: u32,
    /// Whether the spend block was marked invalid.
    spend_failed: bool,
    /// The last block verdict the P2P path recorded.
    reject_err: ?validation.ValidationError,
    /// Was H:<COIN_H-1> present in the DB when the spend block was judged?
    coin_prev_h_indexed: bool,
};

/// Build the chain (nTime spacing `spacing`, spend locked `units` * 512 s),
/// announce all headers, deliver every body in order through the P2P handlers.
fn run(a: std.mem.Allocator, spacing: u32, units: u32) !Outcome {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var db = try storage.Database.open(path, 64, a);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, a);
    defer cs.deinit();
    cs.wireUtxoParent();
    cs.setNetworkParams(params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    var pm = tl.initPm(a);
    defer pm.deinit();
    defer pm.chain_state = null;
    pm.chain_state = &cs;
    const pa = try tl.addPeer(&pm, a, .{ 10, 0, 0, 1 }, false);
    defer std.posix.close(pa.remote);
    // Drain the getdata the node writes so the socket never fills.
    const flags = try std.posix.fcntl(pa.remote, std.posix.F.GETFL, 0);
    _ = try std.posix.fcntl(pa.remote, std.posix.F.SETFL, flags | @as(usize, 1 << @bitOffsetOf(std.posix.O, "NONBLOCK")));

    const chain = try a.alloc(Mined, CHAIN_LEN + 1);
    defer {
        var h: usize = 1;
        while (h <= CHAIN_LEN) : (h += 1) serialize.freeBlock(a, &chain[h].block);
        a.free(chain);
    }
    var prev = params.genesis_hash;
    var coin_txid: types.Hash256 = undefined;
    var h: u32 = 1;
    while (h <= CHAIN_LEN) : (h += 1) {
        const spend: ?types.Transaction = if (h == SPEND_H) try timeLockedSpend(a, coin_txid, units) else null;
        chain[h] = try mine(a, prev, h, spacing, spend);
        if (h == COIN_H) coin_txid = try crypto.computeTxid(&chain[h].block.transactions[0], a);
        prev = chain[h].hash;
    }

    const hs = try a.alloc(types.BlockHeader, CHAIN_LEN);
    for (hs, 0..) |*hdr, i| hdr.* = chain[i + 1].block.header;
    try pm.ingestHeadersMessage(pa.peer, hs);

    var sink: [1 << 16]u8 = undefined;
    var coin_prev_h_indexed = false;
    h = 1;
    while (h <= CHAIN_LEN) : (h += 1) {
        while (true) {
            const n = std.posix.read(pa.remote, &sink) catch break;
            if (n == 0) break;
        }
        if (h == SPEND_H) coin_prev_h_indexed = cs.getBlockHashByHeight(COIN_H - 1) != null;
        try pm.ingestBlockMessage(pa.peer, try clone(a, &chain[h].block));
        pm.drainBlockBuffer();
    }
    return .{
        .best_height = cs.best_height,
        .spend_failed = pm.isBlockFailed(&chain[SPEND_H].hash),
        .reject_err = pm.last_block_reject_err,
        .coin_prev_h_indexed = coin_prev_h_indexed,
    };
}

test "tests_bip68_coin_mtp_ancestor: the coin's H: entry is absent when the spend is judged (scenario check)" {
    const o = try run(testing.allocator, 600, 1);
    try testing.expect(!o.coin_prev_h_indexed);
}

test "tests_bip68_coin_mtp_ancestor: an unexpired time lock on a coin with no H: entry is rejected bad-txns-nonfinal" {
    // nTime spacing 1 s: MTP(SPEND_H-1) - MTP(COIN_H-1) = 102 s < 512 s.
    const spacing: u32 = 1;
    try testing.expect(chainMtp(SPEND_H - 1, spacing) - chainMtp(COIN_H - 1, spacing) < 512);
    const o = try run(testing.allocator, spacing, 1);
    try testing.expect(!o.coin_prev_h_indexed);
    try testing.expectEqual(@as(u32, SPEND_H - 1), o.best_height);
    try testing.expect(o.spend_failed);
    try testing.expectEqual(@as(?validation.ValidationError, error.SequenceLockNotSatisfied), o.reject_err);
}

test "tests_bip68_coin_mtp_ancestor: the lock one unit past the real MTP gap is rejected (exact coin MTP)" {
    // nTime spacing 10 s: the gap is 1020 s. 2 units need parent MTP >
    // coin MTP + 1023: not met. Core rejects; a coin MTP even 4 s too low
    // would accept.
    const spacing: u32 = 10;
    const gap = chainMtp(SPEND_H - 1, spacing) - chainMtp(COIN_H - 1, spacing);
    try testing.expectEqual(@as(u32, 1020), gap);
    const o = try run(testing.allocator, spacing, 2);
    try testing.expectEqual(@as(u32, SPEND_H - 1), o.best_height);
    try testing.expect(o.spend_failed);
    try testing.expectEqual(@as(?validation.ValidationError, error.SequenceLockNotSatisfied), o.reject_err);
}

test "tests_bip68_coin_mtp_ancestor: negative control, a satisfied time lock on the same chain is accepted" {
    // Same chain shape, 1 unit (512 s) < the 1020 s gap: Core accepts, and the
    // ancestor walk must not turn a valid block invalid.
    const o = try run(testing.allocator, 10, 1);
    try testing.expect(!o.coin_prev_h_indexed);
    try testing.expectEqual(@as(u32, CHAIN_LEN), o.best_height);
    try testing.expect(!o.spend_failed);
}

// ---------------------------------------------------------------------------
// Fail-closed: the walk itself (new API; `@hasDecl` keeps the base compiling).
// ---------------------------------------------------------------------------

const WalkFx = struct {
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: PeerManager,
    hashes: [21]types.Hash256,

    const BASE_TS: u32 = 1_700_000_000;

    /// Heights 0..20 hash-linked; CF_BLOCK_INDEX holds headers only for
    /// heights `lo`..20 (below `lo` the ancestor is missing). No H: entries.
    fn init(self: *WalkFx, a: std.mem.Allocator, lo: u32) !void {
        self.tmp = testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(a, ".");
        self.db = try storage.Database.open(self.path, 64, a);
        self.cs = storage.ChainState.init(&self.db, 64, a);
        self.pm = tl.initPm(a);
        self.pm.chain_state = &self.cs;
        for (0..21) |h| {
            self.hashes[h] = [_]u8{0x5A} ** 32;
            self.hashes[h][0] = @intCast(h + 1);
        }
        self.hashes[0] = params.genesis_hash;
        var h: u32 = @max(lo, 1);
        while (h <= 20) : (h += 1) {
            const hdr = types.BlockHeader{
                .version = 4,
                .prev_block = self.hashes[h - 1],
                .merkle_root = [_]u8{0} ** 32,
                .timestamp = BASE_TS + h * 100,
                .bits = 0x207fffff,
                .nonce = 0,
            };
            var w = serialize.Writer.init(a);
            defer w.deinit();
            try w.writeInt(u32, h);
            try serialize.writeBlockHeader(&w, &hdr);
            try self.db.put(storage.CF_BLOCK_INDEX, &self.hashes[h], w.getWritten());
        }
    }

    fn deinit(self: *WalkFx, a: std.mem.Allocator) void {
        self.pm.chain_state = null;
        self.pm.deinit();
        self.cs.deinit();
        self.db.close();
        a.free(self.path);
        self.tmp.cleanup();
    }
};

test "tests_bip68_coin_mtp_ancestor: the walk returns the true MTP from the block's parent with no H: index" {
    if (!@hasDecl(PeerManager, "CoinMtpWalk")) return error.TestExpectedCoinMtpWalk;
    const a = testing.allocator;
    var fx: WalkFx = undefined;
    try fx.init(a, 1);
    defer fx.deinit(a);
    var walk = PeerManager.CoinMtpWalk.init(&fx.pm, fx.hashes[20], 20);
    defer walk.deinit();
    // MTP(15) = median of heights 5..15 = height 10.
    try testing.expectEqual(WalkFx.BASE_TS + 10 * 100, PeerManager.CoinMtpWalk.trampoline(@ptrCast(&walk), 15));
    // Low heights reach genesis: MTP(3) = median(genesis, 1, 2, 3) (Core picks
    // sorted[n/2] = the 3rd of 4).
    const exp3 = validation.medianTimePast(&[_]u32{ params.genesis_header.timestamp, WalkFx.BASE_TS + 100, WalkFx.BASE_TS + 200, WalkFx.BASE_TS + 300 });
    try testing.expectEqual(exp3, PeerManager.CoinMtpWalk.trampoline(@ptrCast(&walk), 3));
    try testing.expect(walk.err == null);
}

test "tests_bip68_coin_mtp_ancestor: a missing ancestor fails closed (error, not a waived lock)" {
    if (!@hasDecl(PeerManager, "CoinMtpWalk")) return error.TestExpectedCoinMtpWalk;
    const a = testing.allocator;
    var fx: WalkFx = undefined;
    try fx.init(a, 8); // headers 8..20 only: height 7 is missing
    defer fx.deinit(a);
    var walk = PeerManager.CoinMtpWalk.init(&fx.pm, fx.hashes[20], 20);
    defer walk.deinit();
    // MTP(18) needs heights 8..18: all present.
    try testing.expectEqual(WalkFx.BASE_TS + 13 * 100, PeerManager.CoinMtpWalk.trampoline(@ptrCast(&walk), 18));
    try testing.expect(walk.err == null);
    // MTP(15) needs 5..15: height 7 is missing. The walk must not answer a
    // usable MTP; it records an error so the caller voids the result.
    _ = PeerManager.CoinMtpWalk.trampoline(@ptrCast(&walk), 15);
    try testing.expect(walk.err != null);
}

test "tests_bip68_coin_mtp_ancestor: a missing ancestor below the snapshot base keeps the assumeutxo trust" {
    if (!@hasDecl(PeerManager, "CoinMtpWalk")) return error.TestExpectedCoinMtpWalk;
    const a = testing.allocator;
    var fx: WalkFx = undefined;
    try fx.init(a, 8);
    defer fx.deinit(a);
    // The node booted from a snapshot whose base is height 12 (headers below
    // the base are not in the datadir, as after a --load-snapshot boot).
    fx.pm.setSnapshotBaseMtp(1, 12);
    var walk = PeerManager.CoinMtpWalk.init(&fx.pm, fx.hashes[20], 20);
    defer walk.deinit();
    try testing.expectEqual(@as(u32, 0), PeerManager.CoinMtpWalk.trampoline(@ptrCast(&walk), 15));
    try testing.expect(walk.err == null);
}

test "tests_bip68_coin_mtp_ancestor: a height above the block's parent fails closed" {
    if (!@hasDecl(PeerManager, "CoinMtpWalk")) return error.TestExpectedCoinMtpWalk;
    const a = testing.allocator;
    var fx: WalkFx = undefined;
    try fx.init(a, 1);
    defer fx.deinit(a);
    var walk = PeerManager.CoinMtpWalk.init(&fx.pm, fx.hashes[10], 10);
    defer walk.deinit();
    _ = PeerManager.CoinMtpWalk.trampoline(@ptrCast(&walk), 11);
    try testing.expect(walk.err != null);
}
