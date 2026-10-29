//! Security audit 2026-10-29, finding C2: P2P headers were accepted with no
//! proof-of-work check.
//!
//! The `.headers` handler ran only the contextual gates (nBits, MTP,
//! timewarp, future time). Nothing on the header path compared a header's
//! hash with its own target, so a peer could send headers with the right
//! nBits and timestamps and no hashing at all. They became the connect
//! queue, grew expected_blocks and the header DB without bound, and a fake
//! fork could arm pending_reorg. Core refuses such a message in
//! CheckHeadersPoW (net_processing.cpp:2617-2623, called at :2985) before
//! anything is stored, and punishes the peer.
//!
//! Regtest's powLimit lets about half of all hashes pass, so a random header
//! cannot tell a check apart from no check. These tests grind the nonce the
//! other way: each "unhashed" header has the required nBits and a valid
//! timestamp but a hash ABOVE its target. A mainnet-params test covers the
//! audit's exact shape (nonce 0, no hashing). Every test drives the real
//! `.headers` handler through `ingestHeadersMessage` and uses only APIs that
//! exist on the pre-fix tree, so the same file gives the fail-before run.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const storage = @import("storage.zig");
const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

const REGTEST_BITS: u32 = 0x207fffff;
const MAINNET_BITS: u32 = 0x1d00ffff;

/// A header on `prev` whose proof of work passes (`want_valid`) or fails.
fn grind(params: *const consensus.NetworkParams, prev: types.Hash256, bits: u32, timestamp: u32, tag: u8, want_valid: bool) types.BlockHeader {
    var h = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = [_]u8{tag} ** 32,
        .timestamp = timestamp,
        .bits = bits,
        .nonce = 0,
    };
    while (consensus.validateProofOfWork(&h, params) != want_valid) h.nonce +%= 1;
    return h;
}

/// Coinbase-only regtest block at `height` (<= 16) on `prev`, with real PoW.
fn mineBlock(a: std.mem.Allocator, prev: types.Hash256, height: u32, tag: u8) !types.Block {
    const params = &consensus.REGTEST;
    const script_sig = try a.dupe(u8, &[_]u8{ @as(u8, @intCast(0x50 + height)), 0x01, tag });
    const inputs = try a.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const spk = try a.dupe(u8, &[_]u8{0x51});
    const outputs = try a.alloc(types.TxOut, 1);
    outputs[0] = .{ .value = 5_000_000_000, .script_pubkey = spk };
    const txs = try a.alloc(types.Transaction, 1);
    txs[0] = .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = prev,
        .merkle_root = try crypto.computeTxid(&txs[0], a),
        .timestamp = params.genesis_header.timestamp + height * 600 + tag,
        .bits = REGTEST_BITS,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    return .{ .header = header, .transactions = txs };
}

fn cloneBlock(a: std.mem.Allocator, b: *const types.Block) !types.Block {
    var w = serialize.Writer.init(a);
    defer w.deinit();
    try serialize.writeBlock(&w, b);
    var r = serialize.Reader{ .data = w.list.items };
    return serialize.readBlock(&r, a);
}

/// A chainstate at genesis on a temp DB, a PeerManager on `params` and one
/// handshake-complete socketpair peer.
const Fx = struct {
    a: std.mem.Allocator,
    params: *const consensus.NetworkParams,
    tmp: std.testing.TmpDir,
    path: []u8,
    db: storage.Database,
    cs: storage.ChainState,
    pm: PeerManager,
    peer: *Peer,
    remote: std.posix.fd_t,

    fn init(self: *Fx, a: std.mem.Allocator, params: *const consensus.NetworkParams) !void {
        self.a = a;
        self.params = params;
        self.tmp = testing.tmpDir(.{});
        self.path = try self.tmp.dir.realpathAlloc(a, ".");
        self.db = try storage.Database.open(self.path, 64, a);
        self.cs = storage.ChainState.init(&self.db, 64, a);
        self.cs.wireUtxoParent();
        self.cs.setNetworkParams(params);
        self.cs.best_hash = params.genesis_hash;
        self.cs.initGenesisTimestamp(params.genesis_header.timestamp);
        self.pm = PeerManager.init(a, params);
        self.pm.anchors_path = "/dev/null";
        self.pm.ban_list.file_path = null; // never write banlist.json from a test
        self.pm.chain_state = &self.cs;

        var fds: [2]i32 = undefined;
        try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
        const p = try a.create(Peer);
        p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8333), params, a);
        p.state = .handshake_complete;
        p.services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
        try self.pm.peers.append(p);
        self.peer = p;
        self.remote = fds[1];
    }

    fn deinit(self: *Fx) void {
        std.posix.close(self.remote);
        self.pm.chain_state = null;
        self.pm.deinit();
        self.cs.deinit();
        self.db.close();
        self.a.free(self.path);
        self.tmp.cleanup();
    }

    fn send(self: *Fx, hdrs: []const types.BlockHeader) !void {
        const owned = try self.a.dupe(types.BlockHeader, hdrs);
        try self.pm.ingestHeadersMessage(self.peer, owned);
    }

    fn queued(self: *Fx, hash: types.Hash256) bool {
        for (self.pm.expected_blocks.items) |e| {
            if (std.mem.eql(u8, &e, &hash)) return true;
        }
        return false;
    }
};

test "sec_p2p_headers_pow: a header that misses its own nBits target is refused, not queued, and the peer is punished" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;

    // Required nBits, timestamp past MTP and not in the future: only the
    // proof of work is wrong.
    const bad = grind(p, p.genesis_hash, REGTEST_BITS, p.genesis_header.timestamp + 600, 1, false);
    const bad_hash = crypto.computeBlockHash(&bad);
    try fx.send(&.{bad});

    try testing.expect(!fx.queued(bad_hash));
    try testing.expectEqual(@as(usize, 0), fx.pm.expected_blocks.items.len);
    try testing.expect(!fx.pm.header_index.contains(bad_hash));
    try testing.expect(fx.peer.should_ban);
}

test "sec_p2p_headers_pow: one header without proof of work refuses the whole message" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;

    const h1 = grind(p, p.genesis_hash, REGTEST_BITS, t0 + 600, 1, true);
    const h2 = grind(p, crypto.computeBlockHash(&h1), REGTEST_BITS, t0 + 1200, 2, false);
    const h3 = grind(p, crypto.computeBlockHash(&h2), REGTEST_BITS, t0 + 1800, 3, true);
    try fx.send(&.{ h1, h2, h3 });

    // Core CheckHeadersPoW rejects the message as a whole: not even the valid
    // prefix is admitted.
    try testing.expectEqual(@as(usize, 0), fx.pm.expected_blocks.items.len);
    try testing.expect(!fx.pm.header_index.contains(crypto.computeBlockHash(&h1)));
    try testing.expect(!fx.pm.header_index.contains(crypto.computeBlockHash(&h2)));
    try testing.expect(!fx.pm.header_index.contains(crypto.computeBlockHash(&h3)));
    try testing.expect(fx.peer.should_ban);
}

test "sec_p2p_headers_pow: a competing fork without proof of work never reaches header_index or pending_reorg" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;

    // Active chain: genesis <- b1, connected.
    var b1 = try mineBlock(fx.a, p.genesis_hash, 1, 1);
    defer serialize.freeBlock(fx.a, &b1);
    const b1_hash = crypto.computeBlockHash(&b1.header);
    try fx.send(&.{b1.header});
    try fx.pm.ingestBlockMessage(fx.peer, try cloneBlock(fx.a, &b1));
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);
    try testing.expect(!fx.peer.should_ban);

    // Fork off genesis, two headers deep (more work than the 1-block active
    // chain), with the required nBits and no proof of work.
    const f1 = grind(p, p.genesis_hash, REGTEST_BITS, t0 + 650, 7, false);
    const f2 = grind(p, crypto.computeBlockHash(&f1), REGTEST_BITS, t0 + 1250, 8, false);
    try fx.send(&.{ f1, f2 });

    try testing.expect(!fx.pm.header_index.contains(crypto.computeBlockHash(&f1)));
    try testing.expect(!fx.pm.header_index.contains(crypto.computeBlockHash(&f2)));
    try testing.expect(fx.pm.pending_reorg == null);
    try testing.expect(fx.peer.should_ban);
    // The active chain is untouched.
    try testing.expectEqual(@as(u32, 1), fx.cs.best_height);
    try testing.expectEqualSlices(u8, &b1_hash, &fx.cs.best_hash);
}

test "sec_p2p_headers_pow: mainnet headers with the right nBits and no hashing are refused" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.MAINNET);
    defer fx.deinit();
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;

    // The audit's shape: correct difficulty-1 nBits, valid timestamps, nonce
    // never searched. Each hash misses the target with probability 1 - 2^-32;
    // `grind` makes that certain.
    var hdrs: [3]types.BlockHeader = undefined;
    var prev = p.genesis_hash;
    for (&hdrs, 0..) |*h, i| {
        h.* = grind(p, prev, MAINNET_BITS, t0 + 600 * @as(u32, @intCast(i + 1)), @intCast(i + 1), false);
        prev = crypto.computeBlockHash(h);
    }
    try fx.send(&hdrs);

    try testing.expectEqual(@as(usize, 0), fx.pm.expected_blocks.items.len);
    for (&hdrs) |*h| try testing.expect(!fx.pm.header_index.contains(crypto.computeBlockHash(h)));
    try testing.expect(fx.peer.should_ban);
}

test "sec_p2p_headers_pow: control, headers that meet their target are still admitted" {
    var fx: Fx = undefined;
    try fx.init(testing.allocator, &consensus.REGTEST);
    defer fx.deinit();
    const p = fx.params;
    const t0 = p.genesis_header.timestamp;

    const h1 = grind(p, p.genesis_hash, REGTEST_BITS, t0 + 600, 1, true);
    const h2 = grind(p, crypto.computeBlockHash(&h1), REGTEST_BITS, t0 + 1200, 2, true);
    try fx.send(&.{ h1, h2 });

    try testing.expect(fx.queued(crypto.computeBlockHash(&h1)));
    try testing.expect(fx.queued(crypto.computeBlockHash(&h2)));
    try testing.expect(fx.pm.header_index.contains(crypto.computeBlockHash(&h2)));
    try testing.expect(!fx.peer.should_ban);
}
