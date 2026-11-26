//! cffix-clearbit-precomputed-sighash: the whole-tx sighash digests are built
//! once per transaction, not once per signature check.
//!
//! Core: `PrecomputedTransactionData::Init` (script/interpreter.cpp:1403-1460)
//! hashes prevouts / sequences / outputs (and, for taproot, spent amounts and
//! spent scriptPubKeys) once per tx; every CScriptCheck of the tx reads them.
//! clearbit's `crypto.segwitSighash` and `taproot_sighash.buildSigMsg` rebuilt
//! them on every call, so verifying an N-input tx hashed O(N x tx size).
//!
//! Instruments:
//!   (A) bytes ALLOCATED while a production path verifies every input of one
//!       N-input tx.  The digest builders allocate their scratch buffers from
//!       the engine allocator, so on master the per-input bytes grow with N
//!       (each check serializes all N prevouts); with the per-tx data they do
//!       not.  Paths that take a caller allocator: block verify (the
//!       single-threaded branch of `verifyBlockScriptsParallel`) and mempool
//!       accept.  Uses master API only, so it compiles and FAILS on master.
//!   (B) `crypto.test_txwide_digest_bytes`, bytes fed to SHA-256 for the
//!       whole-tx digests (added by the fix; the test fails on master because
//!       there is no per-tx data to count).  Covers the parallel script-check
//!       queue, whose jobs allocate from per-job arenas that also hold a full
//!       re-parse of the tx, so (A) cannot isolate the digest part there.
//!   Negative control: the same counter with the per-tx data withheld grows
//!   with N, so (B) can see a rebuild.
//!
//! Bar (item text): per-input digest work at N=200 under 2x that at N=20
//! (linear-in-N work per input gives ~10x).
//!
//! Vectors: BIP-143's "Native P2WPKH" example (with its hashPrevouts /
//! hashSequence / hashOutputs) and all 7 keyPathSpending inputs of Core's
//! bip341_wallet_vectors.json (five single hashes, sigMsg, sigHash) through
//! the direct AND the precomputed path; a seeded differential over every
//! hash type, annex / script-path, SIGHASH_SINGLE out of range and a
//! >0xFFFF-byte output script; and a stale-cache control proving the
//! comparison would catch a wrong cached digest.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const script = @import("script.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const validation = @import("validation.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const taproot_sighash = @import("taproot_sighash.zig");
const secp = @import("secp.zig").c;

const HAS_TXDATA = @hasDecl(crypto, "PrecomputedTxData") and @hasDecl(crypto, "test_txwide_digest_bytes");

const N_SMALL: usize = 20;
const N_LARGE: usize = 200;
const RATIO_BAR: f64 = 2.0;

// ---------------------------------------------------------------------------
// Counting allocator (single-threaded use only)
// ---------------------------------------------------------------------------

const CountingAllocator = struct {
    child: std.mem.Allocator,
    bytes: usize = 0,

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.bytes += len;
        return self.child.rawAlloc(len, ptr_align, ret);
    }
    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ok = self.child.rawResize(buf, buf_align, new_len, ret);
        if (ok and new_len > buf.len) self.bytes += new_len - buf.len;
        return ok;
    }
    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(buf, buf_align, ret);
    }
};

// ---------------------------------------------------------------------------
// Signed N-input fixtures
// ---------------------------------------------------------------------------

const Kind = enum { p2wpkh, p2tr };

const Keys = struct {
    ctx: *secp.secp256k1_context,
    seckey: [32]u8,
    pubkey: [33]u8,
    keypair: secp.secp256k1_keypair,
    xonly: [32]u8,

    fn init() !Keys {
        const ctx = secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN | secp.SECP256K1_CONTEXT_VERIFY) orelse
            return error.SecpContextFailed;
        var k = Keys{ .ctx = ctx, .seckey = [_]u8{0x42} ** 32, .pubkey = undefined, .keypair = undefined, .xonly = undefined };
        var pk: secp.secp256k1_pubkey = undefined;
        if (secp.secp256k1_ec_pubkey_create(ctx, &pk, &k.seckey) != 1) return error.KeyFailed;
        var len: usize = 33;
        if (secp.secp256k1_ec_pubkey_serialize(ctx, &k.pubkey, &len, &pk, secp.SECP256K1_EC_COMPRESSED) != 1) return error.KeyFailed;
        if (secp.secp256k1_keypair_create(ctx, &k.keypair, &k.seckey) != 1) return error.KeyFailed;
        var xo: secp.secp256k1_xonly_pubkey = undefined;
        if (secp.secp256k1_keypair_xonly_pub(ctx, &xo, null, &k.keypair) != 1) return error.KeyFailed;
        if (secp.secp256k1_xonly_pubkey_serialize(ctx, &k.xonly, &xo) != 1) return error.KeyFailed;
        return k;
    }
    fn deinit(self: *Keys) void {
        secp.secp256k1_context_destroy(self.ctx);
    }
};

/// One N-input tx, every input validly signed, plus a 2-tx block (dummy
/// coinbase + the tx) and a SigopUtxoView over its prevouts.  All memory is
/// in `arena`, which is NOT the measured allocator.
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    tx: types.Transaction,
    amounts: []i64,
    scripts: [][]const u8,
    txs: [2]types.Transaction,

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
    }

    fn block(self: *Fixture) types.Block {
        return .{
            .header = .{ .version = 4, .prev_block = [_]u8{0} ** 32, .merkle_root = [_]u8{0} ** 32, .timestamp = 0, .bits = 0, .nonce = 0 },
            .transactions = &self.txs,
        };
    }

    fn lookup(ctx: *anyopaque, outpoint: *const types.OutPoint) ?validation.SigopUtxoEntry {
        const self: *Fixture = @ptrCast(@alignCast(ctx));
        for (self.tx.inputs, 0..) |inp, i| {
            if (std.mem.eql(u8, &inp.previous_output.hash, &outpoint.hash) and inp.previous_output.index == outpoint.index)
                return .{ .script_pubkey = self.scripts[i], .amount = self.amounts[i] };
        }
        return null;
    }

    fn view(self: *Fixture) validation.SigopUtxoView {
        return .{ .context = @ptrCast(self), .lookupFn = lookup };
    }
};

const coinbase_inputs = [_]types.TxIn{.{
    .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xFFFF_FFFF },
    .script_sig = &[_]u8{ 0x02, 0x01, 0x00 },
    .sequence = 0xFFFF_FFFF,
    .witness = &.{},
}};
const coinbase_outputs = [_]types.TxOut{.{ .value = 0, .script_pubkey = &[_]u8{0x51} }};

/// `corrupt_input`: index of an input whose signature is made invalid (S
/// flipped / Schnorr byte flipped), or null.
fn buildFixture(kind: Kind, n: usize, keys: *const Keys, corrupt_input: ?usize) !*Fixture {
    const f = try testing.allocator.create(Fixture);
    errdefer testing.allocator.destroy(f);
    f.arena = std.heap.ArenaAllocator.init(testing.allocator);
    errdefer f.arena.deinit();
    const a = f.arena.allocator();

    const spk: []u8 = switch (kind) {
        .p2wpkh => blk: {
            const s = try a.alloc(u8, 22);
            s[0] = 0x00;
            s[1] = 0x14;
            const h = crypto.hash160(&keys.pubkey);
            @memcpy(s[2..22], &h);
            break :blk s;
        },
        .p2tr => blk: {
            const s = try a.alloc(u8, 34);
            s[0] = 0x51;
            s[1] = 0x20;
            @memcpy(s[2..34], &keys.xonly);
            break :blk s;
        },
    };

    const inputs = try a.alloc(types.TxIn, n);
    f.amounts = try a.alloc(i64, n);
    f.scripts = try a.alloc([]const u8, n);
    var total: i64 = 0;
    for (inputs, 0..) |*inp, i| {
        var h = [_]u8{0x77} ** 32;
        std.mem.writeInt(u64, h[0..8], @as(u64, i) + 1, .little);
        inp.* = .{
            .previous_output = .{ .hash = h, .index = @intCast(i % 3) },
            .script_sig = &.{},
            .sequence = 0xFFFF_FFFD - @as(u32, @intCast(i % 2)),
            .witness = &.{},
        };
        f.amounts[i] = 100_000 + @as(i64, @intCast(i));
        f.scripts[i] = spk;
        total += f.amounts[i];
    }
    const outputs = try a.alloc(types.TxOut, 2);
    const out_spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCC} ** 20;
    const fee: i64 = 1_000 * @as(i64, @intCast(n));
    outputs[0] = .{ .value = @divTrunc(total, 2), .script_pubkey = try a.dupe(u8, &out_spk) };
    outputs[1] = .{ .value = total - @divTrunc(total, 2) - fee, .script_pubkey = try a.dupe(u8, &out_spk) };
    f.tx = .{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    // Sign every input (witnesses do not enter either sighash).
    for (0..n) |i| {
        const w = try a.alloc([]const u8, if (kind == .p2wpkh) 2 else 1);
        switch (kind) {
            .p2wpkh => {
                var sc: [25]u8 = undefined;
                sc[0] = 0x76;
                sc[1] = 0xa9;
                sc[2] = 0x14;
                @memcpy(sc[3..23], spk[2..22]);
                sc[23] = 0x88;
                sc[24] = 0xac;
                const msg = try crypto.segwitSighash(&f.tx, i, &sc, f.amounts[i], 0x01, a);
                var sig: secp.secp256k1_ecdsa_signature = undefined;
                if (secp.secp256k1_ecdsa_sign(keys.ctx, &sig, &msg, &keys.seckey, null, null) != 1) return error.SignFailed;
                var der: [80]u8 = undefined;
                var len: usize = 72;
                if (secp.secp256k1_ecdsa_signature_serialize_der(keys.ctx, &der, &len, &sig) != 1) return error.SignFailed;
                if (corrupt_input == i) der[len - 2] ^= 0x01;
                der[len] = 0x01;
                w[0] = try a.dupe(u8, der[0 .. len + 1]);
                w[1] = try a.dupe(u8, &keys.pubkey);
            },
            .p2tr => {
                // Even inputs SIGHASH_DEFAULT (64-byte sig), odd SIGHASH_ALL (65).
                const ht: u8 = if (i % 2 == 0) 0x00 else 0x01;
                const msg = try taproot_sighash.computeTaprootSighash(a, &f.tx, i, .{ .amounts = f.amounts, .scripts = f.scripts }, ht, null, null);
                var sig: [65]u8 = undefined;
                if (secp.secp256k1_schnorrsig_sign32(keys.ctx, &sig, &msg, &keys.keypair, null) != 1) return error.SignFailed;
                if (corrupt_input == i) sig[10] ^= 0x01;
                sig[64] = ht;
                w[0] = try a.dupe(u8, if (ht == 0x00) sig[0..64] else sig[0..65]);
            },
        }
        inputs[i].witness = w;
    }
    f.txs = .{
        .{ .version = 1, .inputs = &coinbase_inputs, .outputs = &coinbase_outputs, .lock_time = 0 },
        f.tx,
    };
    return f;
}

fn destroyFixture(f: *Fixture) void {
    f.deinit();
    testing.allocator.destroy(f);
}

fn ratio(small_total: usize, large_total: usize) f64 {
    const s = @as(f64, @floatFromInt(small_total)) / @as(f64, @floatFromInt(N_SMALL));
    const l = @as(f64, @floatFromInt(large_total)) / @as(f64, @floatFromInt(N_LARGE));
    return l / s;
}

// ---------------------------------------------------------------------------
// (A) Allocation instrument — master API only
// ---------------------------------------------------------------------------

const Work = struct { alloc: usize, digest: usize };

/// Bytes allocated (and, on head, whole-tx digest bytes hashed) by the block
/// path (single-threaded branch) verifying the fixture's N inputs.
fn blockWork(kind: Kind, n: usize, keys: *const Keys) !Work {
    const f = try buildFixture(kind, n, keys, null);
    defer destroyFixture(f);
    const blk = f.block();
    const v = f.view();
    var ca = CountingAllocator{ .child = testing.allocator };
    const d0 = counterNow();
    const ok = try validation.verifyBlockScriptsParallel(&blk, 800_000, &consensus.MAINNET, &v, .{ .enabled = false }, ca.allocator());
    try testing.expect(ok);
    return .{ .alloc = ca.bytes, .digest = @intCast(counterNow() - d0) };
}

fn mempoolWork(kind: Kind, n: usize, keys: *const Keys) !Work {
    const f = try buildFixture(kind, n, keys, null);
    defer destroyFixture(f);
    var chain_state = storage.ChainState.init(null, 64, testing.allocator);
    defer chain_state.deinit();
    chain_state.best_height = 800_000;
    for (f.tx.inputs, 0..) |inp, i| {
        try chain_state.utxo_set.add(&inp.previous_output, &types.TxOut{ .value = f.amounts[i], .script_pubkey = f.scripts[i] }, 700_000, false);
    }
    var ca = CountingAllocator{ .child = testing.allocator };
    var pool = mempool_mod.Mempool.init(&chain_state, &consensus.MAINNET, ca.allocator());
    defer pool.deinit();
    // addTransaction, not acceptToMemoryPool(test_accept=true): the dry run
    // does not run the script checks at all (separate item), so it would
    // measure nothing.  The corrupted-signature control below pins that this
    // path really verifies every input.
    const before = ca.bytes;
    const d0 = counterNow();
    _ = pool.addTransaction(f.tx) catch |e| {
        std.debug.print("cffix mempool fixture rejected: {s}\n", .{@errorName(e)});
        return e;
    };
    try testing.expectEqual(@as(usize, 1), pool.entries.count());
    return .{ .alloc = ca.bytes - before, .digest = @intCast(counterNow() - d0) };
}

fn expectFlat(label: []const u8, small: usize, large: usize) !void {
    const r = ratio(small, large);
    std.debug.print("cffix {s}: N={d} {d} B ({d} B/input), N={d} {d} B ({d} B/input), per-input ratio {d:.2} (bar < {d:.1})\n", .{
        label, N_SMALL, small, small / N_SMALL, N_LARGE, large, large / N_LARGE, r, RATIO_BAR,
    });
    if (r >= RATIO_BAR) {
        std.debug.print("cffix {s}: per-input work grows with N: the whole-tx sighash digests are rebuilt per signature check instead of once per tx (Core PrecomputedTransactionData)\n", .{label});
    }
    try testing.expect(r < RATIO_BAR);
}

test "cffix precomputed sighash: block verify, N segwit v0 inputs, allocation per input flat in N" {
    var keys = try Keys.init();
    defer keys.deinit();
    const small = try blockWork(.p2wpkh, N_SMALL, &keys);
    const large = try blockWork(.p2wpkh, N_LARGE, &keys);
    try expectFlat("block P2WPKH alloc", small.alloc, large.alloc);
    // Head only: the digest counter on the same run must be flat too, so
    // the pass comes from sharing the digests, not from cheaper rebuilds.
    if (comptime HAS_TXDATA) try expectFlat("block P2WPKH digest", small.digest, large.digest);
}

test "cffix precomputed sighash: block verify, N taproot key-path inputs, allocation per input flat in N" {
    var keys = try Keys.init();
    defer keys.deinit();
    const small = try blockWork(.p2tr, N_SMALL, &keys);
    const large = try blockWork(.p2tr, N_LARGE, &keys);
    try expectFlat("block P2TR alloc", small.alloc, large.alloc);
    // Head only: the digest counter on the same run must be flat too, so
    // the pass comes from sharing the digests, not from cheaper rebuilds.
    if (comptime HAS_TXDATA) try expectFlat("block P2TR digest", small.digest, large.digest);
}

test "cffix precomputed sighash: mempool accept, N segwit v0 inputs, allocation per input flat in N" {
    var keys = try Keys.init();
    defer keys.deinit();
    const small = try mempoolWork(.p2wpkh, N_SMALL, &keys);
    const large = try mempoolWork(.p2wpkh, N_LARGE, &keys);
    try expectFlat("mempool P2WPKH alloc", small.alloc, large.alloc);
    // Head only: the digest counter on the same run must be flat too, so
    // the pass comes from sharing the digests, not from cheaper rebuilds.
    if (comptime HAS_TXDATA) try expectFlat("mempool P2WPKH digest", small.digest, large.digest);
}

test "cffix precomputed sighash: mempool accept, N taproot key-path inputs, allocation per input flat in N" {
    var keys = try Keys.init();
    defer keys.deinit();
    const small = try mempoolWork(.p2tr, N_SMALL, &keys);
    const large = try mempoolWork(.p2tr, N_LARGE, &keys);
    try expectFlat("mempool P2TR alloc", small.alloc, large.alloc);
    // Head only: the digest counter on the same run must be flat too, so
    // the pass comes from sharing the digests, not from cheaper rebuilds.
    if (comptime HAS_TXDATA) try expectFlat("mempool P2TR digest", small.digest, large.digest);
}

// ---------------------------------------------------------------------------
// (B) Digest-byte counter — parallel script-check queue + negative control
// ---------------------------------------------------------------------------

fn counterNow() u64 {
    return if (comptime HAS_TXDATA) crypto.test_txwide_digest_bytes.load(.monotonic) else 0;
}

/// Digest bytes while the parallel script-check queue (3 extra workers, so
/// jobs really run on other threads) verifies the fixture.
fn queueDigestBytes(kind: Kind, n: usize, keys: *const Keys) !usize {
    const f = try buildFixture(kind, n, keys, null);
    defer destroyFixture(f);
    const blk = f.block();
    const v = f.view();
    const q = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 3);
    defer q.deinit();
    const before = counterNow();
    const ok = try validation.verifyBlockScriptsParallel(&blk, 800_000, &consensus.MAINNET, &v, .{ .queue = q, .min_inputs_for_parallel = 1 }, testing.allocator);
    try testing.expect(ok);
    return @intCast(counterNow() - before);
}

/// Negative control: the same inputs through bare engines with the per-tx
/// data withheld.  The counter must see the per-check rebuilds.
fn bareEngineDigestBytes(kind: Kind, n: usize, keys: *const Keys) !usize {
    const f = try buildFixture(kind, n, keys, null);
    defer destroyFixture(f);
    const flags = validation.getBlockScriptFlags(800_000, &consensus.MAINNET);
    const before = counterNow();
    for (f.tx.inputs, 0..) |inp, i| {
        var engine = script.ScriptEngine.initWithPrevouts(testing.allocator, &f.tx, i, f.amounts[i], flags, f.amounts, f.scripts);
        defer engine.deinit();
        try testing.expect(try engine.verify(inp.script_sig, f.scripts[i], inp.witness));
    }
    return @intCast(counterNow() - before);
}

fn queueFlat() !void {
    var keys = try Keys.init();
    defer keys.deinit();
    try expectFlat("queue P2WPKH digest", try queueDigestBytes(.p2wpkh, N_SMALL, &keys), try queueDigestBytes(.p2wpkh, N_LARGE, &keys));
    try expectFlat("queue P2TR digest", try queueDigestBytes(.p2tr, N_SMALL, &keys), try queueDigestBytes(.p2tr, N_LARGE, &keys));
}

test "cffix precomputed sighash: parallel script-check queue, digest bytes per input flat in N (segwit v0 + taproot)" {
    if (comptime HAS_TXDATA) {
        try queueFlat();
    } else {
        std.debug.print("cffix queue: no crypto.PrecomputedTxData / digest counter: every job's signature checks rebuild the whole-tx digests\n", .{});
        return error.NoPerTxSighashData;
    }
}

fn negativeControlBody() !void {
    var keys = try Keys.init();
    defer keys.deinit();
    inline for (.{ Kind.p2wpkh, Kind.p2tr }) |kind| {
        const r = ratio(try bareEngineDigestBytes(kind, N_SMALL, &keys), try bareEngineDigestBytes(kind, N_LARGE, &keys));
        std.debug.print("cffix control {s}: per-input digest ratio without per-tx data {d:.2} (must be >= 5)\n", .{ @tagName(kind), r });
        try testing.expect(r >= 5.0);
    }
}

test "cffix precomputed sighash: negative control, digest counter sees per-check rebuilds without per-tx data" {
    if (comptime HAS_TXDATA) try negativeControlBody() else return error.NoPerTxSighashData;
}

// ---------------------------------------------------------------------------
// Verdict controls: a bad signature anywhere still rejects, every path.
// The valid fixtures are accepted by the same paths in the tests above.
// ---------------------------------------------------------------------------

test "cffix precomputed sighash: one corrupted signature among N rejects in block (serial + queue) and mempool" {
    var keys = try Keys.init();
    defer keys.deinit();
    inline for (.{ Kind.p2wpkh, Kind.p2tr }) |kind| {
        for ([_]usize{ 0, 117, N_LARGE - 1 }) |bad| {
            const f = try buildFixture(kind, N_LARGE, &keys, bad);
            defer destroyFixture(f);
            const blk = f.block();
            const v = f.view();
            try testing.expect(!try validation.verifyBlockScriptsParallel(&blk, 800_000, &consensus.MAINNET, &v, .{ .enabled = false }, testing.allocator));
            const q = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 3);
            defer q.deinit();
            try testing.expect(!try validation.verifyBlockScriptsParallel(&blk, 800_000, &consensus.MAINNET, &v, .{ .queue = q, .min_inputs_for_parallel = 1 }, testing.allocator));

            var chain_state = storage.ChainState.init(null, 64, testing.allocator);
            defer chain_state.deinit();
            chain_state.best_height = 800_000;
            for (f.tx.inputs, 0..) |inp, i| {
                try chain_state.utxo_set.add(&inp.previous_output, &types.TxOut{ .value = f.amounts[i], .script_pubkey = f.scripts[i] }, 700_000, false);
            }
            var pool = mempool_mod.Mempool.init(&chain_state, &consensus.MAINNET, testing.allocator);
            defer pool.deinit();
            try testing.expectError(mempool_mod.MempoolError.ScriptVerifyFailed, pool.addTransaction(f.tx));
            try testing.expectEqual(@as(usize, 0), pool.entries.count());
        }
    }
}

// ---------------------------------------------------------------------------
// Sighash vectors through the direct and the precomputed path
// ---------------------------------------------------------------------------

fn parseTxHex(a: std.mem.Allocator, hex: []const u8) !types.Transaction {
    const raw = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(raw, hex);
    var reader = serialize.Reader{ .data = raw };
    return serialize.readTransaction(&reader, a);
}

fn hex32(hex: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

/// The vector txs are unsigned; Core's Init only builds digests for a tx
/// with a witness.  Give every input a dummy witness item (no sighash
/// commits to witnesses) so the precomputed path is the one under test.
fn withDummyWitness(a: std.mem.Allocator, tx: *types.Transaction) !void {
    const inputs = try a.dupe(types.TxIn, tx.inputs);
    const item = try a.alloc([]const u8, 1);
    item[0] = &[_]u8{0x01};
    for (inputs) |*inp| inp.witness = item;
    tx.inputs = inputs;
}

const BIP143_RAW = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

fn bip143VectorBody() !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tx = try parseTxHex(a, BIP143_RAW);
    try withDummyWitness(a, &tx);
    const sc = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{ 0x1d, 0x0f, 0x17, 0x2a, 0x0e, 0xcb, 0x48, 0xae, 0xe1, 0xbe, 0x1f, 0x26, 0x87, 0xd2, 0x96, 0x3a, 0xe3, 0x3f, 0x71, 0xa1 } ++ [_]u8{ 0x88, 0xac };
    const want = try hex32("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");

    const txdata = crypto.PrecomputedTxData.init(&tx, &.{}, &.{});
    try testing.expect(txdata.bip143_ready);
    try testing.expectEqual(try hex32("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37"), txdata.hash_prevouts);
    try testing.expectEqual(try hex32("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"), txdata.hash_sequence);
    try testing.expectEqual(try hex32("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"), txdata.hash_outputs);

    try testing.expectEqual(want, try crypto.segwitSighash(&tx, 1, &sc, 600_000_000, 0x01, a));
    try testing.expectEqual(want, try crypto.segwitSighashTxData(&tx, 1, &sc, 600_000_000, 0x01, a, &txdata));
}

test "cffix precomputed sighash: BIP-143 native P2WPKH example, direct and precomputed" {
    if (comptime HAS_TXDATA) try bip143VectorBody() else return error.NoPerTxSighashData;
}

const VECTORS_JSON = @embedFile("testdata/bip341_wallet_vectors.json");

fn bip341VectorBody() !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, VECTORS_JSON, .{});
    const kps = parsed.object.get("keyPathSpending").?.array.items;
    try testing.expectEqual(@as(usize, 1), kps.len);
    var checked: usize = 0;
    for (kps) |v| {
        const given = v.object.get("given").?.object;
        var tx = try parseTxHex(a, given.get("rawUnsignedTx").?.string);
        const utxos = given.get("utxosSpent").?.array.items;
        const amounts = try a.alloc(i64, utxos.len);
        const scripts = try a.alloc([]const u8, utxos.len);
        for (utxos, 0..) |u, i| {
            amounts[i] = u.object.get("amountSats").?.integer;
            const h = u.object.get("scriptPubKey").?.string;
            const s = try a.alloc(u8, h.len / 2);
            _ = try std.fmt.hexToBytes(s, h);
            scripts[i] = s;
        }
        try withDummyWitness(a, &tx);
        const txdata = crypto.PrecomputedTxData.init(&tx, amounts, scripts);
        try testing.expect(txdata.bip341_ready);
        const inter = v.object.get("intermediary").?.object;
        try testing.expectEqual(try hex32(inter.get("hashPrevouts").?.string), txdata.prevouts_single_hash);
        try testing.expectEqual(try hex32(inter.get("hashAmounts").?.string), txdata.spent_amounts_single_hash);
        try testing.expectEqual(try hex32(inter.get("hashScriptPubkeys").?.string), txdata.spent_scripts_single_hash);
        try testing.expectEqual(try hex32(inter.get("hashSequences").?.string), txdata.sequences_single_hash);
        try testing.expectEqual(try hex32(inter.get("hashOutputs").?.string), txdata.outputs_single_hash);

        const prevouts = taproot_sighash.TaprootPrevouts{ .amounts = amounts, .scripts = scripts };
        for (v.object.get("inputSpending").?.array.items) |in| {
            const ig = in.object.get("given").?.object;
            const ii = in.object.get("intermediary").?.object;
            const idx: usize = @intCast(ig.get("txinIndex").?.integer);
            const ht: u8 = @intCast(ig.get("hashType").?.integer);
            const msg_hex = ii.get("sigMsg").?.string;
            const want_msg = try a.alloc(u8, msg_hex.len / 2);
            _ = try std.fmt.hexToBytes(want_msg, msg_hex);
            const want_hash = try hex32(ii.get("sigHash").?.string);

            var direct = std.ArrayList(u8).init(a);
            try taproot_sighash.buildSigMsg(&direct, &tx, idx, prevouts, ht, null, null);
            var cached = std.ArrayList(u8).init(a);
            try taproot_sighash.buildSigMsgTxData(&cached, &tx, idx, prevouts, ht, null, null, &txdata);
            try testing.expectEqualSlices(u8, want_msg, direct.items);
            try testing.expectEqualSlices(u8, want_msg, cached.items);
            try testing.expectEqual(want_hash, try taproot_sighash.computeTaprootSighash(a, &tx, idx, prevouts, ht, null, null));
            try testing.expectEqual(want_hash, try taproot_sighash.computeTaprootSighashTxData(a, &tx, idx, prevouts, ht, null, null, &txdata));
            checked += 1;
        }
    }
    try testing.expectEqual(@as(usize, 7), checked);
}

test "cffix precomputed sighash: Core bip341_wallet_vectors.json keyPathSpending, direct and precomputed" {
    if (comptime HAS_TXDATA) try bip341VectorBody() else return error.NoPerTxSighashData;
}

// ---------------------------------------------------------------------------
// Differential: every hash type, annex, script path, edge shapes
// ---------------------------------------------------------------------------

fn randomTx(a: std.mem.Allocator, rng: std.Random, n_in: usize, n_out: usize, big_output: bool) !struct { tx: types.Transaction, amounts: []i64, scripts: [][]const u8 } {
    const inputs = try a.alloc(types.TxIn, n_in);
    const amounts = try a.alloc(i64, n_in);
    const scripts = try a.alloc([]const u8, n_in);
    const wit = try a.alloc([]const u8, 1);
    wit[0] = &[_]u8{0x01};
    for (inputs, 0..) |*inp, i| {
        var h: [32]u8 = undefined;
        rng.bytes(&h);
        inp.* = .{ .previous_output = .{ .hash = h, .index = rng.int(u32) }, .script_sig = &.{}, .sequence = rng.int(u32), .witness = wit };
        amounts[i] = rng.intRangeAtMost(i64, 0, 21_000_000 * 100_000_000);
        // Mix of P2TR and other scripts, with varying lengths.
        const len: usize = if (i % 3 == 0) 34 else rng.intRangeAtMost(usize, 0, 300);
        const s = try a.alloc(u8, len);
        rng.bytes(s);
        if (len == 34) {
            s[0] = 0x51;
            s[1] = 0x20;
        }
        scripts[i] = s;
    }
    const outputs = try a.alloc(types.TxOut, n_out);
    for (outputs, 0..) |*o, i| {
        const len: usize = if (big_output and i == 0) 0x10005 else rng.intRangeAtMost(usize, 0, 80);
        const s = try a.alloc(u8, len);
        rng.bytes(s);
        o.* = .{ .value = rng.intRangeAtMost(i64, 0, 50 * 100_000_000), .script_pubkey = s };
    }
    return .{
        .tx = .{ .version = rng.int(i32), .inputs = inputs, .outputs = outputs, .lock_time = rng.int(u32) },
        .amounts = amounts,
        .scripts = scripts,
    };
}

fn differentialBody() !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0xC1EA_B17_5164);
    const rng = prng.random();

    const v0_types = [_]u32{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x41, 0x81, 0x82, 0x83, 0xC3, 0xFF, 0x1_0001 };
    const tr_types = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 };
    var compared: usize = 0;
    for (0..12) |round| {
        // >= 2 inputs: input 0 spends P2TR, input 1 a random script, so
        // both halves are built and both cached paths are exercised.
        const n_in = rng.intRangeAtMost(usize, 2, 9);
        const n_out = rng.intRangeAtMost(usize, 0, 5);
        const r = try randomTx(a, rng, n_in, n_out, round == 0);
        const txdata = crypto.PrecomputedTxData.init(&r.tx, r.amounts, r.scripts);
        try testing.expect(txdata.bip143_ready);
        try testing.expect(txdata.bip341_ready);
        const prevouts = taproot_sighash.TaprootPrevouts{ .amounts = r.amounts, .scripts = r.scripts };
        const annex = [_]u8{ 0x50, 0xAA, 0xBB };
        const leaf = [_]u8{0x5C} ** 32;
        for (0..n_in) |idx| {
            const sc = r.scripts[idx];
            for (v0_types) |ht| {
                try testing.expectEqual(
                    try crypto.segwitSighash(&r.tx, idx, sc, r.amounts[idx], ht, a),
                    try crypto.segwitSighashTxData(&r.tx, idx, sc, r.amounts[idx], ht, a, &txdata),
                );
                compared += 1;
            }
            for (tr_types) |ht| {
                for ([_]bool{ false, true }) |with_annex| {
                    for ([_]bool{ false, true }) |script_path| {
                        const an: ?[]const u8 = if (with_annex) &annex else null;
                        const sp: ?taproot_sighash.TapscriptContext = if (script_path) .{ .tapleaf_hash = &leaf, .codesep_pos = @intCast(idx) } else null;
                        const d = taproot_sighash.computeTaprootSighash(a, &r.tx, idx, prevouts, ht, an, sp);
                        const c = taproot_sighash.computeTaprootSighashTxData(a, &r.tx, idx, prevouts, ht, an, sp, &txdata);
                        if (d) |dv| {
                            try testing.expectEqual(dv, try c);
                        } else |de| {
                            // SIGHASH_SINGLE with no matching output: same error both ways.
                            try testing.expectError(de, c);
                        }
                        compared += 1;
                    }
                }
            }
        }
    }
    std.debug.print("cffix differential: {d} sighashes compared, precomputed == direct\n", .{compared});
    try testing.expect(compared > 500);
}

test "cffix precomputed sighash: differential, precomputed == direct for every hash type and shape" {
    if (comptime HAS_TXDATA) try differentialBody() else return error.NoPerTxSighashData;
}

fn staleCacheBody() !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(7);
    const r = try randomTx(a, prng.random(), 4, 2, false);
    const txdata = crypto.PrecomputedTxData.init(&r.tx, r.amounts, r.scripts);
    // Same shape, one output value changed after the data was built.
    const outs = try a.dupe(types.TxOut, r.tx.outputs);
    outs[1].value +%= 1;
    var mutated = r.tx;
    mutated.outputs = outs;
    const prevouts = taproot_sighash.TaprootPrevouts{ .amounts = r.amounts, .scripts = r.scripts };
    try testing.expect(!std.meta.eql(
        try crypto.segwitSighash(&mutated, 0, r.scripts[0], r.amounts[0], 0x01, a),
        try crypto.segwitSighashTxData(&mutated, 0, r.scripts[0], r.amounts[0], 0x01, a, &txdata),
    ));
    try testing.expect(!std.meta.eql(
        try taproot_sighash.computeTaprootSighash(a, &mutated, 0, prevouts, 0x00, null, null),
        try taproot_sighash.computeTaprootSighashTxData(a, &mutated, 0, prevouts, 0x00, null, null, &txdata),
    ));
    // A tx of another shape is refused by the guard: the builder recomputes.
    var fewer = r.tx;
    fewer.outputs = r.tx.outputs[0..1];
    try testing.expectEqual(
        try crypto.segwitSighash(&fewer, 0, r.scripts[0], r.amounts[0], 0x01, a),
        try crypto.segwitSighashTxData(&fewer, 0, r.scripts[0], r.amounts[0], 0x01, a, &txdata),
    );
}

test "cffix precomputed sighash: stale per-tx data changes the digest (the vector comparisons can see a wrong cache)" {
    if (comptime HAS_TXDATA) try staleCacheBody() else return error.NoPerTxSighashData;
}

fn readinessBody() !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(11);
    const r = try randomTx(a, prng.random(), 3, 2, false);
    const p2tr = [_]u8{ 0x51, 0x20 } ++ [_]u8{0x33} ** 32;
    const p2wpkh = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x44} ** 20;
    // No witness anywhere: nothing built (Core: neither flag set).
    var bare = r.tx;
    const bare_in = try a.dupe(types.TxIn, r.tx.inputs);
    for (bare_in) |*inp| inp.witness = &.{};
    bare.inputs = bare_in;
    const none = crypto.PrecomputedTxData.init(&bare, r.amounts, r.scripts);
    try testing.expect(!none.bip143_ready and !none.bip341_ready);
    // All witness inputs spend P2TR: only the BIP-341 half.
    const all_tr = [_][]const u8{ &p2tr, &p2tr, &p2tr };
    const tr_only = crypto.PrecomputedTxData.init(&r.tx, r.amounts, &all_tr);
    try testing.expect(!tr_only.bip143_ready and tr_only.bip341_ready);
    // All spend v0: only the BIP-143 half.
    const all_v0 = [_][]const u8{ &p2wpkh, &p2wpkh, &p2wpkh };
    const v0_only = crypto.PrecomputedTxData.init(&r.tx, r.amounts, &all_v0);
    try testing.expect(v0_only.bip143_ready and !v0_only.bip341_ready);
    // Spent outputs unknown: BIP-143 only, never BIP-341.
    const unknown = crypto.PrecomputedTxData.init(&r.tx, &.{}, &.{});
    try testing.expect(unknown.bip143_ready and !unknown.bip341_ready);
    // A half that is not ready falls back to the direct digest.
    const prevouts = taproot_sighash.TaprootPrevouts{ .amounts = r.amounts, .scripts = &all_tr };
    try testing.expectEqual(
        try taproot_sighash.computeTaprootSighash(a, &r.tx, 1, prevouts, 0x00, null, null),
        try taproot_sighash.computeTaprootSighashTxData(a, &r.tx, 1, prevouts, 0x00, null, null, &v0_only),
    );
    try testing.expectEqual(
        try crypto.segwitSighash(&r.tx, 1, &p2wpkh, r.amounts[1], 0x01, a),
        try crypto.segwitSighashTxData(&r.tx, 1, &p2wpkh, r.amounts[1], 0x01, a, &tr_only),
    );
}

test "cffix precomputed sighash: readiness follows Core's Init (witness + spent-output type)" {
    if (comptime HAS_TXDATA) try readinessBody() else return error.NoPerTxSighashData;
}
