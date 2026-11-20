//! `--load-snapshot` (main.zig loadSnapshotFromFile) must run the assumeutxo
//! content-hash gate, the same one loadtxoutset runs.
//!
//! Core: ChainstateManager::PopulateAndValidateSnapshot computes
//! hash_serialized over the populated coins and refuses the snapshot with
//! "Bad snapshot content hash: expected %s, got %s" when it differs from
//! m_assumeutxo_data.  The CLI path used to check only that the base block
//! hash was whitelisted, then wrote every coin and moved chain_tip, so a file
//! with any one coin altered was adopted as the node's UTXO set.
//!
//! Fixture: resources/test/utxo-299.dat is the boot-smoke fixture
//! (tools/boot-smoke-fixtures/utxo-299.dat in the meta-repo), Core's regtest
//! assumeutxo snapshot at height 299, hash_serialized d2b051ff...63e2.
//!
//! The tests call `main.importSnapshotIntoDb`, the body of
//! loadSnapshotFromFile with its process exits turned into an error.  On a
//! tree without it (the unfixed one) every test fails by name with
//! error.CliSnapshotImportHasNoHashGate.

const std = @import("std");
const testing = std.testing;
const main_mod = @import("main.zig");
const storage = @import("storage.zig");
const consensus = @import("consensus.zig");
const serialize = @import("serialize.zig");
const types = @import("types.zig");

const FIXTURE = @embedFile("../resources/test/utxo-299.dat");
const HAS_ENTRY = @hasDecl(main_mod, "importSnapshotIntoDb");

const Rig = struct {
    tmp: std.testing.TmpDir,
    dir_path: []u8,
    db: storage.Database,

    fn init() !Rig {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const dir_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
        errdefer testing.allocator.free(dir_path);
        const cs_path = try std.fmt.allocPrint(testing.allocator, "{s}/chainstate", .{dir_path});
        defer testing.allocator.free(cs_path);
        const db = try storage.Database.open(cs_path, 8, testing.allocator);
        return .{ .tmp = tmp, .dir_path = dir_path, .db = db };
    }

    fn deinit(self: *Rig) void {
        self.db.close();
        testing.allocator.free(self.dir_path);
        self.tmp.cleanup();
    }

    /// Write `bytes` as a snapshot file in the rig dir; caller frees the path.
    fn writeSnapshot(self: *Rig, name: []const u8, bytes: []const u8) ![]u8 {
        try self.tmp.dir.writeFile(.{ .sub_path = name, .data = bytes });
        return std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ self.dir_path, name });
    }

    fn import(self: *Rig, path: []const u8, params: *const consensus.NetworkParams) !void {
        if (HAS_ENTRY) {
            return main_mod.importSnapshotIntoDb(&self.db, path, params, testing.allocator);
        } else return error.CliSnapshotImportHasNoHashGate;
    }

    fn utxoCount(self: *Rig) u64 {
        var it = self.db.iterator(storage.CF_UTXO);
        defer it.deinit();
        it.seekToFirst();
        var n: u64 = 0;
        while (it.valid()) : (it.next()) n += 1;
        return n;
    }

    fn hasChainTip(self: *Rig) !bool {
        const v = try self.db.get(storage.CF_DEFAULT, "chain_tip");
        if (v) |b| {
            testing.allocator.free(b);
            return true;
        }
        return false;
    }
};

/// End offset of the Core VARINT starting at `pos` (MSB-continuation bytes).
fn varIntEnd(data: []const u8, pos: usize) usize {
    var p = pos;
    while (data[p] & 0x80 != 0) p += 1;
    return p + 1;
}

/// Offset of the last byte of the FIRST coin's compressed-amount VARINT.
/// Layout after the 51-byte header: txid(32) | compactsize(n) | then per coin
/// compactsize(vout) VARINT(code) VARINT(amount) script.
fn firstCoinAmountLastByte(data: []const u8) usize {
    var p: usize = storage.SnapshotMetadata.HEADER_SIZE + 32;
    std.debug.assert(data[p] < 0xfd); // coins_per_txid fits one byte
    p += 1;
    std.debug.assert(data[p] < 0xfd); // vout fits one byte
    p += 1;
    p = varIntEnd(data, p); // code
    return varIntEnd(data, p) - 1; // amount
}

fn regtestEntry299() consensus.AssumeUtxoData {
    for (consensus.REGTEST.assume_utxo) |e| if (e.height == 299) return e;
    unreachable;
}

test "untouched Core regtest-299 snapshot loads and sets the tip (positive control)" {
    var rig = try Rig.init();
    defer rig.deinit();
    const path = try rig.writeSnapshot("utxo-299.dat", FIXTURE);
    defer testing.allocator.free(path);

    try rig.import(path, &consensus.REGTEST);

    const entry = regtestEntry299();
    const tip = (try rig.db.get(storage.CF_DEFAULT, "chain_tip")).?;
    defer testing.allocator.free(tip);
    try testing.expectEqualSlices(u8, &entry.block_hash, tip[0..32]);
    try testing.expectEqual(@as(u32, 299), std.mem.readInt(u32, tip[32..36], .little));
    try testing.expectEqual(@as(u64, 299), rig.utxoCount());

    // The coins as stored hash to the pinned value (the gate measured them).
    var view = storage.UtxoSet.init(&rig.db, 0, testing.allocator);
    defer view.deinit();
    const h = try storage.computeHashSerializedTxOutSet(&view, testing.allocator);
    try testing.expectEqualSlices(u8, &entry.hash_serialized, &h);
}

test "one coin amount flipped: refused with no tip and no coins left behind" {
    var bytes = try testing.allocator.dupe(u8, FIXTURE);
    defer testing.allocator.free(bytes);
    const off = firstCoinAmountLastByte(bytes);
    bytes[off] ^= 0x01; // stays a valid VARINT and a valid MoneyRange amount
    try testing.expect(!std.mem.eql(u8, bytes, FIXTURE));

    var rig = try Rig.init();
    defer rig.deinit();
    const path = try rig.writeSnapshot("utxo-299-amount.dat", bytes);
    defer testing.allocator.free(path);

    try testing.expectError(error.SnapshotRejected, rig.import(path, &consensus.REGTEST));
    try testing.expect(!(try rig.hasChainTip()));
    try testing.expectEqual(@as(u64, 0), rig.utxoCount());
}

test "first txid byte flipped (boot-smoke corrupt twin): refused" {
    var bytes = try testing.allocator.dupe(u8, FIXTURE);
    defer testing.allocator.free(bytes);
    bytes[storage.SnapshotMetadata.HEADER_SIZE] ^= 0x01;

    var rig = try Rig.init();
    defer rig.deinit();
    const path = try rig.writeSnapshot("utxo-299-txid.dat", bytes);
    defer testing.allocator.free(path);

    try testing.expectError(error.SnapshotRejected, rig.import(path, &consensus.REGTEST));
    try testing.expect(!(try rig.hasChainTip()));
    try testing.expectEqual(@as(u64, 0), rig.utxoCount());
}

test "chainstate that already holds coins is refused and left untouched" {
    var rig = try Rig.init();
    defer rig.deinit();
    // A pre-existing coin: the gate hashes all of CF_UTXO, so it cannot vouch
    // for this snapshot, and a refusal must not delete coins it did not write.
    const key = [_]u8{0xee} ** 36;
    try rig.db.put(storage.CF_UTXO, &key, "existing");
    const path = try rig.writeSnapshot("utxo-299.dat", FIXTURE);
    defer testing.allocator.free(path);

    try testing.expectError(error.SnapshotRejected, rig.import(path, &consensus.REGTEST));
    try testing.expect(!(try rig.hasChainTip()));
    try testing.expectEqual(@as(u64, 1), rig.utxoCount());
}

// ---------------------------------------------------------------------------
// Consensus note: the risk of this gate is refusing a VALID snapshot because
// the CLI path hashes the coins in a different form than the pinned value was
// computed in.  The CLI hashes coins after the round trip through clearbit's
// CF_UTXO encoding (CompactUtxo); loadtxoutset hashes the decoded in-memory
// set.  This builds a snapshot whose coins stress that round trip (every
// script class CompactUtxo special-cases plus non-standard scripts, vouts
// across the LE32 byte boundary where key order != numeric order, coinbase
// and non-coinbase, zero and large values), pins the hash the loadtxoutset
// path computes, and requires the CLI path to accept it.
// ---------------------------------------------------------------------------

const SynthCoin = struct { vout: u32, height: u32, coinbase: bool, value: i64, script: []const u8 };

fn h20(b: u8) [20]u8 {
    return [_]u8{b} ** 20;
}
fn h32(b: u8) [32]u8 {
    return [_]u8{b} ** 32;
}

fn writeGroup(w: *serialize.Writer, txid: types.Hash256, coins: []const SynthCoin) !void {
    try w.writeBytes(&txid);
    try w.writeCompactSize(coins.len);
    for (coins) |c| {
        const sc = storage.SnapshotCoin{
            .outpoint = .{ .hash = txid, .index = c.vout },
            .height = c.height,
            .is_coinbase = c.coinbase,
            .value = c.value,
            .script_pubkey = c.script,
        };
        try storage.writeSnapshotCoinPayload(w, c.vout, &sc);
    }
}

fn buildSynthSnapshot(base: types.Hash256) ![]const u8 {
    const a = testing.allocator;
    const p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ h20(0x11) ++ [_]u8{ 0x88, 0xac };
    const p2sh = [_]u8{ 0xa9, 0x14 } ++ h20(0x22) ++ [_]u8{0x87};
    const p2wpkh = [_]u8{ 0x00, 0x14 } ++ h20(0x33);
    const p2wsh = [_]u8{ 0x00, 0x20 } ++ h32(0x44);
    const p2tr = [_]u8{ 0x51, 0x20 } ++ h32(0x55);
    const p2pk_c = [_]u8{ 0x21, 0x02 } ++ h32(0x66) ++ [_]u8{0xac};
    const multisig = [_]u8{ 0x51, 0x21, 0x03 } ++ h32(0x77) ++ [_]u8{ 0x51, 0xae };
    const op_true = [_]u8{0x51};
    const empty = [_]u8{};

    const tx_a = [_]u8{0x01} ++ [_]u8{0xaa} ** 31;
    const tx_b = [_]u8{0x02} ++ [_]u8{0xbb} ** 31;
    // Within a txid the file is in numeric vout order, as Core writes it.
    const coins_a = [_]SynthCoin{
        .{ .vout = 0, .height = 1, .coinbase = true, .value = 50 * 100_000_000, .script = &p2pk_c },
        .{ .vout = 1, .height = 2, .coinbase = false, .value = 0, .script = &p2pkh },
        .{ .vout = 255, .height = 3, .coinbase = false, .value = 12345, .script = &p2sh },
        .{ .vout = 256, .height = 4, .coinbase = false, .value = 999_999, .script = &p2wpkh },
        .{ .vout = 300, .height = 5, .coinbase = false, .value = 21_000_000 * 100_000_000, .script = &p2wsh },
        .{ .vout = 65536, .height = 6, .coinbase = false, .value = 1, .script = &p2tr },
    };
    const coins_b = [_]SynthCoin{
        .{ .vout = 0, .height = 7, .coinbase = false, .value = 546, .script = &multisig },
        .{ .vout = 3, .height = 8, .coinbase = true, .value = 777, .script = &op_true },
        .{ .vout = 9, .height = 9, .coinbase = false, .value = 330, .script = &empty },
    };

    var w = serialize.Writer.init(a);
    errdefer w.deinit();
    const meta = storage.SnapshotMetadata{
        .network_magic = consensus.REGTEST.magic,
        .base_blockhash = base,
        .coins_count = coins_a.len + coins_b.len,
    };
    const hdr = try meta.toBytes(a);
    defer a.free(hdr);
    try w.writeBytes(hdr);
    try writeGroup(&w, tx_a, &coins_a);
    try writeGroup(&w, tx_b, &coins_b);
    return w.toOwnedSlice();
}

test "format-diverse snapshot: CLI gate agrees with the loadtxoutset hash (no false refusal)" {
    const base = [_]u8{0x5a} ** 32;
    const bytes = try buildSynthSnapshot(base);
    defer testing.allocator.free(bytes);

    var rig = try Rig.init();
    defer rig.deinit();
    const path = try rig.writeSnapshot("synth.dat", bytes);
    defer testing.allocator.free(path);

    // The hash the loadtxoutset gate (storage.validateAndLoadSnapshot) computes.
    var loaded = try storage.loadTxOutSet(path, consensus.REGTEST.magic, testing.allocator);
    const rpc_hash = storage.computeHashSerializedTxOutSet(&loaded.chainstate.utxo_set, testing.allocator) catch |e| {
        loaded.chainstate.deinit();
        return e;
    };
    loaded.chainstate.deinit();

    var params = consensus.REGTEST;
    const entries = [_]consensus.AssumeUtxoData{.{
        .height = 10,
        .block_hash = base,
        .hash_serialized = rpc_hash,
        .chain_tx_count = 11,
    }};
    params.assume_utxo = &entries;
    params.snapshot_bootstrap = &.{};

    try rig.import(path, &params);
    try testing.expect(try rig.hasChainTip());
    try testing.expectEqual(@as(u64, 9), rig.utxoCount());
}

test "format-diverse snapshot pinned to a different hash: refused" {
    const base = [_]u8{0x5b} ** 32;
    const bytes = try buildSynthSnapshot(base);
    defer testing.allocator.free(bytes);

    var rig = try Rig.init();
    defer rig.deinit();
    const path = try rig.writeSnapshot("synth.dat", bytes);
    defer testing.allocator.free(path);

    var params = consensus.REGTEST;
    const entries = [_]consensus.AssumeUtxoData{.{
        .height = 10,
        .block_hash = base,
        .hash_serialized = [_]u8{0x42} ** 32,
        .chain_tx_count = 11,
    }};
    params.assume_utxo = &entries;
    params.snapshot_bootstrap = &.{};

    try testing.expectError(error.SnapshotRejected, rig.import(path, &params));
    try testing.expect(!(try rig.hasChainTip()));
    try testing.expectEqual(@as(u64, 0), rig.utxoCount());
}

test "file cut short after a flushed batch: refused and the flushed coins deleted" {
    // The import flushes every 100,000 coins, so 100,001 whole coins puts one
    // batch on disk before the read of coin 100,002 fails.
    const a = testing.allocator;
    const base = [_]u8{0x5c} ** 32;
    const n_written: u32 = 100_001;
    var w = serialize.Writer.init(a);
    defer w.deinit();
    const meta = storage.SnapshotMetadata{
        .network_magic = consensus.REGTEST.magic,
        .base_blockhash = base,
        .coins_count = n_written + 1,
    };
    const hdr = try meta.toBytes(a);
    defer a.free(hdr);
    try w.writeBytes(hdr);
    const p2wpkh = [_]u8{ 0x00, 0x14 } ++ h20(0x33);
    const one = [_]SynthCoin{.{ .vout = 0, .height = 1, .coinbase = false, .value = 1000, .script = &p2wpkh }};
    var i: u32 = 0;
    while (i < n_written) : (i += 1) {
        var txid = [_]u8{0} ** 32;
        std.mem.writeInt(u32, txid[0..4], i, .big);
        try writeGroup(&w, txid, &one);
    }

    var rig = try Rig.init();
    defer rig.deinit();
    const path = try rig.writeSnapshot("short.dat", w.getWritten());
    defer a.free(path);

    var params = consensus.REGTEST;
    const entries = [_]consensus.AssumeUtxoData{.{
        .height = 10,
        .block_hash = base,
        .hash_serialized = [_]u8{0x42} ** 32,
        .chain_tx_count = 11,
    }};
    params.assume_utxo = &entries;
    params.snapshot_bootstrap = &.{};

    try testing.expectError(error.SnapshotRejected, rig.import(path, &params));
    try testing.expect(!(try rig.hasChainTip()));
    try testing.expectEqual(@as(u64, 0), rig.utxoCount());
}
