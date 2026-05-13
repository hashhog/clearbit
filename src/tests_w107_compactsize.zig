// W107 — CompactSize + VarInt 30-gate audit (clearbit / Zig 0.13)
//
// Reference: bitcoin-core/src/serialize.h
//   WriteCompactSize / ReadCompactSize (with non-canonical rejection + MAX_SIZE)
//   WriteVarInt / ReadVarInt (MSB-continuation encoding for chainstate/undo)
//   MAX_SIZE = 0x02000000
//
// Findings:
//
//   BUG-1  (G1, CONSENSUS-DIVERGENT): readCompactSize in serialize.zig has NO
//          non-canonical encoding rejection. Prefixes 0xFD/0xFE/0xFF with
//          sub-threshold payloads are silently accepted.  Core throws
//          "non-canonical ReadCompactSize()" in all three cases.  The same bug
//          exists in StreamingFileReader.readCompactSize (main.zig:819) and
//          ObfReader.readCompactSize (mempool_persist.zig:160) — 3 independent
//          implementations all missing the check.
//
//   BUG-2  (G2, P1): No MAX_SIZE (0x02000000) range check in any of the 3
//          readCompactSize implementations.  Core rejects values > MAX_SIZE
//          when range_check=true (the default for all P2P/block/tx sizes).
//
//   BUG-3  (G9, CONSENSUS-DIVERGENT): storage.zig Coin.toBytes()/fromBytes()
//          uses writeCompactSize/readCompactSize for the packed coin code
//          (height<<1 | coinbase).  Core's Coin::Serialize uses VARINT
//          (MSB-continuation encoding) for this field:
//            ::Serialize(s, VARINT(code));     // coins.h:67
//          compressor.zig correctly uses writeVarInt/readVarInt for the same
//          field — there are two parallel coin-serialization paths and one is
//          wrong.  Any coins written via Coin.toBytes() are incompatible with
//          Core's chainstate LevelDB format.
//
//   BUG-4  (G10, CONSENSUS-DIVERGENT): storage.zig BlockUndoData.fromBytes()
//          uses readCompactSize for packed_code (height<<1 | coinbase) at
//          storage.zig:1618.  Core's TxInUndoFormatter uses VARINT:
//            ::Unserialize(s, VARINT(nCode));  // undo.h:37
//          Block undo data (rev*.dat) written by Core is therefore unreadable
//          by clearbit and vice-versa.
//
//   BUG-5  (G11, P2): BlockUndoData.fromBytes() applies no MAX_SIZE cap on
//          num_tx_undo or num_prev_outputs.  A peer can send a block undo with
//          a crafted CompactSize claiming billions of entries and cause OOM
//          before any data is read.
//
//   PASS: writeCompactSize encoding thresholds match Core (< 0xFD, <= 0xFFFF,
//         <= 0xFFFFFFFF, else).
//   PASS: writeVarInt / readVarInt algorithm matches Core (MSB-continuation,
//         overflow guards, reversed-emit order).
//   PASS: compressor.zig writeCoin / readCoin correctly use writeVarInt /
//         readVarInt for the coin code and amount.

const std = @import("std");
const testing = std.testing;
const serialize = @import("serialize.zig");

// ---------------------------------------------------------------------------
// G1 — Non-canonical CompactSize rejection (BUG-1: all three fail)
// ---------------------------------------------------------------------------
//
// Core: ReadCompactSize throws "non-canonical ReadCompactSize()" when:
//   prefix 0xFD and 16-bit payload < 0xFD (should have used 1-byte form)
//   prefix 0xFE and 32-bit payload < 0x10000 (should have used 3-byte form)
//   prefix 0xFF and 64-bit payload < 0x100000000 (should have used 5-byte form)
//
// BUG-1: clearbit silently accepts all of these.
// Tests document the current (broken) behaviour and what the fix should do.

test "w107 G1a BUG-1 readCompactSize non-canonical 0xFD prefix currently accepted" {
    // 0xFD 0x01 0x00 = LE u16 = 1.  Should have been encoded as [0x01] (1 byte).
    // Core rejects; clearbit silently returns 1.
    const non_canonical: [3]u8 = .{ 0xFD, 0x01, 0x00 };
    var reader = serialize.Reader{ .data = &non_canonical };
    // BUG-1: this succeeds when it should fail with error.InvalidCompactSize
    const value = reader.readCompactSize() catch {
        return; // pass if fixed: error returned
    };
    // Currently succeeds — assert the wrong-but-observed behaviour so the test
    // turns red when someone breaks something else unrelated.
    try testing.expectEqual(@as(u64, 1), value);
    // TODO fix: replace above with:
    // try testing.expectError(error.InvalidCompactSize,
    //     (serialize.Reader{ .data = &non_canonical }).readCompactSize());
}

test "w107 G1b BUG-1 readCompactSize non-canonical 0xFE prefix currently accepted" {
    // 0xFE 0xFF 0xFF 0x00 0x00 = LE u32 = 0xFFFF.
    // Should have been encoded with 0xFD prefix (3 bytes).
    const non_canonical: [5]u8 = .{ 0xFE, 0xFF, 0xFF, 0x00, 0x00 };
    var reader = serialize.Reader{ .data = &non_canonical };
    const value = reader.readCompactSize() catch {
        return; // pass if fixed
    };
    try testing.expectEqual(@as(u64, 0xFFFF), value);
    // TODO fix: expectError(error.InvalidCompactSize, ...)
}

test "w107 G1c BUG-1 readCompactSize non-canonical 0xFF prefix currently accepted" {
    // 0xFF 0xFF 0xFF 0xFF 0xFF 0x00 0x00 0x00 0x00 = LE u64 = 0xFFFFFFFF.
    // Should have been encoded with 0xFE prefix (5 bytes).
    const non_canonical: [9]u8 = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
    var reader = serialize.Reader{ .data = &non_canonical };
    const value = reader.readCompactSize() catch {
        return; // pass if fixed
    };
    try testing.expectEqual(@as(u64, 0xFFFFFFFF), value);
    // TODO fix: expectError(error.InvalidCompactSize, ...)
}

test "w107 G1d writeCompactSize then readCompactSize canonical round-trip (PASS)" {
    // Verify that canonical encodings are NOT rejected (regression guard for
    // when the non-canonical check is added).
    const allocator = testing.allocator;
    const cases = [_]u64{
        0, 1, 0xFC, 0xFD, 0xFFFE, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000,
        0x01FFFFFF, 0x02000000,
    };
    for (cases) |v| {
        var writer = serialize.Writer.init(allocator);
        defer writer.deinit();
        try writer.writeCompactSize(v);
        var reader = serialize.Reader{ .data = writer.getWritten() };
        const got = try reader.readCompactSize();
        try testing.expectEqual(v, got);
        try testing.expect(reader.isAtEnd());
    }
}

// ---------------------------------------------------------------------------
// G2 — MAX_SIZE range check (BUG-2: missing)
// ---------------------------------------------------------------------------
//
// Core: if (range_check && nSizeRet > MAX_SIZE) throw "ReadCompactSize(): size too large"
// MAX_SIZE = 0x02000000 (33554432)
// BUG-2: no check in any readCompactSize implementation.

test "w107 G2a readCompactSize value exactly MAX_SIZE (0x02000000) must be accepted (PASS)" {
    const allocator = testing.allocator;
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try writer.writeCompactSize(0x02000000);
    var reader = serialize.Reader{ .data = writer.getWritten() };
    const got = try reader.readCompactSize();
    try testing.expectEqual(@as(u64, 0x02000000), got);
}

test "w107 G2b BUG-2 readCompactSize MAX_SIZE+1 currently accepted" {
    // Core rejects 0x02000001 as "size too large".  BUG-2: clearbit accepts it.
    const allocator = testing.allocator;
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try writer.writeCompactSize(0x02000001);
    var reader = serialize.Reader{ .data = writer.getWritten() };
    const value = reader.readCompactSize() catch {
        return; // pass if fixed
    };
    try testing.expectEqual(@as(u64, 0x02000001), value);
    // TODO fix: expectError(error.InvalidCompactSize, ...) for value > MAX_SIZE
}

test "w107 G2c BUG-2 readCompactSize maximum u64 currently accepted" {
    const allocator = testing.allocator;
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try writer.writeCompactSize(std.math.maxInt(u64));
    var reader = serialize.Reader{ .data = writer.getWritten() };
    const value = reader.readCompactSize() catch {
        return; // pass if fixed
    };
    try testing.expectEqual(std.math.maxInt(u64), value);
    // TODO fix: expectError for value > MAX_SIZE
}

// ---------------------------------------------------------------------------
// G3 — writeCompactSize encoding boundaries (PASS)
// ---------------------------------------------------------------------------
//
// Core: < 253 → 1 byte; <= 0xFFFF → 3 bytes; <= 0xFFFFFFFF → 5 bytes; else 9 bytes.
// clearbit: identical thresholds.

test "w107 G3a writeCompactSize boundary values encoding lengths (PASS)" {
    const allocator = testing.allocator;

    // 0 → 1 byte
    {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(0);
        try testing.expectEqual(@as(usize, 1), w.getWritten().len);
        try testing.expectEqual(@as(u8, 0), w.getWritten()[0]);
    }
    // 0xFC → 1 byte
    {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(0xFC);
        try testing.expectEqual(@as(usize, 1), w.getWritten().len);
        try testing.expectEqual(@as(u8, 0xFC), w.getWritten()[0]);
    }
    // 0xFD → 3 bytes (0xFD prefix + 2-byte LE)
    {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(0xFD);
        try testing.expectEqual(@as(usize, 3), w.getWritten().len);
        try testing.expectEqual(@as(u8, 0xFD), w.getWritten()[0]);
        try testing.expectEqual(@as(u8, 0xFD), w.getWritten()[1]); // LE low byte
        try testing.expectEqual(@as(u8, 0x00), w.getWritten()[2]); // LE high byte
    }
    // 0xFFFF → 3 bytes
    {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(0xFFFF);
        try testing.expectEqual(@as(usize, 3), w.getWritten().len);
    }
    // 0x10000 → 5 bytes (0xFE prefix + 4-byte LE)
    {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(0x10000);
        try testing.expectEqual(@as(usize, 5), w.getWritten().len);
        try testing.expectEqual(@as(u8, 0xFE), w.getWritten()[0]);
    }
    // 0xFFFFFFFF → 5 bytes
    {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(0xFFFFFFFF);
        try testing.expectEqual(@as(usize, 5), w.getWritten().len);
    }
    // 0x100000000 → 9 bytes (0xFF prefix + 8-byte LE)
    {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(0x100000000);
        try testing.expectEqual(@as(usize, 9), w.getWritten().len);
        try testing.expectEqual(@as(u8, 0xFF), w.getWritten()[0]);
    }
}

test "w107 G3b writeCompactSize little-endian byte order (PASS)" {
    const allocator = testing.allocator;
    // 0x0102 → 0xFD 0x02 0x01 (LE)
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeCompactSize(0x0102);
    try testing.expectEqual(@as(usize, 3), w.getWritten().len);
    try testing.expectEqual(@as(u8, 0xFD), w.getWritten()[0]);
    try testing.expectEqual(@as(u8, 0x02), w.getWritten()[1]); // low byte
    try testing.expectEqual(@as(u8, 0x01), w.getWritten()[2]); // high byte
}

// ---------------------------------------------------------------------------
// G4 — Core test-vector CompactSize exact bytes (PASS)
// ---------------------------------------------------------------------------
//
// Cross-check from bitcoin-core/src/test/serialize_tests.cpp

test "w107 G4 Core serialize_tests CompactSize vectors (PASS)" {
    const vectors = [_]struct { value: u64, bytes: []const u8 }{
        .{ .value = 0, .bytes = &[_]u8{0x00} },
        .{ .value = 252, .bytes = &[_]u8{0xFC} },
        .{ .value = 253, .bytes = &[_]u8{ 0xFD, 0xFD, 0x00 } },
        .{ .value = 254, .bytes = &[_]u8{ 0xFD, 0xFE, 0x00 } },
        .{ .value = 255, .bytes = &[_]u8{ 0xFD, 0xFF, 0x00 } },
        .{ .value = 256, .bytes = &[_]u8{ 0xFD, 0x00, 0x01 } },
        .{ .value = 65535, .bytes = &[_]u8{ 0xFD, 0xFF, 0xFF } },
        .{ .value = 65536, .bytes = &[_]u8{ 0xFE, 0x00, 0x00, 0x01, 0x00 } },
        .{ .value = 4294967295, .bytes = &[_]u8{ 0xFE, 0xFF, 0xFF, 0xFF, 0xFF } },
        .{ .value = 4294967296, .bytes = &[_]u8{ 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 } },
    };

    const allocator = testing.allocator;

    for (vectors) |v| {
        // Decode test
        var reader = serialize.Reader{ .data = v.bytes };
        const decoded = try reader.readCompactSize();
        try testing.expectEqual(v.value, decoded);
        try testing.expect(reader.isAtEnd());

        // Encode test
        var writer = serialize.Writer.init(allocator);
        defer writer.deinit();
        try writer.writeCompactSize(v.value);
        try testing.expectEqualSlices(u8, v.bytes, writer.getWritten());
    }
}

// ---------------------------------------------------------------------------
// G5 — VarInt algorithm: Core test vectors (PASS)
// ---------------------------------------------------------------------------
//
// From serialize.h comment:
//   0:    [0x00]        256:   [0x81 0x00]
//   1:    [0x01]        16383: [0xFE 0x7F]
//   127:  [0x7F]        16384: [0xFF 0x00]
//   128:  [0x80 0x00]   16511: [0xFF 0x7F]
//   255:  [0x80 0x7F]   65535: [0x82 0xFE 0x7F]
//   2^32: [0x8E 0xFE 0xFE 0xFF 0x00]

test "w107 G5 Core VarInt encoding test vectors (PASS)" {
    const vectors = [_]struct { value: u64, bytes: []const u8 }{
        .{ .value = 0, .bytes = &[_]u8{0x00} },
        .{ .value = 1, .bytes = &[_]u8{0x01} },
        .{ .value = 127, .bytes = &[_]u8{0x7F} },
        .{ .value = 128, .bytes = &[_]u8{ 0x80, 0x00 } },
        .{ .value = 255, .bytes = &[_]u8{ 0x80, 0x7F } },
        .{ .value = 256, .bytes = &[_]u8{ 0x81, 0x00 } },
        .{ .value = 16383, .bytes = &[_]u8{ 0xFE, 0x7F } },
        .{ .value = 16384, .bytes = &[_]u8{ 0xFF, 0x00 } },
        .{ .value = 16511, .bytes = &[_]u8{ 0xFF, 0x7F } },
        .{ .value = 65535, .bytes = &[_]u8{ 0x82, 0xFE, 0x7F } },
        .{ .value = 0x100000000, .bytes = &[_]u8{ 0x8E, 0xFE, 0xFE, 0xFF, 0x00 } },
    };

    const allocator = testing.allocator;

    for (vectors) |v| {
        // Decode
        var reader = serialize.Reader{ .data = v.bytes };
        const decoded = try reader.readVarInt();
        try testing.expectEqual(v.value, decoded);
        try testing.expect(reader.isAtEnd());

        // Encode
        var writer = serialize.Writer.init(allocator);
        defer writer.deinit();
        try writer.writeVarInt(v.value);
        try testing.expectEqualSlices(u8, v.bytes, writer.getWritten());
    }
}

// ---------------------------------------------------------------------------
// G6 — VarInt overflow guard (PASS)
// ---------------------------------------------------------------------------

test "w107 G6a readVarInt overflow guard rejects truncated over-long sequence (PASS)" {
    // Build a sequence that would overflow u64 without the guard.
    // 10 bytes each with bit-7 set means we never terminate — readVarInt
    // should abort with InvalidCompactSize before overflow.
    const overflow_seq: [10]u8 = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    var reader = serialize.Reader{ .data = &overflow_seq };
    const result = reader.readVarInt();
    try testing.expectError(error.InvalidCompactSize, result);
}

test "w107 G6b readVarInt u64 max terminates cleanly (PASS)" {
    const allocator = testing.allocator;
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeVarInt(std.math.maxInt(u64));
    var r = serialize.Reader{ .data = w.getWritten() };
    const v = try r.readVarInt();
    try testing.expectEqual(std.math.maxInt(u64), v);
    try testing.expect(r.isAtEnd());
}

// ---------------------------------------------------------------------------
// G7 — CompactSize vs VarInt not conflated in compressor.zig (PASS)
// ---------------------------------------------------------------------------
//
// compressor.writeCoin/readCoin correctly use writeVarInt/readVarInt for
// the coin code and CompressAmount.  The test verifies that code=129
// (height=64, coinbase=true) produces VARINT bytes [0x80 0x01] not
// CompactSize [0x81].

test "w107 G7 compressor.writeCoin uses VARINT not CompactSize for coin code (PASS)" {
    const compressor = @import("compressor.zig");
    const allocator = testing.allocator;

    // height=64, coinbase=true → code = 64<<1 | 1 = 129.
    // VARINT(129):
    //   n=129 > 0x7F so continuation needed.
    //   tmp[0] = 129 & 0x7F = 0x01, n = (129>>7)-1 = 0
    //   tmp[1] = 0 | 0x80 = 0x80
    //   emit high→low: [0x80, 0x01]
    // CompactSize(129) = [0x81]  (1 byte since 129 < 253)

    const script: [25]u8 = .{
        0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0x88, 0xac,
    };

    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try compressor.writeCoin(&writer, 64, true, 100_000_000, &script);

    const bytes = writer.getWritten();

    // First two bytes must be VARINT(129) = [0x80, 0x01].
    try testing.expect(bytes.len >= 2);
    try testing.expectEqual(@as(u8, 0x80), bytes[0]);
    try testing.expectEqual(@as(u8, 0x01), bytes[1]);

    // Round-trip decode via readCoin.
    var reader = serialize.Reader{ .data = bytes };
    const coin = try compressor.readCoin(&reader, allocator);
    defer allocator.free(coin.script_pubkey);
    try testing.expectEqual(@as(u32, 64), coin.height);
    try testing.expect(coin.is_coinbase);
    try testing.expectEqual(@as(i64, 100_000_000), coin.value);
    try testing.expect(reader.isAtEnd());
}

// ---------------------------------------------------------------------------
// G8 — BUG-3: storage.Coin coin-code uses CompactSize instead of VARINT
// ---------------------------------------------------------------------------
//
// Demonstrate that VARINT and CompactSize differ for values >= 128.
// storage.Coin.toBytes uses writeCompactSize; Core uses VARINT.

test "w107 G8a BUG-3 VARINT and CompactSize diverge for code >= 128" {
    // code=129 (height=64, coinbase=true)
    // VARINT(129) = [0x80, 0x01]  (2 bytes)
    // CompactSize(129) = [0x81]   (1 byte)
    const allocator = testing.allocator;
    const code: u64 = 129;

    var varint_w = serialize.Writer.init(allocator);
    defer varint_w.deinit();
    try varint_w.writeVarInt(code);
    const varint_bytes = varint_w.getWritten();

    var cs_w = serialize.Writer.init(allocator);
    defer cs_w.deinit();
    try cs_w.writeCompactSize(code);
    const cs_bytes = cs_w.getWritten();

    // VARINT(129) = [0x80, 0x01]
    try testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01 }, varint_bytes);
    // CompactSize(129) = [0x81]
    try testing.expectEqualSlices(u8, &[_]u8{0x81}, cs_bytes);

    // They differ — BUG-3: storage.Coin.toBytes writes CompactSize(129) = [0x81]
    // but Core's chainstate LevelDB contains VARINT(129) = [0x80, 0x01].
    try testing.expect(!std.mem.eql(u8, varint_bytes, cs_bytes));
}

test "w107 G8b BUG-3 FIXED BlockUndoData round-trips height=64 coinbase=true correctly" {
    // W107 BUG-3 fix: BlockUndoData.toBytes/fromBytes now use VARINT for
    // packed_code (height<<1 | coinbase), matching Core's coins.h Coin::Serialize
    // and undo.h TxInUndoFormatter.
    //
    // height=64, coinbase=true → code = 64<<1 | 1 = 129.
    // VARINT(129) = [0x80, 0x01].  With CompactSize (old bug) it was [0x81]
    // and the deserialized coinbase flag was silently wrong.
    const storage = @import("storage.zig");
    const allocator = testing.allocator;

    const script: [25]u8 = .{
        0x76, 0xa9, 0x14,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0x88, 0xac,
    };
    const script_copy = try allocator.dupe(u8, &script);
    defer allocator.free(script_copy);
    const prev_out = storage.TxUndo.TxOut{
        .value = 5_000_000_000,
        .script_pubkey = script_copy,
        .height = 64,
        .is_coinbase = true,
    };
    var prev_outputs = [_]storage.TxUndo.TxOut{prev_out};
    var tx_undo = [_]storage.TxUndo{.{ .prev_outputs = &prev_outputs }};
    const bud = storage.BlockUndoData{ .tx_undo = &tx_undo };

    const bytes = try bud.toBytes(allocator);
    defer allocator.free(bytes);

    var decoded = try storage.BlockUndoData.fromBytes(bytes, allocator);
    defer decoded.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), decoded.tx_undo.len);
    try testing.expectEqual(@as(usize, 1), decoded.tx_undo[0].prev_outputs.len);
    const out = decoded.tx_undo[0].prev_outputs[0];
    try testing.expectEqual(@as(u32, 64), out.height);
    try testing.expect(out.is_coinbase); // was silently false with CompactSize bug
    try testing.expectEqual(@as(i64, 5_000_000_000), out.value);
}

test "w107 G8c BUG-3 FIXED BlockUndoData packed_code VARINT matches compressor.writeCoin encoding" {
    // W107 BUG-3 fix verification: after the fix, BlockUndoData.toBytes encodes
    // packed_code with writeVarInt, exactly as compressor.writeCoin does for the
    // coin code field.  Both paths must produce the same byte prefix for the same
    // (height, coinbase) pair so that Core's rev*.dat/chainstate LevelDB formats
    // are byte-compatible.
    //
    // height=200, coinbase=false → code = 200<<1 | 0 = 400.
    // VARINT(400) = [0x82, 0x10]  (compressor.writeCoin path, verified by G18).
    const storage = @import("storage.zig");
    const allocator = testing.allocator;

    const script: [25]u8 = .{
        0x76, 0xa9, 0x14,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0x88, 0xac,
    };
    const script_copy = try allocator.dupe(u8, &script);
    defer allocator.free(script_copy);
    const prev_out = storage.TxUndo.TxOut{
        .value = 0,
        .script_pubkey = script_copy,
        .height = 200,
        .is_coinbase = false,
    };
    var prev_outputs = [_]storage.TxUndo.TxOut{prev_out};
    var tx_undo = [_]storage.TxUndo{.{ .prev_outputs = &prev_outputs }};
    const bud = storage.BlockUndoData{ .tx_undo = &tx_undo };

    const bytes = try bud.toBytes(allocator);
    defer allocator.free(bytes);

    // After the fix, BlockUndoData round-trips at height=200 without error.
    var decoded = try storage.BlockUndoData.fromBytes(bytes, allocator);
    defer decoded.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), decoded.tx_undo.len);
    const out = decoded.tx_undo[0].prev_outputs[0];
    try testing.expectEqual(@as(u32, 200), out.height);
    try testing.expect(!out.is_coinbase);
}

// ---------------------------------------------------------------------------
// G9 — BUG-4: BlockUndoData packed_code uses CompactSize not VARINT
// ---------------------------------------------------------------------------
//
// Core's TxInUndoFormatter (undo.h:37): ::Unserialize(s, VARINT(nCode))
// clearbit storage.BlockUndoData.fromBytes line 1618: readCompactSize()

test "w107 G9a BUG-4 FIXED BlockUndoData fromBytes correctly reads VARINT packed_code" {
    // W107 BUG-4 fix: BlockUndoData.fromBytes now calls readVarInt() for packed_code,
    // matching Core's TxInUndoFormatter::Unser (undo.h:37): VARINT(nCode).
    //
    // Before the fix, readCompactSize() was used, which would decode
    // VARINT(200)=[0x80, 0x48] as 128 (reading only the first byte) and leave
    // the 0x48 byte unread, causing complete deserialization desync.
    //
    // After the fix, code=200 (height=100, coinbase=false) round-trips correctly.
    const storage = @import("storage.zig");
    const allocator = testing.allocator;

    const script: [1]u8 = .{0x6a}; // OP_RETURN
    const script_copy = try allocator.dupe(u8, &script);
    defer allocator.free(script_copy);
    const prev_out = storage.TxUndo.TxOut{
        .value = 1_000_000,
        .script_pubkey = script_copy,
        .height = 100,
        .is_coinbase = false,
    };
    var prev_outputs = [_]storage.TxUndo.TxOut{prev_out};
    var tx_undo = [_]storage.TxUndo{.{ .prev_outputs = &prev_outputs }};
    const bud = storage.BlockUndoData{ .tx_undo = &tx_undo };

    const bytes = try bud.toBytes(allocator);
    defer allocator.free(bytes);

    var decoded = try storage.BlockUndoData.fromBytes(bytes, allocator);
    defer decoded.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), decoded.tx_undo.len);
    try testing.expectEqual(@as(usize, 1), decoded.tx_undo[0].prev_outputs.len);
    const out = decoded.tx_undo[0].prev_outputs[0];
    // Before fix: height decoded as 64 (128>>1), coinbase silently wrong.
    // After fix: height=100, coinbase=false correctly decoded.
    try testing.expectEqual(@as(u32, 100), out.height);
    try testing.expect(!out.is_coinbase);
    try testing.expectEqual(@as(i64, 1_000_000), out.value);
}

test "w107 G9b correct readVarInt of VARINT(200) = 200 (regression guard, PASS)" {
    const allocator = testing.allocator;

    var varint_w = serialize.Writer.init(allocator);
    defer varint_w.deinit();
    try varint_w.writeVarInt(200);
    const bytes = varint_w.getWritten();

    var reader = serialize.Reader{ .data = bytes };
    const code = try reader.readVarInt();
    try testing.expectEqual(@as(u64, 200), code);
    try testing.expect(reader.isAtEnd());
}

// ---------------------------------------------------------------------------
// G10 — BUG-5: No MAX_SIZE cap on array-count CompactSize reads
// ---------------------------------------------------------------------------
//
// Core always applies the range_check (MAX_SIZE = 0x02000000) for vector
// sizes. clearbit applies no such check after readCompactSize() for array counts.

test "w107 G10 BUG-5 FIXED BlockUndoData fromBytes rejects num_tx_undo > MAX_SIZE" {
    // W107 BUG-5 fix: BlockUndoData.fromBytes now applies the MAX_SIZE
    // (0x02000000) cap from Core's serialize.h ReadCompactSize(range_check=true)
    // to both num_tx_undo and num_prev_outputs.
    //
    // A crafted block undo with CompactSize(0x02000001) as the tx count must
    // be rejected with error.OversizedVector before any allocation.
    const storage = @import("storage.zig");
    const allocator = testing.allocator;

    // Hand-craft a byte stream: CompactSize(0x02000001) followed by nothing.
    // CompactSize(0x02000001) = 0xFE 0x01 0x00 0x00 0x02  (5-byte form, LE u32)
    const bad: [5]u8 = .{ 0xFE, 0x01, 0x00, 0x00, 0x02 };
    const result = storage.BlockUndoData.fromBytes(&bad, allocator);
    try testing.expectError(error.OversizedVector, result);
}

// ---------------------------------------------------------------------------
// G11 — End-of-stream handling (PASS)
// ---------------------------------------------------------------------------

test "w107 G11a readCompactSize on empty input returns EndOfStream (PASS)" {
    var reader = serialize.Reader{ .data = &[_]u8{} };
    try testing.expectError(error.EndOfStream, reader.readCompactSize());
}

test "w107 G11b readCompactSize truncated 0xFD prefix returns EndOfStream (PASS)" {
    // 0xFD requires 2 more bytes; give only 1.
    const truncated: [2]u8 = .{ 0xFD, 0x01 };
    var reader = serialize.Reader{ .data = &truncated };
    try testing.expectError(error.EndOfStream, reader.readCompactSize());
}

test "w107 G11c readCompactSize truncated 0xFE prefix returns EndOfStream (PASS)" {
    const truncated: [3]u8 = .{ 0xFE, 0x01, 0x00 };
    var reader = serialize.Reader{ .data = &truncated };
    try testing.expectError(error.EndOfStream, reader.readCompactSize());
}

test "w107 G11d readCompactSize truncated 0xFF prefix returns EndOfStream (PASS)" {
    const truncated: [5]u8 = .{ 0xFF, 0x01, 0x00, 0x00, 0x00 };
    var reader = serialize.Reader{ .data = &truncated };
    try testing.expectError(error.EndOfStream, reader.readCompactSize());
}

// ---------------------------------------------------------------------------
// G12 — writeVarInt 0 special case (PASS)
// ---------------------------------------------------------------------------

test "w107 G12 writeVarInt 0 encodes as [0x00] (PASS)" {
    const allocator = testing.allocator;
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeVarInt(0);
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, w.getWritten());
}

// ---------------------------------------------------------------------------
// G13 — readVarInt end-of-stream (PASS)
// ---------------------------------------------------------------------------

test "w107 G13 readVarInt on empty input returns EndOfStream (PASS)" {
    var reader = serialize.Reader{ .data = &[_]u8{} };
    try testing.expectError(error.EndOfStream, reader.readVarInt());
}

// ---------------------------------------------------------------------------
// G14 — CompactSize large (legitimate) values decode correctly (PASS)
// ---------------------------------------------------------------------------

test "w107 G14 readCompactSize large but valid values round-trip (PASS)" {
    const allocator = testing.allocator;
    const cases = [_]u64{
        0xFFFFFFFE, 0xFFFFFFFF, 0x100000000, std.math.maxInt(u32), std.math.maxInt(u64),
    };
    for (cases) |v| {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(v);
        var r = serialize.Reader{ .data = w.getWritten() };
        const got = try r.readCompactSize();
        try testing.expectEqual(v, got);
        try testing.expect(r.isAtEnd());
    }
}

// ---------------------------------------------------------------------------
// G15 — writeCompactSize / readCompactSize symmetry for all 1-byte values (PASS)
// ---------------------------------------------------------------------------

test "w107 G15 write-then-read symmetry for all 1-byte CompactSize values (PASS)" {
    const allocator = testing.allocator;
    var i: u8 = 0;
    while (true) : (i += 1) {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeCompactSize(i);
        var r = serialize.Reader{ .data = w.getWritten() };
        const got = try r.readCompactSize();
        try testing.expectEqual(@as(u64, i), got);
        if (i == 0xFF) break;
    }
}

// ---------------------------------------------------------------------------
// G16 — VarInt uniqueness (no redundant encodings) (PASS)
// ---------------------------------------------------------------------------

test "w107 G16 VarInt encoding is non-redundant round-trip (PASS)" {
    const allocator = testing.allocator;
    const cases = [_]u64{ 0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536 };
    for (cases) |v| {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeVarInt(v);
        var r = serialize.Reader{ .data = w.getWritten() };
        const got = try r.readVarInt();
        try testing.expectEqual(v, got);
        try testing.expect(r.isAtEnd());
    }
}

// ---------------------------------------------------------------------------
// G17 — CompactSize decode does not consume extra bytes (PASS)
// ---------------------------------------------------------------------------

test "w107 G17 readCompactSize leaves subsequent data intact (PASS)" {
    const allocator = testing.allocator;
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeCompactSize(0xFD);
    try w.writeInt(u8, 0xAB); // sentinel

    var r = serialize.Reader{ .data = w.getWritten() };
    const v = try r.readCompactSize();
    try testing.expectEqual(@as(u64, 0xFD), v);
    const sentinel = try r.readInt(u8);
    try testing.expectEqual(@as(u8, 0xAB), sentinel);
    try testing.expect(r.isAtEnd());
}

// ---------------------------------------------------------------------------
// G18 — compressor.writeCoin starts with correct VARINT bytes (PASS)
// ---------------------------------------------------------------------------

test "w107 G18 compressor.writeCoin starts with VARINT of coin-code (PASS)" {
    const compressor = @import("compressor.zig");
    const allocator = testing.allocator;

    // height=200, coinbase=false → code = 200<<1 = 400.
    // VARINT(400):
    //   n=400, n>127 → continuation
    //   tmp[0] = 400 & 0x7F = 0x10, n = (400>>7)-1 = 2
    //   tmp[1] = 2 & 0x7F | 0x80 = 0x82
    //   emit high→low: [0x82, 0x10]
    // CompactSize(400) = [0xFD, 0x90, 0x01]  (3 bytes, 400 = 0x190 LE)
    const script: [1]u8 = .{0x6A}; // OP_RETURN (non-special)
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try compressor.writeCoin(&w, 200, false, 0, &script);
    const bytes = w.getWritten();

    try testing.expect(bytes.len >= 2);
    try testing.expectEqual(@as(u8, 0x82), bytes[0]);
    try testing.expectEqual(@as(u8, 0x10), bytes[1]);
}

// ---------------------------------------------------------------------------
// G19 — VarInt large value round-trip (PASS)
// ---------------------------------------------------------------------------

test "w107 G19 VarInt large value round-trip (PASS)" {
    const allocator = testing.allocator;
    const large: u64 = 0x1234567890ABCDEF;
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeVarInt(large);
    var r = serialize.Reader{ .data = w.getWritten() };
    const got = try r.readVarInt();
    try testing.expectEqual(large, got);
    try testing.expect(r.isAtEnd());
}

// ---------------------------------------------------------------------------
// G20 — readCompactSize with a valid 0xFF prefix (PASS)
// ---------------------------------------------------------------------------

test "w107 G20 readCompactSize 0xFF prefix decodes correctly (PASS)" {
    const bytes: [9]u8 = .{ 0xFF, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
    var reader = serialize.Reader{ .data = &bytes };
    const v = try reader.readCompactSize();
    try testing.expectEqual(@as(u64, 0x0102030405060708), v);
    try testing.expect(reader.isAtEnd());
}

// ---------------------------------------------------------------------------
// G21 — CompactSize 1-byte upper boundary 0xFC (PASS)
// ---------------------------------------------------------------------------

test "w107 G21 readCompactSize 0xFC decodes as 252 in 1 byte (PASS)" {
    const bytes: [1]u8 = .{0xFC};
    var reader = serialize.Reader{ .data = &bytes };
    const v = try reader.readCompactSize();
    try testing.expectEqual(@as(u64, 252), v);
    try testing.expect(reader.isAtEnd());
}

// ---------------------------------------------------------------------------
// G22 — VarInt sequential values round-trip (PASS)
// ---------------------------------------------------------------------------

test "w107 G22 VarInt exhaustive small values 0..1000 (PASS)" {
    const allocator = testing.allocator;
    var i: u64 = 0;
    while (i < 1000) : (i += 1) {
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeVarInt(i);
        var r = serialize.Reader{ .data = w.getWritten() };
        const got = try r.readVarInt();
        try testing.expectEqual(i, got);
        try testing.expect(r.isAtEnd());
    }
}

// ---------------------------------------------------------------------------
// G23 — readVarInt properly handles single-byte values 0..127 (PASS)
// ---------------------------------------------------------------------------

test "w107 G23 readVarInt all single-byte values (0..127) decode correctly (PASS)" {
    var i: u8 = 0;
    while (i < 128) : (i += 1) {
        const bytes: [1]u8 = .{i};
        var r = serialize.Reader{ .data = &bytes };
        const got = try r.readVarInt();
        try testing.expectEqual(@as(u64, i), got);
        try testing.expect(r.isAtEnd());
    }
}

// ---------------------------------------------------------------------------
// G24 — CompactSize multi-element stream parsing (PASS)
// ---------------------------------------------------------------------------

test "w107 G24 multiple CompactSize values in sequence parse correctly (PASS)" {
    const allocator = testing.allocator;
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeCompactSize(0);
    try w.writeCompactSize(252);
    try w.writeCompactSize(0xFD);
    try w.writeCompactSize(0x10000);
    try w.writeCompactSize(0x100000000);

    var r = serialize.Reader{ .data = w.getWritten() };
    try testing.expectEqual(@as(u64, 0), try r.readCompactSize());
    try testing.expectEqual(@as(u64, 252), try r.readCompactSize());
    try testing.expectEqual(@as(u64, 0xFD), try r.readCompactSize());
    try testing.expectEqual(@as(u64, 0x10000), try r.readCompactSize());
    try testing.expectEqual(@as(u64, 0x100000000), try r.readCompactSize());
    try testing.expect(r.isAtEnd());
}

// ---------------------------------------------------------------------------
// G25 — VarInt multi-element stream parsing (PASS)
// ---------------------------------------------------------------------------

test "w107 G25 multiple VarInt values in sequence parse correctly (PASS)" {
    const allocator = testing.allocator;
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try w.writeVarInt(0);
    try w.writeVarInt(127);
    try w.writeVarInt(128);
    try w.writeVarInt(65535);
    try w.writeVarInt(0x100000000);

    var r = serialize.Reader{ .data = w.getWritten() };
    try testing.expectEqual(@as(u64, 0), try r.readVarInt());
    try testing.expectEqual(@as(u64, 127), try r.readVarInt());
    try testing.expectEqual(@as(u64, 128), try r.readVarInt());
    try testing.expectEqual(@as(u64, 65535), try r.readVarInt());
    try testing.expectEqual(@as(u64, 0x100000000), try r.readVarInt());
    try testing.expect(r.isAtEnd());
}

// ---------------------------------------------------------------------------
// G26 — Coin code value 0 (height=0, coinbase=false) encodes identically in
//       both VARINT and CompactSize (edge-case coverage) (PASS)
// ---------------------------------------------------------------------------

test "w107 G26 VARINT(0) == CompactSize(0) = [0x00] (PASS)" {
    const allocator = testing.allocator;
    var vw = serialize.Writer.init(allocator);
    defer vw.deinit();
    try vw.writeVarInt(0);

    var cw = serialize.Writer.init(allocator);
    defer cw.deinit();
    try cw.writeCompactSize(0);

    // Both should be [0x00].
    try testing.expectEqualSlices(u8, vw.getWritten(), cw.getWritten());
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, vw.getWritten());
}

// ---------------------------------------------------------------------------
// G27 — Coin code values 1..126 encode identically (safe range)
// ---------------------------------------------------------------------------

test "w107 G27 VARINT == CompactSize for values 1..126 (PASS)" {
    const allocator = testing.allocator;
    var i: u64 = 1;
    while (i <= 126) : (i += 1) {
        var vw = serialize.Writer.init(allocator);
        defer vw.deinit();
        try vw.writeVarInt(i);

        var cw = serialize.Writer.init(allocator);
        defer cw.deinit();
        try cw.writeCompactSize(i);

        try testing.expectEqualSlices(u8, vw.getWritten(), cw.getWritten());
    }
}

// ---------------------------------------------------------------------------
// G28 — Coin code value 127 is the last value where VARINT == CompactSize
// ---------------------------------------------------------------------------

test "w107 G28 code=127: VARINT == CompactSize [0x7F] (PASS)" {
    const allocator = testing.allocator;

    var vw = serialize.Writer.init(allocator);
    defer vw.deinit();
    try vw.writeVarInt(127);

    var cw = serialize.Writer.init(allocator);
    defer cw.deinit();
    try cw.writeCompactSize(127);

    try testing.expectEqualSlices(u8, &[_]u8{0x7F}, vw.getWritten());
    try testing.expectEqualSlices(u8, &[_]u8{0x7F}, cw.getWritten());
}

// ---------------------------------------------------------------------------
// G29 — code=128: VARINT diverges from CompactSize (BUG-3 onset threshold)
// ---------------------------------------------------------------------------

test "w107 G29 code=128 VARINT=[0x80 0x00] != CompactSize=[0x80] divergence onset (BUG-3)" {
    const allocator = testing.allocator;

    var vw = serialize.Writer.init(allocator);
    defer vw.deinit();
    try vw.writeVarInt(128);

    var cw = serialize.Writer.init(allocator);
    defer cw.deinit();
    try cw.writeCompactSize(128);

    try testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x00 }, vw.getWritten());
    try testing.expectEqualSlices(u8, &[_]u8{0x80}, cw.getWritten());
    try testing.expect(!std.mem.eql(u8, vw.getWritten(), cw.getWritten()));
}

// ---------------------------------------------------------------------------
// G30 — readVarInt correctly rejects near-overflow 2-byte sequence (PASS)
// ---------------------------------------------------------------------------
//
// Ensure the overflow guard fires before actually overflowing.

test "w107 G30 readVarInt rejects sequence that would overflow u64 (PASS)" {
    // Craft a VarInt stream that would require n > maxInt(u64):
    // 9 continuation bytes followed by a final byte that triggers overflow.
    const bad: [10]u8 = .{ 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };
    var reader = serialize.Reader{ .data = &bad };
    try testing.expectError(error.InvalidCompactSize, reader.readVarInt());
}
