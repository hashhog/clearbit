const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const crypto = @import("crypto.zig");
const script = @import("script.zig");
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");

// ============================================================
// SHA-256 / Hash256 test vectors
// ============================================================

test "SHA-256 empty string" {
    const result = crypto.sha256("");
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "SHA-256 abc" {
    const result = crypto.sha256("abc");
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "Hash256 (double SHA-256) of genesis block header" {
    // Genesis block header bytes (80 bytes)
    const genesis_header = [_]u8{
        0x01, 0x00, 0x00, 0x00, // version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // prev_block
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2,
        0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
        0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, // merkle_root
        0x29, 0xab, 0x5f, 0x49, // timestamp
        0xff, 0xff, 0x00, 0x1d, // bits
        0x1d, 0xac, 0x2b, 0x7c, // nonce
    };
    const hash = crypto.hash256(&genesis_header);
    // Genesis block hash (reversed for display):
    // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    const expected = [_]u8{
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
        0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
        0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
        0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try testing.expectEqualSlices(u8, &expected, &hash);
}

test "RIPEMD-160 empty" {
    const result = crypto.ripemd160("");
    const expected = [_]u8{
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
        0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31,
    };
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "RIPEMD-160 hello" {
    const result = crypto.ripemd160("hello");
    const expected = [_]u8{
        0x10, 0x8f, 0x07, 0xb8, 0x38, 0x24, 0x12, 0x61, 0x2c, 0x04,
        0x8d, 0x07, 0xd1, 0x3f, 0x81, 0x41, 0x18, 0x44, 0x5a, 0xcd,
    };
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "HASH-160 (RIPEMD160(SHA256))" {
    // Test with a well-known public key (Satoshi's genesis coinbase)
    const pubkey = [_]u8{
        0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67,
        0xf1, 0xa6, 0x71, 0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0,
        0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde, 0xb6,
        0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04,
        0xe5, 0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b,
        0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f,
    };
    const result = crypto.hash160(&pubkey);
    const expected = [_]u8{
        0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
        0x99, 0xeb, 0xf6, 0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
    };
    try testing.expectEqualSlices(u8, &expected, &result);
}

// ============================================================
// Serialization test vectors
// ============================================================

test "CompactSize encoding single byte" {
    const allocator = testing.allocator;
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    try writer.writeCompactSize(0xFC);
    const bytes = writer.getWritten();
    try testing.expectEqual(@as(usize, 1), bytes.len);
    try testing.expectEqual(@as(u8, 0xFC), bytes[0]);
}

test "CompactSize encoding two bytes" {
    const allocator = testing.allocator;
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    try writer.writeCompactSize(0xFD);
    const bytes = writer.getWritten();
    try testing.expectEqual(@as(usize, 3), bytes.len);
    try testing.expectEqual(@as(u8, 0xFD), bytes[0]);
}

test "CompactSize encoding four bytes" {
    const allocator = testing.allocator;
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    try writer.writeCompactSize(0x10000);
    const bytes = writer.getWritten();
    try testing.expectEqual(@as(usize, 5), bytes.len);
    try testing.expectEqual(@as(u8, 0xFE), bytes[0]);
}

test "CompactSize round-trip" {
    const allocator = testing.allocator;
    const test_values = [_]u64{
        0,
        1,
        0xFC,
        0xFD,
        0xFFFE,
        0xFFFF,
        0x10000,
        0xFFFFFFFF,
        0x100000000,
    };

    for (test_values) |value| {
        var writer = serialize.Writer.init(allocator);
        defer writer.deinit();

        try writer.writeCompactSize(value);
        const bytes = writer.getWritten();

        var reader = serialize.Reader{ .data = bytes };
        const read_value = try reader.readCompactSize();

        try testing.expectEqual(value, read_value);
        try testing.expect(reader.isAtEnd());
    }
}

test "Deserialize genesis block" {
    const allocator = testing.allocator;
    const genesis_raw = @embedFile("testdata/genesis_block.bin");
    var reader = serialize.Reader{ .data = genesis_raw };
    const block = try serialize.readBlock(&reader, allocator);
    defer {
        for (block.transactions) |tx| {
            for (tx.inputs) |input| {
                allocator.free(input.script_sig);
                allocator.free(input.witness);
            }
            allocator.free(tx.inputs);
            for (tx.outputs) |output| {
                allocator.free(output.script_pubkey);
            }
            allocator.free(tx.outputs);
        }
        allocator.free(block.transactions);
    }

    try testing.expectEqual(@as(i32, 1), block.header.version);
    try testing.expectEqual(@as(usize, 1), block.transactions.len);
    // Genesis coinbase has one input and one output
    try testing.expectEqual(@as(usize, 1), block.transactions[0].inputs.len);
    try testing.expectEqual(@as(usize, 1), block.transactions[0].outputs.len);
    // Genesis coinbase output value is 50 BTC = 5_000_000_000 satoshis
    try testing.expectEqual(@as(i64, 5_000_000_000), block.transactions[0].outputs[0].value);
}

test "Block header serialization round-trip" {
    const allocator = testing.allocator;

    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0xAB} ** 32,
        .timestamp = 1231006505,
        .bits = 0x1d00ffff,
        .nonce = 2083236893,
    };

    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try serialize.writeBlockHeader(&writer, &header);

    const bytes = writer.getWritten();
    try testing.expectEqual(@as(usize, 80), bytes.len);

    var reader = serialize.Reader{ .data = bytes };
    const parsed = try serialize.readBlockHeader(&reader);

    try testing.expectEqual(header.version, parsed.version);
    try testing.expectEqualSlices(u8, &header.prev_block, &parsed.prev_block);
    try testing.expectEqualSlices(u8, &header.merkle_root, &parsed.merkle_root);
    try testing.expectEqual(header.timestamp, parsed.timestamp);
    try testing.expectEqual(header.bits, parsed.bits);
    try testing.expectEqual(header.nonce, parsed.nonce);
}

// ============================================================
// Script validation test vectors
// ============================================================

test "Script: OP_TRUE evaluates to true" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Script: OP_1 (0x51)
    const s = [_]u8{0x51};
    try engine.execute(&s);

    try testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    // OP_1 pushes a single byte with value 1
    try testing.expectEqual(@as(usize, 1), engine.stack.items[0].len);
    try testing.expectEqual(@as(u8, 1), engine.stack.items[0][0]);
}

test "Script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
    const s = [_]u8{ 0x51, 0x51, 0x93, 0x52, 0x87 };
    try engine.execute(&s);

    try testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    // OP_EQUAL pushes 1 (true) when equal
    try testing.expectEqual(@as(usize, 1), engine.stack.items[0].len);
    try testing.expectEqual(@as(u8, 1), engine.stack.items[0][0]);
}

test "Script: P2PKH template classification" {
    // Standard P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    var s: [25]u8 = undefined;
    s[0] = 0x76; // OP_DUP
    s[1] = 0xa9; // OP_HASH160
    s[2] = 0x14; // Push 20 bytes
    @memset(s[3..23], 0xAB); // 20 byte hash
    s[23] = 0x88; // OP_EQUALVERIFY
    s[24] = 0xac; // OP_CHECKSIG

    try testing.expectEqual(script.ScriptType.p2pkh, script.classifyScript(&s));
}

test "Script: P2SH template classification" {
    // Standard P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    var s: [23]u8 = undefined;
    s[0] = 0xa9; // OP_HASH160
    s[1] = 0x14; // Push 20 bytes
    @memset(s[2..22], 0xAB); // 20 byte hash
    s[22] = 0x87; // OP_EQUAL

    try testing.expectEqual(script.ScriptType.p2sh, script.classifyScript(&s));
}

test "Script: P2WPKH template classification" {
    // Standard P2WPKH: OP_0 <20 bytes>
    var s: [22]u8 = undefined;
    s[0] = 0x00; // OP_0
    s[1] = 0x14; // Push 20 bytes
    @memset(s[2..22], 0xAB); // 20 byte hash

    try testing.expectEqual(script.ScriptType.p2wpkh, script.classifyScript(&s));
}

test "Script: P2WSH template classification" {
    // Standard P2WSH: OP_0 <32 bytes>
    var s: [34]u8 = undefined;
    s[0] = 0x00; // OP_0
    s[1] = 0x20; // Push 32 bytes
    @memset(s[2..34], 0xAB); // 32 byte hash

    try testing.expectEqual(script.ScriptType.p2wsh, script.classifyScript(&s));
}

test "Script: P2TR template classification" {
    // Standard P2TR: OP_1 <32 bytes>
    var s: [34]u8 = undefined;
    s[0] = 0x51; // OP_1
    s[1] = 0x20; // Push 32 bytes
    @memset(s[2..34], 0xAB); // 32 byte x-only pubkey

    try testing.expectEqual(script.ScriptType.p2tr, script.classifyScript(&s));
}

test "Script: OP_RETURN classified as null_data" {
    const s = [_]u8{ 0x6a, 0x04, 0x01, 0x02, 0x03, 0x04 };
    try testing.expectEqual(script.ScriptType.null_data, script.classifyScript(&s));
}

// ============================================================
// MINIMALIF test vectors (BIP-342 / segwit consensus)
// ============================================================

test "MINIMALIF: OP_IF with 0x02 fails in witness v0" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Set witness v0 mode to enforce MINIMALIF
    engine.sig_version = .witness_v0;

    // Push 0x02 (invalid MINIMALIF value), then OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    // Script: <0x02> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    const s = [_]u8{ 0x01, 0x02, 0x63, 0x51, 0x67, 0x00, 0x68 };
    const result = engine.execute(&s);
    try testing.expectError(script.ScriptError.MinimalIf, result);
}

test "MINIMALIF: OP_IF with 0x01 passes in witness v0" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Set witness v0 mode to enforce MINIMALIF
    engine.sig_version = .witness_v0;

    // Push 0x01 (valid MINIMALIF true value), then OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    // Script: <0x01> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    const s = [_]u8{ 0x01, 0x01, 0x63, 0x51, 0x67, 0x00, 0x68 };
    try engine.execute(&s);

    // Should have taken the true branch and pushed OP_1
    try testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    try testing.expectEqual(@as(u8, 1), engine.stack.items[0][0]);
}

test "MINIMALIF: OP_IF with empty slice takes else branch in witness v0" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Set witness v0 mode to enforce MINIMALIF
    engine.sig_version = .witness_v0;

    // Push empty (OP_0), then OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
    // Script: OP_0 OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
    const s = [_]u8{ 0x00, 0x63, 0x51, 0x67, 0x52, 0x68 };
    try engine.execute(&s);

    // Should have taken the false (else) branch and pushed OP_2
    try testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    try testing.expectEqual(@as(u8, 2), engine.stack.items[0][0]);
}

test "MINIMALIF: OP_IF with 0x00 byte fails in witness v0" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Set witness v0 mode to enforce MINIMALIF
    engine.sig_version = .witness_v0;

    // Push a single 0x00 byte (invalid - only empty slice is acceptable for false)
    // Script: <0x00> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    const s = [_]u8{ 0x01, 0x00, 0x63, 0x51, 0x67, 0x00, 0x68 };
    const result = engine.execute(&s);
    try testing.expectError(script.ScriptError.MinimalIf, result);
}

test "MINIMALIF: OP_NOTIF with 0x02 fails in witness v0" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Set witness v0 mode to enforce MINIMALIF
    engine.sig_version = .witness_v0;

    // Push 0x02 (invalid MINIMALIF value), then OP_NOTIF OP_1 OP_ELSE OP_0 OP_ENDIF
    // Script: <0x02> OP_NOTIF OP_1 OP_ELSE OP_0 OP_ENDIF
    const s = [_]u8{ 0x01, 0x02, 0x64, 0x51, 0x67, 0x00, 0x68 };
    const result = engine.execute(&s);
    try testing.expectError(script.ScriptError.MinimalIf, result);
}

test "MINIMALIF: multi-byte value fails in witness v0" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Set witness v0 mode to enforce MINIMALIF
    engine.sig_version = .witness_v0;

    // Push [0x01, 0x00] (multi-byte, even though would be truthy, fails MINIMALIF)
    // Script: <0x01 0x00> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    const s = [_]u8{ 0x02, 0x01, 0x00, 0x63, 0x51, 0x67, 0x00, 0x68 };
    const result = engine.execute(&s);
    try testing.expectError(script.ScriptError.MinimalIf, result);
}

test "MINIMALIF: OP_IF with 0x02 allowed in legacy (base) mode" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Default is base mode (legacy), MINIMALIF not enforced
    // Push 0x02 (truthy in legacy), then OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    // Script: <0x02> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    const s = [_]u8{ 0x01, 0x02, 0x63, 0x51, 0x67, 0x00, 0x68 };
    try engine.execute(&s);

    // Should have taken the true branch since 0x02 is truthy in legacy
    try testing.expectEqual(@as(usize, 1), engine.stack.items.len);
    try testing.expectEqual(@as(u8, 1), engine.stack.items[0][0]);
}

test "MINIMALIF: enforced in tapscript mode" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();

    // Set tapscript mode to enforce MINIMALIF
    engine.sig_version = .tapscript;

    // Push 0x02 (invalid MINIMALIF value), then OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    const s = [_]u8{ 0x01, 0x02, 0x63, 0x51, 0x67, 0x00, 0x68 };
    const result = engine.execute(&s);
    try testing.expectError(script.ScriptError.MinimalIf, result);
}

// ============================================================
// Consensus rules test vectors
// ============================================================

test "Block subsidy halving" {
    const params = consensus.getNetworkParams(.mainnet);
    try testing.expectEqual(@as(i64, 5_000_000_000), consensus.getBlockSubsidy(0, params));
    try testing.expectEqual(@as(i64, 5_000_000_000), consensus.getBlockSubsidy(209_999, params));
    try testing.expectEqual(@as(i64, 2_500_000_000), consensus.getBlockSubsidy(210_000, params));
    try testing.expectEqual(@as(i64, 1_250_000_000), consensus.getBlockSubsidy(420_000, params));
    // After 64 halvings, subsidy is 0
    try testing.expectEqual(@as(i64, 0), consensus.getBlockSubsidy(210_000 * 64, params));
}

test "Block subsidy regtest interval" {
    const params = consensus.getNetworkParams(.regtest);
    // Regtest has 150 block halving interval
    try testing.expectEqual(@as(i64, 5_000_000_000), consensus.getBlockSubsidy(0, params));
    try testing.expectEqual(@as(i64, 2_500_000_000), consensus.getBlockSubsidy(150, params));
}

test "Difficulty adjustment no change" {
    // Test with known mainnet difficulty adjustments
    // If blocks came in exactly 2 weeks, no adjustment
    const params = consensus.getNetworkParams(.mainnet);
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = consensus.TARGET_TIMESPAN, // exactly 2 weeks
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    const new_bits = consensus.calculateNextWorkRequired(&header, 0, params);
    // Same target since exactly 2 weeks elapsed
    try testing.expectEqual(@as(u32, 0x1d00ffff), new_bits);
}

test "Difficulty adjustment clamps to 4x max" {
    const params = consensus.getNetworkParams(.mainnet);

    // If blocks came in 8x too slow, difficulty should only decrease 4x (clamped)
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = consensus.TARGET_TIMESPAN * 8, // 8x target (should clamp to 4x)
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    const new_bits = consensus.calculateNextWorkRequired(&header, 0, params);
    // Target should increase (easier difficulty) but capped at 4x
    // The actual bits value depends on the calculation, but it should be different
    try testing.expect(new_bits != 0x1d00ffff);
}

test "Regtest no retarget" {
    const params = consensus.getNetworkParams(.regtest);
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1000,
        .bits = 0x207fffff,
        .nonce = 0,
    };

    // On regtest, difficulty never changes
    const new_bits = consensus.calculateNextWorkRequired(&header, 0, params);
    try testing.expectEqual(header.bits, new_bits);
}

test "Valid money range" {
    try testing.expect(consensus.isValidMoney(0));
    try testing.expect(consensus.isValidMoney(100_000_000)); // 1 BTC
    try testing.expect(consensus.isValidMoney(consensus.MAX_MONEY));
    try testing.expect(!consensus.isValidMoney(consensus.MAX_MONEY + 1));
    try testing.expect(!consensus.isValidMoney(-1));
}

test "Genesis block hash matches mainnet" {
    const header = consensus.MAINNET.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try testing.expectEqualSlices(u8, &consensus.MAINNET.genesis_hash, &computed_hash);
}

test "Genesis block hash matches testnet" {
    const header = consensus.TESTNET.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try testing.expectEqualSlices(u8, &consensus.TESTNET.genesis_hash, &computed_hash);
}

test "Genesis block hash matches regtest" {
    const header = consensus.REGTEST.genesis_header;
    const computed_hash = crypto.computeBlockHash(&header);
    try testing.expectEqualSlices(u8, &consensus.REGTEST.genesis_hash, &computed_hash);
}

test "Genesis block meets pow target" {
    const header = consensus.MAINNET.genesis_header;
    const target = consensus.bitsToTarget(header.bits);
    const block_hash = crypto.computeBlockHash(&header);
    try testing.expect(consensus.hashMeetsTarget(&block_hash, &target));
}

// ============================================================
// P2P message test vectors
// ============================================================

test "P2P version message round-trip" {
    const allocator = testing.allocator;

    const version_msg = p2p.VersionMessage{
        .version = p2p.PROTOCOL_VERSION,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS | p2p.NODE_NETWORK_LIMITED,
        .timestamp = 1234567890,
        .addr_recv = types.NetworkAddress{
            .services = p2p.NODE_NETWORK,
            .ip = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 },
            .port = 8333,
        },
        .addr_from = types.NetworkAddress{
            .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
            .ip = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1 },
            .port = 8333,
        },
        .nonce = 0xDEADBEEFCAFEBABE,
        .user_agent = p2p.USER_AGENT,
        .start_height = 800000,
        .relay = true,
    };

    const msg = p2p.Message{ .version = version_msg };
    const serialized = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(serialized);

    // Decode header
    const header = p2p.MessageHeader.decode(serialized[0..24]);
    try testing.expectEqual(p2p.NetworkMagic.MAINNET, header.magic);
    try testing.expectEqualStrings("version", header.commandName());

    // Verify checksum
    const payload = serialized[24..];
    try testing.expect(header.verifyChecksum(payload));

    // Decode payload
    const decoded_msg = try p2p.decodePayload(header.commandName(), payload, allocator);
    const deserialized = decoded_msg.version;

    try testing.expectEqual(version_msg.version, deserialized.version);
    try testing.expectEqual(version_msg.services, deserialized.services);
    try testing.expectEqualSlices(u8, version_msg.user_agent, deserialized.user_agent);
    try testing.expectEqual(version_msg.start_height, deserialized.start_height);
    try testing.expectEqual(version_msg.relay, deserialized.relay);
}

test "P2P ping/pong round-trip" {
    const allocator = testing.allocator;
    const nonce: u64 = 0x123456789ABCDEF0;

    // Test ping
    {
        const msg = p2p.Message{ .ping = .{ .nonce = nonce } };
        const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        const header = p2p.MessageHeader.decode(encoded[0..24]);
        try testing.expectEqualStrings("ping", header.commandName());
        try testing.expectEqual(@as(u32, 8), header.length);

        const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
        try testing.expectEqual(nonce, decoded.ping.nonce);
    }

    // Test pong
    {
        const msg = p2p.Message{ .pong = .{ .nonce = nonce } };
        const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
        defer allocator.free(encoded);

        const header = p2p.MessageHeader.decode(encoded[0..24]);
        try testing.expectEqualStrings("pong", header.commandName());

        const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
        try testing.expectEqual(nonce, decoded.pong.nonce);
    }
}

test "P2P message header checksum" {
    const magic = p2p.NetworkMagic.MAINNET;
    const payload = "test payload";
    const header = p2p.MessageHeader.create(magic, "version", payload);

    // Verify checksum is hash256(payload)[0..4]
    const expected_checksum = crypto.hash256(payload)[0..4];
    try testing.expectEqualSlices(u8, &expected_checksum.*, &header.checksum);
    try testing.expect(header.verifyChecksum(payload));
    try testing.expect(!header.verifyChecksum("wrong payload"));
}

test "P2P empty payload checksum" {
    // For empty payloads, checksum is hash256("")[0..4] = 0x5df6e0e2
    const header = p2p.MessageHeader.create(p2p.NetworkMagic.MAINNET, "verack", "");
    const expected = [_]u8{ 0x5d, 0xf6, 0xe0, 0xe2 };
    try testing.expectEqualSlices(u8, &expected, &header.checksum);
}

test "P2P network magic values" {
    try testing.expectEqual(@as(u32, 0xD9B4BEF9), p2p.NetworkMagic.MAINNET);
    try testing.expectEqual(@as(u32, 0x0709110B), p2p.NetworkMagic.TESTNET);
    try testing.expectEqual(@as(u32, 0xDAB5BFFA), p2p.NetworkMagic.REGTEST);
    try testing.expectEqual(@as(u32, 0x40CF030A), p2p.NetworkMagic.SIGNET);
}

// ============================================================
// Merkle tree test vectors
// ============================================================

test "Merkle root single hash" {
    const allocator = testing.allocator;
    const hash = [_]u8{0xAB} ** 32;
    const hashes = [_]types.Hash256{hash};
    const root = try crypto.computeMerkleRoot(&hashes, allocator);
    try testing.expectEqualSlices(u8, &hash, &root);
}

test "Merkle root two hashes" {
    const allocator = testing.allocator;
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const hashes = [_]types.Hash256{ a, b };

    // Expected: hash256(a ++ b)
    var concat: [64]u8 = undefined;
    @memcpy(concat[0..32], &a);
    @memcpy(concat[32..64], &b);
    const expected = crypto.hash256(&concat);

    const root = try crypto.computeMerkleRoot(&hashes, allocator);
    try testing.expectEqualSlices(u8, &expected, &root);
}

test "Merkle root three hashes duplicates last" {
    const allocator = testing.allocator;
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const hashes = [_]types.Hash256{ a, b, c };

    // Level 1: hash(a,b), hash(c,c)
    var ab: [64]u8 = undefined;
    @memcpy(ab[0..32], &a);
    @memcpy(ab[32..64], &b);
    const hash_ab = crypto.hash256(&ab);

    var cc: [64]u8 = undefined;
    @memcpy(cc[0..32], &c);
    @memcpy(cc[32..64], &c);
    const hash_cc = crypto.hash256(&cc);

    // Level 2: hash(hash_ab, hash_cc)
    var final: [64]u8 = undefined;
    @memcpy(final[0..32], &hash_ab);
    @memcpy(final[32..64], &hash_cc);
    const expected = crypto.hash256(&final);

    const root = try crypto.computeMerkleRoot(&hashes, allocator);
    try testing.expectEqualSlices(u8, &expected, &root);
}

// ============================================================
// Fuzz targets
// ============================================================

test "fuzz: CompactSize decoding" {
    // Test that random input doesn't crash
    const test_inputs = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x00},
        &[_]u8{0xFC},
        &[_]u8{0xFD},
        &[_]u8{ 0xFD, 0x00 },
        &[_]u8{ 0xFD, 0x00, 0x01 },
        &[_]u8{0xFE},
        &[_]u8{ 0xFE, 0x00, 0x00, 0x01, 0x00 },
        &[_]u8{0xFF},
        &[_]u8{ 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 },
    };

    for (test_inputs) |input| {
        var reader = serialize.Reader{ .data = input };
        // Should not crash, may return error
        _ = reader.readCompactSize() catch {};
    }
}

test "fuzz: block header parsing" {
    // Test that random input of correct length parses without crash
    const test_inputs = [_][80]u8{
        [_]u8{0} ** 80,
        [_]u8{0xFF} ** 80,
        [_]u8{0x01} ++ [_]u8{0} ** 79,
    };

    for (test_inputs) |input| {
        var reader = serialize.Reader{ .data = &input };
        // Should not crash
        _ = serialize.readBlockHeader(&reader) catch {};
    }
}

test "fuzz: script evaluation" {
    const allocator = testing.allocator;
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // Test that random scripts don't crash
    const test_scripts = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x00}, // OP_0
        &[_]u8{0x51}, // OP_1
        &[_]u8{ 0x51, 0x51, 0x93 }, // OP_1 OP_1 OP_ADD
        &[_]u8{0x6a}, // OP_RETURN
        &[_]u8{ 0xFF, 0xFF, 0xFF }, // Invalid opcodes
        &[_]u8{ 0x4c, 0x00 }, // OP_PUSHDATA1 with 0 length
        &[_]u8{ 0x63, 0x68 }, // OP_IF OP_ENDIF
    };

    for (test_scripts) |s| {
        var engine = script.ScriptEngine.init(allocator, &tx, 0, 0, script.ScriptFlags{});
        defer engine.deinit();
        // Should never crash, may return error
        _ = engine.execute(s) catch {};
    }
}

// ============================================================
// Additional consensus tests
// ============================================================

test "bitsToTarget difficulty 1" {
    // 0x1d00ffff is difficulty 1 on mainnet
    const target = consensus.bitsToTarget(0x1d00ffff);

    // Mantissa 0x00FFFF stored little-endian starting at byte 26
    try testing.expectEqual(@as(u8, 0xFF), target[26]);
    try testing.expectEqual(@as(u8, 0xFF), target[27]);
    try testing.expectEqual(@as(u8, 0x00), target[28]);

    // Rest should be zero
    for (0..26) |i| {
        try testing.expectEqual(@as(u8, 0), target[i]);
    }
    for (29..32) |i| {
        try testing.expectEqual(@as(u8, 0), target[i]);
    }
}

test "bitsToTarget regtest" {
    // Regtest uses 0x207fffff
    const target = consensus.bitsToTarget(0x207fffff);

    // exponent = 0x20 = 32, mantissa = 0x7fffff
    // position = 32 - 3 = 29
    try testing.expectEqual(@as(u8, 0xFF), target[29]);
    try testing.expectEqual(@as(u8, 0xFF), target[30]);
    try testing.expectEqual(@as(u8, 0x7F), target[31]);
}

test "targetToBits roundtrip" {
    const test_cases = [_]u32{ 0x1d00ffff, 0x207fffff, 0x1b0404cb, 0x180526fd };

    for (test_cases) |bits| {
        const target = consensus.bitsToTarget(bits);
        const recovered = consensus.targetToBits(&target);
        // Note: roundtrip may not be exact due to normalization
        // But bitsToTarget(recovered) should equal bitsToTarget(bits)
        const target2 = consensus.bitsToTarget(recovered);
        try testing.expectEqualSlices(u8, &target, &target2);
    }
}

test "hashMeetsTarget" {
    // A hash of all zeros meets any non-zero target
    const zero_hash: types.Hash256 = [_]u8{0} ** 32;
    const target = consensus.bitsToTarget(0x1d00ffff);
    try testing.expect(consensus.hashMeetsTarget(&zero_hash, &target));

    // A hash of all 0xFF fails
    const max_hash: types.Hash256 = [_]u8{0xFF} ** 32;
    try testing.expect(!consensus.hashMeetsTarget(&max_hash, &target));
}

test "consensus constants" {
    // Verify key consensus constants
    try testing.expectEqual(@as(u32, 4_000_000), consensus.MAX_BLOCK_WEIGHT);
    try testing.expectEqual(@as(u32, 2016), consensus.DIFFICULTY_ADJUSTMENT_INTERVAL);
    try testing.expectEqual(@as(u32, 600), consensus.TARGET_SPACING);
    try testing.expectEqual(@as(u32, 1_209_600), consensus.TARGET_TIMESPAN);
    try testing.expectEqual(@as(u32, 100), consensus.COINBASE_MATURITY);

    // BIP activation heights
    try testing.expectEqual(@as(u32, 227_931), consensus.BIP34_HEIGHT);
    try testing.expectEqual(@as(u32, 388_381), consensus.BIP65_HEIGHT);
    try testing.expectEqual(@as(u32, 363_725), consensus.BIP66_HEIGHT);
    try testing.expectEqual(@as(u32, 481_824), consensus.SEGWIT_HEIGHT);
    try testing.expectEqual(@as(u32, 709_632), consensus.TAPROOT_HEIGHT);
}

// ============================================================
// Import all module tests
// ============================================================

// This ensures all tests from individual modules are also run
comptime {
    _ = @import("types.zig");
    _ = @import("serialize.zig");
    _ = @import("crypto.zig");
    _ = @import("script.zig");
    _ = @import("consensus.zig");
    _ = @import("p2p.zig");
    _ = @import("address.zig");
    _ = @import("validation.zig");
    _ = @import("mempool.zig");
    _ = @import("perf.zig");
    _ = @import("bench.zig");
    _ = @import("indexes.zig");
    _ = @import("v2_transport.zig");
}
