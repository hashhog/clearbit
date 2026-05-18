//! W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (clearbit / Zig 0.13)
//!
//! Discovery-only audit of clearbit's PSBT implementation vs Bitcoin Core
//! (`bitcoin-core/src/psbt.h`, `bitcoin-core/src/psbt.cpp`,
//!  `bitcoin-core/src/wallet/rpc/spend.cpp`,
//!  `bitcoin-core/src/rpc/rawtransaction.cpp` PSBT entrypoints).
//!
//! BIPs covered: 174 (PSBT v0), 370 (PSBT v2), 371 (Taproot fields), 373
//! (MuSig2 fields).
//!
//! Test shape: a mixture of behavioral round-trip XFAILs (run the parser
//! against crafted-malformed bytes and assert clearbit accepts where Core
//! rejects — flip the assertion when the fix lands) AND source-level
//! grep guards over `psbt.zig` + `wallet.zig` + `rpc.zig` (asserts a
//! Core-named string is absent — flip when wired). Each gate's BUG test
//! asserts the **current (buggy) state** so a future fix wave flips the
//! assertion by closing the gate.
//!
//! Run: `zig build test-w137 --summary all`
//!
//! See `audit/w137_psbt.md` for the full 30-gate matrix and prose.

const std = @import("std");
const testing = std.testing;

const psbt = @import("psbt.zig");
const types = @import("types.zig");
const serialize_mod = @import("serialize.zig");

// ===========================================================================
// Helpers
// ===========================================================================

/// Open `src/<basename>.zig` and return the full contents (caller frees).
fn loadSrc(allocator: std.mem.Allocator, basename: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, "src/{s}.zig", .{basename});
    defer allocator.free(path);
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 32 * 1024 * 1024);
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

/// Build a 1-input / 1-output unsigned tx with a single P2WPKH output.
fn buildUnsignedTx(_: std.mem.Allocator) types.Transaction {
    const inputs = struct {
        const ins: [1]types.TxIn = .{
            .{
                .previous_output = .{
                    .hash = [_]u8{0x11} ** 32,
                    .index = 0,
                },
                .script_sig = &[_]u8{},
                .sequence = 0xFFFFFFFF,
                .witness = &[_][]const u8{},
            },
        };
    }.ins;
    const outputs = struct {
        const spk: [22]u8 = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;
        const outs: [1]types.TxOut = .{
            .{
                .value = 50000,
                .script_pubkey = &spk,
            },
        };
    }.outs;
    return types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };
}

// ===========================================================================
// G1 — Module docstring accurately describes supported BIPs
// Status: DIVERGE (BUG-1). Header says "BIP174/370" but BIP-370 is unimplemented.
// ===========================================================================
test "w137 G1: psbt.zig module docstring lies about BIP-370 support (BUG-1)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // First-line module docstring still advertises BIP-370 alongside BIP-174,
    // but BIP-370 (PSBT v2) has zero corresponding wire types.
    try testing.expect(contains(src, "BIP174/370"));
    // Negative-presence guard: none of the BIP-370 wire types are defined.
    try testing.expect(!contains(src, "PSBT_GLOBAL_TX_VERSION"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_FALLBACK_LOCKTIME"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_INPUT_COUNT"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_OUTPUT_COUNT"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_TX_MODIFIABLE"));
}

// ===========================================================================
// G2 — `key_lookup` set on deserialize prevents duplicate keys
// Status: MISSING (BUG-3). No duplicate-key detection at all.
// ===========================================================================
test "w137 G2: no duplicate-key detection on deserialize (BUG-3)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // No key_lookup set / Duplicate Key string / .DuplicateKey raise anywhere
    // in parseInputMap / parseOutputMap / global reader.
    try testing.expect(!contains(src, "key_lookup"));
    try testing.expect(!contains(src, "Duplicate Key, "));
    // The error variant is declared but never raised by deserialize-time code.
    try testing.expect(contains(src, "DuplicateKey,"));
    try testing.expect(!contains(src, "return PsbtError.DuplicateKey"));
    try testing.expect(!contains(src, "return error.DuplicateKey"));
}

// ===========================================================================
// G2 behavioral — duplicate witness_utxo silently overwritten on deserialize
// Use std.heap.page_allocator so the leak (which is itself evidence of the
// bug — the second witness_utxo overwrite drops the first script_pubkey
// allocation without freeing it) doesn't trip the testing allocator's leak
// detector. Closing BUG-3 will eliminate the leak by rejecting the
// duplicate before it allocates.
// ===========================================================================
test "w137 G2b: duplicate witness_utxo silently overwrites first value (BUG-3)" {
    const allocator = std.heap.page_allocator;

    // Build a minimal PSBT manually: magic + global + 1 input (with two
    // witness_utxo entries, second carries different amount) + 1 output.
    // Wire-format reference: BIP-174.
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    var w = serialize_mod.Writer.init(allocator);
    defer w.deinit();

    // Magic
    try w.writeBytes(&psbt.PSBT_MAGIC);

    // Global map: PSBT_GLOBAL_UNSIGNED_TX
    var tx_writer = serialize_mod.Writer.init(allocator);
    defer tx_writer.deinit();
    const tx = buildUnsignedTx(allocator);
    try serialize_mod.writeTransactionNoWitness(&tx_writer, &tx);
    const tx_bytes = tx_writer.getWritten();

    // key = <1 byte><0x00>
    try w.writeCompactSize(1);
    try w.writeInt(u8, psbt.PSBT_GLOBAL_UNSIGNED_TX);
    // value
    try w.writeCompactSize(tx_bytes.len);
    try w.writeBytes(tx_bytes);
    // separator
    try w.writeInt(u8, psbt.PSBT_SEPARATOR);

    // Input map: TWO `PSBT_IN_WITNESS_UTXO` entries with different values.
    // Entry 1: value = 1000
    try w.writeCompactSize(1);
    try w.writeInt(u8, psbt.PSBT_IN_WITNESS_UTXO);
    const spk = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    var v1 = serialize_mod.Writer.init(allocator);
    defer v1.deinit();
    try v1.writeInt(i64, 1000);
    try v1.writeCompactSize(spk.len);
    try v1.writeBytes(spk);
    try w.writeCompactSize(v1.getWritten().len);
    try w.writeBytes(v1.getWritten());

    // Entry 2 (DUPLICATE!): value = 999999
    try w.writeCompactSize(1);
    try w.writeInt(u8, psbt.PSBT_IN_WITNESS_UTXO);
    var v2 = serialize_mod.Writer.init(allocator);
    defer v2.deinit();
    try v2.writeInt(i64, 999999);
    try v2.writeCompactSize(spk.len);
    try v2.writeBytes(spk);
    try w.writeCompactSize(v2.getWritten().len);
    try w.writeBytes(v2.getWritten());

    // Separator (end of input map)
    try w.writeInt(u8, psbt.PSBT_SEPARATOR);
    // Empty output map: just a separator
    try w.writeInt(u8, psbt.PSBT_SEPARATOR);

    // BUG: deserialize succeeds despite the duplicate witness_utxo key.
    // Core would throw "Duplicate Key, input witness utxo already provided".
    var p = psbt.Psbt.deserialize(allocator, w.getWritten()) catch |e| {
        // If clearbit ever DOES start rejecting this, that's the fix.
        // Flip this whole test in that case.
        std.debug.print("\n(NOTE: clearbit rejected duplicate witness_utxo: {}; flip BUG-3 test)\n", .{e});
        return error.SkipZigTest;
    };
    defer p.deinit();

    // Second value won (last-write-wins on optional overwrite).
    try testing.expectEqual(@as(i64, 999999), p.inputs[0].witness_utxo.?.value);
}

// ===========================================================================
// G3 — `non_witness_utxo` hash matches `tx.vin[i].prevout.hash` on deserialize
// Status: MISSING (BUG-4). No check at all on the deserialize path.
// ===========================================================================
test "w137 G3: non_witness_utxo hash check absent on deserialize (BUG-4)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // parseInputMap's PSBT_IN_NON_WITNESS_UTXO arm just calls readTransaction
    // and stores; no hash check.
    try testing.expect(contains(src, "PSBT_IN_NON_WITNESS_UTXO => {"));
    // The Updater path (addInputNonWitnessUtxo) DOES check; assert it's
    // present so we know the helper exists and can be reused.
    try testing.expect(contains(src, "fn addInputNonWitnessUtxo"));
    try testing.expect(contains(src, "NonWitnessUtxoMismatch"));

    // The deserialize-path arm uses parseInputMap (free function, no `self`
    // pointer to the unsigned tx). Look for the SPECIFIC arm we're auditing:
    // it must NOT contain any "NonWitnessUtxoMismatch" raise within the
    // function body. Grep for the parseInputMap function and its body
    // through the next `fn parseOutputMap`.
    const parse_input_start = std.mem.indexOf(u8, src, "fn parseInputMap").?;
    const parse_output_start = std.mem.indexOf(u8, src, "fn parseOutputMap").?;
    const parse_input_body = src[parse_input_start..parse_output_start];
    // Body must NOT reference the mismatch variant — the check is dead code
    // outside the Updater entry point.
    try testing.expect(!contains(parse_input_body, "NonWitnessUtxoMismatch"));
}

// ===========================================================================
// G4 — Singleton key types reject `key.size() != 1`
// Status: MISSING (BUG-5). No length check on scalar-key arms.
// ===========================================================================
test "w137 G4: singleton key types accept extra key_data bytes (BUG-5)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Core says: "Witness utxo key is more than one byte type", etc.
    // clearbit never emits anything resembling these strings.
    try testing.expect(!contains(src, "key is more than one byte type"));

    // The PSBT_IN_WITNESS_UTXO parse arm has no key_data.len check.
    // Find the arm and assert it doesn't validate key_data.len.
    const witness_utxo_arm_start = std.mem.indexOf(u8, src, "PSBT_IN_WITNESS_UTXO => {").?;
    // Read forward 200 bytes (enough to capture the arm body before the next
    // case).
    const slice_end = @min(src.len, witness_utxo_arm_start + 300);
    const arm_body = src[witness_utxo_arm_start..slice_end];
    // No `key_data.len != 0` check anywhere in the arm.
    try testing.expect(!contains(arm_body, "key_data.len != 0"));
    try testing.expect(!contains(arm_body, "key_data.len > 0"));
}

// ===========================================================================
// G5 — `PSBT_IN_PARTIAL_SIG` pubkey validated as `IsFullyValid`
// Status: MISSING (BUG-6). No validation; also truncates 65-byte uncompressed
// keys to 33 bytes silently.
// ===========================================================================
test "w137 G5: partial_sigs pubkey not validated (BUG-6)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // The parse arm exists but only does a length check (33 or 65).
    try testing.expect(contains(src, "PSBT_IN_PARTIAL_SIG => {"));
    // No IsFullyValid / parseAndValidatePubKey / pubkey-validation reference
    // in the parse path.
    try testing.expect(!contains(src, "parseAndValidatePubKey"));
    try testing.expect(!contains(src, "IsFullyValid"));
    // Storage type is [33]u8: 65-byte uncompressed keys get @memcpy'd to
    // the first 33 bytes, silently losing the y-parity sign byte.
    // The arm body explicitly does `@memcpy(&pubkey, key_data[0..33])`,
    // a 33-byte copy regardless of key_data.len.
    const arm_start = std.mem.indexOf(u8, src, "PSBT_IN_PARTIAL_SIG => {").?;
    const arm_body = src[arm_start..@min(src.len, arm_start + 400)];
    try testing.expect(contains(arm_body, "@memcpy(&pubkey, key_data[0..33])"));
}

// ===========================================================================
// G6 — `PSBT_IN_PARTIAL_SIG` value passes `CheckSignatureEncoding`
// Status: MISSING (BUG-7). No DER-encoding check on the partial-sig value.
// ===========================================================================
test "w137 G6: partial_sig value not DER-encoding-validated (BUG-7)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Core string: "Signature is not a valid encoding".
    try testing.expect(!contains(src, "Signature is not a valid encoding"));
    // No call to a DER-check helper in psbt.zig's parse arms.
    try testing.expect(!contains(src, "checkSignatureEncoding"));
    try testing.expect(!contains(src, "CheckSignatureEncoding"));
    // Also no flag constants imported into psbt.zig.
    try testing.expect(!contains(src, "SCRIPT_VERIFY_DERSIG"));
    try testing.expect(!contains(src, "SCRIPT_VERIFY_STRICTENC"));
}

// ===========================================================================
// G7 — `PSBT_GLOBAL_XPUB` (0x01) parsed AND serialized
// Status: MISSING (BUG-8). Parsed-as-unknown, never emitted.
// ===========================================================================
test "w137 G7: PSBT_GLOBAL_XPUB neither parsed nor serialized (BUG-8)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Constant declared.
    try testing.expect(contains(src, "PSBT_GLOBAL_XPUB: u8 = 0x01"));
    // But NO case arm references PSBT_GLOBAL_XPUB in deserialize. The
    // explicit TODO comment is still in serializeGlobalMap.
    try testing.expect(contains(src, "TODO: Serialize xpubs"));
    // The constant is referenced only in the constant declaration; never
    // matched in any switch arm.
    var hits: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, "PSBT_GLOBAL_XPUB")) |p| {
        hits += 1;
        i = p + 1;
    }
    // The only hit is the const declaration. (If the parser/serializer
    // ever wire up, this jumps to >= 3.)
    try testing.expectEqual(@as(usize, 1), hits);
}

// ===========================================================================
// G8 — `PSBT_{IN,OUT}_PROPRIETARY` (0xFC) parsed AND serialized
// Status: MISSING (BUG-9). Falls into `unknown` bucket.
// ===========================================================================
test "w137 G8: proprietary key type not structurally parsed (BUG-9)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // The constants are declared.
    try testing.expect(contains(src, "PSBT_IN_PROPRIETARY: u8 = 0xFC"));
    try testing.expect(contains(src, "PSBT_OUT_PROPRIETARY: u8 = 0xFC"));
    // But no PSBTProprietary / m_proprietary struct exists.
    try testing.expect(!contains(src, "PSBTProprietary"));
    try testing.expect(!contains(src, "PsbtProprietary"));
    try testing.expect(!contains(src, "m_proprietary"));
    try testing.expect(!contains(src, "proprietary: std.ArrayList"));
    // The constants are NOT case-matched in any parse arm.
    // Count occurrences — should be exactly 1 each (declaration only).
    var hits_in: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, "PSBT_IN_PROPRIETARY")) |p| {
        hits_in += 1;
        i = p + 1;
    }
    try testing.expectEqual(@as(usize, 1), hits_in);
    var hits_out: usize = 0;
    i = 0;
    while (std.mem.indexOfPos(u8, src, i, "PSBT_OUT_PROPRIETARY")) |p| {
        hits_out += 1;
        i = p + 1;
    }
    try testing.expectEqual(@as(usize, 1), hits_out);
}

// ===========================================================================
// G9 — Input-side MuSig2 fields (0x1a/0x1b/0x1c) parsed AND serialized
// Status: MISSING (BUG-10). NONE of the three constants are even defined.
// ===========================================================================
test "w137 G9: input-side MuSig2 BIP-373 fields entirely absent (BUG-10)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // None of the three input-side MuSig2 constants are defined.
    try testing.expect(!contains(src, "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS"));
    try testing.expect(!contains(src, "PSBT_IN_MUSIG2_PUB_NONCE"));
    try testing.expect(!contains(src, "PSBT_IN_MUSIG2_PARTIAL_SIG"));
    // No corresponding field on PsbtInput.
    try testing.expect(!contains(src, "musig2_pubnonces"));
    try testing.expect(!contains(src, "musig2_partial_sigs"));
    // ...even though OUTPUT-side participants ARE supported (the asymmetry).
    try testing.expect(contains(src, "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS"));
}

// ===========================================================================
// G10 — `PSBT_OUT_TAP_TREE` depth+leaf-ver+builder validated
// Status: MISSING (BUG-11). Stored as raw bytes with no validation.
// ===========================================================================
test "w137 G10: tap_tree stored as raw bytes, no depth/leaf-ver/builder check (BUG-11)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // The field type is `?[]const u8` — raw bytes.
    try testing.expect(contains(src, "tap_tree: ?[]const u8 = null"));
    // No depth / leaf-ver / TaprootBuilder.IsComplete check.
    try testing.expect(!contains(src, "TAPROOT_CONTROL_MAX_NODE_COUNT"));
    try testing.expect(!contains(src, "TAPROOT_LEAF_MASK"));
    try testing.expect(!contains(src, "TaprootBuilder"));
    try testing.expect(!contains(src, "builder.IsComplete"));
}

// ===========================================================================
// G11 — BIP-371 output fields (TAP_BIP32, MUSIG2) serialized on wire
// Status: MISSING (BUG-12). Parsed but not emitted.
// ===========================================================================
test "w137 G11: BIP-371 output fields parsed but not serialized (BUG-12)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Parser handles them.
    const parse_out_start = std.mem.indexOf(u8, src, "fn parseOutputMap").?;
    const parse_out_end = std.mem.indexOf(u8, src, "fn cloneTransaction").?;
    const parse_out_body = src[parse_out_start..parse_out_end];
    try testing.expect(contains(parse_out_body, "PSBT_OUT_TAP_INTERNAL_KEY"));
    try testing.expect(contains(parse_out_body, "PSBT_OUT_TAP_TREE"));
    try testing.expect(contains(parse_out_body, "PSBT_OUT_TAP_BIP32_DERIVATION"));
    try testing.expect(contains(parse_out_body, "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS"));

    // But serializer doesn't.
    const ser_out_start = std.mem.indexOf(u8, src, "fn serializeOutputMap").?;
    const ser_out_end = std.mem.indexOfPos(u8, src, ser_out_start, "fn writeKeyValue").?;
    const ser_out_body = src[ser_out_start..ser_out_end];
    try testing.expect(!contains(ser_out_body, "PSBT_OUT_TAP_INTERNAL_KEY"));
    try testing.expect(!contains(ser_out_body, "PSBT_OUT_TAP_TREE"));
    try testing.expect(!contains(ser_out_body, "PSBT_OUT_TAP_BIP32_DERIVATION"));
    try testing.expect(!contains(ser_out_body, "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS"));
}

// ===========================================================================
// G12 — BIP-371 input-side taproot fields serialized on wire
// Status: MISSING (BUG-13). Parsed but not emitted.
// ===========================================================================
test "w137 G12: BIP-371 input fields parsed but not serialized (BUG-13)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Parser arms exist for all six input-side taproot fields.
    const parse_in_start = std.mem.indexOf(u8, src, "fn parseInputMap").?;
    const parse_in_end = std.mem.indexOf(u8, src, "fn parseOutputMap").?;
    const parse_in_body = src[parse_in_start..parse_in_end];
    try testing.expect(contains(parse_in_body, "PSBT_IN_TAP_KEY_SIG"));
    try testing.expect(contains(parse_in_body, "PSBT_IN_TAP_SCRIPT_SIG"));
    try testing.expect(contains(parse_in_body, "PSBT_IN_TAP_LEAF_SCRIPT"));
    try testing.expect(contains(parse_in_body, "PSBT_IN_TAP_BIP32_DERIVATION"));
    try testing.expect(contains(parse_in_body, "PSBT_IN_TAP_INTERNAL_KEY"));
    try testing.expect(contains(parse_in_body, "PSBT_IN_TAP_MERKLE_ROOT"));

    // But serializer has NO branch for any of them.
    const ser_in_start = std.mem.indexOf(u8, src, "fn serializeInputMap").?;
    const ser_in_end = std.mem.indexOfPos(u8, src, ser_in_start, "fn serializeOutputMap").?;
    const ser_in_body = src[ser_in_start..ser_in_end];
    try testing.expect(!contains(ser_in_body, "PSBT_IN_TAP_KEY_SIG"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_TAP_SCRIPT_SIG"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_TAP_LEAF_SCRIPT"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_TAP_BIP32_DERIVATION"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_TAP_INTERNAL_KEY"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_TAP_MERKLE_ROOT"));
}

// ===========================================================================
// G13 — Hash preimage maps parsed AND serialized
// Status: MISSING (BUG-14). Declared+init+deinit but NEVER populated.
// "declare-init-deinit-but-never-populate" universal pattern.
// ===========================================================================
test "w137 G13: hash preimage maps are dead storage (BUG-14)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Fields exist on PsbtInput.
    try testing.expect(contains(src, "ripemd160_preimages: std.AutoHashMap"));
    try testing.expect(contains(src, "sha256_preimages: std.AutoHashMap"));
    try testing.expect(contains(src, "hash160_preimages: std.AutoHashMap"));
    try testing.expect(contains(src, "hash256_preimages: std.AutoHashMap"));

    // Constants exist (0x0A..0x0D).
    try testing.expect(contains(src, "PSBT_IN_RIPEMD160: u8 = 0x0A"));
    try testing.expect(contains(src, "PSBT_IN_SHA256: u8 = 0x0B"));
    try testing.expect(contains(src, "PSBT_IN_HASH160: u8 = 0x0C"));
    try testing.expect(contains(src, "PSBT_IN_HASH256: u8 = 0x0D"));

    // But NO parse arm references the constants.
    const parse_in_start = std.mem.indexOf(u8, src, "fn parseInputMap").?;
    const parse_in_end = std.mem.indexOf(u8, src, "fn parseOutputMap").?;
    const parse_in_body = src[parse_in_start..parse_in_end];
    try testing.expect(!contains(parse_in_body, "PSBT_IN_RIPEMD160"));
    try testing.expect(!contains(parse_in_body, "PSBT_IN_SHA256"));
    try testing.expect(!contains(parse_in_body, "PSBT_IN_HASH160"));
    try testing.expect(!contains(parse_in_body, "PSBT_IN_HASH256"));

    // And NO serializer arm references them either.
    const ser_in_start = std.mem.indexOf(u8, src, "fn serializeInputMap").?;
    const ser_in_end = std.mem.indexOfPos(u8, src, ser_in_start, "fn serializeOutputMap").?;
    const ser_in_body = src[ser_in_start..ser_in_end];
    try testing.expect(!contains(ser_in_body, "PSBT_IN_RIPEMD160"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_SHA256"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_HASH160"));
    try testing.expect(!contains(ser_in_body, "PSBT_IN_HASH256"));
}

// ===========================================================================
// G14 — `PSBT_GLOBAL_PROPRIETARY` parsed AND serialized
// Status: MISSING (BUG-15). Falls into the global `unknown` bucket.
// ===========================================================================
test "w137 G14: global proprietary key type not structurally parsed (BUG-15)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    try testing.expect(contains(src, "PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC"));
    // No structured parser, no `m_proprietary` field on Psbt struct.
    try testing.expect(!contains(src, "proprietary: std.ArrayList(PsbtProprietary)"));
    var hits: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, "PSBT_GLOBAL_PROPRIETARY")) |p| {
        hits += 1;
        i = p + 1;
    }
    try testing.expectEqual(@as(usize, 1), hits); // declaration only
}

// ===========================================================================
// G15 — BIP32 derivation accepts both 33-byte and 65-byte pubkeys
// Status: DIVERGE (BUG-16). 65-byte uncompressed rejected.
// ===========================================================================
test "w137 G15: BIP32 derivation rejects 65-byte uncompressed pubkeys (BUG-16)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // The check is "key_data.len != 33", rejecting 65-byte uncompressed
    // pubkeys outright.
    const parse_in_start = std.mem.indexOf(u8, src, "PSBT_IN_BIP32_DERIVATION => {").?;
    const slice_end = @min(src.len, parse_in_start + 400);
    const arm_body = src[parse_in_start..slice_end];
    try testing.expect(contains(arm_body, "if (key_data.len != 33)"));
    // Should be `(key_data.len != 33 and key_data.len != 65)` after fix.
    try testing.expect(!contains(arm_body, "key_data.len != 65"));

    // Same for output.
    const parse_out_start = std.mem.indexOf(u8, src, "PSBT_OUT_BIP32_DERIVATION => {").?;
    const out_slice_end = @min(src.len, parse_out_start + 400);
    const out_arm = src[parse_out_start..out_slice_end];
    try testing.expect(contains(out_arm, "if (key_data.len != 33)"));
}

// ===========================================================================
// G16 — HD key path length is multiple of 4 AND nonzero
// Status: DIVERGE (BUG-17). Error semantics differ — clearbit's bound is
// `value.len < 4` (rejecting len=0 with InvalidValueLength), Core rejects
// `length == 0` with the specific "Invalid length for HD key path" string.
// ===========================================================================
test "w137 G16: HD key path empty-path semantics differ from Core (BUG-17)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // clearbit uses `value.len < 4 or (value.len - 4) % 4 != 0` which is
    // approximately right but reports a generic InvalidValueLength on
    // length=0, not a domain-specific "Invalid length for HD key path".
    try testing.expect(contains(src, "if (value.len < 4 or (value.len - 4) % 4 != 0)"));
    try testing.expect(!contains(src, "Invalid length for HD key path"));
}

// ===========================================================================
// G17 — `MAX_FILE_SIZE_PSBT` enforced on `deserialize`
// Status: MISSING (BUG-18). Constant declared but never referenced.
// ===========================================================================
test "w137 G17: MAX_PSBT_SIZE declared but never enforced (BUG-18)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    try testing.expect(contains(src, "MAX_PSBT_SIZE: usize = 100_000_000"));
    // Find the deserialize function — assert no MAX_PSBT_SIZE check.
    const deser_start = std.mem.indexOf(u8, src, "pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !Psbt").?;
    const deser_end = std.mem.indexOfPos(u8, src, deser_start, "// ====").?;
    const deser_body = src[deser_start..deser_end];
    try testing.expect(!contains(deser_body, "MAX_PSBT_SIZE"));
    // And fromBase64 doesn't bound the base64 string length either.
    const fb64_start = std.mem.indexOf(u8, src, "pub fn fromBase64").?;
    const fb64_end = std.mem.indexOfPos(u8, src, fb64_start, "// ====").?;
    const fb64_body = src[fb64_start..fb64_end];
    try testing.expect(!contains(fb64_body, "MAX_PSBT_SIZE"));
}

// ===========================================================================
// G18 — Missing separator at EOF maps to MissingSeparator not generic EndOfStream
// Status: DIVERGE (BUG-19). Variant declared but never raised.
// ===========================================================================
test "w137 G18: MissingSeparator error variant is dead enum (BUG-19)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Variant declared.
    try testing.expect(contains(src, "MissingSeparator,"));
    // But never raised.
    try testing.expect(!contains(src, "return PsbtError.MissingSeparator"));
    try testing.expect(!contains(src, "return error.MissingSeparator"));
}

// ===========================================================================
// G19 — `PSBT_IN_SIGHASH` value range-checked
// Status: MISSING (BUG-20). Any u32 accepted.
// ===========================================================================
test "w137 G19: sighash_type accepts any u32 (BUG-20)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Find the PSBT_IN_SIGHASH arm.
    const arm_start = std.mem.indexOf(u8, src, "PSBT_IN_SIGHASH => {").?;
    const arm_body = src[arm_start..@min(src.len, arm_start + 400)];

    // Only check is value.len == 4; no range check on the u32.
    try testing.expect(contains(arm_body, "if (value.len != 4)"));
    // No SIGHASH_ALL / SIGHASH_NONE / SIGHASH_SINGLE / SIGHASH_DEFAULT /
    // SIGHASH_ANYONECANPAY range gate.
    try testing.expect(!contains(arm_body, "SIGHASH_ALL"));
    try testing.expect(!contains(arm_body, "SIGHASH_DEFAULT"));
    try testing.expect(!contains(arm_body, "SIGHASH_ANYONECANPAY"));
}

// ===========================================================================
// G20 — `RemoveUnnecessaryTransactions` drops non_witness_utxo on segwit-v1
// Status: MISSING (BUG-21). Helper absent.
// ===========================================================================
test "w137 G20: RemoveUnnecessaryTransactions helper absent (BUG-21)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    try testing.expect(!contains(src, "RemoveUnnecessaryTransactions"));
    try testing.expect(!contains(src, "removeUnnecessaryTransactions"));
    try testing.expect(!contains(src, "remove_unnecessary_transactions"));
}

// ===========================================================================
// G21 — `PSBTInputSignedAndVerified` runs script interpreter
// Status: MISSING (BUG-22). Only structural `isFinalized` exists.
// ===========================================================================
test "w137 G21: no PSBTInputSignedAndVerified analog (BUG-22)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    try testing.expect(contains(src, "pub fn isFinalized(self: *const PsbtInput) bool"));
    try testing.expect(!contains(src, "isInputSignedAndVerified"));
    try testing.expect(!contains(src, "PSBTInputSignedAndVerified"));
    try testing.expect(!contains(src, "signedAndVerified"));
}

// ===========================================================================
// G22 — `analyzepsbt` per-input `next` role + estimated_vsize
// Status: DIVERGE (BUG-23).
// ===========================================================================
test "w137 G22: analyzepsbt missing per-input next + estimated_vsize (BUG-23)" {
    const allocator = testing.allocator;
    const src_psbt = try loadSrc(allocator, "psbt");
    defer allocator.free(src_psbt);
    const src_rpc = try loadSrc(allocator, "rpc");
    defer allocator.free(src_rpc);

    // psbt.zig analyze returns a single top-level next_role, no per-input role.
    try testing.expect(contains(src_psbt, "next_role: []const u8"));
    // No `per_input_next` / per-input `next` field on AnalysisResult.
    try testing.expect(!contains(src_psbt, "per_input_next"));
    // estimated_vsize is explicitly null in the analyze result.
    try testing.expect(contains(src_psbt, ".estimated_vsize = null"));

    // handleAnalyzePsbt in rpc.zig doesn't emit a per-input next.
    const arm_start = std.mem.indexOf(u8, src_rpc, "fn handleAnalyzePsbt").?;
    const arm_end = std.mem.indexOfPos(u8, src_rpc, arm_start, "fn handleCombinePsbt").?;
    const arm_body = src_rpc[arm_start..arm_end];
    // Each input gets has_utxo + is_final, but no per-input "next".
    try testing.expect(contains(arm_body, "has_utxo"));
    try testing.expect(contains(arm_body, "is_final"));
    try testing.expect(!contains(arm_body, "\"next\""));
}

// ===========================================================================
// G23 — `joinpsbts` RPC
// Status: MISSING (BUG-24). Dispatch arm absent.
// ===========================================================================
test "w137 G23: joinpsbts RPC not dispatched (BUG-24)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    try testing.expect(!contains(src, "\"joinpsbts\""));
    try testing.expect(!contains(src, "handleJoinPsbts"));
    try testing.expect(!contains(src, "joinPsbts"));
}

// ===========================================================================
// G24 — `utxoupdatepsbt` RPC
// Status: MISSING (BUG-25).
// ===========================================================================
test "w137 G24: utxoupdatepsbt RPC not dispatched (BUG-25)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    try testing.expect(!contains(src, "\"utxoupdatepsbt\""));
    try testing.expect(!contains(src, "handleUtxoUpdatePsbt"));
}

// ===========================================================================
// G25 — `walletprocesspsbt` RPC
// Status: MISSING (BUG-26).
// ===========================================================================
test "w137 G25: walletprocesspsbt RPC not dispatched (BUG-26)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    try testing.expect(!contains(src, "\"walletprocesspsbt\""));
    try testing.expect(!contains(src, "handleWalletProcessPsbt"));
    // walletcreatefundedpsbt + psbtbumpfee DO exist — confirm.
    try testing.expect(contains(src, "\"walletcreatefundedpsbt\""));
    try testing.expect(contains(src, "\"psbtbumpfee\""));
}

// ===========================================================================
// G26 — `descriptorprocesspsbt` RPC
// Status: MISSING (BUG-27).
// ===========================================================================
test "w137 G26: descriptorprocesspsbt RPC not dispatched (BUG-27)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "rpc");
    defer allocator.free(src);

    try testing.expect(!contains(src, "\"descriptorprocesspsbt\""));
    try testing.expect(!contains(src, "handleDescriptorProcessPsbt"));
}

// ===========================================================================
// G27 — `extract()` validates signed-and-verified state
// Status: MISSING (BUG-28). Only `isComplete()` check.
// ===========================================================================
test "w137 G27: extract() only structurally validates (BUG-28)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    const arm_start = std.mem.indexOf(u8, src, "pub fn extract(self: *Psbt) !types.Transaction").?;
    const arm_end = std.mem.indexOfPos(u8, src, arm_start, "// ====").?;
    const arm_body = src[arm_start..arm_end];

    // Only check is isComplete().
    try testing.expect(contains(arm_body, "self.isComplete()"));
    // No call to a script-verify helper inside extract.
    try testing.expect(!contains(arm_body, "verifyScript"));
    try testing.expect(!contains(arm_body, "VerifyScript"));
    try testing.expect(!contains(arm_body, "isInputSignedAndVerified"));
}

// ===========================================================================
// G28 — `Merge` refuses PSBTs with different `tx.GetHash()`
// Status: DIVERGE (BUG-29). Only input-count check.
// ===========================================================================
test "w137 G28: mergeFrom doesn't verify same-underlying-tx (BUG-29)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    const arm_start = std.mem.indexOf(u8, src, "pub fn mergeFrom(self: *Psbt, other: *const Psbt) !void").?;
    const arm_end = std.mem.indexOfPos(u8, src, arm_start, "/// Clone this PSBT").?;
    const arm_body = src[arm_start..arm_end];

    // Only check is input/output count match.
    try testing.expect(contains(arm_body, "if (self.inputs.len != other.inputs.len"));
    // No tx-hash comparison in mergeFrom.
    try testing.expect(!contains(arm_body, "writeTransactionNoWitness"));
    try testing.expect(!contains(arm_body, "GetHash"));
    try testing.expect(!contains(arm_body, "self.tx.hash"));
}

// ===========================================================================
// G28 behavioral — two distinct-txid PSBTs combine silently
// ===========================================================================
test "w137 G28b: combine merges PSBTs with different prevout hashes silently (BUG-29)" {
    const allocator = testing.allocator;

    // Two PSBTs with same input count but different prevout hashes.
    const inputs1 = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};
    const inputs2 = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const outputs = [_]types.TxOut{.{
        .value = 50000,
        .script_pubkey = &spk,
    }};

    const tx1 = types.Transaction{
        .version = 2,
        .inputs = &inputs1,
        .outputs = &outputs,
        .lock_time = 0,
    };
    const tx2 = types.Transaction{
        .version = 2,
        .inputs = &inputs2,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var p1 = try psbt.Psbt.create(allocator, tx1);
    defer p1.deinit();
    var p2 = try psbt.Psbt.create(allocator, tx2);
    defer p2.deinit();

    // mergeFrom silently succeeds despite different prevout.hash.
    // Core's Merge would return false here.
    p1.mergeFrom(&p2) catch |e| {
        std.debug.print("\n(NOTE: clearbit now rejects mismatched-tx merge: {}; flip BUG-29 test)\n", .{e});
        return error.SkipZigTest;
    };
    // No assertion crash → bug confirmed (silent acceptance).
}

// ===========================================================================
// G29 — `Psbt.IsNull()` predicate
// Status: MISSING (BUG-30).
// ===========================================================================
test "w137 G29: Psbt has no IsNull / isNull predicate (BUG-30)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    try testing.expect(!contains(src, "pub fn isNull(self: *const Psbt)"));
    try testing.expect(!contains(src, "pub fn IsNull"));
}

// ===========================================================================
// G30 — Any BIP-370 (PSBT v2) wire types defined
// Status: MISSING (BUG-2) — informational; intentional parity with Core
// which also has PSBT_HIGHEST_VERSION = 0.
// ===========================================================================
test "w137 G30: zero BIP-370 wire types defined (BUG-2, info)" {
    const allocator = testing.allocator;
    const src = try loadSrc(allocator, "psbt");
    defer allocator.free(src);

    // Core's PSBT_HIGHEST_VERSION = 0 (psbt.h:80); clearbit matches.
    try testing.expect(contains(src, "PSBT_HIGHEST_VERSION: u32 = 0"));

    // None of the 12 BIP-370 v2 wire types are defined.
    try testing.expect(!contains(src, "PSBT_GLOBAL_TX_VERSION"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_FALLBACK_LOCKTIME"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_INPUT_COUNT"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_OUTPUT_COUNT"));
    try testing.expect(!contains(src, "PSBT_GLOBAL_TX_MODIFIABLE"));
    try testing.expect(!contains(src, "PSBT_IN_PREVIOUS_TXID"));
    try testing.expect(!contains(src, "PSBT_IN_OUTPUT_INDEX"));
    try testing.expect(!contains(src, "PSBT_IN_SEQUENCE"));
    try testing.expect(!contains(src, "PSBT_IN_REQUIRED_TIME_LOCKTIME"));
    try testing.expect(!contains(src, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME"));
    try testing.expect(!contains(src, "PSBT_OUT_AMOUNT"));
    try testing.expect(!contains(src, "PSBT_OUT_SCRIPT"));
}
