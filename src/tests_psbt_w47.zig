//! W47 regression tests for the PSBT finalizer.
//!
//! Closes the W42-A diagnostic on `tools/psbt-multi-input-test.sh`:
//! clearbit's `finalizeP2WSH` was a TODO stub and `finalizeP2SH`'s only
//! real branch was P2SH-P2WPKH, so multi-input fixtures whose inputs
//! were P2SH-multisig + P2SH-P2WSH-multisig couldn't finalize. The two
//! gaps surveyed at W42-A (with file/line cites in the task spec):
//!
//!   1. `finalizeP2WSH` did nothing → bare P2WSH-multisig inputs stayed
//!      unfinalized.
//!   2. `finalizeP2SH` had no legacy-multisig branch and no P2SH-P2WSH
//!      branch → those input shapes also couldn't reach finalized.
//!   3. `partial_sigs` and `bip32_derivation` lived in `std.AutoHashMap`
//!      with hash-table iteration order — the serialized bytes were
//!      non-deterministic between runs / combine permutations, tripping
//!      the cross-impl T2 round-trip assertion.
//!
//! Reference: bitcoin-core/src/script/sign.cpp ProduceSignature for the
//! sig-vector ordering rule (script-pubkey order, NOT insertion order),
//! and bitcoin-core/src/psbt.h:269-270 for the std::map storage choice
//! that pins the emit order.
//!
//! The tests here use synthetic inputs — they don't exercise real
//! ECDSA, only the wire-shape contract the finalizer is responsible for.

const std = @import("std");
const psbt_mod = @import("psbt.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

// ---------------------------------------------------------------------------
// Helpers — synthetic 2-of-3 multisig fixtures
// ---------------------------------------------------------------------------

/// Three deterministic-looking 33-byte compressed pubkeys. Asymmetric per
/// W32-B (no palindromes / repeated bytes across pubkeys) and the W46-4
/// ouroboros lesson (HASH160 order ≠ raw-byte order — the test below
/// confirms the order does flip, so the sort-key choice is exercised).
const PK_A: [33]u8 = blk: {
    var p: [33]u8 = .{0x02} ++ ([_]u8{0xaa} ** 32);
    p[1] = 0x11;
    p[2] = 0x22;
    p[3] = 0x33;
    break :blk p;
};
const PK_B: [33]u8 = blk: {
    var p: [33]u8 = .{0x03} ++ ([_]u8{0xbb} ** 32);
    p[1] = 0x44;
    p[2] = 0x55;
    p[3] = 0x66;
    break :blk p;
};
const PK_C: [33]u8 = blk: {
    var p: [33]u8 = .{0x02} ++ ([_]u8{0xcc} ** 32);
    p[1] = 0x77;
    p[2] = 0x88;
    p[3] = 0x99;
    break :blk p;
};

/// Build an `OP_M <pk1> <pk2> ... <pkN> OP_N OP_CHECKMULTISIG` script for
/// 2-of-3 with the three pubkeys above in script order [A, B, C].
fn build2of3MultisigScript() [105]u8 {
    var out: [105]u8 = undefined;
    out[0] = 0x52; // OP_2
    out[1] = 0x21; // push 33
    @memcpy(out[2..35], &PK_A);
    out[35] = 0x21;
    @memcpy(out[36..69], &PK_B);
    out[69] = 0x21;
    @memcpy(out[70..103], &PK_C);
    out[103] = 0x53; // OP_3
    out[104] = 0xae; // OP_CHECKMULTISIG
    return out;
}

fn buildP2SHScriptPubKey(redeem: []const u8) [23]u8 {
    const h = crypto.hash160(redeem);
    var out: [23]u8 = undefined;
    out[0] = 0xa9;
    out[1] = 0x14;
    @memcpy(out[2..22], &h);
    out[22] = 0x87;
    return out;
}

fn buildP2WSHScriptPubKey(witness_script: []const u8) [34]u8 {
    const h = crypto.sha256(witness_script);
    var out: [34]u8 = undefined;
    out[0] = 0x00;
    out[1] = 0x20;
    @memcpy(out[2..34], &h);
    return out;
}

/// Outer P2SH redeem for P2SH-P2WSH: `OP_0 PUSH32 sha256(witness_script)`.
fn buildP2SHP2WSHRedeem(witness_script: []const u8) [34]u8 {
    return buildP2WSHScriptPubKey(witness_script);
}

fn buildUnsignedTx() types.Transaction {
    const inputs_static = struct {
        const arr = [_]types.TxIn{.{
            .previous_output = .{ .hash = [_]u8{0xab} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFD,
            .witness = &[_][]const u8{},
        }};
    };
    const outputs_static = struct {
        const spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x33} ** 20;
        const arr = [_]types.TxOut{.{
            .value = 90_000,
            .script_pubkey = &spk,
        }};
    };
    return types.Transaction{
        .version = 2,
        .inputs = &inputs_static.arr,
        .outputs = &outputs_static.arr,
        .lock_time = 0,
    };
}

// ---------------------------------------------------------------------------
// Vector 1: bare P2WSH-multisig finalizer
// ---------------------------------------------------------------------------

test "W47 finalizeP2WSH: 2-of-3 multisig emits witness in script order" {
    const allocator = std.testing.allocator;

    const witness_script = build2of3MultisigScript();
    const spk = buildP2WSHScriptPubKey(&witness_script);

    const tx = buildUnsignedTx();
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &spk });
    try psbt.addInputWitnessScript(0, &witness_script);

    // Provide partial signatures for B and C (skipping A) — the finalizer
    // must pick them in script order [B, C], NOT alphabetic-by-pubkey,
    // NOT by HASH160 order, NOT by insertion order.
    const sig_b = [_]u8{0xb1} ** 71;
    const sig_c = [_]u8{0xc1} ** 72;

    // Insert C first to make sure insertion order is NOT the rule.
    try psbt.addPartialSig(0, PK_C, &sig_c);
    try psbt.addPartialSig(0, PK_B, &sig_b);

    try psbt.finalizeInput(0);

    // Witness must be exactly: [empty (OP_0 dummy), sig_b, sig_c, witness_script]
    try std.testing.expect(psbt.inputs[0].final_script_witness != null);
    const w = psbt.inputs[0].final_script_witness.?;
    try std.testing.expectEqual(@as(usize, 4), w.len);
    try std.testing.expectEqual(@as(usize, 0), w[0].len); // empty dummy
    try std.testing.expectEqualSlices(u8, &sig_b, w[1]);
    try std.testing.expectEqualSlices(u8, &sig_c, w[2]);
    try std.testing.expectEqualSlices(u8, &witness_script, w[3]);

    // P2WSH has no scriptSig.
    try std.testing.expect(psbt.inputs[0].final_script_sig == null);

    // Producer fields must be cleared after finalize (W47 cleanup).
    try std.testing.expectEqual(@as(u32, 0), psbt.inputs[0].partial_sigs.count());
    try std.testing.expect(psbt.inputs[0].witness_script == null);
}

test "W47 finalizeP2WSH: missing m sigs leaves input unfinalized" {
    const allocator = std.testing.allocator;

    const witness_script = build2of3MultisigScript();
    const spk = buildP2WSHScriptPubKey(&witness_script);

    const tx = buildUnsignedTx();
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &spk });
    try psbt.addInputWitnessScript(0, &witness_script);

    // Only one sig — 2-of-3 needs two.
    const sig_a = [_]u8{0xa1} ** 71;
    try psbt.addPartialSig(0, PK_A, &sig_a);

    try psbt.finalizeInput(0);

    // No final_script_witness — but no error either (matches Core's
    // "complete:false" silent path).
    try std.testing.expect(psbt.inputs[0].final_script_witness == null);
    try std.testing.expect(psbt.inputs[0].final_script_sig == null);
    try std.testing.expect(!psbt.inputs[0].isFinalized());

    // Producer fields preserved so a later combine() can complete.
    try std.testing.expectEqual(@as(u32, 1), psbt.inputs[0].partial_sigs.count());
    try std.testing.expect(psbt.inputs[0].witness_script != null);
}

// ---------------------------------------------------------------------------
// Vector 2: legacy P2SH-multisig finalizer
// ---------------------------------------------------------------------------

test "W47 finalizeP2SH (legacy multisig): 2-of-3 emits scriptSig in script order" {
    const allocator = std.testing.allocator;

    const redeem_script = build2of3MultisigScript();
    const spk = buildP2SHScriptPubKey(&redeem_script);

    const tx = buildUnsignedTx();
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &spk });
    try psbt.addInputRedeemScript(0, &redeem_script);

    const sig_a = [_]u8{0xa1} ** 71;
    const sig_c = [_]u8{0xc1} ** 72;

    // Insert in non-script order — finalizer must still emit [A, C].
    try psbt.addPartialSig(0, PK_C, &sig_c);
    try psbt.addPartialSig(0, PK_A, &sig_a);

    try psbt.finalizeInput(0);

    try std.testing.expect(psbt.inputs[0].final_script_sig != null);
    try std.testing.expect(psbt.inputs[0].final_script_witness == null);

    const ss = psbt.inputs[0].final_script_sig.?;
    // Expected: 0x00 || push(sig_a) || push(sig_c) || push(redeem_script)
    //   1 + (1+71) + (1+72) + (3+105) = 254
    //   redeem_script is 105 bytes → OP_PUSHDATA1 0x69 = 0x4c 0x69
    try std.testing.expectEqual(@as(u8, 0x00), ss[0]);
    try std.testing.expectEqual(@as(u8, 71), ss[1]);
    try std.testing.expectEqualSlices(u8, &sig_a, ss[2..73]);
    try std.testing.expectEqual(@as(u8, 72), ss[73]);
    try std.testing.expectEqualSlices(u8, &sig_c, ss[74..146]);
    try std.testing.expectEqual(@as(u8, 0x4c), ss[146]); // OP_PUSHDATA1
    try std.testing.expectEqual(@as(u8, 105), ss[147]);
    try std.testing.expectEqualSlices(u8, &redeem_script, ss[148..253]);
    try std.testing.expectEqual(@as(usize, 253), ss.len);
}

test "W47 finalizeP2SH (legacy multisig): forged redeem still fails W31 commitment" {
    const allocator = std.testing.allocator;

    // On-chain commits to redeem_a (script with PK_A,B,C in that order).
    const redeem_a = build2of3MultisigScript();
    const spk = buildP2SHScriptPubKey(&redeem_a);

    // PSBT carries forged redeem_b — same pubkeys but reordered → different hash160.
    var redeem_b: [105]u8 = redeem_a;
    @memcpy(redeem_b[2..35], &PK_C); // swap PK_A and PK_C
    @memcpy(redeem_b[70..103], &PK_A);
    try std.testing.expect(!std.mem.eql(u8, &crypto.hash160(&redeem_a), &crypto.hash160(&redeem_b)));

    const tx = buildUnsignedTx();
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &spk });
    try psbt.addInputRedeemScript(0, &redeem_b);

    const sig_a = [_]u8{0xa1} ** 71;
    const sig_b = [_]u8{0xb1} ** 71;
    try psbt.addPartialSig(0, PK_A, &sig_a);
    try psbt.addPartialSig(0, PK_B, &sig_b);

    const result = psbt.finalizeInput(0);
    try std.testing.expectError(psbt_mod.PsbtError.RedeemScriptCommitmentMismatch, result);
}

// ---------------------------------------------------------------------------
// Vector 3: P2SH-P2WSH-multisig finalizer
// ---------------------------------------------------------------------------

test "W47 finalizeP2SH-P2WSH: 2-of-3 emits both scriptSig and witness" {
    const allocator = std.testing.allocator;

    const witness_script = build2of3MultisigScript();
    const redeem_script = buildP2SHP2WSHRedeem(&witness_script); // OP_0 PUSH32 sha256(ws)
    const spk = buildP2SHScriptPubKey(&redeem_script);

    const tx = buildUnsignedTx();
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &spk });
    try psbt.addInputRedeemScript(0, &redeem_script);
    try psbt.addInputWitnessScript(0, &witness_script);

    const sig_a = [_]u8{0xa1} ** 71;
    const sig_b = [_]u8{0xb1} ** 71;
    try psbt.addPartialSig(0, PK_B, &sig_b);
    try psbt.addPartialSig(0, PK_A, &sig_a);

    try psbt.finalizeInput(0);

    // scriptSig: single push of redeem_script (34 bytes → direct push 0x22).
    try std.testing.expect(psbt.inputs[0].final_script_sig != null);
    const ss = psbt.inputs[0].final_script_sig.?;
    try std.testing.expectEqual(@as(usize, 35), ss.len);
    try std.testing.expectEqual(@as(u8, 0x22), ss[0]); // push 34
    try std.testing.expectEqualSlices(u8, &redeem_script, ss[1..35]);

    // Witness: [empty, sig_a, sig_b, witness_script]
    try std.testing.expect(psbt.inputs[0].final_script_witness != null);
    const w = psbt.inputs[0].final_script_witness.?;
    try std.testing.expectEqual(@as(usize, 4), w.len);
    try std.testing.expectEqual(@as(usize, 0), w[0].len);
    try std.testing.expectEqualSlices(u8, &sig_a, w[1]);
    try std.testing.expectEqualSlices(u8, &sig_b, w[2]);
    try std.testing.expectEqualSlices(u8, &witness_script, w[3]);

    try std.testing.expectEqual(@as(u32, 0), psbt.inputs[0].partial_sigs.count());
    try std.testing.expect(psbt.inputs[0].redeem_script == null);
    try std.testing.expect(psbt.inputs[0].witness_script == null);
}

// ---------------------------------------------------------------------------
// Vector 4: deterministic emit order for partial_sigs
// ---------------------------------------------------------------------------

test "W47 sort-on-emit: partial_sigs serialize in HASH160(pubkey) order" {
    const allocator = std.testing.allocator;

    // Build a P2WSH where finalize CANNOT complete (1-of-3 with no sigs in
    // script-pubkey order would still let some shapes finalize), so the
    // partial_sigs travel through the serializer. Use legacy P2SH-multisig
    // for the UTXO so we can leave the input unfinalized just by not
    // providing redeem_script.
    const tx = buildUnsignedTx();

    // Two PSBTs that hold the same three partial sigs but inserted in
    // opposite orders. Without sort-on-emit, AutoHashMap iteration order
    // is unstable but deterministic-per-process — we'd still see the same
    // bytes within a single run. To prove the SORT actually happens we
    // verify the absolute ordering: HASH160(PK_A) < HASH160(PK_B) <
    // HASH160(PK_C)? Compute it and assert the wire bytes follow that.
    const h_a = crypto.hash160(&PK_A);
    const h_b = crypto.hash160(&PK_B);
    const h_c = crypto.hash160(&PK_C);

    var pkeys = [_][33]u8{ PK_A, PK_B, PK_C };
    var hashes = [_][20]u8{ h_a, h_b, h_c };

    // Sort pkeys by their HASH160 — this is the order serialization MUST emit.
    // (Bubble sort is fine for n=3.)
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var j: usize = 0;
        while (j + 1 < 3 - i) : (j += 1) {
            if (std.mem.lessThan(u8, &hashes[j + 1], &hashes[j])) {
                std.mem.swap([20]u8, &hashes[j], &hashes[j + 1]);
                std.mem.swap([33]u8, &pkeys[j], &pkeys[j + 1]);
            }
        }
    }

    // Verify HASH160 order ≠ raw-pubkey-bytes order (the W46-4 lesson).
    // If this fails the test would still be valid but wouldn't prove the
    // sort key choice — make the failure mode explicit.
    var raw_sorted = [_][33]u8{ PK_A, PK_B, PK_C };
    std.sort.pdq([33]u8, &raw_sorted, {}, struct {
        fn lt(_: void, a: [33]u8, b: [33]u8) bool {
            return std.mem.lessThan(u8, &a, &b);
        }
    }.lt);
    const orders_differ = !std.mem.eql(u8, std.mem.sliceAsBytes(&pkeys), std.mem.sliceAsBytes(&raw_sorted));
    try std.testing.expect(orders_differ);

    // Now do the actual serialize check with the sigs inserted in *reverse*
    // HASH160 order to make sure storage-order is not the rule.
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Put a witness UTXO that doesn't match any finalize path (P2A — Anyone-can-spend
    // pubkey) so finalizeInput silently leaves the input alone.
    const noop_spk = [_]u8{ 0x51, 0x02, 0x4e, 0x73 }; // P2A
    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &noop_spk });

    const fake_sigs = [_][72]u8{
        [_]u8{0x01} ** 72,
        [_]u8{0x02} ** 72,
        [_]u8{0x03} ** 72,
    };
    // Insert in reverse-HASH160 order.
    var k: usize = 0;
    while (k < 3) : (k += 1) {
        const idx = 2 - k;
        try psbt.addPartialSig(0, pkeys[idx], &fake_sigs[idx]);
    }

    const wire = try psbt.serialize(allocator);
    defer allocator.free(wire);

    // Find the three PSBT_IN_PARTIAL_SIG keys (key_type 0x02) in the wire
    // bytes and confirm their associated pubkeys appear in HASH160(pubkey)
    // ascending order.
    //
    // Format per BIP-174: <compactsize keylen> <keytype byte> <key data>
    //                     <compactsize vallen> <value data>
    // For partial sig: keylen = 1+33 = 34 = 0x22, keytype = 0x02,
    // key data = 33-byte pubkey, value = sig bytes (72 here, vallen = 0x48).
    //
    // We scan for the byte sequence [0x22, 0x02] which is "keylen=34, keytype=0x02"
    // — distinctive enough since no other PSBT field combines these two.
    var found_pubkeys = std.ArrayList([33]u8).init(allocator);
    defer found_pubkeys.deinit();
    var p: usize = 0;
    while (p + 2 + 33 < wire.len) : (p += 1) {
        if (wire[p] == 0x22 and wire[p + 1] == 0x02) {
            // Sanity: next 33 bytes must be one of our pubkeys; if not, this
            // was a coincidental byte pattern — skip.
            var pk: [33]u8 = undefined;
            @memcpy(&pk, wire[p + 2 .. p + 2 + 33]);
            const is_ours = std.mem.eql(u8, &pk, &PK_A) or
                std.mem.eql(u8, &pk, &PK_B) or
                std.mem.eql(u8, &pk, &PK_C);
            if (!is_ours) continue;
            try found_pubkeys.append(pk);
        }
    }

    try std.testing.expectEqual(@as(usize, 3), found_pubkeys.items.len);
    // Each found pubkey, in order, must match `pkeys[i]` (the HASH160-sorted
    // expected order computed above).
    var idx2: usize = 0;
    while (idx2 < 3) : (idx2 += 1) {
        try std.testing.expectEqualSlices(u8, &pkeys[idx2], &found_pubkeys.items[idx2]);
    }
}
