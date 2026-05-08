//! P2WSH + P2SH-P2WSH segwit-v0 wallet tests (W29-C / Phase-2).
//!
//! Validates the W29-C closure of W19's `error.NotImplemented` P2WSH stub
//! at `wallet.zig:1208`. Three BIP-143 multisig vectors gate the wave per
//! the design doc:
//!   1. P2WSH 2-of-3 sign + verify (canonical witness order)
//!   2. P2SH-P2WSH 2-of-2 wrap (scriptSig + witness shape)
//!   3. Round-trip: signInput dispatch === manually-constructed canonical
//!      witness (parallel-impl-drift sentinel)
//!
//! Lives at `src/` so it can `@import("wallet.zig")` etc., but is wrapped
//! by `tests_wallet_segwit_v0.zig` at the project root so `@embedFile` in
//! `wallet.zig` resolves the same way it does for the W20 tests.

const std = @import("std");
const wallet_mod = @import("wallet.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an M-of-N CHECKMULTISIG witness script:
///   OP_M <33-byte pk1> ... <33-byte pkN> OP_N OP_CHECKMULTISIG
fn buildMultisigScript(
    allocator: std.mem.Allocator,
    m: u8,
    pubkeys: []const [33]u8,
) ![]u8 {
    std.debug.assert(m >= 1 and m <= 16);
    std.debug.assert(pubkeys.len >= m and pubkeys.len <= 16);
    // length = 1 (OP_M) + N * (1 + 33) + 1 (OP_N) + 1 (OP_CHECKMULTISIG)
    const total = 1 + pubkeys.len * 34 + 2;
    var out = try allocator.alloc(u8, total);
    out[0] = 0x50 + m; // OP_M
    var i: usize = 1;
    for (pubkeys) |pk| {
        out[i] = 0x21; // push 33 bytes
        @memcpy(out[i + 1 .. i + 34], &pk);
        i += 34;
    }
    out[i] = 0x50 + @as(u8, @intCast(pubkeys.len)); // OP_N
    out[i + 1] = 0xae; // OP_CHECKMULTISIG
    return out;
}

/// Import a secret into the wallet and return (key_index, compressed_pubkey).
/// We derive the compressed pubkey via the wallet itself rather than re-doing
/// the libsecp calls in this file, which would cause a dual-cImport opaque-type
/// mismatch (the wallet's `*secp256k1_context` and a local `@cImport` produce
/// the same struct under different opaque type aliases).
fn importAndPub(w: *wallet_mod.Wallet, secret: [32]u8) !struct { ki: usize, pk: [33]u8 } {
    const ki = try w.importKey(secret);
    return .{ .ki = ki, .pk = w.keys.items[ki].public_key };
}

// ---------------------------------------------------------------------------
// Vector 1: P2WSH 2-of-3 sign + verify
// ---------------------------------------------------------------------------

test "W29-C: P2WSH 2-of-3 multisig — sign + ECDSA verify each emitted sig" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();

    // Three deterministic secrets; we import all three into the wallet
    // (cheap way to get their compressed pubkeys without re-running libsecp
    // through a second @cImport) and sign with two of them.
    const k1 = try importAndPub(&w, .{1} ** 32);
    const k2 = try importAndPub(&w, .{2} ** 32);
    const k3 = try importAndPub(&w, .{3} ** 32);

    const witness_script = try buildMultisigScript(
        allocator,
        2,
        &[_][33]u8{ k1.pk, k2.pk, k3.pk },
    );
    defer allocator.free(witness_script);

    // Build a single-input spend of a P2WSH UTXO.
    const ws_hash = crypto.sha256(witness_script);
    var spk: [34]u8 = undefined;
    spk[0] = 0x00; spk[1] = 0x20;
    @memcpy(spk[2..34], &ws_hash);

    const value: i64 = 1_000_000;
    var inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0xa1} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    var outputs = [_]types.TxOut{.{
        .value = 990_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0x10} ** 20),
    }};
    var tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    // Sign with keys 1 and 3 (skip key 2 to exercise canonical-order
    // pubkey matching against the script).
    const key_indices = [_]usize{ k1.ki, k3.ki };
    const witness = try wallet_mod.signP2WSH(
        &w,
        &tx,
        0,
        witness_script,
        value,
        &key_indices,
        null,
        0x01, // SIGHASH_ALL
        allocator,
    );
    defer {
        for (witness) |w_item| allocator.free(w_item);
        allocator.free(witness);
    }

    // Witness shape: [OP_0_dummy, sig_a, sig_b, witness_script] (4 elements).
    try std.testing.expectEqual(@as(usize, 4), witness.len);
    try std.testing.expectEqual(@as(usize, 0), witness[0].len);
    try std.testing.expectEqualSlices(u8, witness_script, witness[3]);

    // Each signature must end with the SIGHASH byte.
    try std.testing.expect(witness[1][witness[1].len - 1] == 0x01);
    try std.testing.expect(witness[2][witness[2].len - 1] == 0x01);

    // Compute the BIP-143 sighash and verify each emitted signature
    // against the corresponding script-pubkey (in canonical script order).
    const sighash = try crypto.segwitSighash(
        &tx,
        0,
        witness_script,
        value,
        0x01,
        allocator,
    );

    // Witness pubkeys in the script are [pk1, pk2, pk3]; canonical witness
    // order picks the first M=2 that signed. We signed with 1 and 3, so
    // the expected sigs verify under pk1 (witness[1]) and pk3 (witness[2]).
    {
        const sig_bytes = witness[1][0 .. witness[1].len - 1];
        try std.testing.expect(try w.verifyEcdsa(sig_bytes, &sighash, &k1.pk));
    }
    {
        const sig_bytes = witness[2][0 .. witness[2].len - 1];
        try std.testing.expect(try w.verifyEcdsa(sig_bytes, &sighash, &k3.pk));
    }
}

// ---------------------------------------------------------------------------
// Vector 2: P2SH-P2WSH 2-of-2 wrap
// ---------------------------------------------------------------------------

test "W29-C: P2SH-P2WSH 2-of-2 — scriptSig pushes redeemScript, witness has BIP-147 dummy" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();

    const ka = try importAndPub(&w, .{0xaa} ** 32);
    const kb = try importAndPub(&w, .{0xbb} ** 32);

    const witness_script = try buildMultisigScript(
        allocator,
        2,
        &[_][33]u8{ ka.pk, kb.pk },
    );
    defer allocator.free(witness_script);

    // P2SH-P2WSH on-chain scriptPubKey: OP_HASH160 <hash160(redeem)> OP_EQUAL
    // where redeem = OP_0 <0x20> <sha256(witness_script)>.
    const ws_hash = crypto.sha256(witness_script);
    var redeem: [34]u8 = undefined;
    redeem[0] = 0x00; redeem[1] = 0x20;
    @memcpy(redeem[2..34], &ws_hash);
    const redeem_h160 = crypto.hash160(&redeem);
    var spk: [23]u8 = undefined;
    spk[0] = 0xa9; spk[1] = 0x14;
    @memcpy(spk[2..22], &redeem_h160);
    spk[22] = 0x87;

    const value: i64 = 500_000;
    var inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0xc3} ** 32, .index = 1 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    var outputs = [_]types.TxOut{.{
        .value = 490_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0x22} ** 20),
    }};
    var tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    // Sign via the module-level signP2SH_P2WSH with both wallet key indices.
    // (This is the cleanest 2-of-2 case; the extras-path variant is exercised
    // separately in the dispatch test below.)
    const key_indices = [_]usize{ ka.ki, kb.ki };
    const result = try wallet_mod.signP2SH_P2WSH(
        &w,
        &tx,
        0,
        witness_script,
        value,
        &key_indices,
        null,
        0x01,
        allocator,
    );
    defer {
        for (result.witness) |w_item| allocator.free(w_item);
        allocator.free(result.witness);
        allocator.free(result.script_sig);
    }

    // scriptSig = 0x22 <34-byte redeemScript>; total 35 bytes.
    try std.testing.expectEqual(@as(usize, 35), result.script_sig.len);
    try std.testing.expectEqual(@as(u8, 0x22), result.script_sig[0]);
    try std.testing.expectEqualSlices(u8, &redeem, result.script_sig[1..35]);

    // Witness: [empty, sig_a, sig_b, witness_script] for 2-of-2.
    try std.testing.expectEqual(@as(usize, 4), result.witness.len);
    try std.testing.expectEqual(@as(usize, 0), result.witness[0].len);
    try std.testing.expectEqualSlices(u8, witness_script, result.witness[3]);

    // Verify both sigs verify under their canonical-order pubkeys.
    const sighash = try crypto.segwitSighash(
        &tx,
        0,
        witness_script,
        value,
        0x01,
        allocator,
    );
    {
        const sig_bytes = result.witness[1][0 .. result.witness[1].len - 1];
        try std.testing.expect(try w.verifyEcdsa(sig_bytes, &sighash, &ka.pk));
    }
    {
        const sig_bytes = result.witness[2][0 .. result.witness[2].len - 1];
        try std.testing.expect(try w.verifyEcdsa(sig_bytes, &sighash, &kb.pk));
    }
}

// ---------------------------------------------------------------------------
// Vector 3: Dispatch round-trip — signInput(.p2wsh) === manual signP2WSH
// ---------------------------------------------------------------------------

test "W29-C: signInput(.p2wsh) dispatch yields canonical witness (drift sentinel)" {
    // Parallel-impl drift sentinel: a future refactor of `signInput` that
    // forgets to thread `witness_script` / `extra_signing_keys` to
    // `signP2WSH` would silently diverge from the manually-constructed
    // canonical witness. This test pins the equivalence — both paths
    // must produce byte-identical witness elements. Also exercises the
    // `extra_signing_keys` route in the dispatch (vs. wallet-only key
    // indices in vectors 1 and 2).
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();

    // Wallet only knows secret_x; secret_y is provided as an extra
    // cosigner secret on the UTXO. We pre-import secret_y into a *second*
    // wallet just to capture its compressed pubkey for the script.
    const secret_y: [32]u8 = .{0x88} ** 32;
    const kx = try importAndPub(&w, .{0x77} ** 32);
    const pk_y = blk: {
        var w2 = try wallet_mod.Wallet.init(allocator, .regtest);
        defer w2.deinit();
        const k = try importAndPub(&w2, secret_y);
        break :blk k.pk;
    };

    const witness_script = try buildMultisigScript(
        allocator,
        2,
        &[_][33]u8{ kx.pk, pk_y },
    );
    defer allocator.free(witness_script);

    const ws_hash = crypto.sha256(witness_script);
    var spk: [34]u8 = undefined;
    spk[0] = 0x00; spk[1] = 0x20;
    @memcpy(spk[2..34], &ws_hash);

    const value: i64 = 750_000;
    var inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x55} ** 32, .index = 4 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    var outputs = [_]types.TxOut{.{
        .value = 740_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0x33} ** 20),
    }};
    var tx_dispatch = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    // Path A: dispatch via signInput on a .p2wsh utxo with witness_script set.
    const extras = [_][32]u8{secret_y};
    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = inputs[0].previous_output,
        .output = .{ .value = value, .script_pubkey = &spk },
        .key_index = kx.ki,
        .address_type = .p2wsh,
        .confirmations = 1,
        .witness_script = witness_script,
        .extra_signing_keys = &extras,
    };
    try w.signInput(&tx_dispatch, 0, utxo, 0x01, null);
    defer {
        for (tx_dispatch.inputs[0].witness) |it| allocator.free(it);
        allocator.free(tx_dispatch.inputs[0].witness);
    }

    // Path B: call signP2WSH directly with the same arguments.
    const key_indices = [_]usize{kx.ki};
    const witness_manual = try wallet_mod.signP2WSH(
        &w,
        &tx_dispatch,
        0,
        witness_script,
        value,
        &key_indices,
        &extras,
        0x01,
        allocator,
    );
    defer {
        for (witness_manual) |it| allocator.free(it);
        allocator.free(witness_manual);
    }

    // ECDSA is deterministic (RFC-6979 in libsecp), so both paths must
    // produce byte-identical witnesses.
    try std.testing.expectEqual(tx_dispatch.inputs[0].witness.len, witness_manual.len);
    for (tx_dispatch.inputs[0].witness, witness_manual) |a, b| {
        try std.testing.expectEqualSlices(u8, a, b);
    }

    // Sanity: 4 elements (dummy + 2 sigs + script).
    try std.testing.expectEqual(@as(usize, 4), witness_manual.len);

    // The signatures must verify against the canonical script-order pubkeys.
    const sighash = try crypto.segwitSighash(
        &tx_dispatch,
        0,
        witness_script,
        value,
        0x01,
        allocator,
    );
    {
        const sig_bytes = witness_manual[1][0 .. witness_manual[1].len - 1];
        try std.testing.expect(try w.verifyEcdsa(sig_bytes, &sighash, &kx.pk));
    }
    {
        const sig_bytes = witness_manual[2][0 .. witness_manual[2].len - 1];
        try std.testing.expect(try w.verifyEcdsa(sig_bytes, &sighash, &pk_y));
    }
}

// ---------------------------------------------------------------------------
// Negative tests — enforce loud failures rather than silent garbage
// ---------------------------------------------------------------------------

test "W29-C: signInput(.p2wsh) without witness_script errors honestly" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();
    _ = try w.generateKey();

    var inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x99} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    var outputs = [_]types.TxOut{.{
        .value = 99_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0xab} ** 20),
    }};
    var tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = inputs[0].previous_output,
        .output = .{ .value = 100_000, .script_pubkey = &[_]u8{0x00} ** 34 },
        .key_index = 0,
        .address_type = .p2wsh,
        .confirmations = 1,
    };

    // Pre-W29-C this returned `error.NotImplemented`; post-W29-C without
    // a witness_script we want a more specific error so callers know what
    // they need to supply.
    try std.testing.expectError(
        error.P2WSHMissingWitnessScript,
        w.signInput(&tx, 0, utxo, 0x01, null),
    );
}

test "W29-C: parseMultisigScript recognises 2-of-3, rejects malformed" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();

    const k1 = try importAndPub(&w, .{0x11} ** 32);
    const k2 = try importAndPub(&w, .{0x22} ** 32);
    const k3 = try importAndPub(&w, .{0x33} ** 32);

    const ws = try buildMultisigScript(allocator, 2, &[_][33]u8{ k1.pk, k2.pk, k3.pk });
    defer allocator.free(ws);

    const parsed = try wallet_mod.parseMultisigScript(allocator, ws);
    try std.testing.expect(parsed != null);
    if (parsed) |p| {
        defer allocator.free(p.pubkeys);
        try std.testing.expectEqual(@as(u8, 2), p.m);
        try std.testing.expectEqual(@as(usize, 3), p.pubkeys.len);
        try std.testing.expectEqualSlices(u8, &k1.pk, p.pubkeys[0]);
        try std.testing.expectEqualSlices(u8, &k2.pk, p.pubkeys[1]);
        try std.testing.expectEqualSlices(u8, &k3.pk, p.pubkeys[2]);
    }

    // Not multisig: bare <pk> OP_CHECKSIG (single-key witness script).
    var bare: [35]u8 = undefined;
    bare[0] = 0x21;
    @memcpy(bare[1..34], &k1.pk);
    bare[34] = 0xac; // OP_CHECKSIG (NOT CHECKMULTISIG)
    const not_ms = try wallet_mod.parseMultisigScript(allocator, &bare);
    try std.testing.expect(not_ms == null);

    // Not multisig: garbage bytes.
    const garbage = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    const not_ms2 = try wallet_mod.parseMultisigScript(allocator, &garbage);
    try std.testing.expect(not_ms2 == null);
}

// ---------------------------------------------------------------------------
// Single-key P2WSH (`<pubkey> OP_CHECKSIG`) round-trip
// ---------------------------------------------------------------------------

test "W29-C: P2WSH single-CHECKSIG witness script — [sig, witness_script] shape" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();

    const k = try importAndPub(&w, .{0x42} ** 32);

    // witness_script = <33-byte pubkey> OP_CHECKSIG
    var ws: [35]u8 = undefined;
    ws[0] = 0x21; // push 33
    @memcpy(ws[1..34], &k.pk);
    ws[34] = 0xac; // OP_CHECKSIG

    const ws_hash = crypto.sha256(&ws);
    var spk: [34]u8 = undefined;
    spk[0] = 0x00; spk[1] = 0x20;
    @memcpy(spk[2..34], &ws_hash);

    const value: i64 = 250_000;
    var inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0xdd} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    var outputs = [_]types.TxOut{.{
        .value = 240_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0x44} ** 20),
    }};
    var tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = inputs[0].previous_output,
        .output = .{ .value = value, .script_pubkey = &spk },
        .key_index = k.ki,
        .address_type = .p2wsh,
        .confirmations = 1,
        .witness_script = &ws,
    };
    try w.signInput(&tx, 0, utxo, 0x01, null);
    defer {
        for (tx.inputs[0].witness) |w_item| allocator.free(w_item);
        allocator.free(tx.inputs[0].witness);
    }

    // Single-key shape: [sig, witness_script] (NO leading dummy).
    try std.testing.expectEqual(@as(usize, 2), tx.inputs[0].witness.len);
    try std.testing.expectEqualSlices(u8, &ws, tx.inputs[0].witness[1]);

    const sighash = try crypto.segwitSighash(&tx, 0, &ws, value, 0x01, allocator);
    const sig_bytes = tx.inputs[0].witness[0][0 .. tx.inputs[0].witness[0].len - 1];
    try std.testing.expect(try w.verifyEcdsa(sig_bytes, &sighash, &k.pk));
}
