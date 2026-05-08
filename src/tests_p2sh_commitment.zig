//! P2SH commitment tests for the PSBT finalizer (W31).
//!
//! Validates the BIP-16 commitment check added to `Psbt.finalizeP2SH`:
//! before emitting `final_script_sig`, the finalizer must verify
//! `hash160(input.redeem_script) == witness_utxo.script_pubkey[2..22]`.
//! Without this guard, a forged `redeem_script` would be wrapped into a
//! structurally-valid scriptSig (rejected by every consensus verifier
//! anyway, but emitted onto the relay path / handed back to the caller
//! with no signal that it's broken). Same bug shape as the cross-impl
//! class found in hotbuns/blockbrew/etc.
//!
//! The two vectors below pin the contract:
//!   1. Positive — correct redeem_script → finalize emits final_script_sig
//!      pushing the redeemScript and a 2-element witness.
//!   2. Negative — forged redeem_script (different hash160 from the on-chain
//!      P2SH scriptPubKey) → finalize errors with
//!      `error.RedeemScriptCommitmentMismatch`.
//!
//! The PSBT module has no `@embedFile` of its own, so this file lives at
//! `src/` and is wired into `build.zig` directly (no project-root
//! wrapper file needed, unlike the wallet-taproot / wallet-segwit-v0
//! tests).

const std = @import("std");
const psbt_mod = @import("psbt.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a P2SH-P2WPKH redeem script for a 20-byte pubkey hash:
///   OP_0 <0x14> <pubkey_hash>   (22 bytes)
fn buildP2WPKHRedeem(pubkey_hash: [20]u8) [22]u8 {
    var out: [22]u8 = undefined;
    out[0] = 0x00; // OP_0
    out[1] = 0x14; // Push 20 bytes
    @memcpy(out[2..22], &pubkey_hash);
    return out;
}

/// Build the P2SH on-chain scriptPubKey for a 22-byte redeem script:
///   OP_HASH160 <0x14> <hash160(redeem)> OP_EQUAL    (23 bytes)
fn buildP2SHScriptPubKey(redeem: []const u8) [23]u8 {
    const h = crypto.hash160(redeem);
    var out: [23]u8 = undefined;
    out[0] = 0xa9; // OP_HASH160
    out[1] = 0x14; // Push 20 bytes
    @memcpy(out[2..22], &h);
    out[22] = 0x87; // OP_EQUAL
    return out;
}

/// Build a minimal one-input/one-output unsigned transaction the PSBT
/// can wrap. Inputs and outputs live on the caller's stack; this is fine
/// since `Psbt.create` makes its own deep copies.
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
// Vector 1: Correct redeemScript finalizes
// ---------------------------------------------------------------------------

test "W31 PSBT finalizeP2SH: matching redeemScript emits final_script_sig" {
    const allocator = std.testing.allocator;

    // Synthetic but BIP-16-valid pubkey hash — its actual derivation
    // doesn't matter for this test, only that hash160(redeem) ==
    // scriptPubKey[2..22] holds.
    const pkh: [20]u8 = .{0x77} ** 20;
    const redeem = buildP2WPKHRedeem(pkh);
    const spk = buildP2SHScriptPubKey(&redeem);

    const tx = buildUnsignedTx();
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Witness UTXO with the matching P2SH scriptPubKey.
    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &spk });
    try psbt.addInputRedeemScript(0, &redeem);

    // For P2SH-P2WPKH the finalizer also requires exactly one partial
    // signature on the input (BIP-174). The signature bytes themselves
    // aren't validated by the finalizer, only structurally consumed —
    // we feed it a placeholder so the path runs to the
    // `final_script_sig` emission step.
    var fake_pubkey: [33]u8 = undefined;
    fake_pubkey[0] = 0x02;
    @memcpy(fake_pubkey[1..33], &([_]u8{0xbb} ** 32));
    const fake_sig = [_]u8{0xcc} ** 71;
    try psbt.addPartialSig(0, fake_pubkey, &fake_sig);

    try psbt.finalizeInput(0);

    // Must have emitted both scriptSig and witness.
    try std.testing.expect(psbt.inputs[0].final_script_sig != null);
    try std.testing.expect(psbt.inputs[0].final_script_witness != null);

    // scriptSig must be a single push of the 22-byte redeemScript.
    const ss = psbt.inputs[0].final_script_sig.?;
    try std.testing.expectEqual(@as(usize, 23), ss.len);
    try std.testing.expectEqual(@as(u8, 0x16), ss[0]); // push 22
    try std.testing.expectEqualSlices(u8, &redeem, ss[1..23]);

    // Witness must be 2 elements: [sig, pubkey].
    try std.testing.expectEqual(@as(usize, 2), psbt.inputs[0].final_script_witness.?.len);
}

// ---------------------------------------------------------------------------
// Vector 2: Forged redeemScript errors with the mismatch sentinel
// ---------------------------------------------------------------------------

test "W31 PSBT finalizeP2SH: forged redeemScript returns RedeemScriptCommitmentMismatch" {
    const allocator = std.testing.allocator;

    // The on-chain scriptPubKey commits to redeemScript A.
    const pkh_a: [20]u8 = .{0x11} ** 20;
    const redeem_a = buildP2WPKHRedeem(pkh_a);
    const spk = buildP2SHScriptPubKey(&redeem_a);

    // The PSBT carries forged redeemScript B (different pubkey hash, so
    // hash160(redeem_b) != hash160(redeem_a) == spk[2..22]).
    const pkh_b: [20]u8 = .{0x22} ** 20;
    const redeem_b = buildP2WPKHRedeem(pkh_b);

    // Sanity: the test would be vacuous if the hashes happened to collide.
    try std.testing.expect(!std.mem.eql(u8, &crypto.hash160(&redeem_a), &crypto.hash160(&redeem_b)));

    const tx = buildUnsignedTx();
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    try psbt.addInputUtxo(0, types.TxOut{ .value = 100_000, .script_pubkey = &spk });
    try psbt.addInputRedeemScript(0, &redeem_b);

    var fake_pubkey: [33]u8 = undefined;
    fake_pubkey[0] = 0x02;
    @memcpy(fake_pubkey[1..33], &([_]u8{0xee} ** 32));
    const fake_sig = [_]u8{0xff} ** 71;
    try psbt.addPartialSig(0, fake_pubkey, &fake_sig);

    // Finalize must refuse with the W31 mismatch sentinel.
    const result = psbt.finalizeInput(0);
    try std.testing.expectError(psbt_mod.PsbtError.RedeemScriptCommitmentMismatch, result);

    // No final_script_sig or final_script_witness should have been set.
    try std.testing.expect(psbt.inputs[0].final_script_sig == null);
    try std.testing.expect(psbt.inputs[0].final_script_witness == null);
}

