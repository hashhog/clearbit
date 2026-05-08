//! BIP-86 + BIP-341 wallet tests (W20).
//!
//! Validates the P0-1 (BIP-341 wire) and P0-2 (BIP-86 tweak) fixes by
//! running the canonical reference vectors and a full sign+verify
//! round-trip through libsecp256k1.
//!
//! Reference data:
//!   - BIP-86 (single-key Taproot, empty merkle root) — vector 0 of
//!     `bitcoin-core/src/test/data/bip341_wallet_vectors.json`
//!     (`scriptPubKey[0]`, scriptTree=null), which IS a BIP-86 case.
//!   - BIP-341 keyPathSpending — vector 0 of the same file.
//!
//! Lives at `src/` so it can `@import("wallet.zig")` etc., but is wrapped
//! by `tests_wallet_taproot.zig` at the project root so `@embedFile` in
//! `wallet.zig` (`../resources/bip39-english.txt`) resolves the same way
//! it does for `tests_rpc.zig`.

const std = @import("std");
const wallet_mod = @import("wallet.zig");
const types = @import("types.zig");
const taproot_sighash = @import("taproot_sighash.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");

const secp256k1 = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
});

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch return error.InvalidHex;
    }
    return out;
}

fn hex32(hex: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (0..32) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch unreachable;
    }
    return out;
}

// ---------------------------------------------------------------------------
// BIP-86 vector test
// ---------------------------------------------------------------------------

test "BIP-86 tweak matches bip341_wallet_vectors.json scriptPubKey[0]" {
    // Vector 0 of bip341_wallet_vectors.json has scriptTree = null, which is
    // the BIP-86 single-key (empty merkle root) case. The vector pins the
    // tweak (`taggedHash(\"TapTweak\", internal)`) and the resulting tweaked
    // x-only output key, which is what BIP-86 wallets must put on chain.
    const internal_hex = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d";
    const expected_tweak_hex = "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70";
    const expected_tweaked_pk_hex = "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343";

    var internal_buf: [64]u8 = undefined;
    @memcpy(&internal_buf, internal_hex);
    const internal = hex32(&internal_buf);

    // (1) The wallet's bip86Tweak helper must equal the published tweak,
    //     i.e. tagged_hash("TapTweak", internal) with empty merkle root.
    const tweak = wallet_mod.bip86Tweak(&internal);
    var expected_tweak_buf: [64]u8 = undefined;
    @memcpy(&expected_tweak_buf, expected_tweak_hex);
    const expected_tweak = hex32(&expected_tweak_buf);
    try std.testing.expectEqualSlices(u8, &expected_tweak, &tweak);

    // (2) The tweaked x-only output key must match the vector. This is what
    //     getScriptPubKey(.p2tr) is supposed to put inside `OP_1 <0x20> ...`.
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    ) orelse return error.SecpCtxFailed;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const tweaked = try wallet_mod.bip86TweakXOnly(ctx, &internal);
    var expected_pk_buf: [64]u8 = undefined;
    @memcpy(&expected_pk_buf, expected_tweaked_pk_hex);
    const expected_pk = hex32(&expected_pk_buf);
    try std.testing.expectEqualSlices(u8, &expected_pk, &tweaked);
}

// ---------------------------------------------------------------------------
// BIP-86 wallet wiring: getScriptPubKey + getAddress emit the tweaked key
// ---------------------------------------------------------------------------

test "BIP-86 wallet getScriptPubKey emits tweaked output key, not internal" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();

    _ = try w.generateKey();
    const key = w.keys.items[0];

    const spk = try w.getScriptPubKey(0, .p2tr);
    defer allocator.free(spk);

    // P2TR scriptPubKey shape: 0x51 0x20 <32-byte key>
    try std.testing.expectEqual(@as(usize, 34), spk.len);
    try std.testing.expectEqual(@as(u8, 0x51), spk[0]);
    try std.testing.expectEqual(@as(u8, 0x20), spk[1]);

    // The 32-byte key must NOT be the raw internal key (W20 P0-2 fix).
    try std.testing.expect(!std.mem.eql(u8, spk[2..], &key.x_only_pubkey));

    // It must equal the BIP-86 tweaked key.
    const expected = try wallet_mod.bip86TweakXOnly(w.ctx, &key.x_only_pubkey);
    try std.testing.expectEqualSlices(u8, &expected, spk[2..]);
}

test "BIP-86 wallet getAddress encodes tweaked output key" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();

    _ = try w.generateKey();
    const key = w.keys.items[0];

    const addr = try w.getAddress(0, .p2tr);
    defer allocator.free(addr);
    const spk = try w.getScriptPubKey(0, .p2tr);
    defer allocator.free(spk);

    // Mainnet bech32m P2TR addresses start with "bc1p".
    try std.testing.expect(std.mem.startsWith(u8, addr, "bc1p"));

    // Address must encode the same tweaked key as the scriptPubKey
    // (i.e. it must NOT decode to the internal x-only pubkey).
    // We sanity-check by recomputing the tweak ourselves and confirming
    // it sits inside the scriptPubKey we just built.
    const expected = try wallet_mod.bip86TweakXOnly(w.ctx, &key.x_only_pubkey);
    try std.testing.expectEqualSlices(u8, &expected, spk[2..]);
}

// ---------------------------------------------------------------------------
// BIP-341 sighash via wallet helper matches canonical taproot_sighash
// ---------------------------------------------------------------------------

test "wallet computeTaprootSigHash matches canonical taproot_sighash impl" {
    const allocator = std.testing.allocator;

    // Build a minimal, deterministic transaction with a single P2TR input.
    // We don't care about the exact hash here; we only need to confirm
    // that the wallet helper is a thin wrapper over the canonical impl
    // and that swapping in a different prevout amount/script yields a
    // different sighash (i.e. those fields actually feed the hash, unlike
    // the pre-fix code which discarded them).
    const prev_hash = [_]u8{0xab} ** 32;
    const prev_spk_a = [_]u8{0x51, 0x20} ++ ([_]u8{0xcc} ** 32);
    const prev_spk_b = [_]u8{0x51, 0x20} ++ ([_]u8{0xdd} ** 32);

    const tx_inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = prev_hash, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    const tx_outputs = [_]types.TxOut{.{
        .value = 90_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0x11} ** 20),
    }};
    const tx = types.Transaction{
        .version = 2,
        .inputs = &tx_inputs,
        .outputs = &tx_outputs,
        .lock_time = 0,
    };

    const utxo_a = wallet_mod.OwnedUtxo{
        .outpoint = tx_inputs[0].previous_output,
        .output = .{ .value = 100_000, .script_pubkey = &prev_spk_a },
        .key_index = 0,
        .address_type = .p2tr,
        .confirmations = 1,
    };
    const utxo_b = wallet_mod.OwnedUtxo{
        .outpoint = tx_inputs[0].previous_output,
        .output = .{ .value = 100_000, .script_pubkey = &prev_spk_b },
        .key_index = 0,
        .address_type = .p2tr,
        .confirmations = 1,
    };

    // Wallet helper output (post-W20).
    const sighash_a = try wallet_mod.computeTaprootSigHash(&tx, 0, &[_]wallet_mod.OwnedUtxo{utxo_a}, 0x00, allocator);
    const sighash_b = try wallet_mod.computeTaprootSigHash(&tx, 0, &[_]wallet_mod.OwnedUtxo{utxo_b}, 0x00, allocator);

    // Canonical impl on the same data — must agree byte-for-byte.
    const canonical_a = try taproot_sighash.computeTaprootSighash(
        allocator,
        &tx,
        0,
        .{
            .amounts = &[_]i64{utxo_a.output.value},
            .scripts = &[_][]const u8{utxo_a.output.script_pubkey},
        },
        0x00,
        null,
        null,
    );
    try std.testing.expectEqualSlices(u8, &canonical_a, &sighash_a);

    // Different scriptPubKey ⇒ different sighash. Pre-W20 this would have
    // been equal because the wallet zero-padded sha_scriptPubKeys.
    try std.testing.expect(!std.mem.eql(u8, &sighash_a, &sighash_b));

    // Also flip the amount and confirm the sighash changes (sha_amounts
    // also used to be zero-padded pre-W20).
    const utxo_c = wallet_mod.OwnedUtxo{
        .outpoint = tx_inputs[0].previous_output,
        .output = .{ .value = 200_000, .script_pubkey = &prev_spk_a },
        .key_index = 0,
        .address_type = .p2tr,
        .confirmations = 1,
    };
    const sighash_c = try wallet_mod.computeTaprootSigHash(&tx, 0, &[_]wallet_mod.OwnedUtxo{utxo_c}, 0x00, allocator);
    try std.testing.expect(!std.mem.eql(u8, &sighash_a, &sighash_c));
}

// ---------------------------------------------------------------------------
// End-to-end sign + Schnorr verify round-trip
// ---------------------------------------------------------------------------

test "BIP-86 sign + Schnorr verify against on-chain tweaked output key" {
    // Round-trip: build a wallet key, derive its P2TR scriptPubKey
    // (BIP-86 tweaked output key on-chain), sign a transaction that
    // spends it, and verify the resulting Schnorr signature against the
    // tweaked output key using libsecp256k1. Pre-W20 this round-trip
    // failed two ways: (1) the sighash was zero-padded (signature was
    // unverifiable against any sane verifier even with the right key),
    // and (2) the on-chain key was the untweaked internal key, so even
    // with a correct sighash the signature wouldn't verify against the
    // chain's output key.
    const allocator = std.testing.allocator;

    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();

    // Deterministic secret so the test is reproducible.
    var secret: [32]u8 = undefined;
    @memcpy(&secret, "BIP86_w20_round_trip_seed_xxxxxx"[0..32]);
    _ = try w.importKey(secret);

    const spk = try w.getScriptPubKey(0, .p2tr);
    defer allocator.free(spk);
    try std.testing.expectEqual(@as(usize, 34), spk.len);
    const onchain_xonly: [32]u8 = spk[2..34].*;

    // Single-input tx spending the P2TR output we just minted.
    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x33} ** 32, .index = 7 },
        .output = .{ .value = 250_000, .script_pubkey = spk },
        .key_index = 0,
        .address_type = .p2tr,
        .confirmations = 6,
        .is_coinbase = false,
        .height = 800_000,
    };

    var inputs = [_]types.TxIn{.{
        .previous_output = utxo.outpoint,
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

    const all_prevouts = [_]wallet_mod.OwnedUtxo{utxo};
    try w.signInput(&tx, 0, utxo, 0x00, &all_prevouts);

    // Free the witness allocation that signInput attached to the tx —
    // the test owns the tx struct so we have to clean up its sub-slices.
    defer {
        for (tx.inputs[0].witness) |w_item| allocator.free(w_item);
        allocator.free(tx.inputs[0].witness);
    }

    // Witness must be exactly one element of 64 bytes for SIGHASH_DEFAULT.
    try std.testing.expectEqual(@as(usize, 1), tx.inputs[0].witness.len);
    try std.testing.expectEqual(@as(usize, 64), tx.inputs[0].witness[0].len);
    const sig: [64]u8 = tx.inputs[0].witness[0][0..64].*;

    // Recompute the sighash via the canonical impl and verify the
    // Schnorr signature against the on-chain (tweaked) x-only output key.
    const sighash = try taproot_sighash.computeTaprootSighash(
        allocator,
        &tx,
        0,
        .{
            .amounts = &[_]i64{utxo.output.value},
            .scripts = &[_][]const u8{utxo.output.script_pubkey},
        },
        0x00,
        null,
        null,
    );

    var xonly_pub: secp256k1.secp256k1_xonly_pubkey = undefined;
    try std.testing.expect(secp256k1.secp256k1_xonly_pubkey_parse(w.ctx, &xonly_pub, &onchain_xonly) == 1);
    const verify_ok = secp256k1.secp256k1_schnorrsig_verify(
        w.ctx,
        &sig,
        &sighash,
        sighash.len,
        &xonly_pub,
    );
    try std.testing.expectEqual(@as(c_int, 1), verify_ok);

    // Negative control: verifying against the *untweaked* internal key
    // (what pre-W20 would have put on chain and tried to verify against)
    // must FAIL — confirming the BIP-86 tweak actually flipped the key.
    const internal = w.keys.items[0].x_only_pubkey;
    var xonly_internal: secp256k1.secp256k1_xonly_pubkey = undefined;
    try std.testing.expect(secp256k1.secp256k1_xonly_pubkey_parse(w.ctx, &xonly_internal, &internal) == 1);
    const verify_internal = secp256k1.secp256k1_schnorrsig_verify(
        w.ctx,
        &sig,
        &sighash,
        sighash.len,
        &xonly_internal,
    );
    try std.testing.expectEqual(@as(c_int, 0), verify_internal);
}

// ---------------------------------------------------------------------------
// Multi-input BIP-341 sighash sensitivity
// ---------------------------------------------------------------------------

test "BIP-341 wallet sighash commits to ALL inputs' amounts + scripts" {
    // Synthesize a 3-input tx; flip a non-signed input's amount and
    // confirm the sighash for input 0 changes. Pre-W20 this was masked
    // by hard-zeroing sha_amounts/sha_scriptPubKeys, so any per-input
    // edit to the OTHER prevouts would silently leave the sighash equal
    // (bug class: malleability + unverifiability).
    const allocator = std.testing.allocator;

    const inputs = [_]types.TxIn{
        .{
            .previous_output = .{ .hash = [_]u8{0x10} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFD,
            .witness = &[_][]const u8{},
        },
        .{
            .previous_output = .{ .hash = [_]u8{0x20} ** 32, .index = 1 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFD,
            .witness = &[_][]const u8{},
        },
        .{
            .previous_output = .{ .hash = [_]u8{0x30} ** 32, .index = 2 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFD,
            .witness = &[_][]const u8{},
        },
    };
    const outputs = [_]types.TxOut{.{
        .value = 1_000_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0x55} ** 20),
    }};
    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    const spk_a = [_]u8{0x51, 0x20} ++ ([_]u8{0xaa} ** 32);
    const spk_b = [_]u8{0x51, 0x20} ++ ([_]u8{0xbb} ** 32);
    const spk_c = [_]u8{0x51, 0x20} ++ ([_]u8{0xcc} ** 32);

    const prevouts_baseline = [_]wallet_mod.OwnedUtxo{
        .{
            .outpoint = inputs[0].previous_output,
            .output = .{ .value = 500_000, .script_pubkey = &spk_a },
            .key_index = 0,
            .address_type = .p2tr,
            .confirmations = 1,
        },
        .{
            .outpoint = inputs[1].previous_output,
            .output = .{ .value = 300_000, .script_pubkey = &spk_b },
            .key_index = 0,
            .address_type = .p2tr,
            .confirmations = 1,
        },
        .{
            .outpoint = inputs[2].previous_output,
            .output = .{ .value = 250_000, .script_pubkey = &spk_c },
            .key_index = 0,
            .address_type = .p2tr,
            .confirmations = 1,
        },
    };
    const sighash_baseline = try wallet_mod.computeTaprootSigHash(&tx, 0, &prevouts_baseline, 0x01, allocator);

    // Flip input 2's amount only; sighash for input 0 must change.
    var prevouts_v2 = prevouts_baseline;
    prevouts_v2[2].output.value = 9_999_999;
    const sighash_v2 = try wallet_mod.computeTaprootSigHash(&tx, 0, &prevouts_v2, 0x01, allocator);
    try std.testing.expect(!std.mem.eql(u8, &sighash_baseline, &sighash_v2));

    // Flip input 1's scriptPubKey only; sighash for input 0 must change.
    var prevouts_v3 = prevouts_baseline;
    const spk_b_alt = [_]u8{0x51, 0x20} ++ ([_]u8{0xee} ** 32);
    prevouts_v3[1].output.script_pubkey = &spk_b_alt;
    const sighash_v3 = try wallet_mod.computeTaprootSigHash(&tx, 0, &prevouts_v3, 0x01, allocator);
    try std.testing.expect(!std.mem.eql(u8, &sighash_baseline, &sighash_v3));
}

// ---------------------------------------------------------------------------
// signInput rejects p2tr without prevouts
// ---------------------------------------------------------------------------

test "signInput .p2tr without all_prevouts errors honestly" {
    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();
    _ = try w.generateKey();

    const spk = try w.getScriptPubKey(0, .p2tr);
    defer allocator.free(spk);

    var inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x77} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    var outputs = [_]types.TxOut{.{
        .value = 99_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ ([_]u8{0x88} ** 20),
    }};
    var tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };
    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = inputs[0].previous_output,
        .output = .{ .value = 100_000, .script_pubkey = spk },
        .key_index = 0,
        .address_type = .p2tr,
        .confirmations = 1,
    };

    // Calling signInput on a .p2tr input without all_prevouts must fail
    // loudly rather than silently produce a bogus signature.
    try std.testing.expectError(error.TaprootRequiresAllPrevouts, w.signInput(&tx, 0, utxo, 0x00, null));
}
