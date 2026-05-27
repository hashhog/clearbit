//! W118 Wallet audit — clearbit (Zig 0.13)
//!
//! 30-gate fleet audit. Same 6-bucket layout as the rustoshi W118 prompt:
//!   G1-G6   Descriptors (BIP-380, checksum, parse, derive, getdescriptorinfo,
//!                        TR + multisig)
//!   G7-G12  BIP-32 HD derivation (master, hardened, CKDpub, xpub serialization,
//!                                 parent fingerprint, BIP-44/49/84/86 paths)
//!   G13-G18 PSBT (BIP-174 v0 round-trip, finalize, combine, BIP-371 taproot,
//!                 BIP-370 v2, BIP-174 base64)
//!   G19-G22 Fee bumping (BIP-125 RBF signal, bumpfee RPC, psbtbumpfee,
//!                        replaceability defaults)
//!   G23-G26 Send (createTransaction signs all inputs, change output present,
//!                 fee accounting, dust output rejection)
//!   G27-G30 UTXO (addUtxo/removeUtxo, lockunspent, spendable vs immature
//!                 coinbase, getbalance maturity)
//!
//! W118 is a SECOND-WAVE wallet audit. The first wave (W111) flagged the
//! XOR-encryption P0 — that has since been fixed (FIX-37 / FIX-39, AES-256-GCM
//! + scrypt KDF). This audit reuses some W111 gates but goes deeper on the
//! parts that have substance (descriptor parser, PSBT signer/finalizer,
//! BIP-32 derivation, createTransaction signing path) and pinpoints what is
//! still missing (PSBT v2 / BIP-370, BIP-371 taproot finalization,
//! bumpfee / psbtbumpfee RPCs, full BIP-32 xpub encoding, descriptor solver
//! / wallet integration).
//!
//! Findings summary (so far — see per-gate notes below):
//!   BUG-1  (HIGH/CDIV) G3  — Descriptor `combo(KEY)` produces a single script
//!                            instead of the 4-script set { pk, pkh, wpkh, sh(wpkh) }
//!                            that Core derives. `deriveScript` for `.combo`
//!                            falls through to `pkh` only.
//!   BUG-2  (MED)       G6  — `getDescriptorInfo.is_solvable` is hard-coded to
//!                            `true` for every descriptor except `addr()`/`raw()`.
//!                            Core checks against actual key availability. RPC
//!                            callers receive misleading information.
//!   BUG-3  (HIGH)      G9  — `ExtendedKey.deriveChild` does not support CKDpub
//!                            (public-only non-hardened derivation). The wallet
//!                            cannot derive child addresses from an imported xpub.
//!                            The same logic exists inside `descriptor.zig`
//!                            (`decodeExtendedKeyToPubkey`) so this is a dead-
//!                            helper / two-pipeline split: one path supports
//!                            CKDpub, the other does not.
//!   BUG-4  (HIGH)      G10 — No xpub/xprv base58check serializer or parser on
//!                            `ExtendedKey`. The 78-byte BIP-32 format is never
//!                            emitted or accepted. Watch-only coordination,
//!                            descriptor export, and hardware-wallet interop
//!                            all rely on this and silently break.
//!   BUG-5  (MED)       G14 — `Psbt.finalizeInput` has no P2TR branch (TODO at
//!                            psbt.zig:833). BIP-371 tap_key_sig fields are
//!                            parsed and stored, but `finalize` produces no
//!                            taproot witness. Same gap noted in W111 G14.
//!   BUG-6  (HIGH)      G17 — PSBT v2 (BIP-370) not supported. `PSBT_HIGHEST_VERSION`
//!                            is 0 and `deserialize` rejects v2 explicitly.
//!                            No PSBT_IN_PREVIOUS_TXID / OUTPUT_INDEX / SEQUENCE
//!                            constants defined.
//!   BUG-7  (HIGH)      G19 — FIX-61: BIP-125 `bumpfee` RPC implemented.
//!                            New `wallet.bumpFee` + `handleBumpFee` in
//!                            rpc.zig dispatcher. Reduces a wallet-owned
//!                            change output by `INCREMENTAL_FEE_RATE *
//!                            orig_vsize` (or by `user_fee_rate * orig_vsize
//!                            - orig_fee` when set), re-signs every input,
//!                            and emits the new tx + fee accounting.
//!   BUG-8  (HIGH)      G20 — FIX-61: `psbtbumpfee` RPC implemented via
//!                            `wallet.psbtBumpFee`. Same flow as bumpFee
//!                            but emits a BIP-174 PSBT instead of a
//!                            signed transaction.
//!   BUG-9  (MED)       G22 — FIX-61: `CreateTxOptions.replaceable` added.
//!                            Default `false` preserves the historical
//!                            `sequence = 0xFFFFFFFE`. `true` emits
//!                            `0xFFFFFFFD` — BIP-125's canonical opt-in
//!                            RBF signal — and is used internally by
//!                            `bumpFee` so the replacement is itself
//!                            bumpable.
//!   BUG-10 (HIGH)      G24 — `createTransaction` does not validate the
//!                            change-output value against fee. Caller can
//!                            request a transaction where outputs exceed
//!                            inputs and the function happily signs it
//!                            (`outputs[0].value` is taken as-is, no
//!                            inputs-sum-vs-outputs-sum check).
//!   BUG-11 (MED)       G25 — No dust-output rejection in `createTransaction`.
//!                            A 100-sat P2PKH output (below DUST_THRESHOLD_P2PKH
//!                            = 546) is built into the tx with no warning.
//!   BUG-12 (MED)       G29 — `unlockAllCoins` not connected to RPC; the
//!                            function exists in wallet.zig but the
//!                            `lockunspent` RPC (rpc.zig:10181) doesn't expose
//!                            an "unlock all" code path.
//!   BUG-13 (HIGH)      G30 — `getbalance` RPC does not honor confirmations
//!                            argument. The wallet has `tip_height` and
//!                            per-utxo `height`, but the RPC sums all
//!                            spendable UTXOs regardless of the `minconf`
//!                            argument that Bitcoin Core's getbalance accepts.
//!
//! Cross-impl observations:
//!   - Two-pipeline split: CKDpub works inside `descriptor.decodeExtendedKeyToPubkey`
//!     but the public `ExtendedKey.deriveChild` returns `error.NotImplemented`.
//!     A descriptor wallet can derive xpub-children fine; the standalone HD path
//!     cannot. Same logic, two implementations, only one finished.
//!   - Comment-as-confession at psbt.zig:833 (`// TODO: Add P2TR finalization`)
//!     and wallet.zig (`unlockAllCoins` exists but no RPC plumbing).
//!
//! Run with `zig build test-wallet-w118` (build.zig step added below in this audit).

const std = @import("std");
const wallet_mod = @import("wallet.zig");
const descriptor_mod = @import("descriptor.zig");
const bip39_mod = @import("bip39.zig");
const psbt_mod = @import("psbt.zig");
const types = @import("types.zig");
const address = @import("address.zig");
const crypto = @import("crypto.zig");

// Phase 2 (single-FFI secp module): see comment in tests_w111_wallet.zig
// for rationale. Route through the tree-wide `secp.c` so types match
// `wallet.zig`'s function signatures.
const secp256k1 = @import("secp.zig").c;

const Wallet = wallet_mod.Wallet;
const ExtendedKey = wallet_mod.ExtendedKey;
const OwnedUtxo = wallet_mod.OwnedUtxo;

// ---------------------------------------------------------------------------
// Hex / fixture helpers
// ---------------------------------------------------------------------------

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch unreachable;
    }
    return out;
}

fn makeContext() ?*secp256k1.secp256k1_context {
    return secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
}

fn destroyContext(ctx: ?*secp256k1.secp256k1_context) void {
    secp256k1.secp256k1_context_destroy(ctx);
}

// ===========================================================================
// G1: Descriptor checksum — BIP-380 round-trip with Core test vectors
// ===========================================================================

test "W118 G1: BIP-380 descriptor checksum Core vectors" {
    // Vector from bitcoin-core/src/test/descriptor_tests.cpp.
    // pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#8fhd9pwu
    const desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    const cs = descriptor_mod.computeChecksum(desc) orelse {
        try std.testing.expect(false); // computeChecksum returned null
        return;
    };
    try std.testing.expectEqualSlices(u8, "8fhd9pwu", &cs);

    // Round-trip: append checksum, verify, mutate, re-verify
    const allocator = std.testing.allocator;
    const with_cs = try descriptor_mod.addChecksum(allocator, desc);
    defer allocator.free(with_cs);
    try std.testing.expect(descriptor_mod.verifyChecksum(with_cs));

    // Mutate a body character → checksum must reject
    var mutated = try allocator.dupe(u8, with_cs);
    defer allocator.free(mutated);
    mutated[10] = if (mutated[10] == 'a') 'b' else 'a';
    try std.testing.expect(!descriptor_mod.verifyChecksum(mutated));
}

// ===========================================================================
// G2: Descriptor parse + deriveScript for wpkh()
// ===========================================================================

test "W118 G2: wpkh() descriptor parse + deriveScript produces expected SPK" {
    const allocator = std.testing.allocator;

    // Compressed pubkey 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    const desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .wpkh);

    const script = try descriptor_mod.deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // Expected wpkh SPK shape: OP_0 (0x00) || PUSH-20 (0x14) || HASH160(pubkey)
    try std.testing.expectEqual(@as(usize, 22), script.len);
    try std.testing.expectEqual(@as(u8, 0x00), script[0]); // OP_0
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // push 20

    // Compute hash160 of the pubkey and compare
    const pubkey = hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    const expected_hash = crypto.hash160(&pubkey);
    try std.testing.expectEqualSlices(u8, &expected_hash, script[2..22]);
}

// ===========================================================================
// G3: combo() descriptor — Core derives FOUR scripts, clearbit derives ONE
// ===========================================================================
//
// BUG-1 (HIGH/CDIV): combo(KEY) is defined by BIP-380 to expand to the union
// of pk(KEY), pkh(KEY), wpkh(KEY) and sh(wpkh(KEY)).  Watch-only wallets that
// import a combo() descriptor expect to see all four scriptPubKey forms.
// clearbit's deriveScript() for `.combo` returns a single legacy P2PKH script.
// Reference: bitcoin-core/src/script/descriptor.cpp ComboDescriptor.

test "W118 G3: combo() descriptor — BUG-1 only emits 1 of 4 expected scripts" {
    const allocator = std.testing.allocator;

    const desc_str = "combo(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .combo);

    // BUG-1: deriveScript only produces one script.  In Core the combo
    // descriptor expands to four scripts.  There is no API like
    // `deriveAllScripts(.combo)` to iterate them.
    const script = try descriptor_mod.deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // The clearbit implementation either errors out or returns a single
    // legacy P2PKH script.  We assert ONE script is produced, documenting the
    // gap — once BUG-1 is fixed, callers should be able to iterate four.
    try std.testing.expect(script.len > 0);

    // Confirm the API surface: no plural "all scripts" function exists.
    const has_all_scripts_fn = @hasDecl(descriptor_mod, "deriveAllScripts") or
        @hasDecl(descriptor_mod, "deriveScripts");
    try std.testing.expect(!has_all_scripts_fn);
}

// ===========================================================================
// G4: tr() descriptor parse — BIP-386 single-key taproot
// ===========================================================================

test "W118 G4: tr(KEY) descriptor parse — single-key taproot accepted" {
    const allocator = std.testing.allocator;

    // 32-byte x-only key from BIP-86 test vector
    const desc_str = "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)";

    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .tr);
    try std.testing.expectEqual(@as(usize, 0), desc.tr.leaves.len); // no script tree
}

// ===========================================================================
// G5: sortedmulti() descriptor — BIP-67 sort-on-emit
// ===========================================================================

test "W118 G5: sortedmulti() — keys sorted lexicographically per BIP-67" {
    const allocator = std.testing.allocator;

    // Two pubkeys in non-sorted order.  BIP-67 says sortedmulti() must emit
    // keys in lex-sorted order regardless of input order.
    // 02f9... < 02c6... so 02c6 must come first
    const desc_str = "sortedmulti(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .sorted_multi);
    try std.testing.expectEqual(@as(u32, 1), desc.sorted_multi.threshold);
    try std.testing.expectEqual(@as(usize, 2), desc.sorted_multi.keys.len);
    try std.testing.expect(desc.sorted_multi.sorted);

    // Derive script for index 0 — the multisig script body must list the
    // keys in lexicographic order (02c6... first).
    const script = try descriptor_mod.deriveScript(allocator, &desc, 0);
    defer allocator.free(script);

    // Script shape: OP_1 PUSH33 <key1> PUSH33 <key2> OP_2 OP_CHECKMULTISIG
    // Length = 1 + 1 + 33 + 1 + 33 + 1 + 1 = 71 bytes
    try std.testing.expectEqual(@as(usize, 71), script.len);
    try std.testing.expectEqual(@as(u8, 0x51), script[0]); // OP_1

    // Sorted: the first push must be the 02c6... key (lex-smaller)
    try std.testing.expectEqual(@as(u8, 0x02), script[2]);
    try std.testing.expectEqual(@as(u8, 0xc6), script[3]);
}

// ===========================================================================
// G6: getDescriptorInfo — is_solvable hard-coded to true (BUG-2)
// ===========================================================================
//
// BUG-2 (MED): getDescriptorInfo returns `is_solvable = true` for any non-
// addr / non-raw descriptor.  Core checks whether the wallet actually has
// the keys to sign — descriptors with only foreign keys are not solvable.
// Reference: bitcoin-core/src/script/descriptor.cpp::IsSolvable() iterates
// the descriptor and checks that every key has a known private (or sufficient
// witness) component.

test "W118 G6: getDescriptorInfo.is_solvable — BUG-2 hard-coded for non-raw" {
    const allocator = std.testing.allocator;

    // A descriptor referencing a foreign pubkey we have no key material for.
    // Core would mark this NOT solvable; clearbit marks it solvable.
    const desc_str = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

    const info = try descriptor_mod.getDescriptorInfo(allocator, desc_str);
    defer allocator.free(info.descriptor);

    // BUG-2: hard-coded true.  This will pass today (documenting the bug) and
    // must continue to pass after a proper fix is implemented (because the
    // pubkey has been imported with private-key material).
    try std.testing.expect(info.is_solvable);

    // The actual gap is at descriptor.zig:1558:
    //   .is_solvable = true, // Simplified - would need to check key availability
}

// ===========================================================================
// G7: BIP-32 master from seed — TV1
// ===========================================================================

test "W118 G7: ExtendedKey.fromSeed produces BIP-32 TV1 master key material" {
    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try ExtendedKey.fromSeed(&seed);

    // TV1 expected master privkey
    const expected_key = hexToBytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    try std.testing.expectEqualSlices(u8, &expected_key, &master.key);

    // TV1 expected chain code
    const expected_cc = hexToBytes("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    try std.testing.expectEqualSlices(u8, &expected_cc, &master.chain_code);

    try std.testing.expectEqual(@as(u8, 0), master.depth);
    try std.testing.expectEqual(@as(u32, 0), master.child_index);
    try std.testing.expect(master.is_private);
}

// ===========================================================================
// G8: BIP-32 hardened derivation (CKDpriv)
// ===========================================================================

test "W118 G8: hardened derivation m/0h chain code matches TV1" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try ExtendedKey.fromSeed(&seed);

    // m/0h
    const c0h = try master.deriveChild(ctx, 0x80000000);
    try std.testing.expectEqual(@as(u8, 1), c0h.depth);
    try std.testing.expectEqual(@as(u32, 0x80000000), c0h.child_index);

    // BIP-32 TV1 m/0h expected chain code:
    // 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
    const expected_cc = hexToBytes("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
    try std.testing.expectEqualSlices(u8, &expected_cc, &c0h.chain_code);
}

// ===========================================================================
// G9: CKDpub — public-only normal derivation (BUG-3 — two-pipeline)
// ===========================================================================
//
// BUG-3 (HIGH): ExtendedKey.deriveChild returns error.NotImplemented when
// is_private=false and the index is non-hardened.  This is CKDpub — the
// BIP-32 algorithm for deriving child PUBLIC keys from a parent xpub.
// Without this, watch-only / xpub-import wallets cannot derive addresses
// through the standalone HD path.
//
// Two-pipeline observation: `descriptor.zig::decodeExtendedKeyToPubkey`
// implements CKDpub correctly inside the descriptor parser.  The wallet's
// own `ExtendedKey.deriveChild` does not.  Same algorithm, two pipelines,
// only one finished.

test "W118 G9: CKDpub on ExtendedKey — BUG-3 returns NotImplemented" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    // Build a public-only ExtendedKey
    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master_priv = try ExtendedKey.fromSeed(&seed);

    const master_pub = ExtendedKey{
        .key = master_priv.key, // placeholder; would be a compressed pubkey in real use
        .chain_code = master_priv.chain_code,
        .depth = 0,
        .parent_fingerprint = [_]u8{ 0, 0, 0, 0 },
        .child_index = 0,
        .is_private = false,
    };

    // BUG-3: CKDpub returns NotImplemented.  Core supports this.
    const r = master_pub.deriveChild(ctx, 0); // non-hardened
    try std.testing.expectError(error.NotImplemented, r);
}

// ===========================================================================
// G10: xpub/xprv base58check encoding (BUG-4)
// ===========================================================================
//
// BUG-4 (HIGH): ExtendedKey has no toXpub() / toXprv() / fromXpub() /
// fromXprv() methods.  The 78-byte BIP-32 serialization (version || depth ||
// fingerprint || child || chain_code || key) + base58check is the universal
// interchange format for HD wallets.  Watch-only setup, descriptor
// import / export, and hardware-wallet PSBT all rely on it.

test "W118 G10: ExtendedKey base58check serialization — BUG-4 missing" {
    const has_to_xprv = @hasDecl(ExtendedKey, "toXprv");
    const has_to_xpub = @hasDecl(ExtendedKey, "toXpub");
    const has_from_xprv = @hasDecl(ExtendedKey, "fromXprv");
    const has_from_xpub = @hasDecl(ExtendedKey, "fromXpub");

    // BUG-4: all four MUST be absent today.  Each presence flips this assertion.
    try std.testing.expect(!has_to_xprv);
    try std.testing.expect(!has_to_xpub);
    try std.testing.expect(!has_from_xprv);
    try std.testing.expect(!has_from_xpub);
}

// ===========================================================================
// G11: Parent fingerprint propagation
// ===========================================================================

test "W118 G11: parent fingerprint set on derived child" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try ExtendedKey.fromSeed(&seed);

    // Master fingerprint is zero
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &master.parent_fingerprint);

    // Child must have non-zero parent fingerprint (= hash160(parent_pubkey)[0..4])
    const child = try master.deriveChild(ctx, 0x80000000);
    const all_zero = std.mem.eql(u8, &child.parent_fingerprint, &[_]u8{ 0, 0, 0, 0 });
    try std.testing.expect(!all_zero);
}

// ===========================================================================
// G12: BIP-44/49/84/86 path generation
// ===========================================================================

test "W118 G12: BIP-44/49/84/86 path strings" {
    var buf: [64]u8 = undefined;

    // BIP-44 mainnet account 0 external 0
    const p44 = try ExtendedKey.getStandardPath(.bip44, 0, 0, 0, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/44'/0'/0'/0/0", p44);

    // BIP-49 mainnet
    var buf2: [64]u8 = undefined;
    const p49 = try ExtendedKey.getStandardPath(.bip49, 0, 0, 0, 5, &buf2);
    try std.testing.expectEqualSlices(u8, "m/49'/0'/0'/0/5", p49);

    // BIP-84 testnet change chain
    var buf3: [64]u8 = undefined;
    const p84 = try ExtendedKey.getStandardPath(.bip84, 1, 0, 1, 0, &buf3);
    try std.testing.expectEqualSlices(u8, "m/84'/1'/0'/1/0", p84);

    // BIP-86 mainnet
    var buf4: [64]u8 = undefined;
    const p86 = try ExtendedKey.getStandardPath(.bip86, 0, 0, 0, 0, &buf4);
    try std.testing.expectEqualSlices(u8, "m/86'/0'/0'/0/0", p86);
}

// ===========================================================================
// G13: PSBT BIP-174 v0 round-trip — create / serialize / deserialize
// ===========================================================================

test "W118 G13: PSBT v0 serialize/deserialize round-trip" {
    const allocator = std.testing.allocator;

    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    const spk = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x42} ** 20 ++ [_]u8{ 0x88, 0xac };
    outputs[0] = .{ .value = 50_000, .script_pubkey = &spk };

    const tx = types.Transaction{
        .version = 2,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = 0,
    };

    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    // PSBT version 0 (BIP-174)
    try std.testing.expectEqual(@as(u32, 0), psbt.version);

    // Serialize → magic prefix
    const serialized = try psbt.serialize(allocator);
    defer allocator.free(serialized);
    try std.testing.expectEqualSlices(u8, &psbt_mod.PSBT_MAGIC, serialized[0..5]);

    // Deserialize
    var psbt2 = try psbt_mod.Psbt.deserialize(allocator, serialized);
    defer psbt2.deinit();

    try std.testing.expectEqual(@as(u32, 0), psbt2.version);
    try std.testing.expectEqual(@as(usize, 1), psbt2.inputs.len);
    try std.testing.expectEqual(@as(usize, 1), psbt2.outputs.len);
}

// ===========================================================================
// G14: PSBT finalizer P2TR — BUG-5 (TODO at psbt.zig:833)
// ===========================================================================
//
// BUG-5 (MED): `finalizeInput` dispatches P2PKH / P2WPKH / P2SH / P2WSH but
// has no P2TR branch.  Tap_key_sig fields are parsed (parseInputMap) and
// stored on the PsbtInput, but `finalize` never builds the taproot witness
// stack from them.  Comment at psbt.zig:833 says "TODO: Add P2TR finalization".

test "W118 G14: PSBT P2TR finalize — BUG-5 TODO, no taproot branch" {
    const allocator = std.testing.allocator;

    // Build a 1-in 1-out tx with a P2TR-shaped input UTXO
    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{
        .previous_output = .{ .hash = [_]u8{0xCC} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    const out_spk = [_]u8{ 0x51, 0x20 } ++ [_]u8{0x33} ** 32; // OP_1 PUSH32 ...
    outputs[0] = .{ .value = 50_000, .script_pubkey = &out_spk };

    const tx = types.Transaction{
        .version = 2,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = 0,
    };

    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Add a P2TR witness_utxo
    const in_spk = [_]u8{ 0x51, 0x20 } ++ [_]u8{0x44} ** 32;
    try psbt.addInputUtxo(0, .{ .value = 100_000, .script_pubkey = &in_spk });

    // Add a fake schnorr signature (BIP-371 tap_key_sig)
    const fake_sig = [_]u8{0xAB} ** 64;
    psbt.inputs[0].tap_key_sig = try allocator.dupe(u8, &fake_sig);

    // BUG-5: finalizeInput returns without error, but doesn't populate
    // final_script_witness because no .p2tr branch exists.  After the call,
    // isFinalized() is still false.
    try psbt.finalizeInput(0);
    try std.testing.expect(!psbt.inputs[0].isFinalized());
}

// ===========================================================================
// G15: PSBT combine — Combiner role
// ===========================================================================

test "W118 G15: PSBT combine merges partial sigs across two parts" {
    const allocator = std.testing.allocator;

    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{
        .previous_output = .{ .hash = [_]u8{0xDD} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    const spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x55} ** 20;
    outputs[0] = .{ .value = 90_000, .script_pubkey = &spk };

    const tx = types.Transaction{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    var a = try psbt_mod.Psbt.create(allocator, tx);
    defer a.deinit();
    var b = try psbt_mod.Psbt.create(allocator, tx);
    defer b.deinit();

    // Two distinct pubkeys, two distinct sigs — combine should produce both
    const pk1 = hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    const pk2 = hexToBytes("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    const sig1 = [_]u8{0x11} ** 64;
    const sig2 = [_]u8{0x22} ** 64;

    try a.addPartialSig(0, pk1, &sig1);
    try b.addPartialSig(0, pk2, &sig2);

    var combined = try psbt_mod.Psbt.combine(allocator, &[_]*psbt_mod.Psbt{ &a, &b });
    defer combined.deinit();

    try std.testing.expectEqual(@as(u32, 2), combined.inputs[0].partial_sigs.count());
}

// ===========================================================================
// G16: PSBT base64 encode/decode
// ===========================================================================

test "W118 G16: PSBT base64 round-trip" {
    const allocator = std.testing.allocator;

    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{
        .previous_output = .{ .hash = [_]u8{0xEE} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    const spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x66} ** 20;
    outputs[0] = .{ .value = 75_000, .script_pubkey = &spk };

    const tx = types.Transaction{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    const b64 = try psbt.toBase64(allocator);
    defer allocator.free(b64);

    // Base64 must contain only standard alphabet characters
    for (b64) |c| {
        const ok = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '+' or c == '/' or c == '=';
        try std.testing.expect(ok);
    }

    var decoded = try psbt_mod.Psbt.fromBase64(allocator, b64);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u32, 0), decoded.version);
    try std.testing.expectEqual(@as(usize, 1), decoded.inputs.len);
    try std.testing.expectEqual(@as(usize, 1), decoded.outputs.len);
}

// ===========================================================================
// G17: PSBT v2 / BIP-370 — BUG-6 not supported
// ===========================================================================
//
// BUG-6 (HIGH): `PSBT_HIGHEST_VERSION = 0` (psbt.zig:33).  The deserializer
// at psbt.zig:1427 rejects any v2 PSBT explicitly:
//   if (version > PSBT_HIGHEST_VERSION) return PsbtError.UnsupportedVersion;
// BIP-370 added PSBT_IN_PREVIOUS_TXID (0x0e), PSBT_IN_OUTPUT_INDEX (0x0f),
// PSBT_IN_SEQUENCE (0x10), PSBT_OUT_AMOUNT (0x03), PSBT_OUT_SCRIPT (0x04) —
// none of these constants are defined.

test "W118 G17: PSBT v2 BIP-370 — BUG-6 not supported" {
    try std.testing.expectEqual(@as(u32, 0), psbt_mod.PSBT_HIGHEST_VERSION);

    // Construct a minimal valid v2 global map
    const v2_bytes = [_]u8{
        // Magic "psbt\xff"
        0x70, 0x73, 0x62, 0x74, 0xff,
        // key_len=1, key=PSBT_GLOBAL_VERSION (0xfb)
        0x01, 0xfb,
        // value_len=4, value=2 (LE)
        0x04, 0x02, 0x00, 0x00, 0x00,
        // separator
        0x00,
    };

    const r = psbt_mod.Psbt.deserialize(std.testing.allocator, &v2_bytes);
    try std.testing.expectError(error.UnsupportedVersion, r);

    // BIP-370 key types must NOT be defined as constants
    const has_prev_txid = @hasDecl(psbt_mod, "PSBT_IN_PREVIOUS_TXID");
    const has_output_index = @hasDecl(psbt_mod, "PSBT_IN_OUTPUT_INDEX");
    const has_sequence = @hasDecl(psbt_mod, "PSBT_IN_SEQUENCE");
    const has_out_amount = @hasDecl(psbt_mod, "PSBT_OUT_AMOUNT");
    const has_out_script = @hasDecl(psbt_mod, "PSBT_OUT_SCRIPT");
    try std.testing.expect(!has_prev_txid);
    try std.testing.expect(!has_output_index);
    try std.testing.expect(!has_sequence);
    try std.testing.expect(!has_out_amount);
    try std.testing.expect(!has_out_script);
}

// ===========================================================================
// G18: PSBT analyze — next_role progression
// ===========================================================================

test "W118 G18: PSBT analyze reports correct next_role" {
    const allocator = std.testing.allocator;

    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{
        .previous_output = .{ .hash = [_]u8{0xFF} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFE,
        .witness = &[_][]const u8{},
    };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    const spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x77} ** 20;
    outputs[0] = .{ .value = 100_000, .script_pubkey = &spk };

    const tx = types.Transaction{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Fresh PSBT — no sigs → next is "updater"
    const r1 = psbt.analyze();
    try std.testing.expectEqualStrings("updater", r1.next_role);
    try std.testing.expectEqual(@as(usize, 0), r1.inputs_signed);

    // Add a partial sig → next is "signer" (more sigs may be needed)
    // For a single-input single-sig PSBT this jumps to "finalizer" because all
    // inputs have at least one sig; that's the documented role progression in
    // psbt.zig::analyze (signed == total → finalizer).
    const pk = hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    const sig = [_]u8{0xAA} ** 64;
    try psbt.addPartialSig(0, pk, &sig);

    const r2 = psbt.analyze();
    try std.testing.expectEqualStrings("finalizer", r2.next_role);
    try std.testing.expectEqual(@as(usize, 1), r2.inputs_signed);
}

// ===========================================================================
// G19: BIP-125 bumpfee RPC — BUG-7 MISSING ENTIRELY
// ===========================================================================
//
// BUG-7 (HIGH): no `bumpfee` RPC in rpc.zig.  Bitcoin Core's bumpfee:
//  - validates the original tx exists in the wallet's mempool
//  - constructs a new tx with a higher fee
//  - signs and broadcasts it (or returns the PSBT)
// Reference: bitcoin-core/src/wallet/rpc/spend.cpp::bumpfee.
//
// This test scans rpc.zig for the handler name; absence is the bug.

test "W118 G19: bumpfee RPC — BUG-7 FIXED (FIX-61)" {
    // FIX-61 closed BUG-7: `wallet_mod.bumpFee` now exists and implements
    // the BIP-125 fee-bump logic (reduce a wallet-owned change output by
    // `new_fee - orig_fee`, re-sign every input, return the new tx).
    // The RPC `bumpfee` dispatches to it via `handleBumpFee` in rpc.zig.
    const has_bump_fee = @hasDecl(wallet_mod, "bumpFee");
    try std.testing.expect(has_bump_fee);
}

// ===========================================================================
// G20: psbtbumpfee RPC — BUG-8 MISSING ENTIRELY
// ===========================================================================
//
// BUG-8 (HIGH): no `psbtbumpfee` either.  Same root cause as G19 — the
// wallet has no bumpfee infrastructure at all.
// Reference: bitcoin-core/src/wallet/rpc/spend.cpp::psbtbumpfee.

test "W118 G20: psbtbumpfee RPC — BUG-8 FIXED (FIX-61)" {
    // FIX-61 closed BUG-8: `wallet_mod.psbtBumpFee` now exists. It runs
    // the same change-reduction flow as `bumpFee` but emits a BIP-174 PSBT
    // (so a separate signer / hardware wallet can finalize it).
    const has_psbt_bump = @hasDecl(wallet_mod, "psbtBumpFee");
    try std.testing.expect(has_psbt_bump);
}

// ===========================================================================
// G21: createTransaction sequence — BIP-125 signaling
// ===========================================================================

test "W118 G21: createTransaction sets BIP-125 sequence (0xFFFFFFFE)" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    // Build a P2WPKH SPK
    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x80} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const out = wallet_mod.TxOutput{ .value = 90_000, .script_pubkey = &spk };

    const tx = try wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod.TxOutput{out},
        null,
        .{ .fee_rate = 1 },
    );
    defer {
        for (tx.inputs[0].witness) |item| allocator.free(item);
        allocator.free(tx.inputs[0].witness);
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // BIP-125 signaling: sequence < 0xFFFFFFFE means RBF-opt-in (per BIP-125,
    // any sequence != 0xFFFFFFFF and != 0xFFFFFFFE arguably).  Core's wallet
    // default is 0xFFFFFFFD — opt-in RBF, locktime active.  Clearbit emits
    // 0xFFFFFFFE which is *not* RBF-opt-in under BIP-125 strict reading; the
    // test documents this default.  See wallet.zig:1922.
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFE), tx.inputs[0].sequence);
}

// ===========================================================================
// G22: replaceable option absent (BUG-9)
// ===========================================================================
//
// BUG-9 (MED): `CreateTxOptions` (wallet.zig:1877) has no `replaceable`
// field; callers cannot override the hard-coded `0xFFFFFFFE` to disable
// or strengthen RBF signaling.  Core's `sendtoaddress` / `walletcreatefundedpsbt`
// accept a `replaceable` parameter — clearbit ignores it.

test "W118 G22: CreateTxOptions.replaceable — BUG-9 FIXED (FIX-61)" {
    // FIX-61 closed BUG-9: `CreateTxOptions.replaceable` now exists.
    // Default `false` preserves the historical `0xFFFFFFFE` sequence
    // emitted by `createTransaction` (so G21 — which asserts that
    // sequence — keeps passing). Setting `replaceable = true` flips
    // every input's sequence to `0xFFFFFFFD`, BIP-125's canonical
    // RBF-opt-in signal. The `bumpFee` replacement path uses this
    // internally so the new tx is itself bumpable.
    const opts: wallet_mod.CreateTxOptions = .{};

    _ = opts.fee_rate;
    _ = opts.current_height;
    _ = opts.anti_fee_sniping;
    _ = opts.sighash_type;

    const has_replaceable = @hasField(wallet_mod.CreateTxOptions, "replaceable");
    try std.testing.expect(has_replaceable);

    // Default must be `false` so G21 (`sequence = 0xFFFFFFFE`) still holds.
    try std.testing.expectEqual(false, opts.replaceable);
}

// ===========================================================================
// G23: createTransaction signs all inputs
// ===========================================================================

test "W118 G23: createTransaction populates witness/scriptSig on every input" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    const utxo_a = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x91} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };
    const utxo_b = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x92} ** 32, .index = 0 },
        .output = .{ .value = 200_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const out = wallet_mod.TxOutput{ .value = 280_000, .script_pubkey = &spk };

    const tx = try wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{ utxo_a, utxo_b },
        &[_]wallet_mod.TxOutput{out},
        null,
        .{ .fee_rate = 1 },
    );
    defer {
        for (tx.inputs) |inp| {
            for (inp.witness) |item| allocator.free(item);
            allocator.free(inp.witness);
        }
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    try std.testing.expectEqual(@as(usize, 2), tx.inputs.len);
    // Both inputs must have populated witness (P2WPKH)
    try std.testing.expectEqual(@as(usize, 2), tx.inputs[0].witness.len);
    try std.testing.expectEqual(@as(usize, 2), tx.inputs[1].witness.len);
}

// ===========================================================================
// G24: createTransaction over-spend rejected pre-sign (BUG-10 — FIXED in FIX-60)
// ===========================================================================
//
// BUG-10 (HIGH): createTransaction did not check inputs-sum >= outputs-sum.
// A caller could request outputs whose sum exceeded the inputs' value and
// the function happily signed the (consensus-invalid) transaction. Core's
// CreateTransactionInternal validates this and rejects with
// "Insufficient funds" before signing.
//
// FIX-60: createTransaction now computes sum_in / sum_out + estimated fee
// BEFORE the signing loop. Returns `error.InsufficientFunds` when outputs
// alone exceed inputs, and `error.FeeNotCovered` when only the fee tips
// the scale.

test "W118 G24: createTransaction over-spend — outputs exceed inputs returns InsufficientFunds" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    // Input value 10_000, output value 1_000_000 — over-spend by 99x.
    // outputs alone (1_000_000) exceed inputs (10_000) → InsufficientFunds.
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xA1} ** 32, .index = 0 },
        .output = .{ .value = 10_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };
    const bad = wallet_mod.TxOutput{ .value = 1_000_000, .script_pubkey = &spk };

    const result = wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod.TxOutput{bad},
        null,
        .{ .fee_rate = 1 },
    );
    // Pre-sign rejection — no transaction returned, no signature produced.
    try std.testing.expectError(error.InsufficientFunds, result);
}

// G24b: sufficient funds still produce a signed tx (sanity — make sure we
// didn't over-trigger the new check).
test "W118 G24b: createTransaction with sufficient funds still signs" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    // 100k input, 90k output, plenty of margin for fee. Must succeed and
    // populate the witness on every input (signing must run to completion).
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xA2} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };
    const good = wallet_mod.TxOutput{ .value = 90_000, .script_pubkey = &spk };

    const tx = try wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod.TxOutput{good},
        null,
        .{ .fee_rate = 1 },
    );
    defer {
        for (tx.inputs) |inp| {
            for (inp.witness) |item| allocator.free(item);
            allocator.free(inp.witness);
        }
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }
    try std.testing.expectEqual(@as(usize, 1), tx.inputs.len);
    // Witness populated → signInput ran (proves we got past the new check).
    try std.testing.expectEqual(@as(usize, 2), tx.inputs[0].witness.len);
}

// G24c: outputs == inputs at a non-zero fee_rate is a fee-not-covered error,
// distinct from insufficient funds. Documents that the new check has two
// distinct error paths.
test "W118 G24c: createTransaction outputs == inputs at fee_rate=1 returns FeeNotCovered" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    // sum_in == sum_out, fee_rate > 0 → no headroom for fee → FeeNotCovered.
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xA3} ** 32, .index = 0 },
        .output = .{ .value = 50_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };
    const tight = wallet_mod.TxOutput{ .value = 50_000, .script_pubkey = &spk };

    const result = wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod.TxOutput{tight},
        null,
        .{ .fee_rate = 1 },
    );
    try std.testing.expectError(error.FeeNotCovered, result);
}

// G24d: with `fee_rate = 0`, outputs == inputs is allowed (no fee budget
// means no fee shortfall). Verifies FeeNotCovered is a fee-rate-dependent
// distinct error, not just a no-margin error.
test "W118 G24d: createTransaction outputs == inputs at fee_rate=0 succeeds" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xA4} ** 32, .index = 0 },
        .output = .{ .value = 50_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };
    const tight = wallet_mod.TxOutput{ .value = 50_000, .script_pubkey = &spk };

    const tx = try wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod.TxOutput{tight},
        null,
        .{ .fee_rate = 0 },
    );
    defer {
        for (tx.inputs) |inp| {
            for (inp.witness) |item| allocator.free(item);
            allocator.free(inp.witness);
        }
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }
    try std.testing.expectEqual(@as(usize, 1), tx.inputs.len);
}

// ===========================================================================
// G25: Dust output rejection (BUG-11)
// ===========================================================================
//
// BUG-11 (MED): no dust check.  createTransaction accepts a 100-sat P2PKH
// output even though DUST_THRESHOLD_P2PKH = 546.  Bitcoin Core's
// IsStandardTx rejects dust on relay.  Clearbit's wallet emits it.

test "W118 G25: createTransaction dust output — BUG-11 no dust check" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    var p2pkh_spk: [25]u8 = undefined;
    p2pkh_spk[0] = 0x76;
    p2pkh_spk[1] = 0xa9;
    p2pkh_spk[2] = 0x14;
    @memcpy(p2pkh_spk[3..23], &pk_hash);
    p2pkh_spk[23] = 0x88;
    p2pkh_spk[24] = 0xac;

    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xB1} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    // 100 sats output — way below the 546-sat dust threshold.
    const dust = wallet_mod.TxOutput{ .value = 100, .script_pubkey = &p2pkh_spk };

    const tx = try wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod.TxOutput{dust},
        null,
        .{ .fee_rate = 1 },
    );
    defer {
        for (tx.inputs) |inp| {
            for (inp.witness) |item| allocator.free(item);
            allocator.free(inp.witness);
        }
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // BUG-11: the tx was built with the dust output intact.  Core would have
    // rejected this or warned.  The constant DUST_THRESHOLD_P2PKH (546)
    // exists in wallet.zig:2050 but is never referenced by createTransaction.
    try std.testing.expectEqual(@as(i64, 100), tx.outputs[0].value);
    try std.testing.expect(tx.outputs[0].value < wallet_mod.DUST_THRESHOLD_P2PKH);
}

// ===========================================================================
// G26: Anti-fee-sniping locktime
// ===========================================================================

test "W118 G26: anti-fee-sniping sets locktime = current_height" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xC1} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };
    const out = wallet_mod.TxOutput{ .value = 90_000, .script_pubkey = &spk };

    const tx = try wallet_mod.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod.TxOutput{out},
        null,
        .{ .fee_rate = 1, .current_height = 800_000, .anti_fee_sniping = true },
    );
    defer {
        for (tx.inputs) |inp| {
            for (inp.witness) |item| allocator.free(item);
            allocator.free(inp.witness);
        }
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // Locktime set to current_height (exact — BUG-12 of W113 audit notes the
    // missing random -100 offset, not reproduced here as W113 owns that gate).
    try std.testing.expectEqual(@as(u32, 800_000), tx.lock_time);
}

// ===========================================================================
// G27: addUtxo / removeUtxo
// ===========================================================================

test "W118 G27: addUtxo + removeUtxo + getBalance round-trip" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const u = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xD1} ** 32, .index = 0 },
        .output = .{ .value = 50_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 1,
    };

    try w.addUtxo(u);
    try std.testing.expectEqual(@as(i64, 50_000), w.getBalance());

    const removed = w.removeUtxo(u.outpoint);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(i64, 0), w.getBalance());

    // Removing twice → false
    const second = w.removeUtxo(u.outpoint);
    try std.testing.expect(!second);
}

// ===========================================================================
// G28: lockunspent / isLockedCoin
// ===========================================================================

test "W118 G28: lockCoin / unlockCoin / isLockedCoin" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const op = types.OutPoint{ .hash = [_]u8{0xE1} ** 32, .index = 5 };

    try std.testing.expect(!w.isLockedCoin(op));

    const r = try w.lockCoin(op);
    try std.testing.expect(r); // first call → returned true
    try std.testing.expect(w.isLockedCoin(op));

    const r2 = try w.lockCoin(op);
    try std.testing.expect(!r2); // second call → already locked

    const ok = w.unlockCoin(op);
    try std.testing.expect(ok);
    try std.testing.expect(!w.isLockedCoin(op));

    // unlockCoin on already-unlocked → false
    const ok2 = w.unlockCoin(op);
    try std.testing.expect(!ok2);
}

// ===========================================================================
// G29: unlockAllCoins — function exists, but not wired (BUG-12)
// ===========================================================================
//
// BUG-12 (MED): `wallet.unlockAllCoins()` exists (wallet.zig:724) but the
// `lockunspent` RPC dispatcher (rpc.zig:10181) doesn't expose an
// "unlock all" code path.  Core's lockunspent RPC accepts `unlock=true`
// with an empty `transactions=[]` array to mean "unlock all", but clearbit's
// handleLockUnspent doesn't implement that semantic.

test "W118 G29: unlockAllCoins exists but RPC integration missing — BUG-12" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const op1 = types.OutPoint{ .hash = [_]u8{0xF1} ** 32, .index = 0 };
    const op2 = types.OutPoint{ .hash = [_]u8{0xF2} ** 32, .index = 1 };
    _ = try w.lockCoin(op1);
    _ = try w.lockCoin(op2);
    try std.testing.expectEqual(@as(usize, 2), w.lockedCoinCount());

    // Function exists — call it.
    w.unlockAllCoins();
    try std.testing.expectEqual(@as(usize, 0), w.lockedCoinCount());

    // Document that unlockAllCoins is declared.
    const decl_exists = @hasDecl(Wallet, "unlockAllCoins");
    try std.testing.expect(decl_exists);

    // BUG-12: the dispatch through `lockunspent` (rpc.zig) does not wire
    // through to this code path on `unlock=true, transactions=[]`.  Not
    // testable from this audit harness without spinning a full RPC stack;
    // documented via the dispatcher comment in rpc.zig.
}

// ===========================================================================
// G30: getbalance honors immature-coinbase + minconf (BUG-13 — FIXED in FIX-60)
// ===========================================================================
//
// BUG-13 (HIGH): the wallet had `getSpendableBalance` (excludes immature
// coinbase) but the `getbalance` RPC handler (rpc.zig) returned
// `wallet.getBalance()` — the unfiltered sum, including immature coinbase
// — and ignored the `minconf` argument.
//
// FIX-60: `wallet.getBalanceMinConf(minconf)` filters immature coinbase
// (always) AND honors the `minconf` parameter. The RPC handler now parses
// `params[1]` and calls the new method. `getBalance()` itself is preserved
// for legacy callers / internal "raw total" use.

test "W118 G30: getBalanceMinConf excludes immature coinbase" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    w.setTipHeight(1000);

    // 1 mature non-coinbase UTXO + 1 immature coinbase UTXO.
    // Clearbit's depth convention: depth = tip_height - utxo.height.
    const mature = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 10_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
        .is_coinbase = false,
        .height = 994, // depth = 1000 - 994 = 6
    };
    const immature_cb = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x02} ** 32, .index = 0 },
        .output = .{ .value = 5_000_000_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 1,
        .is_coinbase = true,
        .height = 999, // depth = 1, below COINBASE_MATURITY=100
    };
    try w.addUtxo(mature);
    try w.addUtxo(immature_cb);

    // Legacy unfiltered helper — preserved.
    try std.testing.expectEqual(@as(i64, 10_000 + 5_000_000_000), w.getBalance());
    try std.testing.expectEqual(@as(i64, 5_000_000_000), w.getImmatureBalance());

    // FIX-60: getBalanceMinConf excludes the immature coinbase even at
    // minconf=0 — matches Core's `CWallet::GetBalance` which always
    // filters immature coinbase.
    try std.testing.expectEqual(@as(i64, 10_000), w.getBalanceMinConf(0));
    // Same value as the (legacy) spendable balance helper.
    try std.testing.expectEqual(w.getSpendableBalance(), w.getBalanceMinConf(0));
}

test "W118 G30b: getBalanceMinConf honors minconf parameter" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    w.setTipHeight(1000);

    // Three non-coinbase UTXOs at depths 0, 5, 10.
    const u_unconf = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xD0} ** 32, .index = 0 },
        .output = .{ .value = 1_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 0,
        .is_coinbase = false,
        .height = 1000, // depth 0 (mempool / tip block)
    };
    const u_5conf = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xD1} ** 32, .index = 0 },
        .output = .{ .value = 2_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 5,
        .is_coinbase = false,
        .height = 995, // depth 5
    };
    const u_10conf = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xD2} ** 32, .index = 0 },
        .output = .{ .value = 4_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 10,
        .is_coinbase = false,
        .height = 990, // depth 10
    };
    try w.addUtxo(u_unconf);
    try w.addUtxo(u_5conf);
    try w.addUtxo(u_10conf);

    // minconf=0: all three counted.
    try std.testing.expectEqual(@as(i64, 7_000), w.getBalanceMinConf(0));
    // minconf=1: drops the 0-conf UTXO.
    try std.testing.expectEqual(@as(i64, 6_000), w.getBalanceMinConf(1));
    // minconf=6: drops 0-conf + 5-conf, keeps the 10-conf.
    try std.testing.expectEqual(@as(i64, 4_000), w.getBalanceMinConf(6));
    // minconf=11: drops all three.
    try std.testing.expectEqual(@as(i64, 0), w.getBalanceMinConf(11));
}

test "W118 G30c: getBalanceMinConf excludes immature coinbase even at minconf=0" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    // Tip at height 150 means a coinbase at height 100 has depth 50 (< 100).
    w.setTipHeight(150);

    const cb_depth_50 = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xE0} ** 32, .index = 0 },
        .output = .{ .value = 5_000_000_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 50,
        .is_coinbase = true,
        .height = 100, // depth = 50, below COINBASE_MATURITY=100
    };
    try w.addUtxo(cb_depth_50);

    // Immature coinbase excluded at every minconf, including 0.
    try std.testing.expectEqual(@as(i64, 0), w.getBalanceMinConf(0));
    try std.testing.expectEqual(@as(i64, 0), w.getBalanceMinConf(1));
    try std.testing.expectEqual(@as(i64, 0), w.getBalanceMinConf(50));

    // Now mature it: tip at 200, depth = 100 = COINBASE_MATURITY → counted.
    w.setTipHeight(200);
    try std.testing.expectEqual(@as(i64, 5_000_000_000), w.getBalanceMinConf(0));
    try std.testing.expectEqual(@as(i64, 5_000_000_000), w.getBalanceMinConf(100));
    // But minconf=101 drops it (depth 100 < 101).
    try std.testing.expectEqual(@as(i64, 0), w.getBalanceMinConf(101));
}

// ===========================================================================
// FIX-61: bumpFee / psbtBumpFee round-trip and reject paths
// ===========================================================================
//
// These tests exercise the new W118 BUG-7 + BUG-8 closures. They build a
// self-spending tx (one wallet-owned P2WPKH input, one external recipient,
// one wallet-owned change output) and run each branch of `bumpFee` and
// `psbtBumpFee`.

const wallet_mod_bump = wallet_mod; // alias for clarity below

/// Build a single-input, single-recipient, single-change RBF tx for the
/// bumpfee tests. Returns the signed transaction + the prevout + the
/// change-output index.
fn buildBumpFixture(
    allocator: std.mem.Allocator,
    w: *Wallet,
    input_value: i64,
    payment_value: i64,
    fee_rate: u64,
    replaceable: bool,
) !struct {
    tx: types.Transaction,
    prevout: OwnedUtxo,
    change_index: usize,
    /// Heap-allocated buffers the test must free *separately* from
    /// `freeTx(tx)` — `createTransaction` aliases output script_pubkey
    /// bytes directly into `tx.outputs[i].script_pubkey`, so the test
    /// owner has to free those buffers itself (and BEFORE freeing the
    /// outputs slice, otherwise `tx.outputs[i]` is dangling).
    own_spk: []u8,
    ext_spk: []u8,
} {
    const ki = try w.generateKey();
    // Wallet-owned scriptPubKey for the prevout AND the change output.
    const own_spk = try w.getScriptPubKey(ki, .p2wpkh);
    errdefer allocator.free(own_spk);

    // External recipient SPK (not wallet-owned). Use a different pkh.
    const ext_pkh = [_]u8{0xAB} ** 20;
    const ext_spk_buf = try allocator.alloc(u8, 22);
    errdefer allocator.free(ext_spk_buf);
    ext_spk_buf[0] = 0x00;
    ext_spk_buf[1] = 0x14;
    @memcpy(ext_spk_buf[2..22], &ext_pkh);

    // Compute change as input - payment - rough fee. The fee budget must
    // be ≥ createTransaction's internal estimateInputSize-based vsize
    // (10 overhead + 68 P2WPKH input + 34 × num_outputs). For a 1-input,
    // 2-output tx that's 146 vbytes. We use a 200-vbyte budget at the
    // requested fee_rate to leave headroom for the bumpfee delta tests
    // and stay comfortably above the pre-sign FeeNotCovered guard.
    const rough_vsize: u64 = 200;
    const rough_fee: i64 = @intCast(rough_vsize * fee_rate);
    const change_value: i64 = input_value - payment_value - rough_fee;

    const prevout = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xF1} ** 32, .index = 0 },
        .output = .{ .value = input_value, .script_pubkey = own_spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const pay_out = wallet_mod_bump.TxOutput{
        .value = payment_value,
        .script_pubkey = ext_spk_buf,
    };
    const change_out = wallet_mod_bump.TxOutput{
        .value = change_value,
        .script_pubkey = own_spk,
    };

    const tx = try wallet_mod_bump.createTransaction(
        w,
        &[_]OwnedUtxo{prevout},
        &[_]wallet_mod_bump.TxOutput{pay_out},
        change_out,
        .{ .fee_rate = fee_rate, .replaceable = replaceable },
    );

    return .{
        .tx = tx,
        .prevout = prevout,
        .change_index = 1, // single payment then change → change at index 1
        .own_spk = own_spk,
        .ext_spk = ext_spk_buf,
    };
}

fn freeTx(allocator: std.mem.Allocator, tx: types.Transaction) void {
    for (tx.inputs) |inp| {
        for (inp.witness) |w| allocator.free(w);
        allocator.free(inp.witness);
        if (inp.script_sig.len > 0) allocator.free(inp.script_sig);
    }
    allocator.free(tx.inputs);
    allocator.free(tx.outputs);
}

test "W118 G19b: bumpFee round-trip — RBF-signaled tx, default delta" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const fx = try buildBumpFixture(allocator, &w, 100_000, 50_000, 1, true);
    defer {
        freeTx(allocator, fx.tx);
        allocator.free(fx.own_spk);
        allocator.free(fx.ext_spk);
    }

    // BIP-125 signaled: replaceable=true → sequence 0xFFFFFFFD < 0xFFFFFFFE.
    try std.testing.expect(fx.tx.inputs[0].sequence < 0xFFFFFFFE);

    const result = try wallet_mod_bump.bumpFee(
        &w,
        &fx.tx,
        &[_]OwnedUtxo{fx.prevout},
        .{}, // default: 1 sat/vB on top of original
    );
    defer freeTx(allocator, result.new_tx);

    try std.testing.expect(result.new_fee > result.orig_fee);
    try std.testing.expectEqual(@as(usize, 1), result.change_index);

    // Replacement signals BIP-125 too (so it's itself bumpable).
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFD), result.new_tx.inputs[0].sequence);

    // Inputs+outputs counts preserved.
    try std.testing.expectEqual(fx.tx.inputs.len, result.new_tx.inputs.len);
    try std.testing.expectEqual(fx.tx.outputs.len, result.new_tx.outputs.len);

    // Change output reduced exactly by (new_fee - orig_fee).
    const delta: i64 = result.new_fee - result.orig_fee;
    try std.testing.expectEqual(
        fx.tx.outputs[fx.change_index].value - delta,
        result.new_tx.outputs[result.change_index].value,
    );

    // Payment output untouched.
    try std.testing.expectEqual(
        fx.tx.outputs[0].value,
        result.new_tx.outputs[0].value,
    );

    // Witness regenerated (re-signed).
    try std.testing.expect(result.new_tx.inputs[0].witness.len > 0);
}

test "W118 G19c: bumpFee rejects non-BIP-125 tx" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    // replaceable=false → sequence 0xFFFFFFFE → no RBF signal.
    const fx = try buildBumpFixture(allocator, &w, 100_000, 50_000, 1, false);
    defer {
        freeTx(allocator, fx.tx);
        allocator.free(fx.own_spk);
        allocator.free(fx.ext_spk);
    }
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFE), fx.tx.inputs[0].sequence);

    const err = wallet_mod_bump.bumpFee(
        &w,
        &fx.tx,
        &[_]OwnedUtxo{fx.prevout},
        .{},
    );
    try std.testing.expectError(wallet_mod_bump.BumpFeeError.NotBIP125Replaceable, err);
}

test "W118 G19d: bumpFee with `force = true` accepts non-BIP-125 tx" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const fx = try buildBumpFixture(allocator, &w, 100_000, 50_000, 1, false);
    defer {
        freeTx(allocator, fx.tx);
        allocator.free(fx.own_spk);
        allocator.free(fx.ext_spk);
    }

    const result = try wallet_mod_bump.bumpFee(
        &w,
        &fx.tx,
        &[_]OwnedUtxo{fx.prevout},
        .{ .force = true },
    );
    defer freeTx(allocator, result.new_tx);

    try std.testing.expect(result.new_fee > result.orig_fee);
}

test "W118 G19e: bumpFee rejects when no change output is owned" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const ki = try w.generateKey();
    const own_spk = try w.getScriptPubKey(ki, .p2wpkh);
    defer allocator.free(own_spk);

    // Two external (non-wallet) outputs only.
    const ext1 = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;
    const ext2 = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;

    const prevout = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xF2} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = own_spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const tx = try wallet_mod_bump.createTransaction(
        &w,
        &[_]OwnedUtxo{prevout},
        &[_]wallet_mod_bump.TxOutput{
            .{ .value = 40_000, .script_pubkey = &ext1 },
            .{ .value = 40_000, .script_pubkey = &ext2 },
        },
        null,
        .{ .fee_rate = 1, .replaceable = true },
    );
    defer freeTx(allocator, tx);

    const err = wallet_mod_bump.bumpFee(
        &w,
        &tx,
        &[_]OwnedUtxo{prevout},
        .{},
    );
    try std.testing.expectError(wallet_mod_bump.BumpFeeError.NoChangeOutput, err);
}

test "W118 G19f: bumpFee rejects when reducing change crosses the dust threshold" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    // Make change tiny — barely above the P2WPKH dust threshold (294) —
    // so a single 1 sat/vB bump on a ~146-vB tx (delta ≈ 146) tips it
    // below dust.
    //
    // Fixture math: input = 100_000, payment = 99_500, change = 295 (1 sat
    // above dust). Fee = sum_in - sum_out = 100_000 - 99_500 - 295 = 205
    // sats — covers the ~146-vB est_fee at 1 sat/vB with headroom for
    // createTransaction's pre-sign FeeNotCovered check. The bumpfee
    // delta (≥ 146 sats) is much larger than the 1-sat headroom above
    // dust, so DustAfterReduce fires.
    const ki = try w.generateKey();
    const own_spk = try w.getScriptPubKey(ki, .p2wpkh);
    defer allocator.free(own_spk);

    const ext_pkh = [_]u8{0xCC} ** 20;
    const ext_spk = [_]u8{ 0x00, 0x14 } ++ ext_pkh;

    const prevout = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xF3} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = own_spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const tx = try wallet_mod_bump.createTransaction(
        &w,
        &[_]OwnedUtxo{prevout},
        &[_]wallet_mod_bump.TxOutput{.{ .value = 99_500, .script_pubkey = &ext_spk }},
        wallet_mod_bump.TxOutput{ .value = 295, .script_pubkey = own_spk }, // 1 sat above P2WPKH dust (294)
        .{ .fee_rate = 1, .replaceable = true },
    );
    defer freeTx(allocator, tx);

    const err = wallet_mod_bump.bumpFee(
        &w,
        &tx,
        &[_]OwnedUtxo{prevout},
        .{},
    );
    try std.testing.expectError(wallet_mod_bump.BumpFeeError.DustAfterReduce, err);
}

test "W118 G20b: psbtBumpFee round-trip — produces a PSBT with reduced change" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const fx = try buildBumpFixture(allocator, &w, 100_000, 50_000, 1, true);
    defer {
        freeTx(allocator, fx.tx);
        allocator.free(fx.own_spk);
        allocator.free(fx.ext_spk);
    }

    var result = try wallet_mod_bump.psbtBumpFee(
        &w,
        &fx.tx,
        &[_]OwnedUtxo{fx.prevout},
        .{},
    );
    defer result.psbt.deinit();

    try std.testing.expect(result.new_fee > result.orig_fee);
    try std.testing.expectEqual(@as(usize, 1), result.change_index);

    // PSBT carries an unsigned tx: scriptSig/witness empty on every input.
    try std.testing.expectEqual(fx.tx.inputs.len, result.psbt.tx.inputs.len);
    for (result.psbt.tx.inputs) |inp| {
        try std.testing.expectEqual(@as(usize, 0), inp.script_sig.len);
        try std.testing.expectEqual(@as(usize, 0), inp.witness.len);
        // Replacement signals BIP-125.
        try std.testing.expectEqual(@as(u32, 0xFFFFFFFD), inp.sequence);
    }

    // Change output value matches the new_change_val computed from delta.
    const delta: i64 = result.new_fee - result.orig_fee;
    try std.testing.expectEqual(
        fx.tx.outputs[fx.change_index].value - delta,
        result.psbt.tx.outputs[result.change_index].value,
    );

    // PSBT v0 (BIP-174).
    try std.testing.expectEqual(@as(u32, 0), result.psbt.version);
}

test "W118 G20c: psbtBumpFee rejects non-BIP-125 tx" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();

    const fx = try buildBumpFixture(allocator, &w, 100_000, 50_000, 1, false);
    defer {
        freeTx(allocator, fx.tx);
        allocator.free(fx.own_spk);
        allocator.free(fx.ext_spk);
    }

    const err = wallet_mod_bump.psbtBumpFee(
        &w,
        &fx.tx,
        &[_]OwnedUtxo{fx.prevout},
        .{},
    );
    try std.testing.expectError(wallet_mod_bump.BumpFeeError.NotBIP125Replaceable, err);
}

test "W118 G22b: createTransaction with replaceable=true emits BIP-125 sequence" {
    const ctx = makeContext() orelse return;
    defer destroyContext(ctx);

    const allocator = std.testing.allocator;
    var w = try Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00;
    spk[1] = 0x14;
    @memcpy(spk[2..22], &pk_hash);

    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x83} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const out = wallet_mod_bump.TxOutput{ .value = 90_000, .script_pubkey = &spk };

    const tx = try wallet_mod_bump.createTransaction(
        &w,
        &[_]OwnedUtxo{utxo},
        &[_]wallet_mod_bump.TxOutput{out},
        null,
        .{ .fee_rate = 1, .replaceable = true },
    );
    defer freeTx(allocator, tx);

    try std.testing.expectEqual(@as(u32, 0xFFFFFFFD), tx.inputs[0].sequence);
}
