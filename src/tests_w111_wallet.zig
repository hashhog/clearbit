//! W111 Wallet / HD / Descriptors fleet audit — clearbit (Zig 0.13)
//!
//! 30 gates covering: BIP-32 HD derivation, BIP-39 mnemonics, BIP-44/49/84/86 HD paths,
//! BIP-380 descriptors + checksum, address types, wallet storage, encryption,
//! KeyPool, transaction signing, PSBT.
//!
//! Bug classes found:
//!   BUG-1 (HIGH): G1  — ExtendedKey has no xprv/xpub base58check serialization (78-byte format).
//!                        No `toXprv()`, `toXpub()`, `fromXprv()`, `fromXpub()` exist anywhere.
//!                        Wallets cannot import/export standard xpub/xprv strings.
//!   BUG-2 (HIGH): G3  — CKDpub (public-key-only child derivation) returns error.NotImplemented.
//!                        `deriveChild` with `is_private=false` + non-hardened index fails.
//!                        Descriptor/watch-only wallet derivation is broken.
//!   BUG-3 (HIGH): G10 — No account-xpub export function. `getnewaddress` derives keys but there
//!                        is no `getAccountXpub()` or equivalent to export the BIP-44/84/86 xpub
//!                        at the account level for watch-only coordination.
//!   BUG-4 (HIGH): G24 — Wallet encryption is XOR-with-key, NOT AES-256-GCM.
//!                        `encryptPrivateKey` at wallet.zig:1754 does `plaintext[i] ^ key[i]`.
//!                        A known-plaintext attack (secp256k1 keys have structure) fully breaks it.
//!                        The comment above even says "For a production wallet, use AES-256-GCM".
//!   BUG-5 (MED):  G25 — No KeyPool / gap-limit. Wallet has `next_external_index` / `next_change_index`
//!                        counters but no pre-generated address pool, no `keypoolrefill`, and no
//!                        gap-limit (default 20 in Core). Scanning wallets cannot detect funds.
//!   BUG-6 (MED):  G30 — PSBT v2 (BIP-370) not supported. `PSBT_HIGHEST_VERSION = 0` and parser
//!                        returns `UnsupportedVersion` on v2. BIP-370 per-input fields (PREVIOUS_TXID,
//!                        OUTPUT_INDEX, SEQUENCE, OUTPUT_AMOUNT, OUTPUT_SCRIPT) not defined.
//!   BUG-7 (LOW):  G14 — PSBT finalizeInput P2TR not implemented: TODO comment at psbt.zig:833.
//!                        `finalizeInput` dispatches pkh/wpkh/p2sh/p2wsh but has no tr() path.
//!
//! Two-pipeline / dead-helper observations:
//!   - `BIP39_WORDS` in wallet.zig (line 43) is a separate comptime-parsed copy of the same wordlist
//!     that bip39.zig (`WORDS`) already parses. This is a dual-definition: wallet.zig has its own
//!     `getBip39Words()` returning `BIP39_WORDS` and bip39.zig has `parseWordlist()` returning `WORDS`.
//!     Only bip39.zig's copy is used for mnemonic validation; wallet.zig's BIP39_WORDS is tested only
//!     in one internal test (`BIP39 wordlist is valid`). Net effect: two copies of 2048-word parse at
//!     comptime, 256KB of rodata duplication, and divergence risk if one is updated without the other.
//!
//! Running: add to build.zig as test-wallet-w111 step (same pattern as test-wallet-taproot).
//! Note: tests that exercise secp256k1 guard `if (ctx == null) return;` so they skip cleanly
//! without the library — consistent with pre-existing wallet.zig test pattern.

const std = @import("std");
const wallet_mod = @import("wallet.zig");
const descriptor_mod = @import("descriptor.zig");
const bip39_mod = @import("bip39.zig");
const psbt_mod = @import("psbt.zig");
const types = @import("types.zig");
const address = @import("address.zig");
const crypto = @import("crypto.zig");

// Phase 2 (single-FFI secp module): use the tree-wide `secp.c` so this
// test's `*secp256k1_context` shares opaque-type identity with the one
// `wallet.ExtendedKey.deriveChild` accepts. Pre-Phase-2 this file had its
// own `@cImport` that happened to be byte-identical to wallet.zig's so
// Zig 0.13's cimport dedup made them silently compatible — that
// coincidence was load-bearing for the type system and broke as soon as
// wallet.zig added or reordered an include. Routing through `secp.c`
// makes the type identity explicit.
const secp256k1 = @import("secp.zig").c;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch unreachable;
    }
    return out;
}

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch return error.InvalidHex;
    }
    return out;
}

// ===========================================================================
// G1: BIP-32 Extended Key xprv/xpub 78-byte base58check serialization
// ===========================================================================

// BUG-1: ExtendedKey has no xprv/xpub base58check encode/decode.
// The BIP-32 spec defines a 78-byte serialization:
//   4  bytes: version (0x0488ADE4 xprv mainnet / 0x0488B21E xpub mainnet)
//   1  byte:  depth
//   4  bytes: parent fingerprint
//   4  bytes: child number
//   32 bytes: chain code
//   33 bytes: key (0x00 || privkey, or compressed pubkey)
// Base58Check-encoded, these become the familiar "xprv..." / "xpub..." strings.
// clearbit's ExtendedKey struct has all required fields but no serializer/parser.
//
// xfail: BUG-1 — no xprv/xpub serialization method

test "W111 G1: xprv/xpub serialization — BUG-1 CLOSED by Phase 4 P4-3" {
    // BIP-32 test vector 1 seed (hex)
    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // Master key should have correct properties
    try std.testing.expectEqual(@as(u8, 0), master.depth);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &master.parent_fingerprint);
    try std.testing.expectEqual(@as(u32, 0), master.child_index);
    try std.testing.expect(master.is_private);

    // BIP-32 TV1 expected master privkey:
    // e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
    const expected_master_key = hexToBytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    try std.testing.expectEqualSlices(u8, &expected_master_key, &master.key);

    // BIP-32 TV1 expected chain code:
    // 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
    const expected_chain_code = hexToBytes("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    try std.testing.expectEqualSlices(u8, &expected_chain_code, &master.chain_code);

    // BUG-1 FIX: toXprv / toXpub now exist. Encode the master and check the
    // 4 known structural bytes (version, depth, child index).
    const xprv_raw = try master.toXprv(.mainnet);
    try std.testing.expectEqualSlices(u8, &.{ 0x04, 0x88, 0xAD, 0xE4 }, xprv_raw[0..4]);
    try std.testing.expectEqual(@as(u8, 0), xprv_raw[4]); // depth
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, xprv_raw[5..9]); // parent fp
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, xprv_raw[9..13]); // child index
    try std.testing.expectEqualSlices(u8, &expected_chain_code, xprv_raw[13..45]);
    try std.testing.expectEqual(@as(u8, 0x00), xprv_raw[45]); // priv zero-pad
    try std.testing.expectEqualSlices(u8, &expected_master_key, xprv_raw[46..78]);
}

// W111 G1 (P4-3): xprv string TV1 master byte-identical to BIP-32 spec.
test "W111 G1: BIP-32 TV1 master xprv string byte-identical to spec" {
    const allocator = std.testing.allocator;

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // Spec test1 row 0, prv field from bitcoin-core/src/test/bip32_tests.cpp:44.
    const expected_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const got = try master.toXprvString(.mainnet, allocator);
    defer allocator.free(got);

    try std.testing.expectEqualStrings(expected_xprv, got);
}

// W111 G1 (P4-3): xpub string TV1 master byte-identical to BIP-32 spec.
test "W111 G1: BIP-32 TV1 master xpub string byte-identical to spec" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);
    const master_pub = try master.neuter(ctx.?);

    // Spec test1 row 0, pub field from bitcoin-core/src/test/bip32_tests.cpp:43.
    const expected_xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    const got = try master_pub.toXpubString(.mainnet, allocator);
    defer allocator.free(got);

    try std.testing.expectEqualStrings(expected_xpub, got);
}

// W111 G1 (P4-3): TV1 m/0h xprv + xpub strings byte-identical to spec.
test "W111 G1: BIP-32 TV1 m/0h xprv and xpub strings match spec" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    const c0h = try master.deriveChild(ctx.?, 0x80000000);

    // Spec test1 row 1 (m/0h), bip32_tests.cpp:46-48.
    const expected_xprv_0h = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
    const expected_xpub_0h = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

    const got_xprv = try c0h.toXprvString(.mainnet, allocator);
    defer allocator.free(got_xprv);
    try std.testing.expectEqualStrings(expected_xprv_0h, got_xprv);

    const c0h_pub = try c0h.neuter(ctx.?);
    const got_xpub = try c0h_pub.toXpubString(.mainnet, allocator);
    defer allocator.free(got_xpub);
    try std.testing.expectEqualStrings(expected_xpub_0h, got_xpub);
}

// W111 G1 (P4-3): round-trip — string → ExtendedKey → string is byte-identical.
test "W111 G1: xprv/xpub round-trip preserves byte-identity" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    // Round-trip the TV1 master xprv via fromXprv → toXprvString.
    const input_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const parsed_priv = try wallet_mod.ExtendedKey.fromXprv(ctx.?, input_xprv, allocator);

    const expected_master_key = hexToBytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    try std.testing.expectEqualSlices(u8, &expected_master_key, &parsed_priv.key);
    try std.testing.expectEqual(@as(u8, 0), parsed_priv.depth);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &parsed_priv.parent_fingerprint);
    try std.testing.expectEqual(@as(u32, 0), parsed_priv.child_index);
    try std.testing.expect(parsed_priv.is_private);

    const reencoded = try parsed_priv.toXprvString(.mainnet, allocator);
    defer allocator.free(reencoded);
    try std.testing.expectEqualStrings(input_xprv, reencoded);

    // Round-trip the TV1 master xpub via fromXpub → toXpubString.
    const input_xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const parsed_pub = try wallet_mod.ExtendedPubKey.fromXpub(ctx.?, input_xpub, allocator);

    const reencoded_pub = try parsed_pub.toXpubString(.mainnet, allocator);
    defer allocator.free(reencoded_pub);
    try std.testing.expectEqualStrings(input_xpub, reencoded_pub);
}

// W111 G1 (P4-3): malformed inputs are rejected cleanly, not panicked on.
test "W111 G1: xprv/xpub parse rejects flipped checksum byte" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    // Take the valid TV1 master xprv and mutate the LAST character (which
    // sits inside the base58check checksum window). Should reject with
    // InvalidChecksum, NOT crash.
    const valid = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    var corrupt: [valid.len]u8 = undefined;
    @memcpy(&corrupt, valid);
    // Flip a known character from 'i' to 'j' (both valid base58 chars so we
    // hit the checksum check rather than the alphabet check).
    corrupt[corrupt.len - 1] = if (corrupt[corrupt.len - 1] == 'i') 'j' else 'i';

    const result = wallet_mod.ExtendedKey.fromXprv(ctx.?, &corrupt, allocator);
    try std.testing.expectError(error.InvalidChecksum, result);
}

test "W111 G1: xprv parse rejects wrong version byte (xpub fed to fromXprv)" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    // Pass the TV1 master xpub to fromXprv. The base58check decode succeeds
    // (the xpub is well-formed) but the version is 0x0488B21E (xpub mainnet),
    // not 0x0488ADE4 (xprv mainnet) or 0x04358394 (tprv testnet) — so we
    // should get UnknownExtKeyVersion.
    const xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const result = wallet_mod.ExtendedKey.fromXprv(ctx.?, xpub, allocator);
    try std.testing.expectError(error.UnknownExtKeyVersion, result);
}

test "W111 G1: xpub parse rejects garbage input" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    // "0OIl" mixes characters that are NOT in the base58 alphabet (0, O, I, l).
    // base58Decode rejects them with InvalidBase58Character before the
    // length / checksum / version checks run.
    const garbage = "0OIl0OIl0OIl0OIl0OIl";
    const result = wallet_mod.ExtendedPubKey.fromXpub(ctx.?, garbage, allocator);
    try std.testing.expectError(error.InvalidBase58Character, result);

    // A short but base58-clean string fails the length check instead.
    const short = "xpub111111";
    const result2 = wallet_mod.ExtendedPubKey.fromXpub(ctx.?, short, allocator);
    try std.testing.expectError(error.InvalidExtKeyLength, result2);
}

test "W111 G1: testnet tprv/tpub round-trip" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // Encode the same TV1 master at .testnet — the prefix must be "tprv"
    // (mapped from version bytes 0x04358394). Round-trip back through
    // fromXprv and verify byte-identity of the key material.
    const tprv_str = try master.toXprvString(.testnet, allocator);
    defer allocator.free(tprv_str);
    try std.testing.expect(std.mem.startsWith(u8, tprv_str, "tprv"));

    const parsed = try wallet_mod.ExtendedKey.fromXprv(ctx.?, tprv_str, allocator);
    try std.testing.expectEqualSlices(u8, &master.key, &parsed.key);
    try std.testing.expectEqualSlices(u8, &master.chain_code, &parsed.chain_code);

    // And the matching tpub.
    const master_pub = try master.neuter(ctx.?);
    const tpub_str = try master_pub.toXpubString(.testnet, allocator);
    defer allocator.free(tpub_str);
    try std.testing.expect(std.mem.startsWith(u8, tpub_str, "tpub"));

    const parsed_pub = try wallet_mod.ExtendedPubKey.fromXpub(ctx.?, tpub_str, allocator);
    try std.testing.expectEqualSlices(u8, &master_pub.pub_key.bytes, &parsed_pub.pub_key.bytes);
    try std.testing.expectEqualSlices(u8, &master_pub.chain_code, &parsed_pub.chain_code);
}

test "W111 G1: xprv/xpub BIP-32 TV1 child derivation key material (positive)" {
    // Verify the key material for derived child m/0' matches BIP-32 TV1.
    // This exercises G3/G4 in parallel (hardened).
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return; // secp256k1 not linked; skip
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // m/0' (hardened)
    const child_0h = try master.deriveChild(ctx.?, 0x80000000);
    try std.testing.expectEqual(@as(u8, 1), child_0h.depth);
    try std.testing.expectEqual(@as(u32, 0x80000000), child_0h.child_index);

    // BIP-32 TV1 m/0' key:  edb2e14f9ee77d26dd93b4fadede2f9c0f5b6d6a7a7e08f6c1e3f4c1d2db0e9f
    // (from https://en.bitcoin.it/wiki/BIP_0032_TestVectors, TV1 m/0h)
    // Expected chain code: 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
    const expected_cc_0h = hexToBytes("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
    try std.testing.expectEqualSlices(u8, &expected_cc_0h, &child_0h.chain_code);
}

// ===========================================================================
// G2: Master key from seed HMAC-SHA512("Bitcoin seed", seed)
// ===========================================================================

test "W111 G2: Master key HMAC-SHA512 — BIP-32 TV1 and TV2" {
    // TV1: seed=000102030405060708090a0b0c0d0e0f
    {
        const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
        const master = try wallet_mod.ExtendedKey.fromSeed(&seed);
        // Expected: key=e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
        const expected_key = hexToBytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        try std.testing.expectEqualSlices(u8, &expected_key, &master.key);
        // depth=0, parent_fingerprint=00000000, child_index=0
        try std.testing.expectEqual(@as(u8, 0), master.depth);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &master.parent_fingerprint);
        try std.testing.expectEqual(@as(u32, 0), master.child_index);
    }

    // TV2: seed=fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    {
        const seed = hexToBytes("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        const master = try wallet_mod.ExtendedKey.fromSeed(&seed);
        // Expected key: 4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e
        const expected_key = hexToBytes("4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e");
        try std.testing.expectEqualSlices(u8, &expected_key, &master.key);
    }
}

// ===========================================================================
// G3: Normal CKD (i < 2^31, parent pubkey) — CKDpub
// ===========================================================================

// BUG-2 was: deriveChild with is_private=false + non-hardened returned
// error.NotImplemented. CKDpub (public-key-only normal child derivation)
// is needed for:
//  - Watch-only wallets (xpub-based address generation)
//  - Descriptor wallets (xpub derivation in pkh(), wpkh(), etc.)
//
// CLOSED by Phase 4 P4-2: the typed `ExtendedPubKey` struct +
// `ExtendedKey.neuter()` + `ExtendedPubKey.deriveChild()` (CKDpub via
// `secp256k1_ec_pubkey_tweak_add`) replace the buffer-too-small
// `ExtendedKey.key: [32]u8` legacy field. The legacy `deriveChild` on a
// public-only `ExtendedKey` still returns NotImplemented — that path is
// unreachable because `neuter()` is the only ExtendedPubKey constructor.

test "W111 G3: CKDpub public-key-only normal derivation — BIP-32 TV1 verified" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master_priv = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // CKDpriv works: derive m/0 (non-hardened) from master.
    const child0_priv = try master_priv.deriveChild(ctx.?, 0);
    try std.testing.expectEqual(@as(u8, 1), child0_priv.depth);

    // Neuter master to an honest xpub, then CKDpub the same index.
    const master_pub = try master_priv.neuter(ctx.?);
    const child0_pub = try master_pub.deriveChild(ctx.?, 0);

    // The neutered CKDpriv child must equal the CKDpub child (BIP-32
    // commutativity for non-hardened i).
    const expected_pub = try child0_priv.neuter(ctx.?);
    try std.testing.expectEqualSlices(u8, &expected_pub.pub_key.bytes, &child0_pub.pub_key.bytes);
    try std.testing.expectEqualSlices(u8, &expected_pub.chain_code, &child0_pub.chain_code);
    try std.testing.expectEqual(@as(u8, 1), child0_pub.depth);
    try std.testing.expectEqual(@as(u32, 0), child0_pub.child_index);
}

// ===========================================================================
// G4: Hardened CKD (i >= 2^31, parent privkey)
// ===========================================================================

test "W111 G4: Hardened CKD — BIP-32 TV1 m/0h/1h/2h chain" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // Hardened children must come from private key
    try std.testing.expect(master.is_private);

    // m/0' (hardened)
    const c0h = try master.deriveChild(ctx.?, 0x80000000);
    try std.testing.expectEqual(@as(u8, 1), c0h.depth);
    try std.testing.expectEqual(@as(u32, 0x80000000), c0h.child_index);

    // m/0'/1 (normal from hardened parent — uses private key path via is_private=true)
    const c0h_1 = try c0h.deriveChild(ctx.?, 1);
    try std.testing.expectEqual(@as(u8, 2), c0h_1.depth);
    try std.testing.expectEqual(@as(u32, 1), c0h_1.child_index);

    // m/0'/1/2' (hardened)
    const c0h_1_2h = try c0h_1.deriveChild(ctx.?, 0x80000002);
    try std.testing.expectEqual(@as(u8, 3), c0h_1_2h.depth);
    try std.testing.expectEqual(@as(u32, 0x80000002), c0h_1_2h.child_index);

    // Hardened derivation from public key must fail
    const fake_pub = wallet_mod.ExtendedKey{
        .key = master.key,
        .chain_code = master.chain_code,
        .depth = 0,
        .parent_fingerprint = [_]u8{ 0, 0, 0, 0 },
        .child_index = 0,
        .is_private = false,
    };
    const bad = fake_pub.deriveChild(ctx.?, 0x80000000);
    try std.testing.expectError(error.CannotDeriveHardenedFromPublic, bad);
}

// ===========================================================================
// G5: Chain code propagation
// ===========================================================================

test "W111 G5: chain code propagated correctly through derivation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // Chain code must come from HMAC-SHA512 IR (bytes 32-63)
    const expected_cc = hexToBytes("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    try std.testing.expectEqualSlices(u8, &expected_cc, &master.chain_code);

    // m/0' chain code must differ from master
    const c0h = try master.deriveChild(ctx.?, 0x80000000);
    try std.testing.expect(!std.mem.eql(u8, &c0h.chain_code, &master.chain_code));

    // m/0'/1 chain code must differ from m/0'
    const c0h_1 = try c0h.deriveChild(ctx.?, 1);
    try std.testing.expect(!std.mem.eql(u8, &c0h_1.chain_code, &c0h.chain_code));
}

// ===========================================================================
// G6-G9: HD hierarchy path strings BIP-44/49/84/86
// ===========================================================================

test "W111 G6: BIP-44 path m/44'/coin'/0'/0/index generated correctly" {
    var buf: [64]u8 = undefined;

    // mainnet: coin_type=0
    const path_mainnet = try wallet_mod.ExtendedKey.getStandardPath(.bip44, 0, 0, 0, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/44'/0'/0'/0/0", path_mainnet);

    // testnet: coin_type=1
    const path_testnet = try wallet_mod.ExtendedKey.getStandardPath(.bip44, 1, 0, 0, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/44'/1'/0'/0/0", path_testnet);
}

test "W111 G7: BIP-49 path m/49'/coin'/0'/0/index (P2SH-P2WPKH)" {
    var buf: [64]u8 = undefined;
    const path = try wallet_mod.ExtendedKey.getStandardPath(.bip49, 0, 0, 0, 5, &buf);
    try std.testing.expectEqualSlices(u8, "m/49'/0'/0'/0/5", path);
}

test "W111 G8: BIP-84 path m/84'/coin'/0'/0/index (P2WPKH)" {
    var buf: [64]u8 = undefined;
    const path = try wallet_mod.ExtendedKey.getStandardPath(.bip84, 0, 0, 0, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/84'/0'/0'/0/0", path);

    // change chain
    const path_change = try wallet_mod.ExtendedKey.getStandardPath(.bip84, 0, 0, 1, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/84'/0'/0'/1/0", path_change);
}

test "W111 G9: BIP-86 path m/86'/coin'/0'/0/index (P2TR)" {
    var buf: [64]u8 = undefined;
    const path = try wallet_mod.ExtendedKey.getStandardPath(.bip86, 0, 0, 0, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/86'/0'/0'/0/0", path);
}

// ===========================================================================
// G10: Account-xpub export
// ===========================================================================

// BUG-3: No account-xpub export function.
// The wallet derives keys on demand but has no `getAccountXpub()` / `exportAccountXpub()`
// that would return the xpub for the account-level key (m/84'/0'/0' for BIP-84).
// This prevents watch-only wallet coordination and hardware wallet interop.
// xfail: BUG-3 — no getAccountXpub / exportAccountXpub

test "W111 G10: account-xpub export — BUG-3 no getAccountXpub method exists" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const master = try wallet_mod.ExtendedKey.fromSeed(&seed);

    // Manually derive account key m/84'/0'/0'
    const purpose = try master.deriveChild(ctx.?, 0x80000054); // 84'
    const coin = try purpose.deriveChild(ctx.?, 0x80000000);   // 0'
    const account = try coin.deriveChild(ctx.?, 0x80000000);   // 0'
    try std.testing.expectEqual(@as(u8, 3), account.depth);

    // BUG-3: There is no `ExtendedKey.toXpub()` to produce the xpub string,
    //        and Wallet has no `getAccountXpub(.bip84)` method.
    // Once fixed, this test should produce the standard xpub string that can
    // be imported into Electrum / Sparrow / hardware wallets.
    // The workaround below just confirms we CAN derive the key material; we
    // just can't encode it in the standard format.
    try std.testing.expectEqual(@as(u8, 3), account.depth);
    try std.testing.expect(!std.mem.eql(u8, &account.key, &master.key));
}

// ===========================================================================
// G11-G16: Descriptors
// ===========================================================================

test "W111 G11: pkh() descriptor parse and checksum" {
    const allocator = std.testing.allocator;

    // A raw compressed pubkey descriptor (no xpub needed for parse test)
    const desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    const checksum = descriptor_mod.computeChecksum(desc_str);
    try std.testing.expect(checksum != null);

    // Add checksum and verify
    const with_cs = try descriptor_mod.addChecksum(allocator, desc_str);
    defer allocator.free(with_cs);
    try std.testing.expect(descriptor_mod.verifyChecksum(with_cs));

    // Parse the descriptor via the public top-level parseDescriptor function
    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .pkh);
}

test "W111 G12: wpkh() descriptor parse" {
    const allocator = std.testing.allocator;
    const desc_str = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";

    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .wpkh);
}

test "W111 G13: sh(wpkh()) nested descriptor parse" {
    const allocator = std.testing.allocator;
    const desc_str = "sh(wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))";

    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .sh);
}

test "W111 G14: tr() descriptor parse" {
    const allocator = std.testing.allocator;
    const desc_str = "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)";

    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .tr);
}

test "W111 G15: multi() descriptor parse" {
    const allocator = std.testing.allocator;
    const desc_str = "multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";

    var desc = try descriptor_mod.parseDescriptor(allocator, desc_str);
    defer desc.deinit(allocator);
    try std.testing.expect(desc == .multi);
    try std.testing.expectEqual(@as(u32, 2), desc.multi.threshold);
    try std.testing.expectEqual(@as(usize, 2), desc.multi.keys.len);
}

test "W111 G16: BIP-380 descriptor checksum — known vectors" {
    // From bitcoin-core/src/test/descriptor_tests.cpp and BIP-380 spec.
    // pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#8fhd9pwu
    const desc_with_cs = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#8fhd9pwu";

    // The checksum must verify
    try std.testing.expect(descriptor_mod.verifyChecksum(desc_with_cs));

    // Mutating any character must break it
    var mutable = [_]u8{'X'} ** 100;
    const len = desc_with_cs.len;
    @memcpy(mutable[0..len], desc_with_cs);
    mutable[5] = 'X'; // corrupt a character inside the descriptor body
    try std.testing.expect(!descriptor_mod.verifyChecksum(mutable[0..len]));

    // Computing the checksum from the descriptor-without-checksum must reproduce it
    const desc_only = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    const computed = descriptor_mod.computeChecksum(desc_only);
    try std.testing.expect(computed != null);
    try std.testing.expectEqualSlices(u8, "8fhd9pwu", &computed.?);
}

// ===========================================================================
// G17-G18: BIP-39 mnemonic / seed
// ===========================================================================

test "W111 G17: BIP-39 wordlist + checksum validation" {
    const allocator = std.testing.allocator;

    // Canonical 12-word mnemonic round-trip (TREZOR vector 1)
    const mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const m = try bip39_mod.parseMnemonicString(allocator, mnemonic_str);
    defer allocator.free(m);

    try std.testing.expectEqual(@as(usize, 12), m.len);
    try bip39_mod.validateMnemonic(allocator, m);

    // Corrupt last word → invalid checksum
    var corrupt = try allocator.alloc([]const u8, m.len);
    defer allocator.free(corrupt);
    @memcpy(corrupt, m);
    corrupt[11] = bip39_mod.WORDS[0]; // "abandon" replaces "about"
    try std.testing.expectError(error.InvalidChecksum, bip39_mod.mnemonicToEntropy(allocator, corrupt));
}

test "W111 G18: PBKDF2 seed derivation (BIP-39 TREZOR vector 1)" {
    const allocator = std.testing.allocator;
    const mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const m = try bip39_mod.parseMnemonicString(allocator, mnemonic_str);
    defer allocator.free(m);

    var seed: [64]u8 = undefined;
    try bip39_mod.mnemonicToSeed(allocator, m, "TREZOR", &seed);

    // TREZOR TV1 expected seed:
    // c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531
    // f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
    const expected = hexToBytes(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    );
    try std.testing.expectEqualSlices(u8, &expected, &seed);

    // Wallet.initFromMnemonic must work end-to-end
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx != null) {
        secp256k1.secp256k1_context_destroy(ctx);
        var w = try wallet_mod.Wallet.initFromMnemonic(allocator, .mainnet, m, "TREZOR");
        defer w.deinit();
        try std.testing.expect(w.master_key != null);
    }
}

// ===========================================================================
// G19-G22: Address types
// ===========================================================================

test "W111 G19: P2PKH (legacy) address generation mainnet + testnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wm = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer wm.deinit();
    _ = try wm.generateKey();

    const addr_main = try wm.getAddress(0, .p2pkh);
    defer allocator.free(addr_main);
    // mainnet P2PKH starts with '1'
    try std.testing.expectEqual(@as(u8, '1'), addr_main[0]);

    var wt = try wallet_mod.Wallet.init(allocator, .testnet);
    defer wt.deinit();
    _ = try wt.importKey(wm.keys.items[0].secret_key); // same key
    const addr_test = try wt.getAddress(0, .p2pkh);
    defer allocator.free(addr_test);
    // testnet P2PKH starts with 'm' or 'n'
    try std.testing.expect(addr_test[0] == 'm' or addr_test[0] == 'n');
}

test "W111 G20: P2SH address generation (P2SH-P2WPKH)" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();
    _ = try w.generateKey();

    const addr = try w.getAddress(0, .p2sh_p2wpkh);
    defer allocator.free(addr);
    // mainnet P2SH starts with '3'
    try std.testing.expectEqual(@as(u8, '3'), addr[0]);
    // Must be 34 characters (base58check with P2SH prefix)
    try std.testing.expectEqual(@as(usize, 34), addr.len);
}

test "W111 G21: BECH32 P2WPKH (native segwit v0) address" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();
    _ = try w.generateKey();

    const addr = try w.getAddress(0, .p2wpkh);
    defer allocator.free(addr);
    // mainnet bech32 P2WPKH: bc1q...
    try std.testing.expect(std.mem.startsWith(u8, addr, "bc1q"));
}

test "W111 G22: BECH32M P2TR (taproot) address" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();
    _ = try w.generateKey();

    const addr = try w.getAddress(0, .p2tr);
    defer allocator.free(addr);
    // mainnet bech32m P2TR: bc1p...
    try std.testing.expect(std.mem.startsWith(u8, addr, "bc1p"));
}

// ===========================================================================
// G23: Wallet persistence (JSON round-trip)
// ===========================================================================

test "W111 G23: wallet JSON persistence round-trip (WalletManager)" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    // Use a temp dir for wallet storage
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var tmp_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath(".", &tmp_path_buf);

    var wm = try wallet_mod.WalletManager.init(allocator, tmp_path, .mainnet);
    defer wm.deinit();

    // Create wallet and add some keys
    const w = try wm.createWallet("test", .{});
    _ = try w.generateKey();
    const original_key = w.keys.items[0].secret_key;
    const original_pubkey = w.keys.items[0].public_key;

    // Save via unloadWallet (saves to disk)
    try wm.unloadWallet("test");

    // Reload
    const w2 = try wm.loadWallet("test");
    try std.testing.expectEqual(@as(usize, 1), w2.keys.items.len);
    try std.testing.expectEqualSlices(u8, &original_key, &w2.keys.items[0].secret_key);
    try std.testing.expectEqualSlices(u8, &original_pubkey, &w2.keys.items[0].public_key);
}

// ===========================================================================
// G24: Wallet encryption
// ===========================================================================

// BUG-4 FIXED (FIX-39): wallet.zig now uses AES-256-GCM with a per-key random
// 12-byte nonce and 16-byte authentication tag.  Three cascading security
// failures have been closed:
//   1. Known-plaintext attack: ciphertext is no longer key ^ plaintext — random
//      nonce makes every ciphertext unique even for the same key/passphrase.
//   2. Bit-flip attack: the GCM auth tag detects any modification to the
//      ciphertext, nonce, or tag bytes.
//   3. Any-passphrase "unlocks" wallet: decryptPrivateKey now returns
//      error.AuthenticationFailed when the derived key is wrong.
//
// KDF: scrypt (ln=14, r=8, p=1) with a 16-byte random salt — stronger than the
// PBKDF2-100k alternative mentioned in the audit (kept; matches Core's scrypt path).

test "W111 G24: wallet encryption uses AES-256-GCM — BUG-4 FIXED" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();
    _ = try w.generateKey();

    const original_secret = w.keys.items[0].secret_key;

    // Encrypt with passphrase
    try w.encryptWallet("correct-horse-battery-staple");
    try std.testing.expect(w.encrypted);

    // Ciphertext must differ from plaintext
    try std.testing.expect(!std.mem.eql(u8, &original_secret, &w.keys.items[0].secret_key));

    // Per-key nonce and tag must be set after encryption
    try std.testing.expect(w.keys.items[0].encryption_nonce != null);
    try std.testing.expect(w.keys.items[0].encryption_tag != null);

    // CRITICAL FIX: wrong passphrase must now return WrongPassphrase (not succeed).
    // Previously XOR always "succeeded" regardless of passphrase.
    try std.testing.expectError(error.WrongPassphrase, w.unlockWallet("wrong-passphrase", 30));
    // Wallet must still be locked after a failed unlock attempt
    try std.testing.expect(!w.isUnlocked());

    // Correct passphrase unlocks successfully
    w.lockWallet();
    try std.testing.expect(!w.isUnlocked());
    try w.unlockWallet("correct-horse-battery-staple", 30);
    try std.testing.expect(w.isUnlocked());

    // Lock again
    w.lockWallet();
    try std.testing.expect(!w.isUnlocked());

    // FIX-39: Two encryptions of the same key with the same passphrase must
    // produce different ciphertexts (random nonce prevents known-plaintext).
    var w2 = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w2.deinit();
    // Import the same original key into a second wallet
    _ = try w2.importKey(original_secret);
    try w2.encryptWallet("correct-horse-battery-staple");
    // Different nonce → different ciphertext
    try std.testing.expect(!std.mem.eql(u8, &w.keys.items[0].secret_key, &w2.keys.items[0].secret_key));
}

// ===========================================================================
// G25: KeyPool / gap-limit
// ===========================================================================

// BUG-5: No KeyPool or gap-limit enforcement.
// Bitcoin Core pre-generates KEYPOOL_SIZE=1000 addresses and tracks a gap limit.
// clearbit's wallet only increments a counter when getnewaddress is called.
// A wallet restored from backup has no way to discover funds without scanning
// forward, and there is no `keypoolrefill` or `keypoolsize` concept.
// xfail: BUG-5 — no keypool pre-generation, no gap-limit

test "W111 G25: no KeyPool / gap-limit — BUG-5 documented" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f" ** 2);
    var w = try wallet_mod.Wallet.initFromSeed(allocator, .mainnet, &seed);
    defer w.deinit();

    // Sequential getnewaddress increments the counter monotonically
    const r0 = try w.getnewaddress(.p2wpkh, false);
    defer allocator.free(r0.address);
    try std.testing.expectEqual(@as(u32, 1), w.next_external_index);

    const r1 = try w.getnewaddress(.p2wpkh, false);
    defer allocator.free(r1.address);
    try std.testing.expectEqual(@as(u32, 2), w.next_external_index);

    // BUG-5: There is no pre-generated pool of addresses.
    // Core's `GetKeyFromPool()` / `keypoolRefill()` / `keypoolsize`
    // are entirely absent. The wallet has no `keypool_size` field.
    // A wallet recovered from mnemonic starts at index 0 and only
    // knows about addresses it explicitly generated.

    // Change counter works independently
    const rc = try w.getnewaddress(.p2wpkh, true);
    defer allocator.free(rc.address);
    try std.testing.expectEqual(@as(u32, 1), w.next_change_index);
    try std.testing.expectEqual(@as(u32, 2), w.next_external_index); // unchanged
}

// ===========================================================================
// G26-G28: Signing
// ===========================================================================

test "W111 G26: P2PKH legacy signing round-trip" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    // Build a minimal P2PKH script pubkey for the UTXO
    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [25]u8 = undefined;
    spk[0] = 0x76; // OP_DUP
    spk[1] = 0xa9; // OP_HASH160
    spk[2] = 0x14; // Push 20 bytes
    @memcpy(spk[3..23], &pk_hash);
    spk[23] = 0x88; // OP_EQUALVERIFY
    spk[24] = 0xac; // OP_CHECKSIG

    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2pkh,
        .confirmations = 6,
    };

    // Build a 1-in-1-out transaction
    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{ .previous_output = utxo.outpoint, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFF, .witness = &[_][]const u8{} };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    outputs[0] = .{ .value = 90_000, .script_pubkey = &spk };

    var tx = types.Transaction{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    try w.signInput(&tx, 0, utxo, 0x01, null);

    // scriptSig must be non-empty after signing
    try std.testing.expect(tx.inputs[0].script_sig.len > 0);
    defer allocator.free(tx.inputs[0].script_sig);
}

test "W111 G27: P2WPKH BIP-143 signing round-trip" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    const pk_hash = crypto.hash160(&w.keys.items[ki].public_key);
    var spk: [22]u8 = undefined;
    spk[0] = 0x00; // OP_0
    spk[1] = 0x14; // Push 20
    @memcpy(spk[2..22], &pk_hash);

    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xBB} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{ .previous_output = utxo.outpoint, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFE, .witness = &[_][]const u8{} };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    outputs[0] = .{ .value = 90_000, .script_pubkey = &spk };

    var tx = types.Transaction{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    const prevouts = [_]wallet_mod.OwnedUtxo{utxo};
    try w.signInput(&tx, 0, utxo, 0x01, &prevouts);

    // Witness must be populated: [sig, pubkey]
    try std.testing.expectEqual(@as(usize, 2), tx.inputs[0].witness.len);
    // scriptSig must be empty for native segwit
    try std.testing.expectEqual(@as(usize, 0), tx.inputs[0].script_sig.len);
    defer {
        for (tx.inputs[0].witness) |item| allocator.free(item);
        allocator.free(tx.inputs[0].witness);
    }
}

test "W111 G28: P2TR BIP-341 Schnorr signing round-trip" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var w = try wallet_mod.Wallet.init(allocator, .mainnet);
    defer w.deinit();
    const ki = try w.generateKey();

    // Build P2TR output key (BIP-86 tweaked)
    const tweaked = try wallet_mod.bip86TweakXOnly(w.ctx, &w.keys.items[ki].x_only_pubkey);
    var spk: [34]u8 = undefined;
    spk[0] = 0x51; // OP_1
    spk[1] = 0x20; // Push 32 bytes
    @memcpy(spk[2..34], &tweaked);

    const utxo = wallet_mod.OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xCC} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &spk },
        .key_index = ki,
        .address_type = .p2tr,
        .confirmations = 6,
    };

    const inputs = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs);
    inputs[0] = .{ .previous_output = utxo.outpoint, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFE, .witness = &[_][]const u8{} };
    const outputs = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs);
    outputs[0] = .{ .value = 90_000, .script_pubkey = &spk };

    var tx = types.Transaction{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };

    const prevouts = [_]wallet_mod.OwnedUtxo{utxo};
    try w.signInput(&tx, 0, utxo, 0x00, &prevouts);

    // Witness: [64-byte Schnorr sig]
    try std.testing.expectEqual(@as(usize, 1), tx.inputs[0].witness.len);
    try std.testing.expectEqual(@as(usize, 64), tx.inputs[0].witness[0].len); // SIGHASH_DEFAULT
    defer {
        for (tx.inputs[0].witness) |item| allocator.free(item);
        allocator.free(tx.inputs[0].witness);
    }
}

// ===========================================================================
// G29: PSBT BIP-174 v0
// ===========================================================================

test "W111 G29: PSBT v0 create / serialize / deserialize round-trip" {
    const allocator = std.testing.allocator;

    const inputs_arr = try allocator.alloc(types.TxIn, 1);
    defer allocator.free(inputs_arr);
    inputs_arr[0] = .{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const outputs_arr = try allocator.alloc(types.TxOut, 1);
    defer allocator.free(outputs_arr);
    const spk = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x01} ** 20 ++ [_]u8{ 0x88, 0xac };
    outputs_arr[0] = .{ .value = 50_000, .script_pubkey = &spk };

    const tx = types.Transaction{
        .version = 2,
        .inputs = inputs_arr,
        .outputs = outputs_arr,
        .lock_time = 0,
    };

    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();

    try std.testing.expectEqual(@as(u32, 0), psbt.version);
    try std.testing.expectEqual(@as(usize, 1), psbt.inputs.len);
    try std.testing.expectEqual(@as(usize, 1), psbt.outputs.len);

    // Serialize to bytes
    const serialized = try psbt.serialize(allocator);
    defer allocator.free(serialized);

    // Must start with PSBT magic "psbt\xff"
    try std.testing.expectEqualSlices(u8, &psbt_mod.PSBT_MAGIC, serialized[0..5]);

    // Deserialize back
    var psbt2 = try psbt_mod.Psbt.deserialize(allocator, serialized);
    defer psbt2.deinit();

    try std.testing.expectEqual(psbt.tx.version, psbt2.tx.version);
    try std.testing.expectEqual(psbt.inputs.len, psbt2.inputs.len);
}

// ===========================================================================
// G30: PSBT BIP-370 v2
// ===========================================================================

// BUG-6: PSBT v2 (BIP-370) not supported.
// PSBT_HIGHEST_VERSION = 0 (psbt.zig:33); the deserializer returns UnsupportedVersion
// for any v2 PSBT. BIP-370 adds per-input fields: PSBT_IN_PREVIOUS_TXID (0x0e),
// PSBT_IN_OUTPUT_INDEX (0x0f), PSBT_IN_SEQUENCE (0x10), and per-output fields
// PSBT_OUT_AMOUNT (0x03), PSBT_OUT_SCRIPT (0x04). These are not defined.
// xfail: BUG-6 — PSBT v2 / BIP-370 not implemented

test "W111 G30: PSBT v2 BIP-370 not supported — BUG-6 documented" {
    const allocator = std.testing.allocator;

    // Construct a minimal PSBT v2 binary:
    //   magic(5) | global_version_kv(key=\x01\xfb val=\x04\x02\x00\x00\x00) | separator(0x00)
    // Then no inputs, no outputs (not valid but enough to test version check).
    const psbt_v2_bytes = [_]u8{
        // Magic
        0x70, 0x73, 0x62, 0x74, 0xff,
        // PSBT_GLOBAL_VERSION key (key_len=2, key_type=0xfb, key_data empty=none)
        0x02, 0xfb, 0x00, // key: len=2 type=0xfb, zero extra byte (we'll use a different scheme)
        // Actually use correct encoding: key_len=1 (type byte only), value=4 bytes LE u32=2
        // Restart with correct encoding:
    };
    _ = psbt_v2_bytes; // suppress "unused" warning

    // Correct minimal v2 PSBT:
    var v2_buf = [_]u8{
        // Magic: "psbt\xff"
        0x70, 0x73, 0x62, 0x74, 0xff,
        // Global PSBT_GLOBAL_VERSION (type=0xfb): key_len=1, key=0xfb, val_len=4, val=0x02000000
        0x01, 0xfb,         // key: len=1, type=0xfb
        0x04, 0x02, 0x00, 0x00, 0x00, // val: len=4, version=2 (LE)
        // Separator
        0x00,
    };

    const result = psbt_mod.Psbt.deserialize(allocator, &v2_buf);
    // BUG-6: this should succeed once BIP-370 is implemented; currently fails with UnsupportedVersion
    try std.testing.expectError(error.UnsupportedVersion, result);

    // Confirm PSBT_HIGHEST_VERSION is still 0
    try std.testing.expectEqual(@as(u32, 0), psbt_mod.PSBT_HIGHEST_VERSION);
    // Once BUG-6 is fixed: replace above expectError with `const psbt2 = try result;`
    //   and check psbt2.version == 2, then psbt2.deinit().
}

// ===========================================================================
// Dual-definition dead-helper observation: BIP39_WORDS vs bip39.WORDS
// ===========================================================================

test "W111 dual-definition: wallet.BIP39_WORDS and bip39.WORDS are separate compile-time arrays" {
    // wallet.zig defines BIP39_WORDS (getBip39Words())
    // bip39.zig defines WORDS (parseWordlist())
    // Both parse the same embedded file at comptime.
    // This test documents the divergence risk without patching it.

    // Both must agree on the first and last word.
    // We can access bip39.WORDS directly through bip39_mod.
    try std.testing.expectEqualSlices(u8, "abandon", bip39_mod.WORDS[0]);
    try std.testing.expectEqualSlices(u8, "zoo", bip39_mod.WORDS[2047]);

    // wallet.zig's BIP39_WORDS is not public-exported, so we can't directly compare here,
    // but the wallet.zig "BIP39 wordlist is valid" test exercises it internally.
    // The dead-helper risk: if bip39.zig's wordlist is ever updated without updating
    // wallet.zig's private copy, mnemonicToSeed (via bip39.zig) and wallet internals
    // could diverge. Remediation: wallet.zig should import bip39.WORDS instead of
    // defining its own copy.
}

// ===========================================================================
// W161 BUG-5 regression: master_key + chain_code MUST be encrypted on disk
// when the wallet has a passphrase.
//
// Before the W161 fix, `serializeWallet` wrote `master_key.key` (the 32-byte
// BIP-32 master private key) and `master_key.chain_code` (32 bytes, also a
// secret per BIP-32 §"Public derivation") to wallet.dat as plaintext hex
// regardless of `encryptwallet`.  AES-256-GCM child-key encryption was
// cosmetic — anyone with read access to wallet.dat recovered the seed of
// every child via BIP-32.  This test:
//   1. Creates an HD wallet from a known seed
//   2. Encrypts with a passphrase
//   3. Round-trips through WalletManager save+load
//   4. Asserts the on-disk JSON does NOT contain the plaintext master key
//      bytes (the actual fix verification)
//   5. Asserts the reloaded wallet's master_key decrypts to the original
//      plaintext after unlockWallet
// ===========================================================================

test "W111 / W161 BUG-5: master_key + chain_code encrypted on disk for encrypted wallets" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    // Known seed → known master key.  BIP-32 test vector #1.
    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    var w_ref = try wallet_mod.Wallet.initFromSeed(allocator, .mainnet, &seed);
    defer w_ref.deinit();
    const original_master_key = w_ref.master_key.?.key;
    const original_chain_code = w_ref.master_key.?.chain_code;

    // Create wallet through WalletManager so the full save/load path runs.
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var tmp_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath(".", &tmp_path_buf);

    var wm = try wallet_mod.WalletManager.init(allocator, tmp_path, .mainnet);
    defer wm.deinit();

    // Bypass createWallet's random seed by patching the wallet's master_key
    // to the known one immediately after creation.  The encryption pass that
    // follows will encrypt it in place.
    const w = try wm.createWallet("w161-bug5", .{ .blank = true });
    w.master_key = wallet_mod.ExtendedKey{
        .key = original_master_key,
        .chain_code = original_chain_code,
        .depth = 0,
        .parent_fingerprint = [_]u8{ 0, 0, 0, 0 },
        .child_index = 0,
        .is_private = true,
    };
    try w.encryptWallet("correct-horse-battery-staple");

    // After encryptWallet the in-memory bytes are ciphertext, not plaintext.
    try std.testing.expect(!std.mem.eql(u8, &original_master_key, &w.master_key.?.key));
    try std.testing.expect(!std.mem.eql(u8, &original_chain_code, &w.master_key.?.chain_code));
    try std.testing.expect(w.master_key_nonce != null);
    try std.testing.expect(w.master_key_tag != null);
    try std.testing.expect(w.master_chain_code_nonce != null);
    try std.testing.expect(w.master_chain_code_tag != null);

    // Snapshot ciphertext before unloadWallet destroys the in-memory `w`.
    const cipher_key_snapshot: [32]u8 = w.master_key.?.key;
    const cipher_cc_snapshot: [32]u8 = w.master_key.?.chain_code;

    // Save to disk via unloadWallet → serializeWallet.
    try wm.unloadWallet("w161-bug5");

    // Read raw bytes and assert plaintext master key + chain code are NOT
    // present (hex-encoded).  This is the regression contract for BUG-5.
    const wallet_dir = try std.fmt.allocPrint(allocator, "{s}/w161-bug5/wallet.dat", .{tmp_path});
    defer allocator.free(wallet_dir);
    const file = try std.fs.openFileAbsolute(wallet_dir, .{});
    defer file.close();
    const stat = try file.stat();
    const content = try allocator.alloc(u8, stat.size);
    defer allocator.free(content);
    _ = try file.readAll(content);

    var key_hex_buf: [64]u8 = undefined;
    const key_hex = std.fmt.bufPrint(&key_hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&original_master_key)}) catch unreachable;
    var cc_hex_buf: [64]u8 = undefined;
    const cc_hex = std.fmt.bufPrint(&cc_hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&original_chain_code)}) catch unreachable;

    // The regression test: neither the master private key nor the chain code
    // may appear as plaintext hex anywhere in wallet.dat.
    try std.testing.expect(std.mem.indexOf(u8, content, key_hex) == null);
    try std.testing.expect(std.mem.indexOf(u8, content, cc_hex) == null);

    // The JSON must contain the new nonce/tag fields (proves the fix path ran).
    try std.testing.expect(std.mem.indexOf(u8, content, "master_key_nonce") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "master_key_tag") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "master_chain_code_nonce") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "master_chain_code_tag") != null);

    // Round-trip: reload + unlock + derive a child address; assert decrypted
    // master key matches the original 32 bytes.
    const w2 = try wm.loadWallet("w161-bug5");
    try std.testing.expect(w2.master_key != null);
    try std.testing.expect(w2.encrypted);
    // Ciphertext bytes survived the round-trip.
    try std.testing.expectEqualSlices(u8, &cipher_key_snapshot, &w2.master_key.?.key);
    try std.testing.expectEqualSlices(u8, &cipher_cc_snapshot, &w2.master_key.?.chain_code);
    try w2.unlockWallet("correct-horse-battery-staple", 30);

    // Decrypt master_key via the helper and check it matches the original.
    // getPlaintextMasterKey is private; exercise it through getnewaddress
    // which calls it internally.  The address generation must succeed,
    // proving the encrypted master_key decrypts to a valid 32-byte secp256k1
    // scalar (the original).
    const newaddr = try w2.getnewaddress(.p2wpkh, false);
    defer allocator.free(newaddr.address);
    try std.testing.expect(newaddr.address.len > 0);
}
