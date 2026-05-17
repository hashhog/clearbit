//! W127 — Taproot / Schnorr / Tapscript 30-gate audit (clearbit / Zig 0.13)
//!
//! Discovery wave. Audits clearbit's BIP-340 / BIP-341 / BIP-342
//! implementation against Bitcoin Core's authoritative references:
//!   bitcoin-core/src/script/interpreter.cpp   (EvalChecksigTapscript,
//!                                              EvalChecksigPreTapscript,
//!                                              SignatureHashSchnorr,
//!                                              VerifyTaprootCommitment,
//!                                              VerifyWitnessProgram,
//!                                              CheckSchnorrSignature,
//!                                              ExecuteWitnessScript,
//!                                              ComputeTapleafHash,
//!                                              ComputeTapbranchHash,
//!                                              ComputeTaprootMerkleRoot)
//!   bitcoin-core/src/script/interpreter.h     (TAPROOT_LEAF_TAPSCRIPT=0xc0,
//!                                              TAPROOT_LEAF_MASK=0xfe,
//!                                              TAPROOT_CONTROL_BASE_SIZE=33,
//!                                              TAPROOT_CONTROL_NODE_SIZE=32,
//!                                              TAPROOT_CONTROL_MAX_NODE_COUNT=128,
//!                                              WITNESS_V1_TAPROOT_SIZE=32,
//!                                              VALIDATION_WEIGHT_PER_SIGOP_PASSED=50,
//!                                              VALIDATION_WEIGHT_OFFSET=50)
//!   bitcoin-core/src/script/script.h          (ANNEX_TAG=0x50)
//!   bitcoin-core/src/script/script_error.h    (SCRIPT_ERR_TAPROOT_*,
//!                                              SCRIPT_ERR_TAPSCRIPT_*,
//!                                              SCRIPT_ERR_SCHNORR_*,
//!                                              SCRIPT_ERR_DISCOURAGE_*)
//!   bitcoin-core/src/pubkey.cpp:236           (XOnlyPubKey::VerifySchnorr)
//!   bitcoin-core/src/script/sigcache.cpp      (CSignatureCache)
//!
//! Status
//! ------
//! XFAIL guards. Tests assert the current observable state — including the
//! catalogued BUGs — so the next fix wave can flip each gate by deliberately
//! breaking the corresponding test. A failure here means the underlying code
//! changed and somebody forgot to update the audit. See
//! `audit/w127_taproot.md` for the prose write-up.
//!
//! Run: `zig build test-w127`

const std = @import("std");
const testing = std.testing;

const script = @import("script.zig");
const crypto = @import("crypto.zig");
const taproot_sighash = @import("taproot_sighash.zig");
const sig_cache = @import("sig_cache.zig");

// ===========================================================================
// Source-text-based forward-regression guards.
//
// Many of the W127 audit observations are about whether a code path EXISTS at
// a specific call site, rather than what it returns at runtime. The
// canonical way to lock those down without re-running the full script
// interpreter is to grep the source bytes at comptime via @embedFile.
// ===========================================================================

const SCRIPT_SRC = @embedFile("script.zig");
const CRYPTO_SRC = @embedFile("crypto.zig");
const SIGHASH_SRC = @embedFile("taproot_sighash.zig");
const SIGCACHE_SRC = @embedFile("sig_cache.zig");
const VALIDATION_SRC = @embedFile("validation.zig");

fn srcContains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

/// Compile-time check whether an error set declares a given variant by name.
/// `ScriptError` is an error set (not a struct/enum), so `@hasField` doesn't
/// apply. We walk `@typeInfo(.ErrorSet)` and string-compare names.
fn errorSetHas(comptime ES: type, comptime name: []const u8) bool {
    const info = @typeInfo(ES).ErrorSet orelse return false;
    inline for (info) |err| {
        if (std.mem.eql(u8, err.name, name)) return true;
    }
    return false;
}

// ===========================================================================
// BIP-340 Schnorr signature verification (G1–G6)
// ===========================================================================

test "w127 G1: verifySchnorr dispatches to libsecp256k1 (PRESENT)" {
    // The crypto.zig Schnorr wrapper goes through secp256k1_schnorrsig_verify.
    // BIP-340 strict semantics (s>=n / rx>=p / non-curve rejection) are then
    // externalised to upstream — clearbit MUST NOT roll its own.
    try testing.expect(srcContains(CRYPTO_SRC, "secp256k1_schnorrsig_verify"));
    try testing.expect(srcContains(CRYPTO_SRC, "secp256k1_xonly_pubkey_parse"));
    // The exported wrapper signature: sig=64B, msg=32B, pk=32B.
    try testing.expect(srcContains(CRYPTO_SRC, "pub fn verifySchnorr(sig: *const [64]u8, msg_hash: *const [32]u8, pubkey_x: *const [32]u8) bool"));
}

test "w127 G2: 65-byte sig accepted; hashtype byte stripped before verify (PRESENT)" {
    // The taproot key-path and tapscript paths both accept sig.len==65 and
    // strip the trailing hashtype byte before invoking the 64-byte verify.
    try testing.expect(srcContains(SCRIPT_SRC, "if (sig_bytes.len != 64 and sig_bytes.len != 65)"));
    try testing.expect(srcContains(SCRIPT_SRC, "if (sig.len != 64 and sig.len != 65)"));
}

test "w127 G3: size ∉ {64,65} → SCRIPT_ERR_SCHNORR_SIG_SIZE (PRESENT)" {
    try testing.expect(srcContains(SCRIPT_SRC, "SchnorrSigSize"));
    // The ScriptError enum surfaces the dedicated SCHNORR_SIG_SIZE variant.
    try testing.expect(errorSetHas(script.ScriptError, "SchnorrSigSize"));
}

test "w127 G4: 65-byte sig with hashtype byte = SIGHASH_DEFAULT (0x00) → SCRIPT_ERR_SCHNORR_SIG_HASHTYPE (PRESENT)" {
    try testing.expect(errorSetHas(script.ScriptError, "SchnorrSigHashType"));
    // Both key-path and tapscript paths gate on hash_type != SIGHASH_DEFAULT
    // when sig.len == 65.
    try testing.expect(srcContains(SCRIPT_SRC, "if (hash_type == taproot_sighash.SIGHASH_DEFAULT)"));
}

test "w127 G5: BIP-341 hashtype byte must be one of {0,1,2,3,0x81,0x82,0x83}" {
    // isValidTaprootHashType is exposed and accepts the 7 canonical values.
    try testing.expect(taproot_sighash.isValidTaprootHashType(0x00));
    try testing.expect(taproot_sighash.isValidTaprootHashType(0x01));
    try testing.expect(taproot_sighash.isValidTaprootHashType(0x02));
    try testing.expect(taproot_sighash.isValidTaprootHashType(0x03));
    try testing.expect(taproot_sighash.isValidTaprootHashType(0x81));
    try testing.expect(taproot_sighash.isValidTaprootHashType(0x82));
    try testing.expect(taproot_sighash.isValidTaprootHashType(0x83));
    // And rejects everything else (sample boundary values).
    try testing.expect(!taproot_sighash.isValidTaprootHashType(0x04));
    try testing.expect(!taproot_sighash.isValidTaprootHashType(0x80));
    try testing.expect(!taproot_sighash.isValidTaprootHashType(0x84));
    try testing.expect(!taproot_sighash.isValidTaprootHashType(0xff));
}

test "w127 G6: x-only pubkey rx >= p rejected via xonly_pubkey_parse (PRESENT)" {
    // x-only pubkey rx >= p (field-overflow) is rejected upstream by
    // libsecp256k1's parse; the BIP-340 vector 14 test in crypto.zig covers
    // this path.
    try testing.expect(srcContains(CRYPTO_SRC, "secp256k1_xonly_pubkey_parse"));
    // Documented test name from crypto.zig.
    try testing.expect(srcContains(CRYPTO_SRC, "verifySchnorr BIP-340 vector 14: pubkey rx >= p"));
}

// ===========================================================================
// BIP-341 Taproot key-path spending (G7–G12)
// ===========================================================================

test "w127 G7: Taproot gate requires witversion=1 ∧ program.len=32 ∧ !via_p2sh (PRESENT)" {
    // The dispatch gate at line 1078 of script.zig must AND all three
    // conditions. Mirrors Core interpreter.cpp:1947.
    try testing.expect(srcContains(SCRIPT_SRC, "wp.version == 1 and wp.program.len == 32 and !via_p2sh"));
}

test "w127 G8: pre-Taproot-activation (!verify_taproot) → success without consuming witness (PRESENT)" {
    // The early-return gate matches Core interpreter.cpp:1949.
    try testing.expect(srcContains(SCRIPT_SRC, "if (!self.flags.verify_taproot)"));
}

test "w127 G9: empty witness on a v1 program → WITNESS_PROGRAM_WITNESS_EMPTY (PRESENT)" {
    try testing.expect(errorSetHas(script.ScriptError, "WitnessProgramWitnessEmpty"));
    try testing.expect(srcContains(SCRIPT_SRC, "if (witness.len == 0) return ScriptError.WitnessProgramWitnessEmpty;"));
}

test "w127 G10: annex stripped only when len ≥ 2 ∧ back[0] == 0x50 (PRESENT)" {
    // The ANNEX_TAG byte must be 0x50 (BIP-341 / Core script.h:58).
    try testing.expect(srcContains(SCRIPT_SRC, "witness[witness.len - 1].len > 0 and witness[witness.len - 1][0] == 0x50"));
    // The strip is gated on witness.len >= 2 — without this, a sole 0x50-prefixed
    // witness item would be misclassified as an annex.
    try testing.expect(srcContains(SCRIPT_SRC, "if (witness.len >= 2 and"));
}

test "w127 G11: annex bytes committed via sha_annex (compactsize-length-prefixed) (PRESENT)" {
    // The sigmsg includes a compactsize length prefix followed by the annex
    // bytes themselves (INCLUDING the 0x50 prefix), all SHA256'd.
    try testing.expect(srcContains(SIGHASH_SRC, "if (annex) |annex_bytes|"));
    try testing.expect(srcContains(SIGHASH_SRC, "try writeCompactSize(&annex_buf, annex_bytes.len);"));
    try testing.expect(srcContains(SIGHASH_SRC, "try annex_buf.appendSlice(annex_bytes);"));
}

test "w127 G12: key-path checkSchnorr against scriptPubKey output key directly (PRESENT)" {
    // BIP-341: the verifier checks the sig against the 32-byte tweaked
    // OUTPUT key (Q) — no on-the-fly tweak math by the verifier. This is
    // distinct from the script-path, which DOES check the commitment.
    // The byte sequence "wp.program[0..32]" at line 1163-1164 in script.zig
    // copies the scriptPubKey program directly into the x-only verify slot.
    try testing.expect(srcContains(SCRIPT_SRC, "@memcpy(&xonly, wp.program[0..32])"));
    try testing.expect(srcContains(SCRIPT_SRC, "crypto.verifySchnorr(&sig, &sighash, &xonly)"));
}

// ===========================================================================
// BIP-341 Taproot script-path spending (G13–G18)
// ===========================================================================

test "w127 G13: control-block size ∈ [33, 33+32*128] ∧ (size-33) % 32 == 0; else TAPROOT_WRONG_CONTROL_SIZE (PRESENT)" {
    try testing.expect(errorSetHas(script.ScriptError, "TaprootWrongControlSize"));
    // Both bounds and modular constraint must be present.
    try testing.expect(srcContains(SCRIPT_SRC, "control.len < 33 or control.len > 33 + 32 * 128"));
    try testing.expect(srcContains(SCRIPT_SRC, "(control.len - 33) % 32 != 0"));
}

test "w127 G14: tapleaf hash uses FULL CompactSize (not capped at 0xFFFF) (PRESENT)" {
    // Critical for Ordinals tapscripts > 64 KiB. The pre-fix code documented
    // at crypto.zig:1541-1546 wrongly rejected mainnet block 947960 because
    // it capped at 0xFFFF. The fix uses appendCompactSize which encodes
    // <0xfd / 0xfd+u16 / 0xfe+u32 / 0xff+u64 per Core's WriteCompactSize.
    try testing.expect(srcContains(CRYPTO_SRC, "fn appendCompactSize"));
    try testing.expect(srcContains(CRYPTO_SRC, "appendCompactSize(&leaf_hasher, tap_script.len)"));
    // The 4 size brackets are all present.
    try testing.expect(srcContains(CRYPTO_SRC, "if (value < 0xfd)"));
    try testing.expect(srcContains(CRYPTO_SRC, "value <= 0xffff"));
    try testing.expect(srcContains(CRYPTO_SRC, "value <= 0xffff_ffff"));
    // Smoke: a 70 KiB script must produce a non-null Hash256.
    var big_script: [70000]u8 = undefined;
    @memset(&big_script, 0x51); // all OP_1, harmless
    const tlh = crypto.computeTapleafHash(&big_script, 0xc0);
    try testing.expect(tlh != null);
}

test "w127 G15: tapbranch uses lexicographic ordering + double-tagged-hash (PRESENT)" {
    // Core's ComputeTapbranchHash sorts a/b lexicographically before hashing.
    // The verifier walk in crypto.zig mirrors this with std.mem.order.
    try testing.expect(srcContains(CRYPTO_SRC, "std.mem.order(u8, &k, node) == .lt"));
    try testing.expect(srcContains(CRYPTO_SRC, "const tap_branch_tag = sha256(\"TapBranch\");"));
}

test "w127 G16: TapTweak verified via xonly_pubkey_tweak_add_check with parity from control[0]&1 (PRESENT)" {
    // The Core canonical path — Q = P + tweak·G, parity = control[0]&1.
    // Verified in one call by libsecp256k1; clearbit must NOT roll its own
    // EC math here (history: dead xonly_pubkey_tweak_add call existed in an
    // earlier revision, documented at crypto.zig:1641).
    try testing.expect(srcContains(CRYPTO_SRC, "secp256k1_xonly_pubkey_tweak_add_check"));
    try testing.expect(srcContains(CRYPTO_SRC, "@intCast(control[0] & 1)"));
    try testing.expect(srcContains(CRYPTO_SRC, "taggedHash(\"TapTweak\""));
}

test "w127 G17: commitment-verify failure surfaces SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH (PRESENT)" {
    // Core uses WITNESS_PROGRAM_MISMATCH (not a dedicated BAD_TAPROOT_*)
    // — interpreter.cpp:1975. clearbit matches.
    try testing.expect(srcContains(SCRIPT_SRC, "if (!crypto.verifyTaprootControlBlock(control, tap_script, wp.program))"));
    try testing.expect(srcContains(SCRIPT_SRC, "return ScriptError.WitnessProgramMismatch"));
}

test "w127 G18: leaf-version mask 0xfe drops parity bit before tapleaf hash (PRESENT)" {
    // BIP-341: leaf_version is `control[0] & TAPROOT_LEAF_MASK` (0xfe).
    // Parity bit (& 0x01) is consumed separately by tweak_add_check.
    try testing.expect(srcContains(SCRIPT_SRC, "const leaf_version = control[0] & 0xfe;"));
    try testing.expect(srcContains(CRYPTO_SRC, "const leaf_version = control[0] & 0xfe;"));
}

// ===========================================================================
// BIP-342 Tapscript (G19–G26)
// ===========================================================================

test "w127 G19: leaf version 0xc0 ONLY executed as tapscript; unknown → success or DISCOURAGE (PRESENT)" {
    // The leaf-version gate matches Core interpreter.cpp:1978-1988:
    // unknown leaf versions are anyone-can-spend (future soft-fork) unless
    // the discourage flag is set.
    try testing.expect(srcContains(SCRIPT_SRC, "if (leaf_version != 0xc0)"));
    try testing.expect(errorSetHas(script.ScriptError, "DiscourageUpgradableTaprootVersion"));
    try testing.expect(srcContains(SCRIPT_SRC, "self.flags.discourage_upgradable_taproot_version"));
}

test "w127 G20: OP_SUCCESSx pre-scan returns success (PRESENT)" {
    try testing.expect(srcContains(SCRIPT_SRC, "fn preScanTapscript"));
    try testing.expect(srcContains(SCRIPT_SRC, "fn isOpSuccess"));
    try testing.expect(errorSetHas(script.ScriptError, "DiscourageOpSuccess"));
    // Core's IsOpSuccess includes opcodes 0x50 (OP_RESERVED), 0x62 (VER),
    // 0x7e-0x81, 0x83-0x86, 0x89-0x8a, 0x8d-0x8e, 0x95-0x99, 0xbb-0xfe.
    // clearbit's isOpSuccess at line 553-560 covers the union.
    try testing.expect(srcContains(SCRIPT_SRC, "return op == 80 or op == 98 or"));
    try testing.expect(srcContains(SCRIPT_SRC, "op >= 187 and op <= 254"));
}

test "w127 G21: validation-weight budget initialised to serializedWitnessStackSize + 50 (PRESENT)" {
    // Core (interpreter.cpp:1981):
    //   m_validation_weight_left = ::GetSerializeSize(witness.stack)
    //                            + VALIDATION_WEIGHT_OFFSET (50)
    try testing.expect(srcContains(SCRIPT_SRC, "fn serializedWitnessStackSize"));
    try testing.expect(srcContains(SCRIPT_SRC, "self.validation_weight_left = @intCast(ws + 50);"));
    // Per-sigop deduct of 50.
    try testing.expect(srcContains(SCRIPT_SRC, "self.validation_weight_left -= 50;"));
    // Negative-residue abort surfaces TapscriptValidationWeight.
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptValidationWeight"));

    // Smoke: serializedWitnessStackSize matches Core's GetSerializeSize on a
    // 3-item witness {<empty>, <1-byte>, <1-byte>}.
    const items = [_][]const u8{ &[_]u8{}, &[_]u8{0x01}, &[_]u8{0x02} };
    // compactsize(3)=1 + per-item (compactsize(0)+0)=1 + (compactsize(1)+1)=2 + (compactsize(1)+1)=2 = 6 bytes
    try testing.expectEqual(@as(u64, 6), script.serializedWitnessStackSize(&items));
}

test "w127 G22: OP_CHECKSIGADD <sig><num><pubkey> → <num+success>; non-empty failure → NULLFAIL (PRESENT)" {
    // EvalChecksigTapscript ordering (Core interpreter.cpp:347-385):
    //   1. success = !sig.empty()
    //   2. if success: deduct weight, abort if < 0
    //   3. empty-pubkey → TAPSCRIPT_EMPTY_PUBKEY
    //   4. 32B pubkey → Schnorr verify; non-empty failure → NULLFAIL abort
    //   5. unknown pubkey size → success unchanged; DISCOURAGE gate
    // The body must include the consumeValidationWeight call gated on
    // success_initial AND a NullFail return in the verify-failure branch.
    try testing.expect(srcContains(SCRIPT_SRC, ".op_checksigadd =>"));
    try testing.expect(srcContains(SCRIPT_SRC, "const success_initial = sig.len > 0;"));
    try testing.expect(srcContains(SCRIPT_SRC, "if (success_initial) {\n                    try self.consumeValidationWeight();"));
    try testing.expect(srcContains(SCRIPT_SRC, "return ScriptError.NullFail;"));
}

test "w127 G23: OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY DISABLED in tapscript (PRESENT)" {
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptCheckmultisigDisabled"));
    try testing.expect(srcContains(SCRIPT_SRC, "TapscriptCheckmultisigDisabled"));
    // Both arms — op_checkmultisig and op_checkmultisigverify — must gate.
    try testing.expect(srcContains(SCRIPT_SRC, "if (self.sig_version == .tapscript) return ScriptError.TapscriptCheckmultisigDisabled;"));
}

test "w127 G24: tapscript: empty pubkey → TAPSCRIPT_EMPTY_PUBKEY (even if sig also empty) (PRESENT)" {
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptEmptyPubkey"));
    // The check fires AFTER the validation-weight deduction (which is itself
    // gated on sig.len > 0), so an empty-sig + empty-pubkey input still
    // surfaces TAPSCRIPT_EMPTY_PUBKEY. Mirrors Core interpreter.cpp:367-368.
    try testing.expect(srcContains(SCRIPT_SRC, "if (pubkey.len == 0) return ScriptError.TapscriptEmptyPubkey;"));
}

test "w127 G25: tapscript: unknown pubkey size (≠ 32) → future-soft-fork (success unchanged) (PRESENT)" {
    try testing.expect(errorSetHas(script.ScriptError, "DiscourageUpgradablePubkeyType"));
    try testing.expect(srcContains(SCRIPT_SRC, "self.flags.discourage_upgradable_pubkeytype"));
    // For op_checksigadd specifically, success is intentionally NOT modified
    // when pubkey.len != 32 — that's the future-soft-fork hook.
    try testing.expect(srcContains(SCRIPT_SRC, "// `success` is intentionally NOT modified"));
}

test "w127 G26: tapscript: MINIMALIF is a CONSENSUS rule (not policy) (PRESENT)" {
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptMinimalIf"));
    // Tapscript MINIMALIF: gated solely on sigversion, no flag check.
    // Witness-v0 MINIMALIF: gated on the flag (policy-only).
    try testing.expect(srcContains(SCRIPT_SRC, "if (self.sig_version == .tapscript) {\n                        if (data.len > 1) return ScriptError.TapscriptMinimalIf;"));
    try testing.expect(srcContains(SCRIPT_SRC, "if (self.sig_version == .witness_v0 and self.flags.verify_minimalif)"));
}

// ===========================================================================
// Cross-cutting / wiring (G27–G30)
// ===========================================================================

test "w127 G27: BIP-341 sighash ext_flag=1 commits to (tapleaf_hash || key_version=0 || codesep_pos) (PRESENT)" {
    // Core SignatureHashSchnorr at interpreter.cpp:1560-1566.
    try testing.expect(srcContains(SIGHASH_SRC, "if (script_path) |sp|"));
    try testing.expect(srcContains(SIGHASH_SRC, "try out.appendSlice(sp.tapleaf_hash);"));
    try testing.expect(srcContains(SIGHASH_SRC, "try out.append(0x00); // key_version"));
    try testing.expect(srcContains(SIGHASH_SRC, "try out.appendSlice(&std.mem.toBytes(std.mem.nativeToLittle(u32, sp.codesep_pos)));"));
}

// ---------------------------------------------------------------------------
// G28: SigCache module exists with Core-parity hashing surface — but is
// never wired into the verify path. BUG-1 P1 (perf).
// ---------------------------------------------------------------------------

test "w127 G28 BUG-1 (P1 perf): SigCache exists with full LRU+nonce shape (PARTIAL)" {
    // The module surface is there:
    try testing.expect(@hasDecl(sig_cache, "SigCache"));
    try testing.expect(@hasDecl(sig_cache.SigCache, "init"));
    try testing.expect(@hasDecl(sig_cache.SigCache, "lookup"));
    try testing.expect(@hasDecl(sig_cache.SigCache, "insert"));
    try testing.expect(@hasDecl(sig_cache.SigCache, "computeKey"));
    // The module's own self-doc claims Schnorr support — 32B x-only pk:
    try testing.expect(srcContains(SIGCACHE_SRC, "32 bytes x-only for Schnorr"));
}

test "w127 G28 BUG-1 (P2 perf): SigCache wired at WHOLE-INPUT granularity, not per-CHECKSIG (xfail)" {
    // SigCache IS wired — in validation.zig's `verifyScriptJob` (the
    // parallel checkqueue worker). That cache keys on
    // (txid, prev_script_pubkey, script_sig||witness, flags) — the
    // whole-input replay key. Mempool→block replay hits this; cross-tx
    // / cross-input signature reuse misses.
    try testing.expect(srcContains(VALIDATION_SRC, "sig_cache_mod"));
    try testing.expect(srcContains(VALIDATION_SRC, "cache.lookup(txid, job.prev_script_pubkey, sig_material, flags_u32)"));
    try testing.expect(srcContains(VALIDATION_SRC, "cache.insert(txid, job.prev_script_pubkey, sig_material, flags_u32)"));

    // But crypto.zig's verifySchnorr / verifyEcdsa do NOT consult any
    // cache — every CHECKSIG goes straight to libsecp256k1.
    try testing.expect(!srcContains(CRYPTO_SRC, "sig_cache"));
    try testing.expect(!srcContains(CRYPTO_SRC, "SigCache"));
    // Likewise script.zig — the per-CHECKSIG site has no cache lookup.
    try testing.expect(!srcContains(SCRIPT_SRC, "sig_cache"));
    try testing.expect(!srcContains(SCRIPT_SRC, "SigCache"));
}

// ---------------------------------------------------------------------------
// G29: PrecomputedTransactionData analog missing. BUG-2 P1 (perf).
// ---------------------------------------------------------------------------

test "w127 G29 BUG-2 (P1 perf): no PrecomputedTransactionData; sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences re-hashed per input (xfail)" {
    // Core's PrecomputedTransactionData caches:
    //   m_prevouts_single_hash, m_spent_amounts_single_hash,
    //   m_spent_scripts_single_hash, m_sequences_single_hash,
    //   m_outputs_single_hash, m_spent_outputs[]
    // and reuses them across every input's sighash. clearbit's
    // taproot_sighash.zig rebuilds all four SHA256 streams on every call —
    // i.e. once per CHECKSIG inside every input. Quadratic-ish cost.
    //
    // None of the cache field names appear in the codebase:
    try testing.expect(!srcContains(SIGHASH_SRC, "PrecomputedTransactionData"));
    try testing.expect(!srcContains(SIGHASH_SRC, "m_prevouts_single_hash"));
    try testing.expect(!srcContains(SIGHASH_SRC, "prevouts_single_hash"));
    try testing.expect(!srcContains(SIGHASH_SRC, "spent_amounts_single_hash"));
    // And the buildSigMsg fn itself walks tx.inputs unconditionally each call:
    try testing.expect(srcContains(SIGHASH_SRC, "for (tx.inputs) |inp| {"));
    try testing.expect(srcContains(SIGHASH_SRC, "&crypto.sha256(prevouts_buf.items)"));
}

// ---------------------------------------------------------------------------
// G30: BIP-341/342 canonical vectors not exercised by `zig build test`.
// BUG-3 P2 (coverage).
// ---------------------------------------------------------------------------

test "w127 G30 BUG-3 (P2 coverage): bip341_wallet_vectors.json not @embedFile'd by any in-tree test (xfail)" {
    // The vector-runner provenance is in `tools/bip341-vector-runner/`,
    // which `zig build test` does NOT invoke. tests_wallet_taproot.zig
    // mentions the vector filename in a docstring + cites Vector 0's
    // hardcoded hex constants for BIP-86 — but neither test actually
    // @embedFile's the JSON and round-trips all 7 keyPathSpending vectors.
    //
    // We test for @embedFile of the literal file name (which would mean
    // the canonical JSON is in tree and CI walks every vector).
    const test_files = .{
        @embedFile("tests_w125_error_parity.zig"),
        @embedFile("tests_wallet_taproot.zig"),
    };
    inline for (test_files) |tf| {
        try testing.expect(!srcContains(tf, "@embedFile(\"bip341_wallet_vectors.json\")"));
        try testing.expect(!srcContains(tf, "@embedFile(\"../bip341_wallet_vectors.json\")"));
    }
}

test "w127 G30 BUG-3 (P2 coverage): script_assets_test.json not embedded by any in-tree test (xfail)" {
    // Same gap for Core's tapscript end-to-end vector file
    // (`src/test/data/script_assets_test.json`) — covers OP_CHECKSIGADD,
    // every leaf-version + control-block error, MINIMALIF, OP_SUCCESSx.
    const test_files = .{
        @embedFile("tests_w125_error_parity.zig"),
        @embedFile("tests_wallet_taproot.zig"),
    };
    inline for (test_files) |tf| {
        try testing.expect(!srcContains(tf, "script_assets_test.json"));
    }
}

// ===========================================================================
// Additional BUG xfails (BUG-4..9) — surfaced during the gate walk but not
// tied to a single G## row. Kept here for forward-regression guard duty.
// ===========================================================================

test "w127 BUG-4 (P2 wire-format): discourage_upgradable_witness_program emits WitnessProgramMismatch (xfail)" {
    // Core emits SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM at
    // interpreter.cpp:1993-1995. clearbit returns
    // ScriptError.WitnessProgramMismatch (script.zig:1281). The dedicated
    // enum variant is MISSING from ScriptError.
    try testing.expect(!errorSetHas(script.ScriptError, "DiscourageUpgradableWitnessProgram"));
    // And the wrong code is hardcoded at the site:
    try testing.expect(srcContains(SCRIPT_SRC, "self.flags.discourage_upgradable_witness_program"));
    try testing.expect(srcContains(SCRIPT_SRC, "return ScriptError.WitnessProgramMismatch;"));
}

test "w127 BUG-5 (P3 cosmetic): comment at script.zig:1262 documents an unreachable branch" {
    // The else-branch at line 1262 ("effective_witness.len == 0 after annex
    // strip") is structurally unreachable because annex strip is gated on
    // witness.len >= 2 (so a strip leaves at least 1 element). The branch
    // exists for defense-in-depth but its docstring is misleading.
    try testing.expect(srcContains(SCRIPT_SRC, "effective_witness.len == 0 after annex strip"));
}

test "w127 BUG-6 (P3 cosmetic): tapleaf_hash field never reset across verify() calls" {
    // The engine's tapleaf_hash field is set at script.zig:1194 and consulted
    // at line 2316. No reset-on-failure path; relies on per-input
    // construction. Tripwire for future engine pooling.
    try testing.expect(srcContains(SCRIPT_SRC, "tapleaf_hash: ?[32]u8 = null"));
    try testing.expect(srcContains(SCRIPT_SRC, "self.tapleaf_hash = tlh;"));
    // No reset between iterations:
    try testing.expect(!srcContains(SCRIPT_SRC, "self.tapleaf_hash = null;"));
}

test "w127 BUG-7 (P3 cosmetic): codesep_pos default set at construction, not per-EvalScript-entry" {
    // Core resets execdata.m_codeseparator_pos = 0xFFFFFFFFUL inside
    // EvalScript at entry (interpreter.cpp:434). clearbit sets it once at
    // engine construction (script.zig:697) and never re-asserts.
    try testing.expect(srcContains(SCRIPT_SRC, ".codesep_pos = 0xFFFFFFFF,"));
    // No per-entry reset inside the script execution loop:
    try testing.expect(!srcContains(SCRIPT_SRC, "self.codesep_pos = 0xFFFFFFFF;"));
}

test "w127 BUG-8 (P3 cosmetic): consumeValidationWeight returns error instead of asserting on uninit (defensive guard)" {
    // Core asserts m_validation_weight_left_init at interpreter.cpp:361.
    // clearbit's consumeValidationWeight returns
    // TapscriptValidationWeight on uninit — fail-closed, but the wrong
    // error class for the assertion-failure mode.
    try testing.expect(srcContains(SCRIPT_SRC, "if (!self.validation_weight_init) return ScriptError.TapscriptValidationWeight;"));
}

test "w127 BUG-9 (P2 wire-format): partial enum coverage of Core's SCRIPT_ERR_* set" {
    // Inventory of Core SCRIPT_ERR_* variants that DO exist in clearbit:
    try testing.expect(errorSetHas(script.ScriptError, "TaprootWrongControlSize"));
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptValidationWeight"));
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptCheckmultisigDisabled"));
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptMinimalIf"));
    try testing.expect(errorSetHas(script.ScriptError, "TapscriptEmptyPubkey"));
    try testing.expect(errorSetHas(script.ScriptError, "SchnorrSigSize"));
    try testing.expect(errorSetHas(script.ScriptError, "SchnorrSigHashType"));
    try testing.expect(errorSetHas(script.ScriptError, "DiscourageOpSuccess"));
    try testing.expect(errorSetHas(script.ScriptError, "DiscourageUpgradablePubkeyType"));
    try testing.expect(errorSetHas(script.ScriptError, "DiscourageUpgradableTaprootVersion"));
    try testing.expect(errorSetHas(script.ScriptError, "WitnessProgramWitnessEmpty"));

    // But these are MISSING:
    //   SchnorrSig         — Core SCRIPT_ERR_SCHNORR_SIG (the actual verify
    //                        failure result code, distinct from SIG_SIZE /
    //                        SIG_HASHTYPE which are encoding-error codes)
    //   DiscourageUpgradableWitnessProgram (also flagged in BUG-4)
    try testing.expect(!errorSetHas(script.ScriptError, "SchnorrSig"));
    try testing.expect(!errorSetHas(script.ScriptError, "DiscourageUpgradableWitnessProgram"));
}

// ===========================================================================
// Sanity smoke tests: actual round-trip arithmetic where convenient.
// ===========================================================================

test "w127 smoke: serializedWitnessStackSize matches hand-computed bytes" {
    // Empty witness: just a compactsize(0) = 1 byte.
    try testing.expectEqual(@as(u64, 1), script.serializedWitnessStackSize(&[_][]const u8{}));

    // One empty item: compactsize(1) + compactsize(0) = 1 + 1 = 2 bytes.
    const one_empty = [_][]const u8{&[_]u8{}};
    try testing.expectEqual(@as(u64, 2), script.serializedWitnessStackSize(&one_empty));

    // Two items, 32 bytes each: cs(2)=1 + 2*(cs(32)+32) = 1 + 2*33 = 67.
    const item32 = [_]u8{0xAA} ** 32;
    const two_32 = [_][]const u8{ &item32, &item32 };
    try testing.expectEqual(@as(u64, 67), script.serializedWitnessStackSize(&two_32));
}

test "w127 smoke: computeTapleafHash differs for different leaf versions" {
    const script_bytes = [_]u8{0x51}; // OP_1
    const tlh_c0 = crypto.computeTapleafHash(&script_bytes, 0xc0).?;
    const tlh_c2 = crypto.computeTapleafHash(&script_bytes, 0xc2).?;
    try testing.expect(!std.mem.eql(u8, &tlh_c0, &tlh_c2));
}

test "w127 smoke: SIGHASH_DEFAULT is 0x00" {
    // Core's SIGHASH_DEFAULT = 0x00 (interpreter.h). Pin this so a renumber
    // would break the audit immediately.
    try testing.expectEqual(@as(u8, 0x00), taproot_sighash.SIGHASH_DEFAULT);
    try testing.expectEqual(@as(u8, 0x01), taproot_sighash.SIGHASH_ALL);
    try testing.expectEqual(@as(u8, 0x02), taproot_sighash.SIGHASH_NONE);
    try testing.expectEqual(@as(u8, 0x03), taproot_sighash.SIGHASH_SINGLE);
    try testing.expectEqual(@as(u8, 0x80), taproot_sighash.SIGHASH_ANYONECANPAY);
}
