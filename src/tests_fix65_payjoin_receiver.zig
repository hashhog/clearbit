//! FIX-65 — BIP-78 PayJoin receiver foundation (plain HTTP).
//!
//! Tests the W119 audit's receiver-side foundation gates flipped by FIX-65:
//!   - G1  receiver HTTP endpoint (handler types + decls present)
//!   - G16 query-parameter parser (`v=`, `additionalfeeoutputindex=`, …)
//!   - G17 4 BIP-78 well-known error codes
//!   - G21 v=1 version-pin handler
//!
//! Also covers the round-trip (deserialize Original PSBT → validate →
//! produce Proposal base64) and the four BIP-78 error paths that the
//! handler emits.
//!
//! Transport stance: PLAIN HTTP ONLY.  See the deferral block in
//! `src/rpc.zig` near `PAYJOIN_VERSION` for the rationale (Zig 0.13
//! stdlib has no server-side TLS; operators must front the route with
//! nginx / Caddy / Tor for production exposure).  Tests here don't
//! exercise TLS — `tests_fix64_tls.zig` covers the deferral surface
//! explicitly.
//!
//! Run with `zig build test-fix65`.

const std = @import("std");
const testing = std.testing;
const rpc = @import("rpc.zig");
const psbt_mod = @import("psbt.zig");
const types = @import("types.zig");

// ---------------------------------------------------------------------------
// G1: receiver foundation decls are present (the audit-flip surface).
// ---------------------------------------------------------------------------
test "fix65/G1: PayjoinHandler + handlePayjoinRequest decls exist" {
    try testing.expect(@hasDecl(rpc, "PayjoinHandler"));
    try testing.expect(@hasDecl(rpc, "handlePayjoinRequest") or @hasDecl(rpc.RpcServer, "handlePayjoinRequest"));
    // PayjoinHandler is a namespace; its key methods must exist.
    try testing.expect(@hasDecl(rpc.PayjoinHandler, "deserializeOriginalBase64"));
    try testing.expect(@hasDecl(rpc.PayjoinHandler, "validateOriginalPsbt"));
    try testing.expect(@hasDecl(rpc.PayjoinHandler, "buildProposalBase64"));
    try testing.expect(@hasDecl(rpc.PayjoinHandler, "formatErrorJson"));
}

// ---------------------------------------------------------------------------
// G17: the four BIP-78 well-known error codes exist as named decls AND
// have the spec-mandated wire strings.  Verbatim wire compatibility is
// load-bearing — BTCPayServer.Payjoin matches on these strings.
// ---------------------------------------------------------------------------
test "fix65/G17: 4 BIP-78 error code constants present with correct strings" {
    try testing.expect(@hasDecl(rpc, "PAYJOIN_ERR_UNAVAILABLE"));
    try testing.expect(@hasDecl(rpc, "PAYJOIN_ERR_NOT_ENOUGH_MONEY"));
    try testing.expect(@hasDecl(rpc, "PAYJOIN_ERR_VERSION_UNSUPPORTED"));
    try testing.expect(@hasDecl(rpc, "PAYJOIN_ERR_ORIGINAL_REJECTED"));
    try testing.expectEqualStrings("unavailable", rpc.PAYJOIN_ERR_UNAVAILABLE);
    try testing.expectEqualStrings("not-enough-money", rpc.PAYJOIN_ERR_NOT_ENOUGH_MONEY);
    try testing.expectEqualStrings("version-unsupported", rpc.PAYJOIN_ERR_VERSION_UNSUPPORTED);
    try testing.expectEqualStrings("original-psbt-rejected", rpc.PAYJOIN_ERR_ORIGINAL_REJECTED);
}

test "fix65/G17: PayjoinError enum maps to all 4 wire codes" {
    try testing.expect(@hasDecl(rpc, "PayjoinError"));
    try testing.expectEqualStrings(rpc.PAYJOIN_ERR_UNAVAILABLE, rpc.payjoinErrorCode(rpc.PayjoinError.Unavailable));
    try testing.expectEqualStrings(rpc.PAYJOIN_ERR_NOT_ENOUGH_MONEY, rpc.payjoinErrorCode(rpc.PayjoinError.NotEnoughMoney));
    try testing.expectEqualStrings(rpc.PAYJOIN_ERR_VERSION_UNSUPPORTED, rpc.payjoinErrorCode(rpc.PayjoinError.VersionUnsupported));
    try testing.expectEqualStrings(rpc.PAYJOIN_ERR_ORIGINAL_REJECTED, rpc.payjoinErrorCode(rpc.PayjoinError.OriginalRejected));
}

// ---------------------------------------------------------------------------
// G21: v=1 version-pin handler — `PAYJOIN_VERSION` + checker present.
// ---------------------------------------------------------------------------
test "fix65/G21: PAYJOIN_VERSION = 1 + checkPayjoinVersion present" {
    try testing.expect(@hasDecl(rpc, "PAYJOIN_VERSION"));
    try testing.expectEqual(@as(u32, 1), rpc.PAYJOIN_VERSION);
    try testing.expect(@hasDecl(rpc, "checkPayjoinVersion"));
}

test "fix65/G21: checkPayjoinVersion rejects missing v=" {
    const q = rpc.PayjoinQuery{}; // version: null
    try testing.expectError(rpc.PayjoinError.VersionUnsupported, rpc.checkPayjoinVersion(&q));
}

test "fix65/G21: checkPayjoinVersion rejects v=2 / v=0 / non-1" {
    const cases = [_]u32{ 0, 2, 99, 0xFFFFFFFF };
    for (cases) |v| {
        const q = rpc.PayjoinQuery{ .version = v };
        try testing.expectError(rpc.PayjoinError.VersionUnsupported, rpc.checkPayjoinVersion(&q));
    }
}

test "fix65/G21: checkPayjoinVersion accepts v=1" {
    const q = rpc.PayjoinQuery{ .version = 1 };
    try rpc.checkPayjoinVersion(&q);
}

// ---------------------------------------------------------------------------
// G16: query parser — exercises all 5 BIP-78 optional parameters.
// ---------------------------------------------------------------------------
test "fix65/G16: parsePayjoinQuery happy path with all 5 params" {
    const q = "v=1&additionalfeeoutputindex=0&maxadditionalfeecontribution=1234&disableoutputsubstitution=0&minfeerate=2";
    const result = try rpc.parsePayjoinQuery(q);
    try testing.expectEqual(@as(?u32, 1), result.version);
    try testing.expectEqual(@as(?usize, 0), result.additional_fee_output_index);
    try testing.expectEqual(@as(?u64, 1234), result.max_additional_fee_contribution);
    try testing.expect(!result.disable_output_substitution);
    try testing.expectEqual(@as(u64, 2), result.min_fee_rate);
}

test "fix65/G16: parsePayjoinQuery empty string → null version (default fields)" {
    const result = try rpc.parsePayjoinQuery("");
    try testing.expectEqual(@as(?u32, null), result.version);
    try testing.expectEqual(@as(?usize, null), result.additional_fee_output_index);
    try testing.expectEqual(@as(?u64, null), result.max_additional_fee_contribution);
    try testing.expect(!result.disable_output_substitution);
    try testing.expectEqual(@as(u64, 0), result.min_fee_rate);
}

test "fix65/G16: parsePayjoinQuery ignores unknown forward-compat params" {
    // BIP-78 §"Forward compatibility": unknown params MUST NOT cause failure.
    // The known `v=1` must still be picked up.
    const q = "v=1&future-flag=xyz&another=abc";
    const result = try rpc.parsePayjoinQuery(q);
    try testing.expectEqual(@as(?u32, 1), result.version);
}

test "fix65/G16: parsePayjoinQuery accepts true/false strings for output-sub" {
    {
        const r = try rpc.parsePayjoinQuery("v=1&disableoutputsubstitution=true");
        try testing.expect(r.disable_output_substitution);
    }
    {
        const r = try rpc.parsePayjoinQuery("v=1&disableoutputsubstitution=false");
        try testing.expect(!r.disable_output_substitution);
    }
    {
        const r = try rpc.parsePayjoinQuery("v=1&disableoutputsubstitution=1");
        try testing.expect(r.disable_output_substitution);
    }
}

test "fix65/G16: parsePayjoinQuery case-insensitive key match" {
    const q = "V=1&AdditionalFeeOutputIndex=3";
    const result = try rpc.parsePayjoinQuery(q);
    try testing.expectEqual(@as(?u32, 1), result.version);
    try testing.expectEqual(@as(?usize, 3), result.additional_fee_output_index);
}

test "fix65/G16: parsePayjoinQuery rejects malformed disableoutputsubstitution" {
    const q = "v=1&disableoutputsubstitution=maybe";
    try testing.expectError(rpc.PayjoinError.OriginalRejected, rpc.parsePayjoinQuery(q));
}

test "fix65/G16: parsePayjoinQuery rejects non-numeric maxadditionalfeecontribution" {
    const q = "v=1&maxadditionalfeecontribution=NaN";
    try testing.expectError(rpc.PayjoinError.OriginalRejected, rpc.parsePayjoinQuery(q));
}

test "fix65/G16: parsePayjoinQuery rejects non-numeric v=" {
    const q = "v=abc";
    try testing.expectError(rpc.PayjoinError.VersionUnsupported, rpc.parsePayjoinQuery(q));
}

// ---------------------------------------------------------------------------
// Round-trip: build a minimal Original PSBT, run it through the receiver
// foundation, and confirm the Proposal is a valid base64 PSBT that round-
// trips.  FIX-65's Proposal is an echo of the Original — see the
// `PayjoinHandler.buildProposalBase64` doc for why this is BIP-78 compliant.
// ---------------------------------------------------------------------------

/// Helper: build a minimal, syntactically-valid Original PSBT with one
/// input (carrying a witness UTXO) and one output.
fn buildMinimalOriginal(allocator: std.mem.Allocator) !psbt_mod.Psbt {
    const tx_inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x42} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD, // BIP-125 RBF (matches FIX-61)
        .witness = &[_][]const u8{},
    }};
    const dummy_spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const tx_outputs = [_]types.TxOut{.{
        .value = 9_000,
        .script_pubkey = &dummy_spk,
    }};
    const tx = types.Transaction{
        .version = 2,
        .inputs = &tx_inputs,
        .outputs = &tx_outputs,
        .lock_time = 0,
    };
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    errdefer psbt.deinit();
    // Witness UTXO is required by validateOriginalPsbt.
    try psbt.addInputUtxo(0, types.TxOut{
        .value = 10_000,
        .script_pubkey = &dummy_spk,
    });
    return psbt;
}

test "fix65/round-trip: Original PSBT → validate → Proposal base64 → re-parse" {
    const allocator = testing.allocator;
    var original = try buildMinimalOriginal(allocator);
    defer original.deinit();

    const original_b64 = try original.toBase64(allocator);
    defer allocator.free(original_b64);

    // 1. deserialize: simulate the HTTP body arriving as base64 text.
    var received = try rpc.PayjoinHandler.deserializeOriginalBase64(allocator, original_b64);
    defer received.deinit();

    // 2. validate: must accept a well-formed Original.
    try rpc.PayjoinHandler.validateOriginalPsbt(&received);

    // 3. build proposal.
    const proposal_b64 = try rpc.PayjoinHandler.buildProposalBase64(allocator, &received);
    defer allocator.free(proposal_b64);

    // 4. proposal must be valid base64 PSBT that round-trips.
    try testing.expect(std.mem.startsWith(u8, proposal_b64, "cHNidP8")); // "psbt\xff" b64
    var reparsed = try psbt_mod.Psbt.fromBase64(allocator, proposal_b64);
    defer reparsed.deinit();
    try testing.expectEqual(original.tx.inputs.len, reparsed.tx.inputs.len);
    try testing.expectEqual(original.tx.outputs.len, reparsed.tx.outputs.len);
    try testing.expectEqual(@as(i64, 9_000), reparsed.tx.outputs[0].value);
}

test "fix65/round-trip: handler tolerates trailing whitespace / CRLF" {
    const allocator = testing.allocator;
    var original = try buildMinimalOriginal(allocator);
    defer original.deinit();

    const original_b64 = try original.toBase64(allocator);
    defer allocator.free(original_b64);

    // Simulate an HTTP client that appends CR/LF/spaces.
    const padded = try std.fmt.allocPrint(allocator, "  {s}\r\n", .{original_b64});
    defer allocator.free(padded);

    var received = try rpc.PayjoinHandler.deserializeOriginalBase64(allocator, padded);
    defer received.deinit();
    try rpc.PayjoinHandler.validateOriginalPsbt(&received);
}

// ---------------------------------------------------------------------------
// Error path 1 (unavailable): not exercised in pure-fn tests at this layer
// — `unavailable` is the wallet-locked path inside handlePayjoinRequest,
// which requires a running RpcServer + Wallet harness.  We assert the
// shape of the JSON instead so the wire emission is verified.
// ---------------------------------------------------------------------------
test "fix65/err-unavailable: JSON shape" {
    const allocator = testing.allocator;
    const body = try rpc.PayjoinHandler.formatErrorJson(allocator, rpc.PAYJOIN_ERR_UNAVAILABLE, "Receiver wallet is locked");
    defer allocator.free(body);
    try testing.expectEqualStrings(
        "{\"errorCode\":\"unavailable\",\"message\":\"Receiver wallet is locked\"}",
        body,
    );
}

// ---------------------------------------------------------------------------
// Error path 2 (not-enough-money): JSON shape sanity.
// ---------------------------------------------------------------------------
test "fix65/err-not-enough-money: JSON shape" {
    const allocator = testing.allocator;
    const body = try rpc.PayjoinHandler.formatErrorJson(allocator, rpc.PAYJOIN_ERR_NOT_ENOUGH_MONEY, "no eligible receiver UTXO");
    defer allocator.free(body);
    try testing.expectEqualStrings(
        "{\"errorCode\":\"not-enough-money\",\"message\":\"no eligible receiver UTXO\"}",
        body,
    );
}

// ---------------------------------------------------------------------------
// Error path 3 (version-unsupported): triggered by parser + checker.
// ---------------------------------------------------------------------------
test "fix65/err-version-unsupported: triggered by v=2" {
    const q = try rpc.parsePayjoinQuery("v=2");
    try testing.expectError(rpc.PayjoinError.VersionUnsupported, rpc.checkPayjoinVersion(&q));
    const allocator = testing.allocator;
    const body = try rpc.PayjoinHandler.formatErrorJson(allocator, rpc.PAYJOIN_ERR_VERSION_UNSUPPORTED, "BIP-78 version not supported");
    defer allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "version-unsupported") != null);
}

// ---------------------------------------------------------------------------
// Error path 4 (original-psbt-rejected): triggered by bad base64 + bad PSBT.
// ---------------------------------------------------------------------------
test "fix65/err-original-rejected: invalid base64 → OriginalRejected" {
    const allocator = testing.allocator;
    try testing.expectError(
        rpc.PayjoinError.OriginalRejected,
        rpc.PayjoinHandler.deserializeOriginalBase64(allocator, "@@@not valid base64@@@"),
    );
}

test "fix65/err-original-rejected: empty body → OriginalRejected" {
    const allocator = testing.allocator;
    try testing.expectError(
        rpc.PayjoinError.OriginalRejected,
        rpc.PayjoinHandler.deserializeOriginalBase64(allocator, ""),
    );
    try testing.expectError(
        rpc.PayjoinError.OriginalRejected,
        rpc.PayjoinHandler.deserializeOriginalBase64(allocator, "   \r\n   "),
    );
}

test "fix65/err-original-rejected: PSBT without UTXO record → reject" {
    const allocator = testing.allocator;
    // Build an Original PSBT but DON'T set the witness/non-witness UTXO on
    // the input — this is exactly the "Original failed checklist" case.
    const tx_inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x42} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    const dummy_spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const tx_outputs = [_]types.TxOut{.{
        .value = 9_000,
        .script_pubkey = &dummy_spk,
    }};
    const tx = types.Transaction{
        .version = 2,
        .inputs = &tx_inputs,
        .outputs = &tx_outputs,
        .lock_time = 0,
    };
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();
    // Note: no addInputUtxo call here — should fail the checklist.
    try testing.expectError(
        rpc.PayjoinError.OriginalRejected,
        rpc.PayjoinHandler.validateOriginalPsbt(&psbt),
    );
}

test "fix65/err-original-rejected: PSBT with zero outputs → reject" {
    const allocator = testing.allocator;
    const tx_inputs = [_]types.TxIn{.{
        .previous_output = .{ .hash = [_]u8{0x42} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFD,
        .witness = &[_][]const u8{},
    }};
    const tx = types.Transaction{
        .version = 2,
        .inputs = &tx_inputs,
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    var psbt = try psbt_mod.Psbt.create(allocator, tx);
    defer psbt.deinit();
    try testing.expectError(
        rpc.PayjoinError.OriginalRejected,
        rpc.PayjoinHandler.validateOriginalPsbt(&psbt),
    );
}

// ---------------------------------------------------------------------------
// Audit-flip preservation guard.
//
// The W119 audit (tests_w119_payjoin.zig) flipped G1/G16/G17/G21 from
// `!@hasDecl` to `@hasDecl` in FIX-65.  Other PayJoin-specific decls
// (G2/G5/G7/etc.) remain absent and are scheduled for future fix waves.
// Re-assert the absence here so a future patch that tries to "complete"
// PayJoin without removing the corresponding `@hasDecl` assertion in
// tests_w119_payjoin.zig fails this file first.
// ---------------------------------------------------------------------------
test "fix65/audit: receiver-foundation decls present (G1+G16+G17+G21 flipped)" {
    try testing.expect(@hasDecl(rpc, "PayjoinHandler"));
    try testing.expect(@hasDecl(rpc, "parsePayjoinQuery"));
    try testing.expect(@hasDecl(rpc, "PayjoinQuery"));
    try testing.expect(@hasDecl(rpc, "PayjoinError"));
    try testing.expect(@hasDecl(rpc, "PAYJOIN_VERSION"));
    try testing.expect(@hasDecl(rpc, "checkPayjoinVersion"));
}

test "fix65/audit: deferred sender + Implementation Suggestions decls remain ABSENT" {
    // G2: sender HTTP client — deferred.
    const wallet_mod = @import("wallet.zig");
    try testing.expect(!@hasDecl(wallet_mod, "sendPayjoinRequest"));
    try testing.expect(!@hasDecl(wallet_mod, "postOriginalPsbt"));
    // G10/G12/G13/G14/G15: sender anti-snoop validators — deferred.
    try testing.expect(!@hasDecl(wallet_mod, "validatePayjoinProposal"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinAntiSnoop"));
    // G18/G19/G20/G30: implementation suggestions — deferred.
    try testing.expect(!@hasDecl(rpc, "PayjoinRequestCache"));
    try testing.expect(!@hasDecl(rpc, "PayjoinReplayCache"));
    try testing.expect(!@hasDecl(wallet_mod, "lockPayjoinUtxo"));
    // G25 Tor / G24 TLS receiver-side — deferred (W119/G3 + G24).
    try testing.expect(!@hasDecl(rpc, "TlsPayjoinServer"));
    try testing.expect(!@hasDecl(rpc, "OnionPayjoinServer"));
    try testing.expect(!@hasDecl(rpc, "publishOnionService"));
}
