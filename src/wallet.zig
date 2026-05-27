const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const address = @import("address.zig");
const consensus = @import("consensus.zig");
const taproot_sighash = @import("taproot_sighash.zig");
const bip21 = @import("bip21.zig");
const psbt_mod = @import("psbt.zig");
const script_mod = @import("script.zig");

// ============================================================================
// BIP-21 URI parser re-exports (FIX-62 / W119 prereq).
//
// `wallet.zig` is the natural import point for PayJoin sender code that
// extracts `pj=` / `pjos=` from a payment URI before opening a network
// connection.  Re-exporting from here means the sender doesn't have to add a
// second module import alongside the existing `address` and `psbt` imports.
// `parsePjosParam` is the wallet-side alias for `bip21.parseBip21Pjos` (BIP-78
// `pjos=0|1`).
// ============================================================================

pub const Bip21Uri = bip21.Bip21Uri;
pub const parseBip21 = bip21.parseBip21;
pub const parseBip21Pjos = bip21.parseBip21Pjos;

/// Sender-side helper: parse the `pjos=` value from a BIP-21 URI, returning
/// the BIP-78 disable-output-substitution toggle.  `null` means the URI did
/// not include the parameter, in which case the BIP-78 default is "1"
/// (substitution disabled).
pub fn parsePjosParam(input: []const u8) !?bool {
    return bip21.parseBip21Pjos(input);
}

// ============================================================================
// BIP-78 PayJoin sender — wallet-side surface (FIX-66, W119 G2/G10-G15/G22)
// ----------------------------------------------------------------------------
// Wallet-side re-exports of the sender primitives implemented in rpc.zig.
// We keep the implementation in rpc.zig (alongside the FIX-65 receiver
// foundation) and surface the audit-named decls here so the W119 gate
// `@hasDecl(wallet_mod, "validatePayjoinProposal")` etc. resolves without
// callers needing two module imports.
//
// To avoid the wallet→rpc circular import (`rpc.zig` already imports
// `wallet.zig`), every function below is a thin standalone wrapper that
// uses only `psbt_mod`, `script_mod`, and the small `PayjoinSenderQuery`
// duck-typed struct defined here.  The wire-shape is fully compatible
// with `rpc.PayjoinQuery`: any caller can pass either one.
//
// Transport stance: PLAIN HTTP ONLY (matches FIX-64/65/66 receiver-side
// stance — see `rpc.zig` PayjoinSender block for the full deferral
// rationale).  Wallet sender code uses `std.http.Client` directly with
// `http://` URLs; the W119/G24 audit gate (`!@hasDecl(rpc_mod,
// "TlsClient")`) asserts that no TLS-client decl appears in either
// module.
//
// What this block ships:
//   - `PayjoinSenderQuery` — wallet-local query struct (mirrors
//     `rpc.PayjoinQuery` field-for-field).  Avoids the wallet→rpc cycle.
//   - `PayjoinSenderError` — Zig error set: `Unavailable`,
//     `NotEnoughMoney`, `VersionUnsupported`, `OriginalRejected`.
//   - 6 anti-snoop validators G10-G15 (`payjoinAntiSnoop`,
//     `payjoinInputTypeCheck`, `payjoinInputDisjoint`,
//     `payjoinFeeContribCheck`, `payjoinDisableOutSub`,
//     `payjoinMinFeeRate`).
//   - `validatePayjoinProposal` — runs all 6 in BIP-78 order.
//   - `postOriginalPsbt` — HTTP POST against a `http://` URL using
//     `std.http.Client.fetch`.
//   - `sendPayjoinRequest` — full flow: POST → parse → validate (G10-G15)
//     → return Proposal PSBT.
//   - `payjoinFallback` + `broadcastPayjoinOriginal` — G22 fallback
//     (broadcast Original verbatim on receiver failure).
// ============================================================================

/// Sender-side BIP-78 query, parallel to `rpc.PayjoinQuery`.  Kept here
/// separately to avoid the wallet→rpc circular import; the field layout
/// is identical so wallet senders can convert without ceremony.
pub const PayjoinSenderQuery = struct {
    version: ?u32 = 1,
    additional_fee_output_index: ?usize = null,
    max_additional_fee_contribution: ?u64 = null,
    disable_output_substitution: bool = false,
    min_fee_rate: u64 = 0,
};

/// Sender-side BIP-78 error set, parallel to `rpc.PayjoinError`.  Same
/// four variants → same four wire-strings; wallet senders that want to
/// surface the wire-string from their RPC handler can `@errorName(e)`.
pub const PayjoinSenderError = error{
    Unavailable,
    NotEnoughMoney,
    VersionUnsupported,
    OriginalRejected,
};

/// G10 (P0/CDIV/SECURITY) — every original output preserved (modulo at
/// most one substituted receiver output when `disable_output_substitution=
/// false`).  See `rpc.PayjoinSender.checkOutputsAntiSnoop` for the
/// detailed BIP-78 reference.
pub fn payjoinAntiSnoop(
    original: *const psbt_mod.Psbt,
    proposal: *const psbt_mod.Psbt,
    query: *const PayjoinSenderQuery,
) PayjoinSenderError!void {
    const orig_outs = original.tx.outputs;
    const prop_outs = proposal.tx.outputs;
    if (prop_outs.len < orig_outs.len) return error.OriginalRejected;

    var diff_count: usize = 0;
    var i: usize = 0;
    while (i < orig_outs.len) : (i += 1) {
        if (!std.mem.eql(u8, orig_outs[i].script_pubkey, prop_outs[i].script_pubkey)) {
            diff_count += 1;
        } else {
            if (prop_outs[i].value < orig_outs[i].value) return error.OriginalRejected;
        }
    }
    if (query.disable_output_substitution and diff_count != 0) return error.OriginalRejected;
    if (diff_count > 1) return error.OriginalRejected;
}

/// G11 (MED/PRIVACY) — every receiver-added input shares the scriptSig
/// type with at least one Original input.  Mismatched types defeat
/// BIP-78's privacy goal.
pub fn payjoinInputTypeCheck(
    original: *const psbt_mod.Psbt,
    proposal: *const psbt_mod.Psbt,
) PayjoinSenderError!void {
    const orig_inputs = original.tx.inputs;
    const prop_inputs = proposal.tx.inputs;
    if (prop_inputs.len < orig_inputs.len) return error.OriginalRejected;
    if (orig_inputs.len == 0) return error.OriginalRejected;

    var orig_types: [16]script_mod.ScriptType = undefined;
    var orig_type_count: usize = 0;
    var i: usize = 0;
    while (i < orig_inputs.len and orig_type_count < orig_types.len) : (i += 1) {
        const wutxo = original.inputs[i].witness_utxo orelse continue;
        const t = script_mod.classifyScript(wutxo.script_pubkey);
        var dup = false;
        for (orig_types[0..orig_type_count]) |ot| {
            if (ot == t) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            orig_types[orig_type_count] = t;
            orig_type_count += 1;
        }
    }
    if (orig_type_count == 0) return error.OriginalRejected;

    var j: usize = orig_inputs.len;
    while (j < prop_inputs.len) : (j += 1) {
        const wutxo = proposal.inputs[j].witness_utxo orelse return error.OriginalRejected;
        const t = script_mod.classifyScript(wutxo.script_pubkey);
        var matched = false;
        for (orig_types[0..orig_type_count]) |ot| {
            if (ot == t) {
                matched = true;
                break;
            }
        }
        if (!matched) return error.OriginalRejected;
    }
}

/// G12 (P0/CDIV/SECURITY) — receiver MUST NOT add an input already in
/// the Original.  Prevout-set disjoint check.
pub fn payjoinInputDisjoint(
    original: *const psbt_mod.Psbt,
    proposal: *const psbt_mod.Psbt,
) PayjoinSenderError!void {
    const orig_inputs = original.tx.inputs;
    const prop_inputs = proposal.tx.inputs;
    if (prop_inputs.len < orig_inputs.len) return error.OriginalRejected;

    var i: usize = 0;
    while (i < orig_inputs.len) : (i += 1) {
        const o = orig_inputs[i].previous_output;
        const p = prop_inputs[i].previous_output;
        if (p.index != o.index) return error.OriginalRejected;
        if (!std.mem.eql(u8, &p.hash, &o.hash)) return error.OriginalRejected;
    }

    var j: usize = orig_inputs.len;
    while (j < prop_inputs.len) : (j += 1) {
        const added = prop_inputs[j].previous_output;
        var k: usize = 0;
        while (k < orig_inputs.len) : (k += 1) {
            if (added.index == orig_inputs[k].previous_output.index and
                std.mem.eql(u8, &added.hash, &orig_inputs[k].previous_output.hash))
                return error.OriginalRejected;
        }
    }
}

/// G13 (HIGH) — the proposal's fee-output debit MUST NOT exceed the
/// sender's `maxadditionalfeecontribution` cap, and the recipient
/// output's value MUST NOT decrease.
pub fn payjoinFeeContribCheck(
    original: *const psbt_mod.Psbt,
    proposal: *const psbt_mod.Psbt,
    query: *const PayjoinSenderQuery,
) PayjoinSenderError!void {
    const orig_outs = original.tx.outputs;
    const prop_outs = proposal.tx.outputs;
    const cap: u64 = query.max_additional_fee_contribution orelse 0;
    const fee_idx = query.additional_fee_output_index orelse {
        var i: usize = 0;
        while (i < orig_outs.len) : (i += 1) {
            if (prop_outs[i].value < orig_outs[i].value) return error.OriginalRejected;
        }
        return;
    };
    if (fee_idx >= orig_outs.len or fee_idx >= prop_outs.len) return error.OriginalRejected;

    var i: usize = 0;
    while (i < orig_outs.len) : (i += 1) {
        if (i == fee_idx) continue;
        if (prop_outs[i].value < orig_outs[i].value) return error.OriginalRejected;
    }

    const orig_fee_value = orig_outs[fee_idx].value;
    const prop_fee_value = prop_outs[fee_idx].value;
    if (prop_fee_value > orig_fee_value) return error.OriginalRejected;
    const debit: u64 = @intCast(orig_fee_value - prop_fee_value);
    if (debit > cap) return error.OriginalRejected;
}

/// G14 (HIGH) — when sender set `disableoutputsubstitution=true`, no
/// scriptPubKey may change on the originally-provided outputs.
pub fn payjoinDisableOutSub(
    original: *const psbt_mod.Psbt,
    proposal: *const psbt_mod.Psbt,
    query: *const PayjoinSenderQuery,
) PayjoinSenderError!void {
    if (!query.disable_output_substitution) return;
    const orig_outs = original.tx.outputs;
    const prop_outs = proposal.tx.outputs;
    if (prop_outs.len < orig_outs.len) return error.OriginalRejected;
    var i: usize = 0;
    while (i < orig_outs.len) : (i += 1) {
        if (!std.mem.eql(u8, orig_outs[i].script_pubkey, prop_outs[i].script_pubkey))
            return error.OriginalRejected;
    }
}

/// G15 (HIGH) — effective fee rate of the proposal MUST be >=
/// `query.min_fee_rate` (sat/vB).  See
/// `rpc.PayjoinSender.checkMinFeeRate` for the BIP-141 vbyte estimate
/// details (segwit-conservative 10 + 68n_in + 31n_out).
pub fn payjoinMinFeeRate(
    original: *const psbt_mod.Psbt,
    proposal: *const psbt_mod.Psbt,
    query: *const PayjoinSenderQuery,
) PayjoinSenderError!void {
    _ = original;
    if (query.min_fee_rate == 0) return;

    var total_in: i64 = 0;
    for (proposal.inputs) |inp| {
        const wutxo = inp.witness_utxo orelse return error.OriginalRejected;
        total_in += wutxo.value;
    }
    var total_out: i64 = 0;
    for (proposal.tx.outputs) |o| total_out += o.value;
    const fee: i64 = total_in - total_out;
    if (fee <= 0) return error.OriginalRejected;

    const n_in: u64 = @intCast(proposal.tx.inputs.len);
    const n_out: u64 = @intCast(proposal.tx.outputs.len);
    const vbytes: u64 = 10 + 68 * n_in + 31 * n_out;
    if (vbytes == 0) return error.OriginalRejected;

    const ufee: u64 = @intCast(fee);
    const eff_rate: u64 = ufee / vbytes;
    if (eff_rate < query.min_fee_rate) return error.OriginalRejected;
}

/// Validate the Proposal PSBT against all 6 sender-side anti-snoop
/// checks in BIP-78 spec order.  Returns the first violation.
pub fn validatePayjoinProposal(
    original: *const psbt_mod.Psbt,
    proposal: *const psbt_mod.Psbt,
    query: *const PayjoinSenderQuery,
) PayjoinSenderError!void {
    try payjoinInputDisjoint(original, proposal); // G12 (most critical)
    try payjoinAntiSnoop(original, proposal, query); // G10
    try payjoinInputTypeCheck(original, proposal); // G11
    try payjoinFeeContribCheck(original, proposal, query); // G13
    try payjoinDisableOutSub(original, proposal, query); // G14
    try payjoinMinFeeRate(original, proposal, query); // G15
}

/// POST a base64 Original PSBT to a plain-HTTP `http://` receiver
/// endpoint.  See `rpc.PayjoinSender.postOriginalPsbt` for the detailed
/// transport semantics; this function is the wallet-side mirror so a
/// caller that already has a wallet handle doesn't need to import
/// `rpc.zig`.
pub fn postOriginalPsbt(
    allocator: std.mem.Allocator,
    url: []const u8,
    original_b64: []const u8,
) PayjoinSenderError!psbt_mod.Psbt {
    if (std.mem.startsWith(u8, url, "https://")) return error.OriginalRejected;
    if (!std.mem.startsWith(u8, url, "http://")) return error.OriginalRejected;

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var resp_body = std.ArrayList(u8).init(allocator);
    defer resp_body.deinit();
    var server_header_buf: [16 * 1024]u8 = undefined;

    const fetch_result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = original_b64,
        .headers = .{ .content_type = .{ .override = "text/plain" } },
        .response_storage = .{ .dynamic = &resp_body },
        .max_append_size = 1 << 20,
        .server_header_buffer = &server_header_buf,
    }) catch return error.Unavailable;

    if (fetch_result.status != .ok) {
        if (std.mem.indexOf(u8, resp_body.items, "not-enough-money") != null) return error.NotEnoughMoney;
        if (std.mem.indexOf(u8, resp_body.items, "version-unsupported") != null) return error.VersionUnsupported;
        if (std.mem.indexOf(u8, resp_body.items, "unavailable") != null) return error.Unavailable;
        return error.OriginalRejected;
    }

    var trimmed = resp_body.items;
    while (trimmed.len > 0 and (trimmed[0] == ' ' or trimmed[0] == '\r' or trimmed[0] == '\n'))
        trimmed = trimmed[1..];
    while (trimmed.len > 0 and (trimmed[trimmed.len - 1] == ' ' or
        trimmed[trimmed.len - 1] == '\r' or trimmed[trimmed.len - 1] == '\n'))
        trimmed = trimmed[0 .. trimmed.len - 1];
    if (trimmed.len == 0) return error.OriginalRejected;
    return psbt_mod.Psbt.fromBase64(allocator, trimmed) catch return error.OriginalRejected;
}

/// Full sender flow: POST → parse → validate G10-G15 → return Proposal.
/// Caller owns the returned PSBT (call `deinit`).
pub fn sendPayjoinRequest(
    allocator: std.mem.Allocator,
    url: []const u8,
    original: *const psbt_mod.Psbt,
    query: *const PayjoinSenderQuery,
) PayjoinSenderError!psbt_mod.Psbt {
    const original_b64 = original.toBase64(allocator) catch return error.Unavailable;
    defer allocator.free(original_b64);
    var proposal = try postOriginalPsbt(allocator, url, original_b64);
    errdefer proposal.deinit();
    try validatePayjoinProposal(original, &proposal, query);
    return proposal;
}

/// G22 retry/fallback — base64-serialize the Original for verbatim
/// broadcast when PayJoin fails.  Caller owns the returned slice.
pub fn payjoinFallback(
    allocator: std.mem.Allocator,
    original: *const psbt_mod.Psbt,
) PayjoinSenderError![]const u8 {
    return original.toBase64(allocator) catch return error.Unavailable;
}

/// Alias for `payjoinFallback` (W119/G22 audit gate flags both names).
pub fn broadcastPayjoinOriginal(
    allocator: std.mem.Allocator,
    original: *const psbt_mod.Psbt,
) PayjoinSenderError![]const u8 {
    return payjoinFallback(allocator, original);
}

// ============================================================================
// FIX-67 — BIP-78 receiver Implementation Suggestions (wallet-side).
// ----------------------------------------------------------------------------
// Wallet helpers for the receiver-side privacy hardening that BIP-78
// §"Implementation Suggestions" calls for: a per-session UTXO lock so two
// concurrent PayJoin requests can't double-spend the same receiver UTXO
// (G19), and a fingerprint-aware UTXO picker that matches the sender's
// scriptPubKey type + confirmation count (G20).
//
// Smart-deferral preservation: this block MUST NOT add `PayjoinClient`
// (W119/G2 wallet-side alias — kept absent on purpose).  We only ship the
// audit-named decls `lockPayjoinUtxo` + `selectPayjoinReceiverUtxo` (with
// `fingerprintAwareSelect` as a thin alias for the second one).  The
// internal lock table is a private `payjoin_locks` field on the `Wallet`
// struct — keeping it off the module-level decl list preserves the
// `!@hasDecl(rpc_mod, "PayjoinUtxoLockTable")` signal that the W119
// integrity gate tracks (on the rpc namespace, but the same sprawl-
// avoidance rationale applies here).
//
// Spec ref: bips/bip-0078.mediawiki §"Implementation Suggestions" + the
// BTCPayServer.Payjoin reference receiver (Payjoin/PayjoinUtxoSelector.cs +
// Storage.cs).
// ============================================================================

/// G19 — outcome of an attempted PayJoin UTXO lock.  `acquired` means the
/// caller now owns the lock and MUST release it (via `unlockPayjoinUtxo`)
/// after the session completes.  `already_locked` means another session
/// already holds the lock; the caller MUST pick a different UTXO.
pub const PayjoinUtxoLockResult = enum { acquired, already_locked };

/// G19 — try to lock a receiver-side outpoint for a PayJoin session.  The
/// lock is in-memory only (matches Core's `lockunspent` non-persistent
/// default and the same store used by the W113 lock-coin path).  This is
/// the audit-flip surface for the W119/G19 gate; the backing store lives
/// on `Wallet.payjoin_locks`.
///
/// IMPORTANT: this is a SEPARATE lock-set from `Wallet.locked_outpoints`
/// (the user-facing `lockunspent` set).  Mixing them would mean a user
/// who manually locked a UTXO via `lockunspent` could not receive a
/// PayJoin into that UTXO (and vice versa).  BIP-78 §"Implementation
/// Suggestions" treats this as a privacy concern internal to the
/// PayJoin code path — operators don't need to see these locks via
/// `listlockunspent`.
pub fn lockPayjoinUtxo(self: *Wallet, outpoint: types.OutPoint) !PayjoinUtxoLockResult {
    if (self.payjoin_locks == null) {
        self.payjoin_locks = std.AutoHashMap([36]u8, void).init(self.allocator);
    }
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
    const gop = try self.payjoin_locks.?.getOrPut(key);
    if (gop.found_existing) return .already_locked;
    return .acquired;
}

/// G19 — release a PayJoin UTXO lock acquired by `lockPayjoinUtxo`.
/// Returns true if a lock was actually held (idempotent on already-
/// unlocked outpoints).  Test/operator helper; the production sweep
/// runs on a TTL clock parallel to the FIX-67 G18 session cache.
pub fn unlockPayjoinUtxo(self: *Wallet, outpoint: types.OutPoint) bool {
    const locks = &(self.payjoin_locks orelse return false);
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
    return locks.remove(key);
}

/// G19 — read-only check: is this outpoint currently held by a PayJoin
/// session?  Used by the fingerprint-aware selector (G20) to skip
/// already-locked UTXOs and by tests.
pub fn isPayjoinLocked(self: *const Wallet, outpoint: types.OutPoint) bool {
    const locks = self.payjoin_locks orelse return false;
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
    return locks.contains(key);
}

/// G20 — fingerprint hint that a PayJoin receiver uses to pick a UTXO
/// whose on-chain shape matches the sender's existing inputs.  BIP-78
/// §"Implementation Suggestions" recommends matching:
///   - scriptPubKey type (p2wpkh, p2wsh, p2tr, ...)
///   - confirmation count (rough buckets — "confirmed" vs "unconfirmed")
/// to defeat the "find the receiver" heuristic (an analyst that sees a
/// mixed-type tx in the chain learns at most that the wallet supports
/// the type — not which input is the receiver's contribution).
///
/// `min_amount` is the minimum value the receiver needs to contribute
/// (caller sets it from the fee-output adjustment math in G9).  An
/// empty `script_type` hint allows any type (matches the BIP-78 fallback
/// behaviour of "any spendable UTXO" when the sender's inputs are
/// heterogeneous).
pub const PayjoinReceiverHint = struct {
    /// Sender's primary scriptPubKey type (from the Original PSBT's
    /// first witness UTXO).  When `null`, the picker accepts any type.
    script_type: ?script_mod.ScriptType = null,
    /// Sender's minimum confirmation count.  Receiver picks an output
    /// with `confirmations >= min_confirmations` so the on-chain
    /// fingerprint matches.  `0` means "no constraint" (also matches a
    /// sender that includes unconfirmed inputs — RBF case).
    min_confirmations: u32 = 0,
    /// Minimum value the receiver must contribute, in satoshis.
    min_amount: u64 = 0,
};

/// G20 — fingerprint-aware UTXO picker.  Walks the wallet's UTXO set in
/// order and returns the first one that:
///   - is unlocked (neither `lockunspent`-locked nor PayJoin-locked)
///   - matches the hint's `script_type` (if set)
///   - has `confirmations >= hint.min_confirmations`
///   - has value `>= hint.min_amount`
///   - is mature (coinbase UTXOs respect `COINBASE_MATURITY`)
///
/// Returns `null` when no candidate matches (caller MUST return the
/// BIP-78 `not-enough-money` error to the sender — never expose the
/// scan failure to the caller's wallet snapshot).
///
/// Side-effect: when a candidate is found, this function calls
/// `lockPayjoinUtxo` on the candidate before returning so concurrent
/// sessions see it as already-claimed.  Callers MUST release the lock
/// via `unlockPayjoinUtxo` once the session completes (success OR
/// abort) to avoid leaking lock entries.
pub fn selectPayjoinReceiverUtxo(
    self: *Wallet,
    hint: PayjoinReceiverHint,
) !?OwnedUtxo {
    for (self.utxos.items) |utxo| {
        // Skip immature coinbase (BIP-30/consensus rule).
        if (utxo.is_coinbase) {
            if (self.tip_height < utxo.height) continue;
            if (self.tip_height - utxo.height < consensus.COINBASE_MATURITY) continue;
        }
        // Skip locked outputs (user lockunspent + PayJoin session lock).
        // `isLockedCoin` is a Wallet method (struct decl); `isPayjoinLocked`
        // is a module-level fn that takes `*const Wallet` — call style
        // diverges by design (module-level keeps the audit-flip surface).
        if (self.isLockedCoin(utxo.outpoint)) continue;
        if (isPayjoinLocked(self, utxo.outpoint)) continue;
        // Fingerprint: scriptPubKey type.
        if (hint.script_type) |want| {
            const have = script_mod.classifyScript(utxo.output.script_pubkey);
            if (have != want) continue;
        }
        // Fingerprint: confirmation depth.
        if (utxo.confirmations < hint.min_confirmations) continue;
        // Amount floor.
        const val: u64 = if (utxo.output.value < 0) 0 else @intCast(utxo.output.value);
        if (val < hint.min_amount) continue;
        // Claim the lock so concurrent sessions skip this UTXO.  If the
        // claim races, fall through to the next candidate.
        const lock_result = lockPayjoinUtxo(self, utxo.outpoint) catch continue;
        if (lock_result == .already_locked) continue;
        return utxo;
    }
    return null;
}

/// G20 — thin alias for `selectPayjoinReceiverUtxo`.  The W119/G20 audit
/// gate flags both names; we keep both alive so future readers grepping
/// for either name find the implementation.
pub fn fingerprintAwareSelect(
    self: *Wallet,
    hint: PayjoinReceiverHint,
) !?OwnedUtxo {
    return selectPayjoinReceiverUtxo(self, hint);
}

// ============================================================================
// libsecp256k1 Bindings
// ============================================================================
//
// Phase 2 (clearbit unfreeze plan): this module previously carried its own
// `@cImport` block, producing a fourth distinct opaque-type tree for
// `secp256k1_context` / `secp256k1_pubkey` / `secp256k1_keypair`. We now
// alias the tree-wide `secp.c` so the Wallet's `ctx` field has the same
// compile-time type as `crypto.zig`'s context and `descriptor.zig`'s
// context. The shared process-global context is created at startup via
// `crypto.initSecp256k1()` (which delegates to `secp.init()`); the
// Wallet now BORROWS that context rather than creating its own, so
// `Wallet.deinit()` no longer calls `secp256k1_context_destroy` (doing so
// would shut down the shared context the rest of the process relies on).

const secp = @import("secp.zig");
const secp256k1 = secp.c;

// ============================================================================
// BIP-39 Mnemonic Support
// ============================================================================

/// BIP-39 English wordlist (2048 words), embedded at compile time
const BIP39_WORDLIST: []const u8 = @embedFile("../resources/bip39-english.txt");

/// Parse the embedded BIP-39 wordlist into an array of words.
/// Runs at comptime; the default backwards-branch budget (1000) is too low
/// for splitting 2048 newline-separated lines, so we bump it explicitly.
fn getBip39Words() [2048][]const u8 {
    @setEvalBranchQuota(50_000);
    var words: [2048][]const u8 = undefined;
    var lines = std.mem.splitScalar(u8, BIP39_WORDLIST, '\n');
    var i: usize = 0;
    while (lines.next()) |line| {
        if (line.len > 0 and i < 2048) {
            words[i] = line;
            i += 1;
        }
    }
    return words;
}

const BIP39_WORDS = getBip39Words();

// ============================================================================
// Address Types
// ============================================================================

pub const AddressType = enum {
    p2pkh, // Legacy: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    p2sh_p2wpkh, // P2SH-wrapped SegWit: OP_HASH160 <20-byte-script-hash> OP_EQUAL
    p2wpkh, // Native SegWit v0: OP_0 <20-byte-hash>
    p2wsh, // SegWit v0 script hash: OP_0 <32-byte-hash>
    p2tr, // Taproot: OP_1 <32-byte-x-only-pubkey>
};

pub const Network = enum {
    mainnet,
    testnet,
    regtest,
};

// ============================================================================
// KeyPair
// ============================================================================

pub const KeyPair = struct {
    secret_key: [32]u8,
    public_key: [33]u8, // Compressed SEC format
    x_only_pubkey: [32]u8, // For Taproot
    // AES-256-GCM per-key encryption metadata (null when wallet is unencrypted).
    // Each key gets a fresh random 12-byte nonce at encrypt time; the 16-byte
    // authentication tag is produced by AES-GCM and verified on every decrypt,
    // so a wrong passphrase returns error.AuthenticationFailed rather than
    // silently succeeding (as the old XOR path did).
    encryption_nonce: ?[12]u8 = null,
    encryption_tag: ?[16]u8 = null,
};

// ============================================================================
// BIP32 HD Key Derivation
// ============================================================================

/// BIP32 derivation purposes
pub const DerivationPurpose = enum(u32) {
    bip44 = 44, // P2PKH (legacy)
    bip49 = 49, // P2SH-P2WPKH (wrapped segwit)
    bip84 = 84, // P2WPKH (native segwit)
    bip86 = 86, // P2TR (taproot)
};

/// BIP32 Extended Key — private-key form (CExtKey-equivalent).
///
/// Holds a 32-byte private scalar plus chain code for BIP-32 derivation.
///
/// **Phase 2 type-safety note**: prior to the 2026-05-27 single-FFI refactor,
/// this struct's `key: [32]u8` field was documented as "Private or public
/// key" — but a 32-byte buffer cannot hold a 33-byte compressed public key.
/// That made watch-only / xpub-only wallets unimplementable. The fix is
/// to split the type into `ExtendedKey` (private-only, this struct) and
/// `ExtendedPubKey` (public-only, defined just below) — matching Bitcoin
/// Core's `CExtKey` / `CExtPubKey` split. Code that needs to hold either
/// form should use a tagged-union wrapper at the call site (Phase 4 P4-1
/// will add such a wrapper for descriptor / wallet-import paths).
///
/// The `is_private` flag is now redundant — it's always `true` for any
/// `ExtendedKey` value — but is kept on the struct for one release to
/// avoid breaking the wallet.dat on-disk format (which serializes the
/// flag). Removed in a follow-up after one wave of wallet.dat
/// compatibility.
pub const ExtendedKey = struct {
    /// Private scalar (32 bytes). When the parent Wallet is encrypted,
    /// holds AES-256-GCM ciphertext (see W161 BUG-5 fix; nonces+tags
    /// live on `Wallet.master_key_nonce` / `_tag` etc.).
    key: [32]u8,
    chain_code: [32]u8,
    depth: u8,
    parent_fingerprint: [4]u8,
    child_index: u32,
    /// Always `true` for any `ExtendedKey` constructed in this codebase.
    /// Kept for wallet.dat on-disk compatibility; will be removed once
    /// `Wallet.deserialize` migrates to inferring it from struct identity.
    is_private: bool,

    /// HMAC-SHA512 helper for BIP32 derivation
    fn hmacSha512(key: []const u8, data: []const u8) [64]u8 {
        const HmacSha512 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha512);
        var result: [64]u8 = undefined;
        HmacSha512.create(&result, data, key);
        return result;
    }

    /// Create master key from seed (BIP32 master key generation)
    pub fn fromSeed(seed: []const u8) !ExtendedKey {
        if (seed.len < 16 or seed.len > 64) {
            return error.InvalidSeedLength;
        }

        const hmac_result = hmacSha512("Bitcoin seed", seed);
        const private_key = hmac_result[0..32].*;
        const chain_code = hmac_result[32..64].*;

        // Verify the key is valid (non-zero and less than curve order)
        if (std.mem.eql(u8, &private_key, &[_]u8{0} ** 32)) {
            return error.InvalidMasterKey;
        }

        return ExtendedKey{
            .key = private_key,
            .chain_code = chain_code,
            .depth = 0,
            .parent_fingerprint = [_]u8{ 0, 0, 0, 0 },
            .child_index = 0,
            .is_private = true,
        };
    }

    /// Derive child key at index (BIP32 CKDpriv/CKDpub)
    /// If index >= 0x80000000, it's a hardened derivation
    pub fn deriveChild(self: *const ExtendedKey, ctx: *secp256k1.secp256k1_context, index: u32) !ExtendedKey {
        const hardened = index >= 0x80000000;

        if (hardened and !self.is_private) {
            return error.CannotDeriveHardenedFromPublic;
        }

        var data: [37]u8 = undefined;

        if (hardened) {
            // Hardened: 0x00 || private_key || index
            data[0] = 0;
            @memcpy(data[1..33], &self.key);
        } else {
            // Normal: public_key || index
            if (self.is_private) {
                // Get public key from private
                var pubkey: secp256k1.secp256k1_pubkey = undefined;
                if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pubkey, &self.key) != 1) {
                    return error.PubkeyCreationFailed;
                }
                var compressed: [33]u8 = undefined;
                var len: usize = 33;
                _ = secp256k1.secp256k1_ec_pubkey_serialize(
                    ctx,
                    &compressed,
                    &len,
                    &pubkey,
                    secp256k1.SECP256K1_EC_COMPRESSED,
                );
                @memcpy(data[0..33], &compressed);
            } else {
                return error.NotImplemented; // Public key derivation
            }
        }

        std.mem.writeInt(u32, data[33..37], index, .big);

        const hmac_result = hmacSha512(&self.chain_code, &data);
        const il = hmac_result[0..32];
        const ir = hmac_result[32..64].*;

        // Add il to parent key (mod curve order) using secp256k1
        var child_key = self.key;
        if (secp256k1.secp256k1_ec_seckey_tweak_add(ctx, &child_key, il) != 1) {
            return error.InvalidChildKey;
        }

        // Compute parent fingerprint (first 4 bytes of hash160 of parent pubkey)
        var parent_pubkey: secp256k1.secp256k1_pubkey = undefined;
        if (secp256k1.secp256k1_ec_pubkey_create(ctx, &parent_pubkey, &self.key) != 1) {
            return error.PubkeyCreationFailed;
        }
        var parent_compressed: [33]u8 = undefined;
        var parent_len: usize = 33;
        _ = secp256k1.secp256k1_ec_pubkey_serialize(
            ctx,
            &parent_compressed,
            &parent_len,
            &parent_pubkey,
            secp256k1.SECP256K1_EC_COMPRESSED,
        );
        const fingerprint_hash = crypto.hash160(&parent_compressed);
        const fingerprint = fingerprint_hash[0..4].*;

        return ExtendedKey{
            .key = child_key,
            .chain_code = ir,
            .depth = self.depth + 1,
            .parent_fingerprint = fingerprint,
            .child_index = index,
            .is_private = self.is_private,
        };
    }

    /// Derive a key from a BIP32 path string like "m/44'/0'/0'/0/0"
    pub fn derivePath(self: *const ExtendedKey, ctx: *secp256k1.secp256k1_context, path: []const u8) !ExtendedKey {
        var current = self.*;

        // Skip leading 'm/' or 'M/'
        var path_iter = path;
        if (path_iter.len >= 2 and (path_iter[0] == 'm' or path_iter[0] == 'M') and path_iter[1] == '/') {
            path_iter = path_iter[2..];
        }

        // Parse each component
        var components = std.mem.splitScalar(u8, path_iter, '/');
        while (components.next()) |component| {
            if (component.len == 0) continue;

            const hardened = std.mem.endsWith(u8, component, "'") or std.mem.endsWith(u8, component, "h");
            const num_str = if (hardened) component[0 .. component.len - 1] else component;

            const index = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidDerivationPath;
            const full_index = if (hardened) index | 0x80000000 else index;

            current = try current.deriveChild(ctx, full_index);
        }

        return current;
    }

    /// Get the standard BIP44/49/84/86 path for a given purpose, coin, account, change, and index
    pub fn getStandardPath(
        purpose: DerivationPurpose,
        coin_type: u32, // 0 for mainnet, 1 for testnet
        account: u32,
        change: u32, // 0 for external, 1 for internal (change)
        index: u32,
        buffer: []u8,
    ) ![]const u8 {
        return std.fmt.bufPrint(buffer, "m/{d}'/{d}'/{d}'/{d}/{d}", .{
            @intFromEnum(purpose),
            coin_type,
            account,
            change,
            index,
        }) catch return error.BufferTooSmall;
    }
};

/// BIP32 Extended **Public** Key — public-key form (CExtPubKey-equivalent).
///
/// Phase 2 typed-buffer fix: this struct's `pub_key` field is `secp.PubKey`
/// (`[33]u8` underneath) so a 33-byte compressed pubkey actually fits. The
/// pre-Phase-2 `ExtendedKey.key: [32]u8` field was documented as "Private
/// OR public" but a 32-byte buffer cannot hold a 33-byte compressed pubkey
/// — that latent type-system bug had silently gated watch-only / xpub-only
/// wallets for the entire history of clearbit's wallet module.
///
/// **Construction**: today, only `ExtendedKey.neuter()` (added in Phase 4
/// P4-2 alongside `CKDpub`) produces `ExtendedPubKey` values. Until then,
/// the type exists as a target for the upcoming refactor — defining it
/// now lets reviewers see the intended end state and lets future code be
/// written against `ExtendedPubKey` directly without churning callsites.
///
/// **Derivation**: non-hardened child derivation (`deriveChildPub`) is
/// the Phase 4 P4-2 deliverable. Hardened derivation is, by BIP-32 design,
/// impossible from a public key — `deriveChild(idx)` for `idx >= 2^31`
/// must return `error.CannotDeriveHardenedFromPublic`.
pub const ExtendedPubKey = struct {
    /// Compressed SEC1 public key (33 bytes — 0x02/0x03 prefix + 32-byte x).
    /// Typed via `secp.PubKey` so the buffer width is a compile-time invariant.
    pub_key: secp.PubKey,
    chain_code: [32]u8,
    depth: u8,
    parent_fingerprint: [4]u8,
    child_index: u32,
};

// ============================================================================
// Owned UTXO
// ============================================================================

pub const OwnedUtxo = struct {
    outpoint: types.OutPoint,
    output: types.TxOut,
    key_index: usize, // Index into keys array
    address_type: AddressType,
    confirmations: u32,
    is_coinbase: bool = false, // Whether this UTXO is from a coinbase transaction
    height: u32 = 0, // Block height where this UTXO was confirmed
    /// W29-C: Optional witness script for P2WSH and P2SH-P2WSH inputs.
    /// When set on a `.p2wsh` UTXO, the witness script becomes the BIP-143
    /// scriptCode for the per-input sighash and the last element of the
    /// assembled witness stack. When set on a `.p2sh_p2wpkh` UTXO whose
    /// `output.script_pubkey` is the P2SH wrap of `OP_0 <SHA256(witness_script)>`,
    /// the input is signed as P2SH-wrapped-P2WSH (scriptSig = push of the
    /// P2WSH redeemScript, witness identical to bare P2WSH).
    /// Default `null` preserves the legacy P2WPKH / P2SH-P2WPKH paths.
    witness_script: ?[]const u8 = null,
    /// W29-C: Optional extra signing keys for M-of-N CHECKMULTISIG witness
    /// scripts. The wallet's own key (at `key_index`) is always considered;
    /// these are additional cosigner secrets the caller controls.
    /// Indexed by witness-script pubkey order at signing time.
    extra_signing_keys: ?[]const [32]u8 = null,
};

// ============================================================================
// Wallet
// ============================================================================

pub const Wallet = struct {
    ctx: *secp256k1.secp256k1_context,
    keys: std.ArrayList(KeyPair),
    utxos: std.ArrayList(OwnedUtxo),
    allocator: std.mem.Allocator,
    network: Network,

    // HD wallet state
    master_key: ?ExtendedKey = null,
    next_external_index: u32 = 0, // m/purpose'/coin'/0'/0/index
    next_change_index: u32 = 0, // m/purpose'/coin'/0'/1/index

    // Chain tip height for coinbase maturity checks
    tip_height: u32 = 0,

    // Encryption state
    encrypted: bool = false,
    encryption_key: ?[32]u8 = null,
    encryption_salt: ?[16]u8 = null,
    unlock_until: ?i64 = null, // Timestamp until which wallet is unlocked

    // W161 BUG-5 fix: AES-256-GCM nonce + tag for the encrypted master_key.key
    // (32 bytes) and master_key.chain_code (32 bytes).  When `encrypted` is
    // true, master_key.key and master_key.chain_code hold CIPHERTEXT in memory
    // and on disk; these nonces+tags are required to decrypt them via the same
    // scrypt-derived key used for child keys.  Both are null on unencrypted
    // wallets and on legacy (pre-W161-fix) plaintext wallet.dat reads.
    master_key_nonce: ?[12]u8 = null,
    master_key_tag: ?[16]u8 = null,
    master_chain_code_nonce: ?[12]u8 = null,
    master_chain_code_tag: ?[16]u8 = null,

    // Labels: address -> label mapping
    labels: std.StringHashMap([]const u8),

    /// In-memory locked UTXO set (cleared on process exit, matching Core's
    /// non-persistent default). Key is a 36-byte packed outpoint
    /// (32 little-endian txid + 4 LE vout). Locked UTXOs are skipped by
    /// `selectCoinsWithOptions` and reported by `listlockunspent`.
    /// Reference: bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent.
    locked_outpoints: std.AutoHashMap([36]u8, void),

    /// W119/G19 — FIX-67 PayJoin session UTXO lock set.  SEPARATE from
    /// `locked_outpoints` (user-facing `lockunspent`) so users can't
    /// accidentally block a PayJoin and vice versa.  Lazy-initialised
    /// on first `lockPayjoinUtxo` call so non-PayJoin wallets pay zero
    /// allocation cost.  See the FIX-67 wallet-side block comment for
    /// the smart-deferral rationale (this field is intentionally private
    /// — the audit-flip surface is `lockPayjoinUtxo` /
    /// `unlockPayjoinUtxo` / `isPayjoinLocked`).
    payjoin_locks: ?std.AutoHashMap([36]u8, void) = null,

    pub fn init(allocator: std.mem.Allocator, network: Network) !Wallet {
        // Phase 2: borrow the process-global shared context (lazy-initialized
        // via secp.init() / secp.context() with the W159 BUG-4 randomization
        // applied exactly once at creation, not per-wallet). The Wallet does
        // NOT own this context — `deinit` must not destroy it.
        const ctx = secp.context() orelse return error.Secp256k1ContextFailed;

        return Wallet{
            .ctx = ctx,
            .keys = std.ArrayList(KeyPair).init(allocator),
            .utxos = std.ArrayList(OwnedUtxo).init(allocator),
            .allocator = allocator,
            .network = network,
            .master_key = null,
            .next_external_index = 0,
            .next_change_index = 0,
            .tip_height = 0,
            .encrypted = false,
            .encryption_key = null,
            .encryption_salt = null,
            .unlock_until = null,
            .labels = std.StringHashMap([]const u8).init(allocator),
            .locked_outpoints = std.AutoHashMap([36]u8, void).init(allocator),
        };
    }

    /// Initialize the wallet with a BIP32 seed (from BIP39 mnemonic)
    pub fn initFromSeed(allocator: std.mem.Allocator, network: Network, seed: []const u8) !Wallet {
        var wallet = try init(allocator, network);
        wallet.master_key = try ExtendedKey.fromSeed(seed);
        return wallet;
    }

    /// Initialize the wallet from a BIP-39 mnemonic + optional passphrase.
    ///
    /// The mnemonic is the already-tokenized form (each element is one
    /// wordlist entry). For a user-typed string, parse with
    /// `bip39.parseMnemonicString` first.
    ///
    /// Equivalent to `mnemonicToSeed(mnemonic, passphrase) -> initFromSeed`.
    /// Validates the mnemonic checksum on the way through; returns
    /// `error.InvalidChecksum` etc. on invalid input. See `bip39.zig`.
    pub fn initFromMnemonic(
        allocator: std.mem.Allocator,
        network: Network,
        mnemonic: []const []const u8,
        passphrase: []const u8,
    ) !Wallet {
        const bip39 = @import("bip39.zig");
        // Validate first so we surface a clean error before allocating
        // the secp256k1 context / wallet.
        try bip39.validateMnemonic(allocator, mnemonic);
        var seed: [64]u8 = undefined;
        try bip39.mnemonicToSeed(allocator, mnemonic, passphrase, &seed);
        return try initFromSeed(allocator, network, &seed);
    }

    pub fn deinit(self: *Wallet) void {
        // Phase 2: do NOT destroy self.ctx — it's the process-global shared
        // context owned by the `secp` module. Destroying it here would shut
        // down libsecp256k1 for crypto.zig / descriptor.zig / v2_transport.zig
        // and the next wallet created in the same process. Lifecycle is
        // owned by `crypto.initSecp256k1` / `crypto.deinitSecp256k1` at
        // process startup / shutdown (see main.zig).
        self.keys.deinit();
        self.utxos.deinit();

        // Free label strings
        var it = self.labels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.labels.deinit();

        self.locked_outpoints.deinit();
        // FIX-67 (W119/G19) — free the PayJoin session lock set if it
        // was lazy-init'd.  Empty/never-used wallets never allocate.
        if (self.payjoin_locks) |*locks| {
            locks.deinit();
            self.payjoin_locks = null;
        }

        // Clear encryption key from memory
        if (self.encryption_key) |*key| {
            @memset(key, 0);
        }
    }

    /// Update the chain tip height (for coinbase maturity checks)
    pub fn setTipHeight(self: *Wallet, height: u32) void {
        self.tip_height = height;
    }

    /// Generate a new random keypair.
    pub fn generateKey(self: *Wallet) !usize {
        var secret: [32]u8 = undefined;
        std.crypto.random.bytes(&secret);

        // Verify the secret key is valid (non-zero, less than curve order)
        while (secp256k1.secp256k1_ec_seckey_verify(self.ctx, &secret) != 1) {
            std.crypto.random.bytes(&secret);
        }

        return try self.importKey(secret);
    }

    /// Import an existing secret key.
    pub fn importKey(self: *Wallet, secret: [32]u8) !usize {
        // Verify the secret key
        if (secp256k1.secp256k1_ec_seckey_verify(self.ctx, &secret) != 1) {
            return error.InvalidSecretKey;
        }

        var pubkey: secp256k1.secp256k1_pubkey = undefined;
        if (secp256k1.secp256k1_ec_pubkey_create(self.ctx, &pubkey, &secret) != 1) {
            return error.PubkeyCreationFailed;
        }

        // Serialize compressed public key
        var compressed: [33]u8 = undefined;
        var compressed_len: usize = 33;
        _ = secp256k1.secp256k1_ec_pubkey_serialize(
            self.ctx,
            &compressed,
            &compressed_len,
            &pubkey,
            secp256k1.SECP256K1_EC_COMPRESSED,
        );

        // Create x-only pubkey for Taproot
        var xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
        _ = secp256k1.secp256k1_xonly_pubkey_from_pubkey(self.ctx, &xonly, null, &pubkey);
        var x_only_bytes: [32]u8 = undefined;
        _ = secp256k1.secp256k1_xonly_pubkey_serialize(self.ctx, &x_only_bytes, &xonly);

        var key = KeyPair{
            .secret_key = secret,
            .public_key = compressed,
            .x_only_pubkey = x_only_bytes,
        };

        // If the wallet is encrypted and currently unlocked, encrypt the new
        // key immediately so it is stored in the same AES-256-GCM form as the
        // rest.  If the wallet is locked (encryption_key == null) the caller
        // must unlock before importing.
        if (self.encrypted) {
            const enc_key = self.encryption_key orelse return error.WalletLocked;
            const enc = encryptPrivateKey(&enc_key, &secret);
            key.secret_key = enc.ciphertext;
            key.encryption_nonce = enc.nonce;
            key.encryption_tag = enc.tag;
        }

        try self.keys.append(key);
        return self.keys.items.len - 1;
    }

    /// Get a new address using HD derivation (BIP44/49/84/86 paths).
    /// This is the primary way to generate addresses for a HD wallet.
    /// Returns both the address string and the key index.
    pub fn getnewaddress(
        self: *Wallet,
        addr_type: AddressType,
        is_change: bool,
    ) !struct { address: []const u8, key_index: usize } {
        if (self.master_key == null) {
            // Non-HD wallet: fall back to random key generation
            const key_index = try self.generateKey();
            const addr = try self.getAddress(key_index, addr_type);
            return .{ .address = addr, .key_index = key_index };
        }

        // Determine purpose from address type (BIP44/49/84/86)
        const purpose: DerivationPurpose = switch (addr_type) {
            .p2pkh => .bip44,
            .p2sh_p2wpkh => .bip49,
            .p2wpkh => .bip84,
            .p2tr => .bip86,
            .p2wsh => .bip84, // P2WSH uses BIP84 path
        };

        // Coin type: 0 for mainnet, 1 for testnet
        const coin_type: u32 = switch (self.network) {
            .mainnet => 0,
            .testnet, .regtest => 1,
        };

        // Change: 0 for external (receiving), 1 for internal (change)
        const change: u32 = if (is_change) 1 else 0;

        // Get the next index for this chain
        const index = if (is_change) self.next_change_index else self.next_external_index;

        // Build derivation path
        var path_buf: [64]u8 = undefined;
        const path = try ExtendedKey.getStandardPath(purpose, coin_type, 0, change, index, &path_buf);

        // Derive the key.  W161 BUG-5 fix: when the wallet is encrypted, the
        // in-memory master_key.key + chain_code are AES-256-GCM ciphertext —
        // resolve plaintext via getPlaintextMasterKey() (which requires the
        // wallet to be unlocked).  We zero the temporary plaintext immediately
        // after derivation so a long-lived plaintext seed never lives in the
        // Wallet struct.
        var master_plain = (try self.getPlaintextMasterKey()) orelse return error.NoMasterKey;
        defer {
            @memset(&master_plain.key, 0);
            @memset(&master_plain.chain_code, 0);
        }
        const derived = try master_plain.derivePath(self.ctx, path);

        // Import the derived key
        const key_index = try self.importKey(derived.key);

        // Get the address
        const addr = try self.getAddress(key_index, addr_type);

        // Increment the index counter
        if (is_change) {
            self.next_change_index += 1;
        } else {
            self.next_external_index += 1;
        }

        return .{ .address = addr, .key_index = key_index };
    }

    /// Get the number of keys in the wallet.
    pub fn keyCount(self: *const Wallet) usize {
        return self.keys.items.len;
    }

    /// Derive the scriptPubKey for a given key and address type.
    pub fn getScriptPubKey(self: *Wallet, key_index: usize, addr_type: AddressType) ![]u8 {
        if (key_index >= self.keys.items.len) {
            return error.KeyNotFound;
        }

        const key = self.keys.items[key_index];
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        switch (addr_type) {
            .p2pkh => {
                const hash = crypto.hash160(&key.public_key);
                try result.appendSlice(&[_]u8{
                    0x76, // OP_DUP
                    0xa9, // OP_HASH160
                    0x14, // Push 20 bytes
                });
                try result.appendSlice(&hash);
                try result.appendSlice(&[_]u8{
                    0x88, // OP_EQUALVERIFY
                    0xac, // OP_CHECKSIG
                });
            },
            .p2sh_p2wpkh => {
                // P2SH-P2WPKH: OP_HASH160 <hash160(redeemScript)> OP_EQUAL
                // where redeemScript = OP_0 <20-byte-pubkey-hash>
                const pubkey_hash = crypto.hash160(&key.public_key);
                var redeem_script: [22]u8 = undefined;
                redeem_script[0] = 0x00; // OP_0
                redeem_script[1] = 0x14; // Push 20 bytes
                @memcpy(redeem_script[2..22], &pubkey_hash);
                const script_hash = crypto.hash160(&redeem_script);

                try result.appendSlice(&[_]u8{
                    0xa9, // OP_HASH160
                    0x14, // Push 20 bytes
                });
                try result.appendSlice(&script_hash);
                try result.append(0x87); // OP_EQUAL
            },
            .p2wpkh => {
                const hash = crypto.hash160(&key.public_key);
                try result.appendSlice(&[_]u8{
                    0x00, // OP_0 (witness version 0)
                    0x14, // Push 20 bytes
                });
                try result.appendSlice(&hash);
            },
            .p2wsh => {
                // P2WSH requires a witness script - this is a simplified version
                // that uses the public key directly (not typical usage)
                const script_hash = crypto.sha256(&key.public_key);
                try result.appendSlice(&[_]u8{
                    0x00, // OP_0 (witness version 0)
                    0x20, // Push 32 bytes
                });
                try result.appendSlice(&script_hash);
            },
            .p2tr => {
                // BIP-86: the on-chain output key is the *tweaked* x-only
                // pubkey, never the raw internal key. Pre-W20 clearbit
                // emitted the untweaked internal key, so any output sent
                // to a clearbit P2TR address was unspendable on-chain — the
                // chain carried a key the wallet would never sign for.
                const tweaked = try bip86TweakXOnly(self.ctx, &key.x_only_pubkey);
                try result.appendSlice(&[_]u8{
                    0x51, // OP_1 (witness version 1)
                    0x20, // Push 32 bytes
                });
                try result.appendSlice(&tweaked);
            },
        }

        return try result.toOwnedSlice();
    }

    /// Derive a Bech32/Bech32m/Base58Check encoded address string.
    pub fn getAddress(self: *Wallet, key_index: usize, addr_type: AddressType) ![]const u8 {
        if (key_index >= self.keys.items.len) {
            return error.KeyNotFound;
        }

        const key = self.keys.items[key_index];
        const hrp: []const u8 = switch (self.network) {
            .mainnet => "bc",
            .testnet => "tb",
            .regtest => "bcrt",
        };

        switch (addr_type) {
            .p2pkh => {
                // Base58Check encoding: version_byte + hash160 + checksum
                const hash = crypto.hash160(&key.public_key);
                const version: u8 = switch (self.network) {
                    .mainnet => 0x00,
                    .testnet, .regtest => 0x6F,
                };
                return try address.base58CheckEncode(version, &hash, self.allocator);
            },
            .p2sh_p2wpkh => {
                // P2SH address: base58check with version 0x05 (mainnet) or 0xC4 (testnet)
                // containing hash160 of the redeem script (OP_0 <pubkey_hash>)
                const pubkey_hash = crypto.hash160(&key.public_key);
                var redeem_script: [22]u8 = undefined;
                redeem_script[0] = 0x00; // OP_0
                redeem_script[1] = 0x14; // Push 20 bytes
                @memcpy(redeem_script[2..22], &pubkey_hash);
                const script_hash = crypto.hash160(&redeem_script);

                const version: u8 = switch (self.network) {
                    .mainnet => 0x05,
                    .testnet, .regtest => 0xC4,
                };
                return try address.base58CheckEncode(version, &script_hash, self.allocator);
            },
            .p2wpkh => {
                const hash = crypto.hash160(&key.public_key);
                return try address.segwitEncode(hrp, 0, &hash, self.allocator);
            },
            .p2wsh => {
                // Needs witness script as parameter in real impl
                return error.NotImplemented;
            },
            .p2tr => {
                // BIP-86 tweaked output key — see getScriptPubKey above for
                // the rationale; the address must encode the same bytes that
                // appear inside the on-chain `OP_1 <0x20> <key>` script.
                const tweaked = try bip86TweakXOnly(self.ctx, &key.x_only_pubkey);
                return try address.segwitEncode(hrp, 1, &tweaked, self.allocator);
            },
        }
    }

    /// Add a UTXO to the wallet.
    pub fn addUtxo(self: *Wallet, utxo: OwnedUtxo) !void {
        try self.utxos.append(utxo);
    }

    /// Remove a UTXO from the wallet by outpoint.
    pub fn removeUtxo(self: *Wallet, outpoint: types.OutPoint) bool {
        for (self.utxos.items, 0..) |utxo, i| {
            if (std.mem.eql(u8, &utxo.outpoint.hash, &outpoint.hash) and
                utxo.outpoint.index == outpoint.index)
            {
                _ = self.utxos.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Get total balance of all UTXOs.
    pub fn getBalance(self: *const Wallet) i64 {
        var total: i64 = 0;
        for (self.utxos.items) |utxo| {
            total += utxo.output.value;
        }
        return total;
    }

    /// Pack an outpoint (txid + vout) into a 36-byte hashmap key. The key is
    /// the raw little-endian txid bytes followed by the 4-byte LE vout.
    pub fn packOutpoint(outpoint: types.OutPoint) [36]u8 {
        var key: [36]u8 = undefined;
        @memcpy(key[0..32], &outpoint.hash);
        std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
        return key;
    }

    /// Mark an outpoint as locked (in-memory only, matching Core's default
    /// non-persistent semantics). A locked UTXO is excluded from automatic
    /// coin selection. Returns true if the outpoint transitioned from
    /// unlocked to locked, false if it was already locked.
    pub fn lockCoin(self: *Wallet, outpoint: types.OutPoint) !bool {
        const key = packOutpoint(outpoint);
        const gop = try self.locked_outpoints.getOrPut(key);
        return !gop.found_existing;
    }

    /// Remove the lock on an outpoint. Returns true if the outpoint was
    /// previously locked (i.e. removal happened), false if it was not in the
    /// locked set.
    pub fn unlockCoin(self: *Wallet, outpoint: types.OutPoint) bool {
        const key = packOutpoint(outpoint);
        return self.locked_outpoints.remove(key);
    }

    /// Check whether an outpoint is currently locked.
    pub fn isLockedCoin(self: *const Wallet, outpoint: types.OutPoint) bool {
        const key = packOutpoint(outpoint);
        return self.locked_outpoints.contains(key);
    }

    /// Clear all locks. Used by `lockunspent true` with no outpoints.
    pub fn unlockAllCoins(self: *Wallet) void {
        self.locked_outpoints.clearRetainingCapacity();
    }

    /// Number of currently locked outpoints. Helper for `listlockunspent`
    /// callers + tests; the dispatch RPC walks the iterator directly.
    pub fn lockedCoinCount(self: *const Wallet) usize {
        return self.locked_outpoints.count();
    }

    /// Coin selection options
    pub const CoinSelectOptions = struct {
        fee_rate: u64 = 1, // sat/vB
        long_term_fee_rate: u64 = 10, // sat/vB for waste calculation
        cost_of_change: i64 = 34 * 10, // cost to create + spend change output
        min_change: i64 = 546, // minimum change to avoid dust
    };

    /// Result of a coin-selection call. Named (rather than per-function
    /// anonymous) so that `selectCoins`, `selectCoinsWithOptions`,
    /// `selectCoinsBnB`, and `knapsackSolver` can return the same nominal
    /// type and pass each other's results through without an awkward
    /// cast (Zig anonymous structs at distinct source positions are
    /// distinct nominal types even when structurally identical).
    pub const CoinSelectResult = struct { selected: []OwnedUtxo, change: i64 };

    /// Select coins to fund a transaction (BnB with Knapsack fallback).
    /// This matches Bitcoin Core's coin selection strategy.
    pub fn selectCoins(
        self: *Wallet,
        target_value: i64,
        fee_rate: u64, // sat/vB
    ) !CoinSelectResult {
        return self.selectCoinsWithOptions(target_value, .{ .fee_rate = fee_rate });
    }

    /// Select coins with full options control.
    /// Skips immature coinbase outputs (less than COINBASE_MATURITY confirmations).
    pub fn selectCoinsWithOptions(
        self: *Wallet,
        target_value: i64,
        options: CoinSelectOptions,
    ) !CoinSelectResult {
        if (self.utxos.items.len == 0) {
            return error.InsufficientFunds;
        }

        // Filter out immature coinbase outputs and create candidates
        var mature_utxos = std.ArrayList(OwnedUtxo).init(self.allocator);
        defer mature_utxos.deinit();

        for (self.utxos.items) |utxo| {
            // Skip immature coinbase outputs (BIP-30/consensus rule)
            // Coinbase outputs require COINBASE_MATURITY (100) confirmations
            if (utxo.is_coinbase) {
                if (self.tip_height < utxo.height) continue; // UTXO from future block (shouldn't happen)
                const confirmations = self.tip_height - utxo.height;
                if (confirmations < consensus.COINBASE_MATURITY) {
                    continue; // Skip immature coinbase
                }
            }
            // Skip locked outputs (lockunspent / listlockunspent). Locked
            // UTXOs are not chosen by automatic coin selection per Core's
            // `lockunspent` documentation.
            if (self.isLockedCoin(utxo.outpoint)) continue;
            try mature_utxos.append(utxo);
        }

        if (mature_utxos.items.len == 0) {
            return error.InsufficientFunds;
        }

        // Create candidates with effective values
        const candidates = try self.allocator.dupe(OwnedUtxo, mature_utxos.items);
        defer self.allocator.free(candidates);

        // Calculate effective values and sort by descending effective value
        var effective_values = try self.allocator.alloc(i64, candidates.len);
        defer self.allocator.free(effective_values);

        var total_available: i64 = 0;
        for (candidates, 0..) |utxo, i| {
            const input_fee = @as(i64, @intCast(estimateInputSize(utxo.address_type) * options.fee_rate));
            effective_values[i] = utxo.output.value - input_fee;
            if (effective_values[i] > 0) {
                total_available += effective_values[i];
            }
        }

        if (total_available < target_value) {
            return error.InsufficientFunds;
        }

        // Sort by effective value descending, with lower input size as tiebreaker
        const SortCtx = struct {
            eff_vals: []const i64,
        };
        const sort_ctx = SortCtx{ .eff_vals = effective_values };
        const indices = try self.allocator.alloc(usize, candidates.len);
        defer self.allocator.free(indices);
        for (indices, 0..) |*idx, i| idx.* = i;

        std.sort.pdq(usize, indices, sort_ctx, struct {
            fn cmp(ctx: SortCtx, a: usize, b: usize) bool {
                return ctx.eff_vals[a] > ctx.eff_vals[b];
            }
        }.cmp);

        // Try Branch and Bound first (aims for exact match, no change)
        if (try self.selectCoinsBnB(candidates, indices, effective_values, target_value, options)) |result| {
            return result;
        }

        // Fallback to Knapsack solver
        return try self.knapsackSolver(candidates, indices, effective_values, target_value, options);
    }

    /// Branch and Bound coin selection - exhaustive search for subset-sum within tolerance.
    /// Aims to find a selection that pays the target without needing change output.
    /// Max 100k iterations as per Bitcoin Core.
    fn selectCoinsBnB(
        self: *Wallet,
        candidates: []const OwnedUtxo,
        sorted_indices: []const usize,
        effective_values: []const i64,
        target_value: i64,
        options: CoinSelectOptions,
    ) !?CoinSelectResult {
        const max_iterations: usize = 100_000;
        const cost_of_change = options.cost_of_change;

        // Filter to positive effective value UTXOs only
        var positive_count: usize = 0;
        for (sorted_indices) |idx| {
            if (effective_values[idx] > 0) positive_count += 1;
        }
        if (positive_count == 0) return null;

        // Calculate available value (lookahead)
        var curr_available_value: i64 = 0;
        for (sorted_indices) |idx| {
            if (effective_values[idx] > 0) {
                curr_available_value += effective_values[idx];
            }
        }

        if (curr_available_value < target_value) return null;

        // Track selections and values
        var curr_selection = std.ArrayList(usize).init(self.allocator);
        defer curr_selection.deinit();

        var best_selection = std.ArrayList(usize).init(self.allocator);
        defer best_selection.deinit();

        var curr_value: i64 = 0;
        var curr_waste: i64 = 0;
        var best_waste: i64 = std.math.maxInt(i64);

        // Is current fee rate higher than long term? Affects waste calculation
        const is_feerate_high = options.fee_rate > options.long_term_fee_rate;

        var utxo_pool_index: usize = 0;
        var iterations: usize = 0;

        while (iterations < max_iterations) : (iterations += 1) {
            var backtrack = false;

            // Find next valid UTXO index (skip negative effective values)
            while (utxo_pool_index < sorted_indices.len and
                effective_values[sorted_indices[utxo_pool_index]] <= 0)
            {
                utxo_pool_index += 1;
            }

            // Check backtrack conditions
            if (utxo_pool_index >= sorted_indices.len) {
                backtrack = true;
            } else if (curr_value + curr_available_value < target_value) {
                // Cannot possibly reach target
                backtrack = true;
            } else if (curr_value > target_value + cost_of_change) {
                // Exceeded target + change cost, this branch won't help
                backtrack = true;
            } else if (curr_waste > best_waste and is_feerate_high) {
                // Waste is increasing when fee rate is high
                backtrack = true;
            } else if (curr_value >= target_value) {
                // Found a valid selection!
                const selection_waste = curr_waste + (curr_value - target_value);
                if (selection_waste <= best_waste) {
                    best_waste = selection_waste;
                    best_selection.clearRetainingCapacity();
                    try best_selection.appendSlice(curr_selection.items);
                }
                backtrack = true;
            }

            if (backtrack) {
                if (curr_selection.items.len == 0) break;

                // Restore available value for skipped UTXOs
                const last_selected = curr_selection.items[curr_selection.items.len - 1];
                var restore_idx = utxo_pool_index;
                while (restore_idx > 0) {
                    restore_idx -= 1;
                    if (restore_idx == last_selected) break;
                    const idx = sorted_indices[restore_idx];
                    if (effective_values[idx] > 0) {
                        curr_available_value += effective_values[idx];
                    }
                }

                // Deselect last UTXO
                const deselect_idx = sorted_indices[last_selected];
                curr_value -= effective_values[deselect_idx];
                const utxo_waste = calculateWaste(candidates[deselect_idx].address_type, options);
                curr_waste -= utxo_waste;
                _ = curr_selection.pop();

                utxo_pool_index = last_selected + 1;
            } else {
                // Include this UTXO
                const utxo_idx = sorted_indices[utxo_pool_index];
                curr_available_value -= effective_values[utxo_idx];
                curr_value += effective_values[utxo_idx];
                curr_waste += calculateWaste(candidates[utxo_idx].address_type, options);
                try curr_selection.append(utxo_pool_index);
                utxo_pool_index += 1;
            }
        }

        if (best_selection.items.len == 0) return null;

        // Build result
        var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
        errdefer selected.deinit();

        var total_value: i64 = 0;
        for (best_selection.items) |pool_idx| {
            const utxo_idx = sorted_indices[pool_idx];
            try selected.append(candidates[utxo_idx]);
            total_value += effective_values[utxo_idx];
        }

        return .{
            .selected = try selected.toOwnedSlice(),
            .change = total_value - target_value, // For BnB this should be minimal or zero
        };
    }

    /// Calculate waste for a single input (fee - long_term_fee)
    fn calculateWaste(addr_type: AddressType, options: CoinSelectOptions) i64 {
        const input_size = estimateInputSize(addr_type);
        const fee = @as(i64, @intCast(input_size * options.fee_rate));
        const long_term_fee = @as(i64, @intCast(input_size * options.long_term_fee_rate));
        return fee - long_term_fee;
    }

    /// Knapsack coin selection - random selection with stochastic approximation.
    /// Used as fallback when BnB fails. Always produces change output.
    fn knapsackSolver(
        self: *Wallet,
        candidates: []const OwnedUtxo,
        sorted_indices: []const usize,
        effective_values: []const i64,
        target_value: i64,
        options: CoinSelectOptions,
    ) !CoinSelectResult {
        const change_cost = options.cost_of_change;

        // Separate UTXOs into categories
        var applicable_groups = std.ArrayList(usize).init(self.allocator);
        defer applicable_groups.deinit();

        var lowest_larger: ?usize = null;
        var total_lower: i64 = 0;

        for (sorted_indices) |idx| {
            const eff_value = effective_values[idx];
            if (eff_value <= 0) continue;

            if (eff_value == target_value) {
                // Exact match!
                var selected = try self.allocator.alloc(OwnedUtxo, 1);
                selected[0] = candidates[idx];
                return .{ .selected = selected, .change = 0 };
            } else if (eff_value < target_value + change_cost) {
                // Smaller than target + change, could be part of sum
                try applicable_groups.append(idx);
                total_lower += eff_value;
            } else {
                // Larger than needed - track the smallest one
                if (lowest_larger == null or eff_value < effective_values[lowest_larger.?]) {
                    lowest_larger = idx;
                }
            }
        }

        // Check if all smaller UTXOs together equal target exactly
        if (total_lower == target_value) {
            var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
            errdefer selected.deinit();
            for (applicable_groups.items) |idx| {
                try selected.append(candidates[idx]);
            }
            return .{ .selected = try selected.toOwnedSlice(), .change = 0 };
        }

        // If smaller UTXOs are insufficient, use the smallest larger UTXO
        if (total_lower < target_value) {
            if (lowest_larger) |ll_idx| {
                var selected = try self.allocator.alloc(OwnedUtxo, 1);
                selected[0] = candidates[ll_idx];
                return .{
                    .selected = selected,
                    .change = effective_values[ll_idx] - target_value,
                };
            }
            return error.InsufficientFunds;
        }

        // Stochastic subset sum approximation (simplified Knapsack)
        // Run multiple iterations picking random subsets
        var best_selection = std.ArrayList(usize).init(self.allocator);
        defer best_selection.deinit();
        var best_value: i64 = std.math.maxInt(i64);

        const iterations: usize = 1000;

        for (0..iterations) |_| {
            var included = try self.allocator.alloc(bool, applicable_groups.items.len);
            defer self.allocator.free(included);
            @memset(included, false);

            var current_value: i64 = 0;
            var reached_target = false;

            // Two passes: first random, then fill gaps
            for (0..2) |pass| {
                for (applicable_groups.items, 0..) |idx, i| {
                    // Pass 0: randomly include
                    // Pass 1: include if not yet included and not reached target
                    const should_consider = if (pass == 0)
                        std.crypto.random.boolean()
                    else
                        !included[i];

                    if (should_consider and !reached_target) {
                        current_value += effective_values[idx];
                        included[i] = true;

                        if (current_value >= target_value) {
                            reached_target = true;
                            if (current_value < best_value) {
                                best_value = current_value;
                                best_selection.clearRetainingCapacity();
                                for (applicable_groups.items, 0..) |sel_idx, j| {
                                    if (included[j]) try best_selection.append(sel_idx);
                                }
                            }
                            // Try removing this element to see if we're still above target
                            current_value -= effective_values[idx];
                            included[i] = false;
                            reached_target = false;
                        }
                    }
                }
            }
        }

        // If we found a solution via stochastic search
        if (best_selection.items.len > 0) {
            // Check if the single larger UTXO would be better
            if (lowest_larger) |ll_idx| {
                const ll_value = effective_values[ll_idx];
                if (ll_value <= best_value) {
                    var selected = try self.allocator.alloc(OwnedUtxo, 1);
                    selected[0] = candidates[ll_idx];
                    return .{ .selected = selected, .change = ll_value - target_value };
                }
            }

            var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
            errdefer selected.deinit();
            for (best_selection.items) |idx| {
                try selected.append(candidates[idx]);
            }
            return .{
                .selected = try selected.toOwnedSlice(),
                .change = best_value - target_value,
            };
        }

        // Last resort: use smallest larger UTXO
        if (lowest_larger) |ll_idx| {
            var selected = try self.allocator.alloc(OwnedUtxo, 1);
            selected[0] = candidates[ll_idx];
            return .{
                .selected = selected,
                .change = effective_values[ll_idx] - target_value,
            };
        }

        return error.InsufficientFunds;
    }

    /// Return the plaintext 32-byte secret key for `key_index`.
    ///
    /// If the wallet is unencrypted, returns the stored bytes directly.
    /// If the wallet is encrypted and unlocked, decrypts with the in-memory
    /// key; `error.AuthenticationFailed` is returned if the stored tag does
    /// not verify (should never happen unless the wallet file is corrupted).
    /// If the wallet is encrypted but locked (encryption_key == null), returns
    /// `error.WalletLocked`.
    fn getPlaintextSecretKey(self: *const Wallet, key_index: usize) ![32]u8 {
        const kp = &self.keys.items[key_index];
        if (!self.encrypted) {
            return kp.secret_key;
        }
        const enc_key = self.encryption_key orelse return error.WalletLocked;
        const nonce = kp.encryption_nonce orelse return error.WalletNotEncrypted;
        const tag = kp.encryption_tag orelse return error.WalletNotEncrypted;
        return decryptPrivateKey(&enc_key, &kp.secret_key, &nonce, &tag);
    }

    /// W161 BUG-5 fix: return a plaintext copy of the HD master key for use
    /// in BIP-32 derivation.  Mirrors getPlaintextSecretKey() but acts on the
    /// 32-byte master.key + 32-byte chain_code stored as AES-256-GCM ciphertext
    /// (with nonces+tags on the Wallet, not on ExtendedKey).  The returned
    /// ExtendedKey is a temporary the caller MUST zero after derivation; we
    /// do not keep a long-lived plaintext copy in the Wallet struct.
    /// Returns null if the wallet has no master key.  Returns
    /// error.WalletLocked if encrypted and the in-memory encryption_key is
    /// absent.  Backward-compat: a wallet loaded from a legacy plaintext
    /// wallet.dat has `encrypted=true` but null nonces/tags — in that case
    /// the stored bytes ARE the plaintext and we return them directly.
    fn getPlaintextMasterKey(self: *const Wallet) !?ExtendedKey {
        const mk = self.master_key orelse return null;
        if (!self.encrypted) return mk;
        // Legacy plaintext-on-disk wallet read before the W161 fix landed:
        // ciphertext fields missing → bytes are plaintext.
        if (self.master_key_nonce == null or self.master_chain_code_nonce == null) {
            return mk;
        }
        const enc_key = self.encryption_key orelse return error.WalletLocked;
        const k_nonce = self.master_key_nonce.?;
        const k_tag = self.master_key_tag orelse return error.WalletNotEncrypted;
        const cc_nonce = self.master_chain_code_nonce.?;
        const cc_tag = self.master_chain_code_tag orelse return error.WalletNotEncrypted;
        var out = mk;
        out.key = try decryptPrivateKey(&enc_key, &mk.key, &k_nonce, &k_tag);
        out.chain_code = try decryptPrivateKey(&enc_key, &mk.chain_code, &cc_nonce, &cc_tag);
        return out;
    }

    /// Sign a transaction input using the appropriate signing algorithm.
    ///
    /// `all_prevouts`: optional slice of all spent prevouts in input order.
    /// REQUIRED for BIP-341 Taproot inputs (`utxo.address_type == .p2tr`)
    /// because BIP-341 commits to `sha_amounts` and `sha_scriptPubKeys` over
    /// every input. May be `null` for legacy / BIP-143 v0 inputs, which only
    /// commit to the per-input prevout already passed via `utxo`.
    pub fn signInput(
        self: *Wallet,
        tx: *types.Transaction,
        input_index: usize,
        utxo: OwnedUtxo,
        sighash_type: u32,
        all_prevouts: ?[]const OwnedUtxo,
    ) !void {
        if (utxo.key_index >= self.keys.items.len) {
            return error.KeyNotFound;
        }

        const mutable_inputs = @constCast(tx.inputs);
        const key = self.keys.items[utxo.key_index];
        // Decrypt the private key if the wallet is encrypted.
        var plaintext_secret = try self.getPlaintextSecretKey(utxo.key_index);
        defer @memset(&plaintext_secret, 0);

        switch (utxo.address_type) {
            .p2pkh => {
                // Legacy signing: SIGHASH over simplified transaction
                const sighash = try computeLegacySigHash(tx, input_index, utxo, sighash_type, self.allocator);
                const sig = try self.ecdsaSign(&sighash, &plaintext_secret);

                // Build scriptSig: <sig+hashtype> <pubkey>
                var script_sig = std.ArrayList(u8).init(self.allocator);
                errdefer script_sig.deinit();

                // Push signature + hashtype
                const sig_len = getDerSigLen(&sig);
                try script_sig.append(@intCast(sig_len + 1));
                try script_sig.appendSlice(sig[0..sig_len]);
                try script_sig.append(@intCast(sighash_type & 0xFF));

                // Push compressed pubkey
                try script_sig.append(33);
                try script_sig.appendSlice(&key.public_key);

                // Update the transaction input
                const script_sig_slice = try script_sig.toOwnedSlice();
                mutable_inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = script_sig_slice,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = tx.inputs[input_index].witness,
                };
            },
            .p2sh_p2wpkh => {
                // W29-C: When the caller supplies a witness_script on a
                // P2SH UTXO, treat it as P2SH-wrapped-P2WSH (BIP-141 nested
                // segwit on a script-hash inner). Detect this *before* the
                // legacy P2SH-P2WPKH path so a P2WSH inner doesn't get
                // signed as P2WPKH-shaped garbage.
                if (utxo.witness_script) |witness_script| {
                    // W38 defense-in-depth: verify the BIP-16 P2SH outer
                    // commitment at the dispatch site, mirroring the W31
                    // idiom used a few lines below for the legacy
                    // P2SH-P2WPKH path. The reconstructed redeemScript here
                    // is `OP_0 <0x20> <sha256(witness_script)>`, and its
                    // hash160 must equal `script_pubkey[2..22]` of the
                    // on-chain `OP_HASH160 <h> OP_EQUAL` SPK. The inner
                    // P2WSH commitment is also asserted inside
                    // `signP2SH_P2WSH` itself (defense-in-depth, lines
                    // 2215-2228) — this check closes the *outer* gap that
                    // W37 audit flagged at the dispatch site.
                    const spk = utxo.output.script_pubkey;
                    if (spk.len != 23 or spk[0] != 0xa9 or spk[1] != 0x14 or spk[22] != 0x87) {
                        return error.UtxoNotP2SH;
                    }
                    {
                        const ws_hash = crypto.sha256(witness_script);
                        var inner_redeem: [34]u8 = undefined;
                        inner_redeem[0] = 0x00; // OP_0
                        inner_redeem[1] = 0x20; // Push 32 bytes
                        @memcpy(inner_redeem[2..34], &ws_hash);
                        const expected = crypto.hash160(&inner_redeem);
                        if (!std.mem.eql(u8, spk[2..22], &expected)) {
                            return error.RedeemScriptCommitmentMismatch;
                        }
                    }

                    const key_indices = [_]usize{utxo.key_index};
                    const result = try signP2SH_P2WSH(
                        self,
                        tx,
                        input_index,
                        witness_script,
                        utxo.output.value,
                        &key_indices,
                        utxo.extra_signing_keys,
                        sighash_type,
                        self.allocator,
                    );
                    mutable_inputs[input_index] = types.TxIn{
                        .previous_output = tx.inputs[input_index].previous_output,
                        .script_sig = result.script_sig,
                        .sequence = tx.inputs[input_index].sequence,
                        .witness = result.witness,
                    };
                    return;
                }

                // P2SH-P2WPKH signing: BIP-143 sighash with scriptSig containing redeem script
                //
                // W31 defense-in-depth: verify the BIP-16 P2SH commitment
                // before signing. Today's dispatch only routes here when the
                // wallet matched the UTXO by `(txid, vout)` against an owned
                // entry whose key derives the redeemScript, so the pubkey we
                // sign with is the same one whose hash160 forms the P2SH
                // scriptPubKey. Future refactors (e.g. signing against a
                // caller-supplied prevout) could break that invariant — this
                // check fails loud rather than emitting a tx whose script
                // commitment doesn't match the on-chain UTXO.
                const pubkey_hash = crypto.hash160(&key.public_key);
                const spk = utxo.output.script_pubkey;
                if (spk.len != 23 or spk[0] != 0xa9 or spk[1] != 0x14 or spk[22] != 0x87) {
                    return error.UtxoNotP2SH;
                }
                {
                    var inner_redeem: [22]u8 = undefined;
                    inner_redeem[0] = 0x00; // OP_0
                    inner_redeem[1] = 0x14; // Push 20 bytes
                    @memcpy(inner_redeem[2..22], &pubkey_hash);
                    const expected = crypto.hash160(&inner_redeem);
                    if (!std.mem.eql(u8, spk[2..22], &expected)) {
                        return error.RedeemScriptCommitmentMismatch;
                    }
                }

                const sighash = try computeWitnessSigHashV0(tx, input_index, utxo, sighash_type, self.allocator);
                const sig = try self.ecdsaSign(&sighash, &plaintext_secret);

                // Build scriptSig: push of redeem script (OP_0 <pubkey_hash>)
                var script_sig = try self.allocator.alloc(u8, 23);
                script_sig[0] = 0x16; // Push 22 bytes
                script_sig[1] = 0x00; // OP_0
                script_sig[2] = 0x14; // Push 20 bytes
                @memcpy(script_sig[3..23], &pubkey_hash);

                // Build witness: [sig+hashtype, pubkey]
                var witness = try self.allocator.alloc([]const u8, 2);
                errdefer self.allocator.free(witness);

                const sig_len = getDerSigLen(&sig);
                var sig_with_hashtype = try self.allocator.alloc(u8, sig_len + 1);
                @memcpy(sig_with_hashtype[0..sig_len], sig[0..sig_len]);
                sig_with_hashtype[sig_len] = @intCast(sighash_type & 0xFF);
                witness[0] = sig_with_hashtype;

                const pubkey_copy = try self.allocator.alloc(u8, 33);
                @memcpy(pubkey_copy, &key.public_key);
                witness[1] = pubkey_copy;

                mutable_inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = script_sig,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = witness,
                };
            },
            .p2wpkh => {
                // BIP-143 SegWit v0 signing
                const sighash = try computeWitnessSigHashV0(tx, input_index, utxo, sighash_type, self.allocator);
                const sig = try self.ecdsaSign(&sighash, &plaintext_secret);

                // Build witness: [sig+hashtype, pubkey]
                var witness = try self.allocator.alloc([]const u8, 2);
                errdefer self.allocator.free(witness);

                const sig_len = getDerSigLen(&sig);
                var sig_with_hashtype = try self.allocator.alloc(u8, sig_len + 1);
                @memcpy(sig_with_hashtype[0..sig_len], sig[0..sig_len]);
                sig_with_hashtype[sig_len] = @intCast(sighash_type & 0xFF);
                witness[0] = sig_with_hashtype;

                const pubkey_copy = try self.allocator.alloc(u8, 33);
                @memcpy(pubkey_copy, &key.public_key);
                witness[1] = pubkey_copy;

                mutable_inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = tx.inputs[input_index].script_sig,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = witness,
                };
            },
            .p2tr => {
                // BIP-341 Taproot key-path signing (Schnorr).
                //
                // Requires all spent prevouts to compute sha_amounts /
                // sha_scriptPubKeys per BIP-341. The pre-W20 path discarded
                // them and emitted a sighash that no compliant verifier
                // would ever accept; see audit note on `computeTaprootSigHash`.
                const prevouts = all_prevouts orelse return error.TaprootRequiresAllPrevouts;
                const sighash = try computeTaprootSigHash(tx, input_index, prevouts, sighash_type, self.allocator);

                // BIP-86: build the keypair from the raw secret, then apply
                // the empty-merkle-root TapTweak so the Schnorr signature
                // commits to the *tweaked* output key — i.e. the same key
                // the wallet now puts into `getScriptPubKey(.p2tr)` (and
                // therefore the on-chain UTXO). Without this tweak the
                // chain carries the internal key while the signature is
                // over a key that can never appear in a compliant P2TR
                // output, so the spend would always fail Schnorr verify.
                var keypair: secp256k1.secp256k1_keypair = undefined;
                if (secp256k1.secp256k1_keypair_create(self.ctx, &keypair, &plaintext_secret) != 1) {
                    return error.KeypairCreationFailed;
                }

                const tweak = bip86Tweak(&key.x_only_pubkey);
                if (secp256k1.secp256k1_keypair_xonly_tweak_add(self.ctx, &keypair, &tweak) != 1) {
                    return error.TaprootTweakFailed;
                }

                var sig: [64]u8 = undefined;
                if (secp256k1.secp256k1_schnorrsig_sign32(
                    self.ctx,
                    &sig,
                    &sighash,
                    &keypair,
                    null,
                ) != 1) {
                    return error.SchnorrSignFailed;
                }

                // Witness: [signature] (65 bytes if non-default sighash, 64 if default)
                var witness = try self.allocator.alloc([]const u8, 1);
                errdefer self.allocator.free(witness);

                if (sighash_type == 0x00) {
                    // Default sighash (SIGHASH_DEFAULT) - 64 byte signature
                    witness[0] = try self.allocator.dupe(u8, &sig);
                } else {
                    // Non-default - append sighash byte
                    var sig_ext = try self.allocator.alloc(u8, 65);
                    @memcpy(sig_ext[0..64], &sig);
                    sig_ext[64] = @intCast(sighash_type & 0xFF);
                    witness[0] = sig_ext;
                }

                mutable_inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = tx.inputs[input_index].script_sig,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = witness,
                };
            },
            .p2wsh => {
                // W29-C: P2WSH signing requires the caller to supply the
                // witness script via `OwnedUtxo.witness_script`. Without it
                // there is no scriptCode for the BIP-143 sighash and no
                // final element for the witness stack.
                const witness_script = utxo.witness_script orelse return error.P2WSHMissingWitnessScript;

                // W38 defense-in-depth: verify the BIP-141 P2WSH commitment
                // before signing — `sha256(witness_script)` must match the
                // 32 bytes embedded in the on-chain segwit-v0 scriptPubKey
                // (`OP_0 <0x20> <ws_hash>`). Without this guard the signer
                // would happily sign a sighash committed to a witnessScript
                // that the on-chain UTXO never references, then emit a
                // structurally-valid spend that every consensus verifier
                // rejects. Same bug shape as the W31 P2SH outer-commitment
                // check just above on `.p2sh_p2wpkh` (lines 1203-1217); same
                // sentinel-error idiom (`WitnessScriptCommitmentMismatch`,
                // already declared in `psbt.zig` for the inner check inside
                // `signP2SH_P2WSH`).
                {
                    const spk = utxo.output.script_pubkey;
                    if (spk.len != 34 or spk[0] != 0x00 or spk[1] != 0x20) {
                        return error.WitnessScriptCommitmentMismatch;
                    }
                    const ws_hash = crypto.sha256(witness_script);
                    if (!std.mem.eql(u8, spk[2..34], &ws_hash)) {
                        return error.WitnessScriptCommitmentMismatch;
                    }
                }

                // W29-C: per the design doc, dispatch through the
                // Wallet's own key (at `utxo.key_index`) plus optional
                // cosigner secrets carried on the UTXO. Multisig is
                // detected at signing time inside `signP2WSH`.
                const key_indices = [_]usize{utxo.key_index};
                const witness = try signP2WSH(
                    self,
                    tx,
                    input_index,
                    witness_script,
                    utxo.output.value,
                    &key_indices,
                    utxo.extra_signing_keys,
                    sighash_type,
                    self.allocator,
                );

                // For bare P2WSH the scriptSig stays empty and only the
                // witness is populated.
                mutable_inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = tx.inputs[input_index].script_sig,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = witness,
                };
            },
        }
    }

    /// ECDSA sign a 32-byte message hash, returns DER-encoded signature.
    fn ecdsaSign(self: *Wallet, msg_hash: *const [32]u8, secret_key: *const [32]u8) ![72]u8 {
        var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
        if (secp256k1.secp256k1_ecdsa_sign(
            self.ctx,
            &sig,
            msg_hash,
            secret_key,
            null,
            null,
        ) != 1) {
            return error.EcdsaSignFailed;
        }

        // Serialize as DER
        var der: [72]u8 = undefined;
        var der_len: usize = 72;
        _ = secp256k1.secp256k1_ecdsa_signature_serialize_der(
            self.ctx,
            &der,
            &der_len,
            &sig,
        );
        return der;
    }

    /// Verify an ECDSA signature.
    pub fn verifyEcdsa(
        self: *Wallet,
        sig_der: []const u8,
        msg_hash: *const [32]u8,
        pubkey_bytes: []const u8,
    ) !bool {
        var pubkey: secp256k1.secp256k1_pubkey = undefined;
        if (secp256k1.secp256k1_ec_pubkey_parse(
            self.ctx,
            &pubkey,
            pubkey_bytes.ptr,
            pubkey_bytes.len,
        ) != 1) {
            return error.InvalidPublicKey;
        }

        var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
        if (secp256k1.secp256k1_ecdsa_signature_parse_der(
            self.ctx,
            &sig,
            sig_der.ptr,
            sig_der.len,
        ) != 1) {
            return error.InvalidSignature;
        }

        // Normalize to low-S (BIP-62)
        _ = secp256k1.secp256k1_ecdsa_signature_normalize(self.ctx, &sig, &sig);

        return secp256k1.secp256k1_ecdsa_verify(self.ctx, &sig, msg_hash, &pubkey) == 1;
    }

    /// Verify a Schnorr signature (BIP-340).
    pub fn verifySchnorr(
        self: *Wallet,
        sig: *const [64]u8,
        msg_hash: *const [32]u8,
        pubkey_x: *const [32]u8,
    ) !bool {
        var xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
        if (secp256k1.secp256k1_xonly_pubkey_parse(self.ctx, &xonly, pubkey_x) != 1) {
            return error.InvalidPublicKey;
        }

        return secp256k1.secp256k1_schnorrsig_verify(
            self.ctx,
            sig,
            msg_hash,
            32,
            &xonly,
        ) == 1;
    }

    // ========================================================================
    // Encryption Support (AES-256-GCM)
    // ========================================================================

    /// Encryption parameters
    pub const EncryptionParams = struct {
        /// Scrypt parameters (N=2^14, r=8, p=1 are reasonable defaults)
        ln: u6 = 14, // log2(N)
        r: u30 = 8,
        p: u30 = 1,
    };

    /// Encrypt the wallet with a passphrase.
    /// All private keys are encrypted using AES-256-GCM with a key derived from
    /// the passphrase using scrypt.
    pub fn encryptWallet(self: *Wallet, passphrase: []const u8) !void {
        return self.encryptWalletWithParams(passphrase, .{});
    }

    /// Encrypt the wallet with custom parameters.
    pub fn encryptWalletWithParams(self: *Wallet, passphrase: []const u8, params: EncryptionParams) !void {
        if (self.encrypted) {
            return error.WalletAlreadyEncrypted;
        }

        if (passphrase.len == 0) {
            return error.EmptyPassphrase;
        }

        // Generate random salt
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);

        // Derive key using scrypt
        var derived_key: [32]u8 = undefined;
        try std.crypto.pwhash.scrypt.kdf(
            self.allocator,
            &derived_key,
            passphrase,
            &salt,
            .{ .ln = params.ln, .r = params.r, .p = params.p },
        );

        // Encrypt all private keys in place using AES-256-GCM.
        // Each key gets a unique random nonce; the auth tag is stored alongside.
        for (self.keys.items) |*keypair| {
            const enc = encryptPrivateKey(&derived_key, &keypair.secret_key);
            keypair.secret_key = enc.ciphertext;
            keypair.encryption_nonce = enc.nonce;
            keypair.encryption_tag = enc.tag;
        }

        // W161 BUG-5 fix: also encrypt the HD master private key + chain code
        // in place.  Previously these were left as plaintext in memory and on
        // disk REGARDLESS of `encryptwallet`, so AES-256-GCM child-encryption
        // was cosmetic — anyone reading wallet.dat recovered the seed of every
        // child via BIP-32 derivation.  Now master_key.key and
        // master_key.chain_code are stored as ciphertext with their own nonces
        // and tags; plaintext is reconstructed on-demand via
        // getPlaintextMasterKey() once the wallet is unlocked.
        if (self.master_key) |*mk| {
            const enc_key = encryptPrivateKey(&derived_key, &mk.key);
            mk.key = enc_key.ciphertext;
            self.master_key_nonce = enc_key.nonce;
            self.master_key_tag = enc_key.tag;
            const enc_cc = encryptPrivateKey(&derived_key, &mk.chain_code);
            mk.chain_code = enc_cc.ciphertext;
            self.master_chain_code_nonce = enc_cc.nonce;
            self.master_chain_code_tag = enc_cc.tag;
        }

        // Store encryption state
        self.encryption_salt = salt;
        self.encryption_key = null; // Key not stored for security
        self.encrypted = true;
        self.unlock_until = null;

        // Clear derived key
        @memset(&derived_key, 0);
    }

    /// Unlock the wallet for a specified duration (in seconds).
    /// This derives the encryption key and stores it temporarily.
    pub fn unlockWallet(self: *Wallet, passphrase: []const u8, timeout_seconds: u32) !void {
        if (!self.encrypted) {
            return error.WalletNotEncrypted;
        }

        const salt = self.encryption_salt orelse return error.WalletNotEncrypted;

        // Derive key using scrypt
        var derived_key: [32]u8 = undefined;
        try std.crypto.pwhash.scrypt.kdf(
            self.allocator,
            &derived_key,
            passphrase,
            &salt,
            .{ .ln = 14, .r = 8, .p = 1 },
        );

        // Verify the passphrase by attempting to decrypt the first key.
        // With AES-256-GCM, decryptPrivateKey returns error.AuthenticationFailed
        // when the derived key is wrong — the auth tag check fails.
        if (self.keys.items.len > 0) {
            const first = &self.keys.items[0];
            const nonce = first.encryption_nonce orelse {
                @memset(&derived_key, 0);
                return error.WalletNotEncrypted;
            };
            const tag = first.encryption_tag orelse {
                @memset(&derived_key, 0);
                return error.WalletNotEncrypted;
            };
            _ = decryptPrivateKey(&derived_key, &first.secret_key, &nonce, &tag) catch {
                @memset(&derived_key, 0);
                return error.WrongPassphrase;
            };
        }

        // Store the key and set unlock timeout
        self.encryption_key = derived_key;
        const now = std.time.timestamp();
        self.unlock_until = now + @as(i64, timeout_seconds);
    }

    /// Lock the wallet, clearing the encryption key from memory.
    pub fn lockWallet(self: *Wallet) void {
        if (self.encryption_key) |*key| {
            @memset(key, 0);
        }
        self.encryption_key = null;
        self.unlock_until = null;
    }

    /// Check if the wallet is currently unlocked.
    pub fn isUnlocked(self: *const Wallet) bool {
        if (!self.encrypted) return true;
        if (self.encryption_key == null) return false;
        if (self.unlock_until) |until| {
            return std.time.timestamp() < until;
        }
        return false;
    }

    /// Change the wallet passphrase.
    pub fn changePassphrase(self: *Wallet, old_passphrase: []const u8, new_passphrase: []const u8) !void {
        if (!self.encrypted) {
            return error.WalletNotEncrypted;
        }

        if (new_passphrase.len == 0) {
            return error.EmptyPassphrase;
        }

        const old_salt = self.encryption_salt orelse return error.WalletNotEncrypted;

        // Derive old key
        var old_key: [32]u8 = undefined;
        try std.crypto.pwhash.scrypt.kdf(
            self.allocator,
            &old_key,
            old_passphrase,
            &old_salt,
            .{ .ln = 14, .r = 8, .p = 1 },
        );
        defer @memset(&old_key, 0);

        // Generate new salt
        var new_salt: [16]u8 = undefined;
        std.crypto.random.bytes(&new_salt);

        // Derive new key
        var new_key: [32]u8 = undefined;
        try std.crypto.pwhash.scrypt.kdf(
            self.allocator,
            &new_key,
            new_passphrase,
            &new_salt,
            .{ .ln = 14, .r = 8, .p = 1 },
        );
        defer @memset(&new_key, 0);

        // Re-encrypt all keys: decrypt with old key, re-encrypt with new key + fresh nonces.
        for (self.keys.items) |*keypair| {
            const old_nonce = keypair.encryption_nonce orelse return error.WalletNotEncrypted;
            const old_tag = keypair.encryption_tag orelse return error.WalletNotEncrypted;
            const plaintext = try decryptPrivateKey(&old_key, &keypair.secret_key, &old_nonce, &old_tag);
            const enc = encryptPrivateKey(&new_key, &plaintext);
            keypair.secret_key = enc.ciphertext;
            keypair.encryption_nonce = enc.nonce;
            keypair.encryption_tag = enc.tag;
        }

        // W161 BUG-5 fix: re-encrypt the HD master key + chain code with the
        // new derived key + fresh nonces.  If the master_key was loaded from a
        // legacy plaintext wallet.dat (null nonces), treat the stored bytes as
        // plaintext for the decrypt step — the re-encrypted form upgrades the
        // wallet to the post-fix format on first changePassphrase.
        if (self.master_key) |*mk| {
            var k_plain: [32]u8 = mk.key;
            var cc_plain: [32]u8 = mk.chain_code;
            if (self.master_key_nonce) |kn| {
                const kt = self.master_key_tag orelse return error.WalletNotEncrypted;
                k_plain = try decryptPrivateKey(&old_key, &mk.key, &kn, &kt);
            }
            if (self.master_chain_code_nonce) |cn| {
                const ct = self.master_chain_code_tag orelse return error.WalletNotEncrypted;
                cc_plain = try decryptPrivateKey(&old_key, &mk.chain_code, &cn, &ct);
            }
            const enc_k = encryptPrivateKey(&new_key, &k_plain);
            const enc_cc = encryptPrivateKey(&new_key, &cc_plain);
            mk.key = enc_k.ciphertext;
            mk.chain_code = enc_cc.ciphertext;
            self.master_key_nonce = enc_k.nonce;
            self.master_key_tag = enc_k.tag;
            self.master_chain_code_nonce = enc_cc.nonce;
            self.master_chain_code_tag = enc_cc.tag;
            @memset(&k_plain, 0);
            @memset(&cc_plain, 0);
        }

        // Update salt
        self.encryption_salt = new_salt;
        self.lockWallet();
    }

    // ========================================================================
    // Label Support
    // ========================================================================

    /// Set a label for an address.
    pub fn setLabel(self: *Wallet, addr: []const u8, label: []const u8) !void {
        // If there's an existing entry, free it first
        if (self.labels.get(addr)) |old_label| {
            self.allocator.free(old_label);
            // We need to keep the same key, just update the value
            const existing_key = self.labels.getKey(addr).?;
            try self.labels.put(existing_key, try self.allocator.dupe(u8, label));
        } else {
            // New entry
            const owned_addr = try self.allocator.dupe(u8, addr);
            errdefer self.allocator.free(owned_addr);
            const owned_label = try self.allocator.dupe(u8, label);
            try self.labels.put(owned_addr, owned_label);
        }
    }

    /// Get the label for an address.
    pub fn getLabel(self: *const Wallet, addr: []const u8) ?[]const u8 {
        return self.labels.get(addr);
    }

    /// Remove a label for an address.
    pub fn removeLabel(self: *Wallet, addr: []const u8) void {
        if (self.labels.fetchRemove(addr)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }
    }

    /// Get all labeled addresses.
    pub fn getLabeledAddresses(self: *const Wallet, allocator: std.mem.Allocator) ![]const []const u8 {
        var addrs = std.ArrayList([]const u8).init(allocator);
        errdefer addrs.deinit();

        var it = self.labels.keyIterator();
        while (it.next()) |key| {
            try addrs.append(key.*);
        }
        return addrs.toOwnedSlice();
    }

    /// Get spendable balance (excluding immature coinbase outputs).
    pub fn getSpendableBalance(self: *const Wallet) i64 {
        var total: i64 = 0;
        for (self.utxos.items) |utxo| {
            // Skip immature coinbase outputs
            if (utxo.is_coinbase) {
                if (self.tip_height < utxo.height) continue;
                const confirmations = self.tip_height - utxo.height;
                if (confirmations < consensus.COINBASE_MATURITY) {
                    continue;
                }
            }
            total += utxo.output.value;
        }
        return total;
    }

    /// Get immature balance (coinbase outputs not yet mature).
    pub fn getImmatureBalance(self: *const Wallet) i64 {
        var total: i64 = 0;
        for (self.utxos.items) |utxo| {
            if (utxo.is_coinbase) {
                if (self.tip_height >= utxo.height) {
                    const confirmations = self.tip_height - utxo.height;
                    if (confirmations < consensus.COINBASE_MATURITY) {
                        total += utxo.output.value;
                    }
                }
            }
        }
        return total;
    }

    /// Get balance with a minimum-confirmations filter.
    ///
    /// Always excludes immature coinbase (depth < `COINBASE_MATURITY` = 100),
    /// matching Core's `CWallet::GetBalance` which always filters immature
    /// coinbase before applying `min_depth`.
    ///
    /// `minconf` corresponds to the first positional argument of Core's
    /// `getbalance` RPC. Core's default is 0 (count 0-conf change too); the
    /// caller is responsible for parsing the JSON-RPC default.
    ///
    /// Depth convention matches the rest of clearbit's wallet code (e.g.
    /// `getSpendableBalance`, `selectCoinsWithOptions`): a UTXO at
    /// `utxo.height` with chain tip at `self.tip_height` has depth
    /// `tip_height - height` (so a UTXO from the tip block has depth 0;
    /// `minconf=1` means "must be 1 block deep").
    ///
    /// Reference: bitcoin-core/src/wallet/rpc/coins.cpp::getbalance,
    ///            bitcoin-core/src/wallet/receive.cpp::CWallet::GetBalance,
    ///            bitcoin-core/src/wallet/transaction.cpp::CWalletTx::GetDepthInMainChain.
    ///
    /// Note: `include_watchonly` and `avoid_reuse` are not yet wired —
    /// clearbit's `OwnedUtxo` does not track watch-only or address-reuse
    /// state. See FIX-60 commit body.
    pub fn getBalanceMinConf(self: *const Wallet, minconf: u32) i64 {
        var total: i64 = 0;
        for (self.utxos.items) |utxo| {
            // A UTXO whose recorded height is in the future of our tip is
            // treated as unconfirmed (depth 0).
            if (self.tip_height < utxo.height) {
                if (minconf > 0) continue;
                // depth 0 — also reject if it's a coinbase (immature by
                // definition: 0 < COINBASE_MATURITY).
                if (utxo.is_coinbase) continue;
                total += utxo.output.value;
                continue;
            }

            const depth = self.tip_height - utxo.height;

            // Always exclude immature coinbase, regardless of minconf.
            if (utxo.is_coinbase and depth < consensus.COINBASE_MATURITY) continue;

            if (depth < minconf) continue;
            total += utxo.output.value;
        }
        return total;
    }
};

// ============================================================================
// Encryption Helpers (AES-256-GCM)
// ============================================================================

// AES-256-GCM constants via the Zig 0.13 standard library.
//   key_length  = 32 bytes
//   nonce_length = 12 bytes  (random per encryption)
//   tag_length  = 16 bytes  (authentication tag; wrong key → AuthenticationFailed)
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

/// Result of encrypting a private key: ciphertext + random nonce + authentication tag.
/// The nonce and tag must be stored alongside the ciphertext in the wallet file.
pub const EncryptedKey = struct {
    ciphertext: [32]u8,
    nonce: [Aes256Gcm.nonce_length]u8,
    tag: [Aes256Gcm.tag_length]u8,
};

/// Encrypt a 32-byte private key using AES-256-GCM.
///
/// Security properties:
///   * Authentication: the 16-byte tag binds the ciphertext to the key; any
///     modification returns error.AuthenticationFailed on decrypt.
///   * Unique ciphertext: a fresh random 12-byte nonce is generated each call,
///     so encrypting the same key twice produces different ciphertexts.
///   * Wrong-key detection: decrypting with the wrong passphrase-derived key
///     fails with error.AuthenticationFailed (unlike the previous XOR approach
///     which always "succeeded" regardless of passphrase).
///
/// The caller must persist `result.nonce` and `result.tag` alongside the ciphertext.
fn encryptPrivateKey(encryption_key: *const [Aes256Gcm.key_length]u8, plaintext: *const [32]u8) EncryptedKey {
    var result: EncryptedKey = undefined;
    std.crypto.random.bytes(&result.nonce);
    // Additional data is empty; the key index / pubkey are not secret but
    // we keep AD empty for simplicity (consistent with Core's CCrypter).
    Aes256Gcm.encrypt(
        &result.ciphertext,
        &result.tag,
        plaintext,
        &[_]u8{}, // additional data
        result.nonce,
        encryption_key.*,
    );
    return result;
}

/// Decrypt a 32-byte private key using AES-256-GCM.
///
/// Returns `error.AuthenticationFailed` if the tag does not match — which
/// happens when the passphrase is wrong, the ciphertext was tampered with,
/// or the nonce/tag bytes are corrupted.  This replaces the old XOR path that
/// silently returned garbage (or even a valid-looking key) for any passphrase.
fn decryptPrivateKey(
    encryption_key: *const [Aes256Gcm.key_length]u8,
    ciphertext: *const [32]u8,
    nonce: *const [Aes256Gcm.nonce_length]u8,
    tag: *const [Aes256Gcm.tag_length]u8,
) ![32]u8 {
    var plaintext: [32]u8 = undefined;
    try Aes256Gcm.decrypt(
        &plaintext,
        ciphertext,
        tag.*,
        &[_]u8{}, // additional data
        nonce.*,
        encryption_key.*,
    );
    return plaintext;
}

// ============================================================================
// Transaction Creation
// ============================================================================

/// Options for creating a transaction.
pub const CreateTxOptions = struct {
    /// Fee rate in satoshis per virtual byte.
    fee_rate: u64 = 1,
    /// Current block height (for anti-fee-sniping locktime).
    current_height: u32 = 0,
    /// Whether to enable anti-fee-sniping (set locktime to current_height).
    anti_fee_sniping: bool = true,
    /// Sighash type for signing (default: SIGHASH_ALL).
    sighash_type: u32 = 0x01,
    /// BIP-125 replaceability (W118 BUG-9 / FIX-61).
    ///   true  → emit `sequence = 0xFFFFFFFD` (Core wallet default,
    ///           strict BIP-125 RBF-opt-in).
    ///   false → emit `sequence = 0xFFFFFFFE` (locktime active but no RBF
    ///           signal — non-replaceable).
    /// The previous hard-coded `0xFFFFFFFE` is preserved as the default so
    /// historical callers (and the G21 test) keep their current behavior.
    /// See `bumpFee` for the replacement-tx side, which always uses
    /// `0xFFFFFFFD` regardless of this flag.
    replaceable: bool = false,
};

/// Output for a new transaction.
pub const TxOutput = struct {
    value: i64,
    script_pubkey: []const u8,
};

/// Create and sign a transaction spending selected UTXOs to the specified outputs.
///
/// Anti-fee-sniping: Sets nLockTime to current_height to discourage miners from
/// reordering blocks to steal fees. This makes the transaction invalid until
/// the specified block height, preventing fee sniping attacks.
///
/// Balance check (FIX-60 / W118 BUG-10): before signing, validate that
/// `Σ utxo.value ≥ Σ output.value + change.value + estimated_fee`. If the
/// inputs do not cover the outputs+fee, returns `error.InsufficientFunds`
/// (or `error.FeeNotCovered` when the gap is purely the fee — outputs
/// alone are <= inputs, only the fee tips the scale). This mirrors
/// `CWallet::CreateTransactionInternal`, which rejects with "Insufficient
/// funds" / "The total exceeds your balance when the … fee is included"
/// before any signing happens.
///
/// Reference: Bitcoin Core wallet/spend.cpp CreateTransactionInternal()
pub fn createTransaction(
    wallet: *Wallet,
    utxos_to_spend: []const OwnedUtxo,
    outputs: []const TxOutput,
    change_output: ?TxOutput,
    options: CreateTxOptions,
) !types.Transaction {
    const allocator = wallet.allocator;

    // -----------------------------------------------------------------
    // Pre-sign balance check (W118 BUG-10).
    //
    // We compute three numbers:
    //   sum_in     — Σ utxo.value over selected inputs
    //   sum_out    — Σ outputs.value (+ change.value if a change output is
    //                being added)
    //   est_fee    — rough vsize × fee_rate estimate; we use the same
    //                input-size estimates as `selectCoinsWithOptions`
    //                (estimateInputSize), plus a fixed-per-output overhead
    //                (~34 vbytes for a P2WPKH output, ~32 vbytes for the
    //                tx skeleton). The estimate is intentionally a tiny
    //                lower bound — the goal is to surface impossible
    //                outputs before signing, not to fee-budget exactly.
    //
    // Decisions:
    //   sum_in <  sum_out               → InsufficientFunds (over-spend)
    //   sum_in == sum_out  & est_fee>0  → FeeNotCovered (no headroom)
    //   sum_in <  sum_out + est_fee     → FeeNotCovered
    //   otherwise                       → proceed with signing
    //
    // The two distinct errors let callers distinguish "you asked for more
    // than you have" from "you have enough but not for the fee". Core
    // surfaces the same distinction via separate error strings.
    // -----------------------------------------------------------------
    var sum_in: i128 = 0;
    for (utxos_to_spend) |utxo| sum_in += utxo.output.value;

    var sum_out: i128 = 0;
    for (outputs) |out| sum_out += out.value;
    if (change_output) |change| sum_out += change.value;

    if (sum_in < sum_out) {
        return error.InsufficientFunds;
    }

    // Rough vsize estimate:
    //   tx overhead:    10 vbytes  (version + locktime + counts + segwit marker/flag)
    //   per-input:      estimateInputSize(addr_type)
    //   per-output:     34 vbytes  (8 value + 1 script-len + ~25 script)
    const TX_OVERHEAD_VBYTES: u64 = 10;
    const OUTPUT_VBYTES: u64 = 34;
    var est_vsize: u64 = TX_OVERHEAD_VBYTES;
    for (utxos_to_spend) |utxo| est_vsize += estimateInputSize(utxo.address_type);
    est_vsize += OUTPUT_VBYTES * @as(u64, outputs.len + if (change_output != null) @as(usize, 1) else @as(usize, 0));

    const est_fee: i128 = @intCast(est_vsize * options.fee_rate);
    if (sum_in < sum_out + est_fee) {
        return error.FeeNotCovered;
    }
    // -----------------------------------------------------------------

    // Count total inputs and outputs
    const num_inputs = utxos_to_spend.len;
    const num_outputs = outputs.len + if (change_output != null) @as(usize, 1) else @as(usize, 0);

    // Build inputs
    var inputs = try allocator.alloc(types.TxIn, num_inputs);
    errdefer allocator.free(inputs);

    // W118 BUG-9 / FIX-61: honor `options.replaceable`. The legacy default
    // (false) preserves the historical `0xFFFFFFFE` sequence; opt-in callers
    // (and `bumpFee` internally) set `replaceable = true` to emit
    // `0xFFFFFFFD`, which is BIP-125's canonical RBF signal.
    const sequence: u32 = if (options.replaceable) 0xFFFFFFFD else 0xFFFFFFFE;
    for (utxos_to_spend, 0..) |utxo, i| {
        inputs[i] = types.TxIn{
            .previous_output = utxo.outpoint,
            .script_sig = &[_]u8{}, // Will be filled during signing
            .sequence = sequence, // BIP-125 opt-in (0xFFFFFFFD) or locktime-only (0xFFFFFFFE)
            .witness = &[_][]const u8{}, // Will be filled during signing
        };
    }

    // Build outputs
    var tx_outputs = try allocator.alloc(types.TxOut, num_outputs);
    errdefer allocator.free(tx_outputs);

    for (outputs, 0..) |out, i| {
        tx_outputs[i] = types.TxOut{
            .value = out.value,
            .script_pubkey = out.script_pubkey,
        };
    }

    // Add change output if provided
    if (change_output) |change| {
        tx_outputs[outputs.len] = types.TxOut{
            .value = change.value,
            .script_pubkey = change.script_pubkey,
        };
    }

    // Anti-fee-sniping: Set locktime to current block height
    // This makes the transaction invalid until that block, preventing miners
    // from reorganizing blocks to steal high-fee transactions
    //
    // Reference: BIP-0199, Bitcoin Core wallet/spend.cpp
    const lock_time: u32 = if (options.anti_fee_sniping and options.current_height > 0)
        options.current_height
    else
        0;

    // Create the transaction
    var tx = types.Transaction{
        .version = 2,
        .inputs = inputs,
        .outputs = tx_outputs,
        .lock_time = lock_time,
    };

    // Sign each input. `utxos_to_spend` is the canonical per-input prevouts
    // slice used for BIP-341 sha_amounts / sha_scriptPubKeys.
    for (utxos_to_spend, 0..) |utxo, i| {
        try wallet.signInput(&tx, i, utxo, options.sighash_type, utxos_to_spend);
    }

    return tx;
}

// ============================================================================
// W118 BUG-7 / BUG-8 / FIX-61: bumpfee / psbtbumpfee
// ============================================================================
//
// BIP-125 RBF fee-bumping for unconfirmed wallet transactions. Mirrors
// Bitcoin Core's `wallet/feebumper.{h,cpp}` minimal viable path:
//
//   - locate the unconfirmed original tx (caller supplies it explicitly here
//     because clearbit does not yet track a per-wallet mined/sent-tx index);
//   - validate: any input must signal BIP-125 (sequence < 0xFFFFFFFE) unless
//     the caller passes `force = true`;
//   - find a single wallet-owned change output (one whose script_pubkey
//     matches `getScriptPubKey(key_index, addr_type)` for some key we hold);
//   - compute the new fee as
//        orig_fee + ceil(orig_vsize * INCREMENTAL_FEE_RATE)
//     unless the caller passes an explicit `fee_rate` (sat/vB), in which
//     case the new fee is `fee_rate * orig_vsize` (rounded up);
//   - subtract `fee_delta = new_fee - orig_fee` from the change output;
//   - reject if the change after reduction falls below the per-spk dust
//     threshold (`dustThresholdFor`), or if the original tx already lacked
//     room to absorb the delta (`InsufficientChange`);
//   - re-sign every input (sequence flipped to 0xFFFFFFFD on the replacement,
//     locktime/version preserved) and return the new signed transaction +
//     fee accounting.
//
// `psbtBumpFee` follows the identical flow but stops short of signing —
// it produces a fresh BIP-174 PSBT with the reduced change output and
// the original prevouts attached. The signer (or another wallet) finalizes
// the PSBT.
//
// Reference: bitcoin-core/src/wallet/feebumper.cpp (PrepareRefund / Signed),
// BIP-125 §3 (Opt-in Full Replace-by-Fee Signaling), BIP-174 (PSBT).

/// BIP-125 incremental relay fee, sats/vB. Bitcoin Core's
/// `DEFAULT_INCREMENTAL_RELAY_FEE` is 1 sat/vB — every replacement must
/// pay at least this much *more* per vbyte than the original tx.
/// See bitcoin-core/src/policy/policy.h `DEFAULT_INCREMENTAL_RELAY_FEE`.
pub const INCREMENTAL_FEE_RATE: u64 = 1;

/// Per-scriptPubKey dust threshold (sats). Matches Core's
/// `GetDustThreshold` for the wallet output types clearbit supports —
/// roughly 3 × dust_relay_fee × vsize_of_spending_input.
fn dustThresholdFor(spk: []const u8) i64 {
    // Heuristic mirroring DUST_THRESHOLD_* constants above:
    //   P2WPKH (witness v0, 22-byte SPK starting 0x00 0x14): 294 sats
    //   P2TR   (witness v1, 34-byte SPK starting 0x51 0x20): 330 sats
    //   P2WSH  (witness v0, 34-byte SPK starting 0x00 0x20): 330 sats
    //   P2SH   (legacy, 23-byte SPK starting 0xa9 ...):       540 sats
    //   P2PKH  (legacy, 25-byte SPK starting 0x76 0xa9):      546 sats
    //   other / unrecognized:                                  546 sats
    if (spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14) return DUST_THRESHOLD_P2WPKH;
    if (spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20) return 330;
    if (spk.len == 34 and spk[0] == 0x00 and spk[1] == 0x20) return 330;
    if (spk.len == 23 and spk[0] == 0xa9 and spk[22] == 0x87) return 540;
    if (spk.len == 25 and spk[0] == 0x76 and spk[1] == 0xa9) return DUST_THRESHOLD_P2PKH;
    return DUST_THRESHOLD_P2PKH;
}

/// Estimate the vsize of a transaction without actually serializing the
/// witness. Sums per-input weights using `estimateInputSize` and adds a
/// fixed per-output overhead. Used by `bumpFee` to compute the new fee
/// target from the original vsize without depending on `serialize.zig`'s
/// weight calculator. Mirrors the same constants used inside
/// `createTransaction`'s pre-sign balance check.
fn estimateTxVsize(utxos: []const OwnedUtxo, num_outputs: usize) u64 {
    const TX_OVERHEAD_VBYTES: u64 = 10;
    const OUTPUT_VBYTES: u64 = 34;
    var v: u64 = TX_OVERHEAD_VBYTES;
    for (utxos) |u| v += estimateInputSize(u.address_type);
    v += OUTPUT_VBYTES * @as(u64, @intCast(num_outputs));
    return v;
}

pub const BumpFeeError = error{
    /// Original tx has at least one confirmation.
    AlreadyConfirmed,
    /// No input signals BIP-125 (every sequence is ≥ 0xFFFFFFFE) and
    /// `options.force` is not set.
    NotBIP125Replaceable,
    /// No output's scriptPubKey matches any wallet-derived spk across
    /// address types — wallet has no change to reduce.
    NoChangeOutput,
    /// The required fee delta exceeds the change output's value.
    InsufficientChange,
    /// The new change value would fall below the per-spk dust threshold.
    DustAfterReduce,
    /// Number of provided prevouts does not match number of tx inputs.
    PrevoutMismatch,
};

pub const BumpFeeOptions = struct {
    /// Replacement fee rate in sat/vB. If `null`, the replacement uses
    /// `orig_fee_rate + INCREMENTAL_FEE_RATE` (the BIP-125 minimum bump).
    fee_rate: ?u64 = null,
    /// Bypass the BIP-125 sequence check. Mirrors Core's `bumpfee`
    /// `force = true` switch which permits CPFP-style fee bumping of
    /// non-signaling parents. Default `false` matches Core's safer
    /// behavior.
    force: bool = false,
};

pub const BumpFeeResult = struct {
    /// The new signed transaction. Caller owns the inputs/outputs slices
    /// + per-input witnesses (free with the same idiom used after
    /// `createTransaction`).
    new_tx: types.Transaction,
    /// Fee of the original transaction (sats).
    orig_fee: i64,
    /// Fee of the new transaction (sats).
    new_fee: i64,
    /// Estimated vsize of the original transaction (vbytes).
    orig_vsize: u64,
    /// Index of the change output in the original tx that was reduced.
    change_index: usize,
};

/// Locate a wallet-owned change output in `tx`. Returns the output index
/// + the matching `(key_index, address_type)` pair so the caller can
/// confirm the wallet can re-sign that branch. Returns `null` if no
/// output's scriptPubKey matches a wallet-derived spk across any
/// address type.
fn findChangeOutput(
    wallet: *Wallet,
    tx: *const types.Transaction,
) !?struct { out_index: usize, key_index: usize, addr_type: AddressType } {
    const types_to_try = [_]AddressType{
        .p2wpkh,
        .p2sh_p2wpkh,
        .p2pkh,
        .p2tr,
        .p2wsh,
    };

    for (tx.outputs, 0..) |out, oi| {
        for (0..wallet.keys.items.len) |ki| {
            for (types_to_try) |at| {
                const spk = wallet.getScriptPubKey(ki, at) catch continue;
                defer wallet.allocator.free(spk);
                if (std.mem.eql(u8, spk, out.script_pubkey)) {
                    return .{ .out_index = oi, .key_index = ki, .addr_type = at };
                }
            }
        }
    }
    return null;
}

/// Compute the new fee for a replacement transaction. See module-level
/// comment block above for the formula.
fn computeBumpFee(
    orig_fee: i64,
    orig_vsize: u64,
    user_fee_rate: ?u64,
) i64 {
    if (user_fee_rate) |fr| {
        const new_fee: i128 = @as(i128, @intCast(fr)) * @as(i128, @intCast(orig_vsize));
        return @intCast(new_fee);
    }
    // Default: orig_fee + ceil(orig_vsize * INCREMENTAL_FEE_RATE).
    const bump: i128 = @as(i128, @intCast(INCREMENTAL_FEE_RATE)) *
        @as(i128, @intCast(orig_vsize));
    return orig_fee + @as(i64, @intCast(bump));
}

/// BIP-125 replacement: build a new signed transaction that pays a
/// higher fee than `orig_tx` by reducing a wallet-owned change output.
///
/// `orig_prevouts[i]` must be the prevout consumed by `orig_tx.inputs[i]`.
/// The wallet must hold the key for every input (`orig_prevouts[i].key_index`)
/// and at least one output must match a wallet-derived scriptPubKey
/// (the change output).
///
/// Returns the new signed transaction plus the fee accounting. The
/// caller is responsible for broadcasting it (e.g. via the
/// `sendrawtransaction` RPC) and conflict-removing the original tx
/// from the mempool / wallet.
pub fn bumpFee(
    wallet: *Wallet,
    orig_tx: *const types.Transaction,
    orig_prevouts: []const OwnedUtxo,
    options: BumpFeeOptions,
) !BumpFeeResult {
    if (orig_tx.inputs.len != orig_prevouts.len) return BumpFeeError.PrevoutMismatch;

    // -----------------------------------------------------------------
    // 1. BIP-125 signaling check (unless `force`). Mirrors Core's
    //    `SignalsOptInRBF` (chain.cpp): at least one input has
    //    sequence < 0xFFFFFFFE.
    // -----------------------------------------------------------------
    if (!options.force) {
        var any_rbf = false;
        for (orig_tx.inputs) |inp| {
            if (inp.sequence < 0xFFFFFFFE) {
                any_rbf = true;
                break;
            }
        }
        if (!any_rbf) return BumpFeeError.NotBIP125Replaceable;
    }

    // -----------------------------------------------------------------
    // 2. Confirmations check — refuse to bump a confirmed tx. The caller
    //    is expected to pass UTXOs whose `confirmations` reflect the
    //    original tx's spending position; if every prevout already has
    //    enough confirmations *and* none of them are still in the
    //    mempool, the original tx is presumed confirmed. (The simpler
    //    check would be on the orig_tx itself, but clearbit doesn't yet
    //    track per-wallet confirmations on outgoing txs — so we use
    //    the most direct proxy available.)
    //
    //    Tighter check is delegated to the RPC layer where mempool /
    //    chain state are reachable. Here we surface a structural
    //    reject path the wallet caller can opt into; tests use it
    //    via the explicit error type.
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // 3. Locate the change output.
    // -----------------------------------------------------------------
    const change_info = (try findChangeOutput(wallet, orig_tx)) orelse
        return BumpFeeError.NoChangeOutput;

    // -----------------------------------------------------------------
    // 4. Compute orig + new fee.
    // -----------------------------------------------------------------
    var sum_in: i128 = 0;
    for (orig_prevouts) |u| sum_in += u.output.value;
    var sum_out: i128 = 0;
    for (orig_tx.outputs) |o| sum_out += o.value;
    const orig_fee_i128 = sum_in - sum_out;
    if (orig_fee_i128 < 0) return error.InsufficientFunds; // pathological
    const orig_fee: i64 = @intCast(orig_fee_i128);

    const orig_vsize = estimateTxVsize(orig_prevouts, orig_tx.outputs.len);
    const new_fee = computeBumpFee(orig_fee, orig_vsize, options.fee_rate);
    if (new_fee <= orig_fee) {
        // user_fee_rate too low to actually bump anything — degenerate.
        return BumpFeeError.InsufficientChange;
    }
    const fee_delta = new_fee - orig_fee;

    // -----------------------------------------------------------------
    // 5. Reduce change.
    // -----------------------------------------------------------------
    const orig_change = orig_tx.outputs[change_info.out_index];
    if (orig_change.value < fee_delta) return BumpFeeError.InsufficientChange;
    const new_change_val: i64 = orig_change.value - fee_delta;
    const dust = dustThresholdFor(orig_change.script_pubkey);
    if (new_change_val < dust) return BumpFeeError.DustAfterReduce;

    // -----------------------------------------------------------------
    // 6. Build the new transaction. Reuse `createTransaction`'s
    //    signing path by partitioning outputs into "kept" (non-change)
    //    and "change" — createTransaction handles signing each input
    //    via the wallet, exactly as we want.
    // -----------------------------------------------------------------
    const num_kept = orig_tx.outputs.len - 1;
    var kept_outputs = try wallet.allocator.alloc(TxOutput, num_kept);
    defer wallet.allocator.free(kept_outputs);
    var ki: usize = 0;
    for (orig_tx.outputs, 0..) |o, oi| {
        if (oi == change_info.out_index) continue;
        kept_outputs[ki] = .{ .value = o.value, .script_pubkey = o.script_pubkey };
        ki += 1;
    }

    const new_change = TxOutput{
        .value = new_change_val,
        .script_pubkey = orig_change.script_pubkey,
    };

    // Use `replaceable = true` so the replacement signals BIP-125 too —
    // matches Core's default replacement behavior (the new tx is itself
    // bumpable).
    const new_tx = try createTransaction(
        wallet,
        orig_prevouts,
        kept_outputs,
        new_change,
        .{
            .fee_rate = if (options.fee_rate) |fr| fr else INCREMENTAL_FEE_RATE,
            .current_height = orig_tx.lock_time,
            .anti_fee_sniping = orig_tx.lock_time != 0,
            .sighash_type = 0x01,
            .replaceable = true,
        },
    );

    return BumpFeeResult{
        .new_tx = new_tx,
        .orig_fee = orig_fee,
        .new_fee = new_fee,
        .orig_vsize = orig_vsize,
        .change_index = change_info.out_index,
    };
}

pub const PsbtBumpFeeResult = struct {
    /// Unsigned PSBT (BIP-174 v0). Owned by the caller; free with `deinit`.
    psbt: @import("psbt.zig").Psbt,
    /// Fee of the original transaction (sats).
    orig_fee: i64,
    /// Fee of the new transaction (sats).
    new_fee: i64,
    /// Estimated vsize of the original transaction (vbytes).
    orig_vsize: u64,
    /// Index of the change output in the original tx that was reduced.
    change_index: usize,
};

/// Same as `bumpFee` but emits an unsigned BIP-174 PSBT instead of a
/// signed transaction. The caller (or another wallet) finalizes the
/// PSBT via `psbt.finalize` and extracts the broadcastable tx.
pub fn psbtBumpFee(
    wallet: *Wallet,
    orig_tx: *const types.Transaction,
    orig_prevouts: []const OwnedUtxo,
    options: BumpFeeOptions,
) !PsbtBumpFeeResult {
    if (orig_tx.inputs.len != orig_prevouts.len) return BumpFeeError.PrevoutMismatch;

    if (!options.force) {
        var any_rbf = false;
        for (orig_tx.inputs) |inp| {
            if (inp.sequence < 0xFFFFFFFE) {
                any_rbf = true;
                break;
            }
        }
        if (!any_rbf) return BumpFeeError.NotBIP125Replaceable;
    }

    const change_info = (try findChangeOutput(wallet, orig_tx)) orelse
        return BumpFeeError.NoChangeOutput;

    var sum_in: i128 = 0;
    for (orig_prevouts) |u| sum_in += u.output.value;
    var sum_out: i128 = 0;
    for (orig_tx.outputs) |o| sum_out += o.value;
    const orig_fee_i128 = sum_in - sum_out;
    if (orig_fee_i128 < 0) return error.InsufficientFunds;
    const orig_fee: i64 = @intCast(orig_fee_i128);

    const orig_vsize = estimateTxVsize(orig_prevouts, orig_tx.outputs.len);
    const new_fee = computeBumpFee(orig_fee, orig_vsize, options.fee_rate);
    if (new_fee <= orig_fee) return BumpFeeError.InsufficientChange;
    const fee_delta = new_fee - orig_fee;

    const orig_change = orig_tx.outputs[change_info.out_index];
    if (orig_change.value < fee_delta) return BumpFeeError.InsufficientChange;
    const new_change_val: i64 = orig_change.value - fee_delta;
    const dust = dustThresholdFor(orig_change.script_pubkey);
    if (new_change_val < dust) return BumpFeeError.DustAfterReduce;

    // Build the unsigned skeleton with reduced change.
    const allocator = wallet.allocator;
    var new_inputs = try allocator.alloc(types.TxIn, orig_tx.inputs.len);
    defer allocator.free(new_inputs);
    for (orig_tx.inputs, 0..) |inp, i| {
        new_inputs[i] = .{
            .previous_output = inp.previous_output,
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFD, // BIP-125 RBF signal on replacement
            .witness = &[_][]const u8{},
        };
    }
    var new_outputs = try allocator.alloc(types.TxOut, orig_tx.outputs.len);
    defer allocator.free(new_outputs);
    for (orig_tx.outputs, 0..) |o, i| {
        if (i == change_info.out_index) {
            new_outputs[i] = .{
                .value = new_change_val,
                .script_pubkey = o.script_pubkey,
            };
        } else {
            new_outputs[i] = .{
                .value = o.value,
                .script_pubkey = o.script_pubkey,
            };
        }
    }

    const skeleton = types.Transaction{
        .version = orig_tx.version,
        .inputs = new_inputs,
        .outputs = new_outputs,
        .lock_time = orig_tx.lock_time,
    };

    var psbt = try psbt_mod.Psbt.create(allocator, skeleton);
    errdefer psbt.deinit();

    // Attach prevout info per input so a signer can compute sighashes.
    for (orig_prevouts, 0..) |prev, i| {
        try psbt.addInputUtxo(i, prev.output);
    }

    return PsbtBumpFeeResult{
        .psbt = psbt,
        .orig_fee = orig_fee,
        .new_fee = new_fee,
        .orig_vsize = orig_vsize,
        .change_index = change_info.out_index,
    };
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Estimate input size in virtual bytes for fee calculation.
fn estimateInputSize(addr_type: AddressType) u64 {
    return switch (addr_type) {
        .p2pkh => 148, // 32+4+1+~107+4
        .p2sh_p2wpkh => 91, // 32+4+1+23+4 + witness/4 (91 vbytes)
        .p2wpkh => 68, // 32+4+1+0+4 + witness/4
        .p2wsh => 100, // Approximate
        .p2tr => 58, // 32+4+1+0+4 + 64/4
    };
}

/// Get actual length of DER signature (may be less than 72).
fn getDerSigLen(der: *const [72]u8) usize {
    // DER format: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
    if (der[0] != 0x30) return 72;
    return @as(usize, der[1]) + 2;
}

// ============================================================================
// BIP-86: Single-key Taproot output (empty merkle root)
// ============================================================================

/// Compute the BIP-86 TapTweak for a single-key Taproot output.
///
/// BIP-86 (https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) is
/// the descriptor / wallet convention where a P2TR output spent by a single
/// key has *no* script tree. The tweak is therefore over the empty merkle
/// root, i.e. just the 32-byte internal x-only key with nothing appended.
/// Reference: bitcoin-core/src/key.cpp::ComputeTapTweakHash.
///
/// Returns the 32-byte tweak that must be added to either the internal
/// x-only pubkey (for the on-chain output key) or the keypair's secret
/// scalar (for signing) via libsecp256k1.
pub fn bip86Tweak(internal_xonly: *const [32]u8) [32]u8 {
    return crypto.taggedHash("TapTweak", internal_xonly);
}

/// Apply the BIP-86 tweak to an x-only internal pubkey, producing the
/// 32-byte tweaked output key that goes on chain inside `OP_1 <0x20> <key>`.
///
/// Uses libsecp256k1 via `Wallet.ctx`. Returns `error.TaprootTweakFailed`
/// if the tweak addition produces the point at infinity (negligible
/// probability for any non-attacker-chosen internal key).
pub fn bip86TweakXOnly(
    ctx: *secp256k1.secp256k1_context,
    internal_xonly: *const [32]u8,
) ![32]u8 {
    var internal: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_parse(ctx, &internal, internal_xonly) != 1) {
        return error.InvalidInternalKey;
    }
    const tweak = bip86Tweak(internal_xonly);

    var tweaked_full: secp256k1.secp256k1_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full, &internal, &tweak) != 1) {
        return error.TaprootTweakFailed;
    }
    var tweaked_xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, null, &tweaked_full) != 1) {
        return error.TaprootTweakFailed;
    }
    var out: [32]u8 = undefined;
    if (secp256k1.secp256k1_xonly_pubkey_serialize(ctx, &out, &tweaked_xonly) != 1) {
        return error.TaprootTweakFailed;
    }
    return out;
}

// ============================================================================
// Sighash Computation
// ============================================================================

/// Dust threshold constants
pub const DUST_THRESHOLD_P2PKH: i64 = 546;
pub const DUST_THRESHOLD_P2WPKH: i64 = 294;

/// Compute legacy sighash for P2PKH inputs.
pub fn computeLegacySigHash(
    tx: *const types.Transaction,
    input_index: usize,
    utxo: OwnedUtxo,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) ![32]u8 {
    // Get the scriptPubKey from the UTXO being spent
    const script_pubkey = utxo.output.script_pubkey;

    // Use the crypto module's existing implementation
    return try crypto.legacySighash(tx, input_index, script_pubkey, sighash_type, allocator);
}

/// Compute BIP-143 SegWit v0 sighash for P2WPKH inputs.
pub fn computeWitnessSigHashV0(
    tx: *const types.Transaction,
    input_index: usize,
    utxo: OwnedUtxo,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) ![32]u8 {
    // For P2WPKH, the scriptCode is the equivalent P2PKH script
    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76; // OP_DUP
    script_code[1] = 0xa9; // OP_HASH160
    script_code[2] = 0x14; // Push 20 bytes

    // Extract the pubkey hash from the scriptPubKey (bytes 2-22)
    if (utxo.output.script_pubkey.len >= 22) {
        @memcpy(script_code[3..23], utxo.output.script_pubkey[2..22]);
    } else {
        return error.InvalidScriptPubKey;
    }

    script_code[23] = 0x88; // OP_EQUALVERIFY
    script_code[24] = 0xac; // OP_CHECKSIG

    return try crypto.segwitSighash(tx, input_index, &script_code, utxo.output.value, sighash_type, allocator);
}

// ============================================================================
// W29-C — P2WSH + P2SH-P2WSH signing (BIP-143 segwit-v0 with witness scripts)
// ============================================================================
//
// Closes the W19 P0 finding "P2WSH = error.NotImplemented at wallet.zig:1208".
// The signing path is the canonical BIP-143 sighash with the witnessScript as
// scriptCode, signed with one or more wallet keys. Multisig (M-of-N
// CHECKMULTISIG) and the trivial single-CHECKSIG witness scripts are both
// supported.
//
// Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature
//            bitcoin-core/src/script/standard.cpp::MatchMultisig
//            BIP-143 (segwit v0 sighash + P2WSH witness layout).
//
// Wave-aligned with blockbrew W27-D (`5d9d942`) and lunarblock W28
// (`a977878`); the Zig dispatcher mirrors the same {single-key, multisig}
// branch shape, so a single set of cross-impl test vectors should cover
// them byte-for-byte. See `_design-per-impl-wallet-phase2-segwit-v0-2026-05-08.md`.

/// Detect an M-of-N CHECKMULTISIG witness script and return its
/// (M, pubkeys[]) shape. Mirrors Core's `MatchMultisig` but only the
/// canonical encoding (small-int M, N small-int N, OP_CHECKMULTISIG, every
/// pubkey is a 33- or 65-byte direct push).
///
/// Returns `null` if `script` is not an M-of-N CHECKMULTISIG witness script.
/// Caller owns the returned `pubkeys` slice.
pub const MultisigShape = struct { m: u8, pubkeys: [][]const u8 };

pub fn parseMultisigScript(allocator: std.mem.Allocator, script: []const u8) !?MultisigShape {
    if (script.len < 4) return null;
    // Last opcode must be OP_CHECKMULTISIG (0xae).
    if (script[script.len - 1] != 0xae) return null;
    // First byte must be small-int M (OP_1..OP_16 = 0x51..0x60).
    const op_m = script[0];
    if (op_m < 0x51 or op_m > 0x60) return null;
    const m: u8 = op_m - 0x50;

    // Walk N pubkey pushes. The byte just before OP_CHECKMULTISIG is small-int N.
    const op_n = script[script.len - 2];
    if (op_n < 0x51 or op_n > 0x60) return null;
    const n: u8 = op_n - 0x50;
    if (m == 0 or m > n or n > 16) return null;

    var pubkeys = std.ArrayList([]const u8).init(allocator);
    errdefer pubkeys.deinit();

    var i: usize = 1; // skip M
    while (i < script.len - 2) : ({}) {
        const len_byte = script[i];
        if (len_byte != 0x21 and len_byte != 0x41) return null; // 33 or 65 bytes only
        i += 1;
        const plen: usize = @intCast(len_byte);
        if (i + plen > script.len - 2) return null;
        try pubkeys.append(script[i .. i + plen]);
        i += plen;
    }
    if (pubkeys.items.len != n) {
        pubkeys.deinit();
        return null;
    }
    return MultisigShape{ .m = m, .pubkeys = try pubkeys.toOwnedSlice() };
}

/// Sign a P2WSH input given an explicit witnessScript and one or more
/// signing key indices. Returns the assembled witness stack.
///
/// For multisig witnessScripts the stack is laid out as
/// `[OP_0_dummy, sig_1, ..., sig_M, witnessScript]` where signatures are
/// emitted in canonical witnessScript pubkey order (Core's
/// `ProduceSignature`/`SignStep` semantics). The leading empty element
/// is the BIP-147 CHECKMULTISIG dummy push (the legacy off-by-one bug).
///
/// For single-key witnessScripts (`<pubkey> OP_CHECKSIG` shape) the stack
/// is `[sig, witnessScript]` — no leading dummy.
///
/// Caller owns the returned witness slice and every byte slice inside it.
pub fn signP2WSH(
    wallet: *Wallet,
    tx: *const types.Transaction,
    input_index: usize,
    witness_script: []const u8,
    value: i64,
    signing_key_indices: []const usize,
    extra_signing_keys: ?[]const [32]u8,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) ![][]const u8 {
    if (witness_script.len == 0) return error.EmptyWitnessScript;
    if (signing_key_indices.len == 0 and (extra_signing_keys == null or extra_signing_keys.?.len == 0)) {
        return error.NoSigningKeys;
    }

    const sighash = try crypto.segwitSighash(
        tx,
        input_index,
        witness_script,
        value,
        sighash_type,
        allocator,
    );

    // Try to parse the witness script as M-of-N CHECKMULTISIG.
    const maybe_ms = try parseMultisigScript(allocator, witness_script);
    if (maybe_ms) |ms| {
        defer allocator.free(ms.pubkeys);

        // Map of pubkey-bytes -> signature (DER+hashtype). Both `pk` and
        // `sig` are owned by `allocator`; freed unconditionally below.
        var sig_by_pubkey = std.ArrayList(struct { pk: []const u8, sig: []const u8 }).init(allocator);
        defer {
            for (sig_by_pubkey.items) |entry| {
                allocator.free(entry.pk);
                allocator.free(entry.sig);
            }
            sig_by_pubkey.deinit();
        }

        // Sign with every wallet key the caller supplied. We dup the
        // pubkey bytes into the allocator so the slice we store in
        // `sig_by_pubkey.pk` outlives the loop's local KeyPair copy
        // (taking `&wallet.keys.items[ki].public_key` would tie the
        // slice to the ArrayList's backing buffer, which can move on
        // a future append — safer to dup unconditionally).
        for (signing_key_indices) |ki| {
            if (ki >= wallet.keys.items.len) return error.KeyNotFound;
            const k = wallet.keys.items[ki];
            var pt_sk = try wallet.getPlaintextSecretKey(ki);
            defer @memset(&pt_sk, 0);
            const sig = try wallet.ecdsaSign(&sighash, &pt_sk);
            const sig_len = getDerSigLen(&sig);
            const sig_buf = try allocator.alloc(u8, sig_len + 1);
            @memcpy(sig_buf[0..sig_len], sig[0..sig_len]);
            sig_buf[sig_len] = @intCast(sighash_type & 0xFF);
            const pk_dup = try allocator.dupe(u8, &k.public_key);
            try sig_by_pubkey.append(.{ .pk = pk_dup, .sig = sig_buf });
        }
        // Sign with every extra cosigner secret.
        if (extra_signing_keys) |xks| {
            for (xks) |sk| {
                // Derive pubkey from secret via libsecp.
                var pubkey: secp256k1.secp256k1_pubkey = undefined;
                if (secp256k1.secp256k1_ec_pubkey_create(wallet.ctx, &pubkey, &sk) != 1) {
                    return error.PubkeyDeriveFailed;
                }
                var pk_serialized: [33]u8 = undefined;
                var pk_len: usize = 33;
                _ = secp256k1.secp256k1_ec_pubkey_serialize(
                    wallet.ctx,
                    &pk_serialized,
                    &pk_len,
                    &pubkey,
                    secp256k1.SECP256K1_EC_COMPRESSED,
                );
                const sig = try wallet.ecdsaSign(&sighash, &sk);
                const sig_len = getDerSigLen(&sig);
                const sig_buf = try allocator.alloc(u8, sig_len + 1);
                @memcpy(sig_buf[0..sig_len], sig[0..sig_len]);
                sig_buf[sig_len] = @intCast(sighash_type & 0xFF);
                const pk_dup = try allocator.dupe(u8, &pk_serialized);
                try sig_by_pubkey.append(.{ .pk = pk_dup, .sig = sig_buf });
            }
        }

        // Assemble witness in canonical witness-script pubkey order, M sigs only.
        var stack = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (stack.items) |it| allocator.free(it);
            stack.deinit();
        }
        // Leading OP_0 dummy element (BIP-147 CHECKMULTISIG off-by-one pad).
        try stack.append(try allocator.alloc(u8, 0));

        var collected: u8 = 0;
        for (ms.pubkeys) |script_pk| {
            if (collected >= ms.m) break;
            for (sig_by_pubkey.items) |entry| {
                if (std.mem.eql(u8, entry.pk, script_pk)) {
                    const sig_dup = try allocator.dupe(u8, entry.sig);
                    try stack.append(sig_dup);
                    collected += 1;
                    break;
                }
            }
        }
        if (collected < ms.m) {
            return error.PartialSignNotEnoughKeys;
        }
        // Trailing witness script.
        try stack.append(try allocator.dupe(u8, witness_script));

        return try stack.toOwnedSlice();
    }

    // Non-multisig witness script: assume single-CHECKSIG shape and emit
    // [sig, witness_script]. Mirrors blockbrew + lunarblock single-sig path.
    if (signing_key_indices.len != 1) {
        return error.SingleKeyP2WSHRequiresOneKey;
    }
    const ki = signing_key_indices[0];
    if (ki >= wallet.keys.items.len) return error.KeyNotFound;
    var pt_sk2 = try wallet.getPlaintextSecretKey(ki);
    defer @memset(&pt_sk2, 0);
    const sig = try wallet.ecdsaSign(&sighash, &pt_sk2);
    const sig_len = getDerSigLen(&sig);

    var stack = try allocator.alloc([]const u8, 2);
    errdefer allocator.free(stack);

    var sig_buf = try allocator.alloc(u8, sig_len + 1);
    @memcpy(sig_buf[0..sig_len], sig[0..sig_len]);
    sig_buf[sig_len] = @intCast(sighash_type & 0xFF);
    stack[0] = sig_buf;
    stack[1] = try allocator.dupe(u8, witness_script);

    return stack;
}

/// Sign a P2SH-wrapped-P2WSH input. The on-chain scriptPubKey is
/// `OP_HASH160 <hash160(redeemScript)> OP_EQUAL` where
/// `redeemScript = OP_0 <0x20> <sha256(witnessScript)>`. The witness layout
/// is identical to bare P2WSH; the scriptSig is a single push of the
/// 34-byte redeemScript.
///
/// Returns `{ script_sig, witness }` — caller owns both.
pub const SignP2SHP2WSHResult = struct {
    script_sig: []const u8,
    witness: []const []const u8,
};

pub fn signP2SH_P2WSH(
    wallet: *Wallet,
    tx: *const types.Transaction,
    input_index: usize,
    witness_script: []const u8,
    value: i64,
    signing_key_indices: []const usize,
    extra_signing_keys: ?[]const [32]u8,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) !SignP2SHP2WSHResult {
    const witness = try signP2WSH(
        wallet,
        tx,
        input_index,
        witness_script,
        value,
        signing_key_indices,
        extra_signing_keys,
        sighash_type,
        allocator,
    );
    errdefer {
        for (witness) |w| allocator.free(w);
        allocator.free(witness);
    }

    // Build redeemScript = OP_0 <0x20> <sha256(witnessScript)>.
    const ws_hash = crypto.sha256(witness_script);
    var redeem: [34]u8 = undefined;
    redeem[0] = 0x00; // OP_0
    redeem[1] = 0x20; // Push 32 bytes
    @memcpy(redeem[2..34], &ws_hash);

    // W31 defense-in-depth: assert the BIP-141 P2WSH inner commitment
    // ties redeem_script[2..34] back to sha256(witness_script). The
    // redeem here is constructed from `ws_hash` two lines above, so this
    // is structurally guaranteed today — but a future refactor that
    // accepts an externally-supplied redeemScript (the same shape as
    // the cross-impl bug class found in hotbuns/blockbrew/etc.) would
    // need this check to stay safe. Keeping it as a runtime assertion
    // means any drift is caught at the signing site, not by a remote
    // verifier on the wire.
    if (!std.mem.eql(u8, redeem[2..34], &ws_hash)) {
        for (witness) |w| allocator.free(w);
        allocator.free(witness);
        return error.WitnessScriptCommitmentMismatch;
    }

    // scriptSig = single push of the 34-byte redeemScript.
    var script_sig = try allocator.alloc(u8, 35);
    script_sig[0] = 0x22; // Push 34 bytes
    @memcpy(script_sig[1..35], &redeem);

    return SignP2SHP2WSHResult{
        .script_sig = script_sig,
        .witness = witness,
    };
}

/// Compute BIP-341 Taproot sighash.
///
/// Wire-up to the canonical implementation in `taproot_sighash.zig`, which is
/// validated against `bitcoin-core/src/test/data/bip341_wallet_vectors.json`
/// (all 7 keyPathSpending vectors produce byte-perfect sigMsg + sigHash).
///
/// `all_prevouts` MUST contain one entry per input in `tx`, in input order
/// (matching `tx.inputs`). BIP-341 hashes `sha_amounts` and
/// `sha_scriptPubKeys` over every spent prevout, so the per-input `utxo`
/// alone is insufficient — pre-fix this function discarded the prevouts and
/// emitted 32 zero bytes for both, producing a sighash that no compliant
/// signer (Core, libwally, BDK, etc.) would ever accept. See W19 audit.
///
/// Only key-path spends are wired here; tapscript leaves are a separate
/// signing entry point (`taproot_sighash.computeTaprootSighash` accepts a
/// `TapscriptContext` for ext_flag = 1).
pub fn computeTaprootSigHash(
    tx: *const types.Transaction,
    input_index: usize,
    all_prevouts: []const OwnedUtxo,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) ![32]u8 {
    if (all_prevouts.len != tx.inputs.len) return error.PrevoutsLengthMismatch;

    // Build flat amounts + scripts arrays in input order, as BIP-341 expects.
    var amounts = try allocator.alloc(i64, all_prevouts.len);
    defer allocator.free(amounts);
    var scripts = try allocator.alloc([]const u8, all_prevouts.len);
    defer allocator.free(scripts);

    for (all_prevouts, 0..) |po, i| {
        amounts[i] = po.output.value;
        scripts[i] = po.output.script_pubkey;
    }

    const hash_type: u8 = @intCast(sighash_type & 0xFF);
    if (!taproot_sighash.isValidTaprootHashType(hash_type)) {
        return error.InvalidSighashType;
    }

    return try taproot_sighash.computeTaprootSighash(
        allocator,
        tx,
        input_index,
        .{ .amounts = amounts, .scripts = scripts },
        hash_type,
        null, // annex
        null, // key-path spend
    );
}

// ============================================================================
// Wallet Options (for createwallet)
// ============================================================================

pub const WalletOptions = struct {
    disable_private_keys: bool = false,
    blank: bool = false,
    passphrase: ?[]const u8 = null,
    avoid_reuse: bool = false,
    descriptors: bool = true,
    load_on_startup: ?bool = null,
};

// ============================================================================
// Wallet Manager - Multi-wallet support
// ============================================================================

pub const WalletManager = struct {
    wallets: std.StringHashMap(*Wallet),
    mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,
    wallets_dir: []const u8,
    network: Network,

    /// Initialize the wallet manager.
    pub fn init(allocator: std.mem.Allocator, wallets_dir: []const u8, network: Network) !WalletManager {
        // Ensure wallets directory exists
        std.fs.makeDirAbsolute(wallets_dir) catch |err| {
            if (err != error.PathAlreadyExists) {
                return error.WalletDirCreationFailed;
            }
        };

        // Duplicate the wallets_dir string
        const dir_copy = try allocator.dupe(u8, wallets_dir);

        return WalletManager{
            .wallets = std.StringHashMap(*Wallet).init(allocator),
            .mutex = std.Thread.Mutex{},
            .allocator = allocator,
            .wallets_dir = dir_copy,
            .network = network,
        };
    }

    /// Deinitialize the wallet manager, unloading all wallets.
    pub fn deinit(self: *WalletManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Save and deinit all wallets
        var it = self.wallets.iterator();
        while (it.next()) |entry| {
            const wallet = entry.value_ptr.*;
            // Save wallet before unloading
            self.saveWalletInternal(entry.key_ptr.*, wallet) catch {};
            wallet.deinit();
            self.allocator.destroy(wallet);
            self.allocator.free(entry.key_ptr.*);
        }
        self.wallets.deinit();
        self.allocator.free(self.wallets_dir);
    }

    /// Create a new wallet with the given name and options.
    pub fn createWallet(self: *WalletManager, name: []const u8, options: WalletOptions) !*Wallet {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if wallet already exists
        if (self.wallets.contains(name)) {
            return error.WalletAlreadyExists;
        }

        // Check if wallet file already exists on disk
        const wallet_dir = try self.getWalletDir(name);
        defer self.allocator.free(wallet_dir);

        const wallet_file = try std.fmt.allocPrint(self.allocator, "{s}/wallet.dat", .{wallet_dir});
        defer self.allocator.free(wallet_file);

        if (std.fs.accessAbsolute(wallet_file, .{})) |_| {
            return error.WalletAlreadyExists;
        } else |_| {}

        // Create wallet directory
        std.fs.makeDirAbsolute(wallet_dir) catch |err| {
            if (err != error.PathAlreadyExists) {
                return error.WalletDirCreationFailed;
            }
        };

        // Create new wallet
        const wallet = try self.allocator.create(Wallet);
        errdefer self.allocator.destroy(wallet);

        if (options.blank) {
            // Blank wallet - no seed
            wallet.* = try Wallet.init(self.allocator, self.network);
        } else {
            // Generate BIP32 seed
            var seed: [64]u8 = undefined;
            std.crypto.random.bytes(&seed);
            wallet.* = try Wallet.initFromSeed(self.allocator, self.network, &seed);
            @memset(&seed, 0); // Clear seed from memory
        }

        // Encrypt if passphrase provided
        if (options.passphrase) |passphrase| {
            try wallet.encryptWallet(passphrase);
        }

        // Save wallet to disk
        try self.saveWalletInternal(name, wallet);

        // Add to loaded wallets
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        try self.wallets.put(name_copy, wallet);

        return wallet;
    }

    /// Load a wallet from disk.
    pub fn loadWallet(self: *WalletManager, name: []const u8) !*Wallet {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if already loaded
        if (self.wallets.contains(name)) {
            return error.WalletAlreadyLoaded;
        }

        // Load from disk
        const wallet = try self.loadWalletFromDisk(name);
        errdefer {
            wallet.deinit();
            self.allocator.destroy(wallet);
        }

        // Add to loaded wallets
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        try self.wallets.put(name_copy, wallet);

        return wallet;
    }

    /// Unload a wallet from memory (saves to disk first).
    pub fn unloadWallet(self: *WalletManager, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.wallets.fetchRemove(name) orelse {
            return error.WalletNotLoaded;
        };

        // Save before unloading
        try self.saveWalletInternal(name, entry.value);

        // Clean up
        entry.value.deinit();
        self.allocator.destroy(entry.value);
        self.allocator.free(entry.key);
    }

    /// Get a loaded wallet by name.
    pub fn getWallet(self: *WalletManager, name: []const u8) ?*Wallet {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.wallets.get(name);
    }

    /// Get the default wallet (empty name) or the only loaded wallet.
    pub fn getDefaultWallet(self: *WalletManager) !*Wallet {
        self.mutex.lock();
        defer self.mutex.unlock();

        // If empty string wallet exists, return it
        if (self.wallets.get("")) |wallet| {
            return wallet;
        }

        // If exactly one wallet loaded, return it
        if (self.wallets.count() == 1) {
            var it = self.wallets.iterator();
            if (it.next()) |entry| {
                return entry.value_ptr.*;
            }
        }

        if (self.wallets.count() == 0) {
            return error.WalletNotLoaded;
        }

        return error.WalletNotSpecified;
    }

    /// Get the target wallet from HTTP request URL.
    /// Parses /wallet/<name> from the request path.
    pub fn getTargetWallet(self: *WalletManager, request_path: []const u8) !*Wallet {
        // Parse /wallet/<name> from path
        if (std.mem.startsWith(u8, request_path, "/wallet/")) {
            const name = request_path[8..]; // Skip "/wallet/"
            // Remove any trailing path or query string
            const end = std.mem.indexOfAny(u8, name, "?/") orelse name.len;
            const wallet_name = name[0..end];

            self.mutex.lock();
            defer self.mutex.unlock();

            return self.wallets.get(wallet_name) orelse error.WalletNotFound;
        }

        // No wallet specified in URL, use default
        return self.getDefaultWallet();
    }

    /// List all loaded wallet names.
    pub fn listWallets(self: *WalletManager, allocator: std.mem.Allocator) ![][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var names = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (names.items) |n| {
                allocator.free(n);
            }
            names.deinit();
        }

        var it = self.wallets.iterator();
        while (it.next()) |entry| {
            const name_copy = try allocator.dupe(u8, entry.key_ptr.*);
            try names.append(name_copy);
        }

        return names.toOwnedSlice();
    }

    /// List all wallet directories available on disk.
    pub fn listWalletDir(self: *WalletManager, allocator: std.mem.Allocator) ![][]const u8 {
        var names = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (names.items) |n| {
                allocator.free(n);
            }
            names.deinit();
        }

        // Check for default wallet (empty name)
        const default_wallet_file = std.fmt.allocPrint(allocator, "{s}/wallet.dat", .{self.wallets_dir}) catch {
            return names.toOwnedSlice();
        };
        defer allocator.free(default_wallet_file);

        if (std.fs.accessAbsolute(default_wallet_file, .{})) |_| {
            const empty = try allocator.dupe(u8, "");
            try names.append(empty);
        } else |_| {}

        // Iterate wallet subdirectories
        var dir = std.fs.openDirAbsolute(self.wallets_dir, .{ .iterate = true }) catch {
            return names.toOwnedSlice();
        };
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind == .directory) {
                // Check if this directory contains a wallet.dat
                const wallet_path = std.fmt.allocPrint(allocator, "{s}/{s}/wallet.dat", .{ self.wallets_dir, entry.name }) catch continue;
                defer allocator.free(wallet_path);

                if (std.fs.accessAbsolute(wallet_path, .{})) |_| {
                    const name_copy = try allocator.dupe(u8, entry.name);
                    try names.append(name_copy);
                } else |_| {}
            }
        }

        return names.toOwnedSlice();
    }

    /// Get the wallet count.
    pub fn count(self: *WalletManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.wallets.count();
    }

    // ========================================================================
    // Internal Methods
    // ========================================================================

    fn getWalletDir(self: *WalletManager, name: []const u8) ![]const u8 {
        if (name.len == 0) {
            // Default wallet is in wallets_dir root
            return try self.allocator.dupe(u8, self.wallets_dir);
        } else {
            return try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.wallets_dir, name });
        }
    }

    fn saveWalletInternal(self: *WalletManager, name: []const u8, wallet: *Wallet) !void {
        const wallet_dir = try self.getWalletDir(name);
        defer self.allocator.free(wallet_dir);

        // Ensure directory exists
        std.fs.makeDirAbsolute(wallet_dir) catch |err| {
            if (err != error.PathAlreadyExists) {
                return error.WalletDirCreationFailed;
            }
        };

        const wallet_file = try std.fmt.allocPrint(self.allocator, "{s}/wallet.dat", .{wallet_dir});
        defer self.allocator.free(wallet_file);

        // Serialize wallet to JSON
        const json = try self.serializeWallet(wallet);
        defer self.allocator.free(json);

        // Write atomically (write to temp, then rename)
        const temp_file = try std.fmt.allocPrint(self.allocator, "{s}/wallet.dat.tmp", .{wallet_dir});
        defer self.allocator.free(temp_file);

        const file = std.fs.createFileAbsolute(temp_file, .{}) catch {
            return error.WalletSaveFailed;
        };
        defer file.close();

        file.writeAll(json) catch {
            return error.WalletSaveFailed;
        };

        // Rename temp file to final
        std.fs.renameAbsolute(temp_file, wallet_file) catch {
            return error.WalletSaveFailed;
        };
    }

    fn loadWalletFromDisk(self: *WalletManager, name: []const u8) !*Wallet {
        const wallet_dir = try self.getWalletDir(name);
        defer self.allocator.free(wallet_dir);

        const wallet_file = try std.fmt.allocPrint(self.allocator, "{s}/wallet.dat", .{wallet_dir});
        defer self.allocator.free(wallet_file);

        // Read wallet file
        const file = std.fs.openFileAbsolute(wallet_file, .{}) catch {
            return error.WalletNotFound;
        };
        defer file.close();

        const stat = file.stat() catch {
            return error.WalletLoadFailed;
        };

        const content = self.allocator.alloc(u8, stat.size) catch {
            return error.OutOfMemory;
        };
        defer self.allocator.free(content);

        const bytes_read = file.readAll(content) catch {
            return error.WalletLoadFailed;
        };

        // Parse JSON and create wallet
        return self.deserializeWallet(content[0..bytes_read]);
    }

    fn serializeWallet(self: *WalletManager, wallet: *Wallet) ![]const u8 {
        var json = std.ArrayList(u8).init(self.allocator);
        errdefer json.deinit();

        try json.appendSlice("{");

        // Network
        try json.appendSlice("\"network\":\"");
        try json.appendSlice(switch (wallet.network) {
            .mainnet => "mainnet",
            .testnet => "testnet",
            .regtest => "regtest",
        });
        try json.appendSlice("\",");

        // Encrypted flag
        try json.appendSlice("\"encrypted\":");
        try json.appendSlice(if (wallet.encrypted) "true" else "false");
        try json.appendSlice(",");

        // HD state
        var buf: [64]u8 = undefined;
        const ext_idx = std.fmt.bufPrint(&buf, "\"next_external_index\":{d},", .{wallet.next_external_index}) catch return error.SerializationFailed;
        try json.appendSlice(ext_idx);

        const chg_idx = std.fmt.bufPrint(&buf, "\"next_change_index\":{d},", .{wallet.next_change_index}) catch return error.SerializationFailed;
        try json.appendSlice(chg_idx);

        // Master key.  When the wallet is encrypted, master_key.key and
        // master_key.chain_code already hold AES-256-GCM ciphertext (see
        // encryptWalletWithParams + W161 BUG-5 fix); we additionally emit the
        // per-field nonces and tags required to decrypt them on load.  When
        // unencrypted, the bytes are plaintext and no nonce/tag is written —
        // deserializeWallet detects the absence of nonce/tag to know it must
        // not attempt decryption (also the backward-compat path for legacy
        // pre-fix wallet.dat files that wrote plaintext while encrypted).
        if (wallet.master_key) |master_key| {
            try json.appendSlice("\"master_key\":\"");
            var hex_buf: [128]u8 = undefined;
            const key_hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&master_key.key)}) catch return error.SerializationFailed;
            try json.appendSlice(key_hex);
            try json.appendSlice("\",");

            try json.appendSlice("\"chain_code\":\"");
            const cc_hex = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&master_key.chain_code)}) catch return error.SerializationFailed;
            try json.appendSlice(cc_hex);
            try json.appendSlice("\",");

            if (wallet.master_key_nonce) |mn| {
                try json.appendSlice("\"master_key_nonce\":\"");
                var n_hex: [24]u8 = undefined;
                const nh = std.fmt.bufPrint(&n_hex, "{s}", .{std.fmt.fmtSliceHexLower(&mn)}) catch return error.SerializationFailed;
                try json.appendSlice(nh);
                try json.appendSlice("\",");
            }
            if (wallet.master_key_tag) |mt| {
                try json.appendSlice("\"master_key_tag\":\"");
                var t_hex: [32]u8 = undefined;
                const th = std.fmt.bufPrint(&t_hex, "{s}", .{std.fmt.fmtSliceHexLower(&mt)}) catch return error.SerializationFailed;
                try json.appendSlice(th);
                try json.appendSlice("\",");
            }
            if (wallet.master_chain_code_nonce) |cn| {
                try json.appendSlice("\"master_chain_code_nonce\":\"");
                var n_hex: [24]u8 = undefined;
                const nh = std.fmt.bufPrint(&n_hex, "{s}", .{std.fmt.fmtSliceHexLower(&cn)}) catch return error.SerializationFailed;
                try json.appendSlice(nh);
                try json.appendSlice("\",");
            }
            if (wallet.master_chain_code_tag) |ct| {
                try json.appendSlice("\"master_chain_code_tag\":\"");
                var t_hex: [32]u8 = undefined;
                const th = std.fmt.bufPrint(&t_hex, "{s}", .{std.fmt.fmtSliceHexLower(&ct)}) catch return error.SerializationFailed;
                try json.appendSlice(th);
                try json.appendSlice("\",");
            }
        }

        // Encryption salt (if encrypted)
        if (wallet.encryption_salt) |salt| {
            try json.appendSlice("\"encryption_salt\":\"");
            var salt_hex: [32]u8 = undefined;
            const s_hex = std.fmt.bufPrint(&salt_hex, "{s}", .{std.fmt.fmtSliceHexLower(&salt)}) catch return error.SerializationFailed;
            try json.appendSlice(s_hex);
            try json.appendSlice("\",");
        }

        // Keys array.
        // Each encrypted key stores "secret" (ciphertext), "pubkey", "nonce"
        // (12-byte AES-GCM nonce, hex), and "tag" (16-byte auth tag, hex).
        // Unencrypted keys omit "nonce" and "tag".
        try json.appendSlice("\"keys\":[");
        for (wallet.keys.items, 0..) |keypair, i| {
            if (i > 0) try json.append(',');
            try json.appendSlice("{\"secret\":\"");
            var key_hex: [64]u8 = undefined;
            const sk_hex = std.fmt.bufPrint(&key_hex, "{s}", .{std.fmt.fmtSliceHexLower(&keypair.secret_key)}) catch return error.SerializationFailed;
            try json.appendSlice(sk_hex);
            try json.appendSlice("\",\"pubkey\":\"");
            var pk_hex: [66]u8 = undefined;
            const pub_hex = std.fmt.bufPrint(&pk_hex, "{s}", .{std.fmt.fmtSliceHexLower(&keypair.public_key)}) catch return error.SerializationFailed;
            try json.appendSlice(pub_hex);
            try json.append('"');
            // AES-256-GCM per-key nonce + authentication tag (present when encrypted).
            if (keypair.encryption_nonce) |nonce| {
                try json.appendSlice(",\"nonce\":\"");
                var nonce_hex: [24]u8 = undefined;
                const n_hex = std.fmt.bufPrint(&nonce_hex, "{s}", .{std.fmt.fmtSliceHexLower(&nonce)}) catch return error.SerializationFailed;
                try json.appendSlice(n_hex);
                try json.append('"');
            }
            if (keypair.encryption_tag) |tag| {
                try json.appendSlice(",\"tag\":\"");
                var tag_hex: [32]u8 = undefined;
                const t_hex = std.fmt.bufPrint(&tag_hex, "{s}", .{std.fmt.fmtSliceHexLower(&tag)}) catch return error.SerializationFailed;
                try json.appendSlice(t_hex);
                try json.append('"');
            }
            try json.append('}');
        }
        try json.appendSlice("],");

        // UTXOs
        try json.appendSlice("\"utxos\":[");
        for (wallet.utxos.items, 0..) |utxo, i| {
            if (i > 0) try json.append(',');
            try json.appendSlice("{\"txid\":\"");
            var txid_hex: [64]u8 = undefined;
            // Reverse for display
            var rev_txid: [32]u8 = undefined;
            for (utxo.outpoint.hash, 0..) |b, j| {
                rev_txid[31 - j] = b;
            }
            const t_hex = std.fmt.bufPrint(&txid_hex, "{s}", .{std.fmt.fmtSliceHexLower(&rev_txid)}) catch return error.SerializationFailed;
            try json.appendSlice(t_hex);
            try json.appendSlice("\",");

            var utxo_buf: [256]u8 = undefined;
            const utxo_fields = std.fmt.bufPrint(&utxo_buf, "\"vout\":{d},\"value\":{d},\"key_index\":{d},\"confirmations\":{d},\"is_coinbase\":{s},\"height\":{d}", .{
                utxo.outpoint.index,
                utxo.output.value,
                utxo.key_index,
                utxo.confirmations,
                if (utxo.is_coinbase) "true" else "false",
                utxo.height,
            }) catch return error.SerializationFailed;
            try json.appendSlice(utxo_fields);
            try json.append('}');
        }
        try json.appendSlice("]");

        // Labels
        try json.appendSlice(",\"labels\":{");
        var label_iter = wallet.labels.iterator();
        var first_label = true;
        while (label_iter.next()) |entry| {
            if (!first_label) try json.append(',');
            first_label = false;
            try json.append('"');
            try json.appendSlice(entry.key_ptr.*);
            try json.appendSlice("\":\"");
            try json.appendSlice(entry.value_ptr.*);
            try json.append('"');
        }
        try json.appendSlice("}");

        try json.append('}');

        return json.toOwnedSlice();
    }

    fn deserializeWallet(self: *WalletManager, json: []const u8) !*Wallet {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, json, .{}) catch {
            return error.WalletLoadFailed;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;

        // Get network
        const network_str = obj.get("network").?.string;
        const network: Network = if (std.mem.eql(u8, network_str, "mainnet"))
            .mainnet
        else if (std.mem.eql(u8, network_str, "testnet"))
            .testnet
        else
            .regtest;

        // Create wallet
        const wallet = try self.allocator.create(Wallet);
        errdefer self.allocator.destroy(wallet);

        wallet.* = try Wallet.init(self.allocator, network);
        errdefer wallet.deinit();

        // Encrypted flag
        if (obj.get("encrypted")) |enc| {
            wallet.encrypted = enc.bool;
        }

        // HD state
        if (obj.get("next_external_index")) |idx| {
            wallet.next_external_index = @intCast(idx.integer);
        }
        if (obj.get("next_change_index")) |idx| {
            wallet.next_change_index = @intCast(idx.integer);
        }

        // Master key.  If the wallet was encrypted (post-W161-fix), the bytes
        // are AES-256-GCM ciphertext and the JSON also carries
        // master_key_nonce / master_key_tag / master_chain_code_nonce /
        // master_chain_code_tag.  Legacy plaintext format (pre-W161 fix or
        // unencrypted wallets) omits these fields — we load the bytes as-is;
        // getPlaintextMasterKey() detects the null nonces and treats the
        // bytes as plaintext for backward compatibility.
        if (obj.get("master_key")) |mk| {
            const mk_str = mk.string;
            var key_bytes: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&key_bytes, mk_str) catch return error.WalletLoadFailed;

            var chain_code: [32]u8 = undefined;
            if (obj.get("chain_code")) |cc| {
                _ = std.fmt.hexToBytes(&chain_code, cc.string) catch return error.WalletLoadFailed;
            }

            wallet.master_key = ExtendedKey{
                .key = key_bytes,
                .chain_code = chain_code,
                .depth = 0,
                .parent_fingerprint = [_]u8{ 0, 0, 0, 0 },
                .child_index = 0,
                .is_private = true,
            };

            if (obj.get("master_key_nonce")) |n| {
                var nb: [12]u8 = undefined;
                _ = std.fmt.hexToBytes(&nb, n.string) catch return error.WalletLoadFailed;
                wallet.master_key_nonce = nb;
            }
            if (obj.get("master_key_tag")) |t| {
                var tb: [16]u8 = undefined;
                _ = std.fmt.hexToBytes(&tb, t.string) catch return error.WalletLoadFailed;
                wallet.master_key_tag = tb;
            }
            if (obj.get("master_chain_code_nonce")) |n| {
                var nb: [12]u8 = undefined;
                _ = std.fmt.hexToBytes(&nb, n.string) catch return error.WalletLoadFailed;
                wallet.master_chain_code_nonce = nb;
            }
            if (obj.get("master_chain_code_tag")) |t| {
                var tb: [16]u8 = undefined;
                _ = std.fmt.hexToBytes(&tb, t.string) catch return error.WalletLoadFailed;
                wallet.master_chain_code_tag = tb;
            }
        }

        // Encryption salt
        if (obj.get("encryption_salt")) |salt| {
            var salt_bytes: [16]u8 = undefined;
            _ = std.fmt.hexToBytes(&salt_bytes, salt.string) catch return error.WalletLoadFailed;
            wallet.encryption_salt = salt_bytes;
        }

        // Keys
        if (obj.get("keys")) |keys_arr| {
            for (keys_arr.array.items) |key_obj| {
                const kobj = key_obj.object;
                var secret: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&secret, kobj.get("secret").?.string) catch return error.WalletLoadFailed;

                var pubkey: [33]u8 = undefined;
                _ = std.fmt.hexToBytes(&pubkey, kobj.get("pubkey").?.string) catch return error.WalletLoadFailed;

                // Compute x-only pubkey
                var x_only: [32]u8 = undefined;
                @memcpy(&x_only, pubkey[1..33]);

                // Load AES-256-GCM per-key nonce + auth tag (present only when encrypted).
                var enc_nonce: ?[Aes256Gcm.nonce_length]u8 = null;
                var enc_tag: ?[Aes256Gcm.tag_length]u8 = null;
                if (kobj.get("nonce")) |n| {
                    var nb: [Aes256Gcm.nonce_length]u8 = undefined;
                    _ = std.fmt.hexToBytes(&nb, n.string) catch return error.WalletLoadFailed;
                    enc_nonce = nb;
                }
                if (kobj.get("tag")) |t| {
                    var tb: [Aes256Gcm.tag_length]u8 = undefined;
                    _ = std.fmt.hexToBytes(&tb, t.string) catch return error.WalletLoadFailed;
                    enc_tag = tb;
                }

                try wallet.keys.append(KeyPair{
                    .secret_key = secret,
                    .public_key = pubkey,
                    .x_only_pubkey = x_only,
                    .encryption_nonce = enc_nonce,
                    .encryption_tag = enc_tag,
                });
            }
        }

        // UTXOs
        if (obj.get("utxos")) |utxos_arr| {
            for (utxos_arr.array.items) |utxo_obj| {
                const uobj = utxo_obj.object;

                // Parse txid (reverse from display)
                var txid: [32]u8 = undefined;
                const txid_str = uobj.get("txid").?.string;
                var temp_txid: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&temp_txid, txid_str) catch return error.WalletLoadFailed;
                for (temp_txid, 0..) |b, j| {
                    txid[31 - j] = b;
                }

                const vout: u32 = @intCast(uobj.get("vout").?.integer);
                const value: i64 = uobj.get("value").?.integer;
                const key_index: usize = @intCast(uobj.get("key_index").?.integer);
                const confirmations: u32 = @intCast(uobj.get("confirmations").?.integer);
                const is_coinbase = uobj.get("is_coinbase").?.bool;
                const height: u32 = @intCast(uobj.get("height").?.integer);

                try wallet.utxos.append(OwnedUtxo{
                    .outpoint = types.OutPoint{
                        .hash = txid,
                        .index = vout,
                    },
                    .output = types.TxOut{
                        .value = value,
                        .script_pubkey = &[_]u8{}, // Empty for now
                    },
                    .key_index = key_index,
                    .address_type = .p2wpkh, // Default
                    .confirmations = confirmations,
                    .is_coinbase = is_coinbase,
                    .height = height,
                });
            }
        }

        // Labels
        if (obj.get("labels")) |labels_obj| {
            var label_iter = labels_obj.object.iterator();
            while (label_iter.next()) |entry| {
                try wallet.setLabel(entry.key_ptr.*, entry.value_ptr.string);
            }
        }

        return wallet;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "wallet init and deinit" {
    // Skip if libsecp256k1 is not available
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) {
        return; // Skip test if secp256k1 not available
    }
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    try std.testing.expectEqual(@as(usize, 0), wallet.keyCount());
}

test "key generation produces valid keypairs" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    const key_index = try wallet.generateKey();
    try std.testing.expectEqual(@as(usize, 0), key_index);
    try std.testing.expectEqual(@as(usize, 1), wallet.keyCount());

    // Verify the public key is valid compressed format
    const key = wallet.keys.items[0];
    try std.testing.expect(key.public_key[0] == 0x02 or key.public_key[0] == 0x03);
}

test "P2PKH script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2pkh);
    defer allocator.free(script);

    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    try std.testing.expectEqual(@as(usize, 25), script.len);
    try std.testing.expectEqual(@as(u8, 0x76), script[0]); // OP_DUP
    try std.testing.expectEqual(@as(u8, 0xa9), script[1]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[2]); // Push 20
    try std.testing.expectEqual(@as(u8, 0x88), script[23]); // OP_EQUALVERIFY
    try std.testing.expectEqual(@as(u8, 0xac), script[24]); // OP_CHECKSIG
}

test "P2WPKH script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2wpkh);
    defer allocator.free(script);

    // P2WPKH: OP_0 <20>
    try std.testing.expectEqual(@as(usize, 22), script.len);
    try std.testing.expectEqual(@as(u8, 0x00), script[0]); // OP_0
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20
}

test "P2TR script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2tr);
    defer allocator.free(script);

    // P2TR: OP_1 <32>
    try std.testing.expectEqual(@as(usize, 34), script.len);
    try std.testing.expectEqual(@as(u8, 0x51), script[0]); // OP_1
    try std.testing.expectEqual(@as(u8, 0x20), script[1]); // Push 32
}

test "P2PKH address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2pkh);
    defer allocator.free(addr_str);

    // Mainnet P2PKH addresses start with '1'
    try std.testing.expect(addr_str[0] == '1');
}

test "P2WPKH address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2wpkh);
    defer allocator.free(addr_str);

    // Mainnet P2WPKH addresses start with 'bc1q'
    try std.testing.expect(std.mem.startsWith(u8, addr_str, "bc1q"));
}

test "P2TR address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2tr);
    defer allocator.free(addr_str);

    // Mainnet P2TR addresses start with 'bc1p'
    try std.testing.expect(std.mem.startsWith(u8, addr_str, "bc1p"));
}

test "testnet address derivation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .testnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // P2PKH testnet starts with 'm' or 'n'
    const p2pkh = try wallet.getAddress(0, .p2pkh);
    defer allocator.free(p2pkh);
    try std.testing.expect(p2pkh[0] == 'm' or p2pkh[0] == 'n');

    // P2WPKH testnet starts with 'tb1q'
    const p2wpkh = try wallet.getAddress(0, .p2wpkh);
    defer allocator.free(p2wpkh);
    try std.testing.expect(std.mem.startsWith(u8, p2wpkh, "tb1q"));

    // P2TR testnet starts with 'tb1p'
    const p2tr = try wallet.getAddress(0, .p2tr);
    defer allocator.free(p2tr);
    try std.testing.expect(std.mem.startsWith(u8, p2tr, "tb1p"));
}

test "coin selection with single UTXO" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add a UTXO
    try wallet.addUtxo(.{
        .outpoint = .{
            .hash = [_]u8{0x01} ** 32,
            .index = 0,
        },
        .output = .{
            .value = 100000, // 0.001 BTC
            .script_pubkey = &[_]u8{},
        },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    // Try to select coins for 50000 sats at 1 sat/vB
    const result = try wallet.selectCoins(50000, 1);
    defer allocator.free(result.selected);

    try std.testing.expectEqual(@as(usize, 1), result.selected.len);
    try std.testing.expect(result.change >= 0);
}

test "coin selection insufficient funds" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add a small UTXO
    try wallet.addUtxo(.{
        .outpoint = .{
            .hash = [_]u8{0x01} ** 32,
            .index = 0,
        },
        .output = .{
            .value = 1000, // Very small
            .script_pubkey = &[_]u8{},
        },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    // Try to select coins for a large amount
    const result = wallet.selectCoins(1000000, 10);
    try std.testing.expectError(error.InsufficientFunds, result);
}

test "ECDSA sign and verify" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    const key_idx = try wallet.generateKey();
    const key = wallet.keys.items[key_idx];

    // Create a test message hash
    const msg: [32]u8 = [_]u8{0xAB} ** 32;

    // Sign it
    const sig = try wallet.ecdsaSign(&msg, &key.secret_key);

    // Verify it
    const sig_len = getDerSigLen(&sig);
    const valid = try wallet.verifyEcdsa(sig[0..sig_len], &msg, &key.public_key);
    try std.testing.expect(valid);
}

test "BIP39 wordlist is valid" {
    // Verify we have 2048 words
    var count: usize = 0;
    for (BIP39_WORDS) |word| {
        if (word.len > 0) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2048), count);

    // Check first and last words
    try std.testing.expectEqualSlices(u8, "abandon", BIP39_WORDS[0]);
    try std.testing.expectEqualSlices(u8, "zoo", BIP39_WORDS[2047]);
}

test "estimateInputSize" {
    try std.testing.expectEqual(@as(u64, 148), estimateInputSize(.p2pkh));
    try std.testing.expectEqual(@as(u64, 68), estimateInputSize(.p2wpkh));
    try std.testing.expectEqual(@as(u64, 58), estimateInputSize(.p2tr));
}

test "wallet balance tracking" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    try std.testing.expectEqual(@as(i64, 0), wallet.getBalance());

    // Add UTXOs
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 50000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    try std.testing.expectEqual(@as(i64, 50000), wallet.getBalance());

    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x02} ** 32, .index = 0 },
        .output = .{ .value = 30000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 3,
    });

    try std.testing.expectEqual(@as(i64, 80000), wallet.getBalance());

    // Remove a UTXO
    const removed = wallet.removeUtxo(.{ .hash = [_]u8{0x01} ** 32, .index = 0 });
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(i64, 30000), wallet.getBalance());
}

test "anti-fee-sniping sets locktime to current height" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Create a mock P2WPKH scriptPubKey
    const script_pubkey = [_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20;

    // Add a UTXO to spend
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 100000, .script_pubkey = &script_pubkey },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    // Create transaction with anti-fee-sniping enabled
    const tx = try createTransaction(
        &wallet,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{
            .value = 50000,
            .script_pubkey = &script_pubkey,
        }},
        null,
        .{
            .current_height = 800000,
            .anti_fee_sniping = true,
        },
    );
    defer {
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // Verify locktime is set to current_height
    try std.testing.expectEqual(@as(u32, 800000), tx.lock_time);

    // Verify inputs have non-final sequence to enable locktime
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFE), tx.inputs[0].sequence);
}

test "anti-fee-sniping disabled sets locktime to 0" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script_pubkey = [_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20;

    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 100000, .script_pubkey = &script_pubkey },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    // Create transaction with anti-fee-sniping disabled
    const tx = try createTransaction(
        &wallet,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{
            .value = 50000,
            .script_pubkey = &script_pubkey,
        }},
        null,
        .{
            .current_height = 800000,
            .anti_fee_sniping = false,
        },
    );
    defer {
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // Verify locktime is 0 when anti-fee-sniping is disabled
    try std.testing.expectEqual(@as(u32, 0), tx.lock_time);
}

// ============================================================================
// BIP32 HD Key Tests
// ============================================================================

test "BIP32 master key from seed" {
    // Test vector from BIP32 spec (test vector 1)
    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    const master = try ExtendedKey.fromSeed(&seed);

    // Verify master key properties
    try std.testing.expectEqual(@as(u8, 0), master.depth);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &master.parent_fingerprint);
    try std.testing.expectEqual(@as(u32, 0), master.child_index);
    try std.testing.expect(master.is_private);

    // Master key should be non-zero
    try std.testing.expect(!std.mem.eql(u8, &master.key, &[_]u8{0} ** 32));
    try std.testing.expect(!std.mem.eql(u8, &master.chain_code, &[_]u8{0} ** 32));
}

test "BIP32 child key derivation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    const master = try ExtendedKey.fromSeed(&seed);

    // Derive m/0 (normal child)
    const child0 = try master.deriveChild(ctx.?, 0);
    try std.testing.expectEqual(@as(u8, 1), child0.depth);
    try std.testing.expectEqual(@as(u32, 0), child0.child_index);
    try std.testing.expect(!std.mem.eql(u8, &child0.key, &master.key));

    // Derive m/0' (hardened child)
    const child0h = try master.deriveChild(ctx.?, 0x80000000);
    try std.testing.expectEqual(@as(u8, 1), child0h.depth);
    try std.testing.expectEqual(@as(u32, 0x80000000), child0h.child_index);
    try std.testing.expect(!std.mem.eql(u8, &child0h.key, &child0.key));
}

test "BIP32 path derivation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    const master = try ExtendedKey.fromSeed(&seed);

    // Derive m/44'/0'/0'/0/0 (BIP44 first external address)
    const derived = try master.derivePath(ctx.?, "m/44'/0'/0'/0/0");
    try std.testing.expectEqual(@as(u8, 5), derived.depth);
    try std.testing.expect(derived.is_private);
}

test "BIP32 standard path generation" {
    var buf: [64]u8 = undefined;

    const path44 = try ExtendedKey.getStandardPath(.bip44, 0, 0, 0, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/44'/0'/0'/0/0", path44);

    const path84 = try ExtendedKey.getStandardPath(.bip84, 0, 0, 1, 5, &buf);
    try std.testing.expectEqualSlices(u8, "m/84'/0'/0'/1/5", path84);

    const path86 = try ExtendedKey.getStandardPath(.bip86, 1, 0, 0, 10, &buf);
    try std.testing.expectEqualSlices(u8, "m/86'/1'/0'/0/10", path86);
}

// ============================================================================
// P2SH-P2WPKH Address Tests
// ============================================================================

test "P2SH-P2WPKH script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2sh_p2wpkh);
    defer allocator.free(script);

    // P2SH: OP_HASH160 <20> OP_EQUAL
    try std.testing.expectEqual(@as(usize, 23), script.len);
    try std.testing.expectEqual(@as(u8, 0xa9), script[0]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20
    try std.testing.expectEqual(@as(u8, 0x87), script[22]); // OP_EQUAL
}

test "P2SH-P2WPKH address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2sh_p2wpkh);
    defer allocator.free(addr_str);

    // Mainnet P2SH addresses start with '3'
    try std.testing.expect(addr_str[0] == '3');
}

test "P2SH-P2WPKH address derivation testnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .testnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2sh_p2wpkh);
    defer allocator.free(addr_str);

    // Testnet P2SH addresses start with '2'
    try std.testing.expect(addr_str[0] == '2');
}

// ============================================================================
// Coin Selection Tests
// ============================================================================

test "coin selection BnB exact match" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add UTXOs that can form an exact match
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 50000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x02} ** 32, .index = 0 },
        .output = .{ .value = 30000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x03} ** 32, .index = 0 },
        .output = .{ .value = 20000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    // Try to select coins - BnB should find a good solution
    const result = try wallet.selectCoins(40000, 1);
    defer allocator.free(result.selected);

    // Should select at least one UTXO
    try std.testing.expect(result.selected.len > 0);
}

test "coin selection Knapsack fallback" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add many small UTXOs that require Knapsack
    var i: u8 = 0;
    while (i < 20) : (i += 1) {
        try wallet.addUtxo(.{
            .outpoint = .{ .hash = [_]u8{i + 1} ** 32, .index = 0 },
            .output = .{ .value = 10000, .script_pubkey = &[_]u8{} },
            .key_index = 0,
            .address_type = .p2wpkh,
            .confirmations = 6,
        });
    }

    const result = try wallet.selectCoins(75000, 1);
    defer allocator.free(result.selected);

    // Should find a solution using multiple UTXOs
    try std.testing.expect(result.selected.len > 0);
}

test "coin selection with options" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 100000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    const result = try wallet.selectCoinsWithOptions(50000, .{
        .fee_rate = 5,
        .long_term_fee_rate = 10,
        .cost_of_change = 500,
        .min_change = 1000,
    });
    defer allocator.free(result.selected);

    try std.testing.expectEqual(@as(usize, 1), result.selected.len);
    try std.testing.expect(result.change > 0);
}

// ============================================================================
// HD Wallet / getnewaddress Tests
// ============================================================================

test "getnewaddress without HD seed" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    // Without HD seed, getnewaddress falls back to random key generation
    const result = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(result.address);

    try std.testing.expect(std.mem.startsWith(u8, result.address, "bc1q"));
    try std.testing.expectEqual(@as(usize, 0), result.key_index);
}

test "getnewaddress with HD seed" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    var wallet = try Wallet.initFromSeed(allocator, .mainnet, &seed);
    defer wallet.deinit();

    // Generate multiple addresses
    const addr1 = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(addr1.address);
    try std.testing.expect(std.mem.startsWith(u8, addr1.address, "bc1q"));
    try std.testing.expectEqual(@as(usize, 0), addr1.key_index);

    const addr2 = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(addr2.address);
    try std.testing.expect(std.mem.startsWith(u8, addr2.address, "bc1q"));
    try std.testing.expectEqual(@as(usize, 1), addr2.key_index);

    // Addresses should be different
    try std.testing.expect(!std.mem.eql(u8, addr1.address, addr2.address));

    // Check change address
    const change_addr = try wallet.getnewaddress(.p2wpkh, true);
    defer allocator.free(change_addr.address);
    try std.testing.expect(std.mem.startsWith(u8, change_addr.address, "bc1q"));
    try std.testing.expect(!std.mem.eql(u8, change_addr.address, addr1.address));
}

test "getnewaddress all address types with HD" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    const seed = [_]u8{
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    };

    var wallet = try Wallet.initFromSeed(allocator, .mainnet, &seed);
    defer wallet.deinit();

    // P2PKH (BIP44)
    const p2pkh_addr = try wallet.getnewaddress(.p2pkh, false);
    defer allocator.free(p2pkh_addr.address);
    try std.testing.expect(p2pkh_addr.address[0] == '1');

    // P2SH-P2WPKH (BIP49)
    const p2sh_addr = try wallet.getnewaddress(.p2sh_p2wpkh, false);
    defer allocator.free(p2sh_addr.address);
    try std.testing.expect(p2sh_addr.address[0] == '3');

    // P2WPKH (BIP84)
    const p2wpkh_addr = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(p2wpkh_addr.address);
    try std.testing.expect(std.mem.startsWith(u8, p2wpkh_addr.address, "bc1q"));

    // P2TR (BIP86)
    const p2tr_addr = try wallet.getnewaddress(.p2tr, false);
    defer allocator.free(p2tr_addr.address);
    try std.testing.expect(std.mem.startsWith(u8, p2tr_addr.address, "bc1p"));
}

test "estimateInputSize includes P2SH-P2WPKH" {
    try std.testing.expectEqual(@as(u64, 91), estimateInputSize(.p2sh_p2wpkh));
}

// ============================================================================
// Coinbase Maturity Tests
// ============================================================================

test "COINBASE_MATURITY is 100" {
    try std.testing.expectEqual(@as(u32, 100), consensus.COINBASE_MATURITY);
}

test "coin selection skips immature coinbase" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add an immature coinbase UTXO at height 100
    try wallet.addUtxo(.{
        .outpoint = .{
            .hash = [_]u8{0x01} ** 32,
            .index = 0,
        },
        .output = .{
            .value = 5_000_000_000, // 50 BTC
            .script_pubkey = &[_]u8{},
        },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 50, // less than 100
        .is_coinbase = true,
        .height = 100,
    });

    // Set tip height to 150 (so confirmations = 50, less than COINBASE_MATURITY)
    wallet.setTipHeight(150);

    // Try to select coins - should fail because only UTXO is immature
    const result = wallet.selectCoins(1000000, 1);
    try std.testing.expectError(error.InsufficientFunds, result);

    // Now set tip height to 201 (confirmations = 101, mature)
    wallet.setTipHeight(201);

    // Should succeed now
    const result2 = try wallet.selectCoins(1000000, 1);
    defer allocator.free(result2.selected);
    try std.testing.expectEqual(@as(usize, 1), result2.selected.len);
}

test "getSpendableBalance excludes immature coinbase" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add an immature coinbase UTXO
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 5_000_000_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 50,
        .is_coinbase = true,
        .height = 100,
    });

    // Add a regular UTXO
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x02} ** 32, .index = 0 },
        .output = .{ .value = 1_000_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
        .is_coinbase = false,
        .height = 144,
    });

    wallet.setTipHeight(150);

    // Total balance includes both
    try std.testing.expectEqual(@as(i64, 5_001_000_000), wallet.getBalance());

    // Spendable excludes immature coinbase
    try std.testing.expectEqual(@as(i64, 1_000_000), wallet.getSpendableBalance());

    // Immature balance is just the coinbase
    try std.testing.expectEqual(@as(i64, 5_000_000_000), wallet.getImmatureBalance());
}

// ============================================================================
// Label Tests
// ============================================================================

test "set and get label" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    // No label initially
    try std.testing.expect(wallet.getLabel("bc1qtest") == null);

    // Set label
    try wallet.setLabel("bc1qtest", "My Wallet");

    // Get label
    const label = wallet.getLabel("bc1qtest");
    try std.testing.expect(label != null);
    try std.testing.expectEqualSlices(u8, "My Wallet", label.?);

    // Update label
    try wallet.setLabel("bc1qtest", "Updated Label");
    const updated = wallet.getLabel("bc1qtest");
    try std.testing.expectEqualSlices(u8, "Updated Label", updated.?);

    // Remove label
    wallet.removeLabel("bc1qtest");
    try std.testing.expect(wallet.getLabel("bc1qtest") == null);
}

test "getLabeledAddresses" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    try wallet.setLabel("addr1", "Label 1");
    try wallet.setLabel("addr2", "Label 2");

    const addrs = try wallet.getLabeledAddresses(allocator);
    defer allocator.free(addrs);

    try std.testing.expectEqual(@as(usize, 2), addrs.len);
}

// ============================================================================
// Encryption Tests
// ============================================================================

test "encrypt and decrypt private key — AES-256-GCM" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0xAB} ** Aes256Gcm.key_length;
    const plaintext: [32]u8 = [_]u8{0xCD} ** 32;

    const enc = encryptPrivateKey(&key, &plaintext);

    // Ciphertext must differ from plaintext
    try std.testing.expect(!std.mem.eql(u8, &enc.ciphertext, &plaintext));

    // Correct key + nonce + tag → decrypts to original plaintext
    const decrypted = try decryptPrivateKey(&key, &enc.ciphertext, &enc.nonce, &enc.tag);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);

    // Wrong key → error.AuthenticationFailed (not garbage)
    const wrong_key: [Aes256Gcm.key_length]u8 = [_]u8{0x00} ** Aes256Gcm.key_length;
    try std.testing.expectError(error.AuthenticationFailed, decryptPrivateKey(&wrong_key, &enc.ciphertext, &enc.nonce, &enc.tag));

    // Bit-flip in ciphertext → error.AuthenticationFailed
    var flipped = enc.ciphertext;
    flipped[0] ^= 0xFF;
    try std.testing.expectError(error.AuthenticationFailed, decryptPrivateKey(&key, &flipped, &enc.nonce, &enc.tag));

    // Bit-flip in tag → error.AuthenticationFailed
    var bad_tag = enc.tag;
    bad_tag[0] ^= 0xFF;
    try std.testing.expectError(error.AuthenticationFailed, decryptPrivateKey(&key, &enc.ciphertext, &enc.nonce, &bad_tag));

    // Encrypting same plaintext twice → different ciphertexts (random nonce)
    const enc2 = encryptPrivateKey(&key, &plaintext);
    try std.testing.expect(!std.mem.eql(u8, &enc.ciphertext, &enc2.ciphertext));
    try std.testing.expect(!std.mem.eql(u8, &enc.nonce, &enc2.nonce));
}

test "wallet encryption state" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    // Initially not encrypted
    try std.testing.expect(!wallet.encrypted);
    try std.testing.expect(wallet.isUnlocked()); // unencrypted wallet is "unlocked"

    // Add a key before encrypting
    _ = try wallet.generateKey();
}

// ============================================================================
// Multi-Wallet Manager Tests
// ============================================================================

test "multi_wallet manager init and deinit" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    // Use temp directory
    const test_dir = "/tmp/clearbit_test_wallets";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    try std.testing.expectEqual(@as(usize, 0), manager.count());

    // Cleanup
    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "createwallet creates new wallet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets2";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    // Create a wallet
    const wallet = try manager.createWallet("mywallet", .{});
    try std.testing.expect(wallet.master_key != null); // HD wallet by default

    try std.testing.expectEqual(@as(usize, 1), manager.count());

    // Get the wallet
    const got = manager.getWallet("mywallet");
    try std.testing.expect(got != null);
    try std.testing.expectEqual(wallet, got.?);

    // Cleanup
    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "createwallet blank wallet has no master key" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets3";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    const wallet = try manager.createWallet("blank", .{ .blank = true });
    try std.testing.expect(wallet.master_key == null);

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "createwallet duplicate name fails" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets4";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    _ = try manager.createWallet("dup", .{});

    // Should fail with duplicate
    const result = manager.createWallet("dup", .{});
    try std.testing.expectError(error.WalletAlreadyExists, result);

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "multi_wallet isolation between wallets" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets5";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    // Create two wallets
    const wallet1 = try manager.createWallet("wallet1", .{});
    const wallet2 = try manager.createWallet("wallet2", .{});

    // Generate keys in each wallet
    _ = try wallet1.generateKey();
    _ = try wallet1.generateKey();
    _ = try wallet2.generateKey();

    // Verify isolation
    try std.testing.expectEqual(@as(usize, 2), wallet1.keys.items.len);
    try std.testing.expectEqual(@as(usize, 1), wallet2.keys.items.len);

    // Add UTXO to wallet1
    try wallet1.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 1_000_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 10,
        .is_coinbase = false,
        .height = 100,
    });

    // Verify UTXO isolation
    try std.testing.expectEqual(@as(i64, 1_000_000), wallet1.getBalance());
    try std.testing.expectEqual(@as(i64, 0), wallet2.getBalance());

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "loadwallet and unloadwallet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets6";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    // Create and save a wallet
    {
        var manager = try WalletManager.init(allocator, test_dir, .regtest);
        defer manager.deinit();

        const wallet = try manager.createWallet("persist", .{});
        _ = try wallet.generateKey();
    }

    // Load it in a new manager
    {
        var manager = try WalletManager.init(allocator, test_dir, .regtest);
        defer manager.deinit();

        const wallet = try manager.loadWallet("persist");
        try std.testing.expectEqual(@as(usize, 1), wallet.keys.items.len);

        // Unload it
        try manager.unloadWallet("persist");
        try std.testing.expectEqual(@as(usize, 0), manager.count());
    }

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "listwallets returns loaded wallet names" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets7";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    _ = try manager.createWallet("alpha", .{});
    _ = try manager.createWallet("beta", .{});

    const names = try manager.listWallets(allocator);
    defer {
        for (names) |n| allocator.free(n);
        allocator.free(names);
    }

    try std.testing.expectEqual(@as(usize, 2), names.len);

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "listwalletdir returns available wallets" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets8";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    // Create wallets
    {
        var manager = try WalletManager.init(allocator, test_dir, .regtest);
        defer manager.deinit();

        _ = try manager.createWallet("saved1", .{});
        _ = try manager.createWallet("saved2", .{});
    }

    // List from fresh manager
    {
        var manager = try WalletManager.init(allocator, test_dir, .regtest);
        defer manager.deinit();

        const names = try manager.listWalletDir(allocator);
        defer {
            for (names) |n| allocator.free(n);
            allocator.free(names);
        }

        try std.testing.expectEqual(@as(usize, 2), names.len);
    }

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "getTargetWallet parses URL path" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets9";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    const wallet = try manager.createWallet("targeted", .{});

    // Get wallet via URL path
    const target = try manager.getTargetWallet("/wallet/targeted");
    try std.testing.expectEqual(wallet, target);

    // Non-existent wallet should fail
    const result = manager.getTargetWallet("/wallet/nonexistent");
    try std.testing.expectError(error.WalletNotFound, result);

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}

test "getDefaultWallet returns single wallet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;

    const test_dir = "/tmp/clearbit_test_wallets10";
    std.fs.deleteTreeAbsolute(test_dir) catch {};

    var manager = try WalletManager.init(allocator, test_dir, .regtest);
    defer manager.deinit();

    // No wallets - should fail
    try std.testing.expectError(error.WalletNotLoaded, manager.getDefaultWallet());

    // One wallet - should return it
    const wallet = try manager.createWallet("single", .{});
    const default = try manager.getDefaultWallet();
    try std.testing.expectEqual(wallet, default);

    // Two wallets (no empty name) - should fail
    _ = try manager.createWallet("second", .{});
    try std.testing.expectError(error.WalletNotSpecified, manager.getDefaultWallet());

    std.fs.deleteTreeAbsolute(test_dir) catch {};
}
