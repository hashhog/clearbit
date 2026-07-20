//! Phase B `verifyscript` shim for clearbit.
//!
//! Drives clearbit's REAL consensus script interpreter
//! (`ScriptEngine.verify`, src/script.zig:884) against the Phase B
//! bounded reject-bar harness (tools/phaseb-vectors). Generalizes the
//! proven rustoshi shim (tools/phaseb-vectors/rustoshi-shim/src/main.rs,
//! 1217/1217) to Zig, reusing clearbit's OWN tx serialization + txid
//! (src/serialize.zig) so that any signature-dependent row computes a
//! byte-identical sighash.
//!
//! It reconstructs Core's crediting + spending transaction pair exactly
//! as `src/test/util/transaction_utils.cpp`
//! (BuildCreditingTransaction / BuildSpendingTransaction) does:
//!   credit  = v1, locktime 0, one null-prevout input with scriptSig
//!             OP_0 OP_0 (bytes 00 00), seq 0xFFFFFFFF, one output
//!             {test scriptPubKey, amount}.
//!   spend   = v1, locktime 0, one input spending credit.txid():0 with
//!             the test scriptSig + witness, seq 0xFFFFFFFF, one output
//!             {empty script, same amount}.
//!
//! Protocol (line-delimited JSON on stdin/stdout):
//!   request:  {"op":"verifyscript",
//!              "scriptSig_hex":"...","scriptPubKey_hex":"...",
//!              "witness":["hex",...],"amount_sats":0,
//!              "flags":["P2SH","WITNESS",...]}
//!   response: {"result":true}                  (accept)
//!             {"result":false,"reason":"..."}  (reject)
//!             {"error":"..."}                  (could not evaluate /
//!                                               unmapped flag / panic)
//!
//! Second op `verifytx` (for tx_valid.json / tx_invalid.json): unlike
//! `verifyscript` (which rebuilds Core's synthetic credit/spend pair),
//! these vectors give a REAL serialized multi-input tx, so the sighash
//! must be computed over THAT tx. Mirrors
//! bitcoin-core/src/test/transaction_tests.cpp::CheckTxScripts: decode
//! tx_hex with clearbit's OWN deserializer (segwit marker/flag +
//! witnesses), build the prevout map, then for EACH input run clearbit's
//! real ScriptEngine.verify(scriptSig, matching prevout scriptPubKey,
//! witness, flags, prevouts bound to THE REAL TX + this input index +
//! amount + all-prevouts). The tx is valid iff ALL inputs pass; reject on
//! the FIRST failing input (Core's loop is `i < vin.size() && tx_valid`).
//!
//!   request:  {"op":"verifytx",
//!              "tx_hex":"...",
//!              "prevouts":[{"txid":"<display-hex>","vout":N,
//!                           "scriptPubKey_hex":"...","amount_sats":0},...],
//!              "flags":["P2SH","WITNESS",...]}
//!   response: {"valid":true}                   (all inputs verify)
//!             {"valid":false,"reason":"..."}   (>=1 input failed)
//!             {"error":"..."}                  (could not evaluate)
//!
//! Third op `checktx` (CheckTransaction-level, context-free structural
//! validation): mirrors bitcoin-core/src/consensus/tx_check.cpp::
//! CheckTransaction. These are the checks `verifytx` (per-input
//! VerifyScript only) cannot catch — empty vin/vout, oversize (tx weight >
//! MAX_BLOCK_WEIGHT), output value range and running total, duplicate
//! inputs, coinbase scriptSig length [2,100], and null prevout in a
//! non-coinbase. We deserialize tx_hex and call clearbit's OWN
//! `checkTransactionSanity` (src/validation.zig:316) so the harness
//! exercises clearbit's real consensus code, NOT a reimplementation in the
//! shim. No UTXO / chain state is needed.
//!
//!   request:  {"op":"checktx","tx_hex":"..."}
//!   response: {"valid":true}                   (structurally valid)
//!             {"valid":false,"reason":"..."}   (CheckTransaction rejected)
//!             {"error":"..."}                  (could not deserialize)
//!
//! KEY: the prevout `txid` in the request is DISPLAY-order hex (big-endian
//! txid as shown by RPC); the deserialized tx stores prevout hashes in
//! WIRE/internal order. We reverse the request txid to wire order before
//! keying the map so it matches the tx's `previous_output.hash`.

const std = @import("std");
const script = @import("script.zig");
const serialize = @import("serialize.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const validation = @import("validation.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexChar,
    };
}

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = (try hexNibble(hex[i * 2]) << 4) | (try hexNibble(hex[i * 2 + 1]));
    }
    return out;
}

/// Map Core flag tokens (interpreter.cpp:2168 ScriptFlagNamesToEnum) to
/// clearbit's `ScriptFlags` packed struct. CRITICAL: clearbit's struct
/// defaults most verify_* fields to `true`, so we MUST start from an
/// all-false base and switch ON only the tokens the vector lists —
/// otherwise a row that omits e.g. DERSIG would still get the DER check.
///
/// STRICTENC maps to ONLY `verify_strictenc` (NOT also dersig/low_s):
/// clearbit's interpreter already triggers the DER-encoding check when
/// `dersig OR low_s OR strictenc` is set (script.zig:2139/2215), exactly
/// matching Core's CheckSignatureEncoding gate, so STRICTENC alone is
/// sufficient and force-enabling dersig+low_s would diverge from Core.
///
/// Returns an error (→ {"error":...}, driver skips) on an unknown token.
fn buildFlags(tokens: []const std.json.Value) !script.ScriptFlags {
    var f = script.ScriptFlags{
        .verify_p2sh = false,
        .verify_witness = false,
        .verify_clean_stack = false,
        .verify_dersig = false,
        .verify_low_s = false,
        .verify_nulldummy = false,
        .verify_nullfail = false,
        .verify_minimaldata = false,
        .verify_checklocktimeverify = false,
        .verify_checksequenceverify = false,
        .verify_taproot = false,
        .verify_witness_pubkeytype = false,
        .discourage_op_success = false,
        .discourage_upgradable_nops = false,
        .verify_sigpushonly = false,
        .verify_strictenc = false,
        .discourage_upgradable_witness_program = false,
        .verify_const_scriptcode = false,
        .discourage_upgradable_pubkeytype = false,
        .discourage_upgradable_taproot_version = false,
        .verify_minimalif = false,
    };

    for (tokens) |t| {
        const name = switch (t) {
            .string => |s| s,
            else => return error.FlagNotString,
        };
        if (std.mem.eql(u8, name, "P2SH")) {
            f.verify_p2sh = true;
        } else if (std.mem.eql(u8, name, "STRICTENC")) {
            f.verify_strictenc = true;
        } else if (std.mem.eql(u8, name, "DERSIG")) {
            f.verify_dersig = true;
        } else if (std.mem.eql(u8, name, "LOW_S")) {
            f.verify_low_s = true;
        } else if (std.mem.eql(u8, name, "SIGPUSHONLY")) {
            f.verify_sigpushonly = true;
        } else if (std.mem.eql(u8, name, "MINIMALDATA")) {
            f.verify_minimaldata = true;
        } else if (std.mem.eql(u8, name, "NULLDUMMY")) {
            f.verify_nulldummy = true;
        } else if (std.mem.eql(u8, name, "DISCOURAGE_UPGRADABLE_NOPS")) {
            f.discourage_upgradable_nops = true;
        } else if (std.mem.eql(u8, name, "CLEANSTACK")) {
            f.verify_clean_stack = true;
        } else if (std.mem.eql(u8, name, "MINIMALIF")) {
            f.verify_minimalif = true;
        } else if (std.mem.eql(u8, name, "NULLFAIL")) {
            f.verify_nullfail = true;
        } else if (std.mem.eql(u8, name, "CHECKLOCKTIMEVERIFY")) {
            f.verify_checklocktimeverify = true;
        } else if (std.mem.eql(u8, name, "CHECKSEQUENCEVERIFY")) {
            f.verify_checksequenceverify = true;
        } else if (std.mem.eql(u8, name, "WITNESS")) {
            f.verify_witness = true;
        } else if (std.mem.eql(u8, name, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM")) {
            f.discourage_upgradable_witness_program = true;
        } else if (std.mem.eql(u8, name, "WITNESS_PUBKEYTYPE")) {
            f.verify_witness_pubkeytype = true;
        } else if (std.mem.eql(u8, name, "CONST_SCRIPTCODE")) {
            f.verify_const_scriptcode = true;
        } else if (std.mem.eql(u8, name, "TAPROOT")) {
            f.verify_taproot = true;
        } else if (std.mem.eql(u8, name, "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")) {
            f.discourage_upgradable_pubkeytype = true;
        } else if (std.mem.eql(u8, name, "DISCOURAGE_OP_SUCCESS")) {
            f.discourage_op_success = true;
        } else if (std.mem.eql(u8, name, "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")) {
            f.discourage_upgradable_taproot_version = true;
        } else {
            return error.UnknownFlagToken;
        }
    }
    return f;
}

/// Double-SHA256 of the no-witness serialization = txid (internal order),
/// reusing clearbit's own serializer so the credit txid that the spend's
/// prevout commits to matches clearbit's own consensus computation.
fn computeTxid(allocator: std.mem.Allocator, tx: *const types.Transaction) ![32]u8 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try serialize.writeTransactionNoWitness(&writer, tx);
    return crypto.hash256(writer.getWritten());
}

fn jsonEscape(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice("\\\""),
            '\\' => try buf.appendSlice("\\\\"),
            '\n' => try buf.appendSlice("\\n"),
            '\r' => try buf.appendSlice("\\r"),
            '\t' => try buf.appendSlice("\\t"),
            else => try buf.append(c),
        }
    }
    return buf.toOwnedSlice();
}

/// Key for the prevout map: wire-order txid + vout index.
const OutPointKey = struct { hash: [32]u8, index: u32 };

/// Value: the prevout's scriptPubKey bytes + amount in sats.
const PrevoutVal = struct { spk: []const u8, amount: i64 };

/// `checktx` op: CheckTransaction-level (context-free, structural)
/// validation. Mirrors bitcoin-core/src/consensus/tx_check.cpp::
/// CheckTransaction by delegating to clearbit's OWN
/// `validation.checkTransactionSanity` (src/validation.zig:316), so a
/// divergence here is a clearbit consensus bug, not a shim bug. No
/// UTXO / chain state is needed. We deserialize tx_hex with clearbit's
/// own deserializer; an undeserializable tx => {"error"} so the driver
/// SKIPS the row (the driver counts that as a reject decision, never a
/// fake-pass).
fn processChecktx(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const tx_hex = switch (obj.get("tx_hex") orelse return error.MissingTxHex) {
        .string => |s| s,
        else => return error.TxHexNotString,
    };
    const tx_bytes = try hexDecode(a, tx_hex);

    var reader = serialize.Reader{ .data = tx_bytes };
    const tx = serialize.readTransaction(&reader, a) catch |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"error\":\"tx deserialize: {s}\"}}\n", .{reason});
        return;
    };

    if (validation.checkTransactionSanity(&tx)) |_| {
        try out.writeAll("{\"valid\":true}\n");
    } else |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"valid\":false,\"reason\":\"{s}\"}}\n", .{reason});
    }
}

/// `verifytx` op: deserialize the REAL tx with clearbit's own
/// deserializer, build the prevout map, then run clearbit's real
/// ScriptEngine.verify per input over THAT tx (so legacy/BIP-143/BIP-341
/// sighash commits to the actual surrounding transaction). Valid iff ALL
/// inputs pass; reject on the FIRST failing input, mirroring Core's
/// transaction_tests.cpp short-circuit `i < vin.size() && fValid`.
fn processVerifytx(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const tx_hex = switch (obj.get("tx_hex") orelse return error.MissingTxHex) {
        .string => |s| s,
        else => return error.TxHexNotString,
    };
    const tx_bytes = try hexDecode(a, tx_hex);

    var reader = serialize.Reader{ .data = tx_bytes };
    const tx = serialize.readTransaction(&reader, a) catch |err| {
        // Undeserializable tx => {"error"} so the driver SKIPS the row
        // (never fake-pass / fake-reject on a parse failure we can't model).
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"error\":\"tx deserialize: {s}\"}}\n", .{reason});
        return;
    };

    const flags = try buildFlags((obj.get("flags") orelse return error.MissingFlags).array.items);

    // Build the prevout map keyed by (wire-order txid, vout). The request
    // txid is DISPLAY-order hex => reverse to wire order before keying so
    // it matches the deserialized tx's previous_output.hash.
    var prevout_map = std.AutoHashMap(OutPointKey, PrevoutVal).init(a);
    const prevouts = (obj.get("prevouts") orelse return error.MissingPrevouts).array.items;
    for (prevouts) |p| {
        const po = p.object;
        const txid_disp = switch (po.get("txid") orelse return error.PrevoutMissingTxid) {
            .string => |s| s,
            else => return error.PrevoutTxidNotString,
        };
        const txid_disp_bytes = try hexDecode(a, txid_disp);
        if (txid_disp_bytes.len != 32) return error.PrevoutTxidLen;
        // Reverse display-order -> wire-order.
        var wire_hash: [32]u8 = undefined;
        for (0..32) |i| wire_hash[i] = txid_disp_bytes[31 - i];

        const vout: u32 = switch (po.get("vout") orelse return error.PrevoutMissingVout) {
            .integer => |iv| @truncate(@as(u64, @bitCast(iv))),
            else => return error.PrevoutVoutNotInt,
        };

        const spk = try hexDecode(a, switch (po.get("scriptPubKey_hex") orelse return error.PrevoutMissingSpk) {
            .string => |s| s,
            else => return error.PrevoutSpkNotString,
        });

        // amount defaults to 0 when absent (Core: map_prevout_values
        // .contains(prevout) ? at(prevout) : 0).
        const amount: i64 = blk: {
            if (po.get("amount_sats")) |v| switch (v) {
                .integer => |iv| break :blk iv,
                else => break :blk 0,
            };
            break :blk 0;
        };

        try prevout_map.put(.{ .hash = wire_hash, .index = vout }, .{ .spk = spk, .amount = amount });
    }

    // Assemble per-input spent_scripts / spent_amounts in the tx's OWN
    // input order, so spent_amounts[i]/spent_scripts[i] line up with input
    // i (BIP-341 commits to ALL prevouts). A prevout missing from the map
    // is a malformed row => {"error"} skip (never fake-pass).
    const n = tx.inputs.len;
    var spent_scripts = try a.alloc([]const u8, n);
    var spent_amounts = try a.alloc(i64, n);
    for (tx.inputs, 0..) |input, i| {
        const key = OutPointKey{ .hash = input.previous_output.hash, .index = input.previous_output.index };
        const val = prevout_map.get(key) orelse {
            try out.writeAll("{\"error\":\"no prevout scriptPubKey for an input\"}\n");
            return;
        };
        spent_scripts[i] = val.spk;
        spent_amounts[i] = val.amount;
    }

    // Per-input VerifyScript over the real tx. Reject on first failure.
    for (0..n) |i| {
        const input = tx.inputs[i];
        const spk = spent_scripts[i];
        const amount = spent_amounts[i];

        var engine = script.ScriptEngine.initWithPrevouts(
            a,
            &tx,
            i,
            amount,
            flags,
            spent_amounts,
            spent_scripts,
        );
        defer engine.deinit();

        if (engine.verify(input.script_sig, spk, input.witness)) |ok| {
            if (!ok) {
                try out.print("{{\"valid\":false,\"reason\":\"input {d}: VerifyFalse\"}}\n", .{i});
                return;
            }
        } else |err| {
            const reason = try jsonEscape(a, @errorName(err));
            try out.print("{{\"valid\":false,\"reason\":\"input {d}: {s}\"}}\n", .{ i, reason });
            return;
        }
    }

    try out.writeAll("{\"valid\":true}\n");
}

/// In-memory coin for the connecttx UTXO view: the spent output's
/// scriptPubKey + value + the metadata Core's CheckTxInputs needs
/// (coin.nHeight + fCoinBase). One entry per request prevout; an OMITTED
/// outpoint models a missing/spent input.
const ConnectCoin = struct {
    spk: []const u8,
    value: i64,
    height: u32,
    is_coinbase: bool,
};

/// Map a connecttx ValidationError to the canonical Core "bad-txns-*" reject
/// token. Mirrors rpc.zig:6307 validationErrToBip22 for the CheckTxInputs
/// subset (the connecttx op only surfaces these economic errors). The reason
/// is informational; the DECISION (valid=false) is what is scored.
fn connectErrToReason(err: validation.ValidationError) []const u8 {
    return switch (err) {
        error.MissingInput, error.InputAlreadySpent => "bad-txns-inputs-missingorspent",
        error.ImmatureCoinbase => "bad-txns-premature-spend-of-coinbase",
        // Connect-block script stage: Core validation.cpp:2122
        // "block-script-verify-flag-failed" (rpc.zig:6321 parity).
        error.ScriptVerificationFailed => "block-script-verify-flag-failed",
        error.InputValuesOutOfRange => "bad-txns-inputvalues-outofrange",
        error.InsufficientFunds => "bad-txns-in-belowout",
        // BIP-68 SequenceLocks + BIP-113/IsFinalTx finality (checkblock op):
        // both surface as Core "bad-txns-nonfinal" (validation.cpp:2549-2561
        // ConnectBlock SequenceLocks + ContextualCheckBlock IsFinalTx).
        // rpc.zig:6316 validationErrToBip22 parity. Advisory only; the valid
        // bool is what is scored.
        error.NonFinalTx, error.SequenceLockNotSatisfied => "bad-txns-nonfinal",
        // Block-level (checkblock op) connect/check errors -> canonical Core
        // BIP22 reject tokens.  Advisory only; the valid bool is scored.
        error.BadCoinbaseValue => "bad-cb-amount",
        error.TooManySigops => "bad-blk-sigops",
        error.BadBlockWeight => "bad-blk-length",
        error.BadCoinbaseHeight => "bad-cb-height",
        error.BadWitnessCommitment => "bad-witness-merkle-match",
        error.UnexpectedWitness => "unexpected-witness",
        error.BadMerkleRoot => "bad-txnmrklroot",
        error.DuplicateTx => "bad-txns-duplicate",
        error.FirstTxNotCoinbase => "bad-cb-missing",
        error.MultipleCoinbase => "bad-cb-multiple",
        error.BadProofOfWork => "high-hash",
        error.BadDifficulty => "bad-diffbits",
        else => @errorName(err),
    };
}

/// `connecttx` op: drives clearbit's REAL connect-time economic check
/// (validation.zig::checkTxInputs — the script-free extraction of the per-tx
/// body in validateBlockForIBD / Core Consensus::CheckTxInputs,
/// tx_verify.cpp:164-214): the no-inflation rule value-in >= value-out
/// (bad-txns-in-belowout), per-input + running-sum MoneyRange
/// (bad-txns-inputvalues-outofrange), coinbase maturity 100
/// (bad-txns-premature-spend-of-coinbase), and missing/spent inputs
/// (bad-txns-inputs-missingorspent).
///
/// Seeds an in-memory UTXO VIEW with one coin per request prevout entry
/// (value + height + is_coinbase). An OMITTED prevout models a
/// missing/spent input → MissingInput. We DO NOT run script verification
/// here (this op isolates the economic verdict — a script failure must not
/// mask the monetary decision), and we DO NOT re-implement value-in>=out in
/// the shim: the decision comes entirely from checkTxInputs.
///
///   request:  {"op":"connecttx","tx_hex":"...",
///              "prevouts":[{"txid":"<display-hex>","vout":N,
///                           "scriptPubKey_hex":"...","value_sats":<i64>,
///                           "height":<int>,"is_coinbase":<bool>},...],
///              "spend_height":<int>}
///   response: {"valid":true,"fee_sats":<i64>}   (CheckTxInputs accepts)
///             {"valid":false,"reason":"bad-txns-*"} (economic reject)
///             {"error":"..."}                   (could not evaluate → SKIP)
fn processConnecttx(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const tx_hex = switch (obj.get("tx_hex") orelse return error.MissingTxHex) {
        .string => |s| s,
        else => return error.TxHexNotString,
    };
    const tx_bytes = try hexDecode(a, tx_hex);

    var reader = serialize.Reader{ .data = tx_bytes };
    const tx = serialize.readTransaction(&reader, a) catch |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"error\":\"tx deserialize: {s}\"}}\n", .{reason});
        return;
    };

    const spend_height: u32 = switch (obj.get("spend_height") orelse return error.MissingSpendHeight) {
        .integer => |iv| @intCast(iv),
        else => return error.SpendHeightNotInt,
    };

    // Seed the in-memory UTXO view: one coin per prevout entry, keyed by
    // (wire-order txid, vout). Reuse the verifytx display->wire txid reversal.
    var view = std.AutoHashMap(OutPointKey, ConnectCoin).init(a);
    const prevouts = (obj.get("prevouts") orelse return error.MissingPrevouts).array.items;
    for (prevouts) |p| {
        const po = p.object;
        const txid_disp = switch (po.get("txid") orelse return error.PrevoutMissingTxid) {
            .string => |s| s,
            else => return error.PrevoutTxidNotString,
        };
        const txid_disp_bytes = try hexDecode(a, txid_disp);
        if (txid_disp_bytes.len != 32) return error.PrevoutTxidLen;
        var wire_hash: [32]u8 = undefined;
        for (0..32) |i| wire_hash[i] = txid_disp_bytes[31 - i];

        const vout: u32 = switch (po.get("vout") orelse return error.PrevoutMissingVout) {
            .integer => |iv| @truncate(@as(u64, @bitCast(iv))),
            else => return error.PrevoutVoutNotInt,
        };

        const spk = try hexDecode(a, switch (po.get("scriptPubKey_hex") orelse return error.PrevoutMissingSpk) {
            .string => |s| s,
            else => return error.PrevoutSpkNotString,
        });

        const value: i64 = switch (po.get("value_sats") orelse return error.PrevoutMissingValue) {
            .integer => |iv| iv,
            else => return error.PrevoutValueNotInt,
        };

        const height: u32 = switch (po.get("height") orelse return error.PrevoutMissingHeight) {
            .integer => |iv| @intCast(iv),
            else => return error.PrevoutHeightNotInt,
        };

        const is_coinbase: bool = switch (po.get("is_coinbase") orelse return error.PrevoutMissingIsCoinbase) {
            .bool => |b| b,
            else => return error.PrevoutIsCoinbaseNotBool,
        };

        try view.put(.{ .hash = wire_hash, .index = vout }, .{
            .spk = spk,
            .value = value,
            .height = height,
            .is_coinbase = is_coinbase,
        });
    }

    // Lookup closure over the seeded view. Returns the coin as a
    // validation.PrevOutInfo (owner_allocator=null: scripts borrow the arena,
    // never freed by checkTxInputs). A miss => null => MissingInput.
    const View = struct {
        map: *std.AutoHashMap(OutPointKey, ConnectCoin),
        fn lookup(ctx_ptr: *anyopaque, outpoint: *const types.OutPoint) ?validation.PrevOutInfo {
            const me: *@This() = @ptrCast(@alignCast(ctx_ptr));
            const key = OutPointKey{ .hash = outpoint.hash, .index = outpoint.index };
            const coin = me.map.get(key) orelse return null;
            return .{
                .script_pubkey = coin.spk,
                .amount = coin.value,
                .height = coin.height,
                .is_coinbase = coin.is_coinbase,
                .owner_allocator = null,
            };
        }
    };
    var view_ctx = View{ .map = &view };

    // Drive clearbit's REAL connect-time economic check. NO script verify,
    // NO shim-side re-implementation of value-in>=out / maturity / missing.
    const fee = validation.checkTxInputs(&tx, spend_height, &view_ctx, View.lookup) catch |err| {
        const reason = try jsonEscape(a, connectErrToReason(err));
        try out.print("{{\"valid\":false,\"reason\":\"{s}\"}}\n", .{reason});
        return;
    };

    try out.print("{{\"valid\":true,\"fee_sats\":{d}}}\n", .{fee});
}

/// `checkblock` op: DECISION-LEVEL block validation (VALIDATE-ONLY). Drives
/// clearbit's REAL block-accept pipeline — validation.acceptBlock ->
/// validateBlockForIBD — which runs Core's CheckBlock (coinbase position +
/// sanity, merkle root, weight, BIP-34 height, BIP-141 witness commitment,
/// legacy sigops) -> ContextualCheckBlock (IsFinalTx, version gates) ->
/// ConnectBlock-equivalent (seeded UTXO view -> per-input value sums + fee,
/// coinbase value <= subsidy + fees, full P2SH/witness sigop budget, REAL
/// script verification) — at MAINNET params with spend_height 709742
/// (post-Taproot: every mainnet deployment active).
///
/// VALIDATE-ONLY contract: the block_hex is FINAL/mutated bytes; we deserialize
/// and validate AS-IS (do NOT recompute the merkle root, do NOT re-mutate).
/// `skip_pow=true` (Core fCheckPOW=false parity) bypasses ONLY the header PoW
/// gate via the new validation.AcceptBlockOptions.force_skip_pow flag — every
/// other consensus check still runs. The corpus bytes miss the mainnet target
/// by construction, so if skip_pow were not wired a body mutant would reject on
/// high-hash and the body gate would be a SILENT DEAD-GATE.
///
/// Seeds the SAME in-memory UTXO View as connecttx — one coin per request
/// prevout (one per NON-COINBASE input across all non-coinbase txs), keyed by
/// (wire-order txid, vout). An OMITTED prevout models a missing/spent input.
///
///   request:  {"op":"checkblock","block_hex":"<FINAL block bytes>",
///              "prevouts":[{"txid":"<display-hex>","vout":N,
///                           "scriptPubKey_hex":"...","value_sats":<u64>,
///                           "height":N,"is_coinbase":bool},...],
///              "spend_height":709742,"skip_pow":true,"skip_scripts":false}
///   response: {"valid":true}                    (block accepted)
///             {"valid":false,"reason":"<token>"} (rejected; advisory token)
///             {"error":"..."}                    (could not evaluate => SKIP)
fn processCheckblock(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const block_hex = switch (obj.get("block_hex") orelse return error.MissingBlockHex) {
        .string => |s| s,
        else => return error.BlockHexNotString,
    };
    const block_bytes = try hexDecode(a, block_hex);

    // Deserialize the FINAL block bytes with clearbit's OWN reader (80B header
    // + CompactSize txcount + per-tx segwit-aware readTransaction loop). A
    // parse failure => {"error"} so the driver SKIPS (never fake-decision).
    var reader = serialize.Reader{ .data = block_bytes };
    const block = serialize.readBlock(&reader, a) catch |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"error\":\"block deserialize: {s}\"}}\n", .{reason});
        return;
    };

    const spend_height: u32 = switch (obj.get("spend_height") orelse return error.MissingSpendHeight) {
        .integer => |iv| @intCast(iv),
        else => return error.SpendHeightNotInt,
    };

    const skip_pow: bool = blk: {
        if (obj.get("skip_pow")) |v| switch (v) {
            .bool => |b| break :blk b,
            else => break :blk true,
        };
        break :blk true;
    };
    const skip_scripts: bool = blk: {
        if (obj.get("skip_scripts")) |v| switch (v) {
            .bool => |b| break :blk b,
            else => break :blk false,
        };
        break :blk false;
    };

    // Seed the in-memory UTXO view: one coin per prevout entry, keyed by
    // (wire-order txid, vout). VERBATIM the connecttx seeding plumbing.
    var view = std.AutoHashMap(OutPointKey, ConnectCoin).init(a);
    const prevouts = (obj.get("prevouts") orelse return error.MissingPrevouts).array.items;
    for (prevouts) |p| {
        const po = p.object;
        const txid_disp = switch (po.get("txid") orelse return error.PrevoutMissingTxid) {
            .string => |s| s,
            else => return error.PrevoutTxidNotString,
        };
        const txid_disp_bytes = try hexDecode(a, txid_disp);
        if (txid_disp_bytes.len != 32) return error.PrevoutTxidLen;
        var wire_hash: [32]u8 = undefined;
        for (0..32) |i| wire_hash[i] = txid_disp_bytes[31 - i];

        const vout: u32 = switch (po.get("vout") orelse return error.PrevoutMissingVout) {
            .integer => |iv| @truncate(@as(u64, @bitCast(iv))),
            else => return error.PrevoutVoutNotInt,
        };

        const spk = try hexDecode(a, switch (po.get("scriptPubKey_hex") orelse return error.PrevoutMissingSpk) {
            .string => |s| s,
            else => return error.PrevoutSpkNotString,
        });

        const value: i64 = switch (po.get("value_sats") orelse return error.PrevoutMissingValue) {
            .integer => |iv| iv,
            else => return error.PrevoutValueNotInt,
        };

        const height: u32 = switch (po.get("height") orelse return error.PrevoutMissingHeight) {
            .integer => |iv| @intCast(iv),
            else => return error.PrevoutHeightNotInt,
        };

        const is_coinbase: bool = switch (po.get("is_coinbase") orelse return error.PrevoutMissingIsCoinbase) {
            .bool => |b| b,
            else => return error.PrevoutIsCoinbaseNotBool,
        };

        try view.put(.{ .hash = wire_hash, .index = vout }, .{
            .spk = spk,
            .value = value,
            .height = height,
            .is_coinbase = is_coinbase,
        });
    }

    // SAME View.lookup closure as connecttx (PrevOutInfo over the seeded view).
    const View = struct {
        map: *std.AutoHashMap(OutPointKey, ConnectCoin),
        fn lookup(ctx_ptr: *anyopaque, outpoint: *const types.OutPoint) ?validation.PrevOutInfo {
            const me: *@This() = @ptrCast(@alignCast(ctx_ptr));
            const key = OutPointKey{ .hash = outpoint.hash, .index = outpoint.index };
            const coin = me.map.get(key) orelse return null;
            return .{
                .script_pubkey = coin.spk,
                .amount = coin.value,
                .height = coin.height,
                .is_coinbase = coin.is_coinbase,
                .owner_allocator = null,
            };
        }
    };
    var view_ctx = View{ .map = &view };

    // Compute the block hash from the (final) header — used by acceptBlock for
    // the BIP-30 exemption check + script-flag-for-hash selection. We do NOT
    // recompute the merkle root; validation recomputes + compares it itself.
    const block_hash = crypto.computeBlockHash(&block.header);

    const params = consensus.getNetworkParams(.mainnet);

    // Synthesize the canonical-anchor active_chain so the BIP-30/BIP-34
    // short-circuit gate runs EXACTLY as it does on the live node. clearbit's
    // BIP-30 gate (validation.zig:1387) skips the HaveCoin scan once BIP-34 is
    // active — but ONLY when ctx.active_chain holds the canonical BIP34Hash at
    // index params.bip34_height (W79 gate G3; null => conservative gate G4
    // which over-enforces). A real synced node ALWAYS has that anchor by the
    // time it validates a post-BIP34 block, so the validate-only `checkblock`
    // op reproduces it: an array of length spend_height+1 with index
    // bip34_height set to params.bip34_hash (every other slot is irrelevant to
    // the gate). Gated to the BIP-34-active range with a known anchor hash so
    // pre-BIP34 vectors (e.g. h=91000) keep active_chain=null and the BIP-30
    // scan still fires (R1 flagship). Core ref: validation.cpp:2460-2462
    // (pindexBIP34height->GetBlockHash() == params.BIP34Hash).
    var active_chain: ?[]const types.Hash256 = null;
    if (params.bip34_hash) |anchor| {
        if (spend_height >= params.bip34_height) {
            const chain = try a.alloc(types.Hash256, spend_height + 1);
            @memset(chain, [_]u8{0} ** 32);
            chain[params.bip34_height] = anchor;
            active_chain = chain;
        }
    }

    // Drive clearbit's REAL block-accept consensus pipeline at MAINNET params.
    // force_skip_pow mirrors Core's CheckBlock fCheckPOW=false (the FINAL bytes
    // miss the mainnet target by construction). force_skip_scripts honours the
    // request (default false => REAL per-input script verification runs).
    validation.acceptBlock(
        &block,
        &block_hash,
        spend_height,
        params,
        &view_ctx,
        View.lookup,
        a,
        .{ .force_skip_scripts = skip_scripts, .force_skip_pow = skip_pow, .active_chain = active_chain },
    ) catch |err| {
        const reason = try jsonEscape(a, connectErrToReason(err));
        try out.print("{{\"valid\":false,\"reason\":\"{s}\"}}\n", .{reason});
        return;
    };

    try out.writeAll("{\"valid\":true}\n");
}

/// Parse a 32-byte big-endian hex work value into a [32]u8 (BE) buffer.
fn parseWork256(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.WorkHexLen;
    var out: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = (try hexNibble(hex[i * 2]) << 4) | (try hexNibble(hex[i * 2 + 1]));
    }
    return out;
}

/// One coin parsed from a request "fork_utxo" / "undo[].vin" entry.
const ReorgCoin = struct {
    txid_wire: [32]u8,
    vout: u32,
    spk: []const u8,
    value: i64,
    height: u32,
    is_coinbase: bool,
};

fn parseReorgCoin(a: std.mem.Allocator, po: std.json.ObjectMap) !ReorgCoin {
    const txid_disp = switch (po.get("txid") orelse return error.CoinMissingTxid) {
        .string => |s| s,
        else => return error.CoinTxidNotString,
    };
    const disp = try hexDecode(a, txid_disp);
    if (disp.len != 32) return error.CoinTxidLen;
    var wire: [32]u8 = undefined;
    for (0..32) |i| wire[i] = disp[31 - i];
    const vout: u32 = switch (po.get("vout") orelse return error.CoinMissingVout) {
        .integer => |iv| @truncate(@as(u64, @bitCast(iv))),
        else => return error.CoinVoutNotInt,
    };
    const spk = try hexDecode(a, switch (po.get("scriptPubKey_hex") orelse return error.CoinMissingSpk) {
        .string => |s| s,
        else => return error.CoinSpkNotString,
    });
    const value: i64 = switch (po.get("value_sats") orelse return error.CoinMissingValue) {
        .integer => |iv| iv,
        else => return error.CoinValueNotInt,
    };
    const height: u32 = switch (po.get("height") orelse return error.CoinMissingHeight) {
        .integer => |iv| @intCast(iv),
        else => return error.CoinHeightNotInt,
    };
    const is_coinbase: bool = switch (po.get("is_coinbase") orelse return error.CoinMissingIsCoinbase) {
        .bool => |b| b,
        else => return error.CoinIsCoinbaseNotBool,
    };
    return .{ .txid_wire = wire, .vout = vout, .spk = spk, .value = value, .height = height, .is_coinbase = is_coinbase };
}

/// Append a coin's canonical digest bytes (matching the rustoshi-side
/// view_digest format the corpus goldens were computed with):
///   wire_txid[32] || vout u32 LE || height u32 LE || is_coinbase u8
///   || value u64 LE || spk_len u32 LE || spk
fn appendCoinDigestBytes(buf: *std.ArrayList(u8), c: ReorgCoin) !void {
    try buf.appendSlice(&c.txid_wire);
    var tmp4: [4]u8 = undefined;
    std.mem.writeInt(u32, &tmp4, c.vout, .little);
    try buf.appendSlice(&tmp4);
    std.mem.writeInt(u32, &tmp4, c.height, .little);
    try buf.appendSlice(&tmp4);
    try buf.append(if (c.is_coinbase) 1 else 0);
    var tmp8: [8]u8 = undefined;
    std.mem.writeInt(u64, &tmp8, @bitCast(c.value), .little);
    try buf.appendSlice(&tmp8);
    std.mem.writeInt(u32, &tmp4, @intCast(c.spk.len), .little);
    try buf.appendSlice(&tmp4);
    try buf.appendSlice(c.spk);
}

/// sha256 over the sorted (wire_txid, vout) canonical coins-view.
fn coinsViewDigest(a: std.mem.Allocator, coins: []ReorgCoin) ![64]u8 {
    std.mem.sort(ReorgCoin, coins, {}, struct {
        fn lt(_: void, x: ReorgCoin, y: ReorgCoin) bool {
            const c = std.mem.order(u8, &x.txid_wire, &y.txid_wire);
            if (c != .eq) return c == .lt;
            return x.vout < y.vout;
        }
    }.lt);
    var buf = std.ArrayList(u8).init(a);
    defer buf.deinit();
    for (coins) |c| try appendCoinDigestBytes(&buf, c);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(buf.items, &digest, .{});
    var hexbuf: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hexbuf, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;
    return hexbuf;
}

/// `reorg` op: DECISION-FIRST differential reorg. Drives clearbit's REAL
/// mechanism-layer reorg (storage.zig::reorgToChainWithOptions →
/// disconnectBlockByHashCFNoFlush + validation.acceptBlock +
/// connectBlockFastWithUndoNoFlush + peer.zig::cmpChainWorkBE), NOT the
/// P2P/activateBestChain decision layer (which reads live tip / first-seen).
///
/// Pipeline mirroring the reorgToChain contract exactly:
///   (1) work-compare: cmpChainWorkBE(new, old) — STRICT new>old, else
///       outcome=no-reorg-equal-or-less-work and the seeded view is untouched.
///   (2) seed an explicit RocksDB-backed ChainState with the WORKING coins-view
///       (fork_utxo), set network params so reorg-connect re-validation runs.
///   (3) for the disconnect side, stage the old-branch block bodies + the
///       explicit undo into CF_BLOCKS / CF_BLOCK_UNDO and set the tip, then
///       reorgToChainWithOptions walks them tip-first through the REAL
///       disconnectBlockByHashCFInner (4-field identity check + ApplyTxInUndo
///       + BIP30 exemption).
///   (4) connect side: each block re-validated via the REAL acceptBlock at its
///       own height (full scripts+economics; force_skip_pow for the crafted
///       headers), stopping at the first reject (connected_count = blocks that
///       passed before it).
///   (5) digest = sha256 over clearbit's REAL post-reorg coins-view.
fn processReorg(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const network = try parseNetwork(switch (obj.get("network") orelse return error.MissingNetwork) {
        .string => |s| s,
        else => return error.NetworkNotString,
    });
    const old_work = try parseWork256(switch (obj.get("old_tip_work_hex") orelse return error.MissingOldWork) {
        .string => |s| s,
        else => return error.OldWorkNotString,
    });
    const new_work = try parseWork256(switch (obj.get("new_tip_work_hex") orelse return error.MissingNewWork) {
        .string => |s| s,
        else => return error.NewWorkNotString,
    });

    const peer = @import("peer.zig");

    // Parse fork_utxo (the WORKING coins-view) into ReorgCoin[].
    var fork_coins = std.ArrayList(ReorgCoin).init(a);
    const fork_arr = (obj.get("fork_utxo") orelse return error.MissingForkUtxo).array.items;
    for (fork_arr) |c| try fork_coins.append(try parseReorgCoin(a, c.object));

    // ---- (1) work-compare: STRICT new>old via the REAL BE-256 comparator ----
    if (peer.cmpChainWorkBE(&new_work, &old_work) <= 0) {
        // No reorg: the view is UNTOUCHED. Digest the seeded fork_utxo directly
        // (clearbit never opens a chainstate or evaluates any block here).
        const digest = try coinsViewDigest(a, fork_coins.items);
        try out.print(
            "{{\"outcome\":\"no-reorg-equal-or-less-work\",\"connected_count\":0,\"fork_utxo_digest\":\"{s}\"}}\n",
            .{digest},
        );
        return;
    }

    // ---- (2) seed an explicit RocksDB-backed ChainState ----
    const params = consensus.getNetworkParams(network);

    // Unique temp dir per request so concurrent runs never collide.
    var seed_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&seed_bytes);
    const tmp_path = try std.fmt.allocPrint(a, "/tmp/clearbit-reorg-{x}-{d}", .{
        std.fmt.fmtSliceHexLower(&seed_bytes), std.time.milliTimestamp(),
    });
    std.fs.cwd().makePath(tmp_path) catch {};
    defer std.fs.cwd().deleteTree(tmp_path) catch {};

    var db = storage.Database.open(tmp_path, 64, a) catch |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"error\":\"db open: {s}\"}}\n", .{reason});
        return;
    };
    defer db.close();

    var cs = storage.ChainState.initWithUndo(&db, 256, tmp_path, a);
    defer cs.deinit();
    cs.wireUtxoParent();
    // CRITICAL: set network params so the reorg-connect side runs FULL script
    // re-validation (else the network_params==null branch skips scripts and
    // the flagship R1/R9 false-accept guard becomes a dead gate).
    cs.setNetworkParams(params);

    // Seed the WORKING coins-view (pre-disconnect view for disconnect vectors,
    // fork-point view otherwise) into the REAL utxo_set.
    for (fork_coins.items) |c| {
        const op = types.OutPoint{ .hash = c.txid_wire, .index = c.vout };
        const txout = types.TxOut{ .value = c.value, .script_pubkey = c.spk };
        try cs.utxo_set.add(&op, &txout, c.height, c.is_coinbase);
    }

    const disc_arr: []const std.json.Value = if (obj.get("disconnect")) |d| switch (d) {
        .array => |arr| arr.items,
        else => &[_]std.json.Value{},
    } else &[_]std.json.Value{};
    const conn_arr: []const std.json.Value = if (obj.get("connect")) |c| switch (c) {
        .array => |arr| arr.items,
        else => &[_]std.json.Value{},
    } else &[_]std.json.Value{};

    var fork_point: types.Hash256 = [_]u8{0} ** 32;

    // ---- (3) disconnect side ----
    // Two faithful sub-paths into the SAME reorgToChainWithOptions:
    //   (a) depth-cap probe (disconnect.len > MAX_REORG_DEPTH): build a REAL
    //       linked coinbase-only old chain of that depth via the production
    //       connectBlockFastWithUndo, so the disconnect WALK hits the
    //       MAX_REORG_DEPTH=288 cap and returns error.ReorgTooDeep. The corpus
    //       block bytes for this case are placeholders signalling "N deep".
    //   (b) normal disconnect: stage each given old block body + explicit undo
    //       into CF_BLOCKS/CF_BLOCK_UNDO and set the tip; reorgToChain walks
    //       them through the REAL disconnectBlockByHashCFInner.
    const depth_cap_probe = disc_arr.len > storage.ChainState.MAX_REORG_DEPTH;

    if (depth_cap_probe) {
        // The production cap is PRUNED-mode semantics: reorgDepthCap()
        // returns MAX_REORG_DEPTH(288) only when prune_target_mib != 0 and
        // maxInt on an archive node (Core-parity — Core has no fixed cap and
        // an archive node's undo data is unbounded).  The fleet runs pruned
        // (prune=10000), and the R10 corpus vector encodes the pruned bound,
        // so the probe must present a PRUNED chainstate — without this the
        // scratch cs is archive, the cap is maxInt, and the 289-deep reorg
        // APPLIES (the standing reorg_prove_clearbit divergence, ≥1wk red,
        // root-caused 2026-07-20).
        cs.prune_target_mib = 10000;
        // Build a linked coinbase-only old chain of disc_arr.len blocks.
        var prev: [32]u8 = [_]u8{0} ** 32;
        var hh: u32 = 1;
        while (hh <= disc_arr.len) : (hh += 1) {
            const blk = try makeCoinbaseOnlyBlock(a, prev, hh);
            const bh = crypto.computeBlockHash(&blk.header);
            var w = serialize.Writer.init(a);
            try serialize.writeBlock(&w, &blk);
            const body: []u8 = @constCast(try w.toOwnedSlice());
            try cs.queueBlockWrite(&bh, body, hh);
            try cs.connectBlockFastWithUndo(&blk, &bh, hh);
            prev = bh;
        }
        // fork_point = genesis (all-zero) so the walk must rewind every block.
        fork_point = [_]u8{0} ** 32;
    } else if (disc_arr.len > 0) {
        // Stage each disconnect block (tip-first order in the corpus) into the
        // CFs, chaining best_hash/best_height to the deepest. We push them so
        // that block[0] is the tip; each block's prev_block is its parent.
        // The corpus single-disconnect vectors use prev_block=0, so after
        // disconnecting block[0] the tip rewinds to 0 = fork_point.
        // For a multi-block (linked) disconnect, the corpus chains them.
        var idx: usize = disc_arr.len;
        // Store all bodies + undo first.
        while (idx > 0) {
            idx -= 1;
            const dobj = disc_arr[idx].object;
            const block_hex = switch (dobj.get("block_hex") orelse return error.DiscMissingBlockHex) {
                .string => |s| s,
                else => return error.DiscBlockHexNotString,
            };
            const block_bytes = try hexDecode(a, block_hex);
            var rdr = serialize.Reader{ .data = block_bytes };
            const blk = serialize.readBlock(&rdr, a) catch |err| {
                const reason = try jsonEscape(a, @errorName(err));
                try out.print("{{\"error\":\"disconnect block deserialize: {s}\"}}\n", .{reason});
                return;
            };
            const bh = crypto.computeBlockHash(&blk.header);
            const height: u32 = switch (dobj.get("height") orelse return error.DiscMissingHeight) {
                .integer => |iv| @intCast(iv),
                else => return error.DiscHeightNotInt,
            };
            // Store block body in CF_BLOCKS (disconnect reads it to remove
            // created outputs).
            try db.put(storage.CF_BLOCKS, &bh, block_bytes);
            // Build + store the explicit undo in CF_BLOCK_UNDO.
            const undo_bytes = try buildUndoBytes(a, dobj);
            try db.put(storage.CF_BLOCK_UNDO, &bh, undo_bytes);
            // The tip is the FIRST corpus entry (disc_arr[0]); the fork point
            // is the parent of the LAST (deepest) entry.
            if (idx == 0) {
                cs.best_hash = bh;
                cs.best_height = height;
            }
            if (idx == disc_arr.len - 1) {
                fork_point = blk.header.prev_block;
            }
        }
    }

    // ---- forward-only fork-point + tip setup ----
    // With no disconnect, the side branch grows directly from the fork point.
    // The corpus crafts each connect block with prev_block=0 (the synthetic
    // fork sentinel) and contiguous heights H, H+1, ...; the fork point is the
    // synthetic parent of the FIRST connect block at height H-1.
    if (disc_arr.len == 0 and conn_arr.len > 0) {
        const first_h: u32 = switch (conn_arr[0].object.get("height") orelse return error.ConnMissingHeight) {
            .integer => |iv| @intCast(iv),
            else => return error.ConnHeightNotInt,
        };
        fork_point = [_]u8{0} ** 32;
        cs.best_hash = fork_point;
        cs.best_height = if (first_h > 0) first_h - 1 else 0;
    }

    // ---- build the new_chain ReorgBlock[] (ordered side-branch blocks) ----
    // RELINK: clearbit's reorgToChain enforces a STRICT parent linkage
    // (entry.block.header.prev_block == running tip) on every connect block —
    // a real side branch is internally chained.  The crafted corpus blocks
    // all carry prev_block=0 (rustoshi's op derived linkage implicitly from
    // order), so we set each block's prev_block to its actual parent (fork
    // point for the first, the prior connect block's recomputed hash for the
    // rest) and recompute the hash.  This touches ONLY the header parent
    // pointer — txids, scripts, amounts, merkle root and heights are
    // unchanged, so the REAL re-validation (acceptBlock) runs over identical
    // consensus content; we just give clearbit the explicit chaining its
    // mechanism layer requires.
    var new_chain = std.ArrayList(storage.ChainState.ReorgBlock).init(a);
    var running_parent: types.Hash256 = fork_point;
    for (conn_arr) |c| {
        const cobj = c.object;
        const block_hex = switch (cobj.get("block_hex") orelse return error.ConnMissingBlockHex) {
            .string => |s| s,
            else => return error.ConnBlockHexNotString,
        };
        const block_bytes = try hexDecode(a, block_hex);
        var rdr = serialize.Reader{ .data = block_bytes };
        var blk = serialize.readBlock(&rdr, a) catch |err| {
            const reason = try jsonEscape(a, @errorName(err));
            try out.print("{{\"error\":\"connect block deserialize: {s}\"}}\n", .{reason});
            return;
        };
        const height: u32 = switch (cobj.get("height") orelse return error.ConnMissingHeight) {
            .integer => |iv| @intCast(iv),
            else => return error.ConnHeightNotInt,
        };
        blk.header.prev_block = running_parent;
        const bh = crypto.computeBlockHash(&blk.header);
        running_parent = bh;
        try new_chain.append(.{ .hash = bh, .block = blk, .height = height });
    }

    // ---- (4) drive the REAL reorg mechanism ----
    var drive_result = storage.ChainState.ReorgDriveResult{};
    const drive_opts = storage.ChainState.ReorgDriveOptions{
        .connect_force_skip_pow = true, // crafted nonce=0 headers (Core fCheckPOW=false)
        .tolerate_unclean_disconnect = true, // UNCLEAN is logged-but-continue (Core ApplyTxInUndo)
    };
    const reorg_res = cs.reorgToChainWithOptions(&fork_point, new_chain.items, drive_opts, &drive_result);

    const disc_result_str: []const u8 = if (drive_result.disconnect_unclean) "unclean" else "ok";

    if (reorg_res) |connected| {
        // reorg-applied. Compute the digest over clearbit's REAL final view.
        const digest = try computeFinalDigest(a, &cs, fork_coins.items, disc_arr, conn_arr);
        try out.print(
            "{{\"outcome\":\"reorg-applied\",\"disconnect_result\":\"{s}\",\"connected_count\":{d},\"fork_utxo_digest\":\"{s}\"}}\n",
            .{ disc_result_str, connected, digest },
        );
    } else |err| {
        if (err == error.ReorgTooDeep) {
            try out.print("{{\"outcome\":\"reorg-too-deep\",\"disconnect_result\":\"{s}\"}}\n", .{disc_result_str});
            return;
        }
        // Connect-side validation reject (error.ReorgBlockInvalid) or a
        // disconnect-side hard failure. Map the recorded validation error to
        // the canonical Core reject token; the OUTCOME is what is scored.
        const reason: []const u8 = if (drive_result.connect_reject_err) |verr|
            connectErrToReason(verr)
        else
            @errorName(err);
        const esc = try jsonEscape(a, reason);
        try out.print(
            "{{\"outcome\":\"reorg-rejected\",\"disconnect_result\":\"{s}\",\"connected_count\":{d},\"reject_reason\":\"{s}\"}}\n",
            .{ disc_result_str, drive_result.connected_before_reject, esc },
        );
    }
}

/// Build a coinbase-only block at the given height with prev_block linkage.
/// Used only to synthesize a deep linked old chain for the R10 depth-cap probe.
fn makeCoinbaseOnlyBlock(a: std.mem.Allocator, prev: [32]u8, height: u32) !types.Block {
    var ssig = std.ArrayList(u8).init(a);
    // BIP34-ish height push + filler, kept >= 2 bytes.
    var h = height;
    var le = std.ArrayList(u8).init(a);
    while (h > 0) {
        try le.append(@intCast(h & 0xFF));
        h >>= 8;
    }
    if (le.items.len == 0) try le.append(0);
    try ssig.append(@intCast(le.items.len));
    try ssig.appendSlice(le.items);
    try ssig.append(0x00);
    const cb_in = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = try ssig.toOwnedSlice(),
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const cb_out = types.TxOut{ .value = 5000000000, .script_pubkey = try a.dupe(u8, &[_]u8{0x51}) };
    const cb_tx = types.Transaction{
        .version = 1,
        .inputs = try a.dupe(types.TxIn, &[_]types.TxIn{cb_in}),
        .outputs = try a.dupe(types.TxOut, &[_]types.TxOut{cb_out}),
        .lock_time = 0,
    };
    return types.Block{
        .header = types.BlockHeader{
            .version = 1,
            .prev_block = prev,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = 0x7FFFFFFE,
            .bits = 0x207FFFFF,
            .nonce = height, // unique nonce per height => unique block hash
        },
        .transactions = try a.dupe(types.Transaction, &[_]types.Transaction{cb_tx}),
    };
}

/// Build CF_BLOCK_UNDO bytes for a disconnect block from its "undo" array.
/// Each undo entry has tx_index + vin[] of coins (the prevouts that tx spent).
/// We assemble a storage.BlockUndoData with one TxUndo per NON-coinbase tx in
/// the block (tx_undo[i] ↔ block.transactions[i+1]), populating only the
/// indices the corpus lists and leaving the rest empty.
fn buildUndoBytes(a: std.mem.Allocator, dobj: std.json.ObjectMap) ![]const u8 {
    const block_hex = switch (dobj.get("block_hex").?) {
        .string => |s| s,
        else => return error.DiscBlockHexNotString,
    };
    const block_bytes = try hexDecode(a, block_hex);
    var rdr = serialize.Reader{ .data = block_bytes };
    const blk = try serialize.readBlock(&rdr, a);
    const n_noncoinbase = blk.transactions.len - 1;

    var tx_undo = try a.alloc(storage.TxUndo, n_noncoinbase);
    for (tx_undo) |*t| t.* = .{ .prev_outputs = &[_]storage.TxUndo.TxOut{} };

    if (dobj.get("undo")) |uv| {
        if (uv == .array) {
            for (uv.array.items) |entry| {
                const eobj = entry.object;
                const tx_index: usize = switch (eobj.get("tx_index") orelse return error.UndoMissingTxIndex) {
                    .integer => |iv| @intCast(iv),
                    else => return error.UndoTxIndexNotInt,
                };
                if (tx_index == 0 or tx_index > n_noncoinbase) return error.UndoTxIndexRange;
                const vin = (eobj.get("vin") orelse return error.UndoMissingVin).array.items;
                var outs = try a.alloc(storage.TxUndo.TxOut, vin.len);
                for (vin, 0..) |vc, vi| {
                    const coin = try parseReorgCoin(a, vc.object);
                    outs[vi] = .{
                        .value = coin.value,
                        .script_pubkey = coin.spk,
                        .height = coin.height,
                        .is_coinbase = coin.is_coinbase,
                    };
                }
                tx_undo[tx_index - 1] = .{ .prev_outputs = outs };
            }
        }
    }

    var bud = storage.BlockUndoData{ .tx_undo = tx_undo };
    return bud.toBytes(a);
}

/// Compute the digest over clearbit's REAL post-reorg coins-view by probing
/// every candidate outpoint (fork_utxo ∪ disconnect-created ∪ undo-restored ∪
/// connect-created ∪ connect-spent) against the REAL utxo_set and including
/// only those clearbit reports LIVE — with clearbit's own stored coin data.
fn computeFinalDigest(
    a: std.mem.Allocator,
    cs: *storage.ChainState,
    fork_coins: []ReorgCoin,
    disc_arr: []const std.json.Value,
    conn_arr: []const std.json.Value,
) ![64]u8 {
    var candidates = std.AutoHashMap(OutPointKey, void).init(a);

    // fork_utxo outpoints.
    for (fork_coins) |c| try candidates.put(.{ .hash = c.txid_wire, .index = c.vout }, {});

    // disconnect blocks: their created outputs + their undo-restored prevouts.
    for (disc_arr) |dv| {
        const dobj = dv.object;
        if (dobj.get("block_hex")) |bh| {
            if (bh == .string) {
                const bytes = try hexDecode(a, bh.string);
                var rdr = serialize.Reader{ .data = bytes };
                if (serialize.readBlock(&rdr, a)) |blk| {
                    for (blk.transactions) |tx| {
                        const txid = crypto.computeTxidStreaming(&tx);
                        for (0..tx.outputs.len) |o| try candidates.put(.{ .hash = txid, .index = @intCast(o) }, {});
                        for (tx.inputs) |in| try candidates.put(.{ .hash = in.previous_output.hash, .index = in.previous_output.index }, {});
                    }
                } else |_| {}
            }
        }
        if (dobj.get("undo")) |uv| {
            if (uv == .array) for (uv.array.items) |entry| {
                if (entry.object.get("vin")) |vv| if (vv == .array) for (vv.array.items) |vc| {
                    const coin = try parseReorgCoin(a, vc.object);
                    try candidates.put(.{ .hash = coin.txid_wire, .index = coin.vout }, {});
                };
            };
        }
    }

    // connect blocks: their created outputs + spent inputs.
    for (conn_arr) |cv| {
        const cobj = cv.object;
        if (cobj.get("block_hex")) |bh| if (bh == .string) {
            const bytes = try hexDecode(a, bh.string);
            var rdr = serialize.Reader{ .data = bytes };
            if (serialize.readBlock(&rdr, a)) |blk| {
                for (blk.transactions) |tx| {
                    const txid = crypto.computeTxidStreaming(&tx);
                    for (0..tx.outputs.len) |o| try candidates.put(.{ .hash = txid, .index = @intCast(o) }, {});
                    for (tx.inputs) |in| try candidates.put(.{ .hash = in.previous_output.hash, .index = in.previous_output.index }, {});
                }
            } else |_| {}
        };
    }

    // Probe each candidate against the REAL utxo_set; collect the live coins
    // with clearbit's own stored value/height/is_coinbase + reconstructed spk.
    var live = std.ArrayList(ReorgCoin).init(a);
    var it = candidates.keyIterator();
    while (it.next()) |k| {
        const op = types.OutPoint{ .hash = k.hash, .index = k.index };
        if (cs.utxo_set.get(&op) catch null) |compact_const| {
            var compact = compact_const;
            defer compact.deinit(a);
            const spk = try compact.reconstructScript(a);
            try live.append(.{
                .txid_wire = k.hash,
                .vout = k.index,
                .spk = spk,
                .value = compact.value,
                .height = compact.height,
                .is_coinbase = compact.is_coinbase,
            });
        }
    }

    return coinsViewDigest(a, live.items);
}

/// Parse an 8-hex compact-bits string (Core getblockheader "bits" format,
/// big-endian hex of the u32) into a u32. Errors (=> {"error"}, driver
/// SKIPS) on any malformed input rather than fabricating a value.
fn parseBits(hex: []const u8) !u32 {
    if (hex.len != 8) return error.BitsHexLen;
    var v: u32 = 0;
    for (hex) |c| v = (v << 4) | @as(u32, try hexNibble(c));
    return v;
}

/// Map the request "network" token to clearbit's consensus.Network enum.
fn parseNetwork(name: []const u8) !consensus.Network {
    if (std.mem.eql(u8, name, "mainnet")) return .mainnet;
    if (std.mem.eql(u8, name, "testnet3")) return .testnet3;
    if (std.mem.eql(u8, name, "testnet4")) return .testnet4;
    if (std.mem.eql(u8, name, "regtest")) return .regtest;
    if (std.mem.eql(u8, name, "signet")) return .signet;
    return error.UnknownNetwork;
}

/// Read one {"height","bits","time"} chain node into a consensus.BlockIndexEntry.
fn readNode(obj: std.json.ObjectMap) !consensus.BlockIndexEntry {
    const h: u32 = switch (obj.get("height") orelse return error.NodeMissingHeight) {
        .integer => |iv| @intCast(iv),
        else => return error.NodeHeightNotInt,
    };
    const bits_hex = switch (obj.get("bits") orelse return error.NodeMissingBits) {
        .string => |s| s,
        else => return error.NodeBitsNotString,
    };
    const t: u32 = switch (obj.get("time") orelse return error.NodeMissingTime) {
        .integer => |iv| @intCast(iv),
        else => return error.NodeTimeNotInt,
    };
    return .{ .height = h, .timestamp = t, .bits = try parseBits(bits_hex) };
}

/// Map a ContextualCheckBlockHeader / CheckBlockHeader ValidationError to the
/// canonical Core BIP22 reject token for the `checkheader` op. CRITICAL: this
/// DIFFERS from `connectErrToReason` on `BadDifficulty` — at the header level
/// Core folds BOTH "nBits malformed / target > powLimit" (clearbit's
/// `BadDifficulty` out of `checkBlockHeader`) AND "hash > target"
/// (`BadProofOfWork`) into the SINGLE token "high-hash" (CheckBlockHeader,
/// validation.cpp). `BadDifficulty` only means "bad-diffbits" when it comes
/// out of the CONTEXTUAL nBits!=GetNextWorkRequired gate. The checkheader op
/// distinguishes the two by WHICH stage raised it (see processCheckheader):
/// the high-hash stage maps its `BadDifficulty` to "high-hash" before calling
/// here, so by the time this maps `BadDifficulty` it is the contextual
/// bad-diffbits gate. Reasons are advisory; the accept/reject DECISION is scored.
fn checkheaderErrToReason(err: validation.ValidationError) []const u8 {
    return switch (err) {
        // Contextual nBits!=GetNextWorkRequired (validation.cpp:4088).
        error.BadDifficulty => "bad-diffbits",
        // CheckBlockHeader hash>target / target>powLimit (validation.cpp).
        error.BadProofOfWork => "high-hash",
        // ContextualCheckBlockHeader time / version gates.
        error.BadTimestamp => "time-too-old",
        error.TimewarpAttack => "time-timewarp-attack",
        error.FutureTimestamp => "time-too-new",
        error.BadVersion => "bad-version",
        else => @errorName(err),
    };
}

/// `checkheader` op: DECISION-FIRST header-level reject differential. Drives
/// clearbit's REAL header gates over an EXPLICIT (header, prev-context) tuple —
/// never a live tip/clock. This is the header-only differential the `checkblock`
/// op cannot reach in isolation: it exercises Core's CheckBlockHeader (high-hash)
/// + ContextualCheckBlockHeader (bad-diffbits / time-too-old / timewarp /
/// time-too-new / bad-version) directly.
///
/// It drives the two REAL consensus functions:
///   - `validation.checkBlockHeader(&header, params)` (validation.zig:642 — the
///      STRICT path enforcing target<=powLimit AND hash<=target) for the
///      `high-hash` class, when `skip_pow=false`. clearbit raises `BadDifficulty`
///      for target>powLimit and `BadProofOfWork` for hash>target; BOTH are
///      Core's single "high-hash" token, so we remap them to "high-hash" here.
///   - `validation.contextualCheckBlockHeader(&header, height, params, ctx)`
///      (validation.zig — the SAME function validateBlockForIBD calls, so the
///      gate set cannot drift) for bad-diffbits / time-too-old / timewarp /
///      time-too-new / bad-version.
///
/// `expected_bits` is computed HERE via the SAME `consensus.getNextWorkRequired`
/// the `nextwork` op differentially tests, now at DECISION level: build a
/// height-keyed ancestors map from the supplied `prev` (at height-1) plus an
/// optional `first` (at the period start, for retarget-boundary rows) and
/// recompute the mandated nBits, then let `contextualCheckBlockHeader` compare
/// it against the header's claimed bits (the bad-diffbits gate — THE flagship
/// false-accept guard). An explicit `expected_bits` request override isolates
/// the timewarp gate (diffbits made a no-op) exactly as the corpus requires.
///
///   request:  {"op":"checkheader","network":"mainnet|testnet4|regtest|...",
///              "header_hex":"<80-byte header>","height":<u32>,
///              "prev":{"bits":"<8hex>","time":<u32>,"hash":"<display-hex>"},
///              "first":{"height":<u32>,"time":<u32>,"bits":"<8hex>"}  // opt; boundary
///              "mtp":<u32 median-time-past of prev's 11 ancestors>,
///              "current_time":<i64; 0 = disable time-too-new (sentinel)>,
///              "skip_pow":<bool; false = exercise high-hash, true = bypass>,
///              "expected_bits":"<8hex>"  // opt override; else GetNextWorkRequired}
///   response: {"accept":true} | {"accept":false,"reason":"<bip22 token>"}
///             {"error":"..."}  (could not evaluate => driver SKIPS)
fn processCheckheader(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const network = try parseNetwork(switch (obj.get("network") orelse return error.MissingNetwork) {
        .string => |s| s,
        else => return error.NetworkNotString,
    });
    const params = consensus.getNetworkParams(network);

    const header_hex = switch (obj.get("header_hex") orelse return error.MissingHeaderHex) {
        .string => |s| s,
        else => return error.HeaderHexNotString,
    };
    const header_bytes = try hexDecode(a, header_hex);
    if (header_bytes.len != 80) return error.HeaderHexLen;
    var hdr_reader = serialize.Reader{ .data = header_bytes };
    const header = serialize.readBlockHeader(&hdr_reader) catch |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"error\":\"header deserialize: {s}\"}}\n", .{reason});
        return;
    };

    const height: u32 = switch (obj.get("height") orelse return error.MissingHeight) {
        .integer => |iv| @intCast(iv),
        else => return error.HeightNotInt,
    };
    const current_time: i64 = blk: {
        if (obj.get("current_time")) |v| switch (v) {
            .integer => |iv| break :blk iv,
            else => break :blk 0,
        };
        break :blk 0;
    };
    // skip_pow defaults FALSE for checkheader: the whole point is to drive the
    // strict checkBlockHeader over a crafted header (unlike checkblock, whose
    // mutated body no longer meets target so it defaults skip_pow=true).
    const skip_pow: bool = blk: {
        if (obj.get("skip_pow")) |v| switch (v) {
            .bool => |b| break :blk b,
            else => break :blk false,
        };
        break :blk false;
    };

    // prev-context: bits (bad-diffbits base / BIP-94 floor), time (timewarp
    // prev-600 floor + min-difficulty walk-back).
    const prev = switch (obj.get("prev") orelse return error.MissingPrev) {
        .object => |o| o,
        else => return error.PrevNotObject,
    };
    const prev_bits = try parseBits(switch (prev.get("bits") orelse return error.PrevMissingBits) {
        .string => |s| s,
        else => return error.PrevBitsNotString,
    });
    const prev_time: u32 = switch (prev.get("time") orelse return error.PrevMissingTime) {
        .integer => |iv| @intCast(iv),
        else => return error.PrevTimeNotInt,
    };

    // MTP of prev's 11 ancestors, supplied directly (drives time-too-old).
    const mtp: u32 = blk: {
        if (obj.get("mtp")) |v| switch (v) {
            .integer => |iv| break :blk @intCast(iv),
            else => break :blk 0,
        };
        break :blk 0;
    };

    // ---- Stage 1: high-hash (CheckBlockHeader, strict PoW path) ----
    // Core CheckBlockHeader folds hash>target AND target>powLimit (nBits
    // malformed) into the single "high-hash" token. clearbit raises
    // BadProofOfWork for the former and BadDifficulty for the latter; remap
    // BOTH to "high-hash" here so the contextual bad-diffbits gate is the ONLY
    // source of the "bad-diffbits" token.
    if (!skip_pow) {
        if (validation.checkBlockHeader(&header, params)) |_| {
            // PoW ok; fall through to the contextual gates.
        } else |_| {
            try out.writeAll("{\"accept\":false,\"reason\":\"high-hash\"}\n");
            return;
        }
    }

    // ---- expected_bits = GetNextWorkRequired(pindexPrev) ----
    // Honor an explicit override; else recompute from a height-keyed ancestors
    // map (prev at height-1, optional first at the period start) via clearbit's
    // REAL retarget fn — the SAME getNextWorkRequired the nextwork op tests.
    const expected_bits: u32 = blk: {
        if (obj.get("expected_bits")) |v| {
            switch (v) {
                .string => |s| break :blk try parseBits(s),
                else => {},
            }
        }
        // Build ancestors: prev keyed at its OWN height (height-1), plus first
        // (period start) on retarget boundaries so ancestor(h-2016) resolves.
        var ancestors = std.AutoHashMap(u32, consensus.BlockIndexEntry).init(a);
        const prev_height = if (height > 0) height - 1 else 0;
        try ancestors.put(prev_height, .{ .height = prev_height, .timestamp = prev_time, .bits = prev_bits });
        if (obj.get("first")) |fv| {
            if (fv == .object) {
                const first_node = try readNode(fv.object);
                try ancestors.put(first_node.height, first_node);
            }
        }
        const view = consensus.BlockIndexView{
            .context = @ptrCast(&ancestors),
            .getAtHeightFn = struct {
                fn get(ctx: *anyopaque, h: u32) ?consensus.BlockIndexEntry {
                    const m: *std.AutoHashMap(u32, consensus.BlockIndexEntry) = @ptrCast(@alignCast(ctx));
                    return m.get(h);
                }
            }.get,
            .pow_limit_bits = consensus.getPowLimitBits(params),
        };
        // getNextWorkRequired takes the height of the block BEING validated
        // (it derives prev_height = height-1 internally) and the new block's
        // timestamp (for the testnet min-difficulty exception).
        break :blk consensus.getNextWorkRequired(height, header.timestamp, &view, params);
    };

    // ---- Stage 2: ContextualCheckBlockHeader (REAL clearbit gate set) ----
    // expected_bits drives the bad-diffbits gate; prev_block_timestamp (=prev.time)
    // drives the BIP-94 timewarp floor; mtp drives time-too-old; current_time
    // drives time-too-new. The SAME function validateBlockForIBD calls.
    if (validation.contextualCheckBlockHeader(&header, height, params, .{
        .prev_mtp = mtp,
        .prev_block_timestamp = prev_time,
        .current_time = current_time,
        .expected_bits = expected_bits,
    })) |_| {
        try out.writeAll("{\"accept\":true}\n");
    } else |err| {
        // bad-version carries the offending nVersion in Core's token
        // (strprintf("bad-version(0x%08x)", block.nVersion), validation.cpp:4116).
        // clearbit's BadVersion error is value-free, so reconstruct the suffix
        // here from the header version (the DECISION is scored; this keeps the
        // advisory token byte-identical to Core for the corpus check).
        if (err == error.BadVersion) {
            try out.print(
                "{{\"accept\":false,\"reason\":\"bad-version(0x{x:0>8})\"}}\n",
                .{@as(u32, @bitCast(header.version))},
            );
            return;
        }
        const reason = try jsonEscape(a, checkheaderErrToReason(err));
        try out.print("{{\"accept\":false,\"reason\":\"{s}\"}}\n", .{reason});
    }
}

/// `nextwork` op: differential PoW. Drives clearbit's REAL
/// consensus.getNextWorkRequired (src/consensus.zig:1031) — the
/// BlockIndex/chain-generic entrypoint that does the retarget, the off-by-one
/// (it reads pindexLast at height-1 and the period's first at
/// (height-1)-(interval-1) = height-2016), the 4x timespan clamps, the
/// powLimit ceiling, and the BIP-94 first-block selection — NOT a value-based
/// or legacy twin.
///
/// We build a tiny 2-node chain in an ancestors map keyed by height:
///   last  at height-1            (always)
///   first at height-2016         (only on retarget boundaries; H%2016==0)
/// and hand getNextWorkRequired a BlockIndexView whose getAtHeightFn closes
/// over that map. On a passthrough (non-boundary) row only `last` is consulted
/// and the impl returns last.bits unchanged.
///
///   request:  {"op":"nextwork","network":"mainnet","height":H,
///              "block_time":<u32>,
///              "last":{"height":..,"bits":"<8hex>","time":..},
///              "first":{...}}     // first present ONLY when H%2016==0
///   response: {"nbits":"<8hex>"}  (the impl's REAL computed required nBits)
///             {"error":"..."}     (could not compute => driver SKIPS)
fn processNextwork(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const network = try parseNetwork(switch (obj.get("network") orelse return error.MissingNetwork) {
        .string => |s| s,
        else => return error.NetworkNotString,
    });
    const height: u32 = switch (obj.get("height") orelse return error.MissingHeight) {
        .integer => |iv| @intCast(iv),
        else => return error.HeightNotInt,
    };
    const block_time: u32 = switch (obj.get("block_time") orelse return error.MissingBlockTime) {
        .integer => |iv| @intCast(iv),
        else => return error.BlockTimeNotInt,
    };

    // Build the ancestors map (height -> entry) from `last` (+ `first` on
    // boundaries). getNextWorkRequired indexes by absolute height, so we key
    // by each node's own height.
    var ancestors = std.AutoHashMap(u32, consensus.BlockIndexEntry).init(a);
    const last_node = try readNode((obj.get("last") orelse return error.MissingLast).object);
    try ancestors.put(last_node.height, last_node);
    if (obj.get("first")) |fv| {
        const first_node = try readNode(fv.object);
        try ancestors.put(first_node.height, first_node);
    }

    const params = consensus.getNetworkParams(network);

    const view = consensus.BlockIndexView{
        .context = @ptrCast(&ancestors),
        .getAtHeightFn = struct {
            fn get(ctx: *anyopaque, h: u32) ?consensus.BlockIndexEntry {
                const m: *std.AutoHashMap(u32, consensus.BlockIndexEntry) = @ptrCast(@alignCast(ctx));
                return m.get(h);
            }
        }.get,
        .pow_limit_bits = consensus.getPowLimitBits(params),
    };

    const nbits = consensus.getNextWorkRequired(height, block_time, &view, params);
    try out.print("{{\"nbits\":\"{x:0>8}\"}}\n", .{nbits});
}

/// `merkleroot` op: differential transaction-merkle-root + CVE-2012-2459
/// mutation reporting. Drives clearbit's REAL merkle primitive
/// (crypto.computeMerkleRoot, src/crypto.zig:621) — the SAME function the
/// block-accept path calls (src/validation.zig:800) to recompute the
/// header merkle root.
///
/// The request `txids` are DISPLAY-order hex (Core getblock convention,
/// big-endian as shown by RPC). The merkle primitive operates on
/// WIRE/internal-order 32-byte hashes, so we reverse each txid to wire
/// order before feeding it in (the exact reversal `verifytx` does on its
/// prevout txids), then reverse the computed internal root back to display
/// order so it matches Core's header `merkleroot`.
///
/// `mutated`: reports what clearbit's REAL block-accept path concludes about a
/// CVE-2012-2459 duplicate-tx malleation. clearbit's merkle check
/// (validation.zig checkBlock) now computes the root via the mutation-aware
/// `computeMerkleRootMutated` (crypto.zig) — Core's adjacent-pair-equal scan at
/// the TOP of each level BEFORE the odd-tail duplication (merkle.cpp:46-63) —
/// and rejects a mutated block with `DuplicateTx` (Core "bad-txns-duplicate").
/// We drive the SAME primitive here and report the real flag: honest rows
/// (including odd-N) report mutated=false, a cve2459 duplicate-tail row reports
/// mutated=true.
///
///   request:  {"op":"merkleroot","txids":["<64-hex display>",...]}
///   response: {"root":"<64-hex display>","mutated":<bool>}
///             {"error":"..."}   (could not compute => driver SKIPS)
fn processMerkleroot(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    const txids = switch (obj.get("txids") orelse return error.MissingTxids) {
        .array => |arr| arr.items,
        else => return error.TxidsNotArray,
    };
    if (txids.len == 0) return error.EmptyTxids;

    // Reverse each DISPLAY-order txid -> WIRE-order Hash256 (same reversal
    // verifytx applies to prevout txids), feeding the impl's merkle code the
    // internal byte order it expects.
    var hashes = try a.alloc(types.Hash256, txids.len);
    for (txids, 0..) |t, i| {
        const txid_disp = switch (t) {
            .string => |s| s,
            else => return error.TxidNotString,
        };
        const disp_bytes = try hexDecode(a, txid_disp);
        if (disp_bytes.len != 32) return error.TxidLen;
        var wire: types.Hash256 = undefined;
        for (0..32) |j| wire[j] = disp_bytes[31 - j];
        hashes[i] = wire;
    }

    // REAL merkle primitive (clearbit's block-accept path uses this exact fn,
    // with the same mutation out-param it now consults to reject CVE-2012-2459).
    var mutated: bool = false;
    const internal_root = crypto.computeMerkleRootMutated(hashes, a, &mutated) catch |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"error\":\"computeMerkleRoot: {s}\"}}\n", .{reason});
        return;
    };

    // Reverse internal-order root -> DISPLAY order to match Core's header
    // merkleroot.
    var disp_root: [32]u8 = undefined;
    for (0..32) |j| disp_root[j] = internal_root[31 - j];

    // mutated: the REAL flag from clearbit's block-accept merkle check.
    try out.print(
        "{{\"root\":\"{s}\",\"mutated\":{s}}}\n",
        .{ std.fmt.bytesToHex(disp_root, .lower), if (mutated) "true" else "false" },
    );
}

/// `subsidy` op: differential block-subsidy. Drives clearbit's REAL
/// consensus.getBlockSubsidy (src/consensus.zig:865) at MAINNET params
/// (consensus.getNetworkParams(.mainnet), halving interval 210000) — the
/// SAME function block validation / ConnectBlock uses for the coinbase
/// output cap. We do NOT reimplement the halving schedule here, so a bug in
/// the impl's fn (halving-boundary off-by-one, missing >=64 zero-guard,
/// shift overflow) surfaces as a divergence.
///
///   request:  {"op":"subsidy","height":<int>}
///   response: {"subsidy_sats":<int>}   (the impl's REAL subsidy in sats)
///             {"error":"..."}          (could not compute => driver SKIPS)
fn processSubsidy(a: std.mem.Allocator, obj: std.json.ObjectMap, out: anytype) !void {
    _ = a;
    const height: u32 = switch (obj.get("height") orelse return error.MissingHeight) {
        .integer => |iv| std.math.cast(u32, iv) orelse return error.HeightOutOfRange,
        else => return error.HeightNotInt,
    };
    const params = consensus.getNetworkParams(.mainnet);
    const subsidy = consensus.getBlockSubsidy(height, params);
    try out.print("{{\"subsidy_sats\":{d}}}\n", .{subsidy});
}

/// Process one request line; dispatches on the JSON "op" field (default
/// "verifyscript" for back-compat). On success writes the response, on
/// failure returns an error which main() turns into {"error":...}.
fn process(allocator: std.mem.Allocator, line: []const u8, out: anytype) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, line, .{});
    const obj = parsed.value.object;

    const op: []const u8 = if (obj.get("op")) |v| switch (v) {
        .string => |s| s,
        else => "verifyscript",
    } else "verifyscript";

    if (std.mem.eql(u8, op, "verifytx")) {
        return processVerifytx(a, obj, out);
    } else if (std.mem.eql(u8, op, "checktx")) {
        return processChecktx(a, obj, out);
    } else if (std.mem.eql(u8, op, "connecttx")) {
        return processConnecttx(a, obj, out);
    } else if (std.mem.eql(u8, op, "checkblock")) {
        return processCheckblock(a, obj, out);
    } else if (std.mem.eql(u8, op, "reorg")) {
        return processReorg(a, obj, out);
    } else if (std.mem.eql(u8, op, "checkheader")) {
        return processCheckheader(a, obj, out);
    } else if (std.mem.eql(u8, op, "nextwork")) {
        return processNextwork(a, obj, out);
    } else if (std.mem.eql(u8, op, "merkleroot")) {
        return processMerkleroot(a, obj, out);
    } else if (std.mem.eql(u8, op, "subsidy")) {
        return processSubsidy(a, obj, out);
    } else if (!std.mem.eql(u8, op, "verifyscript")) {
        return error.UnknownOp;
    }

    const ssig = try hexDecode(a, obj.get("scriptSig_hex").?.string);
    const spk = try hexDecode(a, obj.get("scriptPubKey_hex").?.string);

    const amount: i64 = blk: {
        if (obj.get("amount_sats")) |v| {
            switch (v) {
                .integer => |i| break :blk i,
                else => break :blk 0,
            }
        }
        break :blk 0;
    };

    // Witness: array of hex strings (may be absent / null).
    var witness_list = std.ArrayList([]const u8).init(a);
    if (obj.get("witness")) |w| {
        if (w == .array) {
            for (w.array.items) |item| {
                const hx = switch (item) {
                    .string => |s| s,
                    else => return error.WitnessElemNotString,
                };
                try witness_list.append(try hexDecode(a, hx));
            }
        }
    }
    const witness: []const []const u8 = witness_list.items;

    const flags = try buildFlags(obj.get("flags").?.array.items);

    // --- Build Core's crediting tx (no witness) ---
    const credit_ssig = try a.dupe(u8, &[_]u8{ 0x00, 0x00 }); // OP_0 OP_0
    var credit_inputs = try a.alloc(types.TxIn, 1);
    credit_inputs[0] = .{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xFFFFFFFF },
        .script_sig = credit_ssig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    var credit_outputs = try a.alloc(types.TxOut, 1);
    credit_outputs[0] = .{ .value = amount, .script_pubkey = spk };
    const credit_tx = types.Transaction{
        .version = 1,
        .inputs = credit_inputs,
        .outputs = credit_outputs,
        .lock_time = 0,
    };
    const credit_txid = try computeTxid(a, &credit_tx);

    // --- Build Core's spending tx (carries the test scriptSig+witness) ---
    var spend_inputs = try a.alloc(types.TxIn, 1);
    spend_inputs[0] = .{
        .previous_output = .{ .hash = credit_txid, .index = 0 },
        .script_sig = ssig,
        .sequence = 0xFFFFFFFF,
        .witness = witness,
    };
    var spend_outputs = try a.alloc(types.TxOut, 1);
    spend_outputs[0] = .{ .value = amount, .script_pubkey = &[_]u8{} };
    const spend_tx = types.Transaction{
        .version = 1,
        .inputs = spend_inputs,
        .outputs = spend_outputs,
        .lock_time = 0,
    };

    // Per-input prevout data for the BIP-341 Taproot sighash (single input).
    const spent_amounts = [_]i64{amount};
    const spent_scripts = [_][]const u8{spk};

    var engine = script.ScriptEngine.initWithPrevouts(
        a,
        &spend_tx,
        0,
        amount,
        flags,
        &spent_amounts,
        &spent_scripts,
    );
    defer engine.deinit();

    if (engine.verify(ssig, spk, witness)) |ok| {
        if (ok) {
            try out.writeAll("{\"result\":true}\n");
        } else {
            try out.writeAll("{\"result\":false,\"reason\":\"VerifyFalse\"}\n");
        }
    } else |err| {
        const reason = try jsonEscape(a, @errorName(err));
        try out.print("{{\"result\":false,\"reason\":\"{s}\"}}\n", .{reason});
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Real signature verification needs the libsecp256k1 context up
    // (same as test_script.zig main()).
    _ = crypto.initSecp256k1();
    defer crypto.deinitSecp256k1();

    const stdin = std.io.getStdIn().reader();
    const stdout = std.io.getStdOut().writer();

    var line_buf = std.ArrayList(u8).init(allocator);
    defer line_buf.deinit();

    while (true) {
        line_buf.clearRetainingCapacity();
        stdin.streamUntilDelimiter(line_buf.writer(), '\n', null) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const line = std.mem.trim(u8, line_buf.items, " \t\r\n");
        if (line.len == 0) continue;

        process(allocator, line, stdout) catch |err| {
            const esc = jsonEscape(allocator, @errorName(err)) catch {
                try stdout.writeAll("{\"error\":\"alloc\"}\n");
                continue;
            };
            defer allocator.free(esc);
            try stdout.print("{{\"error\":\"{s}\"}}\n", .{esc});
        };
    }
}
