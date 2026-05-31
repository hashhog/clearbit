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
        error.InputValuesOutOfRange => "bad-txns-inputvalues-outofrange",
        error.InsufficientFunds => "bad-txns-in-belowout",
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

    // Drive clearbit's REAL block-accept consensus pipeline at MAINNET params.
    // force_skip_pow mirrors Core's CheckBlock fCheckPOW=false (the FINAL bytes
    // miss the mainnet target by construction). force_skip_scripts honours the
    // request (default false => REAL per-input script verification runs).
    validation.acceptBlock(
        &block,
        &block_hash,
        spend_height,
        consensus.getNetworkParams(.mainnet),
        &view_ctx,
        View.lookup,
        a,
        .{ .force_skip_scripts = skip_scripts, .force_skip_pow = skip_pow },
    ) catch |err| {
        const reason = try jsonEscape(a, connectErrToReason(err));
        try out.print("{{\"valid\":false,\"reason\":\"{s}\"}}\n", .{reason});
        return;
    };

    try out.writeAll("{\"valid\":true}\n");
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
