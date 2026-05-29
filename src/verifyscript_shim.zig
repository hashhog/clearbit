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

const std = @import("std");
const script = @import("script.zig");
const serialize = @import("serialize.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

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

/// Process one request line; on success writes the response, on failure
/// returns an error which main() turns into {"error":...}.
fn process(allocator: std.mem.Allocator, line: []const u8, out: anytype) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, line, .{});
    const obj = parsed.value.object;

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
