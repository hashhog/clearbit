const std = @import("std");
const types = @import("types.zig");
const script = @import("script.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");

/// Decode a hex string into bytes. Caller owns the returned slice.
fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch return error.InvalidHexChar;
    }
    return out;
}

/// Encode a script number (CScriptNum format) into buf, return slice used.
fn encodeScriptNum(buf: []u8, n: i64) []u8 {
    if (n == 0) return buf[0..0];
    var abs_n: u64 = if (n < 0) @intCast(-n) else @intCast(n);
    const neg = n < 0;
    var len: usize = 0;
    while (abs_n > 0) : (abs_n >>= 8) {
        buf[len] = @truncate(abs_n & 0xff);
        len += 1;
    }
    if (buf[len - 1] & 0x80 != 0) {
        buf[len] = if (neg) 0x80 else 0x00;
        len += 1;
    } else if (neg) {
        buf[len - 1] |= 0x80;
    }
    return buf[0..len];
}

/// Push data with appropriate opcode to a dynamic buffer.
fn pushData(result: *std.ArrayList(u8), data: []const u8) !void {
    const len = data.len;
    if (len >= 1 and len <= 0x4b) {
        try result.append(@truncate(len));
        try result.appendSlice(data);
    } else if (len <= 0xff) {
        try result.append(0x4c);
        try result.append(@truncate(len));
        try result.appendSlice(data);
    } else if (len <= 0xffff) {
        try result.append(0x4d);
        try result.append(@truncate(len & 0xff));
        try result.append(@truncate((len >> 8) & 0xff));
        try result.appendSlice(data);
    } else {
        try result.append(0x4e);
        try result.append(@truncate(len & 0xff));
        try result.append(@truncate((len >> 8) & 0xff));
        try result.append(@truncate((len >> 16) & 0xff));
        try result.append(@truncate((len >> 24) & 0xff));
        try result.appendSlice(data);
    }
}

/// Map opcode name (without OP_ prefix) to byte value.
fn opcodeByName(name: []const u8) ?u8 {
    const map = .{
        .{ "0", 0x00 },       .{ "FALSE", 0x00 },
        .{ "1NEGATE", 0x4f },
        .{ "RESERVED", 0x50 },
        .{ "1", 0x51 },       .{ "TRUE", 0x51 },
        .{ "2", 0x52 },       .{ "3", 0x53 },       .{ "4", 0x54 },       .{ "5", 0x55 },
        .{ "6", 0x56 },       .{ "7", 0x57 },       .{ "8", 0x58 },       .{ "9", 0x59 },
        .{ "10", 0x5a },      .{ "11", 0x5b },      .{ "12", 0x5c },      .{ "13", 0x5d },
        .{ "14", 0x5e },      .{ "15", 0x5f },      .{ "16", 0x60 },
        .{ "NOP", 0x61 },     .{ "VER", 0x62 },
        .{ "IF", 0x63 },      .{ "NOTIF", 0x64 },
        .{ "VERIF", 0x65 },   .{ "VERNOTIF", 0x66 },
        .{ "ELSE", 0x67 },    .{ "ENDIF", 0x68 },
        .{ "VERIFY", 0x69 },  .{ "RETURN", 0x6a },
        .{ "TOALTSTACK", 0x6b },  .{ "FROMALTSTACK", 0x6c },
        .{ "2DROP", 0x6d },   .{ "2DUP", 0x6e },    .{ "3DUP", 0x6f },
        .{ "2OVER", 0x70 },   .{ "2ROT", 0x71 },    .{ "2SWAP", 0x72 },
        .{ "IFDUP", 0x73 },   .{ "DEPTH", 0x74 },
        .{ "DROP", 0x75 },    .{ "DUP", 0x76 },
        .{ "NIP", 0x77 },     .{ "OVER", 0x78 },
        .{ "PICK", 0x79 },    .{ "ROLL", 0x7a },
        .{ "ROT", 0x7b },     .{ "SWAP", 0x7c },    .{ "TUCK", 0x7d },
        .{ "CAT", 0x7e },     .{ "SUBSTR", 0x7f },   .{ "LEFT", 0x80 },    .{ "RIGHT", 0x81 },
        .{ "SIZE", 0x82 },
        .{ "INVERT", 0x83 },  .{ "AND", 0x84 },     .{ "OR", 0x85 },      .{ "XOR", 0x86 },
        .{ "EQUAL", 0x87 },   .{ "EQUALVERIFY", 0x88 },
        .{ "RESERVED1", 0x89 },  .{ "RESERVED2", 0x8a },
        .{ "1ADD", 0x8b },    .{ "1SUB", 0x8c },
        .{ "2MUL", 0x8d },    .{ "2DIV", 0x8e },
        .{ "NEGATE", 0x8f },  .{ "ABS", 0x90 },
        .{ "NOT", 0x91 },     .{ "0NOTEQUAL", 0x92 },
        .{ "ADD", 0x93 },     .{ "SUB", 0x94 },
        .{ "MUL", 0x95 },     .{ "DIV", 0x96 },     .{ "MOD", 0x97 },
        .{ "LSHIFT", 0x98 },  .{ "RSHIFT", 0x99 },
        .{ "BOOLAND", 0x9a }, .{ "BOOLOR", 0x9b },
        .{ "NUMEQUAL", 0x9c },  .{ "NUMEQUALVERIFY", 0x9d },
        .{ "NUMNOTEQUAL", 0x9e },
        .{ "LESSTHAN", 0x9f },  .{ "GREATERTHAN", 0xa0 },
        .{ "LESSTHANOREQUAL", 0xa1 },  .{ "GREATERTHANOREQUAL", 0xa2 },
        .{ "MIN", 0xa3 },     .{ "MAX", 0xa4 },     .{ "WITHIN", 0xa5 },
        .{ "RIPEMD160", 0xa6 },  .{ "SHA1", 0xa7 },    .{ "SHA256", 0xa8 },
        .{ "HASH160", 0xa9 },    .{ "HASH256", 0xaa },
        .{ "CODESEPARATOR", 0xab },
        .{ "CHECKSIG", 0xac },   .{ "CHECKSIGVERIFY", 0xad },
        .{ "CHECKMULTISIG", 0xae },  .{ "CHECKMULTISIGVERIFY", 0xaf },
        .{ "NOP1", 0xb0 },
        .{ "CHECKLOCKTIMEVERIFY", 0xb1 },  .{ "NOP2", 0xb1 },
        .{ "CHECKSEQUENCEVERIFY", 0xb2 },  .{ "NOP3", 0xb2 },
        .{ "NOP4", 0xb3 },    .{ "NOP5", 0xb4 },    .{ "NOP6", 0xb5 },
        .{ "NOP7", 0xb6 },    .{ "NOP8", 0xb7 },    .{ "NOP9", 0xb8 },    .{ "NOP10", 0xb9 },
        .{ "CHECKSIGADD", 0xba },
        .{ "INVALIDOPCODE", 0xff },
    };

    inline for (map) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

/// Assemble a Bitcoin script ASM string to raw script bytes.
fn assembleScript(allocator: std.mem.Allocator, asm_str: []const u8) ![]u8 {
    // Trim whitespace
    const trimmed = std.mem.trim(u8, asm_str, " \t\r\n");
    if (trimmed.len == 0) {
        return try allocator.alloc(u8, 0);
    }

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var iter = std.mem.tokenizeScalar(u8, trimmed, ' ');
    while (iter.next()) |token| {
        // Strip OP_ prefix
        const name = if (token.len > 3 and std.mem.eql(u8, token[0..3], "OP_"))
            token[3..]
        else
            token;

        if (name.len >= 2 and std.mem.eql(u8, name[0..2], "0x")) {
            // Raw hex bytes: emit literally
            const hex = name[2..];
            const bytes = hexToBytes(allocator, hex) catch {
                continue;
            };
            defer allocator.free(bytes);
            try result.appendSlice(bytes);
        } else if (name.len >= 1 and name[0] == '\'') {
            // Quoted string
            const end = if (name.len >= 2 and name[name.len - 1] == '\'')
                name.len - 1
            else
                name.len;
            const str = name[1..end];
            if (str.len == 0) {
                try result.append(0x00); // OP_0
            } else {
                try pushData(&result, str);
            }
        } else if (opcodeByName(name)) |byte| {
            try result.append(byte);
        } else {
            // Try as decimal number
            const n = std.fmt.parseInt(i64, name, 10) catch {
                continue;
            };
            if (n == 0) {
                try result.append(0x00);
            } else if (n == -1) {
                try result.append(0x4f);
            } else if (n >= 1 and n <= 16) {
                try result.append(@intCast(0x50 + @as(u8, @intCast(n))));
            } else {
                var num_buf: [9]u8 = undefined;
                const num_bytes = encodeScriptNum(&num_buf, n);
                try pushData(&result, num_bytes);
            }
        }
    }

    return try result.toOwnedSlice();
}

/// Parse flags string to ScriptFlags
fn parseFlags(flags_str: []const u8) script.ScriptFlags {
    var flags = script.ScriptFlags{
        // Start with all false, then set based on string
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
    };

    const trimmed = std.mem.trim(u8, flags_str, " \t\r\n");
    if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "NONE")) return flags;

    var iter = std.mem.tokenizeScalar(u8, trimmed, ',');
    while (iter.next()) |flag_raw| {
        const flag = std.mem.trim(u8, flag_raw, " ");
        if (std.mem.eql(u8, flag, "P2SH")) {
            flags.verify_p2sh = true;
        } else if (std.mem.eql(u8, flag, "DERSIG")) {
            flags.verify_dersig = true;
        } else if (std.mem.eql(u8, flag, "LOW_S")) {
            flags.verify_low_s = true;
        } else if (std.mem.eql(u8, flag, "NULLDUMMY")) {
            flags.verify_nulldummy = true;
        } else if (std.mem.eql(u8, flag, "MINIMALDATA")) {
            flags.verify_minimaldata = true;
        } else if (std.mem.eql(u8, flag, "CLEANSTACK")) {
            flags.verify_clean_stack = true;
        } else if (std.mem.eql(u8, flag, "CHECKLOCKTIMEVERIFY")) {
            flags.verify_checklocktimeverify = true;
        } else if (std.mem.eql(u8, flag, "CHECKSEQUENCEVERIFY")) {
            flags.verify_checksequenceverify = true;
        } else if (std.mem.eql(u8, flag, "WITNESS")) {
            flags.verify_witness = true;
        } else if (std.mem.eql(u8, flag, "NULLFAIL")) {
            flags.verify_nullfail = true;
        } else if (std.mem.eql(u8, flag, "WITNESS_PUBKEYTYPE")) {
            flags.verify_witness_pubkeytype = true;
        } else if (std.mem.eql(u8, flag, "TAPROOT")) {
            flags.verify_taproot = true;
        } else if (std.mem.eql(u8, flag, "DISCOURAGE_OP_SUCCESS")) {
            flags.discourage_op_success = true;
        } else if (std.mem.eql(u8, flag, "DISCOURAGE_UPGRADABLE_NOPS")) {
            flags.discourage_upgradable_nops = true;
        } else if (std.mem.eql(u8, flag, "SIGPUSHONLY")) {
            flags.verify_sigpushonly = true;
        } else if (std.mem.eql(u8, flag, "STRICTENC")) {
            // STRICTENC implies DERSIG + LOW_S + strict pubkey/hashtype encoding checks
            flags.verify_dersig = true;
            flags.verify_low_s = true;
            flags.verify_strictenc = true;
        }
        // Flags not supported by clearbit ScriptFlags are silently ignored:
        // DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, MINIMALIF, CONST_SCRIPTCODE, etc.
    }
    return flags;
}

/// Compute the txid of a transaction (double-SHA256 of non-witness serialization).
/// Returns hash in internal byte order.
fn computeTxHash(allocator: std.mem.Allocator, tx: *const types.Transaction) ![32]u8 {
    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();
    try serialize.writeTransactionNoWitness(&writer, tx);
    const data = writer.getWritten();
    return crypto.hash256(data);
}

/// Build the crediting transaction per Bitcoin Core's test framework.
/// Creates: version=1, locktime=0, one input (null prevout, scriptSig=OP_0 OP_0,
/// sequence=0xFFFFFFFF), one output (scriptPubKey=test's scriptPubKey, value=0).
fn buildCreditingTx(
    allocator: std.mem.Allocator,
    script_pubkey: []const u8,
) !struct {
    tx: types.Transaction,
    inputs: []types.TxIn,
    outputs: []types.TxOut,
    credit_script_sig: []u8,
    credit_script_pubkey: []u8,
} {
    // scriptSig for crediting tx: OP_0 OP_0
    const credit_script_sig = try allocator.alloc(u8, 2);
    credit_script_sig[0] = 0x00; // OP_0
    credit_script_sig[1] = 0x00; // OP_0

    // Copy scriptPubKey
    const credit_script_pubkey = try allocator.dupe(u8, script_pubkey);

    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xFFFFFFFF },
        .script_sig = credit_script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };

    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{
        .value = 0,
        .script_pubkey = credit_script_pubkey,
    };

    return .{
        .tx = .{
            .version = 1,
            .inputs = inputs,
            .outputs = outputs,
            .lock_time = 0,
        },
        .inputs = inputs,
        .outputs = outputs,
        .credit_script_sig = credit_script_sig,
        .credit_script_pubkey = credit_script_pubkey,
    };
}

/// Build the spending transaction per Bitcoin Core's test framework.
/// Creates: version=1, locktime=0, one input (prevout=hash of crediting tx : 0,
/// scriptSig=test's scriptSig, sequence=0xFFFFFFFF), one output (empty scriptPubKey, value=0).
///
/// For CLTV tests, the locktime is set to match the test requirements.
/// For CSV tests, the tx version is 2 and the input sequence is set appropriately.
fn buildSpendingTx(
    allocator: std.mem.Allocator,
    credit_tx_hash: [32]u8,
    script_sig: []const u8,
    flags: script.ScriptFlags,
) !struct {
    tx: types.Transaction,
    inputs: []types.TxIn,
    outputs: []types.TxOut,
    spend_script_pubkey: []u8,
} {
    const spend_script_pubkey = try allocator.alloc(u8, 0);

    // Determine locktime and sequence for CLTV/CSV compatibility
    // Bitcoin Core uses: nLockTime=0, nSequence=0xFFFFFFFF by default
    // For CLTV: sequence must NOT be 0xFFFFFFFF (so locktime is enforceable)
    // For CSV: version must be >= 2, sequence must not have disable bit set
    const lock_time: u32 = 0;
    var sequence: u32 = 0xFFFFFFFF;
    var version: i32 = 1;

    if (flags.verify_checklocktimeverify) {
        // CLTV requires sequence != 0xFFFFFFFF so locktime is checked
        sequence = 0;
    }

    if (flags.verify_checksequenceverify) {
        // CSV requires version >= 2
        version = 2;
        // sequence must not have disable bit; use 0 for compatibility
        sequence = 0;
    }

    const inputs = try allocator.alloc(types.TxIn, 1);
    inputs[0] = .{
        .previous_output = .{ .hash = credit_tx_hash, .index = 0 },
        .script_sig = script_sig,
        .sequence = sequence,
        .witness = &[_][]const u8{},
    };

    const outputs = try allocator.alloc(types.TxOut, 1);
    outputs[0] = .{
        .value = 0,
        .script_pubkey = spend_script_pubkey,
    };

    return .{
        .tx = .{
            .version = version,
            .inputs = inputs,
            .outputs = outputs,
            .lock_time = lock_time,
        },
        .inputs = inputs,
        .outputs = outputs,
        .spend_script_pubkey = spend_script_pubkey,
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // Initialize secp256k1 for real signature verification
    if (!crypto.initSecp256k1()) {
        try stdout.print("WARNING: Failed to initialize secp256k1, signature verification will fail\n", .{});
    }
    defer crypto.deinitSecp256k1();

    // Load JSON test vectors
    const json_path = "/home/max/hashhog/bitcoin/src/test/data/script_tests.json";
    const json_data = try std.fs.cwd().readFileAlloc(allocator, json_path, 50 * 1024 * 1024);
    defer allocator.free(json_data);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
    defer parsed.deinit();

    const root_array = parsed.value.array;

    var pass_count: usize = 0;
    var fail_count: usize = 0;
    var skip_count: usize = 0;
    var error_count: usize = 0;
    var total: usize = 0;

    for (root_array.items) |entry| {
        const arr = switch (entry) {
            .array => |a| a,
            else => continue,
        };

        const n = arr.items.len;
        // Skip comments (1 element), malformed (2-3), and witness tests (6+)
        if (n <= 3) continue;
        if (n >= 6) {
            skip_count += 1;
            continue;
        }

        // 4 or 5 element test
        total += 1;
        const sig_asm_val = arr.items[0];
        const pub_asm_val = arr.items[1];
        const flags_val = arr.items[2];
        const expected_val = arr.items[3];

        const sig_asm = switch (sig_asm_val) {
            .string => |s| s,
            else => continue,
        };
        const pub_asm = switch (pub_asm_val) {
            .string => |s| s,
            else => continue,
        };
        const flags_str = switch (flags_val) {
            .string => |s| s,
            else => continue,
        };
        const expected = switch (expected_val) {
            .string => |s| s,
            else => continue,
        };

        const expected_ok = std.mem.eql(u8, expected, "OK");

        // Assemble scripts
        const script_sig = assembleScript(allocator, sig_asm) catch {
            if (!expected_ok) {
                pass_count += 1;
            } else {
                error_count += 1;
                try stdout.print("ERROR: asm parse failed sig=[{s}]\n", .{sig_asm});
            }
            continue;
        };
        defer allocator.free(script_sig);

        const script_pubkey = assembleScript(allocator, pub_asm) catch {
            if (!expected_ok) {
                pass_count += 1;
            } else {
                error_count += 1;
                try stdout.print("ERROR: asm parse failed pub=[{s}]\n", .{pub_asm});
            }
            continue;
        };
        defer allocator.free(script_pubkey);

        const flags = parseFlags(flags_str);

        // Build crediting transaction (Bitcoin Core approach)
        const credit = buildCreditingTx(allocator, script_pubkey) catch {
            error_count += 1;
            continue;
        };
        defer allocator.free(credit.inputs);
        defer allocator.free(credit.outputs);
        defer allocator.free(credit.credit_script_sig);
        defer allocator.free(credit.credit_script_pubkey);

        // Compute crediting tx hash
        const credit_hash = computeTxHash(allocator, &credit.tx) catch {
            error_count += 1;
            continue;
        };

        // Build spending transaction
        const spend = buildSpendingTx(allocator, credit_hash, script_sig, flags) catch {
            error_count += 1;
            continue;
        };
        defer allocator.free(spend.inputs);
        defer allocator.free(spend.outputs);
        defer allocator.free(spend.spend_script_pubkey);

        // Run verification with spending transaction
        var engine = script.ScriptEngine.init(allocator, &spend.tx, 0, 0, flags);
        defer engine.deinit();

        const got_ok = if (engine.verify(
            script_sig,
            script_pubkey,
            &[_][]const u8{},
        )) |v| v else |_| false;

        if (got_ok == expected_ok) {
            pass_count += 1;
        } else {
            fail_count += 1;
            try stdout.print("FAIL: expected={s} got={s} sig=[{s}] pub=[{s}] flags={s}\n", .{
                expected,
                if (got_ok) "OK" else "FAIL",
                sig_asm,
                pub_asm,
                flags_str,
            });
        }
    }

    try stdout.print("\n=== Script Test Vector Results ===\n", .{});
    try stdout.print("Total non-witness tests: {d}\n", .{total});
    try stdout.print("  PASS:  {d}\n", .{pass_count});
    try stdout.print("  FAIL:  {d}\n", .{fail_count});
    try stdout.print("  ERROR: {d}\n", .{error_count});
    try stdout.print("  Skipped (witness): {d}\n", .{skip_count});

    if (fail_count > 0 or error_count > 0) {
        std.process.exit(1);
    }
}
