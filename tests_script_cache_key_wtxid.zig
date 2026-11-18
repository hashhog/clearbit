//! Script-check cache key must commit to the whole witness (wtxid).
//!
//! Bitcoin Core: CheckInputScripts (validation.cpp) keys
//! m_script_execution_cache on SHA256(nonce || tx.GetWitnessHash() || flags),
//! so any change to any witness byte, including the item count, is a miss.
//!
//! The clearbit job path (validation.zig verifyScriptJob) keyed its
//! process-wide cache on a per-input digest built from the TXID, plus at most
//! 520 bytes of scriptSig and at most 4096 bytes of the witness items
//! concatenated with no count or length prefixes. A cache hit returns OK
//! without running the interpreter, so after the valid witness of a tx had
//! been verified once, a malleated INVALID witness for the same tx with the
//! same key was accepted:
//!
//!   case 1: P2WPKH [sig, pk] then [sig, pk, ""] (Core: witness program
//!           mismatch, P2WPKH needs exactly two items) — same concatenation.
//!   case 2: P2WSH whose witnesses differ only after byte 4096 (the witness
//!           script, last item, differs in its last byte: Core: witness
//!           program mismatch) — same truncated prefix.
//!
//! Control: a valid repeated verify of the same tx still hits the cache.
//!
//! CONTROL: `zig build test-script-cache-key-wtxid --summary all`

const std = @import("std");
const testing = std.testing;
const types = @import("src/types.zig");
const script = @import("src/script.zig");
const crypto = @import("src/crypto.zig");
const serialize = @import("src/serialize.zig");
const validation = @import("src/validation.zig");
const consensus = @import("src/consensus.zig");
const secp = @import("src/secp.zig").c;

const OP_0: u8 = 0x00;
const OP_TRUE: u8 = 0x51;
const OP_DROP: u8 = 0x75;
const OP_2DROP: u8 = 0x6d;
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;

const AMOUNT: i64 = 50_000;

fn blockFlags() script.ScriptFlags {
    const f = validation.getBlockScriptFlags(800_000, &consensus.MAINNET);
    std.debug.assert(f.verify_witness);
    return f;
}

const Key = struct { seckey: [32]u8, pubkey: [33]u8 };

fn testCtx() !*secp.secp256k1_context {
    return secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN | secp.SECP256K1_CONTEXT_VERIFY) orelse
        error.SecpContextFailed;
}

fn makeKey(ctx: *secp.secp256k1_context) !Key {
    var k = Key{ .seckey = [_]u8{0x42} ** 32, .pubkey = undefined };
    var pk: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_create(ctx, &pk, &k.seckey) != 1) return error.KeyFailed;
    var len: usize = 33;
    if (secp.secp256k1_ec_pubkey_serialize(ctx, &k.pubkey, &len, &pk, secp.SECP256K1_EC_COMPRESSED) != 1) return error.KeyFailed;
    return k;
}

/// DER signature over `msg` with SIGHASH_ALL appended.
fn signDer(ctx: *secp.secp256k1_context, key: *const Key, msg: *const [32]u8, out: *[80]u8) !usize {
    var sig: secp.secp256k1_ecdsa_signature = undefined;
    if (secp.secp256k1_ecdsa_sign(ctx, &sig, msg, &key.seckey, null, null) != 1) return error.SignFailed;
    var len: usize = 72;
    if (secp.secp256k1_ecdsa_signature_serialize_der(ctx, out, &len, &sig) != 1) return error.SignFailed;
    out[len] = 0x01; // SIGHASH_ALL
    return len + 1;
}

const out_spk = [_]u8{OP_TRUE};

/// One-input, one-output tx spending a fixed outpoint.  The witness is set by
/// the caller; it does not change the txid.
const Spend = struct {
    tx: types.Transaction = undefined,
    inputs: [1]types.TxIn = undefined,
    outputs: [1]types.TxOut = undefined,

    fn init(self: *Spend) void {
        self.inputs = .{.{
            .previous_output = .{ .hash = [_]u8{0x5A} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }};
        self.outputs = .{.{ .value = 40_000, .script_pubkey = &out_spk }};
        self.tx = .{ .version = 2, .inputs = &self.inputs, .outputs = &self.outputs, .lock_time = 0 };
    }
};

/// Run one input-0 script check of `tx` (with `witness`) through the job path
/// on `queue`, as connectBlock does.  Returns the batch result.
fn runJob(
    queue: *validation.ScriptCheckQueue,
    tx: *const types.Transaction,
    spk: []const u8,
    witness: []const []const u8,
) !validation.BatchResult {
    var with_wit = tx.*;
    var ins: [1]types.TxIn = .{tx.inputs[0]};
    ins[0].witness = witness;
    with_wit.inputs = &ins;

    var writer = serialize.Writer.init(testing.allocator);
    defer writer.deinit();
    try serialize.writeTransaction(&writer, &with_wit);

    const amounts = [_]i64{AMOUNT};
    const scripts = [_][]const u8{spk};
    var jobs = [_]validation.ScriptCheckJob{validation.ScriptCheckJob.initWithPrevouts(
        writer.list.items,
        0,
        spk,
        AMOUNT,
        blockFlags(),
        witness,
        &amounts,
        &scripts,
    )};
    queue.submit(&jobs);
    return queue.waitAllDetailed();
}

fn p2wpkhSpk(key: *const Key, buf: *[22]u8) []const u8 {
    buf[0] = OP_0;
    buf[1] = 20;
    const h = crypto.hash160(&key.pubkey);
    @memcpy(buf[2..22], &h);
    return buf;
}

test "tests_script_cache_key_wtxid: P2WPKH [sig,pk,\"\"] after a cached [sig,pk] is rejected" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);

    var spk_buf: [22]u8 = undefined;
    const spk = p2wpkhSpk(&key, &spk_buf);

    var s = Spend{};
    s.init();

    // BIP-143 script code for P2WPKH: DUP HASH160 <20> EQUALVERIFY CHECKSIG.
    var code: [25]u8 = undefined;
    code[0] = OP_DUP;
    code[1] = OP_HASH160;
    code[2] = 20;
    @memcpy(code[3..23], spk[2..22]);
    code[23] = OP_EQUALVERIFY;
    code[24] = OP_CHECKSIG;
    const sh = try crypto.segwitSighash(&s.tx, 0, &code, AMOUNT, 1, testing.allocator);
    var sig_buf: [80]u8 = undefined;
    const sig_len = try signDer(ctx, &key, &sh, &sig_buf);
    const sig = sig_buf[0..sig_len];

    const good = [_][]const u8{ sig, &key.pubkey };
    const bad = [_][]const u8{ sig, &key.pubkey, &[_]u8{} };

    // Instrument: the malleated witness is invalid on a cold cache.
    {
        var cold = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
        defer cold.deinit();
        const r = try runJob(cold, &s.tx, spk, &bad);
        try testing.expect(!r.ok);
        try testing.expectEqual(
            @as(u32, @intFromEnum(validation.ScriptCheckFailCode.witness_program_mismatch)),
            r.first_fail_code,
        );
    }

    var queue = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
    defer queue.deinit();

    // 1. Valid witness verifies and fills the cache.
    const r1 = try runJob(queue, &s.tx, spk, &good);
    try testing.expect(r1.ok);
    try testing.expectEqual(@as(u64, 1), queue.sig_cache.getStats().insertions);

    // 2. Same tx, extra empty witness item: must be re-run and rejected.
    const r2 = try runJob(queue, &s.tx, spk, &bad);
    try testing.expect(!r2.ok);
    try testing.expectEqual(
        @as(u32, @intFromEnum(validation.ScriptCheckFailCode.witness_program_mismatch)),
        r2.first_fail_code,
    );

    // Perf control: the valid witness again is a cache hit.
    const hits_before = queue.sig_cache.getStats().hits;
    const r3 = try runJob(queue, &s.tx, spk, &good);
    try testing.expect(r3.ok);
    try testing.expectEqual(hits_before + 1, queue.sig_cache.getStats().hits);
}

test "tests_script_cache_key_wtxid: P2WSH witnesses differing only after byte 4096 are keyed apart" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);

    // 9 filler items of 500 bytes (each under the 520-byte element limit)
    // push the witness script past byte 4096 of the concatenated witness.
    const n_fill = 9;
    const fill = [_]u8{0xEE} ** 500;

    // ws = 2DROP x4, DROP, <pk> CHECKSIG  (drops the 9 fillers, checks sig)
    var ws: [4 + 1 + 1 + 33 + 1]u8 = undefined;
    @memset(ws[0..4], OP_2DROP);
    ws[4] = OP_DROP;
    ws[5] = 33;
    @memcpy(ws[6..39], &key.pubkey);
    ws[39] = OP_CHECKSIG;

    // Malleated: last byte CHECKSIG -> CHECKSIGVERIFY, so sha256(ws') no
    // longer matches the program (Core: witness program mismatch).
    var ws_bad = ws;
    ws_bad[39] = OP_CHECKSIGVERIFY;

    var spk: [34]u8 = undefined;
    spk[0] = OP_0;
    spk[1] = 32;
    std.crypto.hash.sha2.Sha256.hash(&ws, spk[2..34], .{});

    var s = Spend{};
    s.init();
    const sh = try crypto.segwitSighash(&s.tx, 0, &ws, AMOUNT, 1, testing.allocator);
    var sig_buf: [80]u8 = undefined;
    const sig_len = try signDer(ctx, &key, &sh, &sig_buf);
    const sig = sig_buf[0..sig_len];

    var good: [1 + n_fill + 1][]const u8 = undefined;
    var bad: [1 + n_fill + 1][]const u8 = undefined;
    good[0] = sig;
    bad[0] = sig;
    for (1..1 + n_fill) |i| {
        good[i] = &fill;
        bad[i] = &fill;
    }
    good[1 + n_fill] = &ws;
    bad[1 + n_fill] = &ws_bad;

    // Instrument: the two witnesses really are identical in their first
    // 4096 concatenated bytes and differ only after it.
    var first_diff: usize = 0;
    {
        var off: usize = 0;
        var found = false;
        for (good, bad) |g, b| {
            for (g, 0..) |gb, j| {
                if (gb != b[j]) {
                    first_diff = off + j;
                    found = true;
                    break;
                }
            }
            if (found) break;
            off += g.len;
        }
        try testing.expect(found);
    }
    try testing.expect(first_diff >= 4096);

    // Instrument: the malleated witness is invalid on a cold cache.
    {
        var cold = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
        defer cold.deinit();
        const r = try runJob(cold, &s.tx, &spk, &bad);
        try testing.expect(!r.ok);
    }

    var queue = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
    defer queue.deinit();

    const r1 = try runJob(queue, &s.tx, &spk, &good);
    try testing.expect(r1.ok);

    const r2 = try runJob(queue, &s.tx, &spk, &bad);
    try testing.expect(!r2.ok);
    try testing.expectEqual(
        @as(u32, @intFromEnum(validation.ScriptCheckFailCode.witness_program_mismatch)),
        r2.first_fail_code,
    );

    // Perf control.
    const hits_before = queue.sig_cache.getStats().hits;
    const r3 = try runJob(queue, &s.tx, &spk, &good);
    try testing.expect(r3.ok);
    try testing.expectEqual(hits_before + 1, queue.sig_cache.getStats().hits);
}
