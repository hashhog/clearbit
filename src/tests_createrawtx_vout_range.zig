//! createrawtransaction — vout/sequence/locktime must be validated Core's way.
//!
//! Run via `zig build test-createrawtx`.
//!
//! THE DEFECT (regression pinned by this suite)
//! --------------------------------------------
//! The input parser bounded `vout` against `maxInt(u32)` — the width of the
//! *storage* field — instead of against `int32`, the width Bitcoin Core
//! converts to.  It also answered with clearbit's own invented codes and
//! wording rather than Core's:
//!
//!     vout 2147483648 (2^31)  ->  ACCEPTED, written as outpoint index
//!                                 0x80000000.  Core REJECTS this value.
//!     vout 4294967296 (2^32)  ->  -8  "Invalid parameter, vout is too large"
//!                                 (invented; Core says -1 "JSON integer out
//!                                 of range")
//!     missing vout            ->  -32602 "Missing vout"
//!                                 (Core: -8 "Invalid parameter, missing vout key")
//!     txid "abc"              ->  -32602 "Invalid txid"
//!                                 (Core: -8, ParseHashV wording)
//!
//! The 2^31 case is the quiet one and the worse one: a silent ACCEPT of an
//! input Core refuses, producing a transaction Core's own
//! createrawtransaction would never build.  The u32 bound came from commit
//! 8e18116, which fixed a real `@intCast` panic that KILLED the node
//! (`vout:-1` -> "integer cast truncated bits"); this suite extends that fix
//! to Core's actual bound and must never be allowed to regress it — a
//! too-wide value is still range-checked BEFORE any cast.
//!
//! WHAT BITCOIN CORE DOES
//! ----------------------
//! `AddInputs` (bitcoin-core/src/rpc/rawtransaction_util.cpp:36-45) reads the
//! field with `find_value(o, "vout").getInt<int>()` — `int`, i.e. THIRTY-TWO
//! bits.  `UniValue::getInt<Int>` (src/univalue/include/univalue.h:139-150)
//! converts with `std::from_chars` into the destination width and throws
//! `std::runtime_error("JSON integer out of range")` when the token does not
//! fit; rpc/server.cpp:514-515 turns that into RPC_MISC_ERROR (-1).
//!
//! THE ORDERING IS UNIVALUE'S, NOT THE HANDLER'S: the width check lives inside
//! the *conversion*, so it runs BEFORE `if (nOutput < 0) throw ... "vout
//! cannot be negative"`.  That is why -1 gets the vout-specific -8 message
//! while 2147483648 — equally "not a valid vout" to a human — gets the generic
//! -1 "JSON integer out of range".  `vout -2147483649` is the case that pins
//! the order: negative AND out of int32 range, and Core answers -1, not -8.
//!
//! TEETH
//! -----
//! Every case above is a rejection, and a handler that rejected EVERY input
//! would satisfy all of them.  The two CONTROL tests make that impossible:
//! they drive the real dispatcher to success and then DECODE the returned hex
//! with the node's own `serialize.readTransaction`, asserting the outpoint
//! index that actually reached the wire bytes.  The int32-MAX control
//! (2147483647) fails loudly if the new bound is off by one in the tight
//! direction.  Both controls pass BEFORE the fix as well as after — that is
//! what makes them controls.
//!
//! References:
//!   bitcoin-core/src/rpc/rawtransaction_util.cpp:36-45   AddInputs
//!   bitcoin-core/src/rpc/rawtransaction_util.cpp:151-156 ConstructTransaction
//!   bitcoin-core/src/univalue/include/univalue.h:139-150 getInt<Int>
//!   bitcoin-core/src/rpc/util.cpp:117-125                ParseHashV
//!   bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
//!                                                        RPC_INVALID_PARAMETER = -8

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const serialize = @import("serialize.zig");

/// Well-formed 64-hex txid.  Its content is irrelevant: createrawtransaction
/// builds an UNSIGNED transaction from its arguments alone and never looks the
/// outpoint up, so no chainstate is involved.
const TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

/// A single OP_RETURN output.  Deliberately data-only so the test never
/// touches address encoding or the network params — a failure here can only
/// mean the INPUT parser, never the output parser.
const OUTPUTS = "{\"data\":\"deadbeef\"}";

const INT32_MAX: i64 = 2147483647;

/// Minimal live RpcServer.  Same rig the existing rpc.zig dispatch tests use
/// (signrawtransactionwithkey / fundrawtransaction), heap-allocated so the
/// server's pointers to its dependencies stay valid when the rig is moved.
const Rig = struct {
    allocator: std.mem.Allocator,
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    peer_manager: *peer_mod.PeerManager,
    server: *rpc.RpcServer,

    fn init(allocator: std.mem.Allocator) !Rig {
        const cs = try allocator.create(storage.ChainState);
        cs.* = storage.ChainState.init(null, 64, allocator);
        const mp = try allocator.create(mempool_mod.Mempool);
        mp.* = mempool_mod.Mempool.init(null, null, allocator);
        const pm = try allocator.create(peer_mod.PeerManager);
        pm.* = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
        const srv = try allocator.create(rpc.RpcServer);
        srv.* = rpc.RpcServer.init(allocator, cs, mp, pm, &consensus.MAINNET, .{});
        return .{
            .allocator = allocator,
            .chain_state = cs,
            .mempool = mp,
            .peer_manager = pm,
            .server = srv,
        };
    }

    fn deinit(self: *Rig) void {
        self.server.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
        self.allocator.destroy(self.server);
        self.allocator.destroy(self.peer_manager);
        self.allocator.destroy(self.mempool);
        self.allocator.destroy(self.chain_state);
    }

    /// Drive the REAL dispatcher (not a reimplementation) and hand back the
    /// caller-owned reply JSON.
    fn dispatchCreateRaw(self: *Rig, params_json: []const u8) ![]const u8 {
        const req = try std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":1,\"method\":\"createrawtransaction\",\"params\":{s}}}",
            .{params_json},
        );
        defer self.allocator.free(req);
        return self.server.dispatch(req);
    }
};

/// Build the params array for a single input `{txid, <extra>}` plus the
/// standard OP_RETURN output, e.g. extra = "\"vout\":-1".
fn oneInputParams(allocator: std.mem.Allocator, input_fields: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"{s}\",{s}}}],{s}]",
        .{ TXID, input_fields, OUTPUTS },
    );
}

/// Assert the dispatcher answers with Core's exact code AND message.
///
/// A reply that SUCCEEDS is reported as a distinct failure (with the returned
/// hex printed) rather than silently passing — the pre-fix 2^31 behaviour was
/// a success, and it must be visible as such in the mutation run.
fn expectRpcError(rig: *Rig, params_json: []const u8, want_code: i64, want_msg: []const u8) !void {
    const resp = try rig.dispatchCreateRaw(params_json);
    defer rig.allocator.free(resp);

    var parsed = try std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{});
    defer parsed.deinit();

    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v != .object) {
        std.debug.print(
            "\nexpected error {d} \"{s}\", got a SUCCESS reply: {s}\n",
            .{ want_code, want_msg, resp },
        );
        return error.ExpectedRpcErrorGotSuccess;
    }
    const got_code = err_v.object.get("code").?.integer;
    const got_msg = err_v.object.get("message").?.string;
    if (got_code != want_code or !std.mem.eql(u8, got_msg, want_msg)) {
        std.debug.print(
            "\nexpected {d} \"{s}\", got {d} \"{s}\"\n",
            .{ want_code, want_msg, got_code, got_msg },
        );
    }
    try testing.expectEqual(want_code, got_code);
    try testing.expectEqualStrings(want_msg, got_msg);
}

/// Decode the returned hex with the node's OWN deserializer and report the
/// outpoint index that actually landed in the transaction bytes.
fn firstInputVout(rig: *Rig, params_json: []const u8) !u32 {
    const resp = try rig.dispatchCreateRaw(params_json);
    defer rig.allocator.free(resp);

    var parsed = try std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{});
    defer parsed.deinit();

    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nexpected success, got error reply: {s}\n", .{resp});
        return error.UnexpectedRpcError;
    }
    const hex = parsed.value.object.get("result").?.string;
    try testing.expect(hex.len > 0);

    const bytes = try rig.allocator.alloc(u8, hex.len / 2);
    defer rig.allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var reader = serialize.Reader{ .data = bytes };
    const tx = try serialize.readTransaction(&reader, rig.allocator);
    defer serialize.freeTransaction(rig.allocator, &tx);
    try testing.expectEqual(@as(usize, 1), tx.inputs.len);
    return tx.inputs[0].previous_output.index;
}

// ==========================================================================
// THE REGRESSION: vout is an int32 in Core, and RANGE beats SIGN.
// ==========================================================================

/// One out-of-int32 `vout` case.  Each value gets its OWN test so a mutation
/// run (production change reverted, tests kept) reports every case
/// independently instead of stopping at the first failure — the 2^31 case in
/// particular is a SILENT ACCEPT pre-fix and has to be visible as one.
fn expectVoutOutOfRange(vout_literal: []const u8) !void {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const fields = try std.fmt.allocPrint(allocator, "\"vout\":{s}", .{vout_literal});
    defer allocator.free(fields);
    const params = try oneInputParams(allocator, fields);
    defer allocator.free(params);
    try expectRpcError(&rig, params, -1, "JSON integer out of range");
}

test "tests_createrawtx_vout_range: vout 4294967296 (2^32) -> -1 JSON integer out of range" {
    try expectVoutOutOfRange("4294967296");
}

test "tests_createrawtx_vout_range: vout 8589934592 (2^33) -> -1 JSON integer out of range" {
    try expectVoutOutOfRange("8589934592");
}

test "tests_createrawtx_vout_range: vout 2147483648 (int32 MAX + 1) -> -1 JSON integer out of range" {
    // The exact boundary: one past what Core's getInt<int> can hold. THIS is
    // the regression — pre-fix the value was ACCEPTED and written as outpoint
    // index 0x80000000.
    try expectVoutOutOfRange("2147483648");
}

test "tests_createrawtx_vout_range: vout -2147483649 (int32 MIN - 1) -> -1, range beats sign" {
    // Negative AND out of int32 range. Core's range check lives inside the
    // conversion, so it wins over the "cannot be negative" message. This is
    // the ORDERING assertion.
    try expectVoutOutOfRange("-2147483649");
}

// ==========================================================================
// Neighbouring guards must report Core's own codes and wording.
// ==========================================================================

test "tests_createrawtx_vout_range: vout -1 -> -8 vout cannot be negative" {
    // -1 fits in an int32, so the range check passes and the sign test speaks.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try oneInputParams(allocator, "\"vout\":-1");
    defer allocator.free(params);
    try expectRpcError(&rig, params, -8, "Invalid parameter, vout cannot be negative");
}

test "tests_createrawtx_vout_range: missing vout -> -8 missing vout key" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"{s}\"}}],{s}]",
        .{ TXID, OUTPUTS },
    );
    defer allocator.free(params);
    try expectRpcError(&rig, params, -8, "Invalid parameter, missing vout key");
}

fn expectSequenceOutOfRange(seq_literal: []const u8) !void {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const fields = try std.fmt.allocPrint(
        allocator,
        "\"vout\":0,\"sequence\":{s}",
        .{seq_literal},
    );
    defer allocator.free(fields);
    const params = try oneInputParams(allocator, fields);
    defer allocator.free(params);
    try expectRpcError(&rig, params, -8, "Invalid parameter, sequence number is out of range");
}

test "tests_createrawtx_vout_range: sequence 4294967296 -> -8 sequence number is out of range" {
    try expectSequenceOutOfRange("4294967296");
}

test "tests_createrawtx_vout_range: sequence -1 -> -8 sequence number is out of range" {
    try expectSequenceOutOfRange("-1");
}

test "tests_createrawtx_vout_range: locktime -1 -> -8 locktime out of range" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"{s}\",\"vout\":0}}],{s},-1]",
        .{ TXID, OUTPUTS },
    );
    defer allocator.free(params);
    try expectRpcError(&rig, params, -8, "Invalid parameter, locktime out of range");
}

test "tests_createrawtx_vout_range: malformed txid -> -8 with ParseHashV wording" {
    // Core runs ParseHashO BEFORE it looks at vout, so a malformed txid is
    // reported as a txid problem with ParseHashV's exact message.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const short = try std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"abc\",\"vout\":0}}],{s}]",
        .{OUTPUTS},
    );
    defer allocator.free(short);
    try expectRpcError(&rig, short, -8, "txid must be of length 64 (not 3, for 'abc')");

    // Right length, non-hex characters -> ParseHashV's second message.
    const nonhex = "zz" ++ TXID[2..];
    const bad = try std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"{s}\",\"vout\":0}}],{s}]",
        .{ nonhex, OUTPUTS },
    );
    defer allocator.free(bad);
    const want = try std.fmt.allocPrint(
        allocator,
        "txid must be hexadecimal string (not '{s}')",
        .{nonhex},
    );
    defer allocator.free(want);
    try expectRpcError(&rig, bad, -8, want);
}

test "tests_createrawtx_vout_range: non-numeric sequence is IGNORED, not an error" {
    // Core guards the read with `if (sequenceObj.isNum())`, so the default
    // applies (replaceable defaults true -> MAX_BIP125_RBF_SEQUENCE).
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try oneInputParams(allocator, "\"vout\":0,\"sequence\":\"nope\"");
    defer allocator.free(params);

    const resp = try rig.dispatchCreateRaw(params);
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nexpected success, got error reply: {s}\n", .{resp});
        return error.UnexpectedRpcError;
    }

    const hex = parsed.value.object.get("result").?.string;
    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);
    var reader = serialize.Reader{ .data = bytes };
    const tx = try serialize.readTransaction(&reader, allocator);
    defer serialize.freeTransaction(allocator, &tx);
    try testing.expectEqual(@as(u32, 0xfffffffd), tx.inputs[0].sequence);
}

// ==========================================================================
// CONTROLS — these must pass BOTH before and after the fix.  Without them the
// suite above is satisfiable by a handler that rejects everything, and an
// over-tight bound would slip through.
// ==========================================================================

test "tests_createrawtx_vout_range: CONTROL int32 MAX is ACCEPTED and lands in the bytes" {
    // Proves the new upper bound is `> maxInt(i32)`, not `>=` or some smaller
    // cap. Fails loudly if the guard is over-tight by even one.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try oneInputParams(allocator, "\"vout\":2147483647");
    defer allocator.free(params);
    try testing.expectEqual(@as(u32, @intCast(INT32_MAX)), try firstInputVout(&rig, params));
}

test "tests_createrawtx_vout_range: CONTROL an ordinary vout 7 is ACCEPTED and lands in the bytes" {
    // Proves the handler still does its normal job, so the rejection tests
    // above cannot be satisfied by a reject-everything stub.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try oneInputParams(allocator, "\"vout\":7");
    defer allocator.free(params);
    try testing.expectEqual(@as(u32, 7), try firstInputVout(&rig, params));
}

// ==========================================================================
// SECOND REGRESSION: an EXPLICIT `replaceable=true` that the supplied sequence
// numbers CONTRADICT must be REJECTED, not silently resolved.
// ==========================================================================
//
// THE DEFECT
// ----------
// `createrawtransaction(ins, outs, 0, true)` asks for a REPLACEABLE
// transaction.  BIP-125 opt-in signalling means at least one input carrying
// nSequence <= MAX_BIP125_RBF_SEQUENCE (0xfffffffd); a sequence ABOVE that is
// precisely the opt-OUT.  A caller who passes replaceable=true and also pins
// every input to 0xfffffffe or 0xffffffff has asked for two things that cannot
// both hold.
//
// clearbit resolved that silently, in favour of the sequence: it returned a
// well-formed transaction hex that CANNOT be fee-bumped, with no error, no
// warning and no log line.  The caller learns the truth only when the bump is
// needed and the replacement is refused under BIP-125 Rule 1 — at which point
// the transaction is broadcast and the fee is stuck.
//
// WHAT BITCOIN CORE DOES
// ----------------------
// The LAST statement of ConstructTransaction, after AddInputs AND AddOutputs
// (bitcoin-core/src/rpc/rawtransaction_util.cpp:166-168):
//
//     if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
//         !SignalsOptInRBF(CTransaction(rawTx)))
//         throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter
//             combination: Sequence number(s) contradict replaceable option");
//
// SignalsOptInRBF (bitcoin-core/src/util/rbf.cpp) is true if ANY input has
// nSequence <= MAX_BIP125_RBF_SEQUENCE.  "Any" rather than "all" is deliberate
// upstream: in a multi-party protocol a single participant must not be able to
// disable replacement by opting out in their own input.
//
// THE ABSENT-vs-EXPLICIT ASYMMETRY (the subtle part)
// --------------------------------------------------
// `rbf` is a std::optional<bool>, left nullopt when the JSON argument is
// absent or null, and TWO DIFFERENT QUESTIONS are asked of it:
//   * AddInputs asks rbf.value_or(true)          — absent counts as TRUE,
//     which is what makes 0xfffffffd the DEFAULT sequence;
//   * this check asks rbf.has_value() && value() — absent counts as NOT SET,
//     so no check fires at all.
// Consequence, verified against the live Core node (2026-08-28): an omitted
// `replaceable` with an explicit final sequence is ACCEPTED, while the same
// call with `replaceable=true` spelled out is REJECTED.  A check keyed off the
// effective boolean instead of has_value() breaks the first, which is
// ordinary, legal usage.
//
// TEETH
// -----
// Only two of the nine rows below are rejections.  The seven ACCEPT rows are
// the controls, and they are the ones an over-eager check breaks: each drives
// the real dispatcher to success and DECODES the returned hex, asserting the
// nSequence values that actually reached the wire bytes rather than merely
// that the call did not error.
//
// Oracle table, every row captured from the LIVE Core node on 2026-08-28:
//   rbf ABSENT + sequence 0xFFFFFFFF          ACCEPT, emits 0xffffffff
//   rbf null   + sequence 0xFFFFFFFF          ACCEPT, emits 0xffffffff
//   rbf true   + sequence 0xFFFFFFFD          ACCEPT, emits 0xfffffffd
//   rbf true   + sequence 0xFFFFFFFE          REJECT -8
//   rbf true   + sequence 0xFFFFFFFF          REJECT -8
//   rbf true   + no inputs                    ACCEPT
//   rbf true   + two inputs, one signals      ACCEPT, emits {0xffffffff, 0}
//   rbf false  + sequence 0xFFFFFFFF          ACCEPT, emits 0xffffffff
//   rbf true   + no explicit sequence         ACCEPT, emits 0xfffffffd

const CONTRADICT_MSG =
    "Invalid parameter combination: Sequence number(s) contradict replaceable option";

/// Build the params array for one input with an optional explicit sequence and
/// optional trailing `locktime, replaceable` arguments.  `rbf_json` is spliced
/// in as LITERAL JSON text so that ABSENT (null slice) and the JSON literals
/// `true` / `false` / `null` reach the dispatcher exactly as they would off the
/// wire — the absent/present distinction is the whole point of these rows and
/// must not be laundered through an encoder.
fn rbfParams(
    allocator: std.mem.Allocator,
    sequence_json: ?[]const u8,
    rbf_json: ?[]const u8,
) ![]const u8 {
    const seq_part = if (sequence_json) |s|
        try std.fmt.allocPrint(allocator, ",\"sequence\":{s}", .{s})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(seq_part);

    const tail = if (rbf_json) |r|
        try std.fmt.allocPrint(allocator, ",0,{s}", .{r})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(tail);

    return std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"{s}\",\"vout\":0{s}}}],{s}{s}]",
        .{ TXID, seq_part, OUTPUTS, tail },
    );
}

/// Drive the real dispatcher, require SUCCESS, and return every input's
/// nSequence as it actually landed in the serialized bytes.  Caller owns the
/// returned slice.
fn inputSequences(rig: *Rig, params_json: []const u8) ![]u32 {
    const resp = try rig.dispatchCreateRaw(params_json);
    defer rig.allocator.free(resp);

    var parsed = try std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{});
    defer parsed.deinit();

    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nexpected success, got error reply: {s}\n", .{resp});
        return error.UnexpectedRpcError;
    }
    const hex = parsed.value.object.get("result").?.string;

    const bytes = try rig.allocator.alloc(u8, hex.len / 2);
    defer rig.allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var reader = serialize.Reader{ .data = bytes };
    const tx = try serialize.readTransaction(&reader, rig.allocator);
    defer serialize.freeTransaction(rig.allocator, &tx);

    const seqs = try rig.allocator.alloc(u32, tx.inputs.len);
    for (tx.inputs, 0..) |txin, i| seqs[i] = txin.sequence;
    return seqs;
}

fn expectSequences(
    rig: *Rig,
    params_json: []const u8,
    expected: []const u32,
) !void {
    const got = try inputSequences(rig, params_json);
    defer rig.allocator.free(got);
    try testing.expectEqualSlices(u32, expected, got);
}

test "tests_createrawtx_vout_range: row 1 rbf ABSENT + final sequence is ACCEPTED" {
    // The asymmetry row. Absent still DEFAULTS to replaceable for CHOOSING the
    // sequence, but has_value() is false so the contradiction check never
    // arms. A check keyed off the effective boolean breaks this ordinary call.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try rbfParams(allocator, "4294967295", null);
    defer allocator.free(params);
    try expectSequences(&rig, params, &[_]u32{0xffffffff});
}

test "tests_createrawtx_vout_range: rbf JSON null + final sequence is ACCEPTED" {
    // Core's test is params[3].isNull(), so a literal null is identical to
    // omitting the argument: nullopt, has_value() false, no check.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try rbfParams(allocator, "4294967295", "null");
    defer allocator.free(params);
    try expectSequences(&rig, params, &[_]u32{0xffffffff});
}

test "tests_createrawtx_vout_range: row 2 rbf true + 0xfffffffd is ACCEPTED" {
    // Exactly MAX_BIP125_RBF_SEQUENCE: SignalsOptInRBF compares `<=`, so this
    // signals. Fails loudly if the comparison is written `<`.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try rbfParams(allocator, "4294967293", "true");
    defer allocator.free(params);
    try expectSequences(&rig, params, &[_]u32{0xfffffffd});
}

test "tests_createrawtx_vout_range: row 3 rbf true + 0xfffffffe -> -8 contradiction" {
    // One above MAX_BIP125_RBF_SEQUENCE — the tight boundary on the other
    // side. MAX_SEQUENCE_NONFINAL is still non-final for locktime purposes but
    // is NOT RBF-signalling.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try rbfParams(allocator, "4294967294", "true");
    defer allocator.free(params);
    try expectRpcError(&rig, params, -8, CONTRADICT_MSG);
}

test "tests_createrawtx_vout_range: row 4 rbf true + 0xffffffff -> -8 contradiction" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try rbfParams(allocator, "4294967295", "true");
    defer allocator.free(params);
    try expectRpcError(&rig, params, -8, CONTRADICT_MSG);
}

test "tests_createrawtx_vout_range: row 5 rbf true + NO inputs is ACCEPTED" {
    // A transaction with no inputs cannot signal, and Core does not punish it:
    // rawTx.vin.size() > 0 short-circuits first. Dropping that guard turns
    // this legal call into an error.
    //
    // Asserted on the RAW BYTES rather than through the deserializer: a
    // zero-input tx serializes as `02000000 00 01 ...`, whose 0x00 0x01 is
    // byte-identical to the BIP-144 segwit marker+flag, so any witness-aware
    // reader (ours and Core's alike) mis-reads it. Byte 5 — right after the
    // 4-byte version — is the CompactSize input count and must be 0.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try std.fmt.allocPrint(allocator, "[[],{s},0,true]", .{OUTPUTS});
    defer allocator.free(params);

    const resp = try rig.dispatchCreateRaw(params);
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nexpected success, got error reply: {s}\n", .{resp});
        return error.UnexpectedRpcError;
    }
    const hex = parsed.value.object.get("result").?.string;
    try testing.expect(hex.len >= 10);
    try testing.expectEqualStrings("00", hex[8..10]);
}

test "tests_createrawtx_vout_range: row 6 rbf true + ONE of two inputs signals is ACCEPTED" {
    // SignalsOptInRBF is ANY, not ALL — deliberately, so that in a multi-party
    // protocol one participant cannot disable replacement by opting out in
    // their own input. A check written as "every input must signal" passes
    // rows 3 and 4 and fails here.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"{s}\",\"vout\":0,\"sequence\":4294967295}}," ++
            "{{\"txid\":\"{s}\",\"vout\":1,\"sequence\":0}}],{s},0,true]",
        .{ TXID, TXID, OUTPUTS },
    );
    defer allocator.free(params);
    try expectSequences(&rig, params, &[_]u32{ 0xffffffff, 0 });
}

test "tests_createrawtx_vout_range: row 7 rbf FALSE + final sequence is ACCEPTED" {
    // The caller asserted NON-replaceable and supplied a matching sequence.
    // Nothing contradicts anything; rbf.value() is false.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try rbfParams(allocator, "4294967295", "false");
    defer allocator.free(params);
    try expectSequences(&rig, params, &[_]u32{0xffffffff});
}

test "tests_createrawtx_vout_range: row 8 rbf true + NO explicit sequence is ACCEPTED" {
    // The single most common RBF call there is. With no "sequence" key
    // AddInputs picks MAX_BIP125_RBF_SEQUENCE because rbf.value_or(true) is
    // true, so the default is itself signalling and the check is satisfied.
    // Breaking this row would break the RPC for its main use — and the
    // assertion is on the EMITTED sequence, so a handler that accepted while
    // writing SEQUENCE_FINAL still fails.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try rbfParams(allocator, null, "true");
    defer allocator.free(params);
    try expectSequences(&rig, params, &[_]u32{0xfffffffd});
}

test "tests_createrawtx_vout_range: an OUTPUT error still outranks the contradiction" {
    // Core runs the check as the LAST statement of ConstructTransaction, after
    // AddOutputs, so a bad output is reported first even though the
    // rbf/sequence pair also contradicts. Hoisting the check up next to the
    // input loop — where it reads more naturally — silently changes which
    // error this request reports. Pins the placement.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const params = try std.fmt.allocPrint(
        allocator,
        "[[{{\"txid\":\"{s}\",\"vout\":0,\"sequence\":4294967295}}]," ++
            "{{\"notanaddress\":0.1}},0,true]",
        .{TXID},
    );
    defer allocator.free(params);

    const resp = try rig.dispatchCreateRaw(params);
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v != .object) {
        std.debug.print("\nexpected an output error, got: {s}\n", .{resp});
        return error.ExpectedRpcErrorGotSuccess;
    }
    const got_msg = err_v.object.get("message").?.string;
    if (std.mem.eql(u8, got_msg, CONTRADICT_MSG)) {
        std.debug.print(
            "\nthe contradiction check outranked the OUTPUT error; Core reports the output error first: {s}\n",
            .{resp},
        );
        return error.ContradictionCheckRanTooEarly;
    }
    // The address error itself: -5 RPC_INVALID_ADDRESS_OR_KEY.  Asserted on
    // the PREFIX, not the whole string: clearbit still says "Invalid Bitcoin
    // address" where Core says "Invalid Bitcoin address: <addr>". That gap is
    // a separate, known divergence and is deliberately NOT what this row is
    // about — this row is only about WHICH error wins.
    try testing.expectEqual(@as(i64, -5), err_v.object.get("code").?.integer);
    try testing.expect(std.mem.startsWith(u8, got_msg, "Invalid Bitcoin address"));
}
