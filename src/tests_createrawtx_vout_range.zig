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
