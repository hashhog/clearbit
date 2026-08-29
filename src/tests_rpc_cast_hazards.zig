//! Unchecked narrowing casts on RPC integer arguments — the node-kill class.
//!
//! Run via `zig build test-cast-hazards`.
//!
//! THE DEFECT
//! ----------
//! Zig's `@intCast` is checked in Debug and ReleaseSafe but PANICS in the
//! ReleaseFast build the fleet actually ships.  Every RPC argument that reaches
//! a narrowing cast without a prior range check is therefore a remote,
//! single-request node-kill: the handler aborts the whole process with
//! "integer cast truncated bits".  Not a wrong answer — no answer, and no node.
//!
//! `getblockhash 4294967296` killed the LIVE MAINNET clearbit process at
//! 01:41:25 on 2026-08-29 (SIGABRT, restart counter 1).  Five more handlers had
//! the same hole:
//!
//!   gettxout <txid> 4294967296              -> SIGABRT   (fixed 1b0cc35)
//!   deriveaddresses <desc> 4294967296       -> SIGABRT   (fixed 1b0cc35)
//!   getrawtransaction <txid> -4294967297    -> SIGABRT
//!   createpsbt [..] {} 4294967296           -> SIGABRT
//!   walletcreatefundedpsbt [..] {} 4294967296 -> SIGABRT
//!   getnetworkhashps 120 4294967296         -> SIGABRT
//!
//! Two of them are worth naming, because both LOOK guarded:
//!
//!   gettxout          `if (v.integer < 0) return ...;  @intCast(v.integer);`
//!                     A guard on one end of a range is not a range check.
//!
//!   getrawtransaction `verbosity = @intCast(@min(v.integer, 2));
//!                      if (v.integer < 0) verbosity = 0;`
//!                     The negative guard is one line BELOW the cast that
//!                     crashes, so it never runs for the values it rejects.
//!                     `@min` bounds the top only.
//!
//! And one about scope: Core builds createrawtransaction, createpsbt and
//! walletcreatefundedpsbt from ONE argument builder (ConstructTransaction,
//! rawtransaction_util.cpp).  clearbit has three separate parsers, so the
//! bounds added to createrawtransaction in the earlier sweep left both PSBT
//! entry points still crashing.
//!
//! WHAT BITCOIN CORE DOES
//! ----------------------
//! Core reads each of these with univalue's `getInt<int>()` — a THIRTY-TWO bit
//! parse (univalue.h:139-150).  The width check lives inside the conversion, so
//! it runs BEFORE the handler's own domain test, and rpc/server.cpp:514-515
//! reports it as RPC_MISC_ERROR (-1) "JSON integer out of range".  That is why
//! `vout -1` gets the vout-specific -8 while `vout -2147483649` — equally "not
//! a vout" to a human — gets the generic -1.
//!
//! HOW THIS FAILS AT THE PARENT COMMIT
//! -----------------------------------
//! BY CRASHING, not by assertion.  At the parent, each hostile case aborts the
//! test binary itself with "integer cast truncated bits"; there is no error
//! object to compare.  A mutation run therefore shows a dead test process, not
//! a red assertion, and that IS the pin — the defect is that the process dies.
//! The CONTROLS below are what stop "reject everything" from passing: they
//! drive the same handlers to a real answer and check the answer.
//!
//! References:
//!   bitcoin-core/src/rpc/blockchain.cpp        gettxout, getblockhash
//!   bitcoin-core/src/rpc/rawtransaction.cpp    getrawtransaction, createpsbt
//!   bitcoin-core/src/rpc/rawtransaction_util.cpp  ConstructTransaction/AddInputs
//!   bitcoin-core/src/rpc/mining.cpp            getnetworkhashps (Arg<int> x2)
//!   bitcoin-core/src/rpc/output_script.cpp     deriveaddresses (range)
//!   bitcoin-core/src/univalue/include/univalue.h:139-150  getInt<Int>

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");

const TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
const DESC = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

const OUT_OF_RANGE = "JSON integer out of range";

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
        return .{ .allocator = allocator, .chain_state = cs, .mempool = mp,
                  .peer_manager = pm, .server = srv };
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
    /// Drive the REAL dispatcher, not a reimplementation of the parser.
    fn dispatch(self: *Rig, method: []const u8, params_json: []const u8) ![]const u8 {
        const req = try std.fmt.allocPrint(self.allocator,
            "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        defer self.allocator.free(req);
        return self.server.dispatch(req);
    }
};

/// Assert the dispatcher ANSWERS (the process is still alive to answer at all)
/// with Core's code and message.  A success reply is reported as its own
/// failure rather than passing quietly.
fn expectError(method: []const u8, params_json: []const u8,
               want_code: i64, want_msg: []const u8) !void {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const resp = try rig.dispatch(method, params_json);
    defer allocator.free(resp);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();

    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v != .object) {
        std.debug.print("\n{s}: expected error {d} \"{s}\", got SUCCESS: {s}\n",
            .{ method, want_code, want_msg, resp });
        return error.ExpectedRpcErrorGotSuccess;
    }
    const got_code = err_v.object.get("code").?.integer;
    const got_msg = err_v.object.get("message").?.string;
    if (got_code != want_code or !std.mem.eql(u8, got_msg, want_msg)) {
        std.debug.print("\n{s}: expected {d} \"{s}\", got {d} \"{s}\"\n",
            .{ method, want_code, want_msg, got_code, got_msg });
    }
    try testing.expectEqual(want_code, got_code);
    try testing.expectEqualStrings(want_msg, got_msg);
}

// ==========================================================================
// THE SIX KILL VECTORS.  Each is its own test so a mutation run reports
// every handler independently instead of dying at the first one.
// ==========================================================================

test "tests_rpc_cast_hazards: gettxout vout 2^32 -> -1, not a dead process" {
    try expectError("gettxout", "[\"" ++ TXID ++ "\",4294967296]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: gettxout vout int32 MIN-1 -> -1, range beats sign" {
    try expectError("gettxout", "[\"" ++ TXID ++ "\",-2147483649]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: deriveaddresses range 2^32 -> -1" {
    try expectError("deriveaddresses", "[\"" ++ DESC ++ "\",4294967296]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: deriveaddresses range pair [0, 2^32] -> -1" {
    try expectError("deriveaddresses", "[\"" ++ DESC ++ "\",[0,4294967296]]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: getrawtransaction verbosity -4294967297 -> -1" {
    // The guard for this value existed at the parent — one line BELOW the
    // cast that crashed before it could run.
    try expectError("getrawtransaction", "[\"" ++ TXID ++ "\",-4294967297]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: getrawtransaction verbosity 2^32 -> -1" {
    try expectError("getrawtransaction", "[\"" ++ TXID ++ "\",4294967296]", -1, OUT_OF_RANGE);
}
// NOTE ON THE OUTPUTS ARGUMENT: these cases pass `outputs` as an ARRAY, not
// an object, because clearbit's createpsbt rejects the object form outright
// ("inputs and outputs must be arrays", -32602) before it ever reaches the
// locktime parser.  Core accepts BOTH forms —
// `outputs_is_obj ? outputs_in.get_obj() : outputs_in.get_array()`
// (rawtransaction_util.cpp:80-81) — so that rejection is a real divergence in
// its own right, tracked separately.  It is deliberately NOT pinned here: this
// suite is about narrowing casts, and a test that fails for two unrelated
// reasons diagnoses neither.
test "tests_rpc_cast_hazards: createpsbt locktime 2^32 -> -8 locktime out of range" {
    // Inside int64 but outside Core's [0, LOCKTIME_MAX]: the domain error,
    // reached only because the cast no longer fires first.
    try expectError("createpsbt",
        "[[{\"txid\":\"" ++ TXID ++ "\",\"vout\":0}],[{\"data\":\"deadbeef\"}],4294967296]",
        -8, "Invalid parameter, locktime out of range");
}
test "tests_rpc_cast_hazards: createpsbt vout int32 MAX+1 -> -1" {
    try expectError("createpsbt",
        "[[{\"txid\":\"" ++ TXID ++ "\",\"vout\":2147483648}],[{\"data\":\"deadbeef\"}]]",
        -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: createpsbt sequence 2^32 -> -8 sequence out of range" {
    try expectError("createpsbt",
        "[[{\"txid\":\"" ++ TXID ++ "\",\"vout\":0,\"sequence\":4294967296}],[{\"data\":\"deadbeef\"}]]",
        -8, "Invalid parameter, sequence number is out of range");
}
test "tests_rpc_cast_hazards: getnetworkhashps height 2^32 -> -1" {
    try expectError("getnetworkhashps", "[120,4294967296]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: getnetworkhashps nblocks 2^32 -> -1" {
    try expectError("getnetworkhashps", "[4294967296]", -1, OUT_OF_RANGE);
}

// ==========================================================================
// CONTROLS.  Without these, a handler that rejected every input would pass
// every test above.  Each drives the SAME handler to a real answer.
// ==========================================================================

test "tests_rpc_cast_hazards: CONTROL getnetworkhashps [120,-1] answers a number" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const resp = try rig.dispatch("getnetworkhashps", "[120,-1]");
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nCONTROL failed, getnetworkhashps errored: {s}\n", .{resp});
        return error.ControlRejected;
    }
}

test "tests_rpc_cast_hazards: CONTROL int32-MAX values are NOT rejected as out of range" {
    // Off-by-one in the tight direction: 2147483647 is IN range for Core, so
    // none of these may answer -1.  A bound written as `> 2147483646` or a
    // `>=` slip fails here and nowhere else.
    const allocator = testing.allocator;
    inline for (.{
        .{ "gettxout", "[\"" ++ TXID ++ "\",2147483647]" },
        .{ "getrawtransaction", "[\"" ++ TXID ++ "\",2147483647]" },
        .{ "getnetworkhashps", "[2147483647,-1]" },
    }) |c| {
        var rig = try Rig.init(allocator);
        defer rig.deinit();
        const resp = try rig.dispatch(c[0], c[1]);
        defer allocator.free(resp);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
        defer parsed.deinit();
        const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
        if (err_v == .object) {
            const msg = err_v.object.get("message").?.string;
            if (std.mem.eql(u8, msg, OUT_OF_RANGE)) {
                std.debug.print("\n{s}: int32 MAX wrongly rejected as out of range\n", .{c[0]});
                return error.Int32MaxRejected;
            }
        }
    }
}

test "tests_rpc_cast_hazards: CONTROL createpsbt builds a psbt from in-range args" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const resp = try rig.dispatch("createpsbt",
        "[[{\"txid\":\"" ++ TXID ++ "\",\"vout\":0,\"sequence\":4294967295}],[{\"data\":\"deadbeef\"}],0]");
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nCONTROL failed, createpsbt errored on valid args: {s}\n", .{resp});
        return error.ControlRejected;
    }
    const r = parsed.value.object.get("result").?;
    try testing.expect(r == .string and r.string.len > 0);
}

// ==========================================================================
// waitfor* timeout — the same unchecked range, with a worse consequence.
//
// Core reads the timeout with getInt<int>() (rpc/blockchain.cpp), so a value
// outside int32 fails inside the conversion, before the "Negative timeout"
// check.  clearbit accepted 4294967296 and started a ~49-day wait; because its
// RPC server handles requests serially, the node then answered NOTHING —
// getblockcount timed out, the process stayed alive, and only a restart
// recovered it.  One unprivileged request disabled the entire RPC interface.
//
// The wedge itself is broader than this bound: any large-but-valid timeout
// still occupies the server.  That is a separate, architectural defect and is
// tracked separately; these tests pin the argument bound only, and say so
// rather than implying the wedge is closed.
// ==========================================================================

test "tests_rpc_cast_hazards: waitforblock timeout 2^32 -> -1" {
    try expectError("waitforblock", "[\"" ++ TXID ++ "\",4294967296]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: waitfornewblock timeout 2^32 -> -1" {
    try expectError("waitfornewblock", "[4294967296]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: waitforblockheight timeout 2^32 -> -1" {
    try expectError("waitforblockheight", "[0,4294967296]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: waitforblock timeout int32 MIN-1 -> -1, range beats sign" {
    // Both out of range AND negative.  Core answers -1 "JSON integer out of
    // range", not "Negative timeout": the width check lives inside the
    // conversion and therefore runs first.
    try expectError("waitforblock", "[\"" ++ TXID ++ "\",-4294967297]", -1, OUT_OF_RANGE);
}
test "tests_rpc_cast_hazards: CONTROL waitforblock timeout -1 still says Negative timeout" {
    // The new bound must not swallow the in-range negative case: that ordering
    // is Core's and the earlier commit's ordering bug was exactly this shape.
    try expectError("waitforblock", "[\"" ++ TXID ++ "\",-1]", -1, "Negative timeout");
}
test "tests_rpc_cast_hazards: CONTROL waitfornewblock with a 1ms timeout still returns" {
    // Without this, "reject every timeout" would satisfy all of the above.
    // A 1ms wait must come back promptly with a result, not an error.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const resp = try rig.dispatch("waitfornewblock", "[1]");
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nCONTROL failed, waitfornewblock[1] errored: {s}\n", .{resp});
        return error.ControlRejected;
    }
}

// ==========================================================================
// createrawtransaction / createpsbt must HONOUR the `version` argument (#84).
//
// Core's createrawtransaction takes a 5th argument, `version`
// (rpc/rawtransaction.cpp:122), reads it as `self.Arg<uint32_t>("version")`,
// bounds it to [TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION] = [1, 3]
// (policy/policy.h:152-153) and ASSIGNS it (rawtransaction_util.cpp:158-161).
//
// clearbit hardcoded `.version = 2` in BOTH handlers and ignored the argument.
// Asked for version 1, 2 or 3 it returned 02000000 every time, and version 4 —
// which Core rejects — was accepted. Version 3 is TRUC (BIP 431), so a caller
// who asked for v3 and got v2 holds a transaction with different relay
// behaviour than the one requested.
//
// THE WIDTH IS UNSIGNED here, unlike every other argument in this suite: 2^31
// fits a uint32, survives the conversion and reaches the DOMAIN error (-8),
// while -1 and 2^32 fail the CONVERSION first (-1). Both pinned.
//
// These assertions DECODE THE VERSION BYTES off the returned transaction.
// Asserting the call was accepted is exactly the pre-fix behaviour.
// ==========================================================================

/// First 4 bytes of the returned tx hex, little-endian.
fn versionOfReply(allocator: std.mem.Allocator, resp: []const u8) !i64 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\nexpected a transaction, got error reply: {s}\n", .{resp});
        return error.UnexpectedRpcError;
    }
    const hex = parsed.value.object.get("result").?.string;
    if (hex.len < 8) return error.ReplyTooShort;
    var b: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, hex[0..8]);
    return @as(i64, b[0]) | (@as(i64, b[1]) << 8) | (@as(i64, b[2]) << 16) | (@as(i64, b[3]) << 24);
}

fn createrawWithVersion(rig: *Rig, version_literal: ?[]const u8) ![]const u8 {
    const params = if (version_literal) |v|
        try std.fmt.allocPrint(rig.allocator,
            "[[{{\"txid\":\"{s}\",\"vout\":0}}],{{\"data\":\"deadbeef\"}},0,false,{s}]",
            .{ TXID, v })
    else
        try std.fmt.allocPrint(rig.allocator,
            "[[{{\"txid\":\"{s}\",\"vout\":0}}],{{\"data\":\"deadbeef\"}},0,false]",
            .{TXID});
    defer rig.allocator.free(params);
    return rig.dispatch("createrawtransaction", params);
}

test "tests_rpc_cast_hazards: createrawtransaction emits versions 1, 2 and 3" {
    const allocator = testing.allocator;
    inline for (.{ .{ "1", 1 }, .{ "2", 2 }, .{ "3", 3 } }) |c| {
        var rig = try Rig.init(allocator);
        defer rig.deinit();
        const resp = try createrawWithVersion(&rig, c[0]);
        defer allocator.free(resp);
        const got = try versionOfReply(allocator, resp);
        if (got != c[1]) {
            std.debug.print("\nasked for version {s}, transaction carries {d}\n", .{ c[0], got });
            return error.VersionNotHonoured;
        }
    }
}

test "tests_rpc_cast_hazards: createrawtransaction version outside [1,3] -> -8" {
    inline for (.{ "0", "4", "2147483648" }) |bad| {
        const allocator = testing.allocator;
        var rig = try Rig.init(allocator);
        defer rig.deinit();
        const params = try std.fmt.allocPrint(allocator,
            "[[{{\"txid\":\"{s}\",\"vout\":0}}],{{\"data\":\"deadbeef\"}},0,false,{s}]",
            .{ TXID, bad });
        defer allocator.free(params);
        const resp = try rig.dispatch("createrawtransaction", params);
        defer allocator.free(resp);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
        defer parsed.deinit();
        const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
        if (err_v != .object) {
            std.debug.print("\nversion {s} was ACCEPTED: {s}\n", .{ bad, resp });
            return error.OutOfDomainVersionAccepted;
        }
        try testing.expectEqual(@as(i64, -8), err_v.object.get("code").?.integer);
        try testing.expectEqualStrings("Invalid parameter, version out of range(1~3)",
            err_v.object.get("message").?.string);
    }
}

test "tests_rpc_cast_hazards: createrawtransaction version outside uint32 -> -1" {
    // Paired with the test above: -8 inside uint32, -1 outside it. The split is
    // at the UNSIGNED edge, which is what makes this argument different from
    // vout.
    inline for (.{ "-1", "-2147483649", "4294967296" }) |bad| {
        const allocator = testing.allocator;
        var rig = try Rig.init(allocator);
        defer rig.deinit();
        const params = try std.fmt.allocPrint(allocator,
            "[[{{\"txid\":\"{s}\",\"vout\":0}}],{{\"data\":\"deadbeef\"}},0,false,{s}]",
            .{ TXID, bad });
        defer allocator.free(params);
        const resp = try rig.dispatch("createrawtransaction", params);
        defer allocator.free(resp);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
        defer parsed.deinit();
        const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
        if (err_v != .object) {
            std.debug.print("\nversion {s} was ACCEPTED: {s}\n", .{ bad, resp });
            return error.OutOfRangeVersionAccepted;
        }
        try testing.expectEqual(@as(i64, -1), err_v.object.get("code").?.integer);
        try testing.expectEqualStrings("JSON integer out of range",
            err_v.object.get("message").?.string);
    }
}

test "tests_rpc_cast_hazards: CONTROL absent version defaults to 2" {
    // Without this, a handler that rejected every version would pass every
    // rejection test above.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const resp = try createrawWithVersion(&rig, null);
    defer allocator.free(resp);
    try testing.expectEqual(@as(i64, 2), try versionOfReply(allocator, resp));
}
