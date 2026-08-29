//! createpsbt must build its outputs the way createrawtransaction does.
//!
//! Run via `zig build test-createpsbt-outputs`.
//!
//! THE DEFECT
//! ----------
//! `createpsbt` never decoded the destination address.  Every non-data output
//! got a hardcoded placeholder scriptPubKey — `0014` followed by twenty zero
//! bytes — with the source comment "in production, decode the address / This
//! is a simplified implementation".  The address was not mis-encoded; it was
//! never read.  Measured, two valid regtest addresses:
//!
//!   bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080              -> PSBT X
//!   bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 -> PSBT X
//!
//! Byte-identical.  A PSBT built to pay someone paid an unspendable script
//! instead, and the caller had no way to tell from the reply.
//!
//! Two more defects lived in the same block:
//!
//!   * `@intCast(amount_val.integer * 100_000_000)` — the MULTIPLY overflows
//!     i64 before the cast is reached.  92233720368 was ACCEPTED and serialised
//!     as a wrapped value near i64::MAX.  The float path had no bound at all,
//!     so 1e300 serialised as i64::MIN.
//!   * the object form of `outputs` was rejected outright, though Core accepts
//!     both forms.
//!
//! WHAT BITCOIN CORE DOES
//! ----------------------
//! Core builds createrawtransaction, createpsbt and walletcreatefundedpsbt from
//! ONE routine: ConstructTransaction -> ParseOutputs (rawtransaction_util.cpp).
//! Outputs may be an object or an array —
//! `outputs_is_obj ? outputs_in.get_obj() : outputs_in.get_array()` (:80-81) —
//! amounts go through AmountFromValue, which range-checks against MoneyRange and
//! raises RPC_TYPE_ERROR (-3) "Amount out of range", and destinations go through
//! DecodeDestination + GetScriptForDestination.
//!
//! THE ROOT CAUSE IS THE DUPLICATION, so the fix is to remove it: clearbit's
//! builder is now one file-scope `appendTxOutput`, shared by all three methods,
//! rather than three copies that drifted apart.  That is also how #81's PSBT
//! node-kills survived a sweep of createrawtransaction — the sweep tested one
//! sibling and the other two had their own parsers.
//!
//! HOW THIS FAILS AT THE PARENT COMMIT
//! -----------------------------------
//! By assertion, not by crash.  At the parent, "two different addresses" returns
//! two identical PSBTs and the placeholder-detection test finds twenty zero
//! bytes where a real witness program belongs.
//!
//! References:
//!   bitcoin-core/src/rpc/rawtransaction_util.cpp:80-120  ParseOutputs
//!   bitcoin-core/src/rpc/util.cpp                        AmountFromValue
//!   bitcoin-core/src/rpc/protocol.h                      RPC_TYPE_ERROR = -3

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");

const TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
const ADDR_A = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const ADDR_B = "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4ncqjuxsq";

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
        pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
        const srv = try allocator.create(rpc.RpcServer);
        srv.* = rpc.RpcServer.init(allocator, cs, mp, pm, &consensus.REGTEST, .{});
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
    fn dispatch(self: *Rig, method: []const u8, params_json: []const u8) ![]const u8 {
        const req = try std.fmt.allocPrint(self.allocator,
            "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        defer self.allocator.free(req);
        return self.server.dispatch(req);
    }
};

/// Returns the caller-owned `result` string, or an error if the reply carried
/// an error object (printing it, so a failure names the actual reply).
fn resultOf(rig: *Rig, method: []const u8, params_json: []const u8) ![]const u8 {
    const resp = try rig.dispatch(method, params_json);
    defer rig.allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v == .object) {
        std.debug.print("\n{s}: unexpected error reply: {s}\n", .{ method, resp });
        return error.UnexpectedRpcError;
    }
    return try rig.allocator.dupe(u8, parsed.value.object.get("result").?.string);
}

fn expectError(rig: *Rig, method: []const u8, params_json: []const u8,
               want_code: i64, want_msg: []const u8) !void {
    const resp = try rig.dispatch(method, params_json);
    defer rig.allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v != .object) {
        std.debug.print("\n{s}: expected {d} \"{s}\", got SUCCESS: {s}\n",
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

fn paramsFor(allocator: std.mem.Allocator, outputs: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        "[[{{\"txid\":\"{s}\",\"vout\":0}}],{s}]", .{ TXID, outputs });
}

// ==========================================================================
// THE REGRESSION
// ==========================================================================

test "tests_createpsbt_outputs: two different addresses must not give the same psbt" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const pa = try paramsFor(allocator, "[{\"" ++ ADDR_A ++ "\":0.001}]");
    defer allocator.free(pa);
    const pb = try paramsFor(allocator, "[{\"" ++ ADDR_B ++ "\":0.001}]");
    defer allocator.free(pb);

    const a = try resultOf(&rig, "createpsbt", pa);
    defer allocator.free(a);
    const b = try resultOf(&rig, "createpsbt", pb);
    defer allocator.free(b);

    if (std.mem.eql(u8, a, b)) {
        std.debug.print("\ntwo DIFFERENT addresses produced a byte-identical psbt:\n  {s}\n", .{a});
        return error.AddressIgnored;
    }
}

test "tests_createpsbt_outputs: the psbt must not carry the zero-witness placeholder" {
    // The pre-fix script was 0x00 0x14 followed by twenty zero bytes.  A real
    // P2WPKH program is never all zeros, so finding that run of zeros in the
    // serialised transaction means the address was not decoded.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();

    const raw = try paramsFor(allocator, "[{\"" ++ ADDR_A ++ "\":0.001}]");
    defer allocator.free(raw);
    const b64 = try resultOf(&rig, "createpsbt", raw);
    defer allocator.free(b64);

    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    const bytes = try allocator.alloc(u8, n);
    defer allocator.free(bytes);
    try dec.decode(bytes, b64);

    const placeholder = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x00} ** 20;
    if (std.mem.indexOf(u8, bytes, &placeholder) != null) {
        std.debug.print("\npsbt contains the placeholder script (address not decoded)\n", .{});
        return error.PlaceholderScriptPresent;
    }
}

test "tests_createpsbt_outputs: integer amount past MAX_MONEY -> -3 Amount out of range" {
    // 92233720368 * 100_000_000 overflows i64.  Pre-fix this was ACCEPTED and
    // serialised as a wrapped value; the multiply now cannot be reached.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const p = try paramsFor(allocator, "[{\"" ++ ADDR_A ++ "\":92233720368}]");
    defer allocator.free(p);
    try expectError(&rig, "createpsbt", p, -3, "Amount out of range");
}

test "tests_createpsbt_outputs: float amount 1e300 -> -3 Amount out of range" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const p = try paramsFor(allocator, "[{\"" ++ ADDR_A ++ "\":1e300}]");
    defer allocator.free(p);
    try expectError(&rig, "createpsbt", p, -3, "Amount out of range");
}

test "tests_createpsbt_outputs: outputs as an OBJECT is accepted, as Core accepts it" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const p = try paramsFor(allocator, "{\"" ++ ADDR_A ++ "\":0.001}");
    defer allocator.free(p);
    const r = try resultOf(&rig, "createpsbt", p);
    defer allocator.free(r);
    try testing.expect(r.len > 0);
}

test "tests_createpsbt_outputs: an invalid address is REJECTED, not silently replaced" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const p = try paramsFor(allocator, "[{\"not-an-address\":0.001}]");
    defer allocator.free(p);
    try expectError(&rig, "createpsbt", p, -5, "Invalid Bitcoin address");
}

// ==========================================================================
// CONTROLS — every test above is satisfiable by a handler that rejects
// everything or returns something different each time.  These are not.
// ==========================================================================

test "tests_createpsbt_outputs: CONTROL the same address twice is deterministic" {
    // Guards against "make the outputs differ" being satisfied by nondeterminism
    // (a timestamp, a counter, uninitialised memory) rather than by decoding.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const p = try paramsFor(allocator, "[{\"" ++ ADDR_A ++ "\":0.001}]");
    defer allocator.free(p);
    const a = try resultOf(&rig, "createpsbt", p);
    defer allocator.free(a);
    const b = try resultOf(&rig, "createpsbt", p);
    defer allocator.free(b);
    try testing.expectEqualStrings(a, b);
}

test "tests_createpsbt_outputs: CONTROL createpsbt and createrawtransaction agree on the script" {
    // Core builds both from one routine, so the scriptPubKey bytes must match.
    // This is the assertion that actually pins "shares the builder": it fails
    // if createpsbt regrows its own output parser, even a correct one that
    // happens to differ.
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const p = try paramsFor(allocator, "[{\"" ++ ADDR_A ++ "\":0.001}]");
    defer allocator.free(p);

    const b64 = try resultOf(&rig, "createpsbt", p);
    defer allocator.free(b64);
    const hex = try resultOf(&rig, "createrawtransaction", p);
    defer allocator.free(hex);

    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    const psbt_bytes = try allocator.alloc(u8, n);
    defer allocator.free(psbt_bytes);
    try dec.decode(psbt_bytes, b64);

    const raw_bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(raw_bytes);
    _ = try std.fmt.hexToBytes(raw_bytes, hex);

    // The output script produced by createrawtransaction must appear verbatim
    // inside the PSBT's unsigned transaction.
    const spk_start = std.mem.indexOf(u8, raw_bytes, &[_]u8{ 0x00, 0x14 }) orelse {
        std.debug.print("\ncontrol setup failed: no P2WPKH script in the raw tx\n", .{});
        return error.ControlSetupFailed;
    };
    const spk = raw_bytes[spk_start .. spk_start + 22];
    if (std.mem.indexOf(u8, psbt_bytes, spk) == null) {
        std.debug.print("\ncreatepsbt and createrawtransaction disagree on the output script\n", .{});
        return error.BuildersDisagree;
    }
}

test "tests_createpsbt_outputs: CONTROL a data output still builds an OP_RETURN" {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator);
    defer rig.deinit();
    const p = try paramsFor(allocator, "[{\"data\":\"deadbeef\"}]");
    defer allocator.free(p);
    const b64 = try resultOf(&rig, "createpsbt", p);
    defer allocator.free(b64);

    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    const bytes = try allocator.alloc(u8, n);
    defer allocator.free(bytes);
    try dec.decode(bytes, b64);
    // 6a 04 de ad be ef
    const want = [_]u8{ 0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef };
    try testing.expect(std.mem.indexOf(u8, bytes, &want) != null);
}
