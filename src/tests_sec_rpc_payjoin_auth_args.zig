//! Security audit 2026-10-29 (audits/security/clearbit-2026-10-29.md in the
//! meta-repo), findings C6, H4, H5 and H6.
//!
//!   C6  POST /payjoin is answered before the RPC auth check, and its PSBT
//!       parser sized the witness vector from an attacker count: one 104-byte
//!       POST committed ~512 MiB and leaked it.
//!   H4  RPC numeric parameters reached bare @intFromFloat / @intCast / `*`:
//!       one authenticated request aborted the node (20 sites).
//!   H5  RPC was served one connection at a time, so idle sockets froze it.
//!   H6  importdescriptors range had no cap (Core: end < 2^31, width < 1e6).
//!
//! HOW THESE FAIL AT THE PARENT COMMIT
//!   C6, H5, H6 fail by assertion.  The H4 cases fail by CRASHING the test
//!   binary with "integer part of floating point value out of bounds" /
//!   "integer cast truncated bits" / "integer overflow", which is the defect.
//!   Because a crash stops the binary at the first such test, each test can be
//!   run alone with SEC_RPC_ONLY=<tag> (no recompile): every other test in
//!   this file then skips.
//!
//! Run: zig build test-unit -Dtest-filter=sec_rpc

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const psbt = @import("psbt.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const wallet_mod = @import("wallet.zig");

/// Run only the test tagged `tag` when SEC_RPC_ONLY is set (see header).
fn only(comptime tag: []const u8) !void {
    const sel = std.posix.getenv("SEC_RPC_ONLY") orelse return;
    if (!std.mem.eql(u8, sel, tag)) return error.SkipZigTest;
}

// ---------------------------------------------------------------------------
// An allocator that, once armed, refuses any single request above `cap` and
// records the largest one asked for.  Delegates to testing.allocator, so leaks
// still fail.  Arm it after setup: RpcServer/ChainState init make their own
// large, legitimate allocations.
// ---------------------------------------------------------------------------
const CappedAllocator = struct {
    child: std.mem.Allocator,
    cap: usize,
    peak_request: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    armed: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    fn allocator(self: *CappedAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .free = free } };
    }
    fn note(self: *CappedAllocator, n: usize) void {
        if (!self.armed.load(.acquire)) return;
        var cur = self.peak_request.load(.monotonic);
        while (n > cur) {
            cur = self.peak_request.cmpxchgWeak(cur, n, .monotonic, .monotonic) orelse return;
        }
    }
    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret: usize) ?[*]u8 {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        self.note(len);
        if (self.armed.load(.acquire) and len > self.cap) return null;
        return self.child.rawAlloc(len, ptr_align, ret);
    }
    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret: usize) bool {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        self.note(new_len);
        if (self.armed.load(.acquire) and new_len > self.cap) return false;
        return self.child.rawResize(buf, buf_align, new_len, ret);
    }
    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret: usize) void {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(buf, buf_align, ret);
    }
};

const CAP: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Rig: a real RpcServer (optionally with a wallet), driven through dispatch.
// ---------------------------------------------------------------------------
const Rig = struct {
    allocator: std.mem.Allocator,
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    peer_manager: *peer_mod.PeerManager,
    server: *rpc.RpcServer,
    wallet: ?*wallet_mod.Wallet = null,

    fn init(allocator: std.mem.Allocator, config: rpc.RpcConfig, with_wallet: bool) !Rig {
        const cs = try allocator.create(storage.ChainState);
        cs.* = storage.ChainState.init(null, 64, allocator);
        const mp = try allocator.create(mempool_mod.Mempool);
        mp.* = mempool_mod.Mempool.init(null, null, allocator);
        const pm = try allocator.create(peer_mod.PeerManager);
        pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
        const srv = try allocator.create(rpc.RpcServer);
        srv.* = rpc.RpcServer.init(allocator, cs, mp, pm, &consensus.REGTEST, config);
        var rig: Rig = .{ .allocator = allocator, .chain_state = cs, .mempool = mp, .peer_manager = pm, .server = srv };
        if (with_wallet) {
            const w = try allocator.create(wallet_mod.Wallet);
            w.* = try wallet_mod.Wallet.init(allocator, .regtest);
            srv.wallet = w;
            rig.wallet = w;
        }
        return rig;
    }
    fn deinit(self: *Rig) void {
        self.server.deinit();
        if (self.wallet) |w| {
            w.deinit();
            self.allocator.destroy(w);
        }
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
        self.allocator.destroy(self.server);
        self.allocator.destroy(self.peer_manager);
        self.allocator.destroy(self.mempool);
        self.allocator.destroy(self.chain_state);
    }
    fn dispatch(self: *Rig, method: []const u8, params_json: []const u8) ![]const u8 {
        const req = try std.fmt.allocPrint(self.allocator, "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        defer self.allocator.free(req);
        return self.server.dispatch(req);
    }
};

/// The dispatcher must ANSWER (the process is alive) with an error object.
/// When `want_msg` is non-null the message must match too, which proves the
/// request reached the guarded site rather than failing earlier.
fn expectRejected(with_wallet: bool, method: []const u8, params_json: []const u8, want_code: ?i64, want_msg: ?[]const u8) !void {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator, .{}, with_wallet);
    defer rig.deinit();
    const resp = try rig.dispatch(method, params_json);
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    const err_v = parsed.value.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v != .object) {
        std.debug.print("\n{s} {s}: expected an error, got {s}\n", .{ method, params_json, resp });
        return error.ExpectedRpcError;
    }
    const got_code = err_v.object.get("code").?.integer;
    const got_msg = err_v.object.get("message").?.string;
    if ((want_code != null and want_code.? != got_code) or (want_msg != null and !std.mem.eql(u8, want_msg.?, got_msg))) {
        std.debug.print("\n{s} {s}: expected {?d} \"{?s}\", got {d} \"{s}\"\n", .{ method, params_json, want_code, want_msg, got_code, got_msg });
        return error.WrongRpcError;
    }
}

const OOR = "JSON integer out of range";
const AOR = "Amount out of range";
const TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
const ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
// version 2, one input (null-ish prevout), one 10000-sat output, empty scripts.
const TX_HEX = "0200000001" ++ "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" ++
    "00000000" ++ "00" ++ "ffffffff" ++ "01" ++ "1027000000000000" ++ "00" ++ "00000000";

// ===========================================================================
// H4 — every row of the audit's table, one test each.
// ===========================================================================

test "sec_rpc H4 getblockstats height 1e300 is rejected, not a dead process" {
    try only("getblockstats");
    try expectRejected(false, "getblockstats", "[1e300]", -1, OOR);
}
test "sec_rpc H4 getchaintxstats nblocks 1e300 is rejected" {
    try only("getchaintxstats");
    try expectRejected(false, "getchaintxstats", "[1e300]", null, null);
}
test "sec_rpc H4 estimaterawfee conf_target 1e300 is rejected" {
    try only("estimaterawfee");
    try expectRejected(false, "estimaterawfee", "[1e300]", -1, OOR);
}
test "sec_rpc H4 setban bantime 1e300 is rejected" {
    try only("setban");
    try expectRejected(false, "setban", "[\"10.0.0.1\",\"add\",1e300]", -1, OOR);
}
test "sec_rpc H4 disconnectnode nodeid 1e300 is rejected" {
    try only("disconnectnode");
    try expectRejected(false, "disconnectnode", "[\"\",1e300]", -1, OOR);
}
test "sec_rpc H4 sendrawtransaction maxfeerate 1e300 is rejected" {
    try only("sendrawtransaction");
    try expectRejected(false, "sendrawtransaction", "[\"" ++ TX_HEX ++ "\",1e300]", -3, AOR);
}
test "sec_rpc H4 addpeeraddress services 1e300 is rejected" {
    try only("addpeeraddress");
    try expectRejected(false, "addpeeraddress", "[\"1.2.3.4\",8333,1e300]", -1, OOR);
}
test "sec_rpc H4 getbalance minconf 1e300 is rejected" {
    try only("getbalance-float");
    try expectRejected(true, "getbalance", "[\"*\",1e300]", -1, OOR);
}
test "sec_rpc H4 getbalance minconf 4294967296 is rejected" {
    try only("getbalance-int");
    try expectRejected(true, "getbalance", "[\"*\",4294967296]", -1, OOR);
}
test "sec_rpc H4 sendtoaddress amount 1e300 is rejected" {
    try only("sendtoaddress-float");
    try expectRejected(true, "sendtoaddress", "[\"" ++ ADDR ++ "\",1e300]", -3, AOR);
}
test "sec_rpc H4 sendtoaddress integer amount that overflows i64 sats is rejected" {
    try only("sendtoaddress-int");
    try expectRejected(true, "sendtoaddress", "[\"" ++ ADDR ++ "\",92233720369]", -3, AOR);
}
test "sec_rpc H4 bumpfee fee_rate 1e300 is rejected" {
    try only("bumpfee");
    try expectRejected(true, "bumpfee", "[\"" ++ TXID ++ "\",{\"fee_rate\":1e300}]", -3, AOR);
}
test "sec_rpc H4 importdescriptors timestamp 1e300 is rejected" {
    try only("importdescriptors-ts");
    try expectImportRejected("{{\"desc\":\"{s}\",\"timestamp\":1e300}}", OOR);
}
test "sec_rpc H4 rescanblockchain start_height 4294967296 is rejected" {
    try only("rescanblockchain");
    try expectRejected(true, "rescanblockchain", "[4294967296]", -1, OOR);
}
test "sec_rpc H4 walletpassphrase timeout 4294967296 is rejected" {
    try only("walletpassphrase");
    try expectRejected(true, "walletpassphrase", "[\"pw\",4294967296]", -1, OOR);
}
test "sec_rpc H4 lockunspent vout 4294967296 is rejected" {
    try only("lockunspent");
    try expectRejected(true, "lockunspent", "[false,[{\"txid\":\"" ++ TXID ++ "\",\"vout\":4294967296}]]", -1, OOR);
}
test "sec_rpc H4 walletcreatefundedpsbt input vout -1 is rejected" {
    try only("walletcreatefundedpsbt");
    try expectRejected(true, "walletcreatefundedpsbt", "[[{\"txid\":\"" ++ TXID ++ "\",\"vout\":-1}],[{\"" ++ ADDR ++ "\":0.1}]]", -8, "Invalid parameter, vout cannot be negative");
}
test "sec_rpc H4 signrawtransactionwithkey prevtx vout -1 is answered" {
    try only("signrawtransactionwithkey");
    // Key 1, regtest WIF.  The prevtx entry names the tx's own input; with
    // vout -1 it matches no outpoint, so the reply is an ordinary error.
    try expectRejectedOrAnswered(false, "signrawtransactionwithkey", "[\"" ++ TX_HEX ++ "\",[\"cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA\"],[{\"txid\":\"" ++ TXID ++ "\",\"vout\":-1,\"scriptPubKey\":\"51\"}]]");
}
test "sec_rpc H4 generatetoaddress maxtries -1 is rejected" {
    try only("generatetoaddress");
    try expectRejected(false, "generatetoaddress", "[1,\"" ++ ADDR ++ "\",-1]", -1, OOR);
}
test "sec_rpc H4 generatetodescriptor maxtries -1 is rejected" {
    try only("generatetodescriptor");
    try expectRejected(false, "generatetodescriptor", "[1,\"raw(51)\",-1]", -1, OOR);
}
test "sec_rpc H4 fundrawtransaction fee_rate -1 is rejected" {
    try only("fundrawtransaction");
    try expectRejected(true, "fundrawtransaction", "[\"" ++ TX_HEX ++ "\",{\"fee_rate\":-1}]", -3, AOR);
}
test "sec_rpc H4 importdescriptors range 4294967295 is rejected" {
    try only("importdescriptors-range-max");
    try expectImportRejected("{{\"desc\":\"{s}\",\"timestamp\":\"now\",\"range\":4294967295}}", "End of range is too high");
}

/// Like expectRejected, but a success reply is also fine: the defect is the
/// abort, and for signrawtransactionwithkey both answers are legitimate.
fn expectRejectedOrAnswered(with_wallet: bool, method: []const u8, params_json: []const u8) !void {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator, .{}, with_wallet);
    defer rig.deinit();
    const resp = try rig.dispatch(method, params_json);
    defer allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .object);
}

// ---- importdescriptors helpers --------------------------------------------

/// A ranged descriptor with a private key, checksummed by the node itself
/// (the wallet has private keys enabled, so a public-only one is refused
/// before the range is read).
const RANGED_DESC = "wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0/*)";

fn checksummedDesc(rig: *Rig, buf: []u8) ![]const u8 {
    const resp = try rig.dispatch("getdescriptorinfo", "[\"" ++ RANGED_DESC ++ "\"]");
    defer rig.allocator.free(resp);
    var parsed = try std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{});
    defer parsed.deinit();
    const res = parsed.value.object.get("result") orelse return error.NoDescriptorInfo;
    if (res != .object) {
        std.debug.print("\ngetdescriptorinfo: {s}\n", .{resp});
        return error.NoDescriptorInfo;
    }
    const cs = res.object.get("checksum").?.string;
    return std.fmt.bufPrint(buf, RANGED_DESC ++ "#{s}", .{cs});
}

/// importdescriptors answers an array of per-request results; the request
/// must come back success:false with `want_msg`.
fn importOne(rig: *Rig, comptime req_fmt: []const u8) !std.json.Parsed(std.json.Value) {
    var dbuf: [256]u8 = undefined;
    const desc = try checksummedDesc(rig, &dbuf);
    const req = try std.fmt.allocPrint(rig.allocator, "[[" ++ req_fmt ++ "]]", .{desc});
    defer rig.allocator.free(req);
    const resp = try rig.dispatch("importdescriptors", req);
    defer rig.allocator.free(resp);
    return std.json.parseFromSlice(std.json.Value, rig.allocator, resp, .{ .allocate = .alloc_always });
}

fn expectImportRejected(comptime req_fmt: []const u8, want_msg: []const u8) !void {
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator, .{}, true);
    defer rig.deinit();
    var parsed = try importOne(&rig, req_fmt);
    defer parsed.deinit();
    const msg: []const u8 = blk: {
        if (parsed.value.object.get("error")) |e| if (e == .object) break :blk e.object.get("message").?.string;
        const res = parsed.value.object.get("result").?;
        const first = res.array.items[0].object;
        if (first.get("success").?.bool) return error.ImportUnexpectedlySucceeded;
        break :blk first.get("error").?.object.get("message").?.string;
    };
    if (!std.mem.eql(u8, msg, want_msg)) {
        std.debug.print("\nimportdescriptors: expected \"{s}\", got \"{s}\"\n", .{ want_msg, msg });
        return error.WrongRpcError;
    }
}

// ===========================================================================
// H6 — importdescriptors range caps (Core ParseDescriptorRange).
// ===========================================================================

test "sec_rpc H6 importdescriptors range [0,1000000] is too large (Core cap)" {
    try only("h6-width");
    try expectImportRejected("{{\"desc\":\"{s}\",\"timestamp\":\"now\",\"range\":[0,1000000]}}", "Range is too large");
}
test "sec_rpc H6 importdescriptors range end 2^31 is too high (Core cap)" {
    try only("h6-end");
    try expectImportRejected("{{\"desc\":\"{s}\",\"timestamp\":\"now\",\"range\":[2147483000,2147483648]}}", "End of range is too high");
}
test "sec_rpc H6 CONTROL importdescriptors range [0,5] still imports" {
    try only("h6-control");
    const allocator = testing.allocator;
    var rig = try Rig.init(allocator, .{}, true);
    defer rig.deinit();
    var parsed = try importOne(&rig, "{{\"desc\":\"{s}\",\"timestamp\":\"now\",\"range\":[0,5]}}");
    defer parsed.deinit();
    const first = parsed.value.object.get("result").?.array.items[0].object;
    try testing.expect(first.get("success").?.bool);
}

// ===========================================================================
// H4 helper unit tests.
// ===========================================================================

test "sec_rpc H4 helper floatToIntChecked bounds" {
    try only("helper");
    // Guarded so this file still compiles at the parent commit.
    if (!@hasDecl(rpc, "floatToIntChecked")) return error.HelperMissing else {
        const f = rpc.floatToIntChecked;
        try testing.expectEqual(@as(?u32, null), f(u32, 1e300));
        try testing.expectEqual(@as(?u32, null), f(u32, std.math.nan(f64)));
        try testing.expectEqual(@as(?u32, null), f(u32, std.math.inf(f64)));
        try testing.expectEqual(@as(?u32, null), f(u32, -1.0));
        try testing.expectEqual(@as(?u32, null), f(u32, 4294967296.0));
        try testing.expectEqual(@as(?u32, 4294967295), f(u32, 4294967295.0));
        try testing.expectEqual(@as(?u32, 0), f(u32, -0.5)); // truncates like @intFromFloat
        try testing.expectEqual(@as(?i64, null), f(i64, 9223372036854775808.0));
        try testing.expectEqual(@as(?i64, std.math.minInt(i64)), f(i64, -9223372036854775808.0));
        try testing.expectEqual(@as(?i64, 7), f(i64, 7.9));
    }
}

// ===========================================================================
// C6 — PSBT witness allocation bound, and the PayJoin route behind a flag.
// ===========================================================================

/// One input, one 10000-sat output, empty scripts (unsigned, non-witness).
const UNSIGNED_TX = [_]u8{ 0x02, 0, 0, 0, 0x01 } ++ [_]u8{0x11} ** 32 ++ [_]u8{ 0, 0, 0, 0, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01 } ++
    [_]u8{ 0x10, 0x27, 0, 0, 0, 0, 0, 0, 0x00 } ++ [_]u8{ 0, 0, 0, 0 };

/// A PSBT whose one input carries PSBT_IN_SCRIPTWITNESS claiming MAX_SIZE
/// (0x02000000) witness items in a 6-byte value.  80 bytes on the wire.
const HOSTILE_PSBT = [_]u8{ 'p', 's', 'b', 't', 0xff } ++ [_]u8{ 0x01, 0x00, UNSIGNED_TX.len } ++ UNSIGNED_TX ++ [_]u8{0x00} ++
    // input map: key {0x08}, value = compactsize 0x02000000 + one stray byte
    [_]u8{ 0x01, 0x08, 0x06, 0xfe, 0x00, 0x00, 0x00, 0x02, 0x01 } ++ [_]u8{0x00} ++
    // output map
    [_]u8{0x00};

test "sec_rpc C6 PSBT witness count is bounded by the bytes present" {
    try only("c6-psbt");
    var capped = CappedAllocator{ .child = testing.allocator, .cap = CAP };
    const bytes = HOSTILE_PSBT;
    if (psbt.Psbt.deserialize(capped.allocator(), &bytes)) |p| {
        var pp = p;
        pp.deinit();
        return error.HostilePsbtAccepted;
    } else |_| {}
    const peak = capped.peak_request.load(.monotonic);
    if (peak > 1024 * 1024) {
        std.debug.print("\nPSBT parser asked for {d} bytes for a {d}-byte PSBT\n", .{ peak, bytes.len });
        return error.AttackerSizedAllocation;
    }
}

test "sec_rpc C6 CONTROL a PSBT with a real 2-item witness still parses" {
    try only("c6-control");
    const bytes = [_]u8{ 'p', 's', 'b', 't', 0xff } ++ [_]u8{ 0x01, 0x00, UNSIGNED_TX.len } ++ UNSIGNED_TX ++ [_]u8{0x00} ++
        // witness: 2 items, "\xaa\xbb" and "\xcc" -> value = 02 02 aa bb 01 cc (6 bytes)
        [_]u8{ 0x01, 0x08, 0x06, 0x02, 0x02, 0xaa, 0xbb, 0x01, 0xcc } ++ [_]u8{0x00} ++ [_]u8{0x00};
    var p = try psbt.Psbt.deserialize(testing.allocator, &bytes);
    defer p.deinit();
    const w = p.inputs[0].final_script_witness.?;
    try testing.expectEqual(@as(usize, 2), w.len);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, w[0]);
    try testing.expectEqualSlices(u8, &.{0xcc}, w[1]);
}

// ---- a live RpcServer on an ephemeral 127.0.0.1 port -----------------------

const Live = struct {
    rig: Rig,
    thread: std.Thread,
    port: u16,

    fn start(allocator: std.mem.Allocator, config: rpc.RpcConfig) !*Live {
        const self = try testing.allocator.create(Live);
        errdefer testing.allocator.destroy(self);
        var cfg = config;
        cfg.port = 0;
        self.rig = try Rig.init(allocator, cfg, false);
        try self.rig.server.start();
        self.port = self.rig.server.listener.?.listen_address.getPort();
        self.thread = try std.Thread.spawn(.{}, runServer, .{self.rig.server});
        return self;
    }
    fn runServer(srv: *rpc.RpcServer) void {
        srv.run() catch {};
    }
    fn stop(self: *Live) void {
        self.rig.server.stop();
        self.thread.join();
        if (self.rig.server.listener) |*l| l.deinit();
        self.rig.server.listener = null;
        self.rig.deinit();
        testing.allocator.destroy(self);
    }
    fn connect(self: *Live) !std.net.Stream {
        return std.net.tcpConnectToAddress(try std.net.Address.parseIp("127.0.0.1", self.port));
    }
};

fn setRecvTimeout(s: std.net.Stream, secs: i64) void {
    const tv = std.posix.timeval{ .tv_sec = @intCast(secs), .tv_usec = 0 };
    std.posix.setsockopt(s.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
}

/// Send `req`, read the reply until EOF (or `secs` timeout), return status.
fn roundTrip(live: *Live, req: []const u8, secs: i64, reply: []u8) !struct { status: u16, body: []const u8 } {
    const s = try live.connect();
    defer s.close();
    setRecvTimeout(s, secs);
    try s.writeAll(req);
    var n: usize = 0;
    while (n < reply.len) {
        const r = s.read(reply[n..]) catch |e| {
            if (e == error.WouldBlock) return error.RpcDidNotAnswerInTime;
            return e;
        };
        if (r == 0) break;
        n += r;
    }
    const text = reply[0..n];
    if (!std.mem.startsWith(u8, text, "HTTP/1.1 ") or text.len < 12) return error.NoHttpReply;
    const status = try std.fmt.parseInt(u16, text[9..12], 10);
    const body_at = (std.mem.indexOf(u8, text, "\r\n\r\n") orelse text.len - 4) + 4;
    return .{ .status = status, .body = text[body_at..] };
}

/// The audit's request: an unauthenticated text/plain POST of the hostile
/// PSBT in base64 (108 characters).
fn hostilePayjoinPost(buf: []u8) []const u8 {
    var b64: [std.base64.standard.Encoder.calcSize(HOSTILE_PSBT.len)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&b64, &HOSTILE_PSBT);
    return std.fmt.bufPrint(buf, "POST /payjoin?v=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}", .{ b64.len, b64 }) catch unreachable;
}

test "sec_rpc C6 POST /payjoin without credentials is refused by default and parses nothing" {
    try only("c6-route-default");
    var capped = CappedAllocator{ .child = testing.allocator, .cap = CAP };
    capped.armed.store(false, .release);
    // A cookie is configured, as on every real node: the JSON-RPC path needs it.
    const live = try Live.start(capped.allocator(), .{ .cookie_token = "X19jb29raWVfXzp0ZXN0" });
    defer live.stop();
    capped.armed.store(true, .release);
    var req_buf: [512]u8 = undefined;
    var reply: [4096]u8 = undefined;
    const r = try roundTrip(live, hostilePayjoinPost(&req_buf), 10, &reply);
    const peak = capped.peak_request.load(.monotonic);
    if (r.status != 404 or peak > 1024 * 1024) {
        std.debug.print("\nunauthenticated POST /payjoin: HTTP {d}, body \"{s}\", largest allocation {d} bytes\n", .{ r.status, r.body, peak });
        return error.UnauthenticatedPayjoinServed;
    }
}

test "sec_rpc C6 opted-in PayJoin receiver rejects the hostile PSBT without the 512 MiB allocation" {
    try only("c6-route-optin");
    var capped = CappedAllocator{ .child = testing.allocator, .cap = CAP };
    capped.armed.store(false, .release);
    var cfg: rpc.RpcConfig = .{ .cookie_token = "X19jb29raWVfXzp0ZXN0" };
    if (@hasField(rpc.RpcConfig, "payjoin_receiver")) cfg.payjoin_receiver = true;
    const live = try Live.start(capped.allocator(), cfg);
    defer live.stop();
    capped.armed.store(true, .release);
    var req_buf: [512]u8 = undefined;
    var reply: [4096]u8 = undefined;
    const r = try roundTrip(live, hostilePayjoinPost(&req_buf), 10, &reply);
    const peak = capped.peak_request.load(.monotonic);
    if (std.mem.indexOf(u8, r.body, "original-psbt-rejected") == null or peak > 1024 * 1024) {
        std.debug.print("\nopted-in POST /payjoin: HTTP {d}, body \"{s}\", largest allocation {d} bytes\n", .{ r.status, r.body, peak });
        return error.AttackerSizedAllocation;
    }
}

// ===========================================================================
// H5 — idle sockets must not freeze the RPC server.
// ===========================================================================

const GBC = "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 49\r\n\r\n{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockcount\"}";

test "sec_rpc H5 four idle connections do not delay getblockcount" {
    try only("h5-idle");
    const live = try Live.start(testing.allocator, .{});
    defer live.stop();
    var idle: [4]std.net.Stream = undefined;
    for (&idle) |*s| s.* = try live.connect();
    defer for (idle) |s| s.close();
    std.time.sleep(200 * std.time.ns_per_ms); // let the server accept them
    var reply: [4096]u8 = undefined;
    var timer = try std.time.Timer.start();
    const r = try roundTrip(live, GBC, 5, &reply);
    const ms = timer.read() / std.time.ns_per_ms;
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expect(std.mem.indexOf(u8, r.body, "\"result\":0") != null);
    try testing.expect(ms < 5000);
}

test "sec_rpc H5 a client trickling its headers does not delay getblockcount" {
    try only("h5-trickle");
    const live = try Live.start(testing.allocator, .{});
    defer live.stop();
    const slow = try live.connect();
    defer slow.close();
    try slow.writeAll("P"); // first byte of a request line, then silence
    std.time.sleep(200 * std.time.ns_per_ms);
    var reply: [4096]u8 = undefined;
    const r = try roundTrip(live, GBC, 5, &reply);
    try testing.expectEqual(@as(u16, 200), r.status);
}

test "sec_rpc H5 CONTROL concurrent requests are each answered" {
    try only("h5-control");
    const live = try Live.start(testing.allocator, .{});
    defer live.stop();
    var reply: [4096]u8 = undefined;
    for (0..8) |_| {
        const r = try roundTrip(live, GBC, 5, &reply);
        try testing.expectEqual(@as(u16, 200), r.status);
    }
}
