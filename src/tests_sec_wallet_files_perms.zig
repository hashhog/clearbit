//! Security audit 2026-10-29 (audits/security/clearbit-2026-10-29.md in the
//! meta-repo), findings H8, H9 and H11.
//!
//!   H8  Path-taking RPCs.  Core (bitcoin-core/src/rpc/blockchain.cpp:3133,
//!       :3408) resolves a RELATIVE dumptxoutset / loadtxoutset path against
//!       the network datadir; clearbit resolved it against the process CWD.
//!       Core's savemempool takes no path at all and only ever writes
//!       <datadir>/mempool.dat; clearbit's dumpmempool / savemempool /
//!       loadmempool took any caller path, so one RPC overwrote or opened any
//!       file the node could reach.  These are now confined to the datadir.
//!       backupwallet, restorewallet, importmempool and wallet names are left
//!       as they are: Core accepts any path there too (see RESULT.md).
//!   H9  No private umask, so wallet.dat (master_key in cleartext when the
//!       wallet is not encrypted) landed group/world readable.  Core calls
//!       umask(0077) at startup (common/system.cpp:92-93).
//!   H11 Labels were written into wallet.dat's JSON unescaped, so a label
//!       could inject top-level keys (network, master_key, keys) that the
//!       last-key-wins parser then honoured on load.
//!
//! Every test fails at the parent commit by assertion (no crashes).
//!
//! Run: zig build test-unit -Dtest-filter=sec_wallet

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const wallet_mod = @import("wallet.zig");
const ops = @import("ops.zig");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const Rig = struct {
    allocator: std.mem.Allocator,
    chain_state: *storage.ChainState,
    mempool: *mempool_mod.Mempool,
    peer_manager: *peer_mod.PeerManager,
    server: *rpc.RpcServer,
    wallet: ?*wallet_mod.Wallet = null,

    fn init(allocator: std.mem.Allocator, datadir: []const u8) !Rig {
        const cs = try allocator.create(storage.ChainState);
        cs.* = storage.ChainState.init(null, 64, allocator);
        const mp = try allocator.create(mempool_mod.Mempool);
        mp.* = mempool_mod.Mempool.init(null, null, allocator);
        const pm = try allocator.create(peer_mod.PeerManager);
        pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
        const srv = try allocator.create(rpc.RpcServer);
        srv.* = rpc.RpcServer.init(allocator, cs, mp, pm, &consensus.REGTEST, .{ .datadir = datadir });
        return .{ .allocator = allocator, .chain_state = cs, .mempool = mp, .peer_manager = pm, .server = srv };
    }
    fn withWallet(self: *Rig) !void {
        const w = try self.allocator.create(wallet_mod.Wallet);
        w.* = try wallet_mod.Wallet.init(self.allocator, .regtest);
        self.server.wallet = w;
        self.wallet = w;
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
    /// Dispatch `method` with `params` (a JSON array built by the caller).
    fn call(self: *Rig, method: []const u8, params_json: []const u8) !std.json.Parsed(std.json.Value) {
        const req = try std.fmt.allocPrint(self.allocator, "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        defer self.allocator.free(req);
        const resp = try self.server.dispatch(req);
        defer self.allocator.free(resp);
        return std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{ .allocate = .alloc_always });
    }
};

/// JSON-quote `s` for splicing into a params array.
fn quote(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try std.json.encodeJsonString(s, .{}, out.writer());
    return out.toOwnedSlice();
}

fn errorMessage(v: std.json.Value) ?[]const u8 {
    const e = v.object.get("error") orelse return null;
    if (e != .object) return null;
    const m = e.object.get("message") orelse return null;
    return if (m == .string) m.string else null;
}

fn errorCode(v: std.json.Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    if (e != .object) return null;
    const c = e.object.get("code") orelse return null;
    return if (c == .integer) c.integer else null;
}

fn readAllAbsolute(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const f = try std.fs.openFileAbsolute(path, .{});
    defer f.close();
    return f.readToEndAlloc(allocator, 1 << 20);
}

fn writeAllAbsolute(path: []const u8, bytes: []const u8) !void {
    const f = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer f.close();
    try f.writeAll(bytes);
}

fn existsAbsolute(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

fn modeOf(path: []const u8) !u32 {
    const st = try std.posix.fstatat(std.posix.AT.FDCWD, path, 0);
    return @intCast(st.mode & 0o777);
}

/// <tmp>/datadir (the node's datadir) and <tmp>/outside (a sibling it must
/// not reach).  Paths are absolute.
const Dirs = struct {
    tmp: std.testing.TmpDir,
    root_buf: [std.fs.max_path_bytes]u8 = undefined,
    root: []const u8 = "",
    datadir: []u8 = &.{},
    outside: []u8 = &.{},

    fn init(self: *Dirs, allocator: std.mem.Allocator) !void {
        self.tmp = std.testing.tmpDir(.{});
        self.root = try self.tmp.dir.realpath(".", &self.root_buf);
        try self.tmp.dir.makeDir("datadir");
        try self.tmp.dir.makeDir("outside");
        self.datadir = try std.fs.path.join(allocator, &.{ self.root, "datadir" });
        self.outside = try std.fs.path.join(allocator, &.{ self.root, "outside" });
    }
    fn deinit(self: *Dirs, allocator: std.mem.Allocator) void {
        allocator.free(self.datadir);
        allocator.free(self.outside);
        self.tmp.cleanup();
    }
};

// ===========================================================================
// H8 — path-taking RPCs
// ===========================================================================

/// dumpmempool / savemempool given an absolute path outside the datadir must
/// be refused and must leave the victim file untouched (the audit's proof).
fn expectDumpRefusesOutside(method: []const u8, want_code: ?i64) !void {
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    const victim = try std.fs.path.join(allocator, &.{ d.outside, "victim.conf" });
    defer allocator.free(victim);
    try writeAllAbsolute(victim, "rpcpassword=keep-me\n");

    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    const q = try quote(allocator, victim);
    defer allocator.free(q);
    const params = try std.fmt.allocPrint(allocator, "[{s}]", .{q});
    defer allocator.free(params);
    var resp = try rig.call(method, params);
    defer resp.deinit();

    const after = try readAllAbsolute(allocator, victim);
    defer allocator.free(after);
    if (!std.mem.eql(u8, after, "rpcpassword=keep-me\n")) {
        std.debug.print("\n{s} overwrote a file outside the datadir: {s}\n", .{ method, victim });
        return error.FileOutsideDatadirOverwritten;
    }
    const code = errorCode(resp.value) orelse return error.ExpectedRpcError;
    if (want_code) |w| if (code != w) return error.WrongRpcError;
}

test "sec_wallet H8 dumpmempool refuses an absolute path outside the datadir" {
    try expectDumpRefusesOutside("dumpmempool", rpc.RPC_INVALID_PARAMETER);
}

// Control.  Core's savemempool takes no argument at all; clearbit's arity
// table already refused one at the parent, and must keep doing so.
test "sec_wallet H8 control: savemempool with a path argument is refused and writes nothing" {
    try expectDumpRefusesOutside("savemempool", null);
}

test "sec_wallet H8 dumpmempool refuses a ../ path that escapes the datadir" {
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    var resp = try rig.call("dumpmempool", "[\"../outside/escaped.dat\"]");
    defer resp.deinit();

    const escaped = try std.fs.path.join(allocator, &.{ d.outside, "escaped.dat" });
    defer allocator.free(escaped);
    if (existsAbsolute(escaped)) return error.FileOutsideDatadirCreated;
    if (errorCode(resp.value) != rpc.RPC_INVALID_PARAMETER) return error.ExpectedInvalidParameter;
}

test "sec_wallet H8 loadmempool refuses to open a file outside the datadir" {
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    const foreign = try std.fs.path.join(allocator, &.{ d.outside, "passwd" });
    defer allocator.free(foreign);
    try writeAllAbsolute(foreign, "root:x:0:0:root:/root:/bin/bash\n");

    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    const q = try quote(allocator, foreign);
    defer allocator.free(q);
    const params = try std.fmt.allocPrint(allocator, "[{s}]", .{q});
    defer allocator.free(params);
    var resp = try rig.call("loadmempool", params);
    defer resp.deinit();
    // At the parent the file was opened and parsed (rejected only on its
    // version byte: an internal error); the refusal must come first.
    if (errorCode(resp.value) != rpc.RPC_INVALID_PARAMETER) {
        std.debug.print("\nloadmempool {s}: got code {?d} \"{?s}\"\n", .{ foreign, errorCode(resp.value), errorMessage(resp.value) });
        return error.ForeignFileOpened;
    }
}

test "sec_wallet H8 dumpmempool resolves a relative path under the datadir" {
    // At the parent a relative path landed in the process CWD.
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    const name = "sec-wallet-h8-relative-mempool.dat";
    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    var resp = try rig.call("dumpmempool", "[\"" ++ name ++ "\"]");
    defer resp.deinit();
    std.fs.cwd().deleteFile(name) catch {};
    if (resp.value.object.get("error")) |e| if (e != .null) return error.InsideDatadirRefused;
    const inside = try std.fs.path.join(allocator, &.{ d.datadir, name });
    defer allocator.free(inside);
    if (!existsAbsolute(inside)) return error.RelativePathNotUnderDatadir;
}

test "sec_wallet H8 control: savemempool with no path still writes <datadir>/mempool.dat" {
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    var resp = try rig.call("savemempool", "[]");
    defer resp.deinit();
    if (resp.value.object.get("error")) |e| if (e != .null) return error.DefaultPathRefused;
    const default = try std.fs.path.join(allocator, &.{ d.datadir, "mempool.dat" });
    defer allocator.free(default);
    try testing.expect(existsAbsolute(default));

    // And an absolute path that is inside the datadir is still allowed.
    const abs_inside = try std.fs.path.join(allocator, &.{ d.datadir, "abs-inside.dat" });
    defer allocator.free(abs_inside);
    const q = try quote(allocator, abs_inside);
    defer allocator.free(q);
    const params = try std.fmt.allocPrint(allocator, "[{s}]", .{q});
    defer allocator.free(params);
    var resp2 = try rig.call("dumpmempool", params);
    defer resp2.deinit();
    if (resp2.value.object.get("error")) |e| if (e != .null) return error.AbsoluteInsideRefused;
    try testing.expect(existsAbsolute(abs_inside));
}

test "sec_wallet H8 resolvePathInDatadir refuses a symlinked dir that leads out" {
    if (!@hasDecl(rpc, "resolvePathInDatadir")) return error.ResolverMissing;
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);
    const link = try std.fs.path.join(allocator, &.{ d.datadir, "link" });
    defer allocator.free(link);
    try std.posix.symlink(d.outside, link);
    try testing.expectError(error.PathOutsideDatadir, rpc.resolvePathInDatadir(allocator, d.datadir, "link/x.dat"));
    try testing.expectError(error.PathOutsideDatadir, rpc.resolvePathInDatadir(allocator, d.datadir, "."));
    try testing.expectError(error.PathOutsideDatadir, rpc.resolvePathInDatadir(allocator, d.datadir, "a/../../x"));
    // A sibling whose name starts with the datadir's is not inside it.
    const sib = try std.fmt.allocPrint(allocator, "{s}2/x", .{d.datadir});
    defer allocator.free(sib);
    try testing.expectError(error.PathOutsideDatadir, rpc.resolvePathInDatadir(allocator, d.datadir, sib));
    const ok = try rpc.resolvePathInDatadir(allocator, d.datadir, "a/../ok.dat");
    defer allocator.free(ok);
    try testing.expect(std.mem.endsWith(u8, ok, "/datadir/ok.dat"));
}

test "sec_wallet H8 dumptxoutset resolves a relative path against the datadir, as Core" {
    // Core: AbsPathJoin(GetDataDirNet(), path) then "already exists" (-8).
    // An existing <datadir>/existing.dat must therefore be refused.  At the
    // parent the check looked in the CWD, missed the file, and went on to
    // write the snapshot into the CWD.
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    const name = "sec-wallet-h8-dumptxoutset-relative.dat";
    const in_datadir = try std.fs.path.join(allocator, &.{ d.datadir, name });
    defer allocator.free(in_datadir);
    try writeAllAbsolute(in_datadir, "occupied");

    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    var resp = try rig.call("dumptxoutset", "[\"" ++ name ++ "\",\"latest\"]");
    defer resp.deinit();
    // Never leave a parent-commit dump behind in the CWD.
    std.fs.cwd().deleteFile(name) catch {};
    std.fs.cwd().deleteFile(name ++ ".incomplete") catch {};

    const msg = errorMessage(resp.value) orelse "";
    if (std.mem.indexOf(u8, msg, "already exists") == null) {
        std.debug.print("\ndumptxoutset relative: got \"{s}\"\n", .{msg});
        return error.RelativePathNotUnderDatadir;
    }
}

test "sec_wallet H8 loadtxoutset resolves a relative path against the datadir, as Core" {
    // Core: AbsPathForConfigVal(datadir, path) then "Couldn't open file".
    // A file present only under the datadir must be opened (and then fail
    // to parse), not reported as unopenable.
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    const name = "sec-wallet-h8-loadtxoutset-relative.dat";
    const in_datadir = try std.fs.path.join(allocator, &.{ d.datadir, name });
    defer allocator.free(in_datadir);
    try writeAllAbsolute(in_datadir, "not a snapshot");

    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    var resp = try rig.call("loadtxoutset", "[\"" ++ name ++ "\"]");
    defer resp.deinit();
    const msg = errorMessage(resp.value) orelse "";
    if (std.mem.indexOf(u8, msg, "Couldn't open file") != null) {
        std.debug.print("\nloadtxoutset relative: got \"{s}\"\n", .{msg});
        return error.RelativePathNotUnderDatadir;
    }
}

// ===========================================================================
// H9 — umask and wallet file modes
// ===========================================================================

test "sec_wallet H9 ops.applyPrivateUmask sets Core's 0077" {
    if (!@hasDecl(ops, "applyPrivateUmask")) return error.PrivateUmaskHelperMissing;
    const before = std.os.linux.syscall1(.umask, 0o002);
    defer _ = std.os.linux.syscall1(.umask, before);
    ops.applyPrivateUmask();
    const now = std.os.linux.syscall1(.umask, 0o002);
    try testing.expectEqual(@as(usize, 0o077), now);
}

// Under a permissive umask (0002, the one the audit observed), every wallet
// file and directory clearbit creates must still be private.
test "sec_wallet H9 createwallet, backupwallet and restorewallet write 0600 files in 0700 dirs" {
    const allocator = testing.allocator;
    const old = std.os.linux.syscall1(.umask, 0o002);
    defer _ = std.os.linux.syscall1(.umask, old);

    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);
    const wallets_dir = try std.fs.path.join(allocator, &.{ d.datadir, "wallets" });
    defer allocator.free(wallets_dir);

    var wm = try wallet_mod.WalletManager.init(allocator, wallets_dir, .regtest);
    defer wm.deinit();
    _ = try wm.createWallet("walletA", .{});

    const wdir = try std.fs.path.join(allocator, &.{ wallets_dir, "walletA" });
    defer allocator.free(wdir);
    const wdat = try std.fs.path.join(allocator, &.{ wdir, "wallet.dat" });
    defer allocator.free(wdat);
    const backup = try std.fs.path.join(allocator, &.{ d.outside, "walletA.bak" });
    defer allocator.free(backup);
    try wm.backupWallet("walletA", backup);

    // A backup written by someone else with a loose mode must not be
    // restored as a loose wallet.dat.
    const loose = try std.fs.path.join(allocator, &.{ d.outside, "loose.bak" });
    defer allocator.free(loose);
    try std.fs.copyFileAbsolute(backup, loose, .{ .override_mode = 0o644 });
    _ = try wm.restoreWallet("walletB", loose);
    const rdat = try std.fs.path.join(allocator, &.{ wallets_dir, "walletB", "wallet.dat" });
    defer allocator.free(rdat);

    const Check = struct { path: []const u8, want: u32 };
    const checks = [_]Check{
        .{ .path = wallets_dir, .want = 0o700 },
        .{ .path = wdir, .want = 0o700 },
        .{ .path = wdat, .want = 0o600 },
        .{ .path = backup, .want = 0o600 },
        .{ .path = rdat, .want = 0o600 },
    };
    var bad: usize = 0;
    for (checks) |c| {
        const m = try modeOf(c.path);
        if (m != c.want) {
            std.debug.print("\n{s}: mode {o}, want {o}\n", .{ c.path, m, c.want });
            bad += 1;
        }
    }
    if (bad != 0) return error.WalletFilesNotPrivate;
}

test "sec_wallet H9 a re-save tightens a wallet.dat left 0664 by an older build" {
    const allocator = testing.allocator;
    const old = std.os.linux.syscall1(.umask, 0o002);
    defer _ = std.os.linux.syscall1(.umask, old);

    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    var wm = try wallet_mod.WalletManager.init(allocator, d.datadir, .regtest);
    defer wm.deinit();
    _ = try wm.createWallet("w", .{});
    const wdat = try std.fs.path.join(allocator, &.{ d.datadir, "w", "wallet.dat" });
    defer allocator.free(wdat);
    const tmp = try std.fs.path.join(allocator, &.{ d.datadir, "w", "wallet.dat.tmp" });
    defer allocator.free(tmp);
    // A stale 0664 wallet.dat.tmp from an interrupted older write: createFile
    // with .truncate keeps its mode, so the next save would inherit it.
    try writeAllAbsolute(tmp, "stale");
    try std.posix.fchmodat(std.posix.AT.FDCWD, tmp, 0o664, 0);
    try wm.saveWallet("w");
    try testing.expectEqual(@as(u32, 0o600), try modeOf(wdat));
}

// ===========================================================================
// H11 — label injection into wallet.dat
// ===========================================================================

const INJECT = "x\"},\"network\":\"mainnet\",\"master_key\":\"00\",\"labels\":{\"a\":\"b";

test "sec_wallet H11 a label with quotes round-trips and cannot inject wallet keys" {
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    var wm = try wallet_mod.WalletManager.init(allocator, d.datadir, .regtest);
    defer wm.deinit();
    const w = try wm.createWallet("w", .{});
    try w.setLabel("bcrt1qaddr", INJECT);
    try w.setLabel("bcrt1q\"key\\", "back\\slash\nnewline\x01ctl");
    try wm.saveWallet("w");

    const wdat = try std.fs.path.join(allocator, &.{ d.datadir, "w", "wallet.dat" });
    defer allocator.free(wdat);
    const bytes = try readAllAbsolute(allocator, wdat);
    defer allocator.free(bytes);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return error.WalletJsonInvalid;
    defer parsed.deinit();
    const obj = parsed.value.object;

    // The injected text must be data, not structure.
    const net = obj.get("network") orelse return error.NetworkMissing;
    if (net != .string or !std.mem.eql(u8, net.string, "regtest")) return error.NetworkOverridden;
    const labels = obj.get("labels") orelse return error.LabelsMissing;
    if (labels != .object) return error.LabelsNotObject;
    if (labels.object.get("a") != null) return error.LabelInjected;
    const got = labels.object.get("bcrt1qaddr") orelse return error.LabelLost;
    if (got != .string or !std.mem.eql(u8, got.string, INJECT)) return error.LabelMangled;
    const got2 = labels.object.get("bcrt1q\"key\\") orelse return error.LabelKeyLost;
    if (got2 != .string or !std.mem.eql(u8, got2.string, "back\\slash\nnewline\x01ctl")) return error.LabelMangled;
}

test "sec_wallet H11 a wallet.dat with a duplicate key is refused on load" {
    // Zig's dynamic parser keeps the LAST duplicate (std/json/dynamic.zig
    // handleCompleteValue: object.put).  A file that says two different
    // things about master_key or network is not one wallet; refuse it.
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);

    {
        var wm = try wallet_mod.WalletManager.init(allocator, d.datadir, .regtest);
        defer wm.deinit();
        _ = try wm.createWallet("w", .{});
    }
    const wdat = try std.fs.path.join(allocator, &.{ d.datadir, "w", "wallet.dat" });
    defer allocator.free(wdat);
    const bytes = try readAllAbsolute(allocator, wdat);
    defer allocator.free(bytes);
    // Append a second "network" key just before the closing brace.
    const end = std.mem.lastIndexOfScalar(u8, bytes, '}') orelse return error.BadFixture;
    const doubled = try std.fmt.allocPrint(allocator, "{s},\"network\":\"mainnet\"}}", .{bytes[0..end]});
    defer allocator.free(doubled);
    try writeAllAbsolute(wdat, doubled);

    var wm = try wallet_mod.WalletManager.init(allocator, d.datadir, .regtest);
    defer wm.deinit();
    if (wm.loadWallet("w")) |w| {
        std.debug.print("\nduplicate-key wallet loaded with network={s}\n", .{@tagName(w.network)});
        return error.DuplicateKeyWalletLoaded;
    } else |_| {}
}

test "sec_wallet H11 a type-confused wallet.dat fails to load instead of aborting" {
    // The audit's payload made "network" an integer and "labels" a string:
    // deserializeWallet read .string / .object off the wrong union tag.  That
    // is safety-checked illegal behaviour; at the parent this test aborts the
    // test binary (run it alone with -Dtest-filter to see it by name).
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);
    {
        const p = try std.fs.path.join(allocator, &.{ d.datadir, "w" });
        defer allocator.free(p);
        try std.fs.makeDirAbsolute(p);
    }
    const wdat = try std.fs.path.join(allocator, &.{ d.datadir, "w", "wallet.dat" });
    defer allocator.free(wdat);

    var wm = try wallet_mod.WalletManager.init(allocator, d.datadir, .regtest);
    defer wm.deinit();
    for ([_][]const u8{
        "{\"network\":7,\"keys\":[],\"labels\":{}}",
        "{\"network\":\"regtest\",\"keys\":[],\"labels\":\"x\"}",
        "{\"network\":\"regtest\",\"keys\":[],\"labels\":{\"a\":7}}",
        "[]",
    }) |body| {
        try writeAllAbsolute(wdat, body);
        if (wm.loadWallet("w")) |_| {
            std.debug.print("\ntype-confused wallet.dat loaded: {s}\n", .{body});
            return error.TypeConfusedWalletLoaded;
        } else |_| {}
    }
}

test "sec_wallet H11 getaddressinfo returns a quoted label as valid JSON" {
    // The same label also reached getaddressinfo's reply unescaped, so the
    // reply was not JSON at all (seen end to end on regtest).
    const allocator = testing.allocator;
    var d: Dirs = .{ .tmp = undefined };
    try d.init(allocator);
    defer d.deinit(allocator);
    var rig = try Rig.init(allocator, d.datadir);
    defer rig.deinit();
    try rig.withWallet();

    // Through the wallet API: the getnewaddress RPC handler leaks its
    // address string (not this item), which the test allocator would flag.
    const na = try rig.wallet.?.getnewaddress(.p2wpkh, false);
    defer allocator.free(na.address);
    const addr = na.address;
    try rig.wallet.?.setLabel(addr, INJECT);

    const q = try quote(allocator, addr);
    defer allocator.free(q);
    const params = try std.fmt.allocPrint(allocator, "[{s}]", .{q});
    defer allocator.free(params);
    const req = try std.fmt.allocPrint(allocator, "{{\"id\":1,\"method\":\"getaddressinfo\",\"params\":{s}}}", .{params});
    defer allocator.free(req);
    const resp = try rig.server.dispatch(req);
    defer allocator.free(resp);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp, .{}) catch {
        std.debug.print("\ngetaddressinfo reply is not JSON: {s}\n", .{resp});
        return error.ReplyNotJson;
    };
    defer parsed.deinit();
    const result = parsed.value.object.get("result") orelse return error.NoResult;
    if (result != .object) return error.NoResult;
    const label = result.object.get("label") orelse return error.LabelMissing;
    if (label != .string or !std.mem.eql(u8, label.string, INJECT)) return error.LabelMangled;
    const labels = result.object.get("labels") orelse return error.LabelMissing;
    if (labels != .array or labels.array.items.len != 1 or labels.array.items[0] != .string or
        !std.mem.eql(u8, labels.array.items[0].string, INJECT)) return error.LabelMangled;
}
