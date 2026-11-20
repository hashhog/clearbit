//! walletpassphrase <pass> <timeout> must relock the wallet when the timeout
//! runs out.
//!
//! Core (wallet/rpc/encrypt.cpp walletpassphrase): sets
//! `nRelockTime = GetTime() + nSleepTime` and schedules RelockWallet, which
//! calls `pwallet->Lock()` (wipes vMasterKey) and zeroes nRelockTime. After
//! that IsLocked() is true, and every signing RPC hits
//! EnsureWalletIsUnlocked -> RPC_WALLET_UNLOCK_NEEDED (-13) "Error: Please
//! enter the wallet passphrase with walletpassphrase first."
//!
//! clearbit stored `unlock_until` but every key access (getPlaintextSecretKey,
//! getPlaintextMasterKey, importKey) tested only `encryption_key != null`, so
//! once unlocked the wallet kept decrypting keys forever. At the parent
//! commit the expiry tests below sign (or export the key) after the window.
//!
//! Run: zig build test-walletpassphrase-relock

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const wallet_mod = @import("wallet.zig");
const types = @import("types.zig");
const serialize = @import("serialize.zig");

const PASS = "relock-test-passphrase";

const Rig = struct {
    arena: std.heap.ArenaAllocator,
    server: *rpc.RpcServer,
    wallet: *wallet_mod.Wallet,
    unsigned_hex: []const u8,

    /// Encrypted regtest wallet with one owned P2WPKH coin, wired into an RPC
    /// server, plus an unsigned tx spending that coin. Arena-backed: the
    /// signing handlers hand ownership of witness buffers to the tx and the
    /// tests only care about the RPC verdict.
    fn init() !*Rig {
        const rig = try std.heap.page_allocator.create(Rig);
        rig.arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        const a = rig.arena.allocator();

        const cs = try a.create(storage.ChainState);
        cs.* = storage.ChainState.init(null, 64, a);
        const mp = try a.create(mempool_mod.Mempool);
        mp.* = mempool_mod.Mempool.init(null, null, a);
        const pm = try a.create(peer_mod.PeerManager);
        pm.* = peer_mod.PeerManager.init(a, &consensus.REGTEST);
        const srv = try a.create(rpc.RpcServer);
        srv.* = rpc.RpcServer.init(a, cs, mp, pm, &consensus.REGTEST, .{});

        const w = try a.create(wallet_mod.Wallet);
        w.* = try wallet_mod.Wallet.init(a, .regtest);
        const ki = try w.generateKey();
        const spk = try w.getScriptPubKey(ki, .p2wpkh);
        cs.best_height = 200;
        w.setTipHeight(200);
        const outpoint = types.OutPoint{ .hash = [_]u8{0x42} ** 32, .index = 0 };
        try w.addUtxo(.{
            .outpoint = outpoint,
            .output = .{ .value = 100_000_000, .script_pubkey = spk },
            .key_index = ki,
            .address_type = .p2wpkh,
            .confirmations = 100,
            .height = 101,
        });
        try w.encryptWallet(PASS);
        srv.wallet = w;

        const inputs = try a.alloc(types.TxIn, 1);
        inputs[0] = .{ .previous_output = outpoint, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &.{} };
        const outputs = try a.alloc(types.TxOut, 1);
        outputs[0] = .{ .value = 99_990_000, .script_pubkey = spk };
        const tx = types.Transaction{ .version = 2, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
        var wr = serialize.Writer.init(a);
        try serialize.writeTransaction(&wr, &tx);
        rig.unsigned_hex = try std.fmt.allocPrint(a, "{s}", .{std.fmt.fmtSliceHexLower(wr.list.items)});

        rig.server = srv;
        rig.wallet = w;
        return rig;
    }

    fn deinit(self: *Rig) void {
        mempool_mod.setMockTime(0);
        self.arena.deinit();
        std.heap.page_allocator.destroy(self);
    }

    fn call(self: *Rig, method: []const u8, params_json: []const u8) !std.json.Value {
        const a = self.arena.allocator();
        const req = try std.fmt.allocPrint(a, "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        const resp = try self.server.dispatch(req);
        const parsed = try std.json.parseFromSlice(std.json.Value, a, resp, .{ .allocate = .alloc_always });
        return parsed.value;
    }

    fn signRaw(self: *Rig) !std.json.Value {
        const a = self.arena.allocator();
        const params = try std.fmt.allocPrint(a, "[\"{s}\"]", .{self.unsigned_hex});
        return self.call("signrawtransactionwithwallet", params);
    }

    /// walletpassphrase PASS <secs>, asserting success.
    fn unlock(self: *Rig, secs: u32) !void {
        const a = self.arena.allocator();
        const params = try std.fmt.allocPrint(a, "[\"{s}\",{d}]", .{ PASS, secs });
        const r = try self.call("walletpassphrase", params);
        const err_v = r.object.get("error") orelse std.json.Value{ .null = {} };
        try testing.expect(err_v == .null);
    }
};

fn expectUnlockNeeded(reply: std.json.Value) !void {
    const err_v = reply.object.get("error") orelse return error.ExpectedRpcError;
    if (err_v != .object) return error.ExpectedRpcError;
    try testing.expectEqual(@as(i64, -13), err_v.object.get("code").?.integer);
    try testing.expectEqualStrings(
        "Error: Please enter the wallet passphrase with walletpassphrase first.",
        err_v.object.get("message").?.string,
    );
}

fn signedComplete(reply: std.json.Value) !bool {
    const err_v = reply.object.get("error") orelse std.json.Value{ .null = {} };
    if (err_v != .null) return error.UnexpectedRpcError;
    return reply.object.get("result").?.object.get("complete").?.bool;
}

test "tests_walletpassphrase_relock: CONTROL signrawtransactionwithwallet signs inside the unlock window" {
    const rig = try Rig.init();
    defer rig.deinit();
    try rig.unlock(60);
    try testing.expect(try signedComplete(try rig.signRaw()));
}

test "tests_walletpassphrase_relock: signrawtransactionwithwallet on a never-unlocked encrypted wallet is -13" {
    const rig = try Rig.init();
    defer rig.deinit();
    try expectUnlockNeeded(try rig.signRaw());
}

test "tests_walletpassphrase_relock: signrawtransactionwithwallet after the timeout is -13" {
    const rig = try Rig.init();
    defer rig.deinit();
    try rig.unlock(1);
    mempool_mod.setMockTime(std.time.timestamp() + 2);
    try expectUnlockNeeded(try rig.signRaw());
}

test "tests_walletpassphrase_relock: sendtoaddress after the timeout is -13" {
    const rig = try Rig.init();
    defer rig.deinit();
    try rig.unlock(1);
    mempool_mod.setMockTime(std.time.timestamp() + 2);
    const addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const r = try rig.call("sendtoaddress", "[\"" ++ addr ++ "\",0.1]");
    try expectUnlockNeeded(r);
}

test "tests_walletpassphrase_relock: expiry wipes the key and reports unlocked_until 0" {
    const rig = try Rig.init();
    defer rig.deinit();
    try rig.unlock(1);
    mempool_mod.setMockTime(std.time.timestamp() + 2);
    // Core's RelockWallet zeroes nRelockTime, so getwalletinfo shows 0.
    const r = try rig.call("getwalletinfo", "[]");
    const until = r.object.get("result").?.object.get("unlocked_until").?.integer;
    try testing.expectEqual(@as(i64, 0), until);
    // ...and the decryption key no longer sits in memory.
    try testing.expect(rig.wallet.encryption_key == null);
}

test "tests_walletpassphrase_relock: key access layer refuses after expiry even without an RPC relock" {
    const rig = try Rig.init();
    defer rig.deinit();
    try rig.unlock(1);
    try testing.expect(rig.wallet.isUnlocked());
    _ = try rig.wallet.exportSecretKey(0);
    mempool_mod.setMockTime(std.time.timestamp() + 2);
    try testing.expectError(error.WalletLocked, rig.wallet.exportSecretKey(0));
    try testing.expect(!rig.wallet.isUnlocked());
}

test "tests_walletpassphrase_relock: re-unlocking after expiry signs again" {
    const rig = try Rig.init();
    defer rig.deinit();
    try rig.unlock(1);
    const t0 = std.time.timestamp();
    mempool_mod.setMockTime(t0 + 2);
    try expectUnlockNeeded(try rig.signRaw());
    try rig.unlock(60);
    try testing.expect(try signedComplete(try rig.signRaw()));
}
