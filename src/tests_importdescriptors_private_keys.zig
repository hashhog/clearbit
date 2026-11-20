//! importdescriptors with private keys: lock gate + no plaintext key at rest.
//!
//! Core (wallet/rpc/backup.cpp importdescriptors) calls
//! EnsureWalletIsUnlocked before processing any request, so a locked
//! encrypted wallet refuses the call with RPC_WALLET_UNLOCK_NEEDED (-13).
//! DescriptorScriptPubKeyMan keeps the descriptor in its public form and the
//! private keys in the key store (encrypted when the wallet is), and
//! listdescriptors shows the public form unless private=true.
//!
//! clearbit, before this fix, took the import on a locked wallet, stored the
//! raw xprv/WIF descriptor string, wrote it into wallet.dat in plaintext even
//! when the wallet was encrypted, and returned it from listdescriptors.
//!
//! Expected public forms are Bitcoin Core 31.1 output for the same inputs:
//! `listdescriptors` on a blank Core wallet that imported them
//! (DescriptorScriptPubKeyMan::GetDescriptorString -> ToNormalizedString),
//! recorded in the PR body. Where the key path has no hardened step this is
//! also what `getdescriptorinfo` prints.
//!
//! Run: zig build test-unit -Dtest-filter=importdesc_privkeys

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const wallet_mod = @import("wallet.zig");
const descriptor = @import("descriptor.zig");

const TPRV = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";
// Core 31.1: listdescriptors after importing "wpkh(<TPRV>/0/*)".
const TPUB = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
const CORE_PUBLIC_RANGED = "wpkh(" ++ TPUB ++ "/0/*)#efr7m7hr";
// The private descriptor with its checksum (Core: checksum xgqsjp6d).
const PRIV_RANGED = "wpkh(" ++ TPRV ++ "/0/*)#xgqsjp6d";

const WIF = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"; // regtest key 1
const PRIV_WIF = "wpkh(" ++ WIF ++ ")#4wpu93nd";
const CORE_PUBLIC_WIF = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#ucxz0gak";

const PASS = "importdesc-test-passphrase";
const UNLOCK = "\"result\":null,\"error\":null"; // walletpassphrase success

fn has(hay: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, hay, needle) != null;
}

const Fixture = struct {
    chain_state: storage.ChainState,
    mempool: mempool_mod.Mempool,
    peer_manager: peer_mod.PeerManager,
    wm: wallet_mod.WalletManager,
    server: rpc.RpcServer,
    tmp: testing.TmpDir,
    dir: []const u8,
    allocator: std.mem.Allocator,

    fn init(self: *Fixture, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.tmp = testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        self.dir = try self.tmp.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(self.dir);
        self.chain_state = storage.ChainState.init(null, 64, allocator);
        errdefer self.chain_state.deinit();
        self.mempool = mempool_mod.Mempool.init(null, null, allocator);
        errdefer self.mempool.deinit();
        self.peer_manager = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
        errdefer self.peer_manager.deinit();
        self.wm = try wallet_mod.WalletManager.init(allocator, self.dir, .regtest);
        errdefer self.wm.deinit();
        self.server = rpc.RpcServer.initWithWalletManager(
            allocator,
            &self.chain_state,
            &self.mempool,
            &self.peer_manager,
            &consensus.REGTEST,
            &self.wm,
            .{},
        );
    }

    fn deinit(self: *Fixture) void {
        self.server.deinit();
        self.wm.deinit();
        self.peer_manager.deinit();
        self.mempool.deinit();
        self.chain_state.deinit();
        self.allocator.free(self.dir);
        self.tmp.cleanup();
    }

    fn call(self: *Fixture, method: []const u8, params_json: []const u8) ![]const u8 {
        const req = try std.fmt.allocPrint(self.allocator, "{{\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params_json });
        defer self.allocator.free(req);
        return self.server.dispatch(req);
    }

    /// createwallet "w" + a key (unlockWallet verifies the passphrase against
    /// the first key) + encryptwallet. Leaves the wallet encrypted and locked.
    fn encryptedLockedWallet(self: *Fixture) !*wallet_mod.Wallet {
        const created = try self.call("createwallet", "[\"w\"]");
        defer self.allocator.free(created);
        try testing.expect(has(created, "\"error\":null"));
        const w = self.wm.getWallet("w").?;
        _ = try w.generateKey();
        const enc = try self.call("encryptwallet", "[\"" ++ PASS ++ "\"]");
        defer self.allocator.free(enc);
        try testing.expect(has(enc, "\"error\":null"));
        try testing.expect(w.encrypted and !w.isUnlocked());
        return w;
    }

    fn readWalletDat(self: *Fixture) ![]u8 {
        const path = try std.fmt.allocPrint(self.allocator, "{s}/w/wallet.dat", .{self.dir});
        defer self.allocator.free(path);
        const f = try std.fs.openFileAbsolute(path, .{});
        defer f.close();
        return f.readToEndAlloc(self.allocator, 64 * 1024 * 1024);
    }
};

fn importReq(comptime desc: []const u8) []const u8 {
    return "[[{\"desc\":\"" ++ desc ++ "\",\"timestamp\":\"now\",\"range\":[0,2]}]]";
}

test "importdesc_privkeys locked encrypted wallet refuses importdescriptors with -13" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    const w = try fx.encryptedLockedWallet();

    const resp = try fx.call("importdescriptors", importReq(PRIV_RANGED));
    defer testing.allocator.free(resp);
    if (!has(resp, "\"code\":-13") or !has(resp, "Please enter the wallet passphrase with walletpassphrase first")) {
        std.debug.print("\nimportdescriptors on a locked wallet answered: {s}\n", .{resp});
        return error.ImportAcceptedOnLockedWallet;
    }
    // Nothing was taken in.
    try testing.expectEqual(@as(usize, 0), w.imported_scripts.items.len);
}

test "importdesc_privkeys unlocked import keeps no xprv in wallet.dat or listdescriptors" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    _ = try fx.encryptedLockedWallet();

    const unl = try fx.call("walletpassphrase", "[\"" ++ PASS ++ "\",600]");
    defer testing.allocator.free(unl);
    try testing.expect(has(unl, UNLOCK));

    const resp = try fx.call("importdescriptors", importReq(PRIV_RANGED));
    defer testing.allocator.free(resp);
    if (!has(resp, "[{\"success\":true}]")) {
        std.debug.print("\nimportdescriptors (unlocked) answered: {s}\n", .{resp});
        return error.ImportFailed;
    }

    // listdescriptors: Core's public form, never the tprv.
    const ld = try fx.call("listdescriptors", "[]");
    defer testing.allocator.free(ld);
    if (has(ld, "tprv") or !has(ld, "\"desc\":\"" ++ CORE_PUBLIC_RANGED ++ "\"")) {
        std.debug.print("\nlistdescriptors answered: {s}\nwant desc {s}\n", .{ ld, CORE_PUBLIC_RANGED });
        return error.ListDescriptorsShowsPrivateForm;
    }

    // wallet.dat at rest: no extended private key, in any position.
    try fx.wm.saveWallet("w");
    const bytes = try fx.readWalletDat();
    defer testing.allocator.free(bytes);
    if (has(bytes, TPRV) or has(bytes, "tprv")) {
        std.debug.print("\nwallet.dat of an ENCRYPTED wallet holds the imported tprv in plaintext\n", .{});
        return error.PlaintextPrivateKeyInWalletDat;
    }
    // Control: the import did persist (the descriptor is there, public).
    try testing.expect(has(bytes, CORE_PUBLIC_RANGED));
}

test "importdesc_privkeys WIF import stores the hex pubkey form" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    _ = try fx.encryptedLockedWallet();
    const unl = try fx.call("walletpassphrase", "[\"" ++ PASS ++ "\",600]");
    defer testing.allocator.free(unl);
    try testing.expect(has(unl, UNLOCK));

    const resp = try fx.call("importdescriptors", "[[{\"desc\":\"" ++ PRIV_WIF ++ "\",\"timestamp\":\"now\"}]]");
    defer testing.allocator.free(resp);
    try testing.expect(has(resp, "[{\"success\":true}]"));

    const ld = try fx.call("listdescriptors", "[]");
    defer testing.allocator.free(ld);
    if (has(ld, WIF) or !has(ld, "\"desc\":\"" ++ CORE_PUBLIC_WIF ++ "\"")) {
        std.debug.print("\nlistdescriptors answered: {s}\nwant desc {s}\n", .{ ld, CORE_PUBLIC_WIF });
        return error.ListDescriptorsShowsPrivateForm;
    }
    try fx.wm.saveWallet("w");
    const bytes = try fx.readWalletDat();
    defer testing.allocator.free(bytes);
    try testing.expect(!has(bytes, WIF));
}

test "importdesc_privkeys unencrypted wallet: import still works, public form stored" {
    // Control for the gate: an unencrypted wallet is never "locked", so the
    // -13 check must not fire there (Core IsLocked() is false when not
    // encrypted).
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    const created = try fx.call("createwallet", "[\"w\"]");
    defer testing.allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));

    const resp = try fx.call("importdescriptors", importReq(PRIV_RANGED));
    defer testing.allocator.free(resp);
    try testing.expect(has(resp, "[{\"success\":true}]"));
    const ld = try fx.call("listdescriptors", "[]");
    defer testing.allocator.free(ld);
    try testing.expect(has(ld, "\"desc\":\"" ++ CORE_PUBLIC_RANGED ++ "\""));
    try testing.expect(!has(ld, "tprv"));
}

test "importdesc_privkeys a wallet.dat written before the fix loads with the public form" {
    // Files written by the unfixed import hold the private descriptor in
    // imported_scripts[].desc. Simulate one (import, save, put the private
    // string back in the file) and load it with a fresh manager: the loaded
    // record must be the public form, so the next save drops the key.
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    const created = try fx.call("createwallet", "[\"w\"]");
    defer testing.allocator.free(created);
    try testing.expect(has(created, "\"error\":null"));
    const resp = try fx.call("importdescriptors", "[[{\"desc\":\"" ++ PRIV_WIF ++ "\",\"timestamp\":\"now\"}]]");
    defer testing.allocator.free(resp);
    try testing.expect(has(resp, "[{\"success\":true}]"));
    try fx.wm.saveWallet("w");

    const bytes = try fx.readWalletDat();
    defer testing.allocator.free(bytes);
    const legacy = try std.mem.replaceOwned(u8, testing.allocator, bytes, CORE_PUBLIC_WIF, PRIV_WIF);
    defer testing.allocator.free(legacy);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/w/wallet.dat", .{fx.dir});
    defer testing.allocator.free(path);
    {
        const f = try std.fs.createFileAbsolute(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll(legacy);
    }
    // Control: the simulated legacy file really holds the WIF.
    try testing.expect(has(legacy, WIF));

    var wm2 = try wallet_mod.WalletManager.init(testing.allocator, fx.dir, .regtest);
    defer wm2.deinit();
    const w2 = try wm2.loadWallet("w");
    try testing.expect(w2.imported_scripts.items.len == 1);
    try testing.expectEqualStrings(CORE_PUBLIC_WIF, w2.imported_scripts.items[0].desc);
    try wm2.saveWallet("w");
    const after = try fx.readWalletDat();
    defer testing.allocator.free(after);
    try testing.expect(!has(after, WIF));
}

// Core 31.1 importdescriptors (blank wallet) -> listdescriptors, one row each
// (CORE_PUBLIC_WIF is getdescriptorinfo; no hardened step, so the same form).
const CoreVector = struct { priv: []const u8, core: []const u8 };
const CORE_VECTORS = [_]CoreVector{
    // BIP-84 shape: hardened prefix re-rooted into the origin, root fp added.
    .{ .priv = "wpkh(" ++ TPRV ++ "/84h/1h/0h/0/*)#pe5sgqha", .core = "wpkh([0c5f9a1e/84h/1h/0h]tpubDCxzhZZE31g2EqSv1UajMAw5Hd62htydz9r2XBkrccHgBh8uw3n62zr6Zjmj64tfTk8Tjxo6VctjUMAh5DXWTErfQPC6RmQhTdtNnXuTXTQ/0/*)#jgtynm6c" },
    // Existing origin extended by the hardened prefix; apostrophes -> h.
    .{ .priv = "pkh([d34db33f/44'/1']" ++ TPRV ++ "/1'/2/*)#zd2ex2nw", .core = "pkh([d34db33f/44h/1h/1h]tpubD8MQJFNHgAX8vnSnh9XYgiR45ofayYzBn2rRrxzEjYg7jmLgPuK7V9TdF381RP3MiwWynwYUXdQ3keKCNeiV6av9pfzJwh93BQQjP5GmdtP/2/*)#f70fes0p" },
    // Hardened-ranged: root xpub kept, marker printed as h.
    .{ .priv = "sh(wpkh(" ++ TPRV ++ "/7/*'))#zmh0uxw8", .core = "sh(wpkh(" ++ TPUB ++ "/7/*h))#fjguwcts" },
    // No hardened step: xpub swapped in place.
    .{ .priv = PRIV_RANGED, .core = CORE_PUBLIC_RANGED },
    // WIF with an origin.
    .{ .priv = "wpkh([aabbccdd/0']" ++ WIF ++ ")#lnc03fse", .core = "wpkh([aabbccdd/0h]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#20ec8aw5" },
    // Non-ranged taproot key with a hardened prefix.
    .{ .priv = "tr(" ++ TPRV ++ "/86'/1'/0'/0/5)#706a9aam", .core = "tr([0c5f9a1e/86h/1h/0h]tpubDDCA1MQNPcAVLUaV3A3yWNLuM25zSoXMWHYTQwLVeNRmKkT61j8SZ1XCsXDAUoU7mwbVhmntBji9ydEQrCdE8PcqwCytXb18J7bi8tfCbHA/0/5)#3l4ynhzv" },
    // Multisig, origin on the private key, a plain hex pubkey beside it.
    .{ .priv = "wsh(multi(1,[d34db33f/84'/1'/0']" ++ TPRV ++ "/1/*,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))#4jt3rg3p", .core = "wsh(multi(1,[d34db33f/84h/1h/0h]" ++ TPUB ++ "/1/*,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))#23x7s3vc" },
    .{ .priv = PRIV_WIF, .core = CORE_PUBLIC_WIF },
    // P2TR context: a WIF prints x-only, as internal key and in a tap leaf.
    .{ .priv = "tr(" ++ WIF ++ ")#tnrke5yz", .core = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gxjkeue2" },
    .{ .priv = "tr(" ++ TPUB ++ ",pk(" ++ WIF ++ "))#d5ktc8ud", .core = "tr(" ++ TPUB ++ ",pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))#el9cgupy" },
    // Origin path elements print from their value: 044' -> 44h.
    .{ .priv = "pkh([d34db33f/044']" ++ TPRV ++ "/0)#nr8xdjap", .core = "pkh([d34db33f/44h]" ++ TPUB ++ "/0)#qse2zq9w" },
};

test "importdesc_privkeys BIP-32 depth past 255 is refused, not wrapped" {
    // Core CExtKey::Derive refuses to go past depth 255. The root here has
    // depth 0, so 255 hardened steps re-root at depth 255 and 256 must fail.
    if (comptime !@hasDecl(descriptor, "toPublicDescriptor")) {
        return error.NoPublicDescriptorConversion;
    } else {
        var buf = std.ArrayList(u8).init(testing.allocator);
        defer buf.deinit();
        try buf.appendSlice("wpkh(" ++ TPRV);
        var n: usize = 0;
        while (n < 255) : (n += 1) try buf.appendSlice("/0h");
        try buf.append(')');
        const ok = try descriptor.toPublicDescriptor(testing.allocator, buf.items);
        defer testing.allocator.free(ok);
        try testing.expect(std.mem.indexOf(u8, ok, "tprv") == null);
        buf.shrinkRetainingCapacity(buf.items.len - 1);
        try buf.appendSlice("/0h)");
        try testing.expectError(error.InvalidKeyExpression, descriptor.toPublicDescriptor(testing.allocator, buf.items));
    }
}

test "importdesc_privkeys public form matches Core listdescriptors (11 vectors)" {
    // Guarded so this file compiles on the base commit (where the function
    // does not exist) and fails there on the assertion.
    if (comptime !@hasDecl(descriptor, "toPublicDescriptor")) {
        return error.NoPublicDescriptorConversion;
    } else {
        for (CORE_VECTORS) |v| {
            const got = try descriptor.toPublicDescriptor(testing.allocator, v.priv);
            defer testing.allocator.free(got);
            try testing.expectEqualStrings(v.core, got);
            // Idempotent: Core's own output converts to itself.
            const again = try descriptor.toPublicDescriptor(testing.allocator, v.core);
            defer testing.allocator.free(again);
            try testing.expectEqualStrings(v.core, again);
        }
    }
}

test "importdesc_privkeys BIP-84 hardened import lists Core's re-rooted xpub" {
    var fx: Fixture = undefined;
    try fx.init(testing.allocator);
    defer fx.deinit();
    _ = try fx.encryptedLockedWallet();
    const unl = try fx.call("walletpassphrase", "[\"" ++ PASS ++ "\",600]");
    defer testing.allocator.free(unl);
    try testing.expect(has(unl, UNLOCK));

    const v = CORE_VECTORS[0];
    const req = try std.fmt.allocPrint(testing.allocator, "[[{{\"desc\":\"{s}\",\"timestamp\":\"now\",\"range\":[0,2]}}]]", .{v.priv});
    defer testing.allocator.free(req);
    const resp = try fx.call("importdescriptors", req);
    defer testing.allocator.free(resp);
    if (!has(resp, "[{\"success\":true}]")) {
        std.debug.print("\nimportdescriptors answered: {s}\n", .{resp});
        return error.ImportFailed;
    }
    const ld = try fx.call("listdescriptors", "[]");
    defer testing.allocator.free(ld);
    const want = try std.fmt.allocPrint(testing.allocator, "\"desc\":\"{s}\"", .{v.core});
    defer testing.allocator.free(want);
    if (has(ld, "tprv") or !has(ld, want)) {
        std.debug.print("\nlistdescriptors answered: {s}\nwant {s}\n", .{ ld, want });
        return error.ListDescriptorsNotCoreForm;
    }
}
