//! submitblock must feed a block that became the tip to the wallets, as
//! Core's CWallet::blockConnected does for every connected block. Pre-fix
//! only generate* and the P2P path scanned, so a chain built over submitblock
//! (the Core regtest harness's wallet group) left getbalance at 0 and
//! sendtoaddress failing "Insufficient funds".
//!
//! Run with `zig build test-submitblock-wallet`. Filter `submitblock-wallet`.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const wallet_mod = @import("src/wallet.zig");
const types = @import("src/types.zig");
const crypto = @import("src/crypto.zig");
const serialize = @import("src/serialize.zig");

fn has(body: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, body, needle) != null;
}

test "submitblock-wallet coinbase paying a wallet key shows up in listtransactions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const params = &consensus.REGTEST;
    const dir = "/tmp/clearbit_submitblock_wallet";
    std.fs.deleteTreeAbsolute(dir) catch {};
    defer std.fs.deleteTreeAbsolute(dir) catch {};

    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_hash = params.genesis_hash;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();
    var wm = try wallet_mod.WalletManager.init(allocator, dir, .regtest);
    defer wm.deinit();
    var server = rpc.RpcServer.initWithWalletManager(allocator, &chain_state, &mempool, &peer_manager, params, &wm, .{});
    defer server.deinit();

    const created = try server.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"w\"]}");
    try testing.expect(has(created, "\"error\":null"));
    const w = wm.getWallet("w").?;
    const ki = try w.generateKey();
    const spk = try w.getScriptPubKey(ki, .p2wpkh);

    // Height 1 on top of genesis: BIP34 coinbase height push, 50 BTC to the wallet.
    var script_sig = [_]u8{ 0x51, 0x00 };
    var inputs = [_]types.TxIn{.{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};
    var outputs = [_]types.TxOut{.{ .value = 5_000_000_000, .script_pubkey = spk }};
    var txs = [_]types.Transaction{.{ .version = 1, .inputs = &inputs, .outputs = &outputs, .lock_time = 0 }};
    var header = types.BlockHeader{
        .version = 0x20000000,
        .prev_block = params.genesis_hash,
        .merkle_root = try crypto.computeTxid(&txs[0], allocator),
        .timestamp = params.genesis_header.timestamp + 600,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = &txs };

    var wr = serialize.Writer.init(allocator);
    try serialize.writeBlock(&wr, &block);
    const hex = try allocator.alloc(u8, wr.list.items.len * 2);
    _ = std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(wr.list.items)}) catch unreachable;
    const req = try std.fmt.allocPrint(allocator, "{{\"id\":2,\"method\":\"submitblock\",\"params\":[\"{s}\"]}}", .{hex});

    const resp = try server.dispatch(req);
    try testing.expect(has(resp, "\"result\":null"));
    try testing.expectEqual(@as(u32, 1), chain_state.best_height);

    // The wallet ledger saw the coinbase: one history record, immature.
    try testing.expectEqual(@as(usize, 1), w.tx_history.items.len);
}
