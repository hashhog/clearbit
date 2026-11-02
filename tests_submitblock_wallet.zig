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
const validation = @import("src/validation.zig");

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

const block_template = @import("src/block_template.zig");

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// Build the next block on the tip paying `payee` (plus `extra` txs, with a
/// BIP-141 commitment when given) and hand it to submitblock, as the Core
/// regtest harness's wallet group does.
fn submitNext(
    server: *rpc.RpcServer,
    chain_state: *storage.ChainState,
    allocator: std.mem.Allocator,
    payee: []const u8,
    extra: []const types.Transaction,
) !void {
    const params = &consensus.REGTEST;
    const height = chain_state.best_height + 1;
    // BIP34: CScript() << height, padded to the 2-byte minimum.
    var sig_buf: [4]u8 = undefined;
    const script_sig: []u8 = if (height <= 16) blk: {
        sig_buf[0] = 0x50 + @as(u8, @intCast(height));
        sig_buf[1] = 0x00;
        break :blk sig_buf[0..2];
    } else if (height <= 127) blk: {
        sig_buf[0] = 0x01;
        sig_buf[1] = @intCast(height);
        break :blk sig_buf[0..2];
    } else blk: {
        sig_buf[0] = 0x02;
        sig_buf[1] = @intCast(height & 0xff);
        sig_buf[2] = @intCast(height >> 8);
        break :blk sig_buf[0..3];
    };
    const reserved = [_]u8{0} ** 32;
    const cb_witness = [_][]const u8{&reserved};
    var cb_inputs = [_]types.TxIn{.{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = try allocator.dupe(u8, script_sig),
        .sequence = 0xFFFFFFFF,
        .witness = if (extra.len > 0) &cb_witness else &[_][]const u8{},
    }};
    var cb_outputs = std.ArrayList(types.TxOut).init(allocator);
    try cb_outputs.append(.{ .value = 5_000_000_000, .script_pubkey = payee });
    if (extra.len > 0) {
        const commitment = try block_template.computeWitnessCommitment(extra, reserved, allocator);
        const script = block_template.createWitnessCommitmentScript(commitment);
        try cb_outputs.append(.{ .value = 0, .script_pubkey = try allocator.dupe(u8, &script) });
    }
    var txs = std.ArrayList(types.Transaction).init(allocator);
    try txs.append(.{ .version = 1, .inputs = &cb_inputs, .outputs = cb_outputs.items, .lock_time = 0 });
    try txs.appendSlice(extra);

    var txids = std.ArrayList(types.Hash256).init(allocator);
    for (txs.items) |*tx| try txids.append(try crypto.computeTxid(tx, allocator));
    var header = types.BlockHeader{
        .version = 0x20000000,
        .prev_block = chain_state.best_hash,
        .merkle_root = try crypto.computeMerkleRoot(txids.items, allocator),
        .timestamp = params.genesis_header.timestamp + 600 * height,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = txs.items };

    var wr = serialize.Writer.init(allocator);
    try serialize.writeBlock(&wr, &block);
    const hex = try allocator.alloc(u8, wr.list.items.len * 2);
    _ = std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(wr.list.items)}) catch unreachable;
    const req = try std.fmt.allocPrint(allocator, "{{\"id\":4,\"method\":\"submitblock\",\"params\":[\"{s}\"]}}", .{hex});
    const sub = try server.dispatch(req);
    if (!has(sub, "\"result\":null")) std.debug.print("submitblock at {d}: {s}\n", .{ height, sub });
    try testing.expect(has(sub, "\"result\":null"));
    try testing.expectEqual(height, chain_state.best_height);
}

fn resultString(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    return parsed.value.object.get("result").?.string;
}

test "submitblock-wallet a confirmed self-send has 1 confirmation and Core's send/receive details" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const params = &consensus.REGTEST;
    const dir = "/tmp/clearbit_submitblock_wallet_send";
    std.fs.deleteTreeAbsolute(dir) catch {};
    defer std.fs.deleteTreeAbsolute(dir) catch {};
    try std.fs.makeDirAbsolute(dir);
    const db_path = dir ++ "/chain";
    const wallet_dir = dir ++ "/wallets";

    // A booted node as main.zig wires it: chainstate on a database, a block
    // index (ChainManager) so submitblock can extend past height 1, and a
    // mempool that reads that chainstate.
    var db = try storage.Database.open(db_path, 64, allocator);
    defer db.close();
    var chain_state = storage.ChainState.init(&db, 64, allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();
    chain_state.setNetworkParams(params);
    chain_state.best_hash = params.genesis_hash;
    chain_state.initGenesisTimestamp(params.genesis_header.timestamp);
    chain_state.initGenesisRetarget(params.genesis_header.timestamp, params.genesis_header.bits);
    chain_state.seedGenesisTotalWork(params.genesis_header.bits);
    var cm = validation.ChainManager.init(&chain_state, null, allocator);
    defer cm.deinit();
    try cm.loadGenesis(params);
    var mempool = mempool_mod.Mempool.init(&chain_state, params, allocator);
    defer mempool.deinit();
    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();
    peer_manager.chain_state = &chain_state;
    var wm = try wallet_mod.WalletManager.init(allocator, wallet_dir, .regtest);
    defer wm.deinit();
    // 0.0002 BTC/kvB, the harness adapter's --fallbackfee.
    var server = rpc.RpcServer.initWithWalletManager(allocator, &chain_state, &mempool, &peer_manager, params, &wm, .{ .fallback_fee_sat_per_kvb = 20_000 });
    defer server.deinit();
    server.setChainManager(&cm);

    try testing.expect(has(try server.dispatch("{\"id\":1,\"method\":\"createwallet\",\"params\":[\"w\"]}"), "\"error\":null"));
    const addr_a = try resultString(allocator, try server.dispatch("{\"id\":1,\"method\":\"getnewaddress\",\"params\":[]}"));
    const addr_b = try resultString(allocator, try server.dispatch("{\"id\":1,\"method\":\"getnewaddress\",\"params\":[]}"));

    const info_req = try std.fmt.allocPrint(allocator, "{{\"id\":1,\"method\":\"getaddressinfo\",\"params\":[\"{s}\"]}}", .{addr_a});
    const info = try std.json.parseFromSlice(std.json.Value, allocator, try server.dispatch(info_req), .{});
    const spk_a = try hexToBytes(allocator, info.value.object.get("result").?.object.get("scriptPubKey").?.string);

    // 101 blocks to addr_a: block 1's coinbase is mature, the rest are not.
    for (0..101) |_| try submitNext(&server, &chain_state, allocator, spk_a, &.{});
    try testing.expectEqual(@as(u32, 101), chain_state.best_height);

    const send_req = try std.fmt.allocPrint(allocator, "{{\"id\":5,\"method\":\"sendtoaddress\",\"params\":[\"{s}\",1.0]}}", .{addr_b});
    const send = try server.dispatch(send_req);
    try testing.expect(has(send, "\"error\":null"));
    const txid = try resultString(allocator, send);

    // Block 102 mines the send, read back from the mempool.
    const raw_req = try std.fmt.allocPrint(allocator, "{{\"id\":5,\"method\":\"getrawtransaction\",\"params\":[\"{s}\"]}}", .{txid});
    const raw = try hexToBytes(allocator, try resultString(allocator, try server.dispatch(raw_req)));
    var reader = serialize.Reader{ .data = raw };
    const send_tx = try serialize.readTransaction(&reader, allocator);
    try submitNext(&server, &chain_state, allocator, spk_a, &.{send_tx});
    try testing.expectEqual(@as(u32, 102), chain_state.best_height);

    // listunspent: every spendable coin the send created is in block 102,
    // so 1 confirmation (Core); block 1's coinbase was spent by the send.
    const lu = try server.dispatch("{\"id\":6,\"method\":\"listunspent\",\"params\":[]}");
    const lu_parsed = try std.json.parseFromSlice(std.json.Value, allocator, lu, .{});
    var seen_sent = false;
    var non_coinbase: usize = 0;
    for (lu_parsed.value.object.get("result").?.array.items) |e| {
        const conf = e.object.get("confirmations").?.integer;
        if (std.mem.eql(u8, e.object.get("txid").?.string, txid)) {
            non_coinbase += 1;
            try testing.expectEqual(@as(i64, 1), conf);
            if (e.object.get("amount").?.float == 1.0) seen_sent = true;
        }
    }
    try testing.expect(seen_sent);
    try testing.expectEqual(@as(usize, 2), non_coinbase); // the 1 BTC output + change

    // gettransaction: Core lists the output to addr_b as send -1 and receive
    // +1; the change output has no detail line.
    const gt_req = try std.fmt.allocPrint(allocator, "{{\"id\":7,\"method\":\"gettransaction\",\"params\":[\"{s}\"]}}", .{txid});
    server.current_wallet = wm.getWallet("w").?; // the HTTP layer's single-wallet routing
    const gt = try server.dispatch(gt_req);
    const gt_parsed = try std.json.parseFromSlice(std.json.Value, allocator, gt, .{});
    if (gt_parsed.value.object.get("result").? != .object) std.debug.print("gettransaction: {s}\n", .{gt});
    try testing.expect(gt_parsed.value.object.get("result").? == .object);
    const result = gt_parsed.value.object.get("result").?.object;
    try testing.expectEqual(@as(i64, 1), result.get("confirmations").?.integer);
    const details = result.get("details").?.array.items;
    try testing.expectEqual(@as(usize, 2), details.len);
    var sends: usize = 0;
    var receives: usize = 0;
    for (details) |d| {
        const cat = d.object.get("category").?.string;
        const amt = d.object.get("amount").?.float;
        if (std.mem.eql(u8, cat, "send")) {
            sends += 1;
            try testing.expectEqual(@as(f64, -1.0), amt);
        } else if (std.mem.eql(u8, cat, "receive")) {
            receives += 1;
            try testing.expectEqual(@as(f64, 1.0), amt);
        }
    }
    try testing.expectEqual(@as(usize, 1), sends);
    try testing.expectEqual(@as(usize, 1), receives);
}
