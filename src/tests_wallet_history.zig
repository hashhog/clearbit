//! Wallet history regression: a spend the wallet itself committed (so
//! `commitWalletSend` already dropped the spent coin from the ledger) must
//! still be recorded as a `send` when its block is scanned.
//! Run with `zig build test-wallet-history`.

const std = @import("std");
const wallet_mod = @import("wallet.zig");
const types = @import("types.zig");
const secp256k1 = @import("secp.zig").c;

test "wallet-history: wallet spend committed before its block is a send, not a receive" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var w = try wallet_mod.Wallet.init(allocator, .regtest);
    defer w.deinit();
    const ki = try w.generateKey();
    const own_spk = try w.getScriptPubKey(ki, .p2wpkh);
    defer allocator.free(own_spk);

    // A confirmed wallet coin of 50 BTC.
    const funding = types.OutPoint{ .hash = [_]u8{0xA1} ** 32, .index = 0 };
    try w.addUtxo(.{
        .outpoint = funding,
        .output = .{ .value = 5_000_000_000, .script_pubkey = try allocator.dupe(u8, own_spk) },
        .key_index = ki,
        .address_type = .p2wpkh,
        .confirmations = 10,
    });

    // The spend: 10 BTC to a foreign P2WPKH, 39.999 BTC change, 0.001 fee.
    var foreign_spk = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x77} ** 20;
    const inputs = [_]types.TxIn{.{ .previous_output = funding, .script_sig = &.{}, .sequence = 0xffffffff, .witness = &.{} }};
    const outputs = [_]types.TxOut{
        .{ .value = 1_000_000_000, .script_pubkey = &foreign_spk },
        .{ .value = 3_999_900_000, .script_pubkey = own_spk },
    };
    const tx = types.Transaction{ .version = 2, .inputs = &inputs, .outputs = &outputs, .lock_time = 0 };

    // sendtoaddress/commitWalletSend drops the spent input from the ledger as
    // soon as the tx enters the mempool — i.e. BEFORE the block is scanned.
    try std.testing.expect(w.removeUtxo(funding));

    const txs = [_]types.Transaction{tx};
    const block = types.Block{
        .header = .{ .version = 1, .prev_block = [_]u8{0} ** 32, .merkle_root = [_]u8{0} ** 32, .timestamp = 1, .bits = 0x207fffff, .nonce = 0 },
        .transactions = &txs,
    };
    try w.scanBlockForWallet(&block, 102);

    try std.testing.expectEqual(@as(usize, 1), w.tx_history.items.len);
    const rec = &w.tx_history.items[0];
    try std.testing.expect(rec.is_from_me);
    try std.testing.expectEqual(@as(i64, 5_000_000_000), rec.debit);
    try std.testing.expectEqual(@as(i64, 100_000), rec.fee);
    var sends: usize = 0;
    var receives: usize = 0;
    for (rec.details.items) |d| {
        if (d.category == .send) {
            sends += 1;
            try std.testing.expectEqual(@as(u32, 0), d.vout);
            try std.testing.expectEqual(@as(i64, 1_000_000_000), d.amount);
        } else if (d.category == .receive) {
            receives += 1;
            try std.testing.expectEqual(@as(u32, 1), d.vout);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), sends);
    try std.testing.expectEqual(@as(usize, 1), receives);
}
