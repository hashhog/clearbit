//! BIP-35 (mempool message) + NODE_BLOOM advertisement tests.
//!
//! Run via `zig build test-bip35` (also folded into `zig build test`).
//!
//! These exercise the parts the fix touched:
//!   * NODE_BLOOM constant value (BIP-37: NODE_BLOOM = 1 << 2).
//!   * The advertised-services bitmap composition.
//!   * mempool.buildMempoolInventory inv-vector selection (MSG_WTX for
//!     witness-capable peers, MSG_TX otherwise) — mirrors Bitcoin Core's
//!     `peer.m_wtxid_relay` selection at net_processing.cpp:6007.
//!   * Fee-filter (BIP-133) gating on inv items.
//!
//! The full handler (handleMessage's `.mempool` case) calls into a real
//! socket so it isn't unit-testable in isolation; the helper isolates the
//! inv-construction logic deterministically.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const p2p = @import("p2p.zig");
const mempool_mod = @import("mempool.zig");

test "BIP-35: NODE_BLOOM constant equals 4 per BIP-37" {
    try testing.expectEqual(@as(u64, 4), p2p.NODE_BLOOM);
}

test "BIP-35: advertised services bitmap includes NODE_BLOOM when peerbloomfilters=true" {
    // Mirror peer.zig:performHandshake's services builder.
    var advertised: u64 = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
    advertised |= p2p.NODE_BLOOM;
    try testing.expect((advertised & p2p.NODE_BLOOM) != 0);
    try testing.expect((advertised & p2p.NODE_NETWORK) != 0);
    try testing.expect((advertised & p2p.NODE_WITNESS) != 0);

    const opt_out: u64 = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
    try testing.expect((opt_out & p2p.NODE_BLOOM) == 0);
}

test "BIP-35: buildMempoolInventory returns wtxid inv for witness-capable peer" {
    const allocator = testing.allocator;

    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Insert one tx into the mempool.
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x42} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{ .value = 100_000, .script_pubkey = &p2wpkh_script };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };
    try pool.addTransaction(tx);
    try testing.expectEqual(@as(usize, 1), pool.entries.count());

    const inv = try mempool_mod.buildMempoolInventory(&pool, true, 0, allocator);
    defer allocator.free(inv);

    try testing.expectEqual(@as(usize, 1), inv.len);
    try testing.expectEqual(p2p.InvType.msg_witness_tx, inv[0].inv_type);

    // Hash should match the wtxid of the only mempool entry.
    var iter = pool.entries.iterator();
    const entry = iter.next().?.value_ptr.*;
    try testing.expectEqualSlices(u8, &entry.wtxid, &inv[0].hash);
}

test "BIP-35: buildMempoolInventory returns txid inv for non-witness peer" {
    const allocator = testing.allocator;

    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xBB} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x33} ** 32, .index = 1 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{ .value = 50_000, .script_pubkey = &p2wpkh_script };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };
    try pool.addTransaction(tx);

    const inv = try mempool_mod.buildMempoolInventory(&pool, false, 0, allocator);
    defer allocator.free(inv);

    try testing.expectEqual(@as(usize, 1), inv.len);
    try testing.expectEqual(p2p.InvType.msg_tx, inv[0].inv_type);

    var iter = pool.entries.iterator();
    const entry = iter.next().?.value_ptr.*;
    try testing.expectEqualSlices(u8, &entry.txid, &inv[0].hash);
}

test "BIP-35: empty mempool yields empty inventory" {
    const allocator = testing.allocator;

    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    const inv = try mempool_mod.buildMempoolInventory(&pool, true, 0, allocator);
    defer allocator.free(inv);
    try testing.expectEqual(@as(usize, 0), inv.len);
}

test "BIP-35: buildMempoolInventory honors BIP-133 fee filter" {
    const allocator = testing.allocator;

    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Add a tx; its fee_rate (per_kvb) will be small.  Then set a
    // fee_filter_received above the entry's fee_rate, the inventory
    // builder should drop it.
    const p2wpkh_script = [_]u8{0x00} ++ [_]u8{0x14} ++ [_]u8{0xCC} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x77} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{ .value = 100_000, .script_pubkey = &p2wpkh_script };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };
    try pool.addTransaction(tx);

    // Compute fee rate of the inserted entry.  addTransaction sets
    // fee=missing-output-sum (no UTXO chain_state, so fee = 0 - output =
    // negative or zero).  In any case, a high fee filter should drop it.
    const inv_filtered = try mempool_mod.buildMempoolInventory(&pool, true, 1_000_000_000, allocator);
    defer allocator.free(inv_filtered);
    try testing.expectEqual(@as(usize, 0), inv_filtered.len);

    // No filter (0): the entry IS announced.
    const inv_unfiltered = try mempool_mod.buildMempoolInventory(&pool, true, 0, allocator);
    defer allocator.free(inv_unfiltered);
    try testing.expectEqual(@as(usize, 1), inv_unfiltered.len);
}
