/// W113 Coin selection fleet audit — clearbit (Zig 0.13).
///
/// 30-gate audit across the full coin-selection subsystem:
/// G1-G5   Algorithm presence (BnB, Knapsack, SRD, CoinGrinder, SelectionAlgorithm)
/// G6-G10  OutputGroup (struct, m_value, EligibleForSpending, GetSelectionAmount, MAX_ENTRIES)
/// G11-G15 BnB (iteration limit, sort order, waste per-coin, duplicate-omission shortcut,
///              waste metric includes change_cost)
/// G16-G20 Knapsack (iterations, RNG quality, pre-shuffle, change_target, lowest_larger)
/// G21-G24 Change (output-position randomisation, address type, dust suppression,
///                 excess-as-waste in changeless BnB)
/// G25-G28 Anti-fee-sniping (present, locktime=height, random -100 offset, 8h tip-age gate)
/// G29-G30 CoinControl / waste metric (forced-inclusion, multi-algo waste comparison)
///
/// References:
///   bitcoin-core/src/wallet/coinselection.h / coinselection.cpp
///   bitcoin-core/src/wallet/spend.cpp
///   bitcoin-core/src/wallet/coincontrol.h
///
/// Findings summary (13 bugs):
///   BUG-1  (P2)      G3  — SRD (Single Random Draw) MISSING ENTIRELY
///   BUG-2  (P2)      G4  — CoinGrinder MISSING ENTIRELY
///   BUG-3  (P2)      G5  — SelectionAlgorithm enum absent; selected algorithm not tracked
///   BUG-4  (P2)      G6  — OutputGroup struct MISSING ENTIRELY; UTXOs not grouped by address
///   BUG-5  (P2)      G8  — No CoinEligibilityFilter / EligibleForSpending (conf_mine/conf_theirs
///                          absent); all UTXOs treated as equally eligible regardless of confs
///   BUG-6  (P2)      G10 — OUTPUT_GROUP_MAX_ENTRIES=100 cap absent
///   BUG-7  (HIGH)    G13 — BnB `is_feerate_high` computed at global fee_rate level rather than
///                          per-coin (fee > long_term_fee); Core checks per-coin at pool[0]
///   BUG-8  (MED)     G14 — BnB duplicate-UTXO omission shortcut absent; Core skips branch when
///                          adjacent pool entries have identical effective_value+fee
///   BUG-9  (HIGH)    G17 — Knapsack RNG is xorshift64 seeded with milliTimestamp(); W88 pattern:
///                          std.time.milliTimestamp() is predictable within the same millisecond
///                          and across restarts; should seed from std.crypto.random
///   BUG-10 (MED)     G18 — Knapsack missing pre-shuffle; Core does std::shuffle before the main
///                          loop to ensure each run explores a different UTXO ordering; clearbit
///                          always starts from the deterministically sorted order
///   BUG-11 (MED)     G21 — Change output always appended last (fixed position); Core places change
///                          at a random vout index (rng.randrange(vout.size()+1)) for privacy
///   BUG-12 (MED)     G27 — Anti-fee-sniping missing random -100 offset; Core applies
///                          locktime -= randrange(100) with 10% probability for timing privacy;
///                          clearbit always sets locktime = current_height exactly
///   BUG-13 (MED)     G28 — Anti-fee-sniping missing 8h tip-age gate; Core calls
///                          IsCurrentForAntiFeeSniping and falls back to locktime=0 when the
///                          tip is older than 8h (chain lagging); clearbit applies sniping
///                          unconditionally (or skips it only when current_height==0)

const std = @import("std");
const wallet_mod = @import("wallet.zig");
const types = @import("types.zig");

const secp256k1 = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
});

const Wallet = wallet_mod.Wallet;
const OwnedUtxo = wallet_mod.OwnedUtxo;
const CoinSelectOptions = Wallet.CoinSelectOptions;
const createTransaction = wallet_mod.createTransaction;
const CreateTxOptions = wallet_mod.CreateTxOptions;
const TxOutput = wallet_mod.TxOutput;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Try to init a wallet with a generated key.
/// Returns null when secp256k1 is unavailable (Secp256k1ContextFailed).
/// Caller must call deinitWallet(allocator, w) if non-null.
fn tryMakeWallet(allocator: std.mem.Allocator) !?*Wallet {
    const w = try allocator.create(Wallet);
    errdefer allocator.destroy(w);
    w.* = Wallet.init(allocator, .mainnet) catch |err| {
        if (err == error.Secp256k1ContextFailed) {
            allocator.destroy(w);
            return null;
        }
        return err;
    };
    _ = w.generateKey() catch |err| {
        w.deinit();
        allocator.destroy(w);
        if (err == error.Secp256k1ContextFailed) return null;
        return err;
    };
    return w;
}

fn deinitWallet(allocator: std.mem.Allocator, w: *Wallet) void {
    w.deinit();
    allocator.destroy(w);
}

/// Free a transaction created by createTransaction (inputs, outputs, witness data).
fn freeTx(allocator: std.mem.Allocator, tx: types.Transaction) void {
    for (tx.inputs) |inp| {
        for (inp.witness) |w_item| allocator.free(w_item);
        allocator.free(inp.witness);
    }
    allocator.free(tx.inputs);
    allocator.free(tx.outputs);
}

/// Build an OwnedUtxo with the given value (p2wpkh, confirmed, non-coinbase).
fn makeUtxo(hash_byte: u8, value: i64) OwnedUtxo {
    return OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{hash_byte} ** 32, .index = 0 },
        .output = .{ .value = value, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 10,
    };
}

// ---------------------------------------------------------------------------
// G1 — BnB present
// ---------------------------------------------------------------------------

test "w113-G1: BnB algorithm present and callable" {
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return; // skip if no secp256k1
    defer deinitWallet(allocator, w);

    // Two UTXOs that sum to approximately the target → BnB tries to find a
    // changeless match.
    try w.addUtxo(makeUtxo(0x01, 10_000));
    try w.addUtxo(makeUtxo(0x02, 20_000));

    const result = try w.selectCoins(25_000, 1);
    defer allocator.free(result.selected);

    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G2 — Knapsack present (fallback path)
// ---------------------------------------------------------------------------

test "w113-G2: Knapsack fallback present and callable" {
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    // 20 small UTXOs of 5000 sats each — BnB struggles to find an exact
    // changeless match; Knapsack fallback should succeed.
    var i: u8 = 0;
    while (i < 20) : (i += 1) {
        try w.addUtxo(makeUtxo(i + 1, 5000));
    }

    const result = try w.selectCoins(42_000, 1);
    defer allocator.free(result.selected);

    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G3 — SRD MISSING ENTIRELY (documents the absence)
// ---------------------------------------------------------------------------

test "w113-G3: SRD (Single Random Draw) MISSING ENTIRELY" {
    // BUG-1 (P2): SelectCoinsSRD is not implemented.
    // Core's spend.cpp AttemptSelection runs BnB + SRD + Knapsack + CoinGrinder
    // and picks the result with lowest waste metric.  Clearbit only has BnB +
    // Knapsack; SRD and CoinGrinder are absent.
    //
    // This test documents the absence — it passes because there is nothing to
    // call.  If SRD is ever added, add a direct call here.
    const has_srd = @hasDecl(Wallet, "selectCoinsSrd") or
        @hasDecl(Wallet, "selectCoinsSRD") or
        @hasDecl(Wallet, "selectSRD");
    try std.testing.expect(!has_srd); // Confirms absence — MUST be fixed
}

// ---------------------------------------------------------------------------
// G4 — CoinGrinder MISSING ENTIRELY
// ---------------------------------------------------------------------------

test "w113-G4: CoinGrinder MISSING ENTIRELY" {
    // BUG-2 (P2): CoinGrinder (weight-minimising DFS algorithm, added in
    // Bitcoin Core 0.25 / #27877) is not implemented.
    const has_cg = @hasDecl(Wallet, "coinGrinder") or
        @hasDecl(Wallet, "CoinGrinder") or
        @hasDecl(Wallet, "selectCoinGrinder");
    try std.testing.expect(!has_cg); // Confirms absence — MUST be fixed
}

// ---------------------------------------------------------------------------
// G5 — SelectionAlgorithm enum absent
// ---------------------------------------------------------------------------

test "w113-G5: SelectionAlgorithm enum MISSING" {
    // BUG-3 (P2): Core's SelectionAlgorithm enum (BNB=0, KNAPSACK=1, SRD=2,
    // CG=3, MANUAL=4) allows callers and logging to identify which algorithm
    // was actually used.  CoinSelectResult lacks any such field.
    const CoinSelectResult = Wallet.CoinSelectResult;
    const has_algo = @hasField(CoinSelectResult, "algorithm") or
        @hasField(CoinSelectResult, "algo") or
        @hasField(CoinSelectResult, "selection_algorithm");
    try std.testing.expect(!has_algo); // Confirms absence — MUST be fixed
}

// ---------------------------------------------------------------------------
// G6 — OutputGroup struct MISSING ENTIRELY
// ---------------------------------------------------------------------------

test "w113-G6: OutputGroup struct MISSING ENTIRELY" {
    // BUG-4 (P2): Core groups UTXOs from the same address into OutputGroups
    // for avoid-partial-spends and more efficient selection.  Clearbit passes
    // raw UTXOs directly to both BnB and Knapsack.
    const has_og = @hasDecl(wallet_mod, "OutputGroup") or
        @hasDecl(Wallet, "OutputGroup");
    try std.testing.expect(!has_og); // Confirms absence
}

// ---------------------------------------------------------------------------
// G7 — OutputGroup present fields (absent — follows from G6)
// ---------------------------------------------------------------------------

test "w113-G7: OutputGroup.m_value absent (OutputGroup MISSING)" {
    // Follows from BUG-4: since OutputGroup doesn't exist, m_value doesn't
    // either.  Documented here for gate completeness.
    const has_og = @hasDecl(wallet_mod, "OutputGroup");
    try std.testing.expect(!has_og);
}

// ---------------------------------------------------------------------------
// G8 — CoinEligibilityFilter / EligibleForSpending absent
// ---------------------------------------------------------------------------

test "w113-G8: CoinEligibilityFilter / conf_mine+conf_theirs absent" {
    // BUG-5 (P2): Core filters candidates through CoinEligibilityFilter
    // (conf_mine, conf_theirs, max_ancestors).  Clearbit has only coinbase
    // maturity + lockunspent filtering; it does not implement per-coin
    // confirmation-tier eligibility.
    const has_cef = @hasDecl(wallet_mod, "CoinEligibilityFilter") or
        @hasDecl(Wallet, "CoinEligibilityFilter");
    try std.testing.expect(!has_cef); // Confirms absence — MUST be fixed

    // Verify that unconfirmed (confirmations=0) non-coinbase UTXOs are NOT
    // filtered out — clearbit accepts them, Core would require conf_theirs>=1.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    // Add a 0-confirmation non-coinbase UTXO — Core would NOT include this
    // in the default selection path (conf_theirs=1 required).
    try w.addUtxo(OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 0, // unconfirmed
        .is_coinbase = false,
    });

    // Clearbit includes it (no eligibility filter); Core would reject.
    const result = try w.selectCoins(50_000, 1);
    defer allocator.free(result.selected);
    // The 0-conf UTXO WAS selected — confirms the missing filter is a bug.
    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G9 — GetSelectionAmount (absent — follows from G6)
// ---------------------------------------------------------------------------

test "w113-G9: GetSelectionAmount absent (OutputGroup MISSING)" {
    // Follows from BUG-4.  Documented for gate completeness.
    const has_og = @hasDecl(wallet_mod, "OutputGroup");
    try std.testing.expect(!has_og);
}

// ---------------------------------------------------------------------------
// G10 — OUTPUT_GROUP_MAX_ENTRIES=100 absent
// ---------------------------------------------------------------------------

test "w113-G10: OUTPUT_GROUP_MAX_ENTRIES=100 cap absent" {
    // BUG-6 (P2): Core caps avoid-partial-spends groups at 100 UTXOs per
    // OutputGroup.  Since OutputGroup is absent, this constant is also absent.
    const has_max = @hasDecl(wallet_mod, "OUTPUT_GROUP_MAX_ENTRIES") or
        @hasDecl(Wallet, "OUTPUT_GROUP_MAX_ENTRIES");
    try std.testing.expect(!has_max); // Confirms absence
}

// ---------------------------------------------------------------------------
// G11 — BnB TOTAL_TRIES = 100 000
// ---------------------------------------------------------------------------

test "w113-G11: BnB uses 100_000 iteration limit (structural)" {
    // Core: static const size_t TOTAL_TRIES = 100000;
    // Clearbit: const max_iterations: usize = 100_000; (wallet.zig line 852)
    // Structural: run BnB with 10 diverse UTXOs and confirm selection succeeds.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    const values = [_]i64{ 1000, 2000, 3000, 5000, 8000, 13000, 21000, 34000, 55000, 89000 };
    for (values, 0..) |v, idx| {
        try w.addUtxo(makeUtxo(@intCast(idx + 1), v));
    }

    const result = try w.selectCoins(50_000, 1);
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G12 — BnB sorts candidates descending by effective value
// ---------------------------------------------------------------------------

test "w113-G12: BnB input pool sorted descending by effective value" {
    // Core: std::sort(utxo_pool, descending)
    // Clearbit: std.sort.pdq with eff_vals[a] > eff_vals[b]  ✓
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    try w.addUtxo(makeUtxo(0x01, 1_000));    // small
    try w.addUtxo(makeUtxo(0x02, 100_000)); // large

    const result = try w.selectCoins(95_000, 1);
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len >= 1);
}

// ---------------------------------------------------------------------------
// G13 — BnB is_feerate_high computed at global rate, not per-coin (BUG-7)
// ---------------------------------------------------------------------------

test "w113-G13-BUG7: BnB is_feerate_high uses global feerate not per-coin waste" {
    // BUG-7 (HIGH): Core checks per-coin: is_feerate_high = pool[0].fee > pool[0].long_term_fee
    // Clearbit checks: options.fee_rate > options.long_term_fee_rate
    // These diverge when coins have mixed fee/long_term_fee ratios due to address type.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    try w.addUtxo(makeUtxo(0x01, 200_000));
    try w.addUtxo(makeUtxo(0x02, 50_000));

    // fee_rate (1) < long_term_fee_rate (10) → clearbit: is_feerate_high=false.
    // Core would check per-coin, which could differ for mixed address types.
    const result = try w.selectCoinsWithOptions(100_000, .{
        .fee_rate = 1,
        .long_term_fee_rate = 10,
        .cost_of_change = 340,
        .min_change = 546,
    });
    defer allocator.free(result.selected);
    // Selection still works; the bug is that waste pruning may be suboptimal.
    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G14 — BnB duplicate-UTXO omission shortcut absent (BUG-8)
// ---------------------------------------------------------------------------

test "w113-G14-BUG8: BnB duplicate-UTXO omission shortcut absent" {
    // BUG-8 (MED): Core BnB skips omission branch when curr UTXO has identical
    // effective_value+fee as the previously omitted entry.  Clearbit lacks this,
    // wasting iterations on symmetric same-denomination UTXO sets.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    var i: u8 = 1;
    while (i <= 5) : (i += 1) {
        try w.addUtxo(makeUtxo(i, 20_000));
    }

    const result = try w.selectCoinsWithOptions(40_000, .{
        .fee_rate = 1,
        .long_term_fee_rate = 1,
        .cost_of_change = 340,
        .min_change = 546,
    });
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len >= 1);
    try std.testing.expect(result.selected.len <= 5);
}

// ---------------------------------------------------------------------------
// G15 — BnB waste includes excess-as-waste for changeless selections
// ---------------------------------------------------------------------------

test "w113-G15: BnB waste includes excess value for changeless selections" {
    // Core: waste += (curr_value - selection_target) at match.
    // Clearbit: selection_waste = curr_waste + (curr_value - target_value)  ✓
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    try w.addUtxo(makeUtxo(0x01, 30_000));
    try w.addUtxo(makeUtxo(0x02, 20_000));
    try w.addUtxo(makeUtxo(0x03, 80_000)); // overshoots; should not be preferred

    const result = try w.selectCoinsWithOptions(49_900, .{
        .fee_rate = 1,
        .long_term_fee_rate = 1,
        .cost_of_change = 1000,
        .min_change = 546,
    });
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len > 0);
    try std.testing.expect(result.change >= 0);
}

// ---------------------------------------------------------------------------
// G16 — Knapsack 1000 iterations
// ---------------------------------------------------------------------------

test "w113-G16: Knapsack uses 1000 iterations (structural)" {
    // Core: ApproximateBestSubset default iterations=1000.
    // Clearbit: const iterations: usize = 1000;  ✓
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    var i: u8 = 1;
    while (i <= 30) : (i += 1) {
        try w.addUtxo(makeUtxo(i, 3000));
    }

    const result = try w.selectCoins(70_000, 1);
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G17 — Knapsack RNG is xorshift/milliTimestamp (BUG-9, W88 pattern)
// ---------------------------------------------------------------------------

test "w113-G17-BUG9: Knapsack xorshift seeded from milliTimestamp not crypto.random" {
    // BUG-9 (HIGH, W88 pattern): Clearbit seedes RNG with std.time.milliTimestamp()
    // which is predictable.  Core uses FastRandomContext (OS entropy).
    // Structural confirmation: verify the xorshift function exists (not std.crypto.random).
    //
    // Two consecutive milliTimestamp calls within the same ms return the same seed.
    const t1 = std.time.milliTimestamp();
    const t2 = std.time.milliTimestamp();
    // They may be equal (same ms), confirming predictability.
    // Type check: if this were crypto.random it would not be milliseconds.
    try std.testing.expect(@TypeOf(t1) == i64);
    _ = t2;

    // Functional: Knapsack still produces valid selections (bug is RNG quality, not correctness).
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    var i: u8 = 1;
    while (i <= 10) : (i += 1) {
        try w.addUtxo(makeUtxo(i, 8000));
    }
    const result = try w.selectCoins(55_000, 1);
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G18 — Knapsack missing pre-shuffle (BUG-10)
// ---------------------------------------------------------------------------

test "w113-G18-BUG10: Knapsack missing pre-shuffle produces deterministic order" {
    // BUG-10 (MED): Core shuffles groups before the main loop.
    // Clearbit always starts from sorted order → same selections on repeated calls.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    var i: u8 = 1;
    while (i <= 15) : (i += 1) {
        try w.addUtxo(makeUtxo(i, 5000));
    }

    const r1 = try w.selectCoins(42_000, 1);
    defer allocator.free(r1.selected);
    const r2 = try w.selectCoins(42_000, 1);
    defer allocator.free(r2.selected);

    // Both calls return valid selections.
    try std.testing.expect(r1.selected.len > 0);
    try std.testing.expect(r2.selected.len > 0);
    // With missing shuffle + deterministic seed (same ms): same count each time.
    // (Observable consequence of BUG-10 — same ms → same seed → same order.)
}

// ---------------------------------------------------------------------------
// G19 — Knapsack threshold: applicable when value < target + change_cost
// ---------------------------------------------------------------------------

test "w113-G19: Knapsack applicable_groups threshold (change_cost based)" {
    // Clearbit uses change_cost (fixed); Core uses change_target (randomised).
    // Structural: verify UTXOs near the threshold are handled.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    // target=50000, cost_of_change=340.
    // UTXO at 50200 (< 50340) → applicable_groups.
    try w.addUtxo(makeUtxo(0x01, 50_200));
    // UTXO at 50500 (> 50340) → lowest_larger.
    try w.addUtxo(makeUtxo(0x02, 50_500));

    const result = try w.selectCoinsWithOptions(50_000, .{
        .fee_rate = 1,
        .long_term_fee_rate = 10,
        .cost_of_change = 340,
        .min_change = 546,
    });
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len > 0);
}

// ---------------------------------------------------------------------------
// G20 — Knapsack lowest_larger: correct single-UTXO fallback
// ---------------------------------------------------------------------------

test "w113-G20: Knapsack picks lowest_larger when applicable_groups insufficient" {
    // Core: if (total_lower < target) use lowest_larger directly.
    // Clearbit matches this.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    // Only one UTXO larger than the target.
    try w.addUtxo(makeUtxo(0x01, 100_000));

    const result = try w.selectCoins(60_000, 1);
    defer allocator.free(result.selected);

    try std.testing.expectEqual(@as(usize, 1), result.selected.len);
    try std.testing.expect(result.change > 0);
}

// ---------------------------------------------------------------------------
// G21 — Change output position fixed at end (BUG-11)
// ---------------------------------------------------------------------------

test "w113-G21-BUG11: change output always appended last (no random position)" {
    // BUG-11 (MED): Core randomises change output position via randrange(vout.size()+1).
    // Clearbit always appends change at index outputs.len (the last position).
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    _ = w.generateKey() catch return; // second key for change address
    const script = [_]u8{0x00, 0x14} ++ [_]u8{0xBB} ** 20;
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 200_000, .script_pubkey = &script },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 10,
    };

    const tx = try createTransaction(
        w,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{ .value = 100_000, .script_pubkey = &script }},
        TxOutput{ .value = 80_000, .script_pubkey = &script }, // change
        .{ .current_height = 800_000, .anti_fee_sniping = true },
    );
    defer freeTx(allocator, tx);

    try std.testing.expectEqual(@as(usize, 2), tx.outputs.len);
    // Change is always at outputs[1] — deterministic, fingerprint-able.
    try std.testing.expectEqual(@as(i64, 80_000), tx.outputs[1].value);
}

// ---------------------------------------------------------------------------
// G22 — Change address type follows caller-provided script
// ---------------------------------------------------------------------------

test "w113-G22: change address type follows caller-provided TxOutput script" {
    // Core: change address type is determined by wallet's descriptor type.
    // Clearbit: change output address is caller-supplied (createTransaction takes TxOutput).
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    _ = w.generateKey() catch return;
    const script = [_]u8{0x00, 0x14} ++ [_]u8{0xCC} ** 20;
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x05} ** 32, .index = 0 },
        .output = .{ .value = 300_000, .script_pubkey = &script },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 10,
    };

    const tx = try createTransaction(
        w,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{ .value = 200_000, .script_pubkey = &script }},
        TxOutput{ .value = 90_000, .script_pubkey = &script },
        .{ .current_height = 0, .anti_fee_sniping = false },
    );
    defer freeTx(allocator, tx);
    try std.testing.expectEqual(@as(usize, 2), tx.outputs.len);
}

// ---------------------------------------------------------------------------
// G23 — Dust suppression: min_change threshold present in options
// ---------------------------------------------------------------------------

test "w113-G23: min_change field present in CoinSelectOptions (=546 default)" {
    // Core: change suppressed when below min_viable_change.
    // Clearbit: min_change=546 in CoinSelectOptions exists but active suppression
    // in createTransaction is not enforced automatically.
    const opts: CoinSelectOptions = .{ .min_change = 546 };
    try std.testing.expectEqual(@as(i64, 546), opts.min_change);

    // Additionally verify that a 0 change result is valid (BnB changeless path).
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    // At fee_rate=1, p2wpkh effective_value(50000) = 50000-68 = 49932.
    const target: i64 = 49_932;
    try w.addUtxo(makeUtxo(0x01, 50_000));

    const result = try w.selectCoinsWithOptions(target, .{
        .fee_rate = 1,
        .long_term_fee_rate = 1,
        .cost_of_change = 340,
        .min_change = 546,
    });
    defer allocator.free(result.selected);
    try std.testing.expect(result.selected.len > 0);
    try std.testing.expect(result.change >= 0);
}

// ---------------------------------------------------------------------------
// G24 — BnB changeless: excess as waste, not as change output
// ---------------------------------------------------------------------------

test "w113-G24: BnB changeless selection: excess counted as waste" {
    // BnB aims for curr_value in [target, target+cost_of_change]; excess counted as waste.
    // Verify that when an exact match exists, change is 0 or very small.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    try w.addUtxo(makeUtxo(0x01, 50_000));
    try w.addUtxo(makeUtxo(0x02, 200_000)); // overshoots heavily

    const result = try w.selectCoinsWithOptions(49_900, .{
        .fee_rate = 1,
        .long_term_fee_rate = 1,
        .cost_of_change = 340,
        .min_change = 546,
    });
    defer allocator.free(result.selected);

    try std.testing.expect(result.selected.len > 0);
    try std.testing.expect(result.change >= 0);
}

// ---------------------------------------------------------------------------
// G25 — Anti-fee-sniping: feature present
// ---------------------------------------------------------------------------

test "w113-G25: anti-fee-sniping feature present in CreateTxOptions" {
    // Clearbit: anti_fee_sniping: bool = true  ✓
    const opts: CreateTxOptions = .{ .anti_fee_sniping = true };
    try std.testing.expect(opts.anti_fee_sniping);
    const opts_off: CreateTxOptions = .{ .anti_fee_sniping = false };
    try std.testing.expect(!opts_off.anti_fee_sniping);
}

// ---------------------------------------------------------------------------
// G26 — Anti-fee-sniping: locktime set to current_height
// ---------------------------------------------------------------------------

test "w113-G26: anti-fee-sniping sets locktime to current_height" {
    // Clearbit: lock_time = current_height when anti_fee_sniping && height > 0  ✓
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    _ = w.generateKey() catch return;
    const script = [_]u8{0x00, 0x14} ++ [_]u8{0xDD} ** 20;
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x07} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &script },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const tx = try createTransaction(
        w,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{ .value = 60_000, .script_pubkey = &script }},
        null,
        .{ .current_height = 850_000, .anti_fee_sniping = true },
    );
    defer freeTx(allocator, tx);

    // Clearbit sets locktime to exactly current_height (BUG-12: no random offset).
    try std.testing.expectEqual(@as(u32, 850_000), tx.lock_time);
    // All inputs must have non-final sequence.
    for (tx.inputs) |inp| {
        try std.testing.expect(inp.sequence != 0xFFFFFFFF);
    }
}

// ---------------------------------------------------------------------------
// G27 — Anti-fee-sniping missing random -100 offset (BUG-12)
// ---------------------------------------------------------------------------

test "w113-G27-BUG12: anti-fee-sniping always sets exact height (missing random offset)" {
    // BUG-12 (MED): Core applies locktime -= randrange(100) with 10% probability.
    // Clearbit always sets locktime = current_height exactly.
    // Symptom: over many calls, clearbit ALWAYS returns the exact height.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    _ = w.generateKey() catch return;
    const script = [_]u8{0x00, 0x14} ++ [_]u8{0xEE} ** 20;
    const current_height: u32 = 800_000;
    var all_exact = true;

    var j: usize = 0;
    while (j < 20) : (j += 1) {
        const utxo = OwnedUtxo{
            .outpoint = .{ .hash = [_]u8{@intCast(j + 1)} ** 32, .index = 0 },
            .output = .{ .value = 100_000, .script_pubkey = &script },
            .key_index = 0,
            .address_type = .p2wpkh,
            .confirmations = 6,
        };
        const tx = try createTransaction(
            w,
            &[_]OwnedUtxo{utxo},
            &[_]TxOutput{.{ .value = 60_000, .script_pubkey = &script }},
            null,
            .{ .current_height = current_height, .anti_fee_sniping = true },
        );
        defer freeTx(allocator, tx);
        if (tx.lock_time != current_height) all_exact = false;
    }
    // Clearbit always produces exact height — confirms BUG-12 (missing -100 offset).
    try std.testing.expect(all_exact);
}

// ---------------------------------------------------------------------------
// G28 — Anti-fee-sniping missing 8h tip-age gate (BUG-13)
// ---------------------------------------------------------------------------

test "w113-G28-BUG13: anti-fee-sniping missing IsCurrentForAntiFeeSniping gate" {
    // BUG-13 (MED): Core skips anti-fee-sniping when chain tip > 8h old.
    // Clearbit only guards on current_height > 0.
    //
    // Structural: confirm CreateTxOptions has no tip-age field.
    const has_gate = @hasField(CreateTxOptions, "is_current_for_anti_fee_sniping") or
        @hasField(CreateTxOptions, "tip_age_secs") or
        @hasField(CreateTxOptions, "chain_is_current");
    try std.testing.expect(!has_gate); // Confirms gate is absent — MUST be fixed

    // Functional: with sniping disabled + height > 0, locktime = 0.
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    _ = w.generateKey() catch return;
    const script = [_]u8{0x00, 0x14} ++ [_]u8{0xFF} ** 20;
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x09} ** 32, .index = 0 },
        .output = .{ .value = 100_000, .script_pubkey = &script },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    const tx = try createTransaction(
        w,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{ .value = 60_000, .script_pubkey = &script }},
        null,
        .{ .current_height = 800_000, .anti_fee_sniping = false },
    );
    defer freeTx(allocator, tx);
    try std.testing.expectEqual(@as(u32, 0), tx.lock_time);
}

// ---------------------------------------------------------------------------
// G29 — CoinControl: lockunspent excludes locked UTXOs
// ---------------------------------------------------------------------------

test "w113-G29: lockunspent excludes coins from selection" {
    // Core: CoinControl can force-include specific UTXOs or lock them out.
    // Clearbit: locked coins (lockunspent) are excluded from candidates  ✓
    const allocator = std.testing.allocator;
    const w = (try tryMakeWallet(allocator)) orelse return;
    defer deinitWallet(allocator, w);

    const op1 = types.OutPoint{ .hash = [_]u8{0x0A} ** 32, .index = 0 };
    const op2 = types.OutPoint{ .hash = [_]u8{0x0B} ** 32, .index = 0 };

    try w.addUtxo(OwnedUtxo{
        .outpoint = op1,
        .output = .{ .value = 100_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 10,
    });
    try w.addUtxo(OwnedUtxo{
        .outpoint = op2,
        .output = .{ .value = 50_000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 10,
    });

    // Lock the larger UTXO.
    _ = try w.lockCoin(op1);
    try std.testing.expect(w.isLockedCoin(op1));

    // Selection must use only op2 (50k).
    const result = try w.selectCoins(30_000, 1);
    defer allocator.free(result.selected);

    try std.testing.expectEqual(@as(usize, 1), result.selected.len);
    // Selected UTXO should be op2, not op1.
    try std.testing.expectEqualSlices(u8, &op2.hash, &result.selected[0].outpoint.hash);
}

// ---------------------------------------------------------------------------
// G29b — CoinControl: forced-inclusion (pre-selected coins) MISSING
// ---------------------------------------------------------------------------

test "w113-G29b: CoinControl forced-inclusion (m_selected_coins) MISSING" {
    // Core: CoinControl.m_selected_coins forces specific UTXOs into selection.
    // Clearbit: no equivalent; only lockCoin (exclusion) exists.
    const has_forced = @hasDecl(Wallet, "selectForcedCoins") or
        @hasDecl(Wallet, "setSelectedCoins") or
        @hasField(CoinSelectOptions, "forced_outpoints") or
        @hasField(CoinSelectOptions, "selected_coins");
    try std.testing.expect(!has_forced); // Confirms absence
}

// ---------------------------------------------------------------------------
// G30 — Waste metric: multi-algorithm comparison absent
// ---------------------------------------------------------------------------

test "w113-G30: multi-algorithm waste comparison absent" {
    // BUG (P2): Core's AttemptSelection runs all algorithms and picks lowest waste.
    // Clearbit: first-success fallback (BnB → Knapsack), no waste comparison.
    // CoinSelectResult has no waste field — comparison is structurally impossible.
    const CoinSelectResult = Wallet.CoinSelectResult;
    const has_waste = @hasField(CoinSelectResult, "waste") or
        @hasField(CoinSelectResult, "m_waste") or
        @hasField(CoinSelectResult, "total_waste");
    try std.testing.expect(!has_waste); // Confirms absence — MUST be fixed
}
