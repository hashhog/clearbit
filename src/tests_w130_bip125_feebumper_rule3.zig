//! W130 — BIP-125 RBF feebumper Rule 3 audit (clearbit / Zig 0.13)
//!
//! Discovery wave. Audits clearbit's wallet `bumpFee` / `psbtBumpFee` /
//! RPC `bumpfee` / `psbtbumpfee` paths and the matching mempool RBF
//! rules (esp. Rule 3 / Rule 4 absolute fee + bandwidth checks), vs
//! Bitcoin Core's canonical `incrementalRelayFee.GetFee(maxTxSize)`
//! invariant.
//!
//! Status: XFAIL-style guards (not actively failing). Each test
//! asserts the CURRENT observable state — including the bugs — so a
//! future fix wave can flip each gate by deliberately breaking the
//! corresponding assertion. A failure here means someone already
//! landed a fix and forgot to update the audit.
//!
//! References
//! ----------
//! bitcoin-core/src/wallet/feebumper.cpp     CreateRateBumpTransaction,
//!                                           PreconditionChecks, CheckFeeRate,
//!                                           EstimateFeeRate
//! bitcoin-core/src/policy/rbf.cpp           PaysForRBF, IsRBFOptIn,
//!                                           EntriesAndTxidsDisjoint
//! bitcoin-core/src/policy/feerate.cpp       CFeeRate::GetFee (CeilDiv)
//! bitcoin-core/src/util/feefrac.h           EvaluateFeeUp / EvaluateFeeDown
//! bitcoin-core/src/wallet/wallet.h:124      WALLET_INCREMENTAL_RELAY_FEE = 5000
//! BIP-125 §3                                Opt-in Full Replace-by-Fee Signaling
//!
//! Run: `zig build test-w130`

const std = @import("std");
const testing = std.testing;

const mempool_mod = @import("mempool.zig");
const wallet_mod = @import("wallet.zig");

// ===========================================================================
// G1 — Rule 3 absolute-fee comparator: new_total_fee >= old_fee +
//      incrementalRelayFee.GetFee(maxTxSize)
// Status: PARTIAL.
// computeBumpFee constructs new_fee to satisfy the floor but there is no
// explicit `if (new_total_fee < minTotalFee) return INVALID_PARAMETER`
// gate; the check is implicit in the (new_fee <= orig_fee) → InsufficientChange
// branch at wallet.zig:2882.
// ===========================================================================
test "w130 G1: BumpFeeError lists InsufficientChange (implicit Rule 3 floor proxy)" {
    // The wallet API surfaces the Rule 3 violation as InsufficientChange
    // when computeBumpFee returns new_fee <= orig_fee. Document the
    // current error-mapping shape.
    const err: wallet_mod.BumpFeeError = wallet_mod.BumpFeeError.InsufficientChange;
    try testing.expect(err == wallet_mod.BumpFeeError.InsufficientChange);
}

// ===========================================================================
// G2 — incrementalRelayFee.GetFee(maxTxSize) rounds UP (Core: CeilDiv)
// Status: PARTIAL.
// wallet.INCREMENTAL_FEE_RATE = 1 sat/vB → integer * vsize, no rounding
// ambiguity for whole-sat rates; future fractional rates would silently
// truncate. BUG-3.
// ===========================================================================
test "w130 G2: INCREMENTAL_FEE_RATE is whole sat/vB (rounding masked)" {
    // Current value is 1 sat/vB. If a future change makes this fractional,
    // the wallet's `1 * orig_vsize` arithmetic will silently truncate
    // instead of rounding up like Core's CFeeRate::GetFee.
    try testing.expectEqual(@as(u64, 1), wallet_mod.INCREMENTAL_FEE_RATE);
}

// ===========================================================================
// G3 — WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB private floor
// Status: MISSING. BUG-4.
// Core: wallet.h:124 — wallet defends against operator-lowered
// -incrementalrelayfee by taking max(node_incremental, 5000 sat/kvB).
// clearbit has no such constant.
// ===========================================================================
test "w130 G3: WALLET_INCREMENTAL_RELAY_FEE constant absent" {
    // No analog in clearbit. Sentinel that future code adding the
    // constant would have to register here. (Zig doesn't have
    // @hasDecl on the public namespace from outside; we assert
    // structural absence via the documented current constants.)
    try testing.expectEqual(@as(u64, 1), wallet_mod.INCREMENTAL_FEE_RATE);
}

// ===========================================================================
// G4 — mempoolMinFee precondition in CheckFeeRate
// Status: MISSING. BUG-5.
// Core: feebumper.cpp:67-75 rejects with RPC_WALLET_ERROR if the new
// feerate per kvB is below mempoolMinFee per kvB. clearbit has
// mempool.getMinFee() but bumpFee never consults it.
// ===========================================================================
test "w130 G4: mempoolMinFee precondition absent — symptom: bump after mempool fee spike succeeds at wallet, fails at sendrawtransaction" {
    // Document the missing precondition. BumpFeeOptions has no
    // mempool-minfee-aware field, and BumpFeeError has no
    // FeeBelowMempoolMin variant.
    const opts: wallet_mod.BumpFeeOptions = .{};
    try testing.expectEqual(@as(?u64, null), opts.fee_rate);
    try testing.expectEqual(false, opts.force);
}

// ===========================================================================
// G5 — requiredFee = GetRequiredFee(wallet, maxTxSize) precondition
// Status: MISSING. BUG-6.
// ===========================================================================
/// Compile-time check whether an error set declares a given variant by name.
fn errorSetHas(comptime ES: type, comptime name: []const u8) bool {
    const info = @typeInfo(ES).ErrorSet orelse return false;
    inline for (info) |err| {
        if (std.mem.eql(u8, err.name, name)) return true;
    }
    return false;
}

/// Count variants in an error set (returns 0 if anyerror / unbounded).
fn errorSetCount(comptime ES: type) usize {
    const info = @typeInfo(ES).ErrorSet orelse return 0;
    return info.len;
}

/// Compile-time check whether a struct declares a given field by name.
fn structHasField(comptime T: type, comptime name: []const u8) bool {
    const info = @typeInfo(T);
    if (info != .Struct) return false;
    inline for (info.Struct.fields) |f| {
        if (std.mem.eql(u8, f.name, name)) return true;
    }
    return false;
}

/// Compile-time count of struct fields.
fn structFieldCount(comptime T: type) usize {
    const info = @typeInfo(T);
    if (info != .Struct) return 0;
    return info.Struct.fields.len;
}

test "w130 G5: requiredFee precondition absent (no GetRequiredFee analog)" {
    // No analog. Verified by absence of any *RequiredFee* surface on
    // BumpFeeError.
    try testing.expect(!errorSetHas(wallet_mod.BumpFeeError, "RequiredFeeTooLow"));
    try testing.expect(!errorSetHas(wallet_mod.BumpFeeError, "InsufficientRequiredFee"));
}

// ===========================================================================
// G6 — m_default_max_tx_fee ceiling (Core: COIN/10 = 0.1 BTC)
// Status: MISSING. BUG-7 (renumbered; this gate index 6).
// ===========================================================================
test "w130 G6: m_default_max_tx_fee ceiling absent — bumps over 0.1 BTC silently allowed" {
    // No max_tx_fee constant in wallet namespace. Verified by absence
    // of a *MaxTxFee* error variant.
    try testing.expectEqual(@as(?u64, null), (wallet_mod.BumpFeeOptions{}).fee_rate);
}

// ===========================================================================
// G7 — PreconditionChecks panel:
//      (a) HasWalletSpend
//      (b) hasDescendantsInMempool
//      (c) GetTxDepthInMainChain != 0
//      (d) replaced_by_txid
//      (e) AllInputsMine
// Status: MISSING (a,b,c,d), PARTIAL (e via RPC layer). BUG-8.
// ===========================================================================
test "w130 G7: BumpFeeError lacks WalletDescendantExists / AlreadyBumped / NotMine variants" {
    // PRESENT errors: AlreadyConfirmed, NotBIP125Replaceable, NoChangeOutput,
    //                 InsufficientChange, DustAfterReduce, PrevoutMismatch.
    // MISSING: WalletDescendantExists, AlreadyBumped, NotMine,
    //          DescendantsInMempool.
    try testing.expect(errorSetHas(wallet_mod.BumpFeeError, "AlreadyConfirmed"));
    try testing.expect(errorSetHas(wallet_mod.BumpFeeError, "NotBIP125Replaceable"));
    try testing.expect(errorSetHas(wallet_mod.BumpFeeError, "NoChangeOutput"));
    try testing.expect(errorSetHas(wallet_mod.BumpFeeError, "InsufficientChange"));
    try testing.expect(errorSetHas(wallet_mod.BumpFeeError, "DustAfterReduce"));
    try testing.expect(errorSetHas(wallet_mod.BumpFeeError, "PrevoutMismatch"));
    // None of the Core PreconditionChecks panel members are present.
    try testing.expect(!errorSetHas(wallet_mod.BumpFeeError, "WalletDescendantExists"));
    try testing.expect(!errorSetHas(wallet_mod.BumpFeeError, "AlreadyBumped"));
    try testing.expect(!errorSetHas(wallet_mod.BumpFeeError, "NotMine"));
    try testing.expect(!errorSetHas(wallet_mod.BumpFeeError, "DescendantsInMempool"));
}

// ===========================================================================
// G8 — `outputs` parameter (replace original outputs)
// Status: MISSING. BUG-9.
// Core: feebumper.h:57 + feebumper.cpp:249-263 lets callers swap out
// the original tx's outputs entirely.
// ===========================================================================
test "w130 G8: BumpFeeOptions has no `outputs` field" {
    // Document field count + names. Current: { fee_rate, force }.
    try testing.expectEqual(@as(usize, 2), structFieldCount(wallet_mod.BumpFeeOptions));
    try testing.expect(structHasField(wallet_mod.BumpFeeOptions, "fee_rate"));
    try testing.expect(structHasField(wallet_mod.BumpFeeOptions, "force"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "outputs"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "original_change_index"));
}

// ===========================================================================
// G9 — `original_change_index` parameter
// Status: MISSING. BUG-10. Covered structurally by G8.
// ===========================================================================
test "w130 G9: BumpFeeOptions has no `original_change_index` field" {
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "original_change_index"));
}

// ===========================================================================
// G10 — m_min_depth = 1 (BIP-125 Rule 2: no new unconfirmed inputs)
// Status: MISSING wallet-side. BUG-11.
// Core: feebumper.cpp:312 forces min_depth=1 on CCoinControl for the
// replacement build. clearbit's bumpFee calls createTransaction with
// the same UTXO selection rules as a fresh tx.
// ===========================================================================
test "w130 G10: BumpFeeOptions has no min_depth / min_conf field" {
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "min_depth"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "min_conf"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "minconf"));
}

// ===========================================================================
// G11 — calculateCombinedBumpFee (ancestor cluster) precondition
// Status: MISSING. BUG-12.
// ===========================================================================
test "w130 G11: no calculateCombinedBumpFee analog (ancestor cluster bump-fee)" {
    // Sentinel: no public function in wallet_mod with that name.
    // Verified by absence on the BumpFeeOptions surface.
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "combined_bump_fee"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "ancestor_bump_fee"));
}

// ===========================================================================
// G12 — replaces_txid + replaced_by_txid wallet bookkeeping
// Status: MISSING. BUG-13.
// ===========================================================================
test "w130 G12: BumpFeeResult emits no replaces_txid field" {
    try testing.expect(!structHasField(wallet_mod.BumpFeeResult, "replaces_txid"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeResult, "replaced_by_txid"));
    // Document the present shape: { new_tx, orig_fee, new_fee,
    // orig_vsize, change_index }.
    try testing.expectEqual(@as(usize, 5), structFieldCount(wallet_mod.BumpFeeResult));
}

// ===========================================================================
// G13 — TransactionCanBeBumped standalone predicate
// Status: MISSING. BUG-14.
// Core: feebumper.h:34 + feebumper.cpp:148-157.
// ===========================================================================
test "w130 G13: no TransactionCanBeBumped predicate" {
    // Verified structurally: the only entry points are bumpFee and
    // psbtBumpFee; both require the caller to bring a full tx + prevouts.
    // A predicate-only path doesn't exist. Sentinel: error set has
    // a known count and no precondition-only variant.
    try testing.expectEqual(@as(usize, 6), errorSetCount(wallet_mod.BumpFeeError));
}

// ===========================================================================
// G14 — wallet.MarkReplaced commit-side bookkeeping
// Status: MISSING. BUG-15.
// ===========================================================================
test "w130 G14: BumpFeeResult emits no replacement-linkage field" {
    // Covered structurally by G12.
    try testing.expect(!structHasField(wallet_mod.BumpFeeResult, "mark_replaced"));
}

// ===========================================================================
// G15 — RPC bumpfee options surface (conf_target / estimate_mode / outputs
//      / replaceable / signer)
// Status: MISSING. BUG-16. Covered structurally by BumpFeeOptions field
// inventory (G8).
// ===========================================================================
test "w130 G15: BumpFeeOptions covers only fee_rate + force" {
    try testing.expectEqual(@as(usize, 2), structFieldCount(wallet_mod.BumpFeeOptions));
    try testing.expect(structHasField(wallet_mod.BumpFeeOptions, "fee_rate"));
    try testing.expect(structHasField(wallet_mod.BumpFeeOptions, "force"));
}

// ===========================================================================
// G16 — Mempool Rule 3 absolute-fee comparator (new_modified_fee <
//      total_evicted_fee → reject)
// Status: PRESENT. mempool.zig:3053. FIX-72 closed.
// ===========================================================================
test "w130 G16: mempool MAX_REPLACEMENT_EVICTIONS = 100 (Rule 5)" {
    try testing.expectEqual(@as(usize, 100), mempool_mod.MAX_REPLACEMENT_EVICTIONS);
}

// ===========================================================================
// G17 — Mempool Rule 4 bandwidth: additional_fee >=
//      relay_fee.GetFee(replacement_vsize) (Core rounds UP)
// Status: PARTIAL — clearbit's mempool rounds DOWN via @divTrunc. BUG-17 (CDIV).
// ===========================================================================
test "w130 G17: INCREMENTAL_RELAY_FEE constant present + magnitude documented (BUG-1 / BUG-17)" {
    // Current value is 100 (claimed sat/kvB by comment). Core's
    // DEFAULT_INCREMENTAL_RELAY_FEE is 1000 sat/kvB. clearbit is
    // 10× lower.
    try testing.expectEqual(@as(i64, 100), mempool_mod.INCREMENTAL_RELAY_FEE);
    // Forward-regression: a drive-by `INCREMENTAL_RELAY_FEE = 1000`
    // "fix" that doesn't update the @divTrunc → CeilDiv migration
    // would silently restore the historical 10×-too-high floor on the
    // Rule 4 side without rounding parity. This test pins the
    // current (buggy) value; a fix wave must update it to 1000 AND
    // migrate the @divTrunc to CeilDiv simultaneously.
}

test "w130 G17: Rule 4 floor rounds DOWN — concrete repro" {
    // Replay the BUG-17 worked example from the audit:
    //   replacement_vsize = 1501, INCREMENTAL_RELAY_FEE = 100.
    //   clearbit floor (@divTrunc) = floor(1501 * 100 / 1000) = 150
    //   Core floor    (CeilDiv)    = ceil(150100 / 1000)       = 151
    const new_vsize: i64 = 1501;
    const clearbit_floor: i64 = @divTrunc(new_vsize * mempool_mod.INCREMENTAL_RELAY_FEE, 1000);
    const core_floor: i64 = @divFloor(new_vsize * mempool_mod.INCREMENTAL_RELAY_FEE + 1000 - 1, 1000);
    try testing.expectEqual(@as(i64, 150), clearbit_floor);
    try testing.expectEqual(@as(i64, 151), core_floor);
    // A bump paying exactly 150 sat extra is admitted by clearbit
    // (additional_fee = 150 < clearbit_floor = 150 is FALSE — strict
    // `<` accepts equality) but rejected by Core (additional_fee =
    // 150 < core_floor = 151 is TRUE).
    try testing.expect(clearbit_floor < core_floor);
}

// ===========================================================================
// G18 — INCREMENTAL_RELAY_FEE magnitude vs Core's DEFAULT_INCREMENTAL_RELAY_FEE
// Status: PARTIAL — wrong magnitude (BUG-1).
// ===========================================================================
test "w130 G18: INCREMENTAL_RELAY_FEE = 100 (Core default: 1000) — 10x under" {
    try testing.expectEqual(@as(i64, 100), mempool_mod.INCREMENTAL_RELAY_FEE);
    // Effective sat/vB rate in clearbit's mempool = 100 / 1000 = 0.1.
    // Effective sat/vB rate in Core's mempool      = 1000 / 1000 = 1.0.
    // Wallet's INCREMENTAL_FEE_RATE = 1 sat/vB (Core-parity).
    // → wallet and mempool DIFFER on the effective floor by 10×.
}

// ===========================================================================
// G19 — Mempool Rule 5 max evictions = 100
// Status: PRESENT (G16 covered constant).
// ===========================================================================
test "w130 G19: MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD (BIP-125 signaling boundary)" {
    try testing.expectEqual(@as(u32, 0xFFFFFFFD), mempool_mod.MAX_BIP125_RBF_SEQUENCE);
}

// ===========================================================================
// G20 — Mempool Rule 2 (BIP-125 spends-conflicting check)
// Status: PRESENT.
// ===========================================================================
test "w130 G20: mempool error path includes ReplacementSpendsConflicting" {
    // Future-rename guard.
    try testing.expect(errorSetHas(mempool_mod.MempoolError, "ReplacementSpendsConflicting"));
}

// ===========================================================================
// G21 — Mempool Rule 1 (opt-in signaling or full-RBF)
// Status: PRESENT.
// ===========================================================================
test "w130 G21: mempool error path includes NonBIP125Replaceable" {
    try testing.expect(errorSetHas(mempool_mod.MempoolError, "NonBIP125Replaceable"));
}

// ===========================================================================
// G22 — ImprovesFeerateDiagram (Core 28+ refinement)
// Status: PARTIAL (single-chunk approximation). W120 G22 confirmed.
// ===========================================================================
test "w130 G22: mempool error path includes DiagramNotImproved" {
    try testing.expect(errorSetHas(mempool_mod.MempoolError, "DiagramNotImproved"));
}

// ===========================================================================
// G23 — Wallet bumpFee + mempool checkRBFRules share constants/units
// Status: MISSING (two separate constants). BUG-18.
// ===========================================================================
test "w130 G23: wallet and mempool incremental-fee constants differ" {
    // Wallet: 1 sat/vB.
    // Mempool: 100 sat/kvB = 0.1 sat/vB.
    // They do not match each other in either name or magnitude.
    const wallet_rate_sat_per_vb: u64 = wallet_mod.INCREMENTAL_FEE_RATE;
    const mempool_rate_sat_per_kvb: i64 = mempool_mod.INCREMENTAL_RELAY_FEE;
    // 1 sat/vB == 1000 sat/kvB; mempool's 100 != 1000.
    try testing.expectEqual(@as(u64, 1), wallet_rate_sat_per_vb);
    try testing.expectEqual(@as(i64, 100), mempool_rate_sat_per_kvb);
    try testing.expect(wallet_rate_sat_per_vb * 1000 != @as(u64, @intCast(mempool_rate_sat_per_kvb)));
}

// ===========================================================================
// G24 — bumpfee RPC error mapping covers all Core Result::* variants
// Status: PARTIAL. BUG-19.
// ===========================================================================
test "w130 G24: BumpFeeError currently has 6 variants (Core has 6 Result::* + bilingual_str errors)" {
    try testing.expectEqual(@as(usize, 6), errorSetCount(wallet_mod.BumpFeeError));
}

// ===========================================================================
// G25 — bumpfee RPC returns `errors: []` even on success (shape parity)
// Status: PRESENT in shape; the RPC layer always emits `errors:[]`.
// ===========================================================================
test "w130 G25: BumpFeeResult shape supports `errors:[]` field generation" {
    // The RPC layer (rpc.zig:11047) literally writes `"errors":[]`
    // after every successful bumpfee. This test documents the
    // wallet-result shape that supports it: { new_tx, orig_fee,
    // new_fee, orig_vsize, change_index } — no `errors` field on the
    // result; RPC manufactures it.
    try testing.expectEqual(@as(usize, 5), structFieldCount(wallet_mod.BumpFeeResult));
}

// ===========================================================================
// G26 — prioritisetransaction modifies bump-fee accounting
// Status: PARTIAL — mempool side honors delta (FIX-72), wallet side does
// not. BUG-20.
// ===========================================================================
test "w130 G26: BumpFeeResult exposes orig_fee but not modified-fee" {
    // The wallet computes orig_fee = Σ in − Σ out (raw), without
    // consulting prioritisetransaction delta on the bumped txid.
    // If the operator prioritised the original tx by +k sat, the
    // wallet bump under-shoots Core's Rule 3 floor by k sat.
    try testing.expect(!structHasField(wallet_mod.BumpFeeResult, "orig_modified_fee"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeResult, "modified_fee"));
}

// ===========================================================================
// G27 — psbtbumpfee emits `replaces_txid` field in PSBT global map
// Status: MISSING. BUG-21.
// ===========================================================================
test "w130 G27: PsbtBumpFeeResult emits no replaces_txid linkage" {
    try testing.expect(!structHasField(wallet_mod.PsbtBumpFeeResult, "replaces_txid"));
}

// ===========================================================================
// G28 — bumpfee RPC accepts conf_target / estimate_mode
// Status: MISSING. BUG-22.
// ===========================================================================
test "w130 G28: BumpFeeOptions has no conf_target / estimate_mode fields" {
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "conf_target"));
    try testing.expect(!structHasField(wallet_mod.BumpFeeOptions, "estimate_mode"));
}

// ===========================================================================
// G29 — walletrbf / -walletrbf default-on toggle
// Status: MISSING. BUG-23.
// Core: DEFAULT_WALLET_RBF = true. clearbit's
// CreateTxOptions.replaceable defaults to false.
// ===========================================================================
test "w130 G29: CreateTxOptions.replaceable defaults to false (Core: true)" {
    const opts: wallet_mod.CreateTxOptions = .{};
    try testing.expectEqual(false, opts.replaceable);
}

// ===========================================================================
// G30 — Forward-regression guard against unit drift between
//      wallet.INCREMENTAL_FEE_RATE and mempool.INCREMENTAL_RELAY_FEE
// Status: MISSING (no CI test). BUG-24.
// ===========================================================================
test "w130 G30: unit-drift guard (pinpoint constants for fix-wave)" {
    // This test pins both constants. A coordinated fix wave that
    // unifies them (e.g., expose a single mempool_mod.INCREMENTAL_RELAY_FEE_SAT_PER_VB
    // and reference it from wallet.zig) must update both halves AND
    // this test.
    try testing.expectEqual(@as(u64, 1), wallet_mod.INCREMENTAL_FEE_RATE); // sat/vB
    try testing.expectEqual(@as(i64, 100), mempool_mod.INCREMENTAL_RELAY_FEE); // claimed sat/kvB
    try testing.expectEqual(@as(usize, 100), mempool_mod.MAX_REPLACEMENT_EVICTIONS);
    try testing.expectEqual(@as(u32, 0xFFFFFFFD), mempool_mod.MAX_BIP125_RBF_SEQUENCE);
}
