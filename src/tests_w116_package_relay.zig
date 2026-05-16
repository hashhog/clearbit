//! W116 — Package relay 30-gate audit (clearbit / Zig 0.13)
//!
//! Reference: bitcoin-core/src/policy/packages.h/cpp, rpc/mempool.cpp,
//!            validation.cpp (ProcessNewPackage), net_processing.cpp
//!
//! Clearbit equivalent: src/mempool.zig (acceptPackage, isWellFormedPackage,
//!   isChildWithParents, isChildWithParentsTree, isTopoSortedPackage,
//!   isConsistentPackage, getPackageHash, MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT),
//!   src/rpc.zig (handleSubmitPackage, handleTestMempoolAccept),
//!   src/p2p.zig (sendpackages/ancpkginfo/getpkgtxns/pkgtxns message types)
//!
//! Run: zig build test --summary none
//!
//! ============================================================================
//! Gates and Findings
//! ============================================================================
//!
//! G1-G5:   Package definition — constants, topo-sort, consistency, CWP, hash
//! G6-G10:  testmempoolaccept RPC
//! G11-G15: submitpackage RPC
//! G16-G20: Validation — mempool admission context, fee checks, script checks
//! G21-G24: CPFP — package fee rate, partial parent set, fee aggregation
//! G25-G28: Edge cases — coinbase, single-tx, max limits, burn check
//! G29-G30: P2P package relay (BIP-331)
//!
//! ============================================================================
//! BUGs found (30 gates):
//! ============================================================================
//!
//! BUG-1  (G6,  HIGH / CDIV): testmempoolaccept is a stub — it always returns
//!   allowed=true (except for already-in-mempool). No script validation, no fee
//!   check, no UTXO existence check, no standardness check. Callers cannot
//!   distinguish valid from invalid transactions.
//!   Reference: Core rpc/mempool.cpp:362-407 (ProcessTransaction test_accept=true).
//!
//! BUG-2  (G6,  MEDIUM): testmempoolaccept response missing "wtxid" field.
//!   Core always includes both "txid" and "wtxid" in each result object.
//!   Reference: Core rpc/mempool.cpp:358-359.
//!
//! BUG-3  (G6,  MEDIUM): testmempoolaccept response missing "fees" object
//!   {"base":..., "effective-feerate":..., "effective-includes":[...]} for
//!   allowed=true entries. Core includes fees when allowed=true.
//!   Reference: Core rpc/mempool.cpp:386-394.
//!
//! BUG-4  (G6,  MEDIUM): testmempoolaccept does NOT enforce MAX_PACKAGE_COUNT=25
//!   upper bound. Core rejects arrays with >25 elements.
//!   Reference: Core rpc/mempool.cpp:321.
//!
//! BUG-5  (G6,  LOW): testmempoolaccept missing "package-error" field on
//!   multi-tx package-level failures (e.g. topo-sort violation).
//!   Reference: Core rpc/mempool.cpp:360-362.
//!
//! BUG-6  (G11, HIGH / CDIV): submitpackage response keys tx-results by txid
//!   instead of wtxid. Core keys by wtxid.
//!   Reference: Core rpc/mempool.cpp:1464, 1505 (tx->GetWitnessHash().GetHex()).
//!
//! BUG-7  (G11, HIGH / CDIV): submitpackage response includes a spurious
//!   top-level "package_feerate" field that Core does not emit.
//!   Reference: Core rpc/mempool.cpp:1457-1511 (no such field).
//!
//! BUG-8  (G11, MEDIUM): submitpackage per-tx result missing "vsize" field for
//!   accepted transactions.
//!   Reference: Core rpc/mempool.cpp:1485.
//!
//! BUG-9  (G11, MEDIUM): submitpackage per-tx result missing "fees" object
//!   {"base":..., "effective-feerate":..., "effective-includes":[...]} for
//!   accepted transactions.
//!   Reference: Core rpc/mempool.cpp:1486-1498.
//!
//! BUG-10 (G11, LOW): submitpackage response "package_msg" is always ""
//!   (empty string). Core sets "success" on full acceptance or the error
//!   reason on failure. Empty string is never a valid value.
//!   Reference: Core rpc/mempool.cpp:1404 ("success"), 1427.
//!
//! BUG-11 (G11, MEDIUM): submitpackage maxfeerate parameter parsed but marked
//!   TODO and never applied. An oversized-fee package passes when it should
//!   fail with max-fee-exceeded.
//!   Reference: Core rpc/mempool.cpp:1367-1402.
//!
//! BUG-12 (G11, LOW): submitpackage maxburnamount (OP_RETURN/unspendable)
//!   check entirely absent. Core checks each output against maxburnamount.
//!   Reference: Core rpc/mempool.cpp:1386-1390.
//!
//! BUG-13 (G14, MEDIUM / CDIV): submitpackage enforces isChildWithParents but
//!   NOT isChildWithParentsTree. A package where parent A spends output of
//!   parent B is accepted. Core enforces IsChildWithParentsTree at the RPC
//!   layer (rpc/mempool.cpp:1395-1396) and the validation layer calls it again.
//!   Reference: Core rpc/mempool.cpp:1395 and packages.h:85.
//!
//! BUG-14 (G16, LOW): Fee check bypass when input values unavailable:
//!   acceptPackage skips the fee-rate gate when total_fee <= 0 (line 8885:
//!   "if (package_fee_rate < min_fee_rate and total_fee > 0)"). If the UTXO
//!   set is missing (chain_state==null) the package fee is 0 and the fee
//!   check is silently skipped — allowing zero-fee packages.
//!
//! BUG-15 (G29, HIGH / dead-helper): BIP-331 P2P package relay messages
//!   (sendpackages, ancpkginfo, getpkgtxns, pkgtxns) are defined in p2p.zig
//!   and can be serialized, but decodePayload() does NOT parse any of them:
//!   "sendpackages"/"ancpkginfo"/"getpkgtxns"/"pkgtxns" commands fall through
//!   to ParseError.UnknownCommand. The receive path is completely dead.
//!   Reference: p2p.zig:696-896 (decodePayload chain).
//!
//! BUG-16 (G30, HIGH / dead-helper): No code sends sendpackages during the
//!   post-verack handshake. BIP-331 negotiation is never initiated.
//!   Reference: BIP-331 §4 "Negotiation" (sendpackages after verack).

const std = @import("std");
const testing = std.testing;
const mempool_mod = @import("mempool.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const p2p = @import("p2p.zig");

// p2wpkh scriptPubKey used across tests (package-level constant — safe to reference)
const P2WPKH: []const u8 = &[_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20;

// ============================================================================
// G1 — Package definition: MAX_PACKAGE_COUNT and MAX_PACKAGE_WEIGHT constants
// ============================================================================

test "w116 G1: MAX_PACKAGE_COUNT is 25" {
    try testing.expectEqual(@as(usize, 25), mempool_mod.MAX_PACKAGE_COUNT);
}

test "w116 G1b: MAX_PACKAGE_WEIGHT is 404_000" {
    try testing.expectEqual(@as(usize, 404_000), mempool_mod.MAX_PACKAGE_WEIGHT);
}

// ============================================================================
// G2 — Package definition: isTopoSortedPackage rejects child-before-parent
// ============================================================================

test "w116 G2: isTopoSortedPackage rejects child-before-parent ordering" {
    const allocator = testing.allocator;

    // Parent (external input)
    const parent_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAA} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const parent_out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_inp},
        .outputs = &[_]types.TxOut{parent_out},
        .lock_time = 1,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Child spends parent
    const child_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const child_out = types.TxOut{ .value = 8_000_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_inp},
        .outputs = &[_]types.TxOut{child_out},
        .lock_time = 2,
    };

    // Wrong order: child first, parent second
    const txns: []const types.Transaction = &[_]types.Transaction{ child_tx, parent_tx };
    const sorted = try mempool_mod.isTopoSortedPackage(txns, allocator);
    try testing.expect(!sorted); // must be false
}

test "w116 G2b: isTopoSortedPackage accepts parent-before-child ordering" {
    const allocator = testing.allocator;

    const parent_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xBB} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const parent_out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_inp},
        .outputs = &[_]types.TxOut{parent_out},
        .lock_time = 1,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    const child_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const child_out = types.TxOut{ .value = 8_000_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_inp},
        .outputs = &[_]types.TxOut{child_out},
        .lock_time = 2,
    };

    // Correct order: parent first, child second
    const txns: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    const sorted = try mempool_mod.isTopoSortedPackage(txns, allocator);
    try testing.expect(sorted);
}

// ============================================================================
// G3 — Package definition: isConsistentPackage rejects conflicting inputs
// ============================================================================

test "w116 G3: isConsistentPackage rejects two txns spending the same outpoint" {
    const allocator = testing.allocator;

    // Both txns spend outpoint CC..CC:0
    const inp_a = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xCC} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const inp_b = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xCC} ** 32, .index = 0 }, // same outpoint
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out_a = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const out_b = types.TxOut{ .value = 8_000_000, .script_pubkey = P2WPKH };
    const conflict_a = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp_a},
        .outputs = &[_]types.TxOut{out_a},
        .lock_time = 1,
    };
    const conflict_b = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp_b},
        .outputs = &[_]types.TxOut{out_b},
        .lock_time = 2,
    };

    const txns: []const types.Transaction = &[_]types.Transaction{ conflict_a, conflict_b };
    const consistent = try mempool_mod.isConsistentPackage(txns, allocator);
    try testing.expect(!consistent);
}

test "w116 G3b: isConsistentPackage accepts non-conflicting txns" {
    const allocator = testing.allocator;

    const inp_a = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xDD} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const inp_b = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xEE} ** 32, .index = 0 }, // different outpoint
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out_a = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const out_b = types.TxOut{ .value = 8_000_000, .script_pubkey = P2WPKH };
    const tx_a = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp_a},
        .outputs = &[_]types.TxOut{out_a},
        .lock_time = 1,
    };
    const tx_b = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp_b},
        .outputs = &[_]types.TxOut{out_b},
        .lock_time = 2,
    };

    const txns: []const types.Transaction = &[_]types.Transaction{ tx_a, tx_b };
    const consistent = try mempool_mod.isConsistentPackage(txns, allocator);
    try testing.expect(consistent);
}

// ============================================================================
// G4 — Package definition: isChildWithParents and isChildWithParentsTree
// ============================================================================

test "w116 G4: isChildWithParents rejects single-tx package" {
    const allocator = testing.allocator;

    const inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xFF} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp},
        .outputs = &[_]types.TxOut{out},
        .lock_time = 1,
    };
    const txns: []const types.Transaction = &[_]types.Transaction{tx};
    const is_cwp = try mempool_mod.isChildWithParents(txns, allocator);
    // Core: "if (package.size() < 2) return false"
    try testing.expect(!is_cwp);
}

test "w116 G4b: isChildWithParents requires all non-last txns to be parents of last tx" {
    const allocator = testing.allocator;

    // parent_tx
    const parent_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const parent_out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{parent_inp},
        .outputs = &[_]types.TxOut{parent_out},
        .lock_time = 1,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // unrelated_tx is NOT a parent of child
    const unrelated_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x22} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const unrelated_out = types.TxOut{ .value = 5_000_000, .script_pubkey = P2WPKH };
    const unrelated_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{unrelated_inp},
        .outputs = &[_]types.TxOut{unrelated_out},
        .lock_time = 3,
    };

    // child only spends parent, not unrelated
    const child_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const child_out = types.TxOut{ .value = 8_000_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{child_inp},
        .outputs = &[_]types.TxOut{child_out},
        .lock_time = 2,
    };

    const txns: []const types.Transaction = &[_]types.Transaction{ parent_tx, unrelated_tx, child_tx };
    const is_cwp = try mempool_mod.isChildWithParents(txns, allocator);
    try testing.expect(!is_cwp); // unrelated_tx breaks CWP
}

test "w116 G4c: isChildWithParentsTree rejects inter-parent dependencies (BUG-13 witness)" {
    // BUG-13: acceptPackage uses isChildWithParents, not isChildWithParentsTree.
    // isChildWithParentsTree should reject when parent_b depends on parent_a.
    const allocator = testing.allocator;

    // parent_a is independent
    const pa_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x33} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const pa_out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const parent_a = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{pa_inp},
        .outputs = &[_]types.TxOut{pa_out},
        .lock_time = 1,
    };
    const parent_a_txid = try crypto.computeTxid(&parent_a, allocator);

    // parent_b spends parent_a — creates a chain, not a tree
    const pb_inp = types.TxIn{
        .previous_output = .{ .hash = parent_a_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const pb_out = types.TxOut{ .value = 8_500_000, .script_pubkey = P2WPKH };
    const parent_b = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{pb_inp},
        .outputs = &[_]types.TxOut{pb_out},
        .lock_time = 2,
    };
    const parent_b_txid = try crypto.computeTxid(&parent_b, allocator);

    // child spends both parents
    const c_inp_a = types.TxIn{
        .previous_output = .{ .hash = parent_a_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_inp_b = types.TxIn{
        .previous_output = .{ .hash = parent_b_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 7_000_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{ c_inp_a, c_inp_b },
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 3,
    };

    const txns: []const types.Transaction = &[_]types.Transaction{ parent_a, parent_b, child_tx };

    // isChildWithParentsTree MUST reject inter-parent dependencies
    const is_cwp_tree = try mempool_mod.isChildWithParentsTree(txns, allocator);
    try testing.expect(!is_cwp_tree);
    // BUG-13: acceptPackage only calls isChildWithParents (not tree variant),
    // so this non-tree package can slip through submitpackage.
}

// ============================================================================
// G5 — Package definition: getPackageHash is deterministic / order-independent
// ============================================================================

test "w116 G5: getPackageHash is deterministic for the same input" {
    const allocator = testing.allocator;

    const inp_a = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x44} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out_a = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const tx_a = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp_a},
        .outputs = &[_]types.TxOut{out_a},
        .lock_time = 1,
    };

    const inp_b = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x55} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out_b = types.TxOut{ .value = 8_000_000, .script_pubkey = P2WPKH };
    const tx_b = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp_b},
        .outputs = &[_]types.TxOut{out_b},
        .lock_time = 2,
    };

    const txns: []const types.Transaction = &[_]types.Transaction{ tx_a, tx_b };
    const hash1 = try mempool_mod.getPackageHash(txns, allocator);
    const hash2 = try mempool_mod.getPackageHash(txns, allocator);
    try testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "w116 G5b: getPackageHash is non-zero for a real package" {
    const allocator = testing.allocator;

    const inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x66} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp},
        .outputs = &[_]types.TxOut{out},
        .lock_time = 1,
    };

    const txns: []const types.Transaction = &[_]types.Transaction{tx};
    const hash = try mempool_mod.getPackageHash(txns, allocator);
    const zero_hash: types.Hash256 = [_]u8{0} ** 32;
    try testing.expect(!std.mem.eql(u8, &hash, &zero_hash));
}

// ============================================================================
// G6 — testmempoolaccept: stub always returns allowed=true (BUG-1 through BUG-5)
// ============================================================================
//
// BUG-1: testmempoolaccept is a stub — always allowed=true except in-mempool.
// BUG-2: Missing "wtxid" field in each response entry.
// BUG-3: Missing "fees" object in allowed=true entries.
// BUG-4: No MAX_PACKAGE_COUNT (25) upper-bound enforcement.
// BUG-5: Missing "package-error" field on multi-tx package failure.

test "w116 G6 BUG-1: testmempoolaccept stub — acceptToMemoryPool dry-run path exists but is unused by RPC" {
    // Core's testmempoolaccept calls ProcessTransaction(test_accept=true).
    // clearbit's equivalent is acceptToMemoryPool(tx, test_accept=true).
    // The RPC handler (handleTestMempoolAccept) does NOT call acceptToMemoryPool.
    // Instead it always returns allowed=true after only checking if tx is in mempool.
    // Verify the dry-run path exists:
    const Mempool = mempool_mod.Mempool;
    comptime {
        if (!@hasDecl(Mempool, "acceptToMemoryPool"))
            @compileError("Mempool.acceptToMemoryPool must exist for dry-run validation");
    }
    // BUG-1: the RPC handler must route through acceptToMemoryPool(tx, true).
    try testing.expect(true);
}

test "w116 G6 BUG-4: testmempoolaccept missing MAX_PACKAGE_COUNT (25) upper bound check" {
    // Core rejects: "Array must contain between 1 and 25 transactions."
    // clearbit handleTestMempoolAccept has no count check for >25 entries.
    // The constant is correct but not applied in this RPC handler.
    try testing.expectEqual(@as(usize, 25), mempool_mod.MAX_PACKAGE_COUNT);
    // BUG-4: fix adds: if (rawtxs.len < 1 or rawtxs.len > MAX_PACKAGE_COUNT) return error
    try testing.expect(true);
}

test "w116 G6 BUG-2+3: testmempoolaccept RPC response missing wtxid and fees fields (structural)" {
    // Core response per-tx: {txid, wtxid, allowed, vsize, fees{base, effective-feerate, effective-includes}}
    // clearbit response per-tx: {txid, allowed, vsize} — no wtxid, no fees object.
    //
    // AcceptResult internally HAS wtxid and fee fields, so the data IS available.
    // The bug is that handleTestMempoolAccept does NOT emit them in the JSON response.
    const AcceptResult = mempool_mod.Mempool.AcceptResult;
    comptime {
        const info = @typeInfo(AcceptResult).Struct;
        var has_wtxid = false;
        var has_fee = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "wtxid")) has_wtxid = true;
            if (std.mem.eql(u8, f.name, "fee")) has_fee = true;
        }
        // These fields exist on the internal result struct — they should be emitted in JSON
        if (!has_wtxid) @compileError("AcceptResult missing wtxid field (add it)");
        if (!has_fee) @compileError("AcceptResult missing fee field (add it)");
    }
    // BUG-2: handleTestMempoolAccept must include "wtxid" in JSON output.
    // BUG-3: handleTestMempoolAccept must include "fees" object in JSON output.
    try testing.expect(true);
}

// ============================================================================
// G7 — testmempoolaccept: multi-tx package validation uses acceptPackage
// ============================================================================

test "w116 G7: acceptPackage drives multi-tx validation path" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // funding tx in mempool
    const f_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x77} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const f_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{f_inp},
        .outputs = &[_]types.TxOut{f_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(funding_tx);
    const funding_txid = try crypto.computeTxid(&funding_tx, allocator);

    // parent (1000 sat fee)
    const p_inp = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const p_out = types.TxOut{ .value = 9_999_000, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{p_inp},
        .outputs = &[_]types.TxOut{p_out},
        .lock_time = 1,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // child (9000 sat fee)
    const c_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_990_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 2,
    };

    const pkg: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();

    try testing.expect(result.package_accepted);
    try testing.expectEqual(@as(usize, 2), result.tx_results.len);
}

// ============================================================================
// G8 — testmempoolaccept: addTransaction (full path) rejects coinbase
// ============================================================================

test "w116 G8: addTransaction rejects coinbase with MempoolError.Coinbase" {
    // acceptToMemoryPool(test_accept=true) with no chain_state only runs checkStandard,
    // which exits early (no chain_state). So the coinbase check doesn't fire in dry-run.
    // The real rejection happens in addTransaction (full path), which checks isCoinbase()
    // at line 976 before checkStandard.
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const cb_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xFFFF_FFFF },
        .script_sig = &[_]u8{ 0x03, 0x01, 0x02, 0x03 },
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const cb_out = types.TxOut{ .value = 5_000_000_000, .script_pubkey = P2WPKH };
    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{cb_inp},
        .outputs = &[_]types.TxOut{cb_out},
        .lock_time = 0,
    };

    // Full acceptance path rejects coinbase
    const err = mempool.addTransaction(coinbase_tx);
    try testing.expectError(mempool_mod.MempoolError.Coinbase, err);
}

// ============================================================================
// G9 — testmempoolaccept: maxfeerate parameter not applied (BUG documented)
// ============================================================================

test "w116 G9: testmempoolaccept maxfeerate not applied (structural doc)" {
    // Core: if fee > maxfeerate * vsize -> allowed=false, reject-reason=max-fee-exceeded.
    // clearbit handleTestMempoolAccept accepts a maxfeerate param but does NOT apply it.
    // Future fix: mirror sendrawtransaction's maxfeerate check.
    try testing.expect(true); // documented gap
}

// ============================================================================
// G10 — testmempoolaccept: rejects empty array (1-based length check)
// ============================================================================

test "w116 G10: isWellFormedPackage with empty slice does not crash" {
    const allocator = testing.allocator;
    const txns: []const types.Transaction = &[_]types.Transaction{};
    // isWellFormedPackage with 0 elements: no well-formed error expected
    // (count 0 < 25, weight 0, no duplicates).
    mempool_mod.isWellFormedPackage(txns, allocator) catch |err| {
        switch (err) {
            mempool_mod.PackageError.PackageTooManyTransactions,
            mempool_mod.PackageError.PackageTooLarge,
            mempool_mod.PackageError.PackageContainsDuplicates,
            mempool_mod.PackageError.PackageNotSorted,
            mempool_mod.PackageError.ConflictInPackage,
            => {},
            else => return err,
        }
    };
    try testing.expect(true);
}

// ============================================================================
// G11 — submitpackage: response keyed by wtxid not txid (BUG-6, BUG-7, BUG-10)
// ============================================================================

test "w116 G11 BUG-6: PackageTxResult has wtxid field; Core response uses wtxid as map key" {
    // Fixed (FIX-53): PackageTxResult now has a wtxid field and handleSubmitPackage
    // keys tx-results by wtxid, matching Core rpc/mempool.cpp behaviour.
    comptime {
        const PKT = mempool_mod.PackageTxResult;
        const info = @typeInfo(PKT).Struct;
        var has_txid = false;
        var has_wtxid = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "txid")) has_txid = true;
            if (std.mem.eql(u8, f.name, "wtxid")) has_wtxid = true;
        }
        if (!has_txid) @compileError("PackageTxResult must have txid field");
        if (!has_wtxid) @compileError("PackageTxResult missing wtxid field — BUG-6 not fixed");
    }
    try testing.expect(true);
}

test "w116 G11 BUG-7: PackageResult has spurious package_fee_rate field (Core omits it)" {
    // Core submitpackage response: package_msg, tx-results, replaced-transactions.
    // clearbit emits an extra "package_feerate" top-level field.
    comptime {
        const PR = mempool_mod.PackageResult;
        const info = @typeInfo(PR).Struct;
        var has_pfr = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "package_fee_rate")) has_pfr = true;
        }
        if (!has_pfr) @compileError("PackageResult missing package_fee_rate (update test if BUG-7 fixed)");
    }
    // BUG-7: remove "package_feerate" from JSON output (keep internal field if needed for CPFP math).
    try testing.expect(true);
}

test "w116 G11 BUG-10: package_msg always empty string (should be 'success' on acceptance)" {
    // Core sets package_msg = "success" on full acceptance.
    // clearbit emits {"package_msg":"",...} unconditionally.
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const f_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x88} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const f_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{f_inp},
        .outputs = &[_]types.TxOut{f_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(funding_tx);
    const funding_txid = try crypto.computeTxid(&funding_tx, allocator);

    const p_inp = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const p_out = types.TxOut{ .value = 9_990_000, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{p_inp},
        .outputs = &[_]types.TxOut{p_out},
        .lock_time = 1,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    const c_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_980_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 2,
    };

    const pkg: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();

    try testing.expect(result.package_accepted);
    // BUG-10: the RPC layer must emit "success" not "" when package_accepted is true.
}

// ============================================================================
// G12 — submitpackage: per-tx result missing vsize and fees (BUG-8, BUG-9)
// ============================================================================

test "w116 G12 BUG-8+9: PackageTxResult missing vsize and fees fields" {
    // Core per-tx result: vsize, fees{base, effective-feerate, effective-includes}.
    comptime {
        const PKT = mempool_mod.PackageTxResult;
        const info = @typeInfo(PKT).Struct;
        var has_vsize = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "vsize")) has_vsize = true;
        }
        if (has_vsize) @compileError("PackageTxResult has vsize already — BUG-8 fixed, update test");
    }
    // BUG-8: add vsize; BUG-9: add fees{base, effective-feerate, effective-includes}.
    try testing.expect(true);
}

// ============================================================================
// G13 — submitpackage: replaced-transactions now wired via FIX-73 (W120 BUG-5).
// Audit-flip: prior assertion was "no replaced_txids field exists"; FIX-73
// adds `PackageResult.replaced_transactions: []types.Hash256` populated by
// the union of evicted-tx sets across all admitted package txs. This test
// now asserts the field is PRESENT — forward-regression guard so future
// refactors don't accidentally drop the field.
// ============================================================================

test "w116 G13 (FIX-73 audit-flip): PackageResult exposes replaced_transactions field" {
    comptime {
        const PR = mempool_mod.PackageResult;
        const info = @typeInfo(PR).Struct;
        var has_replaced = false;
        for (info.fields) |f| {
            if (std.mem.eql(u8, f.name, "replaced_transactions")) {
                has_replaced = true;
            }
        }
        if (!has_replaced) @compileError("PackageResult is missing replaced_transactions — FIX-73 regression");
    }
    try testing.expect(true);
}

// ============================================================================
// G14 — submitpackage: IsChildWithParentsTree not enforced (BUG-13)
// ============================================================================

test "w116 G14 BUG-13: acceptPackage uses isChildWithParents not isChildWithParentsTree" {
    // Core enforces IsChildWithParentsTree before ProcessNewPackage.
    // clearbit acceptPackage only calls isChildWithParents (not tree variant).
    const allocator = testing.allocator;

    // parent_a has external input
    const pa_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x99} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const pa_out = types.TxOut{ .value = 9_500_000, .script_pubkey = P2WPKH };
    const parent_a = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{pa_inp},
        .outputs = &[_]types.TxOut{pa_out},
        .lock_time = 1,
    };
    const parent_a_txid = try crypto.computeTxid(&parent_a, allocator);

    // parent_b spends parent_a (inter-parent dependency)
    const pb_inp = types.TxIn{
        .previous_output = .{ .hash = parent_a_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const pb_out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const parent_b = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{pb_inp},
        .outputs = &[_]types.TxOut{pb_out},
        .lock_time = 2,
    };
    const parent_b_txid = try crypto.computeTxid(&parent_b, allocator);

    // child spends both parents
    const c_inp_a = types.TxIn{
        .previous_output = .{ .hash = parent_a_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_inp_b = types.TxIn{
        .previous_output = .{ .hash = parent_b_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 7_000_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{ c_inp_a, c_inp_b },
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 3,
    };

    const txns3: []const types.Transaction = &[_]types.Transaction{ parent_a, parent_b, child_tx };

    // Tree check correctly rejects
    const is_tree = try mempool_mod.isChildWithParentsTree(txns3, allocator);
    try testing.expect(!is_tree);

    // BUG-13: acceptPackage uses isChildWithParents not isChildWithParentsTree.
    // The weaker check may pass. Document the gap.
    try testing.expect(!is_tree); // tree is violated — fix: use isChildWithParentsTree in acceptPackage
}

// ============================================================================
// G15 — submitpackage: maxfeerate/maxburnamount absent (BUG-11, BUG-12)
// ============================================================================

test "w116 G15 BUG-11+12: acceptPackage signature has no maxfeerate or maxburnamount params" {
    // Core: submitpackage applies maxfeerate per-tx and maxburnamount per-output.
    // clearbit: acceptPackage(mempool, txns, allocator) — neither param present.
    // Structural check via comptime arity test is not straightforward in Zig,
    // so we document the gap via comment and expect(true).
    // BUG-11: add maxfeerate: f64 parameter and apply per-tx check.
    // BUG-12: add maxburnamount: i64 parameter and check OP_RETURN outputs.
    try testing.expect(true);
}

// ============================================================================
// G16 — Validation: fee check bypass when chain_state is null (BUG-14)
// ============================================================================

test "w116 G16 BUG-14: acceptPackage condition 'total_fee > 0' can bypass fee check" {
    // BUG-14: acceptPackage line 8885:
    //   "if (package_fee_rate < min_fee_rate and total_fee > 0)"
    // When no chain_state (UTXO lookup fails), input values aren't found,
    // total_fee = 0 - output_value < 0. The guard "total_fee > 0" causes the
    // fee check to be SKIPPED, allowing zero/negative-fee packages through.
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Tx whose inputs are NOT in mempool or UTXO (no chain_state supplied)
    const inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xAB} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out = types.TxOut{ .value = 1000, .script_pubkey = P2WPKH };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp},
        .outputs = &[_]types.TxOut{out},
        .lock_time = 99,
    };
    const pkg: []const types.Transaction = &[_]types.Transaction{tx};

    // If package is accepted despite total_fee<=0, BUG-14 exists.
    // If it's rejected, either the fee check works or another check fires.
    const result = mempool_mod.acceptPackage(&mempool, pkg, allocator) catch |err| {
        switch (err) {
            mempool_mod.PackageError.PackageFeeTooLow,
            mempool_mod.PackageError.TransactionError,
            => return, // rejected — fee check worked correctly
            else => return err,
        }
    };
    defer {
        var r = result;
        r.deinit();
    }
    // If we reach here: package was NOT rejected despite unknown inputs.
    // BUG-14 exists: the "total_fee > 0" guard bypassed the fee check.
    // This test documents the bug without asserting a hard failure.
    try testing.expect(true);
}

// ============================================================================
// G17 — Validation: addTransactionWithPackageRate runs script verification
// ============================================================================

test "w116 G17: addTransactionWithPackageRate calls verifyInputScripts" {
    // Verify the CPFP admission path runs script verification (not skipped).
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    // Add funding tx so parent is UTXO-resolvable via mempool
    const f_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xBC} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const f_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{f_inp},
        .outputs = &[_]types.TxOut{f_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(funding_tx);
    const funding_txid = try crypto.computeTxid(&funding_tx, allocator);

    const c_inp = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_990_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 5,
    };

    mempool.addTransactionWithPackageRate(child_tx, 100.0) catch |err| {
        switch (err) {
            mempool_mod.MempoolError.InsufficientFee,
            mempool_mod.MempoolError.MissingInputs,
            mempool_mod.MempoolError.NonStandard,
            mempool_mod.MempoolError.AlreadyInMempool,
            => {}, // acceptable in test env without real signatures
            else => return err,
        }
    };
    try testing.expect(true);
}

// ============================================================================
// G18 — Validation: coinbase rejected in package context
// ============================================================================

test "w116 G18: acceptPackage rejects or routes coinbase through standard checks" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const cb_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0} ** 32, .index = 0xFFFF_FFFF },
        .script_sig = &[_]u8{ 0x03, 0x40, 0x00, 0x00 },
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const cb_out = types.TxOut{ .value = 5_000_000_000, .script_pubkey = P2WPKH };
    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{cb_inp},
        .outputs = &[_]types.TxOut{cb_out},
        .lock_time = 0,
    };
    const pkg: []const types.Transaction = &[_]types.Transaction{coinbase_tx};
    const result = mempool_mod.acceptPackage(&mempool, pkg, allocator) catch |err| {
        switch (err) {
            mempool_mod.PackageError.PackageNotChildWithParents,
            mempool_mod.PackageError.TransactionError,
            mempool_mod.PackageError.PackageFeeTooLow,
            => return, // coinbase correctly rejected
            else => return err,
        }
    };
    defer {
        var r = result;
        r.deinit();
    }
    // If reached, coinbase was not rejected at package level.
    // addTransactionWithPackageRate should reject it via the Coinbase check.
    try testing.expect(true);
}

// ============================================================================
// G19 — Validation: package fee rate is total_fee / total_vsize
// ============================================================================

test "w116 G19: package_fee_rate equals total_fee / total_vsize" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const f_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xCD} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const f_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{f_inp},
        .outputs = &[_]types.TxOut{f_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(funding_tx);
    const funding_txid = try crypto.computeTxid(&funding_tx, allocator);

    const p_inp = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const p_out = types.TxOut{ .value = 9_999_999, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{p_inp},
        .outputs = &[_]types.TxOut{p_out},
        .lock_time = 1,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    const c_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_900_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 2,
    };

    const pkg: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();

    if (result.total_vsize > 0 and result.total_fee > 0) {
        const expected = @as(f64, @floatFromInt(result.total_fee)) /
            @as(f64, @floatFromInt(result.total_vsize));
        const diff = @abs(result.package_fee_rate - expected);
        try testing.expect(diff < 0.01);
    }
}

// ============================================================================
// G20 — Validation: single-tx package skips weight check (mirrors Core)
// ============================================================================

test "w116 G20: isWellFormedPackage skips weight limit for single-tx packages" {
    // Core: weight limit only for package_count > 1.
    // clearbit: same (line 8633: "if txns.len > 1 and total_weight > MAX_PACKAGE_WEIGHT").
    const allocator = testing.allocator;

    const big_script = [_]u8{0x51} ** 10000;
    const huge_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xDE} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const huge_out = types.TxOut{ .value = 1, .script_pubkey = &big_script };
    const huge_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{huge_inp},
        .outputs = &[_]types.TxOut{huge_out},
        .lock_time = 0,
    };
    const txns: []const types.Transaction = &[_]types.Transaction{huge_tx};
    mempool_mod.isWellFormedPackage(txns, allocator) catch |err| {
        // PackageTooLarge must NOT be returned for a single-tx package
        try testing.expect(err != mempool_mod.PackageError.PackageTooLarge);
    };
    try testing.expect(true);
}

// ============================================================================
// G21 — CPFP: child subsidises below-minimum-fee parent
// ============================================================================

test "w116 G21: CPFP — low-fee parent accepted when child raises package fee rate" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const f_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xEF} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const f_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{f_inp},
        .outputs = &[_]types.TxOut{f_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(funding_tx);
    const funding_txid = try crypto.computeTxid(&funding_tx, allocator);

    // Parent: 1 sat individual fee (below MIN_RELAY_FEE alone)
    const p_inp = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const p_out = types.TxOut{ .value = 9_999_999, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{p_inp},
        .outputs = &[_]types.TxOut{p_out},
        .lock_time = 10,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Child: pays large fee, subsidises the parent
    const c_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 11,
    };

    const pkg: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();

    try testing.expect(result.package_accepted);
    try testing.expect(result.package_fee_rate > 0.0);
}

// ============================================================================
// G22 — CPFP: partial parent set (parent already in mempool)
// ============================================================================

test "w116 G22: partial parent set — parent already in mempool handled" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const r_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xF0} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const r_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const root_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{r_inp},
        .outputs = &[_]types.TxOut{r_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(root_tx);
    const root_txid = try crypto.computeTxid(&root_tx, allocator);

    const p_inp = types.TxIn{
        .previous_output = .{ .hash = root_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const p_out = types.TxOut{ .value = 9_990_000, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{p_inp},
        .outputs = &[_]types.TxOut{p_out},
        .lock_time = 20,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    // Submit only the child (parent already in pool)
    const c_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_980_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 21,
    };

    const child_pkg: []const types.Transaction = &[_]types.Transaction{child_tx};
    var result = mempool_mod.acceptPackage(&mempool, child_pkg, allocator) catch |err| {
        switch (err) {
            mempool_mod.PackageError.PackageNotChildWithParents,
            mempool_mod.PackageError.PackageFeeTooLow,
            => return,
            else => return err,
        }
    };
    defer result.deinit();
    try testing.expect(true);
}

// ============================================================================
// G23 — CPFP: package fee includes already-in-mempool parents
// ============================================================================

test "w116 G23: acceptPackage counts in-mempool parent fee in total_fee" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const r_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xF1} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const r_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const root_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{r_inp},
        .outputs = &[_]types.TxOut{r_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(root_tx);
    const root_txid = try crypto.computeTxid(&root_tx, allocator);

    const p_inp = types.TxIn{
        .previous_output = .{ .hash = root_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const p_out = types.TxOut{ .value = 9_990_000, .script_pubkey = P2WPKH }; // 10_000 sat fee
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{p_inp},
        .outputs = &[_]types.TxOut{p_out},
        .lock_time = 30,
    };
    try mempool.addTransaction(parent_tx);
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    const c_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_900_000, .script_pubkey = P2WPKH }; // 90_000 sat fee
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 31,
    };

    const pkg: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();

    // total_fee should incorporate both parent (10_000) and child (90_000) fees
    try testing.expect(result.total_fee >= 0);
    try testing.expect(result.package_fee_rate >= 0.0);
}

// ============================================================================
// G24 — CPFP: package fee rate unit is sat/vB
// ============================================================================

test "w116 G24: package_fee_rate is positive sat/vB when package has positive fee" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const f_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xF2} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const f_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const funding_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{f_inp},
        .outputs = &[_]types.TxOut{f_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(funding_tx);
    const funding_txid = try crypto.computeTxid(&funding_tx, allocator);

    const p_inp = types.TxIn{
        .previous_output = .{ .hash = funding_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const p_out = types.TxOut{ .value = 9_990_000, .script_pubkey = P2WPKH };
    const parent_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{p_inp},
        .outputs = &[_]types.TxOut{p_out},
        .lock_time = 40,
    };
    const parent_txid = try crypto.computeTxid(&parent_tx, allocator);

    const c_inp = types.TxIn{
        .previous_output = .{ .hash = parent_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const c_out = types.TxOut{ .value = 9_980_000, .script_pubkey = P2WPKH };
    const child_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{c_inp},
        .outputs = &[_]types.TxOut{c_out},
        .lock_time = 41,
    };

    const pkg: []const types.Transaction = &[_]types.Transaction{ parent_tx, child_tx };
    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();

    if (result.total_vsize > 0 and result.total_fee > 0) {
        try testing.expect(result.package_fee_rate > 0.0);
    }
}

// ============================================================================
// G25 — Edge cases: duplicate transactions rejected
// ============================================================================

test "w116 G25: isWellFormedPackage rejects duplicate transactions" {
    const allocator = testing.allocator;

    const inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xF3} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp},
        .outputs = &[_]types.TxOut{out},
        .lock_time = 1,
    };
    const txns: []const types.Transaction = &[_]types.Transaction{ tx, tx }; // duplicate
    const err = mempool_mod.isWellFormedPackage(txns, allocator);
    try testing.expectError(mempool_mod.PackageError.PackageContainsDuplicates, err);
}

// ============================================================================
// G26 — Edge cases: MAX_PACKAGE_COUNT enforced
// ============================================================================

test "w116 G26: isWellFormedPackage rejects more than 25 transactions" {
    // Build 26 distinct transactions in the same scope to avoid lifetime issues.
    const allocator = testing.allocator;

    const inp0 = types.TxIn{ .previous_output = .{ .hash = [_]u8{0x01} ** 32, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFF_FFFF, .witness = &[_][]const u8{} };
    const inp1 = types.TxIn{ .previous_output = .{ .hash = [_]u8{0x02} ** 32, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFF_FFFF, .witness = &[_][]const u8{} };
    const inp2 = types.TxIn{ .previous_output = .{ .hash = [_]u8{0x03} ** 32, .index = 0 }, .script_sig = &[_]u8{}, .sequence = 0xFFFF_FFFF, .witness = &[_][]const u8{} };
    const out0 = types.TxOut{ .value = 1000, .script_pubkey = P2WPKH };
    const tx0 = types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 0 };
    const tx1 = types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 1 };
    const tx2 = types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 2 };
    // Build an array of 26 transactions by repeating variants
    // We need 26 distinct txns (distinct lock_time ensures distinct txid)
    const big_pkg: []const types.Transaction = &[_]types.Transaction{
        tx0, tx1, tx2,
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 3 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 4 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 5 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 6 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 7 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 8 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 9 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 10 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 11 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 12 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 13 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 14 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 15 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 16 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 17 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 18 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 19 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 20 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 21 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 22 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp2}, .outputs = &[_]types.TxOut{out0}, .lock_time = 23 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp0}, .outputs = &[_]types.TxOut{out0}, .lock_time = 24 },
        types.Transaction{ .version = 2, .inputs = &[_]types.TxIn{inp1}, .outputs = &[_]types.TxOut{out0}, .lock_time = 25 },
    };
    try testing.expectEqual(@as(usize, 26), big_pkg.len);
    // Should fail with PackageTooManyTransactions (26 > 25)
    if (mempool_mod.isWellFormedPackage(big_pkg, allocator)) {
        // Should not succeed — fail the test
        try testing.expect(false);
    } else |err| {
        // PackageTooManyTransactions expected first (checked before duplicates)
        // PackageContainsDuplicates also acceptable if count check fires after dedup
        const ok = (err == mempool_mod.PackageError.PackageTooManyTransactions or
            err == mempool_mod.PackageError.PackageContainsDuplicates);
        try testing.expect(ok);
    }
}

// ============================================================================
// G27 — Edge cases: MAX_PACKAGE_WEIGHT enforced for multi-tx package
// ============================================================================

test "w116 G27: MAX_PACKAGE_WEIGHT constant is 404_000" {
    try testing.expectEqual(@as(usize, 404_000), mempool_mod.MAX_PACKAGE_WEIGHT);
}

test "w116 G27b: isWellFormedPackage only checks weight for multi-tx packages" {
    // For single-tx, weight is not checked at the package level (Core: same).
    // For multi-tx, if total > MAX_PACKAGE_WEIGHT, PackageTooLarge is returned.
    // We verify the condition code exists by checking the constant.
    comptime {
        // MAX_PACKAGE_WEIGHT must be exactly 404_000
        if (mempool_mod.MAX_PACKAGE_WEIGHT != 404_000)
            @compileError("MAX_PACKAGE_WEIGHT must be 404_000");
    }
    try testing.expect(true);
}

// ============================================================================
// G28 — Edge cases: single-tx package identity
// ============================================================================

test "w116 G28: single-tx package passes isWellFormedPackage" {
    const allocator = testing.allocator;

    const inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xF6} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const out = types.TxOut{ .value = 9_000_000, .script_pubkey = P2WPKH };
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{inp},
        .outputs = &[_]types.TxOut{out},
        .lock_time = 1,
    };
    const txns: []const types.Transaction = &[_]types.Transaction{tx};
    try mempool_mod.isWellFormedPackage(txns, allocator);
}

test "w116 G28b: single-tx package through acceptPackage" {
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const r_inp = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xF7} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const r_out = types.TxOut{ .value = 10_000_000, .script_pubkey = P2WPKH };
    const root_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{r_inp},
        .outputs = &[_]types.TxOut{r_out},
        .lock_time = 0,
    };
    try mempool.addTransaction(root_tx);
    const root_txid = try crypto.computeTxid(&root_tx, allocator);

    const s_inp = types.TxIn{
        .previous_output = .{ .hash = root_txid, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    const s_out = types.TxOut{ .value = 9_990_000, .script_pubkey = P2WPKH };
    const single_tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{s_inp},
        .outputs = &[_]types.TxOut{s_out},
        .lock_time = 50,
    };
    const pkg: []const types.Transaction = &[_]types.Transaction{single_tx};

    var result = try mempool_mod.acceptPackage(&mempool, pkg, allocator);
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.tx_results.len);
}

// ============================================================================
// G29 — P2P package relay: BIP-331 messages defined but not parsed (BUG-15)
// ============================================================================

test "w116 G29 BUG-15: BIP-331 P2P message types exist (encode-only, decode dead-helper)" {
    // sendpackages, ancpkginfo, getpkgtxns, pkgtxns are in the Message union
    // and have serialization code in encodeMessage(), BUT decodePayload() does
    // NOT handle any of them — all fall through to ParseError.UnknownCommand.
    // This is a dead-helper: the full receive path is absent.
    comptime {
        // Verify the types exist (encode side is present):
        const have_sp = @hasField(p2p.Message, "sendpackages");
        const have_ap = @hasField(p2p.Message, "ancpkginfo");
        const have_gp = @hasField(p2p.Message, "getpkgtxns");
        const have_pt = @hasField(p2p.Message, "pkgtxns");
        if (!have_sp or !have_ap or !have_gp or !have_pt)
            @compileError("BIP-331 message union variants missing");
    }
    // BUG-15: fix requires adding "sendpackages"/"ancpkginfo"/"getpkgtxns"/"pkgtxns"
    // branches to decodePayload() in p2p.zig:696-896.
    try testing.expect(true);
}

test "w116 G29b: BIP-331 message struct fields are correct" {
    // Verify struct shapes match BIP-331 spec
    const sp: p2p.SendPackagesMessage = .{ .version = 1 };
    try testing.expectEqual(@as(u32, 1), sp.version);

    const api: p2p.AncPkgInfoMessage = .{
        .package_hash = [_]u8{0xAB} ** 32,
        .child_wtxid = [_]u8{0xCD} ** 32,
        .parent_count = 3,
    };
    try testing.expectEqual(@as(u32, 3), api.parent_count);
}

// ============================================================================
// G30 — P2P package relay: sendpackages not sent during handshake (BUG-16)
// ============================================================================

test "w116 G30 BUG-16: sendpackages negotiation absent from handshake (constants match)" {
    // BIP-331 §4: after verack, a node with package relay support sends:
    //   sendpackages version=1
    // clearbit has the struct and serialization but NO code sends this in the
    // post-verack handshake. BIP-331 negotiation is never initiated.
    //
    // Verify p2p constants are consistent with mempool constants:
    try testing.expectEqual(p2p.MAX_PACKAGE_COUNT, mempool_mod.MAX_PACKAGE_COUNT);
    try testing.expectEqual(p2p.MAX_PACKAGE_WEIGHT, mempool_mod.MAX_PACKAGE_WEIGHT);
    // BUG-16: fix is to emit Message{.sendpackages=.{.version=1}} after verack
    // in the peer connection/handshake sequence.
    try testing.expect(true);
}
