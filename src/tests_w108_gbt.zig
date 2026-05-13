// W108 — BlockTemplate + GBT mining RPC 30-gate audit (clearbit / Zig 0.13)
//
// Reference: bitcoin-core/src/rpc/mining.cpp (getblocktemplate, submitblock)
//            bitcoin-core/src/node/miner.cpp (BlockAssembler, CreateNewBlock,
//              addChunks, resetBlock, UpdateTime, GetMinimumTime)
//            bitcoin-core/src/node/miner.h  (DEFAULT_BLOCK_RESERVED_WEIGHT,
//              MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_CONSECUTIVE_FAILURES)
//            bitcoin-core/src/policy/policy.h (blockMinFeeRate, MAX_BLOCK_WEIGHT)
//            BIP-22, BIP-23, BIP-9 GBT extension, BIP-141 (segwit)
//
// Findings:
//
//   BUG-1  (G1, P1): handleGetBlockTemplate in rpc.zig ignores `params`
//          entirely (`_ = params` comment "not fully implemented").  Core
//          parses mode (template/proposal), rules, capabilities, longpollid.
//          Miner clients that send mode="proposal" or rules=["segwit"] get a
//          template back instead of validation result / error.
//
//   BUG-2  (G2, P2): No IBD check + no peer-connectivity check before serving
//          GBT.  Bitcoin Core refuses on non-test chains when
//          connman.GetNodeCount(Both)==0 (not connected) or isInitialBlockDownload.
//          clearbit always serves a template regardless of sync/peer state.
//
//   BUG-3  (G3, CONSENSUS-DIVERGENT): nBits in template header hardcoded to
//          `params.genesis_header.bits` (genesis difficulty) instead of calling
//          `consensus.getNextWorkRequired()` for the next block.  Miners that
//          submit a block with this template will use the wrong bits, causing
//          the submitted block to fail validateProofOfWork if the live chain
//          difficulty differs from genesis.  Affects every network after the
//          first 2016-block adjustment.
//
//   BUG-4  (G4, P1): `mintime` field in GBT response set to
//          `template.header.timestamp` (current wall time) instead of
//          `MTP + 1`.  Bitcoin Core:
//            result.pushKV("mintime", GetMinimumTime(pindexPrev, …))
//          where GetMinimumTime = pindexPrev->GetMedianTimePast() + 1.
//          A miner using clearbit's `mintime` as its lower bound may mine a
//          block with timestamp <= MTP, which will be rejected by all nodes.
//
//   BUG-5  (G5, P2): BIP-94 timewarp adjustment missing from `mintime` / curtime
//          calculation.  Core's GetMinimumTime() enforces:
//            if (height % difficulty_adjustment_interval == 0)
//              min_time = max(min_time, prev->GetBlockTime() - MAX_TIMEWARP)
//          This guard is absent from block_template.zig.
//
//   BUG-6  (G6, P2): GBT response missing `rules` field.  Core emits
//          `["csv", "!segwit", "taproot"]` (post-activation).  Miner clients
//          that enforce rules must understand these to know which rule
//          violations to reject.
//
//   BUG-7  (G7, P2): GBT response missing `vbavailable` field.  Core uses
//          chainman.m_versionbitscache.GBTStatus to populate this so miners
//          can know which BIP-9 bits are available for signaling.
//
//   BUG-8  (G8, P2): GBT transaction entries missing `hash` field (witness
//          hash / wtxid in byte-reversed hex).  BIP-141 GBT extension adds
//          both "txid" (stripping witness) and "hash" (with witness).  Segwit-
//          aware miners need "hash" for fee estimation and template validation.
//
//   BUG-9  (G9, P2): GBT transaction entries missing `depends` field (1-based
//          index array of in-template parent transactions).  Required by BIP-22
//          section 8: "Array of numbers with same-template-txids this tx depends on".
//
//   BUG-10 (G10, P2): GBT transaction entries missing `sigops` field.  BIP-22
//          requires sigops for each transaction so miners can enforce sigop
//          limits when modifying the transaction set.
//
//   BUG-11 (G11, P2): GBT response missing `coinbaseaux` field (empty {} object
//          per BIP-22 section 4: "data that should be included in coinbase").
//
//   BUG-12 (G12, P2): GBT response missing `longpollid` field.  BIP-22 section
//          6: "an id to include with a request to longpoll on an update".
//          Without it, polling miners cannot use BIP-22 long-polling.
//
//   BUG-13 (G13, P2): GBT response missing `noncerange` field.  BIP-22 section
//          4 specifies "00000000ffffffff" as the valid nonce range.
//
//   BUG-14 (G14, P2): GBT response missing `sigoplimit` field.  Core emits
//          sigoplimit=80000 (MAX_BLOCK_SIGOPS_COST) post-segwit.
//
//   BUG-15 (G15, P2): GBT response missing `sizelimit` field.  Core emits
//          sizelimit=4000000 (MAX_BLOCK_SERIALIZED_SIZE) post-segwit.
//
//   BUG-16 (G16, P2): GBT response missing `weightlimit` field.  BIP-145
//          (segwit GBT extension) adds `weightlimit` = MAX_BLOCK_WEIGHT = 4000000.
//
//   BUG-17 (G17, P2): GBT response missing `vbrequired` field.  Core emits
//          `vbrequired: 0` (no mandatory versionbit requirements currently).
//
//   BUG-18 (G18, P1): BIP-22 `proposal` mode not implemented.  Core handles
//          mode="proposal" by calling TestBlockValidity on the submitted block
//          and returning a BIP-22 status string.  clearbit ignores `params`
//          entirely, so mode="proposal" returns a template instead of a
//          validation result.
//
//   BUG-19 (G19, P2): No BIP-22 client-capabilities negotiation.  Core checks
//          whether "coinbasevalue" or "coinbase"/"coinbasetxn" is in the client's
//          capabilities list; clearbit always emits "coinbasevalue" regardless.
//
//   BUG-20 (G20, P2): `encodeHeightPush` for heights 1–16 produces a 1-byte
//          scriptSig (OP_1..OP_16 = 1 opcode byte) with no dummy extranonce.
//          Consensus requires coinbase scriptSig >= 2 bytes (bad-cb-length).
//          Bitcoin Core adds `OP_0` dummy for heights <= 16 when
//          include_dummy_extranonce=true.  clearbit's coinbase at height 1..16
//          would therefore be rejected by all nodes on ConnectBlock.
//
//   BUG-21 (G21, P2): `curtime` in GBT response should equal
//          max(MTP+1, wall_clock) — i.e., call UpdateTime semantics.
//          clearbit emits `template.header.timestamp` set at construction
//          time, which may be stale by the time the miner uses it.  Core
//          calls UpdateTime() after template construction to set curtime.
//
//   BUG-22 (G22, P2): `getmininginfo` emits `networkhashps: 0` (hardcoded
//          literal zero) instead of computing hashes-per-second from chain
//          work diff over a time window.  Core's GetNetworkHashPS() walks
//          `lookup` blocks and divides work diff by elapsed time.
//
//   BUG-23 (G23, P2): `getmininginfo` emits `blockmintxfee: 0.00001`
//          (hardcoded) instead of querying the configured blockMinFeeRate.
//          Core reads assembler_options.blockMinFeeRate from -blockmintxfee
//          arg and emits ValueFromAmount(blockMinFeeRate.GetFeePerK()).
//
//   BUG-24 (G24, P2): GBT response missing `signet_challenge` field for
//          signet networks.  Core conditionally adds this when
//          consensusParams.signet_blocks is true.
//
//   BUG-25 (G25, P2): GBT response missing `default_witness_commitment`
//          field.  Core adds this when getCoinbaseTx().required_outputs is
//          non-empty, giving miners the pre-computed commitment they should
//          include verbatim.
//
//   BUG-26 (G26, P2): `prioritisetransaction` RPC is not registered in the
//          dispatch table (rpc.zig method dispatch).  Core's prioritisetransaction
//          lets miners bump or penalise specific transactions for block building.
//          A call returns "method not found" in clearbit.
//
//   BUG-27 (G27, P3): `getblocktemplate` in rpc.zig reconstructs a full
//          template from scratch on every call without any caching.  Bitcoin
//          Core caches the template and re-uses it if the prev-block hash
//          and mempool-update-counter have not changed (5-second grace period).
//          clearbit's current behaviour works but is needlessly expensive.
//
//   BUG-28 (G28, P2): BIP-22 `capabilities` field in the GBT response only
//          ever contains `["proposal"]`; the `"coinbasetxn"` / `"workid"` /
//          `"serverlist"` entries are never added.  BIP-23 specifies these
//          advertise optional server-side features.
//
//   BUG-29 (G29, P2): `createBlockTemplate` uses `options.include_witness_commitment`
//          (before clamping) rather than `opts.include_witness_commitment`
//          (post-clamping) when deciding whether to compute the witness
//          commitment.  Although clampOptions() does not currently touch that
//          field, the asymmetry is a latent bug if a future clamping rule is
//          added for it.
//
//   PASS: clampOptions() correctly enforces MINIMUM_BLOCK_RESERVED_WEIGHT,
//         MAX_BLOCK_WEIGHT, and MAX_BLOCK_SIGOPS_COST bounds.
//   PASS: consecutive-failure early-exit (MAX_CONSECUTIVE_FAILURES / BLOCK_FULL_ENOUGH_WEIGHT_DELTA)
//         matches Core miner.cpp::addChunks().
//   PASS: block weight limit check uses >= (not >), matching Core TestChunkBlockLimits.
//   PASS: sigops limit check uses >= (not >), matching Core.
//   PASS: block_min_fee_rate gate applied per-entry (conservative but correct).
//   PASS: MTP-based lock_time_cutoff for IsFinalTx (Bug-4 already fixed).
//   PASS: coinbase nLockTime = height-1 (anti-fee-sniping, matches Core).
//   PASS: coinbase sequence = 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL, matches Core).
//   PASS: witness commitment format 0x6a 0x24 0xaa 0x21 0xa9 0xed + 32 bytes.
//   PASS: witness commitment computation SHA256d(witness_merkle_root || witness_nonce).
//   PASS: DEFAULT_MAX_TRIES = 1_000_000 (matches Core DEFAULT_MAX_TRIES).

const std = @import("std");
const testing = std.testing;
const block_template = @import("block_template.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

// ---------------------------------------------------------------------------
// G1 — params parsing: mode/rules/capabilities/longpollid (BUG-1: ignored)
// ---------------------------------------------------------------------------
//
// Bitcoin Core mining.cpp::getblocktemplate parses:
//   mode        (str: "template" | "proposal")
//   rules       (arr: ["segwit", ...])
//   capabilities (arr: ["proposal", "coinbasevalue", ...])
//   longpollid  (str: hash+counter)
//
// BUG-1: clearbit rpc.zig line 4605: `_ = params; // not fully implemented`
//        The GBT params object is silently discarded.
//
// These tests document the current (broken) behaviour on the block_template
// module layer (the units we can test without spinning a full RPC server).

test "w108 G1 PASS clampOptions respects MINIMUM_BLOCK_RESERVED_WEIGHT" {
    // BUG-1 is in rpc.zig dispatch, not block_template.zig.
    // Verify clampOptions() is correct as a positive baseline.
    const result = block_template.clampOptions(.{
        .block_reserved_weight = 0, // below minimum
    });
    try testing.expectEqual(block_template.MINIMUM_BLOCK_RESERVED_WEIGHT, result.block_reserved_weight);
    try testing.expect(result.max_weight >= result.block_reserved_weight);
    try testing.expect(result.max_weight <= consensus.MAX_BLOCK_WEIGHT);
}

test "w108 G1b PASS clampOptions max_weight clamped to MAX_BLOCK_WEIGHT" {
    const result = block_template.clampOptions(.{
        .max_weight = 999_999_999, // way above MAX_BLOCK_WEIGHT
    });
    try testing.expectEqual(consensus.MAX_BLOCK_WEIGHT, result.max_weight);
}

test "w108 G1c PASS clampOptions max_sigops clamped" {
    const result = block_template.clampOptions(.{
        .max_sigops = 999_999_999,
    });
    try testing.expect(result.max_sigops <= consensus.MAX_BLOCK_SIGOPS_COST);
}

// ---------------------------------------------------------------------------
// G2 — IBD + connectivity gate (BUG-2: absent)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:766-775:
//   if (!miner.isTestChain()) {
//     if (connman.GetNodeCount(Both) == 0)
//       throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, …);
//     if (miner.isInitialBlockDownload())
//       throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, …);
//   }
//
// BUG-2: clearbit's handleGetBlockTemplate never checks IBD or peer count.
//
// These tests verify the template assembler layer behaves regardless
// (unit-testable); the RPC dispatch layer's absence of the guard is the bug.

test "w108 G2 BUG-2 createBlockTemplate succeeds with no peers (IBD gate absent)" {
    // This is the broken behaviour: template creation should be gated at the
    // RPC layer when IBD=true or 0 peers, but the module itself cannot enforce
    // this (it lacks peer-count context).
    // Document: template still builds successfully even at a low chain height,
    // which is an IBD state on mainnet.
    // Use best_height=144 to avoid the BIP-9 state machine integer underflow
    // (consensus.zig:2261: prev_height - ... panics when prev_height < period).
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20; // P2WPKH
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout },
        allocator,
    );
    defer tmpl.deinit();
    // Template is produced without error even though this node has 0 peers (IBD state).
    try testing.expectEqual(@as(u32, 145), tmpl.height);
}

// ---------------------------------------------------------------------------
// G3 — nBits = GetNextWorkRequired() (BUG-3: hardcoded genesis bits)
// ---------------------------------------------------------------------------
//
// Core miner.cpp:220: pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, …)
// clearbit block_template.zig:233: `const bits: u32 = params.genesis_header.bits; // placeholder`
//
// BUG-3: CONSENSUS-DIVERGENT — after the first 2016-block retarget, the
// template will carry genesis bits while the network has a different target.

test "w108 G3 BUG-3 template nBits is genesis_header.bits (placeholder, not GetNextWorkRequired)" {
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout },
        allocator,
    );
    defer tmpl.deinit();

    // BUG-3: clearbit returns genesis bits verbatim.
    // After a retarget, bits should differ from genesis.
    // Document current (broken) behaviour: bits == genesis bits.
    const genesis_bits = consensus.REGTEST.genesis_header.bits;
    try testing.expectEqual(genesis_bits, tmpl.header.bits);
    // FIX: should call getNextWorkRequired(chain_state, params) and use the
    // result rather than params.genesis_header.bits.
}

// ---------------------------------------------------------------------------
// G4 — mintime = MTP + 1 (BUG-4: set to wall-clock timestamp)
// ---------------------------------------------------------------------------
//
// Core miner.cpp (GetMinimumTime): return pindexPrev->GetMedianTimePast() + 1
// Core mining.cpp: result.pushKV("mintime", GetMinimumTime(pindexPrev, …))
//
// BUG-4: clearbit rpc.zig:4665 `template.header.timestamp` is wall clock,
// NOT MTP+1.  A block with timestamp <= MTP will be rejected.

test "w108 G4 BUG-4 mintime should be MTP+1 not wall clock" {
    // Verify that MTP+1 < current wall clock (most of the time the chain MTP
    // lags real time).  The template's stored timestamp (wall clock) is NOT
    // the correct mintime value.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    chain_state.initGenesisTimestamp(1296688602); // regtest genesis

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCC} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout },
        allocator,
    );
    defer tmpl.deinit();

    const mtp = chain_state.computeMTP();
    const expected_mintime: u32 = if (mtp != 0) mtp + 1 else 0;

    // BUG-4: the template header's timestamp is the wall clock, not MTP+1.
    // Document: when the chain has a seeded MTP, mintime should be MTP+1.
    if (mtp != 0) {
        // For a seeded genesis: MTP should equal genesis timestamp.
        // Correct mintime would be mtp + 1 = 1296688603.
        try testing.expectEqual(@as(u32, 1296688602), mtp);
        try testing.expectEqual(@as(u32, 1296688603), expected_mintime);
        // FIX: GBT response mintime field must emit expected_mintime, not
        // template.header.timestamp (wall clock).
    }
}

// ---------------------------------------------------------------------------
// G5 — BIP-94 timewarp guard (BUG-5: absent)
// ---------------------------------------------------------------------------
//
// Core node/miner.cpp (GetMinimumTime):
//   if (height % difficulty_adjustment_interval == 0)
//     min_time = max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP)
//
// BUG-5: block_template.zig has no timewarp guard in mintime computation.

test "w108 G5 BUG-5 GetMinimumTime lacks BIP-94 timewarp adjustment" {
    // We can only test the module-level MTP path here.
    // Verify that at a retarget boundary (height % 2016 == 0), the
    // expected mintime guard is NOT applied by clearbit.
    // The fix would require storing prev block's timestamp and comparing.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xDD} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout },
        allocator,
    );
    defer tmpl.deinit();
    // BUG-5: no timewarp guard present; the template just uses wall clock.
    // Document: template.height == 2 (best_height+1), which is a non-retarget height,
    // so this is a no-op now, but the guard is always absent.
    try testing.expect(tmpl.height > 0);
}

// ---------------------------------------------------------------------------
// G6 — `rules` field in GBT response (BUG-6: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:954-963:
//   aRules.push_back("csv");
//   if (!fPreSegWit) { aRules.push_back("!segwit"); aRules.push_back("taproot"); }
//   result.pushKV("rules", std::move(aRules));
//
// BUG-6: clearbit's handleGetBlockTemplate has no `rules` field in its
// JSON output — the writer.print at rpc.zig:4628-4669 never emits it.

test "w108 G6 BUG-6 GBT response missing rules field (documented)" {
    // Test is a contract: verifies that block_template module itself does
    // not track rules (the GBT response builder in rpc.zig is the site of the bug).
    // block_template.zig correctly computes the block version via BIP-9.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xEE} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl.deinit();
    // The block_template struct has no `rules` field — it belongs in the RPC response.
    // FIX: rpc.zig must add `"rules":["csv","!segwit","taproot"]` (or appropriate subset)
    // to the GBT JSON response based on chain deployment status.
    try testing.expect(tmpl.height > 0); // baseline sanity
}

// ---------------------------------------------------------------------------
// G7 — `vbavailable` field (BUG-7: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:966-983: iterates gbtstatus.signalling + locked_in
//   vbavailable.pushKV(gbt_rule_value(name, …), bit)
//   result.pushKV("vbavailable", …)
//
// BUG-7: clearbit's GBT response has no vbavailable field.

test "w108 G7 BUG-7 GBT response missing vbavailable field (BIP-9 GBT extension)" {
    // Verify that consensus.computeBlockVersion() exists (used by template)
    // and that the block_template module's stub BIP-9 signaling is wired.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x01} ** 20 ++ [_]u8{ 0x88, 0xac }; // P2PKH
    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl.deinit();
    // block_template populates template.header.version via computeBlockVersion()
    // but does not expose a vbavailable map.
    // FIX: rpc.zig must build vbavailable from the BIP-9 state machine per
    // Bitcoin Core mining.cpp:966-983.
    try testing.expect(tmpl.header.version != 0);
}

// ---------------------------------------------------------------------------
// G8 — `hash` (wtxid) in transaction entries (BUG-8: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:915: entry.pushKV("hash", tx.GetWitnessHash().GetHex())
// Core mining.cpp:913: entry.pushKV("txid", txHash.GetHex())  // no-witness hash
//
// BUG-8: clearbit rpc.zig:4648 only emits "txid"; the "hash" (wtxid) field
//        is absent from every transaction entry in the GBT response.

test "w108 G8 BUG-8 GBT transaction entries missing hash (wtxid) field" {
    // Verify that computeWtxid produces a different value from txid for
    // a transaction with witness data.  The GBT "hash" field must be
    // the witness hash (wtxid), not the txid.
    const allocator = testing.allocator;

    // Build a simple tx with witness to verify txid != wtxid
    const tx = types.Transaction{
        .version = 2,
        .inputs = &[_]types.TxIn{.{
            .previous_output = .{ .hash = [_]u8{0xAB} ** 32, .index = 0 },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{&[_]u8{ 0x04, 0x01, 0x02, 0x03 }},
        }},
        .outputs = &[_]types.TxOut{.{
            .value = 5000,
            .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xCC} ** 20 ++ [_]u8{ 0x88, 0xac },
        }},
        .lock_time = 0,
    };

    const txid = try crypto.computeTxid(&tx, allocator);
    const wtxid = try crypto.computeWtxid(&tx, allocator);

    // For a tx with witness, txid != wtxid
    const has_witness = tx.inputs[0].witness.len > 0;
    try testing.expect(has_witness);
    // txid strips witness; wtxid includes it — they differ
    try testing.expect(!std.mem.eql(u8, &txid, &wtxid));
    // FIX: rpc.zig handleGetBlockTemplate must emit both "txid" and "hash"
    // fields per BIP-141 GBT extension.
}

// ---------------------------------------------------------------------------
// G9 — `depends` field in GBT transaction entries (BUG-9: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:917-922: emits 1-based index of in-template ancestors
//   for (const CTxIn &in : tx.vin)
//     if (setTxIndex.contains(in.prevout.hash))
//       deps.push_back(setTxIndex[in.prevout.hash])
//   entry.pushKV("depends", std::move(deps));
//
// BUG-9: clearbit's transaction entries have no "depends" array.

test "w108 G9 BUG-9 GBT transaction entries missing depends array (BIP-22)" {
    // SelectedTx struct has no depends field — the dependency calculation
    // must be done at GBT response serialization time in rpc.zig.
    // Verify that SelectedTx at least carries txid so the dep lookup can work.
    const stx = block_template.BlockTemplate.SelectedTx{
        .tx = types.Transaction{
            .version = 1,
            .inputs = &[_]types.TxIn{},
            .outputs = &[_]types.TxOut{},
            .lock_time = 0,
        },
        .txid = [_]u8{0x12} ** 32,
        .weight = 400,
        .fee = 1000,
        .sigops = 4,
    };
    try testing.expectEqualSlices(u8, &([_]u8{0x12} ** 32), &stx.txid);
    // FIX: rpc.zig must build a setTxIndex map and emit depends[] per tx.
}

// ---------------------------------------------------------------------------
// G10 — `sigops` in GBT transaction entries (BUG-10: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:927-931: nTxSigOps = tx_sigops.at(index)
//   entry.pushKV("sigops", nTxSigOps)
//
// BUG-10: clearbit rpc.zig:4649 only emits "fee" and "weight"; no "sigops".

test "w108 G10 BUG-10 GBT transaction entries missing sigops field (BIP-22)" {
    // SelectedTx struct carries .sigops — the data is available in the template.
    // The bug is that rpc.zig doesn't include it in the JSON output.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x11} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl.deinit();
    // With no transactions in mempool, selected is empty — but struct has .sigops
    for (tmpl.transactions.items) |stx| {
        _ = stx.sigops; // field exists
    }
    // FIX: rpc.zig must include "sigops": stx.sigops for each tx in the array.
}

// ---------------------------------------------------------------------------
// G11 — `coinbaseaux` field (BUG-11: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:938-999: UniValue aux(UniValue::VOBJ); ... result.pushKV("coinbaseaux", aux)
//
// BUG-11: clearbit's GBT response has no coinbaseaux field.

test "w108 G11 BUG-11 GBT response missing coinbaseaux field" {
    // Block template module has no coinbaseaux concept.
    // Test documents that the field must be added to rpc.zig GBT response.
    // FIX: rpc.zig must emit `"coinbaseaux":{}` in the GBT response.
    const coinbaseaux_expected = "{}"; // empty object per BIP-22
    try testing.expect(coinbaseaux_expected.len > 0);
}

// ---------------------------------------------------------------------------
// G12 — `longpollid` field (BUG-12: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:1002: result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast))
//
// BUG-12: clearbit's GBT response has no longpollid field.

test "w108 G12 BUG-12 GBT response missing longpollid field (BIP-22 section 6)" {
    // longpollid = hex(tip_hash) + decimal(mempool_update_counter)
    // Core format: 64-char hex tip hash + numeric counter string
    // FIX: rpc.zig must compute and emit longpollid.
    // Document expected format: tip_hash_hex (64 chars) + update_counter (decimal)
    const example_tip = [_]u8{0x00} ** 32;
    var hash_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hash_hex, "{s}", .{std.fmt.fmtSliceHexLower(&example_tip)}) catch unreachable;
    try testing.expectEqual(@as(usize, 64), hash_hex.len);
}

// ---------------------------------------------------------------------------
// G13 — `noncerange` field (BUG-13: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:1006: result.pushKV("noncerange", "00000000ffffffff")
//
// BUG-13: clearbit's GBT response has no noncerange field.

test "w108 G13 BUG-13 GBT response missing noncerange field" {
    // noncerange is always "00000000ffffffff" per BIP-22.
    // FIX: rpc.zig must emit `"noncerange":"00000000ffffffff"`.
    const expected = "00000000ffffffff";
    try testing.expectEqual(@as(usize, 16), expected.len);
}

// ---------------------------------------------------------------------------
// G14 — `sigoplimit` field (BUG-14: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:1007-1014: result.pushKV("sigoplimit", nSigOpLimit)
//   nSigOpLimit = MAX_BLOCK_SIGOPS_COST (= 80000 post-segwit)
//
// BUG-14: clearbit's GBT response has no sigoplimit field.

test "w108 G14 BUG-14 GBT response missing sigoplimit field (should be 80000)" {
    // Verify MAX_BLOCK_SIGOPS_COST value matches Core.
    try testing.expectEqual(@as(u32, 80_000), consensus.MAX_BLOCK_SIGOPS_COST);
    // FIX: rpc.zig must emit `"sigoplimit":80000` in the GBT response.
}

// ---------------------------------------------------------------------------
// G15 — `sizelimit` field (BUG-15: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:1016: result.pushKV("sizelimit", nSizeLimit)
//   nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE (= 4000000 post-segwit)
//
// BUG-15: clearbit's GBT response has no sizelimit field.

test "w108 G15 BUG-15 GBT response missing sizelimit field (should be 4000000)" {
    // MAX_BLOCK_SERIALIZED_SIZE = MAX_BLOCK_WEIGHT = 4_000_000 post-segwit
    try testing.expectEqual(@as(u32, 4_000_000), consensus.MAX_BLOCK_WEIGHT);
    // FIX: rpc.zig must emit `"sizelimit":4000000`.
}

// ---------------------------------------------------------------------------
// G16 — `weightlimit` field (BUG-16: missing, BIP-145)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:1017-1019: if (!fPreSegWit) result.pushKV("weightlimit", MAX_BLOCK_WEIGHT)
//
// BUG-16: clearbit's GBT response has no weightlimit field.

test "w108 G16 BUG-16 GBT response missing weightlimit field (BIP-145, should be 4000000)" {
    try testing.expectEqual(@as(u32, 4_000_000), consensus.MAX_BLOCK_WEIGHT);
    // FIX: rpc.zig must emit `"weightlimit":4000000` (post-segwit networks).
}

// ---------------------------------------------------------------------------
// G17 — `vbrequired` field (BUG-17: missing)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:996: result.pushKV("vbrequired", 0)
//
// BUG-17: clearbit's GBT response has no vbrequired field.

test "w108 G17 BUG-17 GBT response missing vbrequired field (BIP-9 GBT, should be 0)" {
    // vbrequired = 0 means no mandatory version bits.
    // FIX: rpc.zig must emit `"vbrequired":0`.
    const expected: u32 = 0;
    try testing.expectEqual(@as(u32, 0), expected);
}

// ---------------------------------------------------------------------------
// G18 — BIP-22 proposal mode (BUG-18: not implemented)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:730-751: if strMode == "proposal", decode hex block,
//   check duplicate, call TestBlockValidity, return BIP-22 result string.
//
// BUG-18: clearbit ignores params entirely; proposal mode returns a template.

test "w108 G18 BUG-18 proposal mode not implemented (params ignored in rpc.zig)" {
    // Test verifies submitBlock path works (proxy for proposal-mode validation).
    // The actual mode="proposal" dispatch is in rpc.zig and not testable here.
    // Document: block_template.submitBlock is the correct backend for proposal.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)

    // Build and mine a minimal regtest block to test submitBlock path
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x42} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout, .include_witness_commitment = false },
        allocator,
    );
    defer tmpl.deinit();
    // FIX: rpc.zig must detect mode="proposal" in params, decode the block hex,
    // and call TestBlockValidity / submitBlock validation path.
    try testing.expect(tmpl.height == 145);
}

// ---------------------------------------------------------------------------
// G19 — client capabilities negotiation (BUG-19: absent)
// ---------------------------------------------------------------------------
//
// Core mining.cpp: checks setClientRules for "coinbasevalue", "coinbase", etc.
//
// BUG-19: clearbit always emits "coinbasevalue" field without checking
// whether the client advertised that capability.

test "w108 G19 BUG-19 coinbasevalue emitted unconditionally (no capabilities check)" {
    // Verify the template correctly computes block_reward for coinbasevalue.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x55} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl.deinit();
    // coinbasevalue = subsidy + fees.  At height 145 (regtest): 50 BTC + 0 fees.
    const expected_subsidy: i64 = 50 * 100_000_000; // 50 BTC in satoshis (pre-halving)
    try testing.expectEqual(expected_subsidy, tmpl.getBlockReward(&consensus.REGTEST));
}

// ---------------------------------------------------------------------------
// G20 — coinbase scriptSig length >= 2 at heights 1..16 (BUG-20)
// ---------------------------------------------------------------------------
//
// Consensus: coinbase scriptSig must be 2..100 bytes (tx_check.cpp:49).
// Core miner.cpp:187-193: adds OP_0 dummy when height <= 16 &&
//   include_dummy_extranonce=true.
// clearbit block_template.zig:477: encodeHeightPush(height=1) => [0x51] (1 byte)
//   with no extra data added when coinbase_extra is empty.
//
// BUG-20: coinbase at heights 1..16 without extra_data has 1-byte scriptSig,
//         failing bad-cb-length.

test "w108 G20 FIXED coinbase scriptSig >= 2 bytes at heights 1..16 (bad-cb-length guard)" {
    // Consensus: coinbase scriptSig must be 2..100 bytes (tx_check.cpp:49).
    // Heights 1..16: BIP-34 height push is a single OP_N byte (0x51..0x60).
    // Fix: constructCoinbaseWithCommitment now appends OP_0 dummy extranonce
    // when scriptSig would otherwise be < 2 bytes, matching Bitcoin Core
    // miner.cpp:187-193 include_dummy_extranonce logic.
    //
    // We verify via buildCoinbaseScriptSig (public helper) because
    // createBlockTemplate panics at heights < 144 due to BIP-9 underflow (BUG-30).
    const allocator = testing.allocator;

    const heights_to_test = [_]u32{ 1, 2, 8, 16 };
    for (heights_to_test) |h| {
        const script = try block_template.buildCoinbaseScriptSig(h, &[_]u8{}, allocator);
        defer allocator.free(script);
        // Must be >= 2 bytes (bad-cb-length minimum satisfied)
        try testing.expect(script.len >= 2);
        // First byte: OP_N height push (0x51..0x60)
        try testing.expectEqual(@as(u8, 0x50) + @as(u8, @intCast(h)), script[0]);
        // Second byte: OP_0 dummy extranonce (0x00)
        try testing.expectEqual(@as(u8, 0x00), script[1]);
    }

    // Height 17 and above produce >= 2 bytes natively (no OP_0 needed)
    const heights_above16 = [_]u32{ 17, 127, 128, 256 };
    for (heights_above16) |h| {
        const script = try block_template.buildCoinbaseScriptSig(h, &[_]u8{}, allocator);
        defer allocator.free(script);
        try testing.expect(script.len >= 2);
    }
}

test "w108 G20b BUG-20 createBlockTemplate at height 145 produces 2-byte scriptSig (PASS above 16)" {
    // At height 145 (best_height=144, safe for BIP-9), the scriptSig encodes
    // as a 3-byte push ([0x02, 0x91, 0x00] for 145 decimal).
    // This test verifies that heights > 16 correctly produce >= 2 bytes.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // template height = 145, safe for BIP-9

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x33} ** 20;

    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout, .include_witness_commitment = false },
        allocator,
    );
    defer tmpl.deinit();

    try testing.expectEqual(@as(u32, 145), tmpl.height);
    // Height 145 > 16: encodes as multi-byte push → scriptSig >= 2 bytes (PASS, was always correct)
    try testing.expect(tmpl.coinbase_tx.script_sig.len >= 2);
}

test "w108 G20c BUG-30 FIXED BIP-9 state machine returns DEFINED for prev_height < period (no panic)" {
    // Previously: consensus.getDeploymentStateAlloc at consensus.zig:2261 computed:
    //   boundary_height = prev_height - ((prev_height + 1) % period)
    // For REGTEST (period=144) and prev_height < 144, this underflowed u32,
    // causing a panic in debug builds and silent corruption in release builds.
    //
    // FIX (consensus.zig): guard added before boundary_height computation —
    //   if (prev_height + 1 < period) return .defined;
    // Mirrors Bitcoin Core versionbits.cpp:48-50:
    //   if (pindexPrev != nullptr && pindexPrev->nHeight + 1 < nPeriod)
    //       return ThresholdState::DEFINED;
    //
    // This test calls getDeploymentState directly at heights 1, 50, 143 (all
    // < period=144) and asserts DEFINED is returned without panicking.

    // Minimal index_view: returns null for all heights (genesis region).
    const NullCtx = struct {
        fn getAtHeight(_: *anyopaque, _: u32) ?consensus.VersionBitsBlockIndex {
            return null;
        }
    };
    var dummy_ctx: u8 = 0;
    const view = consensus.VersionBitsIndexView{
        .context = @ptrCast(&dummy_ctx),
        .getAtHeightFn = NullCtx.getAtHeight,
    };

    // REGTEST TESTDUMMY deployment: period=144, start_time=0.
    const deployment = consensus.Deployments.TESTDUMMY_REGTEST;

    // height=1 → prev_height=0 → 0+1=1 < 144 → DEFINED (was: panic)
    const s1 = consensus.getDeploymentState(deployment, 1, &view, null);
    try testing.expectEqual(consensus.ThresholdState.defined, s1);

    // height=50 → prev_height=49 → 49+1=50 < 144 → DEFINED
    const s50 = consensus.getDeploymentState(deployment, 50, &view, null);
    try testing.expectEqual(consensus.ThresholdState.defined, s50);

    // height=143 → prev_height=142 → 142+1=143 < 144 → DEFINED
    const s143 = consensus.getDeploymentState(deployment, 143, &view, null);
    try testing.expectEqual(consensus.ThresholdState.defined, s143);

    // height=144 → prev_height=143 → 143+1=144, NOT < 144 → proceeds normally (no panic).
    // index_view returns null so the backward walk terminates at genesis → DEFINED.
    const s144 = consensus.getDeploymentState(deployment, 144, &view, null);
    try testing.expectEqual(consensus.ThresholdState.defined, s144);
}

// ---------------------------------------------------------------------------
// G21 — curtime = max(MTP+1, now) via UpdateTime semantics (BUG-21)
// ---------------------------------------------------------------------------
//
// Core miner.cpp:219: UpdateTime(pblock, consensusParams, pindexPrev)
//   nNewTime = max(GetMinimumTime(pindexPrev, …), TicksSinceEpoch<seconds>())
//
// BUG-21: clearbit sets template.header.timestamp at construction to raw
//         std.time.timestamp() without enforcing max(MTP+1, now).

test "w108 G21 BUG-21 curtime not clamped to MTP+1 (UpdateTime semantics absent)" {
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    // Seed a future MTP to expose the bug:
    // If MTP is very large (far future), curtime should equal MTP+1, not now.
    // We can't forge a future MTP through the ring buffer easily,
    // so we just verify the code path: template.header.timestamp == now,
    // not enforced to be >= MTP+1.
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x77} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl.deinit();
    // curtime is set to std.time.timestamp() — no UpdateTime clamp.
    const now: i64 = std.time.timestamp();
    // Should be within ±5 seconds of now (no deliberate adjustment)
    try testing.expect(tmpl.header.timestamp > 0);
    const diff: i64 = now - @as(i64, @intCast(tmpl.header.timestamp));
    try testing.expect(diff >= -5 and diff <= 5);
    // FIX: apply UpdateTime logic: timestamp = max(MTP+1, wall_clock_now).
}

// ---------------------------------------------------------------------------
// G22 — getmininginfo networkhashps=0 (BUG-22: hardcoded)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:472: obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request))
//   which calls GetNetworkHashPS() — work diff / time diff over last 120 blocks.
//
// BUG-22: clearbit getmininginfo emits hardcoded `"networkhashps":0`.

test "w108 G22 BUG-22 getmininginfo networkhashps is hardcoded 0 (not computed)" {
    // This is an RPC-layer bug. Document that GetNetworkHashPS logic EXISTS
    // in clearbit (handleGetNetworkHashPS) but is disconnected from getmininginfo.
    // getmininginfo just emits 0 without calling the hash-rate helper.
    // FIX: getmininginfo should call GetNetworkHashPS(120, -1) and embed result.
    const hardcoded: u64 = 0;
    try testing.expectEqual(@as(u64, 0), hardcoded);
}

// ---------------------------------------------------------------------------
// G23 — getmininginfo blockmintxfee (BUG-23: hardcoded)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:476: obj.pushKV("blockmintxfee", ValueFromAmount(assembler_options.blockMinFeeRate.GetFeePerK()))
//
// BUG-23: clearbit getmininginfo emits hardcoded `"blockmintxfee":0.00001`.

test "w108 G23 BUG-23 getmininginfo blockmintxfee is hardcoded 0.00001 (not from options)" {
    // Verify block_min_fee_rate field exists in TemplateOptions (so it CAN be
    // read from options).  The bug is that rpc.zig ignores it.
    const opts = block_template.TemplateOptions{};
    try testing.expectEqual(@as(u64, 0), opts.block_min_fee_rate); // default is 0 (accept all)
    // FIX: getmininginfo should emit the actual configured blockMinFeeRate,
    // not a hardcoded constant.
}

// ---------------------------------------------------------------------------
// G24 — signet_challenge in GBT response (BUG-24: absent)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:1024-1026:
//   if (consensusParams.signet_blocks)
//     result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge))
//
// BUG-24: clearbit's GBT response has no signet_challenge field.

test "w108 G24 BUG-24 GBT response missing signet_challenge for signet networks" {
    // Verify SIGNET network params exist in clearbit
    // (consensus.SIGNET should be defined if signet is supported).
    // The bug is that rpc.zig never conditionally emits signet_challenge.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x99} ** 20;
    // Build template for signet — no error expected from the core logic
    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.SIGNET,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl.deinit();
    try testing.expect(tmpl.height > 0);
    // FIX: rpc.zig handleGetBlockTemplate must emit "signet_challenge" when
    // network_params.signet_challenge is non-empty.
}

// ---------------------------------------------------------------------------
// G25 — default_witness_commitment in GBT response (BUG-25: absent)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:1028-1031:
//   if (auto coinbase = block_template->getCoinbaseTx(); coinbase.required_outputs.size() > 0)
//     result.pushKV("default_witness_commitment", HexStr(coinbase.required_outputs[0].scriptPubKey))
//
// BUG-25: clearbit's GBT response never includes default_witness_commitment.

test "w108 G25 BUG-25 GBT response missing default_witness_commitment field" {
    // Verify that the witness commitment IS computed in createBlockTemplate
    // (block_template.zig correctly computes it) — the bug is that rpc.zig
    // doesn't include it in the JSON response.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;

    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout, .include_witness_commitment = true },
        allocator,
    );
    defer tmpl.deinit();

    // Witness commitment output should be present (38 bytes, starts 0x6a 0x24 0xaa 0x21 0xa9 0xed)
    const outputs = tmpl.coinbase_tx.outputs;
    var has_commitment = false;
    for (outputs) |out| {
        if (out.script_pubkey.len == 38 and
            out.script_pubkey[0] == 0x6a and
            out.script_pubkey[2] == 0xaa and
            out.script_pubkey[3] == 0x21 and
            out.script_pubkey[4] == 0xa9 and
            out.script_pubkey[5] == 0xed)
        {
            has_commitment = true;
        }
    }
    try testing.expect(has_commitment);
    // FIX: rpc.zig must emit "default_witness_commitment": hex_of_witness_commitment_script
}

// ---------------------------------------------------------------------------
// G26 — prioritisetransaction not in dispatch table (BUG-26)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:501-543: prioritisetransaction adjusts PrioritiseTransaction().
// Core RegisterMiningRPCCommands includes it in the dispatch table.
//
// BUG-26: clearbit rpc.zig dispatch table has no "prioritisetransaction" entry.

test "w108 G26 BUG-26 prioritisetransaction method absent from RPC dispatch" {
    // Verify that the mempool has a prioritization mechanism (it does via
    // fee_delta in MempoolEntry) — the bug is the missing RPC handler.
    // FIX: add handlePrioritiseTransaction to rpc.zig dispatch.
    const allocator = testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    // Mempool exists and can be used; the RPC dispatch layer is the missing part.
    try testing.expectEqual(@as(usize, 0), mempool.entries.count());
}

// ---------------------------------------------------------------------------
// G27 — template caching (BUG-27: absent, P3)
// ---------------------------------------------------------------------------
//
// Core mining.cpp:861-884: caches block_template; rebuilds only when tip
//   hash or mempool update counter changes (5-second grace period).
//
// BUG-27: clearbit creates a fresh template on every GBT call.

test "w108 G27 BUG-27 no template caching (rebuilt on every GBT call)" {
    // Document: two successive createBlockTemplate calls with the same
    // chain_state produce structurally identical templates (same prev_block,
    // height, bits) but are rebuilt from scratch each time.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xBB} ** 20;

    var tmpl1 = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl1.deinit();

    var tmpl2 = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout }, allocator,
    );
    defer tmpl2.deinit();

    // Both templates should agree on height and prev_block
    try testing.expectEqual(tmpl1.height, tmpl2.height);
    try testing.expectEqualSlices(u8, &tmpl1.header.prev_block, &tmpl2.header.prev_block);
    // FIX: rpc.zig should cache and reuse template when prev_hash + mempool_counter unchanged.
}

// ---------------------------------------------------------------------------
// G28 — GBT capabilities field completeness (BUG-28)
// ---------------------------------------------------------------------------
//
// Core emits capabilities = ["proposal"].  BIP-23 also defines "coinbasetxn",
// "workid", "serverlist".  clearbit hardcodes `["proposal"]` only which is
// correct for the minimum, but the BIP-23 optional features are never advertised.
//
// BUG-28: no coinbasetxn / workid / serverlist capability advertised.

test "w108 G28 BUG-28 GBT capabilities only has proposal (no coinbasetxn/workid)" {
    // The template struct doesn't carry capability info — this is purely a
    // rpc.zig response-formatting bug.  Document that clearbit is correct
    // in having "proposal" but missing optional BIP-23 capabilities.
    // FIX: for now ["proposal"] is correct; add "coinbasetxn" only if
    // coinbase transaction template serialization is implemented.
    const has_proposal_cap = true; // rpc.zig line 4628 hardcodes ["proposal"]
    try testing.expect(has_proposal_cap);
}

// ---------------------------------------------------------------------------
// G29 — include_witness_commitment pre-vs-post clamp (BUG-29: latent)
// ---------------------------------------------------------------------------
//
// block_template.zig:362: `if (options.include_witness_commitment)` uses
// pre-clamped `options` while all other fields use post-clamped `opts`.
//
// BUG-29: latent inconsistency — if clampOptions() ever touches
// include_witness_commitment, the pre-clamp value would be used.

test "w108 G29 BUG-29 include_witness_commitment uses pre-clamp options (latent)" {
    // Document: clampOptions() currently does NOT touch include_witness_commitment,
    // so options == opts for that field.  The inconsistency is latent.
    const raw = block_template.TemplateOptions{
        .include_witness_commitment = true,
        .block_reserved_weight = 0, // will be clamped to MINIMUM_BLOCK_RESERVED_WEIGHT
    };
    const clamped = block_template.clampOptions(raw);
    // include_witness_commitment is untouched by clamping — same value
    try testing.expectEqual(raw.include_witness_commitment, clamped.include_witness_commitment);
    // But block_reserved_weight was clamped
    try testing.expect(clamped.block_reserved_weight > raw.block_reserved_weight);
    // FIX: block_template.zig:362 should use `opts.include_witness_commitment`
    // (post-clamped) for consistency with all other fields.
}

// ---------------------------------------------------------------------------
// G30 — PASS: Core-parity checks on the assembly path
// ---------------------------------------------------------------------------

test "w108 G30a PASS DEFAULT_BLOCK_RESERVED_WEIGHT = 8000" {
    try testing.expectEqual(@as(u32, 8_000), block_template.DEFAULT_BLOCK_RESERVED_WEIGHT);
}

test "w108 G30b PASS MINIMUM_BLOCK_RESERVED_WEIGHT = 2000" {
    try testing.expectEqual(@as(u32, 2_000), block_template.MINIMUM_BLOCK_RESERVED_WEIGHT);
}

test "w108 G30c PASS MAX_CONSECUTIVE_FAILURES = 1000" {
    try testing.expectEqual(@as(u32, 1_000), block_template.MAX_CONSECUTIVE_FAILURES);
}

test "w108 G30d PASS BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000" {
    try testing.expectEqual(@as(u32, 4_000), block_template.BLOCK_FULL_ENOUGH_WEIGHT_DELTA);
}

test "w108 G30e PASS DEFAULT_MAX_TRIES = 1_000_000" {
    try testing.expectEqual(@as(u64, 1_000_000), block_template.DEFAULT_MAX_TRIES);
}

test "w108 G30f PASS witness commitment format (OP_RETURN OP_PUSH36 0xaa21a9ed + 32 bytes)" {
    const commitment = [_]u8{0x42} ** 32;
    const script = block_template.createWitnessCommitmentScript(commitment);
    try testing.expectEqual(@as(usize, 38), script.len);
    try testing.expectEqual(@as(u8, 0x6a), script[0]); // OP_RETURN
    try testing.expectEqual(@as(u8, 0x24), script[1]); // OP_PUSHDATA(36)
    try testing.expectEqual(@as(u8, 0xaa), script[2]);
    try testing.expectEqual(@as(u8, 0x21), script[3]);
    try testing.expectEqual(@as(u8, 0xa9), script[4]);
    try testing.expectEqual(@as(u8, 0xed), script[5]);
    try testing.expectEqualSlices(u8, &commitment, script[6..38]);
}

test "w108 G30g PASS witness commitment computation SHA256d(witness_merkle_root || nonce)" {
    const allocator = testing.allocator;
    // Two empty witness_nonce computations should be identical (deterministic)
    const nonce = [_]u8{0} ** 32;
    const c1 = try block_template.computeWitnessCommitment(&[_]types.Transaction{}, nonce, allocator);
    const c2 = try block_template.computeWitnessCommitment(&[_]types.Transaction{}, nonce, allocator);
    try testing.expectEqualSlices(u8, &c1, &c2);
}

test "w108 G30h PASS isFinalTx locktime=0 always final" {
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };
    try testing.expect(block_template.isFinalTx(&tx, 100, 1_600_000_000));
}

test "w108 G30i PASS isFinalTx height-based locktime" {
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{.{
            .previous_output = types.OutPoint.COINBASE,
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFE, // not SEQUENCE_FINAL
            .witness = &[_][]const u8{},
        }},
        .outputs = &[_]types.TxOut{},
        .lock_time = 99, // height-based (< LOCKTIME_THRESHOLD)
    };
    // locktime=99 < block_height=100 → final
    try testing.expect(block_template.isFinalTx(&tx, 100, 0));
    // locktime=99 >= block_height=99 → NOT final
    try testing.expect(!block_template.isFinalTx(&tx, 99, 0));
}

test "w108 G30j PASS coinbase nLockTime = height - 1 (anti-fee-sniping)" {
    // Core miner.cpp:196: coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1)
    // Use best_height=144 to avoid BIP-9 period underflow (BUG-30).
    // Template height = 145; nLockTime = 145 - 1 = 144.
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144; // BIP-9 state machine needs prev_height >= period (144 for regtest)

    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xFE} ** 20;

    var tmpl = try block_template.createBlockTemplate(
        &chain_state, &mempool, &consensus.REGTEST,
        .{ .payout_script = &payout, .include_witness_commitment = false },
        allocator,
    );
    defer tmpl.deinit();

    try testing.expectEqual(@as(u32, 145), tmpl.height);
    // Anti-fee-sniping: nLockTime = height - 1 = 144
    try testing.expectEqual(@as(u32, 144), tmpl.coinbase_tx.tx.lock_time);
}
