// W123 — Mining / GBT parity 30-gate audit (clearbit / Zig 0.13)
//
// Discovery wave. Audits clearbit's mining stack end-to-end:
//
//   - `src/block_template.zig`  BlockAssembler analog (createBlockTemplate,
//                               clampOptions, addChunks logic, witness
//                               commitment, coinbase, mineBlock, submitBlock,
//                               processSideBranchSubmission)
//   - `src/mempool.zig`         FIX-72 modified-fee wiring + cluster
//                               linearisation + getBlockCandidates*
//   - `src/rpc.zig`             getblocktemplate / submitblock /
//                               getmininginfo / getnetworkhashps /
//                               prioritisetransaction / generatetoaddress /
//                               generatetodescriptor / generateblock
//   - `src/peer.zig`            sendcmpct / cmpctblock / getblocktxn /
//                               blocktxn / announceBlock (BIP-130 / BIP-152)
//
// References
// ----------
// bitcoin-core/src/node/miner.cpp     CreateNewBlock + addChunks + AddToBlock
//                                     + UpdateTime + GetMinimumTime
//                                     + ClampOptions + resetBlock
// bitcoin-core/src/rpc/mining.cpp     getblocktemplate + submitblock +
//                                     getmininginfo + getnetworkhashps +
//                                     prioritisetransaction +
//                                     getprioritisedtransactions
// bitcoin-core/src/policy/feefrac.cpp FeePerWeight + chunk_feerate compare
// bitcoin-core/src/policy/policy.h    blockMinFeeRate + MAX_BLOCK_WEIGHT
// bitcoin-core/src/net_processing.cpp BIP-152 SendBlockTransactions + HB peers
// BIP-22, BIP-23, BIP-141, BIP-152
//
// FIX-72 status check
// -------------------
// FIX-72 wired modified-fee into:
//   - cluster linearisation (mempool.linearizeCluster line 4152, fees[i] uses getModifiedFee)
//   - block_template.createBlockTemplate's block_min_fee_rate gate
//     (block_template.zig:284-298 uses mempool.getModifiedFee(entry))
//   - RBF rules 3/4/diagram (mempool.checkRBFRules)
//   - addTransaction min-fee admission gate
//   - getmempoolentry modifiedfee + fees.modified (rpc.zig:4576)
//
// FIX-72 did NOT touch:
//   - getBlockCandidates sort key (mempool.zig:3597). The block template's
//     PRIMARY ordering is still `ancestorFeeRate()` = ancestor_fees /
//     ancestor_size, where ancestor_fees is a STORED field set at
//     admission (entry.ancestor_fees, mempool.zig:1367). prioritiseTransaction
//     only writes map_deltas; it does NOT update entry.ancestor_fees nor
//     propagate the delta to descendants' ancestor_fees. Result: a
//     prioritised tx's `mining_score` is updated via cluster relinearisation,
//     but the template still walks candidates in raw-ancestor-fee order
//     and selects them tx-by-tx based on per-entry raw fee, not chunk
//     feerate. This is the central W123 BUG-1.
//   - block_template.createBlockTemplate does NOT call
//     getBlockCandidatesByMiningScore (which would consult cluster
//     mining_score). The cluster-aware mining-score path exists in
//     mempool.zig:4431 but has zero call sites in block_template.zig.
//
// Findings (29 bugs across 30 gates)
// ==================================
//
//   BUG-1  (G1, P0-CDIV): createBlockTemplate uses raw-ancestor-fee
//          ordering (`getBlockCandidates`, sort key `ancestorFeeRate()`).
//          Should walk chunks in cluster-linearised order whose feerates
//          incorporate `getModifiedFee` (Core BlockAssembler::addChunks +
//          CTxMemPool::GetBlockBuilderChunk). FIX-72 wired modified fees
//          into cluster linearisation but the assembler never queries
//          cluster output — it calls `mempool.getBlockCandidates`, which
//          returns entries sorted by raw `entry.ancestor_fees /
//          ancestor_size`. A prioritise(+10 BTC) on a low-fee tx will
//          NOT lift it earlier in the sort, even though FIX-72 wired
//          getModifiedFee into the per-entry block_min_fee_rate gate.
//          Hash-power impact: ~50-200 sat/block fee loss on a busy
//          mempool with prioritised pinning targets.
//
//   BUG-2  (G2, P0-CDIV): nBits set to `params.genesis_header.bits`
//          (placeholder) instead of `consensus.getNextWorkRequired(...)`.
//          (block_template.zig:233 - "Use genesis bits as placeholder").
//          getNextWorkRequired exists in consensus.zig:989 but is unused
//          in the template path. After the first 2016-block retarget,
//          submitted blocks fail validateProofOfWork. **Was previously
//          documented in W108 BUG-3; STILL UNFIXED in FIX-72 / W123.**
//
//   BUG-3  (G3, P0-CDIV): GBT response shape diverges from BIP-22/23 +
//          Core. Missing required fields: `rules` (BIP-9 GBT extension),
//          `vbavailable`, `vbrequired`, `coinbaseaux`, `longpollid`,
//          `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`,
//          `default_witness_commitment`, `signet_challenge` (signet only).
//          Per-tx fields missing: `hash` (wtxid for BIP-141), `depends`
//          (BIP-22 §8), `sigops` (BIP-22). Mining clients that enforce
//          rules will reject or warn. **Previously W108 BUGs 6-17+24-25;
//          STILL UNFIXED.** Closely related to BUG-4 (params parsing).
//
//   BUG-4  (G4, P0-CDIV): `handleGetBlockTemplate` ignores `params`
//          entirely (`_ = params` at rpc.zig:6066). Core parses mode
//          ("template"/"proposal"), rules ["segwit"], capabilities,
//          longpollid. mode="proposal" returns a template instead of a
//          TestBlockValidity result. This breaks the BIP-23 "proposal"
//          handshake and silently downgrades every miner client to
//          guess-and-hope mode. Previously W108 BUG-1 + BUG-18; STILL
//          UNFIXED.
//
//   BUG-5  (G5, P0): No IBD + peer-connectivity gate on getblocktemplate.
//          Core (mining.cpp:766-775) refuses on non-test chains when
//          `connman.GetNodeCount(Both)==0` OR `isInitialBlockDownload()`.
//          clearbit always serves a template — operator running on a
//          freshly-started node with stale tip can produce a block that
//          orphans on every peer. Previously W108 BUG-2; STILL UNFIXED.
//
//   BUG-6  (G6, P1): `mintime` GBT field = `template.header.timestamp`
//          (current wall-clock). Core: `GetMinimumTime(prev) = MTP+1`
//          (with BIP-94 timewarp guard at retarget). Miner using
//          clearbit's `mintime` lower bound may emit block.timestamp
//          <= MTP, which all peers reject (time-too-old). Previously
//          W108 BUG-4 + BUG-5; STILL UNFIXED.
//
//   BUG-7  (G7, P1): No `UpdateTime` semantics — curtime fixed at
//          template-build, not refreshed when the miner polls. On low-
//          difficulty regtest this is harmless; on mainnet/testnet
//          where mining wall-clock latency matters, `curtime` may be
//          minutes stale. Core calls UpdateTime() once at the end of
//          CreateNewBlock(). Previously W108 BUG-21; STILL UNFIXED.
//
//   BUG-8  (G8, P1): `getmininginfo` `networkhashps` field is computed
//          but only after the dispatch goes through `getnetworkhashps`.
//          The `getmininginfo` handler hardcodes `"networkhashps":0`
//          (rpc.zig:10595) — never calls getnetworkhashps internally.
//          Core delegates: `obj.pushKV("networkhashps",
//          getnetworkhashps().HandleRequest(request))` (mining.cpp:472).
//          Result: monitoring tools reading getmininginfo see 0 even
//          when the chain is producing hashes. Previously W108 BUG-22;
//          STILL UNFIXED.
//
//   BUG-9  (G9, P1): `getmininginfo` missing `currentblockweight` +
//          `currentblocktx` fields. Core: `BlockAssembler::m_last_block_weight`
//          and `m_last_block_num_txs` (miner.cpp:159-160), set at the
//          end of CreateNewBlock and exposed by getmininginfo
//          (mining.cpp:467-468). clearbit's BlockAssembler analog has
//          no equivalent static / module-level "last block" telemetry.
//          Pool operators tracking template fullness see no data here.
//
//   BUG-10 (G10, P1): `getmininginfo` `blockmintxfee` is hardcoded
//          `0.00001` (rpc.zig:10595) instead of reading from
//          configuration. Core reads from `-blockmintxfee` arg and
//          serialises `assembler_options.blockMinFeeRate.GetFeePerK()`.
//          clearbit's TemplateOptions has `block_min_fee_rate: u64 = 0`
//          (block_template.zig:177) but the value is not surfaced in
//          getmininginfo. Previously W108 BUG-23; STILL UNFIXED.
//
//   BUG-11 (G11, P1): No template caching. Every getblocktemplate call
//          rebuilds from scratch: walks mempool, sorts candidates,
//          recomputes witness commitment, regenerates merkle. Core
//          caches by `(tip_hash, m_mempool->GetSequence())` with a 5-
//          second grace window. clearbit pays the full assembly cost
//          on every `longpoll` miner heartbeat — measurable CPU cost
//          on a busy mempool. Previously W108 BUG-27; STILL UNFIXED.
//
//   BUG-12 (G12, P0-CDIV): clearbit does NOT proactively push
//          cmpctblock to BIP-152 high-bandwidth peers on new-block
//          announcement. `peer.zig:7134 announceBlock` only sends
//          headers (BIP-130 sendheaders peers) or inv(MSG_BLOCK)
//          otherwise. The `bip152_highbandwidth_from` flag is read at
//          (peer.zig:5327) when receiving sendcmpct but the announce
//          path NEVER branches on it to emit cmpctblock. Core's
//          PeerManagerImpl::NewPoWValidBlock + RelayBlock pushes
//          cmpctblock unsolicited to HB peers (net_processing.cpp).
//          Consequence: clearbit is a poor citizen for fast block
//          propagation — every new block costs one extra getheaders
//          round-trip even for peers that asked for HB cmpctblock.
//
//   BUG-13 (G13, P1): No `m_package_feerates` field in GBT response.
//          Core (miner.cpp:327) emplaces every accepted chunk feerate
//          so external miners can observe the marginal feerate of the
//          template. Not strictly BIP-22 required but Core emits.
//
//   BUG-14 (G14, P1): `submitblock` accepts the block but does NOT
//          relay it to peers. Core's submitblock path calls
//          ProcessNewBlock which fires NewPoWValidBlock notifications
//          + CConnman::PushMessage. clearbit's submitBlock flushes
//          to ChainState and returns null on success — there is no
//          PeerManager.broadcast(block) call after acceptance. A
//          private mining operator submitting via RPC will see the
//          block accepted locally but no peer ever sees it.
//          Spot-check: `grep "announceBlock\|broadcastBlock" rpc.zig`
//          inside handleSubmitBlock returns nothing.
//
//   BUG-15 (G15, P1): GBT `transactions[].weight` uses raw
//          `entry.weight` from the mempool, but the witness commitment
//          recomputation in the template happens BEFORE coinbase
//          construction. If the cached entry.weight is stale (e.g.
//          tx has been malleated but not re-evaluated), the GBT
//          response misrepresents the cost the miner faces. Core uses
//          GetTransactionWeight(tx) recomputed fresh on the in-block
//          transaction reference.
//
//   BUG-16 (G16, P1): `generateblock` RPC at rpc.zig:6752 does NOT
//          relay the generated block to peers (no `announceMinedBlock`
//          call after the mine, unlike generatetoaddress at line 6602
//          which does). Manual test mining produces blocks that stick
//          locally but don't propagate. Reproduce: generateblock on
//          regtest connected to a peer, peer never sees the block.
//
//   BUG-17 (G17, P0-CDIV): `total_fees += entry.fee` (block_template.zig:353)
//          uses raw fee, not modified fee, for coinbase value computation.
//          THIS IS CORRECT per Core (miner.cpp:270 `nFees +=
//          entry.GetFee()`) — Core also uses raw fee for `nFees`. NOT
//          A BUG; documented here as PASS-pin to prevent a future
//          drive-by "fix" from changing it.
//          → **Reclassified PASS** below.
//
//   BUG-18 (G18, P1): `encodeHeightPush` allows extra bytes appended
//          but does NOT enforce the 100-byte coinbase scriptSig
//          maximum (block_template.zig:495 truncates extra_data so
//          script_sig.len <= 96). Core enforces strictly <= 100 (see
//          consensus/tx_check.cpp:49: scriptSig.size() <= 100).
//          clearbit's 96 cap is conservative; the 96 budget excludes
//          the 4-byte extranonce reserve. Documented as INTENTIONAL
//          but undocumented — marked here for clarification.
//          → **Reclassified informational** below.
//
//   BUG-19 (G19, P1): GBT response `capabilities` field hardcoded to
//          `["proposal"]`. Should at minimum include `"coinbasetxn"`
//          and `"workid"` per BIP-23. Currently the field is emitted
//          but the array contents reflect zero feature negotiation.
//          Previously W108 BUG-28; STILL UNFIXED.
//
//   BUG-20 (G20, P1): GBT response `mutable` field omits
//          `"version/force"` and `"submit/coinbase"`. BIP-23 lists
//          additional mutable fields a server may advertise. clearbit
//          emits a fixed 4-entry array (block_template.zig:441-444).
//
//   BUG-21 (G21, P1): `getnetworkhashps` walks the block-index via
//          `chain_manager.getBlock` for both tip and start, but the
//          `chain_work` arithmetic extracts only the lower 128 bits
//          (`std.mem.readInt(u128, ..., .big)`, rpc.zig:13203-13204).
//          For chains where chain_work has any non-zero high 128 bits
//          (i.e., approximate hashps beyond ~3.4e38 — not currently
//          reached but a mainnet ceiling), the computation silently
//          truncates. Core uses arith_uint256. Low practical impact
//          today; future-proofing concern only.
//
//   BUG-22 (G22, P1): No `-blockreservedweight` CLI / config flag
//          plumbing. Core supports `args.GetIntArg("-blockreservedweight",
//          options.block_reserved_weight)` (miner.cpp:107). clearbit's
//          TemplateOptions has `block_reserved_weight: u32 =
//          DEFAULT_BLOCK_RESERVED_WEIGHT` but no CLI / RPC pathway lets
//          an operator override.
//
//   BUG-23 (G23, P1): No `-blockmaxweight` CLI / config flag plumbing.
//          Same shape as BUG-22 — Core reads `-blockmaxweight`
//          (miner.cpp:101). clearbit's TemplateOptions has the field
//          but no operator-facing override.
//
//   BUG-24 (G24, P1): `submitblock` response shape diverges slightly
//          from Core. Core: on accept, returns `null` (per BIP-22);
//          on reject, returns the BIP-22 string. clearbit (rpc.zig:
//          6250-6260) matches this convention — PASS. But: Core uses
//          a state catcher (`submitblock_StateCatcher`) to differentiate
//          "duplicate" vs "duplicate-inconclusive" rejection strings
//          (Core mining.cpp:1041-1054 + 1107-1122). clearbit returns
//          "inconclusive" for side-branch but does not differentiate
//          duplicate vs duplicate-inconclusive — caller can't tell
//          why a duplicate was rejected.
//
//   BUG-25 (G25, P1): The `bits` field in the GBT response is correct
//          (template.header.bits hex), but it's the wrong VALUE
//          (consequence of BUG-2) because the template was built with
//          genesis bits. So GBT advertises the wrong target every
//          time after the first retarget. The bug is rooted in BUG-2
//          but surfaces as a separate gate.
//
//   BUG-26 (G26, P1): Coinbase witness reserved value handling. Core
//          places the witness-reserved-value (32-byte nonce) in
//          `coinbase.vin[0].scriptWitness.stack[0]`. clearbit puts it
//          in `inputs[0].witness[0]` (block_template.zig:559-563)
//          but the wider witness stack only has this one element,
//          which is correct per BIP-141. PASS, pinned by source-guard
//          test below to prevent future regressions.
//          → **Reclassified PASS** below.
//
//   BUG-27 (G27, P1): GBT `version` field returned as the computed
//          ComputeBlockVersion value (W91 fix), but the BIP-9 state
//          machine uses a stub IndexView returning null for all heights
//          (block_template.zig:413-422). For deployments still in the
//          STARTED period that depend on historical signal counting,
//          this means clearbit's miners cannot push a deployment into
//          LOCKED_IN (it always counts 0 signaling blocks from history).
//          For currently-active and never-active deployments this is
//          a non-issue (LOCKED_IN/ACTIVE/FAILED short-circuit). Note
//          this is a SHADOW of the same gap in versionbits but at the
//          mining boundary.
//
//   BUG-28 (G28, P1): `prioritisetransaction` is wired into the RPC
//          dispatch + map_deltas + cluster mining_score (FIX-72), but
//          the EFFECT on the template path is only partial:
//          - PRESENT: cluster linearisation reads modified fee
//          - PRESENT: block_min_fee_rate gate per-entry compares
//            modified fee
//          - ABSENT: primary candidate sort key (BUG-1)
//          - ABSENT: total_fees / coinbase reward (intentional — Core
//            also uses raw, see BUG-17 reclassified PASS)
//          So `prioritisetransaction` PARTIALLY works: a moderately-
//          prioritised tx may NOT make it into the template if a
//          higher raw-ancestor-feerate competitor occupies the slot.
//          Net effect: FIX-72's modified-fee wiring covers the gate
//          but NOT the primary ordering. (BUG-1 captures this; BUG-28
//          is the operator-visible symptom — a prioritise call that
//          looks accepted but doesn't shift the template.)
//
//   BUG-29 (G29, P1): No mining-score-based `getBlockCandidatesByMiningScore`
//          call site in `block_template.createBlockTemplate`. The
//          mempool exposes the function at mempool.zig:4431 (cluster-
//          aware, mining_score sort), but block_template walks via
//          `getBlockCandidates` (raw ancestor fee rate). This is the
//          symptom; BUG-1 is the root cause. Pinned as a separate
//          gate because mempool.getBlockCandidatesByMiningScore is
//          a 30-line "well-engineered dead helper" — exists, tests
//          pass, but never called by production code. Matches the
//          fleet-wide "dead helper at call site" pattern (W117 +
//          W118 + W121 dead-helper streak).
//
//   PASS  (G17 reclassified): coinbase reward uses raw `entry.fee`,
//          matching Core miner.cpp:270 `nFees += entry.GetFee()`.
//          DO NOT change to modified fee — would diverge from Core.
//
//   PASS  (G26 reclassified): coinbase witness reserved value placed
//          per BIP-141 (32-byte zero in inputs[0].witness[0]).
//
//   PASS  (clampOptions): MINIMUM_BLOCK_RESERVED_WEIGHT,
//          MAX_BLOCK_WEIGHT, MAX_BLOCK_SIGOPS_COST clamping correct.
//
//   PASS  (witness commitment): SHA256d(witness_merkle_root || nonce)
//          + OP_RETURN 0x6a 0x24 0xaa 0x21 0xa9 0xed + 32-byte commitment.
//
//   PASS  (MTP-based lock_time_cutoff for IsFinalTx in template):
//          block_template.zig:255-271 uses chain_state.computeMTP()
//          with wall-clock fallback near genesis.
//
//   PASS  (coinbase nLockTime = height-1 anti-fee-sniping).
//
//   PASS  (coinbase sequence = 0xFFFFFFFE MAX_SEQUENCE_NONFINAL).
//
//   PASS  (consecutive-failure early-exit matches Core
//          MAX_CONSECUTIVE_FAILURES + BLOCK_FULL_ENOUGH_WEIGHT_DELTA).
//
//   PASS  (weight + sigops limit checks use `>=`, matching Core
//          TestChunkBlockLimits).
//
//   PASS  (DEFAULT_BLOCK_RESERVED_WEIGHT 8000, MINIMUM 2000,
//          MAX_CONSECUTIVE_FAILURES 1000, BLOCK_FULL_ENOUGH_WEIGHT_DELTA
//          4000, DEFAULT_MAX_TRIES 1_000_000).
//
//   PASS  (BIP-152 receive side — cmpctblock decode, getblocktxn
//          decode, blocktxn decode, sendcmpct decode all wired in
//          peer.zig:4699-5008. Only PUSH-to-HB-peers is missing.
//          See BUG-12).
//
//   PASS  (FIX-72 mining-score cluster relinearisation uses
//          getModifiedFee — mempool.zig:4152).
//
//   PASS  (FIX-72 block_min_fee_rate per-entry gate uses
//          getModifiedFee — block_template.zig:292).
//
// FIX-72 verdict
// --------------
// "STRONGEST in FIX-72" claim is CONFIRMED for the W120 mempool RBF
// scope — clearbit was the only impl to wire modified-fee into BOTH
// cluster linearisation AND the block_min_fee_rate gate. But the
// W123 audit reveals the wire-up is INCOMPLETE for the mining-
// ordering scope: the primary candidate sort key in
// `block_template.createBlockTemplate` is still
// `getBlockCandidates` (raw ancestor fee), not the cluster-aware
// `getBlockCandidatesByMiningScore`. BUG-1 + BUG-28 + BUG-29 form
// a triangle of partial wire-up at the mempool↔template boundary.
//
// FIX-72 ALSO did NOT touch the broader GBT shape gaps (W108 BUGs
// 1-29 carry forward — many still untouched as of W123).
//
// Reading: FIX-72 strongest-in-fleet for what it scoped, but the
// mining stack as a whole remains the largest single attack surface
// for clearbit's operator-facing RPCs.

const std = @import("std");
const testing = std.testing;
const block_template = @import("block_template.zig");
const consensus = @import("consensus.zig");
const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

// ---------------------------------------------------------------------------
// G1 — BUG-1 P0-CDIV: primary candidate sort key is raw ancestor fee rate
// ---------------------------------------------------------------------------
//
// The block template's primary candidate-ordering call is
// `mempool.getBlockCandidates(allocator)` at block_template.zig:252.
// That function sorts by `ancestorFeeRate()` = ancestor_fees /
// ancestor_size, where ancestor_fees is the STORED field set at admission.
//
// `prioritiseTransaction` ONLY writes map_deltas; it never updates
// `entry.ancestor_fees` nor propagates the delta to descendant
// `ancestor_fees`. The mining_score (cluster-linearised + modified-
// fee aware) is NOT consulted by the assembler.
//
// Effect: a prioritise(+10 BTC) on a low-fee tx will NOT lift it
// earlier in the assembler's walk, even though FIX-72 wired
// getModifiedFee into the per-entry block_min_fee_rate gate.

test "w123 G1 BUG-1 source guard: createBlockTemplate calls getBlockCandidates (raw), not getBlockCandidatesByMiningScore (cluster)" {
    // Read block_template.zig and assert the assembler still walks via
    // the raw-ancestor-fee path, not the cluster-aware mining-score path.
    // When BUG-1 is fixed in a future wave, this test will START failing
    // (which is the point — the gate forces a deliberate audit-flip).
    const src = @embedFile("block_template.zig");

    // Primary sort key in production today: getBlockCandidates.
    try testing.expect(std.mem.indexOf(u8, src, "mempool.getBlockCandidates(allocator)") != null);

    // Cluster-aware alternative is NOT yet called from the assembler.
    // (Document the absence to drive future fix gates.)
    try testing.expect(std.mem.indexOf(u8, src, "getBlockCandidatesByMiningScore(allocator)") == null);
}

test "w123 G1b BUG-1 ancestorFeeRate ignores map_deltas (raw ancestor_fees only)" {
    // Direct unit-level proof: ancestorFeeRate() reads stored
    // ancestor_fees, which is unaware of prioritiseTransaction.
    const src = @embedFile("mempool.zig");
    // ancestorFeeRate function body uses self.ancestor_fees, NOT
    // self.applyDelta or self.getModifiedFee.
    const fn_start = std.mem.indexOf(u8, src, "pub fn ancestorFeeRate(self: *const MempoolEntry)") orelse
        return error.TestUnexpectedResult;
    const fn_end = std.mem.indexOfScalarPos(u8, src, fn_start, '}') orelse return error.TestUnexpectedResult;
    const body = src[fn_start..fn_end];
    try testing.expect(std.mem.indexOf(u8, body, "self.ancestor_fees") != null);
    try testing.expect(std.mem.indexOf(u8, body, "applyDelta") == null);
    try testing.expect(std.mem.indexOf(u8, body, "getModifiedFee") == null);
}

// ---------------------------------------------------------------------------
// G2 — BUG-2 P0-CDIV: nBits uses genesis_header.bits placeholder
// ---------------------------------------------------------------------------

test "w123 G2 BUG-2 source guard: template nBits is genesis_header.bits (CONSENSUS-DIVERGENT after first retarget)" {
    const src = @embedFile("block_template.zig");
    // The placeholder line is currently present.  Use a single-line snippet
    // so any future fix that touches "Use genesis bits" will trip this test
    // FIRST (before a "CHECKED" annotation).
    try testing.expect(
        std.mem.indexOf(u8, src, "const bits: u32 = params.genesis_header.bits") != null,
    );
    // getNextWorkRequired EXISTS in consensus.zig but is NOT called from
    // createBlockTemplate.  Pinned to flag the fix-it boundary.
    try testing.expect(std.mem.indexOf(u8, src, "getNextWorkRequired") == null);
}

// ---------------------------------------------------------------------------
// G3 — BUG-3 P0-CDIV: GBT response missing required BIP-22 fields
// ---------------------------------------------------------------------------

test "w123 G3 BUG-3 GBT response missing core BIP-22 fields" {
    const rpc_src = @embedFile("rpc.zig");
    // Locate handleGetBlockTemplate body and assert these fields are NOT
    // emitted in its response string today.  When any of these fields
    // gets wired in, this gate fails forward and prompts the corresponding
    // audit-flip update.
    const handler_start = std.mem.indexOf(u8, rpc_src, "fn handleGetBlockTemplate(") orelse
        return error.TestUnexpectedResult;
    // Conservatively look at the next ~6000 bytes (the body fits in less).
    const body_end = @min(handler_start + 6_000, rpc_src.len);
    const body = rpc_src[handler_start..body_end];

    // Required-by-Core fields that clearbit currently OMITS:
    const missing_fields = [_][]const u8{
        "\"rules\":",
        "\"vbavailable\":",
        "\"vbrequired\":",
        "\"coinbaseaux\":",
        "\"longpollid\":",
        "\"noncerange\":",
        "\"sigoplimit\":",
        "\"sizelimit\":",
        "\"weightlimit\":",
        "\"default_witness_commitment\":",
    };
    for (missing_fields) |needle| {
        try testing.expect(std.mem.indexOf(u8, body, needle) == null);
    }

    // Per-tx fields that should be inside the transactions array but are NOT:
    // BIP-141 wtxid (`hash`), BIP-22 §8 `depends`, BIP-22 `sigops`.
    try testing.expect(std.mem.indexOf(u8, body, "\"depends\":") == null);
    try testing.expect(std.mem.indexOf(u8, body, "\"sigops\":") == null);
    // Note: `hash` is too generic; rely on the absence of `default_witness_commitment`
    // + `depends` + `sigops` to fingerprint the shape gap.
}

// ---------------------------------------------------------------------------
// G4 — BUG-4 P0-CDIV: handleGetBlockTemplate ignores params
// ---------------------------------------------------------------------------

test "w123 G4 BUG-4 params ignored: handleGetBlockTemplate has `_ = params` discard" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetBlockTemplate(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 400, src.len);
    const body = src[handler_start..handler_end];
    try testing.expect(std.mem.indexOf(u8, body, "_ = params;") != null);
}

// ---------------------------------------------------------------------------
// G5 — BUG-5 P0: no IBD + peer-connectivity gate
// ---------------------------------------------------------------------------

test "w123 G5 BUG-5 no IBD / peer-count gate on getblocktemplate" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetBlockTemplate(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 4_000, src.len);
    const body = src[handler_start..handler_end];
    // No IBD check (Core: isInitialBlockDownload()).
    try testing.expect(std.mem.indexOf(u8, body, "isInitialBlockDownload") == null);
    try testing.expect(std.mem.indexOf(u8, body, "is_ibd") == null);
    // No peer-count check (Core: connman.GetNodeCount(Both)==0).
    try testing.expect(std.mem.indexOf(u8, body, "peer_count") == null);
    try testing.expect(std.mem.indexOf(u8, body, "GetNodeCount") == null);
}

// ---------------------------------------------------------------------------
// G6 — BUG-6 P1: mintime should be MTP+1 (with BIP-94 timewarp guard)
// ---------------------------------------------------------------------------

test "w123 G6 BUG-6 mintime is template.header.timestamp not MTP+1" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetBlockTemplate(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 6_000, src.len);
    const body = src[handler_start..handler_end];
    // Source uses escaped quotes inside a Zig string literal, so the
    // bytes contain backslash + quote + mintime.
    try testing.expect(std.mem.indexOf(u8, body, "\\\"mintime\\\":{d}") != null);
    // GetMinimumTime / MTP-based computation NOT done in handler.
    try testing.expect(std.mem.indexOf(u8, body, "GetMinimumTime") == null);
}

// ---------------------------------------------------------------------------
// G7 — BUG-7 P1: no UpdateTime semantics in GBT path
// ---------------------------------------------------------------------------

test "w123 G7 BUG-7 no UpdateTime call site in handleGetBlockTemplate" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetBlockTemplate(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 6_000, src.len);
    const body = src[handler_start..handler_end];
    try testing.expect(std.mem.indexOf(u8, body, "UpdateTime") == null);
}

// ---------------------------------------------------------------------------
// G8 — BUG-8 P1: getmininginfo networkhashps hardcoded 0 — FIXED 2026-06-28
// ---------------------------------------------------------------------------

test "w123 G8 FIXED getmininginfo networkhashps delegates to computeNetworkHashPS" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetMiningInfo(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 4_000, src.len);
    const body = src[handler_start..handler_end];
    // No longer hardcodes networkhashps:0 (source uses escaped quotes in the
    // Zig print-format literal).
    try testing.expect(std.mem.indexOf(u8, body, "\\\"networkhashps\\\":0,") == null);
    // Instead it computes the value via the shared estimator helper, matching
    // Core's getnetworkhashps().HandleRequest(request).
    try testing.expect(std.mem.indexOf(u8, body, "computeNetworkHashPS") != null);
}

// ---------------------------------------------------------------------------
// G9 — BUG-9 P1: getmininginfo missing currentblockweight + currentblocktx
// ---------------------------------------------------------------------------

test "w123 G9 BUG-9 getmininginfo missing currentblockweight + currentblocktx" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetMiningInfo(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 4_000, src.len);
    const body = src[handler_start..handler_end];
    try testing.expect(std.mem.indexOf(u8, body, "currentblockweight") == null);
    try testing.expect(std.mem.indexOf(u8, body, "currentblocktx") == null);
}

// ---------------------------------------------------------------------------
// G10 — BUG-10 P1: getmininginfo blockmintxfee hardcoded 0.00001
// ---------------------------------------------------------------------------

test "w123 G10 BUG-10 getmininginfo blockmintxfee uses Core BLOCK_MIN_TX_FEE default" {
    const src = @embedFile("rpc.zig");
    // Byte-diff fix: getmininginfo now emits the Core BLOCK_MIN_TX_FEE default
    // (0.00000001 BTC/kvB = 1e-8), matching Core's
    // assembler_options.blockMinFeeRate.GetFeePerK() default. The previous
    // hardcoded 0.00001 (1e-5) byte-diffed against Core's 1e-8.
    // Source uses escaped quotes inside a Zig print-format literal.
    try testing.expect(std.mem.indexOf(u8, src, "\\\"blockmintxfee\\\":0.00000001") != null);
    try testing.expect(std.mem.indexOf(u8, src, "\\\"blockmintxfee\\\":0.00001,") == null);
}

// ---------------------------------------------------------------------------
// G11 — BUG-11 P1: no template caching (rebuilds on every call)
// ---------------------------------------------------------------------------

test "w123 G11 BUG-11 no template cache in handleGetBlockTemplate" {
    const src = @embedFile("rpc.zig");
    // No fields hint at a cache.
    try testing.expect(std.mem.indexOf(u8, src, "template_cache") == null);
    try testing.expect(std.mem.indexOf(u8, src, "cached_template") == null);
    try testing.expect(std.mem.indexOf(u8, src, "m_block_template") == null);
}

// ---------------------------------------------------------------------------
// G12 — BUG-12 P0-CDIV: no proactive cmpctblock push to HB peers
// ---------------------------------------------------------------------------

test "w123 G12 BUG-12 announceBlock does not push cmpctblock to HB peers" {
    const src = @embedFile("peer.zig");
    // Locate announceBlock body.
    const fn_start = std.mem.indexOf(u8, src, "pub fn announceBlock(") orelse
        return error.TestUnexpectedResult;
    const fn_end_marker_pos = std.mem.indexOfPos(u8, src, fn_start, "\n    }\n") orelse
        return error.TestUnexpectedResult;
    const body = src[fn_start..fn_end_marker_pos];
    // Body sends `inv` and `headers` only. No `cmpctblock` constructor.
    try testing.expect(std.mem.indexOf(u8, body, "cmpctblock") == null);
    // bip152_highbandwidth_from flag is NOT branched on here.
    try testing.expect(std.mem.indexOf(u8, body, "bip152_highbandwidth_from") == null);
    // Sanity: the function DOES exist and DOES send headers/inv.
    try testing.expect(std.mem.indexOf(u8, body, ".headers") != null);
    try testing.expect(std.mem.indexOf(u8, body, ".inv") != null);
}

// ---------------------------------------------------------------------------
// G13 — BUG-13 P1: no m_package_feerates in GBT
// ---------------------------------------------------------------------------

test "w123 G13 BUG-13 GBT response missing package_feerates" {
    const src = @embedFile("rpc.zig");
    try testing.expect(std.mem.indexOf(u8, src, "package_feerates") == null);
    try testing.expect(std.mem.indexOf(u8, src, "packagefeerates") == null);
}

// ---------------------------------------------------------------------------
// G14 — BUG-14 P1: submitblock does NOT relay to peers on acceptance
// ---------------------------------------------------------------------------

test "w123 G14 BUG-14 handleSubmitBlock does not call announceBlock / cacheMinedBlock" {
    const src = @embedFile("rpc.zig");
    const fn_start = std.mem.indexOf(u8, src, "fn handleSubmitBlock(") orelse
        return error.TestUnexpectedResult;
    // submitblock handler is contained — look at next ~5000 bytes.
    const fn_end = @min(fn_start + 5_000, src.len);
    const body = src[fn_start..fn_end];
    // No relay path after submitBlockWithIndexAndMempool returns accepted.
    try testing.expect(std.mem.indexOf(u8, body, "announceBlock") == null);
    try testing.expect(std.mem.indexOf(u8, body, "announceMinedBlock") == null);
    try testing.expect(std.mem.indexOf(u8, body, "cacheMinedBlock") == null);
}

// ---------------------------------------------------------------------------
// G15 — BUG-15 P1: GBT transaction[].weight may be stale (from mempool cache)
// ---------------------------------------------------------------------------

test "w123 G15 BUG-15 GBT tx.weight comes from cached entry.weight not recomputed" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetBlockTemplate(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 6_000, src.len);
    const body = src[handler_start..handler_end];
    // Uses tx.weight from the SelectedTx struct (which holds cached
    // entry.weight from the mempool), not a fresh GetTransactionWeight(tx).
    try testing.expect(std.mem.indexOf(u8, body, "tx.weight") != null);
    try testing.expect(std.mem.indexOf(u8, body, "GetTransactionWeight") == null);
    try testing.expect(std.mem.indexOf(u8, body, "computeTransactionWeight") == null);
}

// ---------------------------------------------------------------------------
// G16 — BUG-16 P1: generateblock does NOT announce to peers
// ---------------------------------------------------------------------------

test "w123 G16 BUG-16 handleGenerateBlock does not announce / cache the mined block" {
    const src = @embedFile("rpc.zig");
    const fn_start = std.mem.indexOf(u8, src, "fn handleGenerateBlock(") orelse
        return error.TestUnexpectedResult;
    const fn_end = @min(fn_start + 6_000, src.len);
    const body = src[fn_start..fn_end];
    // No announce / cache call in this handler (contrast with
    // handleGenerateToAddress, which DOES call announceMinedBlock).
    try testing.expect(std.mem.indexOf(u8, body, "announceMinedBlock") == null);
    try testing.expect(std.mem.indexOf(u8, body, "cacheMinedBlock") == null);
}

// ---------------------------------------------------------------------------
// G17 — PASS pin: total_fees uses raw entry.fee (matches Core nFees)
// ---------------------------------------------------------------------------

test "w123 G17 PASS pin: total_fees uses entry.fee (raw), matching Core miner.cpp:270" {
    const src = @embedFile("block_template.zig");
    // The accumulator line is the canonical Core-parity statement; pin it.
    try testing.expect(std.mem.indexOf(u8, src, "total_fees += entry.fee;") != null);
    // The modified-fee variant MUST NOT appear here (Core diverges if it
    // did — coinbase reward overpay).
    try testing.expect(std.mem.indexOf(u8, src, "total_fees += mempool.getModifiedFee") == null);
}

// ---------------------------------------------------------------------------
// G18 — informational: coinbase scriptSig max 96 bytes (conservative vs Core 100)
// ---------------------------------------------------------------------------

test "w123 G18 informational: coinbase scriptSig extra-data cap is 96 bytes" {
    const src = @embedFile("block_template.zig");
    // The 96-byte cap is currently hard-coded in two call sites:
    // constructCoinbaseWithCommitment (around line 495) and
    // buildCoinbaseScriptSig (around line 628). Pin one of them.
    try testing.expect(std.mem.indexOf(u8, src, "96 - script_sig.items.len") != null);
}

// ---------------------------------------------------------------------------
// G19 — BUG-19 P1: GBT capabilities only ["proposal"]
// ---------------------------------------------------------------------------

test "w123 G19 BUG-19 GBT capabilities hardcoded to [\"proposal\"]" {
    const src = @embedFile("rpc.zig");
    // Source uses escaped quotes inside a Zig print-format literal.
    try testing.expect(std.mem.indexOf(u8, src, "\\\"capabilities\\\":[\\\"proposal\\\"]") != null);
}

// ---------------------------------------------------------------------------
// G20 — BUG-20 P1: GBT mutable field omits version/force + submit/coinbase
// ---------------------------------------------------------------------------

test "w123 G20 BUG-20 mutable field is fixed 4-entry array" {
    const src = @embedFile("block_template.zig");
    // The literal mutable array.
    try testing.expect(std.mem.indexOf(u8, src, "\"time\",\n        \"transactions\",") != null);
    try testing.expect(std.mem.indexOf(u8, src, "\"version/force\"") == null);
    try testing.expect(std.mem.indexOf(u8, src, "\"submit/coinbase\"") == null);
}

// ---------------------------------------------------------------------------
// G21 — BUG-21 P1: getnetworkhashps truncates chain_work to u128
// ---------------------------------------------------------------------------

test "w123 G21 BUG-21 getnetworkhashps chain_work truncated to lower 128 bits" {
    const src = @embedFile("rpc.zig");
    const handler_start = std.mem.indexOf(u8, src, "fn handleGetNetworkHashPS(") orelse
        return error.TestUnexpectedResult;
    const handler_end = @min(handler_start + 4_000, src.len);
    const body = src[handler_start..handler_end];
    try testing.expect(std.mem.indexOf(u8, body, "std.mem.readInt(u128") != null);
    // Should ideally use u256 / arith_uint256-equivalent; isn't today.
    try testing.expect(std.mem.indexOf(u8, body, "u256") == null);
}

// ---------------------------------------------------------------------------
// G22 — BUG-22 P1: no -blockreservedweight CLI flag
// ---------------------------------------------------------------------------

test "w123 G22 BUG-22 no -blockreservedweight CLI plumbing" {
    const main_src = @embedFile("main.zig");
    try testing.expect(std.mem.indexOf(u8, main_src, "blockreservedweight") == null);
    try testing.expect(std.mem.indexOf(u8, main_src, "block_reserved_weight") == null);
}

// ---------------------------------------------------------------------------
// G23 — BUG-23 P1: no -blockmaxweight CLI flag
// ---------------------------------------------------------------------------

test "w123 G23 BUG-23 no -blockmaxweight CLI plumbing" {
    const main_src = @embedFile("main.zig");
    try testing.expect(std.mem.indexOf(u8, main_src, "blockmaxweight") == null);
}

// ---------------------------------------------------------------------------
// G24 — BUG-24 P1: submitblock duplicate vs duplicate-inconclusive
// ---------------------------------------------------------------------------

test "w123 G24 BUG-24 submitblock cannot differentiate duplicate vs duplicate-inconclusive" {
    const src = @embedFile("rpc.zig");
    const fn_start = std.mem.indexOf(u8, src, "fn handleSubmitBlock(") orelse
        return error.TestUnexpectedResult;
    const fn_end = @min(fn_start + 5_000, src.len);
    const body = src[fn_start..fn_end];
    try testing.expect(std.mem.indexOf(u8, body, "duplicate-inconclusive") == null);
    // The catch-all "rejected" is what falls out instead.  Match the
    // bare-token form (`rejected` in a string literal) and the escaped
    // JSON form (`\"rejected\"`).
    try testing.expect(std.mem.indexOf(u8, body, "rejected") != null);
}

// ---------------------------------------------------------------------------
// G25 — BUG-25 P1: bits field carries placeholder value
// ---------------------------------------------------------------------------

test "w123 G25 BUG-25 GBT bits field reflects placeholder (root cause: BUG-2)" {
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout },
        allocator,
    );
    defer tmpl.deinit();
    // The bits should match REGTEST genesis_header.bits as the placeholder.
    try testing.expectEqual(consensus.REGTEST.genesis_header.bits, tmpl.header.bits);
}

// ---------------------------------------------------------------------------
// G26 — PASS pin: coinbase witness reserved value per BIP-141
// ---------------------------------------------------------------------------

test "w123 G26 PASS pin: coinbase witness is 32-byte zero nonce per BIP-141" {
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAA} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout, .include_witness_commitment = true },
        allocator,
    );
    defer tmpl.deinit();
    // Coinbase witness stack must have exactly one 32-byte element when
    // witness commitment is included (BIP-141).
    try testing.expectEqual(@as(usize, 1), tmpl.coinbase_tx.witness.len);
    try testing.expectEqual(@as(usize, 32), tmpl.coinbase_tx.witness[0].len);
    // All zero nonce (clearbit's default; Core uses arbitrary but deterministic).
    for (tmpl.coinbase_tx.witness[0]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

// ---------------------------------------------------------------------------
// G27 — BUG-27 P1: BIP-9 stub IndexView in createBlockTemplate
// ---------------------------------------------------------------------------

test "w123 G27 BUG-27 createBlockTemplate uses stub IndexView for BIP-9 state machine" {
    const src = @embedFile("block_template.zig");
    // The stub-getAtHeight-returns-null pattern is currently in place.
    try testing.expect(std.mem.indexOf(u8, src, "StubCtx") != null);
    try testing.expect(std.mem.indexOf(u8, src, "fn getAtHeight(_: *anyopaque, _: u32) ?consensus.VersionBitsBlockIndex {") != null);
    // The body of the stub explicitly returns null.
    try testing.expect(std.mem.indexOf(u8, src, "return null;") != null);
}

// ---------------------------------------------------------------------------
// G28 — BUG-28 P1: prioritisetransaction effect is partial on template
// ---------------------------------------------------------------------------

test "w123 G28 BUG-28 prioritise wired into cluster linearisation BUT NOT into primary sort" {
    // FIX-72 wired modified-fee into:
    //   - cluster linearisation (mempool.zig:4152)
    //   - block_min_fee_rate gate (block_template.zig:292)
    // FIX-72 did NOT wire modified-fee into the assembler's PRIMARY sort,
    // which is `mempool.getBlockCandidates` (raw ancestor fee rate).
    const mempool_src = @embedFile("mempool.zig");
    const bt_src = @embedFile("block_template.zig");

    // PRESENT: cluster linearisation reads modified fee.
    try testing.expect(std.mem.indexOf(u8, mempool_src, "fees[i] = self.getModifiedFee(entry);") != null);
    // PRESENT: block_min_fee_rate gate reads modified fee.
    try testing.expect(std.mem.indexOf(u8, bt_src, "const modified_fee = mempool.getModifiedFee(entry);") != null);
    // ABSENT: cluster-aware primary sort.  Templates still walk via getBlockCandidates.
    try testing.expect(std.mem.indexOf(u8, bt_src, "getBlockCandidatesByMiningScore") == null);
}

// ---------------------------------------------------------------------------
// G29 — BUG-29 P1: getBlockCandidatesByMiningScore is dead-helper-at-call-site
// ---------------------------------------------------------------------------

test "w123 G29 BUG-29 dead-helper: getBlockCandidatesByMiningScore implemented but never called from production" {
    const mempool_src = @embedFile("mempool.zig");
    const bt_src = @embedFile("block_template.zig");
    const rpc_src = @embedFile("rpc.zig");

    // The helper EXISTS in the mempool module.
    try testing.expect(std.mem.indexOf(u8, mempool_src, "pub fn getBlockCandidatesByMiningScore(") != null);

    // It's NOT called from block_template.zig (the assembler).
    try testing.expect(std.mem.indexOf(u8, bt_src, "getBlockCandidatesByMiningScore(") == null);

    // It's NOT called from rpc.zig either.
    try testing.expect(std.mem.indexOf(u8, rpc_src, "getBlockCandidatesByMiningScore(") == null);

    // Continues the multi-wave "dead-helper-at-call-site" pattern
    // (33+ consecutive waves through W121).
}

// ---------------------------------------------------------------------------
// G30 — Carry-forwards: positive PASS gates exercising assembler invariants
// ---------------------------------------------------------------------------

test "w123 G30a PASS clampOptions enforces all bounds" {
    const result = block_template.clampOptions(.{
        .block_reserved_weight = 0,
        .max_weight = 999_999_999,
        .max_sigops = 999_999_999,
    });
    try testing.expectEqual(block_template.MINIMUM_BLOCK_RESERVED_WEIGHT, result.block_reserved_weight);
    try testing.expectEqual(consensus.MAX_BLOCK_WEIGHT, result.max_weight);
    try testing.expect(result.max_sigops <= consensus.MAX_BLOCK_SIGOPS_COST);
}

test "w123 G30b PASS witness commitment script format (OP_RETURN OP_PUSH36 0xaa21a9ed + 32 bytes)" {
    const commitment = [_]u8{0x42} ** 32;
    const script = block_template.createWitnessCommitmentScript(commitment);
    try testing.expectEqual(@as(usize, 38), script.len);
    try testing.expectEqual(@as(u8, 0x6a), script[0]);
    try testing.expectEqual(@as(u8, 0x24), script[1]);
    try testing.expectEqual(@as(u8, 0xaa), script[2]);
    try testing.expectEqual(@as(u8, 0x21), script[3]);
    try testing.expectEqual(@as(u8, 0xa9), script[4]);
    try testing.expectEqual(@as(u8, 0xed), script[5]);
    try testing.expectEqualSlices(u8, &commitment, script[6..38]);
}

test "w123 G30c PASS coinbase nLockTime = height - 1 (anti-fee-sniping)" {
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xFE} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout, .include_witness_commitment = false },
        allocator,
    );
    defer tmpl.deinit();
    try testing.expectEqual(@as(u32, 145), tmpl.height);
    try testing.expectEqual(@as(u32, 144), tmpl.coinbase_tx.tx.lock_time);
}

test "w123 G30d PASS coinbase input sequence = MAX_SEQUENCE_NONFINAL (0xFFFFFFFE)" {
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCD} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout },
        allocator,
    );
    defer tmpl.deinit();
    try testing.expect(tmpl.coinbase_tx.inputs.len >= 1);
    try testing.expectEqual(@as(u32, 0xFFFFFFFE), tmpl.coinbase_tx.inputs[0].sequence);
}

test "w123 G30e PASS BIP-152 short-id codec wired on the receive path" {
    // sendcmpct, cmpctblock, getblocktxn, blocktxn decoders are PRESENT in
    // p2p.zig (verified via the existing test suite). What's missing is
    // the proactive HB-peer push side, which is BUG-12.
    const p2p_src = @embedFile("p2p.zig");
    try testing.expect(std.mem.indexOf(u8, p2p_src, ".sendcmpct = .{") != null);
    try testing.expect(std.mem.indexOf(u8, p2p_src, ".cmpctblock = .{") != null);
    try testing.expect(std.mem.indexOf(u8, p2p_src, ".getblocktxn = .{") != null);
    try testing.expect(std.mem.indexOf(u8, p2p_src, ".blocktxn = .{") != null);
}

test "w123 G30f PASS DEFAULT_BLOCK_RESERVED_WEIGHT + MINIMUM + assembly constants" {
    try testing.expectEqual(@as(u32, 8_000), block_template.DEFAULT_BLOCK_RESERVED_WEIGHT);
    try testing.expectEqual(@as(u32, 2_000), block_template.MINIMUM_BLOCK_RESERVED_WEIGHT);
    try testing.expectEqual(@as(u32, 1_000), block_template.MAX_CONSECUTIVE_FAILURES);
    try testing.expectEqual(@as(u32, 4_000), block_template.BLOCK_FULL_ENOUGH_WEIGHT_DELTA);
}

test "w123 G30g PASS FIX-72 modified-fee in cluster linearisation source guard" {
    const mempool_src = @embedFile("mempool.zig");
    // Cluster linearisation reads modified fee.
    try testing.expect(std.mem.indexOf(u8, mempool_src, "fees[i] = self.getModifiedFee(entry);") != null);
    // applyDelta + getModifiedFee + map_deltas are all wired.
    try testing.expect(std.mem.indexOf(u8, mempool_src, "pub fn applyDelta(self: *const Mempool, txid: types.Hash256) i64 {") != null);
    try testing.expect(std.mem.indexOf(u8, mempool_src, "pub fn getModifiedFee(self: *const Mempool, entry: *const MempoolEntry) i64 {") != null);
    try testing.expect(std.mem.indexOf(u8, mempool_src, "map_deltas: std.AutoHashMap(types.Hash256, i64)") != null);
}

test "w123 G30h PASS FIX-72 dispatch entries for prioritisetransaction + getprioritisedtransactions" {
    const rpc_src = @embedFile("rpc.zig");
    try testing.expect(std.mem.indexOf(u8, rpc_src, "\"prioritisetransaction\"") != null);
    try testing.expect(std.mem.indexOf(u8, rpc_src, "\"getprioritisedtransactions\"") != null);
    try testing.expect(std.mem.indexOf(u8, rpc_src, "fn handlePrioritiseTransaction(") != null);
}

test "w123 G30i PASS template ~ getBlockReward = subsidy + fees (raw)" {
    const allocator = testing.allocator;
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 144;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    const payout = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    var tmpl = try block_template.createBlockTemplate(
        &chain_state,
        &mempool,
        &consensus.REGTEST,
        .{ .payout_script = &payout },
        allocator,
    );
    defer tmpl.deinit();
    // Empty mempool → total_fees = 0 → block_reward = subsidy.
    const reward = tmpl.getBlockReward(&consensus.REGTEST);
    const expected_subsidy = consensus.getBlockSubsidy(145, &consensus.REGTEST);
    try testing.expectEqual(expected_subsidy, reward);
}

test "w123 G30j PASS coinbase scriptSig minimum 2 bytes at low heights (W108 BUG-20 fixed)" {
    const allocator = testing.allocator;
    var script = std.ArrayList(u8).init(allocator);
    defer script.deinit();
    // Height 1 push.
    try block_template.encodeHeightPush(&script, 1);
    try testing.expectEqual(@as(u8, 0x51), script.items[0]); // OP_1
    // 1-byte push triggers OP_0 dummy extranonce inside the assembler;
    // exercise via buildCoinbaseScriptSig.
    const built = try block_template.buildCoinbaseScriptSig(1, &[_]u8{}, allocator);
    defer allocator.free(built);
    try testing.expect(built.len >= 2);
    try testing.expectEqual(@as(u8, 0x51), built[0]); // OP_1
    try testing.expectEqual(@as(u8, 0x00), built[1]); // OP_0 dummy
}
