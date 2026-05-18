# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (clearbit)

**Wave:** W150 — `MemPoolAccept`, `AcceptToMemoryPool` /
`AcceptSingleTransaction(Internal|AndCleanup)`, `PreChecks` (~782-981),
`PolicyScriptChecks` (~1135-1155), `ConsensusScriptChecks` (~1158-1189),
`FinalizeSubpackage` (~1191-1240), `CheckFeeRate` (~699-712),
`IsStandardTx` / `AreInputsStandard` / `IsWitnessStandard` /
`GetVirtualTransactionSize` / `GetDustThreshold` / `IsDust` /
`PreCheckEphemeralTx`, operator knobs (`-acceptnonstdtxn`,
`-minrelaytxfee`, `-incrementalrelayfee`, `-dustrelayfee`,
`-permitbaremultisig`, `-datacarriersize`, `-mempoolfullrbf`,
`-bytespersigop`, `-maxmempool`, `-mempoolexpiry`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:435-770` — `MemPoolAccept` class,
  `ATMPArgs` (`SingleAccept` / `PackageTestAccept` / `PackageChildWithParents`
  / `SingleInPackageAccept` ctors with `m_bypass_limits`,
  `m_test_accept`, `m_allow_replacement`, `m_allow_sibling_eviction`,
  `m_package_submission`, `m_package_feerates`, `m_client_maxfeerate`),
  `Workspace` (m_vsize / m_base_fees / m_modified_fees /
  m_package_feerate / m_precomputed_txdata).
- `bitcoin-core/src/validation.cpp:782-981` — `PreChecks`:
  CheckTransaction → coinbase reject → `IsStandardTx` →
  MIN_STANDARD_TX_NONWITNESS_SIZE=65 (CVE-2017-12842) →
  `CheckFinalTxAtTip` → `m_pool.exists(wtxid)` /
  `m_pool.exists(txid)` two-step duplicate detection →
  GetConflictTx per-input → `coins_cache.HaveCoinInCache`
  `txn-already-known` cache check → `CalculateLockPointsAtTip` +
  `CheckSequenceLocksAtTip` (BIP-68) → `Consensus::CheckTxInputs`
  (height+1) → `ValidateInputsStandardness` →
  `IsWitnessStandard` → `GetTransactionSigOpCost` (STANDARD_SCRIPT_VERIFY_FLAGS)
  → `MAX_STANDARD_TX_SIGOPS_COST = 16,000` → `CheckFeeRate`
  (rolling min + min_relay) → `PreCheckEphemeralTx` → TRUC checks.
- `bitcoin-core/src/validation.cpp:1135-1155` — `PolicyScriptChecks`:
  `CheckInputScripts` with `STANDARD_SCRIPT_VERIFY_FLAGS` + cache_sigs
  true / cache_full_scripts false; `SpendsNonAnchorWitnessProg` for
  TX_WITNESS_STRIPPED diagnostic on missing-witness failures.
- `bitcoin-core/src/validation.cpp:1158-1189` — `ConsensusScriptChecks`:
  re-runs `CheckInputsFromMempoolAndCache` with
  `GetBlockScriptFlags(tip, chainman)` — the **current block's**
  consensus flag set, which DIFFERS from STANDARD when a soft-fork
  was incorrectly relaxed in STANDARD. On disagreement: `LogError("BUG!
  PLEASE REPORT THIS!")` + `Assume(false)`.
- `bitcoin-core/src/policy/policy.cpp:100-165` — `IsStandardTx`:
  version∈[1,3], tx-size weight ≤ 400 000, scriptSig ≤ 1650 +
  IsPushOnly, scriptPubKey via `IsStandard`/Solver, NULL_DATA cumulative
  ≤ `max_datacarrier_bytes` (default = MAX_OP_RETURN_RELAY = 100 000),
  bare-multisig gated on `permit_bare_multisig` (default TRUE),
  `GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX (=1)`.
- `bitcoin-core/src/policy/policy.cpp:27-69` — `GetDustThreshold` uses
  `dustRelayFeeIn.GetFee(nSize)` with witness-discount when the spent
  scriptPubKey is a witness program; `IsDust` = `nValue <
  GetDustThreshold(txout, dustRelayFeeIn)`.
- `bitcoin-core/src/policy/policy.cpp:170-263` — `CheckSigopsBIP54`
  (per-tx legacy sigop cap = MAX_TX_LEGACY_SIGOPS = 2 500),
  `ValidateInputsStandardness` (NONSTANDARD / WITNESS_UNKNOWN /
  P2SH redeem-script sigops ≤ MAX_P2SH_SIGOPS = 15).
- `bitcoin-core/src/policy/policy.cpp:265-393` — `IsWitnessStandard`:
  P2A + witness rejected; P2SH-wrap unwrap; non-witness-program + witness
  rejected; P2WSH v0 32-byte program — script ≤ 3600, stack-items ≤ 100,
  each item ≤ 80; P2TR v1 32-byte (non-P2SH) — annex rejected, tapscript
  stack item ≤ 80.
- `bitcoin-core/src/policy/policy.h:38-95` — `MAX_STANDARD_TX_WEIGHT=400 000`,
  `MIN_STANDARD_TX_NONWITNESS_SIZE=65`, `MAX_P2SH_SIGOPS=15`,
  `MAX_STANDARD_TX_SIGOPS_COST=MAX_BLOCK_SIGOPS_COST/5=16 000`,
  `MAX_TX_LEGACY_SIGOPS=2 500`, `DEFAULT_INCREMENTAL_RELAY_FEE=100`,
  `DEFAULT_BYTES_PER_SIGOP=20`, `DEFAULT_PERMIT_BAREMULTISIG=true`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS=100`,
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600`,
  `MAX_STANDARD_SCRIPTSIG_SIZE=1650`, `DUST_RELAY_TX_FEE=3000`,
  `DEFAULT_MIN_RELAY_TX_FEE=100`, `DEFAULT_CLUSTER_LIMIT=64`,
  `DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101`, `DEFAULT_ANCESTOR_LIMIT=25`,
  `DEFAULT_DESCENDANT_LIMIT=25`, `MAX_OP_RETURN_RELAY=100 000`,
  `EXTRA_DESCENDANT_TX_SIZE_LIMIT=10 000` (retired in cluster mempool),
  `MAX_DUST_OUTPUTS_PER_TX=1`.
- `bitcoin-core/src/script/interpreter.h:319-345` —
  `STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY | STRICTENC | MINIMALDATA |
   DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK | MINIMALIF | NULLFAIL |
   LOW_S | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | WITNESS_PUBKEYTYPE |
   CONST_SCRIPTCODE | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
   DISCOURAGE_UPGRADABLE_PUBKEYTYPE | DISCOURAGE_OP_SUCCESS`
   (cross-cite W144).
- `bitcoin-core/src/policy/ephemeral_policy.cpp:23-44` —
  `PreCheckEphemeralTx`: tx with dust outputs MUST be zero-fee
  (`base_fee == 0 && mod_fee == 0`); enforces `MAX_DUST_OUTPUTS_PER_TX
  = 1` on `GetDust(tx, dust_relay_rate)`.
- `bitcoin-core/src/policy/rbf.cpp:85-110` —
  `EntriesAndTxidsDisjoint` reject string `"%s spends conflicting
  transaction %s"`.
- `bitcoin-core/src/policy/packages.h:19-25` —
  `MAX_PACKAGE_COUNT=25`, `MAX_PACKAGE_WEIGHT=404 000`.

**Files audited**
- `src/mempool.zig` (12 892 lines) — `Mempool` struct (line 800-900),
  constants (lines 1-150, 328-340 — MAX_MEMPOOL_SIZE, MAX_ANCESTOR_COUNT,
  MAX_DESCENDANT_COUNT, MAX_ANCESTOR_SIZE, MAX_DESCENDANT_SIZE,
  MEMPOOL_EXPIRY, MIN_RELAY_FEE, INCREMENTAL_RELAY_FEE,
  ROLLING_FEE_HALFLIFE, MAX_REPLACEMENT_EVICTIONS,
  MAX_BIP125_RBF_SEQUENCE, MIN_STANDARD_TX_NONWITNESS_SIZE,
  MAX_STANDARD_SCRIPTSIG_SIZE, MAX_OP_RETURN_RELAY,
  MAX_STANDARD_P2WSH_SCRIPT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEMS,
  MAX_STANDARD_WITNESS_STACK_ITEM_SIZE, MAX_ORPHAN_*, MAX_CLUSTER_SIZE,
  MAX_CLUSTER_VBYTES, EXTRA_DESCENDANT_TX_SIZE_LIMIT, TRUC_VERSION,
  MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT), `Mempool.init` (899-934 —
  no max_size arg), `addTransaction` (986-1434 — canonical accept
  path), `acceptToMemoryPool` (1460-1590 — wrapper, two divergent
  test_accept/full_accept code paths), `blockDisconnected`
  (1778-1810 — re-admits txs via addTransaction without
  bypass_limits), `processOrphansForParent` (2041-2108 — admits via
  addTransaction, no broadcastTxInv), `isRBFSignaled` (2177-2183),
  `isRBFOptIn` (2207-2238), `prioritiseTransaction` (2240-2256),
  `applyDelta` / `getModifiedFee` (2257-2269), `checkWitnessStandard`
  (2383-2497), `validateInputsStandardness` (2516-2545),
  `verifyInputScripts` (2547-2740 — IsWitnessStandard + standardness
  + sigops cost + STANDARD script verify + ConsensusScriptChecks
  re-run), `checkStandard` (2774-2923), `checkRBFRules` (2961-3110 —
  BIP-125 Rules 3/4 + ImprovesFeerateDiagram), `isDust` (3113-3144),
  `evict` (3153-3194), `checkDescendantLimits` (3388-3434),
  `checkDescendantLimitsWithCarveout` (3451-3524 — DEAD HELPER, never
  called), `getMinFee` (3661-3699 — rolling minimum fee), `removeForBlock`
  (1726-1755), `addTransactionWithPackageRate` (3752-3997 — parallel
  package-relay admit path).
- `src/mempool_persist.zig` — `loadMempool` (408-595) goes through
  `acceptToMemoryPool(tx, false)` without bypass_limits; persistence
  loader subject to current rolling fee.
- `src/rpc.zig` —
  - `handleSendRawTransaction` (5484-5675): RPC entrypoint that
    **calls `self.mempool.addTransaction(tx)` directly at line 5628**,
    bypassing `acceptToMemoryPool`. Pre-decodes fee + vsize, validates
    against `max_feerate` (default 10 000 000 sat/kvB = 0.10 BTC/kvB).
    Maps a SMALLER subset of MempoolError → reject-reason than
    `acceptToMemoryPool` does (16 errors fall through to "transaction
    rejected").
  - `handleTestMempoolAccept` (9519-9733): single-tx routes through
    `acceptToMemoryPool(tx, true)`. Multi-tx routes through
    `acceptPackage(...) then removeTransaction(...)` — **mutates
    mempool state then unwinds**.
- `src/peer.zig:5005-5055` — P2P `tx` message handler:
  `pool.acceptToMemoryPool(tx_msg, false)`, broadcasts to relay peers
  on success, queues to orphan pool on "missing-inputs" reject.
- `src/main.zig:85-86, 289-296, 712-715, 1803-1804` — CLI flag parser
  for `--maxmempool` (in MiB, default 300) + `--mempoolexpiry` (hours,
  default 336). Both are **parsed-but-not-plumbed**: `Mempool.init`
  accepts no max_size arg, and the policy constants in `mempool.zig`
  are compile-time `pub const`.
- `src/validation.zig:137-276` — `getBlockScriptFlags`,
  `getBlockScriptFlagsForHash`, `getStandardScriptFlags`,
  `getStandardScriptFlagsForHash` (cross-cite W144 BUG-2).

---

## Gate matrix (33 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | ATMP entry-points unified | G1: P2P → `acceptToMemoryPool` | PASS (`peer.zig:5010`) |
| 1 | … | G2: RPC sendrawtransaction → `acceptToMemoryPool` | **BUG-1 (P0-CDIV)** — RPC bypasses ATMP, calls `addTransaction` directly (line 5628) |
| 1 | … | G3: RPC testmempoolaccept → `acceptToMemoryPool(test_accept=true)` | PARTIAL — single-tx PASS; multi-tx **BUG-2 (P0-CDIV)** mutates + unwinds |
| 1 | … | G4: mempool persist load → `acceptToMemoryPool` | PASS (`mempool_persist.zig:531`) but **BUG-3 (P1)** no bypass_limits |
| 1 | … | G5: orphan promotion → admits with broadcast/relay | **BUG-4 (P1)** — `processOrphansForParent:2093` calls `addTransaction` directly (no relay inv) |
| 1 | … | G6: blockDisconnected re-admit → bypass_limits=true | **BUG-5 (P0)** — calls `addTransaction` without bypass; honest reorg txs dropped on rolling-fee floor |
| 2 | PreChecks gates (Core 782-981) | G7: CheckTransaction sanity (vin/vout/dup-input/MoneyRange/null-prevout) | PASS (`addTransaction:1003-1011`) |
| 2 | … | G8: Coinbase rejected up-front | PASS (`addTransaction:1021`) |
| 2 | … | G9: IsStandardTx (version + weight + scriptSig + scriptPubKey + datacarrier + bare-multisig + dust) | PARTIAL — see BUGs 9, 10, 11 |
| 2 | … | G10: MIN_STANDARD_TX_NONWITNESS_SIZE=65 (CVE-2017-12842) | PASS (`checkStandard:2807`) |
| 2 | … | G11: CheckFinalTxAtTip (BIP-113 MTP) | PASS (`addTransaction:1047-1057`) |
| 2 | … | G12: Two-step duplicate check (wtxid then txid) | PASS (`addTransaction:1034-1039`) |
| 2 | … | G13: `txn-already-known` cache check (PreChecks 859-865) | **BUG-6 (P1)** — only RPC path checks `isTransactionConfirmed`; P2P / orphan-resolution paths return "missing-inputs" for already-confirmed tx |
| 2 | … | G14: BIP-68 CheckSequenceLocksAtTip | PASS (`addTransaction:1159-1198`) |
| 2 | … | G15: `Consensus::CheckTxInputs` (CheckTxInputs at tip height+1) | PASS — inlined into addTransaction (per-input MoneyRange + coinbase maturity) |
| 2 | … | G16: ValidateInputsStandardness (CheckSigopsBIP54 + NONSTANDARD/WITNESS_UNKNOWN + MAX_P2SH_SIGOPS) | PASS (`verifyInputScripts:2615` via `validateInputsStandardness`) |
| 2 | … | G17: IsWitnessStandard (P2A/P2SH/P2WSH/P2TR) | PASS (`verifyInputScripts:2611` via `checkWitnessStandard`) |
| 2 | … | G18: MAX_STANDARD_TX_SIGOPS_COST (=16 000) | PASS (`verifyInputScripts:2658-2661`) |
| 2 | … | G19: CheckFeeRate (rolling min + min_relay_feerate) | PARTIAL — see BUG-15 (single-gate vs Core's two-gate) |
| 2 | … | G20: PreCheckEphemeralTx + MAX_DUST_OUTPUTS_PER_TX | **BUG-7 (P1)** — entire ephemeral-dust pipeline missing |
| 3 | PolicyScriptChecks | G21: STANDARD_SCRIPT_VERIFY_FLAGS applied | PASS (`verifyInputScripts:2559+2665-2698`) |
| 3 | … | G22: TX_WITNESS_STRIPPED diagnostic on missing-witness failure | PASS (`verifyInputScripts:2683-2696`) |
| 4 | ConsensusScriptChecks re-run with currentBlockScriptVerifyFlags | G23: re-run with block-tip flags | PARTIAL — runs at `cs.best_height` without block hash (script_flag_exceptions never consulted) |
| 4 | … | G24: "BUG! REPORT THIS" assertion on policy/consensus disagreement | **BUG-8 (P1)** — silent rejection; no LogError/Assume(false) on STANDARD-pass-but-CONSENSUS-fail |
| 5 | IsStandardTx details | G25: bare-multisig limit n∈[1,3] m∈[1,n] | PASS (`checkStandard:2913-2921`) — but **BUG-9 (P1)** no `-permitbaremultisig` knob |
| 5 | … | G26: datacarrier cumulative ≤ MAX_OP_RETURN_RELAY | PASS (`checkStandard:2901-2906`) — but **BUG-9 cross-cite** no `-datacarriersize` knob |
| 6 | Dust threshold | G27: dust = `dustRelayFee.GetFee(input_size + output_size)` | **BUG-10 (P0)** — hardcoded `3 × (spend_size + output_size)` magic constant; no `-dustrelayfee` knob; per-script-type spend sizes hardcoded (close but not exact); does NOT check `IsUnspendable` (size > MAX_SCRIPT_SIZE = 10 000) |
| 7 | Operator knobs | G28: `-acceptnonstdtxn` `-minrelaytxfee` `-incrementalrelayfee` `-dustrelayfee` `-permitbaremultisig` `-datacarriersize` `-mempoolfullrbf` `-bytespersigop` `-limitancestor*` `-limitdescendant*` | **BUG-11 (P0-CDIV)** — NONE of these CLI flags exist; only `--maxmempool` + `--mempoolexpiry`, and both are **parsed-but-not-plumbed** (BUG-12) |
| 7 | … | G29: `-maxmempool` actually applied at runtime | **BUG-12 (P1)** — `Mempool.init` has no max_size arg; `MAX_MEMPOOL_SIZE` is compile-time `pub const usize = 300 * 1_000_000` |
| 8 | RBF wire-parity | G30: reject string "spends conflicting transaction" for EntriesAndTxidsDisjoint | **BUG-13 (P1)** — clearbit emits `"replacement-adds-unconfirmed"` (line 1545), wrong wire string (cross-cite comment-as-confession at line 3024) |
| 8 | … | G31: missing-inputs reject string uniform across paths | **BUG-14 (P1)** — three distinct strings emitted: mempool `"missing-inputs"`, RPC `"missing inputs"` (space), block validation `"bad-txns-inputs-missingorspent"` |
| 9 | CheckFeeRate two-gate | G32: rolling-min AND min-relay gates both fire | **BUG-15 (P1)** — single gate `modified_fee_rate * 1000 < min_fee_sat_kvb`; `getMinFee` returns `max(rolling, MIN_RELAY_FEE)`. Core uses TWO independent gates (TX_RECONSIDERABLE "mempool min fee not met" + TX_RECONSIDERABLE "min relay fee not met") with distinct reject strings |
| 10 | Test_accept semantics (testmempoolaccept) | G33: validate WITHOUT mutation across the full pipeline | **BUG-16 (P0-CDIV)** — single-tx test_accept only runs `checkStandard`; skips fee gate, input lookup, script verify, RBF, sigops cost, IsFinalTx, BIP-68. Returns "allowed=true" for txs that real ATMP would reject |
| 11 | Dead helper at call-site | G34: descendant carve-out implementation called by addTransaction | **BUG-17 (P1)** — `checkDescendantLimitsWithCarveout` (3451-3524) defined but addTransaction (1319) calls non-carveout variant; carve-out implementation is dead code |

---

## BUG-1 (P0-CDIV) — RPC `sendrawtransaction` bypasses `acceptToMemoryPool`, calls `addTransaction` directly

**Severity:** P0-CDIV ("two-pipeline drift / fork-in-the-road" — first
clearbit instance of the pattern at the ATMP entry boundary; the W148
quad confirmed a 4-way three-pipeline drift in clearbit's
block-acceptance path, this is the same pattern in the mempool
admission path).

Bitcoin Core's RPC `sendrawtransaction` constructs a `Workspace`,
sets `ATMPArgs::SingleAccept(test_accept=false, bypass_limits=false,
allow_replacement=true, allow_sibling_eviction=true,
client_maxfeerate=user-supplied)`, then calls
`AcceptSingleTransactionAndCleanup → AcceptSingleTransactionInternal
→ PreChecks → PolicyScriptChecks → ConsensusScriptChecks →
FinalizeSubpackage`. This is the **only** acceptance entry point — P2P,
RPC, persistence loader, package relay all funnel through the same
`AcceptToMemoryPool` envelope. A divergence in any one is a wire-format
hazard because the corresponding peer's mempool will accept what ours
rejects (or vice-versa).

clearbit's `handleSendRawTransaction` (`src/rpc.zig:5484-5675`) builds
a side pipeline:

```zig
// rpc.zig:5628 — direct addTransaction call bypassing acceptToMemoryPool
self.mempool.addTransaction(tx) catch |err| {
    return switch (err) {
        // 17 of MempoolError's ~30 variants are listed here:
        mempool_mod.MempoolError.AlreadyInMempool => ...,
        mempool_mod.MempoolError.InsufficientFee => self.jsonRpcError(RPC_VERIFY_REJECTED, "min relay fee not met", id),
        mempool_mod.MempoolError.DustOutput => self.jsonRpcError(RPC_VERIFY_REJECTED, "dust output", id),
        mempool_mod.MempoolError.NonStandard => self.jsonRpcError(RPC_VERIFY_REJECTED, "non-standard transaction", id),
        mempool_mod.MempoolError.MissingInputs => self.jsonRpcError(RPC_VERIFY_REJECTED, "missing inputs", id),
        // ... 12 more ...
        else => self.jsonRpcError(RPC_VERIFY_REJECTED, "transaction rejected", id),
    };
};
```

`acceptToMemoryPool(tx, false)` itself just calls `addTransaction` and
maps errors, so the **behaviour** is the same — but the WIRE-LEVEL
REJECT REASON differs because the two error-to-string maps are
divergent:

| MempoolError | `acceptToMemoryPool` (1538-1568) | `handleSendRawTransaction` (5634-5650) |
|---|---|---|
| `AlreadyInMempool` | "txn-already-in-mempool" | (success: re-broadcast txid) |
| `SameNonWitnessDataInMempool` | "txn-same-nonwitness-data-in-mempool" | (else: "transaction rejected") |
| `InsufficientFee` | "min relay fee not met" | "min relay fee not met" |
| `MissingInputs` | "missing-inputs" | "missing inputs" *(BUG-14: SPACE not DASH)* |
| `Coinbase` | "coinbase" | "transaction rejected" |
| `InputValuesOutOfRange` | "bad-txns-inputvalues-outofrange" | "transaction rejected" |
| `TooManySigopsCost` | "bad-txns-too-many-sigops" | "transaction rejected" |
| `WitnessStripped` | "witness-stripped" | "transaction rejected" |
| `NonFinal` | "bad-txns-nonfinal" | "transaction rejected" |
| `ImmatureCoinbase` | "bad-txns-premature-spend-of-coinbase" | "transaction rejected" |
| `SequenceLockNotSatisfied` | "non-BIP68-final" | "transaction rejected" |
| `ReplacementSpendsConflicting` | "replacement-adds-unconfirmed" | "transaction rejected" |
| `ScriptSigTooLarge` | "scriptsig-size" | "transaction rejected" |
| `ScriptSigNotPushOnly` | "scriptsig-not-pushonly" | "transaction rejected" |
| `DatacarrierTooLarge` | "datacarrier" | "transaction rejected" |
| `TxOversize` | "bad-txns-oversize" | "transaction rejected" |
| `TxSanityFailed` | "bad-txns-sanity" | "transaction rejected" |
| `TxTooSmall` | "tx-size-small" | "transaction rejected" |
| `TxWeightTooLarge` | "tx-size" | "transaction rejected" |
| `ScriptVerifyFailed` | "mandatory-script-verify-flag-failed" | "transaction rejected" |
| `ClusterSizeLimitExceeded` | "cluster-size-exceeded" | "transaction rejected" |

A wallet client that submits a P2P tx via `sendrawtransaction` and
relies on the reject reason to triage the failure (Core's RPC returns
the canonical Core reject string verbatim; mempool.space, BTCPay,
LND, and CLN all parse these strings) sees:
- 17 out of ~25 possible failure modes degrade to the generic
  `"transaction rejected"` message,
- the four that DO map (`InsufficientFee`, `DustOutput`,
  `MissingInputs`, `NonStandard`) emit free-form English ("dust
  output", "non-standard transaction") instead of Core's tokens
  ("dust", "scriptpubkey"/"version"/…).

**File:** `src/rpc.zig:5628` (the direct addTransaction call) + lines
5634-5650 (the divergent error map).

**Core ref:**
`bitcoin-core/src/rpc/mempool.cpp::sendrawtransaction` →
`BroadcastTransaction` → `node->m_mempool->m_validation_signals` →
`AcceptToMemoryPool` (`bitcoin-core/src/validation.cpp:312-340`).

**Excerpt (clearbit, divergence):**
```zig
// rpc.zig:5628 - RPC path bypasses acceptToMemoryPool wrapper
self.mempool.addTransaction(tx) catch |err| {
    return switch (err) {
        mempool_mod.MempoolError.InsufficientFee => self.jsonRpcError(RPC_VERIFY_REJECTED, "min relay fee not met", id),
        // ... 16 mapped; rest fall through to "transaction rejected"
        else => self.jsonRpcError(RPC_VERIFY_REJECTED, "transaction rejected", id),
    };
};

// vs. mempool.zig:1537-1568 - acceptToMemoryPool path returns canonical reject_reason
self.addTransaction(tx) catch |err| {
    const reason: []const u8 = switch (err) {
        MempoolError.WitnessStripped => "witness-stripped",
        MempoolError.NonFinal => "bad-txns-nonfinal",
        // ... full enumeration including the 12 RPC drops
        else => "rejected",
    };
    return AcceptResult{ .accepted = false, ..., .reject_reason = reason };
};
```

**Impact:**
- wallets / monitoring tools that integrate-test against Core's RPC
  reject strings see degraded diagnostics on clearbit (e.g. a
  witness-stripped tx that Core reports as `"witness-stripped"`
  returns `"transaction rejected"` from clearbit's RPC);
- a `mandatory-script-verify-flag-failed` (signature failure) is
  indistinguishable from a `bad-txns-nonfinal` (locktime) — both
  return generic "transaction rejected", silently masking ECDSA bugs
  in caller code;
- TX_WITNESS_STRIPPED (Core's TxValidationResult value) is what
  the p2p reject-cache layer uses to decide whether to penalize the
  originating peer; the lost diagnostic also means a stripped-witness
  caller cannot diagnose the issue from the RPC return.
- "two-pipeline drift" pattern, ~16th distinct fleet extension; the
  ATMP envelope is meant to be the single source of truth.

---

## BUG-2 (P0-CDIV) — `testmempoolaccept` multi-tx mutates mempool state, then unwinds

**Severity:** P0-CDIV. `testmempoolaccept` is the dry-run / planning
RPC: callers (wallets, fee-bumping bots, batch-builder UIs) call it
to discover whether a tx package WOULD be accepted **without
mutating the mempool**. Core's `AcceptPackage(test_accept=true)` is
implemented at `bitcoin-core/src/validation.cpp:1602-1750` with the
SAME ATMPArgs path as full submission but with `m_test_accept=true`,
which causes `FinalizeSubpackage` to **skip the mempool
insertion** while still computing the full per-tx feerate and
acceptance result.

clearbit's `handleTestMempoolAccept` (`src/rpc.zig:9519-9733`)
splits on single-tx vs multi-tx:
- single-tx (line 9601-9627) routes through
  `mempool.acceptToMemoryPool(tx, true)` — correct path, but see BUG-16
  for what test_accept actually validates.
- **multi-tx** (line 9669-9728): the comment at 9629-9634 admits:

  ```zig
  // Multi-transaction package path: route through acceptPackage.
  // To preserve test_accept semantics (no mempool mutation), we run
  // validation but roll back any additions by working on a snapshot.
  // Since clearbit has no snapshot support, we call acceptPackage and
  // then remove the added transactions — this is safe because the
  // caller holds no lock and test_accept semantics are required.
  ```

  Then at line 9672-9679:
  ```zig
  const pkg_result_or_err = mempool_mod.acceptPackage(self.mempool, valid_txns.items, self.allocator);
  if (pkg_result_or_err) |pkg_result| {
      // Roll back: remove any transactions acceptPackage added (test_accept semantics).
      for (pkg_result.tx_results) |tx_res| {
          if (tx_res.accepted) {
              self.mempool.removeTransaction(tx_res.txid);
          }
      }
      ...
  }
  ```

This is **comment-as-confession** (the comment says "Since clearbit
has no snapshot support, we call acceptPackage and then remove the
added transactions") — the code admits the bug it perpetuates.
Side-effects that are NOT unwound:
1. **ZMQ publish:** `addTransaction:1420-1427` calls
   `zmq.global.publishTx(&tx_hash, raw_alloc)` on every successful
   admission. Subscribers receive a `rawtx` message for a tx that
   clearbit's caller never actually submitted.
2. **Fee estimator:** `addTransaction:1433` calls
   `self.fee_estimator.trackTransaction(tx_hash, fee_rate,
   track_height)`. The estimator's per-bucket histogram is corrupted
   with a "tx admitted at height H, fee rate R" entry that has no
   counterpart confirmation event — distorting fee estimates.
3. **Rolling minimum fee bump:** if the package's admission triggered
   `evict` (line 1330), `evict` calls `trackPackageRemoved` which
   bumps `rolling_minimum_fee_rate`. The bump is permanent; subsequent
   real submissions face an artificially elevated relay floor.
4. **`prioritisetransaction` delta loss:** if any test_accept tx had
   a pre-set `map_deltas` entry that was consumed/cleared by the
   `removeTransaction` call, the operator's priority delta is lost.
5. **Cluster index allocation:** `addTransaction:1334-1338` allocates
   a `cluster_idx = self.next_cluster_index; self.next_cluster_index += 1`
   PERMANENTLY. The counter is monotone; `removeTransaction` does not
   reclaim it. Each `testmempoolaccept` call leaks ≥1 cluster slot.
6. **Concurrent observers (`getrawmempool`, `getmempoolentry`,
   `getmempoolinfo`, ZMQ `mempool` subscribers):** any observer that
   races between the admission and the unwind sees the test tx in
   the mempool. Comment says "safe because the caller holds no lock",
   but `acceptPackage` itself is under `self.mempool.mutex.lock()`
   (line 9671). The window between unlock at 9680 and the next
   request is still inconsistent if the unwind is interleaved with
   relay (`OnTransactionAdded` hooks).
7. **Orphan resolution:** if a test_accept'd tx is a parent that
   un-blocks orphan children in `processOrphansForParent`, those
   children get admitted (and broadcast inv'd to peers!) — and
   `removeTransaction` of the parent then leaves the children in the
   pool, but the inv was already sent for a never-submitted tx tree.

**File:** `src/rpc.zig:9628-9728` (multi-tx test_accept path).

**Core ref:** `bitcoin-core/src/validation.cpp:1432-1602` —
`AcceptMultipleTransactionsInternal` honors `m_test_accept` by
returning the workspace results without calling
`SubmitPackage`. The `FinalizeSubpackage` path does not run.

**Impact:**
- `testmempoolaccept` becomes a side-channel for arbitrary mempool
  mutation. Operator runs the RPC; ZMQ subscribers get rawtx, fee
  estimator updates, cluster index counter increments — even though
  no tx was "actually" submitted.
- Orphan promotion + relay inv from a never-submitted parent =
  silent broadcast hazard. A scripted test_accept on a package whose
  parents had pending orphan children can cause the children's relay
  inv to fire to all connected peers, even though the package was
  never meant to be submitted.

---

## BUG-3 (P1) — Mempool persist loader does not pass `bypass_limits=true`

**Severity:** P1. Bitcoin Core's `LoadMempool` (`mempool_persist.cpp`)
constructs `ATMPArgs::SingleAccept(...)` with **`bypass_limits=true`**
for every persisted tx. Rationale: the txs in `mempool.dat` were
already in OUR mempool at last shutdown — they passed the rolling-fee
floor THEN. On startup, the rolling-fee floor MAY have been bumped
upward by recent eviction history that's now in the rolling-fee
half-life decay tail. Without `bypass_limits`, those legit txs are
re-rejected on the rolling-fee gate.

clearbit's `loadMempool` (`src/mempool_persist.zig:531`) calls
`pool.acceptToMemoryPool(tx, false)` — no bypass. `addTransaction`'s
rolling-fee gate at line 1218-1228 then re-applies the current
`getMinFee()` to every persisted tx.

**File:** `src/mempool_persist.zig:531`.

**Core ref:**
`bitcoin-core/src/kernel/mempool_persist.cpp::LoadMempool` line ~100
sets `args.m_bypass_limits = true` for the persistence load.

**Impact:** on a node where the rolling fee has decayed since last
shutdown (typical: node was busy at shutdown, restarted hours later,
fee has decayed slightly), persisted txs near the prior floor are
silently dropped. Mempool persistence becomes lossy.

---

## BUG-4 (P1) — Orphan-promotion path does not broadcast inv (relay miss)

**Severity:** P1. Bitcoin Core's `ProcessOrphanTx` (net_processing.cpp)
re-runs `AcceptToMemoryPool` for each orphan whose parent arrived,
and on success fires `RelayTransaction(orphan.GetHash())` so peers
learn about the now-admissible orphan via inv.

clearbit's `processOrphansForParent` (`src/mempool.zig:2041-2108`)
goes the wrong direction in two ways:
1. At line 2093 it calls `self.addTransaction(orphan_ptr.tx)` directly,
   not `self.acceptToMemoryPool(tx, false)`. While the underlying
   work is the same, the AcceptResult is discarded (only `promoted`
   counter is returned).
2. There is no broadcast inv after successful admission. The only
   place tx admission emits relay inv is in `peer.zig:5026-5042`
   when the P2P `tx` handler succeeds — orphan promotion is a
   distinct code path that's missing the relay step.

**File:** `src/mempool.zig:2093-2099`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessOrphanTx`
(also calls `RelayTransaction` for successfully promoted orphans).

**Impact:** when an orphan child finally resolves (parent arrives,
child gets admitted), connected peers DON'T learn about it via inv.
They have to re-discover the child via mempool reconciliation or
wait for a `mempool` message poll. Propagation latency for
parent-then-child packages is degraded.

---

## BUG-5 (P0) — `blockDisconnected` re-admit path lacks `bypass_limits` (reorg drops honest txs)

**Severity:** P0. Bitcoin Core's `Chainstate::DisconnectTip` →
`MaybeUpdateMempoolForReorg` calls `addUnchecked` for txs that were
in the disconnected block; the rationale (in
`txmempool.cpp:UpdateTransactionsFromBlock`) is that they were
already mined, so they're known-valid and should re-enter the mempool
without re-validating against the current rolling-fee floor. The
equivalent flag in the ATMP pathway is `bypass_limits=true`.

clearbit's `blockDisconnected` (`src/mempool.zig:1778-1810`) calls
`self.addTransaction(owned_tx)` for every non-coinbase tx in the
disconnected block. `addTransaction` enforces:
- the rolling-fee gate (line 1218-1228),
- standardness (line 1042 — `checkStandard`),
- script verify (line 1238 — `verifyInputScripts`),
- ancestor/descendant limits (line 1296-1320),
- cluster limits (line 1300-1306),
- mempool size limit (line 1328-1331 — may evict OTHER txs to make room).

The rolling-fee gate is the immediate consensus hazard: a tx that
was mined in the disconnected block at fee rate X may now face a
rolling minimum of Y > X (because more recent eviction has bumped it).
Honest reorg txs that Core would re-admit are dropped by clearbit.

The eviction at line 1330 is worse: re-admitting the disconnected
block's txs MAY trigger `evict` of OTHER txs to make room — but those
other txs were unconditionally valid before the reorg. The reorg
silently truncates the mempool by the disconnected-block weight.

**File:** `src/mempool.zig:1805` (the `addTransaction` call without
bypass).

**Core ref:**
`bitcoin-core/src/txmempool.cpp::CTxMemPool::UpdateTransactionsFromBlock`,
called from `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`.

**Impact:** reorgs > 1 block deep silently drop honest txs from the
mempool. On a 6-block reorg (rare but real), the entire mempool can
be reshuffled or partially purged depending on the rolling-fee state.
Cross-impl divergence: Core preserves the mempool across reorgs;
clearbit truncates it.

---

## BUG-6 (P1) — `txn-already-known` check absent from P2P and orphan-resolution paths

**Severity:** P1. Bitcoin Core's `PreChecks` (`validation.cpp:859-866`)
checks whether ANY output of the incoming tx already exists in
`coins_cache`. If so, the tx has already been confirmed (and we got a
late relay) and the correct reject reason is `"txn-already-known"`
rather than `"bad-txns-inputs-missingorspent"` (which would imply
the tx is invalid because of missing inputs).

clearbit's `handleSendRawTransaction` does check this via
`isTransactionConfirmed` (`src/rpc.zig:5570-5573` →
`RPC_VERIFY_ALREADY_IN_CHAIN`) — but only for the RPC entrypoint.
The P2P path (`src/peer.zig:5010 → acceptToMemoryPool → addTransaction`)
never consults the UTXO set for "do we already have outputs of this
hash?" — `addTransaction` checks inputs only. So a late-relay of a
confirmed tx returns `"missing-inputs"`, which:
1. triggers orphan-pool addition at `peer.zig:5050-5053`, parking the
   tx for 5 minutes (`ORPHAN_TX_EXPIRE_TIME`),
2. consumes per-peer orphan-pool budget,
3. produces no diagnostic that distinguishes "we just don't have the
   parent yet" from "the parent is in a block".

**File:** `src/mempool.zig:986-1141` (addTransaction; no
coins_cache.HaveCoinInCache check for `tx_hash`'s OWN outputs).

**Core ref:** `bitcoin-core/src/validation.cpp:858-867`.

**Impact:** late-relayed confirmed txs occupy orphan-pool budget for
5 minutes; per-peer orphan budget is consumed unnecessarily; no
clean diagnostic for the "already mined" case on the P2P path.

---

## BUG-7 (P1) — `PreCheckEphemeralTx` + `MAX_DUST_OUTPUTS_PER_TX` policy missing

**Severity:** P1 (relay-divergence; primary impact is "dust output"
false positives on otherwise-valid Core-policy-conformant txs).

Bitcoin Core implements ephemeral dust policy
(`bitcoin-core/src/policy/ephemeral_policy.cpp:23-44`):
- A tx MAY have up to `MAX_DUST_OUTPUTS_PER_TX = 1` dust outputs IF
  the tx pays ZERO fee (`base_fee == 0 && mod_fee == 0`). The
  intended use is ephemeral CPFP anchors: the parent is zero-fee with
  a single dust output (1 sat or less); the child immediately spends
  the dust and pays for both.
- `IsStandardTx` line 159 enforces `GetDust(tx, dust_relay_fee).size()
  > MAX_DUST_OUTPUTS_PER_TX → "dust"`. With `MAX_DUST_OUTPUTS_PER_TX=1`,
  exactly 1 dust output passes if combined with the ephemeral-tx
  zero-fee constraint.

clearbit's policy:
- `addTransaction` line 1323-1325: `for (tx.outputs) |output| { if
  (isDust(&output)) return MempoolError.DustOutput; }`. ANY dust
  output is rejected, no carve-out.
- No `PreCheckEphemeralTx` function exists.
- No `MAX_DUST_OUTPUTS_PER_TX` constant.

**File:** `src/mempool.zig:1322-1325`.

**Core ref:** `bitcoin-core/src/policy/ephemeral_policy.cpp:23-44`,
`bitcoin-core/src/policy/policy.h:93-95` (`MAX_DUST_OUTPUTS_PER_TX{1}`),
`bitcoin-core/src/policy/policy.cpp:158-162`.

**Impact:** ephemeral-dust CPFP anchors (a forward-compatible relay
pattern Bitcoin Core 25.0+ supports) are rejected by clearbit. Wallets
that build anchor-output zero-fee parents (Lightning splice
proposals, Ark protocols, certain hot wallets) cannot relay those txs
through a clearbit peer.

---

## BUG-8 (P1) — ConsensusScriptChecks silently rejects on STANDARD-pass-but-CONSENSUS-fail; no "BUG! PLEASE REPORT THIS!" diagnostic

**Severity:** P1. Bitcoin Core's `ConsensusScriptChecks`
(`validation.cpp:1158-1189`) re-runs script verification with the
current block-tip consensus flags, AFTER `PolicyScriptChecks` ran
with STANDARD flags. If the two paths disagree (i.e., STANDARD
accepted but CONSENSUS rejected), Core treats this as a critical
internal inconsistency and:

```cpp
LogError("BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags %s, %s", hash.ToString(), state.ToString());
return Assume(false);
```

The rationale (Core comment 1173-1177): "useful in case of bugs in
the standard flags that cause transactions to pass as valid when
they're actually invalid. For instance the STRICTENC flag was
incorrectly allowing certain CHECKSIG NOT scripts to pass". Without
this gate, an attacker can craft txs that pass standard-flag verify
but fail consensus, then mine those into a block to DoS the mempool
(and any peer that has the tx in mempool sees its mempool invalidated
when the block disconnects).

clearbit's `verifyInputScripts` (`src/mempool.zig:2701-2739`) runs
the same two-phase script verify (STANDARD at 2665, then CONSENSUS
at 2716). On consensus disagreement it returns
`MempoolError.ScriptVerifyFailed` silently — no LogError, no
panic/assertion, no operator alert. The "BUG!" diagnostic is gone.

**File:** `src/mempool.zig:2733-2739`.

**Core ref:** `bitcoin-core/src/validation.cpp:1182-1186`.

**Impact:** an attacker can craft tx that exercises an incorrectly
permissive STANDARD flag (cross-cite W144 BUG-13 — clearbit's
STANDARD set is mostly correct, but a future bug could re-open the
gap). clearbit silently rejects; operator/dev never learns the
STANDARD flag set has a bug. Loss of the canary that helped Core
catch STRICTENC bugs in 2018.

---

## BUG-9 (P1) — No `-permitbaremultisig` / `-datacarriersize` / `-acceptnonstdtxn` operator knobs

**Severity:** P1. Bitcoin Core operator knobs for relay policy:
- `-permitbaremultisig` (default true): when false, ALL bare-multisig
  outputs are NONSTANDARD regardless of m/n ratio.
- `-datacarriersize` (default 100 000): max cumulative OP_RETURN bytes.
- `-datacarrier` (default true): when false, ALL OP_RETURN outputs
  are NONSTANDARD.
- `-acceptnonstdtxn` (default false on mainnet, true on regtest):
  when true, skip the entire `IsStandardTx` gate. Required for many
  regression tests + dev workflows.

clearbit's `Mempool` struct (`src/mempool.zig:800-900`) has no
options bag for any of these. `checkStandard` hardcodes:
- bare-multisig: `n∈[1,3]` and `m∈[1,n]` — no permit-all knob.
- datacarrier: `MAX_OP_RETURN_RELAY = 100 000` is a `pub const`.
- IsStandardTx is unconditional.

A clearbit operator who needs to permit non-standard txs for testing
(e.g., spending an old non-standard scriptPubKey, testing a new
script template before relay-policy lands) has no way to opt out of
`checkStandard` short of editing source + recompiling.

**File:** `src/main.zig:445-720` (parseFlags) — no flags;
`src/mempool.zig:800-934` (Mempool struct + init) — no options.

**Core ref:** `bitcoin-core/src/policy/policy.h:48-95`, plus
`bitcoin-core/src/kernel/mempool_options.h` for the options bag.

**Impact:** dev/test workflows that require relaxed standardness
cannot run on clearbit. Cross-impl divergence on regtest mempool
ergonomics. (Also exposes the underlying lack of operator-policy
configurability — a future "mempool policy fork" would require
source patches.)

---

## BUG-10 (P0) — Dust threshold uses hardcoded `3 × (spend + output)` formula; no `-dustrelayfee` knob; missing `IsUnspendable` for oversized scripts

**Severity:** P0. Bitcoin Core's `GetDustThreshold`
(`policy/policy.cpp:27-64`):
1. Returns 0 (never dust) when `scriptPubKey.IsUnspendable()` — i.e.,
   OP_RETURN (`scriptPubKey[0] == OP_RETURN`) OR
   `scriptPubKey.size() > MAX_SCRIPT_SIZE` (= 10 000).
2. Computes `nSize = GetSerializeSize(txout)` + spend overhead, where
   the spend overhead depends on whether the prevout is a witness
   program (`32 + 4 + 1 + (107/4) + 4 = 67.75 → 68` for witness;
   `32 + 4 + 1 + 107 + 4 = 148` for non-witness).
3. Returns `dustRelayFeeIn.GetFee(nSize)` — i.e., `nSize *
   dust_relay_feerate / 1000`. Default `dust_relay_feerate = 3000`
   sat/kvB; configurable via `-dustrelayfee`.

clearbit's `isDust` (`src/mempool.zig:3113-3144`):
```zig
pub fn isDust(output: *const types.TxOut) bool {
    if (output.script_pubkey.len > 0 and output.script_pubkey[0] == 0x6a) return false;

    const stype = script.classifyScript(output.script_pubkey);
    if (stype == .anchor) return output.value != 0;

    const spend_size: i64 = switch (stype) {
        .p2pkh => 148, .p2sh => 91, .p2wpkh => 68, .p2wsh => 108,
        .p2tr => 58, .p2pk => 114, else => 148,
    };
    const output_size: i64 = 8 + 1 + @as(i64, @intCast(output.script_pubkey.len));
    const dust_threshold = 3 * (spend_size + output_size);
    return output.value < dust_threshold;
}
```

Three divergences:

1. **No `IsUnspendable()` for oversized scripts.** Only `script_pubkey[0]
   == 0x6a` skip; a script > MAX_SCRIPT_SIZE (10 000 bytes) is also
   provably unspendable and Core returns dust_threshold=0. clearbit
   gives it the default-148 spend size and a dust_threshold of `3 *
   (148 + 8 + 1 + 10001) ≈ 30 474 sat` — false-positive dust rejection.

2. **No `-dustrelayfee` knob.** The literal `3` is the only dust
   feerate clearbit supports. Operators cannot run with the elevated
   dust threshold that Core supports for "no-dust" relay policies
   (some merchants run -dustrelayfee=10000 to keep tiny outputs off
   their relay).

3. **Spend-size constants are approximations, not Core's exact
   formula.**
   - P2WPKH: clearbit 68; Core `32 + 4 + 1 + 107/4 + 4 = 67.75 → 68`
     (correct round).
   - P2TR: clearbit 58; Core also uses 67.75 → 68 because
     `GetDustThreshold` does NOT special-case Taproot (Core comment:
     "this computation was kept to not further reduce the dust
     level"). **clearbit is 10 sat too low for P2TR dust** — accepts
     dust outputs Core rejects (and vice-versa for P2TR with values
     in the 58-67 sat range).
   - P2WSH: clearbit 108; Core ≈ 68 (witness discount → still 68).
     **clearbit is too HIGH for P2WSH dust — rejects valid Core
     outputs**.
   - P2SH: clearbit 91; Core 148 (no witness discount on legacy P2SH).
     **clearbit is way TOO LOW; accepts dust outputs Core rejects**.

**File:** `src/mempool.zig:3113-3144`.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:27-78`,
`bitcoin-core/src/script/script.h::CScript::IsUnspendable()`.

**Impact:** dust rejection diverges from Core on **every script
type**:
- P2TR: clearbit accepts outputs Core rejects (10-sat gap).
- P2WSH: clearbit rejects outputs Core accepts (40-sat gap).
- P2SH: clearbit accepts outputs Core rejects (57-sat gap).
- Oversized-script: clearbit rejects outputs Core treats as
  unspendable-not-dust.

A network of clearbit+Core peers will reject each other's relayed txs
non-deterministically based on which outputs land in the gaps. Wire-level
relay divergence on a feature (dust threshold) that hashhog tests will
silently miss if the test inputs don't exercise the boundary outputs.

---

## BUG-11 (P0-CDIV) — Comprehensive operator-knob absence (10+ Core relay-policy flags missing)

**Severity:** P0-CDIV ("operator-knob absence", fleet pattern,
~9th distinct clearbit instance per W124+). Core relay-policy
operator knobs that clearbit DOES NOT support:

| Core CLI flag | Default | Purpose | clearbit |
|---|---|---|---|
| `-acceptnonstdtxn` | false (true on regtest) | bypass IsStandardTx | absent |
| `-minrelaytxfee=<sat/kvB>` | 100 | mempool min-relay floor | absent (compile-const `MIN_RELAY_FEE=100`) |
| `-incrementalrelayfee=<sat/kvB>` | 100 | RBF Rule 4 increment | absent (compile-const `INCREMENTAL_RELAY_FEE=100`) |
| `-dustrelayfee=<sat/kvB>` | 3000 | dust threshold base | absent (hardcoded coefficient `3`; cross-cite BUG-10) |
| `-permitbaremultisig` | true | allow bare multisig | absent |
| `-datacarrier` | true | allow OP_RETURN | absent (always allowed) |
| `-datacarriersize=<bytes>` | 100 000 | OP_RETURN cumulative cap | absent (compile-const `MAX_OP_RETURN_RELAY`) |
| `-mempoolfullrbf` | true (24.0+) | accept all-RBF replacement | absent (internal flag `full_rbf` defaults false; no CLI plumbing) |
| `-bytespersigop` | 20 | virtual-size sigop weight | absent |
| `-limitancestorcount` | 25 | mempool ancestor count cap | absent (compile-const `MAX_ANCESTOR_COUNT`) |
| `-limitancestorsize=<kvB>` | 101 | mempool ancestor vbytes cap | absent (compile-const `MAX_ANCESTOR_SIZE`) |
| `-limitdescendantcount` | 25 | mempool descendant count cap | absent (compile-const `MAX_DESCENDANT_COUNT`) |
| `-limitdescendantsize=<kvB>` | 101 | mempool descendant vbytes cap | absent (compile-const `MAX_DESCENDANT_SIZE`) |
| `-mempoolexpiry=<hr>` | 336 | tx expiry hours | **parsed but not plumbed** (BUG-12) |
| `-maxmempool=<MB>` | 300 | mempool total bytes cap | **parsed but not plumbed** (BUG-12) |

The only two flags actually accepted (`--maxmempool` + `--mempoolexpiry`)
are themselves ignored at runtime (see BUG-12). Net result: **clearbit
has zero operational mempool tunability**.

**File:** `src/main.zig:85-86, 289-296` (the two parsed-but-not-plumbed
flags); `src/mempool.zig:1-150` (compile-const policy constants).

**Core ref:** `bitcoin-core/src/init.cpp` (`SetupServerArgs` block
listing all mempool/policy flags), `bitcoin-core/src/kernel/mempool_options.h`
(the options bag those flags populate).

**Impact:** clearbit cannot be reconfigured for:
- regtest workflows requiring relaxed standardness
  (`-acceptnonstdtxn`);
- merchants running stricter dust policies (`-dustrelayfee`);
- nodes that want to disable RBF (`-mempoolfullrbf=0`);
- nodes that want larger mempools (`-maxmempool=2000`);
- testing scenarios that require different limit profiles;
- responding to a network-wide dust-storm by elevating
  `-minrelaytxfee` temporarily.

Cross-fleet pattern: every other hashhog node likely also misses
several of these, but the 13+ missing flags here put clearbit at the
extreme end of "no operator control" — the only `--maxmempool` arg
that IS parsed is also ignored.

---

## BUG-12 (P1) — `--maxmempool` and `--mempoolexpiry` are dead-data plumbing

**Severity:** P1 ("dead-data plumbing" / "wiring-look-but-no-wire"
fleet pattern; ~10th distinct clearbit instance per W138/W141/W144
tracking).

`src/main.zig` parses `--maxmempool=<MiB>` (default 300 — note: spec
calls it MiB, Core uses SI MB) and `--mempoolexpiry=<hours>` (default
336) and writes them into `config.maxmempool` / `config.mempoolexpiry`.
However:
- `Mempool.init` (`src/mempool.zig:899-934`) accepts NO max_size or
  expiry argument.
- `MAX_MEMPOOL_SIZE` is a compile-time `pub const usize = 300 *
  1_000_000` (line 29).
- `MEMPOOL_EXPIRY` is a compile-time `pub const i64 = 14 * 24 * 60 * 60`
  (line 44).
- `evict` (line 3153) uses the compile-time `MAX_MEMPOOL_SIZE`
  unconditionally.
- `removeExpired` (line 3729) uses the compile-time `MEMPOOL_EXPIRY`
  unconditionally.

Grep over `src/` shows ZERO call sites that pass `config.maxmempool`
or `config.mempoolexpiry` to anything mempool-related. They're parsed,
stored in the Config struct, and silently ignored.

**File:** `src/main.zig:85-86, 289-296, 712-715`;
`src/mempool.zig:29, 44, 899` (no consumers).

**Core ref:** `bitcoin-core/src/init.cpp` — `-maxmempool` reads into
`MempoolOptions.max_size_bytes`; `-mempoolexpiry` into
`MempoolOptions.expiry`.

**Impact:** operator who sets `--maxmempool=2000` to allow a larger
mempool on a 128GB-RAM node sees the flag parsed-and-ignored; mempool
stays at the compiled 300 MB. Operator who runs a test scenario with
`--mempoolexpiry=1` for short-lived test txs sees no change. Both
flags appear in `--help` output, suggesting functionality that
doesn't exist.

---

## BUG-13 (P1) — RBF reject string for `EntriesAndTxidsDisjoint` is wrong; comment-as-confession at the violation site

**Severity:** P1 (wire-parity drift; cross-cite "comment-as-confession"
pattern — ~9th distinct clearbit instance).

Bitcoin Core `policy/rbf.cpp:85-110` (`EntriesAndTxidsDisjoint`)
emits the reject string `"%s spends conflicting transaction %s"`.
This is one of the canonical BIP-125 reject strings parsed by
mempool.space, electrs, Lightning daemons that build splice
transactions, etc.

clearbit's `acceptToMemoryPool` error map at line 1545 maps the
relevant error variant:

```zig
MempoolError.ReplacementSpendsConflicting => "replacement-adds-unconfirmed",
```

— which is the reject string from the **OBSOLETE** Core "Rule 2"
("BIP-125 Rule 2: no new unconfirmed inputs"), removed from Core
when EntriesAndTxidsDisjoint replaced it. Worse: the comment at
the code that returns the error variant (`checkRBFRules:3024`)
documents the correct string:

```zig
// Gate 4 / Rule 2 (BIP-125): reject if any input of the replacement spends an
// outpoint owned by a tx that would itself be evicted. Doing the
// eviction first and then discovering this would leave an
// unspendable tx in the mempool (parent gone) — Core checks the
// disjointness up-front and rejects with "spends conflicting
// transaction".  ←─── the comment says "spends conflicting transaction"
```

The comment says "spends conflicting transaction"; the code emits
"replacement-adds-unconfirmed". This is the most direct comment-as-
confession instance to date — the comment directly contradicts the
code on the same gate.

**File:** `src/mempool.zig:1545` (the wrong-string emit) +
`src/mempool.zig:3024` (the comment that knows the right string).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:92`.

**Impact:** wallets parsing the reject string see `"replacement-adds-
unconfirmed"` for an `EntriesAndTxidsDisjoint` reject; they don't
recognize this token (Core removed it ~2022), and either treat the
tx as "unknown error" or misinterpret it as the old Rule-2 violation
(which would warrant a different remediation). Cross-impl divergence
in BIP-125 wire-level diagnostics.

---

## BUG-14 (P1) — Three distinct strings emitted for "missing-inputs" error class

**Severity:** P1 (wire-parity drift; "reject-string wire-parity slippage"
fleet pattern — cross-cite W144 BUG-2 lunarblock 9-token sweep).

The same logical failure ("the spent outpoint is not in the UTXO set
and not in the mempool") produces three different reject strings
depending on the call site:

| Path | String | Core canonical |
|---|---|---|
| Mempool (acceptToMemoryPool) | `"missing-inputs"` | `"bad-txns-inputs-missingorspent"` |
| RPC sendrawtransaction | `"missing inputs"` (SPACE not DASH) | `"bad-txns-inputs-missingorspent"` |
| Block validation | `"bad-txns-inputs-missingorspent"` | `"bad-txns-inputs-missingorspent"` |

Sources:
- `src/mempool.zig:1542` → `MempoolError.MissingInputs => "missing-inputs"`.
- `src/rpc.zig:5637` → `mempool_mod.MempoolError.MissingInputs => self.jsonRpcError(RPC_VERIFY_REJECTED, "missing inputs", id)`.
- `src/block_template.zig:1068`, `src/storage.zig:1322`, `src/rpc.zig:6310` → `"bad-txns-inputs-missingorspent"`.

P2P peer-side reject-handling at `src/peer.zig:5050` matches the
mempool-side string `"missing-inputs"` (`if (std.mem.eql(u8, reason,
"missing-inputs"))`), so the orphan-queue behaviour is correct for
the P2P path — but ANY caller that submits via RPC and parses the
reject-reason will see `"missing inputs"` (space-separated) and fail
the string equality check.

**File:** three sites listed above.

**Core ref:** `bitcoin-core/src/validation.cpp:866` —
`bad-txns-inputs-missingorspent` is the single canonical token.

**Impact:** wire-parity drift across three internal call sites for
the same error; one of them is one-character-off from itself
("missing inputs" vs "missing-inputs"); none of them match Core's
canonical token. The peer-side orphan-handling will silently break
if a future drive-by changes the mempool-side string.

---

## BUG-15 (P1) — `CheckFeeRate` runs a single combined gate instead of Core's two-gate (rolling-min + min-relay)

**Severity:** P1. Bitcoin Core `MemPoolAccept::CheckFeeRate`
(`validation.cpp:699-712`) runs TWO independent gates with distinct
`TxValidationResult::TX_RECONSIDERABLE` reject strings:

```cpp
CAmount mempoolRejectFee = m_pool.GetMinFee().GetFee(package_size);
if (mempoolRejectFee > 0 && package_fee < mempoolRejectFee) {
    return state.Invalid(TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met", strprintf("%d < %d", package_fee, mempoolRejectFee));
}
if (package_fee < m_pool.m_opts.min_relay_feerate.GetFee(package_size)) {
    return state.Invalid(TxValidationResult::TX_RECONSIDERABLE, "min relay fee not met", strprintf(...));
}
```

The TWO distinct rejects let the caller distinguish "your fee is
below the current eviction-driven minimum" (which may decay back down)
from "your fee is below the configured min-relay floor" (which is
operator-controlled).

clearbit's `addTransaction:1218-1228` runs a single combined check:

```zig
const min_fee_sat_kvb = @as(f64, @floatFromInt(self.getMinFee()));
const modified_fee_rate = (modified_fee * 1000) / vsize;
if (modified_fee_rate * 1000.0 < min_fee_sat_kvb) {
    return MempoolError.InsufficientFee;
}
```

`getMinFee` returns `max(rolling, MIN_RELAY_FEE)`, so the gate is
effectively combined. On rejection, both cases emit the same
`InsufficientFee` error → same reject string `"min relay fee not met"`.
The caller cannot distinguish:
- "wait, the rolling minimum is decaying, retry in 10 min" (rolling
  case), from
- "you actually need to pay more fee for this network" (min-relay
  case).

Wallets that auto-bump fees in response to mempool-min-fee rejects
behave wrong: they will keep bumping endlessly even when the issue
is the operator-set min-relay floor.

**File:** `src/mempool.zig:1218-1228`, `getMinFee` at line 3661-3699.

**Core ref:** `bitcoin-core/src/validation.cpp:699-712`.

**Impact:** wallets that retry on `"mempool min fee not met"` (per
Core's distinction) cannot distinguish the rolling-minimum-bump case
from the min-relay case on clearbit. Cross-impl divergence in
fee-bumping logic.

---

## BUG-16 (P0-CDIV) — `acceptToMemoryPool(test_accept=true)` only runs `checkStandard`; misses ALL of: fee gate, script verify, input lookup, RBF, sigops, IsFinalTx, BIP-68

**Severity:** P0-CDIV (testmempoolaccept lies to callers).

Bitcoin Core's `testmempoolaccept` calls
`AcceptSingleTransaction(test_accept=true)` which runs the **full**
ATMP pipeline (`PreChecks → PolicyScriptChecks →
ConsensusScriptChecks`) and only short-circuits in
`FinalizeSubpackage` (skipping the mempool-insertion step). The
returned MempoolAcceptResult is therefore the **exact** answer to
"would this tx be accepted?".

clearbit's `acceptToMemoryPool` at line 1472-1534 takes a separate
branch for `test_accept=true`:

```zig
if (test_accept) {
    // wtxid/txid duplicate check
    if (self.by_wtxid.contains(wtxid)) return ...txn-already-in-mempool;
    if (self.entries.contains(tx_hash)) return ...txn-same-nonwitness-data-in-mempool;

    // ONLY runs checkStandard:
    self.checkStandard(&tx) catch |err| { ... return failure };

    // Returns "allowed=true" if checkStandard passed.
    const weight = computeTxWeight(&tx, self.allocator) catch 0;
    const vsize = (weight + 3) / 4;
    return AcceptResult{ .accepted = true, .fee = 0, ... };  // fee always 0
}
```

What test_accept SKIPS that the full path runs:
1. **Coinbase reject** (only the wtxid-dup check fires; a coinbase
   tx submitted via testmempoolaccept gets through to script verify
   step which is also skipped).
2. **`checkTransactionSanity`** (BIP-30 dup-input, MoneyRange,
   negative values, oversized).
3. **`isFinalTx` BIP-113.** Locktime-bound txs returns allowed=true.
4. **Input lookup** (UTXO + mempool). A tx spending nonexistent
   outputs returns allowed=true.
5. **`MoneyRange` per-input + accumulated.**
6. **Coinbase maturity** (100-conf check).
7. **`isValidMoney` fee check.** A tx with negative fee returns
   allowed=true.
8. **Rolling minimum fee gate / min-relay floor.** A tx paying 1
   sat/kvB returns allowed=true.
9. **BIP-68 sequence locks.**
10. **STANDARD script verify** (all 14 STANDARD flags missing —
    LOW_S, NULLFAIL, MINIMALDATA, CLEANSTACK, MINIMALIF,
    DISCOURAGE_UPGRADABLE_NOPS, etc.).
11. **CONSENSUS script verify** (MANDATORY flags missing — DERSIG,
    CLTV, CSV, NULLDUMMY, P2SH, WITNESS, TAPROOT).
12. **`IsWitnessStandard`** (P2A witness stuffing).
13. **`validateInputsStandardness`** (P2SH redeem-script sigops,
    NONSTANDARD prevout).
14. **`MAX_STANDARD_TX_SIGOPS_COST`** check (16 000 cost cap).
15. **RBF rules** (Rules 3/4 + ImprovesFeerateDiagram).
16. **Cluster/ancestor/descendant limits.**
17. **Dust gate (BUG-10).**

Returned `fee=0` always — Core returns the actual computed fee in
`MempoolAcceptResult::vsize` and the fee-rate fields.

**File:** `src/mempool.zig:1500-1534`.

**Core ref:** `bitcoin-core/src/validation.cpp:1317-1390`
(`AcceptSingleTransactionInternal` honors `m_test_accept` only in
`FinalizeSubpackage`, not by short-circuiting earlier checks).

**Impact:** every wallet / bot / fee-bumper that uses
`testmempoolaccept` to predict whether their tx will succeed:
- gets `"allowed": true` for txs with bad signatures, missing inputs,
  low fee, locktime not satisfied, BIP-68 violation, etc.;
- gets `"vsize": <computed>` correctly but `"fees": {"base":
  0.00000000}` always, breaking fee estimation feedback;
- sees no "missing-inputs" diagnostic for orphan txs (Core reports
  them with TX_MISSING_INPUTS).

The RPC contract is **completely broken** for any non-trivial
validation case. Cross-impl: a wallet that runs the same
testmempoolaccept against clearbit and Core sees opposite answers
("allowed=true" vs "missing-inputs" / "bad-txns-in-belowout" /
"mandatory-script-verify-flag-failed" / etc.).

---

## BUG-17 (P1) — `checkDescendantLimitsWithCarveout` is dead code; CPFP carve-out never applied

**Severity:** P1 ("dead-helper-at-call-site" fleet pattern, ~4th
distinct clearbit instance per W149 tracking — W149 BUG-3/4/5 found
3 instances of this).

`checkDescendantLimitsWithCarveout` (`src/mempool.zig:3451-3524`)
implements Bitcoin Core's pre-cluster CPFP carve-out
(`EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10 000` vbytes): if the
candidate tx has exactly ONE in-mempool ancestor AND is ≤10 000
vbytes, the descendant-count limit for that one ancestor is
relaxed from 25 to 26.

`addTransaction:1319` calls `checkDescendantLimits` (the
non-carveout variant at 3388-3434), not the carveout variant. Grep
confirms `checkDescendantLimitsWithCarveout` has ZERO call sites.

The comment at line 1310-1312 acknowledges that "CPFP carve-out
(EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10_000 vbytes) was active in
pre-cluster Bitcoin Core; removed in Core 28+ when cluster mempool
replaced ancestor/descendant enforcement". So the carve-out helper
was intentionally written and then orphaned when cluster mempool
landed — but the dead-helper sits in the codebase, suggesting
functionality that isn't active.

**File:** `src/mempool.zig:3451-3524` (the dead helper).

**Core ref:** `bitcoin-core/src/policy/policy.h:90`
(`EXTRA_DESCENDANT_TX_SIZE_LIMIT` constant still defined; no other
usages in current Core).

**Impact:** **none functionally** (the cluster mempool gates at
line 1300-1306 supersede the descendant-limit relaxation Core
removed). Listed as a cleanup candidate; the dead-helper-at-call-site
pattern is a code-rot indicator and a maintenance hazard (a future
contributor could mistakenly wire it in, re-introducing pre-cluster
behaviour). Carve-out comment at line 1310 documents the dead code.

---

## BUG-18 (P1) — `processOrphansForParent` admits orphans then doesn't recompute their post-parent fee or refresh against current rolling-min

**Severity:** P1. When an orphan is promoted (parent arrives), Core's
`ProcessOrphanTx` re-enters the full ATMP pipeline. clearbit's
`processOrphansForParent` (`src/mempool.zig:2093`) calls
`addTransaction(orphan_ptr.tx)` directly — which DOES re-validate
fee + script — but does not re-check **all** of:
- the orphan may now be a TRUC-policy violation (parent's TRUC depth
  + this child's),
- the orphan may now exceed cluster vbytes (parent's cluster joined
  ours),
- the orphan may now be CPFP-bumping the parent which itself was
  rolled into a TRUC ancestry,
- the parent may have been admitted at a LOWER feerate than the
  orphan expected — package feerate semantics are lost.

The `addTransaction` path does check cluster + ancestor/descendant
limits per-input, so most of these are caught. The TRUC + package
feerate semantics are the genuinely-missed cases.

**File:** `src/mempool.zig:2041-2108`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessOrphanTx`
+ `bitcoin-core/src/validation.cpp::AcceptSingleTransaction` (full
re-entry).

**Impact:** orphan promotion may admit txs that, taken together with
the parent's actual admission state, violate package or TRUC policy.
Lower-severity because clearbit's TRUC enforcement is fairly tight.

---

## BUG-19 (P1) — `verifyInputScripts` does not pass the block hash to `getStandardScriptFlagsForHash` (cross-cite W144)

**Severity:** P1 (consistent with W144 BUG-2; mempool-specific). `verifyInputScripts`
line 2559 calls `getStandardScriptFlags(cs.best_height, params)` and
line 2716 calls `getBlockScriptFlags(cs.best_height, params)` — both
WITHOUT a block-hash argument. The `script_flag_exceptions` table
(`src/validation.zig:144` `getBlockScriptFlagsForHash`) lookup keys
on the block hash; without the hash, the BIP-16 and Taproot
violator-block exceptions are never applied to the mempool path.

In practice this is correct (the mempool runs at the tip, and both
exception blocks are deep history), but the API misuse mirrors the
same shape as W144 BUG-2's `verifyBlockScriptsParallel` (which DOES
need the block hash but doesn't pass it). The mempool here is
defensible only because the tip is never an exception block; a future
exception block (e.g., a re-org corner case at exception height) would
disagree.

**File:** `src/mempool.zig:2559, 2716`.

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::ConsensusScriptChecks`
calls `GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), ...)`
which IS the tip block index — so Core IS using the tip block hash.

**Impact:** consistency with W144 BUG-2; no current functional impact
because the tip never is an exception block during mempool admission
(the exception blocks are deep history).

---

## BUG-20 (P1) — `MAX_OP_RETURN_RELAY` derivation links MAX_STANDARD_TX_WEIGHT → MAX_OP_RETURN_RELAY = 100 000

**Severity:** P1. Bitcoin Core's `MAX_OP_RETURN_RELAY` is defined
(`policy/policy.h:84`) as `MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR
= 100 000`. clearbit duplicates the same derivation (`mempool.zig:86`)
which couples two policy constants that have nothing to do with each
other semantically.

If a future Core change bumps `MAX_STANDARD_TX_WEIGHT` (proposed in
several Core dev discussions for very large multisig txs), clearbit
would silently bump `MAX_OP_RETURN_RELAY` along with it — a behaviour
change Core would consciously avoid by decoupling.

**File:** `src/mempool.zig:86`.

**Core ref:** `bitcoin-core/src/policy/policy.h:84` — same coupling
exists in Core. Listed here because the derivation is a fragility,
not because it diverges from current Core.

**Impact:** none today; flagged as a fleet-consistency-with-Core item
(both have the same fragility).

---

## BUG-21 (P1) — `addTransaction` does not check tx hasn't been pre-submitted as part of a package validation snapshot

**Severity:** P1 (race + state corruption). The mempool mutex
(`self.mutex`) is held at line 9601-9603 + 9671-9680 by the
testmempoolaccept handler, but `addTransaction` itself doesn't take
the mutex — it's called by external callers who are expected to
hold it. The persistence-loader path
(`src/mempool_persist.zig:531`), the orphan-promotion path
(`src/mempool.zig:2093`), the block-disconnected path
(`src/mempool.zig:1805`), and the package-relay path
(`src/mempool.zig:addTransactionWithPackageRate:3752`) all call
`addTransaction` and none of them acquire `self.mutex`. The
acceptToMemoryPool entry (used by P2P + RPC) is the only one that
takes the mutex (line 9601-9603 for testmempoolaccept; not visible
elsewhere — actually verified, `acceptToMemoryPool` itself doesn't
lock).

Locking is therefore on the caller, and the caller IS NOT taking
it on the P2P path (`peer.zig:5010` calls `pool.acceptToMemoryPool(tx_msg, false)`
without lock acquisition either).

**File:** `src/mempool.zig:986` (addTransaction signature with no
implicit mutex acquisition); call sites at `peer.zig:5010`,
`mempool_persist.zig:531`, `mempool.zig:2093, 1805, 3752`.

**Core ref:** Bitcoin Core enforces `EXCLUSIVE_LOCKS_REQUIRED(cs_main,
m_pool.cs)` at the type level on `AcceptSingleTransactionInternal`,
`PreChecks`, `PolicyScriptChecks`, `ConsensusScriptChecks` — clang
annotations catch any caller that doesn't take both locks.

**Impact:** concurrent P2P `tx` messages from different peers can
race in `addTransaction` (`entries.put`, `by_wtxid.put`,
`spenders.put`, `children` update, `cluster_union.unite`,
`fee_estimator.trackTransaction`). The mempool has no concurrency
safety unless callers always take `self.mutex` — which they don't.
Whether this matters depends on the runtime threading model
(single-threaded P2P-and-RPC vs multi-threaded), but it's a
type-level safety gap with no compiler enforcement.

---

## BUG-22 (P1) — `IsStandardTx` does not enforce `tx.version > 0` separately; relies on `version < 1` which is a `i32` signed compare

**Severity:** P1. Bitcoin Core's `IsStandardTx`
(`policy/policy.cpp:102`) does `if (tx.version > TX_MAX_STANDARD_VERSION
|| tx.version < TX_MIN_STANDARD_VERSION)` where the version type is
`int32_t`. A negative version (e.g., `-1`) fails the `< 1` test.
clearbit's `checkStandard:2776` does `if (tx.version < 1 or
tx.version > TRUC_VERSION) return MempoolError.NonStandard;` —
correct for the standardness gate.

However: `Transaction.version` in clearbit is `i32` (verified in
`src/types.zig` — common across hashhog). The serialization writes
the version as a little-endian 4-byte signed int (matches Core's
`int32_t`). The standardness gate is correct, but the broader
`addTransaction` flow does NOT check `tx.version > 0` for consensus
(only the standardness gate runs that check, and operators who run
`-acceptnonstdtxn=1` (BUG-9: no such knob) would expose the gap).

Since clearbit has no `-acceptnonstdtxn`, this is a no-op today.
Listed for fleet-pattern continuity ("int32-vs-uint32 inconsistency"
companion finding from W132 / W149).

**File:** `src/mempool.zig:2776`.

**Core ref:** `bitcoin-core/src/policy/policy.h:152-153`
(`TX_MIN_STANDARD_VERSION=1`, `TX_MAX_STANDARD_VERSION=3`).

**Impact:** none today (the gate is the only path that decodes
version). Flagged for the int32-vs-uint32 pattern continuity.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 5 (BUG-1, BUG-2, BUG-11, BUG-13 [downgraded to P1
  here], BUG-16)
- **P0:** 3 (BUG-5, BUG-10, … and BUG-11 [could be P0-CDIV])
- **P1:** 14 (BUG-3, BUG-4, BUG-6, BUG-7, BUG-8, BUG-9, BUG-12,
  BUG-13, BUG-14, BUG-15, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21,
  BUG-22)

Recount: P0-CDIV: BUG-1, BUG-2, BUG-11, BUG-16 = 4. P0: BUG-5,
BUG-10 = 2. P1: BUG-3, BUG-4, BUG-6, BUG-7, BUG-8, BUG-9, BUG-12,
BUG-13, BUG-14, BUG-15, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21,
BUG-22 = 16. Total: 4 + 2 + 16 = 22 ✓.

**Fleet patterns confirmed (with cross-cites):**
- **"two-pipeline drift / fork-in-the-road"** (BUG-1) — RPC bypass
  of acceptToMemoryPool envelope; ~16th distinct fleet extension.
- **"three-pipeline drift"** at the entry-points: P2P (✓ATMP),
  RPC sendrawtransaction (BYPASS), testmempoolaccept (single✓ATMP /
  multi BYPASS-AND-UNWIND), persist (✓ATMP no-bypass), orphan
  promotion (DIRECT), blockDisconnected (DIRECT). **5 distinct entry
  points, 3 of them bypass the canonical envelope** — same shape as
  W143's "5 distinct pipelines bypass consensus" finding fleet-wide.
- **"dead-data plumbing / wiring-look-but-no-wire"** (BUG-12) —
  `--maxmempool` and `--mempoolexpiry` parsed-and-ignored; ~10th
  distinct clearbit instance.
- **"comment-as-confession"** — BUG-2 ("Since clearbit has no
  snapshot support, we call acceptPackage and then remove"),
  BUG-13 (comment says "spends conflicting transaction"; code emits
  "replacement-adds-unconfirmed"). The BUG-13 instance is the most
  direct contradiction yet (~9th distinct clearbit instance).
- **"dead-helper-at-call-site"** (BUG-17) — carve-out function
  defined, exported, never called; 4th distinct clearbit instance.
- **"reject-string wire-parity slippage"** (BUG-14) — 3 distinct
  strings for the same error class; cross-cite W144 BUG-2 lunarblock
  9-token sweep + W125 companion.
- **"operator-knob absence"** (BUG-11) — 13+ Core CLI flags absent;
  symmetric to W148 BUG-6 / W149 BUG-5 / W124+ catalogue.
- **"comment-as-confession at violation site"** (BUG-13) — comment
  knows the right wire string; code emits the wrong one.
- **"30-of-30-gates-buggy"** (NOT triggered) — the gate matrix above
  has 33 sub-gates, of which roughly 22 are buggy + 11 are PASS. The
  "30-of-30-gates-buggy" pattern (W138 + W141 instances) requires
  near-total subsystem rot; clearbit's ATMP is partially correct.
  However, the **entry-point envelope** (5 entry points, 3 bypass)
  is uniformly broken on the bypass dimension.
- **"test-accept lies to callers"** (BUG-16) — testmempoolaccept
  returns "allowed=true" for txs the real path would reject. Unique
  to clearbit in fleet tracking; flag for fleet-wide check.

**Two-pipeline guard — distinct extension:**
- **error-mapping pipeline guard:** the two error-to-reject-string
  maps (one in `acceptToMemoryPool`, one in
  `handleSendRawTransaction`) diverge on 17 of ~25 variants. Any
  future variant added to MempoolError must be plumbed in both
  places. First instance of "two error-map pipelines" in fleet
  tracking — extends two-pipeline-guard by one tier (now
  ~17th distinct extension).

**Top three findings:**
1. **BUG-1 (P0-CDIV) — RPC sendrawtransaction bypasses
   acceptToMemoryPool**, calling `addTransaction` directly with a
   smaller divergent error-to-reject-string map. 17 of 25
   MempoolError variants degrade to generic "transaction rejected".
   Wallets parsing reject strings (mempool.space, BTCPay, LND) get
   degraded diagnostics on clearbit. The two error maps form a new
   "two-pipeline guard" instance.
2. **BUG-16 (P0-CDIV) — `acceptToMemoryPool(test_accept=true)`
   only runs `checkStandard`**, skipping ALL of: fee gate, script
   verify, input lookup, RBF, sigops, IsFinalTx, BIP-68, RBF rules,
   cluster/ancestor/descendant limits, dust gate. Returns
   `"allowed": true` for txs with bad signatures, missing inputs,
   low fees, locktime violations. The RPC contract is completely
   broken for non-trivial validation cases. Cross-impl: wallet sees
   "allowed=true" on clearbit, "mandatory-script-verify-flag-failed"
   on Core for the same tx.
3. **BUG-10 (P0) — Dust threshold uses hardcoded `3 × (spend +
   output)` magic constant; per-script-type spend sizes are
   approximations that diverge from Core on every type**: P2TR is
   10 sats too low, P2WSH is 40 sats too high, P2SH is 57 sats too
   low. No `-dustrelayfee` knob; no `IsUnspendable` for oversized
   scripts. Wire-level dust-rejection diverges from Core on every
   script type — a network of clearbit + Core peers will
   non-deterministically reject each other's relayed txs based on
   which outputs land in the gaps.
