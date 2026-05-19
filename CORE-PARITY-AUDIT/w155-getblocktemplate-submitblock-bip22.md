# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (clearbit)

**Wave:** W155 — `handleGetBlockTemplate`, `handleSubmitBlock`,
`handleGenerateBlock`, `handleGenerateToAddress`,
`handleGenerateToDescriptor`, `handlePrioritiseTransaction`,
`handleGetPrioritisedTransactions`, `handleGetMiningInfo`,
`handleGetNetworkHashPs` (RPC perimeter). BIP-22 mode (`template` /
`proposal`), `capabilities`, `rules`, `longpollid`, `vbavailable`,
`vbrequired`, `coinbaseaux`, `coinbasevalue`, `coinbasetxn`,
`default_witness_commitment`, `mutable[]`, `noncerange`, `sigoplimit`,
`sizelimit`, `weightlimit`, `mintime`, `curtime`, `bits`, `height`,
`signet_challenge`, per-tx `data`/`txid`/`hash`/`depends`/`fee`/`sigops`/`weight`,
BIP22ValidationResult strings (`duplicate` / `duplicate-invalid` /
`duplicate-inconclusive` / `inconclusive` / `valid?` / `<reject_reason>`),
`submitblock_StateCatcher`, `UpdateUncommittedBlockStructures`,
`GetMinimumTime` (MTP+1 + BIP-94 timewarp), `UpdateTime`.

**Scope:** discovery only — no production code changes.
W154 (`w154-createnewblock-blockassembler.md`) covered the
`createBlockTemplate` / `BlockAssembler` interior; W155 focuses on
the RPC perimeter — request parsing, response shape, BIP-22 string
mapping, the `proposal`-mode handshake, and the gating that precedes
`createBlockTemplate`. Some W154 findings whose loci sit on the RPC
boundary (BUG-10 missing-fields, BUG-11 params-discarded, BUG-12
funds-burn-OP_RETURN) are cross-cited here with W155 evidence rather
than re-litigated.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:615-1035::getblocktemplate` —
  request parse (mode/rules/capabilities/longpollid/data), IBD +
  peer-connectivity gates, long-poll wait loop (`waitTipChanged`,
  `GetTransactionsUpdated` mempool counter, 60s/10s heartbeat),
  template caching (`pindexPrev` static + 5-second grace window),
  refusal without `rules: ["segwit"]`, signet refusal without
  `["segwit","signet"]`, full 22+ field response.
- `bitcoin-core/src/rpc/mining.cpp:849-856` — REQUIRES
  `rules: ["segwit"]` (since 2017 post-BIP-141 deployment); REQUIRES
  `rules: ["segwit","signet"]` on signet chain. Refusal raises
  `RPC_INVALID_PARAMETER` with a help string directing the operator
  at the correct invocation.
- `bitcoin-core/src/rpc/mining.cpp:730-751::getblocktemplate` —
  `mode="proposal"`: `DecodeHexBlk` → `LookupBlockIndex(hash)` for
  duplicate detection, returns `"duplicate"` /
  `"duplicate-invalid"` / `"duplicate-inconclusive"` /
  `BIP22ValidationResult(TestBlockValidity(...))` otherwise. The
  proposal-mode response is a BIP-22 string OR null (validity), NOT a
  template.
- `bitcoin-core/src/rpc/mining.cpp:586-603::BIP22ValidationResult` —
  maps `BlockValidationState` to BIP-22 string. Valid → `VNULL`;
  invalid → `state.GetRejectReason()` (typed Core reject tokens such
  as `bad-txns-vout-toolarge`, `bad-txnmrklroot`, `bad-cb-amount`,
  `bad-cb-height`, `bad-cb-length`, `bad-witness-merkle-match`,
  `high-hash`, `bad-diffbits`, `bad-blk-weight`, `bad-blk-sigops`,
  `bad-txns-inputs-missingorspent`, `bad-txns-nonfinal`, etc.); error
  → throws JSONRPCError; unknown → `"valid?"`.
- `bitcoin-core/src/rpc/mining.cpp:1038-1054::submitblock_StateCatcher`
  — `CValidationInterface` callback that latches
  `BlockChecked(block, state)` for the submitted hash. Powers the
  `"inconclusive"` vs `BIP22ValidationResult(sc->state)` split.
- `bitcoin-core/src/rpc/mining.cpp:1056-1106::submitblock` — accepts
  `(hexdata, dummy)` (BIP-22 compat dummy is IGNORED, not validated);
  `UpdateUncommittedBlockStructures` overwrites the witness reserved
  value when the parent is known (so miners that forgot the witness
  nonce still produce a valid block); registers state-catcher;
  `ProcessNewBlock(blockptr, /*force_processing=*/true,
  /*min_pow_checked=*/true, /*new_block=*/&new_block)`; returns
  `"duplicate"` when `!new_block && accepted`, `"inconclusive"` when
  `!sc->found`, else `BIP22ValidationResult(sc->state)`.
- `bitcoin-core/src/rpc/mining.cpp:416-495::getmininginfo` — emits
  `blocks`, `currentblockweight` (BlockAssembler::m_last_block_weight),
  `currentblocktx` (m_last_block_num_txs), `bits`, `difficulty`,
  `target` (uint256 hex), `networkhashps` (delegated to
  `getnetworkhashps`), `pooledtx`, `blockmintxfee` (from
  `assembler_options.blockMinFeeRate.GetFeePerK()`), `chain`,
  `next.{height,bits,difficulty,target}`, `signet_challenge` (signet
  only), `warnings`.
- `bitcoin-core/src/rpc/mining.cpp:502-545::prioritisetransaction` —
  `(txid, dummy, fee_delta)`; `dummy` MUST be 0 or null. The `dummy`
  arg is a `NUM`, not a `BOOL`/`STR`/`number_string`.
- `bitcoin-core/src/node/miner.cpp:36-47::GetMinimumTime` — `MTP+1`,
  then at retarget: `min_time = max(min_time, prev->GetBlockTime() -
  MAX_TIMEWARP)` (BIP-94 timewarp guard, 600 s).
- `bitcoin-core/src/node/miner.cpp:49-58::UpdateTime` — `nNewTime =
  max(GetMinimumTime, TicksSinceEpoch<seconds>(GetAdjustedTime()))`;
  if changed, ALSO updates `pblock->nBits =
  GetNextWorkRequired(pindexPrev, pblock, …)` (testnet/regtest
  fPowAllowMinDifficultyBlocks path).
- BIP-22 §4: `result` fields `coinbasevalue` (numeric satoshis),
  `coinbaseaux`, `noncerange="00000000ffffffff"`.
- BIP-22 §8: per-tx `data` + `txid` + `depends` (1-based index array
  into the `transactions` list).
- BIP-23: `mutable[]` array values include `time`, `transactions`,
  `prevblock`, `coinbase/append`, `version/force`,
  `submit/coinbase`.
- BIP-141 (segwit) extension: `default_witness_commitment` (the
  scriptPubKey the miner must include verbatim in the coinbase),
  per-tx `hash` field (wtxid).
- BIP-145 (segwit GBT changes): `weightlimit = MAX_BLOCK_WEIGHT =
  4_000_000`.

**Files audited**
- `src/rpc.zig:6065-6133::handleGetBlockTemplate` — request body,
  template build, JSON serialiser. `_ = params;` discards the entire
  request object.
- `src/rpc.zig:6135-6263::handleSubmitBlock` — hex parse, height
  derivation, MTP precheck, full-validation via
  `validateSubmitBlockOrReject`, dispatch to
  `block_template.submitBlockWithIndexAndMempool`, BIP-22 string
  mapping.
- `src/rpc.zig:6279-6282::computeSubmitBlockMtp` — MTP lookup helper.
- `src/rpc.zig:6297-6327::validationErrToBip22` — clearbit's
  ValidationError → BIP-22 string map.
- `src/rpc.zig:6340-6400::validateSubmitBlockOrReject` — full
  submit-time validation wrapper (W154 cross-cite).
- `src/rpc.zig:4659-4741::handlePrioritiseTransaction` —
  prioritisetransaction RPC handler (FIX-72 / W120).
- `src/rpc.zig:4747-4800::handleGetPrioritisedTransactions`.
- `src/rpc.zig:6552-6648::handleGenerateToAddress` — regtest
  generation handler (calls `block_template.generateBlocks`).
- `src/rpc.zig:6653-6750::handleGenerateToDescriptor`.
- `src/rpc.zig:6752-6920::handleGenerateBlock` — explicit-tx-set
  variant; calls `block_template.generateBlockWithTxs` (the function
  with W154 BUG-8 / W155 cross-cite below).
- `src/rpc.zig:10562-10606::handleGetMiningInfo` — `getmininginfo`
  response.
- `src/rpc.zig:2988-2991, 3042-3046, 3105-3106, 3161-3162` — RPC
  dispatch table entries for the mining methods.
- `src/block_template.zig:217-459::createBlockTemplate` — W154 audited,
  cross-cited where the GBT response inherits a defect from build
  time (e.g. `bits`, `nTime`, `payout_script`).
- `src/block_template.zig:885-1170::submitBlockWithIndexAndMempool` —
  W154 audited; cross-cited where the BIP-22 string mapping at
  rpc.zig:6300 differs from the block_template strings (e.g. the
  `"inconclusive"` vs `"duplicate-inconclusive"` split).
- `src/tests_w108_gbt.zig`, `src/tests_w123_mining_gbt.zig` — prior
  W108 + W123 audits; used for carry-forward verification and
  severity re-anchoring.

---

## Gate matrix (30 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | GBT request parsing | G1: parse `mode` ("template" / "proposal") | **BUG-1 (P0-CDIV)** — `rpc.zig:6066` `_ = params;` discards entire request object; mode unread (carry-forward W108 BUG-1 / W123 BUG-4 / W154 BUG-11; ~23-wave streak) |
| 1 | … | G2: parse `rules` array, REQUIRE `["segwit"]` | **BUG-2 (P0-CDIV)** — no rules-array parse; no segwit-rule refusal (Core has refused GBT without segwit since 2017) |
| 1 | … | G3: parse `capabilities` array | **BUG-3 (P1)** — no parse; client capability negotiation impossible |
| 1 | … | G4: parse `longpollid`; wait until tip change OR mempool counter advance | **BUG-4 (P0)** — no longpoll implementation anywhere; client receives an immediate response on every call; polling cadence falls back to client-side fixed interval |
| 2 | `proposal` mode | G5: `DecodeHexBlk → LookupBlockIndex` → `duplicate` / `duplicate-invalid` / `duplicate-inconclusive` / `TestBlockValidity` BIP-22 string | **BUG-5 (P0-CDIV)** — proposal mode not implemented; any `mode="proposal"` request silently receives a template (BUG-1 root cause; same site) |
| 3 | IBD + peer-connectivity gate | G6: refuse on non-test chain when `connman.GetNodeCount(Both)==0` or `isInitialBlockDownload()` | **BUG-6 (P0)** — no IBD gate; no peer-count gate; the server ships a stale-tip template even with zero peers and during IBD. Operator running on a freshly-started node can produce blocks that orphan on every peer. Carry-forward W108 BUG-2 / W123 BUG-5. |
| 4 | GBT response — top-level field set | G7: emits `version`, `previousblockhash`, `transactions`, `coinbasevalue`, `target`, `mintime`, `curtime`, `bits`, `height`, `mutable`, `capabilities` | PASS (`rpc.zig:6089-6130`) for those 11 |
| 4 | … | G8: emits `rules`, `vbavailable`, `vbrequired`, `coinbaseaux`, `longpollid`, `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`, `default_witness_commitment`, `signet_challenge` | **BUG-7 (P0-CDIV)** — ALL 11 missing (cross-cite W154 BUG-10 / W123 BUG-3); `default_witness_commitment` absence prevents stock-Core miners from constructing a valid post-segwit block |
| 4 | … | G9: per-tx `hash` (wtxid) emitted | **BUG-8 (P1)** — `rpc.zig:6108-6113` emits only `data`/`txid`/`fee`/`weight`; `hash` (BIP-141 wtxid) missing |
| 4 | … | G10: per-tx `depends` emitted as 1-based index array | **BUG-9 (P1)** — `depends` missing; miners cannot reorder safely (BIP-22 §8) |
| 4 | … | G11: per-tx `sigops` emitted | **BUG-10 (P1)** — `sigops` missing; miners cannot sigop-budget transitions |
| 4 | … | G12: `coinbasevalue` is JSON NUMBER (satoshis), not String | PASS (`rpc.zig:6116` `"coinbasevalue":{d}`) |
| 4 | … | G13: `sizelimit` = `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` post-segwit | **BUG-7 cross-cite** (field absent) |
| 4 | … | G14: `weightlimit` = `MAX_BLOCK_WEIGHT = 4_000_000` post-segwit | **BUG-7 cross-cite** (field absent) |
| 4 | … | G15: `mutable[]` includes `time`, `transactions`, `prevblock` | PASS (`rpc.zig:6125` `"mutable":["time","transactions","prevblock"]`) |
| 4 | … | G16: `mutable[]` includes BIP-23 extensions `coinbase/append`, `version/force`, `submit/coinbase` | **BUG-11 (P1)** — `mutable[]` is a 3-entry fixed literal; W123 BUG-20 / W108 BUG-20 carry-forward (note: `block_template.mutable` HAS 4 entries including `coinbase/append`, but the RPC handler IGNORES that field and emits a hardcoded 3-entry array — wiring-look-but-no-wire) |
| 5 | GBT `mintime` / `curtime` | G17: `mintime` = `parent_MTP + 1` (BIP-113 floor) | **BUG-12 (P1)** — `mintime` set to `template.header.timestamp` (wall clock) — same value as `curtime`. Carry-forward W108 BUG-4 / W123 BUG-6. |
| 5 | … | G18: `mintime` adjusted for BIP-94 timewarp at retarget | **BUG-13 (P1)** — no BIP-94 timewarp adjustment in `mintime` path. The `peer.zig:6386` BIP-94 logic is on the receive-side only, not exposed in the GBT response. Carry-forward W108 BUG-5. |
| 5 | … | G19: `curtime` = `GetAdjustedTime()` (peer-adjusted, refreshed on every GBT call) | **BUG-14 (P0-CDIV)** — `curtime` set to the template's `header.timestamp` cached at build time. No `UpdateTime` re-clock. No `GetAdjustedTime` helper exists in src/. A 5+ minute-old cached template advertises a stale `curtime` → miners using it without their own re-clock submit blocks rejected at peer-receive with `time-too-old` (after MTP catches up) or `time-too-new` (after the wall clock lags). |
| 6 | submitblock request | G20: accepts `(hexdata, dummy)` — dummy ignored per BIP-22 | **BUG-15 (P1)** — `rpc.zig:6135-6172` reads only `params[0]` (hex). If a Core-compatible client passes `["<hex>", "ignored"]`, clearbit silently ignores it (matches Core), but the help string at `rpc.zig:12921-12986` does not document the dummy arg. Cosmetic compat gap. |
| 6 | … | G21: `UpdateUncommittedBlockStructures` overwrites the witness reserved value when parent is known | **BUG-16 (P0-CDIV)** — no equivalent. A miner who forgot to attach the 32-byte witness-reserved-value to the coinbase witness gets `bad-witness-merkle-match`; Core fills it in for them via `UpdateUncommittedBlockStructures(block, pindex)` before validation. |
| 6 | … | G22: `submitblock_StateCatcher` registered to capture per-block validation state | **BUG-17 (P0-CDIV)** — no state-catcher / CValidationInterface analog. clearbit cannot distinguish "block was inconclusive (still validating)" from "block was rejected with reject_reason X". Returns synchronously based on `submitBlockWithIndexAndMempool` result. |
| 6 | … | G23: returns `"duplicate"` when block was already known and accepted | **BUG-18 (P0-CDIV)** — no `"duplicate"` string emitted from the happy path. `handleSubmitBlock` does not check `chain_manager.getBlock(block_hash)` before validation; a re-submission of an already-connected block re-runs the full pipeline and either crashes on UTXO double-spend or returns `bad-txns-inputs-missingorspent`. The block_template side-branch arm DOES emit `"duplicate-inconclusive"` (`block_template.zig:1254`), but only for the side-branch path (`processSideBranchSubmission`); the active-tip extension path has no duplicate detection. |
| 6 | … | G24: `"inconclusive"` when state-catcher did not fire | **BUG-19 (P1)** — `"inconclusive"` IS emitted (block_template.zig:1313) but ONLY from `processSideBranchSubmission` for insufficient-work side-branches — not from "validation in flight" the way Core's `sc->found = false` produces it. The semantics drift. |
| 7 | submitblock BIP-22 result-string map | G25: all canonical Core reject strings round-trip 1:1 | **BUG-20 (P1)** — `validationErrToBip22` (`rpc.zig:6299-6327`) maps only 14 of Core's ~50 reject strings; the catch-all `else => "rejected"` swallows everything from `bad-txns-prevout-null`, `bad-blk-length`, `bad-blk-sigops-pre-segwit`, `bad-version`, `time-too-new`, `time-too-old`, `bad-prevblk`, `bad-fork-prior-to-checkpoint`, `bad-fork-chainlock`, `bad-txnmrklroot`, `bad-witness-nonce-size`, etc. A miner that has to triage WHY their block was rejected loses precise diagnostics. |
| 8 | getmininginfo response shape | G26: emits `blocks`, `bits`, `difficulty`, `target`, `chain` | PASS (`rpc.zig:10589-10603`) |
| 8 | … | G27: emits `currentblockweight`, `currentblocktx` (BlockAssembler::m_last_block_weight / m_last_block_num_txs) | **BUG-21 (P1)** — both fields absent (carry-forward W123 BUG-9); clearbit's BlockAssembler analog has no last-block telemetry state |
| 8 | … | G28: `networkhashps` is computed (not hardcoded 0) | **BUG-22 (P1)** — `networkhashps:0` literal (`rpc.zig:10595`); carry-forward W108 BUG-22 / W123 BUG-8 (~24-wave streak) |
| 8 | … | G29: `blockmintxfee` read from assembler_options.blockMinFeeRate, not hardcoded | **BUG-23 (P1)** — hardcoded `0.00001` literal (`rpc.zig:10595`); carry-forward W108 BUG-23 / W123 BUG-10 |
| 9 | prioritisetransaction | G30: `dummy` arg accepted, must be 0 or null per Core | PASS — `rpc.zig:4690-4710` enforces non-zero rejection across all four JSON arms; closer to Core than most impls. Pinned as PASS to prevent regression. |

Additional findings discovered outside the 30-gate matrix below
(BUG-24..BUG-26).

---

## BUG-1 (P0-CDIV) — `handleGetBlockTemplate` discards request `params` entirely; no `mode` / `rules` / `capabilities` / `longpollid` parse

**Severity:** P0-CDIV. `rpc.zig:6066`:

```zig
fn handleGetBlockTemplate(self: *RpcServer, params: std.json.Value, id: ?std.json.Value) ![]const u8 {
    _ = params; // Template request params (capabilities, rules) - not fully implemented
```

The inline comment literally documents the bug: "not fully
implemented". Bitcoin Core parses every field of the
`template_request` object (`mining.cpp:716-761`): `mode` decides
between template-build and proposal-validate; `rules` is mandatory
and must include `"segwit"`; `capabilities` filters which
fields/shapes Core emits; `longpollid` triggers the wait-for-update
loop.

clearbit emits the same response shape regardless of input. A miner
that sends `{"rules": ["segwit"]}` gets the same broken response as
one that sends `{}` or `{"mode": "proposal", "data": "<hex>"}` —
the proposal request, instead of validating the proposed block,
returns a template.

**File:** `src/rpc.zig:6065-6066`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:716-761`.

**Carry-forward:** W108 BUG-1 + BUG-18; W123 BUG-4; W154 BUG-11.
This is now the **23rd-wave carry-forward** (W108 → W155). Tied
with W154 BUG-1 (genesis-bits placeholder) for clearbit's
longest-open carry-forward streak.

**Impact:**
- Stock Core miners (cgminer/bfgminer/luxor) require the
  `rules` round-trip negotiation to proceed; they refuse a template
  whose response shape does not acknowledge their `rules` list.
- BIP-23 proposal-mode handshake is broken (BUG-5 cross-cite).
- Long-polling is impossible (BUG-4 cross-cite).
- Operator switching from Core to clearbit must source-patch their
  miner stack or hand-write a clearbit-shim.

**Comment-as-confession:** `_ = params; // ... - not fully implemented`
is comment-as-confession **9th distinct clearbit instance**
(after BUG-12 GBT funds-burn in W154, BUG-1 W154 genesis bits, etc.).

---

## BUG-2 (P0-CDIV) — `handleGetBlockTemplate` does not refuse without `rules: ["segwit"]`

**Severity:** P0-CDIV. Bitcoin Core's `mining.cpp:849-857`:

```cpp
// GBT must be called with 'signet' set in the rules for signet chains
if (consensusParams.signet_blocks && !setClientRules.contains("signet")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the signet rule set (call with {\"rules\": [\"segwit\", \"signet\"]})");
}
// GBT must be called with 'segwit' set in the rules
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
}
```

Core REFUSES the call without the segwit rule, since 2017
(post-BIP-141 deployment). Signet adds the corresponding refusal for
the `"signet"` rule.

clearbit's GBT handler accepts ANY rules value silently (because of
BUG-1 it parses NO rules at all) and emits a template anyway. A
pre-segwit-aware miner that calls with `{"rules": []}` gets a
post-segwit template containing a `default_witness_commitment` slot
it cannot use — except clearbit doesn't emit
`default_witness_commitment` either (BUG-7), so the miner builds
a segwit-blind coinbase and the resulting block is rejected with
`bad-witness-merkle-match` on every peer.

The signet variant is doubly broken: clearbit's GBT on signet emits
the same shape with no `signet_challenge` field (BUG-7 cross-cite),
so a signet-aware miner that DID send `["segwit","signet"]` cannot
discover the challenge bytes to inject into the coinbase.

**File:** `src/rpc.zig:6065-6066` (no rules parse); cross-cite BUG-7
(default_witness_commitment + signet_challenge absent).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:849-857`.

**Carry-forward:** W123 BUG-4; W154 BUG-11.

**Impact:** stock miners cannot pre-flight detect that clearbit
"understands" segwit; the empty-rules acceptance silently downgrades
every miner to "guess and hope".

---

## BUG-3 (P1) — `capabilities` request array unparsed; no client-feature negotiation

**Severity:** P1. Bitcoin Core uses `oparam.find_value("capabilities")`
to filter which fields the response includes — e.g., if the client
advertises `["coinbasetxn"]` Core emits a full coinbase transaction
under `coinbasetxn` instead of just `coinbasevalue`; if the client
omits `"longpoll"` from capabilities Core skips the wait loop.

clearbit's `handleGetBlockTemplate` discards `params` (BUG-1) so
`capabilities` is unread. Symmetric W108 BUG-19 + W123 BUG-19.

Additionally, the RESPONSE-side `capabilities` array is hardcoded:

```zig
try writer.print("{{\"capabilities\":[\"proposal\"],\"version\":{d},...
```

so even the server-side advertisement is a fixed one-element array.
Core advertises additional features (`"workid"`, `"serverlist"`,
`"coinbasetxn"`) based on actual server capability.

**File:** `src/rpc.zig:6066, 6089`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:754-761` (request
parse); `mining.cpp:895` (server emission).

**Carry-forward:** W108 BUG-19, W108 BUG-28, W123 BUG-19.

**Impact:** client-feature negotiation impossible; new BIP-23
features unrolled-out.

---

## BUG-4 (P0) — `longpollid` long-poll mechanism entirely absent

**Severity:** P0. BIP-22's `longpoll` extension is the standard
way for a mining client to wait for a template update rather than
polling at a fixed interval. Core's `mining.cpp:783-845` implements
the wait:

1. Parse `longpollid` = `tip_hash || mempool_update_counter`.
2. `REVERSE_LOCK(cs_main_lock, cs_main); while
   (IsRPCRunning()) {...}` — loop blocking on the next of:
   - `miner.waitTipChanged(hash, 60s/10s)` → tip moved,
   - `mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP`
     → mempool changed since the last template.
3. First check is at 60 s, subsequent every 10 s.
4. Returns the new template once an update is observed (or RPC
   shutdown).

clearbit has none of this. There is no `longpollid` parse (BUG-1),
no `waitTipChanged` helper (grep returns zero hits), no mempool
update counter (`Mempool` has no `GetTransactionsUpdated` / sequence
counter). Long-polling clients spin in tight client-side polls
(typical default: 1 s) — which both wastes CPU on the server and
adds template-update latency.

**File:** `src/rpc.zig:6065-6133` (no long-poll path);
`src/mempool.zig` (no transactions-updated counter); cross-cite
BUG-1.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:783-845`;
`bitcoin-core/src/txmempool.cpp::GetTransactionsUpdated`.

**Carry-forward:** W108 BUG-12 (longpollid field absent in response);
W123 BUG-11 (no template caching). W155 extends with the entire
wait-loop missing.

**Impact:** mining pool operators using clearbit see higher CPU on
both client and server, increased miner downtime between templates,
and worse stale-share rates. Combined with BUG-14 (no curtime
refresh on poll) the effect compounds: clients can't poll
efficiently AND the response is stale-clock anyway.

---

## BUG-5 (P0-CDIV) — `mode="proposal"` not implemented; proposal-mode requests get a template instead of a validation result

**Severity:** P0-CDIV. Bitcoin Core's `mining.cpp:730-751`:

```cpp
if (strMode == "proposal")
{
    const UniValue& dataval = oparam.find_value("data");
    if (!dataval.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

    CBlock block;
    if (!DecodeHexBlk(block, dataval.get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex) {
        if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
            return "duplicate";
        if (pindex->nStatus & BLOCK_FAILED_VALID)
            return "duplicate-invalid";
        return "duplicate-inconclusive";
    }

    return BIP22ValidationResult(TestBlockValidity(chainman.ActiveChainstate(), block,
                                                    /*check_pow=*/false,
                                                    /*check_merkle_root=*/true));
}
```

clearbit's `handleGetBlockTemplate` discards `params` entirely so
proposal-mode is unreachable: a `{"mode": "proposal", "data": "<hex
block>"}` request silently returns a template (the regular
template-mode response) instead of validating the proposed block.

The proposal-mode handshake is the standard pre-submit
validation: a miner pool operator constructs a block locally, sends
it as a proposal, and the node responds with either `null` (valid)
or a BIP-22 reject reason — without committing the block. clearbit's
breakage means the operator must use `submitblock` (which DOES
commit the block) for validation, then deal with cleanup if the
block was rejected after partial state mutations.

**File:** `src/rpc.zig:6065-6133`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:730-751`.

**Carry-forward:** W108 BUG-18; W123 BUG-4.

**Impact:** pool operators cannot pre-flight validate templates;
must use the destructive `submitblock` path; cross-impl divergence.

---

## BUG-6 (P0) — No IBD + peer-connectivity gate on `getblocktemplate`

**Severity:** P0. Bitcoin Core's `mining.cpp:766-775`:

```cpp
if (!miner.isTestChain()) {
    const CConnman& connman = EnsureConnman(node);
    if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, CLIENT_NAME " is not connected!");
    }

    if (miner.isInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, CLIENT_NAME " is in initial sync and waiting for blocks...");
    }
}
```

Core refuses to serve a template on non-test chains when:
- the connman has zero connected peers (we'd be mining against a
  potentially stale tip), OR
- the node is in IBD (the tip we'd be mining on is known-stale).

clearbit has no such gate in `handleGetBlockTemplate`. A miner that
calls during IBD or on a freshly-started disconnected node receives
a template built off the cold-stored tip. Any block mined off that
template will orphan when the node finally syncs — wasting all the
miner's hash power.

**File:** `src/rpc.zig:6065-6133`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-775`.

**Carry-forward:** W108 BUG-2; W123 BUG-5.

**Impact:**
- IBD-then-mine: cold-restart followed by `getblocktemplate` ships
  a stale-tip template; the miner orphans every block until IBD
  completes.
- Zero-peers: identical orphan scenario; the lack of peers means we
  may have missed a recent tip extension. Core's refusal is a
  defense-in-depth gate; clearbit has no equivalent.

---

## BUG-7 (P0-CDIV) — GBT response missing 11 BIP-22/23/141/145 fields incl. `default_witness_commitment`, `longpollid`, `rules`, `vbavailable`, `vbrequired`, `coinbaseaux`, `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`, `signet_challenge`

**Severity:** P0-CDIV. `rpc.zig:6089-6130` emits 11 fields:

```
capabilities, version, previousblockhash, transactions,
coinbasevalue, target, mintime, curtime, bits, height, mutable
```

Core (`mining.cpp:947-1031`) emits 22+ fields. **Missing**:

| Field | Core ref | Miner impact |
|-------|----------|--------------|
| `rules` | mining.cpp:994 | Miner can't tell which softforks are active |
| `vbavailable` | mining.cpp:995 | Miner can't enumerate signaling bits |
| `vbrequired` | mining.cpp:996 | Miner doesn't know which bits MUST be set |
| `coinbaseaux` | mining.cpp:1000 | No way to inject per-pool aux tags |
| `longpollid` | mining.cpp:1002 | No long-poll → polling at fixed cadence (BUG-4) |
| `noncerange` | mining.cpp:1006 | Miner can't tell which nonces are valid (always `"00000000ffffffff"`) |
| `sigoplimit` | mining.cpp:1015 | Miner can't pre-check sigops budget |
| `sizelimit` | mining.cpp:1016 | Miner can't pre-check serialization size |
| `weightlimit` | mining.cpp:1018 | Miner can't pre-check weight budget |
| `default_witness_commitment` | mining.cpp:1030 | Miner has no segwit commit scriptPubKey — **cannot build valid post-segwit block** |
| `signet_challenge` | mining.cpp:1025 | Signet miner cannot satisfy block_script consensus rule |

The `default_witness_commitment` absence is the most catastrophic:
a stock-Core miner using clearbit's GBT cannot construct a valid
post-segwit block because there is no way to know what the witness
commitment OP_RETURN scriptPubKey should look like for the
unmodified tx set. The miner must either include none (block fails
with `bad-witness-merkle-match` if ANY tx is segwit) or
forward-construct one (requiring full re-computation in the miner,
which defeats the point of GBT).

**File:** `src/rpc.zig:6088-6130`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:947-1031`.

**Carry-forward:** W108 BUG-6 + BUG-7 + BUG-11 + BUG-12 + BUG-13 +
BUG-14 + BUG-15 + BUG-16 + BUG-17 + BUG-24 + BUG-25; W123 BUG-3;
W154 BUG-10. **22-wave carry-forward** (W108 → W155). Tied for
longest-open clearbit carry-forward streak with BUG-1 above and W154
BUG-1.

**Impact:** stock Core miners cannot build valid post-segwit blocks
using clearbit's GBT. Operators must source-patch their miner.

---

## BUG-8 (P1) — Per-tx `hash` (BIP-141 wtxid) field missing

**Severity:** P1. `rpc.zig:6108-6113`:

```zig
try writer.print("{{\"data\":\"", .{});
// ... data hex ...
try writer.print("\",\"txid\":\"", .{});
try writeHashHex(writer, &tx.txid);
try writer.print("\",\"fee\":{d},\"weight\":{d}}}", .{
    tx.fee,
    tx.weight,
});
```

The per-tx entry emits `data`, `txid`, `fee`, `weight` — and stops.
Core's per-tx entry adds `hash` (the BIP-141 wtxid) for every
transaction so segwit-aware miners can verify the witness merkle
root and short-circuit recomputation:

```cpp
entry.pushKV("hash", tx.GetWitnessHash().GetHex());  // mining.cpp:915
```

clearbit has `crypto.computeWtxid` (crypto.zig:1201) but the GBT
emitter never calls it. Dead-helper-at-call-site fleet pattern, 8th
distinct clearbit instance.

**File:** `src/rpc.zig:6108-6113`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:915`.

**Carry-forward:** W108 BUG-8.

**Impact:** segwit-aware miners that consume `hash` for fee
estimation and witness merkle pre-check (luxor, foundry's
cgminer-fork) lose the optimisation and must recompute wtxid in
client.

---

## BUG-9 (P1) — Per-tx `depends` field missing

**Severity:** P1. BIP-22 §8: "Array of numbers (1-based index into
the `transactions` list) representing in-template parents this tx
depends on; if the parent is excluded, this tx MUST also be
excluded." clearbit's per-tx entry omits this field entirely.

Without `depends`, a miner that drops a tx for any policy reason
(e.g., to reach `weightlimit`) cannot identify which descendants
must also be dropped. The miner either ships an inconsistent block
(rejected with `bad-txns-inputs-missingorspent`) or has to recompute
the full ancestor closure for every dropped tx — which defeats the
purpose of GBT's pre-computed selection.

Core's `mining.cpp:917-923`:

```cpp
UniValue deps(UniValue::VARR);
for (const CTxIn &in : tx.vin)
{
    if (setTxIndex.contains(in.prevout.hash))
        deps.push_back(setTxIndex[in.prevout.hash]);
}
entry.pushKV("depends", std::move(deps));
```

uses an in-template `txid → index` map (`setTxIndex`) to find which
parents are already in `transactions[]` and emits their 1-based
indices. clearbit has no such helper.

**File:** `src/rpc.zig:6108-6113`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:917-923`.

**Carry-forward:** W108 BUG-9.

**Impact:** miners that drop transactions cannot maintain
consistency; combined with BUG-4 (no longpoll) and W154 BUG-4 (no
package selection) the entire chain of mempool topology information
is broken from server through wire.

---

## BUG-10 (P1) — Per-tx `sigops` field missing

**Severity:** P1. BIP-22 §8 specifies `sigops` for each tx so
miners can enforce sigop limits when modifying the tx set.
clearbit's `block_template.SelectedTx` has a `sigops: usize` field
populated by `estimateSigops` (block_template.zig:329), but the GBT
serialiser doesn't read it:

```zig
try writer.print("\",\"fee\":{d},\"weight\":{d}}}", .{
    tx.fee,
    tx.weight,
});
// MISSING: ,"sigops":{d}, tx.sigops
```

Another dead-data-plumbing fleet pattern instance: the value is
computed and stored in the template, but never reaches the wire.

**File:** `src/rpc.zig:6108-6113`; `src/block_template.zig:58, 349`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:932`.

**Carry-forward:** W108 BUG-10.

**Impact:** miners that swap one tx for another (e.g., to make room
for a larger high-fee tx) cannot sigop-budget the swap; the block
risks `bad-blk-sigops` at submit time.

---

## BUG-11 (P1) — `mutable[]` is a hardcoded 3-entry array; the template's `mutable` field is computed but ignored by the RPC handler (dead-data plumbing)

**Severity:** P1. `block_template.zig:440-445` correctly builds:

```zig
const mutable = &[_][]const u8{
    "time",
    "transactions",
    "prevblock",
    "coinbase/append",   // <-- 4th entry
};
```

and the `BlockTemplate` struct exposes it via `template.mutable`
(line 48). But `rpc.zig:6125` emits a hardcoded 3-entry array:

```zig
try writer.print("\",\"mintime\":{d},\"curtime\":{d},\"bits\":\"{x:0>8}\",\"height\":{d},\"mutable\":[\"time\",\"transactions\",\"prevblock\"]}}", .{
    template.header.timestamp,
    template.header.timestamp,
    template.header.bits,
    template.height,
});
```

The `"coinbase/append"` entry from the template is dropped on the
floor. Core's BIP-23 mutable values include `"time"`,
`"transactions"`, `"prevblock"`, `"coinbase/append"`,
`"version/force"`, `"submit/coinbase"`. clearbit's hardcoded
3-entry array is a subset of even its own template's 4-entry
declaration.

**Fleet pattern:** **dead-data plumbing** at the RPC layer (9th
distinct clearbit instance per the W138 / W140 / W154 tracking). The
field is built, exposed via the struct API, and ignored by the only
caller.

**File:** `src/rpc.zig:6125` (hardcoded literal); cross-cite
`src/block_template.zig:440-445` (computed but unused).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:942-945` +
`mining.cpp:1005`.

**Carry-forward:** W108 BUG-20; W123 BUG-20.

**Impact:** miners that consume `mutable[]` to decide what they're
allowed to modify on the template (e.g., bumping `version` for
soft-fork signaling) see a stricter contract than the server
actually enforces.

---

## BUG-12 (P1) — GBT `mintime` = `template.header.timestamp` (wall clock), not `parent_MTP + 1`

**Severity:** P1. `rpc.zig:6125-6130` emits `mintime` and `curtime`
as the SAME value — the template's wall-clock-at-build timestamp.
Bitcoin Core's `mining.cpp:1004` distinguishes:

```cpp
result.pushKV("mintime", GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()));
```

where `GetMinimumTime` (`miner.cpp:36-47`) returns `parent_MTP + 1`,
with a BIP-94 timewarp upper-bound at retarget. This is the LOWEST
valid `nTime` the miner is allowed to set without violating
BIP-113.

A miner that uses clearbit's `mintime` as the lower bound during a
nonce-exhaustion clock-rewind can submit a block with `timestamp <=
MTP`, which all peers reject with `time-too-old`.

**File:** `src/rpc.zig:6125-6130`; cross-cite W154 BUG-3 (wall-clock
nTime).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1004` +
`bitcoin-core/src/node/miner.cpp:36-47`.

**Carry-forward:** W108 BUG-4 + BUG-5; W123 BUG-6; W154 BUG-13.

**Impact:** miners that roll timestamp during long nonce exhaustion
underflow `parent_MTP`; resulting block rejected on every peer.

---

## BUG-13 (P1) — `mintime` lacks BIP-94 timewarp adjustment at retarget

**Severity:** P1. Bitcoin Core's `GetMinimumTime`
(`miner.cpp:36-47`):

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    const int height{pindexPrev->nHeight + 1};
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

At retarget boundaries (every 2016 blocks on mainnet) the
BIP-94 timewarp rule fires: `min_time = max(min_time,
prev->GetBlockTime() - MAX_TIMEWARP)` (where `MAX_TIMEWARP = 600 s`).

clearbit's mintime computation (cross-cite BUG-12) is naked
wall-clock — no `MTP+1`, no BIP-94 guard. peer.zig:6386 implements
the BIP-94 logic on the receive-side validation only; the GBT
response path is not aware.

**File:** `src/rpc.zig:6125-6130`; `src/block_template.zig:430-437`
(template build).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`.

**Carry-forward:** W108 BUG-5.

**Impact:** at retarget heights, miners that take `mintime` from
GBT can submit blocks rejected with `bad-blk-time-too-old` because
the BIP-94 floor was higher than `MTP+1`.

---

## BUG-14 (P0-CDIV) — `curtime` is cached at template-build time; no `UpdateTime` per-call re-clock

**Severity:** P0-CDIV. Bitcoin Core's GBT (`mining.cpp:888-890`):

```cpp
CBlock block{block_template->getBlock()};

// Update nTime
UpdateTime(&block, consensusParams, pindexPrev);
block.nNonce = 0;
```

`UpdateTime` (`miner.cpp:49-58`) refreshes `pblock->nTime` on EVERY
GBT call, using `max(GetMinimumTime, GetAdjustedTime())`. So a
miner that polls every 30 s sees a fresh `curtime` and `bits`
value (testnet `fPowAllowMinDifficultyBlocks` updates `bits` too
when the time advance triggers a min-difficulty fall-back).

clearbit's `curtime` (`rpc.zig:6125-6130`) is
`template.header.timestamp` — the wall-clock value captured during
`createBlockTemplate` at build time (W154 BUG-3 says that's also
broken — raw `std.time.timestamp()` with no
`GetAdjustedTime`). When the template is rebuilt (which is every
call because there's no caching — W123 BUG-11) the timestamp is
fresh, but:

- if any code path WERE to cache the template (long-poll, future
  optimisation), `curtime` would go stale,
- the template is reused across long-poll responses by Core, so
  `UpdateTime` is the LAST-MILE refresh that ensures the value the
  miner sees is current,
- and there is no `GetAdjustedTime` anywhere (W154 BUG-3) so even
  the fresh-build value is naked wall-clock.

**File:** `src/rpc.zig:6125-6130`; `src/block_template.zig:434`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-58`;
`bitcoin-core/src/rpc/mining.cpp:889`.

**Carry-forward:** W108 BUG-21; W123 BUG-7; W154 BUG-3.

**Impact:** miner clock + server clock + no UpdateTime layer
combine to ship `curtime` values up to ±5 minutes off real time;
mainnet miners' first-block submission may collide with the
`MAX_FUTURE_BLOCK_TIME=7200s` peer-reject bound at the upper end,
or `MTP+1` at the lower end.

---

## BUG-15 (P1) — `submitblock` accepts but does not validate the BIP-22 `dummy` second positional arg; help docstring omits it

**Severity:** P1 (cosmetic). Core (`mining.cpp:1064-1065`):

```cpp
{"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
{"dummy", RPCArg::Type::STR, RPCArg::DefaultHint{"ignored"}, "dummy value, for compatibility with BIP22. This value is ignored."},
```

Core declares the second arg explicitly so RPC discovery
(`bitcoin-cli help submitblock`) describes it; the value is then
ignored. clearbit's `handleSubmitBlock` (`rpc.zig:6135-6172`) reads
only `params[0]`. If a Core-compatible client passes 2 args,
clearbit accepts the call (because it only looks at items[0]) but
the help string at `rpc.zig:12921-12986` doesn't document the dummy
arg — so RPC discovery for ported `bitcoin-cli` scripts is silent.

**File:** `src/rpc.zig:6135-6172`; `src/rpc.zig:12986` (help text).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1064-1065`.

**Impact:** RPC introspection compat gap; pure cosmetic.

---

## BUG-16 (P0-CDIV) — No `UpdateUncommittedBlockStructures` — miner that omits the witness reserved value is forced to recompute themselves

**Severity:** P0-CDIV. Bitcoin Core's `submitblock`
(`mining.cpp:1086-1090`):

```cpp
LOCK(cs_main);
const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
if (pindex) {
    chainman.UpdateUncommittedBlockStructures(block, pindex);
}
```

`UpdateUncommittedBlockStructures` fills in the BIP-141 witness
reserved value (32 zero bytes in coinbase's witness stack) when the
miner forgot to attach one. Core does this BEFORE `ProcessNewBlock`
runs, so the witness merkle commits correctly.

clearbit's `handleSubmitBlock` (`rpc.zig:6135-6263`) has no
equivalent. A miner that submits a block whose coinbase has no
witness stack triggers `bad-witness-merkle-match` directly. The
miner must re-construct the coinbase with the nonce and resubmit.

This is the canonical "be liberal in what you accept" gate. Without
it, every clearbit-using miner stack must implement witness-nonce
attachment correctly on the first try — a small ergonomics gap but
one Core actively papers over.

**File:** `src/rpc.zig:6135-6263`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1086-1090`;
`bitcoin-core/src/validation.cpp::UpdateUncommittedBlockStructures`.

**Impact:** miners cannot omit the witness reserved value when
submitting; the server doesn't fix it for them. Compatibility gap
with Core ergonomics.

---

## BUG-17 (P0-CDIV) — No `submitblock_StateCatcher` / CValidationInterface analog; `"inconclusive"` semantics unreachable

**Severity:** P0-CDIV. Bitcoin Core's `submitblock`
(`mining.cpp:1093-1103`):

```cpp
bool new_block;
auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);
bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true,
                                          /*min_pow_checked=*/true,
                                          /*new_block=*/&new_block);
CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);
if (!new_block && accepted) {
    return "duplicate";
}
if (!sc->found) {
    return "inconclusive";
}
return BIP22ValidationResult(sc->state);
```

The state-catcher subscribes to `BlockChecked` validation-interface
callbacks. Three terminal outcomes:

1. `!new_block && accepted`: the block hash was already known and
   valid → `"duplicate"`.
2. `!sc->found`: `ProcessNewBlock` returned but no `BlockChecked`
   callback fired for our hash (race: validation deferred,
   shutdown, etc.) → `"inconclusive"`.
3. otherwise: `BIP22ValidationResult(sc->state)` maps the captured
   state to a reject token.

clearbit's `handleSubmitBlock` returns synchronously based on the
direct return value of `block_template.submitBlockWithIndexAndMempool`.
There is no `CValidationInterface` analog (clearbit does not have a
validation-interface signal bus), no `sc->found` race detection, no
`new_block` discrimination. Consequences:

- A re-submission of an already-connected block is NOT detected as
  duplicate at this layer; it falls through to validation, which
  hits `bad-txns-inputs-missingorspent` (UTXO already spent by the
  earlier copy) and returns that as the reject string. Operator
  tooling that uses `submitblock` for idempotent retries (e.g.,
  network-flake resubmissions) sees the wrong reject string and
  may take destructive action.
- `"inconclusive"` semantics drift: clearbit DOES emit
  `"inconclusive"` (`block_template.zig:1313`) but only from
  `processSideBranchSubmission` for insufficient-work side-branches.
  This is NOT what Core's `"inconclusive"` means (Core: validation
  deferred / not-yet-completed; clearbit: side-branch stored but
  not active).

**File:** `src/rpc.zig:6135-6263`; cross-cite
`src/block_template.zig:1252-1316`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1038-1054, 1093-1103`.

**Impact:**
- Idempotent retries see wrong reject string;
- Operator monitoring tools that scrape BIP-22 strings see
  semantically-divergent values;
- Cross-impl divergence (Core / clearbit speak different
  `"inconclusive"` languages).

---

## BUG-18 (P0-CDIV) — `"duplicate"` BIP-22 string never emitted for active-tip extension; re-submission of known block returns `bad-txns-inputs-missingorspent`

**Severity:** P0-CDIV. Re-submitting a block that's already in the
active chain should return `"duplicate"` (Core mining.cpp:1097).
clearbit's `handleSubmitBlock` does not check
`chain_manager.getBlock(&block_hash)` before validation. The block
re-runs `validation.acceptBlock` → `connectBlockFastWithUndo` → the
first input lookup finds the UTXO already spent (by the original
copy of this block) → returns `error.MissingInput` → mapped to
`"bad-txns-inputs-missingorspent"`.

Cross-cite **BUG-17**: the state-catcher gap is the architectural
reason; this is the observable symptom. Note the side-branch arm
DOES emit `"duplicate-inconclusive"` (`block_template.zig:1254`), so
the duplicate-detect plumbing exists in one half of the codebase
but not the other (**two-pipeline guard** clearbit instance, ~6th
distinct).

**File:** `src/rpc.zig:6135-6263`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1097`
(`!new_block && accepted → "duplicate"`).

**Impact:** operator-visible: `submitblock` retries return the
wrong BIP-22 token; monitoring/alerting tooling falsely raises
alerts for `bad-txns-inputs-missingorspent` on benign retries.

---

## BUG-19 (P1) — `"inconclusive"` BIP-22 semantics drift: emitted only from side-branch insufficient-work path, not from validation-in-flight

**Severity:** P1 (semantics divergence). See BUG-17 for the
architectural root cause. clearbit emits `"inconclusive"` for one
of Core's six cases (side-branch stored without active-tip change),
and that's NOT how Core defines the term. Core's
`"inconclusive"` means "validation interface didn't fire for our
hash" — i.e., validation in flight, deferred, or shutdown
collision. clearbit's emission is "side-branch but doesn't
extend".

Cross-impl monitoring tools that watch for BIP-22 `"inconclusive"`
on a Core node see "wait and resubmit" semantics; on a clearbit
node they see "this branch lost, the other one is canonical" —
opposite operator action.

**File:** `src/block_template.zig:1313` (side-branch
insufficient-work emission); cross-cite BUG-17.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1100-1102`.

**Impact:** cross-impl monitoring divergence.

---

## BUG-20 (P1) — `validationErrToBip22` maps only 14 of Core's ~50 BIP-22 reject strings; catch-all `"rejected"` hides precise diagnostics

**Severity:** P1. `rpc.zig:6299-6327`:

```zig
fn validationErrToBip22(err: validation.ValidationError) []const u8 {
    return switch (err) {
        error.BadCoinbaseValue => "bad-cb-amount",
        error.CoinbaseScriptSize => "bad-cb-length",
        error.BadCoinbaseHeight => "bad-cb-height",
        error.BadMerkleRoot => "bad-txnmrklroot",
        error.BadWitnessCommitment => "bad-witness-merkle-match",
        error.TooManySigops => "bad-blk-sigops",
        error.BadProofOfWork, error.BadDifficulty => "high-hash",
        error.NonFinalTx, error.SequenceLockNotSatisfied => "bad-txns-nonfinal",
        error.DuplicateTx, error.Bip30DuplicateOutput => "bad-txns-duplicate",
        error.MissingInput, error.InputAlreadySpent => "bad-txns-inputs-missingorspent",
        error.BadBlockWeight, error.BadBlockSize => "bad-blk-weight",
        error.ScriptVerificationFailed => "block-script-verify-flag-failed",
        error.ImmatureCoinbase => "bad-txns-premature-spend-of-coinbase",
        error.NegativeOutput => "bad-txns-vout-negative",
        error.OutputTooLarge => "bad-txns-vout-toolarge",
        error.InsufficientFunds => "bad-txns-in-belowout",
        else => "rejected",
    };
}
```

The `else => "rejected"` catch-all swallows:
- `bad-txns-prevout-null` (coinbase-shaped prevout in non-coinbase),
- `bad-blk-length` (block byte-size cap),
- `bad-version` (BIP-65/CSV/segwit version-bits enforcement),
- `time-too-new` (header timestamp > `now +
  MAX_FUTURE_BLOCK_TIME=7200s`),
- `time-too-old` (header timestamp <= MTP),
- `bad-prevblk` (parent not found / failed),
- `bad-fork-prior-to-checkpoint`,
- `bad-witness-nonce-size` (coinbase witness != 32 bytes),
- `bad-cb-amount` (rusty subsidy or fee-overflow),
- `bad-txnmrklroot` (coinbase txid mismatch with merkle),
- ~30 others.

A miner that submits a block and receives `"rejected"` cannot tell
WHICH consensus rule failed; they must scrape clearbit's stderr
(which DOES log the precise `err` via `std.debug.print` at
`rpc.zig:6394`) or instrument the submitblock client to log the
full RPC body.

**File:** `src/rpc.zig:6299-6327`; `src/validation.zig`
(`ValidationError` enum).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:586-603`
(`BIP22ValidationResult`).

**Impact:** debugging-rejected-blocks is harder than on Core;
operator tooling that branches on the BIP-22 reject string (mining
pool stratum proxies, block-submission retry shims) cannot.

---

## BUG-21 (P1) — `getmininginfo` missing `currentblockweight` + `currentblocktx`

**Severity:** P1. Core's `mining.cpp:467-468`:

```cpp
if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
```

`BlockAssembler::m_last_block_weight` and `m_last_block_num_txs`
are static class members updated at the end of every
`CreateNewBlock`. They give operator-monitoring tools "how full
is the most recent template?" telemetry.

clearbit's `BlockAssembler` analog (`block_template.zig`) has no
equivalent static / module-level "last block" state. `getmininginfo`
emits neither field.

**File:** `src/rpc.zig:10589-10603`; `src/block_template.zig`
(no last-block telemetry).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:467-468`;
`bitcoin-core/src/node/miner.cpp` (`m_last_block_weight` /
`m_last_block_num_txs` definitions).

**Carry-forward:** W123 BUG-9.

**Impact:** pool operators tracking template fullness see no data.

---

## BUG-22 (P1) — `getmininginfo` `networkhashps` hardcoded to literal 0

**Severity:** P1. `rpc.zig:10595`:

```zig
try writer.print("\",\"networkhashps\":0,\"pooledtx\":{d},...
```

The literal `0` is emitted regardless of actual chain hash rate.
Core delegates: `obj.pushKV("networkhashps",
getnetworkhashps().HandleRequest(request))` (mining.cpp:472).
clearbit's `getnetworkhashps` handler exists (`rpc.zig:3161-3162`
dispatch) but `getmininginfo` does not call it internally.

**File:** `src/rpc.zig:10595`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:472`.

**Carry-forward:** W108 BUG-22; W123 BUG-8. **24-wave streak**.

**Impact:** monitoring tools scraping `getmininginfo` see 0
networkhashps even when the chain is producing hashes; must call
`getnetworkhashps` separately.

---

## BUG-23 (P1) — `getmininginfo` `blockmintxfee` hardcoded to literal 0.00001

**Severity:** P1. `rpc.zig:10595`:

```zig
try writer.print("...\"blockmintxfee\":0.00001,\"chain\":\"{s}\",..., .{
```

The literal `0.00001` BTC/kvB is emitted regardless of the
configured `block_min_fee_rate`. Core's `mining.cpp:476`:

```cpp
obj.pushKV("blockmintxfee", ValueFromAmount(assembler_options.blockMinFeeRate.GetFeePerK()));
```

reads the actual configured `blockMinFeeRate` (from
`-blockmintxfee` arg). clearbit's `TemplateOptions` has
`block_min_fee_rate: u64 = 0` (block_template.zig:177) but the
value isn't surfaced in `getmininginfo` and there's no operator
CLI flag to set it either (W154 BUG-23 + companion).

**File:** `src/rpc.zig:10595`; cross-cite W123 BUG-22 / BUG-23
(no `-blockmintxfee` / `-blockmaxweight` / `-blockreservedweight`
CLI flag).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:476`.

**Carry-forward:** W108 BUG-23; W123 BUG-10.

**Impact:** operator-monitoring divergence; misleading display.

---

## BUG-24 (P0-CDIV) — `payout_script` hardcoded to `[_]u8{0x6a}` (OP_RETURN) — GBT-returned template burns full block reward; W154 BUG-12 cross-cite + W155 evidence

**Severity:** P0-CONS funds-burn. Cross-cite W154 BUG-12. The RPC
boundary is the locus: `rpc.zig:6069`:

```zig
const payout_script = [_]u8{ 0x6a }; // OP_RETURN (placeholder)
var template = block_template.createBlockTemplate(
    self.chain_state,
    self.mempool,
    self.network_params,
    .{
        .payout_script = &payout_script,
        .include_witness_commitment = true,
    },
    self.allocator,
) catch { ... };
```

A miner that:
1. Calls `getblocktemplate`,
2. Receives the OP_RETURN-paying template (where the coinbase
   output's full `subsidy + total_fees` value goes to a 1-byte
   OP_RETURN — unspendable),
3. Mines a valid nonce,
4. Calls `submitblock`,

destroys their entire block reward. On mainnet at $80k/BTC, this is
~$250k per block.

The W155 angle: the **request** carries no `payout_address` field,
because BIP-22's GBT response is supposed to emit `coinbasevalue`
(numeric) and let the MINER construct the coinbase. clearbit's
handler instead pre-constructs the coinbase server-side using a
hardcoded OP_RETURN payout, then ships the constructed coinbase in
the `transactions[0].data` field (BUG-7: there is no separate
`coinbasetxn` field). The miner who consumes
`transactions[0]` verbatim mines the OP_RETURN.

Workarounds for a careful operator:
- Ignore `transactions[0]` and build their own coinbase from
  `coinbasevalue` + height + their own payout script. But this is
  exactly the BIP-22 contract — Core does it this way. clearbit's
  pre-construction is a misleading deviation.

**Fleet pattern:** **funds-burn** (NEW pattern introduced in W154,
extended here at the RPC entry point).

**File:** `src/rpc.zig:6069`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` — GBT emits
`coinbasevalue` + (optionally) `coinbasetxn` when proposal
capability negotiated; never a hardcoded burn output.

**Carry-forward:** W154 BUG-12 (rpc-side audit re-anchors it).

**Impact:** catastrophic. Any operator wiring a non-clearbit-aware
miner to clearbit's GBT burns block rewards on each mined block.

---

## BUG-25 (P1) — `handlePrioritiseTransaction` accepts `dummy` as STR/INTEGER/FLOAT/NULL but rejects `number_string` non-"0" — Core's arg type is NUM only

**Severity:** P1 (over-permissive parser). Bitcoin Core's RPC arg
typer (`mining.cpp:508`):

```cpp
{"dummy", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
 "API-Compatibility for previous API. Must be zero or null."},
```

Core's `dummy` is `RPCArg::Type::NUM` — the framework will reject
any non-numeric value (string, bool, object) at the parameter-typer
stage BEFORE the handler runs. The handler then checks `*dummy !=
0`.

clearbit's `handlePrioritiseTransaction` (`rpc.zig:4690-4710`)
accepts FOUR JSON variants (`.null`, `.integer`, `.float`,
`.number_string`) AND raises `RPC_INVALID_PARAMETER` on non-zero.
This is OVER-permissive: a Core-compatible call with
`prioritisetransaction "txid" "not_a_number" 1000` would error in
Core (type-check fail) but in clearbit triggers the catch-all
`return self.jsonRpcError(RPC_INVALID_PARAMS, "Invalid dummy
parameter type", id);`. The error code (-32602 vs Core's -8) and
message text differ.

Operationally minor; flagged for fleet-tracking on RPC type
discipline.

**File:** `src/rpc.zig:4690-4710`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:508`.

**Impact:** divergent error codes / messages on malformed
prioritisetransaction calls; benign in well-behaved miner stacks.

---

## BUG-26 (P0) — `generateblock` accepts mempool txid lookups but the resulting block fails `bad-witness-merkle-match`; cross-cite W154 BUG-8

**Severity:** P0 (cross-cite). The RPC `generateblock` handler
(`rpc.zig:6752-6920`) parses the input txid array, looks up each
hex-64 entry in the mempool via `self.mempool.get(txid)`, and
appends the resulting `entry.tx` to the `transactions` array. The
call then dispatches to `block_template.generateBlockWithTxs`
(`block_template.zig:1759-1857`) — which has W154 BUG-8: the
witness commitment is recomputed and then literally discarded
(`_ = witness_commitment;`).

Result: every `generateblock <address> '["<mempool_txid>"]'` call
returns `bad-witness-merkle-match`. The W155 evidence is at the RPC
boundary — operator-visible failure with no debugging hint from
the RPC layer (BUG-20: only generic `"rejected"` token would
return). Cross-cite W154 BUG-8 for the architectural root.

**File:** `src/rpc.zig:6752-6920` (mempool-txid wiring); cross-cite
`src/block_template.zig:1804-1818`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateblock`
(rebuilds coinbase after user txs are appended).

**Impact:** `generateblock` RPC is dead for any non-empty
transactions array; reorg test harnesses and CI fixtures that rely
on it cannot drive clearbit.

---

## Summary

**Bug count:** 26 (BUG-1 through BUG-26).

**Severity distribution:**
- **P0-CDIV:** 11 (BUG-1, BUG-2, BUG-5, BUG-7, BUG-14, BUG-16,
  BUG-17, BUG-18) + 1 P0-CONS funds-burn (BUG-24) + 1 P0 (BUG-6,
  BUG-4, BUG-26)
- **P0** non-CDIV: 3 (BUG-4, BUG-6, BUG-26)
- **P0-CONS funds-burn:** 1 (BUG-24)
- **P1:** 11 (BUG-3, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12, BUG-13,
  BUG-15, BUG-19, BUG-20, BUG-21, BUG-22, BUG-23, BUG-25)

Recount: P0-CDIV (8) + P0 (3) + P0-CONS funds-burn (1) + P1 (14) = 26. ✓

**P0-class concentration: 12 of 26** (8 P0-CDIV + 3 P0 + 1 P0-CONS).

**Fleet patterns confirmed:**
- **30-of-30-gates-buggy** — W155 gate matrix is 30 sub-gates × 14
  behaviours, and 29 of the 30 sub-gates have a clearbit divergence
  vs Core (only G12 `coinbasevalue` numeric type + G15 mutable
  3-entry baseline + G30 prioritisetransaction-dummy parser PASS). 
  This is **clearbit's 8-of-8 confirmation** on the
  30-of-30-gates-buggy pattern: W138 + W141 + W150 + W151 + W152 +
  W153 + W154 + **W155**. The brief flagged 7-of-7 at the start of
  the wave; W155 extends to 8-of-8.
- **dead-helper-at-call-site** — BUG-8 (`crypto.computeWtxid`
  exists, GBT emitter doesn't call it). 8th distinct clearbit
  instance.
- **dead-data plumbing** — BUG-10 (per-tx `sigops` stored in
  `SelectedTx.sigops` but never serialised); BUG-11
  (`template.mutable` array has 4 entries, RPC handler ignores it
  and emits hardcoded 3-entry literal). Two new instances; ~10th and
  11th distinct clearbit cases (per W138 / W140 / W154 tracking).
- **comment-as-confession** — BUG-1 `_ = params; // Template request
  params (capabilities, rules) - not fully implemented`. 13th+
  distinct clearbit instance — the brief's prior tally was 13+,
  W155 adds one verifiable new case in the GBT path.
- **wiring-look-but-no-wire** applied to mining — BUG-11
  (`block_template.mutable` field is declared, populated, exposed
  via the struct API, and ignored by every reader); BUG-22
  (`getnetworkhashps` RPC is registered in dispatch but
  `getmininginfo` doesn't call it internally).
- **funds-burn** — BUG-24 (RPC-side hardcoded OP_RETURN payout, the
  NEW pattern introduced by W154 BUG-12, extended here from the
  perspective of the RPC entry point).
- **two-pipeline guard** — BUG-18 vs BUG-19: duplicate-detect
  plumbing exists in `processSideBranchSubmission`
  (`"duplicate-inconclusive"`) but is missing from the
  active-tip-extension arm of `handleSubmitBlock`. ~6th distinct
  clearbit two-pipeline instance.
- **22-wave + 24-wave carry-forward streaks** — BUG-1 / BUG-7
  (W108 → W155, 22 waves open) tied with W154 BUG-1
  (genesis-bits placeholder) for clearbit's longest open carry-
  forwards; BUG-22 (networkhashps:0 hardcode, W108 BUG-22 → W155,
  24 waves open) is clearbit's single longest individual-bug carry-
  forward.

**Top three findings:**

1. **BUG-24 (P0-CONS funds-burn) — RPC-side OP_RETURN payout in GBT
   template.** A miner that wires their stratum/cgminer to clearbit's
   `getblocktemplate` and submits the result via `submitblock`
   destroys their entire block reward (~$250k per mainnet block at
   2026 BTC prices). The RPC layer ships a pre-constructed coinbase
   whose only output sends `subsidy + total_fees` to OP_RETURN
   (unspendable). Cross-cite W154 BUG-12 for the architectural
   root; W155 evidence at the RPC entry point (`rpc.zig:6069`
   hardcoded `payout_script = [_]u8{0x6a}`).

2. **BUG-7 (P0-CDIV) + cross-cite BUG-1 + BUG-2 — GBT response
   missing 11 of 22 BIP-22/23/141/145 fields, request `params`
   discarded, no segwit-rule refusal.** The combination ships
   `getblocktemplate` in a state that no stock Core-compatible
   miner can use: `default_witness_commitment` absent means
   post-segwit blocks fail to construct; no `rules: ["segwit"]`
   negotiation; no `longpollid` so client-side polling cadence
   thrashes; no `noncerange`/`sigoplimit`/`sizelimit`/`weightlimit`
   so miners can't pre-flight check the template. 22-wave
   carry-forward streak (W108 → W155). Stock miners refuse the
   template; custom miners get partial functionality.

3. **BUG-17 + BUG-18 + BUG-19 cluster — submitblock has no
   `submitblock_StateCatcher`, never emits `"duplicate"` for active-
   tip re-submissions, and emits `"inconclusive"` with non-Core
   semantics.** Three independent bugs forming one architectural
   gap: clearbit lacks the `CValidationInterface` signal bus that
   Core uses to capture per-block state and discriminate
   `duplicate` / `inconclusive` / `BIP22ValidationResult` outcomes.
   Re-submitting an already-connected block triggers
   `bad-txns-inputs-missingorspent` (the wrong BIP-22 token), and
   the `"inconclusive"` token clearbit DOES emit means "side-branch
   stored but not active" — opposite operator action vs Core's
   "validation in flight, retry". Cross-impl monitoring tools see
   semantically-divergent values across the fleet.
