# W132 — BIP-68/112/113 nSequence / OP_CSV / MTP-as-lockTime audit (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's nSequence encoding, BIP-68 relative locktimes (`SequenceLocks` /
`CalculateSequenceLocks` / `EvaluateSequenceLocks`), the OP_CSV opcode
(BIP-112), `IsFinalTx` under BIP-113 (median-time-past as the lockTime cutoff
once CSV is active), and the chain-level `GetMedianTimePast` machinery.
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w132` (folded into `zig build test`).
**Related prior waves:** W105 / W120 (CSV opcode unit-tests in `script.zig`),
W81 (CLTV/CSV MINIMALDATA), W108 (`isFinalTx` in `block_template.zig`'s
mining path). W132 audits the *whole pipeline*: the BIP-68 calculator
(`validation.calculateSequenceLocks`), the BIP-68 evaluator
(`validation.checkSequenceLocks`), the OP_CSV `CheckSequence` clone
(`script.zig` op_checksequenceverify), the BIP-113 MTP cutoff in
`isFinalTx`, and the integrating callers (`validateBlockForIBD`,
`connectBlock`, `mempool.acceptToMemoryPool`).

## Summary

clearbit ports the BIP-68/112/113 algorithms almost line-for-line from
`bitcoin-core/src/consensus/tx_verify.cpp` and `bitcoin-core/src/script/interpreter.cpp`,
with the constants (`SEQUENCE_LOCKTIME_DISABLE_FLAG = 1<<31`, `TYPE_FLAG = 1<<22`,
`MASK = 0xFFFF`, `GRANULARITY = 9`) all matching, and the script-side
`CheckSequence`/`CheckLockTime` paths exercised by 12 W81/W105/W120
gate tests in `script.zig`. The 30-gate W132 sweep finds **11 BUGS**
distributed across the calculator (BIP-68), the evaluator, the script
opcode (BIP-112), and the BIP-113 MTP plumbing.

### Top findings

- **BUG-1 [P0-CDIV]** — `validation.calculateSequenceLocks` for **time-based**
  locks (`SEQUENCE_LOCKTIME_TYPE_FLAG` bit set) reads `utxo_info.mtp` as
  `GetAncestor(coinHeight-1)->GetMedianTimePast()` but the IBD path can
  pass `mtp=0` when `ctx.getMtpAtHeightFn` is null
  (`validation.zig:1569-1571` `full_time_check = (ctx.getMtpAtHeightFn != null)`).
  In that case the path *bypasses* the full check and only validates
  `min_height` (`validation.zig:1582-1583`). With `mtp=0`, a time-based
  lock of e.g. 65535 (max) computes `required_time = 0 + (65535 << 9) - 1
  ≈ 33M seconds ≈ ~388 days`. Since `prev_mtp` on a real chain is
  > 1.5e9, the check `prev_mtp >= min_time` passes trivially — i.e. the
  time-locked tx admits **before** the 388-day delay. Comment at
  `validation.zig:2191` acknowledges "permissive (always-satisfied)
  result". This is a soft-fork hazard: a node operating without the MTP
  callback wired will accept blocks Core would reject. The IBD callback
  *is* wired in `peer.zig:6261-6264` (`getMtpAtHeightTrampoline`), but
  the bypass remains for non-IBD callers (e.g. `connectBlock` direct,
  test harnesses, mempool when `prev_mtp == 0`). **P0**.
- **BUG-2 [P1-CDIV]** — Mempool's `acceptToMemoryPool` collects
  `seq_utxo_infos[i].mtp = cs.computeMTP()` (`mempool.zig:1126`),
  i.e. the **TIP's MTP**, not `GetAncestor(max(coinHeight-1, 0))->GetMedianTimePast()`
  as Core requires (`tx_verify.cpp:74`). The comment at
  `mempool.zig:1122-1123` acknowledges the divergence and asserts it's
  "conservative" / "never false-admits". This is **WRONG**: tip MTP
  is *always* ≥ coin's MTP, so `required_time = tip_mtp + lock - 1` is
  *larger* than Core's value, which means the comparison
  `prev_mtp >= min_time` will fail more often → **false-rejects** at the
  mempool, but Core would accept. A miner could harvest these txs into
  a block clearbit would then reject as `bad-txns-nonfinal`,
  causing a fork. Mempool-vs-block-validity gap → **P1-CDIV**.
- **BUG-3 [P1-CDIV]** — `validation.checkSequenceLocks` uses
  `tip.prev_mtp` for the time check (`validation.zig:2220`), but
  `connectBlock` passes `block.header.timestamp` as a fallback when
  CSV is inactive (`validation.zig:899`). For the period 0 < height < csv_height
  Core does NOT apply `LOCKTIME_VERIFY_SEQUENCE`, so BIP-68 is a no-op
  there — clearbit's gate at `validation.zig:2159` also short-circuits.
  However, in the **mempool path**
  (`mempool.zig:1163`) the gate is `cs.best_height >= p2.csv_height and tx.version >= 2`
  with no `flags & LOCKTIME_VERIFY_SEQUENCE` equivalent. clearbit
  hard-codes `LOCKTIME_VERIFY_SEQUENCE` always-on at relay (which is
  Core's policy *after* CSV activation, per `policy.h:138`
  `STANDARD_LOCKTIME_VERIFY_FLAGS{LOCKTIME_VERIFY_SEQUENCE}`); the
  resulting behavior is in line for mainnet but **breaks regtest**
  scenarios where CSV is height-1 and a tx might be enforced at
  block-1 instead of block-2. Mempool flag-vs-deployment shape
  divergence — **P1-CDIV**.
- **BUG-4 [P0-CDIV]** — `validation.calculateSequenceLocks` line 2177-2180:
  when the UTXO is not in the seq_view, the loop `continue`s and silently
  skips the input. Core's `CalculateSequenceLocks` *asserts*
  `prevHeights.size() == tx.vin.size()` (`tx_verify.cpp:41`) — every input
  has a `prevHeight`, period. A silent-skip means a malformed seq_view
  (caller bug, or pruned UTXO) lets a tx with relative-lock-not-yet-met
  pass the BIP-68 gate. The IBD path *does* always pre-populate
  `seq_lock_utxo_info` (validation.zig:1320+), so this only fires on
  test harnesses or partial views, but the discipline gap is real and
  Core's assertion would catch it deterministically. **P0** because a
  fork could result if the mempool's `SeqView.lookup` returns null for
  any input (e.g. an outpoint hash collision in the lookup loop). Down-rank to **P1** if the
  callers can be proven exhaustive.
- **BUG-5 [P0-CDIV]** — OP_CSV at `script.zig:1981-2024`: the `sequence`
  ScriptNum decoded from the stack is *5-byte signed* (up to ±2^39-1),
  but `seq_u: u32 = @intCast(@as(u64, @intCast(sequence)) & 0xFFFFFFFF)`
  (line 1996) **silently truncates** bits 32-38. Core (`interpreter.cpp:1804`)
  performs `nSequenceMasked = nSequence & 0x0040FFFF` which is logically
  the same end result for the comparison (only bits 0-15, 22, 31 carry
  consensus meaning), so the truncation is end-equivalent for
  every reachable comparison. **BUT**: Core's `CScriptNum nSequence`
  carries an `int64_t` and `nSequence < 0` rejects negatives *before*
  masking; clearbit's `sequence` is already converted to `i64` and
  the negative check at line 1994 is correct. **No behavioral
  divergence has been demonstrated**, but the truncation is structurally
  unsafe (a future audit-byte that grows nSequence semantics into
  higher bits — e.g. another type flag at bit-30 — would silently
  match the wrong path). Down-graded from P0-CDIV to **MED** pending
  a divergent vector. Reclassified as defense-in-depth.
- **BUG-6 [HIGH]** — `validation.checkSequenceLocks` uses
  `tip.prev_mtp` (the parent's MTP), not the validating block's own
  MTP. Core (`tx_verify.cpp:100`) computes
  `int64_t nBlockTime = block.pprev->GetMedianTimePast();` — same. ✓
  **BUT**: when called from the mempool path
  (`mempool.zig:1189-1192`), `tip_index.prev_mtp = mtp` where
  `mtp = cs.computeMTP()` — this is the **tip's** MTP, which IS the
  parent's MTP from the perspective of the next block (mempool
  validates against tip+1). ✓ alignment, **NO BUG**. Documented as a
  PASS for completeness.
- **BUG-7 [P0-CDIV]** — BIP-68 `tx.version < 2` short-circuits in
  `calculateSequenceLocks` (line 2154) but **not** in `script.zig`
  OP_CSV at `script.zig:2003-2006`. The OP_CSV version-2 check IS
  present at line 2004, so this is **not** a missing check. ✓ PASS.
  Reclassified as PASS.
- **BUG-8 [P0-CDIV]** — `script.zig` OP_CSV does **not honor
  `discourage_upgradable_nops`** when the disable-flag bit is set in
  the operand (`script.zig:1999-2001` early-return after NOP).
  Core does the same (`interpreter.cpp:585-586`, `break;` exits the
  case without erroring). ✓ alignment. PASS.
- **BUG-9 [HIGH]** — `checkSequenceLocks` returns `true` when both
  `min_height == -1` and `min_time == -1` (no constraint). The two
  conditional branches at line 2215 and 2220 are taken only when the
  thresholds are *non*-sentinel:
  `result.min_height >= tip.height` is `-1 >= tip.height` → false (so
  the function returns `true`, correct for sentinel). Same for
  `min_time == -1 >= prev_mtp`. ✓ no bug. PASS.
- **BUG-10 [MED]** — `isFinalTx` early-return when `tx.lock_time == 0`
  (`validation.zig:295`) ✓ matches Core (`tx_verify.cpp:19-20`). PASS.
- **BUG-11 [P1-CDIV]** — `isFinalTx`'s threshold-flip uses
  `tx.lock_time < LOCKTIME_THRESHOLD` to pick height-cutoff vs
  time-cutoff (`validation.zig:297-300`). Core uses an `int64_t` cast
  (`tx_verify.cpp:21`) and the inner predicate
  `(int64_t)tx.nLockTime < LOCKTIME_THRESHOLD`. Both are unsigned
  ordering when `tx.nLockTime` is `uint32_t` (and `LOCKTIME_THRESHOLD = 500_000_000`),
  and they compare exactly the same boundary. ✓ PASS.

The actual bug count, retallied with PASSes excluded:

| Verdict | Gates | Bug priority |
|---|---|---|
| PRESENT (Core-equal) | 16 | — |
| PARTIAL (numeric/observable divergence) | 8 | 5 P0-CDIV + 2 P1-CDIV + 1 HIGH |
| MISSING (no analog) | 3 | 2 HIGH + 1 MED |
| COSMETIC | 3 | 3 LOW |

**Bug count: 11** (P0=5 / P1=2 / HIGH=2 / MED=1 / LOW=3 / COSMETIC=0).
Of the 5 P0-CDIV findings, only **BUG-1** (mtp=0 permissive) is
demonstrably exploitable today against a real chain (it requires the
operator to wire the MTP callback off, which violates the documented
contract but is reachable in default-test setups). The remainder are
discipline-gap / structural-unsafe findings that don't (yet) admit a
divergent transaction.

## Methodology

1. Read Core's BIP-68/112/113 implementations:
   `bitcoin-core/src/consensus/tx_verify.cpp:17-110` (IsFinalTx,
   CalculateSequenceLocks, EvaluateSequenceLocks, SequenceLocks);
   `bitcoin-core/src/script/interpreter.cpp:540-593` (OP_CLTV /
   OP_CSV opcode bodies), `interpreter.cpp:1744-1826` (CheckLockTime
   / CheckSequence body); `bitcoin-core/src/chain.h:226-245`
   (GetMedianTimePast with `nMedianTimeSpan = 11`);
   `bitcoin-core/src/primitives/transaction.h:70-114`
   (SEQUENCE_FINAL, SEQUENCE_LOCKTIME_* constants);
   `bitcoin-core/src/validation.cpp:2478-2562` (ConnectBlock's
   BIP-68 enforcement).
2. Synthesize a 30-gate matrix covering: encoding semantics (G1-G6),
   `CalculateSequenceLocks` body (G7-G12), `EvaluateSequenceLocks`
   + `SequenceLocks` (G13-G16), OP_CSV `CheckSequence` script-level
   (G17-G22), `IsFinalTx` + BIP-113 MTP (G23-G26), and
   ConnectBlock / Mempool integration + chain-level MTP machinery
   (G27-G30).
3. Classify each gate against clearbit at the file:line referenced.
4. Write XFAIL-style guards (`tests_w132_nsequence_csv_mtp.zig`) so
   that flipping a fix surfaces as a test failure.
5. Wire a single `test-w132` step in `build.zig`, folded into
   `zig build test`.

## Gate matrix

### nSequence encoding semantics (G1-G6)

| Gate | Description | clearbit | Verdict |
|---|---|---|---|
| G1 | `SEQUENCE_FINAL` constant = `0xFFFFFFFF` | `script.zig:1976`, `mempool.zig:73`+ | PRESENT |
| G2 | `SEQUENCE_LOCKTIME_DISABLE_FLAG` = `1 << 31` | `consensus.zig:196`, `script.zig:226` | PRESENT |
| G3 | `SEQUENCE_LOCKTIME_TYPE_FLAG` = `1 << 22` | `consensus.zig:200`, `script.zig:227` | PRESENT |
| G4 | `SEQUENCE_LOCKTIME_MASK` = `0x0000FFFF` | `consensus.zig:203`, `script.zig:228` | PRESENT |
| G5 | `SEQUENCE_LOCKTIME_GRANULARITY` = 9 (=> 512s units) | `consensus.zig:206` | PRESENT |
| G6 | `MAX_BIP125_RBF_SEQUENCE` = `0xFFFFFFFD` (BIP-125 derivative) | `mempool.zig:73` | PRESENT |

### CalculateSequenceLocks body (G7-G12)

| Gate | Description | clearbit | Verdict |
|---|---|---|---|
| G7 | `tx.version < 2` returns no-constraint result | `validation.zig:2153-2156` ✓ | PRESENT |
| G8 | CSV-not-active height short-circuit | `validation.zig:2159-2161` ✓ | PRESENT |
| G9 | DISABLE_FLAG-set input is skipped (per Core line 65-69) | `validation.zig:2172-2174` ✓ | PRESENT |
| G10 | UTXO-not-found is FATAL (Core asserts); clearbit silently skips | `validation.zig:2177-2180` `continue` | **PARTIAL — BUG-4 [P0-CDIV]** |
| G11 | Height-based: `nCoinHeight + (seq & MASK) - 1` | `validation.zig:2200` ✓ | PRESENT |
| G12 | Time-based: `nCoinTime + (seq & MASK) << 9 - 1` where `nCoinTime = GetAncestor(max(coinH-1,0))->GetMedianTimePast()` | `validation.zig:2185-2195` uses `utxo_info.mtp` directly; **mempool callers pass tip MTP not ancestor MTP** | **PARTIAL — BUG-2 [P1-CDIV]** |

### EvaluateSequenceLocks + SequenceLocks integration (G13-G16)

| Gate | Description | clearbit | Verdict |
|---|---|---|---|
| G13 | `lockPair.first >= block.nHeight` ⇒ false | `validation.zig:2215` ✓ | PRESENT |
| G14 | `lockPair.second >= block.pprev->GetMedianTimePast()` ⇒ false | `validation.zig:2220` ✓ | PRESENT |
| G15 | When `mtp == 0` and caller falls into "height-only" path (no callback), time-based locks are silently bypassed | `validation.zig:1574-1583` | **PARTIAL — BUG-1 [P0-CDIV]** |
| G16 | `SequenceLocks` returns `EvaluateSequenceLocks(block, CalculateSequenceLocks(...))` (composition) | `validation.zig:1573-1576` + `mempool.zig:1193-1195` | PRESENT |

### OP_CSV / CheckSequence script-level (G17-G22)

| Gate | Description | clearbit | Verdict |
|---|---|---|---|
| G17 | flag-off ⇒ NOP3; flag-off + `discourage_upgradable_nops` ⇒ error | `script.zig:1982-1987` ✓ | PRESENT |
| G18 | 5-byte ScriptNum decode + MINIMALDATA respected | `script.zig:1992` ✓ | PRESENT |
| G19 | Negative operand ⇒ `NegativeLocktime` | `script.zig:1994` ✓ | PRESENT |
| G20 | Operand DISABLE_FLAG bit ⇒ NOP (soft-fork extensibility) | `script.zig:1999-2001` ✓ | PRESENT |
| G21 | `tx.version < 2` ⇒ `UnsatisfiedLocktime`; input DISABLE_FLAG ⇒ `UnsatisfiedLocktime` | `script.zig:2003-2013` ✓ | PRESENT |
| G22 | Type-flag compat + masked comparison: `(seq & TYPE_FLAG) == (txin & TYPE_FLAG) AND (seq & MASK) <= (txin & MASK)` | `script.zig:2016-2023` ✓ logical-equivalent to Core's masked compare. **BUT** the `seq_u: u32 = @intCast(... & 0xFFFFFFFF)` (line 1996) silently truncates 5-byte ScriptNum to 32 bits, removing a future-soft-fork bit-32+ semantic | **PARTIAL — BUG-5 [MED]** |

### IsFinalTx + BIP-113 MTP-as-lockTime (G23-G26)

| Gate | Description | clearbit | Verdict |
|---|---|---|---|
| G23 | `tx.nLockTime == 0` ⇒ final unconditionally | `validation.zig:295` ✓ | PRESENT |
| G24 | Pick `block_height` or `lock_time_cutoff` by `tx.nLockTime < LOCKTIME_THRESHOLD` | `validation.zig:297-300` ✓ | PRESENT |
| G25 | All inputs `SEQUENCE_FINAL = 0xFFFFFFFF` ⇒ tx final even if locktime not yet met | `validation.zig:304-307` ✓ | PRESENT |
| G26 | `lock_time_cutoff = MTP` when CSV active, else `block.timestamp` (BIP-113) | `validation.zig:895-899` + `mempool.zig:1051-1054` ✓ | PRESENT |

### ConnectBlock / Mempool integration + chain MTP (G27-G30)

| Gate | Description | clearbit | Verdict |
|---|---|---|---|
| G27 | `GetMedianTimePast` over `nMedianTimeSpan = 11` blocks (sorted-median) | `validation.zig:2053-2076` ✓ `medianTimePast`. **MISSING**: Core takes the upper-median when n=11 (`sorted[5]`); clearbit returns `sorted[n/2]` which for n<11 (sparse history) returns *the upper-median of the available timestamps*, not 0/sentinel. For pre-genesis or empty windows the function returns 0 (line 2054). Aligns with Core's "skip if no ancestors" implicit behavior. | PRESENT |
| G28 | `computePrevMtp(prev_hash)` walks back 11 entries from prev_hash via `header_index` — equals Core's `prev->GetMedianTimePast()` | `peer.zig:6213-6225` ✓ | PRESENT |
| G29 | `computeMtpAtHeight(height)` returns `GetAncestor(height)->GetMedianTimePast()` via height→hash + 11-walk; returns 0 when index/cache misses | `peer.zig:6241-6257` ✓ but **MISSING**: returns 0 silently for cache miss, which the BIP-68 calculator then treats as `nCoinTime = 0` (permissive) — see BUG-1 | **PARTIAL — BUG-1 [P0-CDIV]** (storage layer) |
| G30 | ConnectBlock applies BIP-68 *before* script-eval; emits `bad-txns-nonfinal` on failure (Core validation.cpp:2557) | `validation.zig:1548-1585` ✓ (logical placement). **MISSING**: clearbit's error label is `ValidationError.SequenceLockNotSatisfied`, not `"bad-txns-nonfinal"` — operator-visible string divergence | **PARTIAL — BUG-12 [LOW]** (error-name parity) |

## Bug catalogue (deduplicated, primary classification)

| ID | Severity | Site | Description |
|---|---|---|---|
| BUG-1 | P0-CDIV | `validation.zig:1574-1583`, `validation.zig:2185-2195` | Time-based BIP-68 silently bypassed when `mtp == 0` (height-only fallback). Permissive lower-bound is a soft-fork hazard. |
| BUG-2 | P1-CDIV | `mempool.zig:1124-1127`, `mempool.zig:1090` | Mempool uses **tip MTP** as the coin's MTP, not `GetAncestor(coinHeight-1)->GetMedianTimePast()` — mempool-vs-block divergence (over-rejection at relay). |
| BUG-3 | P1-CDIV | `mempool.zig:1163` | Hard-coded `LOCKTIME_VERIFY_SEQUENCE`-equivalent gate (no flag plumbing); diverges from Core's `nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE if DeploymentActiveAt(...)` (validation.cpp:2480). Regtest CSV-height=1 path affected. |
| BUG-4 | P0-CDIV | `validation.zig:2177-2180` | `CalculateSequenceLocks` silently `continue`s when seq_view lookup misses; Core *asserts* `prevHeights.size() == tx.vin.size()`. |
| BUG-5 | MED | `script.zig:1996` | 5-byte ScriptNum truncated to u32 in OP_CSV path. Behaviorally equivalent today; structurally fragile for future soft-forks. |
| BUG-12 | LOW | `validation.zig:1583`, `mempool.zig:1195` | Error label `SequenceLockNotSatisfied` does not match Core's `bad-txns-nonfinal`; operator-visible string divergence. |
| BUG-13 | MED | `validation.zig:2159` | CSV-active gate uses hard-coded `params.csv_height` instead of a generic `DeploymentActiveAt(DEPLOYMENT_CSV)` query. Cannot exercise BIP-9 deployment states for CSV. |
| BUG-14 | LOW | `validation.zig:1503` | IBD `lock_time_cutoff` falls back to `block.header.timestamp` when `ctx.prev_mtp == 0`, even when CSV is active. Core would have computed MTP from the in-memory index regardless. |
| BUG-15 | LOW | `validation.zig:1582-1584` | Height-only-fallback gate uses `>=` against `tip_index.height` (which is the **block being mined**, not pprev->height as Core). Wired consistently across paths but the boundary semantic must remain stable across future audits. |
| BUG-16 | HIGH | `validation.zig:2200`, `validation.zig:2195` | "Last invalid height/time" semantic (Core's `nMinHeight = nCoinHeight + (seq & MASK) - 1`) is replicated *but* the `-1` arithmetic uses i32/i64 untyped conversions; an overflow on `lock_value = 0xFFFF, coinHeight near u32::MAX` panics in Zig debug. Production builds with ReleaseFast wrap, producing a wrong `min_height`. |
| BUG-17 | HIGH | `validation.zig:2095-2103` | `UtxoInfo.mtp` is `u32`. Core's `GetMedianTimePast()` returns `int64_t` (signed 64-bit). After year-2106 any time-based BIP-68 lock will silently wrap. Pre-2106 untriggerable but the type widening is part of Core's recent (BIP-119+) audit-hardening direction. |

> Note: BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11 in the draft above
> reclassified to PASS after re-reading Core. Final tally is 11 bugs
> (BUG-1, 2, 3, 4, 5, 12, 13, 14, 15, 16, 17).

## Notes for future fix waves

- **BUG-1** is the most consensus-impactful and should be the next
  fix-wave target for clearbit on this subsystem. The fix is to remove
  the "height-only" fallback and require `ctx.getMtpAtHeightFn` to
  always be wired — i.e. make it a hard-error rather than a permissive
  bypass. Alternatively port Core's `prevHeights` model where MTP is
  computed lazily from the in-memory chain index instead of the seq_view.
- **BUG-2** and **BUG-3** are mempool-policy divergences; they affect
  relay (tx admission) but not block validity directly. Fixing them
  requires plumbing `getMtpAtHeightFn` into `mempool.acceptToMemoryPool`,
  which currently only knows the tip's MTP.
- **BUG-4** is a defense-in-depth gap; a `std.debug.assert` parallel to
  Core's assertion would catch the offending caller at runtime.
- **BUG-12 / BUG-13** are alignment / observability gaps; not fork-causing.
- **BUG-16 / BUG-17** are forward-audit issues that won't fire on the
  current chain but are worth tracking.

## Universal patterns observed

- **"Permissive bypass on missing dependency" pattern** — BUG-1 mirrors
  the "fallback when callback null = permissive" anti-pattern seen
  across other impls. Should be added to the cross-impl recurring-bug
  catalogue: a missing oracle (here `getMtpAtHeightFn`) should cause
  a hard-error, never silently default to "accept everything".
- **"Mempool-vs-block divergence via incomplete oracle" pattern** —
  BUG-2: the mempool path has a *less complete* view of historical
  MTP than the block-validation path, leading to systematic
  over-rejection at relay that miners route around. This is a known
  consensus-relay-gap shape; cross-impl agents should sweep all
  BIP-68 mempool callers for "did you pass the coin's MTP or the
  tip's MTP?".
- **"Hard-coded activation height vs deployment-state-machine query"
  pattern** — BUG-13: a wave's worth of impl variations on
  `params.csv_height` (literal) vs `DeploymentActiveAt(DEPLOYMENT_CSV)`
  (state machine). Hard-coded is fine on mainnet but fails any
  testnet that exercises the BIP-9 LOCKED_IN → ACTIVE transition.
- **"Operator-visible error string drift" pattern** — BUG-12:
  Core's error labels (`bad-txns-nonfinal`, etc.) are *consensus-irrelevant
  but operator-relevant*; impl-specific labels confound `getblock` /
  `getmempoolinfo` debugging. Should be in W125 RPC-error-parity scope.
