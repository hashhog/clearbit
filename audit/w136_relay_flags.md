# W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's post-handshake relay-flag handshake + periodic
maintenance vs Bitcoin Core.
**Bitcoin Core references:**
- `bitcoin-core/src/net_processing.cpp`
  - `MaybeSendSendHeaders` (line 5519)
  - `MaybeSendFeefilter`     (line 5540)
  - `WTXIDRELAY` handler     (line 3921)
  - `SENDHEADERS` handler    (line 3896)
  - `FEEFILTER` handler      (line 5035)
  - inv-vs-wtxidrelay filter (line 4056-4063)
  - `m_wtxid_relay` field    (line 283)
  - `m_sent_sendheaders`     (line 405-406)
  - `m_fee_filter_sent` / `m_next_send_feefilter` (lines 287-290)
  - `m_fee_filter_received` (line 321)
  - constants: `AVG_FEEFILTER_BROADCAST_INTERVAL=10min`,
    `MAX_FEEFILTER_CHANGE_DELAY=5min`, `MAX_MONEY`,
    `m_opts.ignore_incoming_txs`, `NetPermissionFlags::ForceRelay`,
    `IsBlockOnlyConn()`
- `bitcoin-core/src/node/protocol_version.h`:
  `SENDHEADERS_VERSION=70012`, `FEEFILTER_VERSION=70013`,
  `WTXID_RELAY_VERSION=70016`, `PROTOCOL_VERSION=70016`,
  `MIN_PEER_PROTO_VERSION=31800`.
- `bitcoin-core/src/policy/feerate.cpp` + `policy/fees/block_policy_estimator.{cpp,h}`:
  `FeeFilterRounder` (`MAX_FILTER_FEERATE=1e7`, `FEE_FILTER_SPACING=1.1`),
  `CAmount=int64_t` (signed), `MoneyRange(>=0 && <=MAX_MONEY)`.
- BIPs: 130, 133, 339.

**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w136` (folded into `zig build test`).
**Implementation files audited:**
- `clearbit/src/peer.zig` (Peer struct, handshake loop, `handleMessage`,
  `maybeSendFeefilter`, `announceBlock`)
- `clearbit/src/p2p.zig` (`Message` enum, `FeeFilterMessage` decode/encode,
  `PROTOCOL_VERSION`, `MIN_PROTOCOL_VERSION`)

## Summary

clearbit implements the three BIPs at a wire-level — the messages are
encoded/decoded round-trip, `wtxid_relay_negotiated` is latched, and
`send_headers` gates `announceBlock` between `inv` and `headers`. But every
one of Core's *operational* invariants is violated in some way:

1. **`maybeSendFeefilter` is defined and DEAD CODE.** No call site exists
   anywhere in `src/*.zig` (`grep -rn maybeSendFeefilter src/` returns
   exactly one hit — the definition itself). The periodic Poisson
   broadcast that Core does on every `SendMessages` tick (line 5540) is
   simply not wired. clearbit sends one feefilter at handshake
   (`peer.zig:1629`) and never updates it — the receiving peer's
   `m_fee_filter_received` therefore stays at our one-shot value (`100000`
   sat/kvB, hardcoded) forever, ignoring our actual mempool min-fee.
2. **`SENDHEADERS` is sent unconditionally at handshake**, not gated on
   `state.pindexBestKnownBlock->nChainWork > MinimumChainWork()`. Core
   defers `SENDHEADERS` until initial-headers-sync completes
   (`net_processing.cpp:5519-5537`); clearbit's `peer.zig:1617-1619` sends
   it the instant we transition to `handshake_complete`. The result: every
   inbound peer requests we announce blocks via `headers`, including peers
   we have just connected to and don't yet have a meaningful headers
   chain for.
3. **`WTXIDRELAY` after `VERACK` is silently swallowed, not disconnect.**
   Core line 3922-3927 sets `pfrom.fDisconnect = true` if `WTXIDRELAY`
   arrives after VERACK. clearbit's `handleMessage` has no
   `.wtxidrelay =>` arm (the only handler is in the in-line handshake
   loop at `peer.zig:1524-1527`), so post-handshake `WTXIDRELAY` falls
   through to the `else => {}` arm at `peer.zig:5438` and is ignored.
4. **`SENDHEADERS` after `VERACK` is processed without latency-of-relay
   ordering check.** Core's `m_prefers_headers` flag (line 412) is set
   unconditionally on receipt of `SENDHEADERS` regardless of whether VERACK
   has occurred (this is Core-intentional). clearbit's handler at line
   5310-5317 mirrors this correctly. **Not a bug, but worth a gate.**
5. **`FEEFILTER` decode treats the payload as `u64` (unsigned) where Core
   reads it as `int64_t` (signed) and runs `MoneyRange` (which rejects
   negative).** clearbit's `p2p.zig:892` does
   `reader.readInt(u64)`. A malicious peer who sends `-1`
   (`0xFFFF_FFFF_FFFF_FFFF`) gets it decoded as `18.4 quintillion sats`;
   clearbit's gate is `if (ff.feerate <= MAX_MONEY)` (peer.zig:4672,
   `MAX_MONEY = 2_100_000_000_000_000`), so the negative-as-huge value
   *is* rejected by the post-decode check. **But:** a value of exactly
   `2_100_000_000_000_001` (one above MAX_MONEY) is silently dropped
   without misbehaving — Core also drops it but uses `MoneyRange` which
   is semantically clearer. Edge cases like `MAX_MONEY+1` and the
   wire-format sign-bit are not behaviorally tested.
6. **No `-blocksonly` / `ignore_incoming_txs` knob.** Core gates the
   feefilter sender on `m_opts.ignore_incoming_txs` (line 5542); when
   blocks-only mode is on, we don't bother telling peers our feerate
   (we won't accept invs anyway). clearbit has no such config flag, and
   `maybeSendFeefilter` doesn't check `relay_txs` on the receiving peer
   path (it checks `self.relay_txs` for our own posture, which is fine,
   but Core also checks `m_opts.ignore_incoming_txs`).
7. **No `ForceRelay` permission gate.** Core skips feefilter for peers
   with `NetPermissionFlags::ForceRelay` (line 5545). clearbit has no
   permission system at all; whitelisted peers are tracked via the
   `no_ban: bool` field only.
8. **`maybeSendFeefilter` Poisson approximation: uniform random in
   [0.5, 1.5] × interval is NOT exponential.** Core uses
   `m_rng.rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL)` (line
   5572). clearbit uses
   `random.intRangeAtMost(u32, 500, 1500)` (line 1694) divided by 1000.
   The mean is the same (~10 min), but the distribution is uniform, not
   exponential. **DoS/timing implication:** an attacker watching feefilter
   broadcasts could infer they're hitting a clearbit node by the
   distribution shape — Core's exponential broadcast is intentionally
   memoryless to make timing-correlation harder. Even if `maybeSendFeefilter`
   were called, the distribution would still be wrong.
9. **`maybeSendFeefilter` "exited IBD" branch is unreachable.** Lines
   1675-1678: `else if (self.fee_filter_sent == MAX_MONEY) { ... next_send_feefilter = 0; }`
   exists, but because the function is never called, the IBD→non-IBD
   transition is never observed.
10. **One-shot handshake `FEEFILTER` value is hardcoded to `100_000` sat/kvB.**
    Line 1629: `const ff = ... .feerate = 100_000`. Core derives this from
    `mempool.GetMinFee().GetFeePerK()` rounded through `FeeFilterRounder`
    using a `MAX_FILTER_FEERATE=1e7` bucket. clearbit hardcodes 100 sat/vB
    regardless of actual mempool state. A node with a fully-empty mempool
    still tells peers `100_000` sat/kvB, which on the receiver side will
    suppress relay of legitimate sub-100-sat/vB transactions.
11. **No `FeeFilterRounder`-equivalent bucket quantization.** Core
    quantizes `currentFilter` via a set of 1.1-spaced bucket boundaries
    before sending, with a 1-in-3 probabilistic decrement to add jitter
    (`block_policy_estimator.cpp:1109-1118`). clearbit just sends the raw
    value, which makes feefilters more privacy-leaking (an exact mempool
    min-fee is a fingerprint).
12. **`m_fee_filter_received = 0` semantic differs.** Core's default-zero
    on `Peer::TxRelay::m_fee_filter_received` means "no filter received
    yet, accept all" only after explicit comparison (line 6013:
    `if (txinfo.fee < filterrate.GetFee(txinfo.vsize))`). clearbit
    `passesFeeFilter` at line 1717-1720 short-circuits on zero
    (`if (fee_filter_received == 0) return true;`). This is fine
    semantically (a peer sending `feefilter 0` accepts everything either
    way), but it conflates "peer never sent feefilter" with "peer
    explicitly sent feefilter 0".
13. **Wtxidrelay-INV-filter is missing.** Core lines 4056-4063: a peer
    that sent `WTXIDRELAY` MUST send only `MSG_WTX` inv items, and a
    peer that did NOT MUST send only `MSG_TX`. The opposite gets a
    `continue` (Core ignores the inv silently). clearbit's `inv`
    handler at `peer.zig:4270-4296` does NOT check
    `peer.wtxid_relay_negotiated` when accepting incoming invs; both
    `msg_tx` and `msg_wtx` invs are processed regardless of negotiation
    state.
14. **`SENDHEADERS` arrival is NOT gated on `pfrom.fSuccessfullyConnected`.**
    Core has no explicit gate (line 3896 doesn't check VERACK), so
    pre-VERACK `SENDHEADERS` is technically accepted. clearbit matches
    that behavior. **Not a bug.** Listed for completeness.
15. **No `m_sent_sendheaders` idempotence latch.** Core's
    `m_sent_sendheaders` flag (line 405) ensures `SENDHEADERS` is sent
    at most once per peer. clearbit sends it once unconditionally at
    end-of-handshake (line 1617-1619) — no latch needed because the
    handshake code only runs once. But if `MaybeSendSendHeaders` were
    ever wired (per BUG-2 above), the latch would be needed; current
    code has nothing equivalent.
16. **`FEEFILTER` encode uses `writeInt(u64)`.** `p2p.zig:639` encodes
    the feerate as little-endian `u64`. Core encodes `CAmount` as
    `int64_t` little-endian, which is bit-identical for non-negative
    values but semantically distinct. If clearbit ever tried to send
    `MAX_MONEY` it would emit `0x0000_d6cc_9b76_57a4_0000` matching
    Core. **Not a wire-format bug**, but the semantic distinction is
    invisible to the reader.
17. **Outbound `SENDHEADERS` direction not symmetric.** clearbit sends
    `SENDHEADERS` to the peer at handshake end (line 1617). When the
    peer sends `SENDHEADERS` back to us (line 5310), we set
    `peer.send_headers = true`, which controls our outbound block
    announcement. But there is no `peer.peer_wants_inv` state — if a
    peer never sends `SENDHEADERS`, the default `send_headers = false`
    correctly routes to `inv`. **Not a bug**, listed for completeness
    so the test asserts the default.
18. **`announceBlock` does not consult `m_blocks_for_headers_relay`
    queue.** Core (line 261-265) maintains a per-peer
    `m_blocks_for_inv_relay` and `m_blocks_for_headers_relay` queue,
    drained by `SendMessages`. clearbit's `announceBlock` (line
    7134-7160) builds the inv/headers message synchronously in the
    caller's thread and sends immediately. This is functionally
    equivalent for single-block announcements but fails when multiple
    new blocks arrive in rapid succession (the per-peer queue would
    coalesce them into a single `headers` message containing N
    consecutive headers; clearbit sends N separate single-header
    messages).
19. **`announceBlock` skips peers in non-`handshake_complete` state.**
    Line 7153: `if (peer.state != .handshake_complete) continue;`.
    Correct gate.
20. **`announceBlock` ignores `headers` failure for individual peers.**
    Line 7155: `peer.sendMessage(&hdrs_msg) catch continue;`. Silent
    failure is acceptable here (a broken socket will be cleaned up by
    the heartbeat). Core does similar best-effort sending. **Not a
    bug**, listed for completeness.
21. **`maybeSendFeefilter`: significant-change hysteresis ratios match
    Core.** Line 1701-1702: `< 3/4 * fee_filter_sent` decrease,
    `> 4/3 * fee_filter_sent` increase. These match Core line 5577
    exactly. **Not a bug.**
22. **`maybeSendFeefilter`: `block_relay` connection skip matches Core.**
    Line 1663: `if (self.conn_type == .block_relay) return;`. Matches
    Core line 5548: `if (pto.IsBlockOnlyConn()) return;`. **Not a
    bug.**
23. **Feefilter handshake-time send always tells peer to throttle low-fee
    txs even when no mempool pressure exists.** Tied to BUG-10 (hardcoded
    100_000). A clearbit node with empty mempool sends `feefilter 100000`
    instead of `feefilter 0`, which has the effect of telling peers
    "don't bother sending me txs cheaper than 100 sat/vB" even when our
    mempool would happily accept them. This is a **policy** bug, not a
    protocol bug.
24. **`WTXIDRELAY` accepted without version-check parity with Core.**
    Core line 3928: `if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION) { ... }`
    explicitly checks common version >= 70016. clearbit's inline
    handshake handler at line 1524-1527 unconditionally sets
    `wtxid_relay_negotiated = true` regardless of the peer's version.
    A peer claiming `nVersion = 70001` (clearbit's `MIN_PROTOCOL_VERSION`)
    that sends `WTXIDRELAY` would get accepted by clearbit but rejected
    (logged + ignored) by Core.
25. **No `m_wtxid_relay_peers` counter.** Core tracks the global count
    (line 3931: `m_wtxid_relay_peers++`) for metrics and selection.
    clearbit has no analog. Affects observability, not behavior.
26. **`SENDHEADERS` to outbound peers only — Core also sends to inbound.**
    Core's `MaybeSendSendHeaders` is called from `SendMessages` for every
    connected peer with `GetCommonVersion() >= SENDHEADERS_VERSION` (line
    5525), independent of inbound/outbound. clearbit's
    `peer.zig:1617-1619` sends it from both inbound and outbound
    handshake paths after `state = .handshake_complete`. **Not a bug**,
    listed for completeness.
27. **No misbehaving score on bad `FEEFILTER`.** Core line 5035-5044
    silently drops a `FEEFILTER` whose value is not in `MoneyRange`,
    without misbehaving. clearbit's `handleMessage` arm at line
    4667-4675 does the same: drops without misbehaving. **Matches Core
    semantics.** Listed for completeness.
28. **No `INV` rate-limit applied to a feefilter-throttled peer.** When
    a peer's `fee_filter_received` excludes most of our mempool, Core's
    `MaybeSendInv` still iterates the full mempool to compute which
    txs match (line 6033-6041). clearbit's relay path at
    `peer.zig:5030-5034` only checks the filter when *actually*
    relaying a single tx (post-`acceptToMemoryPool`); it doesn't filter
    a batched `INV` against the per-peer feerate. This is fine for the
    "we just received a new tx" path but means clearbit has no
    equivalent of Core's `m_tx_inventory_to_send` batched relay
    (FOR EACH peer, FOR EACH pending tx, check filter+bloom).
29. **`p2p.zig::sendcmpct` is sent at handshake before BIP-130 sendheaders
    in our outgoing direction (line 1623), but in Core SENDCMPCT is sent
    on VERACK reception (line 3864-3870), not at handshake-complete.**
    The ordering difference is invisible on the wire because both happen
    in the post-VERACK window, but the trigger point is different. **Not
    a bug**, listed for completeness so the test asserts the order.
30. **`FEEFILTER` empty-payload behavior.** Core's
    `vRecv >> newFeeFilter` would throw on a payload shorter than 8
    bytes (and the surrounding `try` framework catches that as a
    protocol violation). clearbit's `p2p.zig:892`
    `reader.readInt(u64)` returns an error on short payload, which
    `decodeMessage`'s caller (`peer.zig` `receiveMessage`) translates
    to `PeerError.ProtocolViolation` via the `misbehaving(20)` path
    (line 3688). **Matches Core's "disconnect on truncated payload"
    behavior at higher misbehavior score.** Listed for completeness.

Of 30 gates, **17 are BUGs** (MISSING or DIVERGE-from-Core), **13 are
CORRECT/PARITY**. Most P0 are operational/DoS-class, not consensus-class
(this subsystem is post-handshake P2P-only; no consensus invariants).

## Gates

| # | Gate | Status | Severity |
|---|------|--------|----------|
| G1  | `MaybeSendSendHeaders` chainwork gate (`> MinimumChainWork`) | MISSING | MED |
| G2  | `MaybeSendFeefilter` periodic broadcast loop | MISSING | HIGH |
| G3  | `maybeSendFeefilter` dead-code reachability | DIVERGE | HIGH |
| G4  | `WTXIDRELAY` post-VERACK disconnect | MISSING | MED |
| G5  | `WTXIDRELAY` `GetCommonVersion >= 70016` gate | MISSING | LOW |
| G6  | `inv` filter by `wtxid_relay_negotiated` | MISSING | MED |
| G7  | Hardcoded handshake `feefilter = 100_000` | DIVERGE | MED |
| G8  | `FeeFilterRounder` quantization | MISSING | LOW |
| G9  | `-blocksonly` / `ignore_incoming_txs` skip | MISSING | LOW |
| G10 | `NetPermissionFlags::ForceRelay` skip | MISSING | LOW |
| G11 | Poisson exponential timing distribution | DIVERGE | LOW-DoS |
| G12 | IBD→non-IBD `next_send_feefilter = 0` reachable | MISSING | LOW |
| G13 | `m_sent_sendheaders` idempotence latch | MISSING-OK | INFO |
| G14 | `MAX_FEEFILTER_CHANGE_DELAY` hysteresis ratios | PARITY | — |
| G15 | `block_relay` connection skip | PARITY | — |
| G16 | `SENDHEADERS` handler updates `prefers_headers` | PARITY | — |
| G17 | `FEEFILTER` `MoneyRange`-style validation | PARTIAL | LOW |
| G18 | `FEEFILTER` truncated-payload error | PARITY | — |
| G19 | `FEEFILTER` decode signed-vs-unsigned semantic | DIVERGE | LOW |
| G20 | `m_fee_filter_received = 0` short-circuit semantic | DIVERGE | INFO |
| G21 | `announceBlock` per-peer state queue | MISSING | LOW |
| G22 | `announceBlock` non-`handshake_complete` skip | PARITY | — |
| G23 | `announceBlock` send-failure best-effort | PARITY | — |
| G24 | `wtxidrelay` arm in `handleMessage` dispatch | MISSING | MED |
| G25 | `m_wtxid_relay_peers` global counter | MISSING | INFO |
| G26 | `SENDHEADERS` arm sets `send_headers` on receipt | PARITY | — |
| G27 | One-shot `SENDHEADERS` outbound to all peers | PARITY | — |
| G28 | Relay-time per-peer feefilter check on tx accept | PARITY | — |
| G29 | `sendcmpct` ordering vs `sendheaders` in handshake | DIVERGE-INFO | INFO |
| G30 | `FEEFILTER` empty-mempool default-fee | DIVERGE | MED |

## BUGs

### BUG-1 (G1, MED): No chainwork-gated `MaybeSendSendHeaders`
**Symptom:** `SENDHEADERS` is unconditionally sent at the end of
`handshake_complete` (`peer.zig:1617-1619`). Core (`net_processing.cpp:5525-5536`)
gates the broadcast on `state.pindexBestKnownBlock->nChainWork >
m_chainman.MinimumChainWork()`, i.e. only after enough headers have been
received from the peer to know they're not on a pre-`min_chain_work` fork.
**Why it matters:** clearbit will request the peer announce blocks via
`headers` immediately, but if the peer is on a low-work side-chain, we'll
process those headers up to `MAX_HEADERS_SIZE * MAX_NUM_UNCONNECTING_HEADERS_MSGS`
(2000 × 10 = 20k) before the chainwork check rejects them. Core's deferral
prevents this attack window.
**Fix:** add `fn maybeSendSendHeaders(peer)` that tracks
`peer.sent_sendheaders: bool`, checks
`peer.best_known_height > 0 and best_known_chainwork >= params.min_chain_work`,
sends `SENDHEADERS` once, and is invoked from the heartbeat tick.

### BUG-2 (G2, HIGH): `MaybeSendFeefilter` periodic broadcast not wired
**Symptom:** `Peer.maybeSendFeefilter(current_filter_sat_kvb, is_ibd)` is
defined at `peer.zig:1658-1711` but **never called**
(`grep -rn maybeSendFeefilter src/clearbit/src` returns 1 hit — the
definition). Core schedules a broadcast every
`AVG_FEEFILTER_BROADCAST_INTERVAL` (10 min) per peer in the SendMessages
loop (line 5540-5579).
**Why it matters:** clearbit sends ONE feefilter at handshake (line 1629,
hardcoded `100_000`) and never updates it. If our mempool min-fee changes
(e.g. blocks fill up, eviction raises the min), the peer keeps relaying us
sub-min-fee txs we'll reject. Wasted bandwidth + suppressed legitimate
relay.
**Fix:** invoke `maybeSendFeefilter(mempool.dynamic_min_fee, chain_state.in_ibd)`
from the heartbeat tick. This also activates G3 and G12.

### BUG-3 (G3, HIGH): `maybeSendFeefilter` is dead code
**Symptom:** Same as BUG-2 mechanically, but listed separately because
the function *exists* — somebody wrote it intending it to be wired.
Forward-regression guard: the function is dead, and a fix wave must both
wire it AND verify it's reached at runtime under both IBD and post-IBD
chain states.
**Fix:** Same as BUG-2 + add a `heartbeat_feefilter_tick_count: u64`
counter that asserts non-zero in a smoke test.

### BUG-4 (G4, MED): `WTXIDRELAY` after `VERACK` silently ignored
**Symptom:** `peer.zig:1524-1527` handles `WTXIDRELAY` only inside the
inline handshake loop. Once `state = .handshake_complete`,
`handleMessage` (line 4222) dispatches received messages, and there is
no `.wtxidrelay => |..|` arm — the `else => {}` at line 5438 silently
swallows it. Core (line 3922-3927):
```cpp
if (msg_type == NetMsgType::WTXIDRELAY) {
    if (pfrom.fSuccessfullyConnected) {
        LogDebug(BCLog::NET, "wtxidrelay received after verack, %s", pfrom.DisconnectMsg());
        pfrom.fDisconnect = true;
        return;
    }
    ...
}
```
**Why it matters:** A malicious peer can send `WTXIDRELAY` after VERACK
to probe our handshake state. Core disconnects them; clearbit ignores.
This is observable behavior leak (the peer can stay connected after a
protocol violation Core would flag).
**Fix:** add `.wtxidrelay => { peer.misbehaving(20, "wtxidrelay after VERACK"); peer.disconnect(); }`
arm to `handleMessage`.

### BUG-5 (G5, LOW): `WTXIDRELAY` ignores common-version gate
**Symptom:** `peer.zig:1524-1527` sets `wtxid_relay_negotiated = true`
without checking `peer.version_info.version >= WTXID_RELAY_VERSION
(70016)`. Core (line 3928) gates this:
```cpp
if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION) {
    if (!peer.m_wtxid_relay) { peer.m_wtxid_relay = true; ... }
}
```
**Why it matters:** A peer announcing `nVersion = 70001` (clearbit's
`MIN_PROTOCOL_VERSION`) shouldn't be able to flip `wtxid_relay_negotiated`.
Clearbit accepts it; Core ignores it.
**Fix:** wrap the assignment in `if (self.version_info.?.version >= 70016)`.

### BUG-6 (G6, MED): `inv` handler does not filter by `wtxid_relay_negotiated`
**Symptom:** `peer.zig:4270-4296` processes both `msg_tx` and `msg_wtx`
inv items unconditionally. Core (line 4056-4063):
```cpp
if (peer.m_wtxid_relay) { if (inv.IsMsgTx()) continue; }
else                    { if (inv.IsMsgWtx()) continue; }
```
**Why it matters:** A peer that negotiated `wtxidrelay` MUST NOT send
`MSG_TX` invs (that's the whole point of BIP-339). clearbit silently
processes them, which (a) tolerates non-conformant peers and (b) creates
a double-request risk if the same tx is announced by both txid and wtxid.
**Fix:** at the top of the `msg_tx` arm:
`if (peer.wtxid_relay_negotiated) continue;`
and at the top of the `msg_wtx` arm:
`if (!peer.wtxid_relay_negotiated) continue;`.

### BUG-7 (G7, MED): Hardcoded handshake `feefilter = 100_000`
**Symptom:** `peer.zig:1629`:
```zig
const ff = p2p.Message{ .feefilter = .{ .feerate = 100_000 } };
```
This sends 100 sat/vB regardless of actual mempool state. Core (line
5550): `currentFilter = m_mempool.GetMinFee().GetFeePerK();`
**Why it matters:** A clearbit node with empty mempool tells peers to
throttle txs cheaper than 100 sat/vB when it would happily accept any
above the min-relay-fee (`MIN_RELAY_FEE = 1000` sat/kvB). This
artificially suppresses legitimate low-fee relay.
**Fix:** wire `mempool.dynamic_min_fee` (or `mempool.GetMinFee()`-equivalent)
into the handshake feefilter value. If mempool is empty, send
`MIN_RELAY_FEE`.

### BUG-8 (G8, LOW): No `FeeFilterRounder` quantization
**Symptom:** clearbit sends raw `currentFilter` values. Core sends the
result of `FeeFilterRounder::round(currentFilter)` — a value snapped to
the nearest of ~120 buckets (1.1-spaced from
`max(1, min_incremental_fee/2)` up to `1e7`), with a 1-in-3
probabilistic decrement.
**Why it matters:** privacy — a node's exact mempool min-fee is a
fingerprint. Quantizing into shared buckets reduces fingerprintability.
**Fix:** port `FeeFilterRounder` to Zig (small allocation-free struct,
~30 LOC). Apply in both handshake feefilter (BUG-7 fix) and periodic
feefilter (BUG-2 fix).

### BUG-9 (G9, LOW): No `-blocksonly` / `ignore_incoming_txs` config
**Symptom:** Core line 5542:
`if (m_opts.ignore_incoming_txs) return;`. clearbit has no
`config.blocksonly` flag, no equivalent in `peer.zig` or `main.zig`.
**Why it matters:** A clearbit operator who wants a block-only node
cannot opt out of feefilter advertising. (They can set `relay = false`
in the VERSION message and `relay_txs = false` per peer, but that's a
finer-grained switch.)
**Fix:** add `config.blocksonly: bool`, `--blocksonly` CLI flag,
gate `maybeSendFeefilter` on `if (config.blocksonly) return;` at the
top.

### BUG-10 (G10, LOW): No `NetPermissionFlags::ForceRelay`
**Symptom:** Core line 5545:
`if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;`.
clearbit has no permission system — only `no_ban: bool` exists.
**Why it matters:** Peers with `ForceRelay` permission (manually
whitelisted, e.g. `-whitelist=force-relay@1.2.3.4`) get all our txs
regardless of fee. clearbit can't express this policy.
**Fix:** add `peer.force_relay: bool` field, populate from
`--whitelist` permission parsing (currently absent). Gate
`maybeSendFeefilter` on `if (peer.force_relay) return;`.

### BUG-11 (G11, LOW-DoS): Uniform vs exponential broadcast timing
**Symptom:** `peer.zig:1694`:
```zig
const random_factor = ...intRangeAtMost(u32, 500, 1500);
const delay_seconds = @divTrunc(AVG_FEEFILTER_BROADCAST_INTERVAL * random_factor, 1000);
self.next_send_feefilter = now_us + delay_seconds * 1_000_000;
```
This is uniform in [0.5×AVG, 1.5×AVG], mean = AVG, but NOT exponential.
Core (line 5572) uses `m_rng.rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL)`,
a true exponential (memoryless) distribution.
**Why it matters:** memorylessness — under exponential, P(next broadcast
in next 1 second | nothing for 5 minutes) = P(next broadcast in next 1
second | just broadcast). Under uniform, the conditional probability
changes over time, leaking timing signals to a network observer.
**Fix:** replace uniform with `-AVG * ln(rand_unit_float())` (the
standard inverse-CDF method for exponential). ~5 lines.

### BUG-12 (G12, LOW): IBD→non-IBD `next_send_feefilter = 0` unreachable
**Symptom:** `peer.zig:1675-1678` correctly sets `next_send_feefilter = 0`
when transitioning out of IBD (was-MAX_MONEY case), but the function is
never called (BUG-2), so this code path never executes.
**Why it matters:** when clearbit exits IBD (e.g. after a 6-hour sync),
peers should immediately get the real feefilter (not the MAX_MONEY value
sent during IBD). Currently they get NOTHING because the handshake-time
feefilter never updates.
**Fix:** subsumed by BUG-2 (wire `maybeSendFeefilter`).

### BUG-13 (G13, INFO): No `m_sent_sendheaders` idempotence latch
**Symptom:** clearbit sends `SENDHEADERS` once unconditionally at end
of handshake. No latch needed because the handshake code path runs
once.
**Why it matters:** If a fix wave adds periodic `maybeSendSendHeaders`
(per BUG-1), the latch becomes necessary. Documented here so the fix
wave knows to add it.
**Fix:** add `peer.sent_sendheaders: bool = false` field; set true after
the BIP-130 message is sent.

### BUG-17 (G17, LOW): `FEEFILTER` `MoneyRange` validation partial
**Symptom:** `peer.zig:1546` + `peer.zig:4672` gate on
`ff.feerate <= MAX_MONEY` (MAX_MONEY=2.1e15 sats). Core uses
`MoneyRange(newFeeFilter)` which is `>= 0 && <= MAX_MONEY`. Because
clearbit decodes as `u64`, `>= 0` is trivially true. The behavioral
gap is at `MAX_MONEY+1`: both reject. **But:** clearbit does not log
or misbehave on out-of-range values, just silently drops; Core does
the same (`LogDebug(... "received: feefilter ..."`); the `if` is silent
on rejection).
**Why it matters:** behavior matches Core. Listed because the
signed-vs-unsigned semantic (BUG-19) makes this gate fragile if the
type changes.
**Fix:** no production code change required; add a comment referencing
Core's `MoneyRange` semantics.

### BUG-19 (G19, LOW): `FEEFILTER` decode is unsigned vs Core's signed
**Symptom:** `p2p.zig:892`:
`return Message{ .feefilter = .{ .feerate = try reader.readInt(u64) } };`
clearbit's `FeeFilterMessage.feerate: u64` is unsigned. Core's
`CAmount` is `int64_t` (signed). A negative-on-wire value
(`0x8000_0000_0000_0000` or below) is interpreted by clearbit as a
large unsigned value (rejected by MAX_MONEY gate); Core interprets it
as a negative `int64_t` (rejected by `>= 0` gate).
**Why it matters:** semantically equivalent outcomes (both reject),
but reading the source the unsigned form looks suspicious — a reader
might assume clearbit accepts very-large feerates. The MAX_MONEY gate
saves us.
**Fix:** change `FeeFilterMessage.feerate: i64` and decode via
`@bitCast(try reader.readInt(u64))`. ~3 lines plus all the callers.

### BUG-20 (G20, INFO): `m_fee_filter_received = 0` short-circuit
**Symptom:** `passesFeeFilter` line 1717-1720:
```zig
if (self.fee_filter_received == 0) return true;
return tx_fee_rate_sat_kvb >= self.fee_filter_received;
```
This conflates "peer never sent feefilter" with "peer sent
feefilter 0". The behavior is identical (accept all) so observable
difference is zero.
**Why it matters:** semantic clarity — Core distinguishes via the
default `0` value being indistinguishable from a peer-set 0 (Core also
short-circuits at `txinfo.fee < filterrate.GetFee(...)` which returns
0 for filterrate 0).
**Fix:** no production code change needed; add a comment.

### BUG-21 (G21, LOW): No `m_blocks_for_headers_relay` batching queue
**Symptom:** `peer.zig:7134-7160` builds the announcement message
synchronously per-block and per-peer. Core (line 261-265) maintains a
per-peer FIFO of pending block announcements, drained by
`SendMessages`'s once-per-tick walk so multiple new blocks coalesce
into a single `headers` message.
**Why it matters:** if N new blocks arrive in rapid succession (e.g.
post-IBD catch-up), clearbit sends N separate single-header messages
where Core sends 1 N-header message. N-fold packet overhead.
**Fix:** add `peer.headers_relay_queue: ArrayList(BlockHeader)`,
move `announceBlock` to enqueue, drain in heartbeat tick.

### BUG-24 (G24, MED): No `.wtxidrelay =>` arm in `handleMessage`
**Symptom:** same root cause as BUG-4 — the `handleMessage` switch at
`peer.zig:4223` lacks a `.wtxidrelay =>` arm. The handshake-phase
handler at `peer.zig:1524-1527` is the only place that processes
`WTXIDRELAY`. Post-handshake messages of this type fall through to
`else => {}` and are silently dropped.
**Why it matters:** unlike BUG-4 (which is the Core disconnect-on-late
violation), this BUG-24 captures the structural absence of any
dispatch path. A future protocol extension that allows late
`WTXIDRELAY` (none planned, but BIPs evolve) would need this arm
anyway.
**Fix:** as BUG-4.

### BUG-25 (G25, INFO): No `m_wtxid_relay_peers` counter
**Symptom:** Core line 3931: `m_wtxid_relay_peers++;` (and
decremented on disconnect somewhere). clearbit has no analog; the
total count of wtxidrelay-negotiated peers is not tracked.
**Why it matters:** observability only. RPC like `getpeerinfo` doesn't
expose this in clearbit.
**Fix:** add `PeerManager.wtxid_relay_peers: u32 = 0`. Increment on
flip, decrement on disconnect.

### BUG-29 (G29, INFO): `sendcmpct` ordering vs `sendheaders` differs
**Symptom:** clearbit (`peer.zig:1617-1624`) sends in order:
`sendheaders` → `sendcmpct` → `feefilter`. Core (line 3864-3870 + 5519)
sends `sendcmpct` on VERACK reception (in the VERACK handler), and
`sendheaders` from `SendMessages` after chainwork check. The trigger
timing differs (handshake-complete vs VERACK-reception vs
SendMessages-tick) but the on-the-wire order is approximately the
same.
**Why it matters:** observable timing-fingerprint difference. A network
observer could distinguish a clearbit node from a Core node by the
gap between VERACK and the post-handshake messages.
**Fix:** none recommended (timing differences are inherent to a
different implementation).

### BUG-30 (G30, MED): Handshake-time feefilter ignores empty mempool
**Symptom:** clearbit's handshake `feefilter = 100_000` (line 1629) is
sent unconditionally. Core's first `MaybeSendFeefilter` tick sends
`max(currentFilter, MIN_RELAY_FEE)` where `currentFilter` is derived
from the live mempool min-fee.
**Why it matters:** a clearbit node fresh from sync (empty or
near-empty mempool) tells peers to suppress sub-100-sat/vB relay when
it would happily accept any tx above MIN_RELAY_FEE (=1000 sat/kvB =
1 sat/vB). This artificially raises the minimum effective fee for txs
clearbit announces to those peers.
**Fix:** subsumed by BUG-7 + BUG-2. The first periodic broadcast
post-handshake should derive from live mempool state, not hardcoded.

## Patterns observed

- **"Helper exists but never called"** (BUG-2/3/12). The
  `maybeSendFeefilter` function is fully implemented inside the Peer
  struct (defined at line 1658-1711, 54 LOC of correct hysteresis +
  IBD logic) but is never wired into any heartbeat or SendMessages
  equivalent. This is a fleet-recurring pattern — the function is
  often a holdover from a wave that landed the data structure but not
  the call site. **Fix-wave shape:** find every `pub fn maybe*` /
  `pub fn periodic*` and grep for call sites; flag dead ones.
- **"Inline handshake handler vs main dispatch handler"** (BUG-4 / BUG-24).
  Three of the post-handshake-illegal messages (`WTXIDRELAY`,
  `SENDADDRV2`, `SENDCMPCT` v1) are handled inside the inline
  receive-message loop at `peer.zig:1520-1556` and have no
  corresponding `.<name> =>` arm in the main `handleMessage` switch.
  Core has ONE dispatch path (`ProcessMessage`) that checks
  `fSuccessfullyConnected` and disconnects on late arrivals. clearbit
  has TWO dispatch paths, with the post-handshake one silently
  dropping these messages instead of disconnecting.
  **Fix-wave shape:** consolidate to one dispatch path, or duplicate the
  late-violation disconnect arms in `handleMessage`.
- **"Periodic broadcast: uniform vs exponential"** (BUG-11).
  Implementations often substitute uniform for exponential because
  `rand_exp_duration` requires a `ln(rand)` call. The mean is right
  but the distribution shape is wrong. **Fix-wave shape:** every
  Poisson-process broadcast (feefilter, addr, inv-trickle) must use
  exponential.
- **"Hardcoded operational defaults"** (BUG-7 / BUG-30). The
  `feefilter = 100_000` constant is exactly the kind of magic number
  that should be derived from runtime state. Same pattern as W117
  BIP-155 fleet (hardcoded `1<<5` services), W121 BIP-157 fleet
  (hardcoded `CFCHECKPT_INTERVAL` already, but other constants TBD).
- **"Wire-format unsigned where Core uses signed"** (BUG-19).
  Reader-trust issue rather than behavioral. clearbit's `u64` decode
  is safe because the post-decode `MAX_MONEY` gate rejects negative
  values (which become large unsigned values), but the type system
  doesn't help the reader understand the protocol semantics. Sibling
  pattern in other impls: ouroboros's `int` for `nSequence` (W132),
  lunarblock's `number` for `CAmount` everywhere (W113).

## Out of scope

- BIP-152 `SENDCMPCT` proper (owned by W112 + W126).
- BIP-155 `SENDADDRV2` / `ADDRV2` (owned by W117).
- BIP-324 v2 transport handshake (owned by W98).
- `MEMPOOL` BIP-35 + `NODE_BLOOM` gating (owned by W110 / `test-bip35`).
- Full mempool min-fee tracking + dynamic relay-fee logic (mempool.zig).
- VERSION-message field encoding / `nVersion` minimum (owned by W99).

## Verdict

clearbit has the **wire-level** plumbing for all three BIPs — every
message round-trips, every flag is latched, every encoder/decoder
matches Core byte-for-byte. The **operational** layer is shallow:
- `MaybeSendFeefilter` is dead code (BUG-2/3 — HIGH).
- `MaybeSendSendHeaders` is absent (BUG-1 — MED).
- Post-VERACK protocol violations are silently swallowed instead of
  disconnect (BUG-4 / BUG-24 — MED).
- `inv` filter by wtxidrelay-negotiation is missing (BUG-6 — MED).
- Handshake feefilter is hardcoded and never updates (BUG-7 / BUG-30
  — MED).

**17 BUGs of 30 gates** — net BUG count is 17, not 30, because 13 gates
are PARITY/INFO/MISSING-OK that don't justify a fix.

Top fix-wave candidates ordered by closure ROI:

1. **FIX-α: wire `maybeSendFeefilter` from heartbeat** — closes
   BUG-2, BUG-3, BUG-7, BUG-12, BUG-30 in one wave. Single call site
   addition + thread the `mempool.dynamic_min_fee` through. ~30 LOC.
   Largest single-wave closure on this audit.
2. **FIX-β: `.wtxidrelay` arm + `.feefilter` arm in `handleMessage`** —
   closes BUG-4 (and the empty-version-check BUG-5). Add the
   `if (pfrom.fSuccessfullyConnected) disconnect` semantics for the
   late-WTXIDRELAY case. ~15 LOC.
3. **FIX-γ: inv-filter-by-wtxidrelay** — closes BUG-6. Two
   `if (peer.wtxid_relay_negotiated) continue;` lines in the inv
   handler. ~5 LOC.
4. **FIX-δ: `maybeSendSendHeaders` deferral** — closes BUG-1 and adds
   the `m_sent_sendheaders` latch (BUG-13). ~25 LOC.
5. **FIX-ε: `FeeFilterRounder` quantization + exponential timing** —
   closes BUG-8 + BUG-11. Port Core's bucket set + inverse-CDF
   sampling. ~50 LOC, alloc-free.
