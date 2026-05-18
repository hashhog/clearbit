# W152 — Tx relay + inv batching + orphan handling (clearbit)

**Wave:** W152 — `RelayTransaction`, `AddTxAnnouncement`,
`ProcessMessage(msg_tx, msg_inv, msg_notfound)`, SendMessages inv batching
loop, `INVENTORY_BROADCAST_PER_SECOND`, `INVENTORY_BROADCAST_MAX`,
`NextInvToInbounds` Poisson timer, `m_tx_inventory_known_filter`,
`m_tx_inventory_to_send`, `m_next_inv_send_time`, MaybeSendMessage cadence,
`TxOrphanage::{Add,Erase,EraseForBlock,EraseForPeer,LimitOrphans}`,
`DEFAULT_MAX_ORPHAN_TRANSACTIONS=100`, `OrphanByParent` parent-index,
`TxRequestTracker`, `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`,
`MAX_PEER_TX_ANNOUNCEMENTS=5000`, `GETDATA_TX_INTERVAL=60s`,
`TXID_RELAY_DELAY=2s` (BIP-339), `NONPREF_PEER_TX_DELAY=2s`,
`OVERLOADED_PEER_TX_DELAY=2s`, `RejectIncomingTxs`, `IsBlockOnlyConn`,
`ignore_incoming_txs` (-blocksonly), `MSG_WTX=5` vs `MSG_WITNESS_TX=0x40000001`,
`m_lazy_recent_rejects` (CRollingBloomFilter), `MAX_INV_SZ=50000`,
`INBOUND_INVENTORY_BROADCAST_INTERVAL=5s`,
`OUTBOUND_INVENTORY_BROADCAST_INTERVAL=2s`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:152` — `MAX_BLOCKS_TO_ANNOUNCE=8`.
- `bitcoin-core/src/net_processing.cpp:165` —
  `INBOUND_INVENTORY_BROADCAST_INTERVAL{5s}`.
- `bitcoin-core/src/net_processing.cpp:169` —
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL{2s}`.
- `bitcoin-core/src/net_processing.cpp:172` —
  `INVENTORY_BROADCAST_PER_SECOND{14}` (per-peer average; the W152 prompt
  cites the historic value 7).
- `bitcoin-core/src/net_processing.cpp:174-176` —
  `INVENTORY_BROADCAST_TARGET = PER_SECOND × INBOUND_INTERVAL`;
  `INVENTORY_BROADCAST_MAX = 1000` (per-tick send cap, distinct from
  `MAX_INV_SZ=50000` parse cap).
- `bitcoin-core/src/net_processing.cpp:303` —
  `m_tx_inventory_known_filter` (CRollingBloomFilter 50000/1e-6) on every
  `Peer::TxRelay`.
- `bitcoin-core/src/net_processing.cpp:308` — `m_tx_inventory_to_send`
  pending-announcement set.
- `bitcoin-core/src/net_processing.cpp:315` — `m_next_inv_send_time`
  Poisson scheduling timestamp.
- `bitcoin-core/src/net_processing.cpp:1148` — `AddKnownTx` inserts into
  `m_tx_inventory_known_filter` on every received inv (suppresses
  re-announcement back to sender).
- `bitcoin-core/src/net_processing.cpp:2050-2060` — `RelayTransaction`:
  insert into each peer's `m_tx_inventory_to_send` IFF
  `!m_tx_inventory_known_filter.contains(hash)`.
- `bitcoin-core/src/net_processing.cpp:4046-4063` — INV handler:
  - reject if `vInv.size() > MAX_INV_SZ` with `Misbehaving(100)`,
  - BIP-339: skip MSG_TX invs from m_wtxid_relay peers; skip MSG_WTX invs
    from non-m_wtxid_relay peers,
  - feed the rest to `TxRequestTracker::ReceivedInv` (per-peer
    announcement count + dedupe).
- `bitcoin-core/src/net_processing.cpp:4385-4395` — TX handler short-circuits
  during IBD (`m_chainman.IsInitialBlockDownload()` → return), tests
  `RejectIncomingTxs` first (block-relay-only / feeler / -blocksonly).
- `bitcoin-core/src/net_processing.cpp:5062-5075` — NOTFOUND handler:
  feeds back into `m_txdownloadman.ReceivedNotFound` so the in-flight
  request is released and the next announcer can be tried.
- `bitcoin-core/src/net_processing.cpp:5598-5606` — `RejectIncomingTxs`:
  block-relay-only conn → reject; feeler conn → reject; -blocksonly +
  no Relay permission → reject.
- `bitcoin-core/src/net_processing.cpp:5981-5994` — SendMessages
  inv-tick: `m_next_inv_send_time = current_time +
  rand_exp_duration(OUTBOUND_INVENTORY_BROADCAST_INTERVAL)` for outbound,
  Poisson-staggered `NextInvToInbounds` for inbound. Clears
  `m_tx_inventory_to_send` if `!m_relay_txs`.
- `bitcoin-core/src/net_processing.cpp:6045-6082` — per-tick:
  `broadcast_max = INVENTORY_BROADCAST_TARGET + (set_size/1000)*5`,
  capped at INVENTORY_BROADCAST_MAX=1000; pops from
  `m_tx_inventory_to_send`, double-checks
  `m_tx_inventory_known_filter`, INSERTS hash on send.
- `bitcoin-core/src/node/txorphanage.h:19-23` —
  `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER` /
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE{3000}` (modern Core uses a
  weight-and-latency-budget model; the legacy
  `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` is preserved as the W152 prompt's
  citation).
- `bitcoin-core/src/node/txorphanage.h:91` — `AddChildrenToWorkSet`:
  iterates `m_orphans_by_parent` map (O(1) parent → children lookup;
  clearbit does an O(N) scan).
- `bitcoin-core/src/node/txdownloadman.h:25` —
  `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`.
- `bitcoin-core/src/node/txdownloadman.h:30` —
  `MAX_PEER_TX_ANNOUNCEMENTS=5000`.
- `bitcoin-core/src/node/txdownloadman.h:32` — `TXID_RELAY_DELAY{2s}`
  (BIP-339).
- `bitcoin-core/src/node/txdownloadman.h:34` — `NONPREF_PEER_TX_DELAY{2s}`.
- `bitcoin-core/src/node/txdownloadman.h:36` —
  `OVERLOADED_PEER_TX_DELAY{2s}`.
- `bitcoin-core/src/node/txdownloadman.h:38` — `GETDATA_TX_INTERVAL{60s}`.
- `bitcoin-core/src/txrequest.cpp` — `TxRequestTracker::ReceivedInv`,
  `RequestableInvs`, `ReceivedResponse`, `ForgetTxHash`,
  `CountInFlight`, request-scheduler core.
- `bitcoin-core/src/protocol.h:479-486` — `MSG_TX=1`, `MSG_BLOCK=2`,
  `MSG_FILTERED_BLOCK=3`, `MSG_CMPCT_BLOCK=4`, `MSG_WTX=5` (BIP-339
  relay), `MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG = 0x40000001`
  (getdata-only flag for witness-serialised tx).

**Files audited**
- `src/peer.zig` (9317 lines) — `Peer` struct (lines 582-720),
  `PeerManager` struct (~2210-2480), wtxidrelay handshake (outbound
  1506-1556 / inbound 1559-1612), INV handler (4257-4313), TX handler
  (5005-5056), GETDATA handler (5057-5277), MEMPOOL handler (5295-5309),
  relay loop (5026-5042), NOTFOUND handler (5278-5281),
  `announceBlock` (7134-7160), `broadcast` (7115-7122),
  `pruneOrphanSweep` (5815-5826), `eraseOrphansForPeer` callsite
  (6109-6114), `isIBD` (6899-6912), version-message construction with
  `.relay = true` always (1486, 1591, 7304).
- `src/mempool.zig` — `Mempool` struct (768-989), `addTransaction`
  (986-1457), `acceptToMemoryPool` (1460-1590),
  `addTransactionWithPackageRate` (3752-3988), orphan pool constants
  (134-155), `OrphanTx` (743-761), orphan maps (855-870), `addOrphan`
  (1845-1913), `evictOldestOrphan` (1918-1933),
  `removeOrphanByWtxid` (1937-1956), `eraseOrphansForPeer`
  (1968-1983), `sweepExpiredOrphans` (2007-2027),
  `processOrphansForParent` (2041-2108), `eraseOrphansForBlock`
  (2114-2148), `buildMempoolInventory` (4501-4527).
- `src/p2p.zig` — `InvType` enum (236-251; MSG_WTX=5,
  MSG_WITNESS_TX=0x40000001 separate variants),
  `MAX_INV_SIZE=50000` (line 29), `MAX_GETDATA_SZ=1000` (line 34),
  decode-side `MAX_INV_SIZE` enforcement (1148).
- `src/tests_w103_tx_relay.zig` — pre-existing 30-gate audit harness
  (G1..G30) documenting which gaps were closed (G5,G6,G19,G20,G21,G22,
  G23,G24,G25,G27) vs which remain open (G3,G4,G8..G18,G26,G28..G30).
- `src/tests_w136_relay_flags.zig` — confirms no `blocksonly` /
  `ignore_incoming_txs` knob (lines 233-240).

---

## Gate matrix (33 sub-gates / 10 behaviours)

| #  | Behaviour | Sub-gate | Verdict |
|----|-----------|----------|---------|
| 1  | INV receive parse-cap | G1: `vInv > MAX_INV_SZ(50000)` rejected | PASS — decoded at `p2p.zig:1148`; W103/G1 OK |
| 1  | … | G2: rejection score = `Misbehaving(100)` | **BUG-1 (P1)** — handler returns `ProtocolViolation` → only `misbehaving(20)` (W103/G1 cross-cite) |
| 1  | … | G3: getdata-size cap = `MAX_GETDATA_SZ(1000)` server-side enforced | PASS (`peer.zig:5073-5076`, score=100) |
| 2  | INV receive policy | G4: skip MSG_TX from wtxidrelay peer | **BUG-2 (P0-CDIV)** — inv handler accepts BOTH msg_tx and msg_wtx regardless of `peer.wtxid_relay_negotiated` (`peer.zig:4269-4296`) |
| 2  | … | G5: skip MSG_WTX from legacy peer | **BUG-2 cross-cite** |
| 2  | … | G6: IBD short-circuit on TX message | **BUG-3 (P0-CDIV)** — TX handler (`peer.zig:5005`) ALWAYS calls `acceptToMemoryPool`; no `IsInitialBlockDownload()` early-return (Core net_processing.cpp:4395) |
| 2  | … | G7: `RejectIncomingTxs` for block-relay-only / feeler / -blocksonly | **BUG-4 (P0-SEC)** — no `RejectIncomingTxs` equivalent; block-relay-only peers can shove arbitrary TXs (cross-cite W103/G16) |
| 3  | INV-handler wtxidrelay set up on inbound | G8: inbound `wtxidrelay` received → `wtxid_relay_negotiated=true` | **BUG-5 (P0-CDIV)** — inbound handshake (`peer.zig:1606-1612`) discards `wtxidrelay` via the `else => {}` branch; field stays `false` for ALL inbound peers |
| 4  | TX-relay outbound (RelayTransaction) | G9: BIP-339 MSG_WTX (=5) for wtxidrelay peers, MSG_TX (=1) otherwise | PASS in the inline relay loop (`peer.zig:5035-5038`) but **BUG-6 (P0-CDIV)** in `buildMempoolInventory` (BIP-35 path) uses MSG_WITNESS_TX (=0x40000001) for witness peers — the inline relay loop's own comment explicitly forbids this |
| 4  | … | G10: per-peer Poisson `m_next_inv_send_time` cadence (2s outbound / 5s inbound) | **BUG-7 (P0-CDIV)** — no cadence at all; the TX handler fires inv to every peer **synchronously inside `acceptToMemoryPool`** completion (`peer.zig:5026-5042`) |
| 4  | … | G11: per-peer pending set `m_tx_inventory_to_send` | **BUG-8 (P0-CDIV)** — set absent; every tx is sent as a 1-element inv message, no batching, no dedupe |
| 4  | … | G12: per-peer LRU known filter `m_tx_inventory_known_filter` (50000 / 1e-6) | **BUG-9 (P0-CDIV)** — filter absent (W103/G17). Same tx re-announced to same peer indefinitely on every restart / orphan-promotion / package-relay |
| 4  | … | G13: per-tick cap `INVENTORY_BROADCAST_MAX=1000` | **BUG-7 cross-cite** — no tick concept |
| 4  | … | G14: don't relay if `relay_peer.relay_txs == false` | PASS (`peer.zig:5028`) |
| 4  | … | G15: don't relay back to sending peer | PASS (`peer.zig:5027`) |
| 4  | … | G16: BIP-133 fee-filter respected | PASS (`peer.zig:5031-5034`) |
| 4  | … | G17: orphan promotion via `processOrphansForParent` relays admitted txs to peers | **BUG-10 (P0-CDIV)** — `processOrphansForParent` (`mempool.zig:2093-2103`) calls `self.addTransaction(...)` and ON SUCCESS appends to a worklist but never relays. Core's `ProcessOrphanTx` ends with `RelayTransaction(tx->GetHash(), tx->GetWitnessHash())`. Net effect: a tx admitted via orphan promotion is silently held |
| 4  | … | G18: `RejectIncomingTxs` clears `m_tx_inventory_to_send` on disconnect | N/A (no set) |
| 5  | TxRequestTracker | G19: per-peer in-flight cap `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` | **BUG-11 (P0-CDIV)** — absent (W103/G10) |
| 5  | … | G20: per-peer announce cap `MAX_PEER_TX_ANNOUNCEMENTS=5000` | **BUG-11 cross-cite** (W103/G9) |
| 5  | … | G21: getdata interval `GETDATA_TX_INTERVAL=60s` | **BUG-11 cross-cite** (W103/G11) |
| 5  | … | G22: `NONPREF_PEER_TX_DELAY=2s` (inbound peer deprioritisation) | **BUG-11 cross-cite** (W103/G12) |
| 5  | … | G23: `TXID_RELAY_DELAY=2s` (BIP-339 wtxid-peer preference) | **BUG-11 cross-cite** (W103/G13) |
| 5  | … | G24: `OVERLOADED_PEER_TX_DELAY=2s` | **BUG-11 cross-cite** (W103/G14) |
| 5  | … | G25: per-tx announcer set + round-robin on timeout | **BUG-11 cross-cite** (W103/G15) |
| 5  | … | G26: NOTFOUND feeds back into request scheduler | **BUG-12 (P0-CDIV)** — NOTFOUND handler (`peer.zig:5278-5281`) just frees the slice and returns; no fallback to next announcer |
| 5  | … | G27: `m_lazy_recent_rejects` rolling bloom for short-term reject suppression | **BUG-13 (P0-CDIV)** — absent (W103/G29). A tx that fails ATMP is re-requested from every other peer that announces it |
| 6  | TX handler — UNREQUESTED detection | G28: misbehavior score for unsolicited `tx` | **BUG-14 (P1)** — handler accepts any inbound `tx` message regardless of whether a getdata was sent (W103/G28) |
| 7  | Orphan pool (TxOrphanage) | G29: cap `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` | PASS (`mempool.zig:136`, W103/G21) |
| 7  | … | G30: wtxid-keyed primary index | PASS (`mempool.zig:858`, W103/G23) |
| 7  | … | G31: `OrphanByParent` map for O(1) parent → children | **BUG-15 (P1)** — `processOrphansForParent` (`mempool.zig:2063-2072`) iterates every orphan and walks its inputs (O(N×K)) |
| 7  | … | G32: `EraseForPeer` on disconnect | PASS (`peer.zig:6112-6113`, W103/G24) |
| 7  | … | G33: `EraseForBlock` after block connect | PASS (`mempool.zig:1752`, `eraseOrphansForBlock`) |
| 7  | … | G34: TTL sweep (`ORPHAN_TX_EXPIRE_TIME=5min`) | PASS (`mempool.zig:2007-2027`, W103/G22) |
| 7  | … | G35: per-peer cap `MAX_PEER_ORPHANS=100` | PASS (`mempool.zig:144`) |
| 8  | TX → orphan classification | G36: orphan add gated on `reject_reason == "missing-inputs"` | PASS (`peer.zig:5050-5053`) |
| 8  | … | G37: peer-id stability for orphan accounting | **BUG-16 (P1)** — `peer_id = @intFromPtr(peer)` (pointer cast). Re-allocation of `*Peer` to the same address inside the lifetime of an unsswept orphan slips the orphan into a different peer's per-peer count (worst case after `eraseOrphansForPeer + destroy + new connect`) |
| 9  | INV handler — block invs | G38: `sendGetHeaders` rate-limited | **BUG-17 (P1)** — every inv with a block entry triggers `sendGetHeaders` (peer.zig:4298-4299) with no `last_getheaders_time` check; a peer can DoS us by repeatedly inv'ing the same block hash and amplifying outbound getheaders bytes |
| 9  | … | G39: only one inv→getheaders per peer per tip change | **BUG-17 cross-cite** |
| 10 | -blocksonly mode | G40: operator-knob to disable tx relay entirely | **BUG-18 (P2)** — no `-blocksonly` flag; clearbit always relays tx (W136/G9, tests_w136_relay_flags.zig:233-240) |
| 11 | Multiple ATMP entry-points | G41: `addTransactionWithPackageRate` reachable from production | PARTIAL — production never calls it (test-only); but it **bypasses W96 CheckTransaction-sanity, isCoinbase reject, AND BIP-113 IsFinalTx** — see **BUG-19** below (W151 BUG-9 envelope-bypass shape) |

---

## BUG-1 (P1) — Oversized INV decoder downgrades `Misbehaving(100)` to `misbehaving(20)`

**Severity:** P1. Bitcoin Core (`net_processing.cpp:4040-4042`) treats
`vInv.size() > MAX_INV_SZ` as `Misbehaving(peer, 100, ...)` — an instant
discouragement/disconnect. Clearbit raises `ParseError.InvalidData`
inside `decodeInv`, which is mapped to `PeerError.ProtocolViolation`
upstream and lands as `misbehaving(20, "protocol violation")`. A peer
needs 5 oversized inv messages instead of 1 to be disconnected.

**File:** `src/p2p.zig:1148` (decode rejection); upstream
`misbehaving(20, ...)` at the message-loop `ProtocolViolation` branch.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4040-4042`.

**Impact:** trivial pre-existing W103/G1 finding restated for completeness
of the W152 gate matrix. Real-world impact small (the parse failure is
still terminal at the message level) but the score divergence prevents
ban-list propagation under Core's parity expectations.

---

## BUG-2 (P0-CDIV) — INV handler ignores BIP-339 wtxidrelay direction (accepts both MSG_TX and MSG_WTX from every peer)

**Severity:** P0-CDIV. Bitcoin Core (`net_processing.cpp:4046-4063`)
filters incoming invs by the per-peer `m_wtxid_relay` state: if true, all
MSG_TX invs are SILENTLY DROPPED (the BIP-339 wire-format expectation is
that wtxidrelay peers only announce by wtxid); if false, MSG_WTX invs are
silently dropped (legacy peers should not be announcing by wtxid).

Clearbit's INV handler (`peer.zig:4269-4296`) processes both unconditionally:

```zig
for (inv_msg.inventory) |item| {
    const base_type = @as(u32, @intFromEnum(item.inv_type)) & ~@as(u32, 0x40000000);
    if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_block))) {
        has_block_inv = true;
    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_tx))) {
        if (self.mempool) |pool| {
            if (!pool.entries.contains(item.hash)) {
                tx_requests.append(.{ .inv_type = .msg_tx, .hash = item.hash }) catch {};
            }
        }
    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_wtx))) {
        if (self.mempool) |pool| {
            if (!pool.by_wtxid.contains(item.hash)) {
                tx_requests.append(.{ .inv_type = .msg_wtx, .hash = item.hash }) catch {};
            }
        }
    }
}
```

No reference to `peer.wtxid_relay_negotiated`.

**Consequences:**
1. **BIP-339 dispatch ambiguity.** A wtxidrelay-negotiated peer announcing
   a tx by both txid AND wtxid (a buggy peer or an adversary trying to
   amplify our getdata fan-out) triggers **two** getdata round-trips for
   the same tx.
2. **Cache index lookup mismatch.** When the peer is wtxidrelay-negotiated
   and announces by MSG_TX, clearbit consults `pool.entries.contains(item.hash)`
   treating the txid as canonical. Core would have dropped the announcement
   before this check, never consulting the index, so the mempool-hit short
   circuit is moot. The divergence shows up when a malleated witness sits
   in the mempool: clearbit sees txid hit ⇒ no getdata, but the malicious
   wtxid was the actual announcement the peer wanted us to fetch.
3. **DoS amplification.** A peer can announce N MSG_TX + N MSG_WTX with
   the same underlying tx (32-byte hashes, different inv-type), and
   clearbit issues 2N getdata items. Core issues at most N.

**File:** `src/peer.zig:4269-4296`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4046-4063`:
```cpp
if (peer.m_wtxid_relay) {
    if (inv.IsMsgTx()) continue;
} else {
    if (inv.IsMsgWtx()) continue;
}
```

**Impact:** BIP-339 wire-protocol divergence; 2× outbound getdata
amplification under crafted inputs; cache-lookup confusion masks
malleated-witness divergence.

---

## BUG-3 (P0-CDIV) — TX handler does not short-circuit during IBD

**Severity:** P0-CDIV. Bitcoin Core's TX handler
(`net_processing.cpp:4385-4395`) is explicit:

```cpp
if (msg_type == NetMsgType::TX) {
    if (RejectIncomingTxs(pfrom)) {
        LogDebug(BCLog::NET, "transaction sent in violation of protocol, %s", pfrom.DisconnectMsg());
        pfrom.fDisconnect = true;
        return;
    }
    // Stop processing the transaction early if we are still in IBD since we don't
    // have enough information to validate it yet. Sending unsolicited transactions
    // is not considered a protocol violation, so don't punish the peer.
    if (m_chainman.IsInitialBlockDownload()) return;
    ...
}
```

Clearbit's TX handler (`peer.zig:5005`) jumps directly to
`pool.acceptToMemoryPool(tx_msg, false)`. The `PeerManager.isIBD()`
helper exists (`peer.zig:6899-6912`) but is never consulted on the tx
ingress path. Consequences during IBD:

1. **Mempool churn during sync.** Every tx received from peers during
   the first 2-12 hours of IBD is run through CheckTransaction →
   standardness → BIP-68/113 → script verification. Most of these will
   already be confirmed in some block we haven't downloaded yet, so the
   work is purely wasted.
2. **False reject metrics.** During IBD, a tx whose parent is in a block
   we haven't downloaded fails with `missing-inputs` and lands in the
   orphan pool, hogging slots up to the cap. By the time we finish IBD,
   the orphan pool is full of stale entries (the TTL sweep clears them
   in 5 min, but they keep arriving for the duration of IBD).
3. **Script-verification CPU during IBD.** clearbit's IBD is already
   tight on CPU (full script verification is the bottleneck for the
   1->938343 height span); diverting cycles to txn validation slows IBD
   wall-clock further.

**File:** `src/peer.zig:5005-5056`. Missing line:
`if (self.isIBD()) return;` (and a `RejectIncomingTxs` equivalent — see
BUG-4).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4395`.

**Impact:** wasted CPU during IBD; orphan-pool slot exhaustion against
parents we haven't connected yet; cross-impl IBD-time divergence.

---

## BUG-4 (P0-SEC) — No `RejectIncomingTxs` equivalent; block-relay-only and feeler peers can shove TXs

**Severity:** P0-SEC. Bitcoin Core's `RejectIncomingTxs`
(`net_processing.cpp:5598-5606`) gates the TX handler:

```cpp
bool PeerManagerImpl::RejectIncomingTxs(const CNode& peer) const
{
    if (peer.IsBlockOnlyConn()) return true;
    if (peer.IsFeelerConn()) return true;
    if (m_opts.ignore_incoming_txs && !peer.HasPermission(NetPermissionFlags::Relay)) return true;
    return false;
}
```

A block-relay-only outbound connection (clearbit's `conn_type ==
.block_relay`, 2 slots) exists specifically to PROTECT against
transaction-relay-based topology inference / fingerprinting. The peer is
not supposed to receive or send transaction-layer messages. Same for
feeler connections (`conn_type == .feeler`, used only for address-record
validation).

Clearbit's TX handler (`peer.zig:5005`) has no `RejectIncomingTxs`
equivalent. A misbehaving / adversarial block-relay-only peer that
shoves a `tx` message into the wire is silently processed:
- the tx is run through `acceptToMemoryPool`,
- on success, it is relayed to all OTHER full-relay peers, leaking the
  topology-inference signal that the block-relay-only connection was
  meant to suppress,
- the peer is not penalised.

Additionally, the W136/G9 finding (`tests_w136_relay_flags.zig:233-240`)
confirms there is no `blocksonly` / `ignore_incoming_txs` config knob;
a node operator cannot run a relay-disabled clearbit at all.

**File:** `src/peer.zig:5005-5056` (TX handler missing the gate);
`src/peer.zig:543-544` (`.block_relay` / `.feeler` enumerants exist on
`ConnectionType` but nothing on the tx path consults them).

**Core ref:** `bitcoin-core/src/net_processing.cpp:5598-5606`,
`net_processing.cpp:4385-4395`.

**Impact:**
- Block-relay-only outbound peers leak transaction topology by feeding
  txs that propagate to our full-relay peers — defeats the privacy
  rationale for the block-relay-only slot allocation entirely.
- Feeler peers (designed for one-shot address-record validation) can
  push txs that exhaust our mempool slots before disconnect.
- `-blocksonly` operator knob absent.
- Fleet pattern cross-cite: this is the W141/W138 archetype "operator
  knob absent" plus "block-relay-only protection bypassed" — a
  security-property regression analogous to the W128 banman fleet finding
  (security-defining variant of a behaviour conflated with the default).

---

## BUG-5 (P0-CDIV) — Inbound handshake silently drops `wtxidrelay`; all inbound peers stuck on MSG_TX relay forever

**Severity:** P0-CDIV. The outbound handshake (`peer.zig:1520-1556`)
correctly handles inbound `wtxidrelay` messages received during the
verack wait:
```zig
.wtxidrelay => {
    self.wtxid_relay_negotiated = true;
},
```

The inbound handshake (`peer.zig:1606-1612`) does NOT:
```zig
// Wait for their verack
while (true) {
    const msg = try self.receiveMessage();
    switch (msg) {
        .verack => break,
        else => {},      // <-- wtxidrelay falls through silently
    }
}
```

For every **inbound** peer connection, `wtxid_relay_negotiated` stays at
its default of `false`. Consequences:
1. Inbound peers receive every tx announcement via MSG_TX (txid) even
   though they advertised BIP-339 / wtxid relay. They will discard
   those invs per their own BIP-339 filter (BUG-2's symmetric Core
   behaviour), so the tx never propagates back through inbound peers.
2. Inbound peer-set TX propagation drops to zero. Clearbit becomes a
   tx-relay sink for any peer that connected to us rather than out.
3. The BIP-339 wtxid-keyed getdata path on the **outbound** side
   (clearbit → inbound) sends MSG_TX getdata, so the inbound peer
   serves the non-witness-stripped tx variant; clearbit's wtxid index
   never sees the wtxid until **after** addTransaction recomputes it.

**File:** `src/peer.zig:1606-1612` — missing `.wtxidrelay => { self.wtxid_relay_negotiated = true; }` in the inbound verack-wait switch. The
field also needs the corresponding update path for any handler that
processes `wtxidrelay` post-handshake — currently the main message
dispatch (peer.zig:4257+) has no `.wtxidrelay` case at all, so even
mid-session wtxidrelay (a protocol violation Core handles by
disconnecting) is silently dropped (W103/G3 still applies for inbound).

**Core ref:** `bitcoin-core/src/net_processing.cpp:3919-3936`:
```cpp
if (msg_type == NetMsgType::WTXIDRELAY) {
    if (pfrom.fSuccessfullyConnected) { pfrom.fDisconnect = true; return; }
    if (!peer.m_wtxid_relay) { peer.m_wtxid_relay = true; ... }
}
```

**Impact:**
- 100% of inbound peers stuck on MSG_TX relay; on a node with mostly
  inbound peers (typical for a long-running listener), tx propagation
  through inbound peer set is impaired.
- BIP-339 mempool churn: malleated-witness divergence detection
  (`txn-same-nonwitness-data-in-mempool`) cannot fire for inbound
  announcements because the inbound peer sends txid-based, not
  wtxid-based.

---

## BUG-6 (P0-CDIV) — `buildMempoolInventory` uses MSG_WITNESS_TX (0x40000001) for relay invs; comment in adjacent code explicitly forbids this

**Severity:** P0-CDIV. The inline relay loop in the TX handler
(`peer.zig:5021-5025`) carries a load-bearing comment:

```zig
// BIP-339: use MSG_WTX (=5) + wtxid for peers that negotiated
// wtxidrelay; fall back to MSG_TX (=1) + txid for legacy peers.
// Core: net_processing.cpp:6007-6009 RelayTransaction.
// Do NOT use MSG_WITNESS_TX (0x40000001) for relay inv — that
// is a getdata-only flag for witness-serialised block data.
```

`buildMempoolInventory` (`mempool.zig:4501-4527`), the BIP-35 mempool-msg
response path, does exactly what the comment forbids:

```zig
const item = if (is_witness_capable)
    p2p.InvVector{ .inv_type = .msg_witness_tx, .hash = entry.wtxid }
else
    p2p.InvVector{ .inv_type = .msg_tx, .hash = entry.txid };
```

`is_witness_capable` is checked on the **service flag** `NODE_WITNESS`
(set when the peer's services bit `1<<3` is on), not the BIP-339
`wtxid_relay_negotiated` flag. A peer advertising NODE_WITNESS but not
sending `wtxidrelay` receives invs with type `0x40000001`, which Core
treats per its `IsMsgWitnessTx()` check as a getdata flag — peers may
silently drop, treat as unknown, or (per the comment) decode as a
witness-block-encoded tx and trigger validation errors.

**File:** `src/mempool.zig:4501-4527` (`buildMempoolInventory`),
called by `sendMempoolInventory` (`peer.zig:495-516`).

**Core ref:** `bitcoin-core/src/protocol.h:481-486`; `bitcoin-core/src/net_processing.cpp:6007-6009`.

**Impact:**
- BIP-35 `mempool` response payloads are wire-divergent for every
  witness-capable peer (which is essentially all of mainnet since the
  segwit deadline).
- The inline relay loop is correct (BUG-2's branch); only the BIP-35
  bulk-mempool-dump path drifts. **Two-pipeline guard 17th distinct
  extension this quad-audit window**: same function family
  (RelayTransaction), two divergent implementations within ONE file
  pair, one carries the correct BIP-339 logic AND a comment forbidding
  the other's choice.
- "comment-as-confession 13th clearbit instance" — the comment at
  `peer.zig:5024` IS the documentation that the bug it warns about
  exists at `mempool.zig:4520-4523`.

---

## BUG-7 (P0-CDIV) — No `m_next_inv_send_time` Poisson cadence; relay is synchronous-immediate inside TX handler

**Severity:** P0-CDIV. Bitcoin Core's SendMessages tick
(`net_processing.cpp:5981-5994`):
```cpp
if (tx_relay->m_next_inv_send_time < current_time) {
    if (pto->IsInboundConn()) {
        tx_relay->m_next_inv_send_time = NextInvToInbounds(current_time, INBOUND_INVENTORY_BROADCAST_INTERVAL, ...);
    } else {
        tx_relay->m_next_inv_send_time = current_time + m_rng.rand_exp_duration(OUTBOUND_INVENTORY_BROADCAST_INTERVAL);
    }
    // ... pop from m_tx_inventory_to_send, build inv message ...
}
```

Per-peer cadence is deterministic-jittered (Poisson-staggered for inbound
peers via a global key, exponential-distributed for outbound). The
intent is BOTH bandwidth shaping AND **transaction privacy** — a single
tx is announced to different peers at unpredictable times, frustrating
adversarial inference of "which peer first told us about tx X".

Clearbit's TX handler (`peer.zig:5026-5042`) sends a 1-element inv
synchronously, inside the same call that admitted the tx, to every peer
in the same loop iteration order each time:

```zig
for (self.peers.items) |relay_peer| {
    if (relay_peer == peer) continue;
    if (!relay_peer.relay_txs) continue;
    if (relay_peer.state != .connected) continue;
    ...
    const relay_inv_items = [_]p2p.InvVector{relay_inv};
    const inv_msg = p2p.Message{ .inv = .{ .inventory = &relay_inv_items } };
    relay_peer.sendMessage(&inv_msg) catch {};
}
```

**Consequences:**
1. **Privacy regression.** A network observer who watches outbound TCP
   from clearbit and from clearbit's neighbours sees the same fan-out
   pattern (peers index 0..N) every time, in microsecond-tight
   succession. The observer can identify clearbit as the relay-source
   trivially (first sender → first peer in iteration order).
2. **Bandwidth amplification.** 1-element inv messages waste header
   bytes (24-byte message header + 1-byte varint + 36-byte inv ≈ 61 B
   message for 4 B of payload). Core's batching collapses 14 txs/s
   into a single inv ≈ 24 + 1 + 14*36 = 529 B vs 14 × 61 = 854 B —
   ~38 % savings, all the more important at hundreds of peers.
3. **No backpressure on tx flood.** A peer that sends 1000 txs through
   us in 1 s triggers 1000 inv messages per OTHER peer, regardless of
   the receiver's processing capacity.

**File:** `src/peer.zig:5005-5042` (TX handler).

**Core ref:** `bitcoin-core/src/net_processing.cpp:5981-6082`
(SendMessages inv-tick), `:165-176` (INVENTORY_BROADCAST constants).

**Impact:** privacy regression (relay-source trivially fingerprintable);
inv-message bandwidth amplification 1.4×; backpressure absent; tx-relay
worker-thread is fused into the message-receive thread.

---

## BUG-8 (P0-CDIV) — `m_tx_inventory_to_send` pending set absent; per-peer announcement scheduling impossible

**Severity:** P0-CDIV. Core maintains, per peer (per `TxRelay`):
- `std::set<Wtxid> m_tx_inventory_to_send GUARDED_BY(m_tx_inventory_mutex)`
  — pending announcements ready to be batched into the next inv tick.

Clearbit has no equivalent. The TX handler's inline loop builds a
`relay_inv_items` ONCE per accepted tx and dispatches to every peer
immediately. Consequences cascade from BUG-7:
- A tx admitted via orphan promotion (BUG-10 says it's silently held —
  but even if BUG-10 is fixed) cannot be batched with a tx admitted
  from a peer 200 ms later; each goes out as its own inv message.
- A reorg that re-admits 50 txs to the mempool (`removeForBlock`
  reverse path) triggers 50 separate inv messages to every peer if
  the re-admission ever drives a relay loop.

**File:** `src/mempool.zig:768-869` (`Mempool` struct lacks any pending
announce queue); `src/peer.zig:582-720` (`Peer` struct lacks
`tx_inventory_to_send`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:308`,
`:6032-6082`.

**Impact:** inv batching infeasible; per-peer scheduling impossible;
cross-cite with BUG-7 (cadence) and BUG-9 (filter).

---

## BUG-9 (P0-CDIV) — `m_tx_inventory_known_filter` absent; same tx re-announced to same peer indefinitely

**Severity:** P0-CDIV. Core's `m_tx_inventory_known_filter`
(`net_processing.cpp:303`) is a per-peer 50000-element CRollingBloomFilter
(1e-6 false-positive rate) that records every tx hash this node has
either sent to OR received from the peer. The relay loop
(`net_processing.cpp:2050-2060`, `:6067-6082`) consults it before
adding to `m_tx_inventory_to_send`:

```cpp
if (!tx_relay->m_tx_inventory_known_filter.contains(hash)) {
    tx_relay->m_tx_inventory_to_send.insert(wtxid);
}
```

And after popping for send:
```cpp
if (tx_relay->m_tx_inventory_known_filter.contains(inv.hash)) continue;
...
tx_relay->m_tx_inventory_known_filter.insert(inv.hash);
```

Without the filter, clearbit re-announces the same tx to the same peer
on every relay trigger. Specific failure modes:
1. Peer X announces tx T to us → we fetch via getdata → we admit →
   we IMMEDIATELY relay back to peer X (BUG-7 has no per-peer dedupe
   except the `if (relay_peer == peer) continue` guard for the
   announcing peer ONLY). Any OTHER peer Y that also announced T to us
   independently (very common during high-activity periods) receives
   our relay even though Y already knows about T.
2. A tx admitted via orphan promotion (if BUG-10 were fixed) would be
   re-relayed to peers that originally announced it.
3. Reorg re-admission would re-relay txs that peers have already seen.

**File:** `src/peer.zig:582-720` (`Peer` struct lacks any
`tx_inventory_known_filter`); `src/mempool.zig` (no rolling bloom
implementation in this module either).

**Core ref:** `bitcoin-core/src/net_processing.cpp:303`,
`:1148` (AddKnownTx), `:2257-2261`, `:6019`, `:6082`.

**Impact:** outbound inv-message volume amplified by N peers per tx for
every duplicate announcement; significant on a busy mempool day.

---

## BUG-10 (P0-CDIV) — `processOrphansForParent` admits orphans but does NOT relay them; promoted txs are silently held

**Severity:** P0-CDIV. Bitcoin Core's `ProcessOrphanTx`
(net_processing.cpp) ends every successful orphan promotion with
`RelayTransaction(tx->GetHash(), tx->GetWitnessHash())`. The newly-admitted
tx propagates to peers.

Clearbit's `processOrphansForParent` (`mempool.zig:2041-2108`) calls
`self.addTransaction(orphan_ptr.tx)` and on success only appends the
txid to the worklist:

```zig
const accepted = if (self.addTransaction(orphan_ptr.tx)) |_| true else |_| false;
if (accepted) {
    promoted += 1;
    worklist.append(orphan_ptr.txid) catch {};
} else {
    serialize.freeTransaction(self.allocator, &orphan_ptr.tx);
}
```

There is no relay step. The orphan is moved from the orphan pool into
the mempool — purely a local-state change. Peers learn about the tx
only when they ALSO independently see the parent and promote their
own orphan copy (different parent path; race-dependent), or when they
receive an unrelated inv for the same tx from a third peer.

**Consequences:**
1. **Orphan tx propagation collapse.** A common pattern: alice sends
   parent P to one node, child C to a different node. Both nodes see
   only one of {P, C}. Eventually the C-node's peer set carries P from
   the alice-node's peer set, the C-node's orphan promotes — and dies.
   Other nodes that haven't yet seen C learn about it only via
   wallets re-broadcasting.
2. **Block-template impact.** A miner running clearbit would mine a
   block including only P (received directly), not C (promoted from
   orphan but never relayed), foregoing the C fee — even though every
   other miner can include the bundle.
3. **Defeats the orphan-pool's purpose.** The orphan pool exists to
   bridge in-order arrival; the bridge-fix's effect should propagate.

Plus a related issue inside the same function: `processOrphansForParent`
calls `self.addTransaction` directly, not `self.acceptToMemoryPool` —
so the W96 reject-reason string is lost (the wrapper that translates
errors to Core reject-token strings is bypassed). All non-success errors
collapse to "free the tx" with no telemetry.

**File:** `src/mempool.zig:2091-2103` (the success branch).

**Core ref:** Bitcoin Core `net_processing.cpp::ProcessOrphanTx` —
ends with `RelayTransaction(tx->GetHash(), tx->GetWitnessHash())` after
a successful `AcceptToMemoryPool`.

**Impact:** orphan-promoted txs do not propagate; mining-fee divergence
on bundled parent/child txns; defeats the purpose of orphan management.

---

## BUG-11 (P0-CDIV) — `TxRequestTracker` entirely absent (covers 7 sub-gates)

**Severity:** P0-CDIV. Core's `TxRequestTracker` (`txrequest.h`,
`txrequest.cpp`) is a per-node scheduler that:
- caps in-flight requests per peer at `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`
  (txdownloadman.h:25),
- caps announcement-tracking per peer at `MAX_PEER_TX_ANNOUNCEMENTS=5000`
  (txdownloadman.h:30),
- delays getdata for `GETDATA_TX_INTERVAL=60s` after a request to allow
  a slow peer to respond before trying another (txdownloadman.h:38),
- prefers wtxidrelay peers (BIP-339) by deferring txid-relay peers by
  `TXID_RELAY_DELAY=2s` (txdownloadman.h:32),
- defers non-preferred (inbound) peers by `NONPREF_PEER_TX_DELAY=2s`
  (txdownloadman.h:34),
- defers overloaded peers by `OVERLOADED_PEER_TX_DELAY=2s`
  (txdownloadman.h:36),
- tracks the SET OF ANNOUNCERS per tx so when a getdata times out, the
  next announcer can be tried (RequestableInvs / ReceivedNotFound).

Clearbit fires a getdata IMMEDIATELY on every tx inv from every peer
with no per-peer in-flight cap, no announcement cap, no preference for
wtxidrelay peers, no inbound deprioritisation, no overloaded gate, and
no announcer-set fallback (W103/G8..G15 all open).

Specific clearbit gaps:

| Sub-gate | Core constant | Clearbit state |
|----------|---------------|----------------|
| G19 | MAX_PEER_TX_REQUEST_IN_FLIGHT=100 | absent (W103/G10) |
| G20 | MAX_PEER_TX_ANNOUNCEMENTS=5000 | absent (W103/G9) |
| G21 | GETDATA_TX_INTERVAL=60s | absent (W103/G11) |
| G22 | NONPREF_PEER_TX_DELAY=2s | absent (W103/G12) |
| G23 | TXID_RELAY_DELAY=2s | absent (W103/G13) |
| G24 | OVERLOADED_PEER_TX_DELAY=2s | absent (W103/G14) |
| G25 | per-tx announcer set + round-robin | absent (W103/G15) |

**Failure modes:**
1. **Adversarial inv flood DoS.** A single peer can announce 50000 invs
   (the parse cap) per inv message and clearbit will issue 50000
   getdata requests in batches of 1000. The peer can then drop the
   connection, leaving clearbit with 50000 stuck in-flight requests
   that never resolve. Per-peer in-flight cap (100) would absorb this.
2. **Slow-peer wedge.** A peer announces tx T, we send getdata, the
   peer ignores it. No timeout, no re-request from another announcer.
   T never enters our mempool.
3. **Duplicate-request bandwidth.** Two peers announce T within ms of
   each other → clearbit sends getdata to both → both reply → clearbit
   processes the same tx twice (the second one hits `AlreadyInMempool`
   but still incurs decode + sanity-check cost).
4. **No BIP-339 wtxid-relay preference.** Per-BIP-339 rationale, a
   wtxid-relay peer is implicitly trusted-newer than a txid-relay peer;
   Core defers the txid-relay request by 2s to give the wtxid path a
   shot at filling the in-flight slot first. Clearbit treats both
   identically.

**File:** `src/peer.zig:582-720` (`Peer` struct: no `tx_in_flight_count`,
`tx_announcements_count`, `last_tx_request_time`, `nonpref_peer_delay`,
`txid_relay_delay`, `overloaded_peer_delay`); `src/peer.zig:2220-2480`
(`PeerManager` struct: no `tx_request_tracker`, `tx_announcers`).

**Core ref:** `bitcoin-core/src/txrequest.cpp`,
`bitcoin-core/src/node/txdownloadman.h:25-38`.

**Impact:** unbounded inv-flood DoS; slow-peer wedge; getdata
amplification on duplicate announcements; BIP-339 wtxid-preference
ignored. This is a **30-of-30-gates** subsystem (Core has the full
machine; clearbit has none of it). With W138 + W141 + W150 + W151 +
W152, clearbit is now **5-of-5 30-of-30-gates-buggy** — a fleet-pattern
crystallisation: subsystem-rewrite candidate, not incremental patch.

---

## BUG-12 (P0-CDIV) — NOTFOUND handler is a no-op; in-flight slot never released, next announcer never tried

**Severity:** P0-CDIV. Bitcoin Core's NOTFOUND handler
(`net_processing.cpp:5062-5075`) feeds the response into
`m_txdownloadman.ReceivedNotFound(pfrom.GetId(), tx_invs)`, which:
- removes the in-flight entry from the peer's request set (freeing the
  slot in `MAX_PEER_TX_REQUEST_IN_FLIGHT`),
- re-queues the tx for `RequestableInvs` consideration from a different
  announcer.

Clearbit's NOTFOUND handler (`peer.zig:5278-5281`):
```zig
.notfound => |nf| {
    defer self.allocator.free(nf.inventory);
},
```

It frees the slice and returns. No in-flight bookkeeping is updated
(because clearbit doesn't have any — see BUG-11). No fallback peer is
tried. The tx is permanently lost to clearbit (unless another peer
later sends an unprompted inv for it).

**File:** `src/peer.zig:5278-5281`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5062-5075`.

**Impact:** any tx whose first announcer NOTFOUNDs us (peer evicted the
tx from its mempool between announcing and our getdata; peer
disconnected; peer is malicious) is never fetched. Cross-cite with
BUG-11 (no scheduler to fall back to).

---

## BUG-13 (P0-CDIV) — `m_lazy_recent_rejects` rolling bloom absent; rejected txs re-requested indefinitely

**Severity:** P0-CDIV. Core maintains `m_lazy_recent_rejects` (a
CRollingBloomFilter sized for ~120000 entries, p=1e-6) of recently
ATMP-rejected tx hashes. Before issuing a getdata in response to an inv,
the txrequest scheduler consults the filter; rejected-recently tx hashes
are dropped from the request set without firing getdata.

Clearbit has no equivalent (W103/G29). A tx that fails ATMP for any
reason (insufficient-fee, dust, non-standard, ...) is re-fetched and
re-validated on every fresh inv from every peer. Common scenario: a tx
at 1.5 sat/vbyte announced by 20 peers in the first 30 s of its life;
our min-relay-fee rejects all 20 → we ran ATMP 20 times for the same
sanitised tx, returning the same error each time. With the filter, 19
of the 20 are short-circuited.

**File:** `src/peer.zig:2220-2480` (`PeerManager` struct: no
`recent_rejects`, no `m_lazy_recent_rejects`).

**Core ref:** Bitcoin Core `net_processing.cpp::PeerManagerImpl::AlreadyHaveTx` —
consults `m_lazy_recent_rejects.contains(...)`.

**Impact:** wasted CPU on duplicate-reject validation; ATMP runs 10×
to 100× more often during fee-rate-flood periods; cross-impl mempool
churn diverges from Core.

---

## BUG-14 (P1) — UNREQUESTED `tx` message silently accepted; no misbehavior penalty

**Severity:** P1. Bitcoin Core's TX handler verifies the incoming tx
was actually requested (consults `m_txrequest`); unsolicited txs trigger
`Misbehaving(peer, 100, "tx-unrequested")` and disconnect.

Clearbit's TX handler (`peer.zig:5005`) processes every incoming `tx`
message regardless of whether a getdata was sent for it. A peer can
push 50 unrelated txs into our mempool without first observing an inv
from us. This is the W103/G28 finding restated.

**File:** `src/peer.zig:5005-5056`.

**Core ref:** Bitcoin Core `net_processing.cpp::ProcessMessage` (TX
branch) — checks the response is in `m_txrequest`.

**Impact:** any connected peer can push arbitrary txs through us;
amplifies the BUG-7 outbound inv volume by pushing txs we never asked
for.

---

## BUG-15 (P1) — `OrphanByParent` index absent; `processOrphansForParent` is O(N × K)

**Severity:** P1. Bitcoin Core's TxOrphanage maintains a secondary
`m_orphans_by_parent` map (parent_txid → set<orphan_wtxid>) for O(1)
parent → children lookup in `AddChildrenToWorkSet`.

Clearbit's `processOrphansForParent` (`mempool.zig:2041-2108`) does an
O(N × K) scan, where N is the orphan count (≤100) and K is the average
input count per orphan:

```zig
var iter = self.orphans.iterator();
while (iter.next()) |entry| {
    const o = entry.value_ptr.*;
    for (o.tx.inputs) |inp| {
        if (std.mem.eql(u8, &inp.previous_output.hash, &cur_parent)) {
            candidates.append(o.wtxid) catch break;
            break;
        }
    }
}
```

Worst-case fan-out N=100, K=100 → 10000 byte-compares per parent_txid
processed. The fixpoint loop multiplies that by the number of admitted
parents (typically 1-2). Acceptable at the current cap (100 orphans)
but the modern Core orphanage is sized by weight + latency budget and
allows ~3000 latency score (DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE), which
would push the O(N²) cost to a measurable level if clearbit lifts the
100-orphan cap.

**File:** `src/mempool.zig:855-870` (orphan-pool struct fields:
`orphans`, `orphans_by_txid`, `orphans_by_peer` — no `orphans_by_parent`);
`src/mempool.zig:2063-2072` (scan loop).

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp::AddChildrenToWorkSet`
— uses the `m_orphans_by_parent` index.

**Impact:** O(N × K) parent-resolution scan; scales poorly past the
current 100-orphan cap; potential CPU spike on multi-parent reorg
replays.

---

## BUG-16 (P1) — Orphan `peer_id` is `@intFromPtr(peer)` (pointer cast); reused-address aliasing risk

**Severity:** P1. The TX handler captures `peer_id` as
`@intFromPtr(peer)` (`peer.zig:5051`) and stashes it on the orphan
(`OrphanTx.peer_id`, `mempool.zig:760`). The pool uses it for per-peer
accounting (`MAX_PEER_ORPHANS`) and for `eraseOrphansForPeer` on
disconnect.

Clearbit's peer cleanup correctly calls `eraseOrphansForPeer(@intFromPtr(peer))`
BEFORE `allocator.destroy(peer)` (`peer.zig:6109-6116`). However:
- if the orphan pool is full and a new peer is allocated to the same
  address while an orphan from the old peer that wasn't matched by the
  cleanup (e.g., a defensive `if (peer_id == 0) return;` short-circuit
  before the sweep, or any future code path that destroys without
  erasing) the new peer "inherits" the old peer's per-peer orphan
  counter,
- the per-peer `MAX_PEER_ORPHANS=100` budget is then off-by-N for the
  new peer until the orphan TTL sweep clears the stale entries (up to
  5 min).

Core uses a NodeId integer counter assigned at connect time — never
reused for the life of the process — eliminating the aliasing window.

**File:** `src/mempool.zig:760` (`peer_id: u64`),
`src/mempool.zig:1845-1913` (addOrphan stash), `src/peer.zig:5051`
(`@intFromPtr(peer)`).

**Core ref:** `bitcoin-core/src/net.h::NodeId` (monotonic integer),
`bitcoin-core/src/node/txorphanage.cpp` uses NodeId as the per-peer
key.

**Impact:** narrow but real ABA-style aliasing risk; not currently
exploitable in clearbit because the destroy path always erases first,
but the fragility is one defensive-coding mistake away. Fleet pattern
cross-cite: "pointer-cast as ID" is a clearbit-recurrent shape (W148
catalogued the activateBestChain stub; W151 catalogued the
addTransactionWithPackageRate envelope-bypass; this is the third
instance of "use the address bits because we don't have a real ID").

---

## BUG-17 (P1) — Block-inv triggers `sendGetHeaders` with no rate-limit; outbound bandwidth amplification

**Severity:** P1. Clearbit's INV handler at `peer.zig:4298-4300`:

```zig
if (has_block_inv) {
    self.sendGetHeaders(peer) catch {};
}
```

A peer can announce the same block hash repeatedly (or many distinct
block hashes) via inv, each time triggering an outbound getheaders. The
`Peer` struct has a `last_getheaders_time` field (line 627) for
documenting timing, but the INV→getheaders trigger doesn't consult it.

Core (`net_processing.cpp`) has `m_last_getheaders_timestamp` per
m_block_sync_state with a 15s minimum interval check before issuing a
new getheaders to the same peer. clearbit's `sendGetHeaders` does update
`last_getheaders_time` (`peer.zig:627` is set somewhere) but the inv
handler doesn't gate on it.

**File:** `src/peer.zig:4298-4300` (inv-block trigger);
`src/peer.zig:627` (`last_getheaders_time` field exists).

**Core ref:** `bitcoin-core/src/net_processing.cpp` —
`m_last_getheaders_timestamp` gate (~line 2200, headers-sync state).

**Impact:** outbound bandwidth amplification on adversarial inv-block
spam (cheap for the attacker, ~64 B per inv, vs ~200 B per getheaders
with locator); peer cannot DoS our chain via spamming but can amplify
our outbound bytes.

---

## BUG-18 (P2) — No `-blocksonly` / `ignore_incoming_txs` operator knob

**Severity:** P2. Bitcoin Core's `-blocksonly` flag
(`m_opts.ignore_incoming_txs`) disables all tx relay; the node
participates in block-sync only. Used by archival nodes, fee-estimation
clients that defer to a wallet's own RBF logic, and privacy-conscious
operators who want to suppress all transaction-layer signal.

Clearbit has no such config knob (W136/G9,
`tests_w136_relay_flags.zig:233-240`). The node always relays.

**File:** `src/main.zig` (Config struct; no blocksonly field);
`src/peer.zig` (PeerManager; no blocksonly field).

**Core ref:** `bitcoin-core/src/init.cpp::AppInitParameters`
(`-blocksonly` flag).

**Impact:** operator cannot run clearbit in archival-only / privacy-
conscious mode; cross-impl deployment-mode parity gap.

---

## BUG-19 (P1) — `addTransactionWithPackageRate` envelope-bypass: skips CheckTransaction sanity, isCoinbase reject, and BIP-113 IsFinalTx

**Severity:** P1. clearbit's mempool exposes two ATMP entry-points:
- `addTransaction` (`mempool.zig:986-1457`) — canonical W96-gated path:
  CheckTransaction sanity (1a), isCoinbase reject (1b), W96 wtxid/txid
  duplicate split (1c), checkStandard (2), BIP-113 IsFinalTx (2b),
  input validation (3), BIP-68 sequence locks (3b), ... full pipeline.
- `addTransactionWithPackageRate` (`mempool.zig:3752-3988`) — CPFP
  package-rate variant: skips steps 1a (CheckTransaction sanity),
  1b (isCoinbase reject), and 2b (BIP-113 IsFinalTx). The W96 dup
  check is still present, but the **CheckTransaction-sanity gate is
  absent** — a tx with empty inputs/outputs, overflow output values,
  duplicate inputs, or non-coinbase null-prevout could in principle
  enter the mempool via this path.

A grep confirms `addTransactionWithPackageRate` is only called from
tests (`tests_w116_package_relay.zig` and `tests_w120_mempool_rbf.zig`),
not from any p2p production path. The function is fundamentally a
**dead-helper-at-call-site fleet pattern (clearbit's 5th instance)**:
defined + exported + tested but production-unreachable. That said:
- the test coverage gives a false sense that the package-relay code is
  exercised in the field,
- if anyone wires it into p2p (the W116 package-relay wave is
  in-progress fleet-wide), the W96 sanity bypass becomes a P0-CDIV
  consensus issue overnight.

This is the W151 BUG-9 envelope-bypass shape exactly: a parallel
entry-point that diverges from the canonical pipeline. **Two-pipeline
guard 18th distinct extension this quad-audit window** (within-file
guard, ATMP family).

**File:** `src/mempool.zig:3752-3988`.

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::PreChecks`
— a single function runs ALL gates; CheckTransaction is at line 798,
isCoinbase reject at line 803-804, all variants of submit/package
relay flow through the same PreChecks.

**Impact:**
- dead-helper-at-call-site fleet pattern, **clearbit's 5th instance**
  (joining W148 activateBestChain stub, W151 addTransactionWithPackageRate
  package envelope, W149 m_have_pruned dead-data flag, W149 ErrDiskFull
  defined-unused);
- W96 gate set divergent between two ATMP variants;
- live latent risk if/when production wires the package path.

---

## Summary

| Class | BUGs |
|-------|------|
| **P0-CDIV** (chain / wire / privacy / DoS-class) | 11 — BUG-2, BUG-3, BUG-5, BUG-6, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12, BUG-13 |
| **P0-SEC** (security-property regression) | 1 — BUG-4 |
| **P1** (correctness / scoring / efficiency) | 6 — BUG-1, BUG-14, BUG-15, BUG-16, BUG-17, BUG-19 |
| **P2** (operator-knob gap) | 1 — BUG-18 |
| **Total** | **19 bugs** |

---

## Fleet-pattern cross-cites

- **30-of-30-gates-buggy 5th candidate confirmed.** BUG-11 documents the
  entire `TxRequestTracker` subsystem (7 sub-gates) absent. clearbit
  is now **5-of-5** at this scale: W138 (assumeUTXO), W141 (ZMQ/REST/
  notify), W150 (ATMP pre/policy checks per memory index), W151
  (package relay/RBF per memory index), W152 (this wave). Pattern
  crystallisation: subsystem-rewrite candidate, not incremental patch.
- **Dead-helper-at-call-site 5th clearbit instance.** BUG-19's
  `addTransactionWithPackageRate` joins the W148 activateBestChain
  stub, W149 m_have_pruned dead-data flag, W149 ErrDiskFull defined-
  unused, and the W151 envelope-bypass family.
- **Two-pipeline guard 17th-18th distinct extension across this quad-
  audit window.** BUG-6 (RelayTransaction: inline correct vs BIP-35
  bulk-build wrong, **comment forbids the bug** in the same file pair)
  + BUG-19 (addTransaction vs addTransactionWithPackageRate).
- **Comment-as-confession 13th clearbit instance.** BUG-6's
  `peer.zig:5024` comment "Do NOT use MSG_WITNESS_TX (0x40000001) for
  relay inv" IS the documentation that the bug at `mempool.zig:4520-4523`
  exists.
- **Privacy-property regression.** BUG-4 (block-relay-only TX leak)
  + BUG-7 (deterministic relay-order fingerprint) cluster: each is a
  privacy-defining property that clearbit silently weakens. Same
  archetype as W141 unwhitelisted-mempool-bypass.
- **Entry-point envelope bypass (W151 BUG-9 echo).** BUG-19 mirrors
  the multi-entry-point bypass shape; BUG-10 (orphan promotion via
  `addTransaction` not `acceptToMemoryPool`) is a SECOND clearbit
  instance of envelope-bypass in the same wave.
- **Endianness / wire-format wtxid handling.** No endianness mismatch
  found in the inv path (Hash256 is byte-array, compared via
  `std.mem.eql`); the W149 BUG-13 endianness-mismatch pattern does not
  re-occur here. (Spec-checked: BUG-2's inv handler matches on byte
  arrays directly; BUG-6's MSG_WITNESS_TX vs MSG_WTX is a SEMANTIC
  not endian divergence.)

---

## Top 3 findings (priority ranking)

1. **BUG-11 (P0-CDIV) — `TxRequestTracker` 30-of-30-gates absent.**
   Single architectural rewrite closes 7 sub-gates and is the headline
   "5-of-5 30-of-30" fleet-pattern crystallisation. Largest scope:
   ~600 LOC port of `bitcoin-core/src/txrequest.cpp` semantics into
   Zig with per-peer maps, in-flight tracking, and 5 distinct delay
   classes.

2. **BUG-10 (P0-CDIV) — `processOrphansForParent` doesn't relay
   promoted txs.** ~3-line fix (add a relay-loop call into the success
   branch of the inner orphan-admit loop). Defeats the entire purpose
   of orphan management; affects propagation correctness on every node
   that runs clearbit. Cross-impl mining-fee divergence.

3. **BUG-6 (P0-CDIV) — `buildMempoolInventory` uses MSG_WITNESS_TX
   for relay inv.** ~3-line fix (mirror the inline relay loop's BIP-339
   branch). The inline comment at `peer.zig:5024` already says exactly
   what the fix is. **Comment-as-confession 13th instance** — the fix
   is literally documented at the call-site.
