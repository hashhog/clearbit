W134 — BIP-37 Bloom Filter + BIP-111 NODE_BLOOM service flag (clearbit / Zig 0.13)
==================================================================================

Wave: W134
Subsystem: CBloomFilter (common/bloom.{cpp,h}), CMerkleBlock / CPartialMerkleTree
           (merkleblock.{cpp,h}), filterload / filteradd / filterclear / merkleblock
           message handlers, MSG_FILTERED_BLOCK getdata response, NODE_BLOOM service
           bit + BIP-111 disconnect gate, per-peer m_bloom_filter / m_relay_txs state.
Excludes: BIP-157/158 compact filters (W121, W122 — separate codec).
          BIP-37 has been removed from Bitcoin Core's *advertise* path: NODE_BLOOM
          defaults OFF (DEFAULT_PEERBLOOMFILTERS=false since v0.21) but Core still
          implements the full primitive so that operators who opt in continue to
          serve light clients correctly.

References (Bitcoin Core, current `master`):
- bitcoin-core/src/common/bloom.cpp + bloom.h          (CBloomFilter, CRollingBloomFilter)
- bitcoin-core/src/merkleblock.cpp + merkleblock.h     (CMerkleBlock, CPartialMerkleTree,
                                                        BitsToBytes / BytesToBits)
- bitcoin-core/src/net_processing.cpp                  (FILTERLOAD / FILTERADD /
                                                        FILTERCLEAR handlers @ 4963-5033;
                                                        MSG_FILTERED_BLOCK getdata response
                                                        @ 2438-2458; m_bloom_filter,
                                                        m_relay_txs, TxRelay init @ 3676-3691)
- bitcoin-core/src/init.cpp                            (-peerbloomfilters flag @ 572,
                                                        NODE_BLOOM g_local_services
                                                        @ 1104-1105)
- bitcoin-core/src/protocol.h                          (NODE_BLOOM = (1<<2) @ 317;
                                                        BIP-111 cross-ref @ 137)
- bitcoin-core/src/net_processing.h                    (DEFAULT_PEERBLOOMFILTERS=false @ 44)
- bitcoin-core/src/script/script.h                     (MAX_SCRIPT_ELEMENT_SIZE=520 @ 28)
- BIP-37 (Connection Bloom filtering)
- BIP-111 (NODE_BLOOM service bit + disconnect gate)

Likely clearbit paths:
- src/bloom.zig                                         (DOES NOT EXIST — CBloomFilter
                                                         and CMerkleBlock subsystem
                                                         entirely absent in clearbit)
- src/p2p.zig                                           (filterload/filteradd/filterclear/
                                                         merkleblock variants of
                                                         `Message`, opaque payload only;
                                                         NODE_BLOOM constant @ 19;
                                                         InvType.msg_filtered_block @ 240)
- src/peer.zig                                          (handler arms @ 5340-5386 apply
                                                         the BIP-111 disconnect gate;
                                                         Peer.advertise_node_bloom flag
                                                         @ 651; PeerManager.peerbloomfilters
                                                         @ 2357; services bitmap @ 1453-1465)
- src/v2_transport.zig                                  (V2_MESSAGE_IDS short IDs 6/7/8/16
                                                         registered @ 140-150)
- src/main.zig                                          (--peerbloomfilters CLI flag
                                                         @ 297-308)

Prior-wave intersection:
- W110 (2026-05-12) audited the same subsystem and catalogued 11 BUGs across
  G1-G30. FIX-36 (commit b0bc679) closed BUG-6/7/8 (filterload/filteradd/
  filterclear: BIP-111 disconnect gate applied) and turned BUG-9 into PARTIAL
  (merkleblock variant added; PartialMerkleTree response still absent).
- W134 re-audits the same surface against current Core master to detect drift
  (Core compiles unchanged in this area), to extend coverage to gates W110 did
  not formalise (Peer.m_bloom_filter / m_relay_txs absence; -peerbloomfilters
  init.cpp wiring; PartialMerkleTree serialization symmetry; CMerkleBlock
  vMatchedTxn follow-up TX dispatch; CRollingBloomFilter reset / FastRange32
  cross-link), and to identify universal patterns (NODE_BLOOM gate ABSENT on
  the mempool path is found in MORE than one impl).


-------------------------------------------------------------------------------
Summary
-------------------------------------------------------------------------------

**25 BUGs across 30 gates** (PARTIAL or MISSING). 5 gates PASS.

The subsystem status hasn't materially changed since W110: clearbit has NO
CBloomFilter and NO PartialMerkleTree. The wire-layer variants that FIX-36
added are opaque-payload carriers — they let the decoder return a typed
variant instead of `UnknownCommand` and let the handler apply the BIP-111
disconnect gate, but no filter is ever constructed, inserted into, or matched
against. NODE_BLOOM is correctly defined and conditionally advertised.

What W134 adds vs. W110:

1. **G15** — `insert(COutPoint)` 36-byte serialization is split out from
   the bare `insert(span)` overload. CBloomFilter has two `insert` paths
   (Core bloom.cpp:50-67); clearbit has neither.

2. **G24** — `PartialMerkleTree::TraverseAndBuild` and `TraverseAndExtract`
   are formalised as separate gates (W110 lumped both into BUG-9). Symmetry
   between build and extract is the source of the CVE-2012-2459 hardening
   in `TraverseAndExtract` (left == right check).

3. **G25** — `MSG_FILTERED_BLOCK` getdata response is formalised: Core
   net_processing.cpp:2438-2458 sends MERKLEBLOCK *plus* every matched
   transaction as TX (without re-fetching from mempool). Clearbit has no
   such branch in its getdata switch (peer.zig:5077-5253) — BUG-19.

4. **G28** — Per-peer `m_bloom_filter` / `m_relay_txs` state is formalised
   as a NEW gate. Core net_processing.cpp:293-297 holds these *behind a
   mutex* (m_bloom_filter_mutex). Clearbit's Peer has NO such fields —
   BUG-22 (the same Peer struct stores `advertise_node_bloom` for the
   ADVERTISE side, not the RECEIVE side).

5. **G29** — fRelay semantics in VERSION + TxRelay init are formalised.
   Core net_processing.cpp:3682-3691 only initialises `m_relay_txs` when
   one of (`fRelay==true` OR `NODE_BLOOM` offered) is true; if both are
   false the peer is a tx-blind block-only conn. Clearbit always sets
   the local `relay_txs` arg to true and the receive-side has no equivalent
   state, so every inbound peer is treated as a relay peer — BUG-23.

6. **G30** — BIP-111 + mempool gate is re-audited and PARTIAL (mempool
   path PASSES, filter* paths PASS, but ONE missing piece: the BIP-111
   ban score (Core uses Misbehaving(100) on FILTERADD oversize, clearbit
   only disconnect-no-ban — BUG-25).

7. **CRollingBloomFilter** — common/bloom.cpp also defines CRolling*; we
   note its absence (BUG-24) because clearbit lacks even the rolling-bloom
   primitive that BanMan uses for discouragement (cross-ref W128 BUG-16
   — same root cause).

8. **TWO-PIPELINE** — re-affirmed: v2_transport short IDs 6/7/8/16 are
   registered AND p2p.Message has matching variants (CLOSED — FIX-36).


-------------------------------------------------------------------------------
Gate matrix
-------------------------------------------------------------------------------

Legend:
  PASS    — behaviour matches Core (or correctly omits behaviour Core also gates off).
  PARTIAL — primitive exists but is wired wrong / missing fields / wrong DoS score.
  MISSING — primitive entirely absent.
  BUG-N   — catalogued below with priority.

| Gate | Area                                                       | Status   | Bug     | Pri  |
|------|------------------------------------------------------------|----------|---------|------|
| G1   | MAX_BLOOM_FILTER_SIZE = 36000 (bytes)                      | MISSING  | BUG-1   | P1   |
| G2   | MAX_HASH_FUNCS = 50                                        | MISSING  | BUG-2   | P1   |
| G3   | LN2SQUARED precision constant (full 16-digit form)         | MISSING  | BUG-3   | P2   |
| G4   | vData sizing: min(-1/LN2² * nElements * log(fp), 36000*8)/8| MISSING  | BUG-4   | P1   |
| G5   | nHashFuncs: min(vData.size()*8 / nElements * LN2, 50)      | MISSING  | BUG-5   | P1   |
| G6   | MurmurHash3 32-bit primitive                               | MISSING  | BUG-6   | P0   |
| G7   | Hash schedule constant 0xFBA4C795 + nTweak                 | MISSING  | BUG-7   | P0   |
| G8   | Bit index = hash % (vData.size() * 8)                      | MISSING  | BUG-8   | P0   |
| G9   | Bit set: vData[idx >> 3] \|= (1 << (7 & idx))               | MISSING  | BUG-9   | P0   |
| G10  | CVE-2013-5700 divide-by-zero guard (vData.empty()→true)    | MISSING  | BUG-10  | P0   |
| G11  | BLOOM_UPDATE_NONE = 0                                      | MISSING  | BUG-11  | P1   |
| G12  | BLOOM_UPDATE_ALL = 1                                       | MISSING  | BUG-11  | P1   |
| G13  | BLOOM_UPDATE_P2PUBKEY_ONLY = 2                             | MISSING  | BUG-11  | P1   |
| G14  | BLOOM_UPDATE_MASK = 3 + nFlags application                 | MISSING  | BUG-11  | P1   |
| G15  | insert(COutPoint) 36-byte serialization (txid \|\| n LE)     | MISSING  | BUG-12  | P1   |
| G16  | IsRelevantAndUpdate: txid match                            | MISSING  | BUG-13  | P1   |
| G17  | per-output scriptPubKey pushdata extraction (GetOp loop)   | MISSING  | BUG-14  | P1   |
| G18  | P2PK / P2PKH / multisig outpoint insertion (Solver)        | MISSING  | BUG-15  | P1   |
| G19  | outpoint contained-in-filter test (txin.prevout)           | MISSING  | BUG-16  | P1   |
| G20  | scriptSig per-data-element match                           | MISSING  | BUG-17  | P1   |
| G21  | FILTERLOAD: NODE_BLOOM gate + IsWithinSizeConstraints      | PARTIAL  | BUG-18  | P0   |
| G22  | FILTERADD: NODE_BLOOM gate + 520B MAX_SCRIPT_ELEMENT_SIZE  | PARTIAL  | BUG-18  | P0   |
| G23  | FILTERCLEAR: NODE_BLOOM gate + filter reset                | PARTIAL  | BUG-18  | P1   |
| G24  | PartialMerkleTree: TraverseAndBuild / TraverseAndExtract,  |          |         |      |
|      | BitsToBytes / BytesToBits, CVE-2012-2459 left==right reject| MISSING  | BUG-19  | P0   |
| G25  | MSG_FILTERED_BLOCK getdata: send MERKLEBLOCK + matched TXs | MISSING  | BUG-20  | P1   |
| G26  | NODE_BLOOM service bit = (1<<2) = 4                        | PASS     |         |      |
| G27  | -peerbloomfilters default false (DEFAULT_PEERBLOOMFILTERS) | PASS     |         |      |
| G28  | Per-peer m_bloom_filter / m_relay_txs (mutex-guarded)      | MISSING  | BUG-22  | P0   |
| G29  | fRelay semantics + TxRelay init                            |          |         |      |
|      |  (init only when fRelay\|\|NODE_BLOOM)                       | MISSING  | BUG-23  | P1   |
| G30  | BIP-111 misbehaving score on FILTERADD oversize (=100)     | PARTIAL  | BUG-25  | P1   |

Cross-cutting bugs (not gate-numbered):
| -    | CRollingBloomFilter primitive entirely absent              | MISSING  | BUG-24  | P1   |
| -    | TWO-PIPELINE: v2_transport ↔ Message union                 | PASS     |         |      |
| -    | mempool BIP-35/NODE_BLOOM disconnect gate                  | PASS     |         |      |
| -    | filterload/filteradd/filterclear/merkleblock in Message    | PASS     |         |      |


-------------------------------------------------------------------------------
Bug catalogue
-------------------------------------------------------------------------------

BUG-1 — MAX_BLOOM_FILTER_SIZE = 36000 absent (P1).
  Core bloom.h:17 `static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000;`
  Clearbit has no bloom.zig and no module-level constant. Any future
  FILTERLOAD oversize guard would have to introduce the constant. Closes
  W110 BUG-1 mirror at G1.

BUG-2 — MAX_HASH_FUNCS = 50 absent (P1).
  Core bloom.h:18 `static constexpr unsigned int MAX_HASH_FUNCS = 50;`
  Same root as BUG-1: no bloom.zig.

BUG-3 — LN2SQUARED precision constant absent (P2).
  Core bloom.cpp:23 defines the constant to full 16-digit precision:
  `0.4804530139182014246671025263266649717305529515945455`. Reduced
  precision would change vData.size() rounding at certain (nElements, fp)
  combinations and break wire-compat with Core-built filters when the
  rounding is at a byte boundary. Note: Core ALSO has LN2 (bloom.cpp:24)
  used in the nHashFuncs formula; we count both under BUG-3.

BUG-4 — vData sizing formula absent (P1).
  Core bloom.cpp:32:
    `vData(std::min((unsigned int)(-1/LN2SQUARED * nElements * log(nFPRate)),
                    MAX_BLOOM_FILTER_SIZE * 8) / 8)`.
  Note: the *bits* are capped at 36000*8 then divided by 8 to bytes — i.e.
  the cap is applied in BIT space, not BYTE space, which can produce a
  byte-aligned cap that differs from `min(... , 36000)` by one byte in
  edge cases.

BUG-5 — nHashFuncs formula absent (P1).
  Core bloom.cpp:38:
    `nHashFuncs(std::min((unsigned int)(vData.size() * 8 / nElements * LN2),
                          MAX_HASH_FUNCS))`.
  This is INTEGER division of (vData.size()*8) by nElements BEFORE multiplying
  by LN2 — a subtle ordering difference from the textbook formula
  `m/n * ln 2`. Any clean-room re-implementation MUST match this ordering
  or filters will not be wire-compatible.

BUG-6 — MurmurHash3 32-bit absent from crypto module (P0).
  Core uses MurmurHash3 (hash.h:`MurmurHash3`) as the bloom-filter hash.
  Clearbit's crypto.zig has sha256, hash256, ripemd160, siphash — no
  murmur. Note: MurmurHash3 is also used in CRollingBloomFilter
  (bloom.cpp:191) and cross-references W128 BUG-16 (rolling bloom for
  discouragement).

BUG-7 — Hash schedule constant 0xFBA4C795 absent (P0).
  Core bloom.cpp:47: `MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash)`.
  The constant is chosen for "reasonable bit difference between nHashNum
  values" (the Core comment) — any change here desynchronises clearbit-
  built filters from Core-built filters.

BUG-8 — Bit index reduction missing (P0).
  Core bloom.cpp:47-48: `... % (vData.size() * 8)` produces the bit index
  from the 32-bit MurmurHash3 output. Absent in clearbit.

BUG-9 — Bit set/test logic absent (P0).
  Core bloom.cpp:58 (`vData[nIndex >> 3] |= (1 << (7 & nIndex))`) and 77
  (`vData[nIndex >> 3] & (1 << (7 & nIndex))`). The shift constant `7 & nIndex`
  is LSB-first WITHIN the byte (so bit-0 of byte-0 corresponds to hash
  output 0). Clearbit has no bit-set/test logic at all.

BUG-10 — CVE-2013-5700 divide-by-zero guard missing (P0).
  Core bloom.cpp:52, 71, 100 — three call-sites where `vData.empty()` is
  checked BEFORE the modulo. `insert` returns silently, `contains` returns
  true ("match-all"), `IsRelevantAndUpdate` returns true. Absent in clearbit
  (no CBloomFilter; this is a *gate against a fix wave that adds CBloomFilter
  without porting the guard*). Cross-ref CVE-2013-5700.

BUG-11 — BLOOM_UPDATE_* flags + UPDATE_MASK absent (P1).
  Core bloom.h:24-31:
    `BLOOM_UPDATE_NONE = 0`, `BLOOM_UPDATE_ALL = 1`,
    `BLOOM_UPDATE_P2PUBKEY_ONLY = 2`, `BLOOM_UPDATE_MASK = 3`.
  Only the LOW 2 bits of nFlags are consulted; the upper 6 are reserved.
  No constants or mask in clearbit.

BUG-12 — insert(COutPoint) 36-byte serialization absent (P1).
  Core bloom.cpp:62-67: `DataStream stream{}; stream << outpoint; insert(span)`.
  `COutPoint::SERIALIZE_METHODS` is `(hash, n)` → 32 bytes Txid + 4 bytes
  LE n = 36 bytes. The two overloads of `insert` provide the only canonical
  way to add an outpoint; if a clean-room impl serialised outpoints
  differently (big-endian n, or non-32-byte txid form), filters would be
  Core-incompatible.

BUG-13 — IsRelevantAndUpdate: txid match absent (P1).
  Core bloom.cpp:102-104: `const Txid& hash = tx.GetHash(); if (contains(hash.ToUint256())) fFound = true;`
  The TXID is matched first; only if it doesn't match are outputs scanned.
  This is the cheap path: SPV clients seed their filter with txids they care
  about and only fall through to per-output scanning for spending tx.

BUG-14 — per-output scriptPubKey GetOp loop absent (P1).
  Core bloom.cpp:113-135: walks each `txout.scriptPubKey` opcode-by-opcode
  via `CScript::GetOp(pc, opcode, data)`, looking for data pushes whose
  bytes are `contains()`-ed. The Solver() call (BUG-15) is gated on the
  match.

BUG-15 — P2PK / P2PKH / multisig auto-outpoint insertion absent (P1).
  Core bloom.cpp:127-131: when `nFlags == BLOOM_UPDATE_P2PUBKEY_ONLY`,
  calls `Solver(txout.scriptPubKey, vSolutions)` and inserts the matched
  outpoint only if `type == TxoutType::PUBKEY` or `TxoutType::MULTISIG`.
  This is the "P2PUBKEY-only auto-insert" semantic that enables wallet
  privacy modes. Absent in clearbit.

BUG-16 — outpoint contained-in-filter test absent (P1).
  Core bloom.cpp:144: `if (contains(txin.prevout)) return true;`
  This is the spend-side match — clients add outpoints to the filter
  via `filteradd` so that any tx that spends one of their UTXOs hits.

BUG-17 — scriptSig per-data-element match absent (P1).
  Core bloom.cpp:148-157: same GetOp loop as scriptPubKey but on each
  input's scriptSig. Lets SPV clients catch tx that *reveal* a redeem
  script (P2SH-spending tx) that they care about, beyond just the outpoint.

BUG-18 — FILTERLOAD / FILTERADD / FILTERCLEAR: PARTIAL (P0).
  Status: FIX-36 added BIP-111 disconnect gate; the *outer* gate fires
  before the *inner* content checks. So today on every clearbit peer
  with `peerbloomfilters=false` (the default, matching Core), filterload
  triggers disconnect — same observable behaviour as Core.
  Missing if `peerbloomfilters=true` is ever enabled:
    G21: IsWithinSizeConstraints() check after deserialization (Core
         net_processing.cpp:4972-4975 — Misbehaving on oversize).
    G22: MAX_SCRIPT_ELEMENT_SIZE = 520 byte cap on FILTERADD vData (Core
         net_processing.cpp:4997-5001 — Misbehaving on oversize).
    G23: Per-peer filter destruction on FILTERCLEAR + m_relay_txs=true
         (Core net_processing.cpp:5025-5031 — clearbit has no per-peer
         filter to destroy).
  See also W110 BUG-6/7/8/10 (PRE-FIX-36 framing; BUG-10 still applies as
  G21/G22 are unreachable when NODE_BLOOM is off).

BUG-19 — PartialMerkleTree + BitsToBytes / BytesToBits absent (P0 for any
  serving impl; P2 while NODE_BLOOM is off).
  Core merkleblock.cpp:13-29 (helpers), 80-95 (TraverseAndBuild), 99-135
  (TraverseAndExtract with CVE-2012-2459 left==right reject). Clearbit
  has no PartialMerkleTree type at all and cannot serialise a merkleblock.
  The CVE-2012-2459 guard MUST be preserved in any clean-room impl —
  it prevents the duplicate-txid duplicate-subtree attack that breaks
  block validation: `if (right == left) { fBad = true; }`.

BUG-20 — MSG_FILTERED_BLOCK getdata response absent (P1).
  Core net_processing.cpp:2438-2458: when a peer sends getdata with
  InvType::MSG_FILTERED_BLOCK and the peer has a loaded filter, the
  responder builds `CMerkleBlock(*pblock, *bloom_filter)` and sends:
    1. MERKLEBLOCK (the partial merkle tree),
    2. one TX per `vMatchedTxn` entry (Core 2456-2457: `MakeAndPushMessage
       (TX, TX_NO_WITNESS(*pblock->vtx[tx_idx]))`).
  Clearbit's getdata switch (peer.zig:5077-5253) has branches for
  MSG_BLOCK / MSG_CMPCT_BLOCK / MSG_TX / MSG_WTX — NO branch for
  MSG_FILTERED_BLOCK. Behaviour: filtered-block requests fall through to
  `notfound` (the default path Core takes for unknown inv types, since
  no notfound is sent by Core specifically here — Core sends no response).
  Clearbit also sends no useful response, BUT for the wrong reason
  (handler simply absent, not "no filter loaded"). The observable
  difference (notfound vs no-response) is small for production peers
  with NODE_BLOOM off, but the gate is needed for any future serving path.

BUG-21 — (intentionally skipped to keep gate-bug numbering aligned with
  the W110 catalogue; W110 BUG-11 reused NODE_BLOOM PASS).

BUG-22 — Per-peer m_bloom_filter / m_relay_txs state absent (P0).
  Core net_processing.cpp:293-297 stores:
    `RecursiveMutex m_bloom_filter_mutex;`
    `bool m_relay_txs GUARDED_BY(m_bloom_filter_mutex){false};`
    `std::unique_ptr<CBloomFilter> m_bloom_filter PT_GUARDED_BY(...);`
  These three fields are CO-LOCATED on the TxRelay struct (per peer)
  behind ONE mutex. Clearbit's Peer struct has `advertise_node_bloom`
  (the ADVERTISE side: what we tell remote peers about us) but NO
  corresponding *receive*-side state for the bloom filter sent BY the
  remote peer. There is no place to put the CBloomFilter even if BUG-1
  to BUG-17 were closed.

BUG-23 — fRelay semantics + TxRelay init absent (P1).
  Core net_processing.cpp:3676-3691 only sets up TxRelay when
    `!IsBlockOnlyConn() && !IsFeelerConn() && (fRelay || NODE_BLOOM offered)`.
  And inside, `m_relay_txs = fRelay` (so the peer can flip relay on later
  via filterload). Clearbit always inits its EvictionCandidate `relay_txs`
  field as `true` (peer.zig:810, 887, 937) regardless of the inbound peer's
  VERSION fRelay byte. Net effect: a peer that sent `fRelay=false` in
  VERSION (a block-relay-only client) is still treated as a tx-relay peer
  for all evicition / mempool scheduling purposes. Cross-cuts BIP-37
  because clients use `version.relay=false` then `filterload` to ENABLE
  relay; without per-peer m_relay_txs, this transition is silently a no-op.

BUG-24 — CRollingBloomFilter primitive absent (P1).
  Core bloom.h:108-125 + bloom.cpp:163-247. This is a separate primitive
  from CBloomFilter, used by BanMan for discouragement
  (`CRollingBloomFilter m_discouraged{50000, 0.000001}`) and by
  net_processing for already-seen tx tracking. Cross-ref W128 BUG-16:
  the missing rolling-bloom-filter for discouragement is the SAME root
  cause as this gap — clearbit has no MurmurHash3, no FastRange32, no
  generation-rolling logic.

BUG-25 — BIP-111 / Misbehaving score on FILTERADD oversize: PARTIAL (P1).
  Core net_processing.cpp:5010-5012: `Misbehaving(peer, "bad filteradd
  message")` — score 100 (instant discourage) on FILTERADD content >520B
  bytes. Clearbit's handler peer.zig:5354-5363 disconnects on NODE_BLOOM
  absent (correct), but does NOT issue a misbehaving score even when the
  payload is oversized; the oversize check itself is absent because
  CBloomFilter is absent. Cross-cuts W128 BUG-15 (no distinct Discourage
  primitive).


-------------------------------------------------------------------------------
Universal patterns observed
-------------------------------------------------------------------------------

1. **"FIX-36 closed the wire-pipeline gap, not the substance"** — clearbit's
   FIX-36 (b0bc679) added 4 Message-union variants (filterload, filteradd,
   filterclear, merkleblock) and the BIP-111 disconnect gate. This gives
   clearbit the SAME observable peer-facing behaviour as Core on the default
   path (peerbloomfilters=false → instant disconnect). What FIX-36 did NOT
   close: every gate that would matter if NODE_BLOOM were ever turned on.
   Pattern: **opaque-payload-+-disconnect-gate is a valid 26-wave streak
   closure when the upstream service is intentionally OFF by default and
   reactivating it is gated on a separate operator-opt-in flag**. Generalizable
   to BIP-37, BIP-111, BIP-329 (any deprecated-but-not-removed protocol).

2. **"Per-peer state ABSENT but advertisement state PRESENT"** (BUG-22, BUG-23).
   Clearbit has `Peer.advertise_node_bloom` (what we *advertise*) but no
   corresponding `Peer.relay_txs` / `Peer.bloom_filter` (what the *remote*
   sent us about their relay intentions). This is a common shape across
   the fleet (`advertise_*` fields are routine; `m_*` Core-style receive-side
   state is routinely absent because the impl never plans to *serve* the
   subsystem). Cross-cuts BIP-152 (compactblock high-bandwidth peer
   selection), BIP-339 (wtxidrelay receive-side state).

3. **"MurmurHash3 absence is a fleet-wide gap"** (BUG-6, cross-ref W128
   BUG-16). MurmurHash3 is needed for two distinct subsystems —
   CBloomFilter (BIP-37) and CRollingBloomFilter (BanMan discouragement).
   Any impl that lacks one is overwhelmingly likely to lack the other.
   Pattern: **discoveries should cross-reference fleet-mate audits when a
   shared primitive is the lift**. A fix that adds MurmurHash3 to clearbit
   (~30 LOC) unlocks both subsystems simultaneously.

4. **"CVE-2012-2459 left==right reject" is unique to PartialMerkleTree
   and easy to miss in a clean-room rewrite** (BUG-19). The check fires
   only on the merkleblock side, not the full-block validation side
   (full-block uses CHashWriter on the merkle path). Any future
   PartialMerkleTree impl MUST include the `right == left` reject or it
   inherits the CVE.

5. **"NODE_BLOOM service bit value PASS / behaviour MISSING" is the most
   common shape** (G26 PASS, G6-G20 MISSING). The bit was defined when
   the message handlers were stubbed; the substance was deferred.
   Cross-cuts NODE_NETWORK (always advertised — block-serve is impl'd),
   NODE_WITNESS (always advertised — segwit is impl'd), NODE_COMPACT_FILTERS
   (conditionally advertised — BIP-158 impl'd in clearbit via FIX-84
   recently). NODE_BLOOM and NODE_P2P_V2 (BIP-324) sit in the opposite
   bucket: bit defined, subsystem partially or wholly missing.


-------------------------------------------------------------------------------
Test pass/fail expectations
-------------------------------------------------------------------------------

The W134 test module is XFAIL-style: BUG tests assert the CURRENT (buggy or
missing) state so that a future fix wave can flip each gate by intentionally
breaking the test. PASS tests (G26, G27, mempool gate, TWO-PIPELINE) assert
the working state and protect against regression.

Expected: 30/30 PASS at land time. Any FAIL post-land = drift in clearbit
relative to this audit's snapshot of Core master.
