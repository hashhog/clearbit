# W126 — BIP-152 Compact Blocks audit (clearbit / Zig 0.13)

**Date:** 2026-05-17
**Wave:** W126 (discovery — explicit re-audit of BIP-152 subsystem,
follow-on to W112 / W123 G12).
**Scope:** BIP-152 compact-block protocol end-to-end:

- `sendcmpct` handshake-side feature negotiation + version gate.
- `cmpctblock` receive: PoW preliminary, header acceptance, short-id
  reconstruction, fallback paths (full block, getblocktxn).
- `getblocktxn` receive: depth gate + serve `blocktxn` for shallow blocks.
- `blocktxn` receive: completion of round-trip + validation submit.
- HB-peer announce side (W123 G12 BUG-12 anchor): `announceBlock` does NOT
  push `cmpctblock` unsolicited to BIP-152 high-bandwidth peers.
- `PartiallyDownloadedBlock` reconstruction (slot fill, mempool match,
  collision detection, FillBlock + IsBlockMutated).
- Short-tx-id SipHash key derivation + 48-bit mask.
- v1 vs v2 version negotiation.

**Mode:** DISCOVERY (no production code changes; XFAIL guards only).
**Test step:** `zig build test-w126` (30 tests, folded into `zig build test`).

## Reference

- `bitcoin-core/src/blockencodings.h` — `CBlockHeaderAndShortTxIDs`,
  `PartiallyDownloadedBlock` (constructor, `InitData`, `IsTxAvailable`,
  `FillBlock`), `DifferenceFormatter`, `BlockTransactionsRequest`,
  `BlockTransactions`, `PrefilledTransaction`, `SHORTTXIDS_LENGTH = 6`.
- `bitcoin-core/src/blockencodings.cpp` — `FillShortTxIDSelector`,
  `GetShortID` (48-bit mask), `InitData` (prefilled accumulation,
  short-id map, collision detection, bucket overflow, mempool match,
  extra-txn match), `FillBlock` (slot-fill + `IsBlockMutated`).
- `bitcoin-core/src/net_processing.cpp` —
  - `MAX_CMPCTBLOCK_DEPTH = 5` (line 138),
    `MAX_BLOCKTXN_DEPTH = 10` (line 140),
    `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK`,
    `CMPCTBLOCKS_VERSION = 2` (line 199).
  - `MaybeSetPeerAsAnnouncingHeaderAndIDs` (line 1275–1329):
    LRU 3-peer `lNodesAnnouncingHeaderAndIDs`, outbound preference,
    `sendcmpct(hb=true)` on add / `sendcmpct(hb=false)` on evict,
    `m_bip152_highbandwidth_to` latch.
  - `NewPoWValidBlock` (line 2103–2152): unsolicited `cmpctblock` push
    to HB peers, `m_most_recent_block_hash` / `m_most_recent_compact_block`
    cache, segwit-active gate, `m_highest_fast_announce` monotonic.
  - `SENDCMPCT` handler (line 3901–3917):
    `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return`,
    set `m_provides_cmpctblocks`, `m_requested_hb_cmpctblocks`,
    `m_bip152_highbandwidth_from`.
  - `GETBLOCKTXN` handler (line 4245–4304):
    deserialize `BlockTransactionsRequest`, m_most_recent_block fast path,
    `LookupBlockIndex` + `BLOCK_HAVE_DATA`, depth `<= MAX_BLOCKTXN_DEPTH`,
    `ReadBlock` then `SendBlockTransactions`; deeper → push
    `MSG_WITNESS_BLOCK` inv onto `m_getdata_requests`.
  - `CMPCTBLOCK` handler (line 4466–4712):
    `LoadingBlocks` gate, `prev_block` exists or `MaybeSendGetHeaders`,
    `GetBlockProof` anti-DoS threshold, `ProcessNewBlockHeaders` +
    `via_compact_block` punishment flag, `mapBlocksInFlight` accounting +
    `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK`, `CanDirectFetch` gate (IBD),
    `MAX_BLOCKS_IN_TRANSIT_PER_PEER`, `nHeight <= tip+2` proximity guard,
    `PartiallyDownloadedBlock::InitData` with `vExtraTxnForCompact`,
    `READ_STATUS_INVALID` → `Misbehaving` + `RemoveBlockRequest`,
    `READ_STATUS_FAILED` → first-in-flight full-block fetch vs give-up,
    empty-indexes fast-path → `ProcessCompactBlockTxns`,
    optimistic temp-block reconstruction for already-in-flight case,
    `ProcessBlock(force=true, min_pow_checked=true)` + `RemoveBlockRequest`.
  - `BLOCKTXN` handler (line 4714–4730): `LoadingBlocks` gate +
    `ProcessCompactBlockTxns`.
  - `ProcessCompactBlockTxns` (line 3441–3540): persisted-state lookup
    via `mapBlocksInFlight`, `requested_block_from_this_peer` enforcement,
    Misbehaving on multi-fill, `FillBlock` with `segwit_active`,
    `ProcessNewBlock(force_processing=true)`, `RemoveBlockRequest`.
  - `MaybePunishNodeForBlock` (caller sites with `via_compact_block=true`
    bypass for BIP-152 §3 "MUST NOT ban").
  - `SendBlockTransactions` (line 2598–2615): `req.indexes[i] >= vtx.size()`
    Misbehaving, `blocktxn` reply.
- BIP-152: low-bandwidth + high-bandwidth modes, `sendcmpct` semantics,
  3-HB-peer cap, version 2 wtxid short IDs, sibling status of
  `cmpctblock`/`getblocktxn`/`blocktxn` messages.

## SUBSYSTEM STATUS — BIP-152 surface

Pre-audit baseline (`8b6df23` — W124 commit):

- **Decoders (PRESENT — fleet-leading):** `sendcmpct`, `cmpctblock`,
  `getblocktxn`, `blocktxn` all decode with full DoS guards
  (`p2p.zig:886-1018`). Cmpctblock decoder enforces
  `short_id_count > 100_000 → InvalidData`, `prefilled_count > 0xffff`,
  `short_id_count + prefilled_count > 0xffff`, and per-prefilled
  delta-overflow `> 0xffff`. Getblocktxn decoder accumulates deltas
  with `shift > 0xffff` overflow check matching Core
  `DifferenceFormatter::Unser`.
- **Version negotiation (PRESENT — FIX-43 wave):** Both the handshake
  loop (`peer.zig:1531-1541`) and post-handshake dispatch
  (`peer.zig:5318-5328`) drop sendcmpct with `version != 2`. Only v2
  installs compact-relay state on the peer.
  `Peer.bip152_provides_cmpctblocks` + `Peer.bip152_highbandwidth_from`
  fields exist (`peer.zig:682+689`), set on receive, mirror Core
  `m_provides_cmpctblocks` + `m_bip152_highbandwidth_from`.
- **MAX_BLOCKTXN_DEPTH=10 guard (PRESENT — FIX-42 wave):**
  `peer.zig:4944-4990` getblocktxn handler computes
  `tip_height - block_height` and falls back to full block via served-
  blocks/block-buffer cache when `depth > MAX_BLOCKTXN_DEPTH`.
- **MAX_CMPCTBLOCK_DEPTH=5 serve path (PRESENT — FIX-42 wave):**
  `peer.zig:5102-5232` getdata MSG_CMPCT_BLOCK branch: looks up height,
  builds `CBlockHeaderAndShortTxIDs` from cached block (coinbase
  prefilled + non-coinbase as 6-byte short IDs via wtxid SipHash),
  serves `cmpctblock` when `depth <= 5`, else full block, else notfound.
- **Receive-side reconstruction (PARTIAL):** `cmpctblock` handler
  `peer.zig:4703-4943` implements PoW-derived SipHash key
  (header || nonce LE 88-byte digest), prefilled differential
  accumulation with overflow + gap checks, 48-bit short-id mask,
  duplicate-short-id collision detection, bucket-overflow DoS check
  (max 12 per bucket — Core `blockencodings.cpp:110`), mempool wtxid
  iteration with early-exit at full-match, second-mempool-match slot
  clear (Core `blockencodings.cpp:129-136`), missing-index getblocktxn
  emission. All of this is **dead-code-at-tail**: the success path
  ends at `peer.zig:4910` with literal comment
  `// TODO: assemble full block and pass to validation` — the
  reconstructed block is never built into a `types.Block` and never
  submitted to the validation pipeline.
- **Outgoing serve `blocktxn` (MISSING):** getblocktxn handler at
  `peer.zig:4944-4993` falls through the MAX_BLOCKTXN_DEPTH guard and
  then comments `// we don't yet serve blocktxn responses (BUG-7,
  separate from BUG-8). Ignore.` — clearbit is a black hole for
  in-depth `getblocktxn` from peers (peer times out, falls back to
  full block).
- **`blocktxn` receive (MISSING):** `peer.zig:4994-5004` arm allocates +
  frees the deserialized transactions then comments
  `// Response to our getblocktxn request. Since we fall back to /
  full block download, we shouldn't receive these. Ignore.` — the
  round-trip never completes; the partial-block state is also not
  persisted across messages (no `PartiallyDownloadedBlock` in
  `Peer` or `PeerManager` — see G8 below).
- **HB-peer announce push (MISSING — W123 G12 BUG-12 anchor):**
  `announceBlock` (`peer.zig:7134-7160`) consults only
  `peer.send_headers` to choose `inv` vs `headers`. `bip152_highbandwidth_from`
  is read **only** at the receive site `peer.zig:5327` (latch) — the
  announce site does **not** branch on it. Even though the receive side
  knows which peers selected us as HB, we never act on that signal.
- **HB-peer selection MISSING:** No `lNodesAnnouncingHeaderAndIDs`
  equivalent, no `MaybeSetPeerAsAnnouncingHeaderAndIDs`, no outgoing
  `sendcmpct(announce=true, version=2)` on a per-peer basis to mark a
  peer as our HB sender. Our handshake sends
  `sendcmpct(announce=false, version=2)` to every peer (`peer.zig:1623`),
  so we never get HB blocks from anyone either.
- **NewPoWValidBlock signal MISSING:** No fast-announce on tip advance —
  neither for our own mined blocks (`announceMinedBlock` calls
  `announceBlock` directly without a compact path) nor for forwarded
  blocks (no hook in `validation.zig` to enter the compact announce
  pipeline).
- **`PartiallyDownloadedBlock` state persistence MISSING:** The
  reconstruction buffer (`txn_available`) is stack-allocated inside the
  `.cmpctblock` arm at `peer.zig:4749` and freed by `defer`
  (`peer.zig:4760`) before the arm returns. When `getblocktxn` is sent,
  there is no surviving partial-block; if the `blocktxn` response ever
  arrived (it doesn't get processed today — see above) we'd have
  nothing to fill into.
- **`vExtraTxnForCompact` extra-txn pool MISSING:** No ring buffer of
  recently-announced / evicted / orphan-pool txns to supplement the
  mempool during reconstruction. Reduces hit rate on
  recently-replaced txns.
- **IBD gate MISSING on receive:** `cmpctblock` handler does not call
  `PeerManager.isIBD()` (which exists at `peer.zig:6899` for other
  callers). During IBD, compact reconstruction is wasted work because
  the mempool is empty.
- **`LoadingBlocks` gate MISSING on both `cmpctblock` and `blocktxn`:**
  Core gates both handlers explicitly (net_processing.cpp:4469, 4717:
  `if (m_chainman.m_blockman.LoadingBlocks()) return`). clearbit has no
  reindex/loading flag at all.

## Verdict table

| Verdict   | Gates | Notes |
|-----------|------:|-------|
| PRESENT   | 13    | constants, decoders, version gate, both depth guards, cmpctblock serve path, short-id mask, prefilled accumulation, collision detect, mempool match |
| PARTIAL   |  3    | reconstruction pipeline dead at tail, bip152_highbandwidth_from latched but never read at announce site, outbound sendcmpct present but unconditional |
| MISSING   | 14    | HB-peer announce push, HB-peer selection / lNodesAnnouncingHeaderAndIDs, NewPoWValidBlock signal, blocktxn serve, blocktxn receive, PartiallyDownloadedBlock persistence, vExtraTxnForCompact, IBD gate, LoadingBlocks gate, recent-block fast path, m_highest_fast_announce, via_compact_block punishment flag, MSG_CMPCT_BLOCK getdata-by-us, sendcmpct on inbound verack |

**Bug count: 17** (P0-CDIV=0 / P1=5 / P2=10 / P3=2).
No consensus-divergent bugs — every gap is **bandwidth efficiency** /
**relay performance** / **DoS hardening**. Clearbit nodes still relay
blocks correctly via `inv`/`headers` + full `MSG_WITNESS_BLOCK`
download, but pay 100%+ bandwidth overhead vs HB-compact peers (BIP-152
§Motivation: typical block ~1 MiB; cmpctblock ~12 KiB).

## 30 audit gates

Gate numbering is forward-only within W126 (cross-impl fleet-frozen for
the W126 wave only). G1-G6 are constants / version negotiation; G7-G15
cover receive side; G16-G22 cover announce side; G23-G30 cover ancillary
correctness (DoS, segwit, IBD, fast-paths).

### G1: `SHORTTXIDS_LENGTH = 6` bytes
**Status:** PRESENT.
clearbit `p2p.zig:418` — `short_ids: []const [6]u8`. Each short-id is
exactly 6 bytes, matching Core `blockencodings.h:103`.

### G2: `CMPCTBLOCKS_VERSION = 2` only — v1 rejected
**Status:** PRESENT.
clearbit `peer.zig:1537+5325` — both handshake and post-handshake
sendcmpct sites: `if (sc.version != 2) return;`. Mirrors Core
`net_processing.cpp:3907`. Version 1 (legacy non-segwit txid short IDs)
was removed in Core 0.18+ — clearbit correctly drops it.

### G3: SipHash-2-4 short-id key derivation
**Status:** PRESENT.
clearbit `peer.zig:4734-4745` constructs the 88-byte key buffer
(80-byte header + 8-byte LE nonce), single SHA256 yields k0/k1 from
the first 16 bytes LE u64. Mirrors Core `blockencodings.cpp:35-43`
`FillShortTxIDSelector`. The serve-side mirror at
`peer.zig:5149-5163` uses the same derivation.

### G4: 48-bit short-id mask `0x0000ffffffffffff`
**Status:** PRESENT.
clearbit `peer.zig:4883+5177` — `hasher.finalInt() & 0x0000ffffffffffff`.
Mirrors Core `blockencodings.cpp:49`. Upper 16 bits zeroed = 6-byte
short ID.

### G5: Wtxid (not txid) used for short IDs (BIP-152 v2 + BIP-339)
**Status:** PRESENT.
clearbit `peer.zig:4882+5174` — `hasher.update(&entry.wtxid)` on the
receive side, `crypto.computeWtxidStreaming(tx)` on the serve side.
Mirrors Core `blockencodings.cpp:31` `GetWitnessHash()`.

### G6: `sendcmpct` decoder + Peer state latch
**Status:** PRESENT.
clearbit `p2p.zig:886-890` decodes 1-byte announce + 8-byte LE u64
version. `Peer.bip152_provides_cmpctblocks` + `Peer.bip152_highbandwidth_from`
fields (`peer.zig:682+689`) latch on receive. Mirrors
Core `CNodeState::m_provides_cmpctblocks` +
`CNode::m_bip152_highbandwidth_from`.

### G7: `cmpctblock` decoder DoS guards
**Status:** PRESENT.
clearbit `p2p.zig:949-988` enforces:
- `short_id_count > 100_000` → InvalidData
  (Core `blockencodings.cpp:64` MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE_TX_WEIGHT).
- `short_id_count > 0xffff` → InvalidData (BlockTxCount uint16 cap).
- `prefilled_count > 100_000` / `> 0xffff` → InvalidData.
- `short_id_count + prefilled_count > 0xffff` → InvalidData
  (Core `blockencodings.h:125`).
- per-prefilled `delta > 0xffff` → InvalidData
  (Core `blockencodings.cpp:78`).

### G8: `PartiallyDownloadedBlock` state persisted across `getblocktxn` round-trip
**Status:** MISSING.
**BUG-1 (P2):** clearbit's `cmpctblock` arm allocates `txn_available`
on `self.allocator` then frees it via `defer` at `peer.zig:4760`
before returning. No equivalent of Core's
`QueuedBlock::partialBlock` (a persistent `PartiallyDownloadedBlock`
owned by `mapBlocksInFlight`). When clearbit sends `getblocktxn`
(`peer.zig:4935`), there is no surviving state to fill into.
Even after fixing G9 below (wiring the `blocktxn` handler), the
round-trip cannot complete without G8 persistence.
**Suggested fix:** add `PartiallyDownloadedBlock` struct to
`Peer` (or a `compact_block_in_flight: ?PartialState` field on
`PeerManager` keyed by block hash) — Core layout in
`net_processing.cpp:211` `QueuedBlock::partialBlock`.

### G9: `blocktxn` receive — completes reconstruction + submits to validation
**Status:** MISSING.
**BUG-2 (P2):** `peer.zig:4994-5004` `.blocktxn` arm is a no-op
(`"we shouldn't receive these. Ignore."`). No `ProcessCompactBlockTxns`
equivalent, no `FillBlock`, no submission to validation. Confirms
W112 BUG-6.

### G10: `FillBlock` + submit assembled block to validation pipeline
**Status:** MISSING.
**BUG-3 (P2):** even when reconstruction succeeds from mempool alone
(`missing_count == 0` at `peer.zig:4908-4910`), the success path is
literal comment-only: `"// TODO: assemble full block and pass to
validation"`. No `types.Block` is constructed from `txn_available`,
no call into `validation.zig` ConnectBlock / acceptBlock path. The
entire reconstruction pipeline is dead at the tail. Confirms W112
BUG-12. **Largest single dead-helper in BIP-152 subsystem.**

### G11: `getblocktxn` SERVE → `blocktxn` reply
**Status:** PARTIAL.
**BUG-4 (P1):** clearbit serves the depth>MAX_BLOCKTXN_DEPTH=10 case
(falls back to full block, `peer.zig:4967-4988`) but the in-depth
branch at `peer.zig:4990-4992` literally comments
`"we don't yet serve blocktxn responses (BUG-7, separate from BUG-8).
Ignore."` — peers asking us for recent compact-block fillers get
silence and time out. Confirms W112 BUG-7.

### G12: `vExtraTxnForCompact` extra-txn pool for reconstruction
**Status:** MISSING.
**BUG-5 (P2):** no extra-txn pool in `Peer` or `PeerManager`. The
mempool iterator at `peer.zig:4874-4900` is the only source of
candidate txns. Recently-evicted / orphan-pool / pre-announce txns
cannot match. Reduces hit rate, especially after a tx-replacement
or during mempool churn. Core layout:
`net_processing.cpp:997` `vExtraTxnForCompact` ring buffer,
size `DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100`. Confirms
W112 BUG-9.

### G13: IBD gate on incoming `cmpctblock`
**Status:** MISSING.
**BUG-6 (P2):** clearbit processes `cmpctblock` regardless of IBD
state. Core (`net_processing.cpp:4570`) skips the reconstruction
attempt when `!CanDirectFetch()` (IBD-true returns false). During
IBD the mempool is empty so reconstruction always fails →
falls back to full block via `getblocktxn` or full-block request.
Wasted CPU + bandwidth. `PeerManager.isIBD()` exists at
`peer.zig:6899` but is not called. Confirms W112 BUG-13.

### G14: `LoadingBlocks` gate on `cmpctblock` and `blocktxn`
**Status:** MISSING.
**BUG-7 (P3):** Core gates both handlers (`net_processing.cpp:4469`
and `:4717`) with `m_chainman.m_blockman.LoadingBlocks()` to avoid
mid-reindex churn. clearbit has no reindex/loading-blocks flag at
all (no `--reindex` per W124 G29). LOW priority because reindex is
not implemented, but the gate would be needed if reindex lands.

### G15: PoW preliminary check before `cmpctblock` reconstruction
**Status:** MISSING.
**BUG-8 (P2):** Core (`net_processing.cpp:4490-4494`) computes
`prev_block->nChainWork + GetBlockProof(cmpctblock.header)` and
discards low-work compact blocks before any reconstruction.
clearbit jumps straight into SipHash + slot fill. An attacker can
force expensive reconstruction work by sending many low-PoW
compact blocks with valid syntactic structure (DoS amplification).
Bound is the 100k short-id cap (G7) but the SHA256 + SipHash +
mempool-walk is still amplification-heavy.

### G16: `announceBlock` HB-compact branch
**Status:** MISSING.
**BUG-9 (P1):** `peer.zig:7134-7160` `announceBlock` — the body
sends `inv` or `headers` only. `bip152_highbandwidth_from` is
read **only** at the receive latch (`peer.zig:5327`); the announce
site does NOT branch on it. Even though the receive side correctly
records each peer's HB-from selection, we never act on it. Confirms
**W123 G12 BUG-12 (P0-CDIV in original framing; downgraded here
because the inv-fallback path is still consensus-correct, just
extremely inefficient).**
This is the **anchor finding** of W126 — every other gate in the
announce-side section (G17-G22) is downstream of G16.

### G17: `lNodesAnnouncingHeaderAndIDs` — HB-peer selection list
**Status:** MISSING.
**BUG-10 (P1):** no list of "peers we have selected to receive
compact blocks from". Core (`net_processing.cpp:987`) maintains an
LRU list with `<= 3` entries; on each valid block we receive from a
peer, `MaybeSetPeerAsAnnouncingHeaderAndIDs` adds that peer to the
back of the list and (if `size >= 3`) sends `sendcmpct(hb=false)`
to the front to evict it. The new HB peer gets `sendcmpct(hb=true)`.
clearbit never sends `sendcmpct(hb=true)` after handshake (only the
initial `hb=false` at `peer.zig:1623`) so no peer ever knows
clearbit wants HB blocks from them. clearbit also never receives
unsolicited cmpctblock from any peer. Confirms W112 BUG-3.

### G18: `MaybeSetPeerAsAnnouncingHeaderAndIDs` outbound preference
**Status:** MISSING.
**BUG-11 (P2):** even if G17 lands, Core has a specific rule
(`net_processing.cpp:1298-1308`) that an inbound HB candidate must
not evict the only outbound HB peer. Adversarial-inbound peers
otherwise replace honest outbounds. clearbit's missing list means
the rule has nothing to enforce on, but a future fix must
import this preference too.

### G19: `NewPoWValidBlock` signal → cmpctblock fast-announce
**Status:** MISSING.
**BUG-12 (P1):** Core (`net_processing.cpp:2103-2152`) fires
`NewPoWValidBlock` on each new tip with `m_highest_fast_announce`
monotonic, then for-each-peer where
`state.m_requested_hb_cmpctblocks && !PeerHasHeader(pindex) &&
PeerHasHeader(pindex->pprev)`, pushes an unsolicited `cmpctblock`.
clearbit has no equivalent — neither the signal nor the per-peer
gate. Even if G16 wires the branch on `bip152_highbandwidth_from`,
the per-peer state (peer-has-prev-header but not this-header) is
not tracked. **Two-pipeline:** without a NewPoWValidBlock event,
mined-block announce (rpc.zig `announceMinedBlock`) and tip-advance
announce (peer.zig downloader) are also missing the compact path.
Confirms W112 BUG-14.

### G20: `m_most_recent_block` / `m_most_recent_compact_block` cache
**Status:** MISSING.
**BUG-13 (P2):** Core (`net_processing.cpp:2127-2131`) caches the
most recent block + its `CBlockHeaderAndShortTxIDs` under
`m_most_recent_block_mutex`. The `GETBLOCKTXN` handler's fast path
(`net_processing.cpp:4256-4263`) checks
`if (m_most_recent_block_hash == req.blockhash) recent_block =
m_most_recent_block;` to serve without touching disk.
clearbit has `served_blocks` and `block_buffer` (general-purpose)
but no compact-specific cache and no fast-path check in the
getblocktxn handler. Disk hit on every getblocktxn for the tip
block (the common case).

### G21: `m_highest_fast_announce` monotonic guard
**Status:** MISSING.
**BUG-14 (P3):** Core gates `NewPoWValidBlock` with
`if (pindex->nHeight <= m_highest_fast_announce) return;`
(line 2109-2111) so we never compact-announce the same height
twice (e.g. on simultaneous tip races). Trivial to land alongside
G19. LOW priority because G19 itself is missing.

### G22: Initial outbound `sendcmpct(hb=false, v=2)` on handshake
**Status:** PARTIAL.
**BUG-15 (P2):** `peer.zig:1623` outbound handshake sends
`sendcmpct(announce=false, version=2)` to every peer.
- (a) The inbound-handshake path (`peer.zig:1557-1612`) does NOT
  send `sendcmpct` to inbound peers. Inbound peers therefore never
  know clearbit supports compact relay; they default to legacy
  inv-only.
- (b) There is no "fSentCmpctBlock" latch — if the handshake is
  re-entered (peer churn, reconnect) we may re-send. Core has
  `nodestate->fProvidesHeaderAndIDs` indirection.
Confirms W112 BUG-17.

### G23: PartiallyDownloadedBlock `InitData` null-header + both-empty guards
**Status:** PRESENT.
clearbit `peer.zig:4714-4727`:
- null-header → computes block hash, compares to `[_]u8{0} ** 32`,
  returns on match (mirrors Core `blockencodings.cpp:62`
  `cmpctblock.header.IsNull()`).
- both empty (no short IDs AND no prefilled) → return (mirrors
  Core `blockencodings.cpp:62`
  `cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()`).

### G24: Prefilled-tx differential index accumulation + gap check
**Status:** PRESENT.
clearbit `peer.zig:4767-4786`:
- `last_prefilled_index += delta + 1` (Core `blockencodings.cpp:77`).
- `last_prefilled_index > 0xffff` → reject (Core `:78`).
- `last_prefilled_index > short_ids.len + i` → reject
  (Core `:80-85` "tx at index greater than our full list").

### G25: Short-id duplicate-key + bucket-overflow DoS checks
**Status:** PRESENT.
clearbit `peer.zig:4810-4853`:
- duplicate short ID → `READ_STATUS_FAILED` fallback (Core
  `blockencodings.cpp:115-116`).
- bucket size > 12 → fallback (Core `:110-111`, P(>12) ≈ 10⁻⁶).
- clearbit approximates Core's `unordered_map::bucket_size` with
  a count keyed by `sid % 16384`; this is a reasonable Zig
  approximation (Core's bucket-count is implementation-defined).

### G26: Mempool wtxid match with second-match slot-clear
**Status:** PRESENT.
clearbit `peer.zig:4874-4900`:
- iterates mempool entries, computes wtxid short ID, looks up slot.
- if slot already filled by a previous mempool match, **clears**
  the slot (mirrors Core `:129-136` — two different mempool txns
  matching same short ID forces a getblocktxn request).
- early-exit at `mempool_hits == short_ids.len` (Core `:142-143`).

### G27: Reconstruction fallback policy — `getblocktxn` vs full block
**Status:** PARTIAL.
clearbit `peer.zig:4911-4942`:
- `miss_pct > 50%` → full-block via `getdata MSG_WITNESS_BLOCK`.
- `miss_pct <= 50%` → `getblocktxn` for missing indices.
**BUG-16 (P2):** the 50% threshold has no Core analog. Core
(`net_processing.cpp:4609-4633`) uses a more nuanced rule:
- if all missing → `fProcessBLOCKTXN = true` (zero-missing fast path).
- if first-in-flight → always send getblocktxn.
- else if HB-to peer with outbound-priority OR not last in-flight
  slot → getblocktxn.
- otherwise → give up and let other peers serve.
The 50%-cutoff is a clearbit policy invention; under partial-mempool
conditions (50.01% miss) we fall back to full block even though
getblocktxn would be cheaper. LOW efficiency impact, but mirroring
Core's rule would simplify reasoning about the fleet behaviour.

### G28: `MSG_CMPCT_BLOCK` getdata branch (we SERVE compact)
**Status:** PRESENT.
clearbit `peer.zig:5102-5232` MSG_CMPCT_BLOCK getdata handler:
depth ≤ 5 → builds CBlockHeaderAndShortTxIDs (coinbase prefilled +
non-coinbase wtxid short IDs) and serves; depth > 5 → full block;
not in cache → notfound. Matches Core `net_processing.cpp:2461-2476`.
**BUG-17 (P3):** the serve-side InvType `MSG_CMPCT_BLOCK = 4` is
recognized correctly in getdata but `peer.zig:4753`+4791+4858+4918
all use `msg_witness_block` (not `msg_cmpct_block`) for fallback
getdata that WE issue. So peers serving us compact blocks never
get a compact-block-typed getdata — they always serve full witness
blocks. Asymmetric: we can serve compact (depth ≤ 5) but we never
ask for compact. Confirms W112 BUG-18.

### G29: Via-compact-block punishment flag (BIP-152 §"MUST NOT ban" rule)
**Status:** MISSING.
**BUG-18 (P2):** Core (`net_processing.cpp:4505+:4682`) passes
`via_compact_block=true` to `MaybePunishNodeForBlock` /
`ProcessHeadersMessage` when a block originally arrived via cmpctblock,
so subsequent invalid-block discovery (e.g. mutation, bad witness
commitment) does NOT immediately ban the peer (BIP-152 §3:
"a node MUST NOT ban a node for sending a CMPCTBLOCK message
which would be processed under the legacy rules").
clearbit has no via_compact_block flag at all. When we wire G10
(submit reconstructed block to validation), a mutated block
discovered later would incorrectly trigger an immediate ban on
the relaying peer. Forward-regression hazard.

### G30: SipHash key construction is order-stable (header serialize matches Core)
**Status:** PRESENT.
clearbit's `peer.zig:4734-4745` constructs the 88-byte key buffer
inline (not via `serialize.writeBlockHeader`) — but the field order
and endianness match Core's `<<` operator stream:
version (i32 LE), prev_block (32B), merkle_root (32B), timestamp
(u32 LE), bits (u32 LE), nonce (u32 LE), nonce (u64 LE). Verified
against the serve-side mirror (`peer.zig:5149-5163`) using the same
layout, and against `serialize.zig:writeBlockHeader`. PASS pin.

---

## Bug summary by priority

| Bug   | Gate | Priority | Title                                                    |
|-------|------|----------|----------------------------------------------------------|
| BUG-1 | G8   | P2       | PartiallyDownloadedBlock state not persisted             |
| BUG-2 | G9   | P2       | `blocktxn` receive is no-op (round-trip incomplete)      |
| BUG-3 | G10  | P2       | `FillBlock`+validation submit dead (largest dead helper) |
| BUG-4 | G11  | P1       | `getblocktxn` SERVE no-op for depth ≤ 10                 |
| BUG-5 | G12  | P2       | `vExtraTxnForCompact` extra-txn pool absent              |
| BUG-6 | G13  | P2       | IBD gate missing on incoming cmpctblock                  |
| BUG-7 | G14  | P3       | LoadingBlocks gate missing (latent, post-reindex)        |
| BUG-8 | G15  | P2       | PoW preliminary check missing — DoS amplification        |
| BUG-9 | G16  | P1       | **`announceBlock` does not push cmpctblock to HB peers** |
| BUG-10| G17  | P1       | `lNodesAnnouncingHeaderAndIDs` HB-peer list absent       |
| BUG-11| G18  | P2       | Outbound HB preference (anti-inbound eviction) absent    |
| BUG-12| G19  | P1       | NewPoWValidBlock fast-announce signal absent             |
| BUG-13| G20  | P2       | `m_most_recent_block`/compact cache absent               |
| BUG-14| G21  | P3       | `m_highest_fast_announce` monotonic absent (gated on G19)|
| BUG-15| G22  | P2       | Initial sendcmpct missing on inbound + no re-send latch  |
| BUG-16| G27  | P2       | 50%-miss fallback policy diverges from Core              |
| BUG-17| G28  | P3       | `MSG_CMPCT_BLOCK` getdata never issued by us (asymmetric)|
| BUG-18| G29  | P2       | `via_compact_block` punishment flag absent (regression)  |

**Total: 17 BUGs (5×P1 / 10×P2 / 2×P3 / 0×P0-CDIV).**

## Cross-wave findings

### W123 G12 BUG-12 anchor confirmed
W123 listed `announceBlock does not push cmpctblock to HB peers` as
**P0-CDIV**. W126 confirms the gap exists exactly as described but
classifies it as **P1 (bandwidth efficiency)**, not P0-CDIV, because
the inv/headers fallback is consensus-correct — every peer can still
fetch the full block via getdata. The original P0-CDIV framing
referred to "compatibility with HB peers' expected announce behaviour";
strictly speaking BIP-152 does not REQUIRE HB-mode service, only that
the SENDCMPCT negotiation be respected. Promoting to P0-CDIV would
require evidence that an HB peer disconnects when it doesn't receive
compact announcements after selecting us as HB — Core does not.

### W112 vs W126 delta
W112 (FIX-43, FIX-42 era) audited the same subsystem and listed 18
bugs. Of those:
- BUG-1, BUG-2 → fixed by FIX-43 (version + state field).
- BUG-4, BUG-8 → fixed by FIX-42 (depth guards).
- BUG-3, BUG-5, BUG-6, BUG-7, BUG-9, BUG-10, BUG-11 (already valid),
  BUG-12, BUG-13, BUG-14, BUG-15, BUG-17, BUG-18 — still open and
  re-listed under W126 BUG-1..18 with updated gate numbers.
- BUG-16 (short-id mask) — was a PASS in W112 G3; W126 G4 confirms.

W126 adds 5 new gates not in W112:
- **G15** PoW preliminary (DoS amplification) — fleet-leading concern.
- **G18** outbound HB preference (BIP-152 §3 fairness).
- **G19** NewPoWValidBlock signal (announce-side anchor).
- **G20** recent-block fast path (perf).
- **G29** via_compact_block punishment flag (forward-regression).

### Meta-patterns
1. **dead-helper-at-call-site (34-wave streak preserved):** the
   reconstruction pipeline is the prototypical "well-engineered helper
   never wired" — SipHash, slot fill, prefilled accumulation, collision
   detection, mempool match, bucket-overflow DoS check, getblocktxn
   emission are ALL implemented correctly and idiomatically; the
   block is just never assembled (G10) and the response handler is a
   no-op (G9). Roughly 200 LOC of working machinery + 1 missing
   3-line `assembleBlock + chainstate.acceptBlock` call.
2. **comment-as-confession:** `peer.zig:4910`
   `// TODO: assemble full block and pass to validation`.
   `peer.zig:4992` `// we don't yet serve blocktxn responses
   (BUG-7, separate from BUG-8). Ignore.` `peer.zig:5003`
   `// Since we fall back to / full block download, we shouldn't
   receive these. Ignore.` Each is the developer documenting their
   own deferral.
3. **two-pipeline divergence:** mined-block announce
   (`rpc.zig:announceMinedBlock` → `peer.zig:announceBlock`)
   and IBD-block forwarding both bypass the compact path. Even when
   FIX wave for G16/G19 lands, both call sites must enter the same
   pipeline.
4. **receive-side latch read once, written never (the W126 anchor):**
   `bip152_highbandwidth_from` is set by the receive handler
   (`peer.zig:5327`) and never read by any code path. The field is
   a write-only sink — a textbook "well-engineered receive that
   informs no future action" pattern.

## Out of scope

- BIP-330 Erlay set reconciliation (audited W122; separate subsystem).
- BIP-339 `wtxidrelay` for tx-relay short IDs — only the
  block-encoding wtxid usage is in scope here (covered by G5).
- BIP-141 `MSG_WITNESS_FLAG` getdata flag handling — covered by
  W117 / FIX-37.
- Wire-level v2-transport carriage of `cmpctblock` / `blocktxn` —
  covered by W98 BIP-324 audit (see `tests_bip324_w98.zig:601-608`).
- Compact-block depth gating in pruning / NODE_NETWORK_LIMITED —
  block_buffer cache horizon already enforces; not duplicated here.

## Test file

`src/tests_w126_bip152_compact_blocks.zig` — 30 tests, XFAIL guards.
Tests assert the **current** observable state (including bugs), so a
future fix wave deliberately breaks each gate to flip MISSING/PARTIAL
→ PRESENT. Failures here mean someone already landed the fix and
forgot to update the audit.

## Pre-emptive next-wave handoff

**FIX-NN BIP-152 compact-block end-to-end activation** (suggested
single-impl fix wave): the bug set is unusually clustered. A single
~250-LOC patch can flip:
- G10 (assemble block + submit) — pulls G9 (blocktxn receive) and
  G8 (PartialState persistence) along with it.
- G16 (announceBlock HB branch) — pulls G19 (NewPoWValidBlock signal)
  along with it.
- G11 (getblocktxn serve) — independent, ~50 LOC.

Combined, this would close ~12 of the 17 W126 bugs in one wave.
The remaining 5 (G12, G15, G18, G27, G29) are policy / hardening
fixes that can land separately.
