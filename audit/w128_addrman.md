W128 — AddrMan + connman + peer selection audit (clearbit / Zig 0.13)
======================================================================

Wave: W128
Subsystem: AddrMan add/select/good/attempt/connected/terrible · ThreadOpenConnections ·
           outbound peer selection · AttemptToEvictConnection · BanMan · discouragement
Excludes: BIP-155 addrv2 wire (W117), AddrMan storage/bucketing structure (W104), ASMap
          health-check (W115). When a gate overlaps a prior wave's coverage it is noted.

References (Bitcoin Core):
- bitcoin-core/src/addrman.cpp + addrman.h + addrman_impl.h
- bitcoin-core/src/net.cpp (CConnman, ThreadOpenConnections, AttemptToEvictConnection,
  CreateNodeFromAcceptedSocket, CalculateKeyedNetGroup)
- bitcoin-core/src/net_processing.cpp (Misbehaving, MaybeDiscourageAndDisconnect)
- bitcoin-core/src/banman.cpp + banman.h
- bitcoin-core/src/node/eviction.cpp + eviction.h (SelectNodeToEvict,
  ProtectEvictionCandidatesByRatio, ProtectNoBanConnections, ProtectOutboundConnections)
- bitcoin-core/src/util/asmap.cpp + asmap.h

Likely clearbit paths:
- src/peer.zig (PeerManager, EvictionCandidate, selectPeerToConnect, maintainOutbound,
  acceptInbound, misbehaving, getNetGroup, anchors)
- src/banlist.zig (BanList)
- src/asmap.zig (asmap interpreter)


-------------------------------------------------------------------------------
Summary
-------------------------------------------------------------------------------

22 BUGS across 30 gates (PARTIAL or MISSING). 8 gates PASS. The chief defects
fall into five categories:

1. **ban/discourage conflation** (BUG-15, BUG-16, BUG-17, BUG-22).
   clearbit has NO distinct "discouragement" mechanism. `Peer.should_ban` is
   set both for cases Core would only `Discourage()` (misbehavior bloom-filter
   entry) and for cases Core would only `Disconnect` (local peers).
   `processAllMessages` then **bans for 24h** every peer with `should_ban`,
   converting every misbehaviour into a hard ban — the exact pattern the 2024
   `disclose-unbounded-banlist` advisory warned against. There is no rolling
   bloom filter of `m_discouraged`. RPC `setban` cannot distinguish ban vs
   discourage. Discouraged peers are NOT prioritised for eviction when an
   inbound slot is full (no `prefer_evict` field on Peer).

2. **AttemptToEvictConnection ordering & netgroup keying** (BUG-9, BUG-10,
   BUG-11, BUG-12). `selectEvictionCandidate` invents its own protection
   pipeline that does **not** match Core's `SelectNodeToEvict`:
   - clearbit's "netgroup protect 4 distinct groups" passes the FIRST 4
     groups in sorted-ascending order: Core's `EraseLastKElements` pops
     the LAST 4 (after sort), which produces a deterministic but different
     selection.
   - The block-relay-only protect order is wrong: clearbit treats `!relay_txs`
     as the predicate, Core uses `!m_relay_txs && fRelevantServices`.
   - No `ProtectNoBanConnections` ratio: `is_protected` is hand-set instead
     of derived from `Peer.no_ban`.
   - No `ProtectEvictionCandidatesByRatio`: the disadvantaged-network reserve
     (CJDNS / I2P / localhost / Onion) is entirely absent.
   - `nKeyedNetGroup` is not keyed by a per-node `nKey` randomizer: clearbit
     uses the raw `getNetGroup()` u32 (ASN or /16), making the netgroup ordering
     across nodes predictable and attackable.

3. **Selection algorithm divergence** (BUG-1, BUG-3, BUG-7, BUG-8, BUG-13,
   BUG-14). `selectPeerToConnect` is a single-pass min-attempts scan over
   `known_addresses`; it has none of the Core machinery:
   - No new/tried table split → no `Select(new_only=true)` for feelers
     (`ConnectionType.feeler` is dead infrastructure — never scheduled).
   - No `GetChance()` probabilistic weighting.
   - No `ResolveCollisions` / `SelectTriedCollision` (W104-overlap, re-tested
     here because eviction-time `Good()` calls Resolve in Core).
   - No `MAX_OUTBOUND_BLOCK_RELAY` (`block_relay` conn_type slot allocation):
     anchors briefly tag a peer `.block_relay` but `maintainOutbound` never
     creates new block-relay-only peers.
   - **No `MaybePickPreferredNetwork`** — even though `cjdnsreachable` is a
     PeerManager field, there is no logic to make extra outbound to under-
     represented networks.
   - **No `GetTryNewOutboundPeer` / stale-tip extra outbound**: clearbit
     has `evictStaleTipPeer` (kicks bad peer) but never opens an EXTRA
     full-relay slot to compensate (Core net_processing.cpp:5386).

4. **AddrMan Good/Attempt/Connected absence** (BUG-2, BUG-4, BUG-5, BUG-6).
   The triplet of state-update methods on Core's `CAddrMan`
   (Good / Attempt / Connected) does not exist as standalone callables.
   `selectPeerToConnect` increments `attempts` AND sets `last_tried`
   atomically — so a connection that bypasses selection (e.g. anchor reconnect
   in `connectToAnchors`, or a manual reconnect in `maintainManualConnections`)
   does not record the attempt. `Connected()` (which Core uses to refresh
   `nTime` on long-running connections every 20 minutes) is entirely absent
   so an in-progress outbound peer's `last_seen` decays toward `IsTerrible`.

5. **Banlist asymmetry & 24h hard ban** (BUG-19, BUG-21).
   Banlist persists; address book does NOT (already documented in W104).
   But a separate W128-specific issue: **all** misbehaviour produces a 24h
   ban that survives restart. Core's design intentionally uses a **rolling
   bloom filter** for `m_discouraged` so misbehaviour entries decay (50000-
   slot 0.000001-fpr filter), and only manually-issued `setban` produces a
   persistent ban. The 24h JSON ban list is incompatible with Core RPC
   `setban` semantics, which expects distinct ban / unban / listbanned
   behaviour for subnets, not just /32 IPv4 addresses.


-------------------------------------------------------------------------------
Gate matrix
-------------------------------------------------------------------------------

Legend:
  PASS    — behaviour matches Core well enough that misbehaviour is not
            possible from this surface.
  PARTIAL — primitive exists but is wired wrong / missing fields / wrong order.
  MISSING — primitive entirely absent.
  BUG-N   — catalogued below with priority.

| Gate | Area                                              | Status   | Bug     | Pri    |
|------|---------------------------------------------------|----------|---------|--------|
| G1   | AddrMan.Good() standalone API                     | MISSING  | BUG-1   | P1     |
| G2   | AddrMan.Attempt() standalone API                  | MISSING  | BUG-2   | P1     |
| G3   | AddrMan.Connected() refresh                       | MISSING  | BUG-3   | P1     |
| G4   | AddrInfo.IsTerrible() eviction (horizon, fails)   | MISSING  | BUG-4   | P1     |
| G5   | AddrInfo.GetChance() probabilistic weight         | MISSING  | BUG-5   | P1     |
| G6   | Per-node nKey randomizer (eclipse resist)         | MISSING  | BUG-6   | P0     |
| G7   | Cryptographic source-group + ASN bucketing        | PARTIAL  | BUG-7   | P0     |
| G8   | ThreadOpenConnections loop architecture           | PARTIAL  | BUG-8   | P1     |
| G9   | AttemptToEvictConnection netgroup protect order   | PARTIAL  | BUG-9   | P0     |
| G10  | SelectNodeToEvict block-relay-only predicate      | PARTIAL  | BUG-10  | P1     |
| G11  | ProtectNoBanConnections derived from no_ban       | MISSING  | BUG-11  | P1     |
| G12  | ProtectEvictionCandidatesByRatio disadv. networks | MISSING  | BUG-12  | P1     |
| G13  | Feeler scheduling (FEELER_INTERVAL ~120s)         | MISSING  | BUG-13  | P1     |
| G14  | MaybePickPreferredNetwork extra-network slot      | MISSING  | BUG-14  | P2     |
| G15  | BanMan.Discourage() distinct from Ban()           | MISSING  | BUG-15  | P0     |
| G16  | Rolling bloom filter for discouragement           | MISSING  | BUG-16  | P0     |
| G17  | Peer.prefer_evict / m_prefer_evict flag           | MISSING  | BUG-17  | P1     |
| G18  | CalculateKeyedNetGroup with RANDOMIZER_ID_NETGROUP| MISSING  | BUG-18  | P1     |
| G19  | BanMan subnet (CSubNet) banning                   | MISSING  | BUG-19  | P1     |
| G20  | Outbound IPv4/IPv6 distinct netgroup at select    | PASS     |         |        |
| G21  | DEFAULT_MISBEHAVING_BANTIME=24h vs discouragement | PARTIAL  | BUG-21  | P1     |
| G22  | should_ban → 24h ban (Core: discourage only)      | PARTIAL  | BUG-22  | P0     |
| G23  | GetTryNewOutboundPeer stale-tip extra outbound    | MISSING  | BUG-23  | P1     |
| G24  | next_extra_block_relay timer                      | MISSING  | BUG-24  | P2     |
| G25  | MAX_OUTBOUND_FULL_RELAY=8 vs MAX_BLOCK_RELAY=2    | PASS     |         |        |
| G26  | Anchors saved on shutdown (2 block-relay)         | PASS     |         |        |
| G27  | DiscourageAndDisconnect on misbehaviour           | PARTIAL  | BUG-27  | P1     |
| G28  | Inbound: drop discouraged peer if (almost) full   | MISSING  | BUG-28  | P1     |
| G29  | DUMP_BANS_INTERVAL=15min periodic flush           | MISSING  | BUG-29  | P2     |
| G30  | ResolveCollisions called at top of feeler loop    | MISSING  | BUG-30  | P1     |


-------------------------------------------------------------------------------
Bug catalogue
-------------------------------------------------------------------------------

### BUG-1 — `AddrMan.Good()` standalone API missing (P1)

`selectPeerToConnect` writes `info.success = true` AFTER a successful
`connectOutboundNegotiated` (peer.zig:3496-3499), but there is no
`markAddressGood(addr, time)` callable that the rest of the code can use.
Core ref: addrman.h:150 `Good(const CService& addr, NodeSeconds time)`.

Consequence: `connectToAnchors` (peer.zig:3405-3430) connects to an anchor
peer but never updates `known_addresses[anchor].success` so on next restart
the anchor entry's `success` is still false and the address ages out via
the regular path.

Repro target: gate G1.


### BUG-2 — `AddrMan.Attempt()` standalone API missing (P1)

Attempt-counting is welded into `selectPeerToConnect` (`info_ptr.last_tried = now;
info_ptr.attempts += 1;` at peer.zig:3122-3125). Any code path that opens a
connection **bypassing** selection — manual reconnect (maintainManualConnections,
peer.zig:3287), anchor reconnect (connectToAnchors), `tryConnectNode` (onetry RPC)
— never increments `attempts`, so failed manual connections do not register and
the `IsTerrible` check (BUG-4) cannot fire for repeatedly-failing manual targets.

Core ref: addrman.h:127 `Attempt(const CService& addr, bool fCountFailure, NodeSeconds time)`.

Repro target: gate G2.


### BUG-3 — `AddrMan.Connected()` refresh missing (P1)

Core refreshes `info.nTime = max(info.nTime, time - 20*60)` once every 20
minutes for a live connection. This keeps long-lived peers from aging into
the IsTerrible horizon. clearbit's `known_addresses[..].last_seen` is set
once on `addAddress` and once on outbound-connect, never refreshed during
the connection. A 30-day-stable outbound peer would still be "stale" by
clearbit's bookkeeping (though clearbit has no IsTerrible to act on it —
see BUG-4).

Core ref: addrman.h:220 `Connected(const CService& addr, NodeSeconds time)`.

Repro target: gate G3.


### BUG-4 — `IsTerrible` eviction missing (P1)

Five conditions in `AddrInfo::IsTerrible()` (addrman.cpp:49-72):
- entry from the future (>10 min ahead)
- not seen in 30 days (ADDRMAN_HORIZON)
- zero successes after 3 attempts (ADDRMAN_RETRIES)
- 10 successive failures in 7 days (ADDRMAN_MAX_FAILURES)
- entry tried <1 min ago is exempt

None of these checks exist on `AddressInfo`. `known_addresses` grows
without bound, holding entries that Core would have purged. Combined
with the lack of bucket-size caps (W104 BUG: G11), an addr-flood from a
single peer is unbounded.

Repro target: gate G4. (Overlap with W104 G8; re-tested at the eviction-
on-failure call site, which W104 did not exercise.)


### BUG-5 — `GetChance()` probabilistic selection missing (P1)

`selectPeerToConnect` picks the candidate with the **minimum** `attempts`.
Core's `Select()` instead samples random buckets with probability
`fChance = pow(0.66, min(nAttempts, 8)) * (now - m_last_try < 10min ? 0.01 : 1)`.

The clearbit deterministic min-attempts scan is predictable: an attacker
who can inject one fresh address (`attempts == 0`) is guaranteed to be
picked next, even if `1024 * 64 = 65536` Core-quality candidates exist.

Repro target: gate G5. (Overlap with W104 G9; re-tested to surface the
selection-time consequence in conjunction with BUG-13.)


### BUG-6 — Per-node `nKey` randomizer absent (P0)

clearbit's `PeerManager` has no `nKey: [32]u8` randomizer. All keyed
hashing (bucket positions, netgroup keying) uses raw address bytes via
the XOR-folded `addressKey`. An adversary precomputes which addresses
collide and forces clearbit into a small bucket. Core generates `nKey`
randomly at startup and persists it in peers.dat so a single restart
does not reset the bucketing.

Core ref: addrman_impl.h:163 `uint256 nKey;`
         net.cpp:4144-4148  `CalculateKeyedNetGroup` uses
                            `RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036`.

Repro target: gate G6. (Overlap with W104 G7/G20; re-tested for the eviction
& netgroup-diversity-at-select consequence.)


### BUG-7 — Cryptographic source-group + ASN bucketing missing (P0)

Core's `AddrInfo::GetNewBucket(nKey, src, netgroupman)` keys the new-table
bucket by SOURCE address group AND TARGET address group, mixed under nKey:

    hash1 = (nKey << netgroupman.GetGroup(*this) << vchSourceGroupKey).GetCheapHash()
    hash2 = (nKey << vchSourceGroupKey << (hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP))
            .GetCheapHash()
    return hash2 % ADDRMAN_NEW_BUCKET_COUNT

clearbit has none of this: `known_addresses` is a flat AutoHashMap keyed by
the XOR-folded `addressKey`. ASN is computed (asmap.zig works) but used
only for outbound-diversity at *select* time (peer.zig:3441-3444), never
for partitioning the storage table.

Consequence: a single peer with one /16 (or one ASN) can fill 100% of
clearbit's "buckets" because there ARE no buckets — there is only the map.
W104 BUG: G23 documented the lack of `ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP=64`
cap; this gate re-tests at the hashing-key layer.

Repro target: gate G7.


### BUG-8 — `ThreadOpenConnections` loop architecture missing (P1)

`maintainOutbound` (peer.zig:3471-3516) is a *per-tick* function that runs
once per peer-loop iteration. Core's `ThreadOpenConnections` is a
dedicated thread with its own sleep timers (500ms grant wait, addrman
ResolveCollisions, ProcessAddrFetch, 100-tries-per-addrman call). clearbit
has no equivalent of:
- next_feeler timer (FEELER_INTERVAL=2min)
- next_extra_block_relay timer (EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min)
- next_extra_network_peer timer (EXTRA_NETWORK_PEER_INTERVAL=5min)
- 60s startup grace before adding fixed seeds (clearbit has no fixed seeds)
- 100-try inner loop with skip on (current_time - last_try < 10min && tries < 30)

The clearbit equivalent picks ONE address per tick and may bind it to
ANY conn type only at the call site (anchor/manual/outbound).

Repro target: gate G8.


### BUG-9 — `AttemptToEvictConnection` netgroup protect order (P0)

`selectEvictionCandidate` (peer.zig:2118-2243) sorts ascending by
`net_group` then iterates FORWARD protecting the first 4 unique netgroups.
Core's `EraseLastKElements(vEvictionCandidates, CompareNetGroupKeyed, 4)`
sorts ascending and erases the LAST 4 (highest netgroup values).

Both pick 4 unique netgroups; clearbit picks the LOWEST-keyed 4 vs
Core's HIGHEST-keyed 4. Since both are seeded by a deterministic key
visible to an attacker (clearbit's raw ASN/u16 vs Core's nKey-keyed
hash), the attacker can craft addresses that LAND in the unprotected
half by choosing a sort-direction-specific bucket.

Repro target: gate G9.


### BUG-10 — block-relay-only predicate wrong (P1)

clearbit (peer.zig:2156-2165):
    if (!c.relay_txs) protect[i] = true;

Core (eviction.cpp:196):
    EraseLastKElements(..., CompareNodeBlockRelayOnlyTime, 8,
        [](const NodeEvictionCandidate& n) {
            return !n.m_relay_txs && n.fRelevantServices;
        });

clearbit protects every block-relay-only peer up to 8; Core protects only
those that ALSO have all relevant services (NODE_NETWORK, NODE_WITNESS,
NODE_NETWORK_LIMITED, NODE_COMPACT_FILTERS as enabled). A peer with
`relay_txs=false` AND `services=NODE_NONE` (e.g. a misbehaving SPV that
disabled tx relay to dodge protection) gets incorrectly protected by
clearbit.

Repro target: gate G10.


### BUG-11 — `ProtectNoBanConnections` not derived from no_ban (P1)

Core's `SelectNodeToEvict` calls `ProtectNoBanConnections` FIRST
(eviction.cpp:182), which removes any candidate with `m_noban=true`
from the list entirely. clearbit's `is_protected` field is a
manually-set bool on `EvictionCandidate`, never set from `Peer.no_ban`.

Result: a peer with `no_ban=true` is exempt from `misbehaving()` (verified
W99/G2) but NOT exempt from inbound-eviction; if 117 inbound slots are
full and a new connection arrives, the no_ban peer can be evicted.

Repro target: gate G11.


### BUG-12 — `ProtectEvictionCandidatesByRatio` missing (P1)

Core protects up to 50% of remaining candidates by uptime, reserving up
to 25% for **disadvantaged networks** (CJDNS, I2P, localhost, Onion).
clearbit's protect-by-time step (peer.zig:2173-2189) protects half the
remaining peers but has no network-class awareness — Tor/I2P inbound
peers compete with IPv4 on raw uptime alone.

Consequence: clearbit running on Tor + IPv4 will gradually evict its
Tor peers under load even though Core would explicitly reserve slots
for them.

Repro target: gate G12.


### BUG-13 — Feeler scheduling missing (P1)

`ConnectionType.feeler` is defined (peer.zig:548) and `PeerManager` has
no logic to:
- track `next_feeler` as a wall-clock timer
- call `selectPeerToConnect(new_only=true)` for the feeler (since clearbit
  has no new/tried table, there is no `new_only` parameter at all)
- close the connection immediately after a successful handshake (feelers
  are short-lived)
- move the successful address to the tried table (`MakeTried` — no tried
  table exists; cf. BUG-7).

`ConnectionType.feeler` is dead infrastructure.

Repro target: gate G13. (Overlap with W104 G14.)


### BUG-14 — `MaybePickPreferredNetwork` missing (P2)

Core (net.cpp:2514, 2757-2767) opens an extra full-relay slot to a
network that has zero outbound peers, after the regular 8 slots are filled.
This protects against full-bandwidth-network occupation by attackers.
clearbit's `cjdnsreachable` field exists (peer.zig:2441) but
`maintainOutbound` never queries the network of existing peers and never
opens an extra slot.

Repro target: gate G14.


### BUG-15 — `BanMan.Discourage()` distinct primitive missing (P0)

Core's BanMan API has two side-effecting verbs:
- `Ban(addr, ban_time_offset)` — persist to disk, deterministic lookup
- `Discourage(addr)` — insert into rolling bloom filter, probabilistic
  membership test, no disk persistence

clearbit's `BanList` has only `ban` / `unban` / `isBanned`. There is no
`discourage` primitive. `misbehaving()` sets `should_ban=true` and
`processAllMessages` then calls `self.banIP(addr, DEFAULT_BAN_DURATION,
"misbehavior threshold reached")` — a 24h deterministic ban.

Cf. banman.h:38-46 comment for why this distinction matters: the 2024
"disclose-unbounded-banlist" advisory describes how an attacker can
inflate the in-memory ban map by repeatedly misbehaving from different
addresses; the bloom-filter discouragement set is bounded at 50000
entries (banman.h:98).

Repro target: gate G15.


### BUG-16 — Rolling bloom filter for discouragement missing (P0)

Direct consequence of BUG-15. Core: `CRollingBloomFilter m_discouraged
{50000, 0.000001}` (banman.h:98). clearbit: nothing. The misbehaviour
set is unbounded in memory (one `BanEntry` per misbehaving IP, including
the duplicated `reason` string allocation per entry — see banlist.zig:96).

A misbehaviour-flood from 1M unique IPs over 24h would consume
~1M * (8+8+8+reason_len) ≈ tens of MB of resident memory in clearbit;
Core caps at 50000 bloom slots ≈ 350 KiB regardless.

Repro target: gate G16.


### BUG-17 — `Peer.prefer_evict` flag missing (P1)

Core's `NodeEvictionCandidate::prefer_evict` is set by `BanMan::IsDiscouraged`
at accept time (net.cpp:1814: `bool discouraged = m_banman->IsDiscouraged(addr)`)
and surfaces in `SelectNodeToEvict`'s late-stage prefer-evict filter
(eviction.cpp:212-215). clearbit's `Peer` has no equivalent. Even if BUG-16
were fixed, the eviction algorithm would not consult it.

Repro target: gate G17.


### BUG-18 — `CalculateKeyedNetGroup` not keyed by nKey (P1)

Direct dependency on BUG-6. `EvictionCandidate.net_group` is the raw
`netGroup(address)` u32 (peer.zig:2071 → 419: first two octets of IPv4).
Core's `CConnman::CalculateKeyedNetGroup` runs
`GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(vchNetGroup).Finalize()`
so the netgroup map ordering is per-node-secret.

Attacker who knows clearbit's lack-of-keying can compute exactly which /16
groups it will protect (BUG-9 — first 4 in ascending order) and avoid
those /16s.

Repro target: gate G18.


### BUG-19 — Subnet (CSubNet) banning missing (P1)

Core's BanMan accepts both `CNetAddr` and `CSubNet` (banman.cpp:130-154).
RPC `setban "192.168.0.0/16" add` ban-by-subnet works against Core.
clearbit's `BanList.ban` accepts only `ip: [4]u8` — single host, IPv4 only.
`banAddress` silently drops IPv6 ban requests (banlist.zig:109-113: the
`if (addressToIpv4(address))` branch).

A subnet RPC ban call would either fail at parse time (no subnet syntax
support) or be silently no-op'd.

Repro target: gate G19.


### BUG-21 — DEFAULT_MISBEHAVING_BANTIME = 24h but should not ban at all (P1)

clearbit (peer.zig:299): `DEFAULT_BAN_DURATION: i64 = 24 * 60 * 60`.
This matches Core's `DEFAULT_MISBEHAVING_BANTIME = 60 * 60 * 24`.
The duration is right; the **policy of applying it to misbehaviour at
all** is wrong (cf. BUG-15: Core uses `Discourage`, not `Ban`, for
misbehaviour).

Repro target: gate G21.


### BUG-22 — `should_ban` → 24h hard ban at processAllMessages (P0)

`processAllMessages` (peer.zig:3593-3605) iterates peers, and for any
`should_ban==true`, calls:

    self.banIP(peer_obj.address, DEFAULT_BAN_DURATION, "misbehavior threshold reached")

This is the bug surface — `should_ban` is set by `misbehaving()` for
EVERY non-noban/non-manual/non-local peer, and processAllMessages
INSTANTLY commits a 24h JSON ban list entry. The supposed parity with
Core (peer.zig:1879-1881: "single-event discourage") is misnamed:
clearbit performs a single-event **BAN**, not a discouragement.

Repro target: gate G22.


### BUG-23 — `GetTryNewOutboundPeer` stale-tip extra outbound missing (P1)

Core (net_processing.cpp:5380-5390): when our tip is stale for
STALE_CHECK_INTERVAL, `SetTryNewOutboundPeer(true)` opens ONE extra
full-relay slot to attempt to find a new better source. clearbit's
`evictStaleTipPeer` (peer.zig:5984-6021) DISCONNECTS the stalest peer
but does not open an extra slot; the loop simply waits for the next
`maintainOutbound` tick to back-fill.

In practice this works at small scale; under attack (all peers slow but
none stale enough to evict), Core would open an extra outbound and a
faster peer's headers would arrive sooner.

Repro target: gate G23.


### BUG-24 — `next_extra_block_relay` timer missing (P2)

Core (net.cpp:2729-2752): periodically opens an extra block-relay-only
connection (every ~5 min, exponential jitter) and promotes the newest
to anchor if it delivers a block first. clearbit has zero scheduled
block-relay-only-only connection logic; only the 2 anchors loaded at
startup go through `.block_relay`.

Repro target: gate G24.


### BUG-27 — `MaybeDiscourageAndDisconnect` flow conflated (P1)

Core: misbehaviour increments `peer.m_should_discourage`; the per-tick
`MaybeDiscourageAndDisconnect` (net_processing.cpp:5083) reads it and
either (a) calls `banman->Discourage(addr)` then disconnects, or (b)
just disconnects when local. clearbit short-circuits this into the
`misbehaving` function directly setting `should_ban` AND issuing the
disconnect. Net effect (BUG-22) is wrong; this gate tests the missing
intermediate hand-off.

Repro target: gate G27.


### BUG-28 — Inbound: drop discouraged peer when (almost) full missing (P1)

Core (net.cpp:1813-1818):
    bool discouraged = m_banman && m_banman->IsDiscouraged(addr);
    if (!NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan)
        && nInbound + 1 >= m_max_inbound && discouraged) {
        LogDebug(BCLog::NET, "connection from %s dropped (discouraged)\n", ...);
        return;
    }

clearbit's `acceptInbound` (peer.zig:3540-3544) drops if the address is
**banned** (24h deterministic ban) but does not consult any
discouragement set — because there is no discouragement set (BUG-15).
At 116/117 inbound a discouraged peer (in Core) is rejected; in clearbit,
because the same peer is BANNED, it is rejected for a different reason
24h-deterministic-lookup vs probabilistic-membership). Inbound flood
behaviour diverges accordingly.

Repro target: gate G28.


### BUG-29 — DUMP_BANS_INTERVAL = 15min periodic flush missing (P2)

Core (banman.h:23): `static constexpr std::chrono::minutes DUMP_BANS_INTERVAL{15}`.
The wallet/scheduler periodically calls `DumpBanlist()` (banman.cpp:48).
clearbit's `BanList` flushes on `save()` only when `is_dirty=true`
(banlist.zig:206-207), but the call site is only at deinit time
(peer.zig:2495: `self.ban_list.save() catch {}`). A crash between
banning and shutdown loses the ban entry.

Repro target: gate G29.


### BUG-30 — `ResolveCollisions` at top of feeler loop missing (P1)

Core (net.cpp:2773): `addrman.get().ResolveCollisions();` is called at
the top of every ThreadOpenConnections iteration BEFORE selecting an
address, to resolve any test-before-evict collisions from the prior
feeler. clearbit has no collision set (BUG-7 / no tried table) and no
equivalent call. Symptom: a never-confirmed feeler would loop in Core
but is impossible to express in clearbit.

Repro target: gate G30. (Overlap with W104 G15.)


-------------------------------------------------------------------------------
Notable patterns observed
-------------------------------------------------------------------------------

1. **Comment-as-confession**: peer.zig:1879-1881 claims "single-event
   discourage" matching Core's PR #25974 — but the code at peer.zig:3598-3599
   commits a 24h **ban**, not a discouragement. The discouragement
   comment is correctly aware of the intended behaviour; the implementation
   is not. This is exactly the pattern called out in MEMORY: "test-comment-
   as-confession" — accept what the comment admits even when the assertion
   diverges.

2. **Dead-helper-at-call-site**: `ConnectionType.feeler` exists in the
   enum (peer.zig:548) but is never set by any code path. The Core
   feeler-scheduling state machine is entirely absent.

3. **Well-engineered helper never wired**: `EvictionCandidate` and
   `selectEvictionCandidate` (peer.zig:2047-2243) are a careful, working
   implementation of the eviction algorithm — and they are called
   precisely ONCE (peer.zig:3555-3564) from `acceptInbound` when the
   slot is full. They are NOT exposed as a public API for testing,
   and the misbehaviour path bypasses them entirely (BUG-22 commits a
   ban directly).

4. **W104 overlap acknowledged**: W104 G8/G9/G14/G15/G23 all touch
   bucketing/feeler. This wave re-tests at the *eviction*, *select*,
   and *peer-selection* call sites which W104 audited the
   *storage/addAddress* call site of. No double-counting in the bug
   total — gates G4/G5/G6/G7/G13/G30 explicitly call out W104 overlap.

5. **clearbit ahead of Core in one respect**: ASMap is loaded at the
   PeerManager level (peer.zig:2414 `asmap_data: ?[]u8`) and used for
   netgroup keying at outbound-select time (peer.zig:3441-3444). This is
   correct and is the basis for gate G20 PASSing. The bucketing of
   `known_addresses` does not benefit (BUG-7), but the diversity
   enforcement at select time does.


-------------------------------------------------------------------------------
Test design
-------------------------------------------------------------------------------

30 tests in `src/tests_w128_addrman.zig`, wired to `test-w128` step in
`build.zig`. Each test exercises one gate from the matrix:

- G1-G5: assert presence/absence of `markAddressGood`, `markAttempt`,
         `Connected`, `IsTerrible`, `GetChance` on `PeerManager` /
         `AddressInfo`.
- G6-G7: assert no `nKey: [32]u8` field; no `getNewBucket`/`getTriedBucket`
         pure functions.
- G8: assert no `ThreadOpenConnections` daemon thread function; no
       FEELER_INTERVAL / EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL constants.
- G9-G12: drive `buildEvictionCandidates` + `selectEvictionCandidate`
          with synthetic peer arrays; assert the divergent selection.
- G13: assert ConnectionType.feeler exists but no scheduler.
- G14: assert no `maybePickPreferredNetwork` and no per-network outbound count.
- G15-G19: introspect `BanList` for `discourage`/`isDiscouraged`/subnet
           support.
- G21-G22: drive `misbehaving()` and observe ban-list size grows by 1
           (proves BUG-22).
- G23-G24: assert no `setTryNewOutboundPeer` / no
           `next_extra_block_relay`.
- G27-G30: behavioural / structural assertions tied to the conflated
           ban+discourage path.

All tests are PURE assertions over the public API surface — they do not
touch the network, do not spawn peers, do not touch a real datadir.

For the build.zig wire-in, only **one** new `test-w128` step is added,
matching the existing pattern for W104/W122 etc. and following the
parallel-agent coordination protocol (no other build.zig edits).
