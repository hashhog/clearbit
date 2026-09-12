# Stall class: 132 CRITICALs in 30 days

Diagnosed 2026-09-12T12:24Z from `fleet-monitor-history.jsonl`
(PLAN.md window ending 2026-09-10T02:30Z) and the live unit
`hashhog-clearbit-mainnet` (pid 73278, up since 2026-09-11 20:59
EDT). Log: `/data/nvme1/hashhog-mainnet/clearbit/restart.log` plus
rotated `restart.log.1`. **No fix in this commit** — there is not
yet an in-repo control that fails when the class is reverted.

## What "132 CRITICALs" counts

`tools/fleet-monitor.sh` writes every tick into the JSONL unthrottled
(`all_alerts`) and pages on a 1 h `{node, kind, level}` throttle
(`ALERT_THROTTLE_S=3600`). PLAN.md's "clearbit 132" (2026-09-10) is
the cited figure this queue item names. Recomputed with the same
method as ouroboros's 70 (1 h throttle on the `alerts` field):

| window | raw JSONL CRITICAL | 1 h throttle |
|---|---:|---:|
| 30 d to 2026-09-10T02:30Z | 891 | **90** (47 `tip_age`, 33 `rpc_fail`, 10 `no_progress`) |
| 2026-08-08 (class starts) → 2026-09-10 | — | **142** (71 `tip_age`, 61 `rpc_fail`, 10 `no_progress`) |

Zero CRITICAL `lag` (that gate is 500 blocks / 2 h). The node is not
falling hundreds of blocks behind; it **freezes a few to ~160 blocks
off tip for tens of minutes to a day**, or the process is gone and
RPC fails. PLAN's 132 sits between the strict-30d 90 and the
from-first-storm 142; the mechanism below does not depend on which
denominator you pick.

## The 30-day timeline is two modes, not one freeze

Same-tip, lag>0, status=OK episodes ≥20 min (36 of them, 57 h stuck)
plus RPC-down streaks (status≠OK, tip=None):

| start (UTC) | end | frozen tip | max lag | duration | notes |
|---|---|---:|---:|---:|---|
| 2026-08-08 … 08-09 | many 15–45 min | — | — | ~8 h down | RPC-fail storm; 28 of 33 throttled `rpc_fail` |
| 2026-08-16 11:49 | 08-17 12:00 | 962724 | 161 | **24.19 h** | 23 throttled `tip_age`; process up, not advancing |
| 2026-08-18 01:51 | 08-18 10:41 | — | — | **8.84 h** | RPC down, 103 consecutive fails |
| 2026-08-18 14:32 | 08-19 00:33 | — | — | **10.02 h** | RPC down, 121 consecutive fails |
| 2026-08-19 13:59 | 08-19 19:29 | — | — | **5.50 h** | RPC down |
| 2026-08-26 19:00 | 08-27 02:21 | 964181 | 51 | **7.34 h** | L3+L4 of 2026-08-26 (single-hash locator + empty `header_index`); pinned by `tests_reorg_p2p.zig`; **fixed**, not this class |
| 2026-09-06 18:12 … 09-07 15:44 | several | 965814–965944 | 4–11 | 0.4–1.75 h | 3 throttled `no_progress`; SIGKILL 2026-09-07 16:02Z |

The Aug 26 locator/index stall is already closed (`buildGetHeadersLocator`
walks the persisted chain and ends at genesis; `seedForkRootParent`
rehydrates the fork root after restart). What remains, and what the
live log is doing **right now at Core's tip**, is the class below.

## Live signature (this boot, at tip)

`getblockchaininfo`: `blocks == headers == 966675`,
`00000000000000000001d5116d712445`, `initialblockdownload false`,
chainwork reconstructed. Core `:8332` at the same hash. 8 outbound
peers, 0 inbound. `getpeerinfo` `synced_headers`/`synced_blocks` are
**0 for every peer** (see dead `updateBestKnownHeight` below).
`CLEARBIT_REORG=1`. RSS ~2.8 GiB. P2P is one thread
(`PeerManager.run`); RPC is a second thread.

This process's log + the previous rotation (`restart.log.1`, 526 MiB):

| line | this boot (`restart.log`) | previous (`restart.log.1`) |
|---|---:|---:|
| `REORG-CANDIDATE peer announces fork (2000 headers, prev=...0000)` | **881,092** | **6,153,597** |
| `0 headers but behind peers (ours=H+N, best_peer=P), retrying` | **323,709** | **1,055,915** |
| `best_peer=` values | 971349 / 971439 / 971534 | 969452 → 971349 |
| `DRAIN-BREAK-WEDGE` / `drain-wedge recovery` | 817 / 146 | 7061 / 900 |
| total lines | 1.28 M | 8.15 M |

`best_peer` is **~4.7–4.9k above the real chain**. Mainnet is 966675;
971349 is not a height any honest peer has. `ours=966674+87` means
`best_height + expected_blocks.items.len` (not remaining-unconnected).

`prev=...0000` is bytes `[30..32)` of `prev_block` — on mainnet every
block hash starts with zeros in display order, so that suffix is
uninformative. The 2000-header batches are classified
`competing_fork` (parent on the active chain or genesis) and then
refused as too deep. The log line fires **before** the refuse.

## Root cause

Near-tip **headers sync treats VERSION `start_height` as the network
tip**, so an empty `headers` reply (normal at tip) looks like "we are
behind", and a 2000-header genesis-rooted reply looks like "more fork
to fetch". The two form a positive-feedback loop on the single P2P
thread:

1. **`getBestPeerHeight` reads `Peer.start_height` (VERSION), not
   headers.** `peer.zig` 4815–4821. The 0-headers arm
   (5788–5793) retries iff
   `our_height + expected_blocks.items.len < best_peer_h`. The idle
   poll path (4728–4731) re-issues getheaders every 5 s to any peer
   whose VERSION height is above ours. `isIBD` (9894–9896) uses the
   same field, so P2P stays in the 10 ms IBD poll at tip.

2. **`updateBestKnownHeight` is dead code** (`peer.zig` 2393–2397;
   no call site in the tree). `getpeerinfo` reports that always-zero
   field as `synced_headers`/`synced_blocks` (`rpc.zig` ~6503). Core
   v31 dropped `startingheight`, so the liar VERSION height is
   invisible over RPC. The node already has the right slot and does
   not write it.

3. **The behind-check double-counts the header queue.** 5788 uses
   `expected_blocks.items.len`. Twenty lines later the fully-synced
   arm correctly uses `len - connect_cursor`. Compaction of
   `expected_blocks` only runs after `connect_cursor > 10000` (9781),
   so a normal at-tip boot (tens of headers) never compacts and the
   behind-check stays true even after those headers connect.

4. **Zero-headers retry has no backoff and skips block download.**
   On an empty batch that looks "behind", the handler
   `sendGetHeaders(alt_peer)` and `return`s (5791–5812). It never
   reaches `pipelineBlockRequests`. `pickSyncPeer` (4824–4828) is
   "first other peer with `start_height > 0`".

5. **A 2000-header `competing_fork` asks for more of itself.**
   `classifyHeaderBatch` (5164–5166) treats `prev == genesis_hash` as
   competing_fork. `buildGetHeadersLocator` correctly appends genesis
   (4876; that was the L3 fix). A peer that does not share our tip
   therefore answers from block 1 with 2000 headers. The competing_fork
   arm logs REORG-CANDIDATE, contextually-validates and
   `insertHeader`s every header, `maybeArmReorg` refuses the ~966k-deep
   fork — then **`if (h.headers.len >= 2000) sendGetHeaders(peer)`**
   (5966–5968) with the **same locator**. The peer sends the same 2000
   headers again. That is the 6.15 million-line rotation.

Contributing, not sufficient: P2P is one thread, so this ingest starves
`drainBlockBuffer` (the DRAIN-BREAK-WEDGE / drain-wedge lines). RPC is
a separate thread, so Mode B (`rpc_fail`) is the process actually
gone — SIGKILL on 2026-09-07, multi-hour downs on 2026-08-18/19, long
boots — not the header loop blocking `getblockchaininfo`. Both modes
feed the CRITICAL count; only Mode A is still live in the log at tip.

## What a fix control has to fail on

Not another watchdog and not a log-grep. A test that:

- connects two ready peers at a real tip — one with VERSION
  `start_height` thousands above any header it has announced (the
  971349 stand-in), one honest peer that replies empty `headers` —
  and asserts getheaders **stops** after the empty reply (no
  5 s VERSION pump, no immediate alt-peer retry);
- asserts the behind-check uses remaining queue
  (`len - connect_cursor`), not `len`;
- offers a 2000-header batch whose first `prev` is genesis (or any
  ancestor more than `reorgDepthCap` below tip) and asserts we do
  **not** `sendGetHeaders` for more of that fork;
- writes `best_known_height` from accepted headers (the dead
  `updateBestKnownHeight`) and uses **that** for "are we behind",
  matching Core's `pindexBestKnownBlock`.

Until that control exists and is red, do not land a scheduler /
classifier change. L3/L4 stay as the Aug 26 backstop; they do not
close this class.

## Instruments

- `/home/work/hashhog/fleet-monitor-history.jsonl`
- `/data/nvme1/hashhog-mainnet/clearbit/restart.log` (+ `.1`)
- RPC `:8356` `getblockchaininfo` / `getpeerinfo`
- `peer.zig` `getBestPeerHeight`, 0-headers arm, competing_fork 2000
  continue, `updateBestKnownHeight`
