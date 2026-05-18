# W141 — ZMQ + REST + notification scripts audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's ZMQ publisher (`src/zmq.zig`), REST endpoint set
(folded inside `src/rpc.zig::handleRestRequest`), and notification-script
hooks (`-blocknotify`, `-alertnotify`, `-shutdownnotify`, `-startupnotify`,
`-walletnotify`) vs Bitcoin Core.
**Bitcoin Core references:**
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` (`SendZmqMessage`,
  `Initialize`, `Shutdown`, `NotifyBlock` / `NotifyTransaction` / sequence
  helpers; topic names `hashblock` / `hashtx` / `rawblock` / `rawtx` /
  `sequence`; sequence labels `'C' D R A'`)
- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp` (factory map,
  `UpdatedBlockTip` IBD short-circuit, `BlockConnected` per-tx Notify,
  `TransactionAddedToMempool` mempool sequence, `unix://` → `ipc://`
  rewrite at line 62-64, per-topic `hwm` knob at line 69)
- `bitcoin-core/src/zmq/zmqabstractnotifier.h`
  (`DEFAULT_ZMQ_SNDHWM = 1000`, `SetOutboundMessageHighWaterMark(sndhwm >= 0)`)
- `bitcoin-core/src/rest.cpp`
  (`ParseDataFormat` rfind('?'), `CheckWarmup`, `MAX_REST_HEADERS_RESULTS=2000`,
   `MAX_GETUTXOS_OUTPOINTS=15`, dispatch table at line 1141-1159 listing 14
   endpoint prefixes: `/rest/tx/`, `/rest/block/`, `/rest/block/notxdetails/`,
   `/rest/blockpart/`, `/rest/blockfilter/`, `/rest/blockfilterheaders/`,
   `/rest/chaininfo`, `/rest/mempool/`, `/rest/headers/`, `/rest/getutxos`,
   `/rest/deploymentinfo`, `/rest/blockhashbyheight/`, `/rest/spenttxouts/`;
   query-param `count` for `/rest/headers/<hash>?count=N`)
- `bitcoin-core/src/init.cpp`
  (`-blocknotify` block-tip hook at 2008-2018, `-shutdownnotify` at 255-265,
   `-startupnotify` at 737-745; the `block_notify` lambda gates on
   `sync_state == SynchronizationState::POST_INIT` — i.e. NOT during IBD)
- `bitcoin-core/src/node/kernel_notifications.cpp:30-47`
  (`AlertNotify`: `SanitizeString`, single-quote wrap, `ReplaceAll(strCmd, "%s", safeStatus)`)
- `bitcoin-core/src/wallet/init.cpp:75`, `bitcoin-core/src/wallet/wallet.cpp:1480`
  (`-walletnotify`: `%s` = txid, `%w` = wallet name, `%b` = blockhash or
  `unconfirmed`, `%h` = height or `-1`)
- `bitcoin-core/src/common/system.cpp` (`runCommand` → `::system`,
  `ShellEscape` quote-wrap with `'\"'\"'` escape sequence)

**BIPs:** none (this is operator-experience plumbing, not a wire-level
consensus subsystem).
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w141` (folded into `zig build test`).
**Implementation files audited:**
- `clearbit/src/zmq.zig` (349 LOC)
- `clearbit/src/rpc.zig` (REST: `handleRestRequest` @ 1793 and `restBlock` /
  `restTx` / `restHeaders` / `restBlockHashByHeight` / `restGetUtxos` /
  `restBlockFilter` / `restBlockFilterHeaders` @ 1944-2900)
- `clearbit/src/main.zig` (config parsing for `--zmqpub<topic>=` @ 361-376;
  no `--blocknotify` / `--alertnotify` / `--shutdownnotify` /
  `--startupnotify` / `--walletnotify` at all)
- `clearbit/src/sync.zig` (ZMQ block-connect hook @ 1860-1868)
- `clearbit/src/mempool.zig` (ZMQ mempool-add hook @ 1418-1427)

## Summary

clearbit ships a partial ZMQ publisher, a decent (but not Core-parity)
REST endpoint set, and **zero notification-script hooks**. The ZMQ wire
format matches Core for `hashblock` / `rawblock` / sequence-frame label
`'C'`, but the publisher is missing both **disconnect** (`'D'`) and
**mempool-removal** (`'R'`) sequence labels, ignores IBD, and skips
per-block-tx fan-out that Core's `BlockConnected` interface mandates.
REST is missing `/rest/deploymentinfo`, `/rest/spenttxouts/`, and
`/rest/blockpart/`, and the warmup short-circuit (Core
`CheckWarmup` at rest.cpp:171-177) is absent — clearbit serves REST
requests during init when chainstate isn't ready. Notification scripts
are entirely absent: no `-blocknotify`, `-alertnotify`, `-shutdownnotify`,
`-startupnotify`, or `-walletnotify`; `main.zig::Config` has no such
fields and there is no `runCommand` helper anywhere in `src/*.zig`. The
operator-experience gap here is identical to the W124 G11/G12/G13
findings, but this wave catalogues it at full bug granularity.

Key findings ranked by severity:

- **HIGH (operator-visible): `'D'` block-disconnect and `'R'` mempool-removal
  sequence labels are NOT published.** Core's `CZMQPublishSequenceNotifier`
  has four notify methods: `NotifyBlockConnect('C')`,
  `NotifyBlockDisconnect('D')`, `NotifyTransactionAcceptance('A')`,
  `NotifyTransactionRemoval('R')`. clearbit's `Notifier` only emits `'C'`
  and `'A'`. Subscribers tracking blockchain reorgs via the sequence
  topic (the canonical Core pattern) will silently miss every
  reorg/disconnection event. Subscribers tracking RBF / expiry /
  block-inclusion removals via `'R'` will likewise see only acceptances
  with no removal counterpart. See BUG-1 + BUG-2. (G1, G2.)
- **HIGH (consensus-relevant for downstream consumers): IBD is not
  gated.** Core's `UpdatedBlockTip` returns immediately when
  `fInitialDownload || pindexNew == pindexFork`
  (`zmqnotificationinterface.cpp:151-154`). clearbit's
  `sync.zig:1860-1868` fires `publishBlock` on EVERY connected block
  during IBD too. A subscriber wired to `hashblock` will receive ~900k
  notifications during a fresh sync — the wire-design contract is "tip
  changes after we're caught up". See BUG-3. (G3.)
- **HIGH: per-block-tx fan-out on `BlockConnected` is missing.** Core's
  `BlockConnected` (`zmqnotificationinterface.cpp:180-196`) fires
  `NotifyTransaction(tx)` for **every** tx in the connected block, then
  fires `NotifyBlockConnect`. clearbit fires only the block-level
  events; subscribers expecting per-tx `hashtx` / `rawtx` frames at
  block-connection time (e.g. for index-builders, wallets in light
  mode) will see them only at mempool-acceptance time and never for
  coinbase or for any tx that arrived in a block without first
  appearing in the mempool. See BUG-4. (G4.)
- **HIGH: `hashtx` / `rawtx` fired in mempool but never on
  reorg-disconnect.** Core also fires the same per-tx fan-out on
  `BlockDisconnected` (line 200-205). clearbit has no disconnect hook
  at all. See BUG-5. (G5.)
- **MED: `ZMQ_IPV6` set unconditionally.** Core probes
  `IsZMQAddressIPV6(address)` (`zmqpublishnotifier.cpp:82-93`) — calls
  `LookupHost` on the bracketless IP fragment of `tcp://<addr>:<port>`
  and only sets `ZMQ_IPV6 = 1` when the result is IPv6.
  clearbit (`zmq.zig:147`) sets `ZMQ_IPV6 = 1` for every socket
  unconditionally. OpenBSD documentation explicitly says this must NOT
  be enabled when the bind address isn't IPv6 (Core comment line 129);
  on Linux this is benign but the divergence is visible to anyone
  porting subscriber tooling. See BUG-6. (G6.)
- **MED: `ZMQ_LINGER` set at init, not at shutdown.** Core sets linger
  to 0 only inside `Shutdown` (`zmqpublishnotifier.cpp:185-186`). clearbit
  sets it during `bindSocket` (`zmq.zig:153-154`). Effect is functionally
  similar (pending messages drop on close either way), but the operator
  semantic differs: Core lets a socket stay open with default linger
  (infinite) during normal operation, and only forces 0 at orderly close;
  clearbit's sockets refuse to wait at any close — including a libzmq
  internal close on socket re-bind. See BUG-7. (G7.)
- **MED: Per-topic `hwm` knob missing.** Core accepts
  `-zmqpubhashblockhwm=<N>`, `-zmqpubrawtxhwm=<N>`, etc., via
  `gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM)` at
  `zmqnotificationinterface.cpp:69`. clearbit hardcodes `1000`
  (`zmq.zig:145`). Operators tuning back-pressure (e.g. a slow
  subscriber that should drop messages aggressively) have no knob.
  See BUG-8. (G8.)
- **MED: `unix://<path>` prefix rewrite missing.** Core rewrites
  `unix://` to `ipc://` at `zmqnotificationinterface.cpp:62-64` so
  operators can use the friendlier `unix://` prefix. clearbit's
  `bindSocket` would call `zmq_bind` directly on `unix://<path>`, which
  libzmq rejects (it only accepts `ipc://`). See BUG-9. (G9.)
- **MED: Address-reuse / shared-socket multimap missing.** Core's
  `mapPublishNotifiers` lets multiple notifiers (e.g. hashblock +
  rawblock) bind the **same** address; the second notifier reuses the
  socket. clearbit creates one socket per topic per address, so
  `--zmqpubhashblock=tcp://*:28332` and `--zmqpubrawblock=tcp://*:28332`
  would fail-on-bind for the second (EADDRINUSE). Operator-impacting
  but rare. See BUG-10. (G10.)
- **MED: `--zmqpub<topic>` is single-value; Core accepts a list (multimap).**
  Core's `gArgs.GetArgs(arg)` returns a `vector<string>` — operators
  can pass `-zmqpubhashblock=tcp://a -zmqpubhashblock=tcp://b` and get
  TWO sockets. clearbit's `Config.zmq_hashblock` is `?[]const u8` — a
  single value. See BUG-11. (G11.)
- **MED: Sequence frame for `'A'` always sends 8-byte mempool_sequence = 0.**
  Core's `SendSequenceMsg` makes mempool_sequence optional and emits
  33 vs 41 bytes accordingly (`zmqpublishnotifier.cpp:256-265`).
  clearbit always emits 41 bytes with `mempool_seq = 0`
  (`zmq.zig:268-275`). Subscribers reading the wire layout per the
  Core docs MAY interpret the trailing 8 zero bytes as "mempool
  sequence 0" rather than "no mempool sequence available" — Core's
  semantics is "tx with sequence-number 0 was just accepted". Since
  clearbit never increments a mempool sequence anywhere, every
  `'A'` event lies. See BUG-12. (G12.)
- **MED: Multipart `zmq_send` return code ignored — partial-message
  fragmentation possible.** clearbit's `sendMultipart` (`zmq.zig:210-216`)
  ignores the return value of all three `zmq_send` calls. Core
  (`zmq_send_multipart` at zmqpublishnotifier.cpp:62-69) checks each
  send, calls `zmq_msg_close` on failure, and returns -1. If
  `zmq_send` returns -1 on the first frame, clearbit still sends the
  second + third — subscribers receive a corrupt multipart message
  (frame 2/3 of a previous logical event, frame 1 of the next).
  See BUG-13. (G13.)
- **MED: SNDHWM is `c_int(1000)` but `setsockopt` errors are ignored.**
  Same shape as BUG-13: `zmq_setsockopt` return values are dropped
  (`zmq.zig:146-154`). Core checks each call and bails on failure
  (`zmqpublishnotifier.cpp:113-136`). See BUG-14. (G14.)
- **LOW: `zmq.zig` socket-leak path on `try self.sockets.append`
  failure.** `bindSocket` does
  `errdefer _ = c_api.zmq_close(sock)` at line 142, but the path that
  successfully binds and THEN fails on the final `append` (OOM) closes
  via errdefer but does NOT free `addr_z`. Minor leak. (See BUG-15. G15.)
- **REST HIGH: `CheckWarmup` short-circuit MISSING.** Core's REST
  handlers all start with `if (!CheckWarmup(req)) return false;` which
  returns HTTP 503 with "Service temporarily unavailable: ..." while
  RPC is in warmup (`rest.cpp:171-177`). clearbit's REST handlers
  begin executing immediately — they reach for `chain_state.utxo_set.db`
  which may be `null` during init and 500 on it rather than 503'ing
  with a clear message. See BUG-16. (G16.)
- **REST HIGH: `/rest/deploymentinfo` MISSING.** Core ships this since
  v24 (`rest.cpp:743-781`, dispatch entry line 1155-1156). clearbit's
  `handleRestRequest` doesn't recognize the prefix → 404. See BUG-17.
  (G17.)
- **REST HIGH: `/rest/spenttxouts/<hash>` MISSING.** Core ships this
  endpoint (`rest.cpp:313-381`, dispatch entry line 1158). It returns
  the per-block undo data so SPV-clients can replay reverse-block
  application without a full archival node. clearbit returns 404.
  See BUG-18. (G18.)
- **REST MED: `/rest/blockpart/<hash>/<start>/<end>` MISSING.** Core
  ships this as a range-served binary slice of a block
  (`rest.cpp:481-499`, dispatch entry line 1148). Useful for SPV / tail
  pruning. clearbit returns 404. See BUG-19. (G19.)
- **REST MED: `/rest/headers/<hash>?count=N` (new path) MISSING.**
  clearbit only handles the legacy `/rest/headers/<count>/<hash>` form
  (`rpc.zig:2144-2300`). Core accepts BOTH: legacy AND
  `/rest/headers/<hash>?count=N` (rest.cpp:191-205). clearbit strips
  the `?` portion via `indexOfScalar` (`rpc.zig:1796-1799`) which means
  a Core-compatible client using the new path gets the URL stripped of
  the query string, then parses `<hash>` as `<count>` and fails with
  "Invalid path: expected /rest/headers/<count>/<hash>.<ext>".
  See BUG-20. (G20.)
- **REST MED: `restBlockFilterHeaders` walks chain from genesis on
  every call.** clearbit's `rpc.zig:2750-2770` re-computes filter
  bytes for blocks `0..start_entry.height` per request even when the
  persistent BlockFilterIndex would have served the prev-header
  directly. Core's `rest_filter_header` uses
  `LookupFilterHeader(prev_block)` keyed off the index (rest.cpp:573-585),
  making the call O(count) instead of O(start_height + count).
  See BUG-21. (G21.)
- **REST LOW: `restBlock` JSON-vs-error discrimination by substring
  match.** clearbit's `rpc.zig:2044` does
  `std.mem.indexOf(u8, result, "\"error\":null") == null` to decide
  between 200 and 404. A returned JSON payload that legitimately
  contains the bytes `"error":null` (e.g. as a script-pubkey hex
  encoding or, more realistically, a nested error field in a deeper
  RPC result) would produce a false positive. See BUG-22. (G22.)
- **REST LOW: `restTx` same fragile-substring status discrimination.**
  `rpc.zig:2090`. See BUG-23. (G23.)
- **REST LOW: REST endpoint paths lack the trailing-slash variants of
  prefixes.** Core's table at rest.cpp:1141-1159 includes both
  `/rest/deploymentinfo/` AND `/rest/deploymentinfo` (entry 1155-1156)
  for forgiving operators. clearbit's prefix matching is strict.
  See BUG-24. (G24.)
- **NOTIFY HIGH: `-blocknotify=<cmd>` MISSING.** No `blocknotify` field
  on `Config`. No `runCommand` helper. (Also flagged at W124 G11.)
  See BUG-25. (G25.)
- **NOTIFY HIGH: `-alertnotify=<cmd>` MISSING.** No `alertnotify` field
  on `Config`. (Also W124 G12.) See BUG-26. (G26.)
- **NOTIFY HIGH: `-shutdownnotify=<cmd>` MISSING.** No `shutdownnotify`
  field on `Config`. (Also W124 G13.) See BUG-27. (G27.)
- **NOTIFY MED: `-startupnotify=<cmd>` MISSING.** Not in W124's gate
  set. clearbit has no `startupnotify` field on `Config` and no
  fire-and-detach helper in `main.zig` after the bind/listen
  successes. See BUG-28. (G28.)
- **NOTIFY MED: `-walletnotify=<cmd>` MISSING.** No `walletnotify`
  field on `Config`; `wallet.zig` has no `%s` / `%w` / `%b` / `%h`
  expansion. See BUG-29. (G29.)
- **NOTIFY HIGH (security): `ShellEscape` helper for alert sanitization
  MISSING.** Independent of whether `-alertnotify` is wired,
  the codebase has no `ShellEscape` or `SanitizeString` helper. When
  notify scripts ARE eventually added, the natural Zig idiom is to
  format `command` with the hash interpolated via `std.mem.replace`,
  but that path is a **command-injection sink** unless the caller
  sanitizes first. Core sanitizes alert messages with `SanitizeString`
  then single-quote-wraps them; the helper is non-trivial. See
  BUG-30 (forward-regression guard). (G30.)

**Universal patterns spotted:**

- **"test-comment-as-confession" risk**: the docstring at `zmq.zig:271-275`
  says "We don't track [mempool sequence]; emit zero for compatibility."
  That comment is the same shape as W122/W120/FIX-72/FIX-76's
  "test-comment-as-confession" pattern — a comment that documents a
  divergence as if it were a feature. The wire format makes this LOOK
  innocent but every `'A'` event lies to subscribers about the mempool
  ordering (Core's mempool_sequence is monotonic per-mempool,
  reset-to-zero only on restart, never zero in normal operation since
  it increments on every mempool change). Flagged as BUG-12.
- **"missing-disconnect-side" pattern**: same shape as W121's
  `cfheaders` orphan-fork handling and W120's `mempool_persist`
  asymmetry. clearbit consistently ships the connect/add side and
  forgets the disconnect/remove side. BUG-1 + BUG-2 + BUG-5 are three
  instances in a single wave.
- **"silently-ignored-error" pattern**: `zmq_send` / `zmq_setsockopt`
  return values dropped (BUG-13 + BUG-14). Same shape as multiple
  prior `Lwt.async`/fire-and-forget patterns; in this case, the
  consequence is a subscriber-visible corrupt-frame rather than a
  silent miss.
- **shell-injection sink**: not yet exploitable (BUG-25 / 26 / 27
  block any actual `system()` call), but the future-fix path is a
  classic injection vector. Recorded as BUG-30 forward-regression
  guard so a future FIX-* doesn't ship `-blocknotify` without
  sanitization.

**Cross-impl scope**: this audit is single-impl (clearbit). The
universal patterns (missing disconnect-side / silently-ignored-error /
shell-injection-sink) should be tracked at the meta-repo audit framework
level so other impls' W141-equivalent waves can short-circuit on the
same shapes.

## Gate table

| Gate | Subsystem | Bug | Severity | Status |
|------|-----------|-----|----------|--------|
| G1   | ZMQ      | BUG-1 missing `'D'` block-disconnect sequence | HIGH | XFAIL |
| G2   | ZMQ      | BUG-2 missing `'R'` mempool-removal sequence | HIGH | XFAIL |
| G3   | ZMQ      | BUG-3 IBD not gated for block-connect publish | HIGH | XFAIL |
| G4   | ZMQ      | BUG-4 per-block-tx fan-out missing on connect | HIGH | XFAIL |
| G5   | ZMQ      | BUG-5 disconnect hook absent entirely | HIGH | XFAIL |
| G6   | ZMQ      | BUG-6 `ZMQ_IPV6` set unconditionally | MED  | XFAIL |
| G7   | ZMQ      | BUG-7 `ZMQ_LINGER` set at init not shutdown | MED  | XFAIL |
| G8   | ZMQ      | BUG-8 per-topic `hwm` knob missing | MED  | XFAIL |
| G9   | ZMQ      | BUG-9 `unix://` → `ipc://` rewrite missing | MED  | XFAIL |
| G10  | ZMQ      | BUG-10 shared-socket multimap missing | MED  | XFAIL |
| G11  | ZMQ      | BUG-11 single-value vs Core's multi-value list | MED  | XFAIL |
| G12  | ZMQ      | BUG-12 sequence frame `'A'` mempool_seq lies (test-comment-as-confession) | MED | XFAIL |
| G13  | ZMQ      | BUG-13 multipart `zmq_send` return ignored | MED  | XFAIL |
| G14  | ZMQ      | BUG-14 `zmq_setsockopt` return ignored | MED  | XFAIL |
| G15  | ZMQ      | BUG-15 socket-leak / addr_z leak on append failure | LOW  | XFAIL |
| G16  | REST     | BUG-16 `CheckWarmup` short-circuit missing | HIGH | XFAIL |
| G17  | REST     | BUG-17 `/rest/deploymentinfo` missing | HIGH | XFAIL |
| G18  | REST     | BUG-18 `/rest/spenttxouts/<hash>` missing | HIGH | XFAIL |
| G19  | REST     | BUG-19 `/rest/blockpart/...` missing | MED  | XFAIL |
| G20  | REST     | BUG-20 `/rest/headers/<hash>?count=N` (new path) missing | MED | XFAIL |
| G21  | REST     | BUG-21 `restBlockFilterHeaders` quadratic walk | MED  | XFAIL |
| G22  | REST     | BUG-22 `restBlock` JSON status by substring match | LOW  | XFAIL |
| G23  | REST     | BUG-23 `restTx` same | LOW  | XFAIL |
| G24  | REST     | BUG-24 dispatch lacks no-trailing-slash forgiveness | LOW  | XFAIL |
| G25  | NOTIFY   | BUG-25 `-blocknotify` MISSING | HIGH | XFAIL |
| G26  | NOTIFY   | BUG-26 `-alertnotify` MISSING | HIGH | XFAIL |
| G27  | NOTIFY   | BUG-27 `-shutdownnotify` MISSING | HIGH | XFAIL |
| G28  | NOTIFY   | BUG-28 `-startupnotify` MISSING | MED  | XFAIL |
| G29  | NOTIFY   | BUG-29 `-walletnotify` MISSING | MED  | XFAIL |
| G30  | NOTIFY   | BUG-30 `ShellEscape` / `SanitizeString` helper MISSING (forward-regression) | HIGH | XFAIL |

**Bug count: 30 (15 ZMQ + 9 REST + 6 NOTIFY).** All XFAIL — flip when
fixed. Largest single-finding: missing disconnect-side throughout
(BUG-1 / BUG-2 / BUG-5) is one architectural gap manifesting as three
distinct bug numbers; closing it requires a single hook in the
reorg/disconnect code path that re-uses the existing notifier.
