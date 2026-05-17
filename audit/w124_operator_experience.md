# W124 — Operator-experience audit (clearbit / Zig 0.13)

Reference:
- `bitcoin-core/src/init.cpp`   (signals, `Shutdown()`, `Interrupt()`, `SetupServerArgs`,
                                 `InitLogging`, `LockDirectory`, `WritePidFile`)
- `bitcoin-core/src/logging.{cpp,h}` (`BCLog::Logger`, `m_reopen_file`, `ShrinkDebugFile`,
                                       `m_log_timestamps` / `m_log_threadnames`)
- shutdown is in `init.cpp` (`Interrupt`, `Shutdown`) — there is **no** standalone
  `src/shutdown.cpp` in Bitcoin Core 28+. The prompt’s reference list is otherwise
  intact; the audit substitutes `init.cpp` for `shutdown.cpp` everywhere a
  Shutdown function is cited.

Run: `zig build test --summary none` (W124 tests live in `src/tests_w124_operator.zig`,
folded into the root `test` step).

## SUBSYSTEM STATUS — operator surface

Pre-audit baseline (`be6f05d`):
- Signal handling: SIGINT/SIGTERM (graceful), double-Ctrl-C escalation, SIGHUP
  log reopen — **PRESENT and well-engineered**. Two-signal escalation +
  `shutdownWatchdog` (30s hard deadline) puts clearbit *ahead* of Core on
  hang-resistance.
- Daemonize (`ops.daemonize`): double-fork + setsid + `/dev/null` dup2 —
  PRESENT; uses raw `exit_group` syscall in the parent to dodge atexit+stdio
  flush deadlocks (RocksDB MANIFEST lock). Strong design.
- PID file: write + 0644 mode + best-effort unlink — PRESENT, only minor gap
  (no PID-file-stale detection on startup).
- Cookie file: 32 random bytes + 0o600 mode + deleteCookieFile on shutdown —
  PRESENT.
- Datadir / network subdir / `--conf=`: PRESENT.
- Debug-category logging (`debug_log.zig`): full Core BCLog::LogFlags table,
  atomic-OR mask, `enabled(.NET)` is one AND — PRESENT.
- `--logfile=<path>` + SIGHUP-driven reopen (`ops.LogState.maybeReopen`) —
  PRESENT.
- Daemon ready-fd (`--ready-fd=<N>` → `READY=1\n`) for systemd Type=notify /
  runit / daemontools — PRESENT.
- ZMQ publishers (`rawblock`, `hashblock`, `rawtx`, `hashtx`, `sequence`) —
  PRESENT, Bitcoin Core wire-compatible 3-frame multipart.
- Prometheus `/metrics` + `/health` JSON tip endpoint — PRESENT (fleet-leading;
  not in Core).
- Phased shutdown logging — PRESENT.

Gaps cluster on operator-process integration: no `-blocknotify` / `-alertnotify`
/ `-shutdownnotify` command hooks, no `-rpcallowip` CIDR allow-list, no
datadir lock file, no log-time-micros / threadnames / source-location toggles,
no `ShrinkDebugFile` log size cap, no startup banner with config summary, no
runtime `logging` RPC, missing `-stopatheight` operator debug knob, partial
`--reindex`, no operator-facing `warnings` field on getnetworkinfo /
getblockchaininfo. Total: **15 BUGS**, mostly LOW/INFO operator-DX with one
P1 (datadir lock file: prevents double-launch races on the same datadir).

---

## 30 audit gates

Gate numbering is cross-impl frozen — do NOT renumber.

### G1: SIGINT / SIGTERM → graceful shutdown
**Status:** PRESENT.
`main.zig:849-869` installs `signalHandler` for SIGINT + SIGTERM via
`std.posix.sigaction`. First signal sets `shutdown_requested` (atomic);
main loop polls every 100ms and falls through to phased shutdown.

### G2: Double-signal force-exit
**Status:** PRESENT (fleet-leading).
`main.zig:849-859` — `signal_count.fetchAdd(1, .acq_rel)`; if prev>=1,
`std.posix.exit(1)` (raw `_exit` — signal-safe). Two Ctrl-C presses can
always kill a wedged node. Core only has one signal slot via
`SignalInterrupt`.

### G3: Bounded shutdown deadline / watchdog
**Status:** PRESENT (fleet-leading).
`main.zig:876-894` — `SHUTDOWN_DEADLINE_NS = 30 * ns_per_s`; detached
`shutdownWatchdog` thread fires after 30s and `exit(1)`s if
`shutdown_complete` is still false. Core has no equivalent — operators
have historically had to SIGKILL hung shutdown.

### G4: SIGHUP → log reopen
**Status:** PRESENT.
`ops.zig:131-144` installs `sighupHandler`; main loop calls
`log_state.maybeReopen()` every 100ms (`main.zig:2211`). Atomic flag +
file close/reopen path under mutex. Wire-compatible with
logrotate `postrotate /bin/kill -HUP $(cat <pidfile>)`.

### G5: PID file write + 0644 + post-shutdown unlink
**Status:** PRESENT.
`main.zig:1956-1969` resolves `<datadir>/clearbit.pid` (overridable
via `--pid=`), `ops.writePidFile` creates 0644, `ops.removePidFile`
unlinks last (so external supervisors see node alive until truly done).
**BUG-1 (LOW-OPS): no stale PID-file detection on startup.** If a previous
crash left clearbit.pid behind, the new instance silently overwrites it.
Core (`init.cpp::CreatePidFile`) probes the existing PID with
`kill(pid, 0)`; if alive → refuse to start. clearbit would let two daemons
race on the same datadir until one of them died on RocksDB MANIFEST.

### G6: Datadir lock file (`.lock`)
**Status:** MISSING.
Core (`init.cpp:1158-1173 LockDirectory`) takes an exclusive `flock` on
`<datadir>/.lock` and `<blocksdir>/.lock` and refuses to start if held.
clearbit has no datadir-locking — concurrent launches on the same
datadir corrupt RocksDB (the RocksDB MANIFEST internal lock catches it
*eventually* but only after partial writes have already landed).
**BUG-2 (P1-OPS): no `<datadir>/.lock` flock; double-launch on same
datadir is silently undetected until RocksDB MANIFEST screams. Real
mainnet hazard — operator running `start_mainnet.sh` twice (e.g. CI
typo) corrupts chainstate. Core has been doing this since 0.8. Add
`std.posix.flock` on a `<datadir>/.lock` fd held for process lifetime.**

### G7: Daemonize (--daemon: fork + setsid + dup stdio)
**Status:** PRESENT (fleet-leading robustness).
`ops.zig:48-91` does double-fork + setsid + `/dev/null` dup. Parent
uses raw `exit_group` syscall (not `std.posix.exit` / glibc `exit`)
to dodge atexit+stdio+RocksDB-destructor deadlocks. Documented in
ops.zig:48-65 — clearbit has the cleanest implementation of this
in the fleet because it was burned by RocksDB MANIFEST locks once.

### G8: Cookie file generation + 0o600 mode + shutdown unlink
**Status:** PRESENT.
`main.zig:786-826` — `generateCookieFile` uses `std.crypto.random.bytes`
for 32 bytes, hex-encodes, writes `__cookie__:<hex>` to
`<datadir>/.cookie` with `mode=0o600`. `deleteCookieFile` on shutdown.
**BUG-3 (LOW-OPS): cookie file path is `<datadir>/.cookie`, not
`<datadir>/<network>/.cookie` — Core writes the network-specific subdir
(testnet4 → `<datadir>/testnet4/.cookie`). `main.zig:1890` passes
`full_datadir` (network-resolved) so the resulting path IS in the
network subdir — verify but the doc / `deleteCookieFile` argument
is correct. Re-check needed.**
After reading `main.zig:1890` + `main.zig:2316` → both pass
`full_datadir`, so the actual layout matches Core. Demoted to INFO.
INFO-1: cookie file lacks "delete on uncaught crash" coverage —
if main.zig exits via panic, deleteCookieFile never runs and the
next launch reuses the stale cookie value as the *configured* token
(generateCookieFile always rewrites, so this is benign in practice
but worth noting).

### G9: Datadir creation + network subdir (testnet3/testnet4/regtest)
**Status:** PRESENT.
`main.zig:1668-1707`: resolves `~/.clearbit`, creates datadir +
network subdir. `getNetworkSubdir` maps mainnet → "" (no subdir),
testnet → "testnet3", testnet4 → "testnet4", regtest → "regtest" —
matches Core.

### G10: Config file (`--conf=` or `<datadir>/clearbit.conf`)
**Status:** PRESENT.
`main.zig:613-758 loadConfigFile` parses `key=value` lines, accepts
both flag-equivalent names (e.g. `rpc-tls-cert` and `rpctlscert`)
and supports `--conf=<file>` overriding the default
`<datadir>/clearbit.conf` lookup. Section headers (`[main]`, `[test]`)
NOT supported — minor divergence from Core.
**BUG-4 (LOW-OPS): no `[main]` / `[test]` / `[testnet4]` /
`[regtest]` / `[signet]` section parsing.** Operators copying a
Core-style `bitcoin.conf` with sectioned overrides will see only the
top-level keys applied; sectioned `rpcport=` inside `[test]` is
silently dropped. Mitigated by clearbit's `--testnet4` / `--regtest`
flags switching default ports, so this is policy-not-bug *unless* a
shared conf is used across networks.

### G11: `-blocknotify=<cmd>` operator command hook
**Status:** MISSING.
Core (`init.cpp:498`) runs `<cmd>` (with `%s` replaced by block hash)
on every new tip via `g_signals.BlockNotify`. Operators use this for
"my wallet got a new block" desktop notifications, Sentry pings, etc.
clearbit has no `--blocknotify` flag and `validation.ChainManager.connectBlock`
emits no command-spawn hook. **BUG-5 (LOW-OPS, INFO if not used by hashhog
ops): MISSING.** Fleet-wide gap (not a clearbit-only miss); track here for
the audit row.

### G12: `-alertnotify=<cmd>` alerting hook
**Status:** MISSING.
Core (`init.cpp:485`) runs `<cmd>` (`%s` = message) on warnings raised
by validation. clearbit has no equivalent.
**BUG-6 (LOW-OPS): MISSING.** No `getnetworkinfo.warnings` populated, no
hook to fire one. Mitigated by Prometheus `bitcoin_peers_connected`
plus ad-hoc fleet-monitor.sh alerting in `tools/`, but operator-facing
strings (e.g. "Warning: Witness data for blocks after height X requires
validation") never surface.

### G13: `-shutdownnotify=<cmd>` shutdown hook
**Status:** MISSING.
Core (`init.cpp:256-265 ShutdownNotify`) runs commands during shutdown,
joining them before clearing chainstate. clearbit has no equivalent.
**BUG-7 (INFO-OPS): MISSING.** Lowest priority gap; ops covered by
external orchestrators (`stop_mainnet.sh`).

### G14: `--debug=<category>` (BCLog::LogFlags parity)
**Status:** PRESENT.
`debug_log.zig` ships all 31 Core BCLog categories; `parseAndApply`
ORs bits into `active_mask`; `enabled(.NET)` is a single AND on a
relaxed-load atomic. Repeat `--debug=cat` ORs more bits. `--debug=0`
or `--debug=none` clears. `--debug=all` / `--debug` (empty) sets ALL.
Matches Core argspec.

### G15: `--debug=` rejects unknown categories with warning
**Status:** PRESENT.
`main.zig:325-327` + `loadConfigFile:727-729` — unknown category
prints a one-line warning to stderr and is otherwise ignored. Does
NOT abort startup (matches Core's `LogPrintCategoryOrCategories`).

### G16: `--logfile=<path>` file-only logging target
**Status:** PRESENT (partial).
`ops.LogState.open` creates / appends to the file. `--printtoconsole`
is the toggle for tee-to-stderr behavior. **BUG-8 (LOW-OPS):
log writes don't actually use LogState** — clearbit emits via
`std.debug.print` (stderr-only). LogState is *opened* (so SIGHUP
reopen works on the fd) but nothing routes through it. Effectively
`--logfile=` is opened but unused except as a reopen-on-HUP target.
This is the **most common operator-DX surprise** in the fleet:
"I set --logfile and got an empty file". Core's
`LogInstance().LogPrintStr` writes to BOTH `m_fileout` and stdout.

### G17: Log line format — timestamp + threadname + category
**Status:** MISSING (operator-DX gap).
Core (`logging.cpp:304-417`) prefixes log lines with timestamp
(`m_log_timestamps`, microseconds optional via `m_log_time_micros`),
threadname (`m_log_threadnames`), source-location
(`m_log_sourcelocations`), and category (`[net]`, `[mempool]`).
clearbit emits raw `std.debug.print` strings. Operators can't grep
`[net]` to filter, can't see timestamps in --printtoconsole output,
can't correlate threads.
**BUG-9 (LOW-OPS): no timestamp / category / threadname prefix on
log lines.** Mitigated when piped through systemd-journal (journald
adds its own timestamp), but `--logfile=` files are timestamp-less.

### G18: Log file size cap / rotation (`ShrinkDebugFile`)
**Status:** MISSING.
Core (`logging.cpp:514 ShrinkDebugFile`) truncates `debug.log` at
startup if > 10MB, keeping the last ~1MB. clearbit appends forever
unless logrotate is configured externally. **BUG-10 (INFO-OPS):
MISSING.** Operator-DX: a year-long run will produce GB log files.
Mitigated by external logrotate + SIGHUP (G4 works).

### G19: `--ready-fd=<N>` systemd-style readiness notify
**Status:** PRESENT.
`ops.zig:222-228 notifyReadyFd` writes `READY=1\n` and closes the fd.
Fire-and-forget. `main.zig:2195-2197` fires after the P2P listener
and RPC thread are up — correct ordering (Core's
`Notifications::startupNotificationsDone` is the equivalent moment).

### G20: Prometheus `/metrics` + `/health` endpoints
**Status:** PRESENT (fleet-leading).
`main.zig:2343-2429 metricsServerThread` binds `0.0.0.0:9332` by
default, serves Prometheus text format (`bitcoin_blocks_total`,
`bitcoin_peers_connected`, `bitcoin_mempool_size`) on `GET /metrics`,
and a JSON tip status on `GET /health`. Core has no built-in
Prometheus path — fleet exposes via per-node Prometheus exporters.

### G21: ZMQ publisher (`rawblock` / `hashblock` / `rawtx` / `hashtx` / `sequence`)
**Status:** PRESENT.
`zmq.zig` ships all five topics, 3-frame multipart wire format
matching Core (`[topic][payload][LE uint32 sequence]`), bound on
`tcp://host:port` per `--zmqpub<topic>=` flag. Build-gated behind
`-Dzmq=true`; when off, init is a no-op.

### G22: Phased shutdown logging (which subsystem are we waiting on)
**Status:** PRESENT.
`main.zig:2261-2329` prints `stopping RPC` → `stopping P2P` →
`joining RPC thread` → `joining P2P thread` → `flushing chainstate` →
`closing DB` → `exit`. If shutdown ever hangs longer than 30s the
operator can tell which phase. Core has equivalent `LogInfo("Shutdown
in progress...")` but no phase breakout.

### G23: Mempool persistence on shutdown
**Status:** PRESENT.
`main.zig:2289-2300` calls `mempool_persist.dumpMempool` (atomic
`<path>.new → rename` per `mempool_persist.zig:369-385`). Loaded at
startup `main.zig:1820-1836`. Core wire-compatible v2 format with
XOR-obfuscation.

### G24: Atomic file writes for shutdown state (xor-rename pattern)
**Status:** PRESENT.
`mempool_persist.dumpMempool` (line 369-385) and
`FeeEstimator.saveToFile` (line 7097-7120) both write
`<path>.tmp` → fsync? → rename → cleanup on error. **BUG-11
(LOW-RELIABILITY): neither path explicitly fsync()s the temp file
before rename.** A power-loss between `rename` and the next OS dirty-
page flush leaves a zero-length mempool.dat. Core sets
`DUMPER_VERSION = 2` AND does `fclose(f)` before rename — fclose
calls fflush but NOT fsync. So this is a fleet-wide gap, not
clearbit-only. Demote to INFO-2 — track but don't block.

### G25: Final chainstate flush before exit (`Shutdown::ForceFlushStateToDisk`)
**Status:** PRESENT.
`main.zig:2302-2308 chain_state.flush()`. Errors logged but don't
block shutdown (so a flush failure doesn't hold the process forever).
Matches Core's `Shutdown()` (init.cpp:351-388 dual ForceFlushStateToDisk
calls — clearbit does it once because RocksDB batches under the hood).

### G26: `--reindex` honest-progress: parse + warn + continue
**Status:** PARTIAL.
`main.zig:1993-2003` accepts the flag, emits a clear "partial reindex
not implemented" message, and continues. **BUG-12 (LOW-OPS):
`--reindex` is dead-flag at the CF_BLOCKS-replay level.** Operators
expecting Core's `init.cpp::DoReindex` to rebuild UTXO from
CF_BLOCKS get a no-op + a "use rm -rf chainstate" hint. Honest about
the gap; not silent. Tracked as carry-forward.

### G27: `--rpcallowip=<cidr>` IP allow-list
**Status:** MISSING.
Core (`init.cpp` / `httpserver.cpp::ClientAllowed`) accepts CIDR
expressions and checks every incoming RPC connection against them.
clearbit only honors `rpc_bind` (which limits *interface* binding, not
incoming client IPs). If `rpc_bind=0.0.0.0` everyone can hit the RPC,
auth is the only gate. **BUG-13 (P2-SECURITY, LOW-CDIV from clearbit
shipping with `rpc_bind=127.0.0.1` default — but `rpcbind=0.0.0.0`
in any operator's config loses the cidr defense Core has).**

### G28: `stop` RPC method
**Status:** PRESENT.
`rpc.zig:3000-3002`: `stop` method sets `running=false` on the RPC
server (via `self.stop()`); the main loop polls a separate
`shutdown_requested` so the node continues. **BUG-14 (LOW-OPS):
the `stop` RPC only halts the RPC server, NOT the whole node.**
Core's `stop` (rpc/server.cpp::stop) calls `StartShutdown()` which
triggers the SignalInterrupt + the full shutdown sequence. clearbit's
`stop` RPC returns `"clearbit stopping"` and stops responding to RPC,
but the P2P/peer loop keeps running. Operators expecting `bitcoin-cli
stop` to terminate the daemon will be surprised. Patch: have the RPC
method also set `main.shutdown_requested.store(true, .release)`.

### G29: `uptime` RPC method
**Status:** PRESENT.
`rpc.zig:3103` + `10552-10603`: `uptime` returns `(now -
RpcServer.created_at)` in seconds, matching Core's
`src/rpc/server.cpp::uptime`.

### G30: `getrpcinfo` (active commands + per-method logger config)
**Status:** PARTIAL.
`rpc.zig:3167` handles `getrpcinfo` and returns active-command tracking
info, but **BUG-15 (LOW-OPS): the `logging` sub-object (per-category
on/off bitmask) and `version` field are not present in the output.**
Core's `getrpcinfo` includes a `"logpath"` and `"active_commands"` list;
clearbit returns the active-commands but no log path. Operators
debugging "what categories does my running node have enabled" can't
ask the live node — they have to grep startup output.

---

## Universal findings (cross-impl pattern candidates)

- **"datadir flock is missing"** — likely fleet-wide. Worth promoting to a
  fleet-level cross-impl finding once W124 is in for 3+ impls.
- **"--logfile= opens fd but routes nothing through it"** — clearbit gap is
  worse than Core; verify across the fleet but likely a sub-pattern of
  "operator-DX file logging surprises".
- **"`stop` RPC only stops RPC server"** — clearbit-specific bug; Core
  consolidates via `SignalInterrupt`. Other impls may or may not.
- **"signal handler is async-safe via atomic only"** — clearbit POSITIVE,
  matches Core, no fleet bug here.
- **"30s shutdown watchdog"** — clearbit fleet-leading; Core has no
  equivalent. Could be promoted as a "fleet-ahead-of-Core" finding for the
  W124 cumulative.

## Counts

- PRESENT: 19  (G1, G2, G3, G4, G5, G7, G8, G9, G10, G14, G15, G19, G20,
                G21, G22, G23, G24, G25, G28, G29 — 20 but G5 has BUG-1
                attached and G8 + G10 + G24 + G28 each have a sub-bug, so
                "PRESENT-with-gap" count = 5 of 19.)
- PARTIAL: 3   (G16 [logfile route], G26 [reindex], G30 [getrpcinfo logging])
- MISSING: 7   (G6, G11, G12, G13, G17, G18, G27)
  PRESENT recounts: G1,G2,G3,G4,G5,G7,G8,G9,G10,G14,G15,G19,G20,G21,G22,
                    G23,G24,G25,G28,G29 = 20. So PRESENT=20, PARTIAL=3,
                    MISSING=7 (G6, G11, G12, G13, G17, G18, G27).

BUGS (15): BUG-1 stale-pid, **BUG-2 datadir-flock (P1)**, INFO-1 cookie-on-
crash (G8), BUG-4 conf-sections, BUG-5 blocknotify, BUG-6 alertnotify,
BUG-7 shutdownnotify, BUG-8 logfile-fd-unused (most likely operator
surprise), BUG-9 log-line-format, BUG-10 log-file-size-cap, INFO-2 fsync
(G24), BUG-12 reindex-partial, **BUG-13 rpcallowip (P2-SEC)**, BUG-14
stop-rpc-only-half-shuts-down, BUG-15 getrpcinfo-no-logging-info.

**Top findings (priority order)**:
1. **BUG-2 (P1-OPS): no `<datadir>/.lock` flock — silent double-launch
   corrupts RocksDB.** Real mainnet hazard, fix is one `std.posix.flock`
   call held for process lifetime.
2. **BUG-13 (P2-SECURITY): no `--rpcallowip` CIDR allow-list — operator
   setting `rpcbind=0.0.0.0` exposes RPC to anyone reachable, auth is
   the only gate.** Core has CIDR filtering since 0.5.
3. **BUG-14 (P2-OPS): `stop` RPC stops RPC server but not the node.**
   Operator usability bug, easy fix.
4. **BUG-8 (P2-DX): `--logfile=` opens fd but nothing writes through it.**
   Operator-surprise of the wave; fix is to thread `log_state.write` into
   the existing `std.debug.print` call sites or replace them with a
   leaf helper.
5. BUG-1 (P3-OPS): no stale PID-file detection on startup — opens the
   double-launch race that BUG-2 also addresses; closing BUG-2 obviates
   half of this.

## Reference reads

- `bitcoin-core/src/init.cpp:200-457` (signal handlers, ShutdownNotify,
  Shutdown, registerSignalHandler, LockDirectory).
- `bitcoin-core/src/logging.{cpp,h}` (`BCLog::Logger`, `m_reopen_file`,
  `ShrinkDebugFile`, `LogPrintStr`).
- `bitcoin-core/src/httpserver.cpp::ClientAllowed` (rpcallowip CIDR).
- `bitcoin-core/src/rpc/server.cpp::stop` (full-node shutdown via stop RPC).
- `bitcoin-core/src/rpc/server.cpp::getrpcinfo` (logging sub-object shape).

## No production code changes

This wave is DISCOVERY only. Production behavior identical to `be6f05d`.
Bug-fix wave follow-ups: open BUG-2 (datadir-flock) and BUG-14 (stop-rpc)
as P1/P2 fix candidates.
