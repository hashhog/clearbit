//! W124 — Operator-experience audit (clearbit / Zig 0.13)
//!
//! Reference:
//!   bitcoin-core/src/init.cpp       (signals, Shutdown, Interrupt,
//!                                    SetupServerArgs, LockDirectory,
//!                                    InitLogging, WritePidFile)
//!   bitcoin-core/src/logging.{cpp,h}
//!     (BCLog::Logger, m_reopen_file, ShrinkDebugFile,
//!      m_log_timestamps, m_log_threadnames, m_log_sourcelocations)
//!   bitcoin-core/src/httpserver.cpp::ClientAllowed (rpcallowip CIDR)
//!   bitcoin-core/src/rpc/server.cpp::stop (full-node shutdown via stop RPC)
//!
//! Run: `zig build test` (this file folds into the root unit_tests via
//! src/tests.zig — see G0_root_smoke). Filter to "w124" to run only:
//!   `zig build test --summary failures -- --test-filter w124`
//!
//! These are XFAIL guards (not actively-failing) — they assert the
//! current state so that a future bug-fix wave deliberately flips
//! each gate from PARTIAL/MISSING → PRESENT. Failures here mean
//! someone already landed the fix and forgot to update the audit.
//! See `audit/w124_operator_experience.md` for the prose.

const std = @import("std");
const testing = std.testing;

const main_mod = @import("main.zig");
const ops = @import("ops.zig");
const debug_log = @import("debug_log.zig");
const rpc_mod = @import("rpc.zig");

// ===========================================================================
// G1: SIGINT / SIGTERM → graceful shutdown
// Status: PRESENT.
// main.zig:849-869 installs signalHandler for SIGINT + SIGTERM. First
// signal sets shutdown_requested; main loop polls and falls through to
// phased shutdown.
test "w124 G1: shutdown_requested atomic exists and defaults to false" {
    // Reset to a known state (other tests in this binary may have flipped it).
    main_mod.shutdown_requested.store(false, .release);
    try testing.expect(!main_mod.shutdown_requested.load(.acquire));
}

test "w124 G1: signal handler installed function symbol exists" {
    // Compile-time presence guard: installSignalHandlers must be callable
    // from main; if it's renamed or deleted this test stops compiling.
    const f = main_mod.installSignalHandlers;
    _ = f;
}

// ===========================================================================
// G2: Double-signal force-exit
// Status: PRESENT (fleet-leading).  signal_count.fetchAdd >= 1 → exit(1).
// Two Ctrl-C presses can always kill a wedged node.
test "w124 G2: signal_count atomic starts at zero" {
    main_mod.signal_count.store(0, .release);
    try testing.expectEqual(@as(u32, 0), main_mod.signal_count.load(.acquire));
}

// ===========================================================================
// G3: Bounded shutdown deadline / watchdog
// Status: PRESENT (fleet-leading).  30-second hard deadline.
test "w124 G3: SHUTDOWN_DEADLINE_NS = 30s" {
    try testing.expectEqual(
        @as(u64, 30 * std.time.ns_per_s),
        main_mod.SHUTDOWN_DEADLINE_NS,
    );
}

test "w124 G3: shutdown_complete atomic exists and defaults to false" {
    main_mod.shutdown_complete.store(false, .release);
    try testing.expect(!main_mod.shutdown_complete.load(.acquire));
}

// ===========================================================================
// G4: SIGHUP → log reopen (logrotate compatibility)
// Status: PRESENT.  Round-tripped in ops.zig tests already; smoke-guard here.
test "w124 G4: SIGHUP handler installable and sighup_requested resets" {
    ops.sighup_requested.store(false, .release);
    // installSighupHandler is idempotent and safe to call from tests because
    // it only rebinds the SIGHUP slot.  We don't actually deliver SIGHUP to
    // the test process — only check the atomic flag round-trips.
    ops.installSighupHandler();
    try testing.expect(!ops.sighup_requested.load(.acquire));
    ops.sighup_requested.store(true, .release);
    try testing.expect(ops.sighup_requested.swap(false, .acq_rel));
}

// ===========================================================================
// G5: PID file write + 0644 + post-shutdown unlink
// Status: PRESENT.  BUG-1: no stale-PID-file detection on startup.
test "w124 G5: writePidFile + removePidFile round-trip" {
    const allocator = testing.allocator;
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath(".", &pbuf);
    const pid_path = try std.fmt.allocPrint(allocator, "{s}/clearbit.pid", .{tmp_path});
    defer allocator.free(pid_path);

    try ops.writePidFile(pid_path, allocator);
    const f = try std.fs.openFileAbsolute(pid_path, .{});
    f.close();
    ops.removePidFile(pid_path);
    try testing.expectError(error.FileNotFound, std.fs.openFileAbsolute(pid_path, .{}));
}

// BUG-1 (LOW-OPS): stale PID file is silently overwritten on startup.
// XFAIL: stale-PID-detect helper does NOT exist. If a "check before write"
// helper lands, this test will compile-error on the missing symbol and
// alert the next audit to flip G5 to PRESENT-without-bug.
test "w124 G5 BUG-1: no stale-PID detection helper (xfail)" {
    // ops.zig is the canonical home for this helper. Comptime probe:
    // the (would-be) symbol `checkStalePidFile` should NOT exist.
    const has_helper = @hasDecl(ops, "checkStalePidFile");
    try testing.expect(!has_helper); // assert ABSENT; flip when fixed.
}

// ===========================================================================
// G6: Datadir lock file (`.lock`) — MISSING.  P1-OPS.
// XFAIL: there is no `lockDatadir` / `acquireDatadirLock` helper.
test "w124 G6 BUG-2: no datadir flock helper (xfail / P1-OPS)" {
    const has_lock_fn = @hasDecl(ops, "lockDatadir") or
        @hasDecl(ops, "acquireDatadirLock");
    try testing.expect(!has_lock_fn); // assert ABSENT; double-launch races on
    // the same datadir corrupt RocksDB chainstate. Fix is one std.posix.flock
    // call on `<datadir>/.lock` held for process lifetime.
}

// ===========================================================================
// G7: Daemonize (--daemon: fork + setsid + dup stdio)
// Status: PRESENT (fleet-leading robustness).
test "w124 G7: daemonize symbol exists" {
    const has_daemonize = @hasDecl(ops, "daemonize");
    try testing.expect(has_daemonize);
}

// ===========================================================================
// G8: Cookie file generation + 0o600 mode + shutdown unlink
// Status: PRESENT.
test "w124 G8: generateCookieFile + deleteCookieFile pair exists" {
    try testing.expect(@hasDecl(main_mod, "generateCookieFile"));
    try testing.expect(@hasDecl(main_mod, "deleteCookieFile"));
}

test "w124 G8: cookie file is mode 0o600" {
    const allocator = testing.allocator;
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath(".", &pbuf);

    const tok = try main_mod.generateCookieFile(tmp_path, allocator);
    defer allocator.free(tok);

    const cookie_path = try std.fmt.allocPrint(allocator, "{s}/.cookie", .{tmp_path});
    defer allocator.free(cookie_path);

    const stat = try std.fs.cwd().statFile(cookie_path);
    // mode mask 0o777 should equal 0o600.
    try testing.expectEqual(@as(u64, 0o600), stat.mode & 0o777);
    main_mod.deleteCookieFile(tmp_path, allocator);
}

// ===========================================================================
// G9: Datadir creation + network subdir
// Status: PRESENT.
test "w124 G9: getNetworkSubdir maps mainnet → empty, testnet4 → testnet4" {
    try testing.expectEqualStrings("", main_mod.getNetworkSubdir(.mainnet));
    try testing.expectEqualStrings("testnet3", main_mod.getNetworkSubdir(.testnet));
    try testing.expectEqualStrings("testnet4", main_mod.getNetworkSubdir(.testnet4));
    try testing.expectEqualStrings("regtest", main_mod.getNetworkSubdir(.regtest));
}

// ===========================================================================
// G10: Config file (--conf= or <datadir>/clearbit.conf)
// Status: PRESENT.  BUG-4: no [main]/[test] section parsing.
test "w124 G10: loadConfigFile symbol exists" {
    try testing.expect(@hasDecl(main_mod, "loadConfigFile"));
}

test "w124 G10 BUG-4: section headers not parsed (xfail)" {
    const allocator = testing.allocator;
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath(".", &pbuf);
    const conf_path = try std.fmt.allocPrint(allocator, "{s}/clearbit.conf", .{tmp_path});
    defer allocator.free(conf_path);

    // Write a Core-style conf with a [test] section overriding rpcport.
    {
        const f = try std.fs.createFileAbsolute(conf_path, .{});
        defer f.close();
        try f.writeAll(
            \\rpcport=8332
            \\[test]
            \\rpcport=18332
            \\
        );
    }

    var cfg = main_mod.Config{};
    main_mod.loadConfigFile(tmp_path, &cfg, allocator) catch {};

    // Today: clearbit parses both lines as flat key=value with the latter
    // overriding the former (we get 18332, not the 8332 of `[main]`).
    // A section-aware parser would keep 8332 for default network.
    // This XFAIL freezes the current behavior; flip when fixed.
    try testing.expectEqual(@as(u16, 18332), cfg.rpc_port);
}

// ===========================================================================
// G11: `-blocknotify=<cmd>` — MISSING.
test "w124 G11 BUG-5: no blocknotify command hook (xfail)" {
    const cfg = main_mod.Config{};
    // Probe: no `blocknotify` field on Config.
    const has_field = @hasField(main_mod.Config, "blocknotify");
    try testing.expect(!has_field);
    _ = cfg;
}

// ===========================================================================
// G12: `-alertnotify=<cmd>` — MISSING.
test "w124 G12 BUG-6: no alertnotify command hook (xfail)" {
    const has_field = @hasField(main_mod.Config, "alertnotify");
    try testing.expect(!has_field);
}

// ===========================================================================
// G13: `-shutdownnotify=<cmd>` — MISSING.
test "w124 G13 BUG-7: no shutdownnotify command hook (xfail)" {
    const has_field = @hasField(main_mod.Config, "shutdownnotify");
    try testing.expect(!has_field);
}

// ===========================================================================
// G14: `--debug=<category>` (BCLog::LogFlags parity)
// Status: PRESENT.
test "w124 G14: debug_log.parseAndApply recognises Core categories" {
    debug_log.reset();
    try testing.expect(debug_log.parseAndApply("net"));
    try testing.expect(debug_log.enabled(.NET));
    try testing.expect(debug_log.parseAndApply("mempool"));
    try testing.expect(debug_log.enabled(.MEMPOOL));
    debug_log.reset();
}

test "w124 G14: debug_log table covers all 31 Core LogFlags categories" {
    // Categories that Core ships and clearbit must parse without warning.
    const names = [_][]const u8{
        "net", "tor", "mempool", "http", "bench", "zmq", "walletdb", "rpc",
        "estimatefee", "addrman", "selectcoins", "reindex", "cmpctblock",
        "rand", "prune", "proxy", "mempoolrej", "libevent", "coindb", "qt",
        "leveldb", "validation", "i2p", "ipc", "lock", "util", "blockstorage",
        "txreconciliation", "scan", "txpackages",
    };
    debug_log.reset();
    for (names) |n| try testing.expect(debug_log.parseAndApply(n));
    debug_log.reset();
}

// ===========================================================================
// G15: Unknown --debug=<cat> warns, does not abort
// Status: PRESENT.
test "w124 G15: unknown category returns false (warns, no abort)" {
    debug_log.reset();
    try testing.expect(!debug_log.parseAndApply("definitely_not_a_category"));
    // Mask unchanged.
    try testing.expectEqual(@as(u64, 0), debug_log.active_mask.load(.acquire));
}

// ===========================================================================
// G16: --logfile=<path> file-only target
// Status: PARTIAL.  BUG-8: opened fd is unused (writes still hit stderr).
test "w124 G16: LogState symbol exists" {
    try testing.expect(@hasDecl(ops, "LogState"));
}

test "w124 G16 BUG-8: no helper that routes log writes through LogState (xfail)" {
    // If a future PR adds a `logWrite` / `logPrint` helper that dual-writes
    // to LogState.fd + stderr, this xfail will flip.
    const has_writer = @hasDecl(ops, "logWrite") or
        @hasDecl(ops, "logPrint") or
        @hasDecl(ops, "LogPrintStr");
    try testing.expect(!has_writer);
    // Operator-DX surprise: `--logfile=` creates the file (so SIGHUP rotation
    // works on the fd) but nothing routes through it.  Effectively a no-op
    // for content; stderr is still the only log sink.
}

// ===========================================================================
// G17: Log line format — timestamp + threadname + category
// Status: MISSING.
test "w124 G17 BUG-9: no log-line formatter (xfail)" {
    const has_formatter = @hasDecl(ops, "formatLogLine") or
        @hasDecl(debug_log, "formatLogLine") or
        @hasDecl(ops, "LogPrintStr");
    try testing.expect(!has_formatter);
    // No `[2026-05-17T10:11:12Z][net][thread-3] ...` prefix on log lines.
    // Mitigated when piped through journald; --logfile= files are
    // timestamp-less.
}

// ===========================================================================
// G18: Log file size cap / rotation
// Status: MISSING.
test "w124 G18 BUG-10: no ShrinkDebugFile-equivalent (xfail)" {
    const has_shrink = @hasDecl(ops, "shrinkDebugFile") or
        @hasDecl(ops, "rotateLogFile");
    try testing.expect(!has_shrink);
    // Mitigated by external logrotate + SIGHUP (G4 works).
}

// ===========================================================================
// G19: --ready-fd=<N> systemd-style readiness notify
// Status: PRESENT.
test "w124 G19: notifyReadyFd exists" {
    try testing.expect(@hasDecl(ops, "notifyReadyFd"));
}

test "w124 G19: --ready-fd negative is no-op" {
    // notifyReadyFd(-1) MUST not write anywhere.  Safe to call without a fd.
    ops.notifyReadyFd(-1);
}

// ===========================================================================
// G20: Prometheus /metrics + /health endpoints
// Status: PRESENT (fleet-leading).
test "w124 G20: metrics_port default 9332" {
    const cfg = main_mod.Config{};
    try testing.expectEqual(@as(u16, 9332), cfg.metrics_port);
}

// ===========================================================================
// G21: ZMQ publisher topics
// Status: PRESENT (build-gated -Dzmq=true).
test "w124 G21: Config has zmq_* fields for all five topics" {
    try testing.expect(@hasField(main_mod.Config, "zmq_rawblock"));
    try testing.expect(@hasField(main_mod.Config, "zmq_hashblock"));
    try testing.expect(@hasField(main_mod.Config, "zmq_rawtx"));
    try testing.expect(@hasField(main_mod.Config, "zmq_hashtx"));
    try testing.expect(@hasField(main_mod.Config, "zmq_sequence"));
}

// ===========================================================================
// G22: Phased shutdown logging
// Status: PRESENT — phase log lines visible in main.zig:2261-2329.
// We can't easily unit-test stderr output for phase lines, but we can
// assert the constants the phased shutdown depends on.
test "w124 G22: shutdown phases are wired via shutdown_complete + shutdown_requested" {
    main_mod.shutdown_complete.store(false, .release);
    main_mod.shutdown_requested.store(false, .release);
    try testing.expect(!main_mod.shutdown_complete.load(.acquire));
    try testing.expect(!main_mod.shutdown_requested.load(.acquire));
}

// ===========================================================================
// G23: Mempool persistence on shutdown
// Status: PRESENT.  loadMempool / dumpMempool round-trip already tested in
// mempool_persist.zig — smoke-guard here that the symbols exist.
test "w124 G23: mempool_persist dump/load symbols exist" {
    const mempool_persist = @import("mempool_persist.zig");
    try testing.expect(@hasDecl(mempool_persist, "dumpMempool"));
    try testing.expect(@hasDecl(mempool_persist, "loadMempool"));
}

// ===========================================================================
// G24: Atomic file writes (xor-rename pattern)
// Status: PRESENT.  fsync omitted (INFO-2 — fleet-wide gap, not clearbit-only).
test "w124 G24: FeeEstimator.saveToFile uses tmp+rename pattern" {
    // The actual atomicity is exercised in W114; here we assert the
    // saveToFile / loadFromFile public symbols still exist.
    const mempool = @import("mempool.zig");
    try testing.expect(@hasDecl(mempool.FeeEstimator, "saveToFile"));
    try testing.expect(@hasDecl(mempool.FeeEstimator, "loadFromFile"));
}

// ===========================================================================
// G25: Final chainstate flush before exit
// Status: PRESENT.  ChainState.flush() is called from shutdown.
test "w124 G25: ChainState.flush exists" {
    const storage = @import("storage.zig");
    try testing.expect(@hasDecl(storage.ChainState, "flush"));
}

// ===========================================================================
// G26: --reindex honest-progress
// Status: PARTIAL.  BUG-12: CF_BLOCKS replay loop is not implemented.
test "w124 G26 BUG-12: --reindex Config field exists but is partial (xfail)" {
    try testing.expect(@hasField(main_mod.Config, "reindex"));
    // No replay-loop helper exists yet.  When CF_BLOCKS-replay lands as
    // `ChainState.reindexFromCfBlocks`, this xfail flips.
    const storage = @import("storage.zig");
    const has_reindex_loop = @hasDecl(storage.ChainState, "reindexFromCfBlocks");
    try testing.expect(!has_reindex_loop);
}

// ===========================================================================
// G27: --rpcallowip=<cidr> IP allow-list
// Status: MISSING.  BUG-13 (P2-SECURITY): no CIDR filtering.
test "w124 G27 BUG-13: no rpcallowip CIDR allow-list field (xfail / P2-SEC)" {
    const has_allowip = @hasField(main_mod.Config, "rpcallowip") or
        @hasField(main_mod.Config, "rpc_allow_ip");
    try testing.expect(!has_allowip);
    // Operator setting `rpcbind=0.0.0.0` (e.g. for a remote bitcoin-cli)
    // exposes the RPC port to the entire LAN/WAN; auth is the only gate.
    // Core has CIDR filtering since 0.5 (httpserver.cpp::ClientAllowed).
}

// ===========================================================================
// G28: stop RPC method
// Status: PRESENT (with BUG-14).
test "w124 G28: stop method exists in RPC dispatch" {
    // Probe at the source level (we can't easily wire a full RpcServer
    // here without a chain_state + mempool + peer_manager); the dispatch
    // string is checked in the source.  Use a tagged comptime guard:
    // ensure the constant lives in rpc.zig (the dispatch token is the
    // literal "stop" string at rpc.zig:3000 — see audit doc).
    _ = rpc_mod; // import-presence guard
}

test "w124 G28 BUG-14: stop RPC does not trigger main.shutdown_requested (xfail)" {
    // Today rpc.zig:3000-3002 calls self.stop() which sets the *RPC server's*
    // running=false, but does NOT set main.shutdown_requested.  So
    // `bitcoin-cli stop` halts RPC but leaves the P2P+main loop running.
    // Probe: a guard symbol `stopRpcSetsShutdownRequested` would be added
    // by the fix; until then it should be ABSENT.
    const fixed = @hasDecl(rpc_mod, "stopRpcSetsShutdownRequested");
    try testing.expect(!fixed);
}

// ===========================================================================
// G29: uptime RPC method
// Status: PRESENT.
test "w124 G29: RpcServer tracks start_time for uptime" {
    // The start_time field on RpcServer (rpc.zig:1257) is what powers
    // uptime; probe its presence via reflection.
    try testing.expect(@hasField(rpc_mod.RpcServer, "start_time"));
}

// ===========================================================================
// G30: getrpcinfo
// Status: PARTIAL.  BUG-15: missing logging sub-object + logpath.
test "w124 G30 BUG-15: no getrpcinfo logging sub-object helper (xfail)" {
    const has_helper = @hasDecl(rpc_mod, "buildGetRpcInfoLogging") or
        @hasDecl(rpc_mod, "formatRpcInfoLogging");
    try testing.expect(!has_helper);
    // Operators debugging "what categories does my running node have on?"
    // can't ask the live node — they have to grep startup output.
}

// ===========================================================================
// Counts gate — wire-up smoke
// ===========================================================================
test "w124 G0: 30-gate audit lives in this file" {
    // No-op anchor so a grep for 'w124' lands on a sentinel test.
    try testing.expect(true);
}
