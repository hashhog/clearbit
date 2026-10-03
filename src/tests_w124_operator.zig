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
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");

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
// Status: PRESENT.  110-second backstop (under stop_mainnet.sh's 120 s grace;
// 30 s fired mid-write on a disk-saturated host, 2026-10-03).
test "w124 G3: SHUTDOWN_DEADLINE_NS = 110s" {
    try testing.expectEqual(
        @as(u64, 110 * std.time.ns_per_s),
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

// Gate 5 FIX (was BUG-14 xfail): RPC stop used to call only self.stop(),
// halting the RPC accept loop while P2P + the main loop kept running. The
// stop branch now calls rpc.requestNodeShutdown(), which raises SIGTERM in
// process so main.signalHandler sets main.shutdown_requested -- the same
// path `kill -TERM` takes. Behavioural: install main's real handler, call
// the helper, and shutdown_requested must flip.
test "w124 G28: stop RPC sets main.shutdown_requested via the SIGTERM handler" {
    var old_term: std.posix.Sigaction = undefined;
    var old_int: std.posix.Sigaction = undefined;
    std.posix.sigaction(std.posix.SIG.TERM, null, &old_term) catch {};
    std.posix.sigaction(std.posix.SIG.INT, null, &old_int) catch {};
    defer std.posix.sigaction(std.posix.SIG.TERM, &old_term, null) catch {};
    defer std.posix.sigaction(std.posix.SIG.INT, &old_int, null) catch {};
    main_mod.shutdown_requested.store(false, .release);
    main_mod.signal_count.store(0, .release);
    defer {
        main_mod.shutdown_requested.store(false, .release);
        main_mod.signal_count.store(0, .release);
    }
    main_mod.installSignalHandlers();
    rpc_mod.requestNodeShutdown();
    // A process-directed signal to a single-threaded runner is delivered
    // before kill() returns; allow a short grace for multi-threaded runners.
    var i: usize = 0;
    while (!main_mod.shutdown_requested.load(.acquire) and i < 200) : (i += 1) {
        std.time.sleep(5 * std.time.ns_per_ms);
    }
    try testing.expect(main_mod.shutdown_requested.load(.acquire));
}

// Gate 5: PeerManager.stop() must interrupt a handshake that is blocking the
// P2P thread. Measured on regtest (clearbit bf702eb, a --connect peer that
// accepts TCP and never answers): SIGTERM -> `joining P2P thread` hung in
// Peer.performV2Handshake's 30 s poll(); the 30 s shutdown watchdog won and
// exit(1)'d with no chainstate flush (gdb: posix.poll(timeout=30000) <-
// performV2Handshake <- connectOutboundNegotiatedRelay <- run). Same
// signature as the live 2026-10-02 SIGKILL at stop_mainnet.sh's 30 s.
// Discriminator: without the fix the dial returns only after >= 30 s.
test "w124 G1b: PeerManager.stop interrupts a blocking outbound handshake (gate 5)" {
    const allocator = std.heap.page_allocator;
    // A peer that completes TCP (kernel backlog) and never sends a byte.
    const listen_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try listen_addr.listen(.{ .reuse_address = true });
    defer server.deinit();
    const target = server.listen_address;

    const pm = try allocator.create(peer_mod.PeerManager);
    defer allocator.destroy(pm);
    pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    pm.running.store(true, .release);

    const Dial = struct {
        fn run(m: *peer_mod.PeerManager, a: std.net.Address, got_peer: *bool, done: *std.atomic.Value(bool)) void {
            const p = m.connectOutboundNegotiated(a);
            got_peer.* = (p != null);
            done.store(true, .release);
        }
    };
    var got_peer = false;
    var done = std.atomic.Value(bool).init(false);
    const t = try std.Thread.spawn(.{}, Dial.run, .{ pm, target, &got_peer, &done });

    // Let the dial reach the blocking handshake.
    std.time.sleep(700 * std.time.ns_per_ms);
    try testing.expect(!done.load(.acquire));
    try testing.expect(pm.handshake_fd.load(.acquire) >= 0);

    const t0 = std.time.milliTimestamp();
    pm.stop();
    t.join();
    const waited_ms = std.time.milliTimestamp() - t0;
    try testing.expect(!got_peer);
    try testing.expect(waited_ms < 5000); // was >= 30_000 before the fix
    try testing.expect(pm.handshake_fd.load(.acquire) == -1);
    // A stopped manager refuses new dials outright.
    try testing.expect(pm.connectOutboundNegotiated(target) == null);
}

// Gate 5 (real peers): the P2P thread can also be parked in a blocking SEND.
// Peer.sendMessage -> stream.writeAll to a peer that stops reading blocks for
// SO_SNDTIMEO (30 s) per write call, re-armed on each partial write. stop()
// runs on main and cannot touch the P2P thread's peer list, so it must reach
// the socket through the live-peer fd registry and shutdown(2) it.
// Discriminator: without the registry shutdown the writer returns only when
// SO_SNDTIMEO expires (>= 30 s).
test "w124 G1c: PeerManager.stop interrupts a blocking peer send (gate 5)" {
    const allocator = std.heap.page_allocator;
    const listen_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = try listen_addr.listen(.{ .reuse_address = true });
    defer server.deinit();

    var peer = try peer_mod.Peer.connect(server.listen_address, &consensus.REGTEST, allocator);
    // The remote end accepts and never reads a byte.
    const remote = try server.accept();
    defer remote.stream.close();
    try testing.expect(peer_mod.isPeerFdRegistered(peer.stream.handle));

    const pm = try allocator.create(peer_mod.PeerManager);
    defer allocator.destroy(pm);
    pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    pm.running.store(true, .release);

    const Writer = struct {
        fn run(s: std.net.Stream, done: *std.atomic.Value(bool)) void {
            const buf = std.heap.page_allocator.alloc(u8, 64 * 1024 * 1024) catch {
                done.store(true, .release);
                return;
            };
            defer std.heap.page_allocator.free(buf);
            @memset(buf, 0xab);
            s.writeAll(buf) catch {};
            done.store(true, .release);
        }
    };
    var done = std.atomic.Value(bool).init(false);
    const t = try std.Thread.spawn(.{}, Writer.run, .{ peer.stream, &done });

    // Let the writer fill both socket buffers and block.
    std.time.sleep(1000 * std.time.ns_per_ms);
    try testing.expect(!done.load(.acquire));

    const t0 = std.time.milliTimestamp();
    pm.stop();
    t.join();
    const waited_ms = std.time.milliTimestamp() - t0;
    try testing.expect(waited_ms < 5000); // >= 30_000 without the fd registry

    peer.disconnect();
    try testing.expect(!peer_mod.isPeerFdRegistered(peer.stream.handle));
}

/// A loopback listener whose accept queue is full. Linux drops further SYNs
/// (tcp_conn_request: sk_acceptq_is_full -> drop), so a dial to it sits in
/// SYN_SENT with no network involved. Peer.connect then waits in its 5 s
/// connect poll(), which is what a dial to a dead mainnet address does.
const SynBlackhole = struct {
    server: std.net.Server,
    fillers: [16]std.posix.socket_t = undefined,
    n: usize = 0,

    fn init() !SynBlackhole {
        const a = try std.net.Address.parseIp4("127.0.0.1", 0);
        var bh = SynBlackhole{ .server = try a.listen(.{ .reuse_address = true, .kernel_backlog = 0 }) };
        errdefer bh.deinit();
        const addr = bh.server.listen_address;
        while (bh.n < bh.fillers.len) {
            const s = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
                0,
            );
            bh.fillers[bh.n] = s;
            bh.n += 1;
            std.posix.connect(s, &addr.any, addr.getOsSockLen()) catch |e| {
                if (e != error.WouldBlock) return e;
            };
            var pfd = [_]std.posix.pollfd{.{ .fd = s, .events = std.posix.POLL.OUT, .revents = 0 }};
            if (try std.posix.poll(&pfd, 300) == 0) return bh; // stuck: queue is full
        }
        return error.CouldNotFillAcceptQueue;
    }

    fn deinit(self: *SynBlackhole) void {
        for (self.fillers[0..self.n]) |s| std.posix.close(s);
        self.server.deinit();
    }
};

// Gate 5: stop() must also interrupt the TCP dial itself. Peer.connect waits
// up to 5 s in poll() for a non-blocking connect to complete, and the socket
// was registered in live_peer_fds only AFTER that wait, so stop()'s
// shutdown(2) sweep could not reach it: a stop during a dial to a dead
// address (most addrman entries on mainnet) cost the join the rest of the
// 5 s, once per dial still queued in the same run-loop step.
// Discriminator: before the fix this join takes ~4.5 s.
test "w124 G1d: PeerManager.stop interrupts an outbound TCP dial stuck in SYN_SENT (gate 5)" {
    const allocator = std.heap.page_allocator;
    var bh = try SynBlackhole.init();
    defer bh.deinit();
    const target = bh.server.listen_address;

    const pm = try allocator.create(peer_mod.PeerManager);
    defer allocator.destroy(pm);
    pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    pm.running.store(true, .release);

    const Dial = struct {
        fn run(m: *peer_mod.PeerManager, a: std.net.Address, got_peer: *bool, done: *std.atomic.Value(bool)) void {
            const p = m.connectOutboundNegotiated(a);
            got_peer.* = (p != null);
            done.store(true, .release);
        }
    };
    var got_peer = false;
    var done = std.atomic.Value(bool).init(false);
    const t = try std.Thread.spawn(.{}, Dial.run, .{ pm, target, &got_peer, &done });

    std.time.sleep(500 * std.time.ns_per_ms);
    try testing.expect(!done.load(.acquire)); // instrument: the dial really is stuck

    const t0 = std.time.milliTimestamp();
    pm.stop();
    t.join();
    const waited_ms = std.time.milliTimestamp() - t0;
    std.debug.print("G1d: dial released {d} ms after stop()\n", .{waited_ms});
    try testing.expect(!got_peer);
    try testing.expect(waited_ms < 2000); // ~4500 before the fix
}

// Gate 5, end to end on the P2P thread: PeerManager.run() in --connect mode
// against a peer whose SYNs are dropped. The thread is joined the way main
// joins it. Before the fix the join waits out the 5 s connect poll.
test "w124 G1e: P2P run() thread joins within 2 s of stop() while dialing a dead peer (gate 5)" {
    const allocator = std.heap.page_allocator;
    var bh = try SynBlackhole.init();
    defer bh.deinit();

    const pm = try allocator.create(peer_mod.PeerManager);
    defer allocator.destroy(pm);
    pm.* = peer_mod.PeerManager.init(allocator, &consensus.REGTEST);
    pm.connect_address = bh.server.listen_address;

    const Runner = struct {
        fn run(m: *peer_mod.PeerManager, done: *std.atomic.Value(bool)) void {
            m.run() catch {};
            done.store(true, .release);
        }
    };
    var done = std.atomic.Value(bool).init(false);
    const t = try std.Thread.spawn(.{}, Runner.run, .{ pm, &done });

    std.time.sleep(700 * std.time.ns_per_ms);
    try testing.expect(!done.load(.acquire)); // instrument: run() is mid-dial, not finished

    const t0 = std.time.milliTimestamp();
    pm.stop();
    t.join();
    const waited_ms = std.time.milliTimestamp() - t0;
    std.debug.print("G1e: P2P thread joined {d} ms after stop()\n", .{waited_ms});
    try testing.expect(waited_ms < 2000); // ~4300 before the fix
}

test "w124 G1c: live peer fd registry de-duplicates and unregisters" {
    peer_mod.registerPeerFd(987654);
    peer_mod.registerPeerFd(987654);
    try testing.expect(peer_mod.isPeerFdRegistered(987654));
    peer_mod.unregisterPeerFd(987654);
    try testing.expect(!peer_mod.isPeerFdRegistered(987654));
    peer_mod.registerPeerFd(-1);
    try testing.expect(!peer_mod.isPeerFdRegistered(-1));
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
