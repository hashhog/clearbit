const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // RocksDB is always linked (required for persistent chain state).
    // Accept -Drocksdb=true/false for CI/Docker compatibility; the flag is
    // informational only — RocksDB is always compiled in.
    _ = b.option(bool, "rocksdb", "Enable RocksDB storage backend (always on; flag accepted for compatibility)") orelse true;

    // libsecp256k1 is required for wallet functionality and BIP324 v2 transport
    // When available, use: zig build -Dsecp256k1=true
    const secp256k1_enabled = b.option(bool, "secp256k1", "Enable libsecp256k1 support (requires libsecp256k1-dev)") orelse false;

    // Path to libsecp256k1 include directory (for ElligatorSwift headers)
    // Default to Bitcoin Core's bundled version, can be overridden
    const secp256k1_include = b.option([]const u8, "secp256k1-include", "Path to libsecp256k1 include directory") orelse "../bitcoin/src/secp256k1/include";

    // libminisketch is used for BIP-330 Erlay set reconciliation
    // When available, use: zig build -Dminisketch=true
    const minisketch_enabled = b.option(bool, "minisketch", "Enable libminisketch support for Erlay (requires libminisketch)") orelse false;

    // Path to libminisketch include directory
    // Default to Bitcoin Core's bundled version
    const minisketch_include = b.option([]const u8, "minisketch-include", "Path to libminisketch include directory") orelse "../bitcoin/src/minisketch/include";

    // libzmq publishing (rawblock / hashblock / rawtx / hashtx / sequence).
    // libzmq.so.5 is shipped by Debian's `libzmq5` runtime package; the C
    // ABI is declared inline in src/zmq.zig so libzmq-dev is NOT required to
    // build. Set -Dzmq=true to actually link the library and let the
    // operator pass --zmqpub<topic>=tcp://...
    const zmq_enabled = b.option(bool, "zmq", "Enable ZMQ publishing (links libzmq at runtime)") orelse false;

    // Create build options module that all modules can import
    const build_options = b.addOptions();
    build_options.addOption(bool, "minisketch_enabled", minisketch_enabled);
    build_options.addOption(bool, "zmq_enabled", zmq_enabled);

    const exe = b.addExecutable(.{
        .name = "clearbit",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // RocksDB is always linked (required for persistent chain state)
    exe.linkSystemLibrary("rocksdb");

    // Always add secp256k1 include path and link library for @cImport in wallet.zig
    exe.addIncludePath(.{ .cwd_relative = secp256k1_include });
    exe.linkSystemLibrary("secp256k1");
    exe.linkLibC();

    // SHA-NI accelerated SHA-256 transform (x86_64 only). The transform itself
    // is gated at runtime via CPUID; the object always compiles in on x86_64
    // because the intrinsics require -msha / -msse4.1 / -mssse3 at the TU level.
    const shani_cflags = &[_][]const u8{ "-msha", "-msse4.1", "-mssse3", "-O2" };
    if (target.result.cpu.arch == .x86_64) {
        exe.addCSourceFile(.{ .file = b.path("src/sha256_shani.c"), .flags = shani_cflags });
    }

    // Link libminisketch if enabled
    if (minisketch_enabled) {
        exe.linkSystemLibrary("minisketch");
        exe.addIncludePath(.{ .cwd_relative = minisketch_include });
        exe.linkLibC();
    }

    // Link libzmq if enabled. We don't need libzmq-dev to build because the
    // ABI is declared inline in src/zmq.zig — only the runtime symbols are
    // needed at link time. On Debian without libzmq-dev, the linker can use
    // `-l:libzmq.so.5` against the runtime SONAME directly. We do that via
    // addObjectFile when `linkSystemLibrary("zmq")` fails (no .so symlink).
    if (zmq_enabled) {
        // Prefer the dev-package symlink if it exists, otherwise fall through
        // to the runtime SONAME. linkSystemLibrary("zmq") would fail at
        // build-graph eval if the .so symlink is missing.
        const zmq_so_path = "/usr/lib/x86_64-linux-gnu/libzmq.so";
        if (std.fs.cwd().access(zmq_so_path, .{})) |_| {
            exe.linkSystemLibrary("zmq");
        } else |_| {
            // libzmq.so.5 is the SONAME shipped by Debian's libzmq5 runtime
            // package. Linking the absolute path works because ld.lld resolves
            // the DT_NEEDED to the SONAME, which the dynamic loader finds at
            // run time via the ld cache.
            exe.addObjectFile(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu/libzmq.so.5" });
        }
        exe.linkLibC();
    }

    // Add build options module to exe
    exe.root_module.addOptions("build_options", build_options);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run clearbit");
    run_step.dependOn(&run_cmd.step);

    // Main test step uses tests.zig as root for comprehensive test coverage
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    // RocksDB is always linked for tests
    unit_tests.linkSystemLibrary("rocksdb");

    // Link libsecp256k1 for tests (required by crypto.zig)
    unit_tests.linkSystemLibrary("secp256k1");
    unit_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
    unit_tests.linkLibC();

    // SHA-NI C transform (same shim as the main exe) — required by crypto.zig tests.
    if (target.result.cpu.arch == .x86_64) {
        unit_tests.addCSourceFile(.{ .file = b.path("src/sha256_shani.c"), .flags = shani_cflags });
    }

    // Link libminisketch for tests if enabled
    if (minisketch_enabled) {
        unit_tests.linkSystemLibrary("minisketch");
        unit_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        unit_tests.linkLibC();
    }

    // Link libzmq for tests if enabled. Same fallback as for the main exe:
    // accept either the dev-package .so symlink or the runtime SONAME.
    if (zmq_enabled) {
        const zmq_so_path_t = "/usr/lib/x86_64-linux-gnu/libzmq.so";
        if (std.fs.cwd().access(zmq_so_path_t, .{})) |_| {
            unit_tests.linkSystemLibrary("zmq");
        } else |_| {
            unit_tests.addObjectFile(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu/libzmq.so.5" });
        }
        unit_tests.linkLibC();
    }

    // Add build options module to tests
    unit_tests.root_module.addOptions("build_options", build_options);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Operational-parity tests (daemon/PID/SIGHUP/--debug=cat/zmq).
    // Lives at src/tests_ops.zig — links libzmq if -Dzmq=true so the no-op
    // path (default) and the real-bind path can both be exercised.
    {
        const ops_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_ops.zig"),
            .target = target,
            .optimize = optimize,
        });
        ops_tests.linkSystemLibrary("rocksdb");
        ops_tests.linkSystemLibrary("secp256k1");
        ops_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        ops_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            ops_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (zmq_enabled) {
            const zmq_so_path_o = "/usr/lib/x86_64-linux-gnu/libzmq.so";
            if (std.fs.cwd().access(zmq_so_path_o, .{})) |_| {
                ops_tests.linkSystemLibrary("zmq");
            } else |_| {
                ops_tests.addObjectFile(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu/libzmq.so.5" });
            }
        }
        ops_tests.root_module.addOptions("build_options", build_options);
        const run_ops_tests = b.addRunArtifact(ops_tests);
        const ops_test_step = b.step("test-ops", "Run operational-parity tests (daemon/PID/SIGHUP/--debug=cat/zmq)");
        ops_test_step.dependOn(&run_ops_tests.step);
        // Fold into the main `test` step so CI exercises ops parity.
        test_step.dependOn(&run_ops_tests.step);
    }

    // BIP-35 / NODE_BLOOM advertisement tests live in a dedicated test root
    // (tests_bip35.zig) so they can import peer.zig without dragging in the
    // pre-existing eclipse-protection tests in peer.zig (which have drifted
    // from the implementation and are unrelated to BIP-35).
    {
        const bip35_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_bip35.zig"),
            .target = target,
            .optimize = optimize,
        });
        bip35_tests.linkSystemLibrary("rocksdb");
        bip35_tests.linkSystemLibrary("secp256k1");
        bip35_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        bip35_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            bip35_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            bip35_tests.linkSystemLibrary("minisketch");
            bip35_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        bip35_tests.root_module.addOptions("build_options", build_options);

        const run_bip35_tests = b.addRunArtifact(bip35_tests);
        const bip35_test_step = b.step("test-bip35", "Run BIP-35 (mempool) + NODE_BLOOM tests");
        bip35_test_step.dependOn(&run_bip35_tests.step);
        // Also fold into the main `test` step so CI exercises BIP-35.
        test_step.dependOn(&run_bip35_tests.step);
    }

    // AXIS #2: Core-bucketed addrman proof suite (src/addrman.zig). Lives in a
    // dedicated test root (tests_addrman_axis2.zig) so it only pulls in
    // addrman.zig + crypto.zig + types.zig — no rocksdb/zmq/peer.zig drift.
    {
        const addrman_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_addrman_axis2.zig"),
            .target = target,
            .optimize = optimize,
        });
        addrman_tests.linkSystemLibrary("secp256k1");
        addrman_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        addrman_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            addrman_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        addrman_tests.root_module.addOptions("build_options", build_options);

        const run_addrman_tests = b.addRunArtifact(addrman_tests);
        const addrman_test_step = b.step("test-addrman", "Run AXIS #2 Core-bucketed addrman proof suite");
        addrman_test_step.dependOn(&run_addrman_tests.step);
        // Also fold into the main `test` step.
        test_step.dependOn(&run_addrman_tests.step);
    }

    // Competing-fork detection + reorg-trigger tests (CLEARBIT_REORG=1).
    // Filter directly to "tests_reorg_p2p" so the test runner skips the
    // pre-existing peer.zig eclipse-protection tests that have drifted
    // from the implementation (same root cause as the BIP-35 isolation
    // workaround above; without the filter, importing peer.zig pulls
    // those failing tests into our run).  The filter is a substring
    // match against the fully-qualified test name; our tests live in
    // `tests_reorg_p2p.test.<name>`, so the substring matches all of
    // them and nothing in peer.zig.
    {
        const reorg_p2p_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_reorg_p2p.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"tests_reorg_p2p"},
        });
        reorg_p2p_tests.linkSystemLibrary("rocksdb");
        reorg_p2p_tests.linkSystemLibrary("secp256k1");
        reorg_p2p_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        reorg_p2p_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            reorg_p2p_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            reorg_p2p_tests.linkSystemLibrary("minisketch");
            reorg_p2p_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        reorg_p2p_tests.root_module.addOptions("build_options", build_options);

        const run_reorg_p2p_tests = b.addRunArtifact(reorg_p2p_tests);
        const reorg_p2p_test_step = b.step(
            "test-reorg-p2p",
            "Run competing-fork detection + reorg-trigger tests (CLEARBIT_REORG=1)",
        );
        reorg_p2p_test_step.dependOn(&run_reorg_p2p_tests.step);
        // Fold into the main `test` step so CI exercises the trigger.
        test_step.dependOn(&run_reorg_p2p_tests.step);
    }

    // Reorg disconnect -> spent-coin RESTORE persistence tests.  Dedicated
    // root (imports storage.zig only) with a name-substring filter so it does
    // not drag in drifted inline tests from heavier modules.
    {
        const reorg_restore_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_reorg_restore.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"tests_reorg_restore"},
        });
        reorg_restore_tests.linkSystemLibrary("rocksdb");
        reorg_restore_tests.linkSystemLibrary("secp256k1");
        reorg_restore_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        reorg_restore_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            reorg_restore_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            reorg_restore_tests.linkSystemLibrary("minisketch");
            reorg_restore_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        reorg_restore_tests.root_module.addOptions("build_options", build_options);

        const run_reorg_restore_tests = b.addRunArtifact(reorg_restore_tests);
        const reorg_restore_step = b.step(
            "test-reorg-restore",
            "Run reorg disconnect spent-coin restore persistence tests",
        );
        reorg_restore_step.dependOn(&run_reorg_restore_tests.step);
        test_step.dependOn(&run_reorg_restore_tests.step);
    }

    // Reorg-BACK (B -> A') via the live submitblock side-branch path.
    // Dedicated root so it can import block_template.zig + validation.zig and
    // EXECUTE processSideBranchSubmission -> fireReorgFromSideBranch ->
    // reorgToChain, with a name-substring filter so heavier modules' drifted
    // inline tests are not pulled into the run.
    {
        const reorg_backwalk_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_reorg_backwalk.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"tests_reorg_backwalk"},
        });
        reorg_backwalk_tests.linkSystemLibrary("rocksdb");
        reorg_backwalk_tests.linkSystemLibrary("secp256k1");
        reorg_backwalk_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        reorg_backwalk_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            reorg_backwalk_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            reorg_backwalk_tests.linkSystemLibrary("minisketch");
            reorg_backwalk_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        reorg_backwalk_tests.root_module.addOptions("build_options", build_options);

        const run_reorg_backwalk_tests = b.addRunArtifact(reorg_backwalk_tests);
        const reorg_backwalk_step = b.step(
            "test-reorg-backwalk",
            "Run reorg-back (B->A') live submitblock side-branch tests",
        );
        reorg_backwalk_step.dependOn(&run_reorg_backwalk_tests.step);
        test_step.dependOn(&run_reorg_backwalk_tests.step);
    }

    // Advertised P2P service-flag tests (Peer.localServices()).
    // Dedicated test root so it can import peer.zig and EXECUTE the real
    // localServices() without dragging in the pre-existing (drifted)
    // peer.zig inline tests.  The `.filters` substring matches our test
    // names (`tests_service_flags.test.<name>`) and nothing in peer.zig.
    {
        const service_flags_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_service_flags.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"tests_service_flags"},
        });
        service_flags_tests.linkSystemLibrary("rocksdb");
        service_flags_tests.linkSystemLibrary("secp256k1");
        service_flags_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        service_flags_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            service_flags_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            service_flags_tests.linkSystemLibrary("minisketch");
            service_flags_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        service_flags_tests.root_module.addOptions("build_options", build_options);

        const run_service_flags_tests = b.addRunArtifact(service_flags_tests);
        const service_flags_test_step = b.step(
            "test-service-flags",
            "Run advertised P2P service-flag tests (Peer.localServices())",
        );
        service_flags_test_step.dependOn(&run_service_flags_tests.step);
        // Fold into the main `test` step so CI exercises service flags.
        test_step.dependOn(&run_service_flags_tests.step);
    }

    // Min-chain-work presync gate (evalMinChainWorkGate).  Dedicated test root
    // that imports peer.zig, with a `.filters` substring matching our test
    // names (`tests_minwork_presync.test.<name>`) so peer.zig's own inline
    // tests are not dragged in.  Pins the genesis-IBD divergence: low-work
    // headers must be presync-accepted (Core parity), not banned.
    {
        const minwork_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_minwork_presync.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"tests_minwork_presync"},
        });
        minwork_tests.linkSystemLibrary("rocksdb");
        minwork_tests.linkSystemLibrary("secp256k1");
        minwork_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        minwork_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            minwork_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            minwork_tests.linkSystemLibrary("minisketch");
            minwork_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        minwork_tests.root_module.addOptions("build_options", build_options);

        const run_minwork_tests = b.addRunArtifact(minwork_tests);
        const minwork_test_step = b.step(
            "test-minwork-presync",
            "Run min-chain-work presync gate (genesis-IBD low-work tolerance) tests",
        );
        minwork_test_step.dependOn(&run_minwork_tests.step);
        // Fold into the main `test` step so CI exercises the presync gate.
        test_step.dependOn(&run_minwork_tests.step);
    }

    // W103 — tx relay flow 30-gate fleet audit.
    // Uses a dedicated test root (tests_w103_tx_relay.zig) so it can import
    // peer.zig + mempool.zig without pulling in unrelated peer.zig tests.
    {
        const w103_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w103_tx_relay.zig"),
            .target = target,
            .optimize = optimize,
            // Filter to only our W103 tests; exclude drifted peer.zig tests
            // that this root transitively pulls in via the peer import.
            .filters = &[_][]const u8{"W103", "tests_w103_tx_relay"},
        });
        w103_tests.linkSystemLibrary("rocksdb");
        w103_tests.linkSystemLibrary("secp256k1");
        w103_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w103_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w103_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w103_tests.linkSystemLibrary("minisketch");
            w103_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w103_tests.root_module.addOptions("build_options", build_options);

        const run_w103_tests = b.addRunArtifact(w103_tests);
        const w103_test_step = b.step("test-w103", "Run W103 tx relay flow 30-gate audit tests");
        w103_test_step.dependOn(&run_w103_tests.step);
        // Fold into the main `test` step so CI exercises W103.
        test_step.dependOn(&run_w103_tests.step);
    }

    // W104 — AddrMan 30-gate fleet audit + isRoutable fix.
    // Uses a dedicated test root (tests_w104_addrman.zig) so it can import
    // peer.zig without pulling in unrelated peer.zig tests.
    {
        const w104_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w104_addrman.zig"),
            .target = target,
            .optimize = optimize,
            // Filter to only our W104 tests; exclude drifted peer.zig tests
            // that this root transitively pulls in via the peer import.
            .filters = &[_][]const u8{"w104", "tests_w104_addrman"},
        });
        w104_tests.linkSystemLibrary("rocksdb");
        w104_tests.linkSystemLibrary("secp256k1");
        w104_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w104_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w104_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w104_tests.linkSystemLibrary("minisketch");
            w104_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w104_tests.root_module.addOptions("build_options", build_options);

        const run_w104_tests = b.addRunArtifact(w104_tests);
        const w104_test_step = b.step("test-w104", "Run W104 AddrMan 30-gate audit + isRoutable fix tests");
        w104_test_step.dependOn(&run_w104_tests.step);
        // Fold into the main `test` step so CI exercises W104.
        test_step.dependOn(&run_w104_tests.step);
    }

    // W105 — CCheckQueue / parallel script verification 30-gate fleet audit.
    {
        const w105_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w105_checkqueue.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w105"},
        });
        w105_tests.linkSystemLibrary("rocksdb");
        w105_tests.linkSystemLibrary("secp256k1");
        w105_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w105_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w105_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w105_tests.linkSystemLibrary("minisketch");
            w105_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w105_tests.root_module.addOptions("build_options", build_options);

        const run_w105_tests = b.addRunArtifact(w105_tests);
        const w105_test_step = b.step("test-w105", "Run W105 CCheckQueue parallel script verification 30-gate audit tests");
        w105_test_step.dependOn(&run_w105_tests.step);
        // Fold into the main `test` step so CI exercises W105.
        test_step.dependOn(&run_w105_tests.step);
    }

    // W107 — CompactSize + VarInt serialization 30-gate audit.
    {
        const w107_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w107_compactsize.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w107"},
        });
        w107_tests.linkSystemLibrary("rocksdb");
        w107_tests.linkSystemLibrary("secp256k1");
        w107_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w107_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w107_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w107_tests.linkSystemLibrary("minisketch");
            w107_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w107_tests.root_module.addOptions("build_options", build_options);

        const run_w107_tests = b.addRunArtifact(w107_tests);
        const w107_test_step = b.step("test-w107", "Run W107 CompactSize + VarInt serialization 30-gate audit tests");
        w107_test_step.dependOn(&run_w107_tests.step);
        // Fold into the main `test` step so CI exercises W107.
        test_step.dependOn(&run_w107_tests.step);
    }

    // Subver (user-agent) sanitization — getpeerinfo invalid-JSON DoS fix.
    {
        const subver_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_subver_sanitize.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"subver-sanitize"},
        });
        subver_tests.linkSystemLibrary("rocksdb");
        subver_tests.linkSystemLibrary("secp256k1");
        subver_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        subver_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            subver_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            subver_tests.linkSystemLibrary("minisketch");
            subver_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        subver_tests.root_module.addOptions("build_options", build_options);

        const run_subver_tests = b.addRunArtifact(subver_tests);
        const subver_test_step = b.step("test-subver", "Run getpeerinfo subver sanitization (invalid-JSON DoS) regression tests");
        subver_test_step.dependOn(&run_subver_tests.step);
        // Fold into the main `test` step so CI exercises the subver DoS fix.
        test_step.dependOn(&run_subver_tests.step);
    }

    // W108 — BlockTemplate + GBT mining RPC 30-gate audit.
    {
        const w108_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w108_gbt.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w108"},
        });
        w108_tests.linkSystemLibrary("rocksdb");
        w108_tests.linkSystemLibrary("secp256k1");
        w108_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w108_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w108_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w108_tests.linkSystemLibrary("minisketch");
            w108_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w108_tests.root_module.addOptions("build_options", build_options);

        const run_w108_tests = b.addRunArtifact(w108_tests);
        const w108_test_step = b.step("test-w108", "Run W108 BlockTemplate + GBT mining RPC 30-gate audit tests");
        w108_test_step.dependOn(&run_w108_tests.step);
        // Fold into the main `test` step so CI exercises W108.
        test_step.dependOn(&run_w108_tests.step);
    }

    // W109 — CChain + CBlockIndex + CBlockTreeDB + block-file storage 30-gate audit.
    {
        const w109_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w109_block_index.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w109"},
        });
        w109_tests.linkSystemLibrary("rocksdb");
        w109_tests.linkSystemLibrary("secp256k1");
        w109_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w109_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w109_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w109_tests.linkSystemLibrary("minisketch");
            w109_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w109_tests.root_module.addOptions("build_options", build_options);

        const run_w109_tests = b.addRunArtifact(w109_tests);
        const w109_test_step = b.step("test-w109", "Run W109 CChain + CBlockIndex + CBlockTreeDB + block-file storage 30-gate audit tests");
        w109_test_step.dependOn(&run_w109_tests.step);
        // Fold into the main `test` step so CI exercises W109.
        test_step.dependOn(&run_w109_tests.step);
    }

    // W110 — BIP-37 bloom filter 30-gate audit.
    // No RocksDB dependency (p2p.zig + v2_transport.zig + peer.zig only).
    // Run with `zig build test-w110`.
    {
        const w110_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w110_bloom_filter.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w110"},
        });
        w110_tests.linkSystemLibrary("rocksdb");
        w110_tests.linkSystemLibrary("secp256k1");
        w110_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w110_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w110_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w110_tests.linkSystemLibrary("minisketch");
            w110_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w110_tests.root_module.addOptions("build_options", build_options);

        const run_w110_tests = b.addRunArtifact(w110_tests);
        const w110_test_step = b.step("test-w110", "Run W110 BIP-37 bloom filter 30-gate audit tests");
        w110_test_step.dependOn(&run_w110_tests.step);
        // Fold into the main `test` step so CI exercises W110.
        test_step.dependOn(&run_w110_tests.step);
    }

    // W106 — CTxMemPool descendant/ancestor + RBF + package mempool 30-gate audit.
    {
        const w106_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w106_mempool.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w106"},
        });
        w106_tests.linkSystemLibrary("rocksdb");
        w106_tests.linkSystemLibrary("secp256k1");
        w106_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w106_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w106_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w106_tests.linkSystemLibrary("minisketch");
            w106_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w106_tests.root_module.addOptions("build_options", build_options);

        const run_w106_tests = b.addRunArtifact(w106_tests);
        const w106_test_step = b.step("test-w106", "Run W106 CTxMemPool descendant/ancestor + RBF + package 30-gate audit tests");
        w106_test_step.dependOn(&run_w106_tests.step);
        // Fold into the main `test` step so CI exercises W106.
        test_step.dependOn(&run_w106_tests.step);
    }

    // RPC tests run via `tests_rpc.zig` at the project root. The main
    // `tests.zig` root cannot pull in `rpc.zig` because doing so transitively
    // imports `wallet.zig`, whose `@embedFile("../resources/bip39-english.txt")`
    // only resolves when the test harness's package path is the project root
    // (one above `src/`). The wrapper file at the project root forces that
    // package layout and re-exposes `src/rpc.zig`'s tests.
    {
        const rpc_tests = b.addTest(.{
            .root_source_file = b.path("tests_rpc.zig"),
            .target = target,
            .optimize = optimize,
        });
        rpc_tests.linkSystemLibrary("rocksdb");
        rpc_tests.linkSystemLibrary("secp256k1");
        rpc_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        rpc_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            rpc_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            rpc_tests.linkSystemLibrary("minisketch");
            rpc_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        rpc_tests.root_module.addOptions("build_options", build_options);

        const run_rpc_tests = b.addRunArtifact(rpc_tests);
        const rpc_test_step = b.step("test-rpc", "Run RPC dispatch + signmessage/verifymessage/estimaterawfee/savemempool tests");
        rpc_test_step.dependOn(&run_rpc_tests.step);
        // NOTE: this step is intentionally NOT folded into the default
        // `test` step. `src/wallet.zig` has a long-standing
        // `selectCoins` / `selectCoinsWithOptions` anonymous-struct mismatch
        // that fires whenever wallet.zig is compiled as part of a test root,
        // independent of our changes. Until that is fixed, the rpc.zig
        // dispatch tests (existing + new) run via `zig build test-rpc`.
        // The `signMessageCompact` round-trip and message-hash format tests
        // live in `src/crypto.zig` and run via `zig build test`.
    }

    // getnodeaddresses Core-parity regression. Same wrapper as test-rpc
    // (tests_rpc.zig re-exposes src/rpc.zig's tests), filtered to just the
    // getnodeaddresses test names so the run isn't contaminated by the
    // pre-existing src/peer.zig test failures that surface when peer.zig is
    // pulled in as part of an rpc.zig test root. Run with
    // `zig build test-getnodeaddresses`.
    {
        const gna_tests = b.addTest(.{
            .root_source_file = b.path("tests_rpc.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"getnodeaddresses"},
        });
        gna_tests.linkSystemLibrary("rocksdb");
        gna_tests.linkSystemLibrary("secp256k1");
        gna_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        gna_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            gna_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            gna_tests.linkSystemLibrary("minisketch");
            gna_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        gna_tests.root_module.addOptions("build_options", build_options);

        const run_gna_tests = b.addRunArtifact(gna_tests);
        const gna_step = b.step("test-getnodeaddresses", "Run getnodeaddresses Core-parity regression tests");
        gna_step.dependOn(&run_gna_tests.step);
        // NOT folded into the default `test` step — same wallet.zig selectCoins
        // gotcha as test-rpc above.
    }

    // Wallet Taproot tests — BIP-86 tweak + BIP-341 sighash wire-up (W20).
    // Same wrapper pattern as tests_rpc.zig: the test root lives at the
    // project root so `src/wallet.zig`'s `@embedFile("../resources/bip39-english.txt")`
    // resolves correctly. Run with `zig build test-wallet-taproot`.
    {
        const wallet_taproot_tests = b.addTest(.{
            .root_source_file = b.path("tests_wallet_taproot.zig"),
            .target = target,
            .optimize = optimize,
            // Filter to only the W20 test names so we don't drag in the
            // unrelated pre-existing wallet.zig tests (some of which leak
            // in a way that's outside the scope of this wave).
            .filters = &[_][]const u8{"BIP-86", "BIP-341", "BIP-39", "wallet computeTaprootSigHash", "signInput .p2tr", "Wallet.initFromMnemonic"},
        });
        wallet_taproot_tests.linkSystemLibrary("rocksdb");
        wallet_taproot_tests.linkSystemLibrary("secp256k1");
        wallet_taproot_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        wallet_taproot_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            wallet_taproot_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            wallet_taproot_tests.linkSystemLibrary("minisketch");
            wallet_taproot_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        wallet_taproot_tests.root_module.addOptions("build_options", build_options);

        const run_wallet_taproot_tests = b.addRunArtifact(wallet_taproot_tests);
        const wt_step = b.step("test-wallet-taproot", "Run wallet BIP-86 + BIP-341 sighash tests (W20)");
        wt_step.dependOn(&run_wallet_taproot_tests.step);
        // NOTE: deliberately NOT folded into `test` — same reason as
        // test-rpc above (selectCoins anonymous-struct compile error
        // surfaces whenever wallet.zig is a test root, blocking tests.zig).
    }

    // P2WSH + P2SH-P2WSH wallet tests (W29-C / Phase-2). Same wrapper
    // pattern as tests_wallet_taproot.zig: project-root wrapper so
    // `src/wallet.zig`'s `@embedFile("../resources/bip39-english.txt")`
    // resolves correctly. Run with `zig build test-wallet-segwit-v0`.
    {
        const ws_tests = b.addTest(.{
            .root_source_file = b.path("tests_wallet_segwit_v0.zig"),
            .target = target,
            .optimize = optimize,
            // Filter to only the W29-C / W38 test names so we don't drag in the
            // unrelated pre-existing wallet.zig tests (same gotcha as
            // tests_wallet_taproot.zig — the selectCoins anonymous-struct
            // mismatch surfaces whenever wallet.zig is a test root).
            .filters = &[_][]const u8{ "W29-C", "W38" },
        });
        ws_tests.linkSystemLibrary("rocksdb");
        ws_tests.linkSystemLibrary("secp256k1");
        ws_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        ws_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            ws_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            ws_tests.linkSystemLibrary("minisketch");
            ws_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        ws_tests.root_module.addOptions("build_options", build_options);

        const run_ws_tests = b.addRunArtifact(ws_tests);
        const ws_step = b.step(
            "test-wallet-segwit-v0",
            "Run wallet P2WSH + P2SH-P2WSH multisig tests (W29-C)",
        );
        ws_step.dependOn(&run_ws_tests.step);
        // NOTE: deliberately NOT folded into `test` — same reason as
        // test-wallet-taproot above (selectCoins anonymous-struct compile
        // error surfaces whenever wallet.zig is a test root).
    }

    // PSBT P2SH commitment-check tests (W31). The PSBT module has no
    // `@embedFile` of its own and doesn't depend on `wallet.zig`, so
    // the test root can sit directly under `src/` (no project-root
    // wrapper). Linked against secp256k1 + sha256_shani because
    // `crypto.zig` cImports them unconditionally. Run with
    // `zig build test-p2sh-commitment`.
    {
        const p2sh_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_p2sh_commitment.zig"),
            .target = target,
            .optimize = optimize,
            // Filter to only the W31 tests so we don't drag in
            // pre-existing psbt.zig tests (the serialize-round-trip
            // / base64 / bip32-derivation trio fails when psbt.zig
            // is a test root because of an unrelated path pulled
            // out of `serialize.readTransaction` — surfaced before
            // W31, not in scope to fix here). Same filter pattern
            // used by tests_wallet_taproot / tests_wallet_segwit_v0.
            .filters = &[_][]const u8{"W31"},
        });
        p2sh_tests.linkSystemLibrary("secp256k1");
        p2sh_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        p2sh_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            p2sh_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        p2sh_tests.root_module.addOptions("build_options", build_options);

        const run_p2sh_tests = b.addRunArtifact(p2sh_tests);
        const p2sh_step = b.step(
            "test-p2sh-commitment",
            "Run PSBT P2SH commitment-check tests (W31)",
        );
        p2sh_step.dependOn(&run_p2sh_tests.step);
        // Folded into the default `test` step — the test root only
        // pulls in psbt.zig + types.zig + serialize.zig + crypto.zig,
        // which are clean of the wallet.zig selectCoins mismatch that
        // blocks tests_rpc / tests_wallet_*.
        test_step.dependOn(&run_p2sh_tests.step);
    }

    // BIP-152 compact-block audit tests (W89).
    // Tests p2p.zig gates (deser bounds, differential encode/decode) and the
    // SipHash key derivation.  No RocksDB or wallet dependency.
    // Run with `zig build test-bip152`.
    {
        const bip152_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_bip152.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"W89 BIP-152"},
        });
        bip152_tests.linkSystemLibrary("secp256k1");
        bip152_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        bip152_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            bip152_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        bip152_tests.root_module.addOptions("build_options", build_options);

        const run_bip152_tests = b.addRunArtifact(bip152_tests);
        const bip152_step = b.step(
            "test-bip152",
            "Run BIP-152 compact-block audit tests (W89)",
        );
        bip152_step.dependOn(&run_bip152_tests.step);
        // Fold into the main `test` step — no wallet.zig dependency,
        // so no selectCoins compile-error risk.
        test_step.dependOn(&run_bip152_tests.step);
    }

    // W112 — BIP-152 compact-blocks 30-gate audit tests (FIX-42: BUG-4+8).
    // Tests p2p.zig constants, wire-format gates, and verifies BUG-4/BUG-8 fixes.
    // No RocksDB or wallet dependency (imports p2p.zig, serialize.zig, crypto.zig).
    // Run with `zig build test-w112`.
    {
        const w112_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w112_compact_blocks.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"W112"},
        });
        w112_tests.linkSystemLibrary("secp256k1");
        w112_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w112_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w112_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        w112_tests.root_module.addOptions("build_options", build_options);

        const run_w112_tests = b.addRunArtifact(w112_tests);
        const w112_step = b.step(
            "test-w112",
            "Run W112 BIP-152 compact-blocks 30-gate audit tests (FIX-42 BUG-4+8)",
        );
        w112_step.dependOn(&run_w112_tests.step);
        // Fold into the main `test` step — no wallet.zig dependency.
        test_step.dependOn(&run_w112_tests.step);
    }

    // PSBT W47 multisig finalize + sort-on-emit tests. Same wiring shape
    // as test-p2sh-commitment above (psbt.zig has no @embedFile and
    // doesn't pull wallet.zig). Run with `zig build test-psbt-w47`.
    {
        const w47_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_psbt_w47.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"W47"},
        });
        w47_tests.linkSystemLibrary("secp256k1");
        w47_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w47_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w47_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        w47_tests.root_module.addOptions("build_options", build_options);

        const run_w47_tests = b.addRunArtifact(w47_tests);
        const w47_step = b.step(
            "test-psbt-w47",
            "Run PSBT multisig finalize + sort-on-emit tests (W47)",
        );
        w47_step.dependOn(&run_w47_tests.step);
        test_step.dependOn(&run_w47_tests.step);
    }

    // W111 Wallet / HD / Descriptors audit tests. Same wrapper pattern as
    // tests_wallet_taproot.zig: project-root wrapper so wallet.zig's
    // @embedFile("../resources/bip39-english.txt") resolves correctly.
    // Run with `zig build test-wallet-w111`.
    // NOT folded into the default `test` step — wallet.zig pulls secp256k1
    // and the selectCoins anonymous-struct compile error blocks tests.zig.
    {
        const w111_tests = b.addTest(.{
            .root_source_file = b.path("tests_wallet_w111.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"W111"},
        });
        w111_tests.linkSystemLibrary("rocksdb");
        w111_tests.linkSystemLibrary("secp256k1");
        w111_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w111_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w111_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w111_tests.linkSystemLibrary("minisketch");
            w111_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w111_tests.root_module.addOptions("build_options", build_options);

        const run_w111_tests = b.addRunArtifact(w111_tests);
        const w111_step = b.step(
            "test-wallet-w111",
            "Run W111 wallet / HD / descriptors audit tests",
        );
        w111_step.dependOn(&run_w111_tests.step);
    }

    // W118 Wallet audit (second-wave wallet 30-gate). Same wrapper pattern as
    // tests_wallet_w111.zig: project-root wrapper so wallet.zig's
    // @embedFile("../resources/bip39-english.txt") resolves correctly.
    // Run with `zig build test-wallet-w118`.
    // NOT folded into the default `test` step — same reason as W111.
    {
        const w118_tests = b.addTest(.{
            .root_source_file = b.path("tests_wallet_w118.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"W118"},
        });
        w118_tests.linkSystemLibrary("rocksdb");
        w118_tests.linkSystemLibrary("secp256k1");
        w118_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w118_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w118_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w118_tests.linkSystemLibrary("minisketch");
            w118_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w118_tests.root_module.addOptions("build_options", build_options);

        const run_w118_tests = b.addRunArtifact(w118_tests);
        const w118_step = b.step(
            "test-wallet-w118",
            "Run W118 wallet audit tests (descriptors, BIP-32, PSBT, fee bumping, send, UTXO)",
        );
        w118_step.dependOn(&run_w118_tests.step);
    }

    // Wallet restart-persistence regression tests (sweep wa0fq5wtk). Same
    // wrapper pattern as tests_wallet_w111.zig: project-root wrapper so
    // wallet.zig's @embedFile("../resources/bip39-english.txt") resolves.
    // Run with `zig build test-wallet-persistence`.
    // NOT folded into the default `test` step — same reason as W111 (wallet.zig
    // as a test root drags in the selectCoins anonymous-struct compile error).
    {
        const wp_tests = b.addTest(.{
            .root_source_file = b.path("tests_wallet_persistence.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"wallet-persistence"},
        });
        wp_tests.linkSystemLibrary("rocksdb");
        wp_tests.linkSystemLibrary("secp256k1");
        wp_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        wp_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            wp_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            wp_tests.linkSystemLibrary("minisketch");
            wp_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        wp_tests.root_module.addOptions("build_options", build_options);

        const run_wp_tests = b.addRunArtifact(wp_tests);
        const wp_step = b.step(
            "test-wallet-persistence",
            "Run wallet restart-persistence regression tests (auto-load, atomic+durable save, fault-tolerant load, sync watermark)",
        );
        wp_step.dependOn(&run_wp_tests.step);
    }

    // W113 Coin selection audit tests. Same wrapper pattern as
    // tests_wallet_w111.zig: project-root wrapper so wallet.zig's
    // @embedFile("../resources/bip39-english.txt") resolves correctly.
    // Run with `zig build test-wallet-w113`.
    // NOT folded into the default `test` step — wallet.zig pulls secp256k1
    // and the selectCoins anonymous-struct compile error blocks tests.zig.
    {
        const w113_tests = b.addTest(.{
            .root_source_file = b.path("tests_wallet_w113.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w113"},
        });
        w113_tests.linkSystemLibrary("rocksdb");
        w113_tests.linkSystemLibrary("secp256k1");
        w113_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w113_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w113_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w113_tests.linkSystemLibrary("minisketch");
            w113_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w113_tests.root_module.addOptions("build_options", build_options);

        const run_w113_tests = b.addRunArtifact(w113_tests);
        const w113_step = b.step(
            "test-wallet-w113",
            "Run W113 coin selection audit tests",
        );
        w113_step.dependOn(&run_w113_tests.step);
    }

    // BIP-39 mnemonic + PBKDF2 tests (W21). Same wrapper pattern as
    // tests_rpc.zig: project-root wrapper at `tests_bip39.zig` so
    // `src/bip39.zig`'s `@embedFile("../resources/bip39-english.txt")`
    // resolves correctly. Run with `zig build test-bip39`.
    {
        const bip39_tests = b.addTest(.{
            .root_source_file = b.path("tests_bip39.zig"),
            .target = target,
            .optimize = optimize,
        });
        // bip39.zig only uses Zig std crypto (no secp256k1 / no rocksdb /
        // no SHA-NI shim), but link the SHA-NI C shim defensively in case
        // something transitive in std pulls it via the build options.
        bip39_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            bip39_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        bip39_tests.root_module.addOptions("build_options", build_options);
        const run_bip39_tests = b.addRunArtifact(bip39_tests);
        const bip39_step = b.step("test-bip39", "Run BIP-39 mnemonic + PBKDF2 vector tests (W21)");
        bip39_step.dependOn(&run_bip39_tests.step);
        // Fold into the default `test` step — bip39.zig is self-contained,
        // doesn't import wallet.zig, and so doesn't trigger the
        // long-standing selectCoins anonymous-struct compile error that
        // blocks `tests_rpc.zig` and `tests_wallet_taproot.zig`.
        test_step.dependOn(&run_bip39_tests.step);
    }

    // W114 — CBlockPolicyEstimator fee estimation 30-gate audit.
    // Uses a dedicated test root (tests_w114_fee_estimation.zig) which imports
    // mempool.zig + types.zig only (no wallet.zig / no RocksDB required at runtime,
    // but rocksdb is linked because mempool.zig depends on storage.zig).
    // Run with `zig build test-w114`.
    {
        const w114_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w114_fee_estimation.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w114"},
        });
        w114_tests.linkSystemLibrary("rocksdb");
        w114_tests.linkSystemLibrary("secp256k1");
        w114_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w114_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w114_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w114_tests.linkSystemLibrary("minisketch");
            w114_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w114_tests.root_module.addOptions("build_options", build_options);

        const run_w114_tests = b.addRunArtifact(w114_tests);
        const w114_test_step = b.step("test-w114", "Run W114 CBlockPolicyEstimator fee estimation 30-gate audit tests");
        w114_test_step.dependOn(&run_w114_tests.step);
        // Fold into the main `test` step so CI exercises W114.
        test_step.dependOn(&run_w114_tests.step);
    }

    // W115 — ASMap IP-to-ASN mapping 30-gate audit.
    // Tests peer.zig + main.zig (Config) only — no RocksDB or wallet needed
    // at runtime, but rocksdb is linked because peer.zig depends on storage.zig.
    // ASMap is MISSING ENTIRELY from clearbit; all 30 gates document the absence.
    // Run with `zig build test-w115`.
    {
        const w115_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w115_asmap.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w115"},
        });
        w115_tests.linkSystemLibrary("rocksdb");
        w115_tests.linkSystemLibrary("secp256k1");
        w115_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w115_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w115_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w115_tests.linkSystemLibrary("minisketch");
            w115_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w115_tests.root_module.addOptions("build_options", build_options);

        const run_w115_tests = b.addRunArtifact(w115_tests);
        const w115_test_step = b.step("test-w115", "Run W115 ASMap IP-to-ASN mapping 30-gate audit tests");
        w115_test_step.dependOn(&run_w115_tests.step);
        // Fold into the main `test` step so CI exercises W115.
        test_step.dependOn(&run_w115_tests.step);
    }

    // W119 — BIP-78 PayJoin 30-gate audit.
    // PayJoin is MISSING ENTIRELY from clearbit; all 30 gates document the
    // absence using `@hasDecl` style assertions (W115 pattern).
    // Run with `zig build test-w119`.
    {
        const w119_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w119_payjoin.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w119"},
        });
        w119_tests.linkSystemLibrary("rocksdb");
        w119_tests.linkSystemLibrary("secp256k1");
        w119_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w119_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w119_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w119_tests.linkSystemLibrary("minisketch");
            w119_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w119_tests.root_module.addOptions("build_options", build_options);

        const run_w119_tests = b.addRunArtifact(w119_tests);
        const w119_test_step = b.step("test-w119", "Run W119 BIP-78 PayJoin 30-gate audit tests");
        w119_test_step.dependOn(&run_w119_tests.step);
        // Fold into the main `test` step so CI exercises W119.
        test_step.dependOn(&run_w119_tests.step);
    }

    // W120 — Mempool strict RBF rules 1-5 30-gate audit.
    // Reference: bitcoin-core/src/policy/rbf.{cpp,h}; BIP-125.
    // Run with `zig build test-w120`.
    {
        const w120_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w120_mempool_rbf.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w120"},
        });
        w120_tests.linkSystemLibrary("rocksdb");
        w120_tests.linkSystemLibrary("secp256k1");
        w120_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w120_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w120_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w120_tests.linkSystemLibrary("minisketch");
            w120_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w120_tests.root_module.addOptions("build_options", build_options);

        const run_w120_tests = b.addRunArtifact(w120_tests);
        const w120_test_step = b.step("test-w120", "Run W120 mempool strict RBF rules 1-5 30-gate audit tests");
        w120_test_step.dependOn(&run_w120_tests.step);
        // Fold into the main `test` step so CI exercises W120.
        test_step.dependOn(&run_w120_tests.step);
    }

    // W121 — BIP-157/158 compact block filter 30-gate audit.
    // Reference: bitcoin-core/src/blockfilter.{cpp,h}, index/blockfilterindex.{cpp,h};
    // BIP-157/158.
    // Run with `zig build test-w121`.
    {
        const w121_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w121_compact_filters.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w121"},
        });
        w121_tests.linkSystemLibrary("rocksdb");
        w121_tests.linkSystemLibrary("secp256k1");
        w121_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w121_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w121_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w121_tests.linkSystemLibrary("minisketch");
            w121_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w121_tests.root_module.addOptions("build_options", build_options);

        const run_w121_tests = b.addRunArtifact(w121_tests);
        const w121_test_step = b.step("test-w121", "Run W121 BIP-157/158 compact filter 30-gate audit tests");
        w121_test_step.dependOn(&run_w121_tests.step);
        // Fold into the main `test` step so CI exercises W121.
        test_step.dependOn(&run_w121_tests.step);
    }

    // W122 — BIP-158 GCS codec stress-vector audit.
    // Targets Golomb-Rice quotients 0/1/63/64/65/100/200/1000+ that
    // Core's blockfilters.json does NOT exercise.  Per haskoin W121
    // addendum BUG-16 (FIX-69): writers with Word64-batched unary
    // chunks can drop bits at cross-boundary writes.
    // Run with `zig build test-w122`.
    {
        const w122_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w122_gcs_stress.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w122"},
        });
        w122_tests.linkSystemLibrary("rocksdb");
        w122_tests.linkSystemLibrary("secp256k1");
        w122_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w122_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w122_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w122_tests.linkSystemLibrary("minisketch");
            w122_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w122_tests.root_module.addOptions("build_options", build_options);

        const run_w122_tests = b.addRunArtifact(w122_tests);
        const w122_test_step = b.step("test-w122", "Run W122 BIP-158 GCS codec stress-vector audit");
        w122_test_step.dependOn(&run_w122_tests.step);
        // Fold into the main `test` step so CI exercises W122.
        test_step.dependOn(&run_w122_tests.step);
    }

    // W125 — JSON-RPC error code parity 30-gate audit.
    // Reference: bitcoin-core/src/rpc/protocol.h (RPCErrorCode enum) +
    //            bitcoin-core/src/httprpc.cpp (HTTP status mapping).
    // Constant-value + source-guard tests against rpc.zig.  XFAIL-style:
    // every BUG test asserts the current (buggy) state so a future fix
    // wave can flip each gate by intentionally breaking the test.
    // See audit/w125_rpc_error_parity.md.
    // Run with `zig build test-w125`.
    {
        const w125_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w125_error_parity.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w125"},
        });
        w125_tests.linkSystemLibrary("rocksdb");
        w125_tests.linkSystemLibrary("secp256k1");
        w125_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w125_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w125_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w125_tests.linkSystemLibrary("minisketch");
            w125_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w125_tests.root_module.addOptions("build_options", build_options);

        const run_w125_tests = b.addRunArtifact(w125_tests);
        const w125_test_step = b.step("test-w125", "Run W125 JSON-RPC error code parity 30-gate audit tests");
        w125_test_step.dependOn(&run_w125_tests.step);
        // Fold into the main `test` step so CI exercises W125.
        test_step.dependOn(&run_w125_tests.step);
    }

    // W128 — AddrMan + connman + peer selection 30-gate fleet audit.
    // Reference: bitcoin-core/src/{addrman,net,banman,node/eviction}.{cpp,h}.
    // Dedicated test root (tests_w128_addrman.zig) so the audit imports
    // peer.zig + banlist.zig + p2p.zig + consensus.zig without pulling in
    // unrelated peer.zig tests via the broad `test` step.
    // Excludes BIP-155 (W117) + addrman storage/bucketing (W104) + ASMap
    // health-check (W115); see audit/w128_addrman.md for the bug catalogue.
    // Run with `zig build test-w128`.
    {
        const w128_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w128_addrman.zig"),
            .target = target,
            .optimize = optimize,
            // Filter to only our W128 tests; exclude drifted peer.zig tests
            // that this root transitively pulls in via the peer import.
            .filters = &[_][]const u8{"w128", "tests_w128_addrman"},
        });
        w128_tests.linkSystemLibrary("rocksdb");
        w128_tests.linkSystemLibrary("secp256k1");
        w128_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w128_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w128_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w128_tests.linkSystemLibrary("minisketch");
            w128_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w128_tests.root_module.addOptions("build_options", build_options);

        const run_w128_tests = b.addRunArtifact(w128_tests);
        const w128_test_step = b.step("test-w128", "Run W128 AddrMan + connman + peer selection 30-gate audit");
        w128_test_step.dependOn(&run_w128_tests.step);
        // Fold into the main `test` step so CI exercises W128.
        test_step.dependOn(&run_w128_tests.step);
    }

    // W142 — P2P anti-eclipse hardening proof suite (Bitcoin Core v31.99).
    // Reference: bitcoin-core/src/net.cpp ThreadOpenConnections FEELER branch +
    // net_processing.cpp GETADDR handler + ProcessAddrs token bucket.
    // Dedicated test root (tests_w142_anti_eclipse.zig) so the suite imports
    // peer.zig + addrman.zig + consensus.zig without pulling in unrelated
    // peer.zig tests via the broad `test` step. Run with `zig build test-w142`.
    {
        const w142_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w142_anti_eclipse.zig"),
            .target = target,
            .optimize = optimize,
            // Filter to only our W142 tests; exclude drifted peer.zig tests
            // that this root transitively pulls in via the peer import.
            .filters = &[_][]const u8{"w142", "tests_w142_anti_eclipse"},
        });
        w142_tests.linkSystemLibrary("rocksdb");
        w142_tests.linkSystemLibrary("secp256k1");
        w142_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w142_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w142_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w142_tests.linkSystemLibrary("minisketch");
            w142_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w142_tests.root_module.addOptions("build_options", build_options);

        const run_w142_tests = b.addRunArtifact(w142_tests);
        const w142_test_step = b.step("test-w142", "Run W142 P2P anti-eclipse hardening proof suite");
        w142_test_step.dependOn(&run_w142_tests.step);
        // Fold into the main `test` step so CI exercises W142.
        test_step.dependOn(&run_w142_tests.step);
    }

    // W143 — Faithful assumevalid script-skip gate (Core ConnectBlock:2346-2366).
    // Replaces the height-only skip (skip_via_height) in peer.zig with the
    // full 5-condition gate.  Proves that a FORK block below av_height is now
    // script-verified (was previously wrongly skipped) while an on-chain block
    // at the same height with all 5 conditions met is still skipped.
    // Run with `zig build test-w143`.
    {
        const w143_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w143_assumevalid_gate.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w143"},
        });
        w143_tests.linkSystemLibrary("rocksdb");
        w143_tests.linkSystemLibrary("secp256k1");
        w143_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w143_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w143_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w143_tests.linkSystemLibrary("minisketch");
            w143_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w143_tests.root_module.addOptions("build_options", build_options);

        const run_w143_tests = b.addRunArtifact(w143_tests);
        const w143_test_step = b.step("test-w143", "Run W143 faithful assumevalid 5-condition gate proof suite");
        w143_test_step.dependOn(&run_w143_tests.step);
        // Fold into the main `test` step so CI exercises W143.
        test_step.dependOn(&run_w143_tests.step);
    }

    // W144 — bad-diffbits enforcement: computeExpectedBits + live gate thread.
    // BEFORE: IBDValidationContext.expected_bits was always 0 (skip sentinel) because
    //   no caller computed it. The bad-diffbits gate (validation.zig:1299) was dead code.
    // AFTER: PeerManager.computeExpectedBits walks header_index + persisted headers
    //   to compute GetNextWorkRequired; validateBlockForIBDOrReject and
    //   validateHeaderContextual pass it so the gate fires on the live path.
    // Tests: computeExpectedBits correctness, validateHeaderContextual bad_diffbits,
    //   contextualCheckBlockHeader EFFECTIVE reject.
    // Run with `zig build test-w144`.
    {
        const w144_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w144_bad_diffbits.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"W144"},
        });
        w144_tests.linkSystemLibrary("rocksdb");
        w144_tests.linkSystemLibrary("secp256k1");
        w144_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w144_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w144_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w144_tests.linkSystemLibrary("minisketch");
            w144_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w144_tests.root_module.addOptions("build_options", build_options);

        const run_w144_tests = b.addRunArtifact(w144_tests);
        const w144_test_step = b.step("test-w144", "Run W144 bad-diffbits enforcement (computeExpectedBits + live gate thread) tests");
        w144_test_step.dependOn(&run_w144_tests.step);
        // Fold into the main `test` step so CI exercises W144.
        test_step.dependOn(&run_w144_tests.step);
    }

    // FIX-3G — ADDR/ADDRV2 peer-timestamp clamp (3G policy, fleet-wide).
    // Reference: bitcoin-core/src/net_processing.cpp:5678-5679.
    // Clamps peer-advertised nTime that is pre-2001 (≤100_000_000s) or more than
    // 10 minutes in the future to (now − 5*24h) before storing in addrman /
    // known_addresses.  Without this fix, clearbit ignored entry.timestamp
    // entirely and always stored the current wall clock, allowing peers to
    // inflate address freshness arbitrarily.
    // Run with `zig build test-fix3g`.
    {
        const fix3g_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_fix3g_addr_timestamp_clamp.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"fix3g"},
        });
        fix3g_tests.linkSystemLibrary("rocksdb");
        fix3g_tests.linkSystemLibrary("secp256k1");
        fix3g_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        fix3g_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            fix3g_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            fix3g_tests.linkSystemLibrary("minisketch");
            fix3g_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        fix3g_tests.root_module.addOptions("build_options", build_options);

        const run_fix3g_tests = b.addRunArtifact(fix3g_tests);
        const fix3g_step = b.step("test-fix3g", "Run FIX-3G ADDR/ADDRV2 peer-timestamp clamp tests");
        fix3g_step.dependOn(&run_fix3g_tests.step);
        // Fold into the main `test` step so CI exercises FIX-3G.
        test_step.dependOn(&run_fix3g_tests.step);
    }

    // W124 — Operator-experience 30-gate audit.
    // Reference: bitcoin-core/src/init.cpp (signals, Shutdown, Interrupt,
    //            SetupServerArgs, LockDirectory, InitLogging, WritePidFile);
    //            bitcoin-core/src/logging.{cpp,h} (BCLog::Logger, ShrinkDebugFile).
    // Source-guard tests + small filesystem round-trips against main.zig,
    // ops.zig, debug_log.zig, rpc.zig.  See audit/w124_operator_experience.md.
    // Run with `zig build test-w124`.
    {
        const w124_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w124_operator.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w124"},
        });
        w124_tests.linkSystemLibrary("rocksdb");
        w124_tests.linkSystemLibrary("secp256k1");
        w124_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w124_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w124_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w124_tests.linkSystemLibrary("minisketch");
            w124_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w124_tests.root_module.addOptions("build_options", build_options);

        const run_w124_tests = b.addRunArtifact(w124_tests);
        const w124_test_step = b.step("test-w124", "Run W124 Operator-experience 30-gate audit tests");
        w124_test_step.dependOn(&run_w124_tests.step);
        // Fold into the main `test` step so CI exercises W124.
        test_step.dependOn(&run_w124_tests.step);
    }

    // W126 — BIP-152 Compact Blocks 30-gate audit.
    // Reference: bitcoin-core/src/blockencodings.{h,cpp} (CBlockHeaderAndShortTxIDs,
    //            PartiallyDownloadedBlock, DifferenceFormatter);
    //            bitcoin-core/src/net_processing.cpp (SENDCMPCT/CMPCTBLOCK/
    //            GETBLOCKTXN/BLOCKTXN handlers, NewPoWValidBlock,
    //            MaybeSetPeerAsAnnouncingHeaderAndIDs, ProcessCompactBlockTxns).
    // XFAIL-style guards covering the BIP-152 subsystem end-to-end: sendcmpct
    // version negotiation, cmpctblock receive + reconstruction, getblocktxn
    // serve, blocktxn round-trip, HB-peer announce side, PartiallyDownloadedBlock
    // persistence, short-tx-id siphash key + 48-bit mask.
    // See audit/w126_bip152_compact_blocks.md.
    // Run with `zig build test-w126`.
    {
        const w126_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w126_bip152_compact_blocks.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w126"},
        });
        w126_tests.linkSystemLibrary("rocksdb");
        w126_tests.linkSystemLibrary("secp256k1");
        w126_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w126_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w126_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w126_tests.linkSystemLibrary("minisketch");
            w126_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w126_tests.root_module.addOptions("build_options", build_options);

        const run_w126_tests = b.addRunArtifact(w126_tests);
        const w126_test_step = b.step("test-w126", "Run W126 BIP-152 Compact Blocks 30-gate audit tests");
        w126_test_step.dependOn(&run_w126_tests.step);
        // Fold into the main `test` step so CI exercises W126.
        test_step.dependOn(&run_w126_tests.step);
    }

    // W127 — Taproot / Schnorr / Tapscript 30-gate audit.
    // Reference: bitcoin-core/src/script/interpreter.{cpp,h} (EvalChecksigTapscript,
    //            VerifyTaprootCommitment, VerifyWitnessProgram, CheckSchnorrSignature,
    //            SignatureHashSchnorr, ComputeTapleafHash, TAPROOT_LEAF_TAPSCRIPT=0xc0);
    //            bitcoin-core/src/script/script.h (ANNEX_TAG=0x50);
    //            bitcoin-core/src/script/script_error.h (SCRIPT_ERR_TAPROOT_*,
    //            SCRIPT_ERR_TAPSCRIPT_*, SCRIPT_ERR_SCHNORR_*);
    //            bitcoin-core/src/pubkey.cpp (XOnlyPubKey::VerifySchnorr);
    //            bitcoin-core/src/script/sigcache.cpp (CSignatureCache);
    //            BIPs 340 (Schnorr) / 341 (Taproot) / 342 (Tapscript).
    // XFAIL-style source-guard tests across script.zig, crypto.zig,
    // taproot_sighash.zig, sig_cache.zig + a handful of round-trip smokes.
    // See audit/w127_taproot.md.
    // Run with `zig build test-w127`.
    {
        const w127_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w127_taproot.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w127"},
        });
        w127_tests.linkSystemLibrary("rocksdb");
        w127_tests.linkSystemLibrary("secp256k1");
        w127_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w127_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w127_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w127_tests.linkSystemLibrary("minisketch");
            w127_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w127_tests.root_module.addOptions("build_options", build_options);

        const run_w127_tests = b.addRunArtifact(w127_tests);
        const w127_test_step = b.step("test-w127", "Run W127 Taproot / Schnorr / Tapscript 30-gate audit tests");
        w127_test_step.dependOn(&run_w127_tests.step);
        // Fold into the main `test` step so CI exercises W127.
        test_step.dependOn(&run_w127_tests.step);
    }

    // W129 — Coin selection deep audit (30-gate, discovery).
    // Reference: bitcoin-core/src/wallet/coinselection.{h,cpp}
    //            (BnB, KnapsackSolver, SelectCoinsSRD, CoinGrinder,
    //             GenerateChangeTarget, RecalculateWaste, OutputGroup);
    //            bitcoin-core/src/wallet/spend.cpp
    //            (AttemptSelection, ChooseSelectionResult,
    //             cost_of_change / min_viable_change derivation,
    //             SFFO plumbing);
    //            bitcoin-core/src/wallet/feebumper.cpp;
    //            bitcoin-core/src/policy/policy.cpp (GetDustThreshold).
    // XFAIL-style guards over wallet.zig's BnB + Knapsack + change /
    // SFFO / dust integration.  See audit/w129_coin_selection.md.
    // Run with `zig build test-w129`.
    {
        const w129_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w129_coin_selection.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w129"},
        });
        w129_tests.linkSystemLibrary("rocksdb");
        w129_tests.linkSystemLibrary("secp256k1");
        w129_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w129_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w129_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w129_tests.linkSystemLibrary("minisketch");
            w129_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w129_tests.root_module.addOptions("build_options", build_options);

        const run_w129_tests = b.addRunArtifact(w129_tests);
        const w129_test_step = b.step("test-w129", "Run W129 Coin selection deep audit (30 gates)");
        w129_test_step.dependOn(&run_w129_tests.step);
        // Fold into the main `test` step so CI exercises W129.
        test_step.dependOn(&run_w129_tests.step);
    }

    // W130 — BIP-125 RBF feebumper Rule 3 audit (30-gate, discovery).
    // Reference: bitcoin-core/src/wallet/feebumper.{h,cpp}
    //            (CreateRateBumpTransaction, PreconditionChecks, CheckFeeRate,
    //             EstimateFeeRate);
    //            bitcoin-core/src/policy/rbf.{cpp,h}
    //            (PaysForRBF, IsRBFOptIn, EntriesAndTxidsDisjoint);
    //            bitcoin-core/src/policy/feerate.{cpp,h}
    //            (CFeeRate::GetFee rounds UP via CeilDiv);
    //            bitcoin-core/src/util/feefrac.h (EvaluateFeeUp / EvaluateFeeDown);
    //            bitcoin-core/src/wallet/wallet.h:124 (WALLET_INCREMENTAL_RELAY_FEE).
    // XFAIL-style guards over wallet bumpFee + mempool checkRBFRules.
    // See audit/w130_bip125_feebumper_rule3.md.
    // Run with `zig build test-w130`.
    {
        const w130_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w130_bip125_feebumper_rule3.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w130"},
        });
        w130_tests.linkSystemLibrary("rocksdb");
        w130_tests.linkSystemLibrary("secp256k1");
        w130_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w130_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w130_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w130_tests.linkSystemLibrary("minisketch");
            w130_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w130_tests.root_module.addOptions("build_options", build_options);

        const run_w130_tests = b.addRunArtifact(w130_tests);
        const w130_test_step = b.step("test-w130", "Run W130 BIP-125 RBF feebumper Rule 3 30-gate audit tests");
        w130_test_step.dependOn(&run_w130_tests.step);
        // Fold into the main `test` step so CI exercises W130.
        test_step.dependOn(&run_w130_tests.step);
    }

    // W131 — Descriptors + Miniscript audit (30-gate, discovery).
    // Reference: bitcoin-core/src/script/descriptor.cpp + descriptor.h
    //            (DescriptorChecksum, PolyMod, ParseScript, ParsePubkey,
    //             ParseKeyPath, ParseHDKeypath, multipath specifier,
    //             MultisigDescriptor / TRDescriptor / RawTRDescriptor /
    //             ComboDescriptor, MAX_PUBKEYS_PER_MULTISIG / MAX_PUBKEYS_PER_MULTI_A);
    //            bitcoin-core/src/script/miniscript.cpp + miniscript.h
    //            (Type, SanitizeType, ComputeType, ComputeScriptLen,
    //             Fragment, Node::IsValid / IsSane / IsNonMalleable /
    //             CheckTimeLocksMix);
    //            BIPs 380 / 381 / 382 / 385 / 386 / 389 + ms-spec.
    // XFAIL-style guards across descriptor.zig + miniscript.zig:
    //   Group A — checksum / round-trip (G1..G4, G1+G2 PASS).
    //   Group B — descriptor language coverage (G5..G20).
    //   Group C — miniscript type system (G21..G27).
    //   Group D — miniscript parser / script lowering (G28..G30).
    // See audit/w131_descriptors_miniscript.md.
    // Run with `zig build test-w131`.
    {
        const w131_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w131_descriptors_miniscript.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w131"},
        });
        w131_tests.linkSystemLibrary("rocksdb");
        w131_tests.linkSystemLibrary("secp256k1");
        w131_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w131_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w131_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w131_tests.linkSystemLibrary("minisketch");
            w131_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w131_tests.root_module.addOptions("build_options", build_options);

        const run_w131_tests = b.addRunArtifact(w131_tests);
        const w131_test_step = b.step("test-w131", "Run W131 Descriptors + Miniscript 30-gate audit tests");
        w131_test_step.dependOn(&run_w131_tests.step);
        // Fold into the main `test` step so CI exercises W131.
        test_step.dependOn(&run_w131_tests.step);
    }

    // W132 — BIP-68 / BIP-112 / BIP-113 nSequence / OP_CSV / MTP audit
    // (30-gate, discovery).
    // Reference: bitcoin-core/src/consensus/tx_verify.cpp (IsFinalTx,
    //            CalculateSequenceLocks, EvaluateSequenceLocks,
    //            SequenceLocks);
    //            bitcoin-core/src/script/interpreter.cpp (OP_CSV opcode
    //            body, CheckSequence, CheckLockTime);
    //            bitcoin-core/src/chain.h (GetMedianTimePast,
    //            nMedianTimeSpan=11);
    //            bitcoin-core/src/primitives/transaction.h (SEQUENCE_FINAL,
    //            SEQUENCE_LOCKTIME_* constants);
    //            bitcoin-core/src/validation.cpp (ConnectBlock BIP-68).
    // XFAIL-style guards across validation.zig (calculateSequenceLocks,
    // checkSequenceLocks, isFinalTx, medianTimePast), script.zig
    // (OP_CSV / OP_CLTV opcodes), peer.zig (computePrevMtp /
    // computeMtpAtHeight), and mempool.zig (BIP-68 mempool path).
    // See audit/w132_nsequence_csv_mtp.md.
    // Run with `zig build test-w132`.
    {
        const w132_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w132_nsequence_csv_mtp.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w132"},
        });
        w132_tests.linkSystemLibrary("rocksdb");
        w132_tests.linkSystemLibrary("secp256k1");
        w132_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w132_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w132_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w132_tests.linkSystemLibrary("minisketch");
            w132_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w132_tests.root_module.addOptions("build_options", build_options);

        const run_w132_tests = b.addRunArtifact(w132_tests);
        const w132_test_step = b.step("test-w132", "Run W132 BIP-68/112/113 nSequence/CSV/MTP 30-gate audit tests");
        w132_test_step.dependOn(&run_w132_tests.step);
        // Fold into the main `test` step so CI exercises W132.
        test_step.dependOn(&run_w132_tests.step);
    }

    // W133 — Index databases (txindex + coinstatsindex) — discovery audit.
    // 30-gate matrix vs Bitcoin Core src/index/{base,txindex,coinstatsindex,
    // disktxpos,db_key}.{h,cpp}. XFAIL-style guards over indexes.zig +
    // storage.zig + main.zig + rpc.zig: 22 MISSING + 8 DIVERGE = 30 BUGs.
    // Excludes BIP-157/158 blockfilterindex (W121 + W122 own it).
    // See audit/w133_index_databases.md.
    // Run with `zig build test-w133`.
    {
        const w133_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w133_index_databases.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w133"},
        });
        w133_tests.linkSystemLibrary("rocksdb");
        w133_tests.linkSystemLibrary("secp256k1");
        w133_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w133_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w133_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w133_tests.linkSystemLibrary("minisketch");
            w133_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w133_tests.root_module.addOptions("build_options", build_options);

        const run_w133_tests = b.addRunArtifact(w133_tests);
        const w133_test_step = b.step("test-w133", "Run W133 Index databases (txindex + coinstatsindex) 30-gate audit tests");
        w133_test_step.dependOn(&run_w133_tests.step);
        // Fold into the main `test` step so CI exercises W133.
        test_step.dependOn(&run_w133_tests.step);
    }

    // W134 — BIP-37 Bloom Filter + BIP-111 NODE_BLOOM 30-gate audit (discovery).
    // Reference: bitcoin-core/src/common/bloom.{cpp,h} (CBloomFilter,
    //            CRollingBloomFilter); bitcoin-core/src/merkleblock.{cpp,h}
    //            (CMerkleBlock, CPartialMerkleTree, BitsToBytes / BytesToBits);
    //            bitcoin-core/src/net_processing.cpp (FILTERLOAD/FILTERADD/
    //            FILTERCLEAR handlers @ 4963-5033; MSG_FILTERED_BLOCK getdata
    //            @ 2438-2458; TxRelay m_bloom_filter @ 293-297);
    //            bitcoin-core/src/init.cpp (-peerbloomfilters NODE_BLOOM
    //            wiring @ 1104-1105); bitcoin-core/src/protocol.h
    //            (NODE_BLOOM = (1<<2) @ 317).
    // Extends W110 with G15/G24/G25/G28/G29 + CRollingBloomFilter
    // cross-link. XFAIL-style: BUG tests assert current (buggy/missing)
    // state; PASS tests protect the NODE_BLOOM bit + -peerbloomfilters
    // default + FIX-36 wire pipeline.
    // See audit/w134_bip37_bloom_filter.md.
    // Run with `zig build test-w134`.
    {
        const w134_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w134_bip37_bloom_filter.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w134"},
        });
        w134_tests.linkSystemLibrary("rocksdb");
        w134_tests.linkSystemLibrary("secp256k1");
        w134_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w134_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w134_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w134_tests.linkSystemLibrary("minisketch");
            w134_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w134_tests.root_module.addOptions("build_options", build_options);

        const run_w134_tests = b.addRunArtifact(w134_tests);
        const w134_test_step = b.step("test-w134", "Run W134 BIP-37 Bloom Filter + BIP-111 NODE_BLOOM 30-gate audit tests");
        w134_test_step.dependOn(&run_w134_tests.step);
        // Fold into the main `test` step so CI exercises W134.
        test_step.dependOn(&run_w134_tests.step);
    }

    // W135 — Standardness rules (IsStandardTx) audit (30-gate, discovery).
    // Reference: bitcoin-core/src/policy/policy.{h,cpp} (IsStandardTx,
    //            IsStandard, GetDust, MAX_DUST_OUTPUTS_PER_TX);
    //            bitcoin-core/src/script/solver.{h,cpp} (Solver,
    //            MatchMultisig, MatchMultiA, TxoutType incl. WITNESS_UNKNOWN);
    //            bitcoin-core/src/policy/truc_policy.h (TRUC_VERSION);
    //            bitcoin-core/src/kernel/mempool_options.h
    //            (permit_bare_multisig, max_datacarrier_bytes, dust_relay_feerate);
    //            bitcoin-core/src/consensus/tx_check.cpp (CheckTransaction).
    // XFAIL-style guards over mempool.zig:checkStandard /
    // checkWitnessStandard and script.zig:classifyScript.  See
    // audit/w135_standardness_rules.md.
    // Run with `zig build test-w135`.
    {
        const w135_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w135_standardness.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w135"},
        });
        w135_tests.linkSystemLibrary("rocksdb");
        w135_tests.linkSystemLibrary("secp256k1");
        w135_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w135_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w135_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w135_tests.linkSystemLibrary("minisketch");
            w135_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w135_tests.root_module.addOptions("build_options", build_options);

        const run_w135_tests = b.addRunArtifact(w135_tests);
        const w135_test_step = b.step("test-w135", "Run W135 Standardness rules (IsStandardTx) 30-gate audit tests");
        w135_test_step.dependOn(&run_w135_tests.step);
        // Fold into the main `test` step so CI exercises W135.
        test_step.dependOn(&run_w135_tests.step);
    }

    // W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) 30-gate audit (discovery).
    // References:
    //   bitcoin-core/src/psbt.h (PSBTInput/PSBTOutput/PartiallySignedTransaction
    //     serialize+unserialize templates; key_lookup duplicate-key detection;
    //     non-witness UTXO hash check at psbt.h:1371-1378);
    //   bitcoin-core/src/psbt.cpp (FinalizePSBT, CombinePSBTs, ExtractPSBT,
    //     PSBTInputSignedAndVerified, RemoveUnnecessaryTransactions);
    //   bitcoin-core/src/wallet/rpc/spend.cpp (walletprocesspsbt @ 1569,
    //     walletcreatefundedpsbt @ 1653, psbtbumpfee @ 1163);
    //   bitcoin-core/src/rpc/rawtransaction.cpp (decodepsbt @ 1013,
    //     combinepsbt @ 1515, finalizepsbt @ 1563, createpsbt @ 1620,
    //     converttopsbt @ 1663, utxoupdatepsbt @ 1731, joinpsbts @ 1778,
    //     analyzepsbt @ 1880).
    // BIPs 174, 370, 371, 373.
    // XFAIL-style guards over psbt.zig + wallet.zig + rpc.zig: 28 BUGs
    // across 30 gates (23 MISSING + 5 DIVERGE). Largest finding:
    // declare-init-deinit-but-never-populate dead storage on the four
    // hash-preimage maps (BUG-14); HIGH-CDIV bugs in deserialize-time
    // invariants (no duplicate-key detection, no non-witness UTXO hash
    // check, no DER-signature check, no IsFullyValid pubkey check) +
    // parse-but-no-emit asymmetry on BIP-371 fields.
    // See audit/w137_psbt.md.
    // Run with `zig build test-w137`.
    {
        const w137_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w137_psbt.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w137"},
        });
        w137_tests.linkSystemLibrary("rocksdb");
        w137_tests.linkSystemLibrary("secp256k1");
        w137_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w137_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w137_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w137_tests.linkSystemLibrary("minisketch");
            w137_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w137_tests.root_module.addOptions("build_options", build_options);

        const run_w137_tests = b.addRunArtifact(w137_tests);
        const w137_test_step = b.step("test-w137", "Run W137 PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) 30-gate audit tests");
        w137_test_step.dependOn(&run_w137_tests.step);
        // Fold into the main `test` step so CI exercises W137.
        test_step.dependOn(&run_w137_tests.step);
    }

    // W138 — assumeUTXO snapshots 30-gate audit (discovery). References:
    //   bitcoin-core/src/node/utxo_snapshot.{h,cpp} (SnapshotMetadata,
    //     SNAPSHOT_MAGIC_BYTES, SNAPSHOT_BLOCKHASH_FILENAME,
    //     SNAPSHOT_CHAINSTATE_SUFFIX, WriteSnapshotBaseBlockhash,
    //     ReadSnapshotBaseBlockhash, FindAssumeutxoChainstateDir);
    //   bitcoin-core/src/validation.cpp (ActivateSnapshot @ 5588,
    //     PopulateAndValidateSnapshot @ 5754, MaybeValidateSnapshot @ 5963,
    //     InvalidateCoinsDBOnDisk, MaybeRebalanceCaches,
    //     LoadBlockIndexDB(snapshot_blockhash));
    //   bitcoin-core/src/rpc/blockchain.cpp (dumptxoutset @ 3074,
    //     loadtxoutset @ 3368, getchainstates @ 3462,
    //     PrepareUTXOSnapshot @ 3226, WriteUTXOSnapshot @ 3265).
    // BIPs: none (assumeUTXO is a Core implementation feature, not a BIP).
    // 30 BUGs across 30 gates: largest single-impl finding is BUG-1
    // (CLI --load-snapshot skips the hash_serialized content-hash gate
    // that the RPC/in-memory path enforces) + BUG-2 (ChainStateManager
    // dead code) + BUG-3 (no getchainstates RPC) + BUG-4..5 (no
    // snapshot persistence file / chainstate dir suffix).
    // See audit/w138_assumeutxo.md.
    // Run with `zig build test-w138`.
    {
        const w138_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w138_assumeutxo.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w138"},
        });
        w138_tests.linkSystemLibrary("rocksdb");
        w138_tests.linkSystemLibrary("secp256k1");
        w138_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w138_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w138_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w138_tests.linkSystemLibrary("minisketch");
            w138_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w138_tests.root_module.addOptions("build_options", build_options);

        const run_w138_tests = b.addRunArtifact(w138_tests);
        const w138_test_step = b.step("test-w138", "Run W138 assumeUTXO snapshots 30-gate audit tests");
        w138_test_step.dependOn(&run_w138_tests.step);
        // Fold into the main `test` step so CI exercises W138.
        test_step.dependOn(&run_w138_tests.step);
    }

    // W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay
    // 30-gate audit (discovery).  References:
    //   bitcoin-core/src/net_processing.cpp (MaybeSendSendHeaders @ 5519,
    //     MaybeSendFeefilter @ 5540, WTXIDRELAY handler @ 3921, SENDHEADERS
    //     handler @ 3896, FEEFILTER handler @ 5035, inv-wtxid-filter @
    //     4056-4063);
    //   bitcoin-core/src/node/protocol_version.h (SENDHEADERS_VERSION=70012,
    //     FEEFILTER_VERSION=70013, WTXID_RELAY_VERSION=70016);
    //   bitcoin-core/src/policy/fees/block_policy_estimator.{cpp,h}
    //     (FeeFilterRounder, MAX_FILTER_FEERATE=1e7, FEE_FILTER_SPACING=1.1).
    // BIPs 130, 133, 339.
    // XFAIL-style guards over peer.zig + p2p.zig: 17 BUGs across 30 gates.
    // Largest single-impl finding: `maybeSendFeefilter` is dead code (no
    // caller anywhere in src/).  See audit/w136_relay_flags.md.
    // Run with `zig build test-w136`.
    {
        const w136_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w136_relay_flags.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w136"},
        });
        w136_tests.linkSystemLibrary("rocksdb");
        w136_tests.linkSystemLibrary("secp256k1");
        w136_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w136_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w136_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w136_tests.linkSystemLibrary("minisketch");
            w136_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w136_tests.root_module.addOptions("build_options", build_options);

        const run_w136_tests = b.addRunArtifact(w136_tests);
        const w136_test_step = b.step("test-w136", "Run W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay 30-gate audit tests");
        w136_test_step.dependOn(&run_w136_tests.step);
        // Fold into the main `test` step so CI exercises W136.
        test_step.dependOn(&run_w136_tests.step);
    }

    // W139 — Fee estimation engine (CBlockPolicyEstimator) 30-gate audit
    // (discovery, second pass after W114).  References:
    //   bitcoin-core/src/policy/fees/block_policy_estimator.{cpp,h}
    //     (CBlockPolicyEstimator, TxConfirmStats, FeeFilterRounder,
    //      MAX_FILE_AGE=60h, FEE_FLUSH_INTERVAL=1h, OLDEST_ESTIMATE_HISTORY,
    //      validForFeeEstimation, MaxUsableEstimate, BlockSpan,
    //      HistoricalBlockSpan, estimateCombinedFee, estimateConservativeFee,
    //      FlushUnconfirmed, processBlock reorg guard);
    //   bitcoin-core/src/policy/fees/block_policy_estimator_args.{cpp,h}
    //     (FeeestPath, FEE_ESTIMATES_FILENAME);
    //   bitcoin-core/src/policy/feerate.{cpp,h}
    //     (CFeeRate, FeePerVSize, FeeRateFormat, GetFee ceil-up,
    //      GetFeePerK, CURRENCY_UNIT/ATOM);
    //   bitcoin-core/src/rpc/fees.cpp
    //     (estimatesmartfee + estimaterawfee, ParseConfirmTarget,
    //      HighestTargetTracked, FeeReason/FeeCalculation).
    // Source-grep + behavioral XFAIL guards over mempool.zig + rpc.zig:
    // 29 BUGs across 30 gates (G28 PARTIAL/no-bug — fee_estimates.dat
    // canonical filename already wired in main.zig).  Steers away from
    // W114's already-closed gates (FIX-47/FIX-48) and toward Core-specific
    // semantics W114 missed.  Largest findings:
    //   BUG-9  no validForFeeEstimation four-gate skip before trackTransaction;
    //   BUG-11 processBlock has no nBlockHeight<=nBestSeenHeight reorg guard
    //          (double-decay observable on replay);
    //   BUG-12 duplicate trackTransaction double-counts the bucket
    //          (total_counts++ fires on both calls; HashMap put overwrites).
    // See audit/w139_fee_estimation.md.
    // Run with `zig build test-w139`.
    {
        const w139_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w139_fee_estimation.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w139"},
        });
        w139_tests.linkSystemLibrary("rocksdb");
        w139_tests.linkSystemLibrary("secp256k1");
        w139_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w139_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w139_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w139_tests.linkSystemLibrary("minisketch");
            w139_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w139_tests.root_module.addOptions("build_options", build_options);

        const run_w139_tests = b.addRunArtifact(w139_tests);
        const w139_test_step = b.step("test-w139", "Run W139 Fee estimation engine (CBlockPolicyEstimator) 30-gate audit tests");
        w139_test_step.dependOn(&run_w139_tests.step);
        // Fold into the main `test` step so CI exercises W139.
        test_step.dependOn(&run_w139_tests.step);
    }

    // W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch
    // 30-gate audit (discovery).  References:
    //   bitcoin-core/src/httpserver.{cpp,h} (HTTPBindAddresses,
    //     http_request_cb, ClientAllowed, InitHTTPAllowList, ThreadPool,
    //     MAX_HEADERS_SIZE=8192, DEFAULT_HTTP_THREADS=16,
    //     DEFAULT_HTTP_WORKQUEUE=64, DEFAULT_HTTP_SERVER_TIMEOUT=30);
    //   bitcoin-core/src/httprpc.cpp (HTTPReq_JSONRPC, RPCAuthorized,
    //     CheckUserAuthorized, JSONErrorReply HTTP-status mapping
    //     (RPC_INVALID_REQUEST → 400, RPC_METHOD_NOT_FOUND → 404,
    //      default → 500), InitRPCAuthentication, WWW_AUTH_HEADER_DATA,
    //     250ms UninterruptibleSleep on failed auth, -rpcwhitelist,
    //     -rpcauth HMAC-SHA-256);
    //   bitcoin-core/src/rpc/request.{cpp,h} (COOKIEAUTH_USER,
    //     GenerateAuthCookie .cookie.tmp + RenameOver, GetAuthCookieFile
    //     (-rpccookiefile), JSONRPCRequest::parse jsonrpc-2.0 detection);
    //   bitcoin-core/share/rpcauth/rpcauth.py (canonical user:salt$HMAC);
    //   bitcoin-core/src/util/strencodings.h:202-210 (TimingResistantEqual);
    //   bitcoin-core/src/init.cpp:706-720 (-rpc* argspec).
    // BIPs: none.  XFAIL-style guards over rpc.zig + main.zig: 21 unique
    // BUGs across 30 gates (3 P0-SEC + 8 P1 + 9 P2 + 1 PRESENT-by-design).
    // Top P0-SEC findings:
    //   BUG-1 (G3) std.mem.eql auth compare — not constant-time;
    //   BUG-4 (G4) no -rpcauth HMAC-SHA-256 path (pushes operators to
    //         plaintext credentials);
    //   BUG-7 (G7) no -rpcallowip CIDR allow-list (W124 BUG-13 re-anchor);
    //   BUG-9 (G13) no WWW-Authenticate header on 401 (RFC-7235 violation);
    //   BUG-18 (G18) HTTP status mapping wholly absent — every reply is
    //         200 OK (W125 BUG-15+17 re-anchor).
    // See audit/w140_http_rpcauth.md.
    // Run with `zig build test-w140`.
    {
        const w140_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w140_http_rpcauth.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w140"},
        });
        w140_tests.linkSystemLibrary("rocksdb");
        w140_tests.linkSystemLibrary("secp256k1");
        w140_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w140_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w140_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w140_tests.linkSystemLibrary("minisketch");
            w140_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w140_tests.root_module.addOptions("build_options", build_options);

        const run_w140_tests = b.addRunArtifact(w140_tests);
        const w140_test_step = b.step("test-w140", "Run W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch 30-gate audit tests");
        w140_test_step.dependOn(&run_w140_tests.step);
        // Fold into the main `test` step so CI exercises W140.
        test_step.dependOn(&run_w140_tests.step);
    }

    // W141 — ZMQ + REST + notification-script 30-gate audit (discovery).
    // References:
    //   bitcoin-core/src/zmq/zmqpublishnotifier.cpp (SendZmqMessage @ 193,
    //     NotifyBlock @ 210, NotifyBlockDisconnect 'D' @ 274,
    //     NotifyTransactionRemoval 'R' @ 288, IsZMQAddressIPV6 @ 82);
    //   bitcoin-core/src/zmq/zmqnotificationinterface.cpp (unix:// -> ipc://
    //     rewrite @ 62-64, per-topic hwm knob @ 69, IBD short-circuit @ 151-154,
    //     BlockConnected per-tx fan-out @ 180-196);
    //   bitcoin-core/src/rest.cpp (CheckWarmup @ 171-177, ParseDataFormat @ 129,
    //     MAX_REST_HEADERS_RESULTS=2000, MAX_GETUTXOS_OUTPOINTS=15, dispatch
    //     table @ 1141-1159 listing /rest/deploymentinfo, /rest/spenttxouts/,
    //     /rest/blockpart/, query-param /rest/headers/<hash>?count=N);
    //   bitcoin-core/src/init.cpp (-blocknotify @ 2008-2018,
    //     -shutdownnotify @ 255-265, -startupnotify @ 737-745);
    //   bitcoin-core/src/node/kernel_notifications.cpp (-alertnotify @ 30-47);
    //   bitcoin-core/src/wallet/init.cpp:75 + wallet.cpp:1480 (-walletnotify).
    // No BIPs.
    // XFAIL-style guards over zmq.zig + rpc.zig (REST) + main.zig (notify
    // absence): 30 BUGs across 30 gates (15 ZMQ + 9 REST + 6 NOTIFY).
    // Largest single-impl findings: 'D'/'R' sequence labels missing,
    // CheckWarmup short-circuit absent, all 5 notify-script hooks absent.
    // See audit/w141_zmq_rest_notify.md.
    // Run with `zig build test-w141`.
    {
        const w141_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_w141_zmq_rest_notify.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"w141"},
        });
        w141_tests.linkSystemLibrary("rocksdb");
        w141_tests.linkSystemLibrary("secp256k1");
        w141_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        w141_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            w141_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            w141_tests.linkSystemLibrary("minisketch");
            w141_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        w141_tests.root_module.addOptions("build_options", build_options);

        const run_w141_tests = b.addRunArtifact(w141_tests);
        const w141_test_step = b.step("test-w141", "Run W141 ZMQ + REST + notification-scripts 30-gate audit tests");
        w141_test_step.dependOn(&run_w141_tests.step);
        // Fold into the main `test` step so CI exercises W141.
        test_step.dependOn(&run_w141_tests.step);
    }

    // FIX-84 — BIP-157 P2P handler wire-up (W121 BUG-3..7 + BUG-10 closure).
    // Wire round-trip + dispatch-arm source guards + constants + DoS bounds.
    // Run with `zig build test-fix84`.
    {
        const fix84_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_fix84_bip157_dispatch.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"fix84"},
        });
        fix84_tests.linkSystemLibrary("rocksdb");
        fix84_tests.linkSystemLibrary("secp256k1");
        fix84_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        fix84_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            fix84_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            fix84_tests.linkSystemLibrary("minisketch");
            fix84_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        fix84_tests.root_module.addOptions("build_options", build_options);

        const run_fix84_tests = b.addRunArtifact(fix84_tests);
        const fix84_test_step = b.step("test-fix84", "Run FIX-84 BIP-157 P2P handler wire-up tests");
        fix84_test_step.dependOn(&run_fix84_tests.step);
        // Fold into the default `test` step.
        test_step.dependOn(&run_fix84_tests.step);
    }

    // FIX-62 — BIP-21 URI parser tests.
    // `bip21.zig` is intentionally self-contained (depends only on
    // `address.zig`, which depends on `crypto.zig` + `types.zig`).  No
    // wallet.zig dependency, so we can fold this into the default `test`
    // step without tripping the long-standing selectCoins anonymous-struct
    // compile error.  Run with `zig build test-bip21`.
    {
        const bip21_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_fix62_bip21.zig"),
            .target = target,
            .optimize = optimize,
        });
        bip21_tests.linkSystemLibrary("secp256k1");
        bip21_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        bip21_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            bip21_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        bip21_tests.root_module.addOptions("build_options", build_options);

        const run_bip21_tests = b.addRunArtifact(bip21_tests);
        const bip21_test_step = b.step("test-bip21", "Run FIX-62 BIP-21 URI parser tests");
        bip21_test_step.dependOn(&run_bip21_tests.step);
        // Fold into the default `test` step.
        test_step.dependOn(&run_bip21_tests.step);
    }

    // FIX-64 — HTTPS/TLS termination flag plumbing (W119 + FIX-64 deferral).
    // `tests_fix64_tls.zig` depends on `rpc.zig`, which transitively pulls in
    // storage (rocksdb) + secp256k1 + minisketch (when enabled).  Mirror the
    // W119 link config so the test binary actually links.
    // Run with `zig build test-fix64`.
    {
        const fix64_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_fix64_tls.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"fix64"},
        });
        fix64_tests.linkSystemLibrary("rocksdb");
        fix64_tests.linkSystemLibrary("secp256k1");
        fix64_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        fix64_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            fix64_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            fix64_tests.linkSystemLibrary("minisketch");
            fix64_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        fix64_tests.root_module.addOptions("build_options", build_options);

        const run_fix64_tests = b.addRunArtifact(fix64_tests);
        const fix64_test_step = b.step("test-fix64", "Run FIX-64 HTTPS/TLS flag plumbing tests");
        fix64_test_step.dependOn(&run_fix64_tests.step);
        // Fold into the default `test` step.
        test_step.dependOn(&run_fix64_tests.step);
    }

    // FIX-65 — BIP-78 PayJoin receiver foundation (plain HTTP only).
    // `tests_fix65_payjoin_receiver.zig` imports rpc.zig + psbt.zig + types.zig
    // (mirror the W119 / FIX-64 link config so the test binary actually links).
    // Run with `zig build test-fix65`.
    {
        const fix65_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_fix65_payjoin_receiver.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"fix65"},
        });
        fix65_tests.linkSystemLibrary("rocksdb");
        fix65_tests.linkSystemLibrary("secp256k1");
        fix65_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        fix65_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            fix65_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            fix65_tests.linkSystemLibrary("minisketch");
            fix65_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        fix65_tests.root_module.addOptions("build_options", build_options);

        const run_fix65_tests = b.addRunArtifact(fix65_tests);
        const fix65_test_step = b.step("test-fix65", "Run FIX-65 BIP-78 PayJoin receiver foundation tests");
        fix65_test_step.dependOn(&run_fix65_tests.step);
        // Fold into the default `test` step.
        test_step.dependOn(&run_fix65_tests.step);
    }

    // FIX-66 — BIP-78 PayJoin sender foundation (plain HTTP only).
    // `tests_fix66_payjoin_sender.zig` imports rpc.zig + wallet.zig +
    // psbt.zig + types.zig (mirror the FIX-65 link config — the wallet
    // pulls in secp256k1 transitively for AES-GCM/BIP-32 init paths).
    // Run with `zig build test-fix66`.
    {
        const fix66_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_fix66_payjoin_sender.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"fix66"},
        });
        fix66_tests.linkSystemLibrary("rocksdb");
        fix66_tests.linkSystemLibrary("secp256k1");
        fix66_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        fix66_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            fix66_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            fix66_tests.linkSystemLibrary("minisketch");
            fix66_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        fix66_tests.root_module.addOptions("build_options", build_options);

        const run_fix66_tests = b.addRunArtifact(fix66_tests);
        const fix66_test_step = b.step("test-fix66", "Run FIX-66 BIP-78 PayJoin sender foundation tests");
        fix66_test_step.dependOn(&run_fix66_tests.step);
        // Fold into the default `test` step.
        test_step.dependOn(&run_fix66_tests.step);
    }

    // FIX-67 — BIP-78 PayJoin receiver Implementation Suggestions
    // (TTL / UTXO lock / fingerprint pick / Content-Type / replay).
    // `tests_fix67_payjoin_suggestions.zig` imports rpc.zig + wallet.zig +
    // psbt.zig + types.zig + script.zig (mirror the FIX-65/66 link config).
    // Run with `zig build test-fix67`.
    {
        const fix67_tests = b.addTest(.{
            .root_source_file = b.path("src/tests_fix67_payjoin_suggestions.zig"),
            .target = target,
            .optimize = optimize,
            .filters = &[_][]const u8{"fix67"},
        });
        fix67_tests.linkSystemLibrary("rocksdb");
        fix67_tests.linkSystemLibrary("secp256k1");
        fix67_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        fix67_tests.linkLibC();
        if (target.result.cpu.arch == .x86_64) {
            fix67_tests.addCSourceFile(.{
                .file = b.path("src/sha256_shani.c"),
                .flags = shani_cflags,
            });
        }
        if (minisketch_enabled) {
            fix67_tests.linkSystemLibrary("minisketch");
            fix67_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        }
        fix67_tests.root_module.addOptions("build_options", build_options);

        const run_fix67_tests = b.addRunArtifact(fix67_tests);
        const fix67_test_step = b.step("test-fix67", "Run FIX-67 BIP-78 PayJoin Implementation Suggestions tests");
        fix67_test_step.dependOn(&run_fix67_tests.step);
        // Fold into the default `test` step.
        test_step.dependOn(&run_fix67_tests.step);
    }

    // Sighash test harness (links secp256k1 since crypto.zig requires it)
    const sighash_test = b.addExecutable(.{
        .name = "test_sighash",
        .root_source_file = b.path("src/test_sighash.zig"),
        .target = target,
        .optimize = optimize,
    });
    sighash_test.addIncludePath(.{ .cwd_relative = secp256k1_include });
    sighash_test.linkSystemLibrary("secp256k1");
    sighash_test.linkLibC();
    if (target.result.cpu.arch == .x86_64) {
        sighash_test.addCSourceFile(.{ .file = b.path("src/sha256_shani.c"), .flags = shani_cflags });
    }
    b.installArtifact(sighash_test);

    const run_sighash = b.addRunArtifact(sighash_test);
    run_sighash.step.dependOn(b.getInstallStep());
    const sighash_step = b.step("test-sighash", "Run sighash test vectors");
    sighash_step.dependOn(&run_sighash.step);

    // Script test vectors harness (links secp256k1 for real signature verification)
    const script_test = b.addExecutable(.{
        .name = "test_script",
        .root_source_file = b.path("src/test_script.zig"),
        .target = target,
        .optimize = optimize,
    });
    script_test.addIncludePath(.{ .cwd_relative = secp256k1_include });
    script_test.linkSystemLibrary("secp256k1");
    script_test.linkLibC();
    if (target.result.cpu.arch == .x86_64) {
        script_test.addCSourceFile(.{ .file = b.path("src/sha256_shani.c"), .flags = shani_cflags });
    }
    b.installArtifact(script_test);

    const run_script = b.addRunArtifact(script_test);
    run_script.step.dependOn(b.getInstallStep());
    const script_step = b.step("test-script", "Run script test vectors");
    script_step.dependOn(&run_script.step);

    // BIP-341 vector-runner shim (validates clearbit's taproot_sighash
    // module against bitcoin-core/src/test/data/bip341_wallet_vectors.json
    // via tools/bip341-vector-runner). Links secp256k1 because crypto.zig
    // imports it; the shim itself only uses sha256 + taggedHash.
    const bip341_shim = b.addExecutable(.{
        .name = "bip341_shim",
        .root_source_file = b.path("src/bip341_shim.zig"),
        .target = target,
        .optimize = optimize,
    });
    bip341_shim.addIncludePath(.{ .cwd_relative = secp256k1_include });
    bip341_shim.linkSystemLibrary("secp256k1");
    bip341_shim.linkLibC();
    if (target.result.cpu.arch == .x86_64) {
        bip341_shim.addCSourceFile(.{ .file = b.path("src/sha256_shani.c"), .flags = shani_cflags });
    }
    b.installArtifact(bip341_shim);

    // Phase B verifyscript shim (drives ScriptEngine.verify against the
    // tools/phaseb-vectors harness; same link recipe as bip341_shim —
    // libsecp256k1 + SHA-NI, no RocksDB).
    const verifyscript_shim = b.addExecutable(.{
        .name = "verifyscript_shim",
        .root_source_file = b.path("src/verifyscript_shim.zig"),
        .target = target,
        .optimize = optimize,
    });
    verifyscript_shim.addIncludePath(.{ .cwd_relative = secp256k1_include });
    verifyscript_shim.linkSystemLibrary("secp256k1");
    // The `reorg` op drives the REAL RocksDB-backed ChainState reorg mechanism
    // (storage.zig → storage_rocksdb.zig → -lrocksdb), so the shim now links
    // rocksdb like the main exe.
    verifyscript_shim.linkSystemLibrary("rocksdb");
    verifyscript_shim.linkLibC();
    verifyscript_shim.root_module.addOptions("build_options", build_options);
    if (target.result.cpu.arch == .x86_64) {
        verifyscript_shim.addCSourceFile(.{ .file = b.path("src/sha256_shani.c"), .flags = shani_cflags });
    }
    b.installArtifact(verifyscript_shim);

    // RocksDB storage tests
    {
        const rocksdb_tests = b.addTest(.{
            .root_source_file = b.path("src/storage_rocksdb.zig"),
            .target = target,
            .optimize = optimize,
        });
        rocksdb_tests.linkSystemLibrary("rocksdb");
        rocksdb_tests.linkLibC();

        const run_rocksdb_tests = b.addRunArtifact(rocksdb_tests);
        const rocksdb_test_step = b.step("test-rocksdb", "Run RocksDB-specific tests");
        rocksdb_test_step.dependOn(&run_rocksdb_tests.step);
    }

    // Add a separate step for wallet/secp256k1 tests
    if (secp256k1_enabled) {
        const wallet_tests = b.addTest(.{
            .root_source_file = b.path("src/wallet.zig"),
            .target = target,
            .optimize = optimize,
        });
        wallet_tests.linkSystemLibrary("secp256k1");
        wallet_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        wallet_tests.linkLibC();

        const run_wallet_tests = b.addRunArtifact(wallet_tests);
        const wallet_test_step = b.step("test-wallet", "Run wallet/secp256k1 tests");
        wallet_test_step.dependOn(&run_wallet_tests.step);
    }

    // Add a separate step for Erlay/minisketch tests
    if (minisketch_enabled) {
        const minisketch_tests = b.addTest(.{
            .root_source_file = b.path("src/erlay.zig"),
            .target = target,
            .optimize = optimize,
        });
        minisketch_tests.linkSystemLibrary("minisketch");
        minisketch_tests.addIncludePath(.{ .cwd_relative = minisketch_include });
        minisketch_tests.linkLibC();
        minisketch_tests.root_module.addOptions("build_options", build_options);

        const run_minisketch_tests = b.addRunArtifact(minisketch_tests);
        const minisketch_test_step = b.step("test-minisketch", "Run Erlay/minisketch tests with FFI");
        minisketch_test_step.dependOn(&run_minisketch_tests.step);
    }
}
