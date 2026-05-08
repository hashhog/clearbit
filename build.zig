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
            .filters = &[_][]const u8{"BIP-86", "BIP-341", "wallet computeTaprootSigHash", "signInput .p2tr"},
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
