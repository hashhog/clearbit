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

    // Create build options module that all modules can import
    const build_options = b.addOptions();
    build_options.addOption(bool, "minisketch_enabled", minisketch_enabled);

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

    // Add build options module to tests
    unit_tests.root_module.addOptions("build_options", build_options);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

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
