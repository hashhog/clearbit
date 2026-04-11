const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
    exe.addLibraryPath(.{ .cwd_relative = "/home/max/.local/lib64" });
    exe.linkSystemLibrary("secp256k1");
    exe.linkLibC();

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
    unit_tests.addLibraryPath(.{ .cwd_relative = "/home/max/.local/lib64" });
    unit_tests.linkLibC();

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

    // Sighash test harness (links secp256k1 since crypto.zig requires it)
    const sighash_test = b.addExecutable(.{
        .name = "test_sighash",
        .root_source_file = b.path("src/test_sighash.zig"),
        .target = target,
        .optimize = optimize,
    });
    sighash_test.addIncludePath(.{ .cwd_relative = secp256k1_include });
    sighash_test.addLibraryPath(.{ .cwd_relative = "/home/max/.local/lib64" });
    sighash_test.linkSystemLibrary("secp256k1");
    sighash_test.linkLibC();
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
    script_test.addLibraryPath(.{ .cwd_relative = "/home/max/.local/lib64" });
    script_test.linkSystemLibrary("secp256k1");
    script_test.linkLibC();
    b.installArtifact(script_test);

    const run_script = b.addRunArtifact(script_test);
    run_script.step.dependOn(b.getInstallStep());
    const script_step = b.step("test-script", "Run script test vectors");
    script_step.dependOn(&run_script.step);

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
