const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // RocksDB is required for full functionality but optional for basic testing
    // When RocksDB is available, use: zig build -Drocksdb=true
    const rocksdb_enabled = b.option(bool, "rocksdb", "Enable RocksDB support (requires librocksdb-dev)") orelse false;

    // libsecp256k1 is required for wallet functionality and BIP324 v2 transport
    // When available, use: zig build -Dsecp256k1=true
    const secp256k1_enabled = b.option(bool, "secp256k1", "Enable libsecp256k1 support (requires libsecp256k1-dev)") orelse false;

    // Path to libsecp256k1 include directory (for ElligatorSwift headers)
    // Default to Bitcoin Core's bundled version, can be overridden
    const secp256k1_include = b.option([]const u8, "secp256k1-include", "Path to libsecp256k1 include directory") orelse "../bitcoin/src/secp256k1/include";

    const exe = b.addExecutable(.{
        .name = "clearbit",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link RocksDB if enabled
    if (rocksdb_enabled) {
        exe.linkSystemLibrary("rocksdb");
        exe.linkLibC();
    }

    // Link libsecp256k1 if enabled
    if (secp256k1_enabled) {
        exe.linkSystemLibrary("secp256k1");
        exe.addIncludePath(.{ .cwd_relative = secp256k1_include });
        exe.linkLibC();
    }

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

    // Link RocksDB for tests if enabled
    if (rocksdb_enabled) {
        unit_tests.linkSystemLibrary("rocksdb");
        unit_tests.linkLibC();
    }

    // Link libsecp256k1 for tests if enabled
    if (secp256k1_enabled) {
        unit_tests.linkSystemLibrary("secp256k1");
        unit_tests.addIncludePath(.{ .cwd_relative = secp256k1_include });
        unit_tests.linkLibC();
    }

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Add a separate step for RocksDB tests
    if (rocksdb_enabled) {
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
}
