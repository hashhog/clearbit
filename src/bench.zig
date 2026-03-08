//! Benchmarking utilities for clearbit performance testing.
//!
//! This module provides benchmarks for critical paths:
//! - Block deserialization throughput
//! - Script validation performance
//! - SHA-256 hashing throughput
//! - UTXO cache operations
//! - Merkle root computation
//!
//! Run benchmarks with: zig build -Doptimize=ReleaseFast
//! Then: ./zig-out/bin/clearbit --benchmark

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const perf = @import("perf.zig");
const script = @import("script.zig");

// ============================================================================
// Benchmark Framework
// ============================================================================

/// Result of a single benchmark run.
pub const BenchmarkResult = struct {
    name: []const u8,
    iterations: u64,
    total_ns: u64,
    bytes_processed: u64,

    /// Nanoseconds per iteration.
    pub fn nsPerOp(self: BenchmarkResult) f64 {
        if (self.iterations == 0) return 0;
        return @as(f64, @floatFromInt(self.total_ns)) / @as(f64, @floatFromInt(self.iterations));
    }

    /// Operations per second.
    pub fn opsPerSec(self: BenchmarkResult) f64 {
        if (self.total_ns == 0) return 0;
        const secs = @as(f64, @floatFromInt(self.total_ns)) / 1_000_000_000.0;
        return @as(f64, @floatFromInt(self.iterations)) / secs;
    }

    /// Throughput in MB/s.
    pub fn mbPerSec(self: BenchmarkResult) f64 {
        if (self.total_ns == 0 or self.bytes_processed == 0) return 0;
        const secs = @as(f64, @floatFromInt(self.total_ns)) / 1_000_000_000.0;
        const mb = @as(f64, @floatFromInt(self.bytes_processed)) / (1024.0 * 1024.0);
        return mb / secs;
    }

    /// Print formatted result.
    pub fn print(self: BenchmarkResult, writer: anytype) !void {
        try writer.print("{s:<30} {d:>12.0} ops/sec", .{ self.name, self.opsPerSec() });
        if (self.bytes_processed > 0) {
            try writer.print("  {d:>8.2} MB/s", .{self.mbPerSec()});
        }
        try writer.print("  ({d:.1} ns/op)\n", .{self.nsPerOp()});
    }
};

/// Run a benchmark function for a specified duration.
pub fn benchmark(
    name: []const u8,
    comptime func: fn (*anyopaque) usize,
    context: *anyopaque,
    min_duration_ns: u64,
) BenchmarkResult {
    var iterations: u64 = 0;
    var bytes: u64 = 0;
    const start = std.time.nanoTimestamp();

    while (true) {
        bytes += func(context);
        iterations += 1;

        const elapsed = @as(u64, @intCast(std.time.nanoTimestamp() - start));
        if (elapsed >= min_duration_ns and iterations >= 10) {
            return .{
                .name = name,
                .iterations = iterations,
                .total_ns = elapsed,
                .bytes_processed = bytes,
            };
        }
    }
}

// ============================================================================
// SHA-256 Benchmarks
// ============================================================================

const Sha256BenchContext = struct {
    data: []const u8,
};

fn benchSha256Single(ctx_ptr: *anyopaque) usize {
    const ctx: *Sha256BenchContext = @ptrCast(@alignCast(ctx_ptr));
    const result = crypto.sha256(ctx.data);
    std.mem.doNotOptimizeAway(&result);
    return ctx.data.len;
}

fn benchHash256(ctx_ptr: *anyopaque) usize {
    const ctx: *Sha256BenchContext = @ptrCast(@alignCast(ctx_ptr));
    const result = crypto.hash256(ctx.data);
    std.mem.doNotOptimizeAway(&result);
    return ctx.data.len;
}

pub fn runSha256Benchmarks(writer: anytype) !void {
    try writer.print("\n=== SHA-256 Benchmarks ===\n", .{});

    // 64 bytes (one block)
    var data_64: [64]u8 = undefined;
    @memset(&data_64, 0xAB);
    var ctx_64 = Sha256BenchContext{ .data = &data_64 };
    const result_64 = benchmark("SHA256 (64 bytes)", benchSha256Single, @ptrCast(&ctx_64), 1_000_000_000);
    try result_64.print(writer);

    // 1 KB
    var data_1k: [1024]u8 = undefined;
    @memset(&data_1k, 0xCD);
    var ctx_1k = Sha256BenchContext{ .data = &data_1k };
    const result_1k = benchmark("SHA256 (1 KB)", benchSha256Single, @ptrCast(&ctx_1k), 1_000_000_000);
    try result_1k.print(writer);

    // Double SHA256 (hash256)
    var ctx_h256 = Sha256BenchContext{ .data = &data_64 };
    const result_h256 = benchmark("hash256 (64 bytes)", benchHash256, @ptrCast(&ctx_h256), 1_000_000_000);
    try result_h256.print(writer);
}

// ============================================================================
// Hash Comparison Benchmarks
// ============================================================================

const HashCompareBenchContext = struct {
    hash: [32]u8,
    target: [32]u8,
};

fn benchHashCompareScalar(ctx_ptr: *anyopaque) usize {
    const ctx: *HashCompareBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const result = perf.hashLessThanTarget(&ctx.hash, &ctx.target);
    std.mem.doNotOptimizeAway(&result);
    return 32;
}

fn benchHashCompareSIMD(ctx_ptr: *anyopaque) usize {
    const ctx: *HashCompareBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const result = perf.hashLessThanTargetSIMD(&ctx.hash, &ctx.target);
    std.mem.doNotOptimizeAway(&result);
    return 32;
}

fn benchHashEqual(ctx_ptr: *anyopaque) usize {
    const ctx: *HashCompareBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const result = perf.hashEqual(&ctx.hash, &ctx.target);
    std.mem.doNotOptimizeAway(&result);
    return 32;
}

pub fn runHashCompareBenchmarks(writer: anytype) !void {
    try writer.print("\n=== Hash Comparison Benchmarks ===\n", .{});

    var ctx = HashCompareBenchContext{
        .hash = undefined,
        .target = undefined,
    };
    @memset(&ctx.hash, 0x11);
    @memset(&ctx.target, 0x22);

    const result_scalar = benchmark("hash < target (scalar)", benchHashCompareScalar, @ptrCast(&ctx), 1_000_000_000);
    try result_scalar.print(writer);

    const result_simd = benchmark("hash < target (SIMD)", benchHashCompareSIMD, @ptrCast(&ctx), 1_000_000_000);
    try result_simd.print(writer);

    const result_eq = benchmark("hash == hash (SIMD)", benchHashEqual, @ptrCast(&ctx), 1_000_000_000);
    try result_eq.print(writer);
}

// ============================================================================
// Merkle Root Benchmarks
// ============================================================================

const MerkleRootBenchContext = struct {
    hashes: []const [32]u8,
    allocator: std.mem.Allocator,
};

fn benchMerkleRoot(ctx_ptr: *anyopaque) usize {
    const ctx: *MerkleRootBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const result = crypto.computeMerkleRoot(ctx.hashes, ctx.allocator) catch return 0;
    std.mem.doNotOptimizeAway(&result);
    return ctx.hashes.len * 32;
}

fn benchMerkleRootSIMD(ctx_ptr: *anyopaque) usize {
    const ctx: *MerkleRootBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const result = perf.computeMerkleRootSIMD(ctx.hashes, ctx.allocator) catch return 0;
    std.mem.doNotOptimizeAway(&result);
    return ctx.hashes.len * 32;
}

pub fn runMerkleRootBenchmarks(allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("\n=== Merkle Root Benchmarks ===\n", .{});

    // Create test hashes (simulating a block with many transactions)
    const tx_counts = [_]usize{ 10, 100, 1000, 2500 };

    for (tx_counts) |count| {
        const hashes = try allocator.alloc([32]u8, count);
        defer allocator.free(hashes);

        for (hashes, 0..) |*h, i| {
            // Generate pseudo-random hash based on index
            const seed: [32]u8 = @bitCast([4]u64{ i, i * 2, i * 3, i * 4 });
            h.* = crypto.sha256(&seed);
        }

        var ctx = MerkleRootBenchContext{
            .hashes = hashes,
            .allocator = allocator,
        };

        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "merkle root ({} txs)", .{count}) catch "merkle root";
        const result = benchmark(name, benchMerkleRoot, @ptrCast(&ctx), 500_000_000);
        try result.print(writer);
    }
}

// ============================================================================
// UTXO Cache Benchmarks
// ============================================================================

const UtxoCacheBenchContext = struct {
    cache: *perf.UtxoCache,
    outpoints: []types.OutPoint,
    index: usize,
};

fn benchUtxoCachePut(ctx_ptr: *anyopaque) usize {
    const ctx: *UtxoCacheBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const outpoint = &ctx.outpoints[ctx.index % ctx.outpoints.len];
    ctx.index +%= 1;

    ctx.cache.put(outpoint, .{
        .value = 5000000000,
        .script_type = .p2wpkh,
        .height = 100000,
        .coinbase = false,
    }, null) catch return 0;

    return @sizeOf(perf.CacheEntry);
}

fn benchUtxoCacheGet(ctx_ptr: *anyopaque) usize {
    const ctx: *UtxoCacheBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const outpoint = &ctx.outpoints[ctx.index % ctx.outpoints.len];
    ctx.index +%= 1;

    const result = ctx.cache.get(outpoint);
    std.mem.doNotOptimizeAway(&result);
    return @sizeOf(perf.CacheEntry);
}

pub fn runUtxoCacheBenchmarks(allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("\n=== UTXO Cache Benchmarks ===\n", .{});

    // Create cache
    var cache = perf.UtxoCache.init(allocator, 100); // 100 MB
    defer cache.deinit();

    // Create test outpoints
    var outpoints = try allocator.alloc(types.OutPoint, 10000);
    defer allocator.free(outpoints);

    for (outpoints, 0..) |*op, i| {
        const seed: [32]u8 = @bitCast([4]u64{ i, i + 1, i + 2, i + 3 });
        op.hash = crypto.sha256(&seed);
        op.index = @intCast(i % 10);
    }

    // Pre-populate cache
    for (outpoints[0..5000]) |*op| {
        try cache.put(op, .{
            .value = 1000000,
            .script_type = .p2pkh,
            .height = 500000,
            .coinbase = false,
        }, null);
    }

    var ctx = UtxoCacheBenchContext{
        .cache = &cache,
        .outpoints = outpoints,
        .index = 0,
    };

    // Benchmark puts
    const result_put = benchmark("UTXO cache put", benchUtxoCachePut, @ptrCast(&ctx), 500_000_000);
    try result_put.print(writer);

    // Reset index for gets
    ctx.index = 0;
    const result_get = benchmark("UTXO cache get (hit)", benchUtxoCacheGet, @ptrCast(&ctx), 500_000_000);
    try result_get.print(writer);

    // Report hit rate
    try writer.print("  Cache hit rate: {d:.1}%\n", .{cache.hitRate() * 100.0});
    try writer.print("  Cache entries: {}\n", .{cache.count()});
}

// ============================================================================
// Arena Allocator Benchmarks
// ============================================================================

const ArenaBenchContext = struct {
    arena: *perf.BlockArena,
    sizes: []const usize,
    index: usize,
};

fn benchArenaAlloc(ctx_ptr: *anyopaque) usize {
    const ctx: *ArenaBenchContext = @ptrCast(@alignCast(ctx_ptr));
    const size = ctx.sizes[ctx.index % ctx.sizes.len];
    ctx.index +%= 1;

    const mem = ctx.arena.allocator().alloc(u8, size) catch return 0;
    std.mem.doNotOptimizeAway(mem.ptr);
    return size;
}

fn benchArenaReset(ctx_ptr: *anyopaque) usize {
    const ctx: *ArenaBenchContext = @ptrCast(@alignCast(ctx_ptr));

    // Allocate a bunch of memory
    for (0..100) |_| {
        const mem = ctx.arena.allocator().alloc(u8, 256) catch continue;
        std.mem.doNotOptimizeAway(mem.ptr);
    }

    // Reset all at once
    ctx.arena.reset();
    return 100 * 256;
}

pub fn runArenaBenchmarks(allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("\n=== Arena Allocator Benchmarks ===\n", .{});

    var arena = perf.BlockArena.init(allocator);
    defer arena.deinit();

    const sizes = [_]usize{ 32, 64, 128, 256, 512, 1024 };

    var ctx = ArenaBenchContext{
        .arena = &arena,
        .sizes = &sizes,
        .index = 0,
    };

    const result_alloc = benchmark("arena alloc (mixed sizes)", benchArenaAlloc, @ptrCast(&ctx), 500_000_000);
    try result_alloc.print(writer);

    arena.reset();
    const result_reset = benchmark("arena alloc + reset (100 items)", benchArenaReset, @ptrCast(&ctx), 500_000_000);
    try result_reset.print(writer);
}

// ============================================================================
// Block Serialization Benchmarks
// ============================================================================

const BlockSerializeBenchContext = struct {
    block_data: []const u8,
    allocator: std.mem.Allocator,
};

fn benchBlockDeserialize(ctx_ptr: *anyopaque) usize {
    const ctx: *BlockSerializeBenchContext = @ptrCast(@alignCast(ctx_ptr));
    var reader = serialize.Reader{ .data = ctx.block_data };

    const block = serialize.readBlock(&reader, ctx.allocator) catch return 0;
    defer {
        for (block.transactions) |tx| {
            for (tx.inputs) |input| {
                ctx.allocator.free(input.script_sig);
                ctx.allocator.free(input.witness);
            }
            ctx.allocator.free(tx.inputs);
            for (tx.outputs) |output| {
                ctx.allocator.free(output.script_pubkey);
            }
            ctx.allocator.free(tx.outputs);
        }
        ctx.allocator.free(block.transactions);
    }

    return ctx.block_data.len;
}

fn benchBlockDeserializeArena(ctx_ptr: *anyopaque) usize {
    const ctx: *BlockSerializeBenchContext = @ptrCast(@alignCast(ctx_ptr));

    // Use arena for all allocations
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();

    var reader = serialize.Reader{ .data = ctx.block_data };
    const block = serialize.readBlock(&reader, arena.allocator()) catch return 0;
    std.mem.doNotOptimizeAway(&block);

    // Arena frees everything at once - no per-object cleanup needed
    return ctx.block_data.len;
}

pub fn runBlockSerializeBenchmarks(allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("\n=== Block Serialization Benchmarks ===\n", .{});

    // Create a synthetic block for benchmarking
    // A typical mainnet block is ~1-2 MB with ~2000 transactions
    const block_data = try createSyntheticBlock(allocator, 100); // 100 transactions
    defer allocator.free(block_data);

    try writer.print("  Synthetic block size: {} bytes ({} transactions)\n", .{ block_data.len, 100 });

    var ctx = BlockSerializeBenchContext{
        .block_data = block_data,
        .allocator = allocator,
    };

    const result_normal = benchmark("block deserialize (normal)", benchBlockDeserialize, @ptrCast(&ctx), 500_000_000);
    try result_normal.print(writer);

    const result_arena = benchmark("block deserialize (arena)", benchBlockDeserializeArena, @ptrCast(&ctx), 500_000_000);
    try result_arena.print(writer);
}

/// Create a synthetic block for benchmarking.
fn createSyntheticBlock(allocator: std.mem.Allocator, tx_count: usize) ![]const u8 {
    var block_writer = serialize.Writer.init(allocator);
    defer block_writer.deinit();

    // Block header (80 bytes)
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0xAB} ** 32,
        .timestamp = 1234567890,
        .bits = 0x1d00ffff,
        .nonce = 12345,
    };
    try serialize.writeBlockHeader(&block_writer, &header);

    // Transaction count
    try block_writer.writeCompactSize(tx_count);

    // Create transactions
    for (0..tx_count) |tx_idx| {
        // Simple transaction with 2 inputs and 2 outputs
        try block_writer.writeInt(i32, 1); // version

        // Inputs
        const input_count: usize = if (tx_idx == 0) 1 else 2;
        try block_writer.writeCompactSize(input_count);
        for (0..input_count) |_| {
            try block_writer.writeBytes(&([_]u8{0x11} ** 32)); // prev txid
            try block_writer.writeInt(u32, 0); // prev index
            // ScriptSig (25 bytes for P2PKH)
            try block_writer.writeCompactSize(25);
            try block_writer.writeBytes(&([_]u8{0x47} ** 25));
            try block_writer.writeInt(u32, 0xFFFFFFFF); // sequence
        }

        // Outputs
        try block_writer.writeCompactSize(2);
        for (0..2) |_| {
            try block_writer.writeInt(i64, 50000000); // value
            // P2PKH scriptPubKey (25 bytes)
            try block_writer.writeCompactSize(25);
            var spk: [25]u8 = undefined;
            spk[0] = 0x76;
            spk[1] = 0xa9;
            spk[2] = 0x14;
            @memset(spk[3..23], 0xAB);
            spk[23] = 0x88;
            spk[24] = 0xac;
            try block_writer.writeBytes(&spk);
        }

        try block_writer.writeInt(u32, 0); // locktime
    }

    return try block_writer.toOwnedSlice();
}

// ============================================================================
// Script Execution Benchmarks
// ============================================================================

const ScriptBenchContext = struct {
    script: []const u8,
    tx: *const types.Transaction,
    allocator: std.mem.Allocator,
};

fn benchScriptExecute(ctx_ptr: *anyopaque) usize {
    const ctx: *ScriptBenchContext = @ptrCast(@alignCast(ctx_ptr));

    var engine = script.ScriptEngine.init(
        ctx.allocator,
        ctx.tx,
        0,
        5000000000,
        script.ScriptFlags{},
    );
    defer engine.deinit();

    engine.execute(ctx.script) catch {};
    return ctx.script.len;
}

pub fn runScriptBenchmarks(allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("\n=== Script Execution Benchmarks ===\n", .{});

    // Create a minimal transaction
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{},
        .lock_time = 0,
    };

    // Simple arithmetic script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
    const simple_script = [_]u8{ 0x51, 0x51, 0x93, 0x52, 0x87 };
    var ctx_simple = ScriptBenchContext{
        .script = &simple_script,
        .tx = &tx,
        .allocator = allocator,
    };
    const result_simple = benchmark("script (simple arithmetic)", benchScriptExecute, @ptrCast(&ctx_simple), 500_000_000);
    try result_simple.print(writer);

    // Hash script: OP_1 OP_HASH160
    const hash_script = [_]u8{ 0x51, 0xa9 };
    var ctx_hash = ScriptBenchContext{
        .script = &hash_script,
        .tx = &tx,
        .allocator = allocator,
    };
    const result_hash = benchmark("script (HASH160)", benchScriptExecute, @ptrCast(&ctx_hash), 500_000_000);
    try result_hash.print(writer);

    // Stack manipulation: OP_1 OP_DUP OP_DUP OP_DUP OP_DROP OP_DROP OP_DROP
    const stack_script = [_]u8{ 0x51, 0x76, 0x76, 0x76, 0x75, 0x75, 0x75 };
    var ctx_stack = ScriptBenchContext{
        .script = &stack_script,
        .tx = &tx,
        .allocator = allocator,
    };
    const result_stack = benchmark("script (stack ops)", benchScriptExecute, @ptrCast(&ctx_stack), 500_000_000);
    try result_stack.print(writer);
}

// ============================================================================
// Main Benchmark Runner
// ============================================================================

/// Run all benchmarks.
pub fn runAllBenchmarks(allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("clearbit Performance Benchmarks\n", .{});
    try writer.print("================================\n", .{});
    try writer.print("Running with {} threads\n", .{std.Thread.getCpuCount() catch 1});

    try runSha256Benchmarks(writer);
    try runHashCompareBenchmarks(writer);
    try runMerkleRootBenchmarks(allocator, writer);
    try runUtxoCacheBenchmarks(allocator, writer);
    try runArenaBenchmarks(allocator, writer);
    try runBlockSerializeBenchmarks(allocator, writer);
    try runScriptBenchmarks(allocator, writer);

    try writer.print("\n=== Benchmark Complete ===\n", .{});
}

// ============================================================================
// Tests
// ============================================================================

test "benchmark result calculations" {
    const result = BenchmarkResult{
        .name = "test",
        .iterations = 1000,
        .total_ns = 1_000_000_000, // 1 second
        .bytes_processed = 1024 * 1024, // 1 MB
    };

    try std.testing.expectApproxEqAbs(@as(f64, 1_000_000), result.nsPerOp(), 1);
    try std.testing.expectApproxEqAbs(@as(f64, 1000), result.opsPerSec(), 1);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), result.mbPerSec(), 0.01);
}

test "synthetic block creation" {
    const allocator = std.testing.allocator;

    const block_data = try createSyntheticBlock(allocator, 10);
    defer allocator.free(block_data);

    // Should be able to parse it back
    var reader = serialize.Reader{ .data = block_data };
    const block = try serialize.readBlock(&reader, allocator);
    defer {
        for (block.transactions) |tx| {
            for (tx.inputs) |input| {
                allocator.free(input.script_sig);
                allocator.free(input.witness);
            }
            allocator.free(tx.inputs);
            for (tx.outputs) |output| {
                allocator.free(output.script_pubkey);
            }
            allocator.free(tx.outputs);
        }
        allocator.free(block.transactions);
    }

    try std.testing.expectEqual(@as(usize, 10), block.transactions.len);
}
