//! cffix-clearbit-dup-input-quadratic (secscan2-clearbit S2-F1).
//!
//! checkTransactionSanity step 3 (the duplicate-input check, Core
//! consensus/tx_check.cpp:41-44) used a pairwise scan over the inputs.  Step 1b
//! (base size * 4 <= MAX_BLOCK_WEIGHT) still admits 24,389 inputs, so one
//! relayed 1 MB tx cost ~3e8 outpoint comparisons, all of it under
//! lockChainThenPool() in Mempool.addTransaction.  Core inserts the prevouts
//! into a std::set<COutPoint>: O(n log n).
//!
//! The first test pins the growth rate, not a wall-clock number, so it holds
//! in Debug and in ReleaseSafe alike: a 16x larger tx may cost at most 80x
//! the time (n log n predicts ~22x, a pairwise scan ~256x).  The rest are
//! controls: the verdict and the reject token are unchanged.
const std = @import("std");
const types = @import("types.zig");
const validation = @import("validation.zig");
const mempool_mod = @import("mempool.zig");

const ValidationError = validation.ValidationError;

/// The most inputs a tx can have and still pass step 1b: 21 bytes of fixed
/// fields (version 4, vin count 3, vout count 1, one empty-script output 9,
/// locktime 4) plus 41 bytes per input (prevout 36, script len 1, sequence 4).
const MAX_INPUTS: usize = 24_389;

const SHARED_HASH: [32]u8 = blk: {
    var h: [32]u8 = undefined;
    for (&h, 0..) |*b, k| b.* = @intCast((k * 37 + 11) & 0xff);
    break :blk h;
};

const EMPTY_OUT = [_]types.TxOut{.{ .value = 0, .script_pubkey = &[_]u8{} }};

/// `n` inputs that all share one prevout hash and use indices 0..n-1, so no
/// two are equal and every outpoint comparison has to read the whole hash.
fn distinctInputs(allocator: std.mem.Allocator, n: usize) ![]types.TxIn {
    const inputs = try allocator.alloc(types.TxIn, n);
    for (inputs, 0..) |*in, k| in.* = .{
        .previous_output = .{ .hash = SHARED_HASH, .index = @intCast(k) },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFF_FFFF,
        .witness = &[_][]const u8{},
    };
    return inputs;
}

fn txOf(inputs: []const types.TxIn) types.Transaction {
    return .{ .version = 2, .inputs = inputs, .outputs = &EMPTY_OUT, .lock_time = 0 };
}

/// Fastest of `reps` runs of checkTransactionSanity, in ns.  The tx must pass.
fn minSanityNs(tx: *const types.Transaction, reps: usize) !u64 {
    var best: u64 = std.math.maxInt(u64);
    for (0..reps) |_| {
        var timer = try std.time.Timer.start();
        try validation.checkTransactionSanity(tx);
        best = @min(best, timer.read());
    }
    return @max(best, 1);
}

test "cffix dup-input: checkTransactionSanity duplicate-input check is O(n log n), not pairwise" {
    const allocator = std.testing.allocator;
    const small_n = MAX_INPUTS / 16;

    const big_inputs = try distinctInputs(allocator, MAX_INPUTS);
    defer allocator.free(big_inputs);
    const small_inputs = try distinctInputs(allocator, small_n);
    defer allocator.free(small_inputs);
    const big = txOf(big_inputs);
    const small = txOf(small_inputs);

    // The big tx is the largest step 1b admits (21 + 41 * 24,389 = 999,970
    // base bytes), so the test measures the real worst case; minSanityNs
    // requires it to pass, so a TxTooLarge would fail the test, not skip it.
    try std.testing.expectEqual(@as(usize, 999_970), 21 + 41 * MAX_INPUTS);

    const small_ns = try minSanityNs(&small, 7);
    const big_ns = try minSanityNs(&big, 3);
    const ratio = @as(f64, @floatFromInt(big_ns)) / @as(f64, @floatFromInt(small_ns));
    std.debug.print(
        "\n  dup-input growth: n={d} {d:.3} ms, n={d} {d:.3} ms, ratio {d:.1} (O(n log n) ~22, pairwise ~256, limit 80)\n",
        .{ small_n, @as(f64, @floatFromInt(small_ns)) / 1e6, MAX_INPUTS, @as(f64, @floatFromInt(big_ns)) / 1e6, ratio },
    );
    if (ratio > 80.0) {
        std.debug.print("  duplicate-input check grew {d:.1}x for 16x the inputs: quadratic\n", .{ratio});
        return error.DuplicateInputCheckIsQuadratic;
    }
}

test "cffix dup-input CONTROL: a duplicate at inputs (0, n-1) of a max-size tx is still DuplicateInput" {
    const allocator = std.testing.allocator;
    const inputs = try distinctInputs(allocator, MAX_INPUTS);
    defer allocator.free(inputs);
    inputs[MAX_INPUTS - 1].previous_output = inputs[0].previous_output;
    const tx = txOf(inputs);
    try std.testing.expectError(ValidationError.DuplicateInput, validation.checkTransactionSanity(&tx));
}

test "cffix dup-input CONTROL: inputs (0,1,0) is DuplicateInput, both alone and inside a 40-input tx" {
    const allocator = std.testing.allocator;
    // Three inputs: the small-tx path.
    {
        const inputs = try distinctInputs(allocator, 3);
        defer allocator.free(inputs);
        inputs[2].previous_output = inputs[0].previous_output;
        const tx = txOf(inputs);
        try std.testing.expectError(ValidationError.DuplicateInput, validation.checkTransactionSanity(&tx));
    }
    // Forty inputs: past the small-tx cutoff, so the sorted path.
    {
        const inputs = try distinctInputs(allocator, 40);
        defer allocator.free(inputs);
        inputs[2].previous_output = inputs[0].previous_output;
        const tx = txOf(inputs);
        try std.testing.expectError(ValidationError.DuplicateInput, validation.checkTransactionSanity(&tx));
    }
}

test "cffix dup-input CONTROL: same hash / other index and same index / other hash are not duplicates" {
    const allocator = std.testing.allocator;
    for ([_]usize{ 3, 40, MAX_INPUTS }) |n| {
        // Same hash, every index different.
        const a = try distinctInputs(allocator, n);
        defer allocator.free(a);
        const tx_a = txOf(a);
        try validation.checkTransactionSanity(&tx_a);

        // Same index, hashes differing only in the last byte (and in byte 30
        // past 256 inputs): neighbours after the sort differ in one byte.
        const b = try distinctInputs(allocator, n);
        defer allocator.free(b);
        for (b, 0..) |*in, k| {
            in.previous_output.index = 7;
            in.previous_output.hash[31] = @intCast(k & 0xff);
            in.previous_output.hash[30] = @intCast((k >> 8) & 0xff);
        }
        const tx_b = txOf(b);
        try validation.checkTransactionSanity(&tx_b);
    }
}

test "cffix dup-input CONTROL: two null prevouts are DuplicateInput before NullInput (Core's check order)" {
    const allocator = std.testing.allocator;
    for ([_]usize{ 3, 40 }) |n| {
        const inputs = try distinctInputs(allocator, n);
        defer allocator.free(inputs);
        inputs[1].previous_output = types.OutPoint.COINBASE;
        const one_null = txOf(inputs);
        try std.testing.expectError(ValidationError.NullInput, validation.checkTransactionSanity(&one_null));

        inputs[n - 1].previous_output = types.OutPoint.COINBASE;
        const two_null = txOf(inputs);
        try std.testing.expectError(ValidationError.DuplicateInput, validation.checkTransactionSanity(&two_null));
    }
}

test "cffix dup-input CONTROL: relay path rejects a max-size duplicate tx as InputsDuplicate (bad-txns-inputs-duplicate)" {
    const allocator = std.testing.allocator;
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();

    const inputs = try distinctInputs(allocator, MAX_INPUTS);
    defer allocator.free(inputs);
    inputs[MAX_INPUTS - 1].previous_output = inputs[0].previous_output;
    try std.testing.expectError(mempool_mod.MempoolError.InputsDuplicate, mempool.addTransaction(txOf(inputs)));
}
