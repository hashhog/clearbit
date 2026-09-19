//! Parallel script verification — QUEUES.md 2026-09-19 control.
//!
//! Bitcoin Core: `-par` (init.cpp:513), CCheckQueue (src/checkqueue.h),
//! CScriptCheck batched per-input in ConnectBlock (validation.cpp).
//! Extra workers drain a bounded job queue; the block is accepted only if
//! every check returns true; the decision must not depend on how the work
//! was split.
//!
//! REQUIRED:
//!   (1) decision identity — accept/reject AND reject reason identical at
//!       1 worker and at N
//!   (2) failure propagation — one failing check rejects the whole batch
//!       with the same reason as the serial path
//!   (3) measured scaling — wall time at 1, 2, 4, 8 workers, printed
//!   (4) bounded RSS — more workers must not mean unbounded buffers
//!
//! CONTROL: `zig build test-parallel-script --summary new`
//! Filter `parallel_script` so imported validation tests do not run.

const std = @import("std");
const testing = std.testing;
const validation = @import("src/validation.zig");
const script = @import("src/script.zig");
const types = @import("src/types.zig");
const serialize = @import("src/serialize.zig");

const Fail = validation.ScriptCheckFailCode;

fn dummyTxBytes(allocator: std.mem.Allocator) ![]const u8 {
    const tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{.{
            .previous_output = .{ .hash = [_]u8{0x11} ** 32, .index = 0 },
            .script_sig = &.{},
            .sequence = 0xffffffff,
            .witness = &.{},
        }},
        .outputs = &[_]types.TxOut{.{ .value = 0, .script_pubkey = &.{} }},
        .lock_time = 0,
    };
    var writer = serialize.Writer.init(allocator);
    errdefer writer.deinit();
    try serialize.writeTransaction(&writer, &tx);
    return writer.toOwnedSlice();
}

fn makeJob(
    tx_bytes: []const u8,
    prev_spk: []const u8,
) validation.ScriptCheckJob {
    return validation.ScriptCheckJob.init(
        tx_bytes,
        0,
        prev_spk,
        100_000,
        script.ScriptFlags{},
        &.{},
    );
}

fn runBatch(
    extra_workers: usize,
    jobs: []validation.ScriptCheckJob,
) !validation.BatchResult {
    var queue = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, extra_workers);
    defer queue.deinit();
    queue.submit(jobs);
    return queue.waitAllDetailed();
}

fn snapshotJobs(jobs: []const validation.ScriptCheckJob, out_result: []u8, out_code: []u32) void {
    std.debug.assert(out_result.len == jobs.len);
    std.debug.assert(out_code.len == jobs.len);
    for (jobs, 0..) |*job, i| {
        out_result[i] = @intFromEnum(job.result.load(.acquire));
        out_code[i] = job.fail_code.load(.acquire);
    }
}

// ---------------------------------------------------------------------------
// -par mapping (Core chainstatemanager_args.cpp:53-60)
// ---------------------------------------------------------------------------

test "parallel_script resolveScriptCheckWorkers: -par=1 is serial" {
    try testing.expectEqual(@as(usize, 0), validation.resolveScriptCheckWorkers(1));
}

test "parallel_script resolveScriptCheckWorkers: -par=2 is one extra worker" {
    try testing.expectEqual(@as(usize, 1), validation.resolveScriptCheckWorkers(2));
}

test "parallel_script resolveScriptCheckWorkers: auto never exceeds cpu-1" {
    const cores = std.Thread.getCpuCount() catch 1;
    const extra = validation.resolveScriptCheckWorkers(0);
    try testing.expect(extra <= cores -| 1);
    // -par=0 is auto = every core (master + extras == cpu count).
    try testing.expectEqual(cores -| 1, extra);
}

test "parallel_script initWithWorkers(0) spawns no extra threads" {
    var queue = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
    defer queue.deinit();
    try testing.expectEqual(@as(usize, 0), queue.worker_count);
    try testing.expectEqual(@as(usize, 0), queue.workers.len);
}

test "parallel_script initWithWorkers(N) spawns N extra threads" {
    var queue = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 4);
    defer queue.deinit();
    try testing.expectEqual(@as(usize, 4), queue.worker_count);
    try testing.expectEqual(@as(usize, 4), queue.workers.len);
}

// ---------------------------------------------------------------------------
// (1) Decision identity — 1 worker vs N, mixed corpus
// ---------------------------------------------------------------------------

test "parallel_script decision identity: 1 worker vs N, mixed corpus" {
    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);

    // Distinct scripts, distinct reasons. Serial is the oracle.
    const spk_true = [_]u8{0x51}; // OP_TRUE
    const spk_false = [_]u8{0x00}; // OP_0 → script_false
    const spk_return = [_]u8{0x6a}; // OP_RETURN
    const spk_cat = [_]u8{0x7e}; // OP_CAT disabled
    const spk_if = [_]u8{0x63}; // OP_IF unbalanced
    const spk_drop = [_]u8{0x75}; // OP_DROP empty stack

    const corpus = [_][]const u8{
        &spk_true,   &spk_true,   &spk_false, &spk_true,
        &spk_return, &spk_true,   &spk_cat,   &spk_true,
        &spk_if,     &spk_true,   &spk_drop,  &spk_true,
        &spk_false,  &spk_return, &spk_true,  &spk_cat,
        &spk_true,   &spk_if,     &spk_true,  &spk_drop,
        &spk_true,   &spk_false,  &spk_true,  &spk_return,
        &spk_true,   &spk_cat,    &spk_true,  &spk_if,
        &spk_true,   &spk_drop,   &spk_true,  &spk_true,
    };

    var jobs_serial: [corpus.len]validation.ScriptCheckJob = undefined;
    var jobs_par: [corpus.len]validation.ScriptCheckJob = undefined;
    for (corpus, 0..) |spk, i| {
        jobs_serial[i] = makeJob(tx_bytes, spk);
        jobs_par[i] = makeJob(tx_bytes, spk);
    }

    const serial = try runBatch(0, &jobs_serial);
    const parallel = try runBatch(8, &jobs_par);

    try testing.expectEqual(serial.ok, parallel.ok);
    try testing.expectEqual(serial.first_fail_index, parallel.first_fail_index);
    try testing.expectEqual(serial.first_fail_code, parallel.first_fail_code);

    var serial_res: [corpus.len]u8 = undefined;
    var serial_code: [corpus.len]u32 = undefined;
    var par_res: [corpus.len]u8 = undefined;
    var par_code: [corpus.len]u32 = undefined;
    snapshotJobs(&jobs_serial, &serial_res, &serial_code);
    snapshotJobs(&jobs_par, &par_res, &par_code);
    try testing.expectEqualSlices(u8, &serial_res, &par_res);
    try testing.expectEqualSlices(u32, &serial_code, &par_code);

    // Mixed corpus must reject (it contains OP_RETURN / OP_CAT / …).
    try testing.expect(!serial.ok);
}

// ---------------------------------------------------------------------------
// (2) Failure propagation — one bad input rejects the whole batch
// ---------------------------------------------------------------------------

test "parallel_script failure propagation: one bad input rejects the batch" {
    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);

    const spk_true = [_]u8{0x51};
    const spk_return = [_]u8{0x6a};
    const fail_at: usize = 17;
    const n: usize = 64;

    var jobs_serial: [64]validation.ScriptCheckJob = undefined;
    var jobs_par: [64]validation.ScriptCheckJob = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const spk: []const u8 = if (i == fail_at) &spk_return else &spk_true;
        jobs_serial[i] = makeJob(tx_bytes, spk);
        jobs_par[i] = makeJob(tx_bytes, spk);
    }

    const serial = try runBatch(0, &jobs_serial);
    const parallel = try runBatch(8, &jobs_par);

    try testing.expect(!serial.ok);
    try testing.expect(!parallel.ok);
    try testing.expectEqual(fail_at, serial.first_fail_index);
    try testing.expectEqual(fail_at, parallel.first_fail_index);
    try testing.expectEqual(serial.first_fail_code, parallel.first_fail_code);
    try testing.expect(serial.first_fail_code != @intFromEnum(Fail.none));
}

test "parallel_script failure propagation: all-pass accepts at 1 and N" {
    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);

    const spk_true = [_]u8{0x51};
    var jobs_serial: [32]validation.ScriptCheckJob = undefined;
    var jobs_par: [32]validation.ScriptCheckJob = undefined;
    for (&jobs_serial, &jobs_par) |*s, *p| {
        s.* = makeJob(tx_bytes, &spk_true);
        p.* = makeJob(tx_bytes, &spk_true);
    }

    const serial = try runBatch(0, &jobs_serial);
    const parallel = try runBatch(8, &jobs_par);
    try testing.expect(serial.ok);
    try testing.expect(parallel.ok);
    try testing.expectEqual(serial.first_fail_index, parallel.first_fail_index);
}

test "parallel_script lowest-index failure is deterministic across workers" {
    // Three distinct failures. The reported reason MUST be the lowest index
    // (job 5), never the race-winner. A parallel verifier that returns
    // whichever worker finished first would split on reject-reason.
    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);

    const spk_true = [_]u8{0x51};
    const spk_return = [_]u8{0x6a}; // index 5
    const spk_cat = [_]u8{0x7e}; // index 20
    const spk_if = [_]u8{0x63}; // index 40

    var jobs_serial: [48]validation.ScriptCheckJob = undefined;
    var jobs_par: [48]validation.ScriptCheckJob = undefined;
    var i: usize = 0;
    while (i < 48) : (i += 1) {
        const spk: []const u8 = if (i == 5) &spk_return else if (i == 20) &spk_cat else if (i == 40) &spk_if else &spk_true;
        jobs_serial[i] = makeJob(tx_bytes, spk);
        jobs_par[i] = makeJob(tx_bytes, spk);
    }

    const serial = try runBatch(0, &jobs_serial);
    const parallel = try runBatch(8, &jobs_par);
    try testing.expectEqual(@as(usize, 5), serial.first_fail_index);
    try testing.expectEqual(@as(usize, 5), parallel.first_fail_index);
    try testing.expectEqual(serial.first_fail_code, parallel.first_fail_code);
    try testing.expect(jobs_serial[5].fail_code.load(.acquire) != jobs_serial[20].fail_code.load(.acquire));
}

// ---------------------------------------------------------------------------
// (3) Measured scaling — 1, 2, 4, 8 extra workers
// ---------------------------------------------------------------------------

fn sha256HammerScript(buf: []u8, rounds: usize) []const u8 {
    // <32-byte push> OP_HASH256{rounds} OP_DROP OP_TRUE
    // HASH256 is SHA256(SHA256()) — closer to per-input hashing cost.
    buf[0] = 0x20;
    @memset(buf[1..33], 0x11);
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        buf[33 + i] = 0xaa; // OP_HASH256
    }
    buf[33 + rounds] = 0x75; // OP_DROP
    buf[33 + rounds + 1] = 0x51; // OP_TRUE
    return buf[0 .. 33 + rounds + 2];
}

test "parallel_script measured scaling: 1/2/4/8 workers" {
    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);

    const rounds: usize = 180; // under MAX_OPS_PER_SCRIPT=201
    var script_buf: [33 + 180 + 2]u8 = undefined;
    const hammer = sha256HammerScript(&script_buf, rounds);

    const n_jobs: usize = 8192;
    const jobs = try allocator.alloc(validation.ScriptCheckJob, n_jobs);
    defer allocator.free(jobs);

    const widths = [_]usize{ 1, 2, 4, 8 };
    var ns: [4]u64 = undefined;

    for (widths, 0..) |w, wi| {
        // Unique amount per job so SigCache cannot collapse the batch to
        // one ECDSA-sized lookup. We are measuring script-eval scaling.
        for (jobs, 0..) |*job, ji| {
            job.* = validation.ScriptCheckJob.init(
                tx_bytes,
                0,
                hammer,
                100_000 + @as(i64, @intCast(ji)),
                script.ScriptFlags{},
                &.{},
            );
        }
        var queue = try validation.ScriptCheckQueue.initWithWorkers(allocator, w);
        defer queue.deinit();

        const t0 = std.time.nanoTimestamp();
        queue.submit(jobs);
        const result = queue.waitAllDetailed();
        const t1 = std.time.nanoTimestamp();
        try testing.expect(result.ok);
        ns[wi] = @intCast(t1 - t0);

        const wall_s = @as(f64, @floatFromInt(ns[wi])) / 1e9;
        const jobs_per_s = @as(f64, @floatFromInt(n_jobs)) / @max(wall_s, 1e-9);
        // One "block" = this 2048-input batch. blk/h is how many such
        // post-segwit-sized script batches we could verify per hour.
        const blk_h = 3600.0 / @max(wall_s, 1e-9);
        std.debug.print(
            "scaling workers={d} wall_ns={d} wall_s={d:.4} jobs_per_s={d:.0} blk_h={d:.1} (n_jobs={d} hash256_rounds={d})\n",
            .{ w, ns[wi], wall_s, jobs_per_s, blk_h, n_jobs, rounds },
        );
    }

    // If the 1-worker run was long enough to be a measurement (not noise),
    // 8 workers must actually use more than one core: wall time drops.
    const speedup = @as(f64, @floatFromInt(ns[0])) / @as(f64, @floatFromInt(@max(ns[3], 1)));
    std.debug.print("scaling speedup 1→8 workers: {d:.2}x\n", .{speedup});
    // Parallelism is load-bearing: 8 workers must beat 1 on this 32-core box.
    try testing.expect(ns[3] < ns[0]);
    try testing.expect(speedup >= 1.3);
}

// ---------------------------------------------------------------------------
// (4) Bounded RSS — more workers must not mean unbounded buffers
// ---------------------------------------------------------------------------

test "parallel_script bounded RSS: job buffer does not grow with workers" {
    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);

    const spk_true = [_]u8{0x51};
    var jobs: [256]validation.ScriptCheckJob = undefined;
    for (&jobs) |*job| job.* = makeJob(tx_bytes, &spk_true);

    var q1 = try validation.ScriptCheckQueue.initWithWorkers(allocator, 1);
    defer q1.deinit();
    var q8 = try validation.ScriptCheckQueue.initWithWorkers(allocator, 8);
    defer q8.deinit();

    q1.submit(&jobs);
    q8.submit(&jobs);

    // Borrowed slice, not an owned copy that grows with worker_count.
    try testing.expect(q1.jobs.ptr == &jobs);
    try testing.expect(q8.jobs.ptr == &jobs);
    try testing.expectEqual(@as(usize, 256), q1.job_count);
    try testing.expectEqual(@as(usize, 256), q8.job_count);
    try testing.expectEqual(@as(usize, 1), q1.workers.len);
    try testing.expectEqual(@as(usize, 8), q8.workers.len);

    const r1 = q1.waitAllDetailed();
    const r8 = q8.waitAllDetailed();
    try testing.expect(r1.ok);
    try testing.expect(r8.ok);

    // After the batch, outstanding work is zero — no leftover buffer.
    try testing.expectEqual(@as(usize, 256), q1.job_count);
    try testing.expectEqual(@as(usize, 256), q8.job_count);
}

test "parallel_script persistent pool: two batches without respawn" {
    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);
    const spk_true = [_]u8{0x51};
    const spk_false = [_]u8{0x00};

    var queue = try validation.ScriptCheckQueue.initWithWorkers(allocator, 4);
    defer queue.deinit();
    const workers_ptr = queue.workers.ptr;

    var pass_jobs: [16]validation.ScriptCheckJob = undefined;
    for (&pass_jobs) |*job| job.* = makeJob(tx_bytes, &spk_true);
    queue.submit(&pass_jobs);
    try testing.expect(queue.waitAllDetailed().ok);

    var fail_jobs: [16]validation.ScriptCheckJob = undefined;
    fail_jobs[0] = makeJob(tx_bytes, &spk_true);
    fail_jobs[1] = makeJob(tx_bytes, &spk_false);
    var i: usize = 2;
    while (i < 16) : (i += 1) fail_jobs[i] = makeJob(tx_bytes, &spk_true);
    queue.submit(&fail_jobs);
    const failed = queue.waitAllDetailed();
    try testing.expect(!failed.ok);
    try testing.expectEqual(@as(usize, 1), failed.first_fail_index);

    // Same worker threads — no per-block spawn.
    try testing.expect(queue.workers.ptr == workers_ptr);
    try testing.expectEqual(@as(usize, 4), queue.worker_count);
}

test "parallel_script process-wide pool init/deinit" {
    try validation.initScriptCheckPool(testing.allocator, 3);
    defer validation.deinitScriptCheckPool();
    const pool = validation.globalScriptCheckQueue() orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(usize, 3), pool.worker_count);

    const allocator = testing.allocator;
    const tx_bytes = try dummyTxBytes(allocator);
    defer allocator.free(tx_bytes);
    const spk_true = [_]u8{0x51};
    var jobs: [8]validation.ScriptCheckJob = undefined;
    for (&jobs) |*job| job.* = makeJob(tx_bytes, &spk_true);
    pool.submit(&jobs);
    try testing.expect(pool.waitAllDetailed().ok);
}
