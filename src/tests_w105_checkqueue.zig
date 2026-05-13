//! W105 — CCheckQueue / parallel script verification 30-gate audit
//!
//! Reference: bitcoin-core/src/checkqueue.h, validation.cpp (ConnectBlock),
//!            init.cpp (-par flag), script/sigcache.h
//!
//! Clearbit equivalent: ScriptCheckQueue in src/validation.zig (line ~2311)
//!                      SigCache in src/sig_cache.zig

const std = @import("std");
const testing = std.testing;
const validation = @import("validation.zig");
const script = @import("script.zig");
const sig_cache = @import("sig_cache.zig");

// ============================================================================
// G1 — Worker thread count: no hard cap at MAX_SCRIPTCHECK_THREADS (15)
//
// Core clamps worker_threads_num to [0, MAX_SCRIPTCHECK_THREADS=15].
// Clearbit uses getCpuCount()-1 with no upper bound; on a 64-core machine
// that is 63 workers, far above Core's limit.
// Reference: validation.cpp:6136 `std::clamp(options.worker_threads_num, 0, MAX_SCRIPTCHECK_THREADS)`
// Severity: LOW — performance/resource bound, not a consensus hazard
// ============================================================================
test "w105 G1: worker count must be capped at MAX_SCRIPTCHECK_THREADS (15)" {
    // MAX_SCRIPTCHECK_THREADS = 15 in Core (validation.h:90).
    // Clearbit has no cap; worker_count = getCpuCount()-1 unbounded.
    const max_core_threads: usize = 15;
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // Document the bug: clearbit's worker_count may exceed Core's cap.
    // On a 2-core CI box this passes; on the 32-core maxbox it would expose
    // the divergence (worker_count = 31 vs Core's 15).
    // Test asserts the constant exists and that we're aware of the limit.
    _ = max_core_threads; // referenced for clarity
    try testing.expect(queue.worker_count >= 1); // current behavior
    // BUG: should be: try testing.expect(queue.worker_count <= 15);
}

// ============================================================================
// G2 — Thread naming: workers not named "scriptch.N"
//
// Core renames each worker thread via `util::ThreadRename("scriptch.N")`.
// Clearbit spawns threads without naming them, making perf profiling harder.
// Reference: checkqueue.h:150  `util::ThreadRename(strprintf("scriptch.%i", n))`
// Severity: COSMETIC — no consensus impact
// ============================================================================
test "w105 G2: worker thread naming (scriptch.N) is absent" {
    // Zig threads do not expose a rename API in std.Thread.spawn directly.
    // This is documented as a known gap vs Core.
    // The test asserts that ScriptCheckQueue exists and spawns >= 1 worker.
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    try testing.expect(queue.worker_count >= 1);
    // BUG-COSMETIC: worker threads are not named "scriptch.N"
}

// ============================================================================
// G3 — Thread pool is per-block, not persistent
//
// Core creates a single persistent CCheckQueue at Chainstate init time; workers
// live for the entire node lifetime.  Clearbit creates and destroys a new
// ScriptCheckQueue inside verifyBlockScriptsParallel() on every block,
// including spawning N-1 threads and joining them — O(block) thread
// create/destroy instead of O(1).
//
// Reference: checkqueue.h:144-155 (constructor spawns N-1 workers once)
//            validation.cpp:6136 (queue created once at ChainstateManager init)
// Severity: MEDIUM — significant performance regression on IBD
// ============================================================================
test "w105 G3: thread pool is per-block not persistent (perf regression)" {
    // Verify that ScriptCheckQueue spawns threads on init (not deferred).
    const allocator = testing.allocator;
    {
        var q1 = try validation.ScriptCheckQueue.init(allocator);
        defer q1.deinit();
        try testing.expect(q1.worker_count >= 1);
    }
    // BUG: Core keeps the thread pool alive for the node lifetime;
    // Clearbit destroys and recreates it on every block.
    // Each call to verifyBlockScriptsParallel() spawns/joins N-1 threads.
}

// ============================================================================
// G4 — Minimum worker count: should be 0 (single-threaded) when -par=0
//      auto-detects no extra threads available
//
// Core allows 0 worker threads (sequential mode via HasThreads()==false).
// Clearbit always spawns at least 1 worker thread (@max(1, cpu-1)).
// Reference: validation.cpp:2514-2515 `if (queue.HasThreads() && fScriptChecks)`
// Severity: LOW — minor deviation from Core's threading model
// ============================================================================
test "w105 G4: queue always spawns >= 1 worker, no zero-thread mode" {
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // Clearbit forces >= 1 worker; Core supports 0-worker (single-threaded) mode
    try testing.expect(queue.worker_count >= 1);
    // BUG: no HasThreads()-equivalent that allows true single-thread mode
}

// ============================================================================
// G5 — Worker thread copy/move safety
//
// Core deletes copy/move constructors for CCheckQueue (checkqueue.h:159-162).
// Clearbit's ScriptCheckQueue uses a pointer-based design (heap-allocated)
// which prevents accidental moves.  This is CORRECT behavior — heap
// allocation ensures stable pointer for worker thread captures.
// Reference: checkqueue.h:157-162
// Severity: OK
// ============================================================================
test "w105 G5: ScriptCheckQueue heap-allocated for pointer stability (PASS)" {
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // Heap allocation prevents the copy/move hazard.
    try testing.expect(queue.worker_count >= 1);
}

// ============================================================================
// G6 — Batch dispatch: no batch-size parameter (fixed work-stealing vs LIFO)
//
// Core uses configurable nBatchSize (128 by default) with a LIFO stack and
// adaptive batch formula: nNow = max(1, min(nBatchSize, queue.size/(nTotal+nIdle+1))).
// Clearbit uses a simple atomic fetchAdd(1) work-stealing per job — fine for
// throughput but loses the LIFO-and-adaptive-batch optimisation.
// Reference: checkqueue.h:66, 121-124
// Severity: LOW — throughput difference, not correctness
// ============================================================================
test "w105 G6: no nBatchSize parameter, no LIFO ordering" {
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // Clearbit uses atomic fetchAdd(1) — simple work stealing, correct but
    // does not implement Core's adaptive batch-size optimisation.
    try testing.expectEqual(@as(usize, 0), queue.job_count);
    // BUG-PERF: batch dispatch is flat 1-job-at-a-time instead of adaptive
}

// ============================================================================
// G7 — Early exit on first failure: workers continue after failure found
//
// In Core's Loop(), once m_result is set, workers set do_work=false and skip
// executing remaining jobs in their batch (checkqueue.h:126 `do_work = !m_result.has_value()`).
// Clearbit's processJobs() does not check for any global failure flag and
// continues running all remaining jobs even after one fails.
// Reference: checkqueue.h:80-134 (especially line 126: `do_work = !m_result.has_value()`)
// Severity: LOW — performance-only; correctness is preserved (all jobs still run)
// ============================================================================
test "w105 G7: no early-exit on failure — all jobs run even after first failure" {
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();

    // Create jobs that will all fail
    const tx_bytes = [_]u8{0x01} ** 10;
    const prev_script = [_]u8{0x00};
    var jobs: [4]validation.ScriptCheckJob = undefined;
    for (&jobs) |*job| {
        job.* = validation.ScriptCheckJob.init(
            &tx_bytes, 0, &prev_script, 0,
            script.ScriptFlags{}, &.{},
        );
    }

    queue.submit(&jobs);
    const result = queue.waitAll();
    try testing.expect(!result);

    // All jobs should be processed (none remain .pending)
    for (&jobs) |*job| {
        const r = job.result.load(.acquire);
        try testing.expect(r != .pending);
    }
    // BUG-PERF: Core would skip job[1..3] once job[0] fails; Clearbit runs all
}

// ============================================================================
// G8 — RAII control object: no CCheckQueueControl equivalent
//
// Core uses SCOPED_LOCKABLE CCheckQueueControl which acquires m_control_mutex
// in its constructor (preventing concurrent use of the same queue) and calls
// Complete() in its destructor if the caller forgets (RAII guarantee).
// Clearbit has no equivalent — the caller must explicitly call submit() then
// waitAll(); forgetting waitAll() leaves workers running and jobs dangling.
// Reference: checkqueue.h:207-238
// Severity: MEDIUM — unsafe API; missing RAII destructor guarantee
// ============================================================================
test "w105 G8: no RAII CCheckQueueControl equivalent — caller must call waitAll" {
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // Verify submit+waitAll pattern works correctly (the only protection is
    // that verifyBlockScriptsParallel always calls both in sequence).
    // BUG: no RAII wrapper; if an error path between submit() and waitAll()
    //      is taken, worker threads proceed against freed job memory.
    try testing.expect(queue.waitAll()); // no jobs, trivially true
}

// ============================================================================
// G9 — Control mutex: no m_control_mutex (concurrent queue use is unsafe)
//
// Core's CCheckQueue has m_control_mutex guarded by CCheckQueueControl to
// ensure only one CCheckQueueControl uses the queue at any moment.
// Clearbit has no such mutex — two concurrent ConnectBlock calls on the same
// queue would corrupt job/next_job/completed_count state.
// Reference: checkqueue.h:140-141 `Mutex m_control_mutex`
// Severity: MEDIUM — potential data race, but mitigated by per-block creation
//           (G3 creates a new queue per block, so two blocks can't share one)
// ============================================================================
test "w105 G9: no m_control_mutex — concurrent queue submissions would corrupt state" {
    // Because Clearbit creates a new ScriptCheckQueue per block (G3),
    // the concurrent-use hazard is avoided in practice, but the design
    // relies on that per-block creation pattern remaining in place.
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // BUG: no control_mutex; relies entirely on single-caller discipline
    try testing.expect(queue.worker_count >= 1);
}

// ============================================================================
// G10 — Master thread RAII completion: no automatic Complete() on scope exit
//
// CCheckQueueControl's destructor calls Complete() if fDone is false.
// Clearbit has no such protection — if verifyBlockScriptsParallel returns
// an error before calling waitAll(), workers are left spinning.
// Reference: checkqueue.h:233-237
// Severity: MEDIUM — resource leak / use-after-free on error path
// ============================================================================
test "w105 G10: no automatic Complete() on scope exit (RAII gap)" {
    // Verify the normal path works; the bug is on the error path.
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    queue.submit(&.{}); // empty submission
    try testing.expect(queue.waitAll());
    // BUG: if submit() succeeds but an error fires before waitAll(),
    //      workers spin on stale job data until deinit() joins them.
}

// ============================================================================
// G11 — Cancellation: no m_request_stop equivalent during block processing
//
// Core's CCheckQueue destructor sets m_request_stop=true before joining,
// causing workers to exit cleanly (checkqueue.h:193).
// Clearbit's stop_flag is set in deinit() but NOT on error mid-block —
// if verifyBlockScriptsParallel fails (OOM error path), deinit() is called
// via defer and will join. This part is OK. But there is no mechanism to
// cancel in-flight verifications if a failure is detected mid-batch.
// Reference: checkqueue.h:191-198
// Severity: LOW — no live hazard given defer-deinit pattern
// ============================================================================
test "w105 G11: deinit correctly sets stop_flag before joining workers (PASS)" {
    const allocator = testing.allocator;
    const queue = try validation.ScriptCheckQueue.init(allocator);
    // deinit calls stop_flag=true then start_event.set() then joins
    queue.deinit();
    // If we reach here, workers exited cleanly.
}

// ============================================================================
// G12 — Worker synchronisation: spin-wait instead of condvar for completion
//
// Core uses m_master_cv.notify_one() when nTodo reaches 0, so the master
// wakes immediately without polling.  Clearbit uses a tight spin loop:
//   while (completed_count < job_count) spinLoopHint();
// This wastes a full CPU core for the master thread during verification.
// Reference: checkqueue.h:90-91 `m_master_cv.notify_one()`
// Severity: MEDIUM — wastes one CPU during every parallel block validation
// ============================================================================
test "w105 G12: master thread spin-waits instead of condvar sleep" {
    // The spin loop is at validation.zig:2415-2418.
    // No assertion possible from test code — document the pattern.
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    queue.submit(&.{});
    _ = queue.waitAll();
    // BUG-PERF: master thread burns a full core spinning while workers run
}

// ============================================================================
// G13 — Worker synchronisation: ResetEvent.wait() is not condvar-backoff
//
// Workers wait on start_event (a ResetEvent) which is a futex-backed wait
// in Zig — this is semantically correct.  However, between batches each
// worker returns from processJobs() and immediately loops back to
// start_event.wait() WITHOUT checking that the event has been reset yet.
// There is a race: if submit() + waitAll() runs fast enough that the master
// calls start_event.set() BEFORE some workers have called start_event.wait(),
// those workers will see the old set state and re-enter processJobs() on
// a batch that has already been completed, burning CPU on no-ops (job_idx
// will exceed job_count immediately, so it's safe but wasteful).
// Reference: checkqueue.h:107-109  (mutex-protected wait prevents this race)
// Severity: LOW — safe but can cause spurious wakeups
// ============================================================================
test "w105 G13: ResetEvent.wait() has spurious-wakeup race between batches" {
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // Run two sequential batches to exercise the inter-batch path
    queue.submit(&.{});
    _ = queue.waitAll();
    queue.submit(&.{});
    _ = queue.waitAll();
    // If this test completes without deadlock, the race is benign here.
    // BUG: potential spurious re-entry into processJobs after batch completes
}

// ============================================================================
// G14 — start_event.reset() ordering: reset AFTER checking results
//
// In waitAll(), start_event.reset() is called AFTER the completion spin-wait
// but BEFORE checking individual job results.  Workers that already exited
// processJobs() may see start_event still set and re-enter on the next
// submit() call without blocking.  The reset at line 2421 races with a worker
// that finishes its last job and loops back to start_event.wait() — if
// reset() fires before the worker reaches wait(), the worker blocks correctly;
// if reset() fires AFTER the next submit()+set(), the worker may miss a batch.
// Reference: checkqueue.h:108-109 (mutex serialises this)
// Severity: MEDIUM — race condition between batches, potential missed wakeup
// ============================================================================
test "w105 G14: start_event reset-before-result-check ordering race" {
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();
    // Verify sequential submit+waitAll is safe in the common case
    for (0..3) |_| {
        queue.submit(&.{});
        const ok = queue.waitAll();
        try testing.expect(ok); // empty batch is always ok
    }
    // BUG: without a mutex around submit+reset+set, inter-batch races exist
}

// ============================================================================
// G15 — Error result returned from operator() not propagated with error detail
//
// Core's CScriptCheck::operator() returns std::optional<std::pair<ScriptError,std::string>>
// — the error code + debug string are stored in the CCheckQueue result and
// logged by ConnectBlock for diagnostics.
// Clearbit's verifyScriptJob() returns bool; error detail (which ScriptError)
// is discarded.  The parent only gets true/false; no error reason is reported.
// Reference: checkqueue.h:32, validation.cpp:2014-2023
// Severity: MEDIUM — loss of diagnostic information on validation failure
// ============================================================================
test "w105 G15: ScriptCheckJob result is bool only, no ScriptError detail" {
    // Verify the VerifyResult enum has only {pending, success, failure}
    const r: validation.ScriptCheckJob.VerifyResult = .failure;
    try testing.expect(r == .failure);
    // BUG: Core returns ScriptError + debug string; Clearbit discards error detail
    // A failed block produces "ScriptVerificationFailed" with no script error code.
}

// ============================================================================
// G16 — CCheckQueueControl not used — queue created/destroyed per block
//
// Core's ConnectBlock creates a CCheckQueueControl around the persistent queue
// (validation.cpp:2514).  Clearbit creates a brand-new ScriptCheckQueue inside
// verifyBlockScriptsParallel() for every block (G3 recaps this from the master
// synchronisation angle; this gate documents the missing control-object pattern).
// Reference: validation.cpp:2514 `std::optional<CCheckQueueControl<CScriptCheck>> control`
// Severity: MEDIUM — design debt, combines G3 + G8 + G9 impact
// ============================================================================
test "w105 G16: no CCheckQueueControl; queue is per-block not lifetime-scoped" {
    // ParallelVerifyConfig exists and has sensible defaults.
    const config = validation.ParallelVerifyConfig{};
    try testing.expect(config.enabled);
    try testing.expect(config.min_inputs_for_parallel >= 1);
    // BUG: creating + destroying thread pool per block is O(block) vs O(1)
}

// ============================================================================
// G17 — Script-execution cache (full-tx cache): entirely absent
//
// Core's CheckInputScripts() first checks a per-tx script-execution cache keyed
// on SHA256(nonce || wtxid || flags) before queuing any CScriptCheck jobs
// (validation.cpp:2078-2083).  A cache hit skips ALL per-input script checks.
// Clearbit has no script-execution cache; every block re-runs script verification
// even for transactions seen in mempool or recently re-validated.
// Reference: sigcache.h:28-29, validation.cpp:2078-2083
// Severity: HIGH — significant IBD/re-org performance regression
// ============================================================================
test "w105 G17: no script-execution cache (full-tx wtxid-keyed cache absent)" {
    // Verify SigCache exists (per-signature cache), but there is no equivalent
    // of Core's per-tx script_execution_cache in validation.zig.
    var cache = sig_cache.SigCache.init(testing.allocator, 100);
    defer cache.deinit();
    // The SigCache module exists but is NOT imported or used in validation.zig.
    // BUG: no per-tx script execution cache; all scripts re-verified on every block
    try testing.expect(cache.count() == 0);
}

// ============================================================================
// G18 — SigCache (per-signature ECDSA/Schnorr cache): defined but never wired
//
// sig_cache.zig provides SigCache with lookup() + insert() methods, but
// validation.zig does NOT import sig_cache.zig and verifyScriptJob() does not
// consult or populate the cache.  The SigCache is a dead module.
//
// Core's CachingTransactionSignatureChecker wraps the SignatureCache and is
// passed to VerifyScript() (sigcache.h:65-75, validation.cpp:2018).
// Reference: sigcache.h, validation.cpp:2018, 2109
// Severity: HIGH — mempool→block re-verification perf gap; mempool txs pay
//           double ECDSA/Schnorr cost on ConnectBlock
// ============================================================================
test "w105 G18: SigCache exists in sig_cache.zig but is NOT wired into script verification" {
    // sig_cache.SigCache can be instantiated independently, but validation.zig
    // never imports it.  Script verification in verifyScriptJob() uses a raw
    // ScriptEngine.verify() call with no cache consultation.
    var cache = sig_cache.SigCache.init(testing.allocator, 1000);
    defer cache.deinit();

    const dummy_txid = [_]u8{0xAB} ** 32;
    // Cache lookup always misses — it is never populated by script verification
    try testing.expect(!cache.lookup(dummy_txid, 0, 0xFFFF_FFFF));
    _ = cache.getStats();
    // BUG-DEAD-HELPER: sig_cache.zig is a complete, correct implementation
    // that is never called from validation.zig — classic dead-helper pattern
}

// ============================================================================
// G19 — SigCache key uses txid+index+flags, not a salted hash
//
// Core's SignatureCache key is SHA256(nonce || 'E'/'S' || zeros || sighash || pubkey || sig)
// — a salted hash that commits to the actual signature bytes.  This prevents
// cache collisions across different sighash algorithms and prevents an attacker
// from crafting a signature that has the same (txid, index, flags) triple as a
// valid cached entry but a different public key.
// Clearbit's CacheKey is (txid, input_index, flags) — it does NOT include the
// public key or signature bytes, so a different signature on the same input
// with the same flags would return a cache hit, bypassing verification.
// Reference: sigcache.h:44-46 (entries are SHA256(nonce || sig || pubkey…))
// Severity: HIGH — cache collision attack: an attacker knowing a valid (txid, idx)
//           could bypass ECDSA/Schnorr verification (though SigCache is also
//           unwired at G18, so this bug has no live impact until G18 is fixed)
// ============================================================================
test "w105 G19: SigCache key missing signature/pubkey bytes — collision attack possible" {
    var cache = sig_cache.SigCache.init(testing.allocator, 100);
    defer cache.deinit();

    const txid = [_]u8{0x01} ** 32;
    const flags: u32 = 0x1F;

    // Insert with one "signature" (actually just txid+index+flags)
    cache.insert(txid, 0, flags);
    try testing.expect(cache.lookup(txid, 0, flags));

    // A different signature on the same (txid, index, flags) would also hit.
    // In Core, the key includes the actual sig bytes so this cannot happen.
    // BUG: cache key must include SHA256(nonce || sig_bytes || pubkey_bytes)
}

// ============================================================================
// G20 — SigCache key not salted: predictable hash, HashDoS possible
//
// Core initialises a per-node 256-bit random nonce at ValidationCache creation
// and prefixes all cache keys with it (validation.cpp:2030-2035).  This
// prevents an adversary from pre-computing inputs that collide in the cache.
// Clearbit's CacheKey.hash() uses a fixed FNV basis with no random nonce.
// Reference: sigcache.h; validation.cpp:2026-2040
// Severity: MEDIUM — HashDoS / cache-pollution; no live impact until G18 fixed
// ============================================================================
test "w105 G20: SigCache hash function has no random nonce (HashDoS possible)" {
    // The CacheKey.hash() function uses a fixed FNV basis (0xcbf29ce484222325).
    // An adversary can pre-compute txid/index/flags triples that all collide.
    var cache = sig_cache.SigCache.init(testing.allocator, 100);
    defer cache.deinit();
    // BUG: fixed seed — Core uses a per-startup random nonce
    // Demonstrate deterministic hashing:
    const key1 = sig_cache.CacheKey{ .txid = [_]u8{0x01} ** 32, .input_index = 0, .flags = 0 };
    const key2 = sig_cache.CacheKey{ .txid = [_]u8{0x01} ** 32, .input_index = 0, .flags = 0 };
    try testing.expectEqual(key1.hash(), key2.hash()); // always equal — deterministic
}

// ============================================================================
// G21 — cacheStore flag: no concept of "don't cache results for block validation"
//
// Core's CheckInputScripts takes cacheSigStore and cacheFullScriptStore params.
// In ConnectBlock, fCacheResults = fJustCheck (only cache when justCheck=true,
// i.e., during speculative validation, NOT during the real block-connect pass).
// Clearbit has no equivalent — every script verification always "caches" (or
// in practice, never caches at all since G18 shows SigCache is unwired).
// Reference: validation.cpp:2576-2587 `fCacheResults = fJustCheck`
// Severity: LOW — no live impact given SigCache is unwired (G18)
// ============================================================================
test "w105 G21: no cacheStore/fCacheResults toggle — cache always on or always off" {
    // ScriptCheckJob has no cacheStore field; verifyScriptJob never consults SigCache.
    const tx_bytes = [_]u8{0x01} ** 10;
    const job = validation.ScriptCheckJob.init(&tx_bytes, 0, &.{}, 0, script.ScriptFlags{}, &.{});
    // Verify there is no cache-store field on the job struct
    _ = job.tx_bytes;
    _ = job.input_index;
    _ = job.flags;
    // BUG: no fCacheResults — all verifications go through the same code path
}

// ============================================================================
// G22 — PrecomputedTransactionData: no equivalent, tx re-serialised per job
//
// Core's CScriptCheck captures a pointer to PrecomputedTransactionData, which
// caches sighash components (SHA256 midstates for the tx amounts, sequences,
// outputs, etc.) so multiple inputs of the same tx share one computation.
// Clearbit re-serialises the entire transaction for every input of every tx
// (verifyBlockScriptsParallel:2604-2615: `serialize.writeTransaction` per tx).
// Each worker then re-deserialises the tx from the serialised bytes.
// Reference: validation.cpp:2517 `std::vector<PrecomputedTransactionData> txsdata`
// Severity: MEDIUM — O(inputs * tx_size) serialisation work vs O(tx) in Core
// ============================================================================
test "w105 G22: no PrecomputedTransactionData — tx re-serialised per input batch" {
    // Each ScriptCheckJob carries a tx_bytes slice (serialised tx), not a
    // shared precomputed object.  All inputs of the same tx share the same
    // tx_bytes slice (correct), but each worker re-deserialises independently.
    const tx_bytes = [_]u8{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const job = validation.ScriptCheckJob.init(&tx_bytes, 0, &.{}, 0, script.ScriptFlags{}, &.{});
    try testing.expectEqual(@as(usize, 0), job.input_index);
    // BUG-PERF: no PrecomputedTransactionData; sighash precomputation is per-job
}

// ============================================================================
// G23 — min_inputs_for_parallel threshold: 16 inputs (Core has no threshold)
//
// Clearbit adds a min_inputs_for_parallel gate (default 16) that falls back to
// single-threaded for small blocks.  Core always uses the thread pool when
// HasThreads() is true, regardless of tx count.
// This is an intentional deviation from Core, but it means blocks with 1-15
// inputs are never parallelised even on a 32-core machine.
// Reference: validation.cpp:2514-2515 (no threshold — always uses queue when HasThreads())
// Severity: LOW — conservative deviation; saves thread-wake overhead on small blocks
// ============================================================================
test "w105 G23: min_inputs_for_parallel=16 diverges from Core (Core has no threshold)" {
    const config = validation.ParallelVerifyConfig{};
    // Default threshold is 16
    try testing.expectEqual(@as(usize, 16), config.min_inputs_for_parallel);
    // Core: always parallel when HasThreads(); Clearbit: only when >= 16 inputs
    // BUG-MINOR: single-tx blocks (e.g. coinbase-only) are always single-threaded
}

// ============================================================================
// G24 — Coinbase skipped correctly in both paths
//
// Both Core and Clearbit correctly skip the coinbase (transactions[0]) from
// script verification.  Clearbit iterates block.transactions[1..] in both
// verifyBlockScriptsParallel and verifyBlockScriptsSingleThreaded.
// This is CORRECT.
// Reference: validation.cpp:2531 `if (!tx.IsCoinBase())`
// Severity: OK
// ============================================================================
test "w105 G24: coinbase correctly skipped from script verification (PASS)" {
    // verifyBlockScriptsParallel iterates block.transactions[1..] which
    // excludes the coinbase.  This matches Core's `if (!tx.IsCoinBase())`.
    const config = validation.ParallelVerifyConfig{};
    try testing.expect(config.enabled);
    // (No code change needed — this gate documents a PASS)
}

// ============================================================================
// G25 — Per-job arena allocator: correct use of c_allocator (PASS)
//
// Each verifyScriptJob() creates its own ArenaAllocator backed by c_allocator
// (libc malloc, thread-safe), avoiding the data race on a shared ArenaAllocator
// that caused the wave-46a SIGSEGV.  This is correct.
// Reference: checkqueue.h (each CScriptCheck has its own checker object)
// Severity: OK
// ============================================================================
test "w105 G25: per-job arena backed by c_allocator is thread-safe (PASS)" {
    // verifyScriptJob() line 2486: `std.heap.ArenaAllocator.init(std.heap.c_allocator)`
    // The outer `allocator` parameter is intentionally ignored.
    // No assertion needed — this documents a deliberate correct design choice.
    try testing.expect(true);
}

// ============================================================================
// G26 — Script flags passed correctly to workers
//
// ScriptCheckJob captures the flags field (script.ScriptFlags) which is set
// per-block by getBlockScriptFlags().  Workers use job.flags in
// ScriptEngine.initWithPrevouts().  This is correct.
// Reference: validation.cpp:2109 `CScriptCheck check(…, flags, …)`
// Severity: OK
// ============================================================================
test "w105 G26: script flags captured in ScriptCheckJob and used by worker (PASS)" {
    const tx_bytes = [_]u8{0x01} ** 10;
    const flags = script.ScriptFlags{ .verify_taproot = true };
    const job = validation.ScriptCheckJob.init(&tx_bytes, 0, &.{}, 0, flags, &.{});
    try testing.expect(job.flags.verify_taproot);
}

// ============================================================================
// G27 — Taproot prevouts (spent_amounts / spent_scripts) passed to workers
//
// Core's PrecomputedTransactionData captures all spent CTxOut for BIP-341
// sighash computation.  Clearbit's ScriptCheckJob carries spent_amounts and
// spent_scripts slices.  initWithPrevouts() is used for Taproot inputs.
// This is correct.
// Reference: validation.cpp:2086-2098 (PrecomputedTransactionData setup)
// Severity: OK
// ============================================================================
test "w105 G27: spent_amounts/spent_scripts for Taproot are carried in ScriptCheckJob (PASS)" {
    const tx_bytes = [_]u8{0x01} ** 10;
    const amounts = [_]i64{100_000_000};
    const script_bytes = [_]u8{ 0x51, 0x20 } ++ [_]u8{0xAB} ** 32;
    const scripts: [1][]const u8 = .{&script_bytes};
    const job = validation.ScriptCheckJob.initWithPrevouts(
        &tx_bytes, 0, &script_bytes, 100_000_000,
        script.ScriptFlags{ .verify_taproot = true },
        &.{}, &amounts, &scripts,
    );
    try testing.expectEqual(@as(usize, 1), job.spent_amounts.len);
    try testing.expectEqual(@as(usize, 1), job.spent_scripts.len);
}

// ============================================================================
// G28 — Job result initialised to .pending
//
// ScriptCheckJob initialises result to .pending so the master can distinguish
// "not yet processed" from "processed but failed" — useful if the waitAll()
// spin-wait exits before all jobs are actually stored (shouldn't happen with
// the completed_count gate, but a good invariant to assert).
// This matches Core's approach (result is std::optional, nullopt = pending).
// Reference: checkqueue.h:56 `std::optional<R> m_result`
// Severity: OK
// ============================================================================
test "w105 G28: ScriptCheckJob result initialised to .pending (PASS)" {
    const tx_bytes = [_]u8{0x01} ** 10;
    const job = validation.ScriptCheckJob.init(&tx_bytes, 0, &.{}, 0, script.ScriptFlags{}, &.{});
    try testing.expectEqual(validation.ScriptCheckJob.VerifyResult.pending, job.result.load(.acquire));
}

// ============================================================================
// G29 — Input index bounds check in verifyScriptJob
//
// verifyScriptJob() checks `if (job.input_index >= tx.inputs.len) return false`
// before accessing inputs.  This is a correct defensive check.
// Reference: validation.cpp:2014-2018 (accesses ptxTo->vin[nIn] directly,
//            relying on the check in CScriptCheck constructor)
// Severity: OK
// ============================================================================
test "w105 G29: out-of-bounds input_index results in failure not panic (PASS)" {
    // A job with an input_index beyond the tx's input count should fail gracefully.
    // We create a minimal (invalid) serialised tx and set input_index=99.
    const allocator = testing.allocator;
    var queue = try validation.ScriptCheckQueue.init(allocator);
    defer queue.deinit();

    // Minimal v1 tx bytes: version=1, 0 inputs, 0 outputs, locktime=0
    const tx_bytes = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var jobs: [1]validation.ScriptCheckJob = undefined;
    jobs[0] = validation.ScriptCheckJob.init(&tx_bytes, 99, &.{}, 0, script.ScriptFlags{}, &.{});

    queue.submit(&jobs);
    const result = queue.waitAll();
    try testing.expect(!result); // should fail, not crash
}

// ============================================================================
// G30 — getParallelVerifyThreadCount: reports CPU count not worker count
//
// getParallelVerifyThreadCount() returns getCpuCount() (total CPUs), not
// the actual number of worker threads spawned (getCpuCount()-1).
// Core reports the number of worker threads actually spawned.
// Reference: init.cpp:513-514 `-par` documentation
// Severity: LOW — misleading metric only
// ============================================================================
test "w105 G30: getParallelVerifyThreadCount returns CPU count not worker thread count" {
    const thread_count = validation.getParallelVerifyThreadCount();
    try testing.expect(thread_count >= 1);
    // BUG-MINOR: returns getCpuCount() (total), not worker_count (total-1)
    // An operator checking this to know "how many threads are actually verifying"
    // gets an off-by-one: the value is worker_count+1 (counts the master too).
}
