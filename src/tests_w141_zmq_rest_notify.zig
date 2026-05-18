//! W141 — ZMQ + REST + notification-scripts 30-gate fleet audit — clearbit.
//!
//! References
//! ----------
//! bitcoin-core/src/zmq/zmqpublishnotifier.cpp:
//!   - SendZmqMessage (line 193)
//!   - NotifyBlock (line 210)            -- hashblock topic
//!   - NotifyTransaction (line 221)      -- hashtx topic
//!   - NotifyBlockDisconnect (line 274)  -- sequence label 'D'
//!   - NotifyTransactionRemoval (line 288) -- sequence label 'R'
//!   - NotifyTransactionAcceptance (line 281) -- sequence label 'A' + mempool_seq
//!   - IsZMQAddressIPV6 (line 82-93)
//!   - Initialize Linger set in Shutdown only (line 185-186)
//! bitcoin-core/src/zmq/zmqnotificationinterface.cpp:
//!   - unix:// -> ipc:// rewrite (line 62-64)
//!   - per-topic hwm knob (line 69)
//!   - UpdatedBlockTip IBD short-circuit (line 151-154)
//!   - BlockConnected per-tx Notify (line 180-196)
//!   - BlockDisconnected per-tx Notify (line 198-211)
//! bitcoin-core/src/zmq/zmqabstractnotifier.h:
//!   - DEFAULT_ZMQ_SNDHWM = 1000 (line 22)
//! bitcoin-core/src/rest.cpp:
//!   - CheckWarmup (line 171-177)
//!   - ParseDataFormat rfind('?') (line 129-152)
//!   - MAX_REST_HEADERS_RESULTS = 2000 (line 45)
//!   - MAX_GETUTXOS_OUTPOINTS = 15 (line 44)
//!   - dispatch table (line 1141-1159) — 14 prefixes including
//!     /rest/deploymentinfo, /rest/spenttxouts/, /rest/blockpart/
//!   - /rest/headers/<hash>?count=N new path (line 195-202)
//! bitcoin-core/src/init.cpp:
//!   - -blocknotify @ 2008-2018 (POST_INIT-only, ReplaceAll %s with hex hash)
//!   - -shutdownnotify @ 255-265
//!   - -startupnotify @ 737-745
//! bitcoin-core/src/node/kernel_notifications.cpp:
//!   - AlertNotify @ 30-47 (SanitizeString + single-quote wrap + ReplaceAll %s)
//! bitcoin-core/src/wallet/init.cpp:75 + wallet.cpp:1480:
//!   - -walletnotify with %s %w %b %h
//! bitcoin-core/src/common/system.cpp:
//!   - runCommand @ 50-61 (::system call)
//!   - ShellEscape @ 41-46 (single-quote wrap with '\"'\"' escape)
//!
//! Mode
//! ----
//! DISCOVERY (XFAIL-style). Each test asserts the CURRENT (often buggy)
//! state — when a fix wave lands, the test must be flipped (intentionally).
//! Audit BUG numbers map 1:1 to gate names (G1..G30) and to BUG-1..BUG-30
//! in `audit/w141_zmq_rest_notify.md`.
//!
//! Run: `zig build test-w141`.

const std = @import("std");
const testing = std.testing;

const main_mod = @import("main.zig");
const zmq = @import("zmq.zig");

// ============================================================================
// Helpers — source-level guards
// ============================================================================

/// Read zmq.zig once for source-level guards.  Many tests use this.
fn readZmqSrc(alloc: std.mem.Allocator) ![]const u8 {
    var dir = try std.fs.cwd().openDir("src", .{});
    defer dir.close();
    return try dir.readFileAlloc(alloc, "zmq.zig", 1 * 1024 * 1024);
}

/// Read rpc.zig for REST-side guards.
fn readRpcSrc(alloc: std.mem.Allocator) ![]const u8 {
    var dir = try std.fs.cwd().openDir("src", .{});
    defer dir.close();
    return try dir.readFileAlloc(alloc, "rpc.zig", 6 * 1024 * 1024);
}

/// Read main.zig for notify-script guards.
fn readMainSrc(alloc: std.mem.Allocator) ![]const u8 {
    var dir = try std.fs.cwd().openDir("src", .{});
    defer dir.close();
    return try dir.readFileAlloc(alloc, "main.zig", 4 * 1024 * 1024);
}

/// Read sync.zig for IBD-gate guard.
fn readSyncSrc(alloc: std.mem.Allocator) ![]const u8 {
    var dir = try std.fs.cwd().openDir("src", .{});
    defer dir.close();
    return try dir.readFileAlloc(alloc, "sync.zig", 2 * 1024 * 1024);
}

// ============================================================================
// G1..G5 — ZMQ sequence-frame coverage + disconnect/removal hooks
// ============================================================================

// G1 BUG-1: missing 'D' block-disconnect sequence-frame label.
// Core's CZMQPublishSequenceNotifier::NotifyBlockDisconnect sends label 'D'
// (zmqpublishnotifier.cpp:274-279).  clearbit's zmq.zig defines no
// publishBlockDisconnect helper, and the only label written in
// publishBlock is 'C' (line 246).  No 'D' is emitted anywhere.
test "w141/G1: no 'D' block-disconnect publisher exists (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    // No literal "'D'" or `seqbuf[..] = 'D'` write anywhere in zmq.zig.
    // Use a deliberately-unique source-level string so this test isn't
    // tripped by an unrelated comment.
    const has_d_write = std.mem.indexOf(u8, src, "= 'D'") != null;
    try testing.expect(!has_d_write);

    // No helper named publishBlockDisconnect / NotifyBlockDisconnect.
    try testing.expect(!@hasDecl(zmq.Notifier, "publishBlockDisconnect"));
    try testing.expect(!@hasDecl(zmq.Notifier, "notifyBlockDisconnect"));
}

// G2 BUG-2: missing 'R' mempool-removal sequence-frame label.
// Core's CZMQPublishSequenceNotifier::NotifyTransactionRemoval sends 'R'
// (zmqpublishnotifier.cpp:288-293) on every non-block-inclusion removal
// (RBF, expiry, mempool-min-fee bumping).  clearbit publishes only 'A'.
test "w141/G2: no 'R' mempool-removal publisher exists (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    const has_r_write = std.mem.indexOf(u8, src, "= 'R'") != null;
    try testing.expect(!has_r_write);

    try testing.expect(!@hasDecl(zmq.Notifier, "publishTxRemoval"));
    try testing.expect(!@hasDecl(zmq.Notifier, "notifyTransactionRemoval"));
}

// G3 BUG-3: IBD not gated for block-connect publish.
// Core's UpdatedBlockTip returns immediately when fInitialDownload is true
// (zmqnotificationinterface.cpp:153-154).  clearbit fires zmq.global.publishBlock
// inside sync.zig:1861-1868 unconditionally — no isInitialBlockDownload check.
test "w141/G3: ZMQ block-connect publish has no IBD guard (xfail)" {
    const alloc = testing.allocator;
    const src = try readSyncSrc(alloc);
    defer alloc.free(src);

    // Locate the ZMQ-publish region — between `if (zmq.global.initialized)` and
    // the matching closing brace.  Check that NO IBD-related identifier
    // appears in or directly before that region.
    const zmq_region_start = std.mem.indexOf(u8, src, "if (zmq.global.initialized)").?;
    // Inspect the 1KB-window before the region: this is the block-connect
    // path that should have gated on IBD.
    const window_start: usize = if (zmq_region_start > 1024) zmq_region_start - 1024 else 0;
    const window = src[window_start..zmq_region_start];

    const has_ibd = std.mem.indexOf(u8, window, "initial_block_download") != null or
        std.mem.indexOf(u8, window, "isInitialBlockDownload") != null or
        std.mem.indexOf(u8, window, "is_initial_download") != null or
        std.mem.indexOf(u8, window, "InitialBlockDownload") != null;
    try testing.expect(!has_ibd);
}

// G4 BUG-4: per-block-tx fan-out on BlockConnected missing.
// Core's BlockConnected iterates pblock->vtx and fires NotifyTransaction
// per tx BEFORE calling NotifyBlockConnect (zmqnotificationinterface.cpp:185-195).
// clearbit's sync.zig zmq-publish path calls only zmq.global.publishBlock —
// no per-tx loop.  This means coinbase + every tx that arrived in the block
// without first appearing in the mempool will not generate hashtx/rawtx events.
test "w141/G4: no per-block-tx hashtx/rawtx fan-out on connect (xfail)" {
    const alloc = testing.allocator;
    const src = try readSyncSrc(alloc);
    defer alloc.free(src);

    // The ZMQ region must NOT contain a publishTx loop over block.transactions.
    const zmq_region_idx = std.mem.indexOf(u8, src, "Phase 4: ZMQ publish").?;
    // Look ahead 600 bytes (the entire ZMQ block) for a publishTx invocation.
    const end_idx = @min(zmq_region_idx + 600, src.len);
    const window = src[zmq_region_idx..end_idx];

    const has_per_tx = std.mem.indexOf(u8, window, "publishTx") != null;
    try testing.expect(!has_per_tx);
}

// G5 BUG-5: no disconnect hook exists at all.
// Even setting aside the missing 'D' sequence label (G1), the reorg /
// disconnect code path in sync.zig (or wherever a block is disconnected)
// does not call into zmq.global at all.  Symmetric to G4 for the
// disconnect direction.
test "w141/G5: no zmq.global call from disconnect path (xfail)" {
    const alloc = testing.allocator;
    const src = try readSyncSrc(alloc);
    defer alloc.free(src);

    // Look for any disconnect-related function that contains a zmq.global.
    // Simple proxy: does the substring "disconnectTip" or "disconnectBlock"
    // appear within 2KB of a zmq.global reference?
    var search_idx: usize = 0;
    var found_paired = false;
    while (std.mem.indexOfPos(u8, src, search_idx, "disconnect")) |idx| {
        const window_end = @min(idx + 2048, src.len);
        const window = src[idx..window_end];
        if (std.mem.indexOf(u8, window, "zmq.global") != null) {
            found_paired = true;
            break;
        }
        search_idx = idx + 1;
    }
    try testing.expect(!found_paired);
}

// ============================================================================
// G6..G10 — ZMQ socket-option + bind hygiene
// ============================================================================

// G6 BUG-6: ZMQ_IPV6 set unconditionally.
// Core probes IsZMQAddressIPV6 (zmqpublishnotifier.cpp:82-93) and sets
// ZMQ_IPV6 = 1 only when the address resolves to IPv6.  clearbit sets it
// always (zmq.zig:147-148).
test "w141/G6: ZMQ_IPV6 set unconditionally to 1 (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    // The code is `const ipv6: c_int = 1;` — strict literal.
    const has_const_one = std.mem.indexOf(u8, src, "const ipv6: c_int = 1;") != null;
    try testing.expect(has_const_one);

    // And no IsZMQAddressIPV6 / isIPv6Address probe before it.
    const has_probe = std.mem.indexOf(u8, src, "IsZMQAddressIPV6") != null or
        std.mem.indexOf(u8, src, "isIPv6Address") != null or
        std.mem.indexOf(u8, src, "isAddressIPv6") != null;
    try testing.expect(!has_probe);
}

// G7 BUG-7: ZMQ_LINGER set during bind, not during Shutdown.
// Core sets linger=0 only inside Shutdown (zmqpublishnotifier.cpp:185-186)
// after removing the notifier from the multimap.  clearbit sets it in
// bindSocket (zmq.zig:153-154).
test "w141/G7: ZMQ_LINGER set at bind time (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    // Locate bindSocket body.
    const bind_idx = std.mem.indexOf(u8, src, "fn bindSocket(").?;
    const bind_end = bind_idx + std.mem.indexOf(u8, src[bind_idx..], "\n    }\n").?;
    const body = src[bind_idx..bind_end];

    // bindSocket should NOT set ZMQ_LINGER.
    const has_linger_in_bind = std.mem.indexOf(u8, body, "ZMQ_LINGER") != null;
    try testing.expect(has_linger_in_bind); // <-- bug present

    // And deinit (Shutdown analogue) does NOT set linger before close.
    const deinit_idx = std.mem.indexOf(u8, src, "pub fn deinit(").?;
    const deinit_end = deinit_idx + std.mem.indexOf(u8, src[deinit_idx..], "\n    }\n").?;
    const deinit_body = src[deinit_idx..deinit_end];
    const has_linger_in_deinit = std.mem.indexOf(u8, deinit_body, "ZMQ_LINGER") != null;
    try testing.expect(!has_linger_in_deinit);
}

// G8 BUG-8: per-topic `hwm` knob missing.
// Core supports `-zmqpubhashblockhwm=<N>` etc. (zmqnotificationinterface.cpp:69).
// clearbit hardcodes hwm=1000 in zmq.zig:145.  Config has no zmq_*_hwm fields.
test "w141/G8: no per-topic hwm knob on Config (xfail)" {
    try testing.expect(!@hasField(main_mod.Config, "zmq_rawblock_hwm"));
    try testing.expect(!@hasField(main_mod.Config, "zmq_hashblock_hwm"));
    try testing.expect(!@hasField(main_mod.Config, "zmq_rawtx_hwm"));
    try testing.expect(!@hasField(main_mod.Config, "zmq_hashtx_hwm"));
    try testing.expect(!@hasField(main_mod.Config, "zmq_sequence_hwm"));
}

// G9 BUG-9: unix:// → ipc:// prefix rewrite missing.
// Core rewrites unix:// to ipc:// (zmqnotificationinterface.cpp:62-64) so
// operators can use the friendlier prefix.  clearbit passes the addr
// through to zmq_bind() verbatim.
test "w141/G9: no unix:// -> ipc:// rewrite (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    const has_unix_rewrite = std.mem.indexOf(u8, src, "unix://") != null or
        std.mem.indexOf(u8, src, "ADDR_PREFIX_UNIX") != null;
    try testing.expect(!has_unix_rewrite);
}

// G10 BUG-10: shared-socket multimap missing.
// Core's mapPublishNotifiers (zmqpublishnotifier.cpp:31 + 100-159) lets two
// notifiers bind the SAME address with shared socket reuse.  clearbit
// always allocates a new socket per topic per address — no map.
test "w141/G10: no shared-socket address-reuse (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    // No multimap-like structure for address sharing.
    const has_addr_map = std.mem.indexOf(u8, src, "mapPublishNotifiers") != null or
        std.mem.indexOf(u8, src, "address_map") != null or
        std.mem.indexOf(u8, src, "addressNotifierMap") != null or
        std.mem.indexOf(u8, src, "sharedSockets") != null;
    try testing.expect(!has_addr_map);

    // Note: actual operator-visible failure (EADDRINUSE on the second bind)
    // is dynamic — verified at runtime, not at compile time.  The static
    // guard here pins the absence of any address-reuse data structure.
}

// ============================================================================
// G11..G15 — ZMQ config + I/O hygiene
// ============================================================================

// G11 BUG-11: single-value --zmqpub<topic> vs Core's vector<string>.
// Core's gArgs.GetArgs("-zmqpubhashblock") returns a vector so operators
// can pass two `-zmqpubhashblock=tcp://X` flags.  clearbit's Config has
// `zmq_hashblock: ?[]const u8` (a single value).
test "w141/G11: Config.zmq_hashblock is single ?[]const u8 (xfail)" {
    // Field type is ?[]const u8, not [][]const u8 or ArrayList.
    const f_type = @TypeOf(@as(main_mod.Config, undefined).zmq_hashblock);
    try testing.expect(f_type == ?[]const u8);

    const r_type = @TypeOf(@as(main_mod.Config, undefined).zmq_rawblock);
    try testing.expect(r_type == ?[]const u8);
}

// G12 BUG-12: sequence frame 'A' always emits 8-byte mempool_seq=0.
// Core's SendSequenceMsg makes the mempool_sequence optional and emits
// 33 vs 41 bytes accordingly (zmqpublishnotifier.cpp:256-265).  clearbit
// always sends 41 bytes with `mempool_seq=0` — the comment at
// zmq.zig:271-275 is the canonical "test-comment-as-confession" shape.
test "w141/G12: 'A' frame fixed-41 + mempool_seq=0 (test-comment-as-confession) (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    // The hardcoded zero write is present.
    const has_zero_seq = std.mem.indexOf(u8, src, "writeInt(u64, seqbuf[33..41], 0,") != null;
    try testing.expect(has_zero_seq);

    // The confession comment is present.
    const has_confession = std.mem.indexOf(u8, src, "We don't track it") != null or
        std.mem.indexOf(u8, src, "emit zero for compatibility") != null;
    try testing.expect(has_confession);

    // No optional/null sentinel for mempool_seq — confirms always-emit.
    const has_optional_seq = std.mem.indexOf(u8, src, "mempool_seq: ?u64") != null or
        std.mem.indexOf(u8, src, "mempool_sequence: ?u64") != null;
    try testing.expect(!has_optional_seq);
}

// G13 BUG-13: multipart zmq_send return ignored.
// Core's zmq_send_multipart (zmqpublishnotifier.cpp:40-79) checks each rc
// and bails on -1.  clearbit's sendMultipart discards all three rc values
// with `_ = c_api.zmq_send(...)`.
test "w141/G13: multipart zmq_send return values discarded (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    const send_multipart_idx = std.mem.indexOf(u8, src, "fn sendMultipart(").?;
    const region_end = send_multipart_idx +
        std.mem.indexOf(u8, src[send_multipart_idx..], "\n    }\n").?;
    const region = src[send_multipart_idx..region_end];

    // Each zmq_send call is `_ = c_api.zmq_send(...)`.  Count discards.
    var discard_count: usize = 0;
    var search_idx: usize = 0;
    while (std.mem.indexOfPos(u8, region, search_idx, "_ = c_api.zmq_send(")) |idx| {
        discard_count += 1;
        search_idx = idx + 1;
    }
    try testing.expect(discard_count >= 3); // three frames, all discarded
}

// G14 BUG-14: zmq_setsockopt return values ignored.
// Same shape as G13 but for setsockopt.  Core checks each call
// (zmqpublishnotifier.cpp:113-136) and closes the socket on -1.
test "w141/G14: zmq_setsockopt return values discarded (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    const bind_idx = std.mem.indexOf(u8, src, "fn bindSocket(").?;
    const region_end = bind_idx + std.mem.indexOf(u8, src[bind_idx..], "\n    }\n").?;
    const region = src[bind_idx..region_end];

    var discard_count: usize = 0;
    var search_idx: usize = 0;
    while (std.mem.indexOfPos(u8, region, search_idx, "_ = c_api.zmq_setsockopt(")) |idx| {
        discard_count += 1;
        search_idx = idx + 1;
    }
    try testing.expect(discard_count >= 4); // SNDHWM, IPV6, TCP_KEEPALIVE, LINGER
}

// G15 BUG-15: socket-leak / addr_z leak on `sockets.append` failure.
// `bindSocket` does `errdefer _ = c_api.zmq_close(sock)` BEFORE the
// `try self.sockets.append(...)`, so an OOM on append closes the socket
// via errdefer but does NOT free `addr_z`.  Cosmetic but documented.
test "w141/G15: addr_z is not errdefer-freed before sockets.append (xfail)" {
    const alloc = testing.allocator;
    const src = try readZmqSrc(alloc);
    defer alloc.free(src);

    const bind_idx = std.mem.indexOf(u8, src, "fn bindSocket(").?;
    const region_end = bind_idx + std.mem.indexOf(u8, src[bind_idx..], "\n    }\n").?;
    const region = src[bind_idx..region_end];

    // There must be an `errdefer ... addr_z` for the leak to be plugged.
    const has_addr_z_errdefer = std.mem.indexOf(u8, region, "errdefer self.allocator.free(addr_z)") != null;
    try testing.expect(!has_addr_z_errdefer);
}

// ============================================================================
// G16..G24 — REST endpoint coverage + behavior
// ============================================================================

// G16 BUG-16: CheckWarmup short-circuit missing.
// Core's REST handlers all begin with `if (!CheckWarmup(req)) return false;`
// which returns HTTP 503 (rest.cpp:171-177).  clearbit's handlers start
// executing immediately.
test "w141/G16: REST handlers lack CheckWarmup short-circuit (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    const has_warmup = std.mem.indexOf(u8, src, "CheckWarmup") != null or
        std.mem.indexOf(u8, src, "checkWarmup") != null or
        std.mem.indexOf(u8, src, "isInWarmup") != null or
        std.mem.indexOf(u8, src, "RPCIsInWarmup") != null;
    try testing.expect(!has_warmup);
}

// G17 BUG-17: /rest/deploymentinfo MISSING.
// Core ships this since v24 (rest.cpp:743-781; dispatch entry 1155-1156).
test "w141/G17: handleRestRequest has no deploymentinfo branch (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    // Find handleRestRequest body.
    const fn_idx = std.mem.indexOf(u8, src, "fn handleRestRequest(").?;
    const fn_end = fn_idx + std.mem.indexOf(u8, src[fn_idx..], "\n    }\n").?;
    const body = src[fn_idx..fn_end];

    const has_deploymentinfo = std.mem.indexOf(u8, body, "deploymentinfo") != null;
    try testing.expect(!has_deploymentinfo);
}

// G18 BUG-18: /rest/spenttxouts/<hash> MISSING.
// Core (rest.cpp:313-381) returns per-block undo so SPV-clients can
// replay reverse-block application without a full archival node.
test "w141/G18: handleRestRequest has no spenttxouts branch (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    const fn_idx = std.mem.indexOf(u8, src, "fn handleRestRequest(").?;
    const fn_end = fn_idx + std.mem.indexOf(u8, src[fn_idx..], "\n    }\n").?;
    const body = src[fn_idx..fn_end];

    const has_spenttxouts = std.mem.indexOf(u8, body, "spenttxouts") != null;
    try testing.expect(!has_spenttxouts);
}

// G19 BUG-19: /rest/blockpart/ MISSING.
// Core (rest.cpp:481-499; dispatch entry 1148) serves a range-slice of a
// block — useful for SPV / tail pruning.
test "w141/G19: handleRestRequest has no blockpart branch (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    const fn_idx = std.mem.indexOf(u8, src, "fn handleRestRequest(").?;
    const fn_end = fn_idx + std.mem.indexOf(u8, src[fn_idx..], "\n    }\n").?;
    const body = src[fn_idx..fn_end];

    const has_blockpart = std.mem.indexOf(u8, body, "blockpart") != null;
    try testing.expect(!has_blockpart);
}

// G20 BUG-20: /rest/headers/<hash>?count=N (new path) MISSING.
// Core accepts BOTH legacy (/rest/headers/<count>/<hash>) AND the new
// query-param form (rest.cpp:191-202).  clearbit only handles legacy.
test "w141/G20: REST headers handler only supports legacy <count>/<hash> path (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    // The new path uses ?count=N — clearbit's handler should call
    // something like GetQueryParameter("count") or parse the ?count= form.
    // Locate restHeaders() body.
    const fn_idx = std.mem.indexOf(u8, src, "fn restHeaders(").?;
    // Headers fn body — limit to first 4096 bytes to bound the scan.
    const fn_end = @min(fn_idx + 4096, src.len);
    const body = src[fn_idx..fn_end];

    const has_query_count = std.mem.indexOf(u8, body, "GetQueryParameter") != null or
        std.mem.indexOf(u8, body, "?count=") != null or
        std.mem.indexOf(u8, body, "parseQueryParam") != null;
    try testing.expect(!has_query_count);
}

// G21 BUG-21: restBlockFilterHeaders walks chain from genesis on every call.
// clearbit recomputes filter bytes for blocks 0..start_entry.height per
// request (rpc.zig:2750-2770).  Core uses a persistent BlockFilterIndex
// lookup (rest.cpp:573-585).
test "w141/G21: restBlockFilterHeaders pre-loop computes filters from genesis (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    // The signature comment claims "O(start_entry.height) per call".
    const has_genesis_walk = std.mem.indexOf(u8, src, "Walk from genesis up to start_entry") != null;
    try testing.expect(has_genesis_walk);

    // And there is no LookupFilterHeader-style index probe before the walk.
    // The fast path goes via computeBasicFilterBytes, which already checks
    // getPersistedFilter, but the recursive chained hash starts at zero —
    // confirming the audit finding.
    const has_prev_header_lookup = std.mem.indexOf(u8, src, "getPersistedFilterHeader") != null or
        std.mem.indexOf(u8, src, "LookupFilterHeader") != null;
    try testing.expect(!has_prev_header_lookup);
}

// G22 BUG-22: restBlock JSON-vs-error discrimination by substring.
// rpc.zig:2044 has `std.mem.indexOf(u8, result, "\"error\":null") == null`.
// In source bytes this appears as the 16-char literal: \"error\":null
// (backslash-escaped double-quote on each side).
test "w141/G22: restBlock uses substring \\\"error\\\":null for status (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    const fn_idx = std.mem.indexOf(u8, src, "fn restBlock(").?;
    const fn_end = @min(fn_idx + 8192, src.len);
    const body = src[fn_idx..fn_end];

    // Source literal: \"error\":null
    const escaped_literal = "\\\"error\\\":null";
    const has_substr = std.mem.indexOf(u8, body, escaped_literal) != null;
    try testing.expect(has_substr);
}

// G23 BUG-23: restTx same substring-status discrimination.
test "w141/G23: restTx uses substring \\\"error\\\":null for status (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    const fn_idx = std.mem.indexOf(u8, src, "fn restTx(").?;
    const fn_end = @min(fn_idx + 4096, src.len);
    const body = src[fn_idx..fn_end];

    const escaped_literal = "\\\"error\\\":null";
    const has_substr = std.mem.indexOf(u8, body, escaped_literal) != null;
    try testing.expect(has_substr);
}

// G24 BUG-24: dispatch lacks no-trailing-slash forgiveness.
// Core's table at rest.cpp:1141-1159 lists both
// "/rest/deploymentinfo/" AND "/rest/deploymentinfo" — both prefixes
// route to the same handler.  clearbit's prefix matching is single-form
// for every prefix it dispatches on.  This is a forward-regression
// guard: when /rest/deploymentinfo lands (G17 fix), the handler must
// accept BOTH the bare prefix and the trailing-slash form.
//
// Static probe: there is no `startsWith(rest_path, "chaininfo/")`
// branch anywhere in handleRestRequest (the only "chaininfo" branch is
// the no-slash form at rpc.zig:1849).  Same shape for every other
// non-slash prefix.  We assert the absence of the trailing-slash
// branch for chaininfo.
test "w141/G24: no dual-prefix forgiveness for chaininfo/ (xfail)" {
    const alloc = testing.allocator;
    const src = try readRpcSrc(alloc);
    defer alloc.free(src);

    const fn_idx = std.mem.indexOf(u8, src, "fn handleRestRequest(").?;
    const fn_end = @min(fn_idx + 32768, src.len);
    const body = src[fn_idx..fn_end];

    // A dual-prefix dispatch would have a `"chaininfo/"` literal in the
    // handler body too (in addition to the bare `"chaininfo"`).  Probe:
    // does the trailing-slash form appear anywhere as a startsWith arg?
    const has_slash_form = std.mem.indexOf(u8, body, "\"chaininfo/\"") != null;
    try testing.expect(!has_slash_form);
}

// ============================================================================
// G25..G30 — Notification-script hooks (all MISSING)
// ============================================================================

// G25 BUG-25: -blocknotify MISSING.
// Already flagged at W124 G11.  Re-asserted here within the W141 audit.
test "w141/G25: no blocknotify field on Config (xfail)" {
    try testing.expect(!@hasField(main_mod.Config, "blocknotify"));
    try testing.expect(!@hasField(main_mod.Config, "block_notify"));
}

// G26 BUG-26: -alertnotify MISSING.
// Already flagged at W124 G12.
test "w141/G26: no alertnotify field on Config (xfail)" {
    try testing.expect(!@hasField(main_mod.Config, "alertnotify"));
    try testing.expect(!@hasField(main_mod.Config, "alert_notify"));
}

// G27 BUG-27: -shutdownnotify MISSING.
// Already flagged at W124 G13.
test "w141/G27: no shutdownnotify field on Config (xfail)" {
    try testing.expect(!@hasField(main_mod.Config, "shutdownnotify"));
    try testing.expect(!@hasField(main_mod.Config, "shutdown_notify"));
}

// G28 BUG-28: -startupnotify MISSING.
// Not tracked by W124.  Core's StartupNotify (init.cpp:737-745) runs
// after AppInitServers — equivalent to clearbit's post-bind / post-RPC-listen
// transition in main.zig.
test "w141/G28: no startupnotify field on Config (xfail)" {
    try testing.expect(!@hasField(main_mod.Config, "startupnotify"));
    try testing.expect(!@hasField(main_mod.Config, "startup_notify"));
}

// G29 BUG-29: -walletnotify MISSING.
// Core's wallet/init.cpp:75 + wallet.cpp:1480 implements %s/%w/%b/%h
// expansion.  clearbit's wallet.zig has no equivalent.
test "w141/G29: no walletnotify field on Config (xfail)" {
    try testing.expect(!@hasField(main_mod.Config, "walletnotify"));
    try testing.expect(!@hasField(main_mod.Config, "wallet_notify"));
}

// G30 BUG-30: ShellEscape / SanitizeString helper MISSING.
// Forward-regression guard: when notify scripts ARE eventually wired,
// the natural Zig idiom is `std.mem.replace` of "%s" with the hash hex —
// but that path is a command-injection sink unless the caller
// sanitizes first.  Core's runCommand uses `::system(strCommand)` which
// is shell-evaluated, so untrusted bytes need ShellEscape (system.cpp:41-46)
// + SanitizeString (kernel_notifications.cpp:40).  This gate fails the
// audit until a sanitizer helper exists in clearbit (which then must be
// invoked at every notify call site).
test "w141/G30: no ShellEscape / SanitizeString helper in main.zig (xfail)" {
    const alloc = testing.allocator;
    const src = try readMainSrc(alloc);
    defer alloc.free(src);

    const has_helper = std.mem.indexOf(u8, src, "ShellEscape") != null or
        std.mem.indexOf(u8, src, "shellEscape") != null or
        std.mem.indexOf(u8, src, "SanitizeString") != null or
        std.mem.indexOf(u8, src, "sanitizeString") != null or
        std.mem.indexOf(u8, src, "shell_escape") != null;
    try testing.expect(!has_helper);

    // And no runCommand helper either — the call site that would need
    // sanitization doesn't exist.
    const has_run_command = std.mem.indexOf(u8, src, "fn runCommand") != null or
        std.mem.indexOf(u8, src, "runCommand(") != null;
    try testing.expect(!has_run_command);
}
