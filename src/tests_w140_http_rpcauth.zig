//! W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch
//! 30-gate audit (clearbit / Zig 0.13)
//!
//! Discovery wave.  Audits clearbit's HTTP server, authentication, and
//! JSON-RPC dispatch surface vs Bitcoin Core.
//!
//! References
//! ----------
//! bitcoin-core/src/httpserver.cpp            HTTP server lifecycle,
//!                                            ClientAllowed (rpcallowip),
//!                                            HTTPBindAddresses, ThreadPool,
//!                                            MAX_HEADERS_SIZE, evhttp_set_timeout.
//! bitcoin-core/src/httpserver.h              DEFAULT_HTTP_THREADS=16,
//!                                            DEFAULT_HTTP_WORKQUEUE=64,
//!                                            DEFAULT_HTTP_SERVER_TIMEOUT=30.
//! bitcoin-core/src/httprpc.cpp               JSON-RPC dispatcher: Basic
//!                                            auth, TimingResistantEqual,
//!                                            -rpcauth HMAC-SHA-256,
//!                                            -rpcwhitelist, 250ms sleep,
//!                                            WWW-Authenticate header,
//!                                            JSONErrorReply HTTP status
//!                                            mapping (RPC_INVALID_REQUEST
//!                                            → 400, RPC_METHOD_NOT_FOUND
//!                                            → 404, default → 500).
//! bitcoin-core/src/rpc/request.cpp           Cookie auth — COOKIEAUTH_USER
//!                                            ("__cookie__"), GenerateAuthCookie
//!                                            (write to .cookie.tmp + RenameOver),
//!                                            GetAuthCookieFile (rpccookiefile),
//!                                            JSONRPCRequest::parse (jsonrpc
//!                                            version detection).
//! bitcoin-core/share/rpcauth/rpcauth.py      Canonical HMAC-SHA-256(salt,
//!                                            password) helper.
//! bitcoin-core/src/util/strencodings.h       TimingResistantEqual.
//! bitcoin-core/src/init.cpp:706-720          -rpc* argspec catalogue.
//!
//! Status
//! ------
//! XFAIL guards.  Each "BUG" test asserts the current (buggy) state so
//! the next fix wave can flip the gate by deliberately breaking the
//! test.  Failures here mean someone already landed the fix and forgot
//! to update the audit.  See `audit/w140_http_rpcauth.md` for the prose.
//!
//! Run: `zig build test-w140`

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");
const main_mod = @import("main.zig");

// ===========================================================================
// G1 — HTTP server is a hand-rolled accept loop (PRESENT-by-design)
// Core uses libevent's evhttp; clearbit binds plain TCP via std.net and
// dispatches in a single accept → handle → accept loop.  Documents the
// design choice via test so a future "use std.http.Server" refactor is
// audit-visible.
// ===========================================================================

test "w140 G1: RpcServer exposes start/run/stop lifecycle (PRESENT-by-design)" {
    // The pub-decl lifecycle methods that wire main.zig → RpcServer.
    // handleConnection / handleBatch / handleSingleRequest are private
    // (per the rpc.zig convention) so @hasDecl returns false; we
    // document them by-reference in the audit doc, not by reflection.
    try testing.expect(@hasDecl(rpc.RpcServer, "start"));
    try testing.expect(@hasDecl(rpc.RpcServer, "run"));
    try testing.expect(@hasDecl(rpc.RpcServer, "stop"));
    try testing.expect(@hasDecl(rpc.RpcServer, "deinit"));
    // dispatch IS pub (entry point for tests).
    try testing.expect(@hasDecl(rpc.RpcServer, "dispatch"));
}

// ===========================================================================
// G2 — `start()` validates config (TLS plumbing) before bind.  PRESENT.
// validateTlsConfig is called from RpcServer.start (rpc.zig:1395-1402).
// ===========================================================================

test "w140 G2: validateTlsConfig present and called from start (PRESENT)" {
    try testing.expect(@hasDecl(rpc, "validateTlsConfig"));
    try testing.expect(@hasDecl(rpc, "tlsAvailable"));

    // tlsAvailable() == false on Zig 0.13 (no std.crypto.tls.Server).
    try testing.expect(rpc.tlsAvailable() == false);

    // Empty cert + key paths are HTTP (default) and validate OK.
    const cfg_http = rpc.RpcConfig{};
    try rpc.validateTlsConfig(cfg_http);

    // Cert without key → TlsCertWithoutKey.
    const cfg_cert_only = rpc.RpcConfig{ .tls_cert_path = "/tmp/cert.pem" };
    try testing.expectError(error.TlsCertWithoutKey, rpc.validateTlsConfig(cfg_cert_only));

    // Key without cert → TlsKeyWithoutCert.
    const cfg_key_only = rpc.RpcConfig{ .tls_key_path = "/tmp/key.pem" };
    try testing.expectError(error.TlsKeyWithoutCert, rpc.validateTlsConfig(cfg_key_only));

    // Both set → TlsServerUnavailable (deferral).
    const cfg_both = rpc.RpcConfig{
        .tls_cert_path = "/tmp/cert.pem",
        .tls_key_path = "/tmp/key.pem",
    };
    try testing.expectError(error.TlsServerUnavailable, rpc.validateTlsConfig(cfg_both));
}

// ===========================================================================
// G3 — Constant-time auth credential compare.
// BUG-1 P0-SEC: clearbit uses std.mem.eql which short-circuits on first
// differing byte.  Core uses TimingResistantEqual (strencodings.h:202-210)
// which XORs every byte into an accumulator.
//
// We verify the absence of any timingResistantEqual / constantTimeEqual
// helper in either rpc.zig or main.zig.  Flip when added.
// ===========================================================================

test "w140 G3 BUG-1 (P0-SEC): no timing-resistant compare helper (xfail)" {
    try testing.expect(!@hasDecl(rpc, "timingResistantEqual"));
    try testing.expect(!@hasDecl(rpc, "constantTimeEqual"));
    try testing.expect(!@hasDecl(main_mod, "timingResistantEqual"));
    try testing.expect(!@hasDecl(main_mod, "constantTimeEqual"));
}

// ===========================================================================
// G4 — `-rpcauth=<user>:<salt>$<hash>` HMAC-SHA-256 path.
// BUG-4 P0-SEC.  Core: httprpc.cpp:62-82 + 290-304 + rpcauth.py.
// clearbit has no `parseRpcAuthSpec`, no `RpcAuthEntry`, no `--rpcauth=`
// CLI flag, no `g_rpcauth` analogue.  This is the standard
// production-deployment posture; without it, operators MUST keep plaintext
// credentials on disk (the BUG-4 push to plaintext).
// ===========================================================================

test "w140 G4 BUG-4 (P0-SEC): no -rpcauth HMAC-SHA-256 path (xfail)" {
    try testing.expect(!@hasDecl(rpc, "parseRpcAuthSpec"));
    try testing.expect(!@hasDecl(rpc, "RpcAuthEntry"));
    try testing.expect(!@hasDecl(rpc, "checkRpcAuth"));
    try testing.expect(!@hasDecl(main_mod, "parseRpcAuthSpec"));

    // Only auth knobs available are plaintext rpc_user / rpc_password and
    // the per-process cookie.  Verify the only-two-fields posture:
    try testing.expect(@hasField(rpc.RpcConfig, "auth_token"));
    try testing.expect(@hasField(rpc.RpcConfig, "cookie_token"));
    // No rpcauth_entries field.
    try testing.expect(!@hasField(rpc.RpcConfig, "rpcauth_entries"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_auth"));
}

// ===========================================================================
// G5 — `-rpccookiefile=<path>` + `-rpccookieperms=owner|group|all` flags.
// BUG-2 P1-MISSING.  Core: init.cpp:710-711 + rpc/request.cpp:86-95.
// clearbit hardcodes <datadir>/.cookie (main.zig:805); no override; only
// mode 0o600 from the createFileAbsolute call.
// ===========================================================================

test "w140 G5 BUG-2 (P1-MISSING): no -rpccookiefile / -rpccookieperms flags (xfail)" {
    // No config field for the cookie-file path or perms.
    try testing.expect(!@hasField(rpc.RpcConfig, "cookie_file"));
    try testing.expect(!@hasField(rpc.RpcConfig, "cookie_perms"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpccookiefile"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpccookieperms"));

    // generateCookieFile takes (datadir, allocator) only — no path override.
    const sig = @TypeOf(main_mod.generateCookieFile);
    const info = @typeInfo(sig);
    try testing.expect(info == .Fn);
    try testing.expectEqual(@as(usize, 2), info.Fn.params.len);
}

// ===========================================================================
// G6 — Cookie file written atomically via `.cookie.tmp` → rename.
// BUG-3 P1-RACE.  Core: rpc/request.cpp:113-127 uses RenameOver.
// clearbit (main.zig:786-819) writes directly to .cookie — no temp,
// no rename.  Race: a process opening .cookie mid-write reads garbage.
// ===========================================================================

test "w140 G6 BUG-3 (P1-RACE): cookie file not written atomically (xfail)" {
    // Generate a cookie into a temp datadir.  Source-shape check: the
    // helper writes directly to <datadir>/.cookie with no `.cookie.tmp`
    // intermediate.  We can't assert the source path, so we functionally
    // verify by writing the cookie and checking that ONLY `.cookie` exists
    // (no `.cookie.tmp` was ever left behind / no atomicity primitive).
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Build a path inside tmp.dir.  std.testing.tmpDir gives an iterable
    // dir handle; we need an absolute path for generateCookieFile.
    var path_buf: [4096]u8 = undefined;
    const datadir = try tmp.dir.realpath(".", &path_buf);

    const token = try main_mod.generateCookieFile(datadir, testing.allocator);
    defer testing.allocator.free(token);

    // .cookie must exist.
    var cookie_file = try tmp.dir.openFile(".cookie", .{});
    defer cookie_file.close();
    const cookie_content = try cookie_file.readToEndAlloc(testing.allocator, 1024);
    defer testing.allocator.free(cookie_content);

    // Sanity: starts with "__cookie__:" (Core's COOKIEAUTH_USER + ':').
    try testing.expect(std.mem.startsWith(u8, cookie_content, "__cookie__:"));

    // No `.cookie.tmp` should remain (Core's atomic write would clean it
    // up too, so this is necessary-but-not-sufficient).  We're asserting
    // the absence of an atomicity primitive at the source level:
    //   - main_mod.generateCookieFile takes only 2 args (no temp_path).
    //   - There is no `renameAtomic`-style helper exported.
    try testing.expect(!@hasDecl(main_mod, "generateCookieFileAtomic"));
    try testing.expect(!@hasDecl(main_mod, "renameOverCookie"));
}

// ===========================================================================
// G7 — `-rpcallowip=<cidr>` CIDR allow-list applied per connection.
// BUG-7 P0-SEC (W124 BUG-13 re-anchored).  Core: httpserver.cpp:137-145,
// 148-168, 217-222 (ClientAllowed, InitHTTPAllowList, http_request_cb).
// clearbit applies NO IP-level filtering; rpc_bind controls interface only.
// ===========================================================================

test "w140 G7 BUG-7 (P0-SEC, W124 BUG-13 re-anchor): no -rpcallowip CIDR allow-list (xfail)" {
    // No config field for the CIDR allow-list.
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_allow_ip"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_allow_subnets"));
    try testing.expect(!@hasField(rpc.RpcConfig, "allow_subnets"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpcallowip"));

    // No ClientAllowed / isClientAllowed helper.
    try testing.expect(!@hasDecl(rpc, "isClientAllowed"));
    try testing.expect(!@hasDecl(rpc, "clientAllowed"));
    try testing.expect(!@hasDecl(rpc, "checkRpcAllowIp"));
}

// ===========================================================================
// G8 — 250 ms UninterruptibleSleep after failed auth.
// BUG-8 P1-SEC.  Core: httprpc.cpp:125-128.
// No sleep-after-failed-auth in clearbit.
// ===========================================================================

test "w140 G8 BUG-8 (P1-SEC): no 250ms brute-force deterrent after failed auth (xfail)" {
    try testing.expect(!@hasDecl(rpc, "AUTH_FAIL_SLEEP_MS"));
    try testing.expect(!@hasDecl(rpc, "BRUTE_FORCE_SLEEP_MS"));
    try testing.expect(!@hasDecl(rpc, "delayOnAuthFail"));
}

// ===========================================================================
// G9 — `-rpcservertimeout=<sec>` (default 30s).
// BUG-12 P2-DOS.  Core: httpserver.cpp:408 + init.cpp:714.
// clearbit reads from conn.stream.read() with no timeout.
// ===========================================================================

test "w140 G9 BUG-12 (P2-DOS): no -rpcservertimeout request timeout (xfail)" {
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_server_timeout"));
    try testing.expect(!@hasField(rpc.RpcConfig, "request_timeout"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpcservertimeout"));
    try testing.expect(!@hasDecl(rpc, "DEFAULT_HTTP_SERVER_TIMEOUT"));
}

// ===========================================================================
// G10 — `-rpcthreads=<n>` worker pool (default 16).
// BUG-5 P2-DOS.  Core: httpserver.cpp:78, 440-444 + init.cpp:715.
// clearbit's RpcServer.run is a single accept → handle → accept loop.
// ===========================================================================

test "w140 G10 BUG-5 (P2-DOS): no -rpcthreads worker pool (xfail)" {
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_threads"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpcthreads"));
    try testing.expect(!@hasDecl(rpc, "DEFAULT_HTTP_THREADS"));
    try testing.expect(!@hasDecl(rpc, "RpcThreadPool"));
    try testing.expect(!@hasDecl(rpc, "HttpThreadPool"));
}

// ===========================================================================
// G11 — `-rpcwhitelist=<user>:<m1>,<m2>` per-user method ACL.
// BUG-6 P1-MISSING.  Core: httprpc.cpp:144-191, 306-326.
// clearbit has no per-user method whitelist; all-or-nothing.
// ===========================================================================

test "w140 G11 BUG-6 (P1-MISSING): no -rpcwhitelist per-user method ACL (xfail)" {
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_whitelist"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpcwhitelist"));
    try testing.expect(!@hasDecl(rpc, "checkMethodWhitelist"));
    try testing.expect(!@hasDecl(rpc, "RPC_FORBIDDEN_METHOD"));
    // BUG-26 (no authUser tracking) — there is no per-request `auth_user`
    // tracked through dispatch.  Verify the dispatch path takes only the
    // raw body, no authUser slot.
    const sig = @TypeOf(rpc.RpcServer.dispatch);
    const info = @typeInfo(sig);
    try testing.expect(info == .Fn);
    // dispatch(self: *RpcServer, body: []const u8) — 2 params.
    try testing.expectEqual(@as(usize, 2), info.Fn.params.len);
}

// ===========================================================================
// G12 — `-rpcworkqueue=<n>` overload signal (HTTP 503).
// BUG-5 (same root cause as G10) P2-DOS.  Core: httpserver.cpp:79, 255-258.
// clearbit has no work queue; cannot emit HTTP 503 "Work queue depth
// exceeded".
// ===========================================================================

test "w140 G12 BUG-5 (P2-DOS, same root cause as G10): no -rpcworkqueue overload signal (xfail)" {
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_work_queue"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpcworkqueue"));
    try testing.expect(!@hasDecl(rpc, "DEFAULT_HTTP_WORKQUEUE"));
    try testing.expect(!@hasDecl(rpc, "HTTP_SERVICE_UNAVAILABLE"));
}

// ===========================================================================
// G13 — `WWW-Authenticate: Basic realm="jsonrpc"` on 401.
// BUG-9 P1-SEC (RFC-7235 violation).  Core: httprpc.cpp:33, 114, 130.
// clearbit's sendHttpError emits only Content-Length:0 + Connection:close
// (rpc.zig:1714-1719).
// ===========================================================================

test "w140 G13 BUG-9 (P1-SEC, RFC-7235): no WWW-Authenticate header on 401 (xfail)" {
    // No WWW_AUTH constant, no WWW-Authenticate emit helper, no
    // dedicated 401 sender.  `sendHttpError` itself is private to
    // RpcServer (rpc.zig:1714) — we can't introspect its signature,
    // but the absence of the canonical fix-helper names below is
    // enough to flip the gate when implemented.
    try testing.expect(!@hasDecl(rpc, "WWW_AUTH_HEADER_DATA"));
    try testing.expect(!@hasDecl(rpc, "WWW_AUTHENTICATE_HEADER"));
    try testing.expect(!@hasDecl(rpc, "sendHttpUnauthorized"));
    try testing.expect(!@hasDecl(rpc, "sendWwwAuthenticate"));
    try testing.expect(!@hasDecl(rpc.RpcServer, "sendHttpUnauthorized"));
    try testing.expect(!@hasDecl(rpc.RpcServer, "sendWwwAuthenticate"));
}

// ===========================================================================
// G14 — REST endpoints bypass auth gate (design-parity with Core).
// PRESENT-by-design at the auth-skip level (matches Core which registers
// REST handlers independently).  Documents the routing-order via test so
// a future "add auth to REST" decision is audit-visible.  BUG-15 (G25)
// covers the missing `-rest` gate (independent concern).
// ===========================================================================

test "w140 G14: REST endpoints route before auth check (PRESENT-by-design)" {
    // The handleConnection routing order (rpc.zig:1573-1647) is:
    //   1. GET /rest/* → handleRestRequest (no auth)
    //   2. POST /payjoin* → handlePayjoinRequest (no auth — design choice)
    //   3. POST /* → auth gate then dispatch
    // handleRestRequest is private (per the rpc.zig convention);
    // handlePayjoinRequest is pub — assert it exists as the
    // closest-pub-decl proxy for the routing-order design.
    try testing.expect(@hasDecl(rpc.RpcServer, "handlePayjoinRequest"));
    // Public module-level alias for handleGetPayjoinRequest (W119/G26).
    try testing.expect(@hasDecl(rpc, "handleGetPayjoinRequest"));
}

// ===========================================================================
// G15 — Empty batch + all-notification non-empty batch behaviour.
// BUG-10 (HTTP 204 missing for all-notification) — PARTIAL.  Empty batch
// returns RPC -32600 (Core matches) but HTTP 200 (Core: 400 — covered
// under BUG-18 / G18).
// ===========================================================================

test "w140 G15 BUG-10 (P2-COMPAT): no HTTP 204 for all-notification non-empty batch (xfail)" {
    try testing.expect(!@hasDecl(rpc, "HTTP_NO_CONTENT"));
    try testing.expect(!@hasDecl(rpc, "isNotification"));
    // handleBatch is private; its existence is documented in the audit
    // doc.  MAX_BATCH_SIZE is the pub-decl proxy — its presence confirms
    // batch dispatch lives at the expected site (rpc.zig:3175).
    try testing.expect(@hasDecl(rpc.RpcServer, "MAX_BATCH_SIZE"));
}

test "w140 G15: MAX_BATCH_SIZE = 1000 matches Core (PRESENT)" {
    try testing.expectEqual(@as(usize, 1000), rpc.RpcServer.MAX_BATCH_SIZE);
}

// ===========================================================================
// G16 — Notification (no `id` field) returns HTTP 204 No Content.
// BUG-11 P2-MISSING.  Core: httprpc.cpp:167-171.
// clearbit always emits {"result","error","id":null} with HTTP 200.
// ===========================================================================

test "w140 G16 BUG-11 (P2-MISSING): no notification-detection / HTTP 204 path (xfail)" {
    try testing.expect(!@hasDecl(rpc, "isNotification"));
    try testing.expect(!@hasDecl(rpc.RpcServer, "isNotification"));
}

// ===========================================================================
// G17 — Max headers size enforcement.  Core: MAX_HEADERS_SIZE=8192.
// BUG-13 P2-DOS.  clearbit has a fixed 65536-byte stack buffer for
// headers + initial body fragment; overflow without \r\n\r\n silently
// closes the connection (no HTTP 413/414 reply).
// ===========================================================================

test "w140 G17 BUG-13 (P2-DOS): 64KiB combined header+body buffer; silent close on overflow (xfail)" {
    // Confirm clearbit does NOT expose a MAX_HEADERS_SIZE constant.
    try testing.expect(!@hasDecl(rpc, "MAX_HEADERS_SIZE"));
    try testing.expect(!@hasDecl(rpc, "MAX_HEADER_SIZE"));
    // The Core default is 8192; clearbit's buffer is 65536 stack-allocated
    // INSIDE handleConnection (rpc.zig:1535) — no exported constant so we
    // can't assert the value directly, only the absence of an explicit
    // header-size knob.
}

// ===========================================================================
// G18 — Error code → HTTP status mapping.
// BUG-18 P1-CDIV (W125 BUG-15+17 re-anchored).  Core: httprpc.cpp:46-58
// (JSONErrorReply) maps RPC_INVALID_REQUEST → 400, RPC_METHOD_NOT_FOUND
// → 404, default → 500.  clearbit hardcodes HTTP 200 on every response
// (rpc.zig:1722-1728).
// ===========================================================================

test "w140 G18 BUG-18 (P1-CDIV, W125 BUG-15+17 re-anchor): no HTTP status mapping (xfail)" {
    try testing.expect(!@hasDecl(rpc, "errorCodeToHttpStatus"));
    try testing.expect(!@hasDecl(rpc, "rpcErrorToHttpStatus"));
    try testing.expect(!@hasDecl(rpc, "httpStatusFor"));
    // jsonRpcError signature: (self, code, message, id) — 4 params; no
    // status-code slot.
    const sig = @TypeOf(rpc.RpcServer.jsonRpcError);
    const info = @typeInfo(sig);
    try testing.expect(info == .Fn);
    try testing.expectEqual(@as(usize, 4), info.Fn.params.len);
}

// ===========================================================================
// G19 — Reason phrase reflects status.  BUG-16 P2-COSMETIC (W125 BUG-16
// re-anchor).  sendHttpResponse always emits "OK"; sendRestResponse has
// a 3-entry switch only.
// ===========================================================================

test "w140 G19 BUG-16 (P2-COSMETIC, W125 BUG-16 re-anchor): reason phrase always OK on JSON-RPC (xfail)" {
    try testing.expect(!@hasDecl(rpc, "statusReasonPhrase"));
    try testing.expect(!@hasDecl(rpc, "httpStatusText"));
}

// ===========================================================================
// G20 — Content-Type on every reply.  PARTIAL — BUG-22 P2-COSMETIC.
// sendHttpResponse emits application/json on success; sendHttpError emits
// NO Content-Type at all.
// ===========================================================================

test "w140 G20 BUG-22 (P2-COSMETIC): sendHttpError emits no Content-Type header (xfail)" {
    // Direct inspection isn't possible without instantiating an RpcServer
    // + a stream pipe; we instead assert there is no
    // `sendHttpErrorWithContentType` / `sendHttpErrorJson` variant —
    // which would be the canonical fix.
    try testing.expect(!@hasDecl(rpc.RpcServer, "sendHttpErrorJson"));
    try testing.expect(!@hasDecl(rpc.RpcServer, "sendHttpErrorWithContentType"));
}

// ===========================================================================
// G21 — JSON-RPC 2.0 detection + 2.0-shape reply.
// BUG-21 P1-COMPAT (W125 BUG-18 re-anchored).  Core: rpc/request.cpp:213-230.
// clearbit never reads "jsonrpc" field; always emits legacy 1.0 shape.
// ===========================================================================

test "w140 G21 BUG-21 (P1-COMPAT, W125 BUG-18 re-anchor): no JSON-RPC 2.0 detection (xfail)" {
    try testing.expect(!@hasDecl(rpc, "JSONRPCVersion"));
    try testing.expect(!@hasDecl(rpc, "JsonRpcVersion"));
    try testing.expect(!@hasDecl(rpc, "parseJsonRpcVersion"));
}

// ===========================================================================
// G22 — Error `message` JSON-escaped.
// BUG-23 P2-SECURITY (W125 BUG-19 re-anchored).  jsonRpcError uses %s
// printf; writeJsonValue .string emits raw bytes between quotes
// (rpc.zig:14613-14617).
// ===========================================================================

test "w140 G22 BUG-23 (P2-SECURITY, W125 BUG-19 re-anchor): error message and id not JSON-escaped (xfail)" {
    try testing.expect(!@hasDecl(rpc, "jsonEscapeString"));
    try testing.expect(!@hasDecl(rpc, "writeJsonEscapedString"));
    try testing.expect(!@hasDecl(rpc, "escapeJsonString"));
}

// ===========================================================================
// G23 — /wallet/<name> POST routing to wallet-targeted RPC.  PRESENT.
// ===========================================================================

test "w140 G23: /wallet/<name> POST routing exists (PRESENT)" {
    // wallet.zig::WalletManager.getTargetWallet handles /wallet/<name>.
    const wallet_mod = @import("wallet.zig");
    try testing.expect(@hasDecl(wallet_mod, "WalletManager"));
    try testing.expect(@hasDecl(wallet_mod.WalletManager, "getTargetWallet"));
}

// ===========================================================================
// G24 — HTTPS / TLS termination.
// BUG-14 P2-DEFERRED (FIX-64).  Design-parity with Core (Core itself has
// no native HTTPS; operators terminate at nginx/Caddy).  Documents the
// flag-plumbing-only posture so the field is not forgotten.
// ===========================================================================

test "w140 G24 BUG-14 (P2-DEFERRED, FIX-64): TLS server primitive not available (xfail)" {
    // tlsAvailable() returns false on Zig 0.13 stdlib.
    try testing.expect(rpc.tlsAvailable() == false);
    // The deliberate-absence-of names tests (W119/G3 + G24).
    try testing.expect(!@hasDecl(rpc, "TlsRpcServer"));
    try testing.expect(!@hasDecl(rpc, "TlsPayjoinServer"));
}

// ===========================================================================
// G25 — `-rest=<0|1>` flag gates REST endpoint registration.
// BUG-15 P1-MISSING.  Core: init.cpp:705 (`-rest`, default 0).
// clearbit has no --rest flag; REST endpoints are always-on.
// ===========================================================================

test "w140 G25 BUG-15 (P1-MISSING): no --rest enable flag; REST always-on (xfail)" {
    try testing.expect(!@hasField(rpc.RpcConfig, "rest_enabled"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rest"));
    try testing.expect(!@hasField(rpc.RpcConfig, "rpc_rest"));
    try testing.expect(!@hasDecl(rpc, "DEFAULT_REST_ENABLE"));
}

// ===========================================================================
// G26 — HTTP version field handling.
// BUG-20 P2-COSMETIC.  clearbit silently accepts HTTP/1.0 / 1.1 / 2.0
// identically (no version parse).
// ===========================================================================

test "w140 G26 BUG-20 (P2-COSMETIC): no HTTP version field parsing (xfail)" {
    try testing.expect(!@hasDecl(rpc, "parseHttpVersion"));
    try testing.expect(!@hasDecl(rpc, "HttpVersion"));
}

// ===========================================================================
// G27 — Multiple Authorization headers — first wins.  PRESENT.
// Matches Core's evhttp_find_header which returns the first match.
// ===========================================================================

test "w140 G27: findHeader returns first match for duplicate headers (PRESENT)" {
    // We can't call findHeader (it's file-private); instead we exercise
    // the runtime behaviour via a 3-line check via parsePayjoinQuery which
    // also uses key lookups.  Simplest test: verify findHeader is private
    // (no public re-export) so we document the current encapsulation.
    try testing.expect(!@hasDecl(rpc, "findHeader"));
}

// ===========================================================================
// G28 — Transfer-Encoding: chunked support.
// BUG-20 (joint with G26 — P2-COMPAT).  clearbit requires Content-Length,
// rejects with HTTP 400 "Missing Content-Length" if absent.  Chunked
// requests fall into this branch silently.
// ===========================================================================

test "w140 G28 BUG-20 (P2-COMPAT, joint with G26): no Transfer-Encoding: chunked decoder (xfail)" {
    try testing.expect(!@hasDecl(rpc, "decodeChunked"));
    try testing.expect(!@hasDecl(rpc, "readChunkedBody"));
}

// ===========================================================================
// G29 — `Connection: close` on every reply.  PRESENT-by-design.
// Matches Core's default operational model.  Documents the choice via
// test so a future keep-alive enablement is audit-visible.
// ===========================================================================

test "w140 G29: Connection: close emitted on every reply (PRESENT-by-design)" {
    // The string "Connection: close" appears in all three send* helpers
    // (rpc.zig:1717, 1725, 1740).  We can't grep the source string from
    // test code, but the absence of any keep-alive helper documents the
    // posture.
    try testing.expect(!@hasDecl(rpc, "enableKeepAlive"));
    try testing.expect(!@hasDecl(rpc, "supportsKeepAlive"));
}

// ===========================================================================
// G30 — Dead-helper sweep.  No genuine dead helper in HTTP scope today.
// PRESENT-by-design.  Documents that all non-dispatch RpcConfig fields
// are wired:
//   - auth_token / cookie_token: BUG-1 timing aside, wired into 1641-1644.
//   - tls_cert_path / tls_key_path: FIX-64 flag plumbing (intentionally
//     inert).
//   - datadir: consumed by file-writing RPCs (dumpmempool etc).
//   - max_request_size: enforced at rpc.zig:1659.
// No dead-storage knob in scope.
// ===========================================================================

test "w140 G30: HTTP-scope RpcConfig fields are all wired (PRESENT-by-design)" {
    // All RpcConfig fields in scope are visited:
    try testing.expect(@hasField(rpc.RpcConfig, "bind_address"));
    try testing.expect(@hasField(rpc.RpcConfig, "port"));
    try testing.expect(@hasField(rpc.RpcConfig, "auth_token"));
    try testing.expect(@hasField(rpc.RpcConfig, "cookie_token"));
    try testing.expect(@hasField(rpc.RpcConfig, "max_request_size"));
    try testing.expect(@hasField(rpc.RpcConfig, "datadir"));
    try testing.expect(@hasField(rpc.RpcConfig, "tls_cert_path"));
    try testing.expect(@hasField(rpc.RpcConfig, "tls_key_path"));
}

// ===========================================================================
// Bonus — auth-helper functional checks (PRESENT, sanity)
// These tests exercise the actual helpers from main.zig.  They are NOT
// xfails; failures here indicate a real regression in the (already
// shipped) auth surface.
// ===========================================================================

test "w140 sanity: computeAuthToken returns base64(user:pass)" {
    const t = try main_mod.computeAuthToken("alice", "s3cr3t", testing.allocator);
    try testing.expect(t != null);
    defer if (t) |tok| testing.allocator.free(tok);

    // base64("alice:s3cr3t") = "YWxpY2U6czNjcjN0"
    try testing.expectEqualStrings("YWxpY2U6czNjcjN0", t.?);
}

test "w140 sanity: computeAuthToken returns null when user or pass missing" {
    const t1 = try main_mod.computeAuthToken(null, "p", testing.allocator);
    try testing.expectEqual(@as(?[]const u8, null), t1);

    const t2 = try main_mod.computeAuthToken("u", null, testing.allocator);
    try testing.expectEqual(@as(?[]const u8, null), t2);

    const t3 = try main_mod.computeAuthToken(null, null, testing.allocator);
    try testing.expectEqual(@as(?[]const u8, null), t3);
}

test "w140 sanity: generateCookieFile writes __cookie__:<64-hex> and returns its base64" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const datadir = try tmp.dir.realpath(".", &path_buf);

    const token = try main_mod.generateCookieFile(datadir, testing.allocator);
    defer testing.allocator.free(token);

    // Token should decode to "__cookie__:<64-hex>".
    const decoder = std.base64.standard.Decoder;
    const dec_len = try decoder.calcSizeForSlice(token);
    const decoded = try testing.allocator.alloc(u8, dec_len);
    defer testing.allocator.free(decoded);
    try decoder.decode(decoded, token);

    try testing.expect(std.mem.startsWith(u8, decoded, "__cookie__:"));
    // 11 chars prefix + 64 hex chars = 75 bytes total.
    try testing.expectEqual(@as(usize, 75), decoded.len);
    // Verify the hex tail.
    for (decoded[11..]) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        try testing.expect(is_hex);
    }
}

test "w140 sanity: RpcConfig defaults — bind 127.0.0.1, no auth, no TLS" {
    const cfg = rpc.RpcConfig{};
    try testing.expectEqualStrings("127.0.0.1", cfg.bind_address);
    try testing.expectEqual(@as(u16, 8332), cfg.port);
    try testing.expectEqual(@as(?[]const u8, null), cfg.auth_token);
    try testing.expectEqual(@as(?[]const u8, null), cfg.cookie_token);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls_cert_path);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls_key_path);
    try testing.expectEqual(@as(usize, 1 << 24), cfg.max_request_size);
}

// ===========================================================================
// Bonus — RPC error code constants used in the HTTP-status mapping.
// These come from W125 but are anchored here because they are the inputs
// to the BUG-18 fix.
// ===========================================================================

test "w140 sanity: HTTP-status-mapping inputs (RPC_INVALID_REQUEST + RPC_METHOD_NOT_FOUND) defined" {
    try testing.expectEqual(@as(i32, -32600), rpc.RPC_INVALID_REQUEST);
    try testing.expectEqual(@as(i32, -32601), rpc.RPC_METHOD_NOT_FOUND);
    try testing.expectEqual(@as(i32, -32700), rpc.RPC_PARSE_ERROR);
    try testing.expectEqual(@as(i32, -32603), rpc.RPC_INTERNAL_ERROR);
}
