# W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit (clearbit)

**Date:** 2026-05-18
**Scope:** clearbit's HTTP server, RPC authentication, cookie generation,
and JSON-RPC dispatch surface vs Bitcoin Core
(`bitcoin-core/src/httpserver.cpp` + `httpserver.h`,
 `bitcoin-core/src/httprpc.cpp`,
 `bitcoin-core/src/rpc/server.cpp` + `rpc/server_util.cpp`,
 `bitcoin-core/src/rpc/request.{cpp,h}` (cookie auth + `JSONRPCRequest::parse`),
 `bitcoin-core/share/rpcauth/rpcauth.py`,
 `bitcoin-core/src/init.cpp` (`-rpc*` argspec)).
**BIPs:** none.
**Files in scope:** `src/rpc.zig` (handleConnection, dispatch, handleBatch,
sendHttpError/Response, RpcServer state, RpcConfig, findHeader,
writeJsonValue, jsonRpcError/Result, `RPC_*` constants, REST routing),
`src/main.zig` (`computeAuthToken`, `generateCookieFile`, `deleteCookieFile`,
`parseArgs --rpc*`).
**Mode:** DISCOVERY (no production code changes; XFAIL-style guards only).
**Test step:** `zig build test-w140` (folded into `zig build test`).
**Related prior waves:**
- W124 (operator experience) — already flagged BUG-13 P2-SEC `--rpcallowip`
  MISSING. Re-anchored here under G7.
- W125 (RPC error parity) — already flagged BUG-15/G25 `RPC_INVALID_REQUEST`
  → HTTP 200 (Core: 400), BUG-17/G27 `RPC_METHOD_NOT_FOUND` → HTTP 200
  (Core: 404), BUG-16/G26 reason-phrase always "OK", BUG-18/G28 JSON-RPC
  2.0 not detected, BUG-19/G29 error `message` not JSON-escaped. Carried
  here under G18 / G19 / G20 / G21 / G22 for HTTP-surface tracking; the
  W125 audit treats them as error-parity gates.
- W119 + FIX-64 — HTTPS/TLS termination DEFERRED (flag-plumbing only).
  Re-anchored under G24.

## Summary

clearbit's HTTP server is a single-threaded, hand-rolled HTTP/1.1 reader
in `RpcServer.handleConnection` (`rpc.zig:1531-1711`). It accepts plain
TCP on `rpc_bind:rpc_port`, parses the request line / `Authorization`
/ `Content-Length` headers, supports HTTP Basic Auth against an
in-memory `auth_token` (Base64("user:pass")) and a per-process cookie
token (Base64("__cookie__:<hex>")), and dispatches POST bodies through
`dispatch()` → `handleSingleRequest()` → a 90-method if/else if chain.
REST endpoints (`/rest/...`) are routed before the auth check (G14
BUG-7). Authentication is "either auth_token-match OR cookie_token-match"
with non-constant-time `std.mem.eql` byte compares (G3 BUG-1).
Cookie generation is non-atomic, has no `-rpccookieperms` / `-rpccookiefile`
plumbing (G5 BUG-2), and uses `mode=0o600` only on the create syscall
(no rename-over-temp) (G6 BUG-3). The server is single-threaded
synchronous accept → handle, with no thread pool, no `-rpcworkqueue`,
no `-rpcservertimeout`, no `-rpcthreads` (G12 BUG-5). There is no
`-rpcauth=<user>:<salt>$<hash>` HMAC-SHA-256 path (G4 BUG-4), no
`-rpcwhitelist` per-user method ACL (G11 BUG-6), no `-rpcallowip` CIDR
allow-list (G7 BUG-7 re-anchored from W124), no `WWW-Authenticate:
Basic realm="jsonrpc"` header on 401 (G13 BUG-9), no 250 ms
`UninterruptibleSleep` brute-force deterrent (G10 BUG-8), and no
batch-empty / notification (no-`id` 204) handling (G15 BUG-10, G16
BUG-11). The body-reader buffer is a 65 536-byte fixed stack buffer
(`buf: [65536]u8`); if request headers + body exceed it without an
embedded `\r\n\r\n` separator early, the reader silently drops the
connection (G17 BUG-13). Multiple `Authorization` headers cause
`findHeader` to return the FIRST match only (Core: undefined but
evhttp normalises) — minor (G27 BUG-19). Transfer-Encoding: chunked
is unsupported (silently treated as missing Content-Length; G28
BUG-20). REST endpoints bypass the auth gate entirely (G14 BUG-7) AND
have no `-rest` enable flag (G25 BUG-15) — exposing REST regardless
of operator intent. HTTPS / TLS termination is DEFERRED (G24
BUG-14 ref FIX-64). HTTP/1.0 requests are silently accepted as
HTTP/1.1 (G26 BUG-18). Connection: close on every reply prevents
keep-alive reuse — Core also does this in libevent's default config,
so PRESENT-by-design (G29).

Key findings ranked by severity:

- **P0-SEC: Authentication uses non-constant-time `std.mem.eql`.**
  `rpc.zig:1641-1644` does `std.mem.eql(u8, provided, t)` against the
  base64-encoded auth token / cookie token. `std.mem.eql` short-circuits
  on the first differing byte. Core uses
  `TimingResistantEqual(hash_from_pass, hash)` (`strencodings.h:202-210`)
  which XORs every byte before comparing the accumulator to 0. An
  attacker on the same machine (or LAN, given default `-rpcbind=127.0.0.1`
  is bypassed when operator sets it to a routable IP) can byte-by-byte
  recover the first ~22 chars of the base64-encoded token via timing
  side-channels. Since both auth_token and cookie_token are checked
  inside an `if/else` with `std.mem.eql` shortcuts, the attack works on
  either path. See BUG-1. (G3.)

- **P0-SEC: No `-rpcauth=<user>:<salt>$<hash>` HMAC-SHA-256 path.**
  Core's primary production deployment mechanism (`httprpc.cpp:62-82,
  290-304`) stores credentials as `user:salt$hash` triples where
  `hash = HexStr(HMAC-SHA-256(salt, password))`. clearbit only
  supports plaintext `--rpcuser` / `--rpcpassword` and a per-process
  random cookie. Operators MUST keep plaintext credentials on disk
  (in `clearbit.conf` or systemd unit `Environment=`), exactly what
  Core's `LogWarning("The use of rpcuser/rpcpassword is less secure
  …")` warns against. `share/rpcauth/rpcauth.py` output is unusable
  with clearbit. **The salt+HMAC scheme is the standard for multi-user
  RPC deployments (Tor controller, BTCPay Server, Specter, etc.); its
  absence pushes operators back to plaintext.** See BUG-4. (G4.)

- **P0-SEC: No `-rpcallowip=<cidr>` CIDR allow-list.**
  (Re-anchored from W124 BUG-13.) Core (`httpserver.cpp:137-145,
  148-168`) defaults to allowing only `127.0.0.0/8` + `::1`, with
  `-rpcallowip` accumulating additional CIDRs. **clearbit applies NO
  IP-level filtering whatsoever**; `RpcServer.handleConnection` does
  not consult the peer address at all. Any operator who sets
  `--rpcbind=0.0.0.0` (a common Docker / port-forward pattern) exposes
  the RPC to the entire reachable network with auth as the only gate.
  Combined with BUG-1 (timing) + BUG-8 (no rate-limit), this is a
  realistic remote-credential-recovery surface. Core additionally
  bind-defaults to `[::1] + 127.0.0.1` ONLY when `-rpcallowip` is
  unset (httpserver.cpp:316-338) — clearbit defaults to `127.0.0.1`
  only (rpc.zig:120). See BUG-7. (G7.)

- **P1-SEC: No `WWW-Authenticate: Basic realm="jsonrpc"` header on 401
  responses.** Core (`httprpc.cpp:113-117, 130-132`) emits
  `WWW-Authenticate: Basic realm="jsonrpc"` on every 401 reply
  (missing OR incorrect Authorization). `sendHttpError(stream, 401,
  "Unauthorized")` (`rpc.zig:1714-1719`) emits ONLY
  `Content-Length: 0\r\nConnection: close\r\n\r\n` — no
  `WWW-Authenticate`. Curl, browsers, and many wallet libraries
  rely on this header to know "credentials needed; here's the realm",
  and will silently not re-prompt or auto-retry-with-creds. RFC 7235
  §3.1: "A 401 response MUST send a WWW-Authenticate header field."
  Spec violation. See BUG-9. (G13.)

- **P1-SEC: No 250 ms brute-force deterrent on failed auth.**
  Core (`httprpc.cpp:125-128`) sleeps 250 ms per failed authorization
  attempt. clearbit returns 401 immediately, so a brute-force
  loop can issue >100 attempts/second per connection per core. At
  64-char hex cookie, exhaustion is infeasible (2^256), but at
  user-chosen plaintext passwords (the only other supported path —
  see BUG-4), a 8-char alnum password is brute-forced in a few hours
  over LAN. The 250 ms wait turns it into months. See BUG-8. (G10.)

- **P1-CDIV: HTTP status mapping wholly absent — every response is
  `200 OK` regardless of RPC error.** Re-anchored from W125 BUG-15
  / BUG-17 (G25 / G27 in that audit). `sendHttpResponse`
  (`rpc.zig:1722-1728`) hardcodes `HTTP/1.1 {d} OK\r\n` with the
  status param but ALWAYS sends 200 (the dispatch path passes 200
  on every code path, including parse errors and method-not-found).
  Core (`httprpc.cpp:46-58`) maps `RPC_INVALID_REQUEST → 400`,
  `RPC_METHOD_NOT_FOUND → 404`, default → 500. Wire-protocol
  divergence: HTTP-status-aware clients (load balancers, monitoring,
  Prometheus exporters that scrape `/health` -shaped semantics)
  see clearbit as "always healthy". See BUG-18. (G18.)

- **P1-MISSING: No `-rpcwhitelist=<user>:<rpc1>,<rpc2>` per-user
  ACL.** Core (`httprpc.cpp:144-191, 306-326`) supports per-user
  method whitelists, with `-rpcwhitelistdefault` toggling the
  fail-open vs fail-closed default. clearbit has neither. Operators
  who want to expose `getblockcount` to a monitoring user but
  refuse `stop` / `signrawtransactionwithwallet` cannot do so —
  the only knob is "RPC fully unlocked" or "no RPC". Defence-in-depth
  loss. See BUG-6. (G11.)

- **P1-MISSING: REST endpoints BYPASS the auth gate entirely.**
  `rpc.zig:1573-1578` routes `/rest/...` BEFORE the auth check at
  `rpc.zig:1631-1647`. So `GET /rest/chaininfo.json` (and all 9
  other REST endpoints) succeed without Authorization. Core
  matches this behaviour (`httpserver.cpp` registers REST handlers
  independently of `httprpc`), BUT Core gates the whole REST
  surface behind `-rest=1` (default 0 — disabled). clearbit has
  NO `-rest` gate; the REST endpoints are always-on. So clearbit's
  rest-without-auth is wider than Core's. **Combined with BUG-7
  (no rpcallowip), any client on a reachable interface can read
  block headers / mempool / chaininfo / blockfilter from clearbit
  without credentials.** See BUG-7 (auth bypass aspect) + BUG-15
  (no `-rest` gate). (G14 + G25.)

- **P1-MISSING: Cookie file is not atomically written via
  `.cookie.tmp` → rename.** Core (`rpc/request.cpp:113-127`)
  writes to a `.cookie.tmp`, closes the stream, then renames to
  `.cookie`. The umask (`common/system.cpp` sets 0077) controls
  the on-disk permissions. clearbit (`main.zig:786-819`) writes
  DIRECTLY to `<datadir>/.cookie` with `mode = 0o600` set on the
  create syscall — but if the process crashes mid-write, the cookie
  file is partial and unparseable; concurrent readers can read
  half a cookie. **More worryingly**: there's no
  `RenameOver`-equivalent, so any tool that opens `.cookie` while
  the daemon is still writing it (race on systemd startup with
  early-readiness probes) gets garbage. See BUG-3. (G6.)

- **P1-MISSING: No `-rpccookiefile=<path>` / `-rpccookieperms=
  owner|group|all` flags.** Core (`httprpc.cpp:247-256`,
  `init.cpp:710-711`, `rpc/request.cpp:86-95`) accepts both.
  clearbit hardcodes the cookie at `<datadir>/.cookie` (`main.zig:805`)
  with no override, and there's no way to relax permissions for
  group access (Docker compose users running RPC client + node in
  separate containers under the same group cannot share auth via
  cookie — they have to fall back to plaintext rpcuser+rpcpassword,
  which is BUG-4). See BUG-2. (G5.)

- **P1-MISSING: No JSON-RPC 2.0 detection or 2.0-shape replies.**
  (Re-anchored from W125 BUG-18.) Core (`rpc/request.cpp:213-230`)
  reads the request's `"jsonrpc"` field, accepts `"1.0"` (legacy)
  or `"2.0"`, rejects anything else with `RPC_INVALID_REQUEST`.
  2.0 mode changes the reply shape (no `"result"` on error,
  `"jsonrpc":"2.0"` field, notifications get 204 no-content).
  clearbit's `handleSingleRequest` (`rpc.zig:2932-2946`) never
  reads `"jsonrpc"`, always emits the legacy 1.0 shape
  `{"result":...,"error":...,"id":...}`. See BUG-21. (G21.)

- **P2-DOS: 65 536-byte fixed stack buffer for the
  request-line+headers+initial body fragment.** `rpc.zig:1535`
  declares `var buf: [65536]u8 = undefined;`. The reader loops
  until `\r\n\r\n` appears anywhere in `buf[0..total_read]` or
  `total_read == buf.len`. Core's `MAX_HEADERS_SIZE = 8192`
  (`httpserver.cpp:51`) bounds the headers ONLY (libevent handles
  body separately). clearbit's 64 KiB is for headers + body
  prefix; a request with no `\r\n\r\n` and 64 KiB of garbage hits
  the `total_read < buf.len` exit, then `headers_end` is
  `std.mem.indexOf(... orelse return)` — silent close. Core
  fails with HTTP 413 Request Entity Too Large or 414 URI Too
  Long. See BUG-13. (G17.)

- **P2-DOS: Single-threaded `run()` — one slow client blocks all
  other RPC.** `rpc.zig:1504-1528` is a serial `accept → handle →
  accept` loop with no thread pool. A POST that uploads
  `max_request_size = 16 MiB` slowly (e.g. 1 byte/sec) stalls all
  other RPC for 16 million seconds. Core uses a
  `ThreadPool g_threadpool_http` (`httpserver.cpp:78`) with
  `-rpcthreads` default 16, `-rpcworkqueue` default 64, and emits
  HTTP 503 "Work queue depth exceeded" on overload. clearbit has
  no concurrency, no work queue, no overload signal. See BUG-5.
  (G12.)

- **P2-MISSING: No 30 s default request timeout.** Core
  (`httpserver.cpp:408`, `-rpcservertimeout`, default 30 s) sets
  `evhttp_set_timeout(http, 30)`. clearbit reads from the socket
  via `conn.stream.read(...)` with no timeout — a client that
  sends headers and then never sends the body keeps the
  single-threaded accept loop blocked indefinitely (compounding
  BUG-5). See BUG-12. (G9.)

The remaining gates split into smaller P2-COSMETIC / P2-MISSING
findings (no notification detection BUG-10/-11, no
`Transfer-Encoding: chunked` BUG-20, multiple-Authorization-header
silently picks first BUG-19, HTTP/1.0 silently accepted BUG-18,
"Content-Type" required check missing BUG-16, basic-auth header
not trimmed of trailing whitespace BUG-17 a) — see the table.

## Methodology

1. Read Core HTTP server (`httpserver.cpp/h`) + JSON-RPC dispatcher
   (`httprpc.cpp`) + cookie generation (`rpc/request.cpp`) + the
   canonical rpcauth.py salt+HMAC script.
2. Built a 30-gate matrix covering: HTTP server lifecycle (start /
   stop / bind / threadpool / timeout), auth (Basic / cookie /
   rpcauth / whitelist / rpcallowip), HTTP status & headers (status
   mapping, reason phrase, WWW-Authenticate, Content-Type,
   Connection), JSON-RPC dispatch (single / batch / notification /
   v2-detection / id-echo / method-not-found), and DoS surface
   (timing-resistant compare, brute-force sleep, max body, max
   headers, max batch, concurrent worker pool).
3. Classified each gate against `rpc.zig` + `main.zig` source.
4. Catalogued 21 BUGs (3 P0-SEC, 8 P1, 9 P2, 1 PRESENT-by-design).
5. Wrote `src/tests_w140_http_rpcauth.zig` (XFAIL-style) +
   `test-w140` build step.

## 30-gate matrix

| Gate | Description | Core ref | Status in clearbit | Verdict |
|------|-------------|----------|---------------------|---------|
| **HTTP server lifecycle** | | | | |
| G1 | Plain TCP `accept()` loop is the HTTP server (no libevent) | `httpserver.cpp:298-306` (libevent) | hand-rolled `RpcServer.run()` (`rpc.zig:1504-1528`) with `std.net.Address.listen` + `accept()` serial loop | **DIVERGE PRESENT — design choice; documents as PRESENT-by-design via test** |
| G2 | `start()` validates config and binds before accepting | `httpserver.cpp:382-426` (`InitHTTPServer`) | `RpcServer.start` (`rpc.zig:1395-1402`) calls `validateTlsConfig`, parses bind, listens; matches | **PRESENT** |
| **Authentication** | | | | |
| G3 | Constant-time string compare on credentials | `httprpc.cpp:66, 77` (`TimingResistantEqual`); `strencodings.h:202-210` | `std.mem.eql(u8, provided, t)` (`rpc.zig:1641-1644`) — early-exits on first differing byte | **MISSING — BUG-1 P0-SEC** |
| G4 | `-rpcauth=<user>:<salt>$<hash>` HMAC-SHA-256 path | `httprpc.cpp:290-304` + `rpcauth.py` + `init.cpp:707` | No `-rpcauth=` flag, no HMAC-SHA-256 helper, no salt store; only plaintext `--rpcuser/--rpcpassword` (`main.zig:232-235`) | **MISSING — BUG-4 P0-SEC** |
| G5 | `-rpccookiefile=<path>` + `-rpccookieperms=owner|group|all` | `init.cpp:710-711`; `rpc/request.cpp:86-95, 130-136` | Hardcoded `<datadir>/.cookie` (`main.zig:805`); only mode 0o600 on creat — no perms flag, no path flag | **MISSING — BUG-2 P1-MISSING** |
| G6 | Cookie file written atomically via `.cookie.tmp` → rename | `rpc/request.cpp:113-127` (`RenameOver`) | Direct write to `<datadir>/.cookie` (`main.zig:786-819`) — no temp file, no rename | **MISSING — BUG-3 P1-RACE** |
| G7 | `-rpcallowip=<cidr>` CIDR allow-list applied per connection | `httpserver.cpp:137-145, 148-168, 217-222` (`ClientAllowed`); `init.cpp:706` | NO check on peer address anywhere in `handleConnection`; `rpc_bind` controls interface only | **MISSING — BUG-7 P0-SEC (W124 BUG-13 re-anchored)** |
| **Anti-DoS / Anti-brute-force** | | | | |
| G8 | 250 ms `UninterruptibleSleep` after failed auth | `httprpc.cpp:125-128` | Immediate 401 reply; no delay | **MISSING — BUG-8 P1-SEC** |
| G9 | `-rpcservertimeout=<sec>` (default 30s) | `httpserver.cpp:408`; `init.cpp:714` | No timeout on `conn.stream.read()`; slow-client wedges single-threaded accept loop indefinitely | **MISSING — BUG-12 P2-DOS** |
| G10 | `-rpcthreads=<n>` worker pool (default 16) | `httpserver.cpp:78, 440-444`; `init.cpp:715` | Single-threaded `accept → handle → accept` serial loop | **MISSING — BUG-5 P2-DOS** |
| G11 | `-rpcwhitelist=<user>:<m1>,<m2>` per-user method ACL | `httprpc.cpp:144-191, 306-326`; `init.cpp:717-718` | No whitelist infrastructure; all-or-nothing | **MISSING — BUG-6 P1-MISSING** |
| G12 | `-rpcworkqueue=<n>` overload signal (HTTP 503) | `httpserver.cpp:79, 255-258, 419-420` | No work queue; cannot signal overload | **MISSING — BUG-5 P2-DOS (same root cause as G10)** |
| **HTTP status / headers** | | | | |
| G13 | `WWW-Authenticate: Basic realm="jsonrpc"` on 401 | `httprpc.cpp:33, 114, 130` | `sendHttpError(s, 401, "Unauthorized")` emits only `Content-Length: 0` + `Connection: close` (`rpc.zig:1714-1719`) | **MISSING — BUG-9 P1-SEC (RFC-7235 violation)** |
| G14 | REST `/rest/...` endpoints gated by `-rest=1` (default 0) | `init.cpp:705` (`-rest`); REST registered via `RegisterHTTPHandler` conditional in init | REST always-on; routed at `rpc.zig:1573-1578` before any flag check; AND bypasses auth (which is design-parity with Core) | **MISSING (`-rest` gate) — BUG-15 P1-MISSING (G25); auth-bypass design-parity (covered under G7)** |
| **JSON-RPC dispatch** | | | | |
| G15 | Empty-batch `[]` returns `RPC_INVALID_REQUEST` AND HTTP 400 | `httprpc.cpp:220-223` (HTTP 204 for all-notification non-empty batch; 400 for invalid) | Empty batch returns RPC error code -32600 ("Empty batch request") but HTTP 200 (`rpc.zig:3180-3182` → `jsonRpcError` → `sendHttpResponse(200)`) | **PARTIAL — error code OK, HTTP status wrong** (BUG-18 anchor; G15 is BUG-10 also for "no 204 for all-notification batch") |
| G16 | Notification (no `id` / `id == null`) returns HTTP 204 No Content | `httprpc.cpp:167-171` (`IsNotification` → `HTTP_NO_CONTENT`) | `handleSingleRequest` always emits full response with `"id":null`; no 204 path | **MISSING — BUG-11 P2-MISSING** |
| G17 | Max headers size enforced (Core: 8192 bytes; clearbit: 65536 implicit) | `httpserver.cpp:51, 409` (`MAX_HEADERS_SIZE = 8192`) | 64 KiB fixed buf for entire request (headers + initial body fragment); silent close on overflow without `\r\n\r\n` | **DIVERGE — BUG-13 P2-DOS (size differs, error path silent close vs 413)** |
| G18 | Error code → HTTP status mapping (RPC_INVALID_REQUEST → 400, RPC_METHOD_NOT_FOUND → 404, else → 500) | `httprpc.cpp:46-58` (JSONErrorReply) | All responses HTTP 200 regardless of error code (`rpc.zig:1722-1728` hardcodes "OK" + caller always passes 200) | **MISSING — BUG-18 P1-CDIV (W125 BUG-15+17 re-anchor)** |
| G19 | Reason phrase reflects status (e.g. "Bad Request") | `httpserver.cpp` libevent default | `sendHttpResponse` always emits "OK" regardless of status (`rpc.zig:1725`); `sendRestResponse` has a 3-entry switch only (`rpc.zig:1734-1739`) | **MISSING — BUG-16 P2-COSMETIC (W125 BUG-16 re-anchor)** |
| G20 | Content-Type: application/json on success replies | libevent default + `httprpc.cpp:228` | `sendHttpResponse` emits `application/json` always (`rpc.zig:1725`); `sendHttpError` emits NO Content-Type at all (`rpc.zig:1717`) | **PARTIAL — BUG-22 P2-COSMETIC** |
| G21 | JSON-RPC 2.0 detection from request `jsonrpc` field, reply shape | `rpc/request.cpp:213-230` + `JSONRPCReplyObj` | No `jsonrpc` read; always legacy 1.0 shape `{"result","error","id"}` | **MISSING — BUG-21 P1-COMPAT (W125 BUG-18 re-anchor)** |
| G22 | Error `message` JSON-escaped | UniValue auto-escapes | `jsonRpcError` printf `%s` (`rpc.zig:13645`); `writeJsonValue .string` no escaping (`rpc.zig:14613-14617`) | **MISSING — BUG-23 P2-SECURITY (W125 BUG-19 re-anchor)** |
| **REST + Wallet path routing** | | | | |
| G23 | `/wallet/<name>` POST routing to wallet-targeted RPC | `httprpc.cpp:339-341` (RegisterHTTPHandler "/wallet/", exactMatch=false) | `getTargetWallet(url_path)` (`rpc.zig:1610`) routes /wallet/<name>; matches Core | **PRESENT** |
| G24 | HTTPS termination (TLS server primitive) | `httpserver.cpp` libevent + OpenSSL when configured; Core actually has no native HTTPS — operators front with nginx/Caddy | `validateTlsConfig` returns `TlsServerUnavailable` if both `--rpc-tls-cert` + `--rpc-tls-key` set (FIX-64 deferral; `rpc.zig:220-228`) — design-parity with Core | **DEFERRED-by-design (BUG-14 P2-DEFERRED; tracked since W119 / FIX-64)** |
| G25 | `-rest=<0|1>` flag gates REST endpoint registration | `init.cpp:705` | No `--rest` flag; REST endpoints always-on (`main.zig` arg parser has no entry) | **MISSING — BUG-15 P1-MISSING** |
| **Edge cases / robustness** | | | | |
| G26 | HTTP/1.0 vs HTTP/1.1 version handling | libevent handles | Version is part of request line but never parsed; "HTTP/1.0", "HTTP/1.1", "HTTP/2.0" all silently treated identically (no version field in any reply check) | **MISSING — BUG-20 P2-COSMETIC** |
| G27 | Multiple `Authorization` headers — first wins | evhttp `evhttp_find_header` returns first | `findHeader` (`rpc.zig:14448-14462`) `splitSequence("\r\n")` returns first match — matches Core | **PRESENT** |
| G28 | `Transfer-Encoding: chunked` support | libevent supports | No chunked decoder; missing Content-Length → 400 (`rpc.zig:1650-1652`); chunked request silently 400 | **MISSING — BUG-20 P2-COMPAT** |
| G29 | `Connection: close` on every reply (no keep-alive reuse) | libevent default for HTTP/1.0 + when explicitly set | clearbit explicitly emits `Connection: close` on every reply (`rpc.zig:1717, 1725, 1740`) — matches Core's default operational model | **PRESENT-by-design** |
| G30 | Dead-helper sweep — config fields documented but inert | n/a | `payjoin_endpoint`, `payjoin_sessions`, `ibd_latched_off` are wired (NOT dead). `tls_cert_path` / `tls_key_path` are deliberately inert as flag-plumbing-only — design-parity. No genuine dead helper found in HTTP scope. | **PRESENT-by-design** |

## BUG catalogue (21 unique BUGs)

### P0-SEC (3)

1. **BUG-1 (G3) — Authentication compares with `std.mem.eql`, not
   constant-time.** `rpc.zig:1641-1644`.  Core: `TimingResistantEqual`
   (`strencodings.h:202-210`).  Patch sketch: add `pub fn
   timingResistantEqual(a, b: []const u8) bool` that XORs every byte
   into an accumulator and returns `accumulator == 0`, then swap both
   `eql` call sites.

2. **BUG-4 (G4) — No `-rpcauth=<user>:<salt>$<hash>` HMAC-SHA-256
   path.** No call sites, no constants.  Core: `httprpc.cpp:62-82,
   290-304` + `rpcauth.py`.  Patch sketch: add `parseRpcAuthSpec(spec)
   → (user, salt, hash_hex)`, store as `std.ArrayList(RpcAuthEntry)`
   on `RpcConfig`, replace `auth_token` check with a loop over
   entries computing `HMAC-SHA-256(salt, password)` and
   timing-comparing against `hash`.  Add `--rpcauth=` to
   `main.zig:parseArgs`. Allow `share/rpcauth/rpcauth.py` output to
   work.

3. **BUG-7 (G7) — No `-rpcallowip=<cidr>` CIDR allow-list.**
   `RpcServer.handleConnection` (`rpc.zig:1531`) does not consult
   `conn.address`.  Core: `httpserver.cpp:137-145, 148-168, 217-222`.
   Patch sketch: parse `--rpcallowip` (repeatable) into a list of
   `SubNet { addr, mask }` at startup, default-add 127.0.0.0/8 + ::1,
   then add `if (!isClientAllowed(conn.address, &self.allow_subnets))`
   gate before any other handling, reply with HTTP 403. **Re-anchored
   from W124 BUG-13.**

### P1 (8)

4. **BUG-2 (G5) — No `-rpccookiefile=<path>` / `-rpccookieperms`
   flags.** `main.zig:805` hardcodes `<datadir>/.cookie`.  Core:
   `init.cpp:710-711`, `rpc/request.cpp:86-95, 130-136`.  Patch:
   add `--rpccookiefile=`, `--rpccookieperms=owner|group|all` to
   parseArgs; honour them in `generateCookieFile`.

5. **BUG-3 (G6) — Cookie file written non-atomically.**
   `main.zig:786-819` writes directly to `.cookie`.  Core uses
   `.cookie.tmp` → `RenameOver` (`rpc/request.cpp:113-127`).  Patch:
   `createFileAbsolute(tmp_path, .{ .mode=0o600 })`, write, close,
   then `std.fs.renameAbsolute(tmp_path, final_path)`.

6. **BUG-5 (G10 + G12) — Single-threaded accept loop, no worker
   pool, no overload signal.**  `rpc.zig:1504-1528`.  Core:
   `httpserver.cpp:78, 255-258, 440-444`.  Patch (large): spawn a
   worker-pool thread on `--rpcthreads`, push accepted connections
   into a bounded channel of depth `--rpcworkqueue`, reply HTTP 503
   when queue full.  Substantial refactor; tracked as design follow-up.

7. **BUG-6 (G11) — No `-rpcwhitelist=<user>:<m1>,<m2>` per-user
   method ACL.**  No infrastructure.  Core: `httprpc.cpp:144-191,
   306-326`.  Patch: per-user `std.StringHashMap(StringSet)` populated
   from `--rpcwhitelist`; consult in `handleSingleRequest` after
   resolving `authUser` (which we currently don't track — see
   BUG-26 below).

8. **BUG-8 (G8) — No 250 ms sleep after failed auth.**  Patch: on
   401 from the BUG-1 fix, `std.time.sleep(std.time.ns_per_ms * 250)`
   BEFORE replying.

9. **BUG-9 (G13) — `WWW-Authenticate: Basic realm="jsonrpc"` missing
   on 401.**  RFC-7235 violation.  Patch: extend `sendHttpError` to
   take an optional `extra_headers` parameter or add a dedicated
   `sendHttpUnauthorized` helper.

10. **BUG-15 (G25) — `--rest=<0|1>` flag missing; REST always-on.**
    Patch: `--rest=0|1` (default 0 per Core); guard `if
    (is_get and std.mem.startsWith(u8, url_path, "/rest/")) and
    self.config.rest_enabled` (`rpc.zig:1573-1578`).

11. **BUG-18 (G18) — All HTTP responses are 200 OK regardless of
    JSON-RPC error code.** Re-anchored from W125 BUG-15+17.  Patch:
    map `RPC_INVALID_REQUEST → 400`, `RPC_METHOD_NOT_FOUND → 404`,
    everything else (including `RPC_INVALID_PARAMS`, application
    errors) → 500 per Core; thread the chosen status from
    `dispatch()` / `handleSingleRequest()` back to `handleConnection`.

12. **BUG-21 (G21) — No JSON-RPC 2.0 detection / 2.0-shape reply.**
    Re-anchored from W125 BUG-18.  Patch: read `"jsonrpc"` in
    `handleSingleRequest`, store on a per-request struct, branch
    `jsonRpcResult` / `jsonRpcError` on the version.

### P2 (9)

13. **BUG-10 (G15) — Empty batch and all-notification batch behaviour
    diverges.**  Empty batch already returns -32600 (good) but HTTP
    200 (BUG-18 covers status).  All-notification non-empty batch
    should return HTTP 204 No Content per Core; clearbit currently
    returns the array of responses with `"id":null`.

14. **BUG-11 (G16) — Notification (request with no `id`) returns full
    response with `"id":null` instead of HTTP 204 No Content.** Per
    JSON-RPC 2.0 spec + Core `httprpc.cpp:167-171`.

15. **BUG-12 (G9) — No request-read timeout.**  Patch: `setsockopt
    SO_RCVTIMEO` to 30s default.  Required for BUG-5 worker-pool
    semantics anyway.

16. **BUG-13 (G17) — Fixed 65536-byte stack buffer for header+body
    prefix; overflow without `\r\n\r\n` silently closes connection
    instead of HTTP 413/414.**  `rpc.zig:1535`.

17. **BUG-14 (G24) — HTTPS/TLS server primitive DEFERRED**
    (Zig 0.13 stdlib gap; FIX-64).  Operators front with
    nginx/Caddy/Tor.  Status: design-parity with Core, but tracked
    so the field is not forgotten.

18. **BUG-16 (G19) — Reason phrase on `sendHttpResponse` always
    "OK".** Re-anchored from W125 BUG-16.  Cosmetic — visible only
    when an operator inspects raw HTTP with `curl -v`.

19. **BUG-19 (G27 incidental) — first-Authorization-header-wins is
    by design, but no documentation; revisit if multi-auth-header
    rules change.**  Currently `findHeader` (`rpc.zig:14448-14462`)
    returns the first match; CONFIRMED matches Core.  Leaving as
    PRESENT — no fix.

20. **BUG-20 (G26 + G28) — HTTP version field silently ignored;
    `Transfer-Encoding: chunked` silently treated as missing
    Content-Length.** Joint cosmetic / compat bug.  Patch sketch
    for chunked: detect `Transfer-Encoding: chunked` header and
    reject with HTTP 411 Length Required if Content-Length is also
    absent OR add a chunked decoder.

21. **BUG-22 (G20) — `sendHttpError` emits no `Content-Type`
    header.** `rpc.zig:1714-1719`.  Cosmetic; most clients tolerate.

22. **BUG-23 (G22) — Error `"message"` and JSON `"id"` string values
    are not JSON-escaped.** Re-anchored from W125 BUG-19.
    P2-SECURITY: client passing a method name with embedded `"` /
    `\` / control chars can break the JSON response shape, possibly
    confusing parser-tolerant clients.

### NEW finding not in W124/W125

23. **BUG-26 (no gate) — `authUser` not tracked per request, so
    `-rpcwhitelist` (BUG-6) is structurally impossible without
    refactor.**  Core's `JSONRPCRequest::authUser` is populated by
    `RPCAuthorized` (`httprpc.cpp:84-102`); clearbit's
    `handleConnection` never decodes the base64 to recover the user
    name.  Required prerequisite for BUG-6.  Logged here as the
    structural blocker.

## Top 5 BUGs to fix first (recommended order)

1. **BUG-1 (P0-SEC, G3) — constant-time auth compare.**
   Most surgical — one tiny helper + two call-sites — and closes
   the most immediate timing-attack vector.

2. **BUG-7 (P0-SEC, G7) — `-rpcallowip` CIDR allow-list.**
   Restores Core's default localhost-only posture and closes the
   "rpc_bind=0.0.0.0" foot-gun. **Re-anchored from W124 BUG-13;
   has been catalogued for over a month — overdue.**

3. **BUG-4 (P0-SEC, G4) — `-rpcauth` HMAC-SHA-256 path.**
   Unlocks the standard production deployment posture (rpcauth.py
   output drops in); eliminates the plaintext-credentials-on-disk
   ask for multi-user setups.

4. **BUG-9 (P1-SEC, G13) — `WWW-Authenticate: Basic
   realm="jsonrpc"` on 401.**  RFC-7235 fix; one extra header line
   in `sendHttpError`'s 401 path; high leverage for client
   compatibility.

5. **BUG-18 (P1-CDIV, G18) — HTTP status mapping.**
   Re-anchored from W125 BUG-15+17.  Threads through
   `handleSingleRequest` → `handleConnection` to emit 400 / 404 /
   500 / 200 per Core; needed for any HTTP-status-aware client
   ecosystem (load balancers, monitoring exporters, Prometheus
   blackbox).

## Out of scope (carry-forward / explicit non-coverage)

- **Full multi-threaded worker pool (BUG-5).** Substantial refactor
  (~600-1000 LOC across rpc.zig + a new threadpool module).
  Tracked as design follow-up; orthogonal to the auth+status fixes.
- **`Transfer-Encoding: chunked` decoder (BUG-20).** Niche compat
  — most clients send Content-Length; document the gap, reject
  with 411 instead of silent 400 for honesty.
- **HTTPS/TLS server primitive (BUG-14).** Tracked since FIX-64;
  blocked on Zig stdlib gap or C-dep ratification.

## Tests

`src/tests_w140_http_rpcauth.zig` (XFAIL-style, zero RpcServer
construction so no rocksdb dependency — pure constant + helper
guards). 30 gates → roughly 30-32 test fns. Run with
`zig build test-w140`.

References (Core)
-----------------

- `bitcoin-core/src/httpserver.cpp` (HTTPBindAddresses,
  http_request_cb, ClientAllowed, InitHTTPAllowList, ThreadHTTP,
  WriteReply).
- `bitcoin-core/src/httpserver.h` (DEFAULT_HTTP_THREADS=16,
  DEFAULT_HTTP_WORKQUEUE=64, DEFAULT_HTTP_SERVER_TIMEOUT=30).
- `bitcoin-core/src/httprpc.cpp` (JSONErrorReply, CheckUserAuthorized,
  RPCAuthorized, HTTPReq_JSONRPC, InitRPCAuthentication,
  StartHTTPRPC).
- `bitcoin-core/src/rpc/request.cpp` (COOKIEAUTH_USER, COOKIEAUTH_FILE,
  GetAuthCookieFile, GenerateAuthCookie, GetAuthCookie,
  DeleteAuthCookie, JSONRPCRequest::parse).
- `bitcoin-core/src/util/strencodings.h:202-210` (TimingResistantEqual).
- `bitcoin-core/share/rpcauth/rpcauth.py` (canonical user / salt /
  HMAC-SHA-256 helper).
- `bitcoin-core/src/init.cpp:706-720` (-rpcallowip, -rpcauth,
  -rpcbind, -rpccookiefile, -rpccookieperms, -rpcpassword, -rpcport,
  -rpcservertimeout, -rpcthreads, -rpcuser, -rpcwhitelist,
  -rpcwhitelistdefault, -rpcworkqueue, -server).
