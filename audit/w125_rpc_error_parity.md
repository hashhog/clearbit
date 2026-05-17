# W125 — JSON-RPC error code parity (clearbit)

**Date:** 2026-05-17
**Scope:** clearbit's `RpcServer` JSON-RPC error wire-format vs Bitcoin Core's
`RPCErrorCode` enum (`bitcoin-core/src/rpc/protocol.h`).
**Mode:** DISCOVERY (no production code changes; XFAIL guards only).
**Test step:** `zig build test-w125` (46 tests, folded into `zig build test`).

## Summary

Discovery wave catalogues clearbit's RPC error wire-format gaps. The constant
table itself is mostly intact — 25 of Core's 40 `RPCErrorCode` values are
defined verbatim and used at least once. The gaps are not at the numeric layer
but at the **mapping** layer:

- Several Core wire-codes are simply **not defined** (`RPC_METHOD_DEPRECATED`,
  the four `RPC_CLIENT_NODE_*` codes, `RPC_WALLET_ALREADY_LOADED/EXISTS`,
  `RPC_CLIENT_INVALID_IP_OR_SUBNET`, etc.).
- Several **are** defined but their natural call site emits a different code
  (`addnode add` returns `-1` instead of `-23`; `disconnectnode` returns
  `-32602` instead of `-29`; `loadwallet already-loaded` returns `-4` instead
  of `-35`; etc.).
- The **HTTP status layer** below the JSON envelope is wholly absent —
  clearbit emits `HTTP/1.1 200 OK` for every JSON-RPC body, where Core maps
  `RPC_INVALID_REQUEST` to `HTTP 400`, `RPC_METHOD_NOT_FOUND` to `HTTP 404`,
  and everything else to `HTTP 500` (`bitcoin-core/src/httprpc.cpp:50-53`).
- The **JSON-RPC 2.0 reply shape** is also absent — clearbit always emits
  both `"result"` and `"error"` fields together (one null), never reads the
  request's `"jsonrpc"` field, and never includes `"jsonrpc"` in replies.

| Verdict | Gates | Notes |
|---|---|---|
| PRESENT | 14 | Core-equal numeric values + at least one call site |
| PARTIAL | 4   | Constant defined but call-site coverage incomplete or absent |
| MISSING | 12 | Wire-code not defined OR call site uses wrong code |

**Bug count: 20** (P0=0 / HIGH=12 / MED=4 / LOW=2 / COSMETIC=2).
No consensus-divergent bugs; all impacts are **client compatibility / wire
format**. Wallet-aware tools (`bitcoin-cli`, `electrum`, RPC libraries) that
key off the numeric `error.code` will misclassify clearbit's errors.

## Gates

### Standard JSON-RPC 2.0 codes (-32700 .. -32603)

| Gate | Code | Core | clearbit | Status |
|---|---|---|---|---|
| G1 | `RPC_PARSE_ERROR` | -32700 | -32700, raised on JSON parse fail (rpc.zig:2912) | PRESENT |
| G2 | `RPC_INVALID_REQUEST` | -32600 | -32600, raised on shape errors (rpc.zig:2925-3198) | PRESENT |
| G3 | `RPC_METHOD_NOT_FOUND` | -32601 | -32601, raised on unknown method (rpc.zig:3170) | PRESENT |
| G4 | `RPC_INVALID_PARAMS` | -32602 | -32602, raised 241× across the file | PRESENT |
| G5 | `RPC_INTERNAL_ERROR` | -32603 | -32603, raised 66× | PRESENT |

### General application errors (-1 .. -28)

| Gate | Code | Core | clearbit | Status |
|---|---|---|---|---|
| G6 | All -1..-26 standard codes | various | All defined verbatim | PRESENT |
| G7 | `RPC_VERIFY_ALREADY_IN_UTXO_SET` | -27 | -27 as `RPC_VERIFY_ALREADY_IN_CHAIN` (legacy alias name) | **PARTIAL — BUG-1** |
| G8 | `RPC_IN_WARMUP` | -28 | Constant defined but never raised (no warmup latch on server) | **PARTIAL — BUG-2 HIGH** |
| G9 | `RPC_METHOD_DEPRECATED` | -32 | Constant MISSING; `prioritisetransaction` dummy uses -8 (rpc.zig:4696-4707) | **MISSING — BUG-3 HIGH** |

### P2P client errors (-9 .. -34)

| Gate | Code | Core | clearbit | Status |
|---|---|---|---|---|
| G10 | `RPC_CLIENT_NOT_CONNECTED` | -9 | MISSING | **MISSING — BUG-4 HIGH** |
| G11 | `RPC_CLIENT_IN_INITIAL_DOWNLOAD` | -10 | MISSING; `loadmempool` doesn't gate on IBD (rpc.zig:4862-4867) | **MISSING — BUG-5 HIGH** |
| G12 | `RPC_CLIENT_NODE_ALREADY_ADDED` | -23 | MISSING; `addnode add` uses -1 RPC_MISC_ERROR (rpc.zig:10484) | **MISSING — BUG-6 HIGH** |
| G13 | `RPC_CLIENT_NODE_NOT_ADDED` | -24 | MISSING; `addnode remove` silently succeeds (rpc.zig:10488) | **MISSING — BUG-7 HIGH** |
| G14 | `RPC_CLIENT_NODE_NOT_CONNECTED` | -29 | MISSING; `disconnectnode` uses -32602 (rpc.zig:10546) | **MISSING — BUG-8 HIGH** |
| G15 | `RPC_CLIENT_INVALID_IP_OR_SUBNET` | -30 | MISSING; `setban`, `addnode` use -32602 (rpc.zig:4934, 10500) | **MISSING — BUG-9 HIGH** |
| G16 | `RPC_CLIENT_P2P_DISABLED` (-31), `RPC_CLIENT_MEMPOOL_DISABLED` (-33), `RPC_CLIENT_NODE_CAPACITY_REACHED` (-34) | various | All three MISSING (no runtime disable-toggle today, but constants needed when it lands) | **MISSING — BUG-10 LOW** |

### Wallet errors (-4 .. -19, -35, -36)

| Gate | Code | Core | clearbit | Status |
|---|---|---|---|---|
| G17 | `RPC_WALLET_ERROR` | -4 | -4 (rpc.zig:103) | PRESENT |
| G18 | `RPC_WALLET_INSUFFICIENT_FUNDS` | -6 | -6 (rpc.zig:104) | PRESENT |
| G19 | `RPC_WALLET_INVALID_LABEL_NAME` | -11 | MISSING; `setlabel` doesn't validate at all | **MISSING — BUG-11 MED** |
| G20 | -12, -13, -14, -15, -16, -17 | Core values | All defined; called from passphrase + encryption paths | PRESENT |
| G21 | `RPC_WALLET_NOT_FOUND`, `RPC_WALLET_NOT_SPECIFIED` | -18, -19 | Both defined and raised | PRESENT |
| G22 | `RPC_WALLET_ALREADY_LOADED` | -35 | MISSING; `loadwallet` already-loaded uses -4 (rpc.zig:5104-5105) | **MISSING — BUG-12 HIGH** |
| G23 | `RPC_WALLET_ALREADY_EXISTS` | -36 | MISSING; `createwallet` exists uses -4 (rpc.zig:5071-5072) | **MISSING — BUG-13 HIGH** |
| G24 | `RPC_WALLET_INVALID_ACCOUNT_NAME` alias | -11 | MISSING (back-compat alias) | **MISSING — BUG-14 LOW** |

### Transport layer (HTTP status code mapping)

| Gate | Behaviour | Core | clearbit | Status |
|---|---|---|---|---|
| G25 | `RPC_INVALID_REQUEST` → HTTP 400 | httprpc.cpp:50-51 | Always HTTP 200 (rpc.zig:1725) | **MISSING — BUG-15 HIGH** |
| G26 | HTTP reason-phrase ("Bad Request", "Not Found", "Internal Server Error") | httprpc.cpp default reply mech | All replies hardcode "OK" regardless of status (rpc.zig:1725) | **MISSING — BUG-16 COSMETIC** |
| G27 | `RPC_METHOD_NOT_FOUND` → HTTP 404 | httprpc.cpp:52-53 | HTTP 200 (rpc.zig:1725) | **MISSING — BUG-17 HIGH** |

### Protocol / wire-shape

| Gate | Behaviour | Core | clearbit | Status |
|---|---|---|---|---|
| G28 | JSON-RPC 2.0 detection from request `"jsonrpc"` field; v2 reply omits `"result"` on error and sets `"jsonrpc":"2.0"` | request.cpp:218-228 + JSONRPCReplyObj | Always legacy 1.0 shape; no version field read or emitted; both `result` and `error` always emitted together (rpc.zig:13627-13649) | **MISSING — BUG-18 MED** |
| G29 | Error `"message"` string JSON-escaped (`"`, `\`, control chars) | UniValue auto-escapes | Raw `%s` printf in jsonRpcError (rpc.zig:13645); same for writeJsonValue .string variant (14613-14617) | **MISSING — BUG-19 MED-SECURITY** |
| G30 | Dead-helper sweep — `RPC_FORBIDDEN_BY_SAFE_MODE` defined and never raised | protocol.h:88-89 documents as inert | Mirrors Core; intentionally inert | PRESENT-by-design (BUG-20 P2-COSMETIC tag for documentation only) |

## Bug catalogue (sorted by severity)

### HIGH-COMPAT (12 bugs)

1. **BUG-2 (G8)** — `RPC_IN_WARMUP` defined, never raised. Operators can't tell
   "RPC initialising" from "RPC genuinely failed". Fix: latch
   `fRPCInWarmup`-equivalent on the server, gate every dispatch through it,
   raise -28 with the current warmup-status string.

2. **BUG-3 (G9)** — `RPC_METHOD_DEPRECATED` (-32) MISSING. `prioritisetransaction`
   dummy-arg emits -8 RPC_INVALID_PARAMETER (rpc.zig:4696-4707). Fix: define
   the constant; emit -32 for the dummy.

3. **BUG-4 (G10)** — `RPC_CLIENT_NOT_CONNECTED` (-9) MISSING. Wire-protocol
   gap; `getblocktemplate` cannot signal "no peers" the way Core does.

4. **BUG-5 (G11)** — `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10) MISSING.
   `loadmempool` doesn't gate on IBD; emits -32603 on failure. Fix: define
   constant; gate `loadmempool` start on `isInitialBlockDownload()`.

5. **BUG-6 (G12)** — `RPC_CLIENT_NODE_ALREADY_ADDED` (-23) MISSING. `addnode
   add` for an already-added node emits -1 (rpc.zig:10484). Fix: define
   constant; emit -23 with Core's message string.

6. **BUG-7 (G13)** — `RPC_CLIENT_NODE_NOT_ADDED` (-24) MISSING. `addnode
   remove` for a never-added node SILENTLY SUCCEEDS (rpc.zig:10488). Fix:
   surface -24.

7. **BUG-8 (G14)** — `RPC_CLIENT_NODE_NOT_CONNECTED` (-29) MISSING.
   `disconnectnode` emits -32602 (rpc.zig:10546). Fix: emit -29.

8. **BUG-9 (G15)** — `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30) MISSING.
   `setban` (rpc.zig:4934, 4950, 4954, 4980) and `addnode onetry`
   (rpc.zig:10500) use -32602. rpc.zig:10497 EVEN ACKNOWLEDGES "Core does
   the same — `LookupHost` failure surfaces as RPC_CLIENT_INVALID_IP_OR_
   SUBNET" but the next line still emits -32602.

9. **BUG-12 (G22)** — `RPC_WALLET_ALREADY_LOADED` (-35) MISSING.
   `loadwallet` already-loaded emits -4 (rpc.zig:5104-5105). Wallet clients
   that auto-handle "already loaded" by code can't.

10. **BUG-13 (G23)** — `RPC_WALLET_ALREADY_EXISTS` (-36) MISSING.
    `createwallet` already-exists emits -4 (rpc.zig:5071-5072).

11. **BUG-15 (G25)** — `RPC_INVALID_REQUEST` → HTTP 200 (Core: 400).
    Transport-layer divergence; `bitcoin-cli`-style clients can't
    distinguish "malformed request" from "valid request returning data".

12. **BUG-17 (G27)** — `RPC_METHOD_NOT_FOUND` → HTTP 200 (Core: 404).
    Same class as BUG-15; clients can't distinguish "RPC missing" from
    "RPC returning structured error".

### MED-COMPAT / MED-SECURITY (4 bugs)

13. **BUG-11 (G19)** — `RPC_WALLET_INVALID_LABEL_NAME` (-11) MISSING.
    `setlabel` doesn't validate. Fix: add label-length / charset validation;
    raise -11 on violation.

14. **BUG-18 (G28)** — JSON-RPC 2.0 reply shape MISSING. Strict 2.0 clients
    reject clearbit's `{"result":null,"error":{...},"id":1}` shape — 2.0
    spec mandates `{"jsonrpc":"2.0","error":{...},"id":1}` with `result`
    OMITTED when `error` is present. Fix: parse `"jsonrpc"` field from
    request; branch reply shape on detected version.

15. **BUG-19 (G29) MED-SECURITY** — Error `"message"` not JSON-escaped.
    `jsonRpcError` uses raw `%s` (rpc.zig:13645); `writeJsonValue` .string
    variant likewise no escape (14613-14617). A wallet name, filesystem
    path, or `@errorName(err)` containing `"` or `\` MALFORMS the JSON
    wire. Severity: not exploitable for code-exec, but corrupts the
    transport, masks the real error code, and could be turned into a
    response-splitting parlor trick if the message is operator-controlled.

16. **BUG-1 (G7)** — `RPC_VERIFY_ALREADY_IN_UTXO_SET` MISSING as alias.
    Core renamed `RPC_VERIFY_ALREADY_IN_CHAIN` upstream; clearbit kept the
    legacy name. Same wire-value (-27); cosmetic for grep parity with
    bitcoin-core/src/.

### LOW-COMPAT (2 bugs)

17. **BUG-10 (G16)** — `RPC_CLIENT_P2P_DISABLED` (-31), `RPC_CLIENT_MEMPOOL_DISABLED`
    (-33), `RPC_CLIENT_NODE_CAPACITY_REACHED` (-34) MISSING. clearbit can't
    runtime-disable P2P/mempool subsystems today; constants will be needed
    once that toggle lands.

18. **BUG-14 (G24)** — `RPC_WALLET_INVALID_ACCOUNT_NAME` back-compat alias
    MISSING. Only relevant if BUG-11 is fixed.

### P2-COSMETIC (2 bugs)

19. **BUG-16 (G26)** — HTTP reason phrase always says "OK" even for 4xx/5xx
    (rpc.zig:1725 `"HTTP/1.1 {d} OK"`).

20. **BUG-20 (G30)** — `RPC_FORBIDDEN_BY_SAFE_MODE` (-2) defined, never
    raised. Mirrors Core's intentional dead-helper-by-design. No fix
    required; gate documents the deliberate inert status.

## Universal patterns observed

- **"Comment-as-confession"** (rpc.zig:10493-10497) — handler comment
  acknowledges Core uses -30 RPC_CLIENT_INVALID_IP_OR_SUBNET for the same
  case, but the very next code line emits -32602 anyway. Continues the
  pattern catalogued in earlier waves (FIX-58/FIX-72 et al.).

- **"Defined-but-never-raised"** (RPC_IN_WARMUP, RPC_FORBIDDEN_BY_SAFE_MODE,
  arguably RPC_VERIFY_ALREADY_IN_CHAIN — never used outside one site) —
  continues the multi-wave "dead-helper" pattern fleet-wide (now ~34 waves
  per the audit memory). RPC_FORBIDDEN_BY_SAFE_MODE is dead-by-design
  matching Core; RPC_IN_WARMUP is dead-by-omission of the latch.

- **"Constants defined, call site uses wrong one"** — six high-COMPAT bugs
  (BUG-6/7/8/9/12/13) follow the same shape: the constant is either
  trivially addable (one `pub const` line) or already present; the divergence
  is purely at the call site. Single fix wave could close all six.

- **"Transport divergence below the JSON envelope"** — the entire HTTP
  status mapping (G25/G26/G27) plus the JSON-RPC 2.0 reply shape (G28)
  are missing. Distinct from numeric-code parity; one helper
  (`httpStatusFromRpcCode(code: i32) u16`) + one dispatcher hook for
  reading `"jsonrpc"` from the request closes the architectural gap.

- **"Audit ahead of fix"** — the rpc.zig:10493-10497 comment shows the
  *correct* behaviour was known at write-time but not implemented. Single
  bookkeeping fix wave (FIX-86 or similar) could close 5-6 BUGs by
  upgrading the existing call sites to the constants the comments already
  reference.

## Suggested follow-up

- **FIX-86 (universal RPC error-code constants):** add the 9 missing
  constants (`RPC_METHOD_DEPRECATED`, six `RPC_CLIENT_NODE_*`,
  `RPC_WALLET_ALREADY_LOADED`, `RPC_WALLET_ALREADY_EXISTS`,
  `RPC_WALLET_INVALID_LABEL_NAME` + alias) and re-route the existing call
  sites identified in the bug table.

- **FIX-87 (HTTP status mapping):** add `httpStatusFromRpcCode()` helper;
  call it from `sendHttpResponse` after parsing the JSON body's
  `error.code` (or pass through from the dispatcher).

- **FIX-88 (JSON escape on error path):** add a small `escapeJsonString`
  helper; wrap `jsonRpcError`'s message arg and `writeJsonValue`'s string
  variant. MED-SECURITY priority.

- **FIX-89 (RPC_IN_WARMUP latch):** add a warmup state-machine matching
  Core's `SetRPCWarmupStatus` / `SetRPCWarmupFinished` semantics; gate
  every dispatch.

- **FIX-90 (JSON-RPC 2.0 envelope):** detect `"jsonrpc":"2.0"` in the
  request; branch reply shape accordingly. MED-COMPAT; needs careful
  test coverage because the 1.0 shape is also valid (Core supports
  both — see httprpc.cpp:44 `Assume(jreq.m_json_version != JSONRPCVersion::V2)`).

## Test wiring

- **File:** `src/tests_w125_error_parity.zig` (46 tests).
- **Step:** `zig build test-w125`.
- **Filter:** `--test-filter "w125"`.
- **Folds into:** `zig build test` (line 1235 of `build.zig`).

XFAIL style: each BUG-N test asserts the current (buggy) state. When a fix
flips the corresponding gate from MISSING/PARTIAL → PRESENT, the test will
fail to compile (because `@hasDecl` flips) or its assertion will fire — the
next audit can then advance the gate's verdict and re-anchor the XFAIL.
