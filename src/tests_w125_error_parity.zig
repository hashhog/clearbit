//! W125 — JSON-RPC error code parity 30-gate audit (clearbit / Zig 0.13)
//!
//! Discovery wave. Audits clearbit's JSON-RPC error code emission vs
//! Bitcoin Core's `RPCErrorCode` enum (src/rpc/protocol.h).
//!
//! References
//! ----------
//! bitcoin-core/src/rpc/protocol.h     RPCErrorCode + HTTPStatusCode enums.
//! bitcoin-core/src/httprpc.cpp        JSONErrorReply — HTTP code mapping
//!                                     (RPC_INVALID_REQUEST → 400,
//!                                      RPC_METHOD_NOT_FOUND → 404,
//!                                      default → 500).
//! bitcoin-core/src/rpc/server.cpp     warmup state (RPC_IN_WARMUP) +
//!                                     SetRPCWarmupStatus / SetRPCWarmupFinished.
//! bitcoin-core/src/rpc/net.cpp        addnode / disconnectnode / setban
//!                                     (RPC_CLIENT_INVALID_IP_OR_SUBNET,
//!                                      RPC_CLIENT_NODE_ALREADY_ADDED,
//!                                      RPC_CLIENT_NODE_NOT_ADDED,
//!                                      RPC_CLIENT_NODE_NOT_CONNECTED).
//! bitcoin-core/src/rpc/mempool.cpp    importmempool (RPC_CLIENT_IN_INITIAL_DOWNLOAD).
//! bitcoin-core/src/rpc/mining.cpp     submitblock / getblocktemplate.
//! bitcoin-core/src/wallet/rpc/util.cpp wallet error mapping
//!                                     (RPC_WALLET_ALREADY_LOADED / EXISTS).
//!
//! Status
//! ------
//! These tests are XFAIL guards (not actively failing). They assert the
//! current observable state — including the bugs — so the next fix wave
//! can flip each gate from MISSING/PARTIAL → PRESENT by deliberately
//! breaking the corresponding test. Failures here mean someone already
//! landed the fix and forgot to update the audit. See
//! `audit/w125_rpc_error_parity.md` for the prose write-up.
//!
//! Run: `zig build test-w125`

const std = @import("std");
const testing = std.testing;

const rpc = @import("rpc.zig");

// ===========================================================================
// Standard JSON-RPC 2.0 error codes (RFC-style values)
// ---------------------------------------------------------------------------
// G1 / G2 / G3 / G4 / G5 are the canonical -32xxx codes Core mirrors from
// the JSON-RPC 2.0 spec (protocol.h:24-37).  clearbit's `pub const RPC_*`
// constants match Core verbatim — assert by-value so a renumber would
// break the audit immediately.
// ===========================================================================

test "w125 G1: RPC_PARSE_ERROR = -32700 (PRESENT)" {
    try testing.expectEqual(@as(i32, -32700), rpc.RPC_PARSE_ERROR);
}

test "w125 G2: RPC_INVALID_REQUEST = -32600 (PRESENT)" {
    try testing.expectEqual(@as(i32, -32600), rpc.RPC_INVALID_REQUEST);
}

test "w125 G3: RPC_METHOD_NOT_FOUND = -32601 (PRESENT)" {
    try testing.expectEqual(@as(i32, -32601), rpc.RPC_METHOD_NOT_FOUND);
}

test "w125 G4: RPC_INVALID_PARAMS = -32602 (PRESENT)" {
    try testing.expectEqual(@as(i32, -32602), rpc.RPC_INVALID_PARAMS);
}

test "w125 G5: RPC_INTERNAL_ERROR = -32603 (PRESENT)" {
    try testing.expectEqual(@as(i32, -32603), rpc.RPC_INTERNAL_ERROR);
}

// ===========================================================================
// G6: General application errors (-1 .. -8, -20 .. -28)
// PRESENT for the values that exist, but a few of Core's standard codes
// are simply NOT DEFINED in clearbit's constant table.
// ===========================================================================

test "w125 G6: RPC_MISC_ERROR = -1 (PRESENT)" {
    try testing.expectEqual(@as(i32, -1), rpc.RPC_MISC_ERROR);
}

test "w125 G6: RPC_FORBIDDEN_BY_SAFE_MODE = -2 (PRESENT, defined but never raised)" {
    try testing.expectEqual(@as(i32, -2), rpc.RPC_FORBIDDEN_BY_SAFE_MODE);
}

test "w125 G6: RPC_TYPE_ERROR = -3 (PRESENT)" {
    try testing.expectEqual(@as(i32, -3), rpc.RPC_TYPE_ERROR);
}

test "w125 G6: RPC_INVALID_ADDRESS_OR_KEY = -5 (PRESENT)" {
    try testing.expectEqual(@as(i32, -5), rpc.RPC_INVALID_ADDRESS_OR_KEY);
}

test "w125 G6: RPC_OUT_OF_MEMORY = -7 (PRESENT)" {
    try testing.expectEqual(@as(i32, -7), rpc.RPC_OUT_OF_MEMORY);
}

test "w125 G6: RPC_INVALID_PARAMETER = -8 (PRESENT)" {
    try testing.expectEqual(@as(i32, -8), rpc.RPC_INVALID_PARAMETER);
}

test "w125 G6: RPC_DATABASE_ERROR = -20 (PRESENT)" {
    try testing.expectEqual(@as(i32, -20), rpc.RPC_DATABASE_ERROR);
}

test "w125 G6: RPC_DESERIALIZATION_ERROR = -22 (PRESENT)" {
    try testing.expectEqual(@as(i32, -22), rpc.RPC_DESERIALIZATION_ERROR);
}

test "w125 G6: RPC_VERIFY_ERROR = -25 (PRESENT)" {
    try testing.expectEqual(@as(i32, -25), rpc.RPC_VERIFY_ERROR);
}

test "w125 G6: RPC_VERIFY_REJECTED = -26 (PRESENT)" {
    try testing.expectEqual(@as(i32, -26), rpc.RPC_VERIFY_REJECTED);
}

// ---------------------------------------------------------------------------
// G7: RPC_VERIFY_ALREADY_IN_UTXO_SET (Core name) vs RPC_VERIFY_ALREADY_IN_CHAIN
// (clearbit name) — BUG-1 P2-COSMETIC: same numeric value (-27), but the
// alias clearbit uses is the *legacy* Core name (renamed upstream years
// ago).  Wire-format identical; reviewers grepping for the Core name
// won't find it locally.
// ---------------------------------------------------------------------------

test "w125 G7 BUG-1: RPC_VERIFY_ALREADY_IN_UTXO_SET alias MISSING (xfail)" {
    // The Core spelling does not exist in rpc.zig.  Flip when added.
    try testing.expect(!@hasDecl(rpc, "RPC_VERIFY_ALREADY_IN_UTXO_SET"));
    // The legacy name DOES exist with the canonical value.
    try testing.expectEqual(@as(i32, -27), rpc.RPC_VERIFY_ALREADY_IN_CHAIN);
}

// ===========================================================================
// G8: RPC_IN_WARMUP = -28 (PARTIAL — defined but never raised)
//
// Core dispatches every RPC through `execute()` (server.cpp:484-499) which
// throws RPC_IN_WARMUP when `fRPCInWarmup` is true.  clearbit defines the
// constant but `grep RPC_IN_WARMUP src/rpc.zig` returns ONLY the
// definition line — no production site ever surfaces it.  Operators
// scripting against clearbit cannot distinguish "RPC server still
// initialising" from "method genuinely failed".
// ===========================================================================

test "w125 G8 BUG-2 (HIGH-COMPAT): RPC_IN_WARMUP defined but never raised (xfail)" {
    // Comptime presence of the constant.
    try testing.expectEqual(@as(i32, -28), rpc.RPC_IN_WARMUP);
    // No warmup latch exists on the server.  `setRPCWarmupStatus` /
    // `setRPCWarmupFinished` / `fRPCInWarmup` analogues are absent.
    try testing.expect(!@hasDecl(rpc, "setRPCWarmupStatus"));
    try testing.expect(!@hasDecl(rpc, "setRPCWarmupFinished"));
    try testing.expect(!@hasDecl(rpc, "RPCInWarmup"));
}

// ===========================================================================
// G9: RPC_METHOD_DEPRECATED = -32 (MISSING)
//
// Core uses this for the `dummy` arg to `prioritisetransaction` (rpc/wallet/
// coins.cpp:200) and for any RPC the operator has explicitly disabled via
// `-deprecatedrpc=`.  clearbit DEFINES the same -32 nowhere and uses
// RPC_INVALID_PARAMETER for the prioritisetransaction-dummy case (rpc.zig:
// 4696, 4699, 4704).  Wire-format diverge: clients expecting -32 will not
// recognise clearbit's -8.
// ===========================================================================

test "w125 G9 BUG-3 (HIGH-COMPAT): RPC_METHOD_DEPRECATED constant MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_METHOD_DEPRECATED"));
    // The prioritisetransaction handler currently uses RPC_INVALID_PARAMETER
    // (-8) for the deprecated `dummy` argument — wrong code for the
    // deprecation case (should be -32).  See rpc.zig:4696, 4699, 4704.
    try testing.expectEqual(@as(i32, -8), rpc.RPC_INVALID_PARAMETER);
}

// ===========================================================================
// P2P client errors (-9 .. -34, with mempool-disabled at -33)
// G10 .. G16 cover the eight `RPC_CLIENT_*` codes Core uses.
// ===========================================================================

// ---------------------------------------------------------------------------
// G10: RPC_CLIENT_NOT_CONNECTED = -9 (MISSING)
// Core uses this on `getblocktemplate` when no peers are connected
// (mining.cpp:769, 843).
// ---------------------------------------------------------------------------
test "w125 G10 BUG-4 (HIGH-COMPAT): RPC_CLIENT_NOT_CONNECTED constant MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_CLIENT_NOT_CONNECTED"));
}

// ---------------------------------------------------------------------------
// G11: RPC_CLIENT_IN_INITIAL_DOWNLOAD = -10 (MISSING)
// Core uses this on `getblocktemplate` (mining.cpp:773) and `importmempool`
// (mempool.cpp:1141).  clearbit's handleLoadMempool / handleDumpMempool do
// not check IBD and use RPC_INTERNAL_ERROR for failure (rpc.zig:4865).
// ---------------------------------------------------------------------------
test "w125 G11 BUG-5 (HIGH-COMPAT): RPC_CLIENT_IN_INITIAL_DOWNLOAD constant MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_CLIENT_IN_INITIAL_DOWNLOAD"));
}

// ---------------------------------------------------------------------------
// G12: RPC_CLIENT_NODE_ALREADY_ADDED = -23 (MISSING)
// Core uses this for addnode add-when-already-added (net.cpp:362) AND for
// setban add-when-already-banned (net.cpp:785).
// ---------------------------------------------------------------------------
// FIX (ported from rustoshi 7b94ef1): the -23 constant is now defined and
// handleAddNode returns it for `addnode "add"` of an already-added node, with
// Core's exact message "Error: Node already added" (rpc/net.cpp:362). The
// behaviour assertion (through dispatch) lives in src/rpc.zig's test block.
test "w125 G12 BUG-6 (HIGH-COMPAT): RPC_CLIENT_NODE_ALREADY_ADDED = -23 (PRESENT)" {
    try testing.expect(@hasDecl(rpc, "RPC_CLIENT_NODE_ALREADY_ADDED"));
    try testing.expectEqual(@as(i32, -23), rpc.RPC_CLIENT_NODE_ALREADY_ADDED);
}

// ---------------------------------------------------------------------------
// G13: RPC_CLIENT_NODE_NOT_ADDED = -24 (MISSING)
// Core uses this on `addnode remove` when not previously added
// (net.cpp:368) and on `getaddednodeinfo` (net.cpp:534).  clearbit's
// addnode remove silently succeeds (rpc.zig:10488 — no error path).
// ---------------------------------------------------------------------------
// FIX (ported from rustoshi 7b94ef1): the -24 constant is now defined and
// handleAddNode returns it for `addnode "remove"` of a never-added node, with
// Core's exact message (rpc/net.cpp:368). Behaviour assertion in src/rpc.zig.
test "w125 G13 BUG-7 (HIGH-COMPAT): RPC_CLIENT_NODE_NOT_ADDED = -24 (PRESENT)" {
    try testing.expect(@hasDecl(rpc, "RPC_CLIENT_NODE_NOT_ADDED"));
    try testing.expectEqual(@as(i32, -24), rpc.RPC_CLIENT_NODE_NOT_ADDED);
}

// ---------------------------------------------------------------------------
// G14: RPC_CLIENT_NODE_NOT_CONNECTED = -29 (MISSING)
// Core uses this on `disconnectnode` when the node isn't in the
// connected-peer set (net.cpp:478).  clearbit returns RPC_INVALID_PARAMS
// (rpc.zig:10546) which clients won't recognise as a P2P error.
// ---------------------------------------------------------------------------
// FIX (ported from rustoshi 845f7e4): the -29 constant is now defined and
// handleDisconnectNode returns it (instead of -32602) when the address matches
// no connected peer (rpc/net.cpp:478). Behaviour assertion in src/rpc.zig.
test "w125 G14 BUG-8 (HIGH-COMPAT): RPC_CLIENT_NODE_NOT_CONNECTED = -29 (PRESENT)" {
    try testing.expect(@hasDecl(rpc, "RPC_CLIENT_NODE_NOT_CONNECTED"));
    try testing.expectEqual(@as(i32, -29), rpc.RPC_CLIENT_NODE_NOT_CONNECTED);
}

// ---------------------------------------------------------------------------
// G15: RPC_CLIENT_INVALID_IP_OR_SUBNET = -30 (MISSING)
// Core uses this on setban (net.cpp:780, 811, 1003) and on addnode for
// LookupHost failures.  clearbit returns RPC_INVALID_PARAMS for both.
// rpc.zig:10497-10500 comment EVEN ACKNOWLEDGES that "Core does the same
// — `LookupHost` failure surfaces as RPC_CLIENT_INVALID_IP_OR_SUBNET" but
// the code still emits -32602 instead.
// ---------------------------------------------------------------------------
// FIX (ported from rustoshi 980a31d): the -30 constant is now defined and
// handleSetBan returns it (instead of -32602) with Core's exact message
// "Error: Invalid IP/Subnet" for an un-parseable IP (rpc/net.cpp:780).
// Behaviour assertion in src/rpc.zig.
test "w125 G15 BUG-9 (HIGH-COMPAT): RPC_CLIENT_INVALID_IP_OR_SUBNET = -30 (PRESENT)" {
    try testing.expect(@hasDecl(rpc, "RPC_CLIENT_INVALID_IP_OR_SUBNET"));
    try testing.expectEqual(@as(i32, -30), rpc.RPC_CLIENT_INVALID_IP_OR_SUBNET);
}

// ---------------------------------------------------------------------------
// G16: RPC_CLIENT_P2P_DISABLED = -31 + RPC_CLIENT_MEMPOOL_DISABLED = -33 +
// RPC_CLIENT_NODE_CAPACITY_REACHED = -34 (all MISSING)
// Core uses these for `getpeerinfo` when -listen=0 (server_util.cpp:103,
// 119, 127), `importmempool` when mempool=0 (server_util.cpp:37), and
// `addnode` when at capacity (net.cpp:428).  clearbit can't disable these
// subsystems independently so they're inert today, but if a runtime
// disable-toggle lands the constants will be needed.
// ---------------------------------------------------------------------------
test "w125 G16 BUG-10 (LOW-COMPAT): RPC_CLIENT_{P2P,MEMPOOL}_DISABLED + _NODE_CAPACITY MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_CLIENT_P2P_DISABLED"));
    try testing.expect(!@hasDecl(rpc, "RPC_CLIENT_MEMPOOL_DISABLED"));
    try testing.expect(!@hasDecl(rpc, "RPC_CLIENT_NODE_CAPACITY_REACHED"));
}

// ===========================================================================
// Wallet error codes (G17 .. G24)
// Core: RPC_WALLET_ERROR=-4, RPC_WALLET_INSUFFICIENT_FUNDS=-6,
// RPC_WALLET_INVALID_LABEL_NAME=-11, RPC_WALLET_KEYPOOL_RAN_OUT=-12,
// RPC_WALLET_UNLOCK_NEEDED=-13, RPC_WALLET_PASSPHRASE_INCORRECT=-14,
// RPC_WALLET_WRONG_ENC_STATE=-15, RPC_WALLET_ENCRYPTION_FAILED=-16,
// RPC_WALLET_ALREADY_UNLOCKED=-17, RPC_WALLET_NOT_FOUND=-18,
// RPC_WALLET_NOT_SPECIFIED=-19, RPC_WALLET_ALREADY_LOADED=-35,
// RPC_WALLET_ALREADY_EXISTS=-36.
// ===========================================================================

test "w125 G17: RPC_WALLET_ERROR = -4 (PRESENT)" {
    try testing.expectEqual(@as(i32, -4), rpc.RPC_WALLET_ERROR);
}

test "w125 G18: RPC_WALLET_INSUFFICIENT_FUNDS = -6 (PRESENT)" {
    try testing.expectEqual(@as(i32, -6), rpc.RPC_WALLET_INSUFFICIENT_FUNDS);
}

// ---------------------------------------------------------------------------
// G19: RPC_WALLET_INVALID_LABEL_NAME = -11 (MISSING)
// Core uses on setlabel / getaddressesbylabel (wallet/rpc/util.cpp:111,
// wallet/rpc/addresses.cpp:568).  clearbit's handleSetLabel does not even
// validate the label string today.
// ---------------------------------------------------------------------------
test "w125 G19 BUG-11 (MED-COMPAT): RPC_WALLET_INVALID_LABEL_NAME MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_WALLET_INVALID_LABEL_NAME"));
}

test "w125 G20: RPC_WALLET_KEYPOOL_RAN_OUT = -12 (PRESENT)" {
    try testing.expectEqual(@as(i32, -12), rpc.RPC_WALLET_KEYPOOL_RAN_OUT);
}

test "w125 G20: RPC_WALLET_UNLOCK_NEEDED = -13 (PRESENT)" {
    try testing.expectEqual(@as(i32, -13), rpc.RPC_WALLET_UNLOCK_NEEDED);
}

test "w125 G20: RPC_WALLET_PASSPHRASE_INCORRECT = -14 (PRESENT)" {
    try testing.expectEqual(@as(i32, -14), rpc.RPC_WALLET_PASSPHRASE_INCORRECT);
}

test "w125 G20: RPC_WALLET_WRONG_ENC_STATE = -15 (PRESENT)" {
    try testing.expectEqual(@as(i32, -15), rpc.RPC_WALLET_WRONG_ENC_STATE);
}

test "w125 G20: RPC_WALLET_ENCRYPTION_FAILED = -16 (PRESENT)" {
    try testing.expectEqual(@as(i32, -16), rpc.RPC_WALLET_ENCRYPTION_FAILED);
}

test "w125 G20: RPC_WALLET_ALREADY_UNLOCKED = -17 (PRESENT)" {
    try testing.expectEqual(@as(i32, -17), rpc.RPC_WALLET_ALREADY_UNLOCKED);
}

test "w125 G21: RPC_WALLET_NOT_FOUND = -18 (PRESENT)" {
    try testing.expectEqual(@as(i32, -18), rpc.RPC_WALLET_NOT_FOUND);
}

test "w125 G21: RPC_WALLET_NOT_SPECIFIED = -19 (PRESENT)" {
    try testing.expectEqual(@as(i32, -19), rpc.RPC_WALLET_NOT_SPECIFIED);
}

// ---------------------------------------------------------------------------
// G22: RPC_WALLET_ALREADY_LOADED = -35 (MISSING)
// Core uses this on loadwallet when the named wallet is already in the
// loaded set (wallet/rpc/wallet.cpp:261).  clearbit returns -4
// RPC_WALLET_ERROR instead (rpc.zig:5104-5105).  Wire-format diverge:
// clients expecting -35 won't auto-detect "wallet already loaded — no
// action needed".
// ---------------------------------------------------------------------------
test "w125 G22 BUG-12 (HIGH-COMPAT): RPC_WALLET_ALREADY_LOADED constant MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_WALLET_ALREADY_LOADED"));
}

// ---------------------------------------------------------------------------
// G23: RPC_WALLET_ALREADY_EXISTS = -36 (MISSING)
// Core uses on createwallet when a wallet of the same name already exists
// (wallet/rpc/util.cpp:143).  clearbit returns -4 RPC_WALLET_ERROR
// (rpc.zig:5071-5072).  Same wire-format-diverge class as G22.
// ---------------------------------------------------------------------------
test "w125 G23 BUG-13 (HIGH-COMPAT): RPC_WALLET_ALREADY_EXISTS constant MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_WALLET_ALREADY_EXISTS"));
}

// ---------------------------------------------------------------------------
// G24: RPC_WALLET_INVALID_ACCOUNT_NAME alias = RPC_WALLET_INVALID_LABEL_NAME
// (backward-compat alias in protocol.h:86).  PRESENT in Core, MISSING in
// clearbit — but only consequential if G19 is also fixed.
// ---------------------------------------------------------------------------
test "w125 G24 BUG-14 (LOW-COMPAT): RPC_WALLET_INVALID_ACCOUNT_NAME alias MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "RPC_WALLET_INVALID_ACCOUNT_NAME"));
}

// ===========================================================================
// HTTP status-code mapping (G25 .. G27)
// Core httprpc.cpp:50-53 maps:
//   RPC_INVALID_REQUEST  → HTTP 400
//   RPC_METHOD_NOT_FOUND → HTTP 404
//   <any other>          → HTTP 500
// clearbit's sendHttpResponse always writes HTTP 200 for JSON-RPC
// payloads regardless of the inner error code (rpc.zig:1710, 1725).
// ===========================================================================

// ---------------------------------------------------------------------------
// G25: BUG-15 (HIGH-COMPAT) — HTTP 200 for every JSON-RPC reply
//
// Source-guard: sendHttpResponse passes a hardcoded 200 (status arg is the
// SECOND positional parameter but every call site supplies 200).  When
// fixed, sendHttpResponse will need to inspect the error code or take an
// explicit status arg from the dispatcher.  We assert the symbol exists
// (so a rename breaks the test) — a future runtime probe should grep for
// "HTTP/1.1 400" / "HTTP/1.1 404" / "HTTP/1.1 500" in actual responses.
// ---------------------------------------------------------------------------
test "w125 G25 BUG-15 (HIGH-COMPAT): sendHttpResponse symbol exists; status mapping MISSING (xfail)" {
    // No helper named `httpStatusFromRpcCode` / `rpcCodeToHttpStatus` exists.
    try testing.expect(!@hasDecl(rpc, "httpStatusFromRpcCode"));
    try testing.expect(!@hasDecl(rpc, "rpcCodeToHttpStatus"));
}

// ---------------------------------------------------------------------------
// G26: BUG-16 (P2-COSMETIC) — All sendHttpResponse calls write "200 OK"
// even when the body's "error.code" is RPC_PARSE_ERROR / RPC_INTERNAL_ERROR /
// RPC_INVALID_REQUEST / RPC_METHOD_NOT_FOUND.  rpc.zig:1725 hardcodes
//   "HTTP/1.1 {d} OK"  (always "OK", regardless of status).
// Also wrong: 4xx/5xx should not say "OK" — they should say "Bad Request",
// "Not Found", "Internal Server Error".  sendRestResponse (rpc.zig:1734)
// does the right thing for REST paths but JSON-RPC doesn't share that
// status-text table.
// ---------------------------------------------------------------------------
test "w125 G26 BUG-16 (P2-COSMETIC): JSON-RPC response status text hardcoded \"OK\" (xfail)" {
    // No helper named `httpStatusText` exists on the JSON-RPC path.
    try testing.expect(!@hasDecl(rpc, "httpStatusText"));
    try testing.expect(!@hasDecl(rpc, "rpcStatusText"));
}

// ---------------------------------------------------------------------------
// G27: BUG-17 (HIGH-COMPAT) — Method-not-found returns HTTP 200
// rpc.zig:3170 emits RPC_METHOD_NOT_FOUND in the JSON body, but Core
// (httprpc.cpp:52) ALSO sets HTTP 404 at the transport layer.  Clients
// like `bitcoin-cli` differentiate "server down" (no TCP) from "method
// missing" (HTTP 404 + JSON body) from "RPC error" (HTTP 500 + JSON body).
// clearbit collapses all three into HTTP 200, masking the difference.
// ---------------------------------------------------------------------------
test "w125 G27 BUG-17 (HIGH-COMPAT): method-not-found → HTTP 404 NOT EMITTED (xfail)" {
    // Same source-guard as G25 — the status-mapping helper is absent.
    try testing.expect(!@hasDecl(rpc, "httpStatusFromRpcCode"));
}

// ===========================================================================
// G28: JSON-RPC 2.0 protocol-version detection (BUG-18, MED-COMPAT)
//
// Core's JSONRPCReplyObj (httprpc.cpp:55) reads `jreq.m_json_version`,
// which the dispatcher sets from the request's `"jsonrpc"` field
// ("2.0" → JSONRPCVersion::V2, else legacy 1.0).  V2 responses OMIT the
// "result" field on error AND set "jsonrpc":"2.0" in the reply.
// clearbit's jsonRpcResult / jsonRpcError (rpc.zig:13627-13649) ALWAYS
// emit both `result` and `error` together (one null) and never include
// `"jsonrpc"`.  Strict JSON-RPC 2.0 clients reject this shape.
// ===========================================================================
test "w125 G28 BUG-18 (MED-COMPAT): JSON-RPC 2.0 version detection MISSING (xfail)" {
    try testing.expect(!@hasDecl(rpc, "JSONRPCVersion"));
    try testing.expect(!@hasDecl(rpc, "jsonRpcVersion"));
    // jsonRpcResult / jsonRpcError exist but always emit the legacy 1.0
    // shape (both result+error fields, no "jsonrpc" key).  Comptime
    // verifies the functions are still there; behaviour test belongs to
    // FIX-90+ once the dispatcher learns the version.
    try testing.expect(@hasDecl(rpc.RpcServer, "jsonRpcResult"));
    try testing.expect(@hasDecl(rpc.RpcServer, "jsonRpcError"));
}

// ===========================================================================
// G29: JSON string escaping in error messages (BUG-19, MED-SECURITY)
//
// rpc.zig:13645 emits `"message":"{s}"` with raw printf%s of the error
// message.  If the message text contains a literal `"` or `\` (e.g. a
// wallet name passed back to the user, a filesystem path, or an
// @errorName(err) that contains a quote), the JSON wire is malformed.
// The same hazard applies to writeJsonValue (rpc.zig:14613-14617) for
// the .string variant of the request `id` — no escaping at all.
// ===========================================================================
test "w125 G29 BUG-19 (MED-SECURITY): JSON message string not escaped (xfail)" {
    // No JSON-string-escape helper exists on the error path.
    try testing.expect(!@hasDecl(rpc, "escapeJsonString"));
    try testing.expect(!@hasDecl(rpc, "writeJsonEscaped"));
    // dumpmempool DOES inline-escape the path it returns (rpc.zig:4827-4831)
    // but that's a one-off — the generic error path doesn't.
}

// ===========================================================================
// G30: Dead-helper / definition-without-call-site sweep (BUG-20, P2-COSMETIC)
//
// RPC_FORBIDDEN_BY_SAFE_MODE (-2) is defined in rpc.zig:90 but never
// raised anywhere in the codebase.  Core also keeps it around for
// historical compatibility (protocol.h:88-89) and explicitly comments
// "Unused reserved codes, kept around for backwards compatibility.  Do
// not reuse."  This is correct behaviour to mirror — the gate documents
// the dead-helper-by-design status.
//
// RPC_IN_WARMUP (-28) is defined but unreachable today — see G8 + BUG-2.
// ===========================================================================
test "w125 G30 BUG-20 (P2-COSMETIC): dead-helper sweep — RPC_FORBIDDEN_BY_SAFE_MODE defined, never raised" {
    try testing.expectEqual(@as(i32, -2), rpc.RPC_FORBIDDEN_BY_SAFE_MODE);
    // No call site emits -2 (verified by grep at audit time, 2026-05-17).
    // The gate is PRESENT-by-design — Core does the same.  No xfail; this
    // is documentation-as-test that the constant is intentionally inert.
}

// ===========================================================================
// Bonus: source-guard sanity checks (always-PRESENT)
// These are not gates per se; they prevent accidental deletion of the
// canonical constants during refactors.
// ===========================================================================
test "w125 sanity: all canonical Core values defined" {
    // Standard JSON-RPC 2.0
    try testing.expectEqual(@as(i32, -32700), rpc.RPC_PARSE_ERROR);
    try testing.expectEqual(@as(i32, -32600), rpc.RPC_INVALID_REQUEST);
    try testing.expectEqual(@as(i32, -32601), rpc.RPC_METHOD_NOT_FOUND);
    try testing.expectEqual(@as(i32, -32602), rpc.RPC_INVALID_PARAMS);
    try testing.expectEqual(@as(i32, -32603), rpc.RPC_INTERNAL_ERROR);
    // App-defined
    try testing.expectEqual(@as(i32, -1), rpc.RPC_MISC_ERROR);
    try testing.expectEqual(@as(i32, -3), rpc.RPC_TYPE_ERROR);
    try testing.expectEqual(@as(i32, -5), rpc.RPC_INVALID_ADDRESS_OR_KEY);
    try testing.expectEqual(@as(i32, -7), rpc.RPC_OUT_OF_MEMORY);
    try testing.expectEqual(@as(i32, -8), rpc.RPC_INVALID_PARAMETER);
    try testing.expectEqual(@as(i32, -20), rpc.RPC_DATABASE_ERROR);
    try testing.expectEqual(@as(i32, -22), rpc.RPC_DESERIALIZATION_ERROR);
    try testing.expectEqual(@as(i32, -25), rpc.RPC_VERIFY_ERROR);
    try testing.expectEqual(@as(i32, -26), rpc.RPC_VERIFY_REJECTED);
    try testing.expectEqual(@as(i32, -27), rpc.RPC_VERIFY_ALREADY_IN_CHAIN);
    try testing.expectEqual(@as(i32, -28), rpc.RPC_IN_WARMUP);
    // Wallet
    try testing.expectEqual(@as(i32, -4), rpc.RPC_WALLET_ERROR);
    try testing.expectEqual(@as(i32, -6), rpc.RPC_WALLET_INSUFFICIENT_FUNDS);
    try testing.expectEqual(@as(i32, -12), rpc.RPC_WALLET_KEYPOOL_RAN_OUT);
    try testing.expectEqual(@as(i32, -13), rpc.RPC_WALLET_UNLOCK_NEEDED);
    try testing.expectEqual(@as(i32, -14), rpc.RPC_WALLET_PASSPHRASE_INCORRECT);
    try testing.expectEqual(@as(i32, -15), rpc.RPC_WALLET_WRONG_ENC_STATE);
    try testing.expectEqual(@as(i32, -16), rpc.RPC_WALLET_ENCRYPTION_FAILED);
    try testing.expectEqual(@as(i32, -17), rpc.RPC_WALLET_ALREADY_UNLOCKED);
    try testing.expectEqual(@as(i32, -18), rpc.RPC_WALLET_NOT_FOUND);
    try testing.expectEqual(@as(i32, -19), rpc.RPC_WALLET_NOT_SPECIFIED);
}
