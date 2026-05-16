//! W119 BIP-78 PayJoin audit — clearbit (Zig 0.13)
//!
//! 30-gate fleet audit of BIP-78 PayJoin (Pay to EndPoint) coverage.
//! Spec: bips/bip-0078.mediawiki + payjoin.org + btcpayserver/payjoin.
//! Bitcoin Core has NO PayJoin, so reference vectors come from the BIP-78
//! spec and the BTCPayServer reference implementation.
//!
//! Status: 10/10 MISSING ENTIRELY. clearbit has zero PayJoin code:
//!   - No `payjoin`, `BIP-78`, `pj=`, `pjos`, `original-psbt-rejected` strings.
//!   - No HTTP/TLS server for receiver endpoint (RPC HTTP exists but is JSON-RPC).
//!   - No BIP-21 URI parser (cannot extract `pj=` / `pjos=` params).
//!   - No `getpayjoinrequest` / `sendpayjoinrequest` RPCs.
//!   - No Original-PSBT validation rules (anti-snoop check set).
//!   - No fee-output substitution logic on the receiver side.
//!
//! However, the PRIMITIVES needed for a future PayJoin implementation are
//! mostly already present (FIX-59 encrypted wallet, FIX-60 `getBalanceMinConf`,
//! FIX-61 `bumpFee` + `psbtBumpFee` + BIP-125 `0xFFFFFFFD` RBF sequence,
//! W47 PSBT v0 + W118 partial v2). What is missing is:
//!   1. A receiver HTTP endpoint (a non-JSON-RPC server that speaks
//!      `application/payjoin-psbt` and `application/json` errors).
//!   2. A BIP-21 URI parser (needed to extract `pj=` and `pjos=` query params).
//!   3. The sender anti-snoop validator (the most subtle correctness piece).
//!
//! 30-gate spec (cross-impl parity — DO NOT renumber):
//!   G1  receiver HTTP endpoint
//!   G2  sender HTTP client
//!   G3  TLS-or-onion transport
//!   G4  Original-PSBT deserialize
//!   G5  receiver-side Original-PSBT validation
//!   G6  fee-output identification
//!   G7  receiver adds inputs
//!   G8  receiver modifies output
//!   G9  receiver fee adjustment
//!   G10 sender anti-snoop on outputs
//!   G11 sender scriptSig-type preservation
//!   G12 sender "no new sender inputs" check
//!   G13 sender maxadditionalfeecontribution honored
//!   G14 sender disableoutputsubstitution honored
//!   G15 sender minfeerate floor
//!   G16 query-parameter parser (`v`, `additionalfeeoutputindex`, …)
//!   G17 4 BIP-78 error codes
//!   G18 receiver TTL on issued Originals
//!   G19 receiver no-double-spend safeguard
//!   G20 receiver UTXO anti-fingerprint
//!   G21 v=1 version-pin header
//!   G22 sender fallback to broadcast Original on receiver failure
//!   G23 receiver Content-Type negotiation
//!   G24 HTTPS certificate validation
//!   G25 Tor `.onion` endpoint support
//!   G26 `getpayjoinrequest` RPC
//!   G27 `sendpayjoinrequest` RPC
//!   G28 BIP-21 `pj=` extraction
//!   G29 BIP-21 `pjos=` extraction
//!   G30 receiver replay protection
//!
//! Bug findings: see `tests_w119_payjoin.zig`-prefixed BUG comments in this
//! file. 15 distinct bugs are documented (the entire BIP-78 surface is
//! missing; bugs are grouped by what is absent at each gate, not by
//! sub-correctness flaws inside an existing implementation).
//!
//! Cross-cutting with FIX-59 / FIX-60 / FIX-61:
//!   - FIX-59 AES-256-GCM + scrypt encrypted wallet is REUSED in PayJoin
//!     signing path (receiver's `signInput` over its newly-added UTXOs must
//!     respect the same passphrase-unlock TTL semantics).
//!   - FIX-61 `BIP125_RBF_SEQUENCE = 0xFFFFFFFD` is REUSED for the PayJoin
//!     output (BIP-78 strongly encourages opt-in RBF on the final tx).
//!   - FIX-61 `bumpFee` shares the "re-sign every input after structural
//!     change" pattern with PayJoin's sender anti-snoop sign-after-add step.
//!   - FIX-60 `getBalanceMinConf` is REUSED as the receiver's UTXO selector
//!     constraint (BIP-78 §"Implementation Suggestions" recommends only
//!     spending inputs that match the sender's confirmation profile to
//!     reduce fingerprinting).
//!
//! Run with `zig build test-w119`.

const std = @import("std");
const testing = std.testing;

const wallet_mod = @import("wallet.zig");
const psbt_mod = @import("psbt.zig");
const rpc_mod = @import("rpc.zig");
const address_mod = @import("address.zig");

// ===========================================================================
// G1: Receiver HTTP endpoint — CLOSED in FIX-65 (foundation, plain HTTP)
//
// FIX-65 adds `PayjoinHandler` (namespace with deserialize / validate /
// build-proposal / format-error helpers) and `RpcServer.handlePayjoinRequest`
// — the `POST /payjoin?v=1&...` route, reachable on the existing JSON-RPC
// HTTP server's port.  Plain HTTP only: BIP-78 §"Receiver's transport
// security" requires HTTPS or .onion in production, but FIX-64 deferred
// server-side TLS (Zig 0.13 stdlib has no Server.zig).  Operators MUST
// front the route with nginx / Caddy / Tor before exposure — same posture
// as Bitcoin Core's own HTTP server.  Test coverage:
// `src/tests_fix65_payjoin_receiver.zig` (`zig build test-fix65`).
//
// BUG-1 (HIGH) — original audit text retained for cross-impl traceability:
//   BIP-78 requires the receiver to publish an HTTPS or .onion endpoint
//   that accepts an Original PSBT via POST and returns a PayJoin Proposal
//   PSBT.  clearbit had only the JSON-RPC HTTP server in src/rpc.zig with
//   no `/payjoin` route.
//
// We deliberately do NOT add `PayjoinServer` / `payjoinServer` /
// `startPayjoinServer` as separate decls — the route lives on the
// existing `RpcServer` (named `handlePayjoinRequest` per BUG-1's enum),
// and adding stub aliases would just sprawl the API surface.  Future
// fix waves layer a sender HTTP client (G2) + Implementation Suggestions
// (G18/G19/G20/G30) on top of this foundation.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's HTTP request handling"
// ===========================================================================
test "w119/G1: receiver HTTP endpoint present (FIX-65 foundation)" {
    // The "server" is the existing RpcServer; the route lives there as a
    // private method.  PayjoinHandler is the namespaced helper module the
    // route delegates to.
    try testing.expect(@hasDecl(rpc_mod, "PayjoinHandler"));
    // handlePayjoinRequest is a private fn on RpcServer; assert the
    // namespace contains a fn by that name (Zig surfaces all decls,
    // including pub-and-private, via @hasDecl on the struct type).
    try testing.expect(@hasDecl(rpc_mod.RpcServer, "handlePayjoinRequest"));
    // Other audit-flagged decl shapes still absent (kept as the W119
    // tracking signal for future API-sprawl avoidance).
    try testing.expect(!@hasDecl(rpc_mod, "PayjoinServer"));
    try testing.expect(!@hasDecl(rpc_mod, "payjoinServer"));
    try testing.expect(!@hasDecl(rpc_mod, "startPayjoinServer"));
}

// ===========================================================================
// G2: Sender HTTP client — MISSING ENTIRELY
//
// BUG-2 (HIGH): The sender POSTs the Original PSBT and reads the proposal
//   back.  clearbit has no HTTP client whatsoever (the v2 transport in
//   v2_transport.zig is raw TCP for BIP-324, not HTTP).
//
// Spec ref: bips/bip-0078.mediawiki, "Sender's HTTP request"
// ===========================================================================
test "w119/G2: sender HTTP client absent (no sendPayjoinRequest)" {
    try testing.expect(!@hasDecl(wallet_mod, "sendPayjoinRequest"));
    try testing.expect(!@hasDecl(wallet_mod, "postOriginalPsbt"));
    try testing.expect(!@hasDecl(wallet_mod, "PayjoinClient"));
}

// ===========================================================================
// G3: TLS-or-onion transport — MISSING ENTIRELY
//
// BUG-3 (HIGH/PRIVACY): BIP-78 §"Receiver's HTTPS or Onion endpoint" REQUIRES
//   either TLS or a .onion endpoint.  clearbit's JSON-RPC server in rpc.zig
//   binds plain TCP only (no TLS context, no .onion publish).  A PayJoin
//   shim on top would fail this requirement.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's transport security"
// ===========================================================================
test "w119/G3: TLS/onion receiver transport absent" {
    // Plain TCP RpcServer exists; no TLS variant + no onion variant.
    try testing.expect(@hasDecl(rpc_mod, "RpcServer")); // baseline present
    try testing.expect(!@hasDecl(rpc_mod, "TlsRpcServer"));
    try testing.expect(!@hasDecl(rpc_mod, "TlsPayjoinServer"));
    try testing.expect(!@hasDecl(rpc_mod, "OnionPayjoinServer"));
}

// ===========================================================================
// G4: Original-PSBT deserialize — PARTIAL (PSBT exists, no v=1 wrapper)
//
// BUG-4 (MED): clearbit can deserialize PSBT v0 (psbt_mod.Psbt.deserialize),
//   which is the wire format PayJoin uses for the Original.  But BIP-78's
//   POST body is a base64-encoded PSBT wrapped by HTTP headers — there is
//   no helper that:
//     1. parses the HTTP body,
//     2. base64-decodes the payload,
//     3. confirms PSBT-magic 0x70736274ff,
//     4. emits a PayJoin-specific `OriginalPsbtRejected` error.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver should reject the request"
// ===========================================================================
test "w119/G4: Original-PSBT deserialize wrapper absent (PSBT primitive present)" {
    // Underlying PSBT primitive exists.
    try testing.expect(@hasDecl(psbt_mod, "Psbt"));
    // BIP-78 wrapper does not.
    try testing.expect(!@hasDecl(psbt_mod, "deserializeOriginalPsbt"));
    try testing.expect(!@hasDecl(psbt_mod, "parsePayjoinOriginal"));
}

// ===========================================================================
// G5: Receiver-side Original-PSBT validation — MISSING ENTIRELY
//
// BUG-5 (HIGH/CDIV): BIP-78 §"Receiver's original PSBT checklist" lists
//   ~10 must-checks the receiver runs against the incoming Original PSBT
//   (each input signed, no wallet-owned inputs, version=1, etc).  None of
//   these gates exist.  A naive shim would forward an unsigned or
//   already-broadcast PSBT, leaking funds + privacy.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's original PSBT checklist"
// ===========================================================================
test "w119/G5: Original-PSBT receiver validator absent" {
    try testing.expect(!@hasDecl(psbt_mod, "validateOriginalPsbt"));
    try testing.expect(!@hasDecl(psbt_mod, "validatePayjoinOriginal"));
    try testing.expect(!@hasDecl(wallet_mod, "validatePayjoinOriginal"));
}

// ===========================================================================
// G6: Fee-output identification — MISSING ENTIRELY
//
// BUG-6 (HIGH): BIP-78's `additionalfeeoutputindex` parameter tells the
//   receiver which sender output (almost always the change) may be
//   debited to pay extra fee.  Without parsing this index AND verifying
//   the output is sender-owned (against the original PSBT's scriptPubKey
//   set), the receiver could siphon value from the recipient output and
//   the sender would unknowingly sign.
//
// Spec ref: bips/bip-0078.mediawiki, "Optional parameters: additionalfeeoutputindex"
// ===========================================================================
test "w119/G6: fee-output identifier absent" {
    try testing.expect(!@hasDecl(psbt_mod, "feeOutputIndex"));
    try testing.expect(!@hasDecl(psbt_mod, "selectFeeOutput"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinFeeOutput"));
}

// ===========================================================================
// G7: Receiver adds inputs — MISSING ENTIRELY
//
// BUG-7 (HIGH): The core PayJoin step: receiver picks one or more of its
//   own UTXOs and appends them as new inputs to the Original PSBT.  Then
//   it signs those inputs and returns the proposal.  None of this routing
//   exists.  The wallet has `selectCoins` (W113) — but no API that takes
//   an Original PSBT, runs CoinSelection over the receiver wallet, and
//   merges the new inputs.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's payment proposal"
// ===========================================================================
test "w119/G7: receiver-add-inputs primitive absent" {
    try testing.expect(!@hasDecl(wallet_mod, "addPayjoinInputs"));
    try testing.expect(!@hasDecl(wallet_mod, "buildPayjoinProposal"));
    try testing.expect(!@hasDecl(psbt_mod, "appendReceiverInputs"));
}

// ===========================================================================
// G8: Receiver modifies output — MISSING ENTIRELY
//
// BUG-8 (MED/PRIVACY): To preserve the equal-output heuristic break,
//   the receiver typically bumps its own receive output by the value of
//   the new inputs.  Output substitution (replacing scriptPubKey) is
//   permitted when `pjos=0`.  No helper to mutate output values or
//   substitute scripts exists.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's payment proposal"
// ===========================================================================
test "w119/G8: receiver-output-modify primitive absent" {
    try testing.expect(!@hasDecl(psbt_mod, "modifyPayjoinOutput"));
    try testing.expect(!@hasDecl(psbt_mod, "substituteReceiverOutput"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinSubstituteOutput"));
}

// ===========================================================================
// G9: Receiver fee adjustment — MISSING ENTIRELY
//
// BUG-9 (HIGH): When the receiver adds inputs, the effective fee rate
//   drops because vsize grew without fee growing.  BIP-78 specifies the
//   receiver MAY debit `maxadditionalfeecontribution` from the sender's
//   fee-output to compensate.  No primitive does this arithmetic.
//
// Spec ref: bips/bip-0078.mediawiki, "Fee output value adjustment"
// ===========================================================================
test "w119/G9: receiver-fee-adjust primitive absent" {
    try testing.expect(!@hasDecl(psbt_mod, "adjustPayjoinFee"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinFeeAdjust"));
}

// ===========================================================================
// G10: Sender anti-snoop on outputs — MISSING ENTIRELY
//
// BUG-10 (P0/CDIV/SECURITY): The single most important sender check.
//   After the proposal returns, the sender MUST verify that every
//   original output (modulo the optional substituted receiver output) is
//   preserved verbatim.  Without this check, a malicious receiver could
//   redirect the recipient output to itself and the sender would sign it
//   away.  No anti-snoop function exists.
//
// Spec ref: bips/bip-0078.mediawiki, "Sender's payment proposal checklist"
// ===========================================================================
test "w119/G10: sender anti-snoop output validator absent" {
    try testing.expect(!@hasDecl(psbt_mod, "validatePayjoinProposal"));
    try testing.expect(!@hasDecl(wallet_mod, "validatePayjoinProposal"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinAntiSnoop"));
}

// ===========================================================================
// G11: Sender scriptSig-type preservation — MISSING ENTIRELY
//
// BUG-11 (MED/PRIVACY): BIP-78 §"Sender's checklist (3)" — every input
//   the receiver added MUST use the same scriptSig type as the sender's
//   inputs (p2wpkh, p2sh-p2wpkh, …).  Mismatched types defeat the
//   privacy goal.  No type-equality check exists.
//
// Spec ref: bips/bip-0078.mediawiki, "Sender's payment proposal checklist"
// ===========================================================================
test "w119/G11: sender scriptSig-type uniformity check absent" {
    try testing.expect(!@hasDecl(psbt_mod, "checkScriptSigUniformity"));
    try testing.expect(!@hasDecl(psbt_mod, "validateInputTypes"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinInputTypeCheck"));
}

// ===========================================================================
// G12: Sender "no new sender inputs" check — MISSING ENTIRELY
//
// BUG-12 (P0/CDIV/SECURITY): The receiver MUST NOT add an input that was
//   already in the Original PSBT (= one of the sender's inputs).  More
//   subtly, the receiver MUST NOT add an input the sender owns.  Without
//   this check (compare prevout sets), the receiver could trick the
//   sender into signing a duplicate or self-input.
//
// Spec ref: bips/bip-0078.mediawiki, "Sender's payment proposal checklist"
// ===========================================================================
test "w119/G12: sender input-set-disjoint check absent" {
    try testing.expect(!@hasDecl(psbt_mod, "checkInputDisjoint"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinInputDisjoint"));
}

// ===========================================================================
// G13: Sender maxadditionalfeecontribution honored — MISSING ENTIRELY
//
// BUG-13 (HIGH): The sender quotes a maximum extra fee it will pay.
//   The proposal's reduced fee-output value MUST satisfy
//   `(original_fee_out - proposal_fee_out) <= maxadditionalfeecontribution`.
//   No primitive evaluates this bound.
//
// Spec ref: bips/bip-0078.mediawiki, "Sender's payment proposal checklist (7)"
// ===========================================================================
test "w119/G13: sender max-fee-contrib enforcement absent" {
    try testing.expect(!@hasDecl(psbt_mod, "checkMaxAdditionalFee"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinFeeContribCheck"));
}

// ===========================================================================
// G14: Sender disableoutputsubstitution honored — MISSING ENTIRELY
//
// BUG-14 (HIGH): When the sender sets `disableoutputsubstitution=true`
//   (or BIP-21 `pjos=1`), the receiver MUST NOT substitute its receive
//   output's scriptPubKey.  The sender SHOULD also re-check this in the
//   proposal.  No such gate exists.
//
// Spec ref: bips/bip-0078.mediawiki, "Optional parameters: disableoutputsubstitution"
// ===========================================================================
test "w119/G14: sender disable-output-substitution enforcement absent" {
    try testing.expect(!@hasDecl(psbt_mod, "checkOutputSubstitution"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinDisableOutSub"));
}

// ===========================================================================
// G15: Sender minfeerate floor — MISSING ENTIRELY
//
// BUG-15 (HIGH): The sender provides `minfeerate` (sat/vB).  The
//   proposal's effective fee rate MUST be >= minfeerate.  Without this
//   floor, a receiver could starve the tx of fee and stall propagation.
//
// Spec ref: bips/bip-0078.mediawiki, "Optional parameters: minfeerate"
// ===========================================================================
test "w119/G15: sender min-fee-rate floor enforcement absent" {
    try testing.expect(!@hasDecl(psbt_mod, "checkMinFeeRate"));
    try testing.expect(!@hasDecl(wallet_mod, "payjoinMinFeeRate"));
}

// ===========================================================================
// G16: Query-parameter parser — CLOSED in FIX-65
//
// FIX-65 adds `parsePayjoinQuery` + `PayjoinQuery` (a struct exposing all
// 5 BIP-78 optional parameters with spec defaults applied at parse time).
// Test coverage: `src/tests_fix65_payjoin_receiver.zig` G16 cluster.
//
// Spec ref: bips/bip-0078.mediawiki, "Optional parameters"
// ===========================================================================
test "w119/G16: query-parameter parser present (FIX-65)" {
    try testing.expect(@hasDecl(rpc_mod, "parsePayjoinQuery"));
    try testing.expect(@hasDecl(rpc_mod, "PayjoinQuery"));
    // `parseQueryString` deliberately NOT added — we want the BIP-78-
    // specific parser, not a generic URL-query helper that would invite
    // misuse outside the PayJoin path.
    try testing.expect(!@hasDecl(rpc_mod, "parseQueryString"));
}

// ===========================================================================
// G17: 4 BIP-78 error codes — CLOSED in FIX-65
//
// FIX-65 adds `PayjoinError` (Zig error set) + the 4 wire-string code
// constants (`PAYJOIN_ERR_UNAVAILABLE` etc).  Verbatim wire-string match
// to BTCPayServer.Payjoin is asserted in
// `src/tests_fix65_payjoin_receiver.zig`.
//
// BUG-16 (MED) — original audit text retained.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's well-known errors"
// ===========================================================================
test "w119/G17: 4 BIP-78 error codes present (FIX-65)" {
    try testing.expect(@hasDecl(rpc_mod, "PayjoinError"));
    try testing.expect(@hasDecl(rpc_mod, "PAYJOIN_ERR_UNAVAILABLE"));
    try testing.expect(@hasDecl(rpc_mod, "PAYJOIN_ERR_NOT_ENOUGH_MONEY"));
    try testing.expect(@hasDecl(rpc_mod, "PAYJOIN_ERR_VERSION_UNSUPPORTED"));
    try testing.expect(@hasDecl(rpc_mod, "PAYJOIN_ERR_ORIGINAL_REJECTED"));
}

// ===========================================================================
// G18: Receiver TTL on issued Originals — MISSING ENTIRELY
//
// BUG-17 (MED): A receiver that gets an Original PSBT but never returns
//   a proposal SHOULD remember the prevouts for ~24h so a re-submission
//   cannot trigger UTXO probing.  No state store for issued requests
//   exists.
//
// Spec ref: bips/bip-0078.mediawiki, "Implementation Suggestions"
// ===========================================================================
test "w119/G18: receiver issued-request TTL store absent" {
    try testing.expect(!@hasDecl(rpc_mod, "PayjoinRequestCache"));
    try testing.expect(!@hasDecl(rpc_mod, "PayjoinSessionTtl"));
}

// ===========================================================================
// G19: Receiver no-double-spend safeguard — MISSING ENTIRELY
//
// BUG-18 (HIGH): The receiver MUST NOT add an input it has already used
//   in another active PayJoin session, because if neither tx confirms
//   the receiver may have double-spent itself.  Without a session UTXO
//   lock, concurrent PayJoin requests racing for the same UTXO are
//   undetected.
//
// Spec ref: bips/bip-0078.mediawiki, "Implementation Suggestions"
// ===========================================================================
test "w119/G19: receiver no-double-spend UTXO lock absent" {
    try testing.expect(!@hasDecl(wallet_mod, "lockPayjoinUtxo"));
    try testing.expect(!@hasDecl(rpc_mod, "PayjoinUtxoLockTable"));
}

// ===========================================================================
// G20: Receiver UTXO anti-fingerprint — MISSING ENTIRELY
//
// BUG-19 (MED/PRIVACY): BIP-78 recommends the receiver pick inputs whose
//   confirmation count + scriptPubKey type matches the sender's inputs,
//   to defeat the "find the receiver" heuristic.  No fingerprint-aware
//   coin selector exists (the W113 selectCoins is fingerprint-agnostic).
//
// Spec ref: bips/bip-0078.mediawiki, "Implementation Suggestions"
// ===========================================================================
test "w119/G20: receiver UTXO anti-fingerprint selector absent" {
    try testing.expect(!@hasDecl(wallet_mod, "selectPayjoinReceiverUtxo"));
    try testing.expect(!@hasDecl(wallet_mod, "fingerprintAwareSelect"));
}

// ===========================================================================
// G21: v=1 version-pin header — CLOSED in FIX-65
//
// FIX-65 adds `PAYJOIN_VERSION = 1` + `checkPayjoinVersion`, returning
// `error.VersionUnsupported` for any other value.  `handlePayjoinRequest`
// calls the checker before reading the body, so a malformed `v=` short-
// circuits to a `version-unsupported` JSON error.  Test coverage:
// `src/tests_fix65_payjoin_receiver.zig` G21 cluster.
//
// Spec ref: bips/bip-0078.mediawiki, "Version negotiation"
// ===========================================================================
test "w119/G21: v=1 version-pin handler present (FIX-65)" {
    try testing.expect(@hasDecl(rpc_mod, "PAYJOIN_VERSION"));
    try testing.expect(@hasDecl(rpc_mod, "checkPayjoinVersion"));
}

// ===========================================================================
// G22: Sender fallback to broadcast Original — MISSING ENTIRELY
//
// BUG-21 (HIGH): If the receiver returns an error or times out, the
//   sender SHOULD broadcast the Original PSBT (signed) so the recipient
//   still gets paid.  Without this fallback, a flaky PayJoin endpoint
//   silently fails the payment.
//
// Spec ref: bips/bip-0078.mediawiki, "Sender's payment flow"
// ===========================================================================
test "w119/G22: sender fallback-broadcast absent" {
    try testing.expect(!@hasDecl(wallet_mod, "payjoinFallback"));
    try testing.expect(!@hasDecl(wallet_mod, "broadcastPayjoinOriginal"));
}

// ===========================================================================
// G23: Receiver Content-Type negotiation — MISSING ENTIRELY
//
// BUG-22 (LOW): BIP-78 specifies Content-Type `text/plain` for the
//   request body (base64 PSBT) and `application/json` for error
//   responses.  No Content-Type routing exists.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's HTTP request"
// ===========================================================================
test "w119/G23: receiver Content-Type negotiator absent" {
    try testing.expect(!@hasDecl(rpc_mod, "negotiatePayjoinContentType"));
    try testing.expect(!@hasDecl(rpc_mod, "CONTENT_TYPE_PAYJOIN"));
}

// ===========================================================================
// G24: HTTPS certificate validation — MISSING ENTIRELY
//
// BUG-23 (HIGH/SECURITY): The sender MUST validate the receiver's TLS
//   certificate (chain + hostname) when the endpoint is https:// .
//   clearbit has no TLS client.  A PayJoin shim would either send
//   plaintext (BIP-78 violation) or skip validation (MITM-vulnerable).
//
// Spec ref: bips/bip-0078.mediawiki, "Sender's transport security"
// ===========================================================================
test "w119/G24: HTTPS cert validation absent" {
    try testing.expect(!@hasDecl(wallet_mod, "validateTlsCert"));
    try testing.expect(!@hasDecl(rpc_mod, "TlsClient"));
}

// ===========================================================================
// G25: Tor .onion endpoint support — MISSING ENTIRELY
//
// BUG-24 (MED/PRIVACY): The receiver SHOULD publish a .onion endpoint
//   to avoid leaking its IP.  clearbit has a Tor proxy client (W117
//   proxy.zig SOCKS5 + Tor control), but no Hidden Service publisher,
//   so a receiver cannot bind a .onion address.
//
// Spec ref: bips/bip-0078.mediawiki, "Receiver's transport security"
// ===========================================================================
test "w119/G25: Tor onion-receiver publisher absent (Tor client present)" {
    // Tor SOCKS5 client / control was wired in W117 (proxy.zig).
    // What's missing is the receiver-side Hidden Service publisher.
    try testing.expect(!@hasDecl(rpc_mod, "publishOnionService"));
    try testing.expect(!@hasDecl(rpc_mod, "OnionService"));
}

// ===========================================================================
// G26: getpayjoinrequest RPC — MISSING ENTIRELY
//
// BUG-25 (HIGH): Receivers expose this RPC to mint a fresh PayJoin URI
//   (with embedded `pj=` endpoint).  clearbit has `getnewaddress` but no
//   PayJoin URI generator.
//
// Spec ref: BTCPayServer payjoin reference: getpayjoinrequest
// ===========================================================================
test "w119/G26: getpayjoinrequest RPC absent" {
    try testing.expect(!@hasDecl(rpc_mod, "handleGetPayjoinRequest"));
    try testing.expect(!@hasDecl(rpc_mod, "handleGetpayjoinrequest"));
}

// ===========================================================================
// G27: sendpayjoinrequest RPC — MISSING ENTIRELY
//
// BUG-26 (HIGH): Senders use this RPC to: (a) construct an Original
//   PSBT, (b) POST it to the receiver endpoint, (c) validate the
//   proposal, (d) sign, (e) broadcast.  Roughly bumpfee-sized scope.
//   Absent.
//
// Spec ref: BTCPayServer payjoin reference: sendpayjoinrequest
// ===========================================================================
test "w119/G27: sendpayjoinrequest RPC absent" {
    try testing.expect(!@hasDecl(rpc_mod, "handleSendPayjoinRequest"));
    try testing.expect(!@hasDecl(rpc_mod, "handleSendpayjoinrequest"));
}

// ===========================================================================
// G28: BIP-21 `pj=` extraction — CLOSED in FIX-62
//
// FIX-62 added `src/bip21.zig` (parseBip21 + Bip21Uri), re-exported from
// `address.zig` and `wallet.zig`.  Full test coverage in
// `src/tests_fix62_bip21.zig` (run via `zig build test-bip21`).  The W119
// audit absence assertions are converted to presence checks below.
//
// BUG-27 (HIGH) — original audit text retained for cross-impl traceability:
//   BIP-21 (`bitcoin:address?amount=…&pj=…`) is the delivery channel for
//   PayJoin endpoints.  clearbit had no BIP-21 parser anywhere.  Senders
//   could not discover a receiver endpoint from a payment URI.
//
// Spec ref: bips/bip-0021.mediawiki + BIP-78 `pj=` extension
// ===========================================================================
test "w119/G28: BIP-21 parser + pj= extraction present (FIX-62)" {
    try testing.expect(@hasDecl(address_mod, "parseBip21"));
    try testing.expect(@hasDecl(address_mod, "Bip21Uri"));
    try testing.expect(@hasDecl(wallet_mod, "parseBip21"));
}

// ===========================================================================
// G29: BIP-21 `pjos=` extraction — CLOSED in FIX-62
//
// BUG-28 (MED) — original audit text retained:
//   The `pjos=0|1` parameter is the BIP-21 toggle for
//   `disableoutputsubstitution`.  FIX-62 adds `parseBip21Pjos` on
//   address.zig and `parsePjosParam` on wallet.zig.
//
// Spec ref: bips/bip-0078.mediawiki, "BIP-21 extension"
// ===========================================================================
test "w119/G29: BIP-21 pjos= extraction present (FIX-62)" {
    try testing.expect(@hasDecl(address_mod, "parseBip21Pjos"));
    try testing.expect(@hasDecl(wallet_mod, "parsePjosParam"));
}

// ===========================================================================
// G30: Receiver replay protection — MISSING ENTIRELY
//
// BUG-29 (MED): If the same Original PSBT is POSTed twice, the receiver
//   MUST return the same proposal (or an error), not a fresh second
//   proposal that selects different UTXOs.  Re-running selection on
//   replay leaks the receiver's full UTXO set over time.  No replay
//   cache exists.
//
// Spec ref: bips/bip-0078.mediawiki, "Implementation Suggestions"
// ===========================================================================
test "w119/G30: receiver replay-protect cache absent" {
    try testing.expect(!@hasDecl(rpc_mod, "PayjoinReplayCache"));
    try testing.expect(!@hasDecl(rpc_mod, "payjoinReplayDedup"));
}

// ===========================================================================
// W119 summary integrity gate
// ===========================================================================

test "w119: BIP-78 surface partial after FIX-62 (BIP-21) + FIX-65 (receiver foundation)" {
    // The audit was originally honest about 10/10 MISSING ENTIRELY.  Two
    // fix waves have flipped a strict subset of gates:
    //   - FIX-62 closed G28 + G29 (BIP-21 URI parser, universal prereq).
    //   - FIX-65 closed G1 + G16 + G17 + G21 (receiver-side foundation:
    //     POST /payjoin route, query parser, 4 error codes, v=1 pin).
    // Every other PayJoin-specific decl remains expected absent.  This
    // summary gate fails loudly if a future fix adds a deferred-shape
    // decl without removing the corresponding `@hasDecl` assertion in
    // its per-gate test above — exactly the desired CI signal.
    //
    // What MUST be present (closed by FIX-65):
    const foundation_present = @hasDecl(rpc_mod, "PayjoinHandler") and
        @hasDecl(rpc_mod.RpcServer, "handlePayjoinRequest") and
        @hasDecl(rpc_mod, "parsePayjoinQuery") and
        @hasDecl(rpc_mod, "PayjoinQuery") and
        @hasDecl(rpc_mod, "PayjoinError") and
        @hasDecl(rpc_mod, "PAYJOIN_VERSION") and
        @hasDecl(rpc_mod, "checkPayjoinVersion");
    try testing.expect(foundation_present);

    // What MUST remain absent (deferred to future fix waves):
    const still_absent = !@hasDecl(rpc_mod, "PayjoinServer") and
        !@hasDecl(wallet_mod, "sendPayjoinRequest") and
        !@hasDecl(psbt_mod, "validateOriginalPsbt") and
        !@hasDecl(psbt_mod, "validatePayjoinProposal") and
        !@hasDecl(rpc_mod, "handleGetPayjoinRequest") and
        !@hasDecl(rpc_mod, "handleSendPayjoinRequest") and
        !@hasDecl(rpc_mod, "TlsPayjoinServer") and
        !@hasDecl(rpc_mod, "OnionPayjoinServer") and
        !@hasDecl(rpc_mod, "PayjoinReplayCache");
    try testing.expect(still_absent);
}
