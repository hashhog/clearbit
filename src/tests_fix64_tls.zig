//! FIX-64 — HTTPS/TLS termination flag plumbing for the JSON-RPC server.
//!
//! Per the W119 PayJoin audit (BUG-3 + BUG-23), BIP-78 requires that the
//! receiver endpoint be either HTTPS or a Tor .onion address.  Implementing
//! server-side TLS today is blocked by Zig 0.13's stdlib (only
//! `std.crypto.tls.Client` is provided — there is no Server.zig).  This file
//! covers the FIX-64 deferral slice:
//!
//!   - `RpcConfig.tls_cert_path` + `RpcConfig.tls_key_path` exist
//!   - `validateTlsConfig` enforces "both-or-neither" and surfaces a clear
//!     `TlsServerUnavailable` error when both are supplied
//!   - `tlsAvailable()` returns `false` on this build
//!   - `RpcServer.start()` calls the validator before bind so a misconfigured
//!     operator gets a startup error, not a silent plain-HTTP downgrade
//!   - W119/G3 + W119/G24 audit-gate names (`TlsRpcServer`, `TlsClient`, ...)
//!     remain ABSENT — the deferral preserves the audit's tracking signal
//!     instead of muting it with stub declarations.
//!
//! Run with `zig build test-fix64`.

const std = @import("std");
const testing = std.testing;
const rpc = @import("rpc.zig");

// ---------------------------------------------------------------------------
// G1: RpcConfig surface — TLS fields exist with the right defaults.
// ---------------------------------------------------------------------------
test "fix64/G1: RpcConfig has tls_cert_path + tls_key_path, default null" {
    const cfg = rpc.RpcConfig{};
    try testing.expect(cfg.tls_cert_path == null);
    try testing.expect(cfg.tls_key_path == null);
}

test "fix64/G1b: RpcConfig accepts both TLS paths via struct init" {
    const cfg = rpc.RpcConfig{
        .tls_cert_path = "/etc/clearbit/cert.pem",
        .tls_key_path = "/etc/clearbit/key.pem",
    };
    try testing.expect(cfg.tls_cert_path != null);
    try testing.expect(cfg.tls_key_path != null);
    try testing.expectEqualStrings("/etc/clearbit/cert.pem", cfg.tls_cert_path.?);
    try testing.expectEqualStrings("/etc/clearbit/key.pem", cfg.tls_key_path.?);
}

// ---------------------------------------------------------------------------
// G2: validateTlsConfig — both unset → HTTP (default, OK).
// ---------------------------------------------------------------------------
test "fix64/G2: both TLS paths unset → validateTlsConfig OK (HTTP default)" {
    const cfg = rpc.RpcConfig{};
    try rpc.validateTlsConfig(cfg);
}

// ---------------------------------------------------------------------------
// G3: validateTlsConfig — partial config rejected.
//
// Either path alone is a misconfiguration (cert without key is unusable,
// key without cert is at best confusing and at worst hides intent).  The
// validator must reject both halves of the split.
// ---------------------------------------------------------------------------
test "fix64/G3a: cert without key → TlsCertWithoutKey" {
    const cfg = rpc.RpcConfig{
        .tls_cert_path = "/etc/clearbit/cert.pem",
        .tls_key_path = null,
    };
    try testing.expectError(rpc.RpcError.TlsCertWithoutKey, rpc.validateTlsConfig(cfg));
}

test "fix64/G3b: key without cert → TlsKeyWithoutCert" {
    const cfg = rpc.RpcConfig{
        .tls_cert_path = null,
        .tls_key_path = "/etc/clearbit/key.pem",
    };
    try testing.expectError(rpc.RpcError.TlsKeyWithoutCert, rpc.validateTlsConfig(cfg));
}

// ---------------------------------------------------------------------------
// G4: validateTlsConfig — both set → TlsServerUnavailable (deferral marker).
//
// This is the load-bearing check: an operator who sets up cert + key
// deliberately MUST see a clear error rather than getting a plain-HTTP
// downgrade by accident.  When the eventual real implementation lands,
// this test flips to `expectEqual({}, validateTlsConfig(cfg))` and a new
// test asserts the cert+key parse correctly.
// ---------------------------------------------------------------------------
test "fix64/G4: both TLS paths set → TlsServerUnavailable (deferral)" {
    const cfg = rpc.RpcConfig{
        .tls_cert_path = "/etc/clearbit/cert.pem",
        .tls_key_path = "/etc/clearbit/key.pem",
    };
    try testing.expectError(rpc.RpcError.TlsServerUnavailable, rpc.validateTlsConfig(cfg));
}

// ---------------------------------------------------------------------------
// G5: tlsAvailable() reports the build's actual capability.
//
// Right now this is unconditionally false (the validator returns
// TlsServerUnavailable as soon as both flags are set).  The eventual real
// implementation flips this to true and the validator stops returning
// TlsServerUnavailable for valid configs.  Both flips happen together so
// the contract for callers is "tlsAvailable() == true implies
// validateTlsConfig accepts a well-formed cert/key pair".
// ---------------------------------------------------------------------------
test "fix64/G5: tlsAvailable() is false on this build (Zig 0.13 stdlib gap)" {
    try testing.expect(!rpc.tlsAvailable());
}

// ---------------------------------------------------------------------------
// G6: RpcError exposes the three TLS error variants.
//
// Compile-time check: the error set must include all three values so callers
// (notably main.zig's startup handler) can switch on them by name.  If a
// future refactor renames or drops a variant the switch in main.zig still
// compiles (else branch), but this test forces the rename to be intentional.
// ---------------------------------------------------------------------------
test "fix64/G6: RpcError exposes the three TLS variants by name" {
    // If any of these is removed the comptime expression below fails to
    // resolve, surfacing the rename at test time.
    const variants = .{
        rpc.RpcError.TlsCertWithoutKey,
        rpc.RpcError.TlsKeyWithoutCert,
        rpc.RpcError.TlsServerUnavailable,
    };
    try testing.expectEqual(@as(usize, 3), variants.len);
}

// ---------------------------------------------------------------------------
// G7: W119 audit gates remain ABSENT.
//
// The W119 PayJoin audit (tests_w119_payjoin.zig) tracks the missing TLS
// stack with `!@hasDecl(rpc_mod, "TlsRpcServer")`, `!@hasDecl(rpc_mod,
// "TlsPayjoinServer")`, `!@hasDecl(rpc_mod, "TlsClient")`,
// `!@hasDecl(rpc_mod, "OnionPayjoinServer")`.  The deferral here MUST NOT
// add any of those names — adding a stub `TlsRpcServer` would mute the
// audit signal without actually delivering working TLS.  Repeat the
// audit's negative assertion here so a future patch that tries to
// "implement" TLS by adding stub decls fails this file before touching
// the W119 file.
// ---------------------------------------------------------------------------
test "fix64/G7: TlsRpcServer / TlsPayjoinServer / OnionPayjoinServer absent" {
    try testing.expect(!@hasDecl(rpc, "TlsRpcServer"));
    try testing.expect(!@hasDecl(rpc, "TlsPayjoinServer"));
    try testing.expect(!@hasDecl(rpc, "OnionPayjoinServer"));
    try testing.expect(!@hasDecl(rpc, "TlsClient"));
}

// ---------------------------------------------------------------------------
// G8: RpcServer.start() validates before bind.
//
// Build a minimal config with a deliberately-bad TLS pair (key only) and
// confirm start() returns the validation error before even attempting to
// parse the bind address.  Uses an invalid bind address that would itself
// fail parseIp — if validateTlsConfig were skipped, we'd see InvalidIPAddressFormat
// instead of TlsKeyWithoutCert.
//
// We DON'T construct a full RpcServer (that requires storage + mempool +
// peer manager + network params) — we exercise validateTlsConfig directly
// and trust the wiring shown in `RpcServer.start` (one-liner: `try
// validateTlsConfig(self.config);` before bind).
// ---------------------------------------------------------------------------
test "fix64/G8: validateTlsConfig short-circuits before bind (semantic)" {
    // Confirm the validator returns the TLS error eagerly for bad configs,
    // even when the bind address would also be invalid downstream.
    const cfg = rpc.RpcConfig{
        .bind_address = "not-an-ip", // would fail parseIp if reached
        .port = 0,
        .tls_cert_path = null,
        .tls_key_path = "/dev/null",
    };
    try testing.expectError(rpc.RpcError.TlsKeyWithoutCert, rpc.validateTlsConfig(cfg));
}
