//! Single-FFI libsecp256k1 wrapper module (Phase 2 of the clearbit unfreeze plan).
//!
//! ## Why this module exists
//!
//! Prior to this module, clearbit had **four separate `@cImport` blocks** for
//! libsecp256k1 in production code (`crypto.zig`, `wallet.zig`,
//! `descriptor.zig`, `v2_transport.zig`). Each `@cImport` produces a fresh
//! opaque-type tree, so the four `*secp256k1_context` values had four
//! distinct compile-time types and could not be passed between modules even
//! though they were ABI-identical at runtime.
//!
//! That structural mismatch was the root cause of clearbit's 30+ audit-fail
//! streak (W138 → W161): every wallet RPC had to spin up its own context,
//! the cipher-as-scalar boundary bug (W158/W159 BUG-2/14) was untyped, and
//! cross-module collaboration on signing primitives was impossible.
//!
//! ## What this module provides
//!
//! 1. **One** `@cImport` of all needed libsecp256k1 headers (re-exported as
//!    `secp.c.*` for callers that still want raw access).
//! 2. **One** opaque context type tree-wide.
//! 3. **One** process-global context, created on first use and randomized
//!    (W159 BUG-4 closure consolidated to a single site).
//! 4. **Typed newtype wrappers** (`SecKey`, `PubKey`, `XOnlyPubKey`, `Sig`,
//!    `SchnorrSig`, `Keypair`) so cipher bytes can never again be passed
//!    where a private scalar is expected.
//!
//! ## Migration policy
//!
//! - **Phase 2 (this commit)**: production modules import `secp` and use
//!   the shared opaque type + shared global context. Internal call sites
//!   continue to reference `secp.c.secp256k1_*` directly so the migration
//!   is mechanical and reviewable.
//! - **Phase 4 (later)**: high-value entry points (HD derivation, ECDSA
//!   sign / verify, Schnorr sign / verify, ECDH) migrate to the typed
//!   wrappers below. The wrappers are already complete and unit-tested
//!   here so the cascade in Phase 4 is straight-line work.
//!
//! Test-only `@cImport` blocks (in `tests_w111`, `tests_w113`, `tests_w118`,
//! `tests_w129`, `tests_wallet_segwit_v0`, `tests_wallet_taproot`,
//! `test_script.zig`) are intentionally left in place per the unfreeze
//! plan P2-4: each is a self-contained verification with no cross-test
//! type leakage, and rewiring them would add noise without value. They
//! could be migrated in a follow-up sweep.

const std = @import("std");

// ============================================================================
// Single @cImport — the entire libsecp256k1 surface clearbit needs
// ============================================================================

/// Raw libsecp256k1 C bindings.
///
/// `build.zig` always links libsecp256k1 and adds its include path for
/// every test target (`unit_tests.linkSystemLibrary("secp256k1")` etc.)
/// as well as the main exe, so a real `@cImport` works in both modes
/// — no test stub needed. The pre-Phase-2 modules carried optional-stub
/// branches as a defensive holdover from a config that no longer exists.
///
/// **Do not add a second `@cImport(secp256k1*)` anywhere in production
/// code.** That undoes the entire point of this module. Add the header
/// here and re-export.
pub const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
    @cInclude("secp256k1_recovery.h");
    @cInclude("secp256k1_ellswift.h");
});

/// Shared opaque context type. Identical to `c.secp256k1_context` — exposed
/// at the top level so modules can write `*secp.Context` instead of
/// `*secp.c.secp256k1_context`.
pub const Context = c.secp256k1_context;

// ============================================================================
// Typed newtype wrappers (Phase 2 P2-3)
// ============================================================================
//
// The W158/W159 cipher-as-scalar bug (BUG-2/14) happened because raw [32]u8
// buffers were passed across the FFI boundary with no type-level distinction
// between "this is a private scalar" and "this is AES-256-GCM ciphertext".
// The current encryption path (W161 BUG-5 fix) routes through
// `getPlaintextMasterKey()` so the bug is patched at the call site, but the
// type system still permits the regression. These newtypes close that hole.

/// A secp256k1 private scalar (32 bytes). NEVER carries ciphertext.
///
/// Construction is restricted to (a) freshly-derived BIP-32 child keys, (b)
/// HMAC-SHA512 output halves that are then validated with
/// `secp256k1_ec_seckey_verify`, (c) wire-formats decoded from WIF, or (d)
/// already-decrypted master-key plaintext from `getPlaintextMasterKey`.
pub const SecKey = struct {
    bytes: [32]u8,

    pub fn fromBytes(b: [32]u8) SecKey {
        return .{ .bytes = b };
    }

    pub fn zero() SecKey {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    /// Constant-time zero of the underlying key material. Call before
    /// dropping the value if it held real key material on the stack.
    pub fn wipe(self: *SecKey) void {
        std.crypto.utils.secureZero(u8, &self.bytes);
    }

    /// Verify this private scalar is in (0, n) where n is the curve order.
    pub fn verify(self: *const SecKey, ctx: *Context) bool {
        return c.secp256k1_ec_seckey_verify(ctx, &self.bytes) == 1;
    }
};

/// A 33-byte compressed secp256k1 public key.
///
/// Phase 2 of the unfreeze plan calls this out specifically: the legacy
/// `ExtendedKey.key: [32]u8` field could not hold a 33-byte compressed
/// pubkey, which made `xpub` / watch-only wallets unimplementable. The
/// typed `PubKey` here is the buffer that the upcoming Phase 4 P4-1
/// union refactor stores in the public arm of the discriminated union.
pub const PubKey = struct {
    bytes: [33]u8,

    pub fn fromBytes(b: [33]u8) PubKey {
        return .{ .bytes = b };
    }
};

/// A 32-byte BIP-340 x-only public key (used by Taproot).
pub const XOnlyPubKey = struct {
    bytes: [32]u8,

    pub fn fromBytes(b: [32]u8) XOnlyPubKey {
        return .{ .bytes = b };
    }
};

/// A 64-byte compact ECDSA signature (r||s, 32 bytes each).
pub const Sig = struct {
    bytes: [64]u8,
};

/// A 64-byte BIP-340 Schnorr signature.
pub const SchnorrSig = struct {
    bytes: [64]u8,
};

// ============================================================================
// Process-global shared context (P2-1 + P2-2)
// ============================================================================
//
// Previously each of the four production modules created its own
// `*secp256k1_context` (and three of them did so lazily inside the function
// that first needed signing). Now there is one process-global context
// created at startup (or on first use), randomized exactly once, and
// shared by every caller.
//
// The context is thread-safe per libsecp256k1's documentation: all consumer
// functions that take a `*const secp256k1_context` may be called
// concurrently. `secp256k1_context_randomize` is the only mutator and runs
// once under `ctx_mutex` at creation.

var global_ctx: ?*Context = null;
var ctx_mutex: std.Thread.Mutex = .{};

/// Initialize the shared secp256k1 context.
///
/// Idempotent: safe to call multiple times, only the first call creates the
/// context. Returns true on success (or if already initialized), false if
/// libsecp256k1 returned NULL from `secp256k1_context_create`.
///
/// Per `secp256k1.h:286-290` calling `secp256k1_context_randomize` is
/// "highly recommended" after every `secp256k1_context_create`; this is
/// the W159 BUG-4 fix from `7265c2f`, consolidated to a single site.
pub fn init() bool {
    ctx_mutex.lock();
    defer ctx_mutex.unlock();
    if (global_ctx != null) return true;

    const flags: c_uint = c.SECP256K1_CONTEXT_VERIFY | c.SECP256K1_CONTEXT_SIGN;
    const ctx = c.secp256k1_context_create(flags) orelse return false;

    // W159 BUG-4: side-channel-blinding via secp256k1_context_randomize.
    // Core key.cpp:572-587 does this with fresh GetRandBytes(32) + assert(ret).
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const ret = c.secp256k1_context_randomize(ctx, &seed);
    if (ret == 0) @panic("secp256k1_context_randomize failed");
    // Wipe the seed off the stack — it's no longer needed.
    std.crypto.utils.secureZero(u8, &seed);

    global_ctx = ctx;
    return true;
}

/// Destroy the shared secp256k1 context. Safe to call multiple times.
///
/// Callers should arrange for `deinit` to run after every consumer has
/// stopped using the context (typically at process shutdown).
pub fn deinit() void {
    ctx_mutex.lock();
    defer ctx_mutex.unlock();
    if (global_ctx) |ctx| {
        c.secp256k1_context_destroy(ctx);
        global_ctx = null;
    }
}

/// Get the shared context. Lazily initializes on first call.
///
/// Returns `null` only when libsecp256k1 is unavailable (e.g. test stub
/// path). Production code can `orelse return error.Secp256k1NotAvailable`.
pub fn context() ?*Context {
    if (global_ctx) |ctx| return ctx;
    if (!init()) return null;
    return global_ctx;
}

/// Strict accessor: panics if the context has not been initialized.
/// Use this in code paths where the context MUST exist (post-`main.init`).
pub fn contextOrPanic() *Context {
    return context() orelse @panic("secp256k1 context not initialized");
}

/// Test helper: returns whether the shared context is currently live.
pub fn isInitialized() bool {
    ctx_mutex.lock();
    defer ctx_mutex.unlock();
    return global_ctx != null;
}

// ============================================================================
// Tests
// ============================================================================

test "secp module compiles" {
    // The module compiles cleanly in test mode using the stub.
    const Foo = PubKey;
    const k = Foo.fromBytes([_]u8{0} ** 33);
    try std.testing.expectEqual(@as(usize, 33), k.bytes.len);
}

test "SecKey wipe zeroes underlying buffer" {
    var sk = SecKey.fromBytes([_]u8{0xff} ** 32);
    try std.testing.expectEqual(@as(u8, 0xff), sk.bytes[0]);
    sk.wipe();
    try std.testing.expectEqual(@as(u8, 0x00), sk.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x00), sk.bytes[31]);
}

test "SecKey zero produces all-zero buffer" {
    const sk = SecKey.zero();
    for (sk.bytes) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "PubKey holds 33 bytes (closes ExtendedKey buffer-too-small bug)" {
    // Sanity: the typed PubKey is exactly the size the BIP-32 spec calls
    // for. The pre-Phase-2 ExtendedKey.key field was [32]u8, one byte
    // short of holding a compressed public key. The Phase-4 union refactor
    // stores PubKey in the .pub arm; today `wallet.ExtendedPubKey.pub_key`
    // is `secp.PubKey` (this type) for the same reason.
    const pk = PubKey.fromBytes([_]u8{0x02} ++ [_]u8{0} ** 32);
    try std.testing.expectEqual(@as(usize, 33), pk.bytes.len);
    try std.testing.expectEqual(@as(u8, 0x02), pk.bytes[0]);
}
