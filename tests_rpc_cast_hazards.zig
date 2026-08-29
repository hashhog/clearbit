//! RPC narrowing-cast hazard regression root (#81).
//!
//! Lives at the project root so the test harness's package path matches
//! `build.zig`, letting `src/wallet.zig` (transitively imported by
//! `src/rpc.zig`) resolve `@embedFile("../resources/bip39-english.txt")` the
//! same way it does in production builds. The actual tests live in
//! `src/tests_rpc_cast_hazards.zig`; this file only sets up the package
//! layout, the same trick used by `tests_createrawtx_vout_range.zig`.
//!
//! Run via `zig build test-cast-hazards`.

comptime {
    _ = @import("src/tests_rpc_cast_hazards.zig");
}
