//! createpsbt output-building regression root (#82).
//!
//! Lives at the project root so the test harness's package path matches
//! `build.zig`, letting `src/wallet.zig` (transitively imported by
//! `src/rpc.zig`) resolve `@embedFile("../resources/bip39-english.txt")` the
//! same way it does in production builds. The actual tests live in
//! `src/tests_createpsbt_outputs.zig`.
//!
//! Run via `zig build test-createpsbt-outputs`.

comptime {
    _ = @import("src/tests_createpsbt_outputs.zig");
}
