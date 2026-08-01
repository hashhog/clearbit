//! Aggregate test root (wraps `src/tests.zig`).
//!
//! Lives at the project root so the test harness's package path matches
//! `build.zig`, letting `src/wallet.zig` resolve
//! `@embedFile("../resources/bip39-english.txt")` the same way it does in
//! production builds. `src/descriptor.zig` imports `src/wallet.zig`
//! (BIP-32 ext-key decode / tr() BIP-86 tweak, P2.1), so the wallet embed
//! is now in the aggregate's transitive closure; a test root inside `src/`
//! would make the package path `src/`, putting the embed outside the
//! package. The actual tests live in `src/tests.zig`; this file is only
//! here to set up the package layout, the same trick used by
//! `tests_rpc.zig` and `tests_bip39.zig`.

comptime {
    _ = @import("src/tests.zig");
}
