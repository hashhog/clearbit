//! BIP-39 test root (W21).
//!
//! Lives at the project root so the test harness's package path matches
//! `build.zig`, letting `src/bip39.zig` resolve `@embedFile("../resources/bip39-english.txt")`
//! the same way it does in production builds. The actual tests live in
//! `src/bip39.zig`; this file is only here to set up the package layout,
//! the same trick used by `tests_rpc.zig` and `tests_wallet_taproot.zig`.

comptime {
    _ = @import("src/bip39.zig");
}
