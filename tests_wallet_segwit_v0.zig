//! P2WSH + P2SH-P2WSH wallet test root (W29-C).
//!
//! Lives at the project root so the test harness's package path matches
//! `build.zig`, letting `src/wallet.zig` resolve `@embedFile("../resources/bip39-english.txt")`
//! the same way it does in production builds. The actual tests live in
//! `src/tests_wallet_segwit_v0.zig`; this file is only here to set up the
//! package layout, the same trick used by `tests_wallet_taproot.zig`.

comptime {
    _ = @import("src/tests_wallet_segwit_v0.zig");
}
