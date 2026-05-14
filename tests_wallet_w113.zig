//! W113 Coin selection audit test root.
//!
//! Lives at the project root so the test harness's package path matches
//! `build.zig`, letting `src/wallet.zig` resolve `@embedFile("../resources/bip39-english.txt")`
//! the same way it does in production builds. The actual tests live in
//! `src/tests_w113_coin_selection.zig`; this file is only here to set up the
//! package layout, the same trick used by `tests_wallet_w111.zig`.

comptime {
    _ = @import("src/tests_w113_coin_selection.zig");
}
