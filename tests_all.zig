//! Project-root wrapper for src/tests.zig.
//!
//! `zig build test` used to root the aggregate test module at `src/tests.zig`,
//! which puts the package path at `src/` — so `src/wallet.zig`'s
//! `@embedFile("../resources/bip39-english.txt")` escaped it and the whole
//! module failed to compile. The 224 tests that did run came from the separate
//! per-file test steps; everything reachable ONLY through src/tests.zig never
//! ran at all, including all 16 campaign_assumeutxo tests.
//!
//! Same wrapper pattern build.zig already uses for tests_wallet_taproot.zig and
//! tests_wallet_w111.zig: root the test at the project root so the embed
//! resolves.
test {
    _ = @import("src/tests.zig");
}
