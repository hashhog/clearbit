//! RPC test root.
//!
//! This file lives at the project root (next to build.zig) so that the test
//! harness's package path is the project root. That matters because
//! `src/wallet.zig` (transitively imported by `src/rpc.zig`) does
//! `@embedFile("../resources/bip39-english.txt")`, which only resolves from a
//! package root that contains `resources/`. A test root inside `src/` would
//! make the package path `src/`, putting the embed outside the package.
//!
//! See `build.zig` `test-rpc` step.

comptime {
    _ = @import("src/rpc.zig");
}
