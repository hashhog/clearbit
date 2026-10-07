//! Chain-lock cross-thread reproducer root (audit 2026-10-07, CB-1/3/4/5/6/8).
//!
//! Lives at the project root so `src/wallet.zig` (imported via `src/rpc.zig`)
//! resolves its `@embedFile("../resources/...")`; same trick as
//! `tests_rpc_cast_hazards.zig`.  The tests live in `src/tests_chain_lock.zig`.
//!
//! Run via `zig build test-chain-lock [-Dchain-lock-filter=<substr>]`.

comptime {
    _ = @import("src/tests_chain_lock.zig");
}
