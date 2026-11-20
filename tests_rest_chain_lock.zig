//! REST chain-lock reproducer root (cffix-clearbit-rest-chain-lock).
//!
//! Lives at the project root so `src/wallet.zig` (imported via `src/rpc.zig`)
//! resolves its `@embedFile("../resources/...")`; same trick as
//! `tests_chain_lock.zig`.  The tests live in `src/tests_rest_chain_lock.zig`.
//!
//! Run via `zig build test-rest-chain-lock`.

comptime {
    _ = @import("src/tests_rest_chain_lock.zig");
}
