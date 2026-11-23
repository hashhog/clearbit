//! RPC header-deadline reproducer root (cffix-clearbit-rpc-header-deadline).
//!
//! Lives at the project root so `src/wallet.zig` (imported via `src/rpc.zig`)
//! resolves its `@embedFile("../resources/...")`; same trick as
//! `tests_rest_chain_lock.zig`.  The tests live in
//! `src/tests_rpc_header_deadline.zig`.
//!
//! Run via `zig build test-rpc-header-deadline`.

comptime {
    _ = @import("src/tests_rpc_header_deadline.zig");
}
