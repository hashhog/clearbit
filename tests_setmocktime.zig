//! setmocktime RPC (regtest only) — Core rpc/node.cpp setmocktime.
//!
//! Lives at the project root (same package-path trick as
//! tests_rpc_cast_hazards.zig). Run via `zig build test-setmocktime`.

comptime {
    _ = @import("src/tests_setmocktime.zig");
}
