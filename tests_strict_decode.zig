//! Root for src/tests_rpc_strict_decode.zig (package layout trick, see
//! tests_rpc_cast_hazards.zig). Run via `zig build test-strict-decode`.
comptime {
    _ = @import("src/tests_rpc_strict_decode.zig");
}
