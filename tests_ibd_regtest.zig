//! Root for src/tests_rpc_ibd_regtest.zig (package layout trick, see
//! tests_strict_decode.zig). Run via `zig build test-ibd-regtest`.
comptime {
    _ = @import("src/tests_rpc_ibd_regtest.zig");
}
