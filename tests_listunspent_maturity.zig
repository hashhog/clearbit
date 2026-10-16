//! listunspent coinbase-maturity regression root. Run: zig build test-listunspent-maturity
comptime {
    _ = @import("src/tests_listunspent_maturity.zig");
}
