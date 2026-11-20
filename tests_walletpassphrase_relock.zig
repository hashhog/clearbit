//! walletpassphrase timeout relock regression root. Run: zig build test-walletpassphrase-relock
comptime {
    _ = @import("src/tests_walletpassphrase_relock.zig");
}
