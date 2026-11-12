//! getwalletinfo field-set regression root. Run: zig build test-wallet-getwalletinfo-fields
comptime {
    _ = @import("src/tests_wallet_getwalletinfo_fields.zig");
}
