//! Test-root for clearbit's operational-parity modules.
//!
//! Pulled into a dedicated root (rather than tests.zig) because src/ops.zig
//! and src/zmq.zig are leaf modules with their own tests; we just want a
//! `zig build test-ops` knob that exercises them on demand without
//! re-running the whole crypto + p2p + rpc battery.

const std = @import("std");

comptime {
    _ = @import("ops.zig");
    _ = @import("debug_log.zig");
    _ = @import("zmq.zig");
}

test "tests_ops root smoke" {
    // Sanity check that the test rig wires up cleanly.
    try std.testing.expect(true);
}
