const std = @import("std");

pub const types = @import("types.zig");
pub const crypto = @import("crypto.zig");
pub const serialize = @import("serialize.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("clearbit - Bitcoin full node in Zig\n", .{});
}

test {
    _ = types;
    _ = crypto;
    _ = serialize;
}
