const std = @import("std");

pub const types = @import("types.zig");
pub const crypto = @import("crypto.zig");
pub const serialize = @import("serialize.zig");
pub const address = @import("address.zig");
pub const script = @import("script.zig");
pub const storage = @import("storage.zig");
pub const consensus = @import("consensus.zig");
pub const validation = @import("validation.zig");
pub const p2p = @import("p2p.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("clearbit - Bitcoin full node in Zig\n", .{});
}

test {
    _ = types;
    _ = crypto;
    _ = serialize;
    _ = address;
    _ = script;
    _ = storage;
    _ = consensus;
    _ = validation;
    _ = p2p;
}
