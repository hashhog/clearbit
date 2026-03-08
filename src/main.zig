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
pub const peer = @import("peer.zig");
pub const sync = @import("sync.zig");
pub const mempool = @import("mempool.zig");
pub const block_template = @import("block_template.zig");
pub const rpc = @import("rpc.zig");
pub const wallet = @import("wallet.zig");

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
    _ = peer;
    _ = sync;
    _ = mempool;
    _ = block_template;
    _ = rpc;
    // Note: wallet tests require libsecp256k1 to be linked
    // Run with: zig build test -Dsecp256k1=true
    // _ = wallet;
}
