//! BIP-341 sighash shim — drives clearbit's `computeTaprootSighash`
//! against the bip341-vector-runner's stdin/stdout JSON protocol.
//!
//! Input (one JSON object per line on stdin):
//!   {
//!     "tx_hex": "...",
//!     "input_index": 0,
//!     "spent_amounts": [12345, ...],
//!     "spent_scripts": ["hex...", ...],
//!     "hash_type": 0,
//!     "annex_hex": null
//!   }
//!
//! Output (one JSON object per line on stdout):
//!   { "sig_msg": "hex...", "sig_hash": "hex..." }

const std = @import("std");
const taproot_sighash = @import("taproot_sighash.zig");
const serialize = @import("serialize.zig");
const types = @import("types.zig");
const crypto = @import("crypto.zig");

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = (try hexNibble(hex[i * 2]) << 4) | (try hexNibble(hex[i * 2 + 1]));
    }
    return out;
}

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexChar,
    };
}

fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0F];
    }
    return out;
}

fn processRequest(allocator: std.mem.Allocator, line: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, aalloc, line, .{});
    const obj = parsed.value.object;

    const tx_hex = obj.get("tx_hex").?.string;
    const input_index: usize = @intCast(obj.get("input_index").?.integer);
    const hash_type: u8 = @intCast(obj.get("hash_type").?.integer);

    const tx_bytes = try hexDecode(aalloc, tx_hex);
    var reader = serialize.Reader{ .data = tx_bytes };
    const tx = try serialize.readTransaction(&reader, aalloc);

    // spent_amounts
    const amounts_arr = obj.get("spent_amounts").?.array;
    var amounts = try aalloc.alloc(i64, amounts_arr.items.len);
    for (amounts_arr.items, 0..) |v, i| {
        amounts[i] = v.integer;
    }

    // spent_scripts
    const scripts_arr = obj.get("spent_scripts").?.array;
    var scripts = try aalloc.alloc([]const u8, scripts_arr.items.len);
    for (scripts_arr.items, 0..) |v, i| {
        scripts[i] = try hexDecode(aalloc, v.string);
    }

    // annex (optional)
    var annex: ?[]const u8 = null;
    if (obj.get("annex_hex")) |v| {
        if (v != .null) {
            annex = try hexDecode(aalloc, v.string);
        }
    }

    const prevouts = taproot_sighash.TaprootPrevouts{
        .amounts = amounts,
        .scripts = scripts,
    };

    var msg_buf = std.ArrayList(u8).init(aalloc);
    try taproot_sighash.buildSigMsg(&msg_buf, &tx, input_index, prevouts, hash_type, annex, null);

    const sig_hash = try taproot_sighash.computeTaprootSighash(
        aalloc,
        &tx,
        input_index,
        prevouts,
        hash_type,
        annex,
        null,
    );

    const stdout = std.io.getStdOut().writer();
    const msg_hex = try hexEncode(aalloc, msg_buf.items);
    const hash_hex = try hexEncode(aalloc, &sig_hash);
    try stdout.print("{{\"sig_msg\":\"{s}\",\"sig_hash\":\"{s}\"}}\n", .{ msg_hex, hash_hex });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdin = std.io.getStdIn().reader();
    var line_buf = std.ArrayList(u8).init(allocator);
    defer line_buf.deinit();

    while (true) {
        line_buf.clearRetainingCapacity();
        stdin.streamUntilDelimiter(line_buf.writer(), '\n', null) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (line_buf.items.len == 0) continue;

        processRequest(allocator, line_buf.items) catch |err| {
            const stdout = std.io.getStdOut().writer();
            try stdout.print("{{\"error\":\"{s}\"}}\n", .{@errorName(err)});
        };
    }
}
