const std = @import("std");
const types = @import("types.zig");
const serialize = @import("serialize.zig");
const script = @import("script.zig");

/// Decode a hex string into bytes. Caller owns the returned slice.
fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch return error.InvalidHexChar;
    }
    return out;
}

/// Format a [32]u8 hash as a hex string.
fn hashToHex(hash: [32]u8) [64]u8 {
    const charset = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (hash, 0..) |byte, i| {
        out[2 * i] = charset[byte >> 4];
        out[2 * i + 1] = charset[byte & 0x0f];
    }
    return out;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // Load JSON test vectors
    const json_path = "../ouroboros/bitcoin/src/test/data/sighash.json";
    const json_data = try std.fs.cwd().readFileAlloc(allocator, json_path, 50 * 1024 * 1024);
    defer allocator.free(json_data);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
    defer parsed.deinit();

    const root_array = parsed.value.array;

    var pass_count: usize = 0;
    var fail_count: usize = 0;
    var skip_count: usize = 0;
    const total = root_array.items.len - 1; // skip header

    for (root_array.items[1..], 0..) |entry, test_idx| {
        const arr = entry.array;
        if (arr.items.len < 5) {
            skip_count += 1;
            continue;
        }

        const raw_tx_hex = arr.items[0].string;
        const script_hex = arr.items[1].string;
        const input_index_val = arr.items[2].integer;
        const hash_type_val = arr.items[3].integer;
        const expected_hex = arr.items[4].string;

        const input_index: usize = @intCast(input_index_val);
        const hash_type: u32 = @bitCast(@as(i32, @intCast(hash_type_val)));

        // Decode hex values
        const tx_bytes = hexToBytes(allocator, raw_tx_hex) catch {
            try stdout.print("SKIP test {}: bad tx hex\n", .{test_idx});
            skip_count += 1;
            continue;
        };
        defer allocator.free(tx_bytes);

        const script_bytes = hexToBytes(allocator, script_hex) catch {
            try stdout.print("SKIP test {}: bad script hex\n", .{test_idx});
            skip_count += 1;
            continue;
        };
        defer allocator.free(script_bytes);

        const expected_hash_bytes = hexToBytes(allocator, expected_hex) catch {
            try stdout.print("SKIP test {}: bad expected hex\n", .{test_idx});
            skip_count += 1;
            continue;
        };
        defer allocator.free(expected_hash_bytes);

        // Deserialize transaction
        var reader = serialize.Reader{ .data = tx_bytes, .pos = 0 };
        const tx = serialize.readTransaction(&reader, allocator) catch {
            try stdout.print("FAIL test {}: tx deserialization failed\n", .{test_idx});
            fail_count += 1;
            continue;
        };
        // Free tx allocations when done
        defer {
            for (tx.inputs) |inp| {
                allocator.free(inp.script_sig);
                for (inp.witness) |w| allocator.free(w);
                if (inp.witness.len > 0)
                    allocator.free(inp.witness);
            }
            allocator.free(tx.inputs);
            for (tx.outputs) |out| {
                allocator.free(out.script_pubkey);
            }
            allocator.free(tx.outputs);
        }

        // Compute sighash
        const computed_hash = script.legacySignatureHash(
            allocator,
            &tx,
            input_index,
            script_bytes,
            hash_type,
        ) catch {
            try stdout.print("FAIL test {}: sighash computation failed\n", .{test_idx});
            fail_count += 1;
            continue;
        };

        // Compare
        var expected_hash: [32]u8 = undefined;
        if (expected_hash_bytes.len == 32) {
            @memcpy(&expected_hash, expected_hash_bytes);
        } else {
            try stdout.print("SKIP test {}: expected hash wrong length ({})\n", .{ test_idx, expected_hash_bytes.len });
            skip_count += 1;
            continue;
        }

        const computed_hex = hashToHex(computed_hash);
        if (std.mem.eql(u8, &computed_hex, expected_hex)) {
            pass_count += 1;
        } else {
            try stdout.print("FAIL test {}: expected {s}, got {s}\n", .{ test_idx, expected_hex, &computed_hex });
            fail_count += 1;
        }
    }

    try stdout.print("\n=== Sighash Test Results ===\n", .{});
    try stdout.print("Total:   {}\n", .{total});
    try stdout.print("Passed:  {}\n", .{pass_count});
    try stdout.print("Failed:  {}\n", .{fail_count});
    try stdout.print("Skipped: {}\n", .{skip_count});

    if (fail_count > 0) {
        std.process.exit(1);
    }
}
