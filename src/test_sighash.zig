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

// Locate a Bitcoin Core test-vector file.
//
// The path used to be hard-coded to a developer laptop
// ("/home/max/hashhog/bitcoin/...", and for sighash a relative path into a
// SIBLING implementation's vendored tree, "../ouroboros/bitcoin/..."). Neither
// exists on the build host, so `zig build test-script` / `test-sighash` died in
// readFileAlloc before executing a single vector. They are excluded from the
// aggregate `test` step, so nothing ever noticed: the consensus vector suites
// were dead code from whenever the path was written until 2026-08-30, when the
// slow-test lane ran them for the first time.
//
// Try the canonical in-repo location first, then a couple of historical
// layouts, and FAIL LOUDLY naming every path tried — a vector harness that
// cannot find its vectors must never look like a pass.
fn openVectorFile(allocator: std.mem.Allocator, comptime name: []const u8) ![]u8 {
    const candidates = [_][]const u8{
        "../bitcoin-core/src/test/data/" ++ name, // canonical: repo checkout of Core
        "bitcoin-core/src/test/data/" ++ name,    // when cwd is the repo root
        "../bitcoin/src/test/data/" ++ name,      // older vendored layout
    };
    for (candidates) |p| {
        const data = std.fs.cwd().readFileAlloc(allocator, p, 50 * 1024 * 1024) catch continue;
        return data;
    }
    const stderr = std.io.getStdErr().writer();
    try stderr.print("FATAL: could not find test vectors '{s}'. Tried:\n", .{name});
    for (candidates) |p| try stderr.print("  {s}\n", .{p});
    return error.VectorFileNotFound;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // Load JSON test vectors
    const json_data = try openVectorFile(allocator, "sighash.json");
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

        // Core's sighash.json stores the expected value the way
        // src/test/sighash_tests.cpp compares it:
        //     BOOST_CHECK_MESSAGE(sh.GetHex() == sigHashHex, strTest);
        // and uint256::GetHex() prints the hash BYTE-REVERSED (RPC/display
        // order). Our computed_hash is in internal order, so it must be
        // reversed before the comparison. Without this every vector "fails"
        // with got == the exact byte-reverse of expected, which is what this
        // suite did for all 500 vectors — invisible because it could not even
        // open its vector file (see openVectorFile) and so never ran.
        var display_order: [32]u8 = undefined;
        for (computed_hash, 0..) |b, i| display_order[31 - i] = b;

        const computed_hex = hashToHex(display_order);
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
