//! cffix-clearbit-psbt-tap-leaf-count — PSBT TAP_BIP32_DERIVATION leaf-hash
//! count (input 0x16, output 0x07) must be bounded by the bytes present
//! before it sizes an allocation.  Same class as the audit C6 witness-count
//! fix; reachable before auth through an opted-in /payjoin.

const std = @import("std");
const psbt_mod = @import("psbt.zig");
const Psbt = psbt_mod.Psbt;
const PSBT_IN_TAP_BIP32_DERIVATION = psbt_mod.PSBT_IN_TAP_BIP32_DERIVATION;
const PSBT_OUT_TAP_BIP32_DERIVATION = psbt_mod.PSBT_OUT_TAP_BIP32_DERIVATION;

const tap_leaf_test = struct {
    /// One input, one 10000-sat output, empty scripts (unsigned, non-witness).
    const UNSIGNED_TX = [_]u8{ 0x02, 0, 0, 0, 0x01 } ++ [_]u8{0x11} ** 32 ++ [_]u8{ 0, 0, 0, 0, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01 } ++
        [_]u8{ 0x10, 0x27, 0, 0, 0, 0, 0, 0, 0x00 } ++ [_]u8{ 0, 0, 0, 0 };
    const HEADER = [_]u8{ 'p', 's', 'b', 't', 0xff } ++ [_]u8{ 0x01, 0x00, UNSIGNED_TX.len } ++ UNSIGNED_TX ++ [_]u8{0x00};
    const XONLY = [_]u8{0x22} ** 32;

    /// key {type || xonly(32)} with a value of `value`.
    fn entry(comptime key_type: u8, comptime value: []const u8) []const u8 {
        return &([_]u8{ 33, key_type } ++ XONLY ++ [_]u8{value.len} ++ value[0..value.len].*);
    }

    /// 10-byte value claiming MAX_SIZE (0x02000000) leaf hashes: 5-byte
    /// compactsize + 5 stray bytes.  Unbounded this asks for 1 GiB.
    const HOSTILE_VALUE = [_]u8{ 0xfe, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05 };
    /// 1 leaf hash, fingerprint, one path element (m/7').
    const GOOD_VALUE = [_]u8{0x01} ++ [_]u8{0x33} ** 32 ++ [_]u8{ 0xde, 0xad, 0xbe, 0xef } ++ [_]u8{ 0x07, 0x00, 0x00, 0x80 };

    fn inputPsbt(comptime value: []const u8) []const u8 {
        return &(HEADER ++ entry(PSBT_IN_TAP_BIP32_DERIVATION, value)[0..].* ++ [_]u8{0x00} ++ [_]u8{0x00});
    }
    fn outputPsbt(comptime value: []const u8) []const u8 {
        return &(HEADER ++ [_]u8{0x00} ++ entry(PSBT_OUT_TAP_BIP32_DERIVATION, value)[0..].* ++ [_]u8{0x00});
    }

    /// Parse under a 64 KiB FixedBufferAllocator: a count-sized allocation
    /// surfaces as OutOfMemory instead of a real 1 GiB request.
    fn expectRejectedSmall(comptime bytes: []const u8) !void {
        var buf: [64 * 1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        if (Psbt.deserialize(fba.allocator(), bytes)) |p| {
            var pp = p;
            pp.deinit();
            return error.HostilePsbtAccepted;
        } else |err| {
            if (err == error.OutOfMemory) {
                std.debug.print("\nTAP_BIP32_DERIVATION leaf count sized an allocation past a 64 KiB cap for a {d}-byte PSBT\n", .{bytes.len});
                return error.AttackerSizedAllocation;
            }
        }
    }
};

test "psbt tap-leaf-count input TAP_BIP32_DERIVATION leaf count is bounded by the bytes present" {
    try tap_leaf_test.expectRejectedSmall(comptime tap_leaf_test.inputPsbt(&tap_leaf_test.HOSTILE_VALUE));
}

test "psbt tap-leaf-count output TAP_BIP32_DERIVATION leaf count is bounded by the bytes present" {
    try tap_leaf_test.expectRejectedSmall(comptime tap_leaf_test.outputPsbt(&tap_leaf_test.HOSTILE_VALUE));
}

test "psbt tap-leaf-count CONTROL an honest TAP_BIP32_DERIVATION still parses (input and output)" {
    {
        var p = try Psbt.deserialize(std.testing.allocator, comptime tap_leaf_test.inputPsbt(&tap_leaf_test.GOOD_VALUE));
        defer p.deinit();
        const info = p.inputs[0].tap_bip32_derivation.get(tap_leaf_test.XONLY).?;
        try std.testing.expectEqual(@as(usize, 1), info.leaf_hashes.len);
        try std.testing.expectEqualSlices(u8, &([_]u8{0x33} ** 32), &info.leaf_hashes[0]);
        try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, &info.fingerprint);
        try std.testing.expectEqualSlices(u32, &.{0x80000007}, info.path);
    }
    {
        var p = try Psbt.deserialize(std.testing.allocator, comptime tap_leaf_test.outputPsbt(&tap_leaf_test.GOOD_VALUE));
        defer p.deinit();
        const info = p.outputs[0].tap_bip32_derivation.get(tap_leaf_test.XONLY).?;
        try std.testing.expectEqual(@as(usize, 1), info.leaf_hashes.len);
        try std.testing.expectEqualSlices(u32, &.{0x80000007}, info.path);
    }
}
