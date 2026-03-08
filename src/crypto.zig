const std = @import("std");

/// SHA256 hash (32 bytes)
pub const Sha256Hash = [32]u8;

/// RIPEMD160 hash (20 bytes)
pub const Ripemd160Hash = [20]u8;

/// HASH256 = SHA256(SHA256(x)) - used for transaction/block hashes
pub fn hash256(data: []const u8) Sha256Hash {
    var first_hash: Sha256Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &first_hash, .{});
    var result: Sha256Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first_hash, &result, .{});
    return result;
}

/// SHA256 single hash
pub fn sha256(data: []const u8) Sha256Hash {
    var result: Sha256Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &result, .{});
    return result;
}

/// RIPEMD160 - Bitcoin uses this for address generation
/// Zig stdlib doesn't have RIPEMD160, so we implement it
pub fn ripemd160(data: []const u8) Ripemd160Hash {
    var state = Ripemd160State.init();
    state.update(data);
    return state.final();
}

/// HASH160 = RIPEMD160(SHA256(x)) - used for P2PKH/P2SH addresses
pub fn hash160(data: []const u8) Ripemd160Hash {
    const sha_hash = sha256(data);
    return ripemd160(&sha_hash);
}

/// RIPEMD160 implementation
const Ripemd160State = struct {
    state: [5]u32,
    buf: [64]u8,
    buf_len: usize,
    total_len: u64,

    const K_LEFT = [_]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
    const K_RIGHT = [_]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

    const R_LEFT = [_]u8{
        0, 1, 2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        7, 4, 13, 1,  10, 6,  15, 3,  12, 0,  9,  5,  2,  14, 11, 8,
        3, 10, 14, 4, 9,  15, 8,  1,  2,  7,  0,  6,  13, 11, 5,  12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    };

    const R_RIGHT = [_]u8{
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    };

    const S_LEFT = [_]u8{
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    };

    const S_RIGHT = [_]u8{
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    };

    fn init() Ripemd160State {
        return .{
            .state = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    fn update(self: *Ripemd160State, data: []const u8) void {
        var input = data;
        self.total_len += input.len;

        if (self.buf_len > 0) {
            const remaining = 64 - self.buf_len;
            if (input.len < remaining) {
                @memcpy(self.buf[self.buf_len..][0..input.len], input);
                self.buf_len += input.len;
                return;
            }
            @memcpy(self.buf[self.buf_len..][0..remaining], input[0..remaining]);
            self.processBlock(&self.buf);
            input = input[remaining..];
            self.buf_len = 0;
        }

        while (input.len >= 64) {
            self.processBlock(input[0..64]);
            input = input[64..];
        }

        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }
    }

    fn final(self: *Ripemd160State) Ripemd160Hash {
        const bit_len = self.total_len * 8;

        // Padding
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        @memset(self.buf[self.buf_len..56], 0);
        std.mem.writeInt(u64, self.buf[56..64], bit_len, .little);
        self.processBlock(&self.buf);

        var result: Ripemd160Hash = undefined;
        for (0..5) |i| {
            std.mem.writeInt(u32, result[i * 4 ..][0..4], self.state[i], .little);
        }
        return result;
    }

    fn processBlock(self: *Ripemd160State, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        for (0..16) |i| {
            x[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
        }

        var al = self.state[0];
        var bl = self.state[1];
        var cl = self.state[2];
        var dl = self.state[3];
        var el = self.state[4];

        var ar = self.state[0];
        var br = self.state[1];
        var cr = self.state[2];
        var dr = self.state[3];
        var er = self.state[4];

        for (0..80) |j| {
            const round = j / 16;
            const fl = switch (round) {
                0 => bl ^ cl ^ dl,
                1 => (bl & cl) | (~bl & dl),
                2 => (bl | ~cl) ^ dl,
                3 => (bl & dl) | (cl & ~dl),
                4 => bl ^ (cl | ~dl),
                else => unreachable,
            };

            var tl = al +% fl +% x[R_LEFT[j]] +% K_LEFT[round];
            tl = std.math.rotl(u32, tl, @as(u5, @intCast(S_LEFT[j]))) +% el;
            al = el;
            el = dl;
            dl = std.math.rotl(u32, cl, 10);
            cl = bl;
            bl = tl;

            const fr = switch (round) {
                0 => ar ^ (br | ~cr),
                1 => (ar & cr) | (br & ~cr),
                2 => (ar | ~br) ^ cr,
                3 => (ar & br) | (~ar & cr),
                4 => ar ^ br ^ cr,
                else => unreachable,
            };

            var tr = dr +% fr +% x[R_RIGHT[j]] +% K_RIGHT[round];
            tr = std.math.rotl(u32, tr, @as(u5, @intCast(S_RIGHT[j]))) +% er;
            dr = er;
            er = cr;
            cr = std.math.rotl(u32, br, 10);
            br = ar;
            ar = tr;
        }

        const t = self.state[1] +% cl +% dr;
        self.state[1] = self.state[2] +% dl +% er;
        self.state[2] = self.state[3] +% el +% ar;
        self.state[3] = self.state[4] +% al +% br;
        self.state[4] = self.state[0] +% bl +% cr;
        self.state[0] = t;
    }
};

// Tests
test "sha256 basic" {
    const result = sha256("");
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "sha256 hello" {
    const result = sha256("hello");
    const expected = [_]u8{
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash256 empty" {
    const result = hash256("");
    // SHA256(SHA256("")) = 5df6e0e2...
    const expected = [_]u8{
        0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
        0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
        0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
        0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "ripemd160 empty" {
    const result = ripemd160("");
    const expected = [_]u8{
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
        0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "ripemd160 hello" {
    const result = ripemd160("hello");
    const expected = [_]u8{
        0x10, 0x8f, 0x07, 0xb8, 0x38, 0x24, 0x12, 0x61, 0x2c, 0x04,
        0x8d, 0x07, 0xd1, 0x3f, 0x81, 0x41, 0x18, 0x44, 0x5a, 0xcd,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash160 pubkey" {
    // Test with a compressed public key (33 bytes)
    const pubkey = [_]u8{
        0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8,
        0x3c, 0x1a, 0xf1, 0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86,
        0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e, 0x5b, 0x23, 0x52,
    };
    const result = hash160(&pubkey);
    // This should produce a 20-byte pubkey hash
    try std.testing.expectEqual(@as(usize, 20), result.len);
}
