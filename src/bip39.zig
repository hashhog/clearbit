//! BIP-39 mnemonic encoding / decoding + PBKDF2 mnemonic→seed (W21).
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
//!
//! Algorithm (entropy → mnemonic):
//!   1. Generate ENT bits of entropy (ENT ∈ {128, 160, 192, 224, 256}).
//!   2. Compute checksum = first ENT/32 bits of SHA-256(entropy).
//!   3. Concatenate entropy || checksum → (ENT + ENT/32) bits.
//!   4. Split into 11-bit chunks, each indexing into the 2048-word wordlist.
//!
//! Algorithm (mnemonic → seed):
//!   PBKDF2(HMAC-SHA512, NFKD(mnemonic), "mnemonic" || NFKD(passphrase),
//!          c=2048, dkLen=64).
//!
//! NFKD note: Zig std does not ship Unicode normalization. For the English
//! wordlist + ASCII passphrase the operation is a no-op (every word is pure
//! ASCII, every ASCII byte is its own NFKD form). For non-ASCII passphrases
//! we return `error.NonAsciiPassphraseRequiresNfkd` rather than silently
//! producing a wrong seed (cf. the haskoin iteration-collapse trap surfaced
//! today).
//!
//! Wordlist is loaded via `@embedFile` from the same file `wallet.zig`
//! consumes (`resources/bip39-english.txt`); this module owns no copy of
//! the wordlist, just a reference + a comptime parser.

const std = @import("std");

// ---------------------------------------------------------------------------
// Wordlist
// ---------------------------------------------------------------------------

/// BIP-39 English wordlist (2048 entries, newline-separated). Embedded at
/// compile time; same file `wallet.zig` consumes.
const BIP39_WORDLIST_BLOB: []const u8 = @embedFile("../resources/bip39-english.txt");

/// Parse the embedded wordlist into a fixed-size array at comptime.
///
/// The default backwards-branch budget (1000) is too low for splitting
/// 2048 newline-separated lines, so we bump it explicitly.
fn parseWordlist() [2048][]const u8 {
    @setEvalBranchQuota(50_000);
    var words: [2048][]const u8 = undefined;
    var lines = std.mem.splitScalar(u8, BIP39_WORDLIST_BLOB, '\n');
    var i: usize = 0;
    while (lines.next()) |line| {
        if (line.len > 0 and i < 2048) {
            words[i] = line;
            i += 1;
        }
    }
    if (i != 2048) {
        @compileError("BIP-39 wordlist must contain exactly 2048 entries");
    }
    return words;
}

pub const WORDS: [2048][]const u8 = parseWordlist();

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub const BIP39Error = error{
    /// Entropy length must be one of 16/20/24/28/32 bytes.
    InvalidEntropyLength,
    /// Mnemonic word count must be one of 12/15/18/21/24.
    InvalidMnemonicLength,
    /// One of the words is not in the BIP-39 English wordlist.
    UnknownWord,
    /// The trailing checksum bits don't match the SHA-256 of the entropy.
    InvalidChecksum,
    /// Non-ASCII passphrase passed without an NFKD normalizer wired in.
    /// We refuse to silently misinterpret the bytes.
    NonAsciiPassphraseRequiresNfkd,
    /// Internal: mnemonic word containing whitespace or other invalid char.
    InvalidWord,
    /// Re-exported from std.crypto.pwhash.pbkdf2 (rounds < 1).
    WeakParameters,
    /// Re-exported from std.crypto.pwhash.pbkdf2 (output too long).
    OutputTooLong,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha512 = std.crypto.auth.hmac.Hmac(Sha512);

fn entropyByteLenToWordCount(byte_len: usize) BIP39Error!usize {
    return switch (byte_len) {
        16 => 12,
        20 => 15,
        24 => 18,
        28 => 21,
        32 => 24,
        else => error.InvalidEntropyLength,
    };
}

fn wordCountToEntropyByteLen(word_count: usize) BIP39Error!usize {
    return switch (word_count) {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        else => error.InvalidMnemonicLength,
    };
}

/// Look up a word's index in the wordlist (linear scan; the wordlist is
/// sorted but we don't rely on that — the cost is once-per-word and the
/// wordlist is small).
fn wordIndex(word: []const u8) BIP39Error!u11 {
    for (WORDS, 0..) |w, i| {
        if (std.mem.eql(u8, w, word)) {
            return @intCast(i);
        }
    }
    return error.UnknownWord;
}

/// Test whether a slice is pure ASCII (every byte < 0x80).
fn isAscii(s: []const u8) bool {
    for (s) |b| {
        if (b >= 0x80) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// entropy → mnemonic
// ---------------------------------------------------------------------------

/// Convert entropy (16/20/24/28/32 bytes) into a 12/15/18/21/24-word
/// mnemonic. The returned slice and its element slices are owned by the
/// caller; element slices point into the static wordlist (no per-word
/// allocation), so only the outer slice needs to be freed.
pub fn entropyToMnemonic(
    allocator: std.mem.Allocator,
    entropy: []const u8,
) BIP39Error![]const []const u8 {
    const word_count = try entropyByteLenToWordCount(entropy.len);

    // checksum = SHA-256(entropy); we use the first ENT/32 bits.
    var cs: [32]u8 = undefined;
    Sha256.hash(entropy, &cs, .{});
    const checksum_bits: u8 = @intCast(entropy.len / 4); // ENT/32

    // Concatenate entropy || first checksum_bits of cs into a bit buffer
    // that's an exact multiple of 11. Allocate enough bytes to cover both
    // (entropy.len + 1 is enough because checksum_bits ≤ 8).
    const total_bits: usize = entropy.len * 8 + checksum_bits;
    std.debug.assert(total_bits % 11 == 0);
    std.debug.assert(total_bits / 11 == word_count);

    // Build a bit-reader stepping MSB-first across (entropy ++ cs[0]).
    // We only ever consume up to entropy.len + 1 bytes (checksum_bits ≤ 8).
    var buf: [33]u8 = undefined;
    @memcpy(buf[0..entropy.len], entropy);
    buf[entropy.len] = cs[0]; // safe: checksum_bits ≤ 8

    var out = try allocator.alloc([]const u8, word_count);
    errdefer allocator.free(out);

    var bit_pos: usize = 0;
    var w: usize = 0;
    while (w < word_count) : (w += 1) {
        var idx: u16 = 0;
        var b: u4 = 0;
        while (b < 11) : (b += 1) {
            const byte_index = (bit_pos + b) / 8;
            const bit_index: u3 = @intCast(7 - ((bit_pos + b) % 8));
            const bit: u16 = (buf[byte_index] >> bit_index) & 1;
            idx = (idx << 1) | bit;
        }
        bit_pos += 11;
        out[w] = WORDS[idx];
    }
    return out;
}

// ---------------------------------------------------------------------------
// mnemonic → entropy
// ---------------------------------------------------------------------------

/// Convert a 12/15/18/21/24-word mnemonic back into the original entropy.
/// Validates the trailing checksum bits against SHA-256 of the recovered
/// entropy; returns `error.InvalidChecksum` if they don't match.
///
/// The returned slice is allocator-owned and must be freed by the caller.
pub fn mnemonicToEntropy(
    allocator: std.mem.Allocator,
    mnemonic: []const []const u8,
) BIP39Error![]u8 {
    const entropy_len = try wordCountToEntropyByteLen(mnemonic.len);
    const checksum_bits: u8 = @intCast(entropy_len / 4); // ENT/32
    const total_bits: usize = entropy_len * 8 + checksum_bits;
    std.debug.assert(total_bits == mnemonic.len * 11);

    // Pack bits MSB-first into a 33-byte buffer (32 entropy + 1 checksum).
    var buf: [33]u8 = [_]u8{0} ** 33;
    var bit_pos: usize = 0;
    for (mnemonic) |word| {
        const idx_u11 = try wordIndex(word);
        const idx: u16 = idx_u11;
        var b: u4 = 0;
        while (b < 11) : (b += 1) {
            const bit: u8 = @intCast((idx >> @as(u4, 10) - b) & 1);
            const byte_index = (bit_pos + b) / 8;
            const bit_index: u3 = @intCast(7 - ((bit_pos + b) % 8));
            buf[byte_index] |= bit << bit_index;
        }
        bit_pos += 11;
    }

    // Split into entropy + checksum_bits-of-the-next-byte. Verify the
    // checksum byte's high `checksum_bits` match SHA-256(entropy)'s.
    const out = try allocator.alloc(u8, entropy_len);
    errdefer allocator.free(out);
    @memcpy(out, buf[0..entropy_len]);

    var cs: [32]u8 = undefined;
    Sha256.hash(out, &cs, .{});

    // Mask: top `checksum_bits` bits of the byte.
    const mask: u8 = @as(u8, 0xff) << @as(u3, @intCast(8 - checksum_bits));
    const got = buf[entropy_len] & mask;
    const expect = cs[0] & mask;
    if (got != expect) {
        // `errdefer` above will free `out` once we propagate the error.
        return error.InvalidChecksum;
    }
    return out;
}

/// Validate a mnemonic (length + word membership + checksum). Allocates
/// internally for the entropy buffer; releases it before returning.
pub fn validateMnemonic(
    allocator: std.mem.Allocator,
    mnemonic: []const []const u8,
) BIP39Error!void {
    const e = try mnemonicToEntropy(allocator, mnemonic);
    allocator.free(e);
}

// ---------------------------------------------------------------------------
// mnemonic → seed (PBKDF2-HMAC-SHA512)
// ---------------------------------------------------------------------------

/// Derive a 64-byte BIP-39 seed from a mnemonic and optional passphrase.
///
/// Salt = "mnemonic" || NFKD(passphrase). For ASCII passphrases (incl.
/// "TREZOR" used in the canonical vectors) NFKD is the identity. For
/// non-ASCII passphrases we error out — see module docs.
///
/// The mnemonic itself is rendered as space-separated words (the
/// canonical BIP-39 form). Each word in the English wordlist is pure
/// ASCII; the joined string is therefore ASCII and NFKD-stable.
///
/// Iterations: 2048 (BIP-39 fixed). dkLen: 64.
pub fn mnemonicToSeed(
    allocator: std.mem.Allocator,
    mnemonic: []const []const u8,
    passphrase: []const u8,
    out_seed: *[64]u8,
) BIP39Error!void {
    if (!isAscii(passphrase)) return error.NonAsciiPassphraseRequiresNfkd;

    // Build the password = words joined by single ASCII space.
    var pw_len: usize = 0;
    for (mnemonic, 0..) |w, i| {
        // A wordlist word with whitespace would silently corrupt the
        // password. The English wordlist has none, but be defensive.
        for (w) |c| if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
            return error.InvalidWord;
        };
        pw_len += w.len;
        if (i + 1 < mnemonic.len) pw_len += 1; // separator
    }
    const password = try allocator.alloc(u8, pw_len);
    defer allocator.free(password);

    var off: usize = 0;
    for (mnemonic, 0..) |w, i| {
        @memcpy(password[off .. off + w.len], w);
        off += w.len;
        if (i + 1 < mnemonic.len) {
            password[off] = ' ';
            off += 1;
        }
    }
    std.debug.assert(off == pw_len);

    // Salt = "mnemonic" || passphrase (NFKD = no-op for ASCII).
    const SALT_PREFIX = "mnemonic";
    const salt = try allocator.alloc(u8, SALT_PREFIX.len + passphrase.len);
    defer allocator.free(salt);
    @memcpy(salt[0..SALT_PREFIX.len], SALT_PREFIX);
    @memcpy(salt[SALT_PREFIX.len..], passphrase);

    try std.crypto.pwhash.pbkdf2(out_seed, password, salt, 2048, HmacSha512);
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(200_000);
    var out: [hex.len / 2]u8 = undefined;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch unreachable;
    }
    return out;
}

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        out[i] = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch return error.InvalidHex;
    }
    return out;
}

/// Parse a space-separated mnemonic string into a slice of word-references
/// pointing into the static wordlist. Caller frees the outer slice.
fn parseMnemonic(allocator: std.mem.Allocator, s: []const u8) ![]const []const u8 {
    var list = std.ArrayList([]const u8).init(allocator);
    errdefer list.deinit();
    var it = std.mem.tokenizeScalar(u8, s, ' ');
    while (it.next()) |tok| {
        const idx = try wordIndex(tok);
        try list.append(WORDS[idx]);
    }
    return list.toOwnedSlice();
}

test "wordlist sanity: 2048 entries, abandon/about/zoo at known positions" {
    try testing.expectEqual(@as(usize, 2048), WORDS.len);
    try testing.expectEqualSlices(u8, "abandon", WORDS[0]);
    try testing.expectEqualSlices(u8, "about", WORDS[3]);
    try testing.expectEqualSlices(u8, "zoo", WORDS[2047]);
}

// ---------------------------------------------------------------------------
// PBKDF2 sanity check (RFC 6070 vector 4) — verifies Zig std didn't ship
// an iteration-collapse bug. RFC 6070 vector 4 is the canonical
// HMAC-SHA1, c=4096, dklen=25 case.
// ---------------------------------------------------------------------------

test "Zig std PBKDF2 sanity: RFC 6070 HMAC-SHA1 vector 4" {
    const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
    const password = "passwordPASSWORDpassword";
    const salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    var dk: [25]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&dk, password, salt, 4096, HmacSha1);
    const expected = hexToBytes("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
    try testing.expectEqualSlices(u8, &expected, &dk);
}

// ---------------------------------------------------------------------------
// TREZOR vectors — canonical BIP-39 reference vectors.
// Source: bitcoin-core/src/test/bip39_tests.cpp comments + the trezor
// python-mnemonic vectors.json.
// ---------------------------------------------------------------------------

test "TREZOR vector 1: 12-word, all-zero entropy, passphrase=TREZOR" {
    const allocator = testing.allocator;

    const entropy = [_]u8{0} ** 16;
    const expected_mnemonic =
        "abandon abandon abandon abandon abandon abandon " ++
        "abandon abandon abandon abandon abandon about";
    const expected_seed = hexToBytes(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    );

    // entropy → mnemonic
    const m = try entropyToMnemonic(allocator, &entropy);
    defer allocator.free(m);

    var joined = std.ArrayList(u8).init(allocator);
    defer joined.deinit();
    for (m, 0..) |w, i| {
        if (i > 0) try joined.append(' ');
        try joined.appendSlice(w);
    }
    try testing.expectEqualSlices(u8, expected_mnemonic, joined.items);

    // mnemonic → entropy round-trip
    const e2 = try mnemonicToEntropy(allocator, m);
    defer allocator.free(e2);
    try testing.expectEqualSlices(u8, &entropy, e2);

    // mnemonic → seed (the byte-identity check; haskoin's collapse trap)
    var seed: [64]u8 = undefined;
    try mnemonicToSeed(allocator, m, "TREZOR", &seed);
    try testing.expectEqualSlices(u8, &expected_seed, &seed);
}

test "TREZOR vector 2: 12-word, 0x7f entropy, passphrase=TREZOR" {
    const allocator = testing.allocator;

    const entropy = [_]u8{0x7f} ** 16;
    const expected_mnemonic =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const expected_seed = hexToBytes(
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    );

    const m = try entropyToMnemonic(allocator, &entropy);
    defer allocator.free(m);

    var joined = std.ArrayList(u8).init(allocator);
    defer joined.deinit();
    for (m, 0..) |w, i| {
        if (i > 0) try joined.append(' ');
        try joined.appendSlice(w);
    }
    try testing.expectEqualSlices(u8, expected_mnemonic, joined.items);

    const e2 = try mnemonicToEntropy(allocator, m);
    defer allocator.free(e2);
    try testing.expectEqualSlices(u8, &entropy, e2);

    var seed: [64]u8 = undefined;
    try mnemonicToSeed(allocator, m, "TREZOR", &seed);
    try testing.expectEqualSlices(u8, &expected_seed, &seed);
}

test "TREZOR vector 3: 24-word, 0x80 entropy, passphrase=TREZOR" {
    // Source: trezor python-mnemonic vectors.json — 32-byte entropy vector
    // (entropy = 0x80...80, 32 bytes).
    const allocator = testing.allocator;

    const entropy = [_]u8{0x80} ** 32;
    const expected_mnemonic =
        "letter advice cage absurd amount doctor acoustic avoid letter advice " ++
        "cage absurd amount doctor acoustic avoid letter advice cage absurd " ++
        "amount doctor acoustic bless";
    const expected_seed = hexToBytes(
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    );

    const m = try entropyToMnemonic(allocator, &entropy);
    defer allocator.free(m);

    var joined = std.ArrayList(u8).init(allocator);
    defer joined.deinit();
    for (m, 0..) |w, i| {
        if (i > 0) try joined.append(' ');
        try joined.appendSlice(w);
    }
    try testing.expectEqualSlices(u8, expected_mnemonic, joined.items);

    const e2 = try mnemonicToEntropy(allocator, m);
    defer allocator.free(e2);
    try testing.expectEqualSlices(u8, &entropy, e2);

    var seed: [64]u8 = undefined;
    try mnemonicToSeed(allocator, m, "TREZOR", &seed);
    try testing.expectEqualSlices(u8, &expected_seed, &seed);
}

test "invalid checksum: corrupt last word" {
    const allocator = testing.allocator;

    const entropy = [_]u8{0} ** 16;
    const m = try entropyToMnemonic(allocator, &entropy);
    defer allocator.free(m);

    // Replace the last word ("about", index 3) with a different word whose
    // 11-bit index has a different low bit-pattern, breaking the 4-bit
    // checksum. "abandon" (index 0) differs in the low 11 bits.
    var corrupt = try allocator.alloc([]const u8, m.len);
    defer allocator.free(corrupt);
    @memcpy(corrupt, m);
    corrupt[corrupt.len - 1] = WORDS[0]; // "abandon"

    const got = mnemonicToEntropy(allocator, corrupt);
    try testing.expectError(error.InvalidChecksum, got);
}

test "unknown word rejected" {
    const allocator = testing.allocator;
    const bogus = [_][]const u8{ "abandon", "notarealbip39word" };
    const got = wordIndex(bogus[1]);
    try testing.expectError(error.UnknownWord, got);

    // mnemonicToEntropy with the wrong word count fails on length first;
    // build a valid-length mnemonic with one bogus word to exercise the
    // unknown-word path.
    var twelve: [12][]const u8 = undefined;
    inline for (0..12) |i| twelve[i] = WORDS[0];
    twelve[5] = "notarealbip39word";
    const got2 = mnemonicToEntropy(allocator, &twelve);
    try testing.expectError(error.UnknownWord, got2);
}

test "invalid entropy length rejected" {
    const allocator = testing.allocator;
    const bad = [_]u8{0} ** 17;
    try testing.expectError(error.InvalidEntropyLength, entropyToMnemonic(allocator, &bad));
}

test "invalid mnemonic length rejected" {
    const allocator = testing.allocator;
    var thirteen: [13][]const u8 = undefined;
    inline for (0..13) |i| thirteen[i] = WORDS[0];
    try testing.expectError(error.InvalidMnemonicLength, mnemonicToEntropy(allocator, &thirteen));
}

test "non-ASCII passphrase refused (NFKD not implemented)" {
    const allocator = testing.allocator;
    const entropy = [_]u8{0} ** 16;
    const m = try entropyToMnemonic(allocator, &entropy);
    defer allocator.free(m);

    var seed: [64]u8 = undefined;
    const non_ascii = [_]u8{ 0xc3, 0xa9 }; // "é" UTF-8
    try testing.expectError(
        error.NonAsciiPassphraseRequiresNfkd,
        mnemonicToSeed(allocator, m, &non_ascii, &seed),
    );
}

test "parseMnemonic accepts canonical TREZOR vector 1 string" {
    const allocator = testing.allocator;
    const s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const m = try parseMnemonic(allocator, s);
    defer allocator.free(m);
    try testing.expectEqual(@as(usize, 12), m.len);
    try testing.expectEqualSlices(u8, "abandon", m[0]);
    try testing.expectEqualSlices(u8, "about", m[11]);

    var seed: [64]u8 = undefined;
    try mnemonicToSeed(allocator, m, "TREZOR", &seed);
    const expected_seed = hexToBytes(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    );
    try testing.expectEqualSlices(u8, &expected_seed, &seed);
}

// Public re-export for callers that want to parse a user-supplied
// mnemonic string. Not used by Wallet.initFromMnemonic (which takes the
// already-tokenized form to avoid an allocation surface), but useful for
// RPC handlers and CLI tooling.
pub const parseMnemonicString = parseMnemonic;
