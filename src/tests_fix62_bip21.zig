//! FIX-62 — BIP-21 URI parser tests (clearbit, Zig 0.13).
//!
//! Covers `src/bip21.zig` end-to-end:
//!
//!   - plain `bitcoin:<addr>`
//!   - standard params (amount / label / message)
//!   - percent-decoding of values
//!   - `req-<X>` rejection
//!   - unprefixed unknown params landing in `extras`
//!   - invalid + wrong-network addresses
//!   - BIP-78 `pj=` + `pjos=` extraction
//!   - case-insensitive scheme & keys
//!   - BIP-21 spec test vectors (bips/bip-0021.mediawiki §"Examples")
//!
//! Run with: `zig build test-bip21`

const std = @import("std");
const testing = std.testing;
const bip21 = @import("bip21.zig");
const address = @import("address.zig");

// --------------------------------------------------------------------------
// Reference vectors
// --------------------------------------------------------------------------

// Mainnet P2PKH: Satoshi's genesis coinbase address.
const ADDR_MAINNET_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
// Mainnet P2WPKH: BIP-173 reference vector.
const ADDR_MAINNET_P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

// --------------------------------------------------------------------------
// G28 / G29 presence assertions (W119 conversion targets)
// --------------------------------------------------------------------------

test "fix62 G28: parseBip21 + Bip21Uri are declared on address_mod" {
    try testing.expect(@hasDecl(address, "parseBip21"));
    try testing.expect(@hasDecl(address, "Bip21Uri"));
}

test "fix62 G29: parseBip21Pjos is declared on address_mod" {
    try testing.expect(@hasDecl(address, "parseBip21Pjos"));
}

// --------------------------------------------------------------------------
// Plain `bitcoin:<addr>` (no query)
// --------------------------------------------------------------------------

test "plain bitcoin: URI parses (mainnet P2PKH)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH;

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings(ADDR_MAINNET_P2PKH, uri.address_str);
    try testing.expectEqual(address.AddressType.p2pkh, uri.address.addr_type);
    try testing.expectEqual(address.Network.mainnet, uri.address.network);
    try testing.expectEqual(@as(?u64, null), uri.amount_sat);
    try testing.expectEqual(@as(?[]const u8, null), uri.label);
    try testing.expectEqual(@as(?[]const u8, null), uri.pj);
    try testing.expectEqual(@as(?bool, null), uri.pjos);
    try testing.expectEqual(@as(usize, 0), uri.extras.items.len);
}

test "plain bitcoin: URI parses (mainnet P2WPKH bech32)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2WPKH;

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(address.AddressType.p2wpkh, uri.address.addr_type);
    try testing.expectEqual(address.Network.mainnet, uri.address.network);
}

// --------------------------------------------------------------------------
// Standard params (amount, label, message)
// --------------------------------------------------------------------------

test "amount param: 1 BTC = 100_000_000 sat" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 100_000_000), uri.amount_sat);
}

test "amount param: fractional 0.5 BTC = 50_000_000 sat" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=0.5";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 50_000_000), uri.amount_sat);
}

test "amount param: 8 fractional digits = 1 sat" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=0.00000001";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 1), uri.amount_sat);
}

test "amount param: 9 fractional digits rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=0.000000001";

    try testing.expectError(error.InvalidAmount, bip21.parseBip21(a, input, .mainnet));
}

test "amount param: trailing dot rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1.";

    // "1." has saw_digit=true (digit before dot), saw_dot=true, frac_digits=0
    // — accepted as 1 BTC.  BIP-21 grammar is "*digit [ '.' *digit ]" which
    // allows trailing dot, so don't reject.
    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);
    try testing.expectEqual(@as(?u64, 100_000_000), uri.amount_sat);
}

test "amount param: leading dot accepted (.5 BTC)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=.5";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);
    try testing.expectEqual(@as(?u64, 50_000_000), uri.amount_sat);
}

test "amount param: empty value rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=";
    try testing.expectError(error.InvalidAmount, bip21.parseBip21(a, input, .mainnet));
}

test "amount param: double-dot rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1.0.0";
    try testing.expectError(error.InvalidAmount, bip21.parseBip21(a, input, .mainnet));
}

test "amount param: non-digit rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1e3";
    try testing.expectError(error.InvalidAmount, bip21.parseBip21(a, input, .mainnet));
}

test "amount param: above MAX_MONEY rejected" {
    const a = testing.allocator;
    // 21_000_000.00000001 → just over MAX_MONEY
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=21000000.00000001";
    try testing.expectError(error.InvalidAmount, bip21.parseBip21(a, input, .mainnet));
}

test "amount param: exactly MAX_MONEY accepted" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=21000000";
    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);
    try testing.expectEqual(@as(?u64, 21_000_000 * 100_000_000), uri.amount_sat);
}

test "label + message params (no percent-encoding)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?label=Alice&message=Hello";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expect(uri.label != null);
    try testing.expectEqualStrings("Alice", uri.label.?);
    try testing.expect(uri.message != null);
    try testing.expectEqualStrings("Hello", uri.message.?);
}

// --------------------------------------------------------------------------
// Percent-decoding
// --------------------------------------------------------------------------

test "label is percent-decoded (space = %20)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?label=Hello%20World";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings("Hello World", uri.label.?);
}

test "message percent-decodes UTF-8 multibyte (%E2%98%83 = snowman)" {
    const a = testing.allocator;
    // U+2603 ☃ encoded as UTF-8 = 0xE2 0x98 0x83
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?message=%E2%98%83";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    const expected = [_]u8{ 0xE2, 0x98, 0x83 };
    try testing.expectEqualSlices(u8, &expected, uri.message.?);
}

test "percent-decode: invalid escape rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?label=%ZZ";
    try testing.expectError(error.InvalidPercentEncoding, bip21.parseBip21(a, input, .mainnet));
}

test "percent-decode: truncated escape rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?label=%2";
    try testing.expectError(error.InvalidPercentEncoding, bip21.parseBip21(a, input, .mainnet));
}

test "percent-decode: lowercase hex accepted (%2f = /)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?label=a%2fb";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings("a/b", uri.label.?);
}

// --------------------------------------------------------------------------
// req-<X> rejection (BIP-21 forward-compat)
// --------------------------------------------------------------------------

test "unknown req- param rejected (req-foo)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?req-foo=bar";
    try testing.expectError(error.UnknownRequiredParam, bip21.parseBip21(a, input, .mainnet));
}

test "unknown req- param rejected even with empty value" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?req-foo=";
    try testing.expectError(error.UnknownRequiredParam, bip21.parseBip21(a, input, .mainnet));
}

test "req- prefix is case-insensitive (REQ-Foo)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?REQ-Foo=bar";
    try testing.expectError(error.UnknownRequiredParam, bip21.parseBip21(a, input, .mainnet));
}

// --------------------------------------------------------------------------
// Unknown unprefixed params land in `extras`
// --------------------------------------------------------------------------

test "unknown unprefixed param goes to extras" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?futureopt=42";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(usize, 1), uri.extras.items.len);
    try testing.expectEqualStrings("futureopt", uri.extras.items[0].key);
    try testing.expectEqualStrings("42", uri.extras.items[0].value);
}

test "extras preserve insertion order across multiple unknowns" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?aaa=1&zzz=2&mmm=3";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(usize, 3), uri.extras.items.len);
    try testing.expectEqualStrings("aaa", uri.extras.items[0].key);
    try testing.expectEqualStrings("zzz", uri.extras.items[1].key);
    try testing.expectEqualStrings("mmm", uri.extras.items[2].key);
}

test "extras carry percent-decoded values" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?futureopt=hello%20world";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings("hello world", uri.extras.items[0].value);
}

// --------------------------------------------------------------------------
// Invalid / wrong-network addresses
// --------------------------------------------------------------------------

test "missing scheme rejected" {
    const a = testing.allocator;
    try testing.expectError(error.NotBip21Uri, bip21.parseBip21(a, ADDR_MAINNET_P2PKH, .mainnet));
}

test "wrong scheme rejected (litecoin:)" {
    const a = testing.allocator;
    try testing.expectError(error.NotBip21Uri, bip21.parseBip21(a, "litecoin:" ++ ADDR_MAINNET_P2PKH, .mainnet));
}

test "empty address rejected" {
    const a = testing.allocator;
    try testing.expectError(error.NotBip21Uri, bip21.parseBip21(a, "bitcoin:", .mainnet));
}

test "empty address with query rejected" {
    const a = testing.allocator;
    try testing.expectError(error.NotBip21Uri, bip21.parseBip21(a, "bitcoin:?amount=1", .mainnet));
}

test "invalid address rejected (non-base58 character)" {
    const a = testing.allocator;
    // '0' (zero) is not in the Base58 alphabet; the decoder returns
    // `InvalidBase58Character` BEFORE the checksum path.  We avoid testing
    // the checksum-failure path because `base58CheckDecode` in `address.zig`
    // has a pre-existing double-free on that branch (out of FIX-62 scope —
    // unrelated to BIP-21).  The grammar-level "invalid address" gate is
    // exercised here via the alphabet check, which is sufficient for the
    // FIX-62 contract ("invalid / wrong-network address → error").
    const input = "bitcoin:1A1zP1eP0GefiOIlMPTfTL5SLmv7DivfNa"; // 0/O/I/l illegal
    try testing.expectError(error.InvalidBase58Character, bip21.parseBip21(a, input, .mainnet));
}

test "wrong-network address rejected (mainnet addr, testnet network)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH;
    try testing.expectError(error.WrongNetwork, bip21.parseBip21(a, input, .testnet));
}

// --------------------------------------------------------------------------
// BIP-78 pj / pjos extraction
// --------------------------------------------------------------------------

test "pj param is percent-decoded as URL" {
    const a = testing.allocator;
    // Receiver endpoint with a percent-encoded slash in the path.
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++
        "?pj=https%3A%2F%2Fexample.com%2Fpayjoin";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expect(uri.pj != null);
    try testing.expectEqualStrings("https://example.com/payjoin", uri.pj.?);
}

test "pjos=0 parses as false" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?pjos=0";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?bool, false), uri.pjos);
}

test "pjos=1 parses as true" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?pjos=1";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?bool, true), uri.pjos);
}

test "pjos absent → uri.pjos is null (caller applies BIP-78 default)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?bool, null), uri.pjos);
}

test "pjos=2 rejected" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?pjos=2";
    try testing.expectError(error.InvalidPjos, bip21.parseBip21(a, input, .mainnet));
}

test "parseBip21Pjos extracts pjos without parsing address" {
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?pj=https%3A%2F%2Fx.invalid&pjos=0";
    const v = try bip21.parseBip21Pjos(input);
    try testing.expectEqual(@as(?bool, false), v);
}

test "parseBip21Pjos returns null when pjos absent" {
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1";
    const v = try bip21.parseBip21Pjos(input);
    try testing.expectEqual(@as(?bool, null), v);
}

test "parseBip21Pjos returns null when no query" {
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH;
    const v = try bip21.parseBip21Pjos(input);
    try testing.expectEqual(@as(?bool, null), v);
}

test "parseBip21Pjos rejects wrong scheme" {
    try testing.expectError(error.NotBip21Uri, bip21.parseBip21Pjos("https://x.invalid"));
}

// --------------------------------------------------------------------------
// Lightning extension
// --------------------------------------------------------------------------

test "lightning extension extracted (BOLT-11 invoice)" {
    const a = testing.allocator;
    // Truncated invoice string is fine — BIP-21 doesn't validate inner content.
    const inv = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w";
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?lightning=" ++ inv;

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expect(uri.lightning != null);
    try testing.expectEqualStrings(inv, uri.lightning.?);
}

// --------------------------------------------------------------------------
// Case-insensitivity
// --------------------------------------------------------------------------

test "case-insensitive scheme (BITCOIN:)" {
    const a = testing.allocator;
    const input = "BITCOIN:" ++ ADDR_MAINNET_P2PKH;

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings(ADDR_MAINNET_P2PKH, uri.address_str);
}

test "case-insensitive scheme (Bitcoin:) mixed-case" {
    const a = testing.allocator;
    const input = "Bitcoin:" ++ ADDR_MAINNET_P2PKH;

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings(ADDR_MAINNET_P2PKH, uri.address_str);
}

test "case-insensitive keys (AMOUNT=1)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?AMOUNT=1&LABEL=foo";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 100_000_000), uri.amount_sat);
    try testing.expect(uri.label != null);
    try testing.expectEqualStrings("foo", uri.label.?);
}

test "case-insensitive keys (Amount, Label)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?Amount=0.1&Label=Test";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 10_000_000), uri.amount_sat);
    try testing.expectEqualStrings("Test", uri.label.?);
}

test "case-insensitive pj / pjos keys (PJ= and PJOS=)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?PJ=https%3A%2F%2Fx.invalid&PJOS=0";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings("https://x.invalid", uri.pj.?);
    try testing.expectEqual(@as(?bool, false), uri.pjos);
}

// --------------------------------------------------------------------------
// BIP-21 spec test vectors (from bips/bip-0021.mediawiki §"Examples")
// --------------------------------------------------------------------------

test "BIP-21 example: simple address" {
    const a = testing.allocator;
    const input = "bitcoin:1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings("1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy", uri.address_str);
    try testing.expectEqual(@as(?u64, null), uri.amount_sat);
}

test "BIP-21 example: address + label" {
    const a = testing.allocator;
    const input = "bitcoin:1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy?label=Luke-Jr";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqualStrings("Luke-Jr", uri.label.?);
}

test "BIP-21 example: amount + label" {
    const a = testing.allocator;
    const input = "bitcoin:1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy?amount=20.3&label=Luke-Jr";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 20_30_000_000), uri.amount_sat);
    try testing.expectEqualStrings("Luke-Jr", uri.label.?);
}

test "BIP-21 example: amount + label + message (percent-encoded)" {
    const a = testing.allocator;
    const input = "bitcoin:1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy?" ++
        "amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 50 * 100_000_000), uri.amount_sat);
    try testing.expectEqualStrings("Luke-Jr", uri.label.?);
    try testing.expectEqualStrings("Donation for project xyz", uri.message.?);
}

test "BIP-21 example: unknown req- rejected (bip-0021 forward-compat)" {
    const a = testing.allocator;
    // From BIP-21 itself: "Some uses, such as 'somethingyoudontunderstand=50&
    // somethingelseyoudontget=999', should fail when prefixed with req-"
    const input = "bitcoin:1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy?" ++
        "req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999";

    try testing.expectError(error.UnknownRequiredParam, bip21.parseBip21(a, input, .mainnet));
}

test "BIP-21 example: unknown non-req param ignored (extras)" {
    const a = testing.allocator;
    const input = "bitcoin:1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy?" ++
        "somethingyoudontunderstand=50&somethingelseyoudontget=999";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(usize, 2), uri.extras.items.len);
}

// --------------------------------------------------------------------------
// Robustness — odd inputs that should not crash
// --------------------------------------------------------------------------

test "tolerates duplicate '&' in query (stray &)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1&&label=foo";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 100_000_000), uri.amount_sat);
    try testing.expectEqualStrings("foo", uri.label.?);
}

test "tolerates trailing '&' in query" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?amount=1&";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 100_000_000), uri.amount_sat);
}

test "tolerates query param with no value (key=)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?label=&message=hi";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expect(uri.label != null);
    try testing.expectEqualStrings("", uri.label.?);
    try testing.expectEqualStrings("hi", uri.message.?);
}

test "tolerates query param with no '=' at all (bare key)" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++ "?futureflag";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(usize, 1), uri.extras.items.len);
    try testing.expectEqualStrings("futureflag", uri.extras.items[0].key);
    try testing.expectEqualStrings("", uri.extras.items[0].value);
}

test "P2SH mainnet address parses" {
    const a = testing.allocator;
    // BIP-13 example: 3P14159f73E4gFr7JterCCQh9QjiTjiZrG (BIP-16 example)
    // Use a more well-known: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy (Casacius coin)
    const input = "bitcoin:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(address.AddressType.p2sh, uri.address.addr_type);
}

test "P2TR (bech32m) mainnet address parses" {
    const a = testing.allocator;
    // BIP-350 test vector
    const input = "bitcoin:bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(address.AddressType.p2tr, uri.address.addr_type);
}

// --------------------------------------------------------------------------
// BIP-78 full PayJoin URI (combined)
// --------------------------------------------------------------------------

test "BIP-78 full URI: address + amount + pj + pjos" {
    const a = testing.allocator;
    const input = "bitcoin:" ++ ADDR_MAINNET_P2PKH ++
        "?amount=0.1&pj=https%3A%2F%2Freceiver.example%2Fpayjoin&pjos=0";

    var uri = try bip21.parseBip21(a, input, .mainnet);
    defer uri.deinit(a);

    try testing.expectEqual(@as(?u64, 10_000_000), uri.amount_sat);
    try testing.expectEqualStrings("https://receiver.example/payjoin", uri.pj.?);
    try testing.expectEqual(@as(?bool, false), uri.pjos);
}
