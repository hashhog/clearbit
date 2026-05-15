//! BIP-21 URI parser (FIX-62 / W119 prereq).
//!
//! Spec: bips/bip-0021.mediawiki + BIP-78 §"BIP-21 extension".
//!
//! Grammar (BIP-21):
//!
//!   bitcoinurn   = "bitcoin:" bitcoinaddress [ "?" bitcoinparams ]
//!   bitcoinparams= bitcoinparam [ "&" bitcoinparams ]
//!   bitcoinparam = amountparam | labelparam | messageparam | otherparam | reqparam
//!   amountparam  = "amount=" *digit [ "." *digit ]
//!   labelparam   = "label=" *qchar
//!   messageparam = "message=" *qchar
//!   otherparam   = qchar *qchar [ "=" *qchar ]
//!   reqparam     = "req-" qchar *qchar [ "=" *qchar ]
//!
//! BIP-78 extensions (parsed under "extras" — receiver/sender consumes them):
//!
//!   pj    = receiver endpoint URL (BIP-78 PayJoin)
//!   pjos  = "0" | "1" — disableoutputsubstitution toggle (default "1")
//!
//! Lightning extension (parsed under "lightning"): a BOLT-11 invoice string.
//!
//! Error model:
//!
//!   - `error.NotBip21Uri`           — scheme is not `bitcoin:` (case-insensitive)
//!   - `error.UnknownRequiredParam`  — query contains a `req-<X>` key the parser
//!                                     does not understand (BIP-21 §"Forward
//!                                     compatibility" mandates rejection).
//!   - `error.InvalidAmount`         — `amount=` is not a finite decimal in BTC.
//!   - `error.InvalidPercentEncoding`— malformed `%XX` escape.
//!   - any error from `address.Address.decode` (wrong-network, bad checksum, …).
//!
//! Per BIP-21 §"Forward compatibility", **unknown parameters without the
//! `req-` prefix** MUST NOT cause failure; they are returned to the caller via
//! `extras` so the caller may decide whether to surface them.
//!
//! Memory model: the returned `Bip21Uri` owns every allocated slice; call
//! `Bip21Uri.deinit(allocator)` to release them.  Decoded `address` is kept as
//! an `address.Address` (with its hash slice owned by the same allocator).

const std = @import("std");
const address = @import("address.zig");

/// Parsed BIP-21 URI.  Caller owns the memory and must call `deinit`.
pub const Bip21Uri = struct {
    /// Decoded payment address (validated against the supplied network).
    address: address.Address,

    /// Raw address string (case preserved, percent-decoded).  Useful for
    /// senders that want to round-trip the URI verbatim.
    address_str: []const u8,

    /// `amount=` value in BTC, exact decimal — None when the param is absent.
    /// Stored as integer satoshis (1 BTC = 100_000_000 sat).  Senders that
    /// want the original decimal string can find it in `extras` under
    /// `"amount"`.
    amount_sat: ?u64 = null,

    /// `label=` (percent-decoded UTF-8) — None when absent.
    label: ?[]const u8 = null,

    /// `message=` (percent-decoded UTF-8) — None when absent.
    message: ?[]const u8 = null,

    /// BIP-78 receiver endpoint (`pj=`) — percent-decoded URL.
    pj: ?[]const u8 = null,

    /// BIP-78 disable-output-substitution toggle (`pjos=0|1`).  Per the BIP-78
    /// "BIP-21 extension" section, **absent means `1`** (substitution
    /// disabled by default).  Stored as the parsed boolean: `true` means the
    /// receiver MUST NOT substitute its receive output's scriptPubKey.
    pjos: ?bool = null,

    /// Lightning extension (BOLT-11 invoice) — None when absent.
    lightning: ?[]const u8 = null,

    /// Unknown non-`req-` parameters, percent-decoded.  BIP-21 mandates these
    /// must NOT cause failure.  Each entry is a `(key, value)` pair; both
    /// halves are owned by the same allocator that built the Bip21Uri.
    extras: std.ArrayListUnmanaged(KeyValue) = .{},

    pub const KeyValue = struct {
        key: []const u8,
        value: []const u8,
    };

    pub fn deinit(self: *Bip21Uri, allocator: std.mem.Allocator) void {
        self.address.deinit(allocator);
        allocator.free(self.address_str);
        if (self.label) |s| allocator.free(s);
        if (self.message) |s| allocator.free(s);
        if (self.pj) |s| allocator.free(s);
        if (self.lightning) |s| allocator.free(s);
        for (self.extras.items) |kv| {
            allocator.free(kv.key);
            allocator.free(kv.value);
        }
        self.extras.deinit(allocator);
    }
};

/// Decode the BIP-21 URI.  `network` is used to validate the embedded address
/// — a mainnet address parsed against `.testnet` returns
/// `error.WrongNetwork`.
pub fn parseBip21(
    allocator: std.mem.Allocator,
    input: []const u8,
    network: address.Network,
) !Bip21Uri {
    // 1. Strip and validate the `bitcoin:` scheme (case-insensitive per RFC 3986).
    const scheme_lower = "bitcoin:";
    if (input.len < scheme_lower.len) return error.NotBip21Uri;
    {
        var i: usize = 0;
        while (i < scheme_lower.len) : (i += 1) {
            const c = input[i];
            const lc = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
            if (lc != scheme_lower[i]) return error.NotBip21Uri;
        }
    }
    const rest = input[scheme_lower.len..];

    // 2. Split off the query string at the first '?'.
    var addr_part: []const u8 = rest;
    var query_part: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q_idx| {
        addr_part = rest[0..q_idx];
        query_part = rest[q_idx + 1 ..];
    }

    // 3. Percent-decode and validate the address.  The order of cleanup is
    //    subtle: once `uri` is constructed, every subsequent error returns
    //    via the single `errdefer uri.deinit(...)` — earlier errdefers on
    //    `addr_decoded` and `addr` would double-free.  We therefore narrow
    //    the early errdefers to the window before `uri` exists.
    const addr_decoded = blk_addr: {
        errdefer {} // placeholder; the real cleanup is below
        break :blk_addr try percentDecodeAlloc(allocator, addr_part);
    };
    var uri: Bip21Uri = undefined;
    var uri_initialized = false;
    errdefer {
        if (uri_initialized) {
            uri.deinit(allocator);
        } else {
            // We failed before `uri` was assembled — free what we own so far.
            allocator.free(addr_decoded);
        }
    }
    if (addr_decoded.len == 0) return error.NotBip21Uri;

    var addr = address.Address.decode(addr_decoded, allocator) catch |e| {
        return e;
    };
    // From here on, the only cleanup path is the `uri_initialized` errdefer
    // above — but `addr` is not yet owned by `uri`.  Free its hash on the
    // wrong-network early-out.
    if (addr.network != network) {
        addr.deinit(allocator);
        return error.WrongNetwork;
    }

    uri = Bip21Uri{
        .address = addr,
        .address_str = addr_decoded,
    };
    uri_initialized = true;

    // 4. Walk the query, one `key[=value]` pair at a time.
    if (query_part.len == 0) return uri;

    var it = std.mem.splitScalar(u8, query_part, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue; // tolerate stray '&'.

        var key_raw: []const u8 = pair;
        var val_raw: []const u8 = "";
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq_idx| {
            key_raw = pair[0..eq_idx];
            val_raw = pair[eq_idx + 1 ..];
        }
        if (key_raw.len == 0) continue;

        // Lowercase the key for matching (per BIP-21 case-insensitivity).
        // We keep the original case for unknown-key reporting in `extras`.
        const key_lower = try toLowerAlloc(allocator, key_raw);
        defer allocator.free(key_lower);

        // BIP-21 §"Forward compatibility": unknown `req-<X>` MUST reject.
        const is_required = std.mem.startsWith(u8, key_lower, "req-");
        const matched = try assignParam(&uri, allocator, key_lower, val_raw);
        if (!matched) {
            if (is_required) return error.UnknownRequiredParam;
            // Otherwise stash percent-decoded copy in extras.
            const k_copy = try percentDecodeAlloc(allocator, key_raw);
            errdefer allocator.free(k_copy);
            const v_copy = try percentDecodeAlloc(allocator, val_raw);
            errdefer allocator.free(v_copy);
            try uri.extras.append(allocator, .{ .key = k_copy, .value = v_copy });
        }
    }

    return uri;
}

/// Subset of `parseBip21` that only extracts the `pjos=` value from a URI
/// (returns `null` when absent, `true` for "1", `false` for "0").  Provided
/// because BIP-78 senders frequently want a one-shot extraction without
/// parsing the address.
pub fn parseBip21Pjos(input: []const u8) !?bool {
    // Locate the query string.
    const scheme_lower = "bitcoin:";
    if (input.len < scheme_lower.len) return error.NotBip21Uri;
    var i: usize = 0;
    while (i < scheme_lower.len) : (i += 1) {
        const c = input[i];
        const lc = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
        if (lc != scheme_lower[i]) return error.NotBip21Uri;
    }
    const rest = input[scheme_lower.len..];
    const q_idx = std.mem.indexOfScalar(u8, rest, '?') orelse return null;
    const query_part = rest[q_idx + 1 ..];

    var it = std.mem.splitScalar(u8, query_part, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq_idx = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key_raw = pair[0..eq_idx];
        const val_raw = pair[eq_idx + 1 ..];
        if (key_raw.len != 4) continue;
        // Case-insensitive "pjos" match.
        var k_buf: [4]u8 = undefined;
        for (key_raw, 0..) |c, j| {
            k_buf[j] = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
        }
        if (!std.mem.eql(u8, &k_buf, "pjos")) continue;
        return try parsePjosValue(val_raw);
    }
    return null;
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn assignParam(
    uri: *Bip21Uri,
    allocator: std.mem.Allocator,
    key_lower: []const u8,
    val_raw: []const u8,
) !bool {
    if (std.mem.eql(u8, key_lower, "amount")) {
        // amount is NOT percent-encoded per BIP-21, but tolerate it anyway.
        const v_decoded = try percentDecodeAlloc(allocator, val_raw);
        defer allocator.free(v_decoded);
        uri.amount_sat = try parseAmountBtc(v_decoded);
        return true;
    }
    if (std.mem.eql(u8, key_lower, "label")) {
        uri.label = try percentDecodeAlloc(allocator, val_raw);
        return true;
    }
    if (std.mem.eql(u8, key_lower, "message")) {
        uri.message = try percentDecodeAlloc(allocator, val_raw);
        return true;
    }
    if (std.mem.eql(u8, key_lower, "pj")) {
        uri.pj = try percentDecodeAlloc(allocator, val_raw);
        return true;
    }
    if (std.mem.eql(u8, key_lower, "pjos")) {
        const v_decoded = try percentDecodeAlloc(allocator, val_raw);
        defer allocator.free(v_decoded);
        uri.pjos = try parsePjosValue(v_decoded);
        return true;
    }
    if (std.mem.eql(u8, key_lower, "lightning")) {
        uri.lightning = try percentDecodeAlloc(allocator, val_raw);
        return true;
    }
    return false;
}

fn parsePjosValue(v: []const u8) !bool {
    if (v.len == 1 and v[0] == '0') return false;
    if (v.len == 1 and v[0] == '1') return true;
    return error.InvalidPjos;
}

/// Parse a BIP-21 `amount=` decimal-BTC string into satoshis.  The grammar is
/// strict: `[0-9]+(\.[0-9]{1,8})?` — no exponent, no leading `+`, no negative.
/// Returns `error.InvalidAmount` on any deviation, including overflow past
/// 21_000_000 BTC (MAX_MONEY: 21_000_000 * 1e8 = 2_100_000_000_000_000 sat).
fn parseAmountBtc(s: []const u8) !u64 {
    if (s.len == 0) return error.InvalidAmount;
    const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;

    var int_part: u64 = 0;
    var frac_part: u64 = 0;
    var frac_digits: u32 = 0;
    var saw_dot = false;
    var saw_digit = false;

    for (s) |c| {
        if (c == '.') {
            if (saw_dot) return error.InvalidAmount;
            saw_dot = true;
            continue;
        }
        if (c < '0' or c > '9') return error.InvalidAmount;
        saw_digit = true;
        const d: u64 = c - '0';
        if (saw_dot) {
            if (frac_digits >= 8) return error.InvalidAmount;
            frac_part = frac_part * 10 + d;
            frac_digits += 1;
        } else {
            int_part = std.math.mul(u64, int_part, 10) catch return error.InvalidAmount;
            int_part = std.math.add(u64, int_part, d) catch return error.InvalidAmount;
        }
    }
    if (!saw_digit) return error.InvalidAmount;

    // Scale fractional part up to 8 decimals.
    while (frac_digits < 8) : (frac_digits += 1) {
        frac_part *= 10;
    }
    const int_sat = std.math.mul(u64, int_part, 100_000_000) catch return error.InvalidAmount;
    const total = std.math.add(u64, int_sat, frac_part) catch return error.InvalidAmount;
    if (total > MAX_MONEY_SAT) return error.InvalidAmount;
    return total;
}

fn percentDecodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = try std.ArrayList(u8).initCapacity(allocator, input.len);
    errdefer out.deinit();
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const c = input[i];
        if (c == '%') {
            if (i + 2 >= input.len) return error.InvalidPercentEncoding;
            const hi = try hexDigit(input[i + 1]);
            const lo = try hexDigit(input[i + 2]);
            try out.append((hi << 4) | lo);
            i += 2;
        } else if (c == '+') {
            // BIP-21 doesn't mandate '+' → space, but for label/message the
            // common practice (application/x-www-form-urlencoded) treats '+'
            // as a literal space.  We keep '+' literal here because BIP-21
            // uses RFC 3986 query encoding and the spec only mentions
            // percent-encoding.  Real-world wallets vary on this; senders
            // should percent-encode '+' if they mean it.
            try out.append('+');
        } else {
            try out.append(c);
        }
    }
    return out.toOwnedSlice();
}

fn hexDigit(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidPercentEncoding,
    };
}

fn toLowerAlloc(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        out[i] = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
    }
    return out;
}

// ----------------------------------------------------------------------------
// Compile-time sanity: re-export presence for tests.
// ----------------------------------------------------------------------------

comptime {
    _ = parseBip21;
    _ = parseBip21Pjos;
    _ = Bip21Uri;
}
