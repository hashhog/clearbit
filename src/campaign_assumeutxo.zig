//! HASHHOG_CAMPAIGN_ASSUMEUTXO — campaign-only assumeutxo allowlist.
//!
//! hashhog-only mechanism (NOT in Bitcoin Core). Full spec:
//! receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md (meta-repo). Unblocks the M2
//! boundary campaign, which boots each impl with "mainnet params" and fast-
//! forwards a UTXO snapshot to a boundary height without permanently widening
//! any of the 10 impls' production trust tables.
//!
//! Contract:
//!   - Env var `HASHHOG_CAMPAIGN_ASSUMEUTXO=<absolute path to JSON>`.
//!   - Read EXACTLY ONCE per process, on first call to `ensureLoaded`. When
//!     unset or empty: a single getenv call returns "not found" and this
//!     module does nothing else — no file I/O, no table mutation. Bit-
//!     identical to a build without this feature.
//!   - When set: parse the file (array of {height, blockhash, hash_serialized,
//!     m_chain_tx_count} + optional base_mtp), validate, and expose the
//!     entries via `entries()` for the caller (`Config.getNetworkParams`) to
//!     append to the RUNNING network's assumeutxo allowlist.
//!   - On any collision with a built-in entry (same height OR same block
//!     hash) or a duplicate within the campaign file itself: refuse to start
//!     (FATAL + exit). Campaign data may never override a production hash.
//!
//! SECURITY: this module implements only the parse/validate/merge mechanics.
//! The actual guard against production (mainnet P2P) use is external:
//! `tools/start_mainnet.sh` refuses to launch any node with this env var set
//! (launcher guard, mandatory + uniform). See the spec's "Security note".
//!
//! All hex fields are DISPLAY order (as Core's `kernel/chainparams.cpp`
//! prints / `uint256{"..."}` parses), matching every other AssumeUtxoData
//! literal in consensus.zig — converted here with the same reversal
//! `consensus.hexToHash` does at comptime, just at runtime.

const std = @import("std");
const consensus = @import("consensus.zig");
const types = @import("types.zig");

pub const ENV_VAR = "HASHHOG_CAMPAIGN_ASSUMEUTXO";

/// Bound on accepted campaign entries. The M2 boundary campaign fixture is
/// ~17-20 entries; this leaves generous headroom while keeping the merge
/// buffer a fixed-size array — no heap growth on the getNetworkParams() path.
pub const MAX_ENTRIES: usize = 256;

var g_mu: std.Thread.Mutex = .{};
var g_loaded: bool = false;
var g_entries_buf: [MAX_ENTRIES]consensus.AssumeUtxoData = undefined;
var g_entries_len: usize = 0;

/// Campaign entries loaded from the file (empty when unset, on any refusal
/// path that didn't already exit, or before `ensureLoaded` has run once).
pub fn entries() []const consensus.AssumeUtxoData {
    return g_entries_buf[0..g_entries_len];
}

/// Convert a DISPLAY-order (Core-printed) hex hash string to clearbit's
/// internal byte order. Runtime twin of `consensus.hexToHash`, which is
/// comptime-only (fixed-length `*const [64:0]u8` param).
fn parseDisplayHash(hex: []const u8) !types.Hash256 {
    if (hex.len != 64) return error.InvalidHexLength;
    var hash: types.Hash256 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        hash[31 - i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch return error.InvalidHexLength;
    }
    return hash;
}

/// Ensure the campaign table has been loaded (idempotent, thread-safe,
/// exactly-once). `builtin_entries` is the SELECTED network's own comptime
/// `assume_utxo` table (e.g. MAINNET.assume_utxo) — used only to detect
/// collisions; never mutated.
///
/// Unset/empty env var: returns immediately after the getenv call, having
/// touched nothing else (the "bit-identical" contract).
///
/// On a validation failure (bad hex, non-positive height, duplicate, or a
/// collision with a built-in entry) this prints a FATAL message and exits
/// the process — campaign data must never silently coexist with a bad or
/// colliding entry.
pub fn ensureLoaded(allocator: std.mem.Allocator, builtin_entries: []const consensus.AssumeUtxoData) void {
    g_mu.lock();
    defer g_mu.unlock();
    if (g_loaded) return;
    g_loaded = true;

    const path = std.process.getEnvVarOwned(allocator, ENV_VAR) catch |err| {
        switch (err) {
            error.EnvironmentVariableNotFound => {}, // unset: nothing else to do
            else => std.debug.print("[CAMPAIGN-ASSUMEUTXO] warning: could not read {s}: {}\n", .{ ENV_VAR, err }),
        }
        return;
    };
    defer allocator.free(path);
    if (path.len == 0) return; // empty: treat like unset

    loadFromPath(allocator, path, builtin_entries) catch |err| {
        std.debug.print(
            "[CAMPAIGN-ASSUMEUTXO] FATAL: failed to load {s}={s}: {}\n",
            .{ ENV_VAR, path, err },
        );
        std.process.exit(1);
    };
}

fn loadFromPath(
    allocator: std.mem.Allocator,
    path: []const u8,
    builtin_entries: []const consensus.AssumeUtxoData,
) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    // Campaign fixtures are small (~20 entries); 16 MiB is a generous ceiling
    // that still refuses a runaway/garbage file.
    const content = try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(content);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, content, .{});
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidCampaignJson;
    const items = parsed.value.array.items;
    if (items.len == 0) return error.EmptyCampaignFile;
    if (items.len > MAX_ENTRIES) return error.TooManyCampaignEntries;

    var staged: [MAX_ENTRIES]consensus.AssumeUtxoData = undefined;
    var staged_len: usize = 0;

    for (items) |item| {
        if (item != .object) return error.InvalidCampaignEntry;
        const obj = item.object;

        const height_val = obj.get("height") orelse return error.MissingHeight;
        if (height_val != .integer or height_val.integer <= 0) return error.InvalidHeight;
        const height: u32 = std.math.cast(u32, height_val.integer) orelse return error.InvalidHeight;

        const blockhash_val = obj.get("blockhash") orelse return error.MissingBlockhash;
        if (blockhash_val != .string) return error.InvalidBlockhash;
        const block_hash = try parseDisplayHash(blockhash_val.string);

        const hash_serialized_val = obj.get("hash_serialized") orelse return error.MissingHashSerialized;
        if (hash_serialized_val != .string) return error.InvalidHashSerialized;
        const hash_serialized = try parseDisplayHash(hash_serialized_val.string);

        const tx_count_val = obj.get("m_chain_tx_count") orelse return error.MissingChainTxCount;
        if (tx_count_val != .integer or tx_count_val.integer < 0) return error.InvalidChainTxCount;
        const chain_tx_count: u64 = @intCast(tx_count_val.integer);

        // Optional: base_mtp (mainnet post-snapshot BIP-113 proxy). base_header
        // / chainwork are accepted by the shared schema for OTHER impls but
        // clearbit's AssumeUtxoData carries no field for them (its
        // base_tail_headers mechanism serves the same purpose and is not
        // populated from campaign data) — parsed-and-ignored here is correct.
        var base_mtp: u32 = 0;
        if (obj.get("base_mtp")) |bm| {
            if (bm == .integer and bm.integer >= 0) {
                base_mtp = std.math.cast(u32, bm.integer) orelse 0;
            }
        }

        // Refuse collisions with a built-in (production) entry: same height
        // OR same block hash. Campaign data may never override a production
        // hash.
        for (builtin_entries) |b| {
            if (b.height == height or std.mem.eql(u8, &b.block_hash, &block_hash)) {
                return error.CollidesWithBuiltinEntry;
            }
        }
        // Refuse duplicates within the campaign file itself.
        for (staged[0..staged_len]) |s| {
            if (s.height == height or std.mem.eql(u8, &s.block_hash, &block_hash)) {
                return error.DuplicateCampaignEntry;
            }
        }

        staged[staged_len] = .{
            .height = height,
            .block_hash = block_hash,
            .hash_serialized = hash_serialized,
            .chain_tx_count = chain_tx_count,
            .base_mtp = base_mtp,
        };
        staged_len += 1;
    }

    @memcpy(g_entries_buf[0..staged_len], staged[0..staged_len]);
    g_entries_len = staged_len;

    // Loud, greppable startup banner (fleet-monitor alerts if this ever shows
    // up in a production log — see the spec's "Security note" item 3).
    std.debug.print("[CAMPAIGN-ASSUMEUTXO] loaded {d} entries from {s} heights=[", .{ staged_len, path });
    for (staged[0..staged_len], 0..) |s, i| {
        if (i > 0) std.debug.print(",", .{});
        std.debug.print("{d}", .{s.height});
    }
    std.debug.print("]\n", .{});
}

/// Test-only: reset process-global state between test cases.
pub fn resetForTest() void {
    g_mu.lock();
    defer g_mu.unlock();
    g_loaded = false;
    g_entries_len = 0;
}

// ============================================================================
// Tests
//
// These exercise `loadFromPath` directly (it takes an explicit path and
// returns errors rather than exiting), so they don't need to mutate process
// environment variables. `ensureLoaded`'s env-read wrapper is a thin single
// getenv + exit-on-error glue layer, proven by the boot-smoke /
// consensus-difftest integration runs (see PORTER-WAVE-WORKORDER report).
// ============================================================================

const testing = std.testing;

fn writeTempJson(dir: std.fs.Dir, name: []const u8, content: []const u8) ![]const u8 {
    var f = try dir.createFile(name, .{});
    defer f.close();
    try f.writeAll(content);
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try dir.realpath(".", &pbuf);
    return try std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ dir_path, name });
}

test "campaign_assumeutxo: parseDisplayHash matches consensus.hexToHash" {
    const hex = "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397";
    const want = comptime consensus.hexToHash(hex);
    const got = try parseDisplayHash(hex);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "campaign_assumeutxo: parseDisplayHash rejects wrong length" {
    try testing.expectError(error.InvalidHexLength, parseDisplayHash("abcd"));
}

test "campaign_assumeutxo: loadFromPath accepts a valid entry and populates entries()" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try writeTempJson(tmp_dir.dir, "campaign.json",
        \\[ { "height": 481823,
        \\    "blockhash": "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80",
        \\    "hash_serialized": "25429c30cfa0b6051106c29d15b188d746d8e7ecd184bf34fae1cebe2ea447f4",
        \\    "m_chain_tx_count": 249036369 } ]
    );
    defer testing.allocator.free(path);

    try loadFromPath(testing.allocator, path, &.{});

    const got = entries();
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqual(@as(u32, 481823), got[0].height);
    try testing.expectEqual(@as(u64, 249036369), got[0].chain_tx_count);
    const want_hash = comptime consensus.hexToHash("000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80");
    try testing.expectEqualSlices(u8, &want_hash, &got[0].block_hash);
    resetForTest();
}

test "campaign_assumeutxo: loadFromPath refuses collision with builtin (same height)" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try writeTempJson(tmp_dir.dir, "campaign.json",
        \\[ { "height": 840000,
        \\    "blockhash": "1111111111111111111111111111111111111111111111111111111111111111",
        \\    "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
        \\    "m_chain_tx_count": 1 } ]
    );
    defer testing.allocator.free(path);

    const builtin = comptime [_]consensus.AssumeUtxoData{.{
        .height = 840000,
        .block_hash = consensus.hexToHash("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),
        .hash_serialized = consensus.hexToHash("a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"),
        .chain_tx_count = 1,
    }};
    try testing.expectError(error.CollidesWithBuiltinEntry, loadFromPath(testing.allocator, path, &builtin));
    resetForTest();
}

test "campaign_assumeutxo: loadFromPath refuses collision with builtin (same blockhash)" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try writeTempJson(tmp_dir.dir, "campaign.json",
        \\[ { "height": 999999,
        \\    "blockhash": "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
        \\    "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
        \\    "m_chain_tx_count": 1 } ]
    );
    defer testing.allocator.free(path);

    const builtin = consensus.MAINNET.assume_utxo;
    try testing.expectError(error.CollidesWithBuiltinEntry, loadFromPath(testing.allocator, path, builtin));
    resetForTest();
}

test "campaign_assumeutxo: loadFromPath refuses a duplicate height within the file" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try writeTempJson(tmp_dir.dir, "campaign.json",
        \\[ { "height": 500000,
        \\    "blockhash": "1111111111111111111111111111111111111111111111111111111111111111",
        \\    "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
        \\    "m_chain_tx_count": 1 },
        \\  { "height": 500000,
        \\    "blockhash": "3333333333333333333333333333333333333333333333333333333333333333",
        \\    "hash_serialized": "4444444444444444444444444444444444444444444444444444444444444444",
        \\    "m_chain_tx_count": 2 } ]
    );
    defer testing.allocator.free(path);

    try testing.expectError(error.DuplicateCampaignEntry, loadFromPath(testing.allocator, path, &.{}));
    resetForTest();
}

test "campaign_assumeutxo: loadFromPath rejects a non-positive height" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try writeTempJson(tmp_dir.dir, "campaign.json",
        \\[ { "height": 0,
        \\    "blockhash": "1111111111111111111111111111111111111111111111111111111111111111",
        \\    "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
        \\    "m_chain_tx_count": 1 } ]
    );
    defer testing.allocator.free(path);

    try testing.expectError(error.InvalidHeight, loadFromPath(testing.allocator, path, &.{}));
    resetForTest();
}

test "campaign_assumeutxo: loadFromPath rejects an invalid-length blockhash" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try writeTempJson(tmp_dir.dir, "campaign.json",
        \\[ { "height": 500000,
        \\    "blockhash": "abcd",
        \\    "hash_serialized": "2222222222222222222222222222222222222222222222222222222222222222",
        \\    "m_chain_tx_count": 1 } ]
    );
    defer testing.allocator.free(path);

    try testing.expectError(error.InvalidHexLength, loadFromPath(testing.allocator, path, &.{}));
    resetForTest();
}
