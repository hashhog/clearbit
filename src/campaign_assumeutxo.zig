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
//!     m_chain_tx_count} + optional base_mtp / base_header /
//!     base_tail_headers), validate, and expose the entries via `entries()`
//!     for the caller (`Config.getNetworkParams`) to append to the RUNNING
//!     network's assumeutxo allowlist.
//!   - On any collision with a built-in entry (same height OR same block
//!     hash) or a duplicate within the campaign file itself: refuse to start
//!     (FATAL + exit). Campaign data may never override a production hash.
//!
//! SECURITY: this module implements only the parse/validate/merge mechanics.
//! The actual guard against production (mainnet P2P) use is external:
//! `tools/start_mainnet.sh` refuses to launch any node with this env var set
//! (launcher guard, mandatory + uniform). See the spec's "Security note".
//!
//! What "validate" does and does not mean here: a `base_tail_headers` band's
//! CONTENTS are pinned to reality by hash-linkage down from the entry's own
//! blockhash (plus a per-header PoW gate), but the entry's `height` is TRUSTED
//! FIXTURE INPUT and no header-local check can attest it. A genuine band
//! declared at a wrong height installs a difficulty history that never existed
//! there. Full argument on `stageBaseTailHeaders`; this is the reason the
//! launcher guard is load-bearing rather than merely tidy.
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

/// Bound on base-tail headers accepted across ALL entries in one campaign
/// file. The shipped fixtures carry 2027 per entry (a full 2016-block retarget
/// window plus the 11-block BIP-113 window plus slack) and exactly one entry;
/// this leaves room for four such entries while keeping the storage a fixed
/// static array, matching MAX_ENTRIES' no-heap-growth rule.
pub const MAX_BASE_TAIL_HEADERS: usize = 8192;

var g_mu: std.Thread.Mutex = .{};
var g_loaded: bool = false;
var g_entries_buf: [MAX_ENTRIES]consensus.AssumeUtxoData = undefined;
var g_entries_len: usize = 0;
/// Backing store for every entry's `base_tail_headers` slice. Entries in
/// `g_entries_buf` point into this; both live for the life of the process.
///
/// COST NOTE for anyone copying this pattern: at 8192 x 116 bytes this is a
/// ~950 KB ALWAYS-RESIDENT static, present whether or not the env var is set,
/// and it is roughly 95% of the whole binary's `.bss` (measured 2026-09-05:
/// `nm -S` reports 950,272 bytes for this symbol against a 1,003,392-byte
/// `.bss`). The no-heap-growth rule that motivates it is worth the page cost
/// here, but it is not free and it is not small.
var g_tail_buf: [MAX_BASE_TAIL_HEADERS]consensus.BaseTailHeader = undefined;
var g_tail_len: usize = 0;

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

/// Parse an 80-byte serialized block header from its wire-order hex (the form
/// Core's `getblockheader <hash> false` prints — NOT display order; only the
/// standalone hash fields in this schema are display-ordered).
fn parseHeader80(hex: []const u8) ![80]u8 {
    if (hex.len != 160) return error.InvalidHeaderHexLength;
    var raw: [80]u8 = undefined;
    var i: usize = 0;
    while (i < 80) : (i += 1) {
        raw[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch return error.InvalidHeaderHex;
    }
    return raw;
}

/// Block hash (double-SHA256 of the 80-byte header) in internal byte order —
/// the order CF_BLOCK_INDEX is keyed by and `AssumeUtxoData.block_hash` holds.
fn headerHash(raw: *const [80]u8) types.Hash256 {
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &first, .{});
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &out, .{});
    return out;
}

/// Stage one entry's real pre-base headers into `g_tail_buf` and return the
/// slice to hand to `AssumeUtxoData.base_tail_headers`.
///
/// WHY THIS IS NOT OPTIONAL DECORATION. A UTXO snapshot carries coins, not
/// headers. Without real headers the `--load-snapshot` import writes an
/// ALL-ZERO placeholder block-index row for the base (main.zig, the `else`
/// arm of the base-tail block), so the base's nBits reads back as 0. The first
/// header above the base then resolves a REQUIRED nBits of 0, which
/// `PeerManager.computeRequiredBits` rightly refuses to compare against
/// (`.undecidable`), so `validateHeaderBatch` admits nothing, the batch is
/// dropped with no penalty, no block is ever requested, and the node sits at
/// the base forever with a healthy peer feeding it headers it cannot judge.
/// Core never reaches this state: it requires the base block's real header to
/// already be in the block index before a snapshot may be activated
/// (validation.cpp ActivateSnapshot, "Did not find snapshot start
/// blockheader"), so `GetNextWorkRequired(pindexPrev)` always has real bits.
/// This function is how a campaign base gets the same guarantee.
///
/// WHAT IS AND IS NOT PROVEN HERE. Read this before describing the band as
/// "validated" anywhere else; the distinction is the whole security story.
///
///   PROVEN -- the band's CONTENTS. Every element is hashed; every element's
///   prev_block must equal the hash of the element before it; the LAST element
///   must hash to the entry's declared `blockhash`. Those three are a DOWNWARD
///   INDUCTION, not three independent spot checks: the terminal element is
///   pinned by hash, which pins its prev_block, which pins the element below
///   it, and so on to the bottom of the band. So if the terminal anchor is a
///   GENUINE block hash then -- absent a SHA-256d preimage break -- every
///   header in the band is the genuine header of a real block, carrying that
///   block's real nBits and real timestamp. Tampering with any byte of any
///   element is refused: a middle or leading edit breaks linkage, a trailing
///   edit breaks the anchor.
///
///   PROVEN -- proof of work, per header, below. Given the induction above
///   this is REDUNDANT whenever the anchor is genuine, and it is here anyway
///   for two reasons: so this module's guarantee does not silently depend on a
///   check that lives in a different file (main.zig only reaches this data via
///   `findAssumeUtxoEntry`, matching the entry against the snapshot file's own
///   base hash), and so a wholly fabricated band is refused AT PARSE TIME
///   instead of sitting in `entries()` until something downstream happens to
///   reject it. It does NOT address the height problem below -- a genuine
///   header has valid PoW no matter what height it is claimed to sit at.
///
///   NOT PROVEN -- the band's absolute HEIGHT. `height` is trusted fixture
///   input. Nothing local to a header band can attest an absolute height:
///   headers carry no height field, and a genuine band has valid PoW and valid
///   linkage at any claimed height. The derivation below fixes only the band's
///   heights RELATIVE to that claimed anchor. A fixture pairing a genuine band
///   with a wrong `height` installs a genuine difficulty history at heights it
///   never occupied, and `computeRequiredBits` then demands that difficulty of
///   the blocks above the base. Measured 2026-09-05: the real height-6299 band
///   declared as `"height": 700000` made `getblocktemplate` ask for difficulty
///   1 at height 700001, and the retarget window opening at 699552 landed
///   inside the mislabelled band too, so it does not self-correct at the next
///   boundary. THIS is why the env var is development-only and why
///   `tools/start_mainnet.sh` refuses to launch any node with it set.
///
///   Core does not validate its way out of this class -- it avoids the class.
///   `ActivateSnapshot` (validation.cpp, "Did not find snapshot start
///   blockheader") requires the base block's real header to ALREADY be in a
///   genesis-connected block index, so the height is attested by the header
///   chain itself and is never taken from the snapshot's provenance.
///
/// Accepts the fixture's ascending `base_tail_headers` chain (last element IS
/// the base block), falling back to a lone `base_header`. A one-element chain
/// unblocks base+1 but cannot answer a retarget window that reaches below the
/// base, which is why the shipped fixtures carry 2016+ of them.
fn stageBaseTailHeaders(
    obj: std.json.ObjectMap,
    height: u32,
    block_hash: types.Hash256,
    params: *const consensus.NetworkParams,
) ![]const consensus.BaseTailHeader {
    const start = g_tail_len;

    if (obj.get("base_tail_headers")) |v| {
        if (v != .array) return error.InvalidBaseTailHeaders;
        for (v.array.items) |it| {
            if (it != .string) return error.InvalidBaseTailHeaders;
            if (g_tail_len >= MAX_BASE_TAIL_HEADERS) return error.TooManyBaseTailHeaders;
            g_tail_buf[g_tail_len] = .{
                .height = 0, // real heights assigned once the length is known
                .hash = undefined,
                .raw = try parseHeader80(it.string),
            };
            g_tail_len += 1;
        }
    }
    if (g_tail_len == start) {
        if (obj.get("base_header")) |v| {
            if (v != .string) return error.InvalidBaseHeader;
            if (g_tail_len >= MAX_BASE_TAIL_HEADERS) return error.TooManyBaseTailHeaders;
            g_tail_buf[g_tail_len] = .{
                .height = 0,
                .hash = undefined,
                .raw = try parseHeader80(v.string),
            };
            g_tail_len += 1;
        }
    }
    const n = g_tail_len - start;
    if (n == 0) return &[_]consensus.BaseTailHeader{}; // optional; placeholder path still applies

    const chain = g_tail_buf[start..g_tail_len];
    // Hash every element and gate each on its OWN declared target, the two
    // checks Core folds into CheckProofOfWork (pow.cpp): the target must not
    // be above the network's pow_limit, and the header hash must meet it.
    // Mirrors `consensus.validateProofOfWork`, done on raw bytes here because
    // the band is stored serialized. A garbage nBits decodes to a zero target
    // via `bitsToTarget`, which no real hash can meet, so this is fail-closed.
    // Reminder: this says nothing about the band's absolute height.
    for (chain) |*e| {
        e.hash = headerHash(&e.raw);
        const bits = std.mem.readInt(u32, e.raw[72..76], .little);
        const target = consensus.bitsToTarget(bits);
        if (!consensus.hashMeetsTarget(&target, &params.pow_limit)) {
            return error.BaseTailHeaderTargetAbovePowLimit;
        }
        if (!consensus.hashMeetsTarget(&e.hash, &target)) {
            return error.BaseTailHeaderInsufficientPow;
        }
    }

    // The chain must END at the snapshot base: the import path persists its
    // last element IN PLACE OF the all-zero placeholder, keyed by that hash.
    if (!std.mem.eql(u8, &chain[n - 1].hash, &block_hash)) {
        return error.BaseTailHeadersDoNotEndAtBase;
    }
    // ...and be a genuine ancestry, not an arbitrary bag: header[i].prev_block
    // (bytes 4..36, already internal order on the wire) == hash(header[i-1]).
    var i: usize = 1;
    while (i < n) : (i += 1) {
        if (!std.mem.eql(u8, chain[i].raw[4..36], &chain[i - 1].hash)) {
            return error.BaseTailHeadersNotContiguous;
        }
    }
    if (n - 1 > height) return error.BaseTailHeadersBelowGenesis;
    const start_height: u32 = height - @as(u32, @intCast(n - 1));
    // A band that reaches down to height 0 must reach GENESIS. Heights are
    // derived, not carried, so without this a fixture could file an ordinary
    // header under height 0, where the import path's "H:" height index write
    // would shadow the real genesis for every height-keyed lookup.
    if (start_height == 0 and !std.mem.eql(u8, &chain[0].hash, &params.genesis_hash)) {
        return error.BaseTailHeadersDoNotStartAtGenesis;
    }
    for (chain, 0..) |*e, k| e.height = start_height + @as(u32, @intCast(k));
    return chain;
}

/// Ensure the campaign table has been loaded (idempotent, thread-safe,
/// exactly-once). `params` is the SELECTED network's comptime params, used
/// read-only for three things: its `assume_utxo` table (collision detection),
/// its `pow_limit` (the base-tail band's PoW gate) and its `genesis_hash` (the
/// band's bottom-of-chain rule). Never mutated.
///
/// Unset/empty env var: returns immediately after the getenv call, having
/// touched nothing else (the "bit-identical" contract).
///
/// On a validation failure (bad hex, non-positive height, duplicate, or a
/// collision with a built-in entry) this prints a FATAL message and exits
/// the process — campaign data must never silently coexist with a bad or
/// colliding entry.
pub fn ensureLoaded(allocator: std.mem.Allocator, params: *const consensus.NetworkParams) void {
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

    loadFromPath(allocator, path, params, params.assume_utxo) catch |err| {
        std.debug.print(
            "[CAMPAIGN-ASSUMEUTXO] FATAL: failed to load {s}={s}: {}\n",
            .{ ENV_VAR, path, err },
        );
        std.process.exit(1);
    };
}

/// `builtin_entries` stays a separate parameter from `params` (rather than
/// being read off `params.assume_utxo`) so the tests below can drive collision
/// detection with an explicit table — including the empty one — independently
/// of which network's consensus constants are in play. `ensureLoaded` passes
/// `params.assume_utxo`, which is the production wiring.
fn loadFromPath(
    allocator: std.mem.Allocator,
    path: []const u8,
    params: *const consensus.NetworkParams,
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
    // Staged tail headers go straight into the process-lifetime backing store;
    // a load that fails partway leaves it dirty, so reset here rather than on
    // the (process-exiting) error path.
    g_tail_len = 0;

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

        // Optional: base_mtp (mainnet post-snapshot BIP-113 proxy).
        //
        // `base_header` / `base_tail_headers` ARE consumed (see
        // stageBaseTailHeaders): they become the entry's `base_tail_headers`,
        // which the `--load-snapshot` import persists in place of the all-zero
        // placeholder row for the base. Dropping them — as this parser did
        // until 2026-09-05 — leaves the base with nBits=0, which makes the
        // required-difficulty walk undecidable for the first header above the
        // base and wedges P2P forward sync at the base permanently.
        // `chainwork` remains parsed-and-ignored: clearbit's AssumeUtxoData
        // carries no field for it and the min-chain-work gate is already
        // skipped at/above a known snapshot base (peer.zig past_snapshot_base).
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

        const base_tail = try stageBaseTailHeaders(obj, height, block_hash, params);

        staged[staged_len] = .{
            .height = height,
            .block_hash = block_hash,
            .hash_serialized = hash_serialized,
            .chain_tx_count = chain_tx_count,
            .base_mtp = base_mtp,
            .base_tail_headers = base_tail,
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
    std.debug.print("] base_tail_headers={d}\n", .{g_tail_len});
}

/// Test-only: reset process-global state between test cases.
pub fn resetForTest() void {
    g_mu.lock();
    defer g_mu.unlock();
    g_loaded = false;
    g_entries_len = 0;
    g_tail_len = 0;
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

    try loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{});

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
    try testing.expectError(error.CollidesWithBuiltinEntry, loadFromPath(testing.allocator, path, &consensus.MAINNET, &builtin));
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
    try testing.expectError(error.CollidesWithBuiltinEntry, loadFromPath(testing.allocator, path, &consensus.MAINNET, builtin));
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

    try testing.expectError(error.DuplicateCampaignEntry, loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{}));
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

    try testing.expectError(error.InvalidHeight, loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{}));
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

    try testing.expectError(error.InvalidHexLength, loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{}));
    resetForTest();
}

// The 2026-09-05 regression: this parser accepted `base_tail_headers` and threw
// them away, so `--load-snapshot` wrote an all-zero placeholder header for the
// base. Required-nBits above the base then resolved to 0, every inbound headers
// batch was undecidable at header 0, and clearbit sat at the snapshot base
// forever with a healthy peer feeding it headers (range 91795->91825: STALLED).
// Real mainnet headers 91794 and 91795 below; the last one hashes to the entry's
// own blockhash, which is what makes the chain usable as the base's real header.
const TEST_HDR_91794 = "01000000df71cae304b622a2c3dfb73dac9de75edba5176207d5e810febe0700000000006ee35421768887732e04d6ce8a3332d1398289c492939349112abb461648c5e81d0be04c56720e1b229c15d0";
const TEST_HDR_91795 = "01000000a79bbdc164d475467f08f0a3df24612a359fae2f308b70326ea2050000000000bb51e40f36cdbd9b62c3a09348bcfc88eec5a21d0abf9a44d1c7db9195a41eb3680ce04c56720e1b268cd276";

test "campaign_assumeutxo: base_tail_headers are consumed, hashed, and height-stamped" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const json = try std.fmt.allocPrint(testing.allocator,
        \\[ {{ "height": 91795,
        \\    "blockhash": "000000000008efd439511811080d3a7d832f862395ca0c1fc8cb060a72a8f7a8",
        \\    "hash_serialized": "cf05f1d9aaf934cd6dae809e2c318e226f36b6c49a4a47a7553deae8406cf53e",
        \\    "m_chain_tx_count": 142698,
        \\    "base_tail_headers": ["{s}", "{s}"] }} ]
    , .{ TEST_HDR_91794, TEST_HDR_91795 });
    defer testing.allocator.free(json);
    const path = try writeTempJson(tmp_dir.dir, "campaign.json", json);
    defer testing.allocator.free(path);

    try loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{});
    const got = entries();
    try testing.expectEqual(@as(usize, 1), got.len);
    const tail = got[0].base_tail_headers;
    try testing.expectEqual(@as(usize, 2), tail.len);
    try testing.expectEqual(@as(u32, 91_794), tail[0].height);
    try testing.expectEqual(@as(u32, 91_795), tail[1].height);
    // The last entry IS the base, keyed by the same hash the import writes.
    try testing.expectEqualSlices(u8, &got[0].block_hash, &tail[1].hash);
    // A real header, not the all-zero placeholder: nBits 0x1b0e7256.
    try testing.expectEqual(@as(u32, 0x1b0e7256), std.mem.readInt(u32, tail[1].raw[72..76], .little));
    resetForTest();
}

test "campaign_assumeutxo: base_tail_headers must end at the snapshot base" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    // Same two headers, reversed: the chain no longer ends at `blockhash`, so it
    // cannot stand in for the base's block-index row. Refuse rather than persist
    // a header under the wrong key.
    const json = try std.fmt.allocPrint(testing.allocator,
        \\[ {{ "height": 91795,
        \\    "blockhash": "000000000008efd439511811080d3a7d832f862395ca0c1fc8cb060a72a8f7a8",
        \\    "hash_serialized": "cf05f1d9aaf934cd6dae809e2c318e226f36b6c49a4a47a7553deae8406cf53e",
        \\    "m_chain_tx_count": 142698,
        \\    "base_tail_headers": ["{s}", "{s}"] }} ]
    , .{ TEST_HDR_91795, TEST_HDR_91794 });
    defer testing.allocator.free(json);
    const path = try writeTempJson(tmp_dir.dir, "campaign.json", json);
    defer testing.allocator.free(path);

    try testing.expectError(error.BaseTailHeadersDoNotEndAtBase, loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{}));
    resetForTest();
}

test "campaign_assumeutxo: a lone base_header is accepted as a one-block chain" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const json = try std.fmt.allocPrint(testing.allocator,
        \\[ {{ "height": 91795,
        \\    "blockhash": "000000000008efd439511811080d3a7d832f862395ca0c1fc8cb060a72a8f7a8",
        \\    "hash_serialized": "cf05f1d9aaf934cd6dae809e2c318e226f36b6c49a4a47a7553deae8406cf53e",
        \\    "m_chain_tx_count": 142698,
        \\    "base_header": "{s}" }} ]
    , .{TEST_HDR_91795});
    defer testing.allocator.free(json);
    const path = try writeTempJson(tmp_dir.dir, "campaign.json", json);
    defer testing.allocator.free(path);

    try loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{});
    const tail = entries()[0].base_tail_headers;
    try testing.expectEqual(@as(usize, 1), tail.len);
    try testing.expectEqual(@as(u32, 91_795), tail[0].height);
    resetForTest();
}

test "campaign_assumeutxo: an entry with no header fields still loads (schema-optional)" {
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

    try loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{});
    try testing.expectEqual(@as(usize, 0), entries()[0].base_tail_headers.len);
    resetForTest();
}

// ── 2026-09-05 adversarial probe: the three gaps it found ───────────────────
// A hostile fixture was walked through the parser and, where it got that far,
// through `--load-snapshot` against a real UTXO snapshot. Contents held (every
// tamper bounced off linkage or the anchor); these are the cases that did not.

/// Fabricated header: plausible mainnet nBits (0x1d00ffff) but no work behind
/// it. Its own hash 052054de… is far above the 00000000ffff… target.
const TEST_HDR_FABRICATED_NO_POW = "010000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111100f15365ffff001d00000000";
const TEST_HASH_FABRICATED_NO_POW = "052054defd7a24f7ab532d207979c9cc31987a81a53bbba049805e423f7119df";
/// Same body with regtest nBits (0x207fffff): it DOES meet its own absurd
/// target, so only the pow_limit gate can catch it on mainnet params.
const TEST_HDR_TARGET_ABOVE_LIMIT = "010000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111100f15365ffff7f2000000000";
const TEST_HASH_TARGET_ABOVE_LIMIT = "7191afd24462547aa825ff538cfcc8842f04fe7f0467c872ca1f1f5a6596868f";

test "campaign_assumeutxo: a self-consistent but fabricated band is refused (no PoW)" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    // The band is INTERNALLY consistent — the entry declares as its blockhash
    // exactly the hash of the header it ships — so hash-linkage alone cannot
    // reject it. Before the PoW gate this loaded, and was caught (if at all)
    // only downstream, when `findAssumeUtxoEntry` failed to match a real
    // snapshot's base hash. Now it dies at parse time.
    const json = try std.fmt.allocPrint(testing.allocator,
        \\[ {{ "height": 600001,
        \\    "blockhash": "{s}",
        \\    "hash_serialized": "cf05f1d9aaf934cd6dae809e2c318e226f36b6c49a4a47a7553deae8406cf53e",
        \\    "m_chain_tx_count": 1000,
        \\    "base_tail_headers": ["{s}"] }} ]
    , .{ TEST_HASH_FABRICATED_NO_POW, TEST_HDR_FABRICATED_NO_POW });
    defer testing.allocator.free(json);
    const path = try writeTempJson(tmp_dir.dir, "campaign.json", json);
    defer testing.allocator.free(path);

    try testing.expectError(
        error.BaseTailHeaderInsufficientPow,
        loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{}),
    );
    resetForTest();
}

test "campaign_assumeutxo: a band header whose target exceeds pow_limit is refused" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const json = try std.fmt.allocPrint(testing.allocator,
        \\[ {{ "height": 600001,
        \\    "blockhash": "{s}",
        \\    "hash_serialized": "cf05f1d9aaf934cd6dae809e2c318e226f36b6c49a4a47a7553deae8406cf53e",
        \\    "m_chain_tx_count": 1000,
        \\    "base_header": "{s}" }} ]
    , .{ TEST_HASH_TARGET_ABOVE_LIMIT, TEST_HDR_TARGET_ABOVE_LIMIT });
    defer testing.allocator.free(json);
    const path = try writeTempJson(tmp_dir.dir, "campaign.json", json);
    defer testing.allocator.free(path);

    try testing.expectError(
        error.BaseTailHeaderTargetAbovePowLimit,
        loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{}),
    );
    resetForTest();
}

test "campaign_assumeutxo: a band reaching height 0 must reach genesis" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    // Two REAL mainnet headers (valid PoW, valid linkage, terminating at the
    // declared blockhash) declared at `height: 1`, so the derivation puts
    // header 91794 at height 0. Everything except the bottom-of-chain rule
    // passes; without that rule this loaded and the import path would have
    // written a non-genesis header into the "H:" index at height 0.
    const json = try std.fmt.allocPrint(testing.allocator,
        \\[ {{ "height": 1,
        \\    "blockhash": "000000000008efd439511811080d3a7d832f862395ca0c1fc8cb060a72a8f7a8",
        \\    "hash_serialized": "cf05f1d9aaf934cd6dae809e2c318e226f36b6c49a4a47a7553deae8406cf53e",
        \\    "m_chain_tx_count": 142698,
        \\    "base_tail_headers": ["{s}", "{s}"] }} ]
    , .{ TEST_HDR_91794, TEST_HDR_91795 });
    defer testing.allocator.free(json);
    const path = try writeTempJson(tmp_dir.dir, "campaign.json", json);
    defer testing.allocator.free(path);

    try testing.expectError(
        error.BaseTailHeadersDoNotStartAtGenesis,
        loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{}),
    );
    resetForTest();
}

test "campaign_assumeutxo: the height label is NOT validated (documented gap)" {
    resetForTest();
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    // A GENUINE band (real headers, real PoW, real linkage, real terminal
    // anchor) declared at a height it never occupied. This is ACCEPTED, and
    // that is not an oversight: no header-local check can attest an absolute
    // height. The guard against it is external — the env var is development-
    // only and `tools/start_mainnet.sh` refuses to launch with it set. This
    // test exists so the gap stays visible and cannot be quietly assumed shut.
    const json = try std.fmt.allocPrint(testing.allocator,
        \\[ {{ "height": 700000,
        \\    "blockhash": "000000000008efd439511811080d3a7d832f862395ca0c1fc8cb060a72a8f7a8",
        \\    "hash_serialized": "cf05f1d9aaf934cd6dae809e2c318e226f36b6c49a4a47a7553deae8406cf53e",
        \\    "m_chain_tx_count": 142698,
        \\    "base_tail_headers": ["{s}", "{s}"] }} ]
    , .{ TEST_HDR_91794, TEST_HDR_91795 });
    defer testing.allocator.free(json);
    const path = try writeTempJson(tmp_dir.dir, "campaign.json", json);
    defer testing.allocator.free(path);

    try loadFromPath(testing.allocator, path, &consensus.MAINNET, &.{});
    const tail = entries()[0].base_tail_headers;
    try testing.expectEqual(@as(u32, 699_999), tail[0].height);
    try testing.expectEqual(@as(u32, 700_000), tail[1].height);
    resetForTest();
}
