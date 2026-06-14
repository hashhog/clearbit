//! AssumeUTXO REAL background-validation second chainstate (clearbit / Zig 0.13)
//!
//! Bitcoin Core v31.99 parity.  This module is the *background* (validated)
//! chainstate of the two-chainstate AssumeUTXO model:
//!
//!   bitcoin-core/src/validation.cpp
//!     ActivateSnapshot              — load-time authenticate + stage snapshot CS
//!     PopulateAndValidateSnapshot   — coins-file → snapshot CS + load-time hash gate
//!     AddChainstate                 — register the BACKGROUND chainstate with its
//!                                     OWN coins db, seeded EMPTY at genesis
//!     MaybeValidateSnapshot         — at base, recompute the BACKGROUND coins'
//!                                     HASH_SERIALIZED, compare to
//!                                     au_data.hash_serialized → VALIDATED+retire
//!                                     / INVALID (never silent)
//!
//! The defining property of the background chainstate (vs the snapshot
//! chainstate the active node serves from) is that its coins are derived by a
//! GENUINE, INDEPENDENT genesis→base block replay — NOT copied from the
//! snapshot file.  That is what makes the final hash comparison meaningful: a
//! tampered snapshot committed to a hash-of-itself sails through the load-time
//! gate (PopulateAndValidateSnapshot hashes the file's own coins), but the
//! background replay re-derives the GENUINE set whose HASH_SERIALIZED differs,
//! and MaybeValidateSnapshot rejects it.  A real second store + an aliasing
//! guard is what guarantees we never accidentally hash the snapshot set and
//! "validate" it against itself.
//!
//! Shape mirrors the landed from-scratch pilots:
//!   rustoshi 5cfa601 (separate store + aliasing guard + dual_cs reject-falsify)
//!   haskoin  c02803b (separate IORef-Map store + StableName aliasing guard)
//!
//! The per-coin TxOutSer byte layout and the SHA256d HashWriter are NOT
//! re-implemented here — they are the SAME routine the active chainstate's
//! `storage.computeHashSerializedTxOutSet` uses (Core kernel/coinstats.cpp
//! TxOutSer + hash.h HashWriter), so the background hash is computed exactly
//! the way the pinned `au_data.hash_serialized` constants were.

const std = @import("std");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");

/// Outcome of background validation (Core SnapshotCompletionResult, narrowed).
pub const ValidationResult = enum {
    /// Background genesis→base re-derivation hash == au_data.hash_serialized.
    /// Core: SnapshotCompletionResult::SUCCESS → unvalidated_cs.m_assumeutxo =
    /// Assumeutxo::VALIDATED (the background chainstate is then retired).
    validated,
    /// Hash mismatch.  Core: SnapshotCompletionResult::HASH_MISMATCH →
    /// handle_invalid_snapshot() → unvalidated_cs.m_assumeutxo =
    /// Assumeutxo::INVALID (node shuts down; NEVER silently accepts).
    invalid,
};

pub const BgError = error{
    /// The background store's backing map aliases the active chainstate's
    /// coins cache — refusing, because hashing it would be a hash-of-self and
    /// the whole point of the second chainstate is an INDEPENDENT derivation.
    AliasesActiveChainstate,
    /// Genesis block was not the first block connected, or a non-genesis block
    /// did not chain onto the running tip — the replay must be a contiguous
    /// genesis→base walk.
    NonContiguousReplay,
    /// connectToBase was asked to validate before reaching the base height.
    BaseNotReached,
    OutOfMemory,
};

/// A coin in the background store.  Owns its scriptPubKey (allocated on the
/// store allocator); freed by `BgChainState.deinit`.  We keep the FULL
/// scriptPubKey (not clearbit's compact form) so the TxOutSer bytes are
/// byte-identical to Core's regardless of script class.
const BgCoin = struct {
    value: i64,
    script: []const u8,
    height: u32,
    is_coinbase: bool,
};

/// HashMap key context for the 36-byte `txid || LE32(vout)` outpoint key.
/// Private mirror of storage.UtxoKeyContext (that one is not pub).
const BgKeyContext = struct {
    pub fn hash(_: BgKeyContext, key: [36]u8) u64 {
        return std.hash.Wyhash.hash(0, &key);
    }
    pub fn eql(_: BgKeyContext, a: [36]u8, b: [36]u8) bool {
        return std.mem.eql(u8, &a, &b);
    }
};

const BgMap = std.HashMap([36]u8, BgCoin, BgKeyContext, std.hash_map.default_max_load_percentage);

/// The background (validated) chainstate: a SEPARATE UTXO store, seeded empty
/// at genesis, populated by a genuine genesis→base block replay.
pub const BgChainState = struct {
    allocator: std.mem.Allocator,
    /// The independent coins store.  Distinct from any active UtxoSet.cache.
    coins: BgMap,
    /// Captured address of the active chainstate's coins cache, recorded at
    /// construction time when an active UtxoSet is supplied.  The aliasing
    /// guard refuses to operate if `&self.coins` ever equals this address.
    /// 0 means "no active chainstate bound" (pure in-memory test use).
    active_cache_addr: usize,
    /// Running tip height of the replay (-1 == nothing connected yet, encoded
    /// as `connected_count == 0`).  We only ever need "did we reach base".
    tip_height: i64,
    /// Whether genesis (height 0) has been connected, to enforce the
    /// contiguous-from-genesis invariant.
    started: bool,

    /// Construct an EMPTY background store.  When `active_utxo` is non-null we
    /// record its cache address so the aliasing guard can later prove the
    /// background store is a DISTINCT object from the active coins.
    ///
    /// IMPORTANT: this does not, and must not, copy any coins from the active
    /// chainstate — it is seeded empty at genesis (Core AddChainstate creates a
    /// fresh CCoinsViewDB with should_wipe semantics for the background CS).
    pub fn init(allocator: std.mem.Allocator, active_utxo: ?*const storage.UtxoSet) BgChainState {
        return .{
            .allocator = allocator,
            .coins = BgMap.init(allocator),
            .active_cache_addr = if (active_utxo) |u| @intFromPtr(&u.cache) else 0,
            .tip_height = -1,
            .started = false,
        };
    }

    pub fn deinit(self: *BgChainState) void {
        var it = self.coins.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.script);
        }
        self.coins.deinit();
    }

    /// Aliasing guard.  Refuse if our backing map IS the active chainstate's
    /// coins cache — that would make any hash we compute a hash-of-self and
    /// defeat the independent re-derivation.  Core keeps the two chainstates as
    /// distinct `Chainstate` objects each owning a separate `CCoinsViewDB`;
    /// this is the explicit clearbit analogue of that separation invariant
    /// (cf. rustoshi 5cfa601 / haskoin c02803b StableName guard).
    pub fn assertNotAliased(self: *const BgChainState) BgError!void {
        if (self.active_cache_addr != 0 and @intFromPtr(&self.coins) == self.active_cache_addr) {
            return BgError.AliasesActiveChainstate;
        }
    }

    /// Add a created coin to the background store.  Skips provably-unspendable
    /// outputs (OP_RETURN / oversize) exactly as Core's CCoinsViewCache /
    /// AddCoins does (it never stores `IsUnspendable()` outputs in the UTXO
    /// set), so the background set matches the snapshot set's membership.
    fn addCoin(
        self: *BgChainState,
        txid: *const types.Hash256,
        vout: u32,
        out: *const types.TxOut,
        height: u32,
        is_coinbase: bool,
    ) BgError!void {
        if (storage.isScriptUnspendable(out.script_pubkey)) return;
        var key: [36]u8 = undefined;
        @memcpy(key[0..32], txid);
        std.mem.writeInt(u32, key[32..36], vout, .little);

        const script_copy = self.allocator.dupe(u8, out.script_pubkey) catch return BgError.OutOfMemory;
        errdefer self.allocator.free(script_copy);

        // Overwrite-safe: free any prior script the slot held (BIP30 duplicate
        // coinbase overwrites; Core EmplaceCoinInternalDANGER replaces).
        if (self.coins.fetchRemove(key)) |old| {
            self.allocator.free(old.value.script);
        }
        self.coins.put(key, .{
            .value = out.value,
            .script = script_copy,
            .height = height,
            .is_coinbase = is_coinbase,
        }) catch return BgError.OutOfMemory;
    }

    /// Spend (remove) a prevout from the background store.  A miss is tolerated
    /// (the prevout may have been an unspendable output we never stored, or the
    /// caller may be replaying a block whose inputs we deliberately don't have
    /// — never happens on a contiguous genesis→base walk, but harmless).
    fn spendCoin(self: *BgChainState, outpoint: *const types.OutPoint) void {
        var key: [36]u8 = undefined;
        @memcpy(key[0..32], &outpoint.hash);
        std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
        if (self.coins.fetchRemove(key)) |old| {
            self.allocator.free(old.value.script);
        }
    }

    /// Connect one block to the background store at `height`, applying the SAME
    /// UTXO mutations Core's ConnectBlock does: for every tx, remove spent
    /// prevouts (non-coinbase inputs) and add created outputs.  The genesis
    /// coinbase output is unspendable and is never added (Core never indexes
    /// the genesis coinbase into the UTXO set).
    ///
    /// This is a REAL replay — not a counter.  It enforces the
    /// contiguous-from-genesis invariant so the running set can only ever be
    /// the genuine UTXO set at `height`.
    pub fn connectBlock(
        self: *BgChainState,
        block: *const types.Block,
        height: u32,
    ) BgError!void {
        try self.assertNotAliased();

        // Contiguity: first connect must be genesis (0); thereafter strictly +1.
        if (!self.started) {
            if (height != 0) return BgError.NonContiguousReplay;
            self.started = true;
        } else {
            if (@as(i64, height) != self.tip_height + 1) return BgError.NonContiguousReplay;
        }

        for (block.transactions, 0..) |*tx, tx_index| {
            const is_coinbase = tx.isCoinbase();
            const txid = crypto.computeTxid(tx, self.allocator) catch return BgError.OutOfMemory;

            // Spend prevouts (skip the coinbase's null prevout).
            if (!is_coinbase) {
                for (tx.inputs) |*in| {
                    self.spendCoin(&in.previous_output);
                }
            }

            // Add created outputs.  The genesis coinbase (height 0, the single
            // coinbase tx) is unspendable — Core does not add it to the set.
            const genesis_coinbase = (height == 0 and tx_index == 0);
            if (genesis_coinbase) continue;

            for (tx.outputs, 0..) |*out, vout| {
                try self.addCoin(&txid, @intCast(vout), out, height, is_coinbase);
            }
        }

        self.tip_height = @intCast(height);
    }

    /// Compute HASH_SERIALIZED (SHA256d via HashWriter) over the SEPARATE
    /// background store, using the EXACT TxOutSer byte layout the active
    /// chainstate's `storage.computeHashSerializedTxOutSet` uses
    /// (Core kernel/coinstats.cpp TxOutSer + hash.h HashWriter):
    ///   for each coin in (txid, numeric-vout) order:
    ///     txid(32) ‖ LE32 vout ‖ LE32 code ‖ LE i64 value
    ///       ‖ CompactSize(script.len) ‖ script
    ///   where code = (height << 1) | coinbase-bit.
    /// The (txid, numeric-vout) cursor order is load-bearing for HASH_SERIALIZED.
    pub fn computeHashSerialized(self: *BgChainState) BgError!types.Hash256 {
        try self.assertNotAliased();

        var keys = std.ArrayList([36]u8).init(self.allocator);
        defer keys.deinit();
        var it = self.coins.iterator();
        while (it.next()) |entry| {
            keys.append(entry.key_ptr.*) catch return BgError.OutOfMemory;
        }
        std.mem.sort([36]u8, keys.items, {}, utxoKeyLessThan);

        var hw = crypto.Sha256Writer.init();
        for (keys.items) |key| {
            const coin = self.coins.get(key) orelse continue;
            const txid = key[0..32];
            const vout = std.mem.readInt(u32, key[32..36], .little);
            const code: u32 = (@as(u32, coin.height) << 1) | (if (coin.is_coinbase) @as(u32, 1) else 0);
            hw.writeBytes(txid) catch return BgError.OutOfMemory;
            hw.writeInt(u32, vout) catch return BgError.OutOfMemory;
            hw.writeInt(u32, code) catch return BgError.OutOfMemory;
            hw.writeInt(i64, coin.value) catch return BgError.OutOfMemory;
            hw.writeCompactSize(coin.script.len) catch return BgError.OutOfMemory;
            hw.writeBytes(coin.script) catch return BgError.OutOfMemory;
        }
        return hw.finalHash256();
    }

    /// MaybeValidateSnapshot analogue: at the base height, recompute the
    /// background store's HASH_SERIALIZED and compare to the expected
    /// au_data.hash_serialized.  MATCH → validated (the snapshot is now fully
    /// validated; the background chainstate is retired by the caller).
    /// MISMATCH → invalid (Core handle_invalid_snapshot: shut down, NEVER
    /// silently accept).  Always returns a decision; never silently passes.
    ///
    /// `out_actual` (optional) receives the re-derived hash so the caller can
    /// log Core's `[snapshot] hash mismatch: actual=%s, expected=%s` diagnostic.
    pub fn validateAgainst(
        self: *BgChainState,
        au_data: *const consensus.AssumeUtxoData,
        base_height: u32,
        out_actual: ?*types.Hash256,
    ) BgError!ValidationResult {
        // Must have replayed all the way to base — Core only validates once
        // the background chainstate ReachedTarget().
        if (!self.started or self.tip_height != @as(i64, base_height)) {
            return BgError.BaseNotReached;
        }
        const actual = try self.computeHashSerialized();
        if (out_actual) |dst| dst.* = actual;
        if (std.mem.eql(u8, &actual, &au_data.hash_serialized)) {
            return .validated;
        }
        return .invalid;
    }

    /// TEST SEAM (reject-falsification only): inject a coin directly into the
    /// store WITHOUT a block creating it — i.e. exactly what a TAMPERED snapshot
    /// FILE would contain (a phantom coin the genesis→base replay never
    /// produces).  Used to build the tampered "hash-of-self" the load gate would
    /// pass; the genuine replay then re-derives a set WITHOUT this coin, proving
    /// the re-derivation is independent.  Not used on any production path.
    pub fn addPhantomCoin(
        self: *BgChainState,
        txid: types.Hash256,
        vout: u32,
        value: i64,
        script: []const u8,
    ) BgError!void {
        const out = types.TxOut{ .value = value, .script_pubkey = script };
        // height 0 / non-coinbase is fine — the phantom is defined by being
        // absent from the genuine replay, not by its coin metadata.
        try self.addCoin(&txid, vout, &out, 0, false);
    }

    /// Membership probe used by the reject-falsification test to assert a
    /// phantom coin the replay never creates is ABSENT from the bg store
    /// (proving an independent re-derivation, not a hash-of-self copy).
    pub fn hasCoin(self: *BgChainState, txid: *const types.Hash256, vout: u32) bool {
        var key: [36]u8 = undefined;
        @memcpy(key[0..32], txid);
        std.mem.writeInt(u32, key[32..36], vout, .little);
        return self.coins.contains(key);
    }

    /// Number of coins currently in the background store.
    pub fn coinCount(self: *const BgChainState) usize {
        return self.coins.count();
    }
};

/// A source of blocks for the genesis→base replay.  Abstracted so the same
/// driver works for (a) the live node reading bodies from CF_BLOCKS and (b)
/// in-process / test replays over an in-memory list, with NO copy of the
/// snapshot coins reaching the background store.
///
/// `getBlock(ctx, height, out_block)` must populate `out_block.*` with the
/// block at `height` (genesis = 0).  The block is borrowed: it must stay valid
/// until the next `getBlock` call (or the end of activation).
pub const BlockProvider = struct {
    ctx: *anyopaque,
    getBlockFn: *const fn (ctx: *anyopaque, height: u32, out: *types.Block) anyerror!void,

    fn getBlock(self: *const BlockProvider, height: u32, out: *types.Block) anyerror!void {
        return self.getBlockFn(self.ctx, height, out);
    }
};

/// Result of a two-stage AssumeUTXO activation.
pub const ActivationResult = struct {
    /// The background validation decision.
    result: ValidationResult,
    /// Re-derived HASH_SERIALIZED of the background store at base.
    actual_hash: types.Hash256,
    /// Number of coins in the genuine (background-derived) set at base.
    bg_coin_count: usize,
};

/// Two-stage AssumeUTXO activation (Core ActivateSnapshot →
/// PopulateAndValidateSnapshot → AddChainstate → MaybeValidateSnapshot),
/// performed end-to-end against an EMPTY-seeded background chainstate.
///
/// STAGE 1 — load-time hash gate (authenticate the snapshot FILE):
///   The caller has ALREADY authenticated the snapshot file by computing its
///   own coins' HASH_SERIALIZED and matching it against `au_data.hash_serialized`
///   (storage.validateAndLoadSnapshot, Core PopulateAndValidateSnapshot's
///   final `AssumeutxoHash{stats} != au_data.hash_serialized` gate).  We pass
///   `load_gate_passed` so this driver records that the file authenticated —
///   but, crucially, it does NOT trust that result for validation.
///
/// STAGE 2 — REAL background genesis→base re-derivation (this function):
///   Seed an EMPTY background store, replay genesis..base from `provider`
///   (independent of the snapshot file), recompute HASH_SERIALIZED over the
///   SEPARATE store, and compare to `au_data.hash_serialized`.  MATCH →
///   validated.  MISMATCH → invalid (Core MaybeValidateSnapshot
///   handle_invalid_snapshot; never silently accepts).
///
/// `active_utxo` (optional): the live active chainstate's coins; supplied so
/// the aliasing guard can prove the background store is a DISTINCT object.
pub fn runBackgroundValidation(
    allocator: std.mem.Allocator,
    provider: *const BlockProvider,
    au_data: *const consensus.AssumeUtxoData,
    base_height: u32,
    load_gate_passed: bool,
    active_utxo: ?*const storage.UtxoSet,
) BgError!ActivationResult {
    std.debug.assert(load_gate_passed); // stage 1 must have authenticated the file

    var bg = BgChainState.init(allocator, active_utxo);
    defer bg.deinit();

    // Aliasing guard up front: the background store must NOT be the active
    // coins cache (otherwise the hash below would be a hash-of-self).
    try bg.assertNotAliased();

    // STAGE 2: genuine genesis→base replay over the SEPARATE store.
    var height: u32 = 0;
    var block: types.Block = undefined;
    while (height <= base_height) : (height += 1) {
        provider.getBlock(height, &block) catch return BgError.NonContiguousReplay;
        try bg.connectBlock(&block, height);
    }

    var actual: types.Hash256 = undefined;
    const result = try bg.validateAgainst(au_data, base_height, &actual);
    return .{
        .result = result,
        .actual_hash = actual,
        .bg_coin_count = bg.coinCount(),
    };
}

/// (txid, numeric-vout) ordering — identical to storage.utxoKeyLessThan
/// (that one is not pub).  Primary by the 32-byte txid in byte order, then by
/// numeric vout (NOT the LE32 bytes, which mis-order vouts >= 256).
fn utxoKeyLessThan(_: void, a: [36]u8, b: [36]u8) bool {
    const txid_order = std.mem.order(u8, a[0..32], b[0..32]);
    if (txid_order != .eq) return txid_order == .lt;
    const va = std.mem.readInt(u32, a[32..36], .little);
    const vb = std.mem.readInt(u32, b[32..36], .little);
    return va < vb;
}

// ===========================================================================
// Runtime-registerable regtest AssumeUTXO whitelist.
//
// mainnet / testnet4 m_assumeutxo_data are comptime-const and UNTOUCHED.  For
// regtest (and the in-process activation path) we need to register an
// AssumeUtxoData entry at runtime — a freshly-mined regtest chain has a
// different base hash + hash_serialized every run, so there is nothing to
// hard-code.  Core does the equivalent with `-assumeutxo` test params /
// SetMockTime-style test plumbing; here we keep a small process-global table
// that loadtxoutset (regtest only) and the background validator consult IN
// ADDITION to network_params.assume_utxo.
//
// This table is regtest-scoped by contract: callers must only register regtest
// entries.  It is never consulted for mainnet/testnet4 snapshot authentication
// (those go through network_params.assume_utxo, which stays Core-exact).
// ===========================================================================

var regtest_whitelist: std.ArrayListUnmanaged(consensus.AssumeUtxoData) = .{};
var regtest_whitelist_mu: std.Thread.Mutex = .{};

/// Register a regtest AssumeUTXO snapshot at runtime (height, base hash,
/// hash_serialized).  Idempotent on (height, block_hash): a re-register with
/// the same key updates the hash_serialized.  REGTEST ONLY — never call for
/// mainnet/testnet4.
pub fn registerRegtestSnapshot(
    allocator: std.mem.Allocator,
    entry: consensus.AssumeUtxoData,
) BgError!void {
    regtest_whitelist_mu.lock();
    defer regtest_whitelist_mu.unlock();
    for (regtest_whitelist.items) |*e| {
        if (e.height == entry.height and std.mem.eql(u8, &e.block_hash, &entry.block_hash)) {
            e.hash_serialized = entry.hash_serialized;
            e.chain_tx_count = entry.chain_tx_count;
            return;
        }
    }
    regtest_whitelist.append(allocator, entry) catch return BgError.OutOfMemory;
}

/// Look up a runtime-registered regtest snapshot by base block hash.
pub fn findRegtestSnapshot(block_hash: *const types.Hash256) ?consensus.AssumeUtxoData {
    regtest_whitelist_mu.lock();
    defer regtest_whitelist_mu.unlock();
    for (regtest_whitelist.items) |e| {
        if (std.mem.eql(u8, &e.block_hash, block_hash)) return e;
    }
    return null;
}

/// Clear the regtest whitelist (test teardown).
pub fn clearRegtestWhitelist(allocator: std.mem.Allocator) void {
    regtest_whitelist_mu.lock();
    defer regtest_whitelist_mu.unlock();
    regtest_whitelist.deinit(allocator);
    regtest_whitelist = .{};
}
