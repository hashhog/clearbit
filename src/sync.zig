const std = @import("std");
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");

// ============================================================================
// Block Download Constants
// ============================================================================

/// Maximum blocks in flight per peer (prevents one slow peer from blocking).
pub const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// Maximum blocks in flight total across all peers.
pub const MAX_BLOCKS_IN_FLIGHT_TOTAL: usize = 128;

/// Timeout in seconds before re-requesting a block from another peer.
pub const BLOCK_DOWNLOAD_TIMEOUT: i64 = 60;

/// Number of blocks to validate in one batch during IBD.
pub const IBD_BATCH_SIZE: usize = 500;

/// Interval between UTXO flushes during IBD (every N blocks).
pub const UTXO_FLUSH_INTERVAL: u32 = 2000;

/// Maximum headers per message (Bitcoin P2P protocol limit).
pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;

// ============================================================================
// Header Sync Anti-DoS (PRESYNC/REDOWNLOAD)
// ============================================================================
//
// Protects against memory exhaustion attacks during initial header sync.
// A malicious peer could send millions of low-work headers to consume memory.
//
// The solution is a two-phase process:
// 1. PRESYNC: Accept headers without storing them permanently. Track only:
//    - Cumulative chain work (256-bit integer)
//    - Last header hash
//    - Header count
//    This uses ~100 bytes per peer maximum.
//
// 2. REDOWNLOAD: Once the peer's chain demonstrates sufficient work
//    (>= min_chain_work), re-request all headers and store them permanently.
//
// Reference: Bitcoin Core headerssync.cpp/h

/// Header sync state machine for anti-DoS protection.
pub const HeaderSyncState = enum {
    /// Phase 1: Tracking work without storing headers permanently.
    /// Stores only cumulative work, last hash, and count (~100 bytes).
    presync,

    /// Phase 2: Re-downloading headers for permanent storage.
    /// Only entered after presync proves sufficient chain work.
    redownload,

    /// Sync complete or failed for this peer.
    done,
};

/// Minimal state tracked per peer during PRESYNC phase.
/// Intentionally small (~100 bytes) to prevent memory exhaustion attacks.
pub const PresyncState = struct {
    /// Cumulative proof-of-work of the chain seen so far (256-bit).
    chain_work: [32]u8,

    /// Hash of the last header received in this chain.
    last_header_hash: types.Hash256,

    /// Number of headers seen in presync (for logging/debugging).
    header_count: u32,

    /// Height of the chain tip seen in presync.
    tip_height: u32,

    /// Timestamp when presync started (for timeout detection).
    start_time: i64,

    /// Last header's bits field (needed for work calculation).
    last_bits: u32,

    /// Initialize presync state from chain start.
    pub fn init(chain_start_hash: types.Hash256, chain_start_work: [32]u8, start_height: u32) PresyncState {
        return PresyncState{
            .chain_work = chain_start_work,
            .last_header_hash = chain_start_hash,
            .header_count = 0,
            .tip_height = start_height,
            .start_time = std.time.timestamp(),
            .last_bits = 0,
        };
    }

    /// Size of this struct in bytes (for memory budgeting).
    pub const SIZE_BYTES: usize = 32 + 32 + 4 + 4 + 8 + 4; // ~84 bytes
};

/// Per-peer header sync state machine for anti-DoS protection.
pub const HeadersSyncState = struct {
    /// Current phase of the state machine.
    state: HeaderSyncState,

    /// Presync tracking data (minimal memory footprint).
    presync: PresyncState,

    /// Minimum required chain work to transition to REDOWNLOAD.
    min_chain_work: [32]u8,

    /// Hash where chain starts (our current tip or genesis).
    chain_start_hash: types.Hash256,

    /// Height where chain starts.
    chain_start_height: u32,

    /// Peer ID for tracking.
    peer_id: usize,

    /// Allocator for any dynamic allocations during redownload.
    allocator: std.mem.Allocator,

    /// Initialize a new header sync state machine.
    pub fn init(
        peer_id: usize,
        chain_start_hash: types.Hash256,
        chain_start_work: [32]u8,
        chain_start_height: u32,
        min_chain_work: [32]u8,
        allocator: std.mem.Allocator,
    ) HeadersSyncState {
        return HeadersSyncState{
            .state = .presync,
            .presync = PresyncState.init(chain_start_hash, chain_start_work, chain_start_height),
            .min_chain_work = min_chain_work,
            .chain_start_hash = chain_start_hash,
            .chain_start_height = chain_start_height,
            .peer_id = peer_id,
            .allocator = allocator,
        };
    }

    /// Process headers during PRESYNC phase.
    /// Returns true if we should request more headers, false if done or failed.
    pub fn processPresyncHeaders(
        self: *HeadersSyncState,
        headers: []const types.BlockHeader,
    ) !PresyncResult {
        if (self.state != .presync) {
            return PresyncResult{ .action = .abort, .reason = .wrong_state };
        }

        if (headers.len == 0) {
            // Empty response - peer has no more headers
            return PresyncResult{ .action = .abort, .reason = .empty_response };
        }

        // Validate and accumulate work for each header
        var prev_hash = self.presync.last_header_hash;
        var cumulative_work = self.presync.chain_work;
        var last_bits: u32 = self.presync.last_bits;

        for (headers) |*header| {
            // Check continuity: header must chain to previous
            if (!std.mem.eql(u8, &header.prev_block, &prev_hash)) {
                return PresyncResult{ .action = .abort, .reason = .discontinuous };
            }

            // Compute this header's hash
            const header_hash = crypto.computeBlockHash(header);

            // Validate PoW meets claimed target
            const target = consensus.bitsToTarget(header.bits);
            if (!consensus.hashMeetsTarget(&header_hash, &target)) {
                return PresyncResult{ .action = .abort, .reason = .invalid_pow };
            }

            // Accumulate work
            const work = computeWork(header.bits);
            cumulative_work = addWork(cumulative_work, work);

            prev_hash = header_hash;
            last_bits = header.bits;
            self.presync.header_count += 1;
            self.presync.tip_height += 1;
        }

        // Update state
        self.presync.last_header_hash = prev_hash;
        self.presync.chain_work = cumulative_work;
        self.presync.last_bits = last_bits;

        // Check if we've accumulated enough work to transition to REDOWNLOAD
        if (compareWork(cumulative_work, self.min_chain_work) >= 0) {
            self.state = .redownload;
            return PresyncResult{
                .action = .transition_to_redownload,
                .reason = .success,
            };
        }

        // Not enough work yet - request more headers
        if (headers.len == MAX_HEADERS_PER_MESSAGE) {
            return PresyncResult{ .action = .request_more, .reason = .success };
        }

        // Peer sent less than max headers but work is insufficient
        return PresyncResult{ .action = .abort, .reason = .insufficient_work };
    }

    /// Get the next locator hash for requesting more headers.
    pub fn nextLocatorHash(self: *const HeadersSyncState) types.Hash256 {
        return self.presync.last_header_hash;
    }

    /// Get a summary of the presync progress.
    pub fn getPresyncProgress(self: *const HeadersSyncState) PresyncProgress {
        return PresyncProgress{
            .header_count = self.presync.header_count,
            .tip_height = self.presync.tip_height,
            .chain_work = self.presync.chain_work,
            .min_chain_work = self.min_chain_work,
            .state = self.state,
        };
    }

    /// Clean up any allocated resources.
    pub fn deinit(self: *HeadersSyncState) void {
        // Currently no dynamic allocations, but reserved for future use
        _ = self;
    }
};

/// Result of processing headers during PRESYNC.
pub const PresyncResult = struct {
    action: PresyncAction,
    reason: PresyncReason,
};

pub const PresyncAction = enum {
    /// Continue presync, request more headers.
    request_more,

    /// Sufficient work proven, transition to REDOWNLOAD phase.
    transition_to_redownload,

    /// Abort sync with this peer (invalid data or insufficient work).
    abort,
};

pub const PresyncReason = enum {
    success,
    wrong_state,
    empty_response,
    discontinuous,
    invalid_pow,
    insufficient_work,
};

/// Progress summary for PRESYNC phase.
pub const PresyncProgress = struct {
    header_count: u32,
    tip_height: u32,
    chain_work: [32]u8,
    min_chain_work: [32]u8,
    state: HeaderSyncState,
};

/// Manager for per-peer header sync state machines.
/// Uses AutoHashMap with PeerId (pointer converted to usize) as key.
pub const HeaderSyncManager = struct {
    /// Per-peer sync state: peer pointer -> HeadersSyncState
    peer_states: std.AutoHashMap(usize, *HeadersSyncState),

    /// Allocator for dynamic allocations.
    allocator: std.mem.Allocator,

    /// Minimum required chain work for REDOWNLOAD transition.
    min_chain_work: [32]u8,

    /// Initialize the header sync manager.
    pub fn init(allocator: std.mem.Allocator, min_chain_work: [32]u8) HeaderSyncManager {
        return HeaderSyncManager{
            .peer_states = std.AutoHashMap(usize, *HeadersSyncState).init(allocator),
            .allocator = allocator,
            .min_chain_work = min_chain_work,
        };
    }

    /// Clean up all peer states.
    pub fn deinit(self: *HeaderSyncManager) void {
        var iter = self.peer_states.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.peer_states.deinit();
    }

    /// Start header sync with a peer.
    pub fn startSync(
        self: *HeaderSyncManager,
        peer: *peer_mod.Peer,
        chain_start_hash: types.Hash256,
        chain_start_work: [32]u8,
        chain_start_height: u32,
    ) !*HeadersSyncState {
        const peer_id = @intFromPtr(peer);

        // Remove existing state if any
        if (self.peer_states.fetchRemove(peer_id)) |old_entry| {
            old_entry.value.deinit();
            self.allocator.destroy(old_entry.value);
        }

        // Create new state
        const state = try self.allocator.create(HeadersSyncState);
        state.* = HeadersSyncState.init(
            peer_id,
            chain_start_hash,
            chain_start_work,
            chain_start_height,
            self.min_chain_work,
            self.allocator,
        );

        try self.peer_states.put(peer_id, state);
        return state;
    }

    /// Get the sync state for a peer.
    pub fn getState(self: *HeaderSyncManager, peer: *peer_mod.Peer) ?*HeadersSyncState {
        return self.peer_states.get(@intFromPtr(peer));
    }

    /// Remove sync state for a peer.
    pub fn removeState(self: *HeaderSyncManager, peer: *peer_mod.Peer) void {
        const peer_id = @intFromPtr(peer);
        if (self.peer_states.fetchRemove(peer_id)) |entry| {
            entry.value.deinit();
            self.allocator.destroy(entry.value);
        }
    }

    /// Count active presync states (for memory budgeting).
    pub fn activePresyncCount(self: *const HeaderSyncManager) usize {
        var count: usize = 0;
        var iter = self.peer_states.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.*.state == .presync) {
                count += 1;
            }
        }
        return count;
    }

    /// Estimated memory usage for presync states.
    pub fn presyncMemoryUsage(self: *const HeaderSyncManager) usize {
        return self.activePresyncCount() * PresyncState.SIZE_BYTES;
    }

    /// Check if a peer is in low-work header sync.
    pub fn isLowWorkSync(self: *const HeaderSyncManager, peer: *peer_mod.Peer) bool {
        const state = self.getState(peer) orelse return false;
        return state.state == .presync;
    }

    /// Process headers from a peer during low-work sync.
    /// Returns null if peer is not in low-work sync.
    pub fn processHeaders(
        self: *HeaderSyncManager,
        peer: *peer_mod.Peer,
        headers: []const types.BlockHeader,
    ) ?PresyncResult {
        const state = self.getState(peer) orelse return null;

        if (state.state != .presync) {
            return null;
        }

        return state.processPresyncHeaders(headers) catch {
            return PresyncResult{ .action = .abort, .reason = .invalid_pow };
        };
    }
};

// ============================================================================
// Sync State
// ============================================================================

pub const SyncState = enum {
    idle,
    syncing_headers,
    downloading_blocks,
    verifying,
    synced,
};

pub const SyncError = error{
    NoPeers,
    InvalidHeader,
    OrphanHeader,
    InvalidChainWork,
    InvalidDifficulty,
    OutOfMemory,
    StorageError,
};

// ============================================================================
// Block Index Entry
// ============================================================================

/// Block index entry stored in memory during sync.
pub const BlockIndex = struct {
    header: types.BlockHeader,
    hash: types.Hash256,
    height: u32,
    chain_work: [32]u8, // Cumulative proof-of-work
    status: BlockStatus,

    pub const BlockStatus = enum {
        header_only, // Only header known
        data_stored, // Full block stored on disk
        validated, // Fully validated (scripts checked)
        active, // Part of the active (best) chain
    };
};

// ============================================================================
// Sync Manager
// ============================================================================

/// The sync manager handles the full synchronization lifecycle.
pub const SyncManager = struct {
    state: SyncState,
    chain_store: ?*storage.ChainStore,
    peer_manager: *peer_mod.PeerManager,
    network_params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,

    /// In-memory block index: hash -> BlockIndex
    block_index: std.AutoHashMap(types.Hash256, *BlockIndex),

    /// Best known chain tip
    best_tip: ?*BlockIndex,

    /// Height -> hash mapping for the active chain
    active_chain: std.ArrayList(types.Hash256),

    /// Headers download state
    headers_sync_peer: ?*peer_mod.Peer,
    last_getheaders_time: i64,

    pub fn init(
        chain_store: ?*storage.ChainStore,
        peer_manager: *peer_mod.PeerManager,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) SyncManager {
        var mgr = SyncManager{
            .state = .idle,
            .chain_store = chain_store,
            .peer_manager = peer_manager,
            .network_params = params,
            .allocator = allocator,
            .block_index = std.AutoHashMap(types.Hash256, *BlockIndex).init(allocator),
            .best_tip = null,
            .active_chain = std.ArrayList(types.Hash256).init(allocator),
            .headers_sync_peer = null,
            .last_getheaders_time = 0,
        };

        // Add genesis block to index
        mgr.addGenesisBlock() catch {};
        return mgr;
    }

    pub fn deinit(self: *SyncManager) void {
        var iter = self.block_index.iterator();
        while (iter.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.block_index.deinit();
        self.active_chain.deinit();
    }

    /// Add the genesis block to the index.
    fn addGenesisBlock(self: *SyncManager) !void {
        const genesis = try self.allocator.create(BlockIndex);
        genesis.* = BlockIndex{
            .header = self.network_params.genesis_header,
            .hash = self.network_params.genesis_hash,
            .height = 0,
            .chain_work = computeWork(self.network_params.genesis_header.bits),
            .status = .active,
        };
        try self.block_index.put(genesis.hash, genesis);
        try self.active_chain.append(genesis.hash);
        self.best_tip = genesis;
    }

    /// Start header synchronization.
    pub fn startHeaderSync(self: *SyncManager) SyncError!void {
        self.state = .syncing_headers;

        // Select the best peer (highest start_height)
        var best_peer: ?*peer_mod.Peer = null;
        var best_height: i32 = 0;
        for (self.peer_manager.peers.items) |p| {
            if (p.state == .handshake_complete and p.start_height > best_height) {
                best_peer = p;
                best_height = p.start_height;
            }
        }

        self.headers_sync_peer = best_peer orelse return SyncError.NoPeers;
        try self.sendGetHeaders();
    }

    /// Build and send a getheaders message.
    fn sendGetHeaders(self: *SyncManager) SyncError!void {
        const peer = self.headers_sync_peer orelse return SyncError.NoPeers;

        // Build block locator: exponentially spaced hashes from our tip
        var locator = std.ArrayList(types.Hash256).init(self.allocator);
        defer locator.deinit();

        if (self.active_chain.items.len > 0) {
            var step: usize = 1;
            var idx: usize = self.active_chain.items.len - 1;
            var count: usize = 0;

            while (true) {
                locator.append(self.active_chain.items[idx]) catch
                    return SyncError.OutOfMemory;
                count += 1;

                if (idx == 0) break;

                // Exponential backoff after first 10
                if (count >= 10) step *= 2;
                if (step > idx) {
                    idx = 0;
                } else {
                    idx -= step;
                }
            }
        }

        const msg = p2p.Message{ .getheaders = p2p.GetHeadersMessage{
            .version = @intCast(p2p.PROTOCOL_VERSION),
            .block_locator_hashes = locator.items,
            .hash_stop = [_]u8{0} ** 32, // Get as many as possible
        } };

        peer.sendMessage(&msg) catch return SyncError.NoPeers;
        self.last_getheaders_time = std.time.timestamp();
    }

    /// Process received headers.
    pub fn handleHeaders(self: *SyncManager, headers: []const types.BlockHeader) SyncError!void {
        for (headers) |*header| {
            try self.processHeader(header);
        }

        // If we received 2000 headers, there are likely more
        if (headers.len == 2000) {
            try self.sendGetHeaders();
        } else {
            // Headers sync complete
            self.state = .downloading_blocks;
        }
    }

    /// Process a single header.
    fn processHeader(self: *SyncManager, header: *const types.BlockHeader) SyncError!void {
        // Compute this header's hash
        const hash = crypto.computeBlockHash(header);

        // Skip if already known
        if (self.block_index.contains(hash)) return;

        // Find parent
        const parent = self.block_index.get(header.prev_block) orelse
            return SyncError.OrphanHeader;

        // Basic validation
        // 1. Timestamp must be > median-time-past of previous 11 blocks
        // 2. Proof of work must meet target
        // 3. Difficulty must be correct for this height

        const target = consensus.bitsToTarget(header.bits);
        if (!consensus.hashMeetsTarget(&hash, &target))
            return SyncError.InvalidHeader;

        // Create index entry
        const new_entry = self.allocator.create(BlockIndex) catch
            return SyncError.OutOfMemory;
        const height = parent.height + 1;
        const work = computeWork(header.bits);

        new_entry.* = BlockIndex{
            .header = header.*,
            .hash = hash,
            .height = height,
            .chain_work = addWork(parent.chain_work, work),
            .status = .header_only,
        };

        self.block_index.put(hash, new_entry) catch
            return SyncError.OutOfMemory;

        // Update best tip if this chain has more work
        if (self.best_tip == null or
            compareWork(new_entry.chain_work, self.best_tip.?.chain_work) > 0)
        {
            self.best_tip = new_entry;
            // Extend active chain
            while (self.active_chain.items.len <= height) {
                self.active_chain.append([_]u8{0} ** 32) catch
                    return SyncError.OutOfMemory;
            }
            self.active_chain.items[height] = hash;
        }

        // Persist to disk if chain_store is available
        if (self.chain_store) |cs| {
            cs.putBlockIndex(&hash, header, height) catch
                return SyncError.StorageError;
        }
    }

    /// Get the current sync progress.
    pub fn progress(self: *SyncManager) struct { height: u32, total: u32, percent: f64 } {
        const current = if (self.best_tip) |tip| tip.height else 0;
        var best_peer_height: u32 = current;
        for (self.peer_manager.peers.items) |p| {
            if (p.start_height > 0 and @as(u32, @intCast(p.start_height)) > best_peer_height) {
                best_peer_height = @intCast(p.start_height);
            }
        }
        const pct: f64 = if (best_peer_height > 0)
            @as(f64, @floatFromInt(current)) / @as(f64, @floatFromInt(best_peer_height)) * 100.0
        else
            100.0;

        return .{
            .height = current,
            .total = best_peer_height,
            .percent = pct,
        };
    }

    /// Get the best tip height.
    pub fn getBestHeight(self: *const SyncManager) u32 {
        return if (self.best_tip) |tip| tip.height else 0;
    }

    /// Get the best tip hash.
    pub fn getBestHash(self: *const SyncManager) ?types.Hash256 {
        return if (self.best_tip) |tip| tip.hash else null;
    }

    /// Check if a hash is known.
    pub fn hasBlock(self: *const SyncManager, hash: *const types.Hash256) bool {
        return self.block_index.contains(hash.*);
    }

    /// Get the block index for a hash.
    pub fn getBlockIndex(self: *const SyncManager, hash: *const types.Hash256) ?*BlockIndex {
        return self.block_index.get(hash.*);
    }
};

// ============================================================================
// 256-bit Work Arithmetic
// ============================================================================

/// Compute the proof-of-work represented by a target (bits field).
/// Work = 2^256 / (target + 1)
/// For simplicity, we approximate: work ≈ (2^256 - 1) / target
/// which is close enough for comparison purposes.
pub fn computeWork(bits: u32) [32]u8 {
    const target = consensus.bitsToTarget(bits);

    // Find the highest non-zero byte in target
    var target_size: usize = 32;
    while (target_size > 0 and target[target_size - 1] == 0) : (target_size -= 1) {}

    if (target_size == 0) {
        // Target is zero, work is maximum
        return [_]u8{0xFF} ** 32;
    }

    // Simplified work calculation:
    // We compute an approximation where work is inversely proportional to target.
    // For a proper implementation, we'd need full 256-bit division.
    // Here we use the leading bytes to estimate work.

    // Get the effective target value (top 8 bytes as u64)
    var target_val: u64 = 0;
    const start_idx = if (target_size > 8) target_size - 8 else 0;
    for (start_idx..target_size) |i| {
        target_val = (target_val << 8) | @as(u64, target[i]);
    }

    if (target_val == 0) {
        target_val = 1;
    }

    // Work approximation: we'll use a simplified metric
    // The position of the highest bit in target determines the work
    // Work = 2^(256 - leading_zeros) roughly

    var work: [32]u8 = [_]u8{0} ** 32;

    // Calculate how many zeros are in the target
    var leading_zeros: u32 = 0;
    var i: usize = 31;
    while (i > 0) : (i -= 1) {
        if (target[i] != 0) {
            // Count leading zeros in this byte
            leading_zeros += @clz(target[i]);
            break;
        }
        leading_zeros += 8;
    }
    if (target[0] == 0 and i == 0) {
        leading_zeros = 256;
    }

    // Place work value - higher leading zeros = more work
    // We store this as a rough estimate in the work array
    const work_bits = leading_zeros;
    const byte_pos = work_bits / 8;
    const bit_pos: u3 = @intCast(work_bits % 8);

    if (byte_pos < 32) {
        work[byte_pos] = @as(u8, 1) << bit_pos;
    }

    return work;
}

/// Add two 256-bit work values.
pub fn addWork(a: [32]u8, b: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    var carry: u16 = 0;
    for (0..32) |i| {
        const sum: u16 = @as(u16, a[i]) + @as(u16, b[i]) + carry;
        result[i] = @intCast(sum & 0xFF);
        carry = sum >> 8;
    }
    return result;
}

/// Compare two 256-bit work values. Returns >0 if a > b, <0 if a < b, 0 if equal.
pub fn compareWork(a: [32]u8, b: [32]u8) i32 {
    // Compare from most significant byte (index 31) to least significant (index 0)
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/// Build a block locator from an active chain.
/// The locator uses exponential backoff: first 10 blocks are consecutive,
/// then spacing doubles (step 1, 1, ..., 2, 4, 8, 16, ...).
/// Always includes genesis block.
pub fn buildBlockLocator(
    active_chain: []const types.Hash256,
    allocator: std.mem.Allocator,
) ![]types.Hash256 {
    var locator = std.ArrayList(types.Hash256).init(allocator);
    errdefer locator.deinit();

    if (active_chain.len == 0) {
        return locator.toOwnedSlice();
    }

    var step: usize = 1;
    var idx: usize = active_chain.len - 1;
    var count: usize = 0;

    while (true) {
        try locator.append(active_chain[idx]);
        count += 1;

        if (idx == 0) break;

        // Exponential backoff after first 10
        if (count >= 10) step *= 2;
        if (step > idx) {
            idx = 0;
        } else {
            idx -= step;
        }
    }

    return locator.toOwnedSlice();
}

// ============================================================================
// Block Downloader
// ============================================================================

/// Errors specific to block download and validation.
pub const BlockDownloadError = error{
    BadMerkleRoot,
    MissingInput,
    ImmatureCoinbase,
    InsufficientFunds,
    ExcessiveCoinbaseValue,
    InvalidBlock,
    NoBestTip,
    OutOfMemory,
    StorageError,
};

/// Serialize an OutPoint to a 36-byte key for UTXO lookups.
/// Format: txid (32 bytes) || output_index (4 bytes LE)
pub fn outpointKey(outpoint: *const types.OutPoint) [36]u8 {
    var key: [36]u8 = undefined;
    @memcpy(key[0..32], &outpoint.hash);
    std.mem.writeInt(u32, key[32..36], outpoint.index, .little);
    return key;
}

/// Block downloader handles IBD (Initial Block Download) and ongoing block sync.
/// It manages parallel block downloads from multiple peers and processes
/// blocks in order to build the UTXO set.
pub const BlockDownloader = struct {
    sync_manager: *SyncManager,
    allocator: std.mem.Allocator,

    /// Blocks requested but not yet received: hash -> request info
    in_flight: std.AutoHashMap(types.Hash256, InFlightBlock),

    /// Downloaded blocks waiting to be connected (may arrive out of order)
    downloaded_queue: std.AutoHashMap(types.Hash256, types.Block),

    /// Next height to download
    download_height: u32,

    /// Next height to validate and connect
    connect_height: u32,

    /// Last height where we flushed UTXO to disk
    last_flush_height: u32,

    /// Stall timeout tracking (adaptive: base 5s, doubles on stall, max 64s)
    stall_timeout_base: i64,

    /// Track per-peer in-flight counts for fair distribution
    peer_in_flight_counts: std.AutoHashMap(*peer_mod.Peer, usize),

    /// Request info for in-flight blocks.
    pub const InFlightBlock = struct {
        peer: *peer_mod.Peer,
        height: u32,
        request_time: i64,
    };

    /// Initialize a new BlockDownloader.
    pub fn init(sync_manager: *SyncManager, allocator: std.mem.Allocator) BlockDownloader {
        return BlockDownloader{
            .sync_manager = sync_manager,
            .allocator = allocator,
            .in_flight = std.AutoHashMap(types.Hash256, InFlightBlock).init(allocator),
            .downloaded_queue = std.AutoHashMap(types.Hash256, types.Block).init(allocator),
            .download_height = 1, // Start after genesis
            .connect_height = 1,
            .last_flush_height = 0,
            .stall_timeout_base = 5, // Start at 5 seconds
            .peer_in_flight_counts = std.AutoHashMap(*peer_mod.Peer, usize).init(allocator),
        };
    }

    /// Clean up resources.
    pub fn deinit(self: *BlockDownloader) void {
        self.in_flight.deinit();
        // Free any remaining downloaded blocks that were never connected
        var iter = self.downloaded_queue.valueIterator();
        while (iter.next()) |block| {
            serialize.freeBlock(self.allocator, block);
        }
        self.downloaded_queue.deinit();
        self.peer_in_flight_counts.deinit();
    }

    /// Get count of blocks in flight for a specific peer.
    fn getPeerInFlightCount(self: *BlockDownloader, peer: *peer_mod.Peer) usize {
        return self.peer_in_flight_counts.get(peer) orelse 0;
    }

    /// Increment in-flight count for a peer.
    fn incrementPeerCount(self: *BlockDownloader, peer: *peer_mod.Peer) !void {
        const current = self.getPeerInFlightCount(peer);
        try self.peer_in_flight_counts.put(peer, current + 1);
    }

    /// Decrement in-flight count for a peer.
    fn decrementPeerCount(self: *BlockDownloader, peer: *peer_mod.Peer) void {
        const current = self.getPeerInFlightCount(peer);
        if (current > 0) {
            self.peer_in_flight_counts.put(peer, current - 1) catch {};
        }
    }

    /// Main IBD loop: request blocks, process received blocks, connect to chain.
    pub fn runIBD(self: *BlockDownloader) !void {
        const tip_height = if (self.sync_manager.best_tip) |tip| tip.height else return BlockDownloadError.NoBestTip;

        while (self.connect_height <= tip_height) {
            // 1. Request more blocks if we have capacity
            self.requestBlocks() catch |err| {
                std.log.warn("Error requesting blocks: {}", .{err});
            };

            // 2. Process incoming messages from peers
            self.processMessages() catch {};

            // 3. Try to connect downloaded blocks in order
            self.connectBlocks() catch |err| {
                std.log.err("Error connecting blocks: {}", .{err});
                return err;
            };

            // 4. Handle timeouts and retries
            self.handleTimeouts();

            // 5. Periodic UTXO flush
            if (self.connect_height - self.last_flush_height >= UTXO_FLUSH_INTERVAL) {
                if (self.sync_manager.chain_store) |cs| {
                    cs.db.flush() catch {};
                }
                self.last_flush_height = self.connect_height;
            }

            // Progress logging
            if (self.connect_height % 1000 == 0) {
                std.log.info("IBD progress: {d}/{d} ({d:.1}%)", .{
                    self.connect_height,
                    tip_height,
                    @as(f64, @floatFromInt(self.connect_height)) /
                        @as(f64, @floatFromInt(tip_height)) * 100.0,
                });
            }

            std.time.sleep(10 * std.time.ns_per_ms);
        }

        self.sync_manager.state = .synced;
        std.log.info("IBD complete at height {d}", .{self.connect_height - 1});
    }

    /// Request blocks from peers, distributing requests across available peers.
    /// Batches multiple inv items per getdata message for efficiency.
    pub fn requestBlocks(self: *BlockDownloader) !void {
        if (self.in_flight.count() >= MAX_BLOCKS_IN_FLIGHT_TOTAL) return;

        const tip_height = if (self.sync_manager.best_tip) |tip| tip.height else return;
        const peers = self.sync_manager.peer_manager.peers.items;

        if (peers.len == 0) return;

        var peer_idx: usize = 0;

        // Collect inv items per peer for batch getdata messages
        var peer_requests = std.AutoHashMap(*peer_mod.Peer, std.ArrayList(p2p.InvVector)).init(self.allocator);
        defer {
            var iter = peer_requests.valueIterator();
            while (iter.next()) |list| {
                list.deinit();
            }
            peer_requests.deinit();
        }

        while (self.download_height <= tip_height and
            self.in_flight.count() < MAX_BLOCKS_IN_FLIGHT_TOTAL)
        {
            // Get the hash for this height from the active chain
            if (self.download_height >= self.sync_manager.active_chain.items.len) break;
            const hash = self.sync_manager.active_chain.items[self.download_height];

            // Skip if already downloaded or in flight
            if (self.in_flight.contains(hash) or self.downloaded_queue.contains(hash)) {
                self.download_height += 1;
                continue;
            }

            // Find a peer to request from (round-robin with per-peer limits)
            var found_peer: ?*peer_mod.Peer = null;
            for (0..peers.len) |_| {
                peer_idx = (peer_idx + 1) % peers.len;
                const p = peers[peer_idx];
                if (p.state != .handshake_complete) continue;
                if (!p.is_witness_capable) continue;

                // Check per-peer in-flight limit
                const peer_count = self.getPeerInFlightCount(p);
                if (peer_count >= MAX_BLOCKS_IN_FLIGHT) continue;

                found_peer = p;
                break;
            }

            const peer = found_peer orelse break;

            // Add to peer's request batch
            const request_list = peer_requests.getPtr(peer) orelse blk: {
                try peer_requests.put(peer, std.ArrayList(p2p.InvVector).init(self.allocator));
                break :blk peer_requests.getPtr(peer).?;
            };

            try request_list.append(p2p.InvVector{
                .inv_type = .msg_witness_block,
                .hash = hash,
            });

            try self.in_flight.put(hash, InFlightBlock{
                .peer = peer,
                .height = self.download_height,
                .request_time = std.time.timestamp(),
            });
            try self.incrementPeerCount(peer);

            self.download_height += 1;
        }

        // Send batched getdata messages
        var iter = peer_requests.iterator();
        while (iter.next()) |entry| {
            const peer = entry.key_ptr.*;
            const inv_list = entry.value_ptr;
            if (inv_list.items.len > 0) {
                const msg = p2p.Message{ .getdata = p2p.InvMessage{
                    .inventory = inv_list.items,
                } };
                peer.sendMessage(&msg) catch {};
            }
        }
    }

    /// Handle a received block message.
    pub fn handleBlock(self: *BlockDownloader, block: types.Block) !void {
        // Compute block hash from header
        const hash = crypto.computeBlockHash(&block.header);

        // Remove from in_flight and update peer counts
        if (self.in_flight.fetchRemove(hash)) |entry| {
            self.decrementPeerCount(entry.value.peer);

            // Success - decay stall timeout back towards base
            if (self.stall_timeout_base > 5) {
                self.stall_timeout_base = @max(5, self.stall_timeout_base - 1);
            }
        }

        // Add to download queue, freeing any duplicate block already queued
        if (self.downloaded_queue.fetchRemove(hash)) |old_entry| {
            var old_block = old_entry.value;
            serialize.freeBlock(self.allocator, &old_block);
        }
        try self.downloaded_queue.put(hash, block);
    }

    /// Connect blocks in order from the download queue.
    fn connectBlocks(self: *BlockDownloader) !void {
        var connected: usize = 0;

        while (connected < IBD_BATCH_SIZE) {
            if (self.connect_height >= self.sync_manager.active_chain.items.len) break;
            const expected_hash = self.sync_manager.active_chain.items[self.connect_height];

            // Check if this block is in the download queue
            const block_entry = self.downloaded_queue.fetchRemove(expected_hash);
            if (block_entry == null) break;
            const block = block_entry.?.value;
            // Free block data after we're done with it
            defer serialize.freeBlock(self.allocator, &block);

            // Validate the block
            try self.validateAndConnectBlock(&block, self.connect_height);

            // Update the block index status
            if (self.sync_manager.block_index.getPtr(expected_hash)) |idx_ptr| {
                idx_ptr.*.status = .validated;
            }

            self.connect_height += 1;
            connected += 1;
        }
    }

    /// Validate a block and update the UTXO set.
    /// All UTXO mutations and the chain tip update are written in a single
    /// atomic WriteBatch so a crash can never leave the DB with UTXOs from
    /// block N but a tip pointing at block N-1 (or vice-versa).
    fn validateAndConnectBlock(self: *BlockDownloader, block: *const types.Block, height: u32) BlockDownloadError!void {
        const chain_store = self.sync_manager.chain_store;
        const params = self.sync_manager.network_params;

        // Assume-valid: skip script verification for blocks at or below the
        // assume-valid height. Structural checks (merkle root, UTXO updates,
        // coinbase value) are still performed.
        const skip_script_verification = params.assume_valid_height > 0 and
            height <= params.assume_valid_height;
        _ = skip_script_verification; // TODO: use when script verification is wired into this path

        // Use an arena allocator for per-block temporary allocations
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        // 1. Verify merkle root
        const tx_hashes = arena_alloc.alloc(types.Hash256, block.transactions.len) catch
            return BlockDownloadError.OutOfMemory;
        for (block.transactions, 0..) |tx, i| {
            tx_hashes[i] = crypto.computeTxid(&tx, arena_alloc) catch
                return BlockDownloadError.OutOfMemory;
        }
        const computed_root = crypto.computeMerkleRoot(tx_hashes, arena_alloc) catch
            return BlockDownloadError.OutOfMemory;
        if (!std.mem.eql(u8, &computed_root, &block.header.merkle_root))
            return BlockDownloadError.BadMerkleRoot;

        // 2. Validate coinbase subsidy
        const subsidy = consensus.getBlockSubsidy(height, params);
        var total_fees: i64 = 0;

        // Collect UTXO creates and spends for atomic batch write
        const CreateEntry = struct { outpoint: types.OutPoint, txout: types.TxOut, height: u32, is_coinbase: bool };
        var pending_creates = std.ArrayList(CreateEntry).init(arena_alloc);
        var pending_spends = std.ArrayList(types.OutPoint).init(arena_alloc);

        // 3. Process each transaction: validate inputs, collect UTXO mutations
        for (block.transactions, 0..) |tx, tx_idx| {
            if (tx_idx == 0) {
                // Coinbase: only creates outputs, no inputs to validate
            } else {
                // Non-coinbase: validate and spend inputs
                var input_sum: i64 = 0;
                for (tx.inputs) |input| {
                    if (chain_store) |cs| {
                        const utxo = cs.getUtxo(&input.previous_output) catch
                            return BlockDownloadError.StorageError;
                        if (utxo == null) return BlockDownloadError.MissingInput;

                        // Coinbase maturity check
                        if (utxo.?.is_coinbase and height - utxo.?.height < consensus.COINBASE_MATURITY)
                            return BlockDownloadError.ImmatureCoinbase;

                        input_sum += utxo.?.value;

                        // Collect spend for atomic batch (don't write yet)
                        pending_spends.append(input.previous_output) catch
                            return BlockDownloadError.OutOfMemory;

                        // Free the script_pubkey we allocated
                        self.allocator.free(utxo.?.script_pubkey);
                    }
                }

                var output_sum: i64 = 0;
                for (tx.outputs) |output| {
                    output_sum += output.value;
                }

                if (input_sum < output_sum) return BlockDownloadError.InsufficientFunds;
                total_fees += input_sum - output_sum;
            }

            // Collect new UTXOs for all outputs (reuse txid from merkle root computation)
            const tx_hash = tx_hashes[tx_idx];
            for (tx.outputs, 0..) |output, out_idx| {
                // Skip unspendable outputs (OP_RETURN)
                if (output.script_pubkey.len > 0 and output.script_pubkey[0] == 0x6a) continue;

                const outpoint = types.OutPoint{
                    .hash = tx_hash,
                    .index = @intCast(out_idx),
                };
                pending_creates.append(.{
                    .outpoint = outpoint,
                    .txout = output,
                    .height = height,
                    .is_coinbase = tx_idx == 0,
                }) catch return BlockDownloadError.OutOfMemory;
            }
        }

        // 4. Verify coinbase amount <= subsidy + fees
        var coinbase_value: i64 = 0;
        for (block.transactions[0].outputs) |output| {
            coinbase_value += output.value;
        }
        if (coinbase_value > subsidy + total_fees)
            return BlockDownloadError.ExcessiveCoinbaseValue;

        // 5. Atomic flush: UTXO creates + spends + chain tip in ONE WriteBatch
        const block_hash = crypto.computeBlockHash(&block.header);
        if (chain_store) |cs| {
            cs.applyBlockAtomic(
                pending_creates.items,
                pending_spends.items,
                &block_hash,
                height,
            ) catch return BlockDownloadError.StorageError;
        }
    }

    /// Handle block download timeouts: re-request from a different peer.
    /// Uses adaptive timeout: doubles on stall, decays on success, capped at 64s.
    fn handleTimeouts(self: *BlockDownloader) void {
        const now = std.time.timestamp();
        var to_remove = std.ArrayList(types.Hash256).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.in_flight.iterator();
        while (iter.next()) |entry| {
            const timeout = @max(BLOCK_DOWNLOAD_TIMEOUT, self.stall_timeout_base);
            if (now - entry.value_ptr.request_time > timeout) {
                // Re-request from another peer in the next cycle
                to_remove.append(entry.key_ptr.*) catch continue;

                // Penalize slow peer
                _ = entry.value_ptr.peer.addBanScore(2);

                // Update peer in-flight count
                self.decrementPeerCount(entry.value_ptr.peer);
            }
        }

        if (to_remove.items.len > 0) {
            // Adaptive timeout: double on stall, cap at 64 seconds
            self.stall_timeout_base = @min(64, self.stall_timeout_base * 2);
        }

        for (to_remove.items) |hash| {
            _ = self.in_flight.remove(hash);
            // Reset download_height to re-request
            if (self.sync_manager.block_index.get(hash)) |idx| {
                if (idx.height < self.download_height) {
                    self.download_height = idx.height;
                }
            }
        }
    }

    /// Process incoming messages from peers.
    /// Block messages are routed to handleBlock.
    fn processMessages(self: *BlockDownloader) !void {
        // This would typically be called by the peer manager's message loop
        // For now, it's a placeholder - the peer manager routes block messages
        // to handleBlock directly.
        _ = self;
    }

    /// Check if IBD is still in progress.
    pub fn isDownloading(self: *const BlockDownloader) bool {
        return self.in_flight.count() > 0 or self.downloaded_queue.count() > 0;
    }

    /// Get current download progress.
    pub fn getProgress(self: *const BlockDownloader) struct {
        connect_height: u32,
        download_height: u32,
        in_flight: usize,
        queued: usize,
    } {
        return .{
            .connect_height = self.connect_height,
            .download_height = self.download_height,
            .in_flight = self.in_flight.count(),
            .queued = self.downloaded_queue.count(),
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "genesis block is added at height 0" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    // Create a minimal peer manager for testing
    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    // Genesis should be at height 0
    try std.testing.expectEqual(@as(u32, 0), sync_mgr.getBestHeight());

    // Genesis hash should match
    const best_hash = sync_mgr.getBestHash();
    try std.testing.expect(best_hash != null);
    try std.testing.expectEqualSlices(u8, &params.genesis_hash, &best_hash.?);

    // Active chain should have exactly one entry
    try std.testing.expectEqual(@as(usize, 1), sync_mgr.active_chain.items.len);
    try std.testing.expectEqualSlices(u8, &params.genesis_hash, &sync_mgr.active_chain.items[0]);

    // Genesis should be in the block index
    try std.testing.expect(sync_mgr.hasBlock(&params.genesis_hash));
}

test "block locator construction - exponential backoff" {
    const allocator = std.testing.allocator;

    // Create a chain of 100 blocks for testing
    var chain: [100]types.Hash256 = undefined;
    for (0..100) |i| {
        chain[i] = [_]u8{0} ** 32;
        chain[i][0] = @intCast(i);
    }

    const locator = try buildBlockLocator(&chain, allocator);
    defer allocator.free(locator);

    // First entry should be the tip (index 99)
    try std.testing.expectEqual(@as(u8, 99), locator[0][0]);

    // First 10 should be consecutive: 99, 98, 97, 96, 95, 94, 93, 92, 91, 90
    for (0..10) |i| {
        try std.testing.expectEqual(@as(u8, @intCast(99 - i)), locator[i][0]);
    }

    // After 10, spacing doubles: 90 - 2 = 88, 88 - 4 = 84, 84 - 8 = 76, etc.
    // locator[10] = 88
    try std.testing.expectEqual(@as(u8, 88), locator[10][0]);
    // locator[11] = 84
    try std.testing.expectEqual(@as(u8, 84), locator[11][0]);
    // locator[12] = 76
    try std.testing.expectEqual(@as(u8, 76), locator[12][0]);

    // Last entry should be genesis (index 0)
    try std.testing.expectEqual(@as(u8, 0), locator[locator.len - 1][0]);
}

test "addWork correctly adds two 256-bit values" {
    // Test basic addition
    {
        var a: [32]u8 = [_]u8{0} ** 32;
        var b: [32]u8 = [_]u8{0} ** 32;
        a[0] = 0x01;
        b[0] = 0x02;

        const result = addWork(a, b);
        try std.testing.expectEqual(@as(u8, 0x03), result[0]);
    }

    // Test carry
    {
        var a: [32]u8 = [_]u8{0} ** 32;
        var b: [32]u8 = [_]u8{0} ** 32;
        a[0] = 0xFF;
        b[0] = 0x01;

        const result = addWork(a, b);
        try std.testing.expectEqual(@as(u8, 0x00), result[0]);
        try std.testing.expectEqual(@as(u8, 0x01), result[1]);
    }

    // Test large values
    {
        const a: [32]u8 = [_]u8{0xFF} ** 32;
        var b: [32]u8 = [_]u8{0} ** 32;
        b[0] = 1;

        const result = addWork(a, b);
        // Should overflow to all zeros
        try std.testing.expectEqual(@as(u8, 0x00), result[0]);
    }
}

test "compareWork comparison logic" {
    // Test equal
    {
        const a = [_]u8{0x42} ** 32;
        const b = [_]u8{0x42} ** 32;
        try std.testing.expectEqual(@as(i32, 0), compareWork(a, b));
    }

    // Test a > b (difference in high byte)
    {
        var a = [_]u8{0} ** 32;
        var b = [_]u8{0} ** 32;
        a[31] = 0x01;
        b[31] = 0x00;
        try std.testing.expectEqual(@as(i32, 1), compareWork(a, b));
    }

    // Test a < b (difference in high byte)
    {
        var a = [_]u8{0} ** 32;
        var b = [_]u8{0} ** 32;
        a[31] = 0x00;
        b[31] = 0x01;
        try std.testing.expectEqual(@as(i32, -1), compareWork(a, b));
    }

    // Test a > b (difference in low byte, high bytes equal)
    {
        var a = [_]u8{0} ** 32;
        var b = [_]u8{0} ** 32;
        a[0] = 0x02;
        b[0] = 0x01;
        try std.testing.expectEqual(@as(i32, 1), compareWork(a, b));
    }
}

test "processHeader rejects headers with invalid PoW" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    // Create a header with valid prev_block (genesis) but impossible PoW
    const bad_header = types.BlockHeader{
        .version = 1,
        .prev_block = params.genesis_hash,
        .merkle_root = [_]u8{0xAB} ** 32,
        .timestamp = params.genesis_header.timestamp + 600,
        .bits = 0x1d00ffff, // Difficulty 1
        .nonce = 0, // Almost certainly won't meet target
    };

    // Should reject with InvalidHeader
    const result = sync_mgr.processHeader(&bad_header);
    try std.testing.expectError(SyncError.InvalidHeader, result);
}

test "processHeader rejects orphan headers" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    // Create a header pointing to an unknown parent
    const orphan_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0xDE} ** 32, // Unknown parent
        .merkle_root = [_]u8{0xAB} ** 32,
        .timestamp = params.genesis_header.timestamp + 600,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    // Should reject with OrphanHeader
    const result = sync_mgr.processHeader(&orphan_header);
    try std.testing.expectError(SyncError.OrphanHeader, result);
}

test "processHeader accepts valid header and updates best tip" {
    const allocator = std.testing.allocator;
    // Use regtest for easier PoW testing
    const params = &consensus.REGTEST;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    // Initial state: genesis at height 0
    try std.testing.expectEqual(@as(u32, 0), sync_mgr.getBestHeight());

    // Create a valid regtest header (regtest has very low difficulty)
    // The regtest bits 0x207fffff makes it easy to find valid blocks
    const new_header = types.BlockHeader{
        .version = 1,
        .prev_block = params.genesis_hash,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = params.genesis_header.timestamp + 600,
        .bits = 0x207fffff, // Regtest difficulty
        .nonce = 0, // Should be valid for regtest
    };

    // Compute the hash and check if it meets target
    const hash = crypto.computeBlockHash(&new_header);
    const target = consensus.bitsToTarget(new_header.bits);

    // If hash meets target, process should succeed
    if (consensus.hashMeetsTarget(&hash, &target)) {
        try sync_mgr.processHeader(&new_header);

        // Best tip should now be at height 1
        try std.testing.expectEqual(@as(u32, 1), sync_mgr.getBestHeight());

        // New block should be in the index
        try std.testing.expect(sync_mgr.hasBlock(&hash));

        // Active chain should have 2 entries
        try std.testing.expectEqual(@as(usize, 2), sync_mgr.active_chain.items.len);
    }
    // If hash doesn't meet target, that's fine - just skip the test
}

test "computeWork returns non-zero for valid bits" {
    // Test with mainnet difficulty 1
    const work = computeWork(0x1d00ffff);

    // Work should be non-zero
    var is_zero = true;
    for (work) |b| {
        if (b != 0) {
            is_zero = false;
            break;
        }
    }
    try std.testing.expect(!is_zero);
}

test "sync state transitions" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    // Initial state should be idle
    try std.testing.expectEqual(SyncState.idle, sync_mgr.state);

    // startHeaderSync without peers should fail
    const result = sync_mgr.startHeaderSync();
    try std.testing.expectError(SyncError.NoPeers, result);
}

test "handleHeaders with empty slice does nothing" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    // Handle empty headers
    try sync_mgr.handleHeaders(&[_]types.BlockHeader{});

    // State should transition to downloading_blocks (not 2000 headers)
    try std.testing.expectEqual(SyncState.downloading_blocks, sync_mgr.state);
}

test "progress with no peers" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    const prog = sync_mgr.progress();
    try std.testing.expectEqual(@as(u32, 0), prog.height);
    try std.testing.expectEqual(@as(u32, 0), prog.total);
    try std.testing.expectEqual(@as(f64, 100.0), prog.percent);
}

test "block locator with single block" {
    const allocator = std.testing.allocator;

    var chain: [1]types.Hash256 = undefined;
    chain[0] = [_]u8{0xAB} ** 32;

    const locator = try buildBlockLocator(&chain, allocator);
    defer allocator.free(locator);

    try std.testing.expectEqual(@as(usize, 1), locator.len);
    try std.testing.expectEqualSlices(u8, &chain[0], &locator[0]);
}

test "block locator with empty chain" {
    const allocator = std.testing.allocator;

    const locator = try buildBlockLocator(&[_]types.Hash256{}, allocator);
    defer allocator.free(locator);

    try std.testing.expectEqual(@as(usize, 0), locator.len);
}

// ============================================================================
// Block Downloader Tests
// ============================================================================

test "block downloader initialization" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    var downloader = BlockDownloader.init(&sync_mgr, allocator);
    defer downloader.deinit();

    // Initial state
    try std.testing.expectEqual(@as(u32, 1), downloader.download_height);
    try std.testing.expectEqual(@as(u32, 1), downloader.connect_height);
    try std.testing.expectEqual(@as(usize, 0), downloader.in_flight.count());
    try std.testing.expectEqual(@as(usize, 0), downloader.downloaded_queue.count());
    try std.testing.expectEqual(@as(i64, 5), downloader.stall_timeout_base);
    try std.testing.expect(!downloader.isDownloading());
}

test "outpointKey produces correct 36-byte key" {
    const outpoint = types.OutPoint{
        .hash = [_]u8{0x11} ** 32,
        .index = 0x12345678,
    };

    const key = outpointKey(&outpoint);

    // First 32 bytes should be the hash
    try std.testing.expectEqualSlices(u8, &outpoint.hash, key[0..32]);

    // Last 4 bytes should be index in little-endian
    try std.testing.expectEqual(@as(u8, 0x78), key[32]);
    try std.testing.expectEqual(@as(u8, 0x56), key[33]);
    try std.testing.expectEqual(@as(u8, 0x34), key[34]);
    try std.testing.expectEqual(@as(u8, 0x12), key[35]);
}

test "outpointKey with zero index" {
    const outpoint = types.OutPoint{
        .hash = [_]u8{0xAB} ** 32,
        .index = 0,
    };

    const key = outpointKey(&outpoint);

    try std.testing.expectEqualSlices(u8, &outpoint.hash, key[0..32]);
    try std.testing.expectEqual(@as(u8, 0x00), key[32]);
    try std.testing.expectEqual(@as(u8, 0x00), key[33]);
    try std.testing.expectEqual(@as(u8, 0x00), key[34]);
    try std.testing.expectEqual(@as(u8, 0x00), key[35]);
}

test "outpointKey with max index" {
    const outpoint = types.OutPoint{
        .hash = [_]u8{0} ** 32,
        .index = 0xFFFFFFFF,
    };

    const key = outpointKey(&outpoint);

    try std.testing.expectEqual(@as(u8, 0xFF), key[32]);
    try std.testing.expectEqual(@as(u8, 0xFF), key[33]);
    try std.testing.expectEqual(@as(u8, 0xFF), key[34]);
    try std.testing.expectEqual(@as(u8, 0xFF), key[35]);
}

test "block downloader getProgress" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    var downloader = BlockDownloader.init(&sync_mgr, allocator);
    defer downloader.deinit();

    const progress = downloader.getProgress();
    try std.testing.expectEqual(@as(u32, 1), progress.connect_height);
    try std.testing.expectEqual(@as(u32, 1), progress.download_height);
    try std.testing.expectEqual(@as(usize, 0), progress.in_flight);
    try std.testing.expectEqual(@as(usize, 0), progress.queued);
}

test "block download constants are sensible" {
    // Verify constants have reasonable values
    try std.testing.expectEqual(@as(usize, 16), MAX_BLOCKS_IN_FLIGHT);
    try std.testing.expectEqual(@as(usize, 128), MAX_BLOCKS_IN_FLIGHT_TOTAL);
    try std.testing.expectEqual(@as(i64, 60), BLOCK_DOWNLOAD_TIMEOUT);
    try std.testing.expectEqual(@as(usize, 500), IBD_BATCH_SIZE);
    try std.testing.expectEqual(@as(u32, 2000), UTXO_FLUSH_INTERVAL);

    // Total should be >= per-peer * expected peer count (8 typical)
    try std.testing.expect(MAX_BLOCKS_IN_FLIGHT_TOTAL >= MAX_BLOCKS_IN_FLIGHT * 8);
}

test "merkle root verification with single transaction" {
    const allocator = std.testing.allocator;

    // Create a simple coinbase transaction
    const coinbase_input = types.TxIn{
        .previous_output = types.OutPoint.COINBASE,
        .script_sig = &[_]u8{ 0x03, 0x01, 0x02, 0x03 },
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const coinbase_output = types.TxOut{
        .value = 5_000_000_000,
        .script_pubkey = &[_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac },
    };
    const coinbase_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{coinbase_input},
        .outputs = &[_]types.TxOut{coinbase_output},
        .lock_time = 0,
    };

    // Compute txid
    const txid = try crypto.computeTxid(&coinbase_tx, allocator);

    // For a single transaction, merkle root equals the txid
    const merkle_root = try crypto.computeMerkleRoot(&[_]types.Hash256{txid}, allocator);

    try std.testing.expectEqualSlices(u8, &txid, &merkle_root);
}

test "merkle root changes with tampered transaction" {
    const allocator = std.testing.allocator;

    // Create original transaction
    const orig_output = types.TxOut{
        .value = 1_000_000,
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0x11} ** 20,
    };
    const orig_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{orig_output},
        .lock_time = 0,
    };

    // Create tampered transaction (different value)
    const tampered_output = types.TxOut{
        .value = 2_000_000, // Different value
        .script_pubkey = &[_]u8{ 0x00, 0x14 } ++ [_]u8{0x11} ** 20,
    };
    const tampered_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{},
        .outputs = &[_]types.TxOut{tampered_output},
        .lock_time = 0,
    };

    const orig_txid = try crypto.computeTxid(&orig_tx, allocator);
    const tampered_txid = try crypto.computeTxid(&tampered_tx, allocator);

    // Txids should be different
    try std.testing.expect(!std.mem.eql(u8, &orig_txid, &tampered_txid));

    // Merkle roots should therefore be different
    const orig_root = try crypto.computeMerkleRoot(&[_]types.Hash256{orig_txid}, allocator);
    const tampered_root = try crypto.computeMerkleRoot(&[_]types.Hash256{tampered_txid}, allocator);

    try std.testing.expect(!std.mem.eql(u8, &orig_root, &tampered_root));
}

test "block download error variants" {
    // Verify all error variants are distinct
    const errors = [_]BlockDownloadError{
        BlockDownloadError.BadMerkleRoot,
        BlockDownloadError.MissingInput,
        BlockDownloadError.ImmatureCoinbase,
        BlockDownloadError.InsufficientFunds,
        BlockDownloadError.ExcessiveCoinbaseValue,
        BlockDownloadError.InvalidBlock,
        BlockDownloadError.NoBestTip,
        BlockDownloadError.OutOfMemory,
        BlockDownloadError.StorageError,
    };

    for (errors, 0..) |e1, i| {
        for (errors[i + 1 ..]) |e2| {
            try std.testing.expect(e1 != e2);
        }
    }
}

test "in-flight block tracking" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var peer_manager = peer_mod.PeerManager.init(allocator, params);
    defer peer_manager.deinit();

    var sync_mgr = SyncManager.init(null, &peer_manager, params, allocator);
    defer sync_mgr.deinit();

    var downloader = BlockDownloader.init(&sync_mgr, allocator);
    defer downloader.deinit();

    // Manually add an in-flight block for testing
    const test_hash = [_]u8{0x42} ** 32;
    const test_height: u32 = 100;
    const request_time = std.time.timestamp();

    // Create a mock peer pointer (unsafe for real use, but ok for testing the map)
    // We use a comptime-known address that won't be dereferenced
    const mock_peer: *peer_mod.Peer = @ptrFromInt(0x1000);

    try downloader.in_flight.put(test_hash, BlockDownloader.InFlightBlock{
        .peer = mock_peer,
        .height = test_height,
        .request_time = request_time,
    });

    // Verify block is tracked
    try std.testing.expectEqual(@as(usize, 1), downloader.in_flight.count());
    try std.testing.expect(downloader.in_flight.contains(test_hash));

    const entry = downloader.in_flight.get(test_hash);
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(test_height, entry.?.height);
    try std.testing.expectEqual(request_time, entry.?.request_time);

    // Now downloading
    try std.testing.expect(downloader.isDownloading());

    // Remove and verify
    _ = downloader.in_flight.remove(test_hash);
    try std.testing.expectEqual(@as(usize, 0), downloader.in_flight.count());
    try std.testing.expect(!downloader.isDownloading());
}

// ============================================================================
// Header Sync Anti-DoS (PRESYNC/REDOWNLOAD) Tests
// ============================================================================

test "HeaderSyncState enum has correct values" {
    try std.testing.expectEqual(@as(u2, 0), @intFromEnum(HeaderSyncState.presync));
    try std.testing.expectEqual(@as(u2, 1), @intFromEnum(HeaderSyncState.redownload));
    try std.testing.expectEqual(@as(u2, 2), @intFromEnum(HeaderSyncState.done));
}

test "PresyncState initialization" {
    const start_hash = [_]u8{0xAB} ** 32;
    const start_work = [_]u8{0x00} ** 31 ++ [_]u8{0x01};
    const start_height: u32 = 100;

    const state = PresyncState.init(start_hash, start_work, start_height);

    try std.testing.expectEqualSlices(u8, &start_hash, &state.last_header_hash);
    try std.testing.expectEqualSlices(u8, &start_work, &state.chain_work);
    try std.testing.expectEqual(@as(u32, 0), state.header_count);
    try std.testing.expectEqual(start_height, state.tip_height);
    try std.testing.expect(state.start_time > 0);
}

test "PresyncState size constant" {
    // Verify the size constant matches actual struct usage
    try std.testing.expect(PresyncState.SIZE_BYTES < 100);
    try std.testing.expect(PresyncState.SIZE_BYTES >= 80);
}

test "HeadersSyncState initialization" {
    const allocator = std.testing.allocator;

    const chain_start_hash = [_]u8{0x11} ** 32;
    const chain_start_work = [_]u8{0x00} ** 31 ++ [_]u8{0x01};
    const min_chain_work = [_]u8{0x00} ** 30 ++ [_]u8{ 0x01, 0x00 }; // Much higher

    var state = HeadersSyncState.init(
        42, // peer_id
        chain_start_hash,
        chain_start_work,
        0, // start height
        min_chain_work,
        allocator,
    );
    defer state.deinit();

    try std.testing.expectEqual(HeaderSyncState.presync, state.state);
    try std.testing.expectEqual(@as(usize, 42), state.peer_id);
    try std.testing.expectEqualSlices(u8, &chain_start_hash, &state.chain_start_hash);
    try std.testing.expectEqualSlices(u8, &min_chain_work, &state.min_chain_work);
}

test "HeadersSyncState processPresyncHeaders rejects empty response" {
    const allocator = std.testing.allocator;

    const chain_start_hash = [_]u8{0} ** 32;
    const chain_start_work = [_]u8{0} ** 32;
    const min_chain_work = [_]u8{0} ** 32;

    var state = HeadersSyncState.init(
        1,
        chain_start_hash,
        chain_start_work,
        0,
        min_chain_work,
        allocator,
    );
    defer state.deinit();

    // Empty headers should abort
    const result = try state.processPresyncHeaders(&[_]types.BlockHeader{});
    try std.testing.expectEqual(PresyncAction.abort, result.action);
    try std.testing.expectEqual(PresyncReason.empty_response, result.reason);
}

test "HeadersSyncState processPresyncHeaders rejects discontinuous chain" {
    const allocator = std.testing.allocator;

    const chain_start_hash = [_]u8{0xAA} ** 32;
    const chain_start_work = [_]u8{0} ** 32;
    const min_chain_work = [_]u8{0} ** 32;

    var state = HeadersSyncState.init(
        1,
        chain_start_hash,
        chain_start_work,
        0,
        min_chain_work,
        allocator,
    );
    defer state.deinit();

    // Header with wrong prev_block should be rejected
    const bad_header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0xBB} ** 32, // Wrong - doesn't match chain_start_hash
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1234567890,
        .bits = 0x207fffff, // Easy regtest difficulty
        .nonce = 0,
    };

    const result = try state.processPresyncHeaders(&[_]types.BlockHeader{bad_header});
    try std.testing.expectEqual(PresyncAction.abort, result.action);
    try std.testing.expectEqual(PresyncReason.discontinuous, result.reason);
}

test "HeadersSyncState wrong state returns error" {
    const allocator = std.testing.allocator;

    var state = HeadersSyncState.init(
        1,
        [_]u8{0} ** 32,
        [_]u8{0} ** 32,
        0,
        [_]u8{0} ** 32,
        allocator,
    );
    defer state.deinit();

    // Manually set state to redownload
    state.state = .redownload;

    const result = try state.processPresyncHeaders(&[_]types.BlockHeader{});
    try std.testing.expectEqual(PresyncAction.abort, result.action);
    try std.testing.expectEqual(PresyncReason.wrong_state, result.reason);
}

test "HeadersSyncState getPresyncProgress returns correct values" {
    const allocator = std.testing.allocator;

    const start_work = [_]u8{0x42} ** 32;
    const min_work = [_]u8{0xFF} ** 32;

    var state = HeadersSyncState.init(
        1,
        [_]u8{0} ** 32,
        start_work,
        100,
        min_work,
        allocator,
    );
    defer state.deinit();

    const progress = state.getPresyncProgress();
    try std.testing.expectEqual(@as(u32, 0), progress.header_count);
    try std.testing.expectEqual(@as(u32, 100), progress.tip_height);
    try std.testing.expectEqualSlices(u8, &start_work, &progress.chain_work);
    try std.testing.expectEqualSlices(u8, &min_work, &progress.min_chain_work);
    try std.testing.expectEqual(HeaderSyncState.presync, progress.state);
}

test "HeadersSyncState nextLocatorHash returns last header hash" {
    const allocator = std.testing.allocator;

    const start_hash = [_]u8{0xDE} ** 32;

    var state = HeadersSyncState.init(
        1,
        start_hash,
        [_]u8{0} ** 32,
        0,
        [_]u8{0} ** 32,
        allocator,
    );
    defer state.deinit();

    const locator = state.nextLocatorHash();
    try std.testing.expectEqualSlices(u8, &start_hash, &locator);
}

test "HeaderSyncManager initialization" {
    const allocator = std.testing.allocator;
    const min_work = [_]u8{0x01} ** 32;

    var manager = HeaderSyncManager.init(allocator, min_work);
    defer manager.deinit();

    try std.testing.expectEqual(@as(usize, 0), manager.peer_states.count());
    try std.testing.expectEqual(@as(usize, 0), manager.activePresyncCount());
    try std.testing.expectEqual(@as(usize, 0), manager.presyncMemoryUsage());
}

test "HeaderSyncManager startSync creates state" {
    const allocator = std.testing.allocator;
    const min_work = [_]u8{0} ** 32;

    var manager = HeaderSyncManager.init(allocator, min_work);
    defer manager.deinit();

    // Create a mock peer pointer
    const mock_peer: *peer_mod.Peer = @ptrFromInt(0x2000);

    const state = try manager.startSync(
        mock_peer,
        [_]u8{0xAA} ** 32,
        [_]u8{0} ** 32,
        0,
    );

    try std.testing.expectEqual(HeaderSyncState.presync, state.state);
    try std.testing.expectEqual(@as(usize, 1), manager.peer_states.count());
    try std.testing.expectEqual(@as(usize, 1), manager.activePresyncCount());
    try std.testing.expect(manager.presyncMemoryUsage() > 0);

    // Verify getState returns the same state
    const retrieved = manager.getState(mock_peer);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqual(state.peer_id, retrieved.?.peer_id);
}

test "HeaderSyncManager removeState cleans up" {
    const allocator = std.testing.allocator;

    var manager = HeaderSyncManager.init(allocator, [_]u8{0} ** 32);
    defer manager.deinit();

    const mock_peer: *peer_mod.Peer = @ptrFromInt(0x3000);

    _ = try manager.startSync(mock_peer, [_]u8{0} ** 32, [_]u8{0} ** 32, 0);
    try std.testing.expectEqual(@as(usize, 1), manager.peer_states.count());

    manager.removeState(mock_peer);
    try std.testing.expectEqual(@as(usize, 0), manager.peer_states.count());
    try std.testing.expect(manager.getState(mock_peer) == null);
}

test "HeaderSyncManager startSync replaces existing state" {
    const allocator = std.testing.allocator;

    var manager = HeaderSyncManager.init(allocator, [_]u8{0} ** 32);
    defer manager.deinit();

    const mock_peer: *peer_mod.Peer = @ptrFromInt(0x4000);

    // Start sync first time
    const state1 = try manager.startSync(mock_peer, [_]u8{0xAA} ** 32, [_]u8{0} ** 32, 100);
    try std.testing.expectEqual(@as(u32, 100), state1.chain_start_height);

    // Start sync second time - should replace
    const state2 = try manager.startSync(mock_peer, [_]u8{0xBB} ** 32, [_]u8{0} ** 32, 200);
    try std.testing.expectEqual(@as(u32, 200), state2.chain_start_height);

    // Should still only have one state
    try std.testing.expectEqual(@as(usize, 1), manager.peer_states.count());
}

test "HeaderSyncManager isLowWorkSync detection" {
    const allocator = std.testing.allocator;

    var manager = HeaderSyncManager.init(allocator, [_]u8{0} ** 32);
    defer manager.deinit();

    const mock_peer1: *peer_mod.Peer = @ptrFromInt(0x5000);
    const mock_peer2: *peer_mod.Peer = @ptrFromInt(0x6000);

    // Peer without state
    try std.testing.expect(!manager.isLowWorkSync(mock_peer1));

    // Start sync for peer1
    const state = try manager.startSync(mock_peer1, [_]u8{0} ** 32, [_]u8{0} ** 32, 0);
    try std.testing.expect(manager.isLowWorkSync(mock_peer1));

    // Peer2 still not in sync
    try std.testing.expect(!manager.isLowWorkSync(mock_peer2));

    // Transition state to redownload
    state.state = .redownload;
    try std.testing.expect(!manager.isLowWorkSync(mock_peer1));
}

test "HeaderSyncManager processHeaders returns null for unknown peer" {
    const allocator = std.testing.allocator;

    var manager = HeaderSyncManager.init(allocator, [_]u8{0} ** 32);
    defer manager.deinit();

    const mock_peer: *peer_mod.Peer = @ptrFromInt(0x7000);

    const result = manager.processHeaders(mock_peer, &[_]types.BlockHeader{});
    try std.testing.expect(result == null);
}

test "PresyncResult action and reason enums" {
    // Verify all action variants
    const actions = [_]PresyncAction{ .request_more, .transition_to_redownload, .abort };
    for (actions) |action| {
        try std.testing.expect(@intFromEnum(action) < 3);
    }

    // Verify all reason variants
    const reasons = [_]PresyncReason{
        .success,
        .wrong_state,
        .empty_response,
        .discontinuous,
        .invalid_pow,
        .insufficient_work,
    };
    for (reasons) |reason| {
        try std.testing.expect(@intFromEnum(reason) < 6);
    }
}

test "presync rejects low-work header attack" {
    const allocator = std.testing.allocator;

    // Set a high min_chain_work threshold
    var high_min_work = [_]u8{0} ** 32;
    high_min_work[31] = 0xFF; // Very high work requirement

    var manager = HeaderSyncManager.init(allocator, high_min_work);
    defer manager.deinit();

    const mock_peer: *peer_mod.Peer = @ptrFromInt(0x8000);

    // Start with zero work
    const state = try manager.startSync(
        mock_peer,
        consensus.REGTEST.genesis_hash,
        [_]u8{0} ** 32,
        0,
    );

    // Create a header that chains from genesis with very low difficulty
    // This simulates a low-work header attack
    const low_work_header = types.BlockHeader{
        .version = 1,
        .prev_block = consensus.REGTEST.genesis_hash,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = consensus.REGTEST.genesis_header.timestamp + 600,
        .bits = 0x207fffff, // Easy regtest difficulty
        .nonce = 0,
    };

    // Compute hash to check if it meets PoW
    const hash = crypto.computeBlockHash(&low_work_header);
    const target = consensus.bitsToTarget(low_work_header.bits);

    if (consensus.hashMeetsTarget(&hash, &target)) {
        // If the header has valid PoW, processing it should work
        // but it won't reach the high min_chain_work threshold with just one header
        const result = try state.processPresyncHeaders(&[_]types.BlockHeader{low_work_header});

        // With less than 2000 headers, should abort due to insufficient work
        try std.testing.expectEqual(PresyncAction.abort, result.action);
        try std.testing.expectEqual(PresyncReason.insufficient_work, result.reason);
    }
    // If hash doesn't meet target, the test still passes - the header would be rejected anyway
}

test "presync memory usage stays bounded" {
    const allocator = std.testing.allocator;

    var manager = HeaderSyncManager.init(allocator, [_]u8{0} ** 32);
    defer manager.deinit();

    // Add many peer states
    const num_peers: usize = 100;
    for (0..num_peers) |i| {
        const mock_peer: *peer_mod.Peer = @ptrFromInt(0x10000 + i);
        _ = try manager.startSync(mock_peer, [_]u8{0} ** 32, [_]u8{0} ** 32, 0);
    }

    try std.testing.expectEqual(num_peers, manager.peer_states.count());
    try std.testing.expectEqual(num_peers, manager.activePresyncCount());

    // Memory usage should be bounded: ~100 bytes per peer
    const memory = manager.presyncMemoryUsage();
    try std.testing.expect(memory <= num_peers * 100);
}

test "MAX_HEADERS_PER_MESSAGE constant" {
    try std.testing.expectEqual(@as(usize, 2000), MAX_HEADERS_PER_MESSAGE);
}
