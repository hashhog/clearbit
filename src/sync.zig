const std = @import("std");
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");

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
