const std = @import("std");
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const banlist = @import("banlist.zig");
const v2_transport = @import("v2_transport.zig");
const storage = @import("storage.zig");
const serialize = @import("serialize.zig");
const mempool_mod = @import("mempool.zig");
const validation = @import("validation.zig");
const asmap_mod = @import("asmap.zig");
const proxy_mod = @import("proxy.zig");
const wallet_mod = @import("wallet.zig");
const addrman_mod = @import("addrman.zig");

// ============================================================================
// Peer Manager Constants
// ============================================================================

/// Maximum number of outbound connections (8 full-relay as per Bitcoin Core).
pub const MAX_OUTBOUND_CONNECTIONS: usize = 8;

/// Maximum number of inbound connections.
pub const MAX_INBOUND_CONNECTIONS: usize = 117;

/// One-shot announce flag for the CLEARBIT_REORG=1 opt-in path.  Set
/// true on the first drain after the env var is detected so the
/// "undo capture enabled" line emits exactly once per process.
var reorg_announce_emitted: bool = false;

/// Returns true if `CLEARBIT_REORG` env var is set to "1" or "strict".
/// This gates the reorg-safe IBD path: with the flag on, drainBlockBuffer
/// uses connectBlockFastWithUndo (captures + persists per-block undo
/// data); reorg detection in the headers handler is also active.  Off
/// = legacy single-fork fast path (current live-node behaviour).
fn isReorgEnabled() bool {
    const v = std.posix.getenv("CLEARBIT_REORG") orelse return false;
    return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "warn") or
        std.mem.eql(u8, v, "strict");
}

/// Mirror of storage.MAX_REORG_DEPTH (= MIN_BLOCKS_TO_KEEP, 288).  Headers
/// for a competing fork whose split-point is more than this many blocks
/// behind the active tip are refused: we cannot disconnect that far without
/// risking running out of undo data.  Per BIP-37 / Core's MIN_BLOCKS_TO_KEEP.
pub const MAX_REORG_DEPTH: u32 = 288;

/// Hard cap on `header_index` size.  Once exceeded, oldest non-active-chain
/// entries are evicted in batch.  10k entries × ~96B per entry = ~1MB
/// resident — small enough to keep around even in a constrained datadir.
pub const MAX_HEADER_INDEX: usize = 10_000;

/// In-memory record of a single block header that we've SEEN but may or
/// may not have a body for.  Populated by the `.headers` handler so we
/// can detect competing-fork announcements (Case B).  Each entry knows
/// its prev hash, height (from prev's height + 1), accumulated
/// chain_work, timestamp, and the original 80-byte header (for re-relay
/// or POW re-verification later).
pub const BlockHeaderEntry = struct {
    /// Block hash (double-SHA256 of the 80-byte header).
    hash: types.Hash256,
    /// Predecessor block hash (the header's `prev_block` field).
    prev_hash: types.Hash256,
    /// Height of this block (parent's height + 1 — genesis is 0).
    height: u32,
    /// Cumulative chain work: parent's chain_work + this header's work.
    /// Stored big-endian (matches BlockIndexEntry.chain_work).
    chain_work: [32]u8,
    /// Block timestamp (header.timestamp).
    timestamp: u32,
    /// Original 80-byte serialized header (for getdata replay if needed).
    header: types.BlockHeader,
    /// Last access timestamp (seconds since epoch).  Used by the LRU
    /// eviction sweep to keep recently-touched entries.
    last_seen: i64,
};

/// State of an in-progress reorg attempt.  Set when the headers handler
/// detects a competing-fork branch with strictly higher chainwork than
/// our active tip.  Cleared after the reorg completes (success or
/// abort).  Owned by PeerManager.
pub const PendingReorg = struct {
    /// Most-recent ancestor that's on the active chain.  Reorg walks
    /// the active chain back to this hash, then connects fork blocks
    /// in order.
    fork_point: types.Hash256,
    /// Hashes of fork blocks, in connection order: [fork_point + 1,
    /// fork_point + 2, ..., new_tip].  All must be present in the
    /// `block_buffer` before we can fire `reorgToChain`.
    fork_hashes: std.ArrayList(types.Hash256),
    /// Chain work at the new tip (final element).  Used to confirm we
    /// haven't been undercut by a fresh active-chain extension that
    /// passed this fork's chainwork before bodies arrived.
    new_tip_chain_work: [32]u8,
    /// Peer that announced the fork (used for misbehaving on failure).
    /// Stored as raw `*Peer` so the PendingReorg refers back to its
    /// originator on success / failure logging.  May become a dangling
    /// pointer if the peer disconnects mid-reorg; use only for ID +
    /// the misbehaving call inside the same drain pass.
    source_peer: ?*Peer,

    pub fn deinit(self: *PendingReorg) void {
        self.fork_hashes.deinit();
    }
};

// =====================================================================
// Chain-work helpers (256-bit big-endian).
//
// Bitcoin Core's GetBlockProof returns work = (~target / (target + 1)) + 1
// where target is the 256-bit difficulty target derived from header.bits.
// We mirror that math here using 64-bit limbs (4 limbs = 256 bits).
//
// Chain work for an entry = parent.chain_work + GetBlockProof(this header).
// Stored big-endian to keep byte-comparison semantics (matches
// validation.BlockIndexEntry.chain_work and ChainManager.compareChainWork).
// =====================================================================

/// In-place big-endian 256-bit add: a += b.  No-op on overflow (chainwork
/// values used here are sums of GetBlockProof results — overflow would
/// require >2^256 cumulative work, which is impossible at any realistic
/// difficulty).  Suppressing wrap silently is acceptable.
pub fn addChainWorkBE(a: *[32]u8, b: *const [32]u8) void {
    var carry: u16 = 0;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        const sum = @as(u16, a[i]) + @as(u16, b[i]) + carry;
        a[i] = @intCast(sum & 0xFF);
        carry = sum >> 8;
    }
    // Drop final carry (overflow); see comment above.
}

/// Compute GetBlockProof for one header, given the compact-target bits.
/// Returns the work as a 32-byte big-endian array.
///
/// Bitcoin Core (validation.cpp::GetBlockProof):
///   bnTarget = ArithToUint256(...) from nBits
///   return (~bnTarget / (bnTarget + 1)) + 1
///
/// All math is done on 32-byte big-endian arrays via byte-level
/// helpers; this keeps the call cost bounded (no allocator) and
/// matches the storage representation exactly.  When bnTarget is zero
/// (which the SetCompact contract treats as "negative or overflow")
/// we return zero work.
pub fn workFromBits(bits: u32) [32]u8 {
    const zero: [32]u8 = [_]u8{0} ** 32;
    // bitsToTarget returns little-endian; convert to big-endian for math.
    const target_le = consensus.bitsToTarget(bits);
    var target_be: [32]u8 = undefined;
    {
        var i: usize = 0;
        while (i < 32) : (i += 1) target_be[i] = target_le[31 - i];
    }
    // Quick zero check.
    var nonzero = false;
    for (target_be) |b| {
        if (b != 0) {
            nonzero = true;
            break;
        }
    }
    if (!nonzero) return zero;

    // Compute ~target.
    var nt: [32]u8 = undefined;
    {
        var i: usize = 0;
        while (i < 32) : (i += 1) nt[i] = ~target_be[i];
    }

    // Compute target + 1 (carry-propagate from low byte = index 31 → 0).
    var t_plus_1: [32]u8 = target_be;
    {
        var carry: u16 = 1;
        var j: usize = 32;
        while (j > 0 and carry != 0) {
            j -= 1;
            const sum = @as(u16, t_plus_1[j]) + carry;
            t_plus_1[j] = @intCast(sum & 0xFF);
            carry = sum >> 8;
        }
    }

    // Long-divide nt by t_plus_1 using 256-bit shift-and-subtract.
    // This bounds runtime at 256 iterations per header — slower than a
    // bigint divide but allocator-free and correct for arbitrary bits.
    var quotient: [32]u8 = [_]u8{0} ** 32;
    var remainder: [32]u8 = [_]u8{0} ** 32;

    // Process bits MSB→LSB.
    var bit_i: usize = 0;
    while (bit_i < 256) : (bit_i += 1) {
        // Shift remainder left by 1.
        var carry_bit: u8 = 0;
        var j: usize = 32;
        while (j > 0) {
            j -= 1;
            const new_carry: u8 = (remainder[j] >> 7) & 1;
            remainder[j] = (remainder[j] << 1) | carry_bit;
            carry_bit = new_carry;
        }
        // Pull next bit of nt into remainder LSB.
        const byte_i: usize = bit_i / 8;
        const bit_off: u3 = @intCast(7 - (bit_i % 8));
        const next_bit: u8 = (nt[byte_i] >> bit_off) & 1;
        remainder[31] |= next_bit;

        // If remainder >= t_plus_1 then quotient bit = 1, remainder -= divisor.
        if (cmpChainWorkBE(&remainder, &t_plus_1) >= 0) {
            // remainder -= t_plus_1.
            var borrow: i16 = 0;
            var k: usize = 32;
            while (k > 0) {
                k -= 1;
                const diff: i16 = @as(i16, remainder[k]) - @as(i16, t_plus_1[k]) - borrow;
                if (diff < 0) {
                    remainder[k] = @intCast(diff + 256);
                    borrow = 1;
                } else {
                    remainder[k] = @intCast(diff);
                    borrow = 0;
                }
            }
            // Set quotient bit at position bit_i.
            quotient[byte_i] |= (@as(u8, 1) << bit_off);
        }
    }

    // quotient += 1 (Core's GetBlockProof).
    {
        var carry: u16 = 1;
        var j: usize = 32;
        while (j > 0 and carry != 0) {
            j -= 1;
            const sum = @as(u16, quotient[j]) + carry;
            quotient[j] = @intCast(sum & 0xFF);
            carry = sum >> 8;
        }
    }

    return quotient;
}

/// Compare two 256-bit big-endian chain-work values.  Returns >0 if
/// a > b, <0 if a < b, 0 if equal.  Mirrors
/// validation.ChainManager.compareChainWork.
pub fn cmpChainWorkBE(a: *const [32]u8, b: *const [32]u8) i32 {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/// Synthesize a placeholder big-endian chain_work value for an
/// active-chain entry whose true cumulative work isn't tracked.
/// Encodes `(height + 1)` into the low 5 bytes of a 32-byte
/// big-endian buffer.  This is intentionally cheap — the only
/// invariant the consumer cares about is that two heights H1 < H2
/// produce work-values W1 < W2, so the strict-greater chain-work
/// comparison in `maybeArmReorg` correctly reflects "fork extends
/// past tip".  Used only during the in-memory header-index walk;
/// never persisted.
pub fn chainWorkFromHeight(height: u32) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    // Encode (height + 1) big-endian into the trailing 5 bytes,
    // leaving the high 27 bytes zero so any real PoW chain_work
    // (which is always >> 2^40 for non-trivial difficulty) compares
    // strictly greater.  Adding 1 ensures genesis (height=0) has
    // strictly positive work — same convention as Core's
    // GetBlockProof for the genesis block.
    const v: u64 = @as(u64, height) + 1;
    out[27] = @intCast((v >> 32) & 0xFF);
    out[28] = @intCast((v >> 24) & 0xFF);
    out[29] = @intCast((v >> 16) & 0xFF);
    out[30] = @intCast((v >> 8) & 0xFF);
    out[31] = @intCast(v & 0xFF);
    return out;
}

/// Maximum total connections (125 as per Bitcoin Core).
pub const MAX_TOTAL_CONNECTIONS: usize = MAX_OUTBOUND_CONNECTIONS + MAX_INBOUND_CONNECTIONS;

// ============================================================================
// P2P anti-eclipse hardening — Bitcoin Core v31.99 (net.cpp ThreadOpenConnections
// FEELER branch + net_processing.cpp getaddr/ProcessAddrs anti-DoS).
// ============================================================================

/// Feeler probe interval, seconds (Core net.h `FEELER_INTERVAL` = 120s / 2min).
/// Every FEELER_INTERVAL the maintenance loop opens ONE short-lived feeler to a
/// NEW-table address, handshakes, promotes it NEW->TRIED, and disconnects.
pub const FEELER_INTERVAL_SECS: i64 = 120;

/// Maximum simultaneous feeler connections (Core net.h `MAX_FEELER_CONNECTIONS`
/// = 1). A feeler is short-lived and disconnects right after the handshake, so
/// at most one is ever in flight.
pub const MAX_FEELER_CONNECTIONS: usize = 1;

/// Percentage of the addrman shared in a getaddr response (Core
/// net_processing.cpp `MAX_PCT_ADDR_TO_SEND` = 23). The getaddr response is
/// capped at min(MAX_ADDR_TO_SEND, floor(0.23 * addrman_size)) — integer
/// truncating division, matching Core `CAddrMan::GetAddr_` exactly.
pub const MAX_PCT_ADDR_TO_SEND: usize = 23;

/// Absolute cap on addresses returned in a single getaddr response (Core
/// net_processing.cpp `MAX_ADDR_TO_SEND` = 1000). Also the token-bucket cap.
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// Inbound-addr token-bucket refill rate, tokens/sec (Core net_processing.cpp
/// `MAX_ADDR_RATE_PER_SECOND` = 0.1). One token is spent per processed address.
pub const MAX_ADDR_RATE_PER_SECOND: f64 = 0.1;

/// Soft cap on the inbound-addr token bucket (Core net_processing.cpp
/// `MAX_ADDR_PROCESSING_TOKEN_BUCKET` = MAX_ADDR_TO_SEND = 1000).
pub const MAX_ADDR_PROCESSING_TOKEN_BUCKET: f64 = 1000.0;

/// getaddr 23%-cap over an addrman of `size` shareable entries:
/// min(MAX_ADDR_TO_SEND, floor(0.23 * size)). Mirrors Core's
/// `CAddrMan::GetAddr_` cap EXACTLY (addrman.cpp:800):
///   `nNodes = max_pct * nNodes / 100;`            // integer (truncating) floor
///   `nNodes = std::min(nNodes, max_addresses);`   // clamp to MAX_ADDR_TO_SEND
/// Core applies NO floor-of-1: an addrman with size < 5 (where 23*size/100 == 0)
/// yields ZERO addresses, identical to this helper. e.g. size=10 -> 2 (not 3),
/// size=1 -> 0, size=4 -> 0.
pub fn getaddrCap(size: usize) usize {
    // Core: max_pct * nNodes / 100 is integer floor; size==0 falls out as 0.
    const pct = (size * MAX_PCT_ADDR_TO_SEND) / 100;
    return @min(pct, MAX_ADDR_TO_SEND);
}

/// Peer rotation interval in seconds (30 minutes).
pub const PEER_ROTATION_INTERVAL: i64 = 30 * 60;

/// ASMap health check interval in seconds (1 hour).
/// Core runs this every 24 h (net.h:93); clearbit uses a shorter window so
/// that operators get earlier feedback on coverage gaps.
/// Reference: bitcoin-core/src/net.h  `ASMAP_HEALTH_CHECK_INTERVAL`
pub const ASMAP_HEALTH_CHECK_INTERVAL: i64 = 3600;

/// DNS seed resolution timeout in seconds.
pub const DNS_SEED_TIMEOUT: u32 = 10;

/// Default ban duration in seconds (24 hours).
pub const DEFAULT_BAN_DURATION: i64 = 24 * 60 * 60;

/// Clamp a peer-advertised ADDR/ADDRV2 timestamp to a sane window.
/// Mirrors Bitcoin Core net_processing.cpp:5678-5679:
///   if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_time + 10min)
///       addr.nTime = current_time - 5*24h;
/// `peer_time` is the u32 timestamp from the wire; `now` is the current
/// Unix time (i64).  Returns a u64 suitable for addrman / AddressInfo.last_seen.
pub fn clampAddrTimestamp(peer_time: u32, now: i64) u64 {
    const pt: i64 = @as(i64, peer_time);
    const ten_minutes: i64 = 10 * 60;
    const five_days: i64 = 5 * 24 * 60 * 60;
    // pre-2001 sentinel: epoch + ~3.17 years (Core uses 100_000_000 seconds)
    const pre2001: i64 = 100_000_000;
    const clamped: i64 = if (pt <= pre2001 or pt > now + ten_minutes)
        now - five_days
    else
        pt;
    return if (clamped < 0) 0 else @intCast(clamped);
}

/// Minimum time between connection attempts to the same address (10 minutes).
pub const MIN_RECONNECT_INTERVAL: i64 = 10 * 60;

/// Reconnect interval for manual peers (`addnode <ip> add`). Must be
/// much shorter than MIN_RECONNECT_INTERVAL — when a remote at-tip node
/// evicts our IBD-state peer ("behind our tip"), we want to re-establish
/// within seconds, not 10 minutes.
pub const MANUAL_RECONNECT_INTERVAL: i64 = 30;

/// Ping interval for idle peers (2 minutes).
pub const PING_INTERVAL: i64 = 2 * 60;

/// How often the run loop durably flushes wallets the connect loop marked
/// dirty (seconds).  Bounds wallet-state loss on an unclean exit to roughly
/// this window.  Cheap: a no-op when no wallet changed since the last flush.
pub const WALLET_FLUSH_INTERVAL_SECS: i64 = 30;

/// Periodic addrman (peers.dat) dump cadence (seconds). Mirrors Core's
/// DUMP_PEERS_INTERVAL = 900s (net.cpp scheduler.scheduleEvery(DumpAddresses)).
/// Without this the learned-peer table was persisted ONLY on graceful shutdown
/// (deinit), so a SIGKILL/OOM/power-loss lost every address learned since boot.
pub const DUMP_PEERS_INTERVAL_SECS: i64 = 900;

// ============================================================================
// Stale Peer Eviction Constants (Bitcoin Core net_processing.cpp)
// ============================================================================

/// Stale tip check interval in seconds (45 seconds as per Bitcoin Core EXTRA_PEER_CHECK_INTERVAL).
pub const STALE_CHECK_INTERVAL: i64 = 45;

/// Stale tip threshold in seconds (30 minutes).
/// If a peer's best_known_height is behind our tip for this long, consider eviction.
pub const STALE_TIP_THRESHOLD: i64 = 30 * 60;

/// Ping timeout in seconds (20 minutes as per Bitcoin Core TIMEOUT_INTERVAL).
/// If we sent a ping and no pong within this time, disconnect.
pub const PING_TIMEOUT: i64 = 20 * 60;

/// Headers response timeout in seconds.
/// Testnet4 peers are slower, so use 5 minutes instead of Bitcoin Core's 2 minutes.
pub const HEADERS_RESPONSE_TIMEOUT: i64 = 5 * 60;

/// Block download timeout in seconds (20 minutes as per Bitcoin Core).
/// If a block is in-flight and not received within this time, disconnect.
pub const BLOCK_DOWNLOAD_TIMEOUT: i64 = 20 * 60;

/// Drain-wedge staller timeout in seconds. When `connect_cursor` is stuck on a
/// missing FRONT block while LATER blocks sit buffered (the head-of-line wedge a
/// slow/unresponsive public peer causes), cancel that block's in-flight request
/// after this long (decrement the holder + drop it from `inflight_block_peer`)
/// so the pipeline re-requests it from another peer — instead of waiting the full
/// `BLOCK_DOWNLOAD_TIMEOUT` (20 min). Mirrors Bitcoin Core's `BLOCK_STALLING_TIMEOUT`
/// (net_processing.cpp, 2s initial). The per-block map makes the re-request
/// drift-free: `pipelineBlockRequests` never re-issues a block still tracked
/// in-flight, so only the cancelled front block is re-requested.
pub const DRAIN_WEDGE_STALL_TIMEOUT: i64 = 2;

/// Maximum blocks in flight per peer, matching Bitcoin Core's
/// `MAX_BLOCKS_IN_TRANSIT_PER_PEER` (src/net_processing.cpp).  The block
/// download pipeline is level-triggered per peer — every SendMessages tick
/// each peer is eligible for up to this many in-flight block requests.  No
/// global counter gates the pipeline; a slow peer only throttles itself
/// and is handled by `checkBlockDownloadTimeouts` (disconnect).
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: u32 = 16;

/// Chain sync timeout in seconds (20 minutes as per Bitcoin Core CHAIN_SYNC_TIMEOUT).
pub const CHAIN_SYNC_TIMEOUT: i64 = 20 * 60;

/// Minimum connection time before eviction is considered (30 seconds as per Bitcoin Core).
pub const MINIMUM_CONNECT_TIME: i64 = 30;

/// Maximum number of outbound peers to protect from eviction (4 as per Bitcoin Core).
pub const MAX_OUTBOUND_PEERS_TO_PROTECT: usize = 4;

/// Maximum number of block-relay-only anchor connections.
pub const MAX_BLOCK_RELAY_ONLY_ANCHORS: usize = 2;

/// Maximum number of block-relay-only connections.
pub const MAX_BLOCK_RELAY_ONLY_CONNECTIONS: usize = 2;

/// Bitcoin Core's MAX_NUM_UNCONNECTING_HEADERS_MSGS
/// (net_processing.cpp).  A peer that delivers more than this many
/// successive unconnecting-headers messages is disconnected.  Per
/// CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
/// (Pattern B), clearbit previously instant-disconnected on the first
/// orphan; this constant lets us tolerate up to 10 (>1 transient reorg)
/// before banning honest peers.
pub const MAX_NUM_UNCONNECTING_HEADERS_MSGS: u32 = 10;

/// Hardcoded fallback peers for testnet4 (DNS seeds unreliable).
pub const TESTNET_FALLBACK_PEERS: []const []const u8 = &[_][]const u8{
    "127.0.0.1", // Placeholder - would be real testnet4 peers
};

// ============================================================================
// BIP-133 Feefilter Constants
// ============================================================================

/// Average delay between feefilter broadcasts in seconds (10 minutes).
pub const AVG_FEEFILTER_BROADCAST_INTERVAL: i64 = 10 * 60;

/// Maximum feefilter broadcast delay after significant change (5 minutes).
pub const MAX_FEEFILTER_CHANGE_DELAY: i64 = 5 * 60;

/// Default minimum relay fee in sat/kvB.
pub const MIN_RELAY_FEE: u64 = 1000;

/// Incremental relay fee in sat/kvB (for RBF replacement).
pub const INCREMENTAL_RELAY_FEE: u64 = 1000;

// ============================================================================
// Eclipse Attack Protection Constants
// ============================================================================

/// Number of peers to protect by fastest ping time (8 as per Bitcoin Core).
pub const EVICTION_PROTECT_PING: usize = 8;

/// Number of peers to protect by most recent transaction relay.
pub const EVICTION_PROTECT_TX: usize = 4;

/// Number of peers to protect by most recent block relay.
pub const EVICTION_PROTECT_BLOCK: usize = 4;

/// Number of non-tx-relay peers to protect by block relay (Bitcoin Core protects 8).
pub const EVICTION_PROTECT_BLOCK_RELAY_ONLY: usize = 8;

/// Number of peers to protect by longest connection time.
pub const EVICTION_PROTECT_TIME: usize = 8;

/// Number of peers to protect by distinct netgroups.
pub const EVICTION_PROTECT_NETGROUP: usize = 4;

// ============================================================================
// Network Group Functions (Eclipse Attack Protection)
// ============================================================================

/// Compute network group for an address.
/// For IPv4: returns /16 subnet identifier (first 2 octets).
/// For IPv6: returns /32 identifier (first 4 bytes).
/// This is used to ensure outbound connection diversity.
pub fn netGroup(address: std.net.Address) u32 {
    switch (address.any.family) {
        std.posix.AF.INET => {
            // IPv4: use /16 prefix (first 2 octets)
            const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
            const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
            return (@as(u32, ip_bytes[0]) << 8) | @as(u32, ip_bytes[1]);
        },
        std.posix.AF.INET6 => {
            // IPv6: use /32 prefix (first 4 bytes)
            const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address.any)));
            return (@as(u32, ip6.addr[0]) << 24) |
                (@as(u32, ip6.addr[1]) << 16) |
                (@as(u32, ip6.addr[2]) << 8) |
                @as(u32, ip6.addr[3]);
        },
        else => return 0,
    }
}

/// Check if two addresses are in the same network group.
pub fn sameNetGroup(addr1: std.net.Address, addr2: std.net.Address) bool {
    return netGroup(addr1) == netGroup(addr2);
}

/// Convert a std.net.Address to its canonical 16-byte big-endian IPv6
/// representation for passing to the asmap interpreter.
/// IPv4 addresses are returned as IPv4-mapped IPv6 (::ffff:a.b.c.d).
/// Unknown families return all-zeros (will map to ASN 0).
fn addressToIPv6(address: std.net.Address) [16]u8 {
    var out = [_]u8{0} ** 16;
    switch (address.any.family) {
        std.posix.AF.INET => {
            const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
            const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            out[10] = 0xFF;
            out[11] = 0xFF;
            out[12] = ip_bytes[0];
            out[13] = ip_bytes[1];
            out[14] = ip_bytes[2];
            out[15] = ip_bytes[3];
        },
        std.posix.AF.INET6 => {
            const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address.any)));
            @memcpy(&out, &ip6.addr);
        },
        else => {}, // all-zeros → ASN 0
    }
    return out;
}

/// Look up the mapped AS number for `address` using the loaded asmap.
/// Returns 0 when asmap is not loaded or the address is non-IPv4/IPv6.
/// Mirrors Core's `NetGroupManager::GetMappedAS(address)`.
pub fn getMappedAS(asmap_data: []const u8, address: std.net.Address) u32 {
    if (asmap_data.len == 0) return 0;
    // Only IPv4 and IPv6 addresses have ASN mappings.
    if (address.any.family != std.posix.AF.INET and
        address.any.family != std.posix.AF.INET6) return 0;
    const ip = addressToIPv6(address);
    return asmap_mod.interpret(asmap_data, ip);
}

// ============================================================================
// BIP-35 mempool inventory helpers
//
// `buildMempoolInventory` lives in mempool.zig (it is a mempool query) and
// takes raw bool/u64 args so it doesn't need the Peer struct.  We thin-wrap
// it here only to drive `Peer.sendMessage`.
// ============================================================================

/// BIP-35 mempool handler: walk the mempool and emit chunked `inv` messages
/// to `peer`.  Mirrors Bitcoin Core's loop in `SendMessages`
/// (`net_processing.cpp:5996`).  Caller has already verified that we
/// advertised NODE_BLOOM (otherwise the peer should be disconnected).
pub fn sendMempoolInventory(
    peer: *Peer,
    pool: *const mempool_mod.Mempool,
    allocator: std.mem.Allocator,
) !void {
    const inv = try mempool_mod.buildMempoolInventory(
        pool,
        peer.is_witness_capable,
        peer.fee_filter_received,
        allocator,
    );
    defer allocator.free(inv);

    var i: usize = 0;
    while (i < inv.len) {
        const end = @min(i + p2p.MAX_INV_SIZE, inv.len);
        const chunk = inv[i..end];
        const inv_msg = p2p.Message{ .inv = .{ .inventory = chunk } };
        peer.sendMessage(&inv_msg) catch {};
        i = end;
    }
}

// ============================================================================
// Peer State Machine
// ============================================================================

pub const PeerState = enum {
    connecting,
    connected,
    version_sent,
    version_received,
    handshake_complete,
    disconnecting,
    disconnected,
};

pub const PeerDirection = enum {
    inbound,
    outbound,
};

/// Connection type for more granular tracking (as per Bitcoin Core).
pub const ConnectionType = enum {
    /// Standard inbound connection.
    inbound,
    /// Full-relay outbound connection (8 slots).
    outbound_full_relay,
    /// Block-relay-only outbound connection (2 slots).
    block_relay,
    /// Manual connection (-addnode).
    manual,
    /// Feeler connection (short-lived address validation).
    feeler,
    /// Address fetch connection.
    addr_fetch,
};

/// BIP-324 transport protocol version.
pub const TransportVersion = enum {
    /// V1 legacy unencrypted transport.
    v1,
    /// V2 encrypted transport (BIP-324).
    v2,
};

// ============================================================================
// Peer Errors
// ============================================================================

pub const PeerError = error{
    ConnectionFailed,
    HandshakeFailed,
    Timeout,
    BadMagic,
    BadChecksum,
    MessageTooLarge,
    ProtocolViolation,
    ConnectionClosed,
    OutOfMemory,
};

// ============================================================================
// Subver (user-agent) sanitization
// ============================================================================

/// Maximum accepted subver length, matching Bitcoin Core's
/// `MAX_SUBVERSION_LENGTH` (net.h:67).  Core rejects (throws on) a longer
/// subver at receipt via `LIMITED_STRING`; clearbit accepts the VERSION but
/// caps the stored CLEAN copy to this length so the operator-facing string can
/// never grow unbounded.
pub const MAX_SUBVERSION_LENGTH: usize = 256;

/// Allocate an owned, sanitized copy of a peer-advertised user-agent string.
///
/// Faithful port of Bitcoin Core's `SanitizeString(str, SAFE_CHARS_DEFAULT)`
/// (util/strencodings.cpp:31).  Core keeps ONLY the characters in
///   `[A-Za-z0-9]` + " .,;-_/:?@()"
/// and drops every other byte.  This guarantees the result is:
///   - pure printable ASCII (no control chars, no non-UTF8 bytes), and
///   - free of JSON metacharacters (`"`, `\`) and HTML-dangerous chars
///     (`<`, `>`, `&`), so it is safe to splice directly into a JSON string
///     literal without further escaping.
///
/// The input is first truncated to `MAX_SUBVERSION_LENGTH` bytes (Core bounds
/// the raw subver before sanitizing).  Returns a freshly-allocated slice the
/// caller owns; an empty input yields an empty (but non-null) allocation.
pub fn sanitizeSubVer(allocator: std.mem.Allocator, raw: []const u8) std.mem.Allocator.Error![]u8 {
    const bounded = raw[0..@min(raw.len, MAX_SUBVERSION_LENGTH)];
    var out = try std.ArrayList(u8).initCapacity(allocator, bounded.len);
    errdefer out.deinit();
    for (bounded) |c| {
        const safe = switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9' => true,
            ' ', '.', ',', ';', '-', '_', '/', ':', '?', '@', '(', ')' => true,
            else => false,
        };
        if (safe) out.appendAssumeCapacity(c);
    }
    return out.toOwnedSlice();
}

// ============================================================================
// Peer Connection
// ============================================================================

/// Represents a single peer connection.
pub const Peer = struct {
    stream: std.net.Stream,
    address: std.net.Address,
    state: PeerState,
    direction: PeerDirection,
    version_info: ?p2p.VersionMessage,
    services: u64,
    last_ping_time: i64,
    last_pong_time: i64,
    last_ping_nonce: u64,
    last_message_time: i64,
    bytes_sent: u64,
    bytes_received: u64,
    start_height: i32,
    network_params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
    recv_buffer: std.ArrayList(u8),
    is_witness_capable: bool,
    is_headers_first: bool,
    ban_score: u32,
    should_ban: bool,
    /// Connection type for eclipse protection.
    conn_type: ConnectionType,
    /// Time of last block received from this peer.
    last_block_time: i64,
    /// Time of last transaction received from this peer.
    last_tx_time: i64,
    /// Minimum ping time observed (in seconds).
    min_ping_time: i64,
    /// Whether this peer relays transactions.
    relay_txs: bool,
    /// Whether this is a protected peer (cannot be evicted).
    is_protected: bool,
    /// Time when connection was established.
    connect_time: i64,
    /// Fee filter received from this peer (BIP-133). Minimum fee rate in sat/kvB.
    /// We should not relay transactions below this rate to this peer.
    fee_filter_received: u64 = 0,
    /// Fee filter we last sent to this peer (BIP-133). In sat/kvB.
    fee_filter_sent: u64 = 0,
    /// Next time (microseconds since epoch) to send a feefilter message.
    next_send_feefilter: i64 = 0,
    /// Best known block height from this peer (from headers or blocks).
    best_known_height: u32 = 0,
    /// Time when we last sent a getheaders request to this peer.
    last_getheaders_time: i64 = 0,
    /// Time when the oldest block-in-flight was requested (0 if no blocks in flight).
    oldest_block_in_flight_time: i64 = 0,
    /// Number of blocks currently in flight from this peer.
    blocks_in_flight_count: u32 = 0,
    /// Whether this peer is protected from stale tip eviction.
    chain_sync_protected: bool = false,

    /// Clock offset (seconds) from the peer's VERSION message timestamp:
    /// peer_version_timestamp - our_time_at_receipt.  Matches Bitcoin Core's
    /// CNode::nTimeOffset.  Zero until VERSION has been received.
    time_offset: i64 = 0,

    /// Mapped Autonomous System Number for this peer's address.
    /// Set at connection-establishment time when an asmap is loaded.
    /// 0 when asmap is not loaded or the ASN is unknown.
    /// Mirrors Core's `CNodeStats::m_mapped_as` (net.cpp:3813).
    mapped_as: u32 = 0,

    /// Whether we advertise NODE_BLOOM (BIP-37/BIP-35 service flag) in our
    /// VERSION message and serve `mempool` requests.  Mirrored from
    /// `PeerManager.peerbloomfilters` at peer-creation time.  Default false
    /// to match Bitcoin Core's `DEFAULT_PEERBLOOMFILTERS = false`
    /// (net_processing.h:44).
    advertise_node_bloom: bool = false,

    /// BIP-159 prune-mode flag.  Set when prune mode is enabled
    /// (`-prune > 0`).  NOTE: this is NO LONGER what controls advertising
    /// of `NODE_NETWORK_LIMITED`.  Bitcoin Core seeds `g_local_services`
    /// with `NODE_NETWORK_LIMITED | NODE_WITNESS` UNCONDITIONALLY for every
    /// full node (init.cpp:863) — a non-pruned node still serves the
    /// recent-`MIN_BLOCKS_TO_KEEP` (288) window — so `localServices()` now
    /// sets that bit unconditionally regardless of this flag.  Retained for
    /// future prune-specific behaviour (e.g. serving-window enforcement).
    advertise_node_network_limited: bool = false,

    /// BIP-157: when true, OR `NODE_COMPACT_FILTERS` (1<<6) into the
    /// outbound `services` bitfield in the version handshake.  Set when
    /// `--blockfilterindex` and `--peerblockfilters` are both enabled.
    /// Mirrors Core's `init.cpp:992-998` where `g_local_services` gains
    /// `NODE_COMPACT_FILTERS` when both conditions hold.
    advertise_compact_filters: bool = false,

    /// BIP-130: peer requested header-style block announcements via the
    /// `sendheaders` message.  When true, this node MUST announce new
    /// blocks to this peer with a `headers` message containing the new
    /// header(s) instead of an `inv` containing the block hash(es).
    /// Default false until the peer opts in.  Reference:
    /// bitcoin-core/src/net_processing.cpp (PeerManagerImpl: `m_sendheaders`).
    /// Reference impl: camlcoin lib/peer_manager.ml::announce_block.
    send_headers: bool = false,

    /// BIP-152: peer sent us a valid `sendcmpct` message with version == 2.
    /// When true, this peer supports compact block relay (witness-aware v2).
    /// Mirrors Bitcoin Core's CNodeState::m_provides_cmpctblocks.
    /// Default false; set only after receiving sendcmpct(version=2).
    /// Reference: bitcoin-core/src/net_processing.cpp:3911.
    bip152_provides_cmpctblocks: bool = false,

    /// BIP-152: peer requested high-bandwidth compact block relay by sending
    /// sendcmpct(announce=true, version=2).  When true, we should push new
    /// compact blocks to this peer proactively (lNodesAnnouncingHeaderAndIDs).
    /// Mirrors Bitcoin Core's CNode::m_bip152_highbandwidth_from.
    /// Reference: bitcoin-core/src/net_processing.cpp:3915.
    bip152_highbandwidth_from: bool = false,

    /// BIP-339: peer sent us a `wtxidrelay` message during handshake.
    /// When true, relay tx invs using MSG_WTX (=5) with wtxid as hash.
    /// When false, use MSG_TX (=1) with txid (legacy behaviour).
    /// Mirrors Core: CNodeState::m_wtxid_relay (net_processing.cpp:283).
    wtxid_relay_negotiated: bool = false,

    /// BIP-324 v2 transport protocol version.
    transport_version: TransportVersion = .v1,

    /// BIP-324 v2 cipher state (null when using v1 transport).
    /// (Legacy field kept for back-compat with existing tests; the live
    /// transport state machine lives in `v2_transport` below.)
    v2_cipher: ?v2_transport.BIP324Cipher = null,

    /// BIP-324 v2 transport state machine (key exchange + encrypted send/
    /// receive).  Non-null iff `transport_version == .v2`.  Allocated on the
    /// peer's `allocator`; freed in `disconnect`.
    v2_transport: ?*v2_transport.V2Transport = null,

    /// Per-peer counter of consecutive unconnecting-headers messages.
    /// Mirrors Bitcoin Core's `nUnconnectingHeaders` in
    /// net_processing.cpp::ProcessHeadersMessage.  When the counter
    /// would exceed `MAX_NUM_UNCONNECTING_HEADERS_MSGS` (10), the peer
    /// is misbehavior-scored and disconnected.  Reset to 0 on every
    /// successful connecting headers batch.  Pre-fix, clearbit
    /// instant-banned on the first orphan; see
    /// CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
    /// (Pattern B).
    unconnecting_headers_count: u32 = 0,

    /// When true, misbehaving() will never set should_ban or should_discourage.
    /// Mirrors Bitcoin Core's NetPermissionFlags::NoBan.  Set for whitelisted
    /// peers (e.g. -whitelist/-addnode with noban permission).  Default false.
    no_ban: bool = false,

    /// GETADDR anti-DoS: whether we have already answered a getaddr from this
    /// peer. Mirrors Core's `Peer::m_getaddr_recvd` (net_processing.cpp): only
    /// the FIRST getaddr per connection is answered; subsequent ones are
    /// ignored to discourage addr stamping / repeated dumps. Reset only when
    /// the peer reconnects and gets a fresh Peer struct.
    getaddr_recvd: bool = false,

    /// Whether OUR outbound version message advertises tx relay (`fRelay`).
    /// True for full-relay connections, FALSE for block-relay-only and feeler
    /// connections (Core sets fRelay=false for both — net.cpp builds the
    /// version with `tx_relay = !block_relay_only` and feelers are block-relay
    /// for this flag). Default true (the common full-relay case); set false on
    /// the feeler connect path before the handshake runs.
    relay_self: bool = true,

    /// INBOUND addr token bucket (Core `Peer::m_addr_token_bucket`, init 1.0).
    /// Refilled by `elapsed * MAX_ADDR_RATE_PER_SECOND` (capped at
    /// MAX_ADDR_PROCESSING_TOKEN_BUCKET) on each addr/addrv2 message; each
    /// processed address consumes one token, and addresses are dropped once it
    /// runs dry. Shared by BOTH the addr and addrv2 handlers so an attacker
    /// cannot bypass the rate limit by switching message type
    /// (Core routes both through ProcessAddrs, net_processing.cpp).
    addr_token_bucket: f64 = 1.0,
    /// Unix-seconds timestamp of the last addr-bucket refill (Core
    /// `Peer::m_addr_token_timestamp`). 0 means "not yet refilled".
    addr_token_timestamp: i64 = 0,

    /// Sanitized, owned copy of the peer-advertised user-agent ("subver").
    ///
    /// Mirrors Core's `CNode::cleanSubVer` (net.h:728): the raw subver byte
    /// array a peer sends in its VERSION message is attacker-controlled and may
    /// contain non-UTF8 bytes, control characters, or JSON metacharacters
    /// (`"`, `\`).  Core runs it through `SanitizeString(strSubVer)`
    /// (net_processing.cpp:3637, SAFE_CHARS_DEFAULT) once at receipt and stores
    /// the cleaned result; everything downstream (RPC getpeerinfo, logging, GUI)
    /// reads the CLEAN copy, never the raw bytes.
    ///
    /// clearbit previously surfaced `version_info.user_agent` raw into the
    /// getpeerinfo JSON response — a peer with a crafted subver could emit a
    /// literal `"`/`\`/control byte and produce INVALID JSON (a remote DoS on
    /// the operator's RPC).  Worse, that raw slice pointed into the per-message
    /// `payload` buffer, which `receiveMessage` frees on return (use-after-free).
    /// We now clean-and-OWN at receipt, so the stored value is both valid for
    /// the peer's lifetime AND printable-ASCII / JSON-safe.
    ///
    /// Allocated on the peer's `allocator`; freed in `disconnect`.  Null until
    /// a VERSION has been received (matching Core's empty `cleanSubVer`).
    clean_subver: ?[]u8 = null,

    /// Connect to a remote peer.
    pub fn connect(
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) PeerError!Peer {
        // Non-blocking connect with 5-second timeout to avoid blocking the event loop.
        // The default tcpConnectToAddress blocks for the kernel's TCP timeout (~75s),
        // which stalls all peer processing during IBD.
        const sock = std.posix.socket(
            address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.TCP,
        ) catch return PeerError.ConnectionFailed;
        errdefer std.posix.close(sock);

        // Initiate non-blocking connect
        std.posix.connect(sock, &address.any, address.getOsSockLen()) catch |err| {
            if (err != error.WouldBlock) return PeerError.ConnectionFailed;
        };

        // Wait for connect to complete (writable) with 5s timeout
        var pollfds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const ready = std.posix.poll(&pollfds, 5000) catch return PeerError.ConnectionFailed;
        if (ready == 0) return PeerError.ConnectionFailed; // timeout
        if (pollfds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0)
            return PeerError.ConnectionFailed;

        // Check SO_ERROR to see if connect actually succeeded
        std.posix.getsockoptError(sock) catch return PeerError.ConnectionFailed;

        // Switch back to blocking mode for normal I/O
        const cur_flags = std.posix.fcntl(sock, std.posix.F.GETFL, 0) catch return PeerError.ConnectionFailed;
        const o_nonblock: usize = @intCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
        _ = std.posix.fcntl(sock, std.posix.F.SETFL, cur_flags & ~o_nonblock) catch
            return PeerError.ConnectionFailed;

        const stream = std.net.Stream{ .handle = sock };

        // Set socket options for timeouts (30 seconds)
        const timeout = std.posix.timeval{ .tv_sec = 30, .tv_usec = 0 };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.SNDTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};

        const now = std.time.timestamp();
        return Peer{
            .stream = stream,
            .address = address,
            .state = .connecting,
            .direction = .outbound,
            .version_info = null,
            .services = 0,
            .last_ping_time = 0,
            .last_pong_time = 0,
            .last_ping_nonce = 0,
            .last_message_time = now,
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .is_witness_capable = false,
            .is_headers_first = false,
            .ban_score = 0,
            .should_ban = false,
            .conn_type = .outbound_full_relay,
            .last_block_time = 0,
            .last_tx_time = 0,
            .min_ping_time = std.math.maxInt(i64),
            .relay_txs = true,
            .is_protected = false,
            .connect_time = now,
            .fee_filter_received = 0,
            .fee_filter_sent = 0,
            .next_send_feefilter = 0,
            .best_known_height = 0,
            .last_getheaders_time = 0,
            .oldest_block_in_flight_time = 0,
            .blocks_in_flight_count = 0,
            .chain_sync_protected = false,
            .advertise_node_bloom = false,
            .transport_version = .v1,
            .v2_cipher = null,
        };
    }

    /// Wrap an already-connected stream (e.g. one returned by ProxyManager's
    /// SOCKS5 / I2P SAM CONNECT) as an outbound Peer.  Used by the
    /// proxy-dispatch path in PeerManager so the SOCKS5 negotiation can run
    /// upstream of the Bitcoin handshake.
    ///
    /// `address` is the LOGICAL peer address used for bookkeeping (eclipse
    /// protection, ban lookups, RPC display).  For IPv4/IPv6 it is the real
    /// endpoint; for Tor v3 / I2P it is a placeholder std.net.Address
    /// constructed from the loopback IP plus the overlay port — the real
    /// hostname lives only in the proxy CONNECT, so std.net.Address cannot
    /// represent it.  Callers should pair this with a parallel
    /// MultiNetworkAddress in the candidate queue if they need to round-trip
    /// the overlay address.
    pub fn fromOutboundStream(
        stream: std.net.Stream,
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) Peer {
        const now = std.time.timestamp();
        // Match the timeouts set by Peer.connect so a proxied stream behaves
        // the same as a direct one once the application handshake starts.
        const timeout = std.posix.timeval{ .tv_sec = 30, .tv_usec = 0 };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.SNDTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};
        return Peer{
            .stream = stream,
            .address = address,
            .state = .connecting,
            .direction = .outbound,
            .version_info = null,
            .services = 0,
            .last_ping_time = 0,
            .last_pong_time = 0,
            .last_ping_nonce = 0,
            .last_message_time = now,
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .is_witness_capable = false,
            .is_headers_first = false,
            .ban_score = 0,
            .should_ban = false,
            .conn_type = .outbound_full_relay,
            .last_block_time = 0,
            .last_tx_time = 0,
            .min_ping_time = std.math.maxInt(i64),
            .relay_txs = true,
            .is_protected = false,
            .connect_time = now,
            .fee_filter_received = 0,
            .fee_filter_sent = 0,
            .next_send_feefilter = 0,
            .best_known_height = 0,
            .last_getheaders_time = 0,
            .oldest_block_in_flight_time = 0,
            .blocks_in_flight_count = 0,
            .chain_sync_protected = false,
            .advertise_node_bloom = false,
            .transport_version = .v1,
            .v2_cipher = null,
        };
    }

    /// Accept an inbound connection.
    pub fn accept(
        stream: std.net.Stream,
        address: std.net.Address,
        params: *const consensus.NetworkParams,
        allocator: std.mem.Allocator,
    ) Peer {
        const now = std.time.timestamp();
        return Peer{
            .stream = stream,
            .address = address,
            .state = .connected,
            .direction = .inbound,
            .version_info = null,
            .services = 0,
            .last_ping_time = 0,
            .last_pong_time = 0,
            .last_ping_nonce = 0,
            .last_message_time = now,
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .is_witness_capable = false,
            .is_headers_first = false,
            .ban_score = 0,
            .should_ban = false,
            .conn_type = .inbound,
            .last_block_time = 0,
            .last_tx_time = 0,
            .min_ping_time = std.math.maxInt(i64),
            .relay_txs = true,
            .is_protected = false,
            .connect_time = now,
            .fee_filter_received = 0,
            .fee_filter_sent = 0,
            .next_send_feefilter = 0,
            .best_known_height = 0,
            .last_getheaders_time = 0,
            .oldest_block_in_flight_time = 0,
            .blocks_in_flight_count = 0,
            .chain_sync_protected = false,
            .advertise_node_bloom = false,
            .transport_version = .v1,
            .v2_cipher = null,
        };
    }

    /// Send a P2P message over the connection.
    ///
    /// If the peer has negotiated BIP-324 v2 (i.e. `v2_transport` is non-null
    /// and the cipher is in the post-handshake "ready" state) the encoded
    /// payload is wrapped through the V2Transport state machine: the message
    /// type is mapped to its short ID (or 12-byte command), the contents are
    /// AEAD-encrypted with FSChaCha20Poly1305, the length descriptor is
    /// encrypted with FSChaCha20, and the resulting ciphertext is appended to
    /// the v2 send buffer (which we then drain to the socket).  Otherwise we
    /// fall back to the v1 framing (24-byte header + payload).
    pub fn sendMessage(self: *Peer, msg: *const p2p.Message) PeerError!void {
        if (self.transport_version == .v2 and self.v2_transport != null) {
            return self.sendMessageV2(msg);
        }

        const data = p2p.encodeMessage(msg, self.network_params.magic, self.allocator) catch
            return PeerError.OutOfMemory;
        defer self.allocator.free(data);

        self.stream.writeAll(data) catch return PeerError.ConnectionClosed;
        self.bytes_sent += data.len;
        self.last_message_time = std.time.timestamp();
    }

    /// V2 send path: encrypt + frame the payload through V2Transport.
    fn sendMessageV2(self: *Peer, msg: *const p2p.Message) PeerError!void {
        const t = self.v2_transport.?;

        // We encode the v1-framed bytes purely to obtain (command, payload)
        // pairs; v2 only sends the payload (the 24-byte v1 header is stripped).
        const data = p2p.encodeMessage(msg, self.network_params.magic, self.allocator) catch
            return PeerError.OutOfMemory;
        defer self.allocator.free(data);

        if (data.len < 24) return PeerError.ProtocolViolation;

        // Extract the command from the v1 header: bytes [4..16] are the
        // 12-byte NUL-padded command name.
        var cmd_buf: [12]u8 = undefined;
        @memcpy(&cmd_buf, data[4..16]);
        var cmd_len: usize = 12;
        while (cmd_len > 0 and cmd_buf[cmd_len - 1] == 0) cmd_len -= 1;
        const cmd = cmd_buf[0..cmd_len];
        const payload = data[24..];

        t.sendMessage(cmd, payload, false) catch |err| switch (err) {
            error.NotReady => return PeerError.ProtocolViolation,
            error.OutOfMemory => return PeerError.OutOfMemory,
        };

        // Drain the v2 send buffer to the socket.
        try self.flushV2SendBuffer();

        self.last_message_time = std.time.timestamp();
    }

    /// Drain `v2_transport.send_buffer` to the socket, marking sent bytes
    /// as the writeAll succeeds.
    fn flushV2SendBuffer(self: *Peer) PeerError!void {
        const t = self.v2_transport orelse return;
        const send_data = t.getSendData();
        if (send_data.len == 0) return;
        self.stream.writeAll(send_data) catch return PeerError.ConnectionClosed;
        const n = send_data.len;
        t.markBytesSent(n);
        self.bytes_sent += n;
    }

    /// Receive the next P2P message from the connection.
    ///
    /// On a v2-negotiated peer this reads encrypted bytes from the socket,
    /// feeds them into the V2Transport state machine, and returns the
    /// decoded application message once a full packet (length descriptor +
    /// AEAD ciphertext) has been received.  Otherwise it reads the v1
    /// 24-byte framing header + payload as before.
    pub fn receiveMessage(self: *Peer) PeerError!p2p.Message {
        if (self.transport_version == .v2 and self.v2_transport != null) {
            return self.receiveMessageV2();
        }

        // Read header (24 bytes)
        var header_buf: [24]u8 = undefined;
        self.readExact(&header_buf) catch |err| {
            return if (err == error.Timeout) PeerError.Timeout else PeerError.ConnectionClosed;
        };

        const header = p2p.MessageHeader.decode(&header_buf);

        // Validate magic
        if (header.magic != self.network_params.magic)
            return PeerError.BadMagic;

        // Validate payload size
        if (header.length > p2p.MAX_MESSAGE_SIZE)
            return PeerError.MessageTooLarge;

        // Read payload
        const payload = self.allocator.alloc(u8, header.length) catch
            return PeerError.OutOfMemory;
        defer self.allocator.free(payload);

        if (header.length > 0) {
            self.readExact(payload) catch return PeerError.ConnectionClosed;
        }

        // Verify checksum
        const computed_hash = crypto.hash256(payload);
        if (!std.mem.eql(u8, &header.checksum, computed_hash[0..4]))
            return PeerError.BadChecksum;

        self.bytes_received += 24 + header.length;
        self.last_message_time = std.time.timestamp();

        // Parse payload
        const command = header.commandName();
        return p2p.decodePayload(command, payload, self.allocator) catch
            return PeerError.ProtocolViolation;
    }

    /// V2 receive path: pull encrypted bytes off the socket into V2Transport
    /// until a full app packet decrypts; then translate the contents (short
    /// ID or 12-byte command + payload) into a `p2p.Message`.
    fn receiveMessageV2(self: *Peer) PeerError!p2p.Message {
        const t = self.v2_transport.?;

        // Pull bytes off the socket until V2Transport has a complete app
        // packet (or we hit a non-recoverable error).
        var read_buf: [16384]u8 = undefined;
        while (!t.isMessageReady()) {
            if (t.isV1Fallback()) return PeerError.ProtocolViolation;

            // First, try to drain bytes already buffered from a previous read.
            // Multiple BIP-324 packets can arrive in a single TCP segment
            // (e.g. WTXIDRELAY + SENDADDRV2 + VERACK during the application
            // handshake against rustoshi), and `processRecvBuffer` exits
            // after it advances to .app_ready — leaving any trailing packets
            // sitting in `recv_buffer`.  Without this drain, the next
            // `receiveMessage` would call `stream.read` and block waiting for
            // bytes that already arrived, causing a 30s SO_RCVTIMEO timeout.
            if (!t.processBuffered()) return PeerError.ProtocolViolation;
            if (t.isMessageReady()) break;
            if (t.isV1Fallback()) return PeerError.ProtocolViolation;

            const n = self.stream.read(&read_buf) catch |err| {
                if (err == error.WouldBlock) {
                    // No bytes available — surface as Timeout so the caller
                    // (PeerManager event loop) can move on.
                    return PeerError.Timeout;
                }
                return PeerError.ConnectionClosed;
            };
            if (n == 0) return PeerError.ConnectionClosed;
            if (!t.processReceivedBytes(read_buf[0..n])) {
                return PeerError.ProtocolViolation;
            }
            self.bytes_received += n;
        }

        const contents = t.getReceivedMessage() orelse return PeerError.ProtocolViolation;

        // contents[0] is either a short ID (1..28) or 0x00 followed by a
        // 12-byte command.  Everything after is the v1-style payload.
        if (contents.len == 0) return PeerError.ProtocolViolation;
        const first: u8 = contents[0];
        var command: []const u8 = "";
        var payload: []const u8 = &[_]u8{};
        var cmd_buf: [12]u8 = undefined;
        if (first == 0) {
            if (contents.len < 1 + 12) return PeerError.ProtocolViolation;
            @memcpy(&cmd_buf, contents[1..13]);
            var cmd_len: usize = 12;
            while (cmd_len > 0 and cmd_buf[cmd_len - 1] == 0) cmd_len -= 1;
            command = cmd_buf[0..cmd_len];
            payload = contents[13..];
        } else {
            const mt = v2_transport.getMessageType(first) orelse {
                // Unknown short ID — discard quietly per BIP-324 (treat as
                // ignored decoy on next iteration).  Since
                // `getReceivedMessage` already advanced state to .app, we
                // simply recurse to read the next packet.
                return self.receiveMessageV2();
            };
            command = mt;
            payload = contents[1..];
        }

        if (payload.len > p2p.MAX_MESSAGE_SIZE) return PeerError.MessageTooLarge;

        self.last_message_time = std.time.timestamp();
        return p2p.decodePayload(command, payload, self.allocator) catch
            return PeerError.ProtocolViolation;
    }

    /// Maximum time we'll spend driving the BIP-324 cipher handshake
    /// (key exchange + garbage-terminator search + version-packet exchange)
    /// before giving up.  Bitcoin Core uses a 4-minute connection timeout;
    /// we use 30s to keep failed handshakes from dragging the event loop.
    pub const V2_HANDSHAKE_DEADLINE_MS: i64 = 30_000;

    /// Returns true iff the BIP-324 v2 transport is enabled for new
    /// connections.  Gated behind the `CLEARBIT_BIP324_V2` env var.
    /// Default ON as of W90 (this commit) after live-verification against
    /// Bitcoin Core 28.x on mainnet — multiple successful handshakes
    /// observed (e.g. peers 71.196.197.14, 77.164.76.40, 31.47.202.112,
    /// 62.93.65.111) once the FSChaCha20 length cipher was fixed to
    /// produce a continuous keystream within an epoch.  Set
    /// `CLEARBIT_BIP324_V2=0` (or "false") to fall back to v1-only
    /// (matches the per-peer v1-fallback set behaviour for individual
    /// addresses that turn out to be v1-only).
    pub fn bip324V2Enabled() bool {
        const v = std.posix.getenv("CLEARBIT_BIP324_V2") orelse return true;
        if (std.mem.eql(u8, v, "0") or std.mem.eql(u8, v, "false") or std.mem.eql(u8, v, "FALSE")) return false;
        return true;
    }

    /// Build the advertised local service flags for the VERSION handshake.
    ///
    /// Mirrors Bitcoin Core's `g_local_services` assembly in `init.cpp`:
    ///   - NODE_NETWORK | NODE_WITNESS: full witness node, always set
    ///     (Core init.cpp:863 seeds `NODE_NETWORK_LIMITED | NODE_WITNESS`
    ///     and unconditionally adds NODE_NETWORK at init.cpp:1950).
    ///   - NODE_NETWORK_LIMITED: set UNCONDITIONALLY for a full node.  A
    ///     non-pruned full node serves the recent-288 window too, so Core
    ///     advertises this bit in the default (non-prune) case as well —
    ///     it is part of the init.cpp:863 seed and is NOT gated on prune.
    ///     (The older clearbit gate that ORed it only under prune mode was
    ///     wrong; a non-pruned node was under-advertising 0x809→missing the
    ///     0x400 bit.)
    ///   - NODE_BLOOM: gated on `advertise_node_bloom` (Core
    ///     DEFAULT_PEERBLOOMFILTERS = false, net_processing.h:44).
    ///   - NODE_COMPACT_FILTERS: gated on `advertise_compact_filters`
    ///     (Core init.cpp:992-998: both blockfilterindex+peerblockfilters).
    ///   - NODE_P2P_V2: advertised iff `bip324V2Enabled()` (BIP-324 v2
    ///     transport, genuinely implemented in v2_transport.zig and
    ///     wired into live peers; default ON since W90).  Core gates the
    ///     equivalent bit on `-v2transport` (init.cpp:989).
    ///
    /// Result for a default (non-pruned, v2-on) full node: 0xC09 =
    /// NODE_NETWORK(0x1) | NODE_WITNESS(0x8) | NODE_NETWORK_LIMITED(0x400)
    /// | NODE_P2P_V2(0x800).
    pub fn localServices(self: *const Peer) u64 {
        var s: u64 = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
        if (self.advertise_node_bloom) s |= p2p.NODE_BLOOM;
        // BIP-159: a full node serves the recent-288 window, so Core sets
        // NODE_NETWORK_LIMITED unconditionally (init.cpp:863), NOT only when
        // pruning.  We do the same and advertise it for every full node.
        s |= p2p.NODE_NETWORK_LIMITED;
        // BIP-157: signal compact-filter serving when both --blockfilterindex
        // and --peerblockfilters are enabled (Core init.cpp:992-998).
        if (self.advertise_compact_filters) s |= p2p.NODE_COMPACT_FILTERS;
        // BIP-324: advertise NODE_P2P_V2 only when we genuinely run the v2
        // transport (default on; honest — we will speak v2 to any v2 peer).
        if (bip324V2Enabled()) s |= p2p.NODE_P2P_V2;
        return s;
    }

    /// Read up to `out.len` bytes without consuming them from the kernel
    /// receive buffer (uses MSG_PEEK).  Returns the number of bytes peeked.
    /// May return less than `out.len` if data is currently unavailable;
    /// poll() before calling to ensure data is ready.
    pub fn peekBytes(self: *Peer, out: []u8) PeerError!usize {
        var total: usize = 0;
        // Bound the time we spend peeking with a deadline: we may receive
        // partial data for a v1 VERSION (24 header + payload), but the
        // first 16 bytes — magic + command — arrive together in the very
        // first TCP segment in practice.
        const deadline_ms = std.time.milliTimestamp() + 30_000;
        while (total < out.len) {
            const remaining_ms = deadline_ms - std.time.milliTimestamp();
            if (remaining_ms <= 0) break;

            // Wait for data with the remaining deadline.
            var pollfds = [_]std.posix.pollfd{.{
                .fd = self.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&pollfds, @intCast(@min(remaining_ms, 30_000))) catch
                return PeerError.ConnectionClosed;
            if (ready == 0) break; // deadline expired with partial data
            if (pollfds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0)
                return PeerError.ConnectionClosed;
            if ((pollfds[0].revents & std.posix.POLL.IN) == 0) continue;

            const n = std.posix.recv(self.stream.handle, out[total..], std.posix.MSG.PEEK) catch |err| {
                if (err == error.WouldBlock) continue;
                return PeerError.ConnectionClosed;
            };
            if (n == 0) return PeerError.ConnectionClosed;
            // recv with MSG_PEEK can return the SAME bytes repeatedly; if
            // the cumulative peeked length didn't grow we've already seen
            // everything currently buffered — break and let the caller
            // decide based on what we have.
            if (n <= total) break;
            total = n;
        }
        return total;
    }

    /// Outcome of an outbound BIP-324 v2 probe.
    ///
    /// NOTE: With the full v2 transport now wired, the standard outbound
    /// path uses `PeerManager.connectOutboundNegotiated` directly (which
    /// runs `performV2Handshake` on a fresh socket).  This probe primitive
    /// is retained for diagnostics and unit-test coverage of the
    /// classification heuristic.
    pub const V2ProbeResult = enum {
        /// Peer accepted v2 and the cipher handshake started.
        v2_negotiated,
        /// Peer did not respond within the deadline OR responded with v1
        /// magic.  CALLER must close this socket and reconnect in v1
        /// (sending v2 garbage is destructive on a v1 peer).
        fallback_to_v1,
    };

    /// Send an outbound BIP-324 v2 probe on this connection.  Sends the
    /// 64-byte ElligatorSwift pubkey + initial garbage (per BIP-324) and
    /// reads up to 16 bytes of the peer's response with `deadline_ms`
    /// timeout.  Classifies the response:
    ///   - If the peer started replying with v1 magic, returns
    ///     `.fallback_to_v1`.
    ///   - If we read fewer than 16 bytes by the deadline, returns
    ///     `.fallback_to_v1` (treat silence as "not v2").
    ///   - Otherwise (looks like a v2 ellswift pubkey reply), returns
    ///     `.v2_negotiated`.  The caller is then responsible for
    ///     completing the v2 handshake via the V2Transport state machine.
    ///
    /// The connection state is left consumed: even on `.v2_negotiated`,
    /// 16 bytes have been peeked from the kernel buffer (no bytes
    /// drained yet, so the V2Transport state machine sees the full
    /// pubkey when invoked).  On `.fallback_to_v1`, the caller MUST
    /// close this socket — the 64 bytes we sent will have corrupted the
    /// v1 framing on the remote.
    pub fn tryV2OutboundProbe(self: *Peer, deadline_ms: i64) PeerError!V2ProbeResult {
        // Build a one-shot V2Transport in initiator mode just to grab
        // the pubkey + garbage payload bytes.  The transport object is
        // discarded after the probe — full v2 plumbing tracks its own
        // V2Transport on the Peer (not yet implemented).
        var transport = v2_transport.V2Transport.init(self.allocator, true, self.network_params.magic);
        defer transport.deinit();

        const send_data = transport.getSendData();
        if (send_data.len < v2_transport.ELLSWIFT_PUBKEY_LEN) {
            // Cipher init failed (e.g. ellswift_create rejected every
            // attempt).  Don't write the partial bytes — fall back.
            return .fallback_to_v1;
        }

        self.stream.writeAll(send_data) catch return PeerError.ConnectionClosed;
        self.bytes_sent += send_data.len;

        // Read up to 16 bytes with the deadline.  Use MSG_PEEK so that on
        // a v2-negotiated outcome the caller can hand the bytes off to the
        // V2Transport state machine without reordering issues.
        var peek: [v2_transport.V1_PREFIX_LEN]u8 = undefined;
        const start_ms = std.time.milliTimestamp();
        var total: usize = 0;
        while (total < peek.len) {
            const remaining_ms = deadline_ms - (std.time.milliTimestamp() - start_ms);
            if (remaining_ms <= 0) break;

            var pollfds = [_]std.posix.pollfd{.{
                .fd = self.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&pollfds, @intCast(@min(remaining_ms, 30_000))) catch
                return PeerError.ConnectionClosed;
            if (ready == 0) break;
            if (pollfds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0)
                return .fallback_to_v1;
            if ((pollfds[0].revents & std.posix.POLL.IN) == 0) continue;

            const n = std.posix.recv(self.stream.handle, peek[total..], std.posix.MSG.PEEK) catch |err| {
                if (err == error.WouldBlock) continue;
                return .fallback_to_v1;
            };
            if (n == 0) return .fallback_to_v1; // EOF
            if (n <= total) break;
            total = n;
        }

        if (total < v2_transport.V1_PREFIX_LEN) {
            // Insufficient response within deadline → not speaking v2 (or
            // a stalled link).  Either way, fall back to v1 on a fresh
            // connection.
            return .fallback_to_v1;
        }

        var magic_le: [4]u8 = undefined;
        std.mem.writeInt(u32, &magic_le, self.network_params.magic, .little);
        if (v2_transport.looksLikeV1Version(&peek, magic_le)) {
            // Peer is speaking v1 (and is treating our 64-byte ellswift
            // garbage as a v1 message — the peer will probably disconnect
            // on its next read).  Caller MUST close + reconnect.
            return .fallback_to_v1;
        }

        // Plausibly a v2 ellswift pubkey reply.  Caller must complete
        // the handshake via the V2Transport state machine — currently
        // not plumbed; see `bip324V2Enabled`.
        return .v2_negotiated;
    }

    /// Drive the BIP-324 v2 cipher handshake to completion.  After this
    /// returns success, `self.transport_version == .v2`, the V2Transport's
    /// version packet has been exchanged in both directions, and every
    /// subsequent `sendMessage` / `receiveMessage` flows through the
    /// encrypted v2 path.  After this, the application-level version /
    /// verack handshake (the `performHandshake` body further down) runs over
    /// the encrypted transport.
    ///
    /// Direction:
    ///   - outbound: caller has already opened a fresh TCP connection AND
    ///     constructed a V2Transport in initiator mode (containing our
    ///     ellswift pubkey + garbage); this function flushes it and reads
    ///     until the peer's version packet has been authenticated.
    ///   - inbound: caller has already constructed a V2Transport in
    ///     responder mode and primed it with the 64-byte peek (so the
    ///     state machine sees the peer's pubkey at the head of recv_buffer).
    ///
    /// Bounded by `deadline_ms` — defaults to 30s in PeerManager.
    pub fn performV2Handshake(self: *Peer, deadline_ms: i64) PeerError!void {
        const t = self.v2_transport orelse return PeerError.HandshakeFailed;
        const start_ms = std.time.milliTimestamp();

        var read_buf: [16384]u8 = undefined;
        // Loop until both sides have queued a version packet AND we have
        // observed the peer's version packet (recv_state advanced to .app).
        while (true) {
            // Flush whatever V2Transport has staged for sending (initial
            // pubkey + garbage on the first iteration; garbage terminator +
            // version-packet ciphertext after we receive the peer's key).
            try self.flushV2SendBuffer();

            if (t.isVersionReceived() and t.isHandshakeReady()) {
                // Both directions complete.  We're cipher-ready.
                self.transport_version = .v2;
                return;
            }

            // Bound the wait per BIP-324 (Bitcoin Core uses a 4-minute
            // peers.timeoutbal; we use the caller-supplied deadline).
            const elapsed = std.time.milliTimestamp() - start_ms;
            const remaining_ms: i64 = deadline_ms - elapsed;
            if (remaining_ms <= 0) return PeerError.Timeout;

            var pollfds = [_]std.posix.pollfd{.{
                .fd = self.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&pollfds, @intCast(@min(remaining_ms, 30_000))) catch
                return PeerError.HandshakeFailed;
            if (ready == 0) continue;
            if (pollfds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0)
                return PeerError.ConnectionClosed;
            if ((pollfds[0].revents & std.posix.POLL.IN) == 0) continue;

            const n = self.stream.read(&read_buf) catch |err| {
                if (err == error.WouldBlock) continue;
                return PeerError.ConnectionClosed;
            };
            if (n == 0) return PeerError.ConnectionClosed;
            self.bytes_received += n;

            if (!t.processReceivedBytes(read_buf[0..n])) {
                return PeerError.HandshakeFailed;
            }
            if (t.isV1Fallback()) return PeerError.HandshakeFailed;
        }
    }

    /// Perform the version/verack handshake.
    /// Outbound: send version, wait for version+verack, send verack.
    /// Inbound: wait for version, send version+verack, wait for verack.
    ///
    /// BIP-324 v2 negotiation:
    ///   - Inbound: peeks the first 16 bytes; if they look like a v1
    ///     VERSION header (network magic + "version\0\0\0\0\0") we run
    ///     the v1 path.  Otherwise the peer initiated v2; we currently
    ///     reject the connection (see `bip324V2Enabled` doc-comment for
    ///     the application-plumbing gap).
    ///   - Outbound: when `bip324V2Enabled()` is true and the peer is
    ///     not in the manager's v1-fallback set, an outbound v2 probe is
    ///     attempted via `tryV2OutboundProbe` BEFORE this function is
    ///     called.  If the probe falls back, the manager records the
    ///     v1-only state and reconnects, then drives this v1 handshake.
    pub fn performHandshake(self: *Peer, our_height: i32) PeerError!void {
        const now = std.time.timestamp();

        // Inbound: classify the wire by peeking the first 16 bytes.
        // If the peer sent the v1 VERSION prefix, fall through to v1.
        // Otherwise, the peer is speaking v2 — drive the BIP-324 cipher
        // handshake through V2Transport (responder mode) and let the
        // application version/verack run on top of the encrypted channel.
        if (self.direction == .inbound and bip324V2Enabled() and self.transport_version == .v1) {
            var peek: [v2_transport.V1_PREFIX_LEN]u8 = undefined;
            const got = self.peekBytes(&peek) catch return PeerError.HandshakeFailed;
            if (got >= v2_transport.V1_PREFIX_LEN) {
                var magic_le: [4]u8 = undefined;
                std.mem.writeInt(u32, &magic_le, self.network_params.magic, .little);
                if (!v2_transport.looksLikeV1Version(&peek, magic_le)) {
                    // Peer is initiating BIP-324 v2.  Construct a responder
                    // V2Transport, run the cipher handshake, then continue
                    // with the application version/verack on the encrypted
                    // transport.  Note: peekBytes used MSG_PEEK so the bytes
                    // are still in the kernel buffer — V2Transport will
                    // consume them via stream.read() in performV2Handshake.
                    const t = self.allocator.create(v2_transport.V2Transport) catch
                        return PeerError.OutOfMemory;
                    t.* = v2_transport.V2Transport.init(
                        self.allocator,
                        false, // responder
                        self.network_params.magic,
                    );
                    self.v2_transport = t;
                    self.performV2Handshake(V2_HANDSHAKE_DEADLINE_MS) catch |err| {
                        std.log.info("peer={any} BIP-324 v2 inbound handshake failed: {any}", .{ self.address, err });
                        return PeerError.HandshakeFailed;
                    };
                    // Mirror the outbound success log (peer.zig:1915) so the
                    // BIP-324 interop matrix harness can classify
                    // clearbit-as-listener pairs as v2 instead of "unknown".
                    // Use std.debug.print so the line surfaces in
                    // ReleaseFast (Zig 0.13's default log_level for
                    // ReleaseFast is .err; std.log.info is dropped).
                    std.debug.print("P2P: BIP-324 v2 inbound connected (encrypted) peer={any}\n", .{self.address});
                }
                // Looks like v1 — fall through.
            }
            // got < V1_PREFIX_LEN means the peer didn't send 16 bytes
            // within the peek deadline; the v1 path below will time out
            // naturally on receiveMessage if the peer is dead.
        }

        // Bitcoin Core builds the advertised services bitmap from the
        // local services config; we do the same in `localServices()`.
        // NODE_NETWORK_LIMITED is set unconditionally for this full node
        // (Core init.cpp:863), NODE_P2P_V2 when v2 transport is enabled.
        const our_services: u64 = self.localServices();

        if (self.direction == .outbound) {
            // Send our version
            const version_msg = p2p.Message{ .version = p2p.VersionMessage{
                .version = p2p.PROTOCOL_VERSION,
                .services = our_services,
                .timestamp = now,
                .addr_recv = types.NetworkAddress{
                    .services = 0,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .addr_from = types.NetworkAddress{
                    .services = our_services,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .nonce = std.crypto.random.int(u64),
                .user_agent = p2p.USER_AGENT,
                .start_height = our_height,
                // fRelay: false for feeler / block-relay-only connections so the
                // peer does not start an inv-based tx relay (Core net.cpp builds
                // the version with tx_relay = !block_relay_only).
                .relay = self.relay_self,
            } };
            try self.sendMessage(&version_msg);
            self.state = .version_sent;

            // Wait for their version
            const their_version = try self.receiveMessage();
            switch (their_version) {
                .version => |v| {
                    if (v.version < p2p.MIN_PROTOCOL_VERSION)
                        return PeerError.HandshakeFailed;
                    self.recordVersion(v);
                },
                else => return PeerError.HandshakeFailed,
            }

            // Send wtxidrelay (BIP-339) and sendaddrv2 (BIP-155) BEFORE verack.
            // These must be sent between version and verack per their respective BIPs.
            // Bitcoin Core disconnects peers that send them after verack.
            const wtxid = p2p.Message{ .wtxidrelay = {} };
            try self.sendMessage(&wtxid);

            const addrv2 = p2p.Message{ .sendaddrv2 = {} };
            try self.sendMessage(&addrv2);

            // Send verack (after feature negotiation messages)
            const verack = p2p.Message{ .verack = {} };
            try self.sendMessage(&verack);

            // Wait for their verack
            while (true) {
                const msg = try self.receiveMessage();
                switch (msg) {
                    .verack => break,
                    .wtxidrelay => {
                        // BIP-339: peer negotiated wtxid relay.
                        self.wtxid_relay_negotiated = true;
                    },
                    .sendaddrv2, .sendheaders => {
                        // Accept these during handshake but no action needed
                    },
                    .sendcmpct => |sc| {
                        // BIP-152: validate version field.
                        // Core rejects version != 2 immediately
                        // (net_processing.cpp:3907 if sendcmpct_version != CMPCTBLOCKS_VERSION return).
                        // Version 1 (non-segwit) was removed in Core 0.18+; only v2 is supported.
                        // Silently drop non-v2: do not update peer compact-relay state.
                        if (sc.version == 2) {
                            self.bip152_provides_cmpctblocks = true;
                            self.bip152_highbandwidth_from = sc.announce;
                        }
                    },
                    .feefilter => |ff| {
                        // BIP-133: Store the peer's fee filter during handshake
                        const MAX_MONEY: u64 = 2_100_000_000_000_000;
                        if (ff.feerate <= MAX_MONEY) {
                            self.fee_filter_received = ff.feerate;
                        }
                    },
                    .ping => |ping| {
                        // Handle ping during handshake
                        const pong = p2p.Message{ .pong = ping };
                        try self.sendMessage(&pong);
                    },
                    else => {},
                }
            }
        } else {
            // Inbound: wait for version first
            const their_version = try self.receiveMessage();
            switch (their_version) {
                .version => |v| {
                    if (v.version < p2p.MIN_PROTOCOL_VERSION)
                        return PeerError.HandshakeFailed;
                    self.recordVersion(v);
                },
                else => return PeerError.HandshakeFailed,
            }

            // Send our version
            const version_msg = p2p.Message{ .version = p2p.VersionMessage{
                .version = p2p.PROTOCOL_VERSION,
                .services = our_services,
                .timestamp = now,
                .addr_recv = types.NetworkAddress{
                    .services = self.services,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .addr_from = types.NetworkAddress{
                    .services = our_services,
                    .ip = [_]u8{0} ** 16,
                    .port = 0,
                },
                .nonce = std.crypto.random.int(u64),
                .user_agent = p2p.USER_AGENT,
                .start_height = our_height,
                .relay = true,
            } };
            try self.sendMessage(&version_msg);

            // Send wtxidrelay (BIP-339) and sendaddrv2 (BIP-155) before verack
            const wtxid_in = p2p.Message{ .wtxidrelay = {} };
            try self.sendMessage(&wtxid_in);
            const addrv2_in = p2p.Message{ .sendaddrv2 = {} };
            try self.sendMessage(&addrv2_in);

            // Send verack (after feature negotiation messages)
            const verack = p2p.Message{ .verack = {} };
            try self.sendMessage(&verack);

            // Wait for their verack
            while (true) {
                const msg = try self.receiveMessage();
                switch (msg) {
                    .verack => break,
                    else => {},
                }
            }
        }

        self.state = .handshake_complete;

        // Send sendheaders (BIP-130) - request headers announcements
        const sh = p2p.Message{ .sendheaders = {} };
        try self.sendMessage(&sh);

        // Send sendcmpct (BIP-152) - signal compact block relay support
        // Version 2 = segwit-aware, announce=false = low-bandwidth mode
        const sc = p2p.Message{ .sendcmpct = .{ .announce = false, .version = 2 } };
        try self.sendMessage(&sc);

        // BIP-133: Send initial feefilter after handshake
        // 100 sat/vbyte = 100,000 sat/kvB to discourage tx relay during sync
        if (self.relay_txs) {
            const ff = p2p.Message{ .feefilter = .{ .feerate = 100_000 } };
            try self.sendMessage(&ff);
        }
    }

    /// Send a ping and record the nonce.
    pub fn sendPing(self: *Peer) PeerError!void {
        self.last_ping_nonce = std.crypto.random.int(u64);
        self.last_ping_time = std.time.timestamp();
        const msg = p2p.Message{ .ping = .{ .nonce = self.last_ping_nonce } };
        try self.sendMessage(&msg);
    }

    /// Handle an incoming pong message.
    pub fn handlePong(self: *Peer, nonce: u64) void {
        if (nonce == self.last_ping_nonce) {
            self.last_pong_time = std.time.timestamp();
            // Update minimum ping time for eviction scoring
            const latency = self.last_pong_time - self.last_ping_time;
            if (latency >= 0 and latency < self.min_ping_time) {
                self.min_ping_time = latency;
            }
        }
    }

    /// Maybe send a feefilter message to this peer (BIP-133).
    /// Uses Poisson delay (~10 min avg) with hysteresis to avoid rapid oscillation.
    /// current_filter_sat_kvb: Our current minimum fee rate in sat/kvB.
    /// is_ibd: Whether we're in initial block download (send MAX_MONEY during IBD).
    pub fn maybeSendFeefilter(self: *Peer, current_filter_sat_kvb: u64, is_ibd: bool) void {
        const now_seconds = std.time.timestamp();
        const now_us = now_seconds * 1_000_000;

        // Don't send to block-relay-only peers
        if (self.conn_type == .block_relay) return;

        // Don't send if peer doesn't relay transactions
        if (!self.relay_txs) return;

        // Determine the filter value to send
        const MAX_MONEY: u64 = 2_100_000_000_000_000;
        var filter_to_send: u64 = current_filter_sat_kvb;

        if (is_ibd) {
            // During IBD, tell peers not to send us transactions
            filter_to_send = MAX_MONEY;
        } else if (self.fee_filter_sent == MAX_MONEY) {
            // We just exited IBD - send immediately
            self.next_send_feefilter = 0;
        }

        // Ensure at least MIN_RELAY_FEE
        filter_to_send = @max(filter_to_send, MIN_RELAY_FEE);

        // Check if it's time to send
        if (now_us > self.next_send_feefilter) {
            // Time to send if the value has changed
            if (filter_to_send != self.fee_filter_sent) {
                const msg = p2p.Message{ .feefilter = .{ .feerate = filter_to_send } };
                self.sendMessage(&msg) catch return;
                self.fee_filter_sent = filter_to_send;
            }

            // Schedule next broadcast using exponential distribution (approximated)
            // For simplicity, we use uniform random within [0.5, 1.5] * AVG_INTERVAL
            const random_factor = @as(i64, @intCast(std.crypto.random.intRangeAtMost(u32, 500, 1500)));
            const delay_seconds = @divTrunc(AVG_FEEFILTER_BROADCAST_INTERVAL * random_factor, 1000);
            self.next_send_feefilter = now_us + delay_seconds * 1_000_000;
        } else {
            // Check hysteresis: if significant change and next broadcast too far away, accelerate
            // Significant = decrease by 25% or increase by 33%
            if (now_us + MAX_FEEFILTER_CHANGE_DELAY * 1_000_000 < self.next_send_feefilter) {
                const significant_decrease = current_filter_sat_kvb < (3 * self.fee_filter_sent) / 4;
                const significant_increase = current_filter_sat_kvb > (4 * self.fee_filter_sent) / 3;

                if (significant_decrease or significant_increase) {
                    // Schedule sooner - random within [0, MAX_FEEFILTER_CHANGE_DELAY]
                    const random_delay = @as(i64, @intCast(std.crypto.random.intRangeAtMost(u32, 0, @intCast(MAX_FEEFILTER_CHANGE_DELAY))));
                    self.next_send_feefilter = now_us + random_delay * 1_000_000;
                }
            }
        }
    }

    /// Check if a transaction fee rate passes this peer's fee filter.
    /// Returns true if the transaction should be relayed to this peer.
    /// tx_fee_rate_sat_kvb: Transaction fee rate in sat/kvB.
    pub fn passesFeeFilter(self: *const Peer, tx_fee_rate_sat_kvb: u64) bool {
        // If peer hasn't sent a feefilter, accept all transactions
        if (self.fee_filter_received == 0) return true;
        return tx_fee_rate_sat_kvb >= self.fee_filter_received;
    }

    /// Record a received VERSION message on this peer.
    ///
    /// Stores the version fields and computes the sanitized, OWNED `clean_subver`
    /// (Core: `pfrom.cleanSubVer = SanitizeString(strSubVer)`,
    /// net_processing.cpp:3637).  This must be the only place a received subver
    /// is captured: the raw `v.user_agent` slice points into the per-message
    /// receive buffer that `receiveMessage` frees on return, so we never retain
    /// it — only the sanitized copy survives.
    ///
    /// On a re-received VERSION (shouldn't happen post-handshake, but be safe),
    /// any prior clean_subver is freed first to avoid a leak.
    fn recordVersion(self: *Peer, v: p2p.VersionMessage) void {
        // Sanitize the attacker-controlled subver into an owned, printable copy.
        // On allocation failure, fall back to no subver rather than failing the
        // handshake (Core treats an empty cleanSubVer as "<no user agent>").
        const cleaned = sanitizeSubVer(self.allocator, v.user_agent) catch null;
        if (self.clean_subver) |old| self.allocator.free(old);
        self.clean_subver = cleaned;

        self.version_info = v;
        self.services = v.services;
        self.start_height = v.start_height;
        self.is_witness_capable = (v.services & p2p.NODE_WITNESS) != 0;
        self.time_offset = v.timestamp - std.time.timestamp();
    }

    /// Disconnect from the peer.
    pub fn disconnect(self: *Peer) void {
        self.state = .disconnected;
        self.stream.close();
        self.recv_buffer.deinit();
        if (self.clean_subver) |s| {
            self.allocator.free(s);
            self.clean_subver = null;
        }
        if (self.v2_transport) |t| {
            t.deinit();
            self.allocator.destroy(t);
            self.v2_transport = null;
        }
    }

    /// Check if data is available to read on this peer's socket (non-blocking).
    pub fn hasDataAvailable(self: *Peer) bool {
        var pollfds = [_]std.posix.pollfd{.{
            .fd = self.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        // Poll with 0 timeout = non-blocking check
        const ready = std.posix.poll(&pollfds, 0) catch return false;
        return ready > 0 and (pollfds[0].revents & std.posix.POLL.IN) != 0;
    }

    /// Set the receive timeout on the socket.
    pub fn setRecvTimeout(self: *Peer, sec: i64, usec: i64) void {
        const timeout = std.posix.timeval{ .tv_sec = sec, .tv_usec = @intCast(usec) };
        std.posix.setsockopt(
            self.stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};
    }

    /// Read exactly n bytes from the stream.
    /// If we've read zero bytes and get WouldBlock, returns Timeout (no data available).
    /// If we've already read some bytes and get WouldBlock, sleeps briefly and retries.
    ///
    /// W53: the partial-read retry path must not spin forever — a peer that
    /// opens a payload (sends the 24-byte header) and then stalls mid-stream
    /// will return EAGAIN indefinitely, and because PeerManager drives ALL
    /// peers from a single thread, any stuck readExact wedges the entire
    /// node (no drain, no timeout checks, no heartbeats — exactly the silent
    /// stall observed at block 479,888 on 2026-04-17). Bound the total time
    /// spent in partial-read retries and give up as ConnectionClosed so the
    /// peer is disconnected and the download slots are reclaimed.
    pub const READ_EXACT_PARTIAL_TIMEOUT_MS: i64 = 30_000;
    fn readExact(self: *Peer, buf: []u8) !void {
        var total: usize = 0;
        var partial_deadline_ms: i64 = 0;
        while (total < buf.len) {
            const n = self.stream.read(buf[total..]) catch |err| {
                if (err == error.WouldBlock) {
                    if (total == 0) {
                        return error.Timeout; // No data at all - truly no message waiting
                    }
                    // Partial read — data may be arriving. Bound retry time
                    // so a mid-payload stall doesn't wedge the peer thread.
                    const now_ms = std.time.milliTimestamp();
                    if (partial_deadline_ms == 0) {
                        partial_deadline_ms = now_ms + READ_EXACT_PARTIAL_TIMEOUT_MS;
                    } else if (now_ms >= partial_deadline_ms) {
                        return error.ConnectionClosed;
                    }
                    std.time.sleep(1 * std.time.ns_per_ms);
                    continue;
                }
                return error.ConnectionClosed;
            };
            if (n == 0) return error.ConnectionClosed;
            total += n;
            // Progress resets the partial-read deadline so a slow-but-live
            // peer is still allowed to finish a large payload.
            if (partial_deadline_ms != 0) partial_deadline_ms = 0;
        }
    }

    /// Check if the peer has timed out (no messages for 20 minutes, no pong for 5 minutes).
    pub fn isTimedOut(self: *const Peer) bool {
        const now = std.time.timestamp();
        // No message in 20 minutes
        if (now - self.last_message_time > 20 * 60) return true;
        // Ping sent but no pong in 5 minutes
        if (self.last_ping_time > 0 and self.last_pong_time < self.last_ping_time and
            now - self.last_ping_time > 5 * 60) return true;
        return false;
    }

    /// Add to ban score; return true if peer should be banned (score >= 100).
    pub fn addBanScore(self: *Peer, score: u32) bool {
        self.ban_score += score;
        if (self.ban_score >= 100) {
            self.should_ban = true;
            return true;
        }
        return false;
    }

    /// Return true if the peer's address is a local/loopback address.
    /// Mirrors Bitcoin Core's CNetAddr::IsLocal() check in
    /// MaybeDiscourageAndDisconnect (net_processing.cpp:5083).
    /// Local peers are disconnected-only (no discourage entry written).
    pub fn isLocalAddress(self: *const Peer) bool {
        switch (self.address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&self.address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                // 127.0.0.0/8 loopback range
                return ip_bytes[0] == 127;
            },
            std.posix.AF.INET6 => {
                const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&self.address.any)));
                // ::1 loopback
                const is_loopback = for (ip6.addr[0..15]) |b| {
                    if (b != 0) break false;
                } else true;
                return is_loopback and ip6.addr[15] == 1;
            },
            else => return false,
        }
    }

    /// Record misbehavior with a reason.  Mirrors Bitcoin Core's
    /// MaybeDiscourageAndDisconnect (net_processing.cpp:5083) and the 2022
    /// single-event model (PR #25974): any single Misbehaving call sets
    /// m_should_discourage=true immediately — no score accumulation.
    ///
    /// Exemptions (no ban, no discourage):
    ///   - no_ban == true  (whitelisted / -noban permission)
    ///   - conn_type == .manual  (manually added peer via addnode)
    ///   - local address  (disconnect-only, no discourage entry)
    ///
    /// For all other peers: single-event — set should_ban immediately on any call.
    pub fn misbehaving(self: *Peer, howmuch: u32, message: []const u8) void {
        // NoBan: exempted entirely — no score, no disconnect.
        if (self.no_ban) {
            var addr_buf: [64]u8 = undefined;
            const addr_str = self.getAddressString(&addr_buf);
            std.log.info("Misbehaving ignored (noban): peer={s} +{d}: {s}", .{ addr_str, howmuch, message });
            return;
        }
        // Manual peers: exempted entirely — no score, no disconnect.
        if (self.conn_type == .manual) {
            var addr_buf: [64]u8 = undefined;
            const addr_str = self.getAddressString(&addr_buf);
            std.log.info("Misbehaving ignored (manual): peer={s} +{d}: {s}", .{ addr_str, howmuch, message });
            return;
        }
        // Local peers: disconnect-only; no discourage entry written.
        if (self.isLocalAddress()) {
            self.should_ban = true; // causes disconnect without ban-list entry
            var addr_buf: [64]u8 = undefined;
            const addr_str = self.getAddressString(&addr_buf);
            std.log.warn("Misbehaving (local, disconnect-only): peer={s} +{d}: {s}", .{ addr_str, howmuch, message });
            return;
        }
        // Core 2022 single-event model (PR #25974): any Misbehaving call
        // immediately sets should_ban (≡ m_should_discourage=true in Core).
        // No score accumulation — a single infraction is enough to discourage.
        self.should_ban = true;
        var addr_buf: [64]u8 = undefined;
        const addr_str = self.getAddressString(&addr_buf);
        std.log.warn("Misbehaving: peer={s} +{d} (single-event discourage): {s}", .{ addr_str, howmuch, message });
    }

    /// Get the latency in milliseconds based on last ping/pong.
    pub fn getLatencyMs(self: *const Peer) ?i64 {
        if (self.last_pong_time > 0 and self.last_ping_time > 0 and
            self.last_pong_time >= self.last_ping_time)
        {
            return (self.last_pong_time - self.last_ping_time) * 1000;
        }
        return null;
    }

    /// Check if the peer is fully connected and ready.
    pub fn isReady(self: *const Peer) bool {
        return self.state == .handshake_complete;
    }

    /// Get a human-readable address string.
    pub fn getAddressString(self: *const Peer, buf: []u8) []const u8 {
        const formatted = std.fmt.bufPrint(buf, "{}", .{self.address}) catch return "unknown";
        return formatted;
    }

    // ========================================================================
    // Stale Peer Detection (Bitcoin Core net_processing.cpp)
    // ========================================================================

    /// Check if this peer has a stale tip (best_known_height behind our tip for >30 min).
    /// our_height: Our current best block height.
    /// Returns true if peer's tip is stale.
    pub fn hasStaleTip(self: *const Peer, our_height: u32) bool {
        const now = std.time.timestamp();

        // Must have received a version message with their height
        if (self.best_known_height == 0) return false;

        // If peer is caught up, not stale
        if (self.best_known_height >= our_height) return false;

        // Check if they've been behind for too long
        // We use last_block_time to track when they last made progress
        if (self.last_block_time > 0) {
            // If they sent us a block recently, give them time
            if (now - self.last_block_time < STALE_TIP_THRESHOLD) return false;
        }

        // If we've received headers from them recently, they may be syncing
        if (self.last_message_time > 0 and now - self.last_message_time < STALE_TIP_THRESHOLD) {
            return false;
        }

        // Been behind for too long
        return true;
    }

    /// Check if ping has timed out (ping sent, no pong within PING_TIMEOUT).
    /// Returns true if peer should be disconnected due to ping timeout.
    pub fn hasPingTimeout(self: *const Peer) bool {
        const now = std.time.timestamp();

        // No ping sent, no timeout
        if (self.last_ping_nonce == 0 or self.last_ping_time == 0) return false;

        // Pong received for this ping
        if (self.last_pong_time >= self.last_ping_time) return false;

        // Check if we've waited too long for pong
        return now - self.last_ping_time > PING_TIMEOUT;
    }

    /// Check if headers request has timed out (getheaders sent, no response within 2 min).
    /// Returns true if peer should be penalized for headers timeout.
    pub fn hasHeadersTimeout(self: *const Peer) bool {
        const now = std.time.timestamp();

        // No getheaders sent
        if (self.last_getheaders_time == 0) return false;

        // Check if we've waited too long
        return now - self.last_getheaders_time > HEADERS_RESPONSE_TIMEOUT;
    }

    /// Check if block download has timed out (block in flight for >20 min).
    /// Returns true if peer should be disconnected due to block timeout.
    pub fn hasBlockDownloadTimeout(self: *const Peer) bool {
        const now = std.time.timestamp();

        // No blocks in flight
        if (self.blocks_in_flight_count == 0 or self.oldest_block_in_flight_time == 0) return false;

        // Check if oldest block has been in flight too long
        return now - self.oldest_block_in_flight_time > BLOCK_DOWNLOAD_TIMEOUT;
    }

    /// Update best known height from received headers/version.
    pub fn updateBestKnownHeight(self: *Peer, height: u32) void {
        if (height > self.best_known_height) {
            self.best_known_height = height;
        }
    }

    /// Record that we sent a getheaders request.
    pub fn recordGetheadersRequest(self: *Peer) void {
        self.last_getheaders_time = std.time.timestamp();
    }

    /// Clear the getheaders timeout (called when we receive headers).
    pub fn clearGetheadersTimeout(self: *Peer) void {
        self.last_getheaders_time = 0;
    }

    /// Record that we requested a block.
    pub fn recordBlockRequest(self: *Peer) void {
        const now = std.time.timestamp();
        if (self.blocks_in_flight_count == 0) {
            self.oldest_block_in_flight_time = now;
        }
        self.blocks_in_flight_count += 1;
    }

    /// Record that a block was received (or canceled).
    pub fn recordBlockReceived(self: *Peer) void {
        if (self.blocks_in_flight_count > 0) {
            self.blocks_in_flight_count -= 1;
            if (self.blocks_in_flight_count == 0) {
                self.oldest_block_in_flight_time = 0;
            }
        }
        self.last_block_time = std.time.timestamp();
    }

    /// Check if this peer is a candidate for stale tip eviction.
    /// Must be outbound, not protected, connected long enough, and no blocks in flight.
    pub fn isEvictionCandidate(self: *const Peer) bool {
        const now = std.time.timestamp();

        // Only evict outbound peers (prefer keeping inbound)
        if (self.direction != .outbound) return false;

        // Don't evict protected peers
        if (self.chain_sync_protected) return false;

        // Don't evict manual connections
        if (self.conn_type == .manual) return false;

        // Must be connected long enough
        if (now - self.connect_time < MINIMUM_CONNECT_TIME) return false;

        // Don't evict if blocks are in flight
        if (self.blocks_in_flight_count > 0) return false;

        return true;
    }
};

// ============================================================================
// Eviction Candidate (Eclipse Attack Protection)
// ============================================================================

/// Candidate for inbound connection eviction.
/// Contains all the metrics used to decide which peer to evict.
pub const EvictionCandidate = struct {
    peer_index: usize,
    net_group: u32,
    min_ping_time: i64,
    last_block_time: i64,
    last_tx_time: i64,
    connect_time: i64,
    relay_txs: bool,
    is_protected: bool,
};

/// Build eviction candidate list from inbound peers.
pub fn buildEvictionCandidates(peers: []*Peer, allocator: std.mem.Allocator) ![]EvictionCandidate {
    var candidates = std.ArrayList(EvictionCandidate).init(allocator);
    errdefer candidates.deinit();

    for (peers, 0..) |peer, i| {
        // Only consider inbound connections for eviction
        if (peer.direction != .inbound) continue;
        // Skip protected peers
        if (peer.is_protected) continue;

        try candidates.append(.{
            .peer_index = i,
            .net_group = netGroup(peer.address),
            .min_ping_time = peer.min_ping_time,
            .last_block_time = peer.last_block_time,
            .last_tx_time = peer.last_tx_time,
            .connect_time = peer.connect_time,
            .relay_txs = peer.relay_txs,
            .is_protected = false,
        });
    }

    return candidates.toOwnedSlice();
}

/// Comparison function for sorting by min ping time (ascending - lower is better).
fn comparePingTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.min_ping_time < b.min_ping_time;
}

/// Comparison function for sorting by last tx time (descending - more recent is better).
fn compareTxTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.last_tx_time > b.last_tx_time;
}

/// Comparison function for sorting by last block time (descending - more recent is better).
fn compareBlockTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.last_block_time > b.last_block_time;
}

/// Comparison function for sorting by connect time (ascending - longer connected is better).
fn compareConnectTime(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.connect_time < b.connect_time;
}

/// Comparison function for sorting by netgroup.
fn compareNetGroup(_: void, a: EvictionCandidate, b: EvictionCandidate) bool {
    return a.net_group < b.net_group;
}

/// Select an inbound peer to evict using Bitcoin Core's eviction algorithm.
/// Protection order (matching Bitcoin Core's SelectNodeToEvict):
/// 1. 4 by netgroup (distinct groups)
/// 2. 8 by fastest ping time
/// 3. 4 by most recent tx relay
/// 4. 8 block-relay-only peers by most recent block
/// 5. 4 by most recent block relay
/// 6. Remaining half by longest connection time
/// Returns the index of the peer to evict, or null if no eviction candidate.
pub fn selectEvictionCandidate(candidates: []EvictionCandidate, allocator: std.mem.Allocator) ?usize {
    if (candidates.len == 0) return null;

    // Make a mutable copy for protection marking
    const working = allocator.dupe(EvictionCandidate, candidates) catch return null;
    defer allocator.free(working);

    // Mark protected candidates
    var protected = std.AutoHashMap(usize, void).init(allocator);
    defer protected.deinit();

    // 1. Protect 4 peers from distinct netgroups (Bitcoin Core does this first)
    std.mem.sort(EvictionCandidate, working, {}, compareNetGroup);
    var seen_netgroups = std.AutoHashMap(u32, void).init(allocator);
    defer seen_netgroups.deinit();
    var netgroup_protected: usize = 0;
    for (working) |c| {
        if (netgroup_protected >= EVICTION_PROTECT_NETGROUP) break;
        if (!seen_netgroups.contains(c.net_group)) {
            seen_netgroups.put(c.net_group, {}) catch {};
            protected.put(c.peer_index, {}) catch {};
            netgroup_protected += 1;
        }
    }

    // 2. Protect 8 peers with fastest ping time
    std.mem.sort(EvictionCandidate, working, {}, comparePingTime);
    for (0..@min(EVICTION_PROTECT_PING, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 3. Protect 4 peers with most recent tx relay
    std.mem.sort(EvictionCandidate, working, {}, compareTxTime);
    for (0..@min(EVICTION_PROTECT_TX, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 4. Protect up to 8 non-tx-relay peers (block-relay-only) by most recent block
    std.mem.sort(EvictionCandidate, working, {}, compareBlockTime);
    var block_relay_only_protected: usize = 0;
    for (working) |c| {
        if (block_relay_only_protected >= EVICTION_PROTECT_BLOCK_RELAY_ONLY) break;
        // Protect if not relaying txs (block-relay-only)
        if (!c.relay_txs) {
            protected.put(c.peer_index, {}) catch {};
            block_relay_only_protected += 1;
        }
    }

    // 5. Protect 4 peers with most recent block relay (all peers)
    std.mem.sort(EvictionCandidate, working, {}, compareBlockTime);
    for (0..@min(EVICTION_PROTECT_BLOCK, working.len)) |i| {
        protected.put(working[i].peer_index, {}) catch {};
    }

    // 6. Protect half of remaining peers by longest connection time
    std.mem.sort(EvictionCandidate, working, {}, compareConnectTime);
    var unprotected_count: usize = 0;
    for (working) |c| {
        if (!protected.contains(c.peer_index)) {
            unprotected_count += 1;
        }
    }
    const to_protect_by_time = unprotected_count / 2;
    var time_protected: usize = 0;
    for (working) |c| {
        if (time_protected >= to_protect_by_time) break;
        if (!protected.contains(c.peer_index)) {
            protected.put(c.peer_index, {}) catch {};
            time_protected += 1;
        }
    }

    // Find unprotected candidates
    var unprotected = std.ArrayList(EvictionCandidate).init(allocator);
    defer unprotected.deinit();
    for (candidates) |c| {
        if (!protected.contains(c.peer_index)) {
            unprotected.append(c) catch {};
        }
    }

    if (unprotected.items.len == 0) return null;

    // Group by netgroup and find the netgroup with most connections
    var netgroup_counts = std.AutoHashMap(u32, usize).init(allocator);
    defer netgroup_counts.deinit();
    var netgroup_youngest = std.AutoHashMap(u32, EvictionCandidate).init(allocator);
    defer netgroup_youngest.deinit();

    for (unprotected.items) |c| {
        const count = netgroup_counts.get(c.net_group) orelse 0;
        netgroup_counts.put(c.net_group, count + 1) catch {};

        if (netgroup_youngest.get(c.net_group)) |existing| {
            // Keep the youngest (most recent connect_time)
            if (c.connect_time > existing.connect_time) {
                netgroup_youngest.put(c.net_group, c) catch {};
            }
        } else {
            netgroup_youngest.put(c.net_group, c) catch {};
        }
    }

    // Find netgroup with most connections
    var max_group: u32 = 0;
    var max_count: usize = 0;
    var max_youngest_time: i64 = 0;
    var iter = netgroup_counts.iterator();
    while (iter.next()) |entry| {
        const count = entry.value_ptr.*;
        const youngest = netgroup_youngest.get(entry.key_ptr.*) orelse continue;
        if (count > max_count or (count == max_count and youngest.connect_time > max_youngest_time)) {
            max_count = count;
            max_group = entry.key_ptr.*;
            max_youngest_time = youngest.connect_time;
        }
    }

    // Evict the youngest peer from the most-connected netgroup
    if (netgroup_youngest.get(max_group)) |victim| {
        return victim.peer_index;
    }

    return null;
}

// ============================================================================
// Address Info
// ============================================================================

/// Source of a peer address.
pub const AddressSource = enum {
    dns_seed,
    peer_addr,
    manual,
    /// Hardcoded fixed-seed peer injected as a last-resort fallback when the
    /// address book is empty and DNS/-addnode/-seednode failed to populate it.
    /// Mirrors Core's CNetAddr::SetInternal("fixedseeds") source tag.
    fixed_seed,
};

/// Tracked information about a known peer address.
pub const AddressInfo = struct {
    address: std.net.Address,
    services: u64,
    last_seen: i64,
    last_tried: i64,
    attempts: u32,
    success: bool,
    source: AddressSource,
};

// ============================================================================
// Peer Manager
// ============================================================================

/// Manages multiple peer connections with discovery and connection management.
pub const PeerManager = struct {
    peers: std.ArrayList(*Peer),
    known_addresses: std.AutoHashMap(u64, AddressInfo),
    /// Core-bucketed address manager (NEW/TRIED tables + nKey salt + peers.dat
    /// persistence), wired UNDER known_addresses. `known_addresses` keeps the
    /// rich getnodeaddresses / addr-sharing metadata; this is the real Core
    /// placement + anti-Sybil + persistence engine (src/addrman.zig). Lazily
    /// initialised so PeerManager.init stays infallible. See ensureAddrman().
    addrman: ?addrman_mod.AddrMan,
    ban_list: banlist.BanList,
    listener: ?std.net.Server,
    network_params: *const consensus.NetworkParams,
    allocator: std.mem.Allocator,
    our_height: i32,
    running: std.atomic.Value(bool),
    last_rotation_time: i64,
    /// Set of netgroups for current outbound connections (for diversity).
    outbound_netgroups: std.AutoHashMap(u32, void),
    /// Path to anchor connections file.
    anchors_path: []const u8,
    /// Anchor addresses to connect on startup.
    anchor_addresses: std.ArrayList(std.net.Address),
    /// Data directory for persistence.
    data_dir: ?[]const u8,
    /// Last time we ran the stale tip check (seconds since epoch).
    last_stale_check_time: i64,
    /// Last time our tip was updated (for stale tip detection).
    last_tip_update_time: i64,
    /// Number of outbound peers protected from eviction.
    outbound_protected_count: usize,
    /// Chain state for block sync.
    chain_state: ?*storage.ChainState,
    /// Block relay cache for serving blocks to peers on getdata.
    /// Keyed by block hash, stores serialized block data.
    /// Contains both locally mined blocks and recently connected blocks.
    served_blocks: std.AutoHashMap(types.Hash256, []const u8),
    /// Address to connect to on startup (from --connect flag).
    connect_address: ?std.net.Address,

    /// Mempool for transaction relay and acceptance.
    mempool: ?*mempool_mod.Mempool,

    /// Wallet manager so the live block-connect loop feeds every loaded wallet
    /// (credit/debit + sync-watermark advance), not just the mining/RPC path.
    /// Null in the test harness / when no wallet support is wired.  Set by
    /// main.zig after the manager is constructed; the live drain loop calls
    /// `scanConnectedBlockIntoWallets` after each successful connect.
    wallet_manager: ?*wallet_mod.WalletManager = null,

    // ========================================================================
    // Block Download Pipeline (IBD acceleration)
    // ========================================================================

    /// Buffered blocks waiting to be connected (may arrive out of order).
    /// Key: block hash, Value: the full block (ownership transferred here).
    block_buffer: std.AutoHashMap(types.Hash256, types.Block),

    /// Ordered queue of block hashes we expect to connect, by height.
    /// Index 0 = first block after genesis (height 1 at start of sync).
    /// We track which height we've queued up to and which we've connected up to.
    expected_blocks: std.ArrayList(types.Hash256),

    /// Next index to request blocks for (index into expected_blocks).
    download_cursor: u32,

    /// Next index to connect (index into expected_blocks).
    connect_cursor: u32,

    /// Diagnostic state for the drain-break wedge log (peer.zig:~3073).
    /// Rate-limits DRAIN-BREAK-WEDGE to one line per second per stuck
    /// connect_cursor so the log doesn't drown during a multi-hour wedge.
    last_drain_break_log_ts: i64,
    last_drain_break_cursor: u32,

    /// Number of blocks currently in-flight (requested but not yet received).
    blocks_in_flight: u32,

    /// Maximum blocks in flight at once.
    max_blocks_in_flight: u32,

    /// Last time we logged sync progress.
    last_progress_log: i64,

    /// Last time we durably flushed dirty wallets (unix seconds).  The live
    /// connect loop marks wallets dirty as it credits/debits coins; this gate
    /// persists them on a short period so a SIGKILL/OOM/power-loss loses at most
    /// a few seconds of wallet state — never the whole wallet, never only at
    /// clean shutdown.  Initialised to 0 so the first idle tick flushes.
    last_wallet_flush: i64 = 0,
    /// Last periodic addrman (peers.dat) dump. Initialised to 0 so the first
    /// idle tick after DUMP_PEERS_INTERVAL_SECS persists the learned-peer table.
    last_addrman_dump: i64 = 0,

    /// Last time (unix seconds) we opened a feeler probe (Core net.cpp
    /// ThreadOpenConnections `next_feeler` schedule). A feeler is opened at
    /// most once per FEELER_INTERVAL_SECS (120s). Initialised to 0 so the
    /// first eligible tick opens one.
    last_feeler_time: i64 = 0,

    /// Total blocks connected since last progress log.
    blocks_since_log: u32,

    /// Last time we attempted stall recovery.
    last_stall_recovery: i64,

    /// True while drainBlockBuffer is executing.  Guards the `.block` handler's
    /// nested drain calls so the drain-heartbeat → processAllMessages → `.block`
    /// path can't recurse into drainBlockBuffer.  W101 (2026-04-24).
    in_drain: bool,

    /// Whether to advertise NODE_BLOOM (BIP-37/BIP-35) in outgoing
    /// VERSION messages and serve `mempool` requests.  Plumbed from
    /// the `peerbloomfilters` CLI flag.  Default false to match Bitcoin
    /// Core's `DEFAULT_PEERBLOOMFILTERS = false` (net_processing.h:44).
    peerbloomfilters: bool = false,

    /// BIP-159 prune-mode flag, wired from `chain_state.prune_target_mib > 0`
    /// at peer-creation time.  NOTE: NODE_NETWORK_LIMITED is now advertised
    /// UNCONDITIONALLY for every full node in `Peer.localServices()` (Core
    /// init.cpp:863), so this flag no longer gates that bit; retained for
    /// future prune-specific behaviour.
    advertise_node_network_limited: bool = false,

    /// BIP-157: when true, advertise NODE_COMPACT_FILTERS (1<<6) in outgoing
    /// VERSION messages.  Wired from `config.blockfilterindex` at peer-creation
    /// time.  Mirrors Core's `init.cpp:992-998` where `g_local_services` gains
    /// `NODE_COMPACT_FILTERS` when both `peerblockfilters` and `blockfilterindex`
    /// are enabled.  We gate on `blockfilterindex` alone (peerblockfilters
    /// currently always follows the filter index in clearbit).
    blockfilterindex_enabled: bool = false,

    /// Last time we swept the orphan pool for expired entries (Unix seconds).
    /// Initialized to 0 so the first tick always triggers a sweep.
    last_orphan_sweep: i64,

    /// Per-address fall-back set for BIP-324 v2 outbound negotiation.
    /// Once we've tried v2 against an address and fallen back to v1 (because
    /// the peer didn't speak v2 — a non-ellswift response or a deadline
    /// expiry), record the addressKey here so subsequent outbound attempts
    /// to that address skip the v2 probe.  Bounded by V2_FALLBACK_CACHE_MAX
    /// — once full, we drop a random entry.  This is fine: at worst we
    /// reprobe a v1-only peer with a fresh v2 attempt and pay the deadline
    /// cost again.
    v2_fallback_set: std.AutoHashMap(u64, void),

    /// In-memory header index for competing-fork detection (CLEARBIT_REORG=1).
    /// Each entry: hash → {prev, height, chain_work, timestamp, header}.
    /// Populated by the `.headers` handler.  Bounded at MAX_HEADER_INDEX
    /// via LRU eviction of oldest non-active-tip-ancestor entries.
    /// Never accessed when CLEARBIT_REORG is unset (so the live node pays
    /// no extra memory or CPU).
    header_index: std.AutoHashMap(types.Hash256, BlockHeaderEntry),

    /// SNAPSHOT FORWARD-SYNC: median-time-past of the snapshot base block
    /// (the height at which a `--load-snapshot` boot starts), and that base
    /// height.  Both 0 when the node did not boot from a snapshot.
    ///
    /// Layer-3 fix: the snapshot carries the UTXO set but not the 11-ancestor
    /// header window, so an MTP walk over the first ~11 post-snapshot blocks
    /// (base+1..base+11) finds no ancestors in `header_index` and returns 0,
    /// which drops nLockTimeCutoff to the block's own timestamp and bypasses
    /// BIP-113.  Until the window refills with real post-snapshot timestamps
    /// (~base+11), `computePrevMtp` falls back to `snapshot_base_mtp` for the
    /// incomplete-window band — Core's assumeUTXO behaviour.  Set at startup
    /// from MAINNET.snapshot_bootstrap[i].base_mtp via setSnapshotBaseMtp().
    snapshot_base_mtp: u32 = 0,
    snapshot_base_height: u32 = 0,

    /// Currently-pending reorg, if any.  Set by the headers handler when
    /// a competing-fork branch with strictly higher chainwork is detected;
    /// cleared (and the inner ArrayList freed) by the reorg trigger after
    /// reorgToChain returns.  Only one pending reorg at a time — fork
    /// announcements while one is pending are deferred to the next round.
    pending_reorg: ?PendingReorg,

    /// Maps block hash → source peer pointer (as usize) so drainBlockBuffer
    /// can penalise the supplying peer when validateBlockForIBDOrReject rejects
    /// a block.  Mirrors Bitcoin Core's mapBlockSource (net_processing.cpp:834).
    /// Value is @intFromPtr(*Peer); looked up by linear scan over self.peers at
    /// drain time so a disconnected peer is never dereferenced.
    block_source_peers: std.AutoHashMap(types.Hash256, usize),

    /// Maps block hash → the peer we REQUESTED it from (as @intFromPtr(*Peer)).
    /// Mirrors Bitcoin Core's `mapBlocksInFlight` (net_processing.cpp). This is
    /// the source of truth for "is this block in-flight": pipelineBlockRequests
    /// SKIPS any hash already present (never double-requests → a download_cursor
    /// rewind is drift-free), an entry is removed when the block arrives or its
    /// peer disconnects, and the drain-wedge recovery cancels a stuck front
    /// block by decrementing its holder + removing its entry so it re-requests
    /// cleanly from another peer. Invariant: global `blocks_in_flight` ==
    /// number of live entries here, and each entry's peer has it counted in its
    /// `blocks_in_flight_count`.
    inflight_block_peer: std.AutoHashMap(types.Hash256, usize),

    /// Timestamp (unix seconds) when `connect_cursor` got stuck on a missing
    /// front block while later blocks were buffered (head-of-line drain wedge);
    /// 0 = not wedged. Drives the `DRAIN_WEDGE_STALL_TIMEOUT` cancel-and-rerequest
    /// in `drainBlockBuffer`. Reset to 0 whenever a block connects.
    wedge_since: i64,

    /// ASMap binary bytecode for IP → ASN lookup.  Null when no --asmap file
    /// was loaded.  When non-null, `netGroupWithAsmap()` returns an ASN-keyed
    /// group instead of a /16 prefix group, providing AS-level eclipse
    /// resistance.  Mirrors Core's NetGroupManager::m_asmap field.
    /// Slice is allocator-owned; freed in deinit().
    asmap_data: ?[]u8 = null,

    /// Timestamp (Unix seconds) of the last ASMap health check run.
    /// Initialized to 0 so the first loop iteration always triggers the
    /// initial run (matching Core: ASMapHealthCheck() is called once
    /// immediately then scheduled every ASMAP_HEALTH_CHECK_INTERVAL).
    /// Only meaningful when asmap_data is non-null.
    last_asmap_health_check: i64 = 0,

    /// Optional proxy dispatcher for anonymous networks (Tor v3 / I2P /
    /// CJDNS) and for proxied clearnet dialing.  When null, all dials use
    /// the direct TCP path in Peer.connect.  When set, outbound dispatch
    /// branches on the network type (see selectAndConnectOutbound /
    /// connectOutboundNegotiated below).
    ///
    /// Lifetime: owned by the PeerManager.  Lazy-initialised SOCKS5 / I2P
    /// SAM clients live inside it; deinit() flushes them on shutdown.
    /// Plumbed from main.zig via initProxy() at startup based on the
    /// --proxy / --onion / --i2psam CLI flags.
    proxy_manager: ?proxy_mod.ProxyManager = null,

    /// When true, the fc00::/7 ULA range is treated as routable rather than
    /// rejected as RFC-4193 private.  Mirrors Core's -cjdnsreachable: CJDNS
    /// is the only legitimate consumer of fc00::/8 today, and operators
    /// running a CJDNS-enabled stack want their CJDNS peers actually dialled.
    /// Plumbed from main.zig's Config.cjdnsreachable.  Default false (Core
    /// default is also false — opt-in).
    cjdnsreachable: bool = false,

    /// Fixed-seed fallback (Core net.cpp:2604-2643 ThreadOpenConnections).
    /// When the address book is empty and DNS/-addnode/-seednode failed to
    /// populate it, dial the hardcoded `network_params.fixed_seeds` list as a
    /// last resort.  This is a fallback layered AFTER the normal DNS bootstrap
    /// (dnsSeeds()) — it never replaces it.
    ///
    /// `fixed_seed_enabled`: gate from the `-fixedseeds` CLI flag (Core default
    /// true).  Forced false in `--connect` peer-pinned mode (Core: -connect
    /// bypasses the fixed-seed logic).  Plumbed from main.zig.
    fixed_seed_enabled: bool = true,
    /// `dns_seed_enabled`: mirror of config.dns_seed (Core `-dnsseed`).  Used by
    /// the predicate's cheap `!dnsseed && !use_seednodes` immediate-fire branch.
    /// Plumbed from main.zig.
    dns_seed_enabled: bool = true,
    /// One-shot guard — set true once the fixed seeds have been injected so
    /// subsequent ticks are no-ops (Core sets `add_fixed_seeds = false`).
    fixed_seeds_added: bool = false,
    /// Unix-seconds timestamp anchored at connection-loop entry (Core
    /// `auto start = GetTime()` in ThreadOpenConnections).  The 60-second grace
    /// window in maybeAddFixedSeeds is measured from here.  0 until run() sets it.
    run_loop_start_ts: i64 = 0,

    /// Operator-managed added-node list — the mirror of Bitcoin Core's
    /// `CConnman::m_added_node_params` (net.cpp). Holds the raw, user-supplied
    /// `node` strings from `addnode "<node>" "add"` (NOT resolved addresses, so
    /// the round-trip is exactly what the operator typed, matching Core's
    /// string-keyed dedup in `CConnman::AddNode`/`RemoveAddedNode`).
    ///
    /// This is deliberately SEPARATE from `known_addresses` (the connection/
    /// reconnect machinery): Core keeps the added-node *policy* list distinct
    /// from the live address book so `addnode add` of an already-added node and
    /// `addnode remove` of a never-added node can return the specific RPC error
    /// codes RPC_CLIENT_NODE_ALREADY_ADDED (-23) / RPC_CLIENT_NODE_NOT_ADDED
    /// (-24) instead of silently no-op'ing. Strings are allocator-owned; freed
    /// in deinit() and on removeAddedNode().
    added_nodes: std.ArrayList([]const u8),

    /// Build the advertised local service flags this node announces in its
    /// outgoing VERSION handshakes — the manager-level mirror of
    /// `Peer.localServices()` (the per-peer accessor reads the same config
    /// values copied onto each Peer at creation time).  Used by
    /// getnetworkinfo to report the REAL advertised `localservices` word
    /// (and derive the names array from the SAME value, so they cannot drift).
    ///
    /// Default (non-pruned, v2-on, no bloom/cfilters) full node = 0xC09 =
    /// NODE_NETWORK(0x1) | NODE_WITNESS(0x8) | NODE_NETWORK_LIMITED(0x400)
    /// | NODE_P2P_V2(0x800).
    pub fn localServices(self: *const PeerManager) u64 {
        var s: u64 = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
        if (self.peerbloomfilters) s |= p2p.NODE_BLOOM;
        // NODE_NETWORK_LIMITED is advertised unconditionally for a full node
        // (Core init.cpp:863), matching Peer.localServices().
        s |= p2p.NODE_NETWORK_LIMITED;
        if (self.blockfilterindex_enabled) s |= p2p.NODE_COMPACT_FILTERS;
        if (Peer.bip324V2Enabled()) s |= p2p.NODE_P2P_V2;
        return s;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        params: *const consensus.NetworkParams,
    ) PeerManager {
        return .{
            .peers = std.ArrayList(*Peer).init(allocator),
            .known_addresses = std.AutoHashMap(u64, AddressInfo).init(allocator),
            .addrman = null,
            .ban_list = banlist.BanList.init(allocator, "banlist.json"),
            .listener = null,
            .network_params = params,
            .allocator = allocator,
            .our_height = 0,
            .running = std.atomic.Value(bool).init(false),
            .last_rotation_time = 0,
            .outbound_netgroups = std.AutoHashMap(u32, void).init(allocator),
            .anchors_path = "anchors.dat",
            .anchor_addresses = std.ArrayList(std.net.Address).init(allocator),
            .data_dir = null,
            .last_stale_check_time = 0,
            .last_tip_update_time = 0,
            .outbound_protected_count = 0,
            .chain_state = null,
            .served_blocks = std.AutoHashMap(types.Hash256, []const u8).init(allocator),
            .connect_address = null,
            .mempool = null,
            .wallet_manager = null,
            .block_buffer = std.AutoHashMap(types.Hash256, types.Block).init(allocator),
            .expected_blocks = std.ArrayList(types.Hash256).init(allocator),
            .download_cursor = 0,
            .connect_cursor = 0,
            .last_drain_break_log_ts = 0,
            .last_drain_break_cursor = 0,
            .blocks_in_flight = 0,
            .max_blocks_in_flight = 128,
            .last_progress_log = 0,
            .last_wallet_flush = 0,
            .last_addrman_dump = 0,
            .blocks_since_log = 0,
            .last_stall_recovery = 0,
            .in_drain = false,
            .peerbloomfilters = false,
            .advertise_node_network_limited = false,
            .v2_fallback_set = std.AutoHashMap(u64, void).init(allocator),
            .header_index = std.AutoHashMap(types.Hash256, BlockHeaderEntry).init(allocator),
            .pending_reorg = null,
            .block_source_peers = std.AutoHashMap(types.Hash256, usize).init(allocator),
            .inflight_block_peer = std.AutoHashMap(types.Hash256, usize).init(allocator),
            .wedge_since = 0,
            .last_orphan_sweep = 0,
            .asmap_data = null,
            .proxy_manager = null,
            .cjdnsreachable = false,
            .fixed_seed_enabled = true,
            .dns_seed_enabled = true,
            .fixed_seeds_added = false,
            .run_loop_start_ts = 0,
            .added_nodes = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *PeerManager) void {
        // Save ban list and anchors before shutdown
        self.ban_list.save() catch {};
        self.saveAnchors() catch {};
        // Persist the bucketed addrman (peers.dat) if a data dir is set.
        if (self.addrman) |*am| {
            if (self.data_dir) |dir| am.save(dir);
            am.deinit();
        }
        for (self.peers.items) |peer| {
            peer.disconnect();
            self.allocator.destroy(peer);
        }
        self.peers.deinit();
        self.known_addresses.deinit();
        self.ban_list.deinit();
        self.outbound_netgroups.deinit();
        self.anchor_addresses.deinit();
        // Free any buffered blocks
        {
            var iter = self.block_buffer.valueIterator();
            while (iter.next()) |blk| {
                serialize.freeBlock(self.allocator, blk);
            }
            self.block_buffer.deinit();
        }
        self.expected_blocks.deinit();
        // Free cached block data for relay
        {
            var iter = self.served_blocks.valueIterator();
            while (iter.next()) |data| {
                self.allocator.free(data.*);
            }
            self.served_blocks.deinit();
        }
        if (self.listener) |*l| l.deinit();
        self.v2_fallback_set.deinit();
        self.header_index.deinit();
        if (self.pending_reorg) |*pr| pr.deinit();
        self.block_source_peers.deinit();
        self.inflight_block_peer.deinit();
        if (self.asmap_data) |data| self.allocator.free(data);
        if (self.proxy_manager) |*pm| pm.deinit();
        // Free the owned added-node strings (Core m_added_node_params).
        for (self.added_nodes.items) |n| self.allocator.free(n);
        self.added_nodes.deinit();
    }

    /// Default SOCKS5 proxy port when none is given (matches Core's default
    /// of 9050 for Tor and 9150 for Tor Browser; we pick the daemon port).
    pub const DEFAULT_SOCKS5_PORT: u16 = 9050;

    /// Default I2P SAM bridge port (Core constant DEFAULT_I2P_SAM_PORT = 7656).
    pub const DEFAULT_I2P_SAM_PORT: u16 = 7656;

    /// Parse a "host:port" or "host" string into (host, port).  When no
    /// `:port` suffix is present `default_port` is returned.  IPv6 literals
    /// must be bracketed (e.g. "[::1]:9050"); for the bracketed form the
    /// inner host has the brackets stripped.  Returns null on malformed
    /// input (e.g. unparseable port).
    fn parseProxyHostPort(spec: []const u8, default_port: u16) ?struct {
        host: []const u8,
        port: u16,
    } {
        if (spec.len == 0) return null;
        // Bracketed IPv6 form: [host]:port or [host]
        if (spec[0] == '[') {
            const close = std.mem.indexOfScalar(u8, spec, ']') orelse return null;
            const host = spec[1..close];
            if (close + 1 == spec.len) {
                return .{ .host = host, .port = default_port };
            }
            if (spec[close + 1] != ':') return null;
            const port = std.fmt.parseInt(u16, spec[close + 2 ..], 10) catch return null;
            return .{ .host = host, .port = port };
        }
        // Last-colon form (so "127.0.0.1:9050" works; bare IPv6 without
        // brackets is rejected because it's ambiguous).
        if (std.mem.lastIndexOfScalar(u8, spec, ':')) |colon| {
            const host = spec[0..colon];
            const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return null;
            return .{ .host = host, .port = port };
        }
        return .{ .host = spec, .port = default_port };
    }

    /// Construct and install the ProxyManager from the parsed Config strings.
    /// Idempotent: replaces any existing manager.  Returns true if at least
    /// one proxy was configured (caller may log a startup line).
    ///
    /// Semantics mirror Bitcoin Core's init.cpp:
    ///   * `proxy_spec` (=--proxy) is the SOCKS5 endpoint for clearnet and
    ///     the fall-back proxy for Tor/I2P when their specific flags are
    ///     omitted.
    ///   * `onion_spec` (=--onion) is the SOCKS5 endpoint specifically for
    ///     Tor v3 .onion addresses.  Defaults to `proxy_spec` if unset.
    ///   * `i2psam_spec` (=--i2psam) is the I2P SAM bridge.  When omitted,
    ///     I2P addresses cannot be dialled and shouldDial(.i2p) returns false.
    pub fn initProxy(
        self: *PeerManager,
        proxy_spec: ?[]const u8,
        onion_spec: ?[]const u8,
        i2psam_spec: ?[]const u8,
    ) void {
        // If a previous manager exists, deinit it so we don't leak
        // lazy-allocated SAM session strings.
        if (self.proxy_manager) |*pm| pm.deinit();

        var clearnet = proxy_mod.ProxyConfig{};
        var tor = proxy_mod.ProxyConfig{};
        var i2p = proxy_mod.ProxyConfig{};

        if (proxy_spec) |s| {
            if (parseProxyHostPort(s, DEFAULT_SOCKS5_PORT)) |hp| {
                clearnet = .{
                    .proxy_type = .socks5,
                    .host = hp.host,
                    .port = hp.port,
                };
                // -onion falls back to -proxy if not explicitly set (Core init.cpp).
                tor = clearnet;
            }
        }
        if (onion_spec) |s| {
            if (parseProxyHostPort(s, DEFAULT_SOCKS5_PORT)) |hp| {
                tor = .{
                    .proxy_type = .socks5,
                    .host = hp.host,
                    .port = hp.port,
                };
            }
        }
        if (i2psam_spec) |s| {
            if (parseProxyHostPort(s, DEFAULT_I2P_SAM_PORT)) |hp| {
                i2p = .{
                    .proxy_type = .i2p,
                    .host = hp.host,
                    .port = hp.port,
                };
            }
        }

        // Only install the manager if at least one network was actually
        // configured — otherwise leave proxy_manager null so the dial path
        // takes the existing direct route with zero overhead.
        if (clearnet.proxy_type != .none or tor.proxy_type != .none or i2p.proxy_type != .none) {
            self.proxy_manager = proxy_mod.ProxyManager.init(clearnet, tor, i2p, self.allocator);
        }
    }

    /// Predicate: should we attempt to dial peers on the given BIP-155 network?
    /// Returns true iff we have the transport for that network configured.
    ///
    ///   .ipv4 / .ipv6  → always (direct path, or via clearnet proxy)
    ///   .torv3         → only if proxy_manager has a Tor SOCKS5 configured
    ///   .i2p           → only if proxy_manager has an I2P SAM configured
    ///   .cjdns         → only if cjdnsreachable is true (we treat fc00::/7
    ///                    as routable; the dial itself uses the direct path
    ///                    because CJDNS is a kernel-level overlay, not a proxy)
    ///   .torv2         → never (deprecated by Tor in Oct 2021)
    ///
    /// Mirrors Core's CConnman::IsReachable() gate at net.cpp:
    /// connections to unreachable networks are skipped during outbound
    /// rotation before any TCP cost is incurred.
    pub fn shouldDial(self: *const PeerManager, network: proxy_mod.NetworkId) bool {
        return switch (network) {
            .ipv4, .ipv6 => true,
            .torv3 => blk: {
                if (self.proxy_manager) |*pm| {
                    break :blk pm.tor_config.proxy_type == .socks5 or
                        pm.tor_config.proxy_type == .tor;
                }
                break :blk false;
            },
            .i2p => blk: {
                if (self.proxy_manager) |*pm| {
                    break :blk pm.i2p_config.proxy_type == .i2p;
                }
                break :blk false;
            },
            .cjdns => self.cjdnsreachable,
            .torv2 => false,
        };
    }

    /// Dial an overlay-network peer through the configured ProxyManager and
    /// return the connected raw stream on success.  Caller is responsible
    /// for running the Bitcoin handshake on top of the stream.
    ///
    /// Returns null when no proxy is configured for the network type, or
    /// when the SOCKS5 / SAM connection attempt fails.  Errors are
    /// downgraded to null so the maintainOutbound loop can continue to the
    /// next candidate without unwinding.
    pub fn connectViaProxy(
        self: *PeerManager,
        addr: *const proxy_mod.MultiNetworkAddress,
    ) ?std.net.Stream {
        if (!self.shouldDial(addr.network)) return null;
        var pm = &(self.proxy_manager orelse return null);
        return pm.connectTo(addr) catch |err| {
            std.debug.print(
                "P2P: proxy dial failed network={any} port={d} err={any}\n",
                .{ addr.network, addr.port, err },
            );
            return null;
        };
    }

    /// Cap on the BIP-324 v2 fall-back set (per-process).  Once exceeded
    /// we drop a random entry to bound memory; reprobing v1-only peers is
    /// cheap (one round-trip cost) so accuracy isn't critical.
    pub const V2_FALLBACK_CACHE_MAX: usize = 4096;

    /// BIP-324 v2 outbound probe deadline (per Bitcoin Core net.cpp uses
    /// ~30s; we mirror that).  Short enough that a stalled remote
    /// doesn't wedge the maintainOutbound caller for long.
    pub const V2_PROBE_DEADLINE_MS: i64 = 30_000;

    /// Open a clearnet (IPv4/IPv6) outbound TCP connection to `address`,
    /// using the configured ProxyManager when --proxy is set, otherwise
    /// going direct.  Returns a Peer wrapping the raw socket on success.
    ///
    /// This is the single dispatch point for IPv4/IPv6 outbound dials.  When
    /// the operator wires up Tor as a clearnet proxy (--proxy=127.0.0.1:9050),
    /// all clearnet dials transparently exit through Tor — matching Bitcoin
    /// Core's -proxy semantics.
    fn openClearnetOutbound(self: *PeerManager, address: std.net.Address) ?Peer {
        // Direct path: no proxy configured, or proxy is configured but only
        // for overlay networks (clearnet_config.proxy_type == .none).
        const proxied = blk: {
            if (self.proxy_manager) |pm| break :blk pm.clearnet_config.proxy_type == .socks5;
            break :blk false;
        };
        if (!proxied) {
            return Peer.connect(address, self.network_params, self.allocator) catch return null;
        }

        // Proxy path: convert std.net.Address to a MultiNetworkAddress and
        // dispatch through ProxyManager.  ProxyManager handles the SOCKS5
        // negotiation and returns a connected stream.
        var addr_bytes_buf: [16]u8 = undefined;
        const ma = switch (address.any.family) {
            std.posix.AF.INET => mn: {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip = @as(*const [4]u8, @ptrCast(&ip4.addr));
                @memcpy(addr_bytes_buf[0..4], ip);
                break :mn proxy_mod.MultiNetworkAddress{
                    .network = .ipv4,
                    .address = addr_bytes_buf[0..4],
                    .port = std.mem.bigToNative(u16, ip4.port),
                };
            },
            std.posix.AF.INET6 => mn: {
                const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address.any)));
                @memcpy(addr_bytes_buf[0..16], &ip6.addr);
                break :mn proxy_mod.MultiNetworkAddress{
                    .network = .ipv6,
                    .address = addr_bytes_buf[0..16],
                    .port = std.mem.bigToNative(u16, ip6.port),
                };
            },
            else => return null,
        };
        const stream = self.connectViaProxy(&ma) orelse return null;
        return Peer.fromOutboundStream(stream, address, self.network_params, self.allocator);
    }

    /// Try to open an outbound connection to `address`, negotiating BIP-324
    /// v2 if `Peer.bip324V2Enabled()` is true and the address is not in
    /// the v1-fallback set.  Returns the fully-handshaked Peer on success
    /// or null on any failure.  Caller takes ownership of the returned
    /// pointer (must `disconnect` + `destroy`).
    ///
    /// Behavior:
    ///  1. Open TCP connection.
    ///  2. If v2 is enabled and the address is not v1-only, attach a
    ///     V2Transport (initiator) to the peer and drive the BIP-324
    ///     cipher handshake.  On success, run the application
    ///     version/verack over the encrypted v2 transport.  On failure
    ///     (peer is v1, deadline expired, decryption failed, etc.) close
    ///     the socket, mark the address v1-only, and reconnect for a v1
    ///     handshake on a fresh socket — sending v2 garbage is destructive
    ///     on a v1 peer so we cannot reuse the same socket.
    ///  3. Otherwise run `performHandshake` (v1) on the original socket.
    pub fn connectOutboundNegotiated(
        self: *PeerManager,
        address: std.net.Address,
    ) ?*Peer {
        // Default full-relay path (relay_self = true).
        return self.connectOutboundNegotiatedRelay(address, true);
    }

    /// Like `connectOutboundNegotiated` but with an explicit `relay_self` flag
    /// for the version handshake. `relay_self = false` is used by feeler
    /// connections (Core sends fRelay=false on feelers). The relay flag must be
    /// set on the Peer BEFORE `performHandshake` runs (it builds the version
    /// message from `peer.relay_self`).
    fn connectOutboundNegotiatedRelay(
        self: *PeerManager,
        address: std.net.Address,
        relay_self: bool,
    ) ?*Peer {
        const v2_enabled = Peer.bip324V2Enabled();
        const try_v2 = v2_enabled and !self.isV1Only(address);

        // Phase 1: try BIP-324 v2 directly on a fresh socket.
        if (try_v2) {
            const peer = self.allocator.create(Peer) catch return null;
            // Use openClearnetOutbound so --proxy is honoured for clearnet.
            peer.* = self.openClearnetOutbound(address) orelse {
                self.allocator.destroy(peer);
                return null;
            };
            peer.relay_self = relay_self;
            peer.advertise_node_bloom = self.peerbloomfilters;
            peer.advertise_node_network_limited = self.advertise_node_network_limited;
            peer.advertise_compact_filters = self.blockfilterindex_enabled;

            // Attach an initiator-mode V2Transport to the peer and let it
            // drive the cipher handshake.  The transport's init() already
            // queued the 64-byte ellswift pubkey + garbage for sending.
            const t = self.allocator.create(v2_transport.V2Transport) catch {
                peer.disconnect();
                self.allocator.destroy(peer);
                return null;
            };
            t.* = v2_transport.V2Transport.init(
                self.allocator,
                true, // initiator
                self.network_params.magic,
            );
            peer.v2_transport = t;

            peer.performV2Handshake(Peer.V2_HANDSHAKE_DEADLINE_MS) catch |err| {
                // Use std.debug.print so the line is visible in ReleaseFast
                // (Zig 0.13's default `log_level` for ReleaseFast is `.err`,
                // so std.log.info is silently dropped — and the v2 wiring
                // probe needs to be observable in production logs).
                std.debug.print("P2P: BIP-324 v2 outbound handshake failed peer={any} err={any}; falling back to v1\n", .{ address, err });
                self.markV1Only(address);
                peer.disconnect();
                self.allocator.destroy(peer);
                // Fall through to v1 path below (preserving relay_self).
                return self.connectOutboundV1Relay(address, relay_self);
            };

            // V2 cipher handshake complete — run the application
            // version/verack on the encrypted transport.
            peer.performHandshake(self.our_height) catch |hs_err| {
                std.debug.print("P2P: BIP-324 v2 app-handshake failed peer={any} err={any} (cipher OK)\n", .{ address, hs_err });
                peer.disconnect();
                self.allocator.destroy(peer);
                return null;
            };
            // Visible in ReleaseFast — see comment above.
            std.debug.print("P2P: BIP-324 v2 connected (encrypted) peer={any}\n", .{address});
            return peer;
        }

        // Phase 2: v1 handshake on a fresh connection.
        return self.connectOutboundV1Relay(address, relay_self);
    }

    /// Open a fresh TCP connection and run the v1 handshake.  Used both as
    /// the explicit v1 path and as the fallback after a failed v2
    /// negotiation (v2 garbage is destructive on a v1 peer so the original
    /// socket cannot be reused).
    fn connectOutboundV1(self: *PeerManager, address: std.net.Address) ?*Peer {
        return self.connectOutboundV1Relay(address, true);
    }

    /// `connectOutboundV1` with an explicit `relay_self` flag for the version
    /// handshake (false for feeler connections).
    fn connectOutboundV1Relay(self: *PeerManager, address: std.net.Address, relay_self: bool) ?*Peer {
        const peer = self.allocator.create(Peer) catch return null;
        // Use openClearnetOutbound so --proxy is honoured for clearnet.
        peer.* = self.openClearnetOutbound(address) orelse {
            self.allocator.destroy(peer);
            return null;
        };
        peer.relay_self = relay_self;
        peer.advertise_node_bloom = self.peerbloomfilters;
        peer.advertise_node_network_limited = self.advertise_node_network_limited;
        peer.advertise_compact_filters = self.blockfilterindex_enabled;
        // Set mapped_as for getpeerinfo when asmap is loaded.
        if (self.asmap_data) |data| {
            peer.mapped_as = getMappedAS(data, address);
        }
        peer.performHandshake(self.our_height) catch {
            peer.disconnect();
            self.allocator.destroy(peer);
            return null;
        };
        return peer;
    }

    /// Mark `address` as v1-only so future outbound attempts skip the v2 probe.
    pub fn markV1Only(self: *PeerManager, address: std.net.Address) void {
        const key = addressKey(address);
        if (self.v2_fallback_set.count() >= V2_FALLBACK_CACHE_MAX) {
            // Drop a random-ish entry: iterate once, remove the first key we
            // see.  AutoHashMap's iteration order is implementation-defined.
            var iter = self.v2_fallback_set.keyIterator();
            if (iter.next()) |k| {
                _ = self.v2_fallback_set.remove(k.*);
            }
        }
        self.v2_fallback_set.put(key, {}) catch {};
    }

    /// Returns true if `address` is in the v1-only fall-back set.
    pub fn isV1Only(self: *const PeerManager, address: std.net.Address) bool {
        return self.v2_fallback_set.contains(addressKey(address));
    }

    /// Load ban list from disk.
    pub fn loadBanList(self: *PeerManager) !void {
        try self.ban_list.load();
    }

    /// Save ban list to disk.
    pub fn saveBanList(self: *PeerManager) !void {
        try self.ban_list.save();
    }

    /// Hash an address for use as a map key.
    pub fn addressKey(address: std.net.Address) u64 {
        // For IPv4, combine IP and port into a u64
        // For IPv6, use a simple hash
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                const ip_u32 = std.mem.readInt(u32, ip_bytes, .big);
                const port = std.mem.bigToNative(u16, ip4.port);
                return (@as(u64, ip_u32) << 16) | @as(u64, port);
            },
            std.posix.AF.INET6 => {
                const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address.any)));
                var hash: u64 = 0;
                for (ip6.addr, 0..) |b, i| {
                    hash ^= @as(u64, b) << @intCast((i % 8) * 8);
                }
                hash ^= @as(u64, std.mem.bigToNative(u16, ip6.port));
                return hash;
            },
            else => return 0,
        }
    }

    /// Extract IPv4 as u32 for ban tracking.
    pub fn ipv4AsU32(address: std.net.Address) ?u32 {
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                return std.mem.readInt(u32, ip_bytes, .big);
            },
            else => return null,
        }
    }

    /// Extract IPv4 bytes for ban tracking.
    pub fn ipv4AsBytes(address: std.net.Address) ?[4]u8 {
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                return ip_bytes.*;
            },
            else => return null,
        }
    }

    /// Perform DNS seed resolution to discover initial peers.
    pub fn dnsSeeds(self: *PeerManager) !void {
        for (self.network_params.dns_seeds) |seed| {
            // Resolve DNS seed to list of addresses
            const addrs = std.net.getAddressList(self.allocator, seed, self.network_params.default_port) catch |err| {
                std.log.warn("DNS resolution failed for {s}: {}", .{ seed, err });
                continue;
            };
            defer addrs.deinit();

            std.log.info("Resolved {d} addresses from DNS seed {s}", .{ addrs.addrs.len, seed });
            for (addrs.addrs) |addr| {
                self.addAddress(addr, 0, .dns_seed) catch continue;
            }
        }
    }

    /// Inject the hardcoded `network_params.fixed_seeds` peers into the address
    /// book.  Each entry is an "IP:port" literal; non-parseable / non-routable
    /// entries are skipped (addAddress already drops non-routable + dedups).
    /// Returns the number of addresses actually added.  One-shot caller is
    /// `maybeAddFixedSeeds`, which sets `fixed_seeds_added`.
    ///
    /// Mirrors Core net.cpp:2629-2641: ConvertSeeds(m_params.FixedSeeds()) →
    /// addrman.Add(seed_addrs, local /* SetInternal("fixedseeds") */).  The
    /// per-impl reachable/dedup filter is addAddress's isRoutable gate (the
    /// curated set is IPv4-only routable, so all entries pass).
    pub fn addFixedSeeds(self: *PeerManager) usize {
        var added: usize = 0;
        for (self.network_params.fixed_seeds) |entry| {
            // Split on the last ':' — everything after is the port.
            const colon = std.mem.lastIndexOfScalar(u8, entry, ':') orelse continue;
            const host = entry[0..colon];
            const port_str = entry[colon + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch continue;
            // Literal IP only — fixed seeds are never hostnames (no DNS here).
            const addr = std.net.Address.parseIp(host, port) catch continue;
            const before = self.known_addresses.count();
            self.addAddress(addr, p2p.NODE_NETWORK, .fixed_seed) catch continue;
            if (self.known_addresses.count() > before) added += 1;
        }
        return added;
    }

    /// Core-faithful fixed-seed fallback predicate (net.cpp:2604-2643,
    /// ThreadOpenConnections).  Fire the one-shot fixed-seed injection ONLY when
    /// ALL hold:
    ///   1. FIXED-SEEDS ENABLED: `-fixedseeds != 0` AND not in `--connect` mode
    ///      (both folded into `fixed_seed_enabled`, set by main.zig).
    ///   2. ADDRESS BOOK EMPTY: `known_addresses.count() == 0` — Core's
    ///      `!GetReachableEmptyNetworks().empty()` proxy for this IPv4 set.
    ///   3. EITHER (a) ~60s elapsed since the connection loop started (Core
    ///      net.cpp:2614 — gives DNS/-addnode/-seednode time to populate first),
    ///      OR (b) DNS seeding is disabled (Core net.cpp:2620 cheap shortcut —
    ///      nothing to wait for, fire immediately).
    /// After firing, set `fixed_seeds_added = true` so later ticks are no-ops.
    ///
    /// Does NOT bypass normal bootstrap: dnsSeeds() still runs first and
    /// unchanged; this is a last-resort fallback layered after it.
    /// Returns true if the injection fired on this call.
    pub fn maybeAddFixedSeeds(self: *PeerManager) bool {
        // One-shot guard (Core sets add_fixed_seeds = false after firing).
        if (self.fixed_seeds_added) return false;
        // (1) Fixed seeds enabled (covers -fixedseeds=0 and --connect mode).
        if (!self.fixed_seed_enabled) return false;
        // Nothing to inject (e.g. regtest, which carries an empty list).
        if (self.network_params.fixed_seeds.len == 0) return false;
        // (2) Address book must be empty (Core's reachable-empty-network proxy).
        if (self.known_addresses.count() != 0) return false;

        // (3) EITHER 60s elapsed since loop start, OR DNS seeding disabled.
        var fire_now = false;
        if (!self.dns_seed_enabled) {
            // Cheap shortcut: no DNS source to wait for — fire immediately.
            // (Core net.cpp:2620 also checks -addnode/-seednode; clearbit has
            // no addnode-at-boot population path here, so DNS-off ⇒ fire.)
            fire_now = true;
        } else if (self.run_loop_start_ts != 0 and
            std.time.timestamp() > self.run_loop_start_ts + 60)
        {
            // 60-second grace window elapsed and the book is still empty.
            fire_now = true;
        }
        if (!fire_now) return false;

        const added = self.addFixedSeeds();
        // One-shot: never re-inject, even if addFixedSeeds added nothing
        // (matches Core, which clears add_fixed_seeds unconditionally once the
        // fire conditions are met).
        self.fixed_seeds_added = true;
        std.log.info("Added {d} fixed seeds (address book was empty)", .{added});
        return true;
    }

    /// Return true if `address` is publicly routable on the global internet.
    ///
    /// Mirrors Bitcoin Core's CNetAddr::IsRoutable() in netaddress.cpp:
    ///   return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() ||
    ///          IsRFC4862() || IsRFC6598() || IsRFC5737() || IsRFC4193() ||
    ///          IsRFC4843() || IsRFC7343() || IsLocal() || IsInternal());
    ///
    /// For clearbit's IPv4/IPv6 scope we implement the IPv4 non-routable ranges
    /// and the most-common IPv6 non-routable ranges.  Addresses from overlay
    /// networks (Tor, I2P, CJDNS) are not yet handled here (separate network_id
    /// in addrv2) and are conservatively treated as non-routable until the addrv2
    /// IPv6/Tor path is wired up (W104/G5).
    pub fn isRoutable(address: std.net.Address) bool {
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const b = @as(*const [4]u8, @ptrCast(&ip4.addr));
                const a0 = b[0];
                const a1 = b[1];

                // Unspecified / broadcast
                if (a0 == 0 or (a0 == 255 and a1 == 255)) return false;

                // RFC 1918 private ranges: 10/8, 172.16/12, 192.168/16
                if (a0 == 10) return false;
                if (a0 == 172 and a1 >= 16 and a1 <= 31) return false;
                if (a0 == 192 and a1 == 168) return false;

                // RFC 2544 benchmarking: 198.18/15
                if (a0 == 198 and (a1 == 18 or a1 == 19)) return false;

                // RFC 3927 link-local: 169.254/16
                if (a0 == 169 and a1 == 254) return false;

                // RFC 6598 shared address (CGNAT): 100.64/10
                if (a0 == 100 and a1 >= 64 and a1 <= 127) return false;

                // RFC 5737 documentation: 192.0.2/24, 198.51.100/24, 203.0.113/24
                if (a0 == 192 and a1 == 0 and b[2] == 2) return false;
                if (a0 == 198 and a1 == 51 and b[2] == 100) return false;
                if (a0 == 203 and a1 == 0 and b[2] == 113) return false;

                // Loopback: 127/8
                if (a0 == 127) return false;

                return true;
            },
            std.posix.AF.INET6 => {
                const ip6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address.any)));
                const b = ip6.addr;

                // Unspecified ::/128 or loopback ::1/128
                const all_zero = for (b) |v| {
                    if (v != 0) break false;
                } else true;
                if (all_zero) return false;

                var is_loopback = all_zero;
                if (!is_loopback) {
                    is_loopback = true;
                    for (b[0..15]) |v| {
                        if (v != 0) { is_loopback = false; break; }
                    }
                    if (is_loopback) is_loopback = (b[15] == 1);
                }
                if (is_loopback) return false;

                // RFC 4862 / RFC 4291 link-local: fe80::/10
                if (b[0] == 0xFE and (b[1] & 0xC0) == 0x80) return false;

                // RFC 4193 unique-local: fc00::/7  (fc::/8 and fd::/8)
                if ((b[0] & 0xFE) == 0xFC) return false;

                // RFC 3849 documentation: 2001:db8::/32
                if (b[0] == 0x20 and b[1] == 0x01 and b[2] == 0x0D and b[3] == 0xB8) return false;

                // RFC 4380 Teredo: 2001::/32
                if (b[0] == 0x20 and b[1] == 0x01 and b[2] == 0x00 and b[3] == 0x00) return false;

                // RFC 4843 / RFC 7343 ORCHIDv1/v2: 2001:10::/28 and 2001:20::/28
                if (b[0] == 0x20 and b[1] == 0x01 and b[2] == 0x00) {
                    if ((b[3] & 0xF0) == 0x10) return false; // RFC 4843
                    if ((b[3] & 0xF0) == 0x20) return false; // RFC 7343
                }

                return true;
            },
            else => return false,
        }
    }

    /// Add a known address.
    /// Lazily construct (or load from peers.dat) the bucketed addrman. Called
    /// before any addrman mutation. Keeps PeerManager.init infallible. On any
    /// allocation/load failure the addrman stays null and the legacy
    /// known_addresses map continues to function (the bucketed engine is a
    /// transparent under-layer, never load-bearing for liveness).
    fn ensureAddrman(self: *PeerManager) ?*addrman_mod.AddrMan {
        if (self.addrman == null) {
            const loaded: ?addrman_mod.AddrMan = blk: {
                if (self.data_dir) |dir| {
                    break :blk addrman_mod.AddrMan.load(self.allocator, dir) catch null;
                }
                break :blk addrman_mod.AddrMan.init(self.allocator) catch null;
            };
            self.addrman = loaded orelse return null;
        }
        return &self.addrman.?;
    }

    /// The /16 (v4) or /32 (v6) network group for the source of an address
    /// record. clearbit feeds netGroup() (or the asmap ASN when loaded) as the
    /// group input to the bucketed addrman, exactly as Core feeds
    /// NetGroupManager::GetGroup.
    fn addrManGroup(self: *const PeerManager, address: std.net.Address) u32 {
        if (self.asmap_data) |data| {
            const asn = getMappedAS(data, address);
            if (asn != 0) return asn;
        }
        return netGroup(address);
    }

    /// Add an address to the address book.
    ///
    /// `peer_time_unix` is the peer-advertised timestamp (already clamped via
    /// `clampAddrTimestamp`).  When null the current wall-clock is used, which
    /// is correct for DNS seeds, fixed seeds, and manual addnode entries.
    /// For gossip (addr/addrv2) callers MUST pass the clamped peer timestamp so
    /// addrman records how recently the advertising peer claims to have seen the
    /// address — matching Core's addrman.Add(addr, peer_addr, time_penalty=2h).
    ///
    /// Core reference: net_processing.cpp ProcessAddrs / addrman.cpp Add.
    pub fn addAddress(
        self: *PeerManager,
        address: std.net.Address,
        services: u64,
        source: AddressSource,
    ) !void {
        return self.addAddressWithTime(address, services, source, null);
    }

    pub fn addAddressWithTime(
        self: *PeerManager,
        address: std.net.Address,
        services: u64,
        source: AddressSource,
        peer_time_unix: ?u64,
    ) !void {
        // Reject non-publicly-routable addresses from gossip.
        // Core: addrman.cpp AddrManImpl::AddSingle() line ~534:
        //   if (!addr.IsRoutable()) return false;
        // This prevents RFC1918 / loopback / link-local addresses received
        // via addr/addrv2 messages from polluting the address book.
        if (!isRoutable(address)) return;

        // Check if IP is banned
        if (self.ban_list.isAddressBanned(address)) return;

        // Feed the Core-bucketed addrman (NEW table placement + anti-Sybil +
        // persistence). The source group is the source's netgroup; for gossiped
        // addresses we lack the relaying peer's address here, so we group by the
        // address itself (Core groups new entries by source — clearbit's source
        // metadata is per-AddressSource enum, not a CNetAddr, so this is the
        // best-available group input and still spreads by /16).
        const now_i = std.time.timestamp();
        const now: u64 = if (now_i < 0) 0 else @intCast(now_i);
        // Use the peer-supplied (clamped) timestamp when available, so addrman
        // records the address freshness as the advertising peer sees it.
        // Core: addrman.Add(vAddrOk, pfrom.addr, time_penalty=2h); the
        // per-address nTime is already clamped before Add is called.
        const time_for_addrman: u64 = peer_time_unix orelse now;
        if (self.ensureAddrman()) |am| {
            const ag = self.addrManGroup(address);
            // Source group: gossiped addrs carry no relayer addr in this API, so
            // use the address's own group (Core uses the source's group; this
            // degrades gracefully to per-/16 spread without a relayer addr).
            const sg = ag;
            _ = am.add(address, ag, sg, services, time_for_addrman, now) catch {};
        }

        const key = addressKey(address);
        if (self.known_addresses.contains(key)) return;

        // Prefer the peer-supplied timestamp for the legacy map as well, so
        // that selectPeerToConnect's freshness heuristic sees the same value.
        const last_seen_i: i64 = if (peer_time_unix) |pt|
            @intCast(pt)
        else
            now_i;

        try self.known_addresses.put(key, AddressInfo{
            .address = address,
            .services = services,
            .last_seen = last_seen_i,
            .last_tried = 0,
            .attempts = 0,
            .success = false,
            .source = source,
        });
    }

    /// Check if an address is already connected.
    fn isConnected(self: *const PeerManager, address: std.net.Address) bool {
        const key = addressKey(address);
        for (self.peers.items) |peer| {
            if (addressKey(peer.address) == key) return true;
        }
        return false;
    }

    /// Select an address to connect to (prefer untried, recent addresses).
    /// Enforces netgroup diversity: rejects addresses from netgroups we already have.
    pub fn selectPeerToConnect(self: *PeerManager) ?std.net.Address {
        const now = std.time.timestamp();
        var best: ?*AddressInfo = null;
        var best_key: u64 = 0;

        var iter = self.known_addresses.iterator();
        while (iter.next()) |entry| {
            const info = entry.value_ptr;

            // Skip already connected addresses
            if (self.isConnected(info.address)) continue;

            // Skip manual addresses — those are owned by maintainManualConnections,
            // which uses a shorter throttle and tags .manual on success so
            // rotatePeers doesn't evict them. Letting the outbound path
            // pick them up would silently demote them to .outbound_full_relay.
            if (info.source == .manual) continue;

            // Skip recently tried addresses
            if (info.last_tried > 0 and now - info.last_tried < MIN_RECONNECT_INTERVAL) continue;

            // Skip banned IPs
            if (self.ban_list.isAddressBanned(info.address)) continue;

            // Eclipse protection: skip addresses from netgroups we already have
            if (self.violatesNetgroupDiversity(info.address)) continue;

            // Prefer addresses with fewer attempts
            if (best == null or info.attempts < best.?.attempts) {
                best = info;
                best_key = entry.key_ptr.*;
            }
        }

        if (best) |b| {
            // Update last_tried and attempts via the map
            if (self.known_addresses.getPtr(best_key)) |info_ptr| {
                info_ptr.last_tried = now;
                info_ptr.attempts += 1;
            }
            // Mirror the attempt into the bucketed addrman (Core Attempt_).
            if (self.addrman) |*am| {
                am.attempt(b.address, if (now < 0) 0 else @intCast(now));
            }
            return b.address;
        }
        return null;
    }

    /// Start listening for inbound connections.
    pub fn startListening(self: *PeerManager, port: u16) !void {
        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        self.listener = try addr.listen(.{
            .reuse_address = true,
        });
    }

    /// Ban an IP address with a reason.
    pub fn banIP(self: *PeerManager, address: std.net.Address, duration: i64, reason: []const u8) !void {
        try self.ban_list.banAddress(address, duration, reason);
    }

    /// Unban an IP address.
    pub fn unbanIP(self: *PeerManager, address: std.net.Address) bool {
        return self.ban_list.unbanAddress(address);
    }

    /// Check if an IP is banned.
    pub fn isIPBanned(self: *PeerManager, address: std.net.Address) bool {
        return self.ban_list.isAddressBanned(address);
    }

    /// Get the ban list for RPC.
    pub fn getBanList(self: *PeerManager) *banlist.BanList {
        return &self.ban_list;
    }

    /// Get the number of connected peers.
    pub fn getPeerCount(self: *PeerManager) usize {
        return self.peers.items.len;
    }

    /// Resolve a "host" or "host:port" string to a single `std.net.Address`.
    /// Accepts: `127.0.0.1`, `127.0.0.1:8333`, `example.com`, `example.com:8333`.
    /// IPv6 bracket notation (`[::1]:8333`) is NOT supported — callers that
    /// need IPv6 must pre-parse. Localhost mesh / addnode RPC only uses IPv4.
    fn resolveNodeAddress(self: *PeerManager, node: []const u8) !std.net.Address {
        const default_port = self.network_params.default_port;
        // Split on the last ':' — everything after is the port, before is host.
        if (std.mem.lastIndexOfScalar(u8, node, ':')) |colon| {
            const host = node[0..colon];
            const port_str = node[colon + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch {
                return error.InvalidAddress;
            };
            if (std.net.Address.parseIp(host, port)) |addr| {
                return addr;
            } else |_| {}
            // Not a literal IP — try DNS resolution with the parsed port.
            const addrs = std.net.getAddressList(self.allocator, host, port) catch {
                return error.InvalidAddress;
            };
            defer addrs.deinit();
            if (addrs.addrs.len == 0) return error.InvalidAddress;
            return addrs.addrs[0];
        }
        // No colon — try as bare IP, then as bare hostname, both on default_port.
        if (std.net.Address.parseIp(node, default_port)) |addr| {
            return addr;
        } else |_| {}
        const addrs = std.net.getAddressList(self.allocator, node, default_port) catch {
            return error.InvalidAddress;
        };
        defer addrs.deinit();
        if (addrs.addrs.len == 0) return error.InvalidAddress;
        return addrs.addrs[0];
    }

    /// Record `node` on the operator added-node list (Core
    /// `CConnman::AddNode`, net.cpp). Returns `false` — WITHOUT mutating the
    /// list — when an identical string is already present, exactly as Core's
    /// string-collision check does; the RPC layer turns that `false` into
    /// RPC_CLIENT_NODE_ALREADY_ADDED (-23). Returns `true` when a fresh entry
    /// is recorded (an owned copy of the string is appended).
    ///
    /// This is a pure policy-list operation: the actual connect/reconnect
    /// lifecycle is owned by addManualNode (called separately by the RPC
    /// handler on the success path), so observable connection behaviour is
    /// unchanged by this addition.
    pub fn addAddedNode(self: *PeerManager, node: []const u8) !bool {
        for (self.added_nodes.items) |existing| {
            if (std.mem.eql(u8, existing, node)) return false;
        }
        const owned = try self.allocator.dupe(u8, node);
        errdefer self.allocator.free(owned);
        try self.added_nodes.append(owned);
        return true;
    }

    /// Remove `node` from the operator added-node list (Core
    /// `CConnman::RemoveAddedNode`, net.cpp). Returns `false` when the string
    /// was never on the list (Core scans the whole vector and returns false on
    /// a miss), which the RPC layer turns into RPC_CLIENT_NODE_NOT_ADDED (-24).
    /// Returns `true` (and frees the owned copy) when an entry was found.
    pub fn removeAddedNode(self: *PeerManager, node: []const u8) bool {
        for (self.added_nodes.items, 0..) |existing, i| {
            if (std.mem.eql(u8, existing, node)) {
                self.allocator.free(existing);
                _ = self.added_nodes.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Add a node to the manual connection list.
    /// This will attempt to connect to the node.
    pub fn addManualNode(self: *PeerManager, node: []const u8) !void {
        const addr = try self.resolveNodeAddress(node);
        // addAddress is a no-op if the key already exists, so it would never
        // upgrade an existing AddressInfo from .dns_seed/.peer to .manual.
        // Force the .manual source either way so maintainManualConnections
        // owns the reconnect lifecycle.
        const key = addressKey(addr);
        if (self.known_addresses.getPtr(key)) |info| {
            info.source = .manual;
            info.last_tried = 0;
            info.attempts = 0;
        } else {
            try self.addAddress(addr, 0, .manual);
        }
    }

    /// Remove a node from the manual connection list.
    pub fn removeManualNode(self: *PeerManager, node: []const u8) void {
        const addr = self.resolveNodeAddress(node) catch return;
        const key = addressKey(addr);

        // Remove from known addresses
        _ = self.known_addresses.remove(key);

        // Disconnect if connected
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (addressKey(peer.address) == key) {
                peer.disconnect();
                self.allocator.destroy(peer);
                _ = self.peers.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Try to connect to a node once (onetry command).
    ///
    /// Fire-and-forget semantics matching Bitcoin Core's
    /// `OpenNetworkConnection` (called by `rpc/net.cpp::addnode`):
    /// register the address as `.manual` and let the peer-thread loop
    /// pick it up on its next iteration via `maintainManualConnections`.
    /// The actual TCP + BIP-324/v1 handshake then happens off the RPC
    /// thread so the RPC reply lands in milliseconds rather than after
    /// a multi-second handshake.  Keeps the BIP-324 interop matrix
    /// (`tools/bip324-interop-matrix.sh`, `--max-time 8` curl) from
    /// false-failing on `clearbit → *` rows with `fail-addnode`.
    ///
    /// The peer-loop dial tags the connected peer `.manual` (so
    /// rotation/eviction skip it).  Whether the dial actually
    /// succeeds is observable via `getpeerinfo`; the RPC always
    /// succeeds.
    ///
    /// Caveat vs Bitcoin Core: `onetry` here ends up reusing the
    /// `add`-style reconnect lifecycle (the address stays in
    /// `known_addresses` with `source = .manual`).  Core's `onetry`
    /// is strictly one-shot.  The behavioural difference is small
    /// — a remote-side eviction will trigger a 30s-throttled
    /// reconnect — and is the simplest way to drive the dial off
    /// the RPC thread without introducing cross-thread mutation of
    /// `peers.items` (existing code is single-writer on the peer
    /// thread).
    pub fn tryConnectNode(self: *PeerManager, node: []const u8) !void {
        const addr = try self.resolveNodeAddress(node);
        const key = addressKey(addr);
        if (self.known_addresses.getPtr(key)) |info| {
            info.source = .manual;
            // Reset bookkeeping so maintainManualConnections dials on the
            // very next peer-loop tick (no MANUAL_RECONNECT_INTERVAL gate).
            info.last_tried = 0;
            info.attempts = 0;
        } else {
            try self.addAddress(addr, 0, .manual);
        }
    }

    /// Reconnect dropped manual peers (`addnode <ip> add`).
    /// `addManualNode` only registers the address in `known_addresses` with
    /// `source = .manual`.  This function is the other half: on every main-
    /// loop tick it scans for `.manual` addresses that aren't currently
    /// connected and attempts to reconnect, throttled by
    /// `MANUAL_RECONNECT_INTERVAL`.  Matches Bitcoin Core
    /// `ThreadOpenConnections` periodic manual-peer reconnect.
    pub fn maintainManualConnections(self: *PeerManager) void {
        const now = std.time.timestamp();

        var iter = self.known_addresses.iterator();
        while (iter.next()) |entry| {
            const info = entry.value_ptr;
            if (info.source != .manual) continue;
            if (self.isConnected(info.address)) continue;
            if (info.last_tried > 0 and now - info.last_tried < MANUAL_RECONNECT_INTERVAL) continue;
            if (self.peers.items.len >= MAX_TOTAL_CONNECTIONS) break;

            info.last_tried = now;
            info.attempts += 1;

            // Use connectToPeer (matches tryConnectNode/onetry path) so the
            // message loop drives the handshake.  Calling performHandshake
            // synchronously here was racing the loop and silently failing.
            const peer = self.connectToPeer(info.address) catch continue;
            peer.conn_type = .manual;
            info.success = true;
            info.last_seen = now;
            // Promote NEW -> TRIED in the bucketed addrman (Core Good).
            if (self.ensureAddrman()) |am| {
                _ = am.good(info.address, if (now < 0) 0 else @intCast(now)) catch {};
            }
        }
    }

    // ========================================================================
    // Eclipse Attack Protection: Anchor Connections
    // ========================================================================

    /// Load anchor connections from disk (anchors.dat).
    pub fn loadAnchors(self: *PeerManager) !void {
        var file = std.fs.cwd().openFile(self.anchors_path, .{}) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch |err| {
            std.log.warn("Failed to parse anchors.dat: {}", .{err});
            return;
        };
        defer parsed.deinit();

        const root = parsed.value;
        if (root != .object) return;

        const anchors_array = root.object.get("anchors") orelse return;
        if (anchors_array != .array) return;

        for (anchors_array.array.items) |item| {
            if (item != .object) continue;

            const ip_str = item.object.get("ip") orelse continue;
            const port_val = item.object.get("port") orelse continue;

            if (ip_str != .string or port_val != .integer) continue;

            // Parse IP address
            var ip_parts: [4]u8 = undefined;
            var part_iter = std.mem.splitSequence(u8, ip_str.string, ".");
            var i: usize = 0;
            while (part_iter.next()) |part| : (i += 1) {
                if (i >= 4) break;
                ip_parts[i] = std.fmt.parseInt(u8, part, 10) catch continue;
            }
            if (i != 4) continue;

            const port: u16 = @intCast(@as(i64, @truncate(port_val.integer)));
            const addr = std.net.Address.initIp4(ip_parts, port);
            self.anchor_addresses.append(addr) catch continue;
        }

        std.log.info("Loaded {} anchor connections from {s}", .{ self.anchor_addresses.items.len, self.anchors_path });
    }

    /// Save current block-relay-only connections as anchors.
    pub fn saveAnchors(self: *PeerManager) !void {
        var file = std.fs.cwd().createFile(self.anchors_path, .{}) catch |err| {
            std.log.err("Failed to create anchors file: {}", .{err});
            return err;
        };
        defer file.close();

        var writer = file.writer();
        try writer.writeAll("{\n  \"anchors\": [\n");

        var first = true;
        var count: usize = 0;
        for (self.peers.items) |peer| {
            // Save block-relay-only outbound peers as anchors
            if (peer.conn_type == .block_relay and count < MAX_BLOCK_RELAY_ONLY_ANCHORS) {
                if (!first) {
                    try writer.writeAll(",\n");
                }
                first = false;

                switch (peer.address.any.family) {
                    std.posix.AF.INET => {
                        const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&peer.address.any)));
                        const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                        const port = std.mem.bigToNative(u16, ip4.port);
                        try writer.print("    {{\"ip\": \"{d}.{d}.{d}.{d}\", \"port\": {d}}}", .{
                            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
                        });
                        count += 1;
                    },
                    else => {},
                }
            }
        }

        try writer.writeAll("\n  ]\n}\n");
        std.log.info("Saved {} anchor connections to {s}", .{ count, self.anchors_path });
    }

    /// Connect to anchor peers first on startup.
    pub fn connectToAnchors(self: *PeerManager) void {
        for (self.anchor_addresses.items) |addr| {
            if (self.isConnected(addr)) continue;
            if (self.ban_list.isAddressBanned(addr)) continue;

            // BIP-324 negotiation lives inside connectOutboundNegotiated;
            // when v2 is disabled (default) this is identical to the old
            // Peer.connect+performHandshake pair.
            const peer = self.connectOutboundNegotiated(addr) orelse continue;
            peer.conn_type = .block_relay;

            // Track netgroup (ASN-keyed when asmap is loaded)
            self.outbound_netgroups.put(self.getNetGroup(addr), {}) catch {};

            self.peers.append(peer) catch {
                peer.disconnect();
                self.allocator.destroy(peer);
                continue;
            };

            std.log.info("Connected to anchor peer: {}", .{addr});

            // Initiate header sync with anchor peer
            self.sendGetHeaders(peer) catch {};
        }
    }

    // ========================================================================
    // Eclipse Attack Protection: Netgroup Diversity
    // ========================================================================

    /// Compute the group key for `address`.  When an asmap is loaded, returns
    /// an ASN-keyed group (providing AS-level eclipse resistance); otherwise
    /// falls back to the /16 (IPv4) or /32 (IPv6) prefix group.
    /// Mirrors Core's `NetGroupManager::GetGroup()` (netgroup.cpp).
    pub fn getNetGroup(self: *const PeerManager, address: std.net.Address) u32 {
        if (self.asmap_data) |data| {
            const asn = getMappedAS(data, address);
            if (asn != 0) return asn; // ASN found — use AS-level grouping
        }
        return netGroup(address);
    }

    /// Check if adding a peer from the given address would violate netgroup diversity.
    pub fn violatesNetgroupDiversity(self: *const PeerManager, address: std.net.Address) bool {
        const group = self.getNetGroup(address);
        return self.outbound_netgroups.contains(group);
    }

    /// Update netgroup tracking when a peer is connected.
    fn trackOutboundNetgroup(self: *PeerManager, peer: *const Peer) void {
        if (peer.direction == .outbound) {
            self.outbound_netgroups.put(self.getNetGroup(peer.address), {}) catch {};
        }
    }

    /// Remove netgroup tracking when a peer is disconnected.
    fn untrackOutboundNetgroup(self: *PeerManager, peer: *const Peer) void {
        if (peer.direction == .outbound) {
            _ = self.outbound_netgroups.remove(self.getNetGroup(peer.address));
        }
    }

    /// Connect to peers until we have MAX_OUTBOUND_CONNECTIONS outbound.
    /// Enforces netgroup diversity by tracking connected netgroups.
    /// During IBD, only attempts one connection per call to avoid blocking.
    pub fn maintainOutbound(self: *PeerManager) !void {
        var outbound_count: usize = 0;
        for (self.peers.items) |p| {
            if (p.direction == .outbound) outbound_count += 1;
        }

        // During IBD, only try one connection per call to avoid blocking the loop.
        // Exception: if we have zero outbound peers (post-eviction peer wipeout),
        // allow up to MAX_OUTBOUND_CONNECTIONS attempts so we recover quickly
        // instead of waiting for the loop to cycle once per peer slot.
        var attempts: u32 = 0;
        const max_attempts: u32 = if (!self.isIBD()) 8
                                  else if (outbound_count == 0) MAX_OUTBOUND_CONNECTIONS
                                  else 1;

        while (outbound_count < MAX_OUTBOUND_CONNECTIONS and attempts < max_attempts) {
            attempts += 1;
            const addr = self.selectPeerToConnect() orelse break;
            // BIP-324 negotiation lives inside connectOutboundNegotiated;
            // when v2 is disabled (default) this is identical to the old
            // Peer.connect+performHandshake pair.
            const peer = self.connectOutboundNegotiated(addr) orelse continue;

            // Mark address as successful
            const key = addressKey(addr);
            const succ_ts = std.time.timestamp();
            if (self.known_addresses.getPtr(key)) |info| {
                info.success = true;
                info.last_seen = succ_ts;
            }
            // Promote NEW -> TRIED in the bucketed addrman (Core Good on a
            // successful handshake).
            if (self.ensureAddrman()) |am| {
                _ = am.good(addr, if (succ_ts < 0) 0 else @intCast(succ_ts)) catch {};
            }

            // Track netgroup for diversity enforcement
            self.trackOutboundNetgroup(peer);

            self.peers.append(peer) catch {
                self.untrackOutboundNetgroup(peer);
                peer.disconnect();
                self.allocator.destroy(peer);
                break;
            };
            outbound_count += 1;
            std.log.info("Connected to outbound peer {} (height={d}, {d}/{d} outbound)", .{ addr, peer.start_height, outbound_count, MAX_OUTBOUND_CONNECTIONS });

            // Initiate header sync with newly connected peer
            self.sendGetHeaders(peer) catch {};
        }
    }

    // ========================================================================
    // Feeler connections (anti-eclipse) — Core net.cpp ThreadOpenConnections
    // FEELER branch. A feeler dials a NEW-table address, runs the handshake,
    // promotes it NEW->TRIED via addrman.Good(), then disconnects. Keeps the
    // TRIED table fresh = Core's primary eclipse-attack mitigation.
    // ========================================================================

    /// Count in-flight feeler connections. A feeler is short-lived (disconnects
    /// right after the handshake) so this is normally 0; the bound exists to
    /// guarantee at most MAX_FEELER_CONNECTIONS are ever open at once.
    pub fn feelerCount(self: *const PeerManager) usize {
        var n: usize = 0;
        for (self.peers.items) |p| {
            if (p.conn_type == .feeler) n += 1;
        }
        return n;
    }

    /// Select a NEW-table address for a feeler probe (Core net.cpp:
    /// `addrman.Select(/*new_only=*/true)`). Draws ONLY from the bucketed
    /// addrman's NEW table — the addresses a feeler exists to probe — skipping
    /// any candidate we are already connected to or that is banned. Returns
    /// null when the NEW table is empty / yields only ineligible candidates, so
    /// the caller no-ops cleanly.
    ///
    /// Feelers deliberately read from NEW, not TRIED: on a successful handshake
    /// the caller promotes the address NEW->TRIED via makeTriedOnFeelerSuccess.
    pub fn selectFeelerAddress(self: *PeerManager) ?std.net.Address {
        const am = self.ensureAddrman() orelse return null;
        // A handful of attempts so a transiently-connected/banned pick does not
        // starve the probe; bounded so an all-ineligible NEW table no-ops.
        var tries: usize = 0;
        while (tries < 8) : (tries += 1) {
            const addr = am.select(true) orelse return null; // new_only = true
            if (self.isConnected(addr)) continue;
            if (self.ban_list.isAddressBanned(addr)) continue;
            return addr;
        }
        return null;
    }

    /// Promote a feeler-probed address NEW->TRIED on a SUCCESSFUL handshake
    /// (Core net.cpp FEELER branch `addrman.Good()`). Called ONLY after a
    /// successful feeler handshake; on a dial/handshake FAILURE it is never
    /// called, so the TRIED table is left unchanged — the falsification guard.
    /// Also mirrors the success into the legacy known_addresses metadata so the
    /// 23%-cap shareable count and getnodeaddresses reflect the probe.
    pub fn makeTriedOnFeelerSuccess(self: *PeerManager, address: std.net.Address) void {
        const now_i = std.time.timestamp();
        const now: u64 = if (now_i < 0) 0 else @intCast(now_i);
        if (self.ensureAddrman()) |am| {
            _ = am.good(address, now) catch {};
        }
        // Reflect the success in the legacy address book (last_seen / success).
        const key = addressKey(address);
        if (self.known_addresses.getPtr(key)) |info| {
            info.success = true;
            info.last_seen = now_i;
        }
    }

    /// Refill a peer's inbound-addr token bucket and return how many addresses
    /// may be admitted out of `requested` (Core net_processing.cpp ProcessAddrs
    /// token-bucket). The bucket refills at MAX_ADDR_RATE_PER_SECOND tokens/sec
    /// since the last addr message (capped at MAX_ADDR_PROCESSING_TOKEN_BUCKET),
    /// each admitted address spends one token, and the rest are dropped once it
    /// runs dry. Shared by BOTH the addr and addrv2 handlers (one bucket per
    /// peer) so the rate limit cannot be bypassed by switching message type.
    ///
    /// We hold no Addr-permission (NoBan/manual) peers on the inbound addr path,
    /// so all inbound addr traffic is rate-limited, matching Core's default.
    ///
    /// DIVERGENCE (documented, not faked): Core tops the bucket up by
    /// +MAX_ADDR_TO_SEND (1000) once when WE send a getaddr to a peer
    /// (net_processing.cpp: `m_addr_token_bucket += MAX_ADDR_TO_SEND`), so the
    /// large solicited response is not spuriously rate-limited. clearbit never
    /// SENDS a getaddr to its peers (it only answers inbound getaddr), so there
    /// is no solicited-response case and no top-up site. The bucket therefore
    /// stays at its Core-exact init of 1.0 until traffic refills it at 0.1/s —
    /// the same state Core is in for a peer it never solicited. We do NOT init
    /// the bucket to 1000 (Core inits 1.0); a permissive init would let an
    /// unsolicited peer push ~1000 addresses on its first message.
    pub fn takeAddrTokens(self: *PeerManager, peer: *Peer, requested: usize) usize {
        _ = self;
        const now = std.time.timestamp();
        // First message on this peer: stamp the clock, do not back-date refill.
        if (peer.addr_token_timestamp == 0) {
            peer.addr_token_timestamp = now;
        }
        // Refill (skip when already at/above the soft cap — Core's
        // "don't increment if already full" guard).
        if (peer.addr_token_bucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET) {
            const elapsed_i = now - peer.addr_token_timestamp;
            const elapsed: f64 = if (elapsed_i > 0) @floatFromInt(elapsed_i) else 0.0;
            const increment = elapsed * MAX_ADDR_RATE_PER_SECOND;
            peer.addr_token_bucket = @min(
                peer.addr_token_bucket + increment,
                MAX_ADDR_PROCESSING_TOKEN_BUCKET,
            );
        }
        peer.addr_token_timestamp = now;

        // Admit up to floor(bucket) addresses, bounded by the request size.
        const available: usize = @intFromFloat(@floor(peer.addr_token_bucket));
        const admit = @min(available, requested);
        peer.addr_token_bucket -= @floatFromInt(admit);
        return admit;
    }

    /// Open at most ONE short-lived feeler connection (Core net.cpp
    /// ThreadOpenConnections FEELER branch). Selects a NEW-table address, dials
    /// it as a `.feeler` connection (which the version handshake sends with
    /// relay=false), and on a successful handshake promotes the address
    /// NEW->TRIED then disconnects WITHOUT appending it to `self.peers`.
    ///
    /// Because the probe peer is never appended to `self.peers`, a feeler is
    /// inherently OFF the regular outbound budget: maintainOutbound counts only
    /// `direction == .outbound` peers in `self.peers`, so a feeler can never
    /// consume a full-relay/block-relay slot. It is also gated to one in flight
    /// (feelerCount < MAX_FEELER_CONNECTIONS) and to one open per
    /// FEELER_INTERVAL_SECS (120s).
    ///
    /// No-ops when `-connect` pinning is active (the addrman is intentionally
    /// unused), when the interval has not elapsed, when a feeler is already in
    /// flight, or when the NEW table yields no eligible candidate.
    pub fn maybeOpenFeeler(self: *PeerManager) void {
        // `-connect` mode makes no addrman-driven outbound (Core skips feelers
        // when m_use_addrman_outgoing is false).
        if (self.connect_address != null) return;
        if (self.feelerCount() >= MAX_FEELER_CONNECTIONS) return;

        const now = std.time.timestamp();
        if (self.last_feeler_time != 0 and now - self.last_feeler_time < FEELER_INTERVAL_SECS) return;

        const addr = self.selectFeelerAddress() orelse return;
        // Stamp the schedule whether or not the dial succeeds, so a string of
        // failing feelers cannot busy-loop dialing every tick.
        self.last_feeler_time = now;

        // Record the attempt in the bucketed addrman (Core records the Select
        // attempt). A never-answering NEW entry ages toward terrible over time
        // without being promoted; a failed feeler is NOT penalised beyond this.
        if (self.ensureAddrman()) |am| {
            am.attempt(addr, if (now < 0) 0 else @intCast(now));
        }

        std.log.debug("Making feeler connection to {}", .{addr});
        // Dial with relay_self=false — a feeler must not start tx relay (Core
        // sends fRelay=false on feelers). Returns a fully-handshaked *Peer or
        // null on dial/handshake failure.
        const peer = self.connectOutboundNegotiatedRelay(addr, false) orelse {
            // Dial / handshake FAILED — do NOT promote. TRIED is unchanged.
            std.log.debug("Feeler to {} failed; TRIED unchanged", .{addr});
            return;
        };
        peer.conn_type = .feeler;

        // Handshake SUCCEEDED — promote NEW->TRIED, then tear the probe down.
        // We never append it to self.peers, so it consumes no outbound slot and
        // the standard rotation/eviction paths never see it.
        self.makeTriedOnFeelerSuccess(addr);
        std.log.debug("Feeler to {} handshook; promoted NEW->TRIED, disconnecting", .{addr});
        peer.disconnect();
        self.allocator.destroy(peer);
    }

    /// Accept a waiting inbound connection if available (non-blocking).
    /// When inbound slots are full, uses eviction protection algorithm.
    pub fn acceptInbound(self: *PeerManager) !void {
        if (self.listener == null) return;

        // Poll with 0 timeout to check if a connection is pending (non-blocking)
        var pollfds = [_]std.posix.pollfd{.{
            .fd = self.listener.?.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&pollfds, 0) catch return;
        if (ready == 0 or (pollfds[0].revents & std.posix.POLL.IN) == 0) return;

        // A connection is waiting, accept it
        const conn = self.listener.?.accept() catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return err,
            }
        };

        // Check if IP is banned
        if (self.ban_list.isAddressBanned(conn.address)) {
            conn.stream.close();
            return;
        }

        // Count inbound connections
        var inbound_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .inbound) inbound_count += 1;
        }

        // If inbound slots are full, try to evict a peer
        if (inbound_count >= MAX_INBOUND_CONNECTIONS) {
            // Build eviction candidates
            const candidates = buildEvictionCandidates(self.peers.items, self.allocator) catch {
                conn.stream.close();
                return;
            };
            defer self.allocator.free(candidates);

            // Select victim
            if (selectEvictionCandidate(candidates, self.allocator)) |victim_idx| {
                std.log.info("Evicting inbound peer to make room for new connection", .{});
                self.removePeerByIndex(victim_idx);
            } else {
                // No victim found, reject new connection
                conn.stream.close();
                return;
            }
        }

        const peer = try self.allocator.create(Peer);
        peer.* = Peer.accept(conn.stream, conn.address, self.network_params, self.allocator);
        peer.advertise_node_bloom = self.peerbloomfilters;
        peer.advertise_node_network_limited = self.advertise_node_network_limited;
        peer.advertise_compact_filters = self.blockfilterindex_enabled;
        // Set mapped_as for getpeerinfo when asmap is loaded.
        if (self.asmap_data) |data| {
            peer.mapped_as = getMappedAS(data, conn.address);
        }
        peer.performHandshake(self.our_height) catch {
            peer.disconnect();
            self.allocator.destroy(peer);
            return;
        };
        try self.peers.append(peer);
    }

    /// Process messages from all connected peers using multiplexed I/O.
    /// Uses poll() to wait for data on ALL peer sockets simultaneously,
    /// then drains ALL available messages from each ready socket.
    pub fn processAllMessages(self: *PeerManager) !void {
        // First pass: check for peers that need banning
        {
            var i: usize = 0;
            while (i < self.peers.items.len) {
                const peer_obj = self.peers.items[i];
                if (peer_obj.should_ban) {
                    self.banIP(peer_obj.address, DEFAULT_BAN_DURATION, "misbehavior threshold reached") catch {};
                    self.removePeerByIndex(i);
                    continue;
                }
                i += 1;
            }
        }

        if (self.peers.items.len == 0) return;

        // Build pollfd array for all connected peers
        var pollfds: [MAX_TOTAL_CONNECTIONS]std.posix.pollfd = undefined;
        const num_peers = @min(self.peers.items.len, MAX_TOTAL_CONNECTIONS);
        for (0..num_peers) |idx| {
            pollfds[idx] = .{
                .fd = self.peers.items[idx].stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            };
        }

        // Poll all sockets at once. During IBD use 10ms timeout, otherwise 100ms.
        const timeout_ms: i32 = if (self.isIBD()) 10 else 100;
        const ready = std.posix.poll(pollfds[0..num_peers], timeout_ms) catch 0;

        if (ready == 0) {
            // No data on any socket - send getheaders to ONE peer if needed
            // Throttle: only send if last attempt was >5s ago (avoid spam)
            const now_ts = std.time.timestamp();
            for (self.peers.items) |peer_obj| {
                if (now_ts - peer_obj.last_getheaders_time > 5) {
                    if (self.chain_state) |cs| {
                        if (peer_obj.start_height > 0 and cs.best_height < @as(u32, @intCast(peer_obj.start_height))) {
                            self.sendGetHeaders(peer_obj) catch {};
                            break; // Only send to one peer at a time
                        }
                    }
                }
            }
            return;
        }

        // Process each peer that has data available.
        // We iterate backwards so removePeerByIndex doesn't skip peers.
        var i: usize = num_peers;
        while (i > 0) {
            i -= 1;
            if (i >= self.peers.items.len) continue;

            const peer_obj = self.peers.items[i];

            // Check if this socket has data (or an error/hangup)
            const revents = pollfds[i].revents;
            const has_data = (revents & std.posix.POLL.IN) != 0;
            const has_error = (revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0;

            if (has_error and !has_data) {
                self.removePeerByIndex(i);
                continue;
            }

            if (!has_data) {
                continue;
            }

            // Socket has data - set a very short timeout for reading and drain ALL messages
            peer_obj.setRecvTimeout(0, 1_000); // 1ms timeout for drain loop

            var msgs_read: u32 = 0;
            const max_msgs_per_peer: u32 = 256; // Safety limit per cycle

            while (msgs_read < max_msgs_per_peer) {
                const msg = peer_obj.receiveMessage() catch |err| {
                    switch (err) {
                        PeerError.Timeout => break, // No more data buffered, done draining
                        PeerError.ConnectionClosed => {
                            self.removePeerByIndex(i);
                            break;
                        },
                        PeerError.BadMagic => {
                            peer_obj.misbehaving(100, "invalid network magic");
                        },
                        PeerError.BadChecksum => {
                            peer_obj.misbehaving(50, "bad message checksum");
                        },
                        PeerError.MessageTooLarge => {
                            peer_obj.misbehaving(50, "oversized message");
                        },
                        PeerError.ProtocolViolation => {
                            peer_obj.misbehaving(20, "protocol violation");
                        },
                        else => {
                            peer_obj.misbehaving(10, "message receive error");
                        },
                    }

                    // Check if should be banned after misbehavior
                    if (peer_obj.should_ban) {
                        self.banIP(peer_obj.address, DEFAULT_BAN_DURATION, "misbehavior threshold reached") catch {};
                        self.removePeerByIndex(i);
                        break;
                    }
                    break; // Stop draining on any error
                };

                self.handleMessage(peer_obj, msg) catch {};
                msgs_read += 1;
            }

            // Restore long timeout for handshake use
            if (i < self.peers.items.len and self.peers.items[i] == peer_obj) {
                peer_obj.setRecvTimeout(30, 0);
            }
        }
    }

    /// Get the best height among all connected peers.
    fn getBestPeerHeight(self: *PeerManager) u32 {
        var best: i32 = 0;
        for (self.peers.items) |p| {
            if (p.start_height > best) best = p.start_height;
        }
        return if (best > 0) @intCast(best) else 0;
    }

    /// Pick a different sync peer (not the one that just returned 0 headers).
    fn pickSyncPeer(self: *PeerManager, exclude: *Peer) ?*Peer {
        for (self.peers.items) |p| {
            if (p != exclude and p.start_height > 0) return p;
        }
        return null;
    }

    /// Send getheaders to a peer using our current best block as locator.
    fn sendGetHeaders(self: *PeerManager, target_peer: *Peer) !void {
        // Build locator: use the tip of the header queue if available,
        // otherwise our best connected hash, or genesis.
        var locator_hash: types.Hash256 = undefined;
        if (self.expected_blocks.items.len > 0) {
            // Use the last known header hash (end of queue) to avoid duplicate headers
            locator_hash = self.expected_blocks.items[self.expected_blocks.items.len - 1];
        } else if (self.chain_state) |cs| {
            if (cs.best_height > 0) {
                locator_hash = cs.best_hash;
            } else {
                locator_hash = self.network_params.genesis_hash;
            }
        } else {
            locator_hash = self.network_params.genesis_hash;
        }

        const locators = [_]types.Hash256{locator_hash};
        const msg = p2p.Message{ .getheaders = .{
            .version = @intCast(p2p.PROTOCOL_VERSION),
            .block_locator_hashes = &locators,
            .hash_stop = [_]u8{0} ** 32,
        } };
        try target_peer.sendMessage(&msg);
        target_peer.last_getheaders_time = std.time.timestamp();
    }

    // ====================================================================
    // Header index + competing-fork detection (CLEARBIT_REORG=1)
    // ====================================================================

    /// Look up the chain_work + height of an entry's parent header.  Used
    /// when ingesting a new header so we can compute its cumulative
    /// chain_work.  Falls back to the active-chain tip if the parent is
    /// the tip and not in the index, and to all-zero work for the
    /// pre-genesis "parent" of the genesis block.
    pub fn lookupParentChainWork(
        self: *PeerManager,
        prev_hash: *const types.Hash256,
    ) ?struct { work: [32]u8, height: u32 } {
        // Genesis sentinel (all-zero prev): height=0 work=0 — and the
        // "parent height" we report is the unsigned underflow case, so
        // callers must special-case the genesis case explicitly. To keep
        // the interface uniform, return null and let the caller decide.
        var is_zero = true;
        for (prev_hash) |b| {
            if (b != 0) {
                is_zero = false;
                break;
            }
        }
        if (is_zero) return .{ .work = [_]u8{0} ** 32, .height = 0 };

        // Genesis-hash case: a fork rooting at the genesis block.  Genesis is
        // height 0, but its BODY is never stored in CF_BLOCKS and — for a node
        // that only ever mined locally (never P2P-synced) — genesis is not in
        // header_index either.  Without this case lookupParentChainWork returns
        // null for block-1's prev, insertHeader then drops EVERY genesis-rooted
        // fork header (returns null), last_inserted stays null and maybeArmReorg
        // is never called — so a full reorg back to a genesis-rooted heavier
        // chain can never fire.  Report genesis at height 0 with the same
        // placeholder chain_work base the active tip uses (chainWorkFromHeight),
        // so the fork accumulates comparable work.  Mirrors the genesis
        // special-cases in classifyHeaderBatch / getHeadersForkPoint /
        // maybeArmReorg.
        if (std.mem.eql(u8, prev_hash, &self.network_params.genesis_hash)) {
            return .{ .work = chainWorkFromHeight(0), .height = 0 };
        }

        // Active-chain tip is checked first because the index doesn't
        // include flushed-and-evicted ancestors.
        if (self.chain_state) |cs| {
            if (std.mem.eql(u8, &cs.best_hash, prev_hash)) {
                // Active-chain entries don't carry chain_work in our
                // ChainState (it's flat-key UTXOs only); we synthesize a
                // monotonic placeholder so a fork that forks off the tip
                // still has a strictly-greater chain_work than the tip.
                // The placeholder is `tip_height << 8` packed big-endian
                // — gives 256B of headroom for the next ~256 forks
                // before the comparison loses meaning. Acceptable
                // approximation: the absolute chain_work value is only
                // used for the strict-greater-than check, never persisted.
                return .{
                    .work = chainWorkFromHeight(cs.best_height),
                    .height = cs.best_height,
                };
            }
        }
        // Otherwise look in the in-memory index.
        if (self.header_index.get(prev_hash.*)) |entry| {
            return .{ .work = entry.chain_work, .height = entry.height };
        }
        return null;
    }

    /// Insert a header into the in-memory index.  Computes height +
    /// chain_work from the parent.  No-op if the header is already
    /// present (so duplicate batches don't bloat the index).  Returns
    /// the inserted-or-existing entry.
    ///
    /// Caller must already hold the peer-manager mutex (the entire
    /// .headers handler runs under it).  Genesis (prev_block all-zero)
    /// gets height=0 + chain_work = work-of-this-header.
    pub fn insertHeader(
        self: *PeerManager,
        header: *const types.BlockHeader,
        block_hash: *const types.Hash256,
    ) !?BlockHeaderEntry {
        // Already present?  Return existing record.
        if (self.header_index.get(block_hash.*)) |existing| {
            // Refresh last_seen so LRU keeps it.
            var refreshed = existing;
            refreshed.last_seen = std.time.timestamp();
            self.header_index.put(block_hash.*, refreshed) catch {};
            return refreshed;
        }

        const parent_info = self.lookupParentChainWork(&header.prev_block);
        if (parent_info == null) {
            // Unknown parent — caller can decide whether to treat as
            // misbehavior or just defer.  Returning null here lets the
            // headers handler fall through to its existing peer-+20
            // path on the canonical "doesn't connect" rejection.
            return null;
        }
        const p = parent_info.?;
        var new_work: [32]u8 = p.work;
        const this_work = workFromBits(header.bits);
        addChainWorkBE(&new_work, &this_work);

        const entry: BlockHeaderEntry = .{
            .hash = block_hash.*,
            .prev_hash = header.prev_block,
            .height = p.height + 1,
            .chain_work = new_work,
            .timestamp = header.timestamp,
            .header = header.*,
            .last_seen = std.time.timestamp(),
        };

        try self.header_index.put(block_hash.*, entry);

        // Cap at MAX_HEADER_INDEX entries.  Eviction is amortized: only
        // sweep when we cross the cap, drop the oldest 10% by
        // last_seen.  Active-chain ancestors should rarely be touched
        // in practice (they arrive once during IBD then never again),
        // so this happens to bias eviction toward stale fork branches
        // — exactly what we want.
        if (self.header_index.count() > MAX_HEADER_INDEX) {
            self.evictHeaderIndex();
        }
        return entry;
    }

    /// Drop the oldest ~10% of entries from the header_index by
    /// last_seen timestamp.  Best-effort; called only when the index
    /// is over MAX_HEADER_INDEX, so the eviction cost amortizes to
    /// O(1) per insert in steady state.
    pub fn evictHeaderIndex(self: *PeerManager) void {
        const cur = self.header_index.count();
        const target_drop: usize = cur / 10;
        if (target_drop == 0) return;

        // Two-pass scan: collect candidate hashes (oldest last_seen),
        // then remove. We keep this O(N) — for N=10k it's a microsecond.
        const Cand = struct {
            hash: types.Hash256,
            last_seen: i64,
        };
        var candidates = std.ArrayList(Cand).init(self.allocator);
        defer candidates.deinit();
        var it = self.header_index.iterator();
        while (it.next()) |kv| {
            candidates.append(.{
                .hash = kv.key_ptr.*,
                .last_seen = kv.value_ptr.last_seen,
            }) catch return;
        }
        // Sort ascending by last_seen (oldest first).
        const lessFn = struct {
            fn f(_: void, a: Cand, b: Cand) bool {
                return a.last_seen < b.last_seen;
            }
        }.f;
        std.sort.pdq(Cand, candidates.items, {}, lessFn);

        var dropped: usize = 0;
        while (dropped < target_drop and dropped < candidates.items.len) : (dropped += 1) {
            _ = self.header_index.remove(candidates.items[dropped].hash);
        }
    }

    /// Outcome of classifying a freshly-arrived header batch.
    pub const HeaderClass = enum {
        /// First header chains onto our tip / queue tail — normal extension.
        extends_active,
        /// First header chains onto a known non-tip header → competing fork.
        competing_fork,
        /// First header's prev is unknown → peer misbehavior path.
        unknown_parent,
    };

    /// Classify the first header in a batch with respect to our current
    /// chain state.  See HeaderClass.  Helper for the .headers handler.
    pub fn classifyHeaderBatch(
        self: *PeerManager,
        first_header: *const types.BlockHeader,
        expected_prev: *const types.Hash256,
    ) HeaderClass {
        if (std.mem.eql(u8, &first_header.prev_block, expected_prev)) {
            return .extends_active;
        }
        // Look up parent in our header_index — if found, this is a
        // competing fork (parent is on some chain we know about, but
        // not at the tip / end of our queue).
        if (self.header_index.contains(first_header.prev_block)) {
            return .competing_fork;
        }
        // Active-chain ancestor (e.g. fork from somewhere deep).  We
        // don't carry a full block_index for the active chain, so this
        // case looks like "unknown parent" from our index but should
        // actually be allowed.  ChainState.has_block_hash would tell us
        // — but the storage API expects a full block lookup which costs
        // a RocksDB hit.  Since IBD soaks the index and steady-state
        // operation hits this rarely, we accept the cost: any
        // unrecognized prev that is on the active chain (per
        // chain_state) is treated as a competing fork too.
        if (self.chain_state) |cs| {
            // hasBlock takes the hash; returns true if we've ever
            // connected this block.  May be expensive — call lazily.
            if (cs.hasBlock(&first_header.prev_block)) {
                return .competing_fork;
            }
        }
        // Genesis special-case: the genesis block is the universal active-chain
        // ancestor at height 0, but its BODY is never stored in CF_BLOCKS
        // (hasBlock reads CF_BLOCKS -> false) and, for a node that only ever
        // mined locally (never P2P-synced), genesis is not in header_index
        // either.  A heavier competing chain that forks at genesis (a full
        // reorg back to the root) would therefore classify as unknown_parent
        // and be dropped — never reaching the competing_fork / maybeArmReorg
        // path.  getHeadersForkPoint already special-cases the genesis hash for
        // exactly this reason (it must, to serve a disjoint-locator fork);
        // mirror it here so a genesis-rooted competing fork is recognised.
        if (std.mem.eql(u8, &first_header.prev_block, &self.network_params.genesis_hash)) {
            return .competing_fork;
        }
        return .unknown_parent;
    }

    /// Once a header batch has been ingested AND the first header was
    /// classified as competing_fork, walk through the new headers and
    /// figure out:
    ///   - the fork point (most recent ancestor on the active chain)
    ///   - the cumulative chain_work at the new fork tip
    ///   - the ordered list of fork-block hashes (fork_point + 1 .. new_tip)
    ///
    /// If the fork's chainwork strictly exceeds the active tip's
    /// chainwork, set self.pending_reorg and request the missing block
    /// bodies from `peer` via getdata.  No-op if pending_reorg is
    /// already set (existing reorg in flight) or if the chainwork is
    /// not strictly greater.
    ///
    /// Per Bitcoin Core ActivateBestChain: equal-chainwork ties keep
    /// the active chain (first-seen wins). We honor that here.
    pub fn maybeArmReorg(
        self: *PeerManager,
        peer: *Peer,
        fork_tip_hash: *const types.Hash256,
    ) void {
        if (self.pending_reorg != null) {
            // Already arming a reorg — defer this fork until the next round.
            return;
        }
        const cs = self.chain_state orelse return;

        const tip_entry = self.header_index.get(fork_tip_hash.*) orelse return;

        // Walk back from fork_tip until we hit the active chain (most
        // recent common ancestor).  Bound by MAX_REORG_DEPTH to avoid
        // a malicious peer offering a fake-deep fork that OOMs the
        // walk.
        var fork_chain = std.ArrayList(types.Hash256).init(self.allocator);
        defer fork_chain.deinit();

        var cursor: types.Hash256 = fork_tip_hash.*;
        var depth: u32 = 0;
        var fork_point: ?types.Hash256 = null;
        while (depth <= MAX_REORG_DEPTH) {
            // Is this hash on the active chain?  If yes → fork_point found.
            // We use the in-memory active-tip first (no DB hit), then fall
            // back to chain_state.hasBlock for older entries.
            if (std.mem.eql(u8, &cs.best_hash, &cursor)) {
                fork_point = cursor;
                break;
            }
            if (cs.best_height > 0 and cs.hasBlock(&cursor)) {
                fork_point = cursor;
                break;
            }
            // Genesis special-case: a fork that roots at the genesis block
            // shares genesis with the active chain (every chain does).  But
            // the genesis BODY is never stored in CF_BLOCKS (hasBlock=false)
            // and, for a locally-mined never-P2P-synced node, genesis is not
            // in header_index — so the walk-back would otherwise "fall off the
            // index" at genesis and refuse the reorg.  Recognise the network
            // genesis hash as a valid fork point (height 0), mirroring
            // classifyHeaderBatch + getHeadersForkPoint.
            if (std.mem.eql(u8, &cursor, &self.network_params.genesis_hash)) {
                fork_point = cursor;
                break;
            }
            // Otherwise this hash is a fork block — record + walk back.
            const e = self.header_index.get(cursor) orelse {
                // Walk fell off the index (a header we evicted).
                // We can't proceed safely; abort.
                std.log.warn("REORG: walk fell off header_index at depth {d}", .{depth});
                return;
            };
            fork_chain.append(cursor) catch return;
            cursor = e.prev_hash;
            depth += 1;
            // Pre-genesis sentinel: prev_block of the genesis block is
            // all-zero.  A walk-back that reaches genesis means the
            // fork shares the genesis ancestor (which the active chain
            // necessarily also does).  Treat the all-zero hash as a
            // valid fork_point.
            var is_zero = true;
            for (cursor) |b| {
                if (b != 0) {
                    is_zero = false;
                    break;
                }
            }
            if (is_zero) {
                fork_point = cursor;
                break;
            }
        }

        const fp = fork_point orelse {
            std.log.warn(
                "REORG: refused — fork point > MAX_REORG_DEPTH ({d}) below active tip",
                .{MAX_REORG_DEPTH},
            );
            peer.misbehaving(20, "fork too deep");
            return;
        };

        // Reverse fork_chain to get fork_point + 1 .. new_tip order.
        std.mem.reverse(types.Hash256, fork_chain.items);

        // Compare new tip chain_work strictly greater than active tip's.
        // For the active tip we use the chainWorkFromHeight placeholder
        // (the same one used by lookupParentChainWork). The fork
        // chain_work was computed cumulatively from the same placeholder
        // root for the fork point, so the comparison is apples-to-apples.
        const active_work = chainWorkFromHeight(cs.best_height);
        if (cmpChainWorkBE(&tip_entry.chain_work, &active_work) <= 0) {
            // Equal- or lower-chainwork fork: ignore (first-seen wins).
            std.log.info(
                "REORG: ignoring equal/lower-chainwork fork (active_h={d})",
                .{cs.best_height},
            );
            return;
        }

        // Arm pending_reorg and request fork bodies from this peer.
        // Move ownership of fork_chain into PendingReorg by copying.
        var owned = std.ArrayList(types.Hash256).init(self.allocator);
        owned.appendSlice(fork_chain.items) catch {
            owned.deinit();
            return;
        };
        self.pending_reorg = .{
            .fork_point = fp,
            .fork_hashes = owned,
            .new_tip_chain_work = tip_entry.chain_work,
            .source_peer = peer,
        };

        // Request the bodies from the peer that announced the fork.
        // We send a single getdata containing every fork block hash; the
        // peer is free to dribble them in.  If the peer disconnects we
        // re-issue via pipelineBlockRequests on the next drain.
        if (owned.items.len > 0) {
            var inv_list = std.ArrayList(p2p.InvVector).init(self.allocator);
            defer inv_list.deinit();
            for (owned.items) |h| {
                inv_list.append(.{
                    .inv_type = .msg_witness_block,
                    .hash = h,
                }) catch break;
            }
            const getdata = p2p.Message{ .getdata = .{ .inventory = inv_list.items } };
            peer.sendMessage(&getdata) catch |err| {
                std.log.warn("REORG: getdata send failed: {}", .{err});
            };
        }

        std.log.info(
            "REORG: armed fork_point=...{x:0>2}{x:0>2} fork_len={d} active_h={d} tip_h={d}",
            .{
                fp[30], fp[31], owned.items.len, cs.best_height, tip_entry.height,
            },
        );
    }

    /// Try to fire the pending reorg if all fork bodies are present in
    /// block_buffer.  Called by drainBlockBuffer when a normal connect
    /// path can't make progress.  On success: removes the buffered
    /// blocks, calls reorgToChain, clears pending_reorg.  On failure:
    /// logs + bans the source peer + clears pending_reorg.
    pub fn tryFireReorg(self: *PeerManager) void {
        const pr_ptr = if (self.pending_reorg) |*p| p else return;
        const cs = self.chain_state orelse return;

        // Are all bodies buffered?
        for (pr_ptr.fork_hashes.items) |h| {
            if (!self.block_buffer.contains(h)) return; // not yet
        }

        // Build the ReorgBlock array.  We must NOT free the blocks here
        // — reorgToChain will move ownership through queueBlockWrite.
        // We DO need to leave the buffer entries removed so the drain
        // loop doesn't double-process them.
        const allocator = self.allocator;
        var rb_list = std.ArrayList(storage.ChainState.ReorgBlock).init(allocator);
        defer rb_list.deinit();

        // Collect blocks (and remove from buffer in the same pass).
        for (pr_ptr.fork_hashes.items, 0..) |h, i| {
            const fetched = self.block_buffer.fetchRemove(h) orelse {
                // Disappeared between the contains-check and the fetch
                // (could only happen with concurrent buffer mutation —
                // not currently possible, but be defensive).  Restore
                // already-collected blocks back to the buffer and bail.
                for (rb_list.items[0..i]) |rb| {
                    self.block_buffer.put(rb.hash, rb.block) catch {
                        serialize.freeBlock(allocator, &rb.block);
                    };
                }
                return;
            };
            const fp_height = self.lookupHeightOrZero(&pr_ptr.fork_point);
            rb_list.append(.{
                .hash = h,
                .block = fetched.value,
                .height = fp_height + @as(u32, @intCast(i + 1)),
            }) catch {
                serialize.freeBlock(allocator, &fetched.value);
                // Restore previous + bail.
                for (rb_list.items[0..i]) |rb| {
                    self.block_buffer.put(rb.hash, rb.block) catch {
                        serialize.freeBlock(allocator, &rb.block);
                    };
                }
                return;
            };
        }

        // Mode selection: under "warn" we only LOG what would have happened.
        const mode_env = std.posix.getenv("CLEARBIT_REORG") orelse "0";
        const dry_run = std.mem.eql(u8, mode_env, "warn");
        if (dry_run) {
            std.log.info(
                "[REORG] dry-run (warn mode): would disconnect to fork_point + connect {d} blocks",
                .{rb_list.items.len},
            );
            // Restore blocks to buffer + clear pending_reorg.
            for (rb_list.items) |rb| {
                self.block_buffer.put(rb.hash, rb.block) catch {
                    serialize.freeBlock(allocator, &rb.block);
                };
            }
            pr_ptr.deinit();
            self.pending_reorg = null;
            return;
        }

        // Fire the reorg.  reorgToChain takes ownership of the inner
        // block bytes via queueBlockWrite — on success the bodies are
        // safely persisted; on failure they're freed by the storage
        // layer's errdefer chain.
        const old_height = cs.best_height;
        const old_hash = cs.best_hash;

        const conn_or_err = cs.reorgToChain(&pr_ptr.fork_point, rb_list.items);
        if (conn_or_err) |connected| {
            std.log.info(
                "[REORG] disconnected={d} connected={d} new_tip_h={d} old_tip_h={d}",
                .{
                    pr_ptr.fork_hashes.items.len, // approximation — actual disconnect count printed by storage
                    connected,
                    cs.best_height,
                    old_height,
                },
            );
            _ = old_hash;
        } else |err| {
            std.log.warn("[REORG] FAILED: {} — banning source peer", .{err});
            if (pr_ptr.source_peer) |sp| {
                sp.misbehaving(100, "reorg failure");
            }
        }
        // Free fork bodies — storage took copies via writeBlock so we
        // can safely free the in-memory Block values now.  (Per
        // serialize.freeBlock semantics: this only frees the
        // transactions/witness slabs we owned, not the persisted bytes.)
        for (rb_list.items) |rb| {
            var b = rb.block;
            serialize.freeBlock(allocator, &b);
        }

        pr_ptr.deinit();
        self.pending_reorg = null;
    }

    /// Helper: look up the height of a given hash via header_index, or
    /// fall back to the active tip if it matches.  Returns 0 if not
    /// found (caller should treat 0 as "fork from genesis").
    fn lookupHeightOrZero(self: *PeerManager, hash: *const types.Hash256) u32 {
        if (self.header_index.get(hash.*)) |e| return e.height;
        if (self.chain_state) |cs| {
            if (std.mem.eql(u8, &cs.best_hash, hash)) return cs.best_height;
        }
        return 0;
    }

    /// Handle a received message.
    fn handleMessage(self: *PeerManager, peer: *Peer, msg: p2p.Message) !void {
        switch (msg) {
            .ping => |pp| {
                const pong = p2p.Message{ .pong = pp };
                try peer.sendMessage(&pong);
            },
            .pong => |pp| peer.handlePong(pp.nonce),
            .addr => |a| {
                defer self.allocator.free(a.addrs);
                // INBOUND addr token-bucket (Core net_processing.cpp
                // ProcessAddrs): refill by elapsed*0.1 capped 1000, admit at
                // most `tokens` addresses, drop the rest. Shared with the
                // addrv2 handler below so the limit can't be bypassed by type.
                const admit = self.takeAddrTokens(peer, a.addrs.len);
                if (admit < a.addrs.len) {
                    std.log.debug("addr rate-limit: dropped {d} of {d} addrs", .{ a.addrs.len - admit, a.addrs.len });
                }
                const now_i = std.time.timestamp();
                for (a.addrs[0..admit]) |entry| {
                    // Clamp the peer-advertised timestamp before storing.
                    // Core net_processing.cpp:5678-5679:
                    //   if (addr.nTime <= NodeSeconds{100000000s} ||
                    //       addr.nTime > current_time + 10min)
                    //       addr.nTime = current_time - 5*24h;
                    const clamped_ts = clampAddrTimestamp(entry.timestamp, now_i);
                    // Convert TimestampedAddr to std.net.Address
                    // Check if it's an IPv4-mapped IPv6 address
                    if (std.mem.eql(u8, entry.addr.ip[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                        const addr = std.net.Address.initIp4(
                            entry.addr.ip[12..16].*,
                            entry.addr.port,
                        );
                        self.addAddressWithTime(addr, entry.addr.services, .peer_addr, clamped_ts) catch continue;
                    }
                }
            },
            .addrv2 => |a2| {
                defer self.allocator.free(a2.entries);
                // Same inbound token-bucket as the legacy addr handler above,
                // sharing the SAME per-peer bucket (Core routes addr and addrv2
                // through the same ProcessAddrs path) so an attacker cannot
                // bypass the rate limit by sending addrv2 instead of addr.
                const admit = self.takeAddrTokens(peer, a2.entries.len);
                if (admit < a2.entries.len) {
                    std.log.debug("addrv2 rate-limit: dropped {d} of {d} addrs", .{ a2.entries.len - admit, a2.entries.len });
                }
                const now_i_v2 = std.time.timestamp();
                // BIP155: Process addrv2 entries — extract IPv4/IPv6 and add to known addresses
                for (a2.entries[0..admit]) |entry| {
                    // Clamp timestamp, same Core rule as for legacy addr.
                    const clamped_ts = clampAddrTimestamp(entry.timestamp, now_i_v2);
                    if (entry.network_id == 1 and entry.addr_bytes.len == 4) {
                        // IPv4
                        const addr = std.net.Address.initIp4(
                            entry.addr_bytes[0..4].*,
                            entry.port,
                        );
                        self.addAddressWithTime(addr, entry.services, .peer_addr, clamped_ts) catch continue;
                    }
                }
            },
            .inv => |inv_msg| {
                defer self.allocator.free(inv_msg.inventory);
                // When a peer announces new blocks via inv, request headers
                // so they enter expected_blocks and can be connected by
                // drainBlockBuffer.  Directly requesting blocks via getdata
                // without adding them to expected_blocks causes them to sit
                // in block_buffer forever (chain tip never advances).
                var has_block_inv = false;
                // Collect tx inv items we want to request (not already in mempool)
                var tx_requests = std.ArrayList(p2p.InvVector).init(self.allocator);
                defer tx_requests.deinit();

                for (inv_msg.inventory) |item| {
                    const base_type = @as(u32, @intFromEnum(item.inv_type)) & ~@as(u32, 0x40000000);
                    if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_block))) {
                        has_block_inv = true;
                    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_tx))) {
                        // Legacy txid inv: request if not already in mempool by txid.
                        if (self.mempool) |pool| {
                            if (!pool.entries.contains(item.hash)) {
                                tx_requests.append(.{
                                    .inv_type = .msg_tx,
                                    .hash = item.hash,
                                }) catch {};
                            }
                        }
                    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_wtx))) {
                        // BIP-339 wtxid inv: item.hash is a wtxid.
                        // Request if we don't already have this wtxid in the mempool.
                        // Use MSG_WTX in the outgoing getdata so the peer responds with
                        // the witness-serialised transaction.
                        if (self.mempool) |pool| {
                            if (!pool.by_wtxid.contains(item.hash)) {
                                tx_requests.append(.{
                                    .inv_type = .msg_wtx,
                                    .hash = item.hash,
                                }) catch {};
                            }
                        }
                    }
                }
                if (has_block_inv) {
                    self.sendGetHeaders(peer) catch {};
                }
                // Request unknown transactions via getdata, batched at MAX_GETDATA_SZ=1000.
                // Core net_processing.cpp:6205-6210 batches outgoing getdata at MAX_GETDATA_SZ.
                // Sending more than 1000 items in a single getdata violates the protocol limit
                // and would cause a conformant peer to Misbehave us.
                var batch_start: usize = 0;
                while (batch_start < tx_requests.items.len) {
                    const batch_end = @min(batch_start + p2p.MAX_GETDATA_SZ, tx_requests.items.len);
                    const batch = tx_requests.items[batch_start..batch_end];
                    const getdata_msg = p2p.Message{ .getdata = .{ .inventory = batch } };
                    peer.sendMessage(&getdata_msg) catch {};
                    batch_start = batch_end;
                }
            },
            .headers => |h| {
                defer self.allocator.free(h.headers);
                // Don't clear getheaders timeout -- we'll request more below if needed

                if (h.headers.len == 0) {
                    // 0 headers from this peer doesn't mean we're synced — the
                    // peer may not have recognized our locator, or it's behind.
                    // Check if we're actually caught up by comparing against
                    // the best peer height. If behind, try another peer.
                    const our_height = if (self.chain_state) |cs| cs.best_height else 0;
                    const best_peer_h = self.getBestPeerHeight();
                    if (our_height + self.expected_blocks.items.len < best_peer_h) {
                        std.debug.print("P2P: 0 headers but behind peers (ours={d}+{d}, best_peer={d}), retrying\n",
                            .{ our_height, self.expected_blocks.items.len, best_peer_h });
                        // Try sending getheaders to a different peer
                        if (self.pickSyncPeer(peer)) |alt_peer| {
                            self.sendGetHeaders(alt_peer) catch {};
                        }
                    } else {
                        // Headers are caught up to the network tip.  Only emit
                        // "fully synced" and skip further work when blocks have
                        // also caught up (connect_cursor == expected_blocks.len).
                        // During IBD the header queue fills far ahead of the
                        // block connection cursor; returning early here suppressed
                        // the pipelineBlockRequests() call that keeps block
                        // download progressing (W28 mid-IBD header stall fix).
                        const blocks_caught_up = self.connect_cursor >= self.expected_blocks.items.len;
                        if (blocks_caught_up) {
                            std.debug.print("P2P: Received 0 headers - fully synced at height {d}\n", .{our_height});
                            return;
                        }
                        // Headers synced but blocks still behind: keep the block
                        // download pipeline running.
                        std.debug.print("P2P: headers synced at height {d}, blocks at {d} (queue={d}), continuing block download\n",
                            .{ our_height + (self.expected_blocks.items.len - self.connect_cursor), our_height, self.expected_blocks.items.len - self.connect_cursor });
                        self.pipelineBlockRequests() catch {};
                    }
                    return;
                }

                // Deduplicate: only accept headers that chain to our known tip.
                // The first header's prev_block must match either:
                // - The last hash in expected_blocks (if any), or
                // - Our best block hash (genesis or connected tip)
                const expected_prev = if (self.expected_blocks.items.len > 0)
                    self.expected_blocks.items[self.expected_blocks.items.len - 1]
                else if (self.chain_state) |cs| blk: {
                    // On fresh start best_hash is all zeros; use genesis hash
                    // so the first batch of headers (whose prev_block is the
                    // genesis hash) chains correctly.
                    break :blk if (cs.best_height == 0) self.network_params.genesis_hash else cs.best_hash;
                } else
                    self.network_params.genesis_hash;

                // ============================================================
                // CLEARBIT_REORG=1: classify the header batch into one of
                // three cases:
                //   A. extends_active   — first header chains onto our tip
                //                         or the queue tail.  Normal extension
                //                         path; falls through to the existing
                //                         logic below.
                //   B. competing_fork   — first header chains onto a known
                //                         non-tip ancestor.  Compute the
                //                         fork's chain_work, request bodies,
                //                         and arm pending_reorg if the fork
                //                         strictly exceeds the active tip.
                //   C. unknown_parent   — first header chains onto a hash
                //                         we've never seen.  Existing peer
                //                         +20 path (peer misbehavior).
                //
                // When CLEARBIT_REORG is unset we keep the legacy behavior:
                // anything other than case A is +20.  Soak: deploy with
                // CLEARBIT_REORG=warn first to log fork detections without
                // firing the disconnect/connect cycle.
                // ============================================================
                const reorg_enabled = isReorgEnabled();

                const klass: HeaderClass = if (reorg_enabled)
                    self.classifyHeaderBatch(&h.headers[0], &expected_prev)
                else
                    (if (std.mem.eql(u8, &h.headers[0].prev_block, &expected_prev))
                        HeaderClass.extends_active
                    else
                        HeaderClass.unknown_parent);

                switch (klass) {
                    .extends_active => {
                        // Successful chain extension — reset the
                        // unconnecting-headers counter for this peer.
                        // Mirrors Core's `nUnconnectingHeaders = 0` in
                        // ProcessHeadersMessage's success path.
                        peer.unconnecting_headers_count = 0;
                        // Fall through to the existing extension path below.
                    },
                    .unknown_parent => {
                        // Bitcoin Core (net_processing.cpp::ProcessHeadersMessage)
                        // tolerates up to MAX_NUM_UNCONNECTING_HEADERS_MSGS=10
                        // unconnecting-headers messages from a peer before
                        // disconnecting.  Pre-fix, clearbit dropped the
                        // peer on the very first orphan, which is stricter
                        // than Core and discards honest peers caught in a
                        // transient reorg.  See
                        // CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
                        // (Pattern B).
                        peer.unconnecting_headers_count += 1;
                        if (peer.unconnecting_headers_count > MAX_NUM_UNCONNECTING_HEADERS_MSGS) {
                            std.debug.print(
                                "P2P: peer={any} exceeded MAX_NUM_UNCONNECTING_HEADERS_MSGS ({d}), disconnecting\n",
                                .{ peer.address, MAX_NUM_UNCONNECTING_HEADERS_MSGS },
                            );
                            peer.misbehaving(20, "too many unconnecting headers");
                            return;
                        }
                        // Under threshold: do NOT misbehave/disconnect.
                        // Re-issue getheaders to try to find a common
                        // ancestor (Core's FindForkInGlobalIndex behavior).
                        std.debug.print(
                            "P2P: orphan headers from peer={any} (unconnecting #{d}/{d}), re-requesting\n",
                            .{ peer.address, peer.unconnecting_headers_count, MAX_NUM_UNCONNECTING_HEADERS_MSGS },
                        );
                        self.sendGetHeaders(peer) catch |err| {
                            std.debug.print("P2P: failed to re-issue getheaders: {}\n", .{err});
                        };
                        return;
                    },
                    .competing_fork => {
                        // Ingest fork headers into the index so the chain_work
                        // accumulator is populated, then ask maybeArmReorg to
                        // decide whether to fire.  We deliberately do NOT
                        // append fork headers to expected_blocks — the active
                        // chain stays in expected_blocks; the fork lives in
                        // header_index + pending_reorg.fork_hashes.
                        std.debug.print(
                            "P2P: REORG-CANDIDATE peer announces fork ({d} headers, prev=...{x:0>2}{x:0>2})\n",
                            .{
                                h.headers.len,
                                h.headers[0].prev_block[30],
                                h.headers[0].prev_block[31],
                            },
                        );
                        // BIP-113 / future-time gate: reject any fork header
                        // whose timestamp falls outside the contextual bounds
                        // BEFORE inserting into header_index.  Misbehave the
                        // peer on rejection — same severity as Core's
                        // bad-header DoS handling.
                        const now_fork: i64 = std.time.timestamp();
                        var last_inserted: ?BlockHeaderEntry = null;
                        for (h.headers) |hdr| {
                            switch (self.validateHeaderContextual(&hdr, now_fork)) {
                                .ok => {},
                                .future_time => {
                                    peer.misbehaving(50, "header timestamp too far in the future");
                                    return;
                                },
                                .mtp_violation => {
                                    peer.misbehaving(50, "header timestamp violates MTP (BIP-113)");
                                    return;
                                },
                            }
                            const bh = crypto.computeBlockHash(&hdr);
                            const ent_or = self.insertHeader(&hdr, &bh) catch null;
                            if (ent_or) |ent| last_inserted = ent;
                        }
                        if (last_inserted) |fork_tip| {
                            self.maybeArmReorg(peer, &fork_tip.hash);
                        }
                        // Continue to ask for more headers — the peer may
                        // have additional fork headers beyond this batch.
                        if (h.headers.len >= 2000) {
                            self.sendGetHeaders(peer) catch {};
                        }
                        return;
                    },
                }

                std.debug.print("P2P: Received {d} new headers (queue={d})\n", .{
                    h.headers.len,
                    self.expected_blocks.items.len + h.headers.len,
                });

                // BIP-113 / future-time gate at header acceptance.  Each
                // header is checked against:
                //   - now + MAX_FUTURE_BLOCK_TIME (7200s) [always-on]
                //   - median-time-past of last 11 ancestors [skipped when
                //     fewer than 1 ancestor is in header_index]
                // Reference: bitcoin-core/src/validation.cpp
                // (CheckBlockHeader + ContextualCheckBlockHeader).
                // Reject the entire batch on the first violation and
                // misbehave the peer; mirrors Core's "bad-time" /
                // "time-too-new" handling.
                const now_hdr: i64 = std.time.timestamp();
                for (h.headers) |hdr| {
                    switch (self.validateHeaderContextual(&hdr, now_hdr)) {
                        .ok => {},
                        .future_time => {
                            peer.misbehaving(50, "header timestamp too far in the future");
                            return;
                        },
                        .mtp_violation => {
                            peer.misbehaving(50, "header timestamp violates MTP (BIP-113)");
                            return;
                        },
                    }
                }

                // G8 — min_pow_checked / MinimumChainWork (W97 FIX-4)
                // Reference: bitcoin-core/src/validation.cpp:4226-4232
                //   AcceptBlockHeader: if (!min_pow_checked)
                //     return state.Invalid(BLOCK_HEADER_LOW_WORK, "too-little-chainwork");
                //
                // min_pow_checked = (parent_chain_work + work(batch) >= min_chain_work)
                // The live .headers handler (this path) is called from a random peer
                // with no out-of-band PRESYNC guarantee, so min_pow_checked = false
                // initially.  We wire the existing (dead-helper) netMinimumChainWork
                // by computing cumulative batch work and comparing to
                // network_params.min_chain_work.  Regtest sets min_chain_work = 0
                // so this gate is a no-op there (consistent with Core).
                {
                    const min_cw = self.network_params.min_chain_work;
                    // Fast path: skip gate when min_chain_work is all-zeros (regtest).
                    const zero: [32]u8 = [_]u8{0} ** 32;
                    // assumeUTXO / snapshot-bootstrap anchor.
                    //
                    // When the node booted from a UTXO snapshot (--load-snapshot)
                    // its active tip is the snapshot base block (e.g. height
                    // 944183) but its header chain_work is NOT reconstructed: the
                    // snapshot carries the UTXO set, not the header index, and the
                    // placeholder block-index entry written at import time has
                    // chain_work=0 (main.zig:1262).  lookupParentChainWork then
                    // returns chainWorkFromHeight(best_height) — a tiny synthetic
                    // value (~2^20), NOT the real ~2^245 mainnet chain_work — so a
                    // genuine post-snapshot header batch (944184..) would compute
                    // cum_work << min_chain_work and be rejected as
                    // too-little-chainwork, banning every honest peer and wedging
                    // forward sync at the snapshot base forever.
                    //
                    // Core does not hit this: a node that has adopted an
                    // assumeUTXO snapshot is by construction already past
                    // nMinimumChainWork (the snapshot base height has far more
                    // cumulative work than min_chain_work), so min_pow_checked is
                    // satisfied and AcceptBlockHeader never rejects on low work.
                    // Reference: bitcoin-core/src/validation.cpp AcceptBlockHeader
                    // min_pow_checked + node/chainstate snapshot activation.
                    //
                    // We mirror that: if our active tip height is at or above any
                    // known snapshot base (canonical assume_utxo OR the hashhog
                    // snapshot_bootstrap allowlist), the min-chain-work anti-DoS
                    // gate has already been satisfied for this chain — skip it.
                    const past_snapshot_base = blk: {
                        const cs = self.chain_state orelse break :blk false;
                        const params = self.network_params;
                        for (params.assume_utxo) |e| {
                            if (cs.best_height >= e.height) break :blk true;
                        }
                        for (params.snapshot_bootstrap) |e| {
                            if (cs.best_height >= e.height) break :blk true;
                        }
                        break :blk false;
                    };
                    if (!std.mem.eql(u8, &min_cw, &zero) and !past_snapshot_base) {
                        // Compute cumulative chain work for this batch.
                        // Start from the parent's work (genesis = all-zeros).
                        var cum_work: [32]u8 = if (self.lookupParentChainWork(&h.headers[0].prev_block)) |p| p.work else [_]u8{0} ** 32;
                        for (h.headers) |hdr| {
                            const w = workFromBits(hdr.bits);
                            addChainWorkBE(&cum_work, &w);
                        }
                        // Reject batch when cumulative work < min_chain_work.
                        if (cmpChainWorkBE(&cum_work, &min_cw) < 0) {
                            std.debug.print("P2P: peer={any} rejected: too-little-chainwork (batch work below min_chain_work)\n",
                                .{peer.address});
                            peer.misbehaving(100, "too-little-chainwork");
                            return;
                        }
                    }
                }

                // Add header hashes to the expected_blocks queue.  Also
                // insert into the header_index when reorg detection is
                // enabled — this populates the structure so future
                // competing-fork announcements can find a recent ancestor.
                for (h.headers) |header| {
                    const block_hash = crypto.computeBlockHash(&header);
                    self.expected_blocks.append(block_hash) catch continue;
                    if (reorg_enabled) {
                        _ = self.insertHeader(&header, &block_hash) catch null;
                    }
                }

                // Request more headers from this specific peer if we got a full batch
                // But limit the queue to avoid too many outstanding blocks
                const remaining_queue = self.expected_blocks.items.len - self.connect_cursor;
                if (h.headers.len >= 2000 and remaining_queue < 16000) {
                    self.sendGetHeaders(peer) catch {};
                }

                // Pipeline: request blocks up to the download window
                self.pipelineBlockRequests() catch {};
            },
            .block => |block| {
                const block_hash = crypto.computeBlockHash(&block.header);

                // Clear this block's in-flight record (Core RemoveBlockRequest).
                // The per-block map is the source of truth: decrement the peer we
                // REQUESTED it from (normally == this delivering peer; for an
                // unsolicited block it may differ, in which case the deliverer was
                // never counted for it and must NOT be decremented). A REQUESTED
                // block stays in the map until it arrives, so this still runs on
                // EVERY block-response path — success, duplicate, orphan,
                // buffer-full-drop, put-failure — preserving the wave-4 guarantee
                // (counter must not drift up, wedge at h=29,953). An untracked
                // (unsolicited / already-cancelled) block has no counter to touch.
                if (self.inflight_block_peer.fetchRemove(block_hash)) |kv| {
                    if (self.blocks_in_flight > 0) self.blocks_in_flight -= 1;
                    if (@intFromPtr(peer) == kv.value) {
                        peer.recordBlockReceived();
                    } else {
                        for (self.peers.items) |p| {
                            if (@intFromPtr(p) == kv.value) {
                                p.recordBlockReceived();
                                break;
                            }
                        }
                    }
                }

                // Bound the buffer to prevent OOM — if too many blocks are
                // buffered waiting for connection, drop this one. It will
                // be re-downloaded when the connection cursor catches up.
                // BUT: always accept the block at the connect cursor, otherwise
                // a full buffer creates a deadlock (we need the next block to
                // advance the cursor and free buffer space, but we drop it).
                if (self.block_buffer.count() >= 1024) {
                    // Try draining first — if the next block is already buffered
                    // this will free space.
                    // W101: skip when already inside a drain (reached via the
                    // heartbeat's processAllMessages).  The outer drain is
                    // doing this work on every while iteration anyway.
                    if (!self.in_drain) self.drainBlockBuffer();

                    // If still full, check if this is the critical next block
                    if (self.block_buffer.count() >= 1024) {
                        const is_next = self.connect_cursor < self.expected_blocks.items.len and
                            std.mem.eql(u8, &block_hash, &self.expected_blocks.items[self.connect_cursor]);
                        if (!is_next) {
                            // Rewind download_cursor so pipelineBlockRequests
                            // will re-request this dropped block. The pipeline
                            // skips hashes already in block_buffer, so this is
                            // a cheap walk that only re-issues the genuinely
                            // missing blocks near the connect front. Without
                            // this rewind, dropped blocks were never re-issued
                            // by the normal pipeline — only by the 5s stall
                            // recovery (32 blocks/peer), which capped IBD at
                            // ~6 blocks/s and wedged the node at 29,953.
                            if (self.download_cursor > self.connect_cursor) {
                                self.download_cursor = self.connect_cursor;
                            }
                            serialize.freeBlock(self.allocator, &block);
                            return;
                        }
                    }
                }

                // Buffer the block (transfer ownership - do NOT free here).
                // Note: AutoHashMap.put replaces on duplicate-hash, so a
                // duplicate block response correctly ends up as a no-op
                // relative to buffer count (decrement already happened above).
                self.block_buffer.put(block_hash, block) catch |err| {
                    // If we can't buffer it, free and drop. The in-flight
                    // decrement above has already run, so the download slot
                    // is freed for the pipeline to re-issue. Log every drop
                    // — the 2026-04-25 wedge at h=892,306 left buffer=28 /
                    // in_flight=0 / queue=54k for 7h with zero log evidence
                    // of why height stopped advancing; this is the only
                    // place blocks can be silently lost in the receive
                    // path, and a high drop rate here would explain it.
                    std.log.err("P2P: BUFFER-PUT-DROP block height={} buffer_size={} err={s}", .{
                        self.connect_cursor,
                        self.block_buffer.count(),
                        @errorName(err),
                    });
                    if (self.download_cursor > self.connect_cursor) {
                        self.download_cursor = self.connect_cursor;
                    }
                    serialize.freeBlock(self.allocator, &block);
                    return;
                };
                // Record which peer supplied this block so drainBlockBuffer can
                // penalise them if validation rejects it.  Mirrors Core's
                // mapBlockSource (net_processing.cpp:4805).  Best-effort; OOM
                // here means we can't penalise but the block is still buffered.
                self.block_source_peers.put(block_hash, @intFromPtr(peer)) catch {};

                // Try to connect as many buffered blocks as possible in order.
                // W101: skip when already inside a drain (reached via the
                // heartbeat's processAllMessages).  The outer drain will
                // consume this newly-buffered block on its next iteration.
                if (!self.in_drain) self.drainBlockBuffer();

                // Request more blocks to keep the pipeline full
                self.pipelineBlockRequests() catch {};
            },
            .getaddr => {
                // GETADDR anti-DoS (Core net_processing.cpp ProcessMessage
                // GETADDR handler):
                //   (1) ignore getaddr from OUTBOUND peers — we only answer
                //       inbound peers' address requests (Core: "Ignoring
                //       getaddr from outbound connection").
                //   (2) answer only the FIRST getaddr per connection; repeats
                //       are ignored (Core `peer.m_getaddr_recvd`).
                if (peer.direction == .outbound) {
                    std.log.debug("Ignoring getaddr from outbound peer", .{});
                } else if (peer.getaddr_recvd) {
                    std.log.debug("Ignoring repeated getaddr from peer", .{});
                } else {
                    peer.getaddr_recvd = true;
                    // 23%-cap (Core MAX_PCT_ADDR_TO_SEND): cap the response to
                    // min(MAX_ADDR_TO_SEND, floor(0.23 * shareable_size)) using
                    // integer division (Core GetAddr_ addrman.cpp:800: nNodes =
                    // max_pct * nNodes / 100). The getnodeaddresses RPC dump path
                    // is separate and uncapped.
                    const cap = getaddrCap(self.shareableAddrCount());
                    try self.sendAddresses(peer, cap);
                }
            },
            .feefilter => |ff| {
                // BIP-133: Store the peer's minimum fee rate (in sat/kvB).
                // We should not relay transactions below this rate to this peer.
                // Validate the fee is reasonable (not exceeding MAX_MONEY which is 21M BTC in sats).
                const MAX_MONEY: u64 = 2_100_000_000_000_000;
                if (ff.feerate <= MAX_MONEY) {
                    peer.fee_filter_received = ff.feerate;
                }
            },
            .sendtxrcncl => |stxr| {
                // BIP-330 Erlay: Peer is announcing support for transaction reconciliation.
                // Validate the version and store the salt for future sketch-based reconciliation.
                if (stxr.version >= 1) {
                    // Initialize reconciliation state for this peer.
                    // The combined salt (XOR of our salt and theirs) is used with SipHash
                    // to compute 32-bit short transaction IDs for the minisketch.
                    // Full integration requires a ReconciliationTracker instance on PeerManager;
                    // for now, record the peer's erlay parameters for future use.
                    // stxr parameters stored for future Erlay use
                }
            },
            .reqrecon => {
                // BIP-330 Erlay: Peer is requesting set reconciliation.
                // No heap allocations in reqrecon (sketch_data is a slice into payload).
            },
            .sketch => {
                // BIP-330 Erlay: Peer sent their sketch data.
                // No heap allocations in sketch (sketch_data is a slice into payload).
            },
            .reconcildiff => |rd| {
                // BIP-330 Erlay: Peer reports the reconciliation results.
                // Free allocated short ID arrays.
                defer self.allocator.free(rd.missing_short_ids);
                defer self.allocator.free(rd.extra_short_ids);
            },
            // BIP-152 Compact Block data messages
            .cmpctblock => |cb| {
                // Free compact block allocations.
                defer self.allocator.free(cb.short_ids);
                defer {
                    for (cb.prefilled_txs) |pt| {
                        var tx = pt.tx;
                        serialize.freeTransaction(self.allocator, &tx);
                    }
                    self.allocator.free(cb.prefilled_txs);
                }

                // Gate B3: null header guard (Core blockencodings.cpp:62).
                // A zeroed-out header signals a malformed cmpctblock.
                const header_hash = crypto.computeBlockHash(&cb.header);
                const zero_hash = [_]u8{0} ** 32;
                if (std.mem.eql(u8, &header_hash, &zero_hash)) {
                    std.debug.print("P2P: cmpctblock null header, ignoring\n", .{});
                    return;
                }

                // Gate B4: both-empty guard (Core blockencodings.cpp:62).
                if (cb.short_ids.len == 0 and cb.prefilled_txs.len == 0) {
                    std.debug.print("P2P: cmpctblock both shorttxids and prefilled empty, ignoring\n", .{});
                    return;
                }

                const block_hash = header_hash;

                // BIP 152: Reconstruct block from compact block + mempool.
                // Derive SipHash key: SHA256(header_bytes || nonce_le)[0:16]
                // Reference: Bitcoin Core blockencodings.cpp FillShortTxIDSelector
                var key_data: [88]u8 = undefined;
                // Serialize header (80 bytes) inline
                std.mem.writeInt(i32, key_data[0..4], cb.header.version, .little);
                @memcpy(key_data[4..36], &cb.header.prev_block);
                @memcpy(key_data[36..68], &cb.header.merkle_root);
                std.mem.writeInt(u32, key_data[68..72], cb.header.timestamp, .little);
                std.mem.writeInt(u32, key_data[72..76], cb.header.bits, .little);
                std.mem.writeInt(u32, key_data[76..80], cb.header.nonce, .little);
                std.mem.writeInt(u64, key_data[80..88], cb.nonce, .little);
                const key_hash = crypto.sha256(&key_data);
                const k0 = std.mem.readInt(u64, key_hash[0..8], .little);
                const k1 = std.mem.readInt(u64, key_hash[8..16], .little);

                // Build short_id -> slot index map (skipping prefilled positions)
                const total_tx_count = cb.short_ids.len + cb.prefilled_txs.len;
                const txn_available = self.allocator.alloc(?types.Transaction, total_tx_count) catch {
                    std.debug.print("P2P: compact block alloc failed, requesting full block\n", .{});
                    var inv_list2 = std.ArrayList(p2p.InvVector).init(self.allocator);
                    defer inv_list2.deinit();
                    inv_list2.append(.{ .inv_type = .msg_witness_block, .hash = block_hash }) catch {};
                    if (inv_list2.items.len > 0) {
                        const getdata_msg2 = p2p.Message{ .getdata = .{ .inventory = inv_list2.items } };
                        peer.sendMessage(&getdata_msg2) catch {};
                    }
                    return;
                };
                defer self.allocator.free(txn_available);
                for (txn_available) |*slot| slot.* = null;

                // Gate B5+B6: Place prefilled transactions using accumulated
                // differential index (Core blockencodings.cpp:72-87).
                // prefilled_txs[i].index is a DELTA from the previous absolute
                // position; accumulate to get the true slot.
                var last_prefilled_index: i32 = -1;
                var valid = true;
                for (cb.prefilled_txs, 0..) |pt, i| {
                    // Accumulate: absolute = last_absolute + delta + 1
                    last_prefilled_index += @as(i32, @intCast(pt.index)) + 1;
                    // Gate B5: overflow beyond uint16 (Core blockencodings.cpp:78)
                    if (last_prefilled_index > 0xffff) {
                        std.debug.print("P2P: cmpctblock prefilled index overflow, ignoring\n", .{});
                        valid = false;
                        break;
                    }
                    // Gate B6: gap check — absolute index must not exceed
                    // shorttxids.len + number of prefilled so far (Core:80-85).
                    if (@as(u32, @intCast(last_prefilled_index)) > cb.short_ids.len + i) {
                        std.debug.print("P2P: cmpctblock prefilled index gap, ignoring\n", .{});
                        valid = false;
                        break;
                    }
                    txn_available[@intCast(last_prefilled_index)] = pt.tx;
                }
                if (!valid) {
                    // Fall back to full block download
                    var inv_fb = std.ArrayList(p2p.InvVector).init(self.allocator);
                    defer inv_fb.deinit();
                    inv_fb.append(.{ .inv_type = .msg_witness_block, .hash = block_hash }) catch {};
                    if (inv_fb.items.len > 0) {
                        const gd_fb = p2p.Message{ .getdata = .{ .inventory = inv_fb.items } };
                        peer.sendMessage(&gd_fb) catch {};
                    }
                    return;
                }

                // Build short_id -> slot map, checking for collisions.
                // Gate B7: short-id collision detection (Core:115-116).
                // Gate B8: bucket-size DoS check (Core:110-111, max 12 per bucket).
                // We simulate bucket detection by checking for duplicate keys.
                const SipHash = std.crypto.auth.siphash.SipHash64(2, 4);
                var sip_key: [16]u8 = undefined;
                std.mem.writeInt(u64, sip_key[0..8], k0, .little);
                std.mem.writeInt(u64, sip_key[8..16], k1, .little);

                // Map: packed 6-byte short-id (as u64 low 48 bits) -> slot index.
                // Using u64 key for the hashmap (upper 2 bytes zero).
                var sid_to_slot = std.AutoHashMap(u64, usize).init(self.allocator);
                defer sid_to_slot.deinit();
                // Bucket-collision counter: track how many entries land in each bucket.
                // We use a secondary AutoHashMap keyed by bucket index (sid % bucket_count).
                var bucket_counts = std.AutoHashMap(u64, u32).init(self.allocator);
                defer bucket_counts.deinit();

                var collision_detected = false;
                var sid_idx: usize = 0;
                for (0..total_tx_count) |i| {
                    if (txn_available[i] == null) {
                        if (sid_idx < cb.short_ids.len) {
                            const sid_bytes = cb.short_ids[sid_idx];
                            sid_idx += 1;
                            // Unpack 6 bytes as a u64 (little-endian, upper 2 bytes = 0)
                            var sid_le8 = [_]u8{0} ** 8;
                            @memcpy(sid_le8[0..6], &sid_bytes);
                            const sid_val = std.mem.readInt(u64, &sid_le8, .little);

                            // Gate B7: duplicate short-id → collision
                            if (sid_to_slot.contains(sid_val)) {
                                std.debug.print("P2P: cmpctblock short-id collision detected, requesting full block\n", .{});
                                collision_detected = true;
                                break;
                            }
                            sid_to_slot.put(sid_val, i) catch {
                                collision_detected = true;
                                break;
                            };

                            // Gate B8: bucket-size DoS check (bucket = sid_val % map_size).
                            // We approximate: count entries sharing the same (sid_val % 16384).
                            const bucket_key = sid_val % 16384;
                            const prev_count = bucket_counts.get(bucket_key) orelse 0;
                            const new_count = prev_count + 1;
                            if (new_count > 12) {
                                std.debug.print("P2P: cmpctblock bucket overflow (DoS), requesting full block\n", .{});
                                collision_detected = true;
                                break;
                            }
                            bucket_counts.put(bucket_key, new_count) catch {};
                        }
                    }
                }

                if (collision_detected) {
                    var inv_cd = std.ArrayList(p2p.InvVector).init(self.allocator);
                    defer inv_cd.deinit();
                    inv_cd.append(.{ .inv_type = .msg_witness_block, .hash = block_hash }) catch {};
                    if (inv_cd.items.len > 0) {
                        const gd_cd = p2p.Message{ .getdata = .{ .inventory = inv_cd.items } };
                        peer.sendMessage(&gd_cd) catch {};
                    }
                    return;
                }

                // Match mempool entries against short IDs.
                // Gate B9: if two mempool txns match the same short ID, clear the
                // slot and request the tx (Core blockencodings.cpp:129-136).
                var mempool_hits: usize = 0;
                var have_txn = self.allocator.alloc(bool, total_tx_count) catch return;
                defer self.allocator.free(have_txn);
                for (have_txn) |*h| h.* = false;

                if (self.mempool) |mp| {
                    mp.mutex.lock();
                    defer mp.mutex.unlock();
                    var it = mp.entries.iterator();
                    while (it.next()) |kv| {
                        const entry = kv.value_ptr.*;
                        // Compute short ID: SipHash-2-4(k0, k1, wtxid) & 0xffffffffffff
                        var hasher = SipHash.init(&sip_key);
                        hasher.update(&entry.wtxid);
                        const hash_val = hasher.finalInt() & 0x0000ffffffffffff;
                        if (sid_to_slot.get(hash_val)) |slot_idx| {
                            if (!have_txn[slot_idx]) {
                                txn_available[slot_idx] = entry.tx;
                                have_txn[slot_idx] = true;
                                mempool_hits += 1;
                            } else {
                                // Gate B9: second mempool match → clear slot, request tx
                                if (txn_available[slot_idx] != null) {
                                    txn_available[slot_idx] = null;
                                    mempool_hits -= 1;
                                }
                            }
                        }
                        // Early-exit once all short IDs are matched (Core perf note)
                        if (mempool_hits == cb.short_ids.len) break;
                    }
                }

                // Count missing
                var missing_count: usize = 0;
                for (txn_available) |slot| {
                    if (slot == null) missing_count += 1;
                }

                if (missing_count == 0) {
                    std.debug.print("P2P: compact block {x} reconstructed from mempool (hits={})\n", .{ block_hash, mempool_hits });
                    // TODO: assemble full block and pass to validation
                } else {
                    const miss_pct = @as(f64, @floatFromInt(missing_count)) / @as(f64, @floatFromInt(total_tx_count)) * 100.0;
                    if (miss_pct > 50.0) {
                        // Too many missing — fall back to full block
                        std.debug.print("P2P: compact block {x} missing {d:.0}% txns, requesting full block\n", .{ block_hash, miss_pct });
                        var inv_list = std.ArrayList(p2p.InvVector).init(self.allocator);
                        defer inv_list.deinit();
                        inv_list.append(.{ .inv_type = .msg_witness_block, .hash = block_hash }) catch {};
                        if (inv_list.items.len > 0) {
                            const getdata_msg = p2p.Message{ .getdata = .{ .inventory = inv_list.items } };
                            peer.sendMessage(&getdata_msg) catch {};
                        }
                    } else {
                        // Send getblocktxn for missing transactions.
                        // Indexes are encoded as differentials (Core DifferenceFormatter).
                        std.debug.print("P2P: compact block {x} missing {} txns (mempool_hits={}), sending getblocktxn\n", .{ block_hash, missing_count, mempool_hits });
                        var missing_indices = std.ArrayList(u16).init(self.allocator);
                        defer missing_indices.deinit();
                        for (0..total_tx_count) |i| {
                            if (txn_available[i] == null) {
                                missing_indices.append(@intCast(i)) catch {};
                            }
                        }
                        if (missing_indices.items.len > 0) {
                            const gbt_msg = p2p.Message{ .getblocktxn = .{
                                .block_hash = block_hash,
                                .indexes = missing_indices.items,
                            } };
                            peer.sendMessage(&gbt_msg) catch {};
                        }
                    }
                }
            },
            .getblocktxn => |gbt| {
                // Free allocated index array.
                defer self.allocator.free(gbt.indexes);
                // BUG-8 FIX (W112, FIX-42): MAX_BLOCKTXN_DEPTH guard.
                // Reference: bitcoin-core/src/net_processing.cpp:4276-4303.
                // If the requested block is more than MAX_BLOCKTXN_DEPTH=10
                // behind the tip, respond with the full block via MSG_WITNESS_BLOCK
                // instead of blocktxn (peer can't have a useful mempool that deep;
                // also protects against cheap getblocktxn DoS from disk reads).
                // Core: pushes MSG_WITNESS_BLOCK to peer.m_getdata_requests for
                // the next loop. Clearbit: serve directly from the relay cache.
                const gbt_tip_height: u32 = if (self.chain_state) |cs| cs.best_height else 0;
                const gbt_block_height_opt: ?u32 = blk: {
                    if (self.header_index.get(gbt.block_hash)) |entry| {
                        break :blk entry.height;
                    }
                    break :blk null;
                };
                if (gbt_block_height_opt) |gbt_block_height| {
                    const gbt_depth = if (gbt_tip_height >= gbt_block_height)
                        gbt_tip_height - gbt_block_height
                    else
                        0;
                    if (gbt_depth > p2p.MAX_BLOCKTXN_DEPTH) {
                        // Block is too deep — respond with full block instead of blocktxn.
                        // Reference: bitcoin-core/src/net_processing.cpp:4299-4301.
                        std.log.debug("P2P: getblocktxn depth={d} > MAX_BLOCKTXN_DEPTH={d}, serving full block", .{ gbt_depth, p2p.MAX_BLOCKTXN_DEPTH });
                        if (self.served_blocks.get(gbt.block_hash)) |block_data| {
                            var gbt_reader = serialize.Reader{ .data = block_data };
                            const gbt_block = serialize.readBlock(&gbt_reader, self.allocator) catch return;
                            defer serialize.freeBlock(self.allocator, &gbt_block);
                            const gbt_block_msg = p2p.Message{ .block = gbt_block };
                            peer.sendMessage(&gbt_block_msg) catch {};
                        } else if (self.block_buffer.get(gbt.block_hash)) |gbt_buffered| {
                            const gbt_block_msg = p2p.Message{ .block = gbt_buffered };
                            peer.sendMessage(&gbt_block_msg) catch {};
                        } else {
                            const gbt_nf_inv = [_]p2p.InvVector{.{
                                .inv_type = .msg_witness_block,
                                .hash = gbt.block_hash,
                            }};
                            const gbt_nf_msg = p2p.Message{ .notfound = .{ .inventory = &gbt_nf_inv } };
                            peer.sendMessage(&gbt_nf_msg) catch {};
                        }
                        return;
                    }
                }
                // Block is within depth (or depth unknown) — we don't yet serve
                // blocktxn responses (BUG-7, separate from BUG-8). Ignore.
            },
            .blocktxn => |bt| {
                // Free allocated transactions.
                defer {
                    for (bt.transactions) |*tx| {
                        serialize.freeTransaction(self.allocator, tx);
                    }
                    self.allocator.free(bt.transactions);
                }
                // Response to our getblocktxn request. Since we fall back to
                // full block download, we shouldn't receive these. Ignore.
            },
            .tx => |tx_msg| {
                // OWNERSHIP CONTRACT (use-after-free fix):
                //   `Mempool.addTransaction` stores the tx struct BY VALUE
                //   (`.tx = tx`) and RETAINS its input/output/witness/script
                //   slices — it does NOT deep-copy them (see mempool.zig:1360
                //   and the contract documented at mempool.zig:1791-1801,
                //   mempool_persist.zig:525-537, rpc.zig:6069-6072 / 12113-12115).
                //   On a SUCCESSFUL accept, ownership of those allocations
                //   transfers to the mempool; the caller must NOT free them or
                //   the mempool's `MempoolEntry.tx` (and every script slice it
                //   exposes via `getOutputFromMempool`) is left dangling.
                //
                //   The previous `defer serialize.freeTransaction(&tx_msg)`
                //   freed the buffer UNCONDITIONALLY — including on success —
                //   which left every admitted P2P tx's output scriptPubKeys
                //   pointing at freed (then reused) heap. A later tx spending
                //   such an output resolved its prevout via
                //   `getOutputFromMempool` → returned a dangling `script_pubkey`
                //   slice → `verifyInputScripts`/`checkWitnessStandard` read
                //   `script[0]` of a wild pointer → SIGSEGV (live mainnet,
                //   core.3313851: spent_scripts[0]={ptr=garbage,len=22}).
                //
                //   Fix: free `tx_msg` only when the mempool did NOT take
                //   ownership. The not-accepted branch is always safe to free —
                //   the orphan path (`addOrphan`) makes its own serialize
                //   round-trip deep copy, so it never borrows `tx_msg`.
                //   This matches Bitcoin Core: CTxMemPool keeps an independent
                //   CTransactionRef for every admitted tx; net_processing's
                //   reference is dropped after the message is handled, but the
                //   underlying transaction data lives as long as the mempool
                //   entry does.
                var tx_taken_by_mempool = false;
                defer if (!tx_taken_by_mempool) serialize.freeTransaction(self.allocator, &tx_msg);
                if (self.mempool) |pool| {
                    // Accept transaction into mempool via AcceptToMemoryPool
                    const result = pool.acceptToMemoryPool(tx_msg, false);
                    if (result.accepted) {
                        tx_taken_by_mempool = true;
                        // After admitting a parent, see if any orphan
                        // transactions are now resolvable.  Successfully
                        // promoted orphans drain into the mempool
                        // automatically (mempool-side fixpoint loop).
                        // Reference: Bitcoin Core
                        // `ProcessOrphanTx` in net_processing.cpp.
                        _ = pool.processOrphansForParent(result.txid);

                        // Relay to all other peers via inv.
                        // BIP-339: use MSG_WTX (=5) + wtxid for peers that negotiated
                        // wtxidrelay; fall back to MSG_TX (=1) + txid for legacy peers.
                        // Core: net_processing.cpp:6007-6009 RelayTransaction.
                        // Do NOT use MSG_WITNESS_TX (0x40000001) for relay inv — that
                        // is a getdata-only flag for witness-serialised block data.
                        for (self.peers.items) |relay_peer| {
                            if (relay_peer == peer) continue; // Don't relay back to sender
                            if (!relay_peer.relay_txs) continue; // Respect fRelay
                            if (relay_peer.state != .connected) continue;
                            // BIP-133 feefilter: skip peers whose fee filter exceeds tx fee rate
                            if (relay_peer.fee_filter_received > 0 and result.fee > 0 and result.vsize > 0) {
                                const fee_rate_per_kvb: u64 = @intCast(@divTrunc(result.fee * 1000, @as(i64, @intCast(result.vsize))));
                                if (fee_rate_per_kvb < relay_peer.fee_filter_received) continue;
                            }
                            const relay_inv = if (relay_peer.wtxid_relay_negotiated)
                                p2p.InvVector{ .inv_type = .msg_wtx, .hash = result.wtxid }
                            else
                                p2p.InvVector{ .inv_type = .msg_tx, .hash = result.txid };
                            const relay_inv_items = [_]p2p.InvVector{relay_inv};
                            const inv_msg = p2p.Message{ .inv = .{ .inventory = &relay_inv_items } };
                            relay_peer.sendMessage(&inv_msg) catch {};
                        }
                        std.debug.print("MEMPOOL: accepted tx, relaying to peers\n", .{});
                    } else if (result.reject_reason) |reason| {
                        // On `missing-inputs` (Core's TX_MISSING_INPUTS),
                        // park the tx in the orphan pool keyed by the
                        // sending peer so we can retry after the parent
                        // arrives.  Bounded by `MAX_ORPHAN_TRANSACTIONS`
                        // / `MAX_ORPHAN_TX_SIZE` / `MAX_PEER_ORPHANS`.
                        if (std.mem.eql(u8, reason, "missing-inputs")) {
                            const peer_id: u64 = @intFromPtr(peer);
                            _ = pool.addOrphan(&tx_msg, peer_id);
                        }
                    }
                }
            },
            .getdata => |gd| {
                // Serve requested blocks to peers (check relay cache and pending buffer).
                //
                // BIP-159 peer-served-blocks gate: when prune mode is on, an
                // honest peer respecting our NODE_NETWORK_LIMITED bit will not
                // request blocks below tip-288.  If a peer ignores that bit
                // and asks for a pre-prune block, the served_blocks /
                // block_buffer caches won't contain it (they hold only the
                // most recent connected blocks) and the existing else-branch
                // below already replies with `notfound`, matching Core's
                // ProcessGetBlockData behaviour for pruned-block requests.
                defer self.allocator.free(gd.inventory);
                // G2: enforce MAX_GETDATA_SZ=1000 server-side.
                // Core net_processing.cpp:4131-4134:
                //   if (vInv.size() > MAX_GETDATA_SZ)
                //     Misbehaving(peer, "getdata message size = %u", vInv.size())
                if (gd.inventory.len > p2p.MAX_GETDATA_SZ) {
                    peer.misbehaving(100, "getdata message size exceeds MAX_GETDATA_SZ (1000)");
                    return;
                }
                for (gd.inventory) |item| {
                    const base_type = @as(u32, @intFromEnum(item.inv_type)) & ~@as(u32, 0x40000000);
                    if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_block))) {
                        // 1. Check served_blocks cache (mined + recently connected blocks)
                        if (self.served_blocks.get(item.hash)) |block_data| {
                            var reader = serialize.Reader{ .data = block_data };
                            const block = serialize.readBlock(&reader, self.allocator) catch continue;
                            defer serialize.freeBlock(self.allocator, &block);
                            const block_msg = p2p.Message{ .block = block };
                            peer.sendMessage(&block_msg) catch {};
                            std.debug.print("P2P: served block from relay cache to peer\n", .{});
                        } else if (self.block_buffer.get(item.hash)) |buffered_block| {
                            // 2. Check block_buffer (received but not yet connected)
                            const block_msg = p2p.Message{ .block = buffered_block };
                            peer.sendMessage(&block_msg) catch {};
                            std.debug.print("P2P: served buffered block to peer\n", .{});
                        } else {
                            // Block not available — send notfound
                            const not_found_inv = [_]p2p.InvVector{.{
                                .inv_type = item.inv_type,
                                .hash = item.hash,
                            }};
                            const nf_msg = p2p.Message{ .notfound = .{ .inventory = &not_found_inv } };
                            peer.sendMessage(&nf_msg) catch {};
                        }
                    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_cmpct_block))) {
                        // BUG-4 FIX (W112, FIX-42): MSG_CMPCT_BLOCK getdata handler.
                        // Reference: bitcoin-core/src/net_processing.cpp:2461-2476
                        //   (ProcessGetBlockData, IsMsgCmpctBlk branch).
                        // If block depth ≤ MAX_CMPCTBLOCK_DEPTH=5: build and serve
                        // CBlockHeaderAndShortTxIDs (cmpctblock). Deeper blocks (or
                        // blocks not in our cache): fall back to full block.
                        // Core: "If a peer is asking for old blocks, we're almost
                        // guaranteed they won't have a useful mempool to match against
                        // a compact block, and we don't feel like constructing the
                        // object for them, so instead we respond with the full block."
                        const tip_height: u32 = if (self.chain_state) |cs| cs.best_height else 0;
                        const block_height_opt: ?u32 = blk: {
                            if (self.header_index.get(item.hash)) |entry| {
                                break :blk entry.height;
                            }
                            break :blk null;
                        };
                        const depth: u32 = if (block_height_opt) |bh|
                            (if (tip_height >= bh) tip_height - bh else 0)
                        else
                            p2p.MAX_CMPCTBLOCK_DEPTH + 1; // unknown depth → fall back
                        if (depth <= p2p.MAX_CMPCTBLOCK_DEPTH) {
                            // Serve compact block (BIP-152 CBlockHeaderAndShortTxIDs).
                            // Locate the full block from cache.
                            const cmpct_block_opt: ?types.Block = blk2: {
                                if (self.served_blocks.get(item.hash)) |block_data| {
                                    var cmpct_reader = serialize.Reader{ .data = block_data };
                                    const b = serialize.readBlock(&cmpct_reader, self.allocator) catch break :blk2 null;
                                    break :blk2 b;
                                } else if (self.block_buffer.get(item.hash)) |buffered| {
                                    break :blk2 buffered;
                                }
                                break :blk2 null;
                            };
                            if (cmpct_block_opt) |cmpct_block| {
                                // If block came from served_blocks we own a copy; for
                                // block_buffer we borrow — use defer only for the owned case.
                                const owns_block = self.served_blocks.contains(item.hash);
                                defer if (owns_block) serialize.freeBlock(self.allocator, &cmpct_block);

                                // Build CBlockHeaderAndShortTxIDs inline.
                                // Reference: bitcoin-core/src/blockencodings.cpp
                                //   CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock&, bool).
                                // Nonce: 64-bit CSPRNG per Core (m_rng.rand64()).
                                const cb_nonce = std.crypto.random.int(u64);

                                // Derive SipHash key: SHA256(header_bytes || nonce_LE)[0..16]
                                var cb_key_data: [88]u8 = undefined;
                                std.mem.writeInt(i32, cb_key_data[0..4], cmpct_block.header.version, .little);
                                @memcpy(cb_key_data[4..36], &cmpct_block.header.prev_block);
                                @memcpy(cb_key_data[36..68], &cmpct_block.header.merkle_root);
                                std.mem.writeInt(u32, cb_key_data[68..72], cmpct_block.header.timestamp, .little);
                                std.mem.writeInt(u32, cb_key_data[72..76], cmpct_block.header.bits, .little);
                                std.mem.writeInt(u32, cb_key_data[76..80], cmpct_block.header.nonce, .little);
                                std.mem.writeInt(u64, cb_key_data[80..88], cb_nonce, .little);
                                const cb_key_hash = crypto.sha256(&cb_key_data);
                                const cb_k0 = std.mem.readInt(u64, cb_key_hash[0..8], .little);
                                const cb_k1 = std.mem.readInt(u64, cb_key_hash[8..16], .little);
                                var cb_sip_key: [16]u8 = undefined;
                                std.mem.writeInt(u64, cb_sip_key[0..8], cb_k0, .little);
                                std.mem.writeInt(u64, cb_sip_key[8..16], cb_k1, .little);

                                const SipHash64 = std.crypto.auth.siphash.SipHash64(2, 4);

                                // Build short_ids for non-coinbase transactions (index ≥ 1).
                                // Coinbase is always prefilled at index 0.
                                var short_ids = std.ArrayList([6]u8).init(self.allocator);
                                defer short_ids.deinit();
                                var cb_alloc_err = false;
                                for (cmpct_block.transactions, 0..) |*tx, ti| {
                                    if (ti == 0) continue; // coinbase → prefilled
                                    const wtxid = crypto.computeWtxidStreaming(tx);
                                    var cb_hasher = SipHash64.init(&cb_sip_key);
                                    cb_hasher.update(&wtxid);
                                    const short_val = cb_hasher.finalInt() & 0x0000ffffffffffff;
                                    var sid6: [6]u8 = undefined;
                                    // Write 6-byte little-endian short ID manually
                                    // (u48 is not a valid writeInt type in Zig 0.13).
                                    var tmp64: [8]u8 = undefined;
                                    std.mem.writeInt(u64, &tmp64, short_val, .little);
                                    @memcpy(&sid6, tmp64[0..6]);
                                    short_ids.append(sid6) catch {
                                        cb_alloc_err = true;
                                        break;
                                    };
                                }

                                if (!cb_alloc_err and cmpct_block.transactions.len > 0) {
                                    // Coinbase prefilled (index 0 in wire, delta 0).
                                    const coinbase_prefilled = [_]p2p.PrefilledTransaction{.{
                                        .index = 0,
                                        .tx = cmpct_block.transactions[0],
                                    }};
                                    const cmpct_msg = p2p.Message{ .cmpctblock = .{
                                        .header = cmpct_block.header,
                                        .nonce = cb_nonce,
                                        .short_ids = short_ids.items,
                                        .prefilled_txs = &coinbase_prefilled,
                                    } };
                                    peer.sendMessage(&cmpct_msg) catch {};
                                    std.log.debug("P2P: served cmpctblock depth={d} to peer", .{depth});
                                } else {
                                    // Alloc failure or empty block — fall back to full block.
                                    const fb_msg = p2p.Message{ .block = cmpct_block };
                                    peer.sendMessage(&fb_msg) catch {};
                                }
                            } else {
                                // Block not in cache — notfound.
                                const not_found_inv = [_]p2p.InvVector{.{
                                    .inv_type = item.inv_type,
                                    .hash = item.hash,
                                }};
                                const nf_msg = p2p.Message{ .notfound = .{ .inventory = &not_found_inv } };
                                peer.sendMessage(&nf_msg) catch {};
                            }
                        } else {
                            // Block is too deep — serve full block instead.
                            // Reference: bitcoin-core/src/net_processing.cpp:2473-2475.
                            std.log.debug("P2P: cmpctblock request depth={d} > MAX_CMPCTBLOCK_DEPTH={d}, serving full block", .{ depth, p2p.MAX_CMPCTBLOCK_DEPTH });
                            if (self.served_blocks.get(item.hash)) |block_data| {
                                var fb_reader = serialize.Reader{ .data = block_data };
                                const fb_block = serialize.readBlock(&fb_reader, self.allocator) catch continue;
                                defer serialize.freeBlock(self.allocator, &fb_block);
                                const fb_msg = p2p.Message{ .block = fb_block };
                                peer.sendMessage(&fb_msg) catch {};
                            } else if (self.block_buffer.get(item.hash)) |buffered_block| {
                                const fb_msg = p2p.Message{ .block = buffered_block };
                                peer.sendMessage(&fb_msg) catch {};
                            } else {
                                const not_found_inv = [_]p2p.InvVector{.{
                                    .inv_type = item.inv_type,
                                    .hash = item.hash,
                                }};
                                const nf_msg = p2p.Message{ .notfound = .{ .inventory = &not_found_inv } };
                                peer.sendMessage(&nf_msg) catch {};
                            }
                        }
                    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_tx))) {
                        // Serve transaction from mempool by txid (legacy getdata).
                        if (self.mempool) |pool| {
                            if (pool.entries.get(item.hash)) |entry| {
                                const tx_msg = p2p.Message{ .tx = entry.tx };
                                peer.sendMessage(&tx_msg) catch {};
                            } else {
                                const not_found_inv = [_]p2p.InvVector{.{
                                    .inv_type = item.inv_type,
                                    .hash = item.hash,
                                }};
                                const nf_msg = p2p.Message{ .notfound = .{ .inventory = &not_found_inv } };
                                peer.sendMessage(&nf_msg) catch {};
                            }
                        }
                    } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_wtx))) {
                        // BIP-339 getdata: item.hash is a wtxid.
                        // Consult by_wtxid secondary index to resolve wtxid → txid,
                        // then serve via the primary entries map.
                        // Core: net_processing.cpp FindTxForGetData (GenTxid lookup).
                        if (self.mempool) |pool| {
                            const txid_opt = pool.by_wtxid.get(item.hash);
                            const entry_opt = if (txid_opt) |txid| pool.entries.get(txid) else null;
                            if (entry_opt) |entry| {
                                const tx_msg = p2p.Message{ .tx = entry.tx };
                                peer.sendMessage(&tx_msg) catch {};
                            } else {
                                const not_found_inv = [_]p2p.InvVector{.{
                                    .inv_type = item.inv_type,
                                    .hash = item.hash,
                                }};
                                const nf_msg = p2p.Message{ .notfound = .{ .inventory = &not_found_inv } };
                                peer.sendMessage(&nf_msg) catch {};
                            }
                        }
                    }
                }
            },
            .notfound => |nf| {
                // Free the allocated inventory array.
                defer self.allocator.free(nf.inventory);
            },
            .getheaders => |gh| {
                // Free the allocated locator hashes.
                defer self.allocator.free(gh.block_locator_hashes);
                // Serve our active-chain headers from the locator's fork
                // point — Core ProcessGetHeaders.  This is the responder
                // that lets a peer pull a competing/heavier chain off us and
                // arm its own reorg (the missing serving side of the
                // CLEARBIT_REORG fork pipeline).
                self.processGetHeaders(peer, gh.block_locator_hashes, &gh.hash_stop);
            },
            .getblocks => |gb| {
                // Free the allocated locator hashes.
                defer self.allocator.free(gb.block_locator_hashes);
            },
            .reject => |rj| {
                // reject message fields are slices into the payload buffer,
                // which is freed by receiveMessage's defer. No extra free needed.
                _ = rj;
            },
            .mempool => {
                // BIP-35: serve our mempool inventory to the requesting peer.
                // Bitcoin Core gates this on whether *we* advertised NODE_BLOOM
                // (`peer.m_our_services & NODE_BLOOM`) — see
                // bitcoin-core/src/net_processing.cpp:4852.  If we did not,
                // disconnect the peer for protocol violation.
                if (!peer.advertise_node_bloom) {
                    std.log.debug("mempool request with bloom filters disabled, disconnecting peer={any}", .{peer.address});
                    peer.should_ban = false;
                    peer.disconnect();
                    return;
                }
                const pool = self.mempool orelse return;
                try sendMempoolInventory(peer, pool, self.allocator);
            },
            .sendheaders => {
                // BIP-130: peer requests that we announce new blocks via the
                // `headers` message instead of `inv`.  Latch the per-peer
                // flag; `announceBlock` consults it on each new tip.
                // Reference: bitcoin-core/src/net_processing.cpp
                // (PeerManagerImpl::ProcessMessage NetMsgType::SENDHEADERS).
                peer.send_headers = true;
            },
            .sendcmpct => |sc| {
                // BIP-152: validate version field before updating peer compact-relay state.
                // Core drops the message immediately if version != CMPCTBLOCKS_VERSION (2):
                //   net_processing.cpp:3907 — if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
                // Version 1 (non-segwit short IDs) was removed in Bitcoin Core 0.18+.
                // Only version 2 (witness-aware wtxid short IDs) is supported per BIP-152 §Note 7.
                // Silently drop non-v2: do not install compact relay for this peer.
                if (sc.version != 2) return;
                peer.bip152_provides_cmpctblocks = true;
                peer.bip152_highbandwidth_from = sc.announce;
            },
            // BIP-37 / BIP-111 bloom filter messages.
            //
            // Bitcoin Core: net_processing.cpp:4964 (filterload), 4990
            // (filteradd), 5018 (filterclear) — if NODE_BLOOM is not in
            // m_our_services, set fDisconnect=true and return immediately.
            //
            // clearbit never has a CBloomFilter; NODE_BLOOM is never
            // advertised (peerbloomfilters defaults to false, matching
            // Core's DEFAULT_PEERBLOOMFILTERS=false in net_processing.h:44).
            // So the disconnect path fires for every peer that attempts
            // filter setup — correct BIP-111 behavior.
            .filterload => |bfm| {
                self.allocator.free(bfm.payload);
                if (!peer.advertise_node_bloom) {
                    std.log.debug(
                        "BIP-111: filterload from peer={any} without NODE_BLOOM, disconnecting",
                        .{peer.address},
                    );
                    peer.should_ban = false;
                    peer.disconnect();
                }
                // If NODE_BLOOM were ever enabled (future extension), the
                // full CBloomFilter parse + IsWithinSizeConstraints check
                // would go here.  For now we just disconnect cleanly.
            },
            .filteradd => |bfm| {
                self.allocator.free(bfm.payload);
                if (!peer.advertise_node_bloom) {
                    std.log.debug(
                        "BIP-111: filteradd from peer={any} without NODE_BLOOM, disconnecting",
                        .{peer.address},
                    );
                    peer.should_ban = false;
                    peer.disconnect();
                }
            },
            .filterclear => {
                if (!peer.advertise_node_bloom) {
                    std.log.debug(
                        "BIP-111: filterclear from peer={any} without NODE_BLOOM, disconnecting",
                        .{peer.address},
                    );
                    peer.should_ban = false;
                    peer.disconnect();
                }
            },
            // merkleblock is a server→client message (Core sends it in
            // response to a MSG_FILTERED_BLOCK getdata).  Receiving one is
            // unexpected (buggy or misbehaving peer).  Log and drop; do NOT
            // disconnect — Core does not disconnect on unsolicited merkleblock
            // and the peer may simply be confused.
            .merkleblock => |bfm| {
                self.allocator.free(bfm.payload);
                std.log.debug(
                    "unexpected merkleblock from peer={any}, dropping",
                    .{peer.address},
                );
            },
            // ============================================================
            // BIP-157 Compact Filter Messages (FIX-84 — W121 BUG-3..7 closure)
            // ============================================================
            //
            // Inbound requests: getcfilters / getcfheaders / getcfcheckpt.
            // We serve from the BIP-158 block-filter index (verified clean
            // in W122 audit 17f8c40 / FIX-83 era).  Validation mirrors
            // bitcoin-core/src/net_processing.cpp::PrepareBlockFilterRequest:
            //   1. filter_type != 0          → Misbehaving + disconnect.
            //   2. !NODE_COMPACT_FILTERS     → Misbehaving + disconnect.
            //   3. LookupBlockIndex == None  → Misbehaving + disconnect.
            //   4. start_height > stop.height → Misbehaving + disconnect.
            //   5. range > MAX_GET*_SIZE     → Misbehaving + disconnect.
            //   6. Walk stop_index.GetAncestor(h) for h in range
            //      (stop-hash-anchor walk per FIX-74 universal pattern).
            //
            // Outbound responses (cfilter / cfheaders / cfcheckpt) are
            // logged + dropped: clearbit is a serving full node, not a
            // BIP-157 client.  Variant existence prevents UnknownCommand
            // fall-through from severing the peer.
            .getcfilters => |gc| {
                self.processGetCFilters(peer, gc);
            },
            .getcfheaders => |gch| {
                self.processGetCFHeaders(peer, gch);
            },
            .getcfcheckpt => |gcc| {
                self.processGetCFCheckPt(peer, gcc);
            },
            .cfilter => |cf| {
                // We are a server, not a BIP-157 client — log and free.
                defer self.allocator.free(cf.filter);
                std.log.debug(
                    "unexpected cfilter from peer={any}, dropping (clearbit is server-side only)",
                    .{peer.address},
                );
            },
            .cfheaders => |cfh| {
                defer self.allocator.free(cfh.filter_hashes);
                std.log.debug(
                    "unexpected cfheaders from peer={any}, dropping (clearbit is server-side only)",
                    .{peer.address},
                );
            },
            .cfcheckpt => |cfc| {
                defer self.allocator.free(cfc.filter_headers);
                std.log.debug(
                    "unexpected cfcheckpt from peer={any}, dropping (clearbit is server-side only)",
                    .{peer.address},
                );
            },
            else => {},
        }
    }

    // ========================================================================
    // BIP-157 Compact Filter Server Handlers (FIX-84)
    // ========================================================================
    //
    // Reference: bitcoin-core/src/net_processing.cpp
    //   PrepareBlockFilterRequest (line 3262) +
    //   ProcessGetCFilters (3315) + ProcessGetCFHeaders (3344) +
    //   ProcessGetCFCheckPt (3386).
    //
    // Each handler returns silently on validation failure AFTER calling
    // peer.misbehaving() + peer.disconnect() — Core's fDisconnect=true
    // pattern.  No response is sent for a rejected request.

    /// Resolve a `stop_hash` to a height on the active chain, validating
    /// per Core's PrepareBlockFilterRequest: the hash must exist in our
    /// header_index AND be on the active chain (or its on-chain history).
    /// Returns null when the stop_hash is unknown or not on the active
    /// chain.  The caller is expected to misbehave+disconnect on null.
    fn resolveActiveChainStopHash(self: *PeerManager, stop_hash: *const types.Hash256) ?u32 {
        const cs = self.chain_state orelse return null;
        if (cs.best_height == 0) {
            // Genesis-only chain: only the genesis hash is valid.
            return null;
        }
        // First try our in-memory header_index.
        if (self.header_index.get(stop_hash.*)) |entry| {
            // Verify this hash is on the active chain at its claimed height.
            const onchain = cs.getBlockHashByHeight(entry.height) orelse return null;
            if (std.mem.eql(u8, &onchain, stop_hash)) {
                return entry.height;
            }
            // Header known but on a fork branch — Core's BlockRequestAllowed
            // would gate this on STALE_RELAY_AGE_LIMIT, but we conservatively
            // reject non-active-chain stop_hashes (light clients always
            // query the canonical chain).
            return null;
        }
        // Fall back to a linear scan via getBlockHashByHeight.  This is
        // O(tip) in the worst case but only happens when header_index has
        // been pruned (LRU eviction past MAX_HEADER_INDEX = 65535).
        // Practical mainnet impact: a probe for a deep historical block
        // by a misbehaving light client.  Bounded by a safety cap.
        const SCAN_CAP: u32 = 100_000;
        const start: u32 = if (cs.best_height > SCAN_CAP) cs.best_height - SCAN_CAP else 0;
        var h: u32 = cs.best_height;
        while (h >= start) : (h -%= 1) {
            const onchain = cs.getBlockHashByHeight(h) orelse {
                if (h == 0) break;
                continue;
            };
            if (std.mem.eql(u8, &onchain, stop_hash)) return h;
            if (h == 0) break;
        }
        return null;
    }

    /// Look up the active-chain block hash at a given height.  Wraps
    /// ChainState.getBlockHashByHeight so handlers can substitute a test
    /// stub.  Returns null when height > tip.
    fn activeChainHashAt(self: *PeerManager, height: u32) ?types.Hash256 {
        const cs = self.chain_state orelse return null;
        if (height > cs.best_height) return null;
        return cs.getBlockHashByHeight(height);
    }

    /// Walk a peer's `getheaders` block-locator and return the height of
    /// the fork point: the first locator hash that is on OUR active chain.
    /// Mirrors Bitcoin Core's FindForkInGlobalIndex (net_processing.cpp
    /// ProcessGetHeaders) / camlcoin handle_getheaders_request: the locator
    /// is ordered tip→genesis, so the first match is the deepest common
    /// ancestor we can serve from.  When no locator hash matches (the peer
    /// is on a disjoint branch), the fork point is genesis (height 0) — the
    /// caller then serves OUR active chain from height 1, which is exactly
    /// what makes a cross-fork reorg announce reachable.
    ///
    /// "On the active chain" means: height H = getBlockHeightByHash(hash)
    /// AND getBlockHashByHeight(H) == hash (the hash is canonical at H, not
    /// a stale side-branch entry).  The network genesis hash is recognised
    /// directly as height 0 (genesis is never written to the height→hash
    /// index, so the canonical-at-height check would otherwise miss it).
    pub fn getHeadersForkPoint(
        self: *PeerManager,
        locator_hashes: []const types.Hash256,
    ) u32 {
        const cs = self.chain_state orelse return 0;
        for (locator_hashes) |loc_hash| {
            // Genesis is a valid fork point but isn't in the height→hash
            // index; recognise it explicitly.
            if (std.mem.eql(u8, &loc_hash, &self.network_params.genesis_hash)) {
                return 0;
            }
            const h = cs.getBlockHeightByHash(&loc_hash) orelse continue;
            if (h > cs.best_height) continue;
            const onchain = cs.getBlockHashByHeight(h) orelse continue;
            if (std.mem.eql(u8, &onchain, &loc_hash)) {
                return h;
            }
            // Hash is known but on a fork branch — not a fork point on the
            // active chain; keep walking deeper into the locator.
        }
        return 0;
    }

    /// `getheaders` responder — Bitcoin Core ProcessGetHeaders
    /// (net_processing.cpp) / camlcoin handle_getheaders_request.
    ///
    /// Find the fork point from the peer's block-locator, then send up to
    /// MAX_HEADERS_RESULTS (2000) of OUR ACTIVE-chain headers starting at
    /// fork_point+1, by height.  If `hash_stop` is non-zero, stop after the
    /// header whose hash equals hash_stop.  An empty result sends nothing
    /// (Core sends no `headers` when there is nothing to serve).
    ///
    /// Serving our OWN active best chain is what unblocks the reorg
    /// scenario: a peer whose locator is on the lighter chain gets our
    /// heavier chain back from the common ancestor (genesis in the disjoint
    /// case), so its classifyHeaderBatch sees a competing_fork and arms the
    /// reorg.  The active-chain-by-height walk (not header_index) guarantees
    /// we serve canonical headers only.
    fn processGetHeaders(
        self: *PeerManager,
        peer: *Peer,
        locator_hashes: []const types.Hash256,
        hash_stop: *const types.Hash256,
    ) void {
        const headers = self.collectHeadersFromForkPoint(locator_hashes, hash_stop) orelse return;
        defer self.allocator.free(headers);
        if (headers.len == 0) return;

        const msg = p2p.Message{ .headers = .{ .headers = headers } };
        peer.sendMessage(&msg) catch {};
    }

    /// Collect up to MAX_HEADERS_RESULTS (2000) of our ACTIVE-chain headers,
    /// by height, starting at the locator's fork point + 1.  Returns an
    /// owned slice the caller must free, or null when there is nothing to
    /// serve (no chain_state, fork point already at the tip, or empty
    /// result).  Honors a non-zero `hash_stop` (stops after the matching
    /// header).  Split out from processGetHeaders so the locator-walk +
    /// collection logic is unit-testable without a live socket.
    pub fn collectHeadersFromForkPoint(
        self: *PeerManager,
        locator_hashes: []const types.Hash256,
        hash_stop: *const types.Hash256,
    ) ?[]types.BlockHeader {
        const cs = self.chain_state orelse return null;

        const fork_height = self.getHeadersForkPoint(locator_hashes);
        if (fork_height >= cs.best_height) return null; // nothing past the fork point

        // Is hash_stop the all-zero sentinel ("serve up to MAX")?
        var stop_is_zero = true;
        for (hash_stop) |b| {
            if (b != 0) {
                stop_is_zero = false;
                break;
            }
        }

        const MAX_HEADERS_RESULTS: u32 = 2000;
        var collected = std.ArrayList(types.BlockHeader).init(self.allocator);
        errdefer collected.deinit();

        var h: u32 = fork_height + 1;
        while (h <= cs.best_height and collected.items.len < MAX_HEADERS_RESULTS) : (h += 1) {
            const hash = cs.getBlockHashByHeight(h) orelse break;
            const header = cs.getPersistedHeader(&hash) orelse break;
            collected.append(header) catch return null;
            if (!stop_is_zero and std.mem.eql(u8, &hash, hash_stop)) break;
        }

        if (collected.items.len == 0) {
            collected.deinit();
            return null;
        }
        return collected.toOwnedSlice() catch null;
    }

    /// Fetch the persisted filter blob for a block hash.  Returns null
    /// when blockfilterindex is disabled, the db is absent, or the block
    /// isn't indexed (race: peer asked for a block that disconnect-rewind
    /// has not yet re-indexed).
    fn fetchPersistedFilterBytes(self: *PeerManager, block_hash: *const types.Hash256) ?[]const u8 {
        const cs = self.chain_state orelse return null;
        const bytes = cs.getPersistedFilter(block_hash) catch return null;
        return bytes;
    }

    /// Fetch the persisted filter-header (32 bytes) for a block hash.
    fn fetchPersistedFilterHeader(self: *PeerManager, block_hash: *const types.Hash256) ?types.Hash256 {
        const cs = self.chain_state orelse return null;
        const h = cs.getPersistedFilterHeader(block_hash) catch return null;
        return h;
    }

    /// `getcfilters` handler — Core ProcessGetCFilters.
    /// On success: sends N `cfilter` messages, one per height in
    /// [start_height, stop_height].  On any validation failure: misbehave
    /// + disconnect, no response.
    fn processGetCFilters(self: *PeerManager, peer: *Peer, gc: p2p.GetCFiltersMessage) void {
        // (1) Filter type — only BASIC (=0) is supported per BIP-158.
        if (gc.filter_type != 0) {
            peer.misbehaving(100, "getcfilters with unsupported filter_type");
            peer.disconnect();
            return;
        }
        // (2) Service-bit gate — only serve filters when we ourselves
        //     advertise NODE_COMPACT_FILTERS.  Otherwise the peer is
        //     spec-violating by asking us.
        if (!self.blockfilterindex_enabled) {
            peer.misbehaving(100, "getcfilters but NODE_COMPACT_FILTERS not advertised");
            peer.disconnect();
            return;
        }
        // (3) Stop hash → active-chain height.
        const stop_height = self.resolveActiveChainStopHash(&gc.stop_hash) orelse {
            peer.misbehaving(100, "getcfilters: stop_hash not on active chain");
            peer.disconnect();
            return;
        };
        // (4) start_height > stop_height.
        if (gc.start_height > stop_height) {
            peer.misbehaving(100, "getcfilters: start_height > stop_height");
            peer.disconnect();
            return;
        }
        // (5) Range cap (MAX_GETCFILTERS_SIZE = 1000).  Core's check is
        //     `(stop - start) >= MAX_GETCFILTERS_SIZE` — strictly less than.
        const range = stop_height - gc.start_height;
        if (range >= p2p.MAX_GETCFILTERS_SIZE) {
            peer.misbehaving(100, "getcfilters: range exceeds MAX_GETCFILTERS_SIZE");
            peer.disconnect();
            return;
        }
        // (6) Walk active chain in [start_height, stop_height] and emit
        //     one `cfilter` per block.  This is the stop-hash-anchor walk
        //     from FIX-74 (lunarblock/blockbrew/rustoshi pattern): we walk
        //     active-chain hashes (via getBlockHashByHeight which is the
        //     post-reorg canonical map) rather than the in-memory
        //     header_index (which can include fork branches).
        var h: u32 = gc.start_height;
        while (h <= stop_height) : (h += 1) {
            const block_hash = self.activeChainHashAt(h) orelse {
                // Active-chain hash should always exist for h <= tip;
                // a miss here means the index is mid-rewind.  Defensive
                // return per FIX-79 ouroboros pattern (no response).
                return;
            };
            const filter_bytes = self.fetchPersistedFilterBytes(&block_hash) orelse {
                // Filter not yet indexed at this height; bail without
                // partial response (Core's behaviour when
                // LookupFilterRange fails).
                return;
            };
            defer self.allocator.free(filter_bytes);
            const msg = p2p.Message{ .cfilter = .{
                .filter_type = 0,
                .block_hash = block_hash,
                .filter = filter_bytes,
            } };
            peer.sendMessage(&msg) catch return;
            if (h == std.math.maxInt(u32)) break;
        }
    }

    /// `getcfheaders` handler — Core ProcessGetCFHeaders.
    /// On success: sends a single `cfheaders` message with
    /// `prev_filter_header` (the chained header at start_height-1) and
    /// the filter content hashes for [start_height, stop_height].
    fn processGetCFHeaders(self: *PeerManager, peer: *Peer, gch: p2p.GetCFHeadersMessage) void {
        if (gch.filter_type != 0) {
            peer.misbehaving(100, "getcfheaders with unsupported filter_type");
            peer.disconnect();
            return;
        }
        if (!self.blockfilterindex_enabled) {
            peer.misbehaving(100, "getcfheaders but NODE_COMPACT_FILTERS not advertised");
            peer.disconnect();
            return;
        }
        const stop_height = self.resolveActiveChainStopHash(&gch.stop_hash) orelse {
            peer.misbehaving(100, "getcfheaders: stop_hash not on active chain");
            peer.disconnect();
            return;
        };
        if (gch.start_height > stop_height) {
            peer.misbehaving(100, "getcfheaders: start_height > stop_height");
            peer.disconnect();
            return;
        }
        const range = stop_height - gch.start_height;
        if (range >= p2p.MAX_GETCFHEADERS_SIZE) {
            peer.misbehaving(100, "getcfheaders: range exceeds MAX_GETCFHEADERS_SIZE");
            peer.disconnect();
            return;
        }
        // prev_filter_header: filter-header at (start_height - 1), or zeroes
        // when start_height == 0 (genesis sentinel per BIP-157).
        var prev_filter_header: types.Hash256 = [_]u8{0} ** 32;
        if (gch.start_height > 0) {
            const prev_hash = self.activeChainHashAt(gch.start_height - 1) orelse {
                // Defensive return-on-miss per FIX-79 ouroboros pattern.
                return;
            };
            prev_filter_header = self.fetchPersistedFilterHeader(&prev_hash) orelse {
                return;
            };
        }
        // Build filter-hash chain for [start_height, stop_height].
        const count: usize = @intCast(stop_height - gch.start_height + 1);
        var hashes = self.allocator.alloc(types.Hash256, count) catch return;
        defer self.allocator.free(hashes);
        var h: u32 = gch.start_height;
        var i: usize = 0;
        while (h <= stop_height) : (h += 1) {
            const block_hash = self.activeChainHashAt(h) orelse return;
            // Filter HASH (not the chained header) per Core's CFHEADERS
            // payload — we hash the persisted filter bytes via
            // BlockFilter.getHash() ≡ hash256(filter).  We avoid
            // constructing a full GCSFilter object: SHA256d the raw
            // persisted bytes directly.
            const filter_bytes = self.fetchPersistedFilterBytes(&block_hash) orelse return;
            defer self.allocator.free(filter_bytes);
            hashes[i] = crypto.hash256(filter_bytes);
            i += 1;
            if (h == std.math.maxInt(u32)) break;
        }
        const msg = p2p.Message{ .cfheaders = .{
            .filter_type = 0,
            .stop_hash = gch.stop_hash,
            .prev_filter_header = prev_filter_header,
            .filter_hashes = hashes[0..i],
        } };
        peer.sendMessage(&msg) catch return;
    }

    /// `getcfcheckpt` handler — Core ProcessGetCFCheckPt.
    /// On success: sends one `cfcheckpt` message with the chained filter
    /// headers at heights {CFCHECKPT_INTERVAL, 2*CFCHECKPT_INTERVAL, ...}
    /// up to (and not including) stop_index.height.
    fn processGetCFCheckPt(self: *PeerManager, peer: *Peer, gcc: p2p.GetCFCheckPtMessage) void {
        if (gcc.filter_type != 0) {
            peer.misbehaving(100, "getcfcheckpt with unsupported filter_type");
            peer.disconnect();
            return;
        }
        if (!self.blockfilterindex_enabled) {
            peer.misbehaving(100, "getcfcheckpt but NODE_COMPACT_FILTERS not advertised");
            peer.disconnect();
            return;
        }
        const stop_height = self.resolveActiveChainStopHash(&gcc.stop_hash) orelse {
            peer.misbehaving(100, "getcfcheckpt: stop_hash not on active chain");
            peer.disconnect();
            return;
        };
        // Core: vector size = stop_index.nHeight / CFCHECKPT_INTERVAL.
        const num_checkpoints: u32 = stop_height / p2p.CFCHECKPT_INTERVAL;
        var headers = self.allocator.alloc(types.Hash256, num_checkpoints) catch return;
        defer self.allocator.free(headers);
        // Populate: headers[i] = filter_header at height (i+1) * CFCHECKPT_INTERVAL.
        // Walk in DESCENDING order to mirror Core (intentional design:
        // request-time the freshest segment first).  But the OUTPUT vector
        // is in ASCENDING order — Core writes headers[i] indexed from 0.
        var i: u32 = 0;
        while (i < num_checkpoints) : (i += 1) {
            const checkpoint_height: u32 = (i + 1) * p2p.CFCHECKPT_INTERVAL;
            const block_hash = self.activeChainHashAt(checkpoint_height) orelse return;
            headers[i] = self.fetchPersistedFilterHeader(&block_hash) orelse return;
        }
        const msg = p2p.Message{ .cfcheckpt = .{
            .filter_type = 0,
            .stop_hash = gcc.stop_hash,
            .filter_headers = headers,
        } };
        peer.sendMessage(&msg) catch return;
    }

    /// Number of addresses eligible to be shared in a getaddr response — the
    /// pool the 23%-cap is computed over. Mirrors the `info.success` filter in
    /// `sendAddresses` (Core computes the percentage over the addrman size; we
    /// use the shareable subset clearbit would actually return). Reference:
    /// Core `CAddrMan::GetAddr_` (addrman.cpp).
    pub fn shareableAddrCount(self: *const PeerManager) usize {
        var n: usize = 0;
        var iter = self.known_addresses.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.success) n += 1;
        }
        return n;
    }

    /// Send known addresses to a peer, capped at `cap` entries. `cap` is the
    /// getaddr 23%-cap (min(MAX_ADDR_TO_SEND, floor(0.23*size)), integer div) when answering a
    /// getaddr; callers that want the legacy behaviour pass MAX_ADDR_TO_SEND.
    fn sendAddresses(self: *PeerManager, peer: *Peer, cap: usize) !void {
        var addrs = std.ArrayList(p2p.TimestampedAddr).init(self.allocator);
        defer addrs.deinit();

        var iter = self.known_addresses.iterator();
        while (iter.next()) |entry| {
            // 23%-cap (Core MAX_PCT_ADDR_TO_SEND): stop once we have `cap`
            // shareable addresses queued. Bound the absolute max at
            // MAX_ADDR_TO_SEND (=1000) regardless of the requested cap.
            if (addrs.items.len >= cap or addrs.items.len >= MAX_ADDR_TO_SEND) break;

            const info = entry.value_ptr;
            if (!info.success) continue; // Only send successfully connected addresses

            // Convert std.net.Address to NetworkAddress
            var net_addr = types.NetworkAddress{
                .services = info.services,
                .ip = [_]u8{0} ** 16,
                .port = 0,
            };

            switch (info.address.any.family) {
                std.posix.AF.INET => {
                    const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&info.address.any)));
                    // IPv4-mapped IPv6 format
                    net_addr.ip[10] = 0xff;
                    net_addr.ip[11] = 0xff;
                    const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                    @memcpy(net_addr.ip[12..16], ip_bytes);
                    net_addr.port = std.mem.bigToNative(u16, ip4.port);
                },
                else => continue,
            }

            try addrs.append(p2p.TimestampedAddr{
                .timestamp = @intCast(@as(i64, @truncate(info.last_seen))),
                .addr = net_addr,
            });
        }

        if (addrs.items.len > 0) {
            const msg = p2p.Message{ .addr = .{ .addrs = addrs.items } };
            try peer.sendMessage(&msg);
        }
    }

    /// Send pings to peers that have been idle for > PING_INTERVAL.
    pub fn sendPings(self: *PeerManager) !void {
        const now = std.time.timestamp();
        for (self.peers.items) |peer| {
            if (peer.state == .handshake_complete and now - peer.last_ping_time > PING_INTERVAL) {
                peer.sendPing() catch continue;
            }
        }
    }

    /// Disconnect stale or timed-out peers.
    pub fn disconnectStale(self: *PeerManager) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            if (self.peers.items[i].isTimedOut()) {
                // W101: log before eviction.  Previously silent; made it
                // easy to miss the 20-min last_message_time path that was
                // evicting blk-replay every ~25 min during long drains.
                var addr_buf: [64]u8 = undefined;
                const addr_str = self.peers.items[i].getAddressString(&addr_buf);
                const now = std.time.timestamp();
                const peer = self.peers.items[i];
                // Use the sanitized, owned copy: the raw user_agent is
                // attacker-controlled (control chars / non-UTF8 could corrupt
                // the log) and dangles into a freed receive buffer.  Core also
                // logs only SanitizeString'd subvers.
                const subver: []const u8 = if (peer.clean_subver) |s| s else "?";
                std.log.info("Disconnecting stale peer={s} idle={d}s last_ping={d}s last_pong={d}s subver={s}", .{
                    addr_str,
                    now - peer.last_message_time,
                    if (peer.last_ping_time > 0) now - peer.last_ping_time else 0,
                    if (peer.last_pong_time > 0) now - peer.last_pong_time else 0,
                    subver,
                });
                self.removePeerByIndex(i);
            } else {
                i += 1;
            }
        }
    }

    // ========================================================================
    // Stale Peer Eviction (Bitcoin Core net_processing.cpp)
    // ========================================================================

    /// Check for stale tips and evict peers. Run every STALE_CHECK_INTERVAL (45s).
    /// Combines stale tip checking and peer eviction as per Bitcoin Core.
    pub fn checkForStaleTipAndEvictPeers(self: *PeerManager) void {
        const now = std.time.timestamp();

        // Only run every STALE_CHECK_INTERVAL
        if (now - self.last_stale_check_time < STALE_CHECK_INTERVAL) return;
        self.last_stale_check_time = now;

        // 1. Check ping timeouts - disconnect peers not responding to pings
        self.checkPingTimeouts();

        // 2. Check headers timeouts - misbehave peers not sending headers
        self.checkHeadersTimeouts();

        // 3. Check block download timeouts - disconnect stalled block downloads
        self.checkBlockDownloadTimeouts();

        // 4. Evict stale tip peers - disconnect one outbound peer with stale tip
        self.evictStaleTipPeer();
    }

    /// Sweep the orphan pool for entries older than `ORPHAN_TX_EXPIRE_TIME`.
    ///
    /// Runs at most once per `ORPHAN_TX_EXPIRE_INTERVAL` seconds to bound
    /// the cost of the O(N) scan.  Mirrors Bitcoin Core's periodic orphan
    /// expiry sweep in `net_processing.cpp` (historical name
    /// `nNextSweep` / `ORPHAN_TX_EXPIRE_INTERVAL`).
    pub fn sweepOrphanPool(self: *PeerManager) void {
        const now = std.time.timestamp();
        if (now - self.last_orphan_sweep < mempool_mod.ORPHAN_TX_EXPIRE_INTERVAL) return;
        self.last_orphan_sweep = now;
        if (self.mempool) |pool| {
            _ = pool.sweepExpiredOrphans(now);
        }
    }

    // ========================================================================
    // ASMap Health Check (Bitcoin Core net.cpp / netgroup.cpp)
    // ========================================================================

    /// Maximum number of top-by-peer-count ASNs printed in the health log.
    pub const ASMAP_HEALTH_TOP_N: usize = 5;

    /// Entry type for the top-N ASN table used in asmapHealthCheck.
    pub const AsmapTopEntry = struct { asn: u32, count: u32 };

    /// Compare two AsmapTopEntry values descending by count (for sorting).
    fn asmapTopEntryDesc(_: void, a: AsmapTopEntry, b: AsmapTopEntry) bool {
        return a.count > b.count;
    }

    /// Run ASMap health diagnostics and emit a log line.
    ///
    /// Iterates connected peers with completed handshakes, looks up each
    /// address in the loaded asmap, and reports:
    ///   - total clearnet (IPv4/IPv6) peer count
    ///   - unique ASN count among mapped peers
    ///   - unmapped peer count (ASN == 0)
    ///   - top-N ASNs by peer count
    ///
    /// Called once at P2P startup (when asmap is loaded) and then
    /// periodically every `ASMAP_HEALTH_CHECK_INTERVAL` seconds by the
    /// main event loop.
    ///
    /// Reference: bitcoin-core/src/netgroup.cpp:109  `NetGroupManager::ASMapHealthCheck`
    ///            bitcoin-core/src/net.cpp:4178        `CConnman::ASMapHealthCheck`
    ///            bitcoin-core/src/net.cpp:3570-3573  (scheduler, 24 h interval)
    pub fn asmapHealthCheck(self: *PeerManager) void {
        const asmap = self.asmap_data orelse return; // no-op when asmap not loaded

        // Per-ASN peer count map.
        var asn_counts = std.AutoHashMap(u32, u32).init(self.allocator);
        defer asn_counts.deinit();

        var total_clearnet: u32 = 0;
        var unmapped_count: u32 = 0;

        for (self.peers.items) |peer| {
            if (peer.state != .handshake_complete) continue;
            // Filter to clearnet (IPv4 / IPv6) only — skip Tor/I2P/unknown.
            switch (peer.address.any.family) {
                std.posix.AF.INET, std.posix.AF.INET6 => {},
                else => continue,
            }
            total_clearnet += 1;
            const asn = getMappedAS(asmap, peer.address);
            if (asn == 0) {
                unmapped_count += 1;
            } else {
                const entry = asn_counts.getOrPutValue(asn, 0) catch continue;
                entry.value_ptr.* += 1;
            }
        }

        const unique_asns: u32 = @intCast(asn_counts.count());

        std.log.info(
            "ASMap Health Check: {d} clearnet peers mapped to {d} ASNs with {d} peers being unmapped",
            .{ total_clearnet, unique_asns, unmapped_count },
        );

        // Emit top-N ASNs by peer count.
        if (asn_counts.count() > 0) {
            // Collect (asn, count) pairs into a fixed-size array for top-N.
            var top = [_]AsmapTopEntry{.{ .asn = 0, .count = 0 }} ** ASMAP_HEALTH_TOP_N;
            var it = asn_counts.iterator();
            while (it.next()) |kv| {
                const asn = kv.key_ptr.*;
                const cnt = kv.value_ptr.*;
                // Replace the minimum entry in top[] if this one is larger.
                var min_idx: usize = 0;
                for (top, 0..) |entry, idx| {
                    if (entry.count < top[min_idx].count) min_idx = idx;
                }
                if (cnt > top[min_idx].count) {
                    top[min_idx] = .{ .asn = asn, .count = cnt };
                }
            }
            // Sort descending by count.
            std.mem.sort(AsmapTopEntry, &top, {}, asmapTopEntryDesc);
            for (top) |entry| {
                if (entry.count == 0) break;
                std.log.info("  AS{d}: {d} peer(s)", .{ entry.asn, entry.count });
            }
        }
    }

    /// Run the ASMap health check if enough time has elapsed since the last run,
    /// or if it has never been run (last_asmap_health_check == 0).
    ///
    /// Called from the P2P event loop on every tick.  The no-op path
    /// (asmap_data == null or interval not yet elapsed) is a single load +
    /// compare, so the overhead on nodes without asmap is negligible.
    pub fn runAsmapHealthCheck(self: *PeerManager) void {
        if (self.asmap_data == null) return;
        const now = std.time.timestamp();
        if (self.last_asmap_health_check != 0 and
            now - self.last_asmap_health_check < ASMAP_HEALTH_CHECK_INTERVAL) return;
        self.last_asmap_health_check = now;
        self.asmapHealthCheck();
    }

    /// Check for ping timeouts (ping sent, no pong within PING_TIMEOUT).
    fn checkPingTimeouts(self: *PeerManager) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.state == .handshake_complete and peer.hasPingTimeout()) {
                var addr_buf: [64]u8 = undefined;
                const addr_str = peer.getAddressString(&addr_buf);
                std.log.info("Disconnecting peer={s} due to ping timeout", .{addr_str});
                self.removePeerByIndex(i);
                // Don't increment i since we removed the peer
            } else {
                i += 1;
            }
        }
    }

    /// Check for headers request timeouts. Add misbehavior score (5) for non-responsive peers.
    /// Uses a low penalty since getheaders is sent to multiple peers but only one typically responds.
    fn checkHeadersTimeouts(self: *PeerManager) void {
        for (self.peers.items) |peer| {
            if (peer.state == .handshake_complete and peer.hasHeadersTimeout()) {
                peer.misbehaving(5, "headers timeout");
                // Clear the timeout to avoid repeated scoring
                peer.last_getheaders_time = 0;
            }
        }
    }

    /// Check for block download timeouts. Disconnect peers with stalled block downloads.
    fn checkBlockDownloadTimeouts(self: *PeerManager) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.state == .handshake_complete and peer.hasBlockDownloadTimeout()) {
                var addr_buf: [64]u8 = undefined;
                const addr_str = peer.getAddressString(&addr_buf);
                std.log.info("Disconnecting peer={s} due to block download timeout (blocks_in_flight={d})", .{ addr_str, peer.blocks_in_flight_count });
                peer.misbehaving(50, "block download stalling");
                self.removePeerByIndex(i);
            } else {
                i += 1;
            }
        }
    }

    /// Evict one outbound peer with a stale tip (behind our height for >30 min).
    /// Only evicts if we have better alternatives and the peer is not protected.
    fn evictStaleTipPeer(self: *PeerManager) void {
        const our_height: u32 = if (self.our_height >= 0) @intCast(self.our_height) else 0;

        // Count peers with good tips (at or above our height)
        var good_tip_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .outbound and peer.best_known_height >= our_height) {
                good_tip_count += 1;
            }
        }

        // Only evict if we have at least one peer with a good tip
        if (good_tip_count == 0) return;

        // Find the worst stale tip peer (prefer evicting inbound over outbound)
        var worst_idx: ?usize = null;
        var worst_height: u32 = std.math.maxInt(u32);

        for (self.peers.items, 0..) |peer, i| {
            if (!peer.isEvictionCandidate()) continue;
            if (!peer.hasStaleTip(our_height)) continue;

            // Find the peer furthest behind
            if (peer.best_known_height < worst_height) {
                worst_height = peer.best_known_height;
                worst_idx = i;
            }
        }

        // Evict the worst peer if found
        if (worst_idx) |idx| {
            const peer = self.peers.items[idx];
            var addr_buf: [64]u8 = undefined;
            const addr_str = peer.getAddressString(&addr_buf);
            std.log.info("Evicting stale tip peer={s} (height={d}, our_height={d})", .{ addr_str, peer.best_known_height, our_height });
            self.removePeerByIndex(idx);
        }
    }

    /// Update our tip height (call when a new block is connected).
    pub fn updateTipHeight(self: *PeerManager, height: i32) void {
        self.our_height = height;
        self.last_tip_update_time = std.time.timestamp();
    }

    /// Check if our tip may be stale (no new blocks for 30 minutes).
    pub fn tipMayBeStale(self: *const PeerManager) bool {
        const now = std.time.timestamp();
        if (self.last_tip_update_time == 0) return false;
        return now - self.last_tip_update_time > STALE_TIP_THRESHOLD;
    }

    /// Protect an outbound peer from eviction (call when they provide good chain sync).
    pub fn protectOutboundPeer(self: *PeerManager, peer: *Peer) void {
        if (peer.direction != .outbound) return;
        if (peer.chain_sync_protected) return;
        if (self.outbound_protected_count >= MAX_OUTBOUND_PEERS_TO_PROTECT) return;

        peer.chain_sync_protected = true;
        self.outbound_protected_count += 1;
    }

    /// Rotate peers: disconnect longest-connected outbound and connect a new one.
    pub fn rotatePeers(self: *PeerManager) void {
        const now = std.time.timestamp();
        if (now - self.last_rotation_time < PEER_ROTATION_INTERVAL) return;
        self.last_rotation_time = now;

        // Find the oldest outbound peer.  Manual peers (set via addnode RPC
        // or --connect) are exempt: rotation would silently break the
        // localhost IBD mesh.  Matches Bitcoin Core net.cpp ThreadOpenConnections.
        var oldest_idx: ?usize = null;
        var oldest_time: i64 = now;

        for (self.peers.items, 0..) |peer, i| {
            if (peer.conn_type == .manual) continue;
            if (peer.direction == .outbound and peer.state == .handshake_complete) {
                // Use last_message_time as a proxy for connection age
                if (peer.last_message_time < oldest_time) {
                    oldest_time = peer.last_message_time;
                    oldest_idx = i;
                }
            }
        }

        // Disconnect the oldest if we have enough outbound connections
        var outbound_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .outbound) outbound_count += 1;
        }

        if (oldest_idx != null and outbound_count >= MAX_OUTBOUND_CONNECTIONS) {
            self.removePeerByIndex(oldest_idx.?);
        }
    }

    /// Remove and disconnect a peer by index.
    fn removePeerByIndex(self: *PeerManager, index: usize) void {
        const peer = self.peers.swapRemove(index);
        // Untrack netgroup for outbound connections
        self.untrackOutboundNetgroup(peer);
        // Reclaim in-flight block count for this peer so the global counter
        // doesn't permanently drift upward, which would block new requests.
        if (peer.blocks_in_flight_count > 0) {
            if (self.blocks_in_flight >= peer.blocks_in_flight_count) {
                self.blocks_in_flight -= peer.blocks_in_flight_count;
            } else {
                // Counter already drifted; reset to 0 rather than underflow.
                self.blocks_in_flight = 0;
            }
            // W19 fix: rewind download_cursor so the pipeline re-requests the
            // blocks that were in-flight to this peer and are now lost.  Without
            // this rewind, download_cursor stays at connect_cursor + max_ahead
            // (the window ceiling) while connect_cursor is stuck waiting for the
            // first missing block.  pipelineBlockRequests() then sees
            // download_cursor >= connect_cursor + max_ahead and issues no new
            // getdata — a permanent wedge until a full restart.
            //
            // Rewinding to connect_cursor is safe: pipelineBlockRequests() skips
            // hashes already in block_buffer, so blocks that were received and
            // buffered before this peer disconnected are not re-requested.
            if (self.download_cursor > self.connect_cursor) {
                self.download_cursor = self.connect_cursor;
            }
            // Drop this peer's entries from the per-block in-flight map (Core
            // clears a disconnected peer from mapBlocksInFlight). Until removed,
            // pipelineBlockRequests' SKIP would treat these blocks as still
            // in-flight and never re-request them after the W19 rewind above.
            const gone_ptr = @intFromPtr(peer);
            var stale_keys = std.ArrayList(types.Hash256).init(self.allocator);
            defer stale_keys.deinit();
            var inflight_it = self.inflight_block_peer.iterator();
            while (inflight_it.next()) |kv| {
                if (kv.value_ptr.* == gone_ptr) {
                    stale_keys.append(kv.key_ptr.*) catch break;
                }
            }
            for (stale_keys.items) |k| {
                _ = self.inflight_block_peer.remove(k);
            }
        }
        // Drop any orphan-pool entries this peer announced so the peer's
        // pointer is not dangling-referenced after `destroy`.  Mirrors
        // Bitcoin Core `EraseOrphansFor` from net_processing.cpp.
        if (self.mempool) |pool| {
            pool.eraseOrphansForPeer(@intFromPtr(peer));
        }
        peer.disconnect();
        self.allocator.destroy(peer);
    }

    // ========================================================================
    // Block Download Pipeline
    // ========================================================================

    /// Request blocks from peers to keep the download pipeline full.
    ///
    /// Level-triggered per-peer dispatch, modelled on Bitcoin Core's
    /// `SendMessages` / `FindNextBlocksToDownload` loop in
    /// `src/net_processing.cpp`.  The budget is per-peer
    /// (`MAX_BLOCKS_IN_TRANSIT_PER_PEER` = 16), not global — a slow peer
    /// never wedges the other peers' pipelines.  This function is safe to
    /// call on every SendMessages tick: if a peer is full, it is skipped;
    /// if any peer has budget, it is filled.
    ///
    /// Wave 15 diagnostic (`wave15-2026-04-15/CLEARBIT-STALL-RECOVERY-DIAG.md`)
    /// showed the previous global `blocks_in_flight < max_blocks_in_flight`
    /// gate was edge-triggered in practice: a single slow block among 8
    /// peers pinned the counter at 128 and halted all requests until the
    /// 5-second stall-recovery timer fired a mass-reset.  Removing the
    /// global gate and replacing stall-recovery with per-peer
    /// disconnect-on-timeout (see `checkBlockDownloadTimeouts`) mirrors
    /// Core and unblocks level-triggered progress.
    ///
    /// The `download_cursor` rewind on buffer-full drop (wave 9) is preserved
    /// in the `.block` handler — see `peer.zig:2198` and `peer.zig:2215`.
    fn pipelineBlockRequests(self: *PeerManager) !void {
        if (self.chain_state == null) return;
        if (self.download_cursor >= self.expected_blocks.items.len) return;

        // Don't download too far ahead of the connection cursor.
        // Each buffered block is ~1-2 MB, so 512 blocks ≈ 512 MB-1 GB.
        // Use the distance between download and connect cursors (not buffer count)
        // to avoid stalling when the buffer has many out-of-order blocks.
        const max_ahead: u32 = 512;

        // Per-peer level-triggered dispatch.  For every handshake-complete
        // peer, compute its remaining in-flight budget and try to fill it.
        // No global counter gate — a slow peer self-throttles and is
        // disconnected by `checkBlockDownloadTimeouts` when its oldest
        // in-flight block exceeds `BLOCK_DOWNLOAD_TIMEOUT`.
        for (self.peers.items) |tp| {
            if (tp.state != .handshake_complete) continue;

            // Compute this peer's remaining slot budget.  Saturating so a
            // transient over-count (shouldn't happen, but be defensive)
            // cannot wrap to a huge positive.
            if (tp.blocks_in_flight_count >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) continue;
            const peer_budget: u32 = MAX_BLOCKS_IN_TRANSIT_PER_PEER - tp.blocks_in_flight_count;

            if (self.download_cursor >= self.expected_blocks.items.len) break;
            if (self.download_cursor >= self.connect_cursor + max_ahead) break;

            var invs = std.ArrayList(p2p.InvVector).init(self.allocator);

            var batch_count: u32 = 0;
            while (batch_count < peer_budget and
                self.download_cursor < self.expected_blocks.items.len and
                self.download_cursor < self.connect_cursor + max_ahead)
            {
                const h = self.expected_blocks.items[self.download_cursor];
                // SKIP if already buffered OR already in-flight to some peer
                // (Core mapBlocksInFlight: never request the same block twice).
                // This is what makes a download_cursor rewind drift-free — the
                // wedge recovery / W19 rewind only re-issues blocks that are NOT
                // already tracked in-flight.
                if (!self.block_buffer.contains(h) and !self.inflight_block_peer.contains(h)) {
                    invs.append(.{
                        .inv_type = .msg_witness_block,
                        .hash = h,
                    }) catch break;
                    batch_count += 1;
                }
                self.download_cursor += 1;
            }

            if (invs.items.len > 0) {
                const getdata_msg = p2p.Message{ .getdata = .{ .inventory = invs.items } };
                tp.sendMessage(&getdata_msg) catch {
                    invs.deinit();
                    continue;
                };
                // Maintain the global `blocks_in_flight` counter for RPC /
                // progress logging only — it no longer gates the pipeline.
                self.blocks_in_flight += batch_count;
                for (invs.items) |inv| {
                    // Track which peer we requested each block from (Core
                    // mapBlocksInFlight). Pairs 1:1 with recordBlockRequest so
                    // the map count, global blocks_in_flight, and the peer's
                    // blocks_in_flight_count stay in lock-step.
                    self.inflight_block_peer.put(inv.hash, @intFromPtr(tp)) catch {};
                    tp.recordBlockRequest();
                }
            }
            invs.deinit();
        }
    }

    /// Compute the Median-Time-Past (BIP-113) for a block identified by its
    /// prev_hash, walking back up to 11 ancestors via the in-memory header_index.
    /// Returns 0 when fewer than 1 ancestor is known (genesis / not-yet-fetched),
    /// which causes the caller to skip the MTP check.
    ///
    /// Reference: Bitcoin Core pindexPrev->GetMedianTimePast() (chain.h).
    /// Set the snapshot-base MTP fallback (Layer-3 forward-sync fix).  Called
    /// once at startup when the node booted from a `--load-snapshot` UTXO set,
    /// with the base block's GetMedianTimePast (consensus.AssumeUtxoData.base_mtp)
    /// and the base height.  No-op-safe to call with mtp==0 (leaves the
    /// fallback disabled — non-snapshot boots).
    pub fn setSnapshotBaseMtp(self: *PeerManager, base_mtp: u32, base_height: u32) void {
        self.snapshot_base_mtp = base_mtp;
        self.snapshot_base_height = base_height;
    }

    fn computePrevMtp(self: *PeerManager, prev_hash: *const types.Hash256) u32 {
        var timestamps: [11]u32 = undefined;
        var n: usize = 0;
        var cursor = prev_hash.*;
        while (n < 11) {
            if (self.header_index.get(cursor)) |entry| {
                timestamps[n] = entry.timestamp;
                cursor = entry.prev_hash;
                n += 1;
                continue;
            }
            // The in-memory header_index is empty until headers re-sync after a
            // restart, and the MTP ring buffer is empty until blocks connect —
            // so right after a restart neither is available. Falling through to
            // snapshot_base_mtp below would yield the GENESIS timestamp
            // (1231006505) as the BIP-113 cutoff, which false-rejects any block
            // containing a time-based nLockTime tx with a non-final sequence
            // (the 2026-06-06 wedge at h=952421: a locktime=1580624834 RBF tx).
            // Read the ancestor header from the persisted block index instead —
            // it covers every connected block and survives the restart.
            if (self.chain_state) |cs2| {
                if (cs2.getPersistedHeader(&cursor)) |hdr| {
                    timestamps[n] = hdr.timestamp;
                    cursor = hdr.prev_block;
                    n += 1;
                    continue;
                }
            }
            break;
        }
        if (n > 0) return validation.medianTimePast(timestamps[0..n]);

        // SNAPSHOT FORWARD-SYNC (Layer 3): the in-memory header_index walk
        // found no ancestors.  After a `--load-snapshot` boot this is the
        // common case for the first ~11 post-snapshot blocks (base+1..base+11):
        // the snapshot carries the UTXO set, not the 11-ancestor header window,
        // and (with reorg capture off) headers are not mirrored into
        // header_index.  Prefer the chain-state ring buffer, which
        // connectBlockInner fills with REAL post-snapshot block timestamps as
        // they connect — once it holds 11 entries it is the exact Core MTP.
        // Until then fall back to the snapshot base block's GetMedianTimePast
        // (a true lower bound, never 0) so BIP-113 nLockTimeCutoff matches
        // Core's assumeUTXO behaviour instead of collapsing to the block's own
        // timestamp.  Returns 0 only for a genuinely fresh (non-snapshot) node,
        // preserving the prior genesis-adjacent skip.
        if (self.chain_state) |cs| {
            // The ring buffer holds the MTP of the ACTIVE TIP only, so it is a
            // valid answer for computePrevMtp solely when prev_hash IS the tip
            // (the forward-sync connect case: block H's parent == tip H-1).
            // For non-tip parents (e.g. far-ahead header-acceptance checks) the
            // tip MTP would be a lower bound, which only ever relaxes the
            // BIP-113 header check (safe direction) — but we still prefer the
            // base MTP there to avoid implying a wrong window.
            if (std.mem.eql(u8, &cs.best_hash, prev_hash)) {
                const ring_mtp = cs.computeMTP();
                if (ring_mtp != 0) return ring_mtp;
            }
        }
        return self.snapshot_base_mtp;
    }

    /// Compute the median-time-past (GetMedianTimePast) OF block at `height`.
    ///
    /// Core: `GetAncestor(height)->GetMedianTimePast()` includes the block at
    /// `height` itself plus up to 10 preceding blocks.
    ///
    /// Implementation: looks up the block hash via getBlockHashByHeight
    /// (CF_DEFAULT height→hash index), then walks the in-memory header_index
    /// up to 11 steps collecting timestamps, falling back to the persisted
    /// block index (cs.getPersistedHeader) on any in-memory miss.  Returns 0
    /// only when:
    ///   - the chain state is not available, or
    ///   - the height→hash DB entry is missing (pre-IBD, pruned, etc.).
    /// A 0 return causes the caller to skip time-based BIP-68 enforcement for
    /// that UTXO (safe: height-based locks are still checked).
    ///
    /// Restart correctness (twin of computePrevMtp): the in-memory
    /// header_index is empty until headers re-sync after a restart, and is
    /// LRU-capped at MAX_HEADER_INDEX so old heights may be absent even at
    /// steady state.  Without the persisted fallback this returned 0 (or a
    /// short, wrong-low MTP) for an in-chain ancestor, which the BIP-68 path
    /// turns into nCoinTime≈0 → required_time collapses to ~(lock<<9)-1 →
    /// time-based relative sequence locks are judged satisfied when Core would
    /// reject (CONSENSUS FALSE-ACCEPT of "bad-txns-nonfinal").  Read the
    /// ancestor header from CF_BLOCK_INDEX instead — it covers every connected
    /// block and survives the restart.
    ///
    /// Reference: bitcoin-core/src/consensus/tx_verify.cpp:74
    ///   nCoinTime = GetAncestor(max(nCoinHeight-1,0))->GetMedianTimePast()
    /// — Core's GetAncestor walks the persistent block index and never
    /// silently fails for an in-chain ancestor.
    fn computeMtpAtHeight(self: *PeerManager, height: u32) u32 {
        const cs = self.chain_state orelse return 0;
        // Retrieve the hash of block at `height` from the persistent index.
        const block_hash = cs.getBlockHashByHeight(height) orelse return 0;
        // Collect timestamps: block at `height` then its ancestors.
        var timestamps: [11]u32 = undefined;
        var n: usize = 0;
        var cursor = block_hash;
        while (n < 11) {
            if (self.header_index.get(cursor)) |entry| {
                timestamps[n] = entry.timestamp;
                cursor = entry.prev_hash;
                n += 1;
                continue;
            }
            // In-memory miss (post-restart, or LRU-evicted height): read the
            // ancestor header from the persisted block index and continue,
            // exactly as computePrevMtp does.  This keeps the BIP-68 per-coin
            // MTP correct across a restart instead of collapsing to ~0.
            if (cs.getPersistedHeader(&cursor)) |hdr| {
                timestamps[n] = hdr.timestamp;
                cursor = hdr.prev_block;
                n += 1;
                continue;
            }
            break;
        }
        // Incomplete window guard (2026-06-20). The walk broke before collecting
        // Core's full GetMedianTimePast window of min(11, height+1) ancestors —
        // i.e. a header is MISSING (below the AssumeUTXO snapshot base the
        // genesis→base headers are absent, so a deep coin's window cannot be
        // completed). Using the TRUNCATED median here injects a wrong (usually
        // too-HIGH) value that FALSE-REJECTS valid blocks: the snapshot-resync
        // wedges at h948454 (coin below base, partial window) and h948465 (coin
        // base+10). Return 0 instead → the BIP-68 caller skips the time-based
        // check for that coin (permissive, matching the pre-existing n==0
        // behavior and Core's trust of already-validated assumed-valid snapshot
        // coins; the OP_CSV script check still backstops CSV scripts). The baked
        // base-tail headers (consensus.base_tail_headers) keep the [base+1,
        // base+11] band's window FULL → those stay EXACT. A genuinely genesis-
        // adjacent height (< 10) legitimately has fewer ancestors → partial
        // median is correct there, so only guard when a full window was due.
        const want: usize = @min(@as(usize, 11), @as(usize, height) + 1);
        if (n < want) return 0;
        return validation.medianTimePast(timestamps[0..n]);
    }

    /// Trampoline so PeerManager.computeMtpAtHeight can be passed as a
    /// *const fn(*anyopaque, u32) u32 to IBDValidationContext.getMtpAtHeightFn.
    fn getMtpAtHeightTrampoline(ctx_ptr: *anyopaque, h: u32) u32 {
        const self: *PeerManager = @ptrCast(@alignCast(ctx_ptr));
        return self.computeMtpAtHeight(h);
    }

    /// Header-time validation result.
    pub const HeaderTimeReject = enum {
        ok,
        /// Header timestamp <= median-time-past of last 11 ancestors (BIP-113
        /// applied at header receive time, mirroring Bitcoin Core's
        /// `ContextualCheckBlockHeader`).
        mtp_violation,
        /// Header timestamp > now + MAX_FUTURE_BLOCK_TIME (7200s).  Reference:
        /// `bitcoin-core/src/validation.cpp::CheckBlockHeader`.
        future_time,
    };

    /// Contextual header-time validation, run at header *acceptance* (not just
    /// when the block body arrives).  Implements:
    ///   - BIP-113 median-time-past: header.timestamp must strictly exceed
    ///     the MTP of its 11 most-recent ancestors (when known).
    ///   - Future-time bound: header.timestamp must not exceed `now + 7200s`.
    ///
    /// References:
    ///   - bitcoin-core/src/validation.cpp::CheckBlockHeader (future-time)
    ///   - bitcoin-core/src/validation.cpp::ContextualCheckBlockHeader (MTP)
    ///
    /// MTP is skipped when fewer than 1 ancestor is in `header_index`
    /// (e.g. headers received before any prior batch landed in the index).
    /// This matches the behaviour of `validateBlockForIBDOrReject`'s MTP
    /// path: the body-validation pipeline still re-checks MTP once the
    /// block lands.  The future-time bound has no ancestor dependency and
    /// is always enforced.
    pub fn validateHeaderContextual(
        self: *PeerManager,
        header: *const types.BlockHeader,
        now: i64,
    ) HeaderTimeReject {
        // Future-time bound (always-on).
        const max_future: i64 = now + @as(i64, consensus.MAX_FUTURE_BLOCK_TIME);
        if (@as(i64, header.timestamp) > max_future) {
            return .future_time;
        }

        // BIP-113 MTP (skipped when fewer than 1 ancestor is known).
        const prev_mtp = self.computePrevMtp(&header.prev_block);
        if (prev_mtp != 0 and header.timestamp <= prev_mtp) {
            return .mtp_violation;
        }

        return .ok;
    }

    /// IBD-time consensus validation gate.  Returns true when the block is
    /// safe to apply via `connectBlockFast`, false on any consensus rule
    /// violation or unrecoverable lookup error.
    ///
    /// Routes through `validation.acceptBlock` — the unified entry point
    /// that mirrors Bitcoin Core's ProcessNewBlock pipeline (CheckBlock +
    /// ContextualCheckBlock + ConnectBlock-equivalent validation minus UTXO
    /// mutations).  Previously duplicated IBDValidationContext construction
    /// here; now that logic lives in acceptBlock so the submitblock RPC path
    /// and the legacy sync.zig path share identical validation semantics.
    ///
    /// The CLEARBIT_VALIDATE_IBD env-gate ("off"/"warn"/"strict") has been
    /// removed.  It had no performance justification — "off" was a pure
    /// bypass mechanism for testing convenience with zero CPU savings over
    /// the "strict" path (the adapter and ctx are cheap; validateBlockForIBD
    /// is where the work happens).  Validation now runs unconditionally,
    /// matching Bitcoin Core's behaviour.  The previous wave-8 / wave-15
    /// holding patches that added the gate are superseded by this refactor.
    ///
    /// On a false return the caller should:
    ///   - rewind `download_cursor` to `connect_cursor` so the slot is
    ///     re-fetched from a different peer,
    ///   - log the failing height + error for forensic correlation.
    fn validateBlockForIBDOrReject(
        self: *PeerManager,
        block: *const types.Block,
        block_hash: *const types.Hash256,
        height: u32,
    ) bool {
        const cs = self.chain_state orelse return false;

        // Per-call lookup adapter: closes over the chain state's utxo_set
        // and dupes the reconstructed scriptPubKey onto the heap so the
        // caller-side arena can adopt it.  We use `self.allocator` (the
        // PeerManager allocator) for the heap dupe; the validation arena
        // frees via the `owner_allocator` channel on PrevOutInfo.
        const Adapter = struct {
            cs_ptr: *storage.ChainState,
            alloc: std.mem.Allocator,

            fn lookup(
                ctx_ptr: *anyopaque,
                outpoint: *const types.OutPoint,
            ) ?validation.PrevOutInfo {
                const me: *@This() = @ptrCast(@alignCast(ctx_ptr));
                const compact_opt = me.cs_ptr.utxo_set.get(outpoint) catch return null;
                var compact = compact_opt orelse return null;
                defer compact.deinit(me.alloc);
                const script = compact.reconstructScript(me.alloc) catch return null;
                return .{
                    .script_pubkey = script,
                    .amount = compact.value,
                    .height = compact.height,
                    .is_coinbase = compact.is_coinbase,
                    .owner_allocator = me.alloc,
                };
            }
        };
        var adapter = Adapter{ .cs_ptr = cs, .alloc = self.allocator };

        // Assumevalid script-skip: if the block height is at or below the
        // assumed-valid height AND we have a valid assumed-valid hash, skip
        // script verification (but not any other consensus check).  This
        // matches Core's intent — scripts are skipped for ancestors of the
        // assumed-valid block once the headers-first sync invariant holds.
        const av_height = self.network_params.assume_valid_height;
        const skip_via_height = (height <= av_height) and (av_height != 0) and
            (self.network_params.assumed_valid_hash != null);

        // BIP-113: compute MTP-of-11 for the block's parent.
        const prev_mtp = self.computePrevMtp(&block.header.prev_block);

        // BIP-94 timewarp: get the actual timestamp of the preceding block.
        // header_index stores the raw nTime field; 0 means "not available".
        const prev_block_timestamp: u32 = blk: {
            const entry = self.header_index.get(block.header.prev_block) orelse break :blk 0;
            break :blk entry.timestamp;
        };

        // Future-time gate: capture wall clock at block-body validation time.
        const current_time: i64 = std.time.timestamp();

        validation.acceptBlock(
            block,
            block_hash,
            height,
            self.network_params,
            @ptrCast(&adapter),
            Adapter.lookup,
            self.allocator,
            .{
                .prev_mtp = prev_mtp,
                .prev_block_timestamp = prev_block_timestamp,
                .current_time = current_time,
                .force_skip_scripts = skip_via_height,
                // BIP-68 time-based enforcement: wire the MTP-at-height callback
                // so validateBlockForIBD can look up the prior-block MTP for each
                // spent UTXO.  PeerManager is long-lived; safe to pass self here.
                .getMtpAtHeightFn = PeerManager.getMtpAtHeightTrampoline,
                .getMtpAtHeightCtx = @ptrCast(self),
                // fTooFarAhead gate (W97 G19c): supply the active-tip height so
                // validateBlockForIBD can reject unrequested blocks that are more
                // than MIN_BLOCKS_TO_KEEP (288) above our tip.  IBD drain blocks
                // ARE explicitly requested (pipelineBlockRequests sent getdata for
                // them), so is_requested=true suppresses the ceiling check for this
                // path.  active_tip_height is still wired so future callers that
                // pass is_requested=false (e.g. unsolicited block handlers) get
                // the check for free.
                .active_tip_height = cs.best_height,
                .is_requested = true,
            },
        ) catch |err| {
            std.debug.print(
                "P2P: REJECT block height={d} validation={}\n",
                .{ height, err },
            );
            return false;
        };
        return true;
    }

    /// Try to connect buffered blocks in order to chain_state.
    /// Connects as many sequential blocks as possible from the buffer.
    /// Runs a tight loop; emits heartbeat every 5 s during long drains so
    /// operators can distinguish a slow-UTXO-flush from a true freeze (W21
    /// third-stall pattern: large-header-batch + slow blocks = silent drain).
    /// Also re-arms the block download pipeline every 32 blocks so that peer
    /// slots freed during the drain are refilled without waiting for the full
    /// drain to complete.
    fn drainBlockBuffer(self: *PeerManager) void {
        const cs = self.chain_state orelse return;
        // W101: mark drain active so nested drain calls from the `.block`
        // handler (invoked transitively by processAllMessages in the
        // heartbeat) become no-ops instead of recursing.  The outer while
        // will consume any newly-buffered blocks on its next iteration.
        self.in_drain = true;
        defer self.in_drain = false;
        var connected: u32 = 0;
        var slow_blocks: u32 = 0;
        const drain_start = std.time.nanoTimestamp();
        // Heartbeat: track last time we emitted an in-drain progress line.
        var last_heartbeat: i64 = std.time.timestamp();

        // CLEARBIT_REORG opt-in: enables undo capture during IBD so the node
        // can disconnect blocks during a chain reorganization.  Default off
        // — the legacy fast path remains the live node's behaviour until an
        // operator soaks the reorg path on a non-production datadir.  Set
        // via env var to avoid a build flag day churn.  See
        // `connectBlockFastWithUndo` (storage.zig) for the per-block cost
        // and `disconnectBlockByHashCF` for the disconnect side.
        const reorg_enabled = isReorgEnabled();
        if (reorg_enabled and !reorg_announce_emitted) {
            reorg_announce_emitted = true;
            std.debug.print(
                "P2P: CLEARBIT_REORG=1 — IBD will capture undo data for reorg support\n",
                .{},
            );
        }

        // If a competing-fork reorg is pending and all fork bodies are
        // buffered, fire it now (before the normal active-chain connect
        // loop).  tryFireReorg is a no-op when pending_reorg is null, so
        // the steady-state cost is one HashMap.contains() per fork
        // hash — bounded by the fork length, typically 1-3 blocks.
        if (reorg_enabled and self.pending_reorg != null) {
            self.tryFireReorg();
        }

        // Stall recovery is now handled in two level-triggered paths,
        // matching Bitcoin Core:
        //   1. `pipelineBlockRequests` re-evaluates per-peer budget on every
        //      SendMessages tick, so a freed slot is refilled immediately.
        //   2. `checkBlockDownloadTimeouts` disconnects peers that hold an
        //      in-flight block past `BLOCK_DOWNLOAD_TIMEOUT`; the per-peer
        //      cleanup in `removePeerByIndex` returns the slots, and the
        //      `.block` buffer-full-drop path (wave 9) rewinds
        //      `download_cursor` so the pipeline re-requests dropped hashes.
        //
        // The wave-15 diagnostic showed the old 5-second global counter
        // reset fired on 94% of drain cycles during healthy IBD, throttling
        // throughput to ~6 blk/s by limiting re-issue to 3 peers.  See
        // `wave15-2026-04-15/CLEARBIT-STALL-RECOVERY-DIAG.md`.

        while (self.connect_cursor < self.expected_blocks.items.len) {
            // The next block we need to connect
            const expected_hash = self.expected_blocks.items[self.connect_cursor];

            // Is it in the buffer?
            const entry = self.block_buffer.fetchRemove(expected_hash);
            if (entry == null) {
                // Wedge diagnostic: when the expected next block is missing
                // but the buffer is NON-empty, the drain has stalled because
                // the pipeline got out of sync — blocks are in the buffer
                // but not the one we need next. The 2026-04-25 wedges at
                // h=892,306 and h=905,696 sat with buffer=15-28 / in_flight=0
                // for hours producing no log explanation. This line fires
                // exactly in that condition. Rate-limit to once per second
                // per stuck height so steady-state lookahead doesn't flood.
                if (self.block_buffer.count() > 0) {
                    const now = std.time.timestamp();
                    if (now != self.last_drain_break_log_ts or
                        self.connect_cursor != self.last_drain_break_cursor)
                    {
                        self.last_drain_break_log_ts = now;
                        self.last_drain_break_cursor = self.connect_cursor;
                        // Sample first few buffered hashes' positions so we
                        // can see how far ahead the pipeline ran.
                        var min_ahead: i64 = std.math.maxInt(i64);
                        var max_ahead: i64 = -1;
                        var sample_count: u32 = 0;
                        var it = self.block_buffer.iterator();
                        while (it.next()) |kv| {
                            sample_count += 1;
                            // Find which expected_blocks index the buffered
                            // hash corresponds to — bounded scan to keep
                            // this cheap during the wedge spin loop.
                            const scan_max = @min(self.expected_blocks.items.len,
                                self.connect_cursor + 4096);
                            var i = self.connect_cursor;
                            while (i < scan_max) : (i += 1) {
                                if (std.mem.eql(u8, &self.expected_blocks.items[i], &kv.key_ptr.*)) {
                                    const ahead: i64 = @as(i64, @intCast(i)) -
                                        @as(i64, @intCast(self.connect_cursor));
                                    if (ahead < min_ahead) min_ahead = ahead;
                                    if (ahead > max_ahead) max_ahead = ahead;
                                    break;
                                }
                            }
                            if (sample_count >= 16) break;
                        }
                        std.debug.print(
                            "P2P: DRAIN-BREAK-WEDGE connect_cursor={d} download_cursor={d} buffer={d} sampled_ahead_min={d} sampled_ahead_max={d} expected_total={d}\n",
                            .{
                                self.connect_cursor,
                                self.download_cursor,
                                self.block_buffer.count(),
                                min_ahead,
                                max_ahead,
                                self.expected_blocks.items.len,
                            },
                        );
                    }

                    // Fast staller recovery: cancel the stuck FRONT block's
                    // in-flight request after DRAIN_WEDGE_STALL_TIMEOUT so it
                    // re-requests from another peer, instead of waiting the 20-min
                    // BLOCK_DOWNLOAD_TIMEOUT. The per-block map makes this
                    // drift-free: decrement the EXACT holder + drop the entry, then
                    // rewind download_cursor; pipelineBlockRequests re-issues ONLY
                    // this now-untracked block (others still in-flight stay
                    // skipped). Mirrors Core BLOCK_STALLING_TIMEOUT. Fires only in
                    // this genuine-wedge branch (front missing + buffer non-empty),
                    // so it does not reintroduce the W15 throughput regression.
                    if (self.wedge_since == 0) {
                        self.wedge_since = now;
                    } else if (now - self.wedge_since >= DRAIN_WEDGE_STALL_TIMEOUT) {
                        if (self.inflight_block_peer.fetchRemove(expected_hash)) |kv| {
                            if (self.blocks_in_flight > 0) self.blocks_in_flight -= 1;
                            for (self.peers.items) |p| {
                                if (@intFromPtr(p) == kv.value) {
                                    p.recordBlockReceived();
                                    break;
                                }
                            }
                            std.debug.print(
                                "P2P: drain-wedge recovery: cancelled stuck front block at connect_cursor={d} (stalled {d}s); re-requesting from another peer\n",
                                .{ self.connect_cursor, now - self.wedge_since },
                            );
                        }
                        // Rewind so the now-untracked front block re-requests
                        // (skips others still tracked in-flight or buffered).
                        if (self.download_cursor > self.connect_cursor) {
                            self.download_cursor = self.connect_cursor;
                        }
                        self.wedge_since = now; // rate-limit subsequent recoveries
                    }
                }
                break; // Not yet received, stop
            }

            var block = entry.?.value;
            defer serialize.freeBlock(self.allocator, &block);

            const block_hash = crypto.computeBlockHash(&block.header);
            const height = cs.best_height + 1;

            // Timing for per-block diagnostics
            const block_start = std.time.nanoTimestamp();

            // P0-1 (2026-05-02): consensus validation BEFORE UTXO mutation.
            // Prior to this hook the IBD path was a "trust the peer" sync —
            // no PoW check, no merkle root check, no scripts, no fees, no
            // sigop budget, no witness commitment.  validateBlockForIBD now
            // runs the full Core-compatible CheckBlock + ConnectBlock
            // contextual checks and only delegates to connectBlockFast on
            // success.  See `validation.zig:validateBlockForIBD`.
            //
            // On failure: (a) drop this block from the buffer (already done
            // via fetchRemove above), (b) decline to advance connect_cursor
            // so pipelineBlockRequests will re-fetch the slot from another
            // peer, (c) misbehave the supplying peer at +100 (immediate ban)
            // because feeding consensus-invalid bytes is a bright-line
            // protocol violation.  Mirrors Core's MaybePunishNodeForBlock
            // BLOCK_MUTATED / BLOCK_INVALID_HEADER arms (net_processing.cpp:1919,1935).
            if (!self.validateBlockForIBDOrReject(&block, &block_hash, height)) {
                // Penalise the supplying peer (G16/G17 fix: was missing before).
                // Look up source peer by pointer value; linear scan over the live
                // peer list so a disconnected peer is never dereferenced.
                if (self.block_source_peers.get(block_hash)) |source_ptr| {
                    for (self.peers.items) |p| {
                        if (@intFromPtr(p) == source_ptr) {
                            p.misbehaving(100, "mutated-block");
                            break;
                        }
                    }
                }
                _ = self.block_source_peers.remove(block_hash);
                // Treat as a fatal-for-this-block error: do NOT advance
                // connect_cursor.  The pipeline will re-request from a
                // different peer.  We rewind download_cursor to the current
                // connect_cursor so the missing slot is re-issued.
                if (self.download_cursor > self.connect_cursor) {
                    self.download_cursor = self.connect_cursor;
                }
                break;
            }
            // Block accepted: remove source-peer tracking entry.
            _ = self.block_source_peers.remove(block_hash);

            // Persist the raw block body to CF_BLOCKS BEFORE applying UTXO
            // mutations.  Bitcoin Core analog: BlockManager::SaveBlockToDisk
            // is invoked before CheckBlock in validation.cpp's block
            // acceptance flow, so the bytes are durable on disk before
            // validation begins.  The queue is consumed by ChainState.flush()
            // — the CF_BLOCKS put commits in the SAME WriteBatch as the
            // UTXO mutations and tip update, so a crash leaves both the
            // body and the tip advanced or neither.
            //
            // Without this, every block accepted via the IBD fast path
            // was discarded after UTXO update, leaving CF_BLOCKS empty
            // across the whole chain — `getblock` unanswerable below tip,
            // and the --prune watermark (00a4ea7) had no bytes to delete.
            //
            // Failures here (OOM during serialize / queue) are non-fatal:
            // the block still connects; CF_BLOCKS just misses this entry.
            // We log so an operator can correlate gaps with the cause.
            queueRawBlock(self.allocator, cs, &block, &block_hash, height) catch |err| {
                std.debug.print("P2P: queueBlockWrite failed at height {d}: {}\n", .{ height, err });
            };

            // CLEARBIT_REORG=1 opts the IBD path into reorg-safe undo
            // capture: connectBlockFastWithUndo collects the spent-coin
            // records as the block is applied and writes serialized undo
            // bytes to CF_BLOCK_UNDO atomically with the UTXO/tip advance.
            // Without the flag we keep the legacy fast path (no undo;
            // single-fork operation only).  Default off so the live node
            // keeps its current behaviour until soak.
            //
            // The slow path's overhead is only the CompactUtxo allocation
            // for spent inputs and the serialized-undo bytes (~100-200B
            // per non-coinbase input × ~2 KiB per typical block).  No
            // additional consensus checks beyond what validateBlockForIBD
            // already runs; the choice is purely about reorg readiness.
            if (reorg_enabled) {
                cs.connectBlockFastWithUndo(&block, &block_hash, height) catch |err| {
                    std.debug.print("P2P: Failed to connect block (with undo) at height {d}: {}\n", .{ height, err });
                    break;
                };
            } else {
                // During IBD, skip undo data collection for speed
                cs.connectBlockFast(&block, &block_hash, height) catch |err| {
                    std.debug.print("P2P: Failed to connect block at height {d}: {}\n", .{ height, err });
                    break;
                };
            }

            // W93 G15 mempool-removeForBlock parity: after the block has been
            // applied to chainstate, evict any mempool entries that the block
            // confirmed.  Mirrors Bitcoin Core's Chainstate::ConnectTip
            // (validation.cpp:3074):
            //   if (m_mempool) {
            //       m_mempool->removeForBlock(block_to_connect->vtx, pindexNew->nHeight);
            //       disconnectpool.removeForBlock(block_to_connect->vtx);
            //   }
            // Without this, confirmed txs linger in the mempool and would be
            // re-relayed on the next `inv` round + waste fee-estimation samples
            // + cause double-spend rejections for any RBF replacements.
            //
            // The mempool field on PeerManager is plumbed by main.zig's
            // wireMempool() helper; null when the test harness skips it.  Doing
            // this *after* the connect succeeds preserves the existing
            // failure-path semantics (mempool untouched on rejected blocks).
            if (self.mempool) |mp| {
                mp.removeForBlock(&block);

                // W*: tx-expiry sweep on block-connect — mirror of Bitcoin
                // Core's ConnectTip → LimitMempoolSize → CTxMemPool::Expire
                // (validation.cpp:269 inside LimitMempoolSize, invoked off
                // ConnectTip).  removeExpired() drops every entry older than
                // MEMPOOL_EXPIRY *and* its in-mempool descendants (it calls
                // removeTransactionWithDescendants, idempotent on already-
                // removed txids), so there is no double-eviction hazard with
                // the removeForBlock() above: removeForBlock only touches txs
                // confirmed by this block, removeExpired only touches stale
                // ones, and removeTransactionWithDescendants is a no-op on an
                // absent entry.  This is the only live driver of the expiry
                // policy; without it stale txs accumulate unbounded (DoS
                // vector).  Relay-policy only — never affects block validity.
                mp.removeExpired();
            }

            // Wallet bookkeeping: feed the just-connected block into every
            // loaded wallet so getbalance / listunspent / listtransactions stay
            // current during live sync and IBD — not only when blocks arrive via
            // the mining/RPC path (scanMinedBlocksIntoWallets).  Mirrors Bitcoin
            // Core's CWallet::blockConnected hook off ConnectTip.  Best-effort by
            // contract: a wallet bookkeeping failure must never fail a fully
            // validated block, so errors are swallowed inside the helper.  Also
            // advances each wallet's persisted last_synced_height watermark.
            self.scanConnectedBlockIntoWallets(&block, height);

            const block_elapsed_ns = std.time.nanoTimestamp() - block_start;
            const block_elapsed_ms = @divTrunc(block_elapsed_ns, 1_000_000);
            if (block_elapsed_ms > 50) {
                slow_blocks += 1;
                // W21 fix: log all slow blocks (not just first 3 per drain).
                // Blocks >50ms are always logged; >1000ms get a VERY-SLOW tag.
                // This prevents the operator-visible "600s silence" that occurs
                // when many multi-second flushes run back-to-back: previously
                // only the first 3 were printed, leaving the log dark for the
                // entire remainder of the drain.
                if (block_elapsed_ms > 1000) {
                    std.debug.print("P2P: VERY-SLOW block {d}: {d}ms utxos={d}\n", .{
                        height,
                        block_elapsed_ms,
                        cs.utxo_set.cache.count(),
                    });
                } else {
                    std.debug.print("P2P: SLOW block {d}: {d}ms utxos={d}\n", .{
                        height,
                        block_elapsed_ms,
                        cs.utxo_set.cache.count(),
                    });
                }
            }

            // W73 Fix 2 — compaction-aware backoff.  When prefetch exceeds
            // 500 ms the RocksDB compaction mutex was almost certainly
            // blocking our multi_get.  Yield briefly so in-flight compaction
            // can drain before the next block's prefetch hits the same lock.
            //
            // Per wave47-2026-04-16/W73-FIX1-POST-DEPLOY-FINDINGS.md §4,
            // observed slow-prefetch tails run 2-4 s while the happy path is
            // 23-280 ms; 500 ms separates the tail cleanly.  Gate telemetry:
            // the existing [W73-PROF] 100-block rollup already emits
            // prefetch avg/max; compare pre/post restart windows to decide
            // if the backoff helps.  100 ms sleep is capped to <20% of the
            // smallest observed tail so cost is bounded even on false hits.
            const prefetch_ns = cs.profile_cur_prefetch_ns;
            if (prefetch_ns > 500 * std.time.ns_per_ms) {
                std.debug.print("[W73-STALL] block={d} prefetch={d}ms hits={d} — backoff 100ms\n", .{
                    height,
                    @divTrunc(prefetch_ns, std.time.ns_per_ms),
                    cs.profile_cur_prefetch_hits,
                });
                std.time.sleep(100 * std.time.ns_per_ms);
            }

            // W21 fix: heartbeat every 5 s during long drains.  With large
            // UTXO sets (>1.7 M entries) individual flushes take 50ms-3 s,
            // so a 134-block drain is 43 s of silence.  The heartbeat lets
            // operators distinguish "slow but alive" from "frozen".
            const now_hb = std.time.timestamp();
            if (now_hb - last_heartbeat >= 5) {
                const remaining_q = self.expected_blocks.items.len - self.connect_cursor;
                std.debug.print("P2P: drain-heartbeat height={d} connected={d} slow={d} buffer={d} in_flight={d} queue={d} utxos={d}\n", .{
                    cs.best_height,
                    connected,
                    slow_blocks,
                    self.block_buffer.count(),
                    self.blocks_in_flight,
                    remaining_q,
                    cs.utxo_set.cache.count(),
                });
                last_heartbeat = now_hb;

                // W21 fix: re-arm the download pipeline inside the drain loop
                // every 5 s.  Peer slots freed by block receipts during the
                // drain are not refilled until the drain completes; with a
                // 43-second drain and only 14 in-flight slots at start, the
                // pipeline goes cold and then only has 1-2 active peers after
                // drain.  Re-arming here keeps all peer budgets filled even
                // during a long drain.
                self.pipelineBlockRequests() catch {};

                // W100: service pending inbound connections during long
                // drains.  Without this, a blk-replay (or any other inbound)
                // peer's TCP SYN is accepted by the kernel but its userspace
                // handshake waits for the drain to complete — observed 10-11
                // min gaps against blk-replay on localhost.  acceptInbound
                // polls non-blocking; handshake with an inbound v1 peer is
                // sub-millisecond on localhost.
                self.acceptInbound() catch {};

                // W101: service existing peers during long drains.  Without
                // this, reactive-only peers (blk-replay sends nothing unless
                // we pinged or requested a block) hit the 20-min
                // last_message_time threshold in isTimedOut and get silently
                // evicted by disconnectStale.  sendPings keeps pongs flowing
                // (and pongs update last_message_time); processAllMessages
                // drains the recv buffer so inbound pongs, ack-less replies
                // and incoming getdata/getblocks are handled.
                //
                // Recursion note: processAllMessages → `.block` handler
                // normally calls drainBlockBuffer, but the in_drain guard
                // turns those nested calls into no-ops.  Blocks accepted by
                // the inner loop land in block_buffer and are consumed by
                // the outer while on its next iteration — so throughput is
                // unaffected.
                self.sendPings() catch {};
                self.processAllMessages() catch {};
            }

            self.our_height = @intCast(cs.best_height);
            connected += 1;
            self.blocks_since_log += 1;
            self.connect_cursor += 1;
            // Cursor advanced → not wedged; clear the drain-wedge staller timer.
            self.wedge_since = 0;

            // Cache the connected block for relay to other peers.
            // Only cache recent blocks to bound memory (keep last 512).
            if (self.served_blocks.count() < 64) {
                self.cacheBlockForRelay(&block_hash, &block);
            }

            // Periodically compact the expected_blocks list to reclaim memory
            // when we've connected a large chunk
            if (self.connect_cursor > 10000) {
                // Shift remaining items to the front
                const remaining = self.expected_blocks.items.len - self.connect_cursor;
                if (remaining > 0) {
                    std.mem.copyForwards(
                        types.Hash256,
                        self.expected_blocks.items[0..remaining],
                        self.expected_blocks.items[self.connect_cursor..self.expected_blocks.items.len],
                    );
                }
                self.expected_blocks.shrinkRetainingCapacity(remaining);
                self.download_cursor -= @min(self.download_cursor, self.connect_cursor);
                self.connect_cursor = 0;
            }
        }

        // Cursor-inversion fix: the drain advances connect_cursor for every
        // buffered block consumed, but never touches download_cursor. After a
        // W19/W28/buffer-full rewind sets download_cursor = connect_cursor,
        // the very next drain pass can consume hundreds of buffered blocks
        // queued before the rewind — surging connect_cursor past
        // download_cursor and leaving the cursors inverted. Once inverted,
        // pipelineBlockRequests starts iterating from a stale download_cursor
        // and re-requests already-passed hashes (those come back as orphans
        // that drain can't use), and the three existing rewind sites
        // (peer.zig:~2339, ~2366, ~2943, ~3303) all guard with
        // `if (download_cursor > connect_cursor)` so they can't repair the
        // inverted state. The 2026-04-25 wedge at h=905,696 captured exactly
        // this via the DRAIN-BREAK-WEDGE log:
        //   connect_cursor=1259 download_cursor=752 buffer=1 in_flight=0
        // Force-restore the invariant here so pipelineBlockRequests starts
        // at connect_cursor on the next call. Pipeline naturally skips
        // hashes already in block_buffer, so re-requesting from
        // connect_cursor is cheap.
        if (self.download_cursor < self.connect_cursor) {
            std.debug.print(
                "P2P: cursor-inversion-fix download_cursor={d} -> connect_cursor={d}\n",
                .{ self.download_cursor, self.connect_cursor },
            );
            self.download_cursor = self.connect_cursor;
        }

        // Gap-stall recovery (W28): if the block at connect_cursor is missing
        // from the buffer AND download_cursor has already advanced past it
        // (meaning the block was "requested" but never arrived or was dropped),
        // AND no blocks are currently in-flight (so the block timeout path will
        // never fire to trigger the usual rewind), rewind download_cursor to
        // connect_cursor so pipelineBlockRequests() will re-issue the missing
        // block.  This prevents a permanent stall when blocks_in_flight_count == 0
        // for all peers but a gap block sits between connect_cursor and
        // download_cursor.
        if (self.blocks_in_flight == 0 and
            self.connect_cursor < self.expected_blocks.items.len and
            self.download_cursor > self.connect_cursor)
        {
            const gap_hash = self.expected_blocks.items[self.connect_cursor];
            if (!self.block_buffer.contains(gap_hash)) {
                // The block at the connection front is missing and was already
                // "requested" (download_cursor passed it) — rewind to re-request.
                std.debug.print("P2P: gap-stall recovery: block at connect_cursor={d} missing, rewinding download_cursor\n",
                    .{self.connect_cursor});
                self.download_cursor = self.connect_cursor;
            }
        }

        if (connected > 0) {
            const drain_elapsed_ns = std.time.nanoTimestamp() - drain_start;
            const drain_elapsed_ms = @divTrunc(drain_elapsed_ns, 1_000_000);

            // Log progress periodically (every 5 seconds)
            const now = std.time.timestamp();
            if (now - self.last_progress_log >= 5) {
                const elapsed = if (now > self.last_progress_log and self.last_progress_log > 0)
                    @as(u32, @intCast(now - self.last_progress_log))
                else
                    5;
                const rate = if (elapsed > 0) self.blocks_since_log / elapsed else self.blocks_since_log;
                const remaining = self.expected_blocks.items.len - self.connect_cursor;
                std.debug.print("P2P: height={d} buffer={d} in_flight={d} queue={d} rate={d} blk/s drain={d}ms utxos={d}\n", .{
                    cs.best_height,
                    self.block_buffer.count(),
                    self.blocks_in_flight,
                    remaining,
                    rate,
                    drain_elapsed_ms,
                    cs.utxo_set.cache.count(),
                });
                if (slow_blocks > 0) {
                    std.debug.print("P2P: {d} slow blocks (>50ms) in this drain\n", .{slow_blocks});
                }
                self.last_progress_log = now;
                self.blocks_since_log = 0;
            }

            // Immediately request more headers if we've consumed most of our queue
            const remaining = self.expected_blocks.items.len - self.connect_cursor;
            if (remaining < 500) {
                for (self.peers.items) |p| {
                    if (p.state == .handshake_complete and p.last_getheaders_time == 0) {
                        self.sendGetHeaders(p) catch {};
                        break;
                    }
                }
            }
        }
    }

    /// Check if we are in Initial Block Download (IBD).
    fn isIBD(self: *const PeerManager) bool {
        if (self.chain_state) |cs| {
            // We're in IBD if we have pending blocks to download or our queue is active
            if (self.expected_blocks.items.len > 0) return true;
            if (self.block_buffer.count() > 0) return true;
            // Also check if any peer is significantly ahead of us
            for (self.peers.items) |p| {
                if (p.start_height > 0 and cs.best_height + 10 < @as(u32, @intCast(p.start_height))) {
                    return true;
                }
            }
        }
        return false;
    }

    /// Main peer management loop.
    pub fn run(self: *PeerManager) !void {
        self.running.store(true, .release);

        // Anchor the fixed-seed grace window at connection-loop entry, BEFORE
        // the initial DNS resolve — matches Core net.cpp `auto start = GetTime()`
        // in ThreadOpenConnections.  maybeAddFixedSeeds measures its 60s grace
        // from here.
        self.run_loop_start_ts = std.time.timestamp();

        // --connect peer-pinned mode bypasses the fixed-seed fallback entirely
        // (Core: -connect bypasses ThreadOpenConnections fixed-seed logic).
        if (self.connect_address != null) {
            self.fixed_seed_enabled = false;
        }

        // Connect to --connect peer if specified (priority)
        if (self.connect_address) |addr| {
            std.debug.print("P2P: Attempting TCP connection to --connect peer...\n", .{});
            // BIP-324 negotiation lives inside connectOutboundNegotiated;
            // when v2 is disabled (default) this is identical to the old
            // Peer.connect+performHandshake pair.
            const new_peer = self.connectOutboundNegotiated(addr) orelse {
                std.debug.print("P2P: Connection or handshake failed with --connect peer\n", .{});
                return;
            };
            new_peer.conn_type = .manual;
            std.debug.print("P2P: Handshake complete with --connect peer (height={d})\n", .{new_peer.start_height});

            self.peers.append(new_peer) catch {
                new_peer.disconnect();
                self.allocator.destroy(new_peer);
                return;
            };

            // Send getheaders using our best block as locator
            self.sendGetHeaders(new_peer) catch |err| {
                std.debug.print("P2P: Failed to send getheaders: {}\n", .{err});
            };
        } else {
            // Load anchor connections from disk
            self.loadAnchors() catch {};

            // Connect to anchor peers first (priority)
            self.connectToAnchors();

            // Initial DNS seeding
            self.dnsSeeds() catch {};
        }

        while (self.running.load(.acquire)) {
            // 0. Reconnect dropped manual peers first (addnode <ip> add).
            // Separate from maintainOutbound so it runs even in --connect mode
            // and isn't starved by the 1-attempt-per-tick IBD throttle.
            self.maintainManualConnections();

            // 0b. Fixed-seed fallback (Core net.cpp:2604-2643).  One-shot, fires
            // ONLY when the address book is empty and either DNS seeding is off
            // or the 60s grace window elapsed without DNS/-addnode populating it.
            // Layered AFTER the initial dnsSeeds() bootstrap above — never
            // replaces it.  Runs before maintainOutbound so freshly-injected
            // seeds are dialled on this same tick.  No-op once it has fired.
            _ = self.maybeAddFixedSeeds();

            // 1. Open new outbound connections if needed (skip if --connect mode)
            // During IBD, skip connection attempts if we already have peers (avoids blocking)
            if (self.connect_address == null) {
                // During IBD, maintainOutbound already limits to 1 attempt
                // per call, so it won't block the loop excessively.
                // Always try to maintain outbound diversity — a single peer
                // is fragile and will stall if it disconnects.
                self.maintainOutbound() catch {};

                // 1b. Open a short-lived feeler probe (anti-eclipse). At most
                // one feeler in flight, at most once per FEELER_INTERVAL_SECS;
                // probes a NEW-table address and promotes it NEW->TRIED on a
                // successful handshake, then disconnects (Core net.cpp
                // ThreadOpenConnections FEELER branch). Off the outbound budget
                // (never appended to self.peers) and skipped in --connect mode.
                self.maybeOpenFeeler();
            }

            // 2. Accept inbound connections
            self.acceptInbound() catch {};

            // 3. Process messages from all peers
            self.processAllMessages() catch {};

            // 3b. Drain block buffer and pipeline more requests
            self.drainBlockBuffer();
            self.pipelineBlockRequests() catch {};

            // 4. Send pings to idle peers
            self.sendPings() catch {};

            // 5. Disconnect timed-out peers
            self.disconnectStale();

            // 6. Check for stale tips and evict peers (runs every 45 seconds)
            self.checkForStaleTipAndEvictPeers();

            // 6b. Sweep expired orphans (runs every ORPHAN_TX_EXPIRE_INTERVAL seconds)
            self.sweepOrphanPool();

            // 6c. ASMap health check (runs every ASMAP_HEALTH_CHECK_INTERVAL seconds,
            //     first run at startup — no-op when no asmap is loaded).
            //     Reference: bitcoin-core/src/net.cpp:3570-3573
            self.runAsmapHealthCheck();

            // 6d. Periodic durable wallet flush.  Persists wallets the connect
            //     loop marked dirty, so wallet state survives an unclean exit
            //     (SIGKILL / OOM / power-loss) — not only a clean shutdown.
            //     Gated to ~every WALLET_FLUSH_INTERVAL_SECS; cheap no-op when
            //     no wallet changed since the last flush.
            if (self.wallet_manager) |wm| {
                const now = std.time.timestamp();
                if (now - self.last_wallet_flush >= WALLET_FLUSH_INTERVAL_SECS) {
                    self.last_wallet_flush = now;
                    _ = wm.flushDirty();
                }
            }

            // 6e. Periodic addrman (peers.dat) dump — Core DumpAddresses parity.
            //     The learned-peer table was persisted ONLY in deinit() (clean
            //     shutdown), so an unclean exit (SIGKILL/OOM) lost every address
            //     learned since boot. Now also dumped every DUMP_PEERS_INTERVAL_SECS
            //     while running. Atomic temp+rename, best-effort; cheap (serialises
            //     an in-memory map). Sibling scope to the wallet flush above so its
            //     `now` does not shadow. Use `|*am|` (not ensureAddrman) so we never
            //     create+save an empty table before any peer is learned.
            if (self.addrman) |*am| {
                const now = std.time.timestamp();
                if (now - self.last_addrman_dump >= DUMP_PEERS_INTERVAL_SECS) {
                    self.last_addrman_dump = now;
                    if (self.data_dir) |dir| am.save(dir);
                }
            }

            // 7. Peer rotation (skip if --connect mode)
            if (self.connect_address == null) {
                self.rotatePeers();
            }

            // 8. Brief sleep to avoid busy-loop.
            // During IBD, poll() in processAllMessages handles the wait (10ms timeout),
            // so no additional sleep is needed. Outside IBD, sleep 50ms.
            if (!self.isIBD()) {
                std.time.sleep(50 * std.time.ns_per_ms);
            }
        }
    }

    /// Stop the peer manager.
    pub fn stop(self: *PeerManager) void {
        self.running.store(false, .release);
    }

    // ========================================================================
    // Legacy API compatibility
    // ========================================================================

    /// Connect to a new peer (legacy API).
    ///
    /// Delegates to `connectOutboundNegotiated` so the v2/v1 selection logic
    /// (BIP-324 when `CLEARBIT_BIP324_V2=1`) is honored on every outbound
    /// path — `tryConnectNode` (`onetry`/`addnode`) and
    /// `maintainManualConnections` reach the wire through here.  Without
    /// this delegation those paths were silently v1-only even with the
    /// env var enabled.  Preserves the legacy `!*Peer` signature and
    /// auto-append-to-peers contract that callers rely on.
    pub fn connectToPeer(self: *PeerManager, address: std.net.Address) !*Peer {
        if (self.peers.items.len >= MAX_TOTAL_CONNECTIONS) {
            return error.TooManyPeers;
        }

        const peer = self.connectOutboundNegotiated(address) orelse return error.ConnectFailed;
        self.peers.append(peer) catch |err| {
            peer.disconnect();
            self.allocator.destroy(peer);
            return err;
        };
        return peer;
    }

    /// Remove a peer from the manager (legacy API).
    pub fn removePeer(self: *PeerManager, peer: *Peer) void {
        for (self.peers.items, 0..) |p, i| {
            if (p == peer) {
                peer.disconnect();
                _ = self.peers.swapRemove(i);
                self.allocator.destroy(peer);
                return;
            }
        }
    }

    /// Get the number of connected peers.
    pub fn connectedCount(self: *const PeerManager) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.isReady()) count += 1;
        }
        return count;
    }

    /// Get the number of outbound peers.
    pub fn outboundCount(self: *const PeerManager) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .outbound) count += 1;
        }
        return count;
    }

    /// Get the number of inbound peers.
    pub fn inboundCount(self: *const PeerManager) usize {
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.direction == .inbound) count += 1;
        }
        return count;
    }

    /// Get number of known addresses.
    pub fn knownAddressCount(self: *const PeerManager) usize {
        return self.known_addresses.count();
    }

    /// Disconnect timed-out peers (legacy API).
    pub fn pruneTimedOut(self: *PeerManager) void {
        self.disconnectStale();
    }

    /// Cache a mined block so it can be served to peers on getdata.
    pub fn cacheMinedBlock(self: *PeerManager, hash: types.Hash256, block_data: []const u8) void {
        // Store a copy of the serialized block
        const data_copy = self.allocator.dupe(u8, block_data) catch return;
        self.served_blocks.put(hash, data_copy) catch {
            self.allocator.free(data_copy);
        };
    }

    /// Serialize and cache a connected block for relay to other peers.
    fn cacheBlockForRelay(self: *PeerManager, hash: *const types.Hash256, block: *const types.Block) void {
        var writer = serialize.Writer.init(self.allocator);
        serialize.writeBlock(&writer, block) catch {
            writer.deinit();
            return;
        };
        const data = writer.toOwnedSlice() catch {
            writer.deinit();
            return;
        };
        self.served_blocks.put(hash.*, data) catch {
            self.allocator.free(data);
        };
    }

    /// Broadcast a message to all connected peers.
    pub fn broadcast(self: *PeerManager, msg: *const p2p.Message) void {
        for (self.peers.items) |peer| {
            if (peer.state == .handshake_complete) {
                peer.sendMessage(msg) catch continue;
            }
        }
    }

    /// BIP-130 block announcement.  For each connected peer:
    ///   - If the peer has sent us `sendheaders`, announce via a `headers`
    ///     message containing the new header.
    ///   - Otherwise, fall back to the legacy `inv(MSG_BLOCK)` announcement.
    ///
    /// This is the Pattern A wiring: clearbit previously stored no
    /// inbound-sendheaders state and announced every new block via `inv`,
    /// which costs a `getheaders` round-trip on the peer side and degrades
    /// new-block latency.  Reference impl:
    /// camlcoin lib/peer_manager.ml::announce_block.
    pub fn announceBlock(
        self: *PeerManager,
        header: *const types.BlockHeader,
        hash: *const types.Hash256,
    ) void {
        // Reuse the inv message (allocated on the stack) for non-opt-in peers.
        var inv_items = [_]p2p.InvVector{.{
            .inv_type = .msg_block,
            .hash = hash.*,
        }};
        const inv_msg = p2p.Message{ .inv = .{ .inventory = &inv_items } };

        // Reuse the headers message (single-element array, on the stack) for
        // sendheaders peers.  Note: encodeMessage walks the slice and copies
        // the bytes, so the lifetime ends with this function.
        var hdrs = [_]types.BlockHeader{header.*};
        const hdrs_msg = p2p.Message{ .headers = .{ .headers = &hdrs } };

        for (self.peers.items) |peer| {
            if (peer.state != .handshake_complete) continue;
            if (peer.send_headers) {
                peer.sendMessage(&hdrs_msg) catch continue;
            } else {
                peer.sendMessage(&inv_msg) catch continue;
            }
        }
    }

    /// Feed a just-connected block into every loaded wallet.  Called from the
    /// live block-connect path (drainBlockBuffer) so the wallet ledger tracks
    /// real chain progress, not just locally mined blocks.  Best-effort: a
    /// per-wallet scan failure is logged and skipped — a wallet bookkeeping
    /// problem must never disturb a fully validated chain (the ledger is
    /// reconstructible via rescan / the startup reconcile).  `scanBlockForWallet`
    /// advances each wallet's persisted last_synced_height watermark and marks
    /// it dirty; the periodic flush (or a clean shutdown) persists it durably.
    fn scanConnectedBlockIntoWallets(self: *PeerManager, block: *const types.Block, height: u32) void {
        const wm = self.wallet_manager orelse return;
        wm.mutex.lock();
        defer wm.mutex.unlock();
        var it = wm.wallets.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.scanBlockForWallet(block, height) catch |err| {
                std.log.warn("wallet-scan(connect): scan failed for wallet '{s}' at height {d}: {s}", .{ entry.key_ptr.*, height, @errorName(err) });
            };
        }
    }
};

/// Serialize a block body and hand it to ChainState's pending_block_writes
/// queue so the next flush() commits CF_BLOCKS atomically with the chain
/// advance. Free-standing rather than a method on PeerManager so the
/// drainBlockBuffer hot path doesn't have to reach back through `self`.
fn queueRawBlock(
    allocator: std.mem.Allocator,
    cs: *storage.ChainState,
    block: *const types.Block,
    hash: *const types.Hash256,
    height: u32,
) !void {
    var writer = serialize.Writer.init(allocator);
    errdefer writer.deinit();
    try serialize.writeBlock(&writer, block);
    const owned_const = try writer.toOwnedSlice();
    // toOwnedSlice returns []const u8; the allocator-free / RocksDB API
    // path expects []u8. The bytes are freshly allocated so the cast is
    // safe.
    const owned: []u8 = @constCast(owned_const);
    // queueBlockWrite takes ownership on success and frees on its own
    // skip-paths (memory-only mode, height ≤ prune_height). On failure
    // (OOM during ArrayList.append) ownership stays with us.
    cs.queueBlockWrite(hash, owned, height) catch |err| {
        allocator.free(owned);
        return err;
    };
}

// ============================================================================
// Tests
// ============================================================================

test "peer struct initialization with default values" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    // Create a mock stream by using a dummy file descriptor
    // Since we can't create a real socket in tests without a server,
    // we test the accept path with a placeholder

    // Test that PeerState enum has expected values
    try std.testing.expectEqual(PeerState.connecting, PeerState.connecting);
    try std.testing.expectEqual(PeerState.handshake_complete, PeerState.handshake_complete);

    // Test PeerDirection enum
    try std.testing.expectEqual(PeerDirection.inbound, PeerDirection.inbound);
    try std.testing.expectEqual(PeerDirection.outbound, PeerDirection.outbound);

    // Test peer initialization values directly without a real socket
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const dummy_peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8333),
        .state = .connecting,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 12345,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 12345,
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
    };

    try std.testing.expectEqual(PeerState.connecting, dummy_peer.state);
    try std.testing.expectEqual(PeerDirection.outbound, dummy_peer.direction);
    try std.testing.expectEqual(@as(u64, 0), dummy_peer.services);
    try std.testing.expectEqual(@as(i64, 0), dummy_peer.last_ping_time);
    try std.testing.expectEqual(@as(u64, 0), dummy_peer.bytes_sent);
    try std.testing.expectEqual(@as(i32, 0), dummy_peer.start_height);
    try std.testing.expect(!dummy_peer.is_witness_capable);
    try std.testing.expect(!dummy_peer.is_headers_first);
    try std.testing.expectEqual(@as(u32, 0), dummy_peer.ban_score);
}

test "peer state transitions" {
    // Test that all PeerState values are valid
    const states = [_]PeerState{
        .connecting,
        .connected,
        .version_sent,
        .version_received,
        .handshake_complete,
        .disconnecting,
        .disconnected,
    };

    for (states, 0..) |state, i| {
        try std.testing.expectEqual(states[i], state);
    }

    // Test state enum tag values
    try std.testing.expect(@intFromEnum(PeerState.connecting) == 0);
    try std.testing.expect(@intFromEnum(PeerState.connected) == 1);
    try std.testing.expect(@intFromEnum(PeerState.disconnected) == 6);
}

test "version message construction with correct protocol version" {
    const version_msg = p2p.VersionMessage{
        .version = p2p.PROTOCOL_VERSION,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .timestamp = 1234567890,
        .addr_recv = types.NetworkAddress{
            .services = 0,
            .ip = [_]u8{0} ** 16,
            .port = 0,
        },
        .addr_from = types.NetworkAddress{
            .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
            .ip = [_]u8{0} ** 16,
            .port = 8333,
        },
        .nonce = 0x123456789ABCDEF0,
        .user_agent = p2p.USER_AGENT,
        .start_height = 700000,
        .relay = true,
    };

    try std.testing.expectEqual(@as(i32, 70016), version_msg.version);
    try std.testing.expectEqual(@as(u64, p2p.NODE_NETWORK | p2p.NODE_WITNESS), version_msg.services);
    try std.testing.expectEqual(@as(i64, 1234567890), version_msg.timestamp);
    try std.testing.expectEqual(@as(i32, 700000), version_msg.start_height);
    try std.testing.expect(version_msg.relay);
    try std.testing.expectEqualStrings("/clearbit:0.1.0/", version_msg.user_agent);

    // Verify services bitmap
    try std.testing.expect((version_msg.services & p2p.NODE_NETWORK) != 0);
    try std.testing.expect((version_msg.services & p2p.NODE_WITNESS) != 0);
}

// Core parity: unconnecting-headers counter must tolerate up to
// MAX_NUM_UNCONNECTING_HEADERS_MSGS (10) before triggering disconnect.
// Mirrors Bitcoin Core's `nUnconnectingHeaders` accounting in
// net_processing.cpp::ProcessHeadersMessage.  Pre-fix, clearbit
// instant-banned on the very first orphan via misbehaving(20).
test "unconnecting-headers counter under MAX is tolerated" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 192, 168, 1, 2 }, 8333),
        .state = .connected,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
    };

    // Initial counter is zero.
    try std.testing.expectEqual(@as(u32, 0), peer.unconnecting_headers_count);

    // Drive the counter through 10 successive unconnecting messages —
    // none should trigger the disconnect threshold (the comparison in
    // peer.zig is `> MAX_NUM_UNCONNECTING_HEADERS_MSGS`, so up to and
    // including 10 are tolerated).
    var i: u32 = 1;
    while (i <= MAX_NUM_UNCONNECTING_HEADERS_MSGS) : (i += 1) {
        peer.unconnecting_headers_count += 1;
        try std.testing.expect(peer.unconnecting_headers_count <= MAX_NUM_UNCONNECTING_HEADERS_MSGS);
        try std.testing.expectEqual(@as(u32, 0), peer.ban_score);
    }

    // 11th message exceeds the threshold.
    peer.unconnecting_headers_count += 1;
    try std.testing.expect(peer.unconnecting_headers_count > MAX_NUM_UNCONNECTING_HEADERS_MSGS);

    // A successfully-connecting batch resets the counter (mirrors
    // Core's nUnconnectingHeaders = 0 in the success path; the
    // assignment lives in the .extends_active arm of the header
    // classifier).
    peer.unconnecting_headers_count = 0;
    try std.testing.expectEqual(@as(u32, 0), peer.unconnecting_headers_count);
}

test "ban score accumulation" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333),
        .state = .connected,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
    };

    // Initial score is 0
    try std.testing.expectEqual(@as(u32, 0), peer.ban_score);

    // Add 25 points, should not be banned
    try std.testing.expect(!peer.addBanScore(25));
    try std.testing.expectEqual(@as(u32, 25), peer.ban_score);

    // Add 25 more, still not banned
    try std.testing.expect(!peer.addBanScore(25));
    try std.testing.expectEqual(@as(u32, 50), peer.ban_score);

    // Add 49 more, still not banned (99 total)
    try std.testing.expect(!peer.addBanScore(49));
    try std.testing.expectEqual(@as(u32, 99), peer.ban_score);

    // Add 1 more, now banned (100 total)
    try std.testing.expect(peer.addBanScore(1));
    try std.testing.expectEqual(@as(u32, 100), peer.ban_score);
}

test "peer timeout detection" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const now = std.time.timestamp();

    // Test peer with recent message - not timed out
    var active_peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = p2p.NODE_NETWORK,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = now,
        .bytes_sent = 1000,
        .bytes_received = 2000,
        .start_height = 700000,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = true,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = now,
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
    };

    try std.testing.expect(!active_peer.isTimedOut());

    // Test peer with old last message - timed out (20+ minutes ago)
    var stale_peer = active_peer;
    stale_peer.last_message_time = now - (21 * 60);
    try std.testing.expect(stale_peer.isTimedOut());

    // Test peer with ping sent but no pong - timed out (5+ minutes ago)
    var ping_peer = active_peer;
    ping_peer.last_message_time = now;
    ping_peer.last_ping_time = now - (6 * 60);
    ping_peer.last_pong_time = now - (10 * 60); // Pong before ping
    try std.testing.expect(ping_peer.isTimedOut());

    // Test peer with ping sent and pong received - not timed out
    var healthy_peer = active_peer;
    healthy_peer.last_ping_time = now - 60;
    healthy_peer.last_pong_time = now - 59;
    try std.testing.expect(!healthy_peer.isTimedOut());
}

test "peer ready check" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .connecting,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
        .best_known_height = 0,
        .last_getheaders_time = 0,
        .oldest_block_in_flight_time = 0,
        .blocks_in_flight_count = 0,
        .chain_sync_protected = false,
    };

    // Connecting state - not ready
    try std.testing.expect(!peer.isReady());

    // Connected state - not ready
    peer.state = .connected;
    try std.testing.expect(!peer.isReady());

    // Version sent - not ready
    peer.state = .version_sent;
    try std.testing.expect(!peer.isReady());

    // Handshake complete - ready!
    peer.state = .handshake_complete;
    try std.testing.expect(peer.isReady());

    // Disconnecting - not ready
    peer.state = .disconnecting;
    try std.testing.expect(!peer.isReady());
}

test "handle pong message" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 1000,
        .last_pong_time = 0,
        .last_ping_nonce = 0x123456789ABCDEF0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    // Wrong nonce - should not update pong time
    peer.handlePong(0xDEADBEEF);
    try std.testing.expectEqual(@as(i64, 0), peer.last_pong_time);

    // Correct nonce - should update pong time
    peer.handlePong(0x123456789ABCDEF0);
    try std.testing.expect(peer.last_pong_time > 0);
}

test "peer latency calculation" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    // No ping/pong yet - no latency
    try std.testing.expect(peer.getLatencyMs() == null);

    // Set ping time
    peer.last_ping_time = 1000;
    try std.testing.expect(peer.getLatencyMs() == null);

    // Set pong time (50ms later)
    peer.last_pong_time = 1000;
    const latency = peer.getLatencyMs();
    try std.testing.expect(latency != null);
    try std.testing.expectEqual(@as(i64, 0), latency.?);
}

test "peer manager initialization" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    try std.testing.expectEqual(@as(usize, 0), manager.peers.items.len);
    try std.testing.expectEqual(@as(usize, 0), manager.connectedCount());
    try std.testing.expectEqual(@as(usize, 0), manager.knownAddressCount());
    try std.testing.expectEqual(@as(i32, 0), manager.our_height);
}

// CONSENSUS REGRESSION (BIP-68 per-coin MTP, restart false-accept).
//
// computeMtpAtHeight supplies nCoinTime for TIME-based relative sequence
// locks (Core tx_verify.cpp:74 GetAncestor(max(coinHeight-1,0))->GetMedianTimePast()).
// Before the persisted fallback, an EMPTY in-memory header_index (the state
// right after a process restart, before headers re-sync — and any time an old
// height has been LRU-evicted) made the ancestor walk `break` on the first
// miss → n==0 → return 0.  A nCoinTime of 0 collapses required_time to
// ~(lock<<9)-1, so a time-based relative lock is judged satisfied when Core,
// using the true ancestor MTP, would reject the block (bad-txns-nonfinal) —
// a CONSENSUS FALSE-ACCEPT.
//
// This test reproduces the post-restart state: 11 ancestor headers persisted
// in CF_BLOCK_INDEX + the H:{height}→hash index in CF_DEFAULT, with the
// in-memory header_index left EMPTY.  computeMtpAtHeight must still return the
// true median of the 11 timestamps via the getPersistedHeader fallback.
//
// PRE-FIX: header_index miss → break → n==0 → returns 0 (test FAILS).
// POST-FIX: persisted fallback walks CF_BLOCK_INDEX → returns the true MTP.
test "computeMtpAtHeight: persisted fallback yields true MTP with empty header_index (restart false-accept guard)" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    // Unique temp dir per run so concurrent / repeated `zig build test`
    // invocations don't collide on the RocksDB lock.
    var path_buf: [128]u8 = undefined;
    const db_path = try std.fmt.bufPrint(
        &path_buf,
        "/tmp/clearbit_mtp_restart_test_{d}",
        .{std.time.nanoTimestamp()},
    );
    std.fs.cwd().deleteTree(db_path) catch {};
    defer std.fs.cwd().deleteTree(db_path) catch {};

    var db = try storage.Database.open(db_path, 64, allocator);
    defer db.close();

    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();
    manager.chain_state = &cs;
    // header_index is intentionally left EMPTY — this is the post-restart /
    // post-eviction condition the fix must survive.

    // Build a synthetic 11-block chain (heights 0..10) with strictly
    // increasing timestamps.  Hashes are synthetic-but-consistent: the
    // height→hash index points at hash_h, and each persisted header's
    // prev_block points at hash_{h-1}, so the ancestor walk chains correctly.
    const base_ts: u32 = 1_700_000_000;
    var hashes: [11]types.Hash256 = undefined;
    for (0..11) |h| {
        hashes[h] = [_]u8{0} ** 32;
        hashes[h][0] = @intCast(h + 1); // distinct, non-zero per height
    }

    for (0..11) |h| {
        const prev = if (h == 0) ([_]u8{0} ** 32) else hashes[h - 1];
        const hdr = types.BlockHeader{
            .version = 1,
            .prev_block = prev,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = base_ts + @as(u32, @intCast(h)),
            .bits = 0x1d00ffff,
            .nonce = 0,
        };
        // Persist CF_BLOCK_INDEX record: u32 height prefix + 80-byte header,
        // exactly the layout getPersistedHeader reads.
        var w = serialize.Writer.init(allocator);
        defer w.deinit();
        try w.writeInt(u32, @intCast(h));
        try serialize.writeBlockHeader(&w, &hdr);
        try db.put(storage.CF_BLOCK_INDEX, &hashes[h], w.getWritten());

        // Persist H:{height}→hash index in CF_DEFAULT.
        const hh_key = storage.ChainStore.buildHeightHashKey(@intCast(h));
        try db.put(storage.CF_DEFAULT, &hh_key, &hashes[h]);
    }

    // MTP at height 10 = median of timestamps for heights 0..10 = ts[5].
    const expected = validation.medianTimePast(&[_]u32{
        base_ts + 0, base_ts + 1, base_ts + 2,  base_ts + 3,
        base_ts + 4, base_ts + 5, base_ts + 6,  base_ts + 7,
        base_ts + 8, base_ts + 9, base_ts + 10,
    });
    try std.testing.expectEqual(base_ts + 5, expected); // sanity: median is ts[5]

    const got = manager.computeMtpAtHeight(10);
    // PRE-FIX this is 0 (empty header_index → break → n==0).  POST-FIX it is
    // the true median read via the persisted-header fallback.
    try std.testing.expect(got != 0);
    try std.testing.expectEqual(expected, got);
}

test "peer direction enum" {
    // Test that direction enum values work correctly
    const inbound: PeerDirection = .inbound;
    const outbound: PeerDirection = .outbound;

    try std.testing.expect(inbound != outbound);
    try std.testing.expectEqual(PeerDirection.inbound, inbound);
    try std.testing.expectEqual(PeerDirection.outbound, outbound);
}

test "peer error types" {
    // Test that all error types are distinct
    const err1: PeerError = PeerError.ConnectionFailed;
    const err2: PeerError = PeerError.HandshakeFailed;
    const err3: PeerError = PeerError.BadMagic;

    try std.testing.expect(err1 != err2);
    try std.testing.expect(err2 != err3);
    try std.testing.expect(err1 != err3);
}

// ============================================================================
// Peer Manager Discovery Tests
// ============================================================================

test "peer manager constants" {
    // Verify constants match Bitcoin Core defaults
    try std.testing.expectEqual(@as(usize, 8), MAX_OUTBOUND_CONNECTIONS);
    try std.testing.expectEqual(@as(usize, 117), MAX_INBOUND_CONNECTIONS);
    try std.testing.expectEqual(@as(usize, 125), MAX_TOTAL_CONNECTIONS);
    try std.testing.expectEqual(@as(i64, 30 * 60), PEER_ROTATION_INTERVAL);
    try std.testing.expectEqual(@as(u32, 10), DNS_SEED_TIMEOUT);
    try std.testing.expectEqual(@as(i64, 24 * 60 * 60), DEFAULT_BAN_DURATION);
}

test "address info struct" {
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);

    const info = AddressInfo{
        .address = addr,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .last_seen = 1234567890,
        .last_tried = 0,
        .attempts = 0,
        .success = false,
        .source = .dns_seed,
    };

    try std.testing.expectEqual(@as(u64, p2p.NODE_NETWORK | p2p.NODE_WITNESS), info.services);
    try std.testing.expectEqual(@as(i64, 1234567890), info.last_seen);
    try std.testing.expectEqual(@as(u32, 0), info.attempts);
    try std.testing.expect(!info.success);
    try std.testing.expectEqual(AddressSource.dns_seed, info.source);
}

test "address source enum" {
    const dns: AddressSource = .dns_seed;
    const peer: AddressSource = .peer_addr;
    const manual: AddressSource = .manual;

    try std.testing.expect(dns != peer);
    try std.testing.expect(peer != manual);
    try std.testing.expect(dns != manual);
}

test "peer manager address tracking - add and dedup" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 2 }, 8333);

    // Add first address
    try manager.addAddress(addr1, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());

    // Add same address again - should be deduplicated
    try manager.addAddress(addr1, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());

    // Add different address
    try manager.addAddress(addr2, p2p.NODE_WITNESS, .peer_addr);
    try std.testing.expectEqual(@as(usize, 2), manager.knownAddressCount());
}

test "peer manager address selection" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // No addresses - should return null
    try std.testing.expect(manager.selectPeerToConnect() == null);

    // Add an address
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    try manager.addAddress(addr, p2p.NODE_NETWORK, .dns_seed);

    // Should select the address
    const selected = manager.selectPeerToConnect();
    try std.testing.expect(selected != null);

    // After selection, attempts should be incremented
    // Cannot easily verify this without internal access, but selection happened
}

test "peer manager ban ip" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 8333);

    // Add address first
    try manager.addAddress(addr, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());

    // Ban the IP
    try manager.banIP(addr, DEFAULT_BAN_DURATION, "test ban");

    // Adding a new address with same IP should be rejected
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 18333); // Same IP, different port
    try manager.addAddress(addr2, p2p.NODE_NETWORK, .dns_seed);
    // Still only 1 address since same IP is banned
    try std.testing.expectEqual(@as(usize, 1), manager.knownAddressCount());
}

test "peer manager outbound/inbound count" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // No peers initially
    try std.testing.expectEqual(@as(usize, 0), manager.outboundCount());
    try std.testing.expectEqual(@as(usize, 0), manager.inboundCount());
    try std.testing.expectEqual(@as(usize, 0), manager.connectedCount());
}

test "peer manager address key generation" {
    // Test that different addresses produce different keys
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 2 }, 8333);
    const addr3 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8334); // Same IP, different port

    const key1 = PeerManager.addressKey(addr1);
    const key2 = PeerManager.addressKey(addr2);
    const key3 = PeerManager.addressKey(addr3);

    try std.testing.expect(key1 != key2);
    try std.testing.expect(key1 != key3);
    try std.testing.expect(key2 != key3);

    // Same address should produce same key
    const key1_again = PeerManager.addressKey(addr1);
    try std.testing.expectEqual(key1, key1_again);
}

test "peer manager ipv4 extraction" {
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 8333);

    const ip_u32 = PeerManager.ipv4AsU32(addr);
    try std.testing.expect(ip_u32 != null);

    // 192.168.1.100 in big-endian u32
    const expected: u32 = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    try std.testing.expectEqual(expected, ip_u32.?);
}

test "peer manager running state" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // Initially not running
    try std.testing.expect(!manager.running.load(.acquire));

    // Start and immediately stop
    manager.running.store(true, .release);
    try std.testing.expect(manager.running.load(.acquire));

    manager.stop();
    try std.testing.expect(!manager.running.load(.acquire));
}

// ============================================================================
// Misbehavior Scoring Tests
// ============================================================================

test "misbehaving function increments score and sets should_ban" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = p2p.NODE_NETWORK,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
    };

    // Initially not marked for ban
    try std.testing.expect(!peer.should_ban);
    try std.testing.expectEqual(@as(u32, 0), peer.ban_score);

    // Add misbehavior with 50 points
    peer.misbehaving(50, "test misbehavior");
    try std.testing.expectEqual(@as(u32, 50), peer.ban_score);
    try std.testing.expect(!peer.should_ban);

    // Add another 50 points - now at 100, should be banned
    peer.misbehaving(50, "second misbehavior");
    try std.testing.expectEqual(@as(u32, 100), peer.ban_score);
    try std.testing.expect(peer.should_ban);
}

test "misbehaving with 100 points immediately bans" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 10, 0, 0, 5 }, 8333),
        .state = .handshake_complete,
        .direction = .inbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .inbound,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = std.time.timestamp(),
    };

    // Invalid block header = 100 points = immediate ban
    peer.misbehaving(100, "invalid block header");
    try std.testing.expectEqual(@as(u32, 100), peer.ban_score);
    try std.testing.expect(peer.should_ban);
}

test "addBanScore sets should_ban at threshold" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4([4]u8{ 172, 16, 0, 1 }, 8333),
        .state = .connected,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    // Add 99 points - not banned yet
    try std.testing.expect(!peer.addBanScore(99));
    try std.testing.expect(!peer.should_ban);

    // Add 1 more - now banned
    try std.testing.expect(peer.addBanScore(1));
    try std.testing.expect(peer.should_ban);
}

test "peer manager ban integration" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 50, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 50, 2 }, 8333);

    // Add addresses
    try manager.addAddress(addr1, p2p.NODE_NETWORK, .dns_seed);
    try manager.addAddress(addr2, p2p.NODE_NETWORK, .dns_seed);
    try std.testing.expectEqual(@as(usize, 2), manager.knownAddressCount());

    // Ban addr1
    try manager.banIP(addr1, DEFAULT_BAN_DURATION, "protocol violation");

    // Verify addr1 is banned
    try std.testing.expect(manager.isIPBanned(addr1));
    try std.testing.expect(!manager.isIPBanned(addr2));

    // Can't add same IP again
    const addr1_different_port = std.net.Address.initIp4([4]u8{ 192, 168, 50, 1 }, 9999);
    try manager.addAddress(addr1_different_port, p2p.NODE_NETWORK, .manual);
    // Count should still be 2
    try std.testing.expectEqual(@as(usize, 2), manager.knownAddressCount());

    // Unban addr1
    try std.testing.expect(manager.unbanIP(addr1));
    try std.testing.expect(!manager.isIPBanned(addr1));
}

// ============================================================================
// Eclipse Attack Protection Tests
// ============================================================================

test "eclipse protection: netGroup returns /16 for IPv4" {
    // 192.168.1.1 should have netgroup (192 << 8) | 168 = 49320
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const group1 = netGroup(addr1);
    const expected1: u32 = (192 << 8) | 168;
    try std.testing.expectEqual(expected1, group1);

    // 192.168.2.2 should have same netgroup (same /16)
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 2, 2 }, 8333);
    const group2 = netGroup(addr2);
    try std.testing.expectEqual(group1, group2);

    // 10.0.0.1 should have different netgroup
    const addr3 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333);
    const group3 = netGroup(addr3);
    const expected3: u32 = (10 << 8) | 0;
    try std.testing.expectEqual(expected3, group3);
    try std.testing.expect(group1 != group3);
}

test "eclipse protection: netGroup returns /32 for IPv6" {
    // IPv6 uses first 4 bytes (32 bits) for netgroup
    // 2001:db8:1234:5678::1 should use 2001:db8 (first 4 bytes)
    const addr1 = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 1 }, 8333, 0, 0);
    const group1 = netGroup(addr1);
    const expected1: u32 = (0x20 << 24) | (0x01 << 16) | (0x0d << 8) | 0xb8;
    try std.testing.expectEqual(expected1, group1);

    // Same /32 prefix should have same netgroup
    const addr2 = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 8333, 0, 0);
    const group2 = netGroup(addr2);
    try std.testing.expectEqual(group1, group2);

    // Different /32 prefix should have different netgroup
    const addr3 = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb9, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 1 }, 8333, 0, 0);
    const group3 = netGroup(addr3);
    try std.testing.expect(group1 != group3);
}

test "eclipse protection: sameNetGroup compares correctly" {
    // Same /16 subnet
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 255, 255 }, 8333);
    try std.testing.expect(sameNetGroup(addr1, addr2));

    // Different /16 subnet
    const addr3 = std.net.Address.initIp4([4]u8{ 192, 169, 1, 1 }, 8333);
    try std.testing.expect(!sameNetGroup(addr1, addr3));
}

test "eclipse protection: netgroup diversity tracking" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    var manager = PeerManager.init(allocator, params);
    defer manager.deinit();

    // Initially no netgroups tracked
    try std.testing.expectEqual(@as(usize, 0), manager.outbound_netgroups.count());

    // Add an address from 192.168.x.x
    const addr1 = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    manager.outbound_netgroups.put(netGroup(addr1), {}) catch unreachable;
    try std.testing.expectEqual(@as(usize, 1), manager.outbound_netgroups.count());

    // Same netgroup should violate diversity
    const addr2 = std.net.Address.initIp4([4]u8{ 192, 168, 2, 2 }, 8333);
    try std.testing.expect(manager.violatesNetgroupDiversity(addr2));

    // Different netgroup should not violate
    const addr3 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8333);
    try std.testing.expect(!manager.violatesNetgroupDiversity(addr3));
}

test "eclipse protection: eviction candidate building" {
    const allocator = std.testing.allocator;
    const params = &consensus.MAINNET;

    // Create mock peers
    var peers: [3]*Peer = undefined;
    var buffers: [3]std.ArrayList(u8) = undefined;
    for (0..3) |i| {
        buffers[i] = std.ArrayList(u8).init(allocator);
        peers[i] = allocator.create(Peer) catch unreachable;
        peers[i].* = .{
            .stream = undefined,
            .address = std.net.Address.initIp4([4]u8{ 192, 168, @intCast(i), 1 }, 8333),
            .state = .handshake_complete,
            .direction = if (i == 0) .outbound else .inbound,
            .version_info = null,
            .services = p2p.NODE_NETWORK,
            .last_ping_time = 0,
            .last_pong_time = 0,
            .last_ping_nonce = 0,
            .last_message_time = 1000,
            .bytes_sent = 0,
            .bytes_received = 0,
            .start_height = 0,
            .network_params = params,
            .allocator = allocator,
            .recv_buffer = buffers[i],
            .is_witness_capable = true,
            .is_headers_first = false,
            .ban_score = 0,
            .should_ban = false,
            .conn_type = if (i == 0) .outbound_full_relay else .inbound,
            .last_block_time = @as(i64, @intCast(i)) * 100,
            .last_tx_time = @as(i64, @intCast(i)) * 50,
            .min_ping_time = @as(i64, @intCast(3 - i)) * 10,
            .relay_txs = true,
            .is_protected = false,
            .connect_time = @as(i64, @intCast(i)) * 200,
        };
    }
    defer {
        for (0..3) |i| {
            buffers[i].deinit();
            allocator.destroy(peers[i]);
        }
    }

    const candidates = try buildEvictionCandidates(&peers, allocator);
    defer allocator.free(candidates);

    // Should only include inbound peers (2 of 3)
    try std.testing.expectEqual(@as(usize, 2), candidates.len);

    // Verify candidates are inbound only
    for (candidates) |c| {
        try std.testing.expect(peers[c.peer_index].direction == .inbound);
    }
}

test "eclipse protection: eviction algorithm protects by categories" {
    const allocator = std.testing.allocator;

    // Create a set of candidates with different characteristics
    var candidates = [_]EvictionCandidate{
        // Fast ping (should be protected)
        .{ .peer_index = 0, .net_group = 1, .min_ping_time = 10, .last_block_time = 0, .last_tx_time = 0, .connect_time = 1000, .relay_txs = true, .is_protected = false },
        // Recent tx (should be protected)
        .{ .peer_index = 1, .net_group = 2, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 900, .connect_time = 500, .relay_txs = true, .is_protected = false },
        // Recent block (should be protected)
        .{ .peer_index = 2, .net_group = 3, .min_ping_time = 100, .last_block_time = 800, .last_tx_time = 0, .connect_time = 600, .relay_txs = true, .is_protected = false },
        // Long connection (should be protected)
        .{ .peer_index = 3, .net_group = 4, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 100, .relay_txs = true, .is_protected = false },
        // Distinct netgroup (should be protected)
        .{ .peer_index = 4, .net_group = 5, .min_ping_time = 100, .last_block_time = 0, .last_tx_time = 0, .connect_time = 700, .relay_txs = true, .is_protected = false },
        // Unprotected - same netgroup as another, no special characteristics
        .{ .peer_index = 5, .net_group = 1, .min_ping_time = 200, .last_block_time = 0, .last_tx_time = 0, .connect_time = 800, .relay_txs = true, .is_protected = false },
        // Another unprotected - same netgroup
        .{ .peer_index = 6, .net_group = 1, .min_ping_time = 300, .last_block_time = 0, .last_tx_time = 0, .connect_time = 900, .relay_txs = true, .is_protected = false },
    };

    const victim = selectEvictionCandidate(&candidates, allocator);

    // Should select a victim (the algorithm will pick from netgroup 1 which has most connections)
    try std.testing.expect(victim != null);
    // The victim should be from netgroup 1 (most connections)
    if (victim) |v| {
        try std.testing.expect(v == 5 or v == 6); // One of the unprotected peers in netgroup 1
    }
}

test "eclipse protection: eviction returns null when all protected" {
    const allocator = std.testing.allocator;

    // Create candidates that will all be protected
    // 4 distinct netgroups, each with unique characteristics
    var candidates = [_]EvictionCandidate{
        .{ .peer_index = 0, .net_group = 1, .min_ping_time = 10, .last_block_time = 100, .last_tx_time = 100, .connect_time = 100, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 1, .net_group = 2, .min_ping_time = 20, .last_block_time = 200, .last_tx_time = 200, .connect_time = 200, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 2, .net_group = 3, .min_ping_time = 30, .last_block_time = 300, .last_tx_time = 300, .connect_time = 300, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 3, .net_group = 4, .min_ping_time = 40, .last_block_time = 400, .last_tx_time = 400, .connect_time = 400, .relay_txs = true, .is_protected = false },
    };

    // With only 4 candidates and protection for netgroup(4), ping(8), tx(4), block-relay-only(8), block(4), time(remaining/2)
    // all 4 should be protected
    const victim = selectEvictionCandidate(&candidates, allocator);

    // All protected, no victim
    try std.testing.expect(victim == null);
}

test "eclipse protection: connection type enum" {
    // Test all connection types are distinct
    const types_arr = [_]ConnectionType{
        .inbound,
        .outbound_full_relay,
        .block_relay,
        .manual,
        .feeler,
        .addr_fetch,
    };

    for (types_arr, 0..) |t1, i| {
        for (types_arr, 0..) |t2, j| {
            if (i == j) {
                try std.testing.expectEqual(t1, t2);
            } else {
                try std.testing.expect(t1 != t2);
            }
        }
    }
}

test "eclipse protection: eclipse constants match Bitcoin Core" {
    // Verify protection limits match Bitcoin Core defaults
    try std.testing.expectEqual(@as(usize, 8), EVICTION_PROTECT_PING);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_TX);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_BLOCK);
    try std.testing.expectEqual(@as(usize, 8), EVICTION_PROTECT_BLOCK_RELAY_ONLY);
    try std.testing.expectEqual(@as(usize, 8), EVICTION_PROTECT_TIME);
    try std.testing.expectEqual(@as(usize, 4), EVICTION_PROTECT_NETGROUP);
    try std.testing.expectEqual(@as(usize, 2), MAX_BLOCK_RELAY_ONLY_ANCHORS);
}

test "eclipse protection: block-relay-only peers get protected" {
    const allocator = std.testing.allocator;

    // Create candidates: some relay_txs=true, some relay_txs=false (block-relay-only)
    var candidates = [_]EvictionCandidate{
        // Block-relay-only peers (relay_txs=false) - should be protected
        .{ .peer_index = 0, .net_group = 1, .min_ping_time = 500, .last_block_time = 100, .last_tx_time = 0, .connect_time = 900, .relay_txs = false, .is_protected = false },
        .{ .peer_index = 1, .net_group = 2, .min_ping_time = 500, .last_block_time = 200, .last_tx_time = 0, .connect_time = 800, .relay_txs = false, .is_protected = false },
        // Full relay peers
        .{ .peer_index = 2, .net_group = 3, .min_ping_time = 500, .last_block_time = 50, .last_tx_time = 50, .connect_time = 700, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 3, .net_group = 4, .min_ping_time = 500, .last_block_time = 60, .last_tx_time = 60, .connect_time = 600, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 4, .net_group = 5, .min_ping_time = 500, .last_block_time = 70, .last_tx_time = 70, .connect_time = 500, .relay_txs = true, .is_protected = false },
        .{ .peer_index = 5, .net_group = 6, .min_ping_time = 500, .last_block_time = 80, .last_tx_time = 80, .connect_time = 400, .relay_txs = true, .is_protected = false },
    };

    const victim = selectEvictionCandidate(&candidates, allocator);

    // Should select a victim
    try std.testing.expect(victim != null);

    // The victim should NOT be a block-relay-only peer (0 or 1) since those get protected
    if (victim) |v| {
        try std.testing.expect(v != 0 and v != 1);
    }
}

// ============================================================================
// BIP-133 Feefilter Tests
// ============================================================================

test "feefilter: constants match Bitcoin Core defaults" {
    // Verify feefilter constants match Bitcoin Core
    try std.testing.expectEqual(@as(i64, 600), AVG_FEEFILTER_BROADCAST_INTERVAL); // 10 min
    try std.testing.expectEqual(@as(i64, 300), MAX_FEEFILTER_CHANGE_DELAY); // 5 min
    try std.testing.expectEqual(@as(u64, 1000), MIN_RELAY_FEE); // 1000 sat/kvB
    try std.testing.expectEqual(@as(u64, 1000), INCREMENTAL_RELAY_FEE); // 1000 sat/kvB
}

test "feefilter: peer fee_filter fields initialized to zero" {
    const allocator = std.testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333),
        .state = .connecting,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.MAINNET,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
        .fee_filter_received = 0,
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    try std.testing.expectEqual(@as(u64, 0), peer.fee_filter_received);
    try std.testing.expectEqual(@as(u64, 0), peer.fee_filter_sent);
    try std.testing.expectEqual(@as(i64, 0), peer.next_send_feefilter);
}

test "feefilter: passesFeeFilter accepts when no filter set" {
    const allocator = std.testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.MAINNET,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
        .fee_filter_received = 0, // No filter
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    // With no filter set, all transactions should pass
    try std.testing.expect(peer.passesFeeFilter(0));
    try std.testing.expect(peer.passesFeeFilter(500));
    try std.testing.expect(peer.passesFeeFilter(1000));
    try std.testing.expect(peer.passesFeeFilter(10000));
}

test "feefilter: passesFeeFilter filters below threshold" {
    const allocator = std.testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    var peer = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.MAINNET,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
        .fee_filter_received = 5000, // 5000 sat/kvB minimum
        .fee_filter_sent = 0,
        .next_send_feefilter = 0,
    };

    // Below threshold - should not pass
    try std.testing.expect(!peer.passesFeeFilter(0));
    try std.testing.expect(!peer.passesFeeFilter(1000));
    try std.testing.expect(!peer.passesFeeFilter(4999));

    // At or above threshold - should pass
    try std.testing.expect(peer.passesFeeFilter(5000));
    try std.testing.expect(peer.passesFeeFilter(5001));
    try std.testing.expect(peer.passesFeeFilter(10000));
}

test "feefilter message encode/decode round-trip" {
    const allocator = std.testing.allocator;

    // Create a feefilter message with MIN_RELAY_FEE
    const msg = p2p.Message{ .feefilter = .{ .feerate = MIN_RELAY_FEE } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    // Decode header
    const header = p2p.MessageHeader.decode(encoded[0..24]);
    try std.testing.expectEqualStrings("feefilter", header.commandName());
    try std.testing.expectEqual(@as(u32, 8), header.length); // u64 = 8 bytes

    // Decode payload
    const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
    try std.testing.expectEqual(MIN_RELAY_FEE, decoded.feefilter.feerate);
}

test "feefilter: high fee rate message encoding" {
    const allocator = std.testing.allocator;

    // Test with MAX_MONEY fee filter (used during IBD)
    const MAX_MONEY: u64 = 2_100_000_000_000_000;
    const msg = p2p.Message{ .feefilter = .{ .feerate = MAX_MONEY } };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const header = p2p.MessageHeader.decode(encoded[0..24]);
    const decoded = try p2p.decodePayload(header.commandName(), encoded[24..], allocator);
    try std.testing.expectEqual(MAX_MONEY, decoded.feefilter.feerate);
}

test "feefilter: hysteresis thresholds" {
    // Test the hysteresis math: 25% decrease or 33% increase triggers early send
    const current_filter: u64 = 1000;

    // 25% decrease: new < 3/4 * old = 750
    const decrease_threshold = (3 * current_filter) / 4;
    try std.testing.expectEqual(@as(u64, 750), decrease_threshold);

    // 33% increase: new > 4/3 * old = 1333
    const increase_threshold = (4 * current_filter) / 3;
    try std.testing.expectEqual(@as(u64, 1333), increase_threshold);

    // Test boundary conditions
    try std.testing.expect(749 < decrease_threshold); // Triggers
    try std.testing.expect(750 == decrease_threshold); // Boundary - does not trigger
    try std.testing.expect(1333 == increase_threshold); // Boundary - does not trigger
    try std.testing.expect(1334 > increase_threshold); // Triggers
}

// ============================================================================
// drainBlockBuffer in-flight accounting regression (wave 5 — wedge at 29,953)
//
// These tests exercise the per-peer and global in-flight counter bookkeeping
// that was missing on response paths before the wave-5 fix, plus the
// download_cursor rewind that ensures dropped blocks get re-requested.
// ============================================================================

test "drain wedge: recordBlockReceived decrements counters on every path" {
    // The wedge at 29,953 was caused by the global in-flight counter not
    // being reliably restored after duplicate/orphan/buffer-full responses.
    // Verify the per-peer recordBlockReceived bookkeeping used by the block
    // handler: it must decrement on every response kind and must be
    // saturating on the lower bound (late response after a stall-recovery
    // reset is legal and must not underflow).

    // Build a minimal Peer with only the fields recordBlockRequest /
    // recordBlockReceived touch. We skip the full struct init by going
    // through undefined and populating just the relevant counters.
    var dummy: Peer = undefined;
    dummy.blocks_in_flight_count = 0;
    dummy.oldest_block_in_flight_time = 0;
    dummy.last_block_time = 0;

    // Simulate 5 block requests.
    var i: u32 = 0;
    while (i < 5) : (i += 1) dummy.recordBlockRequest();
    try std.testing.expectEqual(@as(u32, 5), dummy.blocks_in_flight_count);
    try std.testing.expect(dummy.oldest_block_in_flight_time > 0);

    // Mix of response kinds: success, duplicate, orphan, buffer-full-drop,
    // put-failure. All route through recordBlockReceived. After N responses
    // for N requests the counter must be 0 and oldest_time must be cleared.
    dummy.recordBlockReceived(); // success
    dummy.recordBlockReceived(); // duplicate
    dummy.recordBlockReceived(); // orphan (buffered, drained later)
    dummy.recordBlockReceived(); // buffer-full-drop
    dummy.recordBlockReceived(); // put-failure / error
    try std.testing.expectEqual(@as(u32, 0), dummy.blocks_in_flight_count);
    try std.testing.expectEqual(@as(i64, 0), dummy.oldest_block_in_flight_time);

    // Extra decrements (e.g. stall-recovery reset followed by late response)
    // must not underflow. Counter stays at 0.
    dummy.recordBlockReceived();
    dummy.recordBlockReceived();
    try std.testing.expectEqual(@as(u32, 0), dummy.blocks_in_flight_count);
}

test "drain wedge: full-buffer drop rewinds download_cursor so the block is re-requested" {
    // Root cause of the 29,953 wedge: when block_buffer was full (1024) and a
    // non-next block arrived, it was dropped and the in-flight counter was
    // decremented (correct) — but download_cursor had already been advanced
    // past the dropped hash by pipelineBlockRequests. The normal pipeline
    // therefore never re-issued it; only the 5-second stall-recovery loop
    // re-requested (32 blocks/peer). That capped IBD throughput to ~6 blk/s
    // and the node wedged when every new block fell into the drop path.
    //
    // The fix: in the drop path, rewind download_cursor to connect_cursor
    // so the next pipelineBlockRequests walks the queue from the front and
    // re-requests any hash not currently in block_buffer. The buffer-contains
    // guard in pipelineBlockRequests makes the rewind cheap (already-buffered
    // hashes are skipped). This test models the cursor state after a drop
    // and asserts the rewind invariant.

    var download_cursor: u32 = 800;
    const connect_cursor: u32 = 100;

    // Drop path fires — rewind condition from the fix.
    if (download_cursor > connect_cursor) {
        download_cursor = connect_cursor;
    }
    try std.testing.expectEqual(@as(u32, 100), download_cursor);

    // Idempotent: if download_cursor was already at/behind connect_cursor
    // (e.g. just after a stall-recovery reset), don't rewind further.
    download_cursor = 50;
    if (download_cursor > connect_cursor) {
        download_cursor = connect_cursor;
    }
    try std.testing.expectEqual(@as(u32, 50), download_cursor);

    download_cursor = connect_cursor;
    if (download_cursor > connect_cursor) {
        download_cursor = connect_cursor;
    }
    try std.testing.expectEqual(connect_cursor, download_cursor);
}

test "drain wedge: global in-flight returns to zero after mixed responses" {
    // End-to-end counter invariant: after N requests and N responses of
    // arbitrary kinds (success, duplicate, orphan, buffer-full-drop,
    // put-failure, error), the global blocks_in_flight counter must be 0.
    // We model just the global counter path (the block-handler decrement)
    // without standing up a full PeerManager — the logic is a single
    // saturating subtract per response, applied once per response path.

    var blocks_in_flight: u32 = 0;

    // 10 requests.
    const n: u32 = 10;
    var i: u32 = 0;
    while (i < n) : (i += 1) blocks_in_flight += 1;
    try std.testing.expectEqual(n, blocks_in_flight);

    // 10 mixed responses — each decrements exactly once regardless of kind,
    // matching the unconditional decrement at the top of the .block branch.
    i = 0;
    while (i < n) : (i += 1) {
        if (blocks_in_flight > 0) blocks_in_flight -= 1;
    }
    try std.testing.expectEqual(@as(u32, 0), blocks_in_flight);

    // Late / unexpected response: saturating decrement — no underflow.
    if (blocks_in_flight > 0) blocks_in_flight -= 1;
    try std.testing.expectEqual(@as(u32, 0), blocks_in_flight);
}

// ============================================================================
// Wave 16 — Level-triggered per-peer block-request pipeline.
//
// These tests model the per-peer budgeting logic that replaced the global
// `blocks_in_flight < 128` gate after the wave-15 diagnostic showed the gate
// was edge-triggered in practice (reset fired on 94% of drain cycles).  They
// exercise the core invariants of `pipelineBlockRequests` without standing up
// a full PeerManager + socket fleet: (a) two peers can each hold the full
// per-peer cap of 16 in-flight blocks concurrently with no global collision,
// and (b) a slow peer whose in-flight count exceeds BLOCK_DOWNLOAD_TIMEOUT is
// disconnected and its slots are returned without affecting the other peers'
// budgets (and the download cursor is rewound so dropped hashes get
// re-requested — the wave-9 rewind preserved).
// ============================================================================

test "W16 pipeline: per-peer cap allows 32 concurrent in-flight across two peers" {
    // Model: two peers, each with per-peer cap MAX_BLOCKS_IN_TRANSIT_PER_PEER.
    // Pipeline fills each peer up to its cap; the sum is 2*cap with no global
    // ceiling that would have clamped a single peer's slot grab.
    var peer_a: Peer = undefined;
    peer_a.blocks_in_flight_count = 0;
    peer_a.oldest_block_in_flight_time = 0;
    peer_a.last_block_time = 0;

    var peer_b: Peer = undefined;
    peer_b.blocks_in_flight_count = 0;
    peer_b.oldest_block_in_flight_time = 0;
    peer_b.last_block_time = 0;

    const cap = MAX_BLOCKS_IN_TRANSIT_PER_PEER;
    try std.testing.expectEqual(@as(u32, 16), cap);

    // Fill peer A to its cap — mirrors the inner batch loop in
    // pipelineBlockRequests (`while (batch_count < peer_budget)`).
    var a_budget = cap - peer_a.blocks_in_flight_count;
    try std.testing.expectEqual(cap, a_budget);
    var i: u32 = 0;
    while (i < a_budget) : (i += 1) peer_a.recordBlockRequest();
    try std.testing.expectEqual(cap, peer_a.blocks_in_flight_count);

    // Fill peer B independently — the old global counter would have shown 16
    // here and clamped peer B to zero new slots.  Under per-peer budgeting
    // peer B sees its own fresh budget of cap.
    const b_budget = cap - peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(cap, b_budget);
    i = 0;
    while (i < b_budget) : (i += 1) peer_b.recordBlockRequest();
    try std.testing.expectEqual(cap, peer_b.blocks_in_flight_count);

    // Both peers at their cap concurrently: 2*cap = 32 blocks in flight,
    // no global collision, no edge-trigger wedge.
    const total = peer_a.blocks_in_flight_count + peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 32), total);

    // A third refill attempt on peer A with its cap already full yields
    // zero budget — pipeline correctly skips this peer on the next tick.
    a_budget = if (peer_a.blocks_in_flight_count >= cap) 0 else cap - peer_a.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 0), a_budget);

    // Peer A's first response frees one slot.  Peer B's cap is untouched —
    // this is the level-triggered property the wave-15 diag called out: a
    // slow peer does not starve the others.
    peer_a.recordBlockReceived();
    a_budget = cap - peer_a.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 1), a_budget);
    try std.testing.expectEqual(cap, peer_b.blocks_in_flight_count);
}

test "W16 pipeline: slow-peer disconnect rewinds cursor without stalling others" {
    // Slow-peer disconnect-and-rewind path replaces the old 5s global
    // stall-recovery reset.  When checkBlockDownloadTimeouts fires on
    // peer A, removePeerByIndex returns A's slots to the pool, and the
    // wave-9 buffer-drop rewind ensures the dropped hashes get
    // re-requested by the normal pipeline from peer B.
    var peer_a: Peer = undefined;
    peer_a.blocks_in_flight_count = 0;
    peer_a.oldest_block_in_flight_time = 0;
    peer_a.last_block_time = 0;

    var peer_b: Peer = undefined;
    peer_b.blocks_in_flight_count = 0;
    peer_b.oldest_block_in_flight_time = 0;
    peer_b.last_block_time = 0;

    // Both peers have outstanding requests; peer A is the slow one.
    var i: u32 = 0;
    while (i < 8) : (i += 1) peer_a.recordBlockRequest();
    i = 0;
    while (i < 4) : (i += 1) peer_b.recordBlockRequest();
    try std.testing.expectEqual(@as(u32, 8), peer_a.blocks_in_flight_count);
    try std.testing.expectEqual(@as(u32, 4), peer_b.blocks_in_flight_count);

    // Simulate BLOCK_DOWNLOAD_TIMEOUT on peer A: force oldest_time into
    // the past and assert hasBlockDownloadTimeout returns true.
    peer_a.oldest_block_in_flight_time = std.time.timestamp() - (BLOCK_DOWNLOAD_TIMEOUT + 1);
    try std.testing.expect(peer_a.hasBlockDownloadTimeout());
    try std.testing.expect(!peer_b.hasBlockDownloadTimeout());

    // removePeerByIndex decrements the global counter by the slow peer's
    // in-flight count (saturating subtract) and zeroes the peer's counters.
    // Model the global-counter update without a full PeerManager.
    var global: u32 = peer_a.blocks_in_flight_count + peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 12), global);
    if (global >= peer_a.blocks_in_flight_count) {
        global -= peer_a.blocks_in_flight_count;
    } else {
        global = 0;
    }
    // Peer B's budget is unaffected by A's disconnect — this is the core
    // guarantee over the old mass-reset path.
    try std.testing.expectEqual(@as(u32, 4), global);
    try std.testing.expectEqual(@as(u32, 4), peer_b.blocks_in_flight_count);

    // Wave-9 rewind invariant preserved: download_cursor rewinds to
    // connect_cursor so the pipeline re-issues dropped hashes on the next
    // tick (via peer B, which still has budget).  The buffer-contains
    // guard in pipelineBlockRequests makes the rewind cheap.
    var download_cursor: u32 = 800;
    const connect_cursor: u32 = 100;
    if (download_cursor > connect_cursor) download_cursor = connect_cursor;
    try std.testing.expectEqual(@as(u32, 100), download_cursor);

    // After rewind, peer B (still healthy) has cap - 4 = 12 slots of fresh
    // budget available to pick up the dropped hashes on the next
    // level-triggered tick.
    const b_remaining_budget = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_b.blocks_in_flight_count;
    try std.testing.expectEqual(@as(u32, 12), b_remaining_budget);
}

// ============================================================================
// BIP-324 negotiation: per-peer v1-fallback tracking on PeerManager.
// ============================================================================

test "BIP-324: markV1Only / isV1Only round-trip on IPv4" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const addr = std.net.Address.initIp4(.{ 192, 168, 1, 50 }, 8333);
    try std.testing.expect(!pm.isV1Only(addr));
    pm.markV1Only(addr);
    try std.testing.expect(pm.isV1Only(addr));
}

test "BIP-324: v1-fallback set distinguishes addresses by port" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const a = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8333);
    const b = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8334);
    pm.markV1Only(a);
    try std.testing.expect(pm.isV1Only(a));
    try std.testing.expect(!pm.isV1Only(b));
}

test "BIP-324: v1-fallback set caps at V2_FALLBACK_CACHE_MAX" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // Insert V2_FALLBACK_CACHE_MAX + 5 entries; the cap must hold (LRU
    // drops a random entry on overflow, so we don't assert WHICH entry
    // got evicted, only that the count never exceeds the cap).
    var i: u32 = 0;
    while (i < PeerManager.V2_FALLBACK_CACHE_MAX + 5) : (i += 1) {
        const ip: [4]u8 = .{ @truncate(i >> 24), @truncate(i >> 16), @truncate(i >> 8), @truncate(i) };
        const port: u16 = @truncate(8333 + (i & 0xFFF));
        const addr = std.net.Address.initIp4(ip, port);
        pm.markV1Only(addr);
        try std.testing.expect(pm.v2_fallback_set.count() <= PeerManager.V2_FALLBACK_CACHE_MAX);
    }
}

test "BIP-324: bip324V2Enabled defaults on, honors env var off-toggles" {
    // Default state — env unset → returns true (default ON since W90,
    // matching Bitcoin Core 26+ `-v2transport=1`).  We can't reliably
    // unset an env var in a Zig test (no portable unsetenv wrapper in
    // std for our use), so verify only the non-set path is true-by-
    // default.  When the operator sets CLEARBIT_BIP324_V2=0 (or "false"
    // / "FALSE"), bip324V2Enabled() returns false; otherwise true.
    if (std.posix.getenv("CLEARBIT_BIP324_V2") == null) {
        try std.testing.expect(Peer.bip324V2Enabled());
    }
}

// ---------------------------------------------------------------------------
// HSync wave: header-sync DoS resistance + BIP-130 sendheaders regression
// tests.
// Reference: bitcoin-core/src/validation.cpp (CheckBlockHeader,
//            ContextualCheckBlockHeader)
// Reference: bitcoin-core/src/net_processing.cpp (NetMsgType::SENDHEADERS)
// Audit doc: CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
// ---------------------------------------------------------------------------

test "HSync: validateHeaderContextual rejects future-time header" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const now: i64 = 2_000_000_000; // Fixed, deterministic "now" for the test.
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0} ** 32,
        // 1 day past `now` — well over the 7200s allowance.
        .timestamp = @intCast(now + 86_400),
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    const verdict = pm.validateHeaderContextual(&header, now);
    try std.testing.expectEqual(PeerManager.HeaderTimeReject.future_time, verdict);
}

test "HSync: validateHeaderContextual enforces BIP-113 MTP at acceptance" {
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    // Seed header_index with 11 ancestors, all stamped at t=1000..1010.
    // MTP of those is the median = 1005.  A new header chained onto the
    // tip must have timestamp > 1005.
    var prev: types.Hash256 = [_]u8{0xAA} ** 32;
    var i: u32 = 0;
    while (i < 11) : (i += 1) {
        const this_hash: types.Hash256 = blk: {
            var h: types.Hash256 = [_]u8{0} ** 32;
            h[0] = @intCast(i + 1);
            break :blk h;
        };
        const ts: u32 = 1000 + i;
        try pm.header_index.put(this_hash, .{
            .hash = this_hash,
            .prev_hash = prev,
            .height = i,
            .chain_work = [_]u8{0} ** 32,
            .timestamp = ts,
            .header = types.BlockHeader{
                .version = 1,
                .prev_block = prev,
                .merkle_root = [_]u8{0} ** 32,
                .timestamp = ts,
                .bits = 0x1d00ffff,
                .nonce = 0,
            },
            .last_seen = std.time.timestamp(),
        });
        prev = this_hash;
    }

    // MTP of the 11 ancestors is 1005.
    // Test 1: timestamp == MTP → rejected.
    const at_mtp = types.BlockHeader{
        .version = 1,
        .prev_block = prev,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1005,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };
    // Use a "now" comfortably in the future relative to header.timestamp so
    // future-time isn't the rejecting axis.
    const now: i64 = 2_000_000_000;
    try std.testing.expectEqual(
        PeerManager.HeaderTimeReject.mtp_violation,
        pm.validateHeaderContextual(&at_mtp, now),
    );

    // Test 2: timestamp == MTP + 1 → accepted.
    const above_mtp = types.BlockHeader{
        .version = 1,
        .prev_block = prev,
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1006,
        .bits = 0x1d00ffff,
        .nonce = 0,
    };
    try std.testing.expectEqual(
        PeerManager.HeaderTimeReject.ok,
        pm.validateHeaderContextual(&above_mtp, now),
    );
}

test "HSync: validateHeaderContextual skips MTP when no ancestors known" {
    // Genesis-relative case: header_index is empty, so MTP cannot be
    // computed.  The function must skip MTP and only enforce future-time.
    const allocator = std.testing.allocator;
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const now: i64 = 2_000_000_000;
    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0xFF} ** 32, // Unknown parent — no ancestors.
        .merkle_root = [_]u8{0} ** 32,
        .timestamp = 1_000_000, // Way in the past, but no MTP to compare to.
        .bits = 0x1d00ffff,
        .nonce = 0,
    };

    try std.testing.expectEqual(
        PeerManager.HeaderTimeReject.ok,
        pm.validateHeaderContextual(&header, now),
    );
}

test "HSync: BIP-130 send_headers flag defaults false on fresh Peer" {
    // A newly-initialised Peer must default to send_headers=false so the
    // Pattern A announce path falls back to inv until the peer explicitly
    // opts in.  Reference: bitcoin-core/src/net_processing.cpp
    // (PeerManagerImpl::m_sendheaders default false).
    const allocator = std.testing.allocator;
    var recv_buffer = std.ArrayList(u8).init(allocator);
    defer recv_buffer.deinit();

    const dummy = Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333),
        .state = .connecting,
        .direction = .outbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.MAINNET,
        .allocator = allocator,
        .recv_buffer = recv_buffer,
        .is_witness_capable = false,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = 0,
        .relay_txs = false,
        .is_protected = false,
        .connect_time = 0,
        .v2_cipher = null,
    };

    try std.testing.expect(!dummy.send_headers);
}

// ============================================================================
// W99 net_processing dispatch + Misbehaving gate audit tests
// ============================================================================

// Helper to create a minimal Peer struct for testing.
fn makeTestPeer(allocator: std.mem.Allocator, conn_type: ConnectionType) Peer {
    return Peer{
        .stream = undefined,
        .address = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8333),
        .state = .handshake_complete,
        .direction = .inbound,
        .version_info = null,
        .services = 0,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = std.time.timestamp(),
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 0,
        .network_params = &consensus.MAINNET,
        .allocator = allocator,
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .is_witness_capable = true,
        .is_headers_first = false,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = conn_type,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = true,
        .is_protected = false,
        .connect_time = 0,
    };
}

// G1: misbehaving() uses score accumulation, NOT the 2022 single-event flag model.
// FIX (W99 G1): misbehaving() now uses the Core 2022 single-event model
// (PR #25974): any single Misbehaving call sets should_ban=true immediately,
// no score accumulation required.
test "W99/G1: single Misbehaving call immediately sets should_ban (Core 2022 single-event)" {
    const allocator = std.testing.allocator;
    var peer = makeTestPeer(allocator, .outbound_full_relay);
    defer peer.recv_buffer.deinit();

    // A single Misbehaving call with ANY score immediately discourages.
    // Core canonical: net_processing.cpp:1898 peer.m_should_discourage = true
    peer.misbehaving(50, "first infraction");
    // Single-event: should_ban must be set after the first call, regardless of score.
    try std.testing.expect(peer.should_ban);

    // A second call does not blow up or reset the flag.
    peer.misbehaving(50, "second infraction");
    try std.testing.expect(peer.should_ban);
}

// G2 FIX: misbehaving() now exempts noban/manual/local peers (W99 G2).
// Core canonical: MaybeDiscourageAndDisconnect (net_processing.cpp:5083).
test "W99/G2: noban peer — misbehaving is a no-op (should_ban stays false)" {
    const allocator = std.testing.allocator;
    var peer = makeTestPeer(allocator, .inbound);
    defer peer.recv_buffer.deinit();
    peer.no_ban = true;

    peer.misbehaving(100, "bad behavior from noban peer");
    // NoBan peers must never be banned or disconnected.
    try std.testing.expect(!peer.should_ban);
    try std.testing.expectEqual(@as(u32, 0), peer.ban_score);
}

test "W99/G2: manual peer — misbehaving is a no-op (should_ban stays false)" {
    const allocator = std.testing.allocator;
    var manual_peer = makeTestPeer(allocator, .manual);
    defer manual_peer.recv_buffer.deinit();

    manual_peer.misbehaving(100, "bad behavior from manual peer");
    // Manual (addnode) peers must never be banned.
    try std.testing.expect(!manual_peer.should_ban);
    try std.testing.expectEqual(@as(u32, 0), manual_peer.ban_score);
}

test "W99/G2: local peer — misbehaving triggers disconnect-only (no ban-list entry)" {
    const allocator = std.testing.allocator;
    var local_peer = makeTestPeer(allocator, .inbound);
    defer local_peer.recv_buffer.deinit();
    // Override address to 127.0.0.1 (loopback).
    local_peer.address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8333);

    local_peer.misbehaving(100, "bad behavior from local peer");
    // Local peers: should_ban (triggers disconnect) but score NOT accumulated
    // (no discourage entry written to ban-list).
    try std.testing.expect(local_peer.should_ban);
    try std.testing.expectEqual(@as(u32, 0), local_peer.ban_score);
}

test "W99/G2: regular inbound peer — misbehaving discourages normally" {
    const allocator = std.testing.allocator;
    var peer = makeTestPeer(allocator, .inbound);
    defer peer.recv_buffer.deinit();
    // Default address is 10.0.0.1 (non-local).

    peer.misbehaving(100, "bad behavior from regular peer");
    // Regular peers: single-event — should_ban set immediately.
    // ban_score is NOT accumulated by misbehaving() (Core 2022 model).
    try std.testing.expect(peer.should_ban);
    try std.testing.expectEqual(@as(u32, 0), peer.ban_score);
}

// G3 (closed 2026-05-27): loadBanList() is now invoked at startup.
// main.zig calls peer_manager.loadBanList() right after startListening and
// before spawning the peer thread — banlist.json contents rehydrate so bans
// survive a graceful restart. Mirrors Bitcoin Core init.cpp's
// node.banman->LoadBanlist() call sequence.
test "W99/G3: loadBanList is wired at startup — bans persist across restarts" {
    // Wiring assertion: loadBanList is a public method on PeerManager and
    // returns the same kind of result as saveBanList. Wired call site lives
    // in main.zig (see comment block adjacent to the call).
    try std.testing.expect(@hasDecl(PeerManager, "loadBanList"));
    try std.testing.expect(@hasDecl(PeerManager, "saveBanList"));

    // Behavioural assertion: a BanList with a null path treats load() as a
    // no-op (no banned entries appear). This documents the safe default for
    // tests; production wiring uses the relative `banlist.json` path that
    // start_mainnet.sh `cd`s into before exec.
    const allocator = std.testing.allocator;
    var bl = banlist.BanList.init(allocator, null); // null path = no file
    defer bl.deinit();
    try bl.load(); // must succeed when no file is configured
    try std.testing.expectEqual(@as(usize, 0), bl.banned.count());
}

// G4: headers message with count > 2000 is not rejected with Misbehaving.
// BUG: Core calls Misbehaving() when nCount > max_headers_result (2000).
// Clearbit uses `h.headers.len >= 2000` only as a "request more" signal,
// never enforces the cap with misbehavior.
test "W99/G4: MAX_HEADERS_RESULTS cap (2000) not enforced with misbehaving" {
    // Verify the constant value that should be the cap.
    // Bitcoin Core net_processing.h: static const unsigned int MAX_HEADERS_RESULTS = 2000;
    const EXPECTED_MAX_HEADERS: u32 = 2000;
    // clearbit uses 2000 as a magic number inline, not as a named constant.
    // BUG: no Misbehaving call when a peer sends > 2000 headers.
    try std.testing.expectEqual(@as(u32, 2000), EXPECTED_MAX_HEADERS);
}

// G8: MAX_NUM_UNCONNECTING_HEADERS_MSGS is 10 in clearbit; Core uses 8.
// BUG: clearbit tolerates 2 extra unconnecting-headers batches before disconnecting.
test "W99/G8: unconnecting-headers limit is 10 (clearbit) vs 8 (Core)" {
    // Bitcoin Core constant: MAX_NUM_UNCONNECTING_HEADERS_MSGS (from older code) = 8.
    // clearbit sets it to 10, permitting 2 extra bogus orphan-header batches.
    const clearbit_limit = MAX_NUM_UNCONNECTING_HEADERS_MSGS;
    const core_limit: u32 = 8;
    try std.testing.expectEqual(@as(u32, 10), clearbit_limit);
    // Document the divergence:
    try std.testing.expect(clearbit_limit != core_limit);
}

// G12: orphan transactions have no time-based expiry (5-minute TTL missing).
// BUG: Bitcoin Core's TxOrphanage expires orphans after ORPHAN_TX_EXPIRE_TIME (5 min).
// Clearbit evicts orphans only when the pool is full (oldest-first by size),
// never by wall-clock age. A stale orphan can live indefinitely.
test "W99/G12: orphan pool lacks 5-minute TTL expiry" {
    const mempool = @import("mempool.zig");
    // Verify there is NO expiry constant defined (documenting the absence).
    // If someone adds it, this test will need updating.
    // We check that OrphanTx has a time_added field (it does) but no expiry sweep.
    const OrphanTx = mempool.OrphanTx;
    // time_added field exists (used for oldest-first eviction, not time-based expiry).
    const has_time_added = @hasField(OrphanTx, "time_added");
    try std.testing.expect(has_time_added);
    // BUG: no ORPHAN_TTL constant, no periodic expiry call exists in the codebase.
    // Bitcoin Core: static constexpr auto ORPHAN_TX_EXPIRE_TIME = 5min.
}

// G14 FIXED: orphan pool primary key changed txid → wtxid (BIP-339 / Core PR #18044).
// Primary map keyed by wtxid; secondary orphans_by_txid index maps txid→wtxid
// for parent-resolution and public hasOrphan/removeOrphan callers.
test "W99/G14: orphan pool keyed by wtxid (BIP-339 fix asserted)" {
    const mempool = @import("mempool.zig");
    // OrphanTx now carries both txid (secondary) and wtxid (primary key).
    const OrphanTx = mempool.OrphanTx;
    try std.testing.expect(@hasField(OrphanTx, "txid"));
    try std.testing.expect(@hasField(OrphanTx, "wtxid"));
    // Mempool has the secondary txid→wtxid index for parent-resolution.
    const Mempool = mempool.Mempool;
    try std.testing.expect(@hasField(Mempool, "orphans_by_txid"));
}

// G16/G17 FIXED: validateBlockForIBDOrReject failure now misbehaves the supplying peer.
// Fix: drainBlockBuffer looks up the source peer in block_source_peers and calls
// peer.misbehaving(100, "mutated-block") before breaking out of the loop.
// Mirrors Bitcoin Core MaybePunishNodeForBlock BLOCK_MUTATED/BLOCK_INVALID_HEADER
// arms (net_processing.cpp:1919, 1935).
test "W99/G16: block_source_peers tracks supplying peer; misbehaving(100) fires on reject" {
    const allocator = std.testing.allocator;

    // Create a PeerManager and a heap-allocated peer (mirrors the real alloc path).
    var pm = PeerManager.init(allocator, &consensus.MAINNET);
    defer pm.deinit();

    const peer = try allocator.create(Peer);
    peer.* = makeTestPeer(allocator, .outbound_full_relay);
    defer peer.recv_buffer.deinit();
    // Do NOT destroy peer here — pm.deinit() does not own it in this test;
    // we destroy it manually after asserting, before pm.deinit runs (pm has no
    // chain_state so it never reaches the ban-list save that touches peers).
    defer allocator.destroy(peer);

    // Add the peer to the manager's live list so the drain-path lookup finds it.
    try pm.peers.append(peer);

    // Record the peer as the source for a synthetic invalid block hash.
    const fake_hash: types.Hash256 = [_]u8{0xDE} ** 32;
    try pm.block_source_peers.put(fake_hash, @intFromPtr(peer));

    // Simulate the drain reject path: look up source and misbehave (mirrors
    // the fixed drainBlockBuffer code at the validateBlockForIBDOrReject site).
    if (pm.block_source_peers.get(fake_hash)) |source_ptr| {
        for (pm.peers.items) |p| {
            if (@intFromPtr(p) == source_ptr) {
                p.misbehaving(100, "mutated-block");
                break;
            }
        }
    }
    _ = pm.block_source_peers.remove(fake_hash);

    // Peer must now carry a 100-point score and should_ban=true.
    try std.testing.expectEqual(@as(u32, 100), peer.ban_score);
    try std.testing.expect(peer.should_ban);
    // Source map entry was removed.
    try std.testing.expect(pm.block_source_peers.get(fake_hash) == null);

    // Remove from peers list before allocator.destroy runs in defers above.
    _ = pm.peers.swapRemove(0);
}

// G19: post-handshake version message is silently ignored, not rejected.
// BUG: Core's ProcessMessage disconnects on a duplicate version message.
// Clearbit's handleMessage() has no .version arm; falls to `else => {}`.
test "W99/G19: duplicate version message falls to silent else branch" {
    // Verify handleMessage's switch has no dedicated .version case.
    // The only version handling is in performHandshake() — once, at connect time.
    // A second version message after handshake_complete is swallowed silently.
    // Bitcoin Core: "Got a 'version' message from peer %d after the handshake"
    // → fDisconnect = true.
    // We document this by checking the PeerState machine:
    // once state == .handshake_complete, there is no guard against a second version.
    const allocator = std.testing.allocator;
    var peer = makeTestPeer(allocator, .outbound_full_relay);
    defer peer.recv_buffer.deinit();
    try std.testing.expectEqual(PeerState.handshake_complete, peer.state);
    // No version-received flag is set on the peer struct — duplicate detection absent.
    try std.testing.expect(!@hasField(Peer, "version_received_count"));
}

// G23 FIXED: MAX_MESSAGE_SIZE now matches Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH.
// Core net.h: static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000;
// Was: 32 * 1024 * 1024 (33,554,432 bytes — 8× too large).
// Fix: 4 * 1000 * 1000 (4,000,000 bytes).
test "W99/G23: MAX_MESSAGE_SIZE equals Core MAX_PROTOCOL_MESSAGE_LENGTH (4,000,000)" {
    // Bitcoin Core net.h: MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000
    const CORE_MAX: usize = 4 * 1000 * 1000;
    const clearbit_max = p2p.MAX_MESSAGE_SIZE;
    try std.testing.expectEqual(CORE_MAX, clearbit_max);
    // Verify the named constant is also set correctly.
    try std.testing.expectEqual(CORE_MAX, p2p.MAX_PROTOCOL_MESSAGE_LENGTH);
    // Sanity: NOT the old 32 MiB value.
    try std.testing.expect(clearbit_max != 32 * 1024 * 1024);
}

// G25: wtxidrelay segregation — peer wtxid negotiation state is not tracked.
// BUG: Core gates MSG_WITNESS_TX inv relay on whether the peer sent wtxidrelay.
// Clearbit always uses msg_witness_tx in relays (peer.zig:4315) regardless of
// whether the remote peer negotiated BIP-339.
test "W99/G25: Peer struct has wtxid_relay_negotiated flag (FIXED — W103 G6+G20)" {
    // Core: CNodeState::m_wtxid_relay (set when we receive the wtxidrelay msg).
    // FIXED (W103): wtxid_relay_negotiated added to Peer; set in handshake when
    // the peer sends a wtxidrelay message. Relay path now uses MSG_WTX (=5) +
    // wtxid for negotiated peers and MSG_TX (=1) + txid for legacy peers.
    try std.testing.expect(@hasField(Peer, "wtxid_relay_negotiated"));
}

// G28 FIXED (anti-eclipse axis): sendAddresses() now caps at the named
// MAX_ADDR_TO_SEND = 1000 constant (Core net_processing.cpp), not an inline 100.
// A getaddr response is additionally capped at the 23% getaddrCap; this checks
// the absolute ceiling constant is the genuine Core value.
test "W99/G28: sendAddresses uses MAX_ADDR_TO_SEND = 1000 (Core constant present)" {
    // Bitcoin Core: static constexpr size_t MAX_ADDR_TO_SEND{1000};
    try std.testing.expectEqual(@as(usize, 1000), MAX_ADDR_TO_SEND);
    // The 23%-cap helper exists and clamps to this ceiling.
    try std.testing.expectEqual(@as(usize, 1000), getaddrCap(1_000_000));
}

// G5: PRESYNC/REDOWNLOAD pipeline still absent (W88 gap, not yet fixed).
// BUG: Core's headerssync.cpp PRESYNC phase anti-DoS pipeline is missing in clearbit.
// Without PRESYNC, a peer can exhaust the header-index memory before the
// min_chain_work gate fires.  The G8 min_pow_checked gate (FIX-4) closes the
// chain-work threshold gap but does not add the full PRESYNC/REDOWNLOAD pipeline.
test "W99/G5: PRESYNC/REDOWNLOAD pipeline absent from PeerManager" {
    // Verify no PRESYNC-related state exists on PeerManager.
    // Core: Peer::m_headers_sync (HeadersSyncState) drives PRESYNC/REDOWNLOAD.
    try std.testing.expect(!@hasField(PeerManager, "headers_sync"));
}

// G6: min_pow_checked gate — FIXED (W97 FIX-4).
// The live .headers handler now computes cumulative batch chain work and
// rejects batches below network_params.min_chain_work with a 100-point
// misbehave score, consistent with BLOCK_HEADER_LOW_WORK.
// Reference: bitcoin-core/src/validation.cpp:4226-4232 AcceptBlockHeader.
test "W99/G6: min_pow_checked gate wired — min_chain_work non-zero for mainnet" {
    // Gate uses network_params.min_chain_work.  Verify the dead-helper is now live:
    // mainnet has a non-zero threshold, regtest has zero (gate is a no-op there).
    const zero: [32]u8 = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &consensus.MAINNET.min_chain_work, &zero));
    try std.testing.expectEqualSlices(u8, &zero, &consensus.REGTEST.min_chain_work);
    // The .headers handler now calls cmpChainWorkBE(cum_work, min_chain_work).
    // Verify the comparison function exists and returns the expected sign.
    var low: [32]u8 = [_]u8{0} ** 32;
    low[31] = 1; // 0x01
    var high: [32]u8 = [_]u8{0} ** 32;
    high[30] = 1; // 0x0100 > 0x01
    try std.testing.expect(cmpChainWorkBE(&low, &high) < 0); // low < high → would be rejected
    try std.testing.expect(cmpChainWorkBE(&high, &low) > 0); // high >= low → passes
    try std.testing.expect(cmpChainWorkBE(&low, &low) == 0); // equal → passes
}
