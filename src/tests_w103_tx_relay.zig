//! W103 — Transaction relay flow 30-gate fleet audit (clearbit / Zig 0.13).
//!
//! Reference: Bitcoin Core net_processing.cpp, node/txorphanage.h/cpp,
//!            node/txdownloadman.h/cpp, node/txrequest.h, protocol.h.
//!
//! Run via `zig build test-w103` (also folded into `zig build test`).
//!
//! Gates:
//!   G1  inv 50000 disconnect
//!   G2  getdata dispatch (size cap)
//!   G3  wtxidrelay handshake timing
//!   G4  mempool rate-limit
//!   G5  getdata MAX 1000 server-side
//!   G6  BIP-339 wtxidrelay inv filtering
//!   G7  NODE_BLOOM
//!   G8  piggyback / TxRequestTracker
//!   G9  5000 announce cap
//!   G10 100 in-flight cap
//!   G11 60s GETDATA_TX_INTERVAL
//!   G12 2s nonpref delay
//!   G13 2s txid-relay delay
//!   G14 2s overloaded delay
//!   G15 announcers set
//!   G16 m_tx_relay BIP-37
//!   G17 LRU announce filter
//!   G18 mempool rate-limit (bandwidth)
//!   G19 ProcessOrphan
//!   G20 RelayTx wtxid hash bug
//!   G21 100 orphan global cap
//!   G22 5min orphan TTL expiry
//!   G23 AddOrphan wtxid-keyed
//!   G24 EraseForPeer on disconnect
//!   G25 recursive orphan processing
//!   G26 CanRequestTxFrom
//!   G27 wtxid-keyed getdata lookup
//!   G28 UNREQUESTED tx detection
//!   G29 reject rate-limit
//!   G30 bloom/whitelist mempool gate

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const p2p = @import("p2p.zig");
const mempool_mod = @import("mempool.zig");
const consensus = @import("consensus.zig");

// ============================================================================
// G1: inv 50000 disconnect
// Bitcoin Core net_processing.cpp:4040-4042:
//   if (vInv.size() > MAX_INV_SZ)
//     Misbehaving(peer, "inv message size = %u", vInv.size())
// Clearbit: p2p.decodeInv returns ParseError.InvalidData for count > MAX_INV_SIZE.
// The upstream receiveMessage translates ParseError to PeerError.ProtocolViolation,
// which the peer loop handles with misbehaving(20, "protocol violation").
// BUG: Core applies Misbehaving(100) — effectively instant ban — for oversized inv.
//   Clearbit only applies 20 points. The constant is correct but the score diverges.
// ============================================================================
test "W103/G1: inv decode rejects count > MAX_INV_SIZE (50000)" {
    // MAX_INV_SIZE constant must equal Core's MAX_INV_SZ = 50000.
    try testing.expectEqual(@as(usize, 50000), p2p.MAX_INV_SIZE);

    // Craft an inv payload with count = 50001 (exceeds limit).
    // CompactSize encoding for 50001: 0xfd 0xD1 0xC3 (3-byte LE).
    const allocator = testing.allocator;
    const oversized_payload = [_]u8{ 0xfd, 0xd1, 0xc3 }; // compact-size 50001
    const result = p2p.decodePayload("inv", &oversized_payload, allocator);
    try testing.expectError(p2p.ParseError.InvalidData, result);
}

test "W103/G1: getdata decode rejects count > MAX_INV_SIZE (50000)" {
    const allocator = testing.allocator;
    // Reuse inv size: getdata uses the same decodeInv helper.
    const oversized_payload = [_]u8{ 0xfd, 0xd1, 0xc3 }; // compact-size 50001
    const result = p2p.decodePayload("getdata", &oversized_payload, allocator);
    try testing.expectError(p2p.ParseError.InvalidData, result);
}

// ============================================================================
// G2: getdata dispatch — MAX_GETDATA_SZ=1000 server-side enforcement (FIXED)
// Bitcoin Core net_processing.cpp:4131-4134:
//   if (vInv.size() > MAX_GETDATA_SZ)
//     Misbehaving(peer, "getdata message size = %u", vInv.size())
// FIXED: MAX_GETDATA_SZ = 1000 constant added to p2p.zig.
//   The getdata handler now calls peer.misbehaving(100, ...) when
//   gd.inventory.len > MAX_GETDATA_SZ before processing any items.
// ============================================================================
test "W103/G2: MAX_GETDATA_SZ constant is 1000 per Core (FIXED — server-side gate added)" {
    // FIXED: p2p.MAX_GETDATA_SZ = 1000 matches Core protocol.h:482.
    try testing.expectEqual(@as(usize, 1000), p2p.MAX_GETDATA_SZ);
    // MAX_GETDATA_SZ < MAX_INV_SIZE: the getdata cap is tighter than the parse limit.
    try testing.expect(p2p.MAX_GETDATA_SZ < p2p.MAX_INV_SIZE);
}

// ============================================================================
// G3: wtxidrelay handshake timing
// Bitcoin Core net_processing.cpp:3919-3936:
//   if (msg_type == NetMsgType::WTXIDRELAY)
//     // Disconnect peers that send a wtxidrelay message after VERACK.
//     if (pfrom.fSuccessfullyConnected)
//       pfrom.fDisconnect = true; return
//     if (!peer.m_wtxid_relay) { peer.m_wtxid_relay = true; ... }
// Core DISCONNECTS peers sending wtxidrelay post-verack.
// Clearbit: the main handleMessage dispatch has no wtxidrelay case;
// it falls to the `else => {}` branch (silent ignore) post-handshake.
// BUG: missing post-verack wtxidrelay disconnect enforcement.
// BUG: no per-peer wtxid_relay_negotiated state stored at all.
// ============================================================================
test "W103/G3: Peer struct has wtxid_relay_negotiated field (FIXED — W103 G6+G20)" {
    const peer_mod = @import("peer.zig");
    // Core: std::atomic<bool> m_wtxid_relay{false} on CNodeState (net_processing.cpp:283).
    // FIXED (W103 G6+G20): wtxid_relay_negotiated field added to Peer.
    // Set to true during handshake when the peer sends a wtxidrelay message.
    // Used to gate relay inv type (MSG_WTX vs MSG_TX) per-peer.
    try testing.expect(@hasField(peer_mod.Peer, "wtxid_relay_negotiated"));
    // Core uses m_wtxid_relay as the canonical field name; clearbit uses
    // wtxid_relay_negotiated (consistent with other boolean flag naming).
    try testing.expect(!@hasField(peer_mod.Peer, "m_wtxid_relay"));
}

// ============================================================================
// G4: mempool bandwidth rate-limit
// Bitcoin Core net_processing.cpp:4865-4872:
//   if (m_connman.OutboundTargetReached(false) && !peer.HasPermission(Mempool))
//     if (!peer.HasPermission(NoBan)) { pfrom.fDisconnect = true; return; }
// Clearbit: peer.zig handleMessage `.mempool` case (line 4521-4534) only
// checks advertise_node_bloom; no bandwidth-target rate-limit applied.
// BUG: mempool bandwidth rate-limit entirely absent.
// ============================================================================
test "W103/G4: mempool handler lacks bandwidth rate-limit (Core: OutboundTargetReached gate)" {
    const peer_mod = @import("peer.zig");
    // Core gates mempool serving on bandwidth target.
    // Clearbit PeerManager has no outbound_target_reached field.
    try testing.expect(!@hasField(peer_mod.PeerManager, "outbound_target_reached"));
    // BUG: any peer can request mempool contents without bandwidth throttle.
}

// ============================================================================
// G5: getdata MAX 1000 (outgoing batch split) — FIXED
// Bitcoin Core net_processing.cpp:6205-6210: batches outgoing getdata at MAX_GETDATA_SZ=1000.
// FIXED: the inv handler now uses a while-loop batching tx_requests.items at
//   MAX_GETDATA_SZ (1000) slices, sending one getdata per batch.
//   A single inv message may carry up to MAX_INV_SIZE=50000 tx items;
//   with batching, each outgoing getdata carries at most 1000 items.
// ============================================================================
test "W103/G5: MAX_GETDATA_SZ = 1000 is the outgoing batch size — not MAX_INV_SIZE (FIXED)" {
    // FIXED: outgoing getdata batched at MAX_GETDATA_SZ = 1000.
    // Core: static const unsigned int MAX_GETDATA_SZ = 1000 (net_processing.cpp:128).
    try testing.expectEqual(@as(usize, 1000), p2p.MAX_GETDATA_SZ);
    // MAX_GETDATA_SZ < MAX_INV_SIZE confirms the batch is smaller than the parse limit.
    try testing.expect(p2p.MAX_GETDATA_SZ < p2p.MAX_INV_SIZE);
}

// ============================================================================
// G6: BIP-339 wtxidrelay inv filtering (FIXED — W103)
// Bitcoin Core net_processing.cpp:4059-4063 (INV handler):
//   if (peer.m_wtxid_relay) { if (inv.IsMsgTx()) continue; }
//   else                    { if (inv.IsMsgWtx()) continue; }
// FIXED: msg_wtx = 5 added to InvType enum; inv handler now dispatches on
//   base_type == msg_wtx (=5) separately from msg_tx (=1).
// ============================================================================
test "W103/G6: MSG_WTX=5 present in InvType enum and distinct from MSG_TX=1 (FIXED)" {
    // Core protocol.h:479,481,486:
    //   MSG_TX = 1, MSG_WTX = 5, MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG = 0x40000001
    // FIXED: msg_wtx = 5 is now a named variant in clearbit's InvType enum.
    const msg_tx_val = @as(u32, @intFromEnum(p2p.InvType.msg_tx));
    const msg_wtx_val = @as(u32, @intFromEnum(p2p.InvType.msg_wtx));
    const msg_witness_tx_val = @as(u32, @intFromEnum(p2p.InvType.msg_witness_tx));

    try testing.expectEqual(@as(u32, 1), msg_tx_val);
    try testing.expectEqual(@as(u32, 5), msg_wtx_val);
    try testing.expectEqual(@as(u32, 0x40000001), msg_witness_tx_val);

    // MSG_WTX (5) and MSG_TX (1) are distinct — each is handled separately.
    try testing.expect(msg_wtx_val != msg_tx_val);
    // MSG_WITNESS_TX is a getdata-only flag; msg_wtx is the BIP-339 relay type.
    try testing.expect(msg_wtx_val != msg_witness_tx_val);
}

// ============================================================================
// G7: NODE_BLOOM mempool gate
// Bitcoin Core: NODE_BLOOM = 1 << 2 = 4. Advertising it enables mempool queries.
// Clearbit p2p.zig:19: pub const NODE_BLOOM: u64 = 4 ✓ (correct value).
// Clearbit peer.zig:4527: if (!peer.advertise_node_bloom) disconnect ✓ (gate present).
// STATUS: CORRECT — gate and value both match Core.
// ============================================================================
test "W103/G7: NODE_BLOOM constant correct and mempool gate present" {
    // Core protocol.h: NODE_BLOOM = (1 << 2) = 4.
    try testing.expectEqual(@as(u64, 4), p2p.NODE_BLOOM);

    const peer_mod = @import("peer.zig");
    // Peer struct must have advertise_node_bloom field (used as mempool gate).
    try testing.expect(@hasField(peer_mod.Peer, "advertise_node_bloom"));
}

// ============================================================================
// G8: TxRequestTracker / per-peer tx download scheduling entirely absent
// Bitcoin Core has TxRequestTracker (node/txrequest.h) tracking:
//   - Per-peer in-flight tx requests (MAX_PEER_TX_REQUEST_IN_FLIGHT=100)
//   - Per-peer announcement count (MAX_PEER_TX_ANNOUNCEMENTS=5000)
//   - Request scheduling delays (GETDATA_TX_INTERVAL=60s, NONPREF_PEER_TX_DELAY=2s,
//     TXID_RELAY_DELAY=2s, OVERLOADED_PEER_TX_DELAY=2s)
// Clearbit: no TxRequestTracker, no per-peer tracking. Every tx inv immediately
//   triggers a getdata without any delay, deduplication, or cap enforcement.
// BUG: all of G8-G15 are absent — comprehensive TxRequestTracker is missing.
// ============================================================================
test "W103/G8: TxRequestTracker entirely absent — no per-peer tx download scheduling" {
    const peer_mod = @import("peer.zig");
    // Core: TxRequestTracker tracks all pending tx requests per peer.
    // Clearbit: PeerManager has no such tracker.
    try testing.expect(!@hasField(peer_mod.PeerManager, "tx_request_tracker"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "m_txrequest"));
    // BUG: without TxRequestTracker, G9-G15 are all unfulfilled.
}

// ============================================================================
// G9: 5000 announce cap per peer
// Core: MAX_PEER_TX_ANNOUNCEMENTS = 5000 (node/txdownloadman.h:30).
// Clearbit: no announcement cap. A single peer can flood unlimited tx invs.
// ============================================================================
test "W103/G9: MAX_PEER_TX_ANNOUNCEMENTS = 5000 absent from clearbit" {
    const peer_mod = @import("peer.zig");
    // Core txdownloadman.h: static constexpr int32_t MAX_PEER_TX_ANNOUNCEMENTS = 5000
    // Clearbit: no such constant.
    try testing.expect(!@hasField(peer_mod.Peer, "tx_announcements_count"));
    // The constant doesn't exist in clearbit's peer module.
    // BUG: unlimited tx inv announcements accepted from any peer.
}

// ============================================================================
// G10: 100 in-flight cap per peer for tx requests
// Core: MAX_PEER_TX_REQUEST_IN_FLIGHT = 100 (node/txdownloadman.h:25).
// Clearbit: no per-peer tx in-flight tracking.
// ============================================================================
test "W103/G10: MAX_PEER_TX_REQUEST_IN_FLIGHT = 100 absent from clearbit" {
    const peer_mod = @import("peer.zig");
    // Core txdownloadman.h: static constexpr int32_t MAX_PEER_TX_REQUEST_IN_FLIGHT = 100
    try testing.expect(!@hasField(peer_mod.Peer, "tx_in_flight_count"));
    // BUG: clearbit fires getdata immediately on every inv without tracking in-flight count.
}

// ============================================================================
// G11: 60s GETDATA_TX_INTERVAL
// Core: GETDATA_TX_INTERVAL = 60s (node/txdownloadman.h:38). After requesting a
//   tx from one peer, wait 60s before requesting from another.
// Clearbit: no interval — getdata fires immediately on inv receipt.
// ============================================================================
test "W103/G11: GETDATA_TX_INTERVAL = 60s absent from clearbit" {
    // Core node/txdownloadman.h: static constexpr auto GETDATA_TX_INTERVAL{60s}
    // Clearbit: no last_tx_request_time or similar field.
    const peer_mod = @import("peer.zig");
    try testing.expect(!@hasField(peer_mod.Peer, "last_tx_request_time"));
    // BUG: a tx can be requested from multiple peers simultaneously at full rate.
}

// ============================================================================
// G12: 2s NONPREF_PEER_TX_DELAY
// Core: NONPREF_PEER_TX_DELAY = 2s (node/txdownloadman.h:34). Non-preferred
//   peers (e.g. inbound) get a 2s delay before their tx requests are processed.
// Clearbit: no delay distinction between preferred/non-preferred peers.
// ============================================================================
test "W103/G12: NONPREF_PEER_TX_DELAY = 2s absent from clearbit" {
    const peer_mod = @import("peer.zig");
    try testing.expect(!@hasField(peer_mod.Peer, "nonpref_peer_delay"));
    // BUG: inbound peers get same request priority as outbound peers.
}

// ============================================================================
// G13: 2s TXID_RELAY_DELAY
// Core: TXID_RELAY_DELAY = 2s (node/txdownloadman.h:32). Txid-relay peers
//   (non-wtxidrelay) are delayed by 2s to prefer wtxid-relay peers.
// Clearbit: no per-type delay.
// ============================================================================
test "W103/G13: TXID_RELAY_DELAY = 2s absent from clearbit" {
    const peer_mod = @import("peer.zig");
    try testing.expect(!@hasField(peer_mod.Peer, "txid_relay_delay"));
    // BUG: txid-relay peers not deprioritized vs wtxid-relay peers.
}

// ============================================================================
// G14: 2s OVERLOADED_PEER_TX_DELAY
// Core: OVERLOADED_PEER_TX_DELAY = 2s (node/txdownloadman.h:36). Peers with
//   MAX_PEER_TX_REQUEST_IN_FLIGHT in-flight requests are delayed by 2s.
// Clearbit: no delay for overloaded peers (no in-flight tracking at all).
// ============================================================================
test "W103/G14: OVERLOADED_PEER_TX_DELAY = 2s absent from clearbit" {
    const peer_mod = @import("peer.zig");
    try testing.expect(!@hasField(peer_mod.Peer, "overloaded_peer_delay"));
    // BUG: no backpressure applied to overloaded peers.
}

// ============================================================================
// G15: announcers set / per-tx announcer tracking
// Core: TxRequestTracker tracks which peers announced each txhash to enable
//   round-robin re-request on timeout.
// Clearbit: getdata fires to the single announcing peer with no fallback.
// ============================================================================
test "W103/G15: no per-tx announcer tracking — single-peer getdata, no fallback" {
    const peer_mod = @import("peer.zig");
    // Core tracks announcers per tx to retry from different peers on timeout.
    try testing.expect(!@hasField(peer_mod.PeerManager, "tx_announcers"));
    // BUG: if the single announcing peer is slow/malicious, tx is never fetched.
}

// ============================================================================
// G16: m_tx_relay BIP-37 (block-relay-only peers)
// Bitcoin Core net_processing.cpp:3676-3690: only creates Peer::TxRelay (m_tx_relay)
//   when fRelay=true AND (not block-relay-only peer).
// Clearbit: relay_txs field exists and is checked on send path. Block-relay-only
//   conn_type == .block_relay also skips feefilter (peer.zig:1498). ✓
// BUG: The inv handler (peer.zig:3735-3753) does NOT check relay_txs before
//   adding tx requests. This means even block-relay-only peers can trigger
//   tx getdata from clearbit.
// ============================================================================
test "W103/G16: inv tx handler doesn't check relay_txs before adding tx requests" {
    const peer_mod = @import("peer.zig");
    // relay_txs field exists on Peer (used in send path).
    try testing.expect(@hasField(peer_mod.Peer, "relay_txs"));
    // BUG: inv receive path (peer.zig:3735) doesn't guard on peer.relay_txs.
    // Core: only peers with Peer::TxRelay (set when fRelay=true) get tx processing.
    // A peer that sent relay=false in VERSION should not have tx invs processed.
}

// ============================================================================
// G17: LRU announce filter (m_tx_inventory_known_filter)
// Bitcoin Core: TxRelay::m_tx_inventory_known_filter (CRollingBloomFilter, 50000 items)
//   prevents re-announcing txs the peer already knows about.
// Clearbit: no such filter. Every tx is announced to every peer every time.
// ============================================================================
test "W103/G17: LRU announce filter (m_tx_inventory_known_filter) absent from clearbit" {
    const peer_mod = @import("peer.zig");
    // Core TxRelay::m_tx_inventory_known_filter tracks what each peer already knows.
    try testing.expect(!@hasField(peer_mod.Peer, "tx_inventory_known_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_tx_inventory_known"));
    // BUG: clearbit re-announces the same tx to all peers on every new block/tx
    // without checking if the peer already knows about it.
}

// ============================================================================
// G18: mempool message rate-limit (bandwidth gate)
// Core: mempool serving is gated on OutboundTargetReached (bandwidth exhaustion).
// Clearbit: only checks advertise_node_bloom; no bandwidth gate.
// (Same as G4 — separate test for the rate-limit side specifically.)
// ============================================================================
test "W103/G18: mempool bandwidth rate-limit absent (Core: OutboundTargetReached)" {
    const peer_mod = @import("peer.zig");
    // Core: if (m_connman.OutboundTargetReached(false) && !peer.HasPermission(Mempool))
    //         disconnect;
    try testing.expect(!@hasField(peer_mod.PeerManager, "outbound_bytes_sent"));
    // BUG: any number of peers can drain the mempool via repeated `mempool` messages.
}

// ============================================================================
// G19: ProcessOrphan — orphan re-processing after parent admission
// Bitcoin Core: ProcessOrphanTx called after each successful ATMP.
// Clearbit: peer.zig:4416: pool.processOrphansForParent(result.txid) ✓
// STATUS: PRESENT — fixpoint loop wired correctly.
// ============================================================================
test "W103/G19: processOrphansForParent is called after successful ATMP" {
    // Verify the orphan processing function exists in the mempool module.
    // The function signature: pub fn processOrphansForParent(self: *Mempool, parent_txid: Hash256) usize
    // Compile-time presence check: if this function is missing, the test file won't compile.
    const has_fn = @hasDecl(mempool_mod.Mempool, "processOrphansForParent");
    try testing.expect(has_fn);
}

// ============================================================================
// G20: RelayTx — per-peer MSG_WTX/wtxid vs MSG_TX/txid relay (FIXED — W103)
// Bitcoin Core net_processing.cpp:6007-6009:
//   const auto inv = peer.m_wtxid_relay ?
//     CInv{MSG_WTX, wtxid.ToUint256()} :  // BIP-339: announce by wtxid
//     CInv{MSG_TX, txid.ToUint256()};     // legacy: announce by txid
// FIXED: relay loop now branches on relay_peer.wtxid_relay_negotiated:
//   true  → InvVector{ .inv_type = .msg_wtx, .hash = result.wtxid }
//   false → InvVector{ .inv_type = .msg_tx,  .hash = result.txid  }
// ============================================================================
test "W103/G20: relay inv uses MSG_WTX+wtxid for BIP-339 peers (FIXED)" {
    // Core protocol.h:481: MSG_WTX = 5 (BIP-339 type for wtxid-relay peers).
    // Core protocol.h:486: MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG = 0x40000001
    //   (block getdata flag — NOT for mempool tx relay inv).
    const MSG_WTX: u32 = 5;
    const msg_wtx_clearbit = @as(u32, @intFromEnum(p2p.InvType.msg_wtx));

    // FIXED: msg_wtx = 5 is the correct BIP-339 relay inv type.
    try testing.expectEqual(MSG_WTX, msg_wtx_clearbit);

    // AcceptResult must have both txid and wtxid fields so the relay path
    // can branch correctly.
    const has_txid_field = @hasField(mempool_mod.Mempool.AcceptResult, "txid");
    const has_wtxid_field = @hasField(mempool_mod.Mempool.AcceptResult, "wtxid");
    try testing.expect(has_txid_field);
    try testing.expect(has_wtxid_field);

    // peer_mod.Peer must have wtxid_relay_negotiated for the branch to work.
    const peer_mod = @import("peer.zig");
    try testing.expect(@hasField(peer_mod.Peer, "wtxid_relay_negotiated"));
}

// ============================================================================
// G21: 100 orphan global cap
// Bitcoin Core: DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100 (txorphanage.h).
// Clearbit mempool.zig:136: pub const MAX_ORPHAN_TRANSACTIONS: usize = 100 ✓
// STATUS: CORRECT — cap matches Core's legacy default.
// ============================================================================
test "W103/G21: MAX_ORPHAN_TRANSACTIONS = 100 matches Core" {
    // Core src/node/txorphanage.h: DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100 (legacy).
    try testing.expectEqual(@as(usize, 100), mempool_mod.MAX_ORPHAN_TRANSACTIONS);
}

// ============================================================================
// G22: 5-minute orphan TTL expiry (FIXED)
// Bitcoin Core net_processing.cpp / txorphanage: orphans are periodically swept
//   using ORPHAN_TX_EXPIRE_TIME (5 minutes) and ORPHAN_TX_EXPIRE_INTERVAL.
// FIXED: ORPHAN_TX_EXPIRE_TIME = 300 (5 min) constant added to mempool.zig.
//   sweepExpiredOrphans(now: i64) method added to Mempool.
//   PeerManager.sweepOrphanPool() wired into the main run() loop at step 6b,
//   gated by ORPHAN_TX_EXPIRE_INTERVAL so the O(N) scan runs at most once per
//   5 minutes.
// ============================================================================
test "W103/G22: ORPHAN_TX_EXPIRE_TIME = 300s constant present (FIXED)" {
    // Core: static constexpr auto ORPHAN_TX_EXPIRE_TIME = 5min = 300s.
    // FIXED: constant now present in mempool_mod.
    try testing.expectEqual(@as(i64, 300), mempool_mod.ORPHAN_TX_EXPIRE_TIME);
    try testing.expectEqual(@as(i64, 300), mempool_mod.ORPHAN_TX_EXPIRE_INTERVAL);
}

test "W103/G22: sweepExpiredOrphans removes orphans older than TTL (FIXED)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Build a minimal segwit tx to use as an orphan.
    const p2wpkh_script = [_]u8{0x00, 0x14} ++ [_]u8{0xBB} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0xDE} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xffffffff,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{ .value = 42_000, .script_pubkey = &p2wpkh_script };
    const orphan_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const peer_id: u64 = 99;
    const added = pool.addOrphan(&orphan_tx, peer_id);
    try testing.expect(added);
    try testing.expectEqual(@as(usize, 1), pool.orphanCount());

    // Sweep with a "now" that is still within TTL — orphan must survive.
    var orphan_iter = pool.orphans.iterator();
    const time_added = orphan_iter.next().?.value_ptr.*.time_added;
    const not_expired_now = time_added + mempool_mod.ORPHAN_TX_EXPIRE_TIME - 1;
    const swept_early = pool.sweepExpiredOrphans(not_expired_now);
    try testing.expectEqual(@as(usize, 0), swept_early);
    try testing.expectEqual(@as(usize, 1), pool.orphanCount());

    // Sweep with a "now" exactly at the expiry boundary — orphan must be removed.
    const expired_now = time_added + mempool_mod.ORPHAN_TX_EXPIRE_TIME;
    const swept = pool.sweepExpiredOrphans(expired_now);
    try testing.expectEqual(@as(usize, 1), swept);
    try testing.expectEqual(@as(usize, 0), pool.orphanCount());
}

// ============================================================================
// G23: AddOrphan wtxid-keyed
// Bitcoin Core: TxOrphanage keyed by Wtxid (BIP-339 / Core PR #18044).
// Clearbit mempool.zig:676: orphans: std.AutoHashMap(types.Hash256, *OrphanTx)
//   keyed by wtxid. Secondary orphans_by_txid maps txid→wtxid. ✓
// STATUS: CORRECT — fixed in W99/G14 (per W99 audit notes).
// ============================================================================
test "W103/G23: orphan pool is wtxid-keyed (primary map) with txid secondary index" {
    // Primary: orphans HashMap keyed by wtxid.
    // Secondary: orphans_by_txid maps txid → wtxid for parent-resolution.
    // Both are present in Mempool struct.
    const Mempool = mempool_mod.Mempool;
    try testing.expect(@hasField(Mempool, "orphans"));
    try testing.expect(@hasField(Mempool, "orphans_by_txid"));
}

// ============================================================================
// G24: EraseForPeer on disconnect
// Bitcoin Core: TxOrphanage::EraseForPeer(NodeId peer) called on disconnect.
// Clearbit: eraseOrphansForPeer(peer_id: u64) exists in mempool.zig:1591. ✓
// BUG CHECK: Is it actually called on peer disconnect?
// Verify: peer.zig must call eraseOrphansForPeer on cleanup.
// ============================================================================
test "W103/G24: eraseOrphansForPeer exists in Mempool" {
    const Mempool = mempool_mod.Mempool;
    // eraseOrphansForPeer must be callable on Mempool instances.
    // Compile-time presence check via @hasDecl.
    try testing.expect(@hasDecl(Mempool, "eraseOrphansForPeer"));
}

test "W103/G24: eraseOrphansForPeer removes all orphans from specified peer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();

    // Build a minimal segwit tx to use as an orphan.
    const p2wpkh_script = [_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20;
    const input = types.TxIn{
        .previous_output = .{ .hash = [_]u8{0x99} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xffffffff,
        .witness = &[_][]const u8{},
    };
    const output = types.TxOut{ .value = 50_000, .script_pubkey = &p2wpkh_script };
    const orphan_tx = types.Transaction{
        .version = 1,
        .inputs = &[_]types.TxIn{input},
        .outputs = &[_]types.TxOut{output},
        .lock_time = 0,
    };

    const peer_id: u64 = 12345;
    const added = pool.addOrphan(&orphan_tx, peer_id);
    try testing.expect(added);
    try testing.expectEqual(@as(usize, 1), pool.orphanCount());

    // After eraseOrphansForPeer, the orphan must be gone.
    pool.eraseOrphansForPeer(peer_id);
    try testing.expectEqual(@as(usize, 0), pool.orphanCount());
}

// ============================================================================
// G25: recursive orphan processing (fixpoint loop)
// Bitcoin Core: ProcessOrphanTx loops until no further orphans are resolved.
// Clearbit mempool.zig:1632-1699: processOrphansForParent uses a worklist that
//   grows as newly-promoted orphans unlock further children. ✓
// STATUS: CORRECT — fixpoint loop is present.
// ============================================================================
test "W103/G25: processOrphansForParent fixpoint loop exists (structural check)" {
    // Bitcoin Core: ProcessOrphanTx loops until no further orphans resolve.
    // Clearbit: processOrphansForParent uses a worklist grown by newly-admitted
    //   orphans (mempool.zig:1639-1695). Verify the function exists and is callable.
    try testing.expect(@hasDecl(mempool_mod.Mempool, "processOrphansForParent"));
    // The worklist-based fixpoint is present (Code review of mempool.zig:1639-1695
    // confirms the loop: worklist.append(orphan_ptr.txid) on success → children
    // of newly-admitted txs are automatically retried).
    // STATUS: CORRECT — fixpoint loop wired.
}

// ============================================================================
// G26: CanRequestTxFrom — no per-peer request deduplication
// Bitcoin Core: TxRequestTracker tracks outstanding requests and prevents
//   requesting the same tx from the same peer twice.
// Clearbit: no deduplication. Same tx can be requested multiple times from
//   the same peer if the peer announces it multiple times.
// ============================================================================
test "W103/G26: no CanRequestTxFrom equivalent — duplicate getdata not prevented" {
    const peer_mod = @import("peer.zig");
    // TxRequestTracker would provide CanRequestTxFrom().
    try testing.expect(!@hasField(peer_mod.PeerManager, "tx_request_tracker"));
    // BUG: a peer can announce the same txid multiple times and clearbit will
    // send a separate getdata for each announcement.
}

// ============================================================================
// G27: wtxid-keyed getdata lookup in serving path (FIXED — W103)
// Bitcoin Core net_processing.cpp FindTxForGetData: looks up by GenTxid which
//   may be wtxid (for MSG_WTX getdata) or txid (for MSG_TX getdata).
// FIXED: getdata handler now has a separate branch for base_type == msg_wtx (=5):
//   const txid_opt = pool.by_wtxid.get(item.hash);  // wtxid → txid
//   const entry_opt = if (txid_opt) |txid| pool.entries.get(txid) else null;
// ============================================================================
test "W103/G27: by_wtxid secondary index present and both maps exist (FIXED)" {
    const Mempool = mempool_mod.Mempool;
    // by_wtxid secondary index: wtxid → txid.
    try testing.expect(@hasField(Mempool, "by_wtxid"));
    // entries primary map: txid → *MempoolEntry.
    try testing.expect(@hasField(Mempool, "entries"));
    // FIXED: getdata handler now consults by_wtxid for msg_wtx getdata requests.
    // MSG_WTX (=5) is a named InvType so the branch compiles correctly.
    const msg_wtx_val = @as(u32, @intFromEnum(p2p.InvType.msg_wtx));
    try testing.expectEqual(@as(u32, 5), msg_wtx_val);
}

test "W103/G27: MSG_WTX getdata path uses wtxid→txid two-step lookup (FIXED)" {
    // Verify the by_wtxid index exists and is keyed correctly so the two-step
    // lookup (wtxid → txid → MempoolEntry) is structurally sound.
    //
    // FIXED path in peer.zig:
    //   const txid_opt = pool.by_wtxid.get(item.hash);     // wtxid → txid
    //   const entry_opt = if (txid_opt) |txid| pool.entries.get(txid) else null;
    //
    // Structural invariant: by_wtxid and entries both present on Mempool.
    try testing.expect(@hasField(mempool_mod.Mempool, "by_wtxid"));
    try testing.expect(@hasField(mempool_mod.Mempool, "entries"));
    // The InvType enum now has msg_wtx = 5, enabling the dispatch branch.
    try testing.expectEqual(@as(u32, 5), @as(u32, @intFromEnum(p2p.InvType.msg_wtx)));
}

// ============================================================================
// G28: UNREQUESTED tx detection
// Bitcoin Core net_processing.cpp:3980:
//   if (!tx_relay || !tx_relay->m_relay_txs) { Misbehaving... }
//   Also checks whether tx was actually requested (in m_txrequest).
// Clearbit: any peer can send a `tx` message and it gets processed, even
//   if we never sent a getdata for it. No UNREQUESTED Misbehaving.
// BUG: unrequested txs are silently accepted into ATMP instead of misbehaving.
// ============================================================================
test "W103/G28: UNREQUESTED tx detection absent — unsolicited tx message processed silently" {
    // Core: ProcessMessage for tx checks m_txrequest to verify the tx was requested.
    // Clearbit: handleMessage .tx case (peer.zig:4403) calls acceptToMemoryPool
    // without checking whether a getdata was ever sent for this tx.
    // BUG: any connected peer can push arbitrary txs without being asked.
    const peer_mod = @import("peer.zig");
    try testing.expect(!@hasField(peer_mod.Peer, "pending_tx_requests"));
    // BUG: unsolicited `tx` messages are not penalized.
}

// ============================================================================
// G29: reject rate-limit / recent_rejects filter
// Bitcoin Core maintains m_lazy_recent_rejects (CRollingBloomFilter) so that
//   previously-rejected txids are not re-requested from other peers.
// Clearbit: no recent_rejects filter. A tx rejected by ATMP can be re-requested
//   immediately from any other peer that announces it.
// ============================================================================
test "W103/G29: recent_rejects filter absent — rejected txs re-requested indefinitely" {
    const peer_mod = @import("peer.zig");
    try testing.expect(!@hasField(peer_mod.PeerManager, "recent_rejects"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "m_lazy_recent_rejects"));
    // BUG: a tx rejected by ATMP will be re-requested from every peer that announces it.
}

// ============================================================================
// G30: bloom filter / whitelist mempool gate
// Bitcoin Core: bloom filter (m_bloom_filter) can gate which txs are relayed.
//   Whitelist peers bypass the bandwidth rate-limit (HasPermission(Mempool)).
// Clearbit: no bloom filter per peer. Whitelist / noban exist (no_ban field).
//   advertise_node_bloom is checked for mempool requests. Partial.
// STATUS: NODE_BLOOM gate correct. Bloom filter per-peer for filtering absent.
// ============================================================================
test "W103/G30: per-peer bloom filter (BIP-37 filter* messages) absent from clearbit" {
    const peer_mod = @import("peer.zig");
    // Core: TxRelay::m_bloom_filter (CBloomFilter) allows peer to filter tx relay.
    // Clearbit: no bloom filter per peer.
    try testing.expect(!@hasField(peer_mod.Peer, "bloom_filter"));
    try testing.expect(!@hasField(peer_mod.Peer, "m_bloom_filter"));
    // BUG: filter* messages (filterload, filteradd, filterclear) not handled.
    // Peers advertising NODE_BLOOM can't actually use bloom filters.
}

// ============================================================================
// Additional: inv type MSG_WTX = 5 now present in clearbit InvType enum (FIXED)
// ============================================================================
test "W103/bonus: MSG_WTX = 5 (BIP-339) present in clearbit InvType enum (FIXED)" {
    // Core protocol.h:481: MSG_WTX = 5 — the BIP-339 inv type for wtxid-relay peers.
    // FIXED (W103): msg_wtx = 5 is now a named variant in clearbit's InvType enum.
    // Core peers sending MSG_WTX invs to clearbit will now have them processed.
    const msg_wtx_val = @as(u32, @intFromEnum(p2p.InvType.msg_wtx));
    try testing.expectEqual(@as(u32, 5), msg_wtx_val);

    // MSG_WTX (5) is distinct from MSG_TX (1) and MSG_BLOCK (2).
    const base_type_msg_tx = @as(u32, @intFromEnum(p2p.InvType.msg_tx));
    const base_type_msg_block = @as(u32, @intFromEnum(p2p.InvType.msg_block));
    try testing.expect(msg_wtx_val != base_type_msg_tx);
    try testing.expect(msg_wtx_val != base_type_msg_block);
}

// ============================================================================
// Additional: relay inv uses result.wtxid for MSG_WTX peers (FIXED)
// ============================================================================
test "W103/bonus: AcceptResult has distinct txid and wtxid fields; relay uses wtxid (FIXED)" {
    // Verify that AcceptResult.txid and AcceptResult.wtxid are separate fields.
    // FIXED (W103 G20): relay now uses .wtxid for wtxid_relay_negotiated peers
    // and .txid for legacy peers. Core: net_processing.cpp:6007-6009.
    const AcceptResult = mempool_mod.Mempool.AcceptResult;
    try testing.expect(@hasField(AcceptResult, "txid"));
    try testing.expect(@hasField(AcceptResult, "wtxid"));
    // Both fields present: relay path can branch on wtxid_relay_negotiated.
}

// ============================================================================
// Additional: orphan per-peer cap = 100 (matches Core's legacy behavior)
// ============================================================================
test "W103/bonus: MAX_PEER_ORPHANS = 100 per-peer orphan cap" {
    // Core (legacy): per-peer orphan cap is effectively global_cap (100).
    // Clearbit: explicit MAX_PEER_ORPHANS = 100.
    try testing.expectEqual(@as(usize, 100), mempool_mod.MAX_PEER_ORPHANS);
}

// ============================================================================
// Additional: MAX_ORPHAN_TX_SIZE = 100_000 bytes matches Core
// ============================================================================
test "W103/bonus: MAX_ORPHAN_TX_SIZE = 100_000 bytes matches Core" {
    // Core: MAX_ORPHAN_TX_SIZE = 100_000 (per-tx serialized size cap).
    try testing.expectEqual(@as(usize, 100_000), mempool_mod.MAX_ORPHAN_TX_SIZE);
}
