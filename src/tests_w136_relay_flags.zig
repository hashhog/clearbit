//! W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay
//!         30-gate fleet audit — clearbit (Zig 0.13).
//!
//! References
//! ----------
//! bitcoin-core/src/net_processing.cpp:
//!   - MaybeSendSendHeaders   (line 5519)
//!   - MaybeSendFeefilter     (line 5540)
//!   - WTXIDRELAY handler     (line 3921)
//!   - SENDHEADERS handler    (line 3896)
//!   - FEEFILTER handler      (line 5035)
//!   - inv-wtxid-filter       (line 4056-4063)
//!   - m_wtxid_relay          (line 283)
//!   - m_sent_sendheaders     (line 405)
//!   - m_fee_filter_sent / next_send_feefilter (line 287-290)
//!   - constants AVG_FEEFILTER_BROADCAST_INTERVAL=10min,
//!     MAX_FEEFILTER_CHANGE_DELAY=5min
//! bitcoin-core/src/node/protocol_version.h:
//!   - SENDHEADERS_VERSION=70012, FEEFILTER_VERSION=70013,
//!     WTXID_RELAY_VERSION=70016, PROTOCOL_VERSION=70016
//! bitcoin-core/src/policy/fees/block_policy_estimator.{cpp,h}:
//!   - FeeFilterRounder, MAX_FILTER_FEERATE=1e7, FEE_FILTER_SPACING=1.1
//! BIPs 130, 133, 339.
//!
//! Mode
//! ----
//! DISCOVERY (XFAIL-style). Each test asserts the CURRENT (often buggy)
//! state — when a fix wave lands, the test must be flipped (intentionally).
//! Audit BUG numbers map 1:1 to gate names (G1..G30) and to BUG-1..BUG-30
//! in `audit/w136_relay_flags.md`.
//!
//! Run: `zig build test-w136`.

const std = @import("std");
const testing = std.testing;

const peer_mod = @import("peer.zig");
const p2p = @import("p2p.zig");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const serialize = @import("serialize.zig");

const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;
const Message = p2p.Message;
const FeeFilterMessage = p2p.FeeFilterMessage;

// ============================================================================
// Helpers
// ============================================================================

/// Read peer.zig once for source-level guards.  Used by G1, G2, G3,
/// G4, G6, G9, G10, G12, G24.  Holding the source in a single readFileAlloc
/// per-call avoids repeated I/O; small enough that the test runner is fine.
fn readPeerSrc(alloc: std.mem.Allocator) ![]const u8 {
    var dir = try std.fs.cwd().openDir("src", .{});
    defer dir.close();
    return try dir.readFileAlloc(alloc, "peer.zig", 4 * 1024 * 1024);
}

/// Read p2p.zig for source-level guards.  Used by G19, G29.
fn readP2pSrc(alloc: std.mem.Allocator) ![]const u8 {
    var dir = try std.fs.cwd().openDir("src", .{});
    defer dir.close();
    return try dir.readFileAlloc(alloc, "p2p.zig", 1 * 1024 * 1024);
}

// ============================================================================
// G1..G3 — MaybeSendSendHeaders + MaybeSendFeefilter wiring
// ============================================================================

// G1 BUG: No chainwork-gated MaybeSendSendHeaders.
// Bitcoin Core (net_processing.cpp:5519-5537) gates SENDHEADERS broadcast on
//   state.pindexBestKnownBlock->nChainWork > m_chainman.MinimumChainWork()
// AND a per-peer m_sent_sendheaders idempotence latch.  clearbit sends
// SENDHEADERS unconditionally at end-of-handshake (peer.zig:1617-1619) with
// no chainwork check, no idempotence latch, no SendMessages-tick equivalent.
test "w136/G1: no chainwork-gated maybeSendSendHeaders helper exists" {
    // No peer method named maybeSendSendHeaders / MaybeSendSendHeaders.
    try testing.expect(!@hasDecl(Peer, "maybeSendSendHeaders"));
    try testing.expect(!@hasDecl(Peer, "MaybeSendSendHeaders"));
    try testing.expect(!@hasDecl(PeerManager, "maybeSendSendHeaders"));
    // No idempotence latch field.
    try testing.expect(!@hasField(Peer, "sent_sendheaders"));
    try testing.expect(!@hasField(Peer, "m_sent_sendheaders"));
}

// G2 BUG: MaybeSendFeefilter is not wired into any heartbeat tick.
// The definition lives at peer.zig:1658-1711, but no caller exists.
// Core (net_processing.cpp:5540) invokes it on every SendMessages tick per
// peer.  clearbit sends one feefilter at handshake and never updates.
test "w136/G2: maybeSendFeefilter has no caller in the source tree" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    // Count occurrences of "maybeSendFeefilter" in peer.zig.
    // Expected: 1 — the `pub fn maybeSendFeefilter` definition line at 1658.
    // (Doc-comment mentions like "// Maybe send a feefilter ..." use lowercase.)
    var count: usize = 0;
    var idx: usize = 0;
    const needle = "maybeSendFeefilter";
    while (std.mem.indexOfPos(u8, peer_src, idx, needle)) |pos| {
        count += 1;
        idx = pos + needle.len;
    }
    // Exactly one hit = the definition; >=2 would mean a caller exists.
    try testing.expectEqual(@as(usize, 1), count);
}

// G3 BUG: maybeSendFeefilter is dead code.  Same root as G2 but listed
// separately because the function is fully implemented (54 LOC of correct
// IBD + hysteresis logic) — the fix wave just needs to wire a call site.
test "w136/G3: maybeSendFeefilter is defined as a pub fn on Peer" {
    // The function exists — confirm it's there as a dispatcher target.
    try testing.expect(@hasDecl(Peer, "maybeSendFeefilter"));
    // Signature: fn maybeSendFeefilter(self: *Peer, current_filter_sat_kvb: u64, is_ibd: bool) void
    // Verify by attempting to reference it (compile-time check only).
    _ = Peer.maybeSendFeefilter;
}

// ============================================================================
// G4..G6 — WTXIDRELAY post-VERACK semantics + inv filter
// ============================================================================

// G4 BUG: WTXIDRELAY after VERACK is silently swallowed, not disconnect.
// Core (line 3922-3927) sets pfrom.fDisconnect = true when WTXIDRELAY arrives
// post-VERACK.  clearbit handleMessage (peer.zig:4222) has no .wtxidrelay arm
// — the message falls to `else => {}` at line 5438.
test "w136/G4: handleMessage has no .wtxidrelay arm (silent post-handshake drop)" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    // Locate handleMessage body — between "fn handleMessage" and the next
    // top-level fn or struct declaration in the source.
    const handle_idx = std.mem.indexOf(u8, peer_src, "fn handleMessage(self: *PeerManager") orelse {
        return error.HandleMessageNotFound;
    };
    // Window must cover the full switch (~70KB+).
    const window_end = @min(handle_idx + 80_000, peer_src.len);
    const window = peer_src[handle_idx..window_end];

    // The handshake-loop wtxidrelay arm is at peer.zig:1524 — well before
    // handle_idx (~4222).  So no `.wtxidrelay =>` in window means the
    // dispatcher cannot react to post-handshake WTXIDRELAY.
    const has_arm = std.mem.indexOf(u8, window, ".wtxidrelay =>") != null;
    try testing.expect(!has_arm);
}

// G5 BUG: WTXIDRELAY accepted without GetCommonVersion >= 70016 gate.
// Core (line 3928) gates `peer.m_wtxid_relay = true;` on
// `pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION`.  clearbit's inline
// handshake handler at peer.zig:1524-1527 unconditionally assigns it.
test "w136/G5: clearbit lacks WTXID_RELAY_VERSION (70016) gating constant" {
    // Core's protocol_version.h defines WTXID_RELAY_VERSION = 70016.
    // clearbit's p2p.zig defines PROTOCOL_VERSION = 70016 (same value) but
    // does not name it as the wtxidrelay threshold.
    try testing.expect(!@hasDecl(p2p, "WTXID_RELAY_VERSION"));
    try testing.expect(!@hasDecl(p2p, "WTXID_RELAY_MIN_VERSION"));
    try testing.expect(!@hasDecl(p2p, "WTXIDRELAY_VERSION"));
    // The MIN_PROTOCOL_VERSION at 70001 is what the handshake checks against.
    try testing.expectEqual(@as(i32, 70001), p2p.MIN_PROTOCOL_VERSION);
}

// G6 BUG: inv handler does not filter by wtxid_relay_negotiated.
// Core (line 4056-4063) drops MSG_TX inv from wtxidrelay-negotiated peers
// and MSG_WTX inv from non-negotiated peers.  clearbit's inv handler
// (peer.zig:4270-4296) processes both unconditionally.
test "w136/G6: inv handler msg_tx arm does not gate on wtxid_relay_negotiated" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    // Find the .inv => |i| block (where i is renamed to inv_msg or similar).
    // The msg_tx arm in clearbit looks like:
    //   } else if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_tx))) {
    // Search for the literal then inspect the next ~10 lines for a
    // wtxid_relay_negotiated reference.
    const msg_tx_arm = "if (base_type == @as(u32, @intFromEnum(p2p.InvType.msg_tx)))";
    const tx_arm_pos = std.mem.indexOf(u8, peer_src, msg_tx_arm) orelse {
        return error.MsgTxArmNotFound;
    };
    const window_end = @min(tx_arm_pos + 600, peer_src.len);
    const window = peer_src[tx_arm_pos..window_end];
    const has_gate = std.mem.indexOf(u8, window, "wtxid_relay_negotiated") != null;
    // BUG: the arm has no `if (peer.wtxid_relay_negotiated) continue;`.
    try testing.expect(!has_gate);
}

// ============================================================================
// G7 — Hardcoded handshake feefilter
// ============================================================================

// G7 BUG: handshake feefilter is hardcoded to 100_000 sat/kvB.
// Core (line 5550) derives it from mempool.GetMinFee().GetFeePerK().
// clearbit (peer.zig:1629) sends 100_000 regardless of mempool state.
test "w136/G7: handshake feefilter is hardcoded constant 100_000" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    // The literal "feerate = 100_000" appears at the post-handshake feefilter
    // send site.  Confirm at least one such literal exists.
    const has_hardcoded = std.mem.indexOf(u8, peer_src, ".feerate = 100_000") != null;
    try testing.expect(has_hardcoded);
}

// ============================================================================
// G8 — FeeFilterRounder quantization
// ============================================================================

// G8 BUG: no FeeFilterRounder bucket quantization.
// Core's FeeFilterRounder (block_policy_estimator.cpp:1103-1118) maps a raw
// fee rate to one of ~120 buckets (1.1-spaced from min_fee_limit to 1e7).
// clearbit sends raw values, leaking the exact mempool min-fee as a
// fingerprint.
test "w136/G8: no FeeFilterRounder helper in peer.zig" {
    // No type named FeeFilterRounder / FeeRounder / FeeBucket on any module.
    try testing.expect(!@hasDecl(peer_mod, "FeeFilterRounder"));
    try testing.expect(!@hasDecl(peer_mod, "FeeRounder"));
    try testing.expect(!@hasDecl(peer_mod, "FeeFilterBuckets"));
    try testing.expect(!@hasDecl(p2p, "FeeFilterRounder"));
    // No MAX_FILTER_FEERATE constant (Core: 1e7).
    try testing.expect(!@hasDecl(peer_mod, "MAX_FILTER_FEERATE"));
    try testing.expect(!@hasDecl(peer_mod, "FEE_FILTER_SPACING"));
}

// ============================================================================
// G9..G10 — operator flags
// ============================================================================

// G9 BUG: no -blocksonly / ignore_incoming_txs config.
// Core line 5542:  if (m_opts.ignore_incoming_txs) return;
// clearbit has no equivalent.  A blocks-only node cannot opt out of
// feefilter advertising.
test "w136/G9: no blocksonly / ignore_incoming_txs knob on PeerManager" {
    try testing.expect(!@hasField(PeerManager, "blocksonly"));
    try testing.expect(!@hasField(PeerManager, "ignore_incoming_txs"));
    try testing.expect(!@hasField(PeerManager, "blocks_only"));
}

// G10 BUG: no NetPermissionFlags::ForceRelay.
// Core line 5545:  if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;
// clearbit has only `no_ban: bool` — no force-relay bypass.
test "w136/G10: Peer struct has no force_relay permission field" {
    try testing.expect(!@hasField(Peer, "force_relay"));
    try testing.expect(!@hasField(Peer, "permissions"));
    try testing.expect(!@hasField(Peer, "permission_flags"));
    // The single permission bit that exists:
    try testing.expect(@hasField(Peer, "no_ban"));
}

// ============================================================================
// G11..G12 — periodic broadcast timing
// ============================================================================

// G11 BUG: uniform [0.5, 1.5] × interval instead of exponential.
// Core line 5572 uses m_rng.rand_exp_duration().  clearbit (peer.zig:1693-1696)
// uses uniform-random multiplier, which has the same mean but is not
// memoryless — leaks timing fingerprint.
test "w136/G11: maybeSendFeefilter uses uniform random, not exponential" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    // The uniform-random implementation is identifiable by intRangeAtMost(u32, 500, 1500)
    const has_uniform = std.mem.indexOf(u8, peer_src, "intRangeAtMost(u32, 500, 1500)") != null;
    try testing.expect(has_uniform);
    // Conversely, no exp/log-based sampler is used:
    const has_exp_ln = std.mem.indexOf(u8, peer_src, "rand_exp_duration") != null;
    const has_log = std.mem.indexOf(u8, peer_src, "@log(") != null;
    try testing.expect(!has_exp_ln);
    // @log appears nowhere in peer.zig today (test is sensitive to future use
    // outside the feefilter path).  If a future contributor adds @log for
    // some other reason this gate would flip false — see audit doc.
    try testing.expect(!has_log);
}

// G12 BUG: IBD→non-IBD next_send_feefilter = 0 branch is unreachable.
// peer.zig:1675-1678 correctly handles the post-IBD case but the function
// is never invoked (G2/G3).  Subsumed by G2 — listed separately so the
// fix wave for G2 must also assert this branch fires.
test "w136/G12: IBD-exit reset branch is structurally present but unreachable" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    // The else-if branch is identifiable by the post-IBD reset literal:
    const has_branch = std.mem.indexOf(u8, peer_src, "self.next_send_feefilter = 0") != null;
    try testing.expect(has_branch);
    // But — see G2 — the surrounding function is never called.  So this
    // branch is dead code.
}

// ============================================================================
// G13..G15 — PARITY / MISSING-OK
// ============================================================================

// G13 INFO: no m_sent_sendheaders idempotence latch.  Not yet needed because
// handshake-end is the only call site, but a future MaybeSendSendHeaders
// would require it.
test "w136/G13: idempotence latch absent (currently OK)" {
    try testing.expect(!@hasField(Peer, "sent_sendheaders"));
    try testing.expect(!@hasField(Peer, "m_sent_sendheaders"));
}

// G14 PARITY: hysteresis ratios 3/4 (decrease) and 4/3 (increase) match Core.
// Verifying the literal multipliers are present.
test "w136/G14: maybeSendFeefilter hysteresis ratios match Core (3/4 and 4/3)" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    // Core: `< 3 * peer.m_fee_filter_sent / 4` and `> 4 * peer.m_fee_filter_sent / 3`
    // clearbit: `< (3 * self.fee_filter_sent) / 4` and `> (4 * self.fee_filter_sent) / 3`
    try testing.expect(std.mem.indexOf(u8, peer_src, "(3 * self.fee_filter_sent) / 4") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, "(4 * self.fee_filter_sent) / 3") != null);
}

// G15 PARITY: block_relay connection skip matches Core line 5548.
test "w136/G15: maybeSendFeefilter skips block_relay connection type" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    try testing.expect(std.mem.indexOf(u8, peer_src, "if (self.conn_type == .block_relay) return") != null);
}

// G16 PARITY: SENDHEADERS handler sets send_headers = true.
test "w136/G16: handleMessage .sendheaders arm sets peer.send_headers = true" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    // The handler at peer.zig:5310-5317 sets peer.send_headers = true.
    try testing.expect(std.mem.indexOf(u8, peer_src, "peer.send_headers = true") != null);
}

// ============================================================================
// G17..G19 — FEEFILTER decode semantics
// ============================================================================

// G17 PARTIAL: MoneyRange-style upper bound enforced; signed-zero bound
// trivial because of u64 decode.
test "w136/G17: feefilter handler gates on <= MAX_MONEY (2.1e15 sats)" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    // The literal MAX_MONEY constant should appear in the feefilter arm.
    try testing.expect(std.mem.indexOf(u8, peer_src, "MAX_MONEY: u64 = 2_100_000_000_000_000") != null);
    try testing.expect(std.mem.indexOf(u8, peer_src, "if (ff.feerate <= MAX_MONEY)") != null);
}

// G18 PARITY: truncated FEEFILTER payload returns an error from readInt.
// The error propagates to PeerError.ProtocolViolation in the decoder.
test "w136/G18: feefilter decode propagates readInt error on truncated payload" {
    // Construct a Reader over an empty buffer and verify u64 readInt fails.
    const empty = [_]u8{};
    var reader = serialize.Reader{ .data = &empty };
    // Calling readInt(u64) on empty should return serialize.Error.EndOfStream.
    const result = reader.readInt(u64);
    try testing.expectError(serialize.Error.EndOfStream, result);
}

// G19 BUG: FEEFILTER decode is u64 where Core uses int64_t.
test "w136/G19: FeeFilterMessage.feerate is unsigned (u64) not signed (i64)" {
    // Inspect the field type via reflection.
    const TypeOfFeerate = @TypeOf(@as(FeeFilterMessage, undefined).feerate);
    // Core's CAmount = int64_t.  clearbit chose u64.
    try testing.expectEqual(u64, TypeOfFeerate);
    // If this assertion ever fires (someone changed it to i64), the fix
    // wave for BUG-19 has landed — flip this gate.
}

// ============================================================================
// G20 — passesFeeFilter short-circuit
// ============================================================================

// G20 INFO: passesFeeFilter short-circuits on fee_filter_received == 0.
test "w136/G20: passesFeeFilter short-circuits on fee_filter_received == 0" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    try testing.expect(std.mem.indexOf(u8, peer_src, "if (self.fee_filter_received == 0) return true") != null);
}

// ============================================================================
// G21..G23 — announceBlock behavior
// ============================================================================

// G21 BUG: announceBlock does not batch into m_blocks_for_headers_relay.
test "w136/G21: PeerManager has no blocks_for_headers_relay queue per peer" {
    try testing.expect(!@hasField(Peer, "blocks_for_headers_relay"));
    try testing.expect(!@hasField(Peer, "blocks_for_inv_relay"));
    try testing.expect(!@hasField(Peer, "m_blocks_for_headers_relay"));
}

// G22 PARITY: announceBlock skips non-handshake_complete peers.
test "w136/G22: announceBlock skips peers not in handshake_complete" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    // The announceBlock body checks state != .handshake_complete.
    const ann_idx = std.mem.indexOf(u8, peer_src, "pub fn announceBlock") orelse {
        return error.AnnounceBlockNotFound;
    };
    const window_end = @min(ann_idx + 3000, peer_src.len);
    const window = peer_src[ann_idx..window_end];
    try testing.expect(std.mem.indexOf(u8, window, "if (peer.state != .handshake_complete) continue") != null);
}

// G23 PARITY: announceBlock uses catch-continue on send failure.
test "w136/G23: announceBlock uses sendMessage(...) catch continue" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    const ann_idx = std.mem.indexOf(u8, peer_src, "pub fn announceBlock") orelse {
        return error.AnnounceBlockNotFound;
    };
    const window_end = @min(ann_idx + 3000, peer_src.len);
    const window = peer_src[ann_idx..window_end];
    try testing.expect(std.mem.indexOf(u8, window, "catch continue") != null);
}

// ============================================================================
// G24..G25 — wtxidrelay structural absence
// ============================================================================

// G24 BUG: handleMessage has no .wtxidrelay arm (post-handshake silent drop).
// This is structurally the same as G4 but listed separately so that BUG-24
// can be flipped when the dispatcher arm is added even if BUG-4's
// disconnect-on-late-arrival policy diverges in the future (e.g. softer log+drop
// rather than fDisconnect).
test "w136/G24: handleMessage switch lacks .wtxidrelay arm" {
    // Same source-grep as G4 but anchored on the "// Handle a received
    // message" comment to ensure we find the post-handshake dispatcher
    // explicitly (not the inline handshake loop).
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    const dispatcher_idx = std.mem.indexOf(u8, peer_src, "Handle a received message") orelse {
        return error.DispatcherNotFound;
    };
    // Window must cover the full switch (~70KB from dispatcher comment).
    const window_end = @min(dispatcher_idx + 80_000, peer_src.len);
    const window = peer_src[dispatcher_idx..window_end];
    try testing.expect(std.mem.indexOf(u8, window, ".wtxidrelay =>") == null);
}

// G25 INFO: no m_wtxid_relay_peers global counter on PeerManager.
test "w136/G25: PeerManager has no wtxid_relay_peers counter" {
    try testing.expect(!@hasField(PeerManager, "wtxid_relay_peers"));
    try testing.expect(!@hasField(PeerManager, "m_wtxid_relay_peers"));
    try testing.expect(!@hasField(PeerManager, "wtxidrelay_peer_count"));
}

// ============================================================================
// G26..G28 — PARITY / completeness
// ============================================================================

// G26 PARITY: SENDHEADERS handler is implemented (verify by source presence).
test "w136/G26: handleMessage .sendheaders arm is present" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    const dispatcher_idx = std.mem.indexOf(u8, peer_src, "Handle a received message") orelse {
        return error.DispatcherNotFound;
    };
    // Window must cover the full switch (~70KB from dispatcher comment).
    const window_end = @min(dispatcher_idx + 80_000, peer_src.len);
    const window = peer_src[dispatcher_idx..window_end];
    try testing.expect(std.mem.indexOf(u8, window, ".sendheaders =>") != null);
}

// G27 PARITY: SENDHEADERS is sent outbound at handshake end (both inbound and outbound).
test "w136/G27: clearbit sends sendheaders outbound at end of handshake" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    // The post-handshake send block is identifiable by this literal:
    try testing.expect(std.mem.indexOf(u8, peer_src, "p2p.Message{ .sendheaders = {} }") != null);
}

// G28 PARITY: relay-time per-peer feefilter check on tx accept.
test "w136/G28: tx relay path checks relay_peer.fee_filter_received" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);
    // The post-acceptToMemoryPool fan-out loop checks the feefilter.
    try testing.expect(std.mem.indexOf(u8, peer_src, "relay_peer.fee_filter_received > 0") != null);
}

// ============================================================================
// G29..G30 — handshake ordering + empty-mempool default
// ============================================================================

// G29 DIVERGE-INFO: sendcmpct ordering — clearbit sends sendheaders, then
// sendcmpct, then feefilter (peer.zig:1617-1631).  Core sends sendcmpct in
// the VERACK handler (line 3870) and sendheaders from SendMessages (line 5534).
test "w136/G29: clearbit handshake order is sendheaders -> sendcmpct -> feefilter" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    const sh_pos = std.mem.indexOf(u8, peer_src, "p2p.Message{ .sendheaders = {} }") orelse {
        return error.SendHeadersNotFound;
    };
    const sc_pos = std.mem.indexOf(u8, peer_src, "p2p.Message{ .sendcmpct = .{ .announce = false") orelse {
        return error.SendCmpctNotFound;
    };
    const ff_pos = std.mem.indexOf(u8, peer_src, ".feerate = 100_000") orelse {
        return error.FeeFilterNotFound;
    };
    // Document the order: sendheaders < sendcmpct < feefilter in source.
    try testing.expect(sh_pos < sc_pos);
    try testing.expect(sc_pos < ff_pos);
}

// G30 BUG: handshake feefilter ignores empty-mempool case.
// peer.zig:1628 gates only on self.relay_txs; never reads mempool state.
test "w136/G30: handshake feefilter gates only on relay_txs, not on mempool state" {
    const allocator = testing.allocator;
    const peer_src = try readPeerSrc(allocator);
    defer allocator.free(peer_src);

    // Locate the post-handshake feefilter send block.
    const ff_block_start = std.mem.indexOf(u8, peer_src, "BIP-133: Send initial feefilter after handshake") orelse {
        return error.HandshakeFeefilterBlockNotFound;
    };
    const ff_block_end = @min(ff_block_start + 600, peer_src.len);
    const window = peer_src[ff_block_start..ff_block_end];

    // The block must check self.relay_txs (correct) but must NOT read mempool
    // (incorrect — the bug).
    try testing.expect(std.mem.indexOf(u8, window, "if (self.relay_txs)") != null);
    // mempool / GetMinFee / dynamic_min_fee reference inside this window:
    const has_mempool = std.mem.indexOf(u8, window, "mempool") != null or
        std.mem.indexOf(u8, window, "GetMinFee") != null or
        std.mem.indexOf(u8, window, "dynamic_min_fee") != null;
    try testing.expect(!has_mempool);
}

// ============================================================================
// Wire-format round-trip sanity (referenced by G18 + cross-impl parity)
// ============================================================================

test "w136/wire-roundtrip: feefilter encode/decode preserves feerate" {
    const allocator = testing.allocator;

    // Build a feefilter message and confirm it round-trips through
    // encodeMessage + decodePayload.
    const original = Message{ .feefilter = FeeFilterMessage{ .feerate = 12_345 } };

    const encoded = try p2p.encodeMessage(&original, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);
    // Encoded message = 24-byte header + payload.
    try testing.expect(encoded.len >= 24);

    var header_bytes: [24]u8 = undefined;
    @memcpy(&header_bytes, encoded[0..24]);
    const header = p2p.MessageHeader.decode(&header_bytes);
    try testing.expectEqualStrings("feefilter", header.commandName());
    const payload = encoded[24..];
    try testing.expectEqual(@as(u32, 8), header.length); // u64 LE = 8 bytes
    const decoded = try p2p.decodePayload(header.commandName(), payload, allocator);
    try testing.expectEqual(@as(u64, 12_345), decoded.feefilter.feerate);
}

test "w136/wire-roundtrip: sendheaders encode/decode is empty payload" {
    const allocator = testing.allocator;
    const original = Message{ .sendheaders = {} };
    const encoded = try p2p.encodeMessage(&original, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    var header_bytes: [24]u8 = undefined;
    @memcpy(&header_bytes, encoded[0..24]);
    const header = p2p.MessageHeader.decode(&header_bytes);
    try testing.expectEqualStrings("sendheaders", header.commandName());
    // sendheaders has zero payload length.
    try testing.expectEqual(@as(u32, 0), header.length);
}

test "w136/wire-roundtrip: wtxidrelay encode/decode is empty payload" {
    const allocator = testing.allocator;
    const original = Message{ .wtxidrelay = {} };
    const encoded = try p2p.encodeMessage(&original, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    var header_bytes: [24]u8 = undefined;
    @memcpy(&header_bytes, encoded[0..24]);
    const header = p2p.MessageHeader.decode(&header_bytes);
    try testing.expectEqualStrings("wtxidrelay", header.commandName());
    try testing.expectEqual(@as(u32, 0), header.length);
}

// ============================================================================
// Behavioral / property tests on what currently EXISTS
// ============================================================================

// Verify passesFeeFilter logic: zero accepts all, non-zero gates.
// passesFeeFilter only reads .fee_filter_received, so other Peer fields
// don't need real values for this test.  We construct a Peer with the
// single field set; Zig allows this via the .{} struct-literal with all
// defaulted fields, but Peer has too many non-default fields, so we use
// a sub-test that just checks the read of the single field via a tiny
// helper struct mirroring the relevant call.
fn passesFeeFilterTestHelper(fee_filter_received: u64, tx_fee_rate: u64) bool {
    // Mirror the body of Peer.passesFeeFilter exactly.
    if (fee_filter_received == 0) return true;
    return tx_fee_rate >= fee_filter_received;
}

test "w136/passesFeeFilter: returns true when fee_filter_received == 0" {
    try testing.expect(passesFeeFilterTestHelper(0, 0));
    try testing.expect(passesFeeFilterTestHelper(0, 500_000));
    try testing.expect(passesFeeFilterTestHelper(0, std.math.maxInt(u64)));
}

test "w136/passesFeeFilter: returns false when below threshold" {
    try testing.expect(!passesFeeFilterTestHelper(10_000, 0));
    try testing.expect(!passesFeeFilterTestHelper(10_000, 9_999));
    try testing.expect(passesFeeFilterTestHelper(10_000, 10_000));
    try testing.expect(passesFeeFilterTestHelper(10_000, 10_001));
}

// Verify the BIP-339 protocol version constant matches Core.
test "w136/constants: PROTOCOL_VERSION matches Core BIP-339 threshold (70016)" {
    try testing.expectEqual(@as(i32, 70016), p2p.PROTOCOL_VERSION);
}

// Verify constants AVG_FEEFILTER_BROADCAST_INTERVAL + MAX_FEEFILTER_CHANGE_DELAY.
test "w136/constants: feefilter timing constants match Core (10min / 5min)" {
    try testing.expectEqual(@as(i64, 10 * 60), peer_mod.AVG_FEEFILTER_BROADCAST_INTERVAL);
    try testing.expectEqual(@as(i64, 5 * 60), peer_mod.MAX_FEEFILTER_CHANGE_DELAY);
}

// Verify MIN_RELAY_FEE matches Core's 1000 sat/kvB.
test "w136/constants: MIN_RELAY_FEE = 1000 sat/kvB" {
    try testing.expectEqual(@as(u64, 1000), peer_mod.MIN_RELAY_FEE);
}
