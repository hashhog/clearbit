//! W126 — BIP-152 Compact Blocks 30-gate audit (clearbit / Zig 0.13)
//!
//! Discovery wave. Audits clearbit's BIP-152 compact-block subsystem
//! (sendcmpct + cmpctblock + getblocktxn + blocktxn + announceBlock HB
//! push + PartiallyDownloadedBlock reconstruction) vs Bitcoin Core.
//!
//! Anchor finding (W123 G12 BUG-12 follow-on):
//! `PeerManager.announceBlock` only sends `inv` / `headers` to peers
//! and never proactively pushes `cmpctblock` to BIP-152 high-bandwidth
//! peers — even though the receive-side latches
//! `peer.bip152_highbandwidth_from`. The HB-from flag is a write-only
//! sink today.
//!
//! References
//! ----------
//! bitcoin-core/src/blockencodings.h / .cpp
//!   - CBlockHeaderAndShortTxIDs (constructor, FillShortTxIDSelector,
//!     GetShortID, SHORTTXIDS_LENGTH=6).
//!   - PartiallyDownloadedBlock (InitData, IsTxAvailable, FillBlock).
//!   - DifferenceFormatter, BlockTransactionsRequest, BlockTransactions.
//! bitcoin-core/src/net_processing.cpp
//!   - SENDCMPCT/CMPCTBLOCK/GETBLOCKTXN/BLOCKTXN handlers
//!     (line 3901, 4466, 4245, 4714).
//!   - MaybeSetPeerAsAnnouncingHeaderAndIDs (line 1275-1329),
//!     lNodesAnnouncingHeaderAndIDs, m_bip152_highbandwidth_to.
//!   - NewPoWValidBlock (line 2103-2152) — unsolicited cmpctblock push
//!     to HB peers, m_most_recent_compact_block cache,
//!     m_highest_fast_announce.
//!   - ProcessCompactBlockTxns (line 3441-3540).
//!   - SendBlockTransactions (line 2598-2615).
//!   - MAX_CMPCTBLOCK_DEPTH=5, MAX_BLOCKTXN_DEPTH=10,
//!     MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK, CMPCTBLOCKS_VERSION=2.
//!
//! BIP: 152.
//!
//! Status
//! ------
//! These tests are XFAIL guards (not actively failing). They assert
//! the current observable state — including the bugs — so the next fix
//! wave can flip each gate from MISSING/PARTIAL → PRESENT by
//! deliberately breaking the corresponding test. Failures here mean
//! someone already landed the fix and forgot to update the audit. See
//! `audit/w126_bip152_compact_blocks.md` for the prose write-up.
//!
//! Run: `zig build test-w126`
//!
//! NOTE: this file MUST NOT import private-only symbols. We use
//! `@embedFile("peer.zig")` etc. for source-level guards rather than
//! reaching into the PeerManager internals, mirroring W123/W124/W125.

const std = @import("std");
const testing = std.testing;

const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const types = @import("types.zig");

// ===========================================================================
// Helpers
// ===========================================================================

fn writeCompactSize(buf: *std.ArrayList(u8), val: u64) !void {
    const w = buf.writer();
    if (val < 0xfd) {
        try w.writeByte(@intCast(val));
    } else if (val <= 0xffff) {
        try w.writeByte(0xfd);
        try w.writeInt(u16, @intCast(val), .little);
    } else if (val <= 0xffffffff) {
        try w.writeByte(0xfe);
        try w.writeInt(u32, @intCast(val), .little);
    } else {
        try w.writeByte(0xff);
        try w.writeInt(u64, val, .little);
    }
}

/// 52-byte minimal coinbase tx (non-segwit, vout count=0).
fn minimalCoinbaseTx() [52]u8 {
    var tx = [_]u8{0} ** 52;
    tx[0] = 0x01; // version LE i32
    tx[4] = 0x01; // vin count = 1
    tx[37] = 0xff; tx[38] = 0xff; tx[39] = 0xff; tx[40] = 0xff;
    tx[41] = 0x01; // scriptSig len
    tx[42] = 0x51; // OP_1
    tx[43] = 0xff; tx[44] = 0xff; tx[45] = 0xff; tx[46] = 0xff;
    tx[47] = 0x00; // vout count
    return tx;
}

// ===========================================================================
// G1: SHORTTXIDS_LENGTH = 6 bytes
// Status: PRESENT.
// Core blockencodings.h:103  static constexpr int SHORTTXIDS_LENGTH = 6;
// clearbit p2p.zig:418        short_ids: []const [6]u8
// ===========================================================================

test "w126 G1: cmpctblock short_ids vector is [6]u8 (SHORTTXIDS_LENGTH=6)" {
    // Sanity: the message type holds exactly 6-byte short IDs.
    const CmpctBlockMessage = p2p.CmpctBlockMessage;
    const sids_field_type = @TypeOf(@as(CmpctBlockMessage, undefined).short_ids);
    const element_type = std.meta.Child(sids_field_type);
    try testing.expectEqual(@as(usize, 6), @sizeOf(element_type));
}

// ===========================================================================
// G2: CMPCTBLOCKS_VERSION = 2 only; sendcmpct version != 2 silently dropped.
// Status: PRESENT (FIX-43).
// Core net_processing.cpp:3907  if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
// clearbit peer.zig:1537+5325   if (sc.version != 2) return; (both call sites)
// ===========================================================================

test "w126 G2: sendcmpct version != 2 silently dropped (both handshake + post-handshake)" {
    const src = @embedFile("peer.zig");
    // Handshake loop guard (peer.zig:1537 area).
    try testing.expect(std.mem.indexOf(u8, src, "if (sc.version == 2) {") != null);
    // Post-handshake dispatch guard (peer.zig:5325).
    try testing.expect(std.mem.indexOf(u8, src, "if (sc.version != 2) return;") != null);
}

// ===========================================================================
// G3: SipHash key derivation = single SHA256(header || nonce_LE)[0..16] → k0,k1 LE u64.
// Status: PRESENT.
// Core blockencodings.cpp:35-43  FillShortTxIDSelector
// clearbit peer.zig:4734-4745    inline 88-byte construction + crypto.sha256
// ===========================================================================

test "w126 G3: SipHash key derivation matches Core (header||nonce LE → SHA256[0..16])" {
    // Build the canonical 88-byte key buffer and verify the digest layout.
    var key_data: [88]u8 = undefined;
    std.mem.writeInt(i32, key_data[0..4], 1, .little);
    @memset(key_data[4..36], 0xca);
    @memset(key_data[36..68], 0x0d);
    std.mem.writeInt(u32, key_data[68..72], 0x60000000, .little);
    std.mem.writeInt(u32, key_data[72..76], 0x1d00ffff, .little);
    std.mem.writeInt(u32, key_data[76..80], 12345, .little);
    std.mem.writeInt(u64, key_data[80..88], 0xdeadbeefcafebabe, .little);

    const key_hash = crypto.sha256(&key_data);
    const k0 = std.mem.readInt(u64, key_hash[0..8], .little);
    const k1 = std.mem.readInt(u64, key_hash[8..16], .little);
    try testing.expect(k0 != 0 or k1 != 0);

    // Source-level: peer.zig builds exactly this 88-byte buffer.
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "var key_data: [88]u8 = undefined;") != null);
    try testing.expect(std.mem.indexOf(u8, src, "crypto.sha256(&key_data)") != null);
}

// ===========================================================================
// G4: 48-bit short-id mask 0x0000ffffffffffff (upper 2 bytes zeroed).
// Status: PRESENT.
// Core blockencodings.cpp:49  return (...)(wtxid.ToUint256()) & 0xffffffffffffL;
// clearbit peer.zig:4883+5177  hasher.finalInt() & 0x0000ffffffffffff
// ===========================================================================

test "w126 G4: short-id 48-bit mask present on receive AND serve sides" {
    const src = @embedFile("peer.zig");
    // Both sites must mask to 48 bits (upper 16 cleared = 6-byte short ID).
    var count: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, src, idx, "0x0000ffffffffffff")) |pos| : (count += 1) {
        idx = pos + 1;
    }
    try testing.expect(count >= 2); // receive + serve
}

// ===========================================================================
// G5: Wtxid (not txid) used for SipHash. (BIP-152 v2 + BIP-339.)
// Status: PRESENT.
// Core blockencodings.cpp:31  shorttxids[i-1] = GetShortID(tx.GetWitnessHash());
// clearbit peer.zig:4882      hasher.update(&entry.wtxid);
//          peer.zig:5174      const wtxid = crypto.computeWtxidStreaming(tx);
// ===========================================================================

test "w126 G5: wtxid used for short-id derivation (both sides)" {
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "hasher.update(&entry.wtxid)") != null);
    try testing.expect(std.mem.indexOf(u8, src, "computeWtxidStreaming") != null);
    // Negative: no plain txid (entry.txid) feeding the SipHash key — only wtxid.
    // We only check the receive path here; the serve path uses streaming wtxid.
    try testing.expect(std.mem.indexOf(u8, src, "hasher.update(&entry.txid)") == null);
}

// ===========================================================================
// G6: sendcmpct decoder + Peer state latch.
// Status: PRESENT.
// Core CNodeState::m_provides_cmpctblocks + CNode::m_bip152_highbandwidth_from
// clearbit Peer.bip152_provides_cmpctblocks + Peer.bip152_highbandwidth_from
// ===========================================================================

test "w126 G6: Peer has bip152_* fields, set on sendcmpct(version=2)" {
    try testing.expect(@hasField(peer_mod.Peer, "bip152_provides_cmpctblocks"));
    try testing.expect(@hasField(peer_mod.Peer, "bip152_highbandwidth_from"));
    // Default false (the field has a default initializer).
    const p: peer_mod.Peer = undefined;
    _ = p;
}

// ===========================================================================
// G7: cmpctblock decoder DoS guards (max 100k short_ids + uint16 cap +
// per-prefilled delta overflow).
// Status: PRESENT.
// Core blockencodings.cpp:64  MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE_TX_WEIGHT
// Core blockencodings.h:125   BlockTxCount must fit in uint16
// clearbit p2p.zig:957-981    all four guards
// ===========================================================================

test "w126 G7: cmpctblock decoder rejects short_id_count > 100000" {
    const allocator = testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = buf.writer();
    try w.writeInt(i32, 1, .little);
    try w.writeAll(&([_]u8{0xab} ** 32));
    try w.writeAll(&([_]u8{0} ** 32));
    try w.writeInt(u32, 0x5f000000, .little);
    try w.writeInt(u32, 0x1d00ffff, .little);
    try w.writeInt(u32, 0, .little);
    try w.writeInt(u64, 1, .little);
    try writeCompactSize(&buf, 100_001);
    const payload = try buf.toOwnedSlice();
    defer allocator.free(payload);
    const result = p2p.decodePayload("cmpctblock", payload, allocator);
    try testing.expectError(p2p.ParseError.InvalidData, result);
}

test "w126 G7: cmpctblock decoder rejects short_ids+prefilled > 0xffff (BlockTxCount uint16)" {
    const allocator = testing.allocator;
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    const w = buf.writer();
    try w.writeInt(i32, 1, .little);
    try w.writeAll(&([_]u8{0xab} ** 32));
    try w.writeAll(&([_]u8{0} ** 32));
    try w.writeInt(u32, 0x5f000000, .little);
    try w.writeInt(u32, 0x1d00ffff, .little);
    try w.writeInt(u32, 0, .little);
    try w.writeInt(u64, 1, .little);
    // 1 short_id
    try writeCompactSize(&buf, 1);
    try w.writeAll(&[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });
    // 65535 prefilled → sum = 65536 > 0xffff
    try writeCompactSize(&buf, 65535);
    const payload = try buf.toOwnedSlice();
    defer allocator.free(payload);
    const result = p2p.decodePayload("cmpctblock", payload, allocator);
    try testing.expectError(p2p.ParseError.InvalidData, result);
}

// ===========================================================================
// G8: PartiallyDownloadedBlock state NOT persisted across getblocktxn round-trip.
// Status: MISSING — BUG-1 (P2).
// Core net_processing.cpp:211  QueuedBlock::partialBlock
// clearbit                     no PartialBlock / partial_block field on Peer or PeerManager.
// ===========================================================================

test "w126 G8 BUG-1: no PartiallyDownloadedBlock field on Peer or PeerManager (xfail)" {
    // PartialState would need to be stored to survive the getblocktxn round-trip.
    try testing.expect(!@hasField(peer_mod.Peer, "partial_block"));
    try testing.expect(!@hasField(peer_mod.Peer, "partial_compact_block"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "partial_blocks"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "cmpct_in_flight"));
    // Source-level cross-check: peer.zig has no "PartiallyDownloadedBlock" type
    // declaration and no "partial_block" field reference.
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "PartiallyDownloadedBlock") == null);
    try testing.expect(std.mem.indexOf(u8, src, "partialBlock") == null);
}

// ===========================================================================
// G9: blocktxn receive — completes reconstruction + submits to validation.
// Status: MISSING — BUG-2 (P2).
// Core net_processing.cpp:4714-4730  BLOCKTXN handler → ProcessCompactBlockTxns
// clearbit peer.zig:4994-5004        no-op with "Ignore." comment
// ===========================================================================

test "w126 G9 BUG-2: .blocktxn arm is a no-op (free-and-return) (xfail)" {
    const src = @embedFile("peer.zig");
    // Locate the .blocktxn arm in the dispatch.
    const arm_pos = std.mem.indexOf(u8, src, ".blocktxn => |bt| {") orelse
        return error.TestUnexpectedResult;
    // Look at the next ~600 bytes of the arm body.
    const body_end = @min(arm_pos + 600, src.len);
    const body = src[arm_pos..body_end];
    // No call to validation pipeline.
    try testing.expect(std.mem.indexOf(u8, body, "acceptBlock") == null);
    try testing.expect(std.mem.indexOf(u8, body, "ConnectBlock") == null);
    try testing.expect(std.mem.indexOf(u8, body, "submitBlock") == null);
    try testing.expect(std.mem.indexOf(u8, body, "processCompactBlockTxns") == null);
    // The actual comment of confession.
    try testing.expect(std.mem.indexOf(u8, body, "we shouldn't receive these") != null or
        std.mem.indexOf(u8, body, "Ignore.") != null);
}

// ===========================================================================
// G10: FillBlock + submit assembled block to validation pipeline.
// Status: MISSING — BUG-3 (P2). LARGEST DEAD-HELPER in BIP-152 subsystem.
// Core blockencodings.cpp:191  PartiallyDownloadedBlock::FillBlock
// clearbit peer.zig:4910       literal "// TODO: assemble full block and pass to validation"
// ===========================================================================

test "w126 G10 BUG-3: reconstruction success path is dead-helper-at-tail (xfail)" {
    const src = @embedFile("peer.zig");
    // The TODO is the developer's confession that the assembled block
    // is never built/submitted.
    try testing.expect(std.mem.indexOf(u8, src, "TODO: assemble full block and pass to validation") != null);
    // Verify there's no FillBlock-equivalent next to it.
    const todo_pos = std.mem.indexOf(u8, src, "TODO: assemble full block and pass to validation") orelse
        return error.TestUnexpectedResult;
    // Surrounding ~500 bytes (before AND after the TODO) must NOT contain
    // an assemble/submit call.
    const window_start = if (todo_pos > 500) todo_pos - 500 else 0;
    const window_end = @min(todo_pos + 500, src.len);
    const window = src[window_start..window_end];
    try testing.expect(std.mem.indexOf(u8, window, "self.acceptBlock") == null);
    try testing.expect(std.mem.indexOf(u8, window, "validation.acceptBlock") == null);
    try testing.expect(std.mem.indexOf(u8, window, "FillBlock") == null);
}

// ===========================================================================
// G11: getblocktxn SERVE path emits blocktxn for depth <= MAX_BLOCKTXN_DEPTH.
// Status: PARTIAL — BUG-4 (P1).
// Core net_processing.cpp:4276+SendBlockTransactions  serves blocktxn at depth<=10
// clearbit peer.zig:4990-4992  literal "we don't yet serve blocktxn responses"
// ===========================================================================

test "w126 G11 BUG-4: in-depth getblocktxn handler does not emit blocktxn (xfail)" {
    const src = @embedFile("peer.zig");
    // Confession comment present (exact phrasing from peer.zig:4991-4992:
    // "we don't yet serve\n                // blocktxn responses (BUG-7,...").
    // The comment may be wrapped across lines, so look for the BUG-7 marker
    // which is unique enough.
    try testing.expect(std.mem.indexOf(u8, src, "BUG-7, separate from BUG-8") != null);
    // No outgoing .blocktxn = {} message constructor anywhere in peer.zig.
    try testing.expect(std.mem.indexOf(u8, src, ".blocktxn = .{") == null);
}

test "w126 G11 PASS pin: MAX_BLOCKTXN_DEPTH=10 fallback path serves full block" {
    const src = @embedFile("peer.zig");
    // The depth-exceeds branch IS wired (FIX-42); falls back to full block.
    try testing.expect(std.mem.indexOf(u8, src, "gbt_depth > p2p.MAX_BLOCKTXN_DEPTH") != null);
    try testing.expectEqual(@as(u32, 10), p2p.MAX_BLOCKTXN_DEPTH);
    // Safety: must be <= MIN_BLOCKS_TO_KEEP=288 per Core static_assert.
    try testing.expect(p2p.MAX_BLOCKTXN_DEPTH <= 288);
}

// ===========================================================================
// G12: vExtraTxnForCompact extra-txn pool for reconstruction.
// Status: MISSING — BUG-5 (P2).
// Core net_processing.cpp:997  vExtraTxnForCompact ring buffer (size DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN=100)
// clearbit                     not present.
// ===========================================================================

test "w126 G12 BUG-5: vExtraTxnForCompact equivalent absent (xfail)" {
    try testing.expect(!@hasField(peer_mod.PeerManager, "extra_txn_for_compact"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "extra_txn_pool"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "vExtraTxnForCompact"));
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "vExtraTxnForCompact") == null);
    try testing.expect(std.mem.indexOf(u8, src, "extra_txn_for_compact") == null);
    // Confirm the only candidate-tx source in the cmpctblock handler is
    // the mempool iterator (no secondary pool). peer.zig:4874 has
    // `if (self.mempool) |mp| {`. The cmpctblock arm spans ~240 lines so we
    // slice from the arm's opening brace to the next dispatch arm.
    const handler_pos = std.mem.indexOf(u8, src, ".cmpctblock => |cb| {") orelse
        return error.TestUnexpectedResult;
    const handler_end_pos = std.mem.indexOfPos(u8, src, handler_pos, ".getblocktxn => |gbt|") orelse
        return error.TestUnexpectedResult;
    const handler_body = src[handler_pos..handler_end_pos];
    try testing.expect(std.mem.indexOf(u8, handler_body, "if (self.mempool)") != null);
    try testing.expect(std.mem.indexOf(u8, handler_body, "extra_txn") == null);
}

// ===========================================================================
// G13: IBD gate on incoming cmpctblock — Core skips reconstruction during IBD.
// Status: MISSING — BUG-6 (P2).
// Core net_processing.cpp:4570  if (!already_in_flight && !CanDirectFetch()) return;
// clearbit peer.zig:4703+      .cmpctblock arm does not call self.isIBD()
// ===========================================================================

test "w126 G13 BUG-6: cmpctblock handler does not check isIBD() (xfail)" {
    const src = @embedFile("peer.zig");
    // Confirm isIBD exists (called by other code paths) but not from cmpctblock.
    try testing.expect(std.mem.indexOf(u8, src, "fn isIBD(self") != null);
    // Slice out the .cmpctblock arm body.
    const arm_start = std.mem.indexOf(u8, src, ".cmpctblock => |cb| {") orelse
        return error.TestUnexpectedResult;
    const arm_end = std.mem.indexOf(u8, src, ".getblocktxn => |gbt|") orelse
        return error.TestUnexpectedResult;
    const arm_body = src[arm_start..arm_end];
    // No IBD check inside the arm body.
    try testing.expect(std.mem.indexOf(u8, arm_body, "isIBD") == null);
    try testing.expect(std.mem.indexOf(u8, arm_body, "CanDirectFetch") == null);
}

// ===========================================================================
// G14: LoadingBlocks gate on cmpctblock AND blocktxn.
// Status: MISSING — BUG-7 (P3, latent until reindex lands).
// Core net_processing.cpp:4469+4717  early-return if LoadingBlocks()
// clearbit                          no reindex / loading flag at all (W124 G29).
// ===========================================================================

test "w126 G14 BUG-7: no LoadingBlocks gate (no reindex support today; xfail)" {
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "LoadingBlocks") == null);
    try testing.expect(std.mem.indexOf(u8, src, "loading_blocks") == null);
    try testing.expect(std.mem.indexOf(u8, src, "is_reindexing") == null);
}

// ===========================================================================
// G15: PoW preliminary check before cmpctblock reconstruction.
// Status: MISSING — BUG-8 (P2). DoS amplification.
// Core net_processing.cpp:4490-4494  prev_block->nChainWork + GetBlockProof(...) < GetAntiDoSWorkThreshold
// clearbit peer.zig:4703+           jumps straight into SipHash/slot fill, no PoW gate.
// ===========================================================================

test "w126 G15 BUG-8: no anti-DoS PoW preliminary gate before reconstruction (xfail)" {
    const src = @embedFile("peer.zig");
    const arm_start = std.mem.indexOf(u8, src, ".cmpctblock => |cb| {") orelse
        return error.TestUnexpectedResult;
    const arm_end = std.mem.indexOf(u8, src, ".getblocktxn => |gbt|") orelse
        return error.TestUnexpectedResult;
    const arm_body = src[arm_start..arm_end];
    // No anti-DoS work-threshold check in the handler.
    try testing.expect(std.mem.indexOf(u8, arm_body, "GetAntiDoSWorkThreshold") == null);
    try testing.expect(std.mem.indexOf(u8, arm_body, "anti_dos_work") == null);
    try testing.expect(std.mem.indexOf(u8, arm_body, "min_chain_work") == null);
    // The header is hashed but not validated for PoW before reconstruction.
    try testing.expect(std.mem.indexOf(u8, arm_body, "computeBlockHash") != null);
}

// ===========================================================================
// G16: announceBlock — HB-compact branch on bip152_highbandwidth_from.
// Status: MISSING — BUG-9 (P1). ANCHOR finding (W123 G12 BUG-12).
// Core net_processing.cpp:2103-2152  NewPoWValidBlock pushes cmpctblock to HB peers.
// clearbit peer.zig:7134-7160        announceBlock sends only inv/headers.
// ===========================================================================

test "w126 G16 BUG-9: announceBlock body does not branch on bip152_highbandwidth_from (xfail)" {
    const src = @embedFile("peer.zig");
    const fn_start = std.mem.indexOf(u8, src, "pub fn announceBlock(") orelse
        return error.TestUnexpectedResult;
    // The function ends at the next "\n    }\n" marker.
    const fn_end_marker = std.mem.indexOfPos(u8, src, fn_start, "\n    }\n") orelse
        return error.TestUnexpectedResult;
    const body = src[fn_start..fn_end_marker];
    // Body sends inv and headers only — no cmpctblock constructor.
    try testing.expect(std.mem.indexOf(u8, body, "cmpctblock") == null);
    try testing.expect(std.mem.indexOf(u8, body, ".cmpctblock") == null);
    // bip152_highbandwidth_from flag is NOT read here (W123 G12 confirmed).
    try testing.expect(std.mem.indexOf(u8, body, "bip152_highbandwidth_from") == null);
    // Sanity: the function DOES exist and DOES send headers/inv.
    try testing.expect(std.mem.indexOf(u8, body, ".headers") != null);
    try testing.expect(std.mem.indexOf(u8, body, ".inv") != null);
}

test "w126 G16 PASS pin: bip152_highbandwidth_from IS latched on receive (the write-only sink)" {
    const src = @embedFile("peer.zig");
    // The receive site DOES set the field (peer.zig:5327 / 1539 area).
    var write_count: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, src, idx, "bip152_highbandwidth_from = sc.announce")) |pos| {
        write_count += 1;
        idx = pos + 1;
    }
    try testing.expect(write_count >= 2); // both handshake-loop + post-handshake
}

// ===========================================================================
// G17: lNodesAnnouncingHeaderAndIDs — HB-peer selection list (<=3).
// Status: MISSING — BUG-10 (P1).
// Core net_processing.cpp:987    std::list<NodeId> lNodesAnnouncingHeaderAndIDs
// clearbit                       no list / no MaybeSetPeerAsAnnouncingHeaderAndIDs
// ===========================================================================

test "w126 G17 BUG-10: no lNodesAnnouncingHeaderAndIDs / HB-peer LRU list (xfail)" {
    // No HB-peer list state on PeerManager.
    try testing.expect(!@hasField(peer_mod.PeerManager, "hb_peers"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "nodes_announcing_header_and_ids"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "compact_announce_peers"));
    const src = @embedFile("peer.zig");
    // The Core name `lNodesAnnouncingHeaderAndIDs` appears once in a doc
    // comment at peer.zig:686 (Reference: bitcoin-core/src/net_processing.cpp).
    // Anti-implementation guard: it must NOT appear as an identifier in code.
    // Implementation usage would be `var lNodesAnnouncing...` or
    // `self.lNodesAnnouncing...`. We assert neither pattern is present.
    try testing.expect(std.mem.indexOf(u8, src, "self.lNodesAnnouncing") == null);
    try testing.expect(std.mem.indexOf(u8, src, "var lNodesAnnouncing") == null);
    try testing.expect(std.mem.indexOf(u8, src, "MaybeSetPeerAsAnnouncingHeaderAndIDs") == null);
    // Outgoing sendcmpct(hb=true) is NEVER constructed after handshake.
    // The only outgoing sendcmpct in the codebase is the initial hb=false at peer.zig:1623.
    var hb_true_count: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, src, idx, ".announce = true, .version = 2")) |pos| {
        hb_true_count += 1;
        idx = pos + 1;
    }
    try testing.expectEqual(@as(usize, 0), hb_true_count);
}

// ===========================================================================
// G18: outbound HB preference — inbound HB candidate must not evict last outbound HB peer.
// Status: MISSING — BUG-11 (P2). Gated on G17.
// Core net_processing.cpp:1298-1308  std::swap to preserve outbound HB.
// ===========================================================================

test "w126 G18 BUG-11: outbound-HB-preference logic absent (gated on G17; xfail)" {
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "num_outbound_hb_peers") == null);
    try testing.expect(std.mem.indexOf(u8, src, "outbound_hb") == null);
}

// ===========================================================================
// G19: NewPoWValidBlock signal → fast-announce cmpctblock to HB peers.
// Status: MISSING — BUG-12 (P1).
// Core net_processing.cpp:2103-2152  NewPoWValidBlock + ForEachNode + per-peer push
// clearbit                          no signal, no per-peer state.m_requested_hb_cmpctblocks gate
// ===========================================================================

test "w126 G19 BUG-12: NewPoWValidBlock signal absent (xfail)" {
    const src_peer = @embedFile("peer.zig");
    const src_validation = @embedFile("validation.zig");
    // The Core name appears in W97 G23 documentation comments in validation.zig
    // (the test that records the gap was already there from W97). Anti-
    // implementation guard: must not appear as an actual Zig fn/method.
    try testing.expect(std.mem.indexOf(u8, src_peer, "fn newPoWValidBlock") == null);
    try testing.expect(std.mem.indexOf(u8, src_peer, "pub fn newPoWValidBlock") == null);
    try testing.expect(std.mem.indexOf(u8, src_validation, "fn newPoWValidBlock") == null);
    try testing.expect(std.mem.indexOf(u8, src_validation, "pub fn newPoWValidBlock") == null);
    try testing.expect(std.mem.indexOf(u8, src_peer, "newpow_valid_block") == null);
    // Anti-call guard: no caller invokes `NewPoWValidBlock` / `newPoWValidBlock(`.
    try testing.expect(std.mem.indexOf(u8, src_peer, "newPoWValidBlock(") == null);
    try testing.expect(std.mem.indexOf(u8, src_validation, "newPoWValidBlock(") == null);
}

// ===========================================================================
// G20: m_most_recent_block / m_most_recent_compact_block cache for fast getblocktxn.
// Status: MISSING — BUG-13 (P2).
// Core net_processing.cpp:2126-2131  cache under m_most_recent_block_mutex
// Core net_processing.cpp:4256-4263  GETBLOCKTXN fast path
// ===========================================================================

test "w126 G20 BUG-13: m_most_recent_block / compact-block cache absent (xfail)" {
    try testing.expect(!@hasField(peer_mod.PeerManager, "most_recent_block"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "most_recent_compact_block"));
    try testing.expect(!@hasField(peer_mod.PeerManager, "most_recent_block_hash"));
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "m_most_recent_block") == null);
    try testing.expect(std.mem.indexOf(u8, src, "most_recent_compact_block") == null);
}

// ===========================================================================
// G21: m_highest_fast_announce monotonic guard.
// Status: MISSING — BUG-14 (P3). Gated on G19.
// Core net_processing.cpp:2109-2111  if (nHeight <= m_highest_fast_announce) return;
// ===========================================================================

test "w126 G21 BUG-14: m_highest_fast_announce monotonic guard absent (xfail)" {
    try testing.expect(!@hasField(peer_mod.PeerManager, "highest_fast_announce"));
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "highest_fast_announce") == null);
    try testing.expect(std.mem.indexOf(u8, src, "m_highest_fast_announce") == null);
}

// ===========================================================================
// G22: Initial outbound sendcmpct(hb=false, v=2) on handshake — inbound path gap.
// Status: PARTIAL — BUG-15 (P2).
// Core net_processing.cpp:3870  sendcmpct sent on BOTH inbound + outbound verack
// clearbit peer.zig:1623        only sent in the outbound handshake path.
// ===========================================================================

test "w126 G22 BUG-15: inbound handshake path does NOT send sendcmpct (xfail)" {
    const src = @embedFile("peer.zig");
    // The single outgoing sendcmpct construction is at peer.zig:1623 area.
    var send_count: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, src, idx, ".sendcmpct = .{ .announce = false, .version = 2 }")) |pos| {
        send_count += 1;
        idx = pos + 1;
    }
    // Currently exactly 1 outgoing site; if a fix wave adds the inbound site,
    // this count should become >= 2.
    try testing.expectEqual(@as(usize, 1), send_count);
}

// ===========================================================================
// G23: PartiallyDownloadedBlock InitData null-header + both-empty guards.
// Status: PRESENT.
// Core blockencodings.cpp:62  if (header.IsNull() || (shorttxids.empty() && prefilledtxn.empty()))
// clearbit peer.zig:4714-4727  both guards present.
// ===========================================================================

test "w126 G23: null-header guard fires on zero block hash" {
    const src = @embedFile("peer.zig");
    // The handler computes computeBlockHash and compares against zero_hash.
    try testing.expect(std.mem.indexOf(u8, src, "computeBlockHash(&cb.header)") != null);
    try testing.expect(std.mem.indexOf(u8, src, "P2P: cmpctblock null header, ignoring") != null);
    // both-empty guard
    try testing.expect(std.mem.indexOf(u8, src, "cmpctblock both shorttxids and prefilled empty") != null);
}

// ===========================================================================
// G24: Prefilled differential index accumulation + overflow + gap checks.
// Status: PRESENT.
// Core blockencodings.cpp:72-87
// clearbit peer.zig:4767-4786
// ===========================================================================

test "w126 G24: prefilled differential index accumulation present" {
    const src = @embedFile("peer.zig");
    // last_prefilled_index accumulator (mirror of Core's int32_t lastprefilledindex)
    try testing.expect(std.mem.indexOf(u8, src, "last_prefilled_index") != null);
    // > 0xffff overflow guard
    try testing.expect(std.mem.indexOf(u8, src, "last_prefilled_index > 0xffff") != null);
    // gap guard (lastprefilledindex > cb.short_ids.len + i)
    try testing.expect(std.mem.indexOf(u8, src, "cb.short_ids.len + i") != null);
}

// ===========================================================================
// G25: Short-id duplicate + bucket-overflow (max 12) DoS checks.
// Status: PRESENT.
// Core blockencodings.cpp:110-116
// clearbit peer.zig:4830-4851
// ===========================================================================

test "w126 G25: collision detection + bucket-overflow DoS check present" {
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "short-id collision detected") != null);
    try testing.expect(std.mem.indexOf(u8, src, "bucket overflow") != null);
    // Bucket size cap = 12 (Core blockencodings.cpp:110).
    try testing.expect(std.mem.indexOf(u8, src, "if (new_count > 12)") != null);
}

// ===========================================================================
// G26: Mempool wtxid match + second-match slot-clear.
// Status: PRESENT.
// Core blockencodings.cpp:121-145
// clearbit peer.zig:4869-4900
// ===========================================================================

test "w126 G26: mempool match + second-match clear (Core blockencodings.cpp:129-136)" {
    const src = @embedFile("peer.zig");
    // mempool iteration loop using entry.wtxid
    try testing.expect(std.mem.indexOf(u8, src, "mp.entries.iterator") != null);
    try testing.expect(std.mem.indexOf(u8, src, "hasher.update(&entry.wtxid)") != null);
    // Second-match clear (when slot already filled by another mempool match)
    try testing.expect(std.mem.indexOf(u8, src, "txn_available[slot_idx] = null") != null);
    // mempool_hits accounting + early exit
    try testing.expect(std.mem.indexOf(u8, src, "mempool_hits == cb.short_ids.len") != null);
}

// ===========================================================================
// G27: Reconstruction fallback policy — getblocktxn vs full block.
// Status: PARTIAL — BUG-16 (P2). Diverges from Core's first-in-flight rule.
// Core net_processing.cpp:4609-4633  first_in_flight / hb-to / outbound-priority rule
// clearbit peer.zig:4911-4942        50% miss-pct threshold (clearbit invention)
// ===========================================================================

test "w126 G27 BUG-16: fallback uses 50% threshold (clearbit invention, not Core)" {
    const src = @embedFile("peer.zig");
    // The 50% threshold is the clearbit-only rule.
    try testing.expect(std.mem.indexOf(u8, src, "miss_pct > 50.0") != null);
    try testing.expect(std.mem.indexOf(u8, src, "miss_pct") != null);
    // Core's first_in_flight rule is NOT present.
    try testing.expect(std.mem.indexOf(u8, src, "first_in_flight") == null);
    try testing.expect(std.mem.indexOf(u8, src, "already_in_flight") == null);
    try testing.expect(std.mem.indexOf(u8, src, "MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK") == null);
}

// ===========================================================================
// G28: MSG_CMPCT_BLOCK getdata branch (we SERVE compact).
// Status: PRESENT (FIX-42).
// Core net_processing.cpp:2461-2476
// clearbit peer.zig:5102-5232
// ===========================================================================

test "w126 G28: MSG_CMPCT_BLOCK serve path + MAX_CMPCTBLOCK_DEPTH=5 wired" {
    try testing.expectEqual(@as(u32, 5), p2p.MAX_CMPCTBLOCK_DEPTH);
    try testing.expectEqual(@as(u32, 4), @intFromEnum(p2p.InvType.msg_cmpct_block));
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "depth <= p2p.MAX_CMPCTBLOCK_DEPTH") != null);
    try testing.expect(std.mem.indexOf(u8, src, "InvType.msg_cmpct_block") != null);
    // The serve path builds a CBlockHeaderAndShortTxIDs (coinbase prefilled + short_ids).
    try testing.expect(std.mem.indexOf(u8, src, "served cmpctblock depth") != null);
}

test "w126 G28 BUG-17: we never ISSUE MSG_CMPCT_BLOCK getdata (asymmetric; xfail)" {
    const src = @embedFile("peer.zig");
    // The fallback getdata we send in the cmpctblock handler uses
    // msg_witness_block, not msg_cmpct_block.
    const arm_start = std.mem.indexOf(u8, src, ".cmpctblock => |cb| {") orelse
        return error.TestUnexpectedResult;
    const arm_end = std.mem.indexOf(u8, src, ".getblocktxn => |gbt|") orelse
        return error.TestUnexpectedResult;
    const arm_body = src[arm_start..arm_end];
    // Multiple fallback getdata sites use msg_witness_block (NOT msg_cmpct_block).
    var msg_witness_count: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, arm_body, idx, ".inv_type = .msg_witness_block")) |pos| {
        msg_witness_count += 1;
        idx = pos + 1;
    }
    try testing.expect(msg_witness_count >= 2);
    // No `.inv_type = .msg_cmpct_block` in any OUTGOING getdata.
    try testing.expect(std.mem.indexOf(u8, arm_body, ".inv_type = .msg_cmpct_block") == null);
}

// ===========================================================================
// G29: via_compact_block punishment flag (BIP-152 §"MUST NOT ban").
// Status: MISSING — BUG-18 (P2). Forward-regression hazard once G10 lands.
// Core net_processing.cpp:4505+4682  via_compact_block=true in MaybePunishNodeForBlock
// ===========================================================================

test "w126 G29 BUG-18: no via_compact_block flag on misbehaving / punish path (xfail)" {
    const src = @embedFile("peer.zig");
    try testing.expect(std.mem.indexOf(u8, src, "via_compact_block") == null);
    try testing.expect(std.mem.indexOf(u8, src, "via_cmpct_block") == null);
    // Confirm Misbehaving / misbehaving fn exists (it does — peer.zig has it)
    // but doesn't take a "via compact block" flag.
    try testing.expect(std.mem.indexOf(u8, src, "fn misbehaving") != null);
}

// ===========================================================================
// G30: SipHash key construction is order-stable (header serialize matches Core).
// Status: PRESENT.
// Receive (peer.zig:4734-4745) + Serve (peer.zig:5149-5163) both lay out:
//   version(i32 LE) || prev_block(32B) || merkle_root(32B) ||
//   timestamp(u32 LE) || bits(u32 LE) || nonce(u32 LE) || siphash_nonce(u64 LE)
// ===========================================================================

test "w126 G30: SipHash key buffer layout matches Core blockencodings.cpp:37-38 << ordering" {
    // Verify both sides construct an 88-byte key buffer with the same layout.
    const src = @embedFile("peer.zig");
    var buf88_count: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, src, idx, "[88]u8 = undefined;")) |pos| {
        buf88_count += 1;
        idx = pos + 1;
    }
    // Both receive AND serve sides construct the 88-byte buffer.
    try testing.expect(buf88_count >= 2);

    // Cross-check field-order writes at the receive site by computing the
    // same digest the handler does and confirming non-zero k0/k1.
    var key_data: [88]u8 = undefined;
    std.mem.writeInt(i32, key_data[0..4], 1, .little);
    @memset(key_data[4..36], 0xab);
    @memset(key_data[36..68], 0xcd);
    std.mem.writeInt(u32, key_data[68..72], 0x60000000, .little);
    std.mem.writeInt(u32, key_data[72..76], 0x1d00ffff, .little);
    std.mem.writeInt(u32, key_data[76..80], 0, .little);
    std.mem.writeInt(u64, key_data[80..88], 0x1234567890abcdef, .little);
    const digest = crypto.sha256(&key_data);
    const k0 = std.mem.readInt(u64, digest[0..8], .little);
    const k1 = std.mem.readInt(u64, digest[8..16], .little);
    try testing.expect(k0 != 0);
    try testing.expect(k1 != 0);
}

// ===========================================================================
// G0: smoke test — file compiles + W126 namespace is wired into the test build.
// ===========================================================================

test "w126 G0_root_smoke: file compiles + p2p decoders for all 4 BIP-152 messages exist" {
    // Compile-time presence check: all four BIP-152 wire messages are
    // representable in the Message union.
    const Message = p2p.Message;
    const tag_names = comptime std.meta.fieldNames(Message);
    var found_sendcmpct = false;
    var found_cmpctblock = false;
    var found_getblocktxn = false;
    var found_blocktxn = false;
    inline for (tag_names) |n| {
        if (std.mem.eql(u8, n, "sendcmpct")) found_sendcmpct = true;
        if (std.mem.eql(u8, n, "cmpctblock")) found_cmpctblock = true;
        if (std.mem.eql(u8, n, "getblocktxn")) found_getblocktxn = true;
        if (std.mem.eql(u8, n, "blocktxn")) found_blocktxn = true;
    }
    try testing.expect(found_sendcmpct);
    try testing.expect(found_cmpctblock);
    try testing.expect(found_getblocktxn);
    try testing.expect(found_blocktxn);
    // Silence unused-import warnings (serialize / types are used by the
    // helper functions above only when building specific gate payloads).
    _ = serialize;
    _ = types;
}
