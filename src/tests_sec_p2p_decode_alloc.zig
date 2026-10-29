//! Security audit 2026-10-29 (audits/security/clearbit-2026-10-29.md in the
//! meta-repo), findings C1, C4 and C5.
//!
//! C1: the P2P decoders allocated `count * sizeof(element)` from an
//!     attacker-supplied CompactSize before reading a single element. A 9-byte
//!     `tx` asked for 2.4 GB (ReleaseSafe memsets it, so it is resident).
//!     Core deserialises vectors in MAX_VECTOR_ALLOCATE batches
//!     (serialize.h), so the same input costs it at most 5 MiB.
//! C4: a decode error part-way through an array leaked the elements decoded
//!     so far, and the handler arms for a post-handshake `version`, `reqrecon`
//!     and `sketch` freed nothing. Under c_allocator both are permanent.
//! C5: `block_buffer.put` replaced a buffered body without freeing it, so a
//!     peer re-sending a body for a queued hash leaked ~4 MB per message.
//!
//! The C1 tests run the decoder under an allocator that refuses (and records)
//! any single request above 1 MiB, so the base commit fails them by name
//! without actually committing gigabytes. The C4/C5 tests rely on
//! std.testing.allocator's leak check.

const std = @import("std");
const testing = std.testing;
const p2p = @import("p2p.zig");
const serialize = @import("serialize.zig");
const types = @import("types.zig");
const consensus = @import("consensus.zig");
const crypto = @import("crypto.zig");
const peer_mod = @import("peer.zig");
const hb = @import("historical_backfill.zig");

// ---------------------------------------------------------------------------
// Allocator that records the largest single request and refuses big ones.
// ---------------------------------------------------------------------------

const CAP: usize = 1 << 20; // 1 MiB: far above any honest 9..100-byte payload

const BoundedAllocator = struct {
    inner: std.mem.Allocator,
    largest: usize = 0,

    fn allocator(self: *BoundedAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (len > self.largest) self.largest = len;
        if (len > CAP) return null;
        return self.inner.rawAlloc(len, ptr_align, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > self.largest) self.largest = new_len;
        if (new_len > CAP) return false;
        return self.inner.rawResize(buf, buf_align, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(buf, buf_align, ret_addr);
    }
};

/// Decode `payload` as `command` under the bounded allocator. Asserts that no
/// single request exceeded CAP and that the decode failed for a reason other
/// than our allocator refusing (OutOfMemory would mean the cap was hit).
fn expectNoHugeAlloc(command: []const u8, payload: []const u8) !void {
    var ba = BoundedAllocator{ .inner = testing.allocator };
    const a = ba.allocator();
    const res = p2p.decodePayload(command, payload, a);
    if (res) |msg| {
        p2p.freeDecodedMessage(a, msg);
        return error.TestUnexpectedResult; // every case below is malformed
    } else |err| {
        if (ba.largest > CAP) {
            std.debug.print("{s}: {d}-byte payload asked for {d} bytes\n", .{ command, payload.len, ba.largest });
        }
        try testing.expect(ba.largest <= CAP);
        try testing.expect(err != error.OutOfMemory);
    }
}

// 0xFE 00 00 00 02 = CompactSize 0x02000000 = MAX_SIZE, the largest count
// readCompactSize accepts.
const MAX_COUNT = [_]u8{ 0xFE, 0x00, 0x00, 0x00, 0x02 };

fn cat(comptime parts: []const []const u8) [total(parts)]u8 {
    var out: [total(parts)]u8 = undefined;
    var i: usize = 0;
    for (parts) |p| {
        @memcpy(out[i .. i + p.len], p);
        i += p.len;
    }
    return out;
}

fn total(comptime parts: []const []const u8) usize {
    var n: usize = 0;
    for (parts) |p| n += p.len;
    return n;
}

const VERSION1 = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
const ZERO32 = [_]u8{0} ** 32;
const ZERO4 = [_]u8{0} ** 4;
const SEQ = [_]u8{0xFF} ** 4;
const HEADER80 = [_]u8{0} ** 80;
/// One complete legacy input with an empty scriptSig.
const INPUT_EMPTY = cat(&.{ &ZERO32, &ZERO4, &[_]u8{0x00}, &SEQ });
/// One complete legacy input with a 5-byte scriptSig (heap-duped on decode).
const INPUT_SIG5 = cat(&.{ &ZERO32, &ZERO4, &[_]u8{ 0x05, 1, 2, 3, 4, 5 }, &SEQ });

// --- C1 -------------------------------------------------------------------

test "sec_p2p_decode: C1 9-byte tx with MAX_SIZE input count does not allocate by count" {
    // Audit: 33,554,432 x sizeof(TxIn) = 2.41 GB before the first read.
    try expectNoHugeAlloc("tx", &cat(&.{ &VERSION1, &MAX_COUNT }));
}

test "sec_p2p_decode: C1 tx with MAX_SIZE output count does not allocate by count" {
    try expectNoHugeAlloc("tx", &cat(&.{ &VERSION1, &[_]u8{0x01}, &INPUT_EMPTY, &MAX_COUNT }));
}

test "sec_p2p_decode: C1 segwit tx with MAX_SIZE witness count does not allocate by count" {
    // marker+flag, 1 input, 0 outputs, then the witness stack count.
    try expectNoHugeAlloc("tx", &cat(&.{ &VERSION1, &[_]u8{ 0x00, 0x01, 0x01 }, &INPUT_EMPTY, &[_]u8{0x00}, &MAX_COUNT }));
}

test "sec_p2p_decode: C1 block with MAX_SIZE tx count does not allocate by count" {
    try expectNoHugeAlloc("block", &cat(&.{ &HEADER80, &MAX_COUNT }));
}

test "sec_p2p_decode: C1 blocktxn with MAX_SIZE tx count does not allocate by count" {
    // The audit's ~41-byte blocktxn: block hash, then the count.
    try expectNoHugeAlloc("blocktxn", &cat(&.{ &ZERO32, &MAX_COUNT }));
}

test "sec_p2p_decode: C1 reconcildiff with MAX_SIZE counts does not allocate by count" {
    try expectNoHugeAlloc("reconcildiff", &cat(&.{ &[_]u8{0x01}, &MAX_COUNT }));
    try expectNoHugeAlloc("reconcildiff", &cat(&.{ &[_]u8{ 0x01, 0x00 }, &MAX_COUNT }));
}

test "sec_p2p_decode: C1 3-byte inv claiming MAX_INV_SZ entries does not allocate 1.8 MB" {
    // FD 50 C3 = 50,000 = MAX_INV_SZ, then no entries at all.
    try expectNoHugeAlloc("inv", &[_]u8{ 0xFD, 0x50, 0xC3 });
}

test "sec_p2p_decode: C1 a well-formed tx still decodes under the bounded allocator" {
    // Negative control: the remaining-bytes cap must not reject honest input.
    // 1 input (5-byte scriptSig), 2 outputs, locktime.
    const out = comptime cat(&.{ &[_]u8{0} ** 8, &[_]u8{ 0x01, 0x51 } });
    const raw = cat(&.{ &VERSION1, &[_]u8{0x01}, &INPUT_SIG5, &[_]u8{0x02}, &out, &out, &ZERO4 });
    var ba = BoundedAllocator{ .inner = testing.allocator };
    const a = ba.allocator();
    const msg = try p2p.decodePayload("tx", &raw, a);
    defer p2p.freeDecodedMessage(a, msg);
    try testing.expectEqual(@as(usize, 1), msg.tx.inputs.len);
    try testing.expectEqual(@as(usize, 2), msg.tx.outputs.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5 }, msg.tx.inputs[0].script_sig);
}

// --- C4 decoder side: truncation must free what was decoded --------------

fn expectDecodeFailsCleanly(command: []const u8, payload: []const u8) !void {
    // testing.allocator reports any leak and fails the test by name.
    if (p2p.decodePayload(command, payload, testing.allocator)) |msg| {
        p2p.freeDecodedMessage(testing.allocator, msg);
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "sec_p2p_decode: C4 tx truncated in the second input frees the first scriptSig" {
    try expectDecodeFailsCleanly("tx", &cat(&.{ &VERSION1, &[_]u8{0x02}, &INPUT_SIG5, INPUT_SIG5[0..20] }));
}

test "sec_p2p_decode: C4 tx truncated in the outputs frees inputs and earlier outputs" {
    const out = comptime cat(&.{ &[_]u8{0} ** 8, &[_]u8{ 0x02, 0x51, 0x52 } });
    try expectDecodeFailsCleanly("tx", &cat(&.{ &VERSION1, &[_]u8{0x01}, &INPUT_SIG5, &[_]u8{0x02}, &out, out[0..9] }));
}

test "sec_p2p_decode: C4 segwit tx truncated in a witness stack frees the stack" {
    // 1 input, 1 output, witness: 2 items, the first 3 bytes, the second cut.
    const out = comptime cat(&.{ &[_]u8{0} ** 8, &[_]u8{ 0x01, 0x51 } });
    try expectDecodeFailsCleanly("tx", &cat(&.{
        &VERSION1,                              &[_]u8{ 0x00, 0x01, 0x01 }, &INPUT_SIG5, &[_]u8{0x01}, &out,
        &[_]u8{ 0x02, 0x03, 9, 9, 9, 0x04, 9 },
    }));
}

test "sec_p2p_decode: C4 segwit tx with an all-empty witness frees everything" {
    // SuperfluousWitnessRecord is raised after every input and output was
    // duped; it must not leak them.
    const out = comptime cat(&.{ &[_]u8{0} ** 8, &[_]u8{ 0x01, 0x51 } });
    try expectDecodeFailsCleanly("tx", &cat(&.{
        &VERSION1, &[_]u8{ 0x00, 0x01, 0x01 }, &INPUT_SIG5, &[_]u8{0x01}, &out, &[_]u8{0x00}, &ZERO4,
    }));
}

/// A complete 1-in/1-out legacy tx with a 5-byte scriptSig.
const TX_OK = cat(&.{ &VERSION1, &[_]u8{0x01}, &INPUT_SIG5, &[_]u8{0x01}, &[_]u8{0} ** 8, &[_]u8{ 0x01, 0x51 }, &ZERO4 });

test "sec_p2p_decode: C4 block truncated in the second tx frees the first tx" {
    try expectDecodeFailsCleanly("block", &cat(&.{ &HEADER80, &[_]u8{0x02}, &TX_OK, TX_OK[0..30] }));
}

test "sec_p2p_decode: C4 blocktxn truncated in the second tx frees the first tx" {
    try expectDecodeFailsCleanly("blocktxn", &cat(&.{ &ZERO32, &[_]u8{0x02}, &TX_OK, TX_OK[0..30] }));
}

test "sec_p2p_decode: C4 cmpctblock truncated in a prefilled tx frees the earlier one" {
    // header, nonce, 0 short ids, 2 prefilled: (idx 0, TX_OK), (idx 0, cut).
    try expectDecodeFailsCleanly("cmpctblock", &cat(&.{
        &HEADER80, &[_]u8{0} ** 8, &[_]u8{ 0x00, 0x02, 0x00 }, &TX_OK, &[_]u8{0x00}, TX_OK[0..30],
    }));
}

test "sec_p2p_decode: C4 reconcildiff truncated in the extra ids frees the missing ids" {
    try expectDecodeFailsCleanly("reconcildiff", &[_]u8{ 0x01, 0x01, 1, 2, 3, 4, 0x01, 1, 2 });
}

test "sec_p2p_decode: C4 headers with a malformed tx_count frees the array" {
    // Non-canonical CompactSize (FD 00 00) fails after one header is read.
    try expectDecodeFailsCleanly("headers", &cat(&.{ &[_]u8{0x01}, &HEADER80, &[_]u8{ 0xFD, 0x00, 0x00 } }));
}

test "sec_p2p_decode: C4 truncated inv / getheaders / addr / cfheaders / cfcheckpt free the array" {
    const inv1 = comptime cat(&.{ &[_]u8{ 0x01, 0, 0, 0 }, &ZERO32 });
    try expectDecodeFailsCleanly("inv", &cat(&.{ &[_]u8{0x01}, inv1[0..20] }));
    try expectDecodeFailsCleanly("getdata", &cat(&.{ &[_]u8{0x01}, inv1[0..20] }));
    try expectDecodeFailsCleanly("notfound", &cat(&.{ &[_]u8{0x01}, inv1[0..20] }));
    // getheaders: version, 1 locator, then no hash_stop.
    try expectDecodeFailsCleanly("getheaders", &cat(&.{ &[_]u8{ 0x80, 0x11, 0x01, 0x00 }, &[_]u8{0x01}, &ZERO32 }));
    try expectDecodeFailsCleanly("getblocks", &cat(&.{ &[_]u8{ 0x80, 0x11, 0x01, 0x00 }, &[_]u8{0x01}, &ZERO32 }));
    try expectDecodeFailsCleanly("addr", &cat(&.{ &[_]u8{0x01}, &[_]u8{0} ** 20 }));
    try expectDecodeFailsCleanly("cfheaders", &cat(&.{ &[_]u8{0x00}, &ZERO32, &ZERO32, &[_]u8{0x01}, &[_]u8{0} ** 10 }));
    try expectDecodeFailsCleanly("cfcheckpt", &cat(&.{ &[_]u8{0x00}, &ZERO32, &[_]u8{0x01}, &[_]u8{0} ** 10 }));
}

test "sec_p2p_decode: C4 version truncated after the user agent frees it" {
    // version..nonce (80 bytes), user agent "/x/", then no start_height.
    try expectDecodeFailsCleanly("version", &cat(&.{ &[_]u8{0} ** 80, &[_]u8{ 0x03, '/', 'x', '/' } }));
}

// --- C4 handler side and C5: PeerManager fixtures --------------------------

fn stubPeer(params: *const consensus.NetworkParams, allocator: std.mem.Allocator) peer_mod.Peer {
    return .{
        .stream = .{ .handle = -1 },
        .address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0),
        .state = .handshake_complete,
        .direction = .outbound,
        .version_info = null,
        .services = p2p.NODE_NETWORK | p2p.NODE_WITNESS,
        .last_ping_time = 0,
        .last_pong_time = 0,
        .last_ping_nonce = 0,
        .last_message_time = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .start_height = 100,
        .network_params = params,
        .allocator = allocator,
        .recv_buffer = std.ArrayList(u8).init(allocator),
        .is_witness_capable = true,
        .is_headers_first = true,
        .ban_score = 0,
        .should_ban = false,
        .conn_type = .outbound_full_relay,
        .last_block_time = 0,
        .last_tx_time = 0,
        .min_ping_time = std.math.maxInt(i64),
        .relay_txs = false,
        .is_protected = false,
        .connect_time = 0,
        .advertise_node_bloom = false,
        .transport_version = .v1,
    };
}

test "sec_p2p_decode: C4 post-handshake version, reqrecon and sketch are freed by the handler" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = peer_mod.PeerManager.init(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();

    // Each payload is decoded exactly as the wire path does, so the handler
    // receives the same owned copies the live node does.
    var ver_raw = cat(&.{ &[_]u8{0} ** 80, &[_]u8{ 0x03, '/', 'x', '/' }, &[_]u8{0} ** 4, &[_]u8{0x01} });
    try pm.ingestMessage(&peer, try p2p.decodePayload("version", &ver_raw, a));
    try pm.ingestMessage(&peer, try p2p.decodePayload("reqrecon", &[_]u8{ 1, 0, 1, 0, 0x03, 7, 7, 7 }, a));
    try pm.ingestMessage(&peer, try p2p.decodePayload("sketch", &[_]u8{ 0x03, 7, 7, 7 }, a));
    // Core ignores a redundant version (net_processing.cpp "redundant
    // version message"): no disconnect, no score.
    try testing.expectEqual(@as(u32, 0), peer.ban_score);
    try testing.expect(!peer.should_ban);
}

fn cloneBlock(a: std.mem.Allocator, block: *const types.Block) !types.Block {
    var w = serialize.Writer.init(a);
    defer w.deinit();
    try serialize.writeBlock(&w, block);
    var r = serialize.Reader{ .data = w.getWritten() };
    return serialize.readBlock(&r, a);
}

test "sec_p2p_decode: C5 a re-sent body for a buffered hash does not leak the old copy" {
    const a = testing.allocator;
    const params = &consensus.REGTEST;
    var pm = peer_mod.PeerManager.init(a, params);
    defer pm.deinit();
    var peer = stubPeer(params, a);
    defer peer.recv_buffer.deinit();
    // Buffer-only: no chain state, so drain never tries to connect.
    pm.chain_state = null;

    const first = try hb.mineCoinbaseBlock(a, [_]u8{0xBB} ** 32, 11, params.genesis_header.timestamp + 600, params.genesis_header.bits, params);
    const second = try cloneBlock(a, &first);
    const h = crypto.computeBlockHash(&first.header);
    try pm.expected_blocks.append(h);
    pm.connect_cursor = 0;

    try pm.ingestBlockMessage(&peer, first);
    try testing.expectEqual(@as(u32, 1), pm.block_buffer.count());
    // Same hash again: the buffer still holds one body, and the displaced
    // copy is freed (testing.allocator fails the test on a leak otherwise).
    try pm.ingestBlockMessage(&peer, second);
    try testing.expectEqual(@as(u32, 1), pm.block_buffer.count());
    try testing.expect(pm.block_buffer.contains(h));
}
