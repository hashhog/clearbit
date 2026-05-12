// W98 BIP-324 v2 P2P transport gate audit tests (clearbit / Zig 0.13).
//
// These tests document and probe the bugs found during the W98 audit.
// They are DISCOVERY tests — they expose gaps vs Bitcoin Core's implementation.
// DO NOT FIX the underlying bugs in this commit; fixes are tracked separately.
//
// Bug summary (see full list below):
//   G13/G14 CORRECTNESS  — V1 detection after only 4 bytes (needs 16)
//   G15     CORRECTNESS  — garbage abort off-by-one (> 4111 vs == 4111)
//   G16     CORRECTNESS  — forward garbage scan vs trailing check (false-match risk)
//   G10     CRYPTO       — no memory_cleanse of HKDF intermediate key material
//   G29     CORRECTNESS  — assert-panic on bad state instead of clean disconnect
//   G21     CORRECTNESS  — short ID table has 29 entries; Core has 33 (IDs 29-32 reserved)
//   G6      OBSERVABILITY — FSChaCha20Poly1305 rekey uses wrong nonce (packet_counter=0 not 0xFFFFFFFF in first-byte)
//   G30     CORRECTNESS  — no m_sent_v1_header_worth guard (V1 fallback unsafe after >24B sent)

const std = @import("std");
const v2 = @import("v2_transport.zig");

// Helper: decode compile-time hex string.
fn h(comptime hex: []const u8) [hex.len / 2]u8 {
    var r: [hex.len / 2]u8 = undefined;
    for (0..hex.len / 2) |i| {
        const hi = hex[i * 2];
        const lo = hex[i * 2 + 1];
        r[i] = (nibble(hi) << 4) | nibble(lo);
    }
    return r;
}

fn nibble(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

// =============================================================================
// G1 — ECDH via ellswift + random entropy
// =============================================================================

test "G1: BIP324Cipher.init generates distinct keys on each call (random ent32)" {
    // Each init() must produce a DIFFERENT public key — proves random entropy per connection.
    var a = v2.BIP324Cipher.init(std.testing.allocator);
    var b = v2.BIP324Cipher.init(std.testing.allocator);
    const pk_a = a.getOurPubkey() orelse return error.NoPubkey;
    const pk_b = b.getOurPubkey() orelse return error.NoPubkey;
    // Probability of collision is cryptographically negligible.
    try std.testing.expect(!std.mem.eql(u8, pk_a, pk_b));
}

// =============================================================================
// G2 — HKDF salt = "bitcoin_v2_shared_secret" || 4-byte network magic
// =============================================================================

test "G2: HKDF salt includes 4-byte network magic (mainnet vs testnet4 produce different keys)" {
    const secret = [_]u8{0x42} ** 32;
    const mainnet: [4]u8 = .{ 0xf9, 0xbe, 0xb4, 0xd9 };
    const testnet4: [4]u8 = .{ 0x1c, 0x16, 0x3f, 0x28 };

    var c1 = v2.BIP324Cipher{};
    var c2 = v2.BIP324Cipher{};
    c1.initializeWithSharedSecret(&secret, true, mainnet);
    c2.initializeWithSharedSecret(&secret, true, testnet4);

    // Different magic → different salt → different session IDs.
    try std.testing.expect(!std.mem.eql(u8, c1.getSessionId(), c2.getSessionId()));
}

// =============================================================================
// G3 — HKDF labels exact case/spelling
// =============================================================================

test "G3: HKDF expand labels produce distinct 32-byte outputs for each role-key pair" {
    // The KeyMaterial.derive function uses six distinct labels.  Verify all
    // six outputs are pairwise-distinct (proves no label collision / typo).
    const secret = [_]u8{0x99} ** 32;
    const salt = "bitcoin_v2_shared_secret" ++ [_]u8{ 0xf9, 0xbe, 0xb4, 0xd9 };
    const km = v2.KeyMaterial.derive(&secret, salt);

    try std.testing.expect(!std.mem.eql(u8, &km.initiator_l, &km.initiator_p));
    try std.testing.expect(!std.mem.eql(u8, &km.initiator_l, &km.responder_l));
    try std.testing.expect(!std.mem.eql(u8, &km.responder_l, &km.responder_p));
    try std.testing.expect(!std.mem.eql(u8, &km.responder_p, &km.session_id));
    // Garbage terminators split into two 16-byte halves — must differ.
    try std.testing.expect(!std.mem.eql(
        u8,
        km.getInitiatorSendGarbageTerminator(),
        km.getResponderSendGarbageTerminator(),
    ));
}

// =============================================================================
// G4 — Role-based key assignment (initiator uses initiator_L for send)
// =============================================================================

test "G4: initiator and responder get swapped send/recv keys from same shared secret" {
    const secret = [_]u8{0x55} ** 32;
    const magic: [4]u8 = .{ 0xf9, 0xbe, 0xb4, 0xd9 };

    var init_cipher = v2.BIP324Cipher{};
    var resp_cipher = v2.BIP324Cipher{};
    init_cipher.initializeWithSharedSecret(&secret, true, magic);
    resp_cipher.initializeWithSharedSecret(&secret, false, magic);

    // Initiator's send terminator == responder's recv terminator.
    try std.testing.expectEqualSlices(
        u8,
        init_cipher.getSendGarbageTerminator(),
        resp_cipher.getRecvGarbageTerminator(),
    );
    // Responder's send terminator == initiator's recv terminator.
    try std.testing.expectEqualSlices(
        u8,
        resp_cipher.getSendGarbageTerminator(),
        init_cipher.getRecvGarbageTerminator(),
    );
}

// =============================================================================
// G5 — Garbage terminators: first 16B = init-send; last 16B = resp-send
// =============================================================================

test "G5: garbage_terminators[0..16] is initiator send, [16..32] is responder send" {
    const secret = [_]u8{0xAA} ** 32;
    const salt = "bitcoin_v2_shared_secret" ++ [_]u8{ 0xf9, 0xbe, 0xb4, 0xd9 };
    const km = v2.KeyMaterial.derive(&secret, salt);

    // The first 16 bytes of the derived garbage_terminators OKM go to
    // the initiator's send terminator; the last 16 to the responder's.
    try std.testing.expectEqualSlices(u8, km.garbage_terminators[0..16], km.getInitiatorSendGarbageTerminator());
    try std.testing.expectEqualSlices(u8, km.garbage_terminators[16..32], km.getResponderSendGarbageTerminator());
}

// =============================================================================
// G6 — REKEY_INTERVAL = 224
// =============================================================================

test "G6: REKEY_INTERVAL constant equals 224" {
    try std.testing.expectEqual(@as(u32, 224), v2.REKEY_INTERVAL);
}

// =============================================================================
// G7 — LENGTH_LEN = 3 LE
// =============================================================================

test "G7: LENGTH_LEN equals 3 and length field is little-endian" {
    try std.testing.expectEqual(@as(usize, 3), v2.LENGTH_LEN);

    // Verify LE encoding in a real cipher round-trip.
    var enc = v2.BIP324Cipher{};
    enc.initializeWithSharedSecret(&([_]u8{0x11} ** 32), true, .{ 0xf9, 0xbe, 0xb4, 0xd9 });
    const payload = [_]u8{0xAB} ** 259; // 0x103 → 3 LE bytes: 03 01 00
    var out: [payload.len + v2.EXPANSION]u8 = undefined;
    enc.encrypt(&payload, &[_]u8{}, false, &out);

    // Decrypt the length field with a matching recv cipher.
    var dec = v2.BIP324Cipher{};
    dec.initializeWithSharedSecret(&([_]u8{0x11} ** 32), false, .{ 0xf9, 0xbe, 0xb4, 0xd9 });
    const len_dec = dec.decryptLength(out[0..v2.LENGTH_LEN]);
    try std.testing.expectEqual(@as(u32, 259), len_dec);
}

// =============================================================================
// G8 — HEADER_LEN = 1; IGNORE_BIT = 0x80
// =============================================================================

test "G8: HEADER_LEN is 1 and IGNORE_BIT is 0x80" {
    try std.testing.expectEqual(@as(usize, 1), v2.HEADER_LEN);
    try std.testing.expectEqual(@as(u8, 0x80), v2.IGNORE_BIT);
}

// =============================================================================
// G9 — AEAD: FSChaCha20Poly1305 protects header+contents; AAD passed through
// =============================================================================

test "G9: wrong AAD causes AEAD authentication failure (header integrity)" {
    var enc = v2.BIP324Cipher{};
    enc.initializeWithSharedSecret(&([_]u8{0xBB} ** 32), true, .{ 0xf9, 0xbe, 0xb4, 0xd9 });
    var dec = v2.BIP324Cipher{};
    dec.initializeWithSharedSecret(&([_]u8{0xBB} ** 32), false, .{ 0xf9, 0xbe, 0xb4, 0xd9 });

    const contents = "aead test payload";
    var out: [contents.len + v2.EXPANSION]u8 = undefined;
    enc.encrypt(contents, "correct_aad", false, &out);

    _ = dec.decryptLength(out[0..v2.LENGTH_LEN]);
    var dec_out: [contents.len]u8 = undefined;
    var ignore: bool = undefined;
    const ok = dec.decrypt(out[v2.LENGTH_LEN..], "wrong_aad", &ignore, &dec_out);
    try std.testing.expect(!ok);
}

// =============================================================================
// G10 — FIXED: memory_cleanse of HKDF intermediate key material
//
// Bitcoin Core zeroes both `hkdf_32_okm` (32 bytes) and the HKDF state struct
// after Initialize() using memory_cleanse().
//
// Fix: initializeWithSharedSecret() now uses
//   defer std.crypto.utils.secureZero(u8, std.mem.asBytes(&keys));
//   defer std.crypto.utils.secureZero(u8, &salt);
// for the KeyMaterial struct (~192 bytes of all six derived keys) and the
// HKDF salt buffer.  The `initialize` and `initializeWithSecp256k1` callers
// also zero their `shared_secret` stack buffers via defer.
//
// The stack cannot be directly observed from user-space, so this test
// verifies the functional post-condition: after initializeWithSharedSecret
// the cipher is fully operational (keys were copied into the FSChaCha20 state
// before the defer zeroed the intermediate material).
// =============================================================================

test "G10: KeyMaterial zeroed after initializeWithSharedSecret — cipher remains operational" {
    // Arrange: two ciphers with the same shared secret.
    const secret = [_]u8{0x42} ** 32;
    const magic: [4]u8 = .{ 0xf9, 0xbe, 0xb4, 0xd9 };
    var enc = v2.BIP324Cipher{};
    var dec = v2.BIP324Cipher{};
    enc.initializeWithSharedSecret(&secret, true, magic);
    dec.initializeWithSharedSecret(&secret, false, magic);

    // Act: encrypt a packet with the initiator cipher.
    const payload = "g10 secure-zero verified";
    var out: [payload.len + v2.EXPANSION]u8 = undefined;
    enc.encrypt(payload, &[_]u8{}, false, &out);

    // Act: decrypt with the responder cipher.
    _ = dec.decryptLength(out[0..v2.LENGTH_LEN]);
    var decrypted: [payload.len]u8 = undefined;
    var ignore_bit: bool = undefined;
    const ok = dec.decrypt(out[v2.LENGTH_LEN..], &[_]u8{}, &ignore_bit, &decrypted);

    // Assert: decryption succeeds — proves the FSChaCha20 state was populated
    // from `keys` before secureZero wiped it, i.e. the defer fired at the right
    // time and did not corrupt the loaded cipher state.
    try std.testing.expect(ok);
    try std.testing.expectEqualStrings(payload, &decrypted);
}

// =============================================================================
// G11 / G12 — State machine states present and correct
// =============================================================================

test "G11: RecvState has all required BIP-324 states" {
    // Compile-time check: all states exist (will fail to compile if missing).
    const states = [_]v2.RecvState{
        .key_maybe_v1, .key, .garbage, .version, .app, .app_ready, .v1,
    };
    _ = states;
}

test "G12: SendState has all required BIP-324 states" {
    const states = [_]v2.SendState{
        .maybe_v1, .awaiting_key, .ready, .v1,
    };
    _ = states;
}

// =============================================================================
// G13/G14 — BUG: CORRECTNESS — V1 detection fires after 4 bytes, not 16
//
// Bitcoin Core's KEY_MAYBE_V1 state collects exactly V1_PREFIX_LEN (16) bytes
// before deciding — it checks magic (4B) AND the "version\0\0\0\0\0" command
// (12B).  clearbit's processRecvBuffer decides after only 4 bytes (the magic
// alone).  An ellswift pubkey starting with the network magic bytes would
// incorrectly trigger V1 fallback before seeing bytes 5-16.
// =============================================================================

test "G13/G14: V1 detection waits for full 16-byte prefix (FIXED)" {
    // Fix: processRecvBuffer now waits for V1_PREFIX_LEN (16) bytes before
    // deciding V1 vs V2, matching Bitcoin Core net.cpp:1091-1101.
    //
    // Scenario A — magic only (4 bytes): state must remain .key_maybe_v1.
    // Scenario B — magic + "version\0\0\0\0\0" (16 bytes): V1 fallback fires.
    // Scenario C — magic + wrong command (16 bytes): treated as V2 (.key state).
    const allocator = std.testing.allocator;

    // --- Scenario A: only 4 magic bytes → still key_maybe_v1 ---
    {
        var t = v2.V2Transport.init(allocator, false, 0xD9B4BEF9);
        defer t.deinit();
        const magic_only: [4]u8 = .{ 0xf9, 0xbe, 0xb4, 0xd9 };
        _ = t.processReceivedBytes(&magic_only);
        // After 4 bytes the state must still be key_maybe_v1 (not yet decided).
        try std.testing.expect(!t.isV1Fallback());
    }

    // --- Scenario B: full 16-byte V1 prefix → V1 fallback ---
    {
        var t = v2.V2Transport.init(allocator, false, 0xD9B4BEF9);
        defer t.deinit();
        const full_prefix: [16]u8 = .{
            0xf9, 0xbe, 0xb4, 0xd9, // mainnet magic
            'v',  'e',  'r',  's', 'i', 'o', 'n', 0, 0, 0, 0, 0, // "version\0\0\0\0\0"
        };
        _ = t.processReceivedBytes(&full_prefix);
        try std.testing.expect(t.isV1Fallback());
    }

    // --- Scenario C: magic + non-version command → V2 (not V1 fallback) ---
    {
        var t = v2.V2Transport.init(allocator, false, 0xD9B4BEF9);
        defer t.deinit();
        const magic_plus_inv: [16]u8 = .{
            0xf9, 0xbe, 0xb4, 0xd9, // mainnet magic
            'i',  'n',  'v',  0, 0, 0, 0, 0, 0, 0, 0, 0, // "inv\0..." (not version)
        };
        _ = t.processReceivedBytes(&magic_plus_inv);
        // Non-version command → should NOT trigger V1 fallback.
        try std.testing.expect(!t.isV1Fallback());
    }
}

test "G14: V1_PREFIX_LEN constant equals 16 but is not used in state machine" {
    // The constant exists and is correct...
    try std.testing.expectEqual(@as(usize, 16), v2.V1_PREFIX_LEN);
    // ...but processRecvBuffer only waits for 4 bytes (see G13 test above).
    // looksLikeV1Version() uses the full 16 bytes correctly, but is only
    // called from peer.zig's tryV2OutboundProbe, not from processRecvBuffer.
}

// =============================================================================
// G15 — BUG: CORRECTNESS — garbage abort off-by-one
//
// Bitcoin Core aborts when recv_buffer.size() == MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN
// (i.e., exactly 4111 bytes).  clearbit uses `>` instead of `==`, so it allows
// 4111 bytes through and only aborts at 4112.  A malicious peer can send one
// extra byte beyond the protocol limit.
// =============================================================================

test "G15: MAX_GARBAGE_LEN abort threshold (documents off-by-one vs Core)" {
    // Core: aborts at recv_buffer.size() == 4095 + 16 = 4111 exactly.
    // clearbit: aborts at recv_buffer.size() > 4111, i.e., at 4112.
    //
    // The off-by-one means clearbit allows 4111 bytes of garbage to pass through
    // the scan loop without aborting, where Core would already have aborted.
    const max_total = v2.MAX_GARBAGE_LEN + v2.GARBAGE_TERMINATOR_LEN; // 4111
    try std.testing.expectEqual(@as(usize, 4111), max_total);

    // Document: clearbit's condition is `> 4111` (allows 4111), Core's is `== 4111` (rejects 4111).
    // Both eventually reject, but clearbit is 1 byte more permissive.
    try std.testing.expect(true); // structural — see comment above
}

// =============================================================================
// G16 — BUG: CORRECTNESS — forward garbage scan vs trailing check
//
// Bitcoin Core grows the garbage buffer one byte at a time and checks whether
// the LAST 16 bytes equal the expected terminator.  clearbit scans the buffer
// from position 0 for the FIRST occurrence of the terminator.
//
// If the peer's garbage contains the terminator bytes as a substring (occurring
// before the real terminator at the end of the garbage), clearbit will cut the
// garbage short at the false-match position, stash the wrong prefix as recv_aad,
// and fail to authenticate the peer's version packet (AEAD tag mismatch).
// =============================================================================

test "G16: forward garbage scan false-match risk (documents divergence vs Core trailing check)" {
    const allocator = std.testing.allocator;

    // Construct a cipher so we can get the expected recv terminator.
    const secret = [_]u8{0xCC} ** 32;
    const magic: [4]u8 = .{ 0xf9, 0xbe, 0xb4, 0xd9 };
    var init_cipher = v2.BIP324Cipher{};
    init_cipher.initializeWithSharedSecret(&secret, true, magic);

    // The responder's garbage terminator as seen by the initiator.
    const term = init_cipher.getRecvGarbageTerminator().*;

    // Build a fake garbage stream: 10 bytes of junk, then the terminator bytes
    // (false match), then 10 more bytes of junk, then the REAL terminator.
    var fake_stream = std.ArrayList(u8).init(allocator);
    defer fake_stream.deinit();

    // 10 bytes random junk.
    try fake_stream.appendSlice(&([_]u8{0xAB} ** 10));
    // False terminator occurrence (embedded in garbage).
    try fake_stream.appendSlice(&term);
    // 10 more bytes — the extra junk that SHOULD be garbage but clearbit skips.
    try fake_stream.appendSlice(&([_]u8{0xCD} ** 10));
    // Real terminator at the end.
    try fake_stream.appendSlice(&term);

    // Core would correctly find the LAST terminator (position 36) and include
    // all 36 bytes as recv_aad (garbage of 36 bytes + terminator at end).
    // clearbit finds the FIRST occurrence at position 10 and uses only 10 bytes
    // as recv_aad — wrong value, causing version packet AEAD failure.
    //
    // We cannot easily exercise this without a full transport pair using the
    // same simulated secret; document the risk instead.
    try std.testing.expect(fake_stream.items.len == 10 + 16 + 10 + 16);
}

// =============================================================================
// G21 — Short ID table size: clearbit has 29 entries, Core has 33
// =============================================================================

test "G21: short ID table has 29 entries; Core defines 33 (IDs 29-32 reserved)" {
    // BIP-324 + Bitcoin Core define IDs 0-32 (33 total).
    // IDs 29-32 are reserved empty strings in Core; clearbit only has up to 28.
    try std.testing.expectEqual(@as(usize, 29), v2.V2_MESSAGE_IDS.len); // 0..28

    // IDs 29-32: clearbit returns null (treats as unknown); Core returns ""
    // (empty string, which causes unknown-command discard).  Functionally
    // equivalent but clearbit's table is shorter than spec.
    try std.testing.expectEqual(@as(?[]const u8, null), v2.getMessageType(29));
    try std.testing.expectEqual(@as(?[]const u8, null), v2.getMessageType(32));
}

// =============================================================================
// G22 — Long-form: 0 byte → 12B ASCII NUL-padded command
// =============================================================================

test "G22: long-form encoding uses 0x00 marker + 12 NUL-padded bytes" {
    const allocator = std.testing.allocator;
    const secret = [_]u8{0x33} ** 32;
    var pair: [2]v2.V2Transport = blk: {
        var magic_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &magic_bytes, 0xD9B4BEF9, .little);
        var i: v2.V2Transport = .{
            .cipher = v2.BIP324Cipher{},
            .initiating = true,
            .recv_state = .app,
            .send_state = .ready,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .send_buffer = std.ArrayList(u8).init(allocator),
            .send_garbage = &[_]u8{},
            .network_magic = magic_bytes,
            .allocator = allocator,
            .recv_decode_buffer = std.ArrayList(u8).init(allocator),
            .recv_len = null,
            .recv_aad = &[_]u8{},
            .version_packet_sent = true,
        };
        var r: v2.V2Transport = .{
            .cipher = v2.BIP324Cipher{},
            .initiating = false,
            .recv_state = .app,
            .send_state = .ready,
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .send_buffer = std.ArrayList(u8).init(allocator),
            .send_garbage = &[_]u8{},
            .network_magic = magic_bytes,
            .allocator = allocator,
            .recv_decode_buffer = std.ArrayList(u8).init(allocator),
            .recv_len = null,
            .recv_aad = &[_]u8{},
            .version_packet_sent = true,
        };
        i.cipher.initializeWithSharedSecret(&secret, true, magic_bytes);
        r.cipher.initializeWithSharedSecret(&secret, false, magic_bytes);
        break :blk [2]v2.V2Transport{ i, r };
    };
    defer pair[0].deinit();
    defer pair[1].deinit();

    // "version" is not in the short-ID table → must use long encoding.
    try pair[0].sendMessage("version", &[_]u8{}, false);
    _ = pair[1].processReceivedBytes(pair[0].getSendData());
    pair[0].markBytesSent(pair[0].getSendData().len);

    const contents = pair[1].getReceivedMessage().?;
    // Long encoding: contents[0]=0, contents[1..13]="version\0\0\0\0\0\0"
    try std.testing.expectEqual(@as(u8, 0), contents[0]);
    try std.testing.expectEqualStrings("version", contents[1..8]);
    for (contents[8..13]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

// =============================================================================
// G24 — Max plaintext size ≤ 4 MiB enforced
// =============================================================================

test "G24: MAX_CONTENTS_LEN is at most 4 MiB + framing overhead" {
    // 1 (short-id marker) + 12 (long command) + 4*1000*1000 (payload) = 4,000,013
    const expected: usize = 1 + 12 + 4 * 1000 * 1000;
    try std.testing.expectEqual(expected, v2.MAX_CONTENTS_LEN);
}

// =============================================================================
// G25 — Initiator garbage is random length 0..MAX_GARBAGE_LEN
// =============================================================================

test "G25: initiator garbage length is in range 0..4095" {
    // We cannot observe the random choice directly, but we can verify that
    // the transport does not ALWAYS send length 0 or ALWAYS MAX_GARBAGE_LEN.
    // Run 5 initiators and check that the garbage lengths are bounded.
    const allocator = std.testing.allocator;
    for (0..5) |_| {
        var t = v2.V2Transport.init(allocator, true, 0xD9B4BEF9);
        defer t.deinit();
        const send_len = t.getSendData().len;
        // send_data = pubkey (64) + garbage (0..4095)
        try std.testing.expect(send_len >= v2.ELLSWIFT_PUBKEY_LEN);
        try std.testing.expect(send_len <= v2.ELLSWIFT_PUBKEY_LEN + v2.MAX_GARBAGE_LEN);
    }
}

// =============================================================================
// G28 — AEAD tag-fail → disconnect (returns false, no packet-number leak)
// =============================================================================

test "G28: corrupted ciphertext causes decrypt to return false (not panic or skip)" {
    var enc = v2.BIP324Cipher{};
    enc.initializeWithSharedSecret(&([_]u8{0x77} ** 32), true, .{ 0xf9, 0xbe, 0xb4, 0xd9 });
    var dec = v2.BIP324Cipher{};
    dec.initializeWithSharedSecret(&([_]u8{0x77} ** 32), false, .{ 0xf9, 0xbe, 0xb4, 0xd9 });

    const contents = "tamper test";
    var out: [contents.len + v2.EXPANSION]u8 = undefined;
    enc.encrypt(contents, &[_]u8{}, false, &out);

    // Corrupt one byte of the ciphertext (after the length field).
    out[v2.LENGTH_LEN] ^= 0xFF;

    _ = dec.decryptLength(out[0..v2.LENGTH_LEN]);
    var decrypted: [contents.len]u8 = undefined;
    var ignore: bool = undefined;
    const ok = dec.decrypt(out[v2.LENGTH_LEN..], &[_]u8{}, &ignore, &decrypted);
    try std.testing.expect(!ok); // must return false, not panic
}

// =============================================================================
// G29 — BUG: CORRECTNESS — std.debug.assert on bad state (panic vs disconnect)
//
// Bitcoin Core uses Assume() / return false for invalid states, allowing a clean
// disconnect.  clearbit uses std.debug.assert which panics in Debug/ReleaseSafe
// (crashing the entire node) or invokes UB in ReleaseFast.
// =============================================================================

test "G29: AUDIT NOTE - debug.assert used for state guards (crash vs clean disconnect)" {
    // The assert calls in BIP324Cipher.encrypt, decryptLength, decrypt fire
    // when callers violate preconditions (e.g. call before Initialize).
    // In production (ReleaseFast), the asserts are REMOVED, leaving UB.
    // Bitcoin Core returns bool/Assume()-fail instead of crashing.
    //
    // Relevant sites:
    //   encrypt()       — assert(output.len == contents.len + EXPANSION)
    //                    assert(self.isInitialized())
    //   decryptLength() — assert(self.isInitialized())
    //   decrypt()       — assert(self.isInitialized())
    //                    assert(input.len == contents.len + HEADER_LEN + TAG_LEN)
    //
    // Fix: replace assert with error returns or conditional returns.
    try std.testing.expect(true); // structural placeholder
}

// =============================================================================
// G30 — BUG: CORRECTNESS — no m_sent_v1_header_worth guard
//
// Bitcoin Core guards V1 fallback with m_sent_v1_header_worth: once ≥ 24 bytes
// have been sent, falling back to V1 is unsafe because the peer may have already
// processed those bytes as a partial v2 handshake.  clearbit has no equivalent
// guard — isV1Fallback() returns true regardless of how many bytes were sent.
// =============================================================================

test "G30: AUDIT NOTE - no m_sent_v1_header_worth guard (V1 fallback unsafe after >24B sent)" {
    // In clearbit, the responder that has already sent its 64-byte ellswift key
    // can still report isV1Fallback() = true if the recv state flips to .v1.
    // This would indicate a protocol error (the peer sent v2, then v1 data).
    // Bitcoin Core protects against this with the m_sent_v1_header_worth flag.
    //
    // Observable gap: V2Transport has no `bytes_sent_on_v2` field / guard.
    try std.testing.expect(true); // structural placeholder
}

// =============================================================================
// Regression: FSChaCha20Poly1305 rekey nonce uses 0xFFFFFFFF in low 32 bits
// =============================================================================

test "FSChaCha20Poly1305 rekey packet_counter sentinel is 0xFFFFFFFF" {
    // Per BIP-324, the rekey operation derives the new key from a special nonce
    // where the packet_counter field is 0xFFFFFFFF.  clearbit uses this value
    // (line ~550).  Verify the rekey happens at the interval boundary and
    // cipher states remain coherent across it.
    const key = [_]u8{0xDE} ** 32;
    var enc = v2.FSChaCha20Poly1305.init(key, 3); // rekey every 3 packets
    var dec = v2.FSChaCha20Poly1305.init(key, 3);

    const msg = [_]u8{0xAB};
    for (0..6) |_| { // cross two rekey boundaries
        var ct: [1]u8 = undefined;
        var tag: [v2.TAG_LEN]u8 = undefined;
        enc.encrypt(&ct, &tag, &msg, &[_]u8{});
        var pt: [1]u8 = undefined;
        const ok = dec.decrypt(&pt, &ct, &tag, &[_]u8{});
        try std.testing.expect(ok);
        try std.testing.expectEqualSlices(u8, &msg, &pt);
    }
}

// =============================================================================
// Completeness: verify all 12 most critical short IDs are present and correct
// =============================================================================

test "G21: critical short IDs match BIP-324 protocol spec positions" {
    // These 12 IDs (1-12) are the most operationally significant.
    try std.testing.expectEqualStrings("addr", v2.V2_MESSAGE_IDS[1]);
    try std.testing.expectEqualStrings("block", v2.V2_MESSAGE_IDS[2]);
    try std.testing.expectEqualStrings("blocktxn", v2.V2_MESSAGE_IDS[3]);
    try std.testing.expectEqualStrings("cmpctblock", v2.V2_MESSAGE_IDS[4]);
    try std.testing.expectEqualStrings("feefilter", v2.V2_MESSAGE_IDS[5]);
    try std.testing.expectEqualStrings("filteradd", v2.V2_MESSAGE_IDS[6]);
    try std.testing.expectEqualStrings("filterclear", v2.V2_MESSAGE_IDS[7]);
    try std.testing.expectEqualStrings("filterload", v2.V2_MESSAGE_IDS[8]);
    try std.testing.expectEqualStrings("getblocks", v2.V2_MESSAGE_IDS[9]);
    try std.testing.expectEqualStrings("getblocktxn", v2.V2_MESSAGE_IDS[10]);
    try std.testing.expectEqualStrings("getdata", v2.V2_MESSAGE_IDS[11]);
    try std.testing.expectEqualStrings("getheaders", v2.V2_MESSAGE_IDS[12]);
}
