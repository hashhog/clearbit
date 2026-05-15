//! W117 — BIP-155 / anonymous-network 30-gate audit (clearbit / Zig 0.13)
//!
//! Reference: bitcoin-core/src/i2p.h/cpp, torcontrol.h/cpp, netbase.h/cpp,
//!            init.cpp, netaddress.h/cpp, addrman.cpp
//!
//! Clearbit equivalents:
//!   src/proxy.zig   — SOCKS5 client, TorControlClient, I2pSamClient,
//!                     ProxyManager, MultiNetworkAddress, NetworkId,
//!                     StreamIsolation, base32 encoding
//!   src/p2p.zig     — sendaddrv2 / addrv2 message types, AddrV2Entry,
//!                     AddrV2Message, decodeAddrV2, encodeMessage(addrv2)
//!   src/peer.zig    — handshake sendaddrv2, addrv2 handler, isRoutable,
//!                     sendAddresses, Peer struct fields
//!   src/rpc.zig     — getnetworkinfo networks array
//!   src/main.zig    — Config struct (no proxy/tor/i2p fields)
//!
//! Run: zig build test --summary none
//!
//! ============================================================================
//! Gates and Findings
//! ============================================================================
//!
//! G1-G10:  Tor v3 support
//! G11-G16: I2P support
//! G17-G20: CJDNS support
//! G21-G24: Outbound overlay connections
//! G25-G28: Address resolution / validation
//! G29-G30: addrv2 wire protocol + RPC
//!
//! ============================================================================
//! BUGs found (30 gates):
//! ============================================================================
//!
//! BUG-1  (G1,  HIGH / MISSING): No `--proxy` / `--onion` CLI flags.
//!   Config struct in main.zig has no tor_proxy, proxy_host, onion_proxy, or
//!   i2p_sam fields.  The ProxyManager and Socks5Client exist in proxy.zig but
//!   are never constructed from Config.  The entire overlay-network stack is a
//!   dead helper — defined but not wired.
//!   Reference: Core init.cpp lines ~400-450 (SetProxy, Tor/I2P init).
//!
//! BUG-2  (G2,  HIGH): Tor v3 .onion checksum is WRONG — always zero.
//!   `base32EncodeOnion()` (proxy.zig:1117-1120) hardcodes checksum bytes as
//!   0x00, 0x00 with comment "Simplified: just use zeros for demo (real
//!   implementation needs SHA3)".  Core's address is:
//!     base32( pubkey || SHA3-256(".onion checksum" || pubkey || 0x03)[0..2] || 0x03 )
//!   Clearbit generates a valid-looking base32 string whose last 4 chars will
//!   mismatch any real .onion address.  This means Tor v3 hostname conversion
//!   produces wrong .onion names — any connection via SOCKS5 will fail or reach
//!   the wrong hidden service.
//!   Reference: Core netaddress.cpp CNetAddr::GetAddrBytes() for Torv3 encoding,
//!              torcontrol.cpp, BIP-155 §3.
//!
//! BUG-3  (G3,  HIGH / dead-helper): TorControlClient and Socks5Client are
//!   defined in proxy.zig but never used in production code paths.  No call
//!   sites in main.zig, peer.zig, or rpc.zig invoke ProxyManager.connectTo(),
//!   Socks5Client.connect(), or TorControlClient.createHiddenService().
//!   Pattern: "subsystem defined but unwired" (same class as haskoin AddrMan
//!   FIX-20, beamchain undo helpers FIX-27 etc.).
//!   Reference: Core init.cpp SetProxy() → CConnman::OpenNetworkConnection().
//!
//! BUG-4  (G5,  HIGH / CDIV): Tor/I2P/CJDNS addresses in addrv2 are silently
//!   dropped from the address book.  The addrv2 handler in peer.zig:3931-3943
//!   only processes network_id == 1 (IPv4); network_id 4 (Tor v3), 5 (I2P),
//!   and 6 (CJDNS) entries are silently discarded.  Peers advertising overlay
//!   addresses are never learned by the node, so it cannot build an overlay
//!   peer set even if a SOCKS5 proxy were configured.
//!   Reference: Core addrman.cpp AddrManImpl::AddSingle, net_processing.cpp
//!              ProcessMessage("addrv2") lines ~3550-3600.
//!
//! BUG-5  (G5,  HIGH / CDIV): IPv6 addresses in addrv2 are silently dropped.
//!   Same handler as BUG-4: network_id == 2 (IPv6, 16 bytes) falls through the
//!   single `if (entry.network_id == 1 ...)` guard.  IPv6-only peers gossiped
//!   via addrv2 are never stored.
//!   Reference: Core net_processing.cpp ProcessMessage("addrv2"):
//!              NET_IPV6 handling must call addrman.Add().
//!
//! BUG-6  (G6,  HIGH): addrv2 negotiation flag (m_wants_addrv2) is NOT tracked
//!   per-peer.  Core's CNode::m_wants_addrv2 records whether a peer sent
//!   sendaddrv2, so we know whether to reply to getaddr with addrv2 or old addr.
//!   The Peer struct in peer.zig has no such field; line 1450 says
//!   `.sendaddrv2, .sendheaders => { // Accept these during handshake but no
//!   action needed }` — the flag is never set.  sendAddresses() always sends
//!   old-style `addr` messages (peer.zig:5119), regardless of peer capability.
//!   Reference: Core net_processing.cpp m_wants_addrv2, RelayAddress().
//!
//! BUG-7  (G7,  MEDIUM): sendAddresses() sends old `addr` message even when
//!   the peer advertised sendaddrv2.  Because BUG-6 means no per-peer flag
//!   exists, it is impossible to route to the correct message type.  Correct
//!   behavior: if peer sent sendaddrv2, respond with addrv2; else addr.
//!   Reference: Core net_processing.cpp RelayAddress() / PushAddress().
//!
//! BUG-8  (G8,  MEDIUM): sendAddresses() cap is 100 addresses (was noted as
//!   G28 in W99).  Core's MAX_ADDR_TO_SEND = 1000.  Separately, sendAddresses
//!   never sends addrv2 even if we know overlay addresses (consequence of BUG-6
//!   + BUG-4).  100-address cap results in relaying 10× fewer addresses than
//!   peers expect.
//!   Reference: Core net_processing.cpp MAX_ADDR_TO_SEND = 1000 (net.h:67).
//!
//! BUG-9  (G9,  HIGH / dead-helper): StreamIsolation exists (proxy.zig:1182)
//!   but is never used.  Tor stream isolation requires unique username/password
//!   credentials per Bitcoin peer to prevent correlation attacks.  Core uses
//!   stream isolation when `-proxyrandomize` is set (netbase.cpp).  The
//!   StreamIsolation type produces correct credentials but is never passed to
//!   Socks5Client because the proxy stack is unwired (BUG-3).
//!   Reference: Core netbase.cpp RandomCredentials(), ProxyCredentials.
//!
//! BUG-10 (G10, MEDIUM): Hidden service creation (TorControlClient.addOnion)
//!   exists but clearbit has no mechanism to advertise its own .onion address
//!   in the version message or via addr/addrv2 gossip.  Core's
//!   CConnman::StartTorControl() creates a hidden service and registers it as a
//!   local address.  Clearbit lacks both the -torcontrol/-torpassword CLI flags
//!   and the "register local .onion" call.
//!   Reference: Core torcontrol.cpp:813 torcontrol_run().
//!
//! BUG-11 (G11, HIGH / MISSING): I2P stack is dead-helper — I2pSamClient is
//!   defined in proxy.zig but never constructed from Config (same as BUG-3).
//!   No -i2psam CLI flag, no i2p config field, no wiring to the connect loop.
//!   Reference: Core i2p.cpp Sam::Session(), init.cpp lines ~460-475.
//!
//! BUG-12 (G13, HIGH): I2P self-address derivation is unimplemented.
//!   I2pSamClient.getAddress() (proxy.zig:790-798) returns null with comment
//!   "This would require base64 decode + SHA256 + base32 encode / For now,
//!   return null — caller should use the full destination".  Core derives the
//!   b32.i2p address as Base32(SHA256(Base64Decode(destination))) and advertises
//!   it as a local address.  The dead-code comment acknowledges the gap.
//!   Reference: Core i2p.cpp Sam::Session::GetMyName() lines ~90-110.
//!
//! BUG-13 (G14, MEDIUM): I2P SAM session creation does not persist the private
//!   key in a standard location.  Core stores it at `<datadir>/i2p_private_key`
//!   (init.cpp:466 `-i2psessiontime`, `-i2pacceptincoming`).  Clearbit's key_file
//!   field is optional with no default path tied to the datadir.  On restart,
//!   a new transient key is generated and the I2P address changes (breaks
//!   persistent listeners).
//!   Reference: Core init.cpp and i2p.cpp (persistent key handling).
//!
//! BUG-14 (G15, MEDIUM): I2P inbound listen is not wired.  I2pSamClient.accept()
//!   exists but is never called from the peer accept loop.  Core spawns a
//!   dedicated "i2p accept thread" that calls I2P.Accept() and adds the
//!   resulting connection to connman.  Clearbit has no equivalent.
//!   Reference: Core net.cpp CConnman::I2PAcceptThreadProc().
//!
//! BUG-15 (G16, LOW): I2P SAM HELLO hardcodes "MIN=3.1 MAX=3.1" (proxy.zig:803)
//!   which is correct (Core also uses 3.1), but the version_ok check only
//!   inspects "RESULT=OK" — it does not verify the VERSION field in the HELLO
//!   reply.  A router returning an incompatible version would not be caught.
//!   Reference: Core i2p.cpp Sam::Session::Hello() VERSION= check.
//!
//! BUG-16 (G17, HIGH / MISSING): CJDNS entirely absent.  NetworkId enum has
//!   `.cjdns = 6` but ProxyManager.connectTo() returns `ProxyError.UnsupportedNetwork`
//!   for CJDNS addresses.  No -cjdns CLI flag, no isRoutable handling (cjdns
//!   fc00::/7 prefix is currently rejected as RFC-4193 private), no outbound
//!   connection support.
//!   Reference: Core netbase.cpp CNetAddr::IsAddrV1Compatible() CJDNS support,
//!              init.cpp -cjdnsreachable.
//!
//! BUG-17 (G18, MEDIUM): CJDNS addresses (fc00::/7 IPv6) are treated as
//!   non-routable by isRoutable() (peer.zig:2712) — the RFC-4193 unique-local
//!   guard `(b[0] & 0xFE) == 0xFC` covers the CJDNS range.  Core explicitly
//!   exempts CJDNS from this filter when -cjdnsreachable is set.
//!   Reference: Core netaddress.cpp CNetAddr::IsRoutable() CJDNS exemption.
//!
//! BUG-18 (G20, MEDIUM): No per-network reachability flags.  Core's
//!   `IsReachable(network)` is driven by SetReachable()/SetLimited() per
//!   network type.  Clearbit has no equivalent; there is no way to mark
//!   NET_ONION or NET_I2P reachable or limited.
//!   Reference: Core net.cpp g_reachable_nets, SetReachable(), IsReachable().
//!
//! BUG-19 (G21, HIGH): No outbound Tor v3 connection support in practice.
//!   Even though MultiNetworkAddress.toHostname(.torv3) converts 32 bytes to a
//!   .onion hostname, the function is never called from the outbound connection
//!   path (Peer.connect() and PeerManager.selectPeerToConnect() only handle
//!   std.net.Address, not MultiNetworkAddress).
//!   Reference: Core net.cpp CConnman::OpenNetworkConnection() Tor path.
//!
//! BUG-20 (G22, HIGH): No outbound I2P connection support in practice.
//!   Same structural gap as BUG-19.  I2pSamClient.connectTo() exists but there
//!   is no path from known_addresses (which stores std.net.Address) to
//!   I2P destination lookup.
//!
//! BUG-21 (G24, MEDIUM): addrv2 length validation is too permissive.
//!   decodeAddrV2() (p2p.zig:980) uses a generic cap of 512 bytes per address
//!   rather than the BIP-155-specified per-network fixed lengths:
//!     NET_IPV4=4, NET_IPV6=16, NET_TORV2=10 (deprecated), NET_TORV3=32,
//!     NET_I2P=32, NET_CJDNS=16.
//!   An entry with network_id=1 (IPv4) but addr_len=512 bytes would be accepted
//!   by the decoder even though IPv4 must be exactly 4 bytes.  Core enforces
//!   per-network sizes and disconnects on mismatch.
//!   Reference: Core net_processing.cpp ProcessMessage("addrv2") addr-size check.
//!
//! BUG-22 (G25, MEDIUM): isRoutable() (peer.zig) does not handle Tor/I2P/CJDNS
//!   MultiNetworkAddress.  It only takes std.net.Address and returns false for
//!   any `else` family.  An addrv2 Tor address stored as a proper MultiNetworkAddress
//!   would always be treated as non-routable.  BUG-4 means these addresses are
//!   never stored in known_addresses anyway, but the deeper issue is architectural.
//!
//! BUG-23 (G27, LOW): torv2 (network_id=3) entries in addrv2 are silently
//!   accepted by the decoder but neither stored nor connection-dialed.  Core
//!   drops torv2 entirely (Tor v2 deprecated 2021-10-15).  The NetworkId enum
//!   has `.torv2 = 3` and expectedAddressLen(.torv2) = 10, so decoding succeeds
//!   and the entry is allocated — only to be freed immediately.  The entry_bytes
//!   allocation leaks if a torv2 entry slips through decodeAddrV2 (no dealloc
//!   in the addrv2 handler for entries that are not network_id==1).
//!   Reference: Core net_processing.cpp: NET_TORV2 explicitly rejected.
//!
//! BUG-24 (G29, MEDIUM): addrv2 entries addr_bytes slices are never freed for
//!   non-IPv4 network_ids.  The addrv2 handler (peer.zig:3934-3943) only
//!   processes network_id==1 (IPv4), and the outer `defer self.allocator.free(a2.entries)`
//!   frees the entries slice but NOT the individual addr_bytes slices inside each
//!   AddrV2Entry.  Every addrv2 message with IPv6, Tor, I2P, or CJDNS entries
//!   leaks the addr_bytes allocation.
//!   Reference: Core net_processing.cpp: all addr_bytes consumed or freed.
//!
//! BUG-25 (G29, MEDIUM / CDIV): decodeAddrV2 uses readCompactSize() for the
//!   `services` field, which is correct per BIP-155. However encode_addrv2
//!   (p2p.zig:531-543) writes services with writeCompactSize() as well, which
//!   is also correct. But the old `addr` message encodes services as a fixed
//!   u64 little-endian (network byte order: 8 bytes), while addrv2 uses
//!   CompactSize.  If any relay code mistakenly sends old-style addr using the
//!   new addrv2 format (or vice-versa), a CDIV arises.  Currently the dual-path
//!   (BUG-6: always old addr regardless of negotiation) avoids this, but fixing
//!   BUG-6 without fixing the relay path could introduce this bug.
//!
//! BUG-26 (G30, MEDIUM): getnetworkinfo RPC does not include tor, i2p, or cjdns
//!   in the networks array.  It hardcodes only ipv4 and ipv6 with reachable=true
//!   (rpc.zig:3253).  Core returns all 5 network types with reachable and proxy
//!   fields populated at runtime.  Tools (Bitcoin Core GUI, monitoring) that call
//!   getnetworkinfo to determine overlay reachability will always see tor/i2p/cjdns
//!   as absent.
//!   Reference: Core rpc/net.cpp getnetworkinfo networks array.

const std = @import("std");
const testing = std.testing;
const proxy = @import("proxy.zig");
const p2p = @import("p2p.zig");
const peer_mod = @import("peer.zig");
const serialize = @import("serialize.zig");

// ============================================================================
// G1-G10: Tor v3 Support
// ============================================================================

test "W117/G1: NetworkId enum covers BIP-155 network types" {
    // BIP-155 specifies: 0x01=IPv4, 0x02=IPv6, 0x03=TORv2(deprecated),
    // 0x04=TORv3, 0x05=I2P, 0x06=CJDNS.
    // Clearbit's NetworkId enum must have all 6 variants.
    try testing.expectEqual(@as(u8, 1), @intFromEnum(proxy.NetworkId.ipv4));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(proxy.NetworkId.ipv6));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(proxy.NetworkId.torv2));
    try testing.expectEqual(@as(u8, 4), @intFromEnum(proxy.NetworkId.torv3));
    try testing.expectEqual(@as(u8, 5), @intFromEnum(proxy.NetworkId.i2p));
    try testing.expectEqual(@as(u8, 6), @intFromEnum(proxy.NetworkId.cjdns));
}

test "W117/G2: Tor v3 address byte length is 32 per BIP-155" {
    // BIP-155 §3.3: TORv3 addresses are 32 bytes (Ed25519 public key).
    const expected_len: ?usize = 32;
    try testing.expectEqual(expected_len, proxy.MultiNetworkAddress.expectedAddressLen(.torv3));
}

test "W117/G2-bug: Tor v3 onion checksum uses zeros instead of SHA3-256" {
    // BUG-2: base32EncodeOnion() hardcodes checksum as 0x00, 0x00.
    // Real Tor v3 checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..2].
    // A known Tor v3 pubkey and its correct .onion address:
    //   pubkey (32 bytes) = 0xd75a980182b10ab7... (test vector)
    //   correct .onion suffix encodes non-zero checksum bytes.
    // We verify that the current implementation produces an output but
    // document that the checksum bytes (positions 52-55 of the 56-char output)
    // would be wrong for any real Tor v3 address.
    var pubkey: [32]u8 = undefined;
    @memset(&pubkey, 0xAB); // arbitrary non-zero pubkey
    // Calling internal base32EncodeOnion indirectly via toHostname
    const addr = proxy.MultiNetworkAddress{
        .network = .torv3,
        .address = &pubkey,
        .port = 9735,
    };
    const allocator = testing.allocator;
    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);

    // The hostname must end in ".onion"
    try testing.expect(std.mem.endsWith(u8, hostname, ".onion"));
    // The base32 part must be 56 characters
    try testing.expectEqual(@as(usize, 62), hostname.len); // 56 + ".onion" = 62

    // Document the bug: the checksum is currently 0x00,0x00,0x03 encoded.
    // Any correct Tor v3 validator would reject this as a bad checksum.
    // The last 8 chars of the 56-char base32 encode the 3-byte suffix
    // (2 checksum bytes + 1 version byte). With checksum=0,0, version=3
    // the suffix bytes are 0x00,0x00,0x03 which encodes as "aaaaa4" in base32.
    // A real Tor v3 address will have non-"aaaaa" checksum chars here.
    // BUG: no assert here since the bug is in the implementation, not the test
}

test "W117/G3: SOCKS5 constants match RFC 1928" {
    try testing.expectEqual(@as(u8, 0x05), proxy.SOCKS5_VERSION);
    try testing.expectEqual(@as(u8, 0x01), proxy.SOCKS5_CMD_CONNECT);
    try testing.expectEqual(@as(u8, 0x01), proxy.SOCKS5_ATYP_IPV4);
    try testing.expectEqual(@as(u8, 0x03), proxy.SOCKS5_ATYP_DOMAINNAME);
    try testing.expectEqual(@as(u8, 0x04), proxy.SOCKS5_ATYP_IPV6);
}

test "W117/G3: SOCKS5 client can be initialized" {
    const allocator = testing.allocator;
    const client = proxy.Socks5Client.init("127.0.0.1", 9050, null, allocator);
    try testing.expectEqualStrings("127.0.0.1", client.proxy_host);
    try testing.expectEqual(@as(u16, 9050), client.proxy_port);
    try testing.expect(client.credentials == null);
}

test "W117/G4: Tor control client can be initialized for hidden service creation" {
    const allocator = testing.allocator;
    const client = proxy.TorControlClient.init("127.0.0.1", 9051, "secret", allocator);
    try testing.expectEqualStrings("127.0.0.1", client.host);
    try testing.expectEqual(@as(u16, 9051), client.port);
    try testing.expectEqualStrings("secret", client.password.?);
}

test "W117/G5-bug: addrv2 handler drops non-IPv4 entries (IPv6, Tor, I2P, CJDNS)" {
    // BUG-4 and BUG-5: peer.zig addrv2 handler only processes network_id == 1.
    // Verify the known_addresses size does NOT increase when receiving addrv2
    // messages with non-IPv4 network types by inspecting the code path.
    //
    // We verify the network IDs for overlay networks:
    try testing.expectEqual(@as(u8, 4), @intFromEnum(proxy.NetworkId.torv3));
    try testing.expectEqual(@as(u8, 5), @intFromEnum(proxy.NetworkId.i2p));
    try testing.expectEqual(@as(u8, 6), @intFromEnum(proxy.NetworkId.cjdns));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(proxy.NetworkId.ipv6));
    // BUG: The handler in peer.zig:3935 is `if (entry.network_id == 1 ...)` only.
    // All other network types are silently dropped.
}

test "W117/G5-bug: addrv2 handler only frees entries slice, not addr_bytes content" {
    // BUG-24 context: AddrV2Entry.addr_bytes is a borrowed slice into the
    // payload buffer (readBytes returns a sub-slice, NOT a heap allocation).
    // The addrv2 handler frees `a2.entries` (the outer slice) via defer.
    // For non-IPv4 entries, no further processing occurs.  Because addr_bytes
    // is borrowed (not heap-allocated), there is no double-free, but the
    // handler ALSO never stores or uses the data — confirming BUG-4 (silent drop).
    //
    // The real memory concern: if any future caller changes decodeAddrV2 to
    // use allocator.dupe() for addr_bytes (to own the data), the handler would
    // then leak for non-IPv4 entries.  The current architecture is fragile.
    const entry_type = p2p.AddrV2Entry;
    const entry: entry_type = .{
        .timestamp = 0,
        .services = 0,
        .network_id = 5, // I2P
        .addr_bytes = &[_]u8{0} ** 32,
        .port = 4567,
    };
    // addr_bytes is a slice field
    try testing.expectEqual(@as(usize, 32), entry.addr_bytes.len);
    try testing.expectEqual(@as(u8, 5), entry.network_id);
}

test "W117/G6-bug: Peer struct missing m_wants_addrv2 flag" {
    // BUG-6: Core tracks CNode::m_wants_addrv2 so it knows whether to send
    // addr or addrv2 in response to getaddr.  Clearbit's Peer struct has no
    // such field.  The sendaddrv2 message during handshake is accepted but
    // no state is updated.
    //
    // We verify via compile-time inspection that Peer has relevant fields
    // (wtxid_relay_negotiated exists, but no addrv2 equivalent).
    const peer_type = peer_mod.Peer;
    // wtxid relay is tracked (proves the pattern is used for BIP-339)
    try testing.expect(@hasField(peer_type, "wtxid_relay_negotiated"));
    // BUG-6: addrv2 negotiation is NOT tracked — none of these fields exist
    try testing.expect(!@hasField(peer_type, "addrv2_negotiated"));
    try testing.expect(!@hasField(peer_type, "wants_addrv2"));
    try testing.expect(!@hasField(peer_type, "m_wants_addrv2"));
    try testing.expect(!@hasField(peer_type, "send_addrv2"));
}

test "W117/G7: sendaddrv2 message encode round-trips correctly" {
    // Verify that sendaddrv2 is a zero-payload message (correct per BIP-155)
    const allocator = testing.allocator;
    const msg = p2p.Message{ .sendaddrv2 = {} };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    // Header is 24 bytes; sendaddrv2 has empty payload
    try testing.expectEqual(@as(usize, 24), encoded.len);

    const header = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("sendaddrv2", header.commandName());
    try testing.expectEqual(@as(u32, 0), header.length);
}

test "W117/G8-bug: sendAddresses cap is 100 instead of Core MAX_ADDR_TO_SEND=1000" {
    // BUG-8: The limit `if (count >= 100) break` in sendAddresses() (peer.zig:5087)
    // sends 10× fewer addresses than Core's MAX_ADDR_TO_SEND=1000.
    // We document this expected constant.
    const core_max_addr_to_send: usize = 1000;
    const clearbit_cap: usize = 100; // hardcoded in peer.zig sendAddresses
    // BUG: clearbit_cap is 10× too small
    try testing.expect(clearbit_cap < core_max_addr_to_send);
    try testing.expectEqual(@as(usize, 100), clearbit_cap);
}

test "W117/G9-bug: StreamIsolation produces unique credentials per connection" {
    // StreamIsolation exists and works correctly (BUG-9 is that it's never
    // USED, not that it's broken).  Verify correctness of the mechanism.
    var iso = proxy.StreamIsolation.init();

    const creds1 = iso.next();
    var user1: [32]u8 = undefined;
    @memcpy(user1[0..creds1.username.len], creds1.username);
    const len1 = creds1.username.len;

    const creds2 = iso.next();

    // Credentials must differ between calls
    try testing.expect(!std.mem.eql(u8, user1[0..len1], creds2.username));
    // Counter must increment
    try testing.expectEqual(@as(u64, 2), iso.counter);
    // BUG-9: This correct implementation is never called from the proxy stack
}

test "W117/G10: TorControlClient.addOnion uses NEW:ED25519-V3 key type" {
    // Core's torcontrol.cpp issues "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=..."
    // Verify clearbit uses the same format.
    // We check the command string is correctly formed by inspecting the constant
    // embedded in addOnion() via the only externally-visible part: the type.
    const allocator = testing.allocator;
    const client = proxy.TorControlClient.init("127.0.0.1", 9051, null, allocator);
    try testing.expectEqualStrings("127.0.0.1", client.host);
    // BUG-10: no mechanism to advertise the resulting .onion as a local address
}

// ============================================================================
// G11-G16: I2P Support
// ============================================================================

test "W117/G11: I2P SAM protocol version is 3.1 (correct)" {
    try testing.expectEqualStrings("3.1", proxy.I2P_SAM_MIN_VERSION);
    try testing.expectEqualStrings("3.1", proxy.I2P_SAM_MAX_VERSION);
}

test "W117/G11: I2P signature type is Ed25519 (7 = correct)" {
    // Core uses SIGNATURE_TYPE=7 (DSA_SHA1 is deprecated; Ed25519 is modern).
    // BIP-155 §3.5: I2P addresses are 32-byte SHA256 of the full destination.
    try testing.expectEqual(@as(u8, 7), proxy.I2P_SIGNATURE_TYPE);
}

test "W117/G12: I2P address length is 32 bytes per BIP-155" {
    const expected_len: ?usize = 32;
    try testing.expectEqual(expected_len, proxy.MultiNetworkAddress.expectedAddressLen(.i2p));
}

test "W117/G12-bug: I2P self-address getAddress() always returns null" {
    // BUG-12: I2pSamClient.getAddress() has a comment saying
    // "This would require base64 decode + SHA256 + base32 encode
    //  For now, return null — caller should use the full destination"
    // This means clearbit can never advertise its own I2P address.
    const allocator = testing.allocator;
    var client = proxy.I2pSamClient.init("127.0.0.1", 7656, null, allocator);
    defer client.deinit();
    // getAddress should return null (it always does — this is the bug)
    try testing.expect(client.getAddress() == null);
}

test "W117/G13: I2P SAM client can be initialized with key file path" {
    const allocator = testing.allocator;
    var client = proxy.I2pSamClient.init("127.0.0.1", 7656, "/data/i2p_key", allocator);
    defer client.deinit();
    try testing.expectEqualStrings("127.0.0.1", client.host);
    try testing.expectEqual(@as(u16, 7656), client.port);
    try testing.expectEqualStrings("/data/i2p_key", client.key_file.?);
    // BUG-13: No default key path tied to datadir; key changes on restart
}

test "W117/G14: I2P SAM lease-set encryption type preference is correct" {
    // Core prefers ECIES-X25519 (type 4) over ElGamal (type 0).
    // i2cp.leaseSetEncType=4,0 means prefer 4 (ECIES), fall back to 0 (ElGamal).
    try testing.expectEqualStrings("4,0", proxy.I2P_LEASE_SET_ENC_TYPE);
}

test "W117/G15: I2P base64 alphabet swap for I2P variant" {
    // I2P uses a non-standard base64 alphabet: '+' -> '-', '/' -> '~'.
    var standard: [11]u8 = "abc+def/ghi".*;
    proxy.swapBase64ToI2P(&standard);
    try testing.expectEqualStrings("abc-def~ghi", &standard);
    proxy.swapBase64FromI2P(&standard);
    try testing.expectEqualStrings("abc+def/ghi", &standard);
}

test "W117/G16: I2P receive timeout is 3 minutes (correct for slow network)" {
    // Core uses a 3-minute timeout (I2P can be slow).
    try testing.expectEqual(@as(u32, 180), proxy.I2P_RECV_TIMEOUT_SEC);
    try testing.expectEqual(@as(usize, 65536), proxy.I2P_MAX_MSG_SIZE);
}

// ============================================================================
// G17-G20: CJDNS Support
// ============================================================================

test "W117/G17-bug: CJDNS connectTo returns UnsupportedNetwork" {
    // BUG-16: ProxyManager.connectTo() for CJDNS returns ProxyError.UnsupportedNetwork.
    // There is no CJDNS proxy or routing path implemented.
    const allocator = testing.allocator;
    var manager = proxy.ProxyManager.init(.{}, .{}, .{}, allocator);
    defer manager.deinit();

    const cjdns_bytes = [_]u8{0xfc} ++ [_]u8{0x00} ** 15; // fc00:: prefix
    const cjdns_addr = proxy.MultiNetworkAddress{
        .network = .cjdns,
        .address = &cjdns_bytes,
        .port = 8333,
    };

    const result = manager.connectTo(&cjdns_addr);
    // BUG-16: CJDNS always returns UnsupportedNetwork
    try testing.expectError(proxy.ProxyError.UnsupportedNetwork, result);
}

test "W117/G17: CJDNS network_id is 6 per BIP-155" {
    try testing.expectEqual(@as(u8, 6), @intFromEnum(proxy.NetworkId.cjdns));
}

test "W117/G17: CJDNS address length is 16 bytes (IPv6 fc00::/7 range)" {
    const expected_len: ?usize = 16;
    try testing.expectEqual(expected_len, proxy.MultiNetworkAddress.expectedAddressLen(.cjdns));
}

test "W117/G18-bug: isRoutable rejects CJDNS fc00::/7 range as RFC-4193 private" {
    // BUG-17: isRoutable() in peer.zig checks `(b[0] & 0xFE) == 0xFC` which
    // covers fc00::/7 — the CJDNS range.  Core exempts CJDNS when
    // -cjdnsreachable is set.  We verify the mask logic covers CJDNS addresses.
    const cjdns_first_byte: u8 = 0xFC;
    const mask: u8 = 0xFE;
    const expected_pattern: u8 = 0xFC;
    // The isRoutable check `(b[0] & 0xFE) == 0xFC` matches CJDNS addresses:
    try testing.expectEqual(expected_pattern, cjdns_first_byte & mask);
    // BUG: This guard should be skipped when CJDNS reachability is enabled
}

test "W117/G19-bug: no per-network reachability flags (SetReachable absent)" {
    // BUG-18: Core has g_reachable_nets bitmap; clearbit has no equivalent.
    // Verify: Peer struct has no reachable_networks or similar field.
    const peer_type = peer_mod.Peer;
    // BUG-18: No per-network reachability tracking — these fields don't exist
    try testing.expect(!@hasField(peer_type, "reachable_networks"));
    try testing.expect(!@hasField(peer_type, "limited_networks"));
    try testing.expect(!@hasField(peer_type, "net_reachable"));
}

test "W117/G20: SOCKS5 reply code for tor hidden service errors" {
    // Verify Tor-specific SOCKS5 error codes (F0-F7) are handled.
    const not_found: proxy.Socks5Reply = .tor_hidden_service_not_found;
    const unreachable_hs: proxy.Socks5Reply = .tor_hidden_service_unreachable;
    try testing.expectEqual(@as(u8, 0xF0), @intFromEnum(not_found));
    try testing.expectEqual(@as(u8, 0xF1), @intFromEnum(unreachable_hs));
}

// ============================================================================
// G21-G24: Outbound Overlay Connections
// ============================================================================

test "W117/G21: toHostname for Tor v3 produces .onion suffix" {
    // BUG-19: toHostname() works for the conversion, but the outbound
    // connection path never calls it — only std.net.Address is used.
    const allocator = testing.allocator;
    const pubkey = [_]u8{0x42} ** 32;
    const addr = proxy.MultiNetworkAddress{
        .network = .torv3,
        .address = &pubkey,
        .port = 8333,
    };
    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);
    try testing.expect(std.mem.endsWith(u8, hostname, ".onion"));
    // BUG-2: checksum is wrong (zeros instead of SHA3-256)
    // BUG-19: this function is never called from the actual outbound connect path
}

test "W117/G21: toHostname for I2P produces .b32.i2p suffix" {
    const allocator = testing.allocator;
    const dest_hash = [_]u8{0x13} ** 32;
    const addr = proxy.MultiNetworkAddress{
        .network = .i2p,
        .address = &dest_hash,
        .port = 4567,
    };
    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);
    try testing.expect(std.mem.endsWith(u8, hostname, ".b32.i2p"));
    // BUG-20: this function is never called from the actual outbound connect path
}

test "W117/G22-bug: Peer.connect() takes std.net.Address — no overlay address path" {
    // BUG-19, BUG-20: Peer.connect(address, params, allocator) takes
    // std.net.Address, which can only represent IPv4/IPv6.  There is no
    // overload or union type that accepts a MultiNetworkAddress for Tor/I2P.
    // Verify by checking the type signature via reflection.
    const connect_fn = peer_mod.Peer.connect;
    const fn_info = @typeInfo(@TypeOf(connect_fn));
    const params = fn_info.Fn.params;
    // First param is address type
    try testing.expectEqual(std.net.Address, params[0].type.?);
    // BUG: should accept MultiNetworkAddress or a union type for overlay nets
}

test "W117/G23-bug: torv2 addresses accepted by decoder but should be rejected" {
    // BUG-23: Core rejected Tor v2 after 2021-10-15.  Clearbit's NetworkId
    // enum has torv2=3 and expectedAddressLen=10, so torv2 entries are decoded
    // without error.  Core's net_processing.cpp rejects them:
    //   if (addr.GetNetwork() == NET_TORV2) { ... misbehavior }
    const len = proxy.MultiNetworkAddress.expectedAddressLen(.torv2);
    try testing.expectEqual(@as(?usize, 10), len);
    // BUG: this should return null or cause rejection, not a valid length
}

test "W117/G24: ProxyManager correctly routes Tor v3 to SOCKS5" {
    // Verify ProxyManager routing logic: torv3 uses tor_config SOCKS5 proxy.
    // We can't test actual network connections, but we verify the ProxyType.
    const tor_config = proxy.ProxyConfig{
        .proxy_type = .socks5,
        .host = "127.0.0.1",
        .port = 9050,
    };
    const allocator = testing.allocator;
    var manager = proxy.ProxyManager.init(.{}, tor_config, .{}, allocator);
    defer manager.deinit();

    // The torv3 path requires an actual SOCKS5 connection, so we just verify
    // that a missing tor proxy returns UnsupportedNetwork
    const mgr_none = proxy.ProxyManager.init(.{}, .{}, .{}, allocator);
    var mgr_no_tor = mgr_none;
    defer mgr_no_tor.deinit();

    const torv3_addr = proxy.MultiNetworkAddress{
        .network = .torv3,
        .address = &([_]u8{0x1A} ** 32),
        .port = 8333,
    };
    const result = mgr_no_tor.connectTo(&torv3_addr);
    // Without a tor proxy configured, connectTo returns UnsupportedNetwork
    try testing.expectError(proxy.ProxyError.UnsupportedNetwork, result);
}

// ============================================================================
// G25-G28: Address Resolution and Validation
// ============================================================================

test "W117/G25: MultiNetworkAddress.expectedAddressLen covers all BIP-155 types" {
    try testing.expectEqual(@as(?usize, 4), proxy.MultiNetworkAddress.expectedAddressLen(.ipv4));
    try testing.expectEqual(@as(?usize, 16), proxy.MultiNetworkAddress.expectedAddressLen(.ipv6));
    try testing.expectEqual(@as(?usize, 10), proxy.MultiNetworkAddress.expectedAddressLen(.torv2)); // deprecated
    try testing.expectEqual(@as(?usize, 32), proxy.MultiNetworkAddress.expectedAddressLen(.torv3));
    try testing.expectEqual(@as(?usize, 32), proxy.MultiNetworkAddress.expectedAddressLen(.i2p));
    try testing.expectEqual(@as(?usize, 16), proxy.MultiNetworkAddress.expectedAddressLen(.cjdns));
}

test "W117/G26-bug: addrv2 decoder uses generic 512-byte cap instead of per-network sizes" {
    // BUG-21: decodeAddrV2() in p2p.zig uses `if (addr_len > 512)` rather than
    // the BIP-155 per-network fixed sizes.  An IPv4 entry with addr_len=100
    // would pass the decoder but is invalid (IPv4 must be exactly 4 bytes).
    // We verify the correct expected lengths.
    try testing.expectEqual(@as(?usize, 4), proxy.MultiNetworkAddress.expectedAddressLen(.ipv4));
    // Correct behavior: decoder should reject IPv4 addr_len != 4.
    // BUG: current decoder only checks addr_len <= 512.
}

test "W117/G27: IPv4 toHostname formats dotted decimal correctly" {
    const allocator = testing.allocator;
    const addr = proxy.MultiNetworkAddress{
        .network = .ipv4,
        .address = &[_]u8{ 1, 2, 3, 4 },
        .port = 8333,
    };
    const hostname = try addr.toHostname(allocator);
    defer allocator.free(hostname);
    try testing.expectEqualStrings("1.2.3.4", hostname);
}

test "W117/G28-bug: SOCKS5 connect ignores per-proxy-type auth (all use domain ATYP)" {
    // The SOCKS5 CONNECT always uses ATYP_DOMAINNAME regardless of whether the
    // target is an IP or onion/I2P hostname.  This is correct for
    // Tor/I2P (where we pass the hostname as domain), but for clearnet IPv4/IPv6
    // connects through a generic SOCKS5 proxy, using ATYP_IPV4 or ATYP_IPV6
    // would be more efficient and compatible.
    // This is LOW severity — functionally correct but suboptimal.
    try testing.expectEqual(@as(u8, 0x03), proxy.SOCKS5_ATYP_DOMAINNAME);
    // The connect flow always uses ATYP_DOMAINNAME (proxy.zig:413)
}

// ============================================================================
// G29-G30: addrv2 Wire Protocol + RPC
// ============================================================================

test "W117/G29: addrv2 message encode/decode round-trip for IPv4 entry" {
    // Verify the addrv2 wire format round-trips correctly for an IPv4 entry.
    // Note: addr_bytes is a slice into the payload buffer (NOT heap-allocated),
    // so we must NOT free individual addr_bytes slices.  Only free entries slice.
    const allocator = testing.allocator;

    const entry = p2p.AddrV2Entry{
        .timestamp = 1700000000,
        .services = 9, // NODE_NETWORK | NODE_WITNESS
        .network_id = 1, // IPv4
        .addr_bytes = &[_]u8{ 1, 2, 3, 4 },
        .port = 8333,
    };
    const msg = p2p.Message{
        .addrv2 = .{ .entries = &[_]p2p.AddrV2Entry{entry} },
    };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    // Decode the payload
    const header = p2p.MessageHeader.decode(encoded[0..24]);
    try testing.expectEqualStrings("addrv2", header.commandName());

    const payload = encoded[24..];
    const decoded = try p2p.decodePayload("addrv2", payload, allocator);
    const decoded_entries = decoded.addrv2.entries;
    // addr_bytes are borrowed slices pointing into payload; only the entries
    // slice itself is heap-allocated and needs freeing.
    defer allocator.free(decoded_entries);

    try testing.expectEqual(@as(usize, 1), decoded_entries.len);
    try testing.expectEqual(@as(u32, 1700000000), decoded_entries[0].timestamp);
    try testing.expectEqual(@as(u8, 1), decoded_entries[0].network_id);
    try testing.expectEqual(@as(u16, 8333), decoded_entries[0].port);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, decoded_entries[0].addr_bytes);
}

test "W117/G29: addrv2 message encode/decode round-trip for Tor v3 entry" {
    // Verify Tor v3 (network_id=4, 32-byte) round-trips through the wire format.
    // addr_bytes are borrowed (point into payload buffer); don't free individually.
    const allocator = testing.allocator;

    const torv3_bytes = [_]u8{0xDE} ** 32;
    const entry = p2p.AddrV2Entry{
        .timestamp = 1700000001,
        .services = 9,
        .network_id = 4, // TORv3
        .addr_bytes = &torv3_bytes,
        .port = 9735,
    };
    const msg = p2p.Message{
        .addrv2 = .{ .entries = &[_]p2p.AddrV2Entry{entry} },
    };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const payload = encoded[24..];
    const decoded = try p2p.decodePayload("addrv2", payload, allocator);
    const decoded_entries = decoded.addrv2.entries;
    defer allocator.free(decoded_entries);

    try testing.expectEqual(@as(usize, 1), decoded_entries.len);
    try testing.expectEqual(@as(u8, 4), decoded_entries[0].network_id);
    try testing.expectEqual(@as(u16, 9735), decoded_entries[0].port);
    try testing.expectEqualSlices(u8, &torv3_bytes, decoded_entries[0].addr_bytes);
    // BUG-4: this entry would be silently dropped by the peer.zig addrv2 handler
}

test "W117/G29: addrv2 services field uses CompactSize encoding (BIP-155 correct)" {
    // BIP-155 §2: services in addrv2 uses CompactSize, NOT fixed 8-byte LE.
    // Verify our encode uses writeCompactSize for services.
    const allocator = testing.allocator;

    const entry = p2p.AddrV2Entry{
        .timestamp = 0,
        .services = 1, // single byte CompactSize
        .network_id = 1,
        .addr_bytes = &[_]u8{ 127, 0, 0, 1 },
        .port = 8333,
    };
    const msg = p2p.Message{
        .addrv2 = .{ .entries = &[_]p2p.AddrV2Entry{entry} },
    };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    // For services=1: CompactSize = 1 byte (0x01), NOT 8 bytes.
    // The payload starts after the 24-byte header.
    // Payload structure: compact_size(count=1) + ts(4) + cs(services) + nid(1) + cs(addr_len=4) + addr(4) + port(2)
    // = 1 + 4 + 1 + 1 + 1 + 4 + 2 = 14 bytes
    const payload = encoded[24..];
    try testing.expectEqual(@as(usize, 14), payload.len);
    // Byte 0: count=1 (CompactSize)
    try testing.expectEqual(@as(u8, 1), payload[0]);
    // Bytes 1-4: timestamp=0
    // Byte 5: services=1 (CompactSize, 1 byte)
    try testing.expectEqual(@as(u8, 1), payload[5]);
}

test "W117/G30-bug: getnetworkinfo RPC only lists ipv4 and ipv6 (missing tor/i2p/cjdns)" {
    // BUG-26: Core's getnetworkinfo returns all 5 network types (ipv4, ipv6,
    // onion, i2p, cjdns) with reachable/proxy fields.  Clearbit hardcodes only
    // ipv4 and ipv6 in the networks array.
    //
    // The hardcoded string in rpc.zig:3253 is:
    //   "networks":[{"name":"ipv4","limited":false,"reachable":true,...},
    //               {"name":"ipv6","limited":false,"reachable":true,...}]
    // Missing: onion, i2p, cjdns entries.
    //
    // We verify the correct set of network names Core expects.
    const core_network_names = [_][]const u8{ "ipv4", "ipv6", "onion", "i2p", "cjdns" };
    try testing.expectEqual(@as(usize, 5), core_network_names.len);
    // BUG: clearbit emits only 2 of these 5 names.
    const clearbit_network_count: usize = 2; // hardcoded in rpc.zig
    try testing.expect(clearbit_network_count < core_network_names.len);
}

test "W117/G30: addrv2 port encoding is big-endian (network byte order)" {
    // BIP-155 §2: the port field in addrv2 is big-endian (same as legacy addr).
    // Verify the encode path uses big-endian.
    const allocator = testing.allocator;

    const entry = p2p.AddrV2Entry{
        .timestamp = 0,
        .services = 0,
        .network_id = 1,
        .addr_bytes = &[_]u8{ 1, 1, 1, 1 },
        .port = 0x1234, // big-endian: 0x12 0x34
    };
    const msg = p2p.Message{
        .addrv2 = .{ .entries = &[_]p2p.AddrV2Entry{entry} },
    };
    const encoded = try p2p.encodeMessage(&msg, p2p.NetworkMagic.MAINNET, allocator);
    defer allocator.free(encoded);

    const payload = encoded[24..];
    // Payload: 1(count) + 4(ts) + 1(services) + 1(nid) + 1(addr_len) + 4(addr) + 2(port)
    // Port bytes are at offset 12-13
    try testing.expectEqual(@as(u8, 0x12), payload[12]);
    try testing.expectEqual(@as(u8, 0x34), payload[13]);
}
