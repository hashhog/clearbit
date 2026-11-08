//! Headers timeout must not drop a peer that is level with our tip.
//!
//! Core's ConsiderEviction (net_processing.cpp:5213-5262) resets an outbound
//! peer's chain-sync timeout whenever the peer's best known block has at
//! least our tip's work, so a peer level with us is never disconnected over
//! a getheaders it did not answer. The headers-sync timeout (:6124-6153)
//! only fires while our own headers are behind. clearbit's
//! checkHeadersTimeouts disconnected every peer with a getheaders older than
//! HEADERS_RESPONSE_TIMEOUT, and on mainnet that took the node from 8 to 3-6
//! full-relay outbound in bursts of three or four.
//!
//! Peers run over unix socketpairs against the real PeerManager.
//!
//! CONTROL: `zig build test-headers-timeout-at-tip --summary all`

const std = @import("std");
const testing = std.testing;
const consensus = @import("src/consensus.zig");
const p2p = @import("src/p2p.zig");
const storage = @import("src/storage.zig");
const peer_mod = @import("src/peer.zig");
const Peer = peer_mod.Peer;
const PeerManager = peer_mod.PeerManager;

const params = &consensus.REGTEST;
const TIP: u32 = 1000;

const Fx = struct {
    a: std.mem.Allocator,
    cs: storage.ChainState,
    pm: PeerManager,
    remotes: std.ArrayList(std.posix.fd_t),

    fn init(self: *Fx, a: std.mem.Allocator) void {
        self.a = a;
        self.cs = storage.ChainState.init(null, 16, a);
        self.cs.best_height = TIP;
        self.pm = PeerManager.init(a, params);
        self.pm.anchors_path = "/dev/null";
        self.pm.ban_list.file_path = null;
        self.pm.chain_state = &self.cs;
        self.remotes = std.ArrayList(std.posix.fd_t).init(a);
    }

    fn deinit(self: *Fx) void {
        for (self.remotes.items) |fd| std.posix.close(fd);
        self.remotes.deinit();
        self.pm.chain_state = null;
        self.pm.deinit();
        self.cs.deinit();
    }

    /// Handshake-complete outbound full-relay peer whose getheaders is
    /// overdue (sent HEADERS_RESPONSE_TIMEOUT + 1 s ago, never answered).
    fn overduePeer(self: *Fx, ip: [4]u8, start_height: i32, announced: u32) !*Peer {
        var fds: [2]i32 = undefined;
        try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
        try self.remotes.append(fds[1]);
        const p = try self.a.create(Peer);
        p.* = Peer.accept(.{ .handle = fds[0] }, std.net.Address.initIp4(ip, 8333), params, self.a);
        p.state = .handshake_complete;
        p.direction = .outbound;
        p.conn_type = .outbound_full_relay;
        p.services = p2p.NODE_NETWORK | p2p.NODE_WITNESS;
        p.start_height = start_height;
        p.blocks_available_height = announced;
        p.last_getheaders_time = std.time.timestamp() - peer_mod.HEADERS_RESPONSE_TIMEOUT - 1;
        try self.pm.peers.append(p);
        return p;
    }

    fn runStaleCheck(self: *Fx) !void {
        self.pm.last_stale_check_time = 0;
        self.pm.checkForStaleTipAndEvictPeers();
        try self.pm.processAllMessages();
    }

    fn has(self: *Fx, p: *const Peer) bool {
        for (self.pm.peers.items) |q| if (q == p) return true;
        return false;
    }
};

test "headers_timeout_at_tip: a peer that reported our tip height at connect is kept after an unanswered getheaders" {
    var fx: Fx = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();

    const at_tip = try fx.overduePeer(.{ 10, 0, 0, 1 }, @intCast(TIP), 0);
    const addr = at_tip.address;
    try fx.runStaleCheck();

    try testing.expect(fx.has(at_tip));
    try testing.expectEqual(@as(usize, 1), fx.pm.countFullRelayOutbound());
    try testing.expectEqual(@as(i64, 0), at_tip.last_getheaders_time);
    try testing.expect(!fx.pm.ban_list.isAddressBanned(addr));
}

test "headers_timeout_at_tip: a peer that announced our tip block is kept after an unanswered getheaders" {
    var fx: Fx = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();

    // Connected 30 blocks ago, has announced every block since.
    const announcer = try fx.overduePeer(.{ 10, 0, 0, 2 }, @intCast(TIP - 30), TIP);
    try fx.runStaleCheck();

    try testing.expect(fx.has(announcer));
    try testing.expectEqual(@as(usize, 1), fx.pm.countFullRelayOutbound());
}

test "headers_timeout_at_tip: a burst of overdue at-tip peers leaves all 8 full-relay slots filled" {
    var fx: Fx = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();

    var i: u8 = 0;
    while (i < peer_mod.MAX_OUTBOUND_CONNECTIONS) : (i += 1) {
        _ = try fx.overduePeer(.{ 10, 0, 1, i + 1 }, @intCast(TIP), 0);
    }
    try fx.runStaleCheck();
    try testing.expectEqual(@as(usize, peer_mod.MAX_OUTBOUND_CONNECTIONS), fx.pm.countFullRelayOutbound());
}

test "headers_timeout_at_tip: a peer behind our tip is still disconnected (no announcement, lower start height)" {
    var fx: Fx = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();

    const behind = try fx.overduePeer(.{ 10, 0, 0, 3 }, @intCast(TIP - 5), 0);
    const addr = behind.address;
    try fx.runStaleCheck();

    try testing.expectEqual(@as(usize, 0), fx.pm.peers.items.len);
    try testing.expect(!fx.pm.ban_list.isAddressBanned(addr));
}

test "headers_timeout_at_tip: a peer claiming headers beyond ours is still disconnected (we are behind, headers-sync timeout)" {
    var fx: Fx = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();

    // It holds our tip but claims 10 more blocks we have no header for: the
    // unanswered getheaders is the one we need answered.
    _ = try fx.overduePeer(.{ 10, 0, 0, 4 }, @intCast(TIP + 10), 0);
    try fx.runStaleCheck();

    try testing.expectEqual(@as(usize, 0), fx.pm.peers.items.len);
}

test "headers_timeout_at_tip: a peer whose getheaders is not yet overdue is untouched either way" {
    var fx: Fx = undefined;
    fx.init(testing.allocator);
    defer fx.deinit();

    const fresh = try fx.overduePeer(.{ 10, 0, 0, 5 }, @intCast(TIP - 5), 0);
    const sent = std.time.timestamp() - 10;
    fresh.last_getheaders_time = sent;
    try fx.runStaleCheck();

    try testing.expect(fx.has(fresh));
    try testing.expectEqual(sent, fresh.last_getheaders_time);
}
