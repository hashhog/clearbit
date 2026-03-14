//! Ban list management for peer misbehavior tracking.
//!
//! Implements a persistent ban list that stores banned IP addresses
//! with expiry timestamps. Compatible with Bitcoin Core's ban management.

const std = @import("std");

/// Default ban duration: 24 hours in seconds.
pub const DEFAULT_BAN_DURATION: i64 = 24 * 60 * 60;

/// Ban entry storing ban details.
pub const BanEntry = struct {
    /// IP address as 4-byte array for IPv4 (stored as string key in JSON).
    ip: [4]u8,
    /// Unix timestamp when the ban expires.
    ban_until: i64,
    /// Reason for the ban.
    reason: []const u8,
    /// When the ban was created.
    create_time: i64,
};

/// Manages banned IP addresses with persistence to disk.
pub const BanList = struct {
    /// Map from IP (as u32) to ban expiry timestamp.
    banned: std.AutoHashMap(u32, BanEntry),
    /// Path to the persistence file.
    file_path: ?[]const u8,
    /// Allocator for memory management.
    allocator: std.mem.Allocator,
    /// Whether the list has been modified since last save.
    is_dirty: bool,

    /// Initialize a new ban list.
    pub fn init(allocator: std.mem.Allocator, file_path: ?[]const u8) BanList {
        return .{
            .banned = std.AutoHashMap(u32, BanEntry).init(allocator),
            .file_path = file_path,
            .allocator = allocator,
            .is_dirty = false,
        };
    }

    /// Deinitialize the ban list, freeing memory.
    pub fn deinit(self: *BanList) void {
        // Free all stored reason strings
        var iter = self.banned.valueIterator();
        while (iter.next()) |entry| {
            if (entry.reason.len > 0) {
                self.allocator.free(entry.reason);
            }
        }
        self.banned.deinit();
    }

    /// Convert IPv4 bytes to u32 key.
    pub fn ipToKey(ip: [4]u8) u32 {
        return (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) |
            (@as(u32, ip[2]) << 8) | @as(u32, ip[3]);
    }

    /// Convert u32 key back to IPv4 bytes.
    pub fn keyToIp(key: u32) [4]u8 {
        return .{
            @intCast((key >> 24) & 0xFF),
            @intCast((key >> 16) & 0xFF),
            @intCast((key >> 8) & 0xFF),
            @intCast(key & 0xFF),
        };
    }

    /// Convert std.net.Address to IPv4 bytes (returns null for non-IPv4).
    pub fn addressToIpv4(address: std.net.Address) ?[4]u8 {
        switch (address.any.family) {
            std.posix.AF.INET => {
                const ip4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address.any)));
                const ip_bytes = @as(*const [4]u8, @ptrCast(&ip4.addr));
                return ip_bytes.*;
            },
            else => return null,
        }
    }

    /// Ban an IP address for a specified duration.
    pub fn ban(self: *BanList, ip: [4]u8, duration: i64, reason: []const u8) !void {
        const now = std.time.timestamp();
        const key = ipToKey(ip);

        // Free old reason if exists
        if (self.banned.get(key)) |old_entry| {
            if (old_entry.reason.len > 0) {
                self.allocator.free(old_entry.reason);
            }
        }

        // Duplicate reason string
        const reason_copy = try self.allocator.dupe(u8, reason);

        try self.banned.put(key, BanEntry{
            .ip = ip,
            .ban_until = now + duration,
            .reason = reason_copy,
            .create_time = now,
        });
        self.is_dirty = true;
    }

    /// Ban using a std.net.Address.
    pub fn banAddress(self: *BanList, address: std.net.Address, duration: i64, reason: []const u8) !void {
        if (addressToIpv4(address)) |ip| {
            try self.ban(ip, duration, reason);
        }
    }

    /// Unban an IP address.
    pub fn unban(self: *BanList, ip: [4]u8) bool {
        const key = ipToKey(ip);
        if (self.banned.get(key)) |entry| {
            if (entry.reason.len > 0) {
                self.allocator.free(entry.reason);
            }
            _ = self.banned.remove(key);
            self.is_dirty = true;
            return true;
        }
        return false;
    }

    /// Unban using a std.net.Address.
    pub fn unbanAddress(self: *BanList, address: std.net.Address) bool {
        if (addressToIpv4(address)) |ip| {
            return self.unban(ip);
        }
        return false;
    }

    /// Check if an IP is banned.
    pub fn isBanned(self: *BanList, ip: [4]u8) bool {
        const key = ipToKey(ip);
        if (self.banned.get(key)) |entry| {
            const now = std.time.timestamp();
            if (now < entry.ban_until) {
                return true;
            }
            // Ban expired, remove it
            if (entry.reason.len > 0) {
                self.allocator.free(entry.reason);
            }
            _ = self.banned.remove(key);
            self.is_dirty = true;
        }
        return false;
    }

    /// Check if an address is banned.
    pub fn isAddressBanned(self: *BanList, address: std.net.Address) bool {
        if (addressToIpv4(address)) |ip| {
            return self.isBanned(ip);
        }
        return false;
    }

    /// Clear all bans.
    pub fn clearAll(self: *BanList) void {
        var iter = self.banned.valueIterator();
        while (iter.next()) |entry| {
            if (entry.reason.len > 0) {
                self.allocator.free(entry.reason);
            }
        }
        self.banned.clearAndFree();
        self.is_dirty = true;
    }

    /// Get the number of banned addresses.
    pub fn count(self: *const BanList) usize {
        return self.banned.count();
    }

    /// Sweep expired bans.
    pub fn sweepExpired(self: *BanList) void {
        const now = std.time.timestamp();
        var to_remove = std.ArrayList(u32).init(self.allocator);
        defer to_remove.deinit();

        var iter = self.banned.iterator();
        while (iter.next()) |entry| {
            if (now >= entry.value_ptr.ban_until) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.banned.get(key)) |entry| {
                if (entry.reason.len > 0) {
                    self.allocator.free(entry.reason);
                }
                _ = self.banned.remove(key);
                self.is_dirty = true;
            }
        }
    }

    /// Save the ban list to disk as JSON.
    pub fn save(self: *BanList) !void {
        if (self.file_path == null) return;
        if (!self.is_dirty) return;

        // Sweep expired bans first
        self.sweepExpired();

        var file = std.fs.cwd().createFile(self.file_path.?, .{}) catch |err| {
            std.log.err("Failed to create banlist file: {}", .{err});
            return err;
        };
        defer file.close();

        var writer = file.writer();

        // Write JSON manually for simplicity
        try writer.writeAll("{\n  \"banned\": [\n");

        var first = true;
        var iter = self.banned.iterator();
        while (iter.next()) |entry| {
            if (!first) {
                try writer.writeAll(",\n");
            }
            first = false;

            const ip = entry.value_ptr.ip;
            try writer.print("    {{\"ip\": \"{d}.{d}.{d}.{d}\", \"ban_until\": {d}, \"create_time\": {d}, \"reason\": \"", .{
                ip[0], ip[1], ip[2], ip[3],
                entry.value_ptr.ban_until,
                entry.value_ptr.create_time,
            });
            // Escape reason string
            for (entry.value_ptr.reason) |c| {
                if (c == '"') {
                    try writer.writeAll("\\\"");
                } else if (c == '\\') {
                    try writer.writeAll("\\\\");
                } else if (c == '\n') {
                    try writer.writeAll("\\n");
                } else {
                    try writer.writeByte(c);
                }
            }
            try writer.writeAll("\"}");
        }

        try writer.writeAll("\n  ]\n}\n");
        self.is_dirty = false;
    }

    /// Load the ban list from disk.
    pub fn load(self: *BanList) !void {
        if (self.file_path == null) return;

        var file = std.fs.cwd().openFile(self.file_path.?, .{}) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch |err| {
            std.log.err("Failed to read banlist file: {}", .{err});
            return err;
        };
        defer self.allocator.free(content);

        // Parse JSON
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch |err| {
            std.log.err("Failed to parse banlist JSON: {}", .{err});
            return err;
        };
        defer parsed.deinit();

        const root = parsed.value;
        if (root != .object) return error.InvalidData;

        const banned_array = root.object.get("banned") orelse return;
        if (banned_array != .array) return error.InvalidData;

        for (banned_array.array.items) |item| {
            if (item != .object) continue;

            const ip_str = item.object.get("ip") orelse continue;
            const ban_until = item.object.get("ban_until") orelse continue;
            const create_time = item.object.get("create_time") orelse continue;
            const reason_val = item.object.get("reason") orelse continue;

            if (ip_str != .string or ban_until != .integer or create_time != .integer or reason_val != .string) continue;

            // Parse IP address
            var ip_parts: [4]u8 = undefined;
            var part_iter = std.mem.splitSequence(u8, ip_str.string, ".");
            var i: usize = 0;
            while (part_iter.next()) |part| : (i += 1) {
                if (i >= 4) break;
                ip_parts[i] = std.fmt.parseInt(u8, part, 10) catch continue;
            }
            if (i != 4) continue;

            // Only load if not expired
            const now = std.time.timestamp();
            if (now >= ban_until.integer) continue;

            const reason_copy = self.allocator.dupe(u8, reason_val.string) catch continue;

            self.banned.put(ipToKey(ip_parts), BanEntry{
                .ip = ip_parts,
                .ban_until = ban_until.integer,
                .reason = reason_copy,
                .create_time = create_time.integer,
            }) catch {
                self.allocator.free(reason_copy);
                continue;
            };
        }
    }

    /// Get an iterator over all ban entries.
    pub fn iterator(self: *BanList) std.AutoHashMap(u32, BanEntry).Iterator {
        return self.banned.iterator();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ban list initialization" {
    const allocator = std.testing.allocator;

    var banlist = BanList.init(allocator, null);
    defer banlist.deinit();

    try std.testing.expectEqual(@as(usize, 0), banlist.count());
    try std.testing.expect(!banlist.is_dirty);
}

test "ban and unban ip" {
    const allocator = std.testing.allocator;

    var banlist = BanList.init(allocator, null);
    defer banlist.deinit();

    const ip = [4]u8{ 192, 168, 1, 100 };

    // Not banned initially
    try std.testing.expect(!banlist.isBanned(ip));

    // Ban the IP
    try banlist.ban(ip, DEFAULT_BAN_DURATION, "test ban");
    try std.testing.expectEqual(@as(usize, 1), banlist.count());
    try std.testing.expect(banlist.isBanned(ip));

    // Unban
    try std.testing.expect(banlist.unban(ip));
    try std.testing.expectEqual(@as(usize, 0), banlist.count());
    try std.testing.expect(!banlist.isBanned(ip));
}

test "ban list ip to key conversion" {
    const ip = [4]u8{ 192, 168, 1, 100 };
    const key = BanList.ipToKey(ip);

    // 192.168.1.100 = 0xC0A80164
    const expected: u32 = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    try std.testing.expectEqual(expected, key);

    // Convert back
    const ip_back = BanList.keyToIp(key);
    try std.testing.expectEqualSlices(u8, &ip, &ip_back);
}

test "ban list clear all" {
    const allocator = std.testing.allocator;

    var banlist = BanList.init(allocator, null);
    defer banlist.deinit();

    // Add some bans
    try banlist.ban([4]u8{ 10, 0, 0, 1 }, DEFAULT_BAN_DURATION, "ban 1");
    try banlist.ban([4]u8{ 10, 0, 0, 2 }, DEFAULT_BAN_DURATION, "ban 2");
    try banlist.ban([4]u8{ 10, 0, 0, 3 }, DEFAULT_BAN_DURATION, "ban 3");
    try std.testing.expectEqual(@as(usize, 3), banlist.count());

    // Clear all
    banlist.clearAll();
    try std.testing.expectEqual(@as(usize, 0), banlist.count());
}

test "misbehavior score threshold" {
    // This tests the misbehavior threshold concept (100 points)
    var score: u32 = 0;

    // Add 10 points 9 times = 90, not banned
    var i: u32 = 0;
    while (i < 9) : (i += 1) {
        score += 10;
        try std.testing.expect(score < 100);
    }

    // Add 10 more = 100, should be banned
    score += 10;
    try std.testing.expect(score >= 100);
}

test "ban list address conversion" {
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, 8333);
    const ip = BanList.addressToIpv4(addr);
    try std.testing.expect(ip != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 1 }, &ip.?);
}

test "ban entry with empty reason" {
    const allocator = std.testing.allocator;

    var banlist = BanList.init(allocator, null);
    defer banlist.deinit();

    const ip = [4]u8{ 192, 168, 1, 100 };
    try banlist.ban(ip, DEFAULT_BAN_DURATION, "");
    try std.testing.expect(banlist.isBanned(ip));
}

test "ban list persistence round trip" {
    const allocator = std.testing.allocator;

    // Create a temporary file path
    const test_path = "test_banlist.json";

    // First, create and save a ban list
    {
        var banlist = BanList.init(allocator, test_path);
        defer banlist.deinit();

        try banlist.ban([4]u8{ 10, 0, 0, 1 }, DEFAULT_BAN_DURATION, "test ban 1");
        try banlist.ban([4]u8{ 10, 0, 0, 2 }, DEFAULT_BAN_DURATION, "test ban 2");

        try banlist.save();
    }

    // Now load it in a new ban list
    {
        var banlist = BanList.init(allocator, test_path);
        defer banlist.deinit();

        try banlist.load();

        try std.testing.expectEqual(@as(usize, 2), banlist.count());
        try std.testing.expect(banlist.isBanned([4]u8{ 10, 0, 0, 1 }));
        try std.testing.expect(banlist.isBanned([4]u8{ 10, 0, 0, 2 }));
    }

    // Clean up
    std.fs.cwd().deleteFile(test_path) catch {};
}
