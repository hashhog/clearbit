//! Security audit 2026-10-29 (audits/security/clearbit-2026-10-29.md in the
//! meta-repo), finding H10.
//!
//! H10: `openDatabase` deleted RocksDB's `LOCK` file before every open, and
//!      the only other guard was an advisory PID file. A second clearbit on
//!      the same datadir therefore opened the live chainstate, deleted the
//!      first process's WAL and MANIFEST, and acknowledged blocks were gone
//!      after a restart. Core takes `<datadir>/.lock` and refuses a second
//!      instance (init.cpp LockDataDirectory, util/fs_helpers.cpp).
//!
//! RocksDB's lock is an fcntl record lock, which is per process: a second
//! open from this same process is refused by RocksDB's own in-process table
//! whether or not the LOCK file exists, so the open's result cannot tell the
//! two behaviours apart. The tests instead ask the kernel, through
//! /proc/locks, whether the file a second process would lock (the inode now
//! at `<chainstate>/LOCK`) is locked. The probe must not open the file:
//! closing any fd on it drops every fcntl lock this process holds there.

const std = @import("std");
const testing = std.testing;
const storage_rocksdb = @import("storage_rocksdb.zig");
const ops = @import("ops.zig");

/// What a second process would find on `path`: true when the inode now at
/// `path` carries a write lock in /proc/locks. FileNotFound when the file
/// has been removed. Never opens `path` (see the header comment).
fn lockHeldOn(path: []const u8) !bool {
    const st = try std.posix.fstatat(std.fs.cwd().fd, path, 0);
    const dev: u64 = st.dev;
    const major = ((dev >> 8) & 0xfff) | ((dev >> 32) & ~@as(u64, 0xfff));
    const minor = (dev & 0xff) | ((dev >> 12) & ~@as(u64, 0xff));
    var kbuf: [64]u8 = undefined;
    const key = try std.fmt.bufPrint(&kbuf, "{x:0>2}:{x:0>2}:{d}", .{ major, minor, st.ino });

    const locks = try std.fs.cwd().readFileAlloc(testing.allocator, "/proc/locks", 1 << 20);
    defer testing.allocator.free(locks);
    var lines = std.mem.splitScalar(u8, locks, '\n');
    while (lines.next()) |line| {
        // "1: POSIX  ADVISORY  WRITE 12345 103:02:4718597 0 EOF"
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        var fields: [8][]const u8 = undefined;
        var n: usize = 0;
        while (it.next()) |f| : (n += 1) {
            if (n == fields.len) break;
            fields[n] = f;
        }
        if (n < 6 or std.mem.eql(u8, fields[1], "->")) continue; // blocked waiter
        if (std.mem.eql(u8, fields[3], "WRITE") and std.mem.eql(u8, fields[5], key)) return true;
    }
    return false;
}

fn tmpPath(tmp: *std.testing.TmpDir, buf: []u8, comptime sub: []const u8) ![]const u8 {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &pbuf);
    return std.fmt.bufPrint(buf, "{s}/" ++ sub, .{root});
}

test "tests_sec_rocksdb_lock H10: a refused second open leaves the live chainstate locked" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const db_path = try tmpPath(&tmp, &dbuf, "chainstate");
    var lbuf: [std.fs.max_path_bytes]u8 = undefined;
    const lock_path = try std.fmt.bufPrint(&lbuf, "{s}/LOCK", .{db_path});

    var db = try storage_rocksdb.openDatabase(db_path, 8, allocator);
    defer storage_rocksdb.closeDatabase(&db);
    // Control: the probe sees the lock RocksDB took on open.
    try testing.expect(try lockHeldOn(lock_path));

    // A second open must fail and must not disturb the first one's lock.
    // Before the fix it deleted LOCK first, so the file a second process
    // would lock was a fresh, unlocked one (or none at all).
    try testing.expectError(error.OpenFailed, storage_rocksdb.openDatabase(db_path, 8, allocator));
    try testing.expect(try lockHeldOn(lock_path));
}

test "tests_sec_rocksdb_lock H10: a LOCK file left by an earlier process does not block reopening" {
    // The deletion existed to recover from a crash leaving LOCK behind. The
    // kernel drops an fcntl lock when its holder exits, so the file left on
    // disk is unlocked and RocksDB reopens over it.
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dbuf: [std.fs.max_path_bytes]u8 = undefined;
    const db_path = try tmpPath(&tmp, &dbuf, "chainstate");
    var lbuf: [std.fs.max_path_bytes]u8 = undefined;
    const lock_path = try std.fmt.bufPrint(&lbuf, "{s}/LOCK", .{db_path});

    var db = try storage_rocksdb.openDatabase(db_path, 8, allocator);
    storage_rocksdb.closeDatabase(&db);
    try testing.expect(!(try lockHeldOn(lock_path))); // file still there, unlocked

    var db2 = try storage_rocksdb.openDatabase(db_path, 8, allocator);
    defer storage_rocksdb.closeDatabase(&db2);
    try testing.expect(try lockHeldOn(lock_path));
}

// The lockDatadir tests reach the helper only when it exists, so on a tree
// without it they fail by name (error.NoDatadirLock) instead of stopping the
// whole file from compiling.
test "tests_sec_rocksdb_lock H10: lockDatadir refuses a second holder until the first releases" {
    return if (comptime @hasDecl(ops, "lockDatadir")) lockDatadirExclusive() else error.NoDatadirLock;
}

fn lockDatadirExclusive() !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const datadir = try tmp.dir.realpath(".", &pbuf);

    // A leftover .lock file (crash, or a clean stop) does not block anyone.
    try tmp.dir.writeFile(.{ .sub_path = ".lock", .data = "" });

    var first = try ops.lockDatadir(datadir);
    // flock conflicts between open file descriptions, so a second take from
    // this process is refused exactly as another process's would be.
    try testing.expectError(error.AlreadyLocked, ops.lockDatadir(datadir));
    try testing.expectError(error.AlreadyLocked, ops.lockDatadir(datadir));

    first.release();
    var again = try ops.lockDatadir(datadir);
    again.release();
}

test "tests_sec_rocksdb_lock H10: lockDatadir creates .lock owner-only and reports a missing datadir" {
    return if (comptime @hasDecl(ops, "lockDatadir")) lockDatadirModeAndMissing() else error.NoDatadirLock;
}

fn lockDatadirModeAndMissing() !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const datadir = try tmp.dir.realpath(".", &pbuf);

    var l = try ops.lockDatadir(datadir);
    defer l.release();
    const st = try tmp.dir.statFile(".lock");
    try testing.expectEqual(@as(u32, 0), @as(u32, @intCast(st.mode)) & 0o077);

    var mbuf: [std.fs.max_path_bytes]u8 = undefined;
    const missing = try std.fmt.bufPrint(&mbuf, "{s}/no/such/dir", .{datadir});
    try testing.expectError(error.OpenFailed, ops.lockDatadir(missing));
}
