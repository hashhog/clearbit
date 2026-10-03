//! Gate 5: the process stays alive after logging `exit`.
//!
//! Observed 2026-10-02 22:39Z: mempool dumped, chainstate flushed, "closing
//! DB", "stopped", "exit", anchors saved — then still alive at stop_mainnet's
//! 60s grace and SIGKILL. The "exit" line is printed and then `main` returns,
//! so every `defer` runs: wallet save, block-index free, anchor/peers save,
//! mempool free, UTXO-cache walk, rocksdb_close (block cache), script-worker
//! join. The cache walks fault a swapped-out heap back in. The fix is
//! `std.process.exit` after the durable writes, which does not run those
//! defers; the kernel drops the address space without reading swap.
//!
//! CONTROL: `zig build test-shutdown-fast-exit --summary new`
//! Before the fix the source contract below is red. The fork tests are the
//! instrument check: `std.process.exit` must skip a deferred write, and a
//! shutdown that returns must NOT (otherwise the first fork test measures
//! nothing).

const std = @import("std");
const testing = std.testing;
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");
const main_mod = @import("src/main.zig");
const storage = @import("src/storage.zig");

const main_src = @embedFile("src/main.zig");

fn lineIsComment(src: []const u8, at: usize) bool {
    const line_start = if (std.mem.lastIndexOfScalar(u8, src[0..at], '\n')) |n| n + 1 else 0;
    const line = src[line_start..at];
    return std.mem.indexOf(u8, line, "//") != null;
}

fn hasCall(src: []const u8, needle: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, needle)) |at| {
        if (!lineIsComment(src, at)) return true;
        i = at + needle.len;
    }
    return false;
}

fn exitStatus(status: u32) ?u8 {
    // WIFEXITED: low 7 bits clear. WEXITSTATUS is the high byte.
    if ((status & 0x7f) != 0) return null;
    return @intCast((status >> 8) & 0xff);
}

test "shutdown_fast_exit: exit log is followed by process termination, not deferred heap teardown" {
    const marker = "std.debug.print(\"exit\\n\", .{});";
    const at = std.mem.indexOf(u8, main_src, marker) orelse {
        std.debug.print("RED: main.zig has no exit log line\n", .{});
        return error.Fail;
    };
    const end = std.mem.indexOfPos(u8, main_src, at, "fn metricsServerThread") orelse main_src.len;
    const tail = main_src[at..end];
    if (!hasCall(tail, "finishShutdown()")) {
        std.debug.print(
            "RED: after logging exit, main returns and its defers free the UTXO cache, mempool, block index, and RocksDB block cache (swapped-out heap; misses the 60s stop grace).\nTAIL:\n{s}\n",
            .{tail},
        );
        return error.Fail;
    }

    const fn_at = std.mem.indexOf(u8, main_src, "pub fn finishShutdown()") orelse {
        std.debug.print("RED: finishShutdown is not defined\n", .{});
        return error.Fail;
    };
    const fn_end = std.mem.indexOfPos(u8, main_src, fn_at, "\nfn ") orelse main_src.len;
    const fn_body = main_src[fn_at..fn_end];
    if (!hasCall(fn_body, "std.process.exit(0)")) {
        std.debug.print("RED: finishShutdown does not call std.process.exit(0)\n{s}\n", .{fn_body});
        return error.Fail;
    }

    // Durable state that used to live in defers AFTER the exit log must run
    // before termination. chain_state.flush() is not enough: anchors, bans,
    // peers.dat and wallets were saved only from deinit.
    const exit_call = std.mem.indexOfPos(u8, main_src, at, "finishShutdown()") orelse return error.Fail;
    const shutdown_start = std.mem.lastIndexOf(u8, main_src[0..at], "Graceful shutdown") orelse {
        std.debug.print("RED: shutdown section marker missing\n", .{});
        return error.Fail;
    };
    const window = main_src[shutdown_start..exit_call];
    if (!hasCall(window, "persistForShutdown()")) {
        std.debug.print("RED: anchors/bans/peers.dat are not persisted before finishShutdown\n", .{});
        return error.Fail;
    }
    if (!hasCall(window, "saveAll()")) {
        std.debug.print("RED: wallets are not saved before finishShutdown\n", .{});
        return error.Fail;
    }
    if (!hasCall(window, "cancelBackgroundWork()")) {
        std.debug.print("RED: RocksDB background work is not cancelled before finishShutdown\n", .{});
        return error.Fail;
    }
}

/// Instrument: a deferred write runs when the function returns.
fn returningShutdown(fd: i32) void {
    const buf = std.heap.c_allocator.alloc(u8, 64) catch std.posix.exit(4);
    defer std.heap.c_allocator.free(buf);
    defer {
        _ = std.posix.write(fd, "freed") catch {};
    }
}

/// Instrument: std.process.exit must NOT run the deferred write. This is the
/// same call finishShutdown makes. If this test ever goes green while the
/// deferred write still happens, the source contract above is not measuring
/// the process-exit behavior.
fn exitingShutdown(fd: i32) void {
    const buf = std.heap.c_allocator.alloc(u8, 8 * 1024 * 1024) catch std.posix.exit(4);
    defer std.heap.c_allocator.free(buf);
    defer {
        _ = std.posix.write(fd, "freed") catch {};
    }
    std.process.exit(0);
}

fn forkAndRead(comptime childFn: fn (i32) void) !struct { n: usize, code: ?u8 } {
    const fds = try std.posix.pipe();
    const pid = try std.posix.fork();
    if (pid == 0) {
        std.posix.close(fds[0]);
        // The test binary is a zig build server client (`--listen`). Drop
        // every inherited fd except the pipe so a child libc exit cannot
        // write on that socket and tear down the parent's result protocol.
        // linux.close ignores EBADF; std.posix.close treats it as unreachable.
        var fd: i32 = 3;
        while (fd < 256) : (fd += 1) {
            if (fd == fds[1]) continue;
            _ = std.os.linux.close(fd);
        }
        childFn(fds[1]);
        // returningShutdown comes back here; exitingShutdown does not.
        // exit_group skips atexit so this path also stays off the listen socket.
        std.os.linux.exit_group(0);
    }
    std.posix.close(fds[1]);
    var buf: [16]u8 = undefined;
    const n = std.posix.read(fds[0], &buf) catch 0;
    std.posix.close(fds[0]);
    const res = std.posix.waitpid(pid, 0);
    return .{ .n = n, .code = exitStatus(res.status) };
}

test "shutdown_fast_exit: negative control — returning runs the deferred free" {
    const got = try forkAndRead(returningShutdown);
    try testing.expectEqual(@as(usize, 5), got.n); // "freed"
    try testing.expectEqual(@as(?u8, 0), got.code);
}

test "shutdown_fast_exit: std.process.exit skips the deferred free" {
    const got = try forkAndRead(exitingShutdown);
    try testing.expectEqual(@as(usize, 0), got.n);
    try testing.expectEqual(@as(?u8, 0), got.code);
}

fn callFinishShutdown(_: i32) void {
    main_mod.finishShutdown();
}

test "shutdown_fast_exit: finishShutdown is process.exit, not a return into defers" {
    const got = try forkAndRead(callFinishShutdown);
    try testing.expectEqual(@as(usize, 0), got.n);
    try testing.expectEqual(@as(?u8, 0), got.code);
}

test "shutdown_fast_exit: persistForShutdown writes anchors, bans, and peers.dat" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);

    const anchor_path = try std.fmt.allocPrint(testing.allocator, "{s}/anchors.dat", .{dir_path});
    defer testing.allocator.free(anchor_path);
    const ban_path = try std.fmt.allocPrint(testing.allocator, "{s}/banlist.json", .{dir_path});
    defer testing.allocator.free(ban_path);

    var pm = peer_mod.PeerManager.init(testing.allocator, &consensus.REGTEST);
    defer pm.deinit();
    pm.anchors_path = anchor_path;
    pm.ban_list.file_path = ban_path;
    pm.data_dir = dir_path;
    try pm.ban_list.ban(.{ 8, 8, 8, 8 }, 3600, "shutdown-test");
    try pm.addAddress(std.net.Address.initIp4(.{ 1, 2, 3, 4 }, 8333), 1, .dns_seed);

    pm.persistForShutdown();

    const anchors = try tmp.dir.readFileAlloc(testing.allocator, "anchors.dat", 64 * 1024);
    defer testing.allocator.free(anchors);
    try testing.expect(std.mem.indexOf(u8, anchors, "\"anchors\"") != null);

    const bans = try tmp.dir.readFileAlloc(testing.allocator, "banlist.json", 64 * 1024);
    defer testing.allocator.free(bans);
    try testing.expect(std.mem.indexOf(u8, bans, "8.8.8.8") != null);

    const peers = try tmp.dir.readFileAlloc(testing.allocator, "peers.dat", 1024 * 1024);
    defer testing.allocator.free(peers);
    try testing.expect(std.mem.startsWith(u8, peers, "ADDRMAN "));

    // Not torn down: a second save still writes. deinit would have freed
    // addrman; calling persist again is the use-after-free discriminator.
    pm.persistForShutdown();
}

// ---------------------------------------------------------------------------
// The shutdown no longer writes RocksDB memtables to SST (it cost 2.5-4.5 s
// of the 30 s watchdog). It fsyncs the WAL instead. Claim: everything a
// committed write put in a memtable is recovered from the WAL on the next
// open, so a process that exits without close() or a memtable flush loses
// nothing. Instrument: copy the DB directory while the DB is still open and
// unflushed -- the files as they are now are exactly what process exit leaves
// -- and open the copy. Negative control: the same copy WITHOUT the WAL files
// must lose the write, otherwise the positive check is not measuring the WAL.

fn copyDbFiles(src: std.fs.Dir, dst: std.fs.Dir, keep_wal: bool) !usize {
    var copied: usize = 0;
    var it = src.iterate();
    while (try it.next()) |e| {
        if (e.kind != .file) continue;
        // WAL segments are NNNNNN.log; the info log is "LOG".
        if (!keep_wal and std.mem.endsWith(u8, e.name, ".log")) continue;
        try src.copyFile(e.name, dst, e.name, .{});
        copied += 1;
    }
    return copied;
}

fn exitCopyKeepsWrite(keep_wal: bool) !bool {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makeDir("live");
    try tmp.dir.makeDir("exited");
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &buf);
    const live = try std.fmt.allocPrint(testing.allocator, "{s}/live", .{root});
    defer testing.allocator.free(live);
    const exited = try std.fmt.allocPrint(testing.allocator, "{s}/exited", .{root});
    defer testing.allocator.free(exited);

    var db = try storage.Database.open(live, 8, testing.allocator);
    defer db.close();
    try db.writeBatch(&[_]storage.BatchOp{
        .{ .put = .{ .cf = storage.CF_UTXO, .key = "gate5-utxo", .value = "coin" } },
    });
    try db.put(storage.CF_BLOCK_INDEX, "gate5-tip", "tip");
    // What shutdown now does before process exit.
    try db.syncWal();

    var src = try tmp.dir.openDir("live", .{ .iterate = true });
    defer src.close();
    var dst = try tmp.dir.openDir("exited", .{});
    defer dst.close();
    _ = try copyDbFiles(src, dst, keep_wal);

    var db2 = try storage.Database.open(exited, 8, testing.allocator);
    defer db2.close();
    const a = try db2.get(storage.CF_UTXO, "gate5-utxo");
    defer if (a) |v| testing.allocator.free(v);
    const b = try db2.get(storage.CF_BLOCK_INDEX, "gate5-tip");
    defer if (b) |v| testing.allocator.free(v);
    return a != null and b != null and std.mem.eql(u8, a.?, "coin") and std.mem.eql(u8, b.?, "tip");
}

test "shutdown_fast_exit: unflushed memtable writes survive process exit via the WAL" {
    try testing.expect(try exitCopyKeepsWrite(true));
}

test "shutdown_fast_exit: negative control -- without the WAL files the same writes are lost" {
    try testing.expect(!(try exitCopyKeepsWrite(false)));
}

test "shutdown_fast_exit: shutdown syncs the WAL instead of flushing memtables" {
    const exit_call = std.mem.indexOf(u8, main_src, "finishShutdown();") orelse return error.Fail;
    const shutdown_start = std.mem.lastIndexOf(u8, main_src[0..exit_call], "Graceful shutdown") orelse return error.Fail;
    const window = main_src[shutdown_start..exit_call];
    try testing.expect(hasCall(window, "p.syncWal()"));
    try testing.expect(!hasCall(window, "p.flush()"));
}
