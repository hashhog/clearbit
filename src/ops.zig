//! Operational helpers for clearbit.
//!
//! Closes parts of the operational-parity gap with Bitcoin Core:
//!
//!   * `daemonize()`     — fork + setsid + dup stdio. Mirrors
//!                          `bitcoin-core/src/util/system.cpp daemon()`.
//!   * `writePidFile()`  — write `<pid>` to a file in `<datadir>/clearbit.pid`
//!                          (overridable via `--pid=<path>`). Mirrors
//!                          `bitcoin-core/src/init/common.cpp g_pidfile_path`.
//!   * `removePidFile()` — best-effort `unlink` on shutdown.
//!   * `sighup_requested` / `installSighupHandler` — async-signal-safe flag
//!                          set by the SIGHUP handler. Main loop drains it and
//!                          calls `LogState.reopen()` from a normal context.
//!   * `LogState`        — owns the open log fd; re-opens on SIGHUP so log
//!                          rotation tools (logrotate, copytruncate-and-HUP)
//!                          work as operators expect.
//!   * `notifyReadyFd()` — write `READY=1\n` to a passed-in fd, à la systemd
//!                          sd_notify. The ready signal is fired once after
//!                          all subsystems are listening.
//!
//! Everything here is platform-specific to Linux because the rest of clearbit
//! already assumes a POSIX environment (RocksDB, signal handling, sockets).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

// ---------------------------------------------------------------------------
// Daemonize
// ---------------------------------------------------------------------------

pub const DaemonError = error{
    ForkFailed,
    SetsidFailed,
    OpenDevNullFailed,
};

/// Fork into the background and detach from the controlling terminal.
///
/// On return:
///   - The child process executes the rest of main().
///   - The parent process exits with status 0.
///   - stdin/stdout/stderr are redirected to `/dev/null` unless
///     `keep_stderr` is true (rare; useful for early-startup diagnostics).
///
/// Mirrors POSIX `daemon(nochdir=1, noclose=0)` — we do NOT chdir to "/" so
/// the operator's --datadir relative paths still resolve.
pub fn daemonize(keep_stderr: bool) DaemonError!void {
    // First fork. linux.fork() returns the child PID (positive) to the
    // parent and 0 to the child. Errors come back as a -errno
    // (interpret as signed). We MUST use the raw `_exit` syscall (NOT
    // `std.posix.exit` / glibc `exit`) for the parent's exit. Reason:
    // when clearbit is linked against glibc + RocksDB, a normal exit()
    // runs atexit + stdio-flush + RocksDB destructors that may deadlock
    // on resources the daemon child is still holding (RocksDB MANIFEST
    // file lock, in particular). _exit jumps straight to exit_group(2).
    const pid1_raw = std.os.linux.fork();
    const pid1: isize = @as(isize, @bitCast(pid1_raw));
    if (pid1 < 0) return DaemonError.ForkFailed;
    if (pid1 != 0) {
        // Parent — exit_group syscall directly, bypass atexit handlers.
        _ = linux.syscall1(.exit_group, 0);
        unreachable;
    }

    // Child: become session leader so we have no controlling tty.
    if (linux.syscall0(.setsid) == @as(usize, @bitCast(@as(isize, -1)))) {
        return DaemonError.SetsidFailed;
    }

    // Second fork — guarantees we can never re-acquire a controlling tty.
    const pid2_raw = std.os.linux.fork();
    const pid2: isize = @as(isize, @bitCast(pid2_raw));
    if (pid2 < 0) return DaemonError.ForkFailed;
    if (pid2 != 0) {
        _ = linux.syscall1(.exit_group, 0);
        unreachable;
    }

    // Redirect stdio to /dev/null unless the operator asked us to keep
    // stderr (useful when --logfile is not yet open).
    const devnull_fd = std.posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0) catch
        return DaemonError.OpenDevNullFailed;
    defer std.posix.close(devnull_fd);

    std.posix.dup2(devnull_fd, std.posix.STDIN_FILENO) catch {};
    std.posix.dup2(devnull_fd, std.posix.STDOUT_FILENO) catch {};
    if (!keep_stderr) {
        std.posix.dup2(devnull_fd, std.posix.STDERR_FILENO) catch {};
    }
}

// ---------------------------------------------------------------------------
// PID file
// ---------------------------------------------------------------------------

pub const PidFileError = error{
    OpenFailed,
    WriteFailed,
    OutOfMemory,
};

/// Write the calling process's PID to `path`, creating it 0644.
/// Caller picks the path; main.zig defaults to `<datadir>/clearbit.pid`.
pub fn writePidFile(path: []const u8, allocator: std.mem.Allocator) PidFileError!void {
    const file = std.fs.createFileAbsolute(path, .{ .mode = 0o644 }) catch
        return PidFileError.OpenFailed;
    defer file.close();

    const pid: u32 = @intCast(linux.getpid());
    const text = std.fmt.allocPrint(allocator, "{d}\n", .{pid}) catch
        return PidFileError.OutOfMemory;
    defer allocator.free(text);

    file.writeAll(text) catch return PidFileError.WriteFailed;
}

/// Best-effort remove a PID file. Errors swallowed — used in shutdown only.
pub fn removePidFile(path: []const u8) void {
    std.fs.deleteFileAbsolute(path) catch {};
}

// ---------------------------------------------------------------------------
// SIGHUP — log reopen
// ---------------------------------------------------------------------------

/// Set by signalHandlerSighup; cleared by mainLoopHandleSighup. Async-signal
/// safe because we only touch atomics from the handler.
pub var sighup_requested = std.atomic.Value(bool).init(false);

fn sighupHandler(sig: c_int) callconv(.C) void {
    _ = sig;
    sighup_requested.store(true, .release);
}

/// Install the SIGHUP handler. Idempotent — main may call this once.
pub fn installSighupHandler() void {
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = sighupHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &sa, null) catch {};
}

/// Owns the optional log file fd. When `LogState.path` is null, the node
/// logs to stderr only (default). When set, all writes go to the file AND
/// to stderr unless `printtoconsole=false`.
///
/// Reopen: SIGHUP causes the next call to `maybeReopen()` to close and
/// reopen the file (preserving the same path). Used with logrotate's
/// `postrotate /bin/kill -HUP $(cat <pidfile>)` idiom.
pub const LogState = struct {
    allocator: std.mem.Allocator,
    path: ?[]u8 = null,
    fd: ?std.fs.File = null,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) LogState {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *LogState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.fd) |f| f.close();
        self.fd = null;
        if (self.path) |p| self.allocator.free(p);
        self.path = null;
    }

    /// Open or re-open the log file at `path`. Append-only.
    pub fn open(self: *LogState, path: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.fd) |f| {
            f.close();
            self.fd = null;
        }
        if (self.path) |p| {
            self.allocator.free(p);
            self.path = null;
        }

        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);

        const f = try std.fs.cwd().createFile(path, .{
            .read = false,
            .truncate = false,
        });
        // Seek to end so we append rather than overwriting.
        try f.seekFromEnd(0);
        self.fd = f;
        self.path = owned;
    }

    /// Drain the SIGHUP flag and re-open the log file if it's set.
    pub fn maybeReopen(self: *LogState) void {
        if (!sighup_requested.swap(false, .acq_rel)) return;
        const path_copy = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            const p = self.path orelse return;
            break :blk self.allocator.dupe(u8, p) catch return;
        };
        defer self.allocator.free(path_copy);
        self.open(path_copy) catch |err| {
            std.debug.print("SIGHUP: log reopen failed for {s}: {}\n", .{ path_copy, err });
        };
        std.debug.print("SIGHUP: log file reopened: {s}\n", .{path_copy});
    }
};

// ---------------------------------------------------------------------------
// Ready FD
// ---------------------------------------------------------------------------

/// Notify a parent supervisor (systemd, runit, daemontools) that the node is
/// ready. Writes "READY=1\n" to fd `n` and closes it. Fire-and-forget.
pub fn notifyReadyFd(n: i32) void {
    if (n < 0) return;
    const fd: std.posix.fd_t = @intCast(n);
    const msg = "READY=1\n";
    _ = std.posix.write(fd, msg) catch {};
    std.posix.close(fd);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "writePidFile + removePidFile round-trip" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const dir = tmp_dir.dir;
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try dir.realpath(".", &pbuf);
    const pid_path = try std.fmt.allocPrint(allocator, "{s}/clearbit.pid", .{tmp_path});
    defer allocator.free(pid_path);

    try writePidFile(pid_path, allocator);
    // File should exist.
    const f = try std.fs.openFileAbsolute(pid_path, .{});
    f.close();

    removePidFile(pid_path);
    // File should be gone.
    const open_err = std.fs.openFileAbsolute(pid_path, .{});
    try std.testing.expectError(error.FileNotFound, open_err);
}

test "sighup_requested round-trip" {
    sighup_requested.store(false, .release);
    sighupHandler(std.posix.SIG.HUP);
    try std.testing.expect(sighup_requested.load(.acquire));
    sighup_requested.store(false, .release);
}

test "LogState init+open+reopen+deinit" {
    var st = LogState.init(std.testing.allocator);
    defer st.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath(".", &pbuf);
    const log_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/test.log", .{tmp_path});
    defer std.testing.allocator.free(log_path);

    try st.open(log_path);
    try std.testing.expect(st.fd != null);
    try std.testing.expectEqualStrings(log_path, st.path.?);

    // Reopen path — same path again.
    try st.open(log_path);
    try std.testing.expect(st.fd != null);
}

test "LogState.maybeReopen no-op when flag unset" {
    sighup_requested.store(false, .release);
    var st = LogState.init(std.testing.allocator);
    defer st.deinit();
    // Should be a no-op even with no fd open.
    st.maybeReopen();
    try std.testing.expect(st.fd == null);
}
