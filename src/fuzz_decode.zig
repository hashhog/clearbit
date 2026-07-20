//! fuzz_decode.zig — structured mutation smoke-fuzzer for clearbit's P2P
//! message decoder (`p2p.decodePayload`), flagship #2's decoder.
//!
//! WHY THIS EXISTS. The rustoshi cargo-fuzz run found two remotely-triggerable
//! DoS bugs in *its* P2P decoder (an unbounded `Vec::with_capacity` OOM and a
//! `body_start + len` usize-overflow slice panic — see
//! receipts/decoder-security-audit-flagships.md). A source audit said clearbit
//! does not share that class, but a source read cannot rule out logic/panic
//! bugs. This harness turns a real fuzzer on clearbit's decoder to close that
//! gap — the recommended P1.2 follow-up from that audit.
//!
//! WHAT IT IS (scope honesty). Zig 0.13 has NO coverage-guided fuzzer
//! (`zig build --fuzz` landed in 0.14). This is therefore a deterministic,
//! seeded, mutation-based *smoke* fuzzer, not libFuzzer/AFL. It drives
//! `decodePayload` with random + mutated payloads across EVERY command, with a
//! lightweight "keep inputs that decoded" corpus as a poor-man's coverage
//! signal. It targets exactly the alloc / arithmetic / panic class the rustoshi
//! run found bugs in — not a substitute for coverage-guided fuzzing.
//!
//! HOW IT CATCHES BUGS.
//!   * Runtime safety is ON (build ReleaseSafe): an `@intCast` truncation, an
//!     integer overflow, or an out-of-bounds slice traps as a process abort —
//!     the panic handler below dumps the crashing {command, payload} to
//!     `fuzz-decode-crash.bin` and prints the seed+iteration for replay.
//!   * A FixedBufferAllocator caps total per-message allocation: an
//!     attacker-controlled count that tries to allocate gigabytes returns
//!     `error.OutOfMemory` gracefully (a legal decode failure) instead of
//!     OOMing the machine — so an *unbounded-alloc* bug shows up as the fuzzer
//!     never being able to make a single valid message exceed the cap, and a
//!     *runaway* alloc is contained rather than fatal to the box.
//!
//! Deterministic: same (seed, iteration) always produces the same input, so a
//! crash reproduces by re-running with the printed seed.
//!
//! Usage: fuzz-decode [iterations] [seed]
//!   iterations  default 20_000_000
//!   seed        default 0x5eed1234c0ffee

const std = @import("std");
const p2p = @import("p2p.zig");

/// Every command `decodePayload` dispatches on, plus a few bogus names to
/// exercise the `UnknownCommand` fall-through and the `std.mem.eql` chain.
const COMMANDS = [_][]const u8{
    "version",   "verack",     "ping",         "pong",       "inv",
    "getdata",   "notfound",   "getheaders",   "getblocks",  "headers",
    "sendheaders", "sendcmpct", "feefilter",   "block",      "tx",
    "wtxidrelay", "sendaddrv2", "addrv2",      "mempool",    "getaddr",
    "addr",      "reject",     "sendtxrcncl",  "reqrecon",   "sketch",
    "reconcildiff", "cmpctblock", "getblocktxn", "blocktxn",  "filterload",
    "filteradd", "filterclear", "merkleblock", "getcfilters", "cfilter",
    "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt",
    // bogus / edge command names
    "", "zzzz", "versionx", "TX",
};

/// One retained fuzzing input: a command index into COMMANDS plus a payload.
const Seed = struct {
    cmd: u8,
    data: []u8,
};

// --- crash-repro state: dumped by the panic handler on a safety trap. --------
var g_cmd_name: []const u8 = "";
var g_payload: []const u8 = &[_]u8{};
var g_iter: u64 = 0;
var g_seed: u64 = 0;

/// Root panic handler override. On any runtime-safety trap (the whole point of
/// running ReleaseSafe), best-effort dump the crashing input before delegating
/// to the default panic so we still get the stack trace.
pub fn panic(msg: []const u8, ert: ?*std.builtin.StackTrace, ra: ?usize) noreturn {
    if (std.fs.cwd().createFile("fuzz-decode-crash.bin", .{})) |file| {
        var w = file.writer();
        w.print("seed=0x{x} iter={d}\ncmd={s}\npayload_len={d}\npayload_hex=", .{
            g_seed, g_iter, g_cmd_name, g_payload.len,
        }) catch {};
        for (g_payload) |b| w.print("{x:0>2}", .{b}) catch {};
        w.writeByte('\n') catch {};
        file.close();
    } else |_| {}
    std.debug.print(
        "\n*** FUZZ-DECODE CRASH ***\n  seed=0x{x} iter={d} cmd=\"{s}\" payload_len={d}\n  reproducer -> fuzz-decode-crash.bin\n\n",
        .{ g_seed, g_iter, g_cmd_name, g_payload.len },
    );
    std.builtin.default_panic(msg, ert, ra);
}

/// Apply 1..8 random mutations to `buf` (already holding a base input).
fn mutate(buf: *std.ArrayList(u8), rnd: std.rand.Random) void {
    const rounds = rnd.intRangeAtMost(u8, 1, 8);
    var r: u8 = 0;
    while (r < rounds) : (r += 1) {
        if (buf.items.len == 0) {
            buf.append(rnd.int(u8)) catch return;
            continue;
        }
        switch (rnd.intRangeAtMost(u8, 0, 8)) {
            0 => { // bit flip
                const i = rnd.intRangeLessThan(usize, 0, buf.items.len);
                buf.items[i] ^= @as(u8, 1) << rnd.intRangeAtMost(u3, 0, 7);
            },
            1 => { // set random byte
                const i = rnd.intRangeLessThan(usize, 0, buf.items.len);
                buf.items[i] = rnd.int(u8);
            },
            2 => { // insert a byte
                const i = rnd.intRangeAtMost(usize, 0, buf.items.len);
                buf.insert(i, rnd.int(u8)) catch {};
            },
            3 => { // delete a byte
                const i = rnd.intRangeLessThan(usize, 0, buf.items.len);
                _ = buf.orderedRemove(i);
            },
            4 => { // truncate
                const n = rnd.intRangeAtMost(usize, 0, buf.items.len);
                buf.shrinkRetainingCapacity(n);
            },
            5 => { // fill a run with 0x00 or 0xff
                const i = rnd.intRangeLessThan(usize, 0, buf.items.len);
                const n = rnd.intRangeAtMost(usize, 1, buf.items.len - i);
                const v: u8 = if (rnd.boolean()) 0x00 else 0xff;
                @memset(buf.items[i .. i + n], v);
            },
            6 => { // overwrite the head with a hostile CompactSize prefix
                const markers = [_]u8{ 0xfd, 0xfe, 0xff };
                buf.items[0] = markers[rnd.intRangeAtMost(usize, 0, 2)];
                var k: usize = 1;
                while (k < buf.items.len and k <= 8) : (k += 1) buf.items[k] = rnd.int(u8);
            },
            7 => { // duplicate a range (grow structure)
                const i = rnd.intRangeLessThan(usize, 0, buf.items.len);
                const n = rnd.intRangeAtMost(usize, 1, @min(buf.items.len - i, 4096));
                // Copy through a stack temp so the append never aliases the
                // ArrayList's own (possibly reallocating) backing store.
                var tmp: [4096]u8 = undefined;
                @memcpy(tmp[0..n], buf.items[i .. i + n]);
                buf.appendSlice(tmp[0..n]) catch return;
            },
            else => { // append random bytes
                const n = rnd.intRangeAtMost(usize, 1, 32);
                var k: usize = 0;
                while (k < n) : (k += 1) buf.append(rnd.int(u8)) catch {};
            },
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    // --- args ---------------------------------------------------------------
    var iterations: u64 = 20_000_000;
    g_seed = 0x5eed1234c0ffee;
    {
        var it = std.process.args();
        _ = it.next(); // exe name
        if (it.next()) |a| iterations = std.fmt.parseInt(u64, a, 0) catch iterations;
        if (it.next()) |a| g_seed = std.fmt.parseInt(u64, a, 0) catch g_seed;
    }

    // --- allocation cap: 256 MiB bump arena, reset per iteration -------------
    // Any single message that tries to allocate past this gets OutOfMemory
    // (a legal decode failure), so a runaway/unbounded alloc is CONTAINED
    // rather than fatal to the host. A real 4 MB block + its txs fit easily.
    const CAP = 256 * 1024 * 1024;
    const backing = try std.heap.page_allocator.alloc(u8, CAP);
    defer std.heap.page_allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);

    // --- lightweight "kept" corpus (poor-man's coverage feedback) -----------
    var corpus = std.ArrayList(Seed).init(alloc);
    defer {
        for (corpus.items) |s| alloc.free(s.data);
        corpus.deinit();
    }
    const CORPUS_MAX = 8192;

    var prng = std.rand.DefaultPrng.init(g_seed);
    const rnd = prng.random();

    var scratch = std.ArrayList(u8).init(alloc);
    defer scratch.deinit();

    std.debug.print(
        "fuzz-decode: seed=0x{x} iterations={d} commands={d} cap={d}MiB (ReleaseSafe)\n",
        .{ g_seed, iterations, COMMANDS.len, CAP / 1024 / 1024 },
    );

    var timer = try std.time.Timer.start();
    var decoded_ok: u64 = 0;
    var last_report: u64 = 0;

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        g_iter = i;

        // --- choose command + build a candidate payload ---------------------
        var cmd_idx: u8 = rnd.intRangeLessThan(u8, 0, COMMANDS.len);
        scratch.clearRetainingCapacity();

        const use_corpus = corpus.items.len > 0 and rnd.intRangeAtMost(u8, 0, 3) != 0;
        if (use_corpus) {
            const base = corpus.items[rnd.intRangeLessThan(usize, 0, corpus.items.len)];
            cmd_idx = base.cmd;
            scratch.appendSlice(base.data) catch {};
            mutate(&scratch, rnd);
        } else {
            // fresh random payload, occasionally large to reach length paths
            const max_len: usize = if (rnd.intRangeAtMost(u8, 0, 15) == 0) 65535 else 512;
            const n = rnd.intRangeAtMost(usize, 0, max_len);
            var k: usize = 0;
            while (k < n) : (k += 1) scratch.append(rnd.int(u8)) catch {};
        }

        const cmd_name = COMMANDS[cmd_idx];

        // publish for the panic handler
        g_cmd_name = cmd_name;
        g_payload = scratch.items;

        // --- drive the decoder under the capped bump allocator --------------
        fba.reset();
        const msg = p2p.decodePayload(cmd_name, scratch.items, fba.allocator());
        if (msg) |_| {
            decoded_ok += 1;
            // Keep a copy as a mutation seed (bounded, biased toward valid).
            // Cap retained size so 8192 entries can't blow up host memory.
            if (corpus.items.len < CORPUS_MAX and scratch.items.len > 0 and scratch.items.len <= 8192) {
                const owned = alloc.dupe(u8, scratch.items) catch continue;
                corpus.append(.{ .cmd = cmd_idx, .data = owned }) catch alloc.free(owned);
            }
        } else |_| {
            // Every decode error is expected (garbage in). Not a bug.
        }

        // --- progress -------------------------------------------------------
        if (i - last_report >= 2_000_000) {
            last_report = i;
            const secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
            const rate = @as(f64, @floatFromInt(i + 1)) / secs;
            std.debug.print(
                "  {d:>12} iters  {d:>10} ok  corpus={d:>5}  {d:.0} exec/s\n",
                .{ i + 1, decoded_ok, corpus.items.len, rate },
            );
        }
    }

    const secs = @as(f64, @floatFromInt(timer.read())) / 1e9;
    std.debug.print(
        "fuzz-decode: DONE {d} iterations, {d} decoded-ok, corpus={d}, {d:.1}s, NO CRASH\n",
        .{ iterations, decoded_ok, corpus.items.len, secs },
    );
}
