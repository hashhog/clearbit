//! Tapscript condition stack must cost O(1) per opcode (Core ConditionStack).
//!
//! Bitcoin Core: script/interpreter.cpp `ConditionStack` keeps only the stack
//! size and the position of the first false entry, so `all_true()`,
//! `push_back()`, `pop_back()` and `toggle_top()` are all O(1). The comment
//! there says why: tapscript has no script-size or op-count limit, so a
//! linear `vfExec` scan per opcode is quadratic in the script length.
//!
//! clearbit kept the conditions in an `ArrayList(bool)` and `isExecuting`
//! scanned every entry for every opcode. BIP-342 removes MAX_SCRIPT_SIZE and
//! MAX_OPS_PER_SCRIPT for tapscript, so one standard 400 kWU tx carrying a
//! leaf of D nested true `OP_1 OP_IF` followed by D `OP_ENDIF` cost about
//! D^2/2 bool reads, run synchronously on the P2P thread from the tx handler.
//!
//! The cost test runs the same opcode multiset two ways:
//!   nested: (OP_1 OP_IF) x D, OP_ENDIF x D, OP_1   -> depth reaches D
//!   flat:   (OP_1 OP_IF OP_ENDIF) x D, OP_1        -> depth never above 1
//! Both execute 3D+1 opcodes. With an O(1) condition stack they cost the
//! same; with the linear scan the nested script is ~D/2 times dearer per
//! opcode. The test asserts nested <= 3x flat (best of 3 runs each), which
//! is self-calibrating against machine speed and build mode. Measured in a
//! Debug build on this host: base ratio 10.1 (flat 0.74 s, nested 7.5 s),
//! fixed ratio 0.98. `OP_1` allocates a stack element, which inflates both
//! sides equally, so a second variant uses the allocation-free `OP_0
//! OP_NOTIF` (also a true branch) and separates the two much further.
//!
//! The semantic tests are controls: they pin IF/NOTIF/ELSE/ENDIF behaviour
//! inside executed and unexecuted branches, and pass before and after.
//!
//! CONTROL: `zig build test-tapscript-condition-stack --summary all`

const std = @import("std");
const testing = std.testing;
const types = @import("src/types.zig");
const script = @import("src/script.zig");

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_RETURN: u8 = 0x6a;
const OP_DROP: u8 = 0x75;

const DEPTH: usize = 50_000;

const dummy_tx = types.Transaction{
    .version = 2,
    .inputs = &[_]types.TxIn{},
    .outputs = &[_]types.TxOut{},
    .lock_time = 0,
};

fn runTapscript(s: []const u8) script.ScriptError!usize {
    var engine = script.ScriptEngine.init(testing.allocator, &dummy_tx, 0, 0, .{});
    defer engine.deinit();
    engine.sig_version = .tapscript;
    try engine.execute(s);
    return engine.stack.items.len;
}

fn buildNested(allocator: std.mem.Allocator, d: usize, push: u8, cond: u8) ![]u8 {
    var s = try std.ArrayList(u8).initCapacity(allocator, 3 * d + 1);
    for (0..d) |_| s.appendSliceAssumeCapacity(&.{ push, cond });
    s.appendNTimesAssumeCapacity(OP_ENDIF, d);
    s.appendAssumeCapacity(OP_1);
    return s.toOwnedSlice();
}

fn buildFlat(allocator: std.mem.Allocator, d: usize, push: u8, cond: u8) ![]u8 {
    var s = try std.ArrayList(u8).initCapacity(allocator, 3 * d + 1);
    for (0..d) |_| s.appendSliceAssumeCapacity(&.{ push, cond, OP_ENDIF });
    s.appendAssumeCapacity(OP_1);
    return s.toOwnedSlice();
}

fn bestOf3(s: []const u8) !u64 {
    var best: u64 = std.math.maxInt(u64);
    for (0..3) |_| {
        var timer = try std.time.Timer.start();
        const depth = try runTapscript(s);
        const ns = timer.read();
        try testing.expectEqual(@as(usize, 1), depth);
        best = @min(best, ns);
    }
    return best;
}

fn expectLinear(push: u8, cond: u8, label: []const u8) !void {
    const nested = try buildNested(testing.allocator, DEPTH, push, cond);
    defer testing.allocator.free(nested);
    const flat = try buildFlat(testing.allocator, DEPTH, push, cond);
    defer testing.allocator.free(flat);
    try testing.expectEqual(nested.len, flat.len);

    // Warm the allocator once so the first measured run is not an outlier.
    _ = try runTapscript(flat);

    const flat_ns = try bestOf3(flat);
    const nested_ns = try bestOf3(nested);
    std.debug.print(
        "\n  condition stack {s} D={d}: flat {d} us, nested {d} us, ratio {d:.2}\n",
        .{ label, DEPTH, flat_ns / 1000, nested_ns / 1000, @as(f64, @floatFromInt(nested_ns)) / @as(f64, @floatFromInt(@max(flat_ns, 1))) },
    );
    try testing.expect(nested_ns <= 3 * flat_ns);
}

test "tests_tapscript_condition_stack: 50k nested true OP_IF costs the same as 50k flat OP_IF" {
    try expectLinear(OP_1, OP_IF, "OP_1 OP_IF");
}

test "tests_tapscript_condition_stack: 50k nested true OP_NOTIF costs the same as 50k flat OP_NOTIF" {
    try expectLinear(OP_0, OP_NOTIF, "OP_0 OP_NOTIF");
}

test "tests_tapscript_condition_stack: deep nesting with a false branch at the bottom" {
    // D-1 true IFs, then a false IF whose body would fail if executed, then
    // unwinding. The OP_RETURN must be skipped; the trailing OP_1 runs.
    const allocator = testing.allocator;
    const d: usize = 10_000;
    var s = std.ArrayList(u8).init(allocator);
    defer s.deinit();
    for (0..d - 1) |_| try s.appendSlice(&.{ OP_1, OP_IF });
    try s.appendSlice(&.{ OP_0, OP_IF, OP_1, OP_IF, OP_RETURN, OP_ENDIF, OP_ENDIF });
    try s.appendNTimes(OP_ENDIF, d - 1);
    try s.append(OP_1);
    try testing.expectEqual(@as(usize, 1), try runTapscript(s.items));
}

test "tests_tapscript_condition_stack: ELSE inside an unexecuted branch stays unexecuted" {
    // 0 IF  1 IF RETURN ELSE RETURN ENDIF  ELSE  2 ENDIF
    // Inner IF/ELSE are inside a false branch: neither arm may run.
    const s = [_]u8{ OP_0, OP_IF, OP_1, OP_IF, OP_RETURN, OP_ELSE, OP_RETURN, OP_ENDIF, OP_ELSE, OP_2, OP_ENDIF };
    try testing.expectEqual(@as(usize, 1), try runTapscript(&s));

    // Same shape, outer false entry is two levels up: 0 IF 1 IF 1 IF RETURN ELSE RETURN ENDIF ENDIF ENDIF 1
    const s2 = [_]u8{ OP_0, OP_IF, OP_1, OP_IF, OP_1, OP_IF, OP_RETURN, OP_ELSE, OP_RETURN, OP_ENDIF, OP_ENDIF, OP_ENDIF, OP_1 };
    try testing.expectEqual(@as(usize, 1), try runTapscript(&s2));
}

test "tests_tapscript_condition_stack: ELSE flips an executed branch and its parent resumes" {
    // 1 IF 0 IF RETURN ELSE 2 ENDIF ELSE RETURN ENDIF 1  -> stack [2, 1]
    const s = [_]u8{ OP_1, OP_IF, OP_0, OP_IF, OP_RETURN, OP_ELSE, OP_2, OP_ENDIF, OP_ELSE, OP_RETURN, OP_ENDIF, OP_1 };
    try testing.expectEqual(@as(usize, 2), try runTapscript(&s));

    // NOTIF with a false argument executes; ELSE ELSE re-enters.
    // 0 NOTIF 1 ELSE RETURN ELSE 2 ENDIF -> stack [1, 2]
    const s2 = [_]u8{ OP_0, OP_NOTIF, OP_1, OP_ELSE, OP_RETURN, OP_ELSE, OP_2, OP_ENDIF };
    try testing.expectEqual(@as(usize, 2), try runTapscript(&s2));

    // After the false entry is popped, the true parent executes again.
    // 1 IF 0 IF RETURN ENDIF 2 ENDIF -> stack [2]
    const s3 = [_]u8{ OP_1, OP_IF, OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_2, OP_ENDIF };
    try testing.expectEqual(@as(usize, 1), try runTapscript(&s3));
}

test "tests_tapscript_condition_stack: unbalanced conditionals still fail" {
    try testing.expectError(script.ScriptError.UnbalancedConditional, runTapscript(&[_]u8{ OP_1, OP_IF }));
    try testing.expectError(script.ScriptError.UnbalancedConditional, runTapscript(&[_]u8{OP_ENDIF}));
    try testing.expectError(script.ScriptError.UnbalancedConditional, runTapscript(&[_]u8{OP_ELSE}));
    // ELSE / ENDIF underflow inside an unexecuted region is also caught.
    try testing.expectError(script.ScriptError.UnbalancedConditional, runTapscript(&[_]u8{ OP_0, OP_IF, OP_ENDIF, OP_ENDIF }));
    try testing.expectError(script.ScriptError.UnbalancedConditional, runTapscript(&[_]u8{ OP_0, OP_IF, OP_1, OP_DROP }));
}
