//! cffix-clearbit-pushowned-overflow-leak (secscan2 S1-F2, LOW): a result buffer leaks
//! when `pushOwned` fails on stack overflow (src/script.zig:1605-1610).
//!
//! OP_1..OP_16 (and every other result-producing opcode) allocate the result
//! and then `try self.pushOwned(result)`. pushOwned returns StackOverflow
//! before it appends the buffer to `owned_elements`, so `deinit` never frees
//! it. In release builds the mempool's engine allocator is c_allocator
//! (main.zig:2163-2171), so each rejected script leaks one chunk.
//!
//! Core: the stack is a std::vector<valtype>; nothing can leak on
//! SCRIPT_ERR_STACK_SIZE (interpreter.cpp EvalScript, `stack.size() +
//! altstack.size() > MAX_STACK_SIZE`).
//!
//! Each test runs the engine on its own GeneralPurposeAllocator and checks
//! for leaks after `engine.deinit()`. On master the overflow test fails by
//! name and the two controls pass.
const std = @import("std");
const script = @import("script.zig");
const types = @import("types.zig");

const empty_tx = types.Transaction{
    .version = 1,
    .inputs = &[_]types.TxIn{},
    .outputs = &[_]types.TxOut{},
    .lock_time = 0,
};

/// Runs `n` copies of `op` on a fresh engine; returns the execute result and
/// whether the allocator saw a leak after deinit.
fn runAndCheckLeak(op: u8, n: usize) !struct { overflowed: bool, leaked: bool } {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const code = try std.testing.allocator.alloc(u8, n);
    defer std.testing.allocator.free(code);
    @memset(code, op);

    var engine = script.ScriptEngine.init(alloc, &empty_tx, 0, 0, script.ScriptFlags{});
    var overflowed = false;
    engine.execute(code) catch |e| {
        try std.testing.expectEqual(script.ScriptError.StackOverflow, e);
        overflowed = true;
    };
    engine.deinit();
    return .{ .overflowed = overflowed, .leaked = gpa.deinit() == .leak };
}

test "secscan2 F2: OP_1 x1001 overflows the stack without leaking the 1001st result" {
    const r = try runAndCheckLeak(0x51, 1001);
    try std.testing.expect(r.overflowed);
    try std.testing.expect(!r.leaked);
}

test "secscan2 F2 control: OP_1 x1000 fills the stack exactly, no overflow, no leak" {
    const r = try runAndCheckLeak(0x51, 1000);
    try std.testing.expect(!r.overflowed);
    try std.testing.expect(!r.leaked);
}

test "secscan2 F2 control: OP_0 x1001 overflows via push (no allocation), no leak" {
    const r = try runAndCheckLeak(0x00, 1001);
    try std.testing.expect(r.overflowed);
    try std.testing.expect(!r.leaked);
}

/// Body for checkAllAllocationFailures: OP_1 OP_2 OP_ADD OP_3 OP_EQUAL. OP_ADD's
/// result goes through pushOwned, so failing each allocation in turn reaches
/// pushOwned's own `owned_elements.append` failure with a live result buffer.
fn runArithmetic(alloc: std.mem.Allocator) !void {
    var engine = script.ScriptEngine.init(alloc, &empty_tx, 0, 0, script.ScriptFlags{});
    defer engine.deinit();
    _ = try engine.execute(&[_]u8{ 0x51, 0x52, 0x93, 0x53, 0x87 });
}

test "pushOwned: an allocation failure at any point leaks nothing and reports OutOfMemory" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, runArithmetic, .{});
}
