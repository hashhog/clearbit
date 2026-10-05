//! Gate 6 fault-injection tests (receipts/gate6-resource-limit-audit-2026-10-04.md,
//! clearbit section): a resource / system fault while checking a script must
//! never become a verdict — neither an ACCEPT (`<sig> <pk> CHECKSIG NOT` passing
//! because a sighash allocation or the secp context failed and CHECKSIG pushed
//! false) nor a REJECT (a valid spend reported as script-failed).
//!
//! These tests compile against the pre-fix tree plus the fault HOOKS only
//! (crypto.test_fault_secp_unavailable, validation.test_job_backing_allocator,
//! fatal.zig as an inert observation module) so each one can be shown to FAIL
//! there and PASS on the fix.  Errors introduced by the fix are matched by
//! @errorName so the file compiles on both trees.
//!
//! Controls (must pass on BOTH trees): a genuinely invalid signature still makes
//! CHECKSIG false (so CHECKSIG NOT is true, NULLFAIL being off for blocks) and a
//! valid signature still makes CHECKSIG NOT fail — the fault-free verdicts are
//! unchanged.

const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const script = @import("script.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const validation = @import("validation.zig");
const consensus = @import("consensus.zig");
const fatal = @import("fatal.zig");
const secp = @import("secp.zig").c;

const OP_CHECKSIG: u8 = 0xac;
const OP_NOT: u8 = 0x91;
const OP_0: u8 = 0x00;
const OP_TRUE: u8 = 0x51;

/// Block-context consensus flags at a modern mainnet height: NULLFAIL is OFF
/// (policy-only in Core), which is what makes a CHECKSIG that wrongly pushes
/// false turn `CHECKSIG NOT` into an accept.
fn blockFlags() script.ScriptFlags {
    const f = validation.getBlockScriptFlags(800_000, &consensus.MAINNET);
    std.debug.assert(!f.verify_nullfail);
    return f;
}

const Key = struct {
    seckey: [32]u8,
    pubkey: [33]u8,
};

fn testCtx() !*secp.secp256k1_context {
    return secp.secp256k1_context_create(secp.SECP256K1_CONTEXT_SIGN | secp.SECP256K1_CONTEXT_VERIFY) orelse
        error.SecpContextFailed;
}

fn makeKey(ctx: *secp.secp256k1_context) !Key {
    var k = Key{ .seckey = [_]u8{0x42} ** 32, .pubkey = undefined };
    var pk: secp.secp256k1_pubkey = undefined;
    if (secp.secp256k1_ec_pubkey_create(ctx, &pk, &k.seckey) != 1) return error.KeyFailed;
    var len: usize = 33;
    if (secp.secp256k1_ec_pubkey_serialize(ctx, &k.pubkey, &len, &pk, secp.SECP256K1_EC_COMPRESSED) != 1) return error.KeyFailed;
    return k;
}

/// DER signature over `msg` with SIGHASH_ALL appended.  `corrupt` flips a byte
/// of S so the encoding stays valid DER but the signature does not verify.
fn signDer(ctx: *secp.secp256k1_context, key: *const Key, msg: *const [32]u8, out: *[80]u8, corrupt: bool) !usize {
    var sig: secp.secp256k1_ecdsa_signature = undefined;
    if (secp.secp256k1_ecdsa_sign(ctx, &sig, msg, &key.seckey, null, null) != 1) return error.SignFailed;
    var len: usize = 72;
    if (secp.secp256k1_ecdsa_signature_serialize_der(ctx, out, &len, &sig) != 1) return error.SignFailed;
    if (corrupt) out[len - 2] ^= 0x01;
    out[len] = 0x01; // SIGHASH_ALL
    return len + 1;
}

/// A one-input spend of `prev_spk` (amount 50_000) whose input is signed for
/// `script_code`.  Legacy: script_sig = <sig>; segwit v0: witness = [sig, ws].
const Spend = struct {
    tx: types.Transaction,
    inputs: [1]types.TxIn,
    outputs: [1]types.TxOut,
    sig_buf: [80]u8 = undefined,
    sig_len: usize = 0,
    script_sig_buf: [81]u8 = undefined,
    witness_items: [2][]const u8 = undefined,
    spk: []const u8,
    amounts: [1]i64 = .{50_000},
    scripts: [1][]const u8 = undefined,

    fn sig(self: *const Spend) []const u8 {
        return self.sig_buf[0..self.sig_len];
    }
};

const out_spk = [_]u8{OP_TRUE};

fn initSpendTx(s: *Spend, spk: []const u8) void {
    s.spk = spk;
    s.scripts = .{spk};
    s.inputs = .{.{
        .previous_output = .{ .hash = [_]u8{0x5A} ** 32, .index = 0 },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};
    s.outputs = .{.{ .value = 40_000, .script_pubkey = &out_spk }};
    s.tx = .{ .version = 1, .inputs = &s.inputs, .outputs = &s.outputs, .lock_time = 0 };
}

/// Legacy `<pk> CHECKSIG [NOT]` spend: scriptSig = <sig>.
fn legacySpend(s: *Spend, ctx: *secp.secp256k1_context, key: *const Key, spk: []const u8, corrupt: bool) !void {
    initSpendTx(s, spk);
    const sh = try script.legacySignatureHash(testing.allocator, &s.tx, 0, spk, 1);
    s.sig_len = try signDer(ctx, key, &sh, &s.sig_buf, corrupt);
    s.script_sig_buf[0] = @intCast(s.sig_len);
    @memcpy(s.script_sig_buf[1 .. 1 + s.sig_len], s.sig());
    s.inputs[0].script_sig = s.script_sig_buf[0 .. 1 + s.sig_len];
}

/// P2WSH spend of witness script `ws`: witness = [<sig>, ws].
fn p2wshSpend(s: *Spend, ctx: *secp.secp256k1_context, key: *const Key, ws: []const u8, spk_buf: *[34]u8, corrupt: bool) !void {
    spk_buf[0] = OP_0;
    spk_buf[1] = 0x20;
    std.crypto.hash.sha2.Sha256.hash(ws, spk_buf[2..34], .{});
    initSpendTx(s, spk_buf);
    const sh = try crypto.segwitSighash(&s.tx, 0, ws, s.amounts[0], 1, testing.allocator);
    s.sig_len = try signDer(ctx, key, &sh, &s.sig_buf, corrupt);
    s.witness_items = .{ s.sig(), ws };
    s.inputs[0].witness = &s.witness_items;
}

fn pkScript(key: *const Key, comptime with_not: bool, buf: *[36]u8) []const u8 {
    buf[0] = 33;
    @memcpy(buf[1..34], &key.pubkey);
    buf[34] = OP_CHECKSIG;
    if (with_not) {
        buf[35] = OP_NOT;
        return buf[0..36];
    }
    return buf[0..35];
}

fn runEngine(a: std.mem.Allocator, s: *const Spend) script.ScriptError!bool {
    var engine = script.ScriptEngine.initWithPrevouts(a, &s.tx, 0, s.amounts[0], blockFlags(), &s.amounts, &s.scripts);
    defer engine.deinit();
    return engine.verify(s.inputs[0].script_sig, s.spk, s.inputs[0].witness);
}

fn isSystemErrName(e: anyerror) bool {
    const n = @errorName(e);
    return std.mem.eql(u8, n, "OutOfMemory") or std.mem.eql(u8, n, "InternalError");
}

/// The script's verdict without faults: true = passes, false = fails (either
/// a false final stack or a consensus ScriptError).  A system error here is a
/// test failure.
fn verdict(r: script.ScriptError!bool) !bool {
    if (r) |ok| return ok else |e| {
        if (isSystemErrName(e)) return error.UnexpectedSystemError;
        return false;
    }
}

/// OOM sweep: inject ONE allocation failure at each allocation index of one
/// script verification (the allocator recovers afterwards — a transient
/// fault; a persistent one would also fail the very next push and hide a
/// swallowed error behind a later OutOfMemory).  Every faulted run must end
/// in a SYSTEM error — never `true` (an accept) and never a script verdict.
/// Returns the number of faulted runs (instrument check: faults happened).
fn oomSweep(s: *const Spend) !usize {
    var faulted: usize = 0;
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        var fa = OnceFailing{ .backing = std.heap.c_allocator, .n = i };
        const r = runEngine(fa.allocator(), s);
        if (!fa.fired) return faulted; // ran clean: sweep complete
        faulted += 1;
        if (r) |ok| {
            std.debug.print("gate6 sweep: fault at alloc #{d} -> script returned {} (must be a system error)\n", .{ i, ok });
            return error.FaultBecameVerdict;
        } else |e| {
            if (!isSystemErrName(e)) {
                std.debug.print("gate6 sweep: fault at alloc #{d} -> {s} (a consensus error; must be a system error)\n", .{ i, @errorName(e) });
                return error.FaultBecameVerdict;
            }
        }
    }
    return error.SweepDidNotTerminate;
}

// ---------------------------------------------------------------------------
// Interpreter level (script.zig)
// ---------------------------------------------------------------------------

test "gate6: controls — fault-free CHECKSIG / CHECKSIG NOT verdicts (block flags, NULLFAIL off)" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b1: [36]u8 = undefined;
    var b2: [36]u8 = undefined;
    const spk_cs = pkScript(&key, false, &b1);
    const spk_not = pkScript(&key, true, &b2);

    var s: Spend = undefined;
    try legacySpend(&s, ctx, &key, spk_cs, false);
    try testing.expect(try verdict(runEngine(testing.allocator, &s))); // valid sig: CHECKSIG passes
    try legacySpend(&s, ctx, &key, spk_not, false);
    try testing.expect(!try verdict(runEngine(testing.allocator, &s))); // valid sig: CHECKSIG NOT fails
    try legacySpend(&s, ctx, &key, spk_not, true);
    try testing.expect(try verdict(runEngine(testing.allocator, &s))); // invalid sig: CHECKSIG NOT passes (NULLFAIL off)
    try legacySpend(&s, ctx, &key, spk_cs, true);
    try testing.expect(!try verdict(runEngine(testing.allocator, &s))); // invalid sig: CHECKSIG fails
}

test "gate6: legacy sighash OOM sweep — <validsig> <pk> CHECKSIG NOT never passes, every fault is a system error" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var s: Spend = undefined;
    try legacySpend(&s, ctx, &key, pkScript(&key, true, &b), false);
    const faulted = try oomSweep(&s);
    try testing.expect(faulted > 0); // instrument check: faults were injected
}

test "gate6: legacy OOM sweep — a VALID <sig> <pk> CHECKSIG spend is never judged invalid under a fault" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var s: Spend = undefined;
    try legacySpend(&s, ctx, &key, pkScript(&key, false, &b), false);
    try testing.expect(try oomSweep(&s) > 0);
}

test "gate6: segwit-v0 sighash OOM sweep — P2WSH <validsig> <pk> CHECKSIG NOT never passes" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var spk_buf: [34]u8 = undefined;
    var s: Spend = undefined;
    try p2wshSpend(&s, ctx, &key, pkScript(&key, true, &b), &spk_buf, false);
    // control (fault-free): valid sig -> CHECKSIG NOT fails
    try testing.expect(!try verdict(runEngine(testing.allocator, &s)));
    try testing.expect(try oomSweep(&s) > 0);
}

test "gate6: secp context unavailable — CHECKSIG NOT with a valid sig is a system error, not an accept" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var s: Spend = undefined;
    try legacySpend(&s, ctx, &key, pkScript(&key, true, &b), false);

    crypto.test_fault_secp_unavailable = true;
    defer crypto.test_fault_secp_unavailable = false;
    const r = runEngine(testing.allocator, &s);
    if (r) |ok| {
        std.debug.print("gate6: secp unavailable -> CHECKSIG NOT returned {} (pre-fix: true = ACCEPT)\n", .{ok});
        return error.FaultBecameVerdict;
    } else |e| try testing.expect(isSystemErrName(e));
}

test "gate6: secp context unavailable — a VALID segwit CHECKSIG spend is a system error, not a reject" {
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var spk_buf: [34]u8 = undefined;
    var s: Spend = undefined;
    try p2wshSpend(&s, ctx, &key, pkScript(&key, false, &b), &spk_buf, false);
    try testing.expect(try verdict(runEngine(testing.allocator, &s))); // control

    crypto.test_fault_secp_unavailable = true;
    defer crypto.test_fault_secp_unavailable = false;
    if (runEngine(testing.allocator, &s)) |ok| {
        std.debug.print("gate6: secp unavailable -> valid CHECKSIG returned {} (must be a system error)\n", .{ok});
        return error.FaultBecameVerdict;
    } else |e| try testing.expect(isSystemErrName(e));
}

// ---------------------------------------------------------------------------
// Block level (validation.verifyBlockScriptsParallel: check queue + sig cache,
// and the single-threaded fallback)
// ---------------------------------------------------------------------------

const BlockFixture = struct {
    txs: [2]types.Transaction,
    cb_inputs: [1]types.TxIn,
    cb_outputs: [1]types.TxOut,
    view_entry: validation.SigopUtxoEntry,
    view: validation.SigopUtxoView,

    fn lookup(ctx_ptr: *anyopaque, op: *const types.OutPoint) ?validation.SigopUtxoEntry {
        const self: *BlockFixture = @ptrCast(@alignCast(ctx_ptr));
        if (op.index != 0 or !std.mem.eql(u8, &op.hash, &([_]u8{0x5A} ** 32))) return null;
        return self.view_entry;
    }

    fn init(self: *BlockFixture, s: *const Spend) types.Block {
        self.cb_inputs = .{.{
            .previous_output = types.OutPoint.COINBASE,
            .script_sig = &[_]u8{ 0x03, 0x00, 0x35, 0x0c },
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        }};
        self.cb_outputs = .{.{ .value = 1, .script_pubkey = &out_spk }};
        self.txs = .{
            .{ .version = 1, .inputs = &self.cb_inputs, .outputs = &self.cb_outputs, .lock_time = 0 },
            s.tx,
        };
        self.view_entry = .{ .script_pubkey = s.spk, .amount = s.amounts[0] };
        self.view = .{ .context = @ptrCast(self), .lookupFn = lookup };
        return .{
            .header = .{ .version = 4, .prev_block = [_]u8{0} ** 32, .merkle_root = [_]u8{0} ** 32, .timestamp = 1_700_000_000, .bits = 0x207fffff, .nonce = 0 },
            .transactions = &self.txs,
        };
    }
};

/// Run the block's scripts through a dedicated serial check queue (the
/// parallel / check-queue path: min_inputs_for_parallel = 0).
fn runQueue(q: *validation.ScriptCheckQueue, block: *const types.Block, view: *const validation.SigopUtxoView) validation.ValidationError!bool {
    return validation.verifyBlockScriptsParallel(block, 800_000, &consensus.MAINNET, view, .{
        .min_inputs_for_parallel = 0,
        .queue = q,
    }, testing.allocator);
}

/// An allocator that fails exactly ONE allocation (#n) and then recovers —
/// a transient fault the retry must ride out.
const OnceFailing = struct {
    backing: std.mem.Allocator,
    n: usize,
    count: usize = 0,
    fired: bool = false,

    fn allocator(self: *OnceFailing) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ra: usize) ?[*]u8 {
        const self: *OnceFailing = @ptrCast(@alignCast(ctx));
        defer self.count += 1;
        if (self.count == self.n) {
            self.fired = true;
            return null;
        }
        return self.backing.rawAlloc(len, ptr_align, ra);
    }
    fn resize(ctx: *anyopaque, buf: []u8, a: u8, new_len: usize, ra: usize) bool {
        const self: *OnceFailing = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(buf, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, buf: []u8, a: u8, ra: usize) void {
        const self: *OnceFailing = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(buf, a, ra);
    }
};

test "gate6: check queue — a persistent OOM in a script job is NOT a reject verdict; it halts (latch)" {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var s: Spend = undefined;
    try legacySpend(&s, ctx, &key, pkScript(&key, false, &b), false);
    var fx: BlockFixture = undefined;
    const block = fx.init(&s);

    const q = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
    defer q.deinit();
    try testing.expect(try runQueue(q, &block, &fx.view)); // control: valid block passes

    var fa = std.testing.FailingAllocator.init(std.heap.c_allocator, .{ .fail_index = 0 });
    validation.test_job_backing_allocator = fa.allocator();
    defer validation.test_job_backing_allocator = null;
    const r = runQueue(q, &block, &fx.view);
    try testing.expect(fa.has_induced_failure);
    if (r) |ok| {
        std.debug.print("gate6: job OOM -> block scripts returned {} (pre-fix: false = REJECT verdict)\n", .{ok});
        return error.FaultBecameVerdict;
    } else |e| try testing.expectEqualStrings("ScriptCheckInternal", @errorName(e));
    try testing.expect(fatal.isLatched());
}

test "gate6: check queue — a TRANSIENT OOM is retried once and the block's true verdict stands (valid passes, invalid fails, no latch)" {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var s: Spend = undefined;
    var fx: BlockFixture = undefined;
    const q = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
    defer q.deinit();

    // valid spend: transient fault -> still accepted
    try legacySpend(&s, ctx, &key, pkScript(&key, false, &b), false);
    var block = fx.init(&s);
    var once = OnceFailing{ .backing = std.heap.c_allocator, .n = 0 };
    validation.test_job_backing_allocator = once.allocator();
    defer validation.test_job_backing_allocator = null;
    const r1 = runQueue(q, &block, &fx.view);
    try testing.expect(once.fired);
    try testing.expect(try r1);

    // invalid spend (bad sig, plain CHECKSIG): transient fault -> still rejected
    try legacySpend(&s, ctx, &key, pkScript(&key, false, &b), true);
    block = fx.init(&s);
    once = OnceFailing{ .backing = std.heap.c_allocator, .n = 0 };
    const r2 = runQueue(q, &block, &fx.view);
    try testing.expect(once.fired);
    try testing.expect(!(try r2));
    try testing.expect(!fatal.isLatched());
}

test "gate6: check queue — secp fault on CHECKSIG NOT is never ACCEPTED, and no wrong result is left in the sig cache" {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    var s: Spend = undefined;
    try legacySpend(&s, ctx, &key, pkScript(&key, true, &b), false);
    var fx: BlockFixture = undefined;
    const block = fx.init(&s);
    const q = try validation.ScriptCheckQueue.initWithWorkers(testing.allocator, 0);
    defer q.deinit();

    crypto.test_fault_secp_unavailable = true;
    const r = runQueue(q, &block, &fx.view);
    crypto.test_fault_secp_unavailable = false;
    if (r) |ok| {
        if (ok) {
            std.debug.print("gate6: secp fault -> invalid CHECKSIG NOT block ACCEPTED (pre-fix)\n", .{});
            return error.FaultBecameAccept;
        }
        return error.FaultBecameVerdict;
    } else |e| try testing.expectEqualStrings("ScriptCheckInternal", @errorName(e));

    // Fault cleared: the same job through the same queue (same sig cache) must
    // now give the TRUE verdict — invalid.  Pre-fix the faulted `true` was
    // inserted into the sig cache and replayed here.
    fatal.resetForTest();
    try testing.expect(!(try runQueue(q, &block, &fx.view)));
}

test "gate6: single-threaded path — OOM sweep never yields a verdict on a valid or a CHECKSIG NOT block" {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);
    var b: [36]u8 = undefined;
    inline for (.{ false, true }) |with_not| {
        var s: Spend = undefined;
        try legacySpend(&s, ctx, &key, pkScript(&key, with_not, &b), false);
        var fx: BlockFixture = undefined;
        const block = fx.init(&s);
        // control
        const truth = try validation.verifyBlockScriptsParallel(&block, 800_000, &consensus.MAINNET, &fx.view, .{ .enabled = false }, testing.allocator);
        try testing.expectEqual(!with_not, truth);
        var i: usize = 0;
        var faulted: usize = 0;
        while (i < 10_000) : (i += 1) {
            // Persistent fault from allocation #i on: the retry faults too,
            // so the only acceptable outcome is an error (and a halt).
            fatal.resetForTest();
            var fa = std.testing.FailingAllocator.init(std.heap.c_allocator, .{ .fail_index = i });
            const r = validation.verifyBlockScriptsParallel(&block, 800_000, &consensus.MAINNET, &fx.view, .{ .enabled = false }, fa.allocator());
            if (!fa.has_induced_failure) break;
            faulted += 1;
            if (r) |ok| {
                std.debug.print("gate6: single-threaded persistent fault at alloc #{d} -> verdict {} (must be an error)\n", .{ i, ok });
                return error.FaultBecameVerdict;
            } else |e| {
                const n = @errorName(e);
                try testing.expect(std.mem.eql(u8, n, "OutOfMemory") or std.mem.eql(u8, n, "ScriptCheckInternal"));
            }
            // Transient fault at #i only: an error, or (after the retry) the
            // TRUE verdict — never the opposite one.
            fatal.resetForTest();
            var once = OnceFailing{ .backing = std.heap.c_allocator, .n = i };
            const r2 = validation.verifyBlockScriptsParallel(&block, 800_000, &consensus.MAINNET, &fx.view, .{ .enabled = false }, once.allocator());
            if (r2) |ok| {
                if (ok != truth) {
                    std.debug.print("gate6: single-threaded transient fault at alloc #{d} -> verdict {} (truth {})\n", .{ i, ok, truth });
                    return error.FaultBecameVerdict;
                }
            } else |e| {
                const n = @errorName(e);
                try testing.expect(std.mem.eql(u8, n, "OutOfMemory") or std.mem.eql(u8, n, "ScriptCheckInternal"));
            }
        }
        try testing.expect(faulted > 0);
    }
}

// ---------------------------------------------------------------------------
// Mempool (mempool.zig verifyInputScripts): a system fault is not
// "mandatory-script-verify-flag-failed".
// ---------------------------------------------------------------------------

const storage = @import("storage.zig");
const mempool_mod = @import("mempool.zig");

test "gate6: mempool — secp fault on a VALID P2PK spend is a system fault, not ScriptVerifyFailed" {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const allocator = testing.allocator;
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);

    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    chain_state.best_height = 800_000;
    var pool = mempool_mod.Mempool.init(&chain_state, &consensus.MAINNET, allocator);
    defer pool.deinit();

    var spk_buf: [36]u8 = undefined;
    const spk = pkScript(&key, false, &spk_buf);
    const prev = types.OutPoint{ .hash = [_]u8{0x43} ** 32, .index = 0 };
    try chain_state.utxo_set.add(&prev, &types.TxOut{ .value = 100_000, .script_pubkey = spk }, 700_000, false);

    const out_script = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCC} ** 20;
    var inputs = [_]types.TxIn{.{ .previous_output = prev, .script_sig = &[_]u8{}, .sequence = 0xFFFF_FFFF, .witness = &[_][]const u8{} }};
    const outputs = [_]types.TxOut{.{ .value = 90_000, .script_pubkey = &out_script }};
    const tx = types.Transaction{ .version = 2, .inputs = &inputs, .outputs = &outputs, .lock_time = 0 };
    const sh = try script.legacySignatureHash(allocator, &tx, 0, spk, 1);

    var sig_buf: [80]u8 = undefined;
    var ss: [81]u8 = undefined;
    // CONTROL (fault-free): the valid spend is accepted (dry run), a
    // corrupted signature is ScriptVerifyFailed.
    {
        const n = try signDer(ctx, &key, &sh, &sig_buf, false);
        ss[0] = @intCast(n);
        @memcpy(ss[1 .. 1 + n], sig_buf[0..n]);
        inputs[0].script_sig = ss[0 .. 1 + n];
        const r = pool.acceptToMemoryPool(tx, true);
        if (!r.accepted) std.debug.print("gate6 mempool control reject: {s}\n", .{r.reject_reason orelse "?"});
        try testing.expect(r.accepted);
    }
    {
        var bad_sig: [80]u8 = undefined;
        var bad_ss: [81]u8 = undefined;
        const n = try signDer(ctx, &key, &sh, &bad_sig, true);
        bad_ss[0] = @intCast(n);
        @memcpy(bad_ss[1 .. 1 + n], bad_sig[0..n]);
        var bad_inputs = inputs;
        bad_inputs[0].script_sig = bad_ss[0 .. 1 + n];
        const bad_tx = types.Transaction{ .version = 2, .inputs = &bad_inputs, .outputs = &outputs, .lock_time = 0 };
        try testing.expectError(mempool_mod.MempoolError.ScriptVerifyFailed, pool.addTransaction(bad_tx));
    }

    // FAULT: no usable secp context while checking the valid spend.
    crypto.test_fault_secp_unavailable = true;
    defer crypto.test_fault_secp_unavailable = false;
    if (pool.addTransaction(tx)) |_| {
        return error.FaultBecameAccept;
    } else |e| {
        if (std.mem.eql(u8, @errorName(e), "ScriptVerifyFailed")) {
            std.debug.print("gate6: mempool secp fault -> ScriptVerifyFailed (pre-fix: a consensus-looking reject of a valid tx)\n", .{});
        }
        try testing.expectEqualStrings("SystemFault", @errorName(e));
    }
    try testing.expectEqual(@as(usize, 0), pool.entries.count());
}

// ---------------------------------------------------------------------------
// submitblock (rpc.zig): a system fault answers RPC_VERIFY_ERROR (-25), never
// a BIP-22 reject token.
// ---------------------------------------------------------------------------

const rpc_mod = @import("rpc.zig");
const peer_mod = @import("peer.zig");

/// Regtest height-1 block on genesis: coinbase + one spend of `prev`
/// (script_sig `ss`).  Returns the block's hex (caller frees).
fn submitBlockHex(allocator: std.mem.Allocator, prev: types.OutPoint, ss: []const u8) ![]u8 {
    const params = &consensus.REGTEST;
    var cb_in = [_]types.TxIn{.{ .previous_output = types.OutPoint.COINBASE, .script_sig = &[_]u8{ 0x51, 0x01, 0x6b }, .sequence = 0xFFFFFFFF, .witness = &[_][]const u8{} }};
    var cb_out = [_]types.TxOut{.{ .value = 5_000_000_000, .script_pubkey = &out_spk }};
    var sp_in = [_]types.TxIn{.{ .previous_output = prev, .script_sig = ss, .sequence = 0xFFFFFFFF, .witness = &[_][]const u8{} }};
    var sp_out = [_]types.TxOut{.{ .value = 40_000, .script_pubkey = &out_spk }};
    var txs = [_]types.Transaction{
        .{ .version = 1, .inputs = &cb_in, .outputs = &cb_out, .lock_time = 0 },
        .{ .version = 1, .inputs = &sp_in, .outputs = &sp_out, .lock_time = 0 },
    };
    const ids = [_]types.Hash256{ try crypto.computeTxid(&txs[0], allocator), try crypto.computeTxid(&txs[1], allocator) };
    var header = types.BlockHeader{
        .version = 4,
        .prev_block = params.genesis_hash,
        .merkle_root = try crypto.computeMerkleRoot(&ids, allocator),
        .timestamp = params.genesis_header.timestamp + 600,
        .bits = 0x207fffff,
        .nonce = 0,
    };
    while (!consensus.validateProofOfWork(&header, params)) header.nonce +%= 1;
    const block = types.Block{ .header = header, .transactions = &txs };
    var w = serialize.Writer.init(allocator);
    defer w.deinit();
    try serialize.writeBlock(&w, &block);
    const hex = try allocator.alloc(u8, w.list.items.len * 2);
    _ = std.fmt.bufPrint(hex, "{}", .{std.fmt.fmtSliceHexLower(w.list.items)}) catch unreachable;
    return hex;
}

fn runSubmitBlock(fault: bool, corrupt: bool) ![]const u8 {
    const allocator = testing.allocator;
    const params = &consensus.REGTEST;
    const ctx = try testCtx();
    defer secp.secp256k1_context_destroy(ctx);
    const key = try makeKey(ctx);

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try storage.Database.open(path, 64, allocator);
    defer db.close();
    var cs = storage.ChainState.init(&db, 64, allocator);
    defer cs.deinit();
    cs.wireUtxoParent();
    cs.setNetworkParams(params);
    cs.best_hash = params.genesis_hash;
    cs.initGenesisTimestamp(params.genesis_header.timestamp);
    var pool = mempool_mod.Mempool.init(null, null, allocator);
    defer pool.deinit();
    var pm = peer_mod.PeerManager.init(allocator, params);
    defer pm.deinit();
    pm.chain_state = &cs;
    pm.data_dir = path; // keep anchors.dat / bans out of the cwd
    var server = rpc_mod.RpcServer.init(allocator, &cs, &pool, &pm, params, .{});
    defer server.deinit();

    var spk_buf: [36]u8 = undefined;
    const spk = pkScript(&key, false, &spk_buf);
    const prev = types.OutPoint{ .hash = [_]u8{0x44} ** 32, .index = 0 };
    try cs.utxo_set.add(&prev, &types.TxOut{ .value = 50_000, .script_pubkey = spk }, 0, false);

    // Sign the spend (legacy SIGHASH_ALL over the coin script).
    var sp_in = [_]types.TxIn{.{ .previous_output = prev, .script_sig = &[_]u8{}, .sequence = 0xFFFFFFFF, .witness = &[_][]const u8{} }};
    const sp_out = [_]types.TxOut{.{ .value = 40_000, .script_pubkey = &out_spk }};
    const sp_tx = types.Transaction{ .version = 1, .inputs = &sp_in, .outputs = &sp_out, .lock_time = 0 };
    const sh = try script.legacySignatureHash(allocator, &sp_tx, 0, spk, 1);
    var sig_buf: [80]u8 = undefined;
    const n = try signDer(ctx, &key, &sh, &sig_buf, corrupt);
    var ss: [81]u8 = undefined;
    ss[0] = @intCast(n);
    @memcpy(ss[1 .. 1 + n], sig_buf[0..n]);

    const hex = try submitBlockHex(allocator, prev, ss[0 .. 1 + n]);
    defer allocator.free(hex);
    const req = try std.fmt.allocPrint(allocator, "{{\"id\":1,\"method\":\"submitblock\",\"params\":[\"{s}\"]}}", .{hex});
    defer allocator.free(req);

    if (fault) crypto.test_fault_secp_unavailable = true;
    defer crypto.test_fault_secp_unavailable = false;
    return server.dispatch(req);
}

test "gate6: submitblock — control: a corrupted signature is the BIP-22 verdict block-script-verify-flag-failed" {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const resp = try runSubmitBlock(false, true);
    defer testing.allocator.free(resp);
    try testing.expect(std.mem.indexOf(u8, resp, "block-script-verify-flag-failed") != null);
}

test "gate6: submitblock — secp fault on a VALID block answers RPC_VERIFY_ERROR (-25), not a BIP-22 reject; the node halts" {
    fatal.resetForTest();
    defer fatal.resetForTest();
    const resp = try runSubmitBlock(true, false);
    defer testing.allocator.free(resp);
    if (std.mem.indexOf(u8, resp, "block-script-verify-flag-failed") != null) {
        std.debug.print("gate6: submitblock under a secp fault answered the BIP-22 verdict (pre-fix): {s}\n", .{resp});
    }
    try testing.expect(std.mem.indexOf(u8, resp, "block-script-verify-flag-failed") == null);
    try testing.expect(std.mem.indexOf(u8, resp, "\"code\":-25") != null);
    try testing.expect(fatal.isLatched());
}
