//! Core's descriptor-driven PSBT Updater/Signer (rpc/rawtransaction.cpp
//! ProcessPSBT + psbt.cpp SignPSBTInput / UpdatePSBTOutput), shared by the
//! `utxoupdatepsbt` and `descriptorprocesspsbt` RPCs.
//!
//! A `Provider` is Core's FlatSigningProvider built by
//! EvalDescriptorStringOrObject: for every descriptor at every index of its
//! range, the scriptPubKey it produces, the redeem/witness script behind it,
//! and each involved key with its KeyOriginInfo (and secret, when the
//! descriptor carries one and the caller asked for private expansion).
//!
//! `update` then walks the PSBT like Core:
//!   inputs  (not already final): a matching script contributes its
//!           redeem/witness script and BIP-32 derivations; with a secret,
//!           P2WPKH / P2SH-P2WPKH / P2PKH inputs are signed (Core's low-R
//!           ECDSA) and, when `finalize`, finalized.
//!   outputs: a matching script contributes redeem/witness script and
//!           BIP-32 derivations.
//!
//! Scope (documented, not silent): taproot (tr/rawtr) and miniscript
//! descriptors contribute no metadata and are never signed, and multisig
//! inputs get metadata but no signatures; such inputs stay incomplete.

const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const descriptor = @import("descriptor.zig");
const psbt_mod = @import("psbt.zig");

pub const KeyEntry = struct {
    pubkey: []u8,
    privkey: ?[32]u8,
    fingerprint: [4]u8,
    path: []u32,
};

pub const Entry = struct {
    spk: []u8,
    redeem_script: ?[]u8 = null,
    witness_script: ?[]u8 = null,
    keys: []KeyEntry,
};

pub const Provider = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry),

    pub fn init(allocator: std.mem.Allocator) Provider {
        return .{ .allocator = allocator, .entries = std.ArrayList(Entry).init(allocator) };
    }

    pub fn deinit(self: *Provider) void {
        for (self.entries.items) |*e| freeEntry(self.allocator, e);
        self.entries.deinit();
    }

    fn find(self: *const Provider, spk: []const u8) ?*const Entry {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.spk, spk)) return e;
        }
        return null;
    }
};

fn freeKeys(allocator: std.mem.Allocator, keys: []KeyEntry) void {
    for (keys) |*k| {
        allocator.free(k.pubkey);
        allocator.free(k.path);
        if (k.privkey) |*p| @memset(p, 0);
    }
    allocator.free(keys);
}

fn freeEntry(allocator: std.mem.Allocator, e: *Entry) void {
    allocator.free(e.spk);
    if (e.redeem_script) |r| allocator.free(r);
    if (e.witness_script) |w| allocator.free(w);
    freeKeys(allocator, e.keys);
}

fn resolveKeys(allocator: std.mem.Allocator, keys: []const descriptor.Key, index: u32, expand_priv: bool) ![]KeyEntry {
    var out = std.ArrayList(KeyEntry).init(allocator);
    errdefer {
        for (out.items) |*k| {
            allocator.free(k.pubkey);
            allocator.free(k.path);
        }
        out.deinit();
    }
    for (keys) |k| {
        const r = try descriptor.resolveKey(allocator, k, index);
        try out.append(.{
            .pubkey = r.pubkey,
            .privkey = if (expand_priv) r.privkey else null,
            .fingerprint = r.fingerprint,
            .path = r.path,
        });
    }
    return out.toOwnedSlice();
}

fn p2shOf(allocator: std.mem.Allocator, script: []const u8) ![]u8 {
    const h = crypto.hash160(script);
    const out = try allocator.alloc(u8, 23);
    out[0] = 0xa9;
    out[1] = 0x14;
    @memcpy(out[2..22], &h);
    out[22] = 0x87;
    return out;
}

fn p2wshOf(allocator: std.mem.Allocator, script: []const u8) ![]u8 {
    const h = crypto.sha256(script);
    const out = try allocator.alloc(u8, 34);
    out[0] = 0x00;
    out[1] = 0x20;
    @memcpy(out[2..34], &h);
    return out;
}

/// Expand one descriptor at `index` into provider entries.
fn expand(allocator: std.mem.Allocator, desc: *const descriptor.Descriptor, index: u32, expand_priv: bool, out: *std.ArrayList(Entry)) !void {
    switch (desc.*) {
        .pk, .pkh, .wpkh => |k| {
            const spk = try descriptor.deriveScript(allocator, desc, index);
            errdefer allocator.free(spk);
            const keys = try resolveKeys(allocator, &.{k}, index, expand_priv);
            try out.append(.{ .spk = spk, .keys = keys });
        },
        .multi, .sorted_multi => |m| {
            const spk = try descriptor.deriveScript(allocator, desc, index);
            errdefer allocator.free(spk);
            const keys = try resolveKeys(allocator, m.keys, index, expand_priv);
            try out.append(.{ .spk = spk, .keys = keys });
        },
        .combo => |k| {
            // Core combo(): pk, pkh, and for a compressed key also wpkh and sh(wpkh).
            const kinds = [_]descriptor.Descriptor{ .{ .pk = k }, .{ .pkh = k }, .{ .wpkh = k } };
            var r = try descriptor.resolveKey(allocator, k, index);
            const compressed = r.pubkey.len == 33;
            r.deinit(allocator);
            for (kinds, 0..) |kd, i| {
                if (i == 2 and !compressed) break;
                try expand(allocator, &kd, index, expand_priv, out);
            }
            if (compressed) {
                var inner = std.ArrayList(Entry).init(allocator);
                defer inner.deinit();
                const wpkh = descriptor.Descriptor{ .wpkh = k };
                try expand(allocator, &wpkh, index, expand_priv, &inner);
                for (inner.items) |*e| {
                    const spk = try p2shOf(allocator, e.spk);
                    try out.append(.{ .spk = spk, .redeem_script = e.spk, .keys = e.keys });
                }
            }
        },
        .sh => |inner_desc| {
            var inner = std.ArrayList(Entry).init(allocator);
            defer inner.deinit();
            try expand(allocator, inner_desc, index, expand_priv, &inner);
            for (inner.items) |e| {
                const spk = try p2shOf(allocator, e.spk);
                if (e.redeem_script) |r| allocator.free(r); // sh(sh(..)) is invalid; never nested
                try out.append(.{ .spk = spk, .redeem_script = e.spk, .witness_script = e.witness_script, .keys = e.keys });
            }
        },
        .wsh => |inner_desc| {
            var inner = std.ArrayList(Entry).init(allocator);
            defer inner.deinit();
            try expand(allocator, inner_desc, index, expand_priv, &inner);
            for (inner.items) |e| {
                const spk = try p2wshOf(allocator, e.spk);
                if (e.redeem_script) |r| allocator.free(r);
                if (e.witness_script) |w| allocator.free(w);
                try out.append(.{ .spk = spk, .witness_script = e.spk, .keys = e.keys });
            }
        },
        else => {
            // addr/raw/rawtr/tr/miniscript: the script alone (no solving data).
            const spk = descriptor.deriveScript(allocator, desc, index) catch return;
            try out.append(.{ .spk = spk, .keys = try allocator.alloc(KeyEntry, 0) });
        },
    }
}

pub const EvalError = struct { code: i32, msg: []u8 };

/// Core EvalDescriptorStringOrObject for one `descriptors` element.  On a
/// Core-reported failure returns the RPC code and message (caller frees msg).
pub fn evalDescriptor(
    allocator: std.mem.Allocator,
    provider: *Provider,
    v: std.json.Value,
    expand_priv: bool,
) !?EvalError {
    var desc_str: []const u8 = undefined;
    var lo: i64 = 0;
    var hi: i64 = 1000;
    switch (v) {
        .string => |s| desc_str = s,
        .object => |o| {
            const d = o.get("desc") orelse std.json.Value.null;
            if (d == .null) return .{ .code = -8, .msg = try allocator.dupe(u8, "Descriptor needs to be provided in scan object") };
            if (d != .string) return .{ .code = -3, .msg = try std.fmt.allocPrint(allocator, "JSON value of type {s} is not of expected type string", .{jsonTypeName(d)}) };
            desc_str = d.string;
            if (o.get("range")) |r| {
                if (r != .null) {
                    if (try parseDescriptorRange(allocator, r, &lo, &hi)) |e| return e;
                }
            }
        },
        else => return .{ .code = -8, .msg = try allocator.dupe(u8, "Scan object needs to be either a string or an object") },
    }

    // Parse(desc_str): an optional "#checksum" must match.
    var body = desc_str;
    if (std.mem.indexOfScalar(u8, desc_str, '#')) |h| {
        body = desc_str[0..h];
        const given = desc_str[h + 1 ..];
        if (given.len != 8) return .{ .code = -5, .msg = try std.fmt.allocPrint(allocator, "Expected 8 character checksum, not {d} characters", .{given.len}) };
        const want = descriptor.computeChecksum(body) orelse
            return .{ .code = -5, .msg = try std.fmt.allocPrint(allocator, "Invalid characters in payload", .{}) };
        if (!std.mem.eql(u8, given, &want)) {
            return .{ .code = -5, .msg = try std.fmt.allocPrint(allocator, "Provided checksum '{s}' does not match computed checksum '{s}'", .{ given, &want }) };
        }
    }
    var parsed = descriptor.parseDescriptor(allocator, body) catch {
        return .{ .code = -5, .msg = try parseErrorMessage(allocator, body) };
    };
    defer parsed.deinit(allocator);
    if (!parsed.isRange()) {
        lo = 0;
        hi = 0;
    }
    var i: i64 = lo;
    while (i <= hi) : (i += 1) {
        expand(allocator, &parsed, @intCast(i), expand_priv, &provider.entries) catch |err| {
            if (err == error.OutOfMemory) return err;
            return .{ .code = -5, .msg = try std.fmt.allocPrint(allocator, "Cannot derive script without private keys: '{s}'", .{desc_str}) };
        };
    }
    return null;
}

/// Core descriptor.cpp ParseScript's top-level complaint for an unknown
/// function name, else a generic parse failure.
fn parseErrorMessage(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const known = [_][]const u8{ "pk", "pkh", "wpkh", "sh", "wsh", "tr", "multi", "sortedmulti", "multi_a", "sortedmulti_a", "addr", "raw", "rawtr", "combo", "musig" };
    const paren = std.mem.indexOfScalar(u8, body, '(');
    if (paren) |p| {
        const name = body[0..p];
        for (known) |k| {
            if (std.mem.eql(u8, k, name)) return std.fmt.allocPrint(allocator, "'{s}' is not a valid descriptor", .{body});
        }
    }
    return std.fmt.allocPrint(allocator, "'{s}' is not a valid descriptor function", .{body});
}

fn jsonTypeName(v: std.json.Value) []const u8 {
    return switch (v) {
        .null => "null",
        .bool => "bool",
        .object => "object",
        .array => "array",
        .string => "string",
        .integer, .float, .number_string => "number",
    };
}

/// Core ParseDescriptorRange (rpc/util.cpp:1309-1337).
fn parseDescriptorRange(allocator: std.mem.Allocator, r: std.json.Value, lo: *i64, hi: *i64) !?EvalError {
    const bad_shape = "Range must be specified as end or as [begin,end]";
    switch (r) {
        .integer => |n| {
            lo.* = 0;
            hi.* = n;
        },
        .array => |a| {
            if (a.items.len != 2 or a.items[0] != .integer or a.items[1] != .integer)
                return .{ .code = -8, .msg = try allocator.dupe(u8, bad_shape) };
            lo.* = a.items[0].integer;
            hi.* = a.items[1].integer;
            if (lo.* > hi.*) return .{ .code = -8, .msg = try allocator.dupe(u8, "Range specified as [begin,end] must not have begin after end") };
        },
        .float, .number_string => return .{ .code = -1, .msg = try allocator.dupe(u8, "JSON integer out of range") },
        else => return .{ .code = -8, .msg = try allocator.dupe(u8, bad_shape) },
    }
    if (lo.* < 0) return .{ .code = -8, .msg = try allocator.dupe(u8, "Range should be greater or equal than 0") };
    if ((hi.* >> 31) != 0) return .{ .code = -8, .msg = try allocator.dupe(u8, "End of range is too high") };
    if (hi.* >= lo.* + 1_000_000) return .{ .code = -8, .msg = try allocator.dupe(u8, "Range is too large") };
    return null;
}

fn isP2WPKH(s: []const u8) bool {
    return s.len == 22 and s[0] == 0x00 and s[1] == 0x14;
}
fn isP2PKH(s: []const u8) bool {
    return s.len == 25 and s[0] == 0x76 and s[1] == 0xa9 and s[2] == 0x14 and s[23] == 0x88 and s[24] == 0xac;
}
fn isP2SH(s: []const u8) bool {
    return s.len == 23 and s[0] == 0xa9 and s[1] == 0x14 and s[22] == 0x87;
}

/// Is a witness program (Core IsSegWitOutput without the P2SH lookup).
pub fn isWitnessProgram(s: []const u8) bool {
    if (s.len < 4 or s.len > 42) return false;
    if (s[0] != 0x00 and (s[0] < 0x51 or s[0] > 0x60)) return false;
    return @as(usize, s[1]) + 2 == s.len;
}

fn putDerivs(allocator: std.mem.Allocator, map: *std.AutoHashMap([33]u8, psbt_mod.KeyOriginInfo), keys: []const KeyEntry) !void {
    for (keys) |k| {
        if (k.pubkey.len != 33) continue; // clearbit's PSBT map is keyed by compressed keys
        var pk: [33]u8 = undefined;
        @memcpy(&pk, k.pubkey);
        if (map.contains(pk)) continue;
        try map.put(pk, .{ .fingerprint = k.fingerprint, .path = if (k.path.len > 0) try allocator.dupe(u32, k.path) else &[_]u32{} });
    }
}

/// The spent output of input `i`, per Core SignPSBTInput: the full previous
/// transaction must hash to the prevout txid and hold the index.
fn inputUtxo(psbt: *const psbt_mod.Psbt, i: usize, allocator: std.mem.Allocator) !?struct { out: types.TxOut, from_witness_utxo: bool } {
    const input = &psbt.inputs[i];
    const prevout = psbt.tx.inputs[i].previous_output;
    if (input.non_witness_utxo) |t| {
        if (prevout.index >= t.outputs.len) return null;
        const txid = try crypto.computeTxid(&t, allocator);
        if (!std.mem.eql(u8, &txid, &prevout.hash)) return null;
        return .{ .out = t.outputs[prevout.index], .from_witness_utxo = false };
    }
    if (input.witness_utxo) |u| return .{ .out = u, .from_witness_utxo = true };
    return null;
}

pub const UpdateError = error{ SighashMismatch, OutOfMemory };

/// Core ProcessPSBT's per-input SignPSBTInput + per-output UpdatePSBTOutput.
/// `sighash`: null = the input's own / default.  Returns error.SighashMismatch
/// exactly where Core returns PSBTError::SIGHASH_MISMATCH.
pub fn update(
    allocator: std.mem.Allocator,
    psbt: *psbt_mod.Psbt,
    provider: *const Provider,
    sighash: ?u32,
    bip32derivs: bool,
    finalize: bool,
) !void {
    for (psbt.inputs, 0..) |*input, i| {
        if (input.isFinalized()) continue;
        const utxo = (inputUtxo(psbt, i, allocator) catch |e| return e) orelse continue;
        const spk = utxo.out.script_pubkey;
        const is_tr = spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20;
        const sh: u32 = sighash orelse (if (is_tr) @as(u32, 0) else 1);
        if (input.sighash_type) |t| {
            if (t != sh) return error.SighashMismatch;
        }
        if (is_tr and sh != 0) input.sighash_type = sh;
        if (!is_tr and sh != 0 and sh != 1) input.sighash_type = sh;
        var sit = input.partial_sigs.iterator();
        while (sit.next()) |e| {
            const sig = e.value_ptr.*;
            if (sh != 0 and (sig.len == 0 or sig[sig.len - 1] != @as(u8, @truncate(sh)))) return error.SighashMismatch;
        }

        const entry = provider.find(spk) orelse continue;
        // Solving data (Core FromSignatureData on an incomplete input).
        if (entry.redeem_script) |r| {
            if (input.redeem_script == null) input.redeem_script = try allocator.dupe(u8, r);
        }
        if (entry.witness_script) |w| {
            if (input.witness_script == null) input.witness_script = try allocator.dupe(u8, w);
        }
        if (bip32derivs) try putDerivs(allocator, &input.bip32_derivation, entry.keys);

        // Signing: single-key P2WPKH / P2SH-P2WPKH / P2PKH.
        if (entry.keys.len != 1) continue;
        const key = entry.keys[0];
        const sk = key.privkey orelse continue;
        if (key.pubkey.len != 33) continue;
        var pk33: [33]u8 = undefined;
        @memcpy(&pk33, key.pubkey);
        const eff: u32 = if (sh == 0) 1 else sh; // DEFAULT aliases ALL for non-taproot
        var digest: [32]u8 = undefined;
        if (isP2WPKH(spk) or (isP2SH(spk) and entry.redeem_script != null and isP2WPKH(entry.redeem_script.?))) {
            const prog = if (isP2WPKH(spk)) spk else entry.redeem_script.?;
            var code: [25]u8 = undefined;
            code[0] = 0x76;
            code[1] = 0xa9;
            code[2] = 0x14;
            @memcpy(code[3..23], prog[2..22]);
            code[23] = 0x88;
            code[24] = 0xac;
            digest = crypto.segwitSighash(&psbt.tx, i, &code, utxo.out.value, eff, allocator) catch continue;
        } else if (isP2PKH(spk)) {
            // A legacy signature commits to no amount: Core requires the full
            // previous transaction (witness_utxo alone -> no signature).
            if (utxo.from_witness_utxo) continue;
            digest = crypto.legacySighash(&psbt.tx, i, spk, eff, allocator) catch continue;
        } else continue;
        const der = crypto.ecdsaSignDer(&digest, &sk) orelse continue;
        const sig = try allocator.alloc(u8, der.len + 1);
        @memcpy(sig[0..der.len], der.bytes[0..der.len]);
        sig[der.len] = @truncate(eff);
        if (input.partial_sigs.fetchRemove(pk33)) |old| allocator.free(old.value);
        try input.partial_sigs.put(pk33, sig);
        if (finalize) {
            psbt.finalizeInput(i) catch {};
            if (input.isFinalized()) clearAfterFinalize(allocator, input);
        }
    }

    for (psbt.tx.outputs, 0..) |out, i| {
        const entry = provider.find(out.script_pubkey) orelse continue;
        const po = &psbt.outputs[i];
        if (entry.redeem_script) |r| {
            if (po.redeem_script == null) po.redeem_script = try allocator.dupe(u8, r);
        }
        if (entry.witness_script) |w| {
            if (po.witness_script == null) po.witness_script = try allocator.dupe(u8, w);
        }
        if (bip32derivs) try putDerivs(allocator, &po.bip32_derivation, entry.keys);
    }
}

/// Core PSBTInput::FromSignatureData on a complete input: the final
/// scriptSig/witness replace partial sigs, key paths and scripts.
fn clearAfterFinalize(allocator: std.mem.Allocator, input: *psbt_mod.PsbtInput) void {
    var sit = input.partial_sigs.iterator();
    while (sit.next()) |e| allocator.free(e.value_ptr.*);
    input.partial_sigs.clearRetainingCapacity();
    var dit = input.bip32_derivation.iterator();
    while (dit.next()) |e| {
        var info = e.value_ptr.*;
        info.deinit(allocator);
    }
    input.bip32_derivation.clearRetainingCapacity();
    if (input.redeem_script) |r| allocator.free(r);
    input.redeem_script = null;
    if (input.witness_script) |w| allocator.free(w);
    input.witness_script = null;
}

/// Core RemoveUnnecessaryTransactions: when EVERY input carries a segwit v1+
/// witness_utxo, the full previous transactions are dropped.
pub fn removeUnnecessaryTransactions(psbt: *psbt_mod.Psbt) void {
    for (psbt.inputs) |*input| {
        const u = input.witness_utxo orelse return;
        if (!isWitnessProgram(u.script_pubkey)) return;
        if (u.script_pubkey[0] == 0x00) return;
    }
    for (psbt.inputs) |*input| {
        if (input.non_witness_utxo) |*t| {
            psbt_mod.freeTransaction(psbt.allocator, t);
            input.non_witness_utxo = null;
        }
    }
}

/// Core PSBTInputSigned: a final scriptSig or witness is present.
pub fn allInputsSigned(psbt: *const psbt_mod.Psbt) bool {
    for (psbt.inputs) |*input| {
        if (!input.isFinalized()) return false;
    }
    return true;
}
