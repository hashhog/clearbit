//! PSBT (Partially Signed Bitcoin Transaction) - BIP174/370
//!
//! This module implements the PSBT format for passing around
//! unsigned or partially signed transactions.
//!
//! Key features:
//! - BIP174 PSBT v0 format support
//! - All PSBT roles: Creator, Updater, Signer, Combiner, Finalizer, Extractor
//! - Base64 encoding/decoding
//! - Full key-value serialization format
//!
//! Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

const std = @import("std");
const types = @import("types.zig");
const serialize_mod = @import("serialize.zig");
const crypto = @import("crypto.zig");

// ============================================================================
// PSBT Constants (BIP174)
// ============================================================================

/// PSBT magic bytes: "psbt" + 0xff
pub const PSBT_MAGIC: [5]u8 = [_]u8{ 0x70, 0x73, 0x62, 0x74, 0xff };

/// Separator byte marking end of a map
pub const PSBT_SEPARATOR: u8 = 0x00;

/// Maximum PSBT file size (100 MB)
pub const MAX_PSBT_SIZE: usize = 100_000_000;

/// Highest supported PSBT version
pub const PSBT_HIGHEST_VERSION: u32 = 0;

// ============================================================================
// Global key types
// ============================================================================

pub const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
pub const PSBT_GLOBAL_XPUB: u8 = 0x01;
pub const PSBT_GLOBAL_VERSION: u8 = 0xFB;
pub const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

// ============================================================================
// Input key types
// ============================================================================

pub const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
pub const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
pub const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
pub const PSBT_IN_SIGHASH: u8 = 0x03;
pub const PSBT_IN_REDEEMSCRIPT: u8 = 0x04;
pub const PSBT_IN_WITNESSSCRIPT: u8 = 0x05;
pub const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
pub const PSBT_IN_SCRIPTSIG: u8 = 0x07;
pub const PSBT_IN_SCRIPTWITNESS: u8 = 0x08;
pub const PSBT_IN_RIPEMD160: u8 = 0x0A;
pub const PSBT_IN_SHA256: u8 = 0x0B;
pub const PSBT_IN_HASH160: u8 = 0x0C;
pub const PSBT_IN_HASH256: u8 = 0x0D;
pub const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
pub const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
pub const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
pub const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
pub const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
pub const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;
pub const PSBT_IN_PROPRIETARY: u8 = 0xFC;

// ============================================================================
// Output key types
// ============================================================================

pub const PSBT_OUT_REDEEMSCRIPT: u8 = 0x00;
pub const PSBT_OUT_WITNESSSCRIPT: u8 = 0x01;
pub const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
pub const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
pub const PSBT_OUT_TAP_TREE: u8 = 0x06;
pub const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
pub const PSBT_OUT_PROPRIETARY: u8 = 0xFC;

// ============================================================================
// Error Types
// ============================================================================

pub const PsbtError = error{
    InvalidMagic,
    InvalidFormat,
    DuplicateKey,
    MissingSeparator,
    MissingUnsignedTx,
    InvalidUnsignedTx,
    UnsupportedVersion,
    InputCountMismatch,
    OutputCountMismatch,
    InvalidKeyLength,
    InvalidValueLength,
    NonWitnessUtxoMismatch,
    OutOfMemory,
    EndOfStream,
    InvalidBase64,
    AlreadyFinalized,
    NotFinalized,
    SignatureMismatch,
    MissingUtxo,
    InvalidCompactSize,
    InvalidSegwitMarker,
    SuperfluousWitnessRecord,
    /// W31: finalizeP2SH refused to emit `final_script_sig` because
    /// `hash160(redeem_script)` did not equal the 20-byte payload of the
    /// witness UTXO's `OP_HASH160 <h> OP_EQUAL` scriptPubKey. Same shape as
    /// the cross-impl bug class found in hotbuns/blockbrew/etc — a forged
    /// or wrong redeemScript would otherwise be wrapped into a malleable
    /// scriptSig that any later verifier would reject anyway, so we fail
    /// loudly at finalize time instead.
    RedeemScriptCommitmentMismatch,
    /// W31: defense-in-depth for `signP2SH_P2WSH` — the inner BIP-141
    /// P2WSH commitment (`sha256(witness_script)` ↔ `redeem_script[2..34]`)
    /// did not match. The dispatch path can't currently reach this (the
    /// inner script is computed from the witness_script the caller hands
    /// us), but the assertion catches drift if the call site is ever
    /// extended to take an externally-supplied redeemScript.
    WitnessScriptCommitmentMismatch,
};

// ============================================================================
// PSBT Key
// ============================================================================

/// A PSBT key consists of a type byte followed by optional key data
pub const PsbtKey = struct {
    key_type: u8,
    key_data: []const u8,

    /// Check if two keys are equal
    pub fn eql(self: PsbtKey, other: PsbtKey) bool {
        return self.key_type == other.key_type and
            std.mem.eql(u8, self.key_data, other.key_data);
    }

    /// Compute a hash for use in hash maps
    pub fn hash(self: PsbtKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&[_]u8{self.key_type});
        h.update(self.key_data);
        return h.final();
    }

    /// Free the key data
    pub fn deinit(self: *PsbtKey, allocator: std.mem.Allocator) void {
        if (self.key_data.len > 0) {
            allocator.free(self.key_data);
        }
    }

    /// Clone the key
    pub fn clone(self: PsbtKey, allocator: std.mem.Allocator) !PsbtKey {
        const key_data = if (self.key_data.len > 0)
            try allocator.dupe(u8, self.key_data)
        else
            &[_]u8{};
        return PsbtKey{
            .key_type = self.key_type,
            .key_data = key_data,
        };
    }
};

// ============================================================================
// BIP32 Key Origin Info
// ============================================================================

/// BIP32 derivation path information
pub const KeyOriginInfo = struct {
    fingerprint: [4]u8,
    path: []u32, // Derivation path indices

    pub fn deinit(self: *KeyOriginInfo, allocator: std.mem.Allocator) void {
        if (self.path.len > 0) {
            allocator.free(self.path);
        }
    }

    pub fn clone(self: KeyOriginInfo, allocator: std.mem.Allocator) !KeyOriginInfo {
        return KeyOriginInfo{
            .fingerprint = self.fingerprint,
            .path = if (self.path.len > 0) try allocator.dupe(u32, self.path) else &[_]u32{},
        };
    }
};

/// Key-value pair for unknown/forward-compatible PSBT entries.
pub const UnknownEntry = struct { key: []const u8, value: []const u8 };

// ============================================================================
// BIP-371 Taproot types
// ============================================================================

/// BIP-371 PSBT_IN_TAP_SCRIPT_SIG entry
/// key: x-only pubkey (32 bytes) || leaf_hash (32 bytes)
/// value: signature
pub const TapScriptSig = struct {
    pubkey: [32]u8,
    leaf_hash: [32]u8,
    sig: []const u8,
};

/// BIP-371 PSBT_IN_TAP_LEAF_SCRIPT entry
/// key: control_block bytes
/// value: script || leaf_ver
pub const TapLeafScript = struct {
    control_block: []const u8,
    script: []const u8,
    leaf_ver: u8,
};

/// BIP-371 tap-specific BIP-32 derivation
/// key: x-only pubkey (32 bytes)
/// value: compact_size(num_leaf_hashes) || leaf_hash[]... || fingerprint(4) || path(4*n)
pub const TapKeyOriginInfo = struct {
    leaf_hashes: []const [32]u8,
    fingerprint: [4]u8,
    path: []u32,

    pub fn deinit(self: *TapKeyOriginInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.leaf_hashes);
        allocator.free(self.path);
    }

    pub fn clone(self: TapKeyOriginInfo, allocator: std.mem.Allocator) !TapKeyOriginInfo {
        return TapKeyOriginInfo{
            .leaf_hashes = try allocator.dupe([32]u8, self.leaf_hashes),
            .fingerprint = self.fingerprint,
            .path = if (self.path.len > 0) try allocator.dupe(u32, self.path) else &[_]u32{},
        };
    }
};

/// BIP-370/371 PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS entry (type 0x08)
/// key: aggregate_pubkey (33 bytes compressed)
/// value: participant_pubkeys (33 bytes each, concatenated)
pub const MuSig2ParticipantEntry = struct {
    aggregate_pubkey: [33]u8,
    participant_pubkeys: []const [33]u8,
};

pub const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x08;

// ============================================================================
// PSBT Input
// ============================================================================

/// Per-input PSBT data
pub const PsbtInput = struct {
    // UTXO data (one or both may be present)
    non_witness_utxo: ?types.Transaction = null,
    witness_utxo: ?types.TxOut = null,

    // Partial signatures: pubkey -> signature
    partial_sigs: std.AutoHashMap([33]u8, []const u8),

    // Sighash type
    sighash_type: ?u32 = null,

    // Scripts
    redeem_script: ?[]const u8 = null,
    witness_script: ?[]const u8 = null,
    final_script_sig: ?[]const u8 = null,
    final_script_witness: ?[]const []const u8 = null,

    // BIP32 derivations: compressed pubkey -> KeyOriginInfo
    bip32_derivation: std.AutoHashMap([33]u8, KeyOriginInfo),

    // Hash preimages
    ripemd160_preimages: std.AutoHashMap([20]u8, []const u8),
    sha256_preimages: std.AutoHashMap([32]u8, []const u8),
    hash160_preimages: std.AutoHashMap([20]u8, []const u8),
    hash256_preimages: std.AutoHashMap([32]u8, []const u8),

    // Taproot data (BIP-371)
    tap_key_sig: ?[]const u8 = null,
    tap_internal_key: ?[32]u8 = null,
    tap_merkle_root: ?[32]u8 = null,
    // BIP-371 extended taproot fields
    tap_script_sigs: std.ArrayList(TapScriptSig),
    tap_leaf_scripts: std.ArrayList(TapLeafScript),
    tap_bip32_derivation: std.AutoHashMap([32]u8, TapKeyOriginInfo),

    // Unknown key-value pairs (for forward compatibility)
    unknown: std.AutoHashMap(u64, UnknownEntry),

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PsbtInput {
        return PsbtInput{
            .partial_sigs = std.AutoHashMap([33]u8, []const u8).init(allocator),
            .bip32_derivation = std.AutoHashMap([33]u8, KeyOriginInfo).init(allocator),
            .ripemd160_preimages = std.AutoHashMap([20]u8, []const u8).init(allocator),
            .sha256_preimages = std.AutoHashMap([32]u8, []const u8).init(allocator),
            .hash160_preimages = std.AutoHashMap([20]u8, []const u8).init(allocator),
            .hash256_preimages = std.AutoHashMap([32]u8, []const u8).init(allocator),
            .unknown = std.AutoHashMap(u64, UnknownEntry).init(allocator),
            .tap_script_sigs = std.ArrayList(TapScriptSig).init(allocator),
            .tap_leaf_scripts = std.ArrayList(TapLeafScript).init(allocator),
            .tap_bip32_derivation = std.AutoHashMap([32]u8, TapKeyOriginInfo).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PsbtInput) void {
        // Free partial signatures
        var sig_iter = self.partial_sigs.iterator();
        while (sig_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.partial_sigs.deinit();

        // Free BIP32 derivations
        var bip32_iter = self.bip32_derivation.iterator();
        while (bip32_iter.next()) |entry| {
            var info = entry.value_ptr.*;
            info.deinit(self.allocator);
        }
        self.bip32_derivation.deinit();

        // Free preimages
        var ripemd_iter = self.ripemd160_preimages.iterator();
        while (ripemd_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.ripemd160_preimages.deinit();

        var sha256_iter = self.sha256_preimages.iterator();
        while (sha256_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.sha256_preimages.deinit();

        var hash160_iter = self.hash160_preimages.iterator();
        while (hash160_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.hash160_preimages.deinit();

        var hash256_iter = self.hash256_preimages.iterator();
        while (hash256_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.hash256_preimages.deinit();

        // Free unknown entries
        var unknown_iter = self.unknown.iterator();
        while (unknown_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.key);
            self.allocator.free(entry.value_ptr.value);
        }
        self.unknown.deinit();

        // Free scripts
        if (self.redeem_script) |s| self.allocator.free(s);
        if (self.witness_script) |s| self.allocator.free(s);
        if (self.final_script_sig) |s| self.allocator.free(s);
        if (self.final_script_witness) |w| {
            for (w) |item| {
                self.allocator.free(item);
            }
            self.allocator.free(w);
        }
        if (self.tap_key_sig) |s| self.allocator.free(s);

        // Free BIP-371 taproot extended fields
        for (self.tap_script_sigs.items) |*entry| {
            self.allocator.free(entry.sig);
        }
        self.tap_script_sigs.deinit();

        for (self.tap_leaf_scripts.items) |*entry| {
            self.allocator.free(entry.control_block);
            self.allocator.free(entry.script);
        }
        self.tap_leaf_scripts.deinit();

        var tap_bip32_iter = self.tap_bip32_derivation.iterator();
        while (tap_bip32_iter.next()) |entry| {
            var info = entry.value_ptr.*;
            info.deinit(self.allocator);
        }
        self.tap_bip32_derivation.deinit();

        // Free non_witness_utxo transaction data
        if (self.non_witness_utxo) |*tx| {
            freeTransaction(self.allocator, tx);
        }

        // Free witness_utxo
        if (self.witness_utxo) |*utxo| {
            self.allocator.free(utxo.script_pubkey);
        }
    }

    /// Check if this input is finalized
    pub fn isFinalized(self: *const PsbtInput) bool {
        return self.final_script_sig != null or self.final_script_witness != null;
    }

    /// Merge another input into this one (for Combiner role)
    pub fn merge(self: *PsbtInput, other: *const PsbtInput) !void {
        // Copy non_witness_utxo if we don't have it
        if (self.non_witness_utxo == null and other.non_witness_utxo != null) {
            self.non_witness_utxo = try cloneTransaction(self.allocator, &other.non_witness_utxo.?);
        }

        // Copy witness_utxo if we don't have it
        if (self.witness_utxo == null and other.witness_utxo != null) {
            self.witness_utxo = types.TxOut{
                .value = other.witness_utxo.?.value,
                .script_pubkey = try self.allocator.dupe(u8, other.witness_utxo.?.script_pubkey),
            };
        }

        // Merge partial signatures
        var sig_iter = other.partial_sigs.iterator();
        while (sig_iter.next()) |entry| {
            if (!self.partial_sigs.contains(entry.key_ptr.*)) {
                try self.partial_sigs.put(entry.key_ptr.*, try self.allocator.dupe(u8, entry.value_ptr.*));
            }
        }

        // Copy scripts if we don't have them
        if (self.redeem_script == null and other.redeem_script != null) {
            self.redeem_script = try self.allocator.dupe(u8, other.redeem_script.?);
        }
        if (self.witness_script == null and other.witness_script != null) {
            self.witness_script = try self.allocator.dupe(u8, other.witness_script.?);
        }

        // Copy sighash if we don't have it
        if (self.sighash_type == null) {
            self.sighash_type = other.sighash_type;
        }

        // Merge BIP32 derivations
        var bip32_iter = other.bip32_derivation.iterator();
        while (bip32_iter.next()) |entry| {
            if (!self.bip32_derivation.contains(entry.key_ptr.*)) {
                try self.bip32_derivation.put(entry.key_ptr.*, try entry.value_ptr.clone(self.allocator));
            }
        }
    }
};

// ============================================================================
// PSBT Output
// ============================================================================

/// Per-output PSBT data
pub const PsbtOutput = struct {
    redeem_script: ?[]const u8 = null,
    witness_script: ?[]const u8 = null,

    // BIP32 derivations
    bip32_derivation: std.AutoHashMap([33]u8, KeyOriginInfo),

    // Taproot data (BIP-371)
    tap_internal_key: ?[32]u8 = null,
    tap_tree: ?[]const u8 = null,
    // BIP-371 extended output taproot fields
    tap_bip32_derivation: std.AutoHashMap([32]u8, TapKeyOriginInfo),
    musig2_participants: std.ArrayList(MuSig2ParticipantEntry),

    // Unknown key-value pairs
    unknown: std.AutoHashMap(u64, UnknownEntry),

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PsbtOutput {
        return PsbtOutput{
            .bip32_derivation = std.AutoHashMap([33]u8, KeyOriginInfo).init(allocator),
            .tap_bip32_derivation = std.AutoHashMap([32]u8, TapKeyOriginInfo).init(allocator),
            .musig2_participants = std.ArrayList(MuSig2ParticipantEntry).init(allocator),
            .unknown = std.AutoHashMap(u64, UnknownEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PsbtOutput) void {
        // Free BIP32 derivations
        var bip32_iter = self.bip32_derivation.iterator();
        while (bip32_iter.next()) |entry| {
            var info = entry.value_ptr.*;
            info.deinit(self.allocator);
        }
        self.bip32_derivation.deinit();

        // Free unknown entries
        var unknown_iter = self.unknown.iterator();
        while (unknown_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.key);
            self.allocator.free(entry.value_ptr.value);
        }
        self.unknown.deinit();

        // Free scripts
        if (self.redeem_script) |s| self.allocator.free(s);
        if (self.witness_script) |s| self.allocator.free(s);
        if (self.tap_tree) |t| self.allocator.free(t);

        // Free BIP-371 extended output fields
        var tap_bip32_iter = self.tap_bip32_derivation.iterator();
        while (tap_bip32_iter.next()) |entry| {
            var info = entry.value_ptr.*;
            info.deinit(self.allocator);
        }
        self.tap_bip32_derivation.deinit();

        for (self.musig2_participants.items) |*entry| {
            self.allocator.free(entry.participant_pubkeys);
        }
        self.musig2_participants.deinit();
    }

    /// Merge another output into this one
    pub fn merge(self: *PsbtOutput, other: *const PsbtOutput) !void {
        if (self.redeem_script == null and other.redeem_script != null) {
            self.redeem_script = try self.allocator.dupe(u8, other.redeem_script.?);
        }
        if (self.witness_script == null and other.witness_script != null) {
            self.witness_script = try self.allocator.dupe(u8, other.witness_script.?);
        }
        if (self.tap_internal_key == null) {
            self.tap_internal_key = other.tap_internal_key;
        }

        // Merge BIP32 derivations
        var bip32_iter = other.bip32_derivation.iterator();
        while (bip32_iter.next()) |entry| {
            if (!self.bip32_derivation.contains(entry.key_ptr.*)) {
                try self.bip32_derivation.put(entry.key_ptr.*, try entry.value_ptr.clone(self.allocator));
            }
        }
    }
};

// ============================================================================
// PSBT (Main Structure)
// ============================================================================

/// A Partially Signed Bitcoin Transaction
pub const Psbt = struct {
    /// The unsigned transaction (required)
    tx: types.Transaction,

    /// Per-input data
    inputs: []PsbtInput,

    /// Per-output data
    outputs: []PsbtOutput,

    /// Global xpubs (KeyOriginInfo -> list of xpubs)
    xpubs: std.AutoHashMap([78]u8, KeyOriginInfo),

    /// PSBT version (0 for BIP174)
    version: u32 = 0,

    /// Unknown global key-value pairs
    unknown: std.AutoHashMap(u64, UnknownEntry),

    allocator: std.mem.Allocator,

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /// Create an empty PSBT (Creator role)
    pub fn create(allocator: std.mem.Allocator, tx: types.Transaction) !Psbt {
        // Validate that the transaction has empty scriptSigs and witnesses
        for (tx.inputs) |input| {
            if (input.script_sig.len > 0 or input.witness.len > 0) {
                return PsbtError.InvalidUnsignedTx;
            }
        }

        // Create input/output arrays
        const inputs = try allocator.alloc(PsbtInput, tx.inputs.len);
        errdefer allocator.free(inputs);
        for (inputs) |*input| {
            input.* = PsbtInput.init(allocator);
        }

        const outputs = try allocator.alloc(PsbtOutput, tx.outputs.len);
        errdefer allocator.free(outputs);
        for (outputs) |*output| {
            output.* = PsbtOutput.init(allocator);
        }

        // Clone the transaction
        const cloned_tx = try cloneTransaction(allocator, &tx);

        return Psbt{
            .tx = cloned_tx,
            .inputs = inputs,
            .outputs = outputs,
            .xpubs = std.AutoHashMap([78]u8, KeyOriginInfo).init(allocator),
            .version = 0,
            .unknown = std.AutoHashMap(u64, UnknownEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Psbt) void {
        // Free inputs
        for (self.inputs) |*input| {
            input.deinit();
        }
        self.allocator.free(self.inputs);

        // Free outputs
        for (self.outputs) |*output| {
            output.deinit();
        }
        self.allocator.free(self.outputs);

        // Free xpubs
        var xpub_iter = self.xpubs.iterator();
        while (xpub_iter.next()) |entry| {
            var info = entry.value_ptr.*;
            info.deinit(self.allocator);
        }
        self.xpubs.deinit();

        // Free unknown entries
        var unknown_iter = self.unknown.iterator();
        while (unknown_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.key);
            self.allocator.free(entry.value_ptr.value);
        }
        self.unknown.deinit();

        // Free transaction
        freeTransaction(self.allocator, &self.tx);
    }

    // ========================================================================
    // Updater Role
    // ========================================================================

    /// Add UTXO information for an input (Updater role)
    pub fn addInputUtxo(self: *Psbt, input_index: usize, utxo: types.TxOut) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;

        self.inputs[input_index].witness_utxo = types.TxOut{
            .value = utxo.value,
            .script_pubkey = try self.allocator.dupe(u8, utxo.script_pubkey),
        };
    }

    /// Add non-witness UTXO (full previous transaction) for an input
    pub fn addInputNonWitnessUtxo(self: *Psbt, input_index: usize, tx: types.Transaction) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;

        // Verify the txid matches
        const prev_outpoint = self.tx.inputs[input_index].previous_output;
        var writer = serialize_mod.Writer.init(self.allocator);
        defer writer.deinit();
        try serialize_mod.writeTransactionNoWitness(&writer, &tx);
        const txid = crypto.hash256(writer.getWritten());

        // Bitcoin displays txids in reverse byte order
        var reversed_txid: [32]u8 = undefined;
        for (0..32) |i| {
            reversed_txid[i] = txid[31 - i];
        }

        if (!std.mem.eql(u8, &reversed_txid, &prev_outpoint.hash)) {
            return PsbtError.NonWitnessUtxoMismatch;
        }

        self.inputs[input_index].non_witness_utxo = try cloneTransaction(self.allocator, &tx);
    }

    /// Add redeem script for an input
    pub fn addInputRedeemScript(self: *Psbt, input_index: usize, script: []const u8) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;
        self.inputs[input_index].redeem_script = try self.allocator.dupe(u8, script);
    }

    /// Add witness script for an input
    pub fn addInputWitnessScript(self: *Psbt, input_index: usize, script: []const u8) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;
        self.inputs[input_index].witness_script = try self.allocator.dupe(u8, script);
    }

    /// Add BIP32 derivation for an input
    pub fn addInputBip32Derivation(
        self: *Psbt,
        input_index: usize,
        pubkey: [33]u8,
        fingerprint: [4]u8,
        path: []const u32,
    ) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;

        const path_copy = try self.allocator.dupe(u32, path);
        try self.inputs[input_index].bip32_derivation.put(pubkey, KeyOriginInfo{
            .fingerprint = fingerprint,
            .path = path_copy,
        });
    }

    /// Set sighash type for an input
    pub fn setInputSighashType(self: *Psbt, input_index: usize, sighash: u32) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;
        self.inputs[input_index].sighash_type = sighash;
    }

    // ========================================================================
    // Signer Role
    // ========================================================================

    /// Add a partial signature for an input (Signer role)
    pub fn addPartialSig(
        self: *Psbt,
        input_index: usize,
        pubkey: [33]u8,
        signature: []const u8,
    ) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;

        const sig_copy = try self.allocator.dupe(u8, signature);
        try self.inputs[input_index].partial_sigs.put(pubkey, sig_copy);
    }

    // ========================================================================
    // Combiner Role
    // ========================================================================

    /// Combine multiple PSBTs into one (Combiner role)
    pub fn combine(allocator: std.mem.Allocator, psbts: []const *Psbt) !Psbt {
        if (psbts.len == 0) return PsbtError.InvalidFormat;

        // Use the first PSBT as the base
        var result = try psbts[0].clone(allocator);
        errdefer result.deinit();

        // Merge all other PSBTs
        for (psbts[1..]) |psbt| {
            try result.mergeFrom(psbt);
        }

        return result;
    }

    /// Merge another PSBT into this one
    pub fn mergeFrom(self: *Psbt, other: *const Psbt) !void {
        // Verify they have the same underlying transaction
        if (self.inputs.len != other.inputs.len or
            self.outputs.len != other.outputs.len)
        {
            return PsbtError.InvalidFormat;
        }

        // Merge inputs
        for (self.inputs, 0..) |*input, i| {
            try input.merge(&other.inputs[i]);
        }

        // Merge outputs
        for (self.outputs, 0..) |*output, i| {
            try output.merge(&other.outputs[i]);
        }
    }

    /// Clone this PSBT
    pub fn clone(self: *const Psbt, allocator: std.mem.Allocator) !Psbt {
        // Clone transaction
        const tx = try cloneTransaction(allocator, &self.tx);
        errdefer freeTransaction(allocator, @constCast(&tx));

        // Clone inputs
        const inputs = try allocator.alloc(PsbtInput, self.inputs.len);
        errdefer allocator.free(inputs);
        for (inputs, 0..) |*input, i| {
            input.* = try clonePsbtInput(allocator, &self.inputs[i]);
        }

        // Clone outputs
        const outputs = try allocator.alloc(PsbtOutput, self.outputs.len);
        errdefer allocator.free(outputs);
        for (outputs, 0..) |*output, i| {
            output.* = try clonePsbtOutput(allocator, &self.outputs[i]);
        }

        return Psbt{
            .tx = tx,
            .inputs = inputs,
            .outputs = outputs,
            .xpubs = std.AutoHashMap([78]u8, KeyOriginInfo).init(allocator),
            .version = self.version,
            .unknown = std.AutoHashMap(u64, UnknownEntry).init(allocator),
            .allocator = allocator,
        };
    }

    // ========================================================================
    // Finalizer Role
    // ========================================================================

    /// Finalize an input by constructing the scriptSig and/or witness (Finalizer role)
    pub fn finalizeInput(self: *Psbt, input_index: usize) !void {
        if (input_index >= self.inputs.len) return PsbtError.InputCountMismatch;

        var input = &self.inputs[input_index];

        // Already finalized?
        if (input.isFinalized()) return;

        // Get the UTXO to determine script type
        const script_pubkey = if (input.witness_utxo) |utxo|
            utxo.script_pubkey
        else if (input.non_witness_utxo) |tx|
            tx.outputs[self.tx.inputs[input_index].previous_output.index].script_pubkey
        else
            return PsbtError.MissingUtxo;

        // Determine script type and finalize accordingly
        if (isP2PKH(script_pubkey)) {
            try self.finalizeP2PKH(input_index);
        } else if (isP2WPKH(script_pubkey)) {
            try self.finalizeP2WPKH(input_index);
        } else if (isP2SH(script_pubkey)) {
            try self.finalizeP2SH(input_index);
        } else if (isP2WSH(script_pubkey)) {
            try self.finalizeP2WSH(input_index);
        }
        // TODO: Add P2TR finalization
    }

    fn finalizeP2PKH(self: *Psbt, input_index: usize) !void {
        var input = &self.inputs[input_index];

        // Need exactly one partial signature
        if (input.partial_sigs.count() != 1) return;

        var sig_iter = input.partial_sigs.iterator();
        const entry = sig_iter.next().?;
        const pubkey = entry.key_ptr.*;
        const sig = entry.value_ptr.*;

        // Build scriptSig: <sig> <pubkey>
        var script_sig = std.ArrayList(u8).init(self.allocator);
        defer script_sig.deinit();

        // Push signature
        try script_sig.append(@intCast(sig.len));
        try script_sig.appendSlice(sig);

        // Push pubkey
        try script_sig.append(33); // compressed pubkey
        try script_sig.appendSlice(&pubkey);

        input.final_script_sig = try script_sig.toOwnedSlice();
    }

    fn finalizeP2WPKH(self: *Psbt, input_index: usize) !void {
        var input = &self.inputs[input_index];

        // Need exactly one partial signature
        if (input.partial_sigs.count() != 1) return;

        var sig_iter = input.partial_sigs.iterator();
        const entry = sig_iter.next().?;
        const pubkey = entry.key_ptr.*;
        const sig = entry.value_ptr.*;

        // Build witness: [sig, pubkey]
        var witness = try self.allocator.alloc([]const u8, 2);
        witness[0] = try self.allocator.dupe(u8, sig);
        witness[1] = try self.allocator.dupe(u8, &pubkey);

        input.final_script_witness = witness;
    }

    fn finalizeP2SH(self: *Psbt, input_index: usize) !void {
        var input = &self.inputs[input_index];

        // Must have redeem script
        const redeem_script = input.redeem_script orelse return;

        // W31: Verify the BIP-16 P2SH commitment before emitting a
        // scriptSig that pushes `redeem_script`. Without this guard the
        // finalizer would happily wrap an arbitrary attacker-supplied
        // redeemScript into a structurally-valid scriptSig — every later
        // verifier would reject it anyway (Core enforces hash160 ==
        // scriptPubKey[2..22]), but we'd silently emit a tx that loses
        // value to fees in the relay pipeline. This matches the same bug
        // shape found across hotbuns/blockbrew/etc.
        //
        // W47: Legacy P2SH-multisig uses PSBT_IN_NON_WITNESS_UTXO (BIP-174
        // forbids witness_utxo for non-segwit), so accept either source.
        // The on-chain P2SH script is `OP_HASH160 <20-byte hash> OP_EQUAL`
        // (23 bytes total) regardless of which UTXO field carries it.
        const spk: []const u8 = if (input.witness_utxo) |utxo|
            utxo.script_pubkey
        else if (input.non_witness_utxo) |tx|
            tx.outputs[self.tx.inputs[input_index].previous_output.index].script_pubkey
        else
            return PsbtError.MissingUtxo;
        if (!isP2SH(spk)) {
            // Caller routed a non-P2SH UTXO to finalizeP2SH; refuse to
            // emit anything rather than commit to garbage.
            return PsbtError.RedeemScriptCommitmentMismatch;
        }
        const expected_h160 = spk[2..22];
        const actual_h160 = crypto.hash160(redeem_script);
        if (!std.mem.eql(u8, expected_h160, &actual_h160)) {
            return PsbtError.RedeemScriptCommitmentMismatch;
        }

        // W47: Dispatch on inner-script shape. Three live variants:
        //   - P2SH-P2WPKH:   redeem = `OP_0 <20>`
        //   - P2SH-P2WSH:    redeem = `OP_0 <32>`  (multisig witnessScript)
        //   - legacy P2SH-multisig: redeem = `OP_M ... OP_N OP_CHECKMULTISIG`
        if (isP2WPKH(redeem_script)) {
            // Need exactly one partial signature
            if (input.partial_sigs.count() != 1) return;

            var sig_iter = input.partial_sigs.iterator();
            const entry = sig_iter.next().?;
            const pubkey = entry.key_ptr.*;
            const sig = entry.value_ptr.*;

            // Build witness
            var witness = try self.allocator.alloc([]const u8, 2);
            witness[0] = try self.allocator.dupe(u8, sig);
            witness[1] = try self.allocator.dupe(u8, &pubkey);
            input.final_script_witness = witness;

            // Build scriptSig: push(redeemScript)
            var script_sig = std.ArrayList(u8).init(self.allocator);
            defer script_sig.deinit();
            try pushScriptData(&script_sig, redeem_script);
            input.final_script_sig = try script_sig.toOwnedSlice();

            try clearProducerFields(input);
        } else if (isP2WSH(redeem_script)) {
            // P2SH-P2WSH-multisig. Outer commitment already checked above.
            // The redeem_script must commit to sha256(witness_script).
            try self.finalizeP2SHP2WSHMultisig(input_index);
        } else if (parseMultisigScript(redeem_script) != null) {
            // Legacy P2SH-multisig.
            try self.finalizeP2SHMultisig(input_index);
        }
        // Unknown P2SH inner shape → leave unfinalized (matches Core: no
        // signal, just `complete:false`).
    }

    fn finalizeP2WSH(self: *Psbt, input_index: usize) !void {
        // W47: Bare P2WSH-multisig (witness program v0, 32-byte hash).
        // Outer commitment is `sha256(witness_script) == spk[2..34]`.
        const input = &self.inputs[input_index];

        const witness_script = input.witness_script orelse return;
        const witness_utxo = input.witness_utxo orelse return PsbtError.MissingUtxo;
        const spk = witness_utxo.script_pubkey;
        if (!isP2WSH(spk)) {
            return PsbtError.WitnessScriptCommitmentMismatch;
        }
        const expected_sha = spk[2..34];
        const actual_sha = crypto.sha256(witness_script);
        if (!std.mem.eql(u8, expected_sha, &actual_sha)) {
            return PsbtError.WitnessScriptCommitmentMismatch;
        }

        try self.buildP2WSHMultisigWitness(input_index, witness_script);
        // Only clear producer fields if we actually finalized — for
        // 1-of-3 multisigs missing M sigs, buildP2WSHMultisigWitness
        // silently leaves the input unfinalized so a later combine() can
        // complete it.
        if (input.final_script_witness != null) {
            try clearProducerFields(input);
        }
    }

    /// W47: Legacy P2SH-multisig finalizer.
    ///
    /// Builds the BIP-11 scriptSig:
    ///   `OP_0 <push sig1> ... <push sigM> <push redeem_script>`
    /// where the M signatures are picked in script-pubkey order (i.e. the
    /// order pubkeys appear in `redeem_script`), NOT insertion order, NOT
    /// hash-table order, and NOT pubkey-byte order. This matches Core
    /// `script/sign.cpp::PushAll` which iterates the multisig pubkey vector
    /// in script order and emits whichever sig matches each slot.
    /// Reference: bitcoin-core/src/script/sign.cpp ProduceSignature.
    fn finalizeP2SHMultisig(self: *Psbt, input_index: usize) !void {
        var input = &self.inputs[input_index];
        const redeem_script = input.redeem_script orelse return;
        const ms = parseMultisigScript(redeem_script) orelse return;

        // Pick sigs in script-pubkey pubkey order. M sigs needed.
        var sigs = std.ArrayList([]const u8).init(self.allocator);
        defer sigs.deinit();
        try collectMultisigSigsInScriptOrder(input, ms, &sigs);

        // Need at least M signatures to finalize.
        if (sigs.items.len < ms.m) return;
        const used = sigs.items[0..ms.m];

        var script_sig = std.ArrayList(u8).init(self.allocator);
        defer script_sig.deinit();
        // Multisig CHECKMULTISIG dummy (BIP-147 enforces it must be empty
        // OP_0, encoded as 0x00 single byte).
        try script_sig.append(0x00); // OP_0 (the bug-fix dummy)
        for (used) |s| {
            try pushScriptData(&script_sig, s);
        }
        try pushScriptData(&script_sig, redeem_script);
        input.final_script_sig = try script_sig.toOwnedSlice();

        try clearProducerFields(input);
    }

    /// W47: P2SH-P2WSH-multisig finalizer.
    ///
    /// Outer (legacy) scriptSig is a single push of the redeem_script
    /// (`OP_0 PUSH32 sha256(witness_script)`). Inner witness stack is the
    /// same shape as bare P2WSH-multisig: `[OP_0_byte, sig1, ..., sigM,
    /// witness_script]`.
    fn finalizeP2SHP2WSHMultisig(self: *Psbt, input_index: usize) !void {
        var input = &self.inputs[input_index];
        const redeem_script = input.redeem_script orelse return;
        const witness_script = input.witness_script orelse return;

        // W31/W38 commitment chain: outer P2SH→redeem already checked by
        // caller (`finalizeP2SH`). Now check inner P2WSH commitment:
        // `redeem_script[2..34] == sha256(witness_script)`.
        if (redeem_script.len != 34 or redeem_script[0] != 0x00 or redeem_script[1] != 0x20) {
            return PsbtError.WitnessScriptCommitmentMismatch;
        }
        const expected_sha = redeem_script[2..34];
        const actual_sha = crypto.sha256(witness_script);
        if (!std.mem.eql(u8, expected_sha, &actual_sha)) {
            return PsbtError.WitnessScriptCommitmentMismatch;
        }

        try self.buildP2WSHMultisigWitness(input_index, witness_script);
        // If the witness side couldn't finalize (missing sigs), don't
        // emit a half-finished outer scriptSig either — leave the input
        // for combine() to complete.
        if (input.final_script_witness == null) return;

        // Outer scriptSig: `<push redeem_script>`.
        var script_sig = std.ArrayList(u8).init(self.allocator);
        defer script_sig.deinit();
        try pushScriptData(&script_sig, redeem_script);
        input.final_script_sig = try script_sig.toOwnedSlice();

        try clearProducerFields(input);
    }

    /// Shared P2WSH-multisig witness-stack builder. Used by bare
    /// P2WSH-multisig (`finalizeP2WSH`) and P2SH-P2WSH-multisig
    /// (`finalizeP2SHP2WSHMultisig`). Sets `final_script_witness` only;
    /// caller is responsible for any outer scriptSig and `clearProducerFields`.
    fn buildP2WSHMultisigWitness(
        self: *Psbt,
        input_index: usize,
        witness_script: []const u8,
    ) !void {
        var input = &self.inputs[input_index];
        const ms = parseMultisigScript(witness_script) orelse
            return; // unknown witness-script shape → leave unfinalized

        var sigs = std.ArrayList([]const u8).init(self.allocator);
        defer sigs.deinit();
        try collectMultisigSigsInScriptOrder(input, ms, &sigs);
        if (sigs.items.len < ms.m) return;
        const used = sigs.items[0..ms.m];

        // Witness stack: [OP_0_byte (0x00 dummy), sig1, ..., sigM, witness_script]
        const stack_len = 1 + ms.m + 1;
        var witness = try self.allocator.alloc([]const u8, stack_len);
        errdefer self.allocator.free(witness);
        // The dummy must be a zero-length push (OP_0 byte in scriptSig
        // becomes empty stack element in witness — Core PushAll emits
        // CScript() << OP_0 which the witness layer encodes as empty).
        witness[0] = try self.allocator.dupe(u8, &[_]u8{});
        for (used, 0..) |s, i| {
            witness[1 + i] = try self.allocator.dupe(u8, s);
        }
        witness[stack_len - 1] = try self.allocator.dupe(u8, witness_script);
        input.final_script_witness = witness;
    }

    /// Finalize all inputs
    pub fn finalize(self: *Psbt) !void {
        for (0..self.inputs.len) |i| {
            try self.finalizeInput(i);
        }
    }

    // ========================================================================
    // Extractor Role
    // ========================================================================

    /// Check if the PSBT is complete (all inputs finalized)
    pub fn isComplete(self: *const Psbt) bool {
        for (self.inputs) |*input| {
            if (!input.isFinalized()) return false;
        }
        return true;
    }

    /// Extract the final signed transaction (Extractor role)
    pub fn extract(self: *Psbt) !types.Transaction {
        if (!self.isComplete()) return PsbtError.NotFinalized;

        // Build the final transaction
        const inputs = try self.allocator.alloc(types.TxIn, self.tx.inputs.len);
        errdefer self.allocator.free(inputs);

        for (inputs, 0..) |*input, i| {
            const psbt_input = &self.inputs[i];
            const orig_input = &self.tx.inputs[i];

            // W47: deep-clone the witness stack. The previous shape used
            // `allocator.dupe([]const u8, w)` which only duplicates the
            // outer `[]const u8` slice — the inner item slices still
            // pointed into PsbtInput's allocation. The RPC handler
            // (`handleFinalizePsbt` in rpc.zig:5460-5466) then freed each
            // item AND `psbt.deinit()` freed the same items again →
            // double-free in glibc tcache. This was latent because the
            // pre-W47 finalizer never produced a complete PSBT, so
            // extract() was never reached. Now that multisig finalize
            // works, the bug fires on every harness run.
            const witness_clone: []const []const u8 = if (psbt_input.final_script_witness) |w| blk: {
                const items = try self.allocator.alloc([]const u8, w.len);
                errdefer self.allocator.free(items);
                for (w, 0..) |item, k| {
                    items[k] = try self.allocator.dupe(u8, item);
                }
                break :blk items;
            } else &[_][]const u8{};

            input.* = types.TxIn{
                .previous_output = orig_input.previous_output,
                .script_sig = if (psbt_input.final_script_sig) |s|
                    try self.allocator.dupe(u8, s)
                else
                    &[_]u8{},
                .sequence = orig_input.sequence,
                .witness = witness_clone,
            };
        }

        // Clone outputs
        const outputs = try self.allocator.alloc(types.TxOut, self.tx.outputs.len);
        for (outputs, 0..) |*output, i| {
            output.* = types.TxOut{
                .value = self.tx.outputs[i].value,
                .script_pubkey = try self.allocator.dupe(u8, self.tx.outputs[i].script_pubkey),
            };
        }

        return types.Transaction{
            .version = self.tx.version,
            .inputs = inputs,
            .outputs = outputs,
            .lock_time = self.tx.lock_time,
        };
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Serialize the PSBT to binary format
    pub fn serialize(self: *const Psbt, allocator: std.mem.Allocator) ![]const u8 {
        var writer = serialize_mod.Writer.init(allocator);
        errdefer writer.deinit();

        // Magic bytes
        try writer.writeBytes(&PSBT_MAGIC);

        // Global map
        try self.serializeGlobalMap(&writer);

        // Input maps
        for (self.inputs) |*input| {
            try self.serializeInputMap(&writer, input);
        }

        // Output maps
        for (self.outputs) |*output| {
            try self.serializeOutputMap(&writer, output);
        }

        return try writer.toOwnedSlice();
    }

    fn serializeGlobalMap(self: *const Psbt, writer: *serialize_mod.Writer) !void {
        // Unsigned TX (required). BIP-174 mandates the unsigned-tx body be
        // serialized in NON-segwit form (no `00 01` marker, no witness
        // sections), even when downstream inputs carry witness data — those
        // travel in PSBT_IN_FINAL_SCRIPTWITNESS (key 0x08) instead.
        // `writeTransactionNoWitness` already enforces that.
        //
        // Critical: `tx_writer` MUST outlive the `writeKeyValue` call below.
        // The previous shape used a labeled block `blk: { var tx_writer =
        // ...; defer tx_writer.deinit(); break :blk tx_writer.getWritten(); }`
        // — but Zig's `defer` runs at scope exit of the enclosing block, so
        // the writer was deinit'd BEFORE `writeKeyValue` consumed the slice.
        // The slice then pointed into freed/reused memory, producing a
        // garbage unsigned-tx body that round-tripped to `EndOfStream`
        // inside `readTransaction.script_sig`. Hoist the writer to function
        // scope so the defer fires after the value has been copied out.
        var tx_writer = serialize_mod.Writer.init(self.allocator);
        defer tx_writer.deinit();
        try serialize_mod.writeTransactionNoWitness(&tx_writer, &self.tx);
        try self.writeKeyValue(
            writer,
            PSBT_GLOBAL_UNSIGNED_TX,
            &[_]u8{},
            tx_writer.getWritten(),
        );

        // Version (if non-zero)
        if (self.version > 0) {
            var version_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &version_buf, self.version, .little);
            try self.writeKeyValue(writer, PSBT_GLOBAL_VERSION, &[_]u8{}, &version_buf);
        }

        // TODO: Serialize xpubs

        // Separator
        try writer.writeInt(u8, PSBT_SEPARATOR);
    }

    fn serializeInputMap(self: *const Psbt, writer: *serialize_mod.Writer, input: *const PsbtInput) !void {
        // Non-witness UTXO
        if (input.non_witness_utxo) |tx| {
            var tx_writer = serialize_mod.Writer.init(self.allocator);
            defer tx_writer.deinit();
            try serialize_mod.writeTransaction(&tx_writer, &tx);
            try self.writeKeyValue(writer, PSBT_IN_NON_WITNESS_UTXO, &[_]u8{}, tx_writer.getWritten());
        }

        // Witness UTXO
        if (input.witness_utxo) |utxo| {
            var utxo_writer = serialize_mod.Writer.init(self.allocator);
            defer utxo_writer.deinit();
            try utxo_writer.writeInt(i64, utxo.value);
            try utxo_writer.writeCompactSize(utxo.script_pubkey.len);
            try utxo_writer.writeBytes(utxo.script_pubkey);
            try self.writeKeyValue(writer, PSBT_IN_WITNESS_UTXO, &[_]u8{}, utxo_writer.getWritten());
        }

        // Partial signatures (not finalized)
        if (!input.isFinalized()) {
            // W47: deterministic emit order. Storage is std.AutoHashMap
            // (unordered, hash-table iteration), but Core's
            // `std::map<CKeyID, SigPair>` (psbt.h:270) emits sorted by
            // HASH160(pubkey). Without this the bytes of the serialized
            // PSBT differ between processes (and between combine()
            // permutations), tripping the cross-impl T2 round-trip
            // assertion. Same fix-shape as blockbrew W45 e000f9b /
            // beamchain W46-2 e8f04a0 / ouroboros W46-4 3d44478.
            const sorted_sigs = try sortedPartialSigs(self.allocator, &input.partial_sigs);
            defer self.allocator.free(sorted_sigs);
            for (sorted_sigs) |entry| {
                try self.writeKeyValue(writer, PSBT_IN_PARTIAL_SIG, &entry.pubkey, entry.sig);
            }

            // Sighash type
            if (input.sighash_type) |sighash| {
                var sighash_buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &sighash_buf, sighash, .little);
                try self.writeKeyValue(writer, PSBT_IN_SIGHASH, &[_]u8{}, &sighash_buf);
            }

            // Redeem script
            if (input.redeem_script) |script| {
                try self.writeKeyValue(writer, PSBT_IN_REDEEMSCRIPT, &[_]u8{}, script);
            }

            // Witness script
            if (input.witness_script) |script| {
                try self.writeKeyValue(writer, PSBT_IN_WITNESSSCRIPT, &[_]u8{}, script);
            }

            // BIP32 derivations.
            // W47: sort by raw pubkey bytes. Core
            // `std::map<CPubKey, KeyOriginInfo>` (psbt.h:269).
            const sorted_d = try sortedBip32Derivation(self.allocator, &input.bip32_derivation);
            defer self.allocator.free(sorted_d);
            for (sorted_d) |entry| {
                var value_writer = serialize_mod.Writer.init(self.allocator);
                defer value_writer.deinit();
                try value_writer.writeBytes(&entry.info.fingerprint);
                for (entry.info.path) |idx| {
                    try value_writer.writeInt(u32, idx);
                }
                try self.writeKeyValue(writer, PSBT_IN_BIP32_DERIVATION, &entry.pubkey, value_writer.getWritten());
            }
        }

        // Final scriptSig
        if (input.final_script_sig) |script| {
            try self.writeKeyValue(writer, PSBT_IN_SCRIPTSIG, &[_]u8{}, script);
        }

        // Final scriptWitness
        if (input.final_script_witness) |witness| {
            var witness_writer = serialize_mod.Writer.init(self.allocator);
            defer witness_writer.deinit();
            try witness_writer.writeCompactSize(witness.len);
            for (witness) |item| {
                try witness_writer.writeCompactSize(item.len);
                try witness_writer.writeBytes(item);
            }
            try self.writeKeyValue(writer, PSBT_IN_SCRIPTWITNESS, &[_]u8{}, witness_writer.getWritten());
        }

        // Separator
        try writer.writeInt(u8, PSBT_SEPARATOR);
    }

    fn serializeOutputMap(self: *const Psbt, writer: *serialize_mod.Writer, output: *const PsbtOutput) !void {
        // Redeem script
        if (output.redeem_script) |script| {
            try self.writeKeyValue(writer, PSBT_OUT_REDEEMSCRIPT, &[_]u8{}, script);
        }

        // Witness script
        if (output.witness_script) |script| {
            try self.writeKeyValue(writer, PSBT_OUT_WITNESSSCRIPT, &[_]u8{}, script);
        }

        // BIP32 derivations.
        // W47: sort by raw pubkey bytes (same key as input bip32, mirrors
        // Core's `std::map<CPubKey, KeyOriginInfo>` from psbt.h:269).
        const sorted_d = try sortedBip32Derivation(self.allocator, &output.bip32_derivation);
        defer self.allocator.free(sorted_d);
        for (sorted_d) |entry| {
            var value_writer = serialize_mod.Writer.init(self.allocator);
            defer value_writer.deinit();
            try value_writer.writeBytes(&entry.info.fingerprint);
            for (entry.info.path) |idx| {
                try value_writer.writeInt(u32, idx);
            }
            try self.writeKeyValue(writer, PSBT_OUT_BIP32_DERIVATION, &entry.pubkey, value_writer.getWritten());
        }

        // Separator
        try writer.writeInt(u8, PSBT_SEPARATOR);
    }

    fn writeKeyValue(
        self: *const Psbt,
        writer: *serialize_mod.Writer,
        key_type: u8,
        key_data: []const u8,
        value: []const u8,
    ) !void {
        _ = self;
        // Key: <compact_size(key_len)><key_type><key_data>
        try writer.writeCompactSize(1 + key_data.len);
        try writer.writeInt(u8, key_type);
        if (key_data.len > 0) {
            try writer.writeBytes(key_data);
        }

        // Value: <compact_size(value_len)><value>
        try writer.writeCompactSize(value.len);
        if (value.len > 0) {
            try writer.writeBytes(value);
        }
    }

    // ========================================================================
    // Deserialization
    // ========================================================================

    /// Deserialize a PSBT from binary data
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !Psbt {
        if (data.len < 5) return PsbtError.InvalidMagic;

        var reader = serialize_mod.Reader{ .data = data };

        // Check magic
        const magic = try reader.readBytes(5);
        if (!std.mem.eql(u8, magic, &PSBT_MAGIC)) {
            return PsbtError.InvalidMagic;
        }

        // Parse global map
        var tx: ?types.Transaction = null;
        var version: u32 = 0;
        var global_unknown = std.AutoHashMap(u64, UnknownEntry).init(allocator);
        var xpubs = std.AutoHashMap([78]u8, KeyOriginInfo).init(allocator);

        errdefer {
            if (tx) |*t| freeTransaction(allocator, t);
            global_unknown.deinit();
            xpubs.deinit();
        }

        // Read global key-value pairs
        while (true) {
            const key_len = try reader.readCompactSize();
            if (key_len == 0) break; // Separator

            const key_bytes = try reader.readBytes(@intCast(key_len));
            const key_type = key_bytes[0];
            const key_data = key_bytes[1..];

            const value_len = try reader.readCompactSize();
            const value = try reader.readBytes(@intCast(value_len));

            switch (key_type) {
                PSBT_GLOBAL_UNSIGNED_TX => {
                    if (key_data.len != 0) return PsbtError.InvalidKeyLength;
                    var tx_reader = serialize_mod.Reader{ .data = value };
                    tx = try serialize_mod.readTransaction(&tx_reader, allocator);
                },
                PSBT_GLOBAL_VERSION => {
                    if (value.len != 4) return PsbtError.InvalidValueLength;
                    version = std.mem.readInt(u32, value[0..4], .little);
                    if (version > PSBT_HIGHEST_VERSION) return PsbtError.UnsupportedVersion;
                },
                else => {
                    // Store unknown entries
                    const key_hash = std.hash.Wyhash.hash(0, key_bytes);
                    try global_unknown.put(key_hash, .{
                        .key = try allocator.dupe(u8, key_bytes),
                        .value = try allocator.dupe(u8, value),
                    });
                },
            }
        }

        // Must have unsigned tx
        const unsigned_tx = tx orelse return PsbtError.MissingUnsignedTx;

        // Create input array
        const inputs = try allocator.alloc(PsbtInput, unsigned_tx.inputs.len);
        errdefer allocator.free(inputs);
        for (inputs) |*input| {
            input.* = PsbtInput.init(allocator);
        }

        // Parse input maps
        for (inputs) |*input| {
            try parseInputMap(allocator, &reader, input);
        }

        // Create output array
        const outputs = try allocator.alloc(PsbtOutput, unsigned_tx.outputs.len);
        errdefer allocator.free(outputs);
        for (outputs) |*output| {
            output.* = PsbtOutput.init(allocator);
        }

        // Parse output maps
        for (outputs) |*output| {
            try parseOutputMap(allocator, &reader, output);
        }

        return Psbt{
            .tx = unsigned_tx,
            .inputs = inputs,
            .outputs = outputs,
            .xpubs = xpubs,
            .version = version,
            .unknown = global_unknown,
            .allocator = allocator,
        };
    }

    // ========================================================================
    // Base64 Encoding/Decoding
    // ========================================================================

    /// Encode PSBT to Base64 string
    pub fn toBase64(self: *const Psbt, allocator: std.mem.Allocator) ![]const u8 {
        const binary = try self.serialize(allocator);
        defer allocator.free(binary);

        const encoder = std.base64.standard;
        const encoded_len = encoder.Encoder.calcSize(binary.len);
        const encoded = try allocator.alloc(u8, encoded_len);

        _ = encoder.Encoder.encode(encoded, binary);
        return encoded;
    }

    /// Decode PSBT from Base64 string
    pub fn fromBase64(allocator: std.mem.Allocator, base64_str: []const u8) !Psbt {
        const decoder = std.base64.standard;
        const decoded_len = try decoder.Decoder.calcSizeForSlice(base64_str);
        const decoded = try allocator.alloc(u8, decoded_len);
        defer allocator.free(decoded);

        try decoder.Decoder.decode(decoded, base64_str);
        return try Psbt.deserialize(allocator, decoded);
    }

    // ========================================================================
    // Analysis
    // ========================================================================

    /// Analyze the PSBT state
    pub const AnalysisResult = struct {
        inputs_signed: usize,
        inputs_finalized: usize,
        total_inputs: usize,
        estimated_vsize: ?u32,
        estimated_fee: ?i64,
        next_role: []const u8,
    };

    pub fn analyze(self: *const Psbt) AnalysisResult {
        var signed: usize = 0;
        var finalized: usize = 0;

        for (self.inputs) |*input| {
            if (input.isFinalized()) {
                finalized += 1;
                signed += 1;
            } else if (input.partial_sigs.count() > 0) {
                signed += 1;
            }
        }

        const next_role: []const u8 = if (finalized == self.inputs.len)
            "extractor"
        else if (signed == self.inputs.len)
            "finalizer"
        else if (signed > 0)
            "signer"
        else
            "updater";

        // Calculate fee if we have all UTXOs
        var total_input: i64 = 0;
        var have_all_utxos = true;
        for (self.inputs, 0..) |*input, i| {
            if (input.witness_utxo) |utxo| {
                total_input += utxo.value;
            } else if (input.non_witness_utxo) |tx| {
                const idx = self.tx.inputs[i].previous_output.index;
                if (idx < tx.outputs.len) {
                    total_input += tx.outputs[idx].value;
                } else {
                    have_all_utxos = false;
                }
            } else {
                have_all_utxos = false;
            }
        }

        var total_output: i64 = 0;
        for (self.tx.outputs) |output| {
            total_output += output.value;
        }

        const fee: ?i64 = if (have_all_utxos) total_input - total_output else null;

        return AnalysisResult{
            .inputs_signed = signed,
            .inputs_finalized = finalized,
            .total_inputs = self.inputs.len,
            .estimated_vsize = null, // TODO: estimate vsize
            .estimated_fee = fee,
            .next_role = next_role,
        };
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

fn parseInputMap(allocator: std.mem.Allocator, reader: *serialize_mod.Reader, input: *PsbtInput) !void {
    while (true) {
        const key_len = try reader.readCompactSize();
        if (key_len == 0) break; // Separator

        const key_bytes = try reader.readBytes(@intCast(key_len));
        const key_type = key_bytes[0];
        const key_data = key_bytes[1..];

        const value_len = try reader.readCompactSize();
        const value = try reader.readBytes(@intCast(value_len));

        switch (key_type) {
            PSBT_IN_NON_WITNESS_UTXO => {
                var tx_reader = serialize_mod.Reader{ .data = value };
                input.non_witness_utxo = try serialize_mod.readTransaction(&tx_reader, allocator);
            },
            PSBT_IN_WITNESS_UTXO => {
                var utxo_reader = serialize_mod.Reader{ .data = value };
                const utxo_value = try utxo_reader.readInt(i64);
                const script_len = try utxo_reader.readCompactSize();
                const script = try utxo_reader.readBytes(@intCast(script_len));
                input.witness_utxo = types.TxOut{
                    .value = utxo_value,
                    .script_pubkey = try allocator.dupe(u8, script),
                };
            },
            PSBT_IN_PARTIAL_SIG => {
                if (key_data.len != 33 and key_data.len != 65) {
                    return PsbtError.InvalidKeyLength;
                }
                var pubkey: [33]u8 = undefined;
                @memcpy(&pubkey, key_data[0..33]);
                try input.partial_sigs.put(pubkey, try allocator.dupe(u8, value));
            },
            PSBT_IN_SIGHASH => {
                if (value.len != 4) return PsbtError.InvalidValueLength;
                input.sighash_type = std.mem.readInt(u32, value[0..4], .little);
            },
            PSBT_IN_REDEEMSCRIPT => {
                input.redeem_script = try allocator.dupe(u8, value);
            },
            PSBT_IN_WITNESSSCRIPT => {
                input.witness_script = try allocator.dupe(u8, value);
            },
            PSBT_IN_BIP32_DERIVATION => {
                if (key_data.len != 33) return PsbtError.InvalidKeyLength;
                if (value.len < 4 or (value.len - 4) % 4 != 0) return PsbtError.InvalidValueLength;

                var pubkey: [33]u8 = undefined;
                @memcpy(&pubkey, key_data[0..33]);

                var fingerprint: [4]u8 = undefined;
                @memcpy(&fingerprint, value[0..4]);

                const path_len = (value.len - 4) / 4;
                const path = try allocator.alloc(u32, path_len);
                for (0..path_len) |i| {
                    path[i] = std.mem.readInt(u32, value[4 + i * 4 ..][0..4], .little);
                }

                try input.bip32_derivation.put(pubkey, KeyOriginInfo{
                    .fingerprint = fingerprint,
                    .path = path,
                });
            },
            PSBT_IN_SCRIPTSIG => {
                input.final_script_sig = try allocator.dupe(u8, value);
            },
            PSBT_IN_SCRIPTWITNESS => {
                var witness_reader = serialize_mod.Reader{ .data = value };
                const witness_count = try witness_reader.readCompactSize();
                var witness = try allocator.alloc([]const u8, @intCast(witness_count));
                for (0..@intCast(witness_count)) |i| {
                    const item_len = try witness_reader.readCompactSize();
                    witness[i] = try allocator.dupe(u8, try witness_reader.readBytes(@intCast(item_len)));
                }
                input.final_script_witness = witness;
            },
            PSBT_IN_TAP_KEY_SIG => {
                input.tap_key_sig = try allocator.dupe(u8, value);
            },
            PSBT_IN_TAP_SCRIPT_SIG => {
                // key_data = x-only-pubkey(32) || leaf_hash(32); value = sig
                if (key_data.len != 64) return PsbtError.InvalidKeyLength;
                var pubkey: [32]u8 = undefined;
                var leaf_hash: [32]u8 = undefined;
                @memcpy(&pubkey, key_data[0..32]);
                @memcpy(&leaf_hash, key_data[32..64]);
                try input.tap_script_sigs.append(TapScriptSig{
                    .pubkey = pubkey,
                    .leaf_hash = leaf_hash,
                    .sig = try allocator.dupe(u8, value),
                });
            },
            PSBT_IN_TAP_LEAF_SCRIPT => {
                // key_data = control_block; value = script || leaf_ver(1)
                if (value.len < 1) return PsbtError.InvalidValueLength;
                const script_len = value.len - 1;
                const leaf_ver = value[value.len - 1];
                try input.tap_leaf_scripts.append(TapLeafScript{
                    .control_block = try allocator.dupe(u8, key_data),
                    .script = try allocator.dupe(u8, value[0..script_len]),
                    .leaf_ver = leaf_ver,
                });
            },
            PSBT_IN_TAP_BIP32_DERIVATION => {
                // key_data = x-only pubkey (32 bytes)
                // value = compact_size(n_leaf_hashes) || [32]u8 * n || fingerprint(4) || path(4*m)
                if (key_data.len != 32) return PsbtError.InvalidKeyLength;
                var xonly: [32]u8 = undefined;
                @memcpy(&xonly, key_data[0..32]);
                var val_reader = serialize_mod.Reader{ .data = value };
                const n_leaf_hashes = try val_reader.readCompactSize();
                const leaf_hashes = try allocator.alloc([32]u8, @intCast(n_leaf_hashes));
                errdefer allocator.free(leaf_hashes);
                for (0..@intCast(n_leaf_hashes)) |i| {
                    const lh_bytes = try val_reader.readBytes(32);
                    @memcpy(&leaf_hashes[i], lh_bytes[0..32]);
                }
                // remaining bytes: fingerprint(4) + path(4*m)
                const remaining = value[val_reader.pos..];
                if (remaining.len < 4 or (remaining.len - 4) % 4 != 0) {
                    allocator.free(leaf_hashes);
                    return PsbtError.InvalidValueLength;
                }
                var fingerprint: [4]u8 = undefined;
                @memcpy(&fingerprint, remaining[0..4]);
                const path_len = (remaining.len - 4) / 4;
                const path = try allocator.alloc(u32, path_len);
                errdefer allocator.free(path);
                for (0..path_len) |i| {
                    path[i] = std.mem.readInt(u32, remaining[4 + i * 4 ..][0..4], .little);
                }
                try input.tap_bip32_derivation.put(xonly, TapKeyOriginInfo{
                    .leaf_hashes = leaf_hashes,
                    .fingerprint = fingerprint,
                    .path = path,
                });
            },
            PSBT_IN_TAP_INTERNAL_KEY => {
                if (value.len != 32) return PsbtError.InvalidValueLength;
                var key_bytes_arr: [32]u8 = undefined;
                @memcpy(&key_bytes_arr, value[0..32]);
                input.tap_internal_key = key_bytes_arr;
            },
            PSBT_IN_TAP_MERKLE_ROOT => {
                if (value.len != 32) return PsbtError.InvalidValueLength;
                var key_bytes_arr: [32]u8 = undefined;
                @memcpy(&key_bytes_arr, value[0..32]);
                input.tap_merkle_root = key_bytes_arr;
            },
            else => {
                // Store unknown entries
                const key_hash = std.hash.Wyhash.hash(0, key_bytes);
                try input.unknown.put(key_hash, .{
                    .key = try allocator.dupe(u8, key_bytes),
                    .value = try allocator.dupe(u8, value),
                });
            },
        }
    }
}

fn parseOutputMap(allocator: std.mem.Allocator, reader: *serialize_mod.Reader, output: *PsbtOutput) !void {
    while (true) {
        const key_len = try reader.readCompactSize();
        if (key_len == 0) break; // Separator

        const key_bytes = try reader.readBytes(@intCast(key_len));
        const key_type = key_bytes[0];
        const key_data = key_bytes[1..];

        const value_len = try reader.readCompactSize();
        const value = try reader.readBytes(@intCast(value_len));

        switch (key_type) {
            PSBT_OUT_REDEEMSCRIPT => {
                output.redeem_script = try allocator.dupe(u8, value);
            },
            PSBT_OUT_WITNESSSCRIPT => {
                output.witness_script = try allocator.dupe(u8, value);
            },
            PSBT_OUT_BIP32_DERIVATION => {
                if (key_data.len != 33) return PsbtError.InvalidKeyLength;
                if (value.len < 4 or (value.len - 4) % 4 != 0) return PsbtError.InvalidValueLength;

                var pubkey: [33]u8 = undefined;
                @memcpy(&pubkey, key_data[0..33]);

                var fingerprint: [4]u8 = undefined;
                @memcpy(&fingerprint, value[0..4]);

                const path_len = (value.len - 4) / 4;
                const path = try allocator.alloc(u32, path_len);
                for (0..path_len) |i| {
                    path[i] = std.mem.readInt(u32, value[4 + i * 4 ..][0..4], .little);
                }

                try output.bip32_derivation.put(pubkey, KeyOriginInfo{
                    .fingerprint = fingerprint,
                    .path = path,
                });
            },
            PSBT_OUT_TAP_INTERNAL_KEY => {
                if (value.len != 32) return PsbtError.InvalidValueLength;
                var key_bytes_arr: [32]u8 = undefined;
                @memcpy(&key_bytes_arr, value[0..32]);
                output.tap_internal_key = key_bytes_arr;
            },
            PSBT_OUT_TAP_TREE => {
                output.tap_tree = try allocator.dupe(u8, value);
            },
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                // same wire format as PSBT_IN_TAP_BIP32_DERIVATION
                if (key_data.len != 32) return PsbtError.InvalidKeyLength;
                var xonly: [32]u8 = undefined;
                @memcpy(&xonly, key_data[0..32]);
                var val_reader = serialize_mod.Reader{ .data = value };
                const n_leaf_hashes = try val_reader.readCompactSize();
                const leaf_hashes = try allocator.alloc([32]u8, @intCast(n_leaf_hashes));
                errdefer allocator.free(leaf_hashes);
                for (0..@intCast(n_leaf_hashes)) |i| {
                    const lh_bytes = try val_reader.readBytes(32);
                    @memcpy(&leaf_hashes[i], lh_bytes[0..32]);
                }
                const remaining = value[val_reader.pos..];
                if (remaining.len < 4 or (remaining.len - 4) % 4 != 0) {
                    allocator.free(leaf_hashes);
                    return PsbtError.InvalidValueLength;
                }
                var fingerprint: [4]u8 = undefined;
                @memcpy(&fingerprint, remaining[0..4]);
                const path_len = (remaining.len - 4) / 4;
                const path = try allocator.alloc(u32, path_len);
                errdefer allocator.free(path);
                for (0..path_len) |i| {
                    path[i] = std.mem.readInt(u32, remaining[4 + i * 4 ..][0..4], .little);
                }
                try output.tap_bip32_derivation.put(xonly, TapKeyOriginInfo{
                    .leaf_hashes = leaf_hashes,
                    .fingerprint = fingerprint,
                    .path = path,
                });
            },
            PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS => {
                // key_data = aggregate_pubkey (33 bytes compressed)
                // value = participant_pubkeys (33 bytes each, concatenated)
                if (key_data.len != 33) return PsbtError.InvalidKeyLength;
                if (value.len == 0 or value.len % 33 != 0) return PsbtError.InvalidValueLength;
                var agg_pubkey: [33]u8 = undefined;
                @memcpy(&agg_pubkey, key_data[0..33]);
                const n_participants = value.len / 33;
                const participants = try allocator.alloc([33]u8, n_participants);
                errdefer allocator.free(participants);
                for (0..n_participants) |i| {
                    @memcpy(&participants[i], value[i * 33 ..][0..33]);
                }
                try output.musig2_participants.append(MuSig2ParticipantEntry{
                    .aggregate_pubkey = agg_pubkey,
                    .participant_pubkeys = participants,
                });
            },
            else => {
                // Store unknown entries
                const key_hash = std.hash.Wyhash.hash(0, key_bytes);
                try output.unknown.put(key_hash, .{
                    .key = try allocator.dupe(u8, key_bytes),
                    .value = try allocator.dupe(u8, value),
                });
            },
        }
    }
}

/// Clone a transaction
pub fn cloneTransaction(allocator: std.mem.Allocator, tx: *const types.Transaction) !types.Transaction {
    const inputs = try allocator.alloc(types.TxIn, tx.inputs.len);
    errdefer allocator.free(inputs);

    for (inputs, 0..) |*input, i| {
        input.* = types.TxIn{
            .previous_output = tx.inputs[i].previous_output,
            .script_sig = try allocator.dupe(u8, tx.inputs[i].script_sig),
            .sequence = tx.inputs[i].sequence,
            .witness = blk: {
                if (tx.inputs[i].witness.len == 0) break :blk &[_][]const u8{};
                const w = try allocator.alloc([]const u8, tx.inputs[i].witness.len);
                for (w, 0..) |*item, j| {
                    item.* = try allocator.dupe(u8, tx.inputs[i].witness[j]);
                }
                break :blk w;
            },
        };
    }

    const outputs = try allocator.alloc(types.TxOut, tx.outputs.len);
    errdefer allocator.free(outputs);

    for (outputs, 0..) |*output, i| {
        output.* = types.TxOut{
            .value = tx.outputs[i].value,
            .script_pubkey = try allocator.dupe(u8, tx.outputs[i].script_pubkey),
        };
    }

    return types.Transaction{
        .version = tx.version,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = tx.lock_time,
    };
}

/// Free a cloned transaction
pub fn freeTransaction(allocator: std.mem.Allocator, tx: *types.Transaction) void {
    for (tx.inputs) |input| {
        if (input.script_sig.len > 0) allocator.free(input.script_sig);
        if (input.witness.len > 0) {
            for (input.witness) |item| {
                if (item.len > 0) allocator.free(item);
            }
            allocator.free(input.witness);
        }
    }
    allocator.free(tx.inputs);

    for (tx.outputs) |output| {
        if (output.script_pubkey.len > 0) allocator.free(output.script_pubkey);
    }
    allocator.free(tx.outputs);
}

/// Clone a PsbtInput
fn clonePsbtInput(allocator: std.mem.Allocator, input: *const PsbtInput) !PsbtInput {
    var result = PsbtInput.init(allocator);
    errdefer result.deinit();

    if (input.non_witness_utxo) |tx| {
        result.non_witness_utxo = try cloneTransaction(allocator, &tx);
    }

    if (input.witness_utxo) |utxo| {
        result.witness_utxo = types.TxOut{
            .value = utxo.value,
            .script_pubkey = try allocator.dupe(u8, utxo.script_pubkey),
        };
    }

    var sig_iter = input.partial_sigs.iterator();
    while (sig_iter.next()) |entry| {
        try result.partial_sigs.put(entry.key_ptr.*, try allocator.dupe(u8, entry.value_ptr.*));
    }

    result.sighash_type = input.sighash_type;

    if (input.redeem_script) |s| result.redeem_script = try allocator.dupe(u8, s);
    if (input.witness_script) |s| result.witness_script = try allocator.dupe(u8, s);
    if (input.final_script_sig) |s| result.final_script_sig = try allocator.dupe(u8, s);
    if (input.tap_key_sig) |s| result.tap_key_sig = try allocator.dupe(u8, s);

    result.tap_internal_key = input.tap_internal_key;
    result.tap_merkle_root = input.tap_merkle_root;

    if (input.final_script_witness) |w| {
        const witness = try allocator.alloc([]const u8, w.len);
        for (witness, 0..) |*item, i| {
            item.* = try allocator.dupe(u8, w[i]);
        }
        result.final_script_witness = witness;
    }

    var bip32_iter = input.bip32_derivation.iterator();
    while (bip32_iter.next()) |entry| {
        try result.bip32_derivation.put(entry.key_ptr.*, try entry.value_ptr.clone(allocator));
    }

    // Clone BIP-371 extended input fields
    for (input.tap_script_sigs.items) |entry| {
        try result.tap_script_sigs.append(TapScriptSig{
            .pubkey = entry.pubkey,
            .leaf_hash = entry.leaf_hash,
            .sig = try allocator.dupe(u8, entry.sig),
        });
    }
    for (input.tap_leaf_scripts.items) |entry| {
        try result.tap_leaf_scripts.append(TapLeafScript{
            .control_block = try allocator.dupe(u8, entry.control_block),
            .script = try allocator.dupe(u8, entry.script),
            .leaf_ver = entry.leaf_ver,
        });
    }
    var tap_bip32_iter = input.tap_bip32_derivation.iterator();
    while (tap_bip32_iter.next()) |entry| {
        try result.tap_bip32_derivation.put(entry.key_ptr.*, try entry.value_ptr.clone(allocator));
    }

    return result;
}

/// Clone a PsbtOutput
fn clonePsbtOutput(allocator: std.mem.Allocator, output: *const PsbtOutput) !PsbtOutput {
    var result = PsbtOutput.init(allocator);
    errdefer result.deinit();

    if (output.redeem_script) |s| result.redeem_script = try allocator.dupe(u8, s);
    if (output.witness_script) |s| result.witness_script = try allocator.dupe(u8, s);
    if (output.tap_tree) |t| result.tap_tree = try allocator.dupe(u8, t);

    result.tap_internal_key = output.tap_internal_key;

    var bip32_iter = output.bip32_derivation.iterator();
    while (bip32_iter.next()) |entry| {
        try result.bip32_derivation.put(entry.key_ptr.*, try entry.value_ptr.clone(allocator));
    }

    // Clone BIP-371 extended output fields
    var tap_bip32_iter = output.tap_bip32_derivation.iterator();
    while (tap_bip32_iter.next()) |entry| {
        try result.tap_bip32_derivation.put(entry.key_ptr.*, try entry.value_ptr.clone(allocator));
    }
    for (output.musig2_participants.items) |entry| {
        try result.musig2_participants.append(MuSig2ParticipantEntry{
            .aggregate_pubkey = entry.aggregate_pubkey,
            .participant_pubkeys = try allocator.dupe([33]u8, entry.participant_pubkeys),
        });
    }

    return result;
}

// ============================================================================
// W47: Multisig parsing + script-push + producer-field cleanup helpers
// ============================================================================

/// Parsed `OP_M <pk1> ... <pkN> OP_N OP_CHECKMULTISIG` multisig template.
const MultisigTemplate = struct {
    m: usize,
    n: usize,
    /// Slices into the source script. Each is a 33-byte compressed pubkey.
    pubkeys: [20][]const u8,
};

/// Recognise a BIP-11 multisig script and return `m`, `n`, and the pubkey
/// slices in script-pubkey order. Only compressed (33-byte) pubkeys are
/// accepted — the finalizer keys partial sigs by [33]u8 so uncompressed
/// signers can't round-trip through this path anyway.
///
/// Returns null on any structural mismatch. Callers treat null as "unknown
/// shape, leave unfinalized" rather than an error (matches Core's silent
/// `complete:false` behavior for unsupported scripts).
fn parseMultisigScript(script: []const u8) ?MultisigTemplate {
    // Minimum: OP_1 <push33> <pk> OP_1 OP_CHECKMULTISIG  (1+34+1+1 = 37)
    if (script.len < 37) return null;
    if (script[script.len - 1] != 0xae) return null; // OP_CHECKMULTISIG
    const m_op = script[0];
    const n_op = script[script.len - 2];
    if (m_op < 0x51 or m_op > 0x60) return null; // OP_1..OP_16
    if (n_op < 0x51 or n_op > 0x60) return null;
    const m: usize = @as(usize, m_op) - 0x50;
    const n: usize = @as(usize, n_op) - 0x50;
    if (m == 0 or m > n or n > 20) return null;

    var t = MultisigTemplate{ .m = m, .n = n, .pubkeys = undefined };
    var i: usize = 1;
    var k: usize = 0;
    while (k < n) : (k += 1) {
        if (i >= script.len) return null;
        const push_op = script[i];
        // Only direct-push compressed (33-byte) pubkeys are accepted.
        if (push_op != 0x21) return null;
        if (i + 1 + 33 > script.len) return null;
        t.pubkeys[k] = script[i + 1 .. i + 1 + 33];
        i += 1 + 33;
    }
    // After the pubkeys we must be exactly at OP_N OP_CHECKMULTISIG.
    if (i != script.len - 2) return null;
    return t;
}

/// Walk the multisig pubkey slots in script-pubkey order, append any
/// partial signature whose pubkey matches the slot to `out`. Skips slots
/// without a sig. Caller decides whether `out.len >= m`.
fn collectMultisigSigsInScriptOrder(
    input: *const PsbtInput,
    ms: MultisigTemplate,
    out: *std.ArrayList([]const u8),
) !void {
    var k: usize = 0;
    while (k < ms.n) : (k += 1) {
        const pk_slice = ms.pubkeys[k];
        if (pk_slice.len != 33) continue;
        var pk_arr: [33]u8 = undefined;
        @memcpy(&pk_arr, pk_slice);
        if (input.partial_sigs.get(pk_arr)) |sig| {
            try out.append(sig);
        }
    }
}

/// Append a properly-encoded script push of `data` to `out`.
///   - 0..75 bytes:   single direct-push opcode (0x01..0x4b)
///   - 76..255:       OP_PUSHDATA1 + 1-byte length
///   - 256..65535:    OP_PUSHDATA2 + 2-byte LE length
/// (Larger pushes are theoretically OP_PUSHDATA4 but no PSBT producer
/// fields ever come close — script size cap is 10000 bytes.)
fn pushScriptData(out: *std.ArrayList(u8), data: []const u8) !void {
    if (data.len <= 75) {
        try out.append(@intCast(data.len));
    } else if (data.len <= 255) {
        try out.append(0x4c); // OP_PUSHDATA1
        try out.append(@intCast(data.len));
    } else if (data.len <= 65535) {
        try out.append(0x4d); // OP_PUSHDATA2
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, @intCast(data.len), .little);
        try out.appendSlice(&buf);
    } else {
        try out.append(0x4e); // OP_PUSHDATA4
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, @intCast(data.len), .little);
        try out.appendSlice(&buf);
    }
    try out.appendSlice(data);
}

/// W47: Deterministic emit order for partial sigs and bip32 derivations.
///
/// Storage uses `std.AutoHashMap` (intentional — it's the cheapest
/// in-memory keyed lookup), but Core stores both as `std::map<...>`
/// (`psbt.h:269` / `psbt.h:270`), and downstream tools (combine round-trip,
/// byte-for-byte fixture compare) rely on the resulting deterministic
/// emit order. The fix is purely on the EMIT path: we materialize the
/// entries into a slice, sort it, and iterate the sorted slice. Storage
/// stays unchanged (no perf regression on lookup).
///
/// Sort keys (matching the cross-impl fleet decision):
///   - partial_sigs: HASH160(pubkey) — Core `std::map<CKeyID, SigPair>`,
///     pinned by blockbrew W45 e000f9b, beamchain W46-2 e8f04a0,
///     ouroboros W46-4 3d44478.
///   - bip32_derivation: raw pubkey bytes — Core
///     `std::map<CPubKey, KeyOriginInfo>` (lex compare on serialized
///     pubkey).
const SortedPartialSig = struct { pubkey: [33]u8, sig: []const u8 };
const SortedBip32 = struct { pubkey: [33]u8, info: KeyOriginInfo };

fn sortedPartialSigs(
    allocator: std.mem.Allocator,
    map: *const std.AutoHashMap([33]u8, []const u8),
) ![]SortedPartialSig {
    const out = try allocator.alloc(SortedPartialSig, map.count());
    var i: usize = 0;
    var iter = map.iterator();
    while (iter.next()) |entry| {
        out[i] = .{ .pubkey = entry.key_ptr.*, .sig = entry.value_ptr.* };
        i += 1;
    }
    std.sort.pdq(SortedPartialSig, out, {}, struct {
        fn lt(_: void, a: SortedPartialSig, b: SortedPartialSig) bool {
            const ha = crypto.hash160(&a.pubkey);
            const hb = crypto.hash160(&b.pubkey);
            return std.mem.lessThan(u8, &ha, &hb);
        }
    }.lt);
    return out;
}

fn sortedBip32Derivation(
    allocator: std.mem.Allocator,
    map: *const std.AutoHashMap([33]u8, KeyOriginInfo),
) ![]SortedBip32 {
    const out = try allocator.alloc(SortedBip32, map.count());
    var i: usize = 0;
    var iter = map.iterator();
    while (iter.next()) |entry| {
        out[i] = .{ .pubkey = entry.key_ptr.*, .info = entry.value_ptr.* };
        i += 1;
    }
    std.sort.pdq(SortedBip32, out, {}, struct {
        fn lt(_: void, a: SortedBip32, b: SortedBip32) bool {
            return std.mem.lessThan(u8, &a.pubkey, &b.pubkey);
        }
    }.lt);
    return out;
}

/// W47: After a successful finalize the producer-side fields (partial sigs,
/// witness/redeem scripts, BIP32 derivations, sighash type) must be
/// cleared so they don't ride along into the finalized PSBT or get
/// re-emitted by the serializer. Matches Core's `psbt.cpp` Finalize() path
/// which sets `final_script_sig`/`final_script_witness` and clears the
/// rest. The serializer already gates these on `!isFinalized()`, but
/// holding stale memory wastes allocator capacity and confuses the
/// Combiner role on a re-merge.
fn clearProducerFields(input: *PsbtInput) !void {
    // Free partial sigs.
    var sig_iter = input.partial_sigs.iterator();
    while (sig_iter.next()) |entry| {
        input.allocator.free(entry.value_ptr.*);
    }
    input.partial_sigs.clearRetainingCapacity();

    // Free BIP32 derivations.
    var d_iter = input.bip32_derivation.iterator();
    while (d_iter.next()) |entry| {
        var info = entry.value_ptr.*;
        info.deinit(input.allocator);
    }
    input.bip32_derivation.clearRetainingCapacity();

    // Drop witness_script / redeem_script. The on-chain commitment lives
    // in final_script_sig / final_script_witness now.
    if (input.redeem_script) |s| {
        input.allocator.free(s);
        input.redeem_script = null;
    }
    if (input.witness_script) |s| {
        input.allocator.free(s);
        input.witness_script = null;
    }

    // Sighash type is producer metadata, not consensus-relevant after
    // finalize.
    input.sighash_type = null;
}

/// Check if script is P2PKH
fn isP2PKH(script: []const u8) bool {
    return script.len == 25 and
        script[0] == 0x76 and // OP_DUP
        script[1] == 0xa9 and // OP_HASH160
        script[2] == 0x14 and // Push 20 bytes
        script[23] == 0x88 and // OP_EQUALVERIFY
        script[24] == 0xac; // OP_CHECKSIG
}

/// Check if script is P2WPKH
fn isP2WPKH(script: []const u8) bool {
    return script.len == 22 and
        script[0] == 0x00 and // OP_0
        script[1] == 0x14; // Push 20 bytes
}

/// Check if script is P2SH
fn isP2SH(script: []const u8) bool {
    return script.len == 23 and
        script[0] == 0xa9 and // OP_HASH160
        script[1] == 0x14 and // Push 20 bytes
        script[22] == 0x87; // OP_EQUAL
}

/// Check if script is P2WSH
fn isP2WSH(script: []const u8) bool {
    return script.len == 34 and
        script[0] == 0x00 and // OP_0
        script[1] == 0x20; // Push 32 bytes
}

/// Check if script is P2TR
fn isP2TR(script: []const u8) bool {
    return script.len == 34 and
        script[0] == 0x51 and // OP_1
        script[1] == 0x20; // Push 32 bytes
}

// ============================================================================
// Tests
// ============================================================================

test "psbt magic bytes" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x70, 0x73, 0x62, 0x74, 0xff }, &PSBT_MAGIC);
}

test "psbt create empty" {
    const allocator = std.testing.allocator;

    // Create a simple unsigned transaction
    const inputs = [_]types.TxIn{.{
        .previous_output = .{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const script_pubkey = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0xAB} ** 20 ++ [_]u8{ 0x88, 0xac };
    const outputs = [_]types.TxOut{.{
        .value = 50000,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var psbt = try Psbt.create(allocator, tx);
    defer psbt.deinit();

    try std.testing.expectEqual(@as(usize, 1), psbt.inputs.len);
    try std.testing.expectEqual(@as(usize, 1), psbt.outputs.len);
    try std.testing.expectEqual(@as(u32, 0), psbt.version);
}

test "psbt serialization round-trip" {
    const allocator = std.testing.allocator;

    // Create a simple PSBT
    const inputs = [_]types.TxIn{.{
        .previous_output = .{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const script_pubkey = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const outputs = [_]types.TxOut{.{
        .value = 50000,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var psbt = try Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Add a witness UTXO
    try psbt.addInputUtxo(0, types.TxOut{
        .value = 100000,
        .script_pubkey = &script_pubkey,
    });

    // Serialize
    const serialized = try psbt.serialize(allocator);
    defer allocator.free(serialized);

    // Deserialize
    var psbt2 = try Psbt.deserialize(allocator, serialized);
    defer psbt2.deinit();

    // Verify
    try std.testing.expectEqual(psbt.inputs.len, psbt2.inputs.len);
    try std.testing.expectEqual(psbt.outputs.len, psbt2.outputs.len);
    try std.testing.expect(psbt2.inputs[0].witness_utxo != null);
    try std.testing.expectEqual(@as(i64, 100000), psbt2.inputs[0].witness_utxo.?.value);
}

test "psbt base64 encoding" {
    const allocator = std.testing.allocator;

    // Create a minimal PSBT
    const inputs = [_]types.TxIn{.{
        .previous_output = .{
            .hash = [_]u8{0x00} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const script_pubkey = [_]u8{0x51}; // OP_TRUE
    const outputs = [_]types.TxOut{.{
        .value = 0,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var psbt = try Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Encode to base64
    const base64 = try psbt.toBase64(allocator);
    defer allocator.free(base64);

    // Verify it starts with the expected pattern
    try std.testing.expect(std.mem.startsWith(u8, base64, "cHNidP8")); // "psbt\xff" in base64

    // Decode back
    var psbt2 = try Psbt.fromBase64(allocator, base64);
    defer psbt2.deinit();

    try std.testing.expectEqual(psbt.inputs.len, psbt2.inputs.len);
}

test "psbt analysis" {
    const allocator = std.testing.allocator;

    const inputs = [_]types.TxIn{.{
        .previous_output = .{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const script_pubkey = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const outputs = [_]types.TxOut{.{
        .value = 50000,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var psbt = try Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Add UTXO info
    try psbt.addInputUtxo(0, types.TxOut{
        .value = 100000,
        .script_pubkey = &script_pubkey,
    });

    const analysis = psbt.analyze();
    try std.testing.expectEqual(@as(usize, 0), analysis.inputs_signed);
    try std.testing.expectEqual(@as(usize, 0), analysis.inputs_finalized);
    try std.testing.expectEqual(@as(usize, 1), analysis.total_inputs);
    try std.testing.expectEqualSlices(u8, "updater", analysis.next_role);
    try std.testing.expectEqual(@as(i64, 50000), analysis.estimated_fee.?);
}

test "psbt script type detection" {
    // P2PKH
    const p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x00} ** 20 ++ [_]u8{ 0x88, 0xac };
    try std.testing.expect(isP2PKH(&p2pkh));
    try std.testing.expect(!isP2WPKH(&p2pkh));

    // P2WPKH
    const p2wpkh = [_]u8{ 0x00, 0x14 } ++ [_]u8{0x00} ** 20;
    try std.testing.expect(isP2WPKH(&p2wpkh));
    try std.testing.expect(!isP2PKH(&p2wpkh));

    // P2SH
    const p2sh = [_]u8{ 0xa9, 0x14 } ++ [_]u8{0x00} ** 20 ++ [_]u8{0x87};
    try std.testing.expect(isP2SH(&p2sh));

    // P2WSH
    const p2wsh = [_]u8{ 0x00, 0x20 } ++ [_]u8{0x00} ** 32;
    try std.testing.expect(isP2WSH(&p2wsh));

    // P2TR
    const p2tr = [_]u8{ 0x51, 0x20 } ++ [_]u8{0x00} ** 32;
    try std.testing.expect(isP2TR(&p2tr));
}

test "psbt combiner role" {
    const allocator = std.testing.allocator;

    // Create base PSBT
    const inputs = [_]types.TxIn{.{
        .previous_output = .{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const script_pubkey = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const outputs = [_]types.TxOut{.{
        .value = 50000,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    // Create two PSBTs with different data
    var psbt1 = try Psbt.create(allocator, tx);
    defer psbt1.deinit();

    var psbt2 = try Psbt.create(allocator, tx);
    defer psbt2.deinit();

    // Add different partial sigs to each
    const pubkey1 = [_]u8{0x02} ++ [_]u8{0x11} ** 32;
    const sig1 = [_]u8{0x30} ++ [_]u8{0x44} ** 70;
    try psbt1.addPartialSig(0, pubkey1, &sig1);

    const pubkey2 = [_]u8{0x02} ++ [_]u8{0x22} ** 32;
    const sig2 = [_]u8{0x30} ++ [_]u8{0x55} ** 70;
    try psbt2.addPartialSig(0, pubkey2, &sig2);

    // Combine
    const psbt_ptrs = [_]*Psbt{ &psbt1, &psbt2 };
    var combined = try Psbt.combine(allocator, &psbt_ptrs);
    defer combined.deinit();

    // Verify both sigs are present
    try std.testing.expectEqual(@as(usize, 2), combined.inputs[0].partial_sigs.count());
    try std.testing.expect(combined.inputs[0].partial_sigs.contains(pubkey1));
    try std.testing.expect(combined.inputs[0].partial_sigs.contains(pubkey2));
}

test "psbt bip32 derivation" {
    const allocator = std.testing.allocator;

    const inputs = [_]types.TxIn{.{
        .previous_output = .{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const script_pubkey = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xAB} ** 20;
    const outputs = [_]types.TxOut{.{
        .value = 50000,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var psbt = try Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Add BIP32 derivation
    const pubkey = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const fingerprint = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const path = [_]u32{ 84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0 };

    try psbt.addInputBip32Derivation(0, pubkey, fingerprint, &path);

    // Serialize and deserialize
    const serialized = try psbt.serialize(allocator);
    defer allocator.free(serialized);

    var psbt2 = try Psbt.deserialize(allocator, serialized);
    defer psbt2.deinit();

    // Verify derivation info
    const info = psbt2.inputs[0].bip32_derivation.get(pubkey).?;
    try std.testing.expectEqualSlices(u8, &fingerprint, &info.fingerprint);
    try std.testing.expectEqual(@as(usize, 5), info.path.len);
    try std.testing.expectEqual(@as(u32, 84 | 0x80000000), info.path[0]);
}

// W32-B regression pin: BIP-174 mandates the unsigned-tx body inside the
// PSBT global map be serialized in NON-segwit form (no `00 01` marker, no
// witness sections), regardless of whether any input carries witness data.
// Pre-W32-B, `serializeGlobalMap` placed the temporary `tx_writer` inside
// a labeled `blk:` whose `defer tx_writer.deinit()` fired BEFORE the slice
// was consumed by `writeKeyValue`, so the unsigned-tx body landed in freed
// memory. The PSBT then round-tripped to `EndOfStream` inside
// `readTransaction.script_sig`. This test exercises the empty-witness
// path explicitly and asserts the round-tripped tx is byte-equal to the
// original — which would have failed deterministically pre-fix.
test "psbt empty-witness round-trip is byte-identical (W32-B regression)" {
    const allocator = std.testing.allocator;

    // Two inputs, both empty-witness, distinct prevout hashes so we'd
    // notice a use-after-free that overwrote one with a stale view of
    // the other.
    const inputs = [_]types.TxIn{
        .{
            .previous_output = .{
                .hash = [_]u8{0xAA} ** 32,
                .index = 0,
            },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFE,
            .witness = &[_][]const u8{},
        },
        .{
            .previous_output = .{
                .hash = [_]u8{0xBB} ** 32,
                .index = 7,
            },
            .script_sig = &[_]u8{},
            .sequence = 0xFFFFFFFF,
            .witness = &[_][]const u8{},
        },
    };

    const script_pubkey = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xCD} ** 20;
    const outputs = [_]types.TxOut{.{
        .value = 12345,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 2,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    var psbt = try Psbt.create(allocator, tx);
    defer psbt.deinit();

    // Build the expected canonical (non-segwit) tx body the way BIP-174
    // requires — this is what should be embedded in the unsigned-tx
    // value, byte-for-byte.
    var expected_body_writer = serialize_mod.Writer.init(allocator);
    defer expected_body_writer.deinit();
    try serialize_mod.writeTransactionNoWitness(&expected_body_writer, &tx);
    const expected_body = expected_body_writer.getWritten();

    // No segwit marker should ever appear inside the unsigned-tx body.
    // Concretely: byte[4] (first byte after nVersion) must be the
    // input count, not 0x00.
    try std.testing.expect(expected_body.len > 4);
    try std.testing.expect(expected_body[4] != 0x00);

    // Serialize and decode back.
    const serialized = try psbt.serialize(allocator);
    defer allocator.free(serialized);

    var psbt2 = try Psbt.deserialize(allocator, serialized);
    defer psbt2.deinit();

    // Re-serialize the round-tripped tx with the same non-witness path
    // and assert byte-equality with the original.
    var actual_body_writer = serialize_mod.Writer.init(allocator);
    defer actual_body_writer.deinit();
    try serialize_mod.writeTransactionNoWitness(&actual_body_writer, &psbt2.tx);
    const actual_body = actual_body_writer.getWritten();

    try std.testing.expectEqualSlices(u8, expected_body, actual_body);

    // Also verify the structural fields survived intact. (Pre-fix the
    // unsigned tx itself wouldn't even decode, so we never got this far;
    // post-fix these double-check we didn't lose data.)
    try std.testing.expectEqual(tx.version, psbt2.tx.version);
    try std.testing.expectEqual(tx.inputs.len, psbt2.tx.inputs.len);
    try std.testing.expectEqual(tx.outputs.len, psbt2.tx.outputs.len);
    try std.testing.expectEqual(tx.lock_time, psbt2.tx.lock_time);
    for (tx.inputs, psbt2.tx.inputs) |orig, got| {
        try std.testing.expectEqualSlices(u8, &orig.previous_output.hash, &got.previous_output.hash);
        try std.testing.expectEqual(orig.previous_output.index, got.previous_output.index);
        try std.testing.expectEqual(orig.sequence, got.sequence);
        try std.testing.expectEqualSlices(u8, orig.script_sig, got.script_sig);
        // Witness must be empty after non-segwit round-trip.
        try std.testing.expectEqual(@as(usize, 0), got.witness.len);
    }
}
