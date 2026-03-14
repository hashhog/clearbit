const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const serialize = @import("serialize.zig");
const address = @import("address.zig");

// ============================================================================
// libsecp256k1 Bindings
// ============================================================================

const secp256k1 = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_schnorrsig.h");
});

// ============================================================================
// BIP-39 Mnemonic Support
// ============================================================================

/// BIP-39 English wordlist (2048 words), embedded at compile time
const BIP39_WORDLIST: []const u8 = @embedFile("../resources/bip39-english.txt");

/// Parse the embedded BIP-39 wordlist into an array of words
fn getBip39Words() [2048][]const u8 {
    var words: [2048][]const u8 = undefined;
    var lines = std.mem.splitScalar(u8, BIP39_WORDLIST, '\n');
    var i: usize = 0;
    while (lines.next()) |line| {
        if (line.len > 0 and i < 2048) {
            words[i] = line;
            i += 1;
        }
    }
    return words;
}

const BIP39_WORDS = getBip39Words();

// ============================================================================
// Address Types
// ============================================================================

pub const AddressType = enum {
    p2pkh, // Legacy: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    p2wpkh, // Native SegWit v0: OP_0 <20-byte-hash>
    p2wsh, // SegWit v0 script hash: OP_0 <32-byte-hash>
    p2tr, // Taproot: OP_1 <32-byte-x-only-pubkey>
};

pub const Network = enum {
    mainnet,
    testnet,
    regtest,
};

// ============================================================================
// KeyPair
// ============================================================================

pub const KeyPair = struct {
    secret_key: [32]u8,
    public_key: [33]u8, // Compressed SEC format
    x_only_pubkey: [32]u8, // For Taproot
};

// ============================================================================
// Owned UTXO
// ============================================================================

pub const OwnedUtxo = struct {
    outpoint: types.OutPoint,
    output: types.TxOut,
    key_index: usize, // Index into keys array
    address_type: AddressType,
    confirmations: u32,
};

// ============================================================================
// Wallet
// ============================================================================

pub const Wallet = struct {
    ctx: *secp256k1.secp256k1_context,
    keys: std.ArrayList(KeyPair),
    utxos: std.ArrayList(OwnedUtxo),
    allocator: std.mem.Allocator,
    network: Network,

    pub fn init(allocator: std.mem.Allocator, network: Network) !Wallet {
        const ctx = secp256k1.secp256k1_context_create(
            secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
        ) orelse return error.Secp256k1ContextFailed;

        return Wallet{
            .ctx = ctx,
            .keys = std.ArrayList(KeyPair).init(allocator),
            .utxos = std.ArrayList(OwnedUtxo).init(allocator),
            .allocator = allocator,
            .network = network,
        };
    }

    pub fn deinit(self: *Wallet) void {
        secp256k1.secp256k1_context_destroy(self.ctx);
        self.keys.deinit();
        self.utxos.deinit();
    }

    /// Generate a new random keypair.
    pub fn generateKey(self: *Wallet) !usize {
        var secret: [32]u8 = undefined;
        std.crypto.random.bytes(&secret);

        // Verify the secret key is valid (non-zero, less than curve order)
        while (secp256k1.secp256k1_ec_seckey_verify(self.ctx, &secret) != 1) {
            std.crypto.random.bytes(&secret);
        }

        return try self.importKey(secret);
    }

    /// Import an existing secret key.
    pub fn importKey(self: *Wallet, secret: [32]u8) !usize {
        // Verify the secret key
        if (secp256k1.secp256k1_ec_seckey_verify(self.ctx, &secret) != 1) {
            return error.InvalidSecretKey;
        }

        var pubkey: secp256k1.secp256k1_pubkey = undefined;
        if (secp256k1.secp256k1_ec_pubkey_create(self.ctx, &pubkey, &secret) != 1) {
            return error.PubkeyCreationFailed;
        }

        // Serialize compressed public key
        var compressed: [33]u8 = undefined;
        var compressed_len: usize = 33;
        _ = secp256k1.secp256k1_ec_pubkey_serialize(
            self.ctx,
            &compressed,
            &compressed_len,
            &pubkey,
            secp256k1.SECP256K1_EC_COMPRESSED,
        );

        // Create x-only pubkey for Taproot
        var xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
        _ = secp256k1.secp256k1_xonly_pubkey_from_pubkey(self.ctx, &xonly, null, &pubkey);
        var x_only_bytes: [32]u8 = undefined;
        _ = secp256k1.secp256k1_xonly_pubkey_serialize(self.ctx, &x_only_bytes, &xonly);

        const key = KeyPair{
            .secret_key = secret,
            .public_key = compressed,
            .x_only_pubkey = x_only_bytes,
        };

        try self.keys.append(key);
        return self.keys.items.len - 1;
    }

    /// Get the number of keys in the wallet.
    pub fn keyCount(self: *const Wallet) usize {
        return self.keys.items.len;
    }

    /// Derive the scriptPubKey for a given key and address type.
    pub fn getScriptPubKey(self: *Wallet, key_index: usize, addr_type: AddressType) ![]u8 {
        if (key_index >= self.keys.items.len) {
            return error.KeyNotFound;
        }

        const key = self.keys.items[key_index];
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        switch (addr_type) {
            .p2pkh => {
                const hash = crypto.hash160(&key.public_key);
                try result.appendSlice(&[_]u8{
                    0x76, // OP_DUP
                    0xa9, // OP_HASH160
                    0x14, // Push 20 bytes
                });
                try result.appendSlice(&hash);
                try result.appendSlice(&[_]u8{
                    0x88, // OP_EQUALVERIFY
                    0xac, // OP_CHECKSIG
                });
            },
            .p2wpkh => {
                const hash = crypto.hash160(&key.public_key);
                try result.appendSlice(&[_]u8{
                    0x00, // OP_0 (witness version 0)
                    0x14, // Push 20 bytes
                });
                try result.appendSlice(&hash);
            },
            .p2wsh => {
                // P2WSH requires a witness script - this is a simplified version
                // that uses the public key directly (not typical usage)
                const script_hash = crypto.sha256(&key.public_key);
                try result.appendSlice(&[_]u8{
                    0x00, // OP_0 (witness version 0)
                    0x20, // Push 32 bytes
                });
                try result.appendSlice(&script_hash);
            },
            .p2tr => {
                try result.appendSlice(&[_]u8{
                    0x51, // OP_1 (witness version 1)
                    0x20, // Push 32 bytes
                });
                try result.appendSlice(&key.x_only_pubkey);
            },
        }

        return try result.toOwnedSlice();
    }

    /// Derive a Bech32/Bech32m/Base58Check encoded address string.
    pub fn getAddress(self: *Wallet, key_index: usize, addr_type: AddressType) ![]const u8 {
        if (key_index >= self.keys.items.len) {
            return error.KeyNotFound;
        }

        const key = self.keys.items[key_index];
        const hrp: []const u8 = switch (self.network) {
            .mainnet => "bc",
            .testnet => "tb",
            .regtest => "bcrt",
        };

        switch (addr_type) {
            .p2pkh => {
                // Base58Check encoding: version_byte + hash160 + checksum
                const hash = crypto.hash160(&key.public_key);
                const version: u8 = switch (self.network) {
                    .mainnet => 0x00,
                    .testnet, .regtest => 0x6F,
                };
                return try address.base58CheckEncode(version, &hash, self.allocator);
            },
            .p2wpkh => {
                const hash = crypto.hash160(&key.public_key);
                return try address.segwitEncode(hrp, 0, &hash, self.allocator);
            },
            .p2wsh => {
                // Needs witness script as parameter in real impl
                return error.NotImplemented;
            },
            .p2tr => {
                return try address.segwitEncode(hrp, 1, &key.x_only_pubkey, self.allocator);
            },
        }
    }

    /// Add a UTXO to the wallet.
    pub fn addUtxo(self: *Wallet, utxo: OwnedUtxo) !void {
        try self.utxos.append(utxo);
    }

    /// Remove a UTXO from the wallet by outpoint.
    pub fn removeUtxo(self: *Wallet, outpoint: types.OutPoint) bool {
        for (self.utxos.items, 0..) |utxo, i| {
            if (std.mem.eql(u8, &utxo.outpoint.hash, &outpoint.hash) and
                utxo.outpoint.index == outpoint.index)
            {
                _ = self.utxos.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Get total balance of all UTXOs.
    pub fn getBalance(self: *const Wallet) i64 {
        var total: i64 = 0;
        for (self.utxos.items) |utxo| {
            total += utxo.output.value;
        }
        return total;
    }

    /// Select coins to fund a transaction (Branch and Bound with fallback to greedy).
    pub fn selectCoins(
        self: *Wallet,
        target_value: i64,
        fee_rate: u64, // sat/vB
    ) !struct { selected: []OwnedUtxo, change: i64 } {
        if (self.utxos.items.len == 0) {
            return error.InsufficientFunds;
        }

        // Sort UTXOs by value descending for greedy selection
        const candidates = try self.allocator.dupe(OwnedUtxo, self.utxos.items);
        defer self.allocator.free(candidates);

        std.mem.sort(OwnedUtxo, candidates, {}, struct {
            fn cmp(_: void, a: OwnedUtxo, b: OwnedUtxo) bool {
                return a.output.value > b.output.value;
            }
        }.cmp);

        // Estimate input/output sizes for fee calculation
        const estimated_overhead: u64 = 10 + 1 + 1; // version + vin count + vout count + locktime
        const output_size: u64 = 34; // value(8) + scriptPubKey(~26)
        const change_output_size: u64 = 34;

        // Try Branch and Bound first for exact match
        if (try self.branchAndBound(candidates, target_value, fee_rate)) |result| {
            return result;
        }

        // Fallback: greedy selection
        var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
        errdefer selected.deinit();
        var total: i64 = 0;

        for (candidates) |utxo| {
            const input_size: u64 = estimateInputSize(utxo.address_type);
            const input_fee = input_size * fee_rate;
            const effective_value = @as(i64, @intCast(utxo.output.value)) - @as(i64, @intCast(input_fee));

            if (effective_value <= 0) continue; // Skip dust inputs

            try selected.append(utxo);
            total += effective_value;

            const total_fee = @as(i64, @intCast(
                (estimated_overhead + output_size + change_output_size +
                    input_size * selected.items.len) * fee_rate,
            ));

            if (total >= target_value + total_fee) {
                return .{
                    .selected = try selected.toOwnedSlice(),
                    .change = total - target_value - total_fee,
                };
            }
        }

        return error.InsufficientFunds;
    }

    /// Branch and Bound coin selection - tries to find exact match (no change)
    fn branchAndBound(
        self: *Wallet,
        candidates: []OwnedUtxo,
        target_value: i64,
        fee_rate: u64,
    ) !?struct { selected: []OwnedUtxo, change: i64 } {
        const max_iterations: usize = 100000;
        var iterations: usize = 0;

        // Calculate effective values
        var effective_values = try self.allocator.alloc(i64, candidates.len);
        defer self.allocator.free(effective_values);

        for (candidates, 0..) |utxo, i| {
            const input_size = estimateInputSize(utxo.address_type);
            const input_fee = @as(i64, @intCast(input_size * fee_rate));
            effective_values[i] = utxo.output.value - input_fee;
        }

        // Track best solution
        var best_selection: ?[]bool = null;
        var best_waste: i64 = std.math.maxInt(i64);

        // Current selection state
        var current = try self.allocator.alloc(bool, candidates.len);
        defer self.allocator.free(current);
        @memset(current, false);

        // BnB exploration (simplified DFS)
        var depth: usize = 0;
        var current_value: i64 = 0;

        while (iterations < max_iterations) {
            iterations += 1;

            if (depth >= candidates.len) {
                // Check if we found a valid selection
                if (current_value >= target_value) {
                    const waste = current_value - target_value;
                    if (waste < best_waste) {
                        best_waste = waste;
                        if (best_selection) |bs| {
                            self.allocator.free(bs);
                        }
                        best_selection = try self.allocator.dupe(bool, current);
                    }
                }

                // Backtrack
                while (depth > 0) {
                    depth -= 1;
                    if (current[depth]) {
                        current[depth] = false;
                        current_value -= effective_values[depth];
                        break;
                    }
                }
                if (depth == 0 and !current[0]) break;
                continue;
            }

            // Try including this UTXO
            if (!current[depth] and effective_values[depth] > 0) {
                current[depth] = true;
                current_value += effective_values[depth];
                depth += 1;
            } else {
                // Already tried or negative effective value, skip
                depth += 1;
            }
        }

        if (best_selection) |selection| {
            defer self.allocator.free(selection);

            var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
            errdefer selected.deinit();

            for (selection, 0..) |included, i| {
                if (included) {
                    try selected.append(candidates[i]);
                }
            }

            return .{
                .selected = try selected.toOwnedSlice(),
                .change = best_waste,
            };
        }

        return null;
    }

    /// Sign a transaction input using the appropriate signing algorithm.
    pub fn signInput(
        self: *Wallet,
        tx: *types.Transaction,
        input_index: usize,
        utxo: OwnedUtxo,
        sighash_type: u32,
    ) !void {
        if (utxo.key_index >= self.keys.items.len) {
            return error.KeyNotFound;
        }

        const key = self.keys.items[utxo.key_index];

        switch (utxo.address_type) {
            .p2pkh => {
                // Legacy signing: SIGHASH over simplified transaction
                const sighash = try computeLegacySigHash(tx, input_index, utxo, sighash_type, self.allocator);
                const sig = try self.ecdsaSign(&sighash, &key.secret_key);

                // Build scriptSig: <sig+hashtype> <pubkey>
                var script_sig = std.ArrayList(u8).init(self.allocator);
                errdefer script_sig.deinit();

                // Push signature + hashtype
                const sig_len = getDerSigLen(&sig);
                try script_sig.append(@intCast(sig_len + 1));
                try script_sig.appendSlice(sig[0..sig_len]);
                try script_sig.append(@intCast(sighash_type & 0xFF));

                // Push compressed pubkey
                try script_sig.append(33);
                try script_sig.appendSlice(&key.public_key);

                // Update the transaction input
                const script_sig_slice = try script_sig.toOwnedSlice();
                tx.inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = script_sig_slice,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = tx.inputs[input_index].witness,
                };
            },
            .p2wpkh => {
                // BIP-143 SegWit v0 signing
                const sighash = try computeWitnessSigHashV0(tx, input_index, utxo, sighash_type, self.allocator);
                const sig = try self.ecdsaSign(&sighash, &key.secret_key);

                // Build witness: [sig+hashtype, pubkey]
                var witness = try self.allocator.alloc([]const u8, 2);
                errdefer self.allocator.free(witness);

                const sig_len = getDerSigLen(&sig);
                var sig_with_hashtype = try self.allocator.alloc(u8, sig_len + 1);
                @memcpy(sig_with_hashtype[0..sig_len], sig[0..sig_len]);
                sig_with_hashtype[sig_len] = @intCast(sighash_type & 0xFF);
                witness[0] = sig_with_hashtype;

                const pubkey_copy = try self.allocator.alloc(u8, 33);
                @memcpy(pubkey_copy, &key.public_key);
                witness[1] = pubkey_copy;

                tx.inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = tx.inputs[input_index].script_sig,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = witness,
                };
            },
            .p2tr => {
                // BIP-341 Taproot key-path signing (Schnorr)
                const sighash = try computeTaprootSigHash(tx, input_index, utxo, sighash_type, self.allocator);
                var sig: [64]u8 = undefined;
                var keypair: secp256k1.secp256k1_keypair = undefined;

                if (secp256k1.secp256k1_keypair_create(self.ctx, &keypair, &key.secret_key) != 1) {
                    return error.KeypairCreationFailed;
                }

                if (secp256k1.secp256k1_schnorrsig_sign32(
                    self.ctx,
                    &sig,
                    &sighash,
                    &keypair,
                    null,
                ) != 1) {
                    return error.SchnorrSignFailed;
                }

                // Witness: [signature] (65 bytes if non-default sighash, 64 if default)
                var witness = try self.allocator.alloc([]const u8, 1);
                errdefer self.allocator.free(witness);

                if (sighash_type == 0x00) {
                    // Default sighash (SIGHASH_DEFAULT) - 64 byte signature
                    witness[0] = try self.allocator.dupe(u8, &sig);
                } else {
                    // Non-default - append sighash byte
                    var sig_ext = try self.allocator.alloc(u8, 65);
                    @memcpy(sig_ext[0..64], &sig);
                    sig_ext[64] = @intCast(sighash_type & 0xFF);
                    witness[0] = sig_ext;
                }

                tx.inputs[input_index] = types.TxIn{
                    .previous_output = tx.inputs[input_index].previous_output,
                    .script_sig = tx.inputs[input_index].script_sig,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = witness,
                };
            },
            .p2wsh => {
                return error.NotImplemented; // Requires witness script
            },
        }
    }

    /// ECDSA sign a 32-byte message hash, returns DER-encoded signature.
    fn ecdsaSign(self: *Wallet, msg_hash: *const [32]u8, secret_key: *const [32]u8) ![72]u8 {
        var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
        if (secp256k1.secp256k1_ecdsa_sign(
            self.ctx,
            &sig,
            msg_hash,
            secret_key,
            null,
            null,
        ) != 1) {
            return error.EcdsaSignFailed;
        }

        // Serialize as DER
        var der: [72]u8 = undefined;
        var der_len: usize = 72;
        _ = secp256k1.secp256k1_ecdsa_signature_serialize_der(
            self.ctx,
            &der,
            &der_len,
            &sig,
        );
        return der;
    }

    /// Verify an ECDSA signature.
    pub fn verifyEcdsa(
        self: *Wallet,
        sig_der: []const u8,
        msg_hash: *const [32]u8,
        pubkey_bytes: []const u8,
    ) !bool {
        var pubkey: secp256k1.secp256k1_pubkey = undefined;
        if (secp256k1.secp256k1_ec_pubkey_parse(
            self.ctx,
            &pubkey,
            pubkey_bytes.ptr,
            pubkey_bytes.len,
        ) != 1) {
            return error.InvalidPublicKey;
        }

        var sig: secp256k1.secp256k1_ecdsa_signature = undefined;
        if (secp256k1.secp256k1_ecdsa_signature_parse_der(
            self.ctx,
            &sig,
            sig_der.ptr,
            sig_der.len,
        ) != 1) {
            return error.InvalidSignature;
        }

        // Normalize to low-S (BIP-62)
        _ = secp256k1.secp256k1_ecdsa_signature_normalize(self.ctx, &sig, &sig);

        return secp256k1.secp256k1_ecdsa_verify(self.ctx, &sig, msg_hash, &pubkey) == 1;
    }

    /// Verify a Schnorr signature (BIP-340).
    pub fn verifySchnorr(
        self: *Wallet,
        sig: *const [64]u8,
        msg_hash: *const [32]u8,
        pubkey_x: *const [32]u8,
    ) !bool {
        var xonly: secp256k1.secp256k1_xonly_pubkey = undefined;
        if (secp256k1.secp256k1_xonly_pubkey_parse(self.ctx, &xonly, pubkey_x) != 1) {
            return error.InvalidPublicKey;
        }

        return secp256k1.secp256k1_schnorrsig_verify(
            self.ctx,
            sig,
            msg_hash,
            32,
            &xonly,
        ) == 1;
    }
};

// ============================================================================
// Transaction Creation
// ============================================================================

/// Options for creating a transaction.
pub const CreateTxOptions = struct {
    /// Fee rate in satoshis per virtual byte.
    fee_rate: u64 = 1,
    /// Current block height (for anti-fee-sniping locktime).
    current_height: u32 = 0,
    /// Whether to enable anti-fee-sniping (set locktime to current_height).
    anti_fee_sniping: bool = true,
    /// Sighash type for signing (default: SIGHASH_ALL).
    sighash_type: u32 = 0x01,
};

/// Output for a new transaction.
pub const TxOutput = struct {
    value: i64,
    script_pubkey: []const u8,
};

/// Create and sign a transaction spending selected UTXOs to the specified outputs.
///
/// Anti-fee-sniping: Sets nLockTime to current_height to discourage miners from
/// reordering blocks to steal fees. This makes the transaction invalid until
/// the specified block height, preventing fee sniping attacks.
///
/// Reference: Bitcoin Core wallet/spend.cpp CreateTransactionInternal()
pub fn createTransaction(
    wallet: *Wallet,
    utxos_to_spend: []const OwnedUtxo,
    outputs: []const TxOutput,
    change_output: ?TxOutput,
    options: CreateTxOptions,
) !types.Transaction {
    const allocator = wallet.allocator;

    // Count total inputs and outputs
    const num_inputs = utxos_to_spend.len;
    const num_outputs = outputs.len + if (change_output != null) @as(usize, 1) else @as(usize, 0);

    // Build inputs
    var inputs = try allocator.alloc(types.TxIn, num_inputs);
    errdefer allocator.free(inputs);

    for (utxos_to_spend, 0..) |utxo, i| {
        inputs[i] = types.TxIn{
            .previous_output = utxo.outpoint,
            .script_sig = &[_]u8{}, // Will be filled during signing
            .sequence = 0xFFFFFFFE, // Enable locktime (not SEQUENCE_FINAL)
            .witness = &[_][]const u8{}, // Will be filled during signing
        };
    }

    // Build outputs
    var tx_outputs = try allocator.alloc(types.TxOut, num_outputs);
    errdefer allocator.free(tx_outputs);

    for (outputs, 0..) |out, i| {
        tx_outputs[i] = types.TxOut{
            .value = out.value,
            .script_pubkey = out.script_pubkey,
        };
    }

    // Add change output if provided
    if (change_output) |change| {
        tx_outputs[outputs.len] = types.TxOut{
            .value = change.value,
            .script_pubkey = change.script_pubkey,
        };
    }

    // Anti-fee-sniping: Set locktime to current block height
    // This makes the transaction invalid until that block, preventing miners
    // from reorganizing blocks to steal high-fee transactions
    //
    // Reference: BIP-0199, Bitcoin Core wallet/spend.cpp
    const lock_time: u32 = if (options.anti_fee_sniping and options.current_height > 0)
        options.current_height
    else
        0;

    // Create the transaction
    var tx = types.Transaction{
        .version = 2,
        .inputs = inputs,
        .outputs = tx_outputs,
        .lock_time = lock_time,
    };

    // Sign each input
    for (utxos_to_spend, 0..) |utxo, i| {
        try wallet.signInput(&tx, i, utxo, options.sighash_type);
    }

    return tx;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Estimate input size in virtual bytes for fee calculation.
fn estimateInputSize(addr_type: AddressType) u64 {
    return switch (addr_type) {
        .p2pkh => 148, // 32+4+1+~107+4
        .p2wpkh => 68, // 32+4+1+0+4 + witness/4
        .p2wsh => 100, // Approximate
        .p2tr => 58, // 32+4+1+0+4 + 64/4
    };
}

/// Get actual length of DER signature (may be less than 72).
fn getDerSigLen(der: *const [72]u8) usize {
    // DER format: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
    if (der[0] != 0x30) return 72;
    return @as(usize, der[1]) + 2;
}

// ============================================================================
// Sighash Computation
// ============================================================================

/// Dust threshold constants
pub const DUST_THRESHOLD_P2PKH: i64 = 546;
pub const DUST_THRESHOLD_P2WPKH: i64 = 294;

/// Compute legacy sighash for P2PKH inputs.
pub fn computeLegacySigHash(
    tx: *const types.Transaction,
    input_index: usize,
    utxo: OwnedUtxo,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) ![32]u8 {
    // Get the scriptPubKey from the UTXO being spent
    const script_pubkey = utxo.output.script_pubkey;

    // Use the crypto module's existing implementation
    return try crypto.legacySighash(tx, input_index, script_pubkey, sighash_type, allocator);
}

/// Compute BIP-143 SegWit v0 sighash for P2WPKH inputs.
pub fn computeWitnessSigHashV0(
    tx: *const types.Transaction,
    input_index: usize,
    utxo: OwnedUtxo,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) ![32]u8 {
    // For P2WPKH, the scriptCode is the equivalent P2PKH script
    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76; // OP_DUP
    script_code[1] = 0xa9; // OP_HASH160
    script_code[2] = 0x14; // Push 20 bytes

    // Extract the pubkey hash from the scriptPubKey (bytes 2-22)
    if (utxo.output.script_pubkey.len >= 22) {
        @memcpy(script_code[3..23], utxo.output.script_pubkey[2..22]);
    } else {
        return error.InvalidScriptPubKey;
    }

    script_code[23] = 0x88; // OP_EQUALVERIFY
    script_code[24] = 0xac; // OP_CHECKSIG

    return try crypto.segwitSighash(tx, input_index, &script_code, utxo.output.value, sighash_type, allocator);
}

/// Compute BIP-341 Taproot sighash.
pub fn computeTaprootSigHash(
    tx: *const types.Transaction,
    input_index: usize,
    utxo: OwnedUtxo,
    sighash_type: u32,
    allocator: std.mem.Allocator,
) ![32]u8 {
    _ = utxo;

    var writer = serialize.Writer.init(allocator);
    defer writer.deinit();

    // Epoch (0x00 for key path spend)
    try writer.writeInt(u8, 0x00);

    // Sighash type
    const hash_type: u8 = if (sighash_type == 0) 0x00 else @intCast(sighash_type & 0xFF);
    try writer.writeInt(u8, hash_type);

    // Transaction data
    try writer.writeInt(i32, tx.version);
    try writer.writeInt(u32, tx.lock_time);

    const base_type = sighash_type & 0x1f;
    const anyone_can_pay = (sighash_type & 0x80) != 0;

    // hashPrevouts
    if (!anyone_can_pay) {
        var prevouts_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (tx.inputs) |input| {
            prevouts_hasher.update(&input.previous_output.hash);
            var idx_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &idx_buf, input.previous_output.index, .little);
            prevouts_hasher.update(&idx_buf);
        }
        var hash_prevouts: [32]u8 = undefined;
        prevouts_hasher.final(&hash_prevouts);
        try writer.writeBytes(&hash_prevouts);
    }

    // hashAmounts (all input amounts)
    if (!anyone_can_pay) {
        // Note: In a real implementation, we'd need all spent outputs' values
        // For now, we'll use placeholder (this is incomplete for full verification)
        var amounts_hash: [32]u8 = [_]u8{0} ** 32;
        try writer.writeBytes(&amounts_hash);
    }

    // hashScriptPubKeys
    if (!anyone_can_pay) {
        // Placeholder - would need all scriptPubKeys
        var scripts_hash: [32]u8 = [_]u8{0} ** 32;
        try writer.writeBytes(&scripts_hash);
    }

    // hashSequences
    if (!anyone_can_pay and base_type != 0x02 and base_type != 0x03) {
        var seq_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (tx.inputs) |input| {
            var seq_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &seq_buf, input.sequence, .little);
            seq_hasher.update(&seq_buf);
        }
        var hash_sequences: [32]u8 = undefined;
        seq_hasher.final(&hash_sequences);
        try writer.writeBytes(&hash_sequences);
    }

    // hashOutputs
    if (base_type != 0x02 and base_type != 0x03) {
        var out_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (tx.outputs) |output| {
            var val_buf: [8]u8 = undefined;
            std.mem.writeInt(i64, &val_buf, output.value, .little);
            out_hasher.update(&val_buf);

            // CompactSize
            if (output.script_pubkey.len < 0xFD) {
                out_hasher.update(&[_]u8{@intCast(output.script_pubkey.len)});
            }
            out_hasher.update(output.script_pubkey);
        }
        var hash_outputs: [32]u8 = undefined;
        out_hasher.final(&hash_outputs);
        try writer.writeBytes(&hash_outputs);
    } else if (base_type == 0x03 and input_index < tx.outputs.len) {
        var out_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        const output = tx.outputs[input_index];
        var val_buf: [8]u8 = undefined;
        std.mem.writeInt(i64, &val_buf, output.value, .little);
        out_hasher.update(&val_buf);
        if (output.script_pubkey.len < 0xFD) {
            out_hasher.update(&[_]u8{@intCast(output.script_pubkey.len)});
        }
        out_hasher.update(output.script_pubkey);
        var hash_outputs: [32]u8 = undefined;
        out_hasher.final(&hash_outputs);
        try writer.writeBytes(&hash_outputs);
    }

    // spend_type (key path = 0)
    try writer.writeInt(u8, 0x00);

    // Input index
    try writer.writeInt(u32, @intCast(input_index));

    const data = try writer.toOwnedSlice();
    defer allocator.free(data);

    // BIP-341 uses tagged hash with "TapSighash"
    return crypto.taggedHash("TapSighash", data);
}

// ============================================================================
// Tests
// ============================================================================

test "wallet init and deinit" {
    // Skip if libsecp256k1 is not available
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) {
        return; // Skip test if secp256k1 not available
    }
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    try std.testing.expectEqual(@as(usize, 0), wallet.keyCount());
}

test "key generation produces valid keypairs" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    const key_index = try wallet.generateKey();
    try std.testing.expectEqual(@as(usize, 0), key_index);
    try std.testing.expectEqual(@as(usize, 1), wallet.keyCount());

    // Verify the public key is valid compressed format
    const key = wallet.keys.items[0];
    try std.testing.expect(key.public_key[0] == 0x02 or key.public_key[0] == 0x03);
}

test "P2PKH script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2pkh);
    defer allocator.free(script);

    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    try std.testing.expectEqual(@as(usize, 25), script.len);
    try std.testing.expectEqual(@as(u8, 0x76), script[0]); // OP_DUP
    try std.testing.expectEqual(@as(u8, 0xa9), script[1]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[2]); // Push 20
    try std.testing.expectEqual(@as(u8, 0x88), script[23]); // OP_EQUALVERIFY
    try std.testing.expectEqual(@as(u8, 0xac), script[24]); // OP_CHECKSIG
}

test "P2WPKH script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2wpkh);
    defer allocator.free(script);

    // P2WPKH: OP_0 <20>
    try std.testing.expectEqual(@as(usize, 22), script.len);
    try std.testing.expectEqual(@as(u8, 0x00), script[0]); // OP_0
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20
}

test "P2TR script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2tr);
    defer allocator.free(script);

    // P2TR: OP_1 <32>
    try std.testing.expectEqual(@as(usize, 34), script.len);
    try std.testing.expectEqual(@as(u8, 0x51), script[0]); // OP_1
    try std.testing.expectEqual(@as(u8, 0x20), script[1]); // Push 32
}

test "P2PKH address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2pkh);
    defer allocator.free(addr_str);

    // Mainnet P2PKH addresses start with '1'
    try std.testing.expect(addr_str[0] == '1');
}

test "P2WPKH address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2wpkh);
    defer allocator.free(addr_str);

    // Mainnet P2WPKH addresses start with 'bc1q'
    try std.testing.expect(std.mem.startsWith(u8, addr_str, "bc1q"));
}

test "P2TR address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2tr);
    defer allocator.free(addr_str);

    // Mainnet P2TR addresses start with 'bc1p'
    try std.testing.expect(std.mem.startsWith(u8, addr_str, "bc1p"));
}

test "testnet address derivation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .testnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // P2PKH testnet starts with 'm' or 'n'
    const p2pkh = try wallet.getAddress(0, .p2pkh);
    defer allocator.free(p2pkh);
    try std.testing.expect(p2pkh[0] == 'm' or p2pkh[0] == 'n');

    // P2WPKH testnet starts with 'tb1q'
    const p2wpkh = try wallet.getAddress(0, .p2wpkh);
    defer allocator.free(p2wpkh);
    try std.testing.expect(std.mem.startsWith(u8, p2wpkh, "tb1q"));

    // P2TR testnet starts with 'tb1p'
    const p2tr = try wallet.getAddress(0, .p2tr);
    defer allocator.free(p2tr);
    try std.testing.expect(std.mem.startsWith(u8, p2tr, "tb1p"));
}

test "coin selection with single UTXO" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add a UTXO
    try wallet.addUtxo(.{
        .outpoint = .{
            .hash = [_]u8{0x01} ** 32,
            .index = 0,
        },
        .output = .{
            .value = 100000, // 0.001 BTC
            .script_pubkey = &[_]u8{},
        },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    // Try to select coins for 50000 sats at 1 sat/vB
    const result = try wallet.selectCoins(50000, 1);
    defer allocator.free(result.selected);

    try std.testing.expectEqual(@as(usize, 1), result.selected.len);
    try std.testing.expect(result.change >= 0);
}

test "coin selection insufficient funds" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add a small UTXO
    try wallet.addUtxo(.{
        .outpoint = .{
            .hash = [_]u8{0x01} ** 32,
            .index = 0,
        },
        .output = .{
            .value = 1000, // Very small
            .script_pubkey = &[_]u8{},
        },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    // Try to select coins for a large amount
    const result = wallet.selectCoins(1000000, 10);
    try std.testing.expectError(error.InsufficientFunds, result);
}

test "ECDSA sign and verify" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    const key_idx = try wallet.generateKey();
    const key = wallet.keys.items[key_idx];

    // Create a test message hash
    const msg: [32]u8 = [_]u8{0xAB} ** 32;

    // Sign it
    const sig = try wallet.ecdsaSign(&msg, &key.secret_key);

    // Verify it
    const sig_len = getDerSigLen(&sig);
    const valid = try wallet.verifyEcdsa(sig[0..sig_len], &msg, &key.public_key);
    try std.testing.expect(valid);
}

test "BIP39 wordlist is valid" {
    // Verify we have 2048 words
    var count: usize = 0;
    for (BIP39_WORDS) |word| {
        if (word.len > 0) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2048), count);

    // Check first and last words
    try std.testing.expectEqualSlices(u8, "abandon", BIP39_WORDS[0]);
    try std.testing.expectEqualSlices(u8, "zoo", BIP39_WORDS[2047]);
}

test "estimateInputSize" {
    try std.testing.expectEqual(@as(u64, 148), estimateInputSize(.p2pkh));
    try std.testing.expectEqual(@as(u64, 68), estimateInputSize(.p2wpkh));
    try std.testing.expectEqual(@as(u64, 58), estimateInputSize(.p2tr));
}

test "wallet balance tracking" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    try std.testing.expectEqual(@as(i64, 0), wallet.getBalance());

    // Add UTXOs
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 50000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    try std.testing.expectEqual(@as(i64, 50000), wallet.getBalance());

    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x02} ** 32, .index = 0 },
        .output = .{ .value = 30000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 3,
    });

    try std.testing.expectEqual(@as(i64, 80000), wallet.getBalance());

    // Remove a UTXO
    const removed = wallet.removeUtxo(.{ .hash = [_]u8{0x01} ** 32, .index = 0 });
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(i64, 30000), wallet.getBalance());
}

test "anti-fee-sniping sets locktime to current height" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Create a mock P2WPKH scriptPubKey
    const script_pubkey = [_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20;

    // Add a UTXO to spend
    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 100000, .script_pubkey = &script_pubkey },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    // Create transaction with anti-fee-sniping enabled
    const tx = try createTransaction(
        &wallet,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{
            .value = 50000,
            .script_pubkey = &script_pubkey,
        }},
        null,
        .{
            .current_height = 800000,
            .anti_fee_sniping = true,
        },
    );
    defer {
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // Verify locktime is set to current_height
    try std.testing.expectEqual(@as(u32, 800000), tx.lock_time);

    // Verify inputs have non-final sequence to enable locktime
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFE), tx.inputs[0].sequence);
}

test "anti-fee-sniping disabled sets locktime to 0" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script_pubkey = [_]u8{0x00, 0x14} ++ [_]u8{0xAA} ** 20;

    const utxo = OwnedUtxo{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 100000, .script_pubkey = &script_pubkey },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    };

    // Create transaction with anti-fee-sniping disabled
    const tx = try createTransaction(
        &wallet,
        &[_]OwnedUtxo{utxo},
        &[_]TxOutput{.{
            .value = 50000,
            .script_pubkey = &script_pubkey,
        }},
        null,
        .{
            .current_height = 800000,
            .anti_fee_sniping = false,
        },
    );
    defer {
        allocator.free(tx.inputs);
        allocator.free(tx.outputs);
    }

    // Verify locktime is 0 when anti-fee-sniping is disabled
    try std.testing.expectEqual(@as(u32, 0), tx.lock_time);
}
