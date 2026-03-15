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
    p2sh_p2wpkh, // P2SH-wrapped SegWit: OP_HASH160 <20-byte-script-hash> OP_EQUAL
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
// BIP32 HD Key Derivation
// ============================================================================

/// BIP32 derivation purposes
pub const DerivationPurpose = enum(u32) {
    bip44 = 44, // P2PKH (legacy)
    bip49 = 49, // P2SH-P2WPKH (wrapped segwit)
    bip84 = 84, // P2WPKH (native segwit)
    bip86 = 86, // P2TR (taproot)
};

/// BIP32 Extended Key - holds key material plus chain code for derivation
pub const ExtendedKey = struct {
    key: [32]u8, // Private or public key
    chain_code: [32]u8, // Chain code for derivation
    depth: u8,
    parent_fingerprint: [4]u8,
    child_index: u32,
    is_private: bool,

    /// HMAC-SHA512 helper for BIP32 derivation
    fn hmacSha512(key: []const u8, data: []const u8) [64]u8 {
        const HmacSha512 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha512);
        var result: [64]u8 = undefined;
        HmacSha512.create(&result, data, key);
        return result;
    }

    /// Create master key from seed (BIP32 master key generation)
    pub fn fromSeed(seed: []const u8) !ExtendedKey {
        if (seed.len < 16 or seed.len > 64) {
            return error.InvalidSeedLength;
        }

        const hmac_result = hmacSha512("Bitcoin seed", seed);
        const private_key = hmac_result[0..32].*;
        const chain_code = hmac_result[32..64].*;

        // Verify the key is valid (non-zero and less than curve order)
        if (std.mem.eql(u8, &private_key, &[_]u8{0} ** 32)) {
            return error.InvalidMasterKey;
        }

        return ExtendedKey{
            .key = private_key,
            .chain_code = chain_code,
            .depth = 0,
            .parent_fingerprint = [_]u8{ 0, 0, 0, 0 },
            .child_index = 0,
            .is_private = true,
        };
    }

    /// Derive child key at index (BIP32 CKDpriv/CKDpub)
    /// If index >= 0x80000000, it's a hardened derivation
    pub fn deriveChild(self: *const ExtendedKey, ctx: *secp256k1.secp256k1_context, index: u32) !ExtendedKey {
        const hardened = index >= 0x80000000;

        if (hardened and !self.is_private) {
            return error.CannotDeriveHardenedFromPublic;
        }

        var data: [37]u8 = undefined;

        if (hardened) {
            // Hardened: 0x00 || private_key || index
            data[0] = 0;
            @memcpy(data[1..33], &self.key);
        } else {
            // Normal: public_key || index
            if (self.is_private) {
                // Get public key from private
                var pubkey: secp256k1.secp256k1_pubkey = undefined;
                if (secp256k1.secp256k1_ec_pubkey_create(ctx, &pubkey, &self.key) != 1) {
                    return error.PubkeyCreationFailed;
                }
                var compressed: [33]u8 = undefined;
                var len: usize = 33;
                _ = secp256k1.secp256k1_ec_pubkey_serialize(
                    ctx,
                    &compressed,
                    &len,
                    &pubkey,
                    secp256k1.SECP256K1_EC_COMPRESSED,
                );
                @memcpy(data[0..33], &compressed);
            } else {
                return error.NotImplemented; // Public key derivation
            }
        }

        std.mem.writeInt(u32, data[33..37], index, .big);

        const hmac_result = hmacSha512(&self.chain_code, &data);
        const il = hmac_result[0..32];
        const ir = hmac_result[32..64].*;

        // Add il to parent key (mod curve order) using secp256k1
        var child_key = self.key;
        if (secp256k1.secp256k1_ec_seckey_tweak_add(ctx, &child_key, il) != 1) {
            return error.InvalidChildKey;
        }

        // Compute parent fingerprint (first 4 bytes of hash160 of parent pubkey)
        var parent_pubkey: secp256k1.secp256k1_pubkey = undefined;
        if (secp256k1.secp256k1_ec_pubkey_create(ctx, &parent_pubkey, &self.key) != 1) {
            return error.PubkeyCreationFailed;
        }
        var parent_compressed: [33]u8 = undefined;
        var parent_len: usize = 33;
        _ = secp256k1.secp256k1_ec_pubkey_serialize(
            ctx,
            &parent_compressed,
            &parent_len,
            &parent_pubkey,
            secp256k1.SECP256K1_EC_COMPRESSED,
        );
        const fingerprint_hash = crypto.hash160(&parent_compressed);
        const fingerprint = fingerprint_hash[0..4].*;

        return ExtendedKey{
            .key = child_key,
            .chain_code = ir,
            .depth = self.depth + 1,
            .parent_fingerprint = fingerprint,
            .child_index = index,
            .is_private = self.is_private,
        };
    }

    /// Derive a key from a BIP32 path string like "m/44'/0'/0'/0/0"
    pub fn derivePath(self: *const ExtendedKey, ctx: *secp256k1.secp256k1_context, path: []const u8) !ExtendedKey {
        var current = self.*;

        // Skip leading 'm/' or 'M/'
        var path_iter = path;
        if (path_iter.len >= 2 and (path_iter[0] == 'm' or path_iter[0] == 'M') and path_iter[1] == '/') {
            path_iter = path_iter[2..];
        }

        // Parse each component
        var components = std.mem.splitScalar(u8, path_iter, '/');
        while (components.next()) |component| {
            if (component.len == 0) continue;

            const hardened = std.mem.endsWith(u8, component, "'") or std.mem.endsWith(u8, component, "h");
            const num_str = if (hardened) component[0 .. component.len - 1] else component;

            const index = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidDerivationPath;
            const full_index = if (hardened) index | 0x80000000 else index;

            current = try current.deriveChild(ctx, full_index);
        }

        return current;
    }

    /// Get the standard BIP44/49/84/86 path for a given purpose, coin, account, change, and index
    pub fn getStandardPath(
        purpose: DerivationPurpose,
        coin_type: u32, // 0 for mainnet, 1 for testnet
        account: u32,
        change: u32, // 0 for external, 1 for internal (change)
        index: u32,
        buffer: []u8,
    ) ![]const u8 {
        return std.fmt.bufPrint(buffer, "m/{d}'/{d}'/{d}'/{d}/{d}", .{
            @intFromEnum(purpose),
            coin_type,
            account,
            change,
            index,
        }) catch return error.BufferTooSmall;
    }
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

    // HD wallet state
    master_key: ?ExtendedKey = null,
    next_external_index: u32 = 0, // m/purpose'/coin'/0'/0/index
    next_change_index: u32 = 0, // m/purpose'/coin'/0'/1/index

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
            .master_key = null,
            .next_external_index = 0,
            .next_change_index = 0,
        };
    }

    /// Initialize the wallet with a BIP32 seed (from BIP39 mnemonic)
    pub fn initFromSeed(allocator: std.mem.Allocator, network: Network, seed: []const u8) !Wallet {
        var wallet = try init(allocator, network);
        wallet.master_key = try ExtendedKey.fromSeed(seed);
        return wallet;
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

    /// Get a new address using HD derivation (BIP44/49/84/86 paths).
    /// This is the primary way to generate addresses for a HD wallet.
    /// Returns both the address string and the key index.
    pub fn getnewaddress(
        self: *Wallet,
        addr_type: AddressType,
        is_change: bool,
    ) !struct { address: []const u8, key_index: usize } {
        if (self.master_key == null) {
            // Non-HD wallet: fall back to random key generation
            const key_index = try self.generateKey();
            const addr = try self.getAddress(key_index, addr_type);
            return .{ .address = addr, .key_index = key_index };
        }

        // Determine purpose from address type (BIP44/49/84/86)
        const purpose: DerivationPurpose = switch (addr_type) {
            .p2pkh => .bip44,
            .p2sh_p2wpkh => .bip49,
            .p2wpkh => .bip84,
            .p2tr => .bip86,
            .p2wsh => .bip84, // P2WSH uses BIP84 path
        };

        // Coin type: 0 for mainnet, 1 for testnet
        const coin_type: u32 = switch (self.network) {
            .mainnet => 0,
            .testnet, .regtest => 1,
        };

        // Change: 0 for external (receiving), 1 for internal (change)
        const change: u32 = if (is_change) 1 else 0;

        // Get the next index for this chain
        const index = if (is_change) self.next_change_index else self.next_external_index;

        // Build derivation path
        var path_buf: [64]u8 = undefined;
        const path = try ExtendedKey.getStandardPath(purpose, coin_type, 0, change, index, &path_buf);

        // Derive the key
        const derived = try self.master_key.?.derivePath(self.ctx, path);

        // Import the derived key
        const key_index = try self.importKey(derived.key);

        // Get the address
        const addr = try self.getAddress(key_index, addr_type);

        // Increment the index counter
        if (is_change) {
            self.next_change_index += 1;
        } else {
            self.next_external_index += 1;
        }

        return .{ .address = addr, .key_index = key_index };
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
            .p2sh_p2wpkh => {
                // P2SH-P2WPKH: OP_HASH160 <hash160(redeemScript)> OP_EQUAL
                // where redeemScript = OP_0 <20-byte-pubkey-hash>
                const pubkey_hash = crypto.hash160(&key.public_key);
                var redeem_script: [22]u8 = undefined;
                redeem_script[0] = 0x00; // OP_0
                redeem_script[1] = 0x14; // Push 20 bytes
                @memcpy(redeem_script[2..22], &pubkey_hash);
                const script_hash = crypto.hash160(&redeem_script);

                try result.appendSlice(&[_]u8{
                    0xa9, // OP_HASH160
                    0x14, // Push 20 bytes
                });
                try result.appendSlice(&script_hash);
                try result.append(0x87); // OP_EQUAL
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
            .p2sh_p2wpkh => {
                // P2SH address: base58check with version 0x05 (mainnet) or 0xC4 (testnet)
                // containing hash160 of the redeem script (OP_0 <pubkey_hash>)
                const pubkey_hash = crypto.hash160(&key.public_key);
                var redeem_script: [22]u8 = undefined;
                redeem_script[0] = 0x00; // OP_0
                redeem_script[1] = 0x14; // Push 20 bytes
                @memcpy(redeem_script[2..22], &pubkey_hash);
                const script_hash = crypto.hash160(&redeem_script);

                const version: u8 = switch (self.network) {
                    .mainnet => 0x05,
                    .testnet, .regtest => 0xC4,
                };
                return try address.base58CheckEncode(version, &script_hash, self.allocator);
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

    /// Coin selection options
    pub const CoinSelectOptions = struct {
        fee_rate: u64 = 1, // sat/vB
        long_term_fee_rate: u64 = 10, // sat/vB for waste calculation
        cost_of_change: i64 = 34 * 10, // cost to create + spend change output
        min_change: i64 = 546, // minimum change to avoid dust
    };

    /// Select coins to fund a transaction (BnB with Knapsack fallback).
    /// This matches Bitcoin Core's coin selection strategy.
    pub fn selectCoins(
        self: *Wallet,
        target_value: i64,
        fee_rate: u64, // sat/vB
    ) !struct { selected: []OwnedUtxo, change: i64 } {
        return self.selectCoinsWithOptions(target_value, .{ .fee_rate = fee_rate });
    }

    /// Select coins with full options control
    pub fn selectCoinsWithOptions(
        self: *Wallet,
        target_value: i64,
        options: CoinSelectOptions,
    ) !struct { selected: []OwnedUtxo, change: i64 } {
        if (self.utxos.items.len == 0) {
            return error.InsufficientFunds;
        }

        // Create candidates with effective values
        const candidates = try self.allocator.dupe(OwnedUtxo, self.utxos.items);
        defer self.allocator.free(candidates);

        // Calculate effective values and sort by descending effective value
        var effective_values = try self.allocator.alloc(i64, candidates.len);
        defer self.allocator.free(effective_values);

        var total_available: i64 = 0;
        for (candidates, 0..) |utxo, i| {
            const input_fee = @as(i64, @intCast(estimateInputSize(utxo.address_type) * options.fee_rate));
            effective_values[i] = utxo.output.value - input_fee;
            if (effective_values[i] > 0) {
                total_available += effective_values[i];
            }
        }

        if (total_available < target_value) {
            return error.InsufficientFunds;
        }

        // Sort by effective value descending, with lower input size as tiebreaker
        const SortCtx = struct {
            eff_vals: []const i64,
        };
        const sort_ctx = SortCtx{ .eff_vals = effective_values };
        const indices = try self.allocator.alloc(usize, candidates.len);
        defer self.allocator.free(indices);
        for (indices, 0..) |*idx, i| idx.* = i;

        std.sort.pdq(usize, indices, sort_ctx, struct {
            fn cmp(ctx: SortCtx, a: usize, b: usize) bool {
                return ctx.eff_vals[a] > ctx.eff_vals[b];
            }
        }.cmp);

        // Try Branch and Bound first (aims for exact match, no change)
        if (try self.selectCoinsBnB(candidates, indices, effective_values, target_value, options)) |result| {
            return result;
        }

        // Fallback to Knapsack solver
        return try self.knapsackSolver(candidates, indices, effective_values, target_value, options);
    }

    /// Branch and Bound coin selection - exhaustive search for subset-sum within tolerance.
    /// Aims to find a selection that pays the target without needing change output.
    /// Max 100k iterations as per Bitcoin Core.
    fn selectCoinsBnB(
        self: *Wallet,
        candidates: []const OwnedUtxo,
        sorted_indices: []const usize,
        effective_values: []const i64,
        target_value: i64,
        options: CoinSelectOptions,
    ) !?struct { selected: []OwnedUtxo, change: i64 } {
        const max_iterations: usize = 100_000;
        const cost_of_change = options.cost_of_change;

        // Filter to positive effective value UTXOs only
        var positive_count: usize = 0;
        for (sorted_indices) |idx| {
            if (effective_values[idx] > 0) positive_count += 1;
        }
        if (positive_count == 0) return null;

        // Calculate available value (lookahead)
        var curr_available_value: i64 = 0;
        for (sorted_indices) |idx| {
            if (effective_values[idx] > 0) {
                curr_available_value += effective_values[idx];
            }
        }

        if (curr_available_value < target_value) return null;

        // Track selections and values
        var curr_selection = std.ArrayList(usize).init(self.allocator);
        defer curr_selection.deinit();

        var best_selection = std.ArrayList(usize).init(self.allocator);
        defer best_selection.deinit();

        var curr_value: i64 = 0;
        var curr_waste: i64 = 0;
        var best_waste: i64 = std.math.maxInt(i64);

        // Is current fee rate higher than long term? Affects waste calculation
        const is_feerate_high = options.fee_rate > options.long_term_fee_rate;

        var utxo_pool_index: usize = 0;
        var iterations: usize = 0;

        while (iterations < max_iterations) : (iterations += 1) {
            var backtrack = false;

            // Find next valid UTXO index (skip negative effective values)
            while (utxo_pool_index < sorted_indices.len and
                effective_values[sorted_indices[utxo_pool_index]] <= 0)
            {
                utxo_pool_index += 1;
            }

            // Check backtrack conditions
            if (utxo_pool_index >= sorted_indices.len) {
                backtrack = true;
            } else if (curr_value + curr_available_value < target_value) {
                // Cannot possibly reach target
                backtrack = true;
            } else if (curr_value > target_value + cost_of_change) {
                // Exceeded target + change cost, this branch won't help
                backtrack = true;
            } else if (curr_waste > best_waste and is_feerate_high) {
                // Waste is increasing when fee rate is high
                backtrack = true;
            } else if (curr_value >= target_value) {
                // Found a valid selection!
                const selection_waste = curr_waste + (curr_value - target_value);
                if (selection_waste <= best_waste) {
                    best_waste = selection_waste;
                    best_selection.clearRetainingCapacity();
                    try best_selection.appendSlice(curr_selection.items);
                }
                backtrack = true;
            }

            if (backtrack) {
                if (curr_selection.items.len == 0) break;

                // Restore available value for skipped UTXOs
                const last_selected = curr_selection.items[curr_selection.items.len - 1];
                var restore_idx = utxo_pool_index;
                while (restore_idx > 0) {
                    restore_idx -= 1;
                    if (restore_idx == last_selected) break;
                    const idx = sorted_indices[restore_idx];
                    if (effective_values[idx] > 0) {
                        curr_available_value += effective_values[idx];
                    }
                }

                // Deselect last UTXO
                const deselect_idx = sorted_indices[last_selected];
                curr_value -= effective_values[deselect_idx];
                const utxo_waste = calculateWaste(candidates[deselect_idx].address_type, options);
                curr_waste -= utxo_waste;
                _ = curr_selection.pop();

                utxo_pool_index = last_selected + 1;
            } else {
                // Include this UTXO
                const utxo_idx = sorted_indices[utxo_pool_index];
                curr_available_value -= effective_values[utxo_idx];
                curr_value += effective_values[utxo_idx];
                curr_waste += calculateWaste(candidates[utxo_idx].address_type, options);
                try curr_selection.append(utxo_pool_index);
                utxo_pool_index += 1;
            }
        }

        if (best_selection.items.len == 0) return null;

        // Build result
        var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
        errdefer selected.deinit();

        var total_value: i64 = 0;
        for (best_selection.items) |pool_idx| {
            const utxo_idx = sorted_indices[pool_idx];
            try selected.append(candidates[utxo_idx]);
            total_value += effective_values[utxo_idx];
        }

        return .{
            .selected = try selected.toOwnedSlice(),
            .change = total_value - target_value, // For BnB this should be minimal or zero
        };
    }

    /// Calculate waste for a single input (fee - long_term_fee)
    fn calculateWaste(addr_type: AddressType, options: CoinSelectOptions) i64 {
        const input_size = estimateInputSize(addr_type);
        const fee = @as(i64, @intCast(input_size * options.fee_rate));
        const long_term_fee = @as(i64, @intCast(input_size * options.long_term_fee_rate));
        return fee - long_term_fee;
    }

    /// Knapsack coin selection - random selection with stochastic approximation.
    /// Used as fallback when BnB fails. Always produces change output.
    fn knapsackSolver(
        self: *Wallet,
        candidates: []const OwnedUtxo,
        sorted_indices: []const usize,
        effective_values: []const i64,
        target_value: i64,
        options: CoinSelectOptions,
    ) !struct { selected: []OwnedUtxo, change: i64 } {
        const change_cost = options.cost_of_change;

        // Separate UTXOs into categories
        var applicable_groups = std.ArrayList(usize).init(self.allocator);
        defer applicable_groups.deinit();

        var lowest_larger: ?usize = null;
        var total_lower: i64 = 0;

        for (sorted_indices) |idx| {
            const eff_value = effective_values[idx];
            if (eff_value <= 0) continue;

            if (eff_value == target_value) {
                // Exact match!
                var selected = try self.allocator.alloc(OwnedUtxo, 1);
                selected[0] = candidates[idx];
                return .{ .selected = selected, .change = 0 };
            } else if (eff_value < target_value + change_cost) {
                // Smaller than target + change, could be part of sum
                try applicable_groups.append(idx);
                total_lower += eff_value;
            } else {
                // Larger than needed - track the smallest one
                if (lowest_larger == null or eff_value < effective_values[lowest_larger.?]) {
                    lowest_larger = idx;
                }
            }
        }

        // Check if all smaller UTXOs together equal target exactly
        if (total_lower == target_value) {
            var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
            errdefer selected.deinit();
            for (applicable_groups.items) |idx| {
                try selected.append(candidates[idx]);
            }
            return .{ .selected = try selected.toOwnedSlice(), .change = 0 };
        }

        // If smaller UTXOs are insufficient, use the smallest larger UTXO
        if (total_lower < target_value) {
            if (lowest_larger) |ll_idx| {
                var selected = try self.allocator.alloc(OwnedUtxo, 1);
                selected[0] = candidates[ll_idx];
                return .{
                    .selected = selected,
                    .change = effective_values[ll_idx] - target_value,
                };
            }
            return error.InsufficientFunds;
        }

        // Stochastic subset sum approximation (simplified Knapsack)
        // Run multiple iterations picking random subsets
        var best_selection = std.ArrayList(usize).init(self.allocator);
        defer best_selection.deinit();
        var best_value: i64 = std.math.maxInt(i64);

        const iterations: usize = 1000;
        var rng_state: u64 = @bitCast(std.time.milliTimestamp());

        for (0..iterations) |_| {
            var included = try self.allocator.alloc(bool, applicable_groups.items.len);
            defer self.allocator.free(included);
            @memset(included, false);

            var current_value: i64 = 0;
            var reached_target = false;

            // Two passes: first random, then fill gaps
            for (0..2) |pass| {
                for (applicable_groups.items, 0..) |idx, i| {
                    // Pass 0: randomly include
                    // Pass 1: include if not yet included and not reached target
                    const should_consider = if (pass == 0)
                        xorshift(&rng_state) % 2 == 0
                    else
                        !included[i];

                    if (should_consider and !reached_target) {
                        current_value += effective_values[idx];
                        included[i] = true;

                        if (current_value >= target_value) {
                            reached_target = true;
                            if (current_value < best_value) {
                                best_value = current_value;
                                best_selection.clearRetainingCapacity();
                                for (applicable_groups.items, 0..) |sel_idx, j| {
                                    if (included[j]) try best_selection.append(sel_idx);
                                }
                            }
                            // Try removing this element to see if we're still above target
                            current_value -= effective_values[idx];
                            included[i] = false;
                            reached_target = false;
                        }
                    }
                }
            }
        }

        // If we found a solution via stochastic search
        if (best_selection.items.len > 0) {
            // Check if the single larger UTXO would be better
            if (lowest_larger) |ll_idx| {
                const ll_value = effective_values[ll_idx];
                if (ll_value <= best_value) {
                    var selected = try self.allocator.alloc(OwnedUtxo, 1);
                    selected[0] = candidates[ll_idx];
                    return .{ .selected = selected, .change = ll_value - target_value };
                }
            }

            var selected = std.ArrayList(OwnedUtxo).init(self.allocator);
            errdefer selected.deinit();
            for (best_selection.items) |idx| {
                try selected.append(candidates[idx]);
            }
            return .{
                .selected = try selected.toOwnedSlice(),
                .change = best_value - target_value,
            };
        }

        // Last resort: use smallest larger UTXO
        if (lowest_larger) |ll_idx| {
            var selected = try self.allocator.alloc(OwnedUtxo, 1);
            selected[0] = candidates[ll_idx];
            return .{
                .selected = selected,
                .change = effective_values[ll_idx] - target_value,
            };
        }

        return error.InsufficientFunds;
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
            .p2sh_p2wpkh => {
                // P2SH-P2WPKH signing: BIP-143 sighash with scriptSig containing redeem script
                const sighash = try computeWitnessSigHashV0(tx, input_index, utxo, sighash_type, self.allocator);
                const sig = try self.ecdsaSign(&sighash, &key.secret_key);

                // Build scriptSig: push of redeem script (OP_0 <pubkey_hash>)
                const pubkey_hash = crypto.hash160(&key.public_key);
                var script_sig = try self.allocator.alloc(u8, 23);
                script_sig[0] = 0x16; // Push 22 bytes
                script_sig[1] = 0x00; // OP_0
                script_sig[2] = 0x14; // Push 20 bytes
                @memcpy(script_sig[3..23], &pubkey_hash);

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
                    .script_sig = script_sig,
                    .sequence = tx.inputs[input_index].sequence,
                    .witness = witness,
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
        .p2sh_p2wpkh => 91, // 32+4+1+23+4 + witness/4 (91 vbytes)
        .p2wpkh => 68, // 32+4+1+0+4 + witness/4
        .p2wsh => 100, // Approximate
        .p2tr => 58, // 32+4+1+0+4 + 64/4
    };
}

/// Simple xorshift64 PRNG for Knapsack randomization
fn xorshift(state: *u64) u64 {
    var x = state.*;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.* = x;
    return x;
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

// ============================================================================
// BIP32 HD Key Tests
// ============================================================================

test "BIP32 master key from seed" {
    // Test vector from BIP32 spec (test vector 1)
    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    const master = try ExtendedKey.fromSeed(&seed);

    // Verify master key properties
    try std.testing.expectEqual(@as(u8, 0), master.depth);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &master.parent_fingerprint);
    try std.testing.expectEqual(@as(u32, 0), master.child_index);
    try std.testing.expect(master.is_private);

    // Master key should be non-zero
    try std.testing.expect(!std.mem.eql(u8, &master.key, &[_]u8{0} ** 32));
    try std.testing.expect(!std.mem.eql(u8, &master.chain_code, &[_]u8{0} ** 32));
}

test "BIP32 child key derivation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    const master = try ExtendedKey.fromSeed(&seed);

    // Derive m/0 (normal child)
    const child0 = try master.deriveChild(ctx.?, 0);
    try std.testing.expectEqual(@as(u8, 1), child0.depth);
    try std.testing.expectEqual(@as(u32, 0), child0.child_index);
    try std.testing.expect(!std.mem.eql(u8, &child0.key, &master.key));

    // Derive m/0' (hardened child)
    const child0h = try master.deriveChild(ctx.?, 0x80000000);
    try std.testing.expectEqual(@as(u8, 1), child0h.depth);
    try std.testing.expectEqual(@as(u32, 0x80000000), child0h.child_index);
    try std.testing.expect(!std.mem.eql(u8, &child0h.key, &child0.key));
}

test "BIP32 path derivation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    defer secp256k1.secp256k1_context_destroy(ctx);

    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    const master = try ExtendedKey.fromSeed(&seed);

    // Derive m/44'/0'/0'/0/0 (BIP44 first external address)
    const derived = try master.derivePath(ctx.?, "m/44'/0'/0'/0/0");
    try std.testing.expectEqual(@as(u8, 5), derived.depth);
    try std.testing.expect(derived.is_private);
}

test "BIP32 standard path generation" {
    var buf: [64]u8 = undefined;

    const path44 = try ExtendedKey.getStandardPath(.bip44, 0, 0, 0, 0, &buf);
    try std.testing.expectEqualSlices(u8, "m/44'/0'/0'/0/0", path44);

    const path84 = try ExtendedKey.getStandardPath(.bip84, 0, 0, 1, 5, &buf);
    try std.testing.expectEqualSlices(u8, "m/84'/0'/0'/1/5", path84);

    const path86 = try ExtendedKey.getStandardPath(.bip86, 1, 0, 0, 10, &buf);
    try std.testing.expectEqualSlices(u8, "m/86'/1'/0'/0/10", path86);
}

// ============================================================================
// P2SH-P2WPKH Address Tests
// ============================================================================

test "P2SH-P2WPKH script generation" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const script = try wallet.getScriptPubKey(0, .p2sh_p2wpkh);
    defer allocator.free(script);

    // P2SH: OP_HASH160 <20> OP_EQUAL
    try std.testing.expectEqual(@as(usize, 23), script.len);
    try std.testing.expectEqual(@as(u8, 0xa9), script[0]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[1]); // Push 20
    try std.testing.expectEqual(@as(u8, 0x87), script[22]); // OP_EQUAL
}

test "P2SH-P2WPKH address derivation mainnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2sh_p2wpkh);
    defer allocator.free(addr_str);

    // Mainnet P2SH addresses start with '3'
    try std.testing.expect(addr_str[0] == '3');
}

test "P2SH-P2WPKH address derivation testnet" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .testnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    const addr_str = try wallet.getAddress(0, .p2sh_p2wpkh);
    defer allocator.free(addr_str);

    // Testnet P2SH addresses start with '2'
    try std.testing.expect(addr_str[0] == '2');
}

// ============================================================================
// Coin Selection Tests
// ============================================================================

test "coin selection BnB exact match" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add UTXOs that can form an exact match
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 50000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x02} ** 32, .index = 0 },
        .output = .{ .value = 30000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });
    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x03} ** 32, .index = 0 },
        .output = .{ .value = 20000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    // Try to select coins - BnB should find a good solution
    const result = try wallet.selectCoins(40000, 1);
    defer allocator.free(result.selected);

    // Should select at least one UTXO
    try std.testing.expect(result.selected.len > 0);
}

test "coin selection Knapsack fallback" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    // Add many small UTXOs that require Knapsack
    var i: u8 = 0;
    while (i < 20) : (i += 1) {
        try wallet.addUtxo(.{
            .outpoint = .{ .hash = [_]u8{i + 1} ** 32, .index = 0 },
            .output = .{ .value = 10000, .script_pubkey = &[_]u8{} },
            .key_index = 0,
            .address_type = .p2wpkh,
            .confirmations = 6,
        });
    }

    const result = try wallet.selectCoins(75000, 1);
    defer allocator.free(result.selected);

    // Should find a solution using multiple UTXOs
    try std.testing.expect(result.selected.len > 0);
}

test "coin selection with options" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    _ = try wallet.generateKey();

    try wallet.addUtxo(.{
        .outpoint = .{ .hash = [_]u8{0x01} ** 32, .index = 0 },
        .output = .{ .value = 100000, .script_pubkey = &[_]u8{} },
        .key_index = 0,
        .address_type = .p2wpkh,
        .confirmations = 6,
    });

    const result = try wallet.selectCoinsWithOptions(50000, .{
        .fee_rate = 5,
        .long_term_fee_rate = 10,
        .cost_of_change = 500,
        .min_change = 1000,
    });
    defer allocator.free(result.selected);

    try std.testing.expectEqual(@as(usize, 1), result.selected.len);
    try std.testing.expect(result.change > 0);
}

// ============================================================================
// HD Wallet / getnewaddress Tests
// ============================================================================

test "getnewaddress without HD seed" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    // Without HD seed, getnewaddress falls back to random key generation
    const result = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(result.address);

    try std.testing.expect(std.mem.startsWith(u8, result.address, "bc1q"));
    try std.testing.expectEqual(@as(usize, 0), result.key_index);
}

test "getnewaddress with HD seed" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    const seed = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    var wallet = try Wallet.initFromSeed(allocator, .mainnet, &seed);
    defer wallet.deinit();

    // Generate multiple addresses
    const addr1 = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(addr1.address);
    try std.testing.expect(std.mem.startsWith(u8, addr1.address, "bc1q"));
    try std.testing.expectEqual(@as(usize, 0), addr1.key_index);

    const addr2 = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(addr2.address);
    try std.testing.expect(std.mem.startsWith(u8, addr2.address, "bc1q"));
    try std.testing.expectEqual(@as(usize, 1), addr2.key_index);

    // Addresses should be different
    try std.testing.expect(!std.mem.eql(u8, addr1.address, addr2.address));

    // Check change address
    const change_addr = try wallet.getnewaddress(.p2wpkh, true);
    defer allocator.free(change_addr.address);
    try std.testing.expect(std.mem.startsWith(u8, change_addr.address, "bc1q"));
    try std.testing.expect(!std.mem.eql(u8, change_addr.address, addr1.address));
}

test "getnewaddress all address types with HD" {
    const ctx = secp256k1.secp256k1_context_create(
        secp256k1.SECP256K1_CONTEXT_SIGN | secp256k1.SECP256K1_CONTEXT_VERIFY,
    );
    if (ctx == null) return;
    secp256k1.secp256k1_context_destroy(ctx);

    const allocator = std.testing.allocator;
    const seed = [_]u8{
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    };

    var wallet = try Wallet.initFromSeed(allocator, .mainnet, &seed);
    defer wallet.deinit();

    // P2PKH (BIP44)
    const p2pkh_addr = try wallet.getnewaddress(.p2pkh, false);
    defer allocator.free(p2pkh_addr.address);
    try std.testing.expect(p2pkh_addr.address[0] == '1');

    // P2SH-P2WPKH (BIP49)
    const p2sh_addr = try wallet.getnewaddress(.p2sh_p2wpkh, false);
    defer allocator.free(p2sh_addr.address);
    try std.testing.expect(p2sh_addr.address[0] == '3');

    // P2WPKH (BIP84)
    const p2wpkh_addr = try wallet.getnewaddress(.p2wpkh, false);
    defer allocator.free(p2wpkh_addr.address);
    try std.testing.expect(std.mem.startsWith(u8, p2wpkh_addr.address, "bc1q"));

    // P2TR (BIP86)
    const p2tr_addr = try wallet.getnewaddress(.p2tr, false);
    defer allocator.free(p2tr_addr.address);
    try std.testing.expect(std.mem.startsWith(u8, p2tr_addr.address, "bc1p"));
}

test "estimateInputSize includes P2SH-P2WPKH" {
    try std.testing.expectEqual(@as(u64, 91), estimateInputSize(.p2sh_p2wpkh));
}
