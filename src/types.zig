const std = @import("std");

/// SHA256 hash (32 bytes) - used for txids, block hashes
pub const Hash256 = [32]u8;

/// RIPEMD160(SHA256) hash (20 bytes) - used for addresses
pub const Hash160 = [20]u8;

/// Bitcoin transaction outpoint (reference to a previous output)
pub const OutPoint = struct {
    hash: Hash256,
    index: u32,

    /// Coinbase transactions reference this special outpoint
    pub const COINBASE = OutPoint{
        .hash = [_]u8{0} ** 32,
        .index = 0xFFFFFFFF,
    };
};

/// Transaction input
pub const TxIn = struct {
    previous_output: OutPoint,
    script_sig: []const u8,
    sequence: u32,
    witness: []const []const u8,
};

/// Transaction output
pub const TxOut = struct {
    value: i64,
    script_pubkey: []const u8,
};

/// Bitcoin transaction
pub const Transaction = struct {
    version: i32,
    inputs: []const TxIn,
    outputs: []const TxOut,
    lock_time: u32,

    /// Check if this is a coinbase transaction
    pub fn isCoinbase(self: *const Transaction) bool {
        return self.inputs.len == 1 and
            std.mem.eql(u8, &self.inputs[0].previous_output.hash, &OutPoint.COINBASE.hash) and
            self.inputs[0].previous_output.index == OutPoint.COINBASE.index;
    }

    /// Check if transaction has witness data
    pub fn hasWitness(self: *const Transaction) bool {
        for (self.inputs) |input| {
            if (input.witness.len > 0) return true;
        }
        return false;
    }
};

/// Bitcoin block header (80 bytes)
pub const BlockHeader = struct {
    version: i32,
    prev_block: Hash256,
    merkle_root: Hash256,
    timestamp: u32,
    bits: u32,
    nonce: u32,
};

/// Bitcoin block
pub const Block = struct {
    header: BlockHeader,
    transactions: []const Transaction,
};

/// Network address (used in P2P messages)
pub const NetworkAddress = struct {
    services: u64,
    ip: [16]u8, // IPv6-mapped IPv4
    port: u16,
};

/// Signature hash types
pub const SigHashType = enum(u8) {
    all = 0x01,
    none = 0x02,
    single = 0x03,
    anyonecanpay = 0x80,
    all_anyonecanpay = 0x81,
    none_anyonecanpay = 0x82,
    single_anyonecanpay = 0x83,
    // Taproot specific
    default = 0x00,

    pub fn baseType(self: SigHashType) u8 {
        return @intFromEnum(self) & 0x1f;
    }

    pub fn hasAnyoneCanPay(self: SigHashType) bool {
        return (@intFromEnum(self) & 0x80) != 0;
    }
};

/// Signature version for sighash computation
pub const SigVersion = enum {
    base,        // Legacy (pre-segwit)
    witness_v0,  // Segwit v0 (BIP143)
    taproot,     // Taproot (BIP341)
    tapscript,   // Tapscript (BIP342)
};

test "transaction basics" {
    const tx = Transaction{
        .version = 1,
        .inputs = &[_]TxIn{},
        .outputs = &[_]TxOut{},
        .lock_time = 0,
    };
    try std.testing.expect(!tx.hasWitness());
}

test "coinbase detection" {
    const coinbase_input = TxIn{
        .previous_output = OutPoint.COINBASE,
        .script_sig = &[_]u8{},
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    };
    const coinbase_tx = Transaction{
        .version = 1,
        .inputs = &[_]TxIn{coinbase_input},
        .outputs = &[_]TxOut{},
        .lock_time = 0,
    };
    try std.testing.expect(coinbase_tx.isCoinbase());

    const regular_tx = Transaction{
        .version = 1,
        .inputs = &[_]TxIn{},
        .outputs = &[_]TxOut{},
        .lock_time = 0,
    };
    try std.testing.expect(!regular_tx.isCoinbase());
}

test "sighash types" {
    try std.testing.expectEqual(@as(u8, 1), SigHashType.all.baseType());
    try std.testing.expect(!SigHashType.all.hasAnyoneCanPay());
    try std.testing.expect(SigHashType.all_anyonecanpay.hasAnyoneCanPay());
}
