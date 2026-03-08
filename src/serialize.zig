const std = @import("std");
const types = @import("types.zig");

/// Serialization errors
pub const Error = error{
    EndOfStream,
    InvalidCompactSize,
    InvalidSegwitMarker,
    OutOfMemory,
};

/// Reader for parsing Bitcoin binary data
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    /// Read n bytes from the stream
    pub fn readBytes(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.data.len) return Error.EndOfStream;
        const result = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return result;
    }

    /// Read a little-endian integer
    pub fn readInt(self: *Reader, comptime T: type) Error!T {
        const size = @sizeOf(T);
        const bytes = try self.readBytes(size);
        return std.mem.readInt(T, bytes[0..size], .little);
    }

    /// Read a CompactSize (variable-length integer)
    pub fn readCompactSize(self: *Reader) Error!u64 {
        const first = try self.readInt(u8);
        if (first < 0xFD) {
            return first;
        } else if (first == 0xFD) {
            return try self.readInt(u16);
        } else if (first == 0xFE) {
            return try self.readInt(u32);
        } else {
            return try self.readInt(u64);
        }
    }

    /// Read a 32-byte hash
    pub fn readHash(self: *Reader) Error!types.Hash256 {
        const bytes = try self.readBytes(32);
        return bytes[0..32].*;
    }

    /// Peek at the next byte without consuming it
    pub fn peek(self: *Reader) Error!u8 {
        if (self.pos >= self.data.len) return Error.EndOfStream;
        return self.data[self.pos];
    }

    /// Check if we've reached the end
    pub fn isAtEnd(self: *Reader) bool {
        return self.pos >= self.data.len;
    }

    /// Get remaining bytes
    pub fn remaining(self: *Reader) usize {
        return if (self.pos >= self.data.len) 0 else self.data.len - self.pos;
    }
};

/// Writer for serializing Bitcoin binary data
pub const Writer = struct {
    list: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) Writer {
        return .{ .list = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: *Writer) void {
        self.list.deinit();
    }

    /// Write raw bytes
    pub fn writeBytes(self: *Writer, data: []const u8) !void {
        try self.list.appendSlice(data);
    }

    /// Write a little-endian integer
    pub fn writeInt(self: *Writer, comptime T: type, value: T) !void {
        var buf: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buf, value, .little);
        try self.list.appendSlice(&buf);
    }

    /// Write a CompactSize (variable-length integer)
    pub fn writeCompactSize(self: *Writer, value: u64) !void {
        if (value < 0xFD) {
            try self.writeInt(u8, @intCast(value));
        } else if (value <= 0xFFFF) {
            try self.writeInt(u8, 0xFD);
            try self.writeInt(u16, @intCast(value));
        } else if (value <= 0xFFFFFFFF) {
            try self.writeInt(u8, 0xFE);
            try self.writeInt(u32, @intCast(value));
        } else {
            try self.writeInt(u8, 0xFF);
            try self.writeInt(u64, value);
        }
    }

    /// Get the written data as an owned slice
    pub fn toOwnedSlice(self: *Writer) ![]const u8 {
        return try self.list.toOwnedSlice();
    }

    /// Get the written data without transferring ownership
    pub fn getWritten(self: *Writer) []const u8 {
        return self.list.items;
    }
};

/// Read a transaction from the binary stream
pub fn readTransaction(reader: *Reader, allocator: std.mem.Allocator) !types.Transaction {
    const version = try reader.readInt(i32);

    // Check for segwit marker (0x00 followed by 0x01)
    var is_segwit = false;
    const marker = try reader.peek();
    if (marker == 0x00) {
        _ = try reader.readInt(u8); // consume marker
        const flag = try reader.readInt(u8);
        if (flag != 0x01) return Error.InvalidSegwitMarker;
        is_segwit = true;
    }

    // Read inputs
    const input_count = try reader.readCompactSize();
    const inputs = try allocator.alloc(types.TxIn, @intCast(input_count));
    errdefer allocator.free(inputs);

    for (inputs) |*input| {
        const prev_hash = try reader.readHash();
        const prev_index = try reader.readInt(u32);
        const script_len = try reader.readCompactSize();
        const script_sig = try allocator.dupe(u8, try reader.readBytes(@intCast(script_len)));
        const sequence = try reader.readInt(u32);

        input.* = .{
            .previous_output = .{ .hash = prev_hash, .index = prev_index },
            .script_sig = script_sig,
            .sequence = sequence,
            .witness = &[_][]const u8{},
        };
    }

    // Read outputs
    const output_count = try reader.readCompactSize();
    const outputs = try allocator.alloc(types.TxOut, @intCast(output_count));
    errdefer allocator.free(outputs);

    for (outputs) |*output| {
        const value = try reader.readInt(i64);
        const script_len = try reader.readCompactSize();
        const script_pubkey = try allocator.dupe(u8, try reader.readBytes(@intCast(script_len)));

        output.* = .{
            .value = value,
            .script_pubkey = script_pubkey,
        };
    }

    // Read witness data if segwit
    if (is_segwit) {
        for (inputs) |*input| {
            const witness_count = try reader.readCompactSize();
            var witness_items = try allocator.alloc([]const u8, @intCast(witness_count));
            for (0..@intCast(witness_count)) |i| {
                const item_len = try reader.readCompactSize();
                witness_items[i] = try allocator.dupe(u8, try reader.readBytes(@intCast(item_len)));
            }
            input.witness = witness_items;
        }
    }

    const lock_time = try reader.readInt(u32);

    return .{
        .version = version,
        .inputs = inputs,
        .outputs = outputs,
        .lock_time = lock_time,
    };
}

/// Read a block header from the binary stream (80 bytes)
pub fn readBlockHeader(reader: *Reader) Error!types.BlockHeader {
    const version = try reader.readInt(i32);
    const prev_block = try reader.readHash();
    const merkle_root = try reader.readHash();
    const timestamp = try reader.readInt(u32);
    const bits = try reader.readInt(u32);
    const nonce = try reader.readInt(u32);

    return .{
        .version = version,
        .prev_block = prev_block,
        .merkle_root = merkle_root,
        .timestamp = timestamp,
        .bits = bits,
        .nonce = nonce,
    };
}

/// Read a full block from the binary stream
pub fn readBlock(reader: *Reader, allocator: std.mem.Allocator) !types.Block {
    const header = try readBlockHeader(reader);
    const tx_count = try reader.readCompactSize();

    var transactions = try allocator.alloc(types.Transaction, @intCast(tx_count));
    errdefer allocator.free(transactions);

    for (0..@intCast(tx_count)) |i| {
        transactions[i] = try readTransaction(reader, allocator);
    }

    return .{
        .header = header,
        .transactions = transactions,
    };
}

/// Write a transaction to the binary stream (full serialization with witness)
pub fn writeTransaction(writer: *Writer, tx: *const types.Transaction) !void {
    try writer.writeInt(i32, tx.version);

    const has_witness = tx.hasWitness();
    if (has_witness) {
        try writer.writeInt(u8, 0x00); // marker
        try writer.writeInt(u8, 0x01); // flag
    }

    // Write inputs
    try writer.writeCompactSize(tx.inputs.len);
    for (tx.inputs) |input| {
        try writer.writeBytes(&input.previous_output.hash);
        try writer.writeInt(u32, input.previous_output.index);
        try writer.writeCompactSize(input.script_sig.len);
        try writer.writeBytes(input.script_sig);
        try writer.writeInt(u32, input.sequence);
    }

    // Write outputs
    try writer.writeCompactSize(tx.outputs.len);
    for (tx.outputs) |output| {
        try writer.writeInt(i64, output.value);
        try writer.writeCompactSize(output.script_pubkey.len);
        try writer.writeBytes(output.script_pubkey);
    }

    // Write witness data if present
    if (has_witness) {
        for (tx.inputs) |input| {
            try writer.writeCompactSize(input.witness.len);
            for (input.witness) |item| {
                try writer.writeCompactSize(item.len);
                try writer.writeBytes(item);
            }
        }
    }

    try writer.writeInt(u32, tx.lock_time);
}

/// Write a transaction without witness data (for txid computation)
pub fn writeTransactionNoWitness(writer: *Writer, tx: *const types.Transaction) !void {
    try writer.writeInt(i32, tx.version);

    // No segwit marker/flag for non-witness serialization

    // Write inputs
    try writer.writeCompactSize(tx.inputs.len);
    for (tx.inputs) |input| {
        try writer.writeBytes(&input.previous_output.hash);
        try writer.writeInt(u32, input.previous_output.index);
        try writer.writeCompactSize(input.script_sig.len);
        try writer.writeBytes(input.script_sig);
        try writer.writeInt(u32, input.sequence);
    }

    // Write outputs
    try writer.writeCompactSize(tx.outputs.len);
    for (tx.outputs) |output| {
        try writer.writeInt(i64, output.value);
        try writer.writeCompactSize(output.script_pubkey.len);
        try writer.writeBytes(output.script_pubkey);
    }

    // No witness data

    try writer.writeInt(u32, tx.lock_time);
}

/// Write a block header to the binary stream (80 bytes)
pub fn writeBlockHeader(writer: *Writer, header: *const types.BlockHeader) !void {
    try writer.writeInt(i32, header.version);
    try writer.writeBytes(&header.prev_block);
    try writer.writeBytes(&header.merkle_root);
    try writer.writeInt(u32, header.timestamp);
    try writer.writeInt(u32, header.bits);
    try writer.writeInt(u32, header.nonce);
}

/// Write a full block to the binary stream
pub fn writeBlock(writer: *Writer, block: *const types.Block) !void {
    try writeBlockHeader(writer, &block.header);
    try writer.writeCompactSize(block.transactions.len);
    for (block.transactions) |*tx| {
        try writeTransaction(writer, tx);
    }
}

// ============================================================================
// Tests
// ============================================================================

test "compactsize round-trip" {
    const allocator = std.testing.allocator;
    const test_values = [_]u64{
        0,
        1,
        0xFC,
        0xFD,
        0xFFFE,
        0xFFFF,
        0x10000,
        0xFFFFFFFF,
        0x100000000,
    };

    for (test_values) |value| {
        var writer = Writer.init(allocator);
        defer writer.deinit();

        try writer.writeCompactSize(value);
        const bytes = writer.getWritten();

        var reader = Reader{ .data = bytes };
        const read_value = try reader.readCompactSize();

        try std.testing.expectEqual(value, read_value);
        try std.testing.expect(reader.isAtEnd());
    }
}

test "compactsize encoding sizes" {
    const allocator = std.testing.allocator;

    // 0-0xFC: 1 byte
    {
        var writer = Writer.init(allocator);
        defer writer.deinit();
        try writer.writeCompactSize(0xFC);
        try std.testing.expectEqual(@as(usize, 1), writer.getWritten().len);
    }

    // 0xFD-0xFFFF: 3 bytes (0xFD + 2 bytes)
    {
        var writer = Writer.init(allocator);
        defer writer.deinit();
        try writer.writeCompactSize(0xFD);
        try std.testing.expectEqual(@as(usize, 3), writer.getWritten().len);
    }

    // 0x10000-0xFFFFFFFF: 5 bytes (0xFE + 4 bytes)
    {
        var writer = Writer.init(allocator);
        defer writer.deinit();
        try writer.writeCompactSize(0x10000);
        try std.testing.expectEqual(@as(usize, 5), writer.getWritten().len);
    }

    // > 0xFFFFFFFF: 9 bytes (0xFF + 8 bytes)
    {
        var writer = Writer.init(allocator);
        defer writer.deinit();
        try writer.writeCompactSize(0x100000000);
        try std.testing.expectEqual(@as(usize, 9), writer.getWritten().len);
    }
}

test "genesis block header parsing" {
    // Bitcoin genesis block header (80 bytes)
    const genesis_header_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    var header_bytes: [80]u8 = undefined;
    _ = std.fmt.hexToBytes(&header_bytes, genesis_header_hex) catch unreachable;

    var reader = Reader{ .data = &header_bytes };
    const header = try readBlockHeader(&reader);

    try std.testing.expectEqual(@as(i32, 1), header.version);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &header.prev_block);
    try std.testing.expectEqual(@as(u32, 1231006505), header.timestamp);
    try std.testing.expectEqual(@as(u32, 0x1d00ffff), header.bits);
    try std.testing.expectEqual(@as(u32, 2083236893), header.nonce);
    try std.testing.expect(reader.isAtEnd());
}

test "block header serialization round-trip" {
    const allocator = std.testing.allocator;

    const header = types.BlockHeader{
        .version = 1,
        .prev_block = [_]u8{0} ** 32,
        .merkle_root = [_]u8{0xAB} ** 32,
        .timestamp = 1231006505,
        .bits = 0x1d00ffff,
        .nonce = 2083236893,
    };

    var writer = Writer.init(allocator);
    defer writer.deinit();
    try writeBlockHeader(&writer, &header);

    const bytes = writer.getWritten();
    try std.testing.expectEqual(@as(usize, 80), bytes.len);

    var reader = Reader{ .data = bytes };
    const parsed = try readBlockHeader(&reader);

    try std.testing.expectEqual(header.version, parsed.version);
    try std.testing.expectEqualSlices(u8, &header.prev_block, &parsed.prev_block);
    try std.testing.expectEqualSlices(u8, &header.merkle_root, &parsed.merkle_root);
    try std.testing.expectEqual(header.timestamp, parsed.timestamp);
    try std.testing.expectEqual(header.bits, parsed.bits);
    try std.testing.expectEqual(header.nonce, parsed.nonce);
}

test "simple transaction round-trip" {
    const allocator = std.testing.allocator;

    // Create a simple non-segwit transaction
    const script_sig = [_]u8{ 0x01, 0x02, 0x03 };
    const script_pubkey = [_]u8{ 0x76, 0xa9, 0x14 };

    const inputs = [_]types.TxIn{.{
        .previous_output = .{
            .hash = [_]u8{0x11} ** 32,
            .index = 0,
        },
        .script_sig = &script_sig,
        .sequence = 0xFFFFFFFF,
        .witness = &[_][]const u8{},
    }};

    const outputs = [_]types.TxOut{.{
        .value = 5000000000,
        .script_pubkey = &script_pubkey,
    }};

    const tx = types.Transaction{
        .version = 1,
        .inputs = &inputs,
        .outputs = &outputs,
        .lock_time = 0,
    };

    // Serialize
    var writer = Writer.init(allocator);
    defer writer.deinit();
    try writeTransaction(&writer, &tx);

    const bytes = writer.getWritten();

    // Deserialize
    var reader = Reader{ .data = bytes };
    const parsed = try readTransaction(&reader, allocator);
    defer {
        for (parsed.inputs) |input| {
            allocator.free(input.script_sig);
            allocator.free(input.witness);
        }
        allocator.free(parsed.inputs);
        for (parsed.outputs) |output| {
            allocator.free(output.script_pubkey);
        }
        allocator.free(parsed.outputs);
    }

    try std.testing.expectEqual(tx.version, parsed.version);
    try std.testing.expectEqual(tx.lock_time, parsed.lock_time);
    try std.testing.expectEqual(tx.inputs.len, parsed.inputs.len);
    try std.testing.expectEqual(tx.outputs.len, parsed.outputs.len);
    try std.testing.expectEqualSlices(u8, tx.inputs[0].script_sig, parsed.inputs[0].script_sig);
    try std.testing.expectEqualSlices(u8, tx.outputs[0].script_pubkey, parsed.outputs[0].script_pubkey);
    try std.testing.expectEqual(tx.outputs[0].value, parsed.outputs[0].value);
}

test "reader basics" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var reader = Reader{ .data = &data };

    try std.testing.expectEqual(@as(usize, 5), reader.remaining());
    try std.testing.expect(!reader.isAtEnd());

    const first_two = try reader.readBytes(2);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02 }, first_two);
    try std.testing.expectEqual(@as(usize, 3), reader.remaining());

    const next = try reader.readInt(u16);
    try std.testing.expectEqual(@as(u16, 0x0403), next); // little-endian

    try std.testing.expectEqual(@as(u8, 0x05), try reader.peek());
    _ = try reader.readInt(u8);
    try std.testing.expect(reader.isAtEnd());
}

test "writer basics" {
    const allocator = std.testing.allocator;
    var writer = Writer.init(allocator);
    defer writer.deinit();

    try writer.writeInt(u16, 0x0102);
    try writer.writeBytes(&[_]u8{ 0xAA, 0xBB });

    const data = writer.getWritten();
    try std.testing.expectEqual(@as(usize, 4), data.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x01, 0xAA, 0xBB }, data);
}
