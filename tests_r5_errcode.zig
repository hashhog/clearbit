//! R5 ERROR-CODE PARITY class — one control per probe that failed on the
//! 2026-09-26 live + regtest R5 runs (tools/r5_probe.py; artifacts
//! 20260926T151432Z-full-0926.json and 20260926T173204Z-regtest-clearbit.json).
//!
//! Every expected code AND message below was read from a live Bitcoin Core
//! v31.99 (bitcoin-core/build-wallet/bin/bitcoind, scratch mainnet datadir,
//! no peers) for the same params, not from Core's source alone.
//!
//! CONTROL: `zig build test-r5-errcode --summary all`
//! Filter `r5_errcode` so imported rpc/peer/wallet tests do not run.

const std = @import("std");
const testing = std.testing;
const rpc = @import("src/rpc.zig");
const storage = @import("src/storage.zig");
const mempool_mod = @import("src/mempool.zig");
const peer_mod = @import("src/peer.zig");
const consensus = @import("src/consensus.zig");

fn dispatch(allocator: std.mem.Allocator, method: []const u8, params: []const u8) ![]const u8 {
    var chain_state = storage.ChainState.init(null, 64, allocator);
    defer chain_state.deinit();
    var mempool = mempool_mod.Mempool.init(null, null, allocator);
    defer mempool.deinit();
    var peer_manager = peer_mod.PeerManager.init(allocator, &consensus.MAINNET);
    defer peer_manager.deinit();
    var server = rpc.RpcServer.init(allocator, &chain_state, &mempool, &peer_manager, &consensus.MAINNET, .{});
    defer server.deinit();
    const req = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"{s}\",\"params\":{s}}}", .{ method, params });
    defer allocator.free(req);
    return server.dispatch(req);
}

/// The response's error object, parsed (null for a success response).
const Err = struct { code: i64, message: []const u8 };

fn expectError(method: []const u8, params: []const u8, want_code: i32, want_msg: []const u8) !void {
    const a = testing.allocator;
    const body = try dispatch(a, method, params);
    defer a.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const err = parsed.value.object.get("error") orelse return error.TestUnexpectedResult;
    if (err != .object) {
        std.debug.print("{s} {s}: expected error {d}, got success: {s}\n", .{ method, params, want_code, body });
        return error.TestUnexpectedResult;
    }
    const code = err.object.get("code").?.integer;
    const msg = err.object.get("message").?.string;
    if (code != want_code or !std.mem.eql(u8, msg, want_msg)) {
        std.debug.print("{s} {s}:\n  want {d} \"{s}\"\n  got  {d} \"{s}\"\n", .{ method, params, want_code, want_msg, code, msg });
        return error.TestUnexpectedResult;
    }
}

/// Success result, re-serialized compactly for an exact comparison.
fn expectResult(method: []const u8, params: []const u8, want_json: []const u8) !void {
    const a = testing.allocator;
    const body = try dispatch(a, method, params);
    defer a.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const err = parsed.value.object.get("error") orelse .null;
    if (err != .null) {
        std.debug.print("{s} {s}: unexpected error {s}\n", .{ method, params, body });
        return error.TestUnexpectedResult;
    }
    const got = try std.json.stringifyAlloc(a, parsed.value.object.get("result").?, .{});
    defer a.free(got);
    var want_parsed = try std.json.parseFromSlice(std.json.Value, a, want_json, .{});
    defer want_parsed.deinit();
    const want = try std.json.stringifyAlloc(a, want_parsed.value, .{});
    defer a.free(want);
    if (!std.mem.eql(u8, got, want)) {
        std.debug.print("{s} {s}:\n  want {s}\n  got  {s}\n", .{ method, params, want, got });
        return error.TestUnexpectedResult;
    }
}

const PSBT_UNKNOWN_IN = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA";
const PSBT_OUT_ONLY = "cHNidP8BACkCAAAAAAGghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAA";
const K1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd";
const K2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626";
const ZERO_TXID = "0000000000000000000000000000000000000000000000000000000000000000";

// ── Blockchain ─────────────────────────────────────────────────────────────

test "r5_errcode verifytxoutproof non-hex is -8 (ParseHexV), not -22" {
    try expectError("verifytxoutproof", "[\"zz\"]", -8, "proof must be hexadecimal string (not 'zz')");
    try expectError("verifytxoutproof", "[\"0\"]", -8, "proof must be hexadecimal string (not '0')");
}

test "r5_errcode verifytxoutproof truncated proof is -1 stream error" {
    try expectError("verifytxoutproof", "[\"00\"]", -1, "SpanReader::read(): end of data: iostream error");
}

test "r5_errcode verifytxoutproof hostile hash count neither allocates nor crashes" {
    // 80-byte header + nTx=1 + CompactSize 0xff ffffffffffffffff hashes.
    const hdr = "00" ** 80;
    try expectError("verifytxoutproof", "[\"" ++ hdr ++ "01000000ffffffffffffffffff\"]", -1, "ReadCompactSize(): size too large: iostream error");
    // A count under MAX_SIZE but past the end of the proof: end of data.
    try expectError("verifytxoutproof", "[\"" ++ hdr ++ "01000000fe00000100\"]", -1, "SpanReader::read(): end of data: iostream error");
}

test "r5_errcode gettxspendingprevout Core's RPCTypeCheckObj order and codes" {
    try expectError("gettxspendingprevout", "[[{\"txid\":\"" ++ ZERO_TXID ++ "\"}]]", -3, "Missing vout");
    try expectError("gettxspendingprevout", "[[{\"txid\":\"" ++ ZERO_TXID ++ "\",\"vout\":\"1\"}]]", -3, "JSON value of type string for field vout is not of expected type number");
    try expectError("gettxspendingprevout", "[[{\"txid\":\"" ++ ZERO_TXID ++ "\",\"vout\":1,\"x\":1}]]", -3, "Unexpected key x");
    try expectError("gettxspendingprevout", "[[{\"txid\":\"zz\",\"vout\":1}]]", -8, "txid must be of length 64 (not 2, for 'zz')");
    try expectError("gettxspendingprevout", "[[1]]", -3, "JSON value of type number is not of expected type object");
    try expectError("gettxspendingprevout", "[[{\"txid\":\"" ++ ZERO_TXID ++ "\",\"vout\":1}], {\"foo\":1}]", -3, "Unexpected key foo");
    try expectError("gettxspendingprevout", "[[{\"txid\":\"" ++ ZERO_TXID ++ "\",\"vout\":1}], 5]", -3, "Wrong type passed:\n{\n    \"Position 2 (options)\": \"JSON value of type number is not of expected type object\"\n}");
}

test "r5_errcode gettxspendingprevout out-of-int vout is -1, never a truncating cast" {
    // Before the fix this was `@intCast(u32)` on an unchecked i64: the RPC
    // thread panicked ("integer cast truncated bits") and the node died.
    try expectError("gettxspendingprevout", "[[{\"txid\":\"" ++ ZERO_TXID ++ "\",\"vout\":99999999999}]]", -1, "JSON integer out of range");
    try expectError("gettxspendingprevout", "[[{\"txid\":\"" ++ ZERO_TXID ++ "\",\"vout\":1.5}]]", -1, "JSON integer out of range");
}

test "r5_errcode scanblocks / scantxoutset unknown action is -8" {
    try expectError("scanblocks", "[\"bogus\"]", -8, "Invalid action 'bogus'");
    try expectError("scantxoutset", "[\"bogus\"]", -8, "Invalid action 'bogus'");
    try expectResult("scantxoutset", "[\"status\"]", "null");
    try expectResult("scantxoutset", "[\"abort\"]", "false");
}

test "r5_errcode pruneblockchain exists; type check precedes the prune-mode check" {
    try expectError("pruneblockchain", "[\"zz\"]", -3, "Wrong type passed:\n{\n    \"Position 1 (height)\": \"JSON value of type string is not of expected type number\"\n}");
    try expectError("pruneblockchain", "[10]", -1, "Cannot prune blocks because node is not in prune mode.");
}

test "r5_errcode importmempool exists and refuses during initial block download" {
    // A fresh chainstate is in IBD, exactly like Core at genesis.
    try expectError("importmempool", "[\"/nonexistent/r5-probe-no-such-file.dat\"]", -10, "Can only import the mempool after the block download and sync is done.");
    try expectError("importmempool", "[5]", -3, "Wrong type passed:\n{\n    \"Position 1 (filepath)\": \"JSON value of type number is not of expected type string\"\n}");
}

// ── Mining ─────────────────────────────────────────────────────────────────

test "r5_errcode prioritisetransaction bad txid is -8 (ParseHashV)" {
    try expectError("prioritisetransaction", "[\"zz\",0,1000]", -8, "txid must be of length 64 (not 2, for 'zz')");
    try expectError("prioritisetransaction", "[\"" ++ ZERO_TXID ++ "\",0,1.5]", -1, "JSON integer out of range");
    try expectError("prioritisetransaction", "[\"" ++ ZERO_TXID ++ "\",1,1000]", -8, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.");
}

// ── Rawtransactions ────────────────────────────────────────────────────────

test "r5_errcode decodescript non-hex is -8 (ParseHexV)" {
    try expectError("decodescript", "[\"zz\"]", -8, "argument must be hexadecimal string (not 'zz')");
    try expectError("decodescript", "[\"0\"]", -8, "argument must be hexadecimal string (not '0')");
    try expectError("decodescript", "[5]", -3, "Wrong type passed:\n{\n    \"Position 1 (hexstring)\": \"JSON value of type number is not of expected type string\"\n}");
}

test "r5_errcode createpsbt bad txid is -8 (ParseHashO)" {
    try expectError("createpsbt", "[[{\"txid\":\"zz\",\"vout\":0}],{\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\":0.001}]", -8, "txid must be of length 64 (not 2, for 'zz')");
}

test "r5_errcode analyzepsbt reports each input's next role" {
    try expectResult("analyzepsbt", "[\"" ++ PSBT_UNKNOWN_IN ++ "\"]", "{\"inputs\":[{\"has_utxo\":false,\"is_final\":false,\"next\":\"updater\"}],\"next\":\"updater\"}");
}

test "r5_errcode combinepsbt empty array is -8; a single PSBT is returned" {
    try expectError("combinepsbt", "[[]]", -8, "Parameter 'txs' cannot be empty");
    try expectResult("combinepsbt", "[[\"" ++ PSBT_UNKNOWN_IN ++ "\"]]", "\"" ++ PSBT_UNKNOWN_IN ++ "\"");
    try expectError("combinepsbt", "[[\"" ++ PSBT_UNKNOWN_IN ++ "\",\"" ++ PSBT_OUT_ONLY ++ "\"]]", -8, "PSBTs not compatible (different transactions)");
}

test "r5_errcode joinpsbts exists: joins, and needs two" {
    try expectResult("joinpsbts", "[[\"" ++ PSBT_UNKNOWN_IN ++ "\",\"" ++ PSBT_OUT_ONLY ++ "\"]]", "\"cHNidP8BAHECAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AqCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9aghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAAAAA=\"");
    try expectError("joinpsbts", "[[\"" ++ PSBT_UNKNOWN_IN ++ "\"]]", -8, "At least two PSBTs are required to join PSBTs.");
    try expectError("joinpsbts", "[[\"" ++ PSBT_UNKNOWN_IN ++ "\",\"" ++ PSBT_UNKNOWN_IN ++ "\"]]", -8, "Input aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0 exists in multiple PSBTs");
}

test "r5_errcode utxoupdatepsbt exists: unknown inputs pass through; bad base64 is -22" {
    try expectResult("utxoupdatepsbt", "[\"" ++ PSBT_UNKNOWN_IN ++ "\"]", "\"" ++ PSBT_UNKNOWN_IN ++ "\"");
    try expectError("utxoupdatepsbt", "[\"notbase64!!\"]", -22, "TX decode failed invalid base64");
}

test "r5_errcode descriptorprocesspsbt: Core arity (2..5), output key path, bad descriptor -5" {
    try expectResult(
        "descriptorprocesspsbt",
        "[\"" ++ PSBT_UNKNOWN_IN ++ "\",[\"wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)\"]]",
        "{\"psbt\":\"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA==\",\"complete\":false}",
    );
    try expectError("descriptorprocesspsbt", "[\"" ++ PSBT_UNKNOWN_IN ++ "\",[\"nonsense(desc)\"]]", -5, "'nonsense(desc)' is not a valid descriptor function");
    try expectError("descriptorprocesspsbt", "[\"" ++ PSBT_UNKNOWN_IN ++ "\",[],\"BOGUS\"]", -8, "'BOGUS' is not a valid sighash parameter.");
}

test "r5_errcode submitpackage empty array is -8; undecodable tx is -22 with Core's text" {
    try expectError("submitpackage", "[[]]", -8, "Array must contain between 1 and 25 transactions.");
    try expectError("submitpackage", "[[\"zz\"]]", -22, "TX decode failed: zz Make sure the tx has at least one input.");
}

// ── Util ───────────────────────────────────────────────────────────────────

test "r5_errcode createmultisig: pubkeys (-5) are checked before the bounds (-8)" {
    try expectError("createmultisig", "[3,[\"" ++ K1 ++ "\",\"" ++ K2 ++ "\"]]", -8, "not enough keys supplied (got 2 keys, but need at least 3 to redeem)");
    try expectError("createmultisig", "[3,[\"deadbeef\",\"deadbeef\"]]", -5, "Pubkey \"deadbeef\" must have a length of either 33 or 65 bytes");
    try expectError("createmultisig", "[1,[\"zz\"]]", -5, "Pubkey \"zz\" must be a hex string");
    try expectError("createmultisig", "[0,[\"" ++ K1 ++ "\"]]", -8, "a multisignature address must require at least one key to redeem");
    try expectError("createmultisig", "[1,[\"" ++ K1 ++ "\"],\"bech32m\"]", -5, "createmultisig cannot create bech32m multisig addresses");
    try expectError("createmultisig", "[1,[\"" ++ K1 ++ "\"],\"bogus\"]", -5, "Unknown address type 'bogus'");
}

test "r5_errcode validateaddress error text is Core's DecodeDestination text" {
    try expectResult("validateaddress", "[\"notanaddress\"]", "{\"isvalid\":false,\"error_locations\":[],\"error\":\"Invalid checksum or length of Base58 address (P2PKH or P2SH)\"}");
    try expectResult("validateaddress", "[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3aa\"]", "{\"isvalid\":false,\"error_locations\":[40,41],\"error\":\"Invalid Bech32 checksum\"}");
    try expectResult("validateaddress", "[\"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn\"]", "{\"isvalid\":false,\"error_locations\":[],\"error\":\"Invalid or unsupported Base58-encoded address.\"}");
}

// ── Control ────────────────────────────────────────────────────────────────

test "r5_errcode stop wrong-type is -3 and does not stop" {
    try expectError("stop", "[\"notanumber\"]", -3, "Wrong type passed:\n{\n    \"Position 1 (wait)\": \"JSON value of type string is not of expected type number\"\n}");
}

test "r5_errcode help lists every probed method that answers" {
    const a = testing.allocator;
    const body = try dispatch(a, "help", "[]");
    defer a.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const text = parsed.value.object.get("result").?.string;
    const must = [_][]const u8{
        "gettxoutsetinfo",      "getnetworkhashps", "deriveaddresses", "getindexinfo",
        "getblockfilter",       "joinpsbts",        "utxoupdatepsbt",  "descriptorprocesspsbt",
        "importmempool",        "pruneblockchain",  "scanblocks",      "scantxoutset",
        "gettxspendingprevout", "verifytxoutproof", "createpsbt",      "analyzepsbt",
        "combinepsbt",          "submitpackage",    "createmultisig",
    };
    for (must) |m| {
        var found = false;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |line| {
            if (std.mem.eql(u8, line, m)) found = true;
        }
        if (!found) {
            std.debug.print("help does not list {s}\n", .{m});
            return error.TestUnexpectedResult;
        }
    }
}

// A PSBT_UNKNOWN_IN whose input carries a P2WPKH witness_utxo (200000 sat)
// paying hash160 of KwDiBf...'s pubkey.  Expected outputs are Core's own.
const PSBT_WPKH_UTXO = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH0ANAwAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAA==";
const WPKH_WIF = "wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)";

test "r5_errcode descriptorprocesspsbt signs + finalizes a P2WPKH input byte-exact with Core" {
    try expectResult(
        "descriptorprocesspsbt",
        "[\"" ++ PSBT_WPKH_UTXO ++ "\",[\"" ++ WPKH_WIF ++ "\"]]",
        "{\"psbt\":\"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH0ANAwAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YBCGsCRzBEAiAxWUTtC9hPEJAWVrz9KSTCu1xgAg1pmyJBmsb2jyu5xgIgA1/LeyUO6FGotQgQRRAnLwFnqWGozPcuUCEM19SpaAQBIQJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA==\",\"complete\":true,\"hex\":\"02000000000101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd6024730440220315944ed0bd84f10901656bcfd2924c2bb5c60020d699b22419ac6f68f2bb9c60220035fcb7b250ee851a8b508104510272f0167a961a8ccf72e50210cd7d4a9680401210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000\"}",
    );
}

test "r5_errcode descriptorprocesspsbt finalize=false keeps the partial sig and key paths" {
    try expectResult(
        "descriptorprocesspsbt",
        "[\"" ++ PSBT_WPKH_UTXO ++ "\",[\"" ++ WPKH_WIF ++ "\"],\"ALL\",true,false]",
        "{\"psbt\":\"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH0ANAwAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEcwRAIgMVlE7QvYTxCQFla8/SkkwrtcYAINaZsiQZrG9o8rucYCIANfy3slDuhRqLUIEEUQJy8BZ6lhqMz3LlAhDNfUqWgEASIGAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYBHUedugAIgICeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5gEdR526AA=\",\"complete\":false}",
    );
    try expectResult(
        "descriptorprocesspsbt",
        "[\"" ++ PSBT_WPKH_UTXO ++ "\",[\"" ++ WPKH_WIF ++ "\"],\"ALL\",false,false]",
        "{\"psbt\":\"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH0ANAwAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEcwRAIgMVlE7QvYTxCQFla8/SkkwrtcYAINaZsiQZrG9o8rucYCIANfy3slDuhRqLUIEEUQJy8BZ6lhqMz3LlAhDNfUqWgEAQAA\",\"complete\":false}",
    );
}

test "r5_errcode descriptorprocesspsbt carries an explicit key origin" {
    try expectResult(
        "descriptorprocesspsbt",
        "[\"" ++ PSBT_WPKH_UTXO ++ "\",[\"wpkh([deadbeef/84h/0h/0h]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)\"]]",
        "{\"psbt\":\"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH0ANAwAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YiBgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmBDerb7vVAAAgAAAAIAAAACAACICAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYEN6tvu9UAACAAAAAgAAAAIAA\",\"complete\":false}",
    );
}

test "r5_errcode utxoupdatepsbt adds key paths from a public descriptor" {
    try expectResult(
        "utxoupdatepsbt",
        "[\"" ++ PSBT_WPKH_UTXO ++ "\",[\"wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)\"]]",
        "\"cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAEBH0ANAwAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YiBgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboACICAnm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYBHUedugA\"",
    );
}

test "r5_errcode analyzepsbt names the missing pubkey of a P2WPKH input" {
    try expectResult(
        "analyzepsbt",
        "[\"" ++ PSBT_WPKH_UTXO ++ "\"]",
        "{\"inputs\":[{\"has_utxo\":true,\"is_final\":false,\"next\":\"updater\",\"missing\":{\"pubkeys\":[\"751e76e8199196d454941c45d1b3a323f1433bd6\"]}}],\"fee\":0.001,\"next\":\"updater\"}",
    );
}

test "r5_errcode central type check reports every mismatching position (Core UniValue::write(4))" {
    try expectError("scanblocks", "[\"x\", 1, \"y\"]", -3, "Wrong type passed:\n{\n    \"Position 2 (scanobjects)\": \"JSON value of type number is not of expected type array\",\n    \"Position 3 (start_height)\": \"JSON value of type string is not of expected type number\"\n}");
    try expectError("createpsbt", "[[], null]", -8, "Invalid parameter, output argument must be non-null");
    try expectError("createrawtransaction", "[[], 5]", -3, "JSON value of type number is not of expected type array");
}

test "r5_errcode getnetworkhashps / gettxoutsetinfo central type check" {
    try expectError("getnetworkhashps", "[1.5, \"x\"]", -3, "Wrong type passed:\n{\n    \"Position 2 (height)\": \"JSON value of type string is not of expected type number\"\n}");
    try expectError("gettxoutsetinfo", "[1]", -3, "Wrong type passed:\n{\n    \"Position 1 (hash_type)\": \"JSON value of type number is not of expected type string\"\n}");
    try expectError("gettxoutsetinfo", "[\"bogus\"]", -8, "'bogus' is not a valid hash_type");
}
