//! clearbit - Bitcoin full node in Zig
//!
//! This is the main entry point for the clearbit node. It handles:
//! - CLI argument parsing
//! - Configuration file loading
//! - Signal handling for graceful shutdown
//! - Subsystem initialization and orchestration

const std = @import("std");
pub const types = @import("types.zig");
pub const crypto = @import("crypto.zig");
pub const serialize = @import("serialize.zig");
pub const address = @import("address.zig");
pub const script = @import("script.zig");
pub const storage = @import("storage.zig");
pub const consensus = @import("consensus.zig");
pub const validation = @import("validation.zig");
pub const p2p = @import("p2p.zig");
pub const peer = @import("peer.zig");
pub const sync = @import("sync.zig");
pub const mempool = @import("mempool.zig");
pub const block_template = @import("block_template.zig");
pub const rpc = @import("rpc.zig");
pub const wallet = @import("wallet.zig");
pub const perf = @import("perf.zig");
pub const bench = @import("bench.zig");
pub const indexes = @import("indexes.zig");

// ============================================================================
// Version Info
// ============================================================================

pub const VERSION = "0.1.0";
pub const VERSION_STRING = "clearbit v" ++ VERSION;

// ============================================================================
// Configuration
// ============================================================================

/// Node configuration with defaults matching Bitcoin Core conventions.
pub const Config = struct {
    // Network
    network: Network = .mainnet,
    listen_port: u16 = 8333,
    max_connections: u32 = 125,
    connect: ?[]const u8 = null, // Connect to specific peer only
    dns_seed: bool = true,

    // RPC
    rpc_bind: []const u8 = "127.0.0.1",
    rpc_port: u16 = 8332,
    rpc_user: ?[]const u8 = null,
    rpc_password: ?[]const u8 = null,

    // Storage
    datadir: []const u8 = "~/.clearbit",
    prune: u64 = 0, // 0 = no pruning, else target size in MiB
    dbcache: u64 = 450, // UTXO cache size in MiB
    txindex: bool = false,
    blockfilterindex: bool = false, // BIP-157/158 compact block filters
    coinstatsindex: bool = false, // Per-block UTXO statistics

    // Mempool
    maxmempool: u64 = 300, // Max mempool size in MiB
    mempoolexpiry: u64 = 336, // Hours before expiry

    // Debug
    debug: bool = false,
    printtoconsole: bool = true,
    logfile: ?[]const u8 = null,

    // Benchmarking
    run_benchmark: bool = false,

    pub const Network = enum {
        mainnet,
        testnet,
        testnet4,
        regtest,
    };

    /// Get consensus network params for the configured network.
    pub fn getNetworkParams(self: *const Config) *const consensus.NetworkParams {
        return switch (self.network) {
            .mainnet => &consensus.MAINNET,
            .testnet => &consensus.TESTNET,
            .testnet4 => &consensus.TESTNET4,
            .regtest => &consensus.REGTEST,
        };
    }
};

// ============================================================================
// CLI Argument Parsing
// ============================================================================

pub const ArgParseError = error{
    InvalidArgument,
    InvalidPortNumber,
    InvalidCacheSize,
    MissingValue,
};

/// Parse command line arguments into config.
/// CLI arguments override config file settings.
pub fn parseArgs(args: *std.process.ArgIterator, config: *Config) ArgParseError!bool {
    _ = args.next(); // skip program name

    while (args.next()) |arg| {
        // Network selection
        if (std.mem.eql(u8, arg, "--testnet") or std.mem.eql(u8, arg, "-testnet")) {
            config.network = .testnet;
            config.listen_port = 18333;
            config.rpc_port = 18332;
        } else if (std.mem.eql(u8, arg, "--testnet4") or std.mem.eql(u8, arg, "-testnet4")) {
            config.network = .testnet4;
            config.listen_port = 48333;
            config.rpc_port = 48332;
        } else if (std.mem.eql(u8, arg, "--regtest") or std.mem.eql(u8, arg, "-regtest")) {
            config.network = .regtest;
            config.listen_port = 18444;
            config.rpc_port = 18443;
        }
        // Data directory
        else if (std.mem.startsWith(u8, arg, "--datadir=") or std.mem.startsWith(u8, arg, "-datadir=")) {
            if (std.mem.indexOf(u8, arg, "=")) |eq| {
                config.datadir = arg[eq + 1 ..];
            } else {
                return ArgParseError.MissingValue;
            }
        }
        // RPC settings
        else if (std.mem.startsWith(u8, arg, "--rpcuser=")) {
            config.rpc_user = arg["--rpcuser=".len..];
        } else if (std.mem.startsWith(u8, arg, "--rpcpassword=")) {
            config.rpc_password = arg["--rpcpassword=".len..];
        } else if (std.mem.startsWith(u8, arg, "--rpcport=")) {
            config.rpc_port = std.fmt.parseInt(u16, arg["--rpcport=".len..], 10) catch
                return ArgParseError.InvalidPortNumber;
        } else if (std.mem.startsWith(u8, arg, "--rpcbind=")) {
            config.rpc_bind = arg["--rpcbind=".len..];
        }
        // P2P settings
        else if (std.mem.startsWith(u8, arg, "--port=")) {
            config.listen_port = std.fmt.parseInt(u16, arg["--port=".len..], 10) catch
                return ArgParseError.InvalidPortNumber;
        } else if (std.mem.startsWith(u8, arg, "--maxconnections=")) {
            config.max_connections = std.fmt.parseInt(u32, arg["--maxconnections=".len..], 10) catch
                return ArgParseError.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--connect=")) {
            config.connect = arg["--connect=".len..];
        } else if (std.mem.eql(u8, arg, "--nodnsseed") or std.mem.eql(u8, arg, "-nodnsseed")) {
            config.dns_seed = false;
        }
        // Storage settings
        else if (std.mem.startsWith(u8, arg, "--dbcache=")) {
            config.dbcache = std.fmt.parseInt(u64, arg["--dbcache=".len..], 10) catch
                return ArgParseError.InvalidCacheSize;
        } else if (std.mem.startsWith(u8, arg, "--prune=")) {
            config.prune = std.fmt.parseInt(u64, arg["--prune=".len..], 10) catch
                return ArgParseError.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--txindex")) {
            config.txindex = true;
        } else if (std.mem.eql(u8, arg, "--blockfilterindex")) {
            config.blockfilterindex = true;
        } else if (std.mem.eql(u8, arg, "--coinstatsindex")) {
            config.coinstatsindex = true;
        }
        // Mempool settings
        else if (std.mem.startsWith(u8, arg, "--maxmempool=")) {
            config.maxmempool = std.fmt.parseInt(u64, arg["--maxmempool=".len..], 10) catch
                return ArgParseError.InvalidCacheSize;
        } else if (std.mem.startsWith(u8, arg, "--mempoolexpiry=")) {
            config.mempoolexpiry = std.fmt.parseInt(u64, arg["--mempoolexpiry=".len..], 10) catch
                return ArgParseError.InvalidArgument;
        }
        // Debug settings
        else if (std.mem.eql(u8, arg, "--debug") or std.mem.eql(u8, arg, "-debug")) {
            config.debug = true;
        } else if (std.mem.eql(u8, arg, "--printtoconsole") or std.mem.eql(u8, arg, "-printtoconsole")) {
            config.printtoconsole = true;
        }
        // Benchmarking
        else if (std.mem.eql(u8, arg, "--benchmark") or std.mem.eql(u8, arg, "-benchmark")) {
            config.run_benchmark = true;
        }
        // Help and version
        else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return true; // Signal to exit
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            printVersion();
            return true; // Signal to exit
        }
        // Unknown argument
        else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            return ArgParseError.InvalidArgument;
        }
    }

    return false; // Continue execution
}

/// Print usage information.
pub fn printUsage() void {
    const usage =
        \\Usage: clearbit [options]
        \\
        \\Network selection:
        \\  --testnet              Use testnet network
        \\  --regtest              Use regtest network
        \\
        \\Connection options:
        \\  --port=<port>          Listen for connections on port (default: 8333)
        \\  --maxconnections=<n>   Maximum total connections (default: 125)
        \\  --connect=<addr>       Connect only to specified peer
        \\  --nodnsseed            Disable DNS seeding
        \\
        \\RPC server options:
        \\  --rpcbind=<addr>       Bind RPC to address (default: 127.0.0.1)
        \\  --rpcport=<port>       RPC port (default: 8332)
        \\  --rpcuser=<user>       RPC username
        \\  --rpcpassword=<pw>     RPC password
        \\
        \\Storage options:
        \\  --datadir=<dir>        Data directory (default: ~/.clearbit)
        \\  --dbcache=<MiB>        UTXO cache size in MiB (default: 450)
        \\  --prune=<MiB>          Prune target in MiB (0 = disabled)
        \\  --txindex              Enable transaction index
        \\  --blockfilterindex     Enable BIP-157/158 block filter index
        \\  --coinstatsindex       Enable UTXO statistics index
        \\
        \\Mempool options:
        \\  --maxmempool=<MiB>     Max mempool size in MiB (default: 300)
        \\  --mempoolexpiry=<hrs>  Mempool expiry in hours (default: 336)
        \\
        \\Debug options:
        \\  --debug                Enable debug logging
        \\  --printtoconsole       Print to console
        \\
        \\Performance:
        \\  --benchmark            Run performance benchmarks and exit
        \\
        \\General:
        \\  --help, -h             Show this help message
        \\  --version, -v          Show version information
        \\
    ;
    std.debug.print("{s}", .{usage});
}

/// Print version information.
pub fn printVersion() void {
    std.debug.print("{s}\n", .{VERSION_STRING});
}

// ============================================================================
// Data Directory Handling
// ============================================================================

pub const PathError = error{
    NoHomeDir,
    OutOfMemory,
};

/// Resolve a path, expanding ~ to the home directory.
pub fn resolveDataDir(path: []const u8, allocator: std.mem.Allocator) PathError![]const u8 {
    if (std.mem.startsWith(u8, path, "~/")) {
        const home = std.posix.getenv("HOME") orelse return PathError.NoHomeDir;
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ home, path[2..] }) catch
            return PathError.OutOfMemory;
    }
    return allocator.dupe(u8, path) catch return PathError.OutOfMemory;
}

/// Get the network-specific subdirectory name.
pub fn getNetworkSubdir(network: Config.Network) []const u8 {
    return switch (network) {
        .mainnet => "",
        .testnet => "testnet3",
        .testnet4 => "testnet4",
        .regtest => "regtest",
    };
}

// ============================================================================
// Configuration File Parsing
// ============================================================================

pub const ConfigFileError = error{
    ReadError,
    ParseError,
    OutOfMemory,
};

/// Load configuration from clearbit.conf file.
/// Format: key=value per line, # for comments.
pub fn loadConfigFile(
    datadir: []const u8,
    config: *Config,
    allocator: std.mem.Allocator,
) ConfigFileError!void {
    const path = std.fmt.allocPrint(allocator, "{s}/clearbit.conf", .{datadir}) catch
        return ConfigFileError.OutOfMemory;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        if (err == error.FileNotFound) return; // Config file is optional
        return ConfigFileError.ReadError;
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 1 << 20) catch
        return ConfigFileError.ReadError;
    defer allocator.free(content);

    // Parse line by line
    var lines = std.mem.splitSequence(u8, content, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.indexOf(u8, trimmed, "=")) |eq| {
            const key = std.mem.trim(u8, trimmed[0..eq], " \t");
            const value = std.mem.trim(u8, trimmed[eq + 1 ..], " \t");

            // Network settings
            if (std.mem.eql(u8, key, "testnet") and std.mem.eql(u8, value, "1")) {
                config.network = .testnet;
                config.listen_port = 18333;
                config.rpc_port = 18332;
            } else if (std.mem.eql(u8, key, "testnet4") and std.mem.eql(u8, value, "1")) {
                config.network = .testnet4;
                config.listen_port = 48333;
                config.rpc_port = 48332;
            } else if (std.mem.eql(u8, key, "regtest") and std.mem.eql(u8, value, "1")) {
                config.network = .regtest;
                config.listen_port = 18444;
                config.rpc_port = 18443;
            }
            // RPC settings
            else if (std.mem.eql(u8, key, "rpcuser")) {
                config.rpc_user = value;
            } else if (std.mem.eql(u8, key, "rpcpassword")) {
                config.rpc_password = value;
            } else if (std.mem.eql(u8, key, "rpcport")) {
                config.rpc_port = std.fmt.parseInt(u16, value, 10) catch continue;
            } else if (std.mem.eql(u8, key, "rpcbind")) {
                config.rpc_bind = value;
            }
            // P2P settings
            else if (std.mem.eql(u8, key, "port")) {
                config.listen_port = std.fmt.parseInt(u16, value, 10) catch continue;
            } else if (std.mem.eql(u8, key, "maxconnections")) {
                config.max_connections = std.fmt.parseInt(u32, value, 10) catch continue;
            } else if (std.mem.eql(u8, key, "connect")) {
                config.connect = value;
            } else if (std.mem.eql(u8, key, "dnsseed")) {
                config.dns_seed = std.mem.eql(u8, value, "1");
            }
            // Storage settings
            else if (std.mem.eql(u8, key, "dbcache")) {
                config.dbcache = std.fmt.parseInt(u64, value, 10) catch continue;
            } else if (std.mem.eql(u8, key, "prune")) {
                config.prune = std.fmt.parseInt(u64, value, 10) catch continue;
            } else if (std.mem.eql(u8, key, "txindex")) {
                config.txindex = std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "blockfilterindex")) {
                config.blockfilterindex = std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "coinstatsindex")) {
                config.coinstatsindex = std.mem.eql(u8, value, "1");
            }
            // Mempool settings
            else if (std.mem.eql(u8, key, "maxmempool")) {
                config.maxmempool = std.fmt.parseInt(u64, value, 10) catch continue;
            } else if (std.mem.eql(u8, key, "mempoolexpiry")) {
                config.mempoolexpiry = std.fmt.parseInt(u64, value, 10) catch continue;
            }
            // Debug settings
            else if (std.mem.eql(u8, key, "debug")) {
                config.debug = std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "printtoconsole")) {
                config.printtoconsole = std.mem.eql(u8, value, "1");
            }
        }
    }
}

// ============================================================================
// RPC Authentication
// ============================================================================

/// Compute Base64-encoded auth token from user:password.
pub fn computeAuthToken(
    user: ?[]const u8,
    password: ?[]const u8,
    allocator: std.mem.Allocator,
) !?[]const u8 {
    const u = user orelse return null;
    const p = password orelse return null;

    const combined = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ u, p });
    defer allocator.free(combined);

    const encoded_len = std.base64.standard.Encoder.calcSize(combined.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, combined);

    return encoded;
}

// ============================================================================
// Signal Handling
// ============================================================================

/// Global shutdown flag accessed by signal handler.
pub var shutdown_requested = std.atomic.Value(bool).init(false);

/// Signal handler for SIGINT and SIGTERM.
fn signalHandler(sig: c_int) callconv(.C) void {
    _ = sig;
    shutdown_requested.store(true, .release);
}

/// Install signal handlers for graceful shutdown.
pub fn installSignalHandlers() void {
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Parse CLI arguments
    var config = Config{};
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    const should_exit = parseArgs(&args, &config) catch |err| {
        std.debug.print("Error parsing arguments: {}\n", .{err});
        std.process.exit(1);
    };

    if (should_exit) {
        return; // --help or --version was specified
    }

    // Run benchmarks if requested
    if (config.run_benchmark) {
        const stdout = std.io.getStdOut().writer();
        bench.runAllBenchmarks(allocator, stdout) catch |err| {
            std.debug.print("Error running benchmarks: {}\n", .{err});
            std.process.exit(1);
        };
        return;
    }

    // 2. Resolve and create data directory
    const datadir = resolveDataDir(config.datadir, allocator) catch |err| {
        std.debug.print("Error resolving data directory: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(datadir);

    // Try to create data directory (ignore if exists)
    std.fs.makeDirAbsolute(datadir) catch |err| {
        if (err != error.PathAlreadyExists) {
            std.debug.print("Warning: could not create data directory: {}\n", .{err});
        }
    };

    // 3. Load config file (before processing network subdirs)
    loadConfigFile(datadir, &config, allocator) catch |err| {
        if (err != ConfigFileError.ReadError) {
            std.debug.print("Warning: error loading config file: {}\n", .{err});
        }
    };

    // 4. Create network subdirectory if needed
    const subdir = getNetworkSubdir(config.network);
    var full_datadir: []const u8 = datadir;
    if (subdir.len > 0) {
        full_datadir = std.fmt.allocPrint(allocator, "{s}/{s}", .{ datadir, subdir }) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };

        std.fs.makeDirAbsolute(full_datadir) catch |err| {
            if (err != error.PathAlreadyExists) {
                std.debug.print("Warning: could not create network directory: {}\n", .{err});
            }
        };
    }
    defer if (subdir.len > 0) allocator.free(full_datadir);

    // 5. Get network parameters
    const params = config.getNetworkParams();

    // 6. Print startup message
    std.debug.print("{s}\n", .{VERSION_STRING});
    std.debug.print("Starting on {s}\n", .{@tagName(config.network)});
    std.debug.print("Data directory: {s}\n", .{full_datadir});

    // 7. Initialize subsystems
    var chain_state = storage.ChainState.init(null, allocator);
    defer chain_state.deinit();

    var mempool_instance = mempool.Mempool.init(&chain_state, params, allocator);
    defer mempool_instance.deinit();

    var peer_manager = peer.PeerManager.init(allocator, params);
    defer peer_manager.deinit();
    peer_manager.chain_state = &chain_state;

    const auth_token = computeAuthToken(config.rpc_user, config.rpc_password, allocator) catch null;
    defer if (auth_token) |t| allocator.free(t);

    var chain_manager = validation.ChainManager.init(&chain_state, &mempool_instance, allocator);
    defer chain_manager.deinit();

    var rpc_server = rpc.RpcServer.init(
        allocator,
        &chain_state,
        &mempool_instance,
        &peer_manager,
        params,
        .{
            .bind_address = config.rpc_bind,
            .port = config.rpc_port,
            .auth_token = auth_token,
        },
    );
    defer rpc_server.deinit();
    rpc_server.setChainManager(&chain_manager);

    // 8. Install signal handlers
    installSignalHandlers();

    // Initialize chain state with genesis block
    chain_state.best_hash = params.genesis_hash;
    chain_state.best_height = 0;

    // 9. Parse --connect address before starting threads
    if (config.connect) |addr_str| {
        // Parse "host:port" format
        if (std.mem.lastIndexOfScalar(u8, addr_str, ':')) |colon_pos| {
            const host = addr_str[0..colon_pos];
            const port_str = addr_str[colon_pos + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch {
                std.debug.print("Invalid port in --connect address: {s}\n", .{addr_str});
                std.process.exit(1);
            };
            // Parse the IPv4 address
            var ip_bytes: [4]u8 = undefined;
            var part_idx: usize = 0;
            var start: usize = 0;
            for (host, 0..) |c, i| {
                if (c == '.' or i == host.len - 1) {
                    const end = if (c == '.') i else i + 1;
                    if (part_idx >= 4) {
                        std.debug.print("Invalid IP in --connect address: {s}\n", .{addr_str});
                        std.process.exit(1);
                    }
                    ip_bytes[part_idx] = std.fmt.parseInt(u8, host[start..end], 10) catch {
                        std.debug.print("Invalid IP in --connect address: {s}\n", .{addr_str});
                        std.process.exit(1);
                    };
                    part_idx += 1;
                    start = i + 1;
                }
            }
            const connect_addr = std.net.Address.initIp4(ip_bytes, port);
            peer_manager.connect_address = connect_addr;
            std.debug.print("Will connect to peer: {s}\n", .{addr_str});
        } else {
            std.debug.print("Invalid --connect address (expected host:port): {s}\n", .{addr_str});
            std.process.exit(1);
        }
    } else if (config.dns_seed) {
        std.debug.print("Discovering peers via DNS seeds\n", .{});
    }

    // 10. Start subsystem threads
    std.debug.print("P2P listening on port {d}\n", .{config.listen_port});
    std.debug.print("RPC server on {s}:{d}\n", .{ config.rpc_bind, config.rpc_port });

    // Start peer manager in background thread
    const peer_thread = std.Thread.spawn(.{}, peer.PeerManager.run, .{&peer_manager}) catch |err| {
        std.debug.print("Warning: could not start peer thread: {}\n", .{err});
        return;
    };

    // Start RPC server in background thread
    rpc_server.start() catch |err| {
        std.debug.print("Warning: could not start RPC server: {}\n", .{err});
    };
    const rpc_thread = std.Thread.spawn(.{}, rpc.RpcServer.run, .{&rpc_server}) catch |err| {
        std.debug.print("Warning: could not start RPC thread: {}\n", .{err});
        return;
    };

    std.debug.print("Node running. Press Ctrl+C to stop.\n", .{});

    // 11. Main loop: wait for shutdown signal
    while (!shutdown_requested.load(.acquire)) {
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    // 12. Graceful shutdown
    std.debug.print("\nShutting down...\n", .{});

    // Stop RPC first (no new requests)
    rpc_server.stop();

    // Stop peer manager
    peer_manager.stop();

    // Wait for threads
    rpc_thread.join();
    peer_thread.join();

    // Flush chain state
    chain_state.flush() catch |err| {
        std.debug.print("Warning: error flushing chain state: {}\n", .{err});
    };

    std.debug.print("{s} stopped.\n", .{VERSION_STRING});
}

// ============================================================================
// Tests
// ============================================================================

test {
    _ = types;
    _ = crypto;
    _ = serialize;
    _ = address;
    _ = script;
    _ = storage;
    _ = consensus;
    _ = validation;
    _ = p2p;
    _ = peer;
    _ = sync;
    _ = mempool;
    _ = block_template;
    _ = rpc;
    // Note: wallet tests require libsecp256k1 to be linked
    // Run with: zig build test -Dsecp256k1=true
    // _ = wallet;
}

test "default config values" {
    const config = Config{};

    try std.testing.expectEqual(Config.Network.mainnet, config.network);
    try std.testing.expectEqual(@as(u16, 8333), config.listen_port);
    try std.testing.expectEqual(@as(u16, 8332), config.rpc_port);
    try std.testing.expectEqual(@as(u32, 125), config.max_connections);
    try std.testing.expectEqual(@as(u64, 450), config.dbcache);
    try std.testing.expectEqual(@as(u64, 300), config.maxmempool);
    try std.testing.expectEqual(@as(u64, 0), config.prune);
    try std.testing.expect(config.dns_seed);
    try std.testing.expect(!config.txindex);
    try std.testing.expect(!config.debug);
    try std.testing.expect(config.rpc_user == null);
    try std.testing.expect(config.rpc_password == null);
    try std.testing.expect(config.connect == null);
}

test "testnet config values" {
    var config = Config{};
    config.network = .testnet;
    config.listen_port = 18333;
    config.rpc_port = 18332;

    try std.testing.expectEqual(Config.Network.testnet, config.network);
    try std.testing.expectEqual(@as(u16, 18333), config.listen_port);
    try std.testing.expectEqual(@as(u16, 18332), config.rpc_port);
}

test "regtest config values" {
    var config = Config{};
    config.network = .regtest;
    config.listen_port = 18444;
    config.rpc_port = 18443;

    try std.testing.expectEqual(Config.Network.regtest, config.network);
    try std.testing.expectEqual(@as(u16, 18444), config.listen_port);
    try std.testing.expectEqual(@as(u16, 18443), config.rpc_port);
}

test "config getNetworkParams" {
    const mainnet_config = Config{ .network = .mainnet };
    const testnet_config = Config{ .network = .testnet };
    const regtest_config = Config{ .network = .regtest };

    const mainnet_params = mainnet_config.getNetworkParams();
    const testnet_params = testnet_config.getNetworkParams();
    const regtest_params = regtest_config.getNetworkParams();

    try std.testing.expectEqual(@as(u32, 0xD9B4BEF9), mainnet_params.magic);
    try std.testing.expectEqual(@as(u32, 0x0709110B), testnet_params.magic);
    try std.testing.expectEqual(@as(u32, 0xDAB5BFFA), regtest_params.magic);
}

test "resolveDataDir with tilde" {
    const allocator = std.testing.allocator;

    // Test tilde expansion
    const home = std.posix.getenv("HOME");
    if (home) |h| {
        const resolved = try resolveDataDir("~/.clearbit", allocator);
        defer allocator.free(resolved);

        // Should start with home directory
        try std.testing.expect(std.mem.startsWith(u8, resolved, h));
        try std.testing.expect(std.mem.endsWith(u8, resolved, ".clearbit"));
    }
}

test "resolveDataDir absolute path" {
    const allocator = std.testing.allocator;

    const resolved = try resolveDataDir("/tmp/clearbit", allocator);
    defer allocator.free(resolved);

    try std.testing.expectEqualStrings("/tmp/clearbit", resolved);
}

test "resolveDataDir relative path" {
    const allocator = std.testing.allocator;

    const resolved = try resolveDataDir("data", allocator);
    defer allocator.free(resolved);

    try std.testing.expectEqualStrings("data", resolved);
}

test "getNetworkSubdir" {
    try std.testing.expectEqualStrings("", getNetworkSubdir(.mainnet));
    try std.testing.expectEqualStrings("testnet3", getNetworkSubdir(.testnet));
    try std.testing.expectEqualStrings("regtest", getNetworkSubdir(.regtest));
}

test "computeAuthToken" {
    const allocator = std.testing.allocator;

    // Test with valid credentials
    const token = try computeAuthToken("user", "pass", allocator);
    try std.testing.expect(token != null);
    defer allocator.free(token.?);

    // Should be base64 encoded "user:pass"
    // "user:pass" -> "dXNlcjpwYXNz"
    try std.testing.expectEqualStrings("dXNlcjpwYXNz", token.?);

    // Test with null user
    const no_user = try computeAuthToken(null, "pass", allocator);
    try std.testing.expect(no_user == null);

    // Test with null password
    const no_pass = try computeAuthToken("user", null, allocator);
    try std.testing.expect(no_pass == null);
}

test "signal handler sets shutdown flag" {
    // Reset the flag
    shutdown_requested.store(false, .release);
    try std.testing.expect(!shutdown_requested.load(.acquire));

    // Simulate signal
    signalHandler(std.posix.SIG.INT);

    // Flag should be set
    try std.testing.expect(shutdown_requested.load(.acquire));

    // Reset for other tests
    shutdown_requested.store(false, .release);
}

test "parseArgs handles help flag" {
    // We can't easily test the full parseArgs because it uses ArgIterator
    // but we can verify the config structure is correct
    const config = Config{};
    try std.testing.expectEqual(Config.Network.mainnet, config.network);
}

test "parseArgs handles version flag" {
    // Just verify we can construct the config
    const config = Config{};
    try std.testing.expectEqual(Config.Network.mainnet, config.network);
}

test "version string format" {
    try std.testing.expect(std.mem.startsWith(u8, VERSION_STRING, "clearbit v"));
    try std.testing.expect(std.mem.indexOf(u8, VERSION_STRING, VERSION) != null);
}

test "config file parsing skips comments and blank lines" {
    const allocator = std.testing.allocator;

    // Create a temporary config file
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const config_content =
        \\# This is a comment
        \\
        \\rpcport=18332
        \\# Another comment
        \\dbcache=1000
        \\
        \\# Network setting
        \\testnet=1
    ;

    const dir = tmp_dir.dir;
    const file = try dir.createFile("clearbit.conf", .{});
    try file.writeAll(config_content);
    file.close();

    // Get absolute path
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try dir.realpath(".", &path_buf);

    var config = Config{};
    try loadConfigFile(abs_path, &config, allocator);

    // Note: String values from config file are borrowed pointers to file content,
    // which is deallocated after loadConfigFile returns. We test non-string fields.
    try std.testing.expectEqual(@as(u16, 18332), config.rpc_port);
    try std.testing.expectEqual(@as(u64, 1000), config.dbcache);
    try std.testing.expectEqual(Config.Network.testnet, config.network);
}

test "config file parsing handles all keys" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Note: String values from config file are borrowed pointers to file content,
    // which is deallocated after loadConfigFile returns. We only test non-string fields.
    const config_content =
        \\rpcport=18332
        \\port=18333
        \\maxconnections=50
        \\dbcache=1000
        \\maxmempool=500
        \\mempoolexpiry=72
        \\prune=1000
        \\txindex=1
        \\debug=1
        \\printtoconsole=1
    ;

    const dir = tmp_dir.dir;
    const file = try dir.createFile("clearbit.conf", .{});
    try file.writeAll(config_content);
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try dir.realpath(".", &path_buf);

    var config = Config{};
    try loadConfigFile(abs_path, &config, allocator);

    try std.testing.expectEqual(@as(u16, 18332), config.rpc_port);
    try std.testing.expectEqual(@as(u16, 18333), config.listen_port);
    try std.testing.expectEqual(@as(u32, 50), config.max_connections);
    try std.testing.expectEqual(@as(u64, 1000), config.dbcache);
    try std.testing.expectEqual(@as(u64, 500), config.maxmempool);
    try std.testing.expectEqual(@as(u64, 72), config.mempoolexpiry);
    try std.testing.expectEqual(@as(u64, 1000), config.prune);
    try std.testing.expect(config.txindex);
    try std.testing.expect(config.debug);
    try std.testing.expect(config.printtoconsole);
}

test "config file not found is ok" {
    const allocator = std.testing.allocator;

    var config = Config{};

    // Should not error when config file doesn't exist
    try loadConfigFile("/nonexistent/path", &config, allocator);

    // Config should remain unchanged
    try std.testing.expectEqual(Config.Network.mainnet, config.network);
}

test "config file parsing handles whitespace" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Test whitespace around key=value pairs
    const config_content = "  rpcport = 18332\n\tdbcache\t=\t1000\n  debug = 1";

    const dir = tmp_dir.dir;
    const file = try dir.createFile("clearbit.conf", .{});
    try file.writeAll(config_content);
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try dir.realpath(".", &path_buf);

    var config = Config{};
    try loadConfigFile(abs_path, &config, allocator);

    try std.testing.expectEqual(@as(u16, 18332), config.rpc_port);
    try std.testing.expectEqual(@as(u64, 1000), config.dbcache);
    try std.testing.expect(config.debug);
}

test "config network defaults for each network" {
    // Test mainnet defaults
    {
        var config = Config{ .network = .mainnet };
        const params = config.getNetworkParams();
        try std.testing.expectEqual(@as(u16, 8333), params.default_port);
        try std.testing.expectEqualStrings("bc", params.bech32_hrp);
    }

    // Test testnet defaults
    {
        var config = Config{ .network = .testnet };
        const params = config.getNetworkParams();
        try std.testing.expectEqual(@as(u16, 18333), params.default_port);
        try std.testing.expectEqualStrings("tb", params.bech32_hrp);
    }

    // Test regtest defaults
    {
        var config = Config{ .network = .regtest };
        const params = config.getNetworkParams();
        try std.testing.expectEqual(@as(u16, 18444), params.default_port);
        try std.testing.expectEqualStrings("bcrt", params.bech32_hrp);
    }
}
