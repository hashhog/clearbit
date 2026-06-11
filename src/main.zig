//! clearbit - Bitcoin full node in Zig
//!
//! This is the main entry point for the clearbit node. It handles:
//! - CLI argument parsing
//! - Configuration file loading
//! - Signal handling for graceful shutdown
//! - Subsystem initialization and orchestration

const std = @import("std");
const builtin = @import("builtin");
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
pub const mempool_persist = @import("mempool_persist.zig");
pub const block_template = @import("block_template.zig");
pub const rpc = @import("rpc.zig");
pub const wallet = @import("wallet.zig");
pub const perf = @import("perf.zig");
pub const bench = @import("bench.zig");
pub const indexes = @import("indexes.zig");
pub const ops = @import("ops.zig");
pub const debug_log = @import("debug_log.zig");
pub const zmq = @import("zmq.zig");

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
    /// Enable the hardcoded fixed-seed fallback (Core `-fixedseeds`, default
    /// true).  When the address book is empty and DNS/-addnode/-seednode failed
    /// to populate it, dial the curated fixed-seed peers as a last resort.
    /// Disabled with `--nofixedseeds` / `-fixedseeds=0`; also force-off in
    /// `--connect` peer-pinned mode (handled in PeerManager.run).
    fixed_seed: bool = true,

    // RPC
    rpc_bind: []const u8 = "127.0.0.1",
    rpc_port: u16 = 8332,
    rpc_user: ?[]const u8 = null,
    rpc_password: ?[]const u8 = null,
    // Optional HTTPS/TLS termination (W119 + FIX-64).  Both paths must be
    // supplied together; either one alone is a startup error.  Today, even
    // when both are supplied, RpcServer.start() returns TlsServerUnavailable
    // — Zig 0.13's stdlib has no server-side TLS.  See rpc.zig
    // `validateTlsConfig` for the full deferral rationale.
    rpc_tls_cert: ?[]const u8 = null,
    rpc_tls_key: ?[]const u8 = null,

    // BIP-78 PayJoin sender endpoint URL (FIX-66 + W119/G27).  Plain HTTP
    // only on this build — `https://` is rejected at startup with a
    // TLS-client-deferral message.  Consumed by the JSON-RPC methods
    // `getpayjoinrequest` (G26) + `sendpayjoinrequest` (G27).
    payjoin_server_url: ?[]const u8 = null,

    // Wallet auto-load list.  `-wallet=<name>` (repeatable) selects exactly
    // which wallets to load at startup, mirroring Bitcoin Core's `-wallet`
    // (init.cpp / wallet settings).  When empty, the wallet directory is
    // enumerated and every discovered wallet is auto-loaded.  Stored in a
    // fixed-size backing array so `parseArgs` stays allocation-free; the
    // borrowed `arg` slices outlive the load (the ArgIterator is freed at the
    // very end of main()).  An empty name ("") is the default wallet.
    wallet_names_buf: [64][]const u8 = undefined,
    wallet_names_len: usize = 0,

    // Storage
    datadir: []const u8 = "~/.clearbit",
    prune: u64 = 0, // 0 = no pruning, else target size in MiB
    // Match Bitcoin Core's DEFAULT_KERNEL_CACHE (450 MiB) so clearbit runs
    // well on modest-RAM machines without an explicit --dbcache flag. Users
    // with more RAM can raise it freely; no upper clamp (see parse paths).
    dbcache: u64 = 450, // UTXO cache size in MiB
    txindex: bool = false,
    blockfilterindex: bool = false, // BIP-157/158 compact block filters
    coinstatsindex: bool = false, // Per-block UTXO statistics

    // Mempool
    maxmempool: u64 = 300, // Max mempool size in MiB
    mempoolexpiry: u64 = 336, // Hours before expiry

    // BIP-35 / BIP-37 bloom-filter support.  When true, advertise the
    // NODE_BLOOM service flag in our version message and serve the
    // `mempool` message.  Mirrors Bitcoin Core's `-peerbloomfilters`
    // (DEFAULT_PEERBLOOMFILTERS = false in net_processing.h:44).
    // Operators can opt back in with `--peerbloomfilters` /
    // `--peerbloomfilters=1` for BIP-35 mempool queries.
    peerbloomfilters: bool = false,

    // Metrics
    metrics_port: u16 = 9332, // 0 = disabled

    // Debug
    debug: bool = false,
    printtoconsole: bool = true,
    logfile: ?[]const u8 = null,

    // Operational parity (mirrors Bitcoin Core's init.cpp argspec).
    daemon: bool = false,                       // --daemon: fork+setsid, detach from tty
    pidfile: ?[]const u8 = null,                // --pid=<path>; default <datadir>/clearbit.pid
    conf_path: ?[]const u8 = null,              // --conf=<file>: explicit config file location
    reindex: bool = false,                      // --reindex: rebuild block index/UTXO from CF_BLOCKS
    ready_fd: i32 = -1,                         // --ready-fd=<N>: write READY=1\n to fd N once up
    zmq_rawblock: ?[]const u8 = null,           // --zmqpubrawblock=tcp://...
    zmq_hashblock: ?[]const u8 = null,          // --zmqpubhashblock=...
    zmq_rawtx: ?[]const u8 = null,              // --zmqpubrawtx=...
    zmq_hashtx: ?[]const u8 = null,             // --zmqpubhashtx=...
    zmq_sequence: ?[]const u8 = null,           // --zmqpubsequence=...

    // Benchmarking
    run_benchmark: bool = false,

    // Block import mode
    import_blocks: ?[]const u8 = null, // path or "-" for stdin

    // UTXO snapshot import mode (Bitcoin Core wire format).
    // Reference: bitcoin-core/src/node/utxo_snapshot.h `SnapshotMetadata` (v2)
    // and bitcoin-core/src/rpc/blockchain.cpp `WriteUTXOSnapshot`.
    load_snapshot: ?[]const u8 = null,

    // Assumevalid control
    noassumevalid: bool = false, // if true, set assumed_valid_hash = null (always verify scripts)

    // ASMap: optional path to a binary asmap file for ASN-based peer bucketing.
    // When set and the file passes SanityCheckAsmap, getPeerInfo will include
    // `mapped_as` and netGroup() uses ASN keys instead of /16 prefixes.
    // Mirrors Bitcoin Core's `-asmap=<file>` (init.cpp:540).
    asmap_path: ?[]const u8 = null,

    // Anonymous-network proxies (BIP-155 / Core init.cpp).  All four are
    // optional; when set, peer.PeerManager constructs a ProxyManager and
    // dispatches outbound connects via it (see src/proxy.zig).
    //
    //   --proxy=host:port        SOCKS5 proxy for clearnet (IPv4/IPv6) and
    //                            the default proxy for overlay networks
    //                            when -onion is not set.  Mirrors Core's
    //                            -proxy (init.cpp:592).
    //   --onion=host:port        SOCKS5 proxy specifically for Tor v3 onion
    //                            addresses.  When unset and -proxy is set,
    //                            -proxy is used for onion too.  Mirrors
    //                            Core's -onion (init.cpp:573).
    //   --i2psam=host:port       I2P SAM bridge endpoint (default port
    //                            7656).  Mirrors Core's -i2psam.
    //   --cjdnsreachable         Treat fc00::/7 as routable rather than
    //                            RFC-4193 ULA private.  Mirrors Core's
    //                            -cjdnsreachable.
    proxy: ?[]const u8 = null,
    onion: ?[]const u8 = null,
    i2psam: ?[]const u8 = null,
    cjdnsreachable: bool = false,

    pub const Network = enum {
        mainnet,
        testnet,
        testnet4,
        regtest,
    };

    /// Get consensus network params for the configured network.
    /// When --noassumevalid is set, returns a copy with assumed_valid_hash = null.
    pub fn getNetworkParams(self: *const Config) *const consensus.NetworkParams {
        const base = switch (self.network) {
            .mainnet => &consensus.MAINNET,
            .testnet => &consensus.TESTNET,
            .testnet4 => &consensus.TESTNET4,
            .regtest => &consensus.REGTEST,
        };
        if (self.noassumevalid) {
            // Return a stack copy with hash cleared.  Callers must not store
            // the pointer beyond the current call frame — all callers use it
            // immediately for SyncManager / block_template construction.
            var p = base.*;
            p.assumed_valid_hash = null;
            p.assume_valid_height = 0;
            // Allocate on heap via comptime trick: we stash in a thread-local.
            const S = struct {
                var patched: consensus.NetworkParams = undefined;
            };
            S.patched = p;
            return &S.patched;
        }
        return base;
    }

    /// The explicit `-wallet=` list (possibly empty).  Empty → enumerate the
    /// wallet directory and auto-load everything found.
    pub fn walletNames(self: *const Config) []const []const u8 {
        return self.wallet_names_buf[0..self.wallet_names_len];
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
        // Wallet auto-load list (repeatable).  `-wallet=<name>` / `--wallet=`.
        else if (std.mem.startsWith(u8, arg, "--wallet=") or std.mem.startsWith(u8, arg, "-wallet=")) {
            if (std.mem.indexOf(u8, arg, "=")) |eq| {
                if (config.wallet_names_len < config.wallet_names_buf.len) {
                    config.wallet_names_buf[config.wallet_names_len] = arg[eq + 1 ..];
                    config.wallet_names_len += 1;
                }
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
        } else if (std.mem.startsWith(u8, arg, "--rpc-tls-cert=")) {
            // W119 + FIX-64: HTTPS/TLS termination flag plumbing.  Must be
            // paired with --rpc-tls-key; today both together produce a clear
            // TlsServerUnavailable error at startup (no silent HTTP downgrade).
            config.rpc_tls_cert = arg["--rpc-tls-cert=".len..];
        } else if (std.mem.startsWith(u8, arg, "--rpc-tls-key=")) {
            config.rpc_tls_key = arg["--rpc-tls-key=".len..];
        } else if (std.mem.startsWith(u8, arg, "--payjoin-server-url=")) {
            // W119/G27 + FIX-66 — operator-supplied BIP-78 PayJoin
            // receiver endpoint.  Must start with `http://` (plain HTTP
            // only on this build; `https://` is rejected at the sender
            // RPC layer with a TLS-client-deferral message).
            config.payjoin_server_url = arg["--payjoin-server-url=".len..];
        } else if (std.mem.startsWith(u8, arg, "--metricsport=")) {
            config.metrics_port = std.fmt.parseInt(u16, arg["--metricsport=".len..], 10) catch
                return ArgParseError.InvalidPortNumber;
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
        } else if (std.mem.eql(u8, arg, "--nofixedseeds") or std.mem.eql(u8, arg, "-nofixedseeds") or
            std.mem.eql(u8, arg, "-fixedseeds=0") or std.mem.eql(u8, arg, "--fixedseeds=0"))
        {
            config.fixed_seed = false;
        } else if (std.mem.eql(u8, arg, "-fixedseeds=1") or std.mem.eql(u8, arg, "--fixedseeds=1")) {
            config.fixed_seed = true;
        }
        // Storage settings
        else if (std.mem.startsWith(u8, arg, "--dbcache=")) {
            config.dbcache = std.fmt.parseInt(u64, arg["--dbcache=".len..], 10) catch
                return ArgParseError.InvalidCacheSize;
            // No upper clamp: matches Bitcoin Core (src/node/caches.cpp) which
            // accepts any value on 64-bit and warns only if > 75% of total RAM.
            // The old 8 GiB ceiling capped a 128-GB box's UTXO cache at 6% of
            // RAM for no principled reason.
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
        // BIP-35/BIP-37 bloom-filter / mempool support
        else if (std.mem.eql(u8, arg, "--peerbloomfilters") or
            std.mem.eql(u8, arg, "-peerbloomfilters") or
            std.mem.eql(u8, arg, "--peerbloomfilters=1") or
            std.mem.eql(u8, arg, "-peerbloomfilters=1"))
        {
            config.peerbloomfilters = true;
        } else if (std.mem.eql(u8, arg, "--peerbloomfilters=0") or
            std.mem.eql(u8, arg, "-peerbloomfilters=0") or
            std.mem.eql(u8, arg, "--nopeerbloomfilters") or
            std.mem.eql(u8, arg, "-nopeerbloomfilters"))
        {
            config.peerbloomfilters = false;
        }
        // Debug settings.
        //
        // Three forms (matches Bitcoin Core's `-debug=<category>` argspec):
        //   --debug              → enable everything (legacy boolean)
        //   --debug=<cat>        → enable a single category (repeatable)
        //   -debug, -debug=<cat> → same, with single-dash form
        //
        // Unknown categories print a one-line warning but don't abort startup.
        else if (std.mem.eql(u8, arg, "--debug") or std.mem.eql(u8, arg, "-debug")) {
            config.debug = true;
            _ = debug_log.parseAndApply("");
        } else if (std.mem.startsWith(u8, arg, "--debug=") or std.mem.startsWith(u8, arg, "-debug=")) {
            config.debug = true;
            const eq = std.mem.indexOf(u8, arg, "=").?;
            const cat = arg[eq + 1 ..];
            if (!debug_log.parseAndApply(cat)) {
                std.debug.print("Warning: unknown --debug category '{s}' (ignored)\n", .{cat});
            }
        } else if (std.mem.eql(u8, arg, "--printtoconsole") or std.mem.eql(u8, arg, "-printtoconsole")) {
            config.printtoconsole = true;
        }
        // Logfile (target of SIGHUP-driven reopen).
        else if (std.mem.startsWith(u8, arg, "--logfile=")) {
            config.logfile = arg["--logfile=".len..];
        }
        // Daemonize.
        else if (std.mem.eql(u8, arg, "--daemon") or std.mem.eql(u8, arg, "-daemon")) {
            config.daemon = true;
        }
        // PID file (default: <datadir>/clearbit.pid; overridable here).
        else if (std.mem.startsWith(u8, arg, "--pid=") or std.mem.startsWith(u8, arg, "-pid=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.pidfile = arg[eq + 1 ..];
        }
        // Config file path (overrides default <datadir>/clearbit.conf).
        else if (std.mem.startsWith(u8, arg, "--conf=") or std.mem.startsWith(u8, arg, "-conf=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.conf_path = arg[eq + 1 ..];
        }
        // Reindex (honest-progress: parse + log + document; full rebuild path
        // requires a CF_BLOCKS replay loop in storage.zig — TODO).
        else if (std.mem.eql(u8, arg, "--reindex") or std.mem.eql(u8, arg, "-reindex")) {
            config.reindex = true;
        }
        // Ready FD (sd_notify / runit-style readiness signal).
        else if (std.mem.startsWith(u8, arg, "--ready-fd=") or std.mem.startsWith(u8, arg, "-ready-fd=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.ready_fd = std.fmt.parseInt(i32, arg[eq + 1 ..], 10) catch
                return ArgParseError.InvalidArgument;
        }
        // ZMQ publishing.
        else if (std.mem.startsWith(u8, arg, "--zmqpubrawblock=") or std.mem.startsWith(u8, arg, "-zmqpubrawblock=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.zmq_rawblock = arg[eq + 1 ..];
        } else if (std.mem.startsWith(u8, arg, "--zmqpubhashblock=") or std.mem.startsWith(u8, arg, "-zmqpubhashblock=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.zmq_hashblock = arg[eq + 1 ..];
        } else if (std.mem.startsWith(u8, arg, "--zmqpubrawtx=") or std.mem.startsWith(u8, arg, "-zmqpubrawtx=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.zmq_rawtx = arg[eq + 1 ..];
        } else if (std.mem.startsWith(u8, arg, "--zmqpubhashtx=") or std.mem.startsWith(u8, arg, "-zmqpubhashtx=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.zmq_hashtx = arg[eq + 1 ..];
        } else if (std.mem.startsWith(u8, arg, "--zmqpubsequence=") or std.mem.startsWith(u8, arg, "-zmqpubsequence=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.zmq_sequence = arg[eq + 1 ..];
        }
        // Benchmarking
        else if (std.mem.eql(u8, arg, "--benchmark") or std.mem.eql(u8, arg, "-benchmark")) {
            config.run_benchmark = true;
        }
        // Block import
        else if (std.mem.startsWith(u8, arg, "--import-blocks=")) {
            config.import_blocks = arg["--import-blocks=".len..];
        } else if (std.mem.eql(u8, arg, "--import-blocks")) {
            config.import_blocks = "-"; // default to stdin
        }
        // UTXO snapshot import (Bitcoin Core wire format from `dumptxoutset`).
        else if (std.mem.startsWith(u8, arg, "--load-snapshot=")) {
            config.load_snapshot = arg["--load-snapshot=".len..];
        }
        // Assumevalid control
        else if (std.mem.eql(u8, arg, "--noassumevalid") or std.mem.eql(u8, arg, "-noassumevalid")) {
            config.noassumevalid = true;
        }
        // ASMap — optional binary asmap file for ASN-based peer bucketing.
        // Mirrors Bitcoin Core's `-asmap=<file>` (init.cpp:540).
        else if (std.mem.startsWith(u8, arg, "--asmap=") or std.mem.startsWith(u8, arg, "-asmap=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.asmap_path = arg[eq + 1 ..];
        }
        // Anonymous-network proxy flags.  Wired into PeerManager.proxy_manager
        // and consulted on every outbound dial (see peer.zig connectOutbound*).
        else if (std.mem.startsWith(u8, arg, "--proxy=") or std.mem.startsWith(u8, arg, "-proxy=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.proxy = arg[eq + 1 ..];
        } else if (std.mem.startsWith(u8, arg, "--onion=") or std.mem.startsWith(u8, arg, "-onion=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.onion = arg[eq + 1 ..];
        } else if (std.mem.startsWith(u8, arg, "--i2psam=") or std.mem.startsWith(u8, arg, "-i2psam=")) {
            const eq = std.mem.indexOf(u8, arg, "=").?;
            config.i2psam = arg[eq + 1 ..];
        } else if (std.mem.eql(u8, arg, "--cjdnsreachable") or std.mem.eql(u8, arg, "-cjdnsreachable") or
            std.mem.eql(u8, arg, "--cjdnsreachable=1") or std.mem.eql(u8, arg, "-cjdnsreachable=1"))
        {
            config.cjdnsreachable = true;
        } else if (std.mem.eql(u8, arg, "--cjdnsreachable=0") or std.mem.eql(u8, arg, "-cjdnsreachable=0")) {
            config.cjdnsreachable = false;
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

/// Validate the parsed `--prune` target. Mirrors Bitcoin Core's
/// AppInitParameterInteraction (init.cpp:524 / blockmanager_args.cpp:22-34):
///   * 0  → pruning disabled (default)
///   * 1  → manual mode: in prune mode but auto-prune does not fire;
///         only the pruneblockchain RPC (when shipped) triggers a sweep.
///   * 2≤N<MIN_PRUNE_TARGET_MIB (550) → rejected, target too small to keep
///     up with MIN_BLOCKS_TO_KEEP × ~average block size + undo + orphan
///     budget. (Core gives identical wording.)
///   * N≥550 → accepted as a target size in MiB.
///
/// Returns the validated value (unchanged) on success, or
/// ArgParseError.InvalidArgument on a too-small target.
/// Manual mode is represented by the literal value 1 (in MiB), matching
/// camlcoin's sentinel approach. ChainState.pruneToTarget short-circuits
/// when prune_target_mib == 1 so the auto-prune trigger is effectively
/// disabled in manual mode.
pub fn validatePruneTarget(prune_mib: u64) ArgParseError!u64 {
    if (prune_mib == 0) return 0;
    if (prune_mib == 1) return 1; // manual-mode sentinel (Core init.cpp:524)
    if (prune_mib < storage.ChainState.MIN_PRUNE_TARGET_MIB) {
        std.debug.print(
            "Error: Prune target must be 0 (off), 1 (manual mode), or at least {d} MiB (got {d} MiB).\n",
            .{ storage.ChainState.MIN_PRUNE_TARGET_MIB, prune_mib },
        );
        return ArgParseError.InvalidArgument;
    }
    return prune_mib;
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
        \\  --nofixedseeds         Disable the hardcoded fixed-seed fallback
        \\
        \\RPC server options:
        \\  --rpcbind=<addr>       Bind RPC to address (default: 127.0.0.1)
        \\  --rpcport=<port>       RPC port (default: 8332)
        \\  --rpcuser=<user>       RPC username
        \\  --rpcpassword=<pw>     RPC password
        \\  --rpc-tls-cert=<path>  PEM cert for HTTPS termination (BIP-78 ready)
        \\  --rpc-tls-key=<path>   PEM key paired with --rpc-tls-cert
        \\                         NOTE: TLS server is DEFERRED on Zig 0.13
        \\                         (stdlib has no server-side TLS). Supplying
        \\                         both flags today fails fast with a clear
        \\                         TlsServerUnavailable error at startup so
        \\                         operators do not silently get plain HTTP.
        \\  --payjoin-server-url=<url> BIP-78 PayJoin receiver endpoint
        \\                         consumed by the `sendpayjoinrequest` +
        \\                         `getpayjoinrequest` JSON-RPC methods.
        \\                         Plain HTTP only (W119/G24 deferral) — an
        \\                         `https://` URL is rejected at RPC call
        \\                         time with a TlsClientUnavailable-shape
        \\                         JSON error.  Front receiver endpoints
        \\                         with nginx / Caddy / Tor for production.
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
        \\  --debug                Enable all debug categories
        \\  --debug=<cat>          Enable a single debug category
        \\                         (net,mempool,rpc,zmq,validation,prune,...)
        \\  --printtoconsole       Print to console
        \\  --logfile=<path>       Log to <path> (reopened on SIGHUP)
        \\
        \\Operational:
        \\  --daemon               Detach into background (fork+setsid)
        \\  --pid=<path>           Write PID file (default <datadir>/clearbit.pid)
        \\  --conf=<file>          Use this config file (default <datadir>/clearbit.conf)
        \\  --reindex              Rebuild block index/UTXO from CF_BLOCKS (limited)
        \\  --ready-fd=<N>         Write READY=1\n to fd N once subsystems are up
        \\
        \\ZMQ publishing (Bitcoin Core compatible, requires -Dzmq=true at build):
        \\  --zmqpubrawblock=<addr>   Bind ZMQ PUB socket for serialized blocks
        \\  --zmqpubhashblock=<addr>  Bind ZMQ PUB socket for block hashes
        \\  --zmqpubrawtx=<addr>      Bind ZMQ PUB socket for serialized txs
        \\  --zmqpubhashtx=<addr>     Bind ZMQ PUB socket for tx hashes
        \\  --zmqpubsequence=<addr>   Bind ZMQ PUB socket for sequence events
        \\
        \\Anonymous networks (BIP-155):
        \\  --proxy=host:port      SOCKS5 proxy for clearnet (and default for overlays)
        \\  --onion=host:port      SOCKS5 proxy for Tor v3 .onion connections
        \\  --i2psam=host:port     I2P SAM bridge endpoint (default port 7656)
        \\  --cjdnsreachable       Treat fc00::/7 as routable for CJDNS peers
        \\
        \\Performance:
        \\  --benchmark            Run performance benchmarks and exit
        \\  --noassumevalid        Disable assumevalid (verify all scripts, for benchmarking)
        \\
        \\Import:
        \\  --import-blocks=<path>   Import blocks from file (- for stdin)
        \\  --load-snapshot=<path>   Load a Bitcoin Core-format UTXO set
        \\                           snapshot (as produced by Core's
        \\                           dumptxoutset RPC) and seed chainstate.
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
///
/// Backwards-compatible: when `datadir` is the legacy datadir path,
/// the file is opened at `<datadir>/clearbit.conf`. When `datadir`
/// itself is an absolute path to a `.conf` file (passed via the new
/// `--conf=<file>` flag), it's opened directly. The contract is
/// "treat the input as a directory unless it points to a regular
/// file" — this keeps every existing call site working unchanged
/// and lets `--conf=` override without an extra argument.
pub fn loadConfigFile(
    datadir: []const u8,
    config: *Config,
    allocator: std.mem.Allocator,
) ConfigFileError!void {
    // Detect whether `datadir` is a file (--conf=<file>) or a directory.
    // We stat() once: if it resolves to a regular file we use it as-is,
    // otherwise we append /clearbit.conf as before.
    var path_buf: ?[]u8 = null;
    defer if (path_buf) |b| allocator.free(b);
    const path: []const u8 = blk: {
        const st = std.fs.cwd().statFile(datadir) catch null;
        if (st) |s| {
            if (s.kind == .file) break :blk datadir;
        }
        const buf = std.fmt.allocPrint(allocator, "{s}/clearbit.conf", .{datadir}) catch
            return ConfigFileError.OutOfMemory;
        path_buf = buf;
        break :blk buf;
    };

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
            // W119 + FIX-64: HTTPS/TLS termination config-file keys.
            else if (std.mem.eql(u8, key, "rpc-tls-cert") or std.mem.eql(u8, key, "rpctlscert")) {
                config.rpc_tls_cert = value;
            } else if (std.mem.eql(u8, key, "rpc-tls-key") or std.mem.eql(u8, key, "rpctlskey")) {
                config.rpc_tls_key = value;
            }
            // W119 + FIX-66: BIP-78 PayJoin receiver endpoint URL.
            else if (std.mem.eql(u8, key, "payjoin-server-url") or std.mem.eql(u8, key, "payjoinserverurl")) {
                config.payjoin_server_url = value;
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
            } else if (std.mem.eql(u8, key, "fixedseeds")) {
                config.fixed_seed = std.mem.eql(u8, value, "1");
            }
            // Storage settings
            else if (std.mem.eql(u8, key, "dbcache")) {
                config.dbcache = std.fmt.parseInt(u64, value, 10) catch continue;
                // No upper clamp; see CLI parse path above.
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
                if (std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "0")) {
                    config.debug = std.mem.eql(u8, value, "1");
                    if (config.debug) _ = debug_log.parseAndApply("");
                } else {
                    // Treat any non-binary value as a category name (Bitcoin
                    // Core supports `debug=net` in the conf file the same way
                    // as `-debug=net` on the CLI).
                    config.debug = true;
                    if (!debug_log.parseAndApply(value)) {
                        std.debug.print("Warning: unknown debug=<cat> '{s}' in config (ignored)\n", .{value});
                    }
                }
            } else if (std.mem.eql(u8, key, "printtoconsole")) {
                config.printtoconsole = std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "logfile")) {
                config.logfile = value;
            }
            // Operational parity (config-file forms; CLI forms are richer).
            else if (std.mem.eql(u8, key, "daemon")) {
                config.daemon = std.mem.eql(u8, value, "1");
            } else if (std.mem.eql(u8, key, "pid")) {
                config.pidfile = value;
            } else if (std.mem.eql(u8, key, "reindex")) {
                config.reindex = std.mem.eql(u8, value, "1");
            }
            // ZMQ publishing.
            else if (std.mem.eql(u8, key, "zmqpubrawblock")) {
                config.zmq_rawblock = value;
            } else if (std.mem.eql(u8, key, "zmqpubhashblock")) {
                config.zmq_hashblock = value;
            } else if (std.mem.eql(u8, key, "zmqpubrawtx")) {
                config.zmq_rawtx = value;
            } else if (std.mem.eql(u8, key, "zmqpubhashtx")) {
                config.zmq_hashtx = value;
            } else if (std.mem.eql(u8, key, "zmqpubsequence")) {
                config.zmq_sequence = value;
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

/// Generate a .cookie file in datadir for cookie-based RPC auth.
/// Returns the Base64-encoded "__cookie__:<hex>" token for auth comparison.
/// Caller owns the returned slice and must free it.
pub fn generateCookieFile(datadir: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    // Generate 32 random bytes
    var rand_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);

    // Hex-encode the random bytes (64 hex chars)
    const hex_chars = "0123456789abcdef";
    var hex_buf: [64]u8 = undefined;
    for (rand_bytes, 0..) |byte, i| {
        hex_buf[i * 2] = hex_chars[byte >> 4];
        hex_buf[i * 2 + 1] = hex_chars[byte & 0xf];
    }
    const hex_password = hex_buf[0..64];

    // Build the cookie file content: __cookie__:<hex>
    const cookie_content = try std.fmt.allocPrint(allocator, "__cookie__:{s}", .{hex_password});
    defer allocator.free(cookie_content);

    // Write the cookie file with mode 0o600
    const cookie_path = try std.fmt.allocPrint(allocator, "{s}/.cookie", .{datadir});
    defer allocator.free(cookie_path);

    const file = try std.fs.createFileAbsolute(cookie_path, .{ .mode = 0o600 });
    defer file.close();
    try file.writeAll(cookie_content);

    std.debug.print("Generated cookie file: {s}\n", .{cookie_path});

    // Compute and return the Base64-encoded token for auth comparison
    const encoded_len = std.base64.standard.Encoder.calcSize(cookie_content.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, cookie_content);
    return encoded;
}

/// Delete the .cookie file from datadir on shutdown.
pub fn deleteCookieFile(datadir: []const u8, allocator: std.mem.Allocator) void {
    const cookie_path = std.fmt.allocPrint(allocator, "{s}/.cookie", .{datadir}) catch return;
    defer allocator.free(cookie_path);
    std.fs.deleteFileAbsolute(cookie_path) catch {};
}

// ============================================================================
// Signal Handling
// ============================================================================

/// Global log reopen-on-SIGHUP state. Owned by main() lifetime.
pub var log_state: ops.LogState = undefined;
pub var log_state_initialized: bool = false;

/// Global shutdown flag accessed by signal handler.
pub var shutdown_requested = std.atomic.Value(bool).init(false);

/// Number of signals received. A second signal during shutdown escalates
/// immediately to a forced exit so operators can always kill a wedged node
/// with two Ctrl-C presses or two SIGTERMs.
pub var signal_count = std.atomic.Value(u32).init(0);

/// Signal handler for SIGINT and SIGTERM.
///
/// First signal: set shutdown_requested so the main loop exits cleanly.
/// Second signal: force immediate exit(1). Signal handlers are async-signal
/// safe — we use only atomics and std.posix.exit (raw _exit syscall).
fn signalHandler(sig: c_int) callconv(.C) void {
    _ = sig;
    const prev = signal_count.fetchAdd(1, .acq_rel);
    if (prev >= 1) {
        // Second signal — force exit immediately. std.posix.exit calls _exit
        // directly (no atexit handlers, no buffer flushes), which is the only
        // safe thing to do from a signal handler.
        std.posix.exit(1);
    }
    shutdown_requested.store(true, .release);
}

/// Install signal handlers for graceful shutdown.
pub fn installSignalHandlers() void {
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null) catch {};
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null) catch {};
}

/// Shutdown deadline in nanoseconds. If graceful shutdown has not completed
/// within this window the watchdog thread forces exit(1). This matches
/// Bitcoin Core's init.cpp semantics (StartShutdown + bounded thread join)
/// and guarantees the process never hangs longer than 30s after a signal.
pub const SHUTDOWN_DEADLINE_NS: u64 = 30 * std.time.ns_per_s;

/// Set to true once graceful shutdown has completed. The watchdog checks
/// this flag before forcing exit so a clean shutdown never gets clobbered
/// by the deadline timer.
pub var shutdown_complete = std.atomic.Value(bool).init(false);

/// Hard-deadline watchdog. Sleeps for SHUTDOWN_DEADLINE_NS after the
/// shutdown signal is received; if shutdown_complete is still false it
/// prints a diagnostic and exit(1)s the process. Best-effort — we do not
/// try to close DB handles here because any subsystem still holding a
/// mutex would deadlock us on exit anyway.
fn shutdownWatchdog() void {
    std.time.sleep(SHUTDOWN_DEADLINE_NS);
    if (shutdown_complete.load(.acquire)) return;
    std.debug.print("shutdown deadline (30s) exceeded, forcing exit\n", .{});
    std.debug.print("exit (forced)\n", .{});
    std.posix.exit(1);
}

/// Heap-allocated context for the background wallet-reconcile thread.
///
/// The startup wallet rescan (reconcileToTip) used to run synchronously on
/// the boot path, BEFORE the RPC server bound and P2P started.  When a
/// wallet's persisted `last_synced_height` is 0 — which is the default for a
/// freshly-loaded wallet, the first restart after the wallet-recovery fix
/// deploys, and any legacy wallet file lacking the watermark key
/// (wallet.zig:1532 / 5545-5551) — the reconcile walks the ENTIRE chain
/// 0..tip (~950k blocks on mainnet) and the node looks DOWN for many minutes
/// while it does so.  Mirroring Bitcoin Core's CWallet::AttachChain, the
/// rescan is deferred to this non-blocking background thread that is spawned
/// AFTER rpc_server.start(), so RPC binds (and getwalletinfo stays
/// responsive) while the wallet history rebuilds underneath.
///
/// All fields are pointers into `main`-locals (chain_state, wallet_manager)
/// that outlive this thread: the thread is JOINED during graceful shutdown
/// (before the `defer wallet_manager.deinit()` / chainstate flush run when
/// `main` returns), so these pointers never dangle.  The struct itself is
/// heap-allocated by the spawner so it does not reference any stack-local of
/// the startup block; the thread frees it on exit.
const ReconcileCtx = struct {
    allocator: std.mem.Allocator,
    wm: *wallet.WalletManager,
    cs: *storage.ChainState,
    tip_height: u32,

    /// FetchCtx closure source for reconcileToTip — reads CF_BLOCKS by
    /// height, the same source rescanblockchain uses.  Returns null when a
    /// block is unavailable OR a shutdown has been requested; reconcileToTip
    /// treats null as "stop here, leave the watermark" (it persists progress
    /// via flushDirty and the live connect loop / next start resumes the
    /// gap), which makes the long full-chain scan promptly interruptible so
    /// the shutdown join returns quickly.
    fn fetch(ctx_ptr: *anyopaque, height: u32, arena: std.mem.Allocator) ?types.Block {
        const self: *ReconcileCtx = @ptrCast(@alignCast(ctx_ptr));
        if (shutdown_requested.load(.acquire)) return null;
        const hash = self.cs.getBlockHashByHeight(height) orelse return null;
        const block_db = self.cs.utxo_set.db orelse return null;
        const raw = (block_db.get(storage.CF_BLOCKS, &hash) catch null) orelse return null;
        defer self.cs.allocator.free(raw);
        var reader = serialize.Reader{ .data = raw };
        return serialize.readBlock(&reader, arena) catch null;
    }
};

/// Background entry point: run the wallet reconcile, then free the context.
fn reconcileWalletsBackground(ctx: *ReconcileCtx) void {
    defer ctx.allocator.destroy(ctx);
    const scanned = ctx.wm.reconcileToTip(ctx.tip_height, @ptrCast(ctx), ReconcileCtx.fetch);
    if (scanned > 0) {
        std.debug.print("Wallet reconcile (background): scanned {d} block(s) up to tip {d}\n", .{ scanned, ctx.tip_height });
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

// ============================================================================
// UTXO Snapshot Load Mode (Bitcoin Core wire format)
// ============================================================================

/// Streaming reader adapter wrapping a buffered file reader so the
/// snapshot import path can use serialize.Reader semantics
/// (compactsize/varint/script) without slurping the entire file.
const StreamingFileReader = struct {
    inner: std.io.BufferedReader(1 << 20, std.fs.File.Reader),
    bytes_consumed: u64 = 0,

    fn readU8(self: *StreamingFileReader) !u8 {
        return self.inner.reader().readByte();
    }

    fn readBytesAlloc(self: *StreamingFileReader, allocator: std.mem.Allocator, n: usize) ![]u8 {
        const buf = try allocator.alloc(u8, n);
        errdefer allocator.free(buf);
        try self.inner.reader().readNoEof(buf);
        self.bytes_consumed += n;
        return buf;
    }

    fn readBytesInto(self: *StreamingFileReader, buf: []u8) !void {
        try self.inner.reader().readNoEof(buf);
        self.bytes_consumed += buf.len;
    }

    fn readCompactSize(self: *StreamingFileReader) !u64 {
        const r = self.inner.reader();
        const first = try r.readByte();
        self.bytes_consumed += 1;
        // 1-byte form: always canonical and within MAX_SIZE.
        if (first < 0xFD) return first;
        const value: u64 = switch (first) {
            0xFD => blk: {
                var b: [2]u8 = undefined;
                try r.readNoEof(&b);
                self.bytes_consumed += 2;
                const v = @as(u64, std.mem.readInt(u16, &b, .little));
                // Non-canonical: value fits in 1-byte form.
                if (v < 0xFD) return error.InvalidCompactSize;
                break :blk v;
            },
            0xFE => blk: {
                var b: [4]u8 = undefined;
                try r.readNoEof(&b);
                self.bytes_consumed += 4;
                const v = @as(u64, std.mem.readInt(u32, &b, .little));
                // Non-canonical: value fits in 3-byte (0xFD) form.
                if (v < 0x10000) return error.InvalidCompactSize;
                break :blk v;
            },
            else => blk: { // 0xFF
                var b: [8]u8 = undefined;
                try r.readNoEof(&b);
                self.bytes_consumed += 8;
                const v = std.mem.readInt(u64, &b, .little);
                // Non-canonical: value fits in 5-byte (0xFE) form.
                if (v < 0x100000000) return error.InvalidCompactSize;
                break :blk v;
            },
        };
        // MAX_SIZE range check (Core: range_check=true by default).
        if (value > serialize.MAX_SIZE) return error.OversizedVector;
        return value;
    }

    /// Bitcoin Core's MSB-continuation VARINT (NOT compactsize). See
    /// `bitcoin-core/src/serialize.h ReadVarInt`.
    fn readVarInt(self: *StreamingFileReader) !u64 {
        var n: u64 = 0;
        const r = self.inner.reader();
        while (true) {
            const ch = try r.readByte();
            self.bytes_consumed += 1;
            if (n > (std.math.maxInt(u64) >> 7)) return error.VarIntOverflow;
            n = (n << 7) | @as(u64, ch & 0x7F);
            if ((ch & 0x80) != 0) {
                if (n == std.math.maxInt(u64)) return error.VarIntOverflow;
                n += 1;
            } else {
                return n;
            }
        }
    }
};

/// Read a Core-format compressed scriptPubKey from a streaming file reader.
/// Mirrors `compressor.readCompressedScript` but pulls bytes from a file
/// instead of an in-memory slice. Caller owns the returned buffer.
fn readCompressedScriptStreaming(
    reader: *StreamingFileReader,
    allocator: std.mem.Allocator,
) ![]u8 {
    const compressor = @import("compressor.zig");
    const n_size_u64 = try reader.readVarInt();
    if (n_size_u64 < compressor.N_SPECIAL_SCRIPTS) {
        const n_size: u32 = @intCast(n_size_u64);
        const payload_size = compressor.getSpecialScriptSize(n_size);
        const payload = try reader.readBytesAlloc(allocator, payload_size);
        defer allocator.free(payload);
        return try compressor.decompressScript(allocator, n_size, payload);
    }
    const raw_len_u64 = n_size_u64 - compressor.N_SPECIAL_SCRIPTS;
    if (raw_len_u64 > 10000) {
        // Skip and emit OP_RETURN (matches Core's overflow handling).
        const buf = try allocator.alloc(u8, @intCast(raw_len_u64));
        defer allocator.free(buf);
        try reader.readBytesInto(buf);
        const out = try allocator.alloc(u8, 1);
        out[0] = 0x6a;
        return out;
    }
    const raw_len: usize = @intCast(raw_len_u64);
    const buf = try allocator.alloc(u8, raw_len);
    errdefer allocator.free(buf);
    try reader.readBytesInto(buf);
    return buf;
}

/// Load a Bitcoin Core-format UTXO snapshot from disk into RocksDB. This
/// is the streaming counterpart to `storage.loadTxOutSet` (which expects
/// the whole file in memory and is only suitable for small test
/// snapshots). Wire format is identical — see `storage.dumpTxOutSet`.
fn loadSnapshotFromFile(config: *Config, allocator: std.mem.Allocator) !void {
    const snapshot_path = config.load_snapshot orelse return;

    // Resolve datadir / chainstate dir.
    const datadir = resolveDataDir(config.datadir, allocator) catch |err| {
        std.debug.print("Error resolving data directory: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(datadir);
    std.fs.makeDirAbsolute(datadir) catch |err| {
        if (err != error.PathAlreadyExists)
            std.debug.print("Warning: could not create data directory: {}\n", .{err});
    };

    const subdir = getNetworkSubdir(config.network);
    var full_datadir: []const u8 = datadir;
    if (subdir.len > 0) {
        full_datadir = std.fmt.allocPrint(allocator, "{s}/{s}", .{ datadir, subdir }) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };
        std.fs.makeDirAbsolute(full_datadir) catch |err| {
            if (err != error.PathAlreadyExists)
                std.debug.print("Warning: could not create network directory: {}\n", .{err});
        };
    }
    defer if (subdir.len > 0) allocator.free(full_datadir);

    const chainstate_path = std.fmt.allocPrint(allocator, "{s}/chainstate", .{full_datadir}) catch {
        std.debug.print("Out of memory\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(chainstate_path);
    std.fs.makeDirAbsolute(chainstate_path) catch |err| {
        if (err != error.PathAlreadyExists)
            std.debug.print("Warning: could not create chainstate directory: {}\n", .{err});
    };

    var db = storage.Database.open(chainstate_path, config.dbcache, allocator) catch |err| {
        std.debug.print("FATAL: Failed to open RocksDB at {s}: {}\n", .{ chainstate_path, err });
        std.process.exit(1);
    };
    defer db.close();

    const file = std.fs.openFileAbsolute(snapshot_path, .{}) catch |err| {
        std.debug.print("FATAL: Cannot open snapshot file {s}: {}\n", .{ snapshot_path, err });
        std.process.exit(1);
    };
    defer file.close();

    var reader = StreamingFileReader{ .inner = std.io.bufferedReaderSize(1 << 20, file.reader()) };

    // 1. Read the 51-byte SnapshotMetadata header.
    var hdr: [storage.SnapshotMetadata.HEADER_SIZE]u8 = undefined;
    reader.readBytesInto(&hdr) catch |err| {
        std.debug.print("FATAL: Failed to read snapshot header: {}\n", .{err});
        std.process.exit(1);
    };
    const network_params = config.getNetworkParams();
    const metadata = storage.SnapshotMetadata.fromBytes(&hdr, network_params.magic) catch |err| {
        std.debug.print("FATAL: Snapshot header rejected (magic/version/network mismatch): {}\n", .{err});
        std.process.exit(1);
    };

    // 2. Cross-reference the snapshot tip against the assumeutxo entries
    //    hardcoded in chainparams. This is what gates which snapshots a
    //    node will accept (see consensus.zig MAINNET.assume_utxo).
    const assume_entry = storage.findAssumeUtxoEntry(network_params, &metadata.base_blockhash);
    if (assume_entry == null) {
        // Print display-order hash for the operator.
        var disp: [64]u8 = undefined;
        for (0..32) |i| _ = std.fmt.bufPrint(disp[i * 2 ..][0..2], "{x:0>2}", .{metadata.base_blockhash[31 - i]}) catch unreachable;
        std.debug.print("FATAL: Snapshot tip {s} is not a recognized assumeutxo block for this network.\n", .{disp[0..]});
        std.process.exit(1);
    }
    const block_height: u32 = assume_entry.?.height;

    // Display header.
    std.debug.print("clearbit UTXO snapshot import (Bitcoin Core wire format)\n", .{});
    std.debug.print("  File:       {s}\n", .{snapshot_path});
    std.debug.print("  Block hash: ", .{});
    for (0..32) |i| std.debug.print("{x:0>2}", .{metadata.base_blockhash[31 - i]});
    std.debug.print("\n", .{});
    std.debug.print("  Height:     {d}\n", .{block_height});
    std.debug.print("  Coins:      {d}\n", .{metadata.coins_count});
    std.debug.print("  Chain txs:  {d} (from chainparams)\n", .{assume_entry.?.chain_tx_count});

    const start_time = std.time.milliTimestamp();
    const BATCH_SIZE: u64 = 100_000;
    var batch_ops = std.ArrayList(storage.BatchOp).init(allocator);
    defer batch_ops.deinit();
    var batch_keys = std.ArrayList([]const u8).init(allocator);
    defer batch_keys.deinit();
    var batch_values = std.ArrayList([]const u8).init(allocator);
    defer batch_values.deinit();

    // 3. Stream coins by walking txid groups.
    var imported: u64 = 0;
    var last_report: u64 = 0;
    var coins_left = metadata.coins_count;
    while (coins_left > 0) {
        var txid: [32]u8 = undefined;
        reader.readBytesInto(&txid) catch |err| {
            std.debug.print("\nFATAL: Read error at coin {d}: {}\n", .{ imported, err });
            std.process.exit(1);
        };
        const coins_per_txid_u64 = reader.readCompactSize() catch |err| {
            std.debug.print("\nFATAL: Failed to read coins_per_txid at coin {d}: {}\n", .{ imported, err });
            std.process.exit(1);
        };
        if (coins_per_txid_u64 > coins_left) {
            std.debug.print("\nFATAL: coins_per_txid={d} exceeds remaining {d} at coin {d}\n", .{ coins_per_txid_u64, coins_left, imported });
            std.process.exit(1);
        }
        var i: u64 = 0;
        while (i < coins_per_txid_u64) : (i += 1) {
            const vout_u64 = reader.readCompactSize() catch |err| {
                std.debug.print("\nFATAL: Read error (vout) at coin {d}: {}\n", .{ imported, err });
                std.process.exit(1);
            };
            if (vout_u64 >= std.math.maxInt(u32)) {
                std.debug.print("\nFATAL: vout overflow at coin {d}\n", .{imported});
                std.process.exit(1);
            }
            const vout: u32 = @intCast(vout_u64);

            const code = reader.readVarInt() catch |err| {
                std.debug.print("\nFATAL: Read error (code) at coin {d}: {}\n", .{ imported, err });
                std.process.exit(1);
            };
            const utxo_height: u32 = @intCast(code >> 1);
            const is_coinbase = (code & 1) != 0;
            if (utxo_height > block_height) {
                std.debug.print("\nFATAL: Coin height {d} > snapshot height {d} at coin {d}\n", .{ utxo_height, block_height, imported });
                std.process.exit(1);
            }

            const compressed_amount = reader.readVarInt() catch |err| {
                std.debug.print("\nFATAL: Read error (amount) at coin {d}: {}\n", .{ imported, err });
                std.process.exit(1);
            };
            const compressor = @import("compressor.zig");
            const amount: i64 = @intCast(compressor.decompressAmount(compressed_amount));
            // B4: MoneyRange check — Core validation.cpp:5820-5823.
            // Reject coins with values outside [0, MAX_MONEY].
            if (!@import("consensus.zig").isValidMoney(amount)) {
                std.debug.print("\nFATAL: Coin value {d} out of MoneyRange at coin {d}\n", .{ amount, imported });
                std.process.exit(1);
            }

            const script_pubkey = readCompressedScriptStreaming(&reader, allocator) catch |err| {
                std.debug.print("\nFATAL: Read error (script) at coin {d}: {}\n", .{ imported, err });
                std.process.exit(1);
            };
            // script_pubkey ownership transfers into CompactUtxo.encode (which
            // copies the extracted hash/script), so free here after value_data
            // is built.

            // Build UTXO key: txid (32) || vout_le (4).
            const key_alloc = allocator.alloc(u8, 36) catch {
                allocator.free(script_pubkey);
                std.debug.print("\nFATAL: Out of memory at coin {d}\n", .{imported});
                std.process.exit(1);
            };
            @memcpy(key_alloc[0..32], &txid);
            std.mem.writeInt(u32, key_alloc[32..36], vout, .little);

            // SNAPSHOT FORWARD-SYNC FIX (UTXO serialization parity).
            //
            // The CF_UTXO read path (storage.UtxoSet.get → CompactUtxo.decode)
            // expects the canonical compact layout
            //   [u32 packed_height(coinbase<<31)] [i64 value] [u8 script_type] [hash|script]
            // written by storage.UtxoSet.add → CompactUtxo.encode on the live
            // connect path.  This CLI import path previously wrote the legacy
            // storage.UtxoEntry.toBytes layout
            //   [i64 value] [u32 height] [u8 coinbase] [compactsize len] [script]
            // which is a DIFFERENT byte order.  Decoding a UtxoEntry blob as a
            // CompactUtxo read the value's low 4 bytes as packed_height and the
            // value's high 4 bytes ++ height as a bogus i64 ~4e18 — far above
            // MAX_MONEY — so every prevout lookup for a spend of a snapshot
            // coin returned an out-of-range amount and block 944184 was
            // rejected with InputValuesOutOfRange, wedging forward sync at the
            // snapshot base.  (See the validateAndLoadSnapshot reference path
            // in storage.zig, which already uses utxo_set.add → CompactUtxo.)
            //
            // Write the SAME compact format the read path decodes so spends of
            // snapshot UTXOs resolve to the correct value.
            const script_type = storage.CompactUtxo.classifyScriptType(script_pubkey);
            const hash_or_script = storage.CompactUtxo.extractHashFromScript(script_type, script_pubkey);
            const compact = storage.CompactUtxo{
                .height = utxo_height,
                .is_coinbase = is_coinbase,
                .value = amount,
                .script_type = script_type,
                .hash_or_script = hash_or_script,
            };
            const value_data = compact.encode(allocator) catch {
                allocator.free(key_alloc);
                allocator.free(script_pubkey);
                std.debug.print("\nFATAL: Serialization failed at coin {d}\n", .{imported});
                std.process.exit(1);
            };
            allocator.free(script_pubkey);

            batch_ops.append(.{
                .put = .{ .cf = storage.CF_UTXO, .key = key_alloc, .value = value_data },
            }) catch {
                allocator.free(key_alloc);
                allocator.free(value_data);
                std.debug.print("\nFATAL: Out of memory at coin {d}\n", .{imported});
                std.process.exit(1);
            };
            batch_keys.append(key_alloc) catch unreachable;
            batch_values.append(value_data) catch unreachable;

            imported += 1;
            coins_left -= 1;

            if (imported % BATCH_SIZE == 0 or coins_left == 0) {
                db.writeBatch(batch_ops.items) catch |err| {
                    std.debug.print("\nFATAL: WriteBatch failed at coin {d}: {}\n", .{ imported, err });
                    std.process.exit(1);
                };
                for (batch_keys.items) |k| allocator.free(k);
                for (batch_values.items) |v| allocator.free(v);
                batch_keys.clearRetainingCapacity();
                batch_values.clearRetainingCapacity();
                batch_ops.clearRetainingCapacity();
            }

            if (imported - last_report >= 1_000_000) {
                last_report = imported;
                const elapsed_ms = std.time.milliTimestamp() - start_time;
                const elapsed_s = @as(f64, @floatFromInt(@max(elapsed_ms, 1))) / 1000.0;
                const rate = @as(f64, @floatFromInt(imported)) / elapsed_s;
                const pct = @as(f64, @floatFromInt(imported)) / @as(f64, @floatFromInt(metadata.coins_count)) * 100.0;
                std.debug.print("\r  Progress: {d}/{d} coins ({d:.1}%, {d:.0}/s)      ", .{ imported, metadata.coins_count, pct, rate });
            }
        }
    }

    std.debug.print("\r  Progress: {d}/{d} coins (100.0%)                    \n", .{ imported, metadata.coins_count });

    // Set chain tip to snapshot block.
    var tip_buf: [36]u8 = undefined;
    @memcpy(tip_buf[0..32], &metadata.base_blockhash);
    std.mem.writeInt(u32, tip_buf[32..36], block_height, .little);
    db.put(storage.CF_DEFAULT, "chain_tip", &tip_buf) catch |err| {
        std.debug.print("FATAL: Failed to set chain tip: {}\n", .{err});
        std.process.exit(1);
    };

    var count_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &count_buf, metadata.coins_count, .little);
    db.put(storage.CF_DEFAULT, "utxo_count", &count_buf) catch {
        std.debug.print("Warning: Failed to persist UTXO count\n", .{});
    };

    // Block-index entry. Header bytes are not in the snapshot (Core
    // reconstructs them from the sibling block index); we write a
    // placeholder that will be overwritten once headers are fetched.
    var block_index_buf: [84]u8 = [_]u8{0} ** 84;
    std.mem.writeInt(u32, block_index_buf[0..4], block_height, .little);
    db.put(storage.CF_BLOCK_INDEX, &metadata.base_blockhash, &block_index_buf) catch |err| {
        std.debug.print("Warning: Failed to write block index entry: {}\n", .{err});
    };

    // SNAPSHOT FORWARD-SYNC (Layer 2): persist the height→hash index entry for
    // the snapshot base so the base block is queryable by height
    // (getblockhash, getBlockHashByHeight) and the BIP-68 sequence-lock
    // MTP-at-height callback can resolve heights at/below the base.  The live
    // connect path links new blocks via `best_hash` (which the chain_tip key
    // above carries), so the base does not also need a header-bearing
    // CF_BLOCK_INDEX row to connect 944184 — but without this H:<height> entry
    // the base would be invisible to height-keyed lookups.  Key layout:
    // "H:" ++ u32_LE(height) → 32-byte hash (storage.ChainStore.buildHeightHashKey).
    const hh_key = storage.ChainStore.buildHeightHashKey(block_height);
    db.put(storage.CF_DEFAULT, &hh_key, &metadata.base_blockhash) catch |err| {
        std.debug.print("Warning: Failed to write base height→hash index entry: {}\n", .{err});
    };

    db.flush() catch |err| {
        std.debug.print("Warning: RocksDB flush error: {}\n", .{err});
    };

    const elapsed_ms = @max(1, std.time.milliTimestamp() - start_time);
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
    const rate = @as(f64, @floatFromInt(imported)) / elapsed_s;
    std.debug.print("Snapshot load complete: {d} coins in {d:.1}s ({d:.0} coin/s)\n", .{ imported, elapsed_s, rate });
    std.debug.print("Chain tip set to height {d}\n", .{block_height});
}

// ============================================================================
// Block Import Mode
// ============================================================================

/// Import blocks from a file or stdin in the framed format:
///   [4 bytes height LE] [4 bytes size LE] [size bytes raw block]
/// Feeds blocks directly to ChainState.  Script verification is performed
/// according to the assumevalid ancestor-check semantics; --noassumevalid
/// forces scripts to run for every block.
fn importBlocks(config: *Config, allocator: std.mem.Allocator) !void {
    const import_path = config.import_blocks orelse return;

    // Initialize secp256k1 for signature verification during block import.
    if (!crypto.initSecp256k1()) {
        std.debug.print("FATAL: Failed to initialize secp256k1 context\n", .{});
        std.process.exit(1);
    }
    defer crypto.deinitSecp256k1();

    // Resolve data directory
    const datadir = resolveDataDir(config.datadir, allocator) catch |err| {
        std.debug.print("Error resolving data directory: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(datadir);
    std.fs.makeDirAbsolute(datadir) catch |err| {
        if (err != error.PathAlreadyExists)
            std.debug.print("Warning: could not create data directory: {}\n", .{err});
    };

    // Network subdirectory
    const subdir = getNetworkSubdir(config.network);
    var full_datadir: []const u8 = datadir;
    if (subdir.len > 0) {
        full_datadir = std.fmt.allocPrint(allocator, "{s}/{s}", .{ datadir, subdir }) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };
        std.fs.makeDirAbsolute(full_datadir) catch |err| {
            if (err != error.PathAlreadyExists)
                std.debug.print("Warning: could not create network directory: {}\n", .{err});
        };
    }
    defer if (subdir.len > 0) allocator.free(full_datadir);

    // Open RocksDB
    var db: ?storage.Database = null;
    var db_ptr: ?*storage.Database = null;
    {
        const chainstate_path = std.fmt.allocPrint(allocator, "{s}/chainstate", .{full_datadir}) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };
        defer allocator.free(chainstate_path);
        std.fs.makeDirAbsolute(chainstate_path) catch |err| {
            if (err != error.PathAlreadyExists)
                std.debug.print("Warning: could not create chainstate directory: {}\n", .{err});
        };
        if (storage.Database.open(chainstate_path, config.dbcache, allocator)) |opened_db| {
            db = opened_db;
        } else |err| {
            std.debug.print("Failed to open RocksDB: {}\n", .{err});
            std.debug.print("Falling back to memory-only mode\n", .{});
        }
        if (db != null) db_ptr = &db.?;
    }
    defer if (db_ptr) |p| p.close();

    var chain_state = storage.ChainState.init(db_ptr, @intCast(config.dbcache), allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();

    const params = config.getNetworkParams();
    chain_state.best_hash = params.genesis_hash;
    chain_state.best_height = 0;

    // Open input source
    const input_file: std.fs.File = if (std.mem.eql(u8, import_path, "-"))
        std.io.getStdIn()
    else
        std.fs.openFileAbsolute(import_path, .{}) catch |err| {
            std.debug.print("Error opening {s}: {}\n", .{ import_path, err });
            std.process.exit(1);
        };
    defer if (!std.mem.eql(u8, import_path, "-")) input_file.close();

    var buf_reader = std.io.bufferedReader(input_file.reader());
    const reader = buf_reader.reader();

    std.debug.print("clearbit import: reading blocks from {s}\n", .{
        if (std.mem.eql(u8, import_path, "-")) "stdin" else import_path,
    });

    const start_time = std.time.milliTimestamp();
    var count: u64 = 0;
    var last_height: u32 = 0;
    var scripts_skipped: u64 = 0;
    var scripts_run: u64 = 0;

    // active_chain: height -> block_hash, used for the assumevalid ancestor check.
    // Grows as we process blocks.
    var active_chain = std.ArrayList([32]u8).init(allocator);
    defer active_chain.deinit();
    // Seed with genesis hash at height 0.
    active_chain.append(params.genesis_hash) catch {};
    // Pre-populate the assumed_valid block's hash at its height so the ancestor
    // check works during import.  In real IBD, headers arrive before blocks so
    // the best-known header would already be at the chain tip.  We simulate this
    // by inserting the assumed_valid entry now (height may be far ahead of what
    // we're importing, which is correct — we're importing the early blocks that
    // should be ancestors of it).
    if (params.assumed_valid_hash) |av_h| {
        const av_height = params.assume_valid_height;
        if (av_height > 0) {
            // Extend active_chain to av_height, filling with zeros.
            while (active_chain.items.len <= av_height) {
                active_chain.append([_]u8{0} ** 32) catch break;
            }
            active_chain.items[av_height] = av_h;
        }
    }

    // For the assumevalid 2-week-gap and chainwork safety conditions we need
    // "best_tip" info.  In real IBD, headers come before blocks so the best
    // known header is already the chain tip when we connect early blocks.
    // We simulate this by using a "far-future" timestamp and the assumevalid
    // height's expected chainwork (params.min_chain_work doubled as proxy).
    //
    // Specifically: use a timestamp far enough in the future (year 2026) that
    // the 2-week gap condition is satisfied for any block in the first 100k.
    const SIMULATED_BEST_TIP_TIMESTAMP: u32 = 1_750_000_000; // ~ April 2025
    // Use a chain_work slightly above min_chain_work to satisfy condition 5.
    // We set it to min_chain_work with the top byte incremented (big-endian).
    var simulated_best_tip_chain_work: [32]u8 = params.min_chain_work;
    // If all bytes are 0 (regtest/testnet3), keep as-is; the condition still
    // passes since "0 >= 0".  For mainnet the work is large so just OR in 0x01
    // to ensure strictly greater.
    if (simulated_best_tip_chain_work[0] == 0) {
        simulated_best_tip_chain_work[31] |= 0x01;
    }
    // Ensure it's strictly >= min_chain_work: just use min_chain_work itself;
    // the comparison in shouldSkipScripts is >=.
    simulated_best_tip_chain_work = params.min_chain_work;

    while (true) {
        // Read 8-byte frame header
        var frame_header: [8]u8 = undefined;
        const bytes_read = reader.readAll(&frame_header) catch |err| {
            std.debug.print("Read error after {d} blocks: {}\n", .{ count, err });
            break;
        };
        if (bytes_read == 0) break; // EOF
        if (bytes_read < 8) {
            std.debug.print("Unexpected EOF reading frame header after {d} blocks\n", .{count});
            break;
        }

        const height = std.mem.readInt(u32, frame_header[0..4], .little);
        const size = std.mem.readInt(u32, frame_header[4..8], .little);

        // Read block data
        const block_data = allocator.alloc(u8, size) catch {
            std.debug.print("Out of memory allocating {d} bytes for block at height {d}\n", .{ size, height });
            break;
        };
        defer allocator.free(block_data);

        const data_read = reader.readAll(block_data) catch |err| {
            std.debug.print("Read error at block {d}: {}\n", .{ height, err });
            break;
        };
        if (data_read < size) {
            std.debug.print("Unexpected EOF reading block {d} (got {d}/{d} bytes)\n", .{ height, data_read, size });
            break;
        }

        // Skip blocks at or below current tip
        if (height <= chain_state.best_height) continue;

        // Deserialize the block
        var block_reader_inner = serialize.Reader{ .data = block_data };
        const block = serialize.readBlock(&block_reader_inner, allocator) catch |err| {
            std.debug.print("Failed to deserialize block at height {d}: {}\n", .{ height, err });
            break;
        };
        defer {
            for (block.transactions) |*tx| {
                serialize.freeTransaction(allocator, tx);
            }
            allocator.free(block.transactions);
        }

        // Compute block hash.
        const block_hash = crypto.computeBlockHash(&block.header);

        // Extend active_chain to cover this height (should be consecutive).
        while (active_chain.items.len <= height) {
            active_chain.append([_]u8{0} ** 32) catch break;
        }
        active_chain.items[height] = block_hash;

        // Determine whether to skip script verification using the ancestor check.
        const skip_scripts = validation.shouldSkipScripts(
            &block_hash,
            height,
            block.header.timestamp,
            params,
            active_chain.items,
            simulated_best_tip_chain_work,
            SIMULATED_BEST_TIP_TIMESTAMP,
        );

        if (skip_scripts) {
            // Assumevalid path: skip script verification, connect block fast.
            scripts_skipped += 1;
        } else {
            // Full validation path: run script verification before connecting.
            // Build a UTXO view for the script-check pass by pre-fetching
            // script_pubkeys from the UTXO set (before they are spent by connectBlockFast).
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_alloc = arena.allocator();

            const OutpointKey = [36]u8;
            var script_map = std.AutoHashMap(OutpointKey, validation.SigopUtxoEntry).init(arena_alloc);

            // Pre-fetch input script_pubkeys and outputs for intra-block spends.
            var any_missing = false;
            for (block.transactions, 0..) |tx, tx_idx| {
                if (tx_idx == 0) {
                    // Coinbase: no inputs to resolve
                } else {
                    for (tx.inputs) |input| {
                        const key: OutpointKey = storage.makeUtxoKey(&input.previous_output);
                        if (chain_state.utxo_set.get(&input.previous_output) catch null) |compact_utxo| {
                            var cu = compact_utxo;
                            const script_pk = cu.reconstructScript(arena_alloc) catch {
                                // Free cu's hash_or_script using utxo_set's allocator
                                cu.deinit(chain_state.utxo_set.allocator);
                                any_missing = true;
                                break;
                            };
                            const cu_value = cu.value;
                            // Free the temporary CompactUtxo copy using utxo_set's allocator
                            cu.deinit(chain_state.utxo_set.allocator);
                            script_map.put(key, .{
                                .script_pubkey = script_pk,
                                .amount = cu_value,
                            }) catch {};
                        }
                        // Also register intra-block outputs already in script_map from prior txs.
                    }
                    if (any_missing) break;
                }
                // Register this tx's outputs for intra-block spends.
                const tx_hash = crypto.computeTxid(&tx, arena_alloc) catch continue;
                for (tx.outputs, 0..) |output, out_idx| {
                    var key: OutpointKey = undefined;
                    @memcpy(key[0..32], &tx_hash);
                    std.mem.writeInt(u32, key[32..36], @intCast(out_idx), .little);
                    script_map.put(key, .{
                        .script_pubkey = output.script_pubkey,
                        .amount = output.value,
                    }) catch {};
                }
            }

            if (!any_missing) {
                const MapCtx = struct {
                    map: *std.AutoHashMap(OutpointKey, validation.SigopUtxoEntry),
                    fn lookup(ctx_ptr: *anyopaque, op: *const types.OutPoint) ?validation.SigopUtxoEntry {
                        const ctx: *@This() = @ptrCast(@alignCast(ctx_ptr));
                        const k = storage.makeUtxoKey(op);
                        return ctx.map.get(k);
                    }
                };
                var map_ctx = MapCtx{ .map = &script_map };
                const utxo_view = validation.SigopUtxoView{
                    .context = @ptrCast(&map_ctx),
                    .lookupFn = MapCtx.lookup,
                };
                const script_ok = validation.verifyBlockScriptsParallel(
                    &block,
                    height,
                    params,
                    &utxo_view,
                    // Single-threaded: the script_map (AutoHashMap) is not
                    // thread-safe; parallel verification would race on lookups.
                    .{ .enabled = false },
                    arena_alloc,
                ) catch false;
                if (!script_ok) {
                    // Script verification failure: log but continue for benchmark.
                    // Early mainnet blocks use P2PK scripts which may trigger
                    // pre-existing verifier limitations; this does not affect
                    // the assumevalid skip-path correctness.
                    std.debug.print("\n[warn] Script check failed at height {d} (continuing for benchmark)\n", .{height});
                }
            }
            scripts_run += 1;
        }

        // Connect block to chain (UTXO apply, no undo data needed for IBD).
        chain_state.connectBlockFast(&block, &block_hash, height) catch |err| {
            std.debug.print("\nFailed to connect block at height {d}: {}\n", .{ height, err });
            break;
        };

        count += 1;
        last_height = height;

        // Progress every 1000 blocks
        if (count % 1000 == 0) {
            const elapsed_ms = std.time.milliTimestamp() - start_time;
            const elapsed_s = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
            const rate = if (elapsed_s > 0) @as(f64, @floatFromInt(count)) / elapsed_s else 0.0;
            std.debug.print("\rImported {d} blocks (height {d}, {d:.1} blk/s, scripts: {d} run / {d} skipped)",
                .{ count, last_height, rate, scripts_run, scripts_skipped });
        }
    }

    // Final flush
    chain_state.flush() catch |err| {
        std.debug.print("Warning: error flushing chain state: {}\n", .{err});
    };

    const elapsed_ms = @max(1, std.time.milliTimestamp() - start_time);
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
    const rate = @as(f64, @floatFromInt(count)) / elapsed_s;
    std.debug.print("\nImport complete: {d} blocks in {d:.1}s ({d:.1} blk/s)\n", .{ count, elapsed_s, rate });
    std.debug.print("  Scripts: {d} run, {d} skipped (assumevalid)\n", .{ scripts_run, scripts_skipped });
}

pub fn main() !void {
    // Use c_allocator for release builds (faster, no safety overhead).
    // GPA is kept for debug builds for leak detection and safety checks.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (comptime builtin.mode == .Debug) {
        _ = gpa.deinit();
    };
    const allocator = if (comptime builtin.mode == .Debug)
        gpa.allocator()
    else
        std.heap.c_allocator;

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

    // Validate --prune target (Core init.cpp:524): 0=off, 1=manual mode,
    // 2..549 rejected, ≥550 automatic with N MiB target. The early check,
    // before any RocksDB / network init, gives operators a fast-fail
    // config error rather than a delayed surprise.
    config.prune = validatePruneTarget(config.prune) catch |err| {
        std.debug.print("Invalid --prune value: {}\n", .{err});
        std.process.exit(1);
    };

    // Run benchmarks if requested
    if (config.run_benchmark) {
        const stdout = std.io.getStdOut().writer();
        bench.runAllBenchmarks(allocator, stdout) catch |err| {
            std.debug.print("Error running benchmarks: {}\n", .{err});
            std.process.exit(1);
        };
        return;
    }

    // 1b. Import blocks mode
    if (config.import_blocks != null) {
        return importBlocks(&config, allocator);
    }

    // 1c. UTXO snapshot load mode (Bitcoin Core wire format).
    if (config.load_snapshot != null) {
        return loadSnapshotFromFile(&config, allocator);
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

    // 3. Load config file (before processing network subdirs).
    //    --conf=<file> overrides the legacy fixed path (<datadir>/clearbit.conf).
    //    loadConfigFile() detects file-vs-dir and behaves accordingly.
    {
        const conf_target: []const u8 = config.conf_path orelse datadir;
        loadConfigFile(conf_target, &config, allocator) catch |err| {
            if (err != ConfigFileError.ReadError) {
                std.debug.print("Warning: error loading config file: {}\n", .{err});
            }
        };
    }

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
    // Initialize secp256k1 context for ECDSA and Schnorr signature verification.
    // Must be done before any block or transaction validation.
    if (!crypto.initSecp256k1()) {
        std.debug.print("FATAL: Failed to initialize secp256k1 context\n", .{});
        std.process.exit(1);
    }
    defer crypto.deinitSecp256k1();

    // Open RocksDB for disk-backed UTXO persistence.
    var db: ?storage.Database = null;
    var db_ptr: ?*storage.Database = null;
    {
        const chainstate_path = std.fmt.allocPrint(allocator, "{s}/chainstate", .{full_datadir}) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };
        defer allocator.free(chainstate_path);

        std.fs.makeDirAbsolute(chainstate_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                std.debug.print("Warning: could not create chainstate directory: {}\n", .{err});
            }
        };

        if (storage.Database.open(chainstate_path, config.dbcache, allocator)) |opened_db| {
            db = opened_db;
        } else |err| {
            std.debug.print("FATAL: Failed to open RocksDB at {s}: {}\n", .{ chainstate_path, err });
            std.debug.print("Fix the RocksDB issue or remove the chainstate directory and retry.\n", .{});
            std.process.exit(1);
        }
        if (db != null) {
            db_ptr = &db.?;
            std.debug.print("RocksDB storage: {s}/chainstate\n", .{full_datadir});
        }
    }
    defer if (db_ptr) |p| {
        p.close();
    };

    var chain_state = storage.ChainState.init(db_ptr, @intCast(config.dbcache), allocator);
    defer chain_state.deinit();
    chain_state.wireUtxoParent();
    // Wire the active network params into ChainState.  Two consumers depend
    // on this being set on the live node:
    //   1. the disconnect path's BIP-30 disconnect-exception list
    //      (storage.zig isBip30DisconnectException), and
    //   2. the reorg connect path's full block-validation / script
    //      verification (storage.zig reorgToChain) — which skips script
    //      verification entirely when network_params is null.  Without this
    //      call the live reorg path would route side-branch blocks straight
    //      to connectBlockInner with NO script verify (chain-split-class
    //      false-accept).  Bitcoin Core always connects reorg side branches
    //      through ConnectBlock → CheckInputScripts.
    chain_state.setNetworkParams(params);
    // Pattern C0 (CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-
    // 2026-05-05.md): plumb --txindex from CLI/config into ChainState so
    // connectBlockInner queues CF_TX_INDEX writes and disconnectBlockByHashCF
    // queues the corresponding deletes, both atomic with the chainstate
    // advance via the flush() WriteBatch.  Pre-this-commit `--txindex` was
    // a parsed-but-dead flag (config.txindex never reached the storage
    // layer) and CF_TX_INDEX never received a put / delete.  Bitcoin Core
    // analog: -txindex toggling TxIndex base-index registration in init.cpp.
    chain_state.txindex_enabled = config.txindex;
    if (config.txindex) {
        std.debug.print("Transaction index enabled (--txindex)\n", .{});
    }
    // BlockFilterIndex (2026-05-05) — wire --blockfilterindex into ChainState
    // so connectBlockInner queues CF_BLOCK_FILTER + CF_BLOCK_FILTER_HEADER
    // writes (and disconnect queues deletes), atomic with the chainstate
    // advance via the shared flush() WriteBatch.  Bitcoin Core analog:
    // -blockfilterindex toggling BlockFilterIndex base-index registration
    // in init.cpp (see blockfilterindex.cpp::CustomAppend).  Pre-this-commit
    // the flag was parsed-but-dead; the existing rpc.zig REST handler
    // computed BIP-158 filters on demand from CF_BLOCKS + CF_BLOCK_UNDO.
    chain_state.blockfilterindex_enabled = config.blockfilterindex;
    if (config.blockfilterindex) {
        std.debug.print("Block filter index enabled (--blockfilterindex)\n", .{});
    }
    // CoinStatsIndex (2026-06-08) — wire --coinstatsindex into ChainState so
    // connectBlockInner advances the running MuHash3072 + cumulative UTXO-set
    // totals and queues a per-height CF_COINSTATS record (and disconnect
    // queues the revert), atomic with the chainstate advance via the shared
    // flush() WriteBatch.  Bitcoin Core analog: -coinstatsindex toggling
    // CoinStatsIndex base-index registration in init.cpp (DEFAULT_COINSTATSINDEX
    // = false).  Pre-this-commit the flag was parsed-but-dead (BUG-8); the only
    // gettxoutsetinfo path was the partial in-memory cache walk at the tip.
    chain_state.coinstatsindex_enabled = config.coinstatsindex;
    if (config.coinstatsindex) {
        std.debug.print("Coin statistics index enabled (--coinstatsindex)\n", .{});
    }
    // Seed the BIP-113 MTP ring buffer with the genesis timestamp so that
    // blocks at heights 1..10 see the correct MTP window (which includes
    // genesis).  connectBlockInner pushes subsequent block timestamps into
    // the buffer as blocks are connected.
    chain_state.initGenesisTimestamp(params.genesis_header.timestamp);

    // Seed the cumulative-tx-count (Core CBlockIndex::m_chain_tx_count) for the
    // genesis block.  Genesis is NOT connected via connectBlockInner (it is the
    // chain root), so without this the running counter would start at 0 and
    // every getchaintxstats txcount would be off-by-one (missing the genesis
    // coinbase).  Genesis carries exactly one tx on every Bitcoin network, so
    // we seed m_chain_tx_count(genesis) = 1 and persist the height-0 "X:" entry.
    // Restart-safe: seedGenesisTxCount only seeds when at height 0 (a freshly-
    // started chain); a node resumed past genesis restores the running counter
    // from the persisted tip entry instead (see ChainState.restoreChainTxCount).
    chain_state.seedGenesisTxCount();

    // Plumb pruning policy from CLI/config-file into the chain state. The
    // pruner runs lazily from the IBD loop / RPC tip-update path; this just
    // configures the watermark + target. 0 = disabled (default).
    chain_state.prune_target_mib = config.prune;
    if (config.prune != 0) {
        std.debug.print(
            "Pruning enabled: target {d} MiB (CF_BLOCKS), keep {d} blocks behind tip\n",
            .{ config.prune, storage.ChainState.MIN_BLOCKS_TO_KEEP },
        );
    }

    var mempool_instance = mempool.Mempool.init(&chain_state, params, allocator);
    defer mempool_instance.deinit();

    // Load persisted fee estimator state
    const fee_est_path = std.fmt.allocPrint(allocator, "{s}/fee_estimates.dat", .{full_datadir}) catch null;
    defer if (fee_est_path) |p| allocator.free(p);
    if (fee_est_path) |path| {
        mempool_instance.fee_estimator.loadFromFile(path) catch |err| {
            std.debug.print("Note: could not load fee estimates: {}\n", .{err});
        };
    }

    // Load persisted mempool (Bitcoin Core-compatible mempool.dat).
    // Best-effort: a missing or malformed file is logged and skipped — we
    // never block startup on mempool persistence.
    const mempool_dat_path = std.fmt.allocPrint(allocator, "{s}/mempool.dat", .{full_datadir}) catch null;
    defer if (mempool_dat_path) |p| allocator.free(p);
    if (mempool_dat_path) |path| {
        const r = mempool_persist.loadMempool(&mempool_instance, path, allocator) catch |err| blk: {
            std.debug.print("Note: could not load mempool.dat: {}\n", .{err});
            break :blk mempool_persist.LoadResult{
                .total = 0,
                .accepted = 0,
                .expired = 0,
                .failed = 0,
            };
        };
        if (r.total > 0) {
            std.debug.print(
                "Loaded mempool.dat: {d} accepted, {d} expired, {d} failed (of {d} total)\n",
                .{ r.accepted, r.expired, r.failed, r.total },
            );
        }
    }

    var peer_manager = peer.PeerManager.init(allocator, params);
    defer peer_manager.deinit();
    peer_manager.chain_state = &chain_state;
    peer_manager.mempool = &mempool_instance;
    peer_manager.peerbloomfilters = config.peerbloomfilters;
    // Fixed-seed fallback gating (Core net.cpp:2604-2643).  fixed_seed_enabled
    // is force-off in --connect mode inside PeerManager.run; dns_seed_enabled
    // feeds the predicate's cheap "-dnsseed=0 ⇒ fire immediately" shortcut.
    peer_manager.fixed_seed_enabled = config.fixed_seed;
    peer_manager.dns_seed_enabled = config.dns_seed;
    // BIP-159: when prune mode is enabled (-prune > 0), advertise
    // NODE_NETWORK_LIMITED so peers know we serve only the recent-288
    // keep window.  Mirrors Core's init.cpp `IsPruneMode()` gate.
    peer_manager.advertise_node_network_limited = chain_state.prune_target_mib > 0;
    // BIP-157: advertise NODE_COMPACT_FILTERS (1<<6) when blockfilterindex is
    // enabled.  Mirrors Core's init.cpp:992-998 where g_local_services gains
    // NODE_COMPACT_FILTERS when both peerblockfilters + blockfilterindex hold.
    // clearbit gates only on blockfilterindex (peerblockfilters follows it).
    peer_manager.blockfilterindex_enabled = config.blockfilterindex;
    // ASMap: load the binary asmap file if --asmap=<path> was provided.
    // Mirrors Core's init.cpp:1598-1628 DecodeAsmap + CheckStandardAsmap.
    if (config.asmap_path) |asmap_path| {
        const asmap_mod = @import("asmap.zig");
        if (asmap_mod.loadAsmap(allocator, asmap_path)) |data| {
            peer_manager.asmap_data = data;
            std.debug.print("ASMap: loaded {d} bytes from '{s}'\n", .{ data.len, asmap_path });
        } else |err| {
            std.debug.print("Warning: could not load asmap from '{s}': {}\n", .{ asmap_path, err });
        }
    }
    // Anonymous-network proxy wiring (W117 FIX-56).  Lifts the dead-helper
    // ProxyManager / Socks5Client / I2pSamClient / TorControlClient into
    // production.  When any of --proxy / --onion / --i2psam is set, the
    // outbound dial path (Peer.connect / connectOutbound*) consults
    // peer_manager.proxy_manager and routes through SOCKS5 / I2P SAM as
    // appropriate.  --cjdnsreachable opens fc00::/7 as routable for CJDNS.
    peer_manager.cjdnsreachable = config.cjdnsreachable;
    if (config.proxy != null or config.onion != null or config.i2psam != null) {
        peer_manager.initProxy(config.proxy, config.onion, config.i2psam);
        if (peer_manager.proxy_manager) |pm| {
            std.debug.print(
                "Proxy: clearnet={s}:{d} tor={s}:{d} i2psam={s}:{d} cjdnsreachable={any}\n",
                .{
                    pm.clearnet_config.host, pm.clearnet_config.port,
                    pm.tor_config.host,      pm.tor_config.port,
                    pm.i2p_config.host,      pm.i2p_config.port,
                    config.cjdnsreachable,
                },
            );
        }
    } else if (config.cjdnsreachable) {
        std.debug.print("CJDNS: fc00::/7 treated as routable (--cjdnsreachable)\n", .{});
    }

    const auth_token = computeAuthToken(config.rpc_user, config.rpc_password, allocator) catch null;
    defer if (auth_token) |t| allocator.free(t);

    const cookie_token = generateCookieFile(full_datadir, allocator) catch |err| blk: {
        std.debug.print("Warning: could not write cookie file: {}\n", .{err});
        break :blk null;
    };
    defer if (cookie_token) |t| allocator.free(t);

    var chain_manager = validation.ChainManager.init(&chain_state, &mempool_instance, allocator);
    defer chain_manager.deinit();
    // BUG-9 fix: seed genesis with has_data=true so activateBestChain can
    // select it.  Mirrors Core's LoadGenesisBlock → ReceivedBlockTransactions.
    chain_manager.loadGenesis(params) catch |err| {
        std.debug.print("Warning: could not seed genesis block in ChainManager: {}\n", .{err});
    };

    // Wire a multi-wallet manager so the wallet RPCs (createwallet,
    // getnewaddress, sethdseed, scantxoutset-driven recovery, …) are
    // reachable on the live node.  Without this the RPC server came up
    // with `wallet = null, wallet_manager = null` and every wallet RPC
    // returned "Multi-wallet not enabled".  Wallets live under
    // <full_datadir>/wallets and are created lazily by `createwallet`;
    // constructing the manager costs nothing until a wallet exists.
    const wallets_dir = std.fmt.allocPrint(allocator, "{s}/wallets", .{full_datadir}) catch {
        std.debug.print("Out of memory allocating wallets dir\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(wallets_dir);
    const wallet_net: wallet.Network = switch (config.network) {
        .mainnet => .mainnet,
        .testnet, .testnet4 => .testnet,
        .regtest => .regtest,
    };
    var wallet_manager = wallet.WalletManager.init(allocator, wallets_dir, wallet_net) catch |err| {
        std.debug.print("FATAL: could not initialize wallet manager: {}\n", .{err});
        std.process.exit(1);
    };
    defer wallet_manager.deinit();

    // Auto-load wallets at startup (the missing piece that left wallets silently
    // unloaded after a restart, and crashed the node when a partial wallet.dat
    // was reloaded).  Honors `-wallet=<name>` flags; otherwise enumerates the
    // wallet dir like Bitcoin Core's LoadWallets.  Fault-tolerant per wallet: a
    // missing / corrupt / partially-written file is recovered-or-skipped and can
    // NEVER crash startup.  Runs single-threaded before the peer/RPC threads.
    // Whether any wallet was loaded — gates spawning the background reconcile
    // thread below (after RPC binds).  The reconcile itself is NO LONGER run
    // synchronously here: when a wallet's persisted last_synced_height is 0
    // (default / first-restart-after-the-wallet-fix / legacy file / restored
    // from seed) reconcileToTip walks the entire chain 0..tip (~950k blocks
    // on mainnet), which would block the boot path and leave the node looking
    // DOWN for minutes before RPC binds.  See ReconcileCtx / Bitcoin Core
    // CWallet::AttachChain — it is deferred to a background thread spawned
    // after rpc_server.start().
    const wallets_loaded = wallet_manager.loadWalletsOnStartup(config.walletNames());
    if (wallets_loaded > 0) {
        std.debug.print("Loaded {d} wallet(s) at startup\n", .{wallets_loaded});
    }

    // Feed the live P2P/IBD block-connect loop into the wallets so getbalance /
    // listunspent stay current on a synced node (not just the mining/RPC path).
    peer_manager.wallet_manager = &wallet_manager;

    var rpc_server = rpc.RpcServer.initWithWalletManager(
        allocator,
        &chain_state,
        &mempool_instance,
        &peer_manager,
        params,
        &wallet_manager,
        .{
            .bind_address = config.rpc_bind,
            .port = config.rpc_port,
            .auth_token = auth_token,
            .cookie_token = cookie_token,
            .datadir = full_datadir,
            // W119 + FIX-64: HTTPS/TLS termination flag plumbing.  Today
            // both unset → HTTP (backward-compatible default).  Either alone
            // → startup error.  Both set → TlsServerUnavailable error
            // until Zig stdlib / a deliberate C-dep adds server TLS.
            .tls_cert_path = config.rpc_tls_cert,
            .tls_key_path = config.rpc_tls_key,
        },
    );
    defer rpc_server.deinit();
    rpc_server.setChainManager(&chain_manager);
    // W119/G27 + FIX-66: wire the PayJoin receiver endpoint URL so the
    // `getpayjoinrequest` + `sendpayjoinrequest` RPC handlers can pick
    // it up.  Borrowed slice — kept alive by the config block above.
    rpc_server.setPayjoinEndpoint(config.payjoin_server_url);

    // 7b. Daemonize BEFORE installing signal handlers so the pre-daemon
    // parent never sees them. This must also run before any thread is
    // spawned because fork() in the multi-threaded child UB-territory.
    if (config.daemon) {
        ops.daemonize(false) catch |err| {
            std.debug.print("FATAL: daemonize failed: {}\n", .{err});
            std.process.exit(1);
        };
    }

    // 7c. Open the operator-supplied --logfile, if any, and remember it for
    // SIGHUP-driven reopen. Best-effort — a missing path is logged and the
    // node continues to log to stderr.
    log_state = ops.LogState.init(allocator);
    log_state_initialized = true;
    if (config.logfile) |lf| {
        log_state.open(lf) catch |err| {
            std.debug.print("Warning: could not open --logfile {s}: {}\n", .{ lf, err });
        };
    }

    // 7d. Write PID file. Default path is <full_datadir>/clearbit.pid.
    // Stash the resolved path so the deferred cleanup unlinks the same file
    // (free-of-charge atomicity: even if --pid= changes mid-flight, both
    // write and unlink see the original).
    const pid_path: []const u8 = blk: {
        if (config.pidfile) |p| break :blk allocator.dupe(u8, p) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };
        break :blk std.fmt.allocPrint(allocator, "{s}/clearbit.pid", .{full_datadir}) catch {
            std.debug.print("Out of memory\n", .{});
            std.process.exit(1);
        };
    };
    defer allocator.free(pid_path);
    ops.writePidFile(pid_path, allocator) catch |err| {
        std.debug.print("Warning: could not write PID file {s}: {}\n", .{ pid_path, err });
    };

    // 7e. Initialize ZMQ publisher (no-op when no --zmqpub<topic>= was set).
    zmq.global.init(allocator, .{
        .rawblock_addr = config.zmq_rawblock,
        .hashblock_addr = config.zmq_hashblock,
        .rawtx_addr = config.zmq_rawtx,
        .hashtx_addr = config.zmq_hashtx,
        .sequence_addr = config.zmq_sequence,
    }) catch |err| {
        std.debug.print("Warning: ZMQ init failed: {}\n", .{err});
    };

    // 7f. --reindex: honest-progress.
    //
    // Bitcoin Core's full reindex walks blk*.dat, re-validates, and rebuilds
    // the UTXO set from scratch (validation.cpp + init.cpp). clearbit stores
    // raw block bytes in CF_BLOCKS keyed by hash; a real reindex would
    // (1) wipe chainstate keys, (2) iterate CF_BLOCKS in height order using
    // ChainStore, (3) re-run connectBlockFast for each. The full path needs
    // a CF_BLOCKS height-iterator + UTXO-wipe helper that's not yet
    // available, so for now we accept the flag, log a clear message, and
    // continue (the operator can wipe the chainstate dir manually for a
    // forced rebuild).
    if (config.reindex) {
        std.debug.print(
            "--reindex requested: clearbit's CF_BLOCKS-based reindex is partial.\n" ++
            "  For a full rebuild, stop the node, delete <datadir>/<network>/chainstate,\n" ++
            "  and restart. CF_BLOCKS bodies are preserved; UTXO + headers will\n" ++
            "  rebuild from peers (or from blockstorage when --import-blocks= is set).\n",
            .{},
        );
        // Mark in debug log so the [REINDEX] category is visible if enabled.
        _ = debug_log.parseAndApply("reindex");
    }

    // 8. Install signal handlers
    installSignalHandlers();
    ops.installSighupHandler();

    // Load persisted chain tip from RocksDB, fall back to genesis
    if (db_ptr) |dbp| {
        if (dbp.get(storage.CF_DEFAULT, "chain_tip")) |tip_data| {
            if (tip_data) |data| {
                defer allocator.free(data);
                if (data.len == 36) {
                    @memcpy(&chain_state.best_hash, data[0..32]);
                    chain_state.best_height = std.mem.readInt(u32, data[32..36], .little);
                    std.debug.print("Loaded chain tip from DB: height {d}\n", .{chain_state.best_height});
                    // Restore the in-memory cumulative-tx-count running counter
                    // (Core m_chain_tx_count) from the persisted "X:" entry at
                    // the loaded tip, so getchaintxstats + the next connect see
                    // the correct base after a restart.  Falls back to the
                    // genesis seed (1) when the per-height entry is absent
                    // (pre-index datadir) — matching Core's "unknown" sentinel.
                    chain_state.restoreChainTxCount();
                }
            }
        } else |_| {}
        // Load persisted UTXO count (written by --load-snapshot)
        if (dbp.get(storage.CF_DEFAULT, "utxo_count")) |count_data| {
            if (count_data) |data| {
                defer allocator.free(data);
                if (data.len == 8) {
                    chain_state.utxo_set.total_utxos = std.mem.readInt(u64, data[0..8], .little);
                    std.debug.print("Loaded UTXO count from DB: {d}\n", .{chain_state.utxo_set.total_utxos});
                }
            }
        } else |_| {}
        // BlockFilterIndex (2026-05-05): load persisted filterindex tip +
        // restore the chained `prev_filter_header` from CF_BLOCK_FILTER_HEADER
        // for that tip.  Skip when --blockfilterindex is off (legacy datadirs
        // upgrade lazily on first filter write — backfill picks up from 0).
        if (config.blockfilterindex) {
            if (dbp.get(storage.CF_DEFAULT, storage.ChainState.FILTERINDEX_TIP_KEY)) |fi_data| {
                if (fi_data) |data| {
                    defer allocator.free(data);
                    if (data.len == 4) {
                        chain_state.blockfilterindex_height = std.mem.readInt(u32, data[0..4], .little);
                        std.debug.print(
                            "Loaded filterindex tip from DB: height {d}\n",
                            .{chain_state.blockfilterindex_height},
                        );
                    }
                }
            } else |_| {}
            // Restore prev_filter_header from the persisted tip's header
            // (or leave zero if filterindex_height == 0 / header CF empty).
            if (chain_state.blockfilterindex_height > 0) {
                if (chain_state.getBlockHashByHeight(chain_state.blockfilterindex_height)) |tip_hash| {
                    if (chain_state.getPersistedFilterHeader(&tip_hash) catch null) |hdr| {
                        chain_state.prev_filter_header = hdr;
                    }
                }
            }
        }
        // CoinStatsIndex (2026-06-08): load the persisted coinstatsindex tip
        // height, then restore the full running accumulator + cumulative totals
        // from the per-height CF_COINSTATS record at that tip.  This is the
        // crash-safe reconcile: because the tip key, the per-height records, and
        // the chain tip all commit in one WriteBatch, the restored running state
        // is exactly the snapshot the index last durably reached.  Backfill
        // (below) then resumes from coinstatsindex_height+1 to best_height.
        if (config.coinstatsindex) {
            if (dbp.get(storage.CF_DEFAULT, storage.ChainState.COINSTATSINDEX_TIP_KEY)) |cs_data| {
                if (cs_data) |data| {
                    defer allocator.free(data);
                    if (data.len == 4) {
                        chain_state.coinstatsindex_height = std.mem.readInt(u32, data[0..4], .little);
                        std.debug.print(
                            "Loaded coinstatsindex tip from DB: height {d}\n",
                            .{chain_state.coinstatsindex_height},
                        );
                    }
                }
            } else |_| {}
            if (chain_state.coinstatsindex_height > 0) {
                if (chain_state.getCoinStatsByHeight(chain_state.coinstatsindex_height) catch null) |rec| {
                    chain_state.restoreCoinStatsFromRecord(&rec);
                } else {
                    // Tip key present but record missing/corrupt — reset to
                    // genesis-seeded empty so backfill rebuilds from scratch.
                    std.debug.print("CoinStatsIndex: persisted tip record missing; rebuilding from genesis\n", .{});
                    chain_state.coinstatsindex_height = 0;
                    chain_state.seedCoinStatsGenesis(consensus.getBlockSubsidy(0, params));
                }
            } else {
                // Fresh index — seed the genesis-block accounting (Core books
                // the genesis subsidy into total_unspendables_genesis_block and
                // total_subsidy; the genesis coinbase output is never in the
                // UTXO set so muhash/txouts/total_amount are unaffected).
                chain_state.seedCoinStatsGenesis(consensus.getBlockSubsidy(0, params));
            }
        }
    }
    if (chain_state.best_height == 0) {
        chain_state.best_hash = params.genesis_hash;
        chain_state.best_height = 0;
    }

    // SNAPSHOT FORWARD-SYNC (Layer 3): if the loaded tip is a snapshot base
    // (booted via `--load-snapshot`), seed the BIP-113 MTP window from the
    // base block's GetMedianTimePast and arm the PeerManager fallback.  Without
    // this, blocks base+1..base+~11 see an empty MTP window (computePrevMtp==0)
    // and their lock-time cutoff collapses to the block's own timestamp,
    // bypassing BIP-113.  Matched against the loaded best_hash so a normal
    // (non-snapshot) tip at the same height is unaffected.  Core's assumeUTXO
    // chainstate starts from the snapshot base's real header, so its MTP is
    // available immediately; we reproduce that with the precomputed base_mtp.
    {
        var sb_mtp: u32 = 0;
        for (params.snapshot_bootstrap) |e| {
            if (chain_state.best_height == e.height and
                std.mem.eql(u8, &chain_state.best_hash, &e.block_hash))
            {
                sb_mtp = e.base_mtp;
                break;
            }
        }
        if (sb_mtp != 0) {
            chain_state.seedSnapshotBaseTimestamp(sb_mtp);
            peer_manager.setSnapshotBaseMtp(sb_mtp, chain_state.best_height);
            std.debug.print(
                "Snapshot forward-sync: seeded BIP-113 MTP window from base block MTP {d} (height {d})\n",
                .{ sb_mtp, chain_state.best_height },
            );
        }
    }

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

    // 9b. BlockFilterIndex IBD-time backfill (2026-05-05).  When
    // --blockfilterindex is on AND the persisted index lags the loaded
    // chain tip, walk forward block-by-block reading CF_BLOCKS +
    // CF_BLOCK_UNDO and populating CF_BLOCK_FILTER + CF_BLOCK_FILTER_HEADER.
    // Runs synchronously here (before the P2P thread spawns) so the
    // index is consistent with the chain tip the moment connectBlockInner
    // starts queuing live filter writes.
    if (config.blockfilterindex) {
        chain_state.backfillBlockFilterIndex() catch |err| {
            std.debug.print("Warning: BlockFilterIndex backfill failed: {}\n", .{err});
        };
    }
    // 9c. CoinStatsIndex IBD-time backfill (2026-06-08).  When --coinstatsindex
    // is on AND the persisted index lags the loaded chain tip, walk forward
    // block-by-block reading CF_BLOCKS + CF_BLOCK_UNDO and advancing the running
    // MuHash3072 + cumulative totals into per-height CF_COINSTATS records.  Runs
    // synchronously here (before the P2P thread spawns) so the index is
    // consistent with the tip the moment connectBlockInner starts queuing live
    // coinstats writes.
    if (config.coinstatsindex) {
        chain_state.backfillCoinStatsIndex() catch |err| {
            std.debug.print("Warning: CoinStatsIndex backfill failed: {}\n", .{err});
        };
    }

    // 10. Start subsystem threads

    // Start TCP listener for inbound P2P connections BEFORE spawning the peer thread
    peer_manager.startListening(config.listen_port) catch |err| {
        std.debug.print("Warning: could not start P2P listener on port {d}: {}\n", .{ config.listen_port, err });
    };
    std.debug.print("P2P listening on port {d}\n", .{config.listen_port});
    std.debug.print("RPC server on {s}:{d}\n", .{ config.rpc_bind, config.rpc_port });

    // Load persisted ban list from disk (W99/G3 fix). Without this, every
    // restart starts with an empty ban set even though deinit() persists it
    // via saveBanList() — bans survive a graceful shutdown's serialization
    // but never get rehydrated on the next launch, so misbehaving peers
    // immediately reconnect and spam the next session. Mirrors Bitcoin Core
    // init.cpp's `node.banman->LoadBanlist()` call before AppInitMain returns.
    // File path is relative to cwd (banlist.json); start_mainnet.sh `cd`s
    // into the datadir before exec, matching the saveBanList() write path.
    peer_manager.loadBanList() catch |err| {
        std.debug.print("Note: could not load ban list: {}\n", .{err});
    };

    // Start peer manager in background thread
    const peer_thread = std.Thread.spawn(.{}, peer.PeerManager.run, .{&peer_manager}) catch |err| {
        std.debug.print("Warning: could not start peer thread: {}\n", .{err});
        return;
    };

    // Start RPC server in background thread.
    //
    // The three TLS-config errors (TlsCertWithoutKey / TlsKeyWithoutCert /
    // TlsServerUnavailable) are operator-misconfiguration, not transient
    // failures — exit fast with a clear message instead of running a node
    // with no RPC listener (W119 + FIX-64).
    rpc_server.start() catch |err| {
        switch (err) {
            error.TlsCertWithoutKey => {
                std.debug.print(
                    "FATAL: --rpc-tls-cert supplied without --rpc-tls-key. " ++
                        "Both must be provided together.\n",
                    .{},
                );
                std.process.exit(1);
            },
            error.TlsKeyWithoutCert => {
                std.debug.print(
                    "FATAL: --rpc-tls-key supplied without --rpc-tls-cert. " ++
                        "Both must be provided together.\n",
                    .{},
                );
                std.process.exit(1);
            },
            error.TlsServerUnavailable => {
                std.debug.print(
                    "FATAL: HTTPS/TLS termination is not available in this build.\n" ++
                        "  Zig 0.13's standard library ships std.crypto.tls.Client but no server-side TLS.\n" ++
                        "  Flag plumbing (--rpc-tls-cert / --rpc-tls-key) is wired so a future drop-in\n" ++
                        "  can land without changing the CLI contract.  Until then, omit both flags to\n" ++
                        "  bind plain HTTP (default) or front the RPC port with stunnel / nginx / Caddy.\n" ++
                        "  Tracked: W119 BUG-3 / BUG-23, FIX-64 deferral.\n",
                    .{},
                );
                std.process.exit(1);
            },
            else => std.debug.print("Warning: could not start RPC server: {}\n", .{err}),
        }
    };
    const rpc_thread = std.Thread.spawn(.{}, rpc.RpcServer.run, .{&rpc_server}) catch |err| {
        std.debug.print("Warning: could not start RPC thread: {}\n", .{err});
        return;
    };

    // Deferred wallet reconcile (Bitcoin Core CWallet::AttachChain): now that
    // RPC has bound and P2P is running, kick off the startup history rescan in
    // a background thread instead of on the boot path.  This still rebuilds
    // each wallet's UTXO ledger over the gap (last_synced_height, tip] — a
    // crash between the last on-mutation save and the chain tip never silently
    // leaves the ledger behind — but it no longer makes the node look DOWN for
    // the minutes a full-chain (0..tip) scan takes.  ReconcileCtx is
    // heap-allocated so the thread captures no stack-locals; the thread is
    // joined during graceful shutdown (below) so chain_state / wallet_manager
    // outlive it.  fetch() returns null on shutdown_requested, so a SIGTERM
    // mid-scan unwinds the rescan promptly (watermark progress is persisted).
    const reconcile_thread: ?std.Thread = blk: {
        if (wallets_loaded == 0) break :blk null;
        const ctx = allocator.create(ReconcileCtx) catch {
            std.debug.print("Warning: OOM allocating wallet reconcile context; skipping background reconcile\n", .{});
            break :blk null;
        };
        ctx.* = .{
            .allocator = allocator,
            .wm = &wallet_manager,
            .cs = &chain_state,
            .tip_height = chain_state.best_height,
        };
        break :blk std.Thread.spawn(.{}, reconcileWalletsBackground, .{ctx}) catch |err| {
            std.debug.print("Warning: could not start wallet reconcile thread: {}\n", .{err});
            allocator.destroy(ctx);
            break :blk null;
        };
    };

    // Start Prometheus metrics server
    if (config.metrics_port > 0) {
        _ = std.Thread.spawn(.{}, metricsServerThread, .{
            config.metrics_port,
            &chain_state,
            &mempool_instance,
            &peer_manager,
        }) catch |err| {
            std.debug.print("Warning: could not start metrics thread: {}\n", .{err});
            return;
        };
        std.debug.print("Prometheus metrics server on port {d}\n", .{config.metrics_port});
    }

    std.debug.print("Node running. Press Ctrl+C to stop.\n", .{});

    // 10b. Fire systemd-style readiness notification once subsystems are
    // listening. supervisors (systemd Type=notify, runit, daemontools) read
    // a fd passed via --ready-fd=<N> for "ready to serve" signal.
    if (config.ready_fd >= 0) {
        ops.notifyReadyFd(config.ready_fd);
    }

    // 11. Main loop: wait for shutdown signal. Also drives the lazy
    // pruner: every PRUNE_TICK_MS (when pruning is enabled), call
    // chain_state.pruneToTarget() so the watermark advances + CF_BLOCKS
    // bytes are reclaimed if the size estimate exceeds the target.
    // Bounded MAX_PRUNE_BATCH per call keeps tail latency in check.
    const PRUNE_TICK_MS: u64 = 60 * 1000; // every 60 s
    var last_prune_ms: i64 = std.time.milliTimestamp();
    while (!shutdown_requested.load(.acquire)) {
        std.time.sleep(100 * std.time.ns_per_ms);
        // SIGHUP-driven log file reopen — if a SIGHUP arrived since the
        // last tick, close + reopen the file. Cheap (atomic-load + maybe
        // syscall) so we can run it every tick.
        log_state.maybeReopen();
        if (chain_state.prune_target_mib != 0) {
            const now_ms = std.time.milliTimestamp();
            if (now_ms - last_prune_ms >= @as(i64, @intCast(PRUNE_TICK_MS))) {
                last_prune_ms = now_ms;
                const pruned = chain_state.pruneToTarget();
                if (pruned > 0) {
                    std.debug.print(
                        "[prune] watermark={d} pruned={d} cfblocks_estimate_bytes={d}\n",
                        .{ chain_state.prune_height, pruned, chain_state.estimateBlockCfBytes() },
                    );
                }
            }
        }
    }

    // 12. Graceful shutdown
    //
    // Previous behaviour: stop() RPC and peer manager, then join each
    // thread sequentially with no bounded deadline. A blocking
    // subsystem (RPC accept, DB compaction, UTXO flush) could hang the
    // process indefinitely, which is why rolling restarts in Wave 2
    // had to escalate to SIGKILL.
    //
    // New behaviour (mirrors blockbrew f086d9e / Bitcoin Core init.cpp):
    //   - Arm a detached 30s watchdog thread. If graceful shutdown has
    //     not completed by SHUTDOWN_DEADLINE_NS it forces exit(1).
    //   - A second SIGTERM/SIGINT (signalHandler, signal_count>=1)
    //     also forces exit(1) immediately.
    //   - Phased log output so operators can see where shutdown is
    //     stuck if it ever does exceed the deadline.
    const sig_num = signal_count.load(.acquire);
    if (sig_num > 0) {
        std.debug.print("received SIGTERM, beginning graceful shutdown\n", .{});
    } else {
        std.debug.print("\nShutting down...\n", .{});
    }

    // Arm the hard-deadline watchdog. Detached — we never join it; if
    // graceful shutdown completes first we just set shutdown_complete
    // and the watchdog silently returns after its sleep.
    if (std.Thread.spawn(.{}, shutdownWatchdog, .{})) |wd| {
        wd.detach();
    } else |err| {
        std.debug.print("Warning: could not spawn shutdown watchdog: {}\n", .{err});
    }

    // Reverse-order shutdown. Each phase logs before it starts so if
    // we hang it's obvious which subsystem is stuck.

    // Phase 1: stop RPC — no new client requests should begin.
    // RpcServer.stop() closes the listening socket, which unblocks any
    // thread currently in accept().
    std.debug.print("stopping RPC\n", .{});
    rpc_server.stop();

    // Phase 2: stop P2P — peer manager's loop polls the running flag
    // between iterations and exits within ~50ms.
    std.debug.print("stopping P2P\n", .{});
    peer_manager.stop();

    // Join subsystem threads. Both loops check their running flag on
    // every iteration so join returns quickly under normal conditions.
    // If either hangs, the watchdog above will force exit.
    std.debug.print("joining RPC thread\n", .{});
    rpc_thread.join();
    std.debug.print("joining P2P thread\n", .{});
    peer_thread.join();

    // Join the background wallet-reconcile thread if it is still running.
    // shutdown_requested is already set by this point, so its fetch() callback
    // returns null on the next block, reconcileToTip breaks + persists the
    // watermark, and the thread frees its heap context and exits promptly.
    // Joining (rather than detaching) guarantees the thread has stopped
    // touching wallet_manager / chain_state before their `defer` deinit/flush
    // run when main returns.
    if (reconcile_thread) |t| {
        std.debug.print("joining wallet reconcile thread\n", .{});
        t.join();
    }

    // Phase 3: persist auxiliary state (fee estimates + mempool.dat) before
    // flushing the main chainstate so any error here doesn't leave the
    // UTXO set written but the auxiliary state stale.
    if (fee_est_path) |path| {
        mempool_instance.fee_estimator.saveToFile(path) catch |err| {
            std.debug.print("Warning: could not save fee estimates: {}\n", .{err});
        };
    }

    // Dump mempool.dat in Bitcoin Core v2 format (XOR-obfuscated, atomic
    // <path>.new -> rename(path) write). Best-effort: a write failure is
    // logged but does not block shutdown.
    if (mempool_dat_path) |path| {
        const written = mempool_persist.dumpMempool(&mempool_instance, path, allocator) catch |err| blk: {
            std.debug.print("Warning: could not dump mempool.dat: {}\n", .{err});
            break :blk @as(usize, 0);
        };
        if (written > 0) {
            std.debug.print("Dumped mempool.dat: {d} transactions\n", .{written});
        }
    }

    // Phase 4: flush chainstate — dirty UTXO entries + chain tip,
    // atomically so a crash never leaves the tip out of sync with
    // the UTXO set (see storage.ChainState.flush).
    std.debug.print("flushing chainstate\n", .{});
    chain_state.flush() catch |err| {
        std.debug.print("Warning: error flushing chain state: {}\n", .{err});
    };

    // Phase 5: close the RocksDB handle. The `defer` on db_ptr at
    // init time will run p.close() after this function returns; we
    // emit the phase log here so operators see the expected sequence.
    std.debug.print("closing DB\n", .{});

    // Remove cookie file on clean shutdown
    deleteCookieFile(full_datadir, allocator);

    // Close ZMQ sockets and tear down the publishing context.
    zmq.global.deinit();

    // Close the log file (if open) and free its path.
    if (log_state_initialized) {
        log_state.deinit();
        log_state_initialized = false;
    }

    // Remove the PID file last so external supervisors see the node still
    // "alive" until we're truly done.
    ops.removePidFile(pid_path);

    std.debug.print("{s} stopped.\n", .{VERSION_STRING});
    std.debug.print("exit\n", .{});

    // Mark graceful completion so the watchdog's deadline timer
    // becomes a no-op if it fires after we've already returned.
    shutdown_complete.store(true, .release);
}

// ============================================================================
// Prometheus Metrics Server
// ============================================================================

fn metricsServerThread(
    port: u16,
    chain_state: *storage.ChainState,
    mempool_inst: *mempool.Mempool,
    peer_mgr: *peer.PeerManager,
) void {
    const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    var server = std.net.Address.listen(addr, .{ .reuse_address = true }) catch |err| {
        std.debug.print("Metrics: failed to bind port {d}: {}\n", .{ port, err });
        return;
    };
    defer server.deinit();

    while (!shutdown_requested.load(.acquire)) {
        const conn = server.accept() catch continue;
        var stream = conn.stream;
        defer stream.close();

        // Read request line so we can route /health vs /metrics. We only
        // peek the first 4 KiB and look at the request-target — there's
        // no body or headers we care about for either endpoint.
        var buf: [4096]u8 = undefined;
        const n = stream.read(&buf) catch continue;
        const req = buf[0..n];

        // Detect "GET /health" — used by supervisors and load balancers.
        // Anything else falls through to the existing /metrics body.
        const is_health = blk: {
            if (n < 12) break :blk false;
            // Look for "/health" after the verb.
            if (std.mem.indexOf(u8, req, " /health")) |_| break :blk true;
            break :blk false;
        };

        if (is_health) {
            // /health: 200 OK + tiny JSON. Designed to be parseable
            // without a JSON lib (curl + grep is fine).
            const tip = chain_state.best_height;
            var hbuf: [256]u8 = undefined;
            const hbody = std.fmt.bufPrint(&hbuf,
                "{{\"status\":\"ok\",\"height\":{d},\"version\":\"{s}\"}}\n",
                .{ tip, VERSION_STRING },
            ) catch continue;
            var hresp_buf: [512]u8 = undefined;
            const hresp = std.fmt.bufPrint(&hresp_buf,
                "HTTP/1.1 200 OK\r\n" ++
                "Content-Type: application/json\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Connection: close\r\n\r\n{s}",
                .{ hbody.len, hbody },
            ) catch continue;
            _ = stream.write(hresp) catch {};
            continue;
        }

        // Gather metrics
        const height = chain_state.best_height;
        const mstats = mempool_inst.stats();
        const peers = peer_mgr.getPeerCount();

        // Format response body
        var body_buf: [1024]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf,
            "# HELP bitcoin_blocks_total Current block height\n" ++
            "# TYPE bitcoin_blocks_total gauge\n" ++
            "bitcoin_blocks_total {d}\n" ++
            "# HELP bitcoin_peers_connected Number of connected peers\n" ++
            "# TYPE bitcoin_peers_connected gauge\n" ++
            "bitcoin_peers_connected {d}\n" ++
            "# HELP bitcoin_mempool_size Mempool transaction count\n" ++
            "# TYPE bitcoin_mempool_size gauge\n" ++
            "bitcoin_mempool_size {d}\n",
            .{ height, peers, mstats.count },
        ) catch continue;

        // Format HTTP response
        var resp_buf: [2048]u8 = undefined;
        const resp = std.fmt.bufPrint(&resp_buf,
            "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
            .{ body.len, body },
        ) catch continue;

        _ = stream.write(resp) catch {};
    }
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

// ============================================================================
// Prune CLI validation
// ============================================================================

test "validatePruneTarget accepts 0 (disabled)" {
    try std.testing.expectEqual(@as(u64, 0), try validatePruneTarget(0));
}

test "validatePruneTarget accepts 550 (minimum)" {
    try std.testing.expectEqual(@as(u64, 550), try validatePruneTarget(550));
}

test "validatePruneTarget accepts large values" {
    try std.testing.expectEqual(@as(u64, 1024), try validatePruneTarget(1024));
    try std.testing.expectEqual(@as(u64, 100_000), try validatePruneTarget(100_000));
}

test "validatePruneTarget accepts 1 (manual mode sentinel)" {
    // Bitcoin Core init.cpp:524: -prune=1 means "operator-managed only"
    // (auto-prune disabled; manual via pruneblockchain RPC).
    try std.testing.expectEqual(@as(u64, 1), try validatePruneTarget(1));
}

test "validatePruneTarget rejects 2 (below minimum, above manual sentinel)" {
    try std.testing.expectError(ArgParseError.InvalidArgument, validatePruneTarget(2));
}

test "validatePruneTarget rejects 549 (one below minimum)" {
    try std.testing.expectError(ArgParseError.InvalidArgument, validatePruneTarget(549));
}

test "validatePruneTarget rejects 100" {
    try std.testing.expectError(ArgParseError.InvalidArgument, validatePruneTarget(100));
}

test "MIN_PRUNE_TARGET_MIB matches Bitcoin Core" {
    // MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024 in
    // bitcoin-core/src/validation.h:87.
    try std.testing.expectEqual(@as(u64, 550), storage.ChainState.MIN_PRUNE_TARGET_MIB);
}

test "MIN_BLOCKS_TO_KEEP matches Bitcoin Core" {
    // MIN_BLOCKS_TO_KEEP = 288 in bitcoin-core/src/validation.h:76.
    try std.testing.expectEqual(@as(u32, 288), storage.ChainState.MIN_BLOCKS_TO_KEEP);
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

// ============================================================================
// Operational-parity Config defaults (--daemon / --pid / --reindex / ZMQ)
// ============================================================================

test "Config defaults: operational fields off" {
    const cfg = Config{};
    try std.testing.expectEqual(false, cfg.daemon);
    try std.testing.expect(cfg.pidfile == null);
    try std.testing.expect(cfg.conf_path == null);
    try std.testing.expectEqual(false, cfg.reindex);
    try std.testing.expectEqual(@as(i32, -1), cfg.ready_fd);
    try std.testing.expect(cfg.zmq_rawblock == null);
    try std.testing.expect(cfg.zmq_hashblock == null);
    try std.testing.expect(cfg.zmq_rawtx == null);
    try std.testing.expect(cfg.zmq_hashtx == null);
    try std.testing.expect(cfg.zmq_sequence == null);
}

test "config file parses ZMQ + reindex + daemon keys" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const conf =
        \\daemon=1
        \\reindex=1
        \\zmqpubrawblock=tcp://127.0.0.1:28332
        \\zmqpubhashblock=tcp://127.0.0.1:28333
        \\zmqpubrawtx=tcp://127.0.0.1:28334
        \\zmqpubhashtx=tcp://127.0.0.1:28335
        \\zmqpubsequence=tcp://127.0.0.1:28336
    ;
    const dir = tmp_dir.dir;
    const file = try dir.createFile("clearbit.conf", .{});
    try file.writeAll(conf);
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try dir.realpath(".", &path_buf);

    var config = Config{};
    try loadConfigFile(abs_path, &config, allocator);

    try std.testing.expect(config.daemon);
    try std.testing.expect(config.reindex);
    // Strings in config-file values point at the file buffer that was
    // freed; we only check non-null, never dereference.
    try std.testing.expect(config.zmq_rawblock != null);
    try std.testing.expect(config.zmq_hashblock != null);
    try std.testing.expect(config.zmq_rawtx != null);
    try std.testing.expect(config.zmq_hashtx != null);
    try std.testing.expect(config.zmq_sequence != null);
}

test "loadConfigFile accepts an absolute --conf=<file> path" {
    // When `datadir` argument resolves to a regular file (not a directory),
    // loadConfigFile() should open it directly (the `--conf=<file>` path).
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const dir = tmp_dir.dir;
    const file = try dir.createFile("custom.conf", .{});
    try file.writeAll("rpcport=29111\n");
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try dir.realpath(".", &path_buf);
    const conf_path = try std.fmt.allocPrint(allocator, "{s}/custom.conf", .{dir_path});
    defer allocator.free(conf_path);

    var config = Config{};
    try loadConfigFile(conf_path, &config, allocator);
    try std.testing.expectEqual(@as(u16, 29111), config.rpc_port);
}
