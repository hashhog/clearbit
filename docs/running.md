# Running clearbit

## Networks and ports

| Network | Flag | P2P port | RPC port | Data subdirectory |
|---|---|---|---|---|
| mainnet | (default) | 8333 | 8332 | `<datadir>/` |
| testnet4 | `--testnet4` | 48333 | 48332 | `<datadir>/testnet4/` |
| testnet3 | `--testnet` | 18333 | 18332 | `<datadir>/testnet3/` |
| regtest | `--regtest` | 18444 | 18443 | `<datadir>/regtest/` |

Signet is not supported. The P2P port listens on all interfaces; the RPC port binds to `127.0.0.1` unless you change `--rpcbind`. A Prometheus endpoint listens on all interfaces on port 9332 (all networks) unless you pass `--metricsport=0`.

## Command-line flags

Flags are written `--name=value` (a space between name and value is not accepted). Most also accept Core's single-dash form (`-regtest`, `-datadir=…`). An unknown flag stops the node with `Unknown argument`. `clearbit --help` prints most of this list; flags marked † are accepted but missing from `--help`.

### General

| Flag | Default | Meaning |
|---|---|---|
| `--help`, `-h` | | Print usage and exit. |
| `--version`, `-v` | | Print the version and exit. |
| `--testnet4` † | | Use testnet4. |
| `--testnet` | | Use testnet3. |
| `--regtest` | | Use regtest. |
| `--datadir=<dir>` | `~/.clearbit` | Base data directory. The network subdirectory is created inside it. |
| `--conf=<file>` | `<datadir>/clearbit.conf` | Config file to read (see below). |
| `--daemon` | off | Fork into the background and detach from the terminal. |
| `--pid=<path>` | `<datadir>/<network>/clearbit.pid` | PID file. |
| `--ready-fd=<n>` | | Write `READY=1\n` to file descriptor `n` once the node is serving. |

### Connections

| Flag | Default | Meaning |
|---|---|---|
| `--port=<port>` | per network | P2P listen port. |
| `--maxconnections=<n>` | 125 | Maximum number of peers. |
| `--connect=<host:port>` | | Connect only to this peer (no other outbound connections). |
| `--nodnsseed` | | Do not query DNS seeds. |
| `--nofixedseeds`, `--fixedseeds=0\|1` | on | Use the built-in fixed seed list when nothing else gives addresses. |
| `--externalip=<ip>[:port]` | | Address to advertise to peers. Repeatable, or comma-separated. Implies `--discover=0` unless `--discover` is also given. |
| `--discover`, `--nodiscover`, `--discover=0\|1` | on | Learn our public address from what outbound peers report. |
| `--peerbloomfilters`, `--nopeerbloomfilters` † | off | Serve BIP-37 bloom filters and the BIP-35 `mempool` message. |
| `--proxy=<host:port>` | | SOCKS5 proxy for outbound connections, and for Tor if `--onion` is not set. |
| `--onion=<host:port>` | | SOCKS5 proxy for Tor `.onion` peers. |
| `--i2psam=<host:port>` | | I2P SAM bridge. |
| `--cjdnsreachable`, `--cjdnsreachable=0\|1` | off | Treat `fc00::/7` addresses as reachable CJDNS peers. |
| `--asmap=<file>` | | ASN map for peer bucketing, in Core's asmap format. |

### RPC and monitoring

| Flag | Default | Meaning |
|---|---|---|
| `--rpcbind=<addr>` | `127.0.0.1` | RPC listen address. |
| `--rpcport=<port>` | per network | RPC port. |
| `--rpcuser=<user>`, `--rpcpassword=<pw>` | | Password authentication. A cookie is always written as well (see below). |
| `--rpc-tls-cert=<path>`, `--rpc-tls-key=<path>` | | Reserved. Zig 0.13 has no TLS server, so setting both makes the node refuse to start rather than fall back to plain HTTP. |
| `--payjoin-server-url=<url>` | | BIP-78 PayJoin receiver endpoint used by `sendpayjoinrequest` and `getpayjoinrequest`. Plain `http://` only. |
| `--metricsport=<port>` † | 9332 | Prometheus metrics port; `0` turns it off. Serves `/metrics` and `/health`. Listens on all interfaces. |
| `--zmqpubrawblock=<addr>`, `--zmqpubhashblock=<addr>`, `--zmqpubrawtx=<addr>`, `--zmqpubhashtx=<addr>`, `--zmqpubsequence=<addr>` | | ZeroMQ notifications, as in Core. Only active in a binary built with `-Dzmq=true` ([building.md](building.md)). |

### Storage and validation

| Flag | Default | Meaning |
|---|---|---|
| `--dbcache=<MiB>` | 450 | UTXO cache size. |
| `--prune=<MiB>` | 0 | 0 keeps all blocks; 1 enables manual pruning (`pruneblockchain`); 550 or more is a target size. Values 2–549 are rejected. |
| `--txindex` | off | Transaction index for `getrawtransaction` on confirmed transactions. |
| `--blockfilterindex` | off | BIP-157/158 compact block filters. |
| `--coinstatsindex` | off | Per-block UTXO statistics. |
| `--txospenderindex` | off | Index of which transaction spent each output (`gettxspendingprevout` for confirmed spends). |
| `--noassumevalid` | off | Verify the scripts of every block. By default scripts are skipped below the built-in assumevalid block, as in Core. |
| `--par=<n>` | 0 | Script verification threads: 0 uses every core, `n>0` uses `n` threads, `n<0` leaves `|n|` cores free. |
| `--reindex` | | Only prints instructions. For a rebuild, stop the node, delete `<datadir>/<network>/chainstate` and restart. |
| `--maxmempool=<MiB>` | 300 | Mempool size limit. |
| `--mempoolexpiry=<hours>` | 336 | Mempool expiry. |
| `--wallet=<name>` † | all | Load only these wallets at startup (repeatable). Without it every wallet in `wallets/` is loaded. |

### Logging

| Flag | Default | Meaning |
|---|---|---|
| `--debug`, `--debug=<category>` | off | Debug logging, for all categories or one (repeatable). Categories follow Core's names: `net`, `tor`, `mempool`, `http`, `bench`, `zmq`, `walletdb`, `rpc`, `estimatefee`, `addrman`, `selectcoins`, `reindex`, `cmpctblock`, `rand`, `prune`, `proxy`, `mempoolrej`, `coindb`, `validation`, `lock`, and others. |
| `--printtoconsole` | on | Log to standard error. |
| `--logfile=<path>` | | Also log to this file. The file is reopened on `SIGHUP`, for log rotation. |

### One-shot modes

These do their work and exit; start the node normally afterwards. They do not read the config file.

| Flag | Meaning |
|---|---|
| `--import-blocks=<path>`, `--import-blocks` | Import blocks from a file, or from standard input when no path is given. Each record is a 4-byte little-endian height, a 4-byte little-endian size and the raw block; this is not the `blk*.dat` format. |
| `--load-snapshot=<path>` | Load a UTXO snapshot written by Bitcoin Core's `dumptxoutset`. The snapshot's block must be in the built-in assumeutxo list for the network. |
| `--benchmark` | Run the built-in micro-benchmarks. |

## Config file

clearbit reads `<datadir>/clearbit.conf`, or the file given with `--conf`, if it exists. The format is Core's: one `key=value` per line, `#` starts a comment, no sections. Boolean keys take `1` or `0`.

Recognised keys: `testnet`, `testnet4`, `regtest`, `rpcuser`, `rpcpassword`, `rpcport`, `rpcbind`, `rpc-tls-cert`, `rpc-tls-key`, `payjoin-server-url`, `port`, `maxconnections`, `connect`, `dnsseed`, `fixedseeds`, `dbcache`, `prune`, `txindex`, `blockfilterindex`, `coinstatsindex`, `txospenderindex`, `maxmempool`, `mempoolexpiry`, `debug` (`1`, `0` or a category), `printtoconsole`, `logfile`, `daemon`, `pid`, `reindex`, `par`, `zmqpubrawblock`, `zmqpubhashblock`, `zmqpubrawtx`, `zmqpubhashtx`, `zmqpubsequence`. Other keys are ignored without a warning.

The config file is read after the command line, so a key set in the file overrides the same flag on the command line. This is the reverse of Core.

Example, starting a regtest node from a config file:

```bash
DATADIR=$(mktemp -d)
printf 'regtest=1\nrpcport=18453\nport=18454\n' > "$DATADIR/clearbit.conf"
./zig-out/bin/clearbit --datadir="$DATADIR" --metricsport=0 &
sleep 5
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getblockcount","params":[]}' http://127.0.0.1:18453/
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18453/
```

`config.example.toml` in the repository root is in a different (TOML) format and is not read by the node.

## Environment variables

| Variable | Effect |
|---|---|
| `CLEARBIT_BIP324_V2=0` | Disable BIP-324 v2 transport for outbound connections (on by default). |
| `CLEARBIT_REORG=0` | Disable reorganisation to a heavier competing chain; `warn` logs what it would do instead. For debugging only. |
| `CLEARBIT_LOCK_DEBUG=1` | Extra lock-order checks. For debugging only. |
| `HASHHOG_UNSAFE_SNAPSHOT_HEIGHT=<height>` | Let `--load-snapshot` accept a snapshot that is not in the built-in list, at the given height. Testing only: the UTXO set is then trusted, not verified. |

## Data directory

After a regtest run the network directory contains:

```
<datadir>/regtest/
  .cookie             RPC cookie (removed on clean shutdown)
  clearbit.pid        PID file (removed on clean shutdown)
  chainstate/         RocksDB: blocks, block index, UTXO set, undo data, optional indexes
  wallets/<name>/     one directory per wallet (wallet.dat)
  peers.dat           address book
  anchors.dat         outbound peers to reconnect to after a restart
  mempool.dat         mempool saved at shutdown
  fee_estimates.dat   fee estimator state
```

Block data lives in RocksDB under `chainstate/`, not in `blk*.dat` files.

## Resources

For mainnet without pruning, plan for disk space similar to an unpruned Bitcoin Core node (several hundred GB). Memory is dominated by `--dbcache`; give it several GB for the initial sync if you have the RAM. Script verification uses every core by default (`--par`).

## Monitoring and shutdown

With `--metricsport` set to a non-zero port, `/metrics` serves Prometheus text and `/health` returns a small JSON object:

```bash
curl -s http://127.0.0.1:9332/health
```

```
{"status":"ok","height":0,"version":"clearbit v0.1.0"}
```

Stop the node with the `stop` RPC, `SIGINT` (Ctrl-C) or `SIGTERM`. Shutdown flushes the UTXO cache and saves the mempool, peers and wallets. A second signal forces an immediate exit.
