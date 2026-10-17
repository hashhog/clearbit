# Architecture

clearbit is a single Zig executable. All modules live in `src/`, compiled from `src/main.zig`. Two C libraries are linked: RocksDB for storage and libsecp256k1 for signatures. Everything else, including hashing, serialization, the script interpreter, P2P and the wallet, is written in Zig.

## Startup

`src/main.zig` parses flags, reads the config file, creates `<datadir>/<network>/`, opens RocksDB, loads the chainstate, then starts the P2P manager, the RPC server and the metrics server on their own threads. Shutdown, through the `stop` RPC or a signal, flushes the UTXO cache and saves the mempool, address book, ban list and wallets before exiting.

## Data types and encoding

| File | Contents |
|---|---|
| `types.zig` | Transactions, blocks, headers, outpoints. |
| `serialize.zig` | Bitcoin wire encoding, CompactSize, witness serialization. |
| `crypto.zig`, `sha256_shani.c` | SHA-256 (with SHA-NI when the CPU has it), RIPEMD-160, HASH160, merkle roots, legacy and BIP-143 sighash. |
| `taproot_sighash.zig` | BIP-341 sighash. |
| `secp.zig` | Wrapper around libsecp256k1 for ECDSA and Schnorr. |
| `address.zig` | Base58Check, Bech32 and Bech32m addresses. |

## Consensus and validation

| File | Contents |
|---|---|
| `consensus.zig` | Chain parameters for mainnet, testnet3, testnet4 and regtest; difficulty retargeting; BIP-9 deployment state; checkpoints; the assumevalid block and the assumeutxo snapshot list. |
| `script.zig` | Script interpreter: all opcodes, P2SH, SegWit v0, Taproot/tapscript, and the verification flags. |
| `sig_cache.zig` | Cache of verified signatures, so transactions checked in the mempool are not checked again in a block. |
| `validation.zig` | Transaction and block checks, `ConnectBlock`, the parallel script-check pool (`--par`), chain selection and reorganisation. |
| `chainwork.zig` | Cumulative proof-of-work for chain selection. |
| `chain_lock.zig` | The chain lock (Core's `cs_main`) and lock-order checks. |

## Storage

`storage.zig` and `storage_rocksdb.zig` keep everything in one RocksDB database under `<datadir>/<network>/chainstate/`, split into column families: raw blocks, the block index, the UTXO set, undo data for reorganisations, and the optional transaction, block-filter, coin-stats and spent-output indexes (`indexes.zig`). In memory, a coins cache sized by `--dbcache` sits in front of the UTXO column family and is flushed in batches. `compressor.zig` and `muhash.zig` implement Core's UTXO serialization and MuHash, used by `gettxoutsetinfo`, `dumptxoutset` and `loadtxoutset`.

AssumeUTXO: a snapshot can be loaded with `--load-snapshot` or `loadtxoutset`. `au_bg_chainstate.zig` validates the history beneath it in a second chainstate, and `historical_backfill.zig` fetches the blocks below the snapshot so that old heights can be served again.

## P2P

| File | Contents |
|---|---|
| `p2p.zig` | Message encoding and decoding. |
| `peer.zig` | Connections, handshake, header sync, block download, compact blocks, transaction relay, misbehaviour handling, eviction. |
| `v2_transport.zig` | BIP-324 encrypted transport, with fallback to v1. |
| `addrman.zig`, `asmap.zig`, `localaddr.zig` | Address manager with Core's bucketing, optional ASN map, and our own advertised addresses. |
| `banlist.zig` | Bans, saved across restarts. |
| `proxy.zig` | SOCKS5 for Tor and other proxies, Tor control, I2P SAM. |
| `erlay.zig` | BIP-330 set reconciliation (needs `-Dminisketch=true`). |

## Mempool and mining

| File | Contents |
|---|---|
| `mempool.zig` | Policy checks, replace-by-fee, TRUC (v3) transactions, cluster limits, package acceptance, eviction, fee estimation. |
| `mempool_persist.zig` | `mempool.dat` save and load, in Core's format. |
| `block_template.zig` | `getblocktemplate` and the regtest `generate*` RPCs. |

## RPC and operations

| File | Contents |
|---|---|
| `rpc.zig` | HTTP server, JSON-RPC dispatch (`handleSingleRequest`), REST, and every RPC handler. |
| `zmq.zig` | ZeroMQ publishers (with `-Dzmq=true`). |
| `ops.zig`, `debug_log.zig`, `fatal.zig` | Daemonising, PID file, log reopening, debug categories, and fatal-error handling that stops the node instead of recording a block as invalid after a disk or database fault. |

## Wallet

| File | Contents |
|---|---|
| `wallet.zig` | Descriptor wallet: keys, address types (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR), coin selection (branch-and-bound and knapsack), signing, encryption, rescans, persistence under `wallets/<name>/`. |
| `descriptor.zig`, `miniscript.zig` | Output descriptors (BIP-380 to 386) and miniscript. |
| `psbt.zig`, `psbt_process.zig` | PSBT (BIP-174, version 0 only, as in Core). |
| `bip39.zig`, `bip21.zig` | Mnemonic word list and payment URIs. |

## Tests

Unit tests sit next to the code (`test "…"` blocks) and in `src/tests*.zig`. `tests_all.zig` at the repository root is the root of the main `zig build test` suite; the other `tests_*.zig` files at the root are roots for named `zig build test-*` steps. `src/test_script.zig` and `src/test_sighash.zig` run Bitcoin Core's JSON test vectors, and `src/fuzz_decode.zig` is a mutation fuzzer for the P2P decoders.
