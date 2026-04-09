# clearbit

A Bitcoin full node written from scratch in Zig. Part of the [Hashhog](https://github.com/hashhog/hashhog) project.

## Quick Start

### Build from Source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y librocksdb-dev libsecp256k1-dev

# Build
zig build -Doptimize=ReleaseFast

# Run on testnet4
./zig-out/bin/clearbit --testnet

# Show help
./zig-out/bin/clearbit --help

# Run performance benchmarks
./zig-out/bin/clearbit --benchmark
```

### Build with Optional Features

```bash
# With RocksDB storage support
zig build -Drocksdb=true

# With wallet/secp256k1 support
zig build -Dsecp256k1=true

# With BIP-324 ElligatorSwift support
zig build -Dsecp256k1=true -Dsecp256k1-include=../bitcoin/src/secp256k1/include

# With Erlay/minisketch support
zig build -Dminisketch=true
```

## Features

- Full block and transaction validation (BIP-16, BIP-34, BIP-68, BIP-141, BIP-143, BIP-146, BIP-341)
- Script interpreter supporting P2PKH, P2SH, P2WPKH, P2WSH, P2TR, and P2A anchor outputs
- SegWit-aware serialization with witness discount and sigop cost counting
- Witness cleanstack enforcement (unconditional for P2WPKH, P2WSH, tapscript)
- Sighash computation (legacy with FindAndDelete/OP_CODESEPARATOR, BIP-143 SegWit, BIP-341 Taproot)
- Headers-first sync with anti-DoS (PRESYNC/REDOWNLOAD, min_chain_work threshold)
- Parallel block downloads with timeout handling
- Multi-layer UTXO cache (CoinsViewCache with FRESH/DIRTY optimization, batch flush)
- RocksDB storage with column families for blocks, UTXOs, and chain state
- Flat file block storage (blk*.dat, 128 MiB max, pre-allocation, RocksDB index)
- Transaction mempool (full RBF, TRUC v3 policy, cluster linearization, mining score, eviction)
- Package relay (BIP-331: ancpkginfo/getpkgtxns/pkgtxns, CPFP, child-with-parents)
- Fee estimation (confirmation tracking, exponential buckets, decay)
- Block template construction (BIP-34 coinbase, BIP-141 witness, locktime validation, anti-fee-sniping)
- HD wallet (BIP-32: P2PKH, P2SH-P2WPKH, P2WPKH, P2TR address types)
- Branch-and-Bound + Knapsack coin selection
- Wallet encryption (scrypt key derivation)
- Address labels (setlabel RPC)
- PSBT support (BIP-174/370: create, decode, analyze, combine, finalize, convert)
- Output descriptors (BIP-380-386: recursive parser, BCH checksum, WIF/xpub/xprv key derivation)
- Miniscript (AST, type system B/V/K/W, wrappers, script compilation, satisfaction, witness analysis)
- Block indexes (txindex, BIP-157/158 blockfilterindex, coinstatsindex)
- BIP-324 v2 P2P transport (ElligatorSwift, HKDF-SHA256, FSChaCha20-Poly1305, V1 fallback)
- BIP-330 Erlay (set reconciliation via libminisketch FFI, SipHash short IDs)
- BIP-9 version bits (soft fork deployment state machine, signaling, caching)
- BIP-133 feefilter (Poisson delay, hysteresis, incremental relay fee)
- assumeUTXO (snapshot creation/loading, hash verification, dual chainstate)
- Tor/I2P proxy support (SOCKS5 RFC 1928, Tor control for hidden services, I2P SAM v3.1)
- Chain management RPCs (invalidateblock, reconsiderblock, preciousblock)
- Eclipse attack protections (netgroup diversity, anchor connections, inbound eviction)
- Misbehavior scoring (100-point threshold, persistent ban list with JSON)
- Stale peer eviction (chain sync timeout, block download timeout, ping timeout)
- Checkpoint verification (comptime checkpoints, binary search, fork rejection)
- Regtest mode with generatetoaddress, generatetodescriptor, generateblock RPCs
- Hardware crypto detection (comptime/runtime: SHA-NI, SSE4.1, AVX2, ARM SHA2)
- Arena allocators, SIMD optimizations, and comptime lookup tables
- Block import from file or stdin

## Configuration

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--testnet` | Use testnet network | |
| `--regtest` | Use regtest network | |
| `--port=<port>` | P2P listen port | `8333` |
| `--maxconnections=<n>` | Maximum total connections | `125` |
| `--connect=<addr>` | Connect only to specified peer | |
| `--nodnsseed` | Disable DNS seeding | |
| `--rpcbind=<addr>` | RPC bind address | `127.0.0.1` |
| `--rpcport=<port>` | RPC port | `8332` |
| `--rpcuser=<user>` | RPC username | |
| `--rpcpassword=<pw>` | RPC password | |
| `--datadir=<dir>` | Data directory | `~/.clearbit` |
| `--dbcache=<MiB>` | UTXO cache size in MiB | `450` |
| `--prune=<MiB>` | Prune target in MiB (0 = disabled) | `0` |
| `--txindex` | Enable transaction index | disabled |
| `--blockfilterindex` | Enable BIP-157/158 block filter index | disabled |
| `--coinstatsindex` | Enable UTXO statistics index | disabled |
| `--maxmempool=<MiB>` | Max mempool size in MiB | `300` |
| `--mempoolexpiry=<hrs>` | Mempool expiry in hours | `336` |
| `--debug` | Enable debug logging | disabled |
| `--printtoconsole` | Print logs to console | disabled |
| `--benchmark` | Run performance benchmarks and exit | |
| `--import-blocks=<path>` | Import blocks from file (`-` for stdin) | |
| `--import-utxo=<path>` | Import UTXO snapshot from .hdog file | |

## RPC API

### Blockchain

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Returns blockchain processing state info |
| `getblockcount` | Returns height of the most-work fully-validated chain |
| `getbestblockhash` | Returns hash of the best (tip) block |
| `getblockhash` | Returns hash of block at given height |
| `getblock` | Returns block data for a given hash |
| `getblockheader` | Returns block header data |
| `getdifficulty` | Returns proof-of-work difficulty |
| `getchaintips` | Returns information about all known tips in the block tree |
| `gettxout` | Returns details about an unspent transaction output |
| `invalidateblock` | Marks a block as invalid |
| `reconsiderblock` | Removes invalidity status from a block |
| `preciousblock` | Treats a block as if it were received first at its height |
| `dumptxoutset` | Dumps the UTXO set to a file |
| `loadtxoutset` | Loads a UTXO snapshot for assumeUTXO |

### Transactions

| Method | Description |
|--------|-------------|
| `getrawtransaction` | Returns raw transaction data |
| `sendrawtransaction` | Submits a raw transaction to the network |
| `decoderawtransaction` | Decodes a hex-encoded raw transaction |
| `createrawtransaction` | Creates an unsigned raw transaction |
| `signrawtransactionwithwallet` | Signs a raw transaction with wallet keys |
| `decodescript` | Decodes a hex-encoded script |
| `testmempoolaccept` | Tests whether a raw transaction would be accepted by the mempool |

### Mempool

| Method | Description |
|--------|-------------|
| `getmempoolinfo` | Returns mempool state details |
| `getrawmempool` | Returns all transaction IDs in the mempool |
| `getmempoolentry` | Returns mempool data for a given transaction |
| `getmempoolancestors` | Returns all in-mempool ancestors for a transaction |
| `getmempooldescendants` | Returns all in-mempool descendants for a transaction |
| `submitpackage` | Submits a package of transactions (BIP-331) |

### Network

| Method | Description |
|--------|-------------|
| `getnetworkinfo` | Returns P2P networking state info |
| `getpeerinfo` | Returns data about each connected peer |
| `getconnectioncount` | Returns the number of connections |
| `addnode` | Adds or removes a peer |
| `listbanned` | Lists all banned IPs/subnets |
| `setban` | Adds or removes an IP/subnet from the ban list |
| `clearbanned` | Clears all banned IPs |

### Mining

| Method | Description |
|--------|-------------|
| `getblocktemplate` | Returns a block template for mining |
| `submitblock` | Submits a new block to the network |
| `getmininginfo` | Returns mining-related information |
| `estimatesmartfee` | Estimates fee rate for confirmation within N blocks |
| `generatetoaddress` | Mines blocks to an address (regtest only) |
| `generatetodescriptor` | Mines blocks to a descriptor (regtest only) |
| `generateblock` | Mines a block with specific transactions (regtest only) |

### Wallet

| Method | Description |
|--------|-------------|
| `createwallet` | Creates a new wallet |
| `loadwallet` | Loads a wallet from disk |
| `unloadwallet` | Unloads a wallet |
| `listwallets` | Lists loaded wallets |
| `listwalletdir` | Lists wallet files in the wallet directory |
| `getnewaddress` | Generates a new receiving address |
| `getbalance` | Returns wallet balance |
| `sendtoaddress` | Sends bitcoin to an address |
| `listunspent` | Lists unspent outputs |
| `listtransactions` | Lists wallet transactions |
| `getwalletinfo` | Returns wallet state info |
| `getaddressinfo` | Returns address info |
| `encryptwallet` | Encrypts the wallet with a passphrase |
| `walletpassphrase` | Unlocks an encrypted wallet |
| `walletlock` | Locks the wallet |
| `walletpassphrasechange` | Changes the wallet passphrase |
| `setlabel` | Sets an address label |
| `importdescriptors` | Imports output descriptors into the wallet |

### Descriptors and PSBT

| Method | Description |
|--------|-------------|
| `getdescriptorinfo` | Analyzes and checksums an output descriptor |
| `deriveaddresses` | Derives addresses from a descriptor |
| `createpsbt` | Creates a PSBT |
| `decodepsbt` | Decodes a base64 PSBT |
| `analyzepsbt` | Analyzes a PSBT for completion status |
| `combinepsbt` | Combines multiple PSBTs |
| `finalizepsbt` | Finalizes a PSBT |
| `converttopsbt` | Converts a raw transaction to a PSBT |

### Utility

| Method | Description |
|--------|-------------|
| `validateaddress` | Validates a Bitcoin address |
| `stop` | Stops the node |
| `help` | Lists available RPC commands |

## Architecture

clearbit exploits Zig's unique language features -- comptime evaluation, explicit allocators, and zero-cost safety checks -- to build a Bitcoin full node that is both memory-efficient and fast. Core Bitcoin types (Transaction, Block, BlockHeader, OutPoint) use Zig's packed structs where possible, and binary serialization employs custom Reader/Writer types with CompactSize encoding and SegWit witness support. Cryptographic hashing (SHA256d, RIPEMD160, HASH160) uses comptime-generated lookup tables and runtime CPU feature detection to select hardware-accelerated implementations (SHA-NI, SSE4.1, AVX2, ARM SHA2) when available. libsecp256k1 is integrated via Zig's C interop for ECDSA and Schnorr signature verification.

The script interpreter implements all standard Bitcoin script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A anchor outputs) with full BIP rule enforcement. Sighash computation covers legacy (with FindAndDelete/OP_CODESEPARATOR), SegWit v0, and Taproot. The consensus module includes difficulty adjustment for all networks, BIP-9 version bits with signaling state caching, and checkpoint verification using comptime-embedded checkpoint data with binary search lookup.

Storage uses RocksDB with separate column families, and block data lives in flat blk*.dat files (128 MiB max) with pre-allocation and a RocksDB index. The UTXO cache implements a CoinsViewCache layer with FRESH/DIRTY optimization for efficient batch flushing. Undo data for reorgs is persisted in rev*.dat files. The assumeUTXO feature supports snapshot creation and loading with hash verification and dual chainstate management.

P2P networking supports both v1 plaintext and BIP-324 v2 encrypted transport (ElligatorSwift key exchange, FSChaCha20-Poly1305 encryption, short message IDs). BIP-330 Erlay provides bandwidth-efficient transaction relay via set reconciliation using libminisketch. The peer manager handles DNS discovery, misbehavior scoring (100-point threshold with JSON-persisted ban lists), and eclipse attack protections (netgroup diversity for /16 IPv4 and /32 IPv6, anchor connections, Bitcoin Core-compatible inbound eviction). Tor and I2P connectivity is supported via SOCKS5 proxying and control protocols.

The mempool implements full RBF with TRUC v3 transaction relay policy and cluster-based linearization for accurate mining score computation. Package relay follows BIP-331 with child-with-parents support. Fee estimation tracks confirmations across exponential buckets with decay. Block template construction selects transactions by ancestor feerate with BIP-34 coinbase height encoding, BIP-141 witness commitment, sigops limits, locktime finality checks, and anti-fee-sniping nLockTime. Arena allocators are used throughout for predictable memory management, and SIMD intrinsics accelerate hot paths like merkle root computation and block deserialization.

## Project Structure

```
src/
  main.zig           # CLI entry point, config, signal handling
  types.zig          # core bitcoin types
  serialize.zig      # binary serialization
  crypto.zig         # hash functions, merkle trees, sighash, CPU feature detection
  address.zig        # address encoding (Base58, Bech32)
  script.zig         # script interpreter and opcodes
  consensus.zig      # consensus rules, network params, difficulty, BIP-9
  storage.zig        # RocksDB storage, UTXO set, chain state, flat file blocks
  validation.zig     # block and transaction validation, chain management
  p2p.zig            # P2P protocol message serialization
  peer.zig           # TCP peer connections, handshake, misbehavior scoring
  banlist.zig        # ban list management with JSON persistence
  sync.zig           # header sync, block download, IBD, anti-DoS
  mempool.zig        # transaction memory pool with RBF and fee estimation
  block_template.zig # block template construction for mining
  rpc.zig            # JSON-RPC server over HTTP
  wallet.zig         # key management, address derivation, tx signing
  descriptor.zig     # output descriptors (BIP-380-386), checksum, derivation
  miniscript.zig     # miniscript AST, type system, satisfaction, compilation
  indexes.zig        # block indexes (txindex, blockfilterindex, coinstatsindex)
  v2_transport.zig   # BIP-324 encrypted P2P transport
  erlay.zig          # BIP-330 Erlay set reconciliation
  proxy.zig          # Tor SOCKS5 and I2P SAM proxy support
  psbt.zig           # PSBT (BIP-174/370) partially signed transactions
  perf.zig           # performance utilities (arena, SIMD, comptime tables)
  bench.zig          # benchmarking suite
  tests.zig          # comprehensive test suite with test vectors
resources/
  bip39-english.txt  # BIP-39 mnemonic wordlist
```

## Running Tests

```bash
zig build test                    # run all tests
zig build test --summary all      # run tests with detailed summary

# Optional tests with external dependencies:
zig build -Drocksdb=true test     # include RocksDB storage tests
zig build -Dsecp256k1=true test   # include wallet/crypto tests
zig build -Dminisketch=true test  # include Erlay/minisketch FFI tests
```

## License

MIT
