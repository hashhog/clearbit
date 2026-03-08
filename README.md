# clearbit

A Bitcoin full node written in Zig.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
clearbit is a from-scratch Bitcoin full node written in Zig that does exactly that.
It leverages comptime for compile-time validation and explicit allocators for memory control.

## Current status

- [x] Core types (Transaction, Block, BlockHeader, OutPoint)
- [x] Binary serialization (CompactSize, Reader/Writer)
- [x] Crypto primitives (SHA256, RIPEMD160, HASH160, HASH256)
- [x] Merkle root computation
- [x] Transaction hashing (txid, wtxid)
- [x] Sighash computation (legacy and BIP-143 segwit)
- [x] libsecp256k1 integration stubs (ECDSA, Schnorr)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Consensus parameters (network config, difficulty, subsidy)
- [x] RocksDB storage layer (blocks, UTXOs, chain state)
- [x] Block and transaction validation (BIP-34, BIP-141 segwit)
- [x] P2P message serialization (version, inv, headers, blocks)
- [x] Peer connections (TCP, version/verack handshake, ping/pong)
- [x] Peer manager and discovery (DNS seeds, addr relay, connection pool)
- [x] Header synchronization (getheaders/headers, block locator, chain work)
- [x] Block download and IBD (parallel downloads, UTXO updates, timeout handling)
- [x] UTXO set manager (compact storage, caching, block connect/disconnect)
- [x] Chain state tracking (reorg support, undo data)
- [x] Mempool (BIP-125 RBF, ancestor/descendant limits, dust detection, eviction)
- [x] Fee estimation (confirmation tracking, exponential buckets, decay)
- [x] Block template construction (getblocktemplate, BIP-34 coinbase, BIP-141 witness commitment)
- [ ] Mining RPC server (JSON-RPC interface)

## Quick start

```bash
zig build              # build the node
zig build run          # run the node
zig build test         # run tests

# With RocksDB support (requires librocksdb-dev):
zig build -Drocksdb=true test
zig build -Drocksdb=true test-rocksdb  # run RocksDB-specific tests
```

## Project structure

```
src/
  main.zig           # entry point and module exports
  types.zig          # core bitcoin types
  serialize.zig      # binary serialization
  crypto.zig         # hash functions, merkle trees, sighash
  address.zig        # address encoding (Base58, Bech32)
  script.zig         # script interpreter and opcodes
  consensus.zig      # consensus rules, network params, difficulty
  storage.zig        # RocksDB storage layer, UTXO set, chain state
  storage_rocksdb.zig  # RocksDB C bindings (when linked)
  validation.zig     # block and transaction validation
  p2p.zig            # P2P protocol message serialization
  peer.zig           # TCP peer connections and handshake
  sync.zig           # header sync, block download, and IBD
  mempool.zig        # transaction memory pool with RBF and fee estimation
  block_template.zig # block template construction for mining
```

## Running tests

```bash
zig build test
```
