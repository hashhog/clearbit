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
- [ ] Block validation
- [ ] P2P networking
- [ ] Mempool
- [ ] RPC interface

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
  main.zig         # entry point
  types.zig        # core bitcoin types
  serialize.zig    # binary serialization
  crypto.zig       # hash functions, merkle trees, sighash
  address.zig      # address encoding (Base58, Bech32)
  script.zig       # script interpreter and opcodes
  consensus.zig    # consensus rules, network params, difficulty
  storage.zig      # RocksDB storage layer (blocks, UTXOs, chain state)
  storage_rocksdb.zig  # RocksDB C bindings (when linked)
```

## Running tests

```bash
zig build test
```
