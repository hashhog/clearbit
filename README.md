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
- [x] Sighash computation (legacy FindAndDelete/OP_CODESEPARATOR, BIP-143 segwit, BIP-341 taproot)
- [x] libsecp256k1 integration (ECDSA signing/verification, Schnorr)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A anchor outputs)
- [x] Consensus parameters (network config, subsidy, soft fork heights)
- [x] Difficulty adjustment (mainnet retarget, testnet 20-min rule, BIP-94, regtest)
- [x] BIP-9 version bits (soft fork deployment state machine, signaling, caching)
- [x] RocksDB storage layer (blocks, UTXOs, chain state)
- [x] Block and transaction validation (BIP-16 P2SH, BIP-34, BIP-68 sequence locks, BIP-141 segwit, BIP-146 NULLFAIL, sigops with witness discount)
- [x] Witness cleanstack enforcement (unconditional for P2WPKH, P2WSH, tapscript - not flag-gated)
- [x] P2P message serialization (version, inv, headers, blocks)
- [x] Peer connections (TCP, version/verack handshake, ping/pong)
- [x] Peer manager and discovery (DNS seeds, addr relay, connection pool)
- [x] Header synchronization (getheaders/headers, block locator, chain work)
- [x] Header sync anti-DoS (PRESYNC/REDOWNLOAD, min_chain_work threshold)
- [x] Block download and IBD (parallel downloads, UTXO updates, timeout handling)
- [x] UTXO set manager (compact storage, caching, block connect/disconnect)
- [x] Chain state tracking (reorg support, undo data with rev*.dat file persistence)
- [x] Mempool (full RBF, TRUC v3 policy, cluster linearization, mining score, eviction)
- [x] Package relay (BIP-331 messages, CPFP, child-with-parents, ancpkginfo/getpkgtxns/pkgtxns)
- [x] Fee estimation (confirmation tracking, exponential buckets, decay)
- [x] Block template construction (getblocktemplate, BIP-34 coinbase, BIP-141 witness, locktime validation, anti-fee-sniping)
- [x] Regtest mining (generatetoaddress, generatetodescriptor, generateblock RPCs for instant block generation)
- [x] JSON-RPC server (Bitcoin Core compatible, HTTP Basic Auth, batch requests, mining, sendrawtransaction, getmempoolentry)
- [x] Wallet (BIP32 HD keys, P2PKH/P2SH-P2WPKH/P2WPKH/P2TR, BnB+Knapsack coin selection, tx signing)
- [x] Coinbase maturity enforcement (100-block delay before spending coinbase outputs)
- [x] Wallet encryption (scrypt key derivation, encrypted private keys)
- [x] Address labels (setlabel RPC, label persistence)
- [x] CLI and application entry point (argument parsing, config files, signal handling)
- [x] Performance optimization (arena allocators, SIMD, comptime tables, UTXO cache)
- [x] Hardware crypto detection (comptime/runtime CPU feature detection for SHA-NI, SSE4.1, AVX2, ARM SHA2)
- [x] Benchmarking suite (SHA256, merkle root, UTXO cache, block deserialization, hw-accelerated hashing)
- [x] Misbehavior scoring and peer banning (per-peer score, 100pt threshold, ban list persistence)
- [x] Eclipse attack protections (netgroup diversity /16 IPv4 /32 IPv6, 2 anchor connections, inbound eviction with Bitcoin Core protection order)
- [x] Checkpoint verification (comptime checkpoints, binary search lookup, fork rejection)
- [x] Flat file block storage (blk*.dat files, 128 MiB max, pre-allocation, RocksDB index)
- [x] UTXO cache layer (CoinsViewCache, FRESH/DIRTY optimization, batch flush)
- [x] Block indexes (txindex, BIP-157/158 blockfilterindex, coinstatsindex)
- [x] BIP-324 v2 P2P transport (ElligatorSwift FFI, HKDF-SHA256, FSChaCha20-Poly1305, short message IDs, garbage padding, V1 fallback)
- [x] Output descriptors (BIP-380/381/382/383/384/385/386, recursive parser, BCH checksum, WIF/xpub/xprv key derivation, RPCs)
- [x] Miniscript (AST, type system B/V/K/W, wrappers, script compilation, satisfaction, witness analysis)
- [x] BIP-133 feefilter (per-peer fee filters, Poisson delay, hysteresis, incremental relay fee)
- [x] BIP-330 Erlay (set reconciliation for tx relay, libminisketch FFI @cImport, SipHash short IDs, negotiation)
- [x] Tor/I2P proxy support (SOCKS5 RFC 1928, Tor control for hidden services, I2P SAM v3.1)
- [x] Chain management RPCs (invalidateblock, reconsiderblock, preciousblock with BFS descendant marking)
- [x] PSBT (BIP-174/370 partially signed transactions, Creator/Updater/Signer/Combiner/Finalizer/Extractor roles, Base64, RPCs)
- [x] assumeUTXO (snapshot creation/loading, hash verification, dual chainstate, loadtxoutset/dumptxoutset RPCs)
- [x] Stale peer eviction (chain sync timeout, block download timeout, ping timeout)
- [ ] Full node integration (P2P + RPC + sync + mempool working together)

## Quick start

```bash
zig build              # build the node
./zig-out/bin/clearbit --help     # show usage
./zig-out/bin/clearbit --version  # show version
./zig-out/bin/clearbit --regtest  # run on regtest
./zig-out/bin/clearbit --benchmark  # run performance benchmarks

# With RocksDB support (requires librocksdb-dev):
zig build -Drocksdb=true test

# With wallet/secp256k1 support (requires libsecp256k1-dev):
zig build -Dsecp256k1=true test

# With BIP-324 ElligatorSwift support (requires libsecp256k1 with ellswift):
zig build -Dsecp256k1=true -Dsecp256k1-include=../bitcoin/src/secp256k1/include test

# Build with full optimizations for benchmarking:
zig build -Doptimize=ReleaseFast
```

## Project structure

```
src/
  main.zig           # CLI entry point, config, signal handling
  types.zig          # core bitcoin types
  serialize.zig      # binary serialization
  crypto.zig         # hash functions, merkle trees, sighash, CPU feature detection
  address.zig        # address encoding (Base58, Bech32)
  script.zig         # script interpreter and opcodes
  consensus.zig      # consensus rules, network params, difficulty, BIP-9
  storage.zig        # RocksDB storage layer, UTXO set, chain state, flat file blocks
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
  miniscript.zig     # miniscript AST, type system, satisfaction, script compilation
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

## Running tests

```bash
zig build test                    # run all tests
zig build test --summary all      # run tests with detailed summary

# Optional tests with external dependencies:
zig build -Drocksdb=true test     # include RocksDB storage tests
zig build -Dsecp256k1=true test   # include wallet/crypto tests
zig build -Dminisketch=true test  # include Erlay/minisketch FFI tests
```
