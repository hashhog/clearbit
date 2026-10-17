# clearbit

A Bitcoin full node written from scratch in Zig. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Block validation | Full consensus rules (BIP-16/34/65/66/68/112/113/141/143/147/341/342). The script interpreter runs Core's `script_tests.json` and `sighash.json` vectors (`zig build test-script test-sighash`, see [docs/status.md](docs/status.md)). |
| UTXO set vs Core | `gettxoutsetinfo` `hash_serialized_3` matches Bitcoin Core v31.1 on the same chain; [docs/status.md](docs/status.md) has a 5-minute regtest check and the mainnet method. |
| RPC | 139 JSON-RPC methods with Core's names and result shapes; error codes for missing or malformed parameters often differ. See [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, BIP-324 v2 transport, addrv2, compact blocks, BIP-157/158 filters (opt-in), Tor/I2P proxies. Tests in `src/tests_*.zig`. |
| Test suite | `zig build test`: 4,893 of 4,905 tests pass, 12 skipped, none fail. See [docs/status.md](docs/status.md#test-suite). |
| Wallet | Descriptor wallet, PSBT and coin selection work on regtest and are unit-tested. Not reviewed for custody: see [SECURITY.md](SECURITY.md). |

Last updated: 2026-10-16.

## Quick start

Tested on Debian 13 with Zig 0.13.0. Other Zig versions do not build this tree; download 0.13.0 from <https://ziglang.org/download/>.

```bash
sudo apt-get install -y librocksdb-dev libsecp256k1-dev curl git
git clone https://github.com/hashhog/clearbit.git && cd clearbit
zig build -Doptimize=ReleaseFast        # a few minutes; binary in zig-out/bin/clearbit
DATADIR=$(mktemp -d)
./zig-out/bin/clearbit --regtest --datadir="$DATADIR" --metricsport=0 &
sleep 5
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

The first `curl` prints the regtest genesis state (`"chain":"regtest","blocks":0`). `--metricsport=0` turns off the Prometheus endpoint, which otherwise listens on all interfaces on port 9332.

## Running

The default network is mainnet. Select another with `--testnet4`, `--testnet` (testnet3) or `--regtest`. Data goes under `--datadir` (default `~/.clearbit`), in a per-network subdirectory:

| Network | Flag | P2P port | RPC port | Data subdirectory |
|---|---|---|---|---|
| mainnet | (none) | 8333 | 8332 | `<datadir>/` |
| testnet4 | `--testnet4` | 48333 | 48332 | `<datadir>/testnet4/` |
| testnet3 | `--testnet` | 18333 | 18332 | `<datadir>/testnet3/` |
| regtest | `--regtest` | 18444 | 18443 | `<datadir>/regtest/` |

Signet is not supported. For mainnet, plan for the same disk as an unpruned Bitcoin Core node (several hundred GB; blocks are stored inside RocksDB), or pass `--prune=<MiB>` (at least 550). Memory use is driven mostly by the UTXO cache, `--dbcache=<MiB>` (default 450); a larger cache makes the initial sync much faster.

Flags take the form `--name=value`. Every flag, the config file, environment variables and the datadir layout are in [docs/running.md](docs/running.md).

## RPC

clearbit serves Bitcoin Core's JSON-RPC interface on the RPC port above. On startup it writes a Core-style cookie to `<datadir>/<network>/.cookie`, or you can set `--rpcuser` / `--rpcpassword`. Any JSON-RPC client that works with `bitcoind` should work. With the quick-start node running (before the final `stop`):

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"createwallet","params":["demo"]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getnewaddress","params":[]}' http://127.0.0.1:18443/wallet/demo
curl -s http://127.0.0.1:18443/rest/chaininfo.json
```

As in Core, wallet calls go to a named wallet through the `/wallet/<name>` URL path. A Core-style REST interface is always on under `/rest/` and has no authentication. The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
zig build test                   # unit and integration tests (about 4,900; a few minutes)
```

```
src/main.zig          CLI, config file, startup and shutdown
src/consensus.zig     chain parameters, difficulty, BIP-9 deployments
src/script.zig        script interpreter
src/validation.zig    block and transaction validation, chain management
src/storage.zig       RocksDB chainstate, UTXO cache, block index
src/p2p.zig, peer.zig  P2P messages, peers, header sync, block download
src/mempool.zig       mempool, RBF, package relay, fee estimation
src/rpc.zig           JSON-RPC and REST server
src/wallet.zig        descriptor wallet, PSBT, coin selection
tests_*.zig           roots for the extra `zig build test-*` steps
```

[docs/architecture.md](docs/architecture.md) describes how the parts fit together, [docs/building.md](docs/building.md) covers the toolchain and build options, and [CONTRIBUTING.md](CONTRIBUTING.md) explains how to send changes.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
