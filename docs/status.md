# Status and how to check it

Each row of the status table in the [README](../README.md) can be checked with the commands on this page. Last updated 2026-10-16, against the `master` commit of that date. Commands run from the repository root after `zig build -Doptimize=ReleaseFast`.

## Test suite

```bash
zig build test --summary all
```

On 2026-10-16 this ran 134 build steps: 4,905 tests, of which 4,893 passed, 12 were skipped and none failed. It takes a few minutes. The output also contains many log lines from tests that exercise failure paths (closed connections, rejected reorganisations); they are expected. The last lines give the totals:

```
Build Summary: 134/134 steps succeeded; 4893/4905 tests passed; 12 skipped
```

## Script interpreter against Core's vectors

The `test-script` and `test-sighash` steps run Bitcoin Core's `script_tests.json` and `sighash.json`. They look for a Bitcoin Core checkout at `../bitcoin-core` (next to this repository) or `./bitcoin-core`:

```bash
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git ../bitcoin-core
zig build test-script test-sighash
```

Results on 2026-10-16: all 500 sighash vectors pass. Of the 1,222 script vectors, 1,174 run and pass and none fail. The other 48 are witness vectors without a trailing comment; the harness counts them in the total but does not run them.

## UTXO set against Core, on regtest

This builds a chain on Bitcoin Core, lets clearbit sync it over P2P, and compares the two UTXO-set hashes. `hash_serialized_3` covers every coin, so one wrong coin, amount or script changes it. You need Bitcoin Core's `bitcoind` and `bitcoin-cli` on your `PATH`; this was run with Core v31.1.

```bash
CORE=$(mktemp -d); NODE=$(mktemp -d)
bitcoind -regtest -datadir="$CORE" -port=18544 -rpcport=18543 -listen=1 -daemon
sleep 3
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 generatetoaddress 200 bcrt1qlfglp2xalgefyyy8hdh3h6wg8ceqn006jdyp89
./zig-out/bin/clearbit --regtest --datadir="$NODE" --metricsport=0 --connect=127.0.0.1:18544 &
sleep 15
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 gettxoutsetinfo
curl -s --user "$(cat "$NODE/regtest/.cookie")" -d '{"method":"gettxoutsetinfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$NODE/regtest/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 stop
```

Both report `"height": 200`, the same `bestblock`, and `"hash_serialized_3": "55a904f0ebf65d38b61e674ea2c411e0241cd7d311ad8c5f35c24c9eafbfe44f"`. The block hashes change from run to run because block times differ, but this UTXO hash does not: the chain holds only coinbase outputs to a fixed address, and their txids do not depend on the time.

## UTXO set against Core, on mainnet

The same comparison works on mainnet but needs a full sync of both nodes. Run clearbit with `--noassumevalid` so every script is verified, wait until both nodes report the same `bestblock` in `gettxoutsetinfo`, and compare `hash_serialized_3`.

Bitcoin Core can also produce the hash for a past height, so you do not have to catch both nodes at the same tip: `bitcoin-cli -named dumptxoutset path=<file> rollback=<height>` returns it as `txoutset_hash`. For height 958,794 Core's value is `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over 166,180,925 coins; a clearbit node whose tip is at that height must report the same `hash_serialized_3`.

## RPC coverage

Start a regtest node as in the README's quick start, then:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"help","params":[]}' http://127.0.0.1:18443/
```

`help` lists 125 methods. [rpc.md](rpc.md) lists all 139 that the dispatch table handles, and the differences from Core that are known.

## Known limitations

- Signet is not supported.
- `--reindex` only prints instructions; to rebuild, delete `<datadir>/<network>/chainstate` and restart.
- Values in the config file override the same flags on the command line (Core does the opposite).
- `--testnet4`, `--metricsport`, `--wallet` and `--peerbloomfilters` work but are missing from `--help`.
- The Prometheus endpoint is on by default and listens on all interfaces; pass `--metricsport=0` to turn it off.
- The REST interface is always on and has no authentication.
- The RPC server cannot use TLS (Zig 0.13 has no TLS server).
- `--version` and `/health` report `v0.1.0`, while the release tags and `CHANGELOG.md` are at 1.0.2.
- For some RPCs, missing or malformed parameters return `-32602` or different wording instead of Core's codes ([rpc.md](rpc.md)).
- `config.example.toml` uses a TOML layout the node does not read; see [running.md](running.md#config-file) for the real format.
- 48 of Core's script vectors are not run by the `test-script` harness (see above).
- Binaries are built for the CPU of the build machine; `-Dcpu=baseline` does not compile ([building.md](building.md#reproducible-builds)).
