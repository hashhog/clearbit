# Building clearbit

## Toolchain

clearbit needs **Zig 0.13.0** exactly. Zig changes its language and standard library between releases, and other versions do not build this tree. Download the 0.13.0 tarball for your platform from <https://ziglang.org/download/> and put `zig` on your `PATH`:

```bash
curl -fsSL https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz | tar -xJ
export PATH="$PWD/zig-linux-x86_64-0.13.0:$PATH"
zig version        # 0.13.0
```

## System libraries

Two C libraries are always linked: RocksDB (chainstate, block index and block storage) and libsecp256k1 (signature verification). On Debian or Ubuntu:

```bash
sudo apt-get install -y librocksdb-dev libsecp256k1-dev
```

This was tested on Debian 13 with `librocksdb-dev` 9.10 and `libsecp256k1-dev` 0.5.0.

## Build

```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/clearbit --version
```

The node binary is `zig-out/bin/clearbit`. The same step also builds the helper programs `test_script`, `test_sighash`, `verifyscript_shim` and `bip341_shim` into `zig-out/bin/`; they are only used for testing. Without `-Doptimize` you get a Debug build, which is much slower but keeps Zig's runtime safety checks (integer overflow, bounds) turned on. `-Doptimize=ReleaseSafe` keeps those checks with optimisation.

## Build options

| Option | Default | Effect |
|---|---|---|
| `-Doptimize=Debug\|ReleaseSafe\|ReleaseFast\|ReleaseSmall` | `Debug` | Standard Zig optimisation mode. |
| `-Dzmq=true` | `false` | Link libzmq and enable the `--zmqpub*` flags. Needs only the runtime package (`libzmq5` on Debian); `libzmq-dev` is not required. Without it the `--zmqpub*` flags are accepted but nothing is published. |
| `-Dminisketch=true` | `false` | Link libminisketch for BIP-330 Erlay set reconciliation. Debian does not package libminisketch; build it yourself and pass `-Dminisketch-include=<dir>`. Not exercised in the default test run. |
| `-Dsecp256k1-include=<dir>` | `../bitcoin/src/secp256k1/include` | Extra include directory for the secp256k1 headers. Not needed when `libsecp256k1-dev` is installed. |
| `-Dsecp256k1=…`, `-Drocksdb=…` | | Accepted for compatibility and ignored: both libraries are always linked. |
| `-Dtest-filter=<substring>` | | Run only the tests in the main test module whose name contains the substring. Use it with `zig build test-unit`; `zig build test` still runs every other test step in full. |

Example with ZeroMQ:

```bash
zig build -Doptimize=ReleaseFast -Dzmq=true
```

`build-release.sh` in the repository root is a shortcut for `zig build -Doptimize=ReleaseFast -Drocksdb=true`.

## Tests

```bash
zig build test                          # every test step, about 4,900 tests
zig build test-unit -Dtest-filter=bip39 # main module only, tests whose name contains "bip39"
zig build --help                        # lists every test-* step
```

The main suite is described in [status.md](status.md#test-suite), together with the steps that run Bitcoin Core's script and sighash vectors.

## Reproducible builds

Release tags (`v1.0.0`, `v1.0.1`, `v1.0.2`) are ordinary git tags; no binaries are published. To build a tag and record its hash:

```bash
git checkout v1.0.2
zig build -Doptimize=ReleaseFast
strip -o clearbit.stripped zig-out/bin/clearbit    # strip is in binutils
sha256sum clearbit.stripped
```

Compare the hash of the stripped binary. The unstripped binary contains debug information with absolute paths to the Zig cache, so two builds of the same commit in different directories differ even when the code is identical; after `strip` they match. Hashes are also only comparable between builds made with the same Zig 0.13.0, the same distribution packages and the same CPU: Zig optimises for the CPU it runs on, and a portable `-Dcpu=baseline` build does not compile at the moment (`src/sha256_shani.c` needs the SHA and SSE4.1 features).
