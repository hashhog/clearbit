#!/bin/sh
# Build clearbit with RocksDB support (required for mainnet)
# Requires: sudo apt-get install -y librocksdb-dev
zig build -Doptimize=ReleaseFast -Drocksdb=true "$@"
