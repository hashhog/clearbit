# Reproducible build — clearbit v0.1.0-rc1

How to build the tagged clearbit validator and verify it. Part of the tagged-validator
release wrapper (see `SECURITY.md` and `../receipts/PRODUCTION-GATE.md` "three bars").

## Released artifact

| | |
|---|---|
| Tag | `clearbit v0.1.0-rc1` |
| Commit | `e173d5bec4f16ceeca2c2eb3bd923884817483e4` |
| Binary | `clearbit/zig-out/bin/clearbit` (pinned to `deploy/clearbit/clearbit`) |
| **sha256** | `38fd1fff735ab5a0a0441e92f88d865ee45e4d313a988e418e95aec72877a68f` |
| Toolchain | `Zig 0.13.0` |
| Target | `x86_64-linux` |
| Build | `zig build -Doptimize=ReleaseFast` |

## Build

```bash
git clone git@github.com:hashhog/clearbit.git
cd clearbit
git checkout v0.1.0-rc1
# install Zig 0.13.0 (exact version matters)
zig build -Doptimize=ReleaseFast
sha256sum zig-out/bin/clearbit
```

## Verify

Reproducibility holds **when the toolchain and target match**: same `Zig 0.13.0`, same
`x86_64-linux`, a clean checkout of the tagged commit.

**Honest caveats** (a hash mismatch under a *different* environment is expected, not
tampering):
- The binary depends on the exact Zig version and target; different Zig releases or
  hosts produce different bytes.
- For an exact match, use `Zig 0.13.0` on a comparable Linux host.
- The stronger guarantee this release rests on is **behavioural, not bit-level**:
  clearbit validates Bitcoin mainnet in consensus with Bitcoin Core —
  trustless-from-genesis (`--noassumevalid`), with a **byte-exact UTXO
  `hash_serialized_3` capture vs Core at C(958794)** (T2, verified), byte-exact at the
  live tip, crash-recovery 3/3, reorg-prove 11/11, boot-smoke green, full diff-test
  corpus parity. Run it beside Core with `consensus-diff` as a live divergence alarm;
  that is the intended trust model (validator, **not** custody).

## Scope of this release

- **Is:** a trustless-from-genesis validating node, byte-exact with Core (incl. a
  captured from-genesis UTXO commitment), to run beside Core in watchtower mode.
- **Is not:** fund-capable (do not custody funds — see `SECURITY.md`).
- **Filed, not gating this tag:** the P2P decoder count-amplification hardening
  (`../receipts/clearbit-decoder-amplification-2026-07-23.md`) — a custody/hostile-
  inbound-exposure item, not required for watchtower validation beside Core.

The release-gate smoke check is `tools/smoke-harness.sh --node=clearbit` (regtest boot
+ genesis-state RPC + clean shutdown), which passes at the tagged commit.
