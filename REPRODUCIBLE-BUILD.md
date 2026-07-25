# Reproducible build — clearbit v0.1.0-rc2

How to build the tagged clearbit validator and verify it. Part of the tagged-validator
release wrapper (see `SECURITY.md` and `../receipts/PRODUCTION-GATE.md` "three bars").

## Released artifact

| | |
|---|---|
| Tag | `clearbit v0.1.0-rc2` |
| Commit | the `v0.1.0-rc2` tag (contents: `bc7cb98` + this wrapper; see "Changes since rc1") |
| Binary | `clearbit/zig-out/bin/clearbit` (pinned to `deploy/clearbit/clearbit`) |
| **sha256** | `0e10c070e8ef5db85cdbdb0a2cdd337c1675f1c3eea05ee0a0baf74b6bbc2dbc` |
| Toolchain | `Zig 0.13.0` |
| Target | `x86_64-linux` |
| Build | `zig build -Doptimize=ReleaseFast` |

## Build

```bash
git clone git@github.com:hashhog/clearbit.git
cd clearbit
git checkout v0.1.0-rc2
# install Zig 0.13.0 (exact version matters)
zig build -Doptimize=ReleaseFast
sha256sum zig-out/bin/clearbit
```

## Changes since v0.1.0-rc1

rc1 (`e173d5b`) is **superseded**. Two of the three changes are behavioural:

- **`bc7cb98` — consensus, latent hard-fork fix.** `connectBlock` used a hash-less
  script-flag overload that skipped Core's `script_flag_exceptions` lookup. Because
  clearbit (correctly, and alone in the fleet) sets P2SH|WITNESS|TAPROOT
  unconditionally, that meant the two historical violator blocks — **170060** (BIP-16)
  and **692261** (Taproot) — would be FALSE-REJECTED on any full revalidation
  (`--noassumevalid`, a reorg, or the import tool), forking the node off mainnet.
  Now threads the block hash into `getBlockScriptFlagsForHash`. Byte order verified
  end-to-end (`crypto.computeBlockHash` raw SHA256d ↔ `consensus.hexToHash` reversal),
  since a mismatch would leave the lookup silently inert.
- **`b0332ce` — policy.** The BIP-133 feefilter advertised a hard-coded 100 sat/vB
  (1000× Core's `DEFAULT_MIN_RELAY_TX_FEE`), so peers withheld nearly all transaction
  relay. Now sourced from `mempool_mod.MIN_RELAY_FEE`.
- `4fefee3` — docs only.

**Anyone running rc1 should move to rc2.** The consensus fix is latent rather than
exploitable (zero reachability on the canonical chain, and `nMinimumChainWork` makes the
adversarial-history path impractical), but it is a genuine rule divergence.

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
