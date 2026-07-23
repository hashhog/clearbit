# Security Policy — clearbit

clearbit is a from-scratch Bitcoin full-node implementation in Zig, part of the
[hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core. Tracking Bitcoin consensus exactly is
the entire purpose of the node.

## Project maturity — read this first

clearbit is released on the **tagged-validator** bar: a node you can build, run
*beside* Bitcoin Core in watchtower mode, and trust to track consensus. It is one of
the flagship implementations, with a completed **trustless-from-genesis validation**
(`--noassumevalid`, scripts on) whose UTXO set is captured **byte-exact against
Bitcoin Core** at a common height (T2: `hash_serialized_3` @ C(958794), verified),
and it is byte-exact with Core at the live chain tip. P0 is fully green: T2 ✓,
crash-recovery 3/3 ✓, reorg-prove 11/11 ✓, boot-smoke ✓.

**It is NOT yet fund-capable.** Do not custody funds on clearbit. The intended trust
model is: run it alongside Core with `consensus-diff` as a live divergence alarm. The
funds-grade ladder (see `../receipts/PRODUCTION-GATE.md`) is a separate, in-progress
track — see the scope note below.

There are no fund-grade guarantees, and until the first tag ships no versioned
release. Run from a pinned commit.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0-rc1` (pinned `e173d5b`) | Validator RC — best-effort; no security SLA until the final `v0.1.0` |
| pre-release (`master`) | Best-effort |

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
resource-handling paths.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix.

## In scope (highest priority)

- **Consensus divergence** — clearbit accepting a block/tx Core rejects, or vice-versa.
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or decode paths.
- **Chainstate corruption on crash** (clearbit passes crash-recovery 3/3; regressions
  are in scope).

## Scope note — P2P hardening for hostile *inbound* exposure

clearbit's watchtower-validator use runs it *beside Core*, typically without accepting
inbound connections (behind NAT), so hostile-peer robustness is not required for this
bar. A known **P2P decoder count-amplification** gap (6 decoder sites bounded by
`MAX_SIZE` rather than remaining payload bytes — see
`../receipts/clearbit-decoder-amplification-2026-07-23.md`) is a **custody/hostile-
exposure hardening item**, filed and tracked. It is *not* a consensus issue and does
**not** gate the watchtower-validator tag; it must close before clearbit accepts open
public inbound (the fund-track P1.3 exposure), not before it validates beside Core.

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed.
