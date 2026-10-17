# Security policy

clearbit is an experimental, independent implementation of a Bitcoin full node. It is meant for research and testing. Do not use it to hold or move real funds.

## Supported versions

Only the latest `master` receives fixes. There are no long-term support releases and no response-time guarantee.

## Reporting a vulnerability

Please do not open a public GitHub issue for a problem in consensus, P2P or wallet code. A public report can put other nodes at risk before a fix exists.

Email the maintainer at `max@dockyard.navy` with:

- the affected component and commit,
- a reproduction: a regtest script, a block or transaction in hex, or a malformed P2P message,
- what happens and what you expected (ideally what Bitcoin Core does with the same input),
- a suggested fix, if you have one.

You will get an acknowledgement, a fix and disclosure timeline agreed with you, and credit if you want it.

## In scope

- Consensus divergence: clearbit accepting a block or transaction that Bitcoin Core rejects, or rejecting one Core accepts.
- Remotely triggerable crashes, hangs, memory exhaustion or disk exhaustion through P2P messages, or through RPC on a port bound beyond localhost.
- Chainstate corruption after a crash or power loss.
- Wallet bugs that sign with the wrong key, produce a transaction the network rejects, compute a wrong fee, or lose keys.

## Out of scope

- Sync speed and resource use that is merely high.
- Attacks that need an already compromised host or access to the datadir.
- Exposing the RPC, REST or metrics port to an untrusted network. RPC is protected by the cookie or password, but REST and metrics have no authentication. The metrics port (9332) listens on all interfaces by default; turn it off with `--metricsport=0` or firewall it.

## Known hardening gaps

- Some P2P message decoders bound element counts by the protocol maximum rather than by the bytes actually remaining in the message, so a hostile peer can make the node allocate more than the message size justifies. Prefer outbound-only operation, or a firewall in front of the P2P port, until this is fixed.
- Release builds use `ReleaseFast`, which removes Zig's runtime safety checks (integer overflow, bounds). A bug that a `ReleaseSafe` or Debug build would stop with a panic can instead continue silently in a `ReleaseFast` build. Build with `-Doptimize=ReleaseSafe` if you prefer a crash to undefined behaviour.

## Wallet caveats

The wallet has not been reviewed for custody. Wallet files live under `<datadir>/<network>/wallets/<name>/` and include the HD seed. They are not encrypted unless you call `encryptwallet`; protect the datadir accordingly.
