# Changelog

All notable changes to clearbit are documented in this file.

## [1.0.0] - 2026-07-31

First stable release of clearbit, a Bitcoin full node written from scratch
in Zig, part of the Hashhog project.

### Highlights since v0.1.0-rc2

- **Consensus, latent hard-fork fix** (`bc7cb98`): `connectBlock` used a
  hash-less script-flag overload that skipped Core's `script_flag_exceptions`
  lookup, so historical violator blocks 170060 (BIP-16) and 692261 (Taproot)
  would be false-rejected on any full revalidation (`--noassumevalid`, a
  reorg, or the import tool). Now threads the block hash into
  `getBlockScriptFlagsForHash`.
- **Policy** (`b0332ce`): the BIP-133 feefilter advertised a hard-coded
  100 sat/vB (1000× Core's `DEFAULT_MIN_RELAY_TX_FEE`), causing peers to
  withhold nearly all transaction relay. Now sourced from
  `mempool_mod.MIN_RELAY_FEE` so the wire advertisement and the mempool
  cannot drift apart.

### Highlights since v0.1.0-rc1

- **Wallet** (`e173d5b`): `walletcreatefundedpsbt` honors `fee_rate` off
  actual vsize.
- **Wallet** (`6e2aeca`): BIP-32 ext-key decode + checksum-of-input +
  deriveaddresses range + `tr()` BIP-86 tweak.
- **RPC** (`c7c9691`): free the parsed block in `handleSubmitBlock` —
  per-submission leak + slow shutdown.
- **P2P** (`8545517`): set inbound recv timeout before the synchronous
  handshake (remote DoS).
- **AssumeUTXO**: regtest Core-parity (110/200/299) plus the
  `HASHHOG_CAMPAIGN_ASSUMEUTXO` campaign flag (`cb6a2e4`, `eaeedc9`);
  `gettxoutsetinfo`/`dumptxoutset`/muhash now hash the full CF_UTXO
  (`b2e59cc`).
- **Consensus genesis-IBD divergences fixed**: difficulty retarget at 32256
  (`ad3ab61`), timestamp MTP monotonicity (`7f0d3ed`), bad-diffbits on the
  submitblock path (`37918c7`), time-too-new on submitblock (`fea5c34`).
- **P2P sync robustness**: reconnect single `--connect` peer after drop
  (`8945ee5`), recover black-hole block wedge without the 20-min timeout
  (`8e80e4e`), batched chainstate flushes during IBD drain (`549107f`).
- **RPC parity**: Core-exact BIP-22 reject reasons + real `size_on_disk`
  (`8c9be66`); `testmempoolaccept` dry-run gains BIP-113 finality,
  input-existence, and full CheckTransaction gates (`b1a0c0a`, `14ff37c`,
  `00eceed`).

### Release engineering

- `--signet` CLI flag (signet params already shipped; the flag wires them
  up: network magic, ports 38333/38332, `signet` datadir subdir).
- Version strings bumped to 1.0.0 (`VERSION`, P2P user agent
  `/clearbit:1.0.0/`, `getnetworkinfo` subversion).
- CI re-enabled (`.github/workflows/ci.yml`, `release.yml`); release
  workflow now installs rocksdb/secp256k1 and pins Intel macOS runners.
- Test suite brought to green: stale gate-audit sentinels updated for the
  feefilter fix, the `walletprocesspsbt` dispatch, genesis `chain_work`
  seeding, Core single-event discourage (PR #25974), addrman IsRoutable
  gating, and Core's eviction-protection constants; the aggregate test root
  moved to a project-root wrapper so `src/wallet.zig`'s BIP-39 embed
  resolves (unmasking — and fixing — several latent stale tests).
- README corrected: `--testnet` runs testnet3, not testnet4.

## [0.1.0-rc2] - 2026-07

Tagged validator release candidate. Supersedes rc1: rc1 carries a latent
consensus defect (see the `bc7cb98` entry above). See REPRODUCIBLE-BUILD.md
for the pinned build recipe and artifact hash.
