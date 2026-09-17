# Changelog

## v1.0.2 — 2026-09-16

- fix: getblockchaininfo reports pruned=true + pruneheight when the height index has a snapshot prefix gap (live mainnet started at 944172 while claiming pruned=false); getblockhash of an in-range unretained height is -1 "Block not available (pruned data)", not -8. Does not backfill genesis→floor.
- fix: R5 accepts-invalid class — reject input Core rejects (combinerawtransaction -25, deriveaddresses checksum/range, getindexinfo type, signrawtransactionwithkey WIF)
- 0436b30 test: align stale audit-flip gates to Core-correct behavior
- 5866132 fix: handle repeated unresolvable REORG-CANDIDATE headers once
- 61caa89 fix: T1 R5 probe parity, min-chainwork gate, verifyCheckpoint caller
- 7d35fe4 docs: stall-class diagnosis — 132 CRITICALs are VERSION-height getheaders retry
- de18c5c fix: reconstruct nChainWork on boot from a pre-fix snapshot index
- 33337be fix: persist genesis-scale nChainWork so chainwork, IBD and nethash match Core


## v1.0.2 — 2026-09-16

Changes since `v1.0.0`:

- fix: handle a repeated/unresolvable competing-fork headers announcement once — rate-limit `REORG-CANDIDATE` (4M-line disk-fill on 2026-09-13), do not re-request a too-deep genesis-rooted 2000-header batch with the active-chain locator, keep `getblockcount` responding. Control: `zig build test-reorg-candidate-spam --summary new`
- T1 R5 probe error/shape parity vs Core (gettxoutsetinfo hash_type, addnode invalid-command, clearbanned help, getnetworkhashps type/nblocks/height, getblocktemplate segwit rule, testmempoolaccept decode); min-chainwork gate no longer skipped at assumeUTXO height; verifyCheckpoint called from insertHeader and validateBlockForIBD; AcceptBlock nMinimumChainWork skip for unrequested low-work blocks
- docs: stall-class diagnosis — 132 CRITICALs are VERSION-height getheaders retry + 2000-header REORG-CANDIDATE ingest (`docs/STALL-CLASS-132-CRITICALS.md`); no fix until a failing control exists
- reconstruct genesis-scale nChainWork on boot from a pre-fix / seed-poisoned snapshot index (do not persist GetBlockProof(genesis) as the tip key before chain_tip is loaded)
- persist genesis-scale nChainWork (Core GetBlockProof) so getblockchaininfo.chainwork, IBD and getnetworkhashps match Core
- 99b8263 docs: say the cited paths are private before the claims that rest on them
- d6c83d7 fix: root the aggregate test module at the project root — 1,779 tests never ran
- 1baacff fix: say what the header band actually proves, and check its proof of work
- 53f1361 fix: persist the snapshot base's real header, or every P2P header batch is dropped
- 3644864 feat: announce when assumevalid is disabled
- 278ebf8 feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

