# Changelog

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

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

