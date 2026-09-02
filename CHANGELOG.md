# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-rc2`:

- f925e66 test: retarget stale expectations to Core, fix DB-less template fixtures and test-side leaks
- 6a745d7 fix(template): resolve retarget ancestors from the in-memory ring before the persisted height index
- 3758e26 fix(rpc): getdeploymentinfo reports buried deployments active from one below the activation height
- 3c37e49 fix(rpc): loadtxoutset reports an unopenable path as RPC_INVALID_PARAMETER, as Core does
- 7bd3a4f fix(rpc): signrawtransactionwithkey leaked the decoded transaction on every call
- 368c0de docs: LICENSE, Zig 0.13.0 + system-library note in README (release hygiene)
- 3842f5b fix(rpc): validate argument COUNT centrally, as Core does (#103)
- 744567c fix(test): clearbit's script + sighash consensus vector suites actually run
- bd0ba85 fix(rpc): the integer conversion runs before the lookup, and setban honours its arguments
- 0095d69 fix(rpc): round 2 of the width sweep — the arguments that were wrong, not fatal
- f0a1f5e fix(rpc): createrawtransaction and createpsbt ignored the `version` argument
- d4e38bb fix(rpc): serve the wait family on its own thread — one call stopped all RPC
- 80ecda9 fix(rpc): one waitforblock call could disable the entire RPC interface
- fb5b2d4 fix(rpc): createpsbt built outputs that paid nobody
- 5beb524 fix(rpc): four more remote node-kills + an unbounded leak in createpsbt
- 1b0cc35 fix(rpc): two more remote node-kills — gettxout and deriveaddresses
- 3ed3c13 fix(rpc): getblockhash range-checks the height — it was a remote node-kill
- c6c71ca fix: register genesis in the height and block-index records at init
- 3b982a1 fix(rpc): createrawtransaction honours Core's replaceable/sequence contradiction check
- 4ff3451 fix(rpc): createrawtransaction argument domains match Core, extending the 8e18116 cast fix
- 8e18116 fix(rpc): range-check vout/sequence/locktime before the u32 cast — one RPC call killed the node
- 9916537 feat(shim): checkblock MTP context — BIP-113 cutoff + time-based BIP-68 locks
- 4400182 test(p2p): free decoded user_agent in version round-trip test (gpa leak row)
- fb4051b fix(consensus): audit-backlog clearbit 3-row batch — BIP-68 fail-closed, template GetNextWorkRequired, FRESH provenance
- 80534a9 fix(consensus): reorg connect enforces MTP-derived gates — BIP-113 time-too-old + strict-MTP cutoff + time-based BIP-68 (#53c)
- 64bd04e feat(zmq)+fix(p2p): wire block notifications into the LIVE connect path; delete dead sync.zig; loud getheaders catches (#71e, #74)
- 62535b9 docs(sync): unmissable DEAD-MODULE banner — live behavior is peer.zig, proven by the byte-identical-sha incident
- 7301ae7 test(p2p): pin stall layers L3+L4 — extract buildGetHeadersLocator + seedForkRootParent
- b5abe1a fix(p2p): seed a competing branch's root parent from the persisted chain
- 7b97bce fix(p2p): send a real block locator, not a single tip hash
- 338e2d1 fix(sync): build the getheaders locator from the persisted chain, not the boot-empty list
- 98b0765 fix(consensus): fork-point height falls back to a bounded tip-down hash walk; basis bits fall back to the block body
- 04a4f41 fix(consensus): resolve fork-point height from the persisted chain; price forks above the fork point (#46 follow-up)
- 3818705 fix(consensus): BIP-113 cutoff must come from persisted headers, not the cold ring (#55)
- 669a63b fix(consensus): refuse reorgs with no comparable chainwork basis (#46)
- f87f504 test: give the address tracking and selection tests routable addresses
- d2a35bc test: give the ban tests routable addresses
- dc97c48 test: move the misbehaving tests onto the single-event contract
- 6b75806 test: fix the arithmetic in the header gate-ordering test
- 7194aaa test: fix a dangling stack slice in the BIP-94 coinbase helper
- 79fb2dd test: fix a use-after-free in teardown and an assertion of abandoned behaviour
- 2b69100 test: heap-allocate block index entries so teardown does not abort the suite
- 9a43a04 fix(p2p): decoded messages own their byte fields — close the receiveMessage UAF (#31)
- fa71198 fix(consensus): widen OP_PUSHDATA1 length in the BIP-342 tapscript pre-scan
- 99a3576 harden(p2p): stop retaining a dangling user_agent in version_info
- 0fade84 fix(mempool): O(n^2) -> O(n) mempool.dat load; node was absent 29+ min on restart
- 3eb2221 feat(rpc): list 21 answered-but-unlisted methods in help (R5 help-parity)
- 0c8b448 fix(rpc): double-free in address decode error paths — SIGABRT'd validateaddress on malformed input
- 736c332 feat(shim): sighash op — byte-exact legacy SignatureHash vs Core sighash.json (500/500)
- 0e801c5 fix(rpc): remove gettxoutproof/verifytxoutproof Core proxies (W67/W68) — R3(a) complete
- 98d823a fix(rpc): remove all Bitcoin Core proxies — honest not-found below the snapshot base (R3)
- 27a10c8 fix: bwmc R2 reason-code parity — emit Core CheckBlock reject tokens
- 5ddd473 fix(rpc): version-dup R2 reason parity — bad-version(0x%08x) suffix + vout-empty/dup-inputs tokens (21/21)
- 407a4e7 fix(consensus): bad-diffbits on every admitted header, not just header[0]
- cc0f1b2 fix(rpc): map FirstTxNotCoinbase to bad-cb-missing
- 0f19a5c fix(policy): Core v31 cluster mempool limits — weight units, >404000, >64

