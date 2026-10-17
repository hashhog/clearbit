# Contributing to clearbit

Thank you for helping. clearbit is a from-scratch Bitcoin node, so correctness matters more than features or speed.

## Build and test

See [docs/building.md](docs/building.md) for Zig 0.13.0 and the system packages. Then:

```bash
zig build -Doptimize=ReleaseFast
zig build test
```

Before opening a pull request, run the tests and check that your change does not add failures. For a change to the script interpreter, also run Core's vectors with `zig build test-script test-sighash` ([docs/status.md](docs/status.md)).

Run `zig fmt` on the files you change. The tree is not `zig fmt`-clean as a whole (about 50 files differ), so do not reformat files you are not otherwise touching.

## Pull requests

- Every behaviour change comes with a test that fails before the change and passes after it. Name the test in the pull request description.
- New tests go in the module they test, or in a `src/tests_*.zig` file wired into `build.zig`. A test file that is not reachable from a build step never runs, so check that your test actually appears in the `zig build test --summary all` output.
- Keep each pull request to one change. Refactors go in their own pull request.
- Do not disable or delete a test without explaining why in the pull request.
- Branch from and target `master`.

## Commit messages

Use a conventional prefix and explain why the change is needed, not only what it does:

```
fix(rpc): return -8 for an out-of-range height in getblockhash

Core returns RPC_INVALID_PARAMETER (-8) here; we returned -1, which broke
clients that match on the code.
```

Common prefixes: `fix`, `feat`, `perf`, `refactor`, `test`, `docs`, `chore`. A scope in parentheses (`consensus`, `p2p`, `rpc`, `storage`, `wallet`) helps reviewers.

## Consensus changes

Anything that can change whether a block or transaction is accepted (script, validation, UTXO handling, chain selection, reorganisations) needs evidence that clearbit behaves like Bitcoin Core afterwards. Point to the Core source that defines the behaviour, add a test with the concrete input (Core's test vectors where they exist), and describe how the change could make a valid block invalid or an invalid block valid, and which test covers that. Where possible, show the same input on Core and on clearbit giving the same result, for example on regtest as in [docs/status.md](docs/status.md).
