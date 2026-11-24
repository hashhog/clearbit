# Repro: auto-pruner racing a cs_main holder (regtest)

`prune_race_regtest.py <clearbit-bin> <workdir> <label> [rounds]` starts one
clearbit on regtest with `--prune=550` (datadir under `<workdir>`), mines 1400
blocks, waits for the first pruner tick (`main.zig`, every 60 s from boot),
then for each round mines 3000 blocks to a fresh address and sends
`invalidateblock` for the block 40 above the prune watermark, timed so that the
walk straddles the next tick. It stops the node with the `stop` RPC.

`analyze_stress.py <workdir>/summary-*.json` classifies each round. A pruner
serialised with the walk (both under cs_main) can only end in one of two states:

- prune-first: watermark = tip_before − 288, and the walk stops at it
- walk-first: tip = X − 1, watermark unchanged

Any other end state means the sweep read a tip that the walk was still moving.

Run it in a local scratch workdir of your own (not committed), once per
binary, then summarise both runs:

```
python3 prune_race_regtest.py <base-clearbit-bin> <workdir> base 5
python3 prune_race_regtest.py <head-clearbit-bin> <workdir> head 5
python3 analyze_stress.py <workdir>/summary-base.json <workdir>/summary-head.json
```

The script writes `datadir-<label>/`, `node-<label>.log` and
`summary-<label>.json` under `<workdir>`; delete the workdir when done. The
2026-11-24 runs used ReleaseFast builds (`zig build -Doptimize=ReleaseFast`).
On a binary with the race, rounds end INTERLEAVED
(`invalidateblock` fails with "Failed to disconnect block", sometimes with the
watermark above the tip); with the pruners under cs_main every round ends
prune-first or walk-first. The tick window is computed from the tick
schedule, since a pruner with nothing to delete prints nothing.
