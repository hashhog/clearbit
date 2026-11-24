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

`output/` is the recorded run from 2026-11-24, ReleaseFast binaries of master
6510c80 (`base`) and of this branch's fix commit b8eb835 (`head`):

```
base: interleaved rounds 5/5   (5x "Failed to disconnect block"; watermark above the tip in 2)
head: interleaved rounds 0/5   (5x invalidateblock ok, tip = X-1, watermark unchanged)
```

The 60 s tick fell inside the `invalidateblock` window in 5/5 base rounds and
4/5 head rounds (`output/analysis.txt`; the window is computed from the tick
schedule, since a pruner with nothing to delete prints nothing).
