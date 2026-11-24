#!/usr/bin/env python3
"""Summarise <workdir>/summary-<label>.json from prune_race_regtest.py.

Per round, a pruner serialised with invalidateblock (both under cs_main) can
only end in one of two states:
  prune-first : it swept with the pre-walk tip, so watermark = tip_before-288,
                and the walk then stops AT the watermark (first missing body);
  walk-first  : the walk finished (tip = X-1, no error) and nothing in
                (watermark, tip-288] was prunable, so the watermark is unchanged.
Anything else means the sweep read the tip while the walk was moving it.
"""
import json, sys

for path in sys.argv[1:]:
    d = json.load(open(path))
    print(f"== {d['label']}")
    bad = 0
    for r in d["rounds"]:
        tip0, wm0, X = r["tip_before"], r["watermark_before"], r["X"]
        b, wm = r["after_invalidate"]["blocks"], r["after_invalidate"]["watermark"]
        tick = r["expected_tick"]
        w0, w1 = r["invalidate_window"]
        prune_first = (wm == tip0 - 288 and b == wm)
        walk_first = (r["invalidate_error"] is None and b == X - 1 and wm == wm0)
        state = "prune-first" if prune_first else "walk-first" if walk_first else "INTERLEAVED"
        bad += state == "INTERLEAVED"
        print(f"round {r['round']}: tick {tick:.3f} in window [{w0:.3f},{w1:.3f}]={w0 <= tick <= w1} "
              f"tip {tip0}->{b} watermark {wm0}->{wm} (tip_before-288={tip0-288}) "
              f"err={r['invalidate_error'] and r['invalidate_error']['message']} "
              f"watermark>tip={wm > b} => {state}")
    print(f"{d['label']}: interleaved rounds {bad}/{len(d['rounds'])}")
