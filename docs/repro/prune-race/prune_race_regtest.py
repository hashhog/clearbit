#!/usr/bin/env python3
"""Regtest stress for investigate-clearbit-prune-race.

Starts one clearbit on regtest with --prune=550 (scratch datadir under the
workdir given), mines a chain, then for N rounds times a deep invalidateblock
so the walk straddles the main-thread pruner tick (every 60 s from boot), and
reconsiderblock afterwards.  Each line of node output is timestamped as it
arrives, so we can see whether the pruner's "[prune] watermark=" line was
printed WHILE invalidateblock (which holds cs_main for the whole walk) was
still running.  If it was, the pruner ran concurrently with a cs_main holder.

Usage: prune_race_regtest.py <clearbit-bin> <workdir> <label> [rounds]
Stops its node with the `stop` RPC.
"""
import base64, json, os, socket, subprocess, sys, threading, time, urllib.request

BIN, WORK, LABEL = sys.argv[1], sys.argv[2], sys.argv[3]
ROUNDS = int(sys.argv[4]) if len(sys.argv) > 4 else 4
ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def p2wpkh_regtest(h160):
    """bech32 (BIP-173) regtest P2WPKH address for a 20-byte program."""
    hrp, cs = "bcrt", "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    acc, bits, data = 0, 0, [0]
    for b in h160:
        acc = (acc << 8) | b; bits += 8
        while bits >= 5:
            bits -= 5; data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    hx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _bech32_polymod(hx + data + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(cs[d] for d in data + chk)


assert p2wpkh_regtest(bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")) == ADDR
os.makedirs(WORK, exist_ok=True)
datadir = os.path.join(WORK, f"datadir-{LABEL}")
os.makedirs(datadir, exist_ok=True)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


rpcport, p2pport = free_port(), free_port()
args = [BIN, "--regtest", f"--datadir={datadir}", f"--rpcport={rpcport}", "--rpcuser=test",
        "--rpcpassword=test", f"--port={p2pport}", "--metricsport=0", "--nodnsseed",
        "--nofixedseeds", "--nodiscover", "--connect=127.0.0.1:1", "--prune=550"]
proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
T0 = time.monotonic()
lines = []  # (t, text)
logf = open(os.path.join(WORK, f"node-{LABEL}.log"), "w")


def reader():
    for raw in proc.stdout:
        t = time.monotonic() - T0
        txt = raw.decode(errors="replace").rstrip()
        lines.append((t, txt))
        logf.write(f"{t:9.3f} {txt}\n"); logf.flush()


threading.Thread(target=reader, daemon=True).start()
AUTH = "Basic " + base64.b64encode(b"test:test").decode()


def rpc(method, *params, timeout=600):
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{rpcport}/", data=body,
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


def out(msg):
    print(f"[{LABEL} t={time.monotonic()-T0:8.3f}] {msg}", flush=True)


for _ in range(240):
    try:
        if rpc("getblockcount", timeout=5).get("result") is not None:
            break
    except Exception:
        pass
    time.sleep(0.5)
else:
    out("node never answered"); proc.kill(); sys.exit(2)

# Mine 1400 blocks quickly (before the first tick at ~60 s).
for _ in range(14):
    r = rpc("generatetoaddress", 100, ADDR)
    if r.get("error"):
        out(f"generate error {r['error']}"); break
info = rpc("getblockchaininfo")["result"]
out(f"mined: blocks={info['blocks']} pruned={info.get('pruned')} pruneheight={info.get('pruneheight')}")


def prune_lines():
    return [(t, x) for (t, x) in lines if "[prune] watermark=" in x]


def wait_tick(n_before, limit=150):
    end = time.monotonic() + limit
    while time.monotonic() < end:
        pl = prune_lines()
        if len(pl) > n_before:
            return pl[-1]
        time.sleep(0.05)
    return None


summary = {"label": LABEL, "rounds": []}
tick = wait_tick(0)
out(f"first tick at t={tick[0]:.3f}: {tick[1]}" if tick else "no first tick")
FIRST_TICK = tick[0] if tick else 60.0
GEN = int(os.environ.get("PRUNE_RACE_GEN", "3000"))
walk_s = 0.7
for rnd in range(ROUNDS):
    n_before = len(prune_lines())
    # Extend the chain so there is a prunable lag at the next tick.
    # A fresh payout per round: after a successful invalidateblock the next
    # block would otherwise be byte-identical to the invalidated one (same
    # coinbase, same MTP+1 time) and be refused as already invalid.
    round_addr = p2wpkh_regtest(bytes([rnd + 1]) * 20)
    for _ in range(GEN // 500):
        g = rpc("generatetoaddress", 500, round_addr)
        if g.get("error"):
            out(f"generate error {g['error']}")
    info = rpc("getblockchaininfo")["result"]
    tip, ph = info["blocks"], info.get("pruneheight", 0)
    watermark0 = max(ph - 1, 0)
    X = watermark0 + 40  # deep target just above the watermark, inside the next sweep
    xhash = rpc("getblockhash", X)["result"]
    now = time.monotonic() - T0
    # The pruner ticks every 60 s from boot (main.zig PRUNE_TICK_MS); it
    # only prints when it deleted something, so anchor on the first print.
    k = int((now + walk_s / 2.0 - FIRST_TICK) // 60.0) + 1
    next_tick = FIRST_TICK + 60.0 * k
    start_at = next_tick - walk_s / 2.0
    while time.monotonic() - T0 < start_at:
        time.sleep(0.002)
    t_inv0 = time.monotonic() - T0
    r_inv = rpc("invalidateblock", xhash)
    t_inv1 = time.monotonic() - T0
    walk_s = max(0.2, t_inv1 - t_inv0)
    after_inv = rpc("getblockchaininfo")["result"]
    tk = wait_tick(n_before, limit=3)
    inside = bool(tk and t_inv0 <= tk[0] <= t_inv1)
    wm_inv = max((after_inv.get("pruneheight") or 1) - 1, 0)
    row = {
        "round": rnd, "tip_before": tip, "watermark_before": watermark0, "X": X,
        "expected_tick": round(next_tick, 3),
        "invalidate_window": [round(t_inv0, 3), round(t_inv1, 3)],
        "invalidate_error": r_inv.get("error"),
        "after_invalidate": {"blocks": after_inv["blocks"], "watermark": wm_inv},
        "prune_tick": [round(tk[0], 3), tk[1]] if tk else None,
        "prune_line_printed_inside_invalidate_window": inside,
        # A serialised pruner can never leave the raw watermark above the tip:
        # either it ran first (the walk then stops AT the watermark, on the
        # first missing body) or after (tip X-1, nothing prunable).  Above the
        # tip means it swept with the pre-walk tip while the walk ran.
        "watermark_above_tip": wm_inv > after_inv["blocks"],
    }
    summary["rounds"].append(row)
    out(json.dumps(row))

summary["any_prune_inside_cs_main_window"] = any(r["prune_line_printed_inside_invalidate_window"] for r in summary["rounds"])
summary["any_watermark_above_tip"] = any(r["watermark_above_tip"] for r in summary["rounds"])
out("SUMMARY " + json.dumps({k: v for k, v in summary.items() if k != "rounds"}))
with open(os.path.join(WORK, f"summary-{LABEL}.json"), "w") as f:
    json.dump(summary, f, indent=1)
rpc("stop", timeout=30)
try:
    proc.wait(timeout=60)
except subprocess.TimeoutExpired:
    out("node did not exit after stop RPC")
logf.close()
