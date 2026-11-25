#!/usr/bin/env python3
"""Submit regtest headers with an obsolete nVersion at height 1 (BIP34/66/65
all active from height 1 on regtest) to Bitcoin Core v31.1 and to clearbit
via submitheader, and print both answers.

Part 2 (audit finding 10, reorg half): extend a 2-block chain with a 3-block
side branch whose first block breaks a contextual header rule (nBits !=
required -> bad-diffbits; nTime > now + 2h -> time-too-new), via submitblock,
and print each node's answers and final tip.  If clearbit's reorg path skipped
those rules this would reorg clearbit and not Core.

Usage: python3 repro.py --bitcoind <bitcoind 31.1> --clearbit <clearbit> \
         --core-src <bitcoin source tree> --workdir <scratch dir>
"""
import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Rpc:
    def __init__(self, port, user, pw):
        self.url = f"http://127.0.0.1:{port}/"
        self.auth = base64.b64encode(f"{user}:{pw}".encode()).decode()

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, body, {"Authorization": "Basic " + self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            out = json.loads(e.read())
        if out.get("error"):
            return {"error": out["error"]}
        return out["result"]


def wait_rpc(rpc, proc, name, timeout=120):
    t = time.time()
    while time.time() - t < timeout:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited rc={proc.returncode}")
        try:
            r = rpc.call("getblockcount")
            if isinstance(r, int):
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"{name} RPC not up after {timeout}s")


def start_core(bitcoind, datadir):
    os.makedirs(datadir)
    rpcport, p2p = free_port(), free_port()
    proc = subprocess.Popen([bitcoind, "-regtest", f"-datadir={datadir}", f"-rpcport={rpcport}", f"-port={p2p}",
                             "-rpcuser=t", "-rpcpassword=t", "-listen=0", "-connect=0", "-dnsseed=0",
                             "-fixedseeds=0", "-printtoconsole=0", "-server=1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rpc = Rpc(rpcport, "t", "t")
    wait_rpc(rpc, proc, "bitcoind")
    return proc, rpc


def start_clearbit(binary, datadir):
    os.makedirs(datadir)
    rpcport, p2p = free_port(), free_port()
    log = open(os.path.join(datadir, "stdout.log"), "w")
    proc = subprocess.Popen([binary, "--regtest", f"--datadir={datadir}", f"--rpcport={rpcport}", "--rpcuser=t",
                             "--rpcpassword=t", f"--port={p2p}", "--metricsport=0", "--nodnsseed", "--nofixedseeds",
                             "--nodiscover", "--connect=127.0.0.1:1"], stdout=log, stderr=subprocess.STDOUT)
    rpc = Rpc(rpcport, "t", "t")
    wait_rpc(rpc, proc, "clearbit")
    return proc, rpc


def stop(proc, rpc):
    try:
        rpc.call("stop")
    except Exception:
        pass
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--clearbit", required=True)
    ap.add_argument("--core-src", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--label", default="clearbit", help="printed instead of the binary path")
    a = ap.parse_args()
    sys.path.insert(0, os.path.join(a.core_src, "test", "functional"))
    from test_framework.messages import CBlockHeader
    print(f"bitcoind: {subprocess.run([a.bitcoind, '-version'], capture_output=True, text=True).stdout.splitlines()[0]}")
    print(f"clearbit: {a.label}")
    wd = os.path.join(a.workdir, "run")  # only this subdirectory is ever removed
    shutil.rmtree(wd, ignore_errors=True)
    core_p, core = start_core(a.bitcoind, os.path.join(wd, "core"))
    cb_p, cb = start_clearbit(a.clearbit, os.path.join(wd, "clearbit"))
    split = False
    try:
        genesis = core.call("getbestblockhash")
        assert cb.call("getbestblockhash") == genesis
        gtime = core.call("getblockheader", genesis)["time"]

        def header(version, bits, want_top_zero_bytes):
            h = CBlockHeader()
            h.nVersion = version
            h.hashPrevBlock = int(genesis, 16)
            h.hashMerkleRoot = 0x5a5a
            h.nTime = gtime + 600
            h.nBits = bits
            h.nNonce = 0
            while True:
                hh = h.hash_int if hasattr(h, "hash_int") else int(h.hash, 16)
                if hh >> (256 - 8 * want_top_zero_bytes) == 0:
                    return h
                h.nNonce += 1

        def show(name, h):
            nonlocal split
            hx = h.serialize().hex()
            rc, rb = core.call("submitheader", hx), cb.call("submitheader", hx)
            fmt = lambda r: "null" if r is None else (r["error"].get("message") if isinstance(r, dict) and "error" in r else repr(r))
            agree = fmt(rc) == fmt(rb)
            split |= (rc is None) != (rb is None)
            print(f"{name}: core={fmt(rc)} | clearbit={fmt(rb)} | {'SAME' if agree else ('VERDICT SPLIT' if (rc is None) != (rb is None) else 'REASON DIFFERS')}")
        for v in (1, 2, 3):
            show(f"submitheader nVersion={v} height=1", header(v, 0x207fffff, 1))
        show("control submitheader nVersion=4 height=1", header(4, 0x207fffff, 1))

        from test_framework.blocktools import create_block, create_coinbase
        from test_framework.script import CScript, OP_TRUE

        def mk(prev_int, height, ntime, bits=None):
            b = create_block(prev_int, create_coinbase(height, script_pubkey=CScript([OP_TRUE])), ntime)
            if bits is not None:
                b.nBits = bits
            b.solve()
            return b

        def both(method, *args):
            return core.call(method, *args), cb.call(method, *args)

        base_t = int(time.time()) - 3000
        a1 = mk(int(genesis, 16), 1, base_t + 1)
        a2 = mk(a1.hash_int, 2, base_t + 2)
        for b in (a1, a2):
            r = both("submitblock", b.serialize().hex())
            assert r == (None, None), r
        for label, bad in (("bad-diffbits (nBits 0x207ffffe)", dict(bits=0x207ffffe)),
                           ("time-too-new (nTime now+3h)", dict(ntime=int(time.time()) + 3 * 3600))):
            b1 = mk(int(genesis, 16), 1, bad.get("ntime", base_t + 10), bad.get("bits"))
            b2 = mk(b1.hash_int, 2, max(b1.nTime, base_t + 11) + 1)
            b3 = mk(b2.hash_int, 3, b2.nTime + 1)
            answers = [both("submitblock", b.serialize().hex()) for b in (b1, b2, b3)]
            tips = both("getbestblockhash")
            fmt = lambda r: "null" if r is None else (r["error"].get("message") if isinstance(r, dict) else repr(r))
            line = "; ".join(f"core={fmt(c)} clearbit={fmt(k)}" for c, k in answers)
            same_tip = tips[0] == tips[1]
            split |= not same_tip
            print(f"side branch {label}: {line} | tip core={tips[0][:16]} clearbit={tips[1][:16]} | "
                  f"{'SAME TIP' if same_tip else 'TIP SPLIT'}")

    finally:
        stop(cb_p, cb)
        stop(core_p, core)
    print("RESULT:", "VERDICT SPLIT" if split else "NO VERDICT SPLIT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
