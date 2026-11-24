#!/usr/bin/env python3
"""Replay the script-interpreter cases against a real Bitcoin Core v31.1
regtest node and a clearbit regtest node, and print each node's verdict.

Part 1 (block consensus, submitblock): the CHECKMULTISIG empty-signature
FindAndDelete blocks below.
Part 2 (mempool policy, sendrawtransaction): P2SH / P2WSH spends that hit the
empty-signature CHECKSIG/CHECKMULTISIG encoding checks and the P2SH-wrapped
pay-to-anchor, plus a control spend both must accept.

Usage:
  python3 repro.py --bitcoind <path to bitcoind 31.1> --clearbit <path to clearbit> \
      --core-src <bitcoin source tree, for test/functional/test_framework> --workdir <scratch dir>

Each case runs on fresh datadirs for both nodes:
  1. 101 blocks, the first coinbase paying 50 BTC to the bare script
       OP_0 OP_DROP OP_3 <pk3> <pk2> <pk1> OP_3 OP_CHECKMULTISIG OP_NOT
  2. block 102 spending that coinbase with scriptSig
       OP_0 OP_0("" sig) <0x300001 not-DER sig> <sig0>
     A: sig0 signs the scriptCode with OP_0 removed (Core's FindAndDelete
        of the empty signature) -> Core: (sig0,pk1) verifies, (bad,pk2) is
        SIG_DER -> block invalid.
     B: sig0 signs the scriptCode with OP_0 kept -> Core: sig0 fails, the
        early-exit fires before the bad sig, CHECKMULTISIG false, OP_NOT true
        -> block valid.
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
    from test_framework.blocktools import create_block, create_coinbase
    from test_framework.key import ECKey
    from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
    from test_framework.script import (CScript, LegacySignatureHash, OP_0, OP_3, OP_CHECKMULTISIG, OP_DROP,
                                       OP_NOT, OP_TRUE, SIGHASH_ALL)

    keys = []
    for secret in (1, 2, 3):
        k = ECKey()
        k.set(secret.to_bytes(32, "big"), True)
        keys.append(k)
    pk1, pk2, pk3 = (k.get_pubkey().get_bytes() for k in keys)
    spk = CScript([OP_0, OP_DROP, OP_3, pk3, pk2, pk1, OP_3, OP_CHECKMULTISIG, OP_NOT])
    cleaned = CScript(bytes(spk)[1:])  # Core: FindAndDelete(scriptCode, CScript() << "") removes the OP_0

    print(f"bitcoind: {subprocess.run([a.bitcoind, '-version'], capture_output=True, text=True).stdout.splitlines()[0]}")
    print(f"clearbit: {a.label}")
    print(f"scriptPubKey: {bytes(spk).hex()}")

    results = {}
    for case, sign_over in (("A (sig0 over OP_0-deleted scriptCode)", cleaned),
                            ("B (sig0 over scriptCode with OP_0)", spk)):
        wd = os.path.join(a.workdir, case[0])
        shutil.rmtree(wd, ignore_errors=True)
        core_p, core = start_core(a.bitcoind, os.path.join(wd, "core"))
        cb_p, cb = start_clearbit(a.clearbit, os.path.join(wd, "clearbit"))
        try:
            genesis = core.call("getbestblockhash")
            assert cb.call("getbestblockhash") == genesis, "genesis differs"
            tip = int(genesis, 16)
            t0 = int(time.time()) - 2000
            first_cb = None
            for h in range(1, 102):
                coinbase = create_coinbase(h, script_pubkey=spk if h == 1 else CScript([OP_TRUE]))
                blk = create_block(tip, coinbase, t0 + h)
                blk.solve()
                hx = blk.serialize().hex()
                rc, rb = core.call("submitblock", hx), cb.call("submitblock", hx)
                if rc is not None or rb is not None:
                    raise RuntimeError(f"setup block {h}: core={rc} clearbit={rb}")
                if h == 1:
                    first_cb = coinbase
                tip = blk.hash_int if hasattr(blk, "hash_int") else int(blk.hash, 16)
            tx = CTransaction()
            tx.version = 1
            tx.vin = [CTxIn(COutPoint(first_cb.txid_int if hasattr(first_cb, "txid_int") else first_cb.sha256, 0), b"", 0xffffffff)]
            tx.vout = [CTxOut(49 * COIN, CScript([OP_TRUE]))]
            sighash, err = LegacySignatureHash(sign_over, tx, 0, SIGHASH_ALL)
            assert err is None
            sig0 = keys[0].sign_ecdsa(sighash) + bytes([SIGHASH_ALL])
            tx.vin[0].scriptSig = CScript([OP_0, OP_0, bytes.fromhex("300001"), sig0])
            blk = create_block(tip, create_coinbase(102, fees=1 * COIN), t0 + 102, txlist=[tx])
            blk.solve()
            hx = blk.serialize().hex()
            rc, rb = core.call("submitblock", hx), cb.call("submitblock", hx)
            tc, tb = core.call("getblockcount"), cb.call("getblockcount")
            print(f"case {case}: core submitblock={rc!r} height={tc} | clearbit submitblock={rb!r} height={tb} | "
                  f"{'AGREE' if (rc is None) == (rb is None) and tc == tb else 'SPLIT'}")
            results[case[0]] = (rc, rb, tc, tb)
        finally:
            stop(cb_p, cb)
            stop(core_p, core)
    split = any((rc is None) != (rb is None) or tc != tb for rc, rb, tc, tb in results.values())

    # ---- Part 2: mempool policy (STANDARD_SCRIPT_VERIFY_FLAGS) ----
    from test_framework.messages import CTxInWitness
    from test_framework.script import OP_1, OP_CHECKSIG, OP_EQUAL, OP_HASH160, hash160
    import hashlib
    uncompressed = bytes.fromhex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                 "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    hybrid = b"\x06" + uncompressed[1:]
    p2a = CScript([OP_1, bytes.fromhex("4e73")])

    def p2sh(redeem):
        return CScript([OP_HASH160, hash160(bytes(redeem)), OP_EQUAL])

    ws_uncompressed = CScript([uncompressed, OP_CHECKSIG, OP_NOT])
    out_spk = CScript([OP_0, hashlib.sha256(bytes(CScript([OP_TRUE]))).digest()])  # P2WSH(OP_TRUE)
    # (name, funding scriptPubKey, scriptSig, witness stack)
    cases = [
        ("F1 policy: P2SH CHECKMULTISIG empty sig, OP_0 in redeemScript (Core SIG_FINDANDDELETE)",
         CScript([OP_0, OP_DROP, OP_1, pk1, OP_1, OP_CHECKMULTISIG, OP_NOT]), None, None),
        ("F2a: P2WSH CHECKSIG empty sig, uncompressed key (Core WITNESS_PUBKEYTYPE)",
         CScript([OP_0, hashlib.sha256(bytes(ws_uncompressed)).digest()]), b"", [b"", bytes(ws_uncompressed)]),
        ("F2b: P2SH CHECKSIG empty sig, hybrid key (Core PUBKEYTYPE)",
         CScript([hybrid, OP_CHECKSIG, OP_NOT]), None, None),
        ("F2c: P2SH CHECKSIG empty sig, OP_0 in redeemScript (Core SIG_FINDANDDELETE)",
         CScript([OP_0, OP_DROP, pk1, OP_CHECKSIG, OP_NOT]), None, None),
        ("F3: P2SH-wrapped pay-to-anchor (Core DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)",
         p2sh(p2a), bytes(CScript([bytes(p2a)])), None),
        ("control: P2SH CHECKSIG empty sig, compressed key, no OP_0 (Core accepts)",
         CScript([pk1, OP_CHECKSIG, OP_NOT]), None, None),
    ]
    fund = []
    for name, script_or_spk, ss, wit in cases:
        if ss is None:  # a redeemScript: fund P2SH(redeem), spend with <""-or-dummy> <redeem>
            redeem = script_or_spk
            pre = [OP_0, OP_0] if b"\xae" in bytes(redeem)[-3:] else [OP_0]
            fund.append((name, p2sh(redeem), bytes(CScript(pre + [bytes(redeem)])), None))
        else:
            fund.append((name, script_or_spk, ss, wit))

    wd = os.path.join(a.workdir, "mempool")
    shutil.rmtree(wd, ignore_errors=True)
    core_p, core = start_core(a.bitcoind, os.path.join(wd, "core"))
    cb_p, cb = start_clearbit(a.clearbit, os.path.join(wd, "clearbit"))
    policy_split = False
    try:
        tip = int(core.call("getbestblockhash"), 16)
        t0 = int(time.time()) - 2000
        coinbases = []
        for h in range(1, 101 + len(fund)):
            spk_h = fund[h - 1][1] if h <= len(fund) else CScript([OP_TRUE])
            coinbase = create_coinbase(h, script_pubkey=spk_h)
            blk = create_block(tip, coinbase, t0 + h)
            blk.solve()
            hx = blk.serialize().hex()
            rc, rb = core.call("submitblock", hx), cb.call("submitblock", hx)
            if rc is not None or rb is not None:
                raise RuntimeError(f"setup block {h}: core={rc} clearbit={rb}")
            coinbases.append(coinbase)
            tip = blk.hash_int
        for i, (name, spk_i, ss, wit) in enumerate(fund):
            tx = CTransaction()
            tx.version = 2
            tx.vin = [CTxIn(COutPoint(coinbases[i].txid_int, 0), ss, 0xfffffffd)]
            tx.vout = [CTxOut(50 * COIN - 20000, out_spk)]
            if wit is not None:
                tx.wit.vtxinwit = [CTxInWitness()]
                tx.wit.vtxinwit[0].scriptWitness.stack = wit
            hx = tx.serialize().hex()
            rc, rb = core.call("sendrawtransaction", hx), cb.call("sendrawtransaction", hx)
            fmt = lambda r: ("accept" if isinstance(r, str) else "reject: " + str(r["error"].get("message")))
            same = (isinstance(rc, str)) == (isinstance(rb, str))
            policy_split |= not same
            print(f"{name}: core={fmt(rc)} | clearbit={fmt(rb)} | {'AGREE' if same else 'SPLIT'}")
    finally:
        stop(cb_p, cb)
        stop(core_p, core)

    print("RESULT blocks:", "SPLIT" if split else "AGREE")
    print("RESULT mempool:", "SPLIT" if policy_split else "AGREE")
    return 1 if (split or policy_split) else 0


if __name__ == "__main__":
    sys.exit(main())
