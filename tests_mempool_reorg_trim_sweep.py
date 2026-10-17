#!/usr/bin/env python3
"""Regtest sweep: clearbit vs Bitcoin Core v31.1 on reorg cluster trim.

Core builds and signs every transaction. clearbit receives the same blocks
(submitblock) and the same raw transactions (sendrawtransaction), then both
nodes invalidateblock / reconsiderblock. Mempool txid sets, verbose entries,
and getblocktemplate fields are compared locally. No outbound peers.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

MAX_CLUSTER = 64
MAX_CLUSTER_WEIGHT = 404_000
CORE_TARBALL_SHA256 = "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"

# getrawmempool `time` is the local admission clock.
JUSTIFIED_VERBOSE = {"time"}
# GBT clock fields. mintime is compared too and only justified when it matches;
# a mismatch is recorded as a real field difference.
JUSTIFIED_GBT_TOP = {"curtime"}


class RpcError(Exception):
    def __init__(self, method, error):
        super().__init__(f"{method}: {error}")
        self.method = method
        self.error = error


class Rpc:
    def __init__(self, url, user, password, timeout=180):
        self.url = url
        self.timeout = timeout
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth = f"Basic {token}"

    def call(self, method, params):
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                raise RpcError(method, f"HTTP {e.code}: {raw[:500]}") from e
        if payload.get("error"):
            raise RpcError(method, payload["error"])
        return payload.get("result")

    def __getattr__(self, method):
        def fn(*params):
            return self.call(method, list(params))

        return fn


def sats_of(value):
    """BTC JSON number or already-integer satoshis -> satoshis."""
    if isinstance(value, bool):
        raise TypeError(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(round(value * 100_000_000))
    text = str(value)
    if "." in text:
        whole, frac = text.split(".", 1)
        frac = (frac + "00000000")[:8]
        sign = -1 if whole.startswith("-") else 1
        whole = whole.lstrip("-") or "0"
        return sign * (int(whole) * 100_000_000 + int(frac))
    return int(text)


def btc_amount(sats):
    sign = "-" if sats < 0 else ""
    sats = abs(int(sats))
    return f"{sign}{sats // 100_000_000}.{sats % 100_000_000:08d}"


def txid_key(txid_hex):
    """Internal (memcmp) order, matching Hash256 byte order."""
    return bytes.fromhex(txid_hex)[::-1]


def wait_rpc(rpc, seconds=120):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        try:
            rpc.getblockcount()
            return
        except Exception as exc:  # noqa: BLE001 - node still booting
            last = exc
            time.sleep(0.4)
    raise RuntimeError(f"RPC never came up: {last}")


def start_proc(argv, log_path, env):
    log = open(log_path, "w")
    proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env)
    proc._sweep_log = log
    return proc


def stop_node(rpc, proc):
    try:
        rpc.stop()
    except Exception:
        pass
    try:
        proc.wait(timeout=40)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    log = getattr(proc, "_sweep_log", None)
    if log:
        log.close()


class Sweep:
    def __init__(self, args):
        self.args = args
        self.report = {
            "core_tarball_sha256": None,
            "core_version": None,
            "scenarios": [],
        }
        self.mismatches = []
        self.core = None
        self.cb = None
        self.core_proc = None
        self.cb_proc = None
        root = args.workdir
        self.core_dir = os.path.join(root, "core")
        self.cb_dir = os.path.join(root, "clearbit")

    def log(self, msg):
        print(msg, flush=True)

    def verify_tarball(self):
        path = self.args.tarball
        if not path or not os.path.exists(path):
            self.log("tarball not present; skipping SHA256 re-check")
            return
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        sums = os.path.join(os.path.dirname(path), "SHA256SUMS")
        listed = None
        if os.path.exists(sums):
            name = os.path.basename(path)
            for line in open(sums):
                if line.strip().endswith(name):
                    listed = line.split()[0]
                    break
        ok = digest == CORE_TARBALL_SHA256 and (listed is None or listed == digest)
        self.report["core_tarball_sha256"] = {
            "path": path,
            "sha256": digest,
            "expected": CORE_TARBALL_SHA256,
            "sums_file": listed,
            "ok": ok,
        }
        self.log(f"SHA256 {digest} ok={ok}")
        if not ok:
            raise SystemExit("Bitcoin Core tarball SHA256 mismatch")

    def start_nodes(self):
        shutil.rmtree(self.args.workdir, ignore_errors=True)
        os.makedirs(self.core_dir, exist_ok=True)
        os.makedirs(self.cb_dir, exist_ok=True)
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = "/usr/local/lib" + (
            ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else ""
        )
        self.core_proc = start_proc(
            [
                self.args.bitcoind,
                "-regtest",
                f"-datadir={self.core_dir}",
                "-port=18444",
                "-bind=127.0.0.1",
                "-rpcbind=127.0.0.1",
                "-rpcport=18443",
                "-rpcallowip=127.0.0.1",
                "-rpcuser=cb",
                "-rpcpassword=cb",
                "-connect=0",
                "-dnsseed=0",
                "-listen=1",
                "-fallbackfee=0.00001",
                "-printtoconsole",
            ],
            os.path.join(self.args.workdir, "core.log"),
            env,
        )
        self.cb_proc = start_proc(
            [
                self.args.clearbit,
                "--regtest",
                f"--datadir={self.cb_dir}",
                "--port=19444",
                "--rpcbind=127.0.0.1",
                "--rpcport=19443",
                "--rpcuser=cb",
                "--rpcpassword=cb",
                "--nodnsseed",
                "--nofixedseeds",
                "--nodiscover",
            ],
            os.path.join(self.args.workdir, "clearbit.log"),
            env,
        )
        self.core = Rpc("http://127.0.0.1:18443", "cb", "cb")
        self.cb = Rpc("http://127.0.0.1:19443", "cb", "cb")
        wait_rpc(self.core)
        wait_rpc(self.cb, seconds=180)
        self.core.createwallet("sweep")
        self.core = Rpc("http://127.0.0.1:18443/wallet/sweep", "cb", "cb")
        info = self.core.getnetworkinfo()
        self.report["core_version"] = {
            "subversion": info.get("subversion"),
            "version": info.get("version"),
        }
        self.log(f"core up {info.get('subversion')} clearbit height {self.cb.getblockcount()}")

    def sync(self):
        target = self.core.getblockcount()
        target_hash = self.core.getbestblockhash()
        guard = 0
        while self.cb.getblockcount() < target or self.cb.getbestblockhash() != target_hash:
            guard += 1
            if guard > target + 5:
                raise RuntimeError(
                    f"sync stalled core={target} {target_hash} cb={self.cb.getblockcount()} {self.cb.getbestblockhash()}"
                )
            nxt = self.cb.getblockcount() + 1
            if nxt > target:
                raise RuntimeError(
                    f"height caught up but tip differs core={target_hash} cb={self.cb.getbestblockhash()}"
                )
            bhash = self.core.getblockhash(nxt)
            raw = self.core.getblock(bhash, 0)
            res = self.cb.submitblock(raw)
            if res not in (None, "duplicate"):
                raise RuntimeError(f"submitblock height {nxt} {bhash}: {res}")
            if nxt % 20 == 0 or nxt == target:
                self.log(f"  synced height {nxt}/{target}")

    def mine(self, n=1):
        hashes = self.core.generatetoaddress(n, self.core.getnewaddress())
        self.sync()
        return hashes

    def mempool_empty_both(self):
        return self.core.getrawmempool() == [] and self.cb.getrawmempool() == []

    def sweep_mempool(self):
        if self.mempool_empty_both():
            return
        self.mine(1)
        if not self.mempool_empty_both():
            raise RuntimeError(
                f"mempool not empty after mining core={self.core.getrawmempool()} cb={self.cb.getrawmempool()}"
            )

    def pick_utxo(self, need_sats):
        for utxo in self.core.listunspent(1, 9999999):
            sats = sats_of(utxo["amount"])
            if sats >= need_sats and utxo["confirmations"] >= 100 and utxo["spendable"]:
                return utxo["txid"], utxo["vout"], sats
        raise RuntimeError(f"no mature coin with {need_sats} sats")

    def signed_tx(self, txid, vout, outputs, locktime=0):
        """outputs: list of (address, sats) or ('data', hex). Exact satoshi amounts."""
        parts = []
        for key, val in outputs:
            if key == "data":
                parts.append(json.dumps({"data": val}))
            else:
                parts.append("{" + json.dumps(key) + ":" + btc_amount(val) + "}")
        params = (
            "["
            + json.dumps([{"txid": txid, "vout": vout}])
            + ","
            + "["
            + ",".join(parts)
            + "],"
            + str(int(locktime))
            + "]"
        )
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "sweep", "method": "createrawtransaction", "params": None}
        )
        # params must stay exact decimals, so splice the raw JSON array in.
        body = body.replace('"params": null', '"params": ' + params)
        req = urllib.request.Request(
            self.core.url,
            data=body.encode(),
            headers={"Authorization": self.core.auth, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode())
        if payload.get("error"):
            raise RpcError("createrawtransaction", payload["error"])
        signed = self.core.signrawtransactionwithwallet(payload["result"])
        if not signed.get("complete"):
            raise RuntimeError(f"sign failed: {signed}")
        decoded = self.core.decoderawtransaction(signed["hex"])
        return signed["hex"], decoded["txid"], decoded["weight"], decoded["vsize"]

    def opreturn_at(self, txid, vout, value_sats, data_len, fill, extra=None):
        extra = extra or []
        payload = (bytes([fill]) * data_len).hex()
        outputs = list(extra) + [("data", payload)]
        hexraw, txid_out, weight, vsize = self.signed_tx(txid, vout, outputs)
        return (hexraw, txid_out, weight, vsize, data_len)

    def sized_opreturn(self, txid, vout, value_sats, target_weight, fill, extra=None, tol=1500):
        """1-input tx whose non-data outputs are `extra`. Fee is value minus extras."""
        extra = extra or []
        extra_sats = sum(v for key, v in extra if key != "data")
        if extra_sats > value_sats:
            raise RuntimeError("extra outputs exceed input value")
        lo, hi = 1, 90_000
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            cand = self.opreturn_at(txid, vout, value_sats, mid, fill, extra)
            if best is None or abs(cand[2] - target_weight) < abs(best[2] - target_weight):
                best = cand
            if cand[2] < target_weight:
                lo = mid + 1
            elif cand[2] > target_weight:
                hi = mid - 1
            else:
                break
        if best is None or abs(best[2] - target_weight) > tol:
            got = None if best is None else best[2]
            raise RuntimeError(f"could not size tx near {target_weight} WU (got {got})")
        return best  # hex, txid, weight, vsize, data_len

    def broadcast(self, hexraw):
        ctxid = self.core.sendrawtransaction(hexraw, 0)
        try:
            btxid = self.cb.sendrawtransaction(hexraw, 0)
        except RpcError as exc:
            raise RuntimeError(f"clearbit rejected {ctxid}: {exc}") from exc
        if ctxid != btxid:
            raise RuntimeError(f"txid mismatch core={ctxid} clearbit={btxid}")
        return ctxid

    def make_parent(self, output_sats):
        fee = 10_000
        need = sum(output_sats) + fee + 50_000
        utxo_txid, utxo_vout, utxo_sats = self.pick_utxo(need)
        change = utxo_sats - sum(output_sats) - fee
        outputs = []
        for value in output_sats:
            outputs.append((self.core.getnewaddress(), value))
        outputs.append((self.core.getnewaddress(), change))
        hexraw, txid, weight, vsize = self.signed_tx(utxo_txid, utxo_vout, outputs)
        self.broadcast(hexraw)
        block_hashes = self.mine(1)
        return {
            "txid": txid,
            "weight": weight,
            "vsize": vsize,
            "fee": fee,
            "block": block_hashes[0],
            "n_child_outputs": len(output_sats),
        }

    def spend_child(self, parent_txid, vout, input_sats, fee):
        if fee >= input_sats:
            raise RuntimeError("fee consumes the output")
        dest = input_sats - fee
        hexraw, txid, weight, vsize = self.signed_tx(
            parent_txid, vout, [(self.core.getnewaddress(), dest)]
        )
        self.broadcast(hexraw)
        return {"txid": txid, "fee": fee, "weight": weight, "vsize": vsize, "vout": vout}

    def record(self, kind, detail):
        self.mismatches.append({"kind": kind, **detail})

    def tips(self, node):
        return {"hash": node.getbestblockhash(), "height": node.getblockcount()}

    def compare_tips(self, phase):
        a, b = self.tips(self.core), self.tips(self.cb)
        if a != b:
            self.record("tip", {"phase": phase, "core": a, "clearbit": b})
        return a, b, a == b

    def compare_verbose(self, phase):
        core_pool = self.core.getrawmempool(True)
        cb_pool = self.cb.getrawmempool(True)
        core_ids, cb_ids = set(core_pool), set(cb_pool)
        if core_ids != cb_ids:
            self.record(
                "txid-set",
                {
                    "phase": phase,
                    "only_core": sorted(core_ids - cb_ids),
                    "only_clearbit": sorted(cb_ids - core_ids),
                    "core_count": len(core_ids),
                    "clearbit_count": len(cb_ids),
                },
            )
        field_miss = {}
        for txid in sorted(core_ids & cb_ids):
            c, b = core_pool[txid], cb_pool[txid]
            keys = set(c) | set(b)
            for key in sorted(keys):
                if key in JUSTIFIED_VERBOSE:
                    continue
                cv, bv = c.get(key, "<absent>"), b.get(key, "<absent>")
                if key == "fees" and cv != "<absent>" and bv != "<absent>":
                    cv = {k: sats_of(v) for k, v in cv.items()}
                    bv = {k: sats_of(v) for k, v in bv.items()}
                if cv != bv:
                    bucket = field_miss.setdefault(key, {"count": 0, "example": None})
                    bucket["count"] += 1
                    if bucket["example"] is None:
                        bucket["example"] = {"txid": txid, "core": cv, "clearbit": bv}
        for key, info in field_miss.items():
            self.record("verbose", {"phase": phase, "field": key, **info})
        return core_pool, cb_pool

    def compare_gbt(self, phase):
        try:
            cg = self.core.getblocktemplate({"rules": ["segwit"]})
        except RpcError as exc:
            self.record("gbt", {"phase": phase, "core_error": str(exc)})
            return
        try:
            bg = self.cb.getblocktemplate({"rules": ["segwit"]})
        except RpcError as exc:
            self.record("gbt", {"phase": phase, "clearbit_error": str(exc)})
            return
        top_keys = set(cg) | set(bg)
        for key in sorted(top_keys - {"transactions"} - JUSTIFIED_GBT_TOP):
            cv, bv = cg.get(key, "<absent>"), bg.get(key, "<absent>")
            if cv != bv:
                shown_c, shown_b = cv, bv
                if key == "transactions":
                    continue
                # Keep long values readable.
                if isinstance(cv, str) and len(cv) > 80:
                    shown_c = cv[:80] + "..."
                if isinstance(bv, str) and len(bv) > 80:
                    shown_b = bv[:80] + "..."
                self.record(
                    "gbt-top",
                    {"phase": phase, "field": key, "core": shown_c, "clearbit": shown_b},
                )
        ct = cg.get("transactions") or []
        bt = bg.get("transactions") or []
        c_ids = [t["txid"] for t in ct]
        b_ids = [t["txid"] for t in bt]
        if c_ids != b_ids:
            self.record(
                "gbt-order",
                {"phase": phase, "core": c_ids, "clearbit": b_ids},
            )
        by_b = {t["txid"]: t for t in bt}
        missing_fields = {}
        value_miss = {}
        for i, tx in enumerate(ct):
            other = by_b.get(tx["txid"])
            if other is None:
                continue
            for field in ("fee", "weight", "sigops", "depends", "data", "hash"):
                if field not in other:
                    missing_fields.setdefault(field, {"count": 0, "example_core": None})
                    missing_fields[field]["count"] += 1
                    if missing_fields[field]["example_core"] is None:
                        missing_fields[field]["example_core"] = {
                            "txid": tx["txid"],
                            "core": tx.get(field),
                        }
                    continue
                cv, bv = tx.get(field), other.get(field)
                if field == "data":
                    if cv != bv:
                        value_miss.setdefault(field, {"count": 0, "example": None})
                        value_miss[field]["count"] += 1
                        if value_miss[field]["example"] is None:
                            value_miss[field]["example"] = {
                                "txid": tx["txid"],
                                "core_len": len(cv or ""),
                                "clearbit_len": len(bv or ""),
                            }
                    continue
                if field == "depends":
                    # Core indexes are 1-based into the template. Compare the
                    # resolved parent txids so an order difference is not
                    # double-counted as a depends difference.
                    def resolve(template, deps):
                        out = []
                        for d in deps or []:
                            idx = d - 1
                            if 0 <= idx < len(template):
                                out.append(template[idx]["txid"])
                            else:
                                out.append(f"<bad {d}>")
                        return out

                    cv, bv = resolve(ct, cv), resolve(bt, bv)
                if cv != bv:
                    value_miss.setdefault(field, {"count": 0, "example": None})
                    value_miss[field]["count"] += 1
                    if value_miss[field]["example"] is None:
                        value_miss[field]["example"] = {
                            "txid": tx["txid"],
                            "index": i,
                            "core": cv,
                            "clearbit": bv,
                        }
        for field, info in missing_fields.items():
            self.record("gbt-missing", {"phase": phase, "field": field, **info})
        for field, info in value_miss.items():
            self.record("gbt-field", {"phase": phase, "field": field, **info})
        # Parent-before-child, using Core's depends as the edge list.
        def index_of(ids):
            return {txid: i for i, txid in enumerate(ids)}

        ci, bi = index_of(c_ids), index_of(b_ids)
        violations = []
        for tx in ct:
            child = tx["txid"]
            for dep in tx.get("depends") or []:
                parent = ct[dep - 1]["txid"]
                for side, idx in (("core", ci), ("clearbit", bi)):
                    if parent not in idx or child not in idx:
                        continue
                    if idx[parent] > idx[child]:
                        violations.append(
                            {"side": side, "parent": parent, "child": child}
                        )
        if violations:
            self.record("gbt-parent-order", {"phase": phase, "violations": violations})

    def invalidate(self, blockhash):
        cr = self.core.invalidateblock(blockhash)
        br = self.cb.invalidateblock(blockhash)
        if cr != br:
            self.record(
                "invalidate-result",
                {"block": blockhash, "core": cr, "clearbit": br},
            )
        tips_ok = self.compare_tips("after-invalidate")[2]
        return cr, br, tips_ok

    def reconsider(self, blockhash):
        cr = self.core.reconsiderblock(blockhash)
        br = self.cb.reconsiderblock(blockhash)
        if cr != br:
            self.record(
                "reconsider-result",
                {"block": blockhash, "core": cr, "clearbit": br},
            )
        tips_ok = self.compare_tips("after-reconsider")[2]
        return cr, br, tips_ok

    def snapshot(self, name, expect_dropped, expect_kept):
        """Compare pools and GBT. expect_* are txids Core should have dropped/kept."""
        before = len(self.mismatches)
        core_pool, cb_pool = self.compare_verbose(name)
        self.compare_gbt(name)
        core_ids = set(core_pool)
        dropped_ok = core_ids == set(expect_kept) and not (core_ids & set(expect_dropped))
        cb_ids = set(cb_pool)
        same = core_ids == cb_ids
        new = self.mismatches[before:]
        scenario = {
            "name": name,
            "core_count": len(core_ids),
            "clearbit_count": len(cb_ids),
            "txid_set_match": same,
            "core_dropped_expected": dropped_ok,
            "expect_dropped": expect_dropped,
            "core_has_dropped": [t for t in expect_dropped if t in core_ids],
            "clearbit_has_dropped": [t for t in expect_dropped if t in cb_ids],
            "mismatch_kinds": sorted({m["kind"] for m in new}),
        }
        self.report["scenarios"].append(scenario)
        self.log(
            f"{name}: core={len(core_ids)} clearbit={len(cb_ids)} "
            f"set_match={same} core_drop_ok={dropped_ok} new_mismatches={len(new)}"
        )
        return scenario

    def fanout(self, name, n_children, expect_drop_lowest):
        self.sweep_mempool()
        per = 200_000
        parent = self.make_parent([per] * n_children)
        children = []
        for i in range(n_children):
            fee = 1_000 + i * 100  # index 0 is the lowest fee, same size
            children.append(self.spend_child(parent["txid"], i, per, fee))
        pre_core = set(self.core.getrawmempool())
        pre_cb = set(self.cb.getrawmempool())
        child_ids = {c["txid"] for c in children}
        if pre_core != child_ids or pre_cb != child_ids:
            self.record(
                "pre-invalidate-set",
                {
                    "phase": name,
                    "only_core": sorted(pre_core - child_ids),
                    "only_clearbit": sorted(pre_cb - child_ids),
                    "missing_core": sorted(child_ids - pre_core),
                    "missing_clearbit": sorted(child_ids - pre_cb),
                },
            )
        inv = self.invalidate(parent["block"])
        dropped = [children[0]["txid"]] if expect_drop_lowest else []
        kept = [parent["txid"]] + [c["txid"] for c in children if c["txid"] not in dropped]
        snap = self.snapshot(name, dropped, kept)
        snap["invalidate_core"] = inv[0]
        snap["invalidate_clearbit"] = inv[1]
        snap["invalidate_tips_match"] = inv[2]
        rec_core, rec_cb, rec_tips = self.reconsider(parent["block"])
        snap["reconsider_core"] = rec_core
        snap["reconsider_clearbit"] = rec_cb
        snap["reconsider_tips_match"] = rec_tips
        snap["parent"] = parent["txid"]
        snap["lowest_child"] = children[0]["txid"]
        snap["block"] = parent["block"]
        self.sweep_mempool()
        return snap

    def weight_case(self):
        self.sweep_mempool()
        low_fee, high_fee = 20_000, 2_000_000
        parent = self.make_parent([low_fee, high_fee])
        low = self.sized_opreturn(parent["txid"], 0, low_fee, 240_000, 0x11)
        high = self.sized_opreturn(parent["txid"], 1, high_fee, 190_000, 0x22)
        # low/high: hex, txid, weight, vsize, data_len
        if not (low[2] > high[2] and low_fee * high[2] < high_fee * low[2]):
            raise RuntimeError(f"feerate setup failed low={low[2:]} high={high[2:]}")
        if parent["weight"] + low[2] + high[2] <= MAX_CLUSTER_WEIGHT:
            raise RuntimeError("cluster does not exceed the weight limit")
        if parent["weight"] + high[2] > MAX_CLUSTER_WEIGHT:
            raise RuntimeError("high child does not fit with the parent")
        self.broadcast(low[0])
        self.broadcast(high[0])
        inv = self.invalidate(parent["block"])
        snap = self.snapshot(
            "weight",
            [low[1]],
            [parent["txid"], high[1]],
        )
        snap["invalidate_core"] = inv[0]
        snap["invalidate_clearbit"] = inv[1]
        snap["invalidate_tips_match"] = inv[2]
        snap["low_weight"] = low[2]
        snap["high_weight"] = high[2]
        snap["parent_weight"] = parent["weight"]
        _, _, rec_tips = self.reconsider(parent["block"])
        snap["reconsider_tips_match"] = rec_tips
        self.sweep_mempool()
        return snap

    def disagree_case(self):
        self.sweep_mempool()
        a_fee, d_fee, b_fee = 60_000, 2_000_000, 50_000
        parent = self.make_parent([a_fee + d_fee, b_fee])
        # A: spendable output (D's input) + OP_RETURN. B: OP_RETURN only.
        dest = self.core.getnewaddress()
        a = self.sized_opreturn(
            parent["txid"],
            0,
            a_fee + d_fee,
            150_000,
            0x31,
            extra=[(dest, d_fee)],
        )
        b = self.sized_opreturn(parent["txid"], 1, b_fee, 250_000, 0x32)
        self.broadcast(a[0])
        self.broadcast(b[0])
        # D spends A's vout 0. Brute the OP_RETURN byte so D's txid memcmp-sorts last.
        probe = self.sized_opreturn(a[1], 0, d_fee, 70_000, 1)
        d = None
        for fill in range(1, 256):
            trial = self.opreturn_at(a[1], 0, d_fee, probe[4], fill)
            if (
                txid_key(trial[1]) > txid_key(a[1])
                and txid_key(trial[1]) > txid_key(b[1])
                and txid_key(trial[1]) > txid_key(parent["txid"])
            ):
                d = trial
                break
        if d is None:
            raise RuntimeError("could not find a D txid above A, B, and P")
        chunk_fee = a_fee + d_fee
        chunk_w = a[2] + d[2]
        if chunk_fee * b[2] <= b_fee * chunk_w:
            raise RuntimeError("AD chunk does not beat B")
        total = parent["weight"] + a[2] + b[2] + d[2]
        keep = parent["weight"] + a[2] + d[2]
        if total <= MAX_CLUSTER_WEIGHT or keep > MAX_CLUSTER_WEIGHT:
            raise RuntimeError(f"weight window missed total={total} keep={keep}")
        self.broadcast(d[0])
        # D is last-added, deepest, and the highest txid. Trim must drop B.
        inv = self.invalidate(parent["block"])
        snap = self.snapshot(
            "disagree",
            [b[1]],
            [parent["txid"], a[1], d[1]],
        )
        snap["invalidate_core"] = inv[0]
        snap["invalidate_clearbit"] = inv[1]
        snap["invalidate_tips_match"] = inv[2]
        snap["d_txid"] = d[1]
        snap["b_txid"] = b[1]
        snap["weights"] = {
            "P": parent["weight"],
            "A": a[2],
            "B": b[2],
            "D": d[2],
        }
        _, _, rec_tips = self.reconsider(parent["block"])
        snap["reconsider_tips_match"] = rec_tips
        self.sweep_mempool()
        return snap

    def multiblock(self):
        self.sweep_mempool()
        n = 64
        per = 200_000
        parent = self.make_parent([per] * n)
        # Build every child, mine only the highest-fee one, leave the rest in the pool.
        built = []
        for i in range(n):
            fee = 1_000 + i * 100
            dest = per - fee
            hexraw, txid, weight, vsize = self.signed_tx(
                parent["txid"], i, [(self.core.getnewaddress(), dest)]
            )
            built.append(
                {"hex": hexraw, "txid": txid, "fee": fee, "weight": weight, "vout": i}
            )
        top = built[-1]
        self.broadcast(top["hex"])
        top_block = self.mine(1)[0]
        for child in built[:-1]:
            self.broadcast(child["hex"])
        pre = set(self.core.getrawmempool())
        if pre != {c["txid"] for c in built[:-1]}:
            raise RuntimeError(f"pre-invalidate mempool {len(pre)} != 63")
        inv = self.invalidate(parent["block"])
        dropped = [built[0]["txid"]]
        kept = [parent["txid"], top["txid"]] + [c["txid"] for c in built[1:-1]]
        snap = self.snapshot("multiblock", dropped, kept)
        snap["invalidate_core"] = inv[0]
        snap["invalidate_clearbit"] = inv[1]
        snap["invalidate_tips_match"] = inv[2]
        snap["parent_block"] = parent["block"]
        snap["top_block"] = top_block
        # Tip after invalidate is the block under the parent. reconsider restores both.
        _, _, rec_tips = self.reconsider(parent["block"])
        snap["reconsider_tips_match"] = rec_tips
        after = self.tips(self.core)
        snap["tip_after_reconsider"] = after
        self.sweep_mempool()
        return snap

    def run(self):
        self.verify_tarball()
        self.start_nodes()
        try:
            self.log("mining mature coinbases")
            self.mine(110)
            self.log(f"tip {self.core.getbestblockhash()} height {self.core.getblockcount()}")
            self.fanout("fanout64", 64, True)
            self.fanout("fanout63", 63, False)
            self.weight_case()
            self.disagree_case()
            self.multiblock()
        finally:
            self.report["mismatches"] = self.mismatches
            out = os.path.join(self.args.workdir, "report.json")
            os.makedirs(self.args.workdir, exist_ok=True)
            with open(out, "w") as fh:
                json.dump(self.report, fh, indent=2)
            self.log(f"wrote {out}")
            if self.core and self.core_proc:
                stop_node(self.core, self.core_proc)
            if self.cb and self.cb_proc:
                stop_node(self.cb, self.cb_proc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoind", default="/tmp/bitcoin-31.1/bin/bitcoind")
    parser.add_argument("--clearbit", default="/workspace/zig-out/bin/clearbit")
    parser.add_argument(
        "--tarball",
        default="/tmp/bitcoin-31.1-x86_64-linux-gnu.tar.gz",
    )
    parser.add_argument("--workdir", default="/tmp/trim-sweep")
    args = parser.parse_args()
    Sweep(args).run()


if __name__ == "__main__":
    main()
