#!/usr/bin/env bash
# CB-7: Bitcoin Core v31.1 regtest vs clearbit, offline.
#
# Mines one regtest chain on bitcoind (110+ blocks, a few spends), feeds those
# blocks to clearbit with submitblock, and compares gettxoutsetinfo / dumptxoutset
# / the snapshot bytes / the tip. Then stalls dumptxoutset on a full pipe
# (the chain lock is already dropped) and delivers the next block on the
# localhost P2P port. The RPC thread is accept-one/serve-one, so a second
# RPC cannot run until the dump returns; the P2P thread is the one CB-7
# starved. The announcement of the new tip while the dump is still blocked
# is the release-binary overlap.
#
# Nothing here dials the public network. bitcoind is -listen=0 on a fresh
# datadir; clearbit is --nodnsseed (regtest has no DNS seeds or fixed seeds).
#
# Usage: src/cb7_core_regtest.sh [bitcoind] [clearbit]
# Defaults: /tmp/btc/bitcoin-31.1/bin/bitcoind and ./zig-out/bin/clearbit
set -euo pipefail

BITCOIND=${1:-/tmp/btc/bitcoin-31.1/bin/bitcoind}
CLEARBIT=${2:-./zig-out/bin/clearbit}
BITCOINCLI=${BITCOINCLI:-$(dirname "$BITCOIND")/bitcoin-cli}
ROOT=${CB7_WORKDIR:-/tmp/cb7-regtest}
CORE_DIR=$ROOT/core
CB_DIR=$ROOT/clearbit
CORE_RPC=18443
CB_RPC=19443
RPCUSER=cb7
RPCPASS=cb7

rm -rf "$ROOT"
mkdir -p "$CORE_DIR" "$CB_DIR" "$ROOT/out"

cleanup() {
    "$BITCOINCLI" -regtest -datadir="$CORE_DIR" -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" \
        stop >/dev/null 2>&1 || true
    if [[ -n "${CB_PID:-}" ]]; then
        kill "$CB_PID" >/dev/null 2>&1 || true
        wait "$CB_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "bitcoind: $BITCOIND"
"$BITCOIND" -version | head -2
echo "clearbit: $CLEARBIT"

"$BITCOIND" -regtest -daemon \
    -datadir="$CORE_DIR" \
    -port=18444 \
    -rpcport="$CORE_RPC" \
    -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" \
    -listen=0 \
    -dnsseed=0 \
    -fallbackfee=0.0002 \
    -server=1

core() {
    "$BITCOINCLI" -regtest -datadir="$CORE_DIR" -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" "$@"
}

echo "waiting for bitcoind RPC"
for _ in $(seq 1 50); do
    if core getblockcount >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
core getblockcount >/dev/null

core createwallet cb7 >/dev/null
ADDR=$(core -rpcwallet=cb7 getnewaddress)
# 101 mature coinbases, three spends, then enough blocks that the tip is past 110.
core -rpcwallet=cb7 generatetoaddress 101 "$ADDR" >/dev/null
DEST=$(core -rpcwallet=cb7 getnewaddress)
# -fallbackfee on bitcoind covers the fee. Named fee_rate is rejected as
# "Invalid amount" by this bitcoin-cli, so the positional form is used.
core -rpcwallet=cb7 sendtoaddress "$DEST" 1.0 >/dev/null
core -rpcwallet=cb7 sendtoaddress "$DEST" 0.5 >/dev/null
core -rpcwallet=cb7 sendtoaddress "$DEST" 0.25 >/dev/null
core -rpcwallet=cb7 generatetoaddress 15 "$ADDR" >/dev/null
TIP=$(core getblockcount)
echo "core tip height: $TIP"
if [[ "$TIP" -lt 110 ]]; then
    echo "expected at least 110 blocks, got $TIP" >&2
    exit 1
fi

core gettxoutsetinfo hash_serialized_3 >"$ROOT/out/core-info-hs.json"
core gettxoutsetinfo muhash >"$ROOT/out/core-info-mu.json"
core getbestblockhash >"$ROOT/out/core-tip.json"
core dumptxoutset "$ROOT/out/core-utxo.dat" latest >"$ROOT/out/core-dump.json"

# Block hex, height 1..tip (both nodes already share the regtest genesis).
: >"$ROOT/out/blocks.hex"
for h in $(seq 1 "$TIP"); do
    hash=$(core getblockhash "$h")
    core getblock "$hash" 0 >>"$ROOT/out/blocks.hex"
done
echo "exported $TIP blocks"

"$CLEARBIT" --regtest \
    --datadir="$CB_DIR" \
    --port=19444 \
    --rpcport="$CB_RPC" \
    --rpcuser="$RPCUSER" --rpcpassword="$RPCPASS" \
    --nodnsseed \
    --maxconnections=0 \
    >"$ROOT/out/clearbit.log" 2>&1 &
CB_PID=$!

cb() {
    curl -sf --user "$RPCUSER:$RPCPASS" \
        -H 'content-type: application/json' \
        --data "$1" \
        "http://127.0.0.1:${CB_RPC}/"
}

echo "waiting for clearbit RPC"
for _ in $(seq 1 100); do
    if cb '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$CB_PID" 2>/dev/null; then
        echo "clearbit exited during startup" >&2
        tail -40 "$ROOT/out/clearbit.log" >&2
        exit 1
    fi
    sleep 0.2
done

python3 - "$ROOT/out/blocks.hex" "$RPCUSER" "$RPCPASS" "$CB_RPC" <<'PY'
import json, sys, urllib.request, base64
path, user, pw, port = sys.argv[1:]
auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
n = 0
with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        body = json.dumps({"jsonrpc": "1.0", "id": "1", "method": "submitblock", "params": [line]}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            data=body,
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode())
        err = payload.get("error")
        result = payload.get("result")
        if err is not None or (result not in (None, "")):
            print(f"submitblock height {n+1} rejected: {payload}", file=sys.stderr)
            sys.exit(1)
        n += 1
print(f"clearbit accepted {n} blocks")
PY

cb '{"jsonrpc":"1.0","id":"1","method":"gettxoutsetinfo","params":["hash_serialized_3"]}' >"$ROOT/out/cb-info-hs.json"
cb '{"jsonrpc":"1.0","id":"1","method":"gettxoutsetinfo","params":["muhash"]}' >"$ROOT/out/cb-info-mu.json"
cb '{"jsonrpc":"1.0","id":"1","method":"getbestblockhash","params":[]}' >"$ROOT/out/cb-tip.json"
cb "{\"jsonrpc\":\"1.0\",\"id\":\"1\",\"method\":\"dumptxoutset\",\"params\":[\"$ROOT/out/cb-utxo.dat\",\"latest\"]}" >"$ROOT/out/cb-dump.json"

set +e
python3 - "$ROOT/out" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])

def load(name):
    return json.loads((out / name).read_text())

def result(obj):
    if isinstance(obj, dict) and "result" in obj and "error" in obj:
        if obj["error"] is not None:
            raise SystemExit(f"rpc error: {obj['error']}")
        return obj["result"]
    return obj

core_hs = result(load("core-info-hs.json"))
cb_hs = result(load("cb-info-hs.json"))
core_mu = result(load("core-info-mu.json"))
cb_mu = result(load("cb-info-mu.json"))
core_dump = result(load("core-dump.json"))
cb_dump = result(load("cb-dump.json"))
# bitcoin-cli prints a bare hex word. A leading digit run is a JSON number,
# so this is not parsed as JSON.
core_tip = (out / "core-tip.json").read_text().strip().strip('"')
cb_tip = result(load("cb-tip.json"))

mismatches = []

def same(label, a, b, justify=None):
    if str(a) != str(b):
        mismatches.append((label, a, b, justify))
        print(f"MISMATCH {label}\n  core:     {a}\n  clearbit: {b}" + (f"\n  note: {justify}" if justify else ""))
    else:
        print(f"match {label}: {a}")

for key in ("height", "bestblock", "txouts", "total_amount", "hash_serialized_3"):
    same(f"gettxoutsetinfo.{key}", core_hs.get(key), cb_hs.get(key))
same("gettxoutsetinfo.muhash", core_mu.get("muhash"), cb_mu.get("muhash"))
same("gettxoutsetinfo.bogosize", core_hs.get("bogosize"), cb_hs.get("bogosize"))
same("gettxoutsetinfo.transactions", core_hs.get("transactions"), cb_hs.get("transactions"))
same(
    "gettxoutsetinfo.disk_size",
    core_hs.get("disk_size"),
    cb_hs.get("disk_size"),
    "clearbit reports 0; it does not surface the LevelDB/RocksDB size Core reports",
)
same("tip", core_tip, cb_tip)
for key in ("coins_written", "base_hash", "base_height", "txoutset_hash", "nchaintx"):
    same(f"dumptxoutset.{key}", core_dump.get(key), cb_dump.get(key))

def sha(p):
    h = hashlib.sha256()
    data = pathlib.Path(p).read_bytes()
    h.update(data)
    return h.hexdigest(), len(data)

csha, clen = sha(out / "core-utxo.dat")
bsha, blen = sha(out / "cb-utxo.dat")
same("snapshot.sha256", csha, bsha)
same("snapshot.bytes", clen, blen)
if csha != bsha:
    a = (out / "core-utxo.dat").read_bytes()
    b = (out / "cb-utxo.dat").read_bytes()
    n = min(len(a), len(b))
    off = next((i for i in range(n) if a[i] != b[i]), n)
    print(f"snapshot first difference at byte {off}")

print(f"SUMMARY mismatches={len(mismatches)}")
for label, a, b, justify in mismatches:
    print(f"  {label}: core={a!r} clearbit={b!r}" + (f" ({justify})" if justify else ""))
# disk_size is the only difference this script treats as expected.
bad = [m for m in mismatches if m[0] != "gettxoutsetinfo.disk_size"]
sys.exit(1 if bad else 0)
PY
PARITY_RC=$?
set -e
echo "parity_exit=$PARITY_RC"

echo "---- stall dumptxoutset, deliver the next block on localhost P2P ----"
# One more Core block. clearbit's RPC thread is busy inside dumptxoutset, so
# the block is delivered as a P2P headers+block from 127.0.0.1, not via
# submitblock. gettxoutsetinfo cannot overlap on that same RPC thread; the
# unit test is what parks the gettxoutsetinfo walk.
PRE_H=$(python3 -c 'import json;print(json.load(open("'"$ROOT/out/cb-info-hs.json"'"))["result"]["height"])')
core -rpcwallet=cb7 generatetoaddress 1 "$ADDR" >/dev/null
NEW_H=$(core getblockcount)
NEW_HASH=$(core getblockhash "$NEW_H")
NEW_HEX=$(core getblock "$NEW_HASH" 0)
printf '%s' "$NEW_HEX" >"$ROOT/out/next-block.hex"

set +e
python3 - "$RPCUSER" "$RPCPASS" "$CB_RPC" "$ROOT/out" "$PRE_H" "$NEW_HASH" 19444 <<'PY'
import array, base64, fcntl, hashlib, json, os, socket, struct, sys, threading, time, urllib.request
from pathlib import Path

user, pw, rpc_port, out, pre_h, new_hash, p2p_port = sys.argv[1:]
pre_h = int(pre_h)
p2p_port = int(p2p_port)
out = Path(out)
block = bytes.fromhex((out / "next-block.hex").read_text().strip())
auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
# Linux fcntl. A 4KiB pipe is the page-size minimum and is smaller than this
# chain's snapshot, so the buffered writer blocks once the pipe is full.
# The chain lock is already dropped: the stall is inside the snapshot write.
F_SETPIPE_SZ = 1031
F_GETPIPE_SZ = 1032
FIONREAD = 0x541B
MAGIC = bytes.fromhex("fabfb5da")  # regtest

def rpc(method, params, timeout=180):
    body = json.dumps({"jsonrpc": "1.0", "id": "1", "method": method, "params": params}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{rpc_port}/",
        data=body,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    return payload, (time.perf_counter() - t0) * 1000

def pipe_pending(fd):
    buf = array.array("i", [0])
    fcntl.ioctl(fd, FIONREAD, buf, True)
    return buf[0]

def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def frame(cmd, payload):
    return MAGIC + cmd.encode().ljust(12, b"\x00") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload

def version_payload(height):
    services = 1 | 8  # NODE_NETWORK | NODE_WITNESS
    now = int(time.time())
    ua = b"/cb7-regtest:0.0.1/"
    addr = struct.pack("<Q", 0) + bytes(16) + struct.pack(">H", 0)
    our = struct.pack("<Q", services) + bytes(16) + struct.pack(">H", 0)
    return (
        struct.pack("<iQq", 70016, services, now)
        + addr
        + our
        + struct.pack("<Q", 0xCB7)
        + bytes([len(ua)])
        + ua
        + struct.pack("<iB", height, 0)
    )

def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"short read {len(buf)}/{n}")
        buf += chunk
    return buf

def read_msg(sock):
    hdr = recvn(sock, 24)
    if hdr[:4] != MAGIC:
        raise ConnectionError(f"bad magic {hdr[:4].hex()}")
    cmd = hdr[4:16].split(b"\x00", 1)[0].decode()
    ln = struct.unpack("<I", hdr[16:20])[0]
    payload = recvn(sock, ln) if ln else b""
    return cmd, payload

fifo = out / "during.fifo"
if fifo.exists():
    fifo.unlink()
os.mkfifo(fifo, 0o600)
# Reader first, then shrink, then the writer. Otherwise the default 64KiB
# pipe absorbs the whole snapshot and the RPC returns before we stall it.
rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
try:
    fcntl.fcntl(rfd, F_SETPIPE_SZ, 4096)
except OSError as e:
    print(f"F_SETPIPE_SZ failed: {e}", file=sys.stderr)
    os.close(rfd)
    sys.exit(2)
pipe_sz = fcntl.fcntl(rfd, F_GETPIPE_SZ)
pre_bytes = (out / "cb-utxo.dat").read_bytes()
print(f"pipe_capacity={pipe_sz} pre_snapshot_bytes={len(pre_bytes)}")
if len(pre_bytes) <= pipe_sz:
    print("snapshot fits in the pipe; mid-write stall is impossible on this chain", file=sys.stderr)
    os.close(rfd)
    sys.exit(2)

box = {}

def dump_call():
    try:
        box["dump"] = rpc("dumptxoutset", [str(fifo), "latest"])
    except Exception as e:
        box["dump_error"] = repr(e)

t = threading.Thread(target=dump_call)
t.start()

# A write smaller than PIPE_BUF (4096) is atomic, so the writer blocks with
# the pipe short of capacity: 4073 bytes in, 23 free, the next 3035-byte
# flush waits until the whole buffer fits. "Full" is the wrong signal.
# A non-zero fill that stops growing while the RPC is still in the call
# means that flush is blocked and the chain lock is already dropped.
stalled = False
last_pending = -1
stable = 0
deadline = time.perf_counter() + 15
while time.perf_counter() < deadline and "dump" not in box and "dump_error" not in box:
    pending = pipe_pending(rfd)
    if pending > 0 and pending == last_pending and t.is_alive():
        stable += 1
        if stable >= 15:
            stalled = True
            break
    else:
        stable = 0
    last_pending = pending
    time.sleep(0.01)

print(f"dump_stalled_mid_write={stalled} pipe_pending={pipe_pending(rfd)} rpc_already_done={'dump' in box}")
if not stalled:
    print("walk finished before the pipe filled; connect-during-walk was not forced", file=sys.stderr)

# Localhost P2P only. No public peer, no DNS. The node is already in
# --nodnsseed with an empty regtest seed list.
announced = False
announce_ms = None
commands = []
p2p_error = None
header = block[:80]
block_hash_internal = dsha(header)
block_hash_display = block_hash_internal[::-1].hex()
print(f"p2p_block_hash={block_hash_display} core_block_hash={new_hash}")

def on_cmd(cmd, payload):
    global announced, announce_ms
    if cmd == "getdata":
        # count is a compact size; one witness-block request is what we expect.
        sock.sendall(frame("block", block))
        commands.append("getdata->block")
        return
    if cmd == "ping" and len(payload) == 8:
        sock.sendall(frame("pong", payload))
        commands.append("ping")
        return
    if cmd == "headers":
        # compact count, then 81-byte entries (80-byte header + tx-count 0).
        i = 1 if payload else 0
        found = False
        while i + 80 <= len(payload):
            h = dsha(payload[i : i + 80])[::-1].hex()
            if h == new_hash or h == block_hash_display:
                found = True
            i += 81
        commands.append(f"headers found_new={found}")
        if found and announce_ms is None:
            announced = True
            announce_ms = (time.perf_counter() - t_send) * 1000
        return
    if cmd == "inv" and len(payload) >= 37:
        # skip compact count (1 byte when count < 253), then type + hash
        inv_hash = payload[5:37][::-1].hex()
        hit = inv_hash == new_hash or inv_hash == block_hash_display
        commands.append(f"inv hit={hit}")
        if hit and announce_ms is None:
            announced = True
            announce_ms = (time.perf_counter() - t_send) * 1000
        return
    commands.append(cmd)

if stalled and block_hash_display != new_hash:
    p2p_error = "block hash does not match Core"
elif stalled:
    try:
        sock = socket.create_connection(("127.0.0.1", p2p_port), timeout=5)
        sock.settimeout(5)
        sock.sendall(frame("version", version_payload(pre_h + 1)))
        saw_verack = False
        t_hs = time.perf_counter()
        while time.perf_counter() - t_hs < 5 and not saw_verack:
            cmd, payload = read_msg(sock)
            commands.append(cmd)
            if cmd == "verack":
                saw_verack = True
            elif cmd == "ping" and len(payload) == 8:
                sock.sendall(frame("pong", payload))
        if not saw_verack:
            p2p_error = "no verack"
        else:
            sock.sendall(frame("verack", b""))
            sock.sendall(frame("sendheaders", b""))
            # headers: one header, txn_count 0.
            sock.sendall(frame("headers", b"\x01" + header + b"\x00"))
            t_send = time.perf_counter()
            sock.settimeout(2)
            t_wait = time.perf_counter()
            while time.perf_counter() - t_wait < 8 and not announced:
                try:
                    cmd, payload = read_msg(sock)
                except socket.timeout:
                    continue
                on_cmd(cmd, payload)
                if "dump" in box:
                    break
        sock.close()
    except Exception as e:
        p2p_error = repr(e)

dump_alive_at_announce = t.is_alive() if announced else False
print(f"p2p_commands={commands}")
print(f"tip_announced_during_dump={announced} announce_ms={announce_ms} dump_thread_alive={dump_alive_at_announce}")
if p2p_error:
    print(f"p2p_error={p2p_error}")

# Unblock the writer and collect the snapshot bytes.
chunks = []
while True:
    try:
        got = os.read(rfd, 1 << 20)
    except BlockingIOError:
        got = b""
    if got:
        chunks.append(got)
        continue
    if not t.is_alive():
        break
    time.sleep(0.005)
t.join(timeout=60)
os.close(rfd)
data = b"".join(chunks)
(out / "cb-utxo-during.dat").write_bytes(data)
during_sha = hashlib.sha256(data).hexdigest()
pre_sha = hashlib.sha256(pre_bytes).hexdigest()
dump_payload, dump_ms = box.get("dump", ({}, -1))
res = (dump_payload or {}).get("result") or {}
(out / "during-dump.json").write_text(json.dumps(dump_payload, default=str))
print(f"dumptxoutset_ms={dump_ms:.2f}")
print(f"dump_base_height={res.get('base_height')} pre_height={pre_h}")
print(f"dump_base_hash={res.get('base_hash')}")
print(f"dump_coins_written={res.get('coins_written')} dump_txoutset_hash={res.get('txoutset_hash')}")
print(f"during_snapshot_sha256={during_sha}")
print(f"pre_snapshot_sha256={pre_sha}")
print(f"during_snapshot_matches_pre={during_sha == pre_sha} during_bytes={len(data)} pre_bytes={len(pre_bytes)}")
print("gettxoutsetinfo_during_dump=not_run reason=single_rpc_thread_busy_in_dumptxoutset")

tip, tip_ms = rpc("getblockcount", [])
tip_hash, _ = rpc("getbestblockhash", [])
print(f"tip_after_dump_ms={tip_ms:.2f} height={tip.get('result')} hash={tip_hash.get('result')}")

if "dump_error" in box:
    print(f"dump error: {box['dump_error']}", file=sys.stderr)
    sys.exit(1)
if not stalled:
    sys.exit(2)
if p2p_error or not announced or not dump_alive_at_announce:
    print("block was not announced while dumptxoutset was still blocked", file=sys.stderr)
    sys.exit(1)
if res.get("base_height") != pre_h or during_sha != pre_sha:
    print("dump did not stay on the pre-connect snapshot", file=sys.stderr)
    sys.exit(1)
if tip.get("result") != pre_h + 1 or tip_hash.get("result") != new_hash:
    print("tip after the dump is not the block delivered during the stall", file=sys.stderr)
    sys.exit(1)
PY
CONCURRENT_RC=$?
set -e
echo "concurrent_exit=$CONCURRENT_RC"

# Solo submit of one more block, for a latency comparison.
core -rpcwallet=cb7 generatetoaddress 1 "$ADDR" >/dev/null
SOLO_H=$(core getblockcount)
SOLO_HASH=$(core getblockhash "$SOLO_H")
SOLO_HEX=$(core getblock "$SOLO_HASH" 0)
python3 - "$RPCUSER" "$RPCPASS" "$CB_RPC" "$SOLO_HEX" <<'PY'
import base64, json, sys, time, urllib.request
user, pw, port, block_hex = sys.argv[1:]
auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
body = json.dumps({"jsonrpc": "1.0", "id": "1", "method": "submitblock", "params": [block_hex]}).encode()
req = urllib.request.Request(
    f"http://127.0.0.1:{port}/",
    data=body,
    headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
)
t0 = time.perf_counter()
with urllib.request.urlopen(req, timeout=120) as resp:
    payload = json.loads(resp.read().decode())
ms = (time.perf_counter() - t0) * 1000
print(f"solo_submitblock_ms={ms:.2f} result={payload.get('result')!r} error={payload.get('error')!r}")
PY

echo "cb7 regtest done parity_exit=$PARITY_RC concurrent_exit=$CONCURRENT_RC"
if [[ "$PARITY_RC" -ne 0 ]]; then
    exit "$PARITY_RC"
fi
exit "$CONCURRENT_RC"
