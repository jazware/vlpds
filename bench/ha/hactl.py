#!/usr/bin/env python3
"""vlpds HA end-to-end harness: multi-node clusters on native processes with
fault injection, continuous load, the sync-1.1 checker, and acked-write
verification.

    python3 bench/ha/hactl.py list
    python3 bench/ha/hactl.py run baseline-3 kill9-1of3 ...
    python3 bench/ha/hactl.py run all

Every node gets two faultproxy instances (bench/ha/faultproxy): an HTTP
proxy as its S3 endpoint, so S3 faults hit one node, and a TCP proxy in
front of its mTLS peer listener that it advertises to peers, so peer traffic
can be cut while clients still reach its public port directly. Nodes share
one dev-mode --peer-tls-dir (the first creates the CA); the harness reads a
node's /internal/v1/cluster with that node's own certificate.

Outputs: bench/ha/out/<run-id>/<scenario>/ (logs, probe CSV, result.json)
and a summary table in bench/ha/out/<run-id>/summary.md.
"""

import atexit
import base64
import csv
import datetime
import glob
import hashlib
import hmac
import json
import os
import random
import re
import signal
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.abspath(os.path.join(HERE, "..", ".."))
BIN_DIR = os.environ.get("VLPDS_BIN_DIR", os.path.join(PKG, "target", "agent-ha", "dev-release"))
VLPDS = os.path.join(BIN_DIR, "vlpds")
LOADGEN = os.path.join(BIN_DIR, "loadgen")
CHECKER = os.environ.get("VLPDS_CHECKER", os.path.join(PKG, "checker", "checker"))
FAULTPROXY = os.path.join(HERE, "faultproxy", "faultproxy")
FHAUDIT = os.path.join(HERE, "fhaudit", "fhaudit")
S3 = os.environ.get("VLPDS_HA_S3", "127.0.0.1:9200")
ADMIN = "dev-admin-token"
ADMIN_AUTH = "Basic " + base64.b64encode(f"admin:{ADMIN}".encode()).decode()
INTERNAL = os.environ.get("VLPDS_HA_INTERNAL_TOKEN", "dev-internal-token")
PEER_TLS_DIR = os.environ.get("VLPDS_HA_PEER_TLS_DIR", os.path.join(HERE, "out", "peer-tls"))
PARTITIONS = int(os.environ.get("VLPDS_HA_PARTITIONS", "64"))  # shards
TTL_MS = int(os.environ.get("VLPDS_HA_TTL_MS", "3000"))
RATE = float(os.environ.get("VLPDS_HA_RATE", "150"))  # writes/s per loadgen (one per node)
# Placeholders: {listen} {url} {peer_listen} {advertise} {tls_dir} {s3}
# {prefix} {id} {ttl_ms} {partitions}
NODE_ARGS = os.environ.get(
    "VLPDS_HA_NODE_ARGS",
    "--listen {listen} --public-url {url} --peer-listen {peer_listen} --advertise-url {advertise} "
    "--peer-tls-dir {tls_dir} --s3-endpoint {s3} --prefix {prefix} "
    "--node-id {id} --lease-ttl-ms {ttl_ms} --shards {partitions} --no-rate-limits --dev-mode --workers 2 "
    "--io-threads 3 --firehose-ring-mb 256",
)
# Ports: node i listens on BASE_PORT+i (public), +800+i (peer, mTLS); its peer
# faultproxy on +200+i (advertised) / +400+i (ctl); S3 proxy +2300+i / +2500+i;
# containers publish +600+i (public) and +1400+i (peer).
BASE_PORT = int(os.environ.get("VLPDS_HA_BASE_PORT", "7100"))
# Injected segment PUT latency so PUTs overlap and K > 1 is exercised; 0 = off.
INJECT_PUT_MS = float(os.environ.get("VLPDS_HA_INJECT_PUT_MS", "25"))
LOG_INFLIGHT = int(os.environ.get("VLPDS_HA_LOG_INFLIGHT", "4"))


def base_env():
    e = {"VLPDS_LOG_INFLIGHT": str(LOG_INFLIGHT)}
    if INJECT_PUT_MS > 0:
        e["VLPDS_INJECT_PUT_MS"] = str(INJECT_PUT_MS)
    return e


PROCS = []


def cleanup():
    for p in PROCS:
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass


atexit.register(cleanup)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def spawn(args, out_path, env=None):
    f = open(out_path, "ab")
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT, env=e, start_new_session=True)
    PROCS.append(p)
    return p


def http(method, url, body=None, headers=None, timeout=10.0, context=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("content-type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
        return r.status, r.read()


def peer_tls_context(node_id):
    """Any node's certificate is accepted; each exists once that node has started."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(os.path.join(PEER_TLS_DIR, "ca.crt"))
    ctx.load_cert_chain(os.path.join(PEER_TLS_DIR, f"{node_id}.crt"), os.path.join(PEER_TLS_DIR, f"{node_id}.key"))
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def partition_of(did, n=PARTITIONS):
    """vlsync-store/src/slots.rs: top 16 bits of sha256(did), uniform contiguous ranges."""
    slot = int.from_bytes(hashlib.sha256(did.encode()).digest()[:2], "big")
    return slot * n // 65536


# probe writers: one account per shard, capped
PROBES = int(os.environ.get("VLPDS_HA_PROBES", "32"))
CLEANUP = os.environ.get("VLPDS_HA_CLEANUP", "1") == "1"
MINIO_IMAGE = os.environ.get("VLPDS_HA_MINIO_IMAGE", "vlpds-minio:local")


def delete_prefix(prefix):
    host = S3 if not S3.startswith("127.0.0.1") else S3.replace("127.0.0.1", "host.docker.internal")
    r = subprocess.run(["docker", "run", "--rm", "--entrypoint", "sh", MINIO_IMAGE, "-c",
                        f"mc alias set n http://{host} minioadmin minioadmin >/dev/null && mc rm -r --force n/vlpds/{prefix} >/dev/null"],
                       capture_output=True, text=True)
    return r.returncode == 0


# --------------------------------------------------------------------------- nodes


class Proxy:
    def __init__(self, mode, listen, target, ctl, out):
        self.ctl = ctl
        self.proc = spawn([FAULTPROXY, "-mode", mode, "-listen", listen, "-target", target, "-ctl", ctl], out)

    def set(self, **kw):
        q = "&".join(f"{k}={v}" for k, v in kw.items())
        http("GET", f"http://{self.ctl}/set?{q}")

    def clear(self):
        http("GET", f"http://{self.ctl}/clear")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()


class Node:
    def __init__(self, idx, prefix, outdir, extra=None, env=None):
        self.idx = idx
        self.id = f"n{idx}"
        self.port = BASE_PORT + idx
        self.url = f"http://127.0.0.1:{self.port}"
        self.peer_port = BASE_PORT + 800 + idx
        self.prefix = prefix
        self.outdir = outdir
        self.extra = extra or []
        self.env = env or {}
        self.proc = None
        self.exits = []  # (time, returncode, proc)
        self.bin = None  # two-build scenarios; None = VLPDS
        self.s3 = Proxy("http", f"127.0.0.1:{BASE_PORT + 2300 + idx}", S3, f"127.0.0.1:{BASE_PORT + 2500 + idx}", os.path.join(outdir, f"{self.id}.s3proxy.log"))
        self.peer = Proxy("tcp", f"127.0.0.1:{BASE_PORT + 200 + idx}", f"127.0.0.1:{self.peer_port}", f"127.0.0.1:{BASE_PORT + 400 + idx}", os.path.join(outdir, f"{self.id}.peerproxy.log"))
        self.advertise = f"https://127.0.0.1:{BASE_PORT + 200 + idx}"

    def start(self):
        os.makedirs(PEER_TLS_DIR, exist_ok=True)
        args = [self.bin or VLPDS] + NODE_ARGS.format(
            listen=f"127.0.0.1:{self.port}", url=self.url, peer_listen=f"127.0.0.1:{self.peer_port}",
            advertise=self.advertise, tls_dir=PEER_TLS_DIR,
            s3=f"http://127.0.0.1:{BASE_PORT + 2300 + self.idx}", prefix=self.prefix, id=self.id,
            ttl_ms=TTL_MS, partitions=PARTITIONS).split() + self.extra
        env = {"RUST_LOG": "info,slatedb=warn", "VLPDS_NO_RATE_LIMITS": "true", **base_env(), **self.env}
        self.proc = spawn(args, os.path.join(self.outdir, f"{self.id}.log"), env)
        self.started_at = time.time()
        return self

    def alive(self):
        if self.proc is None:
            return False
        rc = self.proc.poll()
        if rc is not None and (not self.exits or self.exits[-1][2] is not self.proc):
            self.exits.append((time.time(), rc, self.proc))
        return rc is None

    def exit_codes(self):
        self.alive()
        return [rc for _, rc, _ in self.exits]

    def signal(self, sig):
        if self.proc and self.proc.poll() is None:
            os.kill(self.proc.pid, sig)

    def wait_exit(self, timeout=30):
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.alive()

    def status(self, timeout=2.0):
        """Direct to the peer listener, not through the fault proxy."""
        _, raw = http("GET", f"https://127.0.0.1:{self.peer_port}/internal/v1/cluster",
                      headers={"x-vlpds-internal": INTERNAL}, timeout=timeout, context=peer_tls_context(self.id))
        return json.loads(raw)

    def metrics(self):
        _, raw = http("GET", self.url + "/metrics", timeout=3)
        out = {}
        for line in raw.decode().splitlines():
            if not line or line.startswith("#"):
                continue
            k, _, v = line.rpartition(" ")
            try:
                out[k] = float(v)
            except ValueError:
                pass
        return out

    def ready(self):
        try:
            http("GET", self.url + "/xrpc/_health", timeout=1)
            return True
        except Exception:
            return False

    def teardown(self):
        self.signal(signal.SIGKILL)
        self.s3.stop()
        self.peer.stop()
        if self.proc:
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                pass
            self.alive()


# ---- containers: real network partitions, docker pause, and per-node clock
# skew via libfaketime (realtime only).

DOCKER_NET = os.environ.get("VLPDS_HA_DOCKER_NET", "vlpds-ha")
DOCKER_IMAGE = os.environ.get("VLPDS_HA_IMAGE", "vlpds-ha:local")
DOCKER_S3 = os.environ.get("VLPDS_HA_DOCKER_S3", "http://host.docker.internal:9200")
FAKETIME_LIB = "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1" if os.uname().machine in ("arm64", "aarch64") \
    else "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"


def docker(*args, check=True):
    r = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout.strip()


class _NoProxy:
    def set(self, **kw):
        raise RuntimeError("no proxy in container mode")

    clear = stop = lambda self: None


class CNode(Node):
    """`skew` (e.g. "+2.5s") offsets the wall clock only; monotonic time
    (lease validity) is untouched."""

    skews = {}

    def __init__(self, idx, prefix, outdir, extra=None, env=None):
        self.idx = idx
        self.id = f"n{idx}"
        self.port = BASE_PORT + 600 + idx
        self.url = f"http://127.0.0.1:{self.port}"
        self.peer_port = BASE_PORT + 1400 + idx
        self.prefix, self.outdir, self.extra = prefix, outdir, extra or []
        self.env = dict(env or {})
        self.name = f"vha-{self.id}"
        self.exits = []
        self.proc = None
        self.s3 = self.peer = _NoProxy()
        self.advertise = f"https://{self.name}:2584"
        self.skew = CNode.skews.get(self.id)
        self.started_at = 0
        self.runs = 0

    def start(self):
        docker("rm", "-f", self.name, check=False)
        docker("network", "create", DOCKER_NET, check=False)
        os.makedirs(PEER_TLS_DIR, exist_ok=True)
        args = NODE_ARGS.format(listen="0.0.0.0:2583", url=self.url, peer_listen="0.0.0.0:2584", advertise=self.advertise,
                                tls_dir=PEER_TLS_DIR, s3=DOCKER_S3, prefix=self.prefix, id=self.id, ttl_ms=TTL_MS,
                                partitions=PARTITIONS).split() + self.extra
        env = []
        for k, v in {**base_env(), **self.env}.items():
            env += ["-e", f"{k}={v}"]
        if self.skew:
            env += ["-e", f"LD_PRELOAD={FAKETIME_LIB}", "-e", f"FAKETIME={self.skew}", "-e", "DONT_FAKE_MONOTONIC=1"]
        # same path and our uid: the harness reads each node's key for status calls
        docker("run", "-d", "--name", self.name, "--network", DOCKER_NET, "-p", f"127.0.0.1:{self.port}:2583",
               "-p", f"127.0.0.1:{self.peer_port}:2584", "-v", f"{PEER_TLS_DIR}:{PEER_TLS_DIR}",
               "--user", f"{os.getuid()}:{os.getgid()}", "--cpus", "2", *env, DOCKER_IMAGE, *args)
        self.runs += 1
        self.started_at = time.time()
        self._logpump()
        return self

    def _logpump(self):
        f = open(os.path.join(self.outdir, f"{self.id}.log"), "ab")
        p = subprocess.Popen(["docker", "logs", "-f", self.name], stdout=f, stderr=subprocess.STDOUT)
        PROCS.append(p)

    def alive(self):
        st = docker("inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", self.name, check=False)
        if not st:
            return False
        status, code = st.split()
        if status in ("exited", "dead"):
            if len(self.exits) < self.runs:
                self.exits.append((time.time(), int(code), self.runs))
            return False
        return True

    def signal(self, sig):
        if sig == signal.SIGSTOP:
            docker("pause", self.name, check=False)
        elif sig == signal.SIGCONT:
            docker("unpause", self.name, check=False)
        else:
            docker("kill", "-s", signal.Signals(sig).name, self.name, check=False)

    def wait_exit(self, timeout=30):
        end = time.time() + timeout
        while time.time() < end and self.alive():
            time.sleep(0.2)
        if self.alive():
            docker("kill", self.name, check=False)
            time.sleep(0.5)
        self.alive()

    def disconnect(self):
        docker("network", "disconnect", DOCKER_NET, self.name)

    def connect(self):
        docker("network", "connect", DOCKER_NET, self.name)

    def teardown(self):
        self.alive()
        docker("rm", "-f", self.name, check=False)


def wait_ready(nodes, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        if all(n.ready() for n in nodes):
            return
        time.sleep(0.2)
    raise RuntimeError("nodes not ready")


def ownership(nodes):
    out = {}
    for n in nodes:
        if not n.alive():
            continue
        try:
            out[n.id] = n.status()["owned"]
        except Exception:
            pass
    return out


def layout_shards(nodes):
    """The layout's shard ids every live node agrees on; [] while a
    split/merge is in flight or they disagree, None if no node answered."""
    seen = set()
    for n in nodes:
        if not n.alive():
            continue
        try:
            l = n.status()["layout"]
        except Exception:
            continue
        if l.get("op"):
            return []
        seen.add(tuple(sorted(l["shards"])))
    if len(seen) != 1:
        return [] if seen else None
    return list(seen.pop())


def converged(nodes, expect_nodes=None):
    """Every shard of the layout owned exactly once by a live node (and,
    optionally, spread over `expect_nodes` nodes within fair share)."""
    shards = layout_shards(nodes)
    if not shards:
        return False, {"layout": "changing, disagreeing or unobserved"}
    want = len(shards)
    own = ownership(nodes)
    if not own:
        return False, own
    seen = {}
    for nid, ps in own.items():
        for p in ps:
            if p in seen:
                return False, own
            seen[p] = nid
    if len(seen) != want or set(seen) != set(shards):
        return False, own
    if expect_nodes:
        fair = -(-want // expect_nodes)
        if any(len(ps) > fair for ps in own.values()) or len([1 for ps in own.values() if ps]) < min(expect_nodes, want):
            return False, own
    return True, own


def wait_converged(nodes, expect_nodes=None, timeout=60):
    t0 = time.time()
    own = {}
    while time.time() - t0 < timeout:
        ok, own = converged(nodes, expect_nodes)
        if ok:
            return time.time() - t0, own
        time.sleep(0.2)
    return None, own


# --------------------------------------------------------------------------- load


def setup_accounts(nodes, outdir, per_node=40, records=3, tag="a"):
    files, procs = [], []
    for n in nodes:
        f = os.path.join(outdir, f"accounts-{n.id}.json")
        files.append(f)
        procs.append(spawn([LOADGEN, "--host", n.url, "--accounts-file", f, "setup", "--accounts", str(per_node),
                            "--records", str(records), "--concurrency", "16", "--prefix", f"{tag}{n.id}x"],
                           os.path.join(outdir, f"setup-{n.id}.log")))
    for p in procs:
        if p.wait() != 0:
            raise RuntimeError("loadgen setup failed (see setup-*.log)")
    accts = []
    for f in files:
        accts += json.load(open(f))
    path = os.path.join(outdir, "accounts.json")
    json.dump(accts, open(path, "w"))
    return path, accts


class Loadgen:
    def __init__(self, node, accounts_file, outdir, duration, rate=RATE, tag=""):
        self.node = node
        self.log = os.path.join(outdir, f"loadgen-{node.id}{tag}.log")
        self.acked = os.path.join(outdir, f"acked-{node.id}{tag}.json")
        self.rate = rate
        self.t0 = time.time()
        self.proc = spawn([LOADGEN, "--host", node.url, "--accounts-file", accounts_file, "--threads", "2", "run",
                           "--rate", str(rate), "--duration", str(duration), "--warmup", "0",
                           "--update-pct", "0", "--delete-pct", "0", "--max-inflight", "4000",
                           "--acked-out", self.acked], self.log)

    def wait(self, timeout=None):
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait()

    def windows(self):
        """[(t_end_s, ok_per_s, err_delta, p50_ms, p99_ms, max_ms)] from the 5 s lines."""
        out, last_err = [], 0
        for line in open(self.log, errors="replace"):
            if not line.startswith("[") or "ok/s" not in line:
                continue
            try:
                t = float(line[1:line.index("s]")])
                parts = line.split()
                ok = float(parts[parts.index("ok/s") + 1])
                err = int(parts[parts.index("err") + 1])
                p50 = float(parts[parts.index("p50") + 1].rstrip("ms"))
                p99 = float(parts[parts.index("p99") + 1].rstrip("ms"))
                mx = float(parts[parts.index("max") + 1].rstrip("ms"))
            except (ValueError, IndexError):
                continue
            out.append((t, ok, err - last_err, p50, p99, mx))
            last_err = err
        return out

    def summary(self):
        txt = open(self.log, errors="replace").read()
        res = {"node": self.node.id}
        for line in txt.splitlines():
            if line.startswith("target "):
                res["result"] = line.strip()
            if line.startswith("all "):
                res["latency"] = line.strip()
            if line.startswith("first error"):
                res["first_error"] = line.strip()[:300]
        return res


class Prober:
    """Writes to one account per partition through `node` every `interval`,
    recording each outcome: a precise per-partition availability timeline."""

    def __init__(self, nodes, accts, outdir, interval=0.1, probes=None):
        self.nodes = nodes  # the first alive one is used
        self.interval = interval
        self.outdir = outdir
        self.rows = []
        self.acked = {}
        self.stop_ev = threading.Event()
        by_p = {}
        for a in accts:
            by_p.setdefault(partition_of(a["did"]), a)
        # accounts come grouped by the minting node's shards: shuffle so the
        # probes cover every node
        picks = list(by_p.values())
        random.Random(1).shuffle(picks)
        self.accts = picks[:PROBES if probes is None else probes]
        self.tokens = {}
        self.lock = threading.Lock()
        self.threads = [threading.Thread(target=self.loop, args=(a,), daemon=True) for a in self.accts]

    def target(self):
        for n in self.nodes:
            if n.alive():
                return n
        return self.nodes[0]

    def session(self, a, n):
        _, raw = http("POST", n.url + "/xrpc/com.atproto.server.createSession", {"identifier": a["did"], "password": "hunter2"})
        return json.loads(raw)["accessJwt"]

    def loop(self, a):
        p = partition_of(a["did"])
        i = 0
        while not self.stop_ev.is_set():
            n = self.target()
            t0 = time.time()
            ok, code, err = False, 0, ""
            try:
                if a["did"] not in self.tokens:
                    self.tokens[a["did"]] = self.session(a, n)
                i += 1
                _, raw = http("POST", n.url + "/xrpc/com.atproto.repo.createRecord",
                              {"repo": a["did"], "collection": "app.bsky.feed.post",
                               "record": {"$type": "app.bsky.feed.post", "text": f"probe {i}", "createdAt": "2026-09-30T00:00:00Z"}},
                              headers={"authorization": "Bearer " + self.tokens[a["did"]]}, timeout=15)
                rkey = json.loads(raw)["uri"].rsplit("/", 1)[1]
                with self.lock:
                    self.acked.setdefault(a["did"], []).append(rkey)
                ok, code = True, 200
            except urllib.error.HTTPError as e:
                code = e.code
                err = e.read()[:200].decode(errors="replace")
            except Exception as e:
                err = str(e)[:200]
            t1 = time.time()
            with self.lock:
                self.rows.append((t0, t1, p, n.id, ok, code, err))
            time.sleep(max(0.0, self.interval - (t1 - t0)))

    def start(self):
        for t in self.threads:
            t.start()
        return self

    def stop(self):
        self.stop_ev.set()
        for t in self.threads:
            t.join(20)
        with open(os.path.join(self.outdir, "probe.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["t_send", "t_done", "partition", "via", "ok", "status", "error"])
            w.writerows(sorted(self.rows))
        path = os.path.join(self.outdir, "acked-probe.json")
        json.dump(self.acked, open(path, "w"))
        return path

    def analyze(self, fault_at, slow_s=2.0, t0=None):
        """Unavailability = time covered by failed or slow (> slow_s) probes
        after `fault_at`; recovery = last bad probe end - fault_at."""
        self.t0 = t0 or fault_at
        bad = [(t0, t1) for (t0, t1, p, _, ok, _, _) in self.rows if t0 >= fault_at - 0.5 and (not ok or t1 - t0 > slow_s)]
        errors = sum(1 for r in self.rows if not r[4])
        total = len(self.rows)
        # per shard: longest *contiguous* outage (bad probes less than 1 s
        # apart merge), so a takeover and a later rebalance blip on the same
        # shard count as two windows, not one long one
        per_p_rows = {}
        for (t0, t1, p, _, ok, _, _) in self.rows:
            if t0 >= fault_at - 0.5 and (not ok or t1 - t0 > slow_s):
                per_p_rows.setdefault(p, []).append((t0, t1))
        per_p = {}
        for p, rs in per_p_rows.items():
            rs.sort()
            wins = []
            for a, b in rs:
                if wins and a <= wins[-1][1] + 1.0:
                    wins[-1][1] = max(wins[-1][1], b)
                else:
                    wins.append([a, b])
            per_p[p] = max(wins, key=lambda w: w[1] - w[0])
        if not bad:
            return {"probes": total, "probe_errors": errors, "unavail_s": 0.0, "recovery_s": 0.0, "partitions_hit": 0,
                    "max_partition_outage_s": 0.0, "windows": []}
        bad.sort()
        merged = []
        for s, e in bad:
            if merged and s <= merged[-1][1] + self.interval * 2:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        return {
            "probes": total,
            "probe_errors": errors,
            "unavail_s": round(sum(e - s for s, e in merged), 2),
            "recovery_s": round(max(e for _, e in bad) - fault_at, 2),
            "partitions_hit": len(per_p),
            "max_partition_outage_s": round(max(e - s for s, e in per_p.values()), 2),
            # [start, end, failed probes], relative to the scenario start
            "windows": [[round(s - self.t0, 1), round(e - self.t0, 1),
                         sum(1 for r in self.rows if s <= r[0] <= e and not r[4])] for s, e in merged],
        }


class Checker:
    def __init__(self, node, outdir, tag="", cursor=None):
        self.node = node
        self.out = os.path.join(outdir, f"checker-{node.id}{tag}.log")
        args = [CHECKER, "-host", node.url, "-quiet", "-strict", "-workers", "4"]
        if cursor is not None:
            args += ["-cursor", str(cursor)]
        self.proc = spawn(args, self.out)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return self.result()

    def result(self):
        txt = open(self.out, errors="replace").read()
        res = {"node": self.node.id, "rc": self.proc.poll()}
        for line in txt.splitlines():
            if line.startswith("RESULT:"):
                res["result"] = line.split()[1]
            elif line.startswith("events:"):
                res["events"] = int(line.split()[1])
            elif line.startswith("  #commit:"):
                res["commits"] = int(line.split()[1])
            elif line.startswith("failures:"):
                res["failures"] = line.split(None, 1)[1]
            elif line.startswith("=== vlpds firehose checker summary"):
                res["ended"] = line.strip("= \n")[len("vlpds firehose checker summary "):]
            elif line.startswith("seq range:"):
                res["last_seq"] = int(line.split()[-1])
        fails = [l for l in txt.splitlines() if l.startswith("FAIL #")][:5]
        if fails:
            res["first_failures"] = fails
        return res


class FhAudit:
    """Records every create seen on a node's subscribeRepos."""

    def __init__(self, node, outdir, tag="", cursor=None):
        self.node = node
        self.out = os.path.join(outdir, f"fhaudit-{node.id}{tag}.json")
        args = [FHAUDIT, "-host", node.url, "-out", self.out]
        if cursor is not None:
            args += ["-cursor", str(cursor)]
        self.proc = spawn(args, os.path.join(outdir, f"fhaudit-{node.id}{tag}.log"))

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        try:
            return json.load(open(self.out))
        except Exception:
            return None


def audit_report(data, acked, node):
    if data is None:
        return {"node": node, "error": "no output"}
    seen = {d: set(v) for d, v in data["seen"].items()}
    missing = 0
    missing_dids = set()
    for did, rkeys in acked.items():
        s = seen.get(did, set())
        for k in rkeys:
            if k not in s:
                missing += 1
                missing_dids.add(did)
    return {"node": node, "commits": data["events"], "fh_missing": missing, "dids_affected": len(missing_dids),
            "reorders": data["reorders"], "dups": data["dups"], "infos": data.get("infos"), "last_time": data["last_time"], "end": data["end"],
            "first_seq": data["first_seq"], "last_seq": data["last_seq"]}


def history_diff(datas, common_range=False):
    """Every node must emit the same commits, (seq, did, rev), in the same order. With
    `common_range` only the seq range every node covered is compared (live
    audits start at slightly different points)."""
    logs = {n: [tuple(c) if isinstance(c, list) else (c["s"], c["d"], c["r"]) for c in (d or {}).get("commits") or []]
            for n, d in datas.items() if d}
    if len(logs) < 2:
        return {"compared": list(logs), "agree": True}
    lo = max(l[0][0] for l in logs.values() if l) if common_range and all(logs.values()) else None
    hi = min(l[-1][0] for l in logs.values() if l) if common_range and all(logs.values()) else None
    if lo is not None:
        logs = {n: [c for c in l if lo <= c[0] <= hi] for n, l in logs.items()}
    names = sorted(logs)
    ref = names[0]
    out = {"compared": names, "range": [lo, hi] if lo is not None else None, "agree": True, "pairs": {}}
    rs = set(logs[ref])
    for n in names[1:]:
        ns = set(logs[n])
        only_ref, only_n = sorted(rs - ns), sorted(ns - rs)
        same_order = logs[ref] == logs[n]
        out["pairs"][f"{ref}-{n}"] = {"len": [len(logs[ref]), len(logs[n])], f"only_{ref}": len(only_ref), f"only_{n}": len(only_n),
                                       "same_order": same_order, f"sample_only_{ref}": only_ref[:5], f"sample_only_{n}": only_n[:5]}
        if only_ref or only_n or not same_order:
            out["agree"] = False
    return out


def load_acked(files):
    merged = {}
    for f in files:
        if not os.path.exists(f):
            continue
        try:
            for did, rkeys in json.load(open(f)).items():
                merged.setdefault(did, []).extend(rkeys)
        except Exception as e:
            log(f"bad acked file {f}: {e}")
    return merged


def verify(acked_files, node, outdir):
    """Every acked create must be readable via `node`."""
    merged = load_acked(acked_files)
    path = os.path.join(outdir, "acked-all.json")
    json.dump(merged, open(path, "w"))
    total = sum(len(v) for v in merged.values())
    r = subprocess.run([LOADGEN, "--host", node.url, "verify", "--acked", path], capture_output=True, text=True)
    open(os.path.join(outdir, "verify.log"), "w").write(r.stdout + r.stderr)
    missing = None
    for line in r.stdout.splitlines():
        if line.startswith("verify:"):
            missing = int(line.split(",")[1].split()[0])
    return {"acked": total, "missing": missing, "ok": r.returncode == 0}


# --------------------------------------------------------------------------- scenarios


@dataclass
class Ctx:
    name: str
    outdir: str
    prefix: str
    nodes: list = field(default_factory=list)
    events: list = field(default_factory=list)  # (t, what)
    t0: float = 0.0
    factory: object = None  # Node or CNode

    def __post_init__(self):
        self.factory = self.factory or Node

    def mark(self, what):
        t = time.time()
        self.events.append((round(t - self.t0, 2), what))
        log(f"  [{self.name} +{t - self.t0:5.1f}s] {what}")
        return t


def make_cluster(ctx, n, start=True, extra=None, env=None):
    nodes = [ctx.factory(i + 1, ctx.prefix, ctx.outdir, extra=extra, env=env) for i in range(n)]
    time.sleep(0.3)
    if start:
        for nd in nodes:
            nd.start()
        wait_ready(nodes)
    ctx.nodes = nodes
    return nodes


def teardown(ctx):
    for n in ctx.nodes:
        n.teardown()


def run_load_scenario(ctx, n_nodes, duration, actions, checker_on=0, expect_final=None, per_node=30, rate=RATE,
                      start_nodes=None, node_extra=None, node_env=None, probes=None, replay=True,
                      node_bins=None):
    """cluster up -> accounts -> checker + probes + load on all nodes ->
    `actions` [(at_s, fn(ctx))] -> drain -> verify -> results. `replay=False`
    skips the replay from before the run (with a short --log-retention it is
    OutdatedCursor by design; such scenarios check it)."""
    nodes = make_cluster(ctx, n_nodes, start=False, extra=node_extra, env=node_env)
    for nd, b in zip(nodes, node_bins or []):
        nd.bin = b
    for nd in nodes[: (start_nodes or n_nodes)]:
        nd.start()
    wait_ready(nodes[: (start_nodes or n_nodes)])
    conv, own = wait_converged(nodes, expect_nodes=start_nodes or n_nodes)
    res = {"initial_convergence_s": round(conv, 2) if conv else None, "initial_distribution": own}
    live = nodes[: (start_nodes or n_nodes)]
    accounts_file, accts = setup_accounts(live, ctx.outdir, per_node=per_node)
    ctx.t0 = time.time()
    cp0 = {nd.id: cp_requests(nd) for nd in live}
    checker = Checker(nodes[checker_on], ctx.outdir)
    audits = {nd.id: FhAudit(nd, ctx.outdir) for nd in live}
    time.sleep(1)
    probe_nodes = [nodes[checker_on]] + [n for n in nodes if n is not nodes[checker_on]]
    prober = Prober(probe_nodes, accts, ctx.outdir, probes=probes).start()
    lgs = [Loadgen(nd, accounts_file, ctx.outdir, duration, rate=rate) for nd in live]
    fault_at = None
    extra = []
    start_audits = []  # live audits attached the moment a node (re)started
    for at, fn in sorted(actions, key=lambda a: a[0]):
        dt = ctx.t0 + at - time.time()
        if dt > 0:
            time.sleep(dt)
        r = fn(ctx)
        if r == "fault" and fault_at is None:
            fault_at = time.time()
        if isinstance(r, Loadgen):
            lgs.append(r)
        if isinstance(r, Checker):
            extra.append(r)
        if isinstance(r, FhAudit):
            start_audits.append(r)
    for lg in lgs:
        lg.wait(duration + 120)
    load_end = time.time()
    # nodes restarted mid-run reset their counter: not reported
    res["cp_req_per_s"] = {}
    for nd in nodes:
        if nd.id in cp0 and nd.alive() and not nd.exit_codes() and nd.started_at < ctx.t0:
            c1 = cp_requests(nd)
            if c1 is not None and cp0[nd.id] is not None and c1 >= cp0[nd.id]:
                res["cp_req_per_s"][nd.id] = round((c1 - cp0[nd.id]) / (load_end - ctx.t0), 1)
    time.sleep(3)
    prober_acked = prober.stop()
    # the merged firehose emits at the min watermark, so it trails the node
    # whose clock is furthest ahead by the clock spread: give live audits that
    # long to see the last (probe) writes
    time.sleep(3 + clock_spread_s(ctx))
    res["checker"] = checker.stop()
    res["extra_checkers"] = [c.stop() for c in extra]
    survivors = [n for n in nodes if n.alive()]
    final_conv, final_own = wait_converged(nodes, expect_nodes=expect_final or len(survivors), timeout=30)
    res["final_convergence_wait_s"] = round(final_conv, 2) if final_conv is not None else None
    res["final_distribution"] = final_own
    acked_files = [lg.acked for lg in lgs] + [prober_acked]
    res["verify"] = verify(acked_files, survivors[0] if survivors else nodes[0], ctx.outdir)
    acked = load_acked(acked_files)
    # live audits: only nodes that stayed up for the whole run must be complete
    res["fh_live"] = []
    first_seqs = []
    live_raw = {}
    for nid, a in audits.items():
        data = a.stop()
        rep = audit_report(data, acked, nid)
        node = next(n for n in nodes if n.id == nid)
        rep["node_stayed_up"] = not node.exit_codes() and node.alive()
        if rep["node_stayed_up"]:
            live_raw[nid] = data
        if rep.get("first_seq", -1) > 0:
            first_seqs.append(rep["first_seq"])
        res["fh_live"].append(rep)
    res["fh_replay"] = []
    if first_seqs and replay:
        cur = min(first_seqs) - 1
        reps = [FhAudit(n, ctx.outdir, tag="-replay", cursor=cur) for n in survivors]
        # rejoined nodes backfill the run from S3 segments (slower than the ring)
        time.sleep(8 if all(not n.exit_codes() and n.started_at < ctx.t0 for n in survivors) else 30)
        replay_raw = {}
        for a in reps:
            data = a.stop()
            # rejoined nodes are judged too: the merged stream has no seam at a node's start
            replay_raw[a.node.id] = data
            rep = audit_report(data, acked, a.node.id)
            rep["node_stayed_up"] = not a.node.exit_codes() and a.node.started_at < ctx.t0
            res["fh_replay"].append(rep)
        res["fh_replay_diff"] = history_diff(replay_raw)
        # a live subscriber attached at a node's (re)start must see exactly the
        # merged history from its first event on (compare with a survivor's replay)
        res["fh_start"] = []
        ref = next((k for k, v in replay_raw.items() if v), None)
        for a in start_audits:
            data = a.stop()
            r = audit_report(data, {}, a.node.id)
            if ref and data:
                d = history_diff({ref: replay_raw[ref], f"{a.node.id}-start": data}, common_range=True)
                r["agree"], r["diff"] = d["agree"], d.get("pairs")
            else:
                r["agree"] = False
            res["fh_start"].append(r)
    res["fh_live_diff"] = history_diff(live_raw, common_range=True)
    res["probe"] = prober.analyze(fault_at or ctx.t0 + 1e9, t0=ctx.t0)
    res["loadgens"] = []
    for lg in lgs:
        w = lg.windows()
        s = lg.summary()
        s["windows"] = w
        bad = [x for x in w if x[2] > 0 or x[1] < 0.8 * lg.rate]
        s["degraded_windows"] = len(bad)
        s["errors"] = sum(x[2] for x in w)
        s["max_p99_ms"] = max((x[4] for x in w), default=0)
        res["loadgens"].append(s)
    res["exit_codes"] = {n.id: n.exit_codes() for n in nodes}
    try:
        res["forwarded"] = {n.id: n.metrics().get("vlpds_requests_forwarded_total", 0) for n in survivors}
        res["lease_events"] = {n.id: {k.split('"')[1]: v for k, v in n.metrics().items() if k.startswith("vlpds_lease_events_total")} for n in survivors}
    except Exception:
        pass
    res["events"] = ctx.events
    return res


def clock_spread_s(ctx):
    if getattr(ctx, "factory", None) is not CNode or not CNode.skews:
        return 0.0
    vals = [float(v.rstrip("s")) for v in CNode.skews.values()] + [0.0]
    return max(vals) - min(vals)


def cp_requests(node):
    try:
        return sum(v for k, v in node.metrics().items() if k.startswith("vlpds_cluster_store_requests_total"))
    except Exception:
        return None


def failures(res):
    """Why a load scenario fails: [] when it passes."""
    out = []
    v = res.get("verify", {})
    ck = res.get("checker", {})
    if v.get("missing") != 0 or not v.get("ok"):
        out.append(f"verify: {v.get('missing')} of {v.get('acked')} acked writes missing (ok={v.get('ok')})")
    for c in [ck] + res.get("extra_checkers", []):
        if c.get("result") != "PASS":
            out.append(f"checker {c.get('node')}: {c.get('result')} {c.get('failures')} {c.get('first_failures')}")
    if res.get("final_distribution") is None or res.get("final_convergence_wait_s") is None:
        out.append(f"no final convergence: {res.get('final_distribution')}")
    for a in res.get("fh_live", []):
        if a.get("node_stayed_up") and (a.get("fh_missing") != 0 or a.get("reorders")):
            out.append(f"live firehose {a.get('node')}: missing {a.get('fh_missing')} reorders {a.get('reorders')}")
    for a in res.get("fh_replay", []):
        if a.get("fh_missing") != 0 or a.get("reorders") or a.get("dups") or a.get("infos"):
            out.append(f"replay {a.get('node')}: missing {a.get('fh_missing')} reorders {a.get('reorders')} "
                       f"dups {a.get('dups')} infos {a.get('infos')} {a.get('error') or ''}".rstrip())
    if len({(a.get("commits"), a.get("last_seq")) for a in res.get("fh_replay", [])}) > 1:
        ends = {a.get("node"): (a.get("commits"), a.get("last_seq")) for a in res.get("fh_replay", [])}
        out.append(f"replays disagree on the merged history (commits, last seq): {ends}")
    for a in res.get("fh_start", []):
        if not a.get("agree") or a.get("reorders") or a.get("dups"):
            out.append(f"start audit {a.get('node')}: agree {a.get('agree')} reorders {a.get('reorders')} "
                       f"dups {a.get('dups')} {a.get('diff')}")
    for k in ("fh_replay_diff", "fh_live_diff"):
        if res.get(k) and not res[k].get("agree", True):
            out.append(f"{k}: {res[k].get('pairs')}")
    if res.get("unexpected_exits"):
        out.append(f"unexpected exits: {res['unexpected_exits']}")
    for f in res.get("k_fail") or []:
        out.append(f"k: {f}")
    # e.g. a zombie must fail-stop (3 = fenced log, 5 = lease lapsed) before any restart
    for nid, allowed in (res.get("expect_exit") or {}).items():
        codes = (res.get("exit_codes") or {}).get(nid) or []
        if not codes or codes[0] not in allowed:
            out.append(f"{nid} exited {codes}, expected first one of {allowed}")
    return out


# ---- actions


def kill(idx, sig=signal.SIGKILL, label=None):
    def f(ctx):
        n = ctx.nodes[idx]
        ctx.mark(label or f"signal {signal.Signals(sig).name} -> {n.id}")
        n.signal(sig)
        return "fault"
    return f


def restart(idx):
    def f(ctx):
        n = ctx.nodes[idx]
        if n.alive():
            n.signal(signal.SIGKILL)
            n.wait_exit()
        ctx.mark(f"start {n.id}")
        n.start()
    return f


def graceful_restart(idx):
    def f(ctx):
        n = ctx.nodes[idx]
        t = ctx.mark(f"SIGTERM {n.id} (rolling)")
        n.signal(signal.SIGTERM)
        n.wait_exit(30)
        ctx.mark(f"{n.id} exited rc={n.exit_codes()[-1:]} after {time.time() - t:.1f}s; restarting")
        n.start()
        return "fault"
    return f


def fault(idx, which, label, **kw):
    def f(ctx):
        n = ctx.nodes[idx]
        ctx.mark(f"{label} -> {n.id}")
        (n.s3 if which == "s3" else n.peer).set(**kw)
        return "fault"
    return f


def heal(idx, which=("s3", "peer")):
    def f(ctx):
        n = ctx.nodes[idx]
        ctx.mark(f"heal {','.join(which)} -> {n.id}")
        for w in which:
            (n.s3 if w == "s3" else n.peer).clear()
    return f


def start_node(idx):
    def f(ctx):
        n = ctx.nodes[idx]
        if n.alive():
            return None
        ctx.mark(f"add node {n.id}")
        n.start()
        return "fault"
    return f


def checker_with_cursor(on_idx, back_s=15):
    def f(ctx):
        n = ctx.nodes[on_idx]
        st = n.status()
        cur = st["firehose_last_emitted"] - (int(back_s * 1e6) << 8)
        ctx.mark(f"mid-way checker on {n.id} cursor={cur} ({back_s}s back)")
        return Checker(n, ctx.outdir, tag="-cursor", cursor=cur)
    return f


def audit_from_start(idx):
    """Attaches a cursorless live audit to a node the moment it answers
    (run right after its start/restart action)."""
    def f(ctx):
        n = ctx.nodes[idx]
        wait_ready([n])
        ctx.mark(f"live audit attached to {n.id} at start")
        return FhAudit(n, ctx.outdir, tag="-start")
    return f


SCEN = {}


def scenario(name, desc):
    def deco(fn):
        SCEN[name] = (fn, desc)
        return fn
    return deco


@scenario("baseline-2", "2 nodes, steady split, load through both")
def s_base2(ctx):
    return run_load_scenario(ctx, 2, 30, [])


@scenario("baseline-3", "3 nodes, steady split, load through all")
def s_base3(ctx):
    return run_load_scenario(ctx, 3, 30, [])


@scenario("baseline-5", "5 nodes, steady split, load through all")
def s_base5(ctx):
    return run_load_scenario(ctx, 5, 30, [], per_node=20)


@scenario("kill9-1of3", "kill -9 one of 3 nodes under load, restart it 25 s later")
def s_kill1(ctx):
    return run_load_scenario(ctx, 3, 60, [(15, kill(1)), (40, restart(1))])


@scenario("kill9-2of5", "kill -9 two of 5 nodes at once under load, restart both 25 s later")
def s_kill2(ctx):
    return run_load_scenario(ctx, 5, 60, [(15, kill(2)), (15.01, kill(3)), (40, restart(2)), (40.01, restart(3)),
                                          (40.02, audit_from_start(2)), (40.03, audit_from_start(3)),
                                          (46, checker_with_cursor(2, back_s=10))], per_node=20)


@scenario("sigterm", "SIGTERM one of 3 nodes under load (graceful handoff), restart it later")
def s_term(ctx):
    return run_load_scenario(ctx, 3, 50, [(15, kill(1, signal.SIGTERM)), (35, restart(1))])


@scenario("rolling-restart", "graceful rolling restart of all 3 nodes, one every 12 s")
def s_roll(ctx):
    # checker lives on n1, restarted last; a second checker resumes on n2 by cursor
    acts = [(10, graceful_restart(1)), (10.01, audit_from_start(1)), (22, graceful_restart(2)), (22.01, audit_from_start(2)),
            (34, graceful_restart(0)), (34.01, audit_from_start(0)), (33, checker_with_cursor(1, back_s=25))]
    return run_load_scenario(ctx, 3, 50, acts)


@scenario("zombie", "SIGSTOP one of 3 nodes past its lease TTL, SIGCONT after takeover")
def s_zombie(ctx):
    acts = [(15, kill(1, signal.SIGSTOP)), (15 + 4 * TTL_MS / 1000, kill(1, signal.SIGCONT, "SIGCONT n2 (zombie wakes)")),
            (45, restart(1))]
    return run_load_scenario(ctx, 3, 60, acts)


@scenario("zombie-short", "SIGSTOP one of 3 nodes for ~TTL (wakes around the takeover)")
def s_zombie_short(ctx):
    acts = [(15, kill(1, signal.SIGSTOP)), (15 + TTL_MS / 1000 * 1.1, kill(1, signal.SIGCONT, "SIGCONT n2")),
            (40, restart(1))]
    return run_load_scenario(ctx, 3, 55, acts)


@scenario("s3-partition", "cut one node off from S3 (requests hang) for 12 s, then heal")
def s_s3part(ctx):
    acts = [(15, fault(1, "s3", "S3 blackhole", blackhole=1)), (27, heal(1, ("s3",))), (40, restart(1))]
    return run_load_scenario(ctx, 3, 55, acts)


@scenario("peer-partition", "cut one node's inbound peer traffic (forwarding+streams) for 12 s, S3 still reachable")
def s_peerpart(ctx):
    acts = [(15, fault(1, "peer", "peer blackhole", blackhole=1)), (27, heal(1, ("peer",)))]
    return run_load_scenario(ctx, 3, 50, acts)


@scenario("full-partition", "cut one node from S3 and peers for 12 s, then heal")
def s_fullpart(ctx):
    def both(ctx):
        n = ctx.nodes[1]
        ctx.mark(f"S3+peer blackhole -> {n.id}")
        n.s3.set(blackhole=1)
        n.peer.set(blackhole=1)
        return "fault"
    acts = [(15, both), (27, heal(1)), (40, restart(1))]
    return run_load_scenario(ctx, 3, 55, acts)


@scenario("s3-slow", "S3 latency spikes (400 ms +- 400 ms) on one node for 15 s")
def s_s3slow(ctx):
    acts = [(15, fault(1, "s3", "S3 latency 400ms+400ms jitter", latency_ms=400, jitter_ms=400)), (30, heal(1, ("s3",))),
            (42, restart(1))]
    return run_load_scenario(ctx, 3, 55, acts)


@scenario("s3-slow-all", "S3 latency 1500 ms on every node for 10 s (lease renewals near TTL)")
def s_s3slowall(ctx):
    def slow(ctx):
        ctx.mark("S3 latency 1500ms on all nodes")
        for n in ctx.nodes:
            n.s3.set(latency_ms=1500)
        return "fault"

    def fix(ctx):
        ctx.mark("heal S3 latency on all nodes")
        for n in ctx.nodes:
            n.s3.clear()

    def revive(ctx):
        for n in ctx.nodes:
            if not n.alive():
                ctx.mark(f"restart dead {n.id}")
                n.start()
    return run_load_scenario(ctx, 3, 50, [(15, slow), (25, fix), (35, revive)])


@scenario("s3-5xx", "S3 503 SlowDown on 30% of one node's requests for 15 s, then 100% for 6 s")
def s_s35xx(ctx):
    acts = [(15, fault(1, "s3", "S3 30% 503", err_pct=30, err_code=503)),
            (30, fault(1, "s3", "S3 100% 500", err_pct=100, err_code=500)),
            (36, heal(1, ("s3",))), (45, restart(1))]
    return run_load_scenario(ctx, 3, 60, acts)


@scenario("add-remove", "grow 2 -> 4 nodes under load, then remove two (SIGTERM, then kill -9)")
def s_addremove(ctx):
    acts = [(10, start_node(2)), (20, start_node(3)), (32, kill(3, signal.SIGTERM)), (44, kill(2, signal.SIGKILL))]
    return run_load_scenario(ctx, 4, 60, acts, start_nodes=2, expect_final=2)


@scenario("cas-contention", "8 nodes start at the same instant on a fresh prefix")
def s_cas(ctx):
    nodes = make_cluster(ctx, 8, start=False)
    for n in nodes:
        n.start()
    wait_ready(nodes)
    conv, own = wait_converged(nodes, expect_nodes=8, timeout=90)
    res = {"convergence_s": round(conv, 2) if conv is not None else None, "distribution": own}
    ctx.t0 = time.time()
    accounts_file, accts = setup_accounts(nodes, ctx.outdir, per_node=10)
    checker = Checker(nodes[0], ctx.outdir)
    lgs = [Loadgen(n, accounts_file, ctx.outdir, 20, rate=60) for n in nodes]
    for lg in lgs:
        lg.wait(200)
    time.sleep(3)
    res["checker"] = checker.stop()
    res["final_convergence_wait_s"], res["final_distribution"] = wait_converged(nodes, expect_nodes=8, timeout=10)
    res["verify"] = verify([lg.acked for lg in lgs], nodes[0], ctx.outdir)
    res["loadgens"] = [dict(lg.summary(), errors=sum(x[2] for x in lg.windows())) for lg in lgs]
    res["exit_codes"] = {n.id: n.exit_codes() for n in nodes}
    res["lease_events"] = {}
    for n in nodes:
        try:
            res["lease_events"][n.id] = {k.split('"')[1]: v for k, v in n.metrics().items() if k.startswith("vlpds_lease_events_total")}
        except Exception:
            pass
    res["events"] = ctx.events
    return res


@scenario("handoff-firehose", "checker on n1 while partitions move between n2/n3/n4 (restarts + joins); mid-way cursor subscriber")
def s_handoff(ctx):
    acts = [(10, graceful_restart(1)), (18, start_node(3)), (26, kill(2)), (34, restart(2)),
            (40, checker_with_cursor(0, back_s=20)), (42, graceful_restart(3))]
    return run_load_scenario(ctx, 4, 55, acts, start_nodes=3, expect_final=4)


def watch_log_then(idx, needle, then, label, delay=0.0, timeout=40):
    """Tails node idx's log from now on; when `needle` shows up, waits `delay`
    and runs `then(ctx)` (e.g. kill -9 mid-checkpoint)."""
    def f(ctx):
        n = ctx.nodes[idx]
        path = os.path.join(ctx.outdir, f"{n.id}.log")
        pos = os.path.getsize(path)
        end = time.time() + timeout
        while time.time() < end:
            with open(path, "rb") as fh:
                fh.seek(pos)
                chunk = fh.read()
            if needle.encode() in chunk:
                time.sleep(delay)
                ctx.mark(f"{label} ('{needle}' seen in {n.id}.log)")
                then(ctx)
                return "fault"
            time.sleep(0.005)
        ctx.mark(f"{label}: '{needle}' never seen")
        return None
    return f


@scenario("kill9-rebalance-drainer", "3 nodes; n4 joins under load; kill -9 n2 while it drains shards to n4; restart n2 later")
def s_k9_reb_drainer(ctx):
    grace = 2 * TTL_MS / 5000  # join grace = two renew intervals
    acts = [(12, start_node(3)), (12 + grace + 0.4, kill(1, label="kill -9 n2 (mid-rebalance, draining)")), (32, restart(1))]
    return run_load_scenario(ctx, 4, 55, acts, start_nodes=3, expect_final=4)


@scenario("kill9-rebalance-joiner", "3 nodes; n4 joins under load; kill -9 n4 while it opens/replays the shards it took; restart it later")
def s_k9_reb_joiner(ctx):
    grace = 2 * TTL_MS / 5000
    acts = [(12, start_node(3)), (12 + grace + 0.5, kill(3, label="kill -9 n4 (mid-rebalance, acquiring)")), (32, restart(3))]
    return run_load_scenario(ctx, 4, 55, acts, start_nodes=3, expect_final=4)


@scenario("kill9-rebalance-joiner-after-writes",
          "3 nodes; n4 joins under load, takes shards and acks writes for them; kill -9 n4 ~4 s later "
          "(before its first 10 s checkpoint, so acked writes live only in its log); the old owners retake; no restart")
def s_k9_reb_joiner_writes(ctx):
    grace = 2 * TTL_MS / 5000
    acts = [(12, start_node(3)), (12 + grace + 4, kill(3, label="kill -9 n4 (holding handed-off shards, writes acked)"))]
    res = run_load_scenario(ctx, 4, 45, acts, start_nodes=3, expect_final=3)
    res["expect_exit"] = {"n4": [-9, 137]}
    return res


@scenario("zombie-check", "SIGSTOP n2 for 4x TTL; after SIGCONT it must exit 3 (fenced) or 5 (lease lapsed); no restart")
def s_zombie_check(ctx):
    acts = [(15, kill(1, signal.SIGSTOP)), (15 + 4 * TTL_MS / 1000, kill(1, signal.SIGCONT, "SIGCONT n2 (zombie wakes)"))]
    res = run_load_scenario(ctx, 3, 45, acts)
    res["expect_exit"] = {"n2": [3, 5]}
    return res


@scenario("grow-1-to-3", "fresh prefix: n1 starts alone (its inline first step takes every shard), n2/n3 join under load; nobody may exit")
def s_grow(ctx):
    res = run_load_scenario(ctx, 3, 40, [(8, start_node(1)), (8.01, audit_from_start(1)), (16, start_node(2)),
                                         (16.01, audit_from_start(2)), (22, checker_with_cursor(2, back_s=10))],
                            start_nodes=1, expect_final=3)
    res["expect_exit"] = {}
    if any(res["exit_codes"].values()):
        res["unexpected_exits"] = res["exit_codes"]
    return res


@scenario("s3-5xx-all", "S3 503 SlowDown on 30% of every node's requests for 15 s")
def s_s35xx_all(ctx):
    def bad(ctx):
        ctx.mark("S3 30% 503 on all nodes")
        for n in ctx.nodes:
            n.s3.set(err_pct=30, err_code=503)
        return "fault"

    def fix(ctx):
        ctx.mark("heal S3 on all nodes")
        for n in ctx.nodes:
            n.s3.clear()
    return run_load_scenario(ctx, 3, 50, [(15, bad), (30, fix), (38, revive_dead)])


@scenario("s3-slow-one-long", "S3 latency 1500 ms on one node for 10 s")
def s_s3slow1(ctx):
    acts = [(15, fault(1, "s3", "S3 latency 1500ms", latency_ms=1500)), (25, heal(1, ("s3",))), (35, revive_dead)]
    return run_load_scenario(ctx, 3, 50, acts)


@scenario("kill9-mid-checkpoint", "kill -9 n2 right as its 10 s checkpoint starts (twice), restarting it each time")
def s_k9_ckpt(ctx):
    k = lambda ctx: ctx.nodes[1].signal(signal.SIGKILL)
    acts = [(5, watch_log_then(1, "checkpoint start", k, "kill -9 n2 mid-checkpoint", delay=0.03)),
            (25, restart(1)),
            (27, watch_log_then(1, "checkpoint start", k, "kill -9 n2 mid-checkpoint (2nd)", delay=0.01)),
            (50, restart(1))]
    return run_load_scenario(ctx, 3, 65, acts)


# ---- online shard split/merge (DESIGN.md "Online shard split/merge")


def admin_post(node, nsid, body, timeout=60.0):
    _, raw = http("POST", node.url + "/xrpc/" + nsid, body, headers={"authorization": ADMIN_AUTH}, timeout=timeout)
    return json.loads(raw)


def owned_by(ctx, idx):
    try:
        return sorted(ctx.nodes[idx].status()["owned"])
    except Exception:
        return []


def reshard(idx_via, label, plan):
    """`plan(ctx)` -> (nsid, body)."""
    def f(ctx):
        nsid, body = plan(ctx)
        ctx.mark(f"{label}: {nsid} {body}")
        try:
            r = admin_post(ctx.nodes[idx_via], nsid, body, timeout=90.0)
            ctx.mark(f"{label}: op {r.get('op', {}).get('id')} done={r.get('done')} layout v{r.get('layout', {}).get('version')}")
        except Exception as e:
            ctx.mark(f"{label}: {e}")
        return None
    return f


def split_owned_by(idx):
    return lambda ctx: ("vlpds.admin.splitShard", {"shard": owned_by(ctx, idx)[0], "wait": False})


def merge_adjacent(ctx):
    l = ctx.nodes[0].status()["layout"]["shards"]
    table = ctx.nodes[0].status()["table"]  # [(id, owner)] in slot order
    for (a, oa), (b, ob) in zip(table, table[1:]):
        if oa and ob and oa != ob:
            return "vlpds.admin.mergeShards", {"left": a, "right": b, "wait": True}
    return "vlpds.admin.mergeShards", {"left": l[0], "right": l[1], "wait": True}


@scenario("reshard-kill9",
          "3 nodes under load; split a shard n2 owns and kill -9 n2 as it freezes the parent (mid-split; the "
          "survivors fence, replay, take over driving and finish the split); restart n2; merge two shards held "
          "by different nodes; split again; every acked write readable, firehose complete")
def s_reshard_kill9(ctx):
    k = lambda ctx: ctx.nodes[1].signal(signal.SIGKILL)
    acts = [(12, reshard(0, "split a shard n2 owns", split_owned_by(1))),
            (12.01, watch_log_then(1, "freezing reshard parents", k, "kill -9 n2 mid-split", delay=0.01, timeout=10)),
            (30, restart(1)),
            (40, reshard(0, "merge shards held by two nodes", merge_adjacent)),
            (48, reshard(2, "split a shard n3 owns", lambda ctx: ("vlpds.admin.splitShard", {"shard": owned_by(ctx, 2)[0], "wait": True})))]
    res = run_load_scenario(ctx, 3, 60, acts)
    res["expect_exit"] = {"n2": [-9, 137]}
    try:
        res["final_layout"] = ctx.nodes[0].status().get("layout")
    except Exception:
        pass
    return res


# ---- K segment PUTs in flight: holes, fences, garbage

S3_KEY, S3_SECRET, S3_BUCKET, S3_REGION = "minioadmin", "minioadmin", "vlpds", "us-east-1"


def s3_req(method, key="", query=None, headers=None, timeout=10.0):
    """SigV4, path style."""
    now = time.gmtime()
    amz = time.strftime("%Y%m%dT%H%M%SZ", now)
    day = amz[:8]
    path = "/" + S3_BUCKET + ("/" + quote(key, safe="/~") if key else "")
    q = sorted((query or {}).items())
    qs = "&".join(f"{quote(k, safe='~')}={quote(str(v), safe='~')}" for k, v in q)
    payload = hashlib.sha256(b"").hexdigest()
    hdrs = {"host": S3, "x-amz-date": amz, "x-amz-content-sha256": payload}
    for k, v in (headers or {}).items():
        hdrs[k.lower()] = v
    signed = sorted(hdrs)
    creq = "\n".join([method, path, qs, "".join(f"{k}:{hdrs[k]}\n" for k in signed), ";".join(signed), payload])
    scope = f"{day}/{S3_REGION}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + S3_SECRET).encode()
    for part in (day, S3_REGION, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"http://{S3}{path}" + (f"?{qs}" if qs else ""), method=method)
    for h, v in hdrs.items():
        if h != "host":
            req.add_header(h, v)
    req.add_header("authorization", f"AWS4-HMAC-SHA256 Credential={S3_KEY}/{scope}, SignedHeaders={';'.join(signed)}, Signature={sig}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def s3_list(prefix, start_after=None):
    keys, token = [], None
    while True:
        q = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
        if token:
            q["continuation-token"] = token
        elif start_after:
            q["start-after"] = start_after
        st, body = s3_req("GET", "", q)
        if st != 200:
            raise RuntimeError(f"s3 list {prefix}: {st} {body[:200]}")
        txt = body.decode()
        keys += re.findall(r"<Key>([^<]+)</Key>", txt)
        m = re.search(r"<NextContinuationToken>([^<]+)</NextContinuationToken>", txt)
        if "<IsTruncated>true</IsTruncated>" not in txt or not m:
            return keys
        token = m.group(1)


def s3_get(key):
    st, body = s3_req("GET", key)
    return body if st == 200 else None


def _zstd_decompress(data, size):
    try:
        import zstandard  # optional; else the zstd CLI
        return zstandard.ZstdDecompressor().decompress(data, max_output_size=size)
    except ImportError:
        return subprocess.run(["zstd", "-d", "-c"], input=data, capture_output=True, check=True).stdout


class SegmentFormatError(ValueError):
    pass


# magic -> header fields between count and codec (vlsync-store segment.rs, version.rs)
SEG_FORMATS = {b"VLSEG06\n": ">", b"VLSEGT1\n": ">Q"}


def parse_log_object(b):
    """A log object (vlsync-store/src/segment.rs) -> {'kind': 'segment', log_id, ordinal, prefix_end,
    first_seq, last_seq, seqs}, {'kind': 'fence', by}, or {'kind': 'missing'} for no bytes (pruned).
    Raises SegmentFormatError on a magic, codec or layout this parser doesn't know."""
    if not b:
        return {"kind": "missing"}
    if b[:8] == b"VLFENCE\n":
        return {"kind": "fence", "by": b[8:].decode(errors="replace")}
    extra = SEG_FORMATS.get(b[:8])
    if extra is None:
        raise SegmentFormatError(f"unknown log object magic {b[:8]!r}: hactl.parse_log_object needs the new format")
    try:
        return _parse_segment(b, extra)
    except (struct.error, IndexError) as e:
        raise SegmentFormatError(f"{b[:7].decode()} segment truncated or misparsed: {e}") from None


def _parse_segment(b, extra):
    o = 8
    (n,) = struct.unpack_from(">H", b, o)
    o += 2
    log_id = b[o:o + n].decode()
    o += n
    ordinal, prefix_end, first_seq, last_seq, count = struct.unpack_from(">QQqqI", b, o)
    o += 36
    checksum = struct.unpack_from(extra, b, o)
    o += struct.calcsize(extra)
    codec, body_len = struct.unpack_from(">BI", b, o)
    o += 5
    if codec == 1:  # zstd body behind the uncompressed header
        b = b[:o] + _zstd_decompress(b[o:], body_len)
    elif codec != 0:
        raise SegmentFormatError(f"segment {ordinal} of {log_id}: unknown codec {codec}")
    if len(b) - o != body_len:
        raise SegmentFormatError(f"segment {ordinal} of {log_id}: body is {len(b) - o} bytes, header says {body_len}")
    if checksum and int.from_bytes(hashlib.sha256(b[o:]).digest()[:8], "big") != checksum[0]:
        raise SegmentFormatError(f"segment {ordinal} of {log_id}: body checksum mismatch")
    seqs = []
    for _ in range(count):
        seq, _shard, _epoch, flen = struct.unpack_from(">qIQI", b, o)
        o += 24 + flen
        (mc,) = struct.unpack_from(">I", b, o)
        o += 4
        if mc & 0x80000000:
            # bits 16-30 count muts derived from the frame (not stored), then the repo generation (LEB128)
            mc &= 0xFFFF
            while b[o] & 0x80:
                o += 1
            o += 1
        for _ in range(mc):
            (kl,) = struct.unpack_from(">H", b, o)
            o += 2 + kl
            (vl,) = struct.unpack_from(">I", b, o)
            o += 4 + (0 if vl == 0xFFFFFFFF else vl)
        if flen:
            seqs.append(seq)
    if o != len(b):
        raise SegmentFormatError(f"segment {ordinal} of {log_id}: {len(b) - o} bytes after its {count} entries")
    return {"kind": "segment", "log_id": log_id, "ordinal": ordinal, "prefix_end": prefix_end,
            "first_seq": first_seq, "last_seq": last_seq, "seqs": seqs}


def log_ordinals(prefix, log_id, start_after=None):
    out = []
    for k in s3_list(f"{prefix}/log/{log_id}/", start_after):
        f = k.rsplit("/", 1)[1]
        if f.endswith(".seg"):
            out.append(int(f[:-4]))
    return sorted(out)


def first_hole(ords):
    """(first missing ordinal, ordinals listed above it) of a sorted listing."""
    have = set(ords)
    lo = ords[0] if ords else 0
    n = lo
    while n in have:
        n += 1
    return n, [o for o in ords if o > n]


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(line):
    return ANSI.sub("", line)


def spans_of(prefix, log_id):
    """{(assignment, span start): end} of every span of `log_id` (end None: open)."""
    out = {}
    for k in s3_list(f"{prefix}/assign/"):
        try:
            a = json.loads(s3_get(k))
        except Exception:
            continue
        for sp in a.get("history", []):
            if sp.get("log_id") == log_id:
                out[(k.rsplit("/", 1)[1], sp.get("start"))] = sp.get("end")
    return out


def dead_log(ctx, n, log_id):
    """Records a log that just died for the audit, with the spans its node
    had already closed itself (a handoff before the fault: the shard moved
    on at the release's barrier, below the fence). Read right after the
    fault, a lease TTL before any peer can fence the log."""
    ctx.dead_logs.append((n.id, log_id))
    closed = {k for k, end in spans_of(ctx.prefix, log_id).items() if end is not None}
    ctx.closed_at_fault = {**getattr(ctx, "closed_at_fault", {}), log_id: closed}


def audit_dead_log(prefix, log_id, survivors_logs, fh_files, dead_node=None, closed_at_fault=None):
    """Checks a dead log's end state in S3 against the hole rule:
    - exactly one fence, at the first ordinal that isn't a segment (the first hole);
    - every assignment span of that log still open at the fault ends at the
      fence (all fencers agree); one its node had closed itself (a handoff
      before the fault, `closed_at_fault`) ends at or below it;
    - survivors that logged 'fenced dead node's log' name the same ordinal;
    - no seq of a segment past the fence (garbage) is on any firehose audit
      (live, cursor replay, start audits), while the prefix's last seqs are
      (so the comparison isn't vacuous)."""
    ords = log_ordinals(prefix, log_id)
    objs = {o: parse_log_object(s3_get(f"{prefix}/log/{log_id}/{o:012}.seg") or b"") for o in ords}
    fences = [o for o, v in objs.items() if v["kind"] == "fence"]
    segs = [o for o, v in objs.items() if v["kind"] == "segment"]
    lo = min(ords) if ords else 0
    hole = lo
    while hole in objs and objs[hole]["kind"] == "segment":
        hole += 1
    garbage = [o for o in segs if o > hole]
    garbage_seqs = {s for o in garbage for s in objs[o]["seqs"]}
    prefix_seqs = [s for o in segs if o < hole for s in objs[o]["seqs"]]
    tail = set(prefix_seqs[-20:])
    spans = spans_of(prefix, log_id)
    span_ends = {}
    for (key, _), end in spans.items():
        span_ends.setdefault(str(end), []).append(key)
    released = {k: e for k, e in spans.items() if k in (closed_at_fault or set())}
    fenced = {k: e for k, e in spans.items() if k not in released and e is not None}
    fencers = {}
    for nid, path in survivors_logs.items():
        try:
            for line in open(path, errors="replace"):
                line = strip_ansi(line)
                if "fenced dead node's log" in line and log_id in line:
                    m = re.search(r"fence_ordinal=(\d+)", line)
                    if m:
                        fencers.setdefault(nid, []).append(int(m.group(1)))
        except FileNotFoundError:
            pass
    on_fh, tail_seen = {}, {}
    for f in fh_files:
        try:
            d = json.load(open(f))
        except Exception:
            continue
        seqs = {c["s"] if isinstance(c, dict) else c[0] for c in d.get("commits") or []}
        name = os.path.basename(f)
        on_fh[name] = len(seqs & garbage_seqs)
        # a live audit on the dead node itself ends when it dies
        live_on_dead = dead_node and name in (f"fhaudit-{dead_node}.json", f"fhaudit-{dead_node}-start.json")
        if seqs and min(seqs) <= min(tail, default=0) and not live_on_dead:
            tail_seen[name] = len(seqs & tail)
    closed_ends = {str(e) for e in fenced.values()}
    out = {
        "log_id": log_id, "objects": len(ords), "first_ordinal": lo, "fence_ordinals": fences, "first_hole": hole,
        "fenced_by": [objs[o].get("by") for o in fences],
        "garbage_ordinals": garbage, "garbage_events": len(garbage_seqs),
        "span_ends": {e: len(v) for e, v in span_ends.items()}, "fencer_logs": fencers,
        "released_before_fault": {f"{k[0]}@{k[1]}": e for k, e in released.items()},
        "garbage_on_firehose": on_fh, "prefix_tail_seen": tail_seen,
    }
    fails = []
    if fences != [hole]:
        fails.append(f"fence {fences} not exactly at first hole {hole}")
    if any(e != str(hole) for e in closed_ends):
        fails.append(f"span ends {sorted(closed_ends)} != fence {hole}")
    if any(e > hole for e in released.values()):
        fails.append(f"spans released before the fault end past the fence {hole}: {released}")
    if "None" in span_ends:
        fails.append(f"open spans of a dead log: {span_ends['None']}")
    if any(v != [hole] * len(v) for v in fencers.values()):
        fails.append(f"fencers disagree: {fencers}")
    if any(on_fh.values()):
        fails.append(f"garbage on firehose: {on_fh}")
    if tail and tail_seen and not all(v == len(tail) for v in tail_seen.values()):
        fails.append(f"prefix tail missing from a firehose: {tail_seen}")
    out["fails"] = fails
    return out


def prom(query):
    """Against the local obs stack; None if unavailable."""
    try:
        _, raw = http("GET", f"http://127.0.0.1:9090/api/v1/query?query={quote(query)}", timeout=5)
        return [(r["metric"], float(r["value"][1])) for r in json.loads(raw)["data"]["result"]]
    except Exception:
        return None


def metric_sum(m, name, **labels):
    tot = 0.0
    for k, v in m.items():
        if k == name or k.startswith(name + "{"):
            if all(f'{lk}="{lv}"' in k for lk, lv in labels.items()):
                tot += v
    return tot


def put_counters(node):
    try:
        m = node.metrics()
    except Exception:
        return None
    return {"segments": metric_sum(m, "vlpds_segments_total"), "hedges": metric_sum(m, "vlpds_segment_put_hedges_total"),
            "attempts": metric_sum(m, "vlpds_segment_put_attempts_total"),
            "attempt_errors": metric_sum(m, "vlpds_segment_put_attempts_total", result="error"),
            "already_exists": metric_sum(m, "vlpds_segment_put_attempts_total", result="already_exists"),
            "inflight": metric_sum(m, "vlpds_segment_puts_inflight"), "t": time.time(),
            "nudges_sent": metric_sum(m, "vlpds_cluster_nudges_total", dir="sent"),
            "nudges_received": metric_sum(m, "vlpds_cluster_nudges_total", dir="received"),
            "spills": metric_sum(m, "vlpds_firehose_merge_spills_total"),
            "spill_segments": metric_sum(m, "vlpds_firehose_merge_spill_segments_total")}


def kill_on_hole(idx, label, timeout=15.0, sig=signal.SIGKILL):
    """Polls node idx's current log in S3 and kill -9s it the moment a hole is
    visible (ordinal n missing while a later one landed: K PUTs in flight,
    completing out of order). Records the dead log id for the audit."""
    def f(ctx):
        n = ctx.nodes[idx]
        log_id = n.status()["log"]
        end = time.time() + timeout
        polls, after = 0, None
        while time.time() < end:
            ords = log_ordinals(ctx.prefix, log_id, after)
            polls += 1
            if ords:
                hole, above = first_hole(ords)
                if above:
                    n.signal(sig)
                    ctx.mark(f"{label}: kill -9 {n.id} with a hole at {hole}, {len(above)} later segment(s) landed {above[:4]} (poll {polls})")
                    dead_log(ctx, n, log_id)
                    return "fault"
                after = f"{ctx.prefix}/log/{log_id}/{max(ords[0], hole - 1):012}.seg"
            time.sleep(0.005)
        n.signal(sig)
        ctx.mark(f"{label}: no hole seen in {timeout}s ({polls} polls); kill -9 {n.id} anyway")
        dead_log(ctx, n, log_id)
        return "fault"
    return f


def k_audits(ctx, res):
    logs = {n.id: os.path.join(ctx.outdir, f"{n.id}.log") for n in ctx.nodes}
    fh = glob.glob(os.path.join(ctx.outdir, "fhaudit-*.json"))
    res["dead_logs"] = []
    for nid, log_id in ctx.dead_logs:
        a = audit_dead_log(ctx.prefix, log_id, logs, fh, dead_node=nid,  # a restarted incarnation may fence too
                           closed_at_fault=getattr(ctx, "closed_at_fault", {}).get(log_id))
        a["node"] = nid
        res["dead_logs"].append(a)
        for f in a["fails"]:
            res.setdefault("k_fail", []).append(f"{log_id}: {f}")
    return res


# ~52 KB segments, sealed at ~13 KB with K = 4 while a PUT is in flight: several
# ordinals in flight at harness load (8 MB segments never fill at 150 writes/s)
K_SMALL_SEGS = ["--max-segment-mb", "0.05"]


@scenario("k-kill9-holes", "K=4, small segments, 150 ms lognormal(1.0) PUT latency: kill -9 n2 the instant its log shows a hole "
          "(twice, restarting in between); fence at the first hole, garbage never on any firehose, survivors agree")
def s_k_kill9(ctx):
    ctx.dead_logs = []
    extra = K_SMALL_SEGS + ["--inject-sigma", "1.0"]
    acts = [(15, kill_on_hole(1, "1st", timeout=8)), (30, restart(1)), (40, kill_on_hole(1, "2nd", timeout=8)), (55, restart(1))]
    res = run_load_scenario(ctx, 3, 65, acts, node_extra=extra, node_env={"VLPDS_INJECT_PUT_MS": "150"})
    return k_audits(ctx, res)


def stop_with_puts_held(idx, min_inflight=4, timeout=5.0):
    """Blackholes node idx's S3 (its PUTs hang at the proxy), waits until at
    least `min_inflight` segment PUT attempts are in flight (>= 2 ordinals even
    counting one hedge each), then SIGSTOPs it."""
    def f(ctx):
        n = ctx.nodes[idx]
        log_id = n.status()["log"]
        n.s3.set(blackhole=1)
        ctx.mark(f"S3 blackhole -> {n.id} (PUTs held at the proxy)")
        end, seen = time.time() + timeout, 0
        while time.time() < end:
            c = put_counters(n)
            seen = c["inflight"] if c else seen
            if seen >= min_inflight:
                break
            time.sleep(0.01)
        n.signal(signal.SIGSTOP)
        dead_log(ctx, n, log_id)
        try:
            _, raw = http("GET", f"http://{n.s3.ctl}/stats")
            ctx.k_info["proxy_at_stop"] = json.loads(raw)
        except Exception:
            pass
        ctx.k_info["log_at_stop"] = log_ordinals(ctx.prefix, log_id)[-3:]
        ctx.mark(f"SIGSTOP {n.id} with {seen:.0f} segment PUT attempts in flight")
        ctx.k_info["inflight_at_stop"] = seen
        return "fault"
    return f


@scenario("k-zombie-inflight", "K=4, small segments: n2's S3 blackholed until >= 4 PUT attempts hang, SIGSTOP 4x TTL; "
          "release its held PUTs into the fenced log, then SIGCONT: it must fail-stop (3/5); garbage past the fence harmless")
def s_k_zombie(ctx):
    ctx.dead_logs, ctx.k_info = [], {}

    def release(ctx):
        n = ctx.nodes[1]
        n.s3.clear()
        time.sleep(0.5)
        log_id = ctx.dead_logs[0][1]
        ctx.k_info["log_after_release"] = log_ordinals(ctx.prefix, log_id)[-6:]
        ctx.mark(f"heal S3 -> {n.id} (its held PUTs land while it is still stopped): log tail {ctx.k_info['log_after_release']}")

    def wake(ctx):
        n = ctx.nodes[1]
        ctx.mark(f"SIGCONT {n.id}")
        n.signal(signal.SIGCONT)
        n.wait_exit(10)
        ctx.mark(f"{n.id} exit codes {n.exit_codes()}")
    acts = [(15, stop_with_puts_held(1)), (15 + 4 * TTL_MS / 1000, release), (16.5 + 4 * TTL_MS / 1000, wake)]
    res = run_load_scenario(ctx, 3, 45, acts, node_extra=K_SMALL_SEGS, node_env={"VLPDS_INJECT_PUT_MS": "60"})
    res["expect_exit"] = {"n2": [3, 5]}
    res["k_info"] = ctx.k_info
    try:
        txt = open(os.path.join(ctx.outdir, "n2.log"), errors="replace").read()
        res["k_info"]["zombie_exit_reason"] = [l[-160:] for l in txt.splitlines() if "fail-stop" in l][:3]
    except Exception:
        pass
    k_audits(ctx, res)
    for a in res["dead_logs"]:
        if not a["garbage_ordinals"]:
            res["k_info"]["note"] = "no zombie PUT landed past the fence"
    return res


def log_events(path, needles):
    """[(epoch s, needle, line)] for lines containing any needle (tracing's RFC 3339 timestamps)."""
    out = []
    try:
        for line in open(path, errors="replace"):
            line = strip_ansi(line)
            for nd in needles:
                if nd in line:
                    ts = line.split()[0]
                    try:
                        t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                    except ValueError:
                        t = None
                    out.append((t, nd, line.strip()[-220:]))
    except FileNotFoundError:
        pass
    return out


def handoff_timing(ctx):
    """release -> serving per handoff: a releaser's 'closed and released shards'
    to the first 'shards opened' after it on a node that adopted handed shards."""
    rel, adopt = [], []
    for n in ctx.nodes:
        for t, nd, line in log_events(os.path.join(ctx.outdir, f"{n.id}.log"),
                                      ["closed and released shards", "adopting shards handed to us", "shards opened"]):
            if t is None:
                continue
            if nd == "closed and released shards":
                m = re.search(r"handed=(\d+)", line)
                e = re.search(r"elapsed_ms=(\d+)", line)
                rel.append({"node": n.id, "t": t, "handed": int(m.group(1)) if m else None, "close_ms": int(e.group(1)) if e else None})
            else:
                adopt.append((t, n.id, nd, line))
    out = []
    for r in rel:
        if not r["handed"]:
            continue
        opened = {}
        pending = set()
        for t, nid, nd, line in sorted(adopt):
            if t < r["t"] - 0.05 or t > r["t"] + 10 or nid == r["node"]:
                continue
            if nd == "adopting shards handed to us":
                pending.add(nid)
            elif nid in pending and nid not in opened:
                opened[nid] = round((t - r["t"]) * 1000)
        out.append({"releaser": r["node"], "at_s": round(r["t"] - ctx.t0, 2), "handed": r["handed"], "close_ms": r["close_ms"],
                    "release_to_serving_ms": opened})
    return out


def scrape_inflight(idx, key):
    def f(ctx):
        c = put_counters(ctx.nodes[idx])
        ctx.k_info.setdefault(key, []).append(c and c["inflight"])
    return f


@scenario("k-sigterm-saturated", "K=4, small segments, 100 ms PUT latency, 300 writes/s per node: n4 joins (handback + nudge), "
          "SIGTERM n2 at saturation (draining lease, barrier behind K PUTs), restart n2; release->serving and 503 windows")
def s_k_sigterm(ctx):
    ctx.k_info = {}
    grace = 2 * TTL_MS / 5000

    def term(ctx):
        c = put_counters(ctx.nodes[1])
        ctx.k_info["n2_inflight_at_sigterm"] = c and c["inflight"]
        return kill(1, signal.SIGTERM)(ctx)
    acts = [(12, start_node(3)), (12 + grace - 0.3, scrape_inflight(0, "n1_inflight_before_handback")), (25, term), (38, restart(1))]
    res = run_load_scenario(ctx, 4, 55, acts, start_nodes=3, expect_final=4, rate=300,
                            node_extra=K_SMALL_SEGS, node_env={"VLPDS_INJECT_PUT_MS": "100"})
    res["k_info"] = ctx.k_info
    res["handoffs"] = handoff_timing(ctx)
    res["nudges"] = {n.id: {k: v for k, v in (put_counters(n) or {}).items() if k.startswith("nudges")} for n in ctx.nodes if n.alive()}
    pm = prom('max_over_time(vlpds_segment_puts_inflight{instance=~"127.0.0.1:710[1-4]"}[2m])')
    res["prom_max_inflight"] = {m.get("instance"): v for m, v in pm} if pm else None
    return res


@scenario("k-s3-slow-lowload", "K=4, low load (5 writes/s per node, 4 probes): S3 400+-400 ms on n2 for 20 s; "
          "hedges <= 1 per ordinal, PUT attempts per segment <= 2, PUT rate no higher than before the fault")
def s_k_slow(ctx):
    ctx.k_info = {}
    snaps = {}

    def snap(key):
        def f(ctx):
            snaps[key] = put_counters(ctx.nodes[1])
            ctx.mark(f"n2 PUT counters @{key}: {snaps[key]}")
        return f
    acts = [(5, snap("base0")), (15, snap("base1")), (15.01, fault(1, "s3", "S3 latency 400ms+400ms jitter", latency_ms=400, jitter_ms=400)),
            (35, snap("slow1")), (35.01, heal(1, ("s3",)))]
    res = run_load_scenario(ctx, 3, 45, acts, rate=5, probes=4)

    def rate(a, b):
        dt = snaps[b]["t"] - snaps[a]["t"]
        d = {k: snaps[b][k] - snaps[a][k] for k in ("segments", "hedges", "attempts", "attempt_errors")}
        # PUT requests started: one per segment, plus hedges, plus retries after
        # errors (the attempts counter only sees attempts that finished; a
        # hedge's loser is dropped)
        d["puts_started"] = d["segments"] + d["hedges"] + d["attempt_errors"]
        d["segments_per_s"] = round(d["segments"] / dt, 2)
        d["puts_per_s"] = round(d["puts_started"] / dt, 2)
        d["puts_per_segment"] = round(d["puts_started"] / max(d["segments"], 1), 2)
        return d
    if all(snaps.get(k) for k in ("base0", "base1", "slow1")):
        base, slow = rate("base0", "base1"), rate("base1", "slow1")
        res["k_info"] = {"baseline": base, "slow": slow}
        fails = []
        # one hedge per ordinal at most: hedges <= segments sealed (+ the <= K still in flight)
        if slow["hedges"] > slow["segments"] + LOG_INFLIGHT:
            fails.append(f"hedges {slow['hedges']} > segments {slow['segments']} + K")
        if slow["puts_per_s"] > max(base["puts_per_s"], 1) * 1.5:
            fails.append(f"PUT rate exploded: {slow['puts_per_s']}/s vs {base['puts_per_s']}/s before")
        if fails:
            res["k_fail"] = fails
    else:
        res["k_fail"] = ["metrics snapshots missing"]
    return res


@scenario("k-spill-holes", "K=4, small segments, 150 ms lognormal(1.0) PUT latency, merger queue budget 0.25 MiB: kill -9 n2 "
          "at a hole while survivors' mergers spill to S3 read-back; followers drain to the fence, spills read back across it")
def s_k_spill(ctx):
    ctx.dead_logs, ctx.k_info = [], {}
    extra = K_SMALL_SEGS + ["--inject-sigma", "1.0", "--firehose-merge-queue-mb", "0.25"]
    before = {}

    def snap(ctx):
        for n in ctx.nodes:
            before[n.id] = put_counters(n)
    acts = [(14, snap), (15, kill_on_hole(1, "kill"))]
    res = run_load_scenario(ctx, 3, 40, acts, node_extra=extra, node_env={"VLPDS_INJECT_PUT_MS": "150"})
    res["expect_exit"] = {"n2": [-9]}
    spills = {}
    for n in ctx.nodes:
        if n.id == "n2" or not n.alive():
            continue
        c = put_counters(n)
        b = before.get(n.id) or {}
        spills[n.id] = {"spills": c["spills"] - b.get("spills", 0), "spill_segments": c["spill_segments"] - b.get("spill_segments", 0),
                        "spills_total": c["spills"]}
    res["k_info"] = {"spills_after_kill": spills,
                     "spill_log_lines": {n.id: len(log_events(os.path.join(ctx.outdir, f"{n.id}.log"), ["spilling log to S3 read-back"]))
                                         for n in ctx.nodes}}
    k_audits(ctx, res)
    if not any(v["spill_segments"] > 0 for v in spills.values()):
        res.setdefault("k_fail", []).append("no survivor's merger spilled after the kill (scenario did not exercise read-back)")
    return res


# ---- log retention under failover (src/retention.rs)

# --log-retention for retention-* scenarios (s): short, so a few passes (one
# every 60 s per node, DEFAULT_INTERVAL) prune live and dead logs mid-run
RETENTION_S = int(os.environ.get("VLPDS_HA_RETENTION_S", "45"))
# node-log lines that mean a replay, backfill or follower needed something
# retention had deleted, or a retention pass itself failed
RETENTION_BAD = ["open failed", "firehose backfill failed", "firehose backfill task failed", "draining dead log",
                 "log pruned ahead of its follower", "reading the retained floor failed", "log retention pass failed",
                 "close failed", "a shard failed to close", "reading back a spilled log failed",
                 "dropped late events below the emitted watermark"]


def retained_floor(prefix):
    """Max pruned_seq over the retain/ reports (what readers check a cursor against)."""
    floor = 0
    for k in s3_list(f"{prefix}/retain/"):
        try:
            floor = max(floor, json.loads(s3_get(k) or b"{}").get("pruned_seq", 0))
        except Exception:
            pass
    return floor


def retention_metrics(node):
    try:
        m = node.metrics()
    except Exception:
        return None
    return {"deleted_own": metric_sum(m, "vlpds_retention_deleted_objects_total", log="own"),
            "deleted_dead": metric_sum(m, "vlpds_retention_deleted_objects_total", log="dead"),
            "pruned_seq": metric_sum(m, "vlpds_retention_pruned_seq"),
            "ticks_ok": metric_sum(m, "vlpds_retention_ticks_total", result="ok"),
            "ticks_error": metric_sum(m, "vlpds_retention_ticks_total", result="error")}


@scenario("retention-kill9", f"--log-retention {RETENTION_S}s, 3 nodes under load for 240 s: kill -9 n2 at 75 s, restart it at "
          "135 s; dead log pruned to its fence, no replay needs a pruned segment, old-cursor subscribers get OutdatedCursor and "
          "continue live, restarted node clean")
def s_retention_kill9(ctx):
    ctx.dead_logs, ctx.ret = [], {"cursor_audits": [], "start_audits": []}
    extra = ["--log-retention", f"{RETENTION_S}s"]

    def old_cursor(ctx):
        st = ctx.nodes[0].status()
        ctx.ret["old_cursor"] = st["firehose_last_emitted"]
        ctx.mark(f"old cursor {ctx.ret['old_cursor']} (n1's last emitted)")

    def kill_n2(ctx):
        n = ctx.nodes[1]
        log_id = n.status()["log"]
        r = kill(1)(ctx)
        dead_log(ctx, n, log_id)
        return r

    def start_audit(ctx):
        n = ctx.nodes[1]
        wait_ready([n])
        ctx.mark(f"live audit attached to {n.id} at start")
        ctx.ret["start_audits"].append(FhAudit(n, ctx.outdir, tag="-start"))

    def cursor_audits(ctx):
        # every node (n2 restarted) from a cursor retention has passed: an
        # OutdatedCursor #info, then the stream from the floor on, kept live
        ctx.ret["floor_at_subscribe"] = retained_floor(ctx.prefix)
        ctx.ret["retention_mid"] = {n.id: retention_metrics(n) for n in ctx.nodes}
        ctx.mark(f"old-cursor subscribers on all nodes (cursor {ctx.ret['old_cursor']}, retained floor {ctx.ret['floor_at_subscribe']})")
        ctx.ret["cursor_audits"] = [FhAudit(n, ctx.outdir, tag="-oldcursor", cursor=ctx.ret["old_cursor"]) for n in ctx.nodes]
        time.sleep(1)
        ctx.ret["floor_after_subscribe"] = retained_floor(ctx.prefix)

    acts = [(5, old_cursor), (75, kill_n2), (135, restart(1)), (135.01, start_audit), (200, cursor_audits)]
    res = run_load_scenario(ctx, 3, 240, acts, node_extra=extra, replay=False)
    fails = []
    out = res["retention"] = {"window_s": RETENTION_S, "old_cursor": ctx.ret.get("old_cursor"),
                              "floor_at_subscribe": ctx.ret.get("floor_at_subscribe"),
                              "floor_after_subscribe": ctx.ret.get("floor_after_subscribe"), "retention_mid": ctx.ret.get("retention_mid")}

    logs = {n.id: os.path.join(ctx.outdir, f"{n.id}.log") for n in ctx.nodes}
    dead = ctx.dead_logs[0][1] if ctx.dead_logs else None

    def retired():
        for path in logs.values():
            for line in open(path, errors="replace"):
                if "dead log retired" in line and dead in line:
                    return strip_ansi(line).strip()[:240]
        return None
    end = time.time() + 150
    while dead and not retired() and time.time() < end:
        time.sleep(5)
    out["retired_line"] = retired()
    out["dead_log"] = dead
    if dead:
        ords = log_ordinals(ctx.prefix, dead)
        kinds = [parse_log_object(s3_get(f"{ctx.prefix}/log/{dead}/{o:012}.seg") or b"")["kind"] for o in ords]
        out["dead_log_objects"] = list(zip(ords, kinds))
        out["dead_log_report_left"] = any(k.endswith("/" + dead) for k in s3_list(f"{ctx.prefix}/retain/"))
        if not out["retired_line"]:
            fails.append("dead log never retired")
        if kinds != ["fence"]:
            fails.append(f"dead log not pruned to its fence: {out['dead_log_objects'][:6]}")
        if out["dead_log_report_left"]:
            fails.append("dead log's retain/ report left behind")
        k_audits(ctx, res)  # fence at the first hole, span ends at the fence
    out["retention_end"] = {n.id: retention_metrics(n) for n in ctx.nodes if n.alive()}
    if not any((m or {}).get("deleted_own") for m in out["retention_end"].values()):
        fails.append("no live log pruned")
    if any((m or {}).get("ticks_error") for m in out["retention_end"].values()):
        fails.append("retention pass errors")
    out["final_floor"] = retained_floor(ctx.prefix)
    # nothing needed a pruned segment: no replay/backfill/follower/pass errors in any node log
    bad = {}
    for nid, path in logs.items():
        for line in open(path, errors="replace"):
            if any(b in line for b in RETENTION_BAD):
                bad.setdefault(nid, []).append(strip_ansi(line).strip()[:240])
    out["bad_log_lines"] = {k: v[:5] for k, v in bad.items()}
    out["bad_log_line_counts"] = {k: len(v) for k, v in bad.items()}
    if bad:
        fails.append(f"replay/retention errors in node logs: {out['bad_log_line_counts']}")

    # the reference history: n1's cursorless live audit (stayed up the whole run)
    ref = None
    try:
        ref = json.load(open(os.path.join(ctx.outdir, "fhaudit-n1.json")))
    except Exception:
        fails.append("no n1 live audit")
    out["cursor_audits"] = []
    for a in ctx.ret["cursor_audits"]:
        data = a.stop()
        r = audit_report(data, {}, a.node.id)
        r["info_names"] = (data or {}).get("info_names")
        if not data or not data.get("commits"):
            fails.append(f"{a.node.id}: old-cursor subscriber got no commits")
            out["cursor_audits"].append(r)
            continue
        if (r["info_names"] or [None])[0] != "OutdatedCursor":
            fails.append(f"{a.node.id}: old cursor without OutdatedCursor first ({r['info_names']})")
        if r["reorders"] or r["dups"]:
            fails.append(f"{a.node.id}: old-cursor stream reorders {r['reorders']} dups {r['dups']}")
        if r["first_seq"] <= (ctx.ret.get("old_cursor") or 0):
            fails.append(f"{a.node.id}: old-cursor stream starts at {r['first_seq']}, at or below the cursor")
        if ref:
            # from its first event on, exactly n1's history to the end of the run
            seqs = [c["s"] if isinstance(c, dict) else c[0] for c in data["commits"]]
            ref_seqs = [c["s"] if isinstance(c, dict) else c[0] for c in ref["commits"]]
            want = [x for x in ref_seqs if x >= seqs[0]]
            r["ref_from_first"], r["got"] = len(want), len(seqs)
            if seqs != want:
                fails.append(f"{a.node.id}: old-cursor stream != n1 history from seq {seqs[0]} ({len(seqs)} vs {len(want)})")
            # it continued from the floor: nothing above the floor it was
            # served from (at most the one read after it subscribed) is skipped
            floor = ctx.ret.get("floor_after_subscribe") or 0
            r["skipped_above_floor"] = len([x for x in ref_seqs if floor < x < seqs[0]])
            if r["skipped_above_floor"]:
                fails.append(f"{a.node.id}: {r['skipped_above_floor']} events above the floor {floor} skipped")
        out["cursor_audits"].append(r)
    # the restarted node: its start audit is n1's history over the common range
    out["start_audits"] = []
    for a in ctx.ret["start_audits"]:
        data = a.stop()
        r = audit_report(data, {}, a.node.id)
        if ref and data:
            d = history_diff({"n1": ref, f"{a.node.id}-start": data}, common_range=True)
            r["agree"], r["diff"] = d["agree"], d.get("pairs")
        else:
            r["agree"] = False
        if not r["agree"]:
            fails.append(f"{a.node.id}: start audit disagrees with n1")
        out["start_audits"].append(r)
    codes = res.get("exit_codes") or {}
    if codes.get("n1") or codes.get("n3") or codes.get("n2") not in ([-9], [137]):
        fails.append(f"unexpected exits {codes}")
    if res.get("final_distribution") and len([1 for v in res["final_distribution"].values() if v]) < 3:
        fails.append(f"restarted node owns nothing: {res['final_distribution']}")
    if fails:
        res.setdefault("k_fail", []).extend(fails)
    log(f"  retention: retired={bool(out['retired_line'])} dead objs={out.get('dead_log_objects')} "
        f"floor={out['final_floor']} end={out['retention_end']} bad={out['bad_log_line_counts']} fails={fails}")
    return res


# ---- container scenarios


def net(idx, up):
    def f(ctx):
        n = ctx.nodes[idx]
        ctx.mark(f"network {'reconnect' if up else 'disconnect'} {n.id}")
        n.connect() if up else n.disconnect()
        return None if up else "fault"
    return f


def revive_dead(ctx):
    for n in ctx.nodes:
        if not n.alive():
            ctx.mark(f"restart dead {n.id} (exit codes {n.exit_codes()})")
            n.start()


def containers(skews=None):
    def deco(fn):
        def wrapped(ctx):
            ctx.factory = CNode
            CNode.skews = skews or {}
            return fn(ctx)
        return wrapped
    return deco


@scenario("ctr-baseline-3", "[containers] 3 nodes, steady split (sanity for the container path)")
@containers()
def s_ctr_base(ctx):
    return run_load_scenario(ctx, 3, 30, [])


@scenario("ctr-partition", "[containers] docker network disconnect one of 3 nodes (S3+peers+clients) for 12 s")
@containers()
def s_ctr_part(ctx):
    return run_load_scenario(ctx, 3, 55, [(15, net(1, False)), (27, net(1, True)), (40, revive_dead)])


@scenario("ctr-pause", "[containers] docker pause (cgroup freeze) one of 3 nodes for 4x TTL, then unpause")
@containers()
def s_ctr_pause(ctx):
    return run_load_scenario(ctx, 3, 55, [(15, kill(1, signal.SIGSTOP)), (15 + 4 * TTL_MS / 1000, kill(1, signal.SIGCONT, "unpause n2")),
                                          (40, revive_dead)])


@scenario("ctr-skew-small", "[containers] clocks n2 +250 ms, n3 -250 ms (inside the ttl/5 margin); kill -9 n2, restart")
@containers({"n2": "+0.25s", "n3": "-0.25s"})
def s_ctr_skew_small(ctx):
    return run_load_scenario(ctx, 3, 55, [(15, kill(1)), (35, restart(1))])


@scenario("ctr-skew-large", "[containers] clocks n2 +2.5 s, n3 -2.5 s (beyond the margin); kill -9 n2, restart")
@containers({"n2": "+2.5s", "n3": "-2.5s"})
def s_ctr_skew_large(ctx):
    return run_load_scenario(ctx, 3, 55, [(15, kill(1)), (35, restart(1))])


@scenario("ctr-skew-steady", "[containers] clocks n2 +2.5 s, n3 -2.5 s, no faults (merge lag/ordering under skew)")
@containers({"n2": "+2.5s", "n3": "-2.5s"})
def s_ctr_skew_steady(ctx):
    return run_load_scenario(ctx, 3, 30, [])


# ---- two builds: rolling upgrade / rollback / refusal (DESIGN.md "Rolling
# upgrades and format versioning"). bench/ha/upgrade.sh builds the previous
# release and this tree, plain and with the test-level feature (level 2,
# segment magic VLSEGT1), so finalize changes formats.

UPGRADE_DIR = os.environ.get("VLPDS_UPGRADE_DIR", os.path.join(PKG, "target", "upgrade"))
OLD_BIN = os.environ.get("VLPDS_HA_OLD_BIN", os.path.join(UPGRADE_DIR, "prev", "vlpds"))
NEW_BIN = os.environ.get("VLPDS_HA_NEW_BIN", os.path.join(UPGRADE_DIR, "new", "vlpds"))
NEW_TL_BIN = os.environ.get("VLPDS_HA_NEW_TL_BIN", os.path.join(UPGRADE_DIR, "new-tl", "vlpds"))
SEG_MAGICS = {b"VLSEG06\n": "VLSEG06", b"VLSEGT1\n": "VLSEGT1", b"VLFENCE\n": "fence"}


def segment_magics(prefix):
    """{magic name: count} over every log object of `prefix`."""
    out = {}
    for k in s3_list(f"{prefix}/log/"):
        st, b = s3_req("GET", k, headers={"range": "bytes=0-7"})
        if st not in (200, 206):
            continue  # pruned meanwhile
        name = SEG_MAGICS.get(b[:8], repr(b[:8]))
        out[name] = out.get(name, 0) + 1
    return out


def node_objects(prefix, node_id):
    """Objects a node writes when it joins: its lease, writer claims naming it, its logs."""
    objs = [k for k in s3_list(f"{prefix}/nodes/") if k.endswith(f"/{node_id}")]
    objs += [k for k in s3_list(f"{prefix}/log/") if k.split("/log/", 1)[1].startswith(f"{node_id}.")]
    for k in s3_list(f"{prefix}/writers/"):
        b = s3_get(k) or b""
        if f'"node_id":"{node_id}"'.encode() in b:
            objs.append(k)
    return objs


def cluster_version(ctx, via=None):
    """getClusterStatus `version` from `via` (else the first live node);
    its `binary` is that node's build."""
    for n in ([via] if via else ctx.nodes):
        if n.alive():
            try:
                _, raw = http("GET", n.url + "/xrpc/vlpds.admin.getClusterStatus", headers={"authorization": ADMIN_AUTH}, timeout=5)
                return json.loads(raw).get("version")
            except Exception:
                continue
    return None


def swap_build(idx, bin_path, label, refuse=False):
    """Rolling step: SIGTERM node idx (graceful handoff), start it on `bin_path`.
    With `refuse` the new build must exit 7 (incompatible_level) by itself
    within 20 s; the node is then left down."""
    def f(ctx):
        n = ctx.nodes[idx]
        t = ctx.mark(f"SIGTERM {n.id} -> {label}")
        if n.alive():
            n.signal(signal.SIGTERM)
            n.wait_exit(30)
        n.bin = bin_path
        n.start()
        if refuse:
            n.wait_exit(20)
            ctx.mark(f"{n.id} on {label} exited rc={n.exit_codes()[-1:]} after {time.time() - t:.1f}s")
            ctx.ret.setdefault("refusals", []).append({"node": n.id, "build": label, "rc": n.exit_codes()[-1:]})
            return "fault"
        wait_ready([n], timeout=60)
        ctx.mark(f"{n.id} up on {label} after {time.time() - t:.1f}s")
        return "fault"
    return f


def finalize(idx, expect, level=None):
    """POST setFeatureLevel through node idx (level: default that node's build max). `expect`:
    the HTTP status it must get (200, or 409 IncompatibleNodes). Also records
    the segment magics in the bucket right before the raise."""
    def f(ctx):
        n = ctx.nodes[idx]
        ctx.ret.setdefault("magics_before_finalize", segment_magics(ctx.prefix))
        lv = level or (cluster_version(ctx, n) or {}).get("binary", {}).get("max")
        try:
            r = admin_post(n, "vlpds.admin.setFeatureLevel", {"level": lv}, timeout=30)
            code, body = 200, r
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read()[:300].decode(errors="replace")
        ctx.mark(f"finalize level {lv} via {n.id}: {code} {body}")
        ctx.ret.setdefault("finalize", []).append({"level": lv, "status": code, "expect": expect, "body": body})
        return None
    return f


def upgrade_checks(ctx, res, finalized, new_formats):
    """Two-build invariants on top of `failures`: finalize outcomes as expected;
    segments in the test level's format only after a finalize (and then some);
    refused nodes exited 7 and left nothing in the bucket."""
    fails = []
    for f in ctx.ret.get("finalize", []):
        if f["status"] != f["expect"]:
            fails.append(f"finalize to {f['level']}: {f['status']}, expected {f['expect']}")
    before = ctx.ret.get("magics_before_finalize") or {}
    res["magics_before_finalize"] = before
    res["magics_end"] = end = segment_magics(ctx.prefix)
    if before.get("VLSEGT1"):
        fails.append(f"test-level segments before finalize: {before}")
    if new_formats and not end.get("VLSEGT1"):
        fails.append(f"no test-level segments after finalize: {end}")
    if not new_formats and end.get("VLSEGT1"):
        fails.append(f"test-level segments without a finalize: {end}")
    if set(end) - {"VLSEG06", "VLSEGT1", "fence"}:
        fails.append(f"unknown log objects: {end}")
    for r in ctx.ret.get("refusals", []):
        if r["rc"] != [7]:
            fails.append(f"{r['node']} on {r['build']} exited {r['rc']}, expected [7] (incompatible_level)")
    res["refusals"] = ctx.ret.get("refusals", [])
    res["cluster_version"] = v = cluster_version(ctx)
    if v and finalized is not None and v.get("active") != finalized:
        fails.append(f"active level {v.get('active')}, expected {finalized}")
    for nid in ctx.ret.get("refused_ids", []):
        left = node_objects(ctx.prefix, nid)
        if left:
            fails.append(f"refused node {nid} left objects: {left[:5]}")
    # a node that crashed (not a refusal, not a graceful exit) fails the run
    refused = {r["node"] for r in ctx.ret.get("refusals", [])}
    for nid, codes in (res.get("exit_codes") or {}).items():
        bad = [c for c in codes if c not in (0, 7) or (c == 7 and nid not in refused)]
        if bad:
            fails.append(f"{nid} exited {codes}")
    if fails:
        res.setdefault("k_fail", []).extend(fails)
    log(f"  upgrade: finalize={ctx.ret.get('finalize')} magics before={before} end={end} refusals={res['refusals']} "
        f"version={(v or {}).get('active')} fails={fails}")
    return res


def upgrade_ctx(ctx):
    ctx.ret = {}
    for b in (OLD_BIN, NEW_TL_BIN):
        if not os.path.exists(b):
            raise RuntimeError(f"{b} missing: run bench/ha/upgrade.sh (builds the previous and current releases)")


@scenario("upgrade-rolling",
          "[two builds] 3 old nodes under load; replace them one by one (SIGTERM) with the new build (test feature "
          "level 2); finalize; every acked write readable, checker + firehose complete, new segment format only after finalize")
def s_upgrade_rolling(ctx):
    upgrade_ctx(ctx)
    acts = [(8, swap_build(1, NEW_TL_BIN, "new")), (8.01, audit_from_start(1)),
            (18, swap_build(2, NEW_TL_BIN, "new")), (18.01, audit_from_start(2)),
            (27, checker_with_cursor(1, back_s=20)),
            (28, swap_build(0, NEW_TL_BIN, "new")), (28.01, audit_from_start(0)),
            (36, finalize(1, 200))]
    res = run_load_scenario(ctx, 3, 50, acts, node_bins=[OLD_BIN] * 3)
    return upgrade_checks(ctx, res, finalized=2, new_formats=True)


@scenario("upgrade-rolling-l1",
          "[two builds] the real release path: 3 old nodes under load, replaced one by one with the current build "
          "(no format change between them: level 1 both); finalize to 2 is refused (no build runs it)")
def s_upgrade_rolling_l1(ctx):
    upgrade_ctx(ctx)
    acts = [(8, swap_build(1, NEW_BIN, "new")), (8.01, audit_from_start(1)),
            (18, swap_build(2, NEW_BIN, "new")), (18.01, audit_from_start(2)),
            (27, checker_with_cursor(1, back_s=20)),
            (28, swap_build(0, NEW_BIN, "new")), (28.01, audit_from_start(0)),
            (36, finalize(1, 400, level=2))]
    res = run_load_scenario(ctx, 3, 45, acts, node_bins=[OLD_BIN] * 3)
    return upgrade_checks(ctx, res, finalized=1, new_formats=False)


@scenario("upgrade-rollback",
          "[two builds] 3 old nodes under load; upgrade 2 of 3 to the new build (test level 2); finalize is refused "
          "(an old node is live); roll both back to the old build; nothing in the new format ever written")
def s_upgrade_rollback(ctx):
    upgrade_ctx(ctx)
    acts = [(8, swap_build(1, NEW_TL_BIN, "new")), (8.01, audit_from_start(1)),
            (17, swap_build(2, NEW_TL_BIN, "new")), (17.01, audit_from_start(2)),
            (25, finalize(1, 409)),
            (28, swap_build(2, OLD_BIN, "old (rollback)")), (28.01, audit_from_start(2)),
            (36, swap_build(1, OLD_BIN, "old (rollback)")), (36.01, audit_from_start(1)),
            (38, checker_with_cursor(2, back_s=25))]
    res = run_load_scenario(ctx, 3, 50, acts, node_bins=[OLD_BIN] * 3)
    return upgrade_checks(ctx, res, finalized=1, new_formats=False)


@scenario("upgrade-old-refused",
          "[two builds] old cluster upgraded node by node to the new build (test level 2) and finalized under load; "
          "then an extra old node (n4) and n2 rolled back to the old build both exit 7 without writing anything; "
          "n2 comes back on the new build; the cluster is unaffected")
def s_upgrade_old_refused(ctx):
    upgrade_ctx(ctx)
    ctx.ret["refused_ids"] = ["n4"]
    acts = [(5, swap_build(1, NEW_TL_BIN, "new")), (11, swap_build(2, NEW_TL_BIN, "new")),
            (17, swap_build(0, NEW_TL_BIN, "new")), (17.01, audit_from_start(0)),
            (23, finalize(1, 200)),
            (27, swap_build(3, OLD_BIN, "old", refuse=True)),
            (31, swap_build(1, OLD_BIN, "old (rollback after finalize)", refuse=True)),
            (36, swap_build(1, NEW_TL_BIN, "new")), (36.01, audit_from_start(1)),
            (38, checker_with_cursor(1, back_s=20))]
    res = run_load_scenario(ctx, 4, 50, acts, start_nodes=3, expect_final=3, node_bins=[OLD_BIN] * 4)
    return upgrade_checks(ctx, res, finalized=2, new_formats=True)


def raise_race(old_idx, via_idx, delay_s):
    """Starts an old build on node old_idx and, `delay_s` later (inside its
    startup gate / lease write), finalizes through via_idx. Never both: the
    raise succeeds and the old node exits 7, or the raise gets 409 and the
    old node runs (then it is stopped and the raise retried)."""
    def f(ctx):
        n, via = ctx.nodes[old_idx], ctx.nodes[via_idx]
        lv = (cluster_version(ctx, via) or {}).get("binary", {}).get("max")
        ctx.ret.setdefault("magics_before_finalize", segment_magics(ctx.prefix))
        n.bin = OLD_BIN
        out = {}

        def raise_():
            time.sleep(max(delay_s, 0))
            try:
                admin_post(via, "vlpds.admin.setFeatureLevel", {"level": lv}, timeout=30)
                out["raise"] = 200
            except urllib.error.HTTPError as e:
                out["raise"] = e.code
                out["body"] = e.read()[:300].decode(errors="replace")
        t = threading.Thread(target=raise_)
        ctx.mark(f"start old {n.id} and finalize level {lv} via {via.id} {delay_s * 1000:.0f} ms later")
        if delay_s < 0:  # the raise first, the old node |delay| into it
            t.start()
            time.sleep(-delay_s)
            n.start()
        else:
            n.start()
            t.start()
        t.join(40)
        # the old node either refuses (exit 7) by itself or keeps running
        end = time.time() + 10
        while time.time() < end and n.alive():
            time.sleep(0.2)
        up = n.alive()
        ctx.mark(f"raise -> {out.get('raise')} {out.get('body', '')}; old {n.id} {'running' if up else f'exited {n.exit_codes()}'}")
        race = {"raise": out.get("raise"), "old_running": up, "old_exits": n.exit_codes()}
        ok = (out.get("raise") == 200 and not up and n.exit_codes()[-1:] == [7]) or (out.get("raise") == 409 and up)
        race["ok"] = ok
        ctx.ret["race"] = race
        if up:
            # the raise aborted: the old node leaves (graceful), then it goes through
            n.signal(signal.SIGTERM)
            n.wait_exit(30)
            ctx.ret.setdefault("finalize", []).append({"level": lv, "status": out.get("raise"), "expect": 409, "body": out.get("body")})
            return finalize(via_idx, 200)(ctx)
        ctx.ret.setdefault("finalize", []).append({"level": lv, "status": out.get("raise"), "expect": 200})
        ctx.ret.setdefault("refusals", []).append({"node": n.id, "build": "old (race)", "rc": n.exit_codes()[-1:]})
        return "fault"
    return f


@scenario("upgrade-raise-race",
          "[two builds] old cluster upgraded to the new build (test level 2), still at level 1, under load; an old node starts while a "
          "finalize runs: either the raise aborts (409) and the old node runs, or the old node exits 7; never both")
def s_upgrade_raise_race(ctx):
    upgrade_ctx(ctx)
    delay = float(os.environ.get("VLPDS_HA_RACE_DELAY_MS", str(random.Random().choice([-50, -5, 20, 150])))) / 1000
    acts = [(5, swap_build(1, NEW_TL_BIN, "new")), (10, swap_build(2, NEW_TL_BIN, "new")),
            (15, swap_build(0, NEW_TL_BIN, "new")), (15.01, audit_from_start(0)),
            (22, raise_race(3, 1, delay))]
    res = run_load_scenario(ctx, 4, 40, acts, start_nodes=3, expect_final=3, node_bins=[OLD_BIN] * 4)
    res["race"] = ctx.ret.get("race")
    if not (res["race"] or {}).get("ok"):
        res.setdefault("k_fail", []).append(f"raise race: {res['race']}")
    return upgrade_checks(ctx, res, finalized=2, new_formats=True)


def run_one(name, run_id):
    fn, desc = SCEN[name]
    outdir = os.path.join(HERE, "out", run_id, name)
    os.makedirs(outdir, exist_ok=True)
    prefix = f"ha-{run_id}-{name}"
    ctx = Ctx(name, outdir, prefix)
    log(f"=== {name}: {desc} (prefix {prefix})")
    t = time.time()
    try:
        res = fn(ctx)
        if "convergence_s" not in res:
            res["why"] = failures(res)
        else:
            res["why"] = [w for w, bad in (
                (f"no convergence: {res.get('convergence_s')}", res.get("convergence_s") is None),
                (f"checker: {res['checker'].get('result')} {res['checker'].get('first_failures')}",
                 res["checker"].get("result") != "PASS"),
                (f"verify: {res['verify'].get('missing')} missing", res["verify"].get("missing") != 0)) if bad]
        res["verdict"] = "FAIL" if res["why"] else "PASS"
    except Exception as e:
        traceback.print_exc()
        res = {"verdict": "ERROR", "error": repr(e), "events": ctx.events}
    finally:
        teardown(ctx)
    res["scenario"] = name
    if CLEANUP:
        res["prefix_deleted"] = delete_prefix(prefix)
    res["description"] = desc
    res["wall_s"] = round(time.time() - t, 1)
    json.dump(res, open(os.path.join(outdir, "result.json"), "w"), indent=1, default=str)
    line = summarize(res)
    with open(os.path.join(HERE, "out", run_id, "summary.md"), "a") as f:
        f.write(line + "\n")
    log(line)
    if res["verdict"] != "PASS":
        for w in res.get("why") or [res.get("error")]:
            log(f"  {name} FAIL: {str(w)[:2000]}")
    return res


def summarize(r):
    v = r.get("verify") or {}
    ck = r.get("checker") or {}
    pr = r.get("probe") or {}
    errs = sum(lg.get("errors", 0) for lg in r.get("loadgens", []))
    dist = r.get("final_distribution") or r.get("distribution") or {}
    dist_s = " ".join(f"{k}:{v if isinstance(v, (int, bool)) else len(v)}" for k, v in sorted(dist.items()))
    fl = [f"{a['node']}:{a.get('fh_missing')}" for a in r.get("fh_live", []) if a.get("node_stayed_up")]
    fr = [f"{a['node']}:{a.get('fh_missing')}{'' if a.get('node_stayed_up') else '(rejoined)'}" for a in r.get("fh_replay", [])]
    fs = [f"{a['node']}:{'ok' if a.get('agree') else 'GAP'}" for a in r.get("fh_start", [])]
    xc = [f"{c.get('node')}:{c.get('result')}" for c in r.get("extra_checkers", [])]
    errs_by = {lg["node"]: lg.get("errors", 0) for lg in r.get("loadgens", [])}
    return (f"| {r['scenario']} | {r['verdict']} | acked {v.get('acked')} lost {v.get('missing')} | checker {ck.get('result')} "
            f"| fh-missing live {' '.join(fl)} replay {' '.join(fr)} start-audits {' '.join(fs) or '-'} cursor-checkers {' '.join(xc) or '-'} | windows {pr.get('windows')} | errs {errs_by} "
            f"({ck.get('commits')} commits, fails {ck.get('failures')}) | unavail {pr.get('unavail_s')}s recov {pr.get('recovery_s')}s "
            f"(max partition {pr.get('max_partition_outage_s')}s) | loadgen errs {errs} | final {dist_s} | exits {r.get('exit_codes')} "
            f"| history agree replay={(r.get('fh_replay_diff') or {}).get('agree')} live={(r.get('fh_live_diff') or {}).get('agree')} "
            f"| cp req/s {r.get('cp_req_per_s')} |")


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        for k, (_, d) in SCEN.items():
            print(f"{k:18} {d}")
        return
    names = sys.argv[2:] if sys.argv[1] == "run" else sys.argv[1:]
    if names == ["all"]:
        names = list(SCEN)
    for n in names:
        if n not in SCEN:
            sys.exit(f"unknown scenario {n}")
    if not os.path.exists(FAULTPROXY):
        subprocess.check_call(["go", "build", "-o", FAULTPROXY, "."], cwd=os.path.join(HERE, "faultproxy"))
    run_id = os.environ.get("HA_RUN_ID", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(os.path.join(HERE, "out", run_id), exist_ok=True)
    verdicts = []
    for n in names:
        verdicts.append((n, run_one(n, run_id)["verdict"]))
    print("\n".join(f"{n:18} {v}" for n, v in verdicts))
    sys.exit(0 if all(v == "PASS" for _, v in verdicts) else 1)


if __name__ == "__main__":
    main()
