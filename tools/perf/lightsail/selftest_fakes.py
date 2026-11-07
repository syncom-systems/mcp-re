# SPDX-License-Identifier: Apache-2.0
"""The fake instruments of the selftest: a proxy, a bench, a rig, and a tiny RESP primary."""

from __future__ import annotations

import socketserver
from pathlib import Path

#: A proxy that states the pool it was given (or FAKE_PROXY_STATES_POOL, to model one that
#: ignored the flag), serves, and then writes a per-request audit line.
FAKE_PROXY = r'''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
pool = int(a[a.index("--replay-redis-pool-size") + 1]) if "--replay-redis-pool-size" in a else 8
pool = int(os.environ.get("FAKE_PROXY_STATES_POOL", pool))
for line in ("mcp-re-proxy: replay-store backend=redis tier=REDIS_WAIT_QUORUM guarantee=x",
             f"mcp-re-proxy: replay redis pool = {pool} connections (--replay-redis-pool-size; default 8)",
             "mcp-re-proxy: async fleet serving on 127.0.0.1:1 (1 cores)", "audit: per-request record"):
    print(line, file=sys.stderr)
'''

#: How each fake instrument starts its proxy: through MCP_RE_PROXY_CLI, reading stderr the
#: way the real ones do. The audit line after the serving line must still arrive.
START_PROXY = r'''
import subprocess
def start_proxy():
    p = subprocess.run([os.environ["MCP_RE_PROXY_CLI"], "--bind", "127.0.0.1:0"], capture_output=True, text=True, timeout=30)
    assert "async fleet serving on" in p.stderr and "audit: per-request record" in p.stderr, p.stderr
'''

FAKE_BENCH = r'''#!/usr/bin/env python3
import json, os, sys
''' + START_PROXY + r'''
cores = int(os.environ["MCP_RE_LOADGEN_CORES"]); req = int(os.environ["MCP_RE_LOADGEN_REQUESTS"])
out = os.environ["MCP_RE_LOADGEN_OUT"]
assert os.environ["MCP_RE_LOADGEN_MODE"] == "cold" and os.environ["MCP_RE_PROXY_CLI"].startswith("/")
start_proxy()
fail_marker = os.environ.get("FAKE_FAIL_REP_AT", "")
rep = out.rsplit("rep", 1)[-1].split(".")[0]
if fail_marker == f"c{cores}-rep{rep}":
    print("thread panicked: simulated"); sys.exit(101)
# The real harness writes a trust document under the inherited umask, and the proxy refuses a
# group-writable one; an Ubuntu login shell's 0002 makes every rep fail exactly like this.
trust = out + ".trust.json"
open(trust, "w").close()
if os.stat(trust).st_mode & 0o022:
    print(f"trust document is group-writable (mode {os.stat(trust).st_mode & 0o777:o}) and was refused"); sys.exit(101)
os.unlink(trust)
tput = 1000.0 * (cores if cores else 3) ** 0.8
json.dump({"schema": "mcp-re-load-harness-report/v2", "config": {"declared_cores": cores},
           "results": {"successes": req, "failures": 0, "throughput_rps": tput,
                       "added_latency_us": {"p50": 900, "p99": 4000, "p999": 9000}}}, open(out, "w"))
print("test result: ok. 1 passed; 0 failed")
'''

FAKE_RIG = r'''#!/usr/bin/env python3
import json, os, sys, time
''' + START_PROXY + r'''
a = sys.argv[1:]
start_proxy()
if a == ["--smoke"]:
    print("smoke ok"); sys.exit(0)
assert os.environ["MCP_RE_SAT_REQUIRE_ECHO"] == "1", "a measured success must carry the backend echo"
def arg(k, d=None):
    return a[a.index(k) + 1] if k in a else d
cores = int(arg("--cores")); conns = int(arg("--connections", "256"))
for k in ("MCP_RE_SAT_REDIS_URL", "MCP_RE_SAT_BACKEND", "MCP_RE_SAT_LOADGEN", "MCP_RE_PROXY_CLI"):
    assert os.environ[k], k
# client-limited at the first rung for cores >= 4, saturated after: exercises the ladder
saturated = not (cores >= 4 and conns == 256)
rps = 5000.0 * min(cores if cores else 8, 8) * (1.0 if saturated else 0.7)
requests = int(arg("--requests"))
assert requests <= int(os.environ["FAKE_RUNG_CEILING"]) // sum(range(2, int(arg("--max-generators")) + 1)), \
    "a rung that could climb past the signer retention budget"
row = {"cores": cores, "generators": 3, "rps": rps, "last_gain_pct": 2.0 if saturated else 9.0,
       "saturated": saturated, "failure_pct": 0.0, "p50_us": 700, "failures": 0,
       "proxy_cpu_secs": 1.0, "backend_cpu_secs": 1.0, "generator_cpu_secs": 1.0}
sent = requests * (2 + 3)                   # the steps at 2 and 3 generators were served
if os.environ.get("FAKE_RIG_COLLAPSE") == f"c{cores}":
    # The probe at 3 generators met refusals: each generator stops at its first error, the
    # step comes out slower, and the real rig then keeps the 2-generator row and calls it PROXY.
    for _ in range(3):
        print('  generator error: read: non-2xx response: http/1.1 409 conflict body={"wire_code":"mcp-re.replay_cache_unavailable"}')
    row.update(generators=2, last_gain_pct=-94.0, saturated=True)
    sent = requests * 2 + requests // 4
counter = os.environ["FAKE_SET_COUNTER"]
with open(counter, "r+") as fh:
    n = int(fh.read() or 0) + sent
    fh.seek(0); fh.truncate(); fh.write(str(n))
time.sleep(0.6)                              # the queue sampler sees the rung
json.dump({"schema": "mcp-re-saturation-rig/v1", "points": [row]}, open(os.environ["MCP_RE_SAT_OUT"], "w"))
print("wrote")
'''


class FakePrimary(socketserver.ThreadingTCPServer):
    """Just enough RESP for the queue sampler: CLIENT ID / CLIENT LIST, INFO, CONFIG GET. The
    SET count is whatever the fake rig wrote to `counter` — the store-side tally a rung's
    steps are checked against."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, counter: Path):
        self.counter = counter
        super().__init__(("127.0.0.1", 0), FakePrimaryHandler)


class FakePrimaryHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            head = self.rfile.readline()
            if not head:
                return
            args = []
            for _ in range(int(head[1:])):
                size = int(self.rfile.readline()[1:])
                args.append(self.rfile.read(size + 2)[:-2].decode())
            self.wfile.write(self.answer([a.upper() for a in args[:2]]))

    def answer(self, cmd: list[str]) -> bytes:
        def bulk(text: str) -> bytes:
            data = text.encode()
            return b"$%d\r\n%s\r\n" % (len(data), data)
        if cmd == ["CLIENT", "ID"]:
            return b":1\r\n"
        if cmd == ["CLIENT", "LIST"]:
            return bulk("id=1 addr=x flags=N cmd=client|list qbuf=0\nid=7 addr=x flags=b cmd=wait qbuf=40\n")
        if cmd[:1] == ["CONFIG"]:
            return b"*0\r\n"
        if cmd == ["INFO", "CLIENTS"]:
            return bulk("# Clients\r\nblocked_clients:1\r\n")
        if cmd == ["INFO", "COMMANDSTATS"]:
            sets = int(self.server.counter.read_text() or 0)
            return bulk(f"# Commandstats\r\ncmdstat_set:calls={sets},usec=1\r\ncmdstat_wait:calls={sets},usec=1\r\n")
        if cmd == ["INFO", "REPLICATION"]:
            return bulk("# Replication\r\nrole:master\r\nmaster_repl_offset:1000\r\n"
                        "slave0:ip=127.0.0.1,port=8631,state=online,offset=940,lag=0\r\n")
        return b"-ERR fake primary\r\n"


def telemetry_reading(**over: object) -> dict:
    base = {"available": True, "host_busy_avg": 0.5, "steal_avg": 0.0, "max_cpu_busy_avg": 0.6,
            "ctxt_per_s_avg": 1e5, "procs_running_avg": 8, "tcp_tw_max": 100,
            "categories": {"proxy": {"cores_avg": 3.6}, "loadgen": {"cores_avg": 4.0},
                           "backend": {"cores_avg": 1.0}, "redis": {"pid_max_cores_avg": 0.2}}}
    for key, value in over.items():
        if key.startswith("cat_"):
            name, field = key[4:].split("__")
            base["categories"].setdefault(name, {})[field] = value
        else:
            base[key] = value
    return base

