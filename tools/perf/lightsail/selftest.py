# SPDX-License-Identifier: Apache-2.0
"""Local selftest of the Lightsail orchestration — no host, no Redis, no cloud.

Two layers. Unit cases pin the decisions: the knee and plateau rules, every attribution
rule (each with the telemetry that must fire it), rep validation, the rig verdict mapping,
the ceiling statement in all three outcomes, and the host identity check. The campaign case
then runs the REAL `ceiling.py campaign` end to end against fake instruments (small Python
programs standing in for the bench and the rig) and checks the run directory: the layout,
a deliberately failing rep recorded as INCOMPLETE without stopping the campaign, the
offered-load ladder climbing on a CLIENT verdict, a host that is not the declared context
stopping before any measurement, and a summary that states its rule set.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

from analysis import ceiling_statement, classify, describe_curve  # noqa: E402
from hostfacts import check_expected  # noqa: E402
from phases import rig_verdict, startup_facts, validate_bench_rep  # noqa: E402
from redis_queue import store_clients, summarize as queue_summary  # noqa: E402

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
import json, os, sys
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
row = {"cores": cores, "generators": 3, "rps": rps, "last_gain_pct": 2.0 if saturated else 9.0,
       "saturated": saturated, "failure_pct": 0.0, "p50_us": 700, "failures": 0,
       "proxy_cpu_secs": 1.0, "backend_cpu_secs": 1.0, "generator_cpu_secs": 1.0}
json.dump({"schema": "mcp-re-saturation-rig/v1", "points": [row]}, open(os.environ["MCP_RE_SAT_OUT"], "w"))
print("wrote")
'''


def _telemetry(**over: object) -> dict:
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


def units() -> None:
    # Curves: linear has no knee; a bend is found where incremental efficiency < 0.5.
    linear = describe_curve([(1, 100.0), (2, 200.0), (4, 400.0), (8, 800.0)])
    assert linear["knee"] is None and linear["still_scaling_at_top"] and abs(linear["rows"][-1]["efficiency_vs_1"] - 1) < 1e-9
    bent = describe_curve([(1, 100.0), (2, 190.0), (4, 300.0), (8, 310.0), (16, 312.0)])
    assert bent["knee"] == 8 and bent["plateau_from"] == 4 and not bent["still_scaling_at_top"], bent

    # Attribution: each rule fires on the evidence it names, in the declared order.
    kw = dict(cores=4, workers=1, vcpus=32, client_categories=("loadgen", "rig"), backend_budget=6)
    assert classify(_telemetry(), verdict="PROXY", **kw)["label"] == "PROXY_CPU"
    assert classify(_telemetry(steal_avg=0.08), verdict="PROXY", **kw)["label"] == "HOST_SCHEDULING"
    assert classify(_telemetry(cat_redis__pid_max_cores_avg=0.95), verdict="PROXY", **kw)["label"] == "REPLAY_TIER"
    assert classify(_telemetry(cat_backend__cores_avg=5.5), verdict="PROXY", **kw)["label"] == "BACKEND"
    assert classify(_telemetry(tcp_tw_max=90000), verdict="PROXY", **kw)["label"] == "PROXY_CPU", "a TIME_WAIT count is not refusal"
    assert classify(_telemetry(netstat_delta={"ListenOverflows": 12}), verdict="PROXY", **kw)["label"] == "OS_CONNECTION_PATH"
    hot1 = _telemetry(cat_proxy__cores_avg=2.0, proxy_thread_max_avg=0.99, proxy_threads_hot_avg=1.0)
    assert classify(hot1, verdict="PROXY", **kw)["label"] == "PROXY_SERIALIZATION_OR_CONTENTION"
    hot4 = _telemetry(cat_proxy__cores_avg=3.2, proxy_thread_max_avg=0.99, proxy_threads_hot_avg=3.6)
    assert classify(hot4, verdict="PROXY", **kw)["label"] == "PROXY_CPU", "every serving thread saturated"
    assert classify(_telemetry(), verdict="CLIENT", **kw)["label"] == "CLIENT_LIMITED"
    assert classify(_telemetry(host_busy_avg=0.97), verdict="CLIENT", **kw)["label"] == "INDETERMINATE"
    assert classify(_telemetry(), verdict="INVALID", **kw)["label"] == "INVALID"
    low = _telemetry(cat_proxy__cores_avg=1.5)
    assert classify(low, verdict="PROXY", **kw)["label"] == "PROXY_SERIALIZATION_OR_CONTENTION"
    assert classify(_telemetry(cat_proxy__cores_avg=2.0, host_busy_avg=0.95), verdict="PROXY", **kw)["label"] == "INDETERMINATE"
    assert classify(_telemetry(cat_proxy__cores_avg=2.8), verdict="PROXY", **kw)["label"] == "UNEXPLAINED"
    assert classify({"available": False}, verdict="PROXY", **kw)["label"] == "UNATTRIBUTED"
    # shipped auto topology (cores=0): the proxy's budget is the whole host
    assert classify(_telemetry(cat_proxy__cores_avg=28.0), verdict="PROXY", cores=0, workers=0, vcpus=32,
                    client_categories=("loadgen",), backend_budget=6)["label"] == "PROXY_CPU"

    # Rep validation and rig verdicts.
    with tempfile.TemporaryDirectory() as tmp:
        rpt = Path(tmp) / "r.json"
        assert validate_bench_rep(0, "test result: ok. 1 passed", rpt, 8000)[1] == "no report written"
        rpt.write_text(json.dumps({"results": {"successes": 7999, "failures": 0}}))
        assert "7999 of 8000" in validate_bench_rep(0, "test result: ok. 1 passed", rpt, 8000)[1]
        assert "nothing was measured" in validate_bench_rep(0, "running 0 tests", rpt, 8000)[1]
        assert validate_bench_rep(101, "", rpt, 8000)[1] == "bench exited 101"
    assert rig_verdict({"saturated": True, "failure_pct": 0.6}) == "INVALID"
    assert rig_verdict({"saturated": True, "failure_pct": 0.0}) == "PROXY"
    assert rig_verdict({"saturated": False, "failure_pct": 0.0}) == "CLIENT"

    # The ceiling statement, all three outcomes.
    def rows(rps: list[float], label: str = "PROXY_CPU") -> dict:
        ns = [1, 2, 4, 8, 16, 24, 32][:len(rps)]
        rs = [{"cores": n, "rps_proxy_median": t, "stable": True,
               "attribution": {"label": label, "confidence": "high", "why": "x"}} for n, t in zip(ns, rps)]
        return {"rows": rs, "curve": describe_curve(list(zip(ns, rps)))}
    assert ceiling_statement(rows([1, 2, 4, 8, 16, 24, 32]))["statement"] == "PROXY CEILING: NOT REACHED ON THIS HOST"
    reached = ceiling_statement(rows([1, 2, 4, 8, 12, 12.2, 12.1]))
    assert reached["statement"].startswith("PROXY CEILING: REACHED") and reached["plateau_from_cores"] == 16, reached
    assert ceiling_statement(rows([1, 2, 4, 8, 16, 24, 32], "INDETERMINATE"))["statement"] == "CEILING ATTRIBUTION: INDETERMINATE"
    assert ceiling_statement(None)["statement"] == "CEILING ATTRIBUTION: INDETERMINATE"

    # The replay store's connections as the primary lists them, and their queueing.
    listing = ("id=1 addr=x flags=N cmd=client|list qbuf=0\nid=2 addr=x flags=b cmd=wait qbuf=900\n"
               "id=3 addr=x flags=N cmd=set qbuf=100\nid=4 addr=x flags=S cmd=replconf qbuf=0\nid=5 flags=b cmd=wait qbuf=7")
    assert store_clients(listing, {"5"}) == [{"flags": "b", "qbuf": 900}, {"flags": "N", "qbuf": 100}]
    q = queue_summary([{"t": 0.0, "store_conns": 2, "store_blocked": 1, "qbuf": [900, 100], "set_calls": 0, "wait_calls": 0},
                       {"t": 2.0, "store_conns": 2, "store_blocked": 2, "qbuf": [300, 100], "set_calls": 400, "wait_calls": 398}])
    assert (q["store_conns_max"], q["blocked_in_wait_mean"], q["qbuf_per_conn_mean_bytes"], q["set_per_s"]) == (2, 1.5, 350, 200), q
    assert not queue_summary([])["available"]
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "startup.log"
        log.write_text("mcp-re-proxy: replay-store backend=redis tier=REDIS_WAIT_QUORUM guarantee=x\n"
                       "mcp-re-proxy: replay redis pool = 32 connections (--replay-redis-pool-size; default 8)\n"
                       "mcp-re-proxy: async fleet serving on 127.0.0.1:1 (1 cores)\n")
        assert startup_facts(log) == {"launches": 1, "replay_pool": [32], "replay_tier": ["REDIS_WAIT_QUORUM"]}
        assert startup_facts(Path(tmp) / "absent.log")["replay_pool"] == []

    # Identity: a 16-vCPU or arm64 host is not the declared context.
    facts = {"vcpus_usable": 16, "vcpus_online": 16, "architecture": "aarch64", "mem_total_kib": 64 * 1024 * 1024}
    problems = check_expected(facts, 32, "x86_64", 128)
    assert len(problems) == 4, problems


def campaign_case() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bins = root / "bin"
        bins.mkdir()
        for name in ("saturation_backend", "saturation_loadgen"):
            (bins / name).write_text("#!/bin/sh\nexit 0\n")
        for name in ("mcp-re-proxy-deploy", "mcp-re-proxy-ext"):
            (bins / name).write_text(FAKE_PROXY)
        (bins / "tls_load_harness_bench").write_text(FAKE_BENCH)
        (bins / "saturation_rig").write_text(FAKE_RIG)
        for path in bins.iterdir():
            path.chmod(0o755)
        identity = root / "identity.json"
        identity.write_text(json.dumps({"release_tag": "v0.18.0", "product_commit": "9dab7082",
                                        "tooling_commit": "selftest"}))
        run_dir = root / "run"
        online = os.cpu_count() or 2
        usable = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else online
        # The declared-context check compares online AND usable CPUs; a CI container whose
        # affinity mask is narrower than the machine cannot be "the declared host" at all.
        expect_ok = ["--expect-vcpus", str(usable)] if usable == online else []
        base = [sys.executable, str(HERE / "ceiling.py"), "campaign", str(run_dir), "--bin-dir", str(bins),
                "--identity", str(identity), "--redis-url", "redis://127.0.0.1:1", "--cores", "1,2,4",
                "--reps", "2", "--b-modes", "cold", "--b-repeats", "2", "--partitioned", "",
                "--replay-redis-pool-size", "16"]
        env = dict(os.environ, FAKE_FAIL_REP_AT="c2-rep2")

        # A pool the proxy does not admit is refused before anything is created.
        bad = subprocess.run([*base[:-1], "129"], env=env, capture_output=True, text=True)
        assert bad.returncode == 2 and "between 1 and 128" in bad.stderr and not run_dir.exists(), bad.stderr

        # A proxy that states a pool other than the one asked for fails the smoke: no sweep.
        ignored = root / "ignored"
        ig = subprocess.run([*base[:3], str(ignored), *base[4:]], env=dict(env, FAKE_PROXY_STATES_POOL="8"),
                            capture_output=True, text=True)
        assert ig.returncode == 4 and not (ignored / "phase-b").exists(), ig.stdout + ig.stderr
        assert json.loads((ignored / "manifest.json").read_text())["replay_pool"]["effective_at_smoke"]["rig"]["replay_pool"] == [8]

        # Binaries that are not the ones the bootstrap built are refused before anything runs.
        build = root / "build-identity.json"
        build.write_text(json.dumps({"binaries": {"tls_load_harness_bench": "0" * 64}}))
        drift = subprocess.run(base + ["--build-identity", str(build)], env=env, capture_output=True, text=True)
        assert drift.returncode == 5 and not (run_dir / "phase-a").exists(), drift.stdout + drift.stderr

        # A host that is not the declared context stops BEFORE any measurement.
        wrong = subprocess.run(base + ["--expect-vcpus", str(usable + 1)], env=env, capture_output=True, text=True)
        assert wrong.returncode == 3, wrong.stdout + wrong.stderr
        assert not (run_dir / "phase-a").exists(), "measured on an undeclared host"
        assert json.loads((run_dir / "host" / "identity-check.json").read_text())["problems"]

        # Launched as the `ubuntu` login shell launches it: umask 0002.
        result = subprocess.run(base + expect_ok, env=env, capture_output=True, text=True,
                                preexec_fn=lambda: os.umask(0o002))
        assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
        for rel in ("manifest.json", "summary.json", "summary.md", "SHA256SUMS", "logs/steps.json",
                    "logs/campaign.log", "host/inventory-before.json", "host/inventory-after.json",
                    "phase-a/scaling/c1/rep1.json", "phase-a/scaling/c1/point.json",
                    "phase-a/shipped-auto/c0/point.json", "phase-b/scaling/c4/attempt1/rung2.json",
                    "phase-b/shipped-auto/c0/attempt2/point.json", "phase-a/smoke/rig-smoke.log"):
            assert (run_dir / rel).is_file(), rel
        manifest = json.loads((run_dir / "manifest.json").read_text())
        assert manifest["binaries"]["bench"]["sha256"].startswith("sha256:") and manifest["finished"]
        assert (manifest["umask"], manifest["umask_inherited"]) == ("0022", "0002"), manifest
        pool = manifest["replay_pool"]
        assert (pool["requested"], pool["expected"]) == (16, 16), pool
        assert {k: v["replay_pool"] for k, v in pool["effective_at_smoke"].items()} == {"phase_a": [16], "rig": [16]}, pool
        assert not manifest["redis"]["nodes"]["primary"]["available"], "no Redis listens in the selftest"
        assert manifest["binaries"]["proxy_ext"]["path"].endswith("/mcp-re-proxy-ext"), "the BUILT binary is hashed"
        startup = (run_dir / "phase-b" / "scaling" / "c4" / "attempt1" / "rung1.proxy-startup.log").read_text()
        assert "replay redis pool = 16" in startup and "audit:" not in startup, "only the startup transcript is kept"
        assert not stale_sums(run_dir), f"SHA256SUMS stale after the campaign: {stale_sums(run_dir)}"
        # The launcher writes after the campaign; `pack` re-seals before archiving.
        with open(run_dir / "logs" / "launcher.txt", "a") as fh:
            fh.write("campaign_rc=0\n")
        packed = subprocess.run([sys.executable, str(HERE / "ceiling.py"), "pack", str(run_dir)],
                                capture_output=True, text=True)
        assert packed.returncode == 0, packed.stdout + packed.stderr
        archive = root / "run.tar.gz"
        digest, name = (root / "run.tar.gz.sha256").read_text().split()
        assert name == "run.tar.gz" and digest == hashlib.sha256(archive.read_bytes()).hexdigest()
        unpacked = root / "unpacked"
        with tarfile.open(archive) as tar:
            tar.extractall(unpacked, filter="data")
        assert not stale_sums(unpacked / "run"), f"packed SHA256SUMS stale: {stale_sums(unpacked / 'run')}"
        c2 = json.loads((run_dir / "phase-a" / "scaling" / "c2" / "point.json").read_text())
        assert c2["status"] == "INCOMPLETE" and not c2["reps"][1]["valid"], c2["reps"]
        b4 = json.loads((run_dir / "phase-b" / "scaling" / "c4" / "attempt1" / "point.json").read_text())
        assert [r["verdict"] for r in b4["rungs"]] == ["CLIENT", "PROXY"], b4["rungs"]
        assert [r["proxy"]["replay_pool"] for r in b4["rungs"]] == [[16], [16]], b4["rungs"]
        assert b4["redis_queue"]["available"] is False and b4["redis_queue"]["reason"], b4["redis_queue"]
        assert (run_dir / "phase-b" / "scaling" / "c4" / "attempt2" / "point.json").is_file(), "no repeat at the high end"
        summary = json.loads((run_dir / "summary.json").read_text())
        assert summary["rules"]["rig_saturation_pct"] == 5.0
        assert "A/scaling/c2: INCOMPLETE" in summary["inconclusive"], summary["inconclusive"]
        assert set(summary["phase_a"]) == {"scaling", "shipped-auto"}
        assert summary["phase_b"]["scaling"]["rows"][0]["rps_proxy_median"] == 5000.0
        assert summary["phase_b"]["scaling"]["rows"][0]["replay_pool_stated"] == [16]
        md = (run_dir / "summary.md").read_text()
        assert "Curve 1 — canonical" in md and "Curve 2 — proxy saturation" in md
        assert "replay redis pool: --replay-redis-pool-size 16; expected 16" in md, md


def stale_sums(run_dir: Path) -> list[str]:
    """Files whose SHA256SUMS line does not match, plus files the list omits."""
    listed = {}
    for line in (run_dir / "SHA256SUMS").read_text().splitlines():
        digest, rel = line.split("  ", 1)
        listed[rel] = digest
    bad = [rel for rel, d in listed.items()
           if hashlib.sha256((run_dir / rel).read_bytes()).hexdigest() != d]
    present = {str(p.relative_to(run_dir)) for p in run_dir.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    return sorted(bad + [f"unlisted:{r}" for r in present - set(listed)])


def telemetry_case() -> None:
    """On Linux, the /proc sampler must produce attributable samples around real work."""
    if not os.path.isdir("/proc/self"):
        return
    from telemetry import Telemetry, parse_pid_stat, parse_sockstat
    assert parse_pid_stat("1 (a b) S 0 0 0 0 0 0 0 0 7 0 50 25 0 0 0 0 4 0 0 0 300 0")["ticks"] == 75
    assert parse_sockstat("TCP: inuse 5 orphan 0 tw 12 alloc 9 mem 1\n")["tw"] == 12
    from telemetry import parse_netstat
    assert parse_netstat("TcpExt: A ListenOverflows ListenDrops\nTcpExt: 1 7 9\n") == {"ListenOverflows": 7, "ListenDrops": 9}
    with tempfile.TemporaryDirectory() as tmp:
        tel = Telemetry(Path(tmp), os.cpu_count() or 1, require=False)
        # The work runs in a CHILD, as every measured instrument does: CPU burned on this
        # interpreter's own thread starves the sampler of the GIL, and on a host with a busy
        # /proc not one sample completes inside the window.
        with tel:
            subprocess.run([sys.executable, "-c",
                            "import time\nend = time.time() + 2.5\nwhile time.time() < end: sum(i * i for i in range(10000))"],
                           check=True)
        summary = tel.result
        assert summary["available"] and summary["samples"] >= 1, summary
        assert summary["host_busy_avg"] > 0 and "other" in summary["categories"], summary
        assert (Path(tmp) / "telemetry" / "proc-samples.jsonl").stat().st_size > 0


def run_all() -> int:
    units()
    telemetry_case()
    campaign_case()
    print("lightsail ceiling selftest: OK (rules, attribution, identity stop, ladder, failure recording, layout, "
          "replay pool launch and refusal)")
    return 0
