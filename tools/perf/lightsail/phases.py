# SPDX-License-Identifier: Apache-2.0
"""Phase A (canonical cold-mTLS harness) and Phase B (saturation rig) runners.

Both instruments are the released v0.18.0 binaries, run as plain processes with absolute
paths. Nothing here changes what they measure: the envelope, the replay tier string, the
saturation criterion are theirs. What this module adds is the sweep, the telemetry window
around each measurement, and a record per measurement that says whether it is valid.

PHASE B AND THE RESOLUTION OF THE M -> M+1 TEST. The rig calls a row PROXY when one more
generator raises throughput by <= 5%. Adding one generator to M raises offered load by at
most 1/M, so for M >= 20 a row that is entirely client-limited still cannot gain more than
5%: the test loses the ability to say CLIENT and every row reads PROXY. The criterion is
therefore kept exactly (5%), and offered load is raised the other way: the generator count
stays <= GEN_CAP (one step >= 8.3%) and the connections per generator climb a ladder, with
requests scaled to keep the per-connection request count constant. A point still CLIENT at
the top rung is a floor, and `analysis.py` decides whether the host could have said more.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from common import HW_CLASS, base_env, log, read_json, run_logged, write_json
from redis_tier import Tier
from telemetry import Telemetry, summarize

PASS_LINE = "test result: ok. 1 passed"
GEN_CAP = 12
LADDER = (256, 512, 1024, 2048)        # connections per generator
REQUESTS_PER_CONNECTION = 40000 / 256  # the rig's own default ratio


@dataclass
class Binaries:
    proxy_deploy: Path
    proxy_ext: Path
    bench: Path
    rig: Path
    backend: Path
    loadgen: Path


@dataclass
class Context:
    run_dir: Path
    bins: Binaries
    redis_url: str
    vcpus: int
    require_telemetry: bool
    tier: Tier | None = None         # for snapshots and health; None only in a selftest
    envelope: dict = field(default_factory=lambda: {"concurrency": 128, "requests": 8000, "mode": "cold"})
    ladder: tuple[int, ...] = LADDER
    gen_cap: int = GEN_CAP
    requests_per_connection: float = REQUESTS_PER_CONNECTION


def _snapshot_redis(ctx: Context, path: Path) -> None:
    if ctx.tier is not None:
        ctx.tier.snapshot(path)


def _healthy(ctx: Context) -> bool:
    if ctx.tier is None:
        return True
    try:
        ctx.tier.wait_quorum(deadline_s=30)
        return True
    except Exception as exc:  # noqa: BLE001 — any failure here means the tier is not usable
        log(ctx.run_dir, f"replay tier NOT healthy: {exc}")
        return False


def validate_bench_rep(rc: int, log_text: str, report_path: Path, requests: int) -> tuple[dict | None, str | None]:
    """A canonical rep is valid only if the test ran (`1 passed`), the report parses and it
    accounts for every request. Returns (report, None) or (None, reason)."""
    if rc != 0:
        return None, f"bench exited {rc}"
    if PASS_LINE not in log_text:
        return None, "the bench did not report '1 passed' — nothing was measured"
    if not report_path.is_file():
        return None, "no report written"
    try:
        report = read_json(report_path)
        results = report["results"]
        total = results["successes"] + results["failures"]
    except (ValueError, KeyError) as exc:
        return None, f"report unreadable: {exc}"
    if total != requests:
        return None, f"report accounts for {total} of {requests} requests"
    return report, None


def phase_a_point(ctx: Context, topology: str, cores: int, workers: int, reps: int) -> dict:
    point = ctx.run_dir / "phase-a" / topology / f"c{cores}"
    point.mkdir(parents=True, exist_ok=True)
    record: dict = {"phase": "A", "topology": topology, "cores": cores, "workers_per_shard": workers,
                    "envelope": ctx.envelope, "reps": [], "windows": []}
    if not _healthy(ctx):
        record["status"] = "ABORTED_TIER_UNHEALTHY"
        write_json(point / "point.json", record)
        return record
    _snapshot_redis(ctx, point / "redis-before.json")
    tel = Telemetry(point, ctx.vcpus, ctx.require_telemetry)
    with tel:
        for rep in range(1, reps + 1):
            out = point / f"rep{rep}.json"
            env = dict(base_env(),
                       MCP_RE_PROXY_CLI=str(ctx.bins.proxy_deploy),
                       MCP_RE_LOADGEN_REDIS_URL=ctx.redis_url,
                       MCP_RE_LOADGEN_HW_CLASS=HW_CLASS,
                       MCP_RE_LOADGEN_CORES=str(cores),
                       MCP_RE_LOADGEN_WORKERS_PER_SHARD=str(workers),
                       MCP_RE_LOADGEN_CONCURRENCY=str(ctx.envelope["concurrency"]),
                       MCP_RE_LOADGEN_REQUESTS=str(ctx.envelope["requests"]),
                       MCP_RE_LOADGEN_MODE=ctx.envelope["mode"],
                       MCP_RE_LOADGEN_OUT=str(out))
            start = time.time()
            rc, secs = run_logged([str(ctx.bins.bench), "tls_load_harness_bench", "--exact", "--nocapture"],
                                  point / f"rep{rep}.log", env=env, timeout=1800)
            record["windows"].append([start, time.time()])
            report, reason = validate_bench_rep(rc, (point / f"rep{rep}.log").read_text(errors="replace"),
                                                out, ctx.envelope["requests"])
            entry = {"rep": rep, "seconds": round(secs, 3), "valid": report is not None, "reason": reason}
            if report is not None:
                r = report["results"]
                entry.update(throughput_rps=r["throughput_rps"], successes=r["successes"], failures=r["failures"],
                             p50_us=r["added_latency_us"]["p50"], p99_us=r["added_latency_us"]["p99"],
                             p999_us=r["added_latency_us"]["p999"])
            record["reps"].append(entry)
            log(ctx.run_dir, f"A {topology} c{cores} rep{rep}: " +
                (f"{entry['throughput_rps']:.1f} rps p99={entry['p99_us']}us" if report else f"INVALID ({reason})"))
    _snapshot_redis(ctx, point / "redis-after.json")
    record["telemetry"] = _windowed(tel, record["windows"], ctx.vcpus)
    record["status"] = "COMPLETE" if all(r["valid"] for r in record["reps"]) else "INCOMPLETE"
    write_json(point / "point.json", record)
    return record


def _windowed(tel: Telemetry, windows: list[list[float]], vcpus: int, name: str = "summary-windowed.json") -> dict:
    """Telemetry summarized over the measurement windows only: the gaps between reps
    (process start, presign, teardown) would otherwise dilute every average."""
    if tel.sampler is None:
        return tel.result
    inside = [s for s in tel.sampler.samples if any(a <= s["t"] <= b for a, b in windows)]
    summary = summarize(inside, vcpus)
    (tel.dir / name).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def rig_verdict(row: dict) -> str:
    if row.get("failure_pct", 0.0) > 0.5:
        return "INVALID"
    return "PROXY" if row.get("saturated") else "CLIENT"


def _pin_wrapper(point: Path, proxy: Path, cpus: str) -> Path:
    wrapper = point / "proxy-pinned.sh"
    wrapper.write_text(f'#!/bin/sh\nexec taskset -c {cpus} "{proxy}" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


def phase_b_point(ctx: Context, sweep: str, cores: int, workers: int, mode: str, attempt: int,
                  partition: bool = False) -> dict:
    """One saturation measurement of one core count, climbing the offered-load ladder until
    the rig's own criterion says PROXY (or the ladder is exhausted)."""
    point = ctx.run_dir / "phase-b" / sweep / f"c{cores}" / f"attempt{attempt}"
    point.mkdir(parents=True, exist_ok=True)
    record: dict = {"phase": "B", "sweep": sweep, "cores": cores, "workers_per_shard": workers, "mode": mode,
                    "attempt": attempt, "partitioned": partition, "rungs": [], "windows": []}
    if not _healthy(ctx):
        record["status"] = "ABORTED_TIER_UNHEALTHY"
        write_json(point / "point.json", record)
        return record
    proxy_cli = ctx.bins.proxy_ext
    prefix: list[str] = []
    if partition:
        if cores >= ctx.vcpus:
            raise ValueError(f"a partitioned point needs spare CPUs: {cores} of {ctx.vcpus}")
        proxy_cli = _pin_wrapper(point, ctx.bins.proxy_ext, f"0-{cores - 1}")
        prefix = ["taskset", "-c", f"{cores}-{ctx.vcpus - 1}"]
        record["cpu_partition"] = {"proxy": f"0-{cores - 1}", "load": f"{cores}-{ctx.vcpus - 1}"}
    _snapshot_redis(ctx, point / "redis-before.json")
    tel = Telemetry(point, ctx.vcpus, ctx.require_telemetry)
    final = None
    with tel:
        for rung, conns in enumerate(ctx.ladder, 1):
            out = point / f"rung{rung}.json"
            requests = int(conns * ctx.requests_per_connection)
            env = dict(base_env(), MCP_RE_SAT_REDIS_URL=ctx.redis_url, MCP_RE_SAT_WORKERS_PER_SHARD=str(workers),
                       MCP_RE_SAT_OUT=str(out), MCP_RE_PROXY_CLI=str(proxy_cli),
                       MCP_RE_SAT_BACKEND=str(ctx.bins.backend), MCP_RE_SAT_LOADGEN=str(ctx.bins.loadgen))
            argv = prefix + [str(ctx.bins.rig), "--cores", str(cores), "--mode", mode, "--generators", "2",
                             "--max-generators", str(ctx.gen_cap), "--connections", str(conns),
                             "--requests", str(requests)]
            start = time.time()
            rc, secs = run_logged(argv, point / f"rung{rung}.log", env=env, timeout=5400)
            record["windows"].append([start, time.time()])
            entry = {"rung": rung, "connections_per_generator": conns, "requests_per_generator": requests,
                     "rc": rc, "seconds": round(secs, 3)}
            try:
                row = read_json(out)["points"][0] if rc == 0 else None
            except (OSError, ValueError, KeyError, IndexError):
                row = None
            if row is None:
                entry.update(verdict="ERROR", reason=f"rig exited {rc} or wrote no row")
                record["rungs"].append(entry)
                log(ctx.run_dir, f"B {sweep} c{cores} a{attempt} rung{rung}: ERROR (rc={rc})")
                break
            entry.update(row=row, verdict=rig_verdict(row))
            record["rungs"].append(entry)
            final = entry
            log(ctx.run_dir, f"B {sweep} c{cores} a{attempt} rung{rung} conns={conns}: "
                             f"{row['rps']:.1f} rps gens={row['generators']} -> {entry['verdict']}")
            if entry["verdict"] != "CLIENT":
                break
    _snapshot_redis(ctx, point / "redis-after.json")
    record["telemetry"] = _windowed(tel, record["windows"], ctx.vcpus)
    # The attribution is about the rung whose verdict stands, so it reads that rung alone.
    record["telemetry_final_rung"] = (_windowed(tel, record["windows"][-1:], ctx.vcpus, "summary-final-rung.json")
                                      if record["windows"] else tel.result)
    record["final"] = final
    record["status"] = "COMPLETE" if final is not None and final["verdict"] in {"PROXY", "CLIENT"} else "INCOMPLETE"
    write_json(point / "point.json", record)
    return record
