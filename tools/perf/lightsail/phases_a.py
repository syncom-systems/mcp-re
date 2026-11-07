# SPDX-License-Identifier: Apache-2.0
"""Phase A: the canonical cold-mTLS harness, one point per topology and core count."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import redis_queue
from common import HW_CLASS, base_env, log, read_json, run_logged, write_json
from phases_context import PASS_LINE, STARTUP_LOG_ENV, Context, healthy, redis_roles, snapshot_redis, windowed
from phases_launch import startup_facts
from telemetry import Telemetry


@dataclass(frozen=True)
class Topology:
    """The proxy topology a Phase A point measures: a name, core count and workers per shard."""

    name: str
    cores: int
    workers: int


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


@dataclass(frozen=True)
class _Point:
    """One Phase A point being measured: where it writes, what it measures, what it records."""

    ctx: Context
    point: Path
    topology: Topology
    record: dict


def _rep_environment(p: _Point, rep: int, out: Path) -> dict:
    ctx, topo = p.ctx, p.topology
    return dict(base_env(),
                MCP_RE_PROXY_CLI=str(ctx.bins.proxy_deploy),
                MCP_RE_LOADGEN_REDIS_URL=ctx.redis_url,
                MCP_RE_LOADGEN_HW_CLASS=HW_CLASS,
                MCP_RE_LOADGEN_CORES=str(topo.cores),
                MCP_RE_LOADGEN_WORKERS_PER_SHARD=str(topo.workers),
                MCP_RE_LOADGEN_CONCURRENCY=str(ctx.envelope["concurrency"]),
                MCP_RE_LOADGEN_REQUESTS=str(ctx.envelope["requests"]),
                MCP_RE_LOADGEN_MODE=ctx.envelope["mode"],
                MCP_RE_LOADGEN_OUT=str(out),
                **{STARTUP_LOG_ENV: str(p.point / f"rep{rep}.proxy-startup.log")})


def _measured(report: dict) -> dict:
    r = report["results"]
    return {"throughput_rps": r["throughput_rps"], "successes": r["successes"], "failures": r["failures"],
            "p50_us": r["added_latency_us"]["p50"], "p99_us": r["added_latency_us"]["p99"],
            "p999_us": r["added_latency_us"]["p999"]}


def _run_rep(p: _Point, rep: int) -> None:
    ctx = p.ctx
    out = p.point / f"rep{rep}.json"
    env = _rep_environment(p, rep, out)
    start = time.time()
    rc, secs = run_logged(ctx.instrument_prefix() + [str(ctx.bins.bench), "tls_load_harness_bench", "--exact", "--nocapture"],
                          p.point / f"rep{rep}.log", env=env, timeout=1800)
    p.record["windows"].append([start, time.time()])
    report, reason = validate_bench_rep(rc, (p.point / f"rep{rep}.log").read_text(errors="replace"),
                                        out, ctx.envelope["requests"])
    entry = {"rep": rep, "seconds": round(secs, 3), "valid": report is not None, "reason": reason,
             "proxy": startup_facts(p.point / f"rep{rep}.proxy-startup.log")}
    if report is not None:
        entry.update(_measured(report))
    p.record["reps"].append(entry)
    log(ctx.run_dir, f"A {p.topology.name} c{p.topology.cores} rep{rep}: " +
        (f"{entry['throughput_rps']:.1f} rps p99={entry['p99_us']}us" if report else f"INVALID ({reason})"))


def phase_a_point(ctx: Context, topology: Topology, reps: int) -> dict:
    point = ctx.run_dir / "phase-a" / topology.name / f"c{topology.cores}"
    point.mkdir(parents=True, exist_ok=True)
    record: dict = {"phase": "A", "topology": topology.name, "cores": topology.cores,
                    "workers_per_shard": topology.workers,
                    "envelope": ctx.envelope, "reps": [], "windows": []}
    if not healthy(ctx):
        record["status"] = "ABORTED_TIER_UNHEALTHY"
        write_json(point / "point.json", record)
        return record
    snapshot_redis(ctx, point / "redis-before.json")
    tel = Telemetry(point, ctx.vcpus, ctx.require_telemetry, redis_roles=redis_roles(ctx))
    queue = redis_queue.Window(ctx.redis_url, point)
    with tel, queue:
        for rep in range(1, reps + 1):
            _run_rep(_Point(ctx, point, topology, record), rep)
    snapshot_redis(ctx, point / "redis-after.json")
    record["telemetry"] = windowed(tel, record["windows"], ctx.vcpus)
    record["redis_queue"] = queue.summary(record["windows"])
    record["status"] = "COMPLETE" if all(r["valid"] for r in record["reps"]) else "INCOMPLETE"
    write_json(point / "point.json", record)
    return record
