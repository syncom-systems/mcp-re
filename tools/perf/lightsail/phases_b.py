# SPDX-License-Identifier: Apache-2.0
"""Phase B: the saturation rig, climbing the offered-load ladder until its own criterion says PROXY."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import redis_queue
import stage_sampler
from common import base_env, log, read_json, run_logged, write_json
from phases_context import STARTUP_LOG_ENV, Context, healthy, redis_roles, snapshot_redis, windowed
from phases_launch import startup_facts
from phases_rig import rig_steps, rig_verdict, rung_requests
from telemetry import Telemetry


@dataclass(frozen=True)
class BPoint:
    """One Phase B measurement: which sweep, how many cores, and how the rig is driven."""

    sweep: str
    cores: int
    workers: int
    mode: str
    attempt: int
    partition: bool = False


@dataclass(frozen=True)
class _Run:
    """One Phase B point being measured: where it writes, how the proxy and rig are started."""

    ctx: Context
    spec: BPoint
    point: Path
    proxy_cli: Path
    prefix: list[str]
    stages: stage_sampler.Window
    record: dict


def _pin_wrapper(point: Path, proxy: Path, cpus: str) -> Path:
    wrapper = point / "proxy-pinned.sh"
    wrapper.write_text(f'#!/bin/sh\nexec taskset -c {cpus} "{proxy}" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


def _placement(ctx: Context, spec: BPoint, point: Path, record: dict) -> tuple[Path, list[str]]:
    """The proxy executable and instrument prefix, partitioned onto CPUs when asked."""
    if spec.partition and ctx.isolation is not None:
        raise ValueError("a partitioned point and an isolation plan both place the proxy; use one")
    if not spec.partition:
        return ctx.bins.proxy_ext, ctx.instrument_prefix()
    if spec.cores >= ctx.vcpus:
        raise ValueError(f"a partitioned point needs spare CPUs: {spec.cores} of {ctx.vcpus}")
    record["cpu_partition"] = {"proxy": f"0-{spec.cores - 1}", "load": f"{spec.cores}-{ctx.vcpus - 1}"}
    return (_pin_wrapper(point, ctx.bins.proxy_ext, f"0-{spec.cores - 1}"),
            ["taskset", "-c", f"{spec.cores}-{ctx.vcpus - 1}"])


def _rung_environment(r: _Run, rung: int, out: Path, timers) -> dict:
    ctx = r.ctx
    # MCP_RE_SAT_REQUIRE_ECHO: a 2xx counts as a success only if it carries the
    # backend's echo, so every success in the row is a request the backend served.
    env = dict(base_env(), MCP_RE_SAT_REDIS_URL=ctx.redis_url, MCP_RE_SAT_WORKERS_PER_SHARD=str(r.spec.workers),
               MCP_RE_SAT_OUT=str(out), MCP_RE_PROXY_CLI=str(r.proxy_cli),
               MCP_RE_SAT_BACKEND=str(ctx.bins.backend), MCP_RE_SAT_LOADGEN=str(ctx.bins.loadgen),
               MCP_RE_SAT_REQUIRE_ECHO="1", **{STARTUP_LOG_ENV: str(r.point / f"rung{rung}.proxy-startup.log")})
    if timers is not None:
        env[stage_sampler.STAGE_TIMERS_ENV] = str(timers)
    return env


def _rung_argv(r: _Run, conns: int, requests: int) -> list[str]:
    ctx = r.ctx
    return r.prefix + [str(ctx.bins.rig), "--cores", str(r.spec.cores), "--mode", r.spec.mode, "--generators", "2",
                       "--max-generators", str(ctx.gen_cap), "--connections", str(conns),
                       "--requests", str(requests)]


def _read_row(out: Path, rc: int) -> dict | None:
    try:
        return read_json(out)["points"][0] if rc == 0 else None
    except (OSError, ValueError, KeyError, IndexError):
        return None


def _run_rung(r: _Run, rung: int, conns: int) -> tuple[dict, bool]:
    """Run one rung; the entry that records it, and whether the rig wrote a row."""
    ctx, spec = r.ctx, r.spec
    out = r.point / f"rung{rung}.json"
    requests, capped = rung_requests(conns, ctx.requests_per_connection, ctx.gen_cap)
    timers = r.stages.path_for(r.point / f"rung{rung}.stage-timers.csv")
    env = _rung_environment(r, rung, out, timers)
    argv = _rung_argv(r, conns, requests)
    sets_before = redis_queue.set_calls(ctx.redis_url)
    start = time.time()
    rc, secs = run_logged(argv, r.point / f"rung{rung}.log", env=env, timeout=5400)
    end = time.time()
    sets_after = redis_queue.set_calls(ctx.redis_url)
    r.record["windows"].append([start, end])
    entry = {"rung": rung, "connections_per_generator": conns, "requests_per_generator": requests,
             "requests_capped_by_signer_budget": capped,
             "rc": rc, "seconds": round(secs, 3), "backend_echo_required": True,
             "proxy": startup_facts(r.point / f"rung{rung}.proxy-startup.log")}
    row = _read_row(out, rc)
    if row is None:
        entry.update(verdict="ERROR", reason=f"rig exited {rc} or wrote no row")
        log(ctx.run_dir, f"B {spec.sweep} c{spec.cores} a{spec.attempt} rung{rung}: ERROR (rc={rc})")
        return entry, False
    steps = rig_steps(row, ctx.gen_cap)
    store_sets = None if sets_before is None or sets_after is None else sets_after - sets_before
    verdict, reasons = rig_verdict(row, (r.point / f"rung{rung}.log").read_text(errors="replace"),
                                   store_sets, requests * sum(steps))
    entry.update(row=row, verdict=verdict, invalid_reasons=reasons, steps=steps,
                 store_sets=store_sets, expected_sets=requests * sum(steps),
                 stage_timers=r.stages.summary([[start, end]]))
    log(ctx.run_dir, f"B {spec.sweep} c{spec.cores} a{spec.attempt} rung{rung} conns={conns}: "
                     f"{row['rps']:.1f} rps gens={row['generators']} -> {verdict}"
                     + (f" ({'; '.join(reasons)})" if reasons else ""))
    return entry, True


def _climb(r: _Run) -> dict | None:
    """Climb the ladder until a rung's verdict is not CLIENT; the rung whose verdict stands."""
    final = None
    for rung, conns in enumerate(r.ctx.ladder, 1):
        entry, measured = _run_rung(r, rung, conns)
        r.record["rungs"].append(entry)
        if not measured:
            break
        final = entry
        if entry["verdict"] != "CLIENT":
            break
    return final


def _conclude(r: _Run, tel: Telemetry, queue, final: dict | None) -> None:
    ctx, record = r.ctx, r.record
    snapshot_redis(ctx, r.point / "redis-after.json")
    record["telemetry"] = windowed(tel, record["windows"], ctx.vcpus)
    # The attribution is about the rung whose verdict stands, so it reads that rung alone.
    record["telemetry_final_rung"] = (windowed(tel, record["windows"][-1:], ctx.vcpus, "summary-final-rung.json")
                                      if record["windows"] else tel.result)
    record["redis_queue"] = queue.summary(record["windows"])
    record["redis_queue_final_rung"] = queue.summary(record["windows"][-1:])
    record["final"] = final
    record["status"] = "COMPLETE" if final is not None and final["verdict"] in {"PROXY", "CLIENT"} else "INCOMPLETE"
    write_json(r.point / "point.json", record)


def phase_b_point(ctx: Context, spec: BPoint) -> dict:
    """One saturation measurement of one core count, climbing the offered-load ladder until
    the rig's own criterion says PROXY (or the ladder is exhausted)."""
    point = ctx.run_dir / "phase-b" / spec.sweep / f"c{spec.cores}" / f"attempt{spec.attempt}"
    point.mkdir(parents=True, exist_ok=True)
    record: dict = {"phase": "B", "sweep": spec.sweep, "cores": spec.cores, "workers_per_shard": spec.workers,
                    "mode": spec.mode, "attempt": spec.attempt, "partitioned": spec.partition,
                    "rungs": [], "windows": []}
    if not healthy(ctx):
        record["status"] = "ABORTED_TIER_UNHEALTHY"
        write_json(point / "point.json", record)
        return record
    proxy_cli, prefix = _placement(ctx, spec, point, record)
    snapshot_redis(ctx, point / "redis-before.json")
    tel = Telemetry(point, ctx.vcpus, ctx.require_telemetry, redis_roles=redis_roles(ctx))
    queue = redis_queue.Window(ctx.redis_url, point)
    stages = stage_sampler.Window(point, ctx.stage_timers)
    run = _Run(ctx, spec, point, proxy_cli, prefix, stages, record)
    with tel, queue, stages:
        final = _climb(run)
    _conclude(run, tel, queue, final)
    return record
