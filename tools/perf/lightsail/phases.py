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

A RUNG IS EVIDENCE ONLY IF EVERY STEP OF IT WAS SERVED. The rig climbs M -> M+1 inside one
proxy process and keeps the better of the two rows; a probe step whose generators hit errors
comes out SLOWER, and the rig then reads its collapse as "one more generator bought nothing"
and stamps the row PROXY. So a rung is INVALID — never PROXY, never CLIENT — when the rig log
carries any `generator error:`, when its row counts any failure, or when the replay store's
own SET count over the rung — read from the primary immediately before and after it — differs from what the
rig's steps sent (`rig_steps`). The last check is independent of the rig: a generator that died without reporting cannot hide from it.

THE SIGNER RETENTION BUDGET. Every rig generator signs as the same actor, and one proxy
process admits at most `SIGNER_RETENTION_BUDGET` fresh nonces from one actor while they are
retained (the security bound in `mcp-re-proxy/src/async_replay/bounds.rs`, kept as is). The
requests per generator are therefore capped so that a rung climbing all the way to
`gen_cap` stays below it; the cap and whether it applied are recorded per rung.
"""

from __future__ import annotations

import json
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path

import redis_queue
import stage_sampler
from common import HW_CLASS, base_env, log, read_json, run_logged, write_json
from redis_tier import Tier
from telemetry import Telemetry, summarize

PASS_LINE = "test result: ok. 1 passed"
GEN_CAP = 12
LADDER = (256, 512, 1024, 2048)        # connections per generator
REQUESTS_PER_CONNECTION = 40000 / 256  # the rig's own default ratio
#: The pool the proxy opens when no `--replay-redis-pool-size` is passed.
DEFAULT_REPLAY_POOL = 8
#: Where the launcher appends each proxy's startup transcript; set per rep / rung.
STARTUP_LOG_ENV = "MCP_RE_CEILING_PROXY_LOG"
#: The proxy's per-actor retention budget (`async_replay/bounds.rs`: 1,000,000 entries per
#: replica, of which one actor may hold 800,000 under pressure). Each fresh rig nonce is
#: retained for its signature window (3600 s), so one rung's proxy refuses the rig's
#: 800,001st request — fail closed, `mcp-re.replay_cache_unavailable`.
SIGNER_RETENTION_BUDGET = 800_000
#: What a rung may send at most: the budget less a 5% margin.
RUNG_REQUEST_CEILING = SIGNER_RETENTION_BUDGET * 95 // 100


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
    replay_pool: int | None = None   # None: the flag is omitted and the proxy's default applies
    stage_timers: bool = False       # set MCP_RE_STAGE_TIMERS for every Phase B rung


def rung_requests(conns: int, requests_per_connection: float, gen_cap: int) -> tuple[int, bool]:
    """(requests per generator, whether the signer budget capped it) for one rung: the rig may
    run every step from 2 to `gen_cap` generators, so the worst case sends the sum of them."""
    wanted = int(conns * requests_per_connection)
    ceiling = RUNG_REQUEST_CEILING // sum(range(2, gen_cap + 1))
    return min(wanted, ceiling), wanted > ceiling


def rig_steps(row: dict, gen_cap: int) -> list[int]:
    """The generator count of every step `saturation_rig` ran for `row`. It starts at 2 and
    adds one generator per step; a probe at M+1 that did not beat M (gain <= 0) is not folded
    into the row, so it ran IN ADDITION to the steps up to M."""
    gens = row["generators"]
    steps = list(range(2, gens + 1))
    gain = row.get("last_gain_pct")
    if gain is not None and gain <= 0 and gens < gen_cap:
        steps.append(gens + 1)
    return steps


def rig_verdict(row: dict, log_text: str, store_sets: int | None, expected_sets: int) -> tuple[str, list[str]]:
    """PROXY / CLIENT from the rig's criterion, or INVALID with every reason that applies."""
    reasons = []
    if row.get("failures", 0) or row.get("failure_pct", 0.0) > 0:
        reasons.append(f"the row counts {row.get('failures')} failure(s)")
    errors = [line.strip() for line in log_text.splitlines() if "generator error:" in line]
    if errors:
        codes = sorted(set(re.findall(r'"wire_code":"([a-z0-9_.-]+)"', "\n".join(errors))))
        reasons.append(f"{len(errors)} generator error(s) in the rung" + (f" ({', '.join(codes)})" if codes else ""))
    if store_sets is None:
        reasons.append("the replay store's SET count over the rung could not be read")
    elif store_sets != expected_sets:
        reasons.append(f"the replay store saw {store_sets} SETs; the rig's steps sent {expected_sets}")
    if reasons:
        return "INVALID", reasons
    return ("PROXY" if row.get("saturated") else "CLIENT"), []




def proxy_launcher(out_dir: Path, binary: Path, pool: int | None) -> Path:
    """The proxy as the instruments start it: an exec wrapper adding the pool flag.

    The rig and the bench take the proxy as ONE executable path and build its arguments
    themselves, so a flag can reach it only through a wrapper. `exec` keeps the proxy at the
    wrapper's pid and executable. Its stderr is copied to `$MCP_RE_CEILING_PROXY_LOG` up to
    and including the serving line, then forwarded by `cat` alone: after startup the stream
    is the per-request audit record, which this never parses or writes to disk."""
    wrapper = out_dir / f"{binary.name}.sh"
    flag = f" --replay-redis-pool-size {pool}" if pool is not None else ""
    default_log = shlex.quote(str(out_dir / "proxy-startup.log"))
    wrapper.write_text(
        "#!/bin/bash\n"
        f'log="${{{STARTUP_LOG_ENV}:-{default_log}}}"\n'
        f'exec {shlex.quote(str(binary))} "$@"{flag} 2> >(\n'
        "  while IFS= read -r line; do\n"
        "    printf '%s\\n' \"$line\" >&2\n"
        "    printf '%s\\n' \"$line\" >> \"$log\"\n"
        "    if [[ $line == *\"async fleet serving on \"* ]]; then exec cat >&2; fi\n"
        "  done)\n")
    wrapper.chmod(0o755)
    return wrapper


def startup_facts(log_path: Path) -> dict:
    """What each proxy launch logged in `log_path` stated about its replay store."""
    text = log_path.read_text(errors="replace") if log_path.is_file() else ""
    return {"launches": text.count("async fleet serving on "),
            "replay_pool": [int(n) for n in re.findall(r"replay redis pool = (\d+) connections", text)],
            "replay_tier": re.findall(r"replay-store backend=redis tier=(\S+)", text)}
def _snapshot_redis(ctx: Context, path: Path) -> None:
    if ctx.tier is not None:
        ctx.tier.snapshot(path)


def _redis_roles(ctx: Context) -> dict[int, str]:
    """Each replay-tier process's pid -> role, for per-process telemetry."""
    if ctx.tier is None:
        return {}
    return {proc.pid: role for role, proc in ctx.tier.procs.items()}


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
    tel = Telemetry(point, ctx.vcpus, ctx.require_telemetry, redis_roles=_redis_roles(ctx))
    queue = redis_queue.Window(ctx.redis_url, point)
    with tel, queue:
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
                       MCP_RE_LOADGEN_OUT=str(out),
                       **{STARTUP_LOG_ENV: str(point / f"rep{rep}.proxy-startup.log")})
            start = time.time()
            rc, secs = run_logged([str(ctx.bins.bench), "tls_load_harness_bench", "--exact", "--nocapture"],
                                  point / f"rep{rep}.log", env=env, timeout=1800)
            record["windows"].append([start, time.time()])
            report, reason = validate_bench_rep(rc, (point / f"rep{rep}.log").read_text(errors="replace"),
                                                out, ctx.envelope["requests"])
            entry = {"rep": rep, "seconds": round(secs, 3), "valid": report is not None, "reason": reason,
                     "proxy": startup_facts(point / f"rep{rep}.proxy-startup.log")}
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
    record["redis_queue"] = queue.summary(record["windows"])
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
    tel = Telemetry(point, ctx.vcpus, ctx.require_telemetry, redis_roles=_redis_roles(ctx))
    queue = redis_queue.Window(ctx.redis_url, point)
    stages = stage_sampler.Window(point, ctx.stage_timers)
    final = None
    with tel, queue, stages:
        for rung, conns in enumerate(ctx.ladder, 1):
            out = point / f"rung{rung}.json"
            requests, capped = rung_requests(conns, ctx.requests_per_connection, ctx.gen_cap)
            timers = stages.path_for(point / f"rung{rung}.stage-timers.csv")
            # MCP_RE_SAT_REQUIRE_ECHO: a 2xx counts as a success only if it carries the
            # backend's echo, so every success in the row is a request the backend served.
            env = dict(base_env(), MCP_RE_SAT_REDIS_URL=ctx.redis_url, MCP_RE_SAT_WORKERS_PER_SHARD=str(workers),
                       MCP_RE_SAT_OUT=str(out), MCP_RE_PROXY_CLI=str(proxy_cli),
                       MCP_RE_SAT_BACKEND=str(ctx.bins.backend), MCP_RE_SAT_LOADGEN=str(ctx.bins.loadgen),
                       MCP_RE_SAT_REQUIRE_ECHO="1", **{STARTUP_LOG_ENV: str(point / f"rung{rung}.proxy-startup.log")})
            if timers is not None:
                env[stage_sampler.STAGE_TIMERS_ENV] = str(timers)
            argv = prefix + [str(ctx.bins.rig), "--cores", str(cores), "--mode", mode, "--generators", "2",
                             "--max-generators", str(ctx.gen_cap), "--connections", str(conns),
                             "--requests", str(requests)]
            sets_before = redis_queue.set_calls(ctx.redis_url)
            start = time.time()
            rc, secs = run_logged(argv, point / f"rung{rung}.log", env=env, timeout=5400)
            end = time.time()
            sets_after = redis_queue.set_calls(ctx.redis_url)
            record["windows"].append([start, end])
            entry = {"rung": rung, "connections_per_generator": conns, "requests_per_generator": requests,
                     "requests_capped_by_signer_budget": capped,
                     "rc": rc, "seconds": round(secs, 3), "backend_echo_required": True,
                     "proxy": startup_facts(point / f"rung{rung}.proxy-startup.log")}
            try:
                row = read_json(out)["points"][0] if rc == 0 else None
            except (OSError, ValueError, KeyError, IndexError):
                row = None
            if row is None:
                entry.update(verdict="ERROR", reason=f"rig exited {rc} or wrote no row")
                record["rungs"].append(entry)
                log(ctx.run_dir, f"B {sweep} c{cores} a{attempt} rung{rung}: ERROR (rc={rc})")
                break
            steps = rig_steps(row, ctx.gen_cap)
            store_sets = None if sets_before is None or sets_after is None else sets_after - sets_before
            verdict, reasons = rig_verdict(row, (point / f"rung{rung}.log").read_text(errors="replace"),
                                           store_sets, requests * sum(steps))
            entry.update(row=row, verdict=verdict, invalid_reasons=reasons, steps=steps,
                         store_sets=store_sets, expected_sets=requests * sum(steps),
                         stage_timers=stages.summary([[start, end]]))
            record["rungs"].append(entry)
            final = entry
            log(ctx.run_dir, f"B {sweep} c{cores} a{attempt} rung{rung} conns={conns}: "
                             f"{row['rps']:.1f} rps gens={row['generators']} -> {verdict}"
                             + (f" ({'; '.join(reasons)})" if reasons else ""))
            if entry["verdict"] != "CLIENT":
                break
    _snapshot_redis(ctx, point / "redis-after.json")
    record["telemetry"] = _windowed(tel, record["windows"], ctx.vcpus)
    # The attribution is about the rung whose verdict stands, so it reads that rung alone.
    record["telemetry_final_rung"] = (_windowed(tel, record["windows"][-1:], ctx.vcpus, "summary-final-rung.json")
                                      if record["windows"] else tel.result)
    record["redis_queue"] = queue.summary(record["windows"])
    record["redis_queue_final_rung"] = queue.summary(record["windows"][-1:])
    record["final"] = final
    record["status"] = "COMPLETE" if final is not None and final["verdict"] in {"PROXY", "CLIENT"} else "INCOMPLETE"
    write_json(point / "point.json", record)
    return record
