# SPDX-License-Identifier: Apache-2.0
"""The campaign: identity check, replay tier, smoke, Phase A, Phase B, summary.

Every step is timed and logged into the run directory; a failed point is recorded and the
campaign continues, while a host that is not the declared context, or a smoke that fails,
stops it before the sweep.
"""

from __future__ import annotations

import argparse
import os
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

from analysis import summarize_run
from ceiling_manifest import binaries, drifted_instruments, initial_manifest, launchers, redis_config
from ceiling_seal import finish
from common import base_env, log, ports, read_json, run_logged, write_json
from hostfacts import check_expected, inventory
from phases import (DEFAULT_REPLAY_POOL, STARTUP_LOG_ENV, BPoint, Context, Topology, phase_a_point,
                    phase_b_point, startup_facts)
import isolation
from redis_tier import Tier


def _step(run_dir: Path, steps: list, name: str, fn):
    started = time.time()
    log(run_dir, f"== step {name}")
    try:
        result = fn()
        steps.append({"step": name, "ok": True, "seconds": round(time.time() - started, 1)})
        return result
    except Exception as exc:  # noqa: BLE001 — recorded with its traceback, then re-raised or tolerated by caller
        steps.append({"step": name, "ok": False, "seconds": round(time.time() - started, 1),
                      "error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()})
        write_json(run_dir / "logs" / "steps.json", steps)
        raise
    finally:
        write_json(run_dir / "logs" / "steps.json", steps)


def _tolerant(run_dir: Path, steps: list, name: str, fn) -> None:
    """A failed point is recorded and the campaign continues: the machine is paid for."""
    try:
        _step(run_dir, steps, name, fn)
    except Exception:  # noqa: BLE001 — _step already wrote the error and traceback
        log(run_dir, f"step {name} FAILED (recorded in logs/steps.json); continuing")


def repeat_cores(summary_b: dict, sweep: tuple[int, ...]) -> list[int]:
    """The knee, the point after it, and the high-core region — where stability matters."""
    chosen = {n for n in sweep if n >= 16} | set(sweep[-2:])
    curve = (summary_b.get("scaling") or {}).get("curve") or {}
    knee = curve.get("knee")
    if knee in sweep:
        i = sweep.index(knee)
        chosen |= {knee} | ({sweep[i + 1]} if i + 1 < len(sweep) else set())
    return sorted(chosen)


def smoke(ctx: Context) -> bool:
    """One canonical rep at one core, and the rig's own --smoke, before anything is swept.

    Both proxies must also have STATED the pool this run asked for: a sweep whose proxy
    opened another pool would measure a configuration nobody declared."""
    point = phase_a_point(ctx, Topology("smoke", 1, 1), 1)
    if point["status"] != "COMPLETE":
        return False
    smoke_dir = ctx.run_dir / "phase-a" / "smoke"
    env = dict(base_env(), MCP_RE_SAT_REDIS_URL=ctx.redis_url, MCP_RE_PROXY_CLI=str(ctx.bins.proxy_ext),
               MCP_RE_SAT_BACKEND=str(ctx.bins.backend), MCP_RE_SAT_LOADGEN=str(ctx.bins.loadgen),
               MCP_RE_SAT_OUT=str(smoke_dir / "rig-smoke.json"),
               **{STARTUP_LOG_ENV: str(smoke_dir / "rig-smoke.proxy-startup.log")})
    rc, _ = run_logged(ctx.instrument_prefix() + [str(ctx.bins.rig), "--smoke"], smoke_dir / "rig-smoke.log",
                       env=env, timeout=600)
    stated = {"phase_a": point["reps"][0]["proxy"], "rig": startup_facts(smoke_dir / "rig-smoke.proxy-startup.log")}
    expected = ctx.replay_pool or DEFAULT_REPLAY_POOL
    manifest = read_json(ctx.run_dir / "manifest.json")
    manifest["replay_pool"]["effective_at_smoke"] = stated
    write_json(ctx.run_dir / "manifest.json", manifest)
    wrong = {k: v["replay_pool"] for k, v in stated.items() if not v["replay_pool"] or set(v["replay_pool"]) != {expected}}
    if wrong:
        log(ctx.run_dir, f"SMOKE: the proxy did not state a replay pool of {expected}: {wrong}")
    return rc == 0 and not wrong


@dataclass(frozen=True)
class Sweeps:
    """What the two phases are run over: the context, the step log, the plan and the host."""

    ctx: Context
    steps: list
    args: argparse.Namespace
    sweep: tuple[int, ...]
    vcpus: int


def _phase_a(s: Sweeps) -> None:
    run_dir = s.ctx.run_dir
    for n in s.sweep:
        _tolerant(run_dir, s.steps, f"A-scaling-c{n}", lambda n=n: phase_a_point(s.ctx, Topology("scaling", n, 1), s.args.reps))
    _tolerant(run_dir, s.steps, "A-shipped-auto", lambda: phase_a_point(s.ctx, Topology("shipped-auto", 0, 0), s.args.reps))


def _phase_b_repeats(s: Sweeps, primary: str) -> None:
    run_dir = s.ctx.run_dir
    interim = summarize_run(run_dir, s.vcpus)
    for attempt in range(2, s.args.b_repeats + 1):
        for n in repeat_cores(interim["phase_b"], s.sweep):
            _tolerant(run_dir, s.steps, f"B-scaling-c{n}-a{attempt}",
                      lambda n=n, a=attempt: phase_b_point(s.ctx, BPoint("scaling", n, 1, primary, a)))


def _phase_b_other_modes(s: Sweeps, modes: list[str]) -> None:
    for mode in modes[1:]:
        for n in s.sweep:
            _tolerant(s.ctx.run_dir, s.steps, f"B-{mode}-c{n}",
                      lambda n=n, m=mode: phase_b_point(s.ctx, BPoint(f"scaling-{m}", n, 1, m, 1)))


def _phase_b_partitioned(s: Sweeps, primary: str) -> None:
    for n in (int(x) for x in s.args.partitioned.split(",") if x):
        if n < s.vcpus:
            _tolerant(s.ctx.run_dir, s.steps, f"B-partitioned-c{n}",
                      lambda n=n: phase_b_point(s.ctx, BPoint("partitioned", n, 1, primary, 1, partition=True)))


def _phase_b(s: Sweeps) -> None:
    run_dir = s.ctx.run_dir
    modes = [m for m in s.args.b_modes.split(",") if m]
    primary = modes[0] if modes else "cold"
    for n in s.sweep:
        _tolerant(run_dir, s.steps, f"B-scaling-c{n}", lambda n=n: phase_b_point(s.ctx, BPoint("scaling", n, 1, primary, 1)))
    _phase_b_repeats(s, primary)
    _phase_b_other_modes(s, modes)
    _phase_b_partitioned(s, primary)
    for attempt in range(1, s.args.b_repeats + 1):
        _tolerant(run_dir, s.steps, f"B-shipped-auto-a{attempt}",
                  lambda a=attempt: phase_b_point(s.ctx, BPoint("shipped-auto", 0, 0, primary, a)))


def _identity_check(run_dir: Path, steps: list, args) -> tuple[dict, list[str]]:
    facts = _step(run_dir, steps, "inventory-before", lambda: inventory(args.bundle))
    write_json(run_dir / "host" / "inventory-before.json", facts)
    problems = check_expected(facts, args.expect_vcpus, args.expect_arch, args.expect_mem_gib)
    write_json(run_dir / "host" / "identity-check.json", {"expected": {"vcpus": args.expect_vcpus,
               "arch": args.expect_arch, "mem_gib": args.expect_mem_gib}, "problems": problems})
    return facts, problems


def _isolate(args, run_dir: Path) -> tuple[dict | None, Path | None]:
    """The CPU isolation plan, applied to this process, when the campaign asks for one."""
    if not args.isolate_replay_path:
        return None, None
    if args.redis_url:
        raise SystemExit("ceiling: --isolate-replay-path pins the harness's own replay tier; "
                         "it cannot place an operator-managed one")
    plan = isolation.plan(isolation.topology())
    path = run_dir / "host" / "isolation-plan.json"
    write_json(path, plan)
    # The harness itself and everything it starts (samplers, sysstat, the tier, the
    # instruments, each launcher's enforcer) inherit the general set; only the Redis
    # primary and the proxy's control thread are then placed on reserved cores.
    os.sched_setaffinity(0, plan["general"])
    log(run_dir, f"isolation: redis primary on {plan['redis_primary']}, control thread on "
                 f"{plan['control']}, SMT siblings {plan['idle_siblings']} idle, everything else on "
                 f"{isolation.cpulist(plan['general'])}")
    return plan, path


def _start_tier(args, run_dir: Path, steps: list, iso_plan: dict | None) -> tuple[Tier | None, str]:
    """The replay tier this campaign owns, or None when the operator manages one."""
    if args.redis_url:
        return None, args.redis_url
    tier = Tier(run_dir, ports(Path(args.ports_toml)))
    _step(run_dir, steps, "redis-up", lambda: tier.up(run_dir))
    tier.snapshot(run_dir / "redis" / "info-before.json")
    if iso_plan is not None:
        write_json(run_dir / "redis" / "affinity.json", {
            role: isolation.pin_process(proc.pid, iso_plan["redis_primary"] if role == "primary"
                                        else iso_plan["general"])
            for role, proc in tier.procs.items()})
    return tier, tier.url


def _record_tier(run_dir: Path, redis_url: str, tier: Tier | None, iso_plan: dict | None) -> None:
    manifest = read_json(run_dir / "manifest.json")
    manifest["redis"] = dict(url=redis_url, managed=tier is not None, **redis_config(run_dir, redis_url, tier))
    manifest["isolation"] = ({"plan": "host/isolation-plan.json", **iso_plan,
                              "applied": "redis/affinity.json; per proxy launch <startup log>.affinity.jsonl"}
                             if iso_plan is not None else None)
    write_json(run_dir / "manifest.json", manifest)


@dataclass(frozen=True)
class Host:
    """Where the campaign runs: its directory, usable CPUs, replay tier URL and isolation."""

    run_dir: Path
    vcpus: int
    redis_url: str
    iso_plan: dict | None
    iso_path: Path | None


def _context(args, bins, tier: Tier | None, host: Host) -> Context:
    return Context(host.run_dir, launchers(host.run_dir, bins, args.replay_redis_pool_size, host.iso_path),
                   host.redis_url, host.vcpus, args.require_telemetry, tier,
                   ladder=tuple(int(x) for x in args.ladder.split(",")), gen_cap=args.gen_cap,
                   requests_per_connection=args.requests_per_connection,
                   replay_pool=args.replay_redis_pool_size, stage_timers=args.stage_timers,
                   isolation=host.iso_plan)


def _run_sweeps(s: Sweeps) -> int:
    run_dir = s.ctx.run_dir
    if not _step(run_dir, s.steps, "smoke", lambda: smoke(s.ctx)):
        log(run_dir, "SMOKE FAILED — the expensive sweep is not started")
        return 4
    _phase_a(s)
    _phase_b(s)
    return 0


def _wind_down(run_dir: Path, tier: Tier | None, args, vcpus: int) -> None:
    if tier is not None:
        tier.snapshot(run_dir / "redis" / "info-after.json")
        write_json(run_dir / "redis" / "health-after.json", tier.health())
        tier.down()
    write_json(run_dir / "host" / "inventory-after.json", inventory(args.bundle))
    finish(run_dir, vcpus)


def _check_gen_cap(args) -> None:
    if not 2 <= args.gen_cap < 20:
        raise SystemExit("ceiling: --gen-cap must be 2..19: at 20+ generators one more adds <= 5% offered "
                         "load, so the rig's 5% criterion can no longer report CLIENT")


def _refused_for_drift(run_dir: Path, manifest: dict) -> bool:
    """The binaries measured are the binaries the bootstrap built from the subject, or nothing."""
    drift = drifted_instruments(manifest)
    if drift:
        log(run_dir, f"REFUSED: instrument(s) {drift} differ from the build identity's SHA-256s")
    return bool(drift)


def _host_vcpus(run_dir: Path, steps: list, args) -> int | None:
    """The usable vCPUs of the declared host, or None after logging why it is not that host."""
    facts, problems = _identity_check(run_dir, steps, args)
    if problems:
        log(run_dir, "HOST IS NOT THE DECLARED MEASUREMENT CONTEXT — stopping before any measurement: " + "; ".join(problems))
        return None
    return facts["vcpus_usable"] or os.cpu_count() or 1


def campaign(args: argparse.Namespace, umasks: dict) -> int:
    _check_gen_cap(args)
    run_dir = Path(args.run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    steps: list[dict] = []
    sweep = tuple(int(x) for x in args.cores.split(","))
    bins = binaries(Path(args.bin_dir))
    manifest = initial_manifest(args, bins, sweep, umasks)
    write_json(run_dir / "manifest.json", manifest)
    if _refused_for_drift(run_dir, manifest):
        return 5

    vcpus = _host_vcpus(run_dir, steps, args)
    if vcpus is None:
        return 3
    sweep = tuple(n for n in sweep if n <= vcpus)

    iso_plan, iso_path = _isolate(args, run_dir)
    tier, redis_url = _start_tier(args, run_dir, steps, iso_plan)
    _record_tier(run_dir, redis_url, tier, iso_plan)
    ctx = _context(args, bins, tier, Host(run_dir, vcpus, redis_url, iso_plan, iso_path))
    try:
        return _run_sweeps(Sweeps(ctx, steps, args, sweep, vcpus))
    finally:
        _wind_down(run_dir, tier, args, vcpus)
